/*
 *   Copyright (C) 2020 Canonical Ltd.
 *
 *   This program is free software; you can redistribute it and/or
 *    modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>

#include <sys/apparmor.h>
#include <sys/apparmor_private.h>

#include "cJSON.h"

#define autofree __attribute((cleanup(_aa_autofree)))
#define autofclose __attribute((cleanup(_aa_autofclose)))

#define AA_EXIT_ENABLED 0
#define AA_EXIT_DISABLED 1
#define AA_EXIT_NO_POLICY 2
#define AA_EXIT_NO_CONTROL 3
#define AA_EXIT_NO_PERM 4
#define AA_EXIT_INTERNAL_ERROR 42

/* NOTE: Increment this whenever the JSON format changes */
static const unsigned char aa_status_json_version[] = "2";

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define __unused __attribute__ ((__unused__))

struct profile {
	char *name;
	char *status;
};

static void free_profiles(struct profile *profiles, size_t n) {
	while (n > 0) {
		n--;
		free(profiles[n].name);
		free(profiles[n].status);
	}
	free(profiles);
}

struct process {
	char *pid;
	char *profile;
	char *exe;
	char *mode;
};

static void free_processes(struct process *processes, size_t n) {
	while (n > 0) {
		n--;
		free(processes[n].pid);
		free(processes[n].profile);
		free(processes[n].exe);
		free(processes[n].mode);
        }
	free(processes);
}

static int verbose = 0;

#define dprintf(...)                                                           \
do {									       \
	if (verbose)							       \
		printf(__VA_ARGS__);					       \
} while (0)

#define dfprintf(...)                                                          \
do {									       \
	if (verbose)							       \
		fprintf(__VA_ARGS__);					       \
} while (0)


static int get_profiles(struct profile **profiles, size_t *n) {
	autofree char *apparmorfs = NULL;
	autofree char *apparmor_profiles = NULL;
	struct stat st;
	autofclose FILE *fp = NULL;
	autofree char *line = NULL;
	size_t len = 0;
	int ret;

	*profiles = NULL;
	*n = 0;

	ret = stat("/sys/module/apparmor", &st);
	if (ret != 0) {
		dfprintf(stderr, "apparmor not present.\n");
		ret = AA_EXIT_DISABLED;
		goto exit;
        }
	dprintf("apparmor module is loaded.\n");

	ret = aa_find_mountpoint(&apparmorfs);
	if (ret == -1) {
		dfprintf(stderr, "apparmor filesystem is not mounted.\n");
		ret = AA_EXIT_NO_CONTROL;
		goto exit;
        }

	apparmor_profiles = malloc(strlen(apparmorfs) + 10); // /profiles\0
	if (apparmor_profiles == NULL) {
		ret = AA_EXIT_INTERNAL_ERROR;
		goto exit;
        }
	sprintf(apparmor_profiles, "%s/profiles", apparmorfs);

	fp = fopen(apparmor_profiles, "r");
	if (fp == NULL) {
		if (errno == EACCES) {
			dfprintf(stderr, "You do not have enough privilege to read the profile set.\n");
		} else {
			dfprintf(stderr, "Could not open %s: %s", apparmor_profiles, strerror(errno));
		}
		ret = AA_EXIT_NO_PERM;
		goto exit;
	}

	while (getline(&line, &len, fp) != -1) {
		struct profile *_profiles;
		autofree char *status = NULL;
		autofree char *name = strdup(aa_splitcon(line, &status));

		if (status)
			status = strdup(status);
		// give up if out of memory
		if (name == NULL || status == NULL) {
			free_profiles(*profiles, *n);
			*profiles = NULL;
			*n = 0;
			ret = AA_EXIT_INTERNAL_ERROR;
			break;
		}
		_profiles = realloc(*profiles, (*n + 1) * sizeof(**profiles));
		if (_profiles == NULL) {
			free_profiles(*profiles, *n);
			*profiles = NULL;
			*n = 0;
			ret = AA_EXIT_INTERNAL_ERROR;
			break;
		}
		// steal name and status
		_profiles[*n].name = name;
		_profiles[*n].status = status;
		name = NULL;
		status = NULL;
		*n = *n + 1;
		*profiles = _profiles;
	}

exit:
	return ret == 0 ? (*n > 0 ? AA_EXIT_ENABLED : AA_EXIT_NO_POLICY) : ret;
}

static int compare_profiles(const void *a, const void *b) {
	return strcmp(((struct profile *)a)->name,
		      ((struct profile *)b)->name);
}

static int filter_profiles(struct profile *profiles,
			   size_t n,
			   const char *filter,
			   struct profile **filtered,
			   size_t *nfiltered)
{
	int ret = 0;
	size_t i;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (filter == NULL || strcmp(profiles[i].status, filter) == 0) {
			struct profile *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_profiles(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
                        }
			_filtered[*nfiltered].name = strdup(profiles[i].name);
			_filtered[*nfiltered].status = strdup(profiles[i].status);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}
	if (*nfiltered != 0) {
		qsort(*filtered, *nfiltered, sizeof(*profiles), compare_profiles);
	}
	return ret;
}

static int get_processes(struct profile *profiles,
			 size_t n,
			 struct process **processes,
			 size_t *nprocesses)
{
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	int ret = 0;

	*processes = NULL;
	*nprocesses = 0;

	dir = opendir("/proc");
	if (dir == NULL) {
		ret = AA_EXIT_INTERNAL_ERROR;
		goto exit;
        }
	while ((entry = readdir(dir)) != NULL) {
		size_t i;
		int rc;
		int ispid = 1;
		autofree char *profile = NULL;
		autofree char *mode = NULL; /* be careful */
		autofree char *exe = NULL;
		autofree char *real_exe = NULL;
		autofclose FILE *fp = NULL;
		autofree char *line = NULL;

		// ignore non-pid entries
		for (i = 0; ispid && i < strlen(entry->d_name); i++) {
			ispid = (isdigit(entry->d_name[i]) ? 1 : 0);
		}
		if (!ispid) {
			continue;
		}

		rc = aa_getprocattr(atoi(entry->d_name), "current", &profile, &mode);
		if (rc == -1 && errno != ENOMEM) {
			/* fail to access */
			continue;
		} else if (rc == -1 ||
			   asprintf(&exe, "/proc/%s/exe", entry->d_name) == -1) {
			fprintf(stderr, "ERROR: Failed to allocate memory\n");
			ret = AA_EXIT_INTERNAL_ERROR;
			goto exit;
		} else if (mode) {
			/* TODO: make this not needed. Mode can now be autofreed */
			mode = strdup(mode);
		}
		// get executable - readpath can allocate for us but seems
		// to fail in some cases with errno 2 - no such file or
		// directory - whereas readlink() can succeed in these
		// cases - and readpath() seems to have the same behaviour
		// as in python with better canonicalized results so try it
		// first and fallack to readlink if it fails
		// coverity[toctou]
		real_exe = realpath(exe, NULL);
		if (real_exe == NULL) {
			int res;
			// ensure enough space for NUL terminator
			real_exe = calloc(PATH_MAX + 1, sizeof(char));
			if (real_exe == NULL) {
				fprintf(stderr, "ERROR: Failed to allocate memory\n");
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			res = readlink(exe, real_exe, PATH_MAX);
			if (res == -1) {
				continue;
			}
			real_exe[res] = '\0';
		}


		if (mode == NULL) {
			// is unconfined so keep only if this has a
			// matching profile. TODO: fix to use attachment
			for (i = 0; i < n; i++) {
				if (strcmp(profiles[i].name, real_exe) == 0) {
					profile = strdup(real_exe);
					mode = strdup("unconfined");
					break;
				}
			}
		}
		if (profile != NULL && mode != NULL) {
			struct process *_processes = realloc(*processes,
							     (*nprocesses + 1) * sizeof(**processes));
			if (_processes == NULL) {
				free_processes(*processes, *nprocesses);
				*processes = NULL;
				*nprocesses = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				goto exit;
			}
			_processes[*nprocesses].pid = strdup(entry->d_name);
			_processes[*nprocesses].profile = profile;
			_processes[*nprocesses].exe = strdup(real_exe);
			_processes[*nprocesses].mode = mode;
			*processes = _processes;
			*nprocesses = *nprocesses + 1;
			profile = NULL;
			mode = NULL;
			ret = AA_EXIT_ENABLED;
		}
	}

exit:
	if (dir != NULL) {
		closedir(dir);
	}
	return ret;
}

static int filter_processes(struct process *processes,
			    size_t n,
			    const char *filter,
			    struct process **filtered,
			    size_t *nfiltered)
{
	size_t i;
	int ret = 0;

	*filtered = NULL;
	*nfiltered = 0;

	for (i = 0; i < n; i++) {
		if (filter == NULL || strcmp(processes[i].mode, filter) == 0) {
			struct process *_filtered = realloc(*filtered, (*nfiltered + 1) * sizeof(**filtered));
			if (_filtered == NULL) {
				free_processes(*filtered, *nfiltered);
				*filtered = NULL;
				*nfiltered = 0;
				ret = AA_EXIT_INTERNAL_ERROR;
				break;
			}
			_filtered[*nfiltered].pid = strdup(processes[i].pid);
			_filtered[*nfiltered].profile = strdup(processes[i].profile);
			_filtered[*nfiltered].exe = strdup(processes[i].exe);
			_filtered[*nfiltered].mode = strdup(processes[i].mode);
			*filtered = _filtered;
			*nfiltered = *nfiltered + 1;
		}
	}
	return ret;
}

/**
 * Returns error code if AppArmor is not enabled
 */
static int simple_filtered_count(const char *filter) {
	size_t n;
	struct profile *profiles;
	int ret;

	ret = get_profiles(&profiles, &n);
	if (ret == 0) {
		size_t nfiltered;
		struct profile *filtered = NULL;
		ret = filter_profiles(profiles, n, filter, &filtered, &nfiltered);
		printf("%zd\n", nfiltered);
		free_profiles(filtered, nfiltered);
	}
	free_profiles(profiles, n);
	return ret;
}

static int simple_filtered_process_count(const char *filter) {
	size_t nprocesses, nprofiles;
        struct profile *profiles = NULL;
        struct process *processes = NULL;
        int ret;

        ret = get_profiles(&profiles, &nprofiles);
	if (ret != 0)
		return ret;
        ret = get_processes(profiles, nprofiles, &processes, &nprocesses);
        if (ret == 0) {
                size_t nfiltered;
                struct process *filtered = NULL;
                ret = filter_processes(processes, nprocesses, filter, &filtered, &nfiltered);
                printf("%zd\n", nfiltered);
                free_processes(filtered, nfiltered);
        }
        free_profiles(profiles, nprofiles);
	free_processes(processes, nprocesses);
        return ret;
}

static int cmd_enabled(__unused const char *command) {
	int res = aa_is_enabled();
	return res == 1 ? 0 : 1;
}


static int cmd_profiled(__unused const char *command) {
	return simple_filtered_count(NULL);
}

static int cmd_enforced(__unused const char *command) {
	return simple_filtered_count("enforce");
}

static int cmd_complaining(__unused const char *command) {
	return simple_filtered_count("complain");
}

static int cmd_kill(__unused const char *command) {
        return simple_filtered_count("kill");
}

static int cmd_unconfined(__unused const char *command) {
        return simple_filtered_count("unconfined");
}

static int cmd_process_mixed(__unused const char *command) {
        return simple_filtered_process_count("mixed");
}


static int compare_processes_by_profile(const void *a, const void *b) {
	return strcmp(((struct process *)a)->profile,
                      ((struct process *)b)->profile);
}

static int compare_processes_by_executable(const void *a, const void *b) {
	return strcmp(((struct process *)a)->exe,
                      ((struct process *)b)->exe);
}

static int detailed_output(FILE *json) {
	size_t nprofiles = 0, nprocesses = 0;
	struct profile *profiles = NULL;
	struct process *processes = NULL;
	const char *profile_statuses[] = {"enforce", "complain", "kill", "unconfined"};
	const char *process_statuses[] = {"enforce", "complain", "unconfined", "mixed", "kill"};
	int ret;
	size_t i;

	ret = get_profiles(&profiles, &nprofiles);
	if (ret != 0) {
		goto exit;
	}
	ret = get_processes(profiles, nprofiles, &processes, &nprocesses);
	if (ret != 0) {
		dfprintf(stderr, "Failed to get processes: %d....\n", ret);
		goto exit;
	}

	if (json) {
		fprintf(json, "{\"version\": \"%s\", \"profiles\": {", aa_status_json_version);
	} else {
		dprintf("%zd profiles are loaded.\n", nprofiles);
	}

	for (i = 0; i < ARRAY_SIZE(profile_statuses); i++) {
		size_t nfiltered = 0, j;
		struct profile *filtered = NULL;
		ret = filter_profiles(profiles, nprofiles, profile_statuses[i], &filtered, &nfiltered);
		if (ret != 0) {
			goto exit;
		}
		if (!json) {
			dprintf("%zd profiles are in %s mode.\n", nfiltered, profile_statuses[i]);
		}

		for (j = 0; j < nfiltered; j++) {
			if (json) {
				fprintf(json, "%s\"%s\": \"%s\"",
				       i == 0 && j == 0 ? "" : ", ", filtered[j].name, profile_statuses[i]);
			} else {
				dprintf("   %s\n", filtered[j].name);
			}
		}

		free_profiles(filtered, nfiltered);
	}
	if (json) {
		fprintf(json, "}, \"processes\": {");
	} else {
		dprintf("%zd processes have profiles defined.\n", nprocesses);
	}

	for (i = 0; i < ARRAY_SIZE(process_statuses); i++) {
		size_t nfiltered = 0, j;
		struct process *filtered = NULL;
		ret = filter_processes(processes, nprocesses, process_statuses[i], &filtered, &nfiltered);
		if (ret != 0) {
			goto exit;
		}
		if (!json) {
			if (strcmp(process_statuses[i], "unconfined") == 0) {
				dprintf("%zd processes are unconfined but have a profile defined.\n", nfiltered);
			} else {
				dprintf("%zd processes are in %s mode.\n", nfiltered, process_statuses[i]);
			}
		}

		if (!json) {
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_profile);
			for (j = 0; j < nfiltered; j++) {
				dprintf("   %s (%s) %s\n", filtered[j].exe, filtered[j].pid,
					// hide profile name if matches executable
					(strcmp(filtered[j].profile, filtered[j].exe) == 0 ?
					 "" :
					 filtered[j].profile));
			}
		} else {
			// json output requires processes to be grouped per executable
			qsort(filtered, nfiltered, sizeof(*filtered), compare_processes_by_executable);
			for (j = 0; j < nfiltered; j++) {
				if (j > 0 && strcmp(filtered[j].exe, filtered[j - 1].exe) == 0) {
					// same executable
					fprintf(json, ", {\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       filtered[j].profile, filtered[j].pid, filtered[j].mode);
				} else {
					fprintf(json, "%s\"%s\": [{\"profile\": \"%s\", \"pid\": \"%s\", \"status\": \"%s\"}",
					       // first element will be a unique executable
					       i == 0 && j == 0 ? "" : "], ",
					       filtered[j].exe, filtered[j].profile, filtered[j].pid, filtered[j].mode);
				}

			}
		}
		free_processes(filtered, nfiltered);
	}
	if (json) {
		fprintf(json, "%s}}\n", nprocesses > 0 ? "]" : "");
	}

exit:
	free_processes(processes, nprocesses);
	free_profiles(profiles, nprofiles);
	return ret == 0 ? (nprofiles > 0 ? AA_EXIT_ENABLED : AA_EXIT_NO_POLICY) : ret;
}

static int cmd_json(__unused const char *command) {
	detailed_output(stdout);
	return 0;
}

static int cmd_pretty_json(__unused const char *command) {
	autofree char *buffer = NULL;
	autofree char *pretty = NULL;
	cJSON *json;
	FILE *f;	/* no autofclose - want explicit close to sync */
	size_t size;
	int ret;

	f = open_memstream(&buffer, &size);
	if (!f) {
		dfprintf(stderr, "Failed to open memstream: %m\n");
		return AA_EXIT_INTERNAL_ERROR;
	}

	ret = detailed_output(f);
	fclose(f);
	if (ret)
		return ret;

	json = cJSON_Parse(buffer);
	if (!json) {
		dfprintf(stderr, "Failed to parse json output");
		return AA_EXIT_INTERNAL_ERROR;
	}

	pretty = cJSON_Print(json);
	if (!pretty) {
		dfprintf(stderr, "Failed to print pretty json");
		return AA_EXIT_INTERNAL_ERROR;
	}
	fprintf(stdout, "%s\n", pretty);

	return AA_EXIT_ENABLED;
}

static int cmd_verbose(__unused const char *command) {
	verbose = 1;
	return detailed_output(NULL);
}

static int print_usage(const char *command)
{
	printf("Usage: %s [OPTIONS]\n"
	 "Displays various information about the currently loaded AppArmor policy.\n"
	 "OPTIONS (one only):\n"
	 "  --enabled       returns error code if AppArmor not enabled\n"
	 "  --profiled      prints the number of loaded policies\n"
	 "  --enforced      prints the number of loaded enforcing policies\n"
	 "  --complaining   prints the number of loaded non-enforcing policies\n"
	 "  --kill          prints the number of loaded enforcing policies that kill tasks on policy violations\n"
	 "  --special-unconfined   prints the number of loaded non-enforcing policies in the special unconfined mode\n"
	 "  --process-mixed prints the number processes with mixed profile modes\n"
	 "  --json          displays multiple data points in machine-readable JSON format\n"
	 "  --pretty-json   same data as --json, formatted for human consumption as well\n"
	 "  --verbose       (default) displays multiple data points about loaded policy set\n"
	 "  --help          this message\n",
	 command);
	return 0;
}

struct command {
	const char * const name;
	int (*cmd)(const char *command);
};

static struct command commands[] = {
	{"--enabled", cmd_enabled},
	{"--profiled", cmd_profiled},
	{"--enforced", cmd_enforced},
	{"--complaining", cmd_complaining},
	{"--kill", cmd_kill},
	{"--special-unconfined", cmd_unconfined},
	{"--process-mixed", cmd_process_mixed},
	{"--json", cmd_json},
	{"--pretty-json", cmd_pretty_json},
	{"--verbose", cmd_verbose},
	{"-v", cmd_verbose},
	{"--help", print_usage},
	{"-h", print_usage},
};

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;
	int _ret;
	int (*cmd)(const char*) = cmd_verbose;

	if (argc > 2) {
		dfprintf(stderr, "Error: Too many options.\n");
		cmd = print_usage;
		ret = EXIT_FAILURE;
	} else if (argc == 2) {
		int (*_cmd)(const char*) = NULL;
		size_t i;
		for (i = 0; i < ARRAY_SIZE(commands); i++) {
			if (strcmp(argv[1], commands[i].name) == 0) {
				_cmd = commands[i].cmd;
				break;
			}
		}
		if (_cmd == NULL) {
			dfprintf(stderr, "Error: Invalid command.\n");
			cmd = print_usage;
			ret = EXIT_FAILURE;
		} else {
			cmd = _cmd;
		}
	}

	_ret = cmd(argv[0]);
	exit(ret == EXIT_FAILURE ? ret : _ret);
}
