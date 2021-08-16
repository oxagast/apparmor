/*
 * Copyright (C) 2015, 2019 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Canonical Ltd.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/apparmor.h>

#define OPT_NEW			"new"
#define OPT_CACHE_DIR		"cache-dir"
#define OPT_REMOVE		"remove"
#define OPT_REMOVE_POLICY	"remove-policy"
#define OPT_REPLACE_ALL		"replace-all"
#define OPT_FLAG_MAX_CACHES	"--max-caches"

static void usage(const char *prog)
{
	fprintf(stderr,
		"FAIL - usage: %s %s [%s N] <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PATH>\n"
		"              %s %s <PROFILE_NAME>\n"
		"              %s %s [%s N] <PATH>\n",
		prog, OPT_NEW, OPT_FLAG_MAX_CACHES,
		prog, OPT_CACHE_DIR,
		prog, OPT_REMOVE,
		prog, OPT_REMOVE_POLICY,
		prog, OPT_REPLACE_ALL, OPT_FLAG_MAX_CACHES);
}

static int test_new(const char *path, uint16_t max_caches)
{
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_policy_cache_new(&policy_cache, NULL,
				AT_FDCWD, path, max_caches)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	rc = 0;
out:
	aa_policy_cache_unref(policy_cache);
	return rc;
}

#ifdef COMPAT_PATH_PREVIEW

static char *path_from_fd(int fd)
{
	char *proc_path = NULL;
	char *path = NULL;
	int proc_fd = -1;
	struct stat proc_stat;
	ssize_t size, path_len;

	if (asprintf(&proc_path, "/proc/self/fd/%d", fd) == -1) {
		proc_path = NULL;
		errno = ENOMEM;
		goto err;
	}

	proc_fd = open(proc_path, O_RDONLY | O_CLOEXEC | O_PATH | O_NOFOLLOW);
	if (proc_fd == -1)
		goto out;

	if (fstat(proc_fd, &proc_stat) == -1)
		goto err;

	if (!S_ISLNK(proc_stat.st_mode)) {
		errno = EINVAL;
		goto err;
	}

	size = proc_stat.st_size;
repeat:
	path = malloc(size + 1);
	if (!path)
		goto err;

	/**
	 * Since 2.6.39, symlink file descriptors opened with
	 * (O_PATH | O_NOFOLLOW) can be used as the dirfd with an empty string
	 * as the path. readlinkat() will operate on the symlink inode.
	 */
	path_len = readlinkat(proc_fd, "", path, size);
	if (path_len == -1)
		goto err;
	if (path_len == size) {
		free(path);
		size = size * 2;
		goto repeat;
	}
	path[path_len] = '\0';
	goto out;
err:
	free(path);
out:
	free(proc_path);
	return path;
}

static char *aa_policy_cache_dir_path_preview(aa_features *kernel_features,
					      int dirfd, const char *path)
{
	char *cache_loc = NULL;
	char *dir_path;

	if (dirfd != AT_FDCWD) {
		cache_loc = path_from_fd(dirfd);
		if (!cache_loc)
			return NULL;
	}

	if (asprintf(&dir_path, "%s%s%s", cache_loc ? cache_loc : "",
		     cache_loc ? "/" : "", path) < 0)
		dir_path = NULL;

	free(cache_loc);
	return dir_path;
}

#endif /* COMPAT_PATH_PREVIEW */

static int test_cache_dir(const char *path)
{
	char *cache_dir;
	int rc = 1;

	cache_dir = aa_policy_cache_dir_path_preview(NULL, AT_FDCWD, path);
	if (!cache_dir) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	printf("%s\n", cache_dir);
	rc = 0;
out:
	free(cache_dir);
	return rc;
}

static int test_remove(const char *path)
{
	int rc = 1;

	if (aa_policy_cache_remove(AT_FDCWD, path)) {
		perror("FAIL - aa_policy_cache_remove");
		goto out;
	}

	rc = 0;
out:
	return rc;
}

static int test_remove_policy(const char *name)
{
	aa_kernel_interface *kernel_interface = NULL;
	int rc = 1;

	if (aa_kernel_interface_new(&kernel_interface, NULL, NULL)) {
		perror("FAIL - aa_kernel_interface_new");
		goto out;
	}

	if (aa_kernel_interface_remove_policy(kernel_interface, name)) {
		perror("FAIL - aa_kernel_interface_remove_policy");
		goto out;
	}

	rc = 0;
out:
	aa_kernel_interface_unref(kernel_interface);
	return rc;
}

static int test_replace_all(const char *path, uint16_t max_caches)
{
	aa_policy_cache *policy_cache = NULL;
	int rc = 1;

	if (aa_policy_cache_new(&policy_cache, NULL,
				AT_FDCWD, path, max_caches)) {
		perror("FAIL - aa_policy_cache_new");
		goto out;
	}

	if (aa_policy_cache_replace_all(policy_cache, NULL)) {
		perror("FAIL - aa_policy_cache_replace_all");
		goto out;
	}

	rc = 0;
out:
	aa_policy_cache_unref(policy_cache);
	return rc;
}

int main(int argc, char **argv)
{
	uint16_t max_caches = 0;
	const char *str = NULL;
	bool show_pass = true;
	int rc = 1;

	if (!(argc == 3 || argc == 5)) {
		usage(argv[0]);
		exit(1);
	}

	str = argv[argc - 1];

	if (argc == 5) {
		unsigned long tmp;

		errno = 0;
		tmp = strtoul(argv[3], NULL, 10);
		if ((errno == ERANGE && tmp == ULONG_MAX) ||
		    (errno && tmp == 0)) {
			perror("FAIL - strtoul");
			exit(1);
		}

		if (tmp > UINT16_MAX) {
			fprintf(stderr, "FAIL - %lu larger than UINT16_MAX\n",
				tmp);
			exit(1);
		}

		max_caches = tmp;
	}

	if (strcmp(argv[1], OPT_NEW) == 0) {
		rc = test_new(str, max_caches);
	} else if (strcmp(argv[1], OPT_CACHE_DIR) == 0 && argc == 3) {
		show_pass = false;
		rc = test_cache_dir(str);
	} else if (strcmp(argv[1], OPT_REMOVE) == 0 && argc == 3) {
		rc = test_remove(str);
	} else if (strcmp(argv[1], OPT_REMOVE_POLICY) == 0 && argc == 3) {
		rc = test_remove_policy(str);
	} else if (strcmp(argv[1], OPT_REPLACE_ALL) == 0) {
		rc = test_replace_all(str, max_caches);
	} else {
		usage(argv[0]);
	}

	if (show_pass && !rc)
		printf("PASS\n");

	exit(rc);
}
