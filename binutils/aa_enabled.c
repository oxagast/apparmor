/*
 *   Copyright (C) 2015 Canonical Ltd.
 *
 *   This program is free software; you can redistribute it and/or
 *    modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 */

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#define _(s) gettext(s)

#include <sys/apparmor.h>

void print_help(const char *command)
{
	printf(_("%s: [options]\n"
		 "  options:\n"
		 "  -x | --exclusive    Shared interfaces must be available\n"
		 "  -q | --quiet        Don't print out any messages\n"
		 "  -h | --help         Print help\n"),
	       command);
	exit(1);
}


/* Exit statuses and meanings are documented in the aa-enabled.pod file */
static void exit_with_error(int saved_errno, int quiet)
{
	switch(saved_errno) {
	case ENOSYS:
		if (!quiet)
			printf(_("No - not available on this system.\n"));
		exit(1);
	case ECANCELED:
		if (!quiet)
			printf(_("No - disabled at boot.\n"));
		exit(1);
	case ENOENT:
		if (!quiet)
			printf(_("Maybe - policy interface not available.\n"));
		exit(3);
	case EPERM:
	case EACCES:
		if (!quiet)
			printf(_("Maybe - insufficient permissions to determine availability.\n"));
		exit(4);
	case EBUSY:
		if (!quiet)
			printf(_("Partially - public shared interfaces are not available.\n"));
		exit(10);
	}
	if (!quiet)
		printf(_("Error - %s\n"), strerror(saved_errno));
	exit(64);
}

int main(int argc, char **argv)
{
	int i, enabled;
	int quiet = 0;
	int require_shared = 0;

	setlocale(LC_MESSAGES, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	if (argc > 3) {
		printf(_("unknown or incompatible options\n"));
		print_help(argv[0]);
	}
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--quiet") == 0 ||
		    strcmp(argv[i], "-q") == 0) {
			quiet = 1;
		} else if (strcmp(argv[i], "--exclusive") == 0 ||
		    strcmp(argv[i], "-x") == 0) {
			require_shared = 1;
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			print_help(argv[0]);
		} else {
			printf(_("unknown option '%s'\n"), argv[1]);
			print_help(argv[0]);
		}
	}

	enabled = aa_is_enabled();
	if (!enabled) {
		if (require_shared || errno != EBUSY)
			exit_with_error(errno, quiet);
	}
	if (!quiet)
		printf(_("Yes\n"));
	exit(0);
}
