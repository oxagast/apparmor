#include <sys/types.h>

/*
 *	Copyright (C) 2018 Canonical, Ltd.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2 of the
 *	License.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
 * NAME xattr_profile
 * DESCRIPTION this test asserts that it's running under a specific apparmor
 * profile
 */
int main(int argc, char *argv[])
{
	FILE *fd;
	ssize_t n;
	size_t len = 0;
	char *line;
	char *token;
	const char *path = "/proc/self/attr/current";

	if (argc != 2) {
		fprintf(stderr, "usage: %s apparmor-profile\n", argv[0]);
		return 1;
	}

	fd = fopen(path, "r");
	if (fd == NULL) {
		fprintf(stderr, "failed to open %s: %s", path, strerror(errno));
		return 1;
	}

	if ((n = getline(&line, &len, fd)) == -1) {
		fprintf(stderr, "failed to read %s: %s", path, strerror(errno));
		fclose(fd);
		return 1;
	}
	fclose(fd);
	if ((token = strsep(&line, "\n")) != NULL) {
		line = token;
	}

	// Get name of profile without "(complain)" or similar suffix
	if ((token = strsep(&line, " ")) != NULL) {
		line = token;
	}

	if (strcmp(line, argv[1])) {
		printf("FAILED: run as profile %s, expected %s\n",
		       line, argv[1]);
		return 1;
	}

	printf("PASS\n");
	return 0;
}
