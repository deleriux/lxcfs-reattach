#include "containerpaths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <regex.h>

#define CTREGEX "^[a-f0-9]+: [a-f0-9]+ 0+ [a-f0-9]+ 0001 [a-f0-9]+ [a-f0-9]+ @(.+?/command)$"
#define NETSTAT "/proc/self/net/unix"
#define MAX_PATHS 48

static char *container_paths[MAX_PATHS] = {0};
static int num_paths = 0;

static inline void insert_path(
		const char *path)
{
	for (int i=0; i < num_paths; i++) {
		if (strcmp(path, container_paths[i]) == 0)
			return;
	}

	if (num_paths >= MAX_PATHS) {
		fprintf(stderr, "Internal error: Too many paths!\n");
		exit(EXIT_FAILURE);
	}

	container_paths[num_paths] = strdup(path);
	if (!container_paths[num_paths]) {
		fprintf(stderr, "Internal error: "
				"Cannot add path to cache: %m\n");
		exit(EXIT_FAILURE);
	}

	num_paths++;
}

/* Heuristically determine a unique list of all paths
 * to all running containers, is LXD/LXC agnostic */
void containerpaths_init(
		void)
{
	int rc;
	char errbuf[256] = {0};
	FILE *netfile = NULL;
	regex_t reg;

	/* Build the regex */
	rc = regcomp(&reg, CTREGEX, REG_EXTENDED|REG_NEWLINE);
	if (rc) {
		regerror(rc, &reg, errbuf, 254);
		fprintf(stderr, "Internal error compiling regular expression: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* Open the network file and start extracting line by line */
	netfile = fopen(NETSTAT, "r");
	if (!netfile) {
		fprintf(stderr, "Cannot open %s: %m\n", NETSTAT);
		goto fail;
	}

	while (!feof(netfile) && !ferror(netfile)) {
		regmatch_t matches[2] = {0};
		int ss_len;
		char line[2048] = {0};

		if (!fgets(line, 2048, netfile))
			break;

		/* Evaluate the line against regex */
		if (regexec(&reg, line, 2, matches, 0) == REG_NOMATCH)
			continue;

		/* Overwrite line with just the substring we care for */
		ss_len = matches[1].rm_eo - matches[1].rm_so;
		memmove(line, &line[matches[1].rm_so], ss_len);
		line[ss_len] = 0;

		/* The container path is two elements up on the path. */
		dirname(line);
		dirname(line);

		/* confirm that this path exists and is accessible */
		if (access(line, R_OK|X_OK) < 0) {
			fprintf(stderr, "Error: Cannot access container path: %s: %m\n", line);
			goto fail;
		}

		insert_path((const char *)line);
	}

	verbose("Discovered %d paths to container roots\n", num_paths);

	regfree(&reg);
	fclose(netfile);
	return;

fail:
	regfree(&reg);
	fclose(netfile);
	exit(EXIT_FAILURE);
}

void containerpaths_destroy(
		void)
{
	for (int i=0; i < num_paths; i++)
		free(container_paths[i]);
 
	num_paths = 0;
}

int containerpaths_num(
		void)
{
	return num_paths;
}

const char * containerpaths_path(
    int n)
{
	if (n >= num_paths || n < 0)
		return NULL;

	return (const char *)container_paths[n];
}
