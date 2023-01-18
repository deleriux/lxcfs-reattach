#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>

#include "config.h"
#include "options.h"

static struct {
	int monitor;
	int dry;
	int all;
	int verbose;
	pid_t pid;
	int num_containers;
	char **names;
} config;

static inline void print_help(
		void)
{
	printf("%s [OPTIONS] { --all | --monitor | CONTAINER ... }\n",
			PACKAGE_NAME);
	printf("Re-attach LXCFS bind mounts to containers\n\n");
	printf("OPTIONS\n");
	printf(" -a    --all            Scan all containers.\n");
	printf(" -v    --verbose        Print verbose output.\n");
	printf(" -V    --version        Print version.\n");
	printf(" -p    --pid PID        Use this PID for LXCFS discovery\n");
	printf(" -n    --dry-run        Do not apply any changes. "
			"Just inspect.\n");
	printf(" -m    --monitor        Monitor mode (implies --all).\n");
	printf(" -h    --help           Print this help.\n");
	printf("\n");
}

void options_parse(
		int argc,
		char **argv)
{
	/* Setup defaults for config */
	config.monitor = 0,
	config.dry = 0;
	config.verbose = 0;
	config.all = 0;
	config.num_containers = 0;
	config.names = NULL;
	config.pid = -1;

	static struct option long_options[] = {
		{"all",		no_argument,		NULL,	'a'},
		{"dry-run",	no_argument,		NULL,	'n'},
		{"help",	no_argument,		NULL,	'h'},
		{"monitor",	no_argument,		NULL,	'm'},
		{"pid",		required_argument,	NULL,	'm'},
		{"verbose",	no_argument,		NULL,	'v'},
		{"version",	no_argument,		NULL,	'V'},
		{						},
	};

	int c;
	int rc;
	int optidx;
	int n;

	while (1) {
		c = getopt_long(argc, argv, "anhvVmp:", long_options, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		break;

		case 'v':
			config.verbose = 1;
		break;

		case 'V':
			printf("%s\n", PACKAGE_STRING);
			printf("Bugs: %s\n", PACKAGE_BUGREPORT);
			exit(EXIT_SUCCESS);
		break;

		case 'n':
			config.dry = 1;
		break;

		case 'a':
			config.all = 1;
		break;

		case 'm':
			config.monitor = 1;
			config.all = 1;
		break;

		case 'p':
			config.pid = atoi(optarg);
		break;

		default:
			print_help();
			exit(EXIT_FAILURE);
		break;

		}
	}

	/* If a pid is offered, test for its validity and existence */
	if (config.pid == 0) {
		fprintf(stderr, "PID supplied was invalid.\n");
		exit(EXIT_FAILURE);
	}
	else if (config.pid > 0) {
		if (kill(config.pid, 0) < 0) {
			fprintf(stderr, "Cannot use PID %d: %m\n", config.pid);
			exit(EXIT_FAILURE);
		}
	}

	/* A container name must have been passed in this circumstance */
	if (!config.all && optind >= argc) {
		fprintf(stderr, "You must either pass --all "
				"or a list of containers to process.\n");
		exit(EXIT_FAILURE);
	}
	/* Must not in this circumstance */
	else if (config.all && optind < argc) {
		fprintf(stderr, "You cannot pass a container with --all "
				"or --monitor\n");
		exit(EXIT_FAILURE);
	}

	if (config.dry && config.monitor) {
		fprintf(stderr, "You cannot pass both --dry and --monitor\n");
		exit(EXIT_FAILURE);
	}

	config.num_containers = argc - optind;
	config.names = calloc(config.num_containers, sizeof(char *));
	if (!config.names) {
		fprintf(stderr, "Cannot reserve space for container names: %m\n");
		exit(EXIT_FAILURE);
	}
	
	n = 0;
	for (int i=optind; i < argc; i++) {
		config.names[n] = strdup(argv[i]);
		if (!config.names[n]) {
			fprintf(stderr, "Cannot reserve container name: %m\n");
			exit(EXIT_FAILURE);
		}
		n++;
	}

	return;
}

void options_destroy(
    void)
{
	for (int i=0; i < config.num_containers; i++) 
		free(config.names[i]);
	free(config.names);
}

int options_have_name(
		const char *needle)
{
	if (config.all)
		return 1;
  
	for (int i=0; i < config.num_containers; i++) {
		if (strcmp(needle, config.names[i]) == 0)
			return 1;
	}

	return 0;
}

int options_verbose(
		void)
{
	return config.verbose;
}

int options_dry(
		void)
{
	return config.dry;
}

int options_monitor(
		void)
{
	return config.monitor;
}

int options_pid(
		void)
{
	return config.pid;
}
