#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sched.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>

#include <lxc/lxccontainer.h>

#include "extra_syscalls.h"
#include "options.h"
#include "containerpaths.h"
#include "container.h"
#include "monitor.h"
#include "lxcfs.h"

int main(
		int argc,
		char **argv)
{
	struct lxcfs_key ref = {};
	setlinebuf(stdout);
	setlinebuf(stderr);

	/* Determine if the program will even work. */
	check_kernel_compatibility();

	options_parse(argc, argv);

	/* Determine number of lxcfs instances started */
	lxcfs_instance_scan();

	/* Retrieve a list of paths that provide containers */
	containerpaths_init();

	/* Ready an initial check */
	if (lxcfs_select(&ref) < 0) {
		fprintf(stderr, "Cannot find working instance of lxcfs!\n");
		exit(EXIT_FAILURE);
	}
	container_check(&ref);

	if (!options_monitor())
		while (container_process());
	else
		monitor_run();

done:
	lxcfs_instance_destroy();
	containerpaths_destroy();
	options_destroy();
	exit(EXIT_SUCCESS);
}
