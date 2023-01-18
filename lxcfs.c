#include <common.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <libgen.h>
#include <mntent.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "container.h"
#include "lxcfs.h"
#define CMDLINE_GLOB "/proc/*/cmdline"

#define MAX_ARGS 16

SLIST_HEAD(lxcfs_head, lxcfs_instance);
static struct lxcfs_head head;
static int lxcfs_instances = 0;
static int lxcfs_dirs = 0;

static inline int has_working_directory(
		struct lxcfs_instance *in)
{
	int fd = -1;
	for (int i=0; i < in->n_directories; i++) {
		if (!in->directory[i].mounted)
			continue;

		if (setns(in->mntns, CLONE_NEWNS) < 0) {
			fprintf(stderr, "Cannot switch instance namespace: %m");
			continue;
		}

		/* Test if it actually works */
		fd = openat(in->directory[i].fd, "proc/cpuinfo",
					O_RDONLY|O_CLOEXEC);
		if (fd < 0) {
			in->directory[i].mounted = false;
			continue;
		}

		close(fd);
		return i;
	}

	return -1;
}

static inline int find_mount(
		FILE *mounts,
		char *mntdir)
{
	char buf[1024] = {0};
	struct mntent *mnt = NULL, mntbuf = {0};

	rewind(mounts);

	while (mnt = getmntent_r(mounts, &mntbuf, buf, 1024)) {
		if (strcmp(mnt->mnt_dir, mntdir) != 0)
			continue;

		if (strcmp(mnt->mnt_type, LXCFS_FSTYPE) != 0)
			continue;

		return 1;
	}

	return 0;
}

static inline void clear_lxcfs_directories(
		struct lxcfs_instance *in)
{
	if (!in)
		return;

	for (int i=0; i < in->n_directories; i++) {
		if (in->directory[i].path)
			free(in->directory[i].path);

		if (in->directory[i].fd >= 0)
			close(in->directory[i].fd);
	}
}

static inline int add_lxcfs_directory(
	       struct lxcfs_instance *in,
	       char *dir)
{
	int n = in->n_directories;

	if (n >= MAX_PATHS) {
		fprintf(stderr, "Too many directories to manage in %p\n", in);
		return -1;
	}

	in->directory[n].path = NULL;
	in->directory[n].fd = -1;
	in->directory[n].mounted = 0;

	/* Be sure to be in the right namespace */
	if (setns(in->mntns, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Cannot switch into instance namespace: %m\n");
		return -1;
	}

	/* Need to resolve the canonical path we are inspecting, its not always
	 * the one placed in the lxcfs command line and /proc/self/mounts 
	 * always produces the canonical path */
	in->directory[n].path = realpath(dir, NULL);
	if (!in->directory[n].path) {
		fprintf(stderr, "Cannot resolve instance directory %s: %m\n",
				dir);
		return -1;
	}

	in->directory[n].fd = open(in->directory[n].path,
			O_RDONLY|O_CLOEXEC|O_DIRECTORY);
	if (in->directory[n].fd < 0) {
		fprintf(stderr, "Cannot open base directory %s: %m\n",
				in->directory[n].path);
		free(in->directory[n].path);
		return -1;
	}

	in->directory[n].mounted =
		find_mount(in->mounts, in->directory[n].path);

	in->n_directories++;
	lxcfs_dirs++;

	return 0;
}

static inline void reopen_lxcfs_fd(
		struct lxcfs_instance *in,
		int idx)
{
	/* unlikely */
	if (in->directory[idx].fd >= 0)
		close(in->directory[idx].fd);

	if (setns(in->mntns, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Cannot switch to lxcfs namespace: %m\n");
		exit(EXIT_FAILURE);
	}

	in->directory[idx].fd = open(in->directory[idx].path,
			O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (in->directory[idx].fd < 0) {
		fprintf(stderr, "Cannot reopen LXCFS mount point: %m\n");
		exit(EXIT_FAILURE);
	}
}

static inline void cmdline_to_lxcfs_mnt_dir(
		char *buf,
		char dir[1024])
{
	char *p = buf;
	char *argv[2048] = {0};
	int c, idx;
	int argc = 0;

	/* Ripped from lxcfs sources.. */
	static const struct option lopts[] = {
	        {"debug",               no_argument,            0,      'd'     },
	        {"disable-swap",        no_argument,            0,      'u'     },
	        {"enable-loadavg",      no_argument,            0,      'l'     },
	        {"foreground",          no_argument,            0,      'f'     },
	        {"help",                no_argument,            0,      'h'     },
	        {"version",             no_argument,            0,      'v'     },

        	{"enable-cfs",          no_argument,            0,        0     },
	        {"enable-pidfd",        no_argument,            0,        0     },

        	{"pidfile",             required_argument,      0,      'p'     },
	        {                                                               },
	};

	/* format the args */
	while ((*p)) {
		argv[argc] = p;
		p += strlen(p) + 1;
		argc++;
	}

	/* our own run of getopt sets this value too, so reset it */
	optind = 1;

	while (true) {
		c = getopt_long(argc, argv, "dulfhvso:p:", lopts, &idx);
		if (c < 0)
			break;

		switch (c) {
		case 0:
			if (strcmp(lopts[idx].name, "enable-pidfd") == 0)
				continue;
			if (strcmp(lopts[idx].name, "enable-cfs") == 0)
				continue;
		break;

		case 'd':
		case 'u':
		case 'l':
		case 'f':
		case 'h':
		case 'v':
		case 's':
		case 'o':
		case 'p':
			continue;
		break;

		default:
			fprintf(stderr, "Unknown lxcfs argument #%d in "
					"command line.\n", idx);
			exit(EXIT_FAILURE);
		break;

		}
	}

	/* Remaining arg should be a mandatory argument indicating 
	 * mount point */
	strncpy(dir, argv[optind], 1024);
}

static inline int lxcfs_arg0_matched(
		const char *path,
		char buf[4096])
{
	size_t sz;
	FILE *fp = NULL;

	memset(buf, 0, 4096);

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %m\n", path);
		goto fail;
	}

	/* Some files are 0 bytes */
	if (feof(fp))
		goto fail;

	sz = fread(buf, 1, 4096, fp);
	if (ferror(fp)) {
		fprintf(stderr, "Cannot read %s: %m\n", path);
		goto fail;
	}

	/* cmdline is \0 delimeted so strcmp() will match nicely */
	if (strcmp(LXCFS_PROCESS, basename(buf)) != 0)
		goto fail;

	fclose(fp);
	return 1;

fail:
	if (fp)
		fclose(fp);
	return 0;
}

static inline pid_t procpath_to_pid(
		char *path)
{
	pid_t pid;
	int rc;

	rc = sscanf(path, "/proc/%d/cmdline", &pid);
	if (rc != 1)
		return -1;

	return pid;
}

static inline int same_pid_namespace(
		char *cmdline,
		long unsigned int pidns_id)
{
	struct stat st;
	char tmp[64] = {0};
	pid_t pid;

	pid = procpath_to_pid(cmdline);
	if (pid < 0)
		return -1;

	snprintf(tmp, 64, "/proc/%d/ns/pid", pid);
	if (stat(tmp, &st) < 0) {
		fprintf(stderr, "Could not stat %s: %m\n", tmp);
		return -1;
	}

	return (pidns_id == st.st_ino);
}

static inline struct lxcfs_instance * lxcfs_instance_find(
		pid_t pid)
{
	char tmp[256] = {0};
	struct stat st;
	struct lxcfs_instance *in;

	/* We actually match on the mount namespace ID of the
	 * lxcfs instance, we just use the pid to get there */
	snprintf(tmp, 256, "/proc/%d/ns/mnt", pid);
	if (stat(tmp, &st) < 0) {
		fprintf(stderr, "Cannot stat %s: %m\n", tmp);
		return NULL;
	}

	SLIST_FOREACH(in, &head, e) {
		if (in->mntns_id == st.st_ino)
			return in;
	}

	return NULL;
}

static inline struct lxcfs_instance * lxcfs_instance_create(
		pid_t pid,
		char *dir)
{
	char tmp[256] = {0};	
	struct stat st;
	struct lxcfs_instance *in = NULL;

	in = calloc(1, sizeof(struct lxcfs_instance));
	if (!in)
		return NULL;
	in->mounts = NULL;
	in->mntns_id = -1;
	in->mntns = -1;

	/* Get mount nsid */
	snprintf(tmp, 256, "/proc/%d/ns/mnt", pid);
	if (stat(tmp, &st) < 0) {
		fprintf(stderr, "Cannot get mount namespace id %s: %m\n", tmp);
		goto fail;
	}

	in->mntns_id = st.st_ino;
	in->mntns = open(tmp, O_RDONLY|O_CLOEXEC);
	if (in->mntns < 0) {
		fprintf(stderr, "Cannot open mount namespace %s: %m\n", tmp);
		goto fail;
	}

	memset(tmp, 0, sizeof(tmp));
	snprintf(tmp, 256, "/proc/%d/mounts", pid);
	in->mounts = setmntent(tmp, "r");
	if (!in->mounts) {
		fprintf(stderr, "Cannot open mounts %s: %m\n", tmp);
		goto fail;
	}

	if (add_lxcfs_directory(in, dir) < 0)
		goto fail;

	/* Append to head */
	SLIST_INSERT_HEAD(&head, in, e);
	lxcfs_instances++;

	return in;
fail:
	if (in->mounts)
		endmntent(in->mounts);
	if (in->mntns >= 0)
		close(in->mntns);
	if (in->directory[0].path)
		free(in->directory[0].path);
	if (in->directory[0].fd >= 0)
		close(in->directory[0].fd);
	free(in);
	return NULL;
}

static int lxcfs_instance_setup(
		char *path,
		char *cmdline)
{
	char dir[1024] = {0};

	struct lxcfs_instance *in = NULL;
	pid_t pid = -1;

	pid = procpath_to_pid(path);
	cmdline_to_lxcfs_mnt_dir(cmdline, dir);

	in = lxcfs_instance_find(pid);
	if (!in) {
		in = lxcfs_instance_create(pid, dir);
		if  (!in)
			return -1;
	}
	else {
		if (add_lxcfs_directory(in, dir) < 0)
			return -1;
	}

	return 0;
}

void lxcfs_instance_scan()
{
	struct stat st;
	char tmp[64] = {0};
	long unsigned int pidns_id;
	int rc;
	glob_t matches;
	SLIST_INIT(&head);

	if (stat("/proc/self/ns/pid", &st) < 0) {
		fprintf(stderr, "Cannot fetch own pid namespace: %m");
		exit(EXIT_FAILURE);
	}
	pidns_id = st.st_ino;

	if (options_pid() < 0)
		strcpy(tmp, "/proc/*/cmdline");
	else
		snprintf(tmp, 64, "/proc/%d/cmdline", options_pid());

	rc = glob(tmp, GLOB_NOSORT, NULL, &matches);
	if (rc != 0) {
		if (rc == GLOB_NOMATCH) {
			fprintf(stderr, "Cannot find matching pattern. is "
					"\"/proc\" mounted?\n");
			exit(EXIT_FAILURE);
		}
	}

	verbose("Scanning %lu processes for lxcfs.\n", matches.gl_pathc);

	for (int i=0; i < matches.gl_pathc; i++) {
		char buf[4096];

		if (lxcfs_arg0_matched(matches.gl_pathv[i], buf) <= 0)
			continue;

		/* Do not descend into any other pid namespaces but our own */
		if (same_pid_namespace(matches.gl_pathv[i], pidns_id) <= 0)
			continue;

		if (lxcfs_instance_setup(matches.gl_pathv[i], buf) < 0)
			goto fail;
	}

	if (lxcfs_dirs == 0) {
		fprintf(stderr, "Error: There are no discovered LXCFS mount "
				"points or no lxcfs process is running.\n");
		exit(EXIT_FAILURE);
	}

	verbose("Discovered %d LXCFS mountpoints over %d namespaces.\n",
			lxcfs_dirs, lxcfs_instances);

	globfree(&matches);
	return;

fail:
	globfree(&matches);
	exit(EXIT_FAILURE);
}

void lxcfs_update_mount_state(
		int fd)
{
	struct lxcfs_instance *in = NULL;

	/* Attempt to locate instance based off of FD */
	SLIST_FOREACH(in, &head, e) {
		if (fileno(in->mounts) == fd)
			break;
	}

	if (!in)
		return;

	/* Move into instance namespace */
	if (setns(in->mntns, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Error: Cannot switch into instance "
				"namespace: %m\n");
		exit(EXIT_FAILURE);
	}

	for (int i=0; i < in->n_directories; i++) {
		struct lxcfs_key key;
		bool old = in->directory[i].mounted;

		in->directory[i].mounted =
			find_mount(in->mounts, in->directory[i].path);

		if  (old == false && in->directory[i].mounted == true) {
			printf("LXCFS path %s has re-appeared. "
					"Performing remount.\n",
					in->directory[i].path);

			reopen_lxcfs_fd(in, i);

			key.in = in;
			key.idx = i;
			container_check(&key);
		}
		else if (old == true && in->directory[i].mounted == false) {
			printf("LXCFS path %s has disappeared.\n",
					in->directory[i].path);

			close(in->directory[i].fd);
			in->directory[i].fd = -1;
		}
	}
}

void lxcfs_instance_destroy(void)
{
	struct lxcfs_instance *in = NULL;
	while (!SLIST_EMPTY(&head)) {
		in = SLIST_FIRST(&head);

		if (in->mounts)
			endmntent(in->mounts);
		if (in->mntns >= 0)
			close(in->mntns);

		clear_lxcfs_directories(in);
		SLIST_REMOVE(&head, in, lxcfs_instance, e);
		free(in);
	}
	lxcfs_dirs = 0;
	lxcfs_instances = 0;
}

int lxcfs_select(
		struct lxcfs_key *ref)
{
	int rc;
	struct lxcfs_instance *in = NULL;

	if (!ref)
		return -1;

	SLIST_FOREACH(in, &head, e) {
		rc = has_working_directory(in);
		if (rc < 0)
			return -1;
		ref->in = in;
		ref->idx = rc;
		return 0;
	}

	return -1;
}

int lxcfs_namespace(
		struct lxcfs_key *ref)
{
	if (!ref || !ref->in)
		return -1;

	if (setns(ref->in->mntns, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Cannot switch into lxcfs namespace: %m\n");
		return -1;
	}
	return 0;
}

int lxcfs_base_fd(
		struct lxcfs_key *ref)
{
	if (!ref || !ref->in)
		return -1;

	if (ref->idx < 0 || ref->idx >= ref->in->n_directories)
		return -1;

	return ref->in->directory[ref->idx].fd;
}

const char * lxcfs_base_dir(
		struct lxcfs_key *ref)
{
	if (!ref || !ref->in)
		return NULL;

	if (ref->idx < 0 || ref->idx >= ref->in->n_directories)
		return NULL;

	return ref->in->directory[ref->idx].path;
}

int lxcfs_poll_fds(
		int *fds,
		int sz)
{
	struct lxcfs_instance *in;
	int c = 0;

	/* If passing NULL in fds return size */
	if (!fds)
		return lxcfs_instances;

	if (sz <= 0)
		return -1;

	SLIST_FOREACH(in, &head, e) {
		if (c >= sz)
			return c;

		fds[c] = fileno(in->mounts);
		c++;
	}

	return c;
}
