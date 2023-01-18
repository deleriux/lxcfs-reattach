#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <unistd.h>
#include <errno.h>
#include <lxc/lxccontainer.h>
#include <containerpaths.h>
#include "container.h"
#include "extra_syscalls.h"

#define CONTAINER_MAX_PATHS 64
#define OPEN_TREE_FLAGS AT_EMPTY_PATH|OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC

struct container_mount_entry {
	char path[2048];
	SLIST_ENTRY(container_mount_entry) e;
};
SLIST_HEAD(mount_head, container_mount_entry);

struct container {
	struct lxc_container *con;
	int pidfd;
	struct lxcfs_key key;

	struct mount_head mounts;
	size_t num_mounts;

	int (*work)(struct container *c);
	SLIST_ENTRY(container) e;
};

SLIST_HEAD(container_head, container);
static struct container_head head = SLIST_HEAD_INITIALIZER(container_head);

static int pending = 0;			/* number of containers awaiting work */
static int native_namespace = -1;	/* Must be in our initial namespace when scanning
					   this saves the namespace */

__attribute__((constructor))
static void container_init() {
	native_namespace = open("/proc/self/ns/mnt", O_RDONLY|O_CLOEXEC);
	if (native_namespace < 0) {
		fprintf(stderr, "Cannot obtain initial namespace. "
				"Cannot continue: %m");
		exit(EXIT_FAILURE);
	}
}

static inline int home_namespace(
		void)
{
	if (setns(native_namespace, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Cannot enter native namespace: %m\n");
		return -1;
	}
	return 0;
}

/* Remove container from list */
static inline void container_remove(
		struct container *c)
{
	struct container_mount_entry *me;
	if (!c)
		return;

	if (home_namespace() < 0)
		exit(EXIT_FAILURE);

	while (!SLIST_EMPTY(&c->mounts)) {
		me = SLIST_FIRST(&c->mounts);
		SLIST_REMOVE(&c->mounts, me, container_mount_entry, e);
		free(me);
		me = NULL;
	}
	lxc_container_put(c->con);

	SLIST_REMOVE(&head, c, container, e);
	free(c);
	pending--;
}

/* Fetches the fully formed path of the lxcfs directory we need to
 * rebind with */
static inline int get_path_fd(
		struct container *c,
		struct container_mount_entry *me)
{
	int base_fd = -1;
	int path_fd = -1;
	const char *path = NULL;

	base_fd = lxcfs_base_fd(&c->key);
	if (base_fd < 0) {
		fprintf(stderr, "LXCFS Base FD was invalid.\n");
		return -1;
	}

	/* When the path start as '/sys' or '/proc' trim the
	 * first byte off */
	if (strncmp("/proc/", me->path, 6) == 0)
		path = &me->path[1];

	else if (strncmp("/sys/", me->path, 5) == 0)
		path = &me->path[1];

	/* If the path isn't one of above and ends in "lxcfs" assume
	 * it is the base path and we are fixing the nested container
	 * mountpoint */
	else if (strcmp(basename(me->path), LXCFS_PROCESS) == 0)
		path = lxcfs_base_dir(&c->key);

	else
		path = me->path;

	path_fd = openat(base_fd, path, O_PATH|O_CLOEXEC);
	if (path_fd < 0) {
		fprintf(stderr, "Cannot open path %s for container %s: %m\n", 
				path, c->con->name);
		return -1;
	}

	return path_fd;
}

/* Enter containers namespace */
static inline int container_namespace(
		struct container *c)
{
	if (setns(c->pidfd, CLONE_NEWNS) < 0) {
		fprintf(stderr, "Cannot enter container %s namespace: %m",
				c->con->name);
		return -1;
	}
	return 0;
}

static int rebind_mountpoints(
		struct container *c)
{
	struct container_mount_entry *me;

	/* would be nice to freeze/pre, thaw/post container but that requires 
	 * significant heuristics to work out where the c->con->lxc_conf is 
	 * located */

	SLIST_FOREACH(me, &c->mounts, e) {
		int rc = -1;
		int mount_fd = -1;
		int path_fd = -1;
	
		if (lxcfs_namespace(&c->key) < 0)
			goto next;

		path_fd = get_path_fd(c, me);
		if (path_fd < 0)
			goto next;

		/* Clone the mountpoint, this is equivalent to mount --bind /src ... */
		mount_fd = open_tree(path_fd, "", OPEN_TREE_FLAGS);
		if (mount_fd < 0)
			goto next;

		if (container_namespace(c) < 0)
			goto next;

		/* Unmount the broken path, lazy is fine as its VFS to fix */
		rc = umount2(me->path, MNT_DETACH);
		if (rc < 0 && errno == EBUSY) {
			fprintf(stderr, "%s %s failed to unmount: %m.\n",
					c->con->name, me->path);

			goto next;
		}

		/* Bind mount the lxcfs path back on top */
		rc = move_mount(mount_fd,
				"",
				AT_FDCWD,
				me->path,
			        MOVE_MOUNT_F_EMPTY_PATH);
		if (rc < 0) {
			fprintf(stderr, "%s %s failed to bind to path: %m.\n",
					c->con->name, me->path);
			goto next;
		}

		verbose("Successfully rebound %s %s\n",
				c->con->name, me->path);

next:
		if (path_fd >= 0)
			close(path_fd);
		if (mount_fd >= 0)
			close(mount_fd);
	}

	c->work = NULL;
	return 0;
	
fail:
	c->work = NULL;
	return -1;
}

static int test_mountpoints(
		struct container *c)
{
	struct container_mount_entry *me;
	int fd = -1;

	me = SLIST_FIRST(&c->mounts);
	while (me) {
		struct container_mount_entry *n;
		n = SLIST_NEXT(me, e);

		/* Open each directory and test if it fails with the expected
		 * specific error condition */
		fd = open(me->path, O_RDONLY|O_CLOEXEC);
		if (fd < 0 && errno == ENOTCONN)
			goto next;

		/* Entries here are actually working, so remove from the list
		 * so we dont proceed to rebind them and carry on. */
		close(fd);
		SLIST_REMOVE(&c->mounts, me, container_mount_entry, e);
		free(me);
		c->num_mounts--;

next:
		me = n;
	}

	verbose("Tested %s mountpoints and %ld require rebinding.\n",
 			c->con->name, c->num_mounts);

	if (options_dry() || c->num_mounts == 0)
		c->work = NULL;
	else
		c->work = rebind_mountpoints;
	return 0;

fail:
	c->work = NULL;
	return -1;
}

static int get_mountpoints(
		struct container *c)
{
	FILE *mounts = NULL;
	struct mntent *mnt;

	if (container_namespace(c) < 0)
		goto fail;

	mounts = setmntent("/proc/1/mounts", "r");
	if (!mounts) {
		fprintf(stderr, "Cannot open container %s mounts: %m\n",
				c->con->name);
		goto fail;
	}

	/* Scan mounts looking for lxcfs types */
	while (mnt = getmntent(mounts)) {
		struct container_mount_entry *me = NULL;

		if (strcmp(mnt->mnt_type, LXCFS_FSTYPE) != 0)
			continue;

		me = malloc(sizeof(struct container_mount_entry));
		if (!me) {
			fprintf(stderr, "Cannot save mount dir in %s: %m\n",
					c->con->name);
			goto fail;
		}

		memset(me, 0, sizeof(struct container_mount_entry));
		strncpy(me->path, mnt->mnt_dir, 2048);
		SLIST_INSERT_HEAD(&c->mounts, me, e);
		c->num_mounts++;
	}

	verbose("Scanning %s filesystems and found %lu mount points.\n",
		       	c->con->name,
			c->num_mounts);

	endmntent(mounts);

	c->work = test_mountpoints;
	return 0;

fail:
	if (mounts)
		endmntent(mounts);
	c->work = NULL;
	return -1;
}

/* Returns, or creates a new container. */
static inline struct container * get_container(
		struct lxc_container *con,
		struct lxcfs_key *key)
{
	struct container *c = NULL;

	/* The init pid of each container is used as a key to identify the
	 * entry */
	SLIST_FOREACH(c, &head, e) {
		if (c->con->init_pid(c->con) == con->init_pid(con))
			return c;
	}

	/* No match, create */
	c = malloc(sizeof(struct container));
	if (!c) {
		fprintf(stderr, "Cannot create a new container instance "
				"%s: %m", con->name);
		return NULL;
	}

	c->con = con;
	c->key.in = key->in;
	c->key.idx = key->idx;
	SLIST_INIT(&c->mounts);
	c->num_mounts= 0;
	c->work = get_mountpoints;

	c->pidfd = pidfd_open(con->init_pid(con), 0);
	if (c->pidfd < 0) {
		fprintf(stderr, "Cannot create pidfd of container %s: %m",
				con->name);
		free(c);
		return NULL;
	}

	SLIST_INSERT_HEAD(&head, c, e);
	pending++;

	verbose("Checking container %s\n", c->con->name);
	return c;
}

static inline int append_new_containers(
		struct lxc_container **containers,
		int n_containers,
		struct lxcfs_key *key)
{
	int total = 0;
	for (int i=0; i < n_containers; i++) {
		pid_t pid = -1;
		struct container *con = NULL;
		struct lxc_container *c = containers[i];

		/* returns true if it matches a name given in the options list
		 * or --all was passed */
		if (!options_have_name(c->name))
			goto next;

		if (!c->may_control(c))
			goto next;

		con = get_container(c, key);
		if (!con)
			goto next;

		total++;
		continue;

next:
		lxc_container_put(c);
	}

	return total;
}

/* Pull a container from the queue and process it */
int container_process(
		void)
{
	/* This static ensures a circular work queue */
	static struct container *next = NULL;

	struct container *c = NULL;

	if (SLIST_EMPTY(&head)) {
		next = NULL;
		return 0;
	}

	if (next) {
		c = next;
		next = SLIST_NEXT(next, e);
	}
	else {
		c = SLIST_FIRST(&head);
		next = SLIST_NEXT(c, e);
	}

	if (!c->work)
		goto done;

	if (c->work(c) < 0)
		goto done;

	/* If the work resulted in no new callback, its done */
	if (!c->work)
		goto done;

	return 1;

done:
	container_remove(c);
	return 1;
}

/* Queue up a list of containers to be checked */
void container_check(
		struct lxcfs_key *key)
{
	struct lxc_container **containers = NULL;
	const char *path = NULL;
	int n_containers;
	int l_pending = pending;

	if (!key)
		return;

	if (home_namespace() < 0)
		exit(EXIT_FAILURE);

	for (int i=0; i < containerpaths_num(); i++) {
		path = containerpaths_path(i);
		n_containers = list_active_containers(path, NULL, &containers);
		append_new_containers(containers, n_containers, key);
		free(containers);
		containers = NULL;
	}

	if (pending == l_pending && pending == 0) 
		fprintf(stderr, "There are no containers to check.\n");
	else if (pending == l_pending)
		fprintf(stderr, "There are no more containers to check.\n");
	return;
}

int container_pending(
		void)
{
	return pending;
}

void container_destroy(
		void)
{
	struct container *c;

	while (!SLIST_EMPTY(&head)) {
		c = SLIST_FIRST(&head);
		container_remove(c);
	}
	pending = 0;
}
