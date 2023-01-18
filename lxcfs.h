#ifndef _LXCFS_H_
#define _LXCFS_H_
#include <stdbool.h>
#include <sys/queue.h>

#define MAX_PATHS 48

struct lxcfs_instance {
	FILE *mounts; 	 		/* /proc/<pid>/mounts to monitor */
	int mntns; 			/* the mount namespace FD */
	long int mntns_id;		/* the ID of namespace 
					 *  (key for finding) */
	struct {
		char *path;		/* the canonical path */
		int fd;			/* base fd of path, used for remounts */
		bool mounted;		/* state of if mountpoint exists */
	} directory[MAX_PATHS];		/* path to directory of interest */

	int n_directories;		/* index */
	SLIST_ENTRY(lxcfs_instance) e;
};

struct lxcfs_key {
	struct lxcfs_instance *in;
	int idx;
};

void lxcfs_instance_scan(void);
void lxcfs_instance_destroy(void);

/* Gets list of /proc/pid/mounts file descriptors for monitor */
int lxcfs_poll_fds(int *fds, int sz);
void lxcfs_update_mount_state(int fd);

/* Select a lxcfs with a known working instance */
int lxcfs_select(struct lxcfs_key *ref);
int lxcfs_namespace(struct lxcfs_key *ref);
int lxcfs_base_fd(struct lxcfs_key *ref);
const char * lxcfs_base_dir(struct lxcfs_key *ref);
#endif
