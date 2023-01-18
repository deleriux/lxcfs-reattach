#ifndef _EXTRA_SYSCALLS_H
#define _EXTRA_SYSCALLS_H
#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

/* Copied from authoritative file */
/*
 *  open_tree() flags. 
 */
#define OPEN_TREE_CLONE		1   /* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC	O_CLOEXEC /* Close the file on execve() */

/*
 * move_mount() flags.
 */
#define MOVE_MOUNT_F_SYMLINKS	0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS	0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS	0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS	0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH	0x00000040 /* Empty to path permitted */
#define MOVE_MOUNT_SET_GROUP	0x00000100 /* Set sharing group instead */
#define MOVE_MOUNT__MASK	0x00000177

#ifndef SYS_pidfd_open
	#define SYS_pidfd_open	434
#endif

#ifndef SYS_open_tree
	#define SYS_open_tree	428
#endif

#ifndef SYS_move_mount
	#define SYS_move_mount	429
#endif

static inline void check_kernel_compatibility(
		void)
{
	syscall(SYS_move_mount);
	if (errno == ENOSYS)
		goto bad;

	syscall(SYS_pidfd_open);
	if (errno == ENOSYS)
		goto bad;

	syscall(SYS_open_tree);
	if (errno == ENOSYS)
		goto bad;

	return;

bad:
	fprintf(stderr, "Your kernel does not provide support for this program."
			" Linux kernel >= 5.2 is required.\n");
	exit(EXIT_FAILURE);
}

static inline int move_mount(
		int from_dirfd,
		const char *from_pathname,
		int to_dirfd,
		const char *to_pathname,
		unsigned int flags)
{
	return syscall(SYS_move_mount, from_dirfd, from_pathname, to_dirfd, to_pathname, flags);
}

static inline int pidfd_open(
		pid_t pid,
		unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

static inline int open_tree(
		int dirfd,
		const char *pathname,
		unsigned int flags)
{
	return syscall(SYS_open_tree, dirfd, pathname, flags);
}
#endif
