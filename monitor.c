#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <signal.h>

#include "common.h"
#include "monitor.h"
#include "lxcfs.h"
#include "container.h"

#define MAX_EVENTS 64

static int run = 1;		/* controls main loop */
static int ep_fd = -1;
static int signal_fd = -1;
static sigset_t oldsigs;	/* resets signal mask on exit */

/* Maintain callback list which is iterated on monitor_destroy */
struct cb {
	int fd;
	int (*cb)(struct cb*);
	void *data;
	SLIST_ENTRY(cb) e;
};

static int handle_signal(struct cb *cb);
static int handle_mount_change(struct cb *cb);

SLIST_HEAD(cb_head, cb);
static struct cb_head head = SLIST_HEAD_INITIALIZER(container_head);

static inline struct cb * cb_init(
		int fd,
		int (*callback)(struct cb *),
		void *data)
{
	struct cb *cb;
	cb = malloc(sizeof(struct cb));
	if (!cb) {
		fprintf(stderr, "Cannot create callback: %m\n");
		return NULL;
	}

	cb->fd = fd;
	cb->cb = callback;
	cb->data = data;
	SLIST_INSERT_HEAD(&head, cb, e);
	return cb;
}

static inline void cb_destroy(
		struct cb *cb)
{
	if (!cb)
		return;
	SLIST_REMOVE(&head, cb, cb, e);
	epoll_ctl(ep_fd, EPOLL_CTL_DEL, cb->fd, NULL);
	free(cb);
}

static inline void process_events(
		struct epoll_event *evs,
		int num)
{
	for (int i=0; i < num; i++) {
		struct cb *cb = (struct cb *)evs[i].data.ptr;

		if (!cb || !cb->cb) 
			abort();

		if (cb->cb(cb) < 0) {
			fprintf(stderr, "Callback %p returned an error. "
					"Removing from monitor.\n", cb);
			cb_destroy(cb);
		}
	}
}

static inline int setup_signalfd(
		void)
{
	struct epoll_event ev = {0};
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGINT);

	if (sigprocmask(SIG_BLOCK, &sigs, &oldsigs) < 0) {
		fprintf(stderr, "Cannot setup signal mask: %m\n");
		goto fail;
	}

	signal_fd = signalfd(-1, &sigs, SFD_CLOEXEC);
	if (signal_fd < 0)
		goto fail;

	/* add to the polling set */
	ev.events = EPOLLIN;
	ev.data.ptr = cb_init(signal_fd, handle_signal, NULL);
	if (!ev.data.ptr)
		goto fail;

	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, signal_fd, &ev) < 0) {
		fprintf(stderr, "Cannot add signal fd to polling set: %m\n");
		goto fail;
	}

	return 0;
fail:
	if (ev.data.ptr)
		cb_destroy((struct cb *)ev.data.ptr);
	if (signal_fd >= 0)
		close(signal_fd);
	sigprocmask(SIG_SETMASK, &oldsigs, NULL);
	return -1;
}

static inline int setup_lxcfs_monitors(
		void)
{
	int sz;
	int *fds = NULL;

	/* Get the number FDs to poll */
       	sz = lxcfs_poll_fds(NULL, 0);
	if (sz <= 0) {
		fprintf(stderr, "There are an invalid number of instances "
			        "to monitor\n");
		return -1;
	}

	fds = alloca(sz * sizeof(int));
	if (lxcfs_poll_fds(fds, sz) < 0)
		return -1;

	/* Sets up the callbacks from all found fds */
	for (int i=0; i < sz; i++) {
		struct epoll_event ev;

		ev.events = EPOLLPRI;
		ev.data.ptr = cb_init(fds[i], handle_mount_change, NULL);

		if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, fds[i], &ev) < 0) {
			fprintf(stderr, "Could not add mount entry to "
					"monitor: %m\n");
			exit(EXIT_FAILURE);
		}
	}
}

static int handle_signal(
		struct cb *cb)
{
	struct signalfd_siginfo sv[32] = {0};
	int rc;

	rc = read(signal_fd, sv, sizeof(sv));
	if (rc < 0) {
		fprintf(stderr, "Error reading from signal fd! Aborting: %m\n");
		exit(EXIT_FAILURE);
	}

	verbose("Received signal. Stopping monitor.\n");

	run = 0;
	return 0;
}

static int handle_mount_change(
		struct cb *cb)
{
	lxcfs_update_mount_state(cb->fd);
	return 0;
}

int monitor_run(
		void)
{
	struct epoll_event events[MAX_EVENTS];
	int tout = 25;

	ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		fprintf(stderr, "Cannot create epoll: %m\n");
		goto fail;
	}

	if (setup_signalfd() < 0) {
		goto fail;
	}

	if (setup_lxcfs_monitors() < 0) {
		goto fail;
	}

	while (run) {
		int rc;

		rc = epoll_wait(ep_fd, events, MAX_EVENTS, tout);
		if (rc < 0 && errno == EINTR)
			continue;

		process_events(events, rc);

		/* Do idle work */
		if (run && container_pending()) {
			tout = 25;
			container_process();
		}
		else {
			tout = -1;
		}
	}

	monitor_destroy();
	return 0;

fail:
	monitor_destroy();
	return -1;
}

void monitor_destroy(
		void)
{
	struct cb *cb;

	sigprocmask(SIG_SETMASK, &oldsigs, NULL);

	while (!SLIST_EMPTY(&head)) {
		cb = SLIST_FIRST(&head);

		cb_destroy(cb);
	}

	if (signal_fd >= 0)
		close(signal_fd);

	if (ep_fd >= 0)
		close(ep_fd);

	return; 
}
