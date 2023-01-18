#ifndef _CONTAINER_H_
#define _CONTAINER_H_
#include "lxcfs.h"

void container_check(struct lxcfs_key *key);
int container_process(void);
int container_pending(void);
void container_destroy(void);
#endif
