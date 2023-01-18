#ifndef _CONTAINERPATHS_H_
#define _CONTAINERPATHS_H_
#include "common.h"

void containerpaths_init(void);
void containerpaths_destroy(void);
int containerpaths_num(void);
const char * containerpaths_path(int n);

#endif
