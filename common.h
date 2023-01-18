#ifndef _COMMON_H
#include "options.h"

#define LXCFS_FSTYPE "fuse.lxcfs"
#define LXCFS_PROCESS "lxcfs"

#define verbose(fmt, ...) { if (options_verbose()) printf(fmt, ##__VA_ARGS__); }
#endif
