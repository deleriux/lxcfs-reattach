bin_PROGRAMS = lxcfs-reattach
lxcfs_reattach_SOURCES = main.c extra_syscalls.h containerpaths.c containerpaths.h options.c options.h common.h lxcfs.h lxcfs.c container.c container.h monitor.c monitor.h
lxcfs_reattach_CFLAGS = $(lxc_CFLAGS)
lxcfs_reattach_LDADD = $(lxc_LIBS)

pkgdatadir = ${datadir}/lxcfs-reattach
dist_pkgdata_DATA = lxcfs-reattach.service
