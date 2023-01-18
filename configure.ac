AC_INIT([lxcfs-reattach], [1.1], [matthew@ife.onl])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-extra-portability -Werror subdir-objects])

LT_INIT
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

PKG_CHECK_MODULES([lxc], [lxc])

#AC_SEARCH_LIBS([sqrt], [m])

AC_SUBST([AM_CPPFLAGS], [-D_GNU_SOURCE])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
