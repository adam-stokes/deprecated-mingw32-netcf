AC_INIT(netcf, 0.1.6)
AC_CONFIG_SRCDIR([src/netcf.c])
AC_CONFIG_AUX_DIR([build/aux])
AM_CONFIG_HEADER([config.h])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([-Wno-portability 1.11 color-tests parallel-tests])
AM_SILENT_RULES([yes]) # make --enable-silent-rules the default.

AC_SUBST([LIBNETCF_VERSION_INFO], [4:3:3])

WIN32=no
case "${host}" in
	*-mingw*)
		WIN32=yes
	;;
	*)
	;;
esac
AC_GNU_SOURCE

AC_PROG_CC
gl_EARLY

AC_PROG_LIBTOOL

dnl The backend driver. Right now hardcoded to initscripts, but
dnl eventually needs to be configurable at buildtime
dnl temporary, if win32 then dont build this.
AM_CONDITIONAL(NETCF_DRIVER_INITSCRIPTS, test "x$WIN32" != "xyes")

dnl Compiler flags to be used everywhere
AC_SUBST([NETCF_CFLAGS], ['--std=gnu99 -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fasynchronous-unwind-tables'])

gl_INIT

NETCF_COMPILE_WARNINGS

dnl Need to test if pkg-config exists
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBAUGEAS], [augeas >= 0.5.0], [aug_ok=yes], [aug_ok=no])
AM_CONDITIONAL(HAVE_LIBAUGEAS, test "x$aug_ok" = "xyes")
PKG_CHECK_MODULES([LIBXML], [libxml-2.0])
PKG_CHECK_MODULES([LIBXSLT], [libxslt])
PKG_CHECK_MODULES([LIBEXSLT], [libexslt])
PKG_CHECK_MODULES([LIBNL], [libnl-1], [nl_ok=yes], [nl_ok=no])
AM_CONDITIONAL(HAVE_LIBNL, test "x$nl_ok" = "xyes")

NETCF_CHECK_READLINE

NETCF_LIBDEPS=$(echo $LIBAUGEAS_LIBS $LIBEXSLT_LIBS $LIBXSLT_LIBS $LIBXML_LIBS $LIBNL_LIBS)
AC_SUBST([NETCF_LIBDEPS])

AC_CHECK_HEADER([pthread.h],
	[AC_CHECK_LIB([pthread],[pthread_join],[
		AC_DEFINE([HAVE_LIBPTHREAD],[],[Define if pthread (-lpthread)])
		AC_DEFINE([HAVE_PTHREAD_H],[],[Define if <pthread.h>])
		LIBS="-lpthread $LIBS"
	])])

AC_OUTPUT(Makefile                                          \
          gnulib/lib/Makefile                               \
          gnulib/tests/Makefile                             \
          src/Makefile                                      \
          tests/Makefile                                    \
          doc/Makefile                                      \
          netcf.pc netcf.spec)
