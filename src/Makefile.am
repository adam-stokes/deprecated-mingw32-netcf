
GNULIB= ../gnulib/lib/libgnu.la
GNULIB_CFLAGS= -I $(top_srcdir)/gnulib/lib

AM_CFLAGS = $(NETCF_CFLAGS) $(GNULIB_CFLAGS) $(WARN_CFLAGS) \
  $(LIBXML_CFLAGS) $(LIBXSLT_CFLAGS) $(LIBAUGEAS_CFLAGS)

include_HEADERS = netcf.h

lib_LTLIBRARIES = libnetcf.la

bin_PROGRAMS = ncftool

noinst_PROGRAMS = ncftransform

EXTRA_DIST = netcf_public.syms \
	netcf_private.syms

DRIVER_SOURCES = dutil.h dutil.c netcf.c drv_initscripts.c

if PLATFORM_WIN32
WIN32LIB= -liphlpapi
else
DRIVER_SOURCES += dutil_linux.c
endif

BUILT_SOURCES = datadir.h netcf.syms

DISTCLEANFILES = datadir.h

libnetcf_la_SOURCES = netcf.h internal.h \
     ref.h list.h \
     xslt_ext.c $(DRIVER_SOURCES)
libnetcf_la_LDFLAGS = -Wl,--version-script=netcf.syms \
     -version-info $(LIBNETCF_VERSION_INFO) @MINGW_EXTRA_LDFLAGS@
libnetcf_la_LIBADD = $(NETCF_LIBDEPS) $(GNULIB) $(WIN32LIB) $(LIB_PTHREAD)
#libnetcf_la_DEPENDENCIES = $(libnetcf_la_LIBADD) netcf.syms

ncftool_SOURCES = ncftool.c
ncftool_LDADD = libnetcf.la $(READLINE_LIBS) $(GNULIB)

ncftransform_SOURCES = ncftransform.c
ncftransform_LDADD = libnetcf.la $(GNULIB)

netcf.syms: netcf_public.syms netcf_private.syms
	rm -f $@-tmp $@
	printf '# WARNING: generated from the following files:\n# $^\n\n' >$@-tmp
	cat $(srcdir)/netcf_public.syms >>$@-tmp
	printf '\n\n# Private symbols\n\n' >>$@-tmp
	printf 'NETCF_PRIVATE_$(VERSION) {\n\n'  >>$@-tmp
	printf 'global:\n\n' >>$@-tmp
	cat $(srcdir)/netcf_private.syms >>$@-tmp
	printf '\n\nlocal:\n*;\n\n};' >>$@-tmp
	chmod a-w $@-tmp
	mv $@-tmp $@

# Generate datadir.h. That's where we look for stylesheets
internal.h: datadir.h

datadir.h: $(top_builddir)/config.status
	echo '#define NETCF_DATADIR "$(datadir)"' > datadir.h

DISTCLEANFILES += $(BUILT_SOURCES)
