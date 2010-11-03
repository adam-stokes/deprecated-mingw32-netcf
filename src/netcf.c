/*
 * netcf.c: the public interface for netcf
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David Lutterkort <lutter@redhat.com>
 */

#include <config.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <spawn.h>
#include <errno.h>

#include "safe-alloc.h"
#include "internal.h"
#include "netcf.h"
#ifdef WIN32
# include "netcf_win.h"
#else
# include "dutil.h"
#endif

/* Clear error code and details */
#ifdef WIN32
#define API_ENTRY(ncf) NULL;
#else
#define API_ENTRY(ncf)                          \
    do {                                        \
        (ncf)->errcode = NETCF_NOERROR;         \
        FREE((ncf)->errdetails);                \
        if (ncf->driver != NULL)                \
            drv_entry(ncf);                     \
    } while(0);
#endif

/* Human-readable error messages. This array is indexed by NETCF_ERRCODE_T */
static const char *const errmsgs[] = {
    "no error",                           /* NOERROR   */
    "internal error",                     /* EINTERNAL */
    "unspecified error",                  /* EOTHER    */
    "allocation failed",                  /* ENOMEM    */
    "XML parser failed",                  /* EXMLPARSER */
    "XML invalid",                        /* EXMLINVALID */
    "required entry missing",             /* ENOENT */
    "failed to execute external program", /* EEXEC */
    "instance still in use",              /* EINUSE */
    "XSLT transformation failed",         /* EXSLTFAILED */
    "File operation failed",              /* EFILE */
    "ioctl operation failed",             /* EIOCTL */
    "NETLINK socket operation failed"     /* ENETLINK */
};

static void free_netcf(struct netcf *ncf) {
    if (ncf == NULL)
        return;

    assert(ncf->ref == 0);
    free(ncf->root);
    free(ncf);
}

void free_netcf_if(struct netcf_if *nif) {
    if (nif == NULL)
        return;

    assert(nif->ref == 0);
    unref(nif->ncf, netcf);
    free(nif->name);
    free(nif->mac);
    free(nif);
}

int ncf_init(struct netcf **ncf, const char *root) {
    *ncf = NULL;
    if (make_ref(*ncf) < 0)
        goto oom;
    if (root == NULL) {
#ifdef WIN32
        root = getenv("SYSTEMDRIVE");
        if (!root)
            root = "c:";
#else
        root = "/";
#endif
    }
    if (root[strlen(root)-1] == '/') {
        (*ncf)->root = strdup(root);
    } else {
        if (xasprintf(&(*ncf)->root, "%s/", root) < 0)
            goto oom;
    }
    if ((*ncf)->root == NULL)
        goto oom;
    (*ncf)->data_dir = getenv("NETCF_DATADIR");
    if ((*ncf)->data_dir == NULL)
        (*ncf)->data_dir = NETCF_DATADIR "/netcf";
    (*ncf)->debug = getenv("NETCF_DEBUG") != NULL;
#ifdef WIN32
    return 0;
#else
    /* Needs investigation on WIN32 */
    return drv_init(*ncf);
#endif
 oom:
    ncf_close(*ncf);
    *ncf = NULL;
    return -2;
}

int ncf_close(struct netcf *ncf) {
    if (ncf == NULL)
        return 0;

    API_ENTRY(ncf);

    ERR_COND_BAIL(ncf->ref > 1, ncf, EINUSE);

#ifdef WIN32
    free(ncf->driver);
#else
    drv_close(ncf);
    unref(ncf, netcf);
#endif
    return 0;
 error:
    return -1;
}

/* Number of known interfaces and list of them.
 * For listing we identify the interfaces by UUID, since we don't want
 * to assume that each interface has a (device) name or a hwaddr.
 *
 * Maybe we should just list them as STRUCT NETCF_IF *
 */
int ncf_num_of_interfaces(struct netcf *ncf, unsigned int flags) {
    API_ENTRY(ncf);
    return drv_num_of_interfaces(ncf, flags);
}

int ncf_list_interfaces(struct netcf *ncf, int maxnames, char **names, unsigned int flags) {
    int result;

    API_ENTRY(ncf);
    MEMZERO(names, maxnames);
    result = drv_list_interfaces(ncf, maxnames, names, flags);
    if (result < 0)
        for (int i=0; i < maxnames; i++)
            FREE(names[i]);
    return result;
}

struct netcf_if * ncf_lookup_by_name(struct netcf *ncf, const char *name) {
    API_ENTRY(ncf);
    return drv_lookup_by_name(ncf, name);
}

#ifdef WIN32
int ncf_lookup_by_mac_string(struct netcf *ncf, const char *mac,
                             int maxifaces, struct netcf_if **ifaces) {
    return -1;
}
#else
int
ncf_lookup_by_mac_string(struct netcf *ncf, const char *mac,
                         int maxifaces, struct netcf_if **ifaces) {
    API_ENTRY(ncf);
    return drv_lookup_by_mac_string(ncf, mac, maxifaces, ifaces);
}
#endif

/*
 * Define/start/stop/undefine interfaces
 */

/* Define a new interface */
#ifdef WIN32
struct netcf_if *
ncf_define(struct netcf *ncf, const char *xml) {
    API_ENTRY(ncf);
    return ncf;
}
#else
struct netcf_if *
ncf_define(struct netcf *ncf, const char *xml) {
    API_ENTRY(ncf);
    return drv_define(ncf, xml);
}
#endif

const char *ncf_if_name(struct netcf_if *nif) {
    API_ENTRY(nif->ncf);
    return nif->name;
}

const char *ncf_if_mac_string(struct netcf_if *nif) {
    API_ENTRY(nif->ncf);
    return drv_mac_string(nif);
}

/* Delete the definition */
#ifdef WIN32
/* No mingw implementation */
int ncf_if_undefine(struct netcf_if *nif) {
    return -1;
}
#else
int ncf_if_undefine(struct netcf_if *nif) {
    API_ENTRY(nif->ncf);
    return drv_undefine(nif);
}
#endif

/* Bring the interface up */
int ncf_if_up(struct netcf_if *nif) {
    /* I'm a bit concerned that this assumes nif (and nif->ncf) is non-NULL) */
    API_ENTRY(nif->ncf);
    return drv_if_up(nif);
}

/* Take it down */
int ncf_if_down(struct netcf_if *nif) {
    /* I'm a bit concerned that this assumes nif (and nif->ncf) is non-NULL) */
    API_ENTRY(nif->ncf);
    return drv_if_down(nif);
}

/* Produce an XML description for the interface, in the same format that
 * NCF_DEFINE expects
 */
#ifdef WIN32
/* No mingw implementation */
char *ncf_if_xml_desc(struct netcf_if *nif) {
    return NULL;
}
#else
char *ncf_if_xml_desc(struct netcf_if *nif) {
    API_ENTRY(nif->ncf);
    return drv_xml_desc(nif);
}
#endif

/* Produce an XML description of the current live state of the
 * interface, in the same format that NCF_DEFINE expects, but
 * potentially with extra info not contained in the static config (ie
 * the current IP address of an interface that uses DHCP)
 */
#ifdef WIN32
/* No mingw implementation */
char *ncf_if_xml_state(struct netcf_if *nif) {
    return NULL;
}
#else
char *ncf_if_xml_state(struct netcf_if *nif) {
    API_ENTRY(nif->ncf);
    return drv_xml_state(nif);
}
#endif

/* Report various status info about the interface as bits in
 * "flags". Returns 0 on success, -1 on failure
 */
#ifdef WIN32
/* No mingw implementation */
int ncf_if_status(struct netcf_if *nif, unsigned int *flags) {
    return -1;
}
#else
int ncf_if_status(struct netcf_if *nif, unsigned int *flags) {
    API_ENTRY(nif->ncf);
    return drv_if_status(nif, flags);
}
#endif

/* Release any resources used by this NETCF_IF; the pointer is invalid
 * after this call
 */
void ncf_if_free(struct netcf_if *nif) {
    if (nif == NULL)
        return;

    unref(nif, netcf_if);
}

int ncf_error(struct netcf *ncf, const char **errmsg, const char **details) {
    netcf_errcode_t errcode = ncf->errcode;

    if (ncf->errcode >= ARRAY_CARDINALITY(errmsgs))
        errcode = NETCF_EINTERNAL;

    if (errmsg)
        *errmsg = errmsgs[errcode];
    if (details)
        *details = ncf->errdetails;
    return errcode;
}

/*
 * Test interface
 */
#ifdef WIN32
/* No mingw implementation */
int ncf_get_aug(struct netcf *ncf, const char *ncf_xml, char **aug_xml) {
    return -1;
}
#else
int ncf_get_aug(struct netcf *ncf, const char *ncf_xml, char **aug_xml) {
    API_ENTRY(ncf);

    return drv_get_aug(ncf, ncf_xml, aug_xml);
}
#endif

#ifdef WIN32
/* No mingw implementation */
int ncf_put_aug(struct netcf *ncf, const char *aug_xml, char **ncf_xml) {
    return -1;
}
#else
int ncf_put_aug(struct netcf *ncf, const char *aug_xml, char **ncf_xml) {
    API_ENTRY(ncf);

    return drv_put_aug(ncf, aug_xml, ncf_xml);
}
#endif

#ifdef WIN32
/*
 * Internal helpers
 */

static int
exec_program(struct netcf *ncf,
             const char *const*argv,
             const char *commandline,
             pid_t *pid)
{
    posix_spawnattr_t attr;
    int rc, status;

    rc = posix_spawnattr_init(&attr);
    ERR_COND_BAIL(rc != 0, ncf, EOTHER);
    rc = posix_spawnp(&pid, argv[0], NULL, &attr,
                      (char * const *)argv, environ);
    ERR_COND_BAIL(rc > 0, ncf, EOTHER);
    rc = posix_spawnattr_destroy(&attr);
    ERR_COND_BAIL(rc != 0, ncf, EOTHER);

    (void) waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
error:
    return -1;
}
#else
static int
exec_program(struct netcf *ncf,
             const char *const*argv,
             const char *commandline,
             pid_t *pid)
{
    sigset_t oldmask, newmask;
    struct sigaction sig_action;
    char errbuf[128];

    /* commandline is only used for error reporting */
    if (commandline == NULL)
        commandline = argv[0];
    /*
     * Need to block signals now, so that child process can safely
     * kill off caller's signal handlers without a race.
     */
    sigfillset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, &oldmask) != 0) {
        report_error(ncf, NETCF_EEXEC,
                     "failed to set signal mask while forking for '%s': %s",
                     commandline, strerror_r(errno, errbuf, sizeof(errbuf)));
        goto error;
    }

    *pid = fork();

    ERR_THROW(*pid < 0, ncf, EEXEC, "failed to fork for '%s': %s",
              commandline, strerror_r(errno, errbuf, sizeof(errbuf)));

    if (*pid) { /* parent */
        /* Restore our original signal mask now that the child is
           safely running */
        ERR_THROW(pthread_sigmask(SIG_SETMASK, &oldmask, NULL) != 0,
                  ncf, EEXEC,
                  "failed to restore signal mask while forking for '%s': %s",
                  commandline, strerror_r(errno, errbuf, sizeof(errbuf)));
        return 0;
    }

    /* child */

    /* Clear out all signal handlers from parent so nothing unexpected
       can happen in our child once we unblock signals */
    sig_action.sa_handler = SIG_DFL;
    sig_action.sa_flags = 0;
    sigemptyset(&sig_action.sa_mask);

    int i;
    for (i = 1; i < NSIG; i++) {
        /* Only possible errors are EFAULT or EINVAL
           The former wont happen, the latter we
           expect, so no need to check return value */

        sigaction(i, &sig_action, NULL);
    }

    /* Unmask all signals in child, since we've no idea what the
       caller's done with their signal mask and don't want to
       propagate that to children */
    sigemptyset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, NULL) != 0) {
        /* don't report_error, as it will never be seen anyway */
        _exit(1);
    }

    /* close all open file descriptors */
    int openmax = sysconf (_SC_OPEN_MAX);
    for (i = 3; i < openmax; i++)
        close(i);

    execvp(argv[0], (char **) argv);

    /* if execvp() returns, it has failed */
    /* don't report_error, as it will never be seen anyway */
    _exit(1);

error:
    /* This is cleanup of parent process only - child
       should never jump here on error */
    return -1;
}
#endif

/**
 * Run a command without using the shell.
 *
 * return 0 if the command run and exited with 0 status; Otherwise
 * return -1
 *
 */
int run_program(struct netcf *ncf, const char *const *argv) {

    pid_t childpid;
    int exitstatus, waitret;
    char *argv_str;
    int ret = -1;
    char errbuf[128];

    argv_str = argv_to_string(argv);
    ERR_NOMEM(argv_str == NULL, ncf);

    exec_program(ncf, argv, argv_str, &childpid);
    ERR_BAIL(ncf);

    while ((waitret = waitpid(childpid, &exitstatus, 0) == -1) &&
           errno == EINTR) {
        /* empty loop */
    }

    ERR_THROW(waitret == -1, ncf, EEXEC,
              "Failed waiting for completion of '%s': %s",
              argv_str, strerror_r(errno, errbuf, sizeof(errbuf)));
    ERR_THROW(!WIFEXITED(exitstatus) && WIFSIGNALED(exitstatus), ncf, EEXEC,
              "'%s' terminated by signal: %d",
              argv_str, WTERMSIG(exitstatus));
    ERR_THROW(!WIFEXITED(exitstatus), ncf, EEXEC,
              "'%s' terminated improperly: %d",
              argv_str, WEXITSTATUS(exitstatus));
    ERR_THROW(WEXITSTATUS(exitstatus) != 0, ncf, EEXEC,
              "Running '%s' failed with exit code %d",
              argv_str, WEXITSTATUS(exitstatus));
    ret = 0;

error:
    FREE(argv_str);
    return ret;
}

/*
 * argv_to_string() is borrowed from libvirt's
 * src/util.c:virArgvToString()
 */
char *
argv_to_string(const char *const *argv) {
    int i;
    size_t len;
    char *ret, *p;

    for (len = 1, i = 0; argv[i]; i++)
        len += strlen(argv[i]) + 1;

    if (ALLOC_N(ret, len) < 0)
        return NULL;
    p = ret;

    for (i = 0; argv[i]; i++) {
        if (i != 0)
            *(p++) = ' ';

        strcpy(p, argv[i]);
        p += strlen(argv[i]);
    }

    *p = '\0';

    return ret;
}

void report_error(struct netcf *ncf, netcf_errcode_t errcode,
                  const char *format, ...) {
    va_list ap;

    va_start(ap, format);
    vreport_error(ncf, errcode, format, ap);
    va_end(ap);
}

void vreport_error(struct netcf *ncf, netcf_errcode_t errcode,
                   const char *format, va_list ap) {
    /* We only remember the first error */
    if (ncf->errcode != NETCF_NOERROR)
        return;
    assert(ncf->errdetails == NULL);

    ncf->errcode = errcode;
    if (format != NULL) {
        if (vasprintf(&(ncf->errdetails), format, ap) < 0)
            ncf->errdetails = NULL;
    }
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
