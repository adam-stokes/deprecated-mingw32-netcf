/*
 * netcf-win.c: the public interface for netcf (win32)
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
#include <pthread.h>

#include <sys/wait.h>

#include <signal.h>
#include <errno.h>
#include "safe-alloc.h"

#include "internal.h"
#include "netcf.h"

/* Clear error code and details
#define API_ENTRY(ncf)                          \
    do {                                        \
        (ncf)->errcode = NETCF_NOERROR;         \
        FREE((ncf)->errdetails);                \
        if (ncf->driver != NULL)                \
            drv_entry(ncf);                     \
    } while(0);
*/

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

int
ncf_num_of_interfaces(struct netcf *, unsigned int flags) {
    
}
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
