/*
 * drv_initscripts.c: the initscripts backend for netcf
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
#include <internal.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "safe-alloc.h"
#include "ref.h"
#include "list.h"

#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

#include <libexslt/exslt.h>

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

static int cmpstrp(const void *p1, const void *p2) {
    const char *s1 = * (const char **)p1;
    const char *s2 = * (const char **)p2;
    return strcmp(s1, s2);
}

static int list_interfaces() {
    int nint = 0;

    if ((nint = GetNumberOfInterfaces()) != NO_ERROR) {
        return nint;
    } else {
        return -1;
    }
}

static int drv_list_interfaces(struct netcf *ncf, int maxnames,
			       char **names, unsigned int flags) {
    return list_interfaces();
}

static int drv_num_of_interfaces(struct netcf *ncf, unsigned int flags) {
    return list_interfaces();
}

struct netcf_if *drv_lookup_by_name(struct netcf *ncf, const char *name) {


}
