/*
 * drv_initscripts-win.c: the initscripts backend for mingw-netcf
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
 * Author: Adam Stokes <ajs@redhat.com>
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
#include <iphlpapi.h>

SC_HANDLE svc_manager, svc_control;

static int cmpstrp(const void *p1, const void *p2) {
    const char *s1 = * (const char **)p1;
    const char *s2 = * (const char **)p2;
    return strcmp(s1, s2);
}



static int list_interface_ids(ATTRIBUTE_UNUSED struct netcf *ncf,
			      int maxnames,
			      char **names,
			      unsigned int flags,
			      const char *id_attr) {

    PIP_INTERFACE_INFO intf;
    ULONG buf;
    DWORD result;
    int nint = 0, i, num_intf;

    if ( (result = GetInterfaceInfo(NULL, &buf)) == ERROR_INSUFFICIENT_BUFFER) {
	// reallocate memory based on new buf length
	intf = (IP_INTERFACE_INFO *) malloc(buf);
	if (intf == NULL) {
	    // no memory
	    return 1;
	}
    }

    result = GetInterfaceInfo(intf, &buf);
    num_intf = intf->NumAdapters;
    if (num_intf < 0) {
	// no interfaces?
	return num_intf;
    }
    if (!names) {
	maxnames = num_intf;
    }
    for (i = 0; (i < num_intf) && (nint < maxnames); i++) {
	if(names) {
	    names[nint] = strdup(intf->Adapter[nint].Name);
	}
	nint++;
    }
    return num_intf;
}
int drv_list_interfaces(ATTRIBUTE_UNUSED struct netcf *ncf,
			       int maxnames,
			       char **names,
			       unsigned int flags) {
    return list_interface_ids(ncf, maxnames, names, flags);
}

int drv_num_of_interfaces(ATTRIBUTE_UNUSED struct netcf *ncf,
				 unsigned int flags) {
    return list_interface_ids(ncf, 0, NULL, flags);
}

int stop_dep_svcs(void) {
    // TODO: add code to stop dependent services
    int result = -1;
    return result;
}

int drv_if_down(struct netcf_if *nif) {
    SERVICE_STATUS_PROCESS ssp;

    svc_manager = OpenSCManager(
				NULL,
				NULL,
				SC_MANAGER_ALL_ACCESS);
    if (!svc_manager)
	return result;

    /* Service Handle */
    svc_control = OpenService(
			      svc_manager,
			      nif->name,
			      SERVICE_STOP |
			      SERVICE_QUERY_STATUS |
			      SERVICE_ENUMERATE_DEPENDENTS);

    if (!svc_control) {
	CloseServiceHandle(svc_manager);
	return result;
    }

    /* Test if service already stopped. */
    if (ssp.dwCurrentState == SERVICE_STOPPED)
	goto svc_cleanup;

    /* Wait for a pending stop */
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
	// TODO: sleep timer
	if (ssp.dwCurrentState == SERVICE_STOPPED)
	    result = 0;
	    goto svc_cleanup;
	// TODO: if timeout exceeds break
    }

    /* Dependent services need to be stopped */
    stop_dep_svcs();
    
    /* Send stop code to service */
    if(!ControlService(svc_control,
		       SERVICE_CONTROL_STOP,
		       (LPSERVICE_STATUS) &ssp))
	goto svc_cleanup;

    while(ssp.dwCurrentState != SERVICE_STOPPED) {
	// TODO: sleep timer needed
	if(ssp.dwCurrentState == SERVICE_STOPPED) {
	    result = 0;
	    break;
	}
	// TODO: cleanup if timer exceeds limit
    }
    return result;

 svc_cleanup:
    CloseServiceHandle(svc_control);
    CloseServiceHandle(svc_manager);
    return result;
}

int drv_if_up(struct netcf_if *nif) {
    SERVICE_STATUS_PROCESS ssp;
    int result = -1;
    
    svc_manager = OpenSCManager(
	NULL,
	NULL,
	SC_MANAGER_ALL_ACCESS);
    if (!svc_manager)
	return result;

    svc_control = OpenService(
	svc_manager,
	nif->name,             // Name of service
	SERVICE_ALL_ACCESS);

    if (!svc_control) {
	CloseServiceHandle(svc_manager);
	return result;
    }

    // Test status of service
    if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
	CloseServiceHandle(svc_control);
	CloseServiceHandle(svc_manager);
	goto svc_cleanup;
    }

    // TODO: implement timeout
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
	// timeout code here
    }

    if (!StartService(svc_control, 0, NULL)) {
	CloseServiceHandle(svc_control);
	CloseServiceHandle(svc_manager);
	goto svc_cleanup;
    } else {
	result = 0;
	goto svc_cleanup;
    }

    while (ssp.dwCurrentState == SERVICE_START_PENDING) {
	// setup timeout
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
	result = 0;
	goto svc_cleanup;
    } else {
	goto svc_cleanup;
    }

 svc_cleanup:
    CloseServiceHandle(svc_control);
    CloseServiceHandle(svc_manager);
    return result;
}
