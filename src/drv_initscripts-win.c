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
#include "dutil.h"

#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

#include <libexslt/exslt.h>

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

SC_HANDLE svc_manager, svc_control;

static int list_interface_ids(struct netcf *ncf,
			      int maxnames,
			      char **names,
			      ATTRIBUTE_UNUSED unsigned int flags,
			      ATTRIBUTE_UNUSED const char *id_attr) {

    PIP_INTERFACE_INFO intf;
    ULONG buf;
    DWORD result;
    int nint = 0, i, num_intf;

    if ( (result = GetInterfaceInfo(NULL, &buf)) == ERROR_INSUFFICIENT_BUFFER) {
	// reallocate memory based on new buf length
	intf = (IP_INTERFACE_INFO *) malloc(buf);
	ERR_NOMEM(intf == NULL, ncf);
    }

    ERR_COND_BAIL(GetInterfaceInfo(intf, &buf) == ERROR_NO_DATA, ncf, EOTHER);
    num_intf = intf->NumAdapters;
    ERR_COND_BAIL(num_intf < 0, ncf, EOTHER);

    if (!names) {
	maxnames = num_intf;
    }
    for (i = 0; (i < num_intf) && (nint < maxnames); i++) {
	if(names) {
	    names[nint] = strdup((char *)intf->Adapter[nint].Name);
	}
	nint++;
    }
    return num_intf;
error:
    return -1;
}

int drv_list_interfaces(struct netcf *ncf,
			int maxnames,
			char **names,
			ATTRIBUTE_UNUSED unsigned int flags) {
    return list_interface_ids(ncf, maxnames, names, flags, NULL);
}

int drv_num_of_interfaces(struct netcf *ncf,
			  ATTRIBUTE_UNUSED unsigned int flags) {
    return list_interface_ids(ncf, 0, NULL, flags, NULL);
}

static int stop_dep_svcs() {
    // TODO: add code to stop dependent services
    int result = -1;
    DWORD i, needed, count;
    /* unused for now
    ENUM_SERVICE_STATUS ess;
    SC_HANDLE depserv;
    SERVICE_STATUS_PROCESS ssp;
    */

    if (EnumDependentServices(svc_control, SERVICE_ACTIVE, NULL,
			      0, &needed, &count)) {
	// enum call succeeds return
	result = 0;
	return result;
    }
    
    if (GetLastError() != ERROR_MORE_DATA)
	return result;

    return result;
}

int drv_if_down(struct netcf_if *nif) {
    SERVICE_STATUS_PROCESS ssp;
    struct netcf *ncf = nif->ncf;
    int result = -1;

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
    ERR_COND_BAIL(ssp.dwCurrentState == SERVICE_STOPPED, ncf, EOTHER);

    /* Wait for a pending stop */
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
	// TODO: sleep timer
	result = 0;
	ERR_COND_BAIL(ssp.dwCurrentState == SERVICE_STOPPED, ncf, EOTHER);

	// TODO: if timeout exceeds break
    }

    /* Dependent services need to be stopped */
    stop_dep_svcs();
    
    /* Send stop code to service */
    ERR_COND_BAIL(!ControlService(svc_control,
				  SERVICE_CONTROL_STOP,
				  (LPSERVICE_STATUS) &ssp), ncf, EOTHER);
    
    while(ssp.dwCurrentState != SERVICE_STOPPED) {
	// TODO: sleep timer needed
	if(ssp.dwCurrentState == SERVICE_STOPPED) {
	    result = 0;
	    break;
	}
	// TODO: cleanup if timer exceeds limit
    }
    return result;

error:
    CloseServiceHandle(svc_control);
    CloseServiceHandle(svc_manager);
    return result;
}

int drv_if_up(struct netcf_if *nif) {
    SERVICE_STATUS_PROCESS ssp;
    struct netcf *ncf = nif->ncf;
    DWORD needed;
    int result = -1;
    
    svc_manager = OpenSCManager(
	NULL,
	NULL,
	SC_MANAGER_ALL_ACCESS);
    ERR_COND_BAIL(!svc_manager, ncf, EOTHER);

    svc_control = OpenService(
	svc_manager,
	nif->name,             // Name of service
	SERVICE_ALL_ACCESS);

    if (!svc_control) {
	CloseServiceHandle(svc_manager);
	return result;
    }

    ERR_COND_BAIL(!QueryServiceStatusEx(svc_control, SC_STATUS_PROCESS_INFO, 
					(LPBYTE) &ssp, sizeof(SERVICE_STATUS_PROCESS),
					&needed), ncf, EOTHER);

    ERR_COND_BAIL(ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING, ncf, EOTHER);

    // TODO: implement timeout
    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
	// timeout code here
    }

    if (!StartService(svc_control, 0, NULL)) {
	CloseServiceHandle(svc_control);
	CloseServiceHandle(svc_manager);
	goto error;
    } else {
	result = 0;
	goto error;
    }

    while (ssp.dwCurrentState == SERVICE_START_PENDING) {
	// setup timeout
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
	result = 0;
	goto error;
    } else {
	goto error;
    }

error:
    CloseServiceHandle(svc_control);
    CloseServiceHandle(svc_manager);
    return result;
}

struct netcf_if *drv_lookup_by_name(struct netcf *ncf, const char *name) {
    struct netcf_if *nif = NULL;
    /* char *pathx = NULL; */
    char *name_dup = NULL;

    /*  needs some research
    pathx = find_ifcfg_path(ncf, name);
    ERR_BAIL(ncf);

    if (pathx == NULL || is_slave(ncf, pathx))
        goto done;
    */

    name_dup = strdup(name);
    ERR_NOMEM(name_dup == NULL, ncf);

    nif = make_netcf_if(ncf, name_dup);
    ERR_BAIL(ncf);
    goto done;

 error:
    unref(nif, netcf_if);
    FREE(name_dup);
 done:
    // FREE(pathx);
    return nif;
}

void drv_close(struct netcf *ncf) {
    if (ncf == NULL || ncf->driver == NULL)
        return;
    xsltFreeStylesheet(ncf->driver->get);
    xsltFreeStylesheet(ncf->driver->put);
    xmlRelaxNGFree(ncf->driver->rng);
    netlink_close(ncf);
    if (ncf->driver->ioctl_fd >= 0)
        close(ncf->driver->ioctl_fd);
    FREE(ncf->driver);
}

void drv_entry(struct netcf *ncf) {
    ncf->driver->load_augeas = 0;
}
