/*
 * netcf-win.h: windows functions
 *
 * Copyright (C) 2009-2010 Red Hat Inc.
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
 * Author: Adam Stokes <ajs@redhat.com>
 */

#ifndef NETCF_WIN_H
#define NETCF_WIN_H

#ifndef WINVER
#define WINVER 0x0501
#endif

#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windns.h>
#include "netcf.h"

/* structure return of interface table */
PMIB_IFTABLE _get_if_table(PMIB_IFTABLE intfTable);

/* structure return of adapter info */
PIP_ADAPTER_ADDRESSES _get_ip_adapter_info(PIP_ADAPTER_ADDRESSES addrList);

/* return num of interfaces enabled */
int w32_num_of_interfaces(struct netcf *ncf, unsigned int flags);

/* helper for providing number of interfaces and associated names */
int w32_list_interface_ids(struct netcf *ncf, int maxnames, 
			   char **names, unsigned int flags,
			   const char *id_attr);
			   
/* list interface names */
int w32_list_interfaces(struct netcf *ncf,
			int maxnames, char **names,
			unsigned int flags);

/* lookup interface by name */
struct netcf_if *w32_lookup_by_name(struct netcf *ncf,
				    const char *name);

/* obtain hardware address of interface */
const char *w32_mac_string(struct netcf_if *nif);

/* bring interface down */
int w32_if_down(struct netcf_if *nif);

/* bring interface up */
int w32_if_up(struct netcf_if *nif);

/* Reports ip addresses */
int w32_if_ipaddresses(struct netcf_if *nif);
/* add ip address to device */
int w32_add_ip_address(struct netcf_if *nif, const char *ipAddr);
/* remove ip address from device */
int w32_rm_ip_address(struct netcf_if *nif);
/* add dns server to device */
int w32_add_dns_server(struct netcf_if *nif, ULONG NTEContext);
/* rm dns server from device */
int w32_rm_dns_server(struct netcf_if *nif);

#endif /* NETCF_WIN_H */
