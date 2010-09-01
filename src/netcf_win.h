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

#include <config.h>
#include "internal.h"

#include <stdbool.h>
#include <string.h>
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windns.h>
#include "safe-alloc.h"
#include "ref.h"
#include "list.h"

static int aug_put_xml(struct netcf *ncf, xmlDocPtr xml);
static int bridge_slaves(struct netcf *ncf, const char *name, char ***slaves);
static int cmpstrp(const void *p1, const void *p2);
static int is_slave(struct netcf *ncf, const char *intf);
static int list_ifcfg_paths(struct netcf *ncf, char ***intf);
static int list_interface_ids(struct netcf *ncf, int maxnames, char **names,
			      unsigned int flags, const char *id_attr);
static int list_interfaces(struct netcf *ncf, char ***intf);
static int uniq_ifcfg_paths(struct netcf *ncf, int ndevs, char **devs, char ***intf);
static bool has_ifcfg_file(struct netcf *ncf, const char *name);
static bool is_bond(struct netcf *ncf, const char *name);
static bool is_bridge(struct netcf *ncf, const char *name);
static char *device_name_from_xml(struct netcf *ncf, xmlDocPtr ncf_xml);
static char *find_ifcfg_path_by_device(struct netcf *ncf, const char *name);
static char *find_ifcfg_path_by_hwaddr(struct netcf *ncf, const char *mac);
static char *find_ifcfg_path(struct netcf *ncf, const char *name);
static void bond_setup(struct netcf *ncf, const char *name, bool alias);
static void bridge_physdevs(struct netcf *ncf);
static void rm_all_interfaces(struct netcf *ncf, xmlDocPtr ncf_xml);
static void rm_interface(struct netcf *ncf, const char *name);
static xmlDocPtr aug_get_xml_for_nif(struct netcf_if *nif);
static xmlDocPtr aug_get_xml(struct netcf *ncf, int nint, char **intf);
struct netcf_if *make_netcf_if(struct netcf *ncf, char *name);
int xasprintf(char **strp, const char *format, ...);

/* structure return of interface table */
PMIB_IFTABLE _get_if_table(PMIB_IFTABLE intfTable);

/* structure return of adapter info */
PIP_ADAPTER_ADDRESSES _get_ip_adapter_info(PIP_ADAPTER_ADDRESSES addrList);

PMIB_IPADDRTABLE _get_ip_addr_table(PMIB_IPADDRTABLE ipAddrTable);

/* Reports ip addresses */
int drv_if_ipaddresses(struct netcf_if *nif, char *ipBuf);

/* add ip address to device */
int drv_add_ip_address(struct netcf_if *nif, char *ipAddr,
		       char *netmask);
/* remove ip address from device */
int drv_rm_ip_address(struct netcf_if *nif, ULONG NTEContext);
/* add dns server to device */
int drv_add_dns_server(struct netcf_if *nif, ULONG NTEContext);
/* rm dns server from device */
int drv_rm_dns_server(struct netcf_if *nif);
/* list dns server */
int drv_list_dns_server(struct netcf_if *ncf, char *ip_str);

#endif /* NETCF_WIN_H */
