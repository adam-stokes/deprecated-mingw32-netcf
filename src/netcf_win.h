/*
 * netcf-win.h: windows functions
 *
 * Copyright (C) 2010 Red Hat Inc.
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
# define WINVER 0x0501
#endif

#include "internal.h"

#include <stdbool.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windns.h>
#include "safe-alloc.h"
#include "ref.h"
#include "list.h"

/* Like asprintf, but set *STRP to NULL on error */
ATTRIBUTE_FORMAT(printf, 2, 3)
int xasprintf(char **strp, const char *format, ...);
struct netcf_if *make_netcf_if(struct netcf *ncf, char *name);

/* Reports ip addresses */
int drv_if_ipaddresses(struct netcf_if *nif, char *ipBuf);

/* add ip address to device */
int drv_add_ip_address(struct netcf_if *nif, char *ipAddr,
		       char *netmask);
/* remove ip address from device */
int drv_rm_ip_address(struct netcf_if *nif, uint64_t NTEContext);
/* add dns server to device */
int drv_add_dns_server(struct netcf_if *nif, uint64_t NTEContext);
/* rm dns server from device */
int drv_rm_dns_server(struct netcf_if *nif);
/* list dns server */
int drv_list_dns_server(struct netcf_if *ncf, char *ip_str);

#endif /* NETCF_WIN_H */
