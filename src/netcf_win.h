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

#include "netcf.h"
#include <windows.h>
#include <iphlpapi.h>

int w32_num_of_interfaces(struct netcf *ncf, unsigned int flags);

int w32_list_interface_ids(struct netcf *ncf, 
			   int maxnames, 
			   char **names, 
			   unsigned int flags);

int w32_list_interfaces(struct netcf *ncf,
			int maxnames, char **names,
			unsigned int flags);

struct netcf_if *w32_lookup_by_name(struct netcf *ncf, const char *name);

const char *w32_mac_string(struct netcf_if *nif);

MIB_IFTABLE *w32_intf_table(MIB_IFTABLE *intfTable);
#endif /* NETCF_WIN_H */
