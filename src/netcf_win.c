/*
 * netcf-win.c: windows functions
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

#include <config.h>
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include "netcf_win.h"

#define MAX_TRIES 5
#define GAA_FLAGS ( GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST )
#define BUFSIZE 1024

/* Like asprintf, but set *STRP to NULL on error */
int xasprintf(char **strp, const char *format, ...) {
  va_list args;
  int result;

  va_start (args, format);
  result = vasprintf (strp, format, args);
  va_end (args);
  if (result < 0)
      *strp = NULL;
  return result;
}

/* Create a new netcf if instance for interface NAME */
struct netcf_if *make_netcf_if(struct netcf *ncf, char *name) {
    int r;
    struct netcf_if *result = NULL;

    r = make_ref(result);
    ERR_NOMEM(r < 0, ncf);
    result->ncf = ref(ncf);
    result->name = strdup(name);
    return result;

 error:
    unref(result, netcf_if);
    return result;
}

static int list_interface_ids(struct netcf *ncf,
			      int maxnames,
			      char **names, unsigned int flags,
     			      const char *id_attr) {
    size_t nint = 0;
    DWORD r = 0, tableSize = 0;
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;

    GetAdaptersInfo(NULL, &tableSize);
    adapter_info = malloc(tableSize);
    ERR_NOMEM(adapter_info == NULL, ncf);
    r = GetAdaptersInfo(adapter_info, &tableSize);
    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);
    adapter = adapter_info;
    while(adapter) {
	if(names) {
	    names[nint] = strdup(adapter->AdapterName);
	    ERR_NOMEM(names[nint] == NULL, ncf);
	}
	nint++;
	adapter = adapter->Next;
    }
    if (adapter_info)
	free(adapter_info);
    return nint;
 error:
    while(nint > 0) {
	free(names[nint]);
	nint--;
    }
    if(adapter_info)
	free(adapter_info);
    return -1;
}

int drv_list_interfaces(struct netcf *ncf,
		    int maxnames, char **names,
		    unsigned int flags) {
    return list_interface_ids(ncf, 0, names, 0, NULL);
}


int drv_num_of_interfaces(struct netcf *ncf, unsigned int flags) {
    return list_interface_ids(ncf, 0, NULL, 0, NULL);
}


struct netcf_if *drv_lookup_by_name(struct netcf *ncf, const char *name) {
    struct netcf_if *nif = NULL;
    DWORD r = 0, tableSize = 0;
    char *buf, *nameDup;
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;

    GetAdaptersInfo(NULL, &tableSize);
    adapter_info = malloc(tableSize);
    ERR_NOMEM(adapter_info == NULL, ncf);
    r = GetAdaptersInfo(adapter_info, &tableSize);
    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);
    
    adapter = adapter_info;
    while(adapter) {
	if(name) {
	    if(strcmp(name,adapter->AdapterName) == 0) {
		nameDup = strdup(adapter->AdapterName);
		ERR_NOMEM(nameDup == NULL, ncf);
		nif = make_netcf_if(ncf, nameDup);
		ERR_BAIL(ncf);
	    }
	}
	adapter = adapter->Next;
    }
    return nif;
 error:
    unref(nif, netcf_if);
    if (adapter_info)
	free(adapter_info);
    return nif;
}

const char *drv_mac_string(struct netcf_if *nif) {
    struct netcf *ncf = nif->ncf;
    DWORD r = 0, tableSize = 0;
    size_t nint = 0, i = 0;
    char mac[BUFSIZE], *buf;
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;

    GetAdaptersInfo(NULL, &tableSize);
    adapter_info = malloc(tableSize);
    ERR_NOMEM(adapter_info == NULL, ncf);
    r = GetAdaptersInfo(adapter_info, &tableSize);
    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);

    adapter = adapter_info;
    while(adapter) {
	if(strcmp(nif->name, adapter->AdapterName) == 0) {
	    for(i = 0; i < adapter->AddressLength; i++) {
		if (i == 0) {
		    ERR_NOMEM(asprintf(&buf, "%.2X:", adapter->Address[i]) < 0, ncf);
		    strcpy(mac, buf);
		}
		if (i == (adapter->AddressLength - 1)) {
		    ERR_NOMEM(asprintf(&buf, "%.2X", adapter->Address[i]) < 0, ncf);
		    strcat(mac, buf);
		} else {
		    ERR_NOMEM(asprintf(&buf, "%.2X:", adapter->Address[i]) < 0, ncf);
		    strcat(mac, buf);
		}
		nif->mac = strdup(mac);
		ERR_NOMEM(nif->mac == NULL, ncf);
		if(adapter_info)
		    free(adapter_info);
	    }
	    return nif->mac;
	}
	adapter = adapter->Next;
    }
 error:
    if(buf)
	free(buf);
    if(adapter_info)
	free(adapter_info);
    return nif->mac;
}

int drv_if_down(struct netcf_if *nif) {
    struct netcf *ncf = nif->ncf;
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;
    MIB_IFROW *row;
    DWORD tableSize = 0, r = 0;

    GetAdaptersInfo(NULL, &tableSize);
    adapter_info = malloc(tableSize);
    ERR_NOMEM(adapter_info == NULL, ncf);
    r = GetAdaptersInfo(adapter_info, &tableSize);
    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);

    row = malloc(sizeof(MIB_IFROW));
    adapter = adapter_info;
    while(adapter) {
	if(strcmp(nif->name, adapter->AdapterName) == 0) {
	    row->dwIndex = adapter->Index;
	    row->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
	    r = SetIfEntry(row);
	    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);
	}
	adapter = adapter->Next;
    }
    return 0;
 error:
    if(adapter_info)
	free(adapter_info);
    return -1;
}

int drv_if_up(struct netcf_if *nif) {
    struct netcf *ncf = nif->ncf;
    IP_ADAPTER_INFO *adapter_info;
    IP_ADAPTER_INFO *adapter = NULL;
    MIB_IFROW *row;
    DWORD tableSize = 0, r = 0;

    GetAdaptersInfo(NULL, &tableSize);
    adapter_info = malloc(tableSize);
    ERR_NOMEM(adapter_info == NULL, ncf);
    r = GetAdaptersInfo(adapter_info, &tableSize);
    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);

    adapter = adapter_info;
    while(adapter) {
	if(strcmp(nif->name, adapter->AdapterName) == 0) {
	    row = (MIB_IFROW *) & adapter->Index;
	    row->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
	    r = SetIfEntry(row);
	    ERR_COND_BAIL(r != NO_ERROR, ncf, EOTHER);
	}
	adapter = adapter->Next;
    }
    return 0;
 error:
    if(adapter_info)
	free(adapter_info);
    return -1;
}

/*
int drv_if_ipaddresses(struct netcf_if *nif, char *ipBuf) {
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    PMIB_IPADDRTABLE ipAddrTable = NULL;
    IN_ADDR ipAddr;
    int i;
    DWORD r = 0;
    DWORD buf = 0;

    if ((ipAddrTable = malloc(sizeof (*ipAddrTable))) == NULL)
	return NULL;
    if ((r = GetIpAddrTable(ipAddrTable, &buf, 0)) == ERROR_INSUFFICIENT_BUFFER) {
	free(ipAddrTable);
	if ((ipAddrTable = malloc(sizeof (buf))) == NULL)
	    return NULL;
    }
    if(r == NO_ERROR)
	return ipAddrTable;
    return NULL;
    if (adapterp != NULL) {
	while(adapterp) {
	    if (adapterp->OperStatus != 1)
		continue;

	    for (i = 0; i<ipAddrTable->dwNumEntries; i++) {
		if (ipAddrTable->table[i].dwIndex == adapterp->IfIndex) {
		    char wName[8192];
		    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
					-1, wName, sizeof(wName), NULL, NULL);
		    if (strcmp(wName,nif->name) == 0) {
			ipAddr.S_un.S_addr = ipAddrTable->table[i].dwAddr;
			if((i = asprintf(&ipBuf,"%s",inet_ntoa(ipAddr))) < 0)
			    free(ipBuf);
			    return -1;
			return 0;
		    }
		}
	    }
	    adapterp = adapterp->Next;
	}
    }
    free(ipBuf);
    return -1;
}
*/

int drv_list_dns_server(struct netcf_if *nif, char *ip_str) {
    char bufferLength[1024];
    IP4_ARRAY *ips = (IP4_ARRAY*) bufferLength;
    DWORD len = sizeof(bufferLength);
    DNS_STATUS status;

    status = DnsQueryConfig(DnsConfigDnsServerList, FALSE,
			    NULL, NULL, ips, &len);
    if (status == 0) {
	DWORD i;
	for (i = 0; i < ips->AddrCount; i++) {
	    DWORD ip = ips->AddrArray[i];
	    snprintf(ip_str, sizeof(ip_str),
		     "%lu.%lu.%lu.%lu", (ip >> 0) & 0xff, (ip >> 8) & 0xff,
		     (ip >> 16) & 0xff, (ip >> 24) & 0xff);
	}
    } else {
	return -1;
    }
    return 0;
}

