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
#define GAA_FLAGS ( GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST)
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

static PMIB_IPADDRTABLE get_ip_addr_table(void) {
    PMIB_IPADDRTABLE ipAddrTable = NULL;
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
}

static PMIB_IFTABLE get_if_table(void) {
    PMIB_IFTABLE intfTable = NULL;
    DWORD bufferLength = 0;
    DWORD r = 0;
    if ((intfTable = malloc(sizeof(intfTable))) == NULL)
	return NULL;

    bufferLength = sizeof(MIB_IFTABLE);
    if ((r = GetIfTable(intfTable, &bufferLength, FALSE)) == ERROR_INSUFFICIENT_BUFFER) {
	free(intfTable);
	if ((intfTable = malloc(sizeof(bufferLength))) == NULL)
	    return NULL;
    }
    if (r == NO_ERROR)
	return intfTable;
    return NULL;
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
    size_t nint = 0, tries = 0;
    PIP_ADAPTER_ADDRESSES adapter = NULL , cAddress = NULL;
    ULONG bufferLength = 0;
    DWORD r;

    bufferLength = sizeof(IP_ADAPTER_ADDRESSES);

    do {
	adapter = malloc(bufferLength);
	if (adapter == NULL)
	    goto error;

	r = GetAdaptersAddresses(AF_UNSPEC,
				 GAA_FLAGS,
				 NULL,
				 adapter,
				 &bufferLength);

	if (r == ERROR_BUFFER_OVERFLOW) {
	    free(adapter);
	    adapter = NULL;
	} else {
	    break;
	}
	tries++;
    } while ((r == ERROR_BUFFER_OVERFLOW) && (tries < MAX_TRIES));

    if (r == NO_ERROR)
	cAddress = adapter;

    while(cAddress) {
	if (names) {
	    char name[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, cAddress->FriendlyName,
				-1, name, sizeof(name), NULL, NULL);
	    if ((names[nint] = strdup(name)) == NULL)
		goto error;
	}
	nint++;
	cAddress = cAddress->Next;
    }
    return nint;
 error:
    while(nint > 0) {
	free(names[nint]);
	nint--;
    }
    free(adapter);
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
    DWORD r;
    size_t tries = MAX_TRIES;
    ULONG bufferLength = 0;
    PIP_ADAPTER_ADDRESSES adapter = NULL, cAddress = NULL;
    char *nameDup = NULL;

    bufferLength = sizeof(IP_ADAPTER_ADDRESSES);

    do {
	adapter = malloc(bufferLength);
	if (adapter == NULL)
	    goto error;

	r = GetAdaptersAddresses(AF_UNSPEC,
				 GAA_FLAGS,
				 NULL,
				 adapter,
				 &bufferLength);

	if (r == ERROR_BUFFER_OVERFLOW) {
	    free(adapter);
	    adapter = NULL;
	} else {
	    break;
	}
	tries++;
    } while ((r == ERROR_BUFFER_OVERFLOW) && (tries < MAX_TRIES));

    cAddress = adapter;
    while(cAddress) {
	if (name) {
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, cAddress->FriendlyName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName, name) == 0) {
		nameDup = strdup(name);
		ERR_NOMEM(nameDup == NULL, ncf);

		nif = make_netcf_if(ncf, nameDup);
		ERR_BAIL(ncf);
	    }
	}
	cAddress = cAddress->Next;
    }

    return nif;
 error:
    free(nameDup);
    free(adapter);
    return nif;
}


const char *drv_mac_string(struct netcf_if *nif) {
    PIP_ADAPTER_ADDRESSES adapter = NULL, cAddress = NULL;
    ULONG bufferLength = 0;
    DWORD r;
    size_t tries = MAX_TRIES;
    char *mac;

    bufferLength = sizeof(IP_ADAPTER_ADDRESSES);

    do {
	adapter = malloc(bufferLength);
	if (adapter == NULL)
	    goto error;

	r = GetAdaptersAddresses(AF_UNSPEC,
				 GAA_FLAGS,
				 NULL,
				 adapter,
				 &bufferLength);

	if (r == ERROR_BUFFER_OVERFLOW) {
	    free(adapter);
	    adapter = NULL;
	} else {
	    break;
	}
	tries++;
    } while ((r == ERROR_BUFFER_OVERFLOW) && (tries < MAX_TRIES));

    cAddress = adapter;
    while(cAddress) {
	char wName[BUFSIZE];
	WideCharToMultiByte(CP_UTF8, 0, cAddress->FriendlyName,
			    -1, wName, sizeof(wName), NULL, NULL);
       	if (strcmp(wName,nif->name) == 0) {
	    if (cAddress->PhysicalAddressLength >= 6)
		continue; /* just want ethernet for now */
	    if ((asprintf(&mac, "%02X:%02X:%02X:%02X:%02X:%02X",
			  cAddress->PhysicalAddress[0],
			  cAddress->PhysicalAddress[1],
			  cAddress->PhysicalAddress[2],
			  cAddress->PhysicalAddress[3],
			  cAddress->PhysicalAddress[4],
			  cAddress->PhysicalAddress[5])) < 0)
		return NULL;
	    if ((nif->mac = strdup(mac)) != NULL)
		return nif->mac;
	}
	cAddress = cAddress->Next;
    }

 error:
    free(adapter);
    return NULL;
}

int drv_if_down(struct netcf_if *nif) {
    PMIB_IFTABLE intfTable = NULL;
    PMIB_IFROW intRow;
    int i;

    if (intfTable != NULL) {
	for (i = 0; i < intfTable->dwNumEntries; i++) {
	    intRow = (PMIB_IFROW) & intfTable->table[i];
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, intRow->wszName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName,nif->name) == 0) {
		intRow->dwAdminStatus = MIB_IF_ADMIN_STATUS_DOWN;
		if (SetIfEntry(intRow) == NO_ERROR)
		    goto done;
	    }
	}
	/* Unable to shutdown interface */
	free(intfTable);
	return -1;
    }
 done:
    free(intfTable);
    return 0;
}

int drv_if_up(struct netcf_if *nif) {
    PMIB_IFTABLE intfTable = NULL;
    PMIB_IFROW intRow;
    int i;

    if (intfTable != NULL) {
	for (i = 0; i < (int) intfTable->dwNumEntries; i++) {
	    intRow = (PMIB_IFROW) & intfTable->table[i];
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, intRow->wszName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName,nif->name) == 0) {
		intRow->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
		if (SetIfEntry(intRow) == NO_ERROR)
		    goto done;
	    }
	}
	/* Unable to shutdown interface */
	free(intfTable);
	return -1;
    }
 done:
    free(intfTable);
    return 0;
}

int drv_if_ipaddresses(struct netcf_if *nif, char *ipBuf) {
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    PMIB_IPADDRTABLE ipAddrTable = NULL;
    IN_ADDR ipAddr;
    int i;

    if (adapterp != NULL) {
	while(adapterp) {
	    if (adapterp->OperStatus != 1)
		continue;

	    /* pull ip addresses from interface */
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

int drv_add_ip_address(struct netcf_if *nif, char *ipAddr, char *netmask) {
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    PMIB_IPADDRTABLE ipAddrTable = NULL;
    DWORD r;
    DWORD ifIndex;
    int i;

    /* ipv4 addr/subnetmask */
    UINT IPAddress;
    UINT IPNetMask;

    /* handles to IP returned */
    ULONG NTEContext = 0;
    ULONG NTEInstance = 0;

    if ((IPAddress = inet_addr(ipAddr)) == INADDR_NONE)
	return -1;

    if ((IPNetMask = inet_addr(netmask)) == INADDR_NONE)
	return -1;


    if (ipAddrTable != NULL) {
	for(i=0;i<ipAddrTable->dwNumEntries;i++) {
	    ifIndex = ipAddrTable->table[i].dwIndex;
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName,nif->name) == 0) {
		if ((r = AddIPAddress(IPAddress, IPNetMask, ifIndex,
				      &NTEContext, &NTEInstance)) == NO_ERROR) {
		    return 0;
		}
	    }
	}
    }
    free(ipAddrTable);
    return -1;
}


/* needs further testing
int drv_rm_ip_address(struct netcf_if *nif, ULONG NTEContext) {
    DWORD r = 0;
    if ((r = DeleteIpAddress(NTEConext)) == NO_ERROR)
	return 0;
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

/* NOT IMPLEMENTED
int drv_add_dns_server(struct netcf_if *nif, const char *dnsAddr) {
    return -1;
}

int drv_rm_dns_server(struct netcf_if *nif) {
    return -1;
}
*/
