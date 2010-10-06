#include <config.h>
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include "netcf_win.h"

#define ADDR_BLOCK 5
#define GAA_FLAGS ( GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST )
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

static PIP_ADAPTER_ADDRESSES get_ip_adapter_info(void) {
    PIP_ADAPTER_ADDRESSES addrList = NULL;
    ULONG bufferLength = 0;
    DWORD r;
    size_t i;

    for(i = 0; i < ADDR_BLOCK; i++) {
	r = GetAdaptersAddresses(AF_INET, GAA_FLAGS, NULL, addrList, &bufferLength);
	if (r != ERROR_BUFFER_OVERFLOW) {
	    break;
	}
	if (addrList != NULL) {
	    free(addrList);
	}
	if ((addrList = malloc(sizeof(bufferLength))) == NULL)
	    return addrList;
    }
    return addrList;
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

static int list_interface_ids(struct netcf *ncf ATTRIBUTE_UNUSED,
				  int maxnames,
				  char **names, unsigned int flags,
				  const char *id_attr ATTRIBUTE_UNUSED) {
    unsigned int nint = 0;

    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    adapterp = get_ip_adapter_info();
    for (nint = 0; adapterp != NULL && nint < maxnames; nint++) {
	if (names) {
	    char name[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
				-1, name, sizeof(name), NULL, NULL);
	    if ((names[nint] = strdup(name)) == NULL)
		goto error;
	}
	maxnames++;
	adapterp = adapterp->Next;
    }
    return nint;
 error:
    for (nint = 0; nint < maxnames; nint++) {
	free(names[nint]);
    }
    free(addrList);
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
    unsigned int nint = 0;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    char *nameDup = NULL;

    adapterp = get_ip_adapter_info();
    for (nint = 0; adapterp != NULL; nint++) {
	if (name) {
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName, name) == 0) {
		nameDup = strdup(wName);
		nif = make_netcf_if(ncf, nameDup);
	    }
	}
	adapterp = adapterp->Next;
    }
    free(nameDup);
    return nif;
}


const char *drv_mac_string(struct netcf_if *nif) {
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    adapterp = get_ip_adapter_info();
    int r;
    char *mac;

    while(adapterp != NULL) {
	char wName[BUFSIZE];
	WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
			    -1, wName, sizeof(wName), NULL, NULL);
       	if (strcmp(wName,nif->name) == 0) {
	    if (adapterp->PhysicalAddressLength >= 6)
		continue; /* just want ethernet for now */
	    if ((r = asprintf(&mac, "%02X:%02X:%02X:%02X:%02X:%02X",
			      adapterp->PhysicalAddress[0],
			      adapterp->PhysicalAddress[1],
			      adapterp->PhysicalAddress[2],
			      adapterp->PhysicalAddress[3],
			      adapterp->PhysicalAddress[4],
			      adapterp->PhysicalAddress[5])) < 0)
		return NULL;
	    if ((nif->mac = strdup(mac)) != NULL)
		return nif->mac;
	}
	adapterp = adapterp->Next;
    }
    return NULL;
}

int drv_if_down(struct netcf_if *nif) {
    PMIB_IFTABLE intfTable = NULL;
    PMIB_IFROW intRow;
    int i;

    intfTable = get_if_table();
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

    intfTable = get_if_table();
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

    if ((ipAddrTable = get_ip_addr_table()) == NULL)
	return -1;

    adapterp = get_ip_adapter_info();
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


    ipAddrTable = get_ip_addr_table();
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
