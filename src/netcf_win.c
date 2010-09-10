#include <config.h>
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include "netcf_win.h"

#define ADDR_BLOCK 5
#define GAA_FLAGS ( GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST )
#define BUFSIZE 1024

PMIB_IPADDRTABLE _get_ip_addr_table(PMIB_IPADDRTABLE ipAddrTable) {
    DWORD r = 0;
    DWORD buf = 0;

    ipAddrTable = (PMIB_IPADDRTABLE) sizeof (MIB_IPADDRTABLE);
    if (GetIpAddrTable(ipAddrTable, &buf, 0) == ERROR_INSUFFICIENT_BUFFER) {
	free(ipAddrTable);
	ipAddrTable = (PMIB_IPADDRTABLE) malloc(buf);
	if (ipAddrTable == NULL)
	    goto error;
    }

    if((r = GetIpAddrTable(ipAddrTable, &buf, 0)) == NO_ERROR)
	return ipAddrTable;

 error:
    free(ipAddrTable);
    return ipAddrTable;
}

PMIB_IFTABLE _get_if_table(PMIB_IFTABLE intfTable) {
    DWORD bufferLength = 0;
    DWORD r = 0;
    intfTable = (PMIB_IFTABLE) malloc(sizeof(MIB_IFTABLE));
    if (intfTable == NULL)
	goto error;

    bufferLength = sizeof(MIB_IFTABLE);
    if (GetIfTable(intfTable, &bufferLength, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
	free(intfTable);
	intfTable = (PMIB_IFTABLE) malloc(bufferLength);
	if (intfTable == NULL)
	    goto error;
    }

    if ((r = GetIfTable(intfTable, &bufferLength, FALSE)) == NO_ERROR)
	return intfTable;
 error:
    free(intfTable);
}

PIP_ADAPTER_ADDRESSES _get_ip_adapter_info(PIP_ADAPTER_ADDRESSES addrList) {
    ULONG bufferLength = 0;
    DWORD r;
    int i;

    for(i = 0; i < ADDR_BLOCK; i++) {
	r = GetAdaptersAddresses(AF_INET, GAA_FLAGS, NULL, addrList, &bufferLength);
	if (r != ERROR_BUFFER_OVERFLOW) {
	    break;
	}
	if (addrList != NULL) {
	    goto error;
	}
	addrList = (PIP_ADAPTER_ADDRESSES) malloc(bufferLength);
	if (addrList == NULL)
	    goto error;
    }	
    return addrList;
 error:
    free(addrList);
}

struct netcf_if *drv_define(struct netcf *ncf, const char *xml_str) {
#ifdef WIN32
    return ncf;
#endif
}

static bool has_ifcfg_file(struct netcf *ncf, const char *name) {
#ifdef WIN32
    return FALSE;
#endif
}

static bool is_bond(struct netcf *ncf, const char *name) {
#ifdef WIN32
    return FALSE;
#endif
}

static bool is_bridge(struct netcf *ncf, const char *name) {
#ifdef WIN32
    return FALSE;
#endif
}

static char *device_name_from_xml(struct netcf *ncf, xmlDocPtr ncf_xml) {
#ifdef WIN32
    char *ret = NULL;
    return ret;
#endif
}

static char *find_ifcfg_path_by_device(struct netcf *ncf, const char *name) {
#ifdef WIN32
    char *ret = NULL;
    return ret;
#endif
}

static char *find_ifcfg_path_by_hwaddr(struct netcf *ncf, const char *mac) {
#ifdef WIN32
    char *ret = NULL;
    return ret;
#endif
}

static char *find_ifcfg_path(struct netcf *ncf, const char *name) {
#ifdef WIN32
    char *ret = NULL;
    return ret;
#endif
}

static int aug_put_xml(struct netcf *ncf, xmlDocPtr xml) {
#ifdef WIN32
    return -1;
#endif
}
static int bridge_slaves(struct netcf *ncf, const char *name, char ***slaves) {
#ifdef WIN32
    return -1;
#endif
}

static int cmpstrp(const void *p1, const void *p2) {
#ifdef WIN32
    return -1;
#endif
}

static int is_slave(struct netcf *ncf, const char *intf) {
#ifdef WIN32
    return -1;
#endif
}

static int list_ifcfg_paths(struct netcf *ncf, char ***intf) {
#ifdef WIN32
    return -1;
#endif
}

static int list_interfaces(struct netcf *ncf, char ***intf){
#ifdef WIN32
    return -1;
#endif
}

static int uniq_ifcfg_paths(struct netcf *ncf, int ndevs, char **devs, char ***intf) {
#ifdef WIN32
    return -1;
#endif
}

static void bond_setup(struct netcf *ncf, const char *name, bool alias) {
#ifdef WIN32
    return;
#endif
}

static void bridge_physdevs(struct netcf *ncf) {
#ifdef WIN32
    return;
#endif
}

static void rm_all_interfaces(struct netcf *ncf, xmlDocPtr ncf_xml) {
#ifdef WIN32
    return;
#endif
}

static void rm_interface(struct netcf *ncf, const char *name) {
#ifdef WIN32
    return;
#endif
}

static xmlDocPtr aug_get_xml_for_nif(struct netcf_if *nif) {
#ifdef WIN32
    xmlDocPtr result = NULL;
    return result;
#endif
}

static xmlDocPtr aug_get_xml(struct netcf *ncf, int nint, char **intf) {
#ifdef WIN32
    xmlDocPtr result = NULL;
    return result;
#endif
}

void drv_entry(struct netcf *ncf) {
#ifdef WIN32
    return;
#endif
}

void drv_close(struct netcf *ncf) {
#ifdef WIN32
    return;
#endif
}

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
    result->name = name;
    return result;

 error:
    unref(result, netcf_if);
    return result;
}
    
static int list_interface_ids(struct netcf *ncf ATTRIBUTE_UNUSED, 
				  int maxnames ATTRIBUTE_UNUSED,
				  char **names, unsigned int flags ATTRIBUTE_UNUSED,
				  const char *id_attr ATTRIBUTE_UNUSED) {
    unsigned int nint = 0;

    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    adapterp = _get_ip_adapter_info(addrList);
    for (nint = 0; adapterp != NULL; nint++) {
	if (names) {
	    char name[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
				-1, name, sizeof(name), NULL, NULL);
	    names[nint] = strdup(name);
	}
	adapterp = adapterp->Next;
    }
    return nint;
 error:
    free(addrList);
    return -1;
}

int drv_list_interfaces(struct netcf *ncf,
		    int maxnames ATTRIBUTE_UNUSED, char **names,
		    unsigned int flags ATTRIBUTE_UNUSED) {
    return list_interface_ids(ncf, 0, names, 0, NULL);
}


int drv_num_of_interfaces(struct netcf *ncf, unsigned int flags ATTRIBUTE_UNUSED) {
    return list_interface_ids(ncf, 0, NULL, 0, NULL);
}


struct netcf_if *drv_lookup_by_name(struct netcf *ncf, const char *name) {
    struct netcf_if *nif = NULL;
    char *name_dup;
    unsigned int nint = 0;
    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    adapterp = _get_ip_adapter_info(addrList);
    for (nint = 0; adapterp != NULL; nint++) {
	if (name) {
	    char wName[BUFSIZE];
	    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
				-1, wName, sizeof(wName), NULL, NULL);
	    if (strcmp(wName, name) == 0) {
		name_dup = strdup(wName);
		nif = make_netcf_if(ncf, name_dup);
		goto done;
	    }
	}
	adapterp = adapterp->Next;
    }

 done:
    return nif;
}


const char *drv_mac_string(struct netcf_if *nif) {
    // struct netcf *ncf = nif->ncf;

    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    adapterp = _get_ip_adapter_info(addrList);
    while(adapterp != NULL) {
	char wName[BUFSIZE];
	WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
			    -1, wName, sizeof(wName), NULL, NULL);
       	if (strcmp(wName,nif->name) == 0) {
	    if ((int)adapterp->PhysicalAddressLength >= 6)
		continue; /* just want ethernet for now */
	    nif->mac = asprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
				adapterp->PhysicalAddress[0],
				adapterp->PhysicalAddress[1],
				adapterp->PhysicalAddress[2],
				adapterp->PhysicalAddress[3],
				adapterp->PhysicalAddress[4],
				adapterp->PhysicalAddress[5]);
	    goto done;
	}
	adapterp = adapterp->Next;
    }
 done:
    return nif->mac;
}

int drv_if_down(struct netcf_if *nif) {
    PMIB_IFTABLE intfTable = NULL;
    PMIB_IFTABLE intfTableDup = NULL;
    PMIB_IFROW intRow;
    int i;

    intfTableDup = _get_if_table(intfTable);
    if (intfTableDup != NULL) {
	for (i = 0; i < (int) intfTableDup->dwNumEntries; i++) {
	    intRow = (PMIB_IFROW) & intfTableDup->table[i];
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
	return -1;
    }
 done:
    return 0;
}

int drv_if_up(struct netcf_if *nif) {
    PMIB_IFTABLE intfTable = NULL;
    PMIB_IFTABLE intfTableDup = NULL;
    PMIB_IFROW intRow;
    int i;

    intfTableDup = _get_if_table(intfTable);
    if (intfTableDup != NULL) {
	for (i = 0; i < (int) intfTableDup->dwNumEntries; i++) {
	    intRow = (PMIB_IFROW) & intfTableDup->table[i];
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
	return -1;
    }
 done:
    return 0;
}

int drv_if_ipaddresses(struct netcf_if *nif, char *ipBuf) {
    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    PMIB_IPADDRTABLE ipAddrTable = NULL; 
    PMIB_IPADDRTABLE ipAddrTableDup = NULL;
    IN_ADDR ipAddr;
    DWORD r = 0;
    int i;

    if ((ipAddrTableDup = _get_ip_addr_table(ipAddrTable)) == NULL)
	return -1;

    adapterp = _get_ip_adapter_info(addrList);
    if (adapterp != NULL) {
	while(adapterp) {
	    if (adapterp->OperStatus != 1)
		continue;

	    /* pull ip addresses from interface */
	    for (i = 0; i<ipAddrTableDup->dwNumEntries; i++) {
		if (ipAddrTableDup->table[i].dwIndex == adapterp->IfIndex) {
		    char wName[8192];
		    WideCharToMultiByte(CP_UTF8, 0, adapterp->FriendlyName,
					-1, wName, sizeof(wName), NULL, NULL);
		    if (strcmp(wName,nif->name) == 0) {
			ipAddr.S_un.S_addr = (unsigned long) ipAddrTableDup->table[i].dwAddr;
			sprintf(ipBuf,"%d",inet_ntoa(ipAddr));
			return 0;
		    }
		}
	    }
	    adapterp = adapterp->Next;
	}

    }
    free(ipAddrTable);
    free(addrList);
    return -1;
}

int drv_add_ip_address(struct netcf_if *nif, char *ipAddr, char *netmask) {
    IN_ADDR addr;
    PIP_ADAPTER_ADDRESSES addrList = NULL;
    PIP_ADAPTER_ADDRESSES adapterp = NULL;
    PMIB_IPADDRTABLE ipAddrTable = NULL;
    PMIB_IPADDRTABLE ipAddrTableDup = NULL;
    ULONG bufferLength = 0;
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


    ipAddrTableDup = _get_ip_addr_table(ipAddrTable);
    if (ipAddrTableDup != NULL) {
	for(i=0;i<ipAddrTableDup->dwNumEntries;i++) {
	    ifIndex = ipAddrTableDup->table[i].dwIndex;
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
		     "%d.%d.%d.%d", (ip >> 0) & 255, (ip >> 8) & 255,
		     (ip >> 16) & 255, (ip >> 24) & 255);
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
