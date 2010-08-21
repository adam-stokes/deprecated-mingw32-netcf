#include <config.h>
#include <internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include "netcf_win.h"
#include "dutil.h"

MIB_IFTABLE *w32_intf_table(MIB_IFTABLE *intfTable) {
    /* return interface table */
    DWORD intfTableSize = 0;
    DWORD result = 0;

    intfTable = (MIB_IFTABLE *) malloc(sizeof (MIB_IFTABLE));
    if (intfTable == NULL)
	return intfTable;

    intfTableSize = sizeof(MIB_IFTABLE);
    if (GetIfTable(intfTable, &intfTableSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
	free(intfTable);
	intfTable = malloc(sizeof(intfTableSize));
	if (intfTableSize == NULL)
	    return intfTable;
    }

    if ((result = GetIfTable(intfTable, &intfTableSize, 0)) == NO_ERROR) {
	/* Do we have interface entries in the table? */
	if (intfTable->dwNumEntries > 0)
	    return intfTable;
    }
    return intfTable;
}

int w32_list_interface_ids(struct netcf *ncf,
		       int maxnames, char **names,
		       unsigned int flags) {
    int nint = 0, i;
    PIP_INTERFACE_INFO adapterInfo;
    PIP_INTERFACE_INFO adapter = NULL;
    DWORD result = 0;
    ULONG buf;

    adapterInfo = (IP_INTERFACE_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
    if(GetInterfaceInfo(adapterInfo, &buf) == ERROR_INSUFFICIENT_BUFFER) {
	free(adapterInfo);
	adapterInfo = (IP_INTERFACE_INFO *) malloc(buf);
    }
    if((result = GetInterfaceInfo(adapterInfo, &buf)) == NO_ERROR) {
	nint = adapterInfo->NumAdapters;
	if (!names) {
	    maxnames = nint;    /* if not returning list, ignore maxnames too */
	}
	for (i = 0; (i < nint) && (nint < maxnames); i++) {
	    /* needs active testing, etc */
	    const char *name;
	    if (names) {
		names[i] = strdup(adapterInfo->Adapter[i].Name);
		if (names[i] == NULL)
		    return -1;
	    }
	}
	free(adapterInfo);
    } else {
	/* Some kind of failure, usually no adapters present */
	return -1;
    }
    return nint;
}

int w32_list_interfaces(struct netcf *ncf,
		    int maxnames, char **names,
		    unsigned int flags) {
    return w32_list_interface_ids(ncf, maxnames, names, flags);
}

int w32_num_of_interfaces(struct netcf *ncf, unsigned int flags) {
    return w32_list_interface_ids(ncf, 0, NULL, flags);
}

struct netcf_if *w32_lookup_by_name(struct netcf *ncf, const char *name) {
    struct netcf_if *nif = NULL;
    char *name_dup = NULL;
    MIB_IFTABLE *intfTable = NULL;
    MIB_IFTABLE *intfTableDup = NULL;
    DWORD ret = 0;

    intfTableDup = w32_intf_table(intfTable);
    
    if (intfTableDup != NULL) {
	MIB_IFROW *intfRow;

	intfRow = (MIB_IFROW *) malloc(sizeof(MIB_IFROW));
	if (intfRow == NULL)
	    return nif;

	for (int i = 0; i < (int) intfTableDup->dwNumEntries; i++) {
	    intfRow->dwIndex = intfTableDup->table[i].dwIndex;
	    if (( ret = GetIfEntry(intfRow)) == NO_ERROR) {
		/* TODO: Make sure NAME exist and is not a slave */
		if ((intfRow->wszName != NULL) && (intfRow->wszName == name)) {
		    name_dup = strdup(intfRow->wszName);
		    nif = make_netcf_if(ncf, name_dup);
		}
	    }
	}
    }
    /* Return NIF no matter what */
    return nif;
}

const char *w32_mac_string(struct netcf_if *nif) {
    struct netcf *ncf = nif->ncf;
    const char *mac;
    char *path = NULL;
    
    /* TODO: lookup mac string by adapter name */
    if (mac != NULL) {
	if (nif->mac == NULL || STRNEQ(nif->mac, mac)) {
	    free(nif->mac);
	    nif->mac = strdup(mac);
	    if (nif->mac == NULL) {
		return nif->mac;
	    }
	} else {
	    free(nif->mac);
	}
    }
    return nif->mac;
}
