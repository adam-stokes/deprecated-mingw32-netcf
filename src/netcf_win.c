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

MIB_IFROW *w32_intf_row(MIB_IFROW *intfRow, const char *name) {
    /* return a matched interface row */
    MIB_IFTABLE *intfTable = NULL;
    MIB_IFTABLE *intfTableDup = NULL;
    DWORD ret = 0;
    
    /* TODO: lookup mac string by adapter name */
    intfTableDup = w32_intf_table(intfTable);
    if (intfTableDup != NULL) {
	intfRow = (MIB_IFROW *) malloc(sizeof(MIB_IFROW));
	if (intfRow == NULL)
	    return NULL;
	for (int i = 0; i < (int) intfTableDup->dwNumEntries; i++) {
	    intfRow->dwIndex = intfTableDup->table[i].dwIndex;
	    if (( ret = GetIfEntry(intfRow)) == NO_ERROR) {
		/* TODO: Make sure NAME exist and is not a slave */
		char name_dup[1024];
		WideCharToMultiByte(CP_UTF8, 0, intfRow->wszName, -1, name_dup,
				    sizeof(name_dup), NULL, NULL);
		if (strcmp(name_dup,name) == 0) {
		    return intfRow;
		}
	    }
	}
    }
    return intfRow;
}

int w32_list_interface_ids(struct netcf *ncf,
		       int maxnames, char **names,
		       unsigned int flags) {
    int nint = 0, i;
    PIP_INTERFACE_INFO adapterInfo;
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
	    maxnames = nint;
	}
	for (i = 0; i < nint; i++) {
	    char name[1024];
	    if (names) {
		WideCharToMultiByte(CP_UTF8, 0, adapterInfo->Adapter[i].Name,
				    -1, name, sizeof(name), NULL, NULL);
		names[i] = strdup(name);
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
		char name_dup[1024];
		WideCharToMultiByte(CP_UTF8, 0, intfRow->wszName, -1, name_dup,
				    sizeof(name_dup), NULL, NULL);
		if (strcmp(name_dup,name) == 0) {
		    nif = make_netcf_if(ncf, name_dup);
		    return nif;
		}
	    }
	}
    }
    /* Return NIF no matter what */
    return nif;
}

const char *w32_mac_string(struct netcf_if *nif) {
    struct netcf *ncf = nif->ncf;
    static BYTE macBuf[6];
    MIB_IFROW *row, *tmpIf;

    memset(macBuf, 0, sizeof(macBuf));

    /* clear mac */
    nif->mac = NULL;
    if (nif->mac == NULL) {
	free(nif->mac);
	row = w32_intf_row(tmpIf, nif->name);
	memcpy(macBuf, row->bPhysAddr, row->dwPhysAddrLen);
	nif->mac = strdup((char *)macBuf);
	free(nif->mac);
    }
    return nif->mac;
}
