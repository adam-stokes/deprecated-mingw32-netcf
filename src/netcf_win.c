#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include "netcf_win.h"

int 
w32_num_of_interfaces(struct netcf *ncf, unsigned int flags) {
    int nint = 0;
    PIP_INTERFACE_INFO info;
    info = (IP_INTERFACE_INFO *) malloc(sizeof(IP_INTERFACE_INFO));
    ULONG buf = 0;
    DWORD ret = 0;

    if (GetInterfaceInfo(info, &buf) == ERROR_INSUFFICIENT_BUFFER) {
	free(info);
	info = (IP_INTERFACE_INFO *) malloc(buf);
    }
    // 2nd call to getinterface info
    if((ret = GetInterfaceInfo(info, &buf)) == NO_ERROR) {
	nint = info->NumAdapters;
	free(info);
	return nint;
    }
    return 0;
}

int 
w32_list_interface_ids(struct netcf *ncf,
		       int maxnames, char **names,
		       unsigned int flags) {
    int nint = 0, i;
    PIP_ADAPTER_INFO adapterInfo;
    PIP_ADAPTER_INFO adapter = NULL;
    DWORD result = 0;
    ULONG buf;

    adapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
    if(GetAdaptersInfo(adapterInfo, &buf) == ERROR_BUFFER_OVERFLOW) {
	free(adapterInfo);
	adapterInfo = (IP_ADAPTER_INFO *) malloc(buf);
	if((result = GetAdaptersInfo(adapterInfo, &buf)) == NO_ERROR) {
	    adapter = adapterInfo;
	}
    }
    nint = w32_num_of_interfaces(ncf, flags);
    if (!names) {
        maxnames = nint;    /* if not returning list, ignore maxnames too */
    }
    for (i= 0; (result < nint) && (nint < maxnames); i++) {
	printf("\tmoo\n");
    }
    return 0;
}

int
w32_list_interfaces(struct netcf *ncf,
		    int maxnames, char **names,
		    unsigned int flags) {

    return w32_list_interface_ids(ncf, maxnames, names, flags);
}
