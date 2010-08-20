#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <iphlpapi.h>

int num_interfaces() {
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

static int list_interface_ids(struct netcf *ncf,
                              int maxnames, char **names,
                              unsigned int flags,
                              const char *id_attr) {
    int nint = 0, result = 0;
    nint = num_interfaces();
    printf("There are %d interfaces present\n", nint);
    if (!names) {
        maxnames = nint;    /* if not returning list, ignore maxnames too */
    }
    for (result = 0; (result < nint) && (nint < maxnames); result++) {
	printf("tehehehehe\n");
    }
    return 0;
}
