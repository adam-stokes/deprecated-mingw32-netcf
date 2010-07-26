/* NetworkDevice.c - IP Helper functions under mingw32 
 * Copyright (C) 2010 Adam Stokes
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("error allocating memory for getadaptersinfo\n");
        return 1;
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while(pAdapter) {
            printf("IP Address: %s\n", pAdapter->IpAddressList.IpMask.String);
            pAdapter = pAdapter->Next;
            printf("\n");
        }
    } else {
        printf("GetAdaptersInfo failed with : %d\n", dwRetVal);
    }

    if (pAdapterInfo)
        free(pAdapterInfo);
    return 0;
}
