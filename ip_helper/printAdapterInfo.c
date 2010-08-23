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

void displayAdapters(PIP_ADAPTER_INFO pAdapter) {
  while(pAdapter) {
      printf("name: %s\n", pAdapter->AdapterName);
    printf("IP Address: %s\n", pAdapter->IpAddressList.IpAddress.String);
    printf("Subnet: %s\n", pAdapter->IpAddressList.IpMask.String);
    if(pAdapter->DhcpEnabled) {
        printf("DHCP Enabled: %s\n", pAdapter->IpAddressList.IpMask.String);
    }
    pAdapter = pAdapter->Next;
    printf("\n");
  }
}

int main() {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    printf("ulOutBufLen == %u\n", ulOutBufLen);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) {
        printf("error allocating memory for getadaptersinfo\n");
        return 1;
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        printf("First call successful!\n");
        displayAdapters(pAdapterInfo);
    } else if(dwRetVal == ERROR_BUFFER_OVERFLOW) {
        printf("Adjusting buffer size to %u.\n", ulOutBufLen);
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);

        if((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
            displayAdapters(pAdapterInfo);
        }
    }

    if(dwRetVal != NO_ERROR) {
        switch(dwRetVal) {
        case ERROR_BUFFER_OVERFLOW:   printf("Buffer overflow!\n"); break;
        case ERROR_INVALID_DATA:      printf("Invalid data!\n"); break;
        case ERROR_INVALID_PARAMETER: printf("Invalid parameter!\n"); break;
        case ERROR_NO_DATA:           printf("No data!\n"); break;
        case ERROR_NOT_SUPPORTED:     printf("API not supported!\n"); break;
        default:                      printf("Error: %d\n", dwRetVal); break;
      }
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}
