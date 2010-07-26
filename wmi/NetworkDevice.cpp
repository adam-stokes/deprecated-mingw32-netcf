/* NetworkDevice.cpp - WMI network info 
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

#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <windows.h>
#include <wbemidl.h>
# pragma comment(lib, "wbemuuid.lib")

void main() {
    HRESULT hr;
    IWbemLocator *pLoc = 0;
    IWbemServices *pSvc = 0;
    IWbemClassObject *pNetworkAdapterClass = 0;

    hr = CoIntializeEx(0, COINIT_MULTITHREADED);
    if(FAILED(hr)) {
        cout << "Failed to init COM, error = 0x"
            << hex << hr << endl;
        return hr;
    }

    hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL);
    if (FAILED(hr)) {
        cout << "failed to init security" << endl;
        CoUnintialize();
        return hr;
    }


    hr = CoCreateInstance(CLSID_WbemLocator, 0,
            CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);

    if(FAILED(hr)) {
        CoUnintialize();
        return hr;
    }

    IWbemServices *pSvc = 0;
    hr = pLoc->ConnectServer(
            BSTR(L"ROOT\\DEFAULT").
            NULL, NULL, 0, NULL, 0, 0, &pSvc);

    if(FAILED(hr)) {
        pLoc->Release();
        CoUnintialize();
        return hr;
    }

    cout << "connected to wmi" << endl;


    // Set the proxy so that impersonation of the client occurs.
    hr = CoSetProxyBlanket(pSvc,
       RPC_C_AUTHN_WINNT,
       RPC_C_AUTHZ_NONE,
       NULL,
       RPC_C_AUTHN_LEVEL_CALL,
       RPC_C_IMP_LEVEL_IMPERSONATE,
       NULL,
       EOAC_NONE
    );

    if (FAILED(hr)) {
       cout << "Could not set proxy blanket. Error code = 0x" 
       << hex << hres << endl;
       pSvc->Release();
       pLoc->Release();     
       CoUninitialize();
       return hres;      // Program has failed.
    }

    hr = IWbemServices::GetObject("Win32_NetworkAdapterConfiguration",
                                  WBEM_FLAG_RETURN_WBEM_COMPLETE,
                                  NULL,
                                  &pNetworkAdapterClass,
                                  NULL);

    if(hr != WBEM_S_NO_ERROR) {
        cout << "can not grab network adapter configuration" << endl;
    }

    _variant_t vaMacAddress;
    hr = pNetworkAdapterClass->Get("MACAddress", 0, &vaMacAddress, NULL, NULL);

    cout << "MAC Address is: " << vaMacAddress << endl;
}
