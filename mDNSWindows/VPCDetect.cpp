/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@

    Change History (most recent first):
    
$Log: VPCDetect.cpp,v $
Revision 1.1  2005/11/27 20:21:16  herscher
<rdar://problem/4210580> Workaround Virtual PC bug that incorrectly modifies incoming mDNS packets

*/

#define _WIN32_DCOM
#include "VPCDetect.h"
#include "DebugServices.h"
#include <comdef.h>
#include <Wbemidl.h>

# pragma comment(lib, "wbemuuid.lib")

static BOOL g_doneCheck = FALSE;
static BOOL g_isVPC		= FALSE;


BOOL
IsVPCRunning()
{
	IWbemLocator			*	pLoc 		= 0;
	IWbemServices			*	pSvc 		= 0;
    IEnumWbemClassObject	*	pEnumerator = NULL;
	bool						coInit 		= false;
	HRESULT						hres;

	// Short circuit if we've already done this

	require_action_quiet( !g_doneCheck, exit, g_doneCheck = TRUE );

    // Initialize COM.

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );
	coInit = true;

	// Initialize Security

	hres =  CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );

                      
    // Obtain the initial locator to Windows Management on a particular host computer.

    hres = CoCreateInstance( CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc );
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );
 
    // Connect to the root\cimv2 namespace with the
    // current user and obtain pointer pSvc
    // to make IWbemServices calls.

	hres = pLoc->ConnectServer( _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc );
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );
    
    // Set the IWbemServices proxy so that impersonation
    // of the user (client) occurs.

	hres = CoSetProxyBlanket( pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE );
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:

	hres = pSvc->ExecQuery( bstr_t("WQL"), bstr_t("SELECT * from Win32_BaseBoard"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    
	require_action( SUCCEEDED( hres ), exit, g_isVPC = false );

	do
	{
		IWbemClassObject* pInstance = NULL;
		ULONG dwCount = NULL;

		hres = pEnumerator->Next( WBEM_INFINITE, 1, &pInstance, &dwCount);

		if ( pInstance )
		{
			VARIANT v;
			BSTR strClassProp = SysAllocString(L"Manufacturer");
			HRESULT hr;

			hr = pInstance->Get(strClassProp, 0, &v, 0, 0);
			SysFreeString(strClassProp);

			// check the HRESULT to see if the action succeeded.

			if (SUCCEEDED(hr) && (V_VT(&v) == VT_BSTR))
			{
				wchar_t * wstring = wcslwr( V_BSTR( &v ) );

				if (wcscmp( wstring, L"microsoft corporation" ) == 0 )
				{
					g_isVPC = true;
				}
			}
		
			VariantClear(&v);
		}
	} while (hres == WBEM_S_NO_ERROR);
         
exit:
 
	if ( pSvc != NULL )
	{
    	pSvc->Release();
	}

	if ( pLoc != NULL )
	{
    	pLoc->Release();     
	}

	if ( coInit )
	{
    	CoUninitialize();
	}

	if ( !g_doneCheck )
	{
		g_doneCheck = TRUE;

		if ( g_isVPC )
		{
			dlog( kDebugLevelTrace, "Virtual PC detected" );
		}
	}

	return g_isVPC;
}
