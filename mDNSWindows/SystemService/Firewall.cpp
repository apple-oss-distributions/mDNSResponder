/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
    
$Log: Firewall.cpp,v $
Revision 1.2  2004/09/15 09:39:53  shersche
Retry the method INetFwPolicy::get_CurrentProfile on error

Revision 1.1  2004/09/13 07:32:31  shersche
Wrapper for Windows Firewall API code


*/

#define _WIN32_DCOM 

#include "Firewall.h"
#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>


static const int kMaxTries			= 30;
static const int kRetrySleepPeriod	= 1 * 1000; // 1 second


static OSStatus
mDNSFirewallInitialize(OUT INetFwProfile ** fwProfile)
{
	INetFwMgr		*	fwMgr		= NULL;
	INetFwPolicy	*	fwPolicy	= NULL;
	int					numRetries	= 0;
	HRESULT				err			= kNoErr;
    
	_ASSERT(fwProfile != NULL);

    *fwProfile = NULL;

	// Use COM to get a reference to the firewall settings manager.  This
	// call will fail on anything other than XP SP2

	err = CoCreateInstance( __uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr );
	require(SUCCEEDED(err), exit);

	// Use the reference to get the local firewall policy

	err = fwMgr->get_LocalPolicy(&fwPolicy);
	require(SUCCEEDED(err), exit);

	// Use the reference to get the extant profile. Empirical evidence
	// suggests that there is the potential for a race condition when a system
	// service whose startup type is automatic calls this method.
	// This is true even when the service declares itself to be dependent
	// on the firewall service. Re-trying the method will succeed within
	// a few seconds.

	do
	{
    	err = fwPolicy->get_CurrentProfile(fwProfile);

		if (err)
		{
			Sleep(kRetrySleepPeriod);
		}
	}
	while (err && (numRetries++ < kMaxTries));

	require(SUCCEEDED(err), exit);

	err = kNoErr;

exit:

	// Release temporary COM objects

    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return err;
}


static void
mDNSFirewallCleanup
			(
			IN INetFwProfile	*	fwProfile
			)
{
	// Call Release on the COM reference.

    if (fwProfile != NULL)
    {
        fwProfile->Release();
    }
}


static OSStatus
mDNSFirewallAppIsEnabled
			(
			IN INetFwProfile	*	fwProfile,
			IN const wchar_t	*	fwProcessImageFileName,
			OUT BOOL			*	fwAppEnabled    
			)
{
	BSTR							fwBstrProcessImageFileName = NULL;
	VARIANT_BOOL					fwEnabled;
	INetFwAuthorizedApplication	*	fwApp	= NULL;
	INetFwAuthorizedApplications*	fwApps	= NULL;
	OSStatus						err		= kNoErr;
    
	_ASSERT(fwProfile != NULL);
	_ASSERT(fwProcessImageFileName != NULL);
	_ASSERT(fwAppEnabled != NULL);

    *fwAppEnabled = FALSE;

	// Get the list of authorized applications

	err = fwProfile->get_AuthorizedApplications(&fwApps);
	require(SUCCEEDED(err), exit);

    fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
	require_action(SysStringLen(fwBstrProcessImageFileName) > 0, exit, err = kNoMemoryErr);

	// Look for us

    err = fwApps->Item(fwBstrProcessImageFileName, &fwApp);
	
    if (SUCCEEDED(err))
    {
        // It's listed, but is it enabled?

		err = fwApp->get_Enabled(&fwEnabled);
		require(SUCCEEDED(err), exit);

        if (fwEnabled != VARIANT_FALSE)
        {
			// Yes, it's enabled

            *fwAppEnabled = TRUE;
		}
	}

	err = kNoErr;

exit:

	// Deallocate the BSTR

    SysFreeString(fwBstrProcessImageFileName);

	// Release the COM objects

    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    if (fwApps != NULL)
    {
        fwApps->Release();
    }

    return err;
}


static OSStatus
mDNSFirewallAddApp
			(
            IN INetFwProfile	*	fwProfile,
            IN const wchar_t	*	fwProcessImageFileName,
            IN const wchar_t	*	fwName
            )
{
	BOOL							fwAppEnabled;
	BSTR							fwBstrName = NULL;
	BSTR							fwBstrProcessImageFileName = NULL;
	INetFwAuthorizedApplication	*	fwApp = NULL;
	INetFwAuthorizedApplications*	fwApps = NULL;
	OSStatus						err = S_OK;
    
	_ASSERT(fwProfile != NULL);
    _ASSERT(fwProcessImageFileName != NULL);
    _ASSERT(fwName != NULL);

    // First check to see if the application is already authorized.
	err = mDNSFirewallAppIsEnabled( fwProfile, fwProcessImageFileName, &fwAppEnabled );
	require_noerr(err, exit);

	// Only add the application if it isn't enabled

	if (!fwAppEnabled)
	{
		// Get the list of authorized applications

        err = fwProfile->get_AuthorizedApplications(&fwApps);
		require(SUCCEEDED(err), exit);

        // Create an instance of an authorized application.

		err = CoCreateInstance( __uuidof(NetFwAuthorizedApplication), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwAuthorizedApplication), (void**)&fwApp );
		require(SUCCEEDED(err), exit);

        fwBstrProcessImageFileName = SysAllocString(fwProcessImageFileName);
		require_action(SysStringLen(fwBstrProcessImageFileName) > 0, exit, err = kNoMemoryErr);

		// Set the executable file name

		err = fwApp->put_ProcessImageFileName(fwBstrProcessImageFileName);
		require(SUCCEEDED(err), exit);

		fwBstrName = SysAllocString(fwName);
		require_action(SysStringLen(fwBstrName) > 0, exit, err = kNoMemoryErr);

		// Set the friendly name

        err = fwApp->put_Name(fwBstrName);
		require(SUCCEEDED(err), exit);

		// Now add the application

        err = fwApps->Add(fwApp);
		require(SUCCEEDED(err), exit);
	}

	err = kNoErr;

exit:

	// Deallocate the BSTR objects

    SysFreeString(fwBstrName);
    SysFreeString(fwBstrProcessImageFileName);

    // Release the COM objects

    if (fwApp != NULL)
    {
        fwApp->Release();
    }

    if (fwApps != NULL)
    {
        fwApps->Release();
    }

    return err;
}


OSStatus
mDNSAddToFirewall
		(
		LPWSTR	executable,
		LPWSTR	name
		)
{
	INetFwProfile	*	fwProfile	= NULL;
	HRESULT				comInit		= E_FAIL;
	OSStatus			err			= kNoErr;

	// Initialize COM.

	comInit = CoInitializeEx( 0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE );

	// Ignore this case. RPC_E_CHANGED_MODE means that COM has already been
	// initialized with a different mode.

	if (comInit != RPC_E_CHANGED_MODE)
	{
		err = comInit;
		require(SUCCEEDED(err), exit);
	}

	// Connect to the firewall

	err = mDNSFirewallInitialize(&fwProfile);
	require_noerr(err, exit);

	// Add us to the list of exempt programs

	err = mDNSFirewallAddApp( fwProfile, executable, name );
	require_noerr(err, exit);

exit:

	// Disconnect from the firewall

	mDNSFirewallCleanup(fwProfile);

	// De-initialize COM

	if (SUCCEEDED(comInit))
    {
        CoUninitialize();
    }

	return err;
}
