/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
    
$Log: dllmain.c,v $
Revision 1.3  2005/07/07 19:18:29  shersche
Fix error in previous checkin, change SystemServiceIsDisabled() to IsSystemServiceDisabled()

Revision 1.2  2005/06/30 17:55:35  shersche
<rdar://problem/4096913> Implement ISSystemServiceDisabled().  This is used to determine how long we should wait to connect to the system service.

Revision 1.1  2004/06/18 03:55:11  rpantos
Move DLL up to main level; additional integration from Scott.

Revision 1.1  2004/02/21 04:16:50  bradley
DLL wrapper for DNS-SD API.

*/

#include <windows.h>
#include <DebugServices.h>

BOOL APIENTRY	DllMain( HANDLE inModule, DWORD inReason, LPVOID inReserved )
{
	(void) inModule;
	(void) inReserved;
	
	switch( inReason )
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
    return( TRUE );
}


BOOL
IsSystemServiceDisabled()
{
	ENUM_SERVICE_STATUS	*	lpService = NULL;
	SC_HANDLE					sc;
	BOOL							ret = FALSE;
	BOOL							ok;
	DWORD							bytesNeeded = 0;
	DWORD							srvCount;
	DWORD							resumeHandle = 0;
	DWORD							srvType;
	DWORD							srvState;
	DWORD							dwBytes = 0;
	DWORD							i;
	OSStatus						err;

	sc = OpenSCManager( NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE );
	err = translate_errno( sc, GetLastError(), kUnknownErr );
	require_noerr( err, exit );

	srvType		=	SERVICE_WIN32;
	srvState		=	SERVICE_STATE_ALL;

	for ( ;; )
	{
		// Call EnumServicesStatus using the handle returned by OpenSCManager

		ok = EnumServicesStatus ( sc, srvType, srvState, lpService, dwBytes, &bytesNeeded, &srvCount, &resumeHandle );

		if ( ok || ( GetLastError() != ERROR_MORE_DATA ) )
		{
			break;
		}

		if ( lpService )
		{
			free( lpService );
		}

		dwBytes = bytesNeeded;

		lpService = ( ENUM_SERVICE_STATUS* ) malloc( dwBytes );
		require_action( lpService, exit, ret = FALSE );
	}

	err = translate_errno( ok, GetLastError(), kUnknownErr );
	require_noerr( err, exit );

	for ( i = 0; i < srvCount; i++ )
	{
		if ( strcmp( lpService[i].lpServiceName, "Bonjour Service" ) == 0 )
		{
			if ( ( lpService[i].ServiceStatus.dwCurrentState == SERVICE_PAUSED ) || ( lpService[i].ServiceStatus.dwCurrentState == SERVICE_STOPPED ) )
			{
				ret = TRUE;
			}

			break;
		}
	}

exit:

	if ( lpService )
	{
		free( lpService );
	}

	if ( sc )
	{
		CloseServiceHandle ( sc );
	}

	return ret;
}
