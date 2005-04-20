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
    
$Log: mdnsNSP.c,v $
Revision 1.10  2005/02/23 22:16:07  shersche
Unregister the NSP before registering to workaround an installer problem during upgrade installs

Revision 1.9  2005/02/01 01:45:55  shersche
Change mdnsNSP timeout to 2 seconds

Revision 1.8  2005/01/31 23:27:25  shersche
<rdar://problem/3936771> Don't try and resolve .local hostnames that are referenced in the hosts file

Revision 1.7  2005/01/28 23:50:13  shersche
<rdar://problem/3942551> Implement DllRegisterServer,DllUnregisterServer so mdnsNSP.dll can self-register
Bug #: 3942551

Revision 1.6  2004/12/06 01:56:53  shersche
<rdar://problem/3789425> Use the DNS types and classes defined in dns_sd.h
Bug #: 3789425

Revision 1.5  2004/07/13 21:24:28  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.4  2004/07/09 18:03:33  shersche
removed extraneous DNSServiceQueryRecord call

Revision 1.3  2004/07/07 17:03:49  shersche
<rdar://problem/3715582> Check for LUP_RETURN_ADDR as well as LUP_RETURN_BLOB in NSPLookupServiceBegin
Bug #: 3715582

Revision 1.2  2004/06/24 19:18:07  shersche
Rename to mdnsNSP
Submitted by: herscher

Revision 1.1  2004/06/18 04:13:44  rpantos
Move up one level.

Revision 1.2  2004/04/08 09:43:43  bradley
Changed callback calling conventions to __stdcall so they can be used with C# delegates.

Revision 1.1  2004/01/30 03:00:33  bradley
mDNS NameSpace Provider (NSP). Hooks into the Windows name resolution system to perform
.local name lookups using Multicast DNS in all Windows apps.

*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	"CommonServices.h"
#include	"DebugServices.h"

#include	<guiddef.h>
#include	<ws2spi.h>

#include	"dns_sd.h"

#if 0
#pragma mark == Structures ==
#endif

//===========================================================================================================================
//	Structures
//===========================================================================================================================

typedef struct	Query *		QueryRef;
typedef struct	Query		Query;
struct	Query
{
	QueryRef			next;
	int					refCount;
	DWORD				querySetFlags;
	WSAQUERYSETW *		querySet;
	size_t				querySetSize;
	HANDLE				dataEvent;
	HANDLE				cancelEvent;
	HANDLE				waitHandles[ 2 ];
	DWORD				waitCount;
	DNSServiceRef		resolver;
	char				name[ kDNSServiceMaxDomainName ];
	size_t				nameSize;
	uint32_t			addr;
	bool				addrValid;
};

#define BUFFER_INITIAL_SIZE		4192
#define ALIASES_INITIAL_SIZE	5

typedef struct HostsFile
{
	int			m_bufferSize;
	char	*	m_buffer;
	FILE	*	m_fp;
} HostsFile;


typedef struct HostsFileInfo
{
	struct hostent		m_host;
	struct HostsFileInfo	*	m_next;
} HostsFileInfo;


#if 0
#pragma mark == Prototypes ==
#endif

//===========================================================================================================================
//	Prototypes
//===========================================================================================================================

// DLL Exports

BOOL WINAPI		DllMain( HINSTANCE inInstance, DWORD inReason, LPVOID inReserved );
STDAPI			DllRegisterServer( void );
STDAPI			DllRegisterServer( void );

	
// NSP SPIs

int	WSPAPI	NSPCleanup( LPGUID inProviderID );

DEBUG_LOCAL int WSPAPI
	NSPLookupServiceBegin(
		LPGUID					inProviderID,
		LPWSAQUERYSETW			inQuerySet,
		LPWSASERVICECLASSINFOW	inServiceClassInfo,
		DWORD					inFlags,   
		LPHANDLE				outLookup );

DEBUG_LOCAL int WSPAPI
	NSPLookupServiceNext(  
		HANDLE			inLookup,
		DWORD			inFlags,
		LPDWORD			ioBufferLength,
		LPWSAQUERYSETW	outResults );

DEBUG_LOCAL int WSPAPI	NSPLookupServiceEnd( HANDLE inLookup );

DEBUG_LOCAL int WSPAPI
	NSPSetService(
		LPGUID					inProviderID,						
		LPWSASERVICECLASSINFOW	inServiceClassInfo,   
		LPWSAQUERYSETW			inRegInfo,				  
		WSAESETSERVICEOP		inOperation,			   
		DWORD					inFlags );

DEBUG_LOCAL int WSPAPI	NSPInstallServiceClass( LPGUID inProviderID, LPWSASERVICECLASSINFOW inServiceClassInfo );
DEBUG_LOCAL int WSPAPI	NSPRemoveServiceClass( LPGUID inProviderID, LPGUID inServiceClassID );
DEBUG_LOCAL int WSPAPI	NSPGetServiceClassInfo(	LPGUID inProviderID, LPDWORD ioBufSize, LPWSASERVICECLASSINFOW ioServiceClassInfo );

// Private

#define	NSPLock()		EnterCriticalSection( &gLock );
#define	NSPUnlock()		LeaveCriticalSection( &gLock );

DEBUG_LOCAL OSStatus	QueryCreate( const WSAQUERYSETW *inQuerySet, DWORD inQuerySetFlags, QueryRef *outRef );
DEBUG_LOCAL OSStatus	QueryRetain( QueryRef inRef );
DEBUG_LOCAL OSStatus	QueryRelease( QueryRef inRef );

DEBUG_LOCAL void CALLBACK_COMPAT
	QueryRecordCallback(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,    
		uint16_t			inRRType,
		uint16_t			inRRClass,
		uint16_t			inRDataSize,
		const void *		inRData,
		uint32_t			inTTL,
		void *				inContext );

DEBUG_LOCAL OSStatus
	QueryCopyQuerySet( 
		QueryRef 				inRef, 
		const WSAQUERYSETW *	inQuerySet, 
		DWORD 					inQuerySetFlags, 
		WSAQUERYSETW **			outQuerySet, 
		size_t *				outSize );

DEBUG_LOCAL void
	QueryCopyQuerySetTo( 
		QueryRef 				inRef, 
		const WSAQUERYSETW *	inQuerySet, 
		DWORD 					inQuerySetFlags, 
		WSAQUERYSETW *			outQuerySet );

DEBUG_LOCAL size_t	QueryCopyQuerySetSize( QueryRef inRef, const WSAQUERYSETW *inQuerySet, DWORD inQuerySetFlags );

#if( DEBUG )
	void	DebugDumpQuerySet( DebugLevel inLevel, const WSAQUERYSETW *inQuerySet );
	
	#define	dlog_query_set( LEVEL, SET )		DebugDumpQuerySet( LEVEL, SET )
#else
	#define	dlog_query_set( LEVEL, SET )
#endif

DEBUG_LOCAL BOOL		InHostsTable( const char * name );
DEBUG_LOCAL BOOL		IsLocalName( HostsFileInfo * node );
DEBUG_LOCAL BOOL		IsSameName( HostsFileInfo * node, const char * name );
DEBUG_LOCAL OSStatus	HostsFileOpen( HostsFile ** self, const char * fname );
DEBUG_LOCAL OSStatus	HostsFileClose( HostsFile * self );
DEBUG_LOCAL void		HostsFileInfoFree( HostsFileInfo * info );
DEBUG_LOCAL OSStatus	HostsFileNext( HostsFile * self, HostsFileInfo ** hInfo );


#if 0
#pragma mark == Globals ==
#endif

//===========================================================================================================================
//	Globals
//===========================================================================================================================

// {B600E6E9-553B-4a19-8696-335E5C896153}
DEBUG_LOCAL HINSTANCE				gInstance			= NULL;
DEBUG_LOCAL wchar_t				*	gNSPName			= L"mdnsNSP";
DEBUG_LOCAL GUID					gNSPGUID			= { 0xb600e6e9, 0x553b, 0x4a19, { 0x86, 0x96, 0x33, 0x5e, 0x5c, 0x89, 0x61, 0x53 } };
DEBUG_LOCAL LONG					gRefCount			= 0;
DEBUG_LOCAL CRITICAL_SECTION		gLock;
DEBUG_LOCAL bool					gLockInitialized 	= false;
DEBUG_LOCAL bool					gDNSSDInitialized	= false;
DEBUG_LOCAL QueryRef				gQueryList	 		= NULL;
DEBUG_LOCAL HostsFileInfo		*	gHostsFileInfo		= NULL;

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	DllMain
//===========================================================================================================================

BOOL APIENTRY	DllMain( HINSTANCE inInstance, DWORD inReason, LPVOID inReserved )
{
	DEBUG_USE_ONLY( inInstance );
	DEBUG_UNUSED( inReserved );
	
	switch( inReason )
	{
		case DLL_PROCESS_ATTACH:			
			gInstance = inInstance;		
			gHostsFileInfo	= NULL;
			debug_initialize( kDebugOutputTypeWindowsEventLog, "mDNS NSP", inInstance );
			debug_set_property( kDebugPropertyTagPrintLevel, kDebugLevelInfo );
			dlog( kDebugLevelTrace, "\n" );
			dlog( kDebugLevelVerbose, "%s: process attach\n", __ROUTINE__ );
			break;
		
		case DLL_PROCESS_DETACH:
			HostsFileInfoFree( gHostsFileInfo );
			gHostsFileInfo = NULL;
			dlog( kDebugLevelVerbose, "%s: process detach\n", __ROUTINE__ );
			break;
		
		case DLL_THREAD_ATTACH:
			dlog( kDebugLevelVerbose, "%s: thread attach\n", __ROUTINE__ );
			break;
		
		case DLL_THREAD_DETACH:
			dlog( kDebugLevelVerbose, "%s: thread detach\n", __ROUTINE__ );
			break;
		
		default:
			dlog( kDebugLevelNotice, "%s: unknown reason code (%d)\n", __ROUTINE__, inReason );
			break;
	}
	return( TRUE );
}


//===========================================================================================================================
//	DllRegisterServer
//===========================================================================================================================

STDAPI	DllRegisterServer( void )
{
	WSADATA		wsd;
	WCHAR		path[ MAX_PATH ];
	HRESULT		err;
	
	dlog( kDebugLevelTrace, "DllRegisterServer\n" );

	err = WSAStartup( MAKEWORD( 2, 2 ), &wsd );
	err = translate_errno( err == 0, errno_compat(), WSAEINVAL );
	require_noerr( err, exit );

	// Unregister before registering to workaround an installer
	// problem during upgrade installs.

	WSCUnInstallNameSpace( &gNSPGUID );

	err = GetModuleFileNameW( gInstance, path, sizeof( path ) );
	err = translate_errno( err != 0, errno_compat(), kUnknownErr );
	require_noerr( err, exit );

	err = WSCInstallNameSpace( gNSPName, path, NS_DNS, 1, &gNSPGUID );
	err = translate_errno( err == 0, errno_compat(), WSAEINVAL );
	require_noerr( err, exit );
	
exit:

	WSACleanup();
	return( err );
}

//===========================================================================================================================
//	DllUnregisterServer
//===========================================================================================================================

STDAPI	DllUnregisterServer( void )
{
	WSADATA		wsd;
	HRESULT err;
	
	dlog( kDebugLevelTrace, "DllUnregisterServer\n" );
	
	err = WSAStartup( MAKEWORD( 2, 2 ), &wsd );
	err = translate_errno( err == 0, errno_compat(), WSAEINVAL );
	require_noerr( err, exit );
	
	err = WSCUnInstallNameSpace( &gNSPGUID );
	err = translate_errno( err == 0, errno_compat(), WSAEINVAL );
	require_noerr( err, exit );
		
exit:

	WSACleanup();
	return err;
}


//===========================================================================================================================
//	NSPStartup
//
//	This function is called when our namespace DLL is loaded. It sets up the NSP functions we implement and initializes us.
//===========================================================================================================================

int WSPAPI	NSPStartup( LPGUID inProviderID, LPNSP_ROUTINE outRoutines )
{
	OSStatus		err;
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s (GUID=%U, refCount=%ld)\n", __ROUTINE__, inProviderID, gRefCount );
	
	// Only initialize if this is the first time NSPStartup is called. 
	
	if( InterlockedIncrement( &gRefCount ) != 1 )
	{
		err = NO_ERROR;
		goto exit;
	}
	
	// Initialize our internal state.
	
	InitializeCriticalSection( &gLock );
	gLockInitialized = true;
	
	// Set the size to exclude NSPIoctl because we don't implement it.
	
	outRoutines->cbSize					= FIELD_OFFSET( NSP_ROUTINE, NSPIoctl );
	outRoutines->dwMajorVersion			= 4;
	outRoutines->dwMinorVersion			= 4;
	outRoutines->NSPCleanup				= NSPCleanup;
	outRoutines->NSPLookupServiceBegin	= NSPLookupServiceBegin;
	outRoutines->NSPLookupServiceNext	= NSPLookupServiceNext;
	outRoutines->NSPLookupServiceEnd	= NSPLookupServiceEnd;
	outRoutines->NSPSetService			= NSPSetService;
	outRoutines->NSPInstallServiceClass	= NSPInstallServiceClass;
	outRoutines->NSPRemoveServiceClass	= NSPRemoveServiceClass;
	outRoutines->NSPGetServiceClassInfo	= NSPGetServiceClassInfo;
	
	err = NO_ERROR;
	
exit:
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	if( err != NO_ERROR )
	{
		NSPCleanup( inProviderID );
		SetLastError( (DWORD) err );
		return( SOCKET_ERROR );
	}
	return( NO_ERROR );
}

//===========================================================================================================================
//	NSPCleanup
//
//	This function is called when our namespace DLL is unloaded. It cleans up anything we set up in NSPStartup.
//===========================================================================================================================

int	WSPAPI	NSPCleanup( LPGUID inProviderID )
{
	DEBUG_USE_ONLY( inProviderID );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s (GUID=%U, refCount=%ld)\n", __ROUTINE__, inProviderID, gRefCount );
	
	// Only initialize if this is the first time NSPStartup is called.
	
	if( InterlockedDecrement( &gRefCount ) != 0 )
	{
		goto exit;
	}
	
	// Stop any outstanding queries.
	
	if( gLockInitialized )
	{
		NSPLock();
	}
	while( gQueryList )
	{
		check_string( gQueryList->refCount == 1, "NSPCleanup with outstanding queries!" );
		QueryRelease( gQueryList );
	}
	if( gLockInitialized )
	{
		NSPUnlock();
	}
	
	// Shut down DNS-SD and release our resources.
	
	if( gDNSSDInitialized )
	{
		gDNSSDInitialized = false;
	}
	if( gLockInitialized )
	{
		gLockInitialized = false;
		DeleteCriticalSection( &gLock );
	}
	
exit:
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	return( NO_ERROR );
}

//===========================================================================================================================
//	NSPLookupServiceBegin
//
//	This function maps to the WinSock WSALookupServiceBegin function. It starts the lookup process and returns a HANDLE 
//	that can be used in subsequent operations. Subsequent calls only need to refer to this query by the handle as 
//	opposed to specifying the query parameters each time.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI
	NSPLookupServiceBegin(
		LPGUID					inProviderID,
		LPWSAQUERYSETW			inQuerySet,
		LPWSASERVICECLASSINFOW	inServiceClassInfo,
		DWORD					inFlags,   
		LPHANDLE				outLookup )
{
	OSStatus		err;
	QueryRef		obj;
	LPCWSTR			name;
	size_t			size;
	LPCWSTR			p;
	DWORD           type;
	DWORD			n;
	DWORD			i;
	INT				family;
	INT				protocol;
	
	DEBUG_UNUSED( inProviderID );
	DEBUG_UNUSED( inServiceClassInfo );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	
	obj = NULL;
	require_action( inQuerySet, exit, err = WSAEINVAL );
	name = inQuerySet->lpszServiceInstanceName;
	require_action_quiet( name, exit, err = WSAEINVAL );
	require_action( outLookup, exit, err = WSAEINVAL );
	
	dlog( kDebugLevelTrace, "%s (flags=0x%08X, name=\"%S\")\n", __ROUTINE__, inFlags, name );
	dlog_query_set( kDebugLevelVerbose, inQuerySet );
	
	// Check if we can handle this type of request and if we support any of the protocols being requested.
	// We only support the DNS namespace, TCP and UDP protocols, and IPv4. Only blob results are supported.
	
	require_action_quiet( inFlags & (LUP_RETURN_ADDR|LUP_RETURN_BLOB), exit, err = WSASERVICE_NOT_FOUND );
	
	type = inQuerySet->dwNameSpace;
	require_action_quiet( ( type == NS_DNS ) || ( type == NS_ALL ), exit, err = WSASERVICE_NOT_FOUND );
	
	n = inQuerySet->dwNumberOfProtocols;
	if( n > 0 )
	{
		require_action( inQuerySet->lpafpProtocols, exit, err = WSAEINVAL );
		for( i = 0; i < n; ++i )
		{
			family = inQuerySet->lpafpProtocols[ i ].iAddressFamily;
			protocol = inQuerySet->lpafpProtocols[ i ].iProtocol;
			if( ( family == AF_INET ) && ( ( protocol == IPPROTO_UDP ) || ( protocol == IPPROTO_TCP ) ) )
			{
				break;
			}
		}
		require_action_quiet( i < n, exit, err = WSASERVICE_NOT_FOUND );
	}
	
	// Check if the name ends in ".local" and if not, exit with an error since we only resolve .local names.
	// The name may or may not end with a "." (fully qualified) so handle both cases. DNS is also case 
	// insensitive the check for .local has to be case insensitive (.LoCaL is equivalent to .local). This
	// manually does the wchar_t strlen and stricmp to avoid needing any special wchar_t versions of the 
	// libraries. It is probably faster to do the inline compare than invoke functions to do it anyway.
	
	for( p = name; *p; ++p ) {}		// Find end of string
	size = (size_t)( p - name );
	require_action_quiet( size > sizeof_string( ".local" ), exit, err = WSASERVICE_NOT_FOUND );
	
	p = name + ( size - 1 );
	p = ( *p == '.' ) ? ( p - sizeof_string( ".local" ) ) : ( ( p - sizeof_string( ".local" ) ) + 1 );
	if	( ( ( p[ 0 ] != '.' )						||
		( ( p[ 1 ] != 'L' ) && ( p[ 1 ] != 'l' ) )	||
		( ( p[ 2 ] != 'O' ) && ( p[ 2 ] != 'o' ) )	||
		( ( p[ 3 ] != 'C' ) && ( p[ 3 ] != 'c' ) )	||
		( ( p[ 4 ] != 'A' ) && ( p[ 4 ] != 'a' ) )	||
		( ( p[ 5 ] != 'L' ) && ( p[ 5 ] != 'l' ) ) ) )
	{
		require_action_quiet( size > sizeof_string( ".0.8.e.f.ip6.arpa" ), exit, err = WSASERVICE_NOT_FOUND );
 
		p = name + ( size - 1 );
		p = ( *p == '.' ) ? ( p - sizeof_string( ".0.8.e.f.ip6.arpa" ) ) : ( ( p - sizeof_string( ".0.8.e.f.ip6.arpa" ) ) + 1 );
	
		if	( ( ( p[ 0 ] != '.' )							||
			( ( p[ 1 ] != '0' ) )							||
			( ( p[ 2 ] != '.' ) )							||
			( ( p[ 3 ] != '8' ) )							||
			( ( p[ 4 ] != '.' ) )							||
			( ( p[ 5 ] != 'E' ) && ( p[ 5 ] != 'e' ) )		||
			( ( p[ 6 ] != '.' ) )							||
			( ( p[ 7 ] != 'F' ) && ( p[ 7 ] != 'f' ) )		||
			( ( p[ 8 ] != '.' ) )							||
			( ( p[ 9 ] != 'I' ) && ( p[ 9 ] != 'i' ) )		||
			( ( p[ 10 ] != 'P' ) && ( p[ 10 ] != 'p' ) )	||	
			( ( p[ 11 ] != '6' ) )							||
			( ( p[ 12 ] != '.' ) )							||
			( ( p[ 13 ] != 'A' ) && ( p[ 13 ] != 'a' ) )	||
			( ( p[ 14 ] != 'R' ) && ( p[ 14 ] != 'r' ) )	||
			( ( p[ 15 ] != 'P' ) && ( p[ 15 ] != 'p' ) )	||
			( ( p[ 16 ] != 'A' ) && ( p[ 16 ] != 'a' ) ) ) )
		{
			require_action_quiet( size > sizeof_string( ".254.169.in-addr.arpa" ), exit, err = WSASERVICE_NOT_FOUND );
 
			p = name + ( size - 1 );
			p = ( *p == '.' ) ? ( p - sizeof_string( ".254.169.in-addr.arpa" ) ) : ( ( p - sizeof_string( ".254.169.in-addr.arpa" ) ) + 1 );
	
	require_action_quiet( ( ( p[ 0 ] == '.' )						 &&
									( ( p[ 1 ] == '2' ) )							&&
									( ( p[ 2 ] == '5' ) )							&&
									( ( p[ 3 ] == '4' ) )							&&
									( ( p[ 4 ] == '.' ) )							&&
									( ( p[ 5 ] == '1' ) )							&&
									( ( p[ 6 ] == '6' ) )							&&
									( ( p[ 7 ] == '9' ) )							&&
									( ( p[ 8 ] == '.' ) )							&&
									( ( p[ 9 ] == 'I' ) || ( p[ 9 ] == 'i' ) )		&&
									( ( p[ 10 ] == 'N' ) || ( p[ 10 ] == 'n' ) )	&&	
									( ( p[ 11 ] == '-' ) )							&&
									( ( p[ 12 ] == 'A' ) || ( p[ 12 ] == 'a' ) )	&&
									( ( p[ 13 ] == 'D' ) || ( p[ 13 ] == 'd' ) )	&&
									( ( p[ 14 ] == 'D' ) || ( p[ 14 ] == 'd' ) )	&&
									( ( p[ 15 ] == 'R' ) || ( p[ 15 ] == 'r' ) )	&&
									( ( p[ 16 ] == '.' ) )							&&
									( ( p[ 17 ] == 'A' ) || ( p[ 17 ] == 'a' ) )	&&
									( ( p[ 18 ] == 'R' ) || ( p[ 18 ] == 'r' ) )	&&
									( ( p[ 19 ] == 'P' ) || ( p[ 19 ] == 'p' ) )	&&
									( ( p[ 20 ] == 'A' ) || ( p[ 20 ] == 'a' ) ) ),
									exit, err = WSASERVICE_NOT_FOUND );
		}
	}
	else
	{
		// <rdar://problem/3936771>
		//
		// Check to see if the name of this host is in the hosts table. If so,
		// don't try and resolve it
		
		char	translated[ kDNSServiceMaxDomainName ];
		int		n;

		n = WideCharToMultiByte( CP_UTF8, 0, name, -1, translated, sizeof( translated ), NULL, NULL );
		require_action( n > 0, exit, err = WSASERVICE_NOT_FOUND );
		require_action( InHostsTable( translated ) == FALSE, exit, err = WSASERVICE_NOT_FOUND );
	}

	// The name ends in .local ( and isn't in the hosts table ), .0.8.e.f.ip6.arpa, or .254.169.in-addr.arpa so start the resolve operation. Lazy initialize DNS-SD if needed.
		
	NSPLock();
	if( !gDNSSDInitialized )
	{
		gDNSSDInitialized = true;
	}
	
	err = QueryCreate( inQuerySet, inFlags, &obj );
	NSPUnlock();
	require_noerr( err, exit );
	
	*outLookup = (HANDLE) obj;
	
exit:
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	if( err != NO_ERROR )
	{
		SetLastError( (DWORD) err );
		return( SOCKET_ERROR );
	}
	return( NO_ERROR );
}

//===========================================================================================================================
//	NSPLookupServiceNext
//
//	This function maps to the Winsock call WSALookupServiceNext. This routine takes a handle to a previously defined 
//	query and attempts to locate a service matching the criteria defined by the query. If so, that instance is returned 
//	in the lpqsResults parameter.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI
	NSPLookupServiceNext(  
		HANDLE			inLookup,
		DWORD			inFlags,
		LPDWORD			ioSize,
		LPWSAQUERYSETW	outResults )
{
	OSStatus		err;
	QueryRef		obj;
	DWORD			waitResult;
	size_t			size;
	
	DEBUG_USE_ONLY( inFlags );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	
	obj = NULL;
	NSPLock();
	err = QueryRetain( (QueryRef) inLookup );
	require_noerr( err, exit );
	obj = (QueryRef) inLookup;
	require_action( ioSize, exit, err = WSAEINVAL );
	require_action( outResults, exit, err = WSAEINVAL );
	
	dlog( kDebugLevelTrace, "%s (lookup=%#p, flags=0x%08X, *ioSize=%d)\n", __ROUTINE__, inLookup, inFlags, *ioSize );
	
	// Wait for data or a cancel. Release the lock while waiting. This is safe because we've retained the query.

	NSPUnlock();
	waitResult = WaitForMultipleObjects( obj->waitCount, obj->waitHandles, FALSE, 2 * 1000 );
	NSPLock();
	require_action_quiet( waitResult != ( WAIT_OBJECT_0 + 1 ), exit, err = WSA_E_CANCELLED );
	err = translate_errno( waitResult == WAIT_OBJECT_0, (OSStatus) GetLastError(), WSASERVICE_NOT_FOUND );
	require_noerr_quiet( err, exit );
	DNSServiceProcessResult(obj->resolver);
	require_action_quiet( obj->addrValid, exit, err = WSA_E_NO_MORE );
	
	// Copy the externalized query results to the callers buffer (if it fits).
	
	size = QueryCopyQuerySetSize( obj, obj->querySet, obj->querySetFlags );
	require_action( size <= (size_t) *ioSize, exit, err = WSAEFAULT );
	
	QueryCopyQuerySetTo( obj, obj->querySet, obj->querySetFlags, outResults );
	outResults->dwOutputFlags = RESULT_IS_ADDED;
	obj->addrValid = false;
	
exit:
	if( obj )
	{
		QueryRelease( obj );
	}
	NSPUnlock();
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	if( err != NO_ERROR )
	{
		SetLastError( (DWORD) err );
		return( SOCKET_ERROR );
	}
	return( NO_ERROR );
}

//===========================================================================================================================
//	NSPLookupServiceEnd
//
//	This function maps to the Winsock call WSALookupServiceEnd. Once the user process has finished is query (usually 
//	indicated when WSALookupServiceNext returns the error WSA_E_NO_MORE) a call to this function is made to release any 
//	allocated resources associated with the query.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI	NSPLookupServiceEnd( HANDLE inLookup )
{
	OSStatus		err;

	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	
	dlog( kDebugLevelTrace, "%s (lookup=%#p)\n", __ROUTINE__, inLookup );
	
	NSPLock();
	err = QueryRelease( (QueryRef) inLookup );
	NSPUnlock();
	require_noerr( err, exit );
	
exit:
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	if( err != NO_ERROR )
	{
		SetLastError( (DWORD) err );
		return( SOCKET_ERROR );
	}
	return( NO_ERROR );
}

//===========================================================================================================================
//	NSPSetService
//
//	This function maps to the Winsock call WSASetService. This routine is called when the user wants to register or 
//	deregister an instance of a server with our service. For registration, the user needs to associate the server with a 
//	service class. For deregistration the service class is required along with the servicename. The inRegInfo parameter 
//	contains a WSAQUERYSET structure defining the server (such as protocol and address where it is).
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI
	NSPSetService(
		LPGUID					inProviderID,						
		LPWSASERVICECLASSINFOW	inServiceClassInfo,   
		LPWSAQUERYSETW			inRegInfo,				  
		WSAESETSERVICEOP		inOperation,			   
		DWORD					inFlags )
{
	DEBUG_UNUSED( inProviderID );
	DEBUG_UNUSED( inServiceClassInfo );
	DEBUG_UNUSED( inRegInfo );
	DEBUG_UNUSED( inOperation );
	DEBUG_UNUSED( inFlags );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s\n", __ROUTINE__ );
	
	// We don't allow services to be registered so always return an error.
	
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	return( WSAEINVAL );
}

//===========================================================================================================================
//	NSPInstallServiceClass
//
//	This function maps to the Winsock call WSAInstallServiceClass. This routine is used to install a service class which 
//	is used to define certain characteristics for a group of services. After a service class is registered, an actual
//	instance of a server may be registered.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI	NSPInstallServiceClass( LPGUID inProviderID, LPWSASERVICECLASSINFOW inServiceClassInfo )
{
	DEBUG_UNUSED( inProviderID );
	DEBUG_UNUSED( inServiceClassInfo );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s\n", __ROUTINE__ );
	
	// We don't allow service classes to be installed so always return an error.

	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	return( WSA_INVALID_PARAMETER );
}

//===========================================================================================================================
//	NSPRemoveServiceClass
//
//	This function maps to the Winsock call WSARemoveServiceClass. This routine removes a previously registered service 
//	class. This is accomplished by connecting to the namespace service and writing the GUID which defines the given 
//	service class.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI	NSPRemoveServiceClass( LPGUID inProviderID, LPGUID inServiceClassID )
{
	DEBUG_UNUSED( inProviderID );
	DEBUG_UNUSED( inServiceClassID );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s\n", __ROUTINE__ );
	
	// We don't allow service classes to be installed so always return an error.
	
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	return( WSATYPE_NOT_FOUND );
}

//===========================================================================================================================
//	NSPGetServiceClassInfo
//
//	This function maps to the Winsock call WSAGetServiceClassInfo. This routine returns the information associated with 
//	a given service class.
//===========================================================================================================================

DEBUG_LOCAL int WSPAPI	NSPGetServiceClassInfo(	LPGUID inProviderID, LPDWORD ioSize, LPWSASERVICECLASSINFOW ioServiceClassInfo )
{
	DEBUG_UNUSED( inProviderID );
	DEBUG_UNUSED( ioSize );
	DEBUG_UNUSED( ioServiceClassInfo );
	
	dlog( kDebugLevelTrace, "%s begin (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	dlog( kDebugLevelTrace, "%s\n", __ROUTINE__ );
	
	// We don't allow service classes to be installed so always return an error.
	
	dlog( kDebugLevelTrace, "%s end   (ticks=%d)\n", __ROUTINE__, GetTickCount() );
	return( WSATYPE_NOT_FOUND );
}

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	QueryCreate
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL OSStatus	QueryCreate( const WSAQUERYSETW *inQuerySet, DWORD inQuerySetFlags, QueryRef *outRef )
{
	OSStatus		err;
	QueryRef		obj;
	char			name[ kDNSServiceMaxDomainName ];
	int				n;
	QueryRef *		p;
	
	obj = NULL;
	check( inQuerySet );
	check( inQuerySet->lpszServiceInstanceName );
	check( outRef );
	
	// Convert the wchar_t name to UTF-8.
	
	n = WideCharToMultiByte( CP_UTF8, 0, inQuerySet->lpszServiceInstanceName, -1, name, sizeof( name ), NULL, NULL );
	err = translate_errno( n > 0, (OSStatus) GetLastError(), WSAEINVAL );
	require_noerr( err, exit );
	
	// Allocate the object and append it to the list. Append immediately so releases of partial objects work.
	
	obj = (QueryRef) calloc( 1, sizeof( *obj ) );
	require_action( obj, exit, err = WSA_NOT_ENOUGH_MEMORY );
	
	obj->refCount = 1;
	
	for( p = &gQueryList; *p; p = &( *p )->next ) {}	// Find the end of the list.
	*p = obj;
	
	// Set up events to signal when data is ready and when cancelling.
	
	obj->dataEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
	require_action( obj->dataEvent, exit, err = WSA_NOT_ENOUGH_MEMORY );
	
	obj->cancelEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
	require_action( obj->cancelEvent, exit, err = WSA_NOT_ENOUGH_MEMORY );
	
	// Start the query.

	err = DNSServiceQueryRecord( &obj->resolver, 0, 0, name, kDNSServiceType_A, kDNSServiceClass_IN, 
		QueryRecordCallback, obj );
	require_noerr( err, exit );

	// Attach the socket to the event

	WSAEventSelect(DNSServiceRefSockFD(obj->resolver), obj->dataEvent, FD_READ|FD_CLOSE);
	
	obj->waitCount = 0;
	obj->waitHandles[ obj->waitCount++ ] = obj->dataEvent;
	obj->waitHandles[ obj->waitCount++ ] = obj->cancelEvent;
	check( obj->waitCount == sizeof_array( obj->waitHandles ) );
	
	// Copy the QuerySet so it can be returned later.
	
	obj->querySetFlags = inQuerySetFlags;
	inQuerySetFlags = ( inQuerySetFlags & ~( LUP_RETURN_ADDR | LUP_RETURN_BLOB ) ) | LUP_RETURN_NAME;
	err = QueryCopyQuerySet( obj, inQuerySet, inQuerySetFlags, &obj->querySet, &obj->querySetSize );
	require_noerr( err, exit );
	
	// Success!
	
	*outRef	= obj;
	obj 	= NULL;
	err 	= NO_ERROR;

exit:
	if( obj )
	{
		QueryRelease( obj );
	}
	return( err );
}

//===========================================================================================================================
//	QueryRetain
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL OSStatus	QueryRetain( QueryRef inRef )
{
	OSStatus		err;
	QueryRef		obj;
	
	for( obj = gQueryList; obj; obj = obj->next )
	{
		if( obj == inRef )
		{
			break;
		}
	}
	require_action( obj, exit, err = WSA_INVALID_HANDLE );
	
	++inRef->refCount;
	err = NO_ERROR;
	
exit:
	return( err );
}

//===========================================================================================================================
//	QueryRelease
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL OSStatus	QueryRelease( QueryRef inRef )
{
	OSStatus		err;
	QueryRef *		p;
	BOOL			ok;
		
	// Find the item in the list.
	
	for( p = &gQueryList; *p; p = &( *p )->next )
	{
		if( *p == inRef )
		{
			break;
		}
	}
	require_action( *p, exit, err = WSA_INVALID_HANDLE );
	
	// Signal a cancel to unblock any threads waiting for results.
	
	if( inRef->cancelEvent )
	{
		ok = SetEvent( inRef->cancelEvent );
		check_translated_errno( ok, GetLastError(), WSAEINVAL );
	}
	
	// Stop the query.
	
	if( inRef->resolver )
	{
		DNSServiceRefDeallocate( inRef->resolver );
		inRef->resolver = NULL;
	}
	
	// Decrement the refCount. Fully release if it drops to 0. If still referenced, just exit.
	
	if( --inRef->refCount != 0 )
	{
		err = NO_ERROR;
		goto exit;
	}
	*p = inRef->next;
	
	// Release resources.
	
	if( inRef->cancelEvent )
	{
		ok = CloseHandle( inRef->cancelEvent );
		check_translated_errno( ok, GetLastError(), WSAEINVAL );
	}
	if( inRef->dataEvent )
	{
		ok = CloseHandle( inRef->dataEvent );
		check_translated_errno( ok, GetLastError(), WSAEINVAL );
	}
	if( inRef->querySet )
	{
		free( inRef->querySet );
	}
	free( inRef );
	err = NO_ERROR;
	
exit:
	return( err );
}

//===========================================================================================================================
//	QueryRecordCallback
//===========================================================================================================================

DEBUG_LOCAL void CALLBACK_COMPAT
	QueryRecordCallback(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,    
		uint16_t			inRRType,
		uint16_t			inRRClass,
		uint16_t			inRDataSize,
		const void *		inRData,
		uint32_t			inTTL,
		void *				inContext )
{
	QueryRef			obj;
	const char *		src;
	char *				dst;
	BOOL				ok;
	
	DEBUG_UNUSED( inFlags );
	DEBUG_UNUSED( inInterfaceIndex );
	DEBUG_UNUSED( inTTL );

	NSPLock();
	obj = (QueryRef) inContext;
	check( obj );
	require_noerr( inErrorCode, exit );
	require_quiet( inFlags & kDNSServiceFlagsAdd, exit );
	require( inRRClass   == kDNSServiceClass_IN, exit );
	require( inRRType    == kDNSServiceType_A, exit );
	require( inRDataSize == 4, exit );
	
	dlog( kDebugLevelTrace, "%s (flags=0x%08X, name=%s, rrType=%d, rDataSize=%d)\n", 
		__ROUTINE__, inFlags, inName, inRRType, inRDataSize );
		
	// Copy the name if needed.
	
	if( obj->name[ 0 ] == '\0' )
	{
		src = inName;
		dst = obj->name;
		while( *src != '\0' )
		{
			*dst++ = *src++;
		}
		*dst = '\0';
		obj->nameSize = (size_t)( dst - obj->name );
		check( obj->nameSize < sizeof( obj->name ) );
	}
	
	// Copy the data.
	
	memcpy( &obj->addr, inRData, inRDataSize );
	obj->addrValid = true;
	
	// Signal that a result is ready.
	
	check( obj->dataEvent );
	ok = SetEvent( obj->dataEvent );
	check_translated_errno( ok, GetLastError(), WSAEINVAL );
	
	// Stop the resolver after the first response.
	
	DNSServiceRefDeallocate( inRef );
	obj->resolver = NULL;

exit:
	NSPUnlock();
}

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	QueryCopyQuerySet
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL OSStatus
	QueryCopyQuerySet( 
		QueryRef 				inRef, 
		const WSAQUERYSETW *	inQuerySet, 
		DWORD 					inQuerySetFlags, 
		WSAQUERYSETW **			outQuerySet, 
		size_t *				outSize )
{
	OSStatus			err;
	size_t				size;
	WSAQUERYSETW *		qs;
	
	check( inQuerySet );
	check( outQuerySet );
	
	size  = QueryCopyQuerySetSize( inRef, inQuerySet, inQuerySetFlags );
	qs = (WSAQUERYSETW *) calloc( 1, size );
	require_action( qs, exit, err = WSA_NOT_ENOUGH_MEMORY  );
	
	QueryCopyQuerySetTo( inRef, inQuerySet, inQuerySetFlags, qs );
	
	*outQuerySet = qs;
	if( outSize )
	{
		*outSize = size;
	}
	qs = NULL;
	err = NO_ERROR;
	
exit:
	if( qs )
	{
		free( qs );
	}
	return( err );	
}

//===========================================================================================================================
//	QueryCopyQuerySetTo
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL void
	QueryCopyQuerySetTo( 
		QueryRef 				inRef, 
		const WSAQUERYSETW *	inQuerySet, 
		DWORD 					inQuerySetFlags, 
		WSAQUERYSETW *			outQuerySet )
{
	uint8_t *		dst;
	LPCWSTR			s;
	LPWSTR			q;
	DWORD			n;
	DWORD			i;
	
#if( DEBUG )
	size_t			debugSize;
	
	debugSize = QueryCopyQuerySetSize( inRef, inQuerySet, inQuerySetFlags );
#endif

	check( inQuerySet );
	check( outQuerySet );

	dst = (uint8_t *) outQuerySet;
	
	// Copy the static portion of the results.
	
	*outQuerySet = *inQuerySet;
	dst += sizeof( *inQuerySet );
	
	if( inQuerySetFlags & LUP_RETURN_NAME )
	{
		s = inQuerySet->lpszServiceInstanceName;
		if( s )
		{
			outQuerySet->lpszServiceInstanceName = (LPWSTR) dst;
			q = (LPWSTR) dst;
			while( ( *q++ = *s++ ) != 0 ) {}
			dst = (uint8_t *) q;
		}
	}
	else
	{
		outQuerySet->lpszServiceInstanceName = NULL;
	}
	
	if( inQuerySet->lpServiceClassId )
	{
		outQuerySet->lpServiceClassId  = (LPGUID) dst;
		*outQuerySet->lpServiceClassId = *inQuerySet->lpServiceClassId;
		dst += sizeof( *inQuerySet->lpServiceClassId );
	}
	
	if( inQuerySet->lpVersion )
	{
		outQuerySet->lpVersion  = (LPWSAVERSION) dst;
		*outQuerySet->lpVersion = *inQuerySet->lpVersion;
		dst += sizeof( *inQuerySet->lpVersion );
	}
	
	s = inQuerySet->lpszComment;
	if( s )
	{
		outQuerySet->lpszComment = (LPWSTR) dst;
		q = (LPWSTR) dst;
		while( ( *q++ = *s++ ) != 0 ) {}
		dst = (uint8_t *) q;
	}
	
	if( inQuerySet->lpNSProviderId )
	{
		outQuerySet->lpNSProviderId  = (LPGUID) dst;
		*outQuerySet->lpNSProviderId = *inQuerySet->lpNSProviderId;
		dst += sizeof( *inQuerySet->lpNSProviderId );
	}
	
	s = inQuerySet->lpszContext;
	if( s )
	{
		outQuerySet->lpszContext = (LPWSTR) dst;
		q = (LPWSTR) dst;
		while( ( *q++ = *s++ ) != 0 ) {}
		dst = (uint8_t *) q;
	}
		
	n = inQuerySet->dwNumberOfProtocols;
	if( n > 0 )
	{
		check( inQuerySet->lpafpProtocols );
		
		outQuerySet->lpafpProtocols = (LPAFPROTOCOLS) dst;
		for( i = 0; i < n; ++i )
		{
			outQuerySet->lpafpProtocols[ i ] = inQuerySet->lpafpProtocols[ i ];
			dst += sizeof( *inQuerySet->lpafpProtocols );
		}
	}
		
	s = inQuerySet->lpszQueryString;
	if( s )
	{
		outQuerySet->lpszQueryString = (LPWSTR) dst;
		q = (LPWSTR) dst;
		while( ( *q++ = *s++ ) != 0 ) {}
		dst = (uint8_t *) q;
	}
	
	// Copy the address(es).
	
	if( ( inQuerySetFlags & LUP_RETURN_ADDR ) && inRef->addrValid )
	{
		struct sockaddr_in *		addr;
		
		outQuerySet->dwNumberOfCsAddrs								= 1;
		outQuerySet->lpcsaBuffer 									= (LPCSADDR_INFO) dst;
		dst 													   += sizeof( *outQuerySet->lpcsaBuffer );
		
		outQuerySet->lpcsaBuffer[ 0 ].LocalAddr.lpSockaddr 			= NULL;
		outQuerySet->lpcsaBuffer[ 0 ].LocalAddr.iSockaddrLength		= 0;
		
		outQuerySet->lpcsaBuffer[ 0 ].RemoteAddr.lpSockaddr 		= (LPSOCKADDR) dst;
		outQuerySet->lpcsaBuffer[ 0 ].RemoteAddr.iSockaddrLength	= sizeof( struct sockaddr_in );
		
		addr 														= (struct sockaddr_in *) dst;
		memset( addr, 0, sizeof( *addr ) );
		addr->sin_family											= AF_INET;
		memcpy( &addr->sin_addr, &inRef->addr, 4 );
		dst 													   += sizeof( *addr );
		
		outQuerySet->lpcsaBuffer[ 0 ].iSocketType 					= AF_INET;		// Emulate Tcpip NSP
		outQuerySet->lpcsaBuffer[ 0 ].iProtocol						= IPPROTO_UDP;	// Emulate Tcpip NSP
	}
	else
	{
		outQuerySet->dwNumberOfCsAddrs	= 0;
		outQuerySet->lpcsaBuffer 		= NULL;
	}
	
	// Copy the hostent blob.
	
	if( ( inQuerySetFlags & LUP_RETURN_BLOB ) && inRef->addrValid )
	{
		uint8_t *				base;
		struct hostent *		he;
		uintptr_t *				p;
		
		outQuerySet->lpBlob	 = (LPBLOB) dst;
		dst 				+= sizeof( *outQuerySet->lpBlob );
		
		base = dst;
		he	 = (struct hostent *) dst;
		dst += sizeof( *he );
		
		he->h_name = (char *)( dst - base );
		memcpy( dst, inRef->name, inRef->nameSize + 1 );
		dst += ( inRef->nameSize + 1 );
		
		he->h_aliases 	= (char **)( dst - base );
		p	  			= (uintptr_t *) dst;
		*p++  			= 0;
		dst 		 	= (uint8_t *) p;
		
		he->h_addrtype 	= AF_INET;
		he->h_length	= 4;
		
		he->h_addr_list	= (char **)( dst - base );
		p	  			= (uintptr_t *) dst;
		dst 		   += ( 2 * sizeof( *p ) );
		*p++			= (uintptr_t)( dst - base );
		*p++			= 0;
		p	  			= (uintptr_t *) dst;
		*p++			= (uintptr_t) inRef->addr;
		dst 		 	= (uint8_t *) p;
		
		outQuerySet->lpBlob->cbSize 	= (ULONG)( dst - base );
		outQuerySet->lpBlob->pBlobData	= (BYTE *) base;
	}
	dlog_query_set( kDebugLevelVerbose, outQuerySet );
	
	check( (size_t)( dst - ( (uint8_t *) outQuerySet ) ) == debugSize );
}

//===========================================================================================================================
//	QueryCopyQuerySetSize
//
//	Warning: Assumes the NSP lock is held.
//===========================================================================================================================

DEBUG_LOCAL size_t	QueryCopyQuerySetSize( QueryRef inRef, const WSAQUERYSETW *inQuerySet, DWORD inQuerySetFlags )
{
	size_t		size;
	LPCWSTR		s;
	LPCWSTR		p;
	
	check( inRef );
	check( inQuerySet );
	
	// Calculate the size of the static portion of the results.
	
	size = sizeof( *inQuerySet );
	
	if( inQuerySetFlags & LUP_RETURN_NAME )
	{
		s = inQuerySet->lpszServiceInstanceName;
		if( s )
		{
			for( p = s; *p; ++p ) {}
			size += (size_t)( ( ( p - s ) + 1 ) * sizeof( *p ) );
		}
	}
	
	if( inQuerySet->lpServiceClassId )
	{
		size += sizeof( *inQuerySet->lpServiceClassId );
	}
	
	if( inQuerySet->lpVersion )
	{
		size += sizeof( *inQuerySet->lpVersion );
	}
	
	s = inQuerySet->lpszComment;
	if( s )
	{
		for( p = s; *p; ++p ) {}
		size += (size_t)( ( ( p - s ) + 1 ) * sizeof( *p ) );
	}
	
	if( inQuerySet->lpNSProviderId )
	{
		size += sizeof( *inQuerySet->lpNSProviderId );
	}
	
	s = inQuerySet->lpszContext;
	if( s )
	{
		for( p = s; *p; ++p ) {}
		size += (size_t)( ( ( p - s ) + 1 ) * sizeof( *p ) );
	}
	
	size += ( inQuerySet->dwNumberOfProtocols * sizeof( *inQuerySet->lpafpProtocols ) );
	
	s = inQuerySet->lpszQueryString;
	if( s )
	{
		for( p = s; *p; ++p ) {}
		size += (size_t)( ( ( p - s ) + 1 ) * sizeof( *p ) );
	}
	
	// Calculate the size of the address(es).
	
	if( ( inQuerySetFlags & LUP_RETURN_ADDR ) && inRef->addrValid )
	{
		size += sizeof( *inQuerySet->lpcsaBuffer );
		size += sizeof( struct sockaddr_in );
	}
	
	// Calculate the size of the hostent blob.
	
	if( ( inQuerySetFlags & LUP_RETURN_BLOB ) && inRef->addrValid )
	{
		size += sizeof( *inQuerySet->lpBlob );	// Blob ptr/size structure
		size += sizeof( struct hostent );		// Old-style hostent structure
		size += ( inRef->nameSize + 1 );		// Name and null terminator
		size += 4;								// Alias list terminator (0 offset)
		size += 4;								// Offset to address.
		size += 4;								// Address list terminator (0 offset)
		size += 4;								// IPv4 address
	}
	return( size );
}

#if 0
#pragma mark -
#endif

#if( DEBUG )
//===========================================================================================================================
//	DebugDumpQuerySet
//===========================================================================================================================

#define	DebugSocketFamilyToString( FAM )	( ( FAM ) == AF_INET )  ? "AF_INET"  : \
											( ( FAM ) == AF_INET6 ) ? "AF_INET6" : ""

#define	DebugSocketProtocolToString( PROTO )	( ( PROTO ) == IPPROTO_UDP ) ? "IPPROTO_UDP" : \
												( ( PROTO ) == IPPROTO_TCP ) ? "IPPROTO_TCP" : ""

#define	DebugNameSpaceToString( NS )			( ( NS ) == NS_DNS ) ? "NS_DNS" : ( ( NS ) == NS_ALL ) ? "NS_ALL" : ""

void	DebugDumpQuerySet( DebugLevel inLevel, const WSAQUERYSETW *inQuerySet )
{
	DWORD		i;
	
	check( inQuerySet );

	// Fixed portion of the QuerySet.
		
	dlog( inLevel, "QuerySet:\n" );
	dlog( inLevel, "    dwSize:                  %d (expected %d)\n", inQuerySet->dwSize, sizeof( *inQuerySet ) );
	if( inQuerySet->lpszServiceInstanceName )
	{
		dlog( inLevel, "    lpszServiceInstanceName: %S\n", inQuerySet->lpszServiceInstanceName );
	}
	else
	{
		dlog( inLevel, "    lpszServiceInstanceName: <null>\n" );
	}
	if( inQuerySet->lpServiceClassId )
	{
		dlog( inLevel, "    lpServiceClassId:        %U\n", inQuerySet->lpServiceClassId );
	}
	else
	{
		dlog( inLevel, "    lpServiceClassId:        <null>\n" );
	}
	if( inQuerySet->lpVersion )
	{
		dlog( inLevel, "    lpVersion:\n" );
		dlog( inLevel, "        dwVersion:               %d\n", inQuerySet->lpVersion->dwVersion );
		dlog( inLevel, "        dwVersion:               %d\n", inQuerySet->lpVersion->ecHow );
	}
	else
	{
		dlog( inLevel, "    lpVersion:               <null>\n" );
	}
	if( inQuerySet->lpszComment )
	{
		dlog( inLevel, "    lpszComment:             %S\n", inQuerySet->lpszComment );
	}
	else
	{
		dlog( inLevel, "    lpszComment:             <null>\n" );
	}
	dlog( inLevel, "    dwNameSpace:             %d %s\n", inQuerySet->dwNameSpace, 
		DebugNameSpaceToString( inQuerySet->dwNameSpace ) );
	if( inQuerySet->lpNSProviderId )
	{
		dlog( inLevel, "    lpNSProviderId:          %U\n", inQuerySet->lpNSProviderId );
	}
	else
	{
		dlog( inLevel, "    lpNSProviderId:          <null>\n" );
	}
	if( inQuerySet->lpszContext )
	{
		dlog( inLevel, "    lpszContext:             %S\n", inQuerySet->lpszContext );
	}
	else
	{
		dlog( inLevel, "    lpszContext:             <null>\n" );
	}
	dlog( inLevel, "    dwNumberOfProtocols:     %d\n", inQuerySet->dwNumberOfProtocols );
	dlog( inLevel, "    lpafpProtocols:          %s\n", inQuerySet->lpafpProtocols ? "" : "<null>" );
	for( i = 0; i < inQuerySet->dwNumberOfProtocols; ++i )
	{
		if( i != 0 )
		{
			dlog( inLevel, "\n" );
		}
		dlog( inLevel, "        iAddressFamily:          %d %s\n", inQuerySet->lpafpProtocols[ i ].iAddressFamily, 
			DebugSocketFamilyToString( inQuerySet->lpafpProtocols[ i ].iAddressFamily ) );
		dlog( inLevel, "        iProtocol:               %d %s\n", inQuerySet->lpafpProtocols[ i ].iProtocol, 
			DebugSocketProtocolToString( inQuerySet->lpafpProtocols[ i ].iProtocol ) );
	}
	if( inQuerySet->lpszQueryString )
	{
		dlog( inLevel, "    lpszQueryString:         %S\n", inQuerySet->lpszQueryString );
	}
	else
	{
		dlog( inLevel, "    lpszQueryString:         <null>\n" );
	}
	dlog( inLevel, "    dwNumberOfCsAddrs:       %d\n", inQuerySet->dwNumberOfCsAddrs );
	dlog( inLevel, "    lpcsaBuffer:             %s\n", inQuerySet->lpcsaBuffer ? "" : "<null>" );
	for( i = 0; i < inQuerySet->dwNumberOfCsAddrs; ++i )
	{
		if( i != 0 )
		{
			dlog( inLevel, "\n" );
		}
		if( inQuerySet->lpcsaBuffer[ i ].LocalAddr.lpSockaddr && 
			( inQuerySet->lpcsaBuffer[ i ].LocalAddr.iSockaddrLength > 0 ) )
		{
			dlog( inLevel, "        LocalAddr:               %##a\n", 
				inQuerySet->lpcsaBuffer[ i ].LocalAddr.lpSockaddr );
		}
		else
		{
			dlog( inLevel, "        LocalAddr:               <null/empty>\n" );
		}
		if( inQuerySet->lpcsaBuffer[ i ].RemoteAddr.lpSockaddr && 
			( inQuerySet->lpcsaBuffer[ i ].RemoteAddr.iSockaddrLength > 0 ) )
		{
			dlog( inLevel, "        RemoteAddr:              %##a\n", 
				inQuerySet->lpcsaBuffer[ i ].RemoteAddr.lpSockaddr );
		}
		else
		{
			dlog( inLevel, "        RemoteAddr:              <null/empty>\n" );
		}
		dlog( inLevel, "        iSocketType:             %d\n", inQuerySet->lpcsaBuffer[ i ].iSocketType );
		dlog( inLevel, "        iProtocol:               %d\n", inQuerySet->lpcsaBuffer[ i ].iProtocol );
	}
	dlog( inLevel, "    dwOutputFlags:           %d\n", inQuerySet->dwOutputFlags );
	
	// Blob portion of the QuerySet.
	
	if( inQuerySet->lpBlob )
	{
		dlog( inLevel, "    lpBlob:\n" );
		dlog( inLevel, "        cbSize:                  %ld\n", inQuerySet->lpBlob->cbSize );
		dlog( inLevel, "        pBlobData:               %#p\n", inQuerySet->lpBlob->pBlobData );
		dloghex( inLevel, 12, NULL, 0, 0, NULL, 0, 
			inQuerySet->lpBlob->pBlobData, inQuerySet->lpBlob->pBlobData, inQuerySet->lpBlob->cbSize, 
			kDebugFlagsNone, NULL, 0 );
	}
	else
	{
		dlog( inLevel, "    lpBlob:                  <null>\n" );
	}
}
#endif


//===========================================================================================================================
//	InHostsTable
//===========================================================================================================================

DEBUG_LOCAL BOOL
InHostsTable( const char * name )
{
	HostsFileInfo	*	node;
	BOOL				ret = FALSE;
	OSStatus			err;
	
	check( name );

	if ( gHostsFileInfo == NULL )
	{
		TCHAR				systemDirectory[MAX_PATH];
		TCHAR				hFileName[MAX_PATH];
		HostsFile		*	hFile;

		GetSystemDirectory( systemDirectory, sizeof( systemDirectory ) );
		sprintf( hFileName, "%s\\drivers\\etc\\hosts", systemDirectory );
		err = HostsFileOpen( &hFile, hFileName );
		require_noerr( err, exit );

		while ( HostsFileNext( hFile, &node ) == 0 )
		{
			if ( IsLocalName( node ) )
			{
				node->m_next = gHostsFileInfo;
				gHostsFileInfo = node;
			}
			else
			{
				HostsFileInfoFree( node );
			}
		}

		HostsFileClose( hFile );
	}

	for ( node = gHostsFileInfo; node; node = node->m_next )
	{
		if ( IsSameName( node, name ) )
		{
			ret = TRUE;
			break;
		}
	}

exit:

	return ret;
}


//===========================================================================================================================
//	IsLocalName
//===========================================================================================================================

DEBUG_LOCAL BOOL
IsLocalName( HostsFileInfo * node )
{
	BOOL ret = TRUE;

	check( node );

	if ( strstr( node->m_host.h_name, ".local" ) == NULL )
	{
		int i;

		for ( i = 0; node->m_host.h_aliases[i]; i++ )
		{
			if ( strstr( node->m_host.h_aliases[i], ".local" ) )
			{
				goto exit;
			}
		}

		ret = FALSE;
	}

exit:

	return ret;
}


//===========================================================================================================================
//	IsSameName
//===========================================================================================================================

DEBUG_LOCAL BOOL
IsSameName( HostsFileInfo * node, const char * name )
{
	BOOL ret = TRUE;

	check( node );
	check( name );

	if ( strcmp( node->m_host.h_name, name ) != 0 )
	{
		int i;

		for ( i = 0; node->m_host.h_aliases[i]; i++ )
		{
			if ( strcmp( node->m_host.h_aliases[i], name ) == 0 )
			{
				goto exit;
			}
		}

		ret = FALSE;
	}

exit:

	return ret;
}


//===========================================================================================================================
//	HostsFileOpen
//===========================================================================================================================

DEBUG_LOCAL OSStatus
HostsFileOpen( HostsFile ** self, const char * fname )
{
	OSStatus err = kNoErr;

	*self = (HostsFile*) malloc( sizeof( HostsFile ) );
	require_action( *self, exit, err = kNoMemoryErr );
	memset( *self, 0, sizeof( HostsFile ) );

	(*self)->m_bufferSize = BUFFER_INITIAL_SIZE;
	(*self)->m_buffer = (char*) malloc( (*self)->m_bufferSize );
	require_action( (*self)->m_buffer, exit, err = kNoMemoryErr );

	// check malloc

	(*self)->m_fp = fopen( fname, "r" );
	require_action( (*self)->m_fp, exit, err = kUnknownErr );

exit:

	if ( err && *self )
	{
		HostsFileClose( *self );
		*self = NULL;
	}
		
	return err;
}


//===========================================================================================================================
//	HostsFileClose
//===========================================================================================================================

DEBUG_LOCAL OSStatus
HostsFileClose( HostsFile * self )
{
	check( self );

	if ( self->m_buffer )
	{
		free( self->m_buffer );
		self->m_buffer = NULL;
	}

	if ( self->m_fp )
	{
		fclose( self->m_fp );
		self->m_fp = NULL;
	}

	free( self );

	return kNoErr;
} 


//===========================================================================================================================
//	HostsFileInfoFree
//===========================================================================================================================

DEBUG_LOCAL void
HostsFileInfoFree( HostsFileInfo * info )
{
	while ( info )
	{
		HostsFileInfo * next = info->m_next;

		if ( info->m_host.h_addr_list )
		{
			if ( info->m_host.h_addr_list[0] )
			{
				free( info->m_host.h_addr_list[0] );
				info->m_host.h_addr_list[0] = NULL;
			}

			free( info->m_host.h_addr_list );
			info->m_host.h_addr_list = NULL;
		}

		if ( info->m_host.h_aliases )
		{
			int i;

			for ( i = 0; info->m_host.h_aliases[i]; i++ )
			{
				free( info->m_host.h_aliases[i] );
			}

			free( info->m_host.h_aliases );
		}

		if ( info->m_host.h_name )
		{
			free( info->m_host.h_name );
			info->m_host.h_name = NULL;
		}
			
		free( info );

		info = next;
	}
}


//===========================================================================================================================
//	HostsFileNext
//===========================================================================================================================

DEBUG_LOCAL OSStatus
HostsFileNext( HostsFile * self, HostsFileInfo ** hInfo )
{
	struct sockaddr_in6	addr_6;
	struct sockaddr_in	addr_4;
	int					numAliases = ALIASES_INITIAL_SIZE;
	char			*	line;
	char			*	tok;
	int					dwSize;
	int					idx;
	int					i;
	short				family;
	OSStatus			err = kNoErr;

	check( self );
	check( self->m_fp );
	check( hInfo );

	idx	= 0;

	*hInfo = (HostsFileInfo*) malloc( sizeof( HostsFileInfo ) );
	require_action( *hInfo, exit, err = kNoMemoryErr );
	memset( *hInfo, 0, sizeof( HostsFileInfo ) );

	for ( ; ; )
	{
		line = fgets( self->m_buffer + idx, self->m_bufferSize - idx, self->m_fp );
		
		if ( line == NULL )
		{
			err = 1;
			goto exit;
		}

		// If there's no eol and no eof, then we didn't get the whole line

		if ( !strchr( line, '\n' ) && !feof( self->m_fp ) )
		{
			int			bufferSize;
			char	*	buffer;

			/* Try and allocate space for longer line */

			bufferSize	= self->m_bufferSize * 2;
			buffer		= (char*) realloc( self->m_buffer, bufferSize );
			require_action( buffer, exit, err = kNoMemoryErr );
			self->m_bufferSize	= bufferSize;
			self->m_buffer		= buffer;
			idx					= (int) strlen( self->m_buffer );

			continue;
		}

		line	= self->m_buffer;
		idx		= 0;

		if (*line == '#')
		{
			continue;
		}

		// Get rid of either comments or eol characters

		if (( tok = strpbrk(line, "#\n")) != NULL )
		{
			*tok = '\0';
		}

		// Make sure there is some whitespace on this line

		if (( tok = strpbrk(line, " \t")) == NULL )
		{
			continue;
		}

		// Create two strings, where p == the IP Address and tok is the name list

		*tok++ = '\0';

		while ( *tok == ' ' || *tok == '\t')
		{
			tok++;
		}

		// Now we have the name

		(*hInfo)->m_host.h_name = (char*) malloc( strlen( tok ) + 1 );
		require_action( (*hInfo)->m_host.h_name, exit, err = kNoMemoryErr );
		strcpy( (*hInfo)->m_host.h_name, tok );

		// Now create the address (IPv6/IPv4)

		addr_6.sin6_family	= family = AF_INET6;
		dwSize				= sizeof( addr_6 );

		if ( WSAStringToAddress( line, AF_INET6, NULL, ( struct sockaddr*) &addr_6, &dwSize ) != 0 )
		{
			addr_4.sin_family = family = AF_INET;
			dwSize = sizeof( addr_4 );

			if (WSAStringToAddress( line, AF_INET, NULL, ( struct sockaddr*) &addr_4, &dwSize ) != 0 )
			{
				continue;
			}
		}

		(*hInfo)->m_host.h_addr_list = (char**) malloc( sizeof( char**) * 2 );
		require_action( (*hInfo)->m_host.h_addr_list, exit, err = kNoMemoryErr );

		if ( family == AF_INET6 )
		{
			(*hInfo)->m_host.h_length		= (short) sizeof( addr_6.sin6_addr );
			(*hInfo)->m_host.h_addr_list[0] = (char*) malloc( (*hInfo)->m_host.h_length );
			require_action( (*hInfo)->m_host.h_addr_list[0], exit, err = kNoMemoryErr );
			memmove( (*hInfo)->m_host.h_addr_list[0], &addr_6.sin6_addr, sizeof( addr_6.sin6_addr ) );
			
		}
		else
		{
			(*hInfo)->m_host.h_length		= (short) sizeof( addr_4.sin_addr );
			(*hInfo)->m_host.h_addr_list[0] = (char*) malloc( (*hInfo)->m_host.h_length );
			require_action( (*hInfo)->m_host.h_addr_list[0], exit, err = kNoMemoryErr );
			memmove( (*hInfo)->m_host.h_addr_list[0], &addr_4.sin_addr, sizeof( addr_4.sin_addr ) );
		}

		(*hInfo)->m_host.h_addr_list[1] = NULL;
		(*hInfo)->m_host.h_addrtype		= family;

		// Now get the aliases

		if ((tok = strpbrk(tok, " \t")) != NULL)
		{
			*tok++ = '\0';
		}

		i = 0;

		(*hInfo)->m_host.h_aliases		= (char**) malloc( sizeof(char**) * numAliases );
		require_action( (*hInfo)->m_host.h_aliases, exit, err = kNoMemoryErr );
		(*hInfo)->m_host.h_aliases[0]	= NULL;

		while ( tok && *tok )
		{
			// Skip over the whitespace, waiting for the start of the next alias name

			if (*tok == ' ' || *tok == '\t')
			{
				tok++;
				continue;
			}

			// Check to make sure we don't exhaust the alias buffer

			if ( i >= ( numAliases - 1 ) )
			{
				numAliases = numAliases * 2;
				(*hInfo)->m_host.h_aliases = (char**) realloc( (*hInfo)->m_host.h_aliases, numAliases * sizeof( char** ) );
				require_action( (*hInfo)->m_host.h_aliases, exit, err = kNoMemoryErr );
			}

			(*hInfo)->m_host.h_aliases[i] = (char*) malloc( strlen( tok ) + 1 );
			require_action( (*hInfo)->m_host.h_aliases[i], exit, err = kNoMemoryErr );

			strcpy( (*hInfo)->m_host.h_aliases[i], tok );

			if (( tok = strpbrk( tok, " \t")) != NULL )
			{
				*tok++ = '\0';
			}

			(*hInfo)->m_host.h_aliases[++i] = NULL;
		}

		break;
	}

exit:

	if ( err && ( *hInfo ) )
	{
		HostsFileInfoFree( *hInfo );
		*hInfo = NULL;
	}

	return err;
}
