/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
    
$Log: mDNSWin32.c,v $
Revision 1.22  2003/08/20 06:21:25  bradley
Updated to latest internal version of the Rendezvous for Windows platform plugin: Added support
for Windows CE/PocketPC 2003; re-did interface-related code to emulate getifaddrs/freeifaddrs for
restricting usage to only active, multicast-capable, and non-point-to-point interfaces and to ease
the addition of IPv6 support in the future; Changed init code to serialize thread initialization to
enable ThreadID improvement to wakeup notification; Define platform support structure locally to
allow portable mDNS_Init usage; Removed dependence on modified mDNSCore: define interface ID<->name
structures/prototypes locally; Changed to use _beginthreadex()/_endthreadex() on non-Windows CE
platforms (re-mapped to CreateThread on Window CE) to avoid a leak in the Microsoft C runtime;
Added IPv4/IPv6 string<->address conversion routines; Cleaned up some code and added HeaderDoc.

Revision 1.21  2003/08/18 23:09:57  cheshire
<rdar://problem/3382647> mDNSResponder divide by zero in mDNSPlatformTimeNow()

Revision 1.20  2003/08/12 19:56:27  cheshire
Update to APSL 2.0

Revision 1.19  2003/08/05 23:58:18  cheshire
Update code to compile with the new mDNSCoreReceive() function that requires a TTL
Right now this platform layer just reports 255 instead of returning the real value -- we should fix this

Revision 1.18  2003/07/23 21:16:30  cheshire
Removed a couple of debugfs

Revision 1.17  2003/07/23 02:23:01  cheshire
Updated mDNSPlatformUnlock() to work correctly, now that <rdar://problem/3160248>
"ScheduleNextTask needs to be smarter" has refined the way m->NextScheduledEvent is set

Revision 1.16  2003/07/19 03:15:16  cheshire
Add generic MemAllocate/MemFree prototypes to mDNSPlatformFunctions.h,
and add the obvious trivial implementations to each platform support layer

Revision 1.15  2003/07/02 21:20:04  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.14  2003/05/26 03:21:30  cheshire
Tidy up address structure naming:
mDNSIPAddr         => mDNSv4Addr (for consistency with mDNSv6Addr)
mDNSAddr.addr.ipv4 => mDNSAddr.ip.v4
mDNSAddr.addr.ipv6 => mDNSAddr.ip.v6

Revision 1.13  2003/05/26 03:01:28  cheshire
<rdar://problem/3268904> sprintf/vsprintf-style functions are unsafe; use snprintf/vsnprintf instead

Revision 1.12  2003/05/06 21:06:05  cheshire
<rdar://problem/3242673> mDNSWindows needs a wakeupEvent object to signal the main thread

Revision 1.11  2003/05/06 00:00:51  cheshire
<rdar://problem/3248914> Rationalize naming of domainname manipulation functions

Revision 1.10  2003/04/29 00:06:09  cheshire
<rdar://problem/3242673> mDNSWindows needs a wakeupEvent object to signal the main thread

Revision 1.9  2003/04/26 02:40:01  cheshire
Add void LogMsg( const char *format, ... )

Revision 1.8  2003/03/22 02:57:44  cheshire
Updated mDNSWindows to use new "mDNS_Execute" model (see "mDNSCore/Implementer Notes.txt")

Revision 1.7  2003/03/15 04:40:38  cheshire
Change type called "mDNSOpaqueID" to the more descriptive name "mDNSInterfaceID"

Revision 1.6  2003/02/21 01:54:10  cheshire
Bug #: 3099194 mDNSResponder needs performance improvements
Switched to using new "mDNS_Execute" model (see "Implementer Notes.txt")

Revision 1.5  2003/02/20 00:59:03  cheshire
Brought Windows code up to date so it complies with
Josh Graessley's interface changes for IPv6 support.
(Actual support for IPv6 on Windows will come later.)

Revision 1.4  2002/09/21 20:44:54  zarzycki
Added APSL info

Revision 1.3  2002/09/20 05:50:45  bradley
Multicast DNS platform plugin for Win32

*/

#if( defined( _MSC_VER ) )
	#pragma warning( disable:4127 )		// Disable "conditional expression is constant" warning for debug macros.
#endif

#if( !defined( WIN32_LEAN_AND_MEAN ) )
	#define	WIN32_LEAN_AND_MEAN			// Needed to avoid redefinitions by Windows interfaces.
#endif

#include	<stdarg.h>
#include	<stddef.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	<windows.h>
#include	<winsock2.h>
#include	<Ws2tcpip.h>

#if( !defined( _WIN32_WCE ) )			// Windows CE does not have process.h.
	#include	<process.h>
#endif

#if( DEBUG )
	#define	mDNSlocal
#endif

#include	"mDNSClientAPI.h"
#include	"mDNSPlatformFunctions.h"

#include	"mDNSWin32.h"

#if 0
#pragma mark == Constants ==
#endif

//===========================================================================================================================
//	Constants
//===========================================================================================================================

#define	DEBUG_NAME								"[mDNS] "

#if( !defined( MDNS_DEBUG_SIGNATURE ) )
	#define MDNS_DEBUG_SIGNATURE				"mDNS"
#endif

#define	kMDNSDefaultName						"My Computer"

#define	kWinSockMajorMin						2
#define	kWinSockMinorMin						2

#define	kWaitListCancelEvent					( WAIT_OBJECT_0 + 0 )
#define	kWaitListInterfaceListChangedEvent		( WAIT_OBJECT_0 + 1 )
#define	kWaitListWakeupEvent					( WAIT_OBJECT_0 + 2 )
#define	kWaitListFixedItemCount					3

#if 0
#pragma mark == Macros - Debug ==
#endif

//===========================================================================================================================
//	Macros - Debug
//===========================================================================================================================

#define MDNS_UNUSED( X )		(void)( X )

#define kDebugLevelMask				0x0000FFFFL
#define kDebugLevelChatty			100L
#define kDebugLevelVerbose			500L
#define kDebugLevelTrace 			800L
#define kDebugLevelInfo 			1000L
#define kDebugLevelRareInfo			2000L
#define kDebugLevelNotice			3000L
#define kDebugLevelWarning			4000L
#define kDebugLevelAllowedError		5000L
#define kDebugLevelAssert 			6000L
#define kDebugLevelRequire			7000L
#define kDebugLevelError			8000L
#define kDebugLevelCritical			9000L
#define kDebugLevelCriticalError	kDebugLevelCritical		// DEPRECATED
#define kDebugLevelAlert			10000L
#define kDebugLevelEmergency		11000L
#define kDebugLevelTragic			12000L
#define kDebugLevelAny				0x0000FFFFL

#if( defined( __MWERKS__ ) || defined( __GNUC__ ) )
	#define	__ROUTINE__		__FUNCTION__
#else
	// Apple and Symantec compilers don't support the C99/GCC extensions yet.
	
	#define	__ROUTINE__		NULL
#endif

#if( MDNS_DEBUGMSGS )
	#define	debug_print_assert( ASSERT_STRING, FILENAME, LINE_NUMBER, FUNCTION )										\
		mDNSPlatformPrintAssert( MDNS_DEBUG_SIGNATURE, 0, ( ASSERT_STRING ), NULL, ( FILENAME ), ( LINE_NUMBER ), ( FUNCTION ) )
	
	#define	debug_print_assert_err( ERR, ASSERT_STRING, ERROR_STRING, FILENAME, LINE_NUMBER, FUNCTION )					\
		mDNSPlatformPrintAssert( MDNS_DEBUG_SIGNATURE, ( ERR ), ( ASSERT_STRING ), ( ERROR_STRING ), 							\
						  ( FILENAME ), ( LINE_NUMBER ), ( FUNCTION ) )
	
	#define	dlog		mDNSPlatformDebugLog
#else
	#define	debug_print_assert( ASSERT_STRING, FILENAME, LINE_NUMBER, FUNCTION )
	
	#define	debug_print_assert_err( ERR, ASSERT_STRING, ERROR_STRING, FILENAME, LINE_NUMBER, FUNCTION )

	#define	dlog		while( 0 )
#endif

///
/// The following debugging macros emulate those available on Mac OS in AssertMacros.h/Debugging.h.
/// 

// checks

#define	check( X )																										\
	do {																												\
		if( !( X ) ) {																									\
			debug_print_assert( #X, __FILE__, __LINE__, __ROUTINE__ );													\
		}																												\
	} while( 0 )

#define	check_noerr( ERR )																								\
	do {																												\
		if( ( ERR ) != 0 ) {																							\
			debug_print_assert_err( ( ERR ), #ERR, NULL, __FILE__, __LINE__, __ROUTINE__ );								\
		}																												\
	} while( 0 )

#define	check_errno( ERR, ERRNO )																						\
	do {																												\
		int		localErr;																								\
																														\
		localErr = (int)( ERR );																						\
		if( localErr < 0 ) {																							\
			int		localErrno;																							\
																														\
			localErrno = ( ERRNO );																						\
			localErr = ( localErrno != 0 ) ? localErrno : localErr;														\
			debug_print_assert_err( localErr, #ERR, NULL, __FILE__, __LINE__, __ROUTINE__ );							\
		}																												\
	} while( 0 )

// requires

#define	require( X, LABEL )																								\
	do {																												\
		if( !( X ) ) {																									\
			debug_print_assert( #X, __FILE__, __LINE__, __ROUTINE__ );													\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_quiet( X, LABEL )																						\
	do {																												\
		if( !( X ) ) {																									\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_action( X, LABEL, ACTION )																				\
	do {																												\
		if( !( X ) ) {																									\
			debug_print_assert( #X, __FILE__, __LINE__, __ROUTINE__ );													\
			{ ACTION; }																									\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_action_quiet( X, LABEL, ACTION )																		\
	do {																												\
		if( !( X ) ) {																									\
			{ ACTION; }																									\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_noerr( ERR, LABEL )																						\
	do {																												\
		if( ( ERR ) != 0 ) {																							\
			debug_print_assert_err( ( ERR ), #ERR, NULL, __FILE__, __LINE__, __ROUTINE__ );								\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_noerr_quiet( ERR, LABEL )																				\
	do {																												\
		if( ( ERR ) != 0 ) {																							\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_errno( ERR, ERRNO, LABEL )																				\
	do {																												\
		int		localErr;																								\
																														\
		localErr = (int)( ERR );																						\
		if( localErr < 0 ) {																							\
			int		localErrno;																							\
																														\
			localErrno = ( ERRNO );																						\
			localErr = ( localErrno != 0 ) ? localErrno : localErr;														\
			debug_print_assert_err( localErr, #ERR, NULL, __FILE__, __LINE__, __ROUTINE__ );							\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#define	require_errno_action( ERR, ERRNO, LABEL, ACTION )																\
	do {																												\
		int		localErr;																								\
																														\
		localErr = (int)( ERR );																						\
		if( localErr < 0 ) {																							\
			int		localErrno;																							\
																														\
			localErrno = ( ERRNO );																						\
			localErr = ( localErrno != 0 ) ? localErrno : localErr;														\
			debug_print_assert_err( localErr, #ERR, NULL, __FILE__, __LINE__, __ROUTINE__ );							\
			{ ACTION; }																									\
			goto LABEL;																									\
		}																												\
	} while( 0 )

#if 0
#pragma mark == Macros - General ==
#endif

//===========================================================================================================================
//	Macros - General
//===========================================================================================================================

#define	kInvalidSocketRef		INVALID_SOCKET
#define	IsValidSocket( X )		( ( X ) != INVALID_SOCKET )
#define	close_compat( X )		closesocket( X )
#define	errno_compat()			WSAGetLastError()

// _beginthreadex and _endthreadex are not supported on Windows CE 2.1 or later (the C runtime issues with leaking 
// resources have apparently been resolved and they seem to have just ripped out support for the API) so map it to 
// CreateThread on Windows CE.

#if( defined( _WIN32_WCE ) )
	#define	_beginthreadex( SECURITY_PTR, STACK_SIZE, START_ADDRESS, ARG_LIST, FLAGS, THREAD_ID_PTR )		\
		CreateThread( SECURITY_PTR, STACK_SIZE, (LPTHREAD_START_ROUTINE) START_ADDRESS, ARG_LIST, FLAGS, 	\
					  (LPDWORD) THREAD_ID_PTR )
	
	#define	_endthreadex( RESULT )
#endif

#if 0
#pragma mark == Prototypes ==
#endif

//===========================================================================================================================
//	Prototypes
//===========================================================================================================================

#if( MDNS_DEBUGMSGS )
	mDNSlocal void 			mDNSPlatformDebugLog( unsigned long inLevel, const char *inFormat, ... );
	mDNSlocal void
		mDNSPlatformPrintAssert( 
			const char *		inSignature, 
			long				inError, 
			const char *		inAssertionString, 
			const char *		inErrorString, 
			const char *		inFileName, 
			unsigned long		inLineNumber, 
			const char *		inFunction );
#endif

mDNSlocal mStatus			SetupSynchronizationObjects( mDNS * const inMDNS );
mDNSlocal mStatus			TearDownSynchronizationObjects( mDNS * const inMDNS );
mDNSlocal mStatus			SetupName( mDNS * const inMDNS );
mDNSlocal mStatus			SetupInterfaceList( mDNS * const inMDNS );
mDNSlocal mStatus			TearDownInterfaceList( mDNS * const inMDNS );
mDNSlocal mStatus			SetupInterface( mDNS * const inMDNS, const struct sockaddr_in *inAddress, mDNSInterfaceData **outIFD );
mDNSlocal mStatus			TearDownInterface( mDNS * const inMDNS, mDNSInterfaceData *inIFD );
mDNSlocal mStatus			SetupSocket( mDNS * const 				inMDNS, 
										 const struct sockaddr_in *	inAddress, 
										 mDNSIPPort 				inPort, 
										 SocketRef *				outSocketRef  );
mDNSlocal mStatus			SetupNotifications( mDNS * const inMDNS );
mDNSlocal mStatus			TearDownNotifications( mDNS * const inMDNS );

mDNSlocal mStatus			SetupThread( mDNS * const inMDNS );
mDNSlocal mStatus			TearDownThread( const mDNS * const inMDNS );
mDNSlocal unsigned WINAPI	ProcessingThread( LPVOID inParam );
mDNSlocal mStatus 			ProcessingThreadInitialize( mDNS * const inMDNS );
mDNSlocal mStatus			ProcessingThreadSetupWaitList( mDNS * const inMDNS, HANDLE **outWaitList, int *outWaitListCount );
mDNSlocal void				ProcessingThreadProcessPacket( mDNS *inMDNS, mDNSInterfaceData *inIFD, SocketRef inSocketRef );
mDNSlocal void				ProcessingThreadInterfaceListChanged( mDNS *inMDNS );

// Platform Accessors

#ifdef	__cplusplus
	extern "C" {
#endif

typedef struct mDNSPlatformInterfaceInfo	mDNSPlatformInterfaceInfo;
struct	mDNSPlatformInterfaceInfo
{
	const char *		name;
	mDNSAddr			ip;
};

mDNSexport mStatus	mDNSPlatformInterfaceNameToID( mDNS * const inMDNS, const char *inName, mDNSInterfaceID *outID );
mDNSexport mStatus	mDNSPlatformInterfaceIDToInfo( mDNS * const inMDNS, mDNSInterfaceID inID, mDNSPlatformInterfaceInfo *outInfo );

#ifdef	__cplusplus
	}
#endif

#if 0
#pragma mark == Globals ==
#endif

//===========================================================================================================================
//	Globals
//===========================================================================================================================

mDNSlocal mDNS_PlatformSupport		gMDNSPlatformSupport;
mDNSs32								mDNSPlatformOneSecond = 0;

#if( MDNS_DEBUGMSGS )
	mDNSlocal unsigned long			gDebugLevel = kDebugLevelInfo + 1;
#endif

#if 0
#pragma mark -
#pragma mark == Platform Support APIs ==
#endif

//===========================================================================================================================
//	mDNSPlatformInit
//===========================================================================================================================

mStatus	mDNSPlatformInit( mDNS * const inMDNS )
{
	mStatus		err;
	WSADATA		wsaData;
	int			supported;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "platform init\n" );
	
	// Initialize variables.
	
	memset( &gMDNSPlatformSupport, 0, sizeof( gMDNSPlatformSupport ) );
	inMDNS->p									= &gMDNSPlatformSupport;
	inMDNS->p->interfaceListChangedSocketRef	= kInvalidSocketRef;
	mDNSPlatformOneSecond 						= 1000;		// Use milliseconds as the quantum of time.
	
	// Set everything up.
	
	err = WSAStartup( MAKEWORD( kWinSockMajorMin, kWinSockMinorMin ), &wsaData );
	require_noerr( err, exit );
	
	supported = ( ( LOBYTE( wsaData.wVersion ) == kWinSockMajorMin ) && ( HIBYTE( wsaData.wVersion ) == kWinSockMinorMin ) );
	require_action( supported, exit, err = mStatus_UnsupportedErr );
		
	err = SetupSynchronizationObjects( inMDNS );
	require_noerr( err, exit );
	
	err = SetupThread( inMDNS );
	require_noerr( err, exit );
	
	// Success!
	
	mDNSCoreInitComplete( inMDNS, err );
	
exit:
	if( err )
	{
		mDNSPlatformClose( inMDNS );
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "platform init done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	mDNSPlatformClose
//===========================================================================================================================

void	mDNSPlatformClose( mDNS * const inMDNS )
{
	mStatus		err;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "platform close\n" );
	check( inMDNS );
	
	// Tear everything down in reverse order to how it was set up.
		
	err = TearDownThread( inMDNS );
	check_noerr( err );
	
	err = TearDownInterfaceList( inMDNS );
	check_noerr( err );
		
	err = TearDownSynchronizationObjects( inMDNS );
	check_noerr( err );
	
	WSACleanup();
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "platform close done (err=%ld)\n", err );
}

//===========================================================================================================================
//	mDNSPlatformSendUDP
//===========================================================================================================================

mStatus
	mDNSPlatformSendUDP( 
		const mDNS * const			inMDNS, 
		const DNSMessage * const	inMsg, 
		const mDNSu8 * const		inMsgEnd, 
		mDNSInterfaceID 			inInterfaceID, 
		mDNSIPPort					inSrcPort, 
		const mDNSAddr *			inDstIP, 
		mDNSIPPort 					inDstPort )
{
	mStatus					err;
	mDNSInterfaceData *		ifd;
	struct sockaddr_in		addr;
	int						n;
	
	MDNS_UNUSED( inSrcPort );
	dlog( kDebugLevelChatty, DEBUG_NAME "platform send UDP\n" );
	
	// Check parameters.
	
	check( inMDNS );
	check( inMsg );
	check( inMsgEnd );
	check( inInterfaceID );
	check( inDstIP );
	if( inDstIP->type != mDNSAddrType_IPv4 )
	{
		err = mStatus_BadParamErr;
		goto exit;
	}
	
	// Send the packet.
	
	ifd = (mDNSInterfaceData *) inInterfaceID;
	check( IsValidSocket( ifd->multicastSocketRef ) );
	
	addr.sin_family 		= AF_INET;
	addr.sin_port 			= inDstPort.NotAnInteger;
	addr.sin_addr.s_addr 	= inDstIP->ip.v4.NotAnInteger;

	n = (int)( inMsgEnd - ( (const mDNSu8 * const) inMsg ) );
	n = sendto( ifd->multicastSocketRef, (char *) inMsg, n, 0, (struct sockaddr *) &addr, sizeof( addr ) );
	check_errno( n, errno_compat() );
	
	ifd->sendErrorCounter 		+= ( n < 0 );
	ifd->sendMulticastCounter 	+= ( inDstPort.NotAnInteger == MulticastDNSPort.NotAnInteger );
	ifd->sendUnicastCounter 	+= ( inDstPort.NotAnInteger != MulticastDNSPort.NotAnInteger );
	err = mStatus_NoError;

exit:
	dlog( kDebugLevelChatty, DEBUG_NAME "platform send UDP done\n" );
	return( err );
}

//===========================================================================================================================
//	mDNSPlatformLock
//===========================================================================================================================

void	mDNSPlatformLock( const mDNS * const inMDNS )
{
	EnterCriticalSection( &inMDNS->p->lock );
}

//===========================================================================================================================
//	mDNSPlatformUnlock
//===========================================================================================================================

void	mDNSPlatformUnlock( const mDNS * const inMDNS )
{
	check( inMDNS );
	check( inMDNS->p );
	check( inMDNS->p->threadID );
	
	// When an API routine is called, "m->NextScheduledEvent" is reset to "timenow" before calling mDNSPlatformUnlock()
	// Since our main mDNS_Execute() loop is on a different thread, we need to wake up that thread to:
	// (a) handle immediate work (if any) resulting from this API call
	// (b) calculate the next sleep time between now and the next interesting event
	
	if( ( mDNSPlatformTimeNow() - inMDNS->NextScheduledEvent ) >= 0 )
	{
		// We only need to case a wakeup event when called from a task other than the mDNS task since if we are 
		// called from mDNS task, we'll loop back and call mDNS_Execute. This avoids filling up the command queue.
		
		if( GetCurrentThreadId() != inMDNS->p->threadID )
		{
			BOOL		wasSet;
			
			wasSet = SetEvent( inMDNS->p->wakeupEvent );
			check( wasSet );
		}
	}
	LeaveCriticalSection( &inMDNS->p->lock );
}

//===========================================================================================================================
//	mDNSPlatformStrLen
//===========================================================================================================================

mDNSu32	mDNSPlatformStrLen( const void *inSrc )
{
	check( inSrc );
	
	return( (mDNSu32) strlen( (const char *) inSrc ) );
}

//===========================================================================================================================
//	mDNSPlatformStrCopy
//===========================================================================================================================

void	mDNSPlatformStrCopy( const void *inSrc, void *inDst )
{
	check( inSrc );
	check( inDst );
	
	strcpy( (char *) inDst, (const char*) inSrc );
}

//===========================================================================================================================
//	mDNSPlatformMemCopy
//===========================================================================================================================

void	mDNSPlatformMemCopy( const void *inSrc, void *inDst, mDNSu32 inSize )
{
	check( inSrc );
	check( inDst );
	
	memcpy( inDst, inSrc, inSize );
}

//===========================================================================================================================
//	mDNSPlatformMemSame
//===========================================================================================================================

mDNSBool	mDNSPlatformMemSame( const void *inSrc, const void *inDst, mDNSu32 inSize )
{
	check( inSrc );
	check( inDst );
	
	return( (mDNSBool)( memcmp( inSrc, inDst, inSize ) == 0 ) );
}

//===========================================================================================================================
//	mDNSPlatformMemZero
//===========================================================================================================================

void	mDNSPlatformMemZero( void *inDst, mDNSu32 inSize )
{
	check( inDst );
	
	memset( inDst, 0, inSize );
}

//===========================================================================================================================
//	mDNSPlatformMemAllocate
//===========================================================================================================================

mDNSexport void *	mDNSPlatformMemAllocate( mDNSu32 inSize )
{
	void *		mem;
	
	check( inSize > 0 );
	
	mem = malloc( inSize );
	check( mem );
	
	return( mem );
}

//===========================================================================================================================
//	mDNSPlatformMemFree
//===========================================================================================================================

mDNSexport void	mDNSPlatformMemFree( void *inMem )
{
	check( inMem );
	
	free( inMem );
}

//===========================================================================================================================
//	mDNSPlatformTimeInit
//===========================================================================================================================

mDNSexport mStatus	mDNSPlatformTimeInit( mDNSs32 *outTimeNow )
{
	check( outTimeNow );
	
	// No special setup is required on Windows -- we just use GetTickCount().
	
	*outTimeNow = mDNSPlatformTimeNow();
	return( mStatus_NoError );
}

//===========================================================================================================================
//	mDNSPlatformTimeNow
//===========================================================================================================================

mDNSs32	mDNSPlatformTimeNow( void )
{
	return( (mDNSs32) GetTickCount() );
}

//===========================================================================================================================
//	mDNSPlatformInterfaceNameToID
//===========================================================================================================================

mStatus	mDNSPlatformInterfaceNameToID( mDNS * const inMDNS, const char *inName, mDNSInterfaceID *outID )
{
	mStatus					err;
	mDNSInterfaceData *		ifd;
	
	check( inMDNS );
	check( inMDNS->p );
	check( inName );
	
	// Search for an interface with the specified name,
	
	for( ifd = inMDNS->p->interfaceList; ifd; ifd = ifd->next )
	{
		if( strcmp( ifd->name, inName ) == 0 )
		{
			break;
		}
	}
	require_action_quiet( ifd, exit, err = mStatus_NoSuchNameErr );
	
	// Success!
	
	if( outID )
	{
		*outID = (mDNSInterfaceID) ifd;
	}
	err = mStatus_NoError;
	
exit:
	return( err );
}

//===========================================================================================================================
//	mDNSPlatformInterfaceIDToInfo
//===========================================================================================================================

mStatus	mDNSPlatformInterfaceIDToInfo( mDNS * const inMDNS, mDNSInterfaceID inID, mDNSPlatformInterfaceInfo *outInfo )
{
	mStatus					err;
	mDNSInterfaceData *		ifd;
	
	check( inMDNS );
	check( inID );
	check( outInfo );
	
	// Search for an interface with the specified ID,
	
	for( ifd = inMDNS->p->interfaceList; ifd; ifd = ifd->next )
	{
		if( ifd == (mDNSInterfaceData *) inID )
		{
			break;
		}
	}
	require_action_quiet( ifd, exit, err = mStatus_NoSuchNameErr );
	
	// Success!
	
	outInfo->name 	= ifd->name;
	outInfo->ip 	= ifd->hostSet.ip;
	err 			= mStatus_NoError;
	
exit:
	return( err );
}

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	debugf_
//===========================================================================================================================

#if( MDNS_DEBUGMSGS )
void debugf_( const char *inFormat, ... )
{
	char		buffer[ 512 ];
    va_list		args;
    mDNSu32		length;
	
	va_start( args, inFormat );
	length = mDNS_vsnprintf( buffer, sizeof( buffer ), inFormat, args );
	va_end( args );
	
	dlog( kDebugLevelInfo, "%s\n", buffer );
}
#endif

//===========================================================================================================================
//	verbosedebugf_
//===========================================================================================================================

#if( MDNS_DEBUGMSGS > 1 )
void verbosedebugf_( const char *inFormat, ... )
{
	char		buffer[ 512 ];
    va_list		args;
    mDNSu32		length;
	
	va_start( args, inFormat );
	length = mDNS_vsnprintf( buffer, sizeof( buffer ), inFormat, args );
	va_end( args );
	
	dlog( kDebugLevelVerbose, "%s\n", buffer );
}
#endif

//===========================================================================================================================
//	LogMsg
//===========================================================================================================================

void LogMsg( const char *inFormat, ... )
{
	char		buffer[ 512 ];
    va_list		args;
    mDNSu32		length;
	
	va_start( args, inFormat );
	length = mDNS_vsnprintf( buffer, sizeof( buffer ), inFormat, args );
	va_end( args );
	
	dlog( kDebugLevelWarning, "%s\n", buffer );
}

#if( MDNS_DEBUGMSGS )
//===========================================================================================================================
//	mDNSPlatformDebugLog
//===========================================================================================================================

mDNSlocal void mDNSPlatformDebugLog( unsigned long inLevel, const char *inFormat, ... )
{
	if( inLevel >= gDebugLevel )
	{
		va_list		args;
		
		va_start( args, inFormat );
		vfprintf( stderr, inFormat, args );
		fflush( stderr );
		va_end( args );
	}
}

//===========================================================================================================================
//	mDNSPlatformPrintAssert
//===========================================================================================================================

mDNSlocal void
	mDNSPlatformPrintAssert( 
		const char *		inSignature, 
		long				inError, 
		const char *		inAssertionString, 
		const char *		inErrorString, 
		const char *		inFileName, 
		unsigned long		inLineNumber, 
		const char *		inFunction )
{
	char *		dataPtr;
	char		buffer[ 512 ];
	char		tempSignatureChar;
		
	if( !inSignature )
	{
		tempSignatureChar = '\0';
		inSignature = &tempSignatureChar;
	}
	dataPtr = buffer;
	dataPtr += sprintf( dataPtr, "\n" );
	if( inError != 0 )
	{
		dataPtr += sprintf( dataPtr, "[%s] Error: %ld\n", inSignature, inError );
	}
	else
	{
		dataPtr += sprintf( dataPtr, "[%s] Assertion failed", inSignature );
		if( inAssertionString )
		{
			dataPtr += sprintf( dataPtr, ": %s", inAssertionString );
		}
		dataPtr += sprintf( dataPtr, "\n" );
	}
	if( inErrorString )
	{
		dataPtr += sprintf( dataPtr, "[%s]    %s\n", inSignature, inErrorString );
	}
	if( inFileName )
	{
		dataPtr += sprintf( dataPtr, "[%s]    file:     \"%s\"\n", inSignature, inFileName );
	}	
	if( inLineNumber )
	{
		dataPtr += sprintf( dataPtr, "[%s]    line:     %ld\n", inSignature, inLineNumber );
	}
	if( inFunction )
	{
		dataPtr += sprintf( dataPtr, "[%s]    function: \"%s\"\n", inSignature, inFunction );
	}
	dataPtr += sprintf( dataPtr, "\n" );
	fprintf( stderr, "%s", buffer );
	fflush( stderr );
}
#endif	// MDNS_DEBUGMSGS

#if 0
#pragma mark -
#pragma mark == Platform Internals  ==
#endif

//===========================================================================================================================
//	SetupSynchronizationObjects
//===========================================================================================================================

mDNSlocal mStatus	SetupSynchronizationObjects( mDNS * const inMDNS )
{
	mStatus		err;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up synchronization objects\n" );
	
	InitializeCriticalSection( &inMDNS->p->lock );
	inMDNS->p->lockInitialized = mDNStrue;
	
	inMDNS->p->cancelEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( inMDNS->p->cancelEvent, exit, err = mStatus_NoMemoryErr );
	
	inMDNS->p->quitEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( inMDNS->p->quitEvent, exit, err = mStatus_NoMemoryErr );
	
	inMDNS->p->interfaceListChangedEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( inMDNS->p->interfaceListChangedEvent, exit, err = mStatus_NoMemoryErr );
	
	inMDNS->p->wakeupEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( inMDNS->p->wakeupEvent, exit, err = mStatus_NoMemoryErr );
	
	err = mStatus_NoError;
	
exit:
	if( err )
	{
		TearDownSynchronizationObjects( inMDNS );
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up synchronization objects done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	TearDownSynchronizationObjects
//===========================================================================================================================

mDNSlocal mStatus	TearDownSynchronizationObjects( mDNS * const inMDNS )
{
	mStatus		err;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down synchronization objects\n" );
	
	if( inMDNS->p->quitEvent )
	{
		CloseHandle( inMDNS->p->quitEvent );
		inMDNS->p->quitEvent = 0;
	}
	if( inMDNS->p->cancelEvent )
	{
		CloseHandle( inMDNS->p->cancelEvent );
		inMDNS->p->cancelEvent = 0;
	}
	if( inMDNS->p->interfaceListChangedEvent )
	{
		CloseHandle( inMDNS->p->interfaceListChangedEvent );
		inMDNS->p->interfaceListChangedEvent = 0;
	}
	if( inMDNS->p->wakeupEvent )
	{
		CloseHandle( inMDNS->p->wakeupEvent );
		inMDNS->p->wakeupEvent = 0;
	}
	if( inMDNS->p->lockInitialized )
	{
		DeleteCriticalSection( &inMDNS->p->lock );
		inMDNS->p->lockInitialized = mDNSfalse;
	}
	err = mStatus_NoError;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down synchronization objects done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	SetupName
//===========================================================================================================================

mDNSlocal mStatus	SetupName( mDNS * const inMDNS )
{
	mStatus		err;
	char		tempString[ 256 ];
	
	check( inMDNS );
	
	// Get the name of this machine.
	
	tempString[ 0 ] = '\0';
	err = gethostname( tempString, sizeof( tempString ) - 1 );
	check_errno( err, errno_compat() );
	if( err || ( tempString[ 0 ] == '\0' ) )
	{
		// Invalidate name so fall back to a default name.
		
		strcpy( tempString, kMDNSDefaultName );
	}
	tempString[ sizeof( tempString ) - 1 ] = '\0';
	
	// Set up the host name with mDNS.
	
	inMDNS->nicelabel.c[ 0 ] = (mDNSu8) strlen( tempString );
	memcpy( &inMDNS->nicelabel.c[ 1 ], tempString, inMDNS->nicelabel.c[ 0 ] );
	ConvertUTF8PstringToRFC1034HostLabel( inMDNS->nicelabel.c, &inMDNS->hostlabel );
	if( inMDNS->hostlabel.c[ 0 ] == 0 )
	{
		// Nice name has no characters that are representable as an RFC1034 name (e.g. Japanese) so use the default.
		
		MakeDomainLabelFromLiteralString( &inMDNS->hostlabel, kMDNSDefaultName );
	}
	check( inMDNS->nicelabel.c[ 0 ] != 0 );
	check( inMDNS->hostlabel.c[ 0 ] != 0 );
	
	mDNS_GenerateFQDN( inMDNS );
	
	dlog( kDebugLevelInfo, DEBUG_NAME "nice name \"%.*s\"\n", inMDNS->nicelabel.c[ 0 ], &inMDNS->nicelabel.c[ 1 ] );
	dlog( kDebugLevelInfo, DEBUG_NAME "host name \"%.*s\"\n", inMDNS->hostlabel.c[ 0 ], &inMDNS->hostlabel.c[ 1 ] );
	return( err );
}

//===========================================================================================================================
//	SetupInterfaceList
//===========================================================================================================================

mDNSlocal mStatus	SetupInterfaceList( mDNS * const inMDNS )
{
	mStatus						err;
	mDNSInterfaceData **		next;
	mDNSInterfaceData *			ifd;
	struct ifaddrs *			addrs;
	struct ifaddrs *			p;
	struct ifaddrs *			loopback;
	u_int						flagMask;
	u_int						flagTest;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up interface list\n" );
	check( inMDNS );
	check( inMDNS->p );
	
	addrs = NULL;
	
	// Tear down any existing interfaces that may be set up.
	
	TearDownInterfaceList( inMDNS );
	
	// Set up the name of this machine.
	
	err = SetupName( inMDNS );
	check_noerr( err );
	
	// Set up the interface list change notification.
	
	err = SetupNotifications( inMDNS );
	check_noerr( err );
	
	// Set up each interface that is active, multicast-capable, and not the loopback interface or point-to-point.
	
	flagMask = IFF_UP | IFF_MULTICAST | IFF_LOOPBACK | IFF_POINTTOPOINT;
	flagTest = IFF_UP | IFF_MULTICAST;
	
	loopback = NULL;
	next = &inMDNS->p->interfaceList;
	
	err = getifaddrs( &addrs );
	require_noerr( err, exit );
	
	for( p = addrs; p; p = p->ifa_next )
	{
		if( ( p->ifa_flags & flagMask ) == flagTest )
		{
			if( !p->ifa_addr || ( p->ifa_addr->sa_family != AF_INET ) )		// $$$ TO DO: Update for IPv6.
			{
				continue;
			}
			
			err = SetupInterface( inMDNS, (struct sockaddr_in *) p->ifa_addr, &ifd );
			require_noerr( err, exit );
			
			strcpy( ifd->name, p->ifa_name );
			
			*next = ifd;
			next = &ifd->next;
			++inMDNS->p->interfaceCount;
		}
	}
	
exit:
	if( err )
	{
		TearDownInterfaceList( inMDNS );
	}
	if( addrs )
	{
		freeifaddrs( addrs );
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up interface list done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	TearDownInterfaceList
//===========================================================================================================================

mDNSlocal mStatus	TearDownInterfaceList( mDNS * const inMDNS )
{
	mStatus					err;
	mDNSInterfaceData *		ifd;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down interface list\n" );
	check( inMDNS );
	check( inMDNS->p );
	
	// Tear down interface list change notifications.
	
	err = TearDownNotifications( inMDNS );
	check_noerr( err );
	
	// Tear down all the interfaces.
	
	while( inMDNS->p->interfaceList )
	{
		ifd = inMDNS->p->interfaceList;
		inMDNS->p->interfaceList = ifd->next;
		
		TearDownInterface( inMDNS, ifd );
	}
	inMDNS->p->interfaceCount = 0;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down interface list done\n" );
	return( mStatus_NoError );
}

//===========================================================================================================================
//	SetupInterface
//===========================================================================================================================

mDNSlocal mStatus	SetupInterface( mDNS * const inMDNS, const struct sockaddr_in *inAddress, mDNSInterfaceData **outIFD )
{
	mStatus					err;
	mDNSInterfaceData *		ifd;
	SocketRef				socketRef;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up interface\n" );
	check( inMDNS );
	check( inMDNS->p );
	check( inAddress );
	check( outIFD );
	
	// Allocate memory for the info item.
	
	ifd = (mDNSInterfaceData *) calloc( 1, sizeof( *ifd ) );
	require_action( ifd, exit, err = mStatus_NoMemoryErr );
	ifd->multicastSocketRef = kInvalidSocketRef;
	ifd->unicastSocketRef 	= kInvalidSocketRef;
	
	///
	/// Set up multicast portion of interface.
	///
	
	// Set up the multicast DNS (port 5353) socket for this interface.
	
	err = SetupSocket( inMDNS, inAddress, MulticastDNSPort, &socketRef );
	require_noerr( err, exit );
	ifd->multicastSocketRef = socketRef;
	
	// Set up the read pending event and associate it so we can block until data is available for this socket.
	
	ifd->multicastReadPendingEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( ifd->multicastReadPendingEvent, exit, err = mStatus_NoMemoryErr );
	
	err = WSAEventSelect( ifd->multicastSocketRef, ifd->multicastReadPendingEvent, FD_READ );
	require_noerr( err, exit );
	
	///
	/// Set up unicast portion of interface.
	///
	
	// Set up the unicast DNS (port 53) socket for this interface (to handle normal DNS requests).
	
	err = SetupSocket( inMDNS, inAddress, UnicastDNSPort, &socketRef );
	require_noerr( err, exit );
	ifd->unicastSocketRef = socketRef;
	
	// Set up the read pending event and associate it so we can block until data is available for this socket.
	
	ifd->unicastReadPendingEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( ifd->unicastReadPendingEvent, exit, err = mStatus_NoMemoryErr );
	
	err = WSAEventSelect( ifd->unicastSocketRef, ifd->unicastReadPendingEvent, FD_READ );
	require_noerr( err, exit );
	
	// Register this interface with mDNS.
	
	ifd->hostSet.InterfaceID 			= (mDNSInterfaceID) ifd;
	ifd->hostSet.ip.type 				= mDNSAddrType_IPv4;
	ifd->hostSet.ip.ip.v4.NotAnInteger 	= inAddress->sin_addr.s_addr;
	ifd->hostSet.Advertise       		= inMDNS->AdvertiseLocalAddresses;
	
	err = mDNS_RegisterInterface( inMDNS, &ifd->hostSet );
	require_noerr( err, exit );
	ifd->hostRegistered = mDNStrue;
	
	dlog( kDebugLevelInfo, DEBUG_NAME "Registered IP address: %u.%u.%u.%u\n", 
		  ifd->hostSet.ip.ip.v4.b[ 0 ], 
		  ifd->hostSet.ip.ip.v4.b[ 1 ], 
		  ifd->hostSet.ip.ip.v4.b[ 2 ], 
		  ifd->hostSet.ip.ip.v4.b[ 3 ] );
	
	// Success!
	
	*outIFD = ifd;
	ifd = NULL;
	
exit:
	if( ifd )
	{
		TearDownInterface( inMDNS, ifd );
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up interface done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	TearDownInterface
//===========================================================================================================================

mDNSlocal mStatus	TearDownInterface( mDNS * const inMDNS, mDNSInterfaceData *inIFD )
{
	SocketRef		socketRef;
	
	check( inMDNS );
	check( inIFD );
	
	// Deregister this interface with mDNS.
	
	dlog( kDebugLevelInfo, DEBUG_NAME "Deregistering IP address: %u.%u.%u.%u\n", 
		  inIFD->hostSet.ip.ip.v4.b[ 0 ],
		  inIFD->hostSet.ip.ip.v4.b[ 1 ],
		  inIFD->hostSet.ip.ip.v4.b[ 2 ],
		  inIFD->hostSet.ip.ip.v4.b[ 3 ] );
	
	if( inIFD->hostRegistered )
	{
		inIFD->hostRegistered = mDNSfalse;
		mDNS_DeregisterInterface( inMDNS, &inIFD->hostSet );
	}
	
	// Tear down the multicast socket.
	
	if( inIFD->multicastReadPendingEvent )
	{
		CloseHandle( inIFD->multicastReadPendingEvent );
		inIFD->multicastReadPendingEvent = 0;
	}
	
	socketRef = inIFD->multicastSocketRef;
	inIFD->multicastSocketRef = kInvalidSocketRef;
	if( IsValidSocket( socketRef ) )
	{
		dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down multicast socket %d\n", socketRef );
		close_compat( socketRef );
	}
	
	// Tear down the unicast socket.
	
	if( inIFD->unicastReadPendingEvent )
	{
		CloseHandle( inIFD->unicastReadPendingEvent );
		inIFD->unicastReadPendingEvent = 0;
	}
	
	socketRef = inIFD->unicastSocketRef;
	inIFD->unicastSocketRef = kInvalidSocketRef;
	if( IsValidSocket( socketRef ) )
	{
		dlog( kDebugLevelVerbose, DEBUG_NAME "tearing down unicast socket %d\n", socketRef );
		close_compat( socketRef );
	}
	
	// Free the memory used by the interface info.
	
	free( inIFD );	
	return( mStatus_NoError );
}

//===========================================================================================================================
//	SetupSocket
//===========================================================================================================================

mDNSlocal mStatus
	SetupSocket( 
		mDNS * const 				inMDNS, 
		const struct sockaddr_in *	inAddress, 
		mDNSIPPort 					inPort, 
		SocketRef *					outSocketRef  )
{
	mStatus					err;
	SocketRef				socketRef;
	int						option;
	struct ip_mreq			mreq;
	struct sockaddr_in		addr;
	mDNSv4Addr				ip;
	
	MDNS_UNUSED( inMDNS );
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up socket done\n" );
	check( inMDNS );
	check( outSocketRef );
	
	// Set up a UDP socket. 
	
	socketRef = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
	require_action( IsValidSocket( socketRef ), exit, err = mStatus_NoMemoryErr );
	
	// Turn on reuse address option so multiple servers can listen for Multicast DNS packets.
		
	option = 1;
	err = setsockopt( socketRef, SOL_SOCKET, SO_REUSEADDR, (char *) &option, sizeof( option ) );
	check_errno( err, errno_compat() );
	
	// Bind to the specified port (53 for unicast or 5353 for multicast).
	
	ip.NotAnInteger 		= inAddress->sin_addr.s_addr;
	memset( &addr, 0, sizeof( addr ) );
	addr.sin_family 		= AF_INET;
	addr.sin_port 			= inPort.NotAnInteger;
	addr.sin_addr.s_addr 	= ip.NotAnInteger;
	err = bind( socketRef, (struct sockaddr *) &addr, sizeof( addr ) );
	if( err && ( inPort.NotAnInteger == UnicastDNSPort.NotAnInteger ) )
	{
		// Some systems prevent code without root permissions from binding to the DNS port so ignore this 
		// error since it is not critical. This should only occur with non-root processes.
		
		err = 0;
	}
	check_errno( err, errno_compat() );
	
	// Join the all-DNS multicast group so we receive Multicast DNS packets.
	
	if( inPort.NotAnInteger == MulticastDNSPort.NotAnInteger )
	{
		mreq.imr_multiaddr.s_addr 	= AllDNSLinkGroup.NotAnInteger;
		mreq.imr_interface.s_addr 	= ip.NotAnInteger;
		err = setsockopt( socketRef, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &mreq, sizeof( mreq ) );
		check_errno( err, errno_compat() );
	}
				
	// Direct multicast packets to the specified interface.
	
	addr.sin_addr.s_addr = ip.NotAnInteger;
	err = setsockopt( socketRef, IPPROTO_IP, IP_MULTICAST_IF, (char *) &addr.sin_addr, sizeof( addr.sin_addr ) );
	check_errno( err, errno_compat() );
	
	// Set the TTL of outgoing unicast packets to 255 (helps against spoofing).
		
	option = 255;
	err = setsockopt( socketRef, IPPROTO_IP, IP_TTL, (char *) &option, sizeof( option ) );
	check_errno( err, errno_compat() );
	
	// Set the TTL of outgoing multicast packets to 255 (helps against spoofing).
	
	option = 255;
	err = setsockopt( socketRef, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &option, sizeof( option ) );
	check_errno( err, errno_compat() );
		
	// Success!
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up socket done (%u.%u.%u.%u:%u, %d)\n", 
		  ip.b[ 0 ], ip.b[ 1 ], ip.b[ 2 ], ip.b[ 3 ], ntohs( inPort.NotAnInteger ), socketRef );
	
	*outSocketRef = socketRef;
	socketRef = kInvalidSocketRef;
	err = mStatus_NoError;
	
exit:
	if( IsValidSocket( socketRef ) )
	{
		close_compat( socketRef );
	}
	return( err );
}

//===========================================================================================================================
//	SetupNotifications
//===========================================================================================================================

mDNSlocal mStatus	SetupNotifications( mDNS * const inMDNS )
{
	mStatus				err;
	SocketRef			socketRef;
	unsigned long		param;
	int					inBuffer;
	int					outBuffer;
	DWORD				outSize;
	
	// Register to listen for address list changes.
	
	socketRef = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
	require_action( IsValidSocket( socketRef ), exit, err = mStatus_NoMemoryErr );
	inMDNS->p->interfaceListChangedSocketRef = socketRef;
	
	// Make the socket non-blocking so the WSAIoctl returns immediately with WSAEWOULDBLOCK. It will set the event 
	// when a change to the interface list is detected.
	
	param = 1;
	err = ioctlsocket( socketRef, FIONBIO, &param );
	require_errno( err, errno_compat(), exit );
	
	inBuffer	= 0;
	outBuffer	= 0;
	err = WSAIoctl( socketRef, SIO_ADDRESS_LIST_CHANGE, &inBuffer, 0, &outBuffer, 0, &outSize, NULL, NULL );
	if( err < 0 )
	{
		check( errno_compat() == WSAEWOULDBLOCK );
	}
	
	err = WSAEventSelect( socketRef, inMDNS->p->interfaceListChangedEvent, FD_ADDRESS_LIST_CHANGE );
	require_errno( err, errno_compat(), exit );

exit:
	if( err )
	{
		TearDownNotifications( inMDNS );
	}
	return( err );
}

//===========================================================================================================================
//	TearDownNotifications
//===========================================================================================================================

mDNSlocal mStatus	TearDownNotifications( mDNS * const inMDNS )
{
	SocketRef		socketRef;
	
	socketRef = inMDNS->p->interfaceListChangedSocketRef;
	inMDNS->p->interfaceListChangedSocketRef = kInvalidSocketRef;
	if( IsValidSocket( socketRef ) )
	{
		close_compat( socketRef );
	}
	return( mStatus_NoError );
}

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	SetupThread
//===========================================================================================================================

mDNSlocal mStatus	SetupThread( mDNS * const inMDNS )
{
	mStatus			err;
	HANDLE			threadHandle;
	unsigned		threadID;
	DWORD			result;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up thread\n" );
	
	// To avoid a race condition with the thread ID needed by the unlocking code, we need to make sure the
	// thread has fully initialized. To do this, we create the thread then wait for it to signal it is ready.
	
	inMDNS->p->initEvent = CreateEvent( NULL, FALSE, FALSE, NULL );
	require_action( inMDNS->p->initEvent, exit, err = mStatus_NoMemoryErr );
	inMDNS->p->initStatus = mStatus_Invalid;
	
	// Create thread with _beginthreadex() instead of CreateThread() to avoid memory leaks when using static run-time 
	// libraries. See <http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createthread.asp>.
	
	threadHandle = (HANDLE) _beginthreadex( NULL, 0, ProcessingThread, inMDNS, 0, &threadID );
	require_action( threadHandle, exit, err = mStatus_NoMemoryErr );
	
	result = WaitForSingleObject( inMDNS->p->initEvent, INFINITE );
	require_action( result == WAIT_OBJECT_0, exit, err = mStatus_UnknownErr );
	err = inMDNS->p->initStatus;
	require_noerr( err, exit );
	
exit:
	if( inMDNS->p->initEvent )
	{
		CloseHandle( inMDNS->p->initEvent );
		inMDNS->p->initEvent = 0;
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "setting up thread done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	TearDownThread
//===========================================================================================================================

mDNSlocal mStatus	TearDownThread( const mDNS * const inMDNS )
{
	DWORD		result;
	
	// Signal the cancel event to cause the thread to exit. Then wait for the quit event to be signal indicating it did 
	// exit. If the quit event is not signal in 5 seconds, just give up and close anyway sinec the thread is probably hung.
	
	if( inMDNS->p->cancelEvent )
	{
		BOOL		wasSet;
		
		wasSet = SetEvent( inMDNS->p->cancelEvent );
		check( wasSet );
		
		if( inMDNS->p->quitEvent )
		{
			result = WaitForSingleObject( inMDNS->p->quitEvent, 5 * 1000 );
			check( result == WAIT_OBJECT_0 );
		}
	}
	return( mStatus_NoError );
}

//===========================================================================================================================
//	ProcessingThread
//===========================================================================================================================

mDNSlocal unsigned WINAPI	ProcessingThread( LPVOID inParam )
{
	mDNS *			m;
	int				done;
	mStatus			err;
	HANDLE *		waitList;
	int				waitListCount;
	DWORD			result;
	BOOL			wasSet;
	
	check( inParam );
		
	m = (mDNS *) inParam;
	err = ProcessingThreadInitialize( m );
	require_noerr( err, exit );
	
	done = 0;
	while( !done )
	{
		// Set up the list of objects we'll be waiting on.
		
		waitList 		= NULL;
		waitListCount	= 0;
		err = ProcessingThreadSetupWaitList( m, &waitList, &waitListCount );
		require_noerr( err, exit );
		
		// Main processing loop.
		
		for( ;; )
		{
			// Give the mDNS core a chance to do its work and determine next event time.
			
			mDNSs32 interval = mDNS_Execute(m) - mDNSPlatformTimeNow();
			if      (interval < 0)						interval = 0;
			else if (interval > (0x7FFFFFFF / 1000))	interval = 0x7FFFFFFF / mDNSPlatformOneSecond;
			else										interval = (interval * 1000) / mDNSPlatformOneSecond;
			
			// Wait until something occurs (e.g. cancel, incoming packet, or timeout).
			
			result = WaitForMultipleObjects( (DWORD) waitListCount, waitList, FALSE, (DWORD) interval );
			if( result == WAIT_TIMEOUT )
			{
				// Next task timeout occurred. Loop back up to give mDNS core a chance to work.
				
				dlog( kDebugLevelChatty - 1, DEBUG_NAME "timeout\n" );
				continue;
			}
			else if( result == kWaitListCancelEvent )
			{
				// Cancel event. Set the done flag and break to exit.
				
				dlog( kDebugLevelVerbose, DEBUG_NAME "canceling...\n" );
				done = 1;
				break;
			}
			else if( result == kWaitListInterfaceListChangedEvent )
			{
				// Interface list changed event. Break out of the inner loop to re-setup the wait list.
				
				ProcessingThreadInterfaceListChanged( m );
				break;
			}
			else if( result == kWaitListWakeupEvent )
			{
				// Wakeup event due to an mDNS API call. Loop back to call mDNS_Execute.
				
				dlog( kDebugLevelChatty - 1, DEBUG_NAME "wakeup\n" );
				continue;
			}
			else
			{
				int		waitItemIndex;
				
				// Socket data available event. Determine which socket and process the packet.
				
				waitItemIndex = (int)( ( (int) result ) - WAIT_OBJECT_0 );
				dlog( kDebugLevelChatty, DEBUG_NAME "socket data available on socket index %d\n", waitItemIndex );
				check( ( waitItemIndex >= 0 ) && ( waitItemIndex < waitListCount ) );
				if( ( waitItemIndex >= 0 ) && ( waitItemIndex < waitListCount ) )
				{
					HANDLE					signaledObject;
					int						n;
					mDNSInterfaceData *		ifd;
					
					signaledObject = waitList[ waitItemIndex ];
					
					n = 0;
					for( ifd = m->p->interfaceList; ifd; ifd = ifd->next )
					{
						if( ifd->multicastReadPendingEvent == signaledObject )
						{
							ProcessingThreadProcessPacket( m, ifd, ifd->multicastSocketRef );
							++n;
						}
						if( ifd->unicastReadPendingEvent == signaledObject )
						{
							ProcessingThreadProcessPacket( m, ifd, ifd->unicastSocketRef );
							++n;
						}
					}
					check( n > 0 );
				}
				else
				{
					// Unexpected wait result.
				
					dlog( kDebugLevelAllowedError, DEBUG_NAME "unexpected wait result (result=0x%08X)\n", result );
				}
			}
		}
		
		// Release the wait list.
		
		if( waitList )
		{
			free( waitList );
			waitList = NULL;
			waitListCount = 0;
		}
	}
	
	// Signal the quit event to indicate that the thread is finished.

exit:
	wasSet = SetEvent( m->p->quitEvent );
	check( wasSet );

	// Call _endthreadex() explicitly instead of just exiting normally to avoid memory leaks when using static run-time
	// libraries. See <http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createthread.asp>.
	
	_endthreadex( 0 );
	return( 0 );
}

//===========================================================================================================================
//	ProcessingThreadInitialize
//===========================================================================================================================

mDNSlocal mStatus ProcessingThreadInitialize( mDNS * const inMDNS )
{
	mStatus		err;
	BOOL		wasSet;
	
	inMDNS->p->threadID = GetCurrentThreadId();
	
	err = SetupInterfaceList( inMDNS );
	require_noerr( err, exit );
	
exit:
	if( err )
	{
		TearDownInterfaceList( inMDNS );
	}
	inMDNS->p->initStatus = err;
	wasSet = SetEvent( inMDNS->p->initEvent );
	check( wasSet );
	
	return( err );
}

//===========================================================================================================================
//	ProcessingThreadSetupWaitList
//===========================================================================================================================

mDNSlocal mStatus	ProcessingThreadSetupWaitList( mDNS * const inMDNS, HANDLE **outWaitList, int *outWaitListCount )
{
	mStatus					err;
	int						waitListCount;
	HANDLE *				waitList;
	HANDLE *				waitItemPtr;
	mDNSInterfaceData *		ifd;
	
	dlog( kDebugLevelVerbose, DEBUG_NAME "thread setting up wait list\n" );
	check( inMDNS );
	check( inMDNS->p );
	check( outWaitList );
	check( outWaitListCount );
	
	// Allocate an array to hold all the objects to wait on.
	
	waitListCount = kWaitListFixedItemCount + ( 2 * inMDNS->p->interfaceCount );
	waitList = (HANDLE *) malloc( waitListCount * sizeof( *waitList ) );
	require_action( waitList, exit, err = mStatus_NoMemoryErr );
	waitItemPtr = waitList;
	
	// Add the fixed wait items to the beginning of the list.
	
	*waitItemPtr++ = inMDNS->p->cancelEvent;
	*waitItemPtr++ = inMDNS->p->interfaceListChangedEvent;
	*waitItemPtr++ = inMDNS->p->wakeupEvent;
	
	// Append all the dynamic wait items to the list.
	
	for( ifd = inMDNS->p->interfaceList; ifd; ifd = ifd->next )
	{
		*waitItemPtr++ = ifd->multicastReadPendingEvent;
		*waitItemPtr++ = ifd->unicastReadPendingEvent;
	}
	
	*outWaitList 		= waitList;
	*outWaitListCount	= waitListCount;
	waitList			= NULL;
	err					= mStatus_NoError;
	
exit:
	if( waitList )
	{
		free( waitList );
	}
	dlog( kDebugLevelVerbose, DEBUG_NAME "thread setting up wait list done (err=%ld)\n", err );
	return( err );
}

//===========================================================================================================================
//	ProcessingThreadProcessPacket
//===========================================================================================================================

mDNSlocal void	ProcessingThreadProcessPacket( mDNS *inMDNS, mDNSInterfaceData *inIFD, SocketRef inSocketRef )
{
	int						n;
	mDNSBool				isMulticast;
	DNSMessage				packet;
	struct sockaddr_in		addr;
	int						addrSize;
	mDNSu8 *				packetEndPtr;
	mDNSAddr				srcAddr;
	mDNSIPPort				srcPort;
	mDNSAddr				dstAddr;
	mDNSIPPort				dstPort;
	
	isMulticast = (mDNSBool)( inSocketRef == inIFD->multicastSocketRef );
	
	// Receive the packet.
	
	addrSize = sizeof( addr );
	n = recvfrom( inSocketRef, (char *) &packet, sizeof( packet ), 0, (struct sockaddr *) &addr, &addrSize );
	check( n >= 0 );
	if( n >= 0 )
	{
		// Set up the src/dst/interface info.
		
		srcAddr.type				= mDNSAddrType_IPv4;
		srcAddr.ip.v4.NotAnInteger 	= addr.sin_addr.s_addr;
		srcPort.NotAnInteger		= addr.sin_port;
		dstAddr.type				= mDNSAddrType_IPv4;
		dstAddr.ip.v4				= isMulticast ? AllDNSLinkGroup  : inIFD->hostSet.ip.ip.v4;
		dstPort						= isMulticast ? MulticastDNSPort : UnicastDNSPort;
		
		dlog( kDebugLevelChatty, DEBUG_NAME "packet received\n" );
		dlog( kDebugLevelChatty, DEBUG_NAME "    size      = %d\n", n );
		dlog( kDebugLevelChatty, DEBUG_NAME "    src       = %u.%u.%u.%u:%u\n", 
			  srcAddr.ip.v4.b[ 0 ], srcAddr.ip.v4.b[ 1 ], srcAddr.ip.v4.b[ 2 ], srcAddr.ip.v4.b[ 3 ], 
			  ntohs( srcPort.NotAnInteger ) );
		dlog( kDebugLevelChatty, DEBUG_NAME "    dst       = %u.%u.%u.%u:%u\n", 
			  dstAddr.ip.v4.b[ 0 ], dstAddr.ip.v4.b[ 1 ], dstAddr.ip.v4.b[ 2 ], dstAddr.ip.v4.b[ 3 ], 
			  ntohs( dstPort.NotAnInteger ) );
		dlog( kDebugLevelChatty, DEBUG_NAME "    interface = %u.%u.%u.%u\n", 
			  inIFD->hostSet.ip.ip.v4.b[ 0 ], inIFD->hostSet.ip.ip.v4.b[ 1 ], 
			  inIFD->hostSet.ip.ip.v4.b[ 2 ], inIFD->hostSet.ip.ip.v4.b[ 3 ] );
	
		dlog( kDebugLevelChatty, DEBUG_NAME "--\n" );
		
		// Dispatch the packet to mDNS.
		
		packetEndPtr = ( (mDNSu8 *) &packet ) + n;
		mDNSCoreReceive( inMDNS, &packet, packetEndPtr, &srcAddr, srcPort, &dstAddr, dstPort, inIFD->hostSet.InterfaceID, 255 );
	}
	
	// Update counters.
	
	inIFD->recvMulticastCounter += isMulticast;
	inIFD->recvUnicastCounter 	+= !isMulticast;
	inIFD->recvErrorCounter 	+= ( n < 0 );
}

//===========================================================================================================================
//	ProcessingThreadInterfaceListChanged
//===========================================================================================================================

mDNSlocal void	ProcessingThreadInterfaceListChanged( mDNS *inMDNS )
{
	mStatus		err;
	
	dlog( kDebugLevelInfo, DEBUG_NAME "interface list changed event\n" );
	check( inMDNS );
	
	mDNSPlatformLock( inMDNS );
	
	// Tear down the existing interfaces and set up new ones using the new IP info.
	
	err = TearDownInterfaceList( inMDNS );
	check_noerr( err );
	
	err = SetupInterfaceList( inMDNS );
	check_noerr( err );
		
	mDNSPlatformUnlock( inMDNS );
	
	// Inform clients of the change.
	
	if( inMDNS->MainCallback )
	{
		inMDNS->MainCallback( inMDNS, mStatus_ConfigChanged );
	}
	
	// Force mDNS to update.
	
	mDNSCoreMachineSleep( inMDNS, mDNSfalse );
}

#if 0
#pragma mark -
#pragma mark == Utilities ==
#endif

#if( defined( _WIN32_WCE ) )
//===========================================================================================================================
//	getifaddrs
//===========================================================================================================================

int	getifaddrs( struct ifaddrs **outAddrs )
{
	int							err;
	SocketRef					sock;
	DWORD						size;
	void *						buffer;
	SOCKET_ADDRESS_LIST *		addressList;
	struct ifaddrs *			head;
	struct ifaddrs **			next;
	struct ifaddrs *			ifa;
	int							n;
	int							i;

	sock 	= kInvalidSocketRef;
	buffer	= NULL;
	head	= NULL;
	next	= &head;
	
	// Open a temporary socket because one is needed to use WSAIoctl (we'll close it before exiting this function).
	
	sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
	require_action( IsValidSocket( sock ), exit, err = mStatus_NoMemoryErr );
	
	// Call WSAIoctl with SIO_ADDRESS_LIST_QUERY and pass a null buffer. This call will fail, but the size needed to 
	// for the request will be filled in. Once we know the size, allocate a buffer to hold the entire list.
	//
	// NOTE: Due to a bug in Windows CE, the size returned by WSAIoctl is not enough so double it as a workaround.
	
	size = 0;
	WSAIoctl( sock, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &size, NULL, NULL );
	require_action( size > 0, exit, err = -1 );
	size *= 2;
	
	buffer = malloc( size );
	require_action( buffer, exit, err = -1 );
	
	// We now know the size of the list and have a buffer to hold so call WSAIoctl again to get it.
	
	err = WSAIoctl( sock, SIO_ADDRESS_LIST_QUERY, NULL, 0, buffer, size, &size, NULL, NULL );
	require_noerr( err, exit );
	addressList = (SOCKET_ADDRESS_LIST *) buffer;
	
	// Process the raw interface list and build a linked list of interfaces.
	//
	// NOTE: Due to a bug in Windows CE, the iAddressCount field is always 0 so use 1 in that case.
	
	n = addressList->iAddressCount;
	if( n == 0 )
	{
		n = 1;
	}
	for( i = 0; i < n; ++i )
	{
		ifa = (struct ifaddrs *) calloc( 1, sizeof( struct ifaddrs ) );
		require_action( ifa, exit, err = WSAENOBUFS );
		
		*next = ifa;
		next  = &ifa->ifa_next;
		
		// Fetch the name. $$$ TO DO: Get the real name of the interface.
		
		ifa->ifa_name = (char *) malloc( 16 );
		require_action( ifa->ifa_name, exit, err = WSAENOBUFS );
		sprintf( ifa->ifa_name, "%d", i + 1 );
		
		// Fetch flags. Note: SIO_ADDRESS_LIST_QUERY does not report flags so just fake IFF_UP and IFF_MULTICAST.
		
		ifa->ifa_flags = IFF_UP | IFF_MULTICAST;
		
		// Fetch addresses.
		
		switch( addressList->Address[ i ].lpSockaddr->sa_family )
		{
			case AF_INET:
			{
				struct sockaddr_in *		sinptr4;
				
				sinptr4 = (struct sockaddr_in *) addressList->Address[ i ].lpSockaddr;
				ifa->ifa_addr = (struct sockaddr *) calloc( 1, sizeof( *sinptr4 ) );
				require_action( ifa->ifa_addr, exit, err = WSAENOBUFS );
				memcpy( ifa->ifa_addr, sinptr4, sizeof( *sinptr4 ) );
				break;
			}
			
			default:
				break;
		}
	}
	
	// Success!
	
	if( outAddrs )
	{
		*outAddrs = head;
		head = NULL;
	}
	err = 0;
	
exit:
	if( head )
	{
		freeifaddrs( head );
	}
	if( buffer )
	{
		free( buffer );
	}
	if( sock != INVALID_SOCKET )
	{
		closesocket( sock );
	}
	return( err );
}
#endif	// defined( _WIN32_WCE ) )

#if( !defined( _WIN32_WCE ) )
//===========================================================================================================================
//	getifaddrs
//===========================================================================================================================

int	getifaddrs( struct ifaddrs **outAddrs )
{
	int								err;
	SOCKET							sock;
	DWORD							size;
	DWORD							actualSize;
	INTERFACE_INFO *				buffer;
	INTERFACE_INFO *				tempBuffer;
	INTERFACE_INFO *				ifInfo;
	int								n;
	int								i;
	struct ifaddrs *				head;
	struct ifaddrs **				next;
	struct ifaddrs *				ifa;
	struct sockaddr_in *			sinptr4;
	struct sockaddr_in6_old *		sinptr6;
	struct sockaddr *				sa;
	
	sock	= INVALID_SOCKET;
	buffer	= NULL;
	head	= NULL;
	next	= &head;
	
	// Get the interface list. WSAIoctl is called with SIO_GET_INTERFACE_LIST, but since this does not provide a 
	// way to determine the size of the interface list beforehand, we have to start with an initial size guess and
	// call WSAIoctl repeatedly with increasing buffer sizes until it succeeds. Limit this to 100 tries for safety.
	
	sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
	require_action( sock != INVALID_SOCKET, exit, err = WSAEMFILE );
	
	n = 0;
	size = 16 * sizeof( INTERFACE_INFO );
	for( ;; )
	{
		tempBuffer = (INTERFACE_INFO *) realloc( buffer, size );
		require_action( tempBuffer, exit, err = WSAENOBUFS );
		buffer = tempBuffer;
		
		err = WSAIoctl( sock, SIO_GET_INTERFACE_LIST, NULL, 0, buffer, size, &actualSize, NULL, NULL );
		if( err == 0 )
		{
			break;
		}
		
		++n;
		require_action( n < 100, exit, err = WSAEADDRNOTAVAIL );
		
		size += ( 16 * sizeof( INTERFACE_INFO ) );
	}
	check( actualSize <= size );
	check( ( actualSize % sizeof( INTERFACE_INFO ) ) == 0 );
	n = (int)( actualSize / sizeof( INTERFACE_INFO ) );
	
	// Process the raw interface list and build a linked list of interfaces.
	
	for( i = 0; i < n; ++i )
	{
		ifInfo = &buffer[ i ];
		
		ifa = (struct ifaddrs *) calloc( 1, sizeof( struct ifaddrs ) );
		require_action( ifa, exit, err = WSAENOBUFS );
		
		*next = ifa;
		next  = &ifa->ifa_next;
		
		// Fetch the name. $$$ TO DO: Get the real name of the interface.
		
		ifa->ifa_name = (char *) malloc( 16 );
		require_action( ifa->ifa_name, exit, err = WSAENOBUFS );
		sprintf( ifa->ifa_name, "%d", i + 1 );
		
		// Fetch interface flags.
		
		ifa->ifa_flags = (u_int) ifInfo->iiFlags;
		
		// Fetch addresses.
		
		switch( ifInfo->iiAddress.Address.sa_family )
		{
			case AF_INET:
				sinptr4 = &ifInfo->iiAddress.AddressIn;
				ifa->ifa_addr = (struct sockaddr *) calloc( 1, sizeof( *sinptr4 ) );
				require_action( ifa->ifa_addr, exit, err = WSAENOBUFS );
				memcpy( ifa->ifa_addr, sinptr4, sizeof( *sinptr4 ) );
			
				if( ifInfo->iiNetmask.Address.sa_family == AF_INET )
				{
					sinptr4 = &ifInfo->iiNetmask.AddressIn;
					ifa->ifa_netmask = (struct sockaddr *) calloc( 1, sizeof( *sinptr4 ) );
					require_action( ifa->ifa_netmask, exit, err = WSAENOBUFS );
					memcpy( ifa->ifa_netmask, sinptr4, sizeof( *sinptr4 ) );
				}
				
				if( ifInfo->iiBroadcastAddress.Address.sa_family == AF_INET )
				{
					sinptr4 = &ifInfo->iiBroadcastAddress.AddressIn;
					ifa->ifa_broadaddr = (struct sockaddr *) calloc( 1, sizeof( *sinptr4 ) );
					require_action( ifa->ifa_broadaddr, exit, err = WSAENOBUFS );
					memcpy( ifa->ifa_broadaddr, sinptr4, sizeof( *sinptr4 ) );
				}
				break;
			
			case AF_INET6:
				sinptr6 = &ifInfo->iiAddress.AddressIn6;
				ifa->ifa_addr = (struct sockaddr *) calloc( 1, sizeof( *sinptr6 ) );
				require_action( ifa->ifa_addr, exit, err = WSAENOBUFS );
				memcpy( ifa->ifa_addr, sinptr6, sizeof( *sinptr6 ) );
				break;
			
			default:
				sa = &ifInfo->iiAddress.Address;
				ifa->ifa_addr = (struct sockaddr *) calloc( 1, sizeof( *sa ) );
				require_action( ifa->ifa_addr, exit, err = WSAENOBUFS );
				memcpy( ifa->ifa_addr, sa, sizeof( *sa ) );
				break;
		}
	}
	
	// Success!
	
	if( outAddrs )
	{
		*outAddrs = head;
		head = NULL;
	}
	err = 0;
	
exit:
	if( head )
	{
		freeifaddrs( head );
	}
	if( buffer )
	{
		free( buffer );
	}
	if( sock != INVALID_SOCKET )
	{
		closesocket( sock );
	}
	return( err );
}
#endif	// !defined( _WIN32_WCE ) )

//===========================================================================================================================
//	freeifaddrs
//===========================================================================================================================

void	freeifaddrs( struct ifaddrs *inAddrs )
{
	struct ifaddrs *		p;
	struct ifaddrs *		q;
	
	// Free each piece of the structure. Set to null after freeing to handle macro-aliased fields.
	
	for( p = inAddrs; p; p = q )
	{
		q = p->ifa_next;
		
		if( p->ifa_name )
		{
			free( p->ifa_name );
			p->ifa_name = NULL;
		}
		if( p->ifa_addr )
		{
			free( p->ifa_addr );
			p->ifa_addr = NULL;
		}
		if( p->ifa_netmask )
		{
			free( p->ifa_netmask );
			p->ifa_netmask = NULL;
		}
		if( p->ifa_broadaddr )
		{
			free( p->ifa_broadaddr );
			p->ifa_broadaddr = NULL;
		}
		if( p->ifa_dstaddr )
		{
			free( p->ifa_dstaddr );
			p->ifa_dstaddr = NULL;
		}
		if( p->ifa_data )
		{
			free( p->ifa_data );
			p->ifa_data = NULL;
		}
		free( p );
	}
}

#if( !defined( _WIN32_WCE ) )
//===========================================================================================================================
//	sock_pton
//===========================================================================================================================

int	sock_pton( const char *inString, int inFamily, void *outAddr, size_t inAddrSize, size_t *outAddrSize )
{
	int		err;
	int		size;
	
	if( inAddrSize == 0 )
	{
		if( inFamily == AF_INET )
		{
			inAddrSize = sizeof( struct sockaddr_in );
		}
		else if( inFamily == AF_INET6 )
		{
			inAddrSize = sizeof( struct sockaddr_in6 );
		}
		else
		{
			err = WSAEAFNOSUPPORT;
			goto exit;
		}
	}
	size = (int) inAddrSize;
	
	err = WSAStringToAddressA( (char *) inString, inFamily, NULL, (LPSOCKADDR) outAddr, &size );
	if( err != 0 ) goto exit;
	
	if( outAddrSize )
	{
		*outAddrSize = (size_t) size;
	}
	
exit:
	return( err );
}

//===========================================================================================================================
//	sock_ntop
//===========================================================================================================================

char *	sock_ntop( const void *inAddr, size_t inAddrSize, char *inBuffer, size_t inBufferSize )
{
	DWORD		size;
	int			err;
	DWORD		stringSize;
	
	if( inAddrSize == 0 )
	{
		const struct sockaddr *		addr;
		
		addr = (const struct sockaddr *) inAddr;
		if( addr->sa_family == AF_INET )
		{
			size = sizeof( struct sockaddr_in );
		}
		else if( addr->sa_family == AF_INET6 )
		{
			size = sizeof( struct sockaddr_in6 );
		}
		else
		{
			WSASetLastError( WSAEAFNOSUPPORT );
			inBuffer = NULL;
			goto exit;
		}
	}
	else
	{
		size = (DWORD) inAddrSize;
	}
	
	stringSize = (DWORD) inBufferSize;
	err = WSAAddressToStringA( (LPSOCKADDR) inAddr, size, NULL, inBuffer, &stringSize );
	if( err )
	{
		inBuffer = NULL;
	}
	
exit:
	return( inBuffer );
}
#endif	// !defined( _WIN32_WCE )
