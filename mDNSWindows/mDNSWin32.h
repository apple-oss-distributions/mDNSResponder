/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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
    
$Log: mDNSWin32.h,v $
Revision 1.9  2003/08/20 06:21:25  bradley
Updated to latest internal version of the Rendezvous for Windows platform plugin: Added support
for Windows CE/PocketPC 2003; re-did interface-related code to emulate getifaddrs/freeifaddrs for
restricting usage to only active, multicast-capable, and non-point-to-point interfaces and to ease
the addition of IPv6 support in the future; Changed init code to serialize thread initialization to
enable ThreadID improvement to wakeup notification; Define platform support structure locally to
allow portable mDNS_Init usage; Removed dependence on modified mDNSCore: define interface ID<->name
structures/prototypes locally; Changed to use _beginthreadex()/_endthreadex() on non-Windows CE
platforms (re-mapped to CreateThread on Window CE) to avoid a leak in the Microsoft C runtime;
Added IPv4/IPv6 string<->address conversion routines; Cleaned up some code and added HeaderDoc.

Revision 1.8  2003/08/12 19:56:27  cheshire
Update to APSL 2.0

Revision 1.7  2003/07/23 02:23:01  cheshire
Updated mDNSPlatformUnlock() to work correctly, now that <rdar://problem/3160248>
"ScheduleNextTask needs to be smarter" has refined the way m->NextScheduledEvent is set

Revision 1.6  2003/07/02 21:20:04  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.5  2003/04/29 00:06:09  cheshire
<rdar://problem/3242673> mDNSWindows needs a wakeupEvent object to signal the main thread

Revision 1.4  2003/03/22 02:57:44  cheshire
Updated mDNSWindows to use new "mDNS_Execute" model (see "mDNSCore/Implementer Notes.txt")

Revision 1.3  2002/09/21 20:44:54  zarzycki
Added APSL info

Revision 1.2  2002/09/20 05:55:16  bradley
Multicast DNS platform plugin for Win32

*/

#ifndef	__MDNS_WIN32__
#define	__MDNS_WIN32__

#if( !defined( WIN32_LEAN_AND_MEAN ) )
	#define	WIN32_LEAN_AND_MEAN		// Needed to avoid redefinitions by Windows interfaces.
#endif

#include	<windows.h>
#include	<winsock2.h>
#include	<Ws2tcpip.h>

#include	"mDNSClientAPI.h"

#ifdef	__cplusplus
	extern "C" {
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	SocketRef

	@abstract	Socket file descriptor alias for improved readability.
*/

typedef SOCKET		SocketRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		mDNSInterfaceData

	@abstract	Structure containing interface-specific data.
*/

typedef struct	mDNSInterfaceData	mDNSInterfaceData;
struct	mDNSInterfaceData
{
	mDNSInterfaceData *			next;
	char						name[ 256 ];
	SocketRef					multicastSocketRef;
	HANDLE						multicastReadPendingEvent;
	SocketRef					unicastSocketRef;
	HANDLE						unicastReadPendingEvent;
	NetworkInterfaceInfo		hostSet;
	mDNSBool					hostRegistered;
	
	int							sendMulticastCounter;
	int							sendUnicastCounter;
	int							sendErrorCounter;
	
	int							recvMulticastCounter;
	int							recvUnicastCounter;
	int							recvErrorCounter;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		mDNS_PlatformSupport_struct

	@abstract	Structure containing platform-specific data.
*/

struct	mDNS_PlatformSupport_struct
{
	CRITICAL_SECTION			lock;
	mDNSBool					lockInitialized;
	HANDLE						cancelEvent;
	HANDLE						quitEvent;
	HANDLE						interfaceListChangedEvent;
	HANDLE						wakeupEvent;
	HANDLE						initEvent;
	mStatus						initStatus;
	
	SocketRef					interfaceListChangedSocketRef;
	int							interfaceCount;
	mDNSInterfaceData *			interfaceList;
	DWORD						threadID;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		ifaddrs

	@abstract	Interface information
*/

struct ifaddrs
{
	struct ifaddrs *	ifa_next;
	char *				ifa_name;
	u_int				ifa_flags;
	struct sockaddr	*	ifa_addr;
	struct sockaddr	*	ifa_netmask;
	struct sockaddr	*	ifa_broadaddr;
	struct sockaddr	*	ifa_dstaddr;
	void *				ifa_data;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	getifaddrs

	@abstract	Builds a linked list of interfaces. Caller must free using freeifaddrs if successful.
*/

int	getifaddrs( struct ifaddrs **outAddrs );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	freeifaddrs

	@abstract	Frees a linked list of interfaces built with getifaddrs.
*/

void	freeifaddrs( struct ifaddrs *inAddrs );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	sock_pton

	@abstract	Converts a 'p'resentation address string into a 'n'umeric sockaddr structure.
	
	@result		0 if successful or an error code on failure.
*/

int	sock_pton( const char *inString, int inFamily, void *outAddr, size_t inAddrSize, size_t *outAddrSize );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	sock_ntop

	@abstract	Converts a 'n'umeric sockaddr structure into a 'p'resentation address string.
	
	@result		Ptr to 'p'resentation address string buffer if successful or NULL on failure.
*/

char *	sock_ntop( const void *inAddr, size_t inAddrSize, char *inBuffer, size_t inBufferSize );

#ifdef	__cplusplus
	}
#endif

#endif	// __MDNS_WIN32__
