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
    
$Log: mDNSWin32.h,v $
Revision 1.22  2005/03/04 22:44:53  shersche
<rdar://problem/4022802> mDNSResponder did not notice changes to DNS server config

Revision 1.21  2005/03/03 02:29:00  shersche
Use the RegNames.h header file for registry key names

Revision 1.20  2005/01/25 08:12:52  shersche
<rdar://problem/3947417> Enable Unicast and add Dynamic DNS support.
Bug #: 3947417

Revision 1.19  2004/12/15 07:34:45  shersche
Add platform support for IPv4 and IPv6 unicast sockets

Revision 1.18  2004/10/11 21:53:15  shersche
<rdar://problem/3832450> Change GetWindowsVersionString link scoping from static to non-static so that it can be accessed from other compilation units. The information returned in this function will be used to determine what service dependencies to use when calling CreateService().
Bug #: 3832450

Revision 1.17  2004/09/17 01:08:57  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.16  2004/08/05 05:43:01  shersche
<rdar://problem/3751566> Add HostDescriptionChangedCallback so callers can choose to handle it when mDNSWin32 core detects that the computer description string has changed
Bug #: 3751566

Revision 1.15  2004/07/26 05:42:50  shersche
use "Computer Description" for nicename if available, track dynamic changes to "Computer Description"

Revision 1.14  2004/07/13 21:24:25  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.13  2004/06/24 15:23:24  shersche
Add InterfaceListChanged callback.  This callback is used in Service.c to add link local routes to the routing table
Submitted by: herscher

Revision 1.12  2004/06/18 05:22:16  rpantos
Integrate Scott's changes

Revision 1.11  2004/01/30 02:44:32  bradley
Added support for IPv6 (v4 & v6, v4-only, v6-only, AAAA over v4, etc.). Added support for DNS-SD
InterfaceID<->Interface Index mappings. Added support for loopback usage when no other interfaces
are available. Updated unlock signaling to no longer require timenow - NextScheduledTime to be >= 0
(it no longer is). Added unicast-capable detection to avoid using unicast when there is other mDNS
software running on the same machine. Removed unneeded sock_XtoY routines. Added support for
reporting HINFO records with the  Windows and mDNSResponder version information.

Revision 1.10  2003/10/24 23:23:02  bradley
Removed legacy port 53 support as it is no longer needed.

Revision 1.9  2003/08/20 06:21:25  bradley
Updated to latest internal version of the mDNSWindows platform layer: Added support
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

#include	"CommonServices.h"

#if( !defined( _WIN32_WCE ) )
	#include	<mswsock.h>
#endif

#include	"mDNSEmbeddedAPI.h"
#include	"dDNS.h"

#ifdef	__cplusplus
	extern "C" {
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		mDNSInterfaceData

	@abstract	Structure containing interface-specific data.
*/

typedef struct	mDNSInterfaceData	mDNSInterfaceData;
struct	mDNSInterfaceData
{
	mDNSInterfaceData *			next;
	char						name[ 128 ];
	uint32_t					index;
	uint32_t					scopeID;
	SocketRef					sock;
#if( !defined( _WIN32_WCE ) )
	LPFN_WSARECVMSG				wsaRecvMsgFunctionPtr;
#endif
	HANDLE						readPendingEvent;
	NetworkInterfaceInfo		interfaceInfo;
	mDNSAddr					defaultAddr;
	mDNSBool					hostRegistered;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	IdleThreadCallback

	@abstract	mDNSWin32 core will call out through this function pointer
				after calling mDNS_Execute
*/
typedef mDNSs32 (*IdleThreadCallback)(mDNS * const inMDNS, mDNSs32 interval);
//---------------------------------------------------------------------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	InterfaceListChangedCallback

	@abstract	mDNSWin32 core will call out through this function pointer
				after detecting an interface list changed event
*/
typedef void (*InterfaceListChangedCallback)(mDNS * const inMDNS);
//---------------------------------------------------------------------------------------------------------------------------


//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	HostDescriptionChangedCallback

	@abstract	mDNSWin32 core will call out through this function pointer
				after detecting that the computer description has changed
*/
typedef void (*HostDescriptionChangedCallback)(mDNS * const inMDNS);
//---------------------------------------------------------------------------------------------------------------------------


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
	HANDLE						descChangedEvent;	// Computer description changed event
	HANDLE						tcpipChangedEvent;	// TCP/IP config changed
	HANDLE						ddnsChangedEvent;	// DynDNS config changed
	HANDLE						wakeupEvent;
	HANDLE						initEvent;
	HKEY						descKey;
	HKEY						tcpipKey;
	HKEY						ddnsKey;
	mStatus						initStatus;
	SocketRef					interfaceListChangedSocket;
	int							interfaceCount;
	mDNSInterfaceData *			interfaceList;
	mDNSInterfaceData *			inactiveInterfaceList;
	DWORD						threadID;
	IdleThreadCallback			idleThreadCallback;
	InterfaceListChangedCallback	interfaceListChangedCallback;
	HostDescriptionChangedCallback	hostDescriptionChangedCallback;
	SocketRef						unicastSock4;
	HANDLE							unicastSock4ReadEvent;
	mDNSAddr						unicastSock4DestAddr;
#if( !defined( _WIN32_WCE ) )
	LPFN_WSARECVMSG					unicastSock4RecvMsgPtr;
#endif
	SocketRef						unicastSock6;
	HANDLE							unicastSock6ReadEvent;
	mDNSAddr						unicastSock6DestAddr;
#if( !defined( _WIN32_WCE ) )
	LPFN_WSARECVMSG					unicastSock6RecvMsgPtr;
#endif
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
	
	struct
	{
		uint32_t		index;
	
	}	ifa_extra;
};


//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	GetWindowsVersionString

	@abstract	Stores Windows version information in the string passed in (inBuffer)
*/

OSStatus	GetWindowsVersionString( char *inBuffer, size_t inBufferSize );


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


#ifdef	__cplusplus
	}
#endif

#endif	// __MDNS_WIN32__
