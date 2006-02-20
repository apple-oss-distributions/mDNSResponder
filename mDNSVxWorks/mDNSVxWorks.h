/*
 * Copyright (c) 2002-2005 Apple Computer, Inc. All rights reserved.
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

$Log: mDNSVxWorks.h,v $
Revision 1.4  2005/05/30 07:36:38  bradley
New implementation of the mDNS platform plugin for VxWorks 5.5 or later with IPv6 support.

*/

#ifndef	__MDNS_VXWORKS_H__
#define	__MDNS_VXWORKS_H__

#include	"vxWorks.h"
#include	"config.h"

#include	"semLib.h"

#include	"CommonServices.h"
#include	"DebugServices.h"

#ifdef	__cplusplus
	extern "C" {
#endif

// Forward Declarations

typedef struct	NetworkInterfaceInfoVxWorks		NetworkInterfaceInfoVxWorks;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		SocketSet

	@abstract	Data for IPv4 and IPv6 sockets.
*/

typedef struct	SocketSet	SocketSet;
struct	SocketSet
{
	NetworkInterfaceInfoVxWorks *		info;
	SocketRef							sockV4;
	SocketRef							sockV6;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		NetworkInterfaceInfoVxWorks

	@abstract	Interface info for VxWorks.
*/

struct	NetworkInterfaceInfoVxWorks
{
	NetworkInterfaceInfo				ifinfo;		// MUST be the first element in this structure.
	NetworkInterfaceInfoVxWorks *		next;
	mDNSu32								exists;		// 1 = currently exists in getifaddrs list; 0 = doesn't.
													// 2 = exists, but McastTxRx state changed.
	mDNSs32								lastSeen;	// If exists == 0, last time this interface appeared in getifaddrs list.
	mDNSu32								scopeID;	// Interface index / IPv6 scope ID.
	int									family;		// Socket address family of the primary socket.
	mDNSBool							multicast;
	SocketSet							ss;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		mDNS_PlatformSupport_struct

	@abstract	Data for mDNS platform plugin.
*/

struct	mDNS_PlatformSupport_struct
{
	NetworkInterfaceInfoVxWorks *		interfaceList;
	SocketSet							unicastSS;
	domainlabel							userNiceLabel;
	domainlabel							userHostLabel;
	
	SEM_ID								lock;
	SEM_ID								initEvent;
	mStatus								initErr;
	SEM_ID								quitEvent;	
	int									commandPipe;
	int									taskID;
	mDNSBool							quit;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	mDNSReconfigure
	
	@abstract	Tell mDNS that the configuration has changed. Call when IP address changes, link goes up after being down, etc.
	
	@discussion
	
	VxWorks does not provide a generic mechanism for getting notified when network interfaces change so this routines
	provides a way for BSP-specific code to signal mDNS that something has changed and it should re-build its interfaces.
*/

void	mDNSReconfigure( void );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	mDNSDeferIPv4
	
	@abstract	Tells mDNS whether to defer advertising of IPv4 interfaces.
	
	@discussion
	
	To workaround problems with clients getting a link-local IPv4 address before a DHCP address is acquired, this allows
	external code to defer advertising of IPv4 addresses until a DHCP lease has been acquired (or it times out).
*/

void	mDNSDeferIPv4( mDNSBool inDefer );

#ifdef	__cplusplus
	}
#endif

#endif	// __MDNS_VXWORKS_H__
