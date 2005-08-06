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

	Contains:	mDNS platform plugin for VxWorks.

	Copyright:  Copyright (C) 2002-2003 Apple Computer, Inc., All Rights Reserved.

	Change History (most recent first):

$Log: mDNSVxWorksIPv4Only.h,v $
Revision 1.3  2004/09/17 01:08:57  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.2  2003/08/12 19:56:27  cheshire
Update to APSL 2.0

Revision 1.1  2003/08/02 10:06:49  bradley
mDNS platform plugin for VxWorks.

*/

#ifndef	__MDNS_VXWORKS__
#define	__MDNS_VXWORKS__

#include	"vxWorks.h"
#include	"semLib.h"

#include	"mDNSEmbeddedAPI.h"

#ifdef	__cplusplus
	extern "C" {
#endif

// Forward Declarations

typedef struct	MDNSInterfaceItem	MDNSInterfaceItem;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		mDNS_PlatformSupport_struct

	@abstract	Structure containing platform-specific data.
*/

struct	mDNS_PlatformSupport_struct
{
	SEM_ID					lockID;
	SEM_ID					readyEvent;
	mStatus					taskInitErr;
	SEM_ID					quitEvent;
	MDNSInterfaceItem *		interfaceList;
	int						commandPipe;
	int						task;
	mDNSBool				quit;
	long					configID;
	int						rescheduled;
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

#endif	// __MDNS_VXWORKS__
