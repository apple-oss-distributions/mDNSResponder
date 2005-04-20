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

$Log: mDNSMacOS9.h,v $
Revision 1.10  2004/03/12 21:30:26  cheshire
Build a System-Context Shared Library from mDNSCore, for the benefit of developers
like Muse Research who want to be able to use mDNS/DNS-SD from GPL-licensed code.

Revision 1.9  2004/02/09 23:25:35  cheshire
Need to set TTL 255 to interoperate with peers that check TTL (oops!)

Revision 1.8  2003/08/12 19:56:24  cheshire
Update to APSL 2.0

 */

// ***************************************************************************
// Classic Mac (Open Transport) structures

//#include <Files.h>	// OpenTransport.h requires this
#include <OpenTransport.h>
#include <OpenTptInternet.h>
#include <OpenTptClient.h>

typedef enum
	{
	mOT_Closed = 0,		// We got kOTProviderIsClosed message
	mOT_Reset,			// We got xOTStackWasLoaded message
	mOT_Start,			// We've called OTAsyncOpenEndpoint
	mOT_ReusePort,		// Have just done kReusePortOption
	mOT_RcvDestAddr,	// Have just done kRcvDestAddrOption
	mOT_SetUTTL,		// Have just done kSetUnicastTTLOption
	mOT_SetMTTL,		// Have just done kSetMulticastTTLOption
	mOT_LLScope,		// Have just done kAddLinkMulticastOption
//	mOT_AdminScope,		// Have just done kAddAdminMulticastOption
	mOT_Bind,			// We've just called OTBind
	mOT_Ready			// Got T_BINDCOMPLETE; Interface is registered and active
	} mOT_State;

typedef struct { TOptionHeader h; mDNSv4Addr multicastGroupAddress; mDNSv4Addr InterfaceAddress; } TIPAddMulticastOption;
typedef struct { TOptionHeader h; UInt8 val; } TSetByteOption;
typedef struct { TOptionHeader h; UInt32 flag; } TSetBooleanOption;

// TOptionBlock is a union of various types.
// What they all have in common is that they all start with a TOptionHeader.
typedef union  { TOptionHeader h; TIPAddMulticastOption m; TSetByteOption i; TSetBooleanOption b; } TOptionBlock;

struct mDNS_PlatformSupport_struct
	{
	EndpointRef ep;
	UInt32 mOTstate;				// mOT_State enum
	TOptionBlock optBlock;
	TOptMgmt optReq;
	long OTTimerTask;
	UInt32 nesting;
	NetworkInterfaceInfo interface;
	};
