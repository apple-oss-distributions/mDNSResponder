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

$Log: mDNSLibrary.c,v $
Revision 1.3  2004/12/16 20:49:35  cheshire
<rdar://problem/3324626> Cache memory management improvements

Revision 1.2  2004/09/17 01:08:50  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.1  2004/03/12 21:30:26  cheshire
Build a System-Context Shared Library from mDNSCore, for the benefit of developers
like Muse Research who want to be able to use mDNS/DNS-SD from GPL-licensed code.

 */

// Define the required CFM Shared Library entry and exit points
#include <CodeFragments.h>
#include "mDNSEmbeddedAPI.h"			// Defines the interface to the client layer above
#include "mDNSMacOS9.h"					// Defines the specific types needed to run mDNS on this platform

mDNS mDNSStorage;
static mDNS_PlatformSupport PlatformSupportStorage;
// Start off with a default cache of 16K (about 100 records)
#define RR_CACHE_SIZE ((16*1024) / sizeof(CacheRecord))
static CacheEntity rrcachestorage[RR_CACHE_SIZE];

mDNSlocal void mDNS_StatusCallback(mDNS *const m, mStatus result)
	{
	if (result == mStatus_GrowCache)
		{
		// Allocate another chunk of cache storage
		CacheEntity *storage = OTAllocMem(sizeof(CacheEntity) * RR_CACHE_SIZE);
		if (storage) mDNS_GrowCache(m, storage, RR_CACHE_SIZE);
		}
	}

extern pascal OSErr mDNS_CFMInit(const CFragInitBlock *theInitBlock);
pascal OSErr mDNS_CFMInit(const CFragInitBlock *theInitBlock)
	{
	extern pascal OSErr __initialize(const CFragInitBlock *theInitBlock);
	__initialize(theInitBlock);	// MUST do this first!
		{
		mStatus err;
		THz oldZone = GetZone();
		SetZone(SystemZone());
		LogMsg("mDNS/DNS-SD with Macsbug breaks -- do not ship this version to customers");
		err = mDNS_Init(&mDNSStorage, &PlatformSupportStorage, rrcachestorage, RR_CACHE_SIZE,
			mDNS_Init_AdvertiseLocalAddresses, mDNS_StatusCallback, mDNS_Init_NoInitCallbackContext);
		SetZone(oldZone);
		return((OSErr)err);
		}
	}
	
extern void mDNS_CFMTerm(void);
void mDNS_CFMTerm(void)
	{
	extern pascal void  __terminate(void);
	LogMsg("mDNS_CFMTerm");
	mDNS_Close(&mDNSStorage);
	__terminate();
	}
