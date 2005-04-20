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

*/


#ifndef __dDNS_h
#define __dDNS_h

#include "mDNSEmbeddedAPI.h"
#include "dns_sd.h"

#if 0
#pragma mark - DynDNS structures
#endif

typedef struct IPAddrListElem
	{
	mDNSAddr addr;
	struct IPAddrListElem *next;
	} IPAddrListElem;

extern void dDNS_FreeIPAddrList( IPAddrListElem * list );


// ***************************************************************************
#if 0
#pragma mark - Main Client Functions
#endif

extern mStatus dDNS_Setup( mDNS *const m );
extern mStatus dDNS_InitDNSConfig( mDNS *const m );
extern mStatus dDNS_SetupAddr( mDNSAddr *ip, const struct sockaddr * const sa );


// ***************************************************************************
#if 0
#pragma mark - PlatformSupport interface
#endif

// This section defines the interface to the DynDNS Platform Support layer.

extern void					dDNSPlatformGetConfig(domainname *const fqdn, domainname *const regDomain, DNameListElem ** browseDomains);
extern void					dDNSPlatformSetNameStatus(domainname *const dname, mStatus status);
extern void					dDNSPlatformSetSecretForDomain( mDNS *m, const domainname *domain );
extern DNameListElem	*	dDNSPlatformGetSearchDomainList( void );
extern DNameListElem	*	dDNSPlatformGetReverseMapSearchDomainList( void );
extern IPAddrListElem	*	dDNSPlatformGetDNSServers( void );
extern DNameListElem	*	dDNSPlatformGetDomainName( void );
extern mStatus				dDNSPlatformRegisterSplitDNS( mDNS *m );
extern mStatus				dDNSPlatformGetPrimaryInterface( mDNS * m, mDNSAddr * primary, mDNSAddr * router );
extern void					dDNSPlatformDefaultBrowseDomainChanged( const domainname *d, mDNSBool add );
extern void					dDNSPlatformDefaultRegDomainChanged(const domainname *d, mDNSBool add);

#endif

