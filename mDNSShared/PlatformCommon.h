/* -*- Mode: C; tab-width: 4 -*-
 *
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

$Log: PlatformCommon.h,v $
Revision 1.3  2005/01/19 19:19:21  ksekar
<rdar://problem/3960191> Need a way to turn off domain discovery

Revision 1.2  2004/12/01 03:30:29  cheshire
<rdar://problem/3889346> Add Unicast DNS support to mDNSPosix

Revision 1.1  2004/12/01 01:51:35  cheshire
Move ReadDDNSSettingsFromConfFile() from mDNSMacOSX.c to PlatformCommon.c

 */

extern void FindDefaultRouteIP(mDNSAddr *a);
extern void ReadDDNSSettingsFromConfFile(mDNS *const m, const char *const filename, domainname *const hostname, domainname *const domain, mDNSBool *DomainDiscoveryDisabled);
