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

$Log: mDNSPrefix.h,v $
Revision 1.3  2004/06/11 00:03:28  cheshire
Add code for testing avail/busy subtypes

Revision 1.2  2004/05/21 01:57:08  cheshire
Add macros for malloc() and free() so that dnssd_clientlib.c can use them

Revision 1.1  2004/03/12 21:30:26  cheshire
Build a System-Context Shared Library from mDNSCore, for the benefit of developers
like Muse Research who want to be able to use mDNS/DNS-SD from GPL-licensed code.

 */

// Global definitions that apply to all source files
//
// Symbols that are defined here are available within all source files.
// This is the equivalent of using using "-d SYMBOL=VALUE" in a Makefile
// in command-line build environments.

// For normal DeferredTask time execution, set MDNS_ONLYSYSTEMTASK to 0
// For easier debugging, set MDNS_ONLYSYSTEMTASK to 1, and OT Notifier executions
// will be deferred until SystemTask time. (This option is available only for building
// the standalone application samples that have their own event loop -- don't try
// to build the System Extension with MDNS_ONLYSYSTEMTASK set because it won't work.)

#if   __ide_target("Standalone TestResponder")           || __ide_target("Standalone TestSearcher")           || __ide_target("Standalone SubTypeTester")
#define TARGET_API_MAC_CARBON 1
#define OTCARBONAPPLICATION 1
#define MDNS_ONLYSYSTEMTASK 0
#define MDNS_DEBUGMSGS 0

#elif __ide_target("Standalone TestResponder (Debug)")   || __ide_target("Standalone TestSearcher (Debug)")
#define TARGET_API_MAC_CARBON 1
#define OTCARBONAPPLICATION 1
#define MDNS_ONLYSYSTEMTASK 1
#define MDNS_DEBUGMSGS 1

#elif __ide_target("Standalone TestResponder (Classic)") || __ide_target("Standalone TestSearcher (Classic)")
#define MDNS_ONLYSYSTEMTASK 0
#define MDNS_DEBUGMSGS 0

#elif __ide_target("CFM Library for Extensions Folder")
#define MDNS_BUILDINGSHAREDLIBRARY 2

#elif __ide_target("CFM Library for Extensions (Debug)")
#define MDNS_DEBUGMSGS 0
#define MDNS_BUILDINGSHAREDLIBRARY 1

#elif __ide_target("CFM Stub for clients to link against")
#define MDNS_BUILDINGSTUBLIBRARY 1

#else
#error Options for this target not found in prefix file
#endif

// dnssd_clientlib.c assumes malloc() and free(), so we #define them here to be the OT equivalents
#if MDNS_BUILDINGSHAREDLIBRARY || MDNS_BUILDINGSTUBLIBRARY
#define malloc(x) OTAllocMem(x)
#define free(x) OTFreeMem(x)
#endif
