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

$Log: mDNSMacOSX.h,v $
Revision 1.21  2003/08/19 22:20:00  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured
More minor refinements

Revision 1.20  2003/08/19 05:39:43  cheshire
<rdar://problem/3380097> SIGINFO dump should include resolves started by DNSServiceQueryRecord

Revision 1.19  2003/08/19 05:36:45  cheshire
Add missing "extern" directives

Revision 1.18  2003/08/19 03:04:43  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured

Revision 1.17  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

Revision 1.16  2003/08/08 18:36:04  cheshire
<rdar://problem/3344154> Only need to revalidate on interface removal on platforms that have the PhantomInterfaces bug

Revision 1.15  2003/08/05 00:32:28  cheshire
<rdar://problem/3326712> Time to turn off MACOSX_MDNS_MALLOC_DEBUGGING

Revision 1.14  2003/07/20 03:38:51  ksekar
Bug #: 3320722
Completed support for Unix-domain socket based API.

Revision 1.13  2003/07/18 00:30:00  cheshire
<rdar://problem/3268878> Remove mDNSResponder version from packet header and use HINFO record instead

Revision 1.12  2003/07/12 03:15:20  cheshire
<rdar://problem/3324848> After SCDynamicStore notification, mDNSResponder updates
m->hostlabel even if user hasn't actually actually changed their dot-local hostname

Revision 1.11  2003/07/02 21:19:51  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.10  2003/06/25 23:42:19  ksekar
Bug #: <rdar://problem/3249292>: Feature: New Rendezvous APIs (#7875)
Reviewed by: Stuart Cheshire
Added files necessary to implement Unix domain sockets based enhanced
Rendezvous APIs, and integrated with existing Mach-port based daemon.

Revision 1.9  2003/06/10 01:14:11  cheshire
<rdar://problem/3286004> New APIs require a mDNSPlatformInterfaceIDfromInterfaceIndex() call

Revision 1.8  2003/05/14 07:08:37  cheshire
<rdar://problem/3159272> mDNSResponder should be smarter about reconfigurations
Previously, when there was any network configuration change, mDNSResponder
would tear down the entire list of active interfaces and start again.
That was very disruptive, and caused the entire cache to be flushed,
and caused lots of extra network traffic. Now it only removes interfaces
that have really gone, and only adds new ones that weren't there before.

Revision 1.7  2003/04/26 02:39:24  cheshire
Remove extern void LogMsg(const char *format, ...);

Revision 1.6  2003/03/05 21:59:56  cheshire
Bug #: 3189097 Additional debugging code in mDNSResponder

Revision 1.5  2003/03/05 01:50:38  cheshire
Bug #: 3189097 Additional debugging code in mDNSResponder

Revision 1.4  2003/02/21 01:54:10  cheshire
Bug #: 3099194 mDNSResponder needs performance improvements
Switched to using new "mDNS_Execute" model (see "Implementer Notes.txt")

Revision 1.3  2002/09/21 20:44:51  zarzycki
Added APSL info

Revision 1.2  2002/09/19 04:20:44  cheshire
Remove high-ascii characters that confuse some systems

Revision 1.1  2002/09/17 01:04:09  cheshire
Defines mDNS_PlatformSupport_struct for OS X

*/

#ifndef __mDNSOSX_h
#define __mDNSOSX_h

#ifdef  __cplusplus
    extern "C" {
#endif

#include <SystemConfiguration/SystemConfiguration.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct NetworkInterfaceInfoOSX_struct NetworkInterfaceInfoOSX;
struct NetworkInterfaceInfoOSX_struct
	{
	NetworkInterfaceInfo     ifinfo;			// MUST be the first element in this structure
	NetworkInterfaceInfoOSX *next;
	mDNS                    *m;
	mDNSu32                  CurrentlyActive;	// 0 not active; 1 active; 2 active but TxRx state changed
	char                    *ifa_name;			// Memory for this is allocated using malloc
	mDNSu32                  scope_id;			// interface index / IPv6 scope ID
	u_short                  sa_family;
#if mDNS_AllowPort53
	int                      skt53;
	CFSocketRef              cfs53;
#endif
	int                      sktv4;
	CFSocketRef              cfsv4;
	int                      sktv6;
	CFSocketRef	             cfsv6;
	};

struct mDNS_PlatformSupport_struct
    {
    NetworkInterfaceInfoOSX *InterfaceList;
    domainlabel              userhostlabel;
    SCDynamicStoreRef        Store;
    CFRunLoopSourceRef       StoreRLS;
    io_connect_t             PowerConnection;
    io_object_t              PowerNotifier;
    CFRunLoopSourceRef       PowerRLS;
    };

extern mDNSInterfaceID mDNSPlatformInterfaceIDfromInterfaceIndex(const mDNS *const m, mDNSu32 index);
extern mDNSu32 mDNSPlatformInterfaceIndexfromInterfaceID(const mDNS *const m, mDNSInterfaceID id);
extern mDNSBool mDNSMacOSXSystemBuildNumber(char *HINFO_SWstring);

extern const char mDNSResponderVersionString[];

// Set this symbol to 1 to do extra debug checks on malloc() and free()
// Set this symbol to 2 to write a log message for every malloc() and free()
#define MACOSX_MDNS_MALLOC_DEBUGGING 0

#if MACOSX_MDNS_MALLOC_DEBUGGING >= 1
extern void *mallocL(char *msg, unsigned int size);
extern void freeL(char *msg, void *x);
#else
#define mallocL(X,Y) malloc(Y)
#define freeL(X,Y) free(Y)
#endif

#if MACOSX_MDNS_MALLOC_DEBUGGING >= 2
#define LogMalloc LogMsg
#else
#define	LogMalloc(ARGS...) ((void)0)
#endif

#define LogAllOperations 0

#if LogAllOperations
#define LogOperation LogMsg
#else
#define	LogOperation(ARGS...) ((void)0)
#endif

#ifdef  __cplusplus
    }
#endif

// UDS Server <-> daemon crossover routines/globals
extern mDNS mDNSStorage;            
extern int udsserver_init(void);
extern int udsserver_add_rl_source(void);
extern mDNSs32 udsserver_idle(mDNSs32 nextevent);  // takes the next scheduled event time, does idle work,
                                                   // and returns the updated nextevent time
extern void udsserver_info(void);
extern void udsserver_handle_configchange(void);
extern int udsserver_exit(void);

#endif
