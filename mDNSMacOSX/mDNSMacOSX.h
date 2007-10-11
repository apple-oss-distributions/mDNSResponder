/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

    Change History (most recent first):

$Log: mDNSMacOSX.h,v $
Revision 1.72  2007/08/01 16:09:14  cheshire
Removed unused NATTraversalInfo substructure from AuthRecord; reduced structure sizecheck values accordingly

Revision 1.71  2007/07/27 23:57:23  cheshire
Added compile-time structure size checks

Revision 1.70  2007/07/11 02:55:50  cheshire
<rdar://problem/5303807> Register IPv6-only hostname and don't create port mappings for AutoTunnel services
Remove unused DefaultRegDomainChanged/DefaultBrowseDomainChanged

Revision 1.69  2007/05/08 00:56:17  cheshire
<rdar://problem/4118503> Share single socket instead of creating separate socket for each active interface

Revision 1.68  2007/04/24 00:10:15  cheshire
Increase WatchDogReportingThreshold to 250ms for customer builds

Revision 1.67  2007/04/21 21:47:47  cheshire
<rdar://problem/4376383> Daemon: Add watchdog timer

Revision 1.66  2007/04/07 01:01:48  cheshire
<rdar://problem/5095167> mDNSResponder periodically blocks in SSLRead

Revision 1.65  2007/03/07 02:50:50  cheshire
<rdar://problem/4574528> Name conflict dialog doesn't appear if Bonjour is persistantly unable to find an available hostname

Revision 1.64  2007/03/06 23:29:50  cheshire
<rdar://problem/4331696> Need to call IONotificationPortDestroy on shutdown

Revision 1.63  2007/02/07 19:32:00  cheshire
<rdar://problem/4980353> All mDNSResponder components should contain version strings in SCCS-compatible format

Revision 1.62  2007/01/05 08:30:49  cheshire
Trim excessive "$Log" checkin history from before 2006
(checkin history still available via "cvs log ..." of course)

Revision 1.61  2006/08/14 23:24:40  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.60  2006/07/27 03:24:35  cheshire
<rdar://problem/4049048> Convert mDNSResponder to use kqueue
Further refinement: Declare KQueueEntry parameter "const"

Revision 1.59  2006/07/27 02:59:25  cheshire
<rdar://problem/4049048> Convert mDNSResponder to use kqueue
Further refinements: CFRunLoop thread needs to explicitly wake the kqueue thread
after releasing BigMutex, in case actions it took have resulted in new work for the
kqueue thread (e.g. NetworkChanged events may result in the kqueue thread having to
add new active interfaces to its list, and consequently schedule queries to be sent).

Revision 1.58  2006/07/22 06:08:29  cheshire
<rdar://problem/4049048> Convert mDNSResponder to use kqueue
Further changes

Revision 1.57  2006/07/22 03:43:26  cheshire
<rdar://problem/4049048> Convert mDNSResponder to use kqueue

Revision 1.56  2006/07/05 23:37:26  cheshire
Remove unused LegacyNATInit/LegacyNATDestroy declarations

Revision 1.55  2006/06/29 05:33:30  cheshire
<rdar://problem/4607043> mDNSResponder conditional compilation options

Revision 1.54  2006/03/19 03:27:49  cheshire
<rdar://problem/4118624> Suppress "interface flapping" logic for loopback

Revision 1.53  2006/03/19 02:00:09  cheshire
<rdar://problem/4073825> Improve logic for delaying packets after repeated interface transitions

Revision 1.52  2006/01/05 21:41:49  cheshire
<rdar://problem/4108164> Reword "mach_absolute_time went backwards" dialog

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
#include "mDNSEmbeddedAPI.h"  // for domain name structure

typedef struct NetworkInterfaceInfoOSX_struct NetworkInterfaceInfoOSX;

typedef void (*KQueueEventCallback)(int fd, short filter, void *context);
typedef struct
	{
	KQueueEventCallback	 KQcallback;
	void                *KQcontext;
	const char const    *KQtask;		// For debugging messages
	} KQueueEntry;

typedef struct
	{
	mDNS                    *m;
	int                      sktv4;
	KQueueEntry				 kqsv4;
	int                      sktv6;
	KQueueEntry	             kqsv6;
	} KQSocketSet;

struct NetworkInterfaceInfoOSX_struct
	{
	NetworkInterfaceInfo     ifinfo;			// MUST be the first element in this structure
	NetworkInterfaceInfoOSX *next;
	mDNSu32                  Exists;			// 1 = currently exists in getifaddrs list; 0 = doesn't
												// 2 = exists, but McastTxRx state changed
	mDNSs32                  AppearanceTime;	// Time this interface appeared most recently in getifaddrs list
												// i.e. the first time an interface is seen, AppearanceTime is set.
												// If an interface goes away temporarily and then comes back then
												// AppearanceTime is updated to the time of the most recent appearance.
	mDNSs32                  LastSeen;			// If Exists==0, last time this interface appeared in getifaddrs list
	mDNSBool                 Flashing;			// Set if interface appeared for less than 60 seconds and then vanished
	mDNSBool                 Occulting;			// Set if interface vanished for less than 60 seconds and then came back
	char                    *ifa_name;			// Memory for this is allocated using malloc
	unsigned int             ifa_flags;
	struct in_addr           ifa_v4addr;
	mDNSu32                  scope_id;			// interface index / IPv6 scope ID
	mDNSEthAddr              BSSID;				// BSSID of 802.11 base station, if applicable
	u_short                  sa_family;
	};

struct mDNS_PlatformSupport_struct
	{
	NetworkInterfaceInfoOSX *InterfaceList;
	KQSocketSet              permanentsockets;
	domainlabel              userhostlabel;		// The hostlabel as it was set in System Preferences the last time we looked
	domainlabel              usernicelabel;		// The nicelabel as it was set in System Preferences the last time we looked
	mDNSs32                  NotifyUser;
	mDNSs32                  HostNameConflict;	// Time we experienced conflict on our link-local host name
	mDNSs32                  NetworkChanged;
	SCDynamicStoreRef        Store;
	CFRunLoopSourceRef       StoreRLS;
	IONotificationPortRef    PowerPortRef;
	io_connect_t             PowerConnection;
	io_object_t              PowerNotifier;
	pthread_mutex_t          BigMutex;
	mDNSs32                  BigMutexStartTime;
	int						 WakeKQueueLoopFD;
	};

extern int KQueueFD;

extern void NotifyOfElusiveBug(const char *title, const char *msg);	// Both strings are UTF-8 text
extern void mDNSMacOSXNetworkChanged(mDNS *const m);
extern int mDNSMacOSXSystemBuildNumber(char *HINFO_SWstring);

extern int KQueueSet(int fd, u_short flags, short filter, const KQueueEntry *const entryRef);

// When events are processed on the non-kqueue thread (i.e. CFRunLoop notifications like Sleep/Wake,
// Interface changes, Keychain changes, etc.) they must use KQueueLock/KQueueUnlock to lock out the kqueue thread
extern void KQueueLock(mDNS *const m);
extern void KQueueUnlock(mDNS *const m, const char const *task);

// If any event takes more than WatchDogReportingThreshold milliseconds to be processed, we log a warning message
// General event categories are:
//  o Mach client request initiated / terminated
//  o UDS client request
//  o Handling UDP packets received from the network
//  o Environmental change events:
//    - network interface changes
//    - sleep/wake
//    - keychain changes
//  o Name conflict dialog dismissal
//  o Reception of Unix signal (e.g. SIGINFO)
//  o Idle task processing
// If we find that we're getting warnings for any of these categories, and it's not evident
// what's causing the problem, we may need to subdivide some categories into finer-grained
// sub-categories (e.g. "Idle task processing" covers a pretty broad range of sub-tasks).

#if LogAllOperations
#define WatchDogReportingThreshold 50
#else
#define WatchDogReportingThreshold 250
#endif

struct CompileTimeAssertionChecks_mDNSMacOSX
	{
	// Check our structures are reasonable sizes. Including overly-large buffers, or embedding
	// other overly-large structures instead of having a pointer to them, can inadvertently
	// cause structure sizes (and therefore memory usage) to balloon unreasonably.
	char sizecheck_NetworkInterfaceInfoOSX[(sizeof(NetworkInterfaceInfoOSX) <=  4100) ? 1 : -1];
	char sizecheck_mDNS_PlatformSupport   [(sizeof(mDNS_PlatformSupport)    <=   260) ? 1 : -1];
	};

#ifdef  __cplusplus
    }
#endif

#endif
