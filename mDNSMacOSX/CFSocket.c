/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

$Log: CFSocket.c,v $
Revision 1.115  2003/09/10 00:45:55  cheshire
<rdar://problem/3412328> Don't log "sendto failed" errors during the first two minutes of startup

Revision 1.114  2003/08/27 02:55:13  cheshire
<rdar://problem/3387910>:	Bug: Don't report mDNSPlatformSendUDP sendto errno 64 (Host is down)

Revision 1.113  2003/08/19 22:20:00  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured
More minor refinements

Revision 1.112  2003/08/19 03:04:43  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured

Revision 1.111  2003/08/18 22:53:37  cheshire
<rdar://problem/3382647> mDNSResponder divide by zero in mDNSPlatformTimeNow()

Revision 1.110  2003/08/16 03:39:00  cheshire
<rdar://problem/3338440> InterfaceID -1 indicates "local only"

Revision 1.109  2003/08/15 02:19:49  cheshire
<rdar://problem/3375225> syslog messages: myCFSocketCallBack recvfrom skt 6 error -1 errno 35
Also limit number of messages to at most 100

Revision 1.108  2003/08/12 22:24:52  cheshire
<rdar://problem/3375225> syslog messages: myCFSocketCallBack recvfrom skt 6 error -1 errno 35
This message indicates a kernel bug, but still we don't want to flood syslog.
Do a sleep(1) after writing this log message, to limit the rate.

Revision 1.107  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

Revision 1.106  2003/08/12 13:48:32  cheshire
Add comment explaining clockdivisor calculation

Revision 1.105  2003/08/12 13:44:14  cheshire
<rdar://problem/3370229> mDNSResponder *VERY* unhappy if time goes backwards
Use mach_absolute_time() (which is guaranteed to always go forwards, resetting only on reboot)
instead of gettimeofday() (which can jump back if the user manually changes their time/date)

Revision 1.104  2003/08/12 13:12:07  cheshire
Textual search/replace: Indicate local functions using "mDNSlocal" instead of "static"

Revision 1.103  2003/08/08 18:36:04  cheshire
<rdar://problem/3344154> Only need to revalidate on interface removal on platforms that have the PhantomInterfaces bug

Revision 1.102  2003/08/06 00:14:52  cheshire
<rdar://problem/3330324> Need to check IP TTL on responses
Also add corresponding checks in the IPv6 code path

Revision 1.101  2003/08/05 22:20:16  cheshire
<rdar://problem/3330324> Need to check IP TTL on responses

Revision 1.100  2003/08/05 21:18:50  cheshire
<rdar://problem/3363185> mDNSResponder should ignore 6to4
Only use interfaces that are marked as multicast-capable (IFF_MULTICAST)

Revision 1.99  2003/08/05 20:13:52  cheshire
<rdar://problem/3294080> mDNSResponder using IPv6 interfaces before they are ready
Ignore interfaces with the IN6_IFF_NOTREADY flag set

Revision 1.98  2003/07/20 03:38:51  ksekar
Bug #: 3320722
Completed support for Unix-domain socket based API.

Revision 1.97  2003/07/19 03:15:16  cheshire
Add generic MemAllocate/MemFree prototypes to mDNSPlatformFunctions.h,
and add the obvious trivial implementations to each platform support layer

Revision 1.96  2003/07/18 00:30:00  cheshire
<rdar://problem/3268878> Remove mDNSResponder version from packet header and use HINFO record instead

Revision 1.95  2003/07/12 03:15:20  cheshire
<rdar://problem/3324848> After SCDynamicStore notification, mDNSResponder updates
m->hostlabel even if user hasn't actually actually changed their dot-local hostname

Revision 1.94  2003/07/03 00:51:54  cheshire
<rdar://problem/3287213> When select() and recvmgs() disagree, get more info from kernel about the socket state

Revision 1.93  2003/07/03 00:09:14  cheshire
<rdar://problem/3286004> New APIs require a mDNSPlatformInterfaceIDfromInterfaceIndex() call
Additional refinement suggested by Josh: Use info->scope_id instead of if_nametoindex(info->ifa_name);

Revision 1.92  2003/07/02 21:19:51  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.91  2003/06/24 01:53:51  cheshire
Minor update to comments

Revision 1.90  2003/06/24 01:51:47  cheshire
<rdar://problem/3303118> Oops: Double-dispose of sockets
Don't need to close sockets: CFSocketInvalidate() does that for us

Revision 1.89  2003/06/21 18:12:47  cheshire
<rdar://problem/3296061> Rendezvous cannot handle interfaces whose total name is >3 chars
One-line change: should say "IF_NAMESIZE", not sizeof(ifname)

Revision 1.88  2003/06/12 23:38:37  cheshire
<rdar://problem/3291162> mDNSResponder doesn't detect some configuration changes
Also check that scope_id matches before concluding that two interfaces are the same

Revision 1.87  2003/06/10 01:14:11  cheshire
<rdar://problem/3286004> New APIs require a mDNSPlatformInterfaceIDfromInterfaceIndex() call

Revision 1.86  2003/05/28 02:41:52  cheshire
<rdar://problem/3034346> Time to remove Mac OS 9 UDP Port 53 legacy support

Revision 1.85  2003/05/28 02:39:47  cheshire
Minor change to debugging messages

Revision 1.84  2003/05/27 22:29:40  cheshire
Remove out-dated comment

Revision 1.83  2003/05/26 03:21:29  cheshire
Tidy up address structure naming:
mDNSIPAddr         => mDNSv4Addr (for consistency with mDNSv6Addr)
mDNSAddr.addr.ipv4 => mDNSAddr.ip.v4
mDNSAddr.addr.ipv6 => mDNSAddr.ip.v6

Revision 1.82  2003/05/26 03:01:27  cheshire
<rdar://problem/3268904> sprintf/vsprintf-style functions are unsafe; use snprintf/vsnprintf instead

Revision 1.81  2003/05/24 02:06:42  cheshire
<rdar://problem/3268480> IPv6 Multicast Loopback doesn't work
Tried setting IPV6_MULTICAST_LOOP; it doesn't help.
However, it is probably wise to have the code explicitly set this socket
option anyway, in case the default changes in later versions of Unix.

Revision 1.80  2003/05/24 02:02:24  cheshire
<rdar://problem/3221880> if_indextoname consumes a lot of CPU
Fix error in myIfIndexToName; was returning prematurely

Revision 1.79  2003/05/23 23:07:44  cheshire
<rdar://problem/3268199> Must not write to stderr when running as daemon

Revision 1.78  2003/05/23 01:19:04  cheshire
<rdar://problem/3267085> mDNSResponder needs to signal type of service to AirPort
Mark packets as high-throughput/low-delay (i.e. lowest reliability) to get maximum 802.11 multicast rate

Revision 1.77  2003/05/23 01:12:05  cheshire
Minor code tidying

Revision 1.76  2003/05/22 01:26:01  cheshire
Tidy up log messages

Revision 1.75  2003/05/22 00:07:09  cheshire
<rdar://problem/3264366> myCFSocketCallBack recvfrom(5) error 1, errno 35
Extra logging to determine whether there is a bug in CFSocket

Revision 1.74  2003/05/21 20:20:12  cheshire
Fix warnings (mainly printf format string warnings, like using "%d" where
it should say "%lu", etc.) and improve error logging (use strerror()
to include textual error message as well as numeric error in log messages).

Revision 1.73  2003/05/21 17:56:29  ksekar
Bug #: <rdar://problem/3191277>:	mDNSResponder doesn't watch for IPv6 address changes

Revision 1.72  2003/05/14 18:48:41  cheshire
<rdar://problem/3159272> mDNSResponder should be smarter about reconfigurations
More minor refinements:
CFSocket.c needs to do *all* its mDNS_DeregisterInterface calls before freeing memory
mDNS_DeregisterInterface revalidates cache record when *any* representative of an interface goes away

Revision 1.71  2003/05/14 07:08:37  cheshire
<rdar://problem/3159272> mDNSResponder should be smarter about reconfigurations
Previously, when there was any network configuration change, mDNSResponder
would tear down the entire list of active interfaces and start again.
That was very disruptive, and caused the entire cache to be flushed,
and caused lots of extra network traffic. Now it only removes interfaces
that have really gone, and only adds new ones that weren't there before.

Revision 1.70  2003/05/07 18:30:24  cheshire
Fix signed/unsigned comparison warning

Revision 1.69  2003/05/06 20:14:44  cheshire
Change "tp" to "tv"

Revision 1.68  2003/05/06 00:00:49  cheshire
<rdar://problem/3248914> Rationalize naming of domainname manipulation functions

Revision 1.67  2003/04/29 00:43:44  cheshire
Fix compiler warnings

Revision 1.66  2003/04/26 02:41:58  cheshire
<rdar://problem/3241281> Change timenow from a local variable to a structure member

Revision 1.65  2003/04/26 02:34:01  cheshire
Add missing mDNSexport

Revision 1.64  2003/04/15 16:48:06  jgraessl
Bug #: 3228833
Modified code in CFSocket notifier function to read all packets on the socket
instead of reading only one packet every time the notifier was called.

Revision 1.63  2003/04/15 16:33:50  jgraessl
Bug #: 3221880
Switched to our own copy of if_indextoname to improve performance.

Revision 1.62  2003/03/28 01:55:44  cheshire
Minor improvements to debugging messages

Revision 1.61  2003/03/27 03:30:56  cheshire
<rdar://problem/3210018> Name conflicts not handled properly, resulting in memory corruption, and eventual crash
Problem was that HostNameCallback() was calling mDNS_DeregisterInterface(), which is not safe in a callback
Fixes:
1. Make mDNS_DeregisterInterface() safe to call from a callback
2. Make HostNameCallback() use mDNS_DeadvertiseInterface() instead
   (it never really needed to deregister the interface at all)

Revision 1.60  2003/03/15 04:40:38  cheshire
Change type called "mDNSOpaqueID" to the more descriptive name "mDNSInterfaceID"

Revision 1.59  2003/03/11 01:23:26  cheshire
Bug #: 3194246 mDNSResponder socket problems

Revision 1.58  2003/03/06 01:43:04  cheshire
Bug #: 3189097 Additional debugging code in mDNSResponder
Improve "LIST_ALL_INTERFACES" output

Revision 1.57  2003/03/05 22:36:27  cheshire
Bug #: 3186338 Loopback doesn't work with mDNSResponder-27
Temporary workaround: Skip loopback interface *only* if we found at least one v4 interface to use

Revision 1.56  2003/03/05 01:50:38  cheshire
Bug #: 3189097 Additional debugging code in mDNSResponder

Revision 1.55  2003/02/21 01:54:09  cheshire
Bug #: 3099194 mDNSResponder needs performance improvements
Switched to using new "mDNS_Execute" model (see "Implementer Notes.txt")

Revision 1.54  2003/02/20 06:48:35  cheshire
Bug #: 3169535 Xserve RAID needs to do interface-specific registrations
Reviewed by: Josh Graessley, Bob Bradley

Revision 1.53  2003/01/29 02:21:23  cheshire
Return mStatus_Invalid if can't send packet because socket not available

Revision 1.52  2003/01/28 19:39:43  jgraessl
Enabling AAAA over IPv4 support.

Revision 1.51  2003/01/28 05:11:23  cheshire
Fixed backwards comparison in SearchForInterfaceByName

Revision 1.50  2003/01/13 23:49:44  jgraessl
Merged changes for the following fixes in to top of tree:
3086540  computer name changes not handled properly
3124348  service name changes are not properly handled
3124352  announcements sent in pairs, failing chattiness test

Revision 1.49  2002/12/23 22:13:30  jgraessl
Reviewed by: Stuart Cheshire
Initial IPv6 support for mDNSResponder.

Revision 1.48  2002/11/22 01:37:52  cheshire
Bug #: 3108426 mDNSResponder is monitoring ServiceEntities instead of InterfaceEntities

Revision 1.47  2002/09/21 20:44:51  zarzycki
Added APSL info

Revision 1.46  2002/09/19 21:25:35  cheshire
mDNS_snprintf() doesn't need to be in a separate file

Revision 1.45  2002/09/17 01:45:13  cheshire
Add LIST_ALL_INTERFACES symbol for debugging

Revision 1.44  2002/09/17 01:36:23  cheshire
Move Puma support to CFSocketPuma.c

Revision 1.43  2002/09/17 01:05:28  cheshire
Change mDNS_AdvertiseLocalAddresses to be an Init parameter instead of a global

Revision 1.42  2002/09/16 23:13:50  cheshire
Minor code tidying

 */

// ***************************************************************************
// mDNS-CFSocket.c:
// Supporting routines to run mDNS on a CFRunLoop platform
// ***************************************************************************

// Open Transport 2.7.x on Mac OS 9 used to send Multicast DNS queries to UDP port 53,
// before the Multicast DNS port was changed to 5353. For this reason, the mDNSResponder
// in earlier versions of Mac OS X 10.2 Jaguar used to set mDNS_AllowPort53 to 1 to allow
// it to also listen and answer queries on UDP port 53. Now that Transport 2.8 (included in
// the Classic subsystem of Mac OS X 10.2 Jaguar) has been corrected to issue Multicast DNS
// queries on UDP port 5353, this backwards-compatibility legacy support is no longer needed.
#define mDNS_AllowPort53 0

// For debugging, set LIST_ALL_INTERFACES to 1 to display all found interfaces,
// including ones that mDNSResponder chooses not to use.
#define LIST_ALL_INTERFACES 0

// For enabling AAAA records over IPv4. Setting this to 0 sends only
// A records over IPv4 and AAAA over IPv6. Setting this to 1 sends both
// AAAA and A records over both IPv4 and IPv6.
#define AAAA_OVER_V4	1

#include "mDNSClientAPI.h"          // Defines the interface provided to the client layer above
#include "mDNSPlatformFunctions.h"	// Defines the interface to the supporting layer below
#include "mDNSMacOSX.h"				// Defines the specific types needed to run mDNS on this platform

#include <stdio.h>
#include <unistd.h>					// For select() and close()
#include <stdarg.h>					// For va_list support
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <netinet/in.h>				// For IP_RECVTTL
#ifndef IP_RECVTTL
#define IP_RECVTTL 24	/* bool; receive reception TTL w/dgram */
#endif

#include <netinet/in_systm.h>		// For n_long, required by <netinet/ip.h> below
#include <netinet/ip.h>				// For IPTOS_LOWDELAY etc.
#include <netinet6/in6_var.h>		// For IN6_IFF_NOTREADY etc.

// Code contributed by Dave Heller:
// Define RUN_ON_PUMA_WITHOUT_IFADDRS to compile code that will
// work on Mac OS X 10.1, which does not have the getifaddrs call.
#define RUN_ON_PUMA_WITHOUT_IFADDRS 0
#if RUN_ON_PUMA_WITHOUT_IFADDRS
#include "CFSocketPuma.c"
#else
#include <ifaddrs.h>
#endif

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <mach/mach_time.h>

// ***************************************************************************
// Globals

static mDNSu32 clockdivisor = 0;

// ***************************************************************************
// Macros

#define mDNSSameIPv4Address(A,B) ((A).NotAnInteger == (B).NotAnInteger)
#define mDNSSameIPv6Address(A,B) ((A).l[0] == (B).l[0] && (A).l[1] == (B).l[1] && (A).l[2] == (B).l[2] && (A).l[3] == (B).l[3])

#define mDNSAddressIsAllDNSLinkGroup(X) (                                                     \
	((X)->type == mDNSAddrType_IPv4 && mDNSSameIPv4Address((X)->ip.v4, AllDNSLinkGroup  )) || \
	((X)->type == mDNSAddrType_IPv6 && mDNSSameIPv6Address((X)->ip.v6, AllDNSLinkGroupv6))    )

// ***************************************************************************
// Functions

// Note, this uses mDNS_vsnprintf instead of standard "vsnprintf", because mDNS_vsnprintf knows
// how to print special data types like IP addresses and length-prefixed domain names
#if MDNS_DEBUGMSGS
mDNSexport void debugf_(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	fprintf(stderr,"%s\n", buffer);
	fflush(stderr);
	}
#endif

#if MDNS_DEBUGMSGS > 1
mDNSexport void verbosedebugf_(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	fprintf(stderr,"%s\n", buffer);
	fflush(stderr);
	}
#endif

mDNSexport void LogMsg(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	
	extern int debug_mode;
	if (debug_mode)		// In debug_mode we write to stderr
		{
		fprintf(stderr,"%s\n", buffer);
		fflush(stderr);
		}
	else				// else, in production mode, we write to syslog
		{
		openlog("mDNSResponder", LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "%s", buffer);
		closelog();
		}
	}

mDNSlocal struct ifaddrs* myGetIfAddrs(int refresh)
	{
	static struct ifaddrs *ifa = NULL;
	
	if (refresh && ifa)
		{
		freeifaddrs(ifa);
		ifa = NULL;
		}
	
	if (ifa == NULL) getifaddrs(&ifa);
	
	return ifa;
	}

mDNSlocal int myIfIndexToName(u_short index, char* name)
	{
	struct ifaddrs *ifa;
	for (ifa = myGetIfAddrs(0); ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_LINK)
			if (((struct sockaddr_dl*)ifa->ifa_addr)->sdl_index == index)
				{ strncpy(name, ifa->ifa_name, IF_NAMESIZE); return 0; }
	return -1;
	}

mDNSexport mDNSInterfaceID mDNSPlatformInterfaceIDfromInterfaceIndex(const mDNS *const m, mDNSu32 index)
	{
	NetworkInterfaceInfoOSX *i;
	if (index == (uint32_t)~0) return((mDNSInterfaceID)~0);
	if (index)
		for (i = m->p->InterfaceList; i; i = i->next)
			if (i->scope_id == index)
				return(i->ifinfo.InterfaceID);
	return(mDNSNULL);
	}
	
mDNSexport mDNSu32 mDNSPlatformInterfaceIndexfromInterfaceID(const mDNS *const m, mDNSInterfaceID id)
	{
	NetworkInterfaceInfoOSX *i;
	if (id == (mDNSInterfaceID)~0) return((mDNSu32)~0);
	if (id)
		for (i = m->p->InterfaceList; i; i = i->next)
			if (i->ifinfo.InterfaceID == id)
				return i->scope_id;
	return 0;
	}

mDNSexport mStatus mDNSPlatformSendUDP(const mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
	mDNSInterfaceID InterfaceID, mDNSIPPort srcPort, const mDNSAddr *dst, mDNSIPPort dstPort)
	{
	#pragma unused(m)
	NetworkInterfaceInfoOSX *info = (NetworkInterfaceInfoOSX *)InterfaceID;
	struct sockaddr_storage to;
	int s, err;

	if (!InterfaceID) { LogMsg("mDNSPlatformSendUDP ERROR! Cannot send from zero InterfaceID"); return mStatus_BadParamErr; }

	if (dst->type == mDNSAddrType_IPv4)
		{
		struct sockaddr_in*	sin_to = (struct sockaddr_in*)&to;
		sin_to->sin_len			= sizeof(*sin_to);
		sin_to->sin_family      = AF_INET;
		sin_to->sin_port        = dstPort.NotAnInteger;
		sin_to->sin_addr.s_addr = dst->ip.v4.NotAnInteger;
		}
	else if (dst->type == mDNSAddrType_IPv6)
		{
		struct sockaddr_in6* sin6_to = (struct sockaddr_in6*)&to;
		sin6_to->sin6_len		= sizeof(*sin6_to);
		sin6_to->sin6_family	= AF_INET6;
		sin6_to->sin6_port		= dstPort.NotAnInteger;
		sin6_to->sin6_flowinfo	= 0;
		sin6_to->sin6_addr		= *(struct in6_addr*)&dst->ip.v6;
		sin6_to->sin6_scope_id	= info->scope_id;
		}
	else
		{
		LogMsg("mDNSPlatformSendUDP: dst is not an IPv4 or IPv6 address!\n");
		return mStatus_BadParamErr;
		}

	if (srcPort.NotAnInteger == MulticastDNSPort.NotAnInteger)
		{
		if      (dst->type == mDNSAddrType_IPv4) s = info->sktv4;
		else if (dst->type == mDNSAddrType_IPv6) s = info->sktv6;
		else                                     s = -1;
		}
#if mDNS_AllowPort53
	else if (srcPort.NotAnInteger == UnicastDNSPort.NotAnInteger && dst->type == mDNSAddrType_IPv4)
		s = info->skt53;
#endif
	else { LogMsg("Source port %d not allowed", (mDNSu16)srcPort.b[0]<<8 | srcPort.b[1]); return(-1); }
	
	if (s >= 0)
		verbosedebugf("mDNSPlatformSendUDP: sending on InterfaceID %X %s/%d to %#a:%d skt %d",
			InterfaceID, info->ifa_name, dst->type, dst, (mDNSu16)dstPort.b[0]<<8 | dstPort.b[1], s);
	else
		verbosedebugf("mDNSPlatformSendUDP: NOT sending on InterfaceID %X %s/%d (socket of this type not available)",
			InterfaceID, info->ifa_name, dst->type, dst, (mDNSu16)dstPort.b[0]<<8 | dstPort.b[1]);

	// Note: When sending, mDNSCore may often ask us to send both a v4 multicast packet and then a v6 multicast packet
	// If we don't have the corresponding type of socket available, then return mStatus_Invalid
	if (s < 0) return(mStatus_Invalid);

	err = sendto(s, msg, (UInt8*)end - (UInt8*)msg, 0, (struct sockaddr *)&to, to.ss_len);
	if (err < 0)
		{
		// Don't report EHOSTDOWN (i.e. ARP failure) to unicast destinations
		if (errno == EHOSTDOWN && !mDNSAddressIsAllDNSLinkGroup(dst)) return(err);
		// Don't report EHOSTUNREACH in the first two minutes after boot
		// This is because mDNSResponder intentionally starts up early in the boot process (See <rdar://problem/3409090>)
		// but this means that sometimes it starts before configd has finished setting up the multicast routing entries.
		if (errno == EHOSTUNREACH && (mDNSu32)(m->timenow) < (mDNSu32)(mDNSPlatformOneSecond * 120)) return(err);
		LogMsg("mDNSPlatformSendUDP sendto failed to send packet on InterfaceID %p %s/%ld to %#a:%d skt %d error %d errno %d (%s)",
			InterfaceID, info->ifa_name, dst->type, dst, (mDNSu16)dstPort.b[0]<<8 | dstPort.b[1], s, err, errno, strerror(errno));
		return(err);
		}
	
	return(mStatus_NoError);
	}

mDNSlocal ssize_t myrecvfrom(const int s, void *const buffer, const size_t max,
	struct sockaddr *const from, size_t *const fromlen, mDNSAddr *dstaddr, char ifname[IF_NAMESIZE], mDNSu8 *ttl)
	{
	static unsigned int numLogMessages = 0;
	struct iovec databuffers = { (char *)buffer, max };
	struct msghdr   msg;
	ssize_t         n;
	struct cmsghdr *cmPtr;
	char            ancillary[1024];

	*ttl = 255;			// If kernel fails to provide TTL data (e.g. Jaguar doesn't) then assume the TTL was 255 as it should be

	// Set up the message
	msg.msg_name       = (caddr_t)from;
	msg.msg_namelen    = *fromlen;
	msg.msg_iov        = &databuffers;
	msg.msg_iovlen     = 1;
	msg.msg_control    = (caddr_t)&ancillary;
	msg.msg_controllen = sizeof(ancillary);
	msg.msg_flags      = 0;
	
	// Receive the data
	n = recvmsg(s, &msg, 0);
	if (n<0)
		{
		if (errno != EWOULDBLOCK && numLogMessages++ < 100) LogMsg("CFSocket.c: recvmsg(%d) returned error %d errno %d", s, n, errno);
		return(-1);
		}
	if (msg.msg_controllen < (int)sizeof(struct cmsghdr))
		{
		if (numLogMessages++ < 100) LogMsg("CFSocket.c: recvmsg(%d) msg.msg_controllen %d < sizeof(struct cmsghdr) %lu",
			s, msg.msg_controllen, sizeof(struct cmsghdr));
		return(-1);
		}
	if (msg.msg_flags & MSG_CTRUNC)
		{
		if (numLogMessages++ < 100) LogMsg("CFSocket.c: recvmsg(%d) msg.msg_flags & MSG_CTRUNC", s);
		return(-1);
		}
	
	*fromlen = msg.msg_namelen;
	
	// Parse each option out of the ancillary data.
	for (cmPtr = CMSG_FIRSTHDR(&msg); cmPtr; cmPtr = CMSG_NXTHDR(&msg, cmPtr))
		{
		// debugf("myrecvfrom cmsg_level %d cmsg_type %d", cmPtr->cmsg_level, cmPtr->cmsg_type);
		if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVDSTADDR)
			{
			dstaddr->type = mDNSAddrType_IPv4;
			dstaddr->ip.v4.NotAnInteger = *(u_int32_t*)CMSG_DATA(cmPtr);
			}
		if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVIF)
			{
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmPtr);
			if (sdl->sdl_nlen < IF_NAMESIZE)
				{
				mDNSPlatformMemCopy(sdl->sdl_data, ifname, sdl->sdl_nlen);
				ifname[sdl->sdl_nlen] = 0;
				// debugf("IP_RECVIF sdl_index %d, sdl_data %s len %d", sdl->sdl_index, ifname, sdl->sdl_nlen);
				}
			}
		if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVTTL)
			{
			*ttl = *(u_char*)CMSG_DATA(cmPtr);
			}
		if (cmPtr->cmsg_level == IPPROTO_IPV6 && cmPtr->cmsg_type == IPV6_PKTINFO)
			{
			struct in6_pktinfo *ip6_info = (struct in6_pktinfo*)CMSG_DATA(cmPtr);
			dstaddr->type = mDNSAddrType_IPv6;
			dstaddr->ip.v6 = *(mDNSv6Addr*)&ip6_info->ipi6_addr;
			myIfIndexToName(ip6_info->ipi6_ifindex, ifname);
			}
		if (cmPtr->cmsg_level == IPPROTO_IPV6 && cmPtr->cmsg_type == IPV6_HOPLIMIT)
			{
			*ttl = *(int*)CMSG_DATA(cmPtr);
			}
		}

	return(n);
	}

mDNSlocal void myCFSocketCallBack(CFSocketRef cfs, CFSocketCallBackType CallBackType, CFDataRef address, const void *data, void *context)
	{
	mDNSAddr senderAddr, destAddr;
	mDNSIPPort senderPort, destPort = MulticastDNSPort;
	NetworkInterfaceInfoOSX *info = (NetworkInterfaceInfoOSX *)context;
	mDNS *const m = info->m;
	DNSMessage packet;
	struct sockaddr_storage from;
	size_t fromlen = sizeof(from);
	char packetifname[IF_NAMESIZE] = "";
	int err, s1 = -1, skt = CFSocketGetNative(cfs);
	int count = 0;
	
	(void)address;	// Parameter not used
	(void)data;		// Parameter not used
	
	if (CallBackType != kCFSocketReadCallBack) LogMsg("myCFSocketCallBack: Why is CallBackType %d not kCFSocketReadCallBack?", CallBackType);

#if mDNS_AllowPort53
	if      (cfs == info->cfs53) { s1 = info->skt53; destPort = UnicastDNSPort; }
	else
#endif
	if      (cfs == info->cfsv4) s1 = info->sktv4;
	else if (cfs == info->cfsv6) s1 = info->sktv6;

	if (s1 < 0 || s1 != skt)
		{
		LogMsg("myCFSocketCallBack: s1 %d native socket %d, cfs %p", s1, skt, cfs);
#if mDNS_AllowPort53
		LogMsg("myCFSocketCallBack: cfs53 %p, skt53 %d", info->cfs53, info->skt53);
#endif
		LogMsg("myCFSocketCallBack: cfsv4 %p, sktv4 %d", info->cfsv4, info->sktv4);
		LogMsg("myCFSocketCallBack: cfsv6 %p, sktv6 %d", info->cfsv6, info->sktv6);
		}

	mDNSu8 ttl;
	while ((err = myrecvfrom(s1, &packet, sizeof(packet), (struct sockaddr *)&from, &fromlen, &destAddr, packetifname, &ttl)) >= 0)
		{
		count++;
		if (from.ss_family == AF_INET)
			{
			struct sockaddr_in *sin = (struct sockaddr_in*)&from;
			senderAddr.type = mDNSAddrType_IPv4;
			senderAddr.ip.v4.NotAnInteger = sin->sin_addr.s_addr;
			senderPort.NotAnInteger = sin->sin_port;
			}
		else if (from.ss_family == AF_INET6)
			{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&from;
			senderAddr.type = mDNSAddrType_IPv6;
			senderAddr.ip.v6 = *(mDNSv6Addr*)&sin6->sin6_addr;
			senderPort.NotAnInteger = sin6->sin6_port;
			}
		else
			{
			LogMsg("myCFSocketCallBack from is unknown address family %d", from.ss_family);
			return;
			}

		// Even though we indicated a specific interface in the IP_ADD_MEMBERSHIP call, a weirdness of the
		// sockets API means that even though this socket has only officially joined the multicast group
		// on one specific interface, the kernel will still deliver multicast packets to it no matter which
		// interface they arrive on. According to the official Unix Powers That Be, this is Not A Bug.
		// To work around this weirdness, we use the IP_RECVIF option to find the name of the interface
		// on which the packet arrived, and ignore the packet if it really arrived on some other interface.
		if (strcmp(info->ifa_name, packetifname))
			{
			verbosedebugf("myCFSocketCallBack got a packet from %#a to %#a on interface %#a/%s (Ignored -- really arrived on interface %s)",
				&senderAddr, &destAddr, &info->ifinfo.ip, info->ifa_name, packetifname);
			return;
			}
		else
			verbosedebugf("myCFSocketCallBack got a packet from %#a to %#a on interface %#a/%s",
				&senderAddr, &destAddr, &info->ifinfo.ip, info->ifa_name);
		
		if (err < (int)sizeof(DNSMessageHeader)) { debugf("myCFSocketCallBack packet length (%d) too short", err); return; }
		
		mDNSCoreReceive(m, &packet, (unsigned char*)&packet + err, &senderAddr, senderPort, &destAddr, destPort, info->ifinfo.InterfaceID, ttl);
		}

	if (err < 0 && (errno != EWOULDBLOCK || count == 0))
		{
		// Something is busted here.
		// CFSocket says there is a packet, but myrecvfrom says there is not.
		// Try calling select() to get another opinion.
		// Find out about other socket parameter that can help understand why select() says the socket is ready for read
		// All of this is racy, as data may have arrived after the call to select()
		int save_errno = errno;
		int so_error = -1;
		int so_nread = -1;
		int fionread = -1;
		int solen = sizeof(int);
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(s1, &readfds);
		struct timeval timeout;
		timeout.tv_sec  = 0;
		timeout.tv_usec = 0;
		int selectresult = select(s1+1, &readfds, NULL, NULL, &timeout);
		if (getsockopt(s1, SOL_SOCKET, SO_ERROR, &so_error, &solen) == -1)
			LogMsg("myCFSocketCallBack getsockopt(SO_ERROR) error %d", errno);
		if (getsockopt(s1, SOL_SOCKET, SO_NREAD, &so_nread, &solen) == -1)
			LogMsg("myCFSocketCallBack getsockopt(SO_NREAD) error %d", errno);
		if (ioctl(s1, FIONREAD, &fionread) == -1)
			LogMsg("myCFSocketCallBack ioctl(FIONREAD) error %d", errno);
		static unsigned int numLogMessages = 0;
		if (numLogMessages++ < 100)
			LogMsg("myCFSocketCallBack recvfrom skt %d error %d errno %d (%s) select %d (%spackets waiting) so_error %d so_nread %d fionread %d count %d",
				s1, err, save_errno, strerror(save_errno), selectresult, FD_ISSET(s1, &readfds) ? "" : "*NO* ", so_error, so_nread, fionread, count);
		sleep(1);		// After logging this error, rate limit so we don't flood syslog
		}
	}

// This gets the text of the field currently labelled "Computer Name" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedFriendlyComputerName(domainlabel *const namelabel)
	{
	CFStringEncoding encoding = kCFStringEncodingUTF8;
	CFStringRef cfs = SCDynamicStoreCopyComputerName(NULL, &encoding);
	if (cfs)
		{
		CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
		CFRelease(cfs);
		}
	}

// This gets the text of the field currently labelled "Rendezvous Name" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedRFC1034ComputerName(domainlabel *const namelabel)
	{
	CFStringRef cfs = SCDynamicStoreCopyLocalHostName(NULL);
	if (cfs)
		{
		CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
		CFRelease(cfs);
		}
	}

mDNSlocal mStatus SetupSocket(NetworkInterfaceInfoOSX *i, mDNSIPPort port, int *s, CFSocketRef *c)
	{
	const int on = 1;
	const int twofivefive = 255;

	if (*s >= 0) { LogMsg("SetupSocket ERROR: socket %d is already set", *s); return(-1); }
	if (*c) { LogMsg("SetupSocket ERROR: CFSocketRef %p is already set", *c); return(-1); }

	// Open the socket...
	int skt = socket(i->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 0) { LogMsg("socket error %d errno %d (%s)", skt, errno, strerror(errno)); return(skt); }

	// ... with a shared UDP port
	mStatus err = setsockopt(skt, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	if (err < 0) { LogMsg("setsockopt - SO_REUSEPORT error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }

	if (i->sa_family == AF_INET)
		{
		// We want to receive destination addresses
		err = setsockopt(skt, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IP_RECVDSTADDR error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// We want to receive interface identifiers
		err = setsockopt(skt, IPPROTO_IP, IP_RECVIF, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IP_RECVIF error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// We want to receive packet TTL value so we can check it
		err = setsockopt(skt, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
		// We ignore errors here -- we already know Jaguar doesn't support this, but we can get by without it
		
		// Add multicast group membership on this interface
		struct in_addr addr = { i->ifinfo.ip.ip.v4.NotAnInteger };
		struct ip_mreq imr;
		imr.imr_multiaddr.s_addr = AllDNSLinkGroup.NotAnInteger;
		imr.imr_interface        = addr;
		err = setsockopt(skt, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr));
		if (err < 0) { LogMsg("setsockopt - IP_ADD_MEMBERSHIP error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Specify outgoing interface too
		err = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr));
		if (err < 0) { LogMsg("setsockopt - IP_MULTICAST_IF error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Send unicast packets with TTL 255
		err = setsockopt(skt, IPPROTO_IP, IP_TTL, &twofivefive, sizeof(twofivefive));
		if (err < 0) { LogMsg("setsockopt - IP_TTL error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// And multicast packets with TTL 255 too
		err = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_TTL, &twofivefive, sizeof(twofivefive));
		if (err < 0) { LogMsg("setsockopt - IP_MULTICAST_TTL error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }

		// Mark packets as high-throughput/low-delay (i.e. lowest reliability) to get maximum 802.11 multicast rate
		const int ip_tosbits = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
		err = setsockopt(skt, IPPROTO_IP, IP_TOS, &ip_tosbits, sizeof(ip_tosbits));
		if (err < 0) { LogMsg("setsockopt - IP_TOS error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }

		// And start listening for packets
		struct sockaddr_in listening_sockaddr;
		listening_sockaddr.sin_family      = AF_INET;
		listening_sockaddr.sin_port        = port.NotAnInteger;
		listening_sockaddr.sin_addr.s_addr = 0; // Want to receive multicasts AND unicasts on this socket
		err = bind(skt, (struct sockaddr *) &listening_sockaddr, sizeof(listening_sockaddr));
		if (err)
			{
			// If we fail to bind to port 53 (because we're not root), that's okay, just tidy up and silently continue
			if (port.NotAnInteger == UnicastDNSPort.NotAnInteger) { close(skt); err = 0; }
			else LogMsg("bind error %ld errno %d (%s)", err, errno, strerror(errno));
			return(err);
			}
		}
	else if (i->sa_family == AF_INET6)
		{
		// We want to receive destination addresses and receive interface identifiers
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IPV6_PKTINFO error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// We want to receive packet hop count value so we can check it
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IPV6_HOPLIMIT error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// We want to receive only IPv6 packets, without this option, we may
		// get IPv4 addresses as mapped addresses.
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IPV6_V6ONLY error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Add multicast group membership on this interface
		int	interface_id = if_nametoindex(i->ifa_name);
		struct ipv6_mreq i6mr;
		i6mr.ipv6mr_interface = interface_id;
		i6mr.ipv6mr_multiaddr = *(struct in6_addr*)&AllDNSLinkGroupv6;
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_JOIN_GROUP, &i6mr, sizeof(i6mr));
		if (err < 0) { LogMsg("setsockopt - IPV6_JOIN_GROUP error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Specify outgoing interface too
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_id, sizeof(interface_id));
		if (err < 0) { LogMsg("setsockopt - IPV6_MULTICAST_IF error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Send unicast packets with TTL 255
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &twofivefive, sizeof(twofivefive));
		if (err < 0) { LogMsg("setsockopt - IPV6_UNICAST_HOPS error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// And multicast packets with TTL 255 too
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &twofivefive, sizeof(twofivefive));
		if (err < 0) { LogMsg("setsockopt - IPV6_MULTICAST_HOPS error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// Note: IPV6_TCLASS appears not to be implemented on OS X right now (or indeed on ANY version of Unix?)
		#ifdef IPV6_TCLASS
		// Mark packets as high-throughput/low-delay (i.e. lowest reliability) to get maximum 802.11 multicast rate
		int tclass = IPTOS_LOWDELAY | IPTOS_THROUGHPUT; // This may not be right (since tclass is not implemented on OS X, I can't test it)
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
		if (err < 0) { LogMsg("setsockopt - IPV6_TCLASS error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		#endif
		
		// Want to receive our own packets
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on));
		if (err < 0) { LogMsg("setsockopt - IPV6_MULTICAST_LOOP error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		
		// And start listening for packets
		struct sockaddr_in6 listening_sockaddr6;
		bzero(&listening_sockaddr6, sizeof(listening_sockaddr6));
		listening_sockaddr6.sin6_len		 = sizeof(listening_sockaddr6);
		listening_sockaddr6.sin6_family      = AF_INET6;
		listening_sockaddr6.sin6_port        = port.NotAnInteger;
		listening_sockaddr6.sin6_flowinfo	 = 0;
//		listening_sockaddr6.sin6_addr = IN6ADDR_ANY_INIT; // Want to receive multicasts AND unicasts on this socket
		listening_sockaddr6.sin6_scope_id	 = 0;
		err = bind(skt, (struct sockaddr *) &listening_sockaddr6, sizeof(listening_sockaddr6));
		if (err) { LogMsg("bind error %ld errno %d (%s)", err, errno, strerror(errno)); return(err); }
		}
	
	fcntl(skt, F_SETFL, fcntl(skt, F_GETFL, 0) | O_NONBLOCK); // set non-blocking
	*s = skt;
	CFSocketContext myCFSocketContext = { 0, i->ifinfo.InterfaceID, NULL, NULL, NULL };
	*c = CFSocketCreateWithNative(kCFAllocatorDefault, *s, kCFSocketReadCallBack, myCFSocketCallBack, &myCFSocketContext);
	CFRunLoopSourceRef rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, *c, 0);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
	CFRelease(rls);
	
	return(err);
	}

mDNSlocal mStatus SetupAddr(mDNSAddr *ip, const struct sockaddr *const sa)
	{
	if (sa->sa_family == AF_INET)
		{
		struct sockaddr_in *ifa_addr = (struct sockaddr_in *)sa;
		ip->type = mDNSAddrType_IPv4;
		ip->ip.v4.NotAnInteger = ifa_addr->sin_addr.s_addr;
		return(0);
		}
	else if (sa->sa_family == AF_INET6)
		{
		struct sockaddr_in6 *ifa_addr = (struct sockaddr_in6 *)sa;
		ip->type = mDNSAddrType_IPv6;
		if (IN6_IS_ADDR_LINKLOCAL(&ifa_addr->sin6_addr)) ifa_addr->sin6_addr.__u6_addr.__u6_addr16[1] = 0;
		ip->ip.v6 = *(mDNSv6Addr*)&ifa_addr->sin6_addr;
		return(0);
		}
	else
		{
		LogMsg("SetupAddr invalid sa_family %d", sa->sa_family);
		return(-1);
		}
	}

mDNSlocal mStatus AddInterfaceToList(mDNS *const m, struct ifaddrs *ifa)
	{
	mDNSu32 scope_id = if_nametoindex(ifa->ifa_name);
	mDNSAddr ip;
	SetupAddr(&ip, ifa->ifa_addr);
	NetworkInterfaceInfoOSX **p;
	for (p = &m->p->InterfaceList; *p; p = &(*p)->next)
		if (scope_id == (*p)->scope_id && mDNSSameAddress(&ip, &(*p)->ifinfo.ip))
			{
			debugf("AddInterfaceToList: Found existing interface %u with address %#a", scope_id, &ip);
			(*p)->CurrentlyActive = mDNStrue;
			return(0);
			}

	debugf("AddInterfaceToList: Making   new   interface %u with address %#a", scope_id, &ip);
	NetworkInterfaceInfoOSX *i = (NetworkInterfaceInfoOSX *)mallocL("NetworkInterfaceInfoOSX", sizeof(*i));
	if (!i) return(-1);
	i->ifa_name        = (char *)mallocL("NetworkInterfaceInfoOSX name", strlen(ifa->ifa_name) + 1);
	if (!i->ifa_name) { freeL("NetworkInterfaceInfoOSX", i); return(-1); }
	strcpy(i->ifa_name, ifa->ifa_name);

	i->ifinfo.InterfaceID = mDNSNULL;
	i->ifinfo.ip          = ip;
	i->ifinfo.Advertise   = m->AdvertiseLocalAddresses;
	i->ifinfo.TxAndRx     = mDNSfalse;		// For now; will be set up later at the end of UpdateInterfaceList

	i->next            = mDNSNULL;
	i->m               = m;
	i->scope_id        = scope_id;
	i->CurrentlyActive = mDNStrue;
	i->sa_family       = ifa->ifa_addr->sa_family;
	#if mDNS_AllowPort53
	i->skt53 = -1;
	i->cfs53 = NULL;
	#endif
	i->sktv4 = -1;
	i->cfsv4 = NULL;
	i->sktv6 = -1;
	i->cfsv6 = NULL;
	
	if (!i->ifa_name) return(-1);
	*p = i;
	return(0);
	}

mDNSlocal NetworkInterfaceInfoOSX *FindRoutableIPv4(mDNS *const m, mDNSu32 scope_id)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->CurrentlyActive && i->scope_id == scope_id && i->ifinfo.ip.type == mDNSAddrType_IPv4)
			if (!(i->ifinfo.ip.ip.v4.b[0] == 169 && i->ifinfo.ip.ip.v4.b[1] == 254))
				return(i);
	return(mDNSNULL);
	}

mDNSlocal mStatus UpdateInterfaceList(mDNS *const m)
	{
	mDNSBool foundav4           = mDNSfalse;
	struct ifaddrs *ifa         = myGetIfAddrs(1);
	struct ifaddrs *theLoopback = NULL;
	int err = (ifa != NULL) ? 0 : (errno != 0 ? errno : -1);
	int InfoSocket              = err ? -1 : socket(AF_INET6, SOCK_DGRAM, 0);
	if (err) return(err);

	// Set up the nice label
	m->nicelabel.c[0] = 0;
	GetUserSpecifiedFriendlyComputerName(&m->nicelabel);
	if (m->nicelabel.c[0] == 0) MakeDomainLabelFromLiteralString(&m->nicelabel, "Macintosh");

	// Set up the RFC 1034-compliant label
	domainlabel hostlabel;
	hostlabel.c[0] = 0;
	GetUserSpecifiedRFC1034ComputerName(&hostlabel);
	if (hostlabel.c[0] == 0) MakeDomainLabelFromLiteralString(&hostlabel, "Macintosh");
	// If the user has changed their dot-local host name since the last time we checked, then update our local copy.
	// If the user has not changed their dot-local host name, then leave ours alone (m->hostlabel may have gone through
	// repeated conflict resolution to get to its current value, and if we reset it, we'll have to go through all that again.)
	if (SameDomainLabel(m->p->userhostlabel.c, hostlabel.c))
		debugf("Userhostlabel (%#s) unchanged since last time; not changing m->hostlabel (%#s)", m->p->userhostlabel.c, m->hostlabel.c);
	else
		{
		debugf("Updating m->hostlabel to %#s", hostlabel.c);
		m->p->userhostlabel = m->hostlabel = hostlabel;
		mDNS_GenerateFQDN(m);
		}

	while (ifa)
		{
#if LIST_ALL_INTERFACES
		if (ifa->ifa_addr->sa_family == AF_APPLETALK)
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d is AF_APPLETALK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		else if (ifa->ifa_addr->sa_family == AF_LINK)
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d is AF_LINK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		else if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d not AF_INET (2) or AF_INET6 (30)",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (!(ifa->ifa_flags & IFF_UP))
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d Interface not IFF_UP",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d Interface IFF_POINTOPOINT",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (ifa->ifa_flags & IFF_LOOPBACK)
			debugf("UpdateInterfaceList: %4s(%d) Flags %04X Family %2d Interface IFF_LOOPBACK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
#endif
		if ((ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) &&
			(ifa->ifa_flags & IFF_MULTICAST) &&
		    (ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_POINTOPOINT))
			{
			int	ifru_flags6 = 0;
			if (ifa->ifa_addr->sa_family == AF_INET6 && InfoSocket >= 0)
				{
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				struct in6_ifreq ifr6;
				bzero((char *)&ifr6, sizeof(ifr6));
				strncpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
				ifr6.ifr_addr = *sin6;
				if (ioctl(InfoSocket, SIOCGIFAFLAG_IN6, &ifr6) != -1)
					ifru_flags6 = ifr6.ifr_ifru.ifru_flags6;
				verbosedebugf("%s %.16a %04X %04X", ifa->ifa_name, &sin6->sin6_addr, ifa->ifa_flags, ifru_flags6);
				}
			if (!(ifru_flags6 & (IN6_IFF_NOTREADY | IN6_IFF_DETACHED | IN6_IFF_DEPRECATED | IN6_IFF_TEMPORARY)))
				{
				if (ifa->ifa_flags & IFF_LOOPBACK)
					theLoopback = ifa;
				else
					{
					AddInterfaceToList(m, ifa);
					if (ifa->ifa_addr->sa_family == AF_INET)
						foundav4 = mDNStrue;
					}
				}
			}
		ifa = ifa->ifa_next;
		}

//	Temporary workaround: Multicast loopback on IPv6 interfaces appears not to work.
//	In the interim, we skip loopback interface only if we found at least one v4 interface to use
	if (!foundav4 && theLoopback)
		AddInterfaceToList(m, theLoopback);

	// Now the list is complete, set the TxAndRx setting for each interface.
	// We always send and receive using IPv4.
	// To reduce traffic, we send and receive using IPv6 only on interfaces that have no routable IPv4 address.
	// Having a routable IPv4 address assigned is a reasonable indicator of being on a large configured network,
	// which means there's a good chance that most or all the other devices on that network should also have v4.
	// By doing this we lose the ability to talk to true v6-only devices on that link, but we cut the packet rate in half.
	// At this time, reducing the packet rate is more important than v6-only devices on a large configured network,
	// so we are willing to make that sacrifice.
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->CurrentlyActive)
			{
			mDNSBool txrx = ((i->ifinfo.ip.type == mDNSAddrType_IPv4) || !FindRoutableIPv4(m, i->scope_id));
			if (i->ifinfo.TxAndRx != txrx)
				{
				i->ifinfo.TxAndRx = txrx;
				i->CurrentlyActive = 2;	// State change; need to deregister and reregister this interface
				}
			}

	if (InfoSocket >= 0) close(InfoSocket);
	return(err);
	}

mDNSlocal NetworkInterfaceInfoOSX *SearchForInterfaceByName(mDNS *const m, char *ifname, int type)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (!strcmp(i->ifa_name, ifname) &&
			((AAAA_OVER_V4                                              ) ||
			 (type == AF_INET  && i->ifinfo.ip.type == mDNSAddrType_IPv4) ||
			 (type == AF_INET6 && i->ifinfo.ip.type == mDNSAddrType_IPv6) )) return(i);
	return(NULL);
	}

mDNSlocal void SetupActiveInterfaces(mDNS *const m)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		{
		mStatus err = 0;
		NetworkInterfaceInfo *n = &i->ifinfo;
		NetworkInterfaceInfoOSX *alias = SearchForInterfaceByName(m, i->ifa_name, i->sa_family);
		if (!alias) alias = i;

		if (n->InterfaceID && n->InterfaceID != (mDNSInterfaceID)alias)
			{
			LogMsg("SetupActiveInterfaces ERROR! n->InterfaceID %p != alias %p", n->InterfaceID, alias);
			n->InterfaceID = mDNSNULL;
			}

		if (!n->InterfaceID)
			{
			n->InterfaceID = (mDNSInterfaceID)alias;
			mDNS_RegisterInterface(m, n);
			debugf("SetupActiveInterfaces: Registered  %s(%lu) InterfaceID %p %#a%s",
				i->ifa_name, i->scope_id, alias, &n->ip, n->InterfaceActive ? " (Primary)" : "");
			}

		if (!n->TxAndRx)
			debugf("SetupActiveInterfaces: No TX/Rx on %s(%lu) InterfaceID %p %#a", i->ifa_name, i->scope_id, alias, &n->ip);
		else
			{
			if (i->sa_family == AF_INET && alias->sktv4 == -1)
				{
				#if mDNS_AllowPort53
				err = SetupSocket(i, UnicastDNSPort, &alias->skt53, &alias->cfs53);
				#endif
				if (!err) err = SetupSocket(i, MulticastDNSPort, &alias->sktv4, &alias->cfsv4);
				if (err == 0) debugf("SetupActiveInterfaces: v4 socket%2d %s(%lu) InterfaceID %p %#a", alias->sktv4, i->ifa_name, i->scope_id, n->InterfaceID, &n->ip);
				else LogMsg("SetupActiveInterfaces: v4 socket%2d %s(%lu) InterfaceID %p %#a FAILED",   alias->sktv4, i->ifa_name, i->scope_id, n->InterfaceID, &n->ip);
				}
		
			if (i->sa_family == AF_INET6 && alias->sktv6 == -1)
				{
				err = SetupSocket(i, MulticastDNSPort, &alias->sktv6, &alias->cfsv6);
				if (err == 0) debugf("SetupActiveInterfaces: v6 socket%2d %s(%lu) InterfaceID %p %#a", alias->sktv6, i->ifa_name, i->scope_id, n->InterfaceID, &n->ip);
				else LogMsg("SetupActiveInterfaces: v6 socket%2d %s(%lu) InterfaceID %p %#a FAILED",   alias->sktv6, i->ifa_name, i->scope_id, n->InterfaceID, &n->ip);
				}
			}
		}
	}

mDNSlocal void MarkAllInterfacesInactive(mDNS *const m)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		i->CurrentlyActive = mDNSfalse;
	}

mDNSlocal void ClearInactiveInterfaces(mDNS *const m)
	{
	// First pass:
	// If an interface is going away, then deregister this from the mDNSCore.
	// We also have to deregister it if the alias interface that it's using for its InterfaceID is going away.
	// We have to do this because mDNSCore will use that InterfaceID when sending packets, and if the memory
	// it refers to has gone away we'll crash.
	// Don't actually close the sockets or free the memory yet: When the last representative of an interface goes away
	// mDNSCore may want to send goodbye packets on that interface. (Not yet implemented, but a good idea anyway.)
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		{
		// 1. If this interface is no longer active, or it's InterfaceID is changing, deregister it
		NetworkInterfaceInfoOSX *alias = (NetworkInterfaceInfoOSX *)(i->ifinfo.InterfaceID);
		if (i->ifinfo.InterfaceID && (!i->CurrentlyActive || (alias && !alias->CurrentlyActive) || i->CurrentlyActive == 2))
			{
			debugf("ClearInactiveInterfaces: Deregistering %#a", &i->ifinfo.ip);
			mDNS_DeregisterInterface(m, &i->ifinfo);
			i->ifinfo.InterfaceID = mDNSNULL;
			}
		}

	// Second pass:
	// Now that everything that's going to deregister has done so, we can close sockets and free the memory
	NetworkInterfaceInfoOSX **p = &m->p->InterfaceList;
	while (*p)
		{
		i = *p;
		// 2. Close all our CFSockets. We'll recreate them later as necessary.
		// (We may have previously had both v4 and v6, and we may not need both any more.)
		// Note: MUST NOT close the underlying native BSD sockets.
		// CFSocketInvalidate() will do that for us, in its own good time, which may not necessarily be immediately,
		// because it first has to unhook the sockets from its select() call, before it can safely close them.
		#if mDNS_AllowPort53
		if (i->cfs53) { CFSocketInvalidate(i->cfs53); CFRelease(i->cfs53); }
		i->skt53 = -1;
		i->cfs53 = NULL;
		#endif
		if (i->cfsv4) { CFSocketInvalidate(i->cfsv4); CFRelease(i->cfsv4); }
		if (i->cfsv6) { CFSocketInvalidate(i->cfsv6); CFRelease(i->cfsv6); }
		i->sktv4 = i->sktv6 = -1;
		i->cfsv4 = i->cfsv6 = NULL;

		// 3. If no longer active, delete interface from list and free memory
		if (!i->CurrentlyActive)
			{
			debugf("ClearInactiveInterfaces: Deleting      %#a", &i->ifinfo.ip);
			*p = i->next;
			if (i->ifa_name) freeL("NetworkInterfaceInfoOSX name", i->ifa_name);
			freeL("NetworkInterfaceInfoOSX", i);
			}
		else
			p = &i->next;
		}
	}

mDNSlocal void NetworkChanged(SCDynamicStoreRef store, CFArrayRef changedKeys, void *context)
	{
	(void)store;		// Parameter not used
	(void)changedKeys;	// Parameter not used
	debugf("***   Network Configuration Change   ***");

	mDNS *const m = (mDNS *const)context;
	MarkAllInterfacesInactive(m);
	UpdateInterfaceList(m);
	ClearInactiveInterfaces(m);
	SetupActiveInterfaces(m);
	
	if (m->MainCallback)
		m->MainCallback(m, mStatus_ConfigChanged);
	}

mDNSlocal mStatus WatchForNetworkChanges(mDNS *const m)
	{
	mStatus err = -1;
	SCDynamicStoreContext context = { 0, m, NULL, NULL, NULL };
	SCDynamicStoreRef     store    = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder"), NetworkChanged, &context);
	CFStringRef           key1     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
	CFStringRef           key2     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv6);
	CFStringRef           key3     = SCDynamicStoreKeyCreateComputerName(NULL);
	CFStringRef           key4     = SCDynamicStoreKeyCreateHostNames(NULL);
	CFStringRef           pattern1 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
	CFStringRef           pattern2 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6);

	CFMutableArrayRef     keys     = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	CFMutableArrayRef     patterns = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	if (!store) { LogMsg("SCDynamicStoreCreate failed: %s\n", SCErrorString(SCError())); goto error; }
	if (!key1 || !key2 || !key3 || !key4 || !keys || !pattern1 || !pattern2 || !patterns) goto error;

	CFArrayAppendValue(keys, key1);
	CFArrayAppendValue(keys, key2);
	CFArrayAppendValue(keys, key3);
	CFArrayAppendValue(keys, key4);
	CFArrayAppendValue(patterns, pattern1);
	CFArrayAppendValue(patterns, pattern2);
	if (!SCDynamicStoreSetNotificationKeys(store, keys, patterns))
		{ LogMsg("SCDynamicStoreSetNotificationKeys failed: %s\n", SCErrorString(SCError())); goto error; }

	m->p->StoreRLS = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
	if (!m->p->StoreRLS) { LogMsg("SCDynamicStoreCreateRunLoopSource failed: %s\n", SCErrorString(SCError())); goto error; }

	CFRunLoopAddSource(CFRunLoopGetCurrent(), m->p->StoreRLS, kCFRunLoopDefaultMode);
	m->p->Store = store;
	err = 0;
	goto exit;

error:
	if (store)    CFRelease(store);

exit:
	if (key1)     CFRelease(key1);
	if (key2)     CFRelease(key2);
	if (key3)     CFRelease(key3);
	if (key4)     CFRelease(key4);
	if (pattern1) CFRelease(pattern1);
	if (pattern2) CFRelease(pattern2);
	if (keys)     CFRelease(keys);
	if (patterns) CFRelease(patterns);
	
	return(err);
	}

mDNSlocal void PowerChanged(void *refcon, io_service_t service, natural_t messageType, void *messageArgument)
	{
	mDNS *const m = (mDNS *const)refcon;
	(void)service;		// Parameter not used
	switch(messageType)
		{
		case kIOMessageCanSystemPowerOff:     debugf("PowerChanged kIOMessageCanSystemPowerOff (no action)");                      break; // E0000240
		case kIOMessageSystemWillPowerOff:    debugf("PowerChanged kIOMessageSystemWillPowerOff"); mDNSCoreMachineSleep(m, true);  break; // E0000250
		case kIOMessageSystemWillNotPowerOff: debugf("PowerChanged kIOMessageSystemWillNotPowerOff (no action)");                  break; // E0000260
		case kIOMessageCanSystemSleep:        debugf("PowerChanged kIOMessageCanSystemSleep (no action)");                         break; // E0000270
		case kIOMessageSystemWillSleep:       debugf("PowerChanged kIOMessageSystemWillSleep");    mDNSCoreMachineSleep(m, true);  break; // E0000280
		case kIOMessageSystemWillNotSleep:    debugf("PowerChanged kIOMessageSystemWillNotSleep (no action)");                     break; // E0000290
		case kIOMessageSystemHasPoweredOn:    debugf("PowerChanged kIOMessageSystemHasPoweredOn"); mDNSCoreMachineSleep(m, false); break; // E0000300
		default:                              debugf("PowerChanged unknown message %X", messageType);                              break;
		}
	IOAllowPowerChange(m->p->PowerConnection, (long)messageArgument);
	}

mDNSlocal mStatus WatchForPowerChanges(mDNS *const m)
	{
	IONotificationPortRef thePortRef;
	m->p->PowerConnection = IORegisterForSystemPower(m, &thePortRef, PowerChanged, &m->p->PowerNotifier);
	if (m->p->PowerConnection)
		{
		m->p->PowerRLS = IONotificationPortGetRunLoopSource(thePortRef);
		CFRunLoopAddSource(CFRunLoopGetCurrent(), m->p->PowerRLS, kCFRunLoopDefaultMode);
		return(mStatus_NoError);
		}
	return(-1);
	}

CF_EXPORT CFDictionaryRef _CFCopySystemVersionDictionary(void);
CF_EXPORT const CFStringRef _kCFSystemVersionProductNameKey;
CF_EXPORT const CFStringRef _kCFSystemVersionProductVersionKey;
CF_EXPORT const CFStringRef _kCFSystemVersionBuildVersionKey;		

mDNSexport mDNSBool mDNSMacOSXSystemBuildNumber(char *HINFO_SWstring)
	{
	int major = 0, minor = 0;
	char letter = 0, prodname[256]="Mac OS X", prodvers[256]="", buildver[256]="?";
	CFDictionaryRef vers = _CFCopySystemVersionDictionary();
	if (vers)
		{
		CFStringRef cfprodname = CFDictionaryGetValue(vers, _kCFSystemVersionProductNameKey);
		CFStringRef cfprodvers = CFDictionaryGetValue(vers, _kCFSystemVersionProductVersionKey);
		CFStringRef cfbuildver = CFDictionaryGetValue(vers, _kCFSystemVersionBuildVersionKey);
		if (cfprodname) CFStringGetCString(cfprodname, prodname, sizeof(prodname), kCFStringEncodingUTF8);
		if (cfprodvers) CFStringGetCString(cfprodvers, prodvers, sizeof(prodvers), kCFStringEncodingUTF8);
		if (cfbuildver) CFStringGetCString(cfbuildver, buildver, sizeof(buildver), kCFStringEncodingUTF8);
		sscanf(buildver, "%d%c%d", &major, &letter, &minor);
		CFRelease(vers);
		}
	if (HINFO_SWstring) mDNS_snprintf(HINFO_SWstring, 256, "%s %s (%s), %s", prodname, prodvers, buildver, mDNSResponderVersionString);
	return(major);
	}

mDNSlocal mStatus mDNSPlatformInit_setup(mDNS *const m)
	{
	mStatus err;

	m->hostlabel.c[0]        = 0;

	char *HINFO_HWstring = "Macintosh";
	char HINFO_HWstring_buffer[256];
	int    get_model[2] = { CTL_HW, HW_MODEL };
	size_t len_model = sizeof(HINFO_HWstring_buffer);
	if (sysctl(get_model, 2, HINFO_HWstring_buffer, &len_model, NULL, 0) == 0)
		HINFO_HWstring = HINFO_HWstring_buffer;

	char HINFO_SWstring[256] = "";
	if (mDNSMacOSXSystemBuildNumber(HINFO_SWstring) < 7) m->KnownBugs = mDNS_KnownBug_PhantomInterfaces;

	mDNSu32 hlen = mDNSPlatformStrLen(HINFO_HWstring);
	mDNSu32 slen = mDNSPlatformStrLen(HINFO_SWstring);
	if (hlen + slen < 254)
		{
		m->HIHardware.c[0] = hlen;
		m->HISoftware.c[0] = slen;
		mDNSPlatformMemCopy(HINFO_HWstring, &m->HIHardware.c[1], hlen);
		mDNSPlatformMemCopy(HINFO_SWstring, &m->HISoftware.c[1], slen);
		}

	m->p->InterfaceList      = mDNSNULL;
	m->p->userhostlabel.c[0] = 0;
	UpdateInterfaceList(m);
	SetupActiveInterfaces(m);

	err = WatchForNetworkChanges(m);
	if (err) return(err);
	
	err = WatchForPowerChanges(m);
	return(err);
	}

mDNSexport mStatus mDNSPlatformInit(mDNS *const m)
	{
	mStatus result = mDNSPlatformInit_setup(m);
	// We don't do asynchronous initialization on OS X, so by the time we get here the setup will already
	// have succeeded or failed -- so if it succeeded, we should just call mDNSCoreInitComplete() immediately
	if (result == mStatus_NoError) mDNSCoreInitComplete(m, mStatus_NoError);
	return(result);
	}

mDNSexport void mDNSPlatformClose(mDNS *const m)
	{
	if (m->p->PowerConnection)
		{
		CFRunLoopRemoveSource(CFRunLoopGetCurrent(), m->p->PowerRLS, kCFRunLoopDefaultMode);
		CFRunLoopSourceInvalidate(m->p->PowerRLS);
		CFRelease(m->p->PowerRLS);
		IODeregisterForSystemPower(&m->p->PowerNotifier);
		m->p->PowerConnection = NULL;
		m->p->PowerNotifier   = NULL;
		m->p->PowerRLS        = NULL;
		}
	
	if (m->p->Store)
		{
		CFRunLoopRemoveSource(CFRunLoopGetCurrent(), m->p->StoreRLS, kCFRunLoopDefaultMode);
		CFRunLoopSourceInvalidate(m->p->StoreRLS);
		CFRelease(m->p->StoreRLS);
		CFRelease(m->p->Store);
		m->p->Store    = NULL;
		m->p->StoreRLS = NULL;
		}
	
	MarkAllInterfacesInactive(m);
	ClearInactiveInterfaces(m);
	}

mDNSexport mDNSs32  mDNSPlatformOneSecond = 1000;

mDNSexport mStatus mDNSPlatformTimeInit(mDNSs32 *timenow)
	{
	// Notes: Typical values for mach_timebase_info:
	// tbi.numer = 1000 million
	// tbi.denom =   33 million
	// These are set such that (mach_absolute_time() * numer/denom) gives us nanoseconds;
	//          numer  / denom = nanoseconds per hardware clock tick (e.g. 30);
	//          denom  / numer = hardware clock ticks per nanosecond (e.g. 0.033)
	// (denom*1000000) / numer = hardware clock ticks per millisecond (e.g. 33333)
	// So: mach_absolute_time() / ((denom*1000000)/numer) = milliseconds
	//
	// Arithmetic notes:
	// tbi.denom is at least 1, and not more than 2^32-1.
	// Therefore (tbi.denom * 1000000) is at least one million, but cannot overflow a uint64_t.
	// tbi.denom is at least 1, and not more than 2^32-1.
	// Therefore clockdivisor should end up being a number roughly in the range 10^3 - 10^9.
	// If clockdivisor is less than 10^3 then that means that the native clock frequency is less than 1MHz,
	// which is unlikely on any current or future Macintosh.
	// If clockdivisor is greater than 10^9 then that means the native clock frequency is greater than 1000GHz.
	// When we ship Macs with clock frequencies above 1000GHz, we may have to update this code.
	struct mach_timebase_info tbi;
	kern_return_t result = mach_timebase_info(&tbi);
	if (result != KERN_SUCCESS) return(result);
	clockdivisor = ((uint64_t)tbi.denom * 1000000) / tbi.numer;
	*timenow = mDNSPlatformTimeNow();
	return(mStatus_NoError);
	}

mDNSexport mDNSs32  mDNSPlatformTimeNow(void)
	{
	if (clockdivisor == 0) { LogMsg("mDNSPlatformTimeNow called before mDNSPlatformTimeInit"); return(0); }
	return((mDNSs32)(mach_absolute_time() / clockdivisor));
	}

// Locking is a no-op here, because we're single-threaded with a CFRunLoop, so we can never interrupt ourselves
mDNSexport void     mDNSPlatformLock   (const mDNS *const m) { (void)m; }
mDNSexport void     mDNSPlatformUnlock (const mDNS *const m) { (void)m; }
mDNSexport void     mDNSPlatformStrCopy(const void *src,       void *dst)              { strcpy((char *)dst, (char *)src); }
mDNSexport mDNSu32  mDNSPlatformStrLen (const void *src)                               { return(strlen((char*)src)); }
mDNSexport void     mDNSPlatformMemCopy(const void *src,       void *dst, mDNSu32 len) { memcpy(dst, src, len); }
mDNSexport mDNSBool mDNSPlatformMemSame(const void *src, const void *dst, mDNSu32 len) { return(memcmp(dst, src, len) == 0); }
mDNSexport void     mDNSPlatformMemZero(                       void *dst, mDNSu32 len) { bzero(dst, len); }
mDNSexport void *   mDNSPlatformMemAllocate(mDNSu32 len) { return(mallocL("mDNSPlatformMemAllocate", len)); }
mDNSexport void     mDNSPlatformMemFree    (void *mem)   { freeL("mDNSPlatformMemFree", mem); }
