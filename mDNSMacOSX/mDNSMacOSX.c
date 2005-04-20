/* -*- Mode: C; tab-width: 4 -*-
 *
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

$Log: mDNSMacOSX.c,v $
Revision 1.308  2005/03/09 00:48:44  cheshire
<rdar://problem/4015157> QU packets getting sent too early on wake from sleep
Move "m->p->NetworkChanged = 0;" line from caller to callee

Revision 1.307  2005/03/03 03:12:02  cheshire
Add comment about mDNSMacOSXSystemBuildNumber()

Revision 1.306  2005/03/02 22:18:00  cheshire
<rdar://problem/3930171> mDNSResponder requires AppleInternal packages to build on Tiger

Revision 1.305  2005/02/26 05:08:28  cheshire
<rdar://problem/3930171> mDNSResponder requires AppleInternal packages to build on Tiger
Added dnsinfo.h to project directory

Revision 1.304  2005/02/25 23:51:22  cheshire
<rdar://problem/4021868> SendServiceRegistration fails on wake from sleep
Return mStatus_UnknownErr instead of -1

Revision 1.303  2005/02/25 17:47:45  ksekar
<rdar://problem/4021868> SendServiceRegistration fails on wake from sleep

Revision 1.302  2005/02/25 02:34:14  cheshire
<rdar://problem/4017292> Should not indicate successful dynamic update if no network connection
Show status as 1 (in progress) while we're trying

Revision 1.301  2005/02/24 21:55:57  ksekar
<rdar://problem/4017292> Should not indicate successful dynamic update if no network connection

Revision 1.300  2005/02/15 20:03:13  ksekar
<rdar://problem/4005868> Crash when SCPreferences contains empty array

Revision 1.299  2005/02/15 02:46:53  cheshire
<rdar://problem/3967876> Don't log ENETUNREACH errors for unicast destinations

Revision 1.298  2005/02/10 00:41:59  cheshire
Fix compiler warning

Revision 1.297  2005/02/09 23:38:51  ksekar
<rdar://problem/3993508> Reregister hostname when DNS server changes but IP address does not

Revision 1.296  2005/02/01 21:06:52  ksekar
Avoid spurious log message

Revision 1.295  2005/02/01 19:33:30  ksekar
<rdar://problem/3985239> Keychain format too restrictive

Revision 1.294  2005/01/27 21:30:23  cheshire
<rdar://problem/3952067> "Can't assign requested address" message after AirPort turned off
Don't write syslog messages for EADDRNOTAVAIL if we know network configuration changes are happening

Revision 1.293  2005/01/27 19:15:41  cheshire
Remove extraneous LogMsg() call

Revision 1.292  2005/01/27 17:48:38  cheshire
Added comment about CFSocketInvalidate closing the underlying socket

Revision 1.291  2005/01/27 00:10:58  cheshire
<rdar://problem/3967867> Name change log messages every time machine boots

Revision 1.290  2005/01/25 23:18:30  ksekar
fix for <rdar://problem/3971467> requires that local-only ".local" registration record be created

Revision 1.289  2005/01/25 18:08:31  ksekar
Removed redundant debug output

Revision 1.288  2005/01/25 17:42:26  ksekar
Renamed FoundDefBrowseDomain -> FoundLegacyBrowseDomain,
cleaned up duplicate log messages when adding/removing browse domains

Revision 1.287  2005/01/25 16:59:23  ksekar
<rdar://problem/3971138> sa_len not set checking reachability for TCP connections

Revision 1.286  2005/01/25 02:02:37  cheshire
<rdar://problem/3970673> mDNSResponder leaks
GetSearchDomains() was not calling dns_configuration_free().

Revision 1.285  2005/01/22 00:07:54  ksekar
<rdar://problem/3960546> mDNSResponder should look at all browse domains in SCPreferences

Revision 1.284  2005/01/21 23:07:17  ksekar
<rdar://problem/3960795> mDNSResponder causes Dial on Demand

Revision 1.283  2005/01/19 21:16:16  cheshire
Make sure when we set NetworkChanged that we don't set it to zero

Revision 1.282  2005/01/19 19:19:21  ksekar
<rdar://problem/3960191> Need a way to turn off domain discovery

Revision 1.281  2005/01/18 18:10:55  ksekar
<rdar://problem/3954575> Use 10.4 resolver API to get search domains

Revision 1.280  2005/01/17 22:48:52  ksekar
No longer need to call MarkSearchListElem for registration domain

Revision 1.279  2005/01/17 20:40:34  ksekar
SCPreferences changes should remove exactly one browse and one legacy browse domain for each remove event

Revision 1.278  2005/01/17 19:53:34  ksekar
Refinement to previous fix - register _legacy._browse records for SCPreference domains to achieve correct reference counting

Revision 1.277  2005/01/12 00:17:50  ksekar
<rdar://problem/3933573> Update LLQs *after* setting DNS

Revision 1.276  2005/01/10 17:39:10  ksekar
Refinement to 1.272 - avoid spurious warnings when registration and browse domains are set to same value and toggled on/off

Revision 1.275  2005/01/10 04:02:22  ksekar
Refinement to <rdar://problem/3891628> - strip trailing dot before writing hostname status to dynamic store

Revision 1.274  2005/01/10 03:41:36  ksekar
Correction to checkin 1.272 - check that registration domain is set
before trying to remove it as an implicit browse domain

Revision 1.273  2005/01/08 00:42:18  ksekar
<rdar://problem/3922758> Clean up syslog messages

Revision 1.272  2005/01/07 23:21:42  ksekar
<rdar://problem/3891628> Clean up SCPreferences format

Revision 1.271  2004/12/20 23:18:12  cheshire
<rdar://problem/3485365> Guard against repeating wireless dissociation/re-association
One more refinement: When an interface with a v6LL address gets a v4 address too, that's not a flap

Revision 1.270  2004/12/20 21:28:14  cheshire
<rdar://problem/3485365> Guard against repeating wireless dissociation/re-association
Additional refinements to handle sleep/wake better

Revision 1.269  2004/12/20 20:48:11  cheshire
Only show "mach_absolute_time went backwards" notice on 10.4 (build 8xxx) or later

Revision 1.268  2004/12/18 03:19:04  cheshire
Show netmask in error log

Revision 1.267  2004/12/18 00:51:52  cheshire
Use symbolic constant kDNSServiceInterfaceIndexLocalOnly instead of (mDNSu32) ~0

Revision 1.266  2004/12/17 23:49:38  cheshire
<rdar://problem/3922754> Computer Name change is slow
Also treat changes to "Setup:/Network/DynamicDNS" the same way

Revision 1.265  2004/12/17 23:37:47  cheshire
<rdar://problem/3485365> Guard against repeating wireless dissociation/re-association
(and other repetitive configuration changes)

Revision 1.264  2004/12/17 19:03:05  cheshire
Update debugging messages to show netmask a simple CIDR-style numeric value (0-128)

Revision 1.263  2004/12/17 05:25:46  cheshire
<rdar://problem/3925163> Shorten DNS-SD queries to avoid NAT bugs

Revision 1.262  2004/12/17 04:48:32  cheshire
<rdar://problem/3922754> Computer Name change is slow

Revision 1.261  2004/12/17 02:40:08  cheshire
Undo last change -- it was too strict

Revision 1.260  2004/12/16 22:17:16  cheshire
Only accept multicast packets on interfaces that have McastTxRx set

Revision 1.259  2004/12/16 20:13:01  cheshire
<rdar://problem/3324626> Cache memory management improvements

Revision 1.258  2004/12/14 00:18:05  cheshire
Don't log dns_configuration_copy() failures in the first three minutes after boot

Revision 1.257  2004/12/10 19:45:46  cheshire
<rdar://problem/3915074> Reduce egregious stack space usage
Reduced myCFSocketCallBack() stack frame from 9K to 512 bytes

Revision 1.256  2004/12/10 04:35:43  cheshire
<rdar://problem/3907233> Show "Note: Compiled without Apple-specific split DNS support" only once

Revision 1.255  2004/12/10 04:12:54  ksekar
<rdar://problem/3890764> Need new DefaultBrowseDomain key

Revision 1.254  2004/12/10 01:55:31  ksekar
<rdar://problem/3899067> Keychain lookups should be in lower case.

Revision 1.253  2004/12/09 03:15:41  ksekar
<rdar://problem/3806610> use _legacy instead of _default to find "empty string" browse domains

Revision 1.252  2004/12/07 01:32:42  cheshire
Don't log dns_configuration_copy() failure when running on 10.3

Revision 1.251  2004/12/06 22:30:31  cheshire
Added debugging log message

Revision 1.250  2004/12/06 06:59:08  ksekar
RegisterSplitDNS should return Unsupported error when compiled on Panther

Revision 1.249  2004/12/04 00:29:46  cheshire
Add "#ifdef MAC_OS_X_VERSION_10_4" around split-DNS code that can't be compiled on 10.3 systems
(When compiled on 10.3, code will not include split-DNS support.)

Revision 1.248  2004/12/01 20:57:20  ksekar
<rdar://problem/3873921> Wide Area Service Discovery must be split-DNS aware

Revision 1.247  2004/12/01 03:26:58  cheshire
Remove unused variables

Revision 1.246  2004/12/01 01:51:34  cheshire
Move ReadDDNSSettingsFromConfFile() from mDNSMacOSX.c to PlatformCommon.c

Revision 1.245  2004/11/30 03:24:04  cheshire
<rdar://problem/3854544> Defer processing network configuration changes until configuration has stabilized

Revision 1.244  2004/11/30 02:59:35  cheshire
For debugging diagnostics, added identifying strings in SCDynamicStoreCreate() calls

Revision 1.243  2004/11/29 19:17:29  ksekar
<rdar://problem/3878195> Unnecessary GetUserSpecifiedDDNSConfig log messages

Revision 1.242  2004/11/29 18:37:38  ksekar
<rdar://problem/3889341> Buffer overflow in GetConfigOption

Revision 1.241  2004/11/25 01:37:04  ksekar
<rdar://problem/3894854> Config file and SCPreferences don't play well together

Revision 1.240  2004/11/25 01:29:42  ksekar
Remove unnecessary log messages

Revision 1.239  2004/11/25 01:27:19  ksekar
<rdar://problem/3885859> Don't try to advertise link-local IP addresses via dynamic update

Revision 1.238  2004/11/24 22:00:59  cheshire
Move definition of mDNSAddressIsAllDNSLinkGroup() from mDNSMacOSX.c to mDNSEmbeddedAPI.h

Revision 1.237  2004/11/24 21:54:44  cheshire
<rdar://problem/3894475> mDNSCore not receiving unicast responses properly

Revision 1.236  2004/11/23 03:39:46  cheshire
Let interface name/index mapping capability live directly in JNISupport.c,
instead of having to call through to the daemon via IPC to get this information.

Revision 1.235  2004/11/17 01:45:35  cheshire
<rdar://problem/3847435> mDNS buddy list frequently becomes empty if you let the machine sleep
Refresh our interface list on receiving kIOMessageSystemHasPoweredOn,
in case we get no System Configuration Framework "network changed" event.

Revision 1.234  2004/11/17 00:32:56  ksekar
<rdar://problem/3880773> mDNSResponder will not discover zones contained both in Search Domains and DHCP Domain option

Revision 1.233  2004/11/12 03:16:45  rpantos
rdar://problem/3809541 Add mDNSPlatformGetInterfaceByName, mDNSPlatformGetInterfaceName

Revision 1.232  2004/11/10 20:40:54  ksekar
<rdar://problem/3868216> LLQ mobility fragile on non-primary interface

Revision 1.231  2004/11/06 00:59:33  ksekar
Don't log ENETDOWN errors for unicast destinations (pollutes log on
wake from sleep)

Revision 1.230  2004/11/05 01:04:10  ksekar
<rdar://problem/3774577> LegacyNATDestroy() called too enthusiastically

Revision 1.229  2004/11/03 03:45:16  cheshire
<rdar://problem/3863627> mDNSResponder does not inform user of Computer Name collisions

Revision 1.228  2004/11/02 23:47:32  cheshire
<rdar://problem/3863214> Default hostname and Computer Name should be unique

Revision 1.227  2004/11/02 04:23:03  cheshire
Change to more informative name "GetUserSpecifiedLocalHostName()"

Revision 1.226  2004/11/01 20:36:19  ksekar
<rdar://problem/3802395> mDNSResponder should not receive Keychain Notifications

Revision 1.225  2004/10/28 19:03:04  cheshire
Remove \n from LogMsg() calls

Revision 1.224  2004/10/28 17:47:34  cheshire
Oops. Forgot the %d in the log message.

Revision 1.223  2004/10/28 17:24:28  cheshire
Updated "bad ifa_netmask" log message to give more information

Revision 1.222  2004/10/28 03:36:34  cheshire
<rdar://problem/3856535> Share the same port for both multicast and unicast receiving

Revision 1.221  2004/10/28 03:24:41  cheshire
Rename m->CanReceiveUnicastOn as m->CanReceiveUnicastOn5353

Revision 1.220  2004/10/28 00:53:57  cheshire
Export mDNSMacOSXNetworkChanged() so it's callable from outside this mDNSMacOSX.c;
Add LogOperation() call to record when we get network change events

Revision 1.219  2004/10/27 20:42:20  cheshire
Clean up debugging messages

Revision 1.218  2004/10/27 02:03:59  cheshire
Update debugging messages

Revision 1.217  2004/10/26 20:48:21  cheshire
Improve logging messages

Revision 1.216  2004/10/26 01:02:37  cheshire
Update comment

Revision 1.215  2004/10/25 20:09:00  ksekar
Cleaned up config file parsing.

Revision 1.214  2004/10/25 19:30:53  ksekar
<rdar://problem/3827956> Simplify dynamic host name structures

Revision 1.213  2004/10/23 01:16:01  cheshire
<rdar://problem/3851677> uDNS operations not always reliable on multi-homed hosts

Revision 1.212  2004/10/22 20:52:08  ksekar
<rdar://problem/3799260> Create NAT port mappings for Long Lived Queries

Revision 1.211  2004/10/22 01:07:11  cheshire
<rdar://problem/3375328> select() says data is waiting; recvfrom() says there is no data
Log error message if socket() ever returns file descriptors 0, 1 or 2 (stdin/stdout/stderr).
These are all supposed to be remapped to /dev/null

Revision 1.210  2004/10/20 02:19:54  cheshire
Eliminate "SetupAddr invalid sa_family" warning from RegisterSearchDomains()

Revision 1.209  2004/10/16 00:17:00  cheshire
<rdar://problem/3770558> Replace IP TTL 255 check with local subnet source address check

Revision 1.208  2004/10/15 23:00:18  ksekar
<rdar://problem/3799242> Need to update LLQs on location changes

Revision 1.207  2004/10/13 22:45:23  cheshire
<rdar://problem/3438392> Ten-second delay before kIOMessageSystemHasPoweredOn message

Revision 1.206  2004/10/13 22:11:46  cheshire
Update debugging messages

Revision 1.205  2004/10/12 21:10:11  cheshire
<rdar://problem/3438376> mach_absolute_time() not monotonically increasing
Do a NotifyOfElusiveBug() if we see mach_absolute_time() go backwards

Revision 1.204  2004/10/12 03:20:52  ksekar
<rdar://problem/3835614> Incorrect LogMsg produces garbage on errors

Revision 1.203  2004/10/08 04:29:25  ksekar
<rdar://problem/3831842> Allow default search domains to be set via hint from DHCP

Revision 1.202  2004/10/04 05:56:04  cheshire
<rdar://problem/3824730> mDNSResponder doesn't respond to certain AirPort changes

Revision 1.201  2004/09/30 00:24:59  ksekar
<rdar://problem/3695802> Dynamically update default registration domains on config change

Revision 1.200  2004/09/26 23:20:35  ksekar
<rdar://problem/3813108> Allow default registrations in multiple wide-area domains

Revision 1.199  2004/09/24 23:54:55  cheshire
<rdar://problem/3787102> Don't use kCFSocketCloseOnInvalidate

Revision 1.198  2004/09/24 23:47:49  cheshire
Correct comment and error message

Revision 1.197  2004/09/24 23:39:27  cheshire
<rdar://problem/3733705> Only IPv6 loopback address advertised on laptop w/no networking

Revision 1.196  2004/09/24 20:53:04  cheshire
Revise error message to say "Setsockopt SO_REUSEPORT failed" instead of "Flaw in Kernel"

Revision 1.195  2004/09/24 19:21:45  cheshire
<rdar://problem/3671626> Report "Address already in use" errors

Revision 1.194  2004/09/24 19:16:54  cheshire
Remove "mDNS *const m" parameter from NotifyOfElusiveBug();
Refine error message to say "Flaw in Kernel (select/recvfrom mismatch)"

Revision 1.193  2004/09/22 00:41:59  cheshire
Move tcp connection status codes into the legal range allocated for mDNS use

Revision 1.192  2004/09/21 21:02:55  cheshire
Set up ifname before calling mDNS_RegisterInterface()

Revision 1.191  2004/09/21 19:19:36  cheshire
<rdar://problem/3760923> Combine WatchForDynDNSChanges() into WatchForNetworkChanges()

Revision 1.190  2004/09/21 19:04:45  cheshire
Strip trailing white space from the ends of lines

Revision 1.189  2004/09/21 00:13:28  cheshire
Fix build failure (io_connect_t and io_object_t are integers, not pointers)

Revision 1.188  2004/09/20 23:52:02  cheshire
CFSocket{Puma}.c renamed to mDNSMacOSX{Puma}.c

Revision 1.187  2004/09/18 01:37:01  cheshire
Update comment

Revision 1.186  2004/09/18 01:11:57  ksekar
<rdar://problem/3806734> Add a user's default domain to empty-string browse list

Revision 1.185  2004/09/17 01:08:52  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.184  2004/09/17 00:19:10  cheshire
For consistency with AllDNSLinkGroupv6, rename AllDNSLinkGroup to AllDNSLinkGroupv4

Revision 1.183  2004/09/17 00:15:56  cheshire
Rename mDNSPlatformInit_ReceiveUnicast to mDNSPlatformInit_CanReceiveUnicast

Revision 1.182  2004/09/16 21:36:36  cheshire
<rdar://problem/3803162> Fix unsafe use of mDNSPlatformTimeNow()
Changes to add necessary locking calls around unicast DNS operations

Revision 1.181  2004/09/16 02:03:42  cheshire
<rdar://problem/3802944> Change address to notify user of kernel flaw

Revision 1.180  2004/09/16 01:58:22  cheshire
Fix compiler warnings

Revision 1.179  2004/09/16 00:24:49  cheshire
<rdar://problem/3803162> Fix unsafe use of mDNSPlatformTimeNow()

Revision 1.178  2004/09/15 21:51:34  cheshire
<rdar://problem/3387020> mDNSResponder should notify user of kernel flaw
Calling CFUserNotificationDisplayNotice too early in the boot process seems to kill
the machine, so make sure we don't do this until at least three minutes after boot.

Revision 1.177  2004/09/15 01:16:29  cheshire
<rdar://problem/3387020> mDNSResponder should notify user of kernel flaw

Revision 1.176  2004/09/14 23:42:36  cheshire
<rdar://problem/3801296> Need to seed random number generator from platform-layer data

Revision 1.175  2004/09/14 21:35:46  cheshire
Minor code tidying, and added comments about CFRetainCounts

Revision 1.174  2004/09/14 19:14:57  ksekar
<rdar://problem/3192531> DynDNS: Discovery of DynDNS Zones via Reverse-Map PTR

Revision 1.173  2004/08/25 23:35:22  ksekar
<rdar://problem/3770615>: Error converting shared secret from base-64 to binary

Revision 1.172  2004/08/25 02:01:45  cheshire
<rdar://problem/3774777> Need to be able to get status of Dynamic DNS Host Name Update

Revision 1.171  2004/08/25 01:04:42  cheshire
Don't need to CFRelease name and array

Revision 1.170  2004/08/25 00:37:28  ksekar
<rdar://problem/3774635>: Cleanup DynDNS hostname registration code

Revision 1.169  2004/08/18 17:35:41  ksekar
<rdar://problem/3651443>: Feature #9586: Need support for Legacy NAT gateways

Revision 1.168  2004/08/17 03:16:24  ksekar
Fixed checkin 1.166 - enumeration type changed for wrong invocation of mDNS_GetDomains

Revision 1.167  2004/08/17 00:52:43  ksekar
Fix config file parse error, make semantics match SCPreferences
configuration input.

Revision 1.166  2004/08/16 19:55:07  ksekar
Change enumeration type to BrowseDefault to construct empty-string
browse list as result of checking 1.161.

Revision 1.165  2004/08/16 19:52:40  ksekar
Pass computer name + zone for FQDN after keychain notification,
setting global default service registration domain to the zone.

Revision 1.164  2004/08/16 16:52:37  ksekar
Pass in zone read from keychain to mDNS_SetFQDNs.

Revision 1.163  2004/08/14 03:22:42  cheshire
<rdar://problem/3762579> Dynamic DNS UI <-> mDNSResponder glue
Add GetUserSpecifiedDDNSName() routine
Convert ServiceRegDomain to domainname instead of C string
Replace mDNS_GenerateFQDN/mDNS_GenerateGlobalFQDN with mDNS_SetFQDNs

Revision 1.162  2004/08/12 22:34:00  cheshire
All strings should be read as kCFStringEncodingUTF8, not kCFStringEncodingASCII

Revision 1.161  2004/08/11 00:17:46  ksekar
<rdar://problem/3757662>: 8A227: Need Lighthouse configred machines to
set default bit for their domains

Revision 1.160  2004/07/29 19:27:16  ksekar
NATPMP Support - minor fixes and cleanup

Revision 1.159  2004/07/26 22:49:31  ksekar
<rdar://problem/3651409>: Feature #9516: Need support for NATPMP in client

Revision 1.158  2004/07/13 21:24:24  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.157  2004/06/08 18:54:48  ksekar
<rdar://problem/3681378>: mDNSResponder leaks after exploring in Printer Setup Utility

Revision 1.156  2004/06/05 00:04:26  cheshire
<rdar://problem/3668639>: wide-area domains should be returned in reg. domain enumeration

Revision 1.155  2004/06/04 08:58:30  ksekar
<rdar://problem/3668624>: Keychain integration for secure dynamic update

Revision 1.154  2004/05/31 22:22:28  ksekar
<rdar://problem/3668639>: wide-area domains should be returned in
reg. domain enumeration

Revision 1.153  2004/05/26 17:06:33  cheshire
<rdar://problem/3668515>: Don't rely on CFSocketInvalidate() to remove RunLoopSource

Revision 1.152  2004/05/18 23:51:26  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.151  2004/05/17 21:46:34  cheshire
<rdar://problem/3616426>: When interface is turned off, browse "remove" events are delivered with interface index zero
Take care to correctly update InterfaceIDs when a dormant interface comes back to life

Revision 1.150  2004/05/13 04:54:20  ksekar
Unified list copy/free code.  Added symetric list for

Revision 1.149  2004/05/13 03:55:14  ksekar
Fixed list traversal bug in FoundDefSearchDomain.

Revision 1.148  2004/05/12 22:03:08  ksekar
Made GetSearchDomainList a true platform-layer call (declaration moved
from mDNSMacOSX.h to mDNSEmbeddedAPI.h), impelemted to return "local"
only on non-OSX platforms.  Changed call to return a copy of the list
to avoid shared memory issues.  Added a routine to free the list.

Revision 1.147  2004/05/12 02:03:25  ksekar
Non-local domains will only be browsed by default, and show up in
_browse domain enumeration, if they contain an _browse._dns-sd ptr record.

Revision 1.146  2004/04/27 02:49:15  cheshire
<rdar://problem/3634655>: mDNSResponder leaks sockets on bind() error

Revision 1.145  2004/04/21 03:08:03  cheshire
Rename 'alias' to more descriptive name 'primary'

Revision 1.144  2004/04/21 03:04:35  cheshire
Minor cleanup for clarity

Revision 1.143  2004/04/21 03:03:30  cheshire
Preparation work: AddInterfaceToList() should return pointer to structure it creates

Revision 1.142  2004/04/21 02:49:11  cheshire
To reduce future confusion, renamed 'TxAndRx' to 'McastTxRx'

Revision 1.141  2004/04/21 02:20:47  cheshire
Rename interface field 'CurrentlyActive' to more descriptive 'Exists'

Revision 1.140  2004/04/14 23:09:29  ksekar
Support for TSIG signed dynamic updates.

Revision 1.139  2004/04/09 17:40:26  cheshire
Remove unnecessary "Multicast" field -- it duplicates the semantics of the existing McastTxRx field

Revision 1.138  2004/04/09 16:37:16  cheshire
Suggestion from Bob Bradley:
Move NumCacheRecordsForInterfaceID() to DNSCommon.c so it's available to all platform layers

Revision 1.137  2004/04/08 00:59:55  cheshire
<rdar://problem/3609972> When interface turned off, browse "remove" events delivered with interface index zero
Unify use of the InterfaceID field, and make code that walks the list respect the 'Exists' flag

Revision 1.136  2004/04/07 01:08:57  cheshire
<rdar://problem/3609972> When interface turned off, browse "remove" events delivered with interface index zero

Revision 1.135  2004/03/19 01:01:03  ksekar
Fixed config file parsing to chop newline

Revision 1.134  2004/03/13 01:57:34  ksekar
<rdar://problem/3192546>: DynDNS: Dynamic update of service records

Revision 1.133  2004/02/02 22:46:56  cheshire
Move "CFRelease(dict);" inside the "if (dict)" check

Revision 1.132  2004/01/28 02:30:08  ksekar
Added default Search Domains to unicast browsing, controlled via
Networking sharing prefs pane.  Stopped sending unicast messages on
every interface.  Fixed unicast resolving via mach-port API.

Revision 1.131  2004/01/27 22:57:48  cheshire
<rdar://problem/3534352>: Need separate socket for issuing unicast queries

Revision 1.130  2004/01/27 22:28:40  cheshire
<rdar://problem/3541288>: Time to prune obsolete code for listening on port 53
Additional lingering port 53 code deleted

Revision 1.129  2004/01/27 20:15:23  cheshire
<rdar://problem/3541288>: Time to prune obsolete code for listening on port 53

Revision 1.128  2004/01/24 23:58:17  cheshire
Change to use mDNSVal16() instead of shifting and ORing

Revision 1.127  2004/01/24 04:59:16  cheshire
Fixes so that Posix/Linux, OS9, Windows, and VxWorks targets build again

Revision 1.126  2004/01/23 23:23:15  ksekar
Added TCP support for truncated unicast messages.

Revision 1.125  2004/01/22 03:43:09  cheshire
Export constants like mDNSInterface_LocalOnly so that the client layers can use them

Revision 1.124  2004/01/21 21:53:19  cheshire
<rdar://problem/3448144>: Don't try to receive unicast responses if we're not the first to bind to the UDP port

Revision 1.123  2004/01/20 03:18:25  cheshire
Removed "LogMsg("Hey There!");" that evidently got checked in my mistake

Revision 1.122  2003/12/17 20:43:59  cheshire
<rdar://problem/3496728>: Syslog messages saying "sendto failed"

Revision 1.121  2003/12/13 03:05:28  ksekar
<rdar://problem/3192548>: DynDNS: Unicast query of service records

Revision 1.120  2003/12/08 21:00:46  rpantos
Changes to support mDNSResponder on Linux.

Revision 1.119  2003/12/03 02:35:15  cheshire
Also report value of m->timenow when logging sendto() failure

Revision 1.118  2003/11/14 20:59:09  cheshire
Clients can't use AssignDomainName macro because mDNSPlatformMemCopy is defined in mDNSPlatformFunctions.h.
Best solution is just to combine mDNSEmbeddedAPI.h and mDNSPlatformFunctions.h into a single file.

Revision 1.117  2003/11/08 22:18:29  cheshire
<rdar://problem/3477870>: Don't need to show process ID in *every* mDNSResponder syslog message

Revision 1.116  2003/09/23 16:39:49  cheshire
When LogAllOperations is set, also report registration and deregistration of interfaces

Revision 1.115  2003/09/10 00:45:55  cheshire
<rdar://problem/3412328> Don't log "sendto failed" errors during the first two minutes of startup

Revision 1.114  2003/08/27 02:55:13  cheshire
<rdar://problem/3387910>: Bug: Don't report mDNSPlatformSendUDP sendto errno 64 (Host is down)

Revision 1.113  2003/08/19 22:20:00  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured
More minor refinements

Revision 1.112  2003/08/19 03:04:43  cheshire
<rdar://problem/3376721> Don't use IPv6 on interfaces that have a routable IPv4 address configured

Revision 1.111  2003/08/18 22:53:37  cheshire
<rdar://problem/3382647> mDNSResponder divide by zero in mDNSPlatformRawTime()

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
<rdar://problem/3320722>
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
<rdar://problem/3296061> mDNSResponder cannot handle interfaces whose total name is >3 chars
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
<rdar://problem/3191277>: mDNSResponder doesn't watch for IPv6 address changes

Revision 1.72  2003/05/14 18:48:41  cheshire
<rdar://problem/3159272> mDNSResponder should be smarter about reconfigurations
More minor refinements:
mDNSMacOSX.c needs to do *all* its mDNS_DeregisterInterface calls before freeing memory
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
<rdar://problem/3228833>
Modified code in CFSocket notifier function to read all packets on the socket
instead of reading only one packet every time the notifier was called.

Revision 1.63  2003/04/15 16:33:50  jgraessl
<rdar://problem/3221880>
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
<rdar://problem/3194246> mDNSResponder socket problems

Revision 1.58  2003/03/06 01:43:04  cheshire
<rdar://problem/3189097> Additional debugging code in mDNSResponder
Improve "LIST_ALL_INTERFACES" output

Revision 1.57  2003/03/05 22:36:27  cheshire
<rdar://problem/3186338> Loopback doesn't work with mDNSResponder-27
Temporary workaround: Skip loopback interface *only* if we found at least one v4 interface to use

Revision 1.56  2003/03/05 01:50:38  cheshire
<rdar://problem/3189097> Additional debugging code in mDNSResponder

Revision 1.55  2003/02/21 01:54:09  cheshire
<rdar://problem/3099194> mDNSResponder needs performance improvements
Switched to using new "mDNS_Execute" model (see "Implementer Notes.txt")

Revision 1.54  2003/02/20 06:48:35  cheshire
<rdar://problem/3169535> Xserve RAID needs to do interface-specific registrations
Reviewed by: Josh Graessley, Bob Bradley

Revision 1.53  2003/01/29 02:21:23  cheshire
Return mStatus_Invalid if can't send packet because socket not available

Revision 1.52  2003/01/28 19:39:43  jgraessl
Enabling AAAA over IPv4 support.

Revision 1.51  2003/01/28 05:11:23  cheshire
Fixed backwards comparison in SearchForInterfaceByName

Revision 1.50  2003/01/13 23:49:44  jgraessl
Merged changes for the following fixes in to top of tree:
<rdar://problem/3086540>  computer name changes not handled properly
<rdar://problem/3124348>  service name changes are not properly handled
<rdar://problem/3124352>  announcements sent in pairs, failing chattiness test

Revision 1.49  2002/12/23 22:13:30  jgraessl
Reviewed by: Stuart Cheshire
Initial IPv6 support for mDNSResponder.

Revision 1.48  2002/11/22 01:37:52  cheshire
<rdar://problem/3108426> mDNSResponder is monitoring ServiceEntities instead of InterfaceEntities

Revision 1.47  2002/09/21 20:44:51  zarzycki
Added APSL info

Revision 1.46  2002/09/19 21:25:35  cheshire
mDNS_snprintf() doesn't need to be in a separate file

Revision 1.45  2002/09/17 01:45:13  cheshire
Add LIST_ALL_INTERFACES symbol for debugging

Revision 1.44  2002/09/17 01:36:23  cheshire
Move Puma support to mDNSMacOSXPuma.c

Revision 1.43  2002/09/17 01:05:28  cheshire
Change mDNS_AdvertiseLocalAddresses to be an Init parameter instead of a global

Revision 1.42  2002/09/16 23:13:50  cheshire
Minor code tidying

 */

// ***************************************************************************
// mDNSMacOSX.c:
// Supporting routines to run mDNS on a CFRunLoop platform
// ***************************************************************************

// For debugging, set LIST_ALL_INTERFACES to 1 to display all found interfaces,
// including ones that mDNSResponder chooses not to use.
#define LIST_ALL_INTERFACES 0

// For enabling AAAA records over IPv4. Setting this to 0 sends only
// A records over IPv4 and AAAA over IPv6. Setting this to 1 sends both
// AAAA and A records over both IPv4 and IPv6.
#define AAAA_OVER_V4 1

#include "mDNSEmbeddedAPI.h"          // Defines the interface provided to the client layer above
#include "DNSCommon.h"
#include "mDNSMacOSX.h"               // Defines the specific types needed to run mDNS on this platform
#include "../mDNSShared/uds_daemon.h" // Defines communication interface from platform layer up to UDS daemon
#include "PlatformCommon.h"

#include <stdio.h>
#include <stdarg.h>                 // For va_list support
#include <net/if.h>
#include <net/if_types.h>			// For IFT_ETHER
#include <net/if_dl.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>                   // platform support for UTC time
#include <arpa/inet.h>              // for inet_aton

#include <netinet/in.h>             // For IP_RECVTTL
#ifndef IP_RECVTTL
#define IP_RECVTTL 24               // bool; receive reception TTL w/dgram
#endif

#include <netinet/in_systm.h>       // For n_long, required by <netinet/ip.h> below
#include <netinet/ip.h>             // For IPTOS_LOWDELAY etc.
#include <netinet6/in6_var.h>       // For IN6_IFF_NOTREADY etc.

#include <Security/Security.h>

#include "dnsinfo.h"

// Code contributed by Dave Heller:
// Define RUN_ON_PUMA_WITHOUT_IFADDRS to compile code that will
// work on Mac OS X 10.1, which does not have the getifaddrs call.
#define RUN_ON_PUMA_WITHOUT_IFADDRS 0
#if RUN_ON_PUMA_WITHOUT_IFADDRS
#include "mDNSMacOSXPuma.c"
#else
#include <ifaddrs.h>
#endif

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <mach/mach_time.h>

typedef struct SearchListElem
	{
    struct SearchListElem *next;
    domainname domain;
    int flag;
    DNSQuestion BrowseQ;
    DNSQuestion DefBrowseQ;
    DNSQuestion LegacyBrowseQ;
    DNSQuestion RegisterQ;
    DNSQuestion DefRegisterQ;
    ARListElem *AuthRecs;
	} SearchListElem;


// ***************************************************************************
// Globals

static mDNSu32 clockdivisor = 0;

// for domain enumeration and default browsing/registration
static SearchListElem *SearchList = NULL;      // where we search for _browse domains
static DNSQuestion LegacyBrowseDomainQ;        // our local enumeration query for _legacy._browse domains
static DNameListElem *DefBrowseList = NULL;    // cache of answers to above query (where we search for empty string browses)
static DNameListElem *DefRegList = NULL;       // manually generated list of domains where we register for empty string registrations
static ARListElem *SCPrefBrowseDomains = NULL; // manually generated local-only PTR records for browse domains we get from SCPreferences

static domainname DynDNSRegDomain;             // Default wide-area zone for service registration
static CFArrayRef DynDNSBrowseDomains = NULL;  // Default wide-area zones for legacy ("empty string") browses
static domainname DynDNSHostname;

static mDNSBool DomainDiscoveryDisabled = mDNSfalse;

#define CONFIG_FILE "/etc/mDNSResponder.conf"
#define DYNDNS_KEYCHAIN_SERVICE "DynDNS Shared Secret"
#define SYS_KEYCHAIN_PATH "/Library/Keychains/System.keychain"

// Function Prototypes
mDNSlocal void SetSCPrefsBrowseDomain(mDNS *m, const domainname *d, mDNSBool add);

// ***************************************************************************
// Functions

// routines to allow access to default domain lists from daemon layer

mDNSexport DNameListElem *mDNSPlatformGetSearchDomainList(void)
	{
	return mDNS_CopyDNameList(DefBrowseList);
	}

mDNSexport DNameListElem *mDNSPlatformGetRegDomainList(void)
	{
	return mDNS_CopyDNameList(DefRegList);
	}

// utility routines to manage registration domain lists

mDNSlocal void AddDefRegDomain(domainname *d)
	{
	DNameListElem *newelem = NULL, *ptr;

	// make sure name not already in list
	for (ptr = DefRegList; ptr; ptr = ptr->next)
		{
		if (SameDomainName(&ptr->name, d))
			{ debugf("duplicate addition of default reg domain %##s", d->c); return; }
		}
	
	newelem = mallocL("DNameListElem", sizeof(*newelem));
	if (!newelem) { LogMsg("Error - malloc"); return; }
	AssignDomainName(&newelem->name, d);
	newelem->next = DefRegList;
	DefRegList = newelem;

	DefaultRegDomainChanged(d, mDNStrue);
	udsserver_default_reg_domain_changed(d, mDNStrue);
	}

mDNSlocal void RemoveDefRegDomain(domainname *d)
	{
	DNameListElem *ptr = DefRegList, *prev = NULL;

	while (ptr)
		{
		if (SameDomainName(&ptr->name, d))
			{
			if (prev) prev->next = ptr->next;
			else DefRegList = ptr->next;
			freeL("DNameListElem", ptr);
			DefaultRegDomainChanged(d, mDNSfalse);
			udsserver_default_reg_domain_changed(d, mDNSfalse);
			return;
			}
		prev = ptr;
		ptr = ptr->next;
		}
	debugf("Requested removal of default registration domain %##s not in contained in list", d->c); 
	}

mDNSlocal void NotifyOfElusiveBug(const char *title, mDNSu32 radarid, const char *msg)
	{
	extern mDNS mDNSStorage;
	NetworkInterfaceInfoOSX *i;
	static int notifyCount = 0;
	if (notifyCount) return;
	
	// If we display our alert early in the boot process, then it vanishes once the desktop appears.
	// To avoid this, we don't try to display alerts in the first three minutes after boot.
	if ((mDNSu32)(mDNSPlatformRawTime()) < (mDNSu32)(mDNSPlatformOneSecond * 180)) return;
	
	// Determine if we're at Apple (17.*.*.*)
	for (i = mDNSStorage.p->InterfaceList; i; i = i->next)
		if (i->ifinfo.ip.type == mDNSAddrType_IPv4 && i->ifinfo.ip.ip.v4.b[0] == 17)
			break;
	if (!i) return;	// If not at Apple, don't show the alert

	// Send a notification to the user to contact coreos-networking
	notifyCount++;
	CFStringRef alertHeader  = CFStringCreateWithCString(NULL, title, kCFStringEncodingUTF8);
	CFStringRef alertFormat  = CFSTR("Congratulations, you've reproduced an elusive bug. Please contact the owner of <rdar://problem/%d>. %s");
	CFStringRef alertMessage = CFStringCreateWithFormat(NULL, NULL, alertFormat, radarid, msg);
	CFUserNotificationDisplayNotice(0.0, kCFUserNotificationStopAlertLevel, NULL, NULL, NULL, alertHeader, alertMessage, NULL);
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

mDNSlocal NetworkInterfaceInfoOSX *SearchForInterfaceByName(mDNS *const m, const char *ifname, int type)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->Exists && !strcmp(i->ifa_name, ifname) &&
			((AAAA_OVER_V4                                              ) ||
			 (type == AF_INET  && i->ifinfo.ip.type == mDNSAddrType_IPv4) ||
			 (type == AF_INET6 && i->ifinfo.ip.type == mDNSAddrType_IPv6) )) return(i);
	return(NULL);
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
	if (index == kDNSServiceInterfaceIndexLocalOnly) return(mDNSInterface_LocalOnly);
	if (index)
		for (i = m->p->InterfaceList; i; i = i->next)
			// Don't get tricked by inactive interfaces with no InterfaceID set
			if (i->ifinfo.InterfaceID && i->scope_id == index) return(i->ifinfo.InterfaceID);
	return(mDNSNULL);
	}

mDNSexport mDNSu32 mDNSPlatformInterfaceIndexfromInterfaceID(const mDNS *const m, mDNSInterfaceID id)
	{
	NetworkInterfaceInfoOSX *i;
	if (id == mDNSInterface_LocalOnly) return(kDNSServiceInterfaceIndexLocalOnly);
	if (id)
		for (i = m->p->InterfaceList; i; i = i->next)
			// Don't use i->ifinfo.InterfaceID here, because we DO want to find inactive interfaces, which have no InterfaceID set
			if ((mDNSInterfaceID)i == id) return(i->scope_id);
	return 0;
	}

mDNSlocal mDNSBool AddrRequiresPPPConnection(const struct sockaddr *addr)
	{
	mDNSBool result = mDNSfalse;
	SCNetworkConnectionFlags flags;
	SCNetworkReachabilityRef ReachRef = NULL;

	ReachRef = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, addr);	
	if (!ReachRef) { LogMsg("ERROR: RequiresConnection - SCNetworkReachabilityCreateWithAddress"); goto end; }
	if (!SCNetworkReachabilityGetFlags(ReachRef, &flags)) { LogMsg("ERROR: AddrRequiresPPPConnection - SCNetworkReachabilityGetFlags"); goto end; }
	result = flags & kSCNetworkFlagsConnectionRequired;

	end:
	if (ReachRef) CFRelease(ReachRef);
	return result;	
	}

// NOTE: If InterfaceID is NULL, it means, "send this packet through our anonymous unicast socket"
// NOTE: If InterfaceID is non-NULL it means, "send this packet through our port 5353 socket on the specified interface"
// OR send via our primary v4 unicast socket
mDNSexport mStatus mDNSPlatformSendUDP(const mDNS *const m, const void *const msg, const mDNSu8 *const end,
	mDNSInterfaceID InterfaceID, const mDNSAddr *dst, mDNSIPPort dstPort)
	{
	#pragma unused(m)
	
	// Note: For this platform we've adopted the convention that InterfaceIDs are secretly pointers
	// to the NetworkInterfaceInfoOSX structure that holds the active sockets. The mDNSCore code
	// doesn't know that and doesn't need to know that -- it just treats InterfaceIDs as opaque identifiers.
	NetworkInterfaceInfoOSX *info = (NetworkInterfaceInfoOSX *)InterfaceID;
	char *ifa_name = info ? info->ifa_name : "unicast";
	struct sockaddr_storage to;
	int s = -1, err;

	// Sanity check: Make sure that if we're sending a query via unicast, we're sending it using our
	// anonymous socket created for this purpose, so that we'll receive the response.
	// If we use one of the many multicast sockets bound to port 5353 then we may not receive responses reliably.
	if (info && !mDNSAddrIsDNSMulticast(dst))
		{
		const DNSMessage *const m = (DNSMessage *)msg;
		if ((m->h.flags.b[0] & kDNSFlag0_QR_Mask) == kDNSFlag0_QR_Query)
			LogMsg("mDNSPlatformSendUDP: ERROR: Sending query OP from mDNS port to non-mDNS destination %#a:%d", dst, mDNSVal16(dstPort));
		}
	
	if (dst->type == mDNSAddrType_IPv4)
		{
		struct sockaddr_in *sin_to = (struct sockaddr_in*)&to;
		sin_to->sin_len            = sizeof(*sin_to);
		sin_to->sin_family         = AF_INET;
		sin_to->sin_port           = dstPort.NotAnInteger;
		sin_to->sin_addr.s_addr    = dst->ip.v4.NotAnInteger;
		s = info ? info->ss.sktv4 : m->p->unicastsockets.sktv4;
		}
	else if (dst->type == mDNSAddrType_IPv6)
		{
		struct sockaddr_in6 *sin6_to = (struct sockaddr_in6*)&to;
		sin6_to->sin6_len            = sizeof(*sin6_to);
		sin6_to->sin6_family         = AF_INET6;
		sin6_to->sin6_port           = dstPort.NotAnInteger;
		sin6_to->sin6_flowinfo       = 0;
		sin6_to->sin6_addr           = *(struct in6_addr*)&dst->ip.v6;
		sin6_to->sin6_scope_id       = info ? info->scope_id : 0;
		s = info ? info->ss.sktv6 : m->p->unicastsockets.sktv6;
		}
	else
		{
		LogMsg("mDNSPlatformSendUDP: dst is not an IPv4 or IPv6 address!");
		return mStatus_BadParamErr;
		}

	// Don't send if it would cause dial on demand connection initiation.  As an optimization,
	// don't bother consulting reachability API / routing table when sending Multicast DNS
	// since we ignore PPP interfaces for mDNS traffic
	if (!mDNSAddrIsDNSMulticast(dst) && AddrRequiresPPPConnection((struct sockaddr *)&to))
		{
		debugf("mDNSPlatformSendUDP: Surpressing sending to avoid dial-on-demand connection");
		return mStatus_NoError;
		}
		
	if (s >= 0)
		verbosedebugf("mDNSPlatformSendUDP: sending on InterfaceID %p %5s/%ld to %#a:%d skt %d",
			InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s);
	else
		verbosedebugf("mDNSPlatformSendUDP: NOT sending on InterfaceID %p %5s/%ld (socket of this type not available)",
			InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort));

	// Note: When sending, mDNSCore may often ask us to send both a v4 multicast packet and then a v6 multicast packet
	// If we don't have the corresponding type of socket available, then return mStatus_Invalid
	if (s < 0) return(mStatus_Invalid);

	err = sendto(s, msg, (UInt8*)end - (UInt8*)msg, 0, (struct sockaddr *)&to, to.ss_len);
	if (err < 0)
		{
        // Don't report EHOSTDOWN (i.e. ARP failure), ENETDOWN, or no route to host for unicast destinations
		if (!mDNSAddressIsAllDNSLinkGroup(dst))
			if (errno == EHOSTDOWN || errno == ENETDOWN || errno == EHOSTUNREACH || errno == ENETUNREACH) return(mStatus_TransientErr);
		// Don't report EHOSTUNREACH in the first three minutes after boot
		// This is because mDNSResponder intentionally starts up early in the boot process (See <rdar://problem/3409090>)
		// but this means that sometimes it starts before configd has finished setting up the multicast routing entries.
		if (errno == EHOSTUNREACH && (mDNSu32)(mDNSPlatformRawTime()) < (mDNSu32)(mDNSPlatformOneSecond * 180)) return(mStatus_TransientErr);
		// Don't report EADDRNOTAVAIL ("Can't assign requested address") if we're in the middle of a network configuration change
		if (errno == EADDRNOTAVAIL && m->p->NetworkChanged) return(mStatus_TransientErr);
		LogMsg("mDNSPlatformSendUDP sendto failed to send packet on InterfaceID %p %5s/%ld to %#a:%d skt %d error %d errno %d (%s) %lu",
			InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s, err, errno, strerror(errno), (mDNSu32)(m->timenow));
		return(mStatus_UnknownErr);
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

	*ttl = 255;  // If kernel fails to provide TTL data (e.g. Jaguar doesn't) then assume the TTL was 255 as it should be

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
		if (errno != EWOULDBLOCK && numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) returned error %d errno %d", s, n, errno);
		return(-1);
		}
	if (msg.msg_controllen < (int)sizeof(struct cmsghdr))
		{
		if (numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) msg.msg_controllen %d < sizeof(struct cmsghdr) %lu",
			s, msg.msg_controllen, sizeof(struct cmsghdr));
		return(-1);
		}
	if (msg.msg_flags & MSG_CTRUNC)
		{
		if (numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) msg.msg_flags & MSG_CTRUNC", s);
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

// On entry, context points to our CFSocketSet
// If ss->info is NULL, we received this packet on our anonymous unicast socket
// If ss->info is non-NULL, we received this packet on port 5353 on the indicated interface
mDNSlocal void myCFSocketCallBack(CFSocketRef cfs, CFSocketCallBackType CallBackType, CFDataRef address, const void *data, void *context)
	{
	mDNSAddr senderAddr, destAddr;
	mDNSIPPort senderPort, destPort = MulticastDNSPort;
	const CFSocketSet *ss = (const CFSocketSet *)context;
	mDNS *const m = ss->m;
	mDNSInterfaceID InterfaceID = ss->info ? ss->info->ifinfo.InterfaceID : mDNSNULL;
	struct sockaddr_storage from;
	size_t fromlen = sizeof(from);
	char packetifname[IF_NAMESIZE] = "";
	int err, s1 = -1, skt = CFSocketGetNative(cfs);
	int count = 0;
	
	(void)address; // Parameter not used
	(void)data;    // Parameter not used
	
	if (CallBackType != kCFSocketReadCallBack)
		LogMsg("myCFSocketCallBack: Why is CallBackType %d not kCFSocketReadCallBack?", CallBackType);

	if      (cfs == ss->cfsv4) s1 = ss->sktv4;
	else if (cfs == ss->cfsv6) s1 = ss->sktv6;

	if (s1 < 0 || s1 != skt)
		{
		LogMsg("myCFSocketCallBack: s1 %d native socket %d, cfs %p", s1, skt, cfs);
		LogMsg("myCFSocketCallBack: cfsv4 %p, sktv4 %d", ss->cfsv4, ss->sktv4);
		LogMsg("myCFSocketCallBack: cfsv6 %p, sktv6 %d", ss->cfsv6, ss->sktv6);
		}

	mDNSu8 ttl;
	while ((err = myrecvfrom(s1, &m->imsg, sizeof(m->imsg), (struct sockaddr *)&from, &fromlen, &destAddr, packetifname, &ttl)) >= 0)
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

		if (mDNSAddrIsDNSMulticast(&destAddr))
			{
			// Even though we indicated a specific interface in the IP_ADD_MEMBERSHIP call, a weirdness of the
			// sockets API means that even though this socket has only officially joined the multicast group
			// on one specific interface, the kernel will still deliver multicast packets to it no matter which
			// interface they arrive on. According to the official Unix Powers That Be, this is Not A Bug.
			// To work around this weirdness, we use the IP_RECVIF option to find the name of the interface
			// on which the packet arrived, and ignore the packet if it really arrived on some other interface.
			if (!ss->info || !ss->info->Exists)
				{
				verbosedebugf("myCFSocketCallBack got multicast packet from %#a to %#a on unicast socket (Ignored)", &senderAddr, &destAddr);
				return;
				}
			else if (!strcmp(ss->info->ifa_name, packetifname))
				verbosedebugf("myCFSocketCallBack got multicast packet from %#a to %#a on interface %#a/%s",
					&senderAddr, &destAddr, &ss->info->ifinfo.ip, ss->info->ifa_name);
			else
				{
				verbosedebugf("myCFSocketCallBack got multicast packet from %#a to %#a on interface %#a/%s (Ignored -- really arrived on interface %s)",
					&senderAddr, &destAddr, &ss->info->ifinfo.ip, ss->info->ifa_name, packetifname);
				return;
				}
			}
		else
			{
			// Note: For unicast packets, try to find the matching mDNSCore interface object 
			// (though we may not be able to, for unicast packets received over something like a PPP link)
			NetworkInterfaceInfo *intf = m->HostInterfaces;
			while (intf && strcmp(intf->ifname, packetifname)) intf = intf->next;
			if (intf) InterfaceID = intf->InterfaceID;
			}

		mDNSCoreReceive(m, &m->imsg, (unsigned char*)&m->imsg + err, &senderAddr, senderPort, &destAddr, destPort, InterfaceID);
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
		if (numLogMessages > 5)
			NotifyOfElusiveBug("Flaw in Kernel (select/recvfrom mismatch)", 3375328,
				"Alternatively, you can send email to radar-3387020@group.apple.com. "
				"If possible, please leave your machine undisturbed so that someone can come to investigate the problem.");

		sleep(1);		// After logging this error, rate limit so we don't flood syslog
		}
	}

// TCP socket support for unicast DNS and Dynamic DNS Update

typedef struct
	{
    TCPConnectionCallback callback;
    void *context;
    int connected;
	} tcpInfo_t;

mDNSlocal void tcpCFSocketCallback(CFSocketRef cfs, CFSocketCallBackType CallbackType, CFDataRef address,
								   const void *data, void *context)
	{
	#pragma unused(CallbackType, address, data)
	mDNSBool connect = mDNSfalse;
	
	tcpInfo_t *info = context;
	if (!info->connected)
		{
		connect = mDNStrue;
		info->connected = mDNStrue;  // prevent connected flag from being set in future callbacks
		}
	info->callback(CFSocketGetNative(cfs), info->context, connect);
	// NOTE: the callback may call CloseConnection here, which frees the context structure!
	}

mDNSexport mStatus mDNSPlatformTCPConnect(const mDNSAddr *dst, mDNSOpaque16 dstport, mDNSInterfaceID InterfaceID,
										  TCPConnectionCallback callback, void *context, int *descriptor)
	{
	int sd, on = 1;  // "on" for setsockopt
	struct sockaddr_in saddr;
	CFSocketContext cfContext = { 0, NULL, 0, 0, 0 };
	tcpInfo_t *info;
	CFSocketRef sr;
	CFRunLoopSourceRef rls;
	
	(void)InterfaceID;	//!!!KRS use this if non-zero!!!

	*descriptor = 0;
	if (dst->type != mDNSAddrType_IPv4)
		{
		LogMsg("ERROR: mDNSPlatformTCPConnect - attempt to connect to an IPv6 address: opperation not supported");
		return mStatus_UnknownErr;
		}

	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = dstport.NotAnInteger;
	saddr.sin_len = sizeof(saddr);
	memcpy(&saddr.sin_addr, &dst->ip.v4.NotAnInteger, sizeof(saddr.sin_addr));

	// Don't send if it would cause dial on demand connection initiation.
	if (AddrRequiresPPPConnection((struct sockaddr *)&saddr))
		{
		debugf("mDNSPlatformTCPConnect: Surpressing sending to avoid dial-on-demand connection");
		return mStatus_UnknownErr;
		}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 3) { LogMsg("mDNSPlatformTCPConnect: socket error %d errno %d (%s)", sd, errno, strerror(errno)); return mStatus_UnknownErr; }

	// set non-blocking
	if (fcntl(sd, F_SETFL, O_NONBLOCK) < 0)
		{
		LogMsg("ERROR: setsockopt O_NONBLOCK - %s", strerror(errno));
		return mStatus_UnknownErr;
		}
	
	// receive interface identifiers
	if (setsockopt(sd, IPPROTO_IP, IP_RECVIF, &on, sizeof(on)) < 0)
		{
		LogMsg("setsockopt IP_RECVIF - %s", strerror(errno));
		return mStatus_UnknownErr;
		}
	// set up CF wrapper, add to Run Loop
	info = mallocL("mDNSPlatformTCPConnect", sizeof(tcpInfo_t));
	info->callback = callback;
	info->context = context;
	cfContext.info = info;
	sr = CFSocketCreateWithNative(kCFAllocatorDefault, sd, kCFSocketReadCallBack | kCFSocketConnectCallBack,
								  tcpCFSocketCallback, &cfContext);
	if (!sr)
		{
		LogMsg("ERROR: mDNSPlatformTCPConnect - CFSocketRefCreateWithNative failed");
		freeL("mDNSPlatformTCPConnect", info);
		return mStatus_UnknownErr;
		}

	rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, sr, 0);
	if (!rls)
		{
		LogMsg("ERROR: mDNSPlatformTCPConnect - CFSocketCreateRunLoopSource failed");
		freeL("mDNSPlatformTCPConnect", info);
		return mStatus_UnknownErr;
		}
	
	CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
	CFRelease(rls);
	
	// initiate connection wth peer
	if (connect(sd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		{
		if (errno == EINPROGRESS)
			{
			info->connected = 0;
			*descriptor= sd;
			return mStatus_ConnPending;
			}
		LogMsg("ERROR: mDNSPlatformTCPConnect - connect failed: %s", strerror(errno));
		freeL("mDNSPlatformTCPConnect", info);
		CFSocketInvalidate(sr);		// Note: Also closes the underlying socket
		return mStatus_ConnFailed;
		}
	info->connected = 1;
	*descriptor = sd;
	return mStatus_ConnEstablished;
	}

mDNSexport void mDNSPlatformTCPCloseConnection(int sd)
	{
	CFSocketContext cfContext;
	tcpInfo_t *info;
	CFSocketRef sr;

	if (sd < 3) LogMsg("mDNSPlatformTCPCloseConnection: ERROR sd %d < 3", sd);

    // Get the CFSocket for the descriptor
	sr = CFSocketCreateWithNative(kCFAllocatorDefault, sd, kCFSocketNoCallBack, NULL, NULL);
	if (!sr) { LogMsg("ERROR: mDNSPlatformTCPCloseConnection - CFSocketCreateWithNative returned NULL"); return; }

	CFSocketGetContext(sr, &cfContext);
	if (!cfContext.info)
		{
		LogMsg("ERROR: mDNSPlatformTCPCloseConnection - could not retreive tcpInfo from socket context");
		CFRelease(sr);
		return;
		}
	CFRelease(sr);  // this only releases the copy we allocated with CreateWithNative above
	
	info = cfContext.info;

	// Note: MUST NOT close the underlying native BSD socket.
	// CFSocketInvalidate() will do that for us, in its own good time, which may not necessarily be immediately,
	// because it first has to unhook the sockets from its select() call, before it can safely close them.
	CFSocketInvalidate(sr);
	CFRelease(sr);
	freeL("mDNSPlatformTCPCloseConnection", info);
	}

mDNSexport int mDNSPlatformReadTCP(int sd, void *buf, int buflen)
	{
	int nread = recv(sd, buf, buflen, 0);
	if (nread < 0)
		{
		if (errno == EAGAIN) return 0;  // no data available (call would block)
		LogMsg("ERROR: mDNSPlatformReadTCP - recv: %s", strerror(errno));
		return -1;
		}
	return nread;
	}

mDNSexport int mDNSPlatformWriteTCP(int sd, const char *msg, int len)
	{
	int nsent = send(sd, msg, len, 0);

	if (nsent < 0)
		{
		if (errno == EAGAIN) return 0;  // blocked
		LogMsg("ERROR: mDNSPlatformWriteTCP - sendL %s", strerror(errno));
		return -1;
		}
	return nsent;
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

// This gets the text of the field currently labelled "Local Hostname" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedLocalHostName(domainlabel *const namelabel)
	{
	CFStringRef cfs = SCDynamicStoreCopyLocalHostName(NULL);
	if (cfs)
		{
		CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
		CFRelease(cfs);
		}
	}

mDNSlocal mDNSBool DDNSSettingEnabled(CFDictionaryRef dict)
	{
	mDNSs32 val;
	CFNumberRef state = CFDictionaryGetValue(dict, CFSTR("Enabled"));
	if (!state) return mDNSfalse;
	if (!CFNumberGetValue(state, kCFNumberSInt32Type, &val)) { LogMsg("ERROR: DDNSSettingEnabled - CFNumberGetValue"); return mDNSfalse; }
	return val ? mDNStrue : mDNSfalse;
	}

mDNSlocal void GetUserSpecifiedDDNSConfig(domainname *const fqdn, domainname *const regDomain, CFArrayRef *const browseDomains)
	{
	char buf[MAX_ESCAPED_DOMAIN_NAME];

	fqdn->c[0] = 0;
	regDomain->c[0] = 0;
	buf[0] = 0;
	*browseDomains = NULL;
	
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:GetUserSpecifiedDDNSConfig"), NULL, NULL);
	if (store)
		{
		CFDictionaryRef dict = SCDynamicStoreCopyValue(store, CFSTR("Setup:/Network/DynamicDNS"));
		if (dict)
			{
			CFArrayRef fqdnArray = CFDictionaryGetValue(dict, CFSTR("HostNames"));
			if (fqdnArray && CFArrayGetCount(fqdnArray) > 0)
				{				
				CFDictionaryRef fqdnDict = CFArrayGetValueAtIndex(fqdnArray, 0); // for now, we only look at the first array element.  if we ever support multiple configurations, we will walk the list
				if (fqdnDict && DDNSSettingEnabled(fqdnDict))
					{						
					CFStringRef name = CFDictionaryGetValue(fqdnDict, CFSTR("Domain"));
					if (name)
						{
						if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) ||
							!MakeDomainNameFromDNSNameString(fqdn, buf) || !fqdn->c[0])
							LogMsg("GetUserSpecifiedDDNSConfig SCDynamicStore bad DDNS host name: %s", buf[0] ? buf : "(unknown)");
						else debugf("GetUserSpecifiedDDNSConfig SCDynamicStore DDNS host name: %s", buf);
						}
					}
				}

			CFArrayRef regArray = CFDictionaryGetValue(dict, CFSTR("RegistrationDomains"));
			if (regArray && CFArrayGetCount(regArray) > 0)
				{
				CFDictionaryRef regDict = CFArrayGetValueAtIndex(regArray, 0);
				if (regDict && DDNSSettingEnabled(regDict))
					{
					CFStringRef name = CFDictionaryGetValue(regDict, CFSTR("Domain"));
					if (name)
						{
						if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) ||
							!MakeDomainNameFromDNSNameString(regDomain, buf) || !regDomain->c[0])
							LogMsg("GetUserSpecifiedDDNSConfig SCDynamicStore bad DDNS registration domain: %s", buf[0] ? buf : "(unknown)");
						else debugf("GetUserSpecifiedDDNSConfig SCDynamicStore DDNS registration zone: %s", buf);
						}
					}
				}
			CFArrayRef browseArray = CFDictionaryGetValue(dict, CFSTR("BrowseDomains"));
			if (browseArray && CFArrayGetCount(browseArray) > 0)
				{
				CFRetain(browseArray);
				*browseDomains = browseArray;
				}
			CFRelease(dict);
			}
		CFRelease(store);
		}
	}

mDNSlocal void SetDDNSNameStatus(domainname *const dname, mStatus status)
	{
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:SetDDNSNameStatus"), NULL, NULL);
	if (store)
		{
		char uname[MAX_ESCAPED_DOMAIN_NAME];
		ConvertDomainNameToCString(dname, uname);
		char *p = uname;

		while (*p)
			{
			*p = tolower(*p);
			if (!(*(p+1)) && *p == '.') *p = 0; // if last character, strip trailing dot
			p++;
			}
		
		const void *StatusKey = CFSTR("Status");		
		const void *StatusVal = CFNumberCreate(NULL, kCFNumberSInt32Type, &status); // CFNumberRef
		const void *StatusDict = CFDictionaryCreate(NULL, &StatusKey, &StatusVal, 1, NULL, NULL);

		const void *HostKey = CFStringCreateWithCString(NULL, uname, kCFStringEncodingUTF8);
		const void *HostDict = CFDictionaryCreate(NULL, &HostKey, &StatusDict, 1, NULL, NULL);
				
		const void *StateKey = CFSTR("HostNames"); // CFStringRef
		CFDictionaryRef StateDict = CFDictionaryCreate(NULL, &StateKey, &HostDict, 1, NULL, NULL);
		SCDynamicStoreSetValue(store, CFSTR("State:/Network/DynamicDNS"), StateDict);

		CFRelease(StateDict);
		CFRelease(StateKey);
		CFRelease(HostDict);
		CFRelease(HostKey);
		CFRelease(StatusDict);
		CFRelease(StatusVal);
		CFRelease(StatusKey);
		CFRelease(store);
		}
	}

// If mDNSIPPort port is non-zero, then it's a multicast socket on the specified interface
// If mDNSIPPort port is zero, then it's a randomly assigned port number, used for sending unicast queries
mDNSlocal mStatus SetupSocket(mDNS *const m, CFSocketSet *cp, mDNSBool mcast, const mDNSAddr *ifaddr, u_short sa_family)
	{
	int         *s        = (sa_family == AF_INET) ? &cp->sktv4 : &cp->sktv6;
	CFSocketRef *c        = (sa_family == AF_INET) ? &cp->cfsv4 : &cp->cfsv6;
	CFRunLoopSourceRef *r = (sa_family == AF_INET) ? &cp->rlsv4 : &cp->rlsv6;
	const int on = 1;
	const int twofivefive = 255;
	mStatus err = mStatus_NoError;
	char *errstr = mDNSNULL;

	mDNSIPPort port = (mcast | m->CanReceiveUnicastOn5353) ? MulticastDNSPort : zeroIPPort;

	if (*s >= 0) { LogMsg("SetupSocket ERROR: socket %d is already set", *s); return(-1); }
	if (*c) { LogMsg("SetupSocket ERROR: CFSocketRef %p is already set", *c); return(-1); }

	// Open the socket...
	int skt = socket(sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (skt < 3) { LogMsg("SetupSocket: socket error %d errno %d (%s)", skt, errno, strerror(errno)); return(skt); }

	// ... with a shared UDP port, if it's for multicast receiving
	if (port.NotAnInteger) err = setsockopt(skt, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	if (err < 0) { errstr = "setsockopt - SO_REUSEPORT"; goto fail; }

	if (sa_family == AF_INET)
		{
		// We want to receive destination addresses
		err = setsockopt(skt, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IP_RECVDSTADDR"; goto fail; }
		
		// We want to receive interface identifiers
		err = setsockopt(skt, IPPROTO_IP, IP_RECVIF, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IP_RECVIF"; goto fail; }
		
		// We want to receive packet TTL value so we can check it
		err = setsockopt(skt, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
		// We ignore errors here -- we already know Jaguar doesn't support this, but we can get by without it
		
		// Add multicast group membership on this interface, if it's for multicast receiving
		if (mcast)
			{
			struct in_addr addr = { ifaddr->ip.v4.NotAnInteger };
			struct ip_mreq imr;
			imr.imr_multiaddr.s_addr = AllDNSLinkGroupv4.NotAnInteger;
			imr.imr_interface        = addr;
			err = setsockopt(skt, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr));
			if (err < 0) { errstr = "setsockopt - IP_ADD_MEMBERSHIP"; goto fail; }
			
			// Specify outgoing interface too
			err = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr));
			if (err < 0) { errstr = "setsockopt - IP_MULTICAST_IF"; goto fail; }
			}
		
		// Send unicast packets with TTL 255
		err = setsockopt(skt, IPPROTO_IP, IP_TTL, &twofivefive, sizeof(twofivefive));
		if (err < 0) { errstr = "setsockopt - IP_TTL"; goto fail; }
		
		// And multicast packets with TTL 255 too
		err = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_TTL, &twofivefive, sizeof(twofivefive));
		if (err < 0) { errstr = "setsockopt - IP_MULTICAST_TTL"; goto fail; }

		// Mark packets as high-throughput/low-delay (i.e. lowest reliability) to get maximum 802.11 multicast rate
		const int ip_tosbits = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
		err = setsockopt(skt, IPPROTO_IP, IP_TOS, &ip_tosbits, sizeof(ip_tosbits));
		if (err < 0) { errstr = "setsockopt - IP_TOS"; goto fail; }

		// And start listening for packets
		struct sockaddr_in listening_sockaddr;
		listening_sockaddr.sin_family      = AF_INET;
		listening_sockaddr.sin_port        = port.NotAnInteger;
		listening_sockaddr.sin_addr.s_addr = 0; // Want to receive multicasts AND unicasts on this socket
		err = bind(skt, (struct sockaddr *) &listening_sockaddr, sizeof(listening_sockaddr));
		if (err) { errstr = "bind"; goto fail; }
		}
	else if (sa_family == AF_INET6)
		{
		// We want to receive destination addresses and receive interface identifiers
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IPV6_PKTINFO"; goto fail; }
		
		// We want to receive packet hop count value so we can check it
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IPV6_HOPLIMIT"; goto fail; }
		
		// We want to receive only IPv6 packets, without this option, we may
		// get IPv4 addresses as mapped addresses.
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IPV6_V6ONLY"; goto fail; }
		
		if (mcast)
			{
			// Add multicast group membership on this interface, if it's for multicast receiving
			int interface_id = if_nametoindex(cp->info->ifa_name);
			struct ipv6_mreq i6mr;
			i6mr.ipv6mr_interface = interface_id;
			i6mr.ipv6mr_multiaddr = *(struct in6_addr*)&AllDNSLinkGroupv6;
			err = setsockopt(skt, IPPROTO_IPV6, IPV6_JOIN_GROUP, &i6mr, sizeof(i6mr));
			if (err < 0) { errstr = "setsockopt - IPV6_JOIN_GROUP"; goto fail; }
			
			// Specify outgoing interface too
			err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface_id, sizeof(interface_id));
			if (err < 0) { errstr = "setsockopt - IPV6_MULTICAST_IF"; goto fail; }
			}
		
		// Send unicast packets with TTL 255
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &twofivefive, sizeof(twofivefive));
		if (err < 0) { errstr = "setsockopt - IPV6_UNICAST_HOPS"; goto fail; }
		
		// And multicast packets with TTL 255 too
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &twofivefive, sizeof(twofivefive));
		if (err < 0) { errstr = "setsockopt - IPV6_MULTICAST_HOPS"; goto fail; }
		
		// Note: IPV6_TCLASS appears not to be implemented on OS X right now (or indeed on ANY version of Unix?)
		#ifdef IPV6_TCLASS
		// Mark packets as high-throughput/low-delay (i.e. lowest reliability) to get maximum 802.11 multicast rate
		int tclass = IPTOS_LOWDELAY | IPTOS_THROUGHPUT; // This may not be right (since tclass is not implemented on OS X, I can't test it)
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass));
		if (err < 0) { errstr = "setsockopt - IPV6_TCLASS"; goto fail; }
		#endif
		
		// Want to receive our own packets
		err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on));
		if (err < 0) { errstr = "setsockopt - IPV6_MULTICAST_LOOP"; goto fail; }
		
		// And start listening for packets
		struct sockaddr_in6 listening_sockaddr6;
		bzero(&listening_sockaddr6, sizeof(listening_sockaddr6));
		listening_sockaddr6.sin6_len         = sizeof(listening_sockaddr6);
		listening_sockaddr6.sin6_family      = AF_INET6;
		listening_sockaddr6.sin6_port        = port.NotAnInteger;
		listening_sockaddr6.sin6_flowinfo    = 0;
//		listening_sockaddr6.sin6_addr = IN6ADDR_ANY_INIT; // Want to receive multicasts AND unicasts on this socket
		listening_sockaddr6.sin6_scope_id    = 0;
		err = bind(skt, (struct sockaddr *) &listening_sockaddr6, sizeof(listening_sockaddr6));
		if (err) { errstr = "bind"; goto fail; }
		}
	
	fcntl(skt, F_SETFL, fcntl(skt, F_GETFL, 0) | O_NONBLOCK); // set non-blocking
	*s = skt;
	CFSocketContext myCFSocketContext = { 0, cp, NULL, NULL, NULL };
	*c = CFSocketCreateWithNative(kCFAllocatorDefault, *s, kCFSocketReadCallBack, myCFSocketCallBack, &myCFSocketContext);
	*r = CFSocketCreateRunLoopSource(kCFAllocatorDefault, *c, 0);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), *r, kCFRunLoopDefaultMode);
	
	return(err);

fail:
	LogMsg("%s error %ld errno %d (%s)", errstr, err, errno, strerror(errno));
	if (!strcmp(errstr, "bind") && errno == EADDRINUSE)
		NotifyOfElusiveBug("Setsockopt SO_REUSEPORT failed", 3814904,
			"Alternatively, you can send email to radar-3387020@group.apple.com. "
			"If possible, please leave your machine undisturbed so that someone can come to investigate the problem.");
	close(skt);
	return(err);
	}

mDNSlocal mStatus SetupAddr(mDNSAddr *ip, const struct sockaddr *const sa)
	{
	if (!sa) { LogMsg("SetupAddr ERROR: NULL sockaddr"); return(mStatus_Invalid); }

	if (sa->sa_family == AF_INET)
		{
		struct sockaddr_in *ifa_addr = (struct sockaddr_in *)sa;
		ip->type = mDNSAddrType_IPv4;
		ip->ip.v4.NotAnInteger = ifa_addr->sin_addr.s_addr;
		return(mStatus_NoError);
		}

	if (sa->sa_family == AF_INET6)
		{
		struct sockaddr_in6 *ifa_addr = (struct sockaddr_in6 *)sa;
		ip->type = mDNSAddrType_IPv6;
		if (IN6_IS_ADDR_LINKLOCAL(&ifa_addr->sin6_addr)) ifa_addr->sin6_addr.__u6_addr.__u6_addr16[1] = 0;
		ip->ip.v6 = *(mDNSv6Addr*)&ifa_addr->sin6_addr;
		return(mStatus_NoError);
		}

	LogMsg("SetupAddr invalid sa_family %d", sa->sa_family);
	return(mStatus_Invalid);
	}

mDNSlocal mDNSEthAddr GetBSSID(char *ifa_name)
	{
	mDNSEthAddr eth = zeroEthAddr;
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:GetBSSID"), NULL, NULL);
	if (store)
		{
		CFStringRef entityname = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Interface/%s/AirPort"), ifa_name);
		if (entityname)
			{
			CFDictionaryRef dict = SCDynamicStoreCopyValue(store, entityname);
			if (dict)
				{
				CFRange range = { 0, 6 };		// Offset, length
				CFDataRef data = CFDictionaryGetValue(dict, CFSTR("BSSID"));
				if (data && CFDataGetLength(data) == 6) CFDataGetBytes(data, range, eth.b);
				CFRelease(dict);
				}
			CFRelease(entityname);
			}
		CFRelease(store);
		}
	return(eth);
	}

mDNSlocal NetworkInterfaceInfoOSX *AddInterfaceToList(mDNS *const m, struct ifaddrs *ifa, mDNSs32 utc)
	{
	mDNSu32 scope_id  = if_nametoindex(ifa->ifa_name);
	mDNSEthAddr bssid = GetBSSID(ifa->ifa_name);

	mDNSAddr ip, mask;
	if (SetupAddr(&ip,   ifa->ifa_addr   ) != mStatus_NoError) return(NULL);
	if (SetupAddr(&mask, ifa->ifa_netmask) != mStatus_NoError) return(NULL);

	NetworkInterfaceInfoOSX **p;
	for (p = &m->p->InterfaceList; *p; p = &(*p)->next)
		if (scope_id == (*p)->scope_id && mDNSSameAddress(&ip, &(*p)->ifinfo.ip) && mDNSSameEthAddress(&bssid, &(*p)->BSSID))
			{
			debugf("AddInterfaceToList: Found existing interface %lu %.6a with address %#a at %p", scope_id, &bssid, &ip, *p);
			(*p)->Exists = mDNStrue;
			return(*p);
			}

	NetworkInterfaceInfoOSX *i = (NetworkInterfaceInfoOSX *)mallocL("NetworkInterfaceInfoOSX", sizeof(*i));
	debugf("AddInterfaceToList: Making   new   interface %lu %.6a with address %#a at %p", scope_id, &bssid, &ip, i);
	if (!i) return(mDNSNULL);
	bzero(i, sizeof(NetworkInterfaceInfoOSX));
	i->ifa_name        = (char *)mallocL("NetworkInterfaceInfoOSX name", strlen(ifa->ifa_name) + 1);
	if (!i->ifa_name) { freeL("NetworkInterfaceInfoOSX", i); return(mDNSNULL); }
	strcpy(i->ifa_name, ifa->ifa_name);

	i->ifinfo.InterfaceID = mDNSNULL;
	i->ifinfo.ip          = ip;
	i->ifinfo.mask        = mask;
	strncpy(i->ifinfo.ifname, ifa->ifa_name, sizeof(i->ifinfo.ifname));
	i->ifinfo.ifname[sizeof(i->ifinfo.ifname)-1] = 0;
	i->ifinfo.Advertise   = m->AdvertiseLocalAddresses;
	i->ifinfo.McastTxRx   = mDNSfalse; // For now; will be set up later at the end of UpdateInterfaceList
	
	i->next            = mDNSNULL;
	i->Exists          = mDNStrue;
	i->LastSeen        = utc;
	i->scope_id        = scope_id;
	i->BSSID           = bssid;
	i->sa_family       = ifa->ifa_addr->sa_family;
	i->Multicast       = (ifa->ifa_flags & IFF_MULTICAST) && !(ifa->ifa_flags & IFF_POINTOPOINT);

	i->ss.m     = m;
	i->ss.info  = i;
	i->ss.sktv4 = i->ss.sktv6 = -1;
	i->ss.cfsv4 = i->ss.cfsv6 = NULL;
	i->ss.rlsv4 = i->ss.rlsv6 = NULL;

	*p = i;
	return(i);
	}

mDNSlocal NetworkInterfaceInfoOSX *FindRoutableIPv4(mDNS *const m, mDNSu32 scope_id)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->Exists && i->scope_id == scope_id && i->ifinfo.ip.type == mDNSAddrType_IPv4)
			if (!(i->ifinfo.ip.ip.v4.b[0] == 169 && i->ifinfo.ip.ip.v4.b[1] == 254))
				return(i);
	return(mDNSNULL);
	}

mDNSlocal mStatus UpdateInterfaceList(mDNS *const m, mDNSs32 utc)
	{
	mDNSBool foundav4           = mDNSfalse;
	mDNSBool foundav6           = mDNSfalse;
	struct ifaddrs *ifa         = myGetIfAddrs(1);
	struct ifaddrs *v4Loopback  = NULL;
	struct ifaddrs *v6Loopback  = NULL;
	mDNSEthAddr PrimaryMAC      = zeroEthAddr;
	char defaultname[32];
	int InfoSocket              = socket(AF_INET6, SOCK_DGRAM, 0);
	if (InfoSocket < 3) LogMsg("UpdateInterfaceList: InfoSocket error %d errno %d (%s)", InfoSocket, errno, strerror(errno));
	if (m->SleepState) ifa = NULL;

	while (ifa)
		{
#if LIST_ALL_INTERFACES
		if (ifa->ifa_addr->sa_family == AF_APPLETALK)
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d is AF_APPLETALK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		else if (ifa->ifa_addr->sa_family == AF_LINK)
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d is AF_LINK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		else if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d not AF_INET (2) or AF_INET6 (30)",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (!(ifa->ifa_flags & IFF_UP))
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface not IFF_UP",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (!(ifa->ifa_flags & IFF_MULTICAST))
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface not IFF_MULTICAST",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface IFF_POINTOPOINT",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (ifa->ifa_flags & IFF_LOOPBACK)
			LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface IFF_LOOPBACK",
				ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
#endif

		if (ifa->ifa_addr->sa_family == AF_LINK)
			{
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == sizeof(PrimaryMAC) && mDNSSameEthAddress(&PrimaryMAC, &zeroEthAddr))
				mDNSPlatformMemCopy(sdl->sdl_data + sdl->sdl_nlen, PrimaryMAC.b, 6);
			}

		if (ifa->ifa_flags & IFF_UP && ifa->ifa_addr)
			if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)
				{
				if (!ifa->ifa_netmask)
					{
					mDNSAddr ip;
					SetupAddr(&ip, ifa->ifa_addr);
					LogMsg("getifaddrs: ifa_netmask is NULL for %5s(%d) Flags %04X Family %2d %#a",
						ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family, &ip);
					}
				else if (ifa->ifa_addr->sa_family != ifa->ifa_netmask->sa_family)
					{
					mDNSAddr ip;
					SetupAddr(&ip, ifa->ifa_addr);
					LogMsg("getifaddrs ifa_netmask for %5s(%d) Flags %04X Family %2d %#a has different family: %d",
						ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family, &ip, ifa->ifa_netmask->sa_family);
					}
				else
					{
					int ifru_flags6 = 0;
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
							if (ifa->ifa_addr->sa_family == AF_INET) v4Loopback = ifa;
							else                                     v6Loopback = ifa;
						else
							{
							AddInterfaceToList(m, ifa, utc);
							if (ifa->ifa_addr->sa_family == AF_INET) foundav4 = mDNStrue;
							else                                     foundav6 = mDNStrue;
							}
						}
					}
				}
		ifa = ifa->ifa_next;
		}

    // For efficiency, we don't register a loopback interface when other interfaces of that family are available
	if (!foundav4 && v4Loopback) AddInterfaceToList(m, v4Loopback, utc);
	if (!foundav6 && v6Loopback) AddInterfaceToList(m, v6Loopback, utc);

	// Now the list is complete, set the McastTxRx setting for each interface.
	// We always send and receive using IPv4.
	// To reduce traffic, we send and receive using IPv6 only on interfaces that have no routable IPv4 address.
	// Having a routable IPv4 address assigned is a reasonable indicator of being on a large configured network,
	// which means there's a good chance that most or all the other devices on that network should also have v4.
	// By doing this we lose the ability to talk to true v6-only devices on that link, but we cut the packet rate in half.
	// At this time, reducing the packet rate is more important than v6-only devices on a large configured network,
	// so we are willing to make that sacrifice.
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->Exists)
			{
			mDNSBool txrx = i->Multicast && ((i->ifinfo.ip.type == mDNSAddrType_IPv4) || !FindRoutableIPv4(m, i->scope_id));
			if (i->ifinfo.McastTxRx != txrx)
				{
				i->ifinfo.McastTxRx = txrx;
				i->Exists = 2; // State change; need to deregister and reregister this interface
				}
			}
	if (InfoSocket >= 0) close(InfoSocket);

	mDNS_snprintf(defaultname, sizeof(defaultname), "Macintosh-%02X%02X%02X%02X%02X%02X",
		PrimaryMAC.b[0], PrimaryMAC.b[1], PrimaryMAC.b[2], PrimaryMAC.b[3], PrimaryMAC.b[4], PrimaryMAC.b[5]);

	// Set up the nice label
	domainlabel nicelabel;
	nicelabel.c[0] = 0;
	GetUserSpecifiedFriendlyComputerName(&nicelabel);
	if (nicelabel.c[0] == 0)
		{
		LogMsg("Couldn't read user-specified Computer Name; using default “%s” instead", defaultname);
		MakeDomainLabelFromLiteralString(&nicelabel, defaultname);
		}

	// Set up the RFC 1034-compliant label
	domainlabel hostlabel;
	hostlabel.c[0] = 0;
	GetUserSpecifiedLocalHostName(&hostlabel);
	if (hostlabel.c[0] == 0)
		{
		LogMsg("Couldn't read user-specified local hostname; using default “%s.local” instead", defaultname);
		MakeDomainLabelFromLiteralString(&hostlabel, defaultname);
		}

	if (SameDomainLabel(m->p->usernicelabel.c, nicelabel.c))
		debugf("Usernicelabel (%#s) unchanged since last time; not changing m->nicelabel (%#s)", m->p->usernicelabel.c, m->nicelabel.c);
	else
		{
		debugf("Updating m->nicelabel to %#s", nicelabel.c);
		m->p->usernicelabel = m->nicelabel = nicelabel;
		}

	if (SameDomainLabel(m->p->userhostlabel.c, hostlabel.c))
		debugf("Userhostlabel (%#s) unchanged since last time; not changing m->hostlabel (%#s)", m->p->userhostlabel.c, m->hostlabel.c);
	else
		{
		debugf("Updating m->hostlabel to %#s", hostlabel.c);
		m->p->userhostlabel = m->hostlabel = hostlabel;
		mDNS_SetFQDN(m);
		}

	return(mStatus_NoError);
	}

mDNSlocal int CountMaskBits(mDNSAddr *mask)
	{
	int i = 0, bits = 0;
	int bytes = mask->type == mDNSAddrType_IPv4 ? 4 : mask->type == mDNSAddrType_IPv6 ? 16 : 0;
	while (i < bytes)
		{
		mDNSu8 b = mask->ip.v6.b[i++];
		while (b & 0x80) { bits++; b <<= 1; }
		if (b) return(-1);
		}
	while (i < bytes) if (mask->ip.v6.b[i++]) return(-1);
	return(bits);
	}

// returns count of non-link local V4 addresses registered
mDNSlocal int SetupActiveInterfaces(mDNS *const m, mDNSs32 utc)
	{
	NetworkInterfaceInfoOSX *i;
	int count = 0;
	for (i = m->p->InterfaceList; i; i = i->next)
		if (i->Exists)
			{
			NetworkInterfaceInfo *n = &i->ifinfo;
			NetworkInterfaceInfoOSX *primary = SearchForInterfaceByName(m, i->ifa_name, i->sa_family);
			if (!primary) LogMsg("SetupActiveInterfaces ERROR! SearchForInterfaceByName didn't find %s", i->ifa_name);
	
			if (n->InterfaceID && n->InterfaceID != (mDNSInterfaceID)primary)	// Sanity check
				{
				LogMsg("SetupActiveInterfaces ERROR! n->InterfaceID %p != primary %p", n->InterfaceID, primary);
				n->InterfaceID = mDNSNULL;
				}
	
			if (!n->InterfaceID)
				{
				// NOTE: If n->InterfaceID is set, that means we've called mDNS_RegisterInterface() for this interface,
				// so we need to make sure we call mDNS_DeregisterInterface() before disposing it.
				// If n->InterfaceID is NOT set, then we haven't registered it and we should not try to deregister it
				n->InterfaceID = (mDNSInterfaceID)primary;
				// If i->LastSeen == utc, then this is a brand-new interface, just created, or an interface that never went away.
				// If i->LastSeen != utc, then this is an old interface, previously seen, that went away for (utc - i->LastSeen) seconds.
				// If the interface is an old one that went away and came back in less than a minute, then we're in a flapping scenario.
				mDNSBool flapping = (utc - i->LastSeen > 0 && utc - i->LastSeen < 60);
				mDNS_RegisterInterface(m, n, flapping ? mDNSPlatformOneSecond * 5 : 0);
				if (i->ifinfo.ip.type == mDNSAddrType_IPv4 &&  (i->ifinfo.ip.ip.v4.b[0] != 169 || i->ifinfo.ip.ip.v4.b[1] != 254)) count++;
				LogOperation("SetupActiveInterfaces:   Registered    %5s(%lu) %.6a InterfaceID %p %#a/%d%s%s",
					i->ifa_name, i->scope_id, &i->BSSID, primary, &n->ip, CountMaskBits(&n->mask),
					flapping ? " (Flapping)" : "", n->InterfaceActive ? " (Primary)" : "");
				}
	
			if (!n->McastTxRx)
				debugf("SetupActiveInterfaces:   No Tx/Rx on   %5s(%lu) %.6a InterfaceID %p %#a", i->ifa_name, i->scope_id, &i->BSSID, primary, &n->ip);
			else
				{
				if (i->sa_family == AF_INET && primary->ss.sktv4 == -1)
					{
					mStatus err = SetupSocket(m, &primary->ss, mDNStrue, &i->ifinfo.ip, AF_INET);
					if (err == 0) debugf("SetupActiveInterfaces:   v4 socket%2d %5s(%lu) %.6a InterfaceID %p %#a/%d",          primary->ss.sktv4, i->ifa_name, i->scope_id, &i->BSSID, n->InterfaceID, &n->ip, CountMaskBits(&n->mask));
					else          LogMsg("SetupActiveInterfaces:   v4 socket%2d %5s(%lu) %.6a InterfaceID %p %#a/%d FAILED",   primary->ss.sktv4, i->ifa_name, i->scope_id, &i->BSSID, n->InterfaceID, &n->ip, CountMaskBits(&n->mask));
					}
			
				if (i->sa_family == AF_INET6 && primary->ss.sktv6 == -1)
					{
					mStatus err = SetupSocket(m, &primary->ss, mDNStrue, &i->ifinfo.ip, AF_INET6);
					if (err == 0) debugf("SetupActiveInterfaces:   v6 socket%2d %5s(%lu) %.6a InterfaceID %p %#a/%d",          primary->ss.sktv6, i->ifa_name, i->scope_id, &i->BSSID, n->InterfaceID, &n->ip, CountMaskBits(&n->mask));
					else          LogMsg("SetupActiveInterfaces:   v6 socket%2d %5s(%lu) %.6a InterfaceID %p %#a/%d FAILED",   primary->ss.sktv6, i->ifa_name, i->scope_id, &i->BSSID, n->InterfaceID, &n->ip, CountMaskBits(&n->mask));
					}
				}
			}
	return count;
	}

mDNSlocal void MarkAllInterfacesInactive(mDNS *const m, mDNSs32 utc)
	{
	NetworkInterfaceInfoOSX *i;
	for (i = m->p->InterfaceList; i; i = i->next)
		{
		if (i->Exists) i->LastSeen = utc;
		i->Exists = mDNSfalse;
		}
	}

mDNSlocal void CloseRunLoopSourceSocket(CFRunLoopSourceRef rls, CFSocketRef cfs)
	{
	// Note: CFSocketInvalidate also closes the underlying socket for us
	// Comments show retain counts (obtained via CFGetRetainCount()) after each call.	   rls 3 cfs 3
	CFRunLoopRemoveSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);			// rls 2 cfs 3
	CFRelease(rls);																		// rls ? cfs 3
	CFSocketInvalidate(cfs);															// rls ? cfs 1
	CFRelease(cfs);																		// rls ? cfs ?
	}

mDNSlocal void CloseSocketSet(CFSocketSet *ss)
	{
	// Note: MUST NOT close the underlying native BSD sockets.
	// CFSocketInvalidate() will do that for us, in its own good time, which may not necessarily be immediately,
	// because it first has to unhook the sockets from its select() call, before it can safely close them.
	if (ss->cfsv4) CloseRunLoopSourceSocket(ss->rlsv4, ss->cfsv4);
	if (ss->cfsv6) CloseRunLoopSourceSocket(ss->rlsv6, ss->cfsv6);
	ss->sktv4 = ss->sktv6 = -1;
	ss->cfsv4 = ss->cfsv6 = NULL;
	ss->rlsv4 = ss->rlsv6 = NULL;
	}

// returns count of non-link local V4 addresses deregistered
mDNSlocal int ClearInactiveInterfaces(mDNS *const m, mDNSs32 utc)
	{
	// First pass:
	// If an interface is going away, then deregister this from the mDNSCore.
	// We also have to deregister it if the primary interface that it's using for its InterfaceID is going away.
	// We have to do this because mDNSCore will use that InterfaceID when sending packets, and if the memory
	// it refers to has gone away we'll crash.
	// Don't actually close the sockets or free the memory yet: When the last representative of an interface goes away
	// mDNSCore may want to send goodbye packets on that interface. (Not yet implemented, but a good idea anyway.)
	NetworkInterfaceInfoOSX *i;
	int count = 0;
	for (i = m->p->InterfaceList; i; i = i->next)
		{
		// 1. If this interface is no longer active, or its InterfaceID is changing, deregister it
		NetworkInterfaceInfoOSX *primary = SearchForInterfaceByName(m, i->ifa_name, i->sa_family);
		if (i->ifinfo.InterfaceID)
			if (i->Exists == 0 || i->Exists == 2 || i->ifinfo.InterfaceID != (mDNSInterfaceID)primary)
				{
				LogOperation("ClearInactiveInterfaces: Deregistering %5s(%lu) %.6a InterfaceID %p %#a/%d%s",
					i->ifa_name, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID,
					&i->ifinfo.ip, CountMaskBits(&i->ifinfo.mask), i->ifinfo.InterfaceActive ? " (Primary)" : "");
				mDNS_DeregisterInterface(m, &i->ifinfo);
				if (i->ifinfo.ip.type == mDNSAddrType_IPv4 && (i->ifinfo.ip.ip.v4.b[0] != 169 || i->ifinfo.ip.ip.v4.b[1] != 254)) count++;
				i->ifinfo.InterfaceID = mDNSNULL;
				// NOTE: If n->InterfaceID is set, that means we've called mDNS_RegisterInterface() for this interface,
				// so we need to make sure we call mDNS_DeregisterInterface() before disposing it.
				// If n->InterfaceID is NOT set, then it's not registered and we should not call mDNS_DeregisterInterface() on it.
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
		CloseSocketSet(&i->ss);
		// 3. If no longer active, delete interface from list and free memory
		if (!i->Exists)
			{
			if (i->LastSeen == utc) i->LastSeen = utc - 1;
			mDNSBool delete = (NumCacheRecordsForInterfaceID(m, (mDNSInterfaceID)i) == 0) && (utc - i->LastSeen >= 60);
			LogOperation("ClearInactiveInterfaces: %-13s %5s(%lu) %.6a InterfaceID %p %#a/%d Age %d%s", delete ? "Deleting" : "Holding",
				i->ifa_name, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID,
				&i->ifinfo.ip, CountMaskBits(&i->ifinfo.mask), utc - i->LastSeen,
				i->ifinfo.InterfaceActive ? " (Primary)" : "");
			if (delete)
				{
				*p = i->next;
				if (i->ifa_name) freeL("NetworkInterfaceInfoOSX name", i->ifa_name);
				freeL("NetworkInterfaceInfoOSX", i);
				continue;	// After deleting this object, don't want to do the "p = &i->next;" thing at the end of the loop
				}
			}
		p = &i->next;
		}
	return count;
	}

mDNSlocal mStatus GetDNSConfig(void **result)
	{
#if MDNS_NO_DNSINFO
	static int MessageShown = 0;
	if (!MessageShown) { MessageShown = 1; LogMsg("Note: Compiled without Apple-specific Split-DNS support"); }
	*result = NULL;
	return mStatus_UnsupportedErr;
#else

	*result = dns_configuration_copy();

	if (!*result)
		{
		// When running on 10.3 (build 7xxx) and earlier, we don't expect dns_configuration_copy() to succeed
		if (mDNSMacOSXSystemBuildNumber(NULL) < 8) return mStatus_UnsupportedErr;

		// On 10.4, calls to dns_configuration_copy() early in the boot process often fail.
		// Apparently this is expected behaviour -- "not a bug".
		// Accordingly, we suppress syslog messages for the first three minutes after boot.
		// If we are still getting failures after three minutes, then we log them.
		if ((mDNSu32)(mDNSPlatformRawTime()) < (mDNSu32)(mDNSPlatformOneSecond * 180)) return mStatus_NoError;

		LogMsg("GetDNSConfig: Error: dns_configuration_copy returned NULL");
		return mStatus_UnknownErr;
		}
	return mStatus_NoError;
#endif // MDNS_NO_DNSINFO
	}

mDNSlocal mStatus RegisterSplitDNS(mDNS *m, int *nAdditions, int *nDeletions)
	{
	(void)m;  // unused on 10.3 systems
	void *v;
	*nAdditions = *nDeletions = 0;
	mStatus err = GetDNSConfig(&v);

#if !MDNS_NO_DNSINFO
	if (!err && v)
		{
		int i;
		DNSServer *p;
		dns_config_t *config = v;  // use void * to allow compilation on 10.3 systems
		mDNS_Lock(m);
		p = m->uDNS_info.Servers;
		while (p) { p->flag = -1; p = p->next; }  // mark all for deletion
		
		LogOperation("RegisterSplitDNS: Registering %d resolvers", config->n_resolver);
		for (i = 0; i < config->n_resolver; i++)		
			{
			int j, n;
			domainname d;
			dns_resolver_t *r = config->resolver[i];
			if (r->port == MulticastDNSPort.NotAnInteger) continue; // ignore configurations for .local
			if (r->search_order == DEFAULT_SEARCH_ORDER || !r->domain || !*r->domain) d.c[0] = 0; // we ignore domain for "default" resolver
			else if (!MakeDomainNameFromDNSNameString(&d, r->domain)) { LogMsg("RegisterSplitDNS: bad domain %s", r->domain); continue; }
			
			// check if this is the lowest-weighted server for the domain
			for (j = 0; j < config->n_resolver; j++)
				{
				dns_resolver_t *p = config->resolver[j];
				if (p->port == MulticastDNSPort.NotAnInteger) continue;
				if (p->search_order <= r->search_order)
					{
					domainname tmp;				
					if (p->search_order == DEFAULT_SEARCH_ORDER || !p->domain || !*p->domain) tmp.c[0] = '\0';
					else if (!MakeDomainNameFromDNSNameString(&tmp, p->domain)) { LogMsg("RegisterSplitDNS: bad domain %s", p->domain); continue; }
					if (SameDomainName(&d, &tmp))
						if (p->search_order < r->search_order || j < i) break;  // if equal weights, pick first in list, otherwise pick lower-weight (p)
					}
				}
			if (j < config->n_resolver) // found a lower-weighted resolver for this domain
				{ debugf("Rejecting DNS server in slot %d domain %##s (slot %d outranks)", i, d.c, j); continue; }
			// we're using this resolver - find the first IPv4 address
			for (n = 0; n < r->n_nameserver; n++)
				{
				if (r->nameserver[n]->sa_family == AF_INET && !AddrRequiresPPPConnection(r->nameserver[n]))
					{
					mDNSAddr saddr;
					if (SetupAddr(&saddr, r->nameserver[n])) { LogMsg("RegisterSplitDNS: bad IP address"); continue; }
					debugf("Adding dns server from slot %d %d.%d.%d.%d for domain %##s", i, saddr.ip.v4.b[0], saddr.ip.v4.b[1], saddr.ip.v4.b[2], saddr.ip.v4.b[3], d.c);
					p = m->uDNS_info.Servers;					
					while (p)
						{
						if (mDNSSameAddress(&p->addr, &saddr) && SameDomainName(&p->domain, &d)) { p->flag = 0; break; }
						else p = p->next;
						}
					if (!p)
						{
						p = mallocL("DNSServer", sizeof(*p));
						if (!p) { LogMsg("Error: malloc");  mDNS_Unlock(m); return mStatus_UnknownErr; }
						p->addr = saddr;
						AssignDomainName(&p->domain, &d);
						p->flag = 0;
						p->next = m->uDNS_info.Servers;
						m->uDNS_info.Servers = p;
						(*nAdditions)++;
						}
					break;  // !!!KRS if we ever support round-robin servers, don't break here
					}
				}
			}

		// remove all servers marked for deletion
		DNSServer **s = &m->uDNS_info.Servers;
		while (*s)
			{
			if ((*s)->flag < 0)
				{
				p = *s;
				*s = (*s)->next;
				freeL("DNSServer", p);
				(*nDeletions)--;
				}
			else s = &(*s)->next;
			}
		mDNS_Unlock(m);
		dns_configuration_free(config);
		}
#endif

	return err;
	}

mDNSlocal mStatus RegisterNameServers(mDNS *const m, CFDictionaryRef dict)
	{
	int i, count;
	CFArrayRef values;
	char buf[256];
	mDNSAddr saddr = { mDNSAddrType_IPv4, { { { 0 } } } };
	CFStringRef s;

	mDNS_DeleteDNSServers(m); // deregister orig list
	values = CFDictionaryGetValue(dict, kSCPropNetDNSServerAddresses);
	if (!values) return mStatus_NoError;

	count = CFArrayGetCount(values);
	for (i = 0; i < count; i++)
		{
		s = CFArrayGetValueAtIndex(values, i);
		if (!s) { LogMsg("ERROR: RegisterNameServers - CFArrayGetValueAtIndex"); break; }
		if (!CFStringGetCString(s, buf, 256, kCFStringEncodingUTF8))
			{
			LogMsg("ERROR: RegisterNameServers - CFStringGetCString");
			continue;
			}
		if (!inet_aton(buf, (struct in_addr *)saddr.ip.v4.b))
			{
			LogMsg("ERROR: RegisterNameServers - invalid address string %s", buf);
			continue;
			}
		LogOperation("RegisterNameServers: Adding %#a", &saddr);
		mDNS_AddDNSServer(m, &saddr, NULL);
		}
	return mStatus_NoError;
	}

mDNSlocal void FreeARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
	{
	(void)m;  // unused
	ARListElem *elem = rr->RecordContext;
	if (result == mStatus_MemFree) freeL("FreeARElemCallback", elem);
	}

mDNSlocal void FoundDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	SearchListElem *slElem = question->QuestionContext;
	ARListElem *arElem, *ptr, *prev;
    AuthRecord *dereg;
	const char *name;
	mStatus err;
	
	if (AddRecord)
		{
		arElem = mallocL("FoundDomain - arElem", sizeof(ARListElem));
		if (!arElem) { LogMsg("ERROR: malloc");  return; }
		mDNS_SetupResourceRecord(&arElem->ar, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200,  kDNSRecordTypeShared, FreeARElemCallback, arElem);
		if      (question == &slElem->BrowseQ)       name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowse];
		else if (question == &slElem->DefBrowseQ)    name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseDefault];
		else if (question == &slElem->LegacyBrowseQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseLegacy];
		else if (question == &slElem->RegisterQ)     name = mDNS_DomainTypeNames[mDNS_DomainTypeRegistration];
		else if (question == &slElem->DefRegisterQ)  name = mDNS_DomainTypeNames[mDNS_DomainTypeRegistrationDefault];
		else { LogMsg("FoundDomain - unknown question"); return; }
		
		MakeDomainNameFromDNSNameString(arElem->ar.resrec.name, name);
		AppendDNSNameString            (arElem->ar.resrec.name, "local");
		AssignDomainName(&arElem->ar.resrec.rdata->u.name, &answer->rdata->u.name);
		err = mDNS_Register(m, &arElem->ar);
		if (err)
			{
			LogMsg("ERROR: FoundDomain - mDNS_Register returned %d", err);
			freeL("FoundDomain - arElem", arElem);
			return;
			}
		arElem->next = slElem->AuthRecs;
		slElem->AuthRecs = arElem;
		}
	else
		{
		ptr = slElem->AuthRecs;
		prev = NULL;
		while (ptr)
			{
			if (SameDomainName(&ptr->ar.resrec.rdata->u.name, &answer->rdata->u.name))
				{
				debugf("Deregistering PTR %s -> %s", ptr->ar.resrec.name->c, ptr->ar.resrec.rdata->u.name.c);
                dereg = &ptr->ar;
				if (prev) prev->next = ptr->next;
				else slElem->AuthRecs = ptr->next;
                ptr = ptr->next;
				err = mDNS_Deregister(m, dereg);
				if (err) LogMsg("ERROR: FoundDomain - mDNS_Deregister returned %d", err);
				}
			else
				{
				prev = ptr;
				ptr = ptr->next;
				}
			}
		}
	}

mDNSlocal void MarkSearchListElem(const char *d)
	{
	SearchListElem *new, *ptr;
	domainname domain;
	
	if (!MakeDomainNameFromDNSNameString(&domain, d))
		{ LogMsg("ERROR: MarkSearchListElem - bad domain %##s", d); return; }

	if (SameDomainName(&domain, &localdomain) || SameDomainName(&domain, &LocalReverseMapomain))
		{ debugf("MarkSearchListElem - ignoring local domain %##s", domain.c); return; } 

	// if domain is in list, mark as pre-existent (0)
	for (ptr = SearchList; ptr; ptr = ptr->next)
		if (SameDomainName(&ptr->domain, &domain))
			{
			if (ptr->flag != 1) ptr->flag = 0;  // gracefully handle duplicates - if it is already marked as add, don't bump down to preexistent
			break;
			}
	
	// if domain not in list, add to list, mark as add (1)
	if (!ptr)
		{
		new = mallocL("MarkSearchListElem - SearchListElem", sizeof(SearchListElem));
		if (!new) { LogMsg("ERROR: MarkSearchListElem - malloc"); return; }
		bzero(new, sizeof(SearchListElem));
		AssignDomainName(&new->domain, &domain);
		new->flag = 1;  // add
		new->next = SearchList;
		SearchList = new;
		}
	}

// Get the search domains via OS X resolver routines.  Returns mStatus_UnsupporterErr if compiled or run on 10.3 systems
mDNSlocal mStatus GetSearchDomains(void)
	{
	void *v;
	mStatus err = GetDNSConfig(&v);

#if !MDNS_NO_DNSINFO
	if (!err && v)
		{
		int i;
		dns_config_t *config = v;
		if (!config->n_resolver) return err;
		dns_resolver_t *resolv = config->resolver[0];  // use the first slot for search domains

		for (i = 0; i < resolv->n_search; i++) MarkSearchListElem(resolv->search[i]);
		if (resolv->domain) MarkSearchListElem(resolv->domain);
		dns_configuration_free(config);
		}
#endif

	return err;
	}

// Get search domains from dynamic store - used as a fallback mechanism on 10.3 systems, if GetSearchDomains (above) fails.
mDNSlocal void GetDSSearchDomains(CFDictionaryRef dict)
	{
	char buf[MAX_ESCAPED_DOMAIN_NAME];
	int i, count;

	CFStringRef s;

	// get all the domains from "Search Domains" field of sharing prefs
	if (dict)
		{
		CFArrayRef searchdomains = CFDictionaryGetValue(dict, kSCPropNetDNSSearchDomains);
		if (searchdomains)
			{
			count = CFArrayGetCount(searchdomains);
			for (i = 0; i < count; i++)
				{
				s = CFArrayGetValueAtIndex(searchdomains, i);
				if (!s) { LogMsg("ERROR: GetDSSearchDomains - CFArrayGetValueAtIndex"); break; }
				if (!CFStringGetCString(s, buf, MAX_ESCAPED_DOMAIN_NAME, kCFStringEncodingUTF8))
					{
					LogMsg("ERROR: GetDSSearchDomains - CFStringGetCString");
					continue;
					}
				MarkSearchListElem(buf);
				}
			}

		// get DHCP domain field
		CFStringRef dname = CFDictionaryGetValue(dict, kSCPropNetDNSDomainName);
		if (dname)
			{
			if (CFStringGetCString(dname, buf, MAX_ESCAPED_DOMAIN_NAME, kCFStringEncodingUTF8))
				MarkSearchListElem(buf);
			else LogMsg("ERROR: GetDSSearchDomains - CFStringGetCString");
			}
		}
	}

mDNSlocal mStatus RegisterSearchDomains(mDNS *const m, CFDictionaryRef dict)
	{
	struct ifaddrs *ifa = NULL;
	SearchListElem *ptr, *prev, *freeSLPtr;
	ARListElem *arList;
	mStatus err;

	if (DomainDiscoveryDisabled) return mStatus_NoError;
	
	// step 1: mark each elem for removal (-1), unless we aren't passed a dictionary in which case we mark as preexistent
	for (ptr = SearchList; ptr; ptr = ptr->next) ptr->flag = dict ? -1 : 0;

	// Get search domains from resolver library (available in OS X 10.4 and later), reverting to dynamic store on 10.3 systems
	if (GetSearchDomains() == mStatus_UnsupportedErr) GetDSSearchDomains(dict);
 	
	// Construct reverse-map search domains
	ifa = myGetIfAddrs(1);
	while (ifa)
		{
		mDNSAddr addr;
		if (ifa->ifa_addr->sa_family == AF_INET && !SetupAddr(&addr, ifa->ifa_addr) && !IsPrivateV4Addr(&addr) && !(ifa->ifa_flags & IFF_LOOPBACK) && ifa->ifa_netmask)
			{
			mDNSAddr netmask;
			char buffer[256];
			if (!SetupAddr(&netmask, ifa->ifa_netmask))
				{
				sprintf(buffer, "%d.%d.%d.%d.in-addr.arpa.", addr.ip.v4.b[3] & netmask.ip.v4.b[3],
                                                             addr.ip.v4.b[2] & netmask.ip.v4.b[2],
                                                             addr.ip.v4.b[1] & netmask.ip.v4.b[1],
                                                             addr.ip.v4.b[0] & netmask.ip.v4.b[0]);
				MarkSearchListElem(buffer);
				}
			}
		ifa = ifa->ifa_next;
		}
	
	// delete elems marked for removal, do queries for elems marked add
	prev = NULL;
	ptr = SearchList;
	while (ptr)
		{
		if (ptr->flag == -1)  // remove
			{
			mDNS_StopQuery(m, &ptr->BrowseQ);
			mDNS_StopQuery(m, &ptr->RegisterQ);
			mDNS_StopQuery(m, &ptr->DefBrowseQ);
			mDNS_StopQuery(m, &ptr->DefRegisterQ);
			mDNS_StopQuery(m, &ptr->LegacyBrowseQ);			
			
            // deregister records generated from answers to the query
			arList = ptr->AuthRecs;
			ptr->AuthRecs = NULL;
			while (arList)
				{
				AuthRecord *dereg = &arList->ar;
				arList = arList->next;
				debugf("Deregistering PTR %s -> %s", dereg->resrec.name->c, dereg->resrec.rdata->u.name.c);
				err = mDNS_Deregister(m, dereg);
				if (err) LogMsg("ERROR: RegisterSearchDomains mDNS_Deregister returned %d", err);
				}
			
			// remove elem from list, delete
			if (prev) prev->next = ptr->next;
			else SearchList = ptr->next;
			freeSLPtr = ptr;
			ptr = ptr->next;
			freeL("RegisterSearchDomains - freeSLPtr", freeSLPtr);
			continue;
			}
		
		if (ptr->flag == 1)  // add
			{
			mStatus err1, err2, err3, err4, err5;
			err1 = mDNS_GetDomains(m, &ptr->BrowseQ,       mDNS_DomainTypeBrowse,              &ptr->domain, mDNSInterface_Any, FoundDomain, ptr);
			err2 = mDNS_GetDomains(m, &ptr->DefBrowseQ,    mDNS_DomainTypeBrowseDefault,       &ptr->domain, mDNSInterface_Any, FoundDomain, ptr);
			err3 = mDNS_GetDomains(m, &ptr->RegisterQ,     mDNS_DomainTypeRegistration,        &ptr->domain, mDNSInterface_Any, FoundDomain, ptr);
			err4 = mDNS_GetDomains(m, &ptr->DefRegisterQ,  mDNS_DomainTypeRegistrationDefault, &ptr->domain, mDNSInterface_Any, FoundDomain, ptr);
			err5 = mDNS_GetDomains(m, &ptr->LegacyBrowseQ, mDNS_DomainTypeBrowseLegacy,        &ptr->domain, mDNSInterface_Any, FoundDomain, ptr);
			if (err1 || err2 || err3 || err4 || err5)
				LogMsg("GetDomains for domain %##s returned error(s):\n"
					   "%d (mDNS_DomainTypeBrowse)\n"
					   "%d (mDNS_DomainTypeBrowseDefault)\n"
					   "%d (mDNS_DomainTypeRegistration)\n"
					   "%d (mDNS_DomainTypeRegistrationDefault)"
					   "%d (mDNS_DomainTypeBrowseLegacy)\n",
					   ptr->domain.c, err1, err2, err3, err4, err5);   
			ptr->flag = 0;
			}
		
		if (ptr->flag) { LogMsg("RegisterSearchDomains - unknown flag %d.  Skipping.", ptr->flag); }
		
		prev = ptr;
		ptr = ptr->next;
		}
	
	return mStatus_NoError;
	}

//!!!KRS here is where we will give success/failure notification to the UI
mDNSlocal void SCPrefsDynDNSCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
	{
	(void)m;  // unused
	debugf("SCPrefsDynDNSCallback: result %d for registration of name %##s", result, rr->resrec.name->c);
	SetDDNSNameStatus(rr->resrec.name, result);
	}

mDNSlocal void SetSecretForDomain(mDNS *m, const domainname *domain)
	{
	OSStatus err = 0;
	char dstring[MAX_ESCAPED_DOMAIN_NAME];
	mDNSu32 secretlen;
	void *secret = NULL;
	domainname *d, canon;
	int i, dlen;
	mDNSu32 type = 'ddns';
	mDNSu32 typelen = sizeof(type);	
	char *failedfn = "(none)";
	SecKeychainAttributeList *attrList = NULL;
	SecKeychainItemRef itemRef = NULL;
	
	err = SecKeychainSetPreferenceDomain(kSecPreferencesDomainSystem);
	if (err) { failedfn = "SecKeychainSetPreferenceDomain"; goto cleanup; }
	
	// canonicalize name by converting to lower case (keychain and some name servers are case sensitive)
	ConvertDomainNameToCString(domain, dstring);
	dlen = strlen(dstring);
	for (i = 0; i < dlen; i++) dstring[i] = tolower(dstring[i]);  // canonicalize -> lower case
	MakeDomainNameFromDNSNameString(&canon, dstring);
	d = &canon;		
	
	// find longest-match key, excluding last label (e.g. excluding ".com")
	while (d->c[0] && *(d->c + d->c[0] + 1))
		{
		if (!ConvertDomainNameToCString(d, dstring)) { LogMsg("SetSecretForDomain: bad domain %##s", d->c); return; }	
		dlen = strlen(dstring);		
		if (dstring[dlen-1] == '.') { dstring[dlen-1] = '\0'; dlen--; }  // chop trailing dot
		SecKeychainAttribute attrs[] = { { kSecServiceItemAttr, strlen(dstring), dstring },
										 { kSecTypeItemAttr, typelen, (UInt32 *)&type } };
		SecKeychainAttributeList attributes = { sizeof(attrs) / sizeof(attrs[0]), attrs };
		SecKeychainSearchRef searchRef;

		err = SecKeychainSearchCreateFromAttributes(NULL, kSecGenericPasswordItemClass, &attributes, &searchRef);
		if (err) { failedfn = "SecKeychainSearchCreateFromAttributes"; goto cleanup; }

		err = SecKeychainSearchCopyNext(searchRef, &itemRef);
		if (!err)
			{
	        mDNSu32 tags[1];
			SecKeychainAttributeInfo attrInfo;
			mDNSu32 i;
			char keybuf[MAX_ESCAPED_DOMAIN_NAME+1];			
			domainname keyname;
			
			tags[0] = kSecAccountItemAttr;
			attrInfo.count = 1;
			attrInfo.tag = tags;
			attrInfo.format = NULL;
			
			err = SecKeychainItemCopyAttributesAndData(itemRef,  &attrInfo, NULL, &attrList, &secretlen, &secret);
			if (err || !attrList) { failedfn = "SecKeychainItemCopyAttributesAndData"; goto cleanup; }
			if (!secretlen || !secret) { LogMsg("SetSecretForDomain - bad shared secret"); return; }
			if (((char *)secret)[secretlen-1]) { LogMsg("SetSecretForDomain - Shared secret not NULL-terminated"); goto cleanup; }
			
			for (i = 0; i < attrList->count; i++)
				{
				SecKeychainAttribute attr = attrList->attr[i];
				if (attr.tag == kSecAccountItemAttr)
					{
					if (!attr.length || attr.length > MAX_ESCAPED_DOMAIN_NAME) { LogMsg("SetSecretForDomain - Bad key length %d", attr.length); goto cleanup; }					
					strncpy(keybuf, attr.data, attr.length);
					if (!MakeDomainNameFromDNSNameString(&keyname, keybuf)) { LogMsg("SetSecretForDomain - bad key %s", keybuf); goto cleanup; }
					debugf("Setting shared secret for zone %s with key %##s", dstring, keyname.c);
					mDNS_SetSecretForZone(m, d, &keyname, secret);
					break;
					}
				}
			if (i == attrList->count) LogMsg("SetSecretForDomain - no key name set");
			goto cleanup;
			}
		else if (err == errSecItemNotFound) d = (domainname *)(d->c + d->c[0] + 1);
		else { failedfn = "SecKeychainSearchCopyNext"; goto cleanup; }
		}

	cleanup:
	if (err && err != errSecItemNotFound) LogMsg("Error: SetSecretForDomain - %s failed with error code %d", failedfn, err);
	if (attrList) SecKeychainItemFreeAttributesAndData(attrList, secret);
	if (itemRef) CFRelease(itemRef);
	}

mDNSlocal void SetSCPrefsBrowseDomainsFromCFArray(mDNS *m, CFArrayRef browseDomains, mDNSBool add)
	{
	if (browseDomains)
		{
		CFIndex count = CFArrayGetCount(browseDomains);
		CFDictionaryRef browseDict;
		char buf[MAX_ESCAPED_DOMAIN_NAME];
		int i;
		
		for (i = 0; i < count; i++)
			{
			browseDict = (CFDictionaryRef)CFArrayGetValueAtIndex(browseDomains, i);
			if (browseDict && DDNSSettingEnabled(browseDict))
				{
				CFStringRef name = CFDictionaryGetValue(browseDict, CFSTR("Domain"));
				if (name)
					{
					domainname BrowseDomain;
					if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) || !MakeDomainNameFromDNSNameString(&BrowseDomain, buf) || !BrowseDomain.c[0])
						LogMsg("SetSCPrefsBrowseDomainsFromCFArray SCDynamicStore bad DDNS browse domain: %s", buf[0] ? buf : "(unknown)");
					else SetSCPrefsBrowseDomain(m, &BrowseDomain, add);
					}
				}
			}
		}
	}


mDNSlocal void DynDNSConfigChanged(mDNS *const m)
	{
	static mDNSBool LegacyNATInitialized = mDNSfalse;
	uDNS_GlobalInfo *u = &m->uDNS_info;
	CFDictionaryRef dict;
	CFStringRef     key;
	domainname RegDomain, fqdn;
	CFArrayRef NewBrowseDomains = NULL;
	int nAdditions = 0, nDeletions = 0;
	
	// get fqdn, zone from SCPrefs
	GetUserSpecifiedDDNSConfig(&fqdn, &RegDomain, &NewBrowseDomains);
	ReadDDNSSettingsFromConfFile(m, CONFIG_FILE, fqdn.c[0] ? NULL : &fqdn, RegDomain.c[0] ? NULL : &RegDomain, &DomainDiscoveryDisabled);

	if (!SameDomainName(&RegDomain, &DynDNSRegDomain))
		{		
		if (DynDNSRegDomain.c[0])
			{
			RemoveDefRegDomain(&DynDNSRegDomain);
			SetSCPrefsBrowseDomain(m, &DynDNSRegDomain, mDNSfalse); // if we were automatically browsing in our registration domain, stop
			}
		AssignDomainName(&DynDNSRegDomain, &RegDomain);		
		if (DynDNSRegDomain.c[0])
			{
			SetSecretForDomain(m, &DynDNSRegDomain);
			AddDefRegDomain(&DynDNSRegDomain);
			SetSCPrefsBrowseDomain(m, &DynDNSRegDomain, mDNStrue);
			}
		}

    // Add new browse domains to internal list
	if (NewBrowseDomains) SetSCPrefsBrowseDomainsFromCFArray(m, NewBrowseDomains, mDNStrue);

	// Remove old browse domains from internal list
	if (DynDNSBrowseDomains) 
		{
		SetSCPrefsBrowseDomainsFromCFArray(m, DynDNSBrowseDomains, mDNSfalse);
		CFRelease(DynDNSBrowseDomains);
		}

	// Replace the old browse domains array with the new array
	DynDNSBrowseDomains = NewBrowseDomains;
	
	if (!SameDomainName(&fqdn, &DynDNSHostname))
		{
		if (DynDNSHostname.c[0]) mDNS_RemoveDynDNSHostName(m, &DynDNSHostname);
		AssignDomainName(&DynDNSHostname, &fqdn);
		if (DynDNSHostname.c[0])
			{
			SetSecretForDomain(m, &fqdn); // no-op if "zone" secret, above, is to be used for hostname
			SetDDNSNameStatus(&DynDNSHostname, 1);		// Set status to 1 to indicate "in progress"
			mDNS_AddDynDNSHostName(m, &DynDNSHostname, SCPrefsDynDNSCallback, NULL);
			}
		}

    // get DNS settings
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:DynDNSConfigChanged"), NULL, NULL);
	if (!store) return;
	
	key = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetDNS);
	if (!key) {  LogMsg("ERROR: DNSConfigChanged - SCDynamicStoreKeyCreateNetworkGlobalEntity"); CFRelease(store); return;  }
	dict = SCDynamicStoreCopyValue(store, key);
	CFRelease(key);

	// handle any changes to search domains and DNS server addresses
	if (RegisterSplitDNS(m, &nAdditions, &nDeletions) != mStatus_NoError)
		if (dict) RegisterNameServers(m, dict);  // fall back to non-split DNS aware configuration on failure
	RegisterSearchDomains(m, dict);  // note that we register name servers *before* search domains
	if (dict) CFRelease(dict);

	// get IPv4 settings
	key = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL,kSCDynamicStoreDomainState, kSCEntNetIPv4);
	if (!key) {  LogMsg("ERROR: RouterChanged - SCDynamicStoreKeyCreateNetworkGlobalEntity"); CFRelease(store); return;  }
	dict = SCDynamicStoreCopyValue(store, key);
	CFRelease(key);
	CFRelease(store);
	if (!dict)				// lost v4
		{
		mDNS_SetPrimaryInterfaceInfo(m, NULL, NULL);
		if (DynDNSHostname.c[0]) SetDDNSNameStatus(&DynDNSHostname, 1);	// Set status to 1 to indicate temporary failure
		return;
		} 

	// handle router changes
	mDNSAddr r;
	char buf[256];
	r.type = mDNSAddrType_IPv4;
	r.ip.v4.NotAnInteger = 0;
	CFStringRef router = CFDictionaryGetValue(dict, kSCPropNetIPv4Router);
	if (router)
		{
		struct sockaddr_in saddr;
		
		if (!CFStringGetCString(router, buf, 256, kCFStringEncodingUTF8))
			LogMsg("Could not convert router to CString");
		else
			{
			saddr.sin_len = sizeof(saddr);
			saddr.sin_family = AF_INET;
			saddr.sin_port = 0;			
			inet_aton(buf, &saddr.sin_addr);
			if (AddrRequiresPPPConnection((struct sockaddr *)&saddr)) { debugf("Ignoring router %s (requires PPP connection)", buf); }
			else *(in_addr_t *)&r.ip.v4 = saddr.sin_addr.s_addr;
			}
		}

	// handle primary interface changes
	// if we gained or lost DNS servers (e.g. logged into VPN) "toggle" primary address so it gets re-registered even if it is unchanged
	if (nAdditions || nDeletions) mDNS_SetPrimaryInterfaceInfo(m, NULL, NULL);
	CFStringRef primary = CFDictionaryGetValue(dict, kSCDynamicStorePropNetPrimaryInterface);
	if (primary)
		{
		struct ifaddrs *ifa = myGetIfAddrs(1);

		if (!CFStringGetCString(primary, buf, 256, kCFStringEncodingUTF8))
			{ LogMsg("Could not convert router to CString"); goto error; }		

		// find primary interface in list
		while (ifa)
			{
			if (ifa->ifa_addr->sa_family == AF_INET && !strcmp(buf, ifa->ifa_name))
				{
				mDNSAddr ip;
				SetupAddr(&ip, ifa->ifa_addr);
				if (ip.ip.v4.b[0] == 169 && ip.ip.v4.b[1] == 254)
					{ mDNS_SetPrimaryInterfaceInfo(m, NULL, NULL); break; }  // primary IP is link-local				
				if (ip.ip.v4.NotAnInteger != u->PrimaryIP.ip.v4.NotAnInteger ||
					r.ip.v4.NotAnInteger != u->Router.ip.v4.NotAnInteger)
					{
					if (LegacyNATInitialized) { LegacyNATDestroy(); LegacyNATInitialized = mDNSfalse; }
					if (r.ip.v4.NotAnInteger && IsPrivateV4Addr(&ip))
						{
						mStatus err = LegacyNATInit();
						if (err)  LogMsg("ERROR: LegacyNATInit");
						else LegacyNATInitialized = mDNStrue;
						}					
					mDNS_SetPrimaryInterfaceInfo(m, &ip, r.ip.v4.NotAnInteger ? &r : NULL);
					break;
					}
				}
			ifa = ifa->ifa_next;
			}
		}
	
	error:
	CFRelease(dict);
	}

mDNSexport void mDNSMacOSXNetworkChanged(mDNS *const m)
   {
	LogOperation("***   Network Configuration Change   ***");
	m->p->NetworkChanged = 0;		// If we received a network change event and deferred processing, we're now dealing with it
	mDNSs32 utc = mDNSPlatformUTC();
	MarkAllInterfacesInactive(m, utc);
	UpdateInterfaceList(m, utc);
	int nDeletions = ClearInactiveInterfaces(m, utc);
	int nAdditions = SetupActiveInterfaces(m, utc);
	DynDNSConfigChanged(m);                           // note - call DynDNSConfigChanged *before* mDNS_UpdateLLQs	                        
	if (nDeletions || nAdditions) mDNS_UpdateLLQs(m); // so that LLQs are restarted against the up to date name servers
	
	if (m->MainCallback)
		m->MainCallback(m, mStatus_ConfigChanged);
	}

mDNSlocal void NetworkChanged(SCDynamicStoreRef store, CFArrayRef changedKeys, void *context)
	{
	(void)store;        // Parameter not used
	(void)changedKeys;  // Parameter not used
	mDNS *const m = (mDNS *const)context;
	mDNS_Lock(m);

	mDNSs32 delay = mDNSPlatformOneSecond * 2;							// Start off assuming a two-second delay

	int c = CFArrayGetCount(changedKeys);								// Count changes
	CFRange range = { 0, c };
	CFStringRef k1 = SCDynamicStoreKeyCreateComputerName(NULL);
	CFStringRef k2 = SCDynamicStoreKeyCreateHostNames(NULL);
	if (k1 && k2)
		{
		int c1 = (CFArrayContainsValue(changedKeys, range, k1) != 0);	// See if ComputerName changed
		int c2 = (CFArrayContainsValue(changedKeys, range, k2) != 0);	// See if Local Hostname changed
		int c3 = (CFArrayContainsValue(changedKeys, range, CFSTR("Setup:/Network/DynamicDNS")) != 0);
		if (c && c - c1 - c2 - c3 == 0) delay = mDNSPlatformOneSecond/10;	// If these were the only changes, shorten delay
		}
	if (k1) CFRelease(k1);
	if (k2) CFRelease(k2);

	LogOperation("***   NetworkChanged   *** %d change%s, delay %d", c, c>1?"s":"", delay);

	if (!m->p->NetworkChanged ||
		m->p->NetworkChanged - NonZeroTime(m->timenow + delay) < 0)
		m->p->NetworkChanged = NonZeroTime(m->timenow + delay);
	
	if (!m->SuppressSending ||
		m->SuppressSending - m->p->NetworkChanged < 0)
		m->SuppressSending = m->p->NetworkChanged;
	mDNS_Unlock(m);
	}

mDNSlocal mStatus WatchForNetworkChanges(mDNS *const m)
	{
	mStatus err = -1;
	SCDynamicStoreContext context = { 0, m, NULL, NULL, NULL };
	SCDynamicStoreRef     store    = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:WatchForNetworkChanges"), NetworkChanged, &context);
	CFStringRef           key1     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
	CFStringRef           key2     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv6);
	CFStringRef           key3     = SCDynamicStoreKeyCreateComputerName(NULL);
	CFStringRef           key4     = SCDynamicStoreKeyCreateHostNames(NULL);
	CFStringRef           key5     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetDNS);
	CFStringRef           pattern1 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
	CFStringRef           pattern2 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6);

	CFMutableArrayRef     keys     = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	CFMutableArrayRef     patterns = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	if (!store) { LogMsg("SCDynamicStoreCreate failed: %s", SCErrorString(SCError())); goto error; }
	if (!key1 || !key2 || !key3 || !key4 || !keys || !pattern1 || !pattern2 || !patterns) goto error;

	CFArrayAppendValue(keys, key1);
	CFArrayAppendValue(keys, key2);
	CFArrayAppendValue(keys, key3);
	CFArrayAppendValue(keys, key4);
	CFArrayAppendValue(keys, key5);
	CFArrayAppendValue(keys, CFSTR("Setup:/Network/DynamicDNS"));
	CFArrayAppendValue(patterns, pattern1);
	CFArrayAppendValue(patterns, pattern2);
	CFArrayAppendValue(patterns, CFSTR("State:/Network/Interface/[^/]+/AirPort"));
	if (!SCDynamicStoreSetNotificationKeys(store, keys, patterns))
		{ LogMsg("SCDynamicStoreSetNotificationKeys failed: %s", SCErrorString(SCError())); goto error; }

	m->p->StoreRLS = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
	if (!m->p->StoreRLS) { LogMsg("SCDynamicStoreCreateRunLoopSource failed: %s", SCErrorString(SCError())); goto error; }

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
	if (key5)     CFRelease(key5);
	if (pattern1) CFRelease(pattern1);
	if (pattern2) CFRelease(pattern2);
	if (keys)     CFRelease(keys);
	if (patterns) CFRelease(patterns);
	
	return(err);
	}

mDNSlocal void PowerChanged(void *refcon, io_service_t service, natural_t messageType, void *messageArgument)
	{
	mDNS *const m = (mDNS *const)refcon;
	(void)service;    // Parameter not used
	switch(messageType)
		{
		case kIOMessageCanSystemPowerOff:		debugf      ("PowerChanged kIOMessageCanSystemPowerOff (no action)");				break; // E0000240
		case kIOMessageSystemWillPowerOff:		LogOperation("PowerChanged kIOMessageSystemWillPowerOff");
												mDNSCoreMachineSleep(m, true); mDNSMacOSXNetworkChanged(m);							break; // E0000250
		case kIOMessageSystemWillNotPowerOff:	debugf      ("PowerChanged kIOMessageSystemWillNotPowerOff (no action)");			break; // E0000260
		case kIOMessageCanSystemSleep:			debugf      ("PowerChanged kIOMessageCanSystemSleep (no action)");					break; // E0000270
		case kIOMessageSystemWillSleep:			LogOperation("PowerChanged kIOMessageSystemWillSleep");
												mDNSCoreMachineSleep(m, true); mDNSMacOSXNetworkChanged(m);							break; // E0000280
		case kIOMessageSystemWillNotSleep:		debugf      ("PowerChanged kIOMessageSystemWillNotSleep (no action)");				break; // E0000290
		case kIOMessageSystemHasPoweredOn:		LogOperation("PowerChanged kIOMessageSystemHasPoweredOn");
												// If still sleeping (didn't get 'WillPowerOn' message for some reason?) wake now
												if (m->SleepState) mDNSCoreMachineSleep(m, false);
												// Just to be safe, also make sure our interface list is fully up to date, in case we
												// haven't yet received the System Configuration Framework "network changed" event that
												// we expect to receive some time shortly after the kIOMessageSystemWillPowerOn message
												mDNSMacOSXNetworkChanged(m);														break; // E0000300
		case kIOMessageSystemWillRestart:		debugf      ("PowerChanged kIOMessageSystemWillRestart (no action)");				break; // E0000310
		case kIOMessageSystemWillPowerOn:		LogOperation("PowerChanged kIOMessageSystemWillPowerOn");
												// Make sure our interface list is cleared to the empty state, then tell mDNSCore to wake
												mDNSMacOSXNetworkChanged(m); mDNSCoreMachineSleep(m, false);						break; // E0000320
		default:								LogOperation("PowerChanged unknown message %X", messageType);						break;
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

// Major version 6 is 10.2.x (Jaguar)
// Major version 7 is 10.3.x (Panther)
// Major version 8 is 10.4.x (Tiger)
mDNSexport int mDNSMacOSXSystemBuildNumber(char *HINFO_SWstring)
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

// Test to see if we're the first client running on UDP port 5353, by trying to bind to 5353 without using SO_REUSEPORT.
// If we fail, someone else got here first. That's not a big problem; we can share the port for multicast responses --
// we just need to be aware that we shouldn't expect to successfully receive unicast UDP responses.
mDNSlocal mDNSBool mDNSPlatformInit_CanReceiveUnicast(void)
	{
	int err = -1;
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 3)
		LogMsg("mDNSPlatformInit_CanReceiveUnicast: socket error %d errno %d (%s)", s, errno, strerror(errno));
	else
		{
		struct sockaddr_in s5353;
		s5353.sin_family      = AF_INET;
		s5353.sin_port        = MulticastDNSPort.NotAnInteger;
		s5353.sin_addr.s_addr = 0;
		err = bind(s, (struct sockaddr *)&s5353, sizeof(s5353));
		close(s);
		}

	if (err) LogMsg("No unicast UDP responses");
	else     debugf("Unicast UDP responses okay");
	return(err == 0);
	}

// Callback for the _legacy._browse queries - add answer to list of domains to search for empty-string browses
mDNSlocal void FoundLegacyBrowseDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	DNameListElem *ptr, *prev, *new;
	(void)m; // unused;
	(void)question;  // unused

	LogMsg("%s browse domain %##s", AddRecord ? "Adding" : "Removing", answer->rdata->u.name.c);
	
	if (AddRecord)
		{
		new = mallocL("FoundLegacyBrowseDomain", sizeof(DNameListElem));
		if (!new) { LogMsg("ERROR: malloc"); return; }
		AssignDomainName(&new->name, &answer->rdata->u.name);
		new->next = DefBrowseList;
		DefBrowseList = new;
		DefaultBrowseDomainChanged(&new->name, mDNStrue);
		udsserver_default_browse_domain_changed(&new->name, mDNStrue);
		return;
		}
	else
		{
		ptr = DefBrowseList;
		prev = NULL;
		while (ptr)
			{
			if (SameDomainName(&ptr->name, &answer->rdata->u.name))
				{
				DefaultBrowseDomainChanged(&ptr->name, mDNSfalse);
				udsserver_default_browse_domain_changed(&ptr->name, mDNSfalse);
				if (prev) prev->next = ptr->next;
				else DefBrowseList = ptr->next;
				freeL("FoundLegacyBrowseDomain", ptr);				
				return;
				}
			prev = ptr;
			ptr = ptr->next;
			}
		LogMsg("FoundLegacyBrowseDomain: Got remove event for domain %s not in list", answer->rdata->u.name.c);
		}
	}

mDNSlocal void RegisterBrowseDomainPTR(mDNS *m, const domainname *d, int type)
	{
	// allocate/register legacy and non-legacy _browse PTR record
	ARListElem *browse = mallocL("ARListElem", sizeof(*browse));
	mDNS_SetupResourceRecord(&browse->ar, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200,  kDNSRecordTypeShared, FreeARElemCallback, browse);
	MakeDomainNameFromDNSNameString(browse->ar.resrec.name, mDNS_DomainTypeNames[type]);
	AppendDNSNameString            (browse->ar.resrec.name, "local");
	AssignDomainName(&browse->ar.resrec.rdata->u.name, d);
	mStatus err = mDNS_Register(m, &browse->ar);
	if (err)
		{
		LogMsg("SetSCPrefsBrowseDomain: mDNS_Register returned error %d", err);
		freeL("ARListElem", browse);
		}
	else
		{
		browse->next = SCPrefBrowseDomains;
		SCPrefBrowseDomains = browse;
		}
	}

mDNSlocal void DeregisterBrowseDomainPTR(mDNS *m, const domainname *d, int type)
	{
	ARListElem *remove, **ptr = &SCPrefBrowseDomains;
	domainname lhs; // left-hand side of PTR, for comparison
	
	MakeDomainNameFromDNSNameString(&lhs, mDNS_DomainTypeNames[type]);
	AppendDNSNameString            (&lhs, "local");

	while (*ptr)
		{
		if (SameDomainName(&(*ptr)->ar.resrec.rdata->u.name, d) && SameDomainName((*ptr)->ar.resrec.name, &lhs))
			{
			remove = *ptr;
			*ptr = (*ptr)->next;
			mDNS_Deregister(m, &remove->ar);
			return;
			}
		else ptr = &(*ptr)->next;
		}
	}

// Add or remove a user-specified domain to the list of empty-string browse domains
// Also register a non-legacy _browse PTR record so that the domain appears in enumeration lists
mDNSlocal void SetSCPrefsBrowseDomain(mDNS *m, const domainname *d, mDNSBool add)
	{
	debugf("SetSCPrefsBrowseDomain: %s default browse domain %##s", add ? "Adding" : "Removing", d->c);
	
	if (add)
		{
		RegisterBrowseDomainPTR(m, d, mDNS_DomainTypeBrowse);
		RegisterBrowseDomainPTR(m, d, mDNS_DomainTypeBrowseLegacy);
		}
	else
		{
		DeregisterBrowseDomainPTR(m, d, mDNS_DomainTypeBrowse);
		DeregisterBrowseDomainPTR(m, d, mDNS_DomainTypeBrowseLegacy);
		}
	}

// Construction of Default Browse domain list (i.e. when clients pass NULL) is as follows:
// 1) query for b._dns-sd._udp.local on LocalOnly interface
//    (.local manually generated via explicit callback)
// 2) for each search domain (from prefs pane), query for b._dns-sd._udp.<searchdomain>.
// 3) for each result from (2), register LocalOnly PTR record b._dns-sd._udp.local. -> <result>
// 4) result above should generate a callback from question in (1).  result added to global list
// 5) global list delivered to client via GetSearchDomainList()
// 6) client calls to enumerate domains now go over LocalOnly interface
//    (!!!KRS may add outgoing interface in addition)

mDNSlocal mStatus InitDNSConfig(mDNS *const m)
	{
	mStatus err;
	static AuthRecord LocalRegPTR;
	
	// start query for domains to be used in default (empty string domain) browses
	err = mDNS_GetDomains(m, &LegacyBrowseDomainQ, mDNS_DomainTypeBrowseLegacy, NULL, mDNSInterface_LocalOnly, FoundLegacyBrowseDomain, NULL);

	// provide browse domain "local" automatically
	SetSCPrefsBrowseDomain(m, &localdomain, mDNStrue);

	// register registration domain "local"
	mDNS_SetupResourceRecord(&LocalRegPTR, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200,  kDNSRecordTypeShared, NULL, NULL);
	MakeDomainNameFromDNSNameString(LocalRegPTR.resrec.name, mDNS_DomainTypeNames[mDNS_DomainTypeRegistration]);
	AppendDNSNameString            (LocalRegPTR.resrec.name, "local");
	AssignDomainName(&LocalRegPTR.resrec.rdata->u.name, &localdomain);
	err = mDNS_Register(m, &LocalRegPTR);
	if (err) LogMsg("ERROR: InitDNSConfig - mDNS_Register returned error %d", err);
	
	return mStatus_NoError;
	}

mDNSlocal mStatus mDNSPlatformInit_setup(mDNS *const m)
	{
	// In 10.4, mDNSResponder is launched very early in the boot process, while other subsystems are still in the process of starting up.
	// If we can't read the user's preferences, then we sleep a bit and try again, for up to five seconds before we give up.
	int i;
	for (i=0; i<100; i++)
		{
		domainlabel testlabel;
		testlabel.c[0] = 0;
		GetUserSpecifiedLocalHostName(&testlabel);
		if (testlabel.c[0]) break;
		usleep(50000);
		}

	mStatus err;

   	m->hostlabel.c[0]        = 0;
	
	char *HINFO_HWstring = "Macintosh";
	char HINFO_HWstring_buffer[256];
	int    get_model[2] = { CTL_HW, HW_MODEL };
	size_t len_model = sizeof(HINFO_HWstring_buffer);
	if (sysctl(get_model, 2, HINFO_HWstring_buffer, &len_model, NULL, 0) == 0)
		HINFO_HWstring = HINFO_HWstring_buffer;

	char HINFO_SWstring[256] = "";
	if (mDNSMacOSXSystemBuildNumber(HINFO_SWstring) < 7) m->KnownBugs |= mDNS_KnownBug_PhantomInterfaces;
	if (mDNSPlatformInit_CanReceiveUnicast())            m->CanReceiveUnicastOn5353 = mDNStrue;

	mDNSu32 hlen = mDNSPlatformStrLen(HINFO_HWstring);
	mDNSu32 slen = mDNSPlatformStrLen(HINFO_SWstring);
	if (hlen + slen < 254)
		{
		m->HIHardware.c[0] = hlen;
		m->HISoftware.c[0] = slen;
		mDNSPlatformMemCopy(HINFO_HWstring, &m->HIHardware.c[1], hlen);
		mDNSPlatformMemCopy(HINFO_SWstring, &m->HISoftware.c[1], slen);
		}

 	m->p->unicastsockets.m     = m;
	m->p->unicastsockets.info  = NULL;
	m->p->unicastsockets.sktv4 = m->p->unicastsockets.sktv6 = -1;
	m->p->unicastsockets.cfsv4 = m->p->unicastsockets.cfsv6 = NULL;
	m->p->unicastsockets.rlsv4 = m->p->unicastsockets.rlsv6 = NULL;
	
	err = SetupSocket(m, &m->p->unicastsockets, mDNSfalse, &zeroAddr, AF_INET);
	err = SetupSocket(m, &m->p->unicastsockets, mDNSfalse, &zeroAddr, AF_INET6);

	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
	int n4 = sizeof(s4);
	int n6 = sizeof(s6);
	if (getsockname(m->p->unicastsockets.sktv4, (struct sockaddr *)&s4, &n4) < 0) LogMsg("getsockname v4 error %d (%s)", errno, strerror(errno));
	else m->UnicastPort4.NotAnInteger = s4.sin_port;
	if (getsockname(m->p->unicastsockets.sktv6, (struct sockaddr *)&s6, &n6) < 0) LogMsg("getsockname v6 error %d (%s)", errno, strerror(errno));
	else m->UnicastPort6.NotAnInteger = s6.sin6_port;

	m->p->InterfaceList      = mDNSNULL;
	m->p->userhostlabel.c[0] = 0;
	m->p->usernicelabel.c[0] = 0;
	m->p->NotifyUser         = 0;
	mDNSs32 utc = mDNSPlatformUTC();
	UpdateInterfaceList(m, utc);
	SetupActiveInterfaces(m, utc);

	err = WatchForNetworkChanges(m);
	if (err) return(err);
	
	err = WatchForPowerChanges(m);
	if (err) return err;

	DynDNSRegDomain.c[0] = '\0';
	DynDNSConfigChanged(m);						// Get initial DNS configuration

	InitDNSConfig(m);
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
		m->p->PowerConnection = 0;
		m->p->PowerNotifier   = 0;
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
	
	mDNSs32 utc = mDNSPlatformUTC();
	MarkAllInterfacesInactive(m, utc);
	ClearInactiveInterfaces(m, utc);
	CloseSocketSet(&m->p->unicastsockets);
	}

mDNSexport mDNSu32 mDNSPlatformRandomSeed(void)
	{
	return(mach_absolute_time());
	}

mDNSexport mDNSs32 mDNSPlatformOneSecond = 1000;

mDNSexport mStatus mDNSPlatformTimeInit(void)
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
	if (result == KERN_SUCCESS) clockdivisor = ((uint64_t)tbi.denom * 1000000) / tbi.numer;
	return(result);
	}

mDNSexport mDNSs32 mDNSPlatformRawTime(void)
	{
	if (clockdivisor == 0) { LogMsg("mDNSPlatformRawTime called before mDNSPlatformTimeInit"); return(0); }

	static uint64_t last_mach_absolute_time = 0;
	uint64_t this_mach_absolute_time = mach_absolute_time();
	if ((int64_t)this_mach_absolute_time - (int64_t)last_mach_absolute_time < 0)
		{
		LogMsg("mDNSPlatformRawTime: last_mach_absolute_time %08X%08X", last_mach_absolute_time);
		LogMsg("mDNSPlatformRawTime: this_mach_absolute_time %08X%08X", this_mach_absolute_time);
		// Update last_mach_absolute_time *before* calling NotifyOfElusiveBug()
		last_mach_absolute_time = this_mach_absolute_time;
		// Only show "mach_absolute_time went backwards" notice on 10.4 (build 8xyyy) or later
		if (mDNSMacOSXSystemBuildNumber(NULL) >= 8)
			NotifyOfElusiveBug("mach_absolute_time went backwards!", 3438376, "");
		}
	last_mach_absolute_time = this_mach_absolute_time;

	return((mDNSs32)(this_mach_absolute_time / clockdivisor));
	}

mDNSexport mDNSs32 mDNSPlatformUTC(void)
	{
	return time(NULL);
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
