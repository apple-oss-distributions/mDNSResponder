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
 *
 * Formatting notes:
 * This code follows the "Whitesmiths style" C indentation rules. Plenty of discussion
 * on C indentation can be found on the web, such as <http://www.kafejo.com/komp/1tbs.htm>,
 * but for the sake of brevity here I will say just this: Curly braces are not syntactially
 * part of an "if" statement; they are the beginning and ending markers of a compound statement;
 * therefore common sense dictates that if they are part of a compound statement then they
 * should be indented to the same level as everything else in that compound statement.
 * Indenting curly braces at the same level as the "if" implies that curly braces are
 * part of the "if", which is false. (This is as misleading as people who write "char* x,y;"
 * thinking that variables x and y are both of type "char*" -- and anyone who doesn't
 * understand why variable y is not of type "char*" just proves the point that poor code
 * layout leads people to unfortunate misunderstandings about how the C language really works.)

    Change History (most recent first):

$Log: daemon.c,v $
Revision 1.255  2005/03/09 00:48:43  cheshire
<rdar://problem/4015157> QU packets getting sent too early on wake from sleep
Move "m->p->NetworkChanged = 0;" line from caller to callee

Revision 1.254  2005/03/03 04:34:19  cheshire
<rdar://problem/4025973> Bonjour name conflict dialog appears during MacBuddy

Revision 1.253  2005/03/03 03:55:09  cheshire
<rdar://problem/3862944> Name collision notifications should be localized

Revision 1.252  2005/02/23 02:29:17  cheshire
<rdar://problem/4005191> "Local Hostname is already in use..." dialogue shows for only 60 seconds before being removed
Minor refinements, better variable names, improved comments

Revision 1.251  2005/02/21 21:31:24  ksekar
<rdar://problem/4015162> changed LogMsg to debugf

Revision 1.250  2005/02/19 01:25:04  cheshire
<rdar://problem/4005191> "Local Hostname is already in use..." dialogue shows for only 60 seconds before being removed
Further refinements

Revision 1.249  2005/02/19 00:28:45  cheshire
<rdar://problem/4005191> "Local Hostname is already in use..." dialogue shows for only 60 seconds before being removed

Revision 1.248  2005/02/19 00:18:34  cheshire
Confusing variable name -- alertMessage should be called alertHeader

Revision 1.247  2005/02/15 02:13:49  cheshire
If we did registerBootstrapService() when starting, then we must do
destroyBootstrapService() before exiting, or Mach init will keep restarting us.

Revision 1.246  2005/02/03 00:44:37  cheshire
<rdar://problem/3986663> DNSServiceUpdateRecord returns kDNSServiceErr_Invalid when rdlen=0, rdata=NULL

Revision 1.245  2005/02/01 19:56:47  ksekar
Moved LogMsg from daemon.c to uds_daemon.c, cleaned up wording

Revision 1.244  2005/01/28 00:34:49  cheshire
Turn off "Starting time value" log message

Revision 1.243  2005/01/27 17:46:58  cheshire
Added comment about CFSocketInvalidate closing the underlying socket

Revision 1.242  2005/01/27 00:10:58  cheshire
<rdar://problem/3967867> Name change log messages every time machine boots

Revision 1.241  2005/01/25 17:28:06  ksekar
<rdar://problem/3971467> Should not return "local" twice for domain enumeration

Revision 1.240  2005/01/21 02:39:18  cheshire
Rename FoundDomain() to DomainEnumFound() to avoid order-file symbol clash with other routine called FoundDomain()

Revision 1.239  2005/01/20 00:25:01  cheshire
Improve validatelists() log message generation

Revision 1.238  2005/01/19 19:15:35  ksekar
Refinement to <rdar://problem/3954575> - Simplify mDNS_PurgeResultsForDomain logic and move into daemon layer

Revision 1.237  2005/01/19 03:33:09  cheshire
<rdar://problem/3945652> When changing Computer Name, we drop our own Goobye Packets

Revision 1.236  2005/01/19 03:16:38  cheshire
<rdar://problem/3961051> CPU Spin in mDNSResponder
Improve detail of "Task Scheduling Error" diagnostic messages

Revision 1.235  2005/01/15 00:56:41  ksekar
<rdar://problem/3954575> Unicast services don't disappear when logging
out of VPN

Revision 1.234  2005/01/10 03:42:30  ksekar
Clarify debugf

Revision 1.233  2004/12/18 00:53:46  cheshire
Use symbolic constant mDNSInterface_LocalOnly instead of (mDNSInterfaceID)~0

Revision 1.232  2004/12/17 23:37:48  cheshire
<rdar://problem/3485365> Guard against repeating wireless dissociation/re-association
(and other repetitive configuration changes)

Revision 1.231  2004/12/17 04:13:38  cheshire
Removed debugging check

Revision 1.230  2004/12/17 04:09:30  cheshire
<rdar://problem/3191011> Switch mDNSResponder to launchd

Revision 1.229  2004/12/16 21:51:36  cheshire
Remove some startup messages

Revision 1.228  2004/12/16 20:13:01  cheshire
<rdar://problem/3324626> Cache memory management improvements

Revision 1.227  2004/12/10 13:52:57  cheshire
<rdar://problem/3909995> Turn off SIGPIPE signals

Revision 1.226  2004/12/10 05:27:26  cheshire
<rdar://problem/3909147> Guard against multiple autoname services of the same type on the same machine

Revision 1.225  2004/12/10 04:28:29  cheshire
<rdar://problem/3914406> User not notified of name changes for services using new UDS API

Revision 1.224  2004/12/10 00:41:05  cheshire
Adjust alignment of log messages

Revision 1.223  2004/12/07 20:42:34  cheshire
Add explicit context parameter to mDNS_RemoveRecordFromService()

Revision 1.222  2004/12/06 21:15:23  ksekar
<rdar://problem/3884386> mDNSResponder crashed in CheckServiceRegistrations

Revision 1.221  2004/11/30 03:24:04  cheshire
<rdar://problem/3854544> Defer processing network configuration changes until configuration has stabilized

Revision 1.220  2004/11/29 23:34:31  cheshire
On platforms with coarse time resolutions, ORing time values with one to ensure they are non-zero
is crude, and effectively halves the time resolution. The more selective NonZeroTime() function
only nudges the time value to 1 if the interval calculation happens to result in the value zero.

Revision 1.219  2004/11/25 01:00:56  cheshire
Checkin 1.217 not necessary

Revision 1.218  2004/11/24 20:27:19  cheshire
Add missing "err" parameter in LogMsg() call

Revision 1.217  2004/11/24 17:55:01  ksekar
Added log message clarifying <rdar://problem/3869241> For unicast operations, verify that service types are legal

Revision 1.216  2004/11/24 00:10:44  cheshire
<rdar://problem/3869241> For unicast operations, verify that service types are legal

Revision 1.215  2004/11/23 22:33:01  cheshire
<rdar://problem/3654910> Remove temporary workaround code for iChat

Revision 1.214  2004/11/23 22:13:59  cheshire
<rdar://problem/3886293> Subtype advertising broken for Mach API

Revision 1.213  2004/11/23 06:12:55  cheshire
<rdar://problem/3871405> Update wording for name conflict dialogs

Revision 1.212  2004/11/23 05:15:37  cheshire
<rdar://problem/3875830> Computer Name in use message garbled

Revision 1.211  2004/11/23 05:00:41  cheshire
<rdar://problem/3874629> Name conflict log message should not have ".local" appended

Revision 1.210  2004/11/03 03:45:17  cheshire
<rdar://problem/3863627> mDNSResponder does not inform user of Computer Name collisions

Revision 1.209  2004/11/03 02:25:50  cheshire
<rdar://problem/3324137> Conflict for Computer Name should update *all* empty string services, not just the one with the conflict

Revision 1.208  2004/11/03 01:54:14  cheshire
Update debugging messages

Revision 1.207  2004/11/02 23:58:19  cheshire
<rdar://problem/2974905> mDNSResponder does not inform user of name collisions

Revision 1.206  2004/10/28 02:40:47  cheshire
Add log message to confirm receipt of SIGUSR1 (simulate network configuration change event)

Revision 1.205  2004/10/28 02:21:01  cheshire
<rdar://problem/3856500> Improve mDNSResponder signal handling
Added SIGHUP as a way to do a forced restart of the daemon (better than kill -9)
Added SIGUSR1 to simulate a network change notification from System Configuration Framework

Revision 1.204  2004/10/27 01:57:21  cheshire
Add check of  m->p->InterfaceList

Revision 1.203  2004/10/26 04:31:44  cheshire
Rename CountSubTypes() as ChopSubTypes()

Revision 1.202  2004/10/26 01:29:18  cheshire
Use "#if 0" instead of commenting out code

Revision 1.201  2004/10/25 21:41:39  ksekar
<rdar://problem/3852958> wide-area name conflicts can cause crash

Revision 1.200  2004/10/22 01:03:55  cheshire
<rdar://problem/3375328> select() says data is waiting; recvfrom() says there is no data
Log error message if attempt to remap stdin/stdout/stderr to /dev/null fails

Revision 1.199  2004/10/19 21:33:19  cheshire
<rdar://problem/3844991> Cannot resolve non-local registrations using the mach API
Added flag 'kDNSServiceFlagsForceMulticast'. Passing through an interface id for a unicast name
doesn't force multicast unless you set this flag to indicate explicitly that this is what you want

Revision 1.198  2004/10/15 23:00:18  ksekar
<rdar://problem/3799242> Need to update LLQs on location changes

Revision 1.197  2004/10/12 23:38:59  ksekar
<rdar://problem/3837065> remove unnecessary log message

Revision 1.196  2004/10/04 05:56:04  cheshire
<rdar://problem/3824730> mDNSResponder doesn't respond to certain AirPort changes

Revision 1.195  2004/09/30 00:24:59  ksekar
<rdar://problem/3695802> Dynamically update default registration domains on config change

Revision 1.194  2004/09/26 23:20:35  ksekar
<rdar://problem/3813108> Allow default registrations in multiple wide-area domains

Revision 1.193  2004/09/23 23:35:27  cheshire
Update error message

Revision 1.192  2004/09/21 23:40:12  ksekar
<rdar://problem/3810349> mDNSResponder to return errors on NAT traversal failure

Revision 1.191  2004/09/21 21:05:12  cheshire
Move duplicate code out of mDNSMacOSX/daemon.c and mDNSPosix/PosixDaemon.c,
into mDNSShared/uds_daemon.c

Revision 1.190  2004/09/21 19:51:15  cheshire
Move "Starting time value" message from mDNS.c to mDNSMacOSX/daemon.c

Revision 1.189  2004/09/21 18:17:23  cheshire
<rdar://problem/3785400> Add version info to mDNSResponder

Revision 1.188  2004/09/20 21:45:27  ksekar
Mach IPC cleanup

Revision 1.187  2004/09/17 01:08:52  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.186  2004/09/16 00:24:49  cheshire
<rdar://problem/3803162> Fix unsafe use of mDNSPlatformTimeNow()

Revision 1.185  2004/08/25 02:01:45  cheshire
<rdar://problem/3774777> Need to be able to get status of Dynamic DNS Host Name Update

Revision 1.184  2004/08/19 19:04:12  ksekar
<rdar://problem/3767546>: mDNSResponder crashes when adding a record to a service

Revision 1.183  2004/08/14 03:22:42  cheshire
<rdar://problem/3762579> Dynamic DNS UI <-> mDNSResponder glue
Add GetUserSpecifiedDDNSName() routine
Convert ServiceRegDomain to domainname instead of C string
Replace mDNS_GenerateFQDN/mDNS_GenerateGlobalFQDN with mDNS_SetFQDNs

Revision 1.182  2004/08/13 23:57:59  cheshire
Get rid of non-portable "_UNUSED"

Revision 1.181  2004/08/11 02:02:26  cheshire
Remove "mDNS *globalInstance" parameter from udsserver_init();
Move CheckForDuplicateRegistrations to uds_daemon.c

Revision 1.180  2004/07/13 21:24:25  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.179  2004/06/19 00:02:54  cheshire
Restore fix for <rdar://problem/3548256> Should not allow empty string for resolve domain

Revision 1.178  2004/06/18 19:10:00  cheshire
<rdar://problem/3588761> Current method of doing subtypes causes name collisions

Revision 1.177  2004/06/16 23:14:46  ksekar
<rdar://problem/3693816> Remove fix for <rdar://problem/3548256> Should not allow empty string for resolve domain

Revision 1.176  2004/06/11 20:27:42  cheshire
Rename "SocketRef" as "cfs" to avoid conflict with other plaforms

Revision 1.175  2004/06/10 20:23:21  cheshire
Also list interfaces in SIGINFO output

Revision 1.174  2004/06/08 18:54:48  ksekar
<rdar://problem/3681378>: mDNSResponder leaks after exploring in Printer Setup Utility

Revision 1.173  2004/06/08 17:35:12  cheshire
<rdar://problem/3683988> Detect and report if mDNSResponder uses too much CPU

Revision 1.172  2004/06/05 00:04:26  cheshire
<rdar://problem/3668639>: wide-area domains should be returned in reg. domain enumeration

Revision 1.171  2004/06/04 08:58:30  ksekar
<rdar://problem/3668624>: Keychain integration for secure dynamic update

Revision 1.170  2004/05/30 20:01:50  ksekar
<rdar://problem/3668635>: wide-area default registrations should be in
.local too - fixed service registration when clients pass an explicit
domain (broken by previous checkin)

Revision 1.169  2004/05/30 01:30:16  ksekar
<rdar://problem/3668635>: wide-area default registrations should be in
.local too

Revision 1.168  2004/05/18 23:51:26  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.167  2004/05/14 16:39:47  ksekar
Browse for iChat locally for now.

Revision 1.166  2004/05/13 21:33:52  ksekar
Clean up non-local registration control via config file.  Force iChat
registrations to be local for now.

Revision 1.165  2004/05/13 04:54:20  ksekar
Unified list copy/free code.  Added symetric list for

Revision 1.164  2004/05/12 22:03:08  ksekar
Made GetSearchDomainList a true platform-layer call (declaration moved
from mDNSMacOSX.h to mDNSEmbeddedAPI.h), impelemted to return "local"
only on non-OSX platforms.  Changed call to return a copy of the list
to avoid shared memory issues.  Added a routine to free the list.

Revision 1.163  2004/05/12 02:03:25  ksekar
Non-local domains will only be browsed by default, and show up in
_browse domain enumeration, if they contain an _browse._dns-sd ptr record.

Revision 1.162  2004/04/14 23:09:29  ksekar
Support for TSIG signed dynamic updates.

Revision 1.161  2004/04/07 01:20:04  cheshire
Hash slot value should be unsigned

Revision 1.160  2004/04/06 19:51:24  cheshire
<rdar://problem/3605898> mDNSResponder will not launch if "nobody" user doesn't exist.
After more discussion, we've decided to use userid -2 if "nobody" user doesn't exist.

Revision 1.159  2004/04/03 01:36:55  cheshire
<rdar://problem/3605898> mDNSResponder will not launch if "nobody" user doesn't exist.
If "nobody" user doesn't exist, log a message and continue as "root"

Revision 1.158  2004/04/02 21:39:05  cheshire
Fix errors in comments

Revision 1.157  2004/03/19 18:49:10  ksekar
Increased size check in freeL() to account for LargeCacheRecord
structs larger than 8k

Revision 1.156  2004/03/19 18:19:19  ksekar
Fixed daemon.c to compile with malloc debugging turned on.

Revision 1.155  2004/03/13 01:57:34  ksekar
<rdar://problem/3192546>: DynDNS: Dynamic update of service records

Revision 1.154  2004/03/12 08:42:47  cheshire
<rdar://problem/3548256>: Should not allow empty string for resolve domain

Revision 1.153  2004/03/12 08:08:51  cheshire
Update comments

Revision 1.152  2004/02/05 19:39:29  cheshire
Move creation of /var/run/mDNSResponder.pid to uds_daemon.c,
so that all platforms get this functionality

Revision 1.151  2004/02/03 22:35:34  cheshire
<rdar://problem/3548256>: Should not allow empty string for resolve domain

Revision 1.150  2004/01/28 21:14:23  cheshire
Reconcile debug_mode and gDebugLogging into a single flag (mDNS_DebugMode)

Revision 1.149  2004/01/28 02:30:08  ksekar
Added default Search Domains to unicast browsing, controlled via
Networking sharing prefs pane.  Stopped sending unicast messages on
every interface.  Fixed unicast resolving via mach-port API.

Revision 1.148  2004/01/25 00:03:20  cheshire
Change to use mDNSVal16() instead of private PORT_AS_NUM() macro

Revision 1.147  2004/01/19 19:51:46  cheshire
Fix compiler error (mixed declarations and code) on some versions of Linux

Revision 1.146  2003/12/08 21:00:46  rpantos
Changes to support mDNSResponder on Linux.

Revision 1.145  2003/12/05 22:08:07  cheshire
Update version string to "mDNSResponder-61", including new mechanism to allow dots (e.g. 58.1)

Revision 1.144  2003/11/19 23:21:08  ksekar
<rdar://problem/3486646>: config change handler not called for dns-sd services

Revision 1.143  2003/11/14 21:18:32  cheshire
<rdar://problem/3484766>: Security: Crashing bug in mDNSResponder
Fix code that should use buffer size MAX_ESCAPED_DOMAIN_NAME (1005) instead of 256-byte buffers.

Revision 1.142  2003/11/08 22:18:29  cheshire
<rdar://problem/3477870>: Don't need to show process ID in *every* mDNSResponder syslog message

Revision 1.141  2003/11/07 02:30:57  cheshire
Also check per-slot cache use counts in SIGINFO state log

Revision 1.140  2003/10/21 19:58:26  cheshire
<rdar://problem/3459037> Syslog messages should show TTL as signed (for overdue records)

Revision 1.139  2003/10/21 00:10:18  rpantos
<rdar://problem/3409401>: mDNSResponder should not run as root

Revision 1.138  2003/10/07 20:16:58  cheshire
Shorten syslog message a bit

Revision 1.137  2003/09/23 02:12:43  cheshire
Also include port number in list of services registered via new UDS API

Revision 1.136  2003/09/23 02:07:25  cheshire
Include port number in DNSServiceRegistration START/STOP messages

Revision 1.135  2003/09/23 01:34:02  cheshire
In SIGINFO state log, show remaining TTL on cache records, and port number on ServiceRegistrations

Revision 1.134  2003/08/21 20:01:37  cheshire
<rdar://problem/3387941> Traffic reduction: Detect long-lived Resolve() calls, and report them in syslog

Revision 1.133  2003/08/20 23:39:31  cheshire
<rdar://problem/3344098> Review syslog messages, and remove as appropriate

Revision 1.132  2003/08/20 01:44:56  cheshire
Fix errors in LogOperation() calls (only used for debugging)

Revision 1.131  2003/08/19 05:39:43  cheshire
<rdar://problem/3380097> SIGINFO dump should include resolves started by DNSServiceQueryRecord

Revision 1.130  2003/08/16 03:39:01  cheshire
<rdar://problem/3338440> InterfaceID -1 indicates "local only"

Revision 1.129  2003/08/15 20:16:03  cheshire
<rdar://problem/3366590> mDNSResponder takes too much RPRVT
We want to avoid touching the rdata pages, so we don't page them in.
1. RDLength was stored with the rdata, which meant touching the page just to find the length.
   Moved this from the RData to the ResourceRecord object.
2. To avoid unnecessarily touching the rdata just to compare it,
   compute a hash of the rdata and store the hash in the ResourceRecord object.

Revision 1.128  2003/08/14 19:30:36  cheshire
<rdar://problem/3378473> Include list of cache records in SIGINFO output

Revision 1.127  2003/08/14 02:18:21  cheshire
<rdar://problem/3375491> Split generic ResourceRecord type into two separate types: AuthRecord and CacheRecord

Revision 1.126  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

Revision 1.125  2003/08/08 18:36:04  cheshire
<rdar://problem/3344154> Only need to revalidate on interface removal on platforms that have the PhantomInterfaces bug

Revision 1.124  2003/07/25 18:28:23  cheshire
Minor fix to error messages in syslog: Display string parameters with quotes

Revision 1.123  2003/07/23 17:45:28  cheshire
<rdar://problem/3339388> mDNSResponder leaks a bit
Don't allocate memory for the reply until after we've verified that the reply is valid

Revision 1.122  2003/07/23 00:00:04  cheshire
Add comments

Revision 1.121  2003/07/20 03:38:51  ksekar
<rdar://problem/3320722> Completed support for Unix-domain socket based API.

Revision 1.120  2003/07/18 00:30:00  cheshire
<rdar://problem/3268878> Remove mDNSResponder version from packet header and use HINFO record instead

Revision 1.119  2003/07/17 19:08:58  cheshire
<rdar://problem/3332153> Remove calls to enable obsolete UDS code

Revision 1.118  2003/07/15 21:12:28  cheshire
Added extra debugging checks in validatelists() (not used in final shipping version)

Revision 1.117  2003/07/15 01:55:15  cheshire
<rdar://problem/3315777> Need to implement service registration with subtypes

Revision 1.116  2003/07/02 21:19:51  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.115  2003/07/02 02:41:24  cheshire
<rdar://problem/2986146> mDNSResponder needs to start with a smaller cache and then grow it as needed

Revision 1.114  2003/07/01 21:10:20  cheshire
Reinstate checkin 1.111, inadvertently overwritten by checkin 1.112

Revision 1.113  2003/06/28 17:27:43  vlubet
<rdar://problem/3221246> Redirect standard input, standard output, and
standard error file descriptors to /dev/null just like any other
well behaved daemon

Revision 1.112  2003/06/25 23:42:19  ksekar
<rdar://problem/3249292>: Feature: New DNS-SD APIs (#7875)
Reviewed by: Stuart Cheshire
Added files necessary to implement Unix domain sockets based enhanced
DNS-SD APIs, and integrated with existing Mach-port based daemon.

Revision 1.111  2003/06/11 01:02:43  cheshire
<rdar://problem/3287858> mDNSResponder binary compatibility
Make single binary that can run on both Jaguar and Panther.

Revision 1.110  2003/06/10 01:14:11  cheshire
<rdar://problem/3286004> New APIs require a mDNSPlatformInterfaceIDfromInterfaceIndex() call

Revision 1.109  2003/06/06 19:53:43  cheshire
For clarity, rename question fields name/rrtype/rrclass as qname/qtype/qclass
(Global search-and-replace; no functional change to code execution.)

Revision 1.108  2003/06/06 14:08:06  cheshire
For clarity, pull body of main while() loop out into a separate function called mDNSDaemonIdle()

Revision 1.107  2003/05/29 05:44:55  cheshire
Minor fixes to log messages

Revision 1.106  2003/05/27 18:30:55  cheshire
<rdar://problem/3262962> Need a way to easily examine current mDNSResponder state
Dean Reece suggested SIGINFO is more appropriate than SIGHUP

Revision 1.105  2003/05/26 03:21:29  cheshire
Tidy up address structure naming:
mDNSIPAddr         => mDNSv4Addr (for consistency with mDNSv6Addr)
mDNSAddr.addr.ipv4 => mDNSAddr.ip.v4
mDNSAddr.addr.ipv6 => mDNSAddr.ip.v6

Revision 1.104  2003/05/26 00:42:06  cheshire
<rdar://problem/3268876> Temporarily include mDNSResponder version in packets

Revision 1.103  2003/05/23 23:07:44  cheshire
<rdar://problem/3268199> Must not write to stderr when running as daemon

Revision 1.102  2003/05/22 01:32:31  cheshire
Fix typo in Log message format string

Revision 1.101  2003/05/22 00:26:55  cheshire
<rdar://problem/3239284> DNSServiceRegistrationCreate() should return error on dup
Modify error message to explain that this is technically legal, but may indicate a bug.

Revision 1.100  2003/05/21 21:02:24  ksekar
<rdar://problem/3247035>: Service should be prefixed
Changed kmDNSBootstrapName to "com.apple.mDNSResponderRestart" since we're changing the main
Mach message port to "com.apple.mDNSResponder.

Revision 1.99  2003/05/21 17:33:49  cheshire
Fix warnings (mainly printf format string warnings, like using "%d" where it should say "%lu", etc.)

Revision 1.98  2003/05/20 00:33:07  cheshire
<rdar://problem/3262962> Need a way to easily examine current mDNSResponder state
SIGHUP now writes state summary to syslog

Revision 1.97  2003/05/08 00:19:08  cheshire
<rdar://problem/3250330> Forgot to set "err = mStatus_BadParamErr" in a couple of places

Revision 1.96  2003/05/07 22:10:46  cheshire
<rdar://problem/3250330> Add a few more error logging messages

Revision 1.95  2003/05/07 19:20:17  cheshire
<rdar://problem/3251391> Add version number to mDNSResponder builds

Revision 1.94  2003/05/07 00:28:18  cheshire
<rdar://problem/3250330> Need to make mDNSResponder more defensive against bad clients

Revision 1.93  2003/05/06 00:00:49  cheshire
<rdar://problem/3248914> Rationalize naming of domainname manipulation functions

Revision 1.92  2003/04/04 20:38:57  cheshire
Add $Log header

 */

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <unistd.h>
#include <paths.h>
#include <fcntl.h>
#include <pwd.h>
#include <SystemConfiguration/SCPreferencesSetSpecific.h>

#include "DNSServiceDiscoveryRequestServer.h"
#include "DNSServiceDiscoveryReply.h"

#include "DNSCommon.h"
#include "mDNSMacOSX.h"				// Defines the specific types needed to run mDNS on this platform

#include "uds_daemon.h"				// Interface to the server side implementation of dns_sd.h

#include "GenLinkedList.h"

#include <DNSServiceDiscovery/DNSServiceDiscovery.h>

//*************************************************************************************************************
// Macros

// Note: The C preprocessor stringify operator ('#') makes a string from its argument, without macro expansion
// e.g. If "version" is #define'd to be "4", then STRINGIFY_AWE(version) will return the string "version", not "4"
// To expand "version" to its value before making the string, use STRINGIFY(version) instead
#define STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s) #s
#define STRINGIFY(s) STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s)

//*************************************************************************************************************
// Globals

#define LOCAL_DEFAULT_REG 1 // empty string means register in the local domain
#define DEFAULT_REG_DOMAIN "apple.com." // used if the above flag is turned off
static mDNS_PlatformSupport PlatformStorage;

// Start off with a default cache of 16K (about 100 records)
#define RR_CACHE_SIZE ((16*1024) / sizeof(CacheRecord))
static CacheEntity rrcachestorage[RR_CACHE_SIZE];

static const char kmDNSBootstrapName[] = "com.apple.mDNSResponderRestart";
static mach_port_t client_death_port = MACH_PORT_NULL;
static mach_port_t signal_port       = MACH_PORT_NULL;
static mach_port_t server_priv_port  = MACH_PORT_NULL;

// mDNS Mach Message Timeout, in milliseconds.
// We need this to be short enough that we don't deadlock the mDNSResponder if a client
// fails to service its mach message queue, but long enough to give a well-written
// client a chance to service its mach message queue without getting cut off.
// Empirically, 50ms seems to work, so we set the timeout to 250ms to give
// even extra-slow clients a fair chance before we cut them off.
#define MDNS_MM_TIMEOUT 250

static int restarting_via_mach_init = 0;
static int started_via_launchdaemon = 0;

static int OSXVers;

//*************************************************************************************************************
// Active client list structures

typedef struct DNSServiceDomainEnumeration_struct DNSServiceDomainEnumeration;
struct DNSServiceDomainEnumeration_struct
	{
	DNSServiceDomainEnumeration *next;
	mach_port_t ClientMachPort;
	DNSQuestion dom;	// Question asking for domains
	DNSQuestion def;	// Question asking for default domain
	};

typedef struct DNSServiceBrowserResult_struct DNSServiceBrowserResult;
struct DNSServiceBrowserResult_struct
	{
	DNSServiceBrowserResult *next;
	int resultType;
	domainname result;
	};

typedef struct DNSServiceBrowser_struct DNSServiceBrowser;

typedef struct DNSServiceBrowserQuestion
	{
	struct DNSServiceBrowserQuestion *next;
	DNSQuestion q;
    domainname domain;
	} DNSServiceBrowserQuestion;

struct DNSServiceBrowser_struct
	{
	DNSServiceBrowser *next;
	mach_port_t ClientMachPort;
	DNSServiceBrowserQuestion *qlist;
	DNSServiceBrowserResult *results;
	mDNSs32 lastsuccess;
    mDNSBool DefaultDomain;                // was the browse started on an explicit domain?
    domainname type;                       //  registration type 
	};

typedef struct DNSServiceResolver_struct DNSServiceResolver;
struct DNSServiceResolver_struct
	{
	DNSServiceResolver *next;
	mach_port_t ClientMachPort;
	ServiceInfoQuery q;
	ServiceInfo      i;
	mDNSs32          ReportTime;
	};

// A single registered service: ServiceRecordSet + bookkeeping
// Note that we duplicate some fields from parent DNSServiceRegistration object
// to facilitate cleanup, when instances and parent may be deallocated at different times.
typedef struct ServiceInstance
	{
    struct ServiceInstance *next;
	mach_port_t ClientMachPort;
    mDNSBool autoname;			// Set if this name is tied to the Computer Name
    mDNSBool autorename;		// Set if we just got a name conflict and now need to automatically pick a new name
    domainlabel name;
    domainname domain;
    ServiceRecordSet srs;
	// Don't add any fields after ServiceRecordSet.
	// This is where the implicit extra space goes if we allocate an oversized ServiceRecordSet object
	} ServiceInstance;

// A client-created service.  May reference several ServiceInstance objects if default
// settings cause registration in multiple domains.
typedef struct DNSServiceRegistration
	{
    struct DNSServiceRegistration *next;
	mach_port_t ClientMachPort;
    mDNSBool DefaultDomain;
    mDNSBool autoname;
    size_t rdsize;
    int NumSubTypes;
    char regtype[MAX_ESCAPED_DOMAIN_NAME]; // for use in AllocateSubtypes
    domainlabel name;  // used only if autoname is false 
    domainname type;
    mDNSIPPort port;
    unsigned char txtinfo[1024];
    size_t txt_len;
    uint32_t NextRef;
    ServiceInstance *regs;
	} DNSServiceRegistration;

static DNSServiceDomainEnumeration *DNSServiceDomainEnumerationList = NULL;
static DNSServiceBrowser           *DNSServiceBrowserList           = NULL;
static DNSServiceResolver          *DNSServiceResolverList          = NULL;
static DNSServiceRegistration      *DNSServiceRegistrationList      = NULL;

//*************************************************************************************************************
// General Utility Functions

#if MACOSX_MDNS_MALLOC_DEBUGGING

char _malloc_options[] = "AXZ";

mDNSlocal void validatelists(mDNS *const m)
	{
	DNSServiceDomainEnumeration *e;
	DNSServiceBrowser           *b;
	DNSServiceResolver          *l;
	DNSServiceRegistration      *r;
	AuthRecord                  *rr;
	CacheGroup                  *cg;
	CacheRecord                 *cr;
	DNSQuestion                 *q;
	mDNSu32 slot;
	NetworkInterfaceInfoOSX     *i;

	for (e = DNSServiceDomainEnumerationList; e; e=e->next)
		if (e->ClientMachPort == 0 || e->ClientMachPort == (mach_port_t)~0)
			LogMsg("!!!! DNSServiceDomainEnumerationList: %p is garbage (%X) !!!!", e, e->ClientMachPort);

	for (b = DNSServiceBrowserList; b; b=b->next)
		if (b->ClientMachPort == 0 || b->ClientMachPort == (mach_port_t)~0)
			LogMsg("!!!! DNSServiceBrowserList: %p is garbage (%X) !!!!", b, b->ClientMachPort);

	for (l = DNSServiceResolverList; l; l=l->next)
		if (l->ClientMachPort == 0 || l->ClientMachPort == (mach_port_t)~0)
			LogMsg("!!!! DNSServiceResolverList: %p is garbage (%X) !!!!", l, l->ClientMachPort);

	for (r = DNSServiceRegistrationList; r; r=r->next)
		if (r->ClientMachPort == 0 || r->ClientMachPort == (mach_port_t)~0)
			LogMsg("!!!! DNSServiceRegistrationList: %p is garbage (%X) !!!!", r, r->ClientMachPort);

	for (rr = m->ResourceRecords; rr; rr=rr->next)
		{
		if (rr->resrec.RecordType == 0 || rr->resrec.RecordType == 0xFF)
			LogMsg("!!!! ResourceRecords list: %p is garbage (%X) !!!!", rr, rr->resrec.RecordType);
		if (rr->resrec.name != &rr->namestorage)
			LogMsg("!!!! ResourceRecords list: %p name %p does not point to namestorage %p %##s",
				rr, rr->resrec.name->c, rr->namestorage.c, rr->namestorage.c);
		}

	for (rr = m->DuplicateRecords; rr; rr=rr->next)
		if (rr->resrec.RecordType == 0 || rr->resrec.RecordType == 0xFF)
			LogMsg("!!!! DuplicateRecords list: %p is garbage (%X) !!!!", rr, rr->resrec.RecordType);

	for (q = m->Questions; q; q=q->next)
		if (q->ThisQInterval == (mDNSs32)~0)
			LogMsg("!!!! Questions list: %p is garbage (%lX) !!!!", q, q->ThisQInterval);

	FORALL_CACHERECORDS(slot, cg, cr)
		if (cr->resrec.RecordType == 0 || cr->resrec.RecordType == 0xFF)
			LogMsg("!!!! Cache slot %lu: %p is garbage (%X) !!!!", slot, rr, rr->resrec.RecordType);

	for (i = m->p->InterfaceList; i; i = i->next)
		if (!i->ifa_name)
			LogMsg("!!!! InterfaceList: %p is garbage !!!!", i);
	}

void *mallocL(char *msg, unsigned int size)
	{
	unsigned long *mem = malloc(size+8);
	if (!mem)
		{
		LogMsg("malloc( %s : %d ) failed", msg, size);
		return(NULL);
		}
	else
		{
		LogMalloc("malloc( %s : %lu ) = %p", msg, size, &mem[2]);
		mem[0] = 0xDEAD1234;
		mem[1] = size;
		//bzero(&mem[2], size);
		memset(&mem[2], 0xFF, size);
		validatelists(&mDNSStorage);
		return(&mem[2]);
		}
	}

void freeL(char *msg, void *x)
	{
	if (!x)
		LogMsg("free( %s @ NULL )!", msg);
	else
		{
		unsigned long *mem = ((unsigned long *)x) - 2;
		if (mem[0] != 0xDEAD1234)
			{ LogMsg("free( %s @ %p ) !!!! NOT ALLOCATED !!!!", msg, &mem[2]); return; }
		if (mem[1] > 24000)
			{ LogMsg("free( %s : %ld @ %p) too big!", msg, mem[1], &mem[2]); return; }
		LogMalloc("free( %s : %ld @ %p)", msg, mem[1], &mem[2]);
		//bzero(mem, mem[1]+8);
		memset(mem, 0xFF, mem[1]+8);
		validatelists(&mDNSStorage);
		free(mem);
		}
	}

#endif

//*************************************************************************************************************
// Client Death Detection

mDNSlocal void FreeServiceInstance(ServiceInstance *x)
	{
	ServiceRecordSet *s = &x->srs;
	ExtraResourceRecord *e = x->srs.Extras, *tmp;
	
	while(e)
		{
		e->r.RecordContext = e;
		tmp = e;
		e = e->next;
		FreeExtraRR(&mDNSStorage, &tmp->r, mStatus_MemFree);
		}
	
	if (s->RR_TXT.resrec.rdata != &s->RR_TXT.rdatastorage)
			freeL("TXT RData", s->RR_TXT.resrec.rdata);

	if (s->SubTypes) freeL("ServiceSubTypes", s->SubTypes);
	freeL("ServiceInstance", x);
	}

// AbortClient finds whatever client is identified by the given Mach port,
// stops whatever operation that client was doing, and frees its memory.
// In the case of a service registration, the actual freeing may be deferred
// until we get the mStatus_MemFree message, if necessary
mDNSlocal void AbortClient(mach_port_t ClientMachPort, void *m)
	{
	DNSServiceDomainEnumeration **e = &DNSServiceDomainEnumerationList;
	DNSServiceBrowser           **b = &DNSServiceBrowserList;
	DNSServiceResolver          **l = &DNSServiceResolverList;
	DNSServiceRegistration      **r = &DNSServiceRegistrationList;

	while (*e && (*e)->ClientMachPort != ClientMachPort) e = &(*e)->next;
	if (*e)
		{
		DNSServiceDomainEnumeration *x = *e;
		*e = (*e)->next;
		if (m && m != x)
			LogMsg("%5d: DNSServiceDomainEnumeration(%##s) STOP; WARNING m %p != x %p", ClientMachPort, x->dom.qname.c, m, x);
		else LogOperation("%5d: DNSServiceDomainEnumeration(%##s) STOP", ClientMachPort, x->dom.qname.c);
		mDNS_StopGetDomains(&mDNSStorage, &x->dom);
		mDNS_StopGetDomains(&mDNSStorage, &x->def);
		freeL("DNSServiceDomainEnumeration", x);
		return;
		}

	while (*b && (*b)->ClientMachPort != ClientMachPort) b = &(*b)->next;
	if (*b)
		{
		DNSServiceBrowser *x = *b;
		DNSServiceBrowserQuestion *freePtr, *qptr = x->qlist;
		*b = (*b)->next;
		while (qptr)
			{
			if (m && m != x)
				LogMsg("%5d: DNSServiceBrowser(%##s) STOP; WARNING m %p != x %p", ClientMachPort, qptr->q.qname.c, m, x);
			else LogOperation("%5d: DNSServiceBrowser(%##s) STOP", ClientMachPort, qptr->q.qname.c);
			mDNS_StopBrowse(&mDNSStorage, &qptr->q);
			freePtr = qptr;
			qptr = qptr->next;
			freeL("DNSServiceBrowserQuestion", freePtr);
			}
		while (x->results)
			{
			DNSServiceBrowserResult *r = x->results;
			x->results = x->results->next;
			freeL("DNSServiceBrowserResult", r);
			}
		freeL("DNSServiceBrowser", x);
		return;
		}

	while (*l && (*l)->ClientMachPort != ClientMachPort) l = &(*l)->next;
	if (*l)
		{
		DNSServiceResolver *x = *l;
		*l = (*l)->next;
		if (m && m != x)
			LogMsg("%5d: DNSServiceResolver(%##s) STOP; WARNING m %p != x %p", ClientMachPort, x->i.name.c, m, x);
		else LogOperation("%5d: DNSServiceResolver(%##s) STOP", ClientMachPort, x->i.name.c);
		mDNS_StopResolveService(&mDNSStorage, &x->q);
		freeL("DNSServiceResolver", x);
		return;
		}

	while (*r && (*r)->ClientMachPort != ClientMachPort) r = &(*r)->next;
	if (*r)
		{
		ServiceInstance *si = NULL;
		DNSServiceRegistration *x = *r;
		*r = (*r)->next;

		si = x->regs;
		while (si)
			{
			ServiceInstance *instance = si;
			si = si->next;                 
			instance->autorename = mDNSfalse;
			if (m && m != x) LogMsg("%5d: DNSServiceRegistration(%##s, %u) STOP; WARNING m %p != x %p", ClientMachPort, instance->srs.RR_SRV.resrec.name->c, SRS_PORT(&instance->srs), m, x);			
			else LogOperation("%5d: DNSServiceRegistration(%##s, %u) STOP", ClientMachPort, instance->srs.RR_SRV.resrec.name->c, SRS_PORT(&instance->srs));

			// If mDNS_DeregisterService() returns mStatus_NoError, that means that the service was found in the list,
			// is sending its goodbye packet, and we'll get an mStatus_MemFree message when we can free the memory.
			// If mDNS_DeregisterService() returns an error, it means that the service had already been removed from
			// the list, so we should go ahead and free the memory right now
			if (mDNS_DeregisterService(&mDNSStorage, &instance->srs)) FreeServiceInstance(instance); // FreeServiceInstance invalidates pointer
			}
		x->regs = NULL;		
		freeL("DNSServiceRegistration", x);
		return;
		}

	LogMsg("%5d: died or deallocated, but no record of client can be found!", ClientMachPort);
	}

#define AbortBlockedClient(C,MSG,M) AbortClientWithLogMessage((C), "stopped accepting Mach messages", " (" MSG ")", (M))

mDNSlocal void AbortClientWithLogMessage(mach_port_t c, char *reason, char *msg, void *m)
	{
	DNSServiceDomainEnumeration *e = DNSServiceDomainEnumerationList;
	DNSServiceBrowser           *b = DNSServiceBrowserList;
	DNSServiceResolver          *l = DNSServiceResolverList;
	DNSServiceRegistration      *r = DNSServiceRegistrationList;
	DNSServiceBrowserQuestion   *qptr;

	while (e && e->ClientMachPort != c) e = e->next;
	while (b && b->ClientMachPort != c) b = b->next;
	while (l && l->ClientMachPort != c) l = l->next;
	while (r && r->ClientMachPort != c) r = r->next;
	if      (e)     LogMsg("%5d: DomainEnumeration(%##s) %s%s",                   c, e->dom.qname.c,            reason, msg);
	else if (b)
		{
		for (qptr = b->qlist; qptr; qptr = qptr->next)
			        LogMsg("%5d: Browser(%##s) %s%s",                             c, qptr->q.qname.c,              reason, msg);
		}
	else if (l)     LogMsg("%5d: Resolver(%##s) %s%s",                            c, l->i.name.c,               reason, msg);
	else if (r)
		{
		ServiceInstance *si;
		for (si = r->regs; si; si = si->next) LogMsg("%5d: Registration(%##s) %s%s", c, si->srs.RR_SRV.resrec.name->c, reason, msg);
		}
	else            LogMsg("%5d: (%s) %s, but no record of client can be found!", c,                            reason, msg);

	AbortClient(c, m);
	}

mDNSlocal mDNSBool CheckForExistingClient(mach_port_t c)
	{
	DNSServiceDomainEnumeration *e = DNSServiceDomainEnumerationList;
	DNSServiceBrowser           *b = DNSServiceBrowserList;
	DNSServiceResolver          *l = DNSServiceResolverList;
	DNSServiceRegistration      *r = DNSServiceRegistrationList;
	DNSServiceBrowserQuestion   *qptr;

	while (e && e->ClientMachPort != c) e = e->next;
	while (b && b->ClientMachPort != c) b = b->next;
	while (l && l->ClientMachPort != c) l = l->next;
	while (r && r->ClientMachPort != c) r = r->next;
	if (e) LogMsg("%5d: DomainEnumeration(%##s) already exists!", c, e->dom.qname.c);
	if (b)
		{
		for (qptr = b->qlist; qptr; qptr = qptr->next)
			LogMsg("%5d: Browser(%##s) already exists!",          c, qptr->q.qname.c);
		}
	if (l) LogMsg("%5d: Resolver(%##s) already exists!",          c, l->i.name.c);
	if (r) LogMsg("%5d: Registration(%##s) already exists!",      c, r->regs ? r->regs->srs.RR_SRV.resrec.name->c : NULL);
	return(e || b || l || r);
	}

mDNSlocal void ClientDeathCallback(CFMachPortRef unusedport, void *voidmsg, CFIndex size, void *info)
	{
	mach_msg_header_t *msg = (mach_msg_header_t *)voidmsg;
	(void)unusedport; // Unused
	(void)size; // Unused
	(void)info; // Unused
	if (msg->msgh_id == MACH_NOTIFY_DEAD_NAME)
		{
		const mach_dead_name_notification_t *const deathMessage = (mach_dead_name_notification_t *)msg;
		AbortClient(deathMessage->not_port, NULL);

		/* Deallocate the send right that came in the dead name notification */
		mach_port_destroy(mach_task_self(), deathMessage->not_port);
		}
	}

mDNSlocal void EnableDeathNotificationForClient(mach_port_t ClientMachPort, void *m)
	{
	mach_port_t prev;
	kern_return_t r = mach_port_request_notification(mach_task_self(), ClientMachPort, MACH_NOTIFY_DEAD_NAME, 0,
													 client_death_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
	// If the port already died while we were thinking about it, then abort the operation right away
	if (r != KERN_SUCCESS)
		AbortClientWithLogMessage(ClientMachPort, "died/deallocated before we could enable death notification", "", m);
	}

//*************************************************************************************************************
// Domain Enumeration

mDNSlocal void DomainEnumFound(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	kern_return_t status;
	#pragma unused(m)
	char buffer[MAX_ESCAPED_DOMAIN_NAME];
	DNSServiceDomainEnumerationReplyResultType rt;
	DNSServiceDomainEnumeration *x = (DNSServiceDomainEnumeration *)question->QuestionContext;

	debugf("DomainEnumFound: %##s PTR %##s", answer->name->c, answer->rdata->u.name.c);
	if (answer->rrtype != kDNSType_PTR) return;
	if (!x) { debugf("DomainEnumFound: DNSServiceDomainEnumeration is NULL"); return; }

	if (AddRecord)
		{
		if (question == &x->dom) rt = DNSServiceDomainEnumerationReplyAddDomain;
		else                     rt = DNSServiceDomainEnumerationReplyAddDomainDefault;
		}
	else
		{
		if (question == &x->dom) rt = DNSServiceDomainEnumerationReplyRemoveDomain;
		else return;
		}

	LogOperation("%5d: DNSServiceDomainEnumeration(%##s) %##s %s",
		x->ClientMachPort, x->dom.qname.c, answer->rdata->u.name.c,
		!AddRecord ? "RemoveDomain" :
		question == &x->dom ? "AddDomain" : "AddDomainDefault");

	ConvertDomainNameToCString(&answer->rdata->u.name, buffer);
	status = DNSServiceDomainEnumerationReply_rpc(x->ClientMachPort, rt, buffer, 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		AbortBlockedClient(x->ClientMachPort, "enumeration", x);
	}

mDNSexport kern_return_t provide_DNSServiceDomainEnumerationCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	int regDom)
	{
	// Check client parameter
	(void)unusedserver; // Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

	mDNS_DomainType dt1 = regDom ? mDNS_DomainTypeRegistration        : mDNS_DomainTypeBrowse;
	mDNS_DomainType dt2 = regDom ? mDNS_DomainTypeRegistrationDefault : mDNS_DomainTypeBrowseDefault;

	// Allocate memory, and handle failure
	DNSServiceDomainEnumeration *x = mallocL("DNSServiceDomainEnumeration", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->next = DNSServiceDomainEnumerationList;
	DNSServiceDomainEnumerationList = x;

	verbosedebugf("%5d: Enumerate %s Domains", client, regDom ? "Registration" : "Browsing");

	// Do the operation
	err           = mDNS_GetDomains(&mDNSStorage, &x->dom, dt1, NULL, mDNSInterface_LocalOnly, DomainEnumFound, x);
	if (!err) err = mDNS_GetDomains(&mDNSStorage, &x->def, dt2, NULL, mDNSInterface_LocalOnly, DomainEnumFound, x);
	if (err) { AbortClient(client, x); errormsg = "mDNS_GetDomains"; goto fail; }

	// Succeeded: Wrap up and return
	LogOperation("%5d: DNSServiceDomainEnumeration(%##s) START", client, x->dom.qname.c);
	EnableDeathNotificationForClient(client, x);
	return(mStatus_NoError);

fail:
	LogMsg("%5d: DNSServiceDomainEnumeration(%d) failed: %s (%ld)", client, regDom, errormsg, err);
	return(err);
	}

//*************************************************************************************************************
// Browse for services

mDNSlocal void FoundInstance(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	(void)m;		// Unused

	if (answer->rrtype != kDNSType_PTR)
		{ LogMsg("FoundInstance: Should not be called with rrtype %d (not a PTR record)", answer->rrtype); return; }

	domainlabel name;
	domainname type, domain;
	if (!DeconstructServiceName(&answer->rdata->u.name, &name, &type, &domain))
		{
		LogMsg("FoundInstance: %##s PTR %##s received from network is not valid DNS-SD service pointer",
			answer->name->c, answer->rdata->u.name.c);
		return;
		}

	DNSServiceBrowserResult *x = mallocL("DNSServiceBrowserResult", sizeof(*x));
	if (!x) { LogMsg("FoundInstance: Failed to allocate memory for result %##s", answer->rdata->u.name.c); return; }

	verbosedebugf("FoundInstance: %s %##s", AddRecord ? "Add" : "Rmv", answer->rdata->u.name.c);
	AssignDomainName(&x->result, &answer->rdata->u.name);
	if (AddRecord)
		 x->resultType = DNSServiceBrowserReplyAddInstance;
	else x->resultType = DNSServiceBrowserReplyRemoveInstance;
	x->next = NULL;

	DNSServiceBrowser *browser = (DNSServiceBrowser *)question->QuestionContext;
	DNSServiceBrowserResult **p = &browser->results;
	while (*p) p = &(*p)->next;
	*p = x;
	}

mDNSlocal mStatus AddDomainToBrowser(DNSServiceBrowser *browser, const domainname *d)
	{
	mStatus err = mStatus_NoError;
	DNSServiceBrowserQuestion *ptr, *question = NULL;

	for (ptr = browser->qlist; ptr; ptr = ptr->next)
		{
		if (SameDomainName(&ptr->q.qname, d))
			{ debugf("Domain %##s already contained in browser", d->c); return mStatus_AlreadyRegistered; }
		}
	
	question = mallocL("DNSServiceBrowserQuestion", sizeof(DNSServiceBrowserQuestion));
	if (!question) { LogMsg("Error: malloc"); return mStatus_NoMemoryErr; }
	AssignDomainName(&question->domain, d);
	question->next = browser->qlist;
	browser->qlist = question;
	LogOperation("%5d: DNSServiceBrowse(%##s%##s) START", browser->ClientMachPort, browser->type.c, d->c);
	err = mDNS_StartBrowse(&mDNSStorage, &question->q, &browser->type, d, mDNSInterface_Any, mDNSfalse, FoundInstance, browser);
	if (err) LogMsg("Error: AddDomainToBrowser: mDNS_StartBrowse %d", err);
	return err;
	}

mDNSexport void DefaultBrowseDomainChanged(const domainname *d, mDNSBool add)
	{
	DNSServiceBrowser *ptr;

	debugf("DefaultBrowseDomainChanged: %s default browse domain %##s", add ? "Adding" : "Removing", d->c);
	for (ptr = DNSServiceBrowserList; ptr; ptr = ptr->next)
		{
		if (ptr->DefaultDomain)
			{
			if (add)
				{
				mStatus err = AddDomainToBrowser(ptr, d);
				if (err && err != mStatus_AlreadyRegistered) LogMsg("Default browse in domain %##s for client %5d failed. Continuing", d, ptr->ClientMachPort);
				}
			else
				{
				DNSServiceBrowserQuestion **q = &ptr->qlist;
				while (*q)
					{
					if (SameDomainName(&(*q)->domain, d))
						{
						DNSServiceBrowserQuestion *remove = *q;
						*q = (*q)->next;
						if (remove->q.LongLived)
							{
							// give goodbyes for known answers.  note that since events are sent to client via udns_execute(),
							// we don't need to worry about the question being cancelled mid-loop
							CacheRecord *ka = remove->q.uDNS_info.knownAnswers;
							while (ka) { remove->q.QuestionCallback(&mDNSStorage, &remove->q, &ka->resrec, mDNSfalse); ka = ka->next; }
							}						
						mDNS_StopBrowse(&mDNSStorage, &remove->q);
						freeL("DNSServiceBrowserQuestion", remove );
						return;						
						}					
					q = &(*q)->next;
					}
			    LogMsg("Requested removal of default domain %##s not in client %5d's list", d->c, ptr->ClientMachPort);
				}
			}
		}
	}

mDNSexport kern_return_t provide_DNSServiceBrowserCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString regtype, DNSCString domain)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	DNameListElem *SearchDomains = NULL, *sdPtr;

	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

	// Check other parameters
	domainname t, d;
	t.c[0] = 0;
	mDNSs32 NumSubTypes = ChopSubTypes(regtype);	// Note: Modifies regtype string to remove trailing subtypes
	if (NumSubTypes < 0 || NumSubTypes > 1)               { errormsg = "Bad Service SubType"; goto badparam; }
	if (NumSubTypes == 1 && !AppendDNSNameString(&t, regtype + strlen(regtype) + 1))
	                                                      { errormsg = "Bad Service SubType"; goto badparam; }
	if (!regtype[0] || !AppendDNSNameString(&t, regtype)) { errormsg = "Illegal regtype";     goto badparam; }
	domainname temp;
	if (!MakeDomainNameFromDNSNameString(&temp, regtype)) { errormsg = "Illegal regtype";     goto badparam; }
	if (temp.c[0] > 15 && (!domain || domain[0] == 0)) domain = "local."; // For over-long service types, we only allow domain "local"

	// Allocate memory, and handle failure
	DNSServiceBrowser *x = mallocL("DNSServiceBrowser", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	AssignDomainName(&x->type, &t);
	x->ClientMachPort = client;
	x->results = NULL;
	x->lastsuccess = 0;
	x->qlist = NULL;
	x->next = DNSServiceBrowserList;
	DNSServiceBrowserList = x;

	if (domain[0])
		{
		// Start browser for an explicit domain
		x->DefaultDomain = mDNSfalse;
		if (!MakeDomainNameFromDNSNameString(&d, domain)) { errormsg = "Illegal domain";  goto badparam; }		
		err = AddDomainToBrowser(x, &d);
		if (err) { AbortClient(client, x); errormsg = "AddDomainToBrowser"; goto fail; }
		}
	else
		{
		// Start browser on all domains
		x->DefaultDomain = mDNStrue;
		SearchDomains = mDNSPlatformGetSearchDomainList();
		if (!SearchDomains) { AbortClient(client, x); errormsg = "GetSearchDomainList"; goto fail; }
		for (sdPtr = SearchDomains; sdPtr; sdPtr = sdPtr->next)
			{
			err = AddDomainToBrowser(x, &sdPtr->name);
			if (err)
				{
				// only terminally bail if .local fails
				if (!SameDomainName(&localdomain, &sdPtr->name))
					LogMsg("Default browse in domain %##s failed. Continuing", sdPtr->name.c);
				else { AbortClient(client, x); errormsg = "AddDomainToBrowser"; goto fail; }
				}
			}
		}
	
	// Succeeded: Wrap up and return
	EnableDeathNotificationForClient(client, x);
	mDNS_FreeDNameList(SearchDomains);
	return(mStatus_NoError);

	badparam:
	err = mStatus_BadParamErr;
fail:
	LogMsg("%5d: DNSServiceBrowse(\"%s\", \"%s\") failed: %s (%ld)", client, regtype, domain, errormsg, err);
	if (SearchDomains) mDNS_FreeDNameList(SearchDomains);
	return(err);
		}

//*************************************************************************************************************
// Resolve Service Info
	
mDNSlocal void FoundInstanceInfo(mDNS *const m, ServiceInfoQuery *query)
	{
	kern_return_t status;
	DNSServiceResolver *x = (DNSServiceResolver *)query->ServiceInfoQueryContext;
	NetworkInterfaceInfoOSX *ifx = (NetworkInterfaceInfoOSX *)query->info->InterfaceID;
	if (query->info->InterfaceID == mDNSInterface_LocalOnly) ifx = mDNSNULL;
	struct sockaddr_storage interface;
	struct sockaddr_storage address;
	char cstring[1024];
	int i, pstrlen = query->info->TXTinfo[0];
	(void)m;		// Unused

	//debugf("FoundInstanceInfo %.4a %.4a %##s", &query->info->InterfaceAddr, &query->info->ip, &query->info->name);

	if (query->info->TXTlen > sizeof(cstring)) return;

	bzero(&interface, sizeof(interface));
	bzero(&address,   sizeof(address));

	if (ifx && ifx->ifinfo.ip.type == mDNSAddrType_IPv4)
		{
		struct sockaddr_in *sin = (struct sockaddr_in*)&interface;
		sin->sin_len         = sizeof(*sin);
		sin->sin_family      = AF_INET;
		sin->sin_port        = 0;
		sin->sin_addr.s_addr = ifx->ifinfo.ip.ip.v4.NotAnInteger;
		}
	else if (ifx && ifx->ifinfo.ip.type == mDNSAddrType_IPv6)
		{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&interface;
		sin6->sin6_len       = sizeof(*sin6);
		sin6->sin6_family    = AF_INET6;
		sin6->sin6_flowinfo  = 0;
		sin6->sin6_port      = 0;
		sin6->sin6_addr		 = *(struct in6_addr*)&ifx->ifinfo.ip.ip.v6;
		sin6->sin6_scope_id  = ifx->scope_id;
		}

	if (query->info->ip.type == mDNSAddrType_IPv4)
		{
		struct sockaddr_in *sin = (struct sockaddr_in*)&address;
		sin->sin_len           = sizeof(*sin);
		sin->sin_family        = AF_INET;
		sin->sin_port          = query->info->port.NotAnInteger;
		sin->sin_addr.s_addr   = query->info->ip.ip.v4.NotAnInteger;
		}
	else
		{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&address;
		sin6->sin6_len           = sizeof(*sin6);
		sin6->sin6_family        = AF_INET6;
		sin6->sin6_port          = query->info->port.NotAnInteger;
		sin6->sin6_flowinfo      = 0;
		sin6->sin6_addr			 = *(struct in6_addr*)&query->info->ip.ip.v6;
		sin6->sin6_scope_id      = ifx ? ifx->scope_id : 0;
		}

	// The OS X DNSServiceResolverResolve() API is defined using a C-string,
	// but the mDNS_StartResolveService() call actually returns a packed block of P-strings.
	// Hence we have to convert the P-string(s) to a C-string before returning the result to the client.
	// ASCII-1 characters are used in the C-string as boundary markers,
	// to indicate the boundaries between the original constituent P-strings.
	for (i=1; i<query->info->TXTlen; i++)
		{
		if (--pstrlen >= 0)
			cstring[i-1] = query->info->TXTinfo[i];
		else
			{
			cstring[i-1] = 1;
			pstrlen = query->info->TXTinfo[i];
			}
		}
	cstring[i-1] = 0;		// Put the terminating NULL on the end

	LogOperation("%5d: DNSServiceResolver(%##s) -> %#a:%u", x->ClientMachPort,
		x->i.name.c, &query->info->ip, mDNSVal16(query->info->port));
	status = DNSServiceResolverReply_rpc(x->ClientMachPort,
		(char*)&interface, (char*)&address, cstring, 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		AbortBlockedClient(x->ClientMachPort, "resolve", x);
	}

mDNSexport kern_return_t provide_DNSServiceResolverResolve_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString name, DNSCString regtype, DNSCString domain)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

	// Check other parameters
	domainlabel n;
	domainname t, d, srv;
	if (!name[0]    || !MakeDomainLabelFromLiteralString(&n, name))        { errormsg = "Bad Instance Name"; goto badparam; }
	if (!regtype[0] || !MakeDomainNameFromDNSNameString(&t, regtype))      { errormsg = "Bad Service Type";  goto badparam; }
	if (!domain[0]  || !MakeDomainNameFromDNSNameString(&d, domain))       { errormsg = "Bad Domain";        goto badparam; }
	if (!ConstructServiceName(&srv, &n, &t, &d))                           { errormsg = "Bad Name";          goto badparam; }

	// Allocate memory, and handle failure
	DNSServiceResolver *x = mallocL("DNSServiceResolver", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->i.InterfaceID = mDNSInterface_Any;
	x->i.name = srv;
	x->ReportTime = NonZeroTime(mDNS_TimeNow(&mDNSStorage) + 130 * mDNSPlatformOneSecond);
	x->next = DNSServiceResolverList;
	DNSServiceResolverList = x;

	// Do the operation
	LogOperation("%5d: DNSServiceResolver(%##s) START", client, x->i.name.c);
	err = mDNS_StartResolveService(&mDNSStorage, &x->q, &x->i, FoundInstanceInfo, x);
	if (err) { AbortClient(client, x); errormsg = "mDNS_StartResolveService"; goto fail; }

	// Succeeded: Wrap up and return
	EnableDeathNotificationForClient(client, x);
	return(mStatus_NoError);

badparam:
	err = mStatus_BadParamErr;
fail:
	LogMsg("%5d: DNSServiceResolve(\"%s\", \"%s\", \"%s\") failed: %s (%ld)", client, name, regtype, domain, errormsg, err);
	return(err);
	}

//*************************************************************************************************************
// Registration

mDNSexport void RecordUpdatedNiceLabel(mDNS *const m, mDNSs32 delay)
	{
	m->p->NotifyUser = NonZeroTime(m->timenow + delay);
	}

mDNSlocal void RegCallback(mDNS *const m, ServiceRecordSet *const srs, mStatus result)
	{
	ServiceInstance *si = (ServiceInstance*)srs->ServiceContext;

	if (result == mStatus_NoError)
		{
		kern_return_t status;
		LogOperation("%5d: DNSServiceRegistration(%##s, %u) Name Registered", si->ClientMachPort, srs->RR_SRV.resrec.name->c, SRS_PORT(srs));
		status = DNSServiceRegistrationReply_rpc(si->ClientMachPort, result, MDNS_MM_TIMEOUT);
		if (status == MACH_SEND_TIMED_OUT)
			AbortBlockedClient(si->ClientMachPort, "registration success", si);
		if (si->autoname && CountPeerRegistrations(m, srs) == 0)
			RecordUpdatedNiceLabel(m, 0);	// Successfully got new name, tell user immediately
		}

	else if (result == mStatus_NameConflict)
		{
		LogOperation("%5d: DNSServiceRegistration(%##s, %u) Name Conflict", si->ClientMachPort, srs->RR_SRV.resrec.name->c, SRS_PORT(srs));
		// Note: By the time we get the mStatus_NameConflict message, the service is already deregistered
		// and the memory is free, so we don't have to wait for an mStatus_MemFree message as well.
		if (si->autoname && CountPeerRegistrations(m, srs) == 0)
			{
			// On conflict for an autoname service, rename and reregister *all* autoname services
			IncrementLabelSuffix(&m->nicelabel, mDNStrue);
			m->MainCallback(m, mStatus_ConfigChanged);
			}
		else if (si->autoname)
			{
            mDNS_RenameAndReregisterService(m, srs, mDNSNULL);
            return;
			}
		else
			{
			// If we get a name conflict, we tell the client about it, and then they are expected to dispose
			// of their registration in the usual way (which we will catch via client death notification).
			// If the Mach queue is full, we forcibly abort the client immediately.
			kern_return_t status = DNSServiceRegistrationReply_rpc(si->ClientMachPort, result, MDNS_MM_TIMEOUT);
			if (status == MACH_SEND_TIMED_OUT)
				AbortBlockedClient(si->ClientMachPort, "registration conflict", NULL);
			}
		}

	else if (result == mStatus_MemFree)
		{
		if (si->autorename)
			{
			debugf("RegCallback renaming %#s to %#s", si->name.c, m->nicelabel.c);
			si->autorename = mDNSfalse;
			si->name = m->nicelabel;
			mDNS_RenameAndReregisterService(m, srs, &si->name);
			}
		else
			{
			// SANITY CHECK: make sure service instance is no longer in any ServiceRegistration's list
			DNSServiceRegistration *r;
			for (r = DNSServiceRegistrationList; r; r = r->next)
				{
				ServiceInstance *sp = r->regs, *prev = NULL;
				while (sp)
					{
					if (sp == si)
						{				  
						LogMsg("RegCallback: %##s Still in DNSServiceRegistration list; removing now", srs->RR_SRV.resrec.name->c);			    
						if (prev) prev->next = sp->next;
						else r->regs = sp->next;
						break;
						}
					prev = sp;
					sp = sp->next;
					}
			    }
			// END SANITY CHECK
			FreeServiceInstance(si);
			}
		}

	else if (result != mStatus_NATTraversal)
		LogMsg("%5d: DNSServiceRegistration(%##s, %u) Unknown Result %ld", si->ClientMachPort, srs->RR_SRV.resrec.name->c, SRS_PORT(srs), result);
	}

mDNSlocal mStatus AddServiceInstance(DNSServiceRegistration *x, const domainname *domain)
	{
	mStatus err = 0;
	ServiceInstance *si = NULL;
	AuthRecord *SubTypes = NULL;

	for (si = x->regs; si; si = si->next)
		{
		if (SameDomainName(&si->domain, domain))
			{ LogMsg("Requested addition of domain %##s already in list", domain->c); return mStatus_AlreadyRegistered; }
		}
	
	SubTypes = AllocateSubTypes(x->NumSubTypes, x->regtype);
	if (x->NumSubTypes && !SubTypes) return mStatus_NoMemoryErr;
	
	si = mallocL("ServiceInstance", sizeof(*si) - sizeof(RDataBody) + x->rdsize);
	if (!si) return mStatus_NoMemoryErr;

	si->ClientMachPort = x->ClientMachPort;
	si->autorename = mDNSfalse;
	si->autoname = x->autoname;
	si->name = x->autoname ? mDNSStorage.nicelabel : x->name;
	si->domain = *domain;

	err = mDNS_RegisterService(&mDNSStorage, &si->srs, &si->name, &x->type, domain, NULL, x->port, x->txtinfo, x->txt_len, SubTypes, x->NumSubTypes, mDNSInterface_Any, RegCallback, si);
	if (!err)
		{
		si->next = x->regs;
		x->regs = si;
		}
	else
		{
		LogMsg("Error %d for registration of service in domain %##s", err, domain->c);
		freeL("ServiceInstance", si);
		}
	return err;	
	}

mDNSexport void DefaultRegDomainChanged(const domainname *d, mDNSBool add)
	{
	DNSServiceRegistration *reg;

	for (reg = DNSServiceRegistrationList; reg; reg = reg->next)
		{
		if (reg->DefaultDomain)
			{
			if (add)
				{
				AddServiceInstance(reg, d);
				}
			else
				{
				ServiceInstance *si = reg->regs, *prev = NULL;
				while (si)
					{
					if (SameDomainName(&si->domain, d))
						{
						if (prev) prev->next = si->next;
						else reg->regs = si->next;
						if (mDNS_DeregisterService(&mDNSStorage, &si->srs))
							FreeServiceInstance(si);  // only free memory synchronously on error
						break;
						}
					prev = si;
					si = si->next;
					}
				if (!si) debugf("Requested removal of default domain %##s not in client %5d's list", d, reg->ClientMachPort); // normal if registration failed
				}					
			}
		}
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString name, DNSCString regtype, DNSCString domain, IPPort IpPort, DNSCString txtRecord)
	{
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";

	// older versions of this code passed the port via mach IPC as an int.
	// we continue to pass it as 4 bytes to maintain binary compatibility,
	// but now ensure that the network byte order is preserved by using a struct
	mDNSIPPort port;
	port.b[0] = IpPort.bytes[2];
	port.b[1] = IpPort.bytes[3];

	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

    // Check for sub-types after the service type
	size_t reglen = strlen(regtype) + 1;
	if (reglen > MAX_ESCAPED_DOMAIN_NAME) { errormsg = "reglen too long"; goto badparam; }
	mDNSs32 NumSubTypes = ChopSubTypes(regtype);	// Note: Modifies regtype string to remove trailing subtypes
	if (NumSubTypes < 0) { errormsg = "Bad Service SubType"; goto badparam; }

	// Check other parameters
	domainlabel n;
	domainname t, d;
	domainname srv;
	if (!name[0]) n = mDNSStorage.nicelabel;
	else if (!MakeDomainLabelFromLiteralString(&n, name))                  { errormsg = "Bad Instance Name"; goto badparam; }
	if (!regtype[0] || !MakeDomainNameFromDNSNameString(&t, regtype))      { errormsg = "Bad Service Type";  goto badparam; }
	if (!MakeDomainNameFromDNSNameString(&d, *domain ? domain : "local.")) { errormsg = "Bad Domain";        goto badparam; }
	if (!ConstructServiceName(&srv, &n, &t, &d))                           { errormsg = "Bad Name";          goto badparam; }

	unsigned char txtinfo[1024] = "";
	unsigned int data_len = 0;
	unsigned int size = sizeof(RDataBody);
	unsigned char *pstring = &txtinfo[data_len];
	char *ptr = txtRecord;

	// The OS X DNSServiceRegistrationCreate() API is defined using a C-string,
	// but the mDNS_RegisterService() call actually requires a packed block of P-strings.
	// Hence we have to convert the C-string to a P-string.
	// ASCII-1 characters are allowed in the C-string as boundary markers,
	// so that a single C-string can be used to represent one or more P-strings.
	while (*ptr)
		{
		if (++data_len >= sizeof(txtinfo)) { errormsg = "TXT record too long"; goto badtxt; }
		if (*ptr == 1)		// If this is our boundary marker, start a new P-string
			{
			pstring = &txtinfo[data_len];
			pstring[0] = 0;
			ptr++;
			}
		else
			{
			if (pstring[0] == 255) { errormsg = "TXT record invalid (component longer than 255)"; goto badtxt; }
			pstring[++pstring[0]] = *ptr++;
			}
		}

	data_len++;
	if (size < data_len)
		size = data_len;

	// Some clients use mDNS for lightweight copy protection, registering a pseudo-service with
	// a port number of zero. When two instances of the protected client are allowed to run on one
	// machine, we don't want to see misleading "Bogus client" messages in syslog and the console.
	if (port.NotAnInteger)
		{
		int count = CountExistingRegistrations(&srv, port);
		if (count)
			LogMsg("%5d: Client application registered %d identical instances of service %##s port %u.",
				   client, count+1, srv.c, mDNSVal16(port));
		}
	
	// Allocate memory, and handle failure
	DNSServiceRegistration *x = mallocL("DNSServiceRegistration", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }
	bzero(x, sizeof(*x));

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->DefaultDomain = !domain[0];
	x->autoname = (!name[0]);
	x->rdsize = size;
	x->NumSubTypes = NumSubTypes;
	memcpy(x->regtype, regtype, reglen);
	x->name = n;
	x->type = t;
	x->port = port;
	memcpy(x->txtinfo, txtinfo, 1024);
	x->txt_len = data_len;	
	x->NextRef = 0;
	x->regs = NULL;
	
	x->next = DNSServiceRegistrationList;
	DNSServiceRegistrationList = x;

	LogOperation("%5d: DNSServiceRegistration(\"%s\", \"%s\", \"%s\", %u) START",
		x->ClientMachPort, name, regtype, domain, mDNSVal16(port));

   	err = AddServiceInstance(x, &d);
	if (err) { AbortClient(client, x); errormsg = "mDNS_RegisterService"; goto fail; }  // bail if .local (or explicit domain) fails

	if (x->DefaultDomain)
		{
		DNameListElem *ptr, *regdomains = mDNSPlatformGetRegDomainList();
		for (ptr = regdomains; ptr; ptr = ptr->next)
			AddServiceInstance(x, &ptr->name);
		mDNS_FreeDNameList(regdomains);
		}		

	// Succeeded: Wrap up and return
	EnableDeathNotificationForClient(client, x);
	return(mStatus_NoError);

badtxt:
	LogMsg("%5d: TXT record: %.100s...", client, txtRecord);
badparam:
	err = mStatus_BadParamErr;
fail:
	LogMsg("%5d: DNSServiceRegister(\"%s\", \"%s\", \"%s\", %d) failed: %s (%ld)",
		   client, name, regtype, domain, mDNSVal16(port), errormsg, err);
	return(err);
	}

mDNSlocal CFUserNotificationRef gNotification    = NULL;
mDNSlocal CFRunLoopSourceRef    gNotificationRLS = NULL;
mDNSlocal domainlabel           gNotificationPrefHostLabel;	// The prefs as they were the last time we saw them
mDNSlocal domainlabel           gNotificationPrefNiceLabel;
mDNSlocal domainlabel           gNotificationUserHostLabel;	// The prefs as they were the last time the user changed them
mDNSlocal domainlabel           gNotificationUserNiceLabel;

mDNSlocal void NotificationCallBackDismissed(CFUserNotificationRef userNotification, CFOptionFlags responseFlags)
	{
	(void)responseFlags;	// Unused
	if (userNotification != gNotification) LogMsg("NotificationCallBackDismissed: Wrong CFUserNotificationRef");
	if (gNotificationRLS)
		{
		CFRunLoopRemoveSource(CFRunLoopGetCurrent(), gNotificationRLS, kCFRunLoopDefaultMode);
		CFRelease(gNotificationRLS);
		gNotificationRLS = NULL;
		CFRelease(gNotification);
		gNotification = NULL;
		}
	// By dismissing the alert, the user has conceptually acknowleged the rename.
	// (e.g. the machine's name is now officially "computer-2.local", not "computer.local".)
	// If we get *another* conflict, the new alert should refer to the 'old'.
	// name as now being "computer-2.local", not "computer.local"
	gNotificationUserHostLabel = gNotificationPrefHostLabel;
	gNotificationUserNiceLabel = gNotificationPrefNiceLabel;
	}

mDNSlocal void ShowNameConflictNotification(CFStringRef header, CFStringRef subtext)
	{
	CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!dictionary) return;
	CFDictionarySetValue(dictionary, kCFUserNotificationAlertHeaderKey, header);
	CFDictionarySetValue(dictionary, kCFUserNotificationAlertMessageKey, subtext);

	CFURLRef urlRef = CFURLCreateWithFileSystemPath(NULL, CFSTR("/System/Library/CoreServices/mDNSResponder.bundle"), kCFURLPOSIXPathStyle, true);
	if (urlRef) { CFDictionarySetValue(dictionary, kCFUserNotificationLocalizationURLKey, urlRef); CFRelease(urlRef); }

	if (gNotification)	// If notification already on-screen, update it in place
		CFUserNotificationUpdate(gNotification, 0, kCFUserNotificationCautionAlertLevel, dictionary);
	else				// else, we need to create it
		{
		SInt32 error;
		gNotification = CFUserNotificationCreate(NULL, 0, kCFUserNotificationCautionAlertLevel, &error, dictionary);
		if (!gNotification) { LogMsg("ShowNameConflictNotification: CFUserNotificationRef"); return; }
		gNotificationRLS = CFUserNotificationCreateRunLoopSource(NULL, gNotification, NotificationCallBackDismissed, 0);
		if (!gNotificationRLS) { LogMsg("ShowNameConflictNotification: RLS"); CFRelease(gNotification); gNotification = NULL; return; }
		CFRunLoopAddSource(CFRunLoopGetCurrent(), gNotificationRLS, kCFRunLoopDefaultMode);
		}

	CFRelease(dictionary);
	}

// This updates either the text of the field currently labelled "Local Hostname",
// or the text of the field currently labelled "Computer Name"
// in the Sharing Prefs Control Panel
mDNSlocal void RecordUpdatedName(const mDNS *const m, const domainlabel *const olddl, const domainlabel *const newdl,
	const char *const msg, const char *const suffix, const CFStringRef subtext)
	{
	char oldname[MAX_DOMAIN_LABEL+1];
	char newname[MAX_DOMAIN_LABEL+1];
	ConvertDomainLabelToCString_unescaped(olddl, oldname);
	ConvertDomainLabelToCString_unescaped(newdl, newname);
	const CFStringRef      cfoldname = CFStringCreateWithCString(NULL, oldname,  kCFStringEncodingUTF8);
	const CFStringRef      cfnewname = CFStringCreateWithCString(NULL, newname,  kCFStringEncodingUTF8);
	const CFStringRef      f1        = CFStringCreateWithCString(NULL, " “%@%s” ", kCFStringEncodingUTF8);
	const CFStringRef      f2        = CFStringCreateWithCString(NULL, " “%@%s” ", kCFStringEncodingUTF8);
	const SCPreferencesRef session   = SCPreferencesCreate(NULL, CFSTR("mDNSResponder"), NULL);
	if (!cfoldname || !cfnewname || !f1 || !f2 || !session || !SCPreferencesLock(session, 0))	// If we can't get the lock don't wait
		LogMsg("RecordUpdatedName: ERROR: Couldn't create SCPreferences session");
	else
		{
		const CFStringRef       s0           = CFStringCreateWithCString(NULL, msg, kCFStringEncodingUTF8);
		const CFStringRef       s1           = CFStringCreateWithFormat(NULL, NULL, f1, cfoldname, suffix);
		const CFStringRef       s2           = CFStringCreateWithFormat(NULL, NULL, f2, cfnewname, suffix);
		// On Tiger and later, if we pass an array instead of a string, CFUserNotification will translate each
		// element of the array individually for us, and then concatenate the results to make the final message.
		// This lets us have the relevant bits localized, but not the literal names, which should not be translated.
		// On Panther this does not work, so we just build the string directly, and it will not be translated.
		const CFMutableStringRef alertHeader =
			(OSXVers < 8) ? CFStringCreateMutable(NULL, 0) : (CFMutableStringRef)CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
		Boolean result;
		if (newdl == &gNotificationPrefHostLabel) result = SCPreferencesSetLocalHostName(session, cfnewname);
		else result = SCPreferencesSetComputerName(session, cfnewname, kCFStringEncodingUTF8);
		if (!result || !SCPreferencesCommitChanges(session) || !SCPreferencesApplyChanges(session) || !s0 || !s1 || !s2 || !alertHeader)
			LogMsg("RecordUpdatedName: ERROR: Couldn't update SCPreferences");
		else if (m->p->NotifyUser)
			{
			uid_t uid;
			gid_t gid;
			CFStringRef userName = SCDynamicStoreCopyConsoleUser(NULL, &uid, &gid);
			if (userName)
				{
				CFRelease(userName);
				typedef void CFStringAppendFN(CFMutableStringRef theString, CFStringRef appendedString);
				CFStringAppendFN *const append = (OSXVers < 8) ? &CFStringAppend : (CFStringAppendFN*)&CFArrayAppendValue;
				append(alertHeader, s0);
				append(alertHeader, s1);
				append(alertHeader, CFSTR("is already in use on this network."));
				append(alertHeader, CFSTR("  "));
				append(alertHeader, CFSTR("The name has been changed to"));
				append(alertHeader, s2);
				append(alertHeader, CFSTR("automatically."));
				ShowNameConflictNotification(alertHeader, subtext);
				}
			}
		if (s0)          CFRelease(s0);
		if (s1)          CFRelease(s1);
		if (s2)          CFRelease(s2);
		if (alertHeader) CFRelease(alertHeader);
		SCPreferencesUnlock(session);
		}
	if (cfoldname) CFRelease(cfoldname);
	if (cfnewname) CFRelease(cfnewname);
	if (f1)        CFRelease(f1);
	if (f2)        CFRelease(f2);
	if (session)   CFRelease(session);
	}

mDNSlocal void mDNS_StatusCallback(mDNS *const m, mStatus result)
	{
	(void)m; // Unused
	if (result == mStatus_NoError)	
		{
		// One second pause in case we get a Computer Name update too -- don't want to alert the user twice
		RecordUpdatedNiceLabel(m, mDNSPlatformOneSecond);
		}
	else if (result == mStatus_ConfigChanged)
		{
		// If the user-specified hostlabel from System Configuration has changed since the last time
		// we saw it, and *we* didn't change it, then that implies that the user has changed it,
		// so we auto-dismiss the name conflict alert.
		if (!SameDomainLabel(m->p->userhostlabel.c, gNotificationPrefHostLabel.c) ||
			!SameDomainLabel(m->p->usernicelabel.c, gNotificationPrefNiceLabel.c))
			{
			gNotificationUserHostLabel = gNotificationPrefHostLabel = m->p->userhostlabel;
			gNotificationUserNiceLabel = gNotificationPrefNiceLabel = m->p->usernicelabel;
			// If we're showing a name conflict notification, and the user has manually edited
			// the name to remedy the conflict, we should now remove the notification window.
			if (gNotificationRLS) CFUserNotificationCancel(gNotification);
			}

		DNSServiceRegistration *r;
		for (r = DNSServiceRegistrationList; r; r=r->next)
			if (r->autoname)
				{
				ServiceInstance *si;
				for (si = r->regs; si; si = si->next)
					{
					if (!SameDomainLabel(si->name.c, m->nicelabel.c))
						{
						debugf("NetworkChanged renaming %##s to %#s", si->srs.RR_SRV.resrec.name->c, m->nicelabel.c);
						si->autorename = mDNStrue;
						if (mDNS_DeregisterService(m, &si->srs))	// If service deregistered already, we can re-register immediately
							RegCallback(m, &si->srs, mStatus_MemFree);
						}
					}
				}
		udsserver_handle_configchange();
		}
	else if (result == mStatus_GrowCache)
		{
		// Allocate another chunk of cache storage
		CacheEntity *storage = mallocL("mStatus_GrowCache", sizeof(CacheEntity) * RR_CACHE_SIZE);
		if (storage) mDNS_GrowCache(m, storage, RR_CACHE_SIZE);
		}
	}

//*************************************************************************************************************
// Add / Update / Remove records from existing Registration

mDNSexport kern_return_t provide_DNSServiceRegistrationAddRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	int type, const char *data, mach_msg_type_number_t data_len, uint32_t ttl, natural_t *reference)
	{
	// Check client parameter
	uint32_t id;
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	ServiceInstance *si;
	size_t size;
	(void)unusedserver;		// Unused
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }

	// Check other parameters
	if (data_len > 8192) { err = mStatus_BadParamErr; errormsg = "data_len > 8K"; goto fail; }
	if (data_len > sizeof(RDataBody)) size = data_len;
	else size = sizeof(RDataBody);
	
	id = x->NextRef++;
	*reference = (natural_t)id;
	for (si = x->regs; si; si = si->next)
		{			
		// Allocate memory, and handle failure
		ExtraResourceRecord *extra = mallocL("ExtraResourceRecord", sizeof(*extra) - sizeof(RDataBody) + size);
		if (!extra) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }
		
		// Fill in type, length, and data of new record
		extra->r.resrec.rrtype = type;
		extra->r.rdatastorage.MaxRDLength = size;
		extra->r.resrec.rdlength          = data_len;
		memcpy(&extra->r.rdatastorage.u.data, data, data_len);

		// Do the operation
		LogOperation("%5d: DNSServiceRegistrationAddRecord(%##s, type %d, length %d) REF %p",
					 client, si->srs.RR_SRV.resrec.name->c, type, data_len, extra);
		err = mDNS_AddRecordToService(&mDNSStorage, &si->srs, extra, &extra->r.rdatastorage, ttl);

		if (err)
			{
			freeL("Extra Resource Record", extra);
			errormsg = "mDNS_AddRecordToService";
			goto fail;
			}

		extra->ClientID = id;
		}

	return mStatus_NoError;

fail:
	LogMsg("%5d: DNSServiceRegistrationAddRecord(%##s, type %d, length %d) failed: %s (%ld)", client, x->name.c, type, data_len, errormsg, err);
	return mStatus_UnknownErr;
	}

mDNSlocal void UpdateCallback(mDNS *const m, AuthRecord *const rr, RData *OldRData)
	{
	(void)m;		// Unused
	if (OldRData != &rr->rdatastorage)
		freeL("Old RData", OldRData);
	}

mDNSlocal mStatus UpdateRecord(ServiceRecordSet *srs, mach_port_t client, AuthRecord *rr, const char *data, mach_msg_type_number_t data_len, uint32_t ttl)
	{
    // Check client parameter
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	domainname *name = (domainname *)"";

	name = srs->RR_SRV.resrec.name;

	unsigned int size = sizeof(RDataBody);
    if (size < data_len)
		size = data_len;

	// Allocate memory, and handle failure
	RData *newrdata = mallocL("RData", sizeof(*newrdata) - sizeof(RDataBody) + size);
	if (!newrdata) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Fill in new length, and data
	newrdata->MaxRDLength = size;
	memcpy(&newrdata->u, data, data_len);
	
	// BIND named (name daemon) doesn't allow TXT records with zero-length rdata. This is strictly speaking correct,
	// since RFC 1035 specifies a TXT record as "One or more <character-string>s", not "Zero or more <character-string>s".
	// Since some legacy apps try to create zero-length TXT records, we'll silently correct it here.
	if (rr->resrec.rrtype == kDNSType_TXT && data_len == 0) { data_len = 1; newrdata->u.txt.c[0] = 0; }

	// Do the operation
	LogOperation("%5d: DNSServiceRegistrationUpdateRecord(%##s, new length %d)",
		client, srs->RR_SRV.resrec.name->c, data_len);

	err = mDNS_Update(&mDNSStorage, rr, ttl, data_len, newrdata, UpdateCallback);
	if (err)
		{
		errormsg = "mDNS_Update";
		freeL("RData", newrdata);
		return err;
		}
	return(mStatus_NoError);

fail:
	LogMsg("%5d: DNSServiceRegistrationUpdateRecord(%##s, %d) failed: %s (%ld)", client, name->c, data_len, errormsg, err);
	return(err);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationUpdateRecord_rpc(mach_port_t unusedserver, mach_port_t client,
		natural_t reference, const char *data, mach_msg_type_number_t data_len, uint32_t ttl)
   	{
    // Check client parameter
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	domainname *name = (domainname *)"";
	ServiceInstance *si;

	(void)unusedserver; // unused
    if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }

	// Check other parameters
	if (data_len > 8192) { err = mStatus_BadParamErr; errormsg = "data_len > 8K"; goto fail; }

	for (si = x->regs; si; si = si->next)
		{
		AuthRecord *r = NULL;

		// Find the record we're updating. NULL reference means update the primary TXT record
		if (!reference) r = &si->srs.RR_TXT;
		else
			{
			ExtraResourceRecord *ptr;
			for (ptr = si->srs.Extras; ptr; ptr = ptr->next)
				{
				if ((natural_t)ptr->ClientID == reference)
					{ r = &ptr->r; break; }
				}
			if (!r) { err = mStatus_BadReferenceErr; errormsg = "No such record"; goto fail; }
			}
		err = UpdateRecord(&si->srs, client, r, data, data_len, ttl);
		if (err) goto fail;  //!!!KRS this will cause failures for non-local defaults!
		}
					
	return mStatus_NoError;

fail:
	LogMsg("%5d: DNSServiceRegistrationUpdateRecord(%##s, %X, %d) failed: %s (%ld)", client, name->c, reference, data_len, errormsg, err);
	return(err);
	}

mDNSlocal mStatus RemoveRecord(ServiceRecordSet *srs, ExtraResourceRecord *extra, mach_port_t client)
	{
	domainname *name = srs->RR_SRV.resrec.name;
	mStatus err = mStatus_NoError;

	// Do the operation
	LogOperation("%5d: DNSServiceRegistrationRemoveRecord(%##s)", client, srs->RR_SRV.resrec.name->c);

	err = mDNS_RemoveRecordFromService(&mDNSStorage, srs, extra, FreeExtraRR, extra);
	if (err) LogMsg("%5d: DNSServiceRegistrationRemoveRecord (%##s) failed: %d", client, name->c, err);
	
	return err;
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationRemoveRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	natural_t reference)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	ServiceInstance *si;

	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }

	for (si = x->regs; si; si = si->next)
		{
		ExtraResourceRecord *e;
		for (e = si->srs.Extras; e; e = e->next)
			{
			if ((natural_t)e->ClientID == reference)
				{
				err = RemoveRecord(&si->srs, e, client);
				break;
				}
			}
		if (!e) { err = mStatus_BadReferenceErr; errormsg = "No such reference"; goto fail; }
		}

	return mStatus_NoError;

fail:
	LogMsg("%5d: DNSServiceRegistrationRemoveRecord(%X) failed: %s (%ld)", client, reference, errormsg, err);
	return(err);
	}

//*************************************************************************************************************
// Support Code

mDNSlocal void DNSserverCallback(CFMachPortRef port, void *msg, CFIndex size, void *info)
	{
	mig_reply_error_t *request = msg;
	mig_reply_error_t *reply;
	mach_msg_return_t mr;
	int               options;
	(void)port;		// Unused
	(void)size;		// Unused
	(void)info;		// Unused

	/* allocate a reply buffer */
	reply = CFAllocatorAllocate(NULL, provide_DNSServiceDiscoveryRequest_subsystem.maxsize, 0);

	/* call the MiG server routine */
	(void) DNSServiceDiscoveryRequest_server(&request->Head, &reply->Head);

	if (!(reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) && (reply->RetCode != KERN_SUCCESS))
		{
        if (reply->RetCode == MIG_NO_REPLY)
			{
            /*
             * This return code is a little tricky -- it appears that the
             * demux routine found an error of some sort, but since that
             * error would not normally get returned either to the local
             * user or the remote one, we pretend it's ok.
             */
            CFAllocatorDeallocate(NULL, reply);
            return;
			}

        /*
         * destroy any out-of-line data in the request buffer but don't destroy
         * the reply port right (since we need that to send an error message).
         */
        request->Head.msgh_remote_port = MACH_PORT_NULL;
        mach_msg_destroy(&request->Head);
		}

    if (reply->Head.msgh_remote_port == MACH_PORT_NULL)
		{
        /* no reply port, so destroy the reply */
        if (reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)
            mach_msg_destroy(&reply->Head);
        CFAllocatorDeallocate(NULL, reply);
        return;
		}

    /*
     * send reply.
     *
     * We don't want to block indefinitely because the client
     * isn't receiving messages from the reply port.
     * If we have a send-once right for the reply port, then
     * this isn't a concern because the send won't block.
     * If we have a send right, we need to use MACH_SEND_TIMEOUT.
     * To avoid falling off the kernel's fast RPC path unnecessarily,
     * we only supply MACH_SEND_TIMEOUT when absolutely necessary.
     */

    options = MACH_SEND_MSG;
    if (MACH_MSGH_BITS_REMOTE(reply->Head.msgh_bits) == MACH_MSG_TYPE_MOVE_SEND_ONCE)
        options |= MACH_SEND_TIMEOUT;

    mr = mach_msg(&reply->Head,		/* msg */
		      options,			/* option */
		      reply->Head.msgh_size,	/* send_size */
		      0,			/* rcv_size */
		      MACH_PORT_NULL,		/* rcv_name */
		      MACH_MSG_TIMEOUT_NONE,	/* timeout */
		      MACH_PORT_NULL);		/* notify */

    /* Has a message error occurred? */
    switch (mr)
		{
        case MACH_SEND_INVALID_DEST:
        case MACH_SEND_TIMED_OUT:
            /* the reply can't be delivered, so destroy it */
            mach_msg_destroy(&reply->Head);
            break;

        default :
            /* Includes success case. */
            break;
		}

    CFAllocatorDeallocate(NULL, reply);
	}

mDNSlocal kern_return_t registerBootstrapService()
	{
	kern_return_t status;
	mach_port_t service_send_port, service_rcv_port;

	debugf("Registering Bootstrap Service");

	/*
	 * See if our service name is already registered and if we have privilege to check in.
	 */
	status = bootstrap_check_in(bootstrap_port, (char*)kmDNSBootstrapName, &service_rcv_port);
	if (status == KERN_SUCCESS)
		{
		/*
		 * If so, we must be a followup instance of an already defined server.  In that case,
		 * the bootstrap port we inherited from our parent is the server's privilege port, so set
		 * that in case we have to unregister later (which requires the privilege port).
		 */
		server_priv_port = bootstrap_port;
		restarting_via_mach_init = TRUE;
		}
	else if (status == BOOTSTRAP_UNKNOWN_SERVICE)
		{
		status = bootstrap_create_server(bootstrap_port, "/usr/sbin/mDNSResponder", getuid(),
			FALSE /* relaunch immediately, not on demand */, &server_priv_port);
		if (status != KERN_SUCCESS) return status;

		status = bootstrap_create_service(server_priv_port, (char*)kmDNSBootstrapName, &service_send_port);
		if (status != KERN_SUCCESS)
			{
			mach_port_deallocate(mach_task_self(), server_priv_port);
			return status;
			}

		status = bootstrap_check_in(server_priv_port, (char*)kmDNSBootstrapName, &service_rcv_port);
		if (status != KERN_SUCCESS)
			{
			mach_port_deallocate(mach_task_self(), server_priv_port);
			mach_port_deallocate(mach_task_self(), service_send_port);
			return status;
			}
		assert(service_send_port == service_rcv_port);
		}

	/*
	 * We have no intention of responding to requests on the service port.  We are not otherwise
	 * a Mach port-based service.  We are just using this mechanism for relaunch facilities.
	 * So, we can dispose of all the rights we have for the service port.  We don't destroy the
	 * send right for the server's privileged bootstrap port - in case we have to unregister later.
	 */
	mach_port_destroy(mach_task_self(), service_rcv_port);
	return status;
	}

mDNSlocal kern_return_t destroyBootstrapService()
	{
	debugf("Destroying Bootstrap Service");
	return bootstrap_register(server_priv_port, (char*)kmDNSBootstrapName, MACH_PORT_NULL);
	}

mDNSlocal void ExitCallback(int signal)
	{
	LogMsgIdent(mDNSResponderVersionString, "stopping");

	debugf("ExitCallback");
	if (!mDNS_DebugMode && !started_via_launchdaemon && signal != SIGHUP)
		destroyBootstrapService();

	debugf("ExitCallback: Aborting MIG clients");
	while (DNSServiceDomainEnumerationList)
		AbortClient(DNSServiceDomainEnumerationList->ClientMachPort, DNSServiceDomainEnumerationList);
	while (DNSServiceBrowserList)
		AbortClient(DNSServiceBrowserList          ->ClientMachPort, DNSServiceBrowserList);
	while (DNSServiceResolverList)
		AbortClient(DNSServiceResolverList         ->ClientMachPort, DNSServiceResolverList);
	while (DNSServiceRegistrationList)
		AbortClient(DNSServiceRegistrationList     ->ClientMachPort, DNSServiceRegistrationList);

	debugf("ExitCallback: mDNS_Close");
	mDNS_Close(&mDNSStorage);
	if (udsserver_exit() < 0) LogMsg("ExitCallback: udsserver_exit failed");
	exit(0);
	}

// Send a mach_msg to ourselves (since that is signal safe) telling us to cleanup and exit
mDNSlocal void HandleSIG(int signal)
	{
	debugf(" ");
	debugf("HandleSIG %d", signal);
	mach_msg_header_t header;
	header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	header.msgh_remote_port = signal_port;
	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_size = sizeof(header);
	header.msgh_id = signal;
	if (mach_msg_send(&header) != MACH_MSG_SUCCESS)
		{
		LogMsg("HandleSIG %d: mach_msg_send failed", signal);
		if (signal == SIGHUP || signal == SIGTERM || signal == SIGINT) exit(-1);
		}
	}

mDNSlocal void INFOCallback(void)
	{
	mDNSs32 utc = mDNSPlatformUTC();
	DNSServiceDomainEnumeration *e;
	DNSServiceBrowser           *b;
	DNSServiceResolver          *l;
	DNSServiceRegistration      *r;
	NetworkInterfaceInfoOSX     *i;

	LogMsgIdent(mDNSResponderVersionString, "---- BEGIN STATE LOG ----");
	
	udsserver_info(&mDNSStorage);

	for (e = DNSServiceDomainEnumerationList; e; e=e->next)
		LogMsgNoIdent("%5d: Mach DomainEnumeration   %##s", e->ClientMachPort, e->dom.qname.c);

	for (b = DNSServiceBrowserList; b; b=b->next)
		{
		DNSServiceBrowserQuestion *qptr;
		for (qptr = b->qlist; qptr; qptr = qptr->next)
			LogMsgNoIdent("%5d: Mach ServiceBrowse       %##s", b->ClientMachPort, qptr->q.qname.c);
		}
	for (l = DNSServiceResolverList; l; l=l->next)
		LogMsgNoIdent("%5d: Mach ServiceResolve      %##s", l->ClientMachPort, l->i.name.c);

	for (r = DNSServiceRegistrationList; r; r=r->next)
		{
		ServiceInstance *si;
		for (si = r->regs; si; si = si->next)
			LogMsgNoIdent("%5d: Mach ServiceInstance     %##s %u", si->ClientMachPort, si->srs.RR_SRV.resrec.name->c, mDNSVal16(si->srs.RR_SRV.resrec.rdata->u.srv.port));
		}

	for (i = mDNSStorage.p->InterfaceList; i; i = i->next)
		{
		if (!i->Exists)
			LogMsgNoIdent("Interface: %s %5s(%lu) %.6a DORMANT %d",
				i->sa_family == AF_INET ? "v4" : i->sa_family == AF_INET6 ? "v6" : "??", i->ifa_name, i->scope_id, &i->BSSID, utc - i->LastSeen);
		else
			LogMsgNoIdent("Interface: %s %5s(%lu) %.6a %s %s %2d %s %2d InterfaceID %p %s %s %#a",
				i->sa_family == AF_INET ? "v4" : i->sa_family == AF_INET6 ? "v6" : "??", i->ifa_name, i->scope_id, &i->BSSID,
				i->ifinfo.InterfaceActive ? "Active" : "      ",
				i->ifinfo.IPv4Available ? "v4" : "  ", i->ss.sktv4,
				i->ifinfo.IPv6Available ? "v6" : "  ", i->ss.sktv6,
				i->ifinfo.InterfaceID,
				i->ifinfo.Advertise ? "Adv"  : "   ",
				i->ifinfo.McastTxRx ? "TxRx" : "    ",
				&i->ifinfo.ip);
		}

	LogMsgIdent(mDNSResponderVersionString, "----  END STATE LOG  ----");
	}

mDNSlocal void SignalCallback(CFMachPortRef port, void *msg, CFIndex size, void *info)
	{
	(void)port;		// Unused
	(void)size;		// Unused
	(void)info;		// Unused
	mach_msg_header_t *m = (mach_msg_header_t *)msg;
	switch(m->msgh_id)
		{
		case SIGHUP:  
		case SIGINT:  
		case SIGTERM:	ExitCallback(m->msgh_id); break;
		case SIGINFO:	INFOCallback(); break;
		case SIGUSR1:	LogMsg("SIGUSR1: Simulate Network Configuration Change Event");
						mDNSMacOSXNetworkChanged(&mDNSStorage); break;
		default: LogMsg("SignalCallback: Unknown signal %d", m->msgh_id); break;
		}
	}

// On 10.2 the MachServerName is DNSServiceDiscoveryServer
// On 10.3 and later, the MachServerName is com.apple.mDNSResponder

mDNSlocal kern_return_t mDNSDaemonInitialize(void)
	{
	mStatus            err;
	CFMachPortRef      d_port = CFMachPortCreate(NULL, ClientDeathCallback, NULL, NULL);
	CFMachPortRef      s_port = CFMachPortCreate(NULL, DNSserverCallback, NULL, NULL);
	CFMachPortRef      i_port = CFMachPortCreate(NULL, SignalCallback, NULL, NULL);
	mach_port_t        m_port = CFMachPortGetPort(s_port);
	char *MachServerName = OSXVers < 7 ? "DNSServiceDiscoveryServer" : "com.apple.mDNSResponder";
	kern_return_t      status = bootstrap_register(bootstrap_port, MachServerName, m_port);
	CFRunLoopSourceRef d_rls  = CFMachPortCreateRunLoopSource(NULL, d_port, 0);
	CFRunLoopSourceRef s_rls  = CFMachPortCreateRunLoopSource(NULL, s_port, 0);
	CFRunLoopSourceRef i_rls  = CFMachPortCreateRunLoopSource(NULL, i_port, 0);

	if (status)
		{
		if (status == 1103)
			LogMsg("Bootstrap_register failed(): A copy of the daemon is apparently already running");
		else
			LogMsg("Bootstrap_register failed(): %s %d", mach_error_string(status), status);
		return(status);
		}

	err = mDNS_Init(&mDNSStorage, &PlatformStorage,
		rrcachestorage, RR_CACHE_SIZE,
		mDNS_Init_AdvertiseLocalAddresses,
		mDNS_StatusCallback, mDNS_Init_NoInitCallbackContext);

	if (err) { LogMsg("Daemon start: mDNS_Init failed %ld", err); return(err); }

	gNotificationUserHostLabel = gNotificationPrefHostLabel = PlatformStorage.userhostlabel;
	gNotificationUserNiceLabel = gNotificationPrefNiceLabel = PlatformStorage.usernicelabel;

	client_death_port = CFMachPortGetPort(d_port);
	signal_port = CFMachPortGetPort(i_port);

	CFRunLoopAddSource(CFRunLoopGetCurrent(), d_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), s_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), i_rls, kCFRunLoopDefaultMode);
	CFRelease(d_rls);
	CFRelease(s_rls);
	CFRelease(i_rls);
	if (mDNS_DebugMode) printf("Service registered with Mach Port %d\n", m_port);
	return(err);
	}

mDNSlocal mDNSs32 mDNSDaemonIdle(mDNS *const m)
	{
	mDNSs32 now = mDNS_TimeNow(m);

	// 1. If we have network change events to handle, do them FIRST, before calling mDNS_Execute()
	// Detailed reason:
	// mDNSMacOSXNetworkChanged() currently closes and re-opens its sockets. If there are received packets waiting, they are lost.
	// mDNS_Execute() generates packets, including multicasts that are looped back to ourself.
	// If we call mDNS_Execute() first, and generate packets, and then call mDNSMacOSXNetworkChanged() immediately afterwards
	// we then systematically lose our own looped-back packets.
	if (m->p->NetworkChanged && now - m->p->NetworkChanged >= 0) mDNSMacOSXNetworkChanged(m);

	// 2. Call mDNS_Execute() to let mDNSCore do what it needs to do
	mDNSs32 nextevent = mDNS_Execute(m);

	if (m->p->NetworkChanged)
		if (nextevent - m->p->NetworkChanged > 0)
			nextevent = m->p->NetworkChanged;

	// 3. Deliver any waiting browse messages to clients
	DNSServiceBrowser *b = DNSServiceBrowserList;

	while (b)
		{
		// NOTE: Need to advance b to the next element BEFORE we call DeliverInstance(), because in the
		// event that the client Mach queue overflows, DeliverInstance() will call AbortBlockedClient()
		// and that will cause the DNSServiceBrowser object's memory to be freed before it returns
		DNSServiceBrowser *x = b;
		b = b->next;
		if (x->results)			// Try to deliver the list of results
			{
			while (x->results)
				{
				DNSServiceBrowserResult *const r = x->results;
				domainlabel name;
				domainname type, domain;
				DeconstructServiceName(&r->result, &name, &type, &domain);	// Don't need to check result; already validated in FoundInstance()
				char cname[MAX_DOMAIN_LABEL+1];			// Unescaped name: up to 63 bytes plus C-string terminating NULL.
				char ctype[MAX_ESCAPED_DOMAIN_NAME];
				char cdom [MAX_ESCAPED_DOMAIN_NAME];
				ConvertDomainLabelToCString_unescaped(&name, cname);
				ConvertDomainNameToCString(&type, ctype);
				ConvertDomainNameToCString(&domain, cdom);
				DNSServiceDiscoveryReplyFlags flags = (r->next) ? DNSServiceDiscoverReplyFlagsMoreComing : 0;
				kern_return_t status = DNSServiceBrowserReply_rpc(x->ClientMachPort, r->resultType, cname, ctype, cdom, flags, 1);
				// If we failed to send the mach message, try again in one second
				if (status == MACH_SEND_TIMED_OUT)
					{
					if (nextevent - now > mDNSPlatformOneSecond)
						nextevent = now + mDNSPlatformOneSecond;
					break;
					}
				else
					{
					x->lastsuccess = now;
					x->results = x->results->next;
					freeL("DNSServiceBrowserResult", r);
					}
				}
			// If this client hasn't read a single message in the last 60 seconds, abort it
			if (now - x->lastsuccess >= 60 * mDNSPlatformOneSecond)
				AbortBlockedClient(x->ClientMachPort, "browse", x);
			}
		}

	DNSServiceResolver *l;
	for (l = DNSServiceResolverList; l; l=l->next)
		if (l->ReportTime && now - l->ReportTime >= 0)
			{
			l->ReportTime = 0;
			LogMsgNoIdent("Client application bug: DNSServiceResolver(%##s) active for over two minutes. "
				"This places considerable burden on the network.", l->i.name.c);
			}

	if (m->p->NotifyUser)
		{
		if (m->p->NotifyUser - now < 0)
			{
			if (!SameDomainLabel(m->p->usernicelabel.c, m->nicelabel.c))
				{
				LogMsg("Updating Computer Name from \"%#s\" to \"%#s\"", m->p->usernicelabel.c, m->nicelabel.c);
				gNotificationPrefNiceLabel = m->p->usernicelabel = m->nicelabel;
				RecordUpdatedName(m, &gNotificationUserNiceLabel, &gNotificationPrefNiceLabel, "The name of your computer", "",
					CFSTR("To change the name of your computer, open System Preferences and click Sharing.  "
							"Then type the name in the Computer Name field."));
				// Clear m->p->NotifyUser here -- even if the hostlabel has changed too, we don't want to bug the user with *two* alerts
				m->p->NotifyUser = 0;
				}
			if (!SameDomainLabel(m->p->userhostlabel.c, m->hostlabel.c))
				{
				LogMsg("Updating Local Hostname from \"%#s.local\" to \"%#s.local\"", m->p->userhostlabel.c, m->hostlabel.c);
				gNotificationPrefHostLabel = m->p->userhostlabel = m->hostlabel;
				RecordUpdatedName(m, &gNotificationUserHostLabel, &gNotificationPrefHostLabel, "This computer’s local hostname", ".local",
					CFSTR("To change the local hostname, open System Preferences and click Sharing.  "
							"Then click Edit and type the name in the Local Hostname field."));
				}
			m->p->NotifyUser = 0;
			}
		else
			if (nextevent - m->p->NotifyUser > 0)
				nextevent = m->p->NotifyUser;
		}

	return(nextevent);
	}

mDNSlocal void ShowTaskSchedulingError(mDNS *const m)
	{
	mDNS_Lock(m);

	LogMsg("Task Scheduling Error: Continuously busy for more than a second");
	
	if (m->NewQuestions && (!m->NewQuestions->DelayAnswering || m->timenow - m->NewQuestions->DelayAnswering >= 0))
		LogMsg("Task Scheduling Error: NewQuestion %##s (%s)",
			m->NewQuestions->qname.c, DNSTypeName(m->NewQuestions->qtype));
	if (m->NewLocalOnlyQuestions)
		LogMsg("Task Scheduling Error: NewLocalOnlyQuestions %##s (%s)",
			m->NewLocalOnlyQuestions->qname.c, DNSTypeName(m->NewLocalOnlyQuestions->qtype));
	if (m->NewLocalRecords && LocalRecordReady(m->NewLocalRecords))
		LogMsg("Task Scheduling Error: NewLocalRecords %s", ARDisplayString(m, m->NewLocalRecords));
	if (m->SuppressSending && m->timenow - m->SuppressSending >= 0)
		LogMsg("Task Scheduling Error: m->SuppressSending %d",       m->timenow - m->SuppressSending);
#ifndef UNICAST_DISABLED
	if (m->timenow - m->uDNS_info.nextevent   >= 0)
		LogMsg("Task Scheduling Error: m->uDNS_info.nextevent %d",   m->timenow - m->uDNS_info.nextevent);
#endif
	if (m->timenow - m->NextCacheCheck        >= 0)
		LogMsg("Task Scheduling Error: m->NextCacheCheck %d",        m->timenow - m->NextCacheCheck);
	if (m->timenow - m->NextScheduledQuery    >= 0)
		LogMsg("Task Scheduling Error: m->NextScheduledQuery %d",    m->timenow - m->NextScheduledQuery);
	if (m->timenow - m->NextScheduledProbe    >= 0)
		LogMsg("Task Scheduling Error: m->NextScheduledProbe %d",    m->timenow - m->NextScheduledProbe);
	if (m->timenow - m->NextScheduledResponse >= 0)
		LogMsg("Task Scheduling Error: m->NextScheduledResponse %d", m->timenow - m->NextScheduledResponse);

	mDNS_Unlock(&mDNSStorage);
	}

mDNSexport int main(int argc, char **argv)
	{
	int i;
	kern_return_t status;

	for (i=1; i<argc; i++)
		{
		if (!strcmp(argv[i], "-d")) mDNS_DebugMode = mDNStrue;
		if (!strcmp(argv[i], "-launchdaemon")) started_via_launchdaemon = mDNStrue;
		}

	signal(SIGHUP,  HandleSIG);		// (Debugging) Exit cleanly and let mach_init restart us (for debugging)
	signal(SIGINT,  HandleSIG);		// Ctrl-C: Detach from Mach BootstrapService and exit cleanly
	signal(SIGPIPE, SIG_IGN  );		// Don't want SIGPIPE signals -- we'll handle EPIPE errors directly
	signal(SIGTERM, HandleSIG);		// Machine shutting down: Detach from and exit cleanly like Ctrl-C
	signal(SIGINFO, HandleSIG);		// (Debugging) Write state snapshot to syslog
	signal(SIGUSR1, HandleSIG);		// (Debugging) Simulate network change notification from System Configuration Framework

	// Register the server with mach_init for automatic restart only during normal (non-debug) mode
    if (!mDNS_DebugMode && !started_via_launchdaemon)
    	{
    	registerBootstrapService();
    	if (!restarting_via_mach_init) exit(0); // mach_init will restart us immediately as a daemon
		int fd = open(_PATH_DEVNULL, O_RDWR, 0);
		if (fd < 0) LogMsg("open(_PATH_DEVNULL, O_RDWR, 0) failed errno %d (%s)", errno, strerror(errno));
		else
			{
			// Avoid unnecessarily duplicating a file descriptor to itself
			if (fd != STDIN_FILENO)  if (dup2(fd, STDIN_FILENO)  < 0) LogMsg("dup2(fd, STDIN_FILENO)  failed errno %d (%s)", errno, strerror(errno));
			if (fd != STDOUT_FILENO) if (dup2(fd, STDOUT_FILENO) < 0) LogMsg("dup2(fd, STDOUT_FILENO) failed errno %d (%s)", errno, strerror(errno));
			if (fd != STDERR_FILENO) if (dup2(fd, STDERR_FILENO) < 0) LogMsg("dup2(fd, STDERR_FILENO) failed errno %d (%s)", errno, strerror(errno));
			if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO) (void)close(fd);
			}
		}

	// Make our PID file and Unix Domain Socket first, because launchd waits for those before it starts launching other daemons.
	// The sooner we do this, the faster the machine will boot.
	status = udsserver_init();
	if (status) { LogMsg("Daemon start: udsserver_init failed"); goto exit; }
	
	// First do the all the initialization we need root privilege for, before we change to user "nobody"
	LogMsgIdent(mDNSResponderVersionString, "starting");
	OSXVers = mDNSMacOSXSystemBuildNumber(NULL);
	status = mDNSDaemonInitialize();

#if CAN_UPDATE_DYNAMIC_STORE_WITHOUT_BEING_ROOT
	// Now that we're finished with anything privileged, switch over to running as "nobody"
	const struct passwd *pw = getpwnam("nobody");
	if (pw != NULL)
		setuid(pw->pw_uid);
	else
		setuid(-2);		// User "nobody" is -2; use that value if "nobody" does not appear in the password database
#endif

	if (status == 0)
		{
		LogOperation("Starting time value 0x%08lX (%ld)", (mDNSu32)mDNSStorage.timenow_last, mDNSStorage.timenow_last);
		int numevents = 0;
		int RunLoopStatus = kCFRunLoopRunTimedOut;

		// This is the main work loop:
		// (1) First we give mDNSCore a chance to finish off any of its deferred work and calculate the next sleep time
		// (2) Then we make sure we've delivered all waiting browse messages to our clients
		// (3) Then we sleep for the time requested by mDNSCore, or until the next event, whichever is sooner
		// (4) On wakeup we first process *all* events
		// (5) then when no more events remain, we go back to (1) to finish off any deferred work and do it all again
		while (RunLoopStatus == kCFRunLoopRunTimedOut)
			{
			// 1. Before going into a blocking wait call and letting our process to go sleep,
			// call mDNSDaemonIdle to allow any deferred work to be completed.
			mDNSs32 nextevent = mDNSDaemonIdle(&mDNSStorage);
			nextevent = udsserver_idle(nextevent);

			// 2. Work out how long we expect to sleep before the next scheduled task
			mDNSs32 ticks = nextevent - mDNS_TimeNow(&mDNSStorage);
			static mDNSs32 RepeatedBusy = 0;	// Debugging sanity check, to guard against CPU spins
			if (ticks > 1)
				RepeatedBusy = 0;
			else
				{
				ticks = 1;
				if (++RepeatedBusy >= mDNSPlatformOneSecond) { ShowTaskSchedulingError(&mDNSStorage); RepeatedBusy = 0; }
				}
			CFAbsoluteTime interval = (CFAbsoluteTime)ticks / (CFAbsoluteTime)mDNSPlatformOneSecond;

			// 3. Now do a blocking "CFRunLoopRunInMode" call so we sleep until
			// (a) our next wakeup time, or (b) an event occurs.
			// The 'true' parameter makes it return after handling any event that occurs
			// This gives us chance to regain control so we can call mDNS_Execute() before sleeping again
			verbosedebugf("main: Handled %d events; now sleeping for %d ticks", numevents, ticks);
			numevents = 0;
			RunLoopStatus = CFRunLoopRunInMode(kCFRunLoopDefaultMode, interval, true);

			// 4. Time to do some work? Handle all remaining events as quickly as we can, before returning to mDNSDaemonIdle()
			while (RunLoopStatus == kCFRunLoopRunHandledSource)
				{
				numevents++;
				RunLoopStatus = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, true);
				}
			}

		LogMsg("ERROR: CFRunLoopRun Exiting.");
		mDNS_Close(&mDNSStorage);
		}

	LogMsgIdent(mDNSResponderVersionString, "exiting");

exit:
	if (!mDNS_DebugMode && !started_via_launchdaemon) destroyBootstrapService();
	return(status);
	}

//		uds_daemon.c support routines		/////////////////////////////////////////////

// We keep a list of client-supplied event sources in PosixEventSource records
struct CFSocketEventSource
	{
	udsEventCallback			Callback;
	void						*Context;
	int							fd;
	struct  CFSocketEventSource	*Next;
	CFSocketRef					cfs;
	CFRunLoopSourceRef			RLS;
	};
typedef struct CFSocketEventSource	CFSocketEventSource;

static GenLinkedList	gEventSources;			// linked list of CFSocketEventSource's

mDNSlocal void cf_callback(CFSocketRef s, CFSocketCallBackType t, CFDataRef dr, const void *c, void *i)
	// Called by CFSocket when data appears on socket
	{
	(void)s; // Unused
	(void)t; // Unused
	(void)dr; // Unused
	(void)c; // Unused
	CFSocketEventSource	*source = (CFSocketEventSource*) i;
	source->Callback(source->Context);
	}

mStatus udsSupportAddFDToEventLoop(int fd, udsEventCallback callback, void *context)
	// Arrange things so that callback is called with context when data appears on fd
	{
	CFSocketEventSource	*newSource;
	CFSocketContext cfContext = 	{ 0, NULL, NULL, NULL, NULL 	};

	if (gEventSources.LinkOffset == 0)
		InitLinkedList(&gEventSources, offsetof(CFSocketEventSource, Next));

	if (fd >= FD_SETSIZE || fd < 0)
		return mStatus_UnsupportedErr;
	if (callback == NULL)
		return mStatus_BadParamErr;

	newSource = (CFSocketEventSource*) calloc(1, sizeof *newSource);
	if (NULL == newSource)
		return mStatus_NoMemoryErr;

	newSource->Callback = callback;
	newSource->Context = context;
	newSource->fd = fd;

	cfContext.info = newSource;
	if ( NULL != (newSource->cfs = CFSocketCreateWithNative(kCFAllocatorDefault, fd, kCFSocketReadCallBack,
																	cf_callback, &cfContext)) &&
		 NULL != (newSource->RLS = CFSocketCreateRunLoopSource(kCFAllocatorDefault, newSource->cfs, 0)))
		{
		CFRunLoopAddSource(CFRunLoopGetCurrent(), newSource->RLS, kCFRunLoopDefaultMode);
		AddToTail(&gEventSources, newSource);
		}
	else
		{
		if (newSource->cfs)
			{
			CFSocketInvalidate(newSource->cfs);		// Note: Also closes the underlying socket
			CFRelease(newSource->cfs);
			}
		return mStatus_NoMemoryErr;
		}

	return mStatus_NoError;
	}

mStatus udsSupportRemoveFDFromEventLoop(int fd)		// Note: This also CLOSES the file descriptor
	// Reverse what was done in udsSupportAddFDToEventLoop().
	{
	CFSocketEventSource	*iSource;

	for (iSource=(CFSocketEventSource*)gEventSources.Head; iSource; iSource = iSource->Next)
		{
		if (fd == iSource->fd)
			{
			RemoveFromList(&gEventSources, iSource);
			CFRunLoopRemoveSource(CFRunLoopGetCurrent(), iSource->RLS, kCFRunLoopDefaultMode);
			CFRunLoopSourceInvalidate(iSource->RLS);
			CFRelease(iSource->RLS);
			CFSocketInvalidate(iSource->cfs);		// Note: Also closes the underlying socket
			CFRelease(iSource->cfs);
			free(iSource);
			return mStatus_NoError;
			}
		}
	return mStatus_NoSuchNameErr;
	}

// If mDNSResponder crashes, then this string will be magically included in the automatically-generated crash log
const char *__crashreporter_info__ = mDNSResponderVersionString;
asm(".desc ___crashreporter_info__, 0x10");

// For convenience when using the "strings" command, this is the last thing in the file
mDNSexport const char mDNSResponderVersionString[] = STRINGIFY(mDNSResponderVersion) " (" __DATE__ " " __TIME__ ")";
