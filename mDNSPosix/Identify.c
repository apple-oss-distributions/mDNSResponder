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

$Log: Identify.c,v $
Revision 1.34  2004/12/16 20:17:11  cheshire
<rdar://problem/3324626> Cache memory management improvements

Revision 1.33  2004/11/30 22:37:00  cheshire
Update copyright dates and add "Mode: C; tab-width: 4" headers

Revision 1.32  2004/10/19 21:33:21  cheshire
<rdar://problem/3844991> Cannot resolve non-local registrations using the mach API
Added flag 'kDNSServiceFlagsForceMulticast'. Passing through an interface id for a unicast name
doesn't force multicast unless you set this flag to indicate explicitly that this is what you want

Revision 1.31  2004/10/16 00:17:00  cheshire
<rdar://problem/3770558> Replace IP TTL 255 check with local subnet source address check

Revision 1.30  2004/09/21 23:29:51  cheshire
<rdar://problem/3680045> DNSServiceResolve should delay sending packets

Revision 1.29  2004/09/17 01:08:53  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.28  2004/09/17 00:31:52  cheshire
For consistency with ipv6, renamed rdata field 'ip' to 'ipv4'

Revision 1.27  2004/09/16 01:58:22  cheshire
Fix compiler warnings

Revision 1.26  2004/08/24 21:55:07  cheshire
Don't try to build IPv6 code on systems that don't have IPv6

Revision 1.25  2004/07/20 23:42:37  cheshire
Update to use only "_services._dns-sd._udp.local." meta-query for service enumeration

Revision 1.24  2004/06/15 02:39:47  cheshire
When displaying error message, only show command name, not entire path

Revision 1.23  2004/05/18 23:51:26  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.22  2004/04/20 22:43:28  cheshire
Use _services._dns-sd._udp query, as documented in
<http://files.dns-sd.org/draft-cheshire-dnsext-dns-sd-02.txt>

Revision 1.21  2004/01/28 21:38:57  cheshire
Also ask target host for _services._mdns._udp.local. list

Revision 1.20  2004/01/28 19:04:38  cheshire
Fix Ctrl-C handling when multiple targets are specified

Revision 1.19  2004/01/28 03:49:30  cheshire
Enhanced mDNSIdentify to make use of new targeted-query capability

Revision 1.18  2004/01/27 19:06:51  cheshire
Remove workaround for WWDC 2003 bug; no one has run that buggy build for a long time

Revision 1.17  2004/01/22 03:57:00  cheshire
Use the new meta-interface mDNSInterface_ForceMCast. This restores mDNSIdentify's
ability to use multicast queries with non-link-local target addresses, like 17.x.x.x.

Revision 1.16  2004/01/22 00:03:32  cheshire
Add while() loop so that a list of targets may be specified on the command line

Revision 1.15  2004/01/21 21:55:06  cheshire
Don't need to wait for timeout once we've got the information we wanted

Revision 1.14  2003/12/17 00:51:22  cheshire
Changed mDNSNetMonitor and mDNSIdentify to link the object files
instead of #including the "DNSCommon.c" "uDNS.c" and source files

Revision 1.13  2003/12/13 03:05:28  ksekar
<rdar://problem/3192548>: DynDNS: Unicast query of service records

Revision 1.12  2003/11/14 21:27:09  cheshire
<rdar://problem/3484766>: Security: Crashing bug in mDNSResponder
Fix code that should use buffer size MAX_ESCAPED_DOMAIN_NAME (1005) instead of 256-byte buffers.

Revision 1.11  2003/10/30 19:26:38  cheshire
Fix warnings on certain compilers

Revision 1.10  2003/09/02 20:38:57  cheshire
#include <signal.h> for Linux

Revision 1.9  2003/08/14 23:57:46  cheshire
Report if there is no answer at all from the target host

Revision 1.8  2003/08/14 02:19:55  cheshire
<rdar://problem/3375491> Split generic ResourceRecord type into two separate types: AuthRecord and CacheRecord

Revision 1.7  2003/08/12 19:56:26  cheshire
Update to APSL 2.0

Revision 1.6  2003/08/06 01:46:18  cheshire
Distinguish no answer from partial answer

Revision 1.5  2003/08/05 23:56:26  cheshire
Update code to compile with the new mDNSCoreReceive() function that requires a TTL
(Right now mDNSPosix.c just reports 255 -- we should fix this)

Revision 1.4  2003/08/04 17:24:48  cheshire
Combine the three separate A/AAAA/HINFO queries into a single qtype "ANY" query

Revision 1.3  2003/08/04 17:14:08  cheshire
Do both AAAA queries in parallel

Revision 1.2  2003/08/02 02:25:13  cheshire
Multiple improvements: Now displays host's name, and all v4 and v6 addresses, as well as HINFO record

Revision 1.1  2003/08/01 02:20:02  cheshire
Add mDNSIdentify tool, used to discover what version of mDNSResponder a particular host is running

 */

//*************************************************************************************************************
// Incorporate mDNS.c functionality

// We want to use the functionality provided by "mDNS.c",
// except we'll sneak a peek at the packets before forwarding them to the normal mDNSCoreReceive() routine
#define mDNSCoreReceive __MDNS__mDNSCoreReceive
#include "mDNS.c"
#undef mDNSCoreReceive

//*************************************************************************************************************
// Headers

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>		// For n_long, required by <netinet/ip.h> below
#include <netinet/ip.h>				// For IPTOS_LOWDELAY etc.
#include <arpa/inet.h>
#include <signal.h>

#include "mDNSEmbeddedAPI.h"// Defines the interface to the mDNS core code
#include "mDNSPosix.h"    // Defines the specific types needed to run mDNS on this platform
#include "ExampleClientApp.h"

//*************************************************************************************************************
// Globals

static mDNS mDNSStorage;       // mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;  // Stores this platform's globals
#define RR_CACHE_SIZE 500
static CacheEntity gRRCache[RR_CACHE_SIZE];

static volatile int StopNow;	// 0 means running, 1 means stop because we got an answer, 2 means stop because of Ctrl-C
static volatile int NumAnswers, NumAddr, NumAAAA, NumHINFO;
static char hostname[MAX_ESCAPED_DOMAIN_NAME], hardware[256], software[256];
static mDNSAddr lastsrc, hostaddr, target;
static mDNSOpaque16 lastid, id;

//*************************************************************************************************************
// Utilities

// Special version of printf that knows how to print IP addresses, DNS-format name strings, etc.
mDNSlocal mDNSu32 mprintf(const char *format, ...) IS_A_PRINTF_STYLE_FUNCTION(1,2);
mDNSlocal mDNSu32 mprintf(const char *format, ...)
	{
	mDNSu32 length;
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	length = mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr);
	va_end(ptr);
	printf("%s", buffer);
	return(length);
	}

//*************************************************************************************************************
// Main code

mDNSexport void mDNSCoreReceive(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end,
	const mDNSAddr *const srcaddr, const mDNSIPPort srcport, const mDNSAddr *const dstaddr, const mDNSIPPort dstport,
	const mDNSInterfaceID InterfaceID)
	{
	(void)dstaddr; // Unused
	// Snag copy of header ID, then call through
	lastid = msg->h.id;
	lastsrc = *srcaddr;

	// We *want* to allow off-net unicast responses here.
	// For now, the simplest way to allow that is to pretend it was received via multicast so that mDNSCore doesn't reject the packet
	__MDNS__mDNSCoreReceive(m, msg, end, srcaddr, srcport, &AllDNSLinkGroup_v4, dstport, InterfaceID);
	}

static void NameCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	(void)m;		// Unused
	(void)question;	// Unused
	(void)AddRecord;// Unused
	if (!id.NotAnInteger) id = lastid;
	if (answer->rrtype == kDNSType_PTR || answer->rrtype == kDNSType_CNAME)
		{
		ConvertDomainNameToCString(&answer->rdata->u.name, hostname);
		StopNow = 1;
		mprintf("%##s %s %##s\n", answer->name->c, DNSTypeName(answer->rrtype), answer->rdata->u.name.c);
		}
	}

static void InfoCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	(void)m;		// Unused
	(void)question;	// Unused
	(void)AddRecord;// Unused
	if (answer->rrtype == kDNSType_A)
		{
		if (!id.NotAnInteger) id = lastid;
		NumAnswers++;
		NumAddr++;
		mprintf("%##s %s %.4a\n", answer->name->c, DNSTypeName(answer->rrtype), &answer->rdata->u.ipv4);
		hostaddr.type = mDNSAddrType_IPv4;	// Prefer v4 target to v6 target, for now
		hostaddr.ip.v4 = answer->rdata->u.ipv4;
		}
	else if (answer->rrtype == kDNSType_AAAA)
		{
		if (!id.NotAnInteger) id = lastid;
		NumAnswers++;
		NumAAAA++;
		mprintf("%##s %s %.16a\n", answer->name->c, DNSTypeName(answer->rrtype), &answer->rdata->u.ipv6);
		if (!hostaddr.type)	// Prefer v4 target to v6 target, for now
			{
			hostaddr.type = mDNSAddrType_IPv6;
			hostaddr.ip.v6 = answer->rdata->u.ipv6;
			}
		}
	else if (answer->rrtype == kDNSType_HINFO)
		{
		mDNSu8 *p = answer->rdata->u.data;
		strncpy(hardware, (char*)(p+1), p[0]);
		hardware[p[0]] = 0;
		p += 1 + p[0];
		strncpy(software, (char*)(p+1), p[0]);
		software[p[0]] = 0;
		NumAnswers++;
		NumHINFO++;
		}

	// If we've got everything we're looking for, don't need to wait any more
	if (NumHINFO && (NumAddr || NumAAAA)) StopNow = 1;
	}

static void ServicesCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	(void)m;		// Unused
	(void)question;	// Unused
	(void)AddRecord;// Unused
	// Right now the mDNSCore targeted-query code is incomplete --
	// it issues targeted queries, but accepts answers from anywhere
	// For now, we'll just filter responses here so we don't get confused by responses from someone else
	if (answer->rrtype == kDNSType_PTR && mDNSSameAddress(&lastsrc, &target))
		{
		NumAnswers++;
		NumAddr++;
		mprintf("%##s %s %##s\n", answer->name->c, DNSTypeName(answer->rrtype), answer->rdata->u.name.c);
		StopNow = 1;
		}
	}

mDNSexport void WaitForAnswer(mDNS *const m, int seconds)
	{
	struct timeval end;
	gettimeofday(&end, NULL);
	end.tv_sec += seconds;
	StopNow = 0;
	NumAnswers = 0;
	while (!StopNow)
		{
		int nfds = 0;
		fd_set readfds;
		struct timeval now, remain = end;
		int result;

		FD_ZERO(&readfds);
		gettimeofday(&now, NULL);
		if (remain.tv_usec < now.tv_usec) { remain.tv_usec += 1000000; remain.tv_sec--; }
		if (remain.tv_sec < now.tv_sec) return;
		remain.tv_usec -= now.tv_usec;
		remain.tv_sec  -= now.tv_sec;
		mDNSPosixGetFDSet(m, &nfds, &readfds, &remain);
		result = select(nfds, &readfds, NULL, NULL, &remain);
		if (result >= 0) mDNSPosixProcessFDSet(m, &readfds);
		else if (errno != EINTR) StopNow = 2;
		}
	}

mDNSlocal mStatus StartQuery(DNSQuestion *q, char *qname, mDNSu16 qtype, const mDNSAddr *target, mDNSQuestionCallback callback)
	{
	if (qname) MakeDomainNameFromDNSNameString(&q->qname, qname);
	q->Target           = target ? *target : zeroAddr;
	q->TargetPort       = MulticastDNSPort;
	q->TargetQID        = zeroID;
	q->InterfaceID      = mDNSInterface_Any;
	q->qtype            = qtype;
	q->qclass           = kDNSClass_IN;
	q->LongLived        = mDNSfalse;
	q->ExpectUnique     = mDNStrue;
	q->ForceMCast       = mDNStrue;		// Query via multicast, even for apparently uDNS names like 1.1.1.17.in-addr.arpa.
	q->QuestionCallback = callback;
	q->QuestionContext  = NULL;

	//mprintf("%##s %s ?\n", q->qname.c, DNSTypeName(qtype));
	return(mDNS_StartQuery(&mDNSStorage, q));
	}

mDNSlocal void DoOneQuery(DNSQuestion *q, char *qname, mDNSu16 qtype, const mDNSAddr *target, mDNSQuestionCallback callback)
	{
	mStatus status = StartQuery(q, qname, qtype, target, callback);
	if (status != mStatus_NoError)
		StopNow = 2;
	else
		{
		WaitForAnswer(&mDNSStorage, 4);
		mDNS_StopQuery(&mDNSStorage, q);
		}
	}

mDNSlocal int DoQuery(DNSQuestion *q, char *qname, mDNSu16 qtype, const mDNSAddr *target, mDNSQuestionCallback callback)
	{
	DoOneQuery(q, qname, qtype, target, callback);
	if (StopNow == 0 && target && target->type)
		{
		mprintf("%##s %s Trying multicast\n", q->qname.c, DNSTypeName(q->qtype));
		DoOneQuery(q, qname, qtype, NULL, callback);
		}
	if (StopNow == 0 && NumAnswers == 0)
		mprintf("%##s %s *** No Answer ***\n", q->qname.c, DNSTypeName(q->qtype));
	return(StopNow);
	}

mDNSlocal void HandleSIG(int signal)
	{
	(void)signal;	// Unused
	debugf("%s","");
	debugf("HandleSIG");
	StopNow = 2;
	}

mDNSexport int main(int argc, char **argv)
	{
	const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
	int this_arg = 1;
	mStatus status;
	struct in_addr s4;
#if HAVE_IPV6
	struct in6_addr s6;
#endif
	char buffer[256];
	DNSQuestion q;

	if (argc < 2) goto usage;
	
	// Since this is a special command-line tool, we want LogMsg() errors to go to stderr, not syslog
	mDNS_DebugMode = mDNStrue;
	
    // Initialise the mDNS core.
	status = mDNS_Init(&mDNSStorage, &PlatformStorage,
    	gRRCache, RR_CACHE_SIZE,
    	mDNS_Init_DontAdvertiseLocalAddresses,
    	mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
	if (status) { fprintf(stderr, "Daemon start: mDNS_Init failed %ld\n", status); return(status); }

	signal(SIGINT, HandleSIG);	// SIGINT is what you get for a Ctrl-C
	signal(SIGTERM, HandleSIG);

	while (this_arg < argc)
		{
		char *arg = argv[this_arg++];
		if (this_arg > 2) printf("\n");

		lastid = id = zeroID;
		hostaddr = target = zeroAddr;
		hostname[0] = hardware[0] = software[0] = 0;
		NumAddr = NumAAAA = NumHINFO = 0;

		if (inet_pton(AF_INET, arg, &s4) == 1)
			{
			mDNSu8 *p = (mDNSu8 *)&s4;
			mDNS_snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d.in-addr.arpa.", p[3], p[2], p[1], p[0]);
			printf("%s\n", buffer);
			target.type = mDNSAddrType_IPv4;
			target.ip.v4.NotAnInteger = s4.s_addr;
			DoQuery(&q, buffer, kDNSType_PTR, &target, NameCallback);
			if (StopNow == 2) break;
			}
#if HAVE_IPV6
		else if (inet_pton(AF_INET6, arg, &s6) == 1)
			{
			int i;
			mDNSu8 *p = (mDNSu8 *)&s6;
			for (i = 0; i < 16; i++)
				{
				static const char hexValues[] = "0123456789ABCDEF";
				buffer[i * 4    ] = hexValues[p[15-i] & 0x0F];
				buffer[i * 4 + 1] = '.';
				buffer[i * 4 + 2] = hexValues[p[15-i] >> 4];
				buffer[i * 4 + 3] = '.';
				}
			mDNS_snprintf(&buffer[64], sizeof(buffer)-64, "ip6.arpa.");
			target.type = mDNSAddrType_IPv6;
			bcopy(&s6, &target.ip.v6, sizeof(target.ip.v6));
			DoQuery(&q, buffer, kDNSType_PTR, &target, NameCallback);
			if (StopNow == 2) break;
			}
#endif
		else
			strcpy(hostname, arg);
	
		// Now we have the host name; get its A, AAAA, and HINFO
		if (hostname[0]) DoQuery(&q, hostname, kDNSQType_ANY, &target, InfoCallback);
		if (StopNow == 2) break;
	
		if (hardware[0] || software[0])
			{
			DNSQuestion q1;
			printf("HINFO Hardware: %s\n", hardware);
			printf("HINFO Software: %s\n", software);
			// We need to make sure the services query is targeted
			if (target.type == 0) target = hostaddr;
			StartQuery(&q1, "_services._dns-sd._udp.local.", kDNSQType_ANY, &target, ServicesCallback);
			WaitForAnswer(&mDNSStorage, 4);
			mDNS_StopQuery(&mDNSStorage, &q1);
			if (StopNow == 2) break;
			}
		else if (NumAnswers)
			{
			printf("Host has no HINFO record; Best guess is ");
			if (id.b[1]) printf("mDNSResponder-%d\n", id.b[1]);
			else if (NumAAAA) printf("very early Panther build (mDNSResponder-33 or earlier)\n");
			else printf("Jaguar version of mDNSResponder with no IPv6 support\n");
			}
		else
			printf("Incorrect dot-local hostname, address, or no mDNSResponder running on that machine\n");
		}

	mDNS_Close(&mDNSStorage);
	return(0);

usage:
	fprintf(stderr, "%s <dot-local hostname> or <IPv4 address> or <IPv6 address> ...\n", progname);
	return(-1);
	}
