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

$Log: Identify.c,v $
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

#include "mDNSClientAPI.h"// Defines the interface to the mDNS core code
#include "mDNSPosix.h"    // Defines the specific types needed to run mDNS on this platform
#include "ExampleClientApp.h"

//*************************************************************************************************************
// Globals

static mDNS mDNSStorage;       // mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;  // Stores this platform's globals
#define RR_CACHE_SIZE 500
static CacheRecord gRRCache[RR_CACHE_SIZE];

static volatile int StopNow;	// 0 means running, 1 means stop because we got an answer, 2 means stop because of Ctrl-C
static volatile int NumAnswers, NumAddr, NumAAAA, NumHINFO;
static char hostname[256], hardware[256], software[256];
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
	const mDNSInterfaceID InterfaceID, mDNSu8 ttl)
	{
	// Snag copy of header ID, then call through
	lastid = msg->h.id;
	__MDNS__mDNSCoreReceive(m, msg, end, srcaddr, srcport, dstaddr, dstport, InterfaceID, ttl);
	}

static void NameCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	(void)m;		// Unused
	(void)question;	// Unused
	(void)AddRecord;// Unused
	if (!id.NotAnInteger) id = lastid;
	ConvertDomainNameToCString(&answer->rdata->u.name, hostname);
	StopNow = 1;
	mprintf("%##s %s %##s\n", answer->name.c, DNSTypeName(answer->rrtype), &answer->rdata->u.name.c);
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
		mprintf("%##s %s %.4a\n", answer->name.c, DNSTypeName(answer->rrtype), &answer->rdata->u.ip);
		}
	else if (answer->rrtype == kDNSType_AAAA)
		{
		if (!id.NotAnInteger) id = lastid;
		NumAnswers++;
		NumAAAA++;
		mprintf("%##s %s %.16a\n", answer->name.c, DNSTypeName(answer->rrtype), &answer->rdata->u.ipv6);
		}
	else if (answer->rrtype == kDNSType_HINFO)
		{
		mDNSu8 *p = answer->rdata->u.data;
		strncpy(hardware, p+1, p[0]);
		hardware[p[0]] = 0;
		p += 1 + p[0];
		strncpy(software, p+1, p[0]);
		software[p[0]] = 0;
		NumAnswers++;
		NumHINFO++;
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

mDNSlocal mStatus StartQuery(DNSQuestion *q, char *qname, mDNSu16 qtype, mDNSQuestionCallback callback)
	{
	if (qname) MakeDomainNameFromDNSNameString(&q->qname, qname);

	q->InterfaceID      = mDNSInterface_Any;
	q->qtype            = qtype;
	q->qclass           = kDNSClass_IN;
	q->QuestionCallback = callback;
	q->QuestionContext  = NULL;

	//mprintf("%##s %s ?\n", q->qname.c, DNSTypeName(qtype));
	return(mDNS_StartQuery(&mDNSStorage, q));
	}

mDNSlocal int DoQuery(DNSQuestion *q, char *qname, mDNSu16 qtype, mDNSQuestionCallback callback)
	{
	mStatus status = StartQuery(q, qname, qtype, callback);
	if (status != mStatus_NoError)
		StopNow = 2;
	else
		{
		WaitForAnswer(&mDNSStorage, 4);
		mDNS_StopQuery(&mDNSStorage, q);
		if (StopNow == 0 && NumAnswers == 0)
			printf("%s %s *** No Answer ***\n", qname, DNSTypeName(qtype));
		}
	return(StopNow);
	}

mDNSlocal void HandleSIG(int signal)
	{
	(void)signal;	// Unused
	debugf("");
	debugf("HandleSIG");
	StopNow = 2;
	}

mDNSexport int main(int argc, char **argv)
	{
	mStatus status;
	
	if (argc < 2) goto usage;
	
    // Initialise the mDNS core.
	status = mDNS_Init(&mDNSStorage, &PlatformStorage,
    	gRRCache, RR_CACHE_SIZE,
    	mDNS_Init_DontAdvertiseLocalAddresses,
    	mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
	if (status) { fprintf(stderr, "Daemon start: mDNS_Init failed %ld\n", status); return(status); }

	signal(SIGINT, HandleSIG);	// SIGINT is what you get for a Ctrl-C
	signal(SIGTERM, HandleSIG);

	struct in_addr s4;
	struct in6_addr s6;

	char buffer[256];
	DNSQuestion q;

	if (inet_pton(AF_INET, argv[1], &s4) == 1)
		{
		mDNSu8 *p = (mDNSu8 *)&s4;
		mDNS_snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d.in-addr.arpa.", p[3], p[2], p[1], p[0]);
		printf("%s\n", buffer);
		if (DoQuery(&q, buffer, kDNSType_PTR, NameCallback) != 1) goto exit;
		}
	else if (inet_pton(AF_INET6, argv[1], &s6) == 1)
		{
		DNSQuestion q1, q2;
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
		MakeDomainNameFromDNSNameString(&q1.qname, buffer);
		mDNS_snprintf(&buffer[32], sizeof(buffer)-32, "ip6.arpa.");	// Workaround for WWDC bug
		MakeDomainNameFromDNSNameString(&q2.qname, buffer);
		StartQuery(&q1, NULL, kDNSType_PTR, NameCallback);
		StartQuery(&q2, NULL, kDNSType_PTR, NameCallback);
		WaitForAnswer(&mDNSStorage, 4);
		mDNS_StopQuery(&mDNSStorage, &q1);
		mDNS_StopQuery(&mDNSStorage, &q2);
		if (StopNow != 1) { mprintf("%##s %s *** No Answer ***\n", q1.qname.c, DNSTypeName(q1.qtype)); goto exit; }
		}
	else
		strcpy(hostname, argv[1]);

	// Now we have the host name; get its A, AAAA, and HINFO
	if (DoQuery(&q, hostname, kDNSQType_ANY, InfoCallback) == 2) goto exit;	// Interrupted with Ctrl-C

	if (hardware[0] || software[0])
		{
		printf("HINFO Hardware: %s\n", hardware);
		printf("HINFO Software: %s\n", software);
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

exit:
	mDNS_Close(&mDNSStorage);
	return(0);

usage:
	fprintf(stderr, "%s <dot-local hostname> or <IPv4 address> or <IPv6 address>\n", argv[0]);
	return(-1);
	}
