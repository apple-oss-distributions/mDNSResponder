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

$Log: NetMonitor.c,v $
Revision 1.49  2003/10/30 19:38:56  cheshire
Fix warning on certain compilers

Revision 1.48  2003/10/30 19:30:00  cheshire
Fix warnings on certain compilers

Revision 1.47  2003/09/05 18:49:57  cheshire
Add total packet size to display

Revision 1.46  2003/09/05 02:33:48  cheshire
Set output to be line buffered, so you can redirect to a file and "tail -f" the file in another window

Revision 1.45  2003/09/04 00:16:20  cheshire
Only show count of unique source addresses seen on network if we're not filtering

Revision 1.44  2003/09/02 22:13:28  cheshire
Show total host count in final summary table

Revision 1.43  2003/09/02 21:42:52  cheshire
Improved alignment of final summary table with v6 addresses

Revision 1.42  2003/09/02 20:59:24  cheshire
Use bcopy() instead of non-portable "__u6_addr.__u6_addr32" fields.

Revision 1.41  2003/08/29 22:05:44  cheshire
Also count subsequent KA packets for the purposes of statistics counting

Revision 1.40  2003/08/29 16:43:24  cheshire
Also display breakdown of Probe/Goodbye/BrowseQ etc. for each host

Revision 1.39  2003/08/28 02:07:48  vlubet
Added "per hosts" statistics

Revision 1.38  2003/08/20 22:41:42  cheshire
Also display total multicast packet count

Revision 1.37  2003/08/20 22:32:08  cheshire
Error in DisplayQuery: Authorities come *after* Answers, not before

Revision 1.36  2003/08/18 23:20:10  cheshire
RDLength moved from the RData to the ResourceRecord object.

Revision 1.35  2003/08/15 20:17:28  cheshire
"LargeResourceRecord" changed to "LargeCacheRecord"

Revision 1.34  2003/08/14 02:19:55  cheshire
<rdar://problem/3375491> Split generic ResourceRecord type into two separate types: AuthRecord and CacheRecord

Revision 1.33  2003/08/12 19:56:26  cheshire
Update to APSL 2.0

Revision 1.32  2003/08/06 18:57:01  cheshire
Update comments

Revision 1.31  2003/08/06 02:05:12  cheshire
Add ability to give a list of hosts to monitor

Revision 1.30  2003/08/05 23:56:26  cheshire
Update code to compile with the new mDNSCoreReceive() function that requires a TTL
(Right now mDNSPosix.c just reports 255 -- we should fix this)

Revision 1.29  2003/08/05 00:43:12  cheshire
Report errors encountered while processing authority section

Revision 1.28  2003/07/29 22:51:08  cheshire
Added hexdump for packets we can't decode, so we can find out *why* we couldn't decode them

Revision 1.27  2003/07/29 22:48:04  cheshire
Completed support for decoding packets containing oversized resource records

Revision 1.26  2003/07/19 03:25:23  cheshire
Change to make use of new GetLargeResourceRecord() call, for handling larger records

Revision 1.25  2003/07/18 00:13:23  cheshire
Remove erroneous trailing '\' from TXT record display

Revision 1.24  2003/07/17 17:10:51  cheshire
<rdar://problem/3315761> Implement "unicast response" request, using top bit of qclass
Further work: distinguish between PM and PU

Revision 1.23  2003/07/16 22:20:23  cheshire
<rdar://problem/3315761> Implement "unicast response" request, using top bit of qclass
Made mDNSNetMonitor distinguish between QM and QU in its logging output

Revision 1.22  2003/07/02 21:19:58  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.21  2003/06/18 05:48:41  cheshire
Fix warnings

Revision 1.20  2003/06/06 22:18:22  cheshire
Add extra space in Q output to line it up with RR output

Revision 1.19  2003/06/06 21:05:04  cheshire
Display state of cache-flush bit on additional records

Revision 1.18  2003/06/06 20:01:30  cheshire
For clarity, rename question fields name/rrtype/rrclass as qname/qtype/qclass
(Global search-and-replace; no functional change to code execution.)

Revision 1.17  2003/06/06 14:26:50  cheshire
Explicitly #include <time.h> for the benefit of certain Linux distributions

Revision 1.16  2003/05/29 21:56:36  cheshire
More improvements:
Distinguish modern multicast queries from legacy multicast queries
In addition to record counts, display packet counts of queries, legacy queries, and responses
Include TTL in RR display

Revision 1.15  2003/05/29 20:03:57  cheshire
Various improvements:
Display start and end time, average rates in packets-per-minute,
show legacy queries as -LQ-, improve display of TXT and unknown records

Revision 1.14  2003/05/26 04:45:42  cheshire
Limit line length when printing super-long TXT records

Revision 1.13  2003/05/26 03:21:29  cheshire
Tidy up address structure naming:
mDNSIPAddr         => mDNSv4Addr (for consistency with mDNSv6Addr)
mDNSAddr.addr.ipv4 => mDNSAddr.ip.v4
mDNSAddr.addr.ipv6 => mDNSAddr.ip.v6

Revision 1.12  2003/05/26 03:01:28  cheshire
<rdar://problem/3268904> sprintf/vsprintf-style functions are unsafe; use snprintf/vsnprintf instead

Revision 1.11  2003/05/26 00:48:13  cheshire
If mDNS packet contains a non-zero message ID, then display it.

Revision 1.10  2003/05/22 01:10:32  cheshire
Indicate when the TC bit is set on a query packet

Revision 1.9  2003/05/21 03:56:00  cheshire
Improve display of Probe queries

Revision 1.8  2003/05/09 21:41:56  cheshire
Track deletion/goodbye packets as separate category

Revision 1.7  2003/05/07 00:16:01  cheshire
More detailed decoding of Resource Records

Revision 1.6  2003/05/05 21:16:16  cheshire
<rdar://problem/3241281> Change timenow from a local variable to a structure member

Revision 1.5  2003/04/19 01:16:22  cheshire
Add filter option, to monitor only packets from a single specified source address

Revision 1.4  2003/04/18 00:45:21  cheshire
Distinguish announcements (AN) from deletions (DE)

Revision 1.3  2003/04/15 18:26:01  cheshire
Added timestamps and help information

Revision 1.2  2003/04/04 20:42:02  cheshire
Fix broken statistics counting

Revision 1.1  2003/04/04 01:37:14  cheshire
Added NetMonitor.c

 */

//*************************************************************************************************************
// Incorporate mDNS.c functionality

// We want to use much of the functionality provided by "mDNS.c",
// except we'll steal the packets that would be sent to normal mDNSCoreReceive() routine
#define mDNSCoreReceive __NOT__mDNSCoreReceive__NOT__
#include "mDNS.c"
#undef mDNSCoreReceive

//*************************************************************************************************************
// Headers

#include <stdio.h>			// For printf()
#include <stdlib.h>			// For malloc()
#include <string.h>			// For bcopy()
#include <time.h>			// For "struct tm" etc.
#include <netdb.h>			// For gethostbyname()
#include <sys/socket.h>		// For AF_INET, AF_INET6, etc.
#include <arpa/inet.h>		// For inet_addr()
#include <netinet/in.h>		// For INADDR_NONE

#include "mDNSPosix.h"      // Defines the specific types needed to run mDNS on this platform
#include "ExampleClientApp.h"

//*************************************************************************************************************
// Types and structures

enum
	{
	// Primitive operations
	OP_probe        = 0,
	OP_goodbye      = 1,

	// These are meta-categories;
	// Query and Answer operations are actually subdivided into two classes:
	// Browse  query/answer and
	// Resolve query/answer
	OP_query        = 2,
	OP_answer       = 3,

	// The "Browse" variants of query/answer
	OP_browsegroup  = 2,
	OP_browseq      = 2,
	OP_browsea      = 3,

	// The "Resolve" variants of query/answer
	OP_resolvegroup = 4,
	OP_resolveq     = 4,
	OP_resolvea     = 5,

	OP_NumTypes = 6
	};

typedef struct ActivityStat_struct ActivityStat;
struct ActivityStat_struct
	{
	ActivityStat *next;
	domainname srvtype;
	int printed;
	int totalops;
	int stat[OP_NumTypes];
	};

typedef struct FilterList_struct FilterList;
struct FilterList_struct
	{
	FilterList *next;
	mDNSAddr FilterAddr;
	};

//*************************************************************************************************************
// Globals

static mDNS mDNSStorage;						// mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;	// Stores this platform's globals

struct timeval tv_start, tv_end, tv_interval;

static FilterList *Filters;
#define ExactlyOneFilter (Filters && !Filters->next)

static int NumPktQ, NumPktL, NumPktR, NumPktB;	// Query/Legacy/Response/Bad
static int NumProbes, NumGoodbyes, NumQuestions, NumLegacy, NumAnswers, NumAdditionals;

static ActivityStat *stats;

#define OPBanner "Total Ops   Probe   Goodbye  BrowseQ  BrowseA ResolveQ ResolveA"

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
// Host Address List
//
// Would benefit from a hash

typedef enum
	{
	HostPkt_Q        = 0,		// Query
	HostPkt_L        = 1,		// Legacy Query
	HostPkt_R        = 2,		// Response
	HostPkt_B        = 3,		// Bad
	HostPkt_NumTypes = 4
	} HostPkt_Type;

typedef struct
	{
	mDNSAddr addr;
	unsigned long pkts[HostPkt_NumTypes];
	unsigned long totalops;
	unsigned long stat[OP_NumTypes];
	} HostEntry;

#define HostEntryTotalPackets(H) ((H)->pkts[HostPkt_Q] + (H)->pkts[HostPkt_L] + (H)->pkts[HostPkt_R] + (H)->pkts[HostPkt_B])

typedef struct
	{
	long		num;
	long		max;
	HostEntry	*hosts;
	} HostList;

static HostList IPv4HostList = { 0, 0, 0 };
static HostList IPv6HostList = { 0, 0, 0 };

mDNSlocal HostEntry *FindHost(const mDNSAddr *addr, HostList* list)
	{
	long	i;
	
	for (i = 0; i < list->num; i++)
		{
		HostEntry *entry = list->hosts + i;
		if (mDNSSameAddress(addr, &entry->addr))
			return entry;
		}

	return NULL;
	}
	
mDNSlocal HostEntry *AddHost(HostList* list)
	{
	HostEntry *entry;
	if (list->num >= list->max)
		{
		long newMax = list->max + 64;
		HostEntry *newHosts = realloc(list->hosts, newMax * sizeof(HostEntry));
		if (newHosts == NULL)
			return NULL;
		list->max = newMax;
		list->hosts = newHosts;
		}
	entry = list->hosts + list->num++;
	return(entry);
	}

mDNSlocal HostEntry *GotPacketFromHost(const mDNSAddr *addr, HostPkt_Type t)
	{
	if (ExactlyOneFilter) return(NULL);
	else
		{
		HostList *list = (addr->type == mDNSAddrType_IPv4) ? &IPv4HostList : &IPv6HostList;
		HostEntry *entry = FindHost(addr, list);
		if (!entry)
			{
			int i;
			entry = AddHost(list);
			if (!entry) return(NULL);
			entry->addr = *addr;
			for (i=0; i<HostPkt_NumTypes; i++) entry->pkts[i] = 0;
			entry->totalops = 0;
			for (i=0; i<OP_NumTypes;      i++) entry->stat[i] = 0;
			}
		entry->pkts[t]++;
		return(entry);
		}
	}

mDNSlocal int CompareHosts(const void *p1, const void *p2)
	{
	return (int)(HostEntryTotalPackets((HostEntry *)p2) - HostEntryTotalPackets((HostEntry *)p1));
	}

mDNSlocal void ShowSortedHostList(HostList *list, int max)
	{
	HostEntry *e, *end = &list->hosts[(max < list->num) ? max : list->num];
	qsort(list->hosts, list->num, sizeof(HostEntry), CompareHosts);
	if (list->num) mprintf("\n%-25s%s%s\n", "Source Address", OPBanner, "    Pkts    Query   LegacyQ Response");
	for (e = &list->hosts[0]; e < end; e++)
		{
		int len = mprintf("%#-25a", &e->addr);
		if (len > 25) mprintf("\n%25s", "");
		mprintf("%8d %8d %8d %8d %8d %8d %8d", e->totalops,
			e->stat[OP_probe], e->stat[OP_goodbye],
			e->stat[OP_browseq], e->stat[OP_browsea],
			e->stat[OP_resolveq], e->stat[OP_resolvea]);
		mprintf(" %8lu %8lu %8lu %8lu",
			HostEntryTotalPackets(e), e->pkts[HostPkt_Q], e->pkts[HostPkt_L], e->pkts[HostPkt_R]);
		if (e->pkts[HostPkt_B]) mprintf("Bad: %8lu", e->pkts[HostPkt_B]);
		mprintf("\n");
		}
	}

//*************************************************************************************************************
// Receive and process packets

mDNSexport mDNSBool ExtractServiceType(const domainname *const fqdn, domainname *const srvtype)
	{
	int i, len;
	const mDNSu8 *src = fqdn->c;
	mDNSu8 *dst = srvtype->c;
	
	len = *src;
	if (len == 0 || len >= 0x40) return(mDNSfalse);
	if (src[1] != '_') src += 1 + len;
	
	len = *src;
	if (len == 0 || len >= 0x40 || src[1] != '_') return(mDNSfalse);
	for (i=0; i<=len; i++) *dst++ = *src++;

	len = *src;
	if (len == 0 || len >= 0x40 || src[1] != '_') return(mDNSfalse);
	for (i=0; i<=len; i++) *dst++ = *src++;

	*dst++ = 0;		// Put the null root label on the end of the service type

	return(mDNStrue);
	}

mDNSlocal void recordstat(HostEntry *entry, domainname *fqdn, int op, mDNSu16 rrtype)
	{
	ActivityStat **s = &stats;
	domainname srvtype;

	if (op != OP_probe)
		{
		if (rrtype == kDNSType_SRV || rrtype == kDNSType_TXT) op = op - OP_browsegroup + OP_resolvegroup;
		else if (rrtype != kDNSType_PTR) return;
		}
	
	if (!ExtractServiceType(fqdn, &srvtype)) return;

	while (*s && !SameDomainName(&(*s)->srvtype, &srvtype)) s = &(*s)->next;
	if (!*s)
		{
		int i;
		*s = malloc(sizeof(ActivityStat));
		if (!*s) exit(-1);
		(*s)->next     = NULL;
		(*s)->srvtype  = srvtype;
		(*s)->printed  = 0;
		(*s)->totalops = 0;
		for (i=0; i<OP_NumTypes; i++) (*s)->stat[i] = 0;
		}

	(*s)->totalops++;
	(*s)->stat[op]++;
	if (entry)
		{
		entry->totalops++;
		entry->stat[op]++;
		}
	}

mDNSlocal void printstats(int max)
	{
	int i;
	for (i=0; i<max; i++)
		{
		int max = 0;
		ActivityStat *s, *m = NULL;
		for (s = stats; s; s=s->next)
			if (!s->printed && max < s->totalops)
				{ m = s; max = s->totalops; }
		if (!m) return;
		m->printed = mDNStrue;
		if (i==0) mprintf("%-25s%s\n", "Service Type", OPBanner);
		mprintf("%##-25s%8d %8d %8d %8d %8d %8d %8d\n", &m->srvtype, m->totalops, m->stat[OP_probe],
			m->stat[OP_goodbye], m->stat[OP_browseq], m->stat[OP_browsea], m->stat[OP_resolveq], m->stat[OP_resolvea]);
		}
	}

mDNSlocal const mDNSu8 *FindUpdate(mDNS *const m, const DNSMessage *const query, const mDNSu8 *ptr, const mDNSu8 *const end, DNSQuestion *q, LargeCacheRecord *pkt)
	{
	int i;
	for (i = 0; i < query->h.numAuthorities; i++)
		{
		const mDNSu8 *p2 = ptr;
		ptr = GetLargeResourceRecord(m, query, ptr, end, q->InterfaceID, 0, pkt);
		if (!ptr) break;
		if (ResourceRecordAnswersQuestion(&pkt->r.resrec, q)) return(p2);
		}
	return(mDNSNULL);
	}

mDNSlocal void DisplayTimestamp(void)
	{
	struct timeval tv;
	struct tm tm;
	gettimeofday(&tv, NULL);
	localtime_r((time_t*)&tv.tv_sec, &tm);
	mprintf("\n%d:%02d:%02d.%06d\n", tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
	}

mDNSlocal void DisplayPacketHeader(const DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *srcaddr, mDNSIPPort srcport)
	{
	const char *const ptype =   (msg->h.flags.b[0] & kDNSFlag0_QR_Response)             ? "-R- " :
								(srcport.NotAnInteger == MulticastDNSPort.NotAnInteger) ? "-Q- " : "-LQ-";

	DisplayTimestamp();
	mprintf("%#-16a %s             Q:%3d  Ans:%3d  Auth:%3d  Add:%3d  Size:%5d bytes",
		srcaddr, ptype, msg->h.numQuestions, msg->h.numAnswers, msg->h.numAuthorities, msg->h.numAdditionals, end - (mDNSu8 *)msg);

	if (msg->h.id.NotAnInteger) mprintf("  ID:%u", ((mDNSu16)msg->h.id.b[0])<<8 | msg->h.id.b[1]);

	if (msg->h.flags.b[0] & kDNSFlag0_TC)
		{
		if (msg->h.flags.b[0] & kDNSFlag0_QR_Response) mprintf("   Truncated");
		else                                           mprintf("   Truncated (KA list continues in next packet)");
		}
	mprintf("\n");
	}

mDNSlocal void DisplayResourceRecord(const mDNSAddr *const srcaddr, const char *const op, const ResourceRecord *const pktrr)
	{
	static const char hexchars[16] = "0123456789ABCDEF";
	#define MaxWidth 132
	char buffer[MaxWidth+8];
	char *p = buffer;

	RDataBody *rd = &pktrr->rdata->u;
	mDNSu8 *rdend = (mDNSu8 *)rd + pktrr->rdlength;
	mDNSu32 n = mprintf("%#-16a %-5s %-5s%5d %##s -> ", srcaddr, op, DNSTypeName(pktrr->rrtype), pktrr->rroriginalttl, pktrr->name.c);

	switch(pktrr->rrtype)
		{
		case kDNSType_A:	n += mprintf("%.4a", &rd->ip); break;
		case kDNSType_PTR:	n += mprintf("%##.*s", MaxWidth - n, &rd->name); break;
		case kDNSType_HINFO:// same as kDNSType_TXT below
		case kDNSType_TXT:	{
							mDNSu8 *t = rd->txt.c;
							while (t < rdend && t[0] && p < buffer+MaxWidth)
								{
								int i;
								for (i=1; i<=t[0] && p < buffer+MaxWidth; i++)
									{
									if (t[i] == '\\') *p++ = '\\';
									if (t[i] >= ' ') *p++ = t[i];
									else
										{
										*p++ = '\\';
										*p++ = '0';
										*p++ = 'x';
										*p++ = hexchars[t[i] >> 4];
										*p++ = hexchars[t[i] & 0xF];
										}
									}
								t += 1+t[0];
								if (t < rdend && t[0]) { *p++ = '\\'; *p++ = ' '; }
								}
							*p++ = 0;
							n += mprintf("%.*s", MaxWidth - n, buffer);
							} break;
		case kDNSType_AAAA:	n += mprintf("%.16a", &rd->ipv6); break;
		case kDNSType_SRV:	n += mprintf("%##s:%d", &rd->srv.target, ((mDNSu16)rd->srv.port.b[0] << 8) | rd->srv.port.b[1]); break;
		default:			{
							mDNSu8 *s = rd->data;
							while (s < rdend && p < buffer+MaxWidth)
								{
								if (*s == '\\') *p++ = '\\';
								if (*s >= ' ') *p++ = *s;
								else
									{
									*p++ = '\\';
									*p++ = '0';
									*p++ = 'x';
									*p++ = hexchars[*s >> 4];
									*p++ = hexchars[*s & 0xF];
									}
								s++;
								}
							*p++ = 0;
							n += mprintf("%.*s", MaxWidth - n, buffer);
							} break;
		}
	
	mprintf("\n");
	}

mDNSlocal void HexDump(const mDNSu8 *ptr, const mDNSu8 *const end)
	{
	while (ptr < end)
		{
		int i;
		for (i=0; i<16; i++)
			if (&ptr[i] < end) mprintf("%02X ", ptr[i]);
			else mprintf("   ");
		for (i=0; i<16; i++)
			if (&ptr[i] < end) mprintf("%c", ptr[i] <= ' ' || ptr[i] >= 126 ? '.' : ptr[i]);
		ptr += 16;
		mprintf("\n");
		}
	}

mDNSlocal void DisplayError(const mDNSAddr *srcaddr, const mDNSu8 *ptr, const mDNSu8 *const end, char *msg)
	{
	mprintf("%#-16a **** ERROR: FAILED TO READ %s **** \n", srcaddr, msg);
	HexDump(ptr, end);
	}

mDNSlocal void DisplayQuery(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *srcaddr, mDNSIPPort srcport, const mDNSInterfaceID InterfaceID)
	{
	int i;
	const mDNSu8 *ptr = msg->data;
	const mDNSu8 *auth = LocateAuthorities(msg, end);
	mDNSBool MQ = (srcport.NotAnInteger == MulticastDNSPort.NotAnInteger);
	HostEntry *entry = GotPacketFromHost(srcaddr, MQ ? HostPkt_Q : HostPkt_L);
	LargeCacheRecord pkt;

	DisplayPacketHeader(msg, end, srcaddr, srcport);
	if (MQ) NumPktQ++; else NumPktL++;

	for (i=0; i<msg->h.numQuestions; i++)
		{
		DNSQuestion q;
		mDNSu8 *p2 = (mDNSu8 *)getQuestion(msg, ptr, end, InterfaceID, &q);
		mDNSu16 ucbit = q.qclass & kDNSQClass_UnicastResponse;
		q.qclass &= ~kDNSQClass_UnicastResponse;
		if (!p2) { DisplayError(srcaddr, ptr, end, "QUESTION"); return; }
		ptr = p2;
		p2 = (mDNSu8 *)FindUpdate(m, msg, auth, end, &q, &pkt);
		if (p2)
			{
			NumProbes++;
			DisplayResourceRecord(srcaddr, ucbit ? "(PU)" : "(PM)", &pkt.r.resrec);
			recordstat(entry, &q.qname, OP_probe, q.qtype);
			p2 = (mDNSu8 *)skipDomainName(msg, p2, end);
			// Having displayed this update record, clear type and class so we don't display the same one again.
			p2[0] = p2[1] = p2[2] = p2[3] = 0;
			}
		else
			{
			const char *ptype = ucbit ? "(QU)" : "(QM)";
			if (srcport.NotAnInteger == MulticastDNSPort.NotAnInteger) NumQuestions++;
			else { NumLegacy++; ptype = "(LQ)"; }
			mprintf("%#-16a %-5s %-5s      %##s\n", srcaddr, ptype, DNSTypeName(q.qtype), q.qname.c);
			recordstat(entry, &q.qname, OP_query, q.qtype);
			}
		}

	for (i=0; i<msg->h.numAnswers; i++)
		{
		const mDNSu8 *ep = ptr;
		ptr = GetLargeResourceRecord(m, msg, ptr, end, InterfaceID, 0, &pkt);
		if (!ptr) { DisplayError(srcaddr, ep, end, "KNOWN ANSWER"); return; }
		DisplayResourceRecord(srcaddr, "(KA)", &pkt.r.resrec);
		
		// In the case of queries with long multi-packet KA lists, we count each subsequent KA packet
		// the same as a single query, to more accurately reflect the burden on the network
		// (A query with a six-packet KA list is *at least* six times the burden on the network as a single-packet query.)
		if (msg->h.numQuestions == 0 && i == 0)
			recordstat(entry, &pkt.r.resrec.name, OP_query, pkt.r.resrec.rrtype);
		}

	for (i=0; i<msg->h.numAuthorities; i++)
		{
		const mDNSu8 *ep = ptr;
		ptr = skipResourceRecord(msg, ptr, end);
		if (!ptr) { DisplayError(srcaddr, ep, end, "AUTHORITY"); return; }
		}
	}

mDNSlocal void DisplayResponse(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *end, const mDNSAddr *srcaddr, mDNSIPPort srcport, const mDNSInterfaceID InterfaceID)
	{
	int i;
	const mDNSu8 *ptr = msg->data;
	HostEntry *entry = GotPacketFromHost(srcaddr, HostPkt_R);
	LargeCacheRecord pkt;

	DisplayPacketHeader(msg, end, srcaddr, srcport);
	NumPktR++;

	for (i=0; i<msg->h.numQuestions; i++)
		{
		DNSQuestion q;
		const mDNSu8 *ep = ptr;
		ptr = getQuestion(msg, ptr, end, InterfaceID, &q);
		if (!ptr) { DisplayError(srcaddr, ep, end, "QUESTION"); return; }
		mprintf("%#-16a (?)  **** ERROR: SHOULD NOT HAVE Q IN mDNS RESPONSE **** %-5s %##s\n", srcaddr, DNSTypeName(q.qtype), q.qname.c);
		}

	for (i=0; i<msg->h.numAnswers; i++)
		{
		const mDNSu8 *ep = ptr;
		ptr = GetLargeResourceRecord(m, msg, ptr, end, InterfaceID, 0, &pkt);
		if (!ptr) { DisplayError(srcaddr, ep, end, "ANSWER"); return; }
		if (pkt.r.resrec.rroriginalttl)
			{
			NumAnswers++;
			DisplayResourceRecord(srcaddr, (pkt.r.resrec.RecordType & kDNSRecordTypePacketUniqueMask) ? "(AN)" : "(AN+)", &pkt.r.resrec);
			recordstat(entry, &pkt.r.resrec.name, OP_answer, pkt.r.resrec.rrtype);
			}
		else
			{
			NumGoodbyes++;
			DisplayResourceRecord(srcaddr, "(DE)", &pkt.r.resrec);
			recordstat(entry, &pkt.r.resrec.name, OP_goodbye, pkt.r.resrec.rrtype);
			}
		}

	for (i=0; i<msg->h.numAuthorities; i++)
		{
		const mDNSu8 *ep = ptr;
		ptr = GetLargeResourceRecord(m, msg, ptr, end, InterfaceID, 0, &pkt);
		if (!ptr) { DisplayError(srcaddr, ep, end, "AUTHORITY"); return; }
		mprintf("%#-16a (?)  **** ERROR: SHOULD NOT HAVE AUTHORITY IN mDNS RESPONSE **** %-5s %##s\n",
			srcaddr, DNSTypeName(pkt.r.resrec.rrtype), pkt.r.resrec.name.c);
		}

	for (i=0; i<msg->h.numAdditionals; i++)
		{
		const mDNSu8 *ep = ptr;
		ptr = GetLargeResourceRecord(m, msg, ptr, end, InterfaceID, 0, &pkt);
		if (!ptr) { DisplayError(srcaddr, ep, end, "ADDITIONAL"); return; }
		NumAdditionals++;
		DisplayResourceRecord(srcaddr, (pkt.r.resrec.RecordType & kDNSRecordTypePacketUniqueMask) ? "(AD)" : "(AD+)", &pkt.r.resrec);
		}
	}

mDNSlocal mDNSBool AddressMatchesFilterList(const mDNSAddr *srcaddr)
	{
	FilterList *f;
	if (!Filters) return(srcaddr->type == mDNSAddrType_IPv4);
	for (f=Filters; f; f=f->next) if (mDNSSameAddress(srcaddr, &f->FilterAddr)) return(mDNStrue);
	return(mDNSfalse);
	}

mDNSexport void mDNSCoreReceive(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end,
	const mDNSAddr *srcaddr, mDNSIPPort srcport, const mDNSAddr *dstaddr, mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, mDNSu8 ttl)
	{
	const mDNSu8 StdQ = kDNSFlag0_QR_Query    | kDNSFlag0_OP_StdQuery;
	const mDNSu8 StdR = kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery;
	const mDNSu8 QR_OP = (mDNSu8)(msg->h.flags.b[0] & kDNSFlag0_QROP_Mask);
	mDNSu8 *ptr = (mDNSu8 *)&msg->h.numQuestions;

	(void)dstaddr;	// Unused
	(void)dstport;	// Unused
	
	// Read the integer parts which are in IETF byte-order (MSB first, LSB second)
	msg->h.numQuestions   = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
	msg->h.numAnswers     = (mDNSu16)((mDNSu16)ptr[2] <<  8 | ptr[3]);
	msg->h.numAuthorities = (mDNSu16)((mDNSu16)ptr[4] <<  8 | ptr[5]);
	msg->h.numAdditionals = (mDNSu16)((mDNSu16)ptr[6] <<  8 | ptr[7]);
	
	if (ttl < 254)
		{
		debugf("** Apparent spoof mDNS %s packet from %#-15a to %#-15a TTL %d on %p with %2d Question%s %2d Answer%s %2d Authorit%s %2d Additional%s",
		(QR_OP == StdQ) ? "Query" : (QR_OP == StdR) ? "Response" : "Unkown",
		srcaddr, dstaddr, ttl, InterfaceID,
		msg->h.numQuestions,   msg->h.numQuestions   == 1 ? ", " : "s,",
		msg->h.numAnswers,     msg->h.numAnswers     == 1 ? ", " : "s,",
		msg->h.numAuthorities, msg->h.numAuthorities == 1 ? "y,  " : "ies,",
		msg->h.numAdditionals, msg->h.numAdditionals == 1 ? "" : "s");
		}
	
	// For now we're only interested in monitoring IPv4 traffic.
	// All IPv6 packets should just be duplicates of the v4 packets.
	if (AddressMatchesFilterList(srcaddr))
		{
		if      (QR_OP == StdQ) DisplayQuery   (m, msg, end, srcaddr, srcport, InterfaceID);
		else if (QR_OP == StdR) DisplayResponse(m, msg, end, srcaddr, srcport, InterfaceID);
		else
			{
			debugf("Unknown DNS packet type %02X%02X (ignored)", msg->h.flags.b[0], msg->h.flags.b[1]);
			GotPacketFromHost(srcaddr, HostPkt_B);
			NumPktB++;
			}
		}
	}

mDNSlocal mStatus mDNSNetMonitor(void)
	{
	struct tm tm;
	int h, m, s, mul, div, TotPkt;
	
	mStatus status = mDNS_Init(&mDNSStorage, &PlatformStorage,
		mDNS_Init_NoCache, mDNS_Init_ZeroCacheSize,
		mDNS_Init_DontAdvertiseLocalAddresses,
		mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
	if (status) return(status);

	gettimeofday(&tv_start, NULL);
	ExampleClientEventLoop(&mDNSStorage);	// Wait for user to hit Ctrl-C
	
	// Now display final summary
	TotPkt = NumPktQ + NumPktL + NumPktR;
	gettimeofday(&tv_end, NULL);
	tv_interval = tv_end;
	if (tv_start.tv_usec > tv_interval.tv_usec)
		{ tv_interval.tv_usec += 1000000; tv_interval.tv_sec--; }
	tv_interval.tv_sec  -= tv_start.tv_sec;
	tv_interval.tv_usec -= tv_start.tv_usec;
	h = (tv_interval.tv_sec / 3600);
	m = (tv_interval.tv_sec % 3600) / 60;
	s = (tv_interval.tv_sec % 60);
	if (tv_interval.tv_sec > 10)
		{
		mul = 60;
		div = tv_interval.tv_sec;
		}
	else
		{
		mul = 60000;
		div = tv_interval.tv_sec * 1000 + tv_interval.tv_usec / 1000;
		if (div == 0) div=1;
		}

	mprintf("\n\n");
	localtime_r((time_t*)&tv_start.tv_sec, &tm);
	mprintf("Started      %3d:%02d:%02d.%06d\n", tm.tm_hour, tm.tm_min, tm.tm_sec, tv_start.tv_usec);
	localtime_r((time_t*)&tv_end.tv_sec, &tm);
	mprintf("End          %3d:%02d:%02d.%06d\n", tm.tm_hour, tm.tm_min, tm.tm_sec, tv_end.tv_usec);
	mprintf("Captured for %3d:%02d:%02d.%06d\n", h, m, s, tv_interval.tv_usec);
	if (!Filters) mprintf("Unique source addresses seen on network: %d\n", IPv4HostList.num + IPv6HostList.num);
	mprintf("\n");
	mprintf("Modern Query        Packets:      %7d   (avg%5d/min)\n", NumPktQ,        NumPktQ        * mul / div);
	mprintf("Legacy Query        Packets:      %7d   (avg%5d/min)\n", NumPktL,        NumPktL        * mul / div);
	mprintf("Multicast Response  Packets:      %7d   (avg%5d/min)\n", NumPktR,        NumPktR        * mul / div);
	mprintf("Total     Multicast Packets:      %7d   (avg%5d/min)\n", TotPkt,         TotPkt         * mul / div);
	mprintf("\n");
	mprintf("Total New Service Probes:         %7d   (avg%5d/min)\n", NumProbes,      NumProbes      * mul / div);
	mprintf("Total Goodbye Announcements:      %7d   (avg%5d/min)\n", NumGoodbyes,    NumGoodbyes    * mul / div);
	mprintf("Total Query Questions:            %7d   (avg%5d/min)\n", NumQuestions,   NumQuestions   * mul / div);
	mprintf("Total Queries from Legacy Clients:%7d   (avg%5d/min)\n", NumLegacy,      NumLegacy      * mul / div);
	mprintf("Total Answers/Announcements:      %7d   (avg%5d/min)\n", NumAnswers,     NumAnswers     * mul / div);
	mprintf("Total Additional Records:         %7d   (avg%5d/min)\n", NumAdditionals, NumAdditionals * mul / div);
	mprintf("\n");
	printstats(15);

	if (!ExactlyOneFilter)
		{
		ShowSortedHostList(&IPv4HostList, 15);
		ShowSortedHostList(&IPv6HostList, 15);
		}

	mDNS_Close(&mDNSStorage);
	return(0);
	}

mDNSexport int main(int argc, char **argv)
	{
	int i;
	mStatus status;
	
	setlinebuf(stdout);				// Want to see lines as they appear, not block buffered

	for (i=1; i<argc; i++)
		{
		FilterList *f;
		struct in_addr s4;
		struct in6_addr s6;
		mDNSAddr a;
		a.type = mDNSAddrType_IPv4;

		if (inet_pton(AF_INET, argv[i], &s4) == 1)
			a.ip.v4.NotAnInteger = s4.s_addr;
		else if (inet_pton(AF_INET6, argv[i], &s6) == 1)
			{
			a.type = mDNSAddrType_IPv6;
			bcopy(&s6, &a.ip.v6, sizeof(a.ip.v6));
			}
		else
			{
			struct hostent *h = gethostbyname(argv[i]);
			if (h) a.ip.v4.NotAnInteger = *(long*)h->h_addr;
			else goto usage;
			}
		
		f = malloc(sizeof(*f));
		f->FilterAddr = a;
		f->next = Filters;
		Filters = f;
		}

	status = mDNSNetMonitor();
	if (status) { fprintf(stderr, "%s: mDNSNetMonitor failed %ld\n", argv[0], status); return(status); }
	return(0);

usage:
	fprintf(stderr, "\nmDNS traffic monitor\n");
	fprintf(stderr, "Usage: %s (<host>)\n", argv[0]);
	fprintf(stderr, "Optional <host> parameter displays only packets from that host\n");

	fprintf(stderr, "\nPer-packet header output:\n");
	fprintf(stderr, "-Q-            Multicast Query from mDNS client that accepts multicast responses\n");
	fprintf(stderr, "-R-            Multicast Response packet containing answers/announcements\n");
	fprintf(stderr, "-LQ-           Multicast Query from legacy client that does *not* listen for multicast responses\n");
	fprintf(stderr, "Q/Ans/Auth/Add Number of questions, answers, authority records and additional records in packet\n");

	fprintf(stderr, "\nPer-record display:\n");
	fprintf(stderr, "(PM)           Probe Question (new service starting), requesting multicast response\n");
	fprintf(stderr, "(PU)           Probe Question (new service starting), requesting unicast response\n");
	fprintf(stderr, "(DE)           Deletion/Goodbye (service going away)\n");
	fprintf(stderr, "(LQ)           Legacy Query Question\n");
	fprintf(stderr, "(QM)           Query Question, requesting multicast response\n");
	fprintf(stderr, "(QU)           Query Question, requesting unicast response\n");
	fprintf(stderr, "(KA)           Known Answer (information querier already knows)\n");
	fprintf(stderr, "(AN)           Unique Answer to question (or periodic announcment) (entire RR Set)\n");
	fprintf(stderr, "(AN+)          Answer to question (or periodic announcment) (add to existing RR Set members)\n");
	fprintf(stderr, "(AD)           Unique Additional Record Set (entire RR Set)\n");
	fprintf(stderr, "(AD+)          Additional records (add to existing RR Set members)\n");

	fprintf(stderr, "\nFinal summary, sorted by service type:\n");
	fprintf(stderr, "Probe          Probes for this service type starting up\n");
	fprintf(stderr, "Goodbye        Goodbye (deletion) packets for this service type shutting down\n");
	fprintf(stderr, "BrowseQ        Browse questions from clients browsing to find a list of instances of this service\n");
	fprintf(stderr, "BrowseA        Browse answers/announcments advertising instances of this service\n");
	fprintf(stderr, "ResolveQ       Resolve questions from clients actively connecting to an instance of this service\n");
	fprintf(stderr, "ResolveA       Resolve answers/announcments giving connection information for an instance of this service\n");
	fprintf(stderr, "\n");
	return(-1);
	}
