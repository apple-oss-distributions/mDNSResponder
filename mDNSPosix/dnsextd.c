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

$Log: dnsextd.c,v $
Revision 1.33  2005/03/11 19:09:02  ksekar
Fixed ZERO_LLQID macro

Revision 1.32  2005/03/10 22:54:33  ksekar
<rdar://problem/4046285> dnsextd leaks memory/ports

Revision 1.31  2005/02/24 02:37:57  ksekar
<rdar://problem/4021977> dnsextd memory management improvements

Revision 1.30  2005/01/27 22:57:56  cheshire
Fix compile errors on gcc4

Revision 1.29  2004/12/22 00:13:50  ksekar
<rdar://problem/3873993> Change version, port, and polling interval for LLQ

Revision 1.28  2004/12/17 00:30:00  ksekar
<rdar://problem/3924045> dnsextd memory leak

Revision 1.27  2004/12/17 00:27:32  ksekar
Ignore SIGPIPE

Revision 1.26  2004/12/17 00:21:33  ksekar
Fixes for new CacheRecord structure with indirect name pointer

Revision 1.25  2004/12/16 20:13:02  cheshire
<rdar://problem/3324626> Cache memory management improvements

Revision 1.24  2004/12/14 17:09:06  ksekar
fixed incorrect usage instructions

Revision 1.23  2004/12/06 20:24:31  ksekar
<rdar://problem/3907303> dnsextd leaks sockets

Revision 1.22  2004/12/03 20:20:29  ksekar
<rdar://problem/3904149> dnsextd: support delivery of large records via LLQ events

Revision 1.21  2004/12/03 06:11:34  ksekar
<rdar://problem/3885059> clean up dnsextd arguments

Revision 1.20  2004/12/01 04:27:28  cheshire
<rdar://problem/3872803> Darwin patches for Solaris and Suse
Don't use uint32_t, etc. -- they require stdint.h, which doesn't exist on FreeBSD 4.x, Solaris, etc.

Revision 1.19  2004/12/01 01:16:29  cheshire
Solaris compatibility fixes

Revision 1.18  2004/11/30 23:51:06  cheshire
Remove double semicolons

Revision 1.17  2004/11/30 22:37:01  cheshire
Update copyright dates and add "Mode: C; tab-width: 4" headers

Revision 1.16  2004/11/25 02:02:28  ksekar
Fixed verbose log message argument

Revision 1.15  2004/11/19 02:35:02  ksekar
<rdar://problem/3886317> Wide Area Security: Add LLQ-ID to events

Revision 1.14  2004/11/17 06:17:58  cheshire
Update comments to show correct SRV names: _dns-update._udp.<zone>. and _dns-llq._udp.<zone>.

Revision 1.13  2004/11/13 02:22:36  ksekar
<rdar://problem/3878201> Refresh Acks from daemon malformatted

Revision 1.12  2004/11/12 01:05:01  ksekar
<rdar://problem/3876757> dnsextd: daemon registers the SRV same record
twice at startup

Revision 1.11  2004/11/12 01:03:31  ksekar
<rdar://problem/3876776> dnsextd: KnownAnswers (CacheRecords) leaked

Revision 1.10  2004/11/12 00:35:28  ksekar
<rdar://problem/3876705> dnsextd: uninitialized pointer can cause crash

Revision 1.9  2004/11/10 20:38:17  ksekar
<rdar://problem/3874168> dnsextd: allow a "fudge" in LLQ lease echo

Revision 1.8  2004/11/01 17:48:14  cheshire
Changed SOA serial number back to signed. RFC 1035 may describe it as "unsigned", but
it's wrong. The SOA serial is a modular counter, as explained in "DNS & BIND", page
137. Since C doesn't have a modular type, we used signed, C's closest approximation.

Revision 1.7  2004/10/30 00:06:58  ksekar
<rdar://problem/3722535> Support Long Lived Queries in DNS Extension daemon

Revision 1.6  2004/09/17 01:08:54  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.5  2004/09/16 00:50:54  cheshire
Don't use MSG_WAITALL -- it returns "Invalid argument" on some Linux versions

Revision 1.4  2004/09/14 23:27:48  cheshire
Fix compile errors

Revision 1.3  2004/09/02 01:39:40  cheshire
For better readability, follow consistent convention that QR bit comes first, followed by OP bits

Revision 1.2  2004/08/24 23:27:57  cheshire
Fixes for Linux compatibility:
Don't use strings.h
Don't assume SIGINFO
Don't try to set servaddr.sin_len on platforms that don't have sa_len

Revision 1.1  2004/08/11 00:43:26  ksekar
<rdar://problem/3722542>: DNS Extension daemon for DNS Update Lease

*/

#include "../mDNSCore/mDNSEmbeddedAPI.h"
#include "../mDNSCore/DNSCommon.h"
#include "../mDNSCore/mDNS.c"
//!!!KRS we #include mDNS.c for the various constants defined there  - we should move these to DNSCommon.h

#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

// Compatibility workaround
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

//
// Constants
//

#define LOOPBACK "127.0.0.1"
#define NS_PORT 53
#define DAEMON_PORT 5352                // default, may be overridden via command line argument
#define LISTENQ 128                     // tcp connection backlog
#define RECV_BUFLEN 9000                
#define LEASETABLE_INIT_NBUCKETS 256    // initial hashtable size (doubles as table fills)
#define LLQ_TABLESIZE 1024              // !!!KRS make this dynamically growable
#define EXPIRATION_INTERVAL 300          // check for expired records every 5 minutes
#define SRV_TTL 7200                    // TTL For _dns-update SRV records

// LLQ Lease bounds (seconds)
#define LLQ_MIN_LEASE (15 * 60)
#define LLQ_MAX_LEASE (120 * 60)
#define LLQ_LEASE_FUDGE 60

// LLQ SOA poll interval (microseconds)
#define LLQ_MONITOR_ERR_INTERVAL (60 * 1000000)
#define LLQ_MONITOR_INTERVAL 250000
#ifdef SIGINFO
#define INFO_SIGNAL SIGINFO
#else
#define INFO_SIGNAL SIGUSR1
#endif

#define SAME_INADDR(x,y) (*((mDNSu32 *)&x) == *((mDNSu32 *)&y))
#define ZERO_LLQID(x) (!memcmp(x, "\x0\x0\x0\x0\x0\x0\x0\x0", 8))

//
// Data Structures
// Structs/fields that must be locked for thread safety are explicitly commented
//

typedef struct
	{
    struct sockaddr_in src;
    size_t len;
    DNSMessage msg;
    // Note: extra storage for oversized (TCP) messages goes here
	} PktMsg;

// lease table entry
typedef struct RRTableElem
	{
    struct RRTableElem *next;
    struct sockaddr_in cli;   // client's source address
    long expire;              // expiration time, in seconds since epoch
    domainname zone;          // from zone field of update message
    domainname name;          // name of the record
    CacheRecord rr;           // last field in struct allows for allocation of oversized RRs
	} RRTableElem;

typedef enum
	{
	RequestReceived = 0,
	ChallengeSent   = 1,
	Established     = 2
	} LLQState;

typedef struct AnswerListElem
	{
    struct AnswerListElem *next;
    domainname name;
    mDNSu16 type;
    CacheRecord *KnownAnswers;  // All valid answers delivered to client
    CacheRecord *EventList;     // New answers (adds/removes) to be sent to client
    int refcount;          
	} AnswerListElem;

// llq table entry
typedef struct LLQEntry
	{
    struct LLQEntry *next;     
    struct sockaddr_in cli;   // clien'ts source address 
    domainname qname;
    mDNSu16 qtype;
    mDNSu8 id[8];
    LLQState state;
    mDNSu32 lease;            // original lease, in seconds
    mDNSs32 expire;           // expiration, absolute, in seconds since epoch
    AnswerListElem *AnswerList;
	} LLQEntry;

// daemon-wide information
typedef struct 
	{
    // server variables - read only after initialization (no locking)
    struct in_addr saddr;      // server address
    domainname zone;           // zone being updated
    int tcpsd;                 // listening TCP socket
    int udpsd;                 // listening UDP socket

    // daemon variables - read only after initialization (no locking)
    uDNS_AuthInfo *AuthInfo;   // linked list of keys for signing deletion updates
    mDNSIPPort port;           // listening port

    // lease table variables (locked via mutex after initialization)
    RRTableElem **table;       // hashtable for records with leases
    pthread_mutex_t tablelock; // mutex for lease table
    mDNSs32 nbuckets;          // buckets allocated
    mDNSs32 nelems;            // elements in table

    // LLQ table variables
    LLQEntry *LLQTable[LLQ_TABLESIZE];  // !!!KRS change this and RRTable to use a common data structure
    AnswerListElem *AnswerTable[LLQ_TABLESIZE];
    int LLQEventListenSock;       // Unix domain socket pair - polling thread writes to ServPollSock, which wakes
    int LLQServPollSock;          // the main thread listening on EventListenSock, indicating that the zone has changed
	} DaemonInfo;

// args passed to UDP request handler thread as void*
typedef struct
	{
    PktMsg pkt;
    struct sockaddr_in cliaddr;
    DaemonInfo *d;
	} UDPRequestArgs;

// args passed to TCP request handler thread as void*
typedef struct
	{
    int sd;                     // socket connected to client
    struct sockaddr_in cliaddr; 
    DaemonInfo *d;
	} TCPRequestArgs;

//
// Global Variables
//

// booleans to determine runtime output
// read-only after initialization (no mutex protection)
static mDNSBool foreground = 0;
static mDNSBool verbose = 0;

// globals set via signal handler (accessed exclusively by main select loop and signal handler)
static mDNSBool terminate = 0;
static mDNSBool dumptable = 0;

//
// Logging Routines
// Log messages are delivered to syslog unless -f option specified
//

// common message logging subroutine
mDNSlocal void PrintLog(const char *buffer)
	{
	if (foreground)	
		{
		fprintf(stderr,"%s\n", buffer);
		fflush(stderr);
		}
	else				
		{
		openlog("dnsextd", LOG_CONS | LOG_PERROR, LOG_DAEMON);
		syslog(LOG_ERR, "%s", buffer);
		closelog();
		}
	}

// Verbose Logging (conditional on -v option)
mDNSlocal void VLog(const char *format, ...)
	{
   	char buffer[512];
	va_list ptr;

	if (!verbose) return;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
 	PrintLog(buffer);
	}

// Unconditional Logging
mDNSlocal void Log(const char *format, ...)
	{
   	char buffer[512];
	va_list ptr;

	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
 	PrintLog(buffer);
	}

// Error Logging
// prints message "dnsextd <function>: <operation> - <error message>" 
// must be compiled w/ -D_REENTRANT  for thread-safe errno usage
mDNSlocal void LogErr(const char *fn, const char *operation)
	{
	char buf[512];
	snprintf(buf, sizeof(buf), "%s: %s - %s", fn, operation, strerror(errno));
	PrintLog(buf);
	}

//
// Networking Utility Routines
//

// Convert DNS Message Header from Network to Host byte order
mDNSlocal void HdrNToH(PktMsg *pkt)
	{
	// Read the integer parts which are in IETF byte-order (MSB first, LSB second)
	mDNSu8 *ptr = (mDNSu8 *)&pkt->msg.h.numQuestions;
	pkt->msg.h.numQuestions   = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
	pkt->msg.h.numAnswers     = (mDNSu16)((mDNSu16)ptr[2] <<  8 | ptr[3]);
	pkt->msg.h.numAuthorities = (mDNSu16)((mDNSu16)ptr[4] <<  8 | ptr[5]);
	pkt->msg.h.numAdditionals = (mDNSu16)((mDNSu16)ptr[6] <<  8 | ptr[7]);
	}

// Convert DNS Message Header from Host to Network byte order
mDNSlocal void HdrHToN(PktMsg *pkt)
	{
	mDNSu16 numQuestions   = pkt->msg.h.numQuestions;
	mDNSu16 numAnswers     = pkt->msg.h.numAnswers;
	mDNSu16 numAuthorities = pkt->msg.h.numAuthorities;
	mDNSu16 numAdditionals = pkt->msg.h.numAdditionals;
	mDNSu8 *ptr = (mDNSu8 *)&pkt->msg.h.numQuestions;

	// Put all the integer values in IETF byte-order (MSB first, LSB second)
	*ptr++ = (mDNSu8)(numQuestions   >> 8);
	*ptr++ = (mDNSu8)(numQuestions   &  0xFF);
	*ptr++ = (mDNSu8)(numAnswers     >> 8);
	*ptr++ = (mDNSu8)(numAnswers     &  0xFF);
	*ptr++ = (mDNSu8)(numAuthorities >> 8);
	*ptr++ = (mDNSu8)(numAuthorities &  0xFF);
	*ptr++ = (mDNSu8)(numAdditionals >> 8);
	*ptr++ = (mDNSu8)(numAdditionals &  0xFF);
	}

// create a socket connected to nameserver
// caller terminates connection via close()
mDNSlocal int ConnectToServer(DaemonInfo *d)
	{
	struct sockaddr_in servaddr;
	int sd;
	
	bzero(&servaddr, sizeof(servaddr));
	if (d->saddr.s_addr) servaddr.sin_addr = d->saddr;
	else                 inet_pton(AF_INET, LOOPBACK, &d->saddr);  // use loopback if server not explicitly specified			
	servaddr.sin_port = htons(NS_PORT);
	servaddr.sin_family = AF_INET;
#ifndef NOT_HAVE_SA_LEN
	servaddr.sin_len = sizeof(servaddr); 
#endif
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) { LogErr("ConnectToServer", "socket");  return -1; }
	if (connect(sd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) { LogErr("ConnectToServer", "connect"); return -1; }
	return sd;
	}

// send an entire block of data over a connected socket, blocking if buffers are full
mDNSlocal int MySend(int sd, const void *msg, int len)
	{
	int n, nsent = 0;

	while (nsent < len)
		{
		n = send(sd, (char *)msg + nsent, len - nsent, 0);
		if (n < 0) { LogErr("MySend", "send");  return -1; }
		nsent += n;
		}
	return 0;
	}

// Transmit a DNS message, prefixed by its length, over TCP, blocking if necessary
mDNSlocal int SendTCPMsg(int sd, PktMsg *pkt)
	{
	// send the lenth, in network byte order
	mDNSu16 len = htons((mDNSu16)pkt->len);
	if (MySend(sd, &len, sizeof(len)) < 0) return -1;

	// send the message
	return MySend(sd, &pkt->msg, pkt->len);
	}

// Receive len bytes, waiting until we have all of them.
// Returns number of bytes read (which should always be the number asked for).
static int my_recv(const int sd, void *const buf, const int len)
    {
    // Don't use "MSG_WAITALL"; it returns "Invalid argument" on some Linux versions;
    // use an explicit while() loop instead.
    // Also, don't try to do '+=' arithmetic on the original "void *" pointer --
    // arithmetic on "void *" pointers is compiler-dependent.
    int remaining = len;
    char *ptr = (char *)buf;
    while (remaining)
    	{
    	ssize_t num_read = recv(sd, ptr, remaining, 0);
    	if ((num_read == 0) || (num_read < 0) || (num_read > remaining)) return -1;
    	ptr       += num_read;
    	remaining -= num_read;
    	}
    return(len);
    }

// Return a DNS Message read off of a TCP socket, or NULL on failure
// If storage is non-null, result is placed in that buffer.  Otherwise,
// returned value is allocated with Malloc, and contains sufficient extra
// storage for a Lease OPT RR

mDNSlocal PktMsg *ReadTCPMsg(int sd, PktMsg *storage)
	{	
	int nread, allocsize;
	mDNSu16 msglen = 0;	
	PktMsg *pkt = NULL;
	unsigned int srclen;
	
	nread = my_recv(sd, &msglen, sizeof(msglen));
	if (nread < 0) { LogErr("TCPRequestForkFn", "recv"); goto error; }
	msglen = ntohs(msglen);
	if (nread != sizeof(msglen)) { Log("Could not read length field of message"); goto error; }	

	if (storage)
		{
		if (msglen > sizeof(storage->msg)) { Log("ReadTCPMsg: provided buffer too small."); goto error; }
		pkt = storage;
		}
	else
		{
		// buffer extra space to add an OPT RR
		if (msglen > sizeof(DNSMessage)) allocsize = sizeof(PktMsg) - sizeof(DNSMessage) + msglen;
		else                             allocsize = sizeof(PktMsg);		
		pkt = malloc(allocsize);
		if (!pkt) { LogErr("ReadTCPMsg", "malloc"); goto error; }
		bzero(pkt, sizeof(*pkt));
		}
	
	pkt->len = msglen;
	srclen = sizeof(pkt->src);
	if (getpeername(sd, (struct sockaddr *)&pkt->src, &srclen) ||
		srclen != sizeof(pkt->src)) { LogErr("ReadTCPMsg", "getpeername"); bzero(&pkt->src, sizeof(pkt->src)); }
	nread = my_recv(sd, &pkt->msg, msglen);
	if (nread < 0) { LogErr("TCPRequestForkFn", "recv"); goto error; }
	if (nread != msglen) { Log("Could not read entire message"); goto error; }
	if (pkt->len < sizeof(DNSMessageHeader))
		{ Log("ReadTCPMsg: Message too short (%d bytes)", pkt->len);  goto error; }	
	HdrNToH(pkt);
	return pkt;
	//!!!KRS convert to HBO here?
	error:
	if (pkt && pkt != storage) free(pkt);
	return NULL;
	}

//
// Dynamic Update Utility Routines
//

// Get the lease life of records in a dynamic update
// returns -1 on error or if no lease present
mDNSlocal mDNSs32 GetPktLease(PktMsg *pkt)
	{
	mDNSs32 lease = -1;
	const mDNSu8 *ptr = NULL, *end = (mDNSu8 *)&pkt->msg + pkt->len;
	LargeCacheRecord lcr;
	int i;
	
	HdrNToH(pkt);
	ptr = LocateAdditionals(&pkt->msg, end);
	if (ptr) 
		for (i = 0; i < pkt->msg.h.numAdditionals; i++)
			{
			ptr = GetLargeResourceRecord(NULL, &pkt->msg, ptr, end, 0, kDNSRecordTypePacketAdd, &lcr);
			if (!ptr) { Log("Unable to read additional record"); break; }
			if (lcr.r.resrec.rrtype == kDNSType_OPT)
				{
				if (lcr.r.resrec.rdlength < LEASE_OPT_SIZE) continue;
				if (lcr.r.resrec.rdata->u.opt.opt != kDNSOpt_Lease) continue;
				lease = (mDNSs32)lcr.r.resrec.rdata->u.opt.OptData.lease;
				break;
				}
			}

	HdrHToN(pkt);
	return lease;
	}

// check if a request and server response complete a successful dynamic update
mDNSlocal mDNSBool SuccessfulUpdateTransaction(PktMsg *request, PktMsg *reply)
	{
	char buf[32];
	char *vlogmsg = NULL;
	
	// check messages
	if (!request || !reply) { vlogmsg = "NULL message"; goto failure; }
	if (request->len < sizeof(DNSMessageHeader) || reply->len < sizeof(DNSMessageHeader)) { vlogmsg = "Malformatted message"; goto failure; }

	// check request operation
	if ((request->msg.h.flags.b[0] & kDNSFlag0_QROP_Mask) != (request->msg.h.flags.b[0] & kDNSFlag0_QROP_Mask))
		{ vlogmsg = "Request opcode not an update"; goto failure; }

	// check result
	if ((reply->msg.h.flags.b[1] & kDNSFlag1_RC)) { vlogmsg = "Reply contains non-zero rcode";  goto failure; }
	if ((reply->msg.h.flags.b[0] & kDNSFlag0_QROP_Mask) != (kDNSFlag0_OP_Update | kDNSFlag0_QR_Response))
		{ vlogmsg = "Reply opcode not an update response"; goto failure; }

	VLog("Successful update from %s", inet_ntop(AF_INET, &request->src.sin_addr, buf, 32));
	return mDNStrue;		

	failure:
	VLog("Request %s: %s", inet_ntop(AF_INET, &request->src.sin_addr, buf, 32), vlogmsg);
	return mDNSfalse;
	}

// Allocate an appropriately sized CacheRecord and copy data from original.
// Name pointer in CacheRecord object is set to point to the name specified
//
mDNSlocal CacheRecord *CopyCacheRecord(const CacheRecord *orig, domainname *name)
	{
	CacheRecord *cr;
	size_t size = sizeof(*cr);
	if (orig->resrec.rdlength > InlineCacheRDSize) size += orig->resrec.rdlength - InlineCacheRDSize;
	cr = malloc(size);
	if (!cr) { LogErr("CopyCacheRecord", "malloc"); return NULL; }
	memcpy(cr, orig, size);
	cr->resrec.rdata = (RData*)&cr->rdatastorage;
	cr->resrec.name = name;
	
	return cr;
	}


//
// Lease Hashtable Utility Routines
//

// double hash table size
// caller must lock table prior to invocation
mDNSlocal void RehashTable(DaemonInfo *d)
	{
	RRTableElem *ptr, *tmp, **new;
	int i, bucket, newnbuckets = d->nbuckets * 2;

	VLog("Rehashing lease table (new size %d buckets)", newnbuckets);
	new = malloc(sizeof(RRTableElem *) * newnbuckets);
	if (!new) { LogErr("RehashTable", "malloc");  return; }
	bzero(new, newnbuckets * sizeof(RRTableElem *));

	for (i = 0; i < d->nbuckets; i++)
		{
		ptr = d->table[i];
		while (ptr)
			{
			bucket = ptr->rr.resrec.namehash % newnbuckets;
			tmp = ptr;
			ptr = ptr->next;
			tmp->next = new[bucket];
			new[bucket] = tmp;
			}
		}
	d->nbuckets = newnbuckets;
	free(d->table);
	d->table = new;
	}

// print entire contents of hashtable, invoked via SIGINFO
mDNSlocal void PrintLeaseTable(DaemonInfo *d)
	{
	int i;
	RRTableElem *ptr;
	char rrbuf[80], addrbuf[16];
	struct timeval now;
	int hr, min, sec;

	if (gettimeofday(&now, NULL)) { LogErr("PrintTable", "gettimeofday"); return; }
	if (pthread_mutex_lock(&d->tablelock)) { LogErr("PrintTable", "pthread_mutex_lock"); return; }
	
	Log("Dumping Lease Table Contents (table contains %d resource records)", d->nelems);
	for (i = 0; i < d->nbuckets; i++)
		{
		for (ptr = d->table[i]; ptr; ptr = ptr->next)
			{
			hr = ((ptr->expire - now.tv_sec) / 60) / 60;
			min = ((ptr->expire - now.tv_sec) / 60) % 60;
			sec = (ptr->expire - now.tv_sec) % 60;
			Log("Update from %s, Expires in %d:%d:%d\n\t%s", inet_ntop(AF_INET, &ptr->cli.sin_addr, addrbuf, 16), hr, min, sec,
				GetRRDisplayString_rdb(&ptr->rr.resrec, &ptr->rr.resrec.rdata->u, rrbuf));
			}
		}
	pthread_mutex_unlock(&d->tablelock);
	}

//
// Startup SRV Registration Routines 
// Register _dns-update._udp/_tcp.<zone> SRV records indicating the port on which
// the daemon accepts requests  
//

// delete all RRS of a given name/type
mDNSlocal mDNSu8 *putRRSetDeletion(DNSMessage *msg, mDNSu8 *ptr, mDNSu8 *limit,  ResourceRecord *rr)
	{
	ptr = putDomainNameAsLabels(msg, ptr, limit, rr->name);
	if (!ptr || ptr + 10 >= limit) return NULL;  // out of space
	ptr[0] = (mDNSu8)(rr->rrtype  >> 8);
	ptr[1] = (mDNSu8)(rr->rrtype  &  0xFF);
	ptr[2] = (mDNSu8)((mDNSu16)kDNSQClass_ANY >> 8);
	ptr[3] = (mDNSu8)((mDNSu16)kDNSQClass_ANY &  0xFF);
	bzero(ptr+4, sizeof(rr->rroriginalttl) + sizeof(rr->rdlength)); // zero ttl/rdata
	msg->h.mDNS_numUpdates++;
	return ptr + 10;
	}

mDNSlocal mDNSu8 *PutUpdateSRV(DaemonInfo *d, PktMsg *pkt, mDNSu8 *ptr, char *regtype, mDNSBool registration)
	{
	AuthRecord rr;
	char hostname[1024], buf[80];
	mDNSu8 *end = (mDNSu8 *)&pkt->msg + sizeof(DNSMessage);
	
	mDNS_SetupResourceRecord(&rr, NULL, 0, kDNSType_SRV, SRV_TTL, kDNSRecordTypeUnique, NULL, NULL);
	rr.resrec.rrclass = kDNSClass_IN;
	rr.resrec.rdata->u.srv.priority = 0;
	rr.resrec.rdata->u.srv.weight = 0;
	rr.resrec.rdata->u.srv.port.NotAnInteger = d->port.NotAnInteger;
	if (!gethostname(hostname, 1024) < 0 || MakeDomainNameFromDNSNameString(&rr.resrec.rdata->u.srv.target, hostname))
		rr.resrec.rdata->u.srv.target.c[0] = '\0';
	
	MakeDomainNameFromDNSNameString(rr.resrec.name, regtype);
	AppendDomainName(rr.resrec.name, &d->zone);
	VLog("%s  %s", registration ? "Registering SRV record" : "Deleting existing RRSet",
		 GetRRDisplayString_rdb(&rr.resrec, &rr.resrec.rdata->u, buf));
	if (registration) ptr = PutResourceRecord(&pkt->msg, ptr, &pkt->msg.h.mDNS_numUpdates, &rr.resrec);
	else              ptr = putRRSetDeletion(&pkt->msg, ptr, end, &rr.resrec);
	return ptr;
	}


// perform dynamic update.
// specify deletion by passing false for the register parameter, otherwise register the records.
mDNSlocal int UpdateSRV(DaemonInfo *d, mDNSBool registration)
	{
	int sd = -1;
	mDNSOpaque16 id;
	PktMsg pkt;
	mDNSu8 *ptr = pkt.msg.data;
	mDNSu8 *end = (mDNSu8 *)&pkt.msg + sizeof(DNSMessage);
	mDNSu16 nAdditHBO;  // num additionas, in host byte order, required by message digest routine
	PktMsg *reply = NULL;

	int result = -1;	

	// Initialize message
	id.NotAnInteger = 0;
	InitializeDNSMessage(&pkt.msg.h, id, UpdateReqFlags);
	pkt.src.sin_addr.s_addr = htonl(INADDR_ANY); // address field set solely for verbose logging in subroutines
	pkt.src.sin_family = AF_INET;
	
	// format message body
	ptr = putZone(&pkt.msg, ptr, end, &d->zone, mDNSOpaque16fromIntVal(kDNSClass_IN));
	if (!ptr) goto end;

	ptr = PutUpdateSRV(d, &pkt, ptr, "_dns-update._udp.", registration); if (!ptr) goto end;
	ptr = PutUpdateSRV(d, &pkt, ptr, "_dns-update._tcp.", registration); if (!ptr) goto end;
	ptr = PutUpdateSRV(d, &pkt, ptr, "_dns-llq._udp.", registration);    if (!ptr) goto end;	
	
	nAdditHBO = pkt.msg.h.numAdditionals;
	HdrHToN(&pkt);
	if (d->AuthInfo)
		{
		ptr = DNSDigest_SignMessage(&pkt.msg, &ptr, &nAdditHBO, d->AuthInfo);
		if (!ptr) goto end;
		}
	pkt.len = ptr - (mDNSu8 *)&pkt.msg;
	
	// send message, receive reply
	sd = ConnectToServer(d);
	if (sd < 0) { Log("UpdateSRV: ConnectToServer failed"); goto end; }  
	if (SendTCPMsg(sd, &pkt)) { Log("UpdateSRV: SendTCPMsg failed"); }
	reply = ReadTCPMsg(sd, NULL);
	if (!SuccessfulUpdateTransaction(&pkt, reply))
		Log("SRV record registration failed with rcode %d", reply->msg.h.flags.b[1] & kDNSFlag1_RC);
	else result = 0;
	
	end:
	if (!ptr) { Log("UpdateSRV: Error constructing lease expiration update"); }
	if (sd >= 0) close(sd);	
	if (reply) free(reply);
	return result;
   	}

// wrapper routines/macros
#define ClearUpdateSRV(d) UpdateSRV(d, 0)

// clear any existing records prior to registration
mDNSlocal int SetUpdateSRV(DaemonInfo *d)
	{
	int err;

	err = ClearUpdateSRV(d);         // clear any existing record
	if (!err) err = UpdateSRV(d, 1);
	return err;
	}

//
// Argument Parsing and Configuration
//

// read authentication information for a zone from command line argument
// global optind corresponds to keyname argument on entry
mDNSlocal int ReadAuthKey(int argc, char *argv[], DaemonInfo *d)
	{
	uDNS_AuthInfo *auth = NULL;
	unsigned char keybuf[512];
	mDNSs32 keylen;
	
	auth = malloc(sizeof(*auth));
	if (!auth) { perror("ReadAuthKey, malloc");  goto error; }
	auth->next = NULL;
	if (argc < optind + 1) return -1;  // keyname + secret 
	if (!MakeDomainNameFromDNSNameString(&auth->keyname, optarg))
		{ fprintf(stderr, "Bad key name %s", optarg); goto error; }
	keylen = DNSDigest_Base64ToBin(argv[optind++], keybuf, 512);
	if (keylen < 0)
		{ fprintf(stderr, "Bad shared secret %s (must be base-64 encoded string)", argv[optind-1]); goto error; }
	DNSDigest_ConstructHMACKey(auth, keybuf, (mDNSu32)keylen);
	d->AuthInfo = auth;
	return 0;

	error:
	if (auth) free(auth);
	return -1;	
	}

mDNSlocal int SetPort(DaemonInfo *d, char *PortAsString)
	{
	long l;

	l = strtol(PortAsString, NULL, 10);                    // convert string to long
	if ((!l && errno == EINVAL) || l > 65535) return -1;   // error check conversion
	d->port.NotAnInteger = htons((mDNSu16)l);              // set to network byte order
	return 0;
	}
	
mDNSlocal void PrintUsage(void)
	{
	fprintf(stderr, "Usage: dnsextd -z <zone> [-vf] [ -s server ] [-k keyname secret] ...\n"
			"Use \"dnsextd -h\" for help\n");
	}

mDNSlocal void PrintHelp(void)
	{
	fprintf(stderr, "\n\n");
	PrintUsage();

	fprintf(stderr, 
			"dnsextd is a daemon that implements DNS extensions supporting Dynamic DNS Update Leases\n"
            "and Long Lived Queries, used in Wide-Area DNS Service Discovery, on behalf of name servers\n"
			"that do not natively support these extensions.  (See dns-sd.org for more info on DNS Service\n"
			"Discovery, Update Leases, and Long Lived Queries.)\n\n"

            "dnsextd requires one argument,the zone, which is the domain for which Update Leases\n"
            "and Long Lived Queries are to be administered.  dnsextd communicates directly with the\n"
			"primary master server for this zone.\n\n"

			"The options are as follows:\n\n"

			"-f    Run daemon in foreground.\n\n"

			"-h    Print help.\n\n"

			"-k    Specify TSIG authentication key for dynamic updates from daemon to name server.\n"
			"      -k option is followed by the name of the key, and the shared secret as a base-64\n"
            "      encoded string.  This key/secret are used by the daemon to delete resource records\n"
            "      from the server when leases expire.  Clients are responsible for signing their\n"
            "      update requests.\n\n"
			
			"-s    Specify address (IPv4 address in dotted-decimal notation) of the Primary Master\n"
			"      name server.  Defaults to loopback (127.0.0.1), i.e. daemon and name server\n"
			"      running on the same machine.\n\n"

			"-v    Verbose output.\n\n"
		);		   
	}

// Note: ProcessArgs called before process is daemonized, and therefore must open no descriptors
// returns 0 (success) if program is to continue execution
// output control arguments (-f, -v) do not affect this routine
mDNSlocal int ProcessArgs(int argc, char *argv[], DaemonInfo *d)
	{
	int opt;

	if (argc < 2) goto arg_error;

	d->port.NotAnInteger = htons(DAEMON_PORT);  // default, may be overriden by command option
	while ((opt = getopt(argc, argv, "z:p:hfvs:k:")) != -1)
		{
		switch(opt)
			{
			case 'p': if (SetPort(d, optarg) < 0) goto arg_error;
        			  break;

			case 'h': PrintHelp();    return -1;
			case 'f': foreground = 1; break;
			case 'v': verbose = 1;    break;
			case 's': if (!inet_pton(AF_INET, optarg, &d->saddr)) goto arg_error;
				      break;
			case 'k': if (ReadAuthKey(argc, argv, d) < 0) goto arg_error;
				      break;
			case 'z': if (!MakeDomainNameFromDNSNameString(&d->zone, optarg))
				          {
						  fprintf(stderr, "Bad zone %s", optarg);
						  goto arg_error;
						  }
 				      break;
			default:  goto arg_error;				
			}
		}
		
	if (!d->zone.c[0]) goto arg_error;  // zone is the only required argument
	if (d->AuthInfo) AssignDomainName(&d->AuthInfo->zone, &d->zone); // if we have a shared secret, use it for the entire zone
	return 0;
	
	arg_error:
	PrintUsage();
	return -1;
	}


//
// Initialization Routines
//

// Allocate memory, initialize locks and bookkeeping variables
mDNSlocal int InitLeaseTable(DaemonInfo *d)
	{
	if (pthread_mutex_init(&d->tablelock, NULL)) { LogErr("InitLeaseTable", "pthread_mutex_init"); return -1; }
	d->nbuckets = LEASETABLE_INIT_NBUCKETS;
	d->nelems = 0;
	d->table = malloc(sizeof(RRTableElem *) * LEASETABLE_INIT_NBUCKETS);
	if (!d->table) { LogErr("InitLeaseTable", "malloc"); return -1; }
	bzero(d->table, sizeof(RRTableElem *) * LEASETABLE_INIT_NBUCKETS);
	return 0;
	}
mDNSlocal int SetupSockets(DaemonInfo *daemon)
	{
	struct sockaddr_in daddr;
	int sockpair[2];
	
	// set up sockets on which we receive requests
	bzero(&daddr, sizeof(daddr));
	daddr.sin_family = AF_INET;
	daddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (daemon->port.NotAnInteger) daddr.sin_port = daemon->port.NotAnInteger;
	else                           daddr.sin_port = htons(DAEMON_PORT);
	
	daemon->tcpsd = socket(AF_INET, SOCK_STREAM, 0);
	if (!daemon->tcpsd) { LogErr("SetupSockets", "socket");  return -1; }
	if (bind(daemon->tcpsd, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) { LogErr("SetupSockets", "bind"); return -1; }
	if (listen(daemon->tcpsd, LISTENQ) < 0) { LogErr("SetupSockets", "listen"); return -1; }

	daemon->udpsd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!daemon->udpsd) { LogErr("SetupSockets", "socket");  return -1; }
	if (bind(daemon->udpsd, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) { LogErr("SetupSockets", "bind"); return -1; }

	// set up Unix domain socket pair for LLQ polling thread to signal main thread that a change to the zone occurred
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sockpair) < 0) { LogErr("SetupSockets", "socketpair"); return -1; }
	daemon->LLQEventListenSock = sockpair[0];
	daemon->LLQServPollSock = sockpair[1];
	return 0;
	}

//
// periodic table updates
//

// Delete a resource record from the nameserver via a dynamic update
mDNSlocal void DeleteRecord(DaemonInfo *d, CacheRecord *rr, domainname *zone)
	{
	int sd = -1;
	mDNSOpaque16 id;
	PktMsg pkt;
	mDNSu8 *ptr = pkt.msg.data;
	mDNSu8 *end = (mDNSu8 *)&pkt.msg + sizeof(DNSMessage);
	mDNSu16 nAdditHBO;  // num additionas, in host byte order, required by message digest routine
	char buf[80];
	PktMsg *reply = NULL;
	
	VLog("Expiring record %s", GetRRDisplayString_rdb(&rr->resrec, &rr->resrec.rdata->u, buf));	
	sd = ConnectToServer(d);
	if (sd < 0) { Log("DeleteRecord: ConnectToServer failed"); goto end; }
	
	id.NotAnInteger = 0;
	InitializeDNSMessage(&pkt.msg.h, id, UpdateReqFlags);
	
	ptr = putZone(&pkt.msg, ptr, end, zone, mDNSOpaque16fromIntVal(rr->resrec.rrclass));
	if (!ptr) goto end;
	ptr = putDeletionRecord(&pkt.msg, ptr, &rr->resrec);
	if (!ptr) goto end;

	nAdditHBO = pkt.msg.h.numAdditionals;
	HdrHToN(&pkt);

	if (d->AuthInfo)
		{
		ptr = DNSDigest_SignMessage(&pkt.msg, &ptr, &nAdditHBO, d->AuthInfo);
		if (!ptr) goto end;
		}

	pkt.len = ptr - (mDNSu8 *)&pkt.msg;
	pkt.src.sin_addr.s_addr = htonl(INADDR_ANY); // address field set solely for verbose logging in subroutines
	pkt.src.sin_family = AF_INET;
	if (SendTCPMsg(sd, &pkt)) { Log("DeleteRecord: SendTCPMsg failed"); }
	reply = ReadTCPMsg(sd, NULL);
	if (!SuccessfulUpdateTransaction(&pkt, reply))
		Log("Expiration update failed with rcode %d", reply->msg.h.flags.b[1] & kDNSFlag1_RC);
					  
	end:
	if (!ptr) { Log("DeleteRecord: Error constructing lease expiration update"); }
	if (sd >= 0) close(sd);	
	if (reply) free(reply);
	}

// iterate over table, deleting expired records
mDNSlocal void DeleteExpiredRecords(DaemonInfo *d)
	{
	int i;
	RRTableElem *ptr, *prev, *fptr;	
	struct timeval now;

	if (gettimeofday(&now, NULL)) { LogErr("DeleteExpiredRecords ", "gettimeofday"); return; }
	if (pthread_mutex_lock(&d->tablelock)) { LogErr("DeleteExpiredRecords", "pthread_mutex_lock"); return; }
	for (i = 0; i < d->nbuckets; i++)
		{
		ptr = d->table[i];
		prev = NULL;
		while (ptr)
			{
			if (ptr->expire - now.tv_sec < 0)
				{
				// delete record from server
				DeleteRecord(d, &ptr->rr, &ptr->zone);
				if (prev) prev->next = ptr->next;
				else d->table[i] = ptr->next;
				fptr = ptr;
				ptr = ptr->next;
				free(fptr);
				d->nelems--;
				}
			else
				{
				prev = ptr;
				ptr = ptr->next;
				}
			}
		}
	pthread_mutex_unlock(&d->tablelock);
	}

//
// main update request handling
//

// Add, delete, or refresh records in table based on contents of a successfully completed dynamic update
mDNSlocal void UpdateLeaseTable(PktMsg *pkt, DaemonInfo *d, mDNSs32 lease)
	{
	RRTableElem **rptr, *tmp;
	int i, allocsize, bucket;
	LargeCacheRecord lcr;
	ResourceRecord *rr = &lcr.r.resrec;
	const mDNSu8 *ptr, *end;
	struct timeval time;
	DNSQuestion zone;
	char buf[80];
	
	if (pthread_mutex_lock(&d->tablelock)) { LogErr("UpdateLeaseTable", "pthread_mutex_lock"); return; }
	HdrNToH(pkt);
	ptr = pkt->msg.data;
	end = (mDNSu8 *)&pkt->msg + pkt->len;
	ptr = getQuestion(&pkt->msg, ptr, end, 0, &zone);
	if (!ptr) { Log("UpdateLeaseTable: cannot read zone");  goto cleanup; }
	ptr = LocateAuthorities(&pkt->msg, end);
	if (!ptr) { Log("UpdateLeaseTable: Format error");  goto cleanup; }
	
	for (i = 0; i < pkt->msg.h.mDNS_numUpdates; i++)
		{
		mDNSBool DeleteAllRRSets = mDNSfalse, DeleteOneRRSet = mDNSfalse, DeleteOneRR = mDNSfalse;
		
		ptr = GetLargeResourceRecord(NULL, &pkt->msg, ptr, end, 0, kDNSRecordTypePacketAns, &lcr);
		if (!ptr) { Log("UpdateLeaseTable: GetLargeResourceRecord returned NULL"); goto cleanup; }
		bucket = rr->namehash % d->nbuckets;
		rptr = &d->table[bucket];

		// handle deletions		
		if (rr->rrtype == kDNSQType_ANY && !rr->rroriginalttl && rr->rrclass == kDNSQClass_ANY && !rr->rdlength)
			DeleteAllRRSets = mDNStrue; // delete all rrsets for a name
		else if (!rr->rroriginalttl && rr->rrclass == kDNSQClass_ANY && !rr->rdlength)
			DeleteOneRRSet = mDNStrue;
		else if (!rr->rroriginalttl && rr->rrclass == kDNSClass_NONE)
			DeleteOneRR = mDNStrue;

		if (DeleteAllRRSets || DeleteOneRRSet || DeleteOneRR)
			{
			while (*rptr)
			  {
			  if (SameDomainName((*rptr)->rr.resrec.name, rr->name) &&
				 (DeleteAllRRSets ||
				 (DeleteOneRRSet && (*rptr)->rr.resrec.rrtype == rr->rrtype) ||
				  (DeleteOneRR && SameResourceRecord(&(*rptr)->rr.resrec, rr))))
				  {
				  tmp = *rptr;
				  VLog("Received deletion update for %s", GetRRDisplayString_rdb(&tmp->rr.resrec, &tmp->rr.resrec.rdata->u, buf));
				  *rptr = (*rptr)->next;
				  free(tmp);
				  d->nelems--;
				  }
			  else rptr = &(*rptr)->next;
			  }
			}
		else if (lease > 0)
			{
			// see if add or refresh
			while (*rptr && !SameResourceRecord(&(*rptr)->rr.resrec, rr)) rptr = &(*rptr)->next;
			if (*rptr)
				{
				// refresh
				if (gettimeofday(&time, NULL)) { LogErr("UpdateLeaseTable", "gettimeofday"); goto cleanup; }
				(*rptr)->expire = time.tv_sec + (unsigned)lease;
				VLog("Refreshing lease for %s", GetRRDisplayString_rdb(&lcr.r.resrec, &lcr.r.resrec.rdata->u, buf));					
				}
			else
				{
				// New record - add to table
				if (d->nelems > d->nbuckets)
					{
					RehashTable(d);
					bucket = rr->namehash % d->nbuckets;
					rptr = &d->table[bucket];
					}
				if (gettimeofday(&time, NULL)) { LogErr("UpdateLeaseTable", "gettimeofday"); goto cleanup; }
				allocsize = sizeof(RRTableElem);
				if (rr->rdlength > InlineCacheRDSize) allocsize += (rr->rdlength - InlineCacheRDSize);
				tmp = malloc(allocsize);
				if (!tmp) { LogErr("UpdateLeaseTable", "malloc"); goto cleanup; }
				memcpy(&tmp->rr, &lcr.r, sizeof(CacheRecord) + rr->rdlength - InlineCacheRDSize);
				tmp->rr.resrec.rdata = (RData *)&tmp->rr.rdatastorage;
				AssignDomainName(&tmp->name, rr->name);
				tmp->rr.resrec.name = &tmp->name;
				tmp->expire = time.tv_sec + (unsigned)lease;
				tmp->cli.sin_addr = pkt->src.sin_addr;
				AssignDomainName(&tmp->zone, &zone.qname);
				tmp->next = d->table[bucket];
				d->table[bucket] = tmp;
				d->nelems++;
				VLog("Adding update for %s to lease table", GetRRDisplayString_rdb(&lcr.r.resrec, &lcr.r.resrec.rdata->u, buf));
				}
			}
		}
					
	cleanup:
	pthread_mutex_unlock(&d->tablelock);
	HdrHToN(pkt);
	}

// Given a successful reply from a server, create a new reply that contains lease information
// Replies are currently not signed !!!KRS change this
mDNSlocal PktMsg *FormatLeaseReply(DaemonInfo *d, PktMsg *orig, mDNSu32 lease)
	{
	PktMsg *reply;
	mDNSu8 *ptr, *end;
	mDNSOpaque16 flags;

	(void)d;  //unused
	reply = malloc(sizeof(*reply));
	if (!reply) { LogErr("FormatLeaseReply", "malloc"); return NULL; }
	flags.b[0] = kDNSFlag0_QR_Response | kDNSFlag0_OP_Update;
	flags.b[1] = 0;
 
	InitializeDNSMessage(&reply->msg.h, orig->msg.h.id, flags);
	reply->src.sin_addr.s_addr = htonl(INADDR_ANY);            // unused except for log messages
	reply->src.sin_family = AF_INET;
	ptr = reply->msg.data;
	end = (mDNSu8 *)&reply->msg + sizeof(DNSMessage);
	ptr = putUpdateLease(&reply->msg, ptr, lease);
	if (!ptr) { Log("FormatLeaseReply: putUpdateLease failed"); free(reply); return NULL; }				   
	reply->len = ptr - (mDNSu8 *)&reply->msg;
	return reply;
	}

// pkt is thread-local, not requiring locking
mDNSlocal PktMsg *HandleRequest(PktMsg *pkt, DaemonInfo *d)
	{
	int sd = -1;
	PktMsg *reply = NULL, *LeaseReply;
	mDNSs32 lease;
	char buf[32];
	
	// send msg to server, read reply
	sd = ConnectToServer(d);
	if (sd < 0)
		{ Log("Discarding request from %s due to connection errors", inet_ntop(AF_INET, &pkt->src.sin_addr, buf, 32)); goto cleanup; }
	if (SendTCPMsg(sd, pkt) < 0)
		{ Log("Couldn't relay message from %s to server.  Discarding.", inet_ntop(AF_INET, &pkt->src.sin_addr, buf, 32)); goto cleanup; }
	reply = ReadTCPMsg(sd, NULL);
	
	// process reply
	if (!SuccessfulUpdateTransaction(pkt, reply))
		{ VLog("Message from %s not a successful update.", inet_ntop(AF_INET, &pkt->src.sin_addr, buf, 32));  goto cleanup; }	
	lease = GetPktLease(pkt);
	UpdateLeaseTable(pkt, d, lease);
	if (lease > 0)
		{
		LeaseReply = FormatLeaseReply(d, reply, lease);
		if (!LeaseReply) Log("HandleRequest - unable to format lease reply");
		free(reply); 
		reply = LeaseReply;
		}
	cleanup:
	if (sd >= 0) close(sd);
	return reply;
	}


//
// LLQ Support Routines
//

// Set fields of an LLQ Opt Resource Record
mDNSlocal void FormatLLQOpt(AuthRecord *opt, int opcode, mDNSu8 *id, mDNSs32 lease)
	{
	bzero(opt, sizeof(*opt));
	mDNS_SetupResourceRecord(opt, mDNSNULL, mDNSInterface_Any, kDNSType_OPT, kStandardTTL, kDNSRecordTypeKnownUnique, mDNSNULL, mDNSNULL);
	opt->resrec.rdlength = LLQ_OPT_SIZE;
	opt->resrec.rdestimate = LLQ_OPT_SIZE;
	opt->resrec.rdata->u.opt.opt = kDNSOpt_LLQ;
	opt->resrec.rdata->u.opt.optlen = sizeof(LLQOptData);
	opt->resrec.rdata->u.opt.OptData.llq.vers = kLLQ_Vers;
	opt->resrec.rdata->u.opt.OptData.llq.llqOp = opcode;
	opt->resrec.rdata->u.opt.OptData.llq.err = LLQErr_NoError;
	memcpy(opt->resrec.rdata->u.opt.OptData.llq.id, id, 8);
	opt->resrec.rdata->u.opt.OptData.llq.lease = lease;
	}

// Calculate effective remaining lease of an LLQ
mDNSlocal mDNSu32 LLQLease(LLQEntry *e)
	{
	struct timeval t;
	
	gettimeofday(&t, NULL);
	if (e->expire < t.tv_sec) return 0;
	else return e->expire - t.tv_sec;
	}

mDNSlocal void DeleteLLQ(DaemonInfo *d, LLQEntry *e)
	{
	int  bucket = DomainNameHashValue(&e->qname) % LLQ_TABLESIZE;
	LLQEntry **ptr = &d->LLQTable[bucket];
	AnswerListElem *a = e->AnswerList;
	char addr[32];
	
	inet_ntop(AF_INET, &e->cli.sin_addr, addr, 32);
	VLog("Deleting LLQ table entry for %##s client %s", e->qname.c, addr);

	// free shared answer structure if ref count drops to zero
	if (a && !(--a->refcount))
		{
		CacheRecord *cr = a->KnownAnswers, *tmp;
		AnswerListElem **tbl = &d->AnswerTable[bucket];

		while (cr)
			{
			tmp = cr;
			cr = cr->next;
			free(tmp);
			}

		while (*tbl && *tbl != a) tbl = &(*tbl)->next;
		if (*tbl) { *tbl = (*tbl)->next; free(a); }
		else Log("Error: DeleteLLQ - AnswerList not found in table");
		}

	// remove LLQ from table, free memory
	while(*ptr && *ptr != e) ptr = &(*ptr)->next;
	if (!*ptr) { Log("Error: DeleteLLQ - LLQ not in table"); return; }
	*ptr = (*ptr)->next;
	free(e);	
	}

mDNSlocal int SendLLQ(DaemonInfo *d, PktMsg *pkt, struct sockaddr_in dst)
	{
	char addr[32];
	int err = -1;

	HdrHToN(pkt);
	if (sendto(d->udpsd, &pkt->msg, pkt->len, 0, (struct sockaddr *)&dst, sizeof(dst)) != (int)pkt->len)
		{
		LogErr("DaemonInfo", "sendto");
		Log("Could not send response to client %s", inet_ntop(AF_INET, &dst.sin_addr, addr, 32));
		}
	else err = 0;
	HdrNToH(pkt);
	return err;
	}

// if non-negative, sd is a TCP socket connected to the nameserver
// otherwise, this routine creates and closes its own socket
mDNSlocal CacheRecord *AnswerQuestion(DaemonInfo *d, AnswerListElem *e, int sd)
	{
	PktMsg q;
	int i;
	const mDNSu8 *ansptr;
	mDNSu8 *end = q.msg.data;
	mDNSOpaque16 id, flags = QueryFlags;
	PktMsg *reply = NULL;
	LargeCacheRecord lcr;
	CacheRecord *AnswerList = NULL;
	mDNSu8 rcode;
	mDNSBool CloseSDOnExit = sd < 0;
	
	VLog("Querying server for %##s type %d", e->name.c, e->type);
	
	flags.b[0] |= kDNSFlag0_RD;  // recursion desired
	id.NotAnInteger = 0;
	InitializeDNSMessage(&q.msg.h, id, flags);
	
	end = putQuestion(&q.msg, end, end + AbsoluteMaxDNSMessageData, &e->name, e->type, kDNSClass_IN);
	if (!end) { Log("Error: AnswerQuestion - putQuestion returned NULL"); goto end; }
	q.len = (int)(end - (mDNSu8 *)&q.msg);
	
	if (sd < 0) sd = ConnectToServer(d);
	if (sd < 0) { Log("AnswerQuestion: ConnectToServer failed"); goto end; }
	if (SendTCPMsg(sd, &q)) { Log("AnswerQuestion: SendTCPMsg failed"); close(sd); goto end; }
	reply = ReadTCPMsg(sd, NULL);

	if ((reply->msg.h.flags.b[0] & kDNSFlag0_QROP_Mask) != (kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery))
		{ Log("AnswerQuestion: %##s type %d - Invalid response flags from server"); goto end; }
	rcode = (mDNSu8)(reply->msg.h.flags.b[1] & kDNSFlag1_RC);
	if (rcode && rcode != kDNSFlag1_RC_NXDomain) { Log("AnswerQuestion: %##s type %d - non-zero rcode %d from server", e->name.c, e->type, rcode); goto end; }

	end = (mDNSu8 *)&reply->msg + reply->len;
	ansptr = LocateAnswers(&reply->msg, end);
	if (!ansptr) { Log("Error: AnswerQuestion - LocateAnswers returned NULL"); goto end; }

	for (i = 0; i < reply->msg.h.numAnswers; i++)
		{
		ansptr = GetLargeResourceRecord(NULL, &reply->msg, ansptr, end, 0, kDNSRecordTypePacketAns, &lcr);
		if (!ansptr) { Log("AnswerQuestions: GetLargeResourceRecord returned NULL"); goto end; }
		if (lcr.r.resrec.rrtype != e->type || lcr.r.resrec.rrclass != kDNSClass_IN || !SameDomainName(lcr.r.resrec.name, &e->name))
			{
			Log("AnswerQuestion: response %##s type #d does not answer question %##s type #d.  Discarding",
				  lcr.r.resrec.name->c, lcr.r.resrec.rrtype, e->name.c, e->type);
			}
		else
			{
			CacheRecord *cr = CopyCacheRecord(&lcr.r, &e->name);
			if (!cr) { Log("Error: AnswerQuestion - CopyCacheRecord returned NULL"); goto end; }						   
			cr->next = AnswerList;
			AnswerList = cr;
			}
		}
	
	end:
	if (sd > -1 && CloseSDOnExit) close(sd);
	if (reply) free(reply);
	return AnswerList;
	}

// Routine sets EventList to contain Add/Remove events, and deletes any removes from the KnownAnswer list
mDNSlocal void UpdateAnswerList(DaemonInfo *d, AnswerListElem *a, int sd)
	{
	CacheRecord *cr, *NewAnswers, **na, **ka; // "new answer", "known answer"

	// get up to date answers
	NewAnswers = AnswerQuestion(d, a, sd);
	
	// first pass - mark all answers for deletion
	for (ka = &a->KnownAnswers; *ka; ka = &(*ka)->next)
		(*ka)->resrec.rroriginalttl = (unsigned)-1; // -1 means delete

	// second pass - mark answers pre-existent
	for (ka = &a->KnownAnswers; *ka; ka = &(*ka)->next)
		{
		for (na = &NewAnswers; *na; na = &(*na)->next)
			{
			if (SameResourceRecord(&(*ka)->resrec, &(*na)->resrec))
				{ (*ka)->resrec.rroriginalttl = 0; break; } // 0 means no change
			}
		}

	// third pass - add new records to Event list
	na = &NewAnswers;
	while (*na)		
		{
		for (ka = &a->KnownAnswers; *ka; ka = &(*ka)->next)
			if (SameResourceRecord(&(*ka)->resrec, &(*na)->resrec)) break;
		if (!*ka)
			{
			// answer is not in list - splice from NewAnswers list, add to Event list
			cr = *na;
			*na = (*na)->next;        // splice from list
			cr->next = a->EventList;  // add spliced record to event list
			a->EventList = cr;
			cr->resrec.rroriginalttl = 1; // 1 means add
			}
		else na = &(*na)->next;
		}
	
	// move all the removes from the answer list to the event list	
	ka = &a->KnownAnswers;
	while (*ka) 
		{
		if ((*ka)->resrec.rroriginalttl == (unsigned)-1)
			{
			cr = *ka;
			*ka = (*ka)->next;
			cr->next = a->EventList;
			a->EventList = cr;
			}
		else ka = &(*ka)->next;
		}
	
	// lastly, free the remaining records (known answers) in NewAnswers list
	while (NewAnswers)
		{
		cr = NewAnswers;
		NewAnswers = NewAnswers->next;
		free(cr);
		}  	
	}

mDNSlocal void SendEvents(DaemonInfo *d, LLQEntry *e)
	{
	PktMsg  response;
	CacheRecord *cr;
	mDNSu8 *end = (mDNSu8 *)&response.msg.data;
	mDNSOpaque16 msgID;
	char rrbuf[80], addrbuf[32];
	AuthRecord opt;
	
	msgID.NotAnInteger = random();
	if (verbose) inet_ntop(AF_INET, &e->cli.sin_addr, addrbuf, 32);
	InitializeDNSMessage(&response.msg.h, msgID, ResponseFlags);
	end = putQuestion(&response.msg, end, end + AbsoluteMaxDNSMessageData, &e->qname, e->qtype, kDNSClass_IN);
	if (!end) { Log("Error: SendEvents - putQuestion returned NULL"); return; }
	
	// put adds/removes in packet
	for (cr = e->AnswerList->EventList; cr; cr = cr->next)
		{
		if (verbose) GetRRDisplayString_rdb(&cr->resrec, &cr->resrec.rdata->u, rrbuf);
		VLog("%s (%s): %s", addrbuf, (mDNSs32)cr->resrec.rroriginalttl < 0 ? "Remove": "Add", rrbuf);				 
		end = PutResourceRecordTTLJumbo(&response.msg, end, &response.msg.h.numAnswers, &cr->resrec, cr->resrec.rroriginalttl);
		if (!end) { Log("Error: SendEvents - UpdateAnswerList returned NULL"); return; }
		}
			   
	FormatLLQOpt(&opt, kLLQOp_Event, e->id, LLQLease(e));
	end = PutResourceRecordTTLJumbo(&response.msg, end, &response.msg.h.numAdditionals, &opt.resrec, 0);
	if (!end) { Log("Error: SendEvents - PutResourceRecordTTLJumbo"); return; }

	response.len = (int)(end - (mDNSu8 *)&response.msg);
	if (SendLLQ(d, &response, e->cli) < 0) LogMsg("Error: SendEvents - SendLLQ");		
	}

mDNSlocal void PrintLLQTable(DaemonInfo *d)
	{
	LLQEntry *e;
	char addr[32];
	int i;
	
	Log("Printing LLQ table contents");

	for (i = 0; i < LLQ_TABLESIZE; i++)
		{
		e = d->LLQTable[i];
		while(e)
			{
			inet_ntop(AF_INET, &e->cli.sin_addr, addr, 32);
			Log("LLQ from %##s type %d lease %d (%d remaining)",
				addr, e->qname.c, e->qtype, e->lease, LLQLease(e));
			e = e->next;
			}
		}
	}

// Send events to clients as a result of a change in the zone
mDNSlocal void GenLLQEvents(DaemonInfo *d)
	{
	LLQEntry **e;
	int i, sd;
	struct timeval t;

	VLog("Generating LLQ Events");

	gettimeofday(&t, NULL);
	sd = ConnectToServer(d);
	if (sd < 0) { Log("GenLLQEvents: ConnectToServer failed"); return; }

	// get all answers up to date
	for (i = 0; i < LLQ_TABLESIZE; i++)
		{
		AnswerListElem *a = d->AnswerTable[i];
		while(a)
			{
			UpdateAnswerList(d, a, sd);
			a = a->next;
			}
		}

    // for each established LLQ, send events
	for (i = 0; i < LLQ_TABLESIZE; i++)
		{
		e = &d->LLQTable[i];
		while(*e)
			{
			if ((*e)->expire < t.tv_sec) DeleteLLQ(d, *e);
			else
				{
				if ((*e)->state == Established && (*e)->AnswerList->EventList) SendEvents(d, *e);
				e = &(*e)->next;
				}
			}
		}
	
	// now that all LLQs are updated, we move Add events from the Event list to the Known Answer list, and free Removes
	for (i = 0; i < LLQ_TABLESIZE; i++)
		{
		AnswerListElem *a = d->AnswerTable[i];
		while(a)
			{
			if (a->EventList)
				{
				CacheRecord *cr = a->EventList, *tmp;
				while (cr)
					{
					tmp = cr;
					cr = cr->next;
					if ((signed)tmp->resrec.rroriginalttl < 0) free(tmp);
					else
						{
						tmp->next = a->KnownAnswers;
						a->KnownAnswers = tmp;	
						tmp->resrec.rroriginalttl = 0;
						}
					}
				a->EventList = NULL;
				}
			a = a->next;
			}
		}	
		
	close(sd);
	}

// Monitor zone for changes that may produce LLQ events
mDNSlocal void *LLQEventMonitor(void *DInfoPtr)
	{
	DaemonInfo *d = DInfoPtr;
	PktMsg q;
	mDNSu8 *end = q.msg.data;
	const mDNSu8 *ptr;
	mDNSOpaque16 id, flags = QueryFlags;
	PktMsg reply;
	mDNSs32 serial = 0;
	mDNSBool SerialInitialized = mDNSfalse;
	int sd;
    LargeCacheRecord lcr;
	ResourceRecord *rr = &lcr.r.resrec;
	int i, sleeptime = 0;
	domainname zone;
	char pingmsg[4];
	
	// create question
	id.NotAnInteger = 0;
	InitializeDNSMessage(&q.msg.h, id, flags);
	AssignDomainName(&zone, &d->zone);
	end = putQuestion(&q.msg, end, end + AbsoluteMaxDNSMessageData, &zone, kDNSType_SOA, kDNSClass_IN);
	if (!end) { Log("Error: LLQEventMonitor - putQuestion returned NULL"); return NULL; }
	q.len = (int)(end - (mDNSu8 *)&q.msg);

	sd = ConnectToServer(d);
	if (sd < 0) { Log("LLQEventMonitor: ConnectToServer failed"); return NULL; }

	while(1)
		{
		usleep(sleeptime);
		sleeptime = LLQ_MONITOR_ERR_INTERVAL;  // if we bail on error below, rate limit retry
		
		// send message, receive response
		if (SendTCPMsg(sd, &q)) { Log("LLQEventMonitor: SendTCPMsg failed"); continue; }
		if (!ReadTCPMsg(sd, &reply)) { Log("LLQEventMonitor: ReadTCPMsg failed"); continue; }
		end = (mDNSu8 *)&reply.msg + reply.len;
		if (reply.msg.h.flags.b[1] & kDNSFlag1_RC) { Log("LLQEventMonitor - received non-zero rcode"); continue; }

		// find answer
		ptr = LocateAnswers(&reply.msg, end);
		if (!ptr) { Log("Error: LLQEventMonitor - LocateAnswers returned NULL"); continue; }
		for (i = 0; i < reply.msg.h.numAnswers; i++)
			{
			ptr = GetLargeResourceRecord(NULL, &reply.msg, ptr, end, 0, kDNSRecordTypePacketAns, &lcr);
			if (!ptr) { Log("Error: LLQEventMonitor - GetLargeResourceRecord  returned NULL"); continue; }
			if (rr->rrtype != kDNSType_SOA || rr->rrclass != kDNSClass_IN || !SameDomainName(rr->name, &zone)) continue;
			if (!SerialInitialized)
				{
				// first time through loop
				SerialInitialized = mDNStrue;
				serial = rr->rdata->u.soa.serial;
				sleeptime = LLQ_MONITOR_INTERVAL;
				break;
				}
			else if (rr->rdata->u.soa.serial != serial)
				{
				// update serial, wake main thread
				serial = rr->rdata->u.soa.serial;
				VLog("LLQEventMonitor: zone changed. Signaling main thread.");
				if (send(d->LLQServPollSock, pingmsg, sizeof(pingmsg), 0) != sizeof(pingmsg))
					{ LogErr("LLQEventMonitor", "send"); break; }
				}
			sleeptime = LLQ_MONITOR_INTERVAL;
			break;			
			}
		if (!ptr) Log("LLQEventMonitor: response to query did not contain SOA");
		}
	}

mDNSlocal void SetAnswerList(DaemonInfo *d, LLQEntry *e)
	{
	int bucket = DomainNameHashValue(&e->qname) % LLQ_TABLESIZE;
	AnswerListElem *a = d->AnswerTable[bucket];
	while (a && (a->type != e->qtype ||!SameDomainName(&a->name, &e->qname))) a = a->next;
	if (!a)
		{
		a = malloc(sizeof(*a));
		if (!a) { LogErr("SetAnswerList", "malloc"); return; }
		AssignDomainName(&a->name, &e->qname);
		a->type = e->qtype;
		a->refcount = 0;
		a->KnownAnswers = NULL;
		a->EventList = NULL;
		a->next = d->AnswerTable[bucket];
		d->AnswerTable[bucket] = a;

		// to get initial answer list, call UpdateAnswerList and move cache records from EventList to KnownAnswers
		UpdateAnswerList(d, a, -1);
		a->KnownAnswers = a->EventList;
		a->EventList = NULL;
		}
	
	e->AnswerList = a;
	a->refcount ++;
	}
	
 // Allocate LLQ entry, insert into table
mDNSlocal LLQEntry *NewLLQ(DaemonInfo *d, struct sockaddr_in cli, domainname *qname, mDNSu16 qtype, mDNSu32 lease)
	{
	char addr[32];
	struct timeval t;
	int bucket = DomainNameHashValue(qname) % LLQ_TABLESIZE;
   	LLQEntry *e;

	e = malloc(sizeof(*e));
	if (!e) { LogErr("NewLLQ", "malloc"); return NULL; }

	inet_ntop(AF_INET, &cli.sin_addr, addr, 32);
	VLog("Allocating LLQ entry for client %s question %##s type %d", addr, qname->c, qtype);
	
	// initialize structure
	e->cli = cli;
	AssignDomainName(&e->qname, qname);
	e->qtype = qtype;
	memset(e->id, 0, 8);
	e->state = RequestReceived;
	e->AnswerList = NULL;
	
	if (lease < LLQ_MIN_LEASE) lease = LLQ_MIN_LEASE;
	else if (lease > LLQ_MAX_LEASE) lease = LLQ_MIN_LEASE;
	gettimeofday(&t, NULL);
	e->expire = t.tv_sec + (int)lease;
	e->lease = lease;
	
	// add to table
	e->next = d->LLQTable[bucket];
	d->LLQTable[bucket] = e;
	
	return e;
	}

// Handle a refresh request from client
mDNSlocal void LLQRefresh(DaemonInfo *d, LLQEntry *e, LLQOptData *llq, mDNSOpaque16 msgID)
	{
	AuthRecord opt;
	PktMsg ack;
	mDNSu8 *end = (mDNSu8 *)&ack.msg.data;
	char addr[32];

	inet_ntop(AF_INET, &e->cli.sin_addr, addr, 32);
	VLog("%s LLQ for %##s from %s", llq->lease ? "Refreshing" : "Deleting", e->qname.c, addr);
	
	if (llq->lease)
		{
		if (llq->lease < LLQ_MIN_LEASE) llq->lease = LLQ_MIN_LEASE;
		else if (llq->lease > LLQ_MAX_LEASE) llq->lease = LLQ_MIN_LEASE;
		}
	
	ack.src.sin_addr.s_addr = 0; // unused 
	InitializeDNSMessage(&ack.msg.h, msgID, ResponseFlags);
	end = putQuestion(&ack.msg, end, end + AbsoluteMaxDNSMessageData, &e->qname, e->qtype, kDNSClass_IN);
	if (!end) { Log("Error: putQuestion"); return; }

	FormatLLQOpt(&opt, kLLQOp_Refresh, e->id, llq->lease ? LLQLease(e) : 0);
	end = PutResourceRecordTTLJumbo(&ack.msg, end, &ack.msg.h.numAdditionals, &opt.resrec, 0);
	if (!end) { Log("Error: PutResourceRecordTTLJumbo"); return; }

	ack.len = (int)(end - (mDNSu8 *)&ack.msg);
	if (SendLLQ(d, &ack, e->cli)) Log("Error: LLQRefresh"); 

	if (llq->lease) e->state = Established;
	else DeleteLLQ(d, e);	
	}

// Complete handshake with Ack an initial answers
mDNSlocal void LLQCompleteHandshake(DaemonInfo *d, LLQEntry *e, LLQOptData *llq, mDNSOpaque16 msgID)
	{
	char addr[32];
	CacheRecord *ptr;
	AuthRecord opt;
	PktMsg ack;
	mDNSu8 *end = (mDNSu8 *)&ack.msg.data;
	char rrbuf[80], addrbuf[32];
	
	inet_ntop(AF_INET, &e->cli.sin_addr, addr, 32);

	if (memcmp(llq->id, e->id, 8)           ||
		llq->vers  != kLLQ_Vers             ||
		llq->llqOp != kLLQOp_Setup          ||
		llq->err   != LLQErr_NoError        ||
		llq->lease > e->lease + LLQ_LEASE_FUDGE ||
		llq->lease < e->lease - LLQ_LEASE_FUDGE)
		{ Log("Incorrect challenge response from %s", addr); return; }

	if (e->state == Established) VLog("Retransmitting LLQ ack + answers for %##s", e->qname.c);
	else                         VLog("Delivering LLQ ack + answers for %##s", e->qname.c);  
	
	// format ack + answers
	ack.src.sin_addr.s_addr = 0; // unused 
	InitializeDNSMessage(&ack.msg.h, msgID, ResponseFlags);
	end = putQuestion(&ack.msg, end, end + AbsoluteMaxDNSMessageData, &e->qname, e->qtype, kDNSClass_IN);
	if (!end) { Log("Error: putQuestion"); return; }
	
	if (e->state != Established) { SetAnswerList(d, e); e->state = Established; }
	
	if (verbose) inet_ntop(AF_INET, &e->cli.sin_addr, addrbuf, 32);
	for (ptr = e->AnswerList->KnownAnswers; ptr; ptr = ptr->next)
		{
		if (verbose) GetRRDisplayString_rdb(&ptr->resrec, &ptr->resrec.rdata->u, rrbuf);
		VLog("%s Intitial Answer - %s", addr, rrbuf);
		end = PutResourceRecordTTLJumbo(&ack.msg, end, &ack.msg.h.numAnswers, &ptr->resrec, 1);
		if (!end) { Log("Error: PutResourceRecordTTLJumbo"); return; }
		}

	FormatLLQOpt(&opt, kLLQOp_Setup, e->id, LLQLease(e));
	end = PutResourceRecordTTLJumbo(&ack.msg, end, &ack.msg.h.numAdditionals, &opt.resrec, 0);
	if (!end) { Log("Error: PutResourceRecordTTLJumbo"); return; }

	ack.len = (int)(end - (mDNSu8 *)&ack.msg);
	if (SendLLQ(d, &ack, e->cli)) Log("Error: LLQCompleteHandshake");
	}

mDNSlocal void LLQSetupChallenge(DaemonInfo *d, LLQEntry *e, LLQOptData *llq, mDNSOpaque16 msgID)
	{
	struct timeval t;
	mDNSu32 randval;
	PktMsg challenge;
	mDNSu8 *end = challenge.msg.data;
	AuthRecord opt;

	if (e->state == ChallengeSent) VLog("Retransmitting LLQ setup challenge for %##s", e->qname.c);
	else                           VLog("Sending LLQ setup challenge for %##s", e->qname.c);
	
	if (!ZERO_LLQID(llq->id)) { Log("Error: LLQSetupChallenge - nonzero ID"); return; } // server bug
	if (llq->llqOp != kLLQOp_Setup) { Log("LLQSetupChallenge - incorrrect operation from client"); return; } // client error
	
	if (ZERO_LLQID(e->id)) // don't regenerate random ID for retransmissions
		{
		// construct ID <time><random>
		gettimeofday(&t, NULL);
		randval = random();
		memcpy(e->id, &t.tv_sec, sizeof(t.tv_sec));
		memcpy(e->id + sizeof(t.tv_sec), &randval, sizeof(randval));			   
		}

	// format response (query + LLQ opt rr)
	challenge.src.sin_addr.s_addr = 0; // unused 
	InitializeDNSMessage(&challenge.msg.h, msgID, ResponseFlags);
	end = putQuestion(&challenge.msg, end, end + AbsoluteMaxDNSMessageData, &e->qname, e->qtype, kDNSClass_IN);
	if (!end) { Log("Error: putQuestion"); return; }	
	FormatLLQOpt(&opt, kLLQOp_Setup, e->id, LLQLease(e));
	end = PutResourceRecordTTLJumbo(&challenge.msg, end, &challenge.msg.h.numAdditionals, &opt.resrec, 0);
	if (!end) { Log("Error: PutResourceRecordTTLJumbo"); return; }
	challenge.len = (int)(end - (mDNSu8 *)&challenge.msg);
	if (SendLLQ(d, &challenge, e->cli)) { Log("Error: LLQSetupChallenge"); return; }
	e->state = ChallengeSent;
	}

// Take action on an LLQ message from client.  Entry must be initialized and in table
mDNSlocal void UpdateLLQ(DaemonInfo *d, LLQEntry *e, LLQOptData *llq, mDNSOpaque16 msgID)
	{
	switch(e->state)
		{
		case RequestReceived:
			LLQSetupChallenge(d, e, llq, msgID);
			return;
		case ChallengeSent:
			if (ZERO_LLQID(llq->id)) LLQSetupChallenge(d, e, llq, msgID); // challenge sent and lost
			else LLQCompleteHandshake(d, e, llq, msgID);
			return;
		case Established:
			if (ZERO_LLQID(llq->id))
				{
				// client started over.  reset state.
				LLQEntry *newe = NewLLQ(d, e->cli, &e->qname, e->qtype, llq->lease);
				if (!newe) return;
				DeleteLLQ(d, e);
				LLQSetupChallenge(d, newe, llq, msgID);
				return;
				}
			else if (llq->llqOp == kLLQOp_Setup)
				{ LLQCompleteHandshake(d, e, llq, msgID); return; } // Ack lost				
			else if (llq->llqOp == kLLQOp_Refresh)
				{ LLQRefresh(d, e, llq, msgID); return; }
			else { Log("Unhandled message for established LLQ"); return; }
		}	
	}

mDNSlocal LLQEntry *LookupLLQ(DaemonInfo *d, struct sockaddr_in cli, domainname *qname, mDNSu16 qtype, mDNSu8 *id)
	{	
	int bucket = bucket = DomainNameHashValue(qname) % LLQ_TABLESIZE;
	LLQEntry *ptr = d->LLQTable[bucket];

	while(ptr)
		{
		if (((ptr->state == ChallengeSent && ZERO_LLQID(id)) || // zero-id due to packet loss OK in state ChallengeSent
			 !memcmp(id, ptr->id, 8)) &&                        // id match
			SAME_INADDR(cli, ptr->cli) && qtype == ptr->qtype && SameDomainName(&ptr->qname, qname)) // same source, type, qname
			return ptr;
		ptr = ptr->next;
		}
	return NULL;
	}

mDNSlocal int RecvLLQ(DaemonInfo *d, PktMsg *pkt)
	{
	DNSQuestion q;
	LargeCacheRecord opt;
	int i, err = -1;
	char addr[32];
	const mDNSu8 *qptr = pkt->msg.data;
    const mDNSu8 *end = (mDNSu8 *)&pkt->msg + pkt->len;
	const mDNSu8 *aptr = LocateAdditionals(&pkt->msg, end);
	LLQOptData *llq = NULL;
	LLQEntry *e = NULL;
	
	HdrNToH(pkt);	
	inet_ntop(AF_INET, &pkt->src.sin_addr, addr, 32);

	VLog("Received LLQ msg from %s", addr);
	// sanity-check packet
	if (!pkt->msg.h.numQuestions || !pkt->msg.h.numAdditionals)
		{
		Log("Malformatted LLQ from %s with %d questions, %d additionals", addr, pkt->msg.h.numQuestions, pkt->msg.h.numAdditionals);			
		goto end;
		}

	// find the OPT RR - must be last in message
	for (i = 0; i < pkt->msg.h.numAdditionals; i++)
		{
		aptr = GetLargeResourceRecord(NULL, &pkt->msg, aptr, end, 0, kDNSRecordTypePacketAdd, &opt); 
		if (!aptr) { Log("Malformatted LLQ from %s: could not get Additional record %d", addr, i); goto end; }
		}

	// validate OPT
	if (opt.r.resrec.rrtype != kDNSType_OPT) { Log("Malformatted LLQ from %s: last Additional not an Opt RR", addr); goto end; }
	if (opt.r.resrec.rdlength < pkt->msg.h.numQuestions * LLQ_OPT_SIZE) { Log("Malformatted LLQ from %s: Opt RR to small (%d bytes for %d questions)", addr, opt.r.resrec.rdlength, pkt->msg.h.numQuestions); }
	
	// dispatch each question
	for (i = 0; i < pkt->msg.h.numQuestions; i++)
		{
		qptr = getQuestion(&pkt->msg, qptr, end, 0, &q);
		if (!qptr) { Log("Malformatted LLQ from %s: cannot read question %d", addr, i); goto end; }
		llq = (LLQOptData *)&opt.r.resrec.rdata->u.opt.OptData.llq + i; // point into OptData at index i
		if (llq->vers != kLLQ_Vers) { Log("LLQ from %s contains bad version %d (expected %d)", addr, llq->vers, kLLQ_Vers); goto end; }
		
		e = LookupLLQ(d, pkt->src, &q.qname, q.qtype, llq->id);
		if (!e)
			{
			// no entry - if zero ID, create new
			e = NewLLQ(d, pkt->src, &q.qname, q.qtype, llq->lease);
			if (!e) goto end;
			}
		UpdateLLQ(d, e, llq, pkt->msg.h.id);
		}
	err = 0;
	
	end:
	HdrHToN(pkt);
	return err;
	}

mDNSlocal mDNSBool IsLLQRequest(PktMsg *pkt)
	{
	const mDNSu8 *ptr = NULL, *end = (mDNSu8 *)&pkt->msg + pkt->len;
	LargeCacheRecord lcr;
	int i;
	mDNSBool result = mDNSfalse;
	
	HdrNToH(pkt);		
	if ((mDNSu8)(pkt->msg.h.flags.b[0] & kDNSFlag0_QROP_Mask) != (mDNSu8)(kDNSFlag0_QR_Query | kDNSFlag0_OP_StdQuery)) goto end;

	if (!pkt->msg.h.numAdditionals) goto end;
	ptr = LocateAdditionals(&pkt->msg, end);
	if (!ptr) goto end;

	// find last Additional
	for (i = 0; i < pkt->msg.h.numAdditionals; i++)
		{
		ptr = GetLargeResourceRecord(NULL, &pkt->msg, ptr, end, 0, kDNSRecordTypePacketAdd, &lcr);
		if (!ptr) { Log("Unable to read additional record"); goto end; }
		}
	
	if (lcr.r.resrec.rrtype == kDNSType_OPT &&
		lcr.r.resrec.rdlength >= LLQ_OPT_SIZE &&
		lcr.r.resrec.rdata->u.opt.opt == kDNSOpt_LLQ)
		{ result = mDNStrue; goto end; }

	end:
	HdrHToN(pkt);
	return result;
	}

// !!!KRS implement properly
mDNSlocal mDNSBool IsLLQAck(PktMsg *pkt)
	{
	if (pkt->msg.h.flags.NotAnInteger == ResponseFlags.NotAnInteger &&
		pkt->msg.h.numQuestions && !pkt->msg.h.numAnswers && !pkt->msg.h.numAuthorities) return mDNStrue;
	return mDNSfalse;
	}


// request handler wrappers for TCP and UDP requests
// (read message off socket, fork thread that invokes main processing routine and handles cleanup)
mDNSlocal void *UDPUpdateRequestForkFn(void *vptr)
	{
	char buf[32];
	UDPRequestArgs *req = vptr;
	PktMsg *reply = NULL;
	
	VLog("Received UDP request: %d bytes from %s", req->pkt.len, inet_ntop(AF_INET, &req->pkt.src.sin_addr, buf, 32));  
	//!!!KRS strictly speaking, we shouldn't use TCP for a UDP request because the server may give us a long answer that would require truncation for UDP delivery to client
	reply = HandleRequest(&req->pkt, req->d);
	if (reply)
		{
		if (sendto(req->d->udpsd, &reply->msg, reply->len, 0, (struct sockaddr *)&req->pkt.src, sizeof(req->pkt.src)) != (int)reply->len)
			LogErr("UDPUpdateRequestForkFn", "sendto");		
		}

	if (reply) free(reply);		
	free(req);
	pthread_exit(NULL);
	}

//!!!KRS this needs to be changed to use non-blocking sockets
mDNSlocal int RecvUDPRequest(int sd, DaemonInfo *d)
	{
	UDPRequestArgs *req;
	pthread_t tid;
	unsigned int clisize = sizeof(req->cliaddr);
	
	req = malloc(sizeof(UDPRequestArgs));
	if (!req) { LogErr("RecvUDPRequest", "malloc"); return -1; }
	bzero(req, sizeof(*req));
	req->d = d;
	req->pkt.len = recvfrom(sd, &req->pkt.msg, sizeof(req->pkt.msg), 0, (struct sockaddr *)&req->cliaddr, &clisize);
	if ((int)req->pkt.len < 0) { LogErr("RecvUDPRequest", "recvfrom"); free(req); return -1; }
	if (clisize != sizeof(req->cliaddr)) { Log("Client address of unknown size %d", clisize); free(req); return -1; }
	req->pkt.src = req->cliaddr;

	if (IsLLQRequest(&req->pkt))
		{
		// LLQ messages handled by main thread
		int err = RecvLLQ(d, &req->pkt);
		free(req);
		return err;
		}

	if (IsLLQAck(&req->pkt)) { free(req); return 0; } // !!!KRS need to do acks + retrans
	
	if (pthread_create(&tid, NULL, UDPUpdateRequestForkFn, req)) { LogErr("RecvUDPRequest", "pthread_create"); free(req); return -1; }
	pthread_detach(tid);
	return 0;
	}

mDNSlocal void *TCPRequestForkFn(void *vptr)
	{
	TCPRequestArgs *req = vptr;
	PktMsg *in = NULL, *out = NULL;
	char buf[32];
	
    //!!!KRS if this read blocks indefinitely, we can run out of threads
	// read the request
	in = ReadTCPMsg(req->sd, NULL);
	if (!in)
		{
		LogMsg("TCPRequestForkFn: Could not read message from %s", inet_ntop(AF_INET, &req->cliaddr.sin_addr, buf, 32));
		goto cleanup;
		}

	VLog("Received TCP request: %d bytes from %s", in->len, inet_ntop(AF_INET, &req->cliaddr.sin_addr, buf, 32));  	
	// create the reply
	out = HandleRequest(in, req->d);
	if (!out)
		{
		LogMsg("TCPRequestForkFn: No reply for client %s", inet_ntop(AF_INET, &req->cliaddr.sin_addr, buf, 32));
		goto cleanup;
		}

	// deliver reply to client
	if (SendTCPMsg(req->sd, out) < 0) 
		{
		LogMsg("TCPRequestForkFn: Unable to send reply to client %s", inet_ntop(AF_INET, &req->cliaddr.sin_addr, buf, 32));
		goto cleanup;
		}
		
	cleanup:
	free(req);
	if (in) free(in);
	if (out) free(out);
	pthread_exit(NULL);
	}

mDNSlocal int RecvTCPRequest(int sd, DaemonInfo *d)
	{
	TCPRequestArgs *req;
	pthread_t tid;
	unsigned int clilen = sizeof(req->cliaddr);
	
	req = malloc(sizeof(TCPRequestArgs));
	if (!req) { LogErr("RecvTCPRequest", "malloc"); return -1; }
	bzero(req, sizeof(*req));
	req->d = d;
	req->sd = accept(sd, (struct sockaddr *)&req->cliaddr, &clilen);
	if (req->sd < 0) { LogErr("RecvTCPRequest", "accept"); return -1; }	
	if (clilen != sizeof(req->cliaddr)) { Log("Client address of unknown size %d", clilen); free(req); return -1; }
	if (pthread_create(&tid, NULL, TCPRequestForkFn, req)) { LogErr("RecvTCPRequest", "pthread_create"); free(req); return -1; }
	pthread_detach(tid);
	return 0;
	}

// main event loop
// listen for incoming requests, periodically check table for expired records, respond to signals
mDNSlocal int ListenForUpdates(DaemonInfo *d)
	{
	int err;
	int maxfdp1;
	fd_set rset;
	struct timeval timenow, timeout = { 0, 0 };
	long NextTableCheck = 0;
	
   	VLog("Listening for requests...");

	FD_ZERO(&rset);
	maxfdp1 = d->tcpsd + 1;
	if (d->udpsd + 1 > maxfdp1) maxfdp1 = d->udpsd + 1;
	if (d->LLQEventListenSock + 1 > maxfdp1) maxfdp1 = d->LLQEventListenSock + 1;
	
	while(1)
		{
		// expire records if necessary, set timeout
		if (gettimeofday(&timenow, NULL)) { LogErr("ListenForUpdates", "gettimeofday"); return -1; }
		if (timenow.tv_sec >= NextTableCheck)
			{
			DeleteExpiredRecords(d);
			NextTableCheck = timenow.tv_sec + EXPIRATION_INTERVAL;
			}
		timeout.tv_sec = NextTableCheck - timenow.tv_sec;
		
		FD_SET(d->tcpsd, &rset);
		FD_SET(d->udpsd, &rset);
		FD_SET(d->LLQEventListenSock, &rset);
		
		err = select(maxfdp1, &rset, NULL, NULL, &timeout);		
		if (err < 0)
			{
			if (errno == EINTR)
				{
				if (terminate) { DeleteExpiredRecords(d); return 0; }
				else if (dumptable) { PrintLeaseTable(d); PrintLLQTable(d); dumptable = 0; }
				else Log("Received unhandled signal - continuing"); 
				}
			else { LogErr("ListenForUpdates", "select"); return -1; }
			}
		else
			{
			if (FD_ISSET(d->tcpsd, &rset)) RecvTCPRequest(d->tcpsd, d);
			if (FD_ISSET(d->udpsd, &rset)) RecvUDPRequest(d->udpsd, d); 
			if (FD_ISSET(d->LLQEventListenSock, &rset))
				{
				// clear signalling data off socket
				char buf[32];
				recv(d->LLQEventListenSock, buf, 32, 0);
				GenLLQEvents(d);
				}
			}
		}
	return 0;
	}

// signal handler sets global variables, which are inspected by main event loop
// (select automatically returns due to the handled signal)
mDNSlocal void HndlSignal(int sig)
	{
	if (sig == SIGTERM || sig == SIGINT ) { terminate = 1; return; }
	if (sig == INFO_SIGNAL)               { dumptable = 1; return; }
	}

int main(int argc, char *argv[])
	{
	pthread_t LLQtid;
	DaemonInfo *d;

	d = malloc(sizeof(*d));
	if (!d) { LogErr("main", "malloc"); exit(1); }
	bzero(d, sizeof(DaemonInfo));
	
	if (signal(SIGTERM,     HndlSignal) == SIG_ERR) perror("Can't catch SIGTERM");
	if (signal(INFO_SIGNAL, HndlSignal) == SIG_ERR) perror("Can't catch SIGINFO");
	if (signal(SIGINT,      HndlSignal) == SIG_ERR) perror("Can't catch SIGINT");
	if (signal(SIGPIPE,     SIG_IGN  )  == SIG_ERR) perror("Can't ignore SIGPIPE");
	
	if (ProcessArgs(argc, argv, d) < 0) exit(1);

	if (!foreground)
		{
		if (daemon(0,0))
			{
			LogErr("main", "daemon");
			fprintf(stderr, "Could not daemonize process, running in foreground");
			foreground = 1;
			}	
		}

	if (InitLeaseTable(d) < 0) exit(1);
	if (SetupSockets(d) < 0) exit(1); 
	if (SetUpdateSRV(d) < 0) exit(1);
	
	if (pthread_create(&LLQtid, NULL, LLQEventMonitor, d)) { LogErr("main", "pthread_create"); }	
	else
		{
		pthread_detach(LLQtid);
		ListenForUpdates(d);
		}
		
	if (ClearUpdateSRV(d) < 0) exit(1);  // clear update srv's even if ListenForUpdates or pthread_create returns an error
	free(d);
	exit(0);
 
	}
