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
Bug #: 3320722
Completed support for Unix-domain socket based API.

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
Bug #: <rdar://problem/3249292>: Feature: New Rendezvous APIs (#7875)
Reviewed by: Stuart Cheshire
Added files necessary to implement Unix domain sockets based enhanced
Rendezvous APIs, and integrated with existing Mach-port based daemon.

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
Bug #: <rdar://problem/3247035>: Service should be prefixed
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

#include "DNSServiceDiscoveryRequestServer.h"
#include "DNSServiceDiscoveryReply.h"

#include "mDNSClientAPI.h"			// Defines the interface to the client layer above
#include "mDNSMacOSX.h"				// Defines the specific types needed to run mDNS on this platform

#include <DNSServiceDiscovery/DNSServiceDiscovery.h>

#define ENABLE_UDS 1

//*************************************************************************************************************
// Macros

// Note: The C preprocessor stringify operator ('#') makes a string from its argument, without macro expansion
// e.g. If "version" is #define'd to be "4", then STRINGIFY_AWE(version) will return the string "version", not "4"
// To expand "version" to its value before making the string, use STRINGIFY(version) instead
#define STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s) #s 
#define STRINGIFY(s) STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s)

//*************************************************************************************************************
// Globals

mDNSexport mDNS mDNSStorage;
static mDNS_PlatformSupport PlatformStorage;
#define RR_CACHE_SIZE 64
static CacheRecord rrcachestorage[RR_CACHE_SIZE];
static const char PID_FILE[] = "/var/run/mDNSResponder.pid";

static const char kmDNSBootstrapName[] = "com.apple.mDNSResponderRestart";
static mach_port_t client_death_port = MACH_PORT_NULL;
static mach_port_t exit_m_port       = MACH_PORT_NULL;
static mach_port_t info_m_port       = MACH_PORT_NULL;
static mach_port_t server_priv_port  = MACH_PORT_NULL;

// mDNS Mach Message Timeout, in milliseconds.
// We need this to be short enough that we don't deadlock the mDNSResponder if a client
// fails to service its mach message queue, but long enough to give a well-written
// client a chance to service its mach message queue without getting cut off.
// Empirically, 50ms seems to work, so we set the timeout to 250ms to give
// even extra-slow clients a fair chance before we cut them off.
#define MDNS_MM_TIMEOUT 250

static int restarting_via_mach_init = 0;

#if MDNS_DEBUGMSGS
int debug_mode = 1;
#else
int debug_mode = 0;
#endif

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
	char name[256], type[256], dom[256];
	};

typedef struct DNSServiceBrowser_struct DNSServiceBrowser;
struct DNSServiceBrowser_struct
	{
	DNSServiceBrowser *next;
	mach_port_t ClientMachPort;
	DNSQuestion q;
	DNSServiceBrowserResult *results;
	mDNSs32 lastsuccess;
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

typedef struct DNSServiceRegistration_struct DNSServiceRegistration;
struct DNSServiceRegistration_struct
	{
	DNSServiceRegistration *next;
	mach_port_t ClientMachPort;
	mDNSBool autoname;
	mDNSBool autorename;
	domainlabel name;
	ServiceRecordSet s;
	// Don't add any fields after ServiceRecordSet.
	// This is where the implicit extra space goes if we allocate an oversized ServiceRecordSet object
	};

static DNSServiceDomainEnumeration *DNSServiceDomainEnumerationList = NULL;
static DNSServiceBrowser           *DNSServiceBrowserList           = NULL;
static DNSServiceResolver          *DNSServiceResolverList          = NULL;
static DNSServiceRegistration      *DNSServiceRegistrationList      = NULL;

//*************************************************************************************************************
// General Utility Functions

#if MACOSX_MDNS_MALLOC_DEBUGGING

char _malloc_options[] = "AXZ";

static void validatelists(mDNS *const m)
	{
	DNSServiceDomainEnumeration *e;
	DNSServiceBrowser           *b;
	DNSServiceResolver          *l;
	DNSServiceRegistration      *r;
	AuthRecord                  *rr;
	CacheRecord                 *cr;
	DNSQuestion                 *q;
	mDNSs32 slot;
	
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
		if (rr->RecordType == 0 || rr->RecordType == 0xFF)
			LogMsg("!!!! ResourceRecords list: %p is garbage (%X) !!!!", rr, rr->RecordType);

	for (rr = m->DuplicateRecords; rr; rr=rr->next)
		if (rr->RecordType == 0 || rr->RecordType == 0xFF)
			LogMsg("!!!! DuplicateRecords list: %p is garbage (%X) !!!!", rr, rr->RecordType);

	for (q = m->Questions; q; q=q->next)
		if (q->ThisQInterval == (mDNSs32)~0)
			LogMsg("!!!! Questions list: %p is garbage (%lX) !!!!", q, q->ThisQInterval);

	for (slot = 0; slot < CACHE_HASH_SLOTS; slot++)
		for (cr = mDNSStorage.rrcache_hash[slot]; cr; cr=cr->next)
			if (cr->RecordType == 0 || cr->RecordType == 0xFF)
				LogMsg("!!!! Cache slot %lu: %p is garbage (%X) !!!!", slot, rr, rr->RecordType);
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
		if (mem[1] > 8000)
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

mDNSlocal void FreeDNSServiceRegistration(DNSServiceRegistration *x)
	{
	while (x->s.Extras)
		{
		ExtraResourceRecord *extras = x->s.Extras;
		x->s.Extras = x->s.Extras->next;
		if (extras->r.resrec.rdata != &extras->r.rdatastorage)
			freeL("Extra RData", extras->r.resrec.rdata);
		freeL("ExtraResourceRecord", extras);
		}

	if (x->s.RR_TXT.resrec.rdata != &x->s.RR_TXT.rdatastorage)
			freeL("TXT RData", x->s.RR_TXT.resrec.rdata);

	if (x->s.SubTypes) freeL("ServiceSubTypes", x->s.SubTypes);
	
	freeL("DNSServiceRegistration", x);
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
		*b = (*b)->next;
		if (m && m != x)
			LogMsg("%5d: DNSServiceBrowser(%##s) STOP; WARNING m %p != x %p", ClientMachPort, x->q.qname.c, m, x);
		else LogOperation("%5d: DNSServiceBrowser(%##s) STOP", ClientMachPort, x->q.qname.c);
		mDNS_StopBrowse(&mDNSStorage, &x->q);
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
		DNSServiceRegistration *x = *r;
		*r = (*r)->next;
		x->autorename = mDNSfalse;
		if (m && m != x)
			LogMsg("%5d: DNSServiceRegistration(%##s) STOP; WARNING m %p != x %p", ClientMachPort, x->s.RR_SRV.resrec.name.c, m, x);
		else LogOperation("%5d: DNSServiceRegistration(%##s) STOP", ClientMachPort, x->s.RR_SRV.resrec.name.c);
		// If mDNS_DeregisterService() returns mStatus_NoError, that means that the service was found in the list,
		// is sending its goodbye packet, and we'll get an mStatus_MemFree message when we can free the memory.
		// If mDNS_DeregisterService() returns an error, it means that the service had already been removed from
		// the list, so we should go ahead and free the memory right now
		if (mDNS_DeregisterService(&mDNSStorage, &x->s) != mStatus_NoError)
			FreeDNSServiceRegistration(x);
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
	while (e && e->ClientMachPort != c) e = e->next;
	while (b && b->ClientMachPort != c) b = b->next;
	while (l && l->ClientMachPort != c) l = l->next;
	while (r && r->ClientMachPort != c) r = r->next;
	if      (e) LogMsg("%5d: DomainEnumeration(%##s) %s%s",                   c, e->dom.qname.c,            reason, msg);
	else if (b) LogMsg("%5d: Browser(%##s) %s%s",                             c, b->q.qname.c,              reason, msg);
	else if (l) LogMsg("%5d: Resolver(%##s) %s%s",                            c, l->i.name.c,               reason, msg);
	else if (r) LogMsg("%5d: Registration(%##s) %s%s",                        c, r->s.RR_SRV.resrec.name.c, reason, msg);
	else        LogMsg("%5d: (%s) %s, but no record of client can be found!", c,                            reason, msg);

	AbortClient(c, m);
	}

mDNSlocal mDNSBool CheckForExistingClient(mach_port_t c)
	{
	DNSServiceDomainEnumeration *e = DNSServiceDomainEnumerationList;
	DNSServiceBrowser           *b = DNSServiceBrowserList;
	DNSServiceResolver          *l = DNSServiceResolverList;
	DNSServiceRegistration      *r = DNSServiceRegistrationList;
	while (e && e->ClientMachPort != c) e = e->next;
	while (b && b->ClientMachPort != c) b = b->next;
	while (l && l->ClientMachPort != c) l = l->next;
	while (r && r->ClientMachPort != c) r = r->next;
	if (e) LogMsg("%5d: DomainEnumeration(%##s) already exists!", c, e->dom.qname.c);
	if (b) LogMsg("%5d: Browser(%##s) already exists!",           c, b->q.qname.c);
	if (l) LogMsg("%5d: Resolver(%##s) already exists!",          c, l->i.name.c);
	if (r) LogMsg("%5d: Registration(%##s) already exists!",      c, r->s.RR_SRV.resrec.name.c);
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
		mach_port_destroy( mach_task_self(), deathMessage->not_port );
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

mDNSlocal void FoundDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	kern_return_t status;
	#pragma unused(m)
	char buffer[256];
	DNSServiceDomainEnumerationReplyResultType rt;
	DNSServiceDomainEnumeration *x = (DNSServiceDomainEnumeration *)question->QuestionContext;

	debugf("FoundDomain: %##s PTR %##s", answer->name.c, answer->rdata->u.name.c);
	if (answer->rrtype != kDNSType_PTR) return;
	if (!x) { debugf("FoundDomain: DNSServiceDomainEnumeration is NULL"); return; }

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
	const DNSServiceDomainEnumerationReplyResultType rt = DNSServiceDomainEnumerationReplyAddDomainDefault;

	// Allocate memory, and handle failure
	DNSServiceDomainEnumeration *x = mallocL("DNSServiceDomainEnumeration", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->next = DNSServiceDomainEnumerationList;
	DNSServiceDomainEnumerationList = x;
	
	// Generate initial response
	verbosedebugf("%5d: Enumerate %s Domains", client, regDom ? "Registration" : "Browsing");
	// We always give local. as the initial default browse domain, and then look for more
	kern_return_t status = DNSServiceDomainEnumerationReply_rpc(x->ClientMachPort, rt, "local.", 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		{ AbortBlockedClient(x->ClientMachPort, "local enumeration", x); return(mStatus_UnknownErr); }

	// Do the operation
	err           = mDNS_GetDomains(&mDNSStorage, &x->dom, dt1, mDNSInterface_Any, FoundDomain, x);
	if (!err) err = mDNS_GetDomains(&mDNSStorage, &x->def, dt2, mDNSInterface_Any, FoundDomain, x);
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
			answer->name.c, answer->rdata->u.name.c);
		return;
		}

	DNSServiceBrowserResult *x = mallocL("DNSServiceBrowserResult", sizeof(*x));
	if (!x) { LogMsg("FoundInstance: Failed to allocate memory for result %##s", answer->rdata->u.name.c); return; }
	
	verbosedebugf("FoundInstance: %s %##s", AddRecord ? "Add" : "Rmv", answer->rdata->u.name.c);
	ConvertDomainLabelToCString_unescaped(&name, x->name);
	ConvertDomainNameToCString(&type, x->type);
	ConvertDomainNameToCString(&domain, x->dom);
	if (AddRecord)
		 x->resultType = DNSServiceBrowserReplyAddInstance;
	else x->resultType = DNSServiceBrowserReplyRemoveInstance;
	x->next = NULL;

	DNSServiceBrowser *browser = (DNSServiceBrowser *)question->QuestionContext;
	DNSServiceBrowserResult **p = &browser->results;
	while (*p) p = &(*p)->next;
	*p = x;
	}

mDNSexport kern_return_t provide_DNSServiceBrowserCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString regtype, DNSCString domain)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

	// Check other parameters
	domainname t, d;
	if (!regtype[0] || !MakeDomainNameFromDNSNameString(&t, regtype))      { errormsg = "Illegal regtype"; goto badparam; }
	if (!MakeDomainNameFromDNSNameString(&d, *domain ? domain : "local.")) { errormsg = "Illegal domain";  goto badparam; }

	// Allocate memory, and handle failure
	DNSServiceBrowser *x = mallocL("DNSServiceBrowser", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->results = NULL;
	x->lastsuccess = 0;
	x->next = DNSServiceBrowserList;
	DNSServiceBrowserList = x;

	// Do the operation
	LogOperation("%5d: DNSServiceBrowse(%##s%##s) START", client, t.c, d.c);
	err = mDNS_StartBrowse(&mDNSStorage, &x->q, &t, &d, mDNSInterface_Any, FoundInstance, x);
	if (err) { AbortClient(client, x); errormsg = "mDNS_StartBrowse"; goto fail; }

	// Succeeded: Wrap up and return
	EnableDeathNotificationForClient(client, x);
	return(mStatus_NoError);

badparam:
	err = mStatus_BadParamErr;
fail:
	LogMsg("%5d: DNSServiceBrowse(\"%s\", \"%s\") failed: %s (%ld)", client, regtype, domain, errormsg, err);
	return(err);
	}

//*************************************************************************************************************
// Resolve Service Info

mDNSlocal void FoundInstanceInfo(mDNS *const m, ServiceInfoQuery *query)
	{
	kern_return_t status;
	DNSServiceResolver *x = (DNSServiceResolver *)query->ServiceInfoQueryContext;
	NetworkInterfaceInfoOSX *ifx = (NetworkInterfaceInfoOSX *)query->info->InterfaceID;
	if (query->info->InterfaceID == (mDNSInterfaceID)~0) ifx = mDNSNULL;
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
	
	LogOperation("%5d: DNSServiceResolver(%##s) -> %#a:%d", x->ClientMachPort,
		x->i.name.c, &query->info->ip, (int)query->info->port.b[0] << 8 | query->info->port.b[1]);
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
	if (!MakeDomainNameFromDNSNameString(&d, *domain ? domain : "local.")) { errormsg = "Bad Domain";        goto badparam; }
	if (!ConstructServiceName(&srv, &n, &t, &d))                           { errormsg = "Bad Name";          goto badparam; }

	// Allocate memory, and handle failure
	DNSServiceResolver *x = mallocL("DNSServiceResolver", sizeof(*x));
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->i.InterfaceID = mDNSInterface_Any;
	x->i.name = srv;
	x->ReportTime = (mDNSPlatformTimeNow() + 130 * mDNSPlatformOneSecond) | 1;
	// Don't report errors for old iChat ("_ichat._tcp") service.
	// New iChat ("_presence._tcp") uses DNSServiceQueryRecord() (from /usr/include/dns_sd.h) instead,
	// and so should other applications that have valid reasons to be doing ongoing record monitoring.
	if (SameDomainLabel(t.c, (mDNSu8*)"\x6_ichat")) x->ReportTime = 0;
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

mDNSlocal void RegCallback(mDNS *const m, ServiceRecordSet *const sr, mStatus result)
	{
	DNSServiceRegistration *x = (DNSServiceRegistration*)sr->ServiceContext;

	if (result == mStatus_NoError)
		{
		kern_return_t status;
		LogOperation("%5d: DNSServiceRegistration(%##s) Name Registered", x->ClientMachPort, sr->RR_SRV.resrec.name.c);
		status = DNSServiceRegistrationReply_rpc(x->ClientMachPort, result, MDNS_MM_TIMEOUT);
		if (status == MACH_SEND_TIMED_OUT)
			AbortBlockedClient(x->ClientMachPort, "registration success", x);
		}

	else if (result == mStatus_NameConflict)
		{
		LogOperation("%5d: DNSServiceRegistration(%##s) Name Conflict", x->ClientMachPort, sr->RR_SRV.resrec.name.c);
		// Note: By the time we get the mStatus_NameConflict message, the service is already deregistered
		// and the memory is free, so we don't have to wait for an mStatus_MemFree message as well.
		if (x->autoname)
			mDNS_RenameAndReregisterService(m, sr, mDNSNULL);
		else
			{
			// If we get a name conflict, we tell the client about it, and then they are expected to dispose
			// of their registration in the usual way (which we will catch via client death notification).
			// If the Mach queue is full, we forcibly abort the client immediately.
			kern_return_t status = DNSServiceRegistrationReply_rpc(x->ClientMachPort, result, MDNS_MM_TIMEOUT);
			if (status == MACH_SEND_TIMED_OUT)
				AbortBlockedClient(x->ClientMachPort, "registration conflict", x);
			}
		}

	else if (result == mStatus_MemFree)
		{
		if (x->autorename)
			{
			debugf("RegCallback renaming %#s to %#s", x->name.c, mDNSStorage.nicelabel.c);
			x->autorename = mDNSfalse;
			x->name = mDNSStorage.nicelabel;
			mDNS_RenameAndReregisterService(m, &x->s, &x->name);
			}
		else
			{
			DNSServiceRegistration **r = &DNSServiceRegistrationList;
			while (*r && *r != x) r = &(*r)->next;
			if (*r)
				{
				LogMsg("RegCallback: %##s Still in DNSServiceRegistration list; removing now", sr->RR_SRV.resrec.name.c);
				*r = (*r)->next;
				}
			LogOperation("%5d: DNSServiceRegistration(%##s) Memory Free", x->ClientMachPort, sr->RR_SRV.resrec.name.c);
			FreeDNSServiceRegistration(x);
			}
		}
	
	else
		LogMsg("%5d: DNSServiceRegistration(%##s) Unknown Result %ld",
			x->ClientMachPort, sr->RR_SRV.resrec.name.c, result);
	}

mDNSlocal void CheckForDuplicateRegistrations(DNSServiceRegistration *x, domainname *srv, mDNSIPPort port)
	{
	int count = 1;			// Start with the one we're planning to register, then see if there are any more
	AuthRecord *rr;
	for (rr = mDNSStorage.ResourceRecords; rr; rr=rr->next)
		if (rr->resrec.rrtype == kDNSType_SRV &&
			rr->resrec.rdata->u.srv.port.NotAnInteger == port.NotAnInteger &&
			SameDomainName(&rr->resrec.name, srv))
			count++;

	if (count > 1)
		LogMsg("%5d: Client application registered %d identical instances of service %##s port %d.",
			x->ClientMachPort, count, srv->c, (int)port.b[0] << 8 | port.b[1]);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString name, DNSCString regtype, DNSCString domain, int notAnIntPort, DNSCString txtRecord)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	if (client == (mach_port_t)-1)      { err = mStatus_Invalid; errormsg = "Client id -1 invalid";     goto fail; }
	if (CheckForExistingClient(client)) { err = mStatus_Invalid; errormsg = "Client id already in use"; goto fail; }

	// Check for sub-types after the service type
	AuthRecord *SubTypes = mDNSNULL;
	mDNSu32 i, NumSubTypes = 0;
	char *comma = regtype;
	while (*comma && *comma != ',') comma++;
	if (*comma)					// If we found a comma...
		{
		*comma = 0;				// Overwrite the first comma with a nul
		char *p = comma + 1;	// Start scanning from the next character
		while (*p)
			{
			if ( !(*p && *p != ',')) { errormsg = "Bad Service SubType";  goto badparam; }
			while (*p && *p != ',') p++;
			if (*p) *p++ = 0;
			NumSubTypes++;
			}
		}

	// Check other parameters
	domainlabel n;
	domainname t, d;
	domainname srv;
	if (!name[0]) n = mDNSStorage.nicelabel;
	else if (!MakeDomainLabelFromLiteralString(&n, name))                  { errormsg = "Bad Instance Name"; goto badparam; }
	if (!regtype[0] || !MakeDomainNameFromDNSNameString(&t, regtype))      { errormsg = "Bad Service Type";  goto badparam; }
	if (!MakeDomainNameFromDNSNameString(&d, *domain ? domain : "local.")) { errormsg = "Bad Domain";        goto badparam; }
	if (!ConstructServiceName(&srv, &n, &t, &d))                           { errormsg = "Bad Name";          goto badparam; }

	mDNSIPPort port;
	port.NotAnInteger = notAnIntPort;

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

	// Allocate memory, and handle failure
	DNSServiceRegistration *x = mallocL("DNSServiceRegistration", sizeof(*x) - sizeof(RDataBody) + size);
	if (!x) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	if (NumSubTypes)
		{
		SubTypes = mallocL("ServiceSubTypes", NumSubTypes * sizeof(AuthRecord));
		if (!SubTypes) { freeL("DNSServiceRegistration", x); err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }
		for (i = 0; i < NumSubTypes; i++)
			{
			comma++;				// Advance over the nul character
			MakeDomainNameFromDNSNameString(&SubTypes[i].resrec.name, comma);
			while (*comma) comma++;	// Advance comma to point to the next terminating nul
			}
		}

	// Set up object, and link into list
	x->ClientMachPort = client;
	x->autoname = (!name[0]);
	x->autorename = mDNSfalse;
	x->name = n;
	x->next = DNSServiceRegistrationList;
	DNSServiceRegistrationList = x;

	// Do the operation
	LogOperation("%5d: DNSServiceRegistration(\"%s\", \"%s\", \"%s\") START", x->ClientMachPort, name, regtype, domain);
	// Some clients use mDNS for lightweight copy protection, registering a pseudo-service with
	// a port number of zero. When two instances of the protected client are allowed to run on one
	// machine, we don't want to see misleading "Bogus client" messages in syslog and the console.
	if (port.NotAnInteger) CheckForDuplicateRegistrations(x, &srv, port);

	err = mDNS_RegisterService(&mDNSStorage, &x->s,
		&x->name, &t, &d,		// Name, type, domain
		mDNSNULL, port,			// Host and port
		txtinfo, data_len,		// TXT data, length
		SubTypes, NumSubTypes,	// Subtypes
		mDNSInterface_Any,		// Interace ID
		RegCallback, x);		// Callback and context

	if (err) { AbortClient(client, x); errormsg = "mDNS_RegisterService"; goto fail; }

	// Succeeded: Wrap up and return
	EnableDeathNotificationForClient(client, x);
	return(mStatus_NoError);

badtxt:
	LogMsg("%5d: TXT record: %.100s...", client, txtRecord);
badparam:
	err = mStatus_BadParamErr;
fail:
	LogMsg("%5d: DNSServiceRegister(\"%s\", \"%s\", \"%s\", %d) failed: %s (%ld)",
		client, name, regtype, domain, notAnIntPort, errormsg, err);
	return(err);
	}
	
mDNSlocal void mDNS_StatusCallback(mDNS *const m, mStatus result)
	{
	(void)m; // Unused
	if (result == mStatus_ConfigChanged)
		{
		DNSServiceRegistration *r;
		for (r = DNSServiceRegistrationList; r; r=r->next)
			if (r->autoname && !SameDomainLabel(r->name.c, mDNSStorage.nicelabel.c))
				{
				debugf("NetworkChanged renaming %#s to %#s", r->name.c, mDNSStorage.nicelabel.c);
				r->autorename = mDNStrue;
				mDNS_DeregisterService(&mDNSStorage, &r->s);
				}
		}
	else if (result == mStatus_GrowCache)
		{
		// If we've run out of cache space, then double the total cache size and give the memory to mDNSCore
		mDNSu32 numrecords = m->rrcache_size;
		CacheRecord *storage = mallocL("mStatus_GrowCache", sizeof(CacheRecord) * numrecords);
		if (storage) mDNS_GrowCache(&mDNSStorage, storage, numrecords);
		}
	}

//*************************************************************************************************************
// Add / Update / Remove records from existing Registration

mDNSexport kern_return_t provide_DNSServiceRegistrationAddRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	int type, const char *data, mach_msg_type_number_t data_len, uint32_t ttl, natural_t *reference)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	domainname *name = (domainname *)"";
	if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }
	name = &x->s.RR_SRV.resrec.name;

	// Check other parameters
	if (data_len > 8192) { err = mStatus_BadParamErr; errormsg = "data_len > 8K"; goto fail; }
	unsigned int size = sizeof(RDataBody);
	if (size < data_len)
		size = data_len;
	
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
		client, x->s.RR_SRV.resrec.name.c, type, data_len, extra);
	err = mDNS_AddRecordToService(&mDNSStorage, &x->s, extra, &extra->r.rdatastorage, ttl);
	*reference = (natural_t)extra;
	if (err) { errormsg = "mDNS_AddRecordToService"; goto fail; }
	
	// Succeeded: Wrap up and return
	return(mStatus_NoError);
	
fail:
	LogMsg("%5d: DNSServiceRegistrationAddRecord(%##s, type %d, length %d) failed: %s (%ld)", client, name->c, type, data_len, errormsg, err);
	return(err);
	}

mDNSlocal void UpdateCallback(mDNS *const m, AuthRecord *const rr, RData *OldRData)
	{
	(void)m;		// Unused
	if (OldRData != &rr->rdatastorage)
		freeL("Old RData", OldRData);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationUpdateRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	natural_t reference, const char *data, mach_msg_type_number_t data_len, uint32_t ttl)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	domainname *name = (domainname *)"";
	if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }
	name = &x->s.RR_SRV.resrec.name;

	// Check other parameters
	if (data_len > 8192) { err = mStatus_BadParamErr; errormsg = "data_len > 8K"; goto fail; }
	unsigned int size = sizeof(RDataBody);
	if (size < data_len)
		size = data_len;

	// Find the record we're updating. NULL reference means update the primary TXT record
	AuthRecord *rr = &x->s.RR_TXT;
	if (reference)	// Scan our list to make sure we're updating a valid record that was previously added
		{
		ExtraResourceRecord *e = x->s.Extras;
		while (e && e != (ExtraResourceRecord*)reference) e = e->next;
		if (!e) { err = mStatus_BadReferenceErr; errormsg = "No such record"; goto fail; }
		rr = &e->r;
		}

	// Allocate memory, and handle failure
	RData *newrdata = mallocL("RData", sizeof(*newrdata) - sizeof(RDataBody) + size);
	if (!newrdata) { err = mStatus_NoMemoryErr; errormsg = "No memory"; goto fail; }

	// Fill in new length, and data
	newrdata->MaxRDLength = size;
	memcpy(&newrdata->u, data, data_len);
	
	// Do the operation
	LogOperation("%5d: DNSServiceRegistrationUpdateRecord(%##s, %X, new length %d)",
		client, x->s.RR_SRV.resrec.name.c, reference, data_len);
	err = mDNS_Update(&mDNSStorage, rr, ttl, data_len, newrdata, UpdateCallback);
	if (err) { errormsg = "mDNS_Update"; goto fail; }
	
	// Succeeded: Wrap up and return
	return(mStatus_NoError);

fail:
	LogMsg("%5d: DNSServiceRegistrationUpdateRecord(%##s, %X, %d) failed: %s (%ld)", client, name->c, reference, data_len, errormsg, err);
	return(err);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationRemoveRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	natural_t reference)
	{
	// Check client parameter
	(void)unusedserver;		// Unused
	mStatus err = mStatus_NoError;
	const char *errormsg = "Unknown";
	domainname *name = (domainname *)"";
	if (client == (mach_port_t)-1) { err = mStatus_Invalid;         errormsg = "Client id -1 invalid"; goto fail; }
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)                        { err = mStatus_BadReferenceErr; errormsg = "No such client";       goto fail; }
	name = &x->s.RR_SRV.resrec.name;

	// Do the operation
	LogOperation("%5d: DNSServiceRegistrationRemoveRecord(%##s, %X)", client, x->s.RR_SRV.resrec.name.c, reference);
	ExtraResourceRecord *extra = (ExtraResourceRecord*)reference;
	err = mDNS_RemoveRecordFromService(&mDNSStorage, &x->s, extra);
	if (err) { errormsg = "mDNS_RemoveRecordFromService (No such record)"; goto fail; }

	// Succeeded: Wrap up and return
	if (extra->r.resrec.rdata != &extra->r.rdatastorage)
		freeL("Extra RData", extra->r.resrec.rdata);
	freeL("ExtraResourceRecord", extra);
	return(mStatus_NoError);

fail:
	LogMsg("%5d: DNSServiceRegistrationRemoveRecord(%##s, %X) failed: %s (%ld)", client, name->c, reference, errormsg, err);
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
            /* Includes success case.  */
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

mDNSlocal void ExitCallback(CFMachPortRef port, void *msg, CFIndex size, void *info)
	{
	(void)port;		// Unused
	(void)msg;		// Unused
	(void)size;		// Unused
	(void)info;		// Unused
/*
	CacheRecord *rr;
	int rrcache_active = 0;
	for (rr = mDNSStorage.rrcache; rr; rr=rr->next) if (CacheRRActive(&mDNSStorage, rr)) rrcache_active++;
	debugf("ExitCallback: RR Cache now using %d records, %d active", mDNSStorage.rrcache_used, rrcache_active);
*/

	LogMsg("%s stopping", mDNSResponderVersionString);

	debugf("ExitCallback: destroyBootstrapService");
	if (!debug_mode)
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
#if ENABLE_UDS
	if (udsserver_exit() < 0) LogMsg("ExitCallback: udsserver_exit failed");
#endif
	exit(0);
	}

// Send a mach_msg to ourselves (since that is signal safe) telling us to cleanup and exit
mDNSlocal void HandleSIGTERM(int signal)
	{
	(void)signal;		// Unused
	debugf(" ");
	debugf("SIGINT/SIGTERM");
	mach_msg_header_t header;
	header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	header.msgh_remote_port = exit_m_port;
	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_size = sizeof(header);
	header.msgh_id = 0;
	if (mach_msg_send(&header) != MACH_MSG_SUCCESS)
		{ LogMsg("HandleSIGTERM: mach_msg_send failed; Exiting immediately."); exit(-1); }
	}

mDNSlocal void INFOCallback(CFMachPortRef port, void *msg, CFIndex size, void *info)
	{
	(void)port;		// Unused
	(void)msg;		// Unused
	(void)size;		// Unused
	(void)info;		// Unused
	DNSServiceDomainEnumeration *e;
	DNSServiceBrowser           *b;
	DNSServiceResolver          *l;
	DNSServiceRegistration      *r;
	mDNSs32 slot;
	CacheRecord *rr;
	mDNSu32 CacheUsed = 0, CacheActive = 0;

	LogMsg("%s ---- BEGIN STATE LOG ----", mDNSResponderVersionString);

	for (slot = 0; slot < CACHE_HASH_SLOTS; slot++)
		for (rr = mDNSStorage.rrcache_hash[slot]; rr; rr=rr->next)
			{
			CacheUsed++;
			if (rr->CRActiveQuestion) CacheActive++;
			LogMsg("%s %-5s%-6s%s", rr->CRActiveQuestion ? "Active:  " : "Inactive:", DNSTypeName(rr->resrec.rrtype),
				((NetworkInterfaceInfoOSX *)rr->resrec.InterfaceID)->ifa_name, GetRRDisplayString(&mDNSStorage, rr));
			usleep(1000);	// Limit rate a little so we don't flood syslog too fast
			}
	if (mDNSStorage.rrcache_totalused != CacheUsed)
		LogMsg("Cache use mismatch: rrcache_totalused is %lu, true count %lu", mDNSStorage.rrcache_totalused, CacheUsed);
	if (mDNSStorage.rrcache_active != CacheActive)
		LogMsg("Cache use mismatch: rrcache_active is %lu, true count %lu", mDNSStorage.rrcache_active, CacheActive);
	LogMsg("Cache currently contains %lu records; %lu referenced by active questions", CacheUsed, CacheActive);

	for (e = DNSServiceDomainEnumerationList; e; e=e->next)
		LogMsg("%5d: DomainEnumeration   %##s", e->ClientMachPort, e->dom.qname.c);

	for (b = DNSServiceBrowserList; b; b=b->next)
		LogMsg("%5d: ServiceBrowse       %##s", b->ClientMachPort, b->q.qname.c);

	for (l = DNSServiceResolverList; l; l=l->next)
		LogMsg("%5d: ServiceResolve      %##s", l->ClientMachPort, l->i.name.c);

	for (r = DNSServiceRegistrationList; r; r=r->next)
		LogMsg("%5d: ServiceRegistration %##s", r->ClientMachPort, r->s.RR_SRV.resrec.name.c);

	udsserver_info();

	LogMsg("%s ----  END STATE LOG  ----", mDNSResponderVersionString);
	}

mDNSlocal void HandleSIGINFO(int signal)
	{
	(void)signal;		// Unused
	mach_msg_header_t header;
	header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	header.msgh_remote_port = info_m_port;
	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_size = sizeof(header);
	header.msgh_id = 0;
	if (mach_msg_send(&header) != MACH_MSG_SUCCESS)
		LogMsg("HandleSIGINFO: mach_msg_send failed; No state log will be generated.");
	}

mDNSlocal kern_return_t mDNSDaemonInitialize(void)
	{
	mStatus            err;
	CFMachPortRef      d_port = CFMachPortCreate(NULL, ClientDeathCallback, NULL, NULL);
	CFMachPortRef      s_port = CFMachPortCreate(NULL, DNSserverCallback, NULL, NULL);
	CFMachPortRef      e_port = CFMachPortCreate(NULL, ExitCallback, NULL, NULL);
	CFMachPortRef      i_port = CFMachPortCreate(NULL, INFOCallback, NULL, NULL);
	mach_port_t        m_port = CFMachPortGetPort(s_port);
	char *MachServerName = mDNSMacOSXSystemBuildNumber(NULL) < 7 ? "DNSServiceDiscoveryServer" : "com.apple.mDNSResponder";
	kern_return_t      status = bootstrap_register(bootstrap_port, MachServerName, m_port);
	CFRunLoopSourceRef d_rls  = CFMachPortCreateRunLoopSource(NULL, d_port, 0);
	CFRunLoopSourceRef s_rls  = CFMachPortCreateRunLoopSource(NULL, s_port, 0);
	CFRunLoopSourceRef e_rls  = CFMachPortCreateRunLoopSource(NULL, e_port, 0);
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

	client_death_port = CFMachPortGetPort(d_port);
	exit_m_port = CFMachPortGetPort(e_port);
	info_m_port = CFMachPortGetPort(i_port);

	CFRunLoopAddSource(CFRunLoopGetCurrent(), d_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), s_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), e_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), i_rls, kCFRunLoopDefaultMode);
	CFRelease(d_rls);
	CFRelease(s_rls);
	CFRelease(e_rls);
	CFRelease(i_rls);
	if (debug_mode) printf("Service registered with Mach Port %d\n", m_port);
#if ENABLE_UDS
	err = udsserver_init();
	if (err) { LogMsg("Daemon start: udsserver_init failed"); return err; }
	err = udsserver_add_rl_source();
	if (err) { LogMsg("Daemon start: udsserver_add_rl_source failed"); return err; }
#endif
	return(err);
	}

mDNSlocal mDNSs32 mDNSDaemonIdle(void)
	{
	// 1. Call mDNS_Execute() to let mDNSCore do what it needs to do
	mDNSs32 nextevent = mDNS_Execute(&mDNSStorage);

	mDNSs32 now = mDNSPlatformTimeNow();

	// 2. Deliver any waiting browse messages to clients
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
				DNSServiceDiscoveryReplyFlags flags = (r->next) ? DNSServiceDiscoverReplyFlagsMoreComing : 0;
				kern_return_t status = DNSServiceBrowserReply_rpc(x->ClientMachPort, r->resultType, r->name, r->type, r->dom, flags, 1);
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
			LogMsg("%5d: DNSServiceResolver(%##s) has remained active for over two minutes. "
				"This places considerable burden on the network.", l->ClientMachPort, l->i.name.c);
			}

	return(nextevent);
	}

mDNSexport int main(int argc, char **argv)
	{
	int i;
	kern_return_t status;
	FILE *fp;

	for (i=1; i<argc; i++)
		{
		if (!strcmp(argv[i], "-d")) debug_mode = 1;
		}

	signal(SIGINT,  HandleSIGTERM);		// SIGINT is what you get for a Ctrl-C
	signal(SIGTERM, HandleSIGTERM);
	signal(SIGINFO, HandleSIGINFO);

	// Register the server with mach_init for automatic restart only during debug mode
    if (!debug_mode)
		registerBootstrapService();

	if (!debug_mode && !restarting_via_mach_init)
		exit(0); /* mach_init will restart us immediately as a daemon */

	// Unlike deamon(), mach_init does redirect standard file descriptors to /dev/null
	if (!debug_mode)
		{
		int fd = open(_PATH_DEVNULL, O_RDWR, 0);
		if (fd != -1)
			{
			// Avoid to unnecessarily duplicate a file descriptor to itself
			if (fd != STDIN_FILENO) (void)dup2(fd, STDIN_FILENO);
			if (fd != STDOUT_FILENO) (void)dup2(fd, STDOUT_FILENO);
			if (fd != STDERR_FILENO) (void)dup2(fd, STDERR_FILENO);
			if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO) 
				(void)close (fd);
			}
		}

	fp = fopen(PID_FILE, "w");
	if (fp != NULL)
		{
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
		}
	
	LogMsg("%s starting", mDNSResponderVersionString);
	status = mDNSDaemonInitialize();

	if (status == 0)
		{
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
			mDNSs32 nextevent = mDNSDaemonIdle();
#if ENABLE_UDS
			nextevent = udsserver_idle(nextevent);
#endif

			// 2. Work out how long we expect to sleep before the next scheduled task
			mDNSs32 ticks = nextevent - mDNSPlatformTimeNow();
			if (ticks < 1) ticks = 1;
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

	destroyBootstrapService();

	return(status);
	}

// For convenience when using the "strings" command, this is the last thing in the file
#if mDNSResponderVersion > 1
mDNSexport const char mDNSResponderVersionString[] = "mDNSResponder-" STRINGIFY(mDNSResponderVersion) " (" __DATE__ " " __TIME__ ")";
#else
mDNSexport const char mDNSResponderVersionString[] = "mDNSResponder (Engineering Build) (" __DATE__ " " __TIME__ ")";
#endif
