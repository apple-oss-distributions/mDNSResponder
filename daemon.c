/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
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
 */

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <unistd.h>

#include "DNSServiceDiscoveryRequestServer.h"
#include "DNSServiceDiscoveryReply.h"

#include "mDNSClientAPI.h"				// Defines the interface to the client layer above
#include "mDNSPlatformEnvironment.h"	// Defines the specific types needed to run mDNS on this platform
#include "mDNSsprintf.h"
#include "mDNSvsprintf.h"				// Used to implement LogErrorMessage();

#include <DNSServiceDiscovery/DNSServiceDiscovery.h>

//*************************************************************************************************************
// Globals

static mDNS mDNSStorage;
static mDNS_PlatformSupport PlatformStorage;
#define RR_CACHE_SIZE 500
static ResourceRecord rrcachestorage[RR_CACHE_SIZE];
static const char PID_FILE[] = "/var/run/mDNSResponder.pid";

static const char kmDNSBootstrapName[] = "com.apple.mDNSResponder";
static mach_port_t client_death_port = MACH_PORT_NULL;
static mach_port_t exit_m_port       = MACH_PORT_NULL;
static mach_port_t server_priv_port  = MACH_PORT_NULL;
static CFRunLoopTimerRef DeliverInstanceTimer;

// mDNS Mach Message Timeout, in milliseconds.
// We need this to be short enough that we don't deadlock the mDNSResponder if a client
// fails to service its mach message queue, but long enough to give a well-written
// client a chance to service its mach message queue without getting cut off.
// Empirically, 50ms seems to work, so we set the timeout to 250ms to give
// even extra-slow clients a fair chance before we cut them off.
#define MDNS_MM_TIMEOUT 250

static int restarting_via_mach_init = 0;

#if DEBUGBREAKS
static int debug_mode = 1;
#else
static int debug_mode = 0;
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

typedef struct DNSServiceBrowser_struct DNSServiceBrowser;
struct DNSServiceBrowser_struct
	{
	DNSServiceBrowser *next;
	mach_port_t ClientMachPort;
	DNSQuestion q;
	int resultType;		// Set to -1 if no outstanding reply
	char name[256], type[256], dom[256];
	};

typedef struct DNSServiceResolver_struct DNSServiceResolver;
struct DNSServiceResolver_struct
	{
	DNSServiceResolver *next;
	mach_port_t ClientMachPort;
	ServiceInfoQuery q;
	ServiceInfo      i;
	};

typedef struct DNSServiceRegistration_struct DNSServiceRegistration;
struct DNSServiceRegistration_struct
	{
	DNSServiceRegistration *next;
	mach_port_t ClientMachPort;
	mDNSBool autoname;
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

void LogErrorMessage(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsprintf((char *)buffer, format, ptr)] = 0;
	va_end(ptr);
	openlog("mDNSResponder", LOG_CONS | LOG_PERROR | LOG_PID, LOG_DAEMON);
	fprintf(stderr, "%s\n", buffer);
	syslog(LOG_ERR, "%s", buffer);
	closelog();
	fflush(stderr);
	}

#if MACOSX_MDNS_MALLOC_DEBUGGING

char _malloc_options[] = "AXZ";

static void validatelists(mDNS *const m)
	{
	DNSServiceDomainEnumeration *e;
	DNSServiceBrowser           *b;
	DNSServiceResolver          *l;
	DNSServiceRegistration      *r;
	ResourceRecord              *rr;

	for (e = DNSServiceDomainEnumerationList; e; e=e->next)
		if (e->ClientMachPort == 0)
			LogErrorMessage("!!!! DNSServiceDomainEnumerationList %X is garbage !!!!", e);

	for (b = DNSServiceBrowserList; b; b=b->next)
		if (b->ClientMachPort == 0)
			LogErrorMessage("!!!! DNSServiceBrowserList %X is garbage !!!!", b);

	for (l = DNSServiceResolverList; l; l=l->next)
		if (l->ClientMachPort == 0)
			LogErrorMessage("!!!! DNSServiceResolverList %X is garbage !!!!", l);

	for (r = DNSServiceRegistrationList; r; r=r->next)
		if (r->ClientMachPort == 0)
			LogErrorMessage("!!!! DNSServiceRegistrationList %X is garbage !!!!", r);

	for (rr = m->ResourceRecords; rr; rr=rr->next)
		if (rr->RecordType == 0)
			LogErrorMessage("!!!! ResourceRecords %X list is garbage !!!!");
	}

void *mallocL(char *msg, unsigned int size)
	{
	unsigned long *mem = malloc(size+8);
	if (!mem)
		{ LogErrorMessage("malloc(%s:%d) failed", msg, size); return(NULL); }
	else
		{
		LogErrorMessage("malloc(%s:%d) = %X", msg, size, &mem[2]);
		mem[0] = 0xDEADBEEF;
		mem[1] = size;
		bzero(&mem[2], size);
		validatelists(&mDNSStorage);
		return(&mem[2]);
		}
	}

void freeL(char *msg, void *x)
	{
	if (!x)
		LogErrorMessage("free(%s@NULL)!", msg);
	else
		{
		unsigned long *mem = ((unsigned long *)x) - 2;
		if (mem[0] != 0xDEADBEEF)
			{ LogErrorMessage("free(%s@%X) !!!! NOT ALLOCATED !!!!", msg, &mem[2]); return; }
		if (mem[1] > 8000)
			{ LogErrorMessage("free(%s:%d@%X) too big!", msg, mem[1], &mem[2]); return; }
		LogErrorMessage("free(%s:%d@%X)", msg, mem[1], &mem[2]);
		bzero(mem, mem[1]+8);
		validatelists(&mDNSStorage);
		free(mem);
		}
	}

#endif

//*************************************************************************************************************
// Client Death Detection

mDNSlocal void AbortClient(mach_port_t ClientMachPort)
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
		debugf("Aborting DNSServiceDomainEnumeration %d", ClientMachPort);
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
		debugf("Aborting DNSServiceBrowser %d", ClientMachPort);
		mDNS_StopBrowse(&mDNSStorage, &x->q);
		freeL("DNSServiceBrowser", x);
		return;
		}

	while (*l && (*l)->ClientMachPort != ClientMachPort) l = &(*l)->next;
	if (*l)
		{
		DNSServiceResolver *x = *l;
		*l = (*l)->next;
		debugf("Aborting DNSServiceResolver %d", ClientMachPort);
		mDNS_StopResolveService(&mDNSStorage, &x->q);
		freeL("DNSServiceResolver", x);
		return;
		}

	while (*r && (*r)->ClientMachPort != ClientMachPort) r = &(*r)->next;
	if (*r)
		{
		DNSServiceRegistration *x = *r;
		*r = (*r)->next;
		mDNS_DeregisterService(&mDNSStorage, &x->s);
		// Note that we don't do the "free(x);" here -- wait for the mStatus_MemFree message
		return;
		}
	}

mDNSlocal void AbortBlockedClient(mach_port_t c, char *m)
	{
	DNSServiceDomainEnumeration **e = &DNSServiceDomainEnumerationList;
	DNSServiceBrowser           **b = &DNSServiceBrowserList;
	DNSServiceResolver          **l = &DNSServiceResolverList;
	DNSServiceRegistration      **r = &DNSServiceRegistrationList;
	while (*e && (*e)->ClientMachPort != c) e = &(*e)->next;
	while (*b && (*b)->ClientMachPort != c) b = &(*b)->next;
	while (*l && (*l)->ClientMachPort != c) l = &(*l)->next;
	while (*r && (*r)->ClientMachPort != c) r = &(*r)->next;
	if      (*e) LogErrorMessage("%5d: DomainEnumeration(%##s) stopped accepting Mach messages (%s)", c, &e[0]->dom.name, m);
	else if (*b) LogErrorMessage("%5d: Browser(%##s) stopped accepting Mach messages (%s)",      c, &b[0]->q.name, m);
	else if (*l) LogErrorMessage("%5d: Resolver(%##s) stopped accepting Mach messages (%s)",     c, &l[0]->i.name, m);
	else if (*r) LogErrorMessage("%5d: Registration(%##s) stopped accepting Mach messages (%s)", c, &r[0]->s.RR_SRV.name, m);
	else         LogErrorMessage("%5d (%s) stopped accepting Mach messages, but no record of client can be found!", c, m);

	AbortClient(c);
	}

mDNSlocal void ClientDeathCallback(CFMachPortRef unusedport, void *voidmsg, CFIndex size, void *info)
	{
	mach_msg_header_t *msg = (mach_msg_header_t *)voidmsg;
	if (msg->msgh_id == MACH_NOTIFY_DEAD_NAME)
		{
		const mach_dead_name_notification_t *const deathMessage = (mach_dead_name_notification_t *)msg;
		AbortClient(deathMessage->not_port);

		/* Deallocate the send right that came in the dead name notification */
		mach_port_destroy( mach_task_self(), deathMessage->not_port );
		}
	}

mDNSlocal void EnableDeathNotificationForClient(mach_port_t ClientMachPort)
	{
	mach_port_t prev;
	kern_return_t r = mach_port_request_notification(mach_task_self(), ClientMachPort, MACH_NOTIFY_DEAD_NAME, 0,
													 client_death_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev);
	// If the port already died while we were thinking about it, then abort the operation right away
	if (r != KERN_SUCCESS)
		{
		if (ClientMachPort != (mach_port_t)-1)
			LogErrorMessage("Client %5d died before we could enable death notification", ClientMachPort);
		AbortClient(ClientMachPort);
		}
	}

//*************************************************************************************************************
// Domain Enumeration

mDNSlocal void FoundDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer)
	{
	kern_return_t status;
	#pragma unused(m)
	char buffer[256];
	DNSServiceDomainEnumerationReplyResultType rt;
	DNSServiceDomainEnumeration *x = (DNSServiceDomainEnumeration *)question->Context;

	debugf("FoundDomain: %##s PTR %##s", answer->name.c, answer->rdata->u.name.c);
	if (answer->rrtype != kDNSType_PTR) return;
	if (!x) { debugf("FoundDomain: DNSServiceDomainEnumeration is NULL"); return; }

	if (answer->rrremainingttl > 0)
		{
		if (question == &x->dom) rt = DNSServiceDomainEnumerationReplyAddDomain;
		else                     rt = DNSServiceDomainEnumerationReplyAddDomainDefault;
		}
	else
		{
		if (question == &x->dom) rt = DNSServiceDomainEnumerationReplyRemoveDomain;
		else return;
		}

	ConvertDomainNameToCString(&answer->rdata->u.name, buffer);
	status = DNSServiceDomainEnumerationReply_rpc(x->ClientMachPort, rt, buffer, 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		AbortBlockedClient(x->ClientMachPort, "enumeration");
	}

mDNSexport kern_return_t provide_DNSServiceDomainEnumerationCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	int regDom)
	{
	kern_return_t status;
	mStatus err;

	mDNS_DomainType dt1 = regDom ? mDNS_DomainTypeRegistration        : mDNS_DomainTypeBrowse;
	mDNS_DomainType dt2 = regDom ? mDNS_DomainTypeRegistrationDefault : mDNS_DomainTypeBrowseDefault;
	const DNSServiceDomainEnumerationReplyResultType rt = DNSServiceDomainEnumerationReplyAddDomainDefault;
	DNSServiceDomainEnumeration *x = mallocL("DNSServiceDomainEnumeration", sizeof(*x));
	if (!x) { debugf("provide_DNSServiceDomainEnumerationCreate_rpc: No memory!"); return(mStatus_NoMemoryErr); }
	x->ClientMachPort = client;
	x->next = DNSServiceDomainEnumerationList;
	DNSServiceDomainEnumerationList = x;
	
	debugf("Client %d: Enumerate %s Domains", client, regDom ? "Registration" : "Browsing");
	// We always give local. as the initial default browse domain, and then look for more
	status = DNSServiceDomainEnumerationReply_rpc(x->ClientMachPort, rt, "local.", 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		{
		AbortBlockedClient(x->ClientMachPort, "local enumeration");
		return(mStatus_UnknownErr);
		}

	err           = mDNS_GetDomains(&mDNSStorage, &x->dom, dt1, zeroIPAddr, FoundDomain, x);
	if (!err) err = mDNS_GetDomains(&mDNSStorage, &x->def, dt2, zeroIPAddr, FoundDomain, x);

	if (err) AbortClient(client);
	else EnableDeathNotificationForClient(client);

	if (err) debugf("provide_DNSServiceDomainEnumerationCreate_rpc: mDNS_GetDomains error %d", err);
	return(err);
	}

//*************************************************************************************************************
// Browse for services

mDNSlocal void DeliverInstance(DNSServiceBrowser *x, DNSServiceDiscoveryReplyFlags flags)
	{
	kern_return_t status;
	debugf("DNSServiceBrowserReply_rpc sending reply for %s (%s)", x->name,
		(flags & DNSServiceDiscoverReplyFlagsMoreComing) ? "more coming" : "last in batch");
	status = DNSServiceBrowserReply_rpc(x->ClientMachPort, x->resultType, x->name, x->type, x->dom, flags, MDNS_MM_TIMEOUT);
	x->resultType = -1;
	if (status == MACH_SEND_TIMED_OUT)
		AbortBlockedClient(x->ClientMachPort, "browse");
	}

mDNSlocal void DeliverInstanceTimerCallBack(CFRunLoopTimerRef timer, void *info)
	{
	DNSServiceBrowser *b = DNSServiceBrowserList;
	(void)timer;	// Parameter not used

	while (b)
		{
		// NOTE: Need to advance b to the next element BEFORE we call DeliverInstance(), because in the
		// event that the client Mach queue overflows, DeliverInstance() will call AbortBlockedClient()
		// and that will cause the DNSServiceBrowser object's memory to be freed before it returns
		DNSServiceBrowser *x = b;
		b = b->next;
		if (x->resultType != -1)
			DeliverInstance(x, 0);
		}
	}

mDNSlocal void FoundInstance(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer)
	{
	DNSServiceBrowser *x = (DNSServiceBrowser *)question->Context;
	domainlabel name;
	domainname type, domain;
	
	if (answer->rrtype != kDNSType_PTR)
		{
		debugf("FoundInstance: Should not be called with rrtype %d (not a PTR record)", answer->rrtype);
		return;
		}
	
	if (!DeconstructServiceName(&answer->rdata->u.name, &name, &type, &domain))
		{
		debugf("FoundInstance: %##s PTR %##s is not valid NIAS service pointer", &answer->name, &answer->rdata->u.name);
		return;
		}

	if (x->resultType != -1) DeliverInstance(x, DNSServiceDiscoverReplyFlagsMoreComing);

	debugf("FoundInstance: %##s", answer->rdata->u.name.c);
	ConvertDomainLabelToCString_unescaped(&name, x->name);
	ConvertDomainNameToCString(&type, x->type);
	ConvertDomainNameToCString(&domain, x->dom);
	if (answer->rrremainingttl)
		 x->resultType = DNSServiceBrowserReplyAddInstance;
	else x->resultType = DNSServiceBrowserReplyRemoveInstance;

	// We schedule this timer 1/10 second in the future because CFRunLoop doesn't respect
	// the relative priority between CFSocket and CFRunLoopTimer, and continues to call
	// the timer callback even though there are packets waiting to be processed.
	CFRunLoopTimerSetNextFireDate(DeliverInstanceTimer, CFAbsoluteTimeGetCurrent() + 0.1);
	}

mDNSexport kern_return_t provide_DNSServiceBrowserCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString regtype, DNSCString domain)
	{
	mStatus err;
	domainname t, d;
	DNSServiceBrowser *x = mallocL("DNSServiceBrowser", sizeof(*x));
	if (!x) { debugf("provide_DNSServiceBrowserCreate_rpc: No memory!"); return(mStatus_NoMemoryErr); }
	x->ClientMachPort = client;
	x->resultType = -1;
	x->next = DNSServiceBrowserList;
	DNSServiceBrowserList = x;

	ConvertCStringToDomainName(regtype, &t);
	ConvertCStringToDomainName(*domain ? domain : "local.", &d);

	debugf("Client %d: provide_DNSServiceBrowserCreate_rpc", client);
	debugf("Client %d: Browse for Services: %##s%##s", client, &t, &d);
	err = mDNS_StartBrowse(&mDNSStorage, &x->q, &t, &d, zeroIPAddr, FoundInstance, x);

	if (err) AbortClient(client);
	else EnableDeathNotificationForClient(client);

	if (err) debugf("provide_DNSServiceBrowserCreate_rpc: mDNS_StartBrowse error %d", err);
	return(err);
	}

//*************************************************************************************************************
// Resolve Service Info

mDNSlocal void FoundInstanceInfo(mDNS *const m, ServiceInfoQuery *query)
	{
	kern_return_t status;
	DNSServiceResolver *x = (DNSServiceResolver *)query->Context;
	struct sockaddr_in interface;
	struct sockaddr_in address;
	char cstring[1024];
	int i, pstrlen = query->info->TXTinfo[0];

	//debugf("FoundInstanceInfo %.4a %.4a %##s", &query->info->InterfaceAddr, &query->info->ip, &query->info->name);

	if (query->info->TXTlen > sizeof(cstring)) return;

	bzero(&interface, sizeof(interface));
	bzero(&address,   sizeof(address));

	interface.sin_len         = sizeof(interface);
	interface.sin_family      = AF_INET;
	interface.sin_port        = 0;
	interface.sin_addr.s_addr = query->info->InterfaceAddr.NotAnInteger;
	
	address.sin_len           = sizeof(address);
	address.sin_family        = AF_INET;
	address.sin_port          = query->info->port.NotAnInteger;
	address.sin_addr.s_addr   = query->info->ip.NotAnInteger;

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
	
	status = DNSServiceResolverReply_rpc(x->ClientMachPort,
		(char*)&interface, (char*)&address, cstring, 0, MDNS_MM_TIMEOUT);
	if (status == MACH_SEND_TIMED_OUT)
		AbortBlockedClient(x->ClientMachPort, "resolve");
	}

mDNSexport kern_return_t provide_DNSServiceResolverResolve_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString name, DNSCString regtype, DNSCString domain)
	{
	mStatus err;
	domainlabel n;
	domainname t, d;
	DNSServiceResolver *x = mallocL("DNSServiceResolver", sizeof(*x));
	if (!x) { debugf("provide_DNSServiceResolverResolve_rpc: No memory!"); return(mStatus_NoMemoryErr); }
	x->ClientMachPort = client;
	x->next = DNSServiceResolverList;
	DNSServiceResolverList = x;

	ConvertCStringToDomainLabel(name, &n);
	ConvertCStringToDomainName(regtype, &t);
	ConvertCStringToDomainName(*domain ? domain : "local.", &d);
	ConstructServiceName(&x->i.name, &n, &t, &d);
	x->i.InterfaceAddr = zeroIPAddr;

	debugf("Client %d: provide_DNSServiceResolverResolve_rpc", client);
	debugf("Client %d: Resolve Service: %##s", client, &x->i.name);
	err = mDNS_StartResolveService(&mDNSStorage, &x->q, &x->i, FoundInstanceInfo, x);

	if (err) AbortClient(client);
	else EnableDeathNotificationForClient(client);

	if (err) debugf("provide_DNSServiceResolverResolve_rpc: mDNS_StartResolveService error %d", err);
	return(err);
	}

//*************************************************************************************************************
// Registration

mDNSlocal void FreeDNSServiceRegistration(DNSServiceRegistration *x)
	{
	while (x->s.Extras)
		{
		ExtraResourceRecord *extras = x->s.Extras;
		x->s.Extras = x->s.Extras->next;
		if (extras->r.rdata != &extras->r.rdatastorage)
			freeL("Extra RData", extras->r.rdata);
		freeL("ExtraResourceRecord", extras);
		}

	if (x->s.RR_TXT.rdata != &x->s.RR_TXT.rdatastorage)
			freeL("TXT RData", x->s.RR_TXT.rdata);

	freeL("DNSServiceRegistration", x);
	}

mDNSlocal void RegCallback(mDNS *const m, ServiceRecordSet *const sr, mStatus result)
	{
	DNSServiceRegistration *x = (DNSServiceRegistration*)sr->Context;

	switch (result)
		{
		case mStatus_NoError:      debugf("RegCallback: %##s Name Registered",   sr->RR_SRV.name.c); break;
		case mStatus_NameConflict: debugf("RegCallback: %##s Name Conflict",     sr->RR_SRV.name.c); break;
		case mStatus_MemFree:      debugf("RegCallback: %##s Memory Free",       sr->RR_SRV.name.c); break;
		default:                   debugf("RegCallback: %##s Unknown Result %d", sr->RR_SRV.name.c, result); break;
		}

	if (result == mStatus_NoError)
		{
		kern_return_t status = DNSServiceRegistrationReply_rpc(x->ClientMachPort, result, MDNS_MM_TIMEOUT);
		if (status == MACH_SEND_TIMED_OUT)
			AbortBlockedClient(x->ClientMachPort, "registration success");
		}

	if (result == mStatus_NameConflict)
		{
		// Note: By the time we get the mStatus_NameConflict message, the service is already deregistered
		// and the memory is free, so we don't have to wait for an mStatus_MemFree message as well.
		if (x->autoname)
			mDNS_RenameAndReregisterService(m, sr);
		else
			{
			kern_return_t status;
			// AbortClient unlinks our DNSServiceRegistration from the list so we can safely free it
			AbortClient(x->ClientMachPort);
			status = DNSServiceRegistrationReply_rpc(x->ClientMachPort, result, MDNS_MM_TIMEOUT);
			if (status == MACH_SEND_TIMED_OUT)
				AbortBlockedClient(x->ClientMachPort, "registration conflict"); // Yes, this IS safe :-)
			FreeDNSServiceRegistration(x);
			}
		}

	if (result == mStatus_MemFree)
		{
		DNSServiceRegistration **r = &DNSServiceRegistrationList;
		while (*r && *r != x) r = &(*r)->next;
		if (*r)
			{
			debugf("RegCallback: %##s Still in DNSServiceRegistration list; removing now", sr->RR_SRV.name.c);
			*r = (*r)->next;
			}
		debugf("RegCallback: Freeing DNSServiceRegistration %##s %d", sr->RR_SRV.name.c, x->ClientMachPort);
		FreeDNSServiceRegistration(x);
		}
	}

mDNSlocal void CheckForDuplicateRegistrations(DNSServiceRegistration *x, domainlabel *n, domainname *t, domainname *d)
	{
	char name[256];
	int count = 0;
	ResourceRecord *rr;
	domainname srvname;
	ConstructServiceName(&srvname, n, t, d);
	mDNS_sprintf(name, "%##s", &srvname);

	for (rr = mDNSStorage.ResourceRecords; rr; rr=rr->next)
		if (rr->rrtype == kDNSType_SRV && SameDomainName(&rr->name, &srvname))
			count++;

	if (count)
		{
		debugf("Client %5d   registering Service Record Set \"%##s\"; WARNING! now have %d instances",
			x->ClientMachPort, &srvname, count+1);
		LogErrorMessage("%5d: WARNING! Bogus client application has now registered %d identical instances of service %##s",
			x->ClientMachPort, count+1, &srvname);
		}
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationCreate_rpc(mach_port_t unusedserver, mach_port_t client,
	DNSCString name, DNSCString regtype, DNSCString domain, int notAnIntPort, DNSCString txtRecord)
	{
	mStatus err;
	domainlabel n;
	domainname t, d;
	mDNSIPPort port;
	unsigned char txtinfo[1024] = "";
	int data_len = 0;
	int size = sizeof(RDataBody);
	unsigned char *pstring = &txtinfo[data_len];
	char *ptr = txtRecord;
	DNSServiceRegistration *x;

	// The OS X DNSServiceRegistrationCreate() API is defined using a C-string,
	// but the mDNS_RegisterService() call actually requires a packed block of P-strings.
	// Hence we have to convert the C-string to a P-string.
	// ASCII-1 characters are allowed in the C-string as boundary markers,
	// so that a single C-string can be used to represent one or more P-strings.
	while (*ptr)
		{
		if (++data_len >= sizeof(txtinfo)) return(mStatus_BadParamErr);
		if (*ptr == 1)		// If this is our boundary marker, start a new P-string
			{
			pstring = &txtinfo[data_len];
			pstring[0] = 0;
			ptr++;
			}
		else
			{
			if (pstring[0] == 255) return(mStatus_BadParamErr);
			pstring[++pstring[0]] = *ptr++;
			}
		}

	data_len++;
	if (size < data_len)
		size = data_len;

	x = mallocL("DNSServiceRegistration", sizeof(*x) - sizeof(RDataBody) + size);
	if (!x) { debugf("provide_DNSServiceRegistrationCreate_rpc: No memory!"); return(mStatus_NoMemoryErr); }
	x->ClientMachPort = client;
	x->next = DNSServiceRegistrationList;
	DNSServiceRegistrationList = x;

	x->autoname = (*name == 0);
	if (x->autoname) n = mDNSStorage.nicelabel;
	else ConvertCStringToDomainLabel(name, &n);
	ConvertCStringToDomainName(regtype, &t);
	ConvertCStringToDomainName(*domain ? domain : "local.", &d);
	port.NotAnInteger = notAnIntPort;

	debugf("Client %d: provide_DNSServiceRegistrationCreate_rpc", client);
	debugf("Client %d: Register Service: %#s.%##s%##s %d %.30s",
		client, &n, &t, &d, (int)port.b[0] << 8 | port.b[1], txtRecord);
	CheckForDuplicateRegistrations(x, &n, &t, &d);
	err = mDNS_RegisterService(&mDNSStorage, &x->s, &n, &t, &d, mDNSNULL, port, txtinfo, data_len, RegCallback, x);

	if (err) AbortClient(client);
	else EnableDeathNotificationForClient(client);

	if (err) debugf("provide_DNSServiceRegistrationCreate_rpc: mDNS_RegisterService error %d", err);
	else debugf("Made Service Record Set for %##s", &x->s.RR_SRV.name);

	return(err);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationAddRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	int type, const char *data, mach_msg_type_number_t data_len, uint32_t ttl, natural_t *reference)
	{
	mStatus err;
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	ExtraResourceRecord *extra;
	int size = sizeof(RDataBody);
	if (size < data_len)
		size = data_len;
	
	// Find this registered service
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)
		{
		debugf("provide_DNSServiceRegistrationAddRecord_rpc bad client %X", client);
		return(mStatus_BadReferenceErr);
		}

	// Allocate storage for our new record
	extra = mallocL("ExtraResourceRecord", sizeof(*extra) - sizeof(RDataBody) + size);
	if (!extra) return(mStatus_NoMemoryErr);

	// Fill in type, length, and data
	extra->r.rrtype = type;
	extra->r.rdatastorage.MaxRDLength = size;
	extra->r.rdatastorage.RDLength    = data_len;
	memcpy(&extra->r.rdatastorage.u.data, data, data_len);
	
	// And register it
	err = mDNS_AddRecordToService(&mDNSStorage, &x->s, extra, &extra->r.rdatastorage, ttl);
	*reference = (natural_t)extra;
	debugf("Received a request to add the record of type: %d length: %d; returned reference %X",
		type, data_len, *reference);
	return(err);
	}

mDNSlocal void UpdateCallback(mDNS *const m, ResourceRecord *const rr, RData *OldRData)
	{
	if (OldRData != &rr->rdatastorage)
		freeL("Old RData", OldRData);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationUpdateRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	natural_t reference, const char *data, mach_msg_type_number_t data_len, uint32_t ttl)
	{
	mStatus err;
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	ResourceRecord *rr;
	RData *newrdata;
	int size = sizeof(RDataBody);
	if (size < data_len)
		size = data_len;

	// Find this registered service
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)
		{
		debugf("provide_DNSServiceRegistrationUpdateRecord_rpc bad client %X", client);
		return(mStatus_BadReferenceErr);
		}
	
	// Find the record we're updating
	if (!reference)	// NULL reference means update the primary TXT record
		rr = &x->s.RR_TXT;
	else			// Else, scan our list to make sure we're updating a valid record that was previously added
		{
		ExtraResourceRecord *e = x->s.Extras;
		while (e && e != (ExtraResourceRecord*)reference) e = e->next;
		if (!e)
			{
			debugf("provide_DNSServiceRegistrationUpdateRecord_rpc failed to find record %X", reference);
			return(mStatus_BadReferenceErr);
			}
		rr = &e->r;
		}

	// Allocate storage for our new data
	newrdata = mallocL("RData", sizeof(*newrdata) - sizeof(RDataBody) + size);
	if (!newrdata) return(mStatus_NoMemoryErr);

	// Fill in new length, and data
	newrdata->MaxRDLength = size;
	newrdata->RDLength    = data_len;
	memcpy(&newrdata->u, data, data_len);
	
	// And update our record
	err = mDNS_Update(&mDNSStorage, rr, ttl, newrdata, UpdateCallback);
	if (err)
		{
		debugf("Received a request to update the record of length: %d for reference: %X; failed %d",
			data_len, reference, err);
		return(err);
		}

	debugf("Received a request to update the record of length: %d for reference: %X", data_len, reference);
	return(err);
	}

mDNSexport kern_return_t provide_DNSServiceRegistrationRemoveRecord_rpc(mach_port_t unusedserver, mach_port_t client,
	natural_t reference)
	{
	mStatus err;
	DNSServiceRegistration *x = DNSServiceRegistrationList;
	ExtraResourceRecord *extra = (ExtraResourceRecord*)reference;
	
	// Find this registered service
	while (x && x->ClientMachPort != client) x = x->next;
	if (!x)
		{
		LogErrorMessage("DNSServiceRegistrationRemoveRecord Client %5d not found", client);
		debugf("provide_DNSServiceRegistrationRemoveRecord_rpc bad client %X", client);
		return(mStatus_BadReferenceErr);
		}

	err = mDNS_RemoveRecordFromService(&mDNSStorage, &x->s, extra);
	if (err)
		{
		LogErrorMessage("DNSServiceRegistrationRemoveRecord Client %5d does not have record %X", client, extra);
		debugf("Received a request to remove the record of reference: %X (failed %d)", extra, err);
		return(err);
		}

	debugf("Received a request to remove the record of reference: %X", extra);
	if (extra->r.rdata != &extra->r.rdatastorage)
		freeL("Extra RData", extra->r.rdata);
	freeL("ExtraResourceRecord", extra);
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
	debugf("ExitCallback: destroyBootstrapService");
	if (!debug_mode)
		destroyBootstrapService();

	debugf("ExitCallback: Aborting MIG clients");
	while (DNSServiceDomainEnumerationList) AbortClient(DNSServiceDomainEnumerationList->ClientMachPort);
	while (DNSServiceBrowserList)           AbortClient(DNSServiceBrowserList->ClientMachPort);
	while (DNSServiceResolverList)          AbortClient(DNSServiceResolverList->ClientMachPort);
	while (DNSServiceRegistrationList)      AbortClient(DNSServiceRegistrationList->ClientMachPort);

	debugf("ExitCallback: mDNS_Close");
	mDNS_Close(&mDNSStorage);
	exit(0);
	}

mDNSlocal kern_return_t start(const char *bundleName, const char *bundleDir)
	{
	mStatus            err;
	CFRunLoopTimerContext myCFRunLoopTimerContext = { 0, &mDNSStorage, NULL, NULL, NULL };
	CFMachPortRef      d_port = CFMachPortCreate(NULL, ClientDeathCallback, NULL, NULL);
	CFMachPortRef      s_port = CFMachPortCreate(NULL, DNSserverCallback, NULL, NULL);
	CFMachPortRef      e_port = CFMachPortCreate(NULL, ExitCallback, NULL, NULL);
	mach_port_t        m_port = CFMachPortGetPort(s_port);
	kern_return_t      status = bootstrap_register(bootstrap_port, DNS_SERVICE_DISCOVERY_SERVER, m_port);
	CFRunLoopSourceRef d_rls  = CFMachPortCreateRunLoopSource(NULL, d_port, 0);
	CFRunLoopSourceRef s_rls  = CFMachPortCreateRunLoopSource(NULL, s_port, 0);
	CFRunLoopSourceRef e_rls  = CFMachPortCreateRunLoopSource(NULL, e_port, 0);
	
	if (status)
		{
		if (status == 1103)
			LogErrorMessage("Bootstrap_register failed(): A copy of the daemon is apparently already running");
		else
			LogErrorMessage("Bootstrap_register failed(): %s %d", mach_error_string(status), status);
		return(status);
		}

	// Note: Every CFRunLoopTimer has to be created with an initial fire time, and a repeat interval, or it becomes
	// a one-shot timer and you can't use CFRunLoopTimerSetNextFireDate(timer, when) to schedule subsequent firings.
	// Here we create it with an initial fire time 24 hours from now, and a repeat interval of 24 hours, with
	// the intention that we'll actually reschedule it using CFRunLoopTimerSetNextFireDate(timer, when) as necessary.
	DeliverInstanceTimer = CFRunLoopTimerCreate(kCFAllocatorDefault,
							CFAbsoluteTimeGetCurrent() + 24.0*60.0*60.0, 24.0*60.0*60.0,
							0, // no flags
							9, // low priority execution (after all packets, etc., have been handled).
							DeliverInstanceTimerCallBack, &myCFRunLoopTimerContext);
	if (!DeliverInstanceTimer) return(-1);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), DeliverInstanceTimer, kCFRunLoopDefaultMode);
	
	err = mDNS_Init(&mDNSStorage, &PlatformStorage, rrcachestorage, RR_CACHE_SIZE, NULL, NULL);
	if (err) { LogErrorMessage("Daemon start: mDNS_Init failed %ld", err); return(err); }

	client_death_port = CFMachPortGetPort(d_port);
	exit_m_port = CFMachPortGetPort(e_port);

	CFRunLoopAddSource(CFRunLoopGetCurrent(), d_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), s_rls, kCFRunLoopDefaultMode);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), e_rls, kCFRunLoopDefaultMode);
	CFRelease(d_rls);
	CFRelease(s_rls);
	CFRelease(e_rls);
	if (debug_mode) printf("Service registered with Mach Port %d\n", m_port);

	return(err);
	}

mDNSlocal void HandleSIG(int signal)
	{
	debugf("");
	debugf("HandleSIG");
	
	// Send a mach_msg to ourselves (since that is signal safe) telling us to cleanup and exit
	mach_msg_return_t msg_result;
	mach_msg_header_t header;

	header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
	header.msgh_remote_port = exit_m_port;
	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_size = sizeof(header);
	header.msgh_id = 0;

	msg_result = mach_msg_send(&header);
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

	signal(SIGINT, HandleSIG);	// SIGINT is what you get for a Ctrl-C
	signal(SIGTERM, HandleSIG);

	// Register the server with mach_init for automatic restart only during debug mode
    if (!debug_mode)
		registerBootstrapService();

	if (!debug_mode && !restarting_via_mach_init)
		exit(0); /* mach_init will restart us immediately as a daemon */

	fp = fopen(PID_FILE, "w");
	if (fp != NULL)
		{
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
		}
	
	LogErrorMessage("mDNSResponder (%s %s) starting", __DATE__, __TIME__);
	status = start(NULL, NULL);

	if (status == 0)
		{
		CFRunLoopRun();
		LogErrorMessage("CFRunLoopRun Exiting. This is bad.");
		mDNS_Close(&mDNSStorage);
		}

	destroyBootstrapService();

	return(status);
	}
