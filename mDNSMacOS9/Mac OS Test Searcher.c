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

$Log: Mac\040OS\040Test\040Searcher.c,v $
Revision 1.13  2003/08/14 02:19:54  cheshire
<rdar://problem/3375491> Split generic ResourceRecord type into two separate types: AuthRecord and CacheRecord

Revision 1.12  2003/08/12 19:56:24  cheshire
Update to APSL 2.0

 */

#include <stdio.h>						// For printf()
#include <Events.h>						// For WaitNextEvent()
#include <SIOUX.h>						// For SIOUXHandleOneEvent()

#include "mDNSClientAPI.h"				// Defines the interface to the client layer above
#include "mDNSMacOS9.h"					// Defines the specific types needed to run mDNS on this platform

typedef struct
	{
	OTLIFO serviceinfolist;
	Boolean headerPrinted;
	Boolean lostRecords;
	} SearcherServices;

typedef struct { ServiceInfo i; mDNSBool add; mDNSBool dom; OTLink link; } linkedServiceInfo;

// These don't have to be globals, but their memory does need to remain valid for as
// long as the search is going on. They are declared as globals here for simplicity.
#define RR_CACHE_SIZE 1000
static CacheRecord rrcachestorage[RR_CACHE_SIZE];
static mDNS mDNSStorage;
static mDNS_PlatformSupport PlatformSupportStorage;
static SearcherServices services;
static DNSQuestion browsequestion, domainquestion;

// PrintServiceInfo prints the service information to standard out
// A real application might want to do something else with the information
static void PrintServiceInfo(SearcherServices *services)
	{
	OTLink *link = OTReverseList(OTLIFOStealList(&services->serviceinfolist));
	
	while (link)
		{
		linkedServiceInfo *ls = OTGetLinkObject(link, linkedServiceInfo, link);
		ServiceInfo *s = &ls->i;

		if (!services->headerPrinted)
			{
			printf("%-55s Type             Domain         IP Address       Port Info\n", "Name");
			services->headerPrinted = true;
			}

		if (ls->dom)
			{
			char c_dom[256];
			ConvertDomainNameToCString(&s->name, c_dom);
			if (ls->add) printf("%-55s available for browsing\n", c_dom);
			else         printf("%-55s no longer available for browsing\n", c_dom);
			}
		else
			{
			domainlabel name;
			domainname type, domain;
			UInt16 port = (UInt16)((UInt16)s->port.b[0] << 8 | s->port.b[1]);
			char c_name[64], c_type[256], c_dom[256], c_ip[20];
			
			DeconstructServiceName(&s->name, &name, &type, &domain);
			ConvertDomainLabelToCString_unescaped(&name, c_name);
			ConvertDomainNameToCString(&type, c_type);
			ConvertDomainNameToCString(&domain, c_dom);
			sprintf(c_ip, "%d.%d.%d.%d", s->ip.ip.v4.b[0], s->ip.ip.v4.b[1], s->ip.ip.v4.b[2], s->ip.ip.v4.b[3]);

			printf("%-55s %-16s %-14s ", c_name, c_type, c_dom);
			if (ls->add) printf("%-15s %5d %#s\n", c_ip, port, s->TXTinfo);
			else         printf("Removed\n");
			}

		link = link->fNext;
		OTFreeMem(ls);
		}
	}

// When the name, address, port, and txtinfo for a service is found, FoundInstanceInfo()
// enqueues a record for PrintServiceInfo() to print.
// Note, a browsing application would *not* normally need to get all this information --
// all it needs is the name, to display to the user.
// Finding out the address, port, and txtinfo should be deferred to the time that the user
// actually needs to contact the service to use it.
static void FoundInstanceInfo(mDNS *const m, ServiceInfoQuery *query)
	{
	SearcherServices *services = (SearcherServices *)query->ServiceInfoQueryContext;
	linkedServiceInfo *info = (linkedServiceInfo *)(query->info);
	if (query->info->ip.type == mDNSAddrType_IPv4)
		{
		mDNS_StopResolveService(m, query);		// For this test code, one answer is sufficient
		OTLIFOEnqueue(&services->serviceinfolist, &info->link);
		OTFreeMem(query);
		}
	}

// When a new named instance of a service is found, FoundInstance() is called.
// In this sample code we turn around and immediately issue a query to resolve that service name to
// find its address, port, and txtinfo, but a normal browing application would just display the name.
static void FoundInstance(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	#pragma unused (question)
	SearcherServices *services = (SearcherServices *)question->QuestionContext;
	linkedServiceInfo *info;

	debugf("FoundInstance %##s PTR %##s", answer->name.c, answer->rdata->u.name.c);

	if (answer->rrtype != kDNSType_PTR) return;
	if (!services) { debugf("FoundInstance: services is NULL"); return; }
	
	info = (linkedServiceInfo *)OTAllocMem(sizeof(linkedServiceInfo));
	if (!info) { services->lostRecords = true; return; }
	
	info->i.name          = answer->rdata->u.name;
	info->i.InterfaceID   = answer->InterfaceID;
	info->i.ip.type		  = mDNSAddrType_IPv4;
	info->i.ip.ip.v4  = zeroIPAddr;
	info->i.port          = zeroIPPort;
	info->add             = AddRecord;
	info->dom             = mDNSfalse;
	
	if (!AddRecord)	// If TTL == 0 we're deleting a service,
		OTLIFOEnqueue(&services->serviceinfolist, &info->link);
	else								// else we're adding a new service
		{
		ServiceInfoQuery *q = (ServiceInfoQuery *)OTAllocMem(sizeof(ServiceInfoQuery));
		if (!q) { OTFreeMem(info); services->lostRecords = true; return; }
		mDNS_StartResolveService(m, q, &info->i, FoundInstanceInfo, services);
		}
	}

static void FoundDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	#pragma unused (m)
	#pragma unused (question)
	SearcherServices *services = (SearcherServices *)question->QuestionContext;
	linkedServiceInfo *info;

	debugf("FoundDomain %##s PTR %##s", answer->name.c, answer->rdata->u.name.c);

	if (answer->rrtype != kDNSType_PTR) return;
	if (!services) { debugf("FoundDomain: services is NULL"); return; }
	
	info = (linkedServiceInfo *)OTAllocMem(sizeof(linkedServiceInfo));
	if (!info) { services->lostRecords = true; return; }
	
	info->i.name          = answer->rdata->u.name;
	info->i.InterfaceID   = answer->InterfaceID;
	info->i.ip.type		  = mDNSAddrType_IPv4;
	info->i.ip.ip.v4  = zeroIPAddr;
	info->i.port          = zeroIPPort;
	info->add             = AddRecord;
	info->dom             = mDNStrue;
		
	OTLIFOEnqueue(&services->serviceinfolist, &info->link);
	}

// YieldSomeTime() just cooperatively yields some time to other processes running on classic Mac OS
static Boolean YieldSomeTime(UInt32 milliseconds)
	{
	extern Boolean SIOUXQuitting;
	EventRecord e;
	WaitNextEvent(everyEvent, &e, milliseconds / 17, NULL);
	SIOUXHandleOneEvent(&e);
	return(SIOUXQuitting);
	}

int main()
	{
	extern void mDNSPlatformIdle(mDNS *const m);	// Only needed for debugging version
	mStatus err;
	Boolean DoneSetup = false;

	SIOUXSettings.asktosaveonclose = false;
	SIOUXSettings.userwindowtitle  = "\pMulticast DNS Searcher";
	SIOUXSettings.rows             = 40;
	SIOUXSettings.columns          = 132;

	printf("Prototype Multicast DNS Searcher\n\n");
	printf("WARNING! This is experimental software.\n\n");
	printf("Multicast DNS is currently an experimental protocol.\n\n");
	printf("This software reports errors using MacsBug breaks,\n");
	printf("so if you don't have MacsBug installed your Mac may crash.\n\n");
	printf("******************************************************************************\n");

	err = InitOpenTransport();
	if (err) { debugf("InitOpenTransport failed %d", err); return(err); }

	err = mDNS_Init(&mDNSStorage, &PlatformSupportStorage, rrcachestorage, RR_CACHE_SIZE,
		mDNS_Init_DontAdvertiseLocalAddresses, mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
	if (err) return(err);

	services.serviceinfolist.fHead = NULL;
	services.headerPrinted         = false;
	services.lostRecords           = false;

	while (!YieldSomeTime(35))
		{
		// For debugging, use "#define __ONLYSYSTEMTASK__ 1" and call mDNSPlatformIdle() periodically.
		// For shipping code, don't define __ONLYSYSTEMTASK__, and you don't need to call mDNSPlatformIdle()
		mDNSPlatformIdle(&mDNSStorage);	// Only needed for debugging version
		if (mDNSStorage.mDNSPlatformStatus == mStatus_NoError && !DoneSetup)
			{
			domainname srvtype, srvdom;
			DoneSetup = true;
			printf("\nSending mDNS service lookup queries and waiting for responses...\n\n");
			MakeDomainNameFromDNSNameString(&srvtype, "_http._tcp.");
			MakeDomainNameFromDNSNameString(&srvdom, "local.");
			err = mDNS_StartBrowse(&mDNSStorage, &browsequestion, &srvtype, &srvdom, mDNSInterface_Any, FoundInstance, &services);
			if (err) break;
			err = mDNS_GetDomains(&mDNSStorage, &domainquestion, mDNS_DomainTypeBrowse, mDNSInterface_Any, FoundDomain, &services);
			if (err) break;
			}

		if (services.serviceinfolist.fHead)
			PrintServiceInfo(&services);

		if (services.lostRecords)
			{
			services.lostRecords = false;
			printf("**** Warning: Out of memory: Records have been missed.\n");
			}
		}

	mDNS_StopBrowse(&mDNSStorage, &browsequestion);
	mDNS_Close(&mDNSStorage);
	return(0);
	}
