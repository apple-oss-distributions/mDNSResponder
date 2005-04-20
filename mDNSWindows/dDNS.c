/*
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

*/

#include "dDNS.h"
#include "DNSCommon.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

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
// for domain enumeration and default browsing/registration
static SearchListElem *SearchList = mDNSNULL;      // where we search for _browse domains
static DNSQuestion LegacyBrowseDomainQ;        // our local enumeration query for _legacy._browse domains
static DNameListElem *DefBrowseList = mDNSNULL;    // cache of answers to above query (where we search for empty string browses)
static DNameListElem *DefRegList = mDNSNULL;       // manually generated list of domains where we register for empty string registrations
static ARListElem *SCPrefBrowseDomains = mDNSNULL; // manually generated local-only PTR records for browse domains we get from SCPreferences

static domainname			dDNSRegDomain;             // Default wide-area zone for service registration
static DNameListElem	*	dDNSBrowseDomains;         // Default wide-area zone for legacy ("empty string") browses
static domainname			dDNSHostname;


mStatus dDNS_SetupAddr(mDNSAddr *ip, const struct sockaddr *const sa)
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
#if !defined(_WIN32)
		if (IN6_IS_ADDR_LINKLOCAL(&ifa_addr->sin6_addr)) ifa_addr->sin6_addr.__u6_addr.__u6_addr16[1] = 0;
#else
		if (IN6_IS_ADDR_LINKLOCAL(&ifa_addr->sin6_addr)) ifa_addr->sin6_addr.u.Word[1] = 0;
#endif 		
		ip->ip.v6 = *(mDNSv6Addr*)&ifa_addr->sin6_addr;
		return(mStatus_NoError);
		}

	LogMsg("SetupAddr invalid sa_family %d", sa->sa_family);
	return(mStatus_Invalid);
	}

mDNSlocal void MarkSearchListElem(domainname *domain)
	{
	SearchListElem *new, *ptr;
	
	// if domain is in list, mark as pre-existent (0)
	for (ptr = SearchList; ptr; ptr = ptr->next)
		if (SameDomainName(&ptr->domain, domain))
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
		AssignDomainName(&new->domain, domain);
		new->flag = 1;  // add
		new->next = SearchList;
		SearchList = new;
		}
	}

//!!!KRS here is where we will give success/failure notification to the UI
mDNSlocal void SCPrefsdDNSCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
	{
	(void)m;  // unused
	debugf("SCPrefsdDNSCallback: result %d for registration of name %##s", result, rr->resrec.name->c);
	dDNSPlatformSetNameStatus(rr->resrec.name, result);
	}

mDNSlocal void FreeARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
	{
	ARListElem *elem = rr->RecordContext;
	
	(void)m;  // unused
	
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

mDNSexport DNameListElem *mDNSPlatformGetSearchDomainList(void)
	{
	return mDNS_CopyDNameList(DefBrowseList);
	}

mDNSexport DNameListElem *mDNSPlatformGetRegDomainList(void)
	{
	return mDNS_CopyDNameList(DefRegList);
	}

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

	dDNSPlatformDefaultRegDomainChanged(d, mDNStrue);
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
			dDNSPlatformDefaultRegDomainChanged(d, mDNSfalse);
			udsserver_default_reg_domain_changed(d, mDNSfalse);
			return;
			}
		prev = ptr;
		ptr = ptr->next;
		}
	debugf("Requested removal of default registration domain %##s not in contained in list", d->c); 
	}


mDNSlocal void FoundDefBrowseDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
	{
	DNameListElem *ptr, *prev, *new;
	(void)m; // unused;
	(void)question;  // unused

	if (AddRecord)
		{
		new = mallocL("FoundDefBrowseDomain", sizeof(DNameListElem));
		if (!new) { LogMsg("ERROR: malloc"); return; }
		AssignDomainName(&new->name, &answer->rdata->u.name);
		new->next = DefBrowseList;
		DefBrowseList = new;
		dDNSPlatformDefaultBrowseDomainChanged(&new->name, mDNStrue);
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
				dDNSPlatformDefaultBrowseDomainChanged(&ptr->name, mDNSfalse);
				udsserver_default_browse_domain_changed(&ptr->name, mDNSfalse);
				if (prev) prev->next = ptr->next;
				else DefBrowseList = ptr->next;
				freeL("FoundDefBrowseDomain", ptr);				
				return;
				}
			prev = ptr;
			ptr = ptr->next;
			}
		LogMsg("FoundDefBrowseDomain: Got remove event for domain %s not in list", answer->rdata->u.name.c);
		}
	}


mDNSlocal mStatus RegisterNameServers( mDNS *const m )
	{
	IPAddrListElem	* list;
	IPAddrListElem	* elem;

	mDNS_DeleteDNSServers(m); // deregister orig list

	list = dDNSPlatformGetDNSServers();

	for ( elem = list; elem; elem = elem->next )
		{
		LogOperation("RegisterNameServers: Adding %#a", &elem->addr);
		mDNS_AddDNSServer(m, &elem->addr, NULL);
		}

	dDNS_FreeIPAddrList( list );

	return mStatus_NoError;
	}


mDNSlocal mStatus RegisterSearchDomains( mDNS *const m )
	{
	SearchListElem *ptr, *prev, *freeSLPtr;
	DNameListElem	*	elem;
	DNameListElem	*	list;
	ARListElem *arList;
	mStatus err;
	mDNSBool dict = 1;
	
	// step 1: mark each elem for removal (-1), unless we aren't passed a dictionary in which case we mark as preexistent
	for (ptr = SearchList; ptr; ptr = ptr->next) ptr->flag = dict ? -1 : 0;

	// get all the domains from "Search Domains" field of sharing prefs

	list = dDNSPlatformGetSearchDomainList();
	
	for ( elem = list; elem; elem = elem->next )
		{
		MarkSearchListElem(&elem->name);
		}

	mDNS_FreeDNameList( list );

	list = dDNSPlatformGetDomainName();

	if ( list )
		{
		MarkSearchListElem( &list->name );
		mDNS_FreeDNameList( list );
		}

	list = dDNSPlatformGetReverseMapSearchDomainList( );

	for ( elem = list; elem; elem = elem->next )
		{
		MarkSearchListElem(&elem->name);
		}

	mDNS_FreeDNameList( list );

	if (dDNSRegDomain.c[0]) MarkSearchListElem(&dDNSRegDomain);         // implicitly browse reg domain too (no-op if same as BrowseDomain)
	
	// delete elems marked for removal, do queries for elems marked add
	prev = mDNSNULL;
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
			ptr->AuthRecs = mDNSNULL;
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


mDNSlocal void RegisterBrowseDomainPTR(mDNS *m, const domainname *d, int type)
	{
	// allocate/register legacy and non-legacy _browse PTR record
	mStatus err;
	ARListElem *browse = mallocL("ARListElem", sizeof(*browse));
	mDNS_SetupResourceRecord(&browse->ar, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200,  kDNSRecordTypeShared, FreeARElemCallback, browse);
	MakeDomainNameFromDNSNameString(browse->ar.resrec.name, mDNS_DomainTypeNames[type]);
	AppendDNSNameString            (browse->ar.resrec.name, "local");
	AssignDomainName(&browse->ar.resrec.rdata->u.name, d);
	err = mDNS_Register(m, &browse->ar);
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
	LogMsg("%s default browse domain %##s", add ? "Adding" : "Removing", d->c);
	
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

mDNSlocal void SetSCPrefsBrowseDomains(mDNS *m, DNameListElem * browseDomains, mDNSBool add)
	{
	DNameListElem * browseDomain;

	for ( browseDomain = browseDomains; browseDomain; browseDomain = browseDomain->next )
		{
			if ( !browseDomain->name.c[0] )
				{
				LogMsg("SetSCPrefsBrowseDomains bad DDNS browse domain: %s", browseDomain->name.c[0] ? browseDomain->name.c : "(unknown)");
				}
			else
				{
				SetSCPrefsBrowseDomain(m, &browseDomain->name, add);
				}
		}
	}

mStatus dDNS_Setup( mDNS *const m )
	{
	static mDNSBool LegacyNATInitialized = mDNSfalse;
	mDNSBool dict = mDNStrue;
	mDNSAddr ip;
	mDNSAddr r;
	DNameListElem * BrowseDomains;
	domainname RegDomain, fqdn;
	
	// get fqdn, zone from SCPrefs
	dDNSPlatformGetConfig(&fqdn, &RegDomain, &BrowseDomains);
	
	// YO if (!fqdn.c[0] && !RegDomain.c[0]) ReadDDNSSettingsFromConfFile(m, CONFIG_FILE, &fqdn, &RegDomain);

	if (!SameDomainName(&RegDomain, &dDNSRegDomain))
	{		
		if (dDNSRegDomain.c[0])
		{
			RemoveDefRegDomain(&dDNSRegDomain);
			SetSCPrefsBrowseDomain(m, &dDNSRegDomain, mDNSfalse); // if we were automatically browsing in our registration domain, stop
		}

		AssignDomainName(&dDNSRegDomain, &RegDomain);
	
		if (dDNSRegDomain.c[0])
		{
			dDNSPlatformSetSecretForDomain(m, &dDNSRegDomain);
			AddDefRegDomain(&dDNSRegDomain);
			SetSCPrefsBrowseDomain(m, &dDNSRegDomain, mDNStrue);
		}
	}
	
	// Add new browse domains to internal list
	
	if ( BrowseDomains )
		{
		SetSCPrefsBrowseDomains( m, BrowseDomains, mDNStrue );
		}

	// Remove old browse domains from internal list
	
	if ( dDNSBrowseDomains ) 
		{
		SetSCPrefsBrowseDomains( m, dDNSBrowseDomains, mDNSfalse );
		mDNS_FreeDNameList( dDNSBrowseDomains );
		}

	// Replace the old browse domains array with the new array
	
	dDNSBrowseDomains = BrowseDomains;

	
	if (!SameDomainName(&fqdn, &dDNSHostname))
		{
		if (dDNSHostname.c[0]) mDNS_RemoveDynDNSHostName(m, &dDNSHostname);
		AssignDomainName(&dDNSHostname, &fqdn);
		if (dDNSHostname.c[0])
			{
			dDNSPlatformSetSecretForDomain(m, &fqdn); // no-op if "zone" secret, above, is to be used for hostname
			mDNS_AddDynDNSHostName(m, &dDNSHostname, SCPrefsdDNSCallback, mDNSNULL);
			dDNSPlatformSetNameStatus(&dDNSHostname, 1);
			}
		}

    // get DNS settings
	// YO SCDynamicStoreRef store = SCDynamicStoreCreate(mDNSNULL, CFSTR("mDNSResponder:dDNSConfigChanged"), mDNSNULL, mDNSNULL);
	// YO if (!store) return;
	
	// YO key = SCDynamicStoreKeyCreateNetworkGlobalEntity(mDNSNULL, kSCDynamicStoreDomainState, kSCEntNetDNS);
	// YO if (!key) {  LogMsg("ERROR: DNSConfigChanged - SCDynamicStoreKeyCreateNetworkGlobalEntity"); CFRelease(store); return;  }
	// YO dict = SCDynamicStoreCopyValue(store, key);
	// YO CFRelease(key);

	// handle any changes to search domains and DNS server addresses
	if ( dDNSPlatformRegisterSplitDNS(m) != mStatus_NoError)
		if (dict) RegisterNameServers( m );  // fall back to non-split DNS aware configuration on failure
	RegisterSearchDomains( m );  // note that we register name servers *before* search domains
	// if (dict) CFRelease(dict);

	// get IPv4 settings
	// YO key = SCDynamicStoreKeyCreateNetworkGlobalEntity(mDNSNULL,kSCDynamicStoreDomainState, kSCEntNetIPv4);
	// YO if (!key) {  LogMsg("ERROR: RouterChanged - SCDynamicStoreKeyCreateNetworkGlobalEntity"); CFRelease(store); return;  }
	// YO dict = SCDynamicStoreCopyValue(store, key);
	// YO CFRelease(key);
	// YO CFRelease(store);
	// YO if (!dict)
	// YO	{ mDNS_SetPrimaryInterfaceInfo(m, mDNSNULL, mDNSNULL); return; } // lost v4

	// handle router changes
	// YO mDNSAddr r;
	// YO char buf[256];
	// YO r.type = mDNSAddrType_IPv4;
	// YO r.ip.v4.NotAnInteger = 0;
	// YO CFStringRef router = CFDictionaryGetValue(dict, kSCPropNetIPv4Router);
	// YO if (router)
	// YO	{
	// YO	if (!CFStringGetCString(router, buf, 256, kCFStringEncodingUTF8))
	// YO		LogMsg("Could not convert router to CString");
	// YO	else inet_aton(buf, (struct in_addr *)&r.ip.v4);
	// YO	}

	// handle router and primary interface changes

	ip.type = r.type = mDNSAddrType_IPv4;
	ip.ip.v4.NotAnInteger = r.ip.v4.NotAnInteger = 0;
	
	if ( dDNSPlatformGetPrimaryInterface( m, &ip, &r ) == mStatus_NoError )
		{
		mDNS_SetPrimaryInterfaceInfo(m, &ip, r.ip.v4.NotAnInteger ? &r : mDNSNULL);
		}

	return mStatus_NoError;
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

mStatus dDNS_InitDNSConfig(mDNS *const m)
	{
	mStatus err;

	// start query for domains to be used in default (empty string domain) browses
	err = mDNS_GetDomains(m, &LegacyBrowseDomainQ, mDNS_DomainTypeBrowseLegacy, NULL, mDNSInterface_LocalOnly, FoundDefBrowseDomain, NULL);

	// provide .local automatically
	SetSCPrefsBrowseDomain(m, &localdomain, mDNStrue);
    return mStatus_NoError;
}

void
dDNS_FreeIPAddrList(IPAddrListElem * list)
{
	IPAddrListElem * fptr;

	while (list)
	{
		fptr = list;
		list = list->next;
		mDNSPlatformMemFree(fptr);
	}
}
