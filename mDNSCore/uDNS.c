/*
 * Copyright (c) 2002-2024 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * To Do:
 * Elimate all mDNSPlatformMemAllocate/mDNSPlatformMemFree from this code -- the core code
 * is supposed to be malloc-free so that it runs in constant memory determined at compile-time.
 * Any dynamic run-time requirements should be handled by the platform layer below or client layer above
 */

#include "uDNS.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
#include "dnssd_analytics.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, SYMPTOMS)
#include "SymptomReporter.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#include "mdns_strict.h"

#if (defined(_MSC_VER))
// Disable "assignment within conditional expression".
// Other compilers understand the convention that if you place the assignment expression within an extra pair
// of parentheses, this signals to the compiler that you really intended an assignment and no warning is necessary.
// The Microsoft compiler doesn't understand this convention, so in the absense of any other way to signal
// to the compiler that the assignment is intentional, we have to just turn this warning off completely.
    #pragma warning(disable:4706)
#endif

// For domain enumeration and automatic browsing
// This is the user's DNS search list.
// In each of these domains we search for our special pointer records (lb._dns-sd._udp.<domain>, etc.)
// to discover recommended domains for domain enumeration (browse, default browse, registration,
// default registration) and possibly one or more recommended automatic browsing domains.
mDNSexport SearchListElem *SearchList = mDNSNULL;

// The value can be set to true by the Platform code e.g., MacOSX uses the plist mechanism
mDNSBool StrictUnicastOrdering = mDNSfalse;

extern mDNS mDNSStorage;

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
// We keep track of the number of unicast DNS servers and log a message when we exceed 64.
// Currently the unicast queries maintain a 128 bit map to track the valid DNS servers for that
// question. Bit position is the index into the DNS server list. This is done so to try all
// the servers exactly once before giving up. If we could allocate memory in the core, then
// arbitrary limitation of 128 DNSServers can be removed.
#define MAX_UNICAST_DNS_SERVERS 128
#endif

#define SetNextuDNSEvent(m, rr) { \
        if ((m)->NextuDNSEvent - ((rr)->LastAPTime + (rr)->ThisAPInterval) >= 0)                                                                              \
            (m)->NextuDNSEvent = ((rr)->LastAPTime + (rr)->ThisAPInterval);                                                                         \
}

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    #define DNS_PUSH_SERVER_INVALID_SERIAL 0
#endif

#ifndef UNICAST_DISABLED

// ***************************************************************************
// MARK: - General Utility Functions

// set retry timestamp for record with exponential backoff
mDNSlocal void SetRecordRetry(mDNS *const m, AuthRecord *rr, mDNSu32 random)
{
    rr->LastAPTime = m->timenow;

    if (rr->expire && rr->refreshCount < MAX_UPDATE_REFRESH_COUNT)
    {
        mDNSs32 remaining = rr->expire - m->timenow;
        rr->refreshCount++;
        if (remaining > MIN_UPDATE_REFRESH_TIME)
        {
            // Refresh at 70% + random (currently it is 0 to 10%)
            rr->ThisAPInterval =  7 * (remaining/10) + (random ? random : mDNSRandom(remaining/10));
            // Don't update more often than 5 minutes
            if (rr->ThisAPInterval < MIN_UPDATE_REFRESH_TIME)
                rr->ThisAPInterval = MIN_UPDATE_REFRESH_TIME;
            LogInfo("SetRecordRetry refresh in %d of %d for %s",
                    rr->ThisAPInterval/mDNSPlatformOneSecond, (rr->expire - m->timenow)/mDNSPlatformOneSecond, ARDisplayString(m, rr));
        }
        else
        {
            rr->ThisAPInterval = MIN_UPDATE_REFRESH_TIME;
            LogInfo("SetRecordRetry clamping to min refresh in %d of %d for %s",
                    rr->ThisAPInterval/mDNSPlatformOneSecond, (rr->expire - m->timenow)/mDNSPlatformOneSecond, ARDisplayString(m, rr));
        }
        return;
    }

    rr->expire = 0;

    rr->ThisAPInterval = rr->ThisAPInterval * QuestionIntervalStep; // Same Retry logic as Unicast Queries
    if (rr->ThisAPInterval < INIT_RECORD_REG_INTERVAL)
        rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
    if (rr->ThisAPInterval > MAX_RECORD_REG_INTERVAL)
        rr->ThisAPInterval = MAX_RECORD_REG_INTERVAL;

    LogInfo("SetRecordRetry retry in %d ms for %s", rr->ThisAPInterval, ARDisplayString(m, rr));
}

// ***************************************************************************
// MARK: - Name Server List Management

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
mDNSexport DNSServer *mDNS_AddDNSServer(mDNS *const m, const domainname *domain, const mDNSInterfaceID interface,
    const mDNSs32 serviceID, const mDNSAddr *addr, const mDNSIPPort port, ScopeType scopeType, mDNSu32 timeout,
    mDNSBool isCell, mDNSBool isExpensive, mDNSBool isConstrained, mDNSBool isCLAT46, mDNSu32 resGroupID,
    mDNSBool usableA, mDNSBool usableAAAA, mDNSBool reqDO)
{
    DNSServer **p;
    DNSServer *server;
    int       dnsCount = CountOfUnicastDNSServers(m);
    if (dnsCount >= MAX_UNICAST_DNS_SERVERS)
    {
        LogMsg("mDNS_AddDNSServer: DNS server count of %d reached, not adding this server", dnsCount);
        return mDNSNULL;
    }

    if (!domain) domain = (const domainname *)"";

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "mDNS_AddDNSServer(%d): Adding " PRI_IP_ADDR " for " PRI_DM_NAME " interface " PUB_S " (%p), serviceID %u, "
        "scopeType %d, resGroupID %u" PUB_S PUB_S PUB_S PUB_S PUB_S PUB_S PUB_S,
        dnsCount + 1, addr, DM_NAME_PARAM(domain), InterfaceNameForID(&mDNSStorage, interface), interface, serviceID,
        (int)scopeType, resGroupID,
        usableA       ? ", usableA"     : "",
        usableAAAA    ? ", usableAAAA"  : "",
        isCell        ? ", cell"        : "",
        isExpensive   ? ", expensive"   : "",
        isConstrained ? ", constrained" : "",
        isCLAT46      ? ", CLAT46"      : "",
        reqDO         ? ", reqDO"       : "");

    mDNS_CheckLock(m);

    // Scan our existing list to see if we already have a matching record for this DNS resolver
    for (p = &m->DNSServers; (server = *p) != mDNSNULL; p = &server->next)
    {
        if (server->interface       != interface)       continue;
        if (server->serviceID       != serviceID)       continue;
        if (!mDNSSameAddress(&server->addr, addr))      continue;
        if (!mDNSSameIPPort(server->port, port))        continue;
        if (!SameDomainName(&server->domain, domain))   continue;
        if (server->scopeType       != scopeType)       continue;
        if (server->timeout         != timeout)         continue;
        if (!server->usableA        != !usableA)        continue;
        if (!server->usableAAAA     != !usableAAAA)     continue;
        if (!server->isCell         != !isCell)         continue;
        if (!(server->flags & DNSServerFlag_Delete))
        {
            debugf("Note: DNS Server %#a:%d for domain %##s (%p) registered more than once",
                addr, mDNSVal16(port), domain->c, interface);
        }
        // If we found a matching record, cut it from the list
        // (and if we’re *not* resurrecting a record that was marked for deletion, it’s a duplicate,
        // and the debugf message signifies that we’re collapsing duplicate entries into one)
        *p = server->next;
        server->next = mDNSNULL;
        break;
    }

    // If we broke out because we found an existing matching record, advance our pointer to the end of the list
    while (*p)
    {
        p = &(*p)->next;
    }

    if (server)
    {
        if (server->flags & DNSServerFlag_Delete)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, SYMPTOMS)
            server->flags &= ~DNSServerFlag_Unreachable;
#endif
            server->flags &= ~DNSServerFlag_Delete;
        }
        server->isExpensive   = isExpensive;
        server->isConstrained = isConstrained;
        server->isCLAT46      = isCLAT46;
        *p = server;    // Append resurrected record at end of list
    }
    else
    {
        server = (DNSServer *) mDNSPlatformMemAllocateClear(sizeof(*server));
        if (!server)
        {
            LogMsg("Error: mDNS_AddDNSServer - malloc");
        }
        else
        {
            server->interface     = interface;
            server->serviceID     = serviceID;
            server->addr          = *addr;
            server->port          = port;
            server->scopeType     = scopeType;
            server->timeout       = timeout;
            server->usableA       = usableA;
            server->usableAAAA    = usableAAAA;
            server->isCell        = isCell;
            server->isExpensive   = isExpensive;
            server->isConstrained = isConstrained;
            server->isCLAT46      = isCLAT46;
            AssignDomainName(&server->domain, domain);
            *p = server; // Append new record at end of list
        }
    }
    if (server)
    {
        server->penaltyTime = 0;
        // We always update the ID (not just when we allocate a new instance) because we want
        // all the resGroupIDs for a particular domain to match.
        server->resGroupID  = resGroupID;
    }
    return(server);
}

// PenalizeDNSServer is called when the number of queries to the unicast
// DNS server exceeds MAX_UCAST_UNANSWERED_QUERIES or when we receive an
// error e.g., SERV_FAIL from DNS server.
mDNSexport void PenalizeDNSServer(mDNS *const m, DNSQuestion *q, mDNSOpaque16 responseFlags)
{
    DNSServer *new;
    DNSServer *orig = q->qDNSServer;
    mDNSu8 rcode = '\0';

    mDNS_CheckLock(m);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
              "PenalizeDNSServer: Penalizing DNS server " PRI_IP_ADDR " question for question %p " PRI_DM_NAME " (" PUB_S ") SuppressUnusable %d",
              (q->qDNSServer ? &q->qDNSServer->addr : mDNSNULL), q, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->SuppressUnusable);

    // If we get error from any DNS server, remember the error. If all of the servers,
    // return the error, then return the first error.
    if (mDNSOpaque16IsZero(q->responseFlags))
        q->responseFlags = responseFlags;

    rcode = (mDNSu8)(responseFlags.b[1] & kDNSFlag1_RC_Mask);

    // After we reset the qDNSServer to NULL, we could get more SERV_FAILS that might end up
    // penalizing again.
    if (!q->qDNSServer)
        goto end;

    // If strict ordering of unicast servers needs to be preserved, we just lookup
    // the next best match server below
    //
    // If strict ordering is not required which is the default behavior, we penalize the server
    // for DNSSERVER_PENALTY_TIME. We may also use additional logic e.g., don't penalize for PTR
    // in the future.

    if (!StrictUnicastOrdering)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "PenalizeDNSServer: Strict Unicast Ordering is FALSE");
        // We penalize the server so that new queries don't pick this server for DNSSERVER_PENALTY_TIME
        // XXX Include other logic here to see if this server should really be penalized
        //
        if (q->qtype == kDNSType_PTR)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "PenalizeDNSServer: Not Penalizing PTR question");
        }
        else if ((rcode == kDNSFlag1_RC_FormErr) || (rcode == kDNSFlag1_RC_ServFail) || (rcode == kDNSFlag1_RC_NotImpl))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "PenalizeDNSServer: Not Penalizing DNS Server since it at least responded with rcode %d", rcode);
        }
        else
        {
            const char *reason = "";
            if (rcode == kDNSFlag1_RC_Refused)
            {
                reason = " because server refused to answer";
            }
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "PenalizeDNSServer: Penalizing question type %d" PUB_S,
                      q->qtype, reason);
            q->qDNSServer->penaltyTime = NonZeroTime(m->timenow + DNSSERVER_PENALTY_TIME);
        }
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "PenalizeDNSServer: Strict Unicast Ordering is TRUE");
    }

end:
    new = GetServerForQuestion(m, q);

    if (new == orig)
    {
        if (new)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "PenalizeDNSServer: ERROR!! GetServerForQuestion returned the same server " PRI_IP_ADDR ":%d",
                      &new->addr, mDNSVal16(new->port));
            q->ThisQInterval = 0;   // Inactivate this question so that we dont bombard the network
        }
        else
        {
            // When we have no more DNS servers, we might end up calling PenalizeDNSServer multiple
            // times when we receive SERVFAIL from delayed packets in the network e.g., DNS server
            // is slow in responding and we have sent three queries. When we repeatedly call, it is
            // okay to receive the same NULL DNS server. Next time we try to send the query, we will
            // realize and re-initialize the DNS servers.
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "PenalizeDNSServer: GetServerForQuestion returned the same server NULL");
        }
    }
    else
    {
        // The new DNSServer is set in DNSServerChangeForQuestion
        DNSServerChangeForQuestion(m, q, new);

        if (new)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "PenalizeDNSServer: Server for " PRI_DM_NAME " (" PUB_S ") changed to " PRI_IP_ADDR ":%d (" PRI_DM_NAME ")",
                      DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), &q->qDNSServer->addr, mDNSVal16(q->qDNSServer->port), DM_NAME_PARAM(&q->qDNSServer->domain));
            // We want to try the next server immediately. As the question may already have backed off, reset
            // the interval. We do this only the first time when we try all the DNS servers. Once we reached the end of
            // list and retrying all the servers again e.g., at least one server failed to respond in the previous try, we
            // use the normal backoff which is done in uDNS_CheckCurrentQuestion when we send the packet out.
            if (!q->triedAllServersOnce)
            {
                q->ThisQInterval = InitialQuestionInterval;
                q->LastQTime  = m->timenow - q->ThisQInterval;
                SetNextQueryTime(m, q);
            }
        }
        else
        {
            // We don't have any more DNS servers for this question. If some server in the list did not return
            // any response, we need to keep retrying till we get a response. uDNS_CheckCurrentQuestion handles
            // this case.
            //
            // If all servers responded with a negative response, We need to do two things. First, generate a
            // negative response so that applications get a reply. We also need to reinitialize the DNS servers
            // so that when the cache expires, we can restart the query.  We defer this up until we generate
            // a negative cache response in uDNS_CheckCurrentQuestion.
            //
            // Be careful not to touch the ThisQInterval here. For a normal question, when we answer the question
            // in AnswerCurrentQuestionWithResourceRecord will set ThisQInterval to MaxQuestionInterval and hence
            // the next query will not happen until cache expiry. If it is a long lived question,
            // AnswerCurrentQuestionWithResourceRecord will not set it to MaxQuestionInterval. In that case,
            // we want the normal backoff to work.
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "PenalizeDNSServer: Server for %p, " PRI_DM_NAME " (" PUB_S ") changed to NULL, Interval %d",
                      q, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->ThisQInterval);
        }
        q->unansweredQueries = 0;

    }
}
#endif // !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)

// ***************************************************************************
// MARK: - authorization management

mDNSlocal DomainAuthInfo *GetAuthInfoForName_direct(mDNS *m, const domainname *const name)
{
    const domainname *n = name;
    while (n->c[0])
    {
        DomainAuthInfo *ptr;
        for (ptr = m->AuthInfoList; ptr; ptr = ptr->next)
            if (SameDomainName(&ptr->domain, n))
            {
                debugf("GetAuthInfoForName %##s Matched %##s Key name %##s", name->c, ptr->domain.c, ptr->keyname.c);
                return(ptr);
            }
        n = (const domainname *)(n->c + 1 + n->c[0]);
    }
    //LogInfo("GetAuthInfoForName none found for %##s", name->c);
    return mDNSNULL;
}

// MUST be called with lock held
mDNSexport DomainAuthInfo *GetAuthInfoForName_internal(mDNS *m, const domainname *const name)
{
    DomainAuthInfo **p = &m->AuthInfoList;

    mDNS_CheckLock(m);

    // First purge any dead keys from the list
    while (*p)
    {
        if ((*p)->deltime && m->timenow - (*p)->deltime >= 0)
        {
            DNSQuestion *q;
            DomainAuthInfo *info = *p;
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "GetAuthInfoForName_internal deleting expired key " PRI_DM_NAME " " PRI_DM_NAME,
                DM_NAME_PARAM(&info->domain), DM_NAME_PARAM(&info->keyname));
            *p = info->next;    // Cut DomainAuthInfo from list *before* scanning our question list updating AuthInfo pointers
            for (q = m->Questions; q; q=q->next)
                if (q->AuthInfo == info)
                {
                    q->AuthInfo = GetAuthInfoForName_direct(m, &q->qname);
                    debugf("GetAuthInfoForName_internal updated q->AuthInfo from %##s to %##s for %##s (%s)",
                           info->domain.c, q->AuthInfo ? q->AuthInfo->domain.c : mDNSNULL, q->qname.c, DNSTypeName(q->qtype));
                }

            // Probably not essential, but just to be safe, zero out the secret key data
            // so we don't leave it hanging around in memory
            // (where it could potentially get exposed via some other bug)
            mDNSPlatformMemZero(info, sizeof(*info));
            mDNSPlatformMemFree(info);
        }
        else
            p = &(*p)->next;
    }

    return(GetAuthInfoForName_direct(m, name));
}

mDNSexport DomainAuthInfo *GetAuthInfoForName(mDNS *m, const domainname *const name)
{
    DomainAuthInfo *d;
    mDNS_Lock(m);
    d = GetAuthInfoForName_internal(m, name);
    mDNS_Unlock(m);
    return(d);
}

// MUST be called with the lock held
mDNSexport mStatus mDNS_SetSecretForDomain(mDNS *m, DomainAuthInfo *info,
                                           const domainname *domain, const domainname *keyname, const char *b64keydata, const domainname *hostname, mDNSIPPort *port)
{
    DNSQuestion *q;
    DomainAuthInfo **p = &m->AuthInfoList;
    if (!info || !b64keydata)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "No DomainAuthInfo or Base64 encoded secret - "
            "info: %p, b64keydata: %p", info, b64keydata);
        return mStatus_BadParamErr;
    }

    if (DNSDigest_ConstructHMACKeyfromBase64(info, b64keydata) < 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO, "Could not convert shared secret from base64 - "
            "domain: " PRI_DM_NAME ", key name: " PRI_DM_NAME ".", DM_NAME_PARAM(domain), DM_NAME_PARAM(keyname));
        return mStatus_BadParamErr;
    }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO, "Setting shared secret for domain - "
        "domain: " PRI_DM_NAME ", key name: " PRI_DM_NAME ".", DM_NAME_PARAM(domain), DM_NAME_PARAM(keyname));

    AssignDomainName(&info->domain,  domain);
    AssignDomainName(&info->keyname, keyname);
    if (hostname)
        AssignDomainName(&info->hostname, hostname);
    else
        info->hostname.c[0] = 0;
    if (port)
        info->port = *port;
    else
        info->port = zeroIPPort;

    // Don't clear deltime until after we've ascertained that b64keydata is valid
    info->deltime = 0;

    while (*p && (*p) != info) p=&(*p)->next;
    if (*p)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO, "DomainAuthInfo already in the list - "
            "domain: " PRI_DM_NAME, DM_NAME_PARAM(&(*p)->domain));
        return mStatus_AlreadyRegistered;
    }

    info->next = mDNSNULL;
    *p = info;

    // Check to see if adding this new DomainAuthInfo has changed the credentials for any of our questions
    for (q = m->Questions; q; q=q->next)
    {
        DomainAuthInfo *newinfo = GetAuthInfoForQuestion(m, q);
        if (q->AuthInfo != newinfo)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "Updating question's AuthInfo - "
                "qname: " PRI_DM_NAME ", qtype: " PUB_DNS_TYPE ", old AuthInfo domain: " PRI_DM_NAME
                ", new AuthInfo domain: " PRI_DM_NAME, DM_NAME_PARAM(&q->qname), DNS_TYPE_PARAM(q->qtype),
                DM_NAME_PARAM(q->AuthInfo ? &q->AuthInfo->domain : mDNSNULL),
                DM_NAME_PARAM(newinfo ? &newinfo->domain : mDNSNULL));
            q->AuthInfo = newinfo;
        }
    }

    return(mStatus_NoError);
}

// ***************************************************************************
// MARK: - NAT Traversal

// Keep track of when to request/refresh the external address using NAT-PMP or UPnP/IGD,
// and do so when necessary
mDNSlocal mStatus uDNS_RequestAddress(mDNS *m)
{
    mStatus err = mStatus_NoError;

    if (!m->NATTraversals)
    {
        m->retryGetAddr = NonZeroTime(m->timenow + FutureTime);
        LogInfo("uDNS_RequestAddress: Setting retryGetAddr to future");
    }
    else if (m->timenow - m->retryGetAddr >= 0)
    {
        if (mDNSv4AddrIsRFC1918(&m->Router.ip.v4))
        {
            static NATAddrRequest req = {NATMAP_VERS, NATOp_AddrRequest};
            static mDNSu8* start = (mDNSu8*)&req;
            mDNSu8* end = start + sizeof(NATAddrRequest);
            err = mDNSPlatformSendUDP(m, start, end, 0, mDNSNULL, &m->Router, NATPMPPort, mDNSfalse);
            debugf("uDNS_RequestAddress: Sent NAT-PMP external address request %d", err);

#ifdef _LEGACY_NAT_TRAVERSAL_
            if (mDNSIPPortIsZero(m->UPnPRouterPort) || mDNSIPPortIsZero(m->UPnPSOAPPort))
            {
                LNT_SendDiscoveryMsg(m);
                debugf("uDNS_RequestAddress: LNT_SendDiscoveryMsg");
            }
            else
            {
                mStatus lnterr = LNT_GetExternalAddress(m);
                if (lnterr)
                    LogMsg("uDNS_RequestAddress: LNT_GetExternalAddress returned error %d", lnterr);

                err = err ? err : lnterr; // NAT-PMP error takes precedence
            }
#endif // _LEGACY_NAT_TRAVERSAL_
        }

        // Always update the interval and retry time, so that even if we fail to send the
        // packet, we won't spin in an infinite loop repeatedly failing to send the packet
        if (m->retryIntervalGetAddr < NATMAP_INIT_RETRY)
        {
            m->retryIntervalGetAddr = NATMAP_INIT_RETRY;
        }
        else if (m->retryIntervalGetAddr < NATMAP_MAX_RETRY_INTERVAL / 2)
        {
            m->retryIntervalGetAddr *= 2;
        }
        else
        {
            m->retryIntervalGetAddr = NATMAP_MAX_RETRY_INTERVAL;
        }

        m->retryGetAddr = NonZeroTime(m->timenow + m->retryIntervalGetAddr);
    }
    else
    {
        debugf("uDNS_RequestAddress: Not time to send address request");
    }

    // Always update NextScheduledNATOp, even if we didn't change retryGetAddr, so we'll
    // be called when we need to send the request(s)
    if (m->NextScheduledNATOp - m->retryGetAddr > 0)
        m->NextScheduledNATOp = m->retryGetAddr;

    return err;
}

mDNSlocal mStatus uDNS_SendNATMsg(mDNS *m, NATTraversalInfo *info, mDNSBool usePCP, mDNSBool unmapping)
{
    mStatus err = mStatus_NoError;

    if (!info)
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "uDNS_SendNATMsg called unexpectedly with NULL info");
        return mStatus_BadParamErr;
    }

    // send msg if the router's address is private (which means it's non-zero)
    if (mDNSv4AddrIsRFC1918(&m->Router.ip.v4))
    {
        if (!usePCP)
        {
            if (!info->sentNATPMP)
            {
                if (info->Protocol)
                {
                    static NATPortMapRequest NATPortReq;
                    static const mDNSu8* end = (mDNSu8 *)&NATPortReq + sizeof(NATPortMapRequest);
                    mDNSu8 *p = (mDNSu8 *)&NATPortReq.NATReq_lease;

                    NATPortReq.vers    = NATMAP_VERS;
                    NATPortReq.opcode  = info->Protocol;
                    NATPortReq.unused  = zeroID;
                    NATPortReq.intport = info->IntPort;
                    NATPortReq.extport = info->RequestedPort;
                    p[0] = (mDNSu8)((info->NATLease >> 24) &  0xFF);
                    p[1] = (mDNSu8)((info->NATLease >> 16) &  0xFF);
                    p[2] = (mDNSu8)((info->NATLease >>  8) &  0xFF);
                    p[3] = (mDNSu8)( info->NATLease        &  0xFF);

                    err = mDNSPlatformSendUDP(m, (mDNSu8 *)&NATPortReq, end, 0, mDNSNULL, &m->Router, NATPMPPort, mDNSfalse);
                    debugf("uDNS_SendNATMsg: Sent NAT-PMP mapping request %d", err);
                }

                // In case the address request already went out for another NAT-T,
                // set the NewAddress to the currently known global external address, so
                // Address-only operations will get the callback immediately
                info->NewAddress = m->ExtAddress;

                // Remember that we just sent a NAT-PMP packet, so we won't resend one later.
                // We do this because the NAT-PMP "Unsupported Version" response has no
                // information about the (PCP) request that triggered it, so we must send
                // NAT-PMP requests for all operations. Without this, we'll send n PCP
                // requests for n operations, receive n NAT-PMP "Unsupported Version"
                // responses, and send n NAT-PMP requests for each of those responses,
                // resulting in (n + n^2) packets sent. We only want to send 2n packets:
                // n PCP requests followed by n NAT-PMP requests.
                info->sentNATPMP = mDNStrue;
            }
        }
        else
        {
            PCPMapRequest req;
            mDNSu8* start = (mDNSu8*)&req;
            mDNSu8* end = start + sizeof(req);
            mDNSu8* p = (mDNSu8*)&req.lifetime;

            req.version = PCP_VERS;
            req.opCode = PCPOp_Map;
            req.reserved = zeroID;

            p[0] = (mDNSu8)((info->NATLease >> 24) &  0xFF);
            p[1] = (mDNSu8)((info->NATLease >> 16) &  0xFF);
            p[2] = (mDNSu8)((info->NATLease >>  8) &  0xFF);
            p[3] = (mDNSu8)( info->NATLease        &  0xFF);

            mDNSAddrMapIPv4toIPv6(&m->AdvertisedV4.ip.v4, &req.clientAddr);

            req.nonce[0] = m->PCPNonce[0];
            req.nonce[1] = m->PCPNonce[1];
            req.nonce[2] = m->PCPNonce[2];

            req.protocol = (info->Protocol == NATOp_MapUDP ? PCPProto_UDP : PCPProto_TCP);

            req.reservedMapOp[0] = 0;
            req.reservedMapOp[1] = 0;
            req.reservedMapOp[2] = 0;

            req.intPort = info->Protocol ? info->IntPort : DiscardPort;
            req.extPort = info->RequestedPort;

            // Since we only support IPv4, even if using the all-zeros address, map it, so
            // the PCP gateway will give us an IPv4 address & not an IPv6 address.
            mDNSAddrMapIPv4toIPv6(&info->NewAddress, &req.extAddress);

            err = mDNSPlatformSendUDP(m, start, end, 0, mDNSNULL, &m->Router, NATPMPPort, mDNSfalse);
            debugf("uDNS_SendNATMsg: Sent PCP Mapping request %d", err);

            // Unset the sentNATPMP flag, so that we'll send a NAT-PMP packet if we
            // receive a NAT-PMP "Unsupported Version" packet. This will result in every
            // renewal, retransmission, etc. being tried first as PCP, then if a NAT-PMP
            // "Unsupported Version" response is received, fall-back & send the request
            // using NAT-PMP.
            info->sentNATPMP = mDNSfalse;

#ifdef _LEGACY_NAT_TRAVERSAL_
            // If an unmapping is being performed, then don't send an LNT discovery message or an LNT port map request.
            if (!unmapping)
            {
                if (mDNSIPPortIsZero(m->UPnPRouterPort) || mDNSIPPortIsZero(m->UPnPSOAPPort))
                {
                    LNT_SendDiscoveryMsg(m);
                    debugf("uDNS_SendNATMsg: LNT_SendDiscoveryMsg");
                }
                else
                {
                    mStatus lnterr = LNT_MapPort(m, info);
                    if (lnterr)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "uDNS_SendNATMsg: LNT_MapPort returned error %d", lnterr);
                    }

                    err = err ? err : lnterr; // PCP error takes precedence
                }
            }
#else
            (void)unmapping; // Unused
#endif // _LEGACY_NAT_TRAVERSAL_
        }
    }

    return(err);
}

mDNSexport void RecreateNATMappings(mDNS *const m, const mDNSu32 waitTicks)
{
    mDNSu32 when = NonZeroTime(m->timenow + waitTicks);
    NATTraversalInfo *n;
    for (n = m->NATTraversals; n; n=n->next)
    {
        n->ExpiryTime    = 0;       // Mark this mapping as expired
        n->retryInterval = NATMAP_INIT_RETRY;
        n->retryPortMap  = when;
        n->lastSuccessfulProtocol = NATTProtocolNone;
        if (!n->Protocol) n->NewResult = mStatus_NoError;
#ifdef _LEGACY_NAT_TRAVERSAL_
        if (n->tcpInfo.sock) { mDNSPlatformTCPCloseConnection(n->tcpInfo.sock); n->tcpInfo.sock = mDNSNULL; }
#endif // _LEGACY_NAT_TRAVERSAL_
    }

    m->PCPNonce[0] = mDNSRandom(-1);
    m->PCPNonce[1] = mDNSRandom(-1);
    m->PCPNonce[2] = mDNSRandom(-1);
    m->retryIntervalGetAddr = 0;
    m->retryGetAddr = when;

#ifdef _LEGACY_NAT_TRAVERSAL_
    LNT_ClearState(m);
#endif // _LEGACY_NAT_TRAVERSAL_

    m->NextScheduledNATOp = m->timenow;     // Need to send packets immediately
}

mDNSexport void natTraversalHandleAddressReply(mDNS *const m, mDNSu16 err, mDNSv4Addr ExtAddr)
{
    static mDNSu16 last_err = 0;
    NATTraversalInfo *n;

    if (err)
    {
        if (err != last_err) LogMsg("Error getting external address %d", err);
        ExtAddr = zerov4Addr;
    }
    else
    {
        LogInfo("Received external IP address %.4a from NAT", &ExtAddr);
        if (mDNSv4AddrIsRFC1918(&ExtAddr))
            LogMsg("Double NAT (external NAT gateway address %.4a is also a private RFC 1918 address)", &ExtAddr);
        if (mDNSIPv4AddressIsZero(ExtAddr))
            err = NATErr_NetFail; // fake error to handle routers that pathologically report success with the zero address
    }

    // Globally remember the most recently discovered address, so it can be used in each
    // new NATTraversal structure
    m->ExtAddress = ExtAddr;

    if (!err) // Success, back-off to maximum interval
        m->retryIntervalGetAddr = NATMAP_MAX_RETRY_INTERVAL;
    else if (!last_err) // Failure after success, retry quickly (then back-off exponentially)
        m->retryIntervalGetAddr = NATMAP_INIT_RETRY;
    // else back-off normally in case of pathological failures

    m->retryGetAddr = m->timenow + m->retryIntervalGetAddr;
    if (m->NextScheduledNATOp - m->retryGetAddr > 0)
        m->NextScheduledNATOp = m->retryGetAddr;

    last_err = err;

    for (n = m->NATTraversals; n; n=n->next)
    {
        // We should change n->NewAddress only when n is one of:
        // 1) a mapping operation that most recently succeeded using NAT-PMP or UPnP/IGD,
        //    because such an operation needs the update now. If the lastSuccessfulProtocol
        //    is currently none, then natTraversalHandlePortMapReplyWithAddress() will be
        //    called should NAT-PMP or UPnP/IGD succeed in the future.
        // 2) an address-only operation that did not succeed via PCP, because when such an
        //    operation succeeds via PCP, it's for the TCP discard port just to learn the
        //    address. And that address may be different than the external address
        //    discovered via NAT-PMP or UPnP/IGD. If the lastSuccessfulProtocol
        //    is currently none, we must update the NewAddress as PCP may not succeed.
        if (!mDNSSameIPv4Address(n->NewAddress, ExtAddr) &&
             (n->Protocol ?
               (n->lastSuccessfulProtocol == NATTProtocolNATPMP || n->lastSuccessfulProtocol == NATTProtocolUPNPIGD) :
               (n->lastSuccessfulProtocol != NATTProtocolPCP)))
        {
            // Needs an update immediately
            n->NewAddress    = ExtAddr;
            n->ExpiryTime    = 0;
            n->retryInterval = NATMAP_INIT_RETRY;
            n->retryPortMap  = m->timenow;
#ifdef _LEGACY_NAT_TRAVERSAL_
            if (n->tcpInfo.sock) { mDNSPlatformTCPCloseConnection(n->tcpInfo.sock); n->tcpInfo.sock = mDNSNULL; }
#endif // _LEGACY_NAT_TRAVERSAL_

            m->NextScheduledNATOp = m->timenow;     // Need to send packets immediately
        }
    }
}

// Both places that call NATSetNextRenewalTime() update m->NextScheduledNATOp correctly afterwards
mDNSlocal void NATSetNextRenewalTime(mDNS *const m, NATTraversalInfo *n)
{
    n->retryInterval = (n->ExpiryTime - m->timenow)/2;
    if (n->retryInterval < NATMAP_MIN_RETRY_INTERVAL)   // Min retry interval is 2 seconds
        n->retryInterval = NATMAP_MIN_RETRY_INTERVAL;
    n->retryPortMap = m->timenow + n->retryInterval;
}

mDNSlocal void natTraversalHandlePortMapReplyWithAddress(mDNS *const m, NATTraversalInfo *n, const mDNSInterfaceID InterfaceID, mDNSu16 err, mDNSv4Addr extaddr, mDNSIPPort extport, mDNSu32 lease, NATTProtocol protocol)
{
    const char *prot = n->Protocol == 0 ? "Add" : n->Protocol == NATOp_MapUDP ? "UDP" : n->Protocol == NATOp_MapTCP ? "TCP" : "???";
    (void)prot;
    n->NewResult = err;
    if (err || lease == 0 || mDNSIPPortIsZero(extport))
    {
        LogInfo("natTraversalHandlePortMapReplyWithAddress: %p Response %s Port %5d External %.4a:%d lease %d error %d",
                n, prot, mDNSVal16(n->IntPort), &extaddr, mDNSVal16(extport), lease, err);
        n->retryInterval = NATMAP_MAX_RETRY_INTERVAL;
        n->retryPortMap = m->timenow + NATMAP_MAX_RETRY_INTERVAL;
        // No need to set m->NextScheduledNATOp here, since we're only ever extending the m->retryPortMap time
        if      (err == NATErr_Refused) n->NewResult = mStatus_NATPortMappingDisabled;
        else if (err > NATErr_None && err <= NATErr_Opcode) n->NewResult = mStatus_NATPortMappingUnsupported;
    }
    else
    {
        if (lease > 999999999UL / mDNSPlatformOneSecond)
            lease = 999999999UL / mDNSPlatformOneSecond;
        n->ExpiryTime = NonZeroTime(m->timenow + lease * mDNSPlatformOneSecond);

        if (!mDNSSameIPv4Address(n->NewAddress, extaddr) || !mDNSSameIPPort(n->RequestedPort, extport))
            LogInfo("natTraversalHandlePortMapReplyWithAddress: %p %s Response %s Port %5d External %.4a:%d changed to %.4a:%d lease %d",
                    n,
                    (n->lastSuccessfulProtocol == NATTProtocolNone    ? "None    " :
                     n->lastSuccessfulProtocol == NATTProtocolNATPMP  ? "NAT-PMP " :
                     n->lastSuccessfulProtocol == NATTProtocolUPNPIGD ? "UPnP/IGD" :
                     n->lastSuccessfulProtocol == NATTProtocolPCP     ? "PCP     " :
                     /* else */                                         "Unknown " ),
                    prot, mDNSVal16(n->IntPort), &n->NewAddress, mDNSVal16(n->RequestedPort),
                    &extaddr, mDNSVal16(extport), lease);

        n->InterfaceID   = InterfaceID;
        n->NewAddress    = extaddr;
        if (n->Protocol) n->RequestedPort = extport; // Don't report the (PCP) external port to address-only operations
        n->lastSuccessfulProtocol = protocol;

        NATSetNextRenewalTime(m, n);            // Got our port mapping; now set timer to renew it at halfway point
        m->NextScheduledNATOp = m->timenow;     // May need to invoke client callback immediately
    }
}

// To be called for NAT-PMP or UPnP/IGD mappings, to use currently discovered (global) address
mDNSexport void natTraversalHandlePortMapReply(mDNS *const m, NATTraversalInfo *n, const mDNSInterfaceID InterfaceID, mDNSu16 err, mDNSIPPort extport, mDNSu32 lease, NATTProtocol protocol)
{
    natTraversalHandlePortMapReplyWithAddress(m, n, InterfaceID, err, m->ExtAddress, extport, lease, protocol);
}

// Must be called with the mDNS_Lock held
mDNSexport mStatus mDNS_StartNATOperation_internal(mDNS *const m, NATTraversalInfo *traversal)
{
    NATTraversalInfo **n;

    LogInfo("mDNS_StartNATOperation_internal %p Protocol %d IntPort %d RequestedPort %d NATLease %d", traversal,
            traversal->Protocol, mDNSVal16(traversal->IntPort), mDNSVal16(traversal->RequestedPort), traversal->NATLease);

    // Note: It important that new traversal requests are appended at the *end* of the list, not prepended at the start
    for (n = &m->NATTraversals; *n; n=&(*n)->next)
    {
        if (traversal == *n)
        {
            LogFatalError("Error! Tried to add a NAT traversal that's already in the active list: request %p Prot %d Int %d TTL %d",
                   traversal, traversal->Protocol, mDNSVal16(traversal->IntPort), traversal->NATLease);
            return(mStatus_AlreadyRegistered);
        }
        if (traversal->Protocol && traversal->Protocol == (*n)->Protocol && mDNSSameIPPort(traversal->IntPort, (*n)->IntPort) &&
            !mDNSSameIPPort(traversal->IntPort, SSHPort))
            LogMsg("Warning: Created port mapping request %p Prot %d Int %d TTL %d "
                   "duplicates existing port mapping request %p Prot %d Int %d TTL %d",
                   traversal, traversal->Protocol, mDNSVal16(traversal->IntPort), traversal->NATLease,
                   *n,        (*n)->Protocol, mDNSVal16((*n)->IntPort), (*n)->NATLease);
    }

    // Initialize necessary fields
    traversal->next            = mDNSNULL;
    traversal->ExpiryTime      = 0;
    traversal->retryInterval   = NATMAP_INIT_RETRY;
    traversal->retryPortMap    = m->timenow;
    traversal->NewResult       = mStatus_NoError;
    traversal->lastSuccessfulProtocol = NATTProtocolNone;
    traversal->sentNATPMP      = mDNSfalse;
    traversal->ExternalAddress = onesIPv4Addr;
    traversal->NewAddress      = zerov4Addr;
    traversal->ExternalPort    = zeroIPPort;
    traversal->Lifetime        = 0;
    traversal->Result          = mStatus_NoError;

    // set default lease if necessary
    if (!traversal->NATLease) traversal->NATLease = NATMAP_DEFAULT_LEASE;

#ifdef _LEGACY_NAT_TRAVERSAL_
    mDNSPlatformMemZero(&traversal->tcpInfo, sizeof(traversal->tcpInfo));
#endif // _LEGACY_NAT_TRAVERSAL_

    if (!m->NATTraversals)      // If this is our first NAT request, kick off an address request too
    {
        m->retryGetAddr         = m->timenow;
        m->retryIntervalGetAddr = NATMAP_INIT_RETRY;
    }

    // If this is an address-only operation, initialize to the current global address,
    // or (in non-PCP environments) we won't know the address until the next external
    // address request/response.
    if (!traversal->Protocol)
    {
        traversal->NewAddress = m->ExtAddress;
    }

    m->NextScheduledNATOp = m->timenow; // This will always trigger sending the packet ASAP, and generate client callback if necessary

    *n = traversal;     // Append new NATTraversalInfo to the end of our list

    return(mStatus_NoError);
}

// Must be called with the mDNS_Lock held
mDNSexport mStatus mDNS_StopNATOperation_internal(mDNS *m, NATTraversalInfo *traversal)
{
    mDNSBool unmap = mDNStrue;
    NATTraversalInfo *p;
    NATTraversalInfo **ptr = &m->NATTraversals;

    while (*ptr && *ptr != traversal) ptr=&(*ptr)->next;
    if (*ptr) *ptr = (*ptr)->next;      // If we found it, cut this NATTraversalInfo struct from our list
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNS_StopNATOperation_internal: NATTraversalInfo %p not found in list", traversal);
        return(mStatus_BadReferenceErr);
    }

    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNS_StopNATOperation_internal %p %d %d %d %d", traversal,
        traversal->Protocol, mDNSVal16(traversal->IntPort), mDNSVal16(traversal->RequestedPort), traversal->NATLease);

    if (m->CurrentNATTraversal == traversal)
        m->CurrentNATTraversal = m->CurrentNATTraversal->next;

    // If there is a match for the operation being stopped, don't send a deletion request (unmap)
    for (p = m->NATTraversals; p; p=p->next)
    {
        if (traversal->Protocol ?
            ((traversal->Protocol == p->Protocol && mDNSSameIPPort(traversal->IntPort, p->IntPort)) ||
             (!p->Protocol && traversal->Protocol == NATOp_MapTCP && mDNSSameIPPort(traversal->IntPort, DiscardPort))) :
            (!p->Protocol || (p->Protocol == NATOp_MapTCP && mDNSSameIPPort(p->IntPort, DiscardPort))))
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "Warning: Removed port mapping request %p Prot %d Int %d TTL %d "
                "duplicates existing port mapping request %p Prot %d Int %d TTL %d",
                traversal, traversal->Protocol, mDNSVal16(traversal->IntPort), traversal->NATLease,
                p, p->Protocol, mDNSVal16(p->IntPort), p->NATLease);
            unmap = mDNSfalse;
        }
    }

    // Even if we DIDN'T make a successful UPnP mapping yet, we might still have a partially-open TCP connection we need to clean up
    // Before zeroing traversal->RequestedPort below, perform the LNT unmapping, which requires the mapping's external port,
    // held by the traversal->RequestedPort variable.
    #ifdef _LEGACY_NAT_TRAVERSAL_
    {
        mStatus err = LNT_UnmapPort(m, traversal);
        if (err)
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "Legacy NAT Traversal - unmap request failed with error %d", err);
        }
    }
    #endif // _LEGACY_NAT_TRAVERSAL_

    if (traversal->ExpiryTime && unmap)
    {
        traversal->NATLease = 0;
        traversal->retryInterval = 0;

        // In case we most recently sent NAT-PMP, we need to set sentNATPMP to false so
        // that we'll send a NAT-PMP request to destroy the mapping. We do this because
        // the NATTraversal struct has already been cut from the list, and the client
        // layer will destroy the memory upon returning from this function, so we can't
        // try PCP first and then fall-back to NAT-PMP. That is, if we most recently
        // created/renewed the mapping using NAT-PMP, we need to destroy it using NAT-PMP
        // now, because we won't get a chance later.
        traversal->sentNATPMP = mDNSfalse;

        // Both NAT-PMP & PCP RFCs state that the suggested port in deletion requests
        // should be zero. And for PCP, the suggested external address should also be
        // zero, specifically, the all-zeros IPv4-mapped address, since we would only
        // would have requested an IPv4 address.
        traversal->RequestedPort = zeroIPPort;
        traversal->NewAddress = zerov4Addr;

        uDNS_SendNATMsg(m, traversal, traversal->lastSuccessfulProtocol != NATTProtocolNATPMP, mDNStrue);
    }

    return(mStatus_NoError);
}

mDNSexport mStatus mDNS_StartNATOperation(mDNS *const m, NATTraversalInfo *traversal)
{
    mStatus status;
    mDNS_Lock(m);
    status = mDNS_StartNATOperation_internal(m, traversal);
    mDNS_Unlock(m);
    return(status);
}

mDNSexport mStatus mDNS_StopNATOperation(mDNS *const m, NATTraversalInfo *traversal)
{
    mStatus status;
    mDNS_Lock(m);
    status = mDNS_StopNATOperation_internal(m, traversal);
    mDNS_Unlock(m);
    return(status);
}

// ***************************************************************************
// MARK: - Long-Lived Queries

mDNSlocal const char *LLQStateToString(LLQ_State state);

// Lock must be held -- otherwise m->timenow is undefined
mDNSlocal void StartLLQPolling(mDNS *const m, DNSQuestion *q)
{
    const mDNSu32 request_id = q->request_id;
    const mDNSu16 question_id = mDNSVal16(q->TargetQID);

    if (q->ThisQInterval != -1)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u] Starting long-lived query polling - "
            "qname: " PRI_DM_NAME ", qtype: " PUB_S ", LLQ_State: " PUB_S ".", request_id, question_id,
            DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), LLQStateToString(q->state));
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[R%u->Q%u] Not starting long-lived query polling since the question has been stopped - "
            "qname: " PRI_DM_NAME ", qtype: " PUB_S ", LLQ_State: " PUB_S ".", request_id, question_id,
            DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), LLQStateToString(q->state));
        return;
    }

    // If we start the LLQ poll for the question, then the query for getting the zone data can be canceled since zone
    // data is not required for LLQ poll to work.
    if (q->nta != mDNSNULL)
    {
        const DNSQuestion *const zone_question = &(q->nta->question);
        const mDNSu16 zone_question_id = mDNSVal16(zone_question->TargetQID);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u->subQ%u] Stop getting the zone data - "
            "zone qname: " PRI_DM_NAME ", zone qtype: " PUB_S ".", request_id, question_id, zone_question_id,
            DM_NAME_PARAM(&zone_question->qname), DNSTypeName(zone_question->qtype));
        CancelGetZoneData(m, q->nta);
        q->nta = mDNSNULL;
    }

    q->state = LLQ_Poll;
    q->ThisQInterval = INIT_UCAST_POLL_INTERVAL;
    // We want to send our poll query ASAP, but the "+ 1" is because if we set the time to now,
    // we risk causing spurious "SendQueries didn't send all its queries" log messages
    q->LastQTime     = m->timenow - q->ThisQInterval + 1;
    SetNextQueryTime(m, q);
}

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
mDNSlocal mDNSu8 *putLLQ(DNSMessage *const msg, mDNSu8 *ptr, const DNSQuestion *const question, const LLQOptData *const data)
{
    AuthRecord rr;
    ResourceRecord *opt = &rr.resrec;
    rdataOPT *optRD;

    //!!!KRS when we implement multiple llqs per message, we'll need to memmove anything past the question section
    ptr = putQuestion(msg, ptr, msg->data + AbsoluteMaxDNSMessageData, &question->qname, question->qtype, question->qclass);
    if (!ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "ERROR: putLLQ - putQuestion");
        return mDNSNULL;
    }

    // locate OptRR if it exists, set pointer to end
    // !!!KRS implement me

    // format opt rr (fields not specified are zero-valued)
    mDNS_SetupResourceRecord(&rr, mDNSNULL, mDNSInterface_Any, kDNSType_OPT, kStandardTTL, kDNSRecordTypeKnownUnique, AuthRecordAny, mDNSNULL, mDNSNULL);
    opt->rrclass    = NormalMaxDNSMessageData;
    opt->rdlength   = sizeof(rdataOPT); // One option in this OPT record
    opt->rdestimate = sizeof(rdataOPT);

    optRD = &rr.resrec.rdata->u.opt[0];
    optRD->opt = kDNSOpt_LLQ;
    optRD->u.llq = *data;
    ptr = PutResourceRecordTTLJumbo(msg, ptr, &msg->h.numAdditionals, opt, 0);
    if (!ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "ERROR: putLLQ - PutResourceRecordTTLJumbo");
        return mDNSNULL;
    }

    return ptr;
}

// Normally we'd just request event packets be sent directly to m->LLQNAT.ExternalPort, except...
// with LLQs over TLS/TCP we're doing a weird thing where instead of requesting packets be sent to ExternalAddress:ExternalPort
// we're requesting that packets be sent to ExternalPort, but at the source address of our outgoing TCP connection.
// Normally, after going through the NAT gateway, the source address of our outgoing TCP connection is the same as ExternalAddress,
// so this is fine, except when the TCP connection ends up going over a VPN tunnel instead.
// To work around this, if we find that the source address for our TCP connection is not a private address, we tell the Dot Mac
// LLQ server to send events to us directly at port 5353 on that address, instead of at our mapped external NAT port.

mDNSlocal mDNSu16 GetLLQEventPort(const mDNS *const m, const mDNSAddr *const dst)
{
    mDNSAddr src;
    mDNSPlatformSourceAddrForDest(&src, dst);
    //LogMsg("GetLLQEventPort: src %#a for dst %#a (%d)", &src, dst, mDNSv4AddrIsRFC1918(&src.ip.v4) ? mDNSVal16(m->LLQNAT.ExternalPort) : 0);
    return(mDNSv4AddrIsRFC1918(&src.ip.v4) ? mDNSVal16(m->LLQNAT.ExternalPort) : mDNSVal16(MulticastDNSPort));
}

// Normally called with llq set.
// May be called with llq NULL, when retransmitting a lost Challenge Response
mDNSlocal void sendChallengeResponse(mDNS *const m, DNSQuestion *const q, const LLQOptData *llq)
{
    mDNSu8 *responsePtr = m->omsg.data;
    LLQOptData llqBuf;

    if (q->tcp) { LogMsg("sendChallengeResponse: ERROR!!: question %##s (%s) tcp non-NULL", q->qname.c, DNSTypeName(q->qtype)); return; }

    if (q->ntries++ == kLLQ_MAX_TRIES)
    {
        LogMsg("sendChallengeResponse: %d failed attempts for LLQ %##s", kLLQ_MAX_TRIES, q->qname.c);
        StartLLQPolling(m,q);
        return;
    }

    if (!llq)       // Retransmission: need to make a new LLQOptData
    {
        llqBuf.vers     = kLLQ_Vers;
        llqBuf.llqOp    = kLLQOp_Setup;
        llqBuf.err      = LLQErr_NoError;   // Don't need to tell server UDP notification port when sending over UDP
        llqBuf.id       = q->id;
        llqBuf.llqlease = q->ReqLease;
        llq = &llqBuf;
    }

    q->LastQTime     = m->timenow;
    q->ThisQInterval = q->tcp ? 0 : (kLLQ_INIT_RESEND * q->ntries * mDNSPlatformOneSecond);     // If using TCP, don't need to retransmit
    SetNextQueryTime(m, q);

    // To simulate loss of challenge response packet, uncomment line below
    //if (q->ntries == 1) return;

    InitializeDNSMessage(&m->omsg.h, q->TargetQID, uQueryFlags);
    responsePtr = putLLQ(&m->omsg, responsePtr, q, llq);
    if (responsePtr)
    {
        mStatus err = mDNSSendDNSMessage(m, &m->omsg, responsePtr, mDNSInterface_Any, mDNSNULL, q->LocalSocket, &q->servAddr, q->servPort, mDNSNULL, mDNSfalse);
        if (err) { LogMsg("sendChallengeResponse: mDNSSendDNSMessage%s failed: %d", q->tcp ? " (TCP)" : "", err); }
    }
    else StartLLQPolling(m,q);
}

mDNSlocal void SetLLQTimer(mDNS *const m, DNSQuestion *const q, const LLQOptData *const llq)
{
    mDNSs32 lease = (mDNSs32)llq->llqlease * mDNSPlatformOneSecond;
    q->ReqLease      = llq->llqlease;
    q->LastQTime     = m->timenow;
    q->expire        = m->timenow + lease;
    q->ThisQInterval = lease/2 + mDNSRandom(lease/10);
    debugf("SetLLQTimer setting %##s (%s) to %d %d", q->qname.c, DNSTypeName(q->qtype), lease/mDNSPlatformOneSecond, q->ThisQInterval/mDNSPlatformOneSecond);
    SetNextQueryTime(m, q);
}

mDNSlocal void recvSetupResponse(mDNS *const m, mDNSu8 rcode, DNSQuestion *const q, const LLQOptData *const llq)
{
    if (rcode && rcode != kDNSFlag1_RC_NXDomain)
    { LogMsg("ERROR: recvSetupResponse %##s (%s) - rcode && rcode != kDNSFlag1_RC_NXDomain", q->qname.c, DNSTypeName(q->qtype)); return; }

    if (llq->llqOp != kLLQOp_Setup)
    { LogMsg("ERROR: recvSetupResponse %##s (%s) - bad op %d", q->qname.c, DNSTypeName(q->qtype), llq->llqOp); return; }

    if (llq->vers != kLLQ_Vers)
    { LogMsg("ERROR: recvSetupResponse %##s (%s) - bad vers %d", q->qname.c, DNSTypeName(q->qtype), llq->vers); return; }

    if (q->state == LLQ_InitialRequest)
    {
        //LogInfo("Got LLQ_InitialRequest");

        if (llq->err) { LogMsg("recvSetupResponse - received llq->err %d from server", llq->err); StartLLQPolling(m,q); return; }

        if (q->ReqLease != llq->llqlease)
            debugf("recvSetupResponse: requested lease %lu, granted lease %lu", q->ReqLease, llq->llqlease);

        // cache expiration in case we go to sleep before finishing setup
        q->ReqLease = llq->llqlease;
        q->expire = m->timenow + ((mDNSs32)llq->llqlease * mDNSPlatformOneSecond);

        // update state
        q->state  = LLQ_SecondaryRequest;
        q->id     = llq->id;
        q->ntries = 0; // first attempt to send response
        sendChallengeResponse(m, q, llq);
    }
    else if (q->state == LLQ_SecondaryRequest)
    {
        if (llq->err) { LogMsg("ERROR: recvSetupResponse %##s (%s) code %d from server", q->qname.c, DNSTypeName(q->qtype), llq->err); StartLLQPolling(m,q); return; }
        if (!mDNSSameOpaque64(&q->id, &llq->id))
        { LogMsg("recvSetupResponse - ID changed.  discarding"); return; }     // this can happen rarely (on packet loss + reordering)
        q->state         = LLQ_Established;
        q->ntries        = 0;
        SetLLQTimer(m, q, llq);
    }
}

mDNSexport uDNS_LLQType uDNS_recvLLQResponse(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
                                             const mDNSAddr *const srcaddr, const mDNSIPPort srcport, DNSQuestion **matchQuestion)
{
    DNSQuestion pktQ, *q;
    if (msg->h.numQuestions && getQuestion(msg, msg->data, end, 0, &pktQ))
    {
        const rdataOPT *opt = GetLLQOptData(m, msg, end);

        for (q = m->Questions; q; q = q->next)
        {
            if (!mDNSOpaque16IsZero(q->TargetQID) && q->LongLived && q->qtype == pktQ.qtype && q->qnamehash == pktQ.qnamehash && SameDomainName(&q->qname, &pktQ.qname))
            {
                debugf("uDNS_recvLLQResponse found %##s (%s) %d %#a %#a %X %X %X %X %d",
                       q->qname.c, DNSTypeName(q->qtype), q->state, srcaddr, &q->servAddr,
                       opt ? opt->u.llq.id.l[0] : 0, opt ? opt->u.llq.id.l[1] : 0, q->id.l[0], q->id.l[1], opt ? opt->u.llq.llqOp : 0);
                if (q->state == LLQ_Poll) debugf("uDNS_LLQ_Events: q->state == LLQ_Poll msg->h.id %d q->TargetQID %d", mDNSVal16(msg->h.id), mDNSVal16(q->TargetQID));
                if (q->state == LLQ_Poll && mDNSSameOpaque16(msg->h.id, q->TargetQID))
                {
                    mDNSCoreResetRecord(m);

                    // Don't reset the state to IntialRequest as we may write that to the dynamic store
                    // and PrefPane might wrongly think that we are "Starting" instead of "Polling". If
                    // we are in polling state because of PCP/NAT-PMP disabled or DoubleNAT, next LLQNATCallback
                    // would kick us back to LLQInitialRequest. So, resetting the state here may not be useful.
                    //
                    // If we have a good NAT (neither PCP/NAT-PMP disabled nor Double-NAT), then we should not be
                    // possibly in polling state. To be safe, we want to retry from the start in that case
                    // as there may not be another LLQNATCallback
                    //
                    // NOTE: We can be in polling state if we cannot resolve the SOA record i.e, servAddr is set to
                    // all ones. In that case, we would set it in LLQ_InitialRequest as it overrides the PCP/NAT-PMP or
                    // Double-NAT state.
                    if (!mDNSAddressIsOnes(&q->servAddr) && !mDNSIPPortIsZero(m->LLQNAT.ExternalPort) &&
                        !m->LLQNAT.Result)
                    {
                        debugf("uDNS_recvLLQResponse got poll response; moving to LLQ_InitialRequest for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
                        q->state         = LLQ_InitialRequest;
                    }
                    q->servPort      = zeroIPPort;      // Clear servPort so that startLLQHandshake will retry the GetZoneData processing
                    q->ThisQInterval = LLQ_POLL_INTERVAL + mDNSRandom(LLQ_POLL_INTERVAL/10);    // Retry LLQ setup in approx 15 minutes
                    q->LastQTime     = m->timenow;
                    SetNextQueryTime(m, q);
                    *matchQuestion = q;
                    return uDNS_LLQ_Entire;     // uDNS_LLQ_Entire means flush stale records; assume a large effective TTL
                }
                // Note: In LLQ Event packets, the msg->h.id does not match our q->TargetQID, because in that case the msg->h.id nonce is selected by the server
                else if (opt && q->state == LLQ_Established && opt->u.llq.llqOp == kLLQOp_Event && mDNSSameOpaque64(&opt->u.llq.id, &q->id))
                {
                    mDNSu8 *ackEnd;
                    //debugf("Sending LLQ ack for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
                    InitializeDNSMessage(&m->omsg.h, msg->h.id, ResponseFlags);
                    ackEnd = putLLQ(&m->omsg, m->omsg.data, q, &opt->u.llq);
                    if (ackEnd) mDNSSendDNSMessage(m, &m->omsg, ackEnd, mDNSInterface_Any, mDNSNULL, q->LocalSocket, srcaddr, srcport, mDNSNULL, mDNSfalse);
                    mDNSCoreResetRecord(m);
                    debugf("uDNS_LLQ_Events: q->state == LLQ_Established msg->h.id %d q->TargetQID %d", mDNSVal16(msg->h.id), mDNSVal16(q->TargetQID));
                    *matchQuestion = q;
                    return uDNS_LLQ_Events;
                }
                if (opt && mDNSSameOpaque16(msg->h.id, q->TargetQID))
                {
                    if (q->state == LLQ_Established && opt->u.llq.llqOp == kLLQOp_Refresh && mDNSSameOpaque64(&opt->u.llq.id, &q->id) && msg->h.numAdditionals && !msg->h.numAnswers)
                    {
                        if (opt->u.llq.err != LLQErr_NoError) LogMsg("recvRefreshReply: received error %d from server", opt->u.llq.err);
                        else
                        {
                            //LogInfo("Received refresh confirmation ntries %d for %##s (%s)", q->ntries, q->qname.c, DNSTypeName(q->qtype));
                            // If we're waiting to go to sleep, then this LLQ deletion may have been the thing
                            // we were waiting for, so schedule another check to see if we can sleep now.
                            if (opt->u.llq.llqlease == 0 && m->SleepLimit) m->NextScheduledSPRetry = m->timenow;
                            GrantCacheExtensions(m, q, opt->u.llq.llqlease);
                            SetLLQTimer(m, q, &opt->u.llq);
                            q->ntries = 0;
                        }
                        mDNSCoreResetRecord(m);
                        *matchQuestion = q;
                        return uDNS_LLQ_Ignore;
                    }
                    if (q->state < LLQ_Established && mDNSSameAddress(srcaddr, &q->servAddr))
                    {
                        LLQ_State oldstate = q->state;
                        recvSetupResponse(m, msg->h.flags.b[1] & kDNSFlag1_RC_Mask, q, &opt->u.llq);
                        mDNSCoreResetRecord(m);
                        // We have a protocol anomaly here in the LLQ definition.
                        // Both the challenge packet from the server and the ack+answers packet have opt->u.llq.llqOp == kLLQOp_Setup.
                        // However, we need to treat them differently:
                        // The challenge packet has no answers in it, and tells us nothing about whether our cache entries
                        // are still valid, so this packet should not cause us to do anything that messes with our cache.
                        // The ack+answers packet gives us the whole truth, so we should handle it by updating our cache
                        // to match the answers in the packet, and only the answers in the packet.
                        *matchQuestion = q;
                        return (oldstate == LLQ_SecondaryRequest ? uDNS_LLQ_Entire : uDNS_LLQ_Ignore);
                    }
                }
            }
        }
        mDNSCoreResetRecord(m);
    }
    *matchQuestion = mDNSNULL;
    return uDNS_LLQ_Not;
}
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)

// Stub definition of TCPSocket_struct so we can access flags field. (Rest of TCPSocket_struct is platform-dependent.)
struct TCPSocket_struct { mDNSIPPort port; TCPSocketFlags flags; /* ... */ };

// tcpCallback is called to handle events (e.g. connection opening and data reception) on TCP connections for
// Private DNS operations -- private queries, private LLQs, private record updates and private service updates
mDNSlocal void tcpCallback(TCPSocket *sock, void *context, mDNSBool ConnectionEstablished, mStatus err)
{
    tcpInfo_t *tcpInfo = (tcpInfo_t *)context;
    mDNSBool closed  = mDNSfalse;
    mDNS      *m       = tcpInfo->m;
    DNSQuestion *const q = tcpInfo->question;
    tcpInfo_t **backpointer =
        q                 ? &q->tcp :
        tcpInfo->rr       ? &tcpInfo->rr->tcp : mDNSNULL;
    if (backpointer && *backpointer != tcpInfo)
        LogMsg("tcpCallback: %d backpointer %p incorrect tcpInfo %p question %p rr %p",
               mDNSPlatformTCPGetFD(tcpInfo->sock), *backpointer, tcpInfo, q, tcpInfo->rr);

    if (err) goto exit;

    if (ConnectionEstablished)
    {
        mDNSu8    *end = ((mDNSu8*) &tcpInfo->request) + tcpInfo->requestLen;
        DomainAuthInfo *AuthInfo;

        // Defensive coding for <rdar://problem/5546824> Crash in mDNSResponder at GetAuthInfoForName_internal + 366
        // Don't know yet what's causing this, but at least we can be cautious and try to avoid crashing if we find our pointers in an unexpected state
        if (tcpInfo->rr && tcpInfo->rr->resrec.name != &tcpInfo->rr->namestorage)
            LogMsg("tcpCallback: ERROR: tcpInfo->rr->resrec.name %p != &tcpInfo->rr->namestorage %p",
                   tcpInfo->rr->resrec.name, &tcpInfo->rr->namestorage);
        if (tcpInfo->rr  && tcpInfo->rr->resrec.name != &tcpInfo->rr->namestorage) return;

        AuthInfo =  tcpInfo->rr  ? GetAuthInfoForName(m, tcpInfo->rr->resrec.name)         : mDNSNULL;

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
     // connection is established - send the message
        if (q && q->LongLived && q->state == LLQ_Established)
        {
            // Lease renewal over TCP, resulting from opening a TCP connection in sendLLQRefresh
            end = ((mDNSu8*) &tcpInfo->request) + tcpInfo->requestLen;
        }
        else if (q && q->LongLived && q->state != LLQ_Poll && !mDNSIPPortIsZero(m->LLQNAT.ExternalPort) && !mDNSIPPortIsZero(q->servPort))
        {
            // Notes:
            // If we have a NAT port mapping, ExternalPort is the external port
            // If we have a routable address so we don't need a port mapping, ExternalPort is the same as our own internal port
            // If we need a NAT port mapping but can't get one, then ExternalPort is zero
            LLQOptData llqData;         // set llq rdata
            llqData.vers  = kLLQ_Vers;
            llqData.llqOp = kLLQOp_Setup;
            llqData.err   = GetLLQEventPort(m, &tcpInfo->Addr); // We're using TCP; tell server what UDP port to send notifications to
            LogInfo("tcpCallback: eventPort %d", llqData.err);
            llqData.id    = zeroOpaque64;
            llqData.llqlease = kLLQ_DefLease;
            InitializeDNSMessage(&tcpInfo->request.h, q->TargetQID, uQueryFlags);
            end = putLLQ(&tcpInfo->request, tcpInfo->request.data, q, &llqData);
            if (!end) { LogMsg("ERROR: tcpCallback - putLLQ"); err = mStatus_UnknownErr; goto exit; }
            AuthInfo = q->AuthInfo;     // Need to add TSIG to this message
            q->ntries = 0; // Reset ntries so that tcp/tls connection failures don't affect sendChallengeResponse failures
        }
        else
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
            if (q)
        {
            mDNSOpaque16 HeaderFlags = uQueryFlags;

            // LLQ Polling mode or non-LLQ uDNS over TCP
            InitializeDNSMessage(&tcpInfo->request.h, q->TargetQID, HeaderFlags);
            end = putQuestion(&tcpInfo->request, tcpInfo->request.data, tcpInfo->request.data + AbsoluteMaxDNSMessageData, &q->qname, q->qtype, q->qclass);

            AuthInfo = q->AuthInfo;     // Need to add TSIG to this message
        }

        err = mDNSSendDNSMessage(m, &tcpInfo->request, end, mDNSInterface_Any, sock, mDNSNULL, &tcpInfo->Addr, tcpInfo->Port, AuthInfo, mDNSfalse);
        if (err) { debugf("ERROR: tcpCallback: mDNSSendDNSMessage - %d", err); err = mStatus_UnknownErr; goto exit; }
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
        if (mDNSSameIPPort(tcpInfo->Port, UnicastDNSPort))
        {
            bool isForCell;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            isForCell = (q && q->dnsservice && mdns_dns_service_interface_is_cellular(q->dnsservice));
#else
            isForCell = (q && q->qDNSServer && q->qDNSServer->isCell);
#endif
            dnssd_analytics_update_dns_query_size(isForCell, dns_transport_Do53, (uint32_t)(end - (mDNSu8 *)&tcpInfo->request));
        }
#endif

        // Record time we sent this question
        if (q)
        {
            mDNS_Lock(m);
            q->LastQTime = m->timenow;
            if (q->ThisQInterval < (256 * mDNSPlatformOneSecond))   // Now we have a TCP connection open, make sure we wait at least 256 seconds before retrying
                q->ThisQInterval = (256 * mDNSPlatformOneSecond);
            SetNextQueryTime(m, q);
            mDNS_Unlock(m);
        }
    }
    else
    {
        long n;
        const mDNSBool Read_replylen = (tcpInfo->nread < 2);  // Do we need to read the replylen field first?
        if (Read_replylen)         // First read the two-byte length preceeding the DNS message
        {
            mDNSu8 *lenptr = (mDNSu8 *)&tcpInfo->replylen;
            n = mDNSPlatformReadTCP(sock, lenptr + tcpInfo->nread, 2 - tcpInfo->nread, &closed);
            if (n < 0)
            {
                LogMsg("ERROR: tcpCallback - attempt to read message length failed (%d)", n);
                err = mStatus_ConnFailed;
                goto exit;
            }
            else if (closed)
            {
                // It's perfectly fine for this socket to close after the first reply. The server might
                // be sending gratuitous replies using UDP and doesn't have a need to leave the TCP socket open.
                // We'll only log this event if we've never received a reply before.
                // BIND 9 appears to close an idle connection after 30 seconds.
                if (tcpInfo->numReplies == 0)
                {
                    LogMsg("ERROR: socket closed prematurely tcpInfo->nread = %d", tcpInfo->nread);
                    err = mStatus_ConnFailed;
                    goto exit;
                }
                else
                {
                    // Note that we may not be doing the best thing if an error occurs after we've sent a second request
                    // over this tcp connection.  That is, we only track whether we've received at least one response
                    // which may have been to a previous request sent over this tcp connection.
                    if (backpointer) *backpointer = mDNSNULL; // Clear client backpointer FIRST so we don't risk double-disposing our tcpInfo_t
                    DisposeTCPConn(tcpInfo);
                    return;
                }
            }

            tcpInfo->nread += n;
            if (tcpInfo->nread < 2) goto exit;

            tcpInfo->replylen = (mDNSu16)((mDNSu16)lenptr[0] << 8 | lenptr[1]);
            if (tcpInfo->replylen < sizeof(DNSMessageHeader))
            { LogMsg("ERROR: tcpCallback - length too short (%d bytes)", tcpInfo->replylen); err = mStatus_UnknownErr; goto exit; }

            tcpInfo->reply = (DNSMessage *) mDNSPlatformMemAllocate(tcpInfo->replylen);
            if (!tcpInfo->reply) { LogMsg("ERROR: tcpCallback - malloc failed"); err = mStatus_NoMemoryErr; goto exit; }
        }

        n = mDNSPlatformReadTCP(sock, ((char *)tcpInfo->reply) + (tcpInfo->nread - 2), tcpInfo->replylen - (tcpInfo->nread - 2), &closed);

        if (n < 0)
        {
            // If this is our only read for this invokation, and it fails, then that's bad.
            // But if we did successfully read some or all of the replylen field this time through,
            // and this is now our second read from the socket, then it's expected that sometimes
            // there may be no more data present, and that's perfectly okay.
            // Assuming failure of the second read is a problem is what caused this bug:
            // <rdar://problem/15043194> mDNSResponder fails to read DNS over TCP packet correctly
            if (!Read_replylen) { LogMsg("ERROR: tcpCallback - read returned %d", n); err = mStatus_ConnFailed; }
            goto exit;
        }
        else if (closed)
        {
            if (tcpInfo->numReplies == 0)
            {
                LogMsg("ERROR: socket closed prematurely tcpInfo->nread = %d", tcpInfo->nread);
                err = mStatus_ConnFailed;
                goto exit;
            }
            else
            {
                // Note that we may not be doing the best thing if an error occurs after we've sent a second request
                // over this tcp connection.  That is, we only track whether we've received at least one response
                // which may have been to a previous request sent over this tcp connection.
                if (backpointer) *backpointer = mDNSNULL; // Clear client backpointer FIRST so we don't risk double-disposing our tcpInfo_t
                DisposeTCPConn(tcpInfo);
                return;
            }
        }

        tcpInfo->nread += n;

        if ((tcpInfo->nread - 2) == tcpInfo->replylen)
        {
            mDNSBool tls;
            DNSMessage *reply = tcpInfo->reply;
            mDNSu8     *end   = (mDNSu8 *)tcpInfo->reply + tcpInfo->replylen;
            mDNSAddr Addr  = tcpInfo->Addr;
            mDNSIPPort Port  = tcpInfo->Port;
            mDNSIPPort srcPort = zeroIPPort;
            tcpInfo->numReplies++;
            tcpInfo->reply    = mDNSNULL;   // Detach reply buffer from tcpInfo_t, to make sure client callback can't cause it to be disposed
            tcpInfo->nread    = 0;
            tcpInfo->replylen = 0;

            // If we're going to dispose this connection, do it FIRST, before calling client callback
            // Note: Sleep code depends on us clearing *backpointer here -- it uses the clearing of rr->tcp
            // as the signal that the DNS deregistration operation with the server has completed, and the machine may now sleep
            // If we clear the tcp pointer in the question, mDNSCoreReceiveResponse cannot find a matching question. Hence
            // we store the minimal information i.e., the source port of the connection in the question itself.
            // Dereference sock before it is disposed in DisposeTCPConn below.

            if (sock->flags & kTCPSocketFlags_UseTLS) tls = mDNStrue;
            else tls = mDNSfalse;

            if (q && q->tcp) {srcPort = q->tcp->SrcPort; q->tcpSrcPort = srcPort;}

            if (backpointer)
                if (!q || !q->LongLived || m->SleepState)
                { *backpointer = mDNSNULL; DisposeTCPConn(tcpInfo); }

            mDNSCoreReceive(m, reply, end, &Addr, Port, tls ? (mDNSAddr *)1 : mDNSNULL, srcPort, 0);
            // USE CAUTION HERE: Invoking mDNSCoreReceive may have caused the environment to change, including canceling this operation itself

            mDNSPlatformMemFree(reply);
            return;
        }
    }

exit:

    if (err)
    {
        // Clear client backpointer FIRST -- that way if one of the callbacks cancels its operation
        // we won't end up double-disposing our tcpInfo_t
        if (backpointer) *backpointer = mDNSNULL;

        mDNS_Lock(m);       // Need to grab the lock to get m->timenow

        if (q)
        {
            if (q->ThisQInterval == 0)
            {
                // We get here when we fail to establish a new TCP/TLS connection that would have been used for a new LLQ request or an LLQ renewal.
                // Note that ThisQInterval is also zero when sendChallengeResponse resends the LLQ request on an extant TCP/TLS connection.
                q->LastQTime = m->timenow;
                if (q->LongLived)
                {
                    // We didn't get the chance to send our request packet before the TCP/TLS connection failed.
                    // We want to retry quickly, but want to back off exponentially in case the server is having issues.
                    // Since ThisQInterval was 0, we can't just multiply by QuestionIntervalStep, we must track the number
                    // of TCP/TLS connection failures using ntries.
                    mDNSu32 count = q->ntries + 1; // want to wait at least 1 second before retrying

                    q->ThisQInterval = InitialQuestionInterval;

                    for (; count; count--)
                        q->ThisQInterval *= QuestionIntervalStep;

                    if (q->ThisQInterval > LLQ_POLL_INTERVAL)
                        q->ThisQInterval = LLQ_POLL_INTERVAL;
                    else
                        q->ntries++;

                    LogMsg("tcpCallback: stream connection for LLQ %##s (%s) failed %d times, retrying in %d ms", q->qname.c, DNSTypeName(q->qtype), q->ntries, q->ThisQInterval);
                }
                else
                {
                    q->ThisQInterval = MAX_UCAST_POLL_INTERVAL;
                    LogMsg("tcpCallback: stream connection for %##s (%s) failed, retrying in %d ms", q->qname.c, DNSTypeName(q->qtype), q->ThisQInterval);
                }
                SetNextQueryTime(m, q);
            }
            else if (NextQSendTime(q) - m->timenow > (q->LongLived ? LLQ_POLL_INTERVAL : MAX_UCAST_POLL_INTERVAL))
            {
                // If we get an error and our next scheduled query for this question is more than the max interval from now,
                // reset the next query to ensure we wait no longer the maximum interval from now before trying again.
                q->LastQTime     = m->timenow;
                q->ThisQInterval = q->LongLived ? LLQ_POLL_INTERVAL : MAX_UCAST_POLL_INTERVAL;
                SetNextQueryTime(m, q);
                LogMsg("tcpCallback: stream connection for %##s (%s) failed, retrying in %d ms", q->qname.c, DNSTypeName(q->qtype), q->ThisQInterval);
            }

            // We're about to dispose of the TCP connection, so we must reset the state to retry over TCP/TLS
            // because sendChallengeResponse will send the query via UDP if we don't have a tcp pointer.
            // Resetting to LLQ_InitialRequest will cause uDNS_CheckCurrentQuestion to call startLLQHandshake, which
            // will attempt to establish a new tcp connection.
            if (q->LongLived && q->state == LLQ_SecondaryRequest)
                q->state = LLQ_InitialRequest;

            // ConnFailed may happen if the server sends a TCP reset or TLS fails, in which case we want to retry establishing the LLQ
            // quickly rather than switching to polling mode.  This case is handled by the above code to set q->ThisQInterval just above.
            // If the error isn't ConnFailed, then the LLQ is in bad shape, so we switch to polling mode.
            if (err != mStatus_ConnFailed)
            {
                if (q->LongLived && q->state != LLQ_Poll) StartLLQPolling(m, q);
            }
        }

        mDNS_Unlock(m);

        DisposeTCPConn(tcpInfo);
    }
}

mDNSlocal tcpInfo_t *MakeTCPConn(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
                                 TCPSocketFlags flags, const mDNSAddr *const Addr, const mDNSIPPort Port, domainname *hostname,
                                 DNSQuestion *const question, AuthRecord *const rr)
{
    mStatus err;
    mDNSIPPort srcport = zeroIPPort;
    tcpInfo_t *info;
    mDNSBool useBackgroundTrafficClass;

    useBackgroundTrafficClass = question ? question->UseBackgroundTraffic : mDNSfalse;

    if ((flags & kTCPSocketFlags_UseTLS) && (!hostname || !hostname->c[0]))
    { LogMsg("MakeTCPConn: TLS connection being setup with NULL hostname"); return mDNSNULL; }

    info = (tcpInfo_t *) mDNSPlatformMemAllocateClear(sizeof(*info));
    if (!info) { LogMsg("ERROR: MakeTCP - memallocate failed"); return(mDNSNULL); }

    if (msg)
    {
        const mDNSu8 *const start = (const mDNSu8 *)msg;
        if ((end < start) || ((end - start) > (int)sizeof(info->request)))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "MakeTCPConn: invalid DNS message pointers -- msg: %p, end: %p", msg, end);
            mDNSPlatformMemFree(info);
            return mDNSNULL;
        }
        info->requestLen = (int)(end - start);
        mDNSPlatformMemCopy(&info->request, msg, info->requestLen);
    }

    info->m          = m;
    info->sock       = mDNSPlatformTCPSocket(flags, Addr->type, &srcport, hostname, useBackgroundTrafficClass);
    info->question   = question;
    info->rr         = rr;
    info->Addr       = *Addr;
    info->Port       = Port;
    info->reply      = mDNSNULL;
    info->replylen   = 0;
    info->nread      = 0;
    info->numReplies = 0;
    info->SrcPort = srcport;

    if (!info->sock) { LogMsg("MakeTCPConn: unable to create TCP socket"); mDNSPlatformMemFree(info); return(mDNSNULL); }
    mDNSPlatformSetSocktOpt(info->sock, mDNSTransport_TCP, Addr->type, question);
    err = mDNSPlatformTCPConnect(info->sock, Addr, Port, (question ? question->InterfaceID : mDNSNULL), tcpCallback, info);

    // Probably suboptimal here.
    // Instead of returning mDNSNULL here on failure, we should probably invoke the callback with an error code.
    // That way clients can put all the error handling and retry/recovery code in one place,
    // instead of having to handle immediate errors in one place and async errors in another.
    // Also: "err == mStatus_ConnEstablished" probably never happens.

    // Don't need to log "connection failed" in customer builds -- it happens quite often during sleep, wake, configuration changes, etc.
    if      (err == mStatus_ConnEstablished) { tcpCallback(info->sock, info, mDNStrue, mStatus_NoError); }
    else if (err != mStatus_ConnPending    ) { LogInfo("MakeTCPConn: connection failed"); DisposeTCPConn(info); return(mDNSNULL); }
    return(info);
}

mDNSexport void DisposeTCPConn(struct tcpInfo_t *tcp)
{
    mDNSPlatformTCPCloseConnection(tcp->sock);
    if (tcp->reply) mDNSPlatformMemFree(tcp->reply);
    mDNSPlatformMemFree(tcp);
}

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
// Lock must be held
mDNSexport void startLLQHandshake(mDNS *m, DNSQuestion *q)
{
    // States prior to LLQ_InitialRequest should not react to NAT Mapping changes.
    // startLLQHandshake is never called with q->state < LLQ_InitialRequest except
    // from LLQNATCallback.   When we are actually trying to do LLQ, then q->state will
    // be equal to or greater than LLQ_InitialRequest when LLQNATCallback calls
    // startLLQHandshake.
    if (q->state < LLQ_InitialRequest)
    {
        return;
    }

    if (m->LLQNAT.clientContext != mDNSNULL) // LLQNAT just started, give it some time
    {
        LogInfo("startLLQHandshake: waiting for NAT status for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        q->ThisQInterval = LLQ_POLL_INTERVAL + mDNSRandom(LLQ_POLL_INTERVAL/10);    // Retry in approx 15 minutes
        q->LastQTime = m->timenow;
        SetNextQueryTime(m, q);
        return;
    }

    // Either we don't have {PCP, NAT-PMP, UPnP/IGD} support (ExternalPort is zero) or behind a Double NAT that may or
    // may not have {PCP, NAT-PMP, UPnP/IGD} support (NATResult is non-zero)
    if (mDNSIPPortIsZero(m->LLQNAT.ExternalPort) || m->LLQNAT.Result)
    {
        LogInfo("startLLQHandshake: Cannot receive inbound packets; will poll for %##s (%s) External Port %d, NAT Result %d",
                q->qname.c, DNSTypeName(q->qtype), mDNSVal16(m->LLQNAT.ExternalPort), m->LLQNAT.Result);
        StartLLQPolling(m, q);
        return;
    }

    if (mDNSIPPortIsZero(q->servPort))
    {
        debugf("startLLQHandshake: StartGetZoneData for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        q->ThisQInterval = LLQ_POLL_INTERVAL + mDNSRandom(LLQ_POLL_INTERVAL/10);    // Retry in approx 15 minutes
        q->LastQTime     = m->timenow;
        SetNextQueryTime(m, q);
        q->servAddr = zeroAddr;
        // We know q->servPort is zero because of check above
        if (q->nta) CancelGetZoneData(m, q->nta);
        q->nta = StartGetZoneData(m, &q->qname, ZoneServiceLLQ, LLQGotZoneData, q);
        return;
    }

    debugf("startLLQHandshake: m->AdvertisedV4 %#a%s Server %#a:%d%s %##s (%s)",
           &m->AdvertisedV4,                     mDNSv4AddrIsRFC1918(&m->AdvertisedV4.ip.v4) ? " (RFC 1918)" : "",
           &q->servAddr, mDNSVal16(q->servPort), mDNSAddrIsRFC1918(&q->servAddr)             ? " (RFC 1918)" : "",
           q->qname.c, DNSTypeName(q->qtype));

    if (q->ntries++ >= kLLQ_MAX_TRIES)
    {
        LogMsg("startLLQHandshake: %d failed attempts for LLQ %##s Polling.", kLLQ_MAX_TRIES, q->qname.c);
        StartLLQPolling(m, q);
    }
    else
    {
        mDNSu8 *end;
        LLQOptData llqData;

        // set llq rdata
        llqData.vers  = kLLQ_Vers;
        llqData.llqOp = kLLQOp_Setup;
        llqData.err   = LLQErr_NoError; // Don't need to tell server UDP notification port when sending over UDP
        llqData.id    = zeroOpaque64;
        llqData.llqlease = kLLQ_DefLease;

        InitializeDNSMessage(&m->omsg.h, q->TargetQID, uQueryFlags);
        end = putLLQ(&m->omsg, m->omsg.data, q, &llqData);
        if (!end) { LogMsg("ERROR: startLLQHandshake - putLLQ"); StartLLQPolling(m,q); return; }

        mDNSSendDNSMessage(m, &m->omsg, end, mDNSInterface_Any, mDNSNULL, q->LocalSocket, &q->servAddr, q->servPort , mDNSNULL, mDNSfalse);

        // update question state
        q->state         = LLQ_InitialRequest;
        q->ReqLease      = kLLQ_DefLease;
        q->ThisQInterval = (kLLQ_INIT_RESEND * mDNSPlatformOneSecond);
        q->LastQTime     = m->timenow;
        SetNextQueryTime(m, q);
    }
}
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)

// forward declaration so GetServiceTarget can do reverse lookup if needed
mDNSlocal void GetStaticHostname(mDNS *m);

mDNSexport const domainname *GetServiceTarget(mDNS *m, AuthRecord *const rr)
{
    debugf("GetServiceTarget %##s", rr->resrec.name->c);

    if (!rr->AutoTarget)        // If not automatically tracking this host's current name, just return the existing target
        return(&rr->resrec.rdata->u.srv.target);
    else
    {
        {
            const int srvcount = CountLabels(rr->resrec.name);
            HostnameInfo *besthi = mDNSNULL, *hi;
            int best = 0;
            for (hi = m->Hostnames; hi; hi = hi->next)
                if (hi->arv4.state == regState_Registered || hi->arv4.state == regState_Refresh ||
                    hi->arv6.state == regState_Registered || hi->arv6.state == regState_Refresh)
                {
                    int x, hostcount = CountLabels(&hi->fqdn);
                    for (x = hostcount < srvcount ? hostcount : srvcount; x > 0 && x > best; x--)
                        if (SameDomainName(SkipLeadingLabels(rr->resrec.name, srvcount - x), SkipLeadingLabels(&hi->fqdn, hostcount - x)))
                        { best = x; besthi = hi; }
                }

            if (besthi) return(&besthi->fqdn);
        }
        if (m->StaticHostname.c[0]) return(&m->StaticHostname);
        else GetStaticHostname(m); // asynchronously do reverse lookup for primary IPv4 address
        LogInfo("GetServiceTarget: Returning NULL for %s", ARDisplayString(m, rr));
        return(mDNSNULL);
    }
}

mDNSlocal const domainname *PUBLIC_UPDATE_SERVICE_TYPE         = (const domainname*)"\x0B_dns-update"     "\x04_udp";
mDNSlocal const domainname *PUBLIC_LLQ_SERVICE_TYPE            = (const domainname*)"\x08_dns-llq"        "\x04_udp";

mDNSlocal const domainname *PRIVATE_UPDATE_SERVICE_TYPE        = (const domainname*)"\x0F_dns-update-tls" "\x04_tcp";
mDNSlocal const domainname *PRIVATE_QUERY_SERVICE_TYPE         = (const domainname*)"\x0E_dns-query-tls"  "\x04_tcp";
mDNSlocal const domainname *PRIVATE_LLQ_SERVICE_TYPE           = (const domainname*)"\x0C_dns-llq-tls"    "\x04_tcp";
mDNSlocal const domainname *DNS_PUSH_NOTIFICATION_SERVICE_TYPE = (const domainname*)"\x0D_dns-push-tls"   "\x04_tcp";

#define ZoneDataSRV(X) ( \
        (X)->ZoneService == ZoneServiceUpdate  ? ((X)->ZonePrivate ? PRIVATE_UPDATE_SERVICE_TYPE : PUBLIC_UPDATE_SERVICE_TYPE) : \
        (X)->ZoneService == ZoneServiceQuery   ? ((X)->ZonePrivate ? PRIVATE_QUERY_SERVICE_TYPE  : (const domainname*)""     ) : \
        (X)->ZoneService == ZoneServiceLLQ     ? ((X)->ZonePrivate ? PRIVATE_LLQ_SERVICE_TYPE    : PUBLIC_LLQ_SERVICE_TYPE   ) : \
        (X)->ZoneService == ZoneServiceDNSPush ? DNS_PUSH_NOTIFICATION_SERVICE_TYPE : (const domainname*)"")

// Forward reference: GetZoneData_StartQuery references GetZoneData_QuestionCallback, and
// GetZoneData_QuestionCallback calls GetZoneData_StartQuery
mDNSlocal mStatus GetZoneData_StartQuery(mDNS *const m, ZoneData *zd, mDNSu16 qtype);

// GetZoneData_QuestionCallback is called from normal client callback context (core API calls allowed)
mDNSexport void GetZoneData_QuestionCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    ZoneData *zd = (ZoneData*)question->QuestionContext;

    debugf("GetZoneData_QuestionCallback: %s %s", AddRecord ? "Add" : "Rmv", RRDisplayString(m, answer));

    if (!AddRecord) return;                                             // Don't care about REMOVE events
    if (AddRecord == QC_addnocache && answer->rdlength == 0) return;    // Don't care about transient failure indications
    if (AddRecord == QC_suppressed && answer->rdlength == 0) return;    // Ignore the suppression result caused by no
                                                                        // DNS service, in which case we should not move
                                                                        // to the next name labels.
    if (answer->rrtype != question->qtype) return;                      // Don't care about CNAMEs

    if (answer->rrtype == kDNSType_SOA)
    {
        debugf("GetZoneData GOT SOA %s", RRDisplayString(m, answer));
        mDNS_StopQuery(m, question);
        if (question->ThisQInterval != -1)
            LogMsg("GetZoneData_QuestionCallback: Question %##s (%s) ThisQInterval %d not -1", question->qname.c, DNSTypeName(question->qtype), question->ThisQInterval);
        if (answer->rdlength)
        {
            AssignDomainName(&zd->ZoneName, answer->name);
            zd->ZoneClass = answer->rrclass;
            GetZoneData_StartQuery(m, zd, kDNSType_SRV);
        }
        else if (zd->CurrentSOA->c[0])
        {
            zd->CurrentSOA = (domainname *)(zd->CurrentSOA->c + zd->CurrentSOA->c[0]+1);
            AssignDomainName(&zd->question.qname, zd->CurrentSOA);
            GetZoneData_StartQuery(m, zd, kDNSType_SOA);
        }
        else
        {
            LogInfo("GetZoneData recursed to root label of %##s without finding SOA", zd->ChildName.c);
            zd->ZoneDataCallback(m, mStatus_NoSuchNameErr, zd);
        }
    }
    else if (answer->rrtype == kDNSType_SRV)
    {
        debugf("GetZoneData GOT SRV %s", RRDisplayString(m, answer));
        mDNS_StopQuery(m, question);
        if (question->ThisQInterval != -1)
            LogMsg("GetZoneData_QuestionCallback: Question %##s (%s) ThisQInterval %d not -1", question->qname.c, DNSTypeName(question->qtype), question->ThisQInterval);
// Right now we don't want to fail back to non-encrypted operations
// If the AuthInfo has the AutoTunnel field set, then we want private or nothing
// <rdar://problem/5687667> BTMM: Don't fallback to unencrypted operations when SRV lookup fails
#if 0
        if (!answer->rdlength && zd->ZonePrivate && zd->ZoneService != ZoneServiceQuery)
        {
            zd->ZonePrivate = mDNSfalse;    // Causes ZoneDataSRV() to yield a different SRV name when building the query
            GetZoneData_StartQuery(m, zd, kDNSType_SRV);        // Try again, non-private this time
        }
        else
#endif
        {
            if (answer->rdlength)
            {
                AssignDomainName(&zd->Host, &answer->rdata->u.srv.target);
                zd->Port = answer->rdata->u.srv.port;
                // The MakeTCPConn path, which is used by everything but DNS Push, won't work at all for
                // IPv6.  This should be fixed for all cases we care about, but for now we make an exception
                // for Push notifications: we do not look up the a record here, but rather rely on the DSO
                // infrastructure to do a GetAddrInfo call on the name and try each IP address in sequence
                // until one connects.  We can't do this for the other use cases because this is in the DSO
                // code, not in MakeTCPConn.  Ultimately the fix for this is to use Network Framework to do
                // the connection establishment for all of these use cases.
                //
                // One implication of this is that if two different zones have DNS push server SRV records
                // pointing to the same server using a different domain name, we will not see these as being
                // the same server, and will not share the connection.   This isn't something we can easily
                // fix, and so the advice if someone runs into this and considers it a problem should be to
                // use the same name.
                //
                // Another issue with this code is that at present, we do not wait for more than one SRV
                // record--we cancel the query as soon as the first one comes in.   This isn't ideal: it
                // would be better to wait until we've gotten all our answers and then pick the one with
                // the highest priority.   Of course, this is unlikely to cause an operational problem in
                // practice, and as with the previous point, the fix is easy: figure out which server you
                // want people to use and don't list any other servers.   Fully switching to Network
                // Framework for this would (I think!) address this problem, or at least make it someone
                // else's problem.
                if (zd->ZoneService != ZoneServiceDNSPush)
                {
                    AssignDomainName(&zd->question.qname, &zd->Host);
                    GetZoneData_StartQuery(m, zd, kDNSType_A);
                }
                else
                {
                    zd->ZoneDataCallback(m, mStatus_NoError, zd);
                }
            }
            else
            {
                zd->ZonePrivate = mDNSfalse;
                zd->Host.c[0] = 0;
                zd->Port = zeroIPPort;
                zd->Addr = zeroAddr;
                // The response does not contain any record in the answer section, indicating that the SRV record with
                // the corresponding name does not exist.
                zd->ZoneDataCallback(m, mStatus_NoSuchRecord, zd);
            }
        }
    }
    else if (answer->rrtype == kDNSType_A)
    {
        debugf("GetZoneData GOT A %s", RRDisplayString(m, answer));
        mDNS_StopQuery(m, question);
        if (question->ThisQInterval != -1)
            LogMsg("GetZoneData_QuestionCallback: Question %##s (%s) ThisQInterval %d not -1", question->qname.c, DNSTypeName(question->qtype), question->ThisQInterval);
        zd->Addr.type  = mDNSAddrType_IPv4;
        zd->Addr.ip.v4 = (answer->rdlength == 4) ? answer->rdata->u.ipv4 : zerov4Addr;
        // In order to simulate firewalls blocking our outgoing TCP connections, returning immediate ICMP errors or TCP resets,
        // the code below will make us try to connect to loopback, resulting in an immediate "port unreachable" failure.
        // This helps us test to make sure we handle this case gracefully
        // <rdar://problem/5607082> BTMM: mDNSResponder taking 100 percent CPU after upgrading to 10.5.1
#if 0
        zd->Addr.ip.v4.b[0] = 127;
        zd->Addr.ip.v4.b[1] = 0;
        zd->Addr.ip.v4.b[2] = 0;
        zd->Addr.ip.v4.b[3] = 1;
#endif
        // The caller needs to free the memory when done with zone data
        zd->ZoneDataCallback(m, mStatus_NoError, zd);
    }
}

// GetZoneData_StartQuery is called from normal client context (lock not held, or client callback)
mDNSlocal mStatus GetZoneData_StartQuery(mDNS *const m, ZoneData *zd, mDNSu16 qtype)
{
    if (qtype == kDNSType_SRV)
    {
        AssignDomainName(&zd->question.qname, ZoneDataSRV(zd));
        AppendDomainName(&zd->question.qname, &zd->ZoneName);
        debugf("lookupDNSPort %##s", zd->question.qname.c);
    }

    // CancelGetZoneData can get called at any time. We should stop the question if it has not been
    // stopped already. A value of -1 for ThisQInterval indicates that the question is not active
    // yet.
    zd->question.ThisQInterval       = -1;
    zd->question.InterfaceID         = mDNSInterface_Any;
    zd->question.flags               = 0;
    //zd->question.qname.c[0]        = 0;           // Already set
    zd->question.qtype               = qtype;
    zd->question.qclass              = kDNSClass_IN;
    zd->question.LongLived           = mDNSfalse;
    zd->question.ExpectUnique        = mDNStrue;
    zd->question.ForceMCast          = mDNSfalse;
    zd->question.ReturnIntermed      = mDNStrue;
    zd->question.SuppressUnusable    = mDNSfalse;
    zd->question.AppendSearchDomains = 0;
    zd->question.TimeoutQuestion     = 0;
    zd->question.WakeOnResolve       = 0;
    zd->question.UseBackgroundTraffic = mDNSfalse;
    zd->question.ProxyQuestion      = 0;
    zd->question.pid                 = mDNSPlatformGetPID();
    zd->question.euid                = 0;
    zd->question.QuestionCallback    = GetZoneData_QuestionCallback;
    zd->question.QuestionContext     = zd;

    //LogMsg("GetZoneData_StartQuery %##s (%s) %p", zd->question.qname.c, DNSTypeName(zd->question.qtype), zd->question.Private);
    return(mDNS_StartQuery(m, &zd->question));
}

// StartGetZoneData is an internal routine (i.e. must be called with the lock already held)
mDNSexport ZoneData *StartGetZoneData(mDNS *const m, const domainname *const name, const ZoneService target, ZoneDataCallback callback, void *ZoneDataContext)
{
    ZoneData *zd = (ZoneData*) mDNSPlatformMemAllocateClear(sizeof(*zd));
    if (!zd) { LogMsg("ERROR: StartGetZoneData - mDNSPlatformMemAllocateClear failed"); return mDNSNULL; }
    AssignDomainName(&zd->ChildName, name);
    zd->ZoneService      = target;
    zd->CurrentSOA       = &zd->ChildName;
    zd->ZoneName.c[0]    = 0;
    zd->ZoneClass        = 0;
    zd->Host.c[0]        = 0;
    zd->Port             = zeroIPPort;
    zd->Addr             = zeroAddr;
    zd->ZonePrivate      = mDNSfalse;
    zd->ZoneDataCallback = callback;
    zd->ZoneDataContext  = ZoneDataContext;

    zd->question.QuestionContext = zd;

    mDNS_DropLockBeforeCallback();      // GetZoneData_StartQuery expects to be called from a normal callback, so we emulate that here
    AssignDomainName(&zd->question.qname, zd->CurrentSOA);
    GetZoneData_StartQuery(m, zd, kDNSType_SOA);
    mDNS_ReclaimLockAfterCallback();

    return zd;
}

// Returns if the question is a GetZoneData question. These questions are special in
// that they are created internally while resolving a private query or LLQs.
mDNSexport mDNSBool IsGetZoneDataQuestion(DNSQuestion *q)
{
    if (q->QuestionCallback == GetZoneData_QuestionCallback) return(mDNStrue);
    else return(mDNSfalse);
}

// GetZoneData queries are a special case -- even if we have a key for them, we don't do them privately,
// because that would result in an infinite loop (i.e. to do a private query we first need to get
// the _dns-query-tls SRV record for the zone, and we can't do *that* privately because to do so
// we'd need to already know the _dns-query-tls SRV record.
// Also, as a general rule, we never do SOA queries privately
mDNSexport DomainAuthInfo *GetAuthInfoForQuestion(mDNS *m, const DNSQuestion *const q)  // Must be called with lock held
{
    if (q->QuestionCallback == GetZoneData_QuestionCallback) return(mDNSNULL);
    if (q->qtype            == kDNSType_SOA                ) return(mDNSNULL);
    return(GetAuthInfoForName_internal(m, &q->qname));
}

// ***************************************************************************
// MARK: - host name and interface management

mDNSlocal void SendRecordRegistration(mDNS *const m, AuthRecord *rr);
mDNSlocal void SendRecordDeregistration(mDNS *m, AuthRecord *rr);
mDNSlocal mDNSBool IsRecordMergeable(mDNS *const m, AuthRecord *rr, mDNSs32 time);

// When this function is called, service record is already deregistered. We just
// have to deregister the PTR and TXT records.
mDNSlocal void UpdateAllServiceRecords(mDNS *const m, AuthRecord *rr, mDNSBool reg)
{
    AuthRecord *r, *srvRR;

    if (rr->resrec.rrtype != kDNSType_SRV) { LogMsg("UpdateAllServiceRecords:ERROR!! ResourceRecord not a service record %s", ARDisplayString(m, rr)); return; }

    if (reg && rr->state == regState_NoTarget) { LogMsg("UpdateAllServiceRecords:ERROR!! SRV record %s in noTarget state during registration", ARDisplayString(m, rr)); return; }

    LogInfo("UpdateAllServiceRecords: ResourceRecord %s", ARDisplayString(m, rr));

    for (r = m->ResourceRecords; r; r=r->next)
    {
        if (!AuthRecord_uDNS(r)) continue;
        srvRR = mDNSNULL;
        if (r->resrec.rrtype == kDNSType_PTR)
            srvRR = r->Additional1;
        else if (r->resrec.rrtype == kDNSType_TXT)
            srvRR = r->DependentOn;
        if (srvRR && srvRR->resrec.rrtype != kDNSType_SRV)
            LogMsg("UpdateAllServiceRecords: ERROR!! Resource record %s wrong, expecting SRV type", ARDisplayString(m, srvRR));
        if (srvRR == rr)
        {
            if (!reg)
            {
                LogInfo("UpdateAllServiceRecords: deregistering %s", ARDisplayString(m, r));
                r->SRVChanged = mDNStrue;
                r->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
                r->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
                r->state = regState_DeregPending;
            }
            else
            {
                // Clearing SRVchanged is a safety measure. If our pevious dereg never
                // came back and we had a target change, we are starting fresh
                r->SRVChanged = mDNSfalse;
                // if it is already registered or in the process of registering, then don't
                // bother re-registering. This happens today for non-BTMM domains where the
                // TXT and PTR get registered before SRV records because of the delay in
                // getting the port mapping. There is no point in re-registering the TXT
                // and PTR records.
                if ((r->state == regState_Registered) ||
                    (r->state == regState_Pending && r->nta && !mDNSIPv4AddressIsZero(r->nta->Addr.ip.v4)))
                    LogInfo("UpdateAllServiceRecords: not registering %s, state %d", ARDisplayString(m, r), r->state);
                else
                {
                    LogInfo("UpdateAllServiceRecords: registering %s, state %d", ARDisplayString(m, r), r->state);
                    ActivateUnicastRegistration(m, r);
                }
            }
        }
    }
}

// Called in normal client context (lock not held)
// Currently only supports SRV records for nat mapping
mDNSlocal void CompleteRecordNatMap(mDNS *m, NATTraversalInfo *n)
{
    const domainname *target;
    domainname *srvt;
    AuthRecord *rr = (AuthRecord *)n->clientContext;
    debugf("SRVNatMap complete %.4a IntPort %u ExternalPort %u NATLease %u", &n->ExternalAddress, mDNSVal16(n->IntPort), mDNSVal16(n->ExternalPort), n->NATLease);

    if (!rr) { LogMsg("CompleteRecordNatMap called with unknown AuthRecord object"); return; }
    if (!n->NATLease) { LogMsg("CompleteRecordNatMap No NATLease for %s", ARDisplayString(m, rr)); return; }

    if (rr->resrec.rrtype != kDNSType_SRV) {LogMsg("CompleteRecordNatMap: Not a service record %s", ARDisplayString(m, rr)); return; }

    if (rr->resrec.RecordType == kDNSRecordTypeDeregistering) { LogInfo("CompleteRecordNatMap called for %s, Service deregistering", ARDisplayString(m, rr)); return; }

    if (rr->state == regState_DeregPending) { LogInfo("CompleteRecordNatMap called for %s, record in DeregPending", ARDisplayString(m, rr)); return; }

    // As we free the zone info after registering/deregistering with the server (See hndlRecordUpdateReply),
    // we need to restart the get zone data and nat mapping request to get the latest mapping result as we can't handle it
    // at this moment. Restart from the beginning.
    if (!rr->nta || mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4))
    {
        LogInfo("CompleteRecordNatMap called for %s but no zone information!", ARDisplayString(m, rr));
        // We need to clear out the NATinfo state so that it will result in re-acquiring the mapping
        // and hence this callback called again.
        if (rr->NATinfo.clientContext)
        {
            mDNS_StopNATOperation_internal(m, &rr->NATinfo);
            rr->NATinfo.clientContext = mDNSNULL;
        }
        rr->state = regState_Pending;
        rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
        rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
        return;
    }

    mDNS_Lock(m);
    // Reevaluate the target always as Target could have changed while
    // we were getting the port mapping (See UpdateOneSRVRecord)
    target = GetServiceTarget(m, rr);
    srvt = GetRRDomainNameTarget(&rr->resrec);
    if (!target || target->c[0] == 0 || mDNSIPPortIsZero(n->ExternalPort))
    {
        if (target && target->c[0])
            LogInfo("CompleteRecordNatMap - Target %##s for ResourceRecord %##s, ExternalPort %d", target->c, rr->resrec.name->c, mDNSVal16(n->ExternalPort));
        else
            LogInfo("CompleteRecordNatMap - no target for %##s, ExternalPort %d", rr->resrec.name->c, mDNSVal16(n->ExternalPort));
        if (srvt) srvt->c[0] = 0;
        rr->state = regState_NoTarget;
        rr->resrec.rdlength = rr->resrec.rdestimate = 0;
        mDNS_Unlock(m);
        UpdateAllServiceRecords(m, rr, mDNSfalse);
        return;
    }
    LogInfo("CompleteRecordNatMap - Target %##s for ResourceRecord %##s, ExternalPort %d", target->c, rr->resrec.name->c, mDNSVal16(n->ExternalPort));
    // This function might get called multiple times during a network transition event. Previosuly, we could
    // have put the SRV record in NoTarget state above and deregistered all the other records. When this
    // function gets called again with a non-zero ExternalPort, we need to set the target and register the
    // other records again.
    if (srvt && !SameDomainName(srvt, target))
    {
        AssignDomainName(srvt, target);
        SetNewRData(&rr->resrec, mDNSNULL, 0);      // Update rdlength, rdestimate, rdatahash
    }

    // SRVChanged is set when when the target of the SRV record changes (See UpdateOneSRVRecord).
    // As a result of the target change, we might register just that SRV Record if it was
    // previously registered and we have a new target OR deregister SRV (and the associated
    // PTR/TXT records) if we don't have a target anymore. When we get a response from the server,
    // SRVChanged state tells that we registered/deregistered because of a target change
    // and hence handle accordingly e.g., if we deregistered, put the records in NoTarget state OR
    // if we registered then put it in Registered state.
    //
    // Here, we are registering all the records again from the beginning. Treat this as first time
    // registration rather than a temporary target change.
    rr->SRVChanged = mDNSfalse;

    // We want IsRecordMergeable to check whether it is a record whose update can be
    // sent with others. We set the time before we call IsRecordMergeable, so that
    // it does not fail this record based on time. We are interested in other checks
    // at this time
    rr->state = regState_Pending;
    rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
    rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
    if (IsRecordMergeable(m, rr, m->timenow + MERGE_DELAY_TIME))
        // Delay the record registration by MERGE_DELAY_TIME so that we can merge them
        // into one update
        rr->LastAPTime += MERGE_DELAY_TIME;
    mDNS_Unlock(m);
    // We call this always even though it may not be necessary always e.g., normal registration
    // process where TXT and PTR gets registered followed by the SRV record after it gets
    // the port mapping. In that case, UpdateAllServiceRecords handles the optimization. The
    // update of TXT and PTR record is required if we entered noTargetState before as explained
    // above.
    UpdateAllServiceRecords(m, rr, mDNStrue);
}

mDNSlocal void StartRecordNatMap(mDNS *m, AuthRecord *rr)
{
    const mDNSu8 *p;
    mDNSu8 protocol;

    if (rr->resrec.rrtype != kDNSType_SRV)
    {
        LogInfo("StartRecordNatMap: Resource Record %##s type %d, not supported", rr->resrec.name->c, rr->resrec.rrtype);
        return;
    }
    p = rr->resrec.name->c;
    //Assume <Service Instance>.<App Protocol>.<Transport protocol>.<Name>
    // Skip the first two labels to get to the transport protocol
    if (p[0]) p += 1 + p[0];
    if (p[0]) p += 1 + p[0];
    if      (SameDomainLabel(p, (mDNSu8 *)"\x4" "_tcp")) protocol = NATOp_MapTCP;
    else if (SameDomainLabel(p, (mDNSu8 *)"\x4" "_udp")) protocol = NATOp_MapUDP;
    else { LogMsg("StartRecordNatMap: could not determine transport protocol of service %##s", rr->resrec.name->c); return; }

    //LogMsg("StartRecordNatMap: clientContext %p IntPort %d srv.port %d %s",
    //  rr->NATinfo.clientContext, mDNSVal16(rr->NATinfo.IntPort), mDNSVal16(rr->resrec.rdata->u.srv.port), ARDisplayString(m, rr));
    if (rr->NATinfo.clientContext) mDNS_StopNATOperation_internal(m, &rr->NATinfo);
    rr->NATinfo.Protocol       = protocol;

    // Shouldn't be trying to set IntPort here --
    // BuildUpdateMessage overwrites srs->RR_SRV.resrec.rdata->u.srv.port with external (mapped) port number
    rr->NATinfo.IntPort        = rr->resrec.rdata->u.srv.port;
    rr->NATinfo.RequestedPort  = rr->resrec.rdata->u.srv.port;
    rr->NATinfo.NATLease       = 0;     // Request default lease
    rr->NATinfo.clientCallback = CompleteRecordNatMap;
    rr->NATinfo.clientContext  = rr;
    mDNS_StartNATOperation_internal(m, &rr->NATinfo);
}

// Unlink an Auth Record from the m->ResourceRecords list.
// When a resource record enters regState_NoTarget initially, mDNS_Register_internal
// does not initialize completely e.g., it cannot check for duplicates etc. The resource
// record is temporarily left in the ResourceRecords list so that we can initialize later
// when the target is resolvable. Similarly, when host name changes, we enter regState_NoTarget
// and we do the same.

// This UnlinkResourceRecord routine is very worrying. It bypasses all the normal cleanup performed
// by mDNS_Deregister_internal and just unceremoniously cuts the record from the active list.
// This is why re-regsitering this record was producing syslog messages like this:
// "Error! Tried to add a NAT traversal that's already in the active list"
// Right now UnlinkResourceRecord is fortunately only called by RegisterAllServiceRecords,
// which then immediately calls mDNS_Register_internal to re-register the record, which probably
// masked more serious problems. Any other use of UnlinkResourceRecord is likely to lead to crashes.
// For now we'll workaround that specific problem by explicitly calling mDNS_StopNATOperation_internal,
// but long-term we should either stop cancelling the record registration and then re-registering it,
// or if we really do need to do this for some reason it should be done via the usual
// mDNS_Deregister_internal path instead of just cutting the record from the list.

mDNSlocal mStatus UnlinkResourceRecord(mDNS *const m, AuthRecord *const rr)
{
    AuthRecord **list = &m->ResourceRecords;
    while (*list && *list != rr) list = &(*list)->next;
    if (*list)
    {
        *list = rr->next;
        rr->next = mDNSNULL;

        // Temporary workaround to cancel any active NAT mapping operation
        if (rr->NATinfo.clientContext)
        {
            mDNS_StopNATOperation_internal(m, &rr->NATinfo);
            rr->NATinfo.clientContext = mDNSNULL;
            if (rr->resrec.rrtype == kDNSType_SRV) rr->resrec.rdata->u.srv.port = rr->NATinfo.IntPort;
        }

        return(mStatus_NoError);
    }
    LogMsg("UnlinkResourceRecord:ERROR!! - no such active record %##s", rr->resrec.name->c);
    return(mStatus_NoSuchRecord);
}

// We need to go through mDNS_Register again as we did not complete the
// full initialization last time e.g., duplicate checks.
// After we register, we will be in regState_GetZoneData.
mDNSlocal void RegisterAllServiceRecords(mDNS *const m, AuthRecord *rr)
{
    LogInfo("RegisterAllServiceRecords: Service Record %##s", rr->resrec.name->c);
    // First Register the service record, we do this differently from other records because
    // when it entered NoTarget state, it did not go through complete initialization
    rr->SRVChanged = mDNSfalse;
    UnlinkResourceRecord(m, rr);
    mDNS_Register_internal(m, rr);
    // Register the other records
    UpdateAllServiceRecords(m, rr, mDNStrue);
}

// Called with lock held
mDNSlocal void UpdateOneSRVRecord(mDNS *m, AuthRecord *rr)
{
    // Target change if:
    // We have a target and were previously waiting for one, or
    // We had a target and no longer do, or
    // The target has changed

    domainname *curtarget = &rr->resrec.rdata->u.srv.target;
    const domainname *const nt = GetServiceTarget(m, rr);
    const domainname *const newtarget = nt ? nt : (domainname*)"";
    mDNSBool TargetChanged = (newtarget->c[0] && rr->state == regState_NoTarget) || !SameDomainName(curtarget, newtarget);
    mDNSBool HaveZoneData  = rr->nta && !mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4);

    // Nat state change if:
    // We were behind a NAT, and now we are behind a new NAT, or
    // We're not behind a NAT but our port was previously mapped to a different external port
    // We were not behind a NAT and now we are

    mDNSIPPort port        = rr->resrec.rdata->u.srv.port;
    mDNSBool NowNeedNATMAP = (rr->AutoTarget == Target_AutoHostAndNATMAP && !mDNSIPPortIsZero(port) && mDNSv4AddrIsRFC1918(&m->AdvertisedV4.ip.v4) && rr->nta && !mDNSAddrIsRFC1918(&rr->nta->Addr));
    mDNSBool WereBehindNAT = (rr->NATinfo.clientContext != mDNSNULL);
    mDNSBool PortWasMapped = (rr->NATinfo.clientContext && !mDNSSameIPPort(rr->NATinfo.RequestedPort, port));       // I think this is always false -- SC Sept 07
    mDNSBool NATChanged    = (!WereBehindNAT && NowNeedNATMAP) || (!NowNeedNATMAP && PortWasMapped);

    (void)HaveZoneData; //unused

    LogInfo("UpdateOneSRVRecord: Resource Record %s TargetChanged %d, NewTarget %##s", ARDisplayString(m, rr), TargetChanged, nt->c);

    debugf("UpdateOneSRVRecord: %##s newtarget %##s TargetChanged %d HaveZoneData %d port %d NowNeedNATMAP %d WereBehindNAT %d PortWasMapped %d NATChanged %d",
           rr->resrec.name->c, newtarget,
           TargetChanged, HaveZoneData, mDNSVal16(port), NowNeedNATMAP, WereBehindNAT, PortWasMapped, NATChanged);

    mDNS_CheckLock(m);

    if (!TargetChanged && !NATChanged) return;

    // If we are deregistering the record, then ignore any NAT/Target change.
    if (rr->resrec.RecordType == kDNSRecordTypeDeregistering)
    {
        LogInfo("UpdateOneSRVRecord: Deregistering record, Ignoring TargetChanged %d, NATChanged %d for %##s, state %d", TargetChanged, NATChanged,
                rr->resrec.name->c, rr->state);
        return;
    }

    if (newtarget)
        LogInfo("UpdateOneSRVRecord: TargetChanged %d, NATChanged %d for %##s, state %d, newtarget %##s", TargetChanged, NATChanged, rr->resrec.name->c, rr->state, newtarget->c);
    else
        LogInfo("UpdateOneSRVRecord: TargetChanged %d, NATChanged %d for %##s, state %d, null newtarget", TargetChanged, NATChanged, rr->resrec.name->c, rr->state);
    switch(rr->state)
    {
    case regState_NATMap:
        // In these states, the SRV has either not yet been registered (it will get up-to-date information when it is)
        // or is in the process of, or has already been, deregistered. This assumes that whenever we transition out
        // of this state, we need to look at the target again.
        return;

    case regState_UpdatePending:
        // We are getting a Target change/NAT change while the SRV record is being updated ?
        // let us not do anything for now.
        return;

    case regState_NATError:
        if (!NATChanged) return;
        fallthrough();
    // if nat changed, register if we have a target (below)

    case regState_NoTarget:
        if (!newtarget->c[0])
        {
            LogInfo("UpdateOneSRVRecord: No target yet for Resource Record %s", ARDisplayString(m, rr));
            return;
        }
        RegisterAllServiceRecords(m, rr);
        return;
    case regState_DeregPending:
    // We are in DeregPending either because the service was deregistered from above or we handled
    // a NAT/Target change before and sent the deregistration below. There are a few race conditions
    // possible
    //
    // 1. We are handling a second NAT/Target change while the first dereg is in progress. It is possible
    //    that first dereg never made it through because there was no network connectivity e.g., disconnecting
    //    from network triggers this function due to a target change and later connecting to the network
    //    retriggers this function but the deregistration never made it through yet. Just fall through.
    //    If there is a target register otherwise deregister.
    //
    // 2. While we sent the dereg during a previous NAT/Target change, uDNS_DeregisterRecord gets
    //    called as part of service deregistration. When the response comes back, we call
    //    CompleteDeregistration rather than handle NAT/Target change because the record is in
    //    kDNSRecordTypeDeregistering state.
    //
    // 3. If the upper layer deregisters the service, we check for kDNSRecordTypeDeregistering both
    //    here in this function to avoid handling NAT/Target change and in hndlRecordUpdateReply to call
    //    CompleteDeregistration instead of handling NAT/Target change. Hence, we are not concerned
    //    about that case here.
    //
    // We just handle case (1) by falling through
    case regState_Pending:
    case regState_Refresh:
    case regState_Registered:
        // target or nat changed.  deregister service.  upon completion, we'll look for a new target
        rr->SRVChanged = mDNStrue;
        rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
        rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
        if (newtarget->c[0])
        {
            LogInfo("UpdateOneSRVRecord: SRV record changed for service %##s, registering with new target %##s",
                    rr->resrec.name->c, newtarget->c);
            rr->state = regState_Pending;
        }
        else
        {
            LogInfo("UpdateOneSRVRecord: SRV record changed for service %##s de-registering", rr->resrec.name->c);
            rr->state = regState_DeregPending;
            UpdateAllServiceRecords(m, rr, mDNSfalse);
        }
        return;
    case regState_Unregistered:
    case regState_Zero:
    MDNS_COVERED_SWITCH_DEFAULT:
        break;
    }
    LogMsg("UpdateOneSRVRecord: Unknown state %d for %##s", rr->state, rr->resrec.name->c);
}

mDNSexport void UpdateAllSRVRecords(mDNS *m)
{
    m->NextSRVUpdate = 0;
    LogInfo("UpdateAllSRVRecords %d", m->SleepState);

    if (m->CurrentRecord)
        LogMsg("UpdateAllSRVRecords ERROR m->CurrentRecord already set %s", ARDisplayString(m, m->CurrentRecord));
    m->CurrentRecord = m->ResourceRecords;
    while (m->CurrentRecord)
    {
        AuthRecord *rptr = m->CurrentRecord;
        m->CurrentRecord = m->CurrentRecord->next;
        if (AuthRecord_uDNS(rptr) && rptr->resrec.rrtype == kDNSType_SRV)
            UpdateOneSRVRecord(m, rptr);
    }
}

// Forward reference: AdvertiseHostname references HostnameCallback, and HostnameCallback calls AdvertiseHostname
mDNSlocal void HostnameCallback(mDNS *const m, AuthRecord *const rr, mStatus result);

// Called in normal client context (lock not held)
mDNSlocal void hostnameGetPublicAddressCallback(mDNS *m, NATTraversalInfo *n)
{
    HostnameInfo *h = (HostnameInfo *)n->clientContext;

    if (!h) { LogMsg("RegisterHostnameRecord: registration cancelled"); return; }

    if (!n->Result)
    {
        if (mDNSIPv4AddressIsZero(n->ExternalAddress) || mDNSv4AddrIsRFC1918(&n->ExternalAddress)) return;

        if (h->arv4.resrec.RecordType)
        {
            if (mDNSSameIPv4Address(h->arv4.resrec.rdata->u.ipv4, n->ExternalAddress)) return;  // If address unchanged, do nothing
            LogInfo("Updating hostname %p %##s IPv4 from %.4a to %.4a (NAT gateway's external address)",n,
                    h->arv4.resrec.name->c, &h->arv4.resrec.rdata->u.ipv4, &n->ExternalAddress);
            mDNS_Deregister(m, &h->arv4);   // mStatus_MemFree callback will re-register with new address
        }
        else
        {
            LogInfo("Advertising hostname %##s IPv4 %.4a (NAT gateway's external address)", h->arv4.resrec.name->c, &n->ExternalAddress);
            h->arv4.resrec.RecordType = kDNSRecordTypeKnownUnique;
            h->arv4.resrec.rdata->u.ipv4 = n->ExternalAddress;
            mDNS_Register(m, &h->arv4);
        }
    }
}

// register record or begin NAT traversal
mDNSlocal void AdvertiseHostname(mDNS *m, HostnameInfo *h)
{
    if (!mDNSIPv4AddressIsZero(m->AdvertisedV4.ip.v4) && h->arv4.resrec.RecordType == kDNSRecordTypeUnregistered)
    {
        mDNS_SetupResourceRecord(&h->arv4, mDNSNULL, mDNSInterface_Any, kDNSType_A, kHostNameTTL, kDNSRecordTypeUnregistered, AuthRecordAny, HostnameCallback, h);
        AssignDomainName(&h->arv4.namestorage, &h->fqdn);
        h->arv4.resrec.rdata->u.ipv4 = m->AdvertisedV4.ip.v4;
        h->arv4.state = regState_Unregistered;
        if (mDNSv4AddrIsRFC1918(&m->AdvertisedV4.ip.v4))
        {
            // If we already have a NAT query active, stop it and restart it to make sure we get another callback
            if (h->natinfo.clientContext) mDNS_StopNATOperation_internal(m, &h->natinfo);
            h->natinfo.Protocol         = 0;
            h->natinfo.IntPort          = zeroIPPort;
            h->natinfo.RequestedPort    = zeroIPPort;
            h->natinfo.NATLease         = 0;
            h->natinfo.clientCallback   = hostnameGetPublicAddressCallback;
            h->natinfo.clientContext    = h;
            mDNS_StartNATOperation_internal(m, &h->natinfo);
        }
        else
        {
            LogInfo("Advertising hostname %##s IPv4 %.4a", h->arv4.resrec.name->c, &m->AdvertisedV4.ip.v4);
            h->arv4.resrec.RecordType = kDNSRecordTypeKnownUnique;
            mDNS_Register_internal(m, &h->arv4);
        }
    }

    if (!mDNSIPv6AddressIsZero(m->AdvertisedV6.ip.v6) && h->arv6.resrec.RecordType == kDNSRecordTypeUnregistered)
    {
        mDNS_SetupResourceRecord(&h->arv6, mDNSNULL, mDNSInterface_Any, kDNSType_AAAA, kHostNameTTL, kDNSRecordTypeKnownUnique, AuthRecordAny, HostnameCallback, h);
        AssignDomainName(&h->arv6.namestorage, &h->fqdn);
        h->arv6.resrec.rdata->u.ipv6 = m->AdvertisedV6.ip.v6;
        h->arv6.state = regState_Unregistered;
        LogInfo("Advertising hostname %##s IPv6 %.16a", h->arv6.resrec.name->c, &m->AdvertisedV6.ip.v6);
        mDNS_Register_internal(m, &h->arv6);
    }
}

mDNSlocal void HostnameCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
{
    HostnameInfo *hi = rr->RecordContext;

    if (result == mStatus_MemFree)
    {
        if (hi)
        {
            // If we're still in the Hostnames list, update to new address
            HostnameInfo *i;
            LogInfo("HostnameCallback: Got mStatus_MemFree for %p %p %s", hi, rr, ARDisplayString(m, rr));
            for (i = m->Hostnames; i; i = i->next)
                if (rr == &i->arv4 || rr == &i->arv6)
                { mDNS_Lock(m); AdvertiseHostname(m, i); mDNS_Unlock(m); return; }

            // Else, we're not still in the Hostnames list, so free the memory
            if (hi->arv4.resrec.RecordType == kDNSRecordTypeUnregistered &&
                hi->arv6.resrec.RecordType == kDNSRecordTypeUnregistered)
            {
                if (hi->natinfo.clientContext) mDNS_StopNATOperation_internal(m, &hi->natinfo);
                hi->natinfo.clientContext = mDNSNULL;
                mDNSPlatformMemFree(hi);    // free hi when both v4 and v6 AuthRecs deallocated
            }
        }
        return;
    }

    if (result)
    {
        // don't unlink or free - we can retry when we get a new address/router
        if (rr->resrec.rrtype == kDNSType_A)
            LogMsg("HostnameCallback: Error %d for registration of %##s IP %.4a", result, rr->resrec.name->c, &rr->resrec.rdata->u.ipv4);
        else
            LogMsg("HostnameCallback: Error %d for registration of %##s IP %.16a", result, rr->resrec.name->c, &rr->resrec.rdata->u.ipv6);
        if (!hi) { mDNSPlatformMemFree(rr); return; }
        if (rr->state != regState_Unregistered) LogMsg("Error: HostnameCallback invoked with error code for record not in regState_Unregistered!");

        if (hi->arv4.state == regState_Unregistered &&
            hi->arv6.state == regState_Unregistered)
        {
            // only deliver status if both v4 and v6 fail
            rr->RecordContext = (void *)hi->StatusContext;
            if (hi->StatusCallback)
                hi->StatusCallback(m, rr, result); // client may NOT make API calls here
            rr->RecordContext = hi;
        }
        return;
    }

    // register any pending services that require a target
    mDNS_Lock(m);
    m->NextSRVUpdate = NonZeroTime(m->timenow);
    mDNS_Unlock(m);

    // Deliver success to client
    if (!hi) { LogMsg("HostnameCallback invoked with orphaned address record"); return; }
    if (rr->resrec.rrtype == kDNSType_A)
        LogInfo("Registered hostname %##s IP %.4a", rr->resrec.name->c, &rr->resrec.rdata->u.ipv4);
    else
        LogInfo("Registered hostname %##s IP %.16a", rr->resrec.name->c, &rr->resrec.rdata->u.ipv6);

    rr->RecordContext = (void *)hi->StatusContext;
    if (hi->StatusCallback)
        hi->StatusCallback(m, rr, result); // client may NOT make API calls here
    rr->RecordContext = hi;
}

mDNSlocal void FoundStaticHostname(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    const domainname *pktname = &answer->rdata->u.name;
    domainname *storedname = &m->StaticHostname;
    HostnameInfo *h = m->Hostnames;

    (void)question;

    if (answer->rdlength != 0)
        LogInfo("FoundStaticHostname: question %##s -> answer %##s (%s)", question->qname.c, answer->rdata->u.name.c, AddRecord ? "ADD" : "RMV");
    else
        LogInfo("FoundStaticHostname: question %##s -> answer NULL (%s)", question->qname.c, AddRecord ? "ADD" : "RMV");

    if (AddRecord && answer->rdlength != 0 && !SameDomainName(pktname, storedname))
    {
        AssignDomainName(storedname, pktname);
        while (h)
        {
            if (h->arv4.state == regState_Pending || h->arv4.state == regState_NATMap || h->arv6.state == regState_Pending)
            {
                // if we're in the process of registering a dynamic hostname, delay SRV update so we don't have to reregister services if the dynamic name succeeds
                m->NextSRVUpdate = NonZeroTime(m->timenow + 5 * mDNSPlatformOneSecond);
                debugf("FoundStaticHostname: NextSRVUpdate in %d %d", m->NextSRVUpdate - m->timenow, m->timenow);
                return;
            }
            h = h->next;
        }
        mDNS_Lock(m);
        m->NextSRVUpdate = NonZeroTime(m->timenow);
        mDNS_Unlock(m);
    }
    else if (!AddRecord && SameDomainName(pktname, storedname))
    {
        mDNS_Lock(m);
        storedname->c[0] = 0;
        m->NextSRVUpdate = NonZeroTime(m->timenow);
        mDNS_Unlock(m);
    }
}

// Called with lock held
mDNSlocal void GetStaticHostname(mDNS *m)
{
    char buf[MAX_REVERSE_MAPPING_NAME_V4];
    DNSQuestion *q = &m->ReverseMap;
    mDNSu8 *ip = m->AdvertisedV4.ip.v4.b;
    mStatus err;

    if (m->ReverseMap.ThisQInterval != -1) return; // already running
    if (mDNSIPv4AddressIsZero(m->AdvertisedV4.ip.v4)) return;

    mDNSPlatformMemZero(q, sizeof(*q));
    // Note: This is reverse order compared to a normal dotted-decimal IP address, so we can't use our customary "%.4a" format code
    mDNS_snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0]);
    if (!MakeDomainNameFromDNSNameString(&q->qname, buf)) { LogMsg("Error: GetStaticHostname - bad name %s", buf); return; }

    q->InterfaceID      = mDNSInterface_Any;
    q->flags            = 0;
    q->qtype            = kDNSType_PTR;
    q->qclass           = kDNSClass_IN;
    q->LongLived        = mDNSfalse;
    q->ExpectUnique     = mDNSfalse;
    q->ForceMCast       = mDNSfalse;
    q->ReturnIntermed   = mDNStrue;
    q->SuppressUnusable = mDNSfalse;
    q->AppendSearchDomains = 0;
    q->TimeoutQuestion  = 0;
    q->WakeOnResolve    = 0;
    q->UseBackgroundTraffic = mDNSfalse;
    q->ProxyQuestion      = 0;
    q->pid              = mDNSPlatformGetPID();
    q->euid             = 0;
    q->QuestionCallback = FoundStaticHostname;
    q->QuestionContext  = mDNSNULL;

    LogInfo("GetStaticHostname: %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
    err = mDNS_StartQuery_internal(m, q);
    if (err) LogMsg("Error: GetStaticHostname - StartQuery returned error %d", err);
}

mDNSexport void mDNS_AddDynDNSHostName(mDNS *m, const domainname *fqdn, mDNSRecordCallback *StatusCallback, const void *StatusContext)
{
    HostnameInfo **ptr = &m->Hostnames;

    LogInfo("mDNS_AddDynDNSHostName %##s", fqdn);

    while (*ptr && !SameDomainName(fqdn, &(*ptr)->fqdn)) ptr = &(*ptr)->next;
    if (*ptr) { LogMsg("DynDNSHostName %##s already in list", fqdn->c); return; }

    // allocate and format new address record
    *ptr = (HostnameInfo *) mDNSPlatformMemAllocateClear(sizeof(**ptr));
    if (!*ptr) { LogMsg("ERROR: mDNS_AddDynDNSHostName - malloc"); return; }

    AssignDomainName(&(*ptr)->fqdn, fqdn);
    (*ptr)->arv4.state     = regState_Unregistered;
    (*ptr)->arv6.state     = regState_Unregistered;
    (*ptr)->StatusCallback = StatusCallback;
    (*ptr)->StatusContext  = StatusContext;

    AdvertiseHostname(m, *ptr);
}

mDNSexport void mDNS_RemoveDynDNSHostName(mDNS *m, const domainname *fqdn)
{
    HostnameInfo **ptr = &m->Hostnames;

    LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "mDNS_RemoveDynDNSHostName " PRI_DM_NAME, DM_NAME_PARAM(fqdn));

    while (*ptr && !SameDomainName(fqdn, &(*ptr)->fqdn)) ptr = &(*ptr)->next;
    if (!*ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "mDNS_RemoveDynDNSHostName: no such domainname " PRI_DM_NAME, DM_NAME_PARAM(fqdn));
    }
    else
    {
        HostnameInfo *hi = *ptr;
        // We do it this way because, if we have no active v6 record, the "mDNS_Deregister_internal(m, &hi->arv4);"
        // below could free the memory, and we have to make sure we don't touch hi fields after that.
        mDNSBool f4 = hi->arv4.resrec.RecordType != kDNSRecordTypeUnregistered && hi->arv4.state != regState_Unregistered;
        mDNSBool f6 = hi->arv6.resrec.RecordType != kDNSRecordTypeUnregistered && hi->arv6.state != regState_Unregistered;
        *ptr = (*ptr)->next; // unlink
        if (f4 || f6)
        {
            if (f4)
            {
                LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "mDNS_RemoveDynDNSHostName removing v4 " PRI_DM_NAME, DM_NAME_PARAM(fqdn));
                mDNS_Deregister_internal(m, &hi->arv4, mDNS_Dereg_normal);
            }
            if (f6)
            {
                LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "mDNS_RemoveDynDNSHostName removing v6 " PRI_DM_NAME, DM_NAME_PARAM(fqdn));
                mDNS_Deregister_internal(m, &hi->arv6, mDNS_Dereg_normal);
            }
            // When both deregistrations complete we'll free the memory in the mStatus_MemFree callback
        }
        else
        {
            if (hi->natinfo.clientContext)
            {
                mDNS_StopNATOperation_internal(m, &hi->natinfo);
                hi->natinfo.clientContext = mDNSNULL;
            }
            mDNSPlatformMemFree(hi);
        }
    }
    mDNS_CheckLock(m);
    m->NextSRVUpdate = NonZeroTime(m->timenow);
}

// Currently called without holding the lock
// Maybe we should change that?
mDNSexport void mDNS_SetPrimaryInterfaceInfo(mDNS *m, const mDNSAddr *v4addr, const mDNSAddr *v6addr, const mDNSAddr *router)
{
    mDNSBool v4Changed, v6Changed, RouterChanged;

    mDNS_Lock(m);

    if (v4addr && v4addr->type != mDNSAddrType_IPv4) { LogMsg("mDNS_SetPrimaryInterfaceInfo v4 address - incorrect type.  Discarding. %#a", v4addr); goto exit; }
    if (v6addr && v6addr->type != mDNSAddrType_IPv6) { LogMsg("mDNS_SetPrimaryInterfaceInfo v6 address - incorrect type.  Discarding. %#a", v6addr); goto exit; }
    if (router && router->type != mDNSAddrType_IPv4) { LogMsg("mDNS_SetPrimaryInterfaceInfo passed non-v4 router.  Discarding. %#a",        router); goto exit; }

    v4Changed     = !mDNSSameIPv4Address(m->AdvertisedV4.ip.v4, v4addr ? v4addr->ip.v4 : zerov4Addr);
    v6Changed     = !mDNSSameIPv6Address(m->AdvertisedV6.ip.v6, v6addr ? v6addr->ip.v6 : zerov6Addr);
    RouterChanged = !mDNSSameIPv4Address(m->Router.ip.v4,       router ? router->ip.v4 : zerov4Addr);

    if (v4addr && (v4Changed || RouterChanged))
        debugf("mDNS_SetPrimaryInterfaceInfo: address changed from %#a to %#a", &m->AdvertisedV4, v4addr);

    if (v4addr) m->AdvertisedV4 = *v4addr;else m->AdvertisedV4.ip.v4 = zerov4Addr;
    if (v6addr) m->AdvertisedV6 = *v6addr;else m->AdvertisedV6.ip.v6 = zerov6Addr;
    if (router) m->Router       = *router;else m->Router.ip.v4 = zerov4Addr;
    // setting router to zero indicates that nat mappings must be reestablished when router is reset

    if (v4Changed || RouterChanged || v6Changed)
    {
        HostnameInfo *i;
        LogInfo("mDNS_SetPrimaryInterfaceInfo: %s%s%s%#a %#a %#a",
                v4Changed     ? "v4Changed "     : "",
                RouterChanged ? "RouterChanged " : "",
                v6Changed     ? "v6Changed "     : "", v4addr, v6addr, router);

        for (i = m->Hostnames; i; i = i->next)
        {
            LogInfo("mDNS_SetPrimaryInterfaceInfo updating host name registrations for %##s", i->fqdn.c);

            if (i->arv4.resrec.RecordType > kDNSRecordTypeDeregistering &&
                !mDNSSameIPv4Address(i->arv4.resrec.rdata->u.ipv4, m->AdvertisedV4.ip.v4))
            {
                LogInfo("mDNS_SetPrimaryInterfaceInfo deregistering %s", ARDisplayString(m, &i->arv4));
                mDNS_Deregister_internal(m, &i->arv4, mDNS_Dereg_normal);
            }

            if (i->arv6.resrec.RecordType > kDNSRecordTypeDeregistering &&
                !mDNSSameIPv6Address(i->arv6.resrec.rdata->u.ipv6, m->AdvertisedV6.ip.v6))
            {
                LogInfo("mDNS_SetPrimaryInterfaceInfo deregistering %s", ARDisplayString(m, &i->arv6));
                mDNS_Deregister_internal(m, &i->arv6, mDNS_Dereg_normal);
            }

            // AdvertiseHostname will only register new address records.
            // For records still in the process of deregistering it will ignore them, and let the mStatus_MemFree callback handle them.
            AdvertiseHostname(m, i);
        }

        if (v4Changed || RouterChanged)
        {
            // If we have a non-zero IPv4 address, we should try immediately to see if we have a NAT gateway
            // If we have no IPv4 address, we don't want to be in quite such a hurry to report failures to our clients
            // <rdar://problem/6935929> Sleeping server sometimes briefly disappears over Back to My Mac after it wakes up
            mDNSu32 waitSeconds = v4addr ? 0 : 5;
            NATTraversalInfo *n;
            m->ExtAddress           = zerov4Addr;
            m->LastNATMapResultCode = NATErr_None;

            RecreateNATMappings(m, mDNSPlatformOneSecond * waitSeconds);

            for (n = m->NATTraversals; n; n=n->next)
                n->NewAddress = zerov4Addr;

            LogInfo("mDNS_SetPrimaryInterfaceInfo:%s%s: recreating NAT mappings in %d seconds",
                    v4Changed     ? " v4Changed"     : "",
                    RouterChanged ? " RouterChanged" : "",
                    waitSeconds);
        }

        if (m->ReverseMap.ThisQInterval != -1) mDNS_StopQuery_internal(m, &m->ReverseMap);
        m->StaticHostname.c[0] = 0;

        m->NextSRVUpdate = NonZeroTime(m->timenow);
    }

exit:
    mDNS_Unlock(m);
}

// ***************************************************************************
// MARK: - Incoming Message Processing

mDNSlocal mStatus ParseTSIGError(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end, const domainname *const displayname)
{
    const mDNSu8 *ptr;
    mStatus err = mStatus_NoError;
    int i;

    ptr = LocateAdditionals(msg, end);
    if (!ptr) goto finish;

    for (i = 0; i < msg->h.numAdditionals; i++)
    {
        ptr = GetLargeResourceRecord(m, msg, ptr, end, 0, kDNSRecordTypePacketAdd, &m->rec);
        if (!ptr) goto finish;
        if (m->rec.r.resrec.RecordType != kDNSRecordTypePacketNegative && m->rec.r.resrec.rrtype == kDNSType_TSIG)
        {
            mDNSu32 macsize;
            mDNSu8 *rd = m->rec.r.resrec.rdata->u.data;
            mDNSu8 *rdend = rd + m->rec.r.resrec.rdlength;
            int alglen = DomainNameLengthLimit(&m->rec.r.resrec.rdata->u.name, rdend);
            if (alglen > MAX_DOMAIN_NAME) goto finish;
            rd += alglen;                                       // algorithm name
            if (rd + 6 > rdend) goto finish;
            rd += 6;                                            // 48-bit timestamp
            if (rd + sizeof(mDNSOpaque16) > rdend) goto finish;
            rd += sizeof(mDNSOpaque16);                         // fudge
            if (rd + sizeof(mDNSOpaque16) > rdend) goto finish;
            macsize = mDNSVal16(*(mDNSOpaque16 *)rd);
            rd += sizeof(mDNSOpaque16);                         // MAC size
            if (rd + macsize > rdend) goto finish;
            rd += macsize;
            if (rd + sizeof(mDNSOpaque16) > rdend) goto finish;
            rd += sizeof(mDNSOpaque16);                         // orig id
            if (rd + sizeof(mDNSOpaque16) > rdend) goto finish;
            err = mDNSVal16(*(mDNSOpaque16 *)rd);               // error code

            if      (err == TSIG_ErrBadSig)  { LogMsg("%##s: bad signature", displayname->c);              err = mStatus_BadSig;     }
            else if (err == TSIG_ErrBadKey)  { LogMsg("%##s: bad key", displayname->c);                    err = mStatus_BadKey;     }
            else if (err == TSIG_ErrBadTime) { LogMsg("%##s: bad time", displayname->c);                   err = mStatus_BadTime;    }
            else if (err)                    { LogMsg("%##s: unknown tsig error %d", displayname->c, err); err = mStatus_UnknownErr; }
            goto finish;
        }
        mDNSCoreResetRecord(m);
    }

finish:
    mDNSCoreResetRecord(m);
    return err;
}

mDNSlocal mStatus checkUpdateResult(mDNS *const m, const domainname *const displayname, const mDNSu8 rcode, const DNSMessage *const msg, const mDNSu8 *const end)
{
    (void)msg;  // currently unused, needed for TSIG errors
    if (!rcode) return mStatus_NoError;
    else if (rcode == kDNSFlag1_RC_YXDomain)
    {
        debugf("name in use: %##s", displayname->c);
        return mStatus_NameConflict;
    }
    else if (rcode == kDNSFlag1_RC_Refused)
    {
        LogMsg("Update %##s refused", displayname->c);
        return mStatus_Refused;
    }
    else if (rcode == kDNSFlag1_RC_NXRRSet)
    {
        LogMsg("Reregister refused (NXRRSET): %##s", displayname->c);
        return mStatus_NoSuchRecord;
    }
    else if (rcode == kDNSFlag1_RC_NotAuth)
    {
        // TSIG errors should come with FormErr as per RFC 2845, but BIND 9 sends them with NotAuth so we look here too
        mStatus tsigerr = ParseTSIGError(m, msg, end, displayname);
        if (!tsigerr)
        {
            LogMsg("Permission denied (NOAUTH): %##s", displayname->c);
            return mStatus_UnknownErr;
        }
        else return tsigerr;
    }
    else if (rcode == kDNSFlag1_RC_FormErr)
    {
        mStatus tsigerr = ParseTSIGError(m, msg, end, displayname);
        if (!tsigerr)
        {
            LogMsg("Format Error: %##s", displayname->c);
            return mStatus_UnknownErr;
        }
        else return tsigerr;
    }
    else
    {
        LogMsg("Update %##s failed with rcode %d", displayname->c, rcode);
        return mStatus_UnknownErr;
    }
}

mDNSlocal mDNSu32 RRAdditionalSize(DomainAuthInfo *AuthInfo)
{
    mDNSu32 leaseSize, tsigSize;
    mDNSu32 rr_base_size = 10; // type (2) class (2) TTL (4) rdlength (2)

    // OPT RR : Emptyname(.) + base size + rdataOPT
    leaseSize = 1 + rr_base_size + sizeof(rdataOPT);

    //TSIG: Resource Record Name + base size + RDATA
    // RDATA:
    //  Algorithm name: hmac-md5.sig-alg.reg.int (8+7+3+3 + 5 bytes for length = 26 bytes)
    //  Time: 6 bytes
    //  Fudge: 2 bytes
    //  Mac Size: 2 bytes
    //  Mac: 16 bytes
    //  ID: 2 bytes
    //  Error: 2 bytes
    //  Len: 2 bytes
    //  Total: 58 bytes
    tsigSize = 0;
    if (AuthInfo) tsigSize = DomainNameLength(&AuthInfo->keyname) + rr_base_size + 58;

    return (leaseSize + tsigSize);
}

//Note: Make sure that RREstimatedSize is updated accordingly if anything that is done here
//would modify rdlength/rdestimate
mDNSlocal mDNSu8* BuildUpdateMessage(mDNS *const m, mDNSu8 *ptr, AuthRecord *rr, mDNSu8 *limit)
{
    //If this record is deregistering, then just send the deletion record
    if (rr->state == regState_DeregPending)
    {
        rr->expire = 0;     // Indicate that we have no active registration any more
        ptr = putDeletionRecordWithLimit(&m->omsg, ptr, &rr->resrec, limit);
        if (!ptr) goto exit;
        return ptr;
    }

    // This is a common function to both sending an update in a group or individual
    // records separately. Hence, we change the state here.
    if (rr->state == regState_Registered) rr->state = regState_Refresh;
    if (rr->state != regState_Refresh && rr->state != regState_UpdatePending)
        rr->state = regState_Pending;

    // For Advisory records like e.g., _services._dns-sd, which is shared, don't send goodbyes as multiple
    // host might be registering records and deregistering from one does not make sense
    if (rr->resrec.RecordType != kDNSRecordTypeAdvisory) rr->RequireGoodbye = mDNStrue;

    if ((rr->resrec.rrtype == kDNSType_SRV) && (rr->AutoTarget == Target_AutoHostAndNATMAP) &&
        !mDNSIPPortIsZero(rr->NATinfo.ExternalPort))
    {
        rr->resrec.rdata->u.srv.port = rr->NATinfo.ExternalPort;
    }

    if (rr->state == regState_UpdatePending)
    {
        // delete old RData
        SetNewRData(&rr->resrec, rr->OrigRData, rr->OrigRDLen);
        if (!(ptr = putDeletionRecordWithLimit(&m->omsg, ptr, &rr->resrec, limit))) goto exit; // delete old rdata

        // add new RData
        SetNewRData(&rr->resrec, rr->InFlightRData, rr->InFlightRDLen);
        if (!(ptr = PutResourceRecordTTLWithLimit(&m->omsg, ptr, &m->omsg.h.mDNS_numUpdates, &rr->resrec, rr->resrec.rroriginalttl, limit))) goto exit;
    }
    else
    {
        if (rr->resrec.RecordType == kDNSRecordTypeKnownUnique || rr->resrec.RecordType == kDNSRecordTypeVerified)
        {
            // KnownUnique : Delete any previous value
            // For Unicast registrations, we don't verify that it is unique, but set to verified and hence we want to
            // delete any previous value
            ptr = putDeleteRRSetWithLimit(&m->omsg, ptr, rr->resrec.name, rr->resrec.rrtype, limit);
            if (!ptr) goto exit;
        }
        else if (rr->resrec.RecordType != kDNSRecordTypeShared)
        {
            // For now don't do this, until we have the logic for intelligent grouping of individual records into logical service record sets
            //ptr = putPrereqNameNotInUse(rr->resrec.name, &m->omsg, ptr, end);
            if (!ptr) goto exit;
        }

        ptr = PutResourceRecordTTLWithLimit(&m->omsg, ptr, &m->omsg.h.mDNS_numUpdates, &rr->resrec, rr->resrec.rroriginalttl, limit);
        if (!ptr) goto exit;
    }

    return ptr;
exit:
    LogMsg("BuildUpdateMessage: Error formatting message for %s", ARDisplayString(m, rr));
    return mDNSNULL;
}

// Called with lock held
mDNSlocal void SendRecordRegistration(mDNS *const m, AuthRecord *rr)
{
    mDNSu8 *ptr = m->omsg.data;
    mStatus err = mStatus_UnknownErr;
    mDNSu8 *limit;
    DomainAuthInfo *AuthInfo;

    // For the ability to register large TXT records, we limit the single record registrations
    // to AbsoluteMaxDNSMessageData
    limit = ptr + AbsoluteMaxDNSMessageData;

    AuthInfo = GetAuthInfoForName_internal(m, rr->resrec.name);
    limit -= RRAdditionalSize(AuthInfo);

    mDNS_CheckLock(m);

    if (!rr->nta || mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4))
    {
        // We never call this function when there is no zone information . Log a message if it ever happens.
        LogMsg("SendRecordRegistration: No Zone information, should not happen %s", ARDisplayString(m, rr));
        return;
    }

    rr->updateid = mDNS_NewMessageID(m);
    InitializeDNSMessage(&m->omsg.h, rr->updateid, UpdateReqFlags);

    // set zone
    ptr = putZone(&m->omsg, ptr, limit, rr->zone, mDNSOpaque16fromIntVal(rr->resrec.rrclass));
    if (!ptr) goto exit;

    if (!(ptr = BuildUpdateMessage(m, ptr, rr, limit))) goto exit;

    if (rr->uselease)
    {
        ptr = putUpdateLeaseWithLimit(&m->omsg, ptr, DEFAULT_UPDATE_LEASE, limit);
        if (!ptr) goto exit;
    }
    if (rr->Private)
    {
        LogInfo("SendRecordRegistration TCP %p %s", rr->tcp, ARDisplayString(m, rr));
        if (rr->tcp) LogInfo("SendRecordRegistration: Disposing existing TCP connection for %s", ARDisplayString(m, rr));
        if (rr->tcp) { DisposeTCPConn(rr->tcp); rr->tcp = mDNSNULL; }
        if (!rr->nta) { LogMsg("SendRecordRegistration:Private:ERROR!! nta is NULL for %s", ARDisplayString(m, rr)); return; }
        rr->tcp = MakeTCPConn(m, &m->omsg, ptr, kTCPSocketFlags_UseTLS, &rr->nta->Addr, rr->nta->Port, &rr->nta->Host, mDNSNULL, rr);
    }
    else
    {
        LogInfo("SendRecordRegistration UDP %s", ARDisplayString(m, rr));
        if (!rr->nta) { LogMsg("SendRecordRegistration:ERROR!! nta is NULL for %s", ARDisplayString(m, rr)); return; }
        err = mDNSSendDNSMessage(m, &m->omsg, ptr, mDNSInterface_Any, mDNSNULL, mDNSNULL, &rr->nta->Addr, rr->nta->Port, GetAuthInfoForName_internal(m, rr->resrec.name), mDNSfalse);
        if (err) debugf("ERROR: SendRecordRegistration - mDNSSendDNSMessage - %d", err);
    }

    SetRecordRetry(m, rr, 0);
    return;
exit:
    LogMsg("SendRecordRegistration: Error formatting message for %s, disabling further updates", ARDisplayString(m, rr));
    // Disable this record from future updates
    rr->state = regState_NoTarget;
}

// Is the given record "rr" eligible for merging ?
mDNSlocal mDNSBool IsRecordMergeable(mDNS *const m, AuthRecord *rr, mDNSs32 time)
{
    DomainAuthInfo *info;
    // A record is eligible for merge, if the following properties are met.
    //
    // 1. uDNS Resource Record
    // 2. It is time to send them now
    // 3. It is in proper state
    // 4. Update zone has been resolved
    // 5. if DomainAuthInfo exists for the zone, it should not be soon deleted
    // 6. Zone information is present
    // 7. Update server is not zero
    // 8. It has a non-null zone
    // 9. It uses a lease option
    // 10. DontMerge is not set
    //
    // Following code is implemented as separate "if" statements instead of one "if" statement
    // is for better debugging purposes e.g., we know exactly what failed if debugging turned on.

    if (!AuthRecord_uDNS(rr)) return mDNSfalse;

    if (rr->LastAPTime + rr->ThisAPInterval - time > 0)
    { debugf("IsRecordMergeable: Time %d not reached for %s", rr->LastAPTime + rr->ThisAPInterval - m->timenow, ARDisplayString(m, rr)); return mDNSfalse; }

    if (!rr->zone) return mDNSfalse;

    info = GetAuthInfoForName_internal(m, rr->zone);

    if (info && info->deltime && m->timenow - info->deltime >= 0) {debugf("IsRecordMergeable: Domain %##s will be deleted soon", info->domain.c); return mDNSfalse;}

    if (rr->state != regState_DeregPending && rr->state != regState_Pending && rr->state != regState_Registered && rr->state != regState_Refresh && rr->state != regState_UpdatePending)
    { debugf("IsRecordMergeable: state %d not right  %s", rr->state, ARDisplayString(m, rr)); return mDNSfalse; }

    if (!rr->nta || mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4)) return mDNSfalse;

    if (!rr->uselease) return mDNSfalse;

    if (rr->mState == mergeState_DontMerge) {debugf("IsRecordMergeable Dontmerge true %s", ARDisplayString(m, rr)); return mDNSfalse;}
    debugf("IsRecordMergeable: Returning true for %s", ARDisplayString(m, rr));
    return mDNStrue;
}

// Is the resource record "rr" eligible to merge to with "currentRR" ?
mDNSlocal mDNSBool AreRecordsMergeable(mDNS *const m, AuthRecord *currentRR, AuthRecord *rr, mDNSs32 time)
{
    // A record is eligible to merge with another record as long it is eligible for merge in itself
    // and it has the same zone information as the other record
    if (!IsRecordMergeable(m, rr, time)) return mDNSfalse;

    if (!SameDomainName(currentRR->zone, rr->zone))
    { debugf("AreRecordMergeable zone mismatch current rr Zone %##s, rr zone  %##s", currentRR->zone->c, rr->zone->c); return mDNSfalse; }

    if (!mDNSSameIPv4Address(currentRR->nta->Addr.ip.v4, rr->nta->Addr.ip.v4)) return mDNSfalse;

    if (!mDNSSameIPPort(currentRR->nta->Port, rr->nta->Port)) return mDNSfalse;

    debugf("AreRecordsMergeable: Returning true for %s", ARDisplayString(m, rr));
    return mDNStrue;
}

// If we can't build the message successfully because of problems in pre-computing
// the space, we disable merging for all the current records
mDNSlocal void RRMergeFailure(mDNS *const m)
{
    AuthRecord *rr;
    for (rr = m->ResourceRecords; rr; rr = rr->next)
    {
        rr->mState = mergeState_DontMerge;
        rr->SendRNow = mDNSNULL;
        // Restarting the registration is much simpler than saving and restoring
        // the exact time
        ActivateUnicastRegistration(m, rr);
    }
}

mDNSlocal void SendGroupRRMessage(mDNS *const m, AuthRecord *anchorRR, mDNSu8 *ptr, DomainAuthInfo *info)
{
    mDNSu8 *limit;
    if (!anchorRR) {debugf("SendGroupRRMessage: Could not merge records"); return;}

    limit = m->omsg.data + NormalMaxDNSMessageData;

    // This has to go in the additional section and hence need to be done last
    ptr = putUpdateLeaseWithLimit(&m->omsg, ptr, DEFAULT_UPDATE_LEASE, limit);
    if (!ptr)
    {
        LogMsg("SendGroupRRMessage: ERROR: Could not put lease option, failing the group registration");
        // if we can't put the lease, we need to undo the merge
        RRMergeFailure(m);
        return;
    }
    if (anchorRR->Private)
    {
        if (anchorRR->tcp) debugf("SendGroupRRMessage: Disposing existing TCP connection for %s", ARDisplayString(m, anchorRR));
        if (anchorRR->tcp) { DisposeTCPConn(anchorRR->tcp); anchorRR->tcp = mDNSNULL; }
        if (!anchorRR->nta) { LogMsg("SendGroupRRMessage:ERROR!! nta is NULL for %s", ARDisplayString(m, anchorRR)); return; }
        anchorRR->tcp = MakeTCPConn(m, &m->omsg, ptr, kTCPSocketFlags_UseTLS, &anchorRR->nta->Addr, anchorRR->nta->Port, &anchorRR->nta->Host, mDNSNULL, anchorRR);
        if (!anchorRR->tcp) LogInfo("SendGroupRRMessage: Cannot establish TCP connection for %s", ARDisplayString(m, anchorRR));
        else LogInfo("SendGroupRRMessage: Sent a group update ID: %d start %p, end %p, limit %p", mDNSVal16(m->omsg.h.id), m->omsg.data, ptr, limit);
    }
    else
    {
        mStatus err = mDNSSendDNSMessage(m, &m->omsg, ptr, mDNSInterface_Any, mDNSNULL, mDNSNULL, &anchorRR->nta->Addr, anchorRR->nta->Port, info, mDNSfalse);
        if (err) LogInfo("SendGroupRRMessage: Cannot send UDP message for %s", ARDisplayString(m, anchorRR));
        else LogInfo("SendGroupRRMessage: Sent a group UDP update ID: %d start %p, end %p, limit %p", mDNSVal16(m->omsg.h.id), m->omsg.data, ptr, limit);
    }
    return;
}

// As we always include the zone information and the resource records contain zone name
// at the end, it will get compressed. Hence, we subtract zoneSize and add two bytes for
// the compression pointer
mDNSlocal mDNSu32 RREstimatedSize(AuthRecord *rr, int zoneSize)
{
    int rdlength;

    // Note: Estimation of the record size has to mirror the logic in BuildUpdateMessage, otherwise estimation
    // would be wrong. Currently BuildUpdateMessage calls SetNewRData in UpdatePending case. Hence, we need
    // to account for that here. Otherwise, we might under estimate the size.
    if (rr->state == regState_UpdatePending)
        // old RData that will be deleted
        // new RData that will be added
        rdlength = rr->OrigRDLen + rr->InFlightRDLen;
    else
        rdlength = rr->resrec.rdestimate;

    if (rr->state == regState_DeregPending)
    {
        debugf("RREstimatedSize: ResourceRecord %##s (%s), DomainNameLength %d, zoneSize %d, rdestimate %d",
               rr->resrec.name->c, DNSTypeName(rr->resrec.rrtype), DomainNameLength(rr->resrec.name), zoneSize, rdlength);
        return DomainNameLength(rr->resrec.name) - zoneSize + 2 + 10 + rdlength;
    }

    // For SRV, TXT, AAAA etc. that are Unique/Verified, we also send a Deletion Record
    if (rr->resrec.RecordType == kDNSRecordTypeKnownUnique || rr->resrec.RecordType == kDNSRecordTypeVerified)
    {
        // Deletion Record: Resource Record Name + Base size (10) + 0
        // Record: Resource Record Name (Compressed = 2) + Base size (10) + rdestimate

        debugf("RREstimatedSize: ResourceRecord %##s (%s), DomainNameLength %d, zoneSize %d, rdestimate %d",
               rr->resrec.name->c, DNSTypeName(rr->resrec.rrtype), DomainNameLength(rr->resrec.name), zoneSize, rdlength);
        return DomainNameLength(rr->resrec.name) - zoneSize + 2 + 10 + 2 + 10 + rdlength;
    }
    else
    {
        return DomainNameLength(rr->resrec.name) - zoneSize + 2 + 10 + rdlength;
    }
}

mDNSlocal AuthRecord *MarkRRForSending(mDNS *const m)
{
    AuthRecord *rr;
    AuthRecord *firstRR = mDNSNULL;

    // Look for records that needs to be sent in the next two seconds (MERGE_DELAY_TIME is set to 1 second).
    // The logic is as follows.
    //
    // 1. Record 1 finishes getting zone data and its registration gets delayed by 1 second
    // 2. Record 2 comes 0.1 second later, finishes getting its zone data and its registration is also delayed by
    //    1 second which is now scheduled at 1.1 second
    //
    // By looking for 1 second into the future (m->timenow + MERGE_DELAY_TIME below does that) we have merged both
    // of the above records. Note that we can't look for records too much into the future as this will affect the
    // retry logic. The first retry is scheduled at 3 seconds. Hence, we should always look smaller than that.
    // Anything more than one second will affect the first retry to happen sooner.
    //
    // Note: As a side effect of looking one second into the future to facilitate merging, the retries happen
    // one second sooner.
    for (rr = m->ResourceRecords; rr; rr = rr->next)
    {
        if (!firstRR)
        {
            if (!IsRecordMergeable(m, rr, m->timenow + MERGE_DELAY_TIME)) continue;
            firstRR = rr;
        }
        else if (!AreRecordsMergeable(m, firstRR, rr, m->timenow + MERGE_DELAY_TIME)) continue;

        if (rr->SendRNow) LogMsg("MarkRRForSending: Resourcerecord %s already marked for sending", ARDisplayString(m, rr));
        rr->SendRNow = uDNSInterfaceMark;
    }

    // We parsed through all records and found something to send. The services/records might
    // get registered at different times but we want the refreshes to be all merged and sent
    // as one update. Hence, we accelerate some of the records so that they will sync up in
    // the future. Look at the records excluding the ones that we have already sent in the
    // previous pass. If it half way through its scheduled refresh/retransmit, merge them
    // into this packet.
    //
    // Note that we only look at Registered/Refresh state to keep it simple. As we don't know
    // whether the current update will fit into one or more packets, merging a resource record
    // (which is in a different state) that has been scheduled for retransmit would trigger
    // sending more packets.
    if (firstRR)
    {
        int acc = 0;
        for (rr = m->ResourceRecords; rr; rr = rr->next)
        {
            if ((rr->state != regState_Registered && rr->state != regState_Refresh) ||
                (rr->SendRNow == uDNSInterfaceMark) ||
                (!AreRecordsMergeable(m, firstRR, rr, m->timenow + rr->ThisAPInterval/2)))
                continue;
            rr->SendRNow = uDNSInterfaceMark;
            acc++;
        }
        if (acc) LogInfo("MarkRRForSending: Accelereated %d records", acc);
    }
    return firstRR;
}

mDNSlocal mDNSBool SendGroupUpdates(mDNS *const m)
{
    mDNSOpaque16 msgid = zeroID;
    mDNSs32 spaceleft = 0;
    mDNSs32 zoneSize, rrSize;
    mDNSu8 *oldnext; // for debugging
    mDNSu8 *next = m->omsg.data;
    AuthRecord *rr;
    AuthRecord *anchorRR = mDNSNULL;
    int nrecords = 0;
    AuthRecord *startRR = m->ResourceRecords;
    mDNSu8 *limit = mDNSNULL;
    DomainAuthInfo *AuthInfo = mDNSNULL;
    mDNSBool sentallRecords = mDNStrue;


    // We try to fit as many ResourceRecords as possible in AbsoluteNormal/MaxDNSMessageData. Before we start
    // putting in resource records, we need to reserve space for a few things. Every group/packet should
    // have the following.
    //
    // 1) Needs space for the Zone information (which needs to be at the beginning)
    // 2) Additional section MUST have space for lease option, HINFO and TSIG option (which needs to
    //    to be at the end)
    //
    // In future we need to reserve space for the pre-requisites which also goes at the beginning.
    // To accomodate pre-requisites in the future, first we walk the whole list marking records
    // that can be sent in this packet and computing the space needed for these records.
    // For TXT and SRV records, we delete the previous record if any by sending the same
    // resource record with ANY RDATA and zero rdlen. Hence, we need to have space for both of them.

    while (startRR)
    {
        AuthInfo = mDNSNULL;
        anchorRR = mDNSNULL;
        nrecords = 0;
        zoneSize = 0;
        for (rr = startRR; rr; rr = rr->next)
        {
            if (rr->SendRNow != uDNSInterfaceMark) continue;

            rr->SendRNow = mDNSNULL;

            if (!anchorRR)
            {
                AuthInfo = GetAuthInfoForName_internal(m, rr->zone);

                // Though we allow single record registrations for UDP to be AbsoluteMaxDNSMessageData (See
                // SendRecordRegistration) to handle large TXT records, to avoid fragmentation we limit UDP
                // message to NormalMaxDNSMessageData
                spaceleft = NormalMaxDNSMessageData;

                next = m->omsg.data;
                spaceleft -= RRAdditionalSize(AuthInfo);
                if (spaceleft <= 0)
                {
                    LogMsg("SendGroupUpdates: ERROR!!: spaceleft is zero at the beginning");
                    RRMergeFailure(m);
                    return mDNSfalse;
                }
                limit = next + spaceleft;

                // Build the initial part of message before putting in the other records
                msgid = mDNS_NewMessageID(m);
                InitializeDNSMessage(&m->omsg.h, msgid, UpdateReqFlags);

                // We need zone information at the beginning of the packet. Length: ZNAME, ZTYPE(2), ZCLASS(2)
                // zone has to be non-NULL for a record to be mergeable, hence it is safe to set/ examine zone
                //without checking for NULL.
                zoneSize = DomainNameLength(rr->zone) + 4;
                spaceleft -= zoneSize;
                if (spaceleft <= 0)
                {
                    LogMsg("SendGroupUpdates: ERROR no space for zone information, disabling merge");
                    RRMergeFailure(m);
                    return mDNSfalse;
                }
                next = putZone(&m->omsg, next, limit, rr->zone, mDNSOpaque16fromIntVal(rr->resrec.rrclass));
                if (!next)
                {
                    LogMsg("SendGroupUpdates: ERROR! Cannot put zone, disabling merge");
                    RRMergeFailure(m);
                    return mDNSfalse;
                }
                anchorRR = rr;
            }

            rrSize = RREstimatedSize(rr, zoneSize - 4);

            if ((spaceleft - rrSize) < 0)
            {
                // If we can't fit even a single message, skip it, it will be sent separately
                // in CheckRecordUpdates
                if (!nrecords)
                {
                    LogInfo("SendGroupUpdates: Skipping message %s, spaceleft %d, rrSize %d", ARDisplayString(m, rr), spaceleft, rrSize);
                    // Mark this as not sent so that the caller knows about it
                    rr->SendRNow = uDNSInterfaceMark;
                    // We need to remove the merge delay so that we can send it immediately
                    rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
                    rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
                    rr = rr->next;
                    anchorRR = mDNSNULL;
                    sentallRecords = mDNSfalse;
                }
                else
                {
                    LogInfo("SendGroupUpdates:1: Parsed %d records and sending using %s, spaceleft %d, rrSize %d", nrecords, ARDisplayString(m, anchorRR), spaceleft, rrSize);
                    SendGroupRRMessage(m, anchorRR, next, AuthInfo);
                }
                break;      // breaks out of for loop
            }
            spaceleft -= rrSize;
            oldnext = next;
            LogInfo("SendGroupUpdates: Building a message with resource record %s, next %p, state %d, ttl %d", ARDisplayString(m, rr), next, rr->state, rr->resrec.rroriginalttl);
            if (!(next = BuildUpdateMessage(m, next, rr, limit)))
            {
                // We calculated the space and if we can't fit in, we had some bug in the calculation,
                // disable merge completely.
                LogMsg("SendGroupUpdates: ptr NULL while building message with %s", ARDisplayString(m, rr));
                RRMergeFailure(m);
                return mDNSfalse;
            }
            // If our estimate was higher, adjust to the actual size
            if ((next - oldnext) > rrSize)
                LogMsg("SendGroupUpdates: ERROR!! Record size estimation is wrong for %s, Estimate %d, Actual %d, state %d", ARDisplayString(m, rr), rrSize, next - oldnext, rr->state);
            else { spaceleft += rrSize; spaceleft -= (next - oldnext); }

            nrecords++;
            // We could have sent an update earlier with this "rr" as anchorRR for which we never got a response.
            // To preserve ordering, we blow away the previous connection before sending this.
            if (rr->tcp) { DisposeTCPConn(rr->tcp); rr->tcp = mDNSNULL;}
            rr->updateid = msgid;

            // By setting the retry time interval here, we will not be looking at these records
            // again when we return to CheckGroupRecordUpdates.
            SetRecordRetry(m, rr, 0);
        }
        // Either we have parsed all the records or stopped at "rr" above due to lack of space
        startRR = rr;
    }

    if (anchorRR)
    {
        LogInfo("SendGroupUpdates: Parsed %d records and sending using %s", nrecords, ARDisplayString(m, anchorRR));
        SendGroupRRMessage(m, anchorRR, next, AuthInfo);
    }
    return sentallRecords;
}

// Merge the record registrations and send them as a group only if they
// have same DomainAuthInfo and hence the same key to put the TSIG
mDNSlocal void CheckGroupRecordUpdates(mDNS *const m)
{
    AuthRecord *rr, *nextRR;
    // Keep sending as long as there is at least one record to be sent
    while (MarkRRForSending(m))
    {
        if (!SendGroupUpdates(m))
        {
            // if everything that was marked was not sent, send them out individually
            for (rr = m->ResourceRecords; rr; rr = nextRR)
            {
                // SendRecordRegistrtion might delete the rr from list, hence
                // dereference nextRR before calling the function
                nextRR = rr->next;
                if (rr->SendRNow == uDNSInterfaceMark)
                {
                    // Any records marked for sending should be eligible to be sent out
                    // immediately. Just being cautious
                    if (rr->LastAPTime + rr->ThisAPInterval - m->timenow > 0)
                    { LogMsg("CheckGroupRecordUpdates: ERROR!! Resourcerecord %s not ready", ARDisplayString(m, rr)); continue; }
                    rr->SendRNow = mDNSNULL;
                    SendRecordRegistration(m, rr);
                }
            }
        }
    }

    debugf("CheckGroupRecordUpdates: No work, returning");
    return;
}

mDNSlocal void hndlSRVChanged(mDNS *const m, AuthRecord *rr)
{
    // Reevaluate the target always as NAT/Target could have changed while
    // we were registering/deeregistering
    domainname *dt;
    const domainname *target = GetServiceTarget(m, rr);
    if (!target || target->c[0] == 0)
    {
        // we don't have a target, if we just derregistered, then we don't have to do anything
        if (rr->state == regState_DeregPending)
        {
            LogInfo("hndlSRVChanged: SRVChanged, No Target, SRV Deregistered for %##s, state %d", rr->resrec.name->c,
                    rr->state);
            rr->SRVChanged = mDNSfalse;
            dt = GetRRDomainNameTarget(&rr->resrec);
            if (dt) dt->c[0] = 0;
            rr->state = regState_NoTarget;  // Wait for the next target change
            rr->resrec.rdlength = rr->resrec.rdestimate = 0;
            return;
        }

        // we don't have a target, if we just registered, we need to deregister
        if (rr->state == regState_Pending)
        {
            LogInfo("hndlSRVChanged: SRVChanged, No Target, Deregistering again %##s, state %d", rr->resrec.name->c, rr->state);
            rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
            rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
            rr->state = regState_DeregPending;
            return;
        }
        LogInfo("hndlSRVChanged: Not in DeregPending or RegPending state %##s, state %d", rr->resrec.name->c, rr->state);
    }
    else
    {
        // If we were in registered state and SRV changed to NULL, we deregister and come back here
        // if we have a target, we need to register again.
        //
        // if we just registered check to see if it is same. If it is different just re-register the
        // SRV and its assoicated records
        //
        // UpdateOneSRVRecord takes care of re-registering all service records
        if ((rr->state == regState_DeregPending) ||
            (rr->state == regState_Pending && !SameDomainName(target, &rr->resrec.rdata->u.srv.target)))
        {
            dt = GetRRDomainNameTarget(&rr->resrec);
            if (dt) dt->c[0] = 0;
            rr->state = regState_NoTarget;  // NoTarget will allow us to pick up new target OR nat traversal state
            rr->resrec.rdlength = rr->resrec.rdestimate = 0;
            LogInfo("hndlSRVChanged: SRVChanged, Valid Target %##s, Registering all records for %##s, state %d",
                    target->c, rr->resrec.name->c, rr->state);
            rr->SRVChanged = mDNSfalse;
            UpdateOneSRVRecord(m, rr);
            return;
        }
        // Target did not change while this record was registering. Hence, we go to
        // Registered state - the state we started from.
        if (rr->state == regState_Pending) rr->state = regState_Registered;
    }

    rr->SRVChanged = mDNSfalse;
}

// Called with lock held
mDNSlocal void hndlRecordUpdateReply(mDNS *m, AuthRecord *rr, mStatus err, mDNSu32 random)
{
    mDNSBool InvokeCallback = mDNStrue;
    mDNSIPPort UpdatePort = zeroIPPort;

    mDNS_CheckLock(m);

    LogInfo("hndlRecordUpdateReply: err %d ID %d state %d %s(%p)", err, mDNSVal16(rr->updateid), rr->state, ARDisplayString(m, rr), rr);

    rr->updateError = err;

    SetRecordRetry(m, rr, random);

    rr->updateid = zeroID;  // Make sure that this is not considered as part of a group anymore
    // Later when need to send an update, we will get the zone data again. Thus we avoid
    // using stale information.
    //
    // Note: By clearing out the zone info here, it also helps better merging of records
    // in some cases. For example, when we get out regState_NoTarget state e.g., move out
    // of Double NAT, we want all the records to be in one update. Some BTMM records like
    // _autotunnel6 and host records are registered/deregistered when NAT state changes.
    // As they are re-registered the zone information is cleared out. To merge with other
    // records that might be possibly going out, clearing out the information here helps
    // as all of them try to get the zone data.
    if (rr->nta)
    {
        // We always expect the question to be stopped when we get a valid response from the server.
        // If the zone info tries to change during this time, updateid would be different and hence
        // this response should not have been accepted.
        if (rr->nta->question.ThisQInterval != -1)
            LogMsg("hndlRecordUpdateReply: ResourceRecord %s, zone info question %##s (%s) interval %d not -1",
                   ARDisplayString(m, rr), rr->nta->question.qname.c, DNSTypeName(rr->nta->question.qtype), rr->nta->question.ThisQInterval);
        UpdatePort = rr->nta->Port;
        CancelGetZoneData(m, rr->nta);
        rr->nta = mDNSNULL;
    }

    // If we are deregistering the record, then complete the deregistration. Ignore any NAT/SRV change
    // that could have happened during that time.
    if (rr->resrec.RecordType == kDNSRecordTypeDeregistering && rr->state == regState_DeregPending)
    {
        debugf("hndlRecordUpdateReply: Received reply for deregister record %##s type %d", rr->resrec.name->c, rr->resrec.rrtype);
        if (err) LogMsg("ERROR: Deregistration of record %##s type %d failed with error %d",
                        rr->resrec.name->c, rr->resrec.rrtype, err);
        rr->state = regState_Unregistered;
        CompleteDeregistration(m, rr);
        return;
    }

    // We are returning early without updating the state. When we come back from sleep we will re-register after
    // re-initializing all the state as though it is a first registration. If the record can't be registered e.g.,
    // no target, it will be deregistered. Hence, the updating to the right state should not matter when going
    // to sleep.
    if (m->SleepState)
    {
        // Need to set it to NoTarget state so that RecordReadyForSleep knows that
        // we are done
        if (rr->resrec.rrtype == kDNSType_SRV && rr->state == regState_DeregPending)
            rr->state = regState_NoTarget;
        return;
    }

    if (rr->state == regState_UpdatePending)
    {
        if (err) LogMsg("Update record failed for %##s (err %d)", rr->resrec.name->c, err);
        rr->state = regState_Registered;
        // deallocate old RData
        if (rr->UpdateCallback) rr->UpdateCallback(m, rr, rr->OrigRData, rr->OrigRDLen);
        SetNewRData(&rr->resrec, rr->InFlightRData, rr->InFlightRDLen);
        rr->OrigRData = mDNSNULL;
        rr->InFlightRData = mDNSNULL;
    }

    if (rr->SRVChanged)
    {
        if (rr->resrec.rrtype == kDNSType_SRV)
            hndlSRVChanged(m, rr);
        else
        {
            LogInfo("hndlRecordUpdateReply: Deregistered %##s (%s), state %d", rr->resrec.name->c, DNSTypeName(rr->resrec.rrtype), rr->state);
            rr->SRVChanged = mDNSfalse;
            if (rr->state != regState_DeregPending) LogMsg("hndlRecordUpdateReply: ResourceRecord %s not in DeregPending state %d", ARDisplayString(m, rr), rr->state);
            rr->state = regState_NoTarget;  // Wait for the next target change
        }
        return;
    }

    if (rr->state == regState_Pending || rr->state == regState_Refresh)
    {
        if (!err)
        {
            if (rr->state == regState_Refresh) InvokeCallback = mDNSfalse;
            rr->state = regState_Registered;
        }
        else
        {
            // Retry without lease only for non-Private domains
            LogMsg("hndlRecordUpdateReply: Registration of record %##s type %d failed with error %d", rr->resrec.name->c, rr->resrec.rrtype, err);
            if (!rr->Private && rr->uselease && err == mStatus_UnknownErr && mDNSSameIPPort(UpdatePort, UnicastDNSPort))
            {
                LogMsg("hndlRecordUpdateReply: Will retry update of record %##s without lease option", rr->resrec.name->c);
                rr->uselease = mDNSfalse;
                rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
                rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
                SetNextuDNSEvent(m, rr);
                return;
            }
            // Communicate the error to the application in the callback below
        }
    }

    if (rr->QueuedRData && rr->state == regState_Registered)
    {
        rr->state = regState_UpdatePending;
        rr->InFlightRData = rr->QueuedRData;
        rr->InFlightRDLen = rr->QueuedRDLen;
        rr->OrigRData = rr->resrec.rdata;
        rr->OrigRDLen = rr->resrec.rdlength;
        rr->QueuedRData = mDNSNULL;
        rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
        rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
        SetNextuDNSEvent(m, rr);
        return;
    }

    // Don't invoke the callback on error as this may not be useful to the client.
    // The client may potentially delete the resource record on error which we normally
    // delete during deregistration
    if (!err && InvokeCallback && rr->RecordCallback)
    {
        LogInfo("hndlRecordUpdateReply: Calling record callback on %##s", rr->resrec.name->c);
        mDNS_DropLockBeforeCallback();
        rr->RecordCallback(m, rr, err);
        mDNS_ReclaimLockAfterCallback();
    }
    // CAUTION: MUST NOT do anything more with rr after calling rr->Callback(), because the client's callback function
    // is allowed to do anything, including starting/stopping queries, registering/deregistering records, etc.
}

mDNSlocal void uDNS_ReceiveNATPMPPacket(mDNS *m, const mDNSInterfaceID InterfaceID, mDNSu8 *pkt, mDNSu16 len)
{
    NATTraversalInfo *ptr;
    NATAddrReply     *AddrReply    = (NATAddrReply    *)pkt;
    NATPortMapReply  *PortMapReply = (NATPortMapReply *)pkt;
    mDNSu32 nat_elapsed, our_elapsed;

    // Minimum NAT-PMP packet is vers (1) opcode (1) + err (2) = 4 bytes
    if (len < 4) { LogMsg("NAT-PMP message too short (%d bytes)", len); return; }

    // Read multi-byte error value (field is identical in a NATPortMapReply)
    AddrReply->err = (mDNSu16) ((mDNSu16)pkt[2] << 8 | pkt[3]);

    if (AddrReply->err == NATErr_Vers)
    {
        NATTraversalInfo *n;
        LogInfo("NAT-PMP version unsupported message received");
        for (n = m->NATTraversals; n; n=n->next)
        {
            // Send a NAT-PMP request for this operation as needed
            // and update the state variables
            uDNS_SendNATMsg(m, n, mDNSfalse, mDNSfalse);
        }

        m->NextScheduledNATOp = m->timenow;

        return;
    }

    // The minimum reasonable NAT-PMP packet length is vers (1) + opcode (1) + err (2) + upseconds (4) = 8 bytes
    // If it's not at least this long, bail before we byte-swap the upseconds field & overrun our buffer.
    // The retry timer will ensure we converge to correctness.
    if (len < 8)
    {
        LogMsg("NAT-PMP message too short (%d bytes) 0x%X 0x%X", len, AddrReply->opcode, AddrReply->err);
        return;
    }

    // Read multi-byte upseconds value (field is identical in a NATPortMapReply)
    AddrReply->upseconds = (mDNSs32) ((mDNSs32)pkt[4] << 24 | (mDNSs32)pkt[5] << 16 | (mDNSs32)pkt[6] << 8 | pkt[7]);

    nat_elapsed = AddrReply->upseconds - m->LastNATupseconds;
    our_elapsed = (m->timenow - m->LastNATReplyLocalTime) / mDNSPlatformOneSecond;
    debugf("uDNS_ReceiveNATPMPPacket %X upseconds %u nat_elapsed %d our_elapsed %d", AddrReply->opcode, AddrReply->upseconds, nat_elapsed, our_elapsed);

    // We compute a conservative estimate of how much the NAT gateways's clock should have advanced
    // 1. We subtract 12.5% from our own measured elapsed time, to allow for NAT gateways that have an inacurate clock that runs slowly
    // 2. We add a two-second safety margin to allow for rounding errors: e.g.
    //    -- if NAT gateway sends a packet at t=2.000 seconds, then one at t=7.999, that's approximately 6 real seconds,
    //       but based on the values in the packet (2,7) the apparent difference according to the packet is only 5 seconds
    //    -- if we're slow handling packets and/or we have coarse clock granularity,
    //       we could receive the t=2 packet at our t=1.999 seconds, which we round down to 1
    //       and the t=7.999 packet at our t=8.000 seconds, which we record as 8,
    //       giving an apparent local time difference of 7 seconds
    //    The two-second safety margin coves this possible calculation discrepancy
    if (AddrReply->upseconds < m->LastNATupseconds || nat_elapsed + 2 < our_elapsed - our_elapsed/8)
    { LogMsg("NAT-PMP epoch time check failed: assuming NAT gateway %#a rebooted", &m->Router); RecreateNATMappings(m, 0); }

    m->LastNATupseconds      = AddrReply->upseconds;
    m->LastNATReplyLocalTime = m->timenow;
#ifdef _LEGACY_NAT_TRAVERSAL_
    LNT_ClearState(m);
#endif // _LEGACY_NAT_TRAVERSAL_

    if (AddrReply->opcode == NATOp_AddrResponse)
    {
        if (!AddrReply->err && len < sizeof(NATAddrReply)) { LogMsg("NAT-PMP AddrResponse message too short (%d bytes)", len); return; }
        natTraversalHandleAddressReply(m, AddrReply->err, AddrReply->ExtAddr);
    }
    else if (AddrReply->opcode == NATOp_MapUDPResponse || AddrReply->opcode == NATOp_MapTCPResponse)
    {
        mDNSu8 Protocol = AddrReply->opcode & 0x7F;
        if (!PortMapReply->err)
        {
            if (len < sizeof(NATPortMapReply)) { LogMsg("NAT-PMP PortMapReply message too short (%d bytes)", len); return; }
            PortMapReply->NATRep_lease = (mDNSu32) ((mDNSu32)pkt[12] << 24 | (mDNSu32)pkt[13] << 16 | (mDNSu32)pkt[14] << 8 | pkt[15]);
        }

        // Since some NAT-PMP server implementations don't return the requested internal port in
        // the reply, we can't associate this reply with a particular NATTraversalInfo structure.
        // We globally keep track of the most recent error code for mappings.
        m->LastNATMapResultCode = PortMapReply->err;

        for (ptr = m->NATTraversals; ptr; ptr=ptr->next)
            if (ptr->Protocol == Protocol && mDNSSameIPPort(ptr->IntPort, PortMapReply->intport))
                natTraversalHandlePortMapReply(m, ptr, InterfaceID, PortMapReply->err, PortMapReply->extport, PortMapReply->NATRep_lease, NATTProtocolNATPMP);
    }
    else { LogMsg("Received NAT-PMP response with unknown opcode 0x%X", AddrReply->opcode); return; }

    // Don't need an SSDP socket if we get a NAT-PMP packet
    if (m->SSDPSocket) { debugf("uDNS_ReceiveNATPMPPacket destroying SSDPSocket %p", &m->SSDPSocket); mDNSPlatformUDPClose(m->SSDPSocket); m->SSDPSocket = mDNSNULL; }
}

mDNSlocal void uDNS_ReceivePCPPacket(mDNS *m, const mDNSInterfaceID InterfaceID, mDNSu8 *pkt, mDNSu16 len)
{
    NATTraversalInfo *ptr;
    PCPMapReply *reply = (PCPMapReply*)pkt;
    mDNSu32 client_delta, server_delta;
    mDNSBool checkEpochValidity = m->LastNATupseconds != 0;
    mDNSu8 strippedOpCode;
    mDNSv4Addr mappedAddress = zerov4Addr;
    mDNSu8 protocol = 0;
    mDNSIPPort intport = zeroIPPort;
    mDNSIPPort extport = zeroIPPort;

    // Minimum PCP packet is 24 bytes
    if (len < 24)
    {
        LogMsg("uDNS_ReceivePCPPacket: message too short (%d bytes)", len);
        return;
    }

    strippedOpCode = reply->opCode & 0x7f;

    if ((reply->opCode & 0x80) == 0x00 || (strippedOpCode != PCPOp_Announce && strippedOpCode != PCPOp_Map))
    {
        LogMsg("uDNS_ReceivePCPPacket: unhandled opCode %u", reply->opCode);
        return;
    }

    // Read multi-byte values
    reply->lifetime = (mDNSs32)((mDNSs32)pkt[4] << 24 | (mDNSs32)pkt[5] << 16 | (mDNSs32)pkt[ 6] << 8 | pkt[ 7]);
    reply->epoch    = (mDNSs32)((mDNSs32)pkt[8] << 24 | (mDNSs32)pkt[9] << 16 | (mDNSs32)pkt[10] << 8 | pkt[11]);

    client_delta = (m->timenow - m->LastNATReplyLocalTime) / mDNSPlatformOneSecond;
    server_delta = reply->epoch - m->LastNATupseconds;
    debugf("uDNS_ReceivePCPPacket: %X %X upseconds %u client_delta %d server_delta %d", reply->opCode, reply->result, reply->epoch, client_delta, server_delta);

    // If seconds since the epoch is 0, use 1 so we'll check epoch validity next time
    m->LastNATupseconds      = reply->epoch ? reply->epoch : 1;
    m->LastNATReplyLocalTime = m->timenow;

#ifdef _LEGACY_NAT_TRAVERSAL_
    LNT_ClearState(m);
#endif // _LEGACY_NAT_TRAVERSAL_

    // Don't need an SSDP socket if we get a PCP packet
    if (m->SSDPSocket) { debugf("uDNS_ReceivePCPPacket: destroying SSDPSocket %p", &m->SSDPSocket); mDNSPlatformUDPClose(m->SSDPSocket); m->SSDPSocket = mDNSNULL; }

    if (checkEpochValidity && (client_delta + 2 < server_delta - server_delta / 16 || server_delta + 2 < client_delta - client_delta / 16))
    {
        // If this is an ANNOUNCE packet, wait a random interval up to 5 seconds
        // otherwise, refresh immediately
        mDNSu32 waitTicks = strippedOpCode ? 0 : mDNSRandom(PCP_WAITSECS_AFTER_EPOCH_INVALID * mDNSPlatformOneSecond);
        LogMsg("uDNS_ReceivePCPPacket: Epoch invalid, %#a likely rebooted, waiting %u ticks", &m->Router, waitTicks);
        RecreateNATMappings(m, waitTicks);
        // we can ignore the rest of this packet, as new requests are about to go out
        return;
    }

    if (strippedOpCode == PCPOp_Announce)
        return;

    // We globally keep track of the most recent error code for mappings.
    // This seems bad to do with PCP, but best not change it now.
    m->LastNATMapResultCode = reply->result;

    if (!reply->result)
    {
        if (len < sizeof(PCPMapReply))
        {
            LogMsg("uDNS_ReceivePCPPacket: mapping response too short (%d bytes)", len);
            return;
        }

        // Check the nonce
        if (reply->nonce[0] != m->PCPNonce[0] || reply->nonce[1] != m->PCPNonce[1] || reply->nonce[2] != m->PCPNonce[2])
        {
            LogMsg("uDNS_ReceivePCPPacket: invalid nonce, ignoring. received { %x %x %x } expected { %x %x %x }",
                   reply->nonce[0], reply->nonce[1], reply->nonce[2],
                    m->PCPNonce[0],  m->PCPNonce[1],  m->PCPNonce[2]);
            return;
        }

        // Get the values
        protocol = reply->protocol;
        intport = reply->intPort;
        extport = reply->extPort;

        // Get the external address, which should be mapped, since we only support IPv4
        if (!mDNSAddrIPv4FromMappedIPv6(&reply->extAddress, &mappedAddress))
        {
            LogMsg("uDNS_ReceivePCPPacket: unexpected external address: %.16a", &reply->extAddress);
            reply->result = NATErr_NetFail;
            // fall through to report the error
        }
        else if (mDNSIPv4AddressIsZero(mappedAddress))
        {
            // If this is the deletion case, we will have sent the zero IPv4-mapped address
            // in our request, and the server should reflect it in the response, so we
            // should not log about receiving a zero address. And in this case, we no
            // longer have a NATTraversal to report errors back to, so it's ok to set the
            // result here.
            // In other cases, a zero address is an error, and we will have a NATTraversal
            // to report back to, so set an error and fall through to report it.
            // CheckNATMappings will log the error.
            reply->result = NATErr_NetFail;
        }
    }
    else
    {
        LogInfo("uDNS_ReceivePCPPacket: error received from server. opcode %X result %X lifetime %X epoch %X",
                reply->opCode, reply->result, reply->lifetime, reply->epoch);

        // If the packet is long enough, get the protocol & intport for matching to report
        // the error
        if (len >= sizeof(PCPMapReply))
        {
            protocol = reply->protocol;
            intport = reply->intPort;
        }
    }

    for (ptr = m->NATTraversals; ptr; ptr=ptr->next)
    {
        mDNSu8 ptrProtocol = ((ptr->Protocol & NATOp_MapTCP) == NATOp_MapTCP ? PCPProto_TCP : PCPProto_UDP);
        if ((protocol == ptrProtocol && mDNSSameIPPort(ptr->IntPort, intport)) ||
            (!ptr->Protocol && protocol == PCPProto_TCP && mDNSSameIPPort(DiscardPort, intport)))
        {
            natTraversalHandlePortMapReplyWithAddress(m, ptr, InterfaceID, reply->result ? NATErr_NetFail : NATErr_None, mappedAddress, extport, reply->lifetime, NATTProtocolPCP);
        }
    }
}

mDNSexport void uDNS_ReceiveNATPacket(mDNS *m, const mDNSInterfaceID InterfaceID, mDNSu8 *pkt, mDNSu16 len)
{
    if (len == 0)
        LogMsg("uDNS_ReceiveNATPacket: zero length packet");
    else if (pkt[0] == PCP_VERS)
        uDNS_ReceivePCPPacket(m, InterfaceID, pkt, len);
    else if (pkt[0] == NATMAP_VERS)
        uDNS_ReceiveNATPMPPacket(m, InterfaceID, pkt, len);
    else
        LogMsg("uDNS_ReceiveNATPacket: packet with version %u (expected %u or %u)", pkt[0], PCP_VERS, NATMAP_VERS);
}

// Called from mDNSCoreReceive with the lock held
mDNSexport void uDNS_ReceiveMsg(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr, const mDNSIPPort srcport)
{
    DNSQuestion *qptr;
    mStatus err = mStatus_NoError;

    mDNSu8 StdR    = kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery;
    mDNSu8 UpdateR = kDNSFlag0_QR_Response | kDNSFlag0_OP_Update;
    mDNSu8 QR_OP   = (mDNSu8)(msg->h.flags.b[0] & kDNSFlag0_QROP_Mask);
    mDNSu8 rcode   = (mDNSu8)(msg->h.flags.b[1] & kDNSFlag1_RC_Mask);

    (void)srcport; // Unused

    debugf("uDNS_ReceiveMsg from %#-15a with "
           "%2d Question%s %2d Answer%s %2d Authorit%s %2d Additional%s %d bytes",
           srcaddr,
           msg->h.numQuestions,   msg->h.numQuestions   == 1 ? ", "   : "s,",
           msg->h.numAnswers,     msg->h.numAnswers     == 1 ? ", "   : "s,",
           msg->h.numAuthorities, msg->h.numAuthorities == 1 ? "y,  " : "ies,",
           msg->h.numAdditionals, msg->h.numAdditionals == 1 ? ""     : "s", end - msg->data);
#if MDNSRESPONDER_SUPPORTS(APPLE, SYMPTOMS) && !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    if (NumUnreachableDNSServers > 0)
        SymptomReporterDNSServerReachable(m, srcaddr);
#endif

    if (QR_OP == StdR)
    {
        //if (srcaddr && recvLLQResponse(m, msg, end, srcaddr, srcport)) return;
        for (qptr = m->Questions; qptr; qptr = qptr->next)
            if (msg->h.flags.b[0] & kDNSFlag0_TC && mDNSSameOpaque16(qptr->TargetQID, msg->h.id) && m->timenow - qptr->LastQTime < RESPONSE_WINDOW)
            {
                if (!srcaddr) LogMsg("uDNS_ReceiveMsg: TCP DNS response had TC bit set: ignoring");
                else
                {
                    uDNS_RestartQuestionAsTCP(m, qptr, srcaddr, srcport);
                }
            }
    }

    if (QR_OP == UpdateR)
    {
        mDNSu32 pktlease = 0;
        mDNSBool gotlease = GetPktLease(m, msg, end, &pktlease);
        mDNSu32 lease = gotlease ? pktlease : 60 * 60; // If lease option missing, assume one hour
        mDNSs32 expire = m->timenow + (mDNSs32)lease * mDNSPlatformOneSecond;
        mDNSu32 random = mDNSRandom((mDNSs32)lease * mDNSPlatformOneSecond/10);

        //rcode = kDNSFlag1_RC_ServFail;    // Simulate server failure (rcode 2)

        // Walk through all the records that matches the messageID. There could be multiple
        // records if we had sent them in a group
        if (m->CurrentRecord)
            LogMsg("uDNS_ReceiveMsg ERROR m->CurrentRecord already set %s", ARDisplayString(m, m->CurrentRecord));
        m->CurrentRecord = m->ResourceRecords;
        while (m->CurrentRecord)
        {
            AuthRecord *rptr = m->CurrentRecord;
            m->CurrentRecord = m->CurrentRecord->next;
            if (AuthRecord_uDNS(rptr) && mDNSSameOpaque16(rptr->updateid, msg->h.id))
            {
                err = checkUpdateResult(m, rptr->resrec.name, rcode, msg, end);
                if (!err && rptr->uselease && lease)
                    if (rptr->expire - expire >= 0 || rptr->state != regState_UpdatePending)
                    {
                        rptr->expire = expire;
                        rptr->refreshCount = 0;
                    }
                // We pass the random value to make sure that if we update multiple
                // records, they all get the same random value
                hndlRecordUpdateReply(m, rptr, err, random);
            }
        }
    }
    debugf("Received unexpected response: ID %d matches no active records", mDNSVal16(msg->h.id));
}

// ***************************************************************************
// MARK: - Query Routines

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
mDNSexport void sendLLQRefresh(mDNS *m, DNSQuestion *q)
{
    mDNSu8 *end;
    LLQOptData llq;

    if (q->ReqLease)
        if ((q->state == LLQ_Established && q->ntries >= kLLQ_MAX_TRIES) || q->expire - m->timenow < 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "Unable to refresh LLQ " PRI_DM_NAME " (" PUB_S ") - will retry in %d seconds",
                DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), LLQ_POLL_INTERVAL / mDNSPlatformOneSecond);
            StartLLQPolling(m,q);
            return;
        }

    llq.vers     = kLLQ_Vers;
    llq.llqOp    = kLLQOp_Refresh;
    llq.err      = q->tcp ? GetLLQEventPort(m, &q->servAddr) : LLQErr_NoError;  // If using TCP tell server what UDP port to send notifications to
    llq.id       = q->id;
    llq.llqlease = q->ReqLease;

    InitializeDNSMessage(&m->omsg.h, q->TargetQID, uQueryFlags);
    end = putLLQ(&m->omsg, m->omsg.data, q, &llq);
    if (!end)
    {
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "sendLLQRefresh: putLLQ failed " PRI_DM_NAME " (" PUB_S ")", DM_NAME_PARAM(&q->qname),
            DNSTypeName(q->qtype));
        return;
    }

    {
        mStatus err;

        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "sendLLQRefresh: using existing UDP session " PRI_DM_NAME " (" PUB_S ")", DM_NAME_PARAM(&q->qname),
            DNSTypeName(q->qtype));

        err = mDNSSendDNSMessage(m, &m->omsg, end, mDNSInterface_Any, q->tcp ? q->tcp->sock : mDNSNULL, q->LocalSocket, &q->servAddr, q->servPort, mDNSNULL, mDNSfalse);
        if (err)
        {
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "sendLLQRefresh: mDNSSendDNSMessage" PUB_S " failed: %d", q->tcp ? " (TCP)" : "", err);
            if (q->tcp) { DisposeTCPConn(q->tcp); q->tcp = mDNSNULL; }
        }
    }

    q->ntries++;

    debugf("sendLLQRefresh ntries %d %##s (%s)", q->ntries, q->qname.c, DNSTypeName(q->qtype));

    q->LastQTime = m->timenow;
    SetNextQueryTime(m, q);
}

mDNSexport void LLQGotZoneData(mDNS *const m, mStatus err, const ZoneData *zoneInfo)
{
    DNSQuestion *q = (DNSQuestion *)zoneInfo->ZoneDataContext;

    mDNS_Lock(m);

    // If we get here it means that the GetZoneData operation has completed.
    // We hold on to the zone data if it is AutoTunnel as we use the hostname
    // in zoneInfo during the TLS connection setup.
    q->servAddr = zeroAddr;
    q->servPort = zeroIPPort;

    if (!err && !mDNSIPPortIsZero(zoneInfo->Port) && !mDNSAddressIsZero(&zoneInfo->Addr) && zoneInfo->Host.c[0])
    {
        q->servAddr = zoneInfo->Addr;
        q->servPort = zoneInfo->Port;
        // We don't need the zone data as we use it only for the Host information which we
        // don't need if we are not going to use TLS connections.
        if (q->nta)
        {
            if (q->nta != zoneInfo) LogMsg("LLQGotZoneData: nta (%p) != zoneInfo (%p)  %##s (%s)", q->nta, zoneInfo, q->qname.c, DNSTypeName(q->qtype));
            CancelGetZoneData(m, q->nta);
            q->nta = mDNSNULL;
        }
        q->ntries = 0;
        debugf("LLQGotZoneData %#a:%d", &q->servAddr, mDNSVal16(q->servPort));
        startLLQHandshake(m, q);
    }
    else
    {
        if (q->nta)
        {
            if (q->nta != zoneInfo) LogMsg("LLQGotZoneData: nta (%p) != zoneInfo (%p)  %##s (%s)", q->nta, zoneInfo, q->qname.c, DNSTypeName(q->qtype));
            CancelGetZoneData(m, q->nta);
            q->nta = mDNSNULL;
        }
        StartLLQPolling(m,q);
        if (err == mStatus_NoSuchNameErr)
        {
            // this actually failed, so mark it by setting address to all ones
            q->servAddr.type = mDNSAddrType_IPv4;
            q->servAddr.ip.v4 = onesIPv4Addr;
        }
    }

    mDNS_Unlock(m);
}
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
mDNSlocal mDNSBool SubscribeToDNSPushServer(mDNS *m, DNSQuestion *q,
    DNSPushZone **const outZone, DNSPushServer **const outServer);

mDNSlocal const char *DNSPushServerConnectStateToString(DNSPushServer_ConnectState state);

mDNSexport void DNSPushGotZoneData(mDNS *const m, const mStatus err, const ZoneData *const zoneInfo)
{
    DNSQuestion *const q = (DNSQuestion *)zoneInfo->ZoneDataContext;
    const mDNSu32 requestID = q->request_id;
    const mDNSu16 questionID = mDNSVal16(q->TargetQID);
    const mDNSu16 subquestionID = mDNSVal16(zoneInfo->question.TargetQID);
    mDNSBool succeeded;
    mDNS_Lock(m);

    if (err != mStatus_NoError)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[R%u->Q%u->subQ%u] Failed to get the zone data - err: %d.",
            requestID, questionID, subquestionID, err);
        succeeded = mDNSfalse;
        goto exit;
    }

    // If we get here it means that the GetZoneData operation has completed.
    q->servAddr = zeroAddr;
    q->servPort = zeroIPPort;

    // We should always have zone information if no error happens.
    if (zoneInfo == mDNSNULL || mDNSIPPortIsZero(zoneInfo->Port) || zoneInfo->Host.c[0] == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "[R%u->Q%u->subQ%u] Invalid zoneInfo.", requestID,
            questionID, subquestionID);
        succeeded = mDNSfalse;
        goto exit;
    }

    // Start connecting to the DNS push server we found.
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u->subQ%u] Found a new DNS push server for the served zone - "
        "server: " PRI_DM_NAME ":%d, zone: " PRI_DM_NAME ".", requestID, questionID, subquestionID,
        DM_NAME_PARAM(&zoneInfo->Host), mDNSVal16(zoneInfo->Port), DM_NAME_PARAM(&zoneInfo->ZoneName));

    q->state = LLQ_DNSPush_Connecting;
    succeeded = SubscribeToDNSPushServer(m, q, &q->dnsPushZone, &q->dnsPushServer);
    if (!succeeded)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[R%u->Q%u] Failed to connect to the DNS push server.",
            requestID, questionID);
        goto exit;
    }

    const DNSPushServer_ConnectState state = q->dnsPushServer->connectState;
    // Valid state checking, should never fail.
    if (state != DNSPushServerConnectionInProgress &&
        state != DNSPushServerConnected &&
        state != DNSPushServerSessionEstablished)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "[R%u->Q%u->PushS%u] Invalid DNS push server state - "
            "state: " PUB_S ".", requestID, questionID, q->dnsPushServer->serial,
            DNSPushServerConnectStateToString(state));
        DNSPushServerCancel(q->dnsPushServer, mDNSfalse);
        goto exit;
    }

exit:
    if (!succeeded)
    {
        // If we are unable to connect to the DNS push server for some reason, fall back to LLQ poll.
        StartLLQPolling(m, q);
    }
    mDNS_Unlock(m);
}
#endif

// ***************************************************************************
// MARK: - Dynamic Updates

// Called in normal callback context (i.e. mDNS_busy and mDNS_reentrancy are both 1)
mDNSexport void RecordRegistrationGotZoneData(mDNS *const m, mStatus err, const ZoneData *zoneData)
{
    AuthRecord *newRR;
    AuthRecord *ptr;
    int c1, c2;

    if (!zoneData) { LogMsg("ERROR: RecordRegistrationGotZoneData invoked with NULL result and no error"); return; }

    newRR = (AuthRecord*)zoneData->ZoneDataContext;

    if (newRR->nta != zoneData)
        LogMsg("RecordRegistrationGotZoneData: nta (%p) != zoneData (%p)  %##s (%s)", newRR->nta, zoneData, newRR->resrec.name->c, DNSTypeName(newRR->resrec.rrtype));

    mDNS_VerifyLockState("Check Lock", mDNSfalse, m->mDNS_busy, m->mDNS_reentrancy, __func__, __LINE__);

    // make sure record is still in list (!!!)
    for (ptr = m->ResourceRecords; ptr; ptr = ptr->next) if (ptr == newRR) break;
    if (!ptr)
    {
        LogMsg("RecordRegistrationGotZoneData - RR no longer in list.  Discarding.");
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    // check error/result
    if (err)
    {
        if (err != mStatus_NoSuchNameErr) LogMsg("RecordRegistrationGotZoneData: error %d", err);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    if (newRR->resrec.rrclass != zoneData->ZoneClass)
    {
        LogMsg("ERROR: New resource record's class (%d) does not match zone class (%d)", newRR->resrec.rrclass, zoneData->ZoneClass);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    // Don't try to do updates to the root name server.
    // We might be tempted also to block updates to any single-label name server (e.g. com, edu, net, etc.) but some
    // organizations use their own private pseudo-TLD, like ".home", etc, and we don't want to block that.
    if (zoneData->ZoneName.c[0] == 0)
    {
        LogInfo("RecordRegistrationGotZoneData: No name server found claiming responsibility for \"%##s\"!", newRR->resrec.name->c);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    // Store discovered zone data
    c1 = CountLabels(newRR->resrec.name);
    c2 = CountLabels(&zoneData->ZoneName);
    if (c2 > c1)
    {
        LogMsg("RecordRegistrationGotZoneData: Zone \"%##s\" is longer than \"%##s\"", zoneData->ZoneName.c, newRR->resrec.name->c);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }
    newRR->zone = SkipLeadingLabels(newRR->resrec.name, c1-c2);
    if (!SameDomainName(newRR->zone, &zoneData->ZoneName))
    {
        LogMsg("RecordRegistrationGotZoneData: Zone \"%##s\" does not match \"%##s\" for \"%##s\"", newRR->zone->c, zoneData->ZoneName.c, newRR->resrec.name->c);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    if (mDNSIPPortIsZero(zoneData->Port) || mDNSAddressIsZero(&zoneData->Addr) || !zoneData->Host.c[0])
    {
        LogInfo("RecordRegistrationGotZoneData: No _dns-update._udp service found for \"%##s\"!", newRR->resrec.name->c);
        CancelGetZoneData(m, newRR->nta);
        newRR->nta = mDNSNULL;
        return;
    }

    newRR->Private      = zoneData->ZonePrivate;
    debugf("RecordRegistrationGotZoneData: Set zone information for %##s %##s to %#a:%d",
           newRR->resrec.name->c, zoneData->ZoneName.c, &zoneData->Addr, mDNSVal16(zoneData->Port));

    // If we are deregistering, uDNS_DeregisterRecord will do that as it has the zone data now.
    if (newRR->state == regState_DeregPending)
    {
        mDNS_Lock(m);
        uDNS_DeregisterRecord(m, newRR);
        mDNS_Unlock(m);
        return;
    }

    if (newRR->resrec.rrtype == kDNSType_SRV)
    {
        const domainname *target;
        // Reevaluate the target always as NAT/Target could have changed while
        // we were fetching zone data.
        mDNS_Lock(m);
        target = GetServiceTarget(m, newRR);
        mDNS_Unlock(m);
        if (!target || target->c[0] == 0)
        {
            domainname *t = GetRRDomainNameTarget(&newRR->resrec);
            LogInfo("RecordRegistrationGotZoneData - no target for %##s", newRR->resrec.name->c);
            if (t) t->c[0] = 0;
            newRR->resrec.rdlength = newRR->resrec.rdestimate = 0;
            newRR->state = regState_NoTarget;
            CancelGetZoneData(m, newRR->nta);
            newRR->nta = mDNSNULL;
            return;
        }
    }
    // If we have non-zero service port (always?)
    // and a private address, and update server is non-private
    // and this service is AutoTarget
    // then initiate a NAT mapping request. On completion it will do SendRecordRegistration() for us
    if (newRR->resrec.rrtype == kDNSType_SRV && !mDNSIPPortIsZero(newRR->resrec.rdata->u.srv.port) &&
        mDNSv4AddrIsRFC1918(&m->AdvertisedV4.ip.v4) && newRR->nta && !mDNSAddrIsRFC1918(&newRR->nta->Addr) &&
        newRR->AutoTarget == Target_AutoHostAndNATMAP)
    {
        // During network transitions, we are called multiple times in different states. Setup NAT
        // state just once for this record.
        if (!newRR->NATinfo.clientContext)
        {
            LogInfo("RecordRegistrationGotZoneData StartRecordNatMap %s", ARDisplayString(m, newRR));
            newRR->state = regState_NATMap;
            StartRecordNatMap(m, newRR);
            return;
        }
        else LogInfo("RecordRegistrationGotZoneData: StartRecordNatMap for %s, state %d, context %p", ARDisplayString(m, newRR), newRR->state, newRR->NATinfo.clientContext);
    }
    mDNS_Lock(m);
    // We want IsRecordMergeable to check whether it is a record whose update can be
    // sent with others. We set the time before we call IsRecordMergeable, so that
    // it does not fail this record based on time. We are interested in other checks
    // at this time. If a previous update resulted in error, then don't reset the
    // interval. Preserve the back-off so that we don't keep retrying aggressively.
    if (newRR->updateError == mStatus_NoError)
    {
        newRR->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
        newRR->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
    }
    if (IsRecordMergeable(m, newRR, m->timenow + MERGE_DELAY_TIME))
    {
        // Delay the record registration by MERGE_DELAY_TIME so that we can merge them
        // into one update
        LogInfo("RecordRegistrationGotZoneData: Delayed registration for %s", ARDisplayString(m, newRR));
        newRR->LastAPTime += MERGE_DELAY_TIME;
    }
    mDNS_Unlock(m);
}

mDNSlocal void SendRecordDeregistration(mDNS *m, AuthRecord *rr)
{
    mDNSu8 *ptr = m->omsg.data;
    mDNSu8 *limit;
    DomainAuthInfo *AuthInfo;

    mDNS_CheckLock(m);

    if (!rr->nta || mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4))
    {
        LogMsg("SendRecordDeRegistration: No zone info for Resource record %s RecordType %d", ARDisplayString(m, rr), rr->resrec.RecordType);
        return;
    }

    limit = ptr + AbsoluteMaxDNSMessageData;
    AuthInfo = GetAuthInfoForName_internal(m, rr->resrec.name);
    limit -= RRAdditionalSize(AuthInfo);

    rr->updateid = mDNS_NewMessageID(m);
    InitializeDNSMessage(&m->omsg.h, rr->updateid, UpdateReqFlags);

    // set zone
    ptr = putZone(&m->omsg, ptr, limit, rr->zone, mDNSOpaque16fromIntVal(rr->resrec.rrclass));
    if (!ptr) goto exit;

    ptr = BuildUpdateMessage(m, ptr, rr, limit);

    if (!ptr) goto exit;

    if (rr->Private)
    {
        LogInfo("SendRecordDeregistration TCP %p %s", rr->tcp, ARDisplayString(m, rr));
        if (rr->tcp) LogInfo("SendRecordDeregistration: Disposing existing TCP connection for %s", ARDisplayString(m, rr));
        if (rr->tcp) { DisposeTCPConn(rr->tcp); rr->tcp = mDNSNULL; }
        if (!rr->nta) { LogMsg("SendRecordDeregistration:Private:ERROR!! nta is NULL for %s", ARDisplayString(m, rr)); return; }
        rr->tcp = MakeTCPConn(m, &m->omsg, ptr, kTCPSocketFlags_UseTLS, &rr->nta->Addr, rr->nta->Port, &rr->nta->Host, mDNSNULL, rr);
    }
    else
    {
        mStatus err;
        LogInfo("SendRecordDeregistration UDP %s", ARDisplayString(m, rr));
        if (!rr->nta) { LogMsg("SendRecordDeregistration:ERROR!! nta is NULL for %s", ARDisplayString(m, rr)); return; }
        err = mDNSSendDNSMessage(m, &m->omsg, ptr, mDNSInterface_Any, mDNSNULL, mDNSNULL, &rr->nta->Addr, rr->nta->Port, GetAuthInfoForName_internal(m, rr->resrec.name), mDNSfalse);
        if (err) debugf("ERROR: SendRecordDeregistration - mDNSSendDNSMessage - %d", err);
        //if (rr->state == regState_DeregPending) CompleteDeregistration(m, rr);        // Don't touch rr after this
    }
    SetRecordRetry(m, rr, 0);
    return;
exit:
    LogMsg("SendRecordDeregistration: Error formatting message for %s", ARDisplayString(m, rr));
}

mDNSexport mStatus uDNS_DeregisterRecord(mDNS *const m, AuthRecord *const rr)
{
    DomainAuthInfo *info;

    LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: Resource Record " PRI_S ", state %d", ARDisplayString(m, rr), rr->state);

    switch (rr->state)
    {
    case regState_Refresh:
    case regState_Pending:
    case regState_UpdatePending:
    case regState_Registered: break;
    case regState_DeregPending: break;
    MDNS_COVERED_SWITCH_DEFAULT: break;

    case regState_NATError:
    case regState_NATMap:
    // A record could be in NoTarget to start with if the corresponding SRV record could not find a target.
    // It is also possible to reenter the NoTarget state when we move to a network with a NAT that has
    // no {PCP, NAT-PMP, UPnP/IGD} support. In that case before we entered NoTarget, we already deregistered with
    // the server.
    case regState_NoTarget:
    case regState_Unregistered:
    case regState_Zero:
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: State %d for " PRI_DM_NAME " type " PUB_S,
            rr->state, DM_NAME_PARAM(rr->resrec.name), DNSTypeName(rr->resrec.rrtype));
        // This function may be called during sleep when there are no sleep proxy servers
        if (rr->resrec.RecordType == kDNSRecordTypeDeregistering) CompleteDeregistration(m, rr);
        return mStatus_NoError;
    }

    // if unsent rdata is queued, free it.
    //
    // The data may be queued in QueuedRData or InFlightRData.
    //
    // 1) If the record is in Registered state, we store it in InFlightRData and copy the same in "rdata"
    //   *just* before sending the update to the server. Till we get the response, InFlightRData and "rdata"
    //   in the resource record are same. We don't want to free in that case. It will be freed when "rdata"
    //   is freed. If they are not same, the update has not been sent and we should free it here.
    //
    // 2) If the record is in UpdatePending state, we queue the update in QueuedRData. When the previous update
    //   comes back from the server, we copy it from QueuedRData to InFlightRData and repeat (1). This implies
    //   that QueuedRData can never be same as "rdata" in the resource record. As long as we have something
    //   left in QueuedRData, we should free it here.

    if (rr->InFlightRData && rr->UpdateCallback)
    {
        if (rr->InFlightRData != rr->resrec.rdata)
        {
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: Freeing InFlightRData for " PRI_S, ARDisplayString(m, rr));
            rr->UpdateCallback(m, rr, rr->InFlightRData, rr->InFlightRDLen);
            rr->InFlightRData = mDNSNULL;
        }
        else
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: InFlightRData same as rdata for " PRI_S, ARDisplayString(m, rr));
    }

    if (rr->QueuedRData && rr->UpdateCallback)
    {
        if (rr->QueuedRData == rr->resrec.rdata)
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: ERROR!! QueuedRData same as rdata for " PRI_S, ARDisplayString(m, rr));
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: Freeing QueuedRData for " PRI_S, ARDisplayString(m, rr));
            rr->UpdateCallback(m, rr, rr->QueuedRData, rr->QueuedRDLen);
            rr->QueuedRData = mDNSNULL;
        }
    }

    // If a current group registration is pending, we can't send this deregisration till that registration
    // has reached the server i.e., the ordering is important. Previously, if we did not send this
    // registration in a group, then the previous connection will be torn down as part of sending the
    // deregistration. If we send this in a group, we need to locate the resource record that was used
    // to send this registration and terminate that connection. This means all the updates on that might
    // be lost (assuming the response is not waiting for us at the socket) and the retry will send the
    // update again sometime in the near future.
    //
    // NOTE: SSL handshake failures normally free the TCP connection immediately. Hence, you may not
    // find the TCP below there. This case can happen only when tcp is trying to actively retransmit
    // the request or SSL negotiation taking time i.e resource record is actively trying to get the
    // message to the server. During that time a deregister has to happen.

    if (!mDNSOpaque16IsZero(rr->updateid))
    {
        AuthRecord *anchorRR;
        mDNSBool found = mDNSfalse;
        for (anchorRR = m->ResourceRecords; anchorRR; anchorRR = anchorRR->next)
        {
            if (AuthRecord_uDNS(rr) && mDNSSameOpaque16(anchorRR->updateid, rr->updateid) && anchorRR->tcp)
            {
                LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: Found Anchor RR " PRI_S " terminated", ARDisplayString(m, anchorRR));
                if (found)
                {
                    LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNS_DeregisterRecord: ERROR: Another anchorRR " PRI_S " found",
                        ARDisplayString(m, anchorRR));
                }
                DisposeTCPConn(anchorRR->tcp);
                anchorRR->tcp = mDNSNULL;
                found = mDNStrue;
            }
        }
        if (!found)
        {
            LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "uDNSDeregisterRecord: Cannot find the anchor Resource Record for " PRI_S ", not an error",
                ARDisplayString(m, rr));
        }
    }

    // Retry logic for deregistration should be no different from sending registration the first time.
    // Currently ThisAPInterval most likely is set to the refresh interval
    rr->state          = regState_DeregPending;
    rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
    rr->LastAPTime     = m->timenow - INIT_RECORD_REG_INTERVAL;
    info = GetAuthInfoForName_internal(m, rr->resrec.name);
    if (IsRecordMergeable(m, rr, m->timenow + MERGE_DELAY_TIME))
    {
        // Delay the record deregistration by MERGE_DELAY_TIME so that we can merge them
        // into one update. If the domain is being deleted, delay by 2 * MERGE_DELAY_TIME
        // so that we can merge all the AutoTunnel records and the service records in
        // one update (they get deregistered a little apart)
        if (info && info->deltime) rr->LastAPTime += (2 * MERGE_DELAY_TIME);
        else rr->LastAPTime += MERGE_DELAY_TIME;
    }
    // IsRecordMergeable could have returned false for several reasons e.g., DontMerge is set or
    // no zone information. Most likely it is the latter, CheckRecordUpdates will fetch the zone
    // data when it encounters this record.

    if (m->NextuDNSEvent - (rr->LastAPTime + rr->ThisAPInterval) >= 0)
        m->NextuDNSEvent = (rr->LastAPTime + rr->ThisAPInterval);

    return mStatus_NoError;
}

mDNSexport mStatus uDNS_UpdateRecord(mDNS *m, AuthRecord *rr)
{
    LogInfo("uDNS_UpdateRecord: Resource Record %##s, state %d", rr->resrec.name->c, rr->state);
    switch(rr->state)
    {
    case regState_DeregPending:
    case regState_Unregistered:
        // not actively registered
        goto unreg_error;

    case regState_NATMap:
    case regState_NoTarget:
        // change rdata directly since it hasn't been sent yet
        if (rr->UpdateCallback) rr->UpdateCallback(m, rr, rr->resrec.rdata, rr->resrec.rdlength);
        SetNewRData(&rr->resrec, rr->NewRData, rr->newrdlength);
        rr->NewRData = mDNSNULL;
        return mStatus_NoError;

    case regState_Pending:
    case regState_Refresh:
    case regState_UpdatePending:
        // registration in-flight. queue rdata and return
        if (rr->QueuedRData && rr->UpdateCallback)
            // if unsent rdata is already queued, free it before we replace it
            rr->UpdateCallback(m, rr, rr->QueuedRData, rr->QueuedRDLen);
        rr->QueuedRData = rr->NewRData;
        rr->QueuedRDLen = rr->newrdlength;
        rr->NewRData = mDNSNULL;
        return mStatus_NoError;

    case regState_Registered:
        rr->OrigRData = rr->resrec.rdata;
        rr->OrigRDLen = rr->resrec.rdlength;
        rr->InFlightRData = rr->NewRData;
        rr->InFlightRDLen = rr->newrdlength;
        rr->NewRData = mDNSNULL;
        rr->state = regState_UpdatePending;
        rr->ThisAPInterval = INIT_RECORD_REG_INTERVAL;
        rr->LastAPTime = m->timenow - INIT_RECORD_REG_INTERVAL;
        SetNextuDNSEvent(m, rr);
        return mStatus_NoError;

    case regState_Zero:
    case regState_NATError:
        LogMsg("ERROR: uDNS_UpdateRecord called for record %##s with bad state regState_NATError", rr->resrec.name->c);
        return mStatus_UnknownErr;      // states for service records only

    MDNS_COVERED_SWITCH_DEFAULT:
        break;
    }
    LogMsg("uDNS_UpdateRecord: Unknown state %d for %##s", rr->state, rr->resrec.name->c);

unreg_error:
    LogMsg("uDNS_UpdateRecord: Requested update of record %##s type %d, in erroneous state %d",
           rr->resrec.name->c, rr->resrec.rrtype, rr->state);
    return mStatus_Invalid;
}

// ***************************************************************************
// MARK: - Periodic Execution Routines

#if !MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

mDNSlocal const char *LLQStateToString(LLQ_State state);

mDNSlocal void uDNS_HandleLLQState(mDNS *const NONNULL m, DNSQuestion *const NONNULL q)
{
    const LLQ_State prevState = q->state;
    mDNSBool fallBackToLLQPoll = mDNSfalse;

#if !MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
    (void)m;  // Only used for LLQ
#endif

    switch (prevState)
    {
        case LLQ_Init:
            // If DNS Push isn't supported, LLQ_Init falls through to LLQ_InitialRequest.
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
            // First attempt to use DNS Push.
            DiscoverDNSPushServer(m, q);
            break;
        case LLQ_DNSPush_ServerDiscovery:
            // If mDNResponder is still looking for the available DNS push server, the question should not have a DNS
            // push server assigned.
            if (q->dnsPushServer != mDNSNULL)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[Q%u->PushS%u] Already have a DNS push server while DNS push server discovery is in progress - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ", server state: " PUB_S ".", mDNSVal16(q->TargetQID),
                    q->dnsPushServer->serial, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
                    DNSPushServerConnectStateToString(q->dnsPushServer->connectState));
                // This is an invalid case. It means the DNS push server assigned to this question is not valid.
                // Therefore, the question should undo all the operation related to this DNS push server, and fall back
                // to LLQ poll.
                UnsubscribeQuestionFromDNSPushServer(m, q, mDNSfalse);
                fallBackToLLQPoll = mDNStrue;
            }
            break;
        case LLQ_DNSPush_Connecting:
            // If mDNSResponder is in the middle of connecting to the DNS push server, then it should already have
            // a DNS push server assigned.
            if (q->dnsPushServer == mDNSNULL)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[Q%u] Have no DNS push server assigned while the connection to the DNS push server is in progress - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ".", mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype));
                // This is an invalid case. It means the question is in a bad state where it has no DNS push server
                // assigned but it thought it has. Therefore, the question should fall back to LLQ poll.
                if (q->dnsPushZone != mDNSNULL)
                {
                    DNS_PUSH_RELEASE(q->dnsPushZone, DNSPushZoneFinalize);
                    q->dnsPushZone = mDNSNULL;
                }
                fallBackToLLQPoll = mDNStrue;
            }
            else if (q->dnsPushServer->connectState != DNSPushServerConnectionInProgress &&
                     q->dnsPushServer->connectState != DNSPushServerConnected &&
                     q->dnsPushServer->connectState != DNSPushServerSessionEstablished)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[Q%u->PushS%u] Question state is LLQ_DNSPush_Connecting but the corresponding DNS push server is not in the right state - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ", server state: " PUB_S ".", mDNSVal16(q->TargetQID),
                    q->dnsPushServer->serial, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
                    DNSPushServerConnectStateToString(q->dnsPushServer->connectState));
                // This is an invalid case. It means the question's state and the DNS push server's state do not match.
                // In which case, the question should fall back to LLQ poll.
                UnsubscribeQuestionFromDNSPushServer(m, q, mDNSfalse);
                fallBackToLLQPoll = mDNStrue;
            }
            break;
        case LLQ_DNSPush_Established:
            // If the question state indicates that the session has been established, then the question must have
            // a DNS push server assigned.
            if (q->dnsPushServer != mDNSNULL)
            {
                if (q->dnsPushServer->connectState != DNSPushServerSessionEstablished)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                        "[Q%u->PushS%u] server state does not match question state - "
                        ", qname: " PRI_DM_NAME ", question state: " PUB_S ", server state: " PUB_S ".",
                        mDNSVal16(q->TargetQID), q->dnsPushServer->serial, DM_NAME_PARAM(&q->qname),
                        LLQStateToString(q->state), DNSPushServerConnectStateToString(q->dnsPushServer->connectState));
                    // This is an invalid case. It means the question's state and the DNS push server's state do not match.
                    // In which case, the question should fall back to LLQ poll.
                    UnsubscribeQuestionFromDNSPushServer(m, q, mDNSfalse);
                    fallBackToLLQPoll = mDNStrue;
                }
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[Q%u] DNS push session is established but the question does not have DNS push server assigned - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ".", mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype));
                // This is an invalid case. It means that the question is in a bad state. Therefore the question should
                // fall back to LLQ poll.
                if (q->dnsPushZone != mDNSNULL)
                {
                    DNS_PUSH_RELEASE(q->dnsPushZone, DNSPushZoneFinalize);
                    q->dnsPushZone = mDNSNULL;
                }
                fallBackToLLQPoll = mDNStrue;
            }
            break;
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
        case LLQ_InitialRequest:   startLLQHandshake(m, q); break;
        case LLQ_SecondaryRequest: sendChallengeResponse(m, q, mDNSNULL); break;
        case LLQ_Established:      sendLLQRefresh(m, q); break;
        case LLQ_Poll:             break;       // Do nothing (handled below)
        case LLQ_Invalid:          break;
#else
        case LLQ_InitialRequest:   // Fall through to poll
        case LLQ_SecondaryRequest: // Fall through to poll
        case LLQ_Established:      // Fall through to poll
        case LLQ_Poll:
            fallBackToLLQPoll = mDNStrue;
            break;
        case LLQ_Invalid:          break;
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_LLQ)
#if !MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
        // These are never reached without DNS Push support.
        case LLQ_DNSPush_ServerDiscovery:
        case LLQ_DNSPush_Connecting:
        case LLQ_DNSPush_Established:
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "[Q%u] Question is in DNS push state but DNS push is not supported - "
                "qname: " PRI_DM_NAME ", qtype: " PUB_S ".", mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname),
                DNSTypeName(q->qtype));
            break;
#endif // !MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    }

    if (fallBackToLLQPoll)
    {
        StartLLQPolling(m, q);
    }

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u->PushS%u] LLQ_State changes - "
        "from: " PUB_S ", to: " PUB_S ", qname: " PRI_DM_NAME ", qtype: " PUB_S ".", q->request_id,
        mDNSVal16(q->TargetQID), q->dnsPushServer != mDNSNULL ? q->dnsPushServer->serial : DNS_PUSH_SERVER_INVALID_SERIAL,
        LLQStateToString(prevState), LLQStateToString(q->state), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
#else
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u] LLQ_State changes - "
        "from: " PUB_S ", to: " PUB_S ", qname: " PRI_DM_NAME ", qtype: " PUB_S ".", q->request_id,
        mDNSVal16(q->TargetQID), LLQStateToString(prevState), LLQStateToString(q->state), DM_NAME_PARAM(&q->qname),
        DNSTypeName(q->qtype));
#endif
}
#endif // !MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

// The question to be checked is not passed in as an explicit parameter;
// instead it is implicit that the question to be checked is m->CurrentQuestion.
mDNSlocal void uDNS_CheckCurrentQuestion(mDNS *const m)
{
    DNSQuestion *q = m->CurrentQuestion;
    if (m->timenow - NextQSendTime(q) < 0) return;

#if !MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
    if (q->LongLived)
    {
        uDNS_HandleLLQState(m,q);
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
        // If the question is doing DNS push, then we do not give it to the querier to send the regular unicast query,
        // until the DNS push fails.
        if (DNS_PUSH_IN_PROGRESS(q->state))
        {
            if (!q->LongLived)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[Q%u] DNS Push is active for this question, but the question is not long-lived - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ".", mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype));
            }
            q->LastQTime = m->timenow;
            return;
        }
#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    }
#endif // !MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    Querier_HandleUnicastQuestion(q);
#else
    // We repeat the check above (rather than just making this the "else" case) because startLLQHandshake can change q->state to LLQ_Poll
    if (!(q->LongLived && q->state != LLQ_Poll))
    {
        if (q->unansweredQueries >= MAX_UCAST_UNANSWERED_QUERIES)
        {
            DNSServer *orig = q->qDNSServer;
            if (orig)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u->Q%u] uDNS_CheckCurrentQuestion: Sent %d unanswered queries for " PRI_DM_NAME " (" PUB_S ") to " PRI_IP_ADDR ":%d (" PRI_DM_NAME ")",
                          q->request_id, mDNSVal16(q->TargetQID), q->unansweredQueries, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), &orig->addr, mDNSVal16(orig->port), DM_NAME_PARAM(&orig->domain));
            }

#if MDNSRESPONDER_SUPPORTS(APPLE, SYMPTOMS)
            SymptomReporterDNSServerUnreachable(orig);
#endif
            PenalizeDNSServer(m, q, zeroID);
            q->noServerResponse = 1;
        }
        // There are two cases here.
        //
        // 1. We have only one DNS server for this question. It is not responding even after we sent MAX_UCAST_UNANSWERED_QUERIES.
        //    In that case, we need to keep retrying till we get a response. But we need to backoff as we retry. We set
        //    noServerResponse in the block above and below we do not touch the question interval. When we come here, we
        //    already waited for the response. We need to send another query right at this moment. We do that below by
        //    reinitializing dns servers and reissuing the query.
        //
        // 2. We have more than one DNS server. If at least one server did not respond, we would have set noServerResponse
        //    either now (the last server in the list) or before (non-last server in the list). In either case, if we have
        //    reached the end of DNS server list, we need to try again from the beginning. Ideally we should try just the
        //    servers that did not respond, but for simplicity we try all the servers. Once we reached the end of list, we
        //    set triedAllServersOnce so that we don't try all the servers aggressively. See PenalizeDNSServer.
        if (!q->qDNSServer && q->noServerResponse)
        {
            DNSServer *new;
            DNSQuestion *qptr;
            q->triedAllServersOnce = mDNStrue;
            // Re-initialize all DNS servers for this question. If we have a DNSServer, DNSServerChangeForQuestion will
            // handle all the work including setting the new DNS server.
            SetValidDNSServers(m, q);
            new = GetServerForQuestion(m, q);
            if (new)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u->Q%u] uDNS_checkCurrentQuestion: Retrying question %p " PRI_DM_NAME " (" PUB_S ") DNS Server " PRI_IP_ADDR ":%d ThisQInterval %d",
                          q->request_id, mDNSVal16(q->TargetQID), q, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), new ? &new->addr : mDNSNULL, mDNSVal16(new ? new->port : zeroIPPort), q->ThisQInterval);
                DNSServerChangeForQuestion(m, q, new);
            }
            for (qptr = q->next ; qptr; qptr = qptr->next)
                if (qptr->DuplicateOf == q) { qptr->validDNSServers = q->validDNSServers; qptr->qDNSServer = q->qDNSServer; }
        }
        if (q->qDNSServer)
        {
            mDNSu8 *end;
            mStatus err = mStatus_NoError;
            mDNSOpaque16 HeaderFlags = uQueryFlags;

            InitializeDNSMessage(&m->omsg.h, q->TargetQID, HeaderFlags);
            end = putQuestion(&m->omsg, m->omsg.data, m->omsg.data + AbsoluteMaxDNSMessageData, &q->qname, q->qtype, q->qclass);

            if (end > m->omsg.data)
            {
                debugf("uDNS_CheckCurrentQuestion sending %p %##s (%s) %#a:%d UnansweredQueries %d",
                       q, q->qname.c, DNSTypeName(q->qtype),
                       q->qDNSServer ? &q->qDNSServer->addr : mDNSNULL, mDNSVal16(q->qDNSServer ? q->qDNSServer->port : zeroIPPort), q->unansweredQueries);
                if (!q->LocalSocket)
                {
                    q->LocalSocket = mDNSPlatformUDPSocket(zeroIPPort);
                    if (q->LocalSocket)
                    {
                        mDNSPlatformSetSocktOpt(q->LocalSocket, mDNSTransport_UDP, mDNSAddrType_IPv4, q);
                        mDNSPlatformSetSocktOpt(q->LocalSocket, mDNSTransport_UDP, mDNSAddrType_IPv6, q);
                    }
                }
                if (!q->LocalSocket) err = mStatus_NoMemoryErr; // If failed to make socket (should be very rare), we'll try again next time
                else
                {
                    err = mDNSSendDNSMessage(m, &m->omsg, end, q->qDNSServer->interface, mDNSNULL, q->LocalSocket, &q->qDNSServer->addr, q->qDNSServer->port, mDNSNULL, q->UseBackgroundTraffic);

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
                    if (!err)
                    {
                        bool isForCell  = q->qDNSServer->isCell;
                        dnssd_analytics_update_dns_query_size(isForCell, dns_transport_Do53, (uint32_t)(end - (mDNSu8 *)&m->omsg));
                        if (q->metrics.answered)
                        {
                            q->metrics.querySendCount = 0;
                            q->metrics.answered       = mDNSfalse;
                        }
                        if (q->metrics.querySendCount++ == 0)
                        {
                            q->metrics.firstQueryTime = NonZeroTime(m->timenow);
                        }
                    }
#endif
				}
            }

            if (err == mStatus_HostUnreachErr)
            {
                DNSServer *newServer;

                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u->Q%u] uDNS_CheckCurrentQuestion: host unreachable error for DNS server " PRI_IP_ADDR " for question [%p] " PRI_DM_NAME " (" PUB_S ")",
                          q->request_id, mDNSVal16(q->TargetQID), &q->qDNSServer->addr, q, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));

                if (!StrictUnicastOrdering)
                {
                    q->qDNSServer->penaltyTime = NonZeroTime(m->timenow + DNSSERVER_PENALTY_TIME);
                }

                newServer = GetServerForQuestion(m, q);
                if (!newServer)
                {
                    q->triedAllServersOnce = mDNStrue;
                    SetValidDNSServers(m, q);
                    newServer = GetServerForQuestion(m, q);
                }
                if (newServer)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                              "[R%u->Q%u] uDNS_checkCurrentQuestion: Retrying question %p " PRI_DM_NAME " (" PUB_S ") DNS Server " PRI_IP_ADDR ":%u ThisQInterval %d",
                              q->request_id, mDNSVal16(q->TargetQID), q, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
                              newServer ? &newServer->addr : mDNSNULL, mDNSVal16(newServer ? newServer->port : zeroIPPort), q->ThisQInterval);
                    DNSServerChangeForQuestion(m, q, newServer);
                }
                if (q->triedAllServersOnce)
                {
                    q->LastQTime = m->timenow;
                }
                else
                {
                    q->ThisQInterval = InitialQuestionInterval;
                    q->LastQTime     = m->timenow - q->ThisQInterval;
                }
                q->unansweredQueries = 0;
            }
            else
            {
                if (err != mStatus_TransientErr)   // if it is not a transient error backoff and DO NOT flood queries unnecessarily
                {
                    // If all DNS Servers are not responding, then we back-off using the multiplier UDNSBackOffMultiplier(*2).
                    // Only increase interval if send succeeded

                    q->ThisQInterval = q->ThisQInterval * UDNSBackOffMultiplier;
                    if ((q->ThisQInterval > 0) && (q->ThisQInterval < MinQuestionInterval))  // We do not want to retx within 1 sec
                        q->ThisQInterval = MinQuestionInterval;

                    q->unansweredQueries++;
                    if (q->ThisQInterval > MAX_UCAST_POLL_INTERVAL)
                        q->ThisQInterval = MAX_UCAST_POLL_INTERVAL;
                    if (q->qDNSServer->isCell)
                    {
                        // We don't want to retransmit too soon. Schedule our first retransmisson at
                        // MIN_UCAST_RETRANS_TIMEOUT seconds.
                        if (q->ThisQInterval < MIN_UCAST_RETRANS_TIMEOUT)
                            q->ThisQInterval = MIN_UCAST_RETRANS_TIMEOUT;
                    }
                    debugf("uDNS_CheckCurrentQuestion: Increased ThisQInterval to %d for %##s (%s), cell %d", q->ThisQInterval, q->qname.c, DNSTypeName(q->qtype), q->qDNSServer->isCell);
                }
                q->LastQTime = m->timenow;
            }
            SetNextQueryTime(m, q);
        }
        else
        {
            // If we have no server for this query, or the only server is a disabled one, then we deliver
            // a transient failure indication to the client. This is important for things like iPhone
            // where we want to return timely feedback to the user when no network is available.
            // After calling MakeNegativeCacheRecord() we store the resulting record in the
            // cache so that it will be visible to other clients asking the same question.
            // (When we have a group of identical questions, only the active representative of the group gets
            // passed to uDNS_CheckCurrentQuestion -- we only want one set of query packets hitting the wire --
            // but we want *all* of the questions to get answer callbacks.)
            CacheRecord *cr;
            const mDNSu32 slot = HashSlotFromNameHash(q->qnamehash);
            CacheGroup *const cg = CacheGroupForName(m, q->qnamehash, &q->qname);

            if (!q->qDNSServer)
            {
                if (!mDNSOpaque128IsZero(&q->validDNSServers))
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                              "[R%u->Q%u] uDNS_CheckCurrentQuestion: ERROR!!: valid DNSServer bits not zero 0x%x, 0x%x 0x%x 0x%x for question " PRI_DM_NAME " (" PUB_S ")",
                              q->request_id, mDNSVal16(q->TargetQID), q->validDNSServers.l[3], q->validDNSServers.l[2], q->validDNSServers.l[1], q->validDNSServers.l[0], DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
                // If we reached the end of list while picking DNS servers, then we don't want to deactivate the
                // question. Try after 60 seconds. We find this by looking for valid DNSServers for this question,
                // if we find any, then we must have tried them before we came here. This avoids maintaining
                // another state variable to see if we had valid DNS servers for this question.
                SetValidDNSServers(m, q);
                if (mDNSOpaque128IsZero(&q->validDNSServers))
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                              "[R%u->Q%u] uDNS_CheckCurrentQuestion: no DNS server for " PRI_DM_NAME " (" PUB_S ")",
                              q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
                    q->ThisQInterval = 0;
                }
                else
                {
                    DNSQuestion *qptr;
                    // Pretend that we sent this question. As this is an ActiveQuestion, the NextScheduledQuery should
                    // be set properly. Also, we need to properly backoff in cases where we don't set the question to
                    // MaxQuestionInterval when we answer the question e.g., LongLived, we need to keep backing off
                    q->ThisQInterval = q->ThisQInterval * QuestionIntervalStep;
                    q->LastQTime = m->timenow;
                    SetNextQueryTime(m, q);
                    // Pick a new DNS server now. Otherwise, when the cache is 80% of its expiry, we will try
                    // to send a query and come back to the same place here and log the above message.
                    q->qDNSServer = GetServerForQuestion(m, q);
                    for (qptr = q->next ; qptr; qptr = qptr->next)
                        if (qptr->DuplicateOf == q) { qptr->validDNSServers = q->validDNSServers; qptr->qDNSServer = q->qDNSServer; }
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                              "[R%u->Q%u] uDNS_checkCurrentQuestion: Tried all DNS servers, retry question %p SuppressUnusable %d " PRI_DM_NAME " (" PUB_S ") with DNS Server " PRI_IP_ADDR ":%d after 60 seconds, ThisQInterval %d",
                              q->request_id, mDNSVal16(q->TargetQID), q, q->SuppressUnusable, DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
                              q->qDNSServer ? &q->qDNSServer->addr : mDNSNULL, mDNSVal16(q->qDNSServer ? q->qDNSServer->port : zeroIPPort), q->ThisQInterval);
                }
            }
            else
            {
                q->ThisQInterval = 0;
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u->Q%u] uDNS_CheckCurrentQuestion DNS server " PRI_IP_ADDR ":%d for " PRI_DM_NAME " is disabled",
                          q->request_id, mDNSVal16(q->TargetQID), &q->qDNSServer->addr, mDNSVal16(q->qDNSServer->port), DM_NAME_PARAM(&q->qname));
            }

            if (cg)
            {
                for (cr = cg->members; cr; cr=cr->next)
                {
                    if (SameNameCacheRecordAnswersQuestion(cr, q))
                    {
                        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                                  "[R%u->Q%u] uDNS_CheckCurrentQuestion: Purged resourcerecord " PRI_S,
                                  q->request_id, mDNSVal16(q->TargetQID), CRDisplayString(m, cr));
                        mDNS_PurgeCacheResourceRecord(m, cr);
                    }
                }
            }
            // For some of the WAB queries that we generate form within the mDNSResponder, most of the home routers
            // don't understand and return ServFail/NXDomain. In those cases, we don't want to try too often. We try
            // every fifteen minutes in that case
            q->unansweredQueries = 0;
            const mDNSOpaque16 responseFlags = !mDNSOpaque16IsZero(q->responseFlags) ? q->responseFlags : ResponseFlags;
            MakeNegativeCacheRecordForQuestion(m, &m->rec.r, q, (DomainEnumQuery(&q->qname) ? 60 * 15 : 60),
                mDNSInterface_Any, responseFlags);
            // We're already using the m->CurrentQuestion pointer, so CacheRecordAdd can't use it to walk the question list.
            // To solve this problem we set cr->DelayDelivery to a nonzero value (which happens to be 'now') so that we
            // momentarily defer generating answer callbacks until mDNS_Execute time.
            CreateNewCacheEntry(m, slot, cg, NonZeroTime(m->timenow), mDNStrue, mDNSNULL);
            ScheduleNextCacheCheckTime(m, slot, NonZeroTime(m->timenow));
            m->rec.r.responseFlags = zeroID;
            mDNSCoreResetRecord(m);
            // MUST NOT touch m->CurrentQuestion (or q) after this -- client callback could have deleted it
        }
    }
#endif // MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
}

mDNSexport void CheckNATMappings(mDNS *m)
{
    mDNSBool rfc1918 = mDNSv4AddrIsRFC1918(&m->AdvertisedV4.ip.v4);
    mDNSBool HaveRoutable = !rfc1918 && !mDNSIPv4AddressIsZero(m->AdvertisedV4.ip.v4);
    m->NextScheduledNATOp = m->timenow + FutureTime;

    if (HaveRoutable) m->ExtAddress = m->AdvertisedV4.ip.v4;

    if (m->NATTraversals && rfc1918)            // Do we need to open a socket to receive multicast announcements from router?
    {
        if (m->NATMcastRecvskt == mDNSNULL)     // If we are behind a NAT and the socket hasn't been opened yet, open it
        {
            // we need to log a message if we can't get our socket, but only the first time (after success)
            static mDNSBool needLog = mDNStrue;
            m->NATMcastRecvskt = mDNSPlatformUDPSocket(NATPMPAnnouncementPort);
            if (!m->NATMcastRecvskt)
            {
                if (needLog)
                {
                    LogMsg("CheckNATMappings: Failed to allocate port 5350 UDP multicast socket for PCP & NAT-PMP announcements");
                    needLog = mDNSfalse;
                }
            }
            else
                needLog = mDNStrue;
        }
    }
    else                                        // else, we don't want to listen for announcements, so close them if they're open
    {
        if (m->NATMcastRecvskt) { mDNSPlatformUDPClose(m->NATMcastRecvskt); m->NATMcastRecvskt = mDNSNULL; }
        if (m->SSDPSocket)      { debugf("CheckNATMappings destroying SSDPSocket %p", &m->SSDPSocket); mDNSPlatformUDPClose(m->SSDPSocket); m->SSDPSocket = mDNSNULL; }
    }

    uDNS_RequestAddress(m);

    if (m->CurrentNATTraversal) LogMsg("WARNING m->CurrentNATTraversal already in use");
    m->CurrentNATTraversal = m->NATTraversals;

    while (m->CurrentNATTraversal)
    {
        NATTraversalInfo *cur = m->CurrentNATTraversal;
        mDNSv4Addr EffectiveAddress = HaveRoutable ? m->AdvertisedV4.ip.v4 : cur->NewAddress;
        m->CurrentNATTraversal = m->CurrentNATTraversal->next;

        if (HaveRoutable)       // If not RFC 1918 address, our own address and port are effectively our external address and port
        {
            cur->ExpiryTime = 0;
            cur->NewResult  = mStatus_NoError;
        }
        else // Check if it's time to send port mapping packet(s)
        {
            if (m->timenow - cur->retryPortMap >= 0) // Time to send a mapping request for this packet
            {
                if (cur->ExpiryTime && cur->ExpiryTime - m->timenow < 0)    // Mapping has expired
                {
                    cur->ExpiryTime    = 0;
                    cur->retryInterval = NATMAP_INIT_RETRY;
                }

                uDNS_SendNATMsg(m, cur, mDNStrue, mDNSfalse); // Will also do UPnP discovery for us, if necessary

                if (cur->ExpiryTime)                        // If have active mapping then set next renewal time halfway to expiry
                    NATSetNextRenewalTime(m, cur);
                else                                        // else no mapping; use exponential backoff sequence
                {
                    if      (cur->retryInterval < NATMAP_INIT_RETRY            ) cur->retryInterval = NATMAP_INIT_RETRY;
                    else if (cur->retryInterval < NATMAP_MAX_RETRY_INTERVAL / 2) cur->retryInterval *= 2;
                    else cur->retryInterval = NATMAP_MAX_RETRY_INTERVAL;
                    cur->retryPortMap = m->timenow + cur->retryInterval;
                }
            }

            if (m->NextScheduledNATOp - cur->retryPortMap > 0)
            {
                m->NextScheduledNATOp = cur->retryPortMap;
            }
        }

        // Notify the client if necessary. We invoke the callback if:
        // (1) We have an effective address,
        //     or we've tried and failed a couple of times to discover it
        // AND
        // (2) the client requested the address only,
        //     or the client won't need a mapping because we have a routable address,
        //     or the client has an expiry time and therefore a successful mapping,
        //     or we've tried and failed a couple of times (see "Time line" below)
        // AND
        // (3) we have new data to give the client that's changed since the last callback
        //
        // Time line is: Send, Wait 500ms, Send, Wait 1sec, Send, Wait 2sec, Send
        // At this point we've sent three requests without an answer, we've just sent our fourth request,
        // retryInterval is now 4 seconds, which is greater than NATMAP_INIT_RETRY * 8 (2 seconds),
        // so we return an error result to the caller.
        if (!mDNSIPv4AddressIsZero(EffectiveAddress) || cur->retryInterval > NATMAP_INIT_RETRY * 8)
        {
            const mStatus EffectiveResult = cur->NewResult ? cur->NewResult : mDNSv4AddrIsRFC1918(&EffectiveAddress) ? mStatus_DoubleNAT : mStatus_NoError;
            const mDNSIPPort ExternalPort = HaveRoutable ? cur->IntPort :
                                            !mDNSIPv4AddressIsZero(EffectiveAddress) && cur->ExpiryTime ? cur->RequestedPort : zeroIPPort;

            if (!cur->Protocol || HaveRoutable || cur->ExpiryTime || cur->retryInterval > NATMAP_INIT_RETRY * 8)
            {
                if (!mDNSSameIPv4Address(cur->ExternalAddress, EffectiveAddress) ||
                    !mDNSSameIPPort     (cur->ExternalPort,       ExternalPort)    ||
                    cur->Result != EffectiveResult)
                {
                    //LogMsg("NAT callback %d %d %d", cur->Protocol, cur->ExpiryTime, cur->retryInterval);
                    if (cur->Protocol && mDNSIPPortIsZero(ExternalPort) && !mDNSIPv4AddressIsZero(m->Router.ip.v4))
                    {
                        if (!EffectiveResult)
                            LogInfo("CheckNATMapping: Failed to obtain NAT port mapping %p from router %#a external address %.4a internal port %5d interval %d error %d",
                                    cur, &m->Router, &EffectiveAddress, mDNSVal16(cur->IntPort), cur->retryInterval, EffectiveResult);
                        else
                            LogMsg("CheckNATMapping: Failed to obtain NAT port mapping %p from router %#a external address %.4a internal port %5d interval %d error %d",
                                   cur, &m->Router, &EffectiveAddress, mDNSVal16(cur->IntPort), cur->retryInterval, EffectiveResult);
                    }

                    cur->ExternalAddress = EffectiveAddress;
                    cur->ExternalPort    = ExternalPort;
                    cur->Lifetime        = cur->ExpiryTime && !mDNSIPPortIsZero(ExternalPort) ?
                                           (cur->ExpiryTime - m->timenow + mDNSPlatformOneSecond/2) / mDNSPlatformOneSecond : 0;
                    cur->Result          = EffectiveResult;
                    mDNS_DropLockBeforeCallback();      // Allow client to legally make mDNS API calls from the callback
                    if (cur->clientCallback)
                        cur->clientCallback(m, cur);
                    mDNS_ReclaimLockAfterCallback();    // Decrement mDNS_reentrancy to block mDNS API calls again
                    // MUST NOT touch cur after invoking the callback
                }
            }
        }
    }
}

mDNSlocal mDNSs32 CheckRecordUpdates(mDNS *m)
{
    AuthRecord *rr;
    mDNSs32 nextevent = m->timenow + FutureTime;

    CheckGroupRecordUpdates(m);

    for (rr = m->ResourceRecords; rr; rr = rr->next)
    {
        if (!AuthRecord_uDNS(rr)) continue;
        if (rr->state == regState_NoTarget) {debugf("CheckRecordUpdates: Record %##s in NoTarget", rr->resrec.name->c); continue;}
        // While we are waiting for the port mapping, we have nothing to do. The port mapping callback
        // will take care of this
        if (rr->state == regState_NATMap) {debugf("CheckRecordUpdates: Record %##s in NATMap", rr->resrec.name->c); continue;}
        if (rr->state == regState_Pending || rr->state == regState_DeregPending || rr->state == regState_UpdatePending ||
            rr->state == regState_Refresh || rr->state == regState_Registered)
        {
            if (rr->LastAPTime + rr->ThisAPInterval - m->timenow <= 0)
            {
                if (rr->tcp) { DisposeTCPConn(rr->tcp); rr->tcp = mDNSNULL; }
                if (!rr->nta || mDNSIPv4AddressIsZero(rr->nta->Addr.ip.v4))
                {
                    // Zero out the updateid so that if we have a pending response from the server, it won't
                    // be accepted as a valid response. If we accept the response, we might free the new "nta"
                    if (rr->nta) { rr->updateid = zeroID; CancelGetZoneData(m, rr->nta); }
                    rr->nta = StartGetZoneData(m, rr->resrec.name, ZoneServiceUpdate, RecordRegistrationGotZoneData, rr);

                    // We have just started the GetZoneData. We need to wait for it to finish. SetRecordRetry here
                    // schedules the update timer to fire in the future.
                    //
                    // There are three cases.
                    //
                    // 1) When the updates are sent the first time, the first retry is intended to be at three seconds
                    //    in the future. But by calling SetRecordRetry here we set it to nine seconds. But it does not
                    //    matter because when the answer comes back, RecordRegistrationGotZoneData resets the interval
                    //    back to INIT_RECORD_REG_INTERVAL. This also gives enough time for the query.
                    //
                    // 2) In the case of update errors (updateError), this causes further backoff as
                    //    RecordRegistrationGotZoneData does not reset the timer. This is intentional as in the case of
                    //    errors, we don't want to update aggressively.
                    //
                    // 3) We might be refreshing the update. This is very similar to case (1). RecordRegistrationGotZoneData
                    //    resets it back to INIT_RECORD_REG_INTERVAL.
                    //
                    SetRecordRetry(m, rr, 0);
                }
                else if (rr->state == regState_DeregPending) SendRecordDeregistration(m, rr);
                else SendRecordRegistration(m, rr);
            }
        }
        if (nextevent - (rr->LastAPTime + rr->ThisAPInterval) > 0)
            nextevent = (rr->LastAPTime + rr->ThisAPInterval);
    }
    return nextevent;
}

mDNSexport void uDNS_Tasks(mDNS *const m)
{
    mDNSs32 nexte;
#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    DNSServer *d;
#endif

    m->NextuDNSEvent = m->timenow + FutureTime;

    nexte = CheckRecordUpdates(m);
    if (m->NextuDNSEvent - nexte > 0)
        m->NextuDNSEvent = nexte;

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    for (d = m->DNSServers; d; d=d->next)
        if (d->penaltyTime)
        {
            if (m->timenow - d->penaltyTime >= 0)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "DNS server " PRI_IP_ADDR ":%d out of penalty box", &d->addr, mDNSVal16(d->port));
                d->penaltyTime = 0;
            }
            else
            if (m->NextuDNSEvent - d->penaltyTime > 0)
                m->NextuDNSEvent = d->penaltyTime;
        }
#endif

    if (m->CurrentQuestion)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "uDNS_Tasks ERROR m->CurrentQuestion already set: " PRI_DM_NAME " (" PRI_S ")",
                  DM_NAME_PARAM(&m->CurrentQuestion->qname), DNSTypeName(m->CurrentQuestion->qtype));
    }
    m->CurrentQuestion = m->Questions;
    while (m->CurrentQuestion && m->CurrentQuestion != m->NewQuestions)
    {
        DNSQuestion *const q = m->CurrentQuestion;
        if (ActiveQuestion(q) && !mDNSOpaque16IsZero(q->TargetQID))
        {
            uDNS_CheckCurrentQuestion(m);
            if (q == m->CurrentQuestion)
                if (m->NextuDNSEvent - NextQSendTime(q) > 0)
                    m->NextuDNSEvent = NextQSendTime(q);
        }
        // If m->CurrentQuestion wasn't modified out from under us, advance it now
        // We can't do this at the start of the loop because uDNS_CheckCurrentQuestion()
        // depends on having m->CurrentQuestion point to the right question
        if (m->CurrentQuestion == q)
            m->CurrentQuestion = q->next;
    }
    m->CurrentQuestion = mDNSNULL;
}

// ***************************************************************************
// MARK: - Startup, Shutdown, and Sleep

mDNSexport void SleepRecordRegistrations(mDNS *m)
{
    AuthRecord *rr;
    for (rr = m->ResourceRecords; rr; rr=rr->next)
    {
        if (AuthRecord_uDNS(rr))
        {
            // Zero out the updateid so that if we have a pending response from the server, it won't
            // be accepted as a valid response.
            if (rr->nta) { rr->updateid = zeroID; CancelGetZoneData(m, rr->nta); rr->nta = mDNSNULL; }

            if (rr->NATinfo.clientContext)
            {
                mDNS_StopNATOperation_internal(m, &rr->NATinfo);
                rr->NATinfo.clientContext = mDNSNULL;
            }
            // We are waiting to update the resource record. The original data of the record is
            // in OrigRData and the updated value is in InFlightRData. Free the old and the new
            // one will be registered when we come back.
            if (rr->state == regState_UpdatePending)
            {
                // act as if the update succeeded, since we're about to delete the name anyway
                rr->state = regState_Registered;
                // deallocate old RData
                if (rr->UpdateCallback) rr->UpdateCallback(m, rr, rr->OrigRData, rr->OrigRDLen);
                SetNewRData(&rr->resrec, rr->InFlightRData, rr->InFlightRDLen);
                rr->OrigRData = mDNSNULL;
                rr->InFlightRData = mDNSNULL;
            }

            // If we have not begun the registration process i.e., never sent a registration packet,
            // then uDNS_DeregisterRecord will not send a deregistration
            uDNS_DeregisterRecord(m, rr);

            // When we wake, we call ActivateUnicastRegistration which starts at StartGetZoneData
        }
    }
}

mDNSexport void mDNS_AddSearchDomain(const domainname *const domain, mDNSInterfaceID InterfaceID)
{
    SearchListElem **p;
    SearchListElem *tmp = mDNSNULL;

    // Check to see if we already have this domain in our list
    for (p = &SearchList; *p; p = &(*p)->next)
        if (((*p)->InterfaceID == InterfaceID) && SameDomainName(&(*p)->domain, domain))
        {
            // If domain is already in list, and marked for deletion, unmark the delete
            // Be careful not to touch the other flags that may be present
            LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                "mDNS_AddSearchDomain: domain already in list -- search domain: " PRI_DM_NAME,
                DM_NAME_PARAM_NONNULL(domain));
            if ((*p)->flag & SLE_DELETE) (*p)->flag &= ~SLE_DELETE;
            tmp = *p;
            *p = tmp->next;
            tmp->next = mDNSNULL;
            break;
        }


    // move to end of list so that we maintain the same order
    while (*p) p = &(*p)->next;

    if (tmp) *p = tmp;
    else
    {
        // if domain not in list, add to list, mark as add (1)
        *p = (SearchListElem *) mDNSPlatformMemAllocateClear(sizeof(**p));
        if (!*p)
        {
            LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR, "ERROR: mDNS_AddSearchDomain - malloc");
            return;
        }
        AssignDomainName(&(*p)->domain, domain);
        (*p)->next = mDNSNULL;
        (*p)->InterfaceID = InterfaceID;
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "mDNS_AddSearchDomain: new search domain added -- search domain: " PRI_DM_NAME ", InterfaceID %p",
            DM_NAME_PARAM_NONNULL(domain), InterfaceID);
    }
}

mDNSlocal void FreeARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
{
    (void)m;    // unused
    if (result == mStatus_MemFree) mDNSPlatformMemFree(rr->RecordContext);
}

mDNSlocal void FoundDomain(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    SearchListElem *slElem = question->QuestionContext;
    mStatus err;
    const char *name;

    if (answer->rrtype != kDNSType_PTR) return;
    if (answer->RecordType == kDNSRecordTypePacketNegative) return;
    if (answer->InterfaceID == mDNSInterface_LocalOnly) return;

    if      (question == &slElem->BrowseQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowse];
    else if (question == &slElem->DefBrowseQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseDefault];
    else if (question == &slElem->AutomaticBrowseQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseAutomatic];
    else if (question == &slElem->RegisterQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeRegistration];
    else if (question == &slElem->DefRegisterQ) name = mDNS_DomainTypeNames[mDNS_DomainTypeRegistrationDefault];
    else { LogMsg("FoundDomain - unknown question"); return; }

    LogInfo("FoundDomain: %p %s %s Q %##s A %s", answer->InterfaceID, AddRecord ? "Add" : "Rmv", name, question->qname.c, RRDisplayString(m, answer));

    if (AddRecord)
    {
        ARListElem *arElem = (ARListElem *) mDNSPlatformMemAllocateClear(sizeof(*arElem));
        if (!arElem) { LogMsg("ERROR: FoundDomain out of memory"); return; }
        mDNS_SetupResourceRecord(&arElem->ar, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200, kDNSRecordTypeShared, AuthRecordLocalOnly, FreeARElemCallback, arElem);
        MakeDomainNameFromDNSNameString(&arElem->ar.namestorage, name);
        AppendDNSNameString            (&arElem->ar.namestorage, "local");
        AssignDomainName(&arElem->ar.resrec.rdata->u.name, &answer->rdata->u.name);
        LogInfo("FoundDomain: Registering %s", ARDisplayString(m, &arElem->ar));
        err = mDNS_Register(m, &arElem->ar);
        if (err) { LogMsg("ERROR: FoundDomain - mDNS_Register returned %d", err); mDNSPlatformMemFree(arElem); return; }
        arElem->next = slElem->AuthRecs;
        slElem->AuthRecs = arElem;
    }
    else
    {
        ARListElem **ptr = &slElem->AuthRecs;
        while (*ptr)
        {
            if (SameDomainName(&(*ptr)->ar.resrec.rdata->u.name, &answer->rdata->u.name))
            {
                ARListElem *dereg = *ptr;
                *ptr = (*ptr)->next;
                LogInfo("FoundDomain: Deregistering %s", ARDisplayString(m, &dereg->ar));
                err = mDNS_Deregister(m, &dereg->ar);
                if (err) LogMsg("ERROR: FoundDomain - mDNS_Deregister returned %d", err);
                // Memory will be freed in the FreeARElemCallback
            }
            else
                ptr = &(*ptr)->next;
        }
    }
}


// This should probably move to the UDS daemon -- the concept of legacy clients and automatic registration / automatic browsing
// is really a UDS API issue, not something intrinsic to uDNS

mDNSlocal void uDNS_DeleteWABQueries(mDNS *const m, SearchListElem *ptr, int delete)
{
    const char *name1 = mDNSNULL;
    const char *name2 = mDNSNULL;
    ARListElem **arList = &ptr->AuthRecs;
    domainname namestorage1, namestorage2;
    mStatus err;

    // "delete" parameter indicates the type of query.
    switch (delete)
    {
    case UDNS_WAB_BROWSE_QUERY:
        mDNS_StopGetDomains(m, &ptr->BrowseQ);
        mDNS_StopGetDomains(m, &ptr->DefBrowseQ);
        name1 = mDNS_DomainTypeNames[mDNS_DomainTypeBrowse];
        name2 = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseDefault];
        break;
    case UDNS_WAB_LBROWSE_QUERY:
        mDNS_StopGetDomains(m, &ptr->AutomaticBrowseQ);
        name1 = mDNS_DomainTypeNames[mDNS_DomainTypeBrowseAutomatic];
        break;
    case UDNS_WAB_REG_QUERY:
        mDNS_StopGetDomains(m, &ptr->RegisterQ);
        mDNS_StopGetDomains(m, &ptr->DefRegisterQ);
        name1 = mDNS_DomainTypeNames[mDNS_DomainTypeRegistration];
        name2 = mDNS_DomainTypeNames[mDNS_DomainTypeRegistrationDefault];
        break;
    default:
        LogMsg("uDNS_DeleteWABQueries: ERROR!! returning from default");
        return;
    }
    // When we get the results to the domain enumeration queries, we add a LocalOnly
    // entry. For example, if we issue a domain enumeration query for b._dns-sd._udp.xxxx.com,
    // and when we get a response, we add a LocalOnly entry b._dns-sd._udp.local whose RDATA
    // points to what we got in the response. Locate the appropriate LocalOnly entries and delete
    // them.
    if (name1)
    {
        MakeDomainNameFromDNSNameString(&namestorage1, name1);
        AppendDNSNameString(&namestorage1, "local");
    }
    if (name2)
    {
        MakeDomainNameFromDNSNameString(&namestorage2, name2);
        AppendDNSNameString(&namestorage2, "local");
    }
    while (*arList)
    {
        ARListElem *dereg = *arList;
        if ((name1 && SameDomainName(&dereg->ar.namestorage, &namestorage1)) ||
            (name2 && SameDomainName(&dereg->ar.namestorage, &namestorage2)))
        {
            LogInfo("uDNS_DeleteWABQueries: Deregistering PTR %##s -> %##s", dereg->ar.resrec.name->c, dereg->ar.resrec.rdata->u.name.c);
            *arList = dereg->next;
            err = mDNS_Deregister(m, &dereg->ar);
            if (err) LogMsg("uDNS_DeleteWABQueries:: ERROR!! mDNS_Deregister returned %d", err);
            // Memory will be freed in the FreeARElemCallback
        }
        else
        {
            LogInfo("uDNS_DeleteWABQueries: Skipping PTR %##s -> %##s", dereg->ar.resrec.name->c, dereg->ar.resrec.rdata->u.name.c);
            arList = &(*arList)->next;
        }
    }
}

mDNSexport void uDNS_SetupWABQueries(mDNS *const m)
{
    SearchListElem **p = &SearchList, *ptr;
    mStatus err;
    int action = 0;

    // step 1: mark each element for removal
    for (ptr = SearchList; ptr; ptr = ptr->next)
        ptr->flag |= SLE_DELETE;

    // Make sure we have the search domains from the platform layer so that if we start the WAB
    // queries below, we have the latest information.
    mDNS_Lock(m);
    if (!mDNSPlatformSetDNSConfig(mDNSfalse, mDNStrue, mDNSNULL, mDNSNULL, mDNSNULL, mDNSfalse))
    {
        // If the configuration did not change, clear the flag so that we don't free the searchlist.
        // We still have to start the domain enumeration queries as we may not have started them
        // before.
        for (ptr = SearchList; ptr; ptr = ptr->next)
            ptr->flag &= ~SLE_DELETE;
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, "uDNS_SetupWABQueries: No config change");
    }
    mDNS_Unlock(m);

    if (m->WABBrowseQueriesCount)
        action |= UDNS_WAB_BROWSE_QUERY;
    if (m->WABLBrowseQueriesCount)
        action |= UDNS_WAB_LBROWSE_QUERY;
    if (m->WABRegQueriesCount)
        action |= UDNS_WAB_REG_QUERY;


    // delete elems marked for removal, do queries for elems marked add
    while (*p)
    {
        ptr = *p;
        const mDNSu32 nameHash = mDNS_DomainNameFNV1aHash(&ptr->domain);
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "uDNS_SetupWABQueries -- action: 0x%x, flags: 0x%x, ifid: %p, domain: " PUB_DM_NAME " (%x)",
            action, ptr->flag, ptr->InterfaceID, DM_NAME_PARAM(&ptr->domain), nameHash);
        // If SLE_DELETE is set, stop all the queries, deregister all the records and free the memory.
        // Otherwise, check to see what the "action" requires. If a particular action bit is not set and
        // we have started the corresponding queries as indicated by the "flags", stop those queries and
        // deregister the records corresponding to them.
        if ((ptr->flag & SLE_DELETE) ||
            (!(action & UDNS_WAB_BROWSE_QUERY) && (ptr->flag & SLE_WAB_BROWSE_QUERY_STARTED)) ||
            (!(action & UDNS_WAB_LBROWSE_QUERY) && (ptr->flag & SLE_WAB_LBROWSE_QUERY_STARTED)) ||
            (!(action & UDNS_WAB_REG_QUERY) && (ptr->flag & SLE_WAB_REG_QUERY_STARTED)))
        {
            if (ptr->flag & SLE_DELETE)
            {
                ARListElem *arList = ptr->AuthRecs;
                ptr->AuthRecs = mDNSNULL;
                *p = ptr->next;

                // If the user has "local" in their DNS searchlist, we ignore that for the purposes of domain enumeration queries
                // We suppressed the domain enumeration for scoped search domains below. When we enable that
                // enable this.
                if ((ptr->flag & SLE_WAB_BROWSE_QUERY_STARTED) &&
                    !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: DELETE Browse for domain -- name hash: %x", nameHash);
                    mDNS_StopGetDomains(m, &ptr->BrowseQ);
                    mDNS_StopGetDomains(m, &ptr->DefBrowseQ);
                }
                if ((ptr->flag & SLE_WAB_LBROWSE_QUERY_STARTED) &&
                    !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: DELETE Legacy Browse for domain -- name hash: %x", nameHash);
                    mDNS_StopGetDomains(m, &ptr->AutomaticBrowseQ);
                }
                if ((ptr->flag & SLE_WAB_REG_QUERY_STARTED) &&
                    !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: DELETE Registration for domain -- name hash: %x", nameHash);
                    mDNS_StopGetDomains(m, &ptr->RegisterQ);
                    mDNS_StopGetDomains(m, &ptr->DefRegisterQ);
                }

                mDNSPlatformMemFree(ptr);

                // deregister records generated from answers to the query
                while (arList)
                {
                    ARListElem *dereg = arList;
                    arList = arList->next;
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: DELETE Deregistering PTR -- "
                        "record: " PRI_DM_NAME " PTR " PRI_DM_NAME, DM_NAME_PARAM(dereg->ar.resrec.name),
                        DM_NAME_PARAM(&dereg->ar.resrec.rdata->u.name));
                    err = mDNS_Deregister(m, &dereg->ar);
                    if (err)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                            "uDNS_SetupWABQueries: mDNS_Deregister returned error -- error: %d", err);
                    }
                    // Memory will be freed in the FreeARElemCallback
                }
                continue;
            }

            // If the user has "local" in their DNS searchlist, we ignore that for the purposes of domain enumeration queries
            // We suppressed the domain enumeration for scoped search domains below. When we enable that
            // enable this.
            if (!(action & UDNS_WAB_BROWSE_QUERY) && (ptr->flag & SLE_WAB_BROWSE_QUERY_STARTED) &&
                !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "uDNS_SetupWABQueries: Deleting Browse for domain -- name hash: %x", nameHash);
                ptr->flag &= ~SLE_WAB_BROWSE_QUERY_STARTED;
                uDNS_DeleteWABQueries(m, ptr, UDNS_WAB_BROWSE_QUERY);
            }

            if (!(action & UDNS_WAB_LBROWSE_QUERY) && (ptr->flag & SLE_WAB_LBROWSE_QUERY_STARTED) &&
                !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "uDNS_SetupWABQueries: Deleting Legacy Browse for domain -- name hash: %x", nameHash);
                ptr->flag &= ~SLE_WAB_LBROWSE_QUERY_STARTED;
                uDNS_DeleteWABQueries(m, ptr, UDNS_WAB_LBROWSE_QUERY);
            }

            if (!(action & UDNS_WAB_REG_QUERY) && (ptr->flag & SLE_WAB_REG_QUERY_STARTED) &&
                !SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "uDNS_SetupWABQueries: Deleting Registration for domain -- name hash: %x", nameHash);
                ptr->flag &= ~SLE_WAB_REG_QUERY_STARTED;
                uDNS_DeleteWABQueries(m, ptr, UDNS_WAB_REG_QUERY);
            }

            // Fall through to handle the ADDs
        }

        if ((action & UDNS_WAB_BROWSE_QUERY) && !(ptr->flag & SLE_WAB_BROWSE_QUERY_STARTED))
        {
            // If the user has "local" in their DNS searchlist, we ignore that for the purposes of domain enumeration queries.
            // Also, suppress the domain enumeration for scoped search domains for now until there is a need.
            if (!SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                mStatus err1, err2;
                err1 = mDNS_GetDomains(m, &ptr->BrowseQ,          mDNS_DomainTypeBrowse,              &ptr->domain, ptr->InterfaceID, FoundDomain, ptr);
                if (err1)
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                        "uDNS_SetupWABQueries: GetDomains(mDNS_DomainTypeBrowse) returned error -- "
                        "name hash: %x, error: %d", nameHash, err1);
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: Starting Browse for domain -- name hash: %x", nameHash);
                }
                err2 = mDNS_GetDomains(m, &ptr->DefBrowseQ,       mDNS_DomainTypeBrowseDefault,       &ptr->domain, ptr->InterfaceID, FoundDomain, ptr);
                if (err2)
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                        "uDNS_SetupWABQueries: GetDomains(mDNS_DomainTypeBrowseDefault) returned error -- "
                        "name hash: %x, error: %d", nameHash, err2);
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: Starting Default Browse for domain -- name hash: %x", nameHash);
                }
                // For simplicity, we mark a single bit for denoting that both the browse queries have started.
                // It is not clear as to why one would fail to start and the other would succeed in starting up.
                // If that happens, we will try to stop both the queries and one of them won't be in the list and
                // it is not a hard error.
                if (!err1 || !err2)
                {
                    ptr->flag |= SLE_WAB_BROWSE_QUERY_STARTED;
                }
            }
        }
        if ((action & UDNS_WAB_LBROWSE_QUERY) && !(ptr->flag & SLE_WAB_LBROWSE_QUERY_STARTED))
        {
            // If the user has "local" in their DNS searchlist, we ignore that for the purposes of domain enumeration queries.
            // Also, suppress the domain enumeration for scoped search domains for now until there is a need.
            if (!SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                mStatus err1;
                err1 = mDNS_GetDomains(m, &ptr->AutomaticBrowseQ, mDNS_DomainTypeBrowseAutomatic,     &ptr->domain, ptr->InterfaceID, FoundDomain, ptr);
                if (err1)
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                        "uDNS_SetupWABQueries: GetDomains(mDNS_DomainTypeBrowseAutomatic) returned error -- "
                        "name hash: %x, error: %d", nameHash, err1);
                }
                else
                {
                    ptr->flag |= SLE_WAB_LBROWSE_QUERY_STARTED;
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: Starting Legacy Browse for domain -- name hash: %x", nameHash);
                }
            }
        }
        if ((action & UDNS_WAB_REG_QUERY) && !(ptr->flag & SLE_WAB_REG_QUERY_STARTED))
        {
            // If the user has "local" in their DNS searchlist, we ignore that for the purposes of domain enumeration queries.
            // Also, suppress the domain enumeration for scoped search domains for now until there is a need.
            if (!SameDomainName(&ptr->domain, &localdomain) && (ptr->InterfaceID == mDNSInterface_Any))
            {
                mStatus err1, err2;
                err1 = mDNS_GetDomains(m, &ptr->RegisterQ,        mDNS_DomainTypeRegistration,        &ptr->domain, ptr->InterfaceID, FoundDomain, ptr);
                if (err1)
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                        "uDNS_SetupWABQueries: GetDomains(mDNS_DomainTypeRegistration) returned error -- "
                        "name hash: %x, error: %d", nameHash, err1);
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: Starting Registration for domain -- name hash: %x", nameHash);
                }
                err2 = mDNS_GetDomains(m, &ptr->DefRegisterQ,     mDNS_DomainTypeRegistrationDefault, &ptr->domain, ptr->InterfaceID, FoundDomain, ptr);
                if (err2)
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                        "uDNS_SetupWABQueries: GetDomains(mDNS_DomainTypeRegistrationDefault) returned error -- "
                        "name hash: %x, error: %d", nameHash, err2);
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "uDNS_SetupWABQueries: Starting Default Registration for domain -- name hash: %x", nameHash);
                }
                if (!err1 || !err2)
                {
                    ptr->flag |= SLE_WAB_REG_QUERY_STARTED;
                }
            }
        }

        p = &ptr->next;
    }
}

// mDNS_StartWABQueries is called once per API invocation where normally
// one of the bits is set.
mDNSexport void uDNS_StartWABQueries(mDNS *const m, int queryType)
{
    if (queryType & UDNS_WAB_BROWSE_QUERY)
    {
        m->WABBrowseQueriesCount++;
        LogInfo("uDNS_StartWABQueries: Browse query count %d", m->WABBrowseQueriesCount);
    }
    if (queryType & UDNS_WAB_LBROWSE_QUERY)
    {
        m->WABLBrowseQueriesCount++;
        LogInfo("uDNS_StartWABQueries: Legacy Browse query count %d", m->WABLBrowseQueriesCount);
    }
    if (queryType & UDNS_WAB_REG_QUERY)
    {
        m->WABRegQueriesCount++;
        LogInfo("uDNS_StartWABQueries: Reg query count %d", m->WABRegQueriesCount);
    }
    uDNS_SetupWABQueries(m);
}

// mDNS_StopWABQueries is called once per API invocation where normally
// one of the bits is set.
mDNSexport void uDNS_StopWABQueries(mDNS *const m, int queryType)
{
    if (queryType & UDNS_WAB_BROWSE_QUERY)
    {
        m->WABBrowseQueriesCount--;
        LogInfo("uDNS_StopWABQueries: Browse query count %d", m->WABBrowseQueriesCount);
    }
    if (queryType & UDNS_WAB_LBROWSE_QUERY)
    {
        m->WABLBrowseQueriesCount--;
        LogInfo("uDNS_StopWABQueries: Legacy Browse query count %d", m->WABLBrowseQueriesCount);
    }
    if (queryType & UDNS_WAB_REG_QUERY)
    {
        m->WABRegQueriesCount--;
        LogInfo("uDNS_StopWABQueries: Reg query count %d", m->WABRegQueriesCount);
    }
    uDNS_SetupWABQueries(m);
}

mDNSexport domainname  *uDNS_GetNextSearchDomain(mDNSInterfaceID InterfaceID, int *searchIndex, mDNSBool ignoreDotLocal)
{
    SearchListElem *p = SearchList;
    int count = *searchIndex;

    if (count < 0) { LogMsg("uDNS_GetNextSearchDomain: count %d less than zero", count); return mDNSNULL; }

    // Skip the  domains that we already looked at before. Guard against "p"
    // being NULL. When search domains change we may not set the SearchListIndex
    // of the question to zero immediately e.g., domain enumeration query calls
    // uDNS_SetupWABQueries which reads in the new search domain but does not
    // restart the questions immediately. Questions are restarted as part of
    // network change and hence temporarily SearchListIndex may be out of range.

    for (; count && p; count--)
        p = p->next;

    while (p)
    {
        int labels = CountLabels(&p->domain);
        if (labels > 1)
        {
            const domainname *d = SkipLeadingLabels(&p->domain, labels - 2);
            if (SameDomainName(d, (const domainname *)"\x7" "in-addr" "\x4" "arpa") ||
                SameDomainName(d, (const domainname *)"\x3" "ip6"     "\x4" "arpa"))
            {
                LogInfo("uDNS_GetNextSearchDomain: skipping search domain %##s, InterfaceID %p", p->domain.c, p->InterfaceID);
                (*searchIndex)++;
                p = p->next;
                continue;
            }
        }
        if (ignoreDotLocal && labels > 0)
        {
            const domainname *d = SkipLeadingLabels(&p->domain, labels - 1);
            if (SameDomainLabel(d->c, (const mDNSu8 *)"\x5" "local"))
            {
                LogInfo("uDNS_GetNextSearchDomain: skipping local domain %##s, InterfaceID %p", p->domain.c, p->InterfaceID);
                (*searchIndex)++;
                p = p->next;
                continue;
            }
        }
        // Point to the next one in the list which we will look at next time.
        (*searchIndex)++;
        if (p->InterfaceID == InterfaceID)
        {
            LogInfo("uDNS_GetNextSearchDomain returning domain %##s, InterfaceID %p", p->domain.c, p->InterfaceID);
            return &p->domain;
        }
        LogInfo("uDNS_GetNextSearchDomain skipping domain %##s, InterfaceID %p", p->domain.c, p->InterfaceID);
        p = p->next;
    }
    return mDNSNULL;
}

mDNSexport void uDNS_RestartQuestionAsTCP(mDNS *m, DNSQuestion *const q, const mDNSAddr *const srcaddr, const mDNSIPPort srcport)
{
    // Don't reuse TCP connections. We might have failed over to a different DNS server
    // while the first TCP connection is in progress. We need a new TCP connection to the
    // new DNS server. So, always try to establish a new connection.
    if (q->tcp) { DisposeTCPConn(q->tcp); q->tcp = mDNSNULL; }
    q->tcp = MakeTCPConn(m, mDNSNULL, mDNSNULL, kTCPSocketFlags_Zero, srcaddr, srcport, mDNSNULL, q, mDNSNULL);
}

mDNSlocal void FlushAddressCacheRecords(mDNS *const m)
{
    mDNSu32 slot;
    CacheGroup *cg;
    CacheRecord *cr;
    FORALL_CACHERECORDS(slot, cg, cr)
    {
        if (cr->resrec.InterfaceID) continue;

        // If resource records can answer A, AAAA or are RRSIGs that cover A/AAAA, they need to be flushed so that we
        // will deliver an ADD or RMV.

        RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
    #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
        // Here we are checking if the record should be decided on whether to deliver the remove event to the callback,
        // RRSIG that covers kDNSType_A or kDNSType_AAAA should always be checked.
        // Note that setting the two flags below will not necessarily deliver the remove event for RRSIG
        // that covers kDNSType_A or kDNSType_AAAA records. It still needs to go through the "IsAnswer" process to
        // determine whether to deliver the remove event.
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRValidated;
    #endif
        const mDNSBool typeMatches = RRTypeAnswersQuestionType(&cr->resrec, kDNSType_A, flags) ||
                                     RRTypeAnswersQuestionType(&cr->resrec, kDNSType_AAAA, flags);
        if (!typeMatches)
        {
            continue;
        }

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "FlushAddressCacheRecords: Purging Resourcerecord - "
            "record description: " PRI_S ".", CRDisplayString(m, cr));

        mDNS_PurgeCacheResourceRecord(m, cr);
    }
}

// Retry questions which has seach domains appended
mDNSexport void RetrySearchDomainQuestions(mDNS *const m)
{
    DNSQuestion *q;
    mDNSBool found = mDNSfalse;

    // Check to see if there are any questions which needs search domains to be applied.
    // If there is none, search domains can't possibly affect them.
    for (q = m->Questions; q; q = q->next)
    {
        if (q->AppendSearchDomains)
        {
            found = mDNStrue;
            break;
        }
    }
    if (!found)
    {
        LogInfo("RetrySearchDomainQuestions: Questions with AppendSearchDomain not found");
        return;
    }
    LogInfo("RetrySearchDomainQuestions: Question with AppendSearchDomain found %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
    // Purge all the A/AAAA cache records and restart the queries. mDNSCoreRestartAddressQueries
    // does this. When we restart the question,  we first want to try the new search domains rather
    // than use the entries that is already in the cache. When we appended search domains, we might
    // have created cache entries which is no longer valid as there are new search domains now
    mDNSCoreRestartAddressQueries(m, mDNStrue, FlushAddressCacheRecords, mDNSNULL, mDNSNULL);
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

struct CompileTimeAssertionChecks_uDNS
{
    // Check our structures are reasonable sizes. Including overly-large buffers, or embedding
    // other overly-large structures instead of having a pointer to them, can inadvertently
    // cause structure sizes (and therefore memory usage) to balloon unreasonably.
    char sizecheck_tcpInfo_t     [(sizeof(tcpInfo_t)      <=  9056) ? 1 : -1];
    char sizecheck_SearchListElem[(sizeof(SearchListElem) <=  6381) ? 1 : -1];
};

// MARK: - DNS Push functions

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
mDNSlocal void DNSPushProcessResponse(mDNS *const m, const DNSMessage *const msg,
                                      DNSPushServer *server, ResourceRecord *mrr)
{
    // "(CacheRecord*)1" is a special (non-zero) end-of-list marker
    // We use this non-zero marker so that records in our CacheFlushRecords list will always have NextInCFList
    // set non-zero, and that tells GetCacheEntity() that they're not, at this moment, eligible for recycling.
    CacheRecord *CacheFlushRecords = (CacheRecord*)1;
    CacheRecord **cfp = &CacheFlushRecords;
    enum { removeName, removeClass, removeRRset, removeRR, addRR } action;
    const mDNSInterfaceID if_id = DNSPushServerGetInterfaceID(m, server);

    // Ignore records we don't want to cache.

    // Don't want to cache OPT or TSIG pseudo-RRs
    if (mrr->rrtype == kDNSType_TSIG)
    {
        return;
    }
    if (mrr->rrtype == kDNSType_OPT)
    {
        return;
    }

    if ((mrr->rrtype == kDNSType_CNAME) && SameDomainName(mrr->name, &mrr->rdata->u.name))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[PushS%u] DNSPushProcessResponse: Found a CNAME loop - "
            "rrname: " PRI_DM_NAME ".", server->serial, DM_NAME_PARAM(mrr->name));
        return;
    }

    // TTL == -1: delete individual record
    // TTL == -2: wildcard delete
    //   CLASS != ANY, TYPE != ANY: delete all records of specified type and class
    //   CLASS != ANY, TYPE == ANY: delete all RRs of specified class
    //   CLASS == ANY: delete all RRs on the name, regardless of type or class (TYPE is ignored).
    // If TTL is zero, this is a delete, not an add.
    if ((mDNSs32)mrr->rroriginalttl == -1)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u] DNSPushProcessResponse: Removing a record - "
            "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ", rdlength: %u, rdata: " PRI_S ".",
            server->serial, DM_NAME_PARAM(mrr->name), DNSTypeName(mrr->rrtype), mrr->rdlength, RRDisplayString(m, mrr));
        action = removeRR;
    }
    else if ((mDNSs32)mrr->rroriginalttl == -2)
    {
        if (mrr->rrclass == kDNSQClass_ANY)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u] DNSPushProcessResponse: Removing all records with the same name - rrname: " PRI_DM_NAME ".",
                server->serial, DM_NAME_PARAM(mrr->name));
            action = removeName;
        }
        else if (mrr->rrtype == kDNSQType_ANY)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u] DNSPushProcessResponse: Removing all records with the same name and class - "
                "rrname: " PRI_DM_NAME ", rrclass: %d" ".", server->serial, DM_NAME_PARAM(mrr->name), mrr->rrclass);
            action = removeClass;
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u] DNSPushProcessResponse: Removing the specified RRSet - "
                "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ", rdlength: %u.",
                server->serial, DM_NAME_PARAM(mrr->name), DNSTypeName(mrr->rrtype), mrr->rdlength);
            action = removeRRset;
        }
    }
    else
    {
        action = addRR;
    }

    if (action != addRR)
    {
        if (m->rrcache_size)
        {
            CacheRecord *rr;
            // Remember the unicast question that we found, which we use to make caching
            // decisions later on in this function
            CacheGroup *cg = CacheGroupForName(m, mrr->namehash, mrr->name);
            for (rr = cg ? cg->members : mDNSNULL; rr; rr=rr->next)
            {
                if ( action == removeName  ||
                    (action == removeClass && rr->resrec.rrclass == mrr->rrclass) ||
                    (rr->resrec.rrclass == mrr->rrclass &&
                     ((action == removeRRset && rr->resrec.rrtype == mrr->rrtype) ||
                      (action == removeRR    && rr->resrec.rrtype == mrr->rrtype  &&
                       SameRDataBody(mrr, &rr->resrec.rdata->u, SameDomainName)))))
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                        "[PushS%u] DNSPushProcessResponse: Purging RR - "
                        "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ", rdata: " PRI_S ".", server->serial,
                        DM_NAME_PARAM(rr->resrec.name), DNSTypeName(rr->resrec.rrtype), CRDisplayString(m, rr));

                    // We've found a cache entry to delete.   Now what?
                    mDNS_PurgeCacheResourceRecord(m, rr);
                }
            }
        }
    }
    else
    {
        // It's an add.
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u] DNSPushProcessResponse: Adding a record - "
            "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ", rdlength: %u, rdata: " PRI_S ".",
            server->serial, DM_NAME_PARAM(mrr->name), DNSTypeName(mrr->rrtype), mrr->rdlength, RRDisplayString(m, mrr));

        // Use the DNS Server we remember from the question that created this DNS Push server structure.
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        if (mrr->metadata)
        {
            mdns_cache_metadata_set_dns_service(mrr->metadata, server->dnsservice);
        }
#else
        mrr->rDNSServer = server->qDNSServer;
#endif

        // 2. See if we want to add this packet resource record to our cache
        // We only try to cache answers if we have a cache to put them in
        if (m->rrcache_size)
        {
            const mDNSu32 slot = HashSlotFromNameHash(mrr->namehash);
            CacheGroup *cg = CacheGroupForName(m, mrr->namehash, mrr->name);
            CacheRecord *rr = mDNSNULL;

            // 2a. Check if this packet resource record is already in our cache.
            rr = mDNSCoreReceiveCacheCheck(m, msg, uDNS_LLQ_Events, slot, cg, &cfp, if_id);

            // If packet resource record not in our cache, add it now
            // (unless it is just a deletion of a record we never had, in which case we don't care)
            if (!rr && mrr->rroriginalttl > 0)
            {
                rr = CreateNewCacheEntryEx(m, slot, cg, 0, mDNStrue, &server->connection->transport->remote_addr,
                                           kCreateNewCacheEntryFlagsDNSPushSubscribed);
                if (rr)
                {
                    // Not clear that this is ever used, but for verisimilitude, set this to look like
                    // an authoritative response to a regular query.
                    rr->responseFlags.b[0] = kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery | kDNSFlag0_AA;
                    rr->responseFlags.b[1] = kDNSFlag1_RC_NoErr;
                }
            }
        }
    }
}

mDNSlocal void DNSPushProcessResponses(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *firstAnswer,
                                           const mDNSu8 *const end, DNSPushServer *server)
{
    DNSQuestion *q;
    const mDNSu8 *ptr = firstAnswer;
    mDNSIPPort port;
    port.NotAnInteger = 0;
    ResourceRecord *const mrr = &m->rec.r.resrec;
    const mDNSInterfaceID if_id = DNSPushServerGetInterfaceID(m, server);

    // Validate the contents of the message
    // XXX Right now this code will happily parse all the valid data and then hit invalid data
    // and give up.  I don't think there's a risk here, but we should discuss it.
    // XXX what about source validation?   Like, if we have a VPN, are we safe?   I think yes, but let's think about it.
    while ((ptr = GetLargeResourceRecord(m, msg, ptr, end, if_id, kDNSRecordTypePacketAns, &m->rec)))
    {
    #if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        mdns_forget(&mrr->metadata);
        mrr->metadata = mdns_cache_metadata_create();
    #endif

        int gotOne = 0;
        for (q = m->Questions; q; q = q->next)
        {
            if (q->LongLived &&
                (q->qtype == mrr->rrtype || q->qtype == kDNSServiceType_ANY)
                && q->qnamehash == mrr->namehash && SameDomainName(&q->qname, mrr->name))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[R%u->Q%u] DNSPushProcessResponses found the matched question - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ", LLQ state: " PUB_S ", q's DNS push server: " PRI_S
                    ", DNS push server: " PRI_S ".", q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype), LLQStateToString(q->state),
                    q->dnsPushServer ? (q->dnsPushServer->connection
                                      ? q->dnsPushServer->connection->remote_name
                                      : "<no DNS push connection>") : "<no DNS push server>",
                    server->connection->remote_name
                );

                if (q->dnsPushServer == server)
                {
                    gotOne++;
                    DNSPushProcessResponse(m, msg, server, mrr);
                    break; // question list may have changed
                }
            }
        }
        if (!gotOne)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "[PushS%u->DSO%u] DNSPushProcessResponses found no matched question - "
                "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ".", server->serial, server->connection->serial,
                DM_NAME_PARAM(mrr->name), DNSTypeName(mrr->rrtype));
        }
        mrr->RecordType = 0;     // Clear RecordType to show we're not still using it
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    // Release the temporary metadata that is already retained by the newly added RR.
    mdns_forget(&mrr->metadata);
#endif
}

static void
DNSPushStartConnecting(DNSPushServer *server)
{
    if (server->connectInfo == NULL) {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[PushS%u] DNSPushStartConnecting: can't connect to server " PRI_DM_NAME "%%%u: no connectInfo",
                  server->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
        return;
    }
    if (dso_connect(server->connectInfo))
    {
        server->connectState = DNSPushServerConnectionInProgress;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSOC%u] Connecting to DNS push server - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, server->connectInfo->serial,
            DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
    }
    else
    {
        server->connectState = DNSPushServerConnectFailed;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSOC%u] Failed connect to DNS push server - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, server->connectInfo->serial,
            DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
    }
}

static DNSPushZone *DNSPushZoneCreate(const domainname *const name, DNSPushServer *const server, mDNS *const m)
{
    DNSPushZone *const zone = mDNSPlatformMemAllocateClear(sizeof(*zone));
    if (zone == mDNSNULL)
    {
        goto exit;
    }

    AssignDomainName(&zone->zoneName, name);
    zone->server = server;
    DNS_PUSH_RETAIN(zone->server); // This new zone holds a reference to the existing server.

    // Add the new zone to the beginning of the m->DNSPushZone list.
    zone->next = m->DNSPushZones;
    m->DNSPushZones = zone;
    DNS_PUSH_RETAIN(m->DNSPushZones); // The m->DNSPushZones list holds a reference to the new zone.

    DNS_PUSH_RETAIN(zone); // This create function will return an object that is retained.
exit:
    return zone;
}

// Release the DNSPushZone held by DNSQuestion.
static void ReleaseDNSPushZoneForQuestion(DNSQuestion *const q)
{
    if (q->dnsPushZone != mDNSNULL)
    {
        DNS_PUSH_RELEASE(q->dnsPushZone, DNSPushZoneFinalize);
        q->dnsPushZone = mDNSNULL;
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[Q%u] Question does not have a associated DNS Push zone - qname: " PRI_DM_NAME ".",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname));
    }
}

// Release the DNSPushServer held by DNSQuestion.
static void ReleaseDNSPushServerForQuestion(DNSQuestion *const q)
{
    if (q->dnsPushServer != mDNSNULL)
    {
        // Cannot cancel the server here by calling CancelDNSPushServer(), because there can be other
        // active questions that also use the current DNS push server, only call CancelDNSPushServer() when
        // we know the connection to server is invalid, for example, when the DNS server configuration changes.
        DNS_PUSH_RELEASE(q->dnsPushServer, DNSPushServerFinalize);
        q->dnsPushServer = mDNSNULL;
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[Q%u] Question does not have a associated DNS Push server - qname: " PRI_DM_NAME ".",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname));
    }
}

// Release the DNSPushZone and DNSPushServer reference held by DNSQuestion.
static void ReleaseDNSPushZoneAndServerForQuestion(DNSQuestion *q)
{
    if (q->dnsPushZone != mDNSNULL && q->dnsPushServer != mDNSNULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[Q%u->PushS%u] Releasing the DNS push zone and server"
            " - zone: " PRI_DM_NAME ", server: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID), q->dnsPushServer->serial,
            DM_NAME_PARAM(&q->dnsPushZone->zoneName), DM_NAME_PARAM(&q->dnsPushServer->serverName));
    }
    ReleaseDNSPushZoneForQuestion(q);
    ReleaseDNSPushServerForQuestion(q);
}

static const char kDNSPushActivity_Subscription[] = "dns-push-subscription";

static void DNSPushSendKeepalive(DNSPushServer *server, mDNSu32 inactivity_timeout, mDNSu32 keepalive_interval)
{
    dso_message_t state;
    dso_transport_t *transport = server->connection->transport;
    if (transport == NULL || transport->outbuf == NULL)
    {
        // Should be impossible, don't crash.
        LogInfo("DNSPushSendSubscribe: no transport!");
        return;
    }
    dso_make_message(&state, transport->outbuf, transport->outbuf_size, server->connection, false, false, 0, 0, 0);
    dso_start_tlv(&state, kDSOType_Keepalive);
    dso_add_tlv_u32(&state, inactivity_timeout);
    dso_add_tlv_u32(&state, keepalive_interval);
    dso_finish_tlv(&state);
    dso_message_write(server->connection, &state, mDNSfalse);
}

static void DNSPushSendSubscriptionChange(mDNSBool subscribe, dso_state_t *dso, DNSQuestion *q)
{
    dso_message_t state;
    dso_transport_t *transport = dso->transport;
    mDNSu16 len;
    if (transport == NULL || transport->outbuf == NULL) {
        // Should be impossible, don't crash.
        LogInfo("DNSPushSendSubscribe: no transport!");
        return;
    }
    dso_make_message(&state, transport->outbuf, transport->outbuf_size, dso, subscribe ? false : true, false, 0, 0, q);
    dso_start_tlv(&state, subscribe ? kDSOType_DNSPushSubscribe : kDSOType_DNSPushUnsubscribe);
    len = DomainNameLengthLimit(&q->qname, q->qname.c + (sizeof q->qname));
    dso_add_tlv_bytes(&state, q->qname.c, len);
    dso_add_tlv_u16(&state, q->qtype);
    dso_add_tlv_u16(&state, q->qclass);
    dso_finish_tlv(&state);
    dso_message_write(dso, &state, mDNSfalse);
}

void DNSPushZoneRemove(mDNS *const m, const DNSPushServer *const server)
{
    mDNSBool found = mDNSfalse;
    for (DNSPushZone **ptrToZoneRef = &m->DNSPushZones; *ptrToZoneRef != mDNSNULL;)
    {
        DNSPushZone *zone = *ptrToZoneRef;

        if (zone->server == server)
        {
            *ptrToZoneRef = zone->next;
            DNS_PUSH_RELEASE(zone, DNSPushZoneFinalize);
            found = mDNStrue;
        }
        else
        {
            ptrToZoneRef = &(zone->next);
        }
    }

    if (!found)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[PushS%u] DNS push zone is not found in the system's list - server name: " PRI_DM_NAME ", refCount: %u.",
            server->serial, DM_NAME_PARAM(&server->serverName), server->refCount);
    }
}

// Remove the DNSPushServer entirely from the system, and its corresponding DNSPushZone is also removed from the system.
static void DNSPushServerRemove(mDNS *const m, DNSPushServer *server)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[PushS%u] Removing DNS push server - name: " PRI_DM_NAME ", refCount: %u.", server->serial,
        DM_NAME_PARAM(&server->serverName), server->refCount);

    // 1. Release all the DNS push zones that use this server from the m->DNSPushZones list.
    DNSPushZoneRemove(m, server);

    // 2. Remove the server from the mDNSResponder's list.
    DNSPushServer **server_ptr = &m->DNSPushServers;
    while ((*server_ptr != mDNSNULL) && (*server_ptr != server))
    {
        server_ptr = &(*server_ptr)->next;
    }

    if (*server_ptr != mDNSNULL)
    {
        *server_ptr = server->next;
        server->next = mDNSNULL;
        DNS_PUSH_RELEASE(server, DNSPushServerFinalize);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[PushS%u] DNS push server is removed but it is not found in the system's list - "
            "name: " PRI_DM_NAME ", refCount: %u.", server->serial, DM_NAME_PARAM(&server->serverName),
            server->refCount);
    }
}

// Cancel the the DNSPushServer completely:
// 1. All the existing questions should not use it: completed by UnsubscribeAllQuestionsFromDNSPushServer().
// 2. All the question created in the future should not use it: completed by DNSPushServerRemove() or by the caller
//    of DNSPushServerCancel() if alreadyRemovedFromSystem is true.
// 3. All the underlying objects that are active should be canceled/released/freed.
// When alreadyRemovedFromSystem is set to true, this function will not iterate the m->DNSPushServers and remove it from
// the list. When it is true, we will assume that the DNS push server passed in has been removed from the list before
// the function is called.
mDNSexport void DNSPushServerCancel(DNSPushServer *server, const mDNSBool alreadyRemovedFromSystem)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u] Canceling DNS push server - "
        "server name: " PRI_DM_NAME ".", server->serial, DM_NAME_PARAM(&server->serverName));

    // 1. All the existing questions that have the active subscription should unsubscribe from the DNS push server, and
    // fall back to LLQ poll.
    UnsubscribeAllQuestionsFromDNSPushServer(server->m, server);

    // 2. All the questions created in the future should not use it, so remove it from the system's list.
    if (!alreadyRemovedFromSystem)
    {
        DNSPushServerRemove(server->m, server);
    }

    // 3. All the underlying objects that are active should be canceled/released/freed.
    server->canceling = mDNStrue;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    mdns_forget(&server->dnsservice);
#else
    server->qDNSServer = mDNSNULL;
#endif
    if (server->connection)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u->DSO%u] Canceling dso_state_t for DNS push server - server: " PRI_DM_NAME ":%u.",
            server->serial, server->connection->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));

        dso_state_cancel(server->connection);

        // server->connection will be freed in dso_idle().
        server->connection = mDNSNULL;
    }
    if (server->connectInfo)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u->DSOC%u] Canceling dso_connect_state_t for DNS push server - server: " PRI_DM_NAME ":%u.",
            server->serial, server->connectInfo->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
        dso_connect_state_cancel(server->connectInfo);

        // server->connectInfo will be freed in dso_transport_idle().
        server->connectInfo = mDNSNULL;
    }
}

static void DNSPushDSOCallback(void *context, void *event_context,
                               dso_state_t *dso, dso_event_type_t eventType)
{
    DNSPushServer *const server = context;

    const uint32_t dso_serial = dso != mDNSNULL ? dso->serial : DSO_STATE_INVALID_SERIAL;
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[DSO%u] New DNSPushDSOCallback - "
        "context: %p, event_context: %p, dso: %p, eventType: " PUB_S ", server state: " PUB_S ".",
        dso_serial, context, event_context, dso, dso_event_type_to_string(eventType),
        server != mDNSNULL ? DNSPushServerConnectStateToString(server->connectState) : "No server");

    if (dso == mDNSNULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "Calling DNSPushDSOCallback with NULL dso");
        return;
    }

    const DNSMessage *message;
    dso_message_payload_t *payload;
    dso_activity_t *activity;
    const dso_query_receive_context_t *receive_context;
    const dso_disconnect_context_t *disconnect_context;
    const dso_keepalive_context_t *keepalive_context;
    DNSQuestion *q;
    uint16_t rcode;
    mDNSs32 reconnect_when = 0;
    mDNS *m = server->m;

    mDNS_CheckLock(m);

    switch(eventType)
    {
    case kDSOEventType_DNSMessage:
        // We shouldn't get here because we won't use this connection for DNS messages.
        payload = event_context;
        message = (const DNSMessage *)payload->message;

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[PushS%u->DSO%u] Received an unexpected DNS message from the DSO connection - "
            "opcode: %d, server: " PRI_DM_NAME ":%u.", server->serial, dso_serial,
            (message->h.flags.b[0] & kDNSFlag0_OP_Mask) >> 3, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));
        break;

    case kDSOEventType_DNSResponse:
        // We shouldn't get here because we already handled any DNS messages.
        payload = event_context;
        message = (const DNSMessage *)payload->message;

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[PushS%u->DSO%u] Received an unexpected DNS response from the DSO connection - "
            "opcode: %d, server: " PRI_DM_NAME ":%u.", server->serial, dso_serial,
            (message->h.flags.b[0] & kDNSFlag0_OP_Mask) >> 3, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));
        break;

    case kDSOEventType_DSOMessage:
        payload = event_context;
        message = (const DNSMessage *)payload->message;
        if (dso->primary.opcode == kDSOType_DNSPushUpdate)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u->DSO%u] Received a DSO message from the DSO connection - "
                "server: " PRI_DM_NAME ":%u, message length: %u.", server->serial, dso_serial,
                DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port), dso->primary.length);

            DNSPushProcessResponses(server->m, message, dso->primary.payload,
                                    dso->primary.payload + dso->primary.length, server);
        }
        else
        {
            dso_send_not_implemented(dso, &message->h);

            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "[PushS%u->DSO%u] Received an unknown DSO response from the DSO connection - "
                "primary tlv: %d, server: " PRI_DM_NAME ":%u.", server->serial, dso_serial, dso->primary.opcode,
                DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
        }
        break;

    case kDSOEventType_DSOResponse:
        receive_context = event_context;
        q = receive_context->query_context;
        rcode = receive_context->rcode;
        if (q)
        {
            // If we got an error on a subscribe, we need to evaluate what went wrong.
            if (rcode == kDNSFlag1_RC_NoErr)
            {
                // It is possible that we get duplicate session established responses from the server in a race
                // condition, where the previous session establishing request has finished but the corresponding query
                // has been canceled. In which case, indicate that in the log.
                const mDNSBool sessionEstablishedPreviously = (server->connectState == DNSPushServerSessionEstablished);

                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[R%u->Q%u->PushS%u->DSO%u] Received a DSO response from the DSO connection. Subscription SUCCEEDS - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ", server: " PRI_DM_NAME ":%u" PUB_S ".", q->request_id,
                    mDNSVal16(q->TargetQID), server->serial, dso_serial, DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype), DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port),
                    sessionEstablishedPreviously ? ", session established previously" : "");

                q->state = LLQ_DNSPush_Established;
                server->connectState = DNSPushServerSessionEstablished;

                // If the subscription succeeds, then all the records that are cached before the subscription should
                // be purged. From now on, we rely on the DNS push server to give us the correct notification.
                mDNS_CheckLock(m);
                CacheGroup *const cache_group = CacheGroupForName(m, q->qnamehash, &q->qname);
                if (cache_group != mDNSNULL)
                {
                    for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL;
                         cache_record = cache_record->next)
                    {
                        if (!SameNameCacheRecordAnswersQuestion(cache_record, q))
                        {
                            continue;
                        }
                        if (cache_record->DNSPushSubscribed)
                        {
                            const ResourceRecord *const rr = &cache_record->resrec;
                            // If the session has been established previously, it is possible that the server has
                            // sent some responses back that can be used to answer queries. In which case, it is
                            // valid that the record from the responses is DNS-push-subscribed. However, we still
                            // want to purge it soon because the record might have been updated by the server. The
                            // current subscription will let the server send the new(or duplicate if the records do not
                            // change) responses, which will replace or rescue the old ones. If it has not been
                            // established yet, then it is invalid to have a subscribed record in the cache.
                            if (!sessionEstablishedPreviously)
                            {
                                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                                    "[R%u->Q%u->PushS%u->DSO%u] Already have an existing DNS push subscribed record in the cache - "
                                    "rrname: " PRI_DM_NAME ", rrtype: " PUB_S ", rdlength: %u, rdata: " PRI_S ".",
                                    q->request_id, mDNSVal16(q->TargetQID), server->serial, dso_serial,
                                    DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rdlength,
                                    RRDisplayString(m, rr));
                            }
                            cache_record->DNSPushSubscribed = mDNSfalse;
                        }
                        // Instead of purging the record immediately, we give the record 1 second to be rescued by a
                        // possible following subscription add event to avoid unnecessary add/remove/add sequence.
                        RefreshCacheRecord(m, cache_record, 1);
                    }
                }
            }
            else
            {
                // Don't use this server.
                server->connectState = DNSPushServerNoDNSPush;
                StartLLQPolling(m, q);

                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                    "[R%u->Q%u->PushS%u->DSO%u] Received a DSO response with non-zero error code from the DSO connection. Subscription FAILED, fall back to LLQ poll - "
                    "qname: " PRI_DM_NAME ", qtype: " PUB_S ", server: " PRI_DM_NAME ":%u, rcode: %d.", q->request_id,
                    mDNSVal16(q->TargetQID), server->serial, dso_serial, DM_NAME_PARAM(&q->qname),
                    DNSTypeName(q->qtype), DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port), rcode);
            }
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u->DSO%u] Received a DSO response from DSO connection. Session ESTABLISHED, but the query has been canceled. - "
                "primary tlv: %d, rcode: %d, server: " PRI_DM_NAME ":%u.", server->serial, dso_serial,
                dso->primary.opcode, receive_context->rcode, DM_NAME_PARAM(&server->serverName),
                mDNSVal16(server->port));

            server->connectState = DNSPushServerSessionEstablished;
        }
        break;

    case kDSOEventType_Finalize:
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSO%u] Finalizing dso_state_t - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));

        if (dso->context_callback != NULL)
        {
            // Give the context a callback with dso_life_cycle_free state, so that the context can do the final cleanup.
            dso->context_callback(dso_life_cycle_free, dso->context, dso);
        }
        mDNSPlatformMemFree(dso);
        break;

    case kDSOEventType_Connected:
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSO%u] DNS push server CONNECTED - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));

        server->connectState = DNSPushServerConnected;
        for (activity = dso->activities; activity; activity = activity->next)
        {
            DNSPushSendSubscriptionChange(mDNStrue, dso, activity->context);
        }
        break;

    case kDSOEventType_ConnectFailed:
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[PushS%u->DSO%u] DNS push server FAILED TO CONNECT - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));
        DNSPushServerCancel(server, mDNSfalse);
        break;

    case kDSOEventType_Disconnected:
        disconnect_context = event_context;

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[PushS%u->DSO%u] DNS push server disconnected - "
                  "server name: " PRI_DM_NAME ":%u, delay = %u, " PUB_S, server->serial, dso->serial,
                  DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port), disconnect_context->reconnect_delay,
                  server->connectInfo ? "connectable" : "stale");

        // We can get a disconnect event after the connection has been canceled from our end; in this case, we don't
        // have any work to do.
        if (server->connectInfo == NULL) {
            break;
        }

        // If a network glitch broke the connection, try to reconnect immediately.  But if this happens
        // twice, don't just blindly reconnect.
        if (disconnect_context->reconnect_delay == 0)
        {
            if (m->timenow - server->lastDisconnect < 90 * mDNSPlatformOneSecond)
            {
                reconnect_when = 60; // If we get two disconnects in quick succession, wait a minute before trying again.
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[PushS%u->DSO%u] Connection to the DNS push server disconnected, trying immediate reconnect - "
                    "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
                    mDNSVal16(server->port));

                DNSPushStartConnecting(server);
            }
        }
        else
        {
            reconnect_when = disconnect_context->reconnect_delay;
        }
        if (reconnect_when != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[PushS%u->DSO%u] Holding the DNS push server out as not reconnectable for a while - "
                "duration: %d, server name: " PRI_DM_NAME ":%u.",
                server->serial, dso->serial, reconnect_when,
                DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));

            dso_schedule_reconnect(m, server->connectInfo, reconnect_when);
        }
        server->lastDisconnect = m->timenow;
        break;

        // We get this event when a connection has been dropped and it's time to reconnect. This can happen either
        // because we got a hard connection drop, or because we got a RetryDelay DSO message. In the latter case,
        // the expectation is that we will get this callback when the delay has expired. This is actually set up
        // in this same function when we get a kDSOEventType_RetryDelay event.
    case kDSOEventType_ShouldReconnect:
        // This should be unnecessary, but it would be bad to accidentally have a question pointing at
        // a server that had been freed, so make sure we don't.
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u->DSO%u] ShouldReconnect timer fired for the DNS push server: reconnecting - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));
        if (server->connectInfo == NULL) {
            DNSPushStartConnecting(server);
        } else {
            server->connection = dso;
            dso_reconnect(server->connectInfo, dso);
        }
        break;

    case kDSOEventType_Keepalive:
        if (server->connection == NULL || server->connection->transport == NULL) {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "[PushS%u->DSO%u] Keepalive: connection to the DNS push server missing - server name: " PRI_DM_NAME ":%u.",
                      server->serial, dso->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
        } else {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "[PushS%u->DSO%u] Keepalive timer for the DNS push server fired - server name: " PRI_DM_NAME ":%u.",
                      server->serial, dso->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
            keepalive_context = event_context;

            DNSPushSendKeepalive(server, keepalive_context->inactivity_timeout, keepalive_context->keepalive_interval);
        }
        break;

    case kDSOEventType_KeepaliveRcvd:
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[PushS%u->DSO%u] Keepalive message received from the DNS push server - server name: " PRI_DM_NAME ":%u.",
            server->serial, dso->serial, DM_NAME_PARAM(&server->serverName), mDNSVal16(server->port));
        break;

    case kDSOEventType_Inactive:
        // The set of activities went to zero, and we set the idle timeout.   And it expired without any
        // new activities starting.   So we can disconnect.
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSO%u] Connection is inactive now - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));

        DNSPushServerCancel(server, mDNSfalse);
        break;

    case kDSOEventType_RetryDelay:
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSO%u] Planning reconnecting - "
            "server name: " PRI_DM_NAME ":%u.", server->serial, dso->serial, DM_NAME_PARAM(&server->serverName),
            mDNSVal16(server->port));

        disconnect_context = event_context;
        dso_schedule_reconnect(m, server->connectInfo, disconnect_context->reconnect_delay);
        break;
    }
}

static DNSPushServer *DNSPushServerCreate(const domainname *const name, const mDNSIPPort port,
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    const mdns_dns_service_t dnsService,
#else
    DNSServer *const qDNSServer,
#endif
    mDNS *const m);

// This function retains the DNSPushZone and DNSPushServer returned in *outZone and *outServer.
static mDNSBool DNSPushZoneAndServerCopy(mDNS *m, DNSQuestion *q,
    DNSPushZone **const outZone, DNSPushServer **const outServer)
{
    DNSPushZone   *newZone = mDNSNULL;
    DNSPushServer *newServer = mDNSNULL;

    *outZone = NULL;
    *outServer = NULL;

    // If we already have a question for this zone and if the server is the same, reuse it.
    for (DNSPushZone *zone = m->DNSPushZones; zone != mDNSNULL; zone = zone->next)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "[Q%u] Comparing zone with the question's zone - "
            "zone: " PRI_DM_NAME ", question zone: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID),
            DM_NAME_PARAM(&zone->zoneName), DM_NAME_PARAM(&q->nta->ZoneName));

        if (!SameDomainName(&q->nta->ZoneName, &zone->zoneName))
        {
            continue;
        }

        DNSPushServer *const zoneServer = zone->server;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "[Q%u] Comparing server with the question's target host - "
            "server name: " PRI_DM_NAME ", question target host: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID),
            DM_NAME_PARAM(&zoneServer->serverName), DM_NAME_PARAM(&q->nta->Host));

        if (zoneServer == mDNSNULL || !SameDomainName(&q->nta->Host, &zoneServer->serverName))
        {
            continue;
        }

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[Q%u->PushS%u] Retaining an existing DNS push zone and server for the question - "
            "zone name: " PRI_DM_NAME ", server name: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID), zoneServer->serial,
            DM_NAME_PARAM(&zone->zoneName), DM_NAME_PARAM(&zoneServer->serverName));

        *outZone = zone;
        DNS_PUSH_RETAIN(*outZone);
        *outServer = zoneServer;
        DNS_PUSH_RETAIN(*outServer);

        goto exit;
    }

    // If we have a connection to this server but it is for a different zone, create a new zone entry and reuse the connection.
    for (DNSPushServer *server = m->DNSPushServers; server != mDNSNULL; server = server->next)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "[Q%u] Comparing server with the question's target host - "
            "server name: " PRI_DM_NAME ", question target host: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID),
            DM_NAME_PARAM(&server->serverName), DM_NAME_PARAM(&q->nta->Host));

        if (!SameDomainName(&q->nta->Host, &server->serverName))
        {
            continue;
        }

        newZone = DNSPushZoneCreate(&q->nta->ZoneName, server, m);
        if (newZone == mDNSNULL)
        {
            goto exit;
        }

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[Q%u->PushS%u] Retaining a new DNS push zone and an existing server for the question - "
            "new zone name: " PRI_DM_NAME ", server name: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID), server->serial,
            DM_NAME_PARAM(&newZone->zoneName), DM_NAME_PARAM(&server->serverName));

        *outZone = newZone;
        // newZone = mDNSNULL; The ownership is now transferred.
        *outServer = server;
        DNS_PUSH_RETAIN(*outServer);

        goto exit;
    }

    // If we do not have any existing connections, create a new connection.
    newServer = DNSPushServerCreate(&q->nta->Host, q->nta->Port,
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
                                    q->dnsservice,
#else
                                    q->qDNSServer,
#endif
                                    m);
    if (newServer == mDNSNULL)
    {
        goto exit;
    }

    newZone = DNSPushZoneCreate(&q->nta->ZoneName, newServer, m);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[Q%u->PushS%u] Retaining a new DNS push zone and a new server for the question - "
        "new zone name: " PRI_DM_NAME ", server name: " PRI_DM_NAME ".", mDNSVal16(q->TargetQID), newServer->serial,
        DM_NAME_PARAM(&newZone->zoneName), DM_NAME_PARAM(&newServer->serverName));

    *outZone = newZone;
    // newZone = mDNSNULL; The ownership is now transferred.
    *outServer = newServer;
    newServer = mDNSNULL;

exit:
    if (newServer != mDNSNULL)
    {
        // Revert the work done by DNSPushZoneCreate().
        DNSPushServerCancel(newServer, mDNSfalse);
        DNS_PUSH_RELEASE(newServer, DNSPushServerFinalize); // newServer removes the reference to it.
        // newServer = mDNSNULL; The reference held is released.
        // Then the last reference of the newServer will be released in DNSPushDSOCallback() when dso_idle() cleans
        // dso_connections_needing_cleanup list.
    }
    return *outZone != mDNSNULL && *outServer != mDNSNULL;
}

static bool DSOLifeCycleContextCallBack(const dso_life_cycle_t life_cycle, void *const context,
                                        dso_state_t *const dso)
{
    DNSPushServer *server = context;
    bool status = false;
    if (server == mDNSNULL || dso == mDNSNULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "DSOLifeCycleContextCallBack gets called with NULL pointer - server: %p, dso: %p.",
            context, dso);
        goto exit;
    }

    switch (life_cycle)
    {
        case dso_life_cycle_create:
            DNS_PUSH_RETAIN(server);
            break;
        case dso_life_cycle_cancel:
            // If the DNS Push server is being canceled, then and only then do we want the dso to be collected.
            if (server->canceling) {
                status = true;
            }
            // Otherwise, we expect the DSO object to continue to be used for the next connection attempt to a
            // working DSO server.
            break;
        case dso_life_cycle_free:
            DNS_PUSH_RELEASE(server, DNSPushServerFinalize);
            dso->context = mDNSNULL;
            break;
    }
exit:
    return status;
}

static bool DSOConnectLifeCycleContextCallBack(const dso_connect_life_cycle_t life_cycle, void *const context,
                                               dso_connect_state_t *const dso_connect)
{
    DNSPushServer *server = context;
    bool status = false;

    // Only check the parameter for dso_connect_life_cycle_create and dso_connect_life_cycle_cancel.
    if (life_cycle == dso_connect_life_cycle_create || life_cycle == dso_connect_life_cycle_cancel)
    {
        if (server == mDNSNULL || dso_connect == mDNSNULL)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "DSOConnectLifeCycleContextCallBack gets called with NULL pointer - context: %p, dso_connect: %p.",
                context, dso_connect);
            goto exit;
        }
    }

    switch (life_cycle)
    {
        case dso_connect_life_cycle_create:
            DNS_PUSH_RETAIN(server);
            break;
        case dso_connect_life_cycle_cancel:
            DNS_PUSH_RELEASE(server, DNSPushServerFinalize);
            dso_connect->context = mDNSNULL;
            status = true;
            break;
        case dso_connect_life_cycle_free:
            // Do nothing, the context has been freed in dso_connect_life_cycle_cancel case above.
            break;
    }
exit:
    return status;
}

static DNSPushServer *DNSPushServerCreate(const domainname *const name, const mDNSIPPort port,
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    const mdns_dns_service_t dnsService,
#else
    DNSServer *const qDNSServer,
#endif
    mDNS *const m)
{
    DNSPushServer *serverToReturn = mDNSNULL;
    DNSPushServer *server = mDNSNULL;

    server = mDNSPlatformMemAllocateClear(sizeof(*server));
    if (server == mDNSNULL)
    {
        goto exit;
    }
    DNS_PUSH_RETAIN(server); // This create function will return an object that is retained.

    // Used to uniquely mark DNSPushServer objects, incremented once for each DNSPushServer created.
    // DNS_PUSH_SERVER_INVALID_SERIAL(0) is used to identify the invalid DNSPushServer.
    static uint32_t serial = DNS_PUSH_SERVER_INVALID_SERIAL + 1;
    server->serial = serial++;

    AssignDomainName(&server->serverName, name);
    server->port = port;
    server->m = m;
    server->canceling = mDNSfalse;

    char serverNameCStr[MAX_ESCAPED_DOMAIN_NAME];
    ConvertDomainNameToCString(name, serverNameCStr);
    // server is being passed to dso_state_create() to create dso_state_t, so dso_state_t also holds a reference to the
    // new server. server will be retained in DSOLifeCycleContextCallBack: case dso_life_cycle_create.
    server->connection = dso_state_create(mDNSfalse, 10, serverNameCStr, DNSPushDSOCallback, server,
                                          DSOLifeCycleContextCallBack, mDNSNULL);
    if (server->connection == mDNSNULL)
    {
        goto exit;
    }

    // server is being passed to dso_connect_state_create() to create dso_connect_state_t, so dso_connect_state_t also
    // holds a reference to the new server. server will be retained in DSOConnectLifeCycleContextCallBack: case
    // dso_life_cycle_create. If dso_connect_state_t creates a new dso_state_t later in dso_connection_succeeded(),
    // server will also be retained in DSOLifeCycleContextCallBack: case dso_life_cycle_create, when calling
    // dso_state_create().
    server->connectInfo = dso_connect_state_create(serverNameCStr, mDNSNULL, port, 10, AbsoluteMaxDNSMessageData,
        AbsoluteMaxDNSMessageData, DNSPushDSOCallback, server->connection, server,
        DSOLifeCycleContextCallBack, DSOConnectLifeCycleContextCallBack, "DNSPushServerCreate");
    if (server->connectInfo != mDNSNULL)
    {
        dso_connect_state_use_tls(server->connectInfo);
        DNSPushStartConnecting(server);
    }
    else
    {
        server->connectState = DNSPushServerConnectFailed;
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    mdns_replace(&server->dnsservice, dnsService);
#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)
    if (server->connectInfo)
    {
        // If the underlying DNS service is an mDNS alternative service, then it might have configured alternative TLS
        // trust anchors for us to use when setting up the TLS connection.
        server->connectInfo->trusts_alternative_server_certificates =
            mdns_dns_service_is_mdns_alternative(dnsService);
    }
#endif
#else
    server->qDNSServer = qDNSServer;
#endif

    server->next = m->DNSPushServers;
    m->DNSPushServers = server;
    DNS_PUSH_RETAIN(m->DNSPushServers); // The m->DNSPushServers holds a new reference to the new server.

    serverToReturn = server;
    server = mDNSNULL; // The ownership is now transferred.

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u->DSO%u->DSOC%u] New DNSPushServer created - "
        "server: %p, server name: " PRI_DM_NAME ".", serverToReturn->serial, serverToReturn->connection->serial,
        serverToReturn->connectInfo != mDNSNULL ? serverToReturn->connectInfo->serial : DSO_CONNECT_STATE_INVALID_SERIAL,
        serverToReturn, DM_NAME_PARAM(&serverToReturn->serverName));

exit:
    mDNSPlatformMemFree(server);
    return serverToReturn;
}

mDNSexport mDNSInterfaceID DNSPushServerGetInterfaceID(mDNS *const m, const DNSPushServer *const server)
{
    mDNSInterfaceID ifID = mDNSInterface_Any;
    if (server)
    {
        bool hasLocalPurview = false;
    #if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        if (server->dnsservice)
        {
            // Check if the underlying DNS service of this DNS push server has local purview
            hasLocalPurview = mdns_dns_service_has_local_purview(server->dnsservice);
        }
    #endif
        if (hasLocalPurview && server->connectInfo)
        {
            // If the underlying DNS service has local purview, then this server is specifically related to the
            // interface where the DSO connection is established.
            const dso_connect_state_t *const dcs = server->connectInfo;
            if (dcs->if_idx != 0)
            {
                ifID = mDNSPlatformInterfaceIDfromInterfaceIndex(m, dcs->if_idx);
            }
        }
    }
    return ifID;
}

mDNSexport void DNSPushServerFinalize(DNSPushServer *const server)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[PushS%u] DNSPushServer finalizing - "
        "server: %p, server name: " PRI_DM_NAME ".", server->serial, server, DM_NAME_PARAM(&server->serverName));

    if (server->connection != mDNSNULL || server->connectInfo != mDNSNULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "[PushS%u] server was not canceled before it gets finalized - "
            "server name: " PRI_DM_NAME ", server->connection: %p, server->connectInfo: %p.", server->serial,
            DM_NAME_PARAM(&server->serverName), server->connection, server->connectInfo);
    }
    mDNSPlatformMemFree(server);
}

mDNSexport void DNSPushZoneFinalize(DNSPushZone *const zone)
{
    if (zone->server != mDNSNULL)
    {
        DNS_PUSH_RELEASE(zone->server, DNSPushServerFinalize);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "The zone being released does not have any DNS push server associated - zone: " PRI_DM_NAME,
            DM_NAME_PARAM(&zone->zoneName));
    }

    mDNSPlatformMemFree(zone);
}

static mDNSBool SubscribeToDNSPushServer(mDNS *m, DNSQuestion *q,
    DNSPushZone **const outZone, DNSPushServer **const outServer)
{
    DNSPushZone *zoneSelected = mDNSNULL;
    DNSPushServer *serverSelected = mDNSNULL;
    mDNSBool succeeded = DNSPushZoneAndServerCopy(m, q, &zoneSelected, &serverSelected);
    if (!succeeded)
    {
        goto exit;
    }

    // server->connection should never be NULL here.
    if (serverSelected->connection == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
            "The zone being subscribed does not have any DSO object associated - zone: " PRI_DM_NAME,
            DM_NAME_PARAM(&zoneSelected->zoneName));
        goto exit;
    }

    char name[MAX_ESCAPED_DOMAIN_NAME + 9];  // type(hex)+class(hex)+name
    dso_activity_t *activity;

    // Now we have a connection to a push notification server.   It may be pending, or it may be active,
    // but either way we can add a DNS Push subscription to the server object.
    mDNS_snprintf(name, sizeof name, "%04x%04x", q->qtype, q->qclass);
    ConvertDomainNameToCString(&q->qname, &name[8]);
    activity = dso_add_activity(serverSelected->connection, name, kDNSPushActivity_Subscription, q, mDNSNULL);
    if (activity == mDNSNULL)
    {
        succeeded = mDNSfalse;
        goto exit;
    }

    // If we're already connected, send the subscribe request immediately.
    if (serverSelected->connectState == DNSPushServerConnected ||
        serverSelected->connectState == DNSPushServerSessionEstablished)
    {
        DNSPushSendSubscriptionChange(mDNStrue, serverSelected->connection, q);
    }

    *outZone = zoneSelected;
    zoneSelected = mDNSNULL;
    *outServer = serverSelected;
    serverSelected = mDNSNULL;

exit:
    // When dso_add_activity fails, release the reference we previously retained.
    if (zoneSelected != mDNSNULL)
    {
        DNS_PUSH_RELEASE(zoneSelected, DNSPushZoneFinalize);
    }
    if (serverSelected != mDNSNULL)
    {
        DNS_PUSH_RELEASE(serverSelected, DNSPushServerFinalize);
    }
    return succeeded;
}

mDNSexport void DiscoverDNSPushServer(mDNS *m, DNSQuestion *q)
{
    q->ThisQInterval = LLQ_POLL_INTERVAL + mDNSRandom(LLQ_POLL_INTERVAL/10);    // Retry in approx 15 minutes
    q->LastQTime     = m->timenow;
    SetNextQueryTime(m, q);
    if (q->nta) CancelGetZoneData(m, q->nta);
    q->nta = StartGetZoneData(m, &q->qname, ZoneServiceDNSPush, DNSPushGotZoneData, q);
    q->state = LLQ_DNSPush_ServerDiscovery;
    if (q->nta != mDNSNULL)
    {
        q->nta->question.request_id = q->request_id;
    }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u->Q%u->subQ%u] Starting DNS push server discovery - "
        "qname: " PRI_DM_NAME ", qtype: " PUB_S ".", q->request_id, mDNSVal16(q->TargetQID),
        q->nta != mDNSNULL ? mDNSVal16(q->nta->question.TargetQID) : 0, DM_NAME_PARAM(&q->qname),
        DNSTypeName(q->qtype));
}

mDNSexport void UnsubscribeQuestionFromDNSPushServer(mDNS *const NONNULL m, DNSQuestion *const NONNULL q,
                                                     const mDNSBool fallBackToLLQPoll)
{
    const DNSPushServer *const server = q->dnsPushServer;
    dso_state_t *const dso = (server != mDNSNULL) ? server->connection : mDNSNULL;
    const uint32_t qid = mDNSVal16(q->TargetQID);
    const uint32_t server_serial = (server != mDNSNULL) ? server->serial : DNS_PUSH_SERVER_INVALID_SERIAL;
    const uint32_t dso_serial = (dso != mDNSNULL) ? dso->serial : DSO_STATE_INVALID_SERIAL;

    if (server == mDNSNULL || dso == mDNSNULL)
    {
        // In theory, this should never happen because any outstanding query should have a DSO connection and a DSO
        // server associated with it. However, bug report shows that some outstanding queries will have dangling
        // question pointer which lead to user-after-free crash. Therefore, this function is called to scan through
        // any active DSO query to reset the possible dangling pointer unconditionally, to avoid crash.
        const uint32_t reset_count = dso_connections_reset_outstanding_query_context(q);
        if (reset_count)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[Q%u] Question is not associated with any DSO "
                "connection, but DSO connection(s) have outstanding reference to it, resetting the reference - "
                "reset_count: %u", qid, reset_count);
        }
        goto exit;
    }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[Q%u->PushS%u->DSO%u] Unsubscribing question from the DNS push server - "
        "server name: " PRI_DM_NAME ", connect state: " PUB_S ".", qid, server_serial, dso_serial,
        DM_NAME_PARAM(&server->serverName), DNSPushServerConnectStateToString(server->connectState));

    // Stop any active DSO query.
    const uint32_t disassociated_count = dso_ignore_further_responses(dso, q);
    if (disassociated_count != 0)
    {
        if (server->connectState != DNSPushServerConnected && server->connectState != DNSPushServerSessionEstablished)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "[Q%u->PushS%u->DSO%u] Having unexpected outstanding queries while the DNS Push server is not in the connected or session established state - "
                "server name: " PRI_DM_NAME ", connect state: " PUB_S " outstanding queries: %u.", qid, server_serial,
                dso_serial, DM_NAME_PARAM(&server->serverName), DNSPushServerConnectStateToString(server->connectState),
                disassociated_count);
        }
    }

    if (dso->has_session)
    {
        // When we as a client has an established connection to the server, we will not have an established
        // DSO session to the server until we receive an acknowledgment from the server. Therefore, only send
        // subscription change if we have an established DSO session.
        DNSPushSendSubscriptionChange(mDNSfalse, dso, q);
    }

    // Remove any activity associated with the question.
    dso_activity_t *const activity = dso_find_activity(dso, mDNSNULL, kDNSPushActivity_Subscription, q);
    if (activity != mDNSNULL)
    {
        dso_drop_activity(dso, activity);
    }

    // The cached answer added by the subscription above should be changed back to a regular one, which ages according
    // to the original TTL specified by the DNS push server.
    mDNS_CheckLock(m);
    CacheGroup *const cache_group = CacheGroupForName(m, q->qnamehash, &q->qname);
    if (cache_group == mDNSNULL)
    {
        goto exit;
    }

    for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL; cache_record = cache_record->next)
    {
        if (!SameNameCacheRecordAnswersQuestion(cache_record, q))
        {
            continue;
        }

        // When a subscription is canceled, the added record will be removed immediately from the cache.
        cache_record->DNSPushSubscribed = mDNSfalse;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[Q%u->PushS%u->DSO%u] Removing record from the cache due to the unsubscribed activity - "
            "qname: " PRI_DM_NAME ", qtype: " PUB_S ", TTL: %us.", qid, server_serial, dso_serial,
            DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), cache_record->resrec.rroriginalttl);
        mDNS_PurgeCacheResourceRecord(m, cache_record);
    }

exit:
    // Release the question's reference to the DNS push zone and the DNS push server.
    ReleaseDNSPushZoneAndServerForQuestion(q);
    // If the question is still active when unsubscription happens, it falls back to LLQ poll.
    if (fallBackToLLQPoll)
    {
        // Since the question loses its DNSPushServer, it cannot use DNS push, so fall back to regular unicast
        // DNS(LLQ Poll).
        StartLLQPolling(m, q);
    }
    return;
}

mDNSexport void UnsubscribeAllQuestionsFromDNSPushServer(mDNS *const NONNULL m, DNSPushServer *const NONNULL server)
{
    for (DNSQuestion *q = m->Questions; q != mDNSNULL; q = q->next)
    {
        if (q->dnsPushServer != server)
        {
            continue;
        }
        // Since we are unsubscribing all questions' activities from the DNS push server, and some questions might still
        // be active and waiting for the response, the questions should fall back to LLQ poll.
        UnsubscribeQuestionFromDNSPushServer(m, q, mDNStrue);
    }
}

// Update the duplicate question to the new primary question when the original primary question is being stopped.
mDNSexport void
DNSPushUpdateQuestionDuplicate(DNSQuestion *const NONNULL primary, DNSQuestion *const NONNULL duplicate)
{
    if (primary->dnsPushZone != mDNSNULL)
    {
        // Transfer the ownership of the DNS push zone.
        duplicate->dnsPushZone   = primary->dnsPushZone;
        DNS_PUSH_RETAIN(duplicate->dnsPushZone);
        DNS_PUSH_RELEASE(primary->dnsPushZone, DNSPushZoneFinalize);
        primary->dnsPushZone = mDNSNULL;
    }
    if (primary->dnsPushServer != mDNSNULL)
    {
        dso_state_t *const dso_state = primary->dnsPushServer->connection;
        if (dso_state)
        {
            // Update the outstanding query context from the old primary being stopped to the new primary.
            dso_update_outstanding_query_context(dso_state, primary, duplicate);

            // Also update the context of the dso_activity_t since we are replacing the original primary question with
            // the new one(which is previously a duplicate of the primary question).
            dso_activity_t *const activity = dso_find_activity(dso_state, mDNSNULL, kDNSPushActivity_Subscription,
                primary);
            if (activity != mDNSNULL)
            {
                activity->context = duplicate;
            }
        }

        // Transfer the ownership of the DNS push server.
        duplicate->dnsPushServer = primary->dnsPushServer;
        DNS_PUSH_RETAIN(duplicate->dnsPushServer);
        DNS_PUSH_RELEASE(primary->dnsPushServer, DNSPushServerFinalize);
        primary->dnsPushServer = mDNSNULL;
    }
}

mDNSlocal const char *DNSPushServerConnectStateToString(const DNSPushServer_ConnectState state)
{
#define CASE_TO_STR(s) case s: return (#s)
    switch (state)
    {
        CASE_TO_STR(DNSPushServerDisconnected);
        CASE_TO_STR(DNSPushServerConnectFailed);
        CASE_TO_STR(DNSPushServerConnectionInProgress);
        CASE_TO_STR(DNSPushServerConnected);
        CASE_TO_STR(DNSPushServerSessionEstablished);
        CASE_TO_STR(DNSPushServerNoDNSPush);
    }
#undef CASE_TO_STR
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "Invalid DNSPushServer_ConnectState - state: %u", state);
    return "<INVALID DNSPushServer_ConnectState>";
}

#endif // MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)

mDNSlocal const char *LLQStateToString(const LLQ_State state)
{
#define CASE_TO_STR(s) case s: return (#s)
    switch (state)
    {
        CASE_TO_STR(LLQ_Invalid);
        CASE_TO_STR(LLQ_Init);
        CASE_TO_STR(LLQ_DNSPush_ServerDiscovery);
        CASE_TO_STR(LLQ_DNSPush_Connecting);
        CASE_TO_STR(LLQ_DNSPush_Established);
        CASE_TO_STR(LLQ_InitialRequest);
        CASE_TO_STR(LLQ_SecondaryRequest);
        CASE_TO_STR(LLQ_Established);
        CASE_TO_STR(LLQ_Poll);
        MDNS_COVERED_SWITCH_DEFAULT:
            break;
    }
#undef CASE_TO_STR
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "Invalid LLQ_State - state: %u", state);
    return "<INVALID LLQ_State>";
}

// MARK: -
#else // !UNICAST_DISABLED

mDNSexport const domainname *GetServiceTarget(mDNS *m, AuthRecord *const rr)
{
    (void) m;
    (void) rr;

    return mDNSNULL;
}

mDNSexport DomainAuthInfo *GetAuthInfoForName_internal(mDNS *m, const domainname *const name)
{
    (void) m;
    (void) name;

    return mDNSNULL;
}

mDNSexport DomainAuthInfo *GetAuthInfoForQuestion(mDNS *m, const DNSQuestion *const q)
{
    (void) m;
    (void) q;

    return mDNSNULL;
}

mDNSexport void startLLQHandshake(mDNS *m, DNSQuestion *q)
{
    (void) m;
    (void) q;
}

mDNSexport void DisposeTCPConn(struct tcpInfo_t *tcp)
{
    (void) tcp;
}

mDNSexport mStatus mDNS_StartNATOperation_internal(mDNS *m, NATTraversalInfo *traversal)
{
    (void) m;
    (void) traversal;

    return mStatus_UnsupportedErr;
}

mDNSexport mStatus mDNS_StopNATOperation_internal(mDNS *m, NATTraversalInfo *traversal)
{
    (void) m;
    (void) traversal;

    return mStatus_UnsupportedErr;
}

mDNSexport void sendLLQRefresh(mDNS *m, DNSQuestion *q)
{
    (void) m;
    (void) q;
}

mDNSexport ZoneData *StartGetZoneData(mDNS *const m, const domainname *const name, const ZoneService target, ZoneDataCallback callback, void *ZoneDataContext)
{
    (void) m;
    (void) name;
    (void) target;
    (void) callback;
    (void) ZoneDataContext;

    return mDNSNULL;
}

mDNSexport void RecordRegistrationGotZoneData(mDNS *const m, mStatus err, const ZoneData *zoneData)
{
    (void) m;
    (void) err;
    (void) zoneData;
}

mDNSexport uDNS_LLQType uDNS_recvLLQResponse(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
                                             const mDNSAddr *const srcaddr, const mDNSIPPort srcport, DNSQuestion **matchQuestion)
{
    (void) m;
    (void) msg;
    (void) end;
    (void) srcaddr;
    (void) srcport;
    (void) matchQuestion;

    return uDNS_LLQ_Not;
}

mDNSexport void PenalizeDNSServer(mDNS *const m, DNSQuestion *q, mDNSOpaque16 responseFlags)
{
    (void) m;
    (void) q;
    (void) responseFlags;
}

mDNSexport void mDNS_AddSearchDomain(const domainname *const domain, mDNSInterfaceID InterfaceID)
{
    (void) domain;
    (void) InterfaceID;
}

mDNSexport void RetrySearchDomainQuestions(mDNS *const m)
{
    (void) m;
}

mDNSexport mStatus mDNS_SetSecretForDomain(mDNS *m, DomainAuthInfo *info, const domainname *domain, const domainname *keyname, const char *b64keydata, const domainname *hostname, mDNSIPPort *port)
{
    (void) m;
    (void) info;
    (void) domain;
    (void) keyname;
    (void) b64keydata;
    (void) hostname;
    (void) port;

    return mStatus_UnsupportedErr;
}

mDNSexport domainname  *uDNS_GetNextSearchDomain(mDNSInterfaceID InterfaceID, mDNSs8 *searchIndex, mDNSBool ignoreDotLocal)
{
    (void) InterfaceID;
    (void) searchIndex;
    (void) ignoreDotLocal;

    return mDNSNULL;
}

mDNSexport DomainAuthInfo *GetAuthInfoForName(mDNS *m, const domainname *const name)
{
    (void) m;
    (void) name;

    return mDNSNULL;
}

mDNSexport mStatus mDNS_StartNATOperation(mDNS *const m, NATTraversalInfo *traversal)
{
    (void) m;
    (void) traversal;

    return mStatus_UnsupportedErr;
}

mDNSexport mStatus mDNS_StopNATOperation(mDNS *const m, NATTraversalInfo *traversal)
{
    (void) m;
    (void) traversal;

    return mStatus_UnsupportedErr;
}

mDNSexport DNSServer *mDNS_AddDNSServer(mDNS *const m, const domainname *d, const mDNSInterfaceID interface, const mDNSs32 serviceID, const mDNSAddr *addr,
                                        const mDNSIPPort port, ScopeType scopeType, mDNSu32 timeout, mDNSBool isCell, mDNSBool isExpensive, mDNSBool isConstrained, mDNSBool isCLAT46,
                                        mDNSu32 resGroupID, mDNSBool reqA, mDNSBool reqAAAA, mDNSBool reqDO)
{
    (void) m;
    (void) d;
    (void) interface;
    (void) serviceID;
    (void) addr;
    (void) port;
    (void) scopeType;
    (void) timeout;
    (void) isCell;
    (void) isExpensive;
    (void) isCLAT46;
    (void) isConstrained;
    (void) resGroupID;
    (void) reqA;
    (void) reqAAAA;
    (void) reqDO;

    return mDNSNULL;
}

mDNSexport void uDNS_SetupWABQueries(mDNS *const m)
{
    (void) m;
}

mDNSexport void uDNS_StartWABQueries(mDNS *const m, int queryType)
{
    (void) m;
    (void) queryType;
}

mDNSexport void uDNS_StopWABQueries(mDNS *const m, int queryType)
{
    (void) m;
    (void) queryType;
}

mDNSexport void mDNS_AddDynDNSHostName(mDNS *m, const domainname *fqdn, mDNSRecordCallback *StatusCallback, const void *StatusContext)
{
    (void) m;
    (void) fqdn;
    (void) StatusCallback;
    (void) StatusContext;
}
mDNSexport void mDNS_SetPrimaryInterfaceInfo(mDNS *m, const mDNSAddr *v4addr, const mDNSAddr *v6addr, const mDNSAddr *router)
{
    (void) m;
    (void) v4addr;
    (void) v6addr;
    (void) router;
}

mDNSexport void mDNS_RemoveDynDNSHostName(mDNS *m, const domainname *fqdn)
{
    (void) m;
    (void) fqdn;
}

mDNSexport void RecreateNATMappings(mDNS *const m, const mDNSu32 waitTicks)
{
    (void) m;
    (void) waitTicks;
}

mDNSexport mDNSBool IsGetZoneDataQuestion(DNSQuestion *q)
{
    (void)q;

    return mDNSfalse;
}

mDNSexport void SubscribeToDNSPushServer(mDNS *m, DNSQuestion *q)
{
    (void)m;
    (void)q;
}

mDNSexport void UnsubscribeQuestionFromDNSPushServer(mDNS *m, DNSQuestion *q)
{
    (void)m;
    (void)q;
}

mDNSexport void DiscoverDNSPushServer(mDNS *m, DNSQuestion *q)
{
    (void)m;
    (void)q;
}

#endif // !UNICAST_DISABLED


// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
