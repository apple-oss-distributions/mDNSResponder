/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2011-2024 Apple Inc. All rights reserved.
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
 */

#include "dnsproxy.h"
#include "mrcs_dns_proxy.h"
#include "mrcs_server.h"
#include "mDNSMacOSX.h"
#include <AssertMacros.h>

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
#include <nw/private.h>
#endif

#include "mdns_strict.h"

#ifndef UNICAST_DISABLED

extern mDNS mDNSStorage;

// Implementation Notes
//
// DNS Proxy listens on port 53 (UDPv4v6 & TCPv4v6) for DNS queries. It handles only
// the "Query" opcode of the DNS protocol described in RFC 1035. For all other opcodes, it returns
// "Not Implemented" error. The platform interface mDNSPlatformInitDNSProxySkts
// sets up the sockets and whenever it receives a packet, it calls ProxyTCPCallback or ProxyUDPCallback
// defined here. For TCP socket, the platform does the "accept" and only sends the received packets
// on the newly accepted socket. A single UDP socket (per address family) is used to send/recv
// requests/responses from all clients. For TCP, there is one socket per request. Hence, there is some
// extra state that needs to be disposed at the end.
//
// When a DNS request is received, ProxyCallbackCommon checks for malformed packet etc. and also checks
// for duplicates, before creating DNSProxyClient state and starting a question with the "core"
// (mDNS_StartQuery). When the callback for the question happens, it gathers all the necessary
// resource records, constructs a response and sends it back to the client.
//
//   - Question callback is called with only one resource record at a time. We need all the resource
//     records to construct the response. Hence, we lookup all the records ourselves. 
//
//   - The response may not fit the client's buffer size. In that case, we need to set the truncate bit
//     and the client would retry using TCP.
//
//   - The client may have set the DNSSEC OK bit in the EDNS0 option and that means we also have to
//     return the RRSIGs or the NSEC records with the RRSIGs in the Additional section. We need to
//     ask the "core" to fetch the DNSSEC records and do the validation if the CD bit is not set.
//
// Once the response is sent to the client, the client state is disposed. When there is no response
// from the "core", it eventually times out and we will not find any answers in the cache and we send a
// "NXDomain" response back. Thus, we don't need any special timers to reap the client state in the case
// of errors. 

typedef struct DNSProxyClient_struct DNSProxyClient;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
typedef enum
{
    kDNSProxyDNS64State_Initial                 = 0,    // Initial state.
    kDNSProxyDNS64State_AAAASynthesis           = 1,    // Querying for A record for AAAA record synthesis.
    kDNSProxyDNS64State_PTRSynthesisTrying      = 2,    // Querying for in-addr.arpa PTR record to map from ip6.arpa PTR.
    kDNSProxyDNS64State_PTRSynthesisSuccess     = 3,    // in-addr.arpa PTR query got non-negative non-CNAME answer.
    kDNSProxyDNS64State_PTRSynthesisNXDomain    = 4     // in-addr.arpa PTR query produced no useful result.

}   DNSProxyDNS64State;
#endif

// Note: This needs to maintain compatibility with struct DNSMessage defined in mDNSEmbeddedAPI.h
typedef struct
{
    DNSMessageHeader h;             // Note: Size 12 bytes
    mDNSu8 data[];                  // Flexible storage. Start at NormalUDPDNSMessageData,
                                    // then try rcvBufSize if present or AbsoluteMaxDNSMessageData if tcp
} _DNSMessage;

struct DNSProxyClient_struct
{
    DNSProxyClient *next; 
    mDNSAddr    addr;               // Client's IP address 
    mDNSIPPort  port;               // Client's port number
    mDNSOpaque16 msgid;             // DNS msg id
    mDNSInterfaceID interfaceID;    // Interface on which we received the request
    void *socket;                   // Return socket
    mDNSBool tcp;                   // TCP or UDP ?
    mDNSOpaque16 requestFlags;      // second 16 bit word in the DNSMessageHeader of the request
    mDNSu8 *optRR;                  // EDNS0 option
    mDNSu32 optLen;                 // Total Length of the EDNS0 option
    mDNSu16 rcvBufSize;             // How much can the client receive ?
    void *context;                  // Platform context to be disposed if non-NULL
    domainname qname;               // q->qname can't be used for duplicate check
    DNSQuestion q;                  // as it can change underneath us for CNAMEs
    mDNSu16 qtype;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
    DNSProxyDNS64State dns64state;
#endif
    mDNSu8 *omsg_ptr;               // Where we are in the omsg->data
    mDNSu16 omsg_size;              // The current size of omsg->data
    _DNSMessage *omsg;              // Outgoing message we're building
    mrcs_dns_proxy_t proxy;         // A reference to the DNS proxy that this client request belongs to.
};

typedef struct
{
    DNSMessageHeader h;
    size_t omsg_offset;
} _MsgResourceState;

// 12 (DNS message header) + 500 (DNS message body) = 512 total
#define NormalUDPDNSMessageData 500

// OPT pseudo-resource record fixed-length fields without RDATA
// See <https://tools.ietf.org/html/rfc6891#section-6.1.2>
typedef struct
{
    mDNSu8 name[1];
    mDNSu8 type[2];
    mDNSu8 udpPayloadSize[2];
    mDNSu8 extendedRCode[1];
    mDNSu8 version[1];
    mDNSu8 extendedFlags[2];
    mDNSu8 rdLen[2];
} OPTRecordFixedFields;

extern int sizecheck_OPTRecordFixedFields[(sizeof(OPTRecordFixedFields) == 11) ? 1 : -1];

static DNSProxyClient *DNSProxyClients;

mDNSlocal void FreeDNSProxyClient(DNSProxyClient *pc)
{
    if (pc->optRR)
        mDNSPlatformMemFree(pc->optRR);
    if (pc->omsg)
        mDNSPlatformMemFree(pc->omsg);
    mrcs_forget(&pc->proxy);
    mDNSPlatformMemFree(pc);
}

mDNSlocal mDNSBool DNSProxyPrepareOmsg(const mDNSu16 size, DNSProxyClient *const pc)
{
    mDNSu32 allocation_size = sizeof(_DNSMessage) + size; // Handle values up to UINT16_MAX + sizeof(_DNSMessage)
    size_t offset = 0;
    if (!pc->omsg)
    {
        pc->omsg = mDNSPlatformMemAllocateClear(allocation_size);
        if (!pc->omsg)
        {
            return mDNSfalse;
        }
    }
    else
    {
        void * new_ptr = mDNSPlatformMemAllocateClear(allocation_size);
        if (!new_ptr)
        {
            return mDNSfalse;
        }
        offset = pc->omsg_ptr - pc->omsg->data;
        LogInfo("DNSProxyPrepareOmsg: Preserving offset %ld in size %d", offset, pc->omsg_size);
        memcpy(new_ptr, pc->omsg, MIN(sizeof(_DNSMessage) + pc->omsg_size, allocation_size));
        mDNSPlatformMemFree(pc->omsg);
        pc->omsg = new_ptr;
    }
    pc->omsg_size = size;
    pc->omsg_ptr = pc->omsg->data + offset;
    return mDNStrue;
}

mDNSlocal mDNSBool DNSProxyMsgCanGrow(const DNSProxyClient *const pc, mDNSu16 *out_size)
{
    mDNSu16 max_size;
    if (!pc->tcp)
    {
        if (!pc->rcvBufSize)
        {
            max_size = NormalUDPDNSMessageData;
        }
        else
        {
            mDNSu16 bufSize = (pc->rcvBufSize > sizeof(_DNSMessage)) ? (pc->rcvBufSize - sizeof(_DNSMessage)) : NormalUDPDNSMessageData;
            max_size = (bufSize > AbsoluteMaxDNSMessageData ? AbsoluteMaxDNSMessageData : bufSize);
        }
    }
    else
    {
        // For TCP, max_size is not determined by EDNS0 but by 16 bit rdlength field and
        // AbsoluteMaxDNSMessageData is smaller than 64k.
        max_size = AbsoluteMaxDNSMessageData;
    }
    if (out_size)
    {
        *out_size = max_size;
    }
    return (pc->omsg_size < max_size);
}

mDNSlocal void DNSMsgStateSave(const DNSProxyClient *const pc, _MsgResourceState *const state)
{
    mDNSPlatformMemCopy(&state->h, &pc->omsg->h, sizeof(DNSMessageHeader));
    state->omsg_offset = pc->omsg_ptr - pc->omsg->data;
}

mDNSlocal void DNSMsgStateRestore(DNSProxyClient *const pc, const _MsgResourceState *const state)
{
    mDNSPlatformMemCopy(&pc->omsg->h, &state->h, sizeof(DNSMessageHeader));
    pc->omsg_ptr = pc->omsg->data + state->omsg_offset;
}

mDNSexport mDNSu8 *DNSProxySetAttributes(DNSQuestion *q, DNSMessageHeader *h, DNSMessage *msg, mDNSu8 *ptr, mDNSu8 *limit)
{
    DNSProxyClient *pc = (DNSProxyClient *)q->QuestionContext;

    (void) msg;

    h->flags = pc->requestFlags;
    if (pc->optRR)
    {
        if (ptr + pc->optLen > limit)
        {
            LogInfo("DNSProxySetAttributes: Cannot set EDNS0 option start %p, OptLen %d, end %p", ptr, pc->optLen, limit);
            return ptr;
        }
        h->numAdditionals++;
        mDNSPlatformMemCopy(ptr, pc->optRR, pc->optLen);
        ptr += pc->optLen;
    }
    return ptr;
}

mDNSlocal mDNSu8 *AddEDNS0Option(_DNSMessage *const msg, mDNSu8 *ptr, mDNSu8 *limit)
{
    int len = 4096;

    if (ptr + 11 > limit)
    {
        LogInfo("AddEDNS0Option: not enough space");
        return mDNSNULL;
    }
    msg->h.numAdditionals++;
    ptr[0] = 0;
    ptr[1] = (mDNSu8) (kDNSType_OPT >> 8);
    ptr[2] = (mDNSu8) (kDNSType_OPT & 0xFF);
    ptr[3] = (mDNSu8) (len >> 8);
    ptr[4] = (mDNSu8) (len & 0xFF);
    ptr[5] = 0;     // rcode
    ptr[6] = 0;     // version
    ptr[7] = 0;
    ptr[8] = 0;     // flags
    ptr[9] = 0;     // rdlength
    ptr[10] = 0;    // rdlength

    LogInfo("AddEDNS0 option added to response");

    return (ptr + 11);
}

// Currently RD and CD bit should be copied if present in the request or cleared if
// not present in the request. RD bit is normally set in the response and hence the
// cache reflects the right value. CD bit behaves differently. If the CD bit is set
// the first time, the cache retains it, if it is present in response (assuming the
// upstream server does it right). Next time through we should not use the cached
// value of the CD bit blindly. It depends on whether it was in the request or not.
mDNSlocal mDNSOpaque16 SetResponseFlags(DNSProxyClient *pc, const mDNSOpaque16 responseFlags)
{
    mDNSOpaque16 rFlags = responseFlags;

    if (pc->requestFlags.b[0] & kDNSFlag0_RD)
        rFlags.b[0] |= kDNSFlag0_RD;
    else
        rFlags.b[0] &= ~kDNSFlag0_RD;

    if (pc->requestFlags.b[1] & kDNSFlag1_CD)
        rFlags.b[1] |= kDNSFlag1_CD;
    else
        rFlags.b[1] &= ~kDNSFlag1_CD;

    return rFlags;
}

mDNSlocal mDNSu8 *AddResourceRecord(DNSProxyClient *pc, mDNSu8 **prevptr, mStatus *error, mDNSBool final_answer)
{
    mDNS *const m = &mDNSStorage;
    CacheGroup *cg;
    CacheRecord *cr;
    int len = sizeof(DNSMessageHeader);
    mDNSu8 *ptr = mDNSNULL;
    mDNSs32 now;
    mDNSs32 ttl;
    const CacheRecord *soa = mDNSNULL;
    mDNSu8 *limit;

    *error = mStatus_NoError;
    *prevptr = mDNSNULL;

    mDNS_Lock(m);
    now = m->timenow;
    mDNS_Unlock(m);
    
    if (pc->tcp || !pc->rcvBufSize || pc->rcvBufSize > pc->omsg_size)
    {
        limit = pc->omsg->data + pc->omsg_size;
    }
    else
    {
        limit = pc->omsg->data + pc->rcvBufSize;
    }
    LogInfo("AddResourceRecord: Limit is %d", limit - pc->omsg_ptr);

    cg = CacheGroupForName(m, pc->q.qnamehash, &pc->q.qname);
    if (!cg)
    {
        LogInfo("AddResourceRecord: CacheGroup not found for %##s", pc->q.qname.c);
        *error = mStatus_NoSuchRecord;
        return mDNSNULL;
    }
    for (cr = cg->members; cr; cr = cr->next)
    {
        if (SameNameCacheRecordAnswersQuestion(cr, &pc->q))
        {
            if (pc->omsg->h.numQuestions == 0)
            {
                // If this is the first time, initialize the header and the question.
                // This code needs to be here so that we can use the responseFlags from the
                // cache record
                mDNSOpaque16 responseFlags = SetResponseFlags(pc, cr->responseFlags);
                InitializeDNSMessage(&pc->omsg->h, pc->msgid, responseFlags);
                ptr = putQuestion((DNSMessage*)pc->omsg, pc->omsg->data, limit, &pc->qname, pc->qtype, pc->q.qclass);
                if (!ptr)
                {
                    LogInfo("AddResourceRecord: putQuestion NULL for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
                    return mDNSNULL;
                }
                len += (ptr - pc->omsg_ptr);
                pc->omsg_ptr = ptr;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
                if (pc->dns64state == kDNSProxyDNS64State_PTRSynthesisSuccess)
                {
                    // For the first answer record, synthesize a CNAME record to map the originally requested ip6.arpa
                    // domain name to the in-addr.arpa domain name.
                    // See <https://tools.ietf.org/html/rfc6147#section-5.3.1>.
                    RData rdata;
                    ResourceRecord newRR;
                    mDNSPlatformMemZero(&newRR, (mDNSu32)sizeof(newRR));
                    newRR.RecordType    = kDNSRecordTypePacketAns;
                    newRR.rrtype        = kDNSType_CNAME;
                    newRR.rrclass       = kDNSClass_IN;
                    newRR.name          = &pc->qname;
                    AssignDomainName(&rdata.u.name, &pc->q.qname);
                    rdata.MaxRDLength   = (mDNSu32)sizeof(rdata.u);
                    newRR.rdata         = &rdata;
                    ptr = PutResourceRecordTTLWithLimit((DNSMessage*)pc->omsg, ptr, &pc->omsg->h.numAnswers, &newRR, 0, limit);
                    if (!ptr)
                    {
                        *prevptr = pc->omsg_ptr;
                        return mDNSNULL;
                    }
                    len += (ptr - pc->omsg_ptr);
                    pc->omsg_ptr = ptr;
                }
#endif
            }
            else if (!ptr)
            {
                ptr = pc->omsg_ptr;
            }
            // - For NegativeAnswers there is nothing to add
            // - If DNSSECOK is set, we also automatically lookup the RRSIGs which
            //   will also be returned. If the client is explicitly looking up
            //   a DNSSEC record (e.g., DNSKEY, DS) we should return the response.
            //   DNSSECOK bit only influences whether we add the RRSIG or not.
            mDNSBool addedCNAMERecord = mDNSfalse;
            if (cr->resrec.RecordType != kDNSRecordTypePacketNegative)
            {
                const ResourceRecord *rr;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
                RData rdata;
                ResourceRecord newRR;
                const nw_nat64_prefix_t *const nat64_prefix = mrcs_dns_proxy_get_nat64_prefix(pc->proxy);
                if (nat64_prefix && (pc->dns64state == kDNSProxyDNS64State_AAAASynthesis) && (cr->resrec.rrtype == kDNSType_A))
                {
                    struct in_addr  addrV4;
                    struct in6_addr addrV6;

                    newRR               = cr->resrec;
                    newRR.rrtype        = kDNSType_AAAA;
                    newRR.rdlength      = 16;
                    rdata.MaxRDLength   = newRR.rdlength;
                    newRR.rdata         = &rdata;

                    memcpy(&addrV4.s_addr, cr->resrec.rdata->u.ipv4.b, 4);
                    if (nw_nat64_synthesize_v6(nat64_prefix, &addrV4, &addrV6))
                    {
                        memcpy(rdata.u.ipv6.b, addrV6.s6_addr, 16);
                        rr = &newRR;
                    }
                    else
                    {
                        continue;
                    }
                }
                else
#endif
                {
                    rr = &cr->resrec;
                }
                LogInfo("AddResourceRecord: Answering question with %s", RRDisplayString(m, rr));
                ttl = cr->resrec.rroriginalttl - (now - cr->TimeRcvd) / mDNSPlatformOneSecond;
                ptr = PutResourceRecordTTLWithLimit((DNSMessage*)pc->omsg, ptr, &pc->omsg->h.numAnswers, rr, ttl, limit);
                if (!ptr)
                {
                    *prevptr = pc->omsg_ptr;
                    return mDNSNULL;
                }
                len += (ptr - pc->omsg_ptr);
                pc->omsg_ptr = ptr;
                if (cr->resrec.rrtype == kDNSType_CNAME)
                {
                    addedCNAMERecord = mDNStrue;
                }
            }
            if (cr->soa)
            {
                LogInfo("AddResourceRecord: soa set for %s", CRDisplayString(m ,cr));
                soa = cr->soa;
            }
            // If we are using CNAME to answer a question and CNAME is not the type we
            // are looking for, note down the CNAME record so that we can follow them
            // later. Before we follow the CNAME, print the RRSIGs and any nsec (wildcard
            // expanded) if any.
            if ((pc->q.qtype != cr->resrec.rrtype) && cr->resrec.rrtype == kDNSType_CNAME)
            {
                LogInfo("AddResourceRecord: cname set for %s", CRDisplayString(m ,cr));
            }
            // If a CNAME record was just added to the response for the current QNAME, break out of the for-loop.
            // As described in <https://datatracker.ietf.org/doc/html/rfc2181#section-10.1>, there cannot be more
            // than one CNAME record for a given domain name. This is a defensive measure because because it's
            // currently possible for two CNAME records with the same name to end up in mDNSResponder's cache.
            // To avoid "garbage in, garbage out", which can confuse clients, the DNS proxy shouldn't create
            // responses with multiple CNAME records with the same name. See rdar://117823387 for more details.
            if (addedCNAMERecord)
            {
                break;
            }
        }
    }
    // Along with the nsec records, we also cache the SOA record. For non-DNSSEC question, we need
    // to send the SOA back. Normally we either cache the SOA record (non-DNSSEC question) pointed
    // to by "cr->soa" or the NSEC/SOA records along with their RRSIGs (DNSSEC question) pointed to
    // by "cr->nsec". Two cases:
    //
    // - if we issue a DNSSEC question followed by non-DNSSEC question for the same name,
    //   we only have the nsec records and we need to filter the SOA record alone for the
    //   non-DNSSEC questions.
    //
    // - if we issue a non-DNSSEC question followed by DNSSEC question for the same name,
    //   the "core" flushes the cache entry and re-issue the question with EDNS0/DOK bit and
    //   in this case we return all the DNSSEC records we have.
    if (soa)
    {
        LogInfo("AddResourceRecord: SOA Answering question with %s", CRDisplayString(m, soa));
        ptr = PutResourceRecordTTLWithLimit((DNSMessage*)pc->omsg, ptr, &pc->omsg->h.numAuthorities, &soa->resrec, soa->resrec.rroriginalttl, limit);
        if (!ptr)
        {
            *prevptr = pc->omsg_ptr;
            return mDNSNULL;
        }
        len += (ptr - pc->omsg_ptr);
        pc->omsg_ptr = ptr;
    }
    if (!ptr)
    {
        LogInfo("AddResourceRecord: Did not find any valid ResourceRecords");
        *error = mStatus_NoSuchRecord;
        return mDNSNULL;
    }
    if (final_answer && pc->rcvBufSize)
    {
        ptr = AddEDNS0Option(pc->omsg, ptr, limit);
        if (!ptr)
        {
            *prevptr = pc->omsg_ptr;
            return mDNSNULL;
        }
        len += (ptr - pc->omsg_ptr);
        pc->omsg_ptr = ptr;
    }
    LogInfo("AddResourceRecord: Added %d bytes to the packet", len);
    return ptr;
}

mDNSlocal void ProxyClientCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    DNSProxyClient *pc = question->QuestionContext;
    DNSProxyClient **ppc = &DNSProxyClients;
    mDNSu8 *ptr;
    mDNSu8 *prevptr = mDNSNULL;
    mStatus error;
    mDNSBool final_answer = ((answer->RecordType == kDNSRecordTypePacketNegative) || (answer->rrtype == question->qtype));

    if (!AddRecord)
        return;

    LogInfo("ProxyClientCallback: %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
    if (mrcs_dns_proxy_get_nat64_prefix(pc->proxy))
    {
        if (pc->dns64state == kDNSProxyDNS64State_Initial)
        {
            // If we get a negative AAAA answer, then retry the query as an A record query.
            // See <https://tools.ietf.org/html/rfc6147#section-5.1.6>.
            if ((answer->RecordType == kDNSRecordTypePacketNegative) && (question->qtype == kDNSType_AAAA) &&
                (answer->rrtype == kDNSType_AAAA) && (answer->rrclass == kDNSClass_IN))
            {
                mDNS_StopQuery(m, question);
                pc->dns64state = kDNSProxyDNS64State_AAAASynthesis;
                question->qtype = kDNSType_A;
                mDNS_StartQuery(m, question);
                return;
            }
        }
        else if (pc->dns64state == kDNSProxyDNS64State_PTRSynthesisTrying)
        {
            // If we get a non-negative non-CNAME answer, then this is the answer we give to the client.
            // Otherwise, just respond with NXDOMAIN.
            // See <https://tools.ietf.org/html/rfc6147#section-5.3.1>.
            if ((answer->RecordType != kDNSRecordTypePacketNegative) && (question->qtype == kDNSType_PTR) &&
                (answer->rrtype == kDNSType_PTR) && (answer->rrclass == kDNSClass_IN))
            {
                pc->dns64state = kDNSProxyDNS64State_PTRSynthesisSuccess;
            }
            else
            {
                pc->dns64state = kDNSProxyDNS64State_PTRSynthesisNXDomain;
            }
        }
    }
    if (pc->dns64state == kDNSProxyDNS64State_PTRSynthesisNXDomain)
    {
        const mDNSOpaque16 flags = { { kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery, kDNSFlag1_RC_NXDomain } };
        InitializeDNSMessage(&pc->omsg->h, pc->msgid, flags);
        ptr = putQuestion((DNSMessage*)pc->omsg, pc->omsg->data, pc->omsg->data + pc->omsg_size, &pc->qname, pc->qtype,
            pc->q.qclass);
        if (!ptr)
        {
            LogInfo("ProxyClientCallback: putQuestion NULL for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
        }
    }
    else
#endif
    {
        for(;;)
        {
            _MsgResourceState save;
            DNSMsgStateSave(pc, &save);
            ptr = AddResourceRecord(pc, &prevptr, &error, final_answer);
            if (!ptr)
            {
                mDNSu16 max_size;
                if (DNSProxyMsgCanGrow(pc, &max_size))
                {
                    LogInfo("ProxyClientCallback: Increase omsg buffer size to %d for %##s (%s)", max_size, &pc->qname.c, DNSTypeName(pc->qtype));
                    if (!DNSProxyPrepareOmsg(max_size, pc))
                    {
                        LogMsg("ProxyClientCallback: AbsoluteMaxDNSMessageData memory failure for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
                    }
                    else
                    {
                        DNSMsgStateRestore(pc, &save);
                        continue;   // try again
                    }
                }
            }
            break;
        }
        if (!ptr)
        {
            LogInfo("ProxyClientCallback: AddResourceRecord NULL for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
            if (error == mStatus_NoError && prevptr)
            {
                // No space to add the record. Set the Truncate bit for UDP.
                //
                // TBD: For TCP, we need to send the rest of the data. But finding out what is left
                // is harder. We should allocate enough buffer in the first place to send all
                // of the data.
                if (!pc->tcp)
                {
                    pc->omsg->h.flags.b[0] |= kDNSFlag0_TC;
                    ptr = prevptr;
                }
                else
                {
                    LogInfo("ProxyClientCallback: ERROR!! Not enough space to return in TCP for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
                    ptr = prevptr;
                }
            }
            else
            {
                mDNSOpaque16 flags   = { { kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery, kDNSFlag1_RC_ServFail } };
                // We could not find the record for some reason. Return a response, so that the client
                // is not waiting forever.
                LogInfo("ProxyClientCallback: No response");
                if (!mDNSOpaque16IsZero(pc->q.responseFlags))
                    flags = pc->q.responseFlags;
                InitializeDNSMessage(&pc->omsg->h, pc->msgid, flags);
                ptr = putQuestion((DNSMessage*)pc->omsg, pc->omsg->data, pc->omsg->data + pc->omsg_size, &pc->qname, pc->qtype, pc->q.qclass);
                if (!ptr)
                {
                    LogInfo("ProxyClientCallback: putQuestion NULL for %##s (%s)", &pc->qname.c, DNSTypeName(pc->qtype));
                    goto done;
                }
            }
        }
        if (!final_answer)
        {
            // Wait till we get called for the real response
            LogInfo("ProxyClientCallback: Received %s, not answering yet", RRDisplayString(m, answer));
            return;
        }
    }
    debugf("ProxyClientCallback: InterfaceID is %p for response to client", pc->interfaceID);

    if (!pc->tcp)
    {
        mDNSSendDNSMessage(m, (DNSMessage*)pc->omsg, ptr, pc->interfaceID, mDNSNULL, (UDPSocket *)pc->socket, &pc->addr, pc->port, mDNSNULL, mDNSfalse);
    }
    else
    {
        mDNSSendDNSMessage(m, (DNSMessage*)pc->omsg, ptr, pc->interfaceID, (TCPSocket *)pc->socket, mDNSNULL, &pc->addr, pc->port, mDNSNULL, mDNSfalse);
    }

done:
    mDNS_StopQuery(m, question);

    while (*ppc && *ppc != pc)
        ppc=&(*ppc)->next;
    if (!*ppc)
    {
        LogMsg("ProxyClientCallback: question %##s (%s) not found", question->qname.c, DNSTypeName(question->qtype));
        return;
    }
    *ppc = pc->next;
    mDNSPlatformDisposeProxyContext(pc->context);
    FreeDNSProxyClient(pc);
}

mDNSlocal void SendError(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *dstaddr,
    const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, mDNSBool tcp, void *context, mDNSu8 rcode)
{
    mDNS *const m = &mDNSStorage;
    int pktlen = (int)(end - (mDNSu8 *)msg);

    // RFC 1035 requires that we copy the question back and RFC 2136 is okay with sending nothing
    // in the body or send back whatever we get for updates. It is easy to return whatever we get
    // in the question back to the responder. We return as much as we can fit in our standard
    // output packet.
    if (pktlen > AbsoluteMaxDNSMessageData)
        pktlen = AbsoluteMaxDNSMessageData;

    mDNSPlatformMemCopy(&m->omsg.h, &msg->h, sizeof(DNSMessageHeader));
    m->omsg.h.flags.b[0] |= kDNSFlag0_QR_Response;
    m->omsg.h.flags.b[1] = rcode;
    mDNSPlatformMemCopy(m->omsg.data, (mDNSu8 *)&msg->data, (pktlen - sizeof(DNSMessageHeader)));
    
    if (!tcp)
    {
        mDNSSendDNSMessage(m, &m->omsg, (mDNSu8 *)&m->omsg + pktlen, InterfaceID, mDNSNULL, socket, dstaddr, dstport, mDNSNULL, mDNSfalse);
    }
    else
    {
        mDNSSendDNSMessage(m, &m->omsg, (mDNSu8 *)&m->omsg + pktlen, InterfaceID, (TCPSocket *)socket, mDNSNULL, dstaddr, dstport, mDNSNULL, mDNSfalse);
    }
    mDNSPlatformDisposeProxyContext(context);
}

mDNSlocal DNSQuestion *IsDuplicateClient(const mDNSAddr *const addr, const mDNSIPPort port, const mDNSOpaque16 id,
    const DNSQuestion *const question)
{
    DNSProxyClient *pc;

    for (pc = DNSProxyClients; pc; pc = pc->next)
    {
        if (mDNSSameAddress(&pc->addr, addr)   &&
            mDNSSameIPPort(pc->port, port)  &&
            mDNSSameOpaque16(pc->msgid, id) &&
            pc->qtype == question->qtype  &&
            pc->q.qclass  == question->qclass &&
            SameDomainName(&pc->qname, &question->qname))
        {
            LogInfo("IsDuplicateClient: Found a duplicate client in the list");
            return(&pc->q);
        }
    }
    return(mDNSNULL);
}

static mrcs_dns_proxy_manager_t gProxyManager = mDNSNULL;

mDNSlocal mrcs_dns_proxy_t DNSProxyGetDNSProxyInstance(mDNSInterfaceID InterfaceID)
{
    const mDNSu32 index = (mDNSu32)(uintptr_t)InterfaceID;
    return (gProxyManager ? mrcs_dns_proxy_manager_get_proxy_by_input_interface(gProxyManager, index) : mDNSNULL);
}

mDNSlocal void ProxyCallbackCommon(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr,
    const mDNSIPPort srcport, const mDNSAddr *dstaddr, const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, mDNSBool tcp, void *context)
{
    mDNS *const m = &mDNSStorage;
    mDNSu8 QR_OP;
    const mDNSu8 *ptr;
    DNSQuestion q, *qptr;
    DNSProxyClient *pc;
    const mDNSu8 *optRR = mDNSNULL;
    mDNSu32 optLen = 0;
    DNSProxyClient **ppc = &DNSProxyClients;

    (void) dstaddr;
    (void) dstport;

    debugf("ProxyCallbackCommon: DNS Query coming from InterfaceID %p", InterfaceID);
    // Ignore if the DNS Query is not from a Valid Input InterfaceID
    const mrcs_dns_proxy_t proxy = DNSProxyGetDNSProxyInstance(InterfaceID);
    if (!proxy)
    {
        LogMsg("ProxyCallbackCommon: Rejecting DNS Query coming from InterfaceID %p", InterfaceID);
        return;
    }
    
    if ((unsigned)(end - (mDNSu8 *)msg) < sizeof(DNSMessageHeader))
    {
        debugf("ProxyCallbackCommon: DNS Message from %#a:%d to %#a:%d length %d too short", srcaddr, mDNSVal16(srcport), dstaddr, mDNSVal16(dstport), (int)(end - (mDNSu8 *)msg));
        return;
    }

    // Read the integer parts which are in IETF byte-order (MSB first, LSB second)
    ptr = (mDNSu8 *)&msg->h.numQuestions;
    msg->h.numQuestions   = (mDNSu16)((mDNSu16)ptr[0] << 8 | ptr[1]);
    msg->h.numAnswers     = (mDNSu16)((mDNSu16)ptr[2] << 8 | ptr[3]);
    msg->h.numAuthorities = (mDNSu16)((mDNSu16)ptr[4] << 8 | ptr[5]);
    msg->h.numAdditionals = (mDNSu16)((mDNSu16)ptr[6] << 8 | ptr[7]);

    QR_OP = (mDNSu8)(msg->h.flags.b[0] & kDNSFlag0_QROP_Mask);
    if (QR_OP != kDNSFlag0_QR_Query)
    {
        LogInfo("ProxyCallbackCommon: Not a query(%d) for pkt from %#a:%d", QR_OP, srcaddr, mDNSVal16(srcport));
        SendError(socket, msg, end, srcaddr, srcport, InterfaceID, tcp, context, kDNSFlag1_RC_NotImpl);
        return;
    }
    
    if (msg->h.numQuestions != 1 || msg->h.numAnswers || msg->h.numAuthorities)
    {
        LogInfo("ProxyCallbackCommon: Malformed pkt from %#a:%d, Q:%d, An:%d, Au:%d", srcaddr, mDNSVal16(srcport),
            msg->h.numQuestions, msg->h.numAnswers, msg->h.numAuthorities);
        SendError(socket, msg, end, srcaddr, srcport, InterfaceID, tcp, context, kDNSFlag1_RC_FormErr);
        return;
    }
    ptr = msg->data;
    ptr = getQuestion(msg, ptr, end, InterfaceID, &q);
    if (!ptr)
    {
        LogInfo("ProxyCallbackCommon: Question cannot be parsed for pkt from %#a:%d", srcaddr, mDNSVal16(srcport));
        SendError(socket, msg, end, srcaddr, srcport, InterfaceID, tcp, context, kDNSFlag1_RC_FormErr);
        return;
    }
    else
    {
        LogInfo("ProxyCallbackCommon: Question %##s (%s)", q.qname.c, DNSTypeName(q.qtype));
    }
    ptr = LocateOptRR(msg, end, 0);
    if (ptr)
    {
        optRR = ptr;
        ptr = skipResourceRecord(msg, ptr, end);
        // Be liberal and ignore the EDNS0 option if we can't parse it properly
        if (!ptr)
        {
            LogInfo("ProxyCallbackCommon: EDNS0 cannot be parsed for pkt from %#a:%d, ignoring", srcaddr, mDNSVal16(srcport));
        }
        else
        {
            optLen = (mDNSu32)(ptr - optRR);
            LogInfo("ProxyCallbackCommon: EDNS0 opt length %u present in Question %##s (%s)", optLen, q.qname.c, DNSTypeName(q.qtype));
        }
    }
    else
    {
        LogInfo("ProxyCallbackCommon: EDNS0 opt not present in Question %##s (%s), ptr %p", q.qname.c, DNSTypeName(q.qtype), ptr);
    }
        
    qptr = IsDuplicateClient(srcaddr, srcport, msg->h.id, &q);
    if (qptr)
    {
        LogInfo("ProxyCallbackCommon: Found a duplicate for pkt from %#a:%d, ignoring this", srcaddr, mDNSVal16(srcport));
        return;
    }
    pc = (DNSProxyClient *) mDNSPlatformMemAllocateClear(sizeof(*pc));
    if (!pc)
    {
        LogMsg("ProxyCallbackCommon: Memory failure for pkt from %#a:%d, ignoring this", srcaddr, mDNSVal16(srcport));
        return;
    }
    if (!DNSProxyPrepareOmsg(NormalUDPDNSMessageData, pc))
    {
        LogMsg("ProxyCallbackCommon: NormalUDPDNSMessageData memory failure for pkt from %#a:%d, ignoring this", srcaddr, mDNSVal16(srcport));
        FreeDNSProxyClient(pc);
        return;
    }
    pc->proxy = proxy;
    mrcs_retain(pc->proxy);
    pc->addr = *srcaddr;
    pc->port = srcport;
    pc->msgid = msg->h.id;
    pc->interfaceID = InterfaceID; // input interface 
    pc->socket = socket;
    pc->tcp = tcp;
    pc->requestFlags = msg->h.flags;
    pc->context = context;
    AssignDomainName(&pc->qname, &q.qname);
    if (optRR)
    {
        if (optLen < sizeof(OPTRecordFixedFields))
        {
            LogInfo("ProxyCallbackCommon: Invalid EDNS0 option for pkt from %#a:%d, ignoring this", srcaddr, mDNSVal16(srcport));
        }
        else
        {
            const OPTRecordFixedFields *const fields = (const OPTRecordFixedFields *)optRR;
            pc->rcvBufSize = (mDNSu16)((fields->udpPayloadSize[0] << 8) | fields->udpPayloadSize[1]);
            pc->optRR = (mDNSu8 *) mDNSPlatformMemAllocate(optLen);
            if (!pc->optRR)
            {
                LogMsg("ProxyCallbackCommon: Memory failure for pkt from %#a:%d, ignoring this", srcaddr, mDNSVal16(srcport));
                FreeDNSProxyClient(pc);
                return;
            }
            mDNSPlatformMemCopy(pc->optRR, optRR, optLen);
            pc->optLen = optLen;
        }
    }

    const mDNSu32 outputIndex = mrcs_dns_proxy_get_output_interface(pc->proxy);
    debugf("ProxyCallbackCommon: DNS Query forwarding to interface index %u", outputIndex);
    mDNS_SetupQuestion(&pc->q, (mDNSInterfaceID)(unsigned long)outputIndex, &q.qname, q.qtype, ProxyClientCallback, pc);
    pc->q.TimeoutQuestion = 1;
    // Set ReturnIntermed so that we get the negative responses
    pc->q.ReturnIntermed  = mDNStrue;
    pc->q.ProxyQuestion   = mDNStrue;
    pc->q.responseFlags   = zeroID;
    pc->q.euid            = mrcs_dns_proxy_get_euid(pc->proxy);
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
    pc->qtype = pc->q.qtype;
    const nw_nat64_prefix_t * const nat64_prefix = mrcs_dns_proxy_get_nat64_prefix(pc->proxy);
    if (nat64_prefix)
    {
        if (pc->qtype == kDNSType_PTR)
        {
            struct in6_addr v6Addr;
            struct in_addr v4Addr;
            if (GetReverseIPv6Addr(&pc->qname, v6Addr.s6_addr) && nw_nat64_extract_v4(nat64_prefix, &v6Addr, &v4Addr))
            {
                const mDNSu8 *const a = (const mDNSu8 *)&v4Addr.s_addr;
                char qnameStr[MAX_REVERSE_MAPPING_NAME_V4];
                mDNS_snprintf(qnameStr, (mDNSu32)sizeof(qnameStr), "%u.%u.%u.%u.in-addr.arpa.", a[3], a[2], a[1], a[0]);
                MakeDomainNameFromDNSNameString(&pc->q.qname, qnameStr);
                pc->q.qnamehash = DomainNameHashValue(&pc->q.qname);
                pc->dns64state = kDNSProxyDNS64State_PTRSynthesisTrying;
            }
        }
        else if ((pc->qtype == kDNSType_AAAA) && mrcs_dns_proxy_forces_aaaa_synthesis(pc->proxy))
        {
            pc->dns64state = kDNSProxyDNS64State_AAAASynthesis;
            pc->q.qtype    = kDNSType_A;
        }
    }
#endif

    while (*ppc)
        ppc = &((*ppc)->next);
    *ppc = pc;

    mDNS_StartQuery(m, &pc->q);
}

mDNSexport void ProxyUDPCallback(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr,
    const mDNSIPPort srcport, const mDNSAddr *dstaddr, const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, void *context)
{
    LogInfo("ProxyUDPCallback: DNS Message from %#a:%d to %#a:%d length %d", srcaddr, mDNSVal16(srcport), dstaddr, mDNSVal16(dstport), (int)(end - (mDNSu8 *)msg));
    ProxyCallbackCommon(socket, msg, end, srcaddr, srcport, dstaddr, dstport, InterfaceID, mDNSfalse, context);
}

mDNSexport void ProxyTCPCallback(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr,
    const mDNSIPPort srcport, const mDNSAddr *dstaddr, const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, void *context)
{
    LogInfo("ProxyTCPCallback: DNS Message from %#a:%d to %#a:%d length %d", srcaddr, mDNSVal16(srcport), dstaddr, mDNSVal16(dstport), (int)(end - (mDNSu8 *)msg));
    
    // If the connection was closed from the other side or incoming packet does not match stored input interface list, locate the client
    // state and free it.
    if (((end - (mDNSu8 *)msg) == 0) || (!DNSProxyGetDNSProxyInstance(InterfaceID)))
    {
        DNSProxyClient **ppc = &DNSProxyClients;
        DNSProxyClient **prevpc;

        prevpc = ppc;
        while (*ppc && (*ppc)->socket != socket)
        {
            prevpc = ppc;
            ppc=&(*ppc)->next;
        }
        if (!*ppc)
        {
            mDNSPlatformDisposeProxyContext(socket);
            LogMsg("ProxyTCPCallback: socket cannot be found");
            return;
        }
        *prevpc = (*ppc)->next;
        LogInfo("ProxyTCPCallback: free");
        mDNSPlatformDisposeProxyContext(socket);
        FreeDNSProxyClient(*ppc);
        return;
    }
    ProxyCallbackCommon(socket, msg, end, srcaddr, srcport, dstaddr, dstport, InterfaceID, mDNStrue, context);
}

mDNSlocal OSStatus DNSProxyStart(const mrcs_dns_proxy_t proxy)
{
    OSStatus err;
    if (!gProxyManager)
    {
        gProxyManager = mrcs_dns_proxy_manager_create(&err);
        require_noerr_quiet(err, exit);
    }
    const size_t previousCount = mrcs_dns_proxy_manager_get_count(gProxyManager);
    err = mrcs_dns_proxy_manager_add_proxy(gProxyManager, proxy);
    if (previousCount == 0)
    {
        if (mrcs_dns_proxy_manager_get_count(gProxyManager) > 0)
        {
            mDNSPlatformInitDNSProxySkts(ProxyUDPCallback, ProxyTCPCallback);
        }
    }

exit:
    return err;
}

mDNSlocal OSStatus DNSProxyStop(const mrcs_dns_proxy_t proxy)
{
    OSStatus err;
    require_action_quiet(gProxyManager, exit, err = mStatus_BadStateErr);

    const size_t previousCount = mrcs_dns_proxy_manager_get_count(gProxyManager);
    err = mrcs_dns_proxy_manager_remove_proxy(gProxyManager, proxy);
    require_noerr_quiet(err, exit);

    if (previousCount > 0)
    {
        if (mrcs_dns_proxy_manager_get_count(gProxyManager) == 0)
        {
            mDNSPlatformCloseDNSProxySkts(&mDNSStorage);
        }
    }

exit:
    return err;
}

static mrcs_dns_proxy_t gLegacyProxy = mDNSNULL;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
mDNSexport void DNSProxyInit(mDNSu32 IpIfArr[MaxIp], mDNSu32 OpIf, const mDNSu8 IPv6Prefix[16], int IPv6PrefixBitLen,
                             mDNSBool forceAAAASynthesis)
#else
mDNSexport void DNSProxyInit(mDNSu32 IpIfArr[MaxIp], mDNSu32 OpIf)
#endif
{
    if (gLegacyProxy)
    {
        return;
    }
    gLegacyProxy = mrcs_dns_proxy_create(NULL);
    if (!gLegacyProxy)
    {
        return;
    }
    for (int i = 0; i < MaxIp; ++i)
    {
        mrcs_dns_proxy_add_input_interface(gLegacyProxy, IpIfArr[i]);
    }
    mrcs_dns_proxy_set_output_interface(gLegacyProxy, OpIf);

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PROXY_DNS64)
    if (IPv6Prefix)
    {
        const OSStatus err = mrcs_dns_proxy_set_nat64_prefix(gLegacyProxy, IPv6Prefix, IPv6PrefixBitLen);
        if (!err)
        {
            mrcs_dns_proxy_enable_force_aaaa_synthesis(gLegacyProxy, forceAAAASynthesis ? true : false);
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "DNSProxy using DNS64 IPv6 prefix: " PRI_IPv6_ADDR "/%d" PUB_S,
                IPv6Prefix, IPv6PrefixBitLen, forceAAAASynthesis ? "" : " (force AAAA synthesis)");
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "DNSProxy not using invalid DNS64 IPv6 prefix: " PRI_IPv6_ADDR "/%d", IPv6Prefix, IPv6PrefixBitLen);
        }
    }
#endif
    DNSProxyStart(gLegacyProxy);
}

mDNSexport void DNSProxyTerminate(void)
{
    if (gLegacyProxy)
    {
        DNSProxyStop(gLegacyProxy);
        mrcs_forget(&gLegacyProxy);
    }
}

mDNSlocal OSStatus DNSProxyStartHandler(const mrcs_dns_proxy_t proxy)
{
    KQueueLock();
    const OSStatus err = DNSProxyStart(proxy);
    KQueueUnlock("DNSProxyStartHandler");
    return err;
}

mDNSlocal OSStatus DNSProxyStopHandler(const mrcs_dns_proxy_t proxy)
{
    KQueueLock();
    const OSStatus err = DNSProxyStop(proxy);
    KQueueUnlock("DNSProxyStopHandler");
    return err;
}

mDNSlocal char *DNSProxyGetState(void)
{
    char *state;
    if (gProxyManager && (mrcs_dns_proxy_manager_get_count(gProxyManager) > 0))
    {
        state = mrcs_copy_description(gProxyManager);
    }
    else
    {
        state = mdns_strdup("‹No DNS Proxies›");
    }
    return state;
}

mDNSlocal char *DNSProxyGetStateHandler(void)
{
    KQueueLock();
    char *state = DNSProxyGetState();
    KQueueUnlock("DNSProxyGetStateHandler");
    return state;
}

const struct mrcs_server_dns_proxy_handlers_s kMRCSServerDNSProxyHandlers =
{
    .start = DNSProxyStartHandler,
    .stop = DNSProxyStopHandler,
    .get_state = DNSProxyGetStateHandler
};

#else // UNICAST_DISABLED

mDNSexport void ProxyUDPCallback(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr, const mDNSIPPort srcport, const mDNSAddr *dstaddr, const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, void *context)
{
    (void) socket;
    (void) msg;
    (void) end;
    (void) srcaddr;
    (void) srcport;
    (void) dstaddr;
    (void) dstport;
    (void) InterfaceID;
    (void) context;
}

mDNSexport void ProxyTCPCallback(void *socket, DNSMessage *const msg, const mDNSu8 *const end, const mDNSAddr *const srcaddr, const mDNSIPPort srcport, const mDNSAddr *dstaddr, const mDNSIPPort dstport, const mDNSInterfaceID InterfaceID, void *context)
{
    (void) socket;
    (void) msg;
    (void) end;
    (void) srcaddr;
    (void) srcport;
    (void) dstaddr;
    (void) dstport;
    (void) InterfaceID;
    (void) context;
}

mDNSexport void DNSProxyInit(mDNSu32 IpIfArr[MaxIp], mDNSu32 OpIf)
{
    (void) IpIfArr;
    (void) OpIf;
}
extern void DNSProxyTerminate(void)
{
}


#endif // UNICAST_DISABLED
