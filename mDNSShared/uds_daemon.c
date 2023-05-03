/*
 * Copyright (c) 2003-2022 Apple Inc. All rights reserved.
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

#if defined(_WIN32)
#include <process.h>
#define usleep(X) Sleep(((X)+999)/1000)
#else
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <stdlib.h>
#include <stdio.h>

#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "uDNS.h"
#include "uds_daemon.h"
#include "dns_sd_internal.h"

// Apple-specific functionality, not required for other platforms

#ifdef LOCAL_PEEREPID
#include <sys/un.h>         // for LOCAL_PEEREPID
#include <sys/socket.h>     // for getsockopt
#endif //LOCAL_PEEREPID

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
#include "D2D.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
#include "mDNSMacOSX.h"
#include <os/feature_private.h>
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
#include <mdns/signed_result.h>
#include <mdns/system.h>
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
#include <bsm/libbsm.h>
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSD_XPC_SERVICE)
#include "dnssd_server.h"
#endif

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
#include "discover_resolver.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
#include "resolved_cache.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)
#include "dns_sd_internal.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY)
#include "cf_support.h"
#include "misc_utilities.h"
#include "system_utilities.h"
#endif

#include "mdns_strict.h"

// User IDs 0-500 are system-wide processes, not actual users in the usual sense
// User IDs for real user accounts start at 501 and count up from there
#define SystemUID(X) ((X) <= 500)

// ***************************************************************************
// MARK: - Globals

// globals
mDNSexport mDNS mDNSStorage;
mDNSexport const char ProgramName[] = "mDNSResponder";

#if defined(USE_TCP_LOOPBACK)
static char* boundPath = NULL;
#else
static char* boundPath = MDNS_UDS_SERVERPATH;
#endif
#if DEBUG
#define MDNS_UDS_SERVERPATH_DEBUG "/var/tmp/mDNSResponder"
#endif
static dnssd_sock_t listenfd = dnssd_InvalidSocket;
static request_state *all_requests = NULL;
mDNSlocal void set_peer_pid(request_state *request);
mDNSlocal void LogMcastClientInfo(request_state *req);
mDNSlocal void GetMcastClients(request_state *req);
mDNSlocal mStatus update_record(AuthRecord *ar, mDNSu16 rdlen, const mDNSu8 *rdata, mDNSu32 ttl,
    const mDNSBool *external_advertise, mDNSu32 request_id);
static mDNSu32 mcount;     // tracks the current active mcast operations for McastLogging
static mDNSu32 i_mcount;   // sets mcount when McastLogging is enabled(PROF signal is sent)
static mDNSu32 n_mrecords; // tracks the current active mcast records for McastLogging
static mDNSu32 n_mquests;  // tracks the current active mcast questions for McastLogging


// Note asymmetry here between registration and browsing.
// For service registrations we only automatically register in domains that explicitly appear in local configuration data
// (so AutoRegistrationDomains could equally well be called SCPrefRegDomains)
// For service browsing we also learn automatic browsing domains from the network, so for that case we have:
// 1. SCPrefBrowseDomains (local configuration data)
// 2. LocalDomainEnumRecords (locally-generated local-only PTR records -- equivalent to slElem->AuthRecs in uDNS.c)
// 3. AutoBrowseDomains, which is populated by tracking add/rmv events in AutomaticBrowseDomainChange, the callback function for our mDNS_GetDomains call.
// By creating and removing our own LocalDomainEnumRecords, we trigger AutomaticBrowseDomainChange callbacks just like domains learned from the network would.

mDNSexport DNameListElem *AutoRegistrationDomains;  // Domains where we automatically register for empty-string registrations

static DNameListElem *SCPrefBrowseDomains;          // List of automatic browsing domains read from SCPreferences for "empty string" browsing
static ARListElem    *LocalDomainEnumRecords;       // List of locally-generated PTR records to augment those we learn from the network
mDNSexport DNameListElem *AutoBrowseDomains;        // List created from those local-only PTR records plus records we get from the network

#define MSG_PAD_BYTES 5     // pad message buffer (read from client) with n zero'd bytes to guarantee
                            // n get_string() calls w/o buffer overrun
// initialization, setup/teardown functions

// If a platform specifies its own PID file name, we use that
#ifndef NO_PID_FILE
    #ifndef PID_FILE
    #define PID_FILE "/var/run/mDNSResponder.pid"
    #endif
#endif

#ifndef NORETURN_ATTRIBUTE
#if defined(__GNUC__) && ((__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1 )))
#define NORETURN_ATTRIBUTE __attribute__((noreturn))
#else
#define NORETURN_ATTRIBUTE
#endif
#endif

// ***************************************************************************
// MARK: - General Utility Functions

mDNSlocal mDNSu32 GetNewRequestID(void)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSD_XPC_SERVICE)
    return dnssd_server_get_new_request_id();
#else
    static mDNSu32 s_last_id = 0;
    return ++s_last_id;
#endif
}

NORETURN_ATTRIBUTE
mDNSlocal void FatalError(char *errmsg)
{
    LogMsg("%s: %s", errmsg, dnssd_strerror(dnssd_errno));
    abort();
}

mDNSlocal mDNSu32 dnssd_htonl(mDNSu32 l)
{
    mDNSu32 ret;
    uint8_t *data = (uint8_t *)&ret;
    put_uint32(l, &data);
    return ret;
}

// hack to search-replace perror's to LogMsg's
mDNSlocal void my_perror(char *errmsg)
{
    LogMsg("%s: %d (%s)", errmsg, dnssd_errno, dnssd_strerror(dnssd_errno));
}

// Throttled version of my_perror: Logs once every 250 msgs
mDNSlocal void my_throttled_perror(char *err_msg)
{
    static int uds_throttle_count = 0;
    if ((uds_throttle_count++ % 250) == 0)
        my_perror(err_msg);
}

// LogMcastQuestion/LogMcastQ should be called after the DNSQuestion struct is initialized(especially for q->TargetQID)
// Hence all calls are made after mDNS_StartQuery()/mDNS_StopQuery()/mDNS_StopBrowse() is called.
mDNSlocal void LogMcastQuestion(const DNSQuestion *const q, request_state *req, q_state status)
{
    if (mDNSOpaque16IsZero(q->TargetQID)) // Check for Mcast Query
    {
        mDNSBool mflag = mDNSfalse;
        if (status == q_start)
        {
            if (++mcount == 1)
                mflag = mDNStrue;
        }
        else
        {
            mcount--;
        }
        LogMcast("%s: %##s  (%s) (%s)  Client(%d)[%s]", status ? "+Question" : "-Question", q->qname.c, DNSTypeName(q->qtype),
                 q->InterfaceID == mDNSInterface_LocalOnly ? "lo" :
                 q->InterfaceID == mDNSInterface_P2P ? "p2p" :
                 q->InterfaceID == mDNSInterface_BLE ? "BLE" :
                 q->InterfaceID == mDNSInterface_Any ? "any" : InterfaceNameForID(&mDNSStorage, q->InterfaceID),
                 req->process_id, req->pid_name);
        LogMcastStateInfo(mflag, mDNSfalse, mDNSfalse);
    }
    return;
}

// LogMcastService/LogMcastS should be called after the AuthRecord struct is initialized
// Hence all calls are made after mDNS_Register()/ just before mDNS_Deregister()
mDNSlocal void LogMcastService(const AuthRecord *const ar, request_state *req, reg_state status)
{
    if (!AuthRecord_uDNS(ar)) // Check for Mcast Service
    {
        mDNSBool mflag = mDNSfalse;
        if (status == reg_start)
        {
            if (++mcount == 1)
                mflag = mDNStrue;
        }
        else
        {
            mcount--;
        }
        LogMcast("%s: %##s  (%s)  (%s)  Client(%d)[%s]", status ? "+Service" : "-Service", ar->resrec.name->c, DNSTypeName(ar->resrec.rrtype),
                 ar->resrec.InterfaceID == mDNSInterface_LocalOnly ? "lo" :
                 ar->resrec.InterfaceID == mDNSInterface_P2P ? "p2p" :
                 ar->resrec.InterfaceID == mDNSInterface_BLE ? "BLE" :
                 ar->resrec.InterfaceID == mDNSInterface_Any ? "all" : InterfaceNameForID(&mDNSStorage, ar->resrec.InterfaceID),
                 req->process_id, req->pid_name);
        LogMcastStateInfo(mflag, mDNSfalse, mDNSfalse);
    }
    return;
}

// For complete Mcast State Log, pass mDNStrue to mstatelog in LogMcastStateInfo()
mDNSexport void LogMcastStateInfo(mDNSBool mflag, mDNSBool start, mDNSBool mstatelog)
{
    mDNS *const m = &mDNSStorage;
    if (!mstatelog)
    {
        if (!all_requests)
        {
            LogMcastNoIdent("<None>");
        }
        else
        {
            request_state *req, *r;
            for (req = all_requests; req; req=req->next)
            {
                if (req->primary) // If this is a subbordinate operation, check that the parent is in the list
                {
                    for (r = all_requests; r && r != req; r=r->next)
                        if (r == req->primary)
                            goto foundpar;
                }
                // For non-subbordinate operations, and subbordinate operations that have lost their parent, write out their info
                GetMcastClients(req);
    foundpar:;
            }
            LogMcastNoIdent("--- MCAST RECORDS COUNT[%d] MCAST QUESTIONS COUNT[%d] ---", n_mrecords, n_mquests);
            n_mrecords = n_mquests = 0; // Reset the values
        }
    }
    else
    {
        static mDNSs32 i_mpktnum;
        i_mcount = 0;
        if (start)
            mcount = 0;
        // mcount is initialized to 0 when the PROF signal is sent since mcount could have
        // wrong value if MulticastLogging is disabled and then re-enabled
        LogMcastNoIdent("--- START MCAST STATE LOG ---");
        if (!all_requests)
        {
            mcount = 0;
            LogMcastNoIdent("<None>");
        }
        else
        {
            request_state *req, *r;
            for (req = all_requests; req; req=req->next)
            {
                if (req->primary) // If this is a subbordinate operation, check that the parent is in the list
                {
                    for (r = all_requests; r && r != req; r=r->next)
                        if (r == req->primary)
                            goto foundparent;
                    LogMcastNoIdent("%3d: Orphan operation; parent not found in request list", req->sd);
                }
                // For non-subbordinate operations, and subbordinate operations that have lost their parent, write out their info
                LogMcastClientInfo(req);
    foundparent:;
            }
            if(!mcount) // To initially set mcount
                mcount = i_mcount;
        }
        if (mcount == 0)
        {
            i_mpktnum = m->MPktNum;
            LogMcastNoIdent("--- MCOUNT[%d]: IMPKTNUM[%d] ---", mcount, i_mpktnum);
        }
        if (mflag)
            LogMcastNoIdent("--- MCOUNT[%d]: CMPKTNUM[%d] - IMPKTNUM[%d] = [%d]PKTS ---", mcount, m->MPktNum, i_mpktnum, (m->MPktNum - i_mpktnum));
        LogMcastNoIdent("--- END MCAST STATE LOG ---");
    }
}

mDNSlocal void abort_request(request_state *req)
{
    if (req->terminate == (req_termination_fn) ~0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%d] abort_request: ERROR: Attempt to abort operation %p with req->terminate %p", req->request_id, req, req->terminate);
        return;
    }

    // First stop whatever mDNSCore operation we were doing
    // If this is actually a shared connection operation, then its req->terminate function will scan
    // the all_requests list and terminate any subbordinate operations sharing this file descriptor
    if (req->terminate) req->terminate(req);
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    if (req->custom_service_id != 0)
    {
        Querier_DeregisterCustomDNSService(req->custom_service_id);
        req->custom_service_id = 0;
    }
#endif

    if (!dnssd_SocketValid(req->sd))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%d] abort_request: ERROR: Attempt to abort operation %p with invalid fd %d", req->request_id, req, req->sd);
        return;
    }

    // Now, if this request_state is not subordinate to some other primary, close file descriptor and discard replies
    if (!req->primary)
    {
        if (req->errsd != req->sd)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                      "[R%d] Removing FD %d and closing errsd %d", req->request_id, req->sd, req->errsd);
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                      "[R%d] Removing FD %d", req->request_id, req->sd);
        }
        udsSupportRemoveFDFromEventLoop(req->sd, req->platform_data);       // Note: This also closes file descriptor req->sd for us
        if (req->errsd != req->sd) { dnssd_close(req->errsd); req->errsd = req->sd; }

        while (req->replies)    // free pending replies
        {
            reply_state *ptr = req->replies;
            req->replies = req->replies->next;
            freeL("reply_state (abort)", ptr);
        }
    }

    // Set req->sd to something invalid, so that udsserver_idle knows to unlink and free this structure
#if MDNS_MALLOC_DEBUGGING
    // Don't use dnssd_InvalidSocket (-1) because that's the sentinel value MDNS_MALLOC_DEBUGGING uses
    // for detecting when the memory for an object is inadvertently freed while the object is still on some list
#ifdef WIN32
#error This will not work on Windows, look at IsValidSocket in mDNSShared/CommonServices.h to see why
#endif
    req->sd = req->errsd = -2;
#else
    req->sd = req->errsd = dnssd_InvalidSocket;
#endif
    // We also set req->terminate to a bogus value so we know if abort_request() gets called again for this request
    req->terminate = (req_termination_fn) ~0;
}

#if DEBUG
mDNSexport void SetDebugBoundPath(void)
{
#if !defined(USE_TCP_LOOPBACK)
    boundPath = MDNS_UDS_SERVERPATH_DEBUG;
#endif
}

mDNSexport int IsDebugSocketInUse(void)
{
#if !defined(USE_TCP_LOOPBACK)
    return !strcmp(boundPath, MDNS_UDS_SERVERPATH_DEBUG);
#else
    return mDNSfalse;
#endif
}
#endif

mDNSlocal void AbortUnlinkAndFree(request_state *req)
{
    request_state **p = &all_requests;
    abort_request(req);
    while (*p && *p != req) p=&(*p)->next;
    if (*p)
    {
        *p = req->next;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
        mdns_trust_forget(&req->trust);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
        mdns_forget(&req->signed_obj);
#endif
        freeL("request_state/AbortUnlinkAndFree", req);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "AbortUnlinkAndFree: ERROR: Attempt to abort operation %p not in list", req);
    }
}

mDNSlocal reply_state *create_reply(const reply_op_t op, const size_t datalen, request_state *const request)
{
    reply_state *reply;

    if ((unsigned)datalen < sizeof(reply_hdr))
    {
        LogMsg("ERROR: create_reply - data length less than length of required fields");
        return NULL;
    }

    reply = (reply_state *) callocL("reply_state", sizeof(reply_state) + datalen - sizeof(reply_hdr));
    if (!reply) FatalError("ERROR: calloc");

    reply->next     = mDNSNULL;
    reply->totallen = (mDNSu32)datalen + sizeof(ipc_msg_hdr);
    reply->nwritten = 0;

    reply->mhdr->version        = VERSION;
    reply->mhdr->datalen        = (mDNSu32)datalen;
    reply->mhdr->ipc_flags      = 0;
    reply->mhdr->op             = op;
    reply->mhdr->client_context = request->hdr.client_context;
    reply->mhdr->reg_index      = 0;

    return reply;
}

// Append a reply to the list in a request object
// If our request is sharing a connection, then we append our reply_state onto the primary's list
// If the request does not want asynchronous replies, then the reply is freed instead of being appended to any list.
mDNSlocal void append_reply(request_state *req, reply_state *rep)
{
    request_state *r;
    reply_state **ptr;

    if (req->no_reply)
    {
        freeL("reply_state/append_reply", rep);
        return;
    }

    r = req->primary ? req->primary : req;
    ptr = &r->replies;
    while (*ptr) ptr = &(*ptr)->next;
    *ptr = rep;
    rep->next = NULL;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
mDNSlocal const uint8_t * _get_signed_data_tlvs(request_state *const request, size_t *const out_length)
{
    const mDNSu8 *data = NULL;
    if (request->msgptr && (request->hdr.ipc_flags & IPC_FLAGS_TRAILING_TLVS))
    {
        const mDNSu8 *const start = (const mDNSu8 *)request->msgptr;
        const mDNSu8 *const end   = (const mDNSu8 *)request->msgend;
        DNSServiceValidationPolicy policy = get_tlv_uint32(start, end, IPC_TLV_TYPE_SERVICE_ATTR_VALIDATION_POLICY, mDNSNULL);
        if (policy == kDNSServiceValidationPolicyRequired)
        {
            request->sign_result = mDNStrue;
            size_t len;
            data = get_tlv(start, end, IPC_TLV_TYPE_SERVICE_ATTR_VALIDATION_DATA, &len);
            if (out_length)
            {
                *out_length = len;
            }
        }
    }
    return data;
}

mDNSlocal mStatus get_signed_result_flags_tlvs(request_state *const request)
{
    // No data is expected in this case
    (void)_get_signed_data_tlvs(request, NULL);
    return mStatus_NoError;
}

mDNSlocal mStatus get_signed_browse_tlvs(request_state *const request)
{
    size_t len = 0;
    const mDNSu8 * const data = _get_signed_data_tlvs(request, &len);
    if (request->sign_result)
    {
        if (!data)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "get_signed_browse_tlvs data invalid");
            return mStatus_Invalid;
        }

        OSStatus err;
        mdns_signed_browse_result_t signed_obj = mdns_signed_browse_result_create_from_data(data, len, &err);
        if (!signed_obj || err != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "get_signed_browse_tlvs len %ld data invalid %ld", len,
                (long)err);
            return mStatus_Invalid;
        }

        request->signed_obj = mdns_signed_result_upcast(signed_obj);
    }
    return mStatus_NoError;
}

mDNSlocal mStatus get_signed_resolve_tlvs(request_state *const request)
{
    size_t len = 0;
    const mDNSu8 * const data = _get_signed_data_tlvs(request, &len);
    if (request->sign_result)
    {
        if (!data)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "get_signed_resolve_tlvs data invalid");
            return mStatus_Invalid;
        }

        OSStatus err;
        mdns_signed_resolve_result_t signed_obj = mdns_signed_resolve_result_create_from_data(data, len, &err);
        if (!signed_obj || err != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "get_signed_resolve_tlvs len %ld data invalid %ld", len,
                (long)err);
            return mStatus_Invalid;
        }

        request->signed_obj = mdns_signed_result_upcast(signed_obj);
    }
    return mStatus_NoError;
}

mDNSlocal void put_signed_result_tlvs(const uint8_t *data, uint16_t length, ipc_msg_hdr * const hdr,
    uint8_t ** const ptr, const uint8_t * const limit)
{
    put_tlv(IPC_TLV_TYPE_SERVICE_ATTR_VALIDATION_DATA, length, data, ptr, limit);
    hdr->ipc_flags |= IPC_FLAGS_TRAILING_TLVS;
}
#endif

// Generates a response message giving name, type, domain, plus interface index,
// suitable for a browse result or service registration result.
// On successful completion rep is set to point to a malloc'd reply_state struct
mDNSlocal mStatus GenerateNTDResponse(const domainname *const servicename, const mDNSInterfaceID id,
                                      request_state *const request, reply_state **const rep, reply_op_t op, DNSServiceFlags flags, mStatus err)
{
    domainlabel name;
    domainname type, dom;
    *rep = NULL;
    if (servicename && !DeconstructServiceName(servicename, &name, &type, &dom))
        return kDNSServiceErr_Invalid;
    else
    {
        char namestr[MAX_DOMAIN_LABEL+1];
        char typestr[MAX_ESCAPED_DOMAIN_NAME];
        char domstr [MAX_ESCAPED_DOMAIN_NAME];
        size_t len;
        uint8_t *data;

        if (servicename)
        {
            ConvertDomainLabelToCString_unescaped(&name, namestr);
            ConvertDomainNameToCString(&type, typestr);
            ConvertDomainNameToCString(&dom, domstr);
        }
        else
        {
            namestr[0] = 0;
            typestr[0] = 0;
            domstr[0] = 0;
        }

        mDNSu32 interface_index = mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, id, mDNSfalse);

        // Calculate reply data length
        len = sizeof(DNSServiceFlags);
        len += sizeof(mDNSu32);  // if index
        len += sizeof(DNSServiceErrorType);
        len += (strlen(namestr) + 1);
        len += (strlen(typestr) + 1);
        len += (strlen(domstr) + 1);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
        mdns_signed_browse_result_t signed_result = NULL;
        const uint8_t *signed_data = NULL;
        uint16_t signed_data_length = 0;
        if (request->sign_result && servicename)
        {
            OSStatus error;
            signed_result = mdns_signed_browse_result_create(servicename->c, interface_index, &error);
            if (!signed_result || error != 0)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "GenerateBrowseReply signed_browse failed %ld",
                    (long)error);
            }
            else
            {
                size_t temp_size = 0;
                const uint8_t * temp_data = mdns_signed_result_get_data(signed_result, &temp_size);
                if (temp_size <= UINT16_MAX)
                {
                    signed_data = temp_data;
                    signed_data_length = (uint16_t)temp_size;
                    len += get_required_tlv_length(signed_data_length);
                }
            }
        }
#endif

        // Build reply header
        *rep = create_reply(op, len, request);
        (*rep)->rhdr->flags = dnssd_htonl(flags);
        (*rep)->rhdr->ifi   = dnssd_htonl(interface_index);
        (*rep)->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)err);

        // Build reply body
        data = (uint8_t *)&(*rep)->rhdr[1];
        put_string(namestr, &data);
        put_string(typestr, &data);
        put_string(domstr, &data);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
        if (signed_data)
        {
            put_signed_result_tlvs(signed_data, signed_data_length, (*rep)->mhdr, &data, data+len);
        }
        mdns_forget(&signed_result);
#endif

        return mStatus_NoError;
    }
}

mDNSlocal void GenerateBrowseReply(const domainname *const servicename, const mDNSInterfaceID id,
                                              request_state *const request, reply_state **const rep, reply_op_t op, DNSServiceFlags flags, mStatus err)
{
    char namestr[MAX_DOMAIN_LABEL+1];
    char typestr[MAX_ESCAPED_DOMAIN_NAME];
    static const char domstr[] = ".";
    size_t len;
    uint8_t *data;

    *rep = NULL;

    if (servicename)
    {
        // 1. Put first label in namestr
        ConvertDomainLabelToCString_unescaped((const domainlabel *)servicename, namestr);

        // 2. Put second label and "local" into typestr
        mDNS_snprintf(typestr, sizeof(typestr), "%#s.local.", SecondLabel(servicename));
    }
    else
    {
        namestr[0] = 0;
        typestr[0] = 0;
    }

    // Calculate reply data length
    len = sizeof(DNSServiceFlags);
    len += sizeof(mDNSu32);  // if index
    len += sizeof(DNSServiceErrorType);
    len += (strlen(namestr) + 1);
    len += (strlen(typestr) + 1);
    len += (strlen(domstr) + 1);

    // Build reply header
    *rep = create_reply(op, len, request);
    (*rep)->rhdr->flags = dnssd_htonl(flags);
    (*rep)->rhdr->ifi   = dnssd_htonl(mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, id, mDNSfalse));
    (*rep)->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)err);

    // Build reply body
    data = (uint8_t *)&(*rep)->rhdr[1];
    put_string(namestr, &data);
    put_string(typestr, &data);
    put_string(domstr, &data);
}

// get IPC_TLV_TYPE_SERVICE_ATTR_TIMESTAMP value
// if tlv type IPC_TLV_TYPE_SERVICE_ATTR_TIMESTAMP is present and found is not NULL, *found will be set to mDNStrue,
// otherwise it will be set to mDNSfalse. The caller should check *found before using the returned value. The timestamp
// is a number of seconds in the past, and is unsigned.
mDNSlocal mDNSu32 get_service_attr_timestamp_value(const request_state *const request, mDNSBool *const outFound)
{
    mDNSu32 timestamp = 0;
    if (request->msgptr && (request->hdr.ipc_flags & IPC_FLAGS_TRAILING_TLVS))
    {
        mDNSs32 error;
        const mDNSu8 *const start = (const mDNSu8 *)request->msgptr;
        const mDNSu8 *const end   = (const mDNSu8 *)request->msgend;
        timestamp = (mDNSu32)get_tlv_uint32(start, end, IPC_TLV_TYPE_SERVICE_ATTR_TIMESTAMP, &error);
        if (outFound)
        {
            *outFound = error ? mDNSfalse : mDNStrue;
        }
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "found[" PUB_S "] timestamp %u", error ? "no" : "yes", timestamp);
    }
    return timestamp;
}

// Returns a resource record (allocated w/ malloc) containing the data found in an IPC message
// Data must be in the following format: flags, interfaceIndex, name, rrtype, rrclass, rdlen, rdata, (optional) ttl
// (ttl only extracted/set if ttl argument is non-zero). Returns NULL for a bad-parameter error
mDNSlocal AuthRecord *read_rr_from_ipc_msg(request_state *request, int GetTTL, int validate_flags)
{
    DNSServiceFlags flags  = get_flags(&request->msgptr, request->msgend);
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    char name[MAX_ESCAPED_DOMAIN_NAME];
    int str_err = get_string(&request->msgptr, request->msgend, name, sizeof(name));
    mDNSu16 type  = get_uint16(&request->msgptr, request->msgend);
    mDNSu16 class = get_uint16(&request->msgptr, request->msgend);
    mDNSu16 rdlen = get_uint16(&request->msgptr, request->msgend);
    const mDNSu8 *const rdata = get_rdata(&request->msgptr, request->msgend, rdlen);
    mDNSu32 ttl   = GetTTL ? get_uint32(&request->msgptr, request->msgend) : 0;
    size_t rdcapacity;
    AuthRecord *rr;
    mDNSInterfaceID InterfaceID;
    AuthRecType artype;
    mDNSu8 recordType;

    request->flags = flags;
    request->interfaceIndex = interfaceIndex;

    if (str_err) { LogMsg("ERROR: read_rr_from_ipc_msg - get_string"); return NULL; }
    if (!request->msgptr) { LogMsg("Error reading Resource Record from client"); return NULL; }

    if (validate_flags &&
        !((flags & kDNSServiceFlagsShared) == kDNSServiceFlagsShared) &&
        !((flags & kDNSServiceFlagsUnique) == kDNSServiceFlagsUnique) &&
        !((flags & kDNSServiceFlagsKnownUnique) == kDNSServiceFlagsKnownUnique))
    {
        LogMsg("ERROR: Bad resource record flags (must be one of either kDNSServiceFlagsShared, kDNSServiceFlagsUnique or kDNSServiceFlagsKnownUnique)");
        return NULL;
    }
    InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);

    // The registration is scoped to a specific interface index, but the interface is not currently on our list.
    if ((InterfaceID == mDNSInterface_Any) && (interfaceIndex != kDNSServiceInterfaceIndexAny))
    {
        // On Apple platforms, an interface's mDNSInterfaceID is equal to its index. Using an interface index that isn't
        // currently valid will cause the registration to take place as soon as it becomes valid. On other platforms,
        // mDNSInterfaceID is actually a pointer to a platform-specific interface object, but we don't know what the pointer
        // for the interface index will be ahead of time. For now, just return NULL to indicate an error condition since the
        // interface index is invalid. Otherwise, the registration would be performed on all interfaces.
        return NULL;
    }
    rdcapacity = (rdlen > sizeof(RDataBody2)) ? rdlen : sizeof(RDataBody2);
    rr = (AuthRecord *) callocL("AuthRecord/read_rr_from_ipc_msg", sizeof(*rr) - sizeof(RDataBody) + rdcapacity);
    if (!rr) FatalError("ERROR: calloc");

    if (InterfaceID == mDNSInterface_LocalOnly)
        artype = AuthRecordLocalOnly;
    else if (InterfaceID == mDNSInterface_P2P || InterfaceID == mDNSInterface_BLE)
        artype = AuthRecordP2P;
    else if ((InterfaceID == mDNSInterface_Any) && (flags & kDNSServiceFlagsIncludeP2P)
            && (flags & kDNSServiceFlagsIncludeAWDL))
        artype = AuthRecordAnyIncludeAWDLandP2P;
    else if ((InterfaceID == mDNSInterface_Any) && (flags & kDNSServiceFlagsIncludeP2P))
        artype = AuthRecordAnyIncludeP2P;
    else if ((InterfaceID == mDNSInterface_Any) && (flags & kDNSServiceFlagsIncludeAWDL))
        artype = AuthRecordAnyIncludeAWDL;
    else
        artype = AuthRecordAny;

    if (flags & kDNSServiceFlagsShared)
        recordType = (mDNSu8) kDNSRecordTypeShared;
    else if (flags & kDNSServiceFlagsKnownUnique)
        recordType = (mDNSu8) kDNSRecordTypeKnownUnique;
    else
        recordType = (mDNSu8) kDNSRecordTypeUnique;

    mDNS_SetupResourceRecord(rr, mDNSNULL, InterfaceID, type, 0, recordType, artype, mDNSNULL, mDNSNULL);

    if (!MakeDomainNameFromDNSNameString(&rr->namestorage, name))
    {
        LogMsg("ERROR: bad name: %s", name);
        freeL("AuthRecord/read_rr_from_ipc_msg", rr);
        return NULL;
    }

    if (flags & kDNSServiceFlagsAllowRemoteQuery) rr->AllowRemoteQuery = mDNStrue;
    rr->resrec.rrclass = class;
    rr->resrec.rdlength = rdlen;
    rr->resrec.rdata->MaxRDLength = (mDNSu16)rdcapacity;
    if (!SetRData(mDNSNULL, rdata, rdata + rdlen, &rr->resrec, rdlen))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[R%u] read_rr_from_ipc_msg: SetRData failed for " PRI_DM_NAME " (" PUB_S ")",
            request->request_id, DM_NAME_PARAM(rr->resrec.name), DNSTypeName(type));
        freeL("AuthRecord/read_rr_from_ipc_msg", rr);
        return NULL;
    }
    if (GetTTL) rr->resrec.rroriginalttl = ttl;
    rr->resrec.namehash = DomainNameHashValue(rr->resrec.name);
    SetNewRData(&rr->resrec, mDNSNULL, 0);  // Sets rr->rdatahash for us
    return rr;
}

mDNSlocal int build_domainname_from_strings(domainname *srv, char *name, char *regtype, char *domain)
{
    domainlabel n;
    domainname d, t;

    if (!MakeDomainLabelFromLiteralString(&n, name)) return -1;
    if (!MakeDomainNameFromDNSNameString(&t, regtype)) return -1;
    if (!MakeDomainNameFromDNSNameString(&d, domain)) return -1;
    if (!ConstructServiceName(srv, &n, &t, &d)) return -1;
    return 0;
}

mDNSlocal void send_all(dnssd_sock_t s, const char *ptr, const size_t len)
{
    const ssize_t n = send(s, ptr, len, 0);
    // On a freshly-created Unix Domain Socket, the kernel should *never* fail to buffer a small write for us
    // (four bytes for a typical error code return, 12 bytes for DNSServiceGetProperty(DaemonVersion)).
    // If it does fail, we don't attempt to handle this failure, but we do log it so we know something is wrong.
    if ((n < 0) || (((size_t)n) < len))
    {
        LogMsg("ERROR: send_all(%d) wrote %ld of %lu errno %d (%s)",
            s, (long)n, (unsigned long)len, dnssd_errno, dnssd_strerror(dnssd_errno));
    }
}

#if 0
mDNSlocal mDNSBool AuthorizedDomain(const request_state * const request, const domainname * const d, const DNameListElem * const doms)
{
    const DNameListElem   *delem = mDNSNULL;
    int bestDelta   = -1;                           // the delta of the best match, lower is better
    int dLabels     = 0;
    mDNSBool allow       = mDNSfalse;

    if (SystemUID(request->uid)) return mDNStrue;

    dLabels = CountLabels(d);
    for (delem = doms; delem; delem = delem->next)
    {
        if (delem->uid)
        {
            int delemLabels = CountLabels(&delem->name);
            int delta       = dLabels - delemLabels;
            if ((bestDelta == -1 || delta <= bestDelta) && SameDomainName(&delem->name, SkipLeadingLabels(d, delta)))
            {
                bestDelta = delta;
                allow = (allow || (delem->uid == request->uid));
            }
        }
    }

    return bestDelta == -1 ? mDNStrue : allow;
}
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
mDNSlocal void SetupAuditTokenForRequest(request_state *request)
{

    pid_t audit_pid = audit_token_to_pid(request->audit_token);
    if (audit_pid == 0)
    {
#if !defined(LOCAL_PEERTOKEN)
#define LOCAL_PEERTOKEN         0x006           /* retrieve peer audit token */
#endif
        socklen_t len = sizeof(audit_token_t);
        int ret = getsockopt(request->sd, SOL_LOCAL, LOCAL_PEERTOKEN, &request->audit_token, &len);
        if (ret != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                      "SetupAuditTokenForRequest: No audit_token using LOCAL_PEERTOKEN (%s PID %d) for op %d ret(%d)",
                      request->pid_name, request->process_id, request->hdr.op, ret);
        }
    }
}
#endif

// ***************************************************************************
// MARK: - external helpers

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
mDNSlocal void external_start_advertising_helper(service_instance *const instance)
{
    AuthRecord *st = instance->subtypes;
    ExtraResourceRecord *e;
    mDNSu32 i;
    const pid_t requestPID = instance->request->process_id;

    if (mDNSIPPortIsZero(instance->request->u.servicereg.port))
    {
        LogInfo("external_start_advertising_helper: Not registering service with port number zero");
        return;
    }

    if (instance->external_advertise) LogMsg("external_start_advertising_helper: external_advertise already set!");

    for (i = 0; i < instance->request->u.servicereg.num_subtypes; i++)
        external_start_advertising_service(&st[i].resrec, instance->request->flags, requestPID);

    external_start_advertising_service(&instance->srs.RR_PTR.resrec, instance->request->flags, requestPID);
    external_start_advertising_service(&instance->srs.RR_SRV.resrec, instance->request->flags, requestPID);
    external_start_advertising_service(&instance->srs.RR_TXT.resrec, instance->request->flags, requestPID);

    for (e = instance->srs.Extras; e; e = e->next)
        external_start_advertising_service(&e->r.resrec, instance->request->flags, requestPID);

    instance->external_advertise = mDNStrue;
}

mDNSlocal void external_stop_advertising_helper(service_instance *const instance)
{
    AuthRecord *st = instance->subtypes;
    ExtraResourceRecord *e;
    mDNSu32 i;

    if (!instance->external_advertise) return;

    LogInfo("external_stop_advertising_helper: calling external_stop_advertising_service");

    if (instance->request)
    {
        const pid_t requestPID = instance->request->process_id;
        for (i = 0; i < instance->request->u.servicereg.num_subtypes; i++)
        {
            external_stop_advertising_service(&st[i].resrec, instance->request->flags, requestPID);
        }

        external_stop_advertising_service(&instance->srs.RR_PTR.resrec, instance->request->flags, requestPID);
        external_stop_advertising_service(&instance->srs.RR_SRV.resrec, instance->request->flags, requestPID);
        external_stop_advertising_service(&instance->srs.RR_TXT.resrec, instance->request->flags, requestPID);

        for (e = instance->srs.Extras; e; e = e->next)
        {
            external_stop_advertising_service(&e->r.resrec, instance->request->flags, requestPID);
        }
    }

    instance->external_advertise = mDNSfalse;
}
#endif  // MDNSRESPONDER_SUPPORTS(APPLE, D2D)

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
mDNSlocal dispatch_queue_t _get_trust_results_dispatch_queue(void)
{
    static dispatch_once_t  once    = 0;
    static dispatch_queue_t queue   = NULL;

    dispatch_once(&once, ^{
        dispatch_queue_attr_t const attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
        queue = dispatch_queue_create("com.apple.mDNSResponder.trust_results-queue", attr);
    });
    return queue;
}
#endif

// ***************************************************************************
// MARK: - DNSServiceRegister

mDNSexport void FreeExtraRR(mDNS *const m, AuthRecord *const rr, mStatus result)
{
    ExtraResourceRecord *extra = (ExtraResourceRecord *)rr->RecordContext;
    (void)m;  // Unused

    if (result != mStatus_MemFree) { LogMsg("Error: FreeExtraRR invoked with unexpected error %d", result); return; }

    LogInfo("     FreeExtraRR %s", RRDisplayString(m, &rr->resrec));

    if (rr->resrec.rdata != &rr->rdatastorage)
        freeL("Extra RData", rr->resrec.rdata);
    freeL("ExtraResourceRecord/FreeExtraRR", extra);
}

mDNSlocal void unlink_and_free_service_instance(service_instance *srv)
{
    ExtraResourceRecord *e = srv->srs.Extras, *tmp;

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
    external_stop_advertising_helper(srv);
#endif

    // clear pointers from parent struct
    if (srv->request)
    {
        service_instance **p = &srv->request->u.servicereg.instances;
        while (*p)
        {
            if (*p == srv) { *p = (*p)->next; break; }
            p = &(*p)->next;
        }
    }

    while (e)
    {
        e->r.RecordContext = e;
        tmp = e;
        e = e->next;
        FreeExtraRR(&mDNSStorage, &tmp->r, mStatus_MemFree);
    }

    if (srv->srs.RR_TXT.resrec.rdata != &srv->srs.RR_TXT.rdatastorage)
        freeL("TXT RData", srv->srs.RR_TXT.resrec.rdata);

    if (srv->subtypes)
    {
        freeL("ServiceSubTypes", srv->subtypes);
        srv->subtypes = NULL;
    }
    freeL("service_instance", srv);
}

// Count how many other service records we have locally with the same name, but different rdata.
// For auto-named services, we can have at most one per machine -- if we allowed two auto-named services of
// the same type on the same machine, we'd get into an infinite autoimmune-response loop of continuous renaming.
mDNSexport int CountPeerRegistrations(ServiceRecordSet *const srs)
{
    int count = 0;
    ResourceRecord *r = &srs->RR_SRV.resrec;
    AuthRecord *rr;

    for (rr = mDNSStorage.ResourceRecords; rr; rr=rr->next)
        if (rr->resrec.rrtype == kDNSType_SRV && SameDomainName(rr->resrec.name, r->name) && !IdenticalSameNameRecord(&rr->resrec, r))
            count++;

    verbosedebugf("%d peer registrations for %##s", count, r->name->c);
    return(count);
}

mDNSexport int CountExistingRegistrations(domainname *srv, mDNSIPPort port)
{
    int count = 0;
    AuthRecord *rr;
    for (rr = mDNSStorage.ResourceRecords; rr; rr=rr->next)
        if (rr->resrec.rrtype == kDNSType_SRV &&
            mDNSSameIPPort(rr->resrec.rdata->u.srv.port, port) &&
            SameDomainName(rr->resrec.name, srv))
            count++;
    return(count);
}

mDNSlocal void SendServiceRemovalNotification(ServiceRecordSet *const srs)
{
    reply_state *rep;
    service_instance *instance = srs->ServiceContext;
    if (GenerateNTDResponse(srs->RR_SRV.resrec.name, srs->RR_SRV.resrec.InterfaceID, instance->request, &rep, reg_service_reply_op, 0, mStatus_NoError) != mStatus_NoError)
        LogMsg("%3d: SendServiceRemovalNotification: %##s is not valid DNS-SD SRV name", instance->request->sd, srs->RR_SRV.resrec.name->c);
    else { append_reply(instance->request, rep); instance->clientnotified = mDNSfalse; }
}

// service registration callback performs three duties - frees memory for deregistered services,
// handles name conflicts, and delivers completed registration information to the client
mDNSlocal void regservice_callback(mDNS *const m, ServiceRecordSet *const srs, mStatus result)
{
    mStatus err;
    mDNSBool SuppressError = mDNSfalse;
    service_instance *instance;
    reply_state         *rep;
    (void)m; // Unused

    if (!srs)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "regservice_callback: srs is NULL %d", result);
        return;
    }

    instance = srs->ServiceContext;
    if (!instance)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "regservice_callback: srs->ServiceContext is NULL %d", result);
        return;
    }

    // don't send errors up to client for wide-area, empty-string registrations
    if (instance->request &&
        instance->request->u.servicereg.default_domain &&
        !instance->default_local)
        SuppressError = mDNStrue;

    if (mDNS_LoggingEnabled)
    {
        const char *result_description;
        char description[32]; // 32-byte is enough for holding "suppressed error -2147483648\0"
        mDNSu32 request_id = instance->request ? instance->request->request_id : 0;
        switch (result) {
            case mStatus_NoError:
                result_description = "REGISTERED";
                break;
            case mStatus_MemFree:
                result_description = "DEREGISTERED";
                break;
            case mStatus_NameConflict:
                result_description = "NAME CONFLICT";
                break;
            default:
                mDNS_snprintf(description, sizeof(description), "%s %d", SuppressError ? "suppressed error" : "CALLBACK", result);
                result_description = description;
                break;
        }
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceRegister(" PRI_DM_NAME ", %u) %s",
                  request_id, DM_NAME_PARAM(srs->RR_SRV.resrec.name), mDNSVal16(srs->RR_SRV.resrec.rdata->u.srv.port), result_description);
    }

    if (!instance->request && result != mStatus_MemFree)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "regservice_callback: instance->request is NULL %d", result);
        return;
    }

    if (result == mStatus_NoError)
    {
        if (instance->request->u.servicereg.allowremotequery)
        {
            ExtraResourceRecord *e;
            srs->RR_ADV.AllowRemoteQuery = mDNStrue;
            srs->RR_PTR.AllowRemoteQuery = mDNStrue;
            srs->RR_SRV.AllowRemoteQuery = mDNStrue;
            srs->RR_TXT.AllowRemoteQuery = mDNStrue;
            for (e = instance->srs.Extras; e; e = e->next) e->r.AllowRemoteQuery = mDNStrue;
        }

        if (GenerateNTDResponse(srs->RR_SRV.resrec.name, srs->RR_SRV.resrec.InterfaceID, instance->request, &rep, reg_service_reply_op, kDNSServiceFlagsAdd, result) != mStatus_NoError)
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] regservice_callback: " PRI_DM_NAME " is not valid DNS-SD SRV name", instance->request->request_id, DM_NAME_PARAM(srs->RR_SRV.resrec.name));
        else { append_reply(instance->request, rep); instance->clientnotified = mDNStrue; }

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        if (callExternalHelpers(instance->request->u.servicereg.InterfaceID, &instance->domain, instance->request->flags))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] regservice_callback: calling external_start_advertising_helper()", instance->request->request_id);
            external_start_advertising_helper(instance);
        }
#endif
        if (instance->request->u.servicereg.autoname && CountPeerRegistrations(srs) == 0)
            RecordUpdatedNiceLabel(0);   // Successfully got new name, tell user immediately
    }
    else if (result == mStatus_MemFree)
    {
        if (instance->request && instance->renameonmemfree)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            external_stop_advertising_helper(instance);
#endif
            instance->renameonmemfree = 0;
            err = mDNS_RenameAndReregisterService(m, srs, &instance->request->u.servicereg.name);
            if (err)
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] ERROR: regservice_callback - RenameAndReregisterService returned %d", instance->request->request_id, err);
            // error should never happen - safest to log and continue
        }
        else
            unlink_and_free_service_instance(instance);
    }
    else if (result == mStatus_NameConflict)
    {
        if (instance->request->u.servicereg.autorename)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            external_stop_advertising_helper(instance);
#endif
            if (instance->request->u.servicereg.autoname && CountPeerRegistrations(srs) == 0)
            {
                // On conflict for an autoname service, rename and reregister *all* autoname services
                IncrementLabelSuffix(&m->nicelabel, mDNStrue);
                mDNS_ConfigChanged(m);  // Will call back into udsserver_handle_configchange()
            }
            else    // On conflict for a non-autoname service, rename and reregister just that one service
            {
                if (instance->clientnotified) SendServiceRemovalNotification(srs);
                mDNS_RenameAndReregisterService(m, srs, mDNSNULL);
            }
        }
        else
        {
            if (!SuppressError)
            {
                if (GenerateNTDResponse(srs->RR_SRV.resrec.name, srs->RR_SRV.resrec.InterfaceID, instance->request, &rep, reg_service_reply_op, kDNSServiceFlagsAdd, result) != mStatus_NoError)
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] regservice_callback: " PRI_DM_NAME " is not valid DNS-SD SRV name", instance->request->request_id, DM_NAME_PARAM(srs->RR_SRV.resrec.name));
                else { append_reply(instance->request, rep); instance->clientnotified = mDNStrue; }
            }
            unlink_and_free_service_instance(instance);
        }
    }
    else        // Not mStatus_NoError, mStatus_MemFree, or mStatus_NameConflict
    {
        if (!SuppressError)
        {
            if (GenerateNTDResponse(srs->RR_SRV.resrec.name, srs->RR_SRV.resrec.InterfaceID, instance->request, &rep, reg_service_reply_op, kDNSServiceFlagsAdd, result) != mStatus_NoError)
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] regservice_callback: " PRI_DM_NAME " is not valid DNS-SD SRV name", instance->request->request_id, DM_NAME_PARAM(srs->RR_SRV.resrec.name));
            else { append_reply(instance->request, rep); instance->clientnotified = mDNStrue; }
        }
    }
}

mDNSlocal void regrecord_callback(mDNS *const m, AuthRecord *rr, mStatus result)
{
    (void)m; // Unused
    if (!rr->RecordContext)     // parent struct already freed by termination callback
    {
        if (result == mStatus_NoError)
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Error: regrecord_callback: successful registration of orphaned record " PRI_S, ARDisplayString(m, rr));
        else
        {
            if (result != mStatus_MemFree)
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "regrecord_callback: error %d received after parent termination", result);

            // We come here when the record is being deregistered either from DNSServiceRemoveRecord or connection_termination.
            // If the record has been updated, we need to free the rdata. Every time we call mDNS_Update, it calls update_callback
            // with the old rdata (so that we can free it) and stores the new rdata in "rr->resrec.rdata". This means, we need
            // to free the latest rdata for which the update_callback was never called with.
            if (rr->resrec.rdata != &rr->rdatastorage) freeL("RData/regrecord_callback", rr->resrec.rdata);
            freeL("AuthRecord/regrecord_callback", rr);
        }
    }
    else
    {
        registered_record_entry *re = rr->RecordContext;
        request_state *request = re->request;

        if (mDNS_LoggingEnabled)
        {
            const char *result_description;
            char description[16]; // 16-byte is enough for holding -2147483648\0
            switch (result) {
                case mStatus_NoError:
                    result_description = "REGISTERED";
                    break;
                case mStatus_MemFree:
                    result_description = "DEREGISTERED";
                    break;
                case mStatus_NameConflict:
                    result_description = "NAME CONFLICT";
                    break;
                default:
                    mDNS_snprintf(description, sizeof(description), "%d", result);
                    result_description = description;
                    break;
            }

            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceRegisterRecord(%u " PRI_S ")" PUB_S,
                      request->request_id, re->key, RRDisplayString(m, &rr->resrec), result_description);
        }

        if (result != mStatus_MemFree)
        {
            const size_t len = sizeof(DNSServiceFlags) + sizeof(mDNSu32) + sizeof(DNSServiceErrorType);
            reply_state *reply = create_reply(reg_record_reply_op, len, request);
            reply->mhdr->client_context = re->regrec_client_context;
            reply->rhdr->flags = dnssd_htonl(0);
            reply->rhdr->ifi   = dnssd_htonl(mDNSPlatformInterfaceIndexfromInterfaceID(m, rr->resrec.InterfaceID, mDNSfalse));
            reply->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)result);
            append_reply(request, reply);
        }

        if (result)
        {
            // If this is a callback to a keepalive record, do not free it.
            if (result == mStatus_BadStateErr)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u] regrecord_callback: Callback with error code mStatus_BadStateErr - not freeing the record.", request->request_id);
            }
            else
            {
                // unlink from list, free memory
                registered_record_entry **ptr = &request->u.reg_recs;
                while (*ptr && (*ptr) != re) ptr = &(*ptr)->next;
                if (!*ptr)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                              "[R%u] regrecord_callback - record not in list!", request->request_id);
                    return;
                }
                *ptr = (*ptr)->next;
                freeL("registered_record_entry AuthRecord regrecord_callback", re->rr);
                freeL("registered_record_entry regrecord_callback", re);
             }
        }
        else
        {
            if (re->external_advertise)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u] regrecord_callback: external_advertise already set!", request->request_id);
            }

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            if (callExternalHelpers(re->origInterfaceID, &rr->namestorage, request->flags))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                          "[R%u] regrecord_callback: calling external_start_advertising_service", request->request_id);
                external_start_advertising_service(&rr->resrec, request->flags, request->process_id);
                re->external_advertise = mDNStrue;
            }
#endif
        }
    }
}

// set_peer_pid() is called after mem is allocated for each new request in NewRequest()
// This accounts for 2 places (connect_callback, request_callback)
mDNSlocal void set_peer_pid(request_state *request)
{
    request->pid_name[0] = '\0';
    request->process_id  = -1;
#ifdef LOCAL_PEEREPID
    pid_t           p    = (pid_t) -1;
    socklen_t       len  = sizeof(p);
    if (request->sd < 0)
        return;
    // to extract the effective pid value
    if (getsockopt(request->sd, SOL_LOCAL, LOCAL_PEEREPID, &p, &len) != 0)
        return;
    debugf("set_peer_pid: Client PEEREPID is %d", p);
    request->process_id = p;
#else   // !LOCAL_PEEREPID
    LogInfo("set_peer_pid: Not Supported on this version of OS");
    if (request->sd < 0)
        return;
#endif  // LOCAL_PEEREPID
}

mDNSlocal void connection_termination(request_state *request)
{
    // When terminating a shared connection, we need to scan the all_requests list
    // and terminate any subbordinate operations sharing this file descriptor
    request_state **req = &all_requests;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceCreateConnection STOP PID[%d](" PUB_S ")",
           request->request_id, request->process_id, request->pid_name);

    while (*req)
    {
        if ((*req)->primary == request)
        {
            // Since we're already doing a list traversal, we unlink the request directly instead of using AbortUnlinkAndFree()
            request_state *tmp = *req;
            if (tmp->primary == tmp) LogMsg("connection_termination ERROR (*req)->primary == *req for %p %d",                  tmp, tmp->sd);
            if (tmp->replies) LogMsg("connection_termination ERROR How can subordinate req %p %d have replies queued?", tmp, tmp->sd);
            abort_request(tmp);
            *req = tmp->next;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
            mdns_trust_forget(&tmp->trust);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
            mdns_forget(&tmp->signed_obj);
#endif
            freeL("request_state/connection_termination", tmp);
        }
        else
            req = &(*req)->next;
    }

    while (request->u.reg_recs)
    {
        registered_record_entry *ptr = request->u.reg_recs;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceRegisterRecord(0x%X, %d, " PRI_S ") STOP PID[%d](" PUB_S ")",
               request->request_id, request->flags, request->interfaceIndex, RRDisplayString(&mDNSStorage, &ptr->rr->resrec), request->process_id,
               request->pid_name);
        request->u.reg_recs = request->u.reg_recs->next;
        ptr->rr->RecordContext = NULL;
        if (ptr->external_advertise)
        {
            ptr->external_advertise = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            external_stop_advertising_service(&ptr->rr->resrec, request->flags, request->process_id);
#endif
        }
        LogMcastS(ptr->rr, request, reg_stop);
        mDNS_Deregister(&mDNSStorage, ptr->rr);     // Will free ptr->rr for us
        freeL("registered_record_entry/connection_termination", ptr);
    }
}

mDNSlocal void handle_cancel_request(request_state *request)
{
    request_state **req = &all_requests;
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "[R%d] Cancel %08X %08X",
           request->request_id, request->hdr.client_context.u32[1], request->hdr.client_context.u32[0]);
    while (*req)
    {
        if ((*req)->primary == request &&
            (*req)->hdr.client_context.u32[0] == request->hdr.client_context.u32[0] &&
            (*req)->hdr.client_context.u32[1] == request->hdr.client_context.u32[1])
        {
            // Since we're already doing a list traversal, we unlink the request directly instead of using AbortUnlinkAndFree()
            request_state *tmp = *req;
            abort_request(tmp);
            *req = tmp->next;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
            mdns_trust_forget(&tmp->trust);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
            mdns_forget(&tmp->signed_obj);
#endif
            freeL("request_state/handle_cancel_request", tmp);
        }
        else
            req = &(*req)->next;
    }
}

mDNSlocal mStatus _handle_regrecord_request_start(request_state *request, AuthRecord * rr)
{
    mStatus err;
    registered_record_entry *re;
    // Don't allow non-local domains to be regsitered as LocalOnly. Allowing this would permit
    // clients to register records such as www.bigbank.com A w.x.y.z to redirect Safari.
    if (rr->resrec.InterfaceID == mDNSInterface_LocalOnly && !IsLocalDomain(rr->resrec.name) &&
        rr->resrec.rrclass == kDNSClass_IN && (rr->resrec.rrtype == kDNSType_A || rr->resrec.rrtype == kDNSType_AAAA ||
                                               rr->resrec.rrtype == kDNSType_CNAME))
    {
        freeL("AuthRecord/handle_regrecord_request", rr);
        return (mStatus_BadParamErr);
    }
    // allocate registration entry, link into list
    re = (registered_record_entry *) callocL("registered_record_entry", sizeof(*re));
    if (!re) FatalError("ERROR: calloc");
    re->key                   = request->hdr.reg_index;
    re->rr                    = rr;
    re->regrec_client_context = request->hdr.client_context;
    re->request               = request;
    re->external_advertise    = mDNSfalse;
    rr->RecordContext         = re;
    rr->RecordCallback        = regrecord_callback;
    rr->ForceMCast            = ((request->flags & kDNSServiceFlagsForceMulticast) != 0);

    re->origInterfaceID = rr->resrec.InterfaceID;
    if (rr->resrec.InterfaceID == mDNSInterface_P2P)
        rr->resrec.InterfaceID = mDNSInterface_Any;
#if 0
    if (!AuthorizedDomain(request, rr->resrec.name, AutoRegistrationDomains)) return (mStatus_NoError);
#endif
    if (rr->resrec.rroriginalttl == 0)
        rr->resrec.rroriginalttl = DefaultTTLforRRType(rr->resrec.rrtype);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceRegisterRecord(0x%X, %d, " PRI_S ") START PID[%d](" PUB_S ")",
           request->request_id, request->flags, request->interfaceIndex, RRDisplayString(&mDNSStorage, &rr->resrec), request->process_id,
           request->pid_name);

    err = mDNS_Register(&mDNSStorage, rr);
    if (err)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceRegisterRecord(0x%X, %d," PRI_S ") ERROR (%d)",
               request->request_id, request->flags, request->interfaceIndex, RRDisplayString(&mDNSStorage, &rr->resrec), err);
        freeL("registered_record_entry", re);
        freeL("registered_record_entry/AuthRecord", rr);
    }
    else
    {
        LogMcastS(rr, request, reg_start);
        re->next = request->u.reg_recs;
        request->u.reg_recs = re;
    }
    return err;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_regrecord_request_error(request_state *request, mStatus error)
{
    reply_state *rep;
    if (GenerateNTDResponse(NULL, 0, request, &rep, reg_record_reply_op, 0, error) != mStatus_NoError)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceRegisterRecord _return_regrecord_request_error: error(%d)", request->request_id, error);
    }
    else
    {
        append_reply(request, rep);
    }
}

mDNSlocal mStatus _handle_regrecord_request_with_trust(request_state *request, AuthRecord * rr)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_regrecord_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_regrecord_request_start(request, rr);
    }
    else
    {
        const char *service_ptr = NULL;
        char type_str[MAX_ESCAPED_DOMAIN_NAME] = "";
        domainlabel name;
        domainname type, domain;
        bool good = DeconstructServiceName(rr->resrec.name, &name, &type, &domain);
        if (good)
        {
            ConvertDomainNameToCString(&type, type_str);
            service_ptr = type_str;
        }

        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_bonjour(request->audit_token, service_ptr, &flags);
        switch (status)
        {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, service_ptr, flags);
                if (!trust)
                {
                    freeL("AuthRecord/_handle_regrecord_request_with_trust", rr);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                mdns_trust_set_context(trust, rr);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("AuthRecord/_handle_regrecord_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        AuthRecord * _rr =  mdns_trust_get_context(trust);
                        if (_rr)
                        {
                            if (!error)
                            {
                                mdns_trust_set_context(trust, NULL); // _handle_regrecord_request_start handles free
                                error = _handle_regrecord_request_start(request, _rr);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_regrecord_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_handle_regrecord_request_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_regrecord_request_start(request, rr);
                break;
        }
     }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

// Add a TSR record when DNSServiceRegisterRecordWithAttribute is called with timestamp set correctly
mDNSlocal mStatus regRecordAddTSRRecord(request_state *const request, AuthRecord *const rr, const mDNSs32 tsrTimestamp)
{
    mStatus err = mStatus_NoError;
    AuthRecord *ar;
    size_t rdcapacity = sizeof(RDataBody2);

    ar = (AuthRecord *) callocL("AuthRecord/regRecordAddTSRRecord", sizeof(*ar) - sizeof(RDataBody) + rdcapacity);
    if (!ar)
    {
        FatalError("ERROR: calloc");
    }
    mDNS_SetupResourceRecord(ar, mDNSNULL, rr->resrec.InterfaceID, kDNSType_TSR, kHostNameTTL, rr->resrec.RecordType, rr->ARType, mDNSNULL, mDNSNULL);
    AssignDomainName(&ar->namestorage, rr->resrec.name);
    ar->resrec.rdlength = (mDNSu16)sizeof(tsrTimestamp);
    ar->resrec.rdata->MaxRDLength = (mDNSu16)rdcapacity;
    // tsr timestamp in memory is time of receipt
    ar->resrec.rdata->u.tsr_value = tsrTimestamp;
    ar->resrec.namehash = DomainNameHashValue(ar->resrec.name);
    SetNewRData(&ar->resrec, mDNSNULL, 0);  // Sets ar->rdatahash for us

    ar->ForceMCast            = ((request->flags & kDNSServiceFlagsForceMulticast) != 0);
    LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT, "[R%d] DNSServiceRegisterRecord(0x%X, %d, " PRI_S ") START PID[%d](" PUB_S ")",
              request->request_id, request->flags, request->interfaceIndex, RRDisplayString(&mDNSStorage, &ar->resrec),
              request->process_id, request->pid_name);

    err = mDNS_Register(&mDNSStorage, ar);
    if (err)
    {
        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT, "[R%d] DNSServiceRegisterRecord(0x%X, %d," PRI_S ") ERROR (%d)",
                  request->request_id, request->flags, request->interfaceIndex, RRDisplayString(&mDNSStorage, &ar->resrec), err);
        freeL("registered_record_entry/AuthRecord", ar);
    }
    else
    {
        LogMcastS(ar, request, reg_start);
        ar->RRSet = (uintptr_t)request->sd;
    }
    return err;
}

mDNSlocal mStatus updateTSRRecord(const request_state *const request, AuthRecord *const tsr, const mDNSs32 tsrTimestamp)
{
    mStatus err = mStatus_NoError;
    const RDataBody2 *const rdb = (RDataBody2 *)tsr->resrec.rdata->u.data;
    mDNSu32 unsignedTimestamp = (mDNSu32)tsrTimestamp;
    LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT, "TSR timestamp - name: " PRI_DM_NAME ", new: %d  old: %d",
              DM_NAME_PARAM(tsr->resrec.name), tsrTimestamp, rdb->tsr_value);
    if (tsrTimestamp - rdb->tsr_value < 0)
    {
        const mDNSu8 rdata[4] = { (unsignedTimestamp >> 24) & 0xFF, (unsignedTimestamp >> 16) & 0xFF,
            (unsignedTimestamp >> 8) & 0xFF, unsignedTimestamp & 0xFF};
        err = update_record(tsr, sizeof(rdata), rdata, kHostNameTTL, mDNSNULL, request->request_id);
    }
    return err;
}

mDNSlocal mDNSBool validateTSRTimestamp(mDNSs32 *timestampContinuous, mDNSu32 tsrTimestamp, const AuthRecord *rr)
{
    if (tsrTimestamp > MaxTimeSinceReceived)
    {
        if (rr != NULL)
        {
            LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR, "tsrTimestamp[%u] out of range (%u) on TSR for " PRI_DM_NAME "",
                      tsrTimestamp, MaxTimeSinceReceived, DM_NAME_PARAM(rr->resrec.name));
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR,
                      "tsrTimestamp[%u] out of range (%u) on TSR", tsrTimestamp, MaxTimeSinceReceived);
        }

        return mDNSfalse;
    }
    *timestampContinuous = mDNSPlatformContinuousTimeSeconds() - (mDNSs32)tsrTimestamp;
    return mDNStrue;
}

mDNSlocal mStatus handle_regrecord_request(request_state *request)
{
    mStatus err = mStatus_BadParamErr;
    AuthRecord *rr;

    if (request->terminate != connection_termination)
    { LogMsg("%3d: DNSServiceRegisterRecord(not a shared connection ref)", request->sd); return(err); }

    rr = read_rr_from_ipc_msg(request, 1, 1);
    if (rr)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
        if (os_feature_enabled(mDNSResponder, bonjour_privacy) &&
            IsLocalDomain(rr->resrec.name))
        {
            err = _handle_regrecord_request_with_trust(request, rr);
        }
        else
        {
            err = _handle_regrecord_request_start(request, rr);
        }
#else
        err = _handle_regrecord_request_start(request, rr);
#endif
    }
    if (!err)
    {
        mDNSBool foundTimestampTLV = mDNSfalse;
        const mDNSu32 tsrTimestamp = get_service_attr_timestamp_value(request, &foundTimestampTLV);

        if (foundTimestampTLV)
        {
            AuthRecord *currentTSR = mDNSGetTSRRecord(&mDNSStorage, rr);
            mDNSs32 timestampContinuous;
            if (!validateTSRTimestamp(&timestampContinuous, tsrTimestamp, rr))
            {
                return err;
            }
            if (currentTSR)
            {
                err = updateTSRRecord(request, currentTSR, timestampContinuous);
            }
            else
            {
                err = regRecordAddTSRRecord(request, rr, timestampContinuous);
            }
            if (!err)
            {
                LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                          "handle_regrecord_request: TSR record added with tsrTimestamp %d",
                          timestampContinuous);
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR,
                          "handle_regrecord_request: Failed to add TSR record with tsrTimestamp %d error %d",
                          timestampContinuous, err);
            }
        }
        rr->RRSet = (uintptr_t)request->sd;
    }

    return(err);
}

mDNSlocal void UpdateDeviceInfoRecord(mDNS *const m);

mDNSlocal void regservice_termination_callback(request_state *request)
{
    if (!request)
    {
        LogMsg("regservice_termination_callback context is NULL");
        return;
    }
    while (request->u.servicereg.instances)
    {
        service_instance *p = request->u.servicereg.instances;
        request->u.servicereg.instances = request->u.servicereg.instances->next;
        // only safe to free memory if registration is not valid, i.e. deregister fails (which invalidates p)
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%d] DNSServiceRegister(" PRI_DM_NAME ", %u) STOP PID[%d](" PUB_S ")",
               request->request_id, DM_NAME_PARAM(p->srs.RR_SRV.resrec.name),
               mDNSVal16(p->srs.RR_SRV.resrec.rdata->u.srv.port), request->process_id, request->pid_name);

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        external_stop_advertising_helper(p);
#endif

        // Clear backpointer *before* calling mDNS_DeregisterService/unlink_and_free_service_instance
        // We don't need unlink_and_free_service_instance to cut its element from the list, because we're already advancing
        // request->u.servicereg.instances as we work our way through the list, implicitly cutting one element at a time
        // We can't clear p->request *after* the calling mDNS_DeregisterService/unlink_and_free_service_instance
        // because by then we might have already freed p
        p->request = NULL;
        LogMcastS(&p->srs.RR_SRV, request, reg_stop);
        if (mDNS_DeregisterService(&mDNSStorage, &p->srs))
        {
            unlink_and_free_service_instance(p);
            // Don't touch service_instance *p after this -- it's likely to have been freed already
        }
    }
    if (request->u.servicereg.txtdata)
    {
        freeL("service_info txtdata", request->u.servicereg.txtdata);
        request->u.servicereg.txtdata = NULL;
    }
    if (request->u.servicereg.autoname)
    {
        // Clear autoname before calling UpdateDeviceInfoRecord() so it doesn't mistakenly include this in its count of active autoname registrations
        request->u.servicereg.autoname = mDNSfalse;
        UpdateDeviceInfoRecord(&mDNSStorage);
    }
}

mDNSlocal request_state *LocateSubordinateRequest(request_state *request)
{
    request_state *req;
    for (req = all_requests; req; req = req->next)
        if (req->primary == request &&
            req->hdr.client_context.u32[0] == request->hdr.client_context.u32[0] &&
            req->hdr.client_context.u32[1] == request->hdr.client_context.u32[1]) return(req);
    return(request);
}

mDNSlocal mStatus add_record_to_service(request_state *request, service_instance *instance, mDNSu16 rrtype, mDNSu16 rdlen,
    const mDNSu8 *const rdata, mDNSu32 ttl)
{
    ServiceRecordSet *srs = &instance->srs;
    mStatus result;
    const size_t rdcapacity = (rdlen > sizeof(RDataBody2)) ? rdlen : sizeof(RDataBody2);
    ExtraResourceRecord *extra = (ExtraResourceRecord *)callocL("ExtraResourceRecord", sizeof(*extra) - sizeof(RDataBody) + rdcapacity);
    if (!extra) { my_perror("ERROR: calloc"); return mStatus_NoMemoryErr; }

    extra->r.resrec.rrtype = rrtype;
    extra->r.resrec.rdata = &extra->r.rdatastorage;
    extra->r.resrec.rdata->MaxRDLength = (mDNSu16)rdcapacity;
    extra->r.resrec.rdlength = rdlen;
    if (!SetRData(mDNSNULL, rdata, rdata + rdlen, &extra->r.resrec, rdlen))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[R%u] read_rr_from_ipc_msg: SetRData failed for " PRI_DM_NAME " (" PUB_S ")",
            request->request_id, DM_NAME_PARAM(request->u.servicereg.instances ?
            request->u.servicereg.instances->srs.RR_SRV.resrec.name : mDNSNULL), DNSTypeName(rrtype));
        freeL("ExtraResourceRecord/add_record_to_service", extra);
        return mStatus_BadParamErr;
    }
    SetNewRData(&extra->r.resrec, mDNSNULL, 0);  // Sets rr->rdatahash for us
    // use InterfaceID value from DNSServiceRegister() call that created the original service
    extra->r.resrec.InterfaceID = request->u.servicereg.InterfaceID;

    result = mDNS_AddRecordToService(&mDNSStorage, srs, extra, &extra->r.rdatastorage, ttl, request->flags);
    if (result)
    {
        freeL("ExtraResourceRecord/add_record_to_service", extra);
        return result;
    }
    LogMcastS(&srs->RR_PTR, request, reg_start);

    extra->ClientID = request->hdr.reg_index;
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
    if (   instance->external_advertise
           && callExternalHelpers(request->u.servicereg.InterfaceID, &instance->domain, request->flags))
    {
        LogInfo("add_record_to_service: calling external_start_advertising_service");
        external_start_advertising_service(&extra->r.resrec, request->flags, request->process_id);
    }
#endif
    return result;
}

mDNSlocal mStatus handle_add_request(request_state *request)
{
    service_instance *i;
    mStatus result = mStatus_UnknownErr;
    DNSServiceFlags flags  = get_flags (&request->msgptr, request->msgend);
    mDNSu16 rrtype = get_uint16(&request->msgptr, request->msgend);
    mDNSu16 rdlen  = get_uint16(&request->msgptr, request->msgend);
    const mDNSu8 *const rdata = (const mDNSu8 *)get_rdata(&request->msgptr, request->msgend, rdlen);
    mDNSu32 ttl    = get_uint32(&request->msgptr, request->msgend);
    if (!ttl) ttl = DefaultTTLforRRType(rrtype);
    (void)flags; // Unused

    if (!request->msgptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceAddRecord(unreadable parameters)", request->request_id);
        return(mStatus_BadParamErr);
    }

    // If this is a shared connection, check if the operation actually applies to a subordinate request_state object
    if (request->terminate == connection_termination) request = LocateSubordinateRequest(request);

    if (request->terminate != regservice_termination_callback)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceAddRecord(not a registered service ref)", request->request_id);
        return(mStatus_BadParamErr);
    }

    // For a service registered with zero port, don't allow adding records. This mostly happens due to a bug
    // in the application. See radar://9165807.
    if (mDNSIPPortIsZero(request->u.servicereg.port))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceAddRecord: adding record to a service registered with zero port", request->request_id);
        return(mStatus_BadParamErr);
    }
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceAddRecord(%X, " PRI_DM_NAME ", " PUB_S ", %d) PID[%d](" PUB_S ")",
           request->request_id, flags,
           DM_NAME_PARAM((request->u.servicereg.instances) ? (request->u.servicereg.instances->srs.RR_SRV.resrec.name) : mDNSNULL),
           DNSTypeName(rrtype), rdlen, request->process_id, request->pid_name);

    for (i = request->u.servicereg.instances; i; i = i->next)
    {
        result = add_record_to_service(request, i, rrtype, rdlen, rdata, ttl);
        if (result && i->default_local) break;
        else result = mStatus_NoError;  // suppress non-local default errors
    }

    return(result);
}

mDNSlocal void update_callback(mDNS *const m, AuthRecord *const rr, RData *oldrd, mDNSu16 oldrdlen)
{
    mDNSBool external_advertise = (rr->UpdateContext) ? *((mDNSBool *)rr->UpdateContext) : mDNSfalse;
    (void)m; // Unused

    // There are three cases.
    //
    // 1. We have updated the primary TXT record of the service
    // 2. We have updated the TXT record that was added to the service using DNSServiceAddRecord
    // 3. We have updated the TXT record that was registered using DNSServiceRegisterRecord
    //
    // external_advertise is set if we have advertised at least once during the initial addition
    // of the record in all of the three cases above. We should have checked for InterfaceID/LocalDomain
    // checks during the first time and hence we don't do any checks here
    if (external_advertise)
    {
        ResourceRecord ext = rr->resrec;
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        DNSServiceFlags flags = deriveD2DFlagsFromAuthRecType(rr->ARType);
#endif

        if (ext.rdlength == oldrdlen && mDNSPlatformMemSame(&ext.rdata->u, &oldrd->u, oldrdlen)) goto exit;
        SetNewRData(&ext, oldrd, oldrdlen);
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        external_stop_advertising_service(&ext, flags, 0);
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "update_callback: calling external_start_advertising_service");
        external_start_advertising_service(&rr->resrec, flags, 0);
#endif
    }
exit:
    if (oldrd != &rr->rdatastorage) freeL("RData/update_callback", oldrd);
}

mDNSlocal mStatus update_record(AuthRecord *ar, mDNSu16 rdlen, const mDNSu8 *const rdata, mDNSu32 ttl,
    const mDNSBool *const external_advertise, const mDNSu32 request_id)
{
    ResourceRecord rr;
    mStatus result;
    const size_t rdcapacity = (rdlen > sizeof(RDataBody2)) ? rdlen : sizeof(RDataBody2);
    RData *newrd = (RData *) callocL("RData/update_record", sizeof(*newrd) - sizeof(RDataBody) + rdcapacity);
    if (!newrd) FatalError("ERROR: calloc");
    mDNSPlatformMemZero(&rr, (mDNSu32)sizeof(rr));
    rr.name     = ar->resrec.name;
    rr.rrtype   = ar->resrec.rrtype;
    rr.rrclass  = ar->resrec.rrclass;
    rr.rdata    = newrd;
    rr.rdata->MaxRDLength = (mDNSu16)rdcapacity;
    rr.rdlength = rdlen;
    if (!SetRData(mDNSNULL, rdata, rdata + rdlen, &rr, rdlen))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[R%u] update_record: SetRData failed for " PRI_DM_NAME " (" PUB_S ")",
            request_id, DM_NAME_PARAM(rr.name), DNSTypeName(rr.rrtype));
        freeL("RData/update_record", newrd);
        return mStatus_BadParamErr;
    }
    rdlen = GetRDLength(&rr, mDNSfalse);
    // BIND named (name daemon) doesn't allow TXT records with zero-length rdata. This is strictly speaking correct,
    // since RFC 1035 specifies a TXT record as "One or more <character-string>s", not "Zero or more <character-string>s".
    // Since some legacy apps try to create zero-length TXT records, we'll silently correct it here.
    if (ar->resrec.rrtype == kDNSType_TXT && rdlen == 0) { rdlen = 1; newrd->u.txt.c[0] = 0; }

    if (external_advertise) ar->UpdateContext = (void *)external_advertise;

    result = mDNS_Update(&mDNSStorage, ar, ttl, rdlen, newrd, update_callback);
    if (result) { LogMsg("update_record: Error %d for %s", (int)result, ARDisplayString(&mDNSStorage, ar)); freeL("RData/update_record", newrd); }
    return result;
}

mDNSlocal mStatus handle_tsr_update_request(const request_state *const request, const AuthRecord *const rr, const mDNSu32 tsrTimestamp)
{
    mStatus result = mStatus_NoError;
    AuthRecord *currentTSR = mDNSGetTSRRecord(&mDNSStorage, rr);
    mDNSs32 timestampContinuous;
    if (!validateTSRTimestamp(&timestampContinuous, tsrTimestamp, rr))
    {
        result = mStatus_BadParamErr;
        goto end;
    }
    if (currentTSR)
    {
        result = updateTSRRecord(request, currentTSR, timestampContinuous);
    }
    else
    {
       LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR, "No existing TSR for " PRI_DM_NAME "", DM_NAME_PARAM(rr->resrec.name));
       result = mStatus_BadReferenceErr;
       goto end;
    }

end:
    return result;
}

mDNSlocal mStatus handle_update_request(request_state *request)
{
    const ipc_msg_hdr *const hdr = &request->hdr;
    mStatus result = mStatus_BadReferenceErr;
    service_instance *i;
    AuthRecord *rr = NULL;
    mDNSBool foundTimestampTLV = mDNSfalse;

    // get the message data
    DNSServiceFlags flags = get_flags (&request->msgptr, request->msgend);  // flags unused
    mDNSu16 rdlen = get_uint16(&request->msgptr, request->msgend);
    const mDNSu8 *const rdata = (const mDNSu8 *)get_rdata(&request->msgptr, request->msgend, rdlen);
    mDNSu32 ttl   = get_uint32(&request->msgptr, request->msgend);
    (void)flags; // Unused

    if (!request->msgptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceUpdateRecord(unreadable parameters)", request->request_id);
        return(mStatus_BadParamErr);
    }

    const mDNSu32 tsrTimestamp = get_service_attr_timestamp_value(request, &foundTimestampTLV);
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[R%d] DNSServiceUpdateRecord foundTimestampTLV[%s], tsrTimestamp[%u]", request->request_id,
            foundTimestampTLV ? "true" : "false", tsrTimestamp);

    // If this is a shared connection, check if the operation actually applies to a subordinate request_state object
    if (request->terminate == connection_termination) request = LocateSubordinateRequest(request);

    if (request->terminate == connection_termination)
    {
        // update an individually registered record
        registered_record_entry *reptr;
        for (reptr = request->u.reg_recs; reptr; reptr = reptr->next)
        {
            if (reptr->key == hdr->reg_index)
            {
                if (foundTimestampTLV)
                {
                    result = handle_tsr_update_request(request, reptr->rr, tsrTimestamp);
                }
                else
                {
                    result = update_record(reptr->rr, rdlen, rdata, ttl, &reptr->external_advertise, request->request_id);
                }
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                       "[R%d] DNSServiceUpdateRecord(" PRI_DM_NAME ", " PUB_S ") PID[%d](" PUB_S ")",
                       request->request_id, DM_NAME_PARAM(reptr->rr->resrec.name),
                       reptr->rr ? foundTimestampTLV ? "TSR" : DNSTypeName(reptr->rr->resrec.rrtype) : "<NONE>",
                       request->process_id, request->pid_name);
                goto end;
            }
        }
        result = mStatus_BadReferenceErr;
        goto end;
    }

    if (request->terminate != regservice_termination_callback)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceUpdateRecord(not a registered service ref)", request->request_id);
        return(mStatus_BadParamErr);
    }

    // For a service registered with zero port, only SRV record is initialized. Don't allow any updates.
    if (mDNSIPPortIsZero(request->u.servicereg.port))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceUpdateRecord: updating the record of a service registered with zero port", request->request_id);
        return(mStatus_BadParamErr);
    }

    // update the saved off TXT data for the service
    if (!foundTimestampTLV && hdr->reg_index == TXT_RECORD_INDEX)
    {
        if (request->u.servicereg.txtdata)
        { freeL("service_info txtdata", request->u.servicereg.txtdata); request->u.servicereg.txtdata = NULL; }
        if (rdlen > 0)
        {
            request->u.servicereg.txtdata = mallocL("service_info txtdata", rdlen);
            if (!request->u.servicereg.txtdata) FatalError("ERROR: handle_update_request - malloc");
            mDNSPlatformMemCopy(request->u.servicereg.txtdata, rdata, rdlen);
        }
        request->u.servicereg.txtlen = rdlen;
    }

    // update a record from a service record set
    for (i = request->u.servicereg.instances; i; i = i->next)
    {
        if (hdr->reg_index == TXT_RECORD_INDEX) rr = &i->srs.RR_TXT;
        else
        {
            ExtraResourceRecord *e;
            for (e = i->srs.Extras; e; e = e->next)
                if (e->ClientID == hdr->reg_index) { rr = &e->r; break; }
        }

        if (!rr) { result = mStatus_BadReferenceErr; goto end; }
        if (foundTimestampTLV)
        {
            result = handle_tsr_update_request(request, rr, tsrTimestamp);
            goto end;
        }
        else
        {
            result = update_record(rr, rdlen, rdata, ttl, &i->external_advertise, request->request_id);
        }
        if (result && i->default_local) goto end;
        else result = mStatus_NoError;  // suppress non-local default errors
    }

end:
    if (request->terminate == regservice_termination_callback)
        LogOperation("%3d: DNSServiceUpdateRecord(%##s, %s)  PID[%d](%s)", request->sd,
                     (request->u.servicereg.instances) ? request->u.servicereg.instances->srs.RR_SRV.resrec.name->c : NULL,
                     rr ? foundTimestampTLV ? "TSR" : DNSTypeName(rr->resrec.rrtype) : "<NONE>",
                     request->process_id, request->pid_name);

    return(result);
}

// remove a resource record registered via DNSServiceRegisterRecord()
mDNSlocal mStatus remove_record(request_state *request)
{
    mStatus err = mStatus_UnknownErr;
    registered_record_entry *e, **ptr = &request->u.reg_recs;

    while (*ptr && (*ptr)->key != request->hdr.reg_index) ptr = &(*ptr)->next;
    if (!*ptr) { LogMsg("%3d: DNSServiceRemoveRecord(%u) not found", request->sd, request->hdr.reg_index); return mStatus_BadReferenceErr; }
    e = *ptr;
    *ptr = e->next; // unlink

    LogOperation("%3d: DNSServiceRemoveRecord(%u %s)  PID[%d](%s)",
                request->sd, e->key, RRDisplayString(&mDNSStorage, &e->rr->resrec), request->process_id, request->pid_name);
    e->rr->RecordContext = NULL;
    if (e->external_advertise)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        external_stop_advertising_service(&e->rr->resrec, request->flags, request->process_id);
#endif
        e->external_advertise = mDNSfalse;
    }
    LogMcastS(e->rr, request, reg_stop);
    err = mDNS_Deregister(&mDNSStorage, e->rr);     // Will free e->rr for us; we're responsible for freeing e
    if (err)
    {
        LogMsg("ERROR: remove_record, mDNS_Deregister: %d", err);
        freeL("registered_record_entry AuthRecord remove_record", e->rr);
    }
    freeL("registered_record_entry remove_record", e);
    return err;
}

mDNSlocal mStatus remove_extra(const request_state *const request, service_instance *const serv, mDNSu16 *const rrtype)
{
    mStatus err = mStatus_BadReferenceErr;
    ExtraResourceRecord *ptr;

    for (ptr = serv->srs.Extras; ptr; ptr = ptr->next)
    {
        if (ptr->ClientID == request->hdr.reg_index) // found match
        {
            *rrtype = ptr->r.resrec.rrtype;
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            if (serv->external_advertise)
            {
                external_stop_advertising_service(&ptr->r.resrec, request->flags, request->process_id);
            }
#endif
            err = mDNS_RemoveRecordFromService(&mDNSStorage, &serv->srs, ptr, FreeExtraRR, ptr);
            break;
        }
    }
    return err;
}

mDNSlocal mStatus handle_removerecord_request(request_state *request)
{
    mStatus err = mStatus_BadReferenceErr;
    get_flags(&request->msgptr, request->msgend);   // flags unused

    if (!request->msgptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceRemoveRecord(unreadable parameters)", request->request_id);
        return(mStatus_BadParamErr);
    }

    // If this is a shared connection, check if the operation actually applies to a subordinate request_state object
    if (request->terminate == connection_termination) request = LocateSubordinateRequest(request);

    // LocateSubordinateRequest returns the connection it was passed if the request is not referring to a
    // subordinate request. In this case, if request->terminate == connection_terminate, that means that this
    // is a connection created with DNSServiceCreateConnection, and so the remove would have to apply to a
    // record added with DNSServiceRegisterRecord. We can remove this using remove_record.
    if (request->terminate == connection_termination)
        err = remove_record(request);

    // Otherwise, the only type of request object to which DNSServiceRemoveRecord could apply is one that
    // was created with DNSServiceRegister, which is indicated by request->terminate == regservice_termination_callback.
    // So if that's not the case, the request is invalid.
    else if (request->terminate != regservice_termination_callback)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%d] DNSServiceRemoveRecord(not a registered service ref)", request->request_id);
        return(mStatus_BadParamErr);
    }
    else
    {
        service_instance *i;
        mDNSu16 rrtype = 0;
        // In this case request is a request created with DNSServiceRegister, and there may be more than one
        // instance if there is more than one default registration domain, so we have to iterate across the
        // instances and remove the record from each instance individually, if it is present.
        for (i = request->u.servicereg.instances; i; i = i->next)
        {
            err = remove_extra(request, i, &rrtype);
            if (err && i->default_local) break;
            else err = mStatus_NoError;  // suppress non-local default errors
        }
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%d] DNSServiceRemoveRecord(" PRI_DM_NAME ", " PUB_S ") PID[%d](" PUB_S "): %d",
                  request->request_id,
                  DM_NAME_PARAM((request->u.servicereg.instances)
                                ? (request->u.servicereg.instances->srs.RR_SRV.resrec.name)
                                : mDNSNULL),
                  rrtype ? DNSTypeName(rrtype) : "<NONE>", request->process_id, request->pid_name, err);
    }

    return(err);
}

// If there's a comma followed by another character,
// FindFirstSubType overwrites the comma with a nul and returns the pointer to the next character.
// Otherwise, it returns a pointer to the final nul at the end of the string
mDNSlocal char *FindFirstSubType(char *p)
{
    while (*p)
    {
        if (p[0] == '\\' && p[1])
        {
             p += 2;
        }
        else if (p[0] == ',' && p[1])
        {
            *p++ = 0;
            return(p);
        }
        else
        {
            p++;
        }
    }
    return(p);
}

// If there's a comma followed by another character,
// FindNextSubType overwrites the comma with a nul and returns the pointer to the next character.
// If it finds an illegal unescaped dot in the subtype name, it returns mDNSNULL
// Otherwise, it returns a pointer to the final nul at the end of the string
mDNSlocal char *FindNextSubType(char *p)
{
    while (*p)
    {
        if (p[0] == '\\' && p[1])       // If escape character
            p += 2;                     // ignore following character
        else if (p[0] == ',')           // If we found a comma
        {
            if (p[1]) *p++ = 0;
            return(p);
        }
        else if (p[0] == '.')
            return(mDNSNULL);
        else p++;
    }
    return(p);
}

// Returns -1 if illegal subtype found
mDNSlocal mDNSs32 ChopSubTypes(char *regtype)
{
    mDNSs32 NumSubTypes = 0;
    char *stp = FindFirstSubType(regtype);
    while (stp && *stp)                 // If we found a comma...
    {
        if (*stp == ',') return(-1);
        NumSubTypes++;
        stp = FindNextSubType(stp);
    }
    if (!stp) return(-1);
    return(NumSubTypes);
}

mDNSlocal AuthRecord *AllocateSubTypes(mDNSu32 NumSubTypes, char *p)
{
    AuthRecord *st = mDNSNULL;
    if (NumSubTypes)
    {
        mDNSu32 i;
        st = (AuthRecord *) callocL("ServiceSubTypes", NumSubTypes * sizeof(AuthRecord));
        if (!st) return(mDNSNULL);
        for (i = 0; i < NumSubTypes; i++)
        {
            mDNS_SetupResourceRecord(&st[i], mDNSNULL, mDNSInterface_Any, kDNSQType_ANY, kStandardTTL, 0, AuthRecordAny, mDNSNULL, mDNSNULL);
            while (*p) p++;
            p++;
            if (!MakeDomainNameFromDNSNameString(&st[i].namestorage, p))
            {
                freeL("ServiceSubTypes", st);
                return(mDNSNULL);
            }
        }
    }
    return(st);
}

mDNSlocal mStatus register_service_instance(request_state *request, const domainname *domain)
{
    service_instance **ptr, *instance;
    size_t extra_size = (request->u.servicereg.txtlen > sizeof(RDataBody)) ? (request->u.servicereg.txtlen - sizeof(RDataBody)) : 0;
    const mDNSBool DomainIsLocal = SameDomainName(domain, &localdomain);
    mStatus result;
    mDNSInterfaceID interfaceID = request->u.servicereg.InterfaceID;
    mDNSBool foundTimestampTLV = mDNSfalse;
    const mDNSu32 tsrTimestamp = get_service_attr_timestamp_value(request, &foundTimestampTLV);
    mDNSs32 timestampContinuous = 0;

    if (foundTimestampTLV)
    {
        if (!validateTSRTimestamp(&timestampContinuous, tsrTimestamp, NULL))
        {
            return mStatus_BadParamErr;
        }
    }

    // If the client specified an interface, but no domain, then we honor the specified interface for the "local" (mDNS)
    // registration but for the wide-area registrations we don't (currently) have any concept of a wide-area unicast
    // registrations scoped to a specific interface, so for the automatic domains we add we must *not* specify an interface.
    // (Specifying an interface with an apparently wide-area domain (i.e. something other than "local")
    // currently forces the registration to use mDNS multicast despite the apparently wide-area domain.)
    if (request->u.servicereg.default_domain && !DomainIsLocal) interfaceID = mDNSInterface_Any;

    for (ptr = &request->u.servicereg.instances; *ptr; ptr = &(*ptr)->next)
    {
        if (SameDomainName(&(*ptr)->domain, domain))
        {
            LogMsg("register_service_instance: domain %##s already registered for %#s.%##s",
                   domain->c, &request->u.servicereg.name, &request->u.servicereg.type);
            return mStatus_AlreadyRegistered;
        }
    }

    instance = (service_instance *) callocL("service_instance", sizeof(*instance) + extra_size);
    if (!instance) { my_perror("ERROR: calloc"); return mStatus_NoMemoryErr; }

    instance->next                          = mDNSNULL;
    instance->request                       = request;
    instance->renameonmemfree               = 0;
    instance->clientnotified                = mDNSfalse;
    instance->default_local                 = (request->u.servicereg.default_domain && DomainIsLocal);
    instance->external_advertise            = mDNSfalse;
    AssignDomainName(&instance->domain, domain);

    instance->subtypes = AllocateSubTypes(request->u.servicereg.num_subtypes, request->u.servicereg.type_as_string);

    if (request->u.servicereg.num_subtypes && !instance->subtypes)
    {
        unlink_and_free_service_instance(instance);
        instance = NULL;
        FatalError("ERROR: malloc");
    }

    result = mDNS_RegisterService(&mDNSStorage, &instance->srs,
                                  &request->u.servicereg.name, &request->u.servicereg.type, domain,
                                  request->u.servicereg.host.c[0] ? &request->u.servicereg.host : NULL,
                                  request->u.servicereg.port,
                                  mDNSNULL, request->u.servicereg.txtdata, request->u.servicereg.txtlen,
                                  instance->subtypes, request->u.servicereg.num_subtypes,
                                  interfaceID, regservice_callback, instance, request->flags);
    if (!result && foundTimestampTLV)
    {
        AuthRecord *currentTSR = mDNSGetTSRRecord(&mDNSStorage, &instance->srs.RR_SRV);

        if (currentTSR)
        {
            result = updateTSRRecord(request, currentTSR, timestampContinuous);
        }
        else
        {
            // tsr timestamp in memory is absolute time of receipt
            mDNSu32 uTimestamp = (mDNSu32)timestampContinuous;
            const mDNSu8 rdata[4] = { (uTimestamp >> 24) & 0xFF, (uTimestamp >> 16) & 0xFF,
                                      (uTimestamp >> 8)  & 0xFF,  uTimestamp        & 0xFF };
            result = add_record_to_service(request, instance, kDNSType_TSR, sizeof(rdata), rdata, kHostNameTTL);
        }
        if (!result)
        {
            LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT, "TSR record added with tsrTimestamp %d", timestampContinuous);
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR, "Failed to add TSR record with tsrTimestamp %u error %d",
                      tsrTimestamp, result);
        }
    }

    if (!result)
    {
        *ptr = instance;        // Append this to the end of our request->u.servicereg.instances list
        LogOperation("%3d: DNSServiceRegister(%##s, %u) ADDED", instance->request->sd,
                     instance->srs.RR_SRV.resrec.name->c, mDNSVal16(request->u.servicereg.port));
        LogMcastS(&instance->srs.RR_SRV, request, reg_start);
    }
    else
    {
        LogMsg("register_service_instance %#s.%##s%##s error %d",
               &request->u.servicereg.name, &request->u.servicereg.type, domain->c, result);
        unlink_and_free_service_instance(instance);
    }

    return result;
}

mDNSlocal void udsserver_default_reg_domain_changed(const DNameListElem *const d, const mDNSBool add)
{
    request_state *request;

    LogMsg("%s registration domain %##s", add ? "Adding" : "Removing", d->name.c);
    for (request = all_requests; request; request = request->next)
    {
        if (request->terminate != regservice_termination_callback) continue;
        if (!request->u.servicereg.default_domain) continue;
        if (!d->uid || SystemUID(request->uid) || request->uid == d->uid)
        {
            service_instance **ptr = &request->u.servicereg.instances;
            while (*ptr && !SameDomainName(&(*ptr)->domain, &d->name)) ptr = &(*ptr)->next;
            if (add)
            {
                // If we don't already have this domain in our list for this registration, add it now
                if (!*ptr) register_service_instance(request, &d->name);
                else debugf("udsserver_default_reg_domain_changed %##s already in list, not re-adding", &d->name);
            }
            else
            {
                // Normally we should not fail to find the specified instance
                // One case where this can happen is if a uDNS update fails for some reason,
                // and regservice_callback then calls unlink_and_free_service_instance and disposes of that instance.
                if (!*ptr)
                    LogMsg("udsserver_default_reg_domain_changed domain %##s not found for service %#s type %s",
                           &d->name, request->u.servicereg.name.c, request->u.servicereg.type_as_string);
                else
                {
                    DNameListElem *p;
                    for (p = AutoRegistrationDomains; p; p=p->next)
                        if (!p->uid || SystemUID(request->uid) || request->uid == p->uid)
                            if (SameDomainName(&d->name, &p->name)) break;
                    if (p) debugf("udsserver_default_reg_domain_changed %##s still in list, not removing", &d->name);
                    else
                    {
                        mStatus err;
                        service_instance *si = *ptr;
                        *ptr = si->next;
                        if (si->clientnotified) SendServiceRemovalNotification(&si->srs); // Do this *before* clearing si->request backpointer
                        // Now that we've cut this service_instance from the list, we MUST clear the si->request backpointer.
                        // Otherwise what can happen is this: While our mDNS_DeregisterService is in the
                        // process of completing asynchronously, the client cancels the entire operation, so
                        // regservice_termination_callback then runs through the whole list deregistering each
                        // instance, clearing the backpointers, and then disposing the parent request_state object.
                        // However, because this service_instance isn't in the list any more, regservice_termination_callback
                        // has no way to find it and clear its backpointer, and then when our mDNS_DeregisterService finally
                        // completes later with a mStatus_MemFree message, it calls unlink_and_free_service_instance() with
                        // a service_instance with a stale si->request backpointer pointing to memory that's already been freed.
                        si->request = NULL;
                        err = mDNS_DeregisterService(&mDNSStorage, &si->srs);
                        if (err) { LogMsg("udsserver_default_reg_domain_changed err %d", err); unlink_and_free_service_instance(si); }
                    }
                }
            }
        }
    }
}

// Returns true if the interfaceIndex value matches one of the pre-defined
// special values listed in the switch statement below.
mDNSlocal mDNSBool PreDefinedInterfaceIndex(mDNSu32 interfaceIndex)
{
    switch(interfaceIndex)
    {
        case kDNSServiceInterfaceIndexAny:
        case kDNSServiceInterfaceIndexLocalOnly:
        case kDNSServiceInterfaceIndexUnicast:
        case kDNSServiceInterfaceIndexP2P:
        case kDNSServiceInterfaceIndexBLE:
            return mDNStrue;
        default:
            return mDNSfalse;
    }
}

mDNSlocal mStatus _handle_regservice_request_start(request_state *request, const domainname * const d)
{
    mStatus err;

    request->terminate = regservice_termination_callback;
    err = register_service_instance(request, d);

#if 0
    err = AuthorizedDomain(request, d, AutoRegistrationDomains) ? register_service_instance(request, d) : mStatus_NoError;
#endif
    if (!err)
    {
        if (request->u.servicereg.autoname) UpdateDeviceInfoRecord(&mDNSStorage);

        if (request->u.servicereg.default_domain)
        {
            DNameListElem *ptr;
            // Note that we don't report errors for non-local, non-explicit domains
            for (ptr = AutoRegistrationDomains; ptr; ptr = ptr->next)
                if (!ptr->uid || SystemUID(request->uid) || request->uid == ptr->uid)
                    register_service_instance(request, &ptr->name);
        }
    }
    return err;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_regservice_request_error(request_state *request, mStatus error)
{
    if (request->u.servicereg.txtdata)
    {
        freeL("service_info txtdata", request->u.servicereg.txtdata);
        request->u.servicereg.txtdata = NULL;
    }

    reply_state *rep;
    if (GenerateNTDResponse(NULL, 0, request, &rep, reg_service_reply_op, 0, error) != mStatus_NoError)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceRegister _return_regservice_request_error: error(%d)", request->request_id, error);
    }
    else
    {
        append_reply(request, rep);
    }
}

mDNSlocal mStatus _handle_regservice_request_with_trust(request_state *request, const domainname * const d)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_regservice_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_regservice_request_start(request, d);
    }
    else
    {
        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_register_service(request->audit_token, request->u.servicereg.type_as_string, &flags);
        switch (status) {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, request->u.servicereg.type_as_string, flags);
                if (!trust)
                {
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                void * context = mallocL("context/_handle_regservice_request_with_trust", sizeof(domainname));
                if (!context)
                {
                    my_perror("ERROR: mallocL context/_handle_regservice_request_with_trust");
                    mdns_release(trust);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                memcpy(context, d, sizeof(domainname));
                mdns_trust_set_context(trust, context);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("context/_handle_regservice_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        const domainname * _d = mdns_trust_get_context(trust);
                        if (_d)
                        {
                            if (!error)
                            {
                                error = _handle_regservice_request_start(request, _d);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_regservice_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_register_service_instance_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_regservice_request_start(request, d);
                break;
        }
    }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

mDNSlocal mStatus handle_regservice_request(request_state *request)
{
    char name[256]; // Lots of spare space for extra-long names that we'll auto-truncate down to 63 bytes
    char domain[MAX_ESCAPED_DOMAIN_NAME], host[MAX_ESCAPED_DOMAIN_NAME];
    char type_as_string[MAX_ESCAPED_DOMAIN_NAME];  // Note that this service type may include a trailing list of subtypes
    domainname d, srv;
    mStatus err;
    const uint8_t *msgTXTData;

    DNSServiceFlags flags = get_flags(&request->msgptr, request->msgend);
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    mDNSInterfaceID InterfaceID;
    mDNSs32 subtypeCount;

    // Map kDNSServiceInterfaceIndexP2P to kDNSServiceInterfaceIndexAny with the
    // kDNSServiceFlagsIncludeP2P flag set.
    if (interfaceIndex == kDNSServiceInterfaceIndexP2P)
    {
        LogOperation("handle_regservice_request: mapping kDNSServiceInterfaceIndexP2P to kDNSServiceInterfaceIndexAny + kDNSServiceFlagsIncludeP2P");
        flags |= kDNSServiceFlagsIncludeP2P;
        interfaceIndex = kDNSServiceInterfaceIndexAny;
    }

    InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);

    // The registration is scoped to a specific interface index, but the
    // interface is not currently in our list.
    if (interfaceIndex && !InterfaceID)
    {
        // If it's one of the specially defined inteface index values, just return an error.
        if (PreDefinedInterfaceIndex(interfaceIndex))
        {
            LogInfo("handle_regservice_request: bad interfaceIndex %d", interfaceIndex);
            return(mStatus_BadParamErr);
        }

        // Otherwise, use the specified interface index value and the registration will
        // be applied to that interface when it comes up.
        InterfaceID = (mDNSInterfaceID)(uintptr_t)interfaceIndex;
        LogInfo("handle_regservice_request: registration pending for interface index %d", interfaceIndex);
    }

    if (get_string(&request->msgptr, request->msgend, name,           sizeof(name          )) < 0 ||
        get_string(&request->msgptr, request->msgend, type_as_string, sizeof(type_as_string)) < 0 ||
        get_string(&request->msgptr, request->msgend, domain,         sizeof(domain        )) < 0 ||
        get_string(&request->msgptr, request->msgend, host,           sizeof(host          )) < 0)
    { LogMsg("ERROR: handle_regservice_request - Couldn't read name/regtype/domain"); return(mStatus_BadParamErr); }

    request->flags = flags;
    request->interfaceIndex = interfaceIndex;
    request->u.servicereg.InterfaceID = InterfaceID;
    request->u.servicereg.instances = NULL;
    request->u.servicereg.txtlen  = 0;
    request->u.servicereg.txtdata = NULL;
    mDNSPlatformStrLCopy(request->u.servicereg.type_as_string, type_as_string, sizeof(request->u.servicereg.type_as_string));

    if (request->msgptr + 2 > request->msgend) request->msgptr = NULL;
    else
    {
        request->u.servicereg.port.b[0] = *request->msgptr++;
        request->u.servicereg.port.b[1] = *request->msgptr++;
    }

    request->u.servicereg.txtlen = get_uint16(&request->msgptr, request->msgend);
    msgTXTData = get_rdata(&request->msgptr, request->msgend, request->u.servicereg.txtlen);

    if (!request->msgptr) { LogMsg("%3d: DNSServiceRegister(unreadable parameters)", request->sd); return(mStatus_BadParamErr); }

    if (request->u.servicereg.txtlen)
    {
        request->u.servicereg.txtdata = mallocL("service_info txtdata", request->u.servicereg.txtlen);
        if (!request->u.servicereg.txtdata) FatalError("ERROR: handle_regservice_request - malloc");
        mDNSPlatformMemCopy(request->u.servicereg.txtdata, msgTXTData, request->u.servicereg.txtlen);
    }

    // Check for sub-types after the service type
    subtypeCount = ChopSubTypes(request->u.servicereg.type_as_string);    // Note: Modifies regtype string to remove trailing subtypes
    if (subtypeCount < 0)
    {
        LogMsg("ERROR: handle_regservice_request - ChopSubTypes failed %s", request->u.servicereg.type_as_string);
        goto bad_param;
    }
    request->u.servicereg.num_subtypes = (mDNSu32)subtypeCount;

    // Don't try to construct "domainname t" until *after* ChopSubTypes has worked its magic
    if (!*request->u.servicereg.type_as_string || !MakeDomainNameFromDNSNameString(&request->u.servicereg.type, request->u.servicereg.type_as_string))
    { LogMsg("ERROR: handle_regservice_request - type_as_string bad %s", request->u.servicereg.type_as_string); goto bad_param; }

    if (!name[0])
    {
        request->u.servicereg.name = mDNSStorage.nicelabel;
        request->u.servicereg.autoname = mDNStrue;
    }
    else
    {
        // If the client is allowing AutoRename, then truncate name to legal length before converting it to a DomainLabel
        if ((flags & kDNSServiceFlagsNoAutoRename) == 0)
        {
            const mDNSu32 newlen = TruncateUTF8ToLength((mDNSu8*)name, mDNSPlatformStrLen(name), MAX_DOMAIN_LABEL);
            name[newlen] = 0;
        }
        if (!MakeDomainLabelFromLiteralString(&request->u.servicereg.name, name))
        { LogMsg("ERROR: handle_regservice_request - name bad %s", name); goto bad_param; }
        request->u.servicereg.autoname = mDNSfalse;
    }

    if (*domain)
    {
        request->u.servicereg.default_domain = mDNSfalse;
        if (!MakeDomainNameFromDNSNameString(&d, domain))
        { LogMsg("ERROR: handle_regservice_request - domain bad %s", domain); goto bad_param; }
    }
    else
    {
        request->u.servicereg.default_domain = mDNStrue;
        MakeDomainNameFromDNSNameString(&d, "local.");
    }

    if (!ConstructServiceName(&srv, &request->u.servicereg.name, &request->u.servicereg.type, &d))
    {
        LogMsg("ERROR: handle_regservice_request - Couldn't ConstructServiceName from, “%#s” “%##s” “%##s”",
               request->u.servicereg.name.c, request->u.servicereg.type.c, d.c); goto bad_param;
    }

    if (!MakeDomainNameFromDNSNameString(&request->u.servicereg.host, host))
    { LogMsg("ERROR: handle_regservice_request - host bad %s", host); goto bad_param; }
    request->u.servicereg.autorename       = (flags & kDNSServiceFlagsNoAutoRename    ) == 0;
    request->u.servicereg.allowremotequery = (flags & kDNSServiceFlagsAllowRemoteQuery) != 0;

    // Some clients use mDNS for lightweight copy protection, registering a pseudo-service with
    // a port number of zero. When two instances of the protected client are allowed to run on one
    // machine, we don't want to see misleading "Bogus client" messages in syslog and the console.
    if (!mDNSIPPortIsZero(request->u.servicereg.port))
    {
        int count = CountExistingRegistrations(&srv, request->u.servicereg.port);
        if (count)
            LogMsg("Client application[%d](%s) registered %d identical instances of service %##s port %u.", request->process_id,
                   request->pid_name, count+1, srv.c, mDNSVal16(request->u.servicereg.port));
    }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceRegister(%X, %d, \"" PRI_S "\", \"" PRI_S "\", \"" PRI_S "\", \"" PRI_S "\", %u) START PID[%d](" PUB_S ")",
           request->request_id, request->flags, interfaceIndex, name, request->u.servicereg.type_as_string, domain, host,
           mDNSVal16(request->u.servicereg.port), request->process_id, request->pid_name);

    // We need to unconditionally set request->terminate, because even if we didn't successfully
    // start any registrations right now, subsequent configuration changes may cause successful
    // registrations to be added, and we'll need to cancel them before freeing this memory.
    // We also need to set request->terminate first, before adding additional service instances,
    // because the udsserver_validatelists uses the request->terminate function pointer to determine
    // what kind of request this is, and therefore what kind of list validation is required.
    request->terminate = NULL;

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    if (os_feature_enabled(mDNSResponder, bonjour_privacy) &&
        (request->u.servicereg.default_domain || IsLocalDomain(&d)))
    {
        err = _handle_regservice_request_with_trust(request, &d);
        if (err == mStatus_NoAuth && request->u.servicereg.txtdata)
        {
            freeL("service_info txtdata", request->u.servicereg.txtdata);
            request->u.servicereg.txtdata = NULL;
        }
    }
    else
    {
        err = _handle_regservice_request_start(request, &d);
    }
#else
    err = _handle_regservice_request_start(request, &d);
#endif

    return(err);

bad_param:
    freeL("handle_regservice_request (txtdata)", request->u.servicereg.txtdata);
    request->u.servicereg.txtdata = NULL;
    return mStatus_BadParamErr;
}

// ***************************************************************************
// MARK: - DNSServiceBrowse

mDNSlocal void FoundInstance(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    DNSServiceFlags flags = AddRecord ? kDNSServiceFlagsAdd : 0;
    request_state *req = question->QuestionContext;
    reply_state *rep;
    (void)m; // Unused

    if (answer->rrtype != kDNSType_PTR)
    { LogMsg("%3d: FoundInstance: Should not be called with rrtype %d (not a PTR record)", req->sd, answer->rrtype); return; }

    if (mDNSOpaque16IsZero(question->TargetQID) && (question->BrowseThreshold > 0) && (question->CurrentAnswers >= question->BrowseThreshold))
    {
        flags |= kDNSServiceFlagsThresholdReached;
    }

    // if returning a negative answer, then use question's name in reply
    if (answer->RecordType == kDNSRecordTypePacketNegative)
    {
        GenerateBrowseReply(&question->qname, answer->InterfaceID, req, &rep, browse_reply_op, flags, kDNSServiceErr_NoSuchRecord);
        goto validReply;
    }

    if (GenerateNTDResponse(&answer->rdata->u.name, answer->InterfaceID, req, &rep, browse_reply_op, flags, mStatus_NoError) != mStatus_NoError)
    {
        if (SameDomainName(&req->u.browser.regtype, (const domainname*)"\x09_services\x07_dns-sd\x04_udp"))
        {
            // Special support to enable the DNSServiceBrowse call made by Bonjour Browser
            // Remove after Bonjour Browser is updated to use DNSServiceQueryRecord instead of DNSServiceBrowse
            GenerateBrowseReply(&answer->rdata->u.name, answer->InterfaceID, req, &rep, browse_reply_op, flags, mStatus_NoError);
            goto validReply;
        }

        LogMsg("%3d: FoundInstance: %##s PTR %##s received from network is not valid DNS-SD service pointer",
               req->sd, answer->name->c, answer->rdata->u.name.c);
        return;
    }

validReply:

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d->Q%d] DNSServiceBrowse(" PRI_DM_NAME ", " PUB_S ") RESULT " PUB_S " interface %d: " PRI_S,
           req->request_id, mDNSVal16(question->TargetQID), DM_NAME_PARAM(&question->qname), DNSTypeName(question->qtype),
           AddRecord ? "ADD" : "RMV", mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNSfalse),
           RRDisplayString(m, answer));

    append_reply(req, rep);
}

mDNSlocal void SetQuestionPolicy(DNSQuestion *q, request_state *req)
{
    q->euid = req->uid;
    // The policy is either based on pid or UUID. Pass a zero pid
    // to the "core" if the UUID is valid. If we always pass the pid,
    // then the "core" needs to determine whether the uuid is valid
    // by examining all the 16 bytes at the time of the policy
    // check and also when setting the delegate socket option. Also, it
    // requires that we zero out the uuid wherever the question is
    // initialized to make sure that it is not interpreted as valid.
    // To prevent these intrusive changes, just pass a zero pid to indicate
    // that pid is not valid when uuid is valid. In future if we need the
    // pid in the question, we will reevaluate this strategy.
    if (req->validUUID)
    {
        mDNSPlatformMemCopy(q->uuid, req->uuid, UUID_SIZE);
        q->pid = 0;
    }
    else
    {
        q->pid = req->process_id;
    }

    //debugf("SetQuestionPolicy: q->euid[%d] q->pid[%d] uuid is valid : %s", q->euid, q->pid, req->validUUID ? "true" : "false");
}

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY)
mDNSlocal CFArrayRef _get_unicast_discovery_dns_services(request_state *info)
{
    CFArrayRef result = NULL;
    CFMutableArrayRef defArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
    require_quiet(defArray, exit);

    util_device_media_access_unicast_addr_enumerate(&info->audit_token,
    ^bool(uint8_t family, uint8_t *addr, uint32_t ifindex)
    {
        mdns_dns_service_definition_t definition = NULL;
        require_quiet(addr, exit);

        definition = mdns_dns_service_definition_create();
        require_quiet(definition, exit);

        mdns_address_t serverAddr;
        if (family == AF_INET) {
            uint32_t ipv4_addr;
            memcpy(&ipv4_addr, addr, sizeof(ipv4_addr));
            serverAddr = mdns_address_create_ipv4(ipv4_addr, mDNSVal16(MulticastDNSPort));
        } else if (family == AF_INET6) {
            uint8_t ipv6_addr[16];
            memcpy(&ipv6_addr, addr, sizeof(ipv6_addr));
            serverAddr = mdns_address_create_ipv6(ipv6_addr, mDNSVal16(MulticastDNSPort), ifindex);
        } else {
            serverAddr = NULL;
        }
        require_quiet(serverAddr, exit);

        OSStatus err = mdns_dns_service_definition_append_server_address(definition, serverAddr);
        mdns_forget(&serverAddr);
        require_noerr(err, exit);

        mdns_dns_service_definition_set_interface_index(definition, ifindex, true);

        CFArrayAppendValue(defArray, definition);

    exit:
        mdns_forget(&definition);
        return true;
    });

    result = defArray;
    defArray = NULL;

exit:
    STRICT_DISPOSE_CF_OBJECT(defArray);
    return result;
}
#endif

mDNSlocal mStatus add_domain_to_browser(request_state *info, const domainname *d)
{
    browser_t *b, *p;
    __block mStatus err;

    for (p = info->u.browser.browsers; p; p = p->next)
    {
        if (SameDomainName(&p->domain, d))
        { debugf("add_domain_to_browser %##s already in list", d->c); return mStatus_AlreadyRegistered; }
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY)
    if (info->sign_result && SameDomainName(d, &localdomain))
    {
        CFArrayRef definitions = _get_unicast_discovery_dns_services(info);
        if (definitions)
        {
            err = mStatus_NoError;
            mdns_cfarray_enumerate(definitions,
            ^ bool (const mdns_dns_service_definition_t definition)
            {
                uint32_t ifIndex = mdns_dns_service_definition_get_interface_index(definition);
                mdns_address_t addr = mdns_dns_service_definition_get_first_address(definition);
                if (!addr)
                {
                    return true;
                }
                browser_t *ubrowse = (browser_t *) callocL("browser_t", sizeof(*ubrowse));
                if (!ubrowse)
                {
                    err = mStatus_NoMemoryErr;
                    return false;
                }
                AssignDomainName(&ubrowse->domain, d);
                SetQuestionPolicy(&ubrowse->q, info);
                ubrowse->q.request_id = info->request_id; // This browse request is started on behalf of the original browse request.
                ubrowse->q.UnicastMDNSResolver = mDNSAddr_from_sockaddr(mdns_address_get_sockaddr(addr));
                mDNSInterfaceID InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, ifIndex);
                err = mDNS_StartBrowse(&mDNSStorage, &ubrowse->q, &info->u.browser.regtype, d, InterfaceID, info->flags,
                                        mDNSfalse, (info->flags & kDNSServiceFlagsBackgroundTrafficClass) != 0, mDNSNULL, info);
                if (err)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                        "[R%u] mDNS_StartBrowse returned error (UNICAST_DISCOVERY) -- "
                        "error: %d, type: " PRI_DM_NAME ", domain: " PRI_DM_NAME,
                        info->request_id, err, DM_NAME_PARAM(&info->u.browser.regtype), DM_NAME_PARAM(d));
                    freeL("browser_t/add_domain_to_browser", ubrowse);
                }
                else
                {
                    ubrowse->next = info->u.browser.browsers;
                    info->u.browser.browsers = ubrowse;
                    LogMcastQ(&ubrowse->q, info, q_start);
                }
                return true;
            });
            STRICT_DISPOSE_CF_OBJECT(definitions);
            if (err != mStatus_NoError) return err;
        }
    }
#endif
    
    b = (browser_t *) callocL("browser_t", sizeof(*b));
    if (!b) return mStatus_NoMemoryErr;
    AssignDomainName(&b->domain, d);
    SetQuestionPolicy(&b->q, info);
    b->q.request_id = info->request_id; // This browse request is started on behalf of the original browse request.
    err = mDNS_StartBrowse(&mDNSStorage, &b->q, &info->u.browser.regtype, d, info->u.browser.interface_id, info->flags,
                            info->u.browser.ForceMCast, (info->flags & kDNSServiceFlagsBackgroundTrafficClass) != 0, FoundInstance, info);
    if (err)
    {
        LogMsg("mDNS_StartBrowse returned %d for type %##s domain %##s", err, info->u.browser.regtype.c, d->c);
        freeL("browser_t/add_domain_to_browser", b);
    }
    else
    {
        b->next = info->u.browser.browsers;
        info->u.browser.browsers = b;

        LogMcastQ(&b->q, info, q_start);
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        if (callExternalHelpers(info->u.browser.interface_id, &b->domain, info->flags))
        {
            domainname tmp;
            ConstructServiceName(&tmp, NULL, &info->u.browser.regtype, &b->domain);
            LogDebug("add_domain_to_browser: calling external_start_browsing_for_service()");
            external_start_browsing_for_service(info->u.browser.interface_id, &tmp, kDNSType_PTR, info->flags, info->process_id);
        }
#endif
    }
    return err;
}

mDNSlocal void browse_termination_callback(request_state *info)
{
    if (info->u.browser.default_domain)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceBrowse Cancel domain enumeration for WAB and mDNS "
            "PID[%d](" PUB_S ")" , info->request_id, info->process_id, info->pid_name);
        // Stop the domain enumeration queries to discover the WAB legacy browse domains
        uDNS_StopWABQueries(&mDNSStorage, UDNS_WAB_LBROWSE_QUERY);

    #if !TARGET_OS_WATCH // Disable the domain enumeration on watch.
        // Stop the domain enumeration queries to discover the automatic browse domains on the local network.
        mDNS_StopDomainEnumeration(&mDNSStorage, &localdomain, mDNS_DomainTypeBrowseAutomatic);
    #endif
    }
    while (info->u.browser.browsers)
    {
        browser_t *ptr = info->u.browser.browsers;

#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        if (callExternalHelpers(ptr->q.InterfaceID, &ptr->domain, ptr->q.flags))
        {
            domainname tmp;
            ConstructServiceName(&tmp, NULL, &info->u.browser.regtype, &ptr->domain);
            LogInfo("browse_termination_callback: calling external_stop_browsing_for_service()");
            external_stop_browsing_for_service(ptr->q.InterfaceID, &tmp, kDNSType_PTR, ptr->q.flags, info->process_id);
        }
#endif
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceBrowse(%X, %d, \"" PRI_DM_NAME "\") STOP PID[%d](" PUB_S ")",
               info->request_id, info->flags, info->interfaceIndex, DM_NAME_PARAM(&ptr->q.qname),
               info->process_id, info->pid_name);

        info->u.browser.browsers = ptr->next;
        mDNS_StopBrowse(&mDNSStorage, &ptr->q);  // no need to error-check result
        LogMcastQ(&ptr->q, info, q_stop);
        freeL("browser_t/browse_termination_callback", ptr);
    }
}

mDNSlocal void udsserver_automatic_browse_domain_changed(const DNameListElem *const d, const mDNSBool add)
{
    request_state *request;
    debugf("udsserver_automatic_browse_domain_changed: %s default browse domain %##s", add ? "Adding" : "Removing", d->name.c);

    for (request = all_requests; request; request = request->next)
    {
        if (request->terminate != browse_termination_callback) continue;    // Not a browse operation
        if (!request->u.browser.default_domain) continue;                   // Not an auto-browse operation
        if (!d->uid || SystemUID(request->uid) || request->uid == d->uid)
        {
            browser_t **ptr = &request->u.browser.browsers;
            while (*ptr && !SameDomainName(&(*ptr)->domain, &d->name)) ptr = &(*ptr)->next;
            if (add)
            {
                // If we don't already have this domain in our list for this browse operation, add it now
                if (!*ptr) add_domain_to_browser(request, &d->name);
                else debugf("udsserver_automatic_browse_domain_changed %##s already in list, not re-adding", &d->name);
            }
            else
            {
                if (!*ptr) LogMsg("udsserver_automatic_browse_domain_changed ERROR %##s not found", &d->name);
                else
                {
                    DNameListElem *p;
                    for (p = AutoBrowseDomains; p; p=p->next)
                        if (!p->uid || SystemUID(request->uid) || request->uid == p->uid)
                            if (SameDomainName(&d->name, &p->name)) break;
                    if (p) debugf("udsserver_automatic_browse_domain_changed %##s still in list, not removing", &d->name);
                    else
                    {
                        browser_t *rem = *ptr;
                        *ptr = (*ptr)->next;
                        mDNS_StopQueryWithRemoves(&mDNSStorage, &rem->q);
                        freeL("browser_t/udsserver_automatic_browse_domain_changed", rem);
                    }
                }
            }
        }
    }
}

mDNSlocal void FreeARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
{
    (void)m;  // unused
    if (result == mStatus_MemFree)
    {
        // On shutdown, mDNS_Close automatically deregisters all records
        // Since in this case no one has called DeregisterLocalOnlyDomainEnumPTR to cut the record
        // from the LocalDomainEnumRecords list, we do this here before we free the memory.
        // (This should actually no longer be necessary, now that we do the proper cleanup in
        // udsserver_exit. To confirm this, we'll log an error message if we do find a record that
        // hasn't been cut from the list yet. If these messages don't appear, we can delete this code.)
        ARListElem **ptr = &LocalDomainEnumRecords;
        while (*ptr && &(*ptr)->ar != rr) ptr = &(*ptr)->next;
        if (*ptr)
        {
            *ptr = (*ptr)->next;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "FreeARElemCallback: Have to cut " PRI_S, ARDisplayString(m, rr));
        }
        mDNSPlatformMemFree(rr->RecordContext);
    }
}

// RegisterLocalOnlyDomainEnumPTR and DeregisterLocalOnlyDomainEnumPTR largely duplicate code in
// "FoundDomain" in uDNS.c for creating and destroying these special mDNSInterface_LocalOnly records.
// We may want to turn the common code into a subroutine.

mDNSlocal void RegisterLocalOnlyDomainEnumPTR(mDNS *m, const domainname *d, int type)
{
    // allocate/register legacy and non-legacy _browse PTR record
    mStatus err;
    ARListElem *ptr = (ARListElem *) mDNSPlatformMemAllocateClear(sizeof(*ptr));

    debugf("Incrementing %s refcount for %##s",
           (type == mDNS_DomainTypeBrowse         ) ? "browse domain   " :
           (type == mDNS_DomainTypeRegistration   ) ? "registration dom" :
           (type == mDNS_DomainTypeBrowseAutomatic) ? "automatic browse" : "?", d->c);

    mDNS_SetupResourceRecord(&ptr->ar, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, 7200, kDNSRecordTypeShared, AuthRecordLocalOnly, FreeARElemCallback, ptr);
    MakeDomainNameFromDNSNameString(&ptr->ar.namestorage, mDNS_DomainTypeNames[type]);
    AppendDNSNameString            (&ptr->ar.namestorage, "local");
    AssignDomainName(&ptr->ar.resrec.rdata->u.name, d);
    err = mDNS_Register(m, &ptr->ar);
    if (err)
    {
        LogMsg("SetSCPrefsBrowseDomain: mDNS_Register returned error %d", err);
        mDNSPlatformMemFree(ptr);
    }
    else
    {
        ptr->next = LocalDomainEnumRecords;
        LocalDomainEnumRecords = ptr;
    }
}

mDNSlocal void DeregisterLocalOnlyDomainEnumPTR(mDNS *m, const domainname *d, int type)
{
    DeregisterLocalOnlyDomainEnumPTR_Internal(m, d, type, mDNSfalse);
}

mDNSexport void DeregisterLocalOnlyDomainEnumPTR_Internal(mDNS *const m, const domainname *const d, const int type,
    const mDNSBool LockHeld)
{
    ARListElem **ptr = &LocalDomainEnumRecords;
    domainname lhs; // left-hand side of PTR, for comparison

    debugf("Decrementing %s refcount for %##s",
           (type == mDNS_DomainTypeBrowse         ) ? "browse domain   " :
           (type == mDNS_DomainTypeRegistration   ) ? "registration dom" :
           (type == mDNS_DomainTypeBrowseAutomatic) ? "automatic browse" : "?", d->c);

    MakeDomainNameFromDNSNameString(&lhs, mDNS_DomainTypeNames[type]);
    AppendDNSNameString            (&lhs, "local");

    while (*ptr)
    {
        if (SameDomainName(&(*ptr)->ar.resrec.rdata->u.name, d) && SameDomainName((*ptr)->ar.resrec.name, &lhs))
        {
            ARListElem *rem = *ptr;
            *ptr = (*ptr)->next;
            if (LockHeld)
            {
                mDNS_Deregister_internal(m, &rem->ar, mDNS_Dereg_normal);
            }
            else
            {
                mDNS_Deregister(m, &rem->ar);
            }
            return;
        }
        else ptr = &(*ptr)->next;
    }
}

mDNSlocal DNameListElem * FindDNameListElem(const mDNSu32 uid, const domainname *const name, DNameListElem *domains)
{
    DNameListElem *domain = NULL;
    for (domain = domains; domain != NULL; domain = domain->next)
    {
        if (SameDomainName(name, &domain->name) && domain->uid == uid)
        {
            break;
        }
    }

    return domain;
}

mDNSlocal void AddAutoBrowseDomain(const mDNSu32 uid, const domainname *const name)
{
    DNameListElem *new = FindDNameListElem(uid, name, AutoBrowseDomains);
    if (new != NULL)
    {
        return;
    }

    new = (DNameListElem *) mDNSPlatformMemAllocateClear(sizeof(*new));
    if (new == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "mDNSPlatformMemAllocateClear failed");
        return;
    }

    AssignDomainName(&new->name, name);
    new->uid = uid;
    new->next = AutoBrowseDomains;
    AutoBrowseDomains = new;
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Automatic browsing domain is added - "
        "domain name: " PRI_DM_NAME ", uid: %u", DM_NAME_PARAM(name), uid);

    udsserver_automatic_browse_domain_changed(new, mDNStrue);
}

mDNSlocal void RmvAutoBrowseDomain(const mDNSu32 uid, const domainname *const name)
{
    DNameListElem **p = &AutoBrowseDomains;
    while (*p && (!SameDomainName(&(*p)->name, name) || (*p)->uid != uid)) p = &(*p)->next;
    if (!*p) LogMsg("RmvAutoBrowseDomain: Got remove event for domain %##s not in list", name->c);
    else
    {
        DNameListElem *ptr = *p;
        *p = ptr->next;
        udsserver_automatic_browse_domain_changed(ptr, mDNSfalse);
        mDNSPlatformMemFree(ptr);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Automatic browsing domain is removed - "
            "domain name: " PRI_DM_NAME ", uid: %u", DM_NAME_PARAM(name), uid);
    }
}

mDNSlocal void SetPrefsBrowseDomains(mDNS *m, DNameListElem *browseDomains, mDNSBool add)
{
    DNameListElem *d;
    for (d = browseDomains; d; d = d->next)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "SetPrefsBrowseDomains is adding/removing domain for Browsing and Automatic Browsing domains - "
            "domain name: " PRI_DM_NAME ", uid: %u, result: " PUB_S, DM_NAME_PARAM(&d->name), d->uid,
            add ? "add" : "remove");
        if (add)
        {
            RegisterLocalOnlyDomainEnumPTR(m, &d->name, mDNS_DomainTypeBrowse);
            // This AddAutoBrowseDomain() is a little bit different with the one in AutomaticBrowseDomainChange(),
            // AutomaticBrowseDomainChange() adds automatic browsing domains with uid 0. Then the added domains can be
            // used by any other browse requests. However, AppendDNameListElem() will also append DNameListElem into
            // browseDomains list with uid == 0, which means the AddAutoBrowseDomain() below will:
            // 1. Add domain with uid == 0, which will add duplicate domains into list.
            // 2. Add domain with uid != 0, which is the valid case we want to handle here.
            // When uid == 0, we should call RegisterLocalOnlyDomainEnumPTR() instead of AddAutoBrowseDomain().
            if (d->uid != 0)
            {
                // The automatic browsing domain is added on behave of the user, which means only the same user that
                // registers the record should be able to browse under this domain. All the browse requests started by
                // other user(different uid) should not see this browsing domain.
                AddAutoBrowseDomain(d->uid, &d->name);
            }
            else
            {
                // Notify AutomaticBrowseDomainChange() to call AddAutoBrowseDomain(0, &d->name); after checking for
                // duplicates.
                RegisterLocalOnlyDomainEnumPTR(m, &d->name, mDNS_DomainTypeBrowseAutomatic);
            }
        }
        else
        {
            DeregisterLocalOnlyDomainEnumPTR(m, &d->name, mDNS_DomainTypeBrowse);
            if (d->uid != 0)
            {
                RmvAutoBrowseDomain(d->uid, &d->name);
            }
            else
            {
                // Notify AutomaticBrowseDomainChange() to call RmvAutoBrowseDomain(0, &d->name); after checking
                // for duplicates.
                DeregisterLocalOnlyDomainEnumPTR(m, &d->name, mDNS_DomainTypeBrowseAutomatic);
            }
        }
    }
}

mDNSlocal void UpdateDeviceInfoRecord(mDNS *const m)
{
    (void)m; // unused
}

mDNSexport void udsserver_handle_configchange(mDNS *const m)
{
    request_state *req;
    service_instance *ptr;
    DNameListElem *RegDomains = NULL;
    DNameListElem *BrowseDomains = NULL;
    DNameListElem *p;

    UpdateDeviceInfoRecord(m);

    // For autoname services, see if the default service name has changed, necessitating an automatic update
    for (req = all_requests; req; req = req->next)
        if (req->terminate == regservice_termination_callback)
            if (req->u.servicereg.autoname && !SameDomainLabelCS(req->u.servicereg.name.c, m->nicelabel.c))
            {
                req->u.servicereg.name = m->nicelabel;
                for (ptr = req->u.servicereg.instances; ptr; ptr = ptr->next)
                {
                    ptr->renameonmemfree = 1;
                    if (ptr->clientnotified) SendServiceRemovalNotification(&ptr->srs);
                    LogInfo("udsserver_handle_configchange: Calling deregister for Service %##s", ptr->srs.RR_PTR.resrec.name->c);
                    if (mDNS_DeregisterService_drt(m, &ptr->srs, mDNS_Dereg_rapid))
                        regservice_callback(m, &ptr->srs, mStatus_MemFree); // If service deregistered already, we can re-register immediately
                }
            }

    // Let the platform layer get the current DNS information
    mDNS_Lock(m);
    mDNSPlatformSetDNSConfig(mDNSfalse, mDNSfalse, mDNSNULL, &RegDomains, &BrowseDomains, mDNSfalse);
    mDNS_Unlock(m);

    // Any automatic registration domains are also implicitly automatic browsing domains
    if (RegDomains) SetPrefsBrowseDomains(m, RegDomains, mDNStrue);                             // Add the new list first
    if (AutoRegistrationDomains) SetPrefsBrowseDomains(m, AutoRegistrationDomains, mDNSfalse);  // Then clear the old list

    // Add any new domains not already in our AutoRegistrationDomains list
    for (p=RegDomains; p; p=p->next)
    {
        DNameListElem **pp = &AutoRegistrationDomains;
        while (*pp && ((*pp)->uid != p->uid || !SameDomainName(&(*pp)->name, &p->name))) pp = &(*pp)->next;
        if (!*pp)       // If not found in our existing list, this is a new default registration domain
        {
            RegisterLocalOnlyDomainEnumPTR(m, &p->name, mDNS_DomainTypeRegistration);
            udsserver_default_reg_domain_changed(p, mDNStrue);
        }
        else            // else found same domainname in both old and new lists, so no change, just delete old copy
        {
            DNameListElem *del = *pp;
            *pp = (*pp)->next;
            mDNSPlatformMemFree(del);
        }
    }

    // Delete any domains in our old AutoRegistrationDomains list that are now gone
    while (AutoRegistrationDomains)
    {
        DNameListElem *del = AutoRegistrationDomains;
        AutoRegistrationDomains = AutoRegistrationDomains->next;        // Cut record from list FIRST,
        DeregisterLocalOnlyDomainEnumPTR(m, &del->name, mDNS_DomainTypeRegistration);
        udsserver_default_reg_domain_changed(del, mDNSfalse);           // before calling udsserver_default_reg_domain_changed()
        mDNSPlatformMemFree(del);
    }

    // Now we have our new updated automatic registration domain list
    AutoRegistrationDomains = RegDomains;

    // Add new browse domains to internal list
    if (BrowseDomains) SetPrefsBrowseDomains(m, BrowseDomains, mDNStrue);

    // Remove old browse domains from internal list
    if (SCPrefBrowseDomains)
    {
        SetPrefsBrowseDomains(m, SCPrefBrowseDomains, mDNSfalse);
        while (SCPrefBrowseDomains)
        {
            DNameListElem *fptr = SCPrefBrowseDomains;
            SCPrefBrowseDomains = SCPrefBrowseDomains->next;
            mDNSPlatformMemFree(fptr);
        }
    }

    // Replace the old browse domains array with the new array
    SCPrefBrowseDomains = BrowseDomains;
}

mDNSexport void FoundNonLocalOnlyAutomaticBrowseDomain(mDNS *const m, DNSQuestion *const q,
    const ResourceRecord *const answer, const QC_result add_record)
{
    (void)q; // unused
    // Only accepts response from network.
    if (answer->InterfaceID == mDNSInterface_BLE || answer->InterfaceID == mDNSInterface_P2P
        || answer->InterfaceID == mDNSInterface_LocalOnly)
    {
        goto exit;
    }
    if (add_record != QC_add && add_record != QC_rmv)
    {
        goto exit;
    }
    if (answer->RecordType == kDNSRecordTypePacketNegative)
    {
        goto exit;
    }

    const domainname *const name = &answer->rdata->u.name;

    if (add_record)
    {
        RegisterLocalOnlyDomainEnumPTR(m, name, mDNS_DomainTypeBrowseAutomatic);

        mDNS_AddDomainDiscoveredForDomainEnumeration(m, &localdomain, mDNS_DomainTypeBrowseAutomatic, name);
    }
    else
    {
        DeregisterLocalOnlyDomainEnumPTR(m, name, mDNS_DomainTypeBrowseAutomatic);

        mDNS_RemoveDomainDiscoveredForDomainEnumeration(m, &localdomain, mDNS_DomainTypeBrowseAutomatic, name);
    }

    const char *const if_name = InterfaceNameForID(m, answer->InterfaceID);
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Automatic browsing domain discovered via network - "
        "change: " PUB_S ", interface name: " PUB_S ", browsing domain: " PRI_DM_NAME,
        add_record == QC_add ? "added" : "removed", if_name, DM_NAME_PARAM(name));

exit:
    return;
}

mDNSlocal void AutomaticBrowseDomainChange(mDNS *const m, DNSQuestion *q, const ResourceRecord *const answer,
    QC_result AddRecord)
{
    (void)m; // unused
    (void)q; // unused

    const mDNSBool ignored = (answer->InterfaceID == mDNSInterface_Any);
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Automatic browsing domain changes - "
        "name: " PRI_DM_NAME ", event: " PUB_S ", interface ID: %p" PUB_S, DM_NAME_PARAM(&answer->rdata->u.name),
        AddRecord == QC_add ? "adding" : "removing", answer->InterfaceID, ignored ? ", ignored." : ".");

    if (ignored)
    {
        return;
    }

    if (AddRecord) AddAutoBrowseDomain(0, &answer->rdata->u.name);
    else RmvAutoBrowseDomain(0, &answer->rdata->u.name);

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
    // We also start the local DNS resolver discovery if the automatic browsing domain discovered is the Thread domain.
    if (SameDomainName(&answer->rdata->u.name, THREAD_DOMAIN_NAME))
    {
        // AutomaticBrowseDomainChange() is called as a callback function where the mDNS_Lock is dropped, to start the
        // resolver discovery process, we need to grab the mDNS_Lock again.
        if (AddRecord == QC_add) {
            resolver_discovery_add(THREAD_DOMAIN_NAME, mDNStrue);
        } else {
            resolver_discovery_remove(THREAD_DOMAIN_NAME, mDNStrue);
        }
    }
#endif
}

mDNSlocal mStatus _handle_browse_request_start(request_state *request, const char *domain)
{
    domainname d;
    mStatus err = mStatus_NoError;

    request->terminate = browse_termination_callback;

    if (domain[0])
    {
        if (!MakeDomainNameFromDNSNameString(&d, domain)) return(mStatus_BadParamErr);
        err = add_domain_to_browser(request, &d);
    }
    else
    {
        DNameListElem *sdom;
        for (sdom = AutoBrowseDomains; sdom; sdom = sdom->next)
            if (!sdom->uid || SystemUID(request->uid) || request->uid == sdom->uid)
            {
                err = add_domain_to_browser(request, &sdom->name);
                if (err)
                {
                    if (SameDomainName(&sdom->name, &localdomain)) break;
                    else err = mStatus_NoError;  // suppress errors for non-local "default" domains
                }
            }
    }

    return(err);
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_browse_request_error(request_state *request, mStatus error)
{
    reply_state *rep;

    GenerateBrowseReply(NULL, 0, request, &rep, browse_reply_op, 0, error);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceBrowse _return_browse_request_error: error (%d)", request->request_id, error);

    append_reply(request, rep);
}

mDNSlocal mStatus _handle_browse_request_with_trust(request_state *request, const char * domain)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_browse_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_browse_request_start(request, domain);
    }
    else
    {
        char typestr[MAX_ESCAPED_DOMAIN_NAME];
        typestr[0] = 0;
        domainlabel dName;
        domainname dType, dDomain;
        if (DeconstructServiceName(&request->u.browser.regtype, &dName, &dType, &dDomain))
        {
            ConvertDomainNameToCString(&dType, typestr);
        }
        else
        {
            ConvertDomainNameToCString(&request->u.browser.regtype, typestr);
        }

        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_bonjour(request->audit_token, typestr, &flags);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
        if ((flags & mdns_trust_flags_system_privileged) != mdns_trust_flags_system_privileged)
        {
            request->sign_result = mDNSfalse; // Reset this flag if not system privileged
        }
        if ((flags & mdns_trust_flags_media_discovery_entitlement) == mdns_trust_flags_media_discovery_entitlement)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "[R%u] _handle_browse_request_with_trust: has media discovery entitlement", request->request_id);
            request->sign_result = mDNStrue; // Always sign results for media discovery entitlement
        }
#endif
        switch (status)
        {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, typestr, flags);
                if (!trust )
                {
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }

                size_t len = strlen(domain) + 1;
                void * context = mallocL("context/_handle_browse_request_with_trust", len);
                if (!context)
                {
                    my_perror("ERROR: mallocL context/_handle_browse_request_with_trust");
                    mdns_release(trust);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                memcpy(context, domain, len);
                mdns_trust_set_context(trust, context);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("context/_handle_browse_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        const char * _domain = mdns_trust_get_context(trust);
                        if (_domain)
                        {
                            if (!error)
                            {
                                error = _handle_browse_request_start(request, _domain);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_browse_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_handle_browse_request_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_browse_request_start(request, domain);
                break;
        }
    }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

mDNSlocal mStatus handle_browse_request(request_state *request)
{
    // Note that regtype may include a trailing subtype
    char regtype[MAX_ESCAPED_DOMAIN_NAME], domain[MAX_ESCAPED_DOMAIN_NAME];
    domainname typedn, temp;
    mDNSs32 NumSubTypes;
    mStatus err = mStatus_NoError;

    DNSServiceFlags flags = get_flags(&request->msgptr, request->msgend);
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    mDNSInterfaceID InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);

    // The browse is scoped to a specific interface index, but the
    // interface is not currently in our list.
    if (interfaceIndex && !InterfaceID)
    {
        // If it's one of the specially defined inteface index values, just return an error.
        if (PreDefinedInterfaceIndex(interfaceIndex))
        {
            LogInfo("handle_browse_request: bad interfaceIndex %d", interfaceIndex);
            return(mStatus_BadParamErr);
        }

        // Otherwise, use the specified interface index value and the browse will
        // be applied to that interface when it comes up.
        InterfaceID = (mDNSInterfaceID)(uintptr_t)interfaceIndex;
        LogInfo("handle_browse_request: browse pending for interface index %d", interfaceIndex);
    }

    if (get_string(&request->msgptr, request->msgend, regtype, sizeof(regtype)) < 0 ||
        get_string(&request->msgptr, request->msgend, domain,  sizeof(domain )) < 0) return(mStatus_BadParamErr);

    if (!request->msgptr) { LogMsg("%3d: DNSServiceBrowse(unreadable parameters)", request->sd); return(mStatus_BadParamErr); }

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    err = get_signed_result_flags_tlvs(request);
    if (err) { LogMsg("%3d: handle_browse_request err reading Validation TLVS", request->sd); return(err); }
#endif

    request->flags = flags;
    request->interfaceIndex = interfaceIndex;
    typedn.c[0] = 0;
    NumSubTypes = ChopSubTypes(regtype);    // Note: Modifies regtype string to remove trailing subtypes
    if (NumSubTypes < 0 || NumSubTypes > 1)
        return(mStatus_BadParamErr);
    if (NumSubTypes == 1)
    {
        if (!AppendDNSNameString(&typedn, regtype + strlen(regtype) + 1))
            return(mStatus_BadParamErr);
    }

    if (!regtype[0] || !AppendDNSNameString(&typedn, regtype)) return(mStatus_BadParamErr);

    if (!MakeDomainNameFromDNSNameString(&temp, regtype)) return(mStatus_BadParamErr);
    // For over-long service types, we only allow domain "local"
    if (temp.c[0] > 15 && domain[0] == 0) mDNSPlatformStrLCopy(domain, "local.", sizeof(domain));

    // Set up browser info
    request->u.browser.ForceMCast = (flags & kDNSServiceFlagsForceMulticast) != 0;
    request->u.browser.interface_id = InterfaceID;
    AssignDomainName(&request->u.browser.regtype, &typedn);
    request->u.browser.default_domain = !domain[0];
    request->u.browser.browsers = NULL;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%d] DNSServiceBrowse(%X, %d, \"" PRI_DM_NAME "\", \"" PRI_S "\") START PID[%d](" PUB_S ")",
           request->request_id, request->flags, interfaceIndex, DM_NAME_PARAM(&request->u.browser.regtype), domain,
           request->process_id, request->pid_name);

    if (request->u.browser.default_domain)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%u] DNSServiceBrowse Start domain enumeration for WAB and mDNS "
            "PID[%d](" PUB_S ")", request->request_id, request->process_id, request->pid_name);
        // Start the domain enumeration queries to discover the WAB browse domains
        uDNS_StartWABQueries(&mDNSStorage, UDNS_WAB_LBROWSE_QUERY);

    #if !TARGET_OS_WATCH // Disable the domain enumeration on watch.
        // Start the domain enumeration queries to discover the automatic browse domains on the local network.
        mDNS_StartDomainEnumeration(&mDNSStorage, &localdomain, mDNS_DomainTypeBrowseAutomatic);
    #endif
    }
    // We need to unconditionally set request->terminate, because even if we didn't successfully
    // start any browses right now, subsequent configuration changes may cause successful
    // browses to be added, and we'll need to cancel them before freeing this memory.
    request->terminate = NULL;

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    domainname d;
    if (!MakeDomainNameFromDNSNameString(&d, domain)) return(mStatus_BadParamErr);

    if (os_feature_enabled(mDNSResponder, bonjour_privacy) &&
        (request->u.browser.default_domain || IsLocalDomain(&d) || request->u.browser.ForceMCast))
    {
        err = _handle_browse_request_with_trust(request, domain);
    }
    else
    {
        err = _handle_browse_request_start(request, domain);
    }
#else
    err = _handle_browse_request_start(request, domain);
#endif

    return(err);
}

// ***************************************************************************
// MARK: - DNSServiceResolve

mDNSlocal void resolve_termination_callback(request_state *request)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceResolve(%X, %d, \"" PRI_DM_NAME "\") STOP PID[%d](" PUB_S ")",
           request->request_id, request->flags, request->interfaceIndex, DM_NAME_PARAM(&request->u.resolve.qtxt.qname),
           request->process_id, request->pid_name);
    mDNS_StopQuery(&mDNSStorage, &request->u.resolve.qtxt);
    mDNS_StopQuery(&mDNSStorage, &request->u.resolve.qsrv);
    LogMcastQ(&request->u.resolve.qsrv, request, q_stop);
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
    if (request->u.resolve.external_advertise)
    {
        external_stop_resolving_service(request->u.resolve.qsrv.InterfaceID, &request->u.resolve.qsrv.qname, request->flags, request->process_id);
    }
#endif
}

typedef struct {
    char            regtype[MAX_ESCAPED_DOMAIN_NAME];
    domainname      fqdn;
    mDNSInterfaceID InterfaceID;
} _resolve_start_params_t;

mDNSlocal mStatus _handle_resolve_request_start(request_state *request, const _resolve_start_params_t * const params)
{
    mStatus err;

    err = mDNS_StartQuery(&mDNSStorage, &request->u.resolve.qsrv);

    if (!err)
    {
        err = mDNS_StartQuery(&mDNSStorage, &request->u.resolve.qtxt);
        if (err)
        {
            mDNS_StopQuery(&mDNSStorage, &request->u.resolve.qsrv);
        }
        else
        {
            request->terminate = resolve_termination_callback;
            LogMcastQ(&request->u.resolve.qsrv, request, q_start);
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
            if (callExternalHelpers(params->InterfaceID, &params->fqdn, request->flags))
            {
                request->u.resolve.external_advertise    = mDNStrue;
                LogInfo("handle_resolve_request: calling external_start_resolving_service()");
                external_start_resolving_service(params->InterfaceID, &params->fqdn, request->flags, request->process_id);
            }
#else
            (void)params;
#endif
        }
    }
    return err;
}

mDNSlocal void resolve_result_callback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord)
{
    size_t len = 0;
    char fullname[MAX_ESCAPED_DOMAIN_NAME], target[MAX_ESCAPED_DOMAIN_NAME] = "0";
    uint8_t *data;
    reply_state *rep;
    request_state *req = question->QuestionContext;
    const DNSServiceErrorType error =
        (answer->RecordType == kDNSRecordTypePacketNegative) ? kDNSServiceErr_NoSuchRecord : kDNSServiceErr_NoError;
    (void)m; // Unused

    LogOperation("%3d: DNSServiceResolve(%##s) %s interface %d: %s",
        req->sd, question->qname.c, AddRecord ? "ADD" : "RMV",
        mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNSfalse), RRDisplayString(m, answer));

    if (!AddRecord)
    {
        if (req->u.resolve.srv == answer) req->u.resolve.srv = mDNSNULL;
        if (req->u.resolve.txt == answer) req->u.resolve.txt = mDNSNULL;
        return;
    }

    if (answer->rrtype == kDNSType_SRV) req->u.resolve.srv = answer;
    if (answer->rrtype == kDNSType_TXT) req->u.resolve.txt = answer;

    if (!req->u.resolve.txt || !req->u.resolve.srv) return;     // only deliver result to client if we have both answers

    ConvertDomainNameToCString(answer->name, fullname);

    if (answer->RecordType != kDNSRecordTypePacketNegative)
        ConvertDomainNameToCString(&req->u.resolve.srv->rdata->u.srv.target, target);

    mDNSu32 interface_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNSfalse);
    // calculate reply length
    len += sizeof(DNSServiceFlags);
    len += sizeof(mDNSu32);  // interface index
    len += sizeof(DNSServiceErrorType);
    len += strlen(fullname) + 1;
    len += strlen(target) + 1;
    len += 2 * sizeof(mDNSu16);  // port, txtLen
    len += req->u.resolve.txt->rdlength;
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    mdns_signed_resolve_result_t signed_result = NULL;
    const uint8_t *signed_data = NULL;
    uint16_t signed_data_length = 0;
    if (req->sign_result && req->signed_obj && AddRecord)
    {
        OSStatus err;
        mdns_signed_browse_result_t browseResult = mdns_signed_browse_result_downcast(req->signed_obj);
        if (!browseResult)
        {
            err = mStatus_Invalid;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "[R%u->Q%u] resolve_result_callback mdns_signed_resolve_result_downcast failed",
                req->request_id, mDNSVal16(question->TargetQID));
        }
        else
        {
            signed_result = mdns_signed_resolve_result_create(browseResult, req->u.resolve.srv->rdata->u.srv.target.c,
                req->u.resolve.srv->rdata->u.srv.port.NotAnInteger, interface_index, req->u.resolve.txt->rdata->u.data,
                req->u.resolve.txt->rdlength, &err);
        }
        if (!signed_result || err != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "[R%u->Q%u] resolve_result_callback signed_resolve failed %ld", req->request_id,
                mDNSVal16(question->TargetQID), (long)err);
        }
        else
        {
            size_t temp_size = 0;
            const uint8_t * temp_data = mdns_signed_result_get_data(signed_result, &temp_size);
            if (temp_size <= UINT16_MAX)
            {
                signed_data = temp_data;
                signed_data_length = (uint16_t)temp_size;
                len += get_required_tlv_length(signed_data_length);
            }
        }
    }
#endif

    // allocate/init reply header
    rep = create_reply(resolve_reply_op, len, req);
    rep->rhdr->flags = dnssd_htonl(0);
    rep->rhdr->ifi   = dnssd_htonl(interface_index);
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)error);

    data = (uint8_t *)&rep->rhdr[1];

    // write reply data to message
    put_string(fullname, &data);
    put_string(target, &data);
    *data++ =  req->u.resolve.srv->rdata->u.srv.port.b[0];
    *data++ =  req->u.resolve.srv->rdata->u.srv.port.b[1];
    put_uint16(req->u.resolve.txt->rdlength, &data);
    put_rdata(req->u.resolve.txt->rdlength, req->u.resolve.txt->rdata->u.data, &data);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    if (signed_data)
    {
        put_signed_result_tlvs(signed_data, signed_data_length, rep->mhdr, &data, data+len);
    }
    mdns_forget(&signed_result);
#endif

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%d->Q%d] DNSServiceResolve(" PRI_S ") RESULT   " PRI_S ":%d",
           req->request_id, mDNSVal16(question->TargetQID), fullname, target,
           mDNSVal16(req->u.resolve.srv->rdata->u.srv.port));
    append_reply(req, rep);
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_resolve_request_error(request_state * request, mStatus error)
{
    size_t len;
    char * emptystr = "\0";
    uint8_t *data;
    reply_state *rep;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
       "[R%u] DNSServiceResolve _return_resolve_request_error: error(%d)", request->request_id, error);

    // calculate reply length
    len = sizeof(DNSServiceFlags);
    len += sizeof(mDNSu32);  // interface index
    len += sizeof(DNSServiceErrorType);
    len += 2; // name, target
    len += 2 * sizeof(mDNSu16);  // port, txtLen
    len += 0; //req->u.resolve.txt->rdlength;

    rep = create_reply(resolve_reply_op, len, request);

    rep->rhdr->flags = 0;
    rep->rhdr->ifi   = 0;
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)error);

    data = (uint8_t *)&rep->rhdr[1];

    // write reply data to message
    put_string(emptystr, &data); // name
    put_string(emptystr, &data); // target
    put_uint16(0,        &data); // port
    put_uint16(0,        &data); // txtLen

    append_reply(request, rep);
}

mDNSlocal mStatus _handle_resolve_request_with_trust(request_state *request, const _resolve_start_params_t * const params)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_resolve_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_resolve_request_start(request, params);
    }
    else
    {
        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_bonjour(request->audit_token, params->regtype, &flags);
        switch (status)
        {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, params->regtype, flags);
                if (!trust )
                {
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }

                void * context = mallocL("context/_handle_resolve_request_with_trust", sizeof(_resolve_start_params_t));
                if (!context)
                {
                    my_perror("ERROR: mallocL context/_handle_resolve_request_with_trust");
                    mdns_release(trust);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                memcpy(context, params, sizeof(_resolve_start_params_t));
                mdns_trust_set_context(trust, context);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("context/_handle_resolve_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        _resolve_start_params_t * _params =  mdns_trust_get_context(trust);
                        if (_params)
                        {
                            if (!error)
                            {
                                error = _handle_resolve_request_start(request, _params);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_resolve_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_handle_resolve_request_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_resolve_request_start(request, params);
                break;
        }
    }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

mDNSlocal mStatus handle_resolve_request(request_state *request)
{
    char name[256], domain[MAX_ESCAPED_DOMAIN_NAME];
    _resolve_start_params_t params;
    mStatus err;

    // extract the data from the message
    DNSServiceFlags flags = get_flags(&request->msgptr, request->msgend);
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);

    // Map kDNSServiceInterfaceIndexP2P to kDNSServiceInterfaceIndexAny with the kDNSServiceFlagsIncludeP2P
    // flag set so that the resolve will run over P2P interfaces that are not yet created.
    if (interfaceIndex == kDNSServiceInterfaceIndexP2P)
    {
        LogOperation("handle_resolve_request: mapping kDNSServiceInterfaceIndexP2P to kDNSServiceInterfaceIndexAny + kDNSServiceFlagsIncludeP2P");
        flags |= kDNSServiceFlagsIncludeP2P;
        interfaceIndex = kDNSServiceInterfaceIndexAny;
    }

    params.InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);

    // The operation is scoped to a specific interface index, but the
    // interface is not currently in our list.
    if (interfaceIndex && !params.InterfaceID)
    {
        // If it's one of the specially defined inteface index values, just return an error.
        if (PreDefinedInterfaceIndex(interfaceIndex))
        {
            LogInfo("handle_resolve_request: bad interfaceIndex %d", interfaceIndex);
            return(mStatus_BadParamErr);
        }

        // Otherwise, use the specified interface index value and the operation will
        // be applied to that interface when it comes up.
        params.InterfaceID = (mDNSInterfaceID)(uintptr_t)interfaceIndex;
        LogInfo("handle_resolve_request: resolve pending for interface index %d", interfaceIndex);
    }

    if (get_string(&request->msgptr, request->msgend, name,           sizeof(name   )) < 0 ||
        get_string(&request->msgptr, request->msgend, params.regtype, sizeof(params.regtype)) < 0 ||
        get_string(&request->msgptr, request->msgend, domain,         sizeof(domain )) < 0)
    { LogMsg("ERROR: handle_resolve_request - Couldn't read name/regtype/domain"); return(mStatus_BadParamErr); }

    if (!request->msgptr) { LogMsg("%3d: DNSServiceResolve(unreadable parameters)", request->sd); return(mStatus_BadParamErr); }

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    err = get_signed_browse_tlvs(request);
    if (err) { LogMsg("%3d: handle_resolve_request err reading Validation TLVS", request->sd); return(err); }
#endif

    if (build_domainname_from_strings(&params.fqdn, name, params.regtype, domain) < 0)
    { LogMsg("ERROR: handle_resolve_request bad “%s” “%s” “%s”", name, params.regtype, domain); return(mStatus_BadParamErr); }

    mDNSPlatformMemZero(&request->u.resolve, sizeof(request->u.resolve));

    request->flags = flags;
    request->interfaceIndex = interfaceIndex;

    // format questions
    request->u.resolve.qsrv.InterfaceID      = params.InterfaceID;
    request->u.resolve.qsrv.flags            = flags;
    AssignDomainName(&request->u.resolve.qsrv.qname, &params.fqdn);
    request->u.resolve.qsrv.qtype            = kDNSType_SRV;
    request->u.resolve.qsrv.qclass           = kDNSClass_IN;
    request->u.resolve.qsrv.LongLived        = (flags & kDNSServiceFlagsLongLivedQuery     ) != 0;
    request->u.resolve.qsrv.ExpectUnique     = mDNStrue;
    request->u.resolve.qsrv.ForceMCast       = (flags & kDNSServiceFlagsForceMulticast     ) != 0;
    request->u.resolve.qsrv.ReturnIntermed   = (flags & kDNSServiceFlagsReturnIntermediates) != 0;
    request->u.resolve.qsrv.SuppressUnusable = mDNSfalse;
    request->u.resolve.qsrv.AppendSearchDomains = 0;
    request->u.resolve.qsrv.TimeoutQuestion  = 0;
    request->u.resolve.qsrv.WakeOnResolve    = (flags & kDNSServiceFlagsWakeOnResolve) != 0;
    request->u.resolve.qsrv.UseBackgroundTraffic = (flags & kDNSServiceFlagsBackgroundTrafficClass) != 0;
    request->u.resolve.qsrv.ProxyQuestion    = 0;
    request->u.resolve.qsrv.pid              = request->process_id;
    request->u.resolve.qsrv.euid             = request->uid;
    request->u.resolve.qsrv.QuestionCallback = resolve_result_callback;
    request->u.resolve.qsrv.QuestionContext  = request;

    request->u.resolve.qtxt.InterfaceID      = params.InterfaceID;
    request->u.resolve.qtxt.flags            = flags;
    AssignDomainName(&request->u.resolve.qtxt.qname, &params.fqdn);
    request->u.resolve.qtxt.qtype            = kDNSType_TXT;
    request->u.resolve.qtxt.qclass           = kDNSClass_IN;
    request->u.resolve.qtxt.LongLived        = (flags & kDNSServiceFlagsLongLivedQuery     ) != 0;
    request->u.resolve.qtxt.ExpectUnique     = mDNStrue;
    request->u.resolve.qtxt.ForceMCast       = (flags & kDNSServiceFlagsForceMulticast     ) != 0;
    request->u.resolve.qtxt.ReturnIntermed   = (flags & kDNSServiceFlagsReturnIntermediates) != 0;
    request->u.resolve.qtxt.SuppressUnusable = mDNSfalse;
    request->u.resolve.qtxt.AppendSearchDomains = 0;
    request->u.resolve.qtxt.TimeoutQuestion  = 0;
    request->u.resolve.qtxt.WakeOnResolve    = 0;
    request->u.resolve.qtxt.UseBackgroundTraffic = (flags & kDNSServiceFlagsBackgroundTrafficClass) != 0;
    request->u.resolve.qtxt.ProxyQuestion    = 0;
    request->u.resolve.qtxt.pid              = request->process_id;
    request->u.resolve.qtxt.euid             = request->uid;
    request->u.resolve.qtxt.QuestionCallback = resolve_result_callback;
    request->u.resolve.qtxt.QuestionContext  = request;

    request->u.resolve.ReportTime            = NonZeroTime(mDNS_TimeNow(&mDNSStorage) + 130 * mDNSPlatformOneSecond);

    request->u.resolve.external_advertise    = mDNSfalse;

#if 0
    if (!AuthorizedDomain(request, &fqdn, AutoBrowseDomains)) return(mStatus_NoError);
#endif

    // ask the questions
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceResolve(%X, %d, \"" PRI_DM_NAME "\") START PID[%d](" PUB_S ")",
           request->request_id, flags, interfaceIndex, DM_NAME_PARAM(&request->u.resolve.qsrv.qname),
           request->process_id, request->pid_name);

    request->terminate = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    mDNSBool trust_check_done = mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    if (request->signed_obj)
    {
        mdns_signed_browse_result_t browseResult = mdns_signed_browse_result_downcast(request->signed_obj);
        if (browseResult &&
            mdns_signed_browse_result_contains(browseResult, params.fqdn.c, interfaceIndex))
        {
            if (mdns_system_is_signed_result_uuid_valid(mdns_signed_result_get_uuid(browseResult)))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                       "[R%d] DNSServiceResolve: Allowing signed result",
                          request->request_id);
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
                trust_check_done = mDNStrue;
#endif
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                       "[R%d] DNSServiceResolve: Signed result UUID revoked.",
                          request->request_id);
                return mStatus_PolicyDenied;
            }
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                   "[R%d] DNSServiceResolve: Signed result does not cover service: " PRI_DM_NAME ", ifindex: %u.",
                      request->request_id, DM_NAME_PARAM(&request->u.resolve.qsrv.qname), interfaceIndex);
            request->sign_result = mDNSfalse;
            mdns_forget(&request->signed_obj);
        }
    }
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    domainname d;
    if (!MakeDomainNameFromDNSNameString(&d, domain)) return(mStatus_BadParamErr);

    if (!trust_check_done                                   &&
        os_feature_enabled(mDNSResponder, bonjour_privacy)  &&
        (IsLocalDomain(&d) || request->u.resolve.qsrv.ForceMCast))
    {
        err = _handle_resolve_request_with_trust(request, &params);
    }
    else
    {
        err = _handle_resolve_request_start(request, &params);
    }
#else
    err = _handle_resolve_request_start(request, &params);
#endif

    return(err);
}

// ***************************************************************************
// MARK: - DNSServiceQueryRecord

mDNSlocal void queryrecord_result_reply(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, QC_result AddRecord, DNSServiceErrorType error, void *context)
{
    char name[MAX_ESCAPED_DOMAIN_NAME];
    size_t len;
    DNSServiceFlags flags = 0;
    reply_state *rep;
    uint8_t *data;
    request_state *req = (request_state *)context;

    ConvertDomainNameToCString(answer->name, name);

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    dnssec_result_t dnssec_result = dnssec_indeterminate;
    if (dns_question_is_dnssec_requestor(question))
    {
        flags |= dns_service_flags_init_with_dnssec_result(question, answer);
        dnssec_result = resource_record_get_validation_result(answer);
    }
#endif

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
       "[R%u->Q%u] DNSService" PUB_S "(" PRI_DM_NAME ", " PUB_DNS_TYPE ") RESULT " PUB_ADD_RMV " interface %d: (" PUB_MORTALITY ", " PUB_DNSSEC_RESULT ")" PRI_S,
       req->request_id, mDNSVal16(question->TargetQID), req->hdr.op == query_request ? "QueryRecord" : "GetAddrInfo",
       DM_NAME_PARAM(&question->qname), DNS_TYPE_PARAM(question->qtype), ADD_RMV_PARAM(AddRecord),
       mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNSfalse),
       MORTALITY_PARAM(answer->mortality), DNSSEC_RESULT_PARAM(dnssec_result), RRDisplayString(m, answer));

    // Call mDNSPlatformInterfaceIndexfromInterfaceID, but suppressNetworkChange (last argument). Otherwise, if the
    // InterfaceID is not valid, then it simulates a "NetworkChanged" which in turn makes questions
    // to be stopped and started including  *this* one. Normally the InterfaceID is valid. But when we
    // are using the /etc/hosts entries to answer a question, the InterfaceID may not be known to the
    // mDNS core . Eventually, we should remove the calls to "NetworkChanged" in
    // mDNSPlatformInterfaceIndexfromInterfaceID when it can't find InterfaceID as ResourceRecords
    // should not have existed to answer this question if the corresponding interface is not valid.
    mDNSu32 interface_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNStrue);
    len = sizeof(DNSServiceFlags);  // calculate reply data length
    len += sizeof(mDNSu32);     // interface index
    len += sizeof(DNSServiceErrorType);
    len += strlen(name) + 1;
    len += 3 * sizeof(mDNSu16); // type, class, rdlen
    len += answer->rdlength;
    len += sizeof(mDNSu32);     // TTL
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    mdns_signed_result_t signed_result = NULL;
    const uint8_t *signed_data = NULL;
    uint16_t signed_data_length = 0;
    if (req->sign_result && req->signed_obj && AddRecord &&
        (answer->rrtype == kDNSType_A || answer->rrtype == kDNSType_AAAA || answer->rrtype == kDNSType_TXT))
    {
        OSStatus err = 0;
        if (answer->rrtype == kDNSType_A || answer->rrtype == kDNSType_AAAA)
        {
            mdns_signed_hostname_result_t hostnameResult = NULL;
            mdns_signed_resolve_result_t resolveResult = mdns_signed_resolve_result_downcast(req->signed_obj);
            if (!resolveResult)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                    "[R%u->Q%u] queryrecord_result_reply mdns_signed_resolve_result_downcast failed",
                    req->request_id, mDNSVal16(question->TargetQID));
            }
            else
            {
                if (answer->rrtype == kDNSType_AAAA)
                {
                    hostnameResult = mdns_signed_hostname_result_create_ipv6(resolveResult, answer->rdata->u.data,
                        interface_index, &err);
                }
                else if (answer->rrtype == kDNSType_A)
                {
                    hostnameResult = mdns_signed_hostname_result_create_ipv4(resolveResult, answer->rdata->u.data, &err);
                }

                if (hostnameResult)
                {
                    signed_result = mdns_signed_result_upcast(hostnameResult);
                }
            }
        }
        else if (answer->rrtype == kDNSType_TXT)
        {
            mdns_signed_browse_result_t newBrowseResult = NULL;
            mdns_signed_browse_result_t browseResult = mdns_signed_browse_result_downcast(req->signed_obj);
            if (!browseResult)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                    "[R%u->Q%u] queryrecord_result_reply mdns_signed_browse_result_downcast failed",
                    req->request_id, mDNSVal16(question->TargetQID));
            }
            else
            {
                newBrowseResult = mdns_signed_browse_result_create_txt_variant(browseResult, interface_index,
                    answer->rdata->u.data, answer->rdlength, &err);
                if (newBrowseResult)
                {
                    signed_result = mdns_signed_result_upcast(newBrowseResult);
                }
            }
        }
        if (!signed_result || err != 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "[R%u->Q%u] queryrecord_result_reply signed_result failed %ld",
                req->request_id, mDNSVal16(question->TargetQID), (long)err);
        }
        else
        {
            size_t temp_size = 0;
            const uint8_t * temp_data = mdns_signed_result_get_data(signed_result, &temp_size);
            if (temp_size <= UINT16_MAX)
            {
                signed_data = temp_data;
                signed_data_length = (uint16_t)temp_size;
                len += get_required_tlv_length(signed_data_length);
            }
        }
    }
#endif

    rep = create_reply(req->hdr.op == query_request ? query_reply_op : addrinfo_reply_op, len, req);

    if (AddRecord)
        flags |= kDNSServiceFlagsAdd;
    if (answer->mortality == Mortality_Ghost)
        flags |= kDNSServiceFlagsExpiredAnswer;
    if (!question->InitialCacheMiss)
        flags |= kDNSServiceFlagAnsweredFromCache;

    rep->rhdr->flags = dnssd_htonl(flags);
    rep->rhdr->ifi   = dnssd_htonl(interface_index);
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)error);

    data = (uint8_t *)&rep->rhdr[1];

    put_string(name,             &data);
    put_uint16(answer->rrtype,   &data);
    put_uint16(answer->rrclass,  &data);
    put_uint16(answer->rdlength, &data);
    // We need to use putRData here instead of the crude put_rdata function, because the crude put_rdata
    // function just does a blind memory copy without regard to structures that may have holes in them.
    if (answer->rdlength)
        if (!putRData(mDNSNULL, (mDNSu8 *)data, (mDNSu8 *)rep->rhdr + len, answer))
            LogMsg("queryrecord_result_reply putRData failed %d", (mDNSu8 *)rep->rhdr + len - (mDNSu8 *)data);
    data += answer->rdlength;
    put_uint32(AddRecord ? answer->rroriginalttl : 0, &data);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    if (signed_data)
    {
        put_signed_result_tlvs(signed_data, signed_data_length, rep->mhdr, &data, data+len);
    }
    mdns_forget(&signed_result);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
    if (resolved_cache_is_enabled() && AddRecord &&
        ((answer->rrtype == kDNSType_A) || (answer->rrtype == kDNSType_AAAA)))
    {
        resolved_cache_update_tracking(question);
    }
#endif
    append_reply(req, rep);
}

mDNSlocal void queryrecord_termination_callback(request_state *request)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%u] DNSServiceQueryRecord(%X, %d, " PRI_DM_NAME ", " PUB_S ") STOP PID[%d](" PUB_S ")",
           request->request_id, request->flags, request->interfaceIndex,
           DM_NAME_PARAM(QueryRecordClientRequestGetQName(&request->u.queryrecord)),
           DNSTypeName(QueryRecordClientRequestGetType(&request->u.queryrecord)), request->process_id, request->pid_name);

    QueryRecordClientRequestStop(&request->u.queryrecord);
}

typedef struct
{
    QueryRecordClientRequestParams cr;
    char qname[MAX_ESCAPED_DOMAIN_NAME];
} uds_queryrecord_params_t;

static void _uds_queryrecord_params_init(uds_queryrecord_params_t *const params)
{
    mDNSPlatformMemZero(params, (mDNSu32)sizeof(*params));
    QueryRecordClientRequestParamsInit(&params->cr);
    params->cr.qnameStr = params->qname;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
static void _uds_queryrecord_params_copy(uds_queryrecord_params_t *const dst, const uds_queryrecord_params_t *const src)
{
	*dst = *src;
    dst->cr.qnameStr = dst->qname; // Must point to own qname buffer.
}
#endif

mDNSlocal mStatus _handle_queryrecord_request_start(request_state *request, const uds_queryrecord_params_t *const params)
{
    request->terminate = queryrecord_termination_callback;
    return QueryRecordClientRequestStart(&request->u.queryrecord, &params->cr, queryrecord_result_reply, request);
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_queryrecord_request_error(request_state * request, mStatus error)
{
    size_t len;
    char * emptystr = "\0";
    uint8_t *data;
    reply_state *rep;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
       "[R%u] DNSService" PUB_S " _return_queryrecord_request_error: error(%d)",
       request->request_id, request->hdr.op == query_request ? "QueryRecord" : "GetAddrInfo", error);

    len = sizeof(DNSServiceFlags);  // calculate reply data length
    len += sizeof(mDNSu32);     // interface index
    len += sizeof(DNSServiceErrorType);
    len += strlen(emptystr) + 1;
    len += 3 * sizeof(mDNSu16); // type, class, rdlen
    len += 0;//answer->rdlength;
    len += sizeof(mDNSu32);     // TTL

    rep = create_reply(request->hdr.op == query_request ? query_reply_op : addrinfo_reply_op, len, request);

    rep->rhdr->flags = 0;
    rep->rhdr->ifi   = 0;
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)error);

    data = (uint8_t *)&rep->rhdr[1];

    put_string(emptystr,    &data);
    put_uint16(0,           &data);
    put_uint16(0,           &data);
    put_uint16(0,           &data);
    data += 0;
    put_uint32(0,           &data);

    append_reply(request, rep);
}

mDNSlocal mStatus _handle_queryrecord_request_with_trust(request_state *request,
    const uds_queryrecord_params_t *const params)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_queryrecord_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_queryrecord_request_start(request, params);
    }
    else
    {
        const char *service_ptr = NULL;
        char type_str[MAX_ESCAPED_DOMAIN_NAME] = "";
        domainname query_name;
        if (MakeDomainNameFromDNSNameString(&query_name, params->qname))
        {
            domainlabel name;
            domainname type, domain;
            bool good = DeconstructServiceName(&query_name, &name, &type, &domain);
            if (good)
            {
                ConvertDomainNameToCString(&type, type_str);
                service_ptr = type_str;
            }
        }

        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_query(request->audit_token, params->qname, service_ptr,
            params->cr.qtype, (params->cr.flags & kDNSServiceFlagsForceMulticast) != 0, &flags);
        switch (status)
        {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, service_ptr, flags);
                if (!trust )
                {
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }

                uds_queryrecord_params_t *const context =
                    (uds_queryrecord_params_t *)mallocL("context/_handle_queryrecord_request_with_trust", sizeof(*context));
                if (!context)
                {
                    my_perror("ERROR: mallocL context/_handle_queryrecord_request_with_trust");
                    mdns_release(trust);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                _uds_queryrecord_params_copy(context, params);
                mdns_trust_set_context(trust, context);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("context/_handle_queryrecord_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        uds_queryrecord_params_t * _params =  mdns_trust_get_context(trust);
                        if (_params)
                        {
                            if (!error)
                            {
                                error = _handle_queryrecord_request_start(request, _params);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_queryrecord_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_handle_queryrecord_request_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_queryrecord_request_start(request, params);
                break;
        }
    }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

#if MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)
mDNSlocal void get_queryrecord_tlvs(request_state *const request, uds_queryrecord_params_t *const params)
{
    if (request->msgptr && (request->hdr.ipc_flags & IPC_FLAGS_TRAILING_TLVS))
    {
        const mDNSu8 *const start = (const mDNSu8 *)request->msgptr;
        const mDNSu8 *const end   = (const mDNSu8 *)request->msgend;
        const mDNSu32 aaaaPolicy = get_tlv_uint32(start, end, IPC_TLV_TYPE_SERVICE_ATTR_AAAA_POLICY, mDNSNULL);
        params->cr.useAAAAFallback = (aaaaPolicy == kDNSServiceAAAAPolicyFallback);
        const mDNSu32 failoverPolicy = get_tlv_uint32(start, end, IPC_TLV_TYPE_SERVICE_ATTR_FAILOVER_POLICY, mDNSNULL);
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        params->cr.useFailover = (failoverPolicy == kDNSServiceFailoverPolicyAllow);
        size_t len;
        const mDNSu8 *const data = get_tlv(start, end, IPC_TLV_TYPE_RESOLVER_CONFIG_PLIST_DATA, &len);
        if (data)
        {
            params->cr.customID = Querier_RegisterCustomDNSServiceWithPListData(data, len);
            request->custom_service_id = params->cr.customID;
        }
        params->cr.needEncryption = (get_tlv_uint32(start, end, IPC_TLV_TYPE_REQUIRE_PRIVACY, mDNSNULL) != 0);
#endif
    }
}
#endif

mDNSlocal mStatus handle_queryrecord_request(request_state *request)
{
    mStatus err;
    uds_queryrecord_params_t params;
    _uds_queryrecord_params_init(&params);
    params.cr.flags          = get_flags(&request->msgptr, request->msgend);
    params.cr.interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    if (get_string(&request->msgptr, request->msgend, params.qname, sizeof(params.qname)) < 0)
    {
        err = mStatus_BadParamErr;
        goto exit;
    }
    params.cr.qtype          = get_uint16(&request->msgptr, request->msgend);
    params.cr.qclass         = get_uint16(&request->msgptr, request->msgend);
    params.cr.requestID      = request->request_id;
    params.cr.effectivePID   = request->validUUID ? 0 : request->process_id;
    params.cr.effectiveUUID  = request->validUUID ? request->uuid : mDNSNULL;
    params.cr.peerUID        = request->uid;
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
    params.cr.peerAuditToken = &request->audit_token;
#endif
    if (!request->msgptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[R%d] DNSServiceQueryRecord(unreadable parameters)", request->request_id);
        err = mStatus_BadParamErr;
        goto exit;
    }
    request->flags           = params.cr.flags;
    request->interfaceIndex  = params.cr.interfaceIndex;
#if MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)
    get_queryrecord_tlvs(request, &params);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    err = get_signed_browse_tlvs(request);
    if (err) { LogMsg("%3d: handle_queryrecord_request err reading Validation TLVS", request->sd); return(err); }
#endif

    mDNSBool enablesDNSSEC = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    enablesDNSSEC = dns_service_flags_enables_dnssec(request->flags);
#endif

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[R%d] DNSServiceQueryRecord(%X, %d, " PRI_S ", " PUB_S PUB_S ") START PID[%d](" PUB_S ")",
        request->request_id, request->flags, request->interfaceIndex, params.qname, DNSTypeName(params.cr.qtype),
        enablesDNSSEC ? ", DNSSEC" : "", request->process_id, request->pid_name);

    mDNSPlatformMemZero(&request->u.queryrecord, (mDNSu32)sizeof(request->u.queryrecord));
    request->terminate = NULL;

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    mDNSBool trust_check_done = mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    if (request->signed_obj)
    {
        domainname query_name;
        mdns_signed_browse_result_t browseResult = mdns_signed_browse_result_downcast(request->signed_obj);
        if (browseResult &&
            MakeDomainNameFromDNSNameString(&query_name, params.qname) &&
            mdns_signed_browse_result_contains(browseResult, query_name.c, request->interfaceIndex))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                   "[R%d] DNSServiceQueryRecord: Allowing signed result",
                      request->request_id);
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
            trust_check_done = mDNStrue;
#endif
        }
        else
        {
            request->sign_result = mDNSfalse;
            mdns_forget(&request->signed_obj);
        }
    }
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    if (!trust_check_done && os_feature_enabled(mDNSResponder, bonjour_privacy) )
    {
        err = _handle_queryrecord_request_with_trust(request, &params);
    }
    else
#endif
    {
        err = _handle_queryrecord_request_start(request, &params);
    }

exit:
    return(err);
}

// ***************************************************************************
// MARK: - DNSServiceEnumerateDomains

mDNSlocal reply_state *format_enumeration_reply(request_state *request,
                                                const char *domain, DNSServiceFlags flags, mDNSu32 ifi, DNSServiceErrorType err)
{
    size_t len;
    reply_state *reply;
    uint8_t *data;

    len = sizeof(DNSServiceFlags);
    len += sizeof(mDNSu32);
    len += sizeof(DNSServiceErrorType);
    len += strlen(domain) + 1;

    reply = create_reply(enumeration_reply_op, len, request);
    reply->rhdr->flags = dnssd_htonl(flags);
    reply->rhdr->ifi   = dnssd_htonl(ifi);
    reply->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)err);
    data = (uint8_t *)&reply->rhdr[1];
    put_string(domain, &data);
    return reply;
}

mDNSlocal void enum_termination_callback(request_state *request)
{
    // Stop the domain enumeration queries to discover the WAB Browse/Registration domains
    if (request->u.enumeration.flags & kDNSServiceFlagsRegistrationDomains)
    {
        LogInfo("%3d: DNSServiceEnumeration Cancel WAB Registration PID[%d](%s)", request->sd, request->process_id, request->pid_name);
        uDNS_StopWABQueries(&mDNSStorage, UDNS_WAB_REG_QUERY);
    }
    else
    {
        LogInfo("%3d: DNSServiceEnumeration Cancel WAB Browse PID[%d](%s)", request->sd, request->process_id, request->pid_name);
        uDNS_StopWABQueries(&mDNSStorage, UDNS_WAB_BROWSE_QUERY | UDNS_WAB_LBROWSE_QUERY);
        mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_autoall);
    }
    mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_all);
    mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_default);
}

mDNSlocal void enum_result_callback(mDNS *const m,
                                    DNSQuestion *const question, const ResourceRecord *const answer, QC_result AddRecord)
{
    char domain[MAX_ESCAPED_DOMAIN_NAME];
    request_state *request = question->QuestionContext;
    DNSServiceFlags flags = 0;
    reply_state *reply;
    (void)m; // Unused

    if (answer->rrtype != kDNSType_PTR) return;

#if 0
    if (!AuthorizedDomain(request, &answer->rdata->u.name, request->u.enumeration.flags ? AutoRegistrationDomains : AutoBrowseDomains)) return;
#endif

    // We only return add/remove events for the browse and registration lists
    // For the default browse and registration answers, we only give an "ADD" event
    if (question == &request->u.enumeration.q_default && !AddRecord) return;

    if (AddRecord)
    {
        flags |= kDNSServiceFlagsAdd;
        if (question == &request->u.enumeration.q_default) flags |= kDNSServiceFlagsDefault;
    }

    ConvertDomainNameToCString(&answer->rdata->u.name, domain);
    // Note that we do NOT propagate specific interface indexes to the client - for example, a domain we learn from
    // a machine's system preferences may be discovered on the LocalOnly interface, but should be browsed on the
    // network, so we just pass kDNSServiceInterfaceIndexAny
    reply = format_enumeration_reply(request, domain, flags, kDNSServiceInterfaceIndexAny, kDNSServiceErr_NoError);
    if (!reply) { LogMsg("ERROR: enum_result_callback, format_enumeration_reply"); return; }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d->Q%d] DNSServiceEnumerateDomains(%2.*s) RESULT " PUB_S ": " PRI_S,
           request->request_id, mDNSVal16(question->TargetQID), question->qname.c[0], &question->qname.c[1],
           AddRecord ? "ADD" : "RMV", domain);

    append_reply(request, reply);
}

mDNSlocal mStatus handle_enum_request(request_state *request)
{
    mStatus err;
    DNSServiceFlags flags = get_flags(&request->msgptr, request->msgend);
    DNSServiceFlags reg = flags & kDNSServiceFlagsRegistrationDomains;
    mDNS_DomainType t_all     = reg ? mDNS_DomainTypeRegistration        : mDNS_DomainTypeBrowse;
    mDNS_DomainType t_default = reg ? mDNS_DomainTypeRegistrationDefault : mDNS_DomainTypeBrowseDefault;
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    mDNSInterfaceID InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);
    if (interfaceIndex && !InterfaceID) return(mStatus_BadParamErr);

    if (!request->msgptr)
    { LogMsg("%3d: DNSServiceEnumerateDomains(unreadable parameters)", request->sd); return(mStatus_BadParamErr); }

    request->flags = flags;
    request->interfaceIndex = interfaceIndex;

    // mark which kind of enumeration we're doing so that we know what domain enumeration queries to stop
    request->u.enumeration.flags = reg;

    // enumeration requires multiple questions, so we must link all the context pointers so that
    // necessary context can be reached from the callbacks
    request->u.enumeration.q_all.QuestionContext = request;
    request->u.enumeration.q_default.QuestionContext = request;
    if (!reg) request->u.enumeration.q_autoall.QuestionContext = request;

    // if the caller hasn't specified an explicit interface, we use local-only to get the system-wide list.
    if (!InterfaceID) InterfaceID = mDNSInterface_LocalOnly;

    // make the calls
    LogOperation("%3d: DNSServiceEnumerateDomains(%X=%s)", request->sd, flags,
                 (flags & kDNSServiceFlagsBrowseDomains      ) ? "kDNSServiceFlagsBrowseDomains" :
                 (flags & kDNSServiceFlagsRegistrationDomains) ? "kDNSServiceFlagsRegistrationDomains" : "<<Unknown>>");
    err = mDNS_GetDomains(&mDNSStorage, &request->u.enumeration.q_all, t_all, NULL, InterfaceID, enum_result_callback, request);
    if (!err)
    {
        err = mDNS_GetDomains(&mDNSStorage, &request->u.enumeration.q_default, t_default, NULL, InterfaceID, enum_result_callback, request);
        if (err) mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_all);
        else if (!reg)
        {
            err = mDNS_GetDomains(&mDNSStorage, &request->u.enumeration.q_autoall, mDNS_DomainTypeBrowseAutomatic, NULL, InterfaceID, enum_result_callback, request);
            if (err)
            {
                mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_all);
                mDNS_StopGetDomains(&mDNSStorage, &request->u.enumeration.q_default);
            }
        }
        if (!err) request->terminate = enum_termination_callback;
    }
    if (!err)
    {
        // Start the domain enumeration queries to discover the WAB Browse/Registration domains
        if (reg)
        {
            LogInfo("%3d: DNSServiceEnumerateDomains Start WAB Registration PID[%d](%s)", request->sd, request->process_id, request->pid_name);
            uDNS_StartWABQueries(&mDNSStorage, UDNS_WAB_REG_QUERY);
        }
        else
        {
            LogInfo("%3d: DNSServiceEnumerateDomains Start WAB Browse PID[%d](%s)", request->sd, request->process_id, request->pid_name);
            uDNS_StartWABQueries(&mDNSStorage, UDNS_WAB_BROWSE_QUERY | UDNS_WAB_LBROWSE_QUERY);
        }
    }

    return(err);
}

// ***************************************************************************
// MARK: - DNSServiceReconfirmRecord & Misc

mDNSlocal mStatus handle_reconfirm_request(request_state *request)
{
    mStatus status = mStatus_BadParamErr;
    AuthRecord *rr = read_rr_from_ipc_msg(request, 0, 0);
    if (rr)
    {
        status = mDNS_ReconfirmByValue(&mDNSStorage, &rr->resrec);
        LogOperation(
            (status == mStatus_NoError) ?
            "%3d: DNSServiceReconfirmRecord(%s) interface %d initiated PID[%d](%s)" :
            "%3d: DNSServiceReconfirmRecord(%s) interface %d failed PID[%d](%s) status %d",
            request->sd, RRDisplayString(&mDNSStorage, &rr->resrec),
            mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, rr->resrec.InterfaceID, mDNSfalse),
            request->process_id, request->pid_name, status);
        freeL("AuthRecord/handle_reconfirm_request", rr);
    }
    return(status);
}


mDNSlocal mStatus handle_release_request(request_state *request)
{
    (void) request;
    return mStatus_UnsupportedErr;
}


mDNSlocal mStatus handle_setdomain_request(request_state *request)
{
    char domainstr[MAX_ESCAPED_DOMAIN_NAME];
    domainname domain;
    DNSServiceFlags flags = get_flags(&request->msgptr, request->msgend);
    (void)flags; // Unused
    if (get_string(&request->msgptr, request->msgend, domainstr, sizeof(domainstr)) < 0 ||
        !MakeDomainNameFromDNSNameString(&domain, domainstr))
    { LogMsg("%3d: DNSServiceSetDefaultDomainForUser(unreadable parameters)", request->sd); return(mStatus_BadParamErr); }

    LogOperation("%3d: DNSServiceSetDefaultDomainForUser(%##s)", request->sd, domain.c);
    return(mStatus_NoError);
}

typedef packedstruct
{
    mStatus err;
    mDNSu32 len;
    mDNSu32 vers;
} DaemonVersionReply;

mDNSlocal void handle_getproperty_request(request_state *request)
{
    const mStatus BadParamErr = (mStatus)dnssd_htonl((mDNSu32)mStatus_BadParamErr);
    char prop[256];
    if (get_string(&request->msgptr, request->msgend, prop, sizeof(prop)) >= 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceGetProperty(" PUB_S ")", request->request_id, prop);
        if (!strcmp(prop, kDNSServiceProperty_DaemonVersion))
        {
            DaemonVersionReply x = { 0, dnssd_htonl(4), dnssd_htonl(_DNS_SD_H) };
            send_all(request->sd, (const char *)&x, sizeof(x));
            return;
        }
    }

    // If we didn't recogize the requested property name, return BadParamErr
    send_all(request->sd, (const char *)&BadParamErr, sizeof(BadParamErr));
}

mDNSlocal void handle_connection_delegate_request(request_state *request)
{
    (void) request;
}

typedef packedstruct
{
    mStatus err;
    mDNSs32 pid;
} PIDInfo;

// ***************************************************************************
// MARK: - DNSServiceNATPortMappingCreate

#define DNSServiceProtocol(X) ((X) == NATOp_AddrRequest ? 0 : (X) == NATOp_MapUDP ? kDNSServiceProtocol_UDP : kDNSServiceProtocol_TCP)

mDNSlocal void port_mapping_termination_callback(request_state *request)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[R%d] DNSServiceNATPortMappingCreate(%X, %u, %u, %d) STOP PID[%d](" PUB_S ")",
           request->request_id, DNSServiceProtocol(request->u.pm.NATinfo.Protocol),
           mDNSVal16(request->u.pm.NATinfo.IntPort), mDNSVal16(request->u.pm.ReqExt), request->u.pm.NATinfo.NATLease,
           request->process_id, request->pid_name);

    mDNS_StopNATOperation(&mDNSStorage, &request->u.pm.NATinfo);
}

// Called via function pointer when we get a NAT Traversal (address request or port mapping) response
mDNSlocal void port_mapping_create_request_callback(mDNS *m, NATTraversalInfo *n)
{
    request_state *request = (request_state *)n->clientContext;
    reply_state *rep;
    size_t replyLen;
    uint8_t *data;

    if (!request) { LogMsg("port_mapping_create_request_callback called with unknown request_state object"); return; }

    // calculate reply data length
    replyLen = sizeof(DNSServiceFlags);
    replyLen += 3 * sizeof(mDNSu32);  // if index + addr + ttl
    replyLen += sizeof(DNSServiceErrorType);
    replyLen += 2 * sizeof(mDNSu16);  // Internal Port + External Port
    replyLen += sizeof(mDNSu8);       // protocol

    rep = create_reply(port_mapping_reply_op, replyLen, request);

    rep->rhdr->flags = dnssd_htonl(0);
    rep->rhdr->ifi   = dnssd_htonl(mDNSPlatformInterfaceIndexfromInterfaceID(m, n->InterfaceID, mDNSfalse));
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)n->Result);

    data = (uint8_t *)&rep->rhdr[1];

    *data++ = request->u.pm.NATinfo.ExternalAddress.b[0];
    *data++ = request->u.pm.NATinfo.ExternalAddress.b[1];
    *data++ = request->u.pm.NATinfo.ExternalAddress.b[2];
    *data++ = request->u.pm.NATinfo.ExternalAddress.b[3];
    *data++ = DNSServiceProtocol(request->u.pm.NATinfo.Protocol);
    *data++ = request->u.pm.NATinfo.IntPort.b[0];
    *data++ = request->u.pm.NATinfo.IntPort.b[1];
    *data++ = request->u.pm.NATinfo.ExternalPort.b[0];
    *data++ = request->u.pm.NATinfo.ExternalPort.b[1];
    put_uint32(request->u.pm.NATinfo.Lifetime, &data);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceNATPortMappingCreate(%X, %u, %u, %d) RESULT " PRI_IPv4_ADDR ":%u TTL %u",
           request->request_id, DNSServiceProtocol(request->u.pm.NATinfo.Protocol),
           mDNSVal16(request->u.pm.NATinfo.IntPort), mDNSVal16(request->u.pm.ReqExt), request->u.pm.NATinfo.NATLease,
           &request->u.pm.NATinfo.ExternalAddress, mDNSVal16(request->u.pm.NATinfo.ExternalPort),
           request->u.pm.NATinfo.Lifetime);

    append_reply(request, rep);
}

mDNSlocal mStatus handle_port_mapping_request(request_state *request)
{
    mDNSu32 ttl = 0;
    mStatus err = mStatus_NoError;

    DNSServiceFlags flags          = get_flags(&request->msgptr, request->msgend);
    mDNSu32 interfaceIndex = get_uint32(&request->msgptr, request->msgend);
    mDNSInterfaceID InterfaceID    = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, interfaceIndex);
    mDNSu8 protocol       = (mDNSu8)get_uint32(&request->msgptr, request->msgend);
    (void)flags; // Unused
    if (interfaceIndex && !InterfaceID) return(mStatus_BadParamErr);
    if (request->msgptr + 8 > request->msgend) request->msgptr = NULL;
    else
    {
        request->u.pm.NATinfo.IntPort.b[0] = *request->msgptr++;
        request->u.pm.NATinfo.IntPort.b[1] = *request->msgptr++;
        request->u.pm.ReqExt.b[0]          = *request->msgptr++;
        request->u.pm.ReqExt.b[1]          = *request->msgptr++;
        ttl = get_uint32(&request->msgptr, request->msgend);
    }

    if (!request->msgptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%d] DNSServiceNATPortMappingCreate(unreadable parameters)", request->request_id);
        return(mStatus_BadParamErr);
    }

    if (protocol == 0)  // If protocol == 0 (i.e. just request public address) then IntPort, ExtPort, ttl must be zero too
    {
        if (!mDNSIPPortIsZero(request->u.pm.NATinfo.IntPort) || !mDNSIPPortIsZero(request->u.pm.ReqExt) || ttl) return(mStatus_BadParamErr);
    }
    else
    {
        if (mDNSIPPortIsZero(request->u.pm.NATinfo.IntPort)) return(mStatus_BadParamErr);
        if (!(protocol & (kDNSServiceProtocol_UDP | kDNSServiceProtocol_TCP))) return(mStatus_BadParamErr);
    }

    request->flags                       = flags;
    request->interfaceIndex              = interfaceIndex;
    request->u.pm.NATinfo.Protocol       = !protocol ? NATOp_AddrRequest : (protocol == kDNSServiceProtocol_UDP) ? NATOp_MapUDP : NATOp_MapTCP;
    //       u.pm.NATinfo.IntPort        = already set above
    request->u.pm.NATinfo.RequestedPort  = request->u.pm.ReqExt;
    request->u.pm.NATinfo.NATLease       = ttl;
    request->u.pm.NATinfo.clientCallback = port_mapping_create_request_callback;
    request->u.pm.NATinfo.clientContext  = request;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%d] DNSServiceNATPortMappingCreate(%X, %u, %u, %d) START PID[%d](" PUB_S ")",
           request->request_id, protocol, mDNSVal16(request->u.pm.NATinfo.IntPort), mDNSVal16(request->u.pm.ReqExt),
           request->u.pm.NATinfo.NATLease, request->process_id, request->pid_name);
    err = mDNS_StartNATOperation(&mDNSStorage, &request->u.pm.NATinfo);
    if (err) LogMsg("ERROR: mDNS_StartNATOperation: %d", (int)err);
    else request->terminate = port_mapping_termination_callback;

    return(err);
}

// ***************************************************************************
// MARK: - DNSServiceGetAddrInfo

mDNSlocal void addrinfo_termination_callback(request_state *request)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
           "[R%u] DNSServiceGetAddrInfo(" PRI_DM_NAME ") STOP PID[%d](" PUB_S ")",
           request->request_id, DM_NAME_PARAM(GetAddrInfoClientRequestGetQName(&request->u.addrinfo)),
           request->process_id, request->pid_name);

    GetAddrInfoClientRequestStop(&request->u.addrinfo);
}

typedef struct {
    mDNSu32     protocols;
    char        hostname[MAX_ESCAPED_DOMAIN_NAME];
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    mDNSBool    require_privacy;
#endif
} _addrinfo_start_params_t;

mDNSlocal mStatus _handle_addrinfo_request_start(request_state *request, const _addrinfo_start_params_t * const params)
{
    mStatus err;

    request->terminate = addrinfo_termination_callback;

    GetAddrInfoClientRequestParams gaiParams;
    GetAddrInfoClientRequestParamsInit(&gaiParams);
    gaiParams.requestID      = request->request_id;
    gaiParams.hostnameStr    = params->hostname;
    gaiParams.interfaceIndex = request->interfaceIndex;
    gaiParams.flags          = request->flags;
    gaiParams.protocols      = params->protocols;
    gaiParams.effectivePID   = request->validUUID ? 0 : request->process_id;
    gaiParams.effectiveUUID  = request->validUUID ? request->uuid : mDNSNULL;
    gaiParams.peerUID        = request->uid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    gaiParams.needEncryption = params->require_privacy ? mDNStrue : mDNSfalse;
    gaiParams.customID       = request->custom_service_id;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
    gaiParams.peerAuditToken = &request->audit_token;
#endif
    err = GetAddrInfoClientRequestStart(&request->u.addrinfo, &gaiParams, queryrecord_result_reply, request);

    return err;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

mDNSlocal void _return_addrinfo_request_error(request_state * request, mStatus error)
{
    _return_queryrecord_request_error(request, error);
}

mDNSlocal mStatus _handle_addrinfo_request_with_trust(request_state *request, const _addrinfo_start_params_t * const params)
{
    mStatus err;
    if (audit_token_to_pid(request->audit_token) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING, "[R%u] _handle_addrinfo_request_with_trust: no audit token for pid(%s %d)", request->request_id, request->pid_name, request->process_id);
        err = _handle_addrinfo_request_start(request, params);
    }
    else
    {
        mdns_trust_flags_t flags = mdns_trust_flags_none;
        mdns_trust_status_t status = mdns_trust_check_getaddrinfo(request->audit_token, params->hostname, &flags);
        switch (status)
        {
            case mdns_trust_status_denied:
            case mdns_trust_status_pending:
            {
                mdns_trust_t trust = mdns_trust_create(request->audit_token, NULL, flags);
                if (!trust )
                {
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }

                void * context = mallocL("context/_handle_addrinfo_request_with_trust", sizeof(_addrinfo_start_params_t));
                if (!context)
                {
                    my_perror("ERROR: mallocL context/_handle_addrinfo_request_with_trust");
                    mdns_release(trust);
                    err = mStatus_NoMemoryErr;
                    goto exit;
                }
                memcpy(context, params, sizeof(_addrinfo_start_params_t));
                mdns_trust_set_context(trust, context);
                mdns_trust_service_set_context_finalizer(trust, ^(void *ref)
                {
                    freeL("context/_handle_addrinfo_request_with_trust finalizer", ref);
                });
                mdns_trust_set_queue(trust, _get_trust_results_dispatch_queue());
                mdns_trust_set_event_handler(trust, ^(mdns_trust_event_t event, mdns_trust_status_t update)
                {
                    if (event == mdns_trust_event_result)
                    {
                        mStatus error = (update != mdns_trust_status_granted) ? mStatus_PolicyDenied : mStatus_NoError;
                        KQueueLock();
                        _addrinfo_start_params_t * _params =  mdns_trust_get_context(trust);
                        if (_params)
                        {
                            if (!error)
                            {
                                error = _handle_addrinfo_request_start(request, _params);
                                // No context means the request was canceled before we got here
                            }
                            if (error) // (not else if) Always check for error result
                            {
                                _return_addrinfo_request_error(request, error);
                            }
                        }
                        KQueueUnlock("_handle_addrinfo_request_with_trust");
                    }
                });
                request->trust = trust;
                mdns_trust_activate(trust);
                err = mStatus_NoError;
                break;
            }

            case mdns_trust_status_no_entitlement:
                err = mStatus_NoAuth;
                break;

            case mdns_trust_status_granted:
                err = _handle_addrinfo_request_start(request, params);
                break;
        }
    }
exit:
    return err;
}
#endif // TRUST_ENFORCEMENT

mDNSlocal mStatus handle_addrinfo_request(request_state *request)
{
    mStatus             err;
    DNSServiceFlags     flags;
    mDNSu32             interfaceIndex;
    _addrinfo_start_params_t params;

    flags               = get_flags(&request->msgptr, request->msgend);
    interfaceIndex      = get_uint32(&request->msgptr, request->msgend);
    params.protocols    = get_uint32(&request->msgptr, request->msgend);
    if (get_string(&request->msgptr, request->msgend, params.hostname, sizeof(params.hostname)) < 0)
    {
        err = mStatus_BadParamErr;
        goto exit;
    }
    if (!request->msgptr)
    {
        LogMsg("%3d: DNSServiceGetAddrInfo(unreadable parameters)", request->sd);
        err = mStatus_BadParamErr;
        goto exit;
    }
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    params.require_privacy = mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER) && MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)
    if (request->msgptr && (request->hdr.ipc_flags & IPC_FLAGS_TRAILING_TLVS))
    {
        size_t len;
        const mDNSu8 *const start = (const mDNSu8 *)request->msgptr;
        const mDNSu8 *const end   = (const mDNSu8 *)request->msgend;
        const mDNSu8 *const data = get_tlv(start, end, IPC_TLV_TYPE_RESOLVER_CONFIG_PLIST_DATA, &len);
        if (data)
        {
            request->custom_service_id = Querier_RegisterCustomDNSServiceWithPListData(data, len);
        }
        const mDNSu32 u32 = get_tlv_uint32(start, end, IPC_TLV_TYPE_REQUIRE_PRIVACY, mDNSNULL);
        params.require_privacy = (u32 != 0) ? mDNStrue : mDNSfalse;
    }
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    err = get_signed_resolve_tlvs(request);
    if (err) { LogMsg("%3d: handle_addrinfo_request err reading Validation TLVS", request->sd); return(err); }
#endif
    request->flags          = flags;
    request->interfaceIndex = interfaceIndex;

    mDNSBool enablesDNSSEC = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    enablesDNSSEC = dns_service_flags_enables_dnssec(request->flags);
#endif

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[R%u] DNSServiceGetAddrInfo(%X, %d, %u, " PRI_S PUB_S ") START PID[%d](" PUB_S ")",
        request->request_id, request->flags, request->interfaceIndex, params.protocols, params.hostname,
        enablesDNSSEC ? ", DNSSEC" : "", request->process_id, request->pid_name);

    mDNSPlatformMemZero(&request->u.addrinfo, (mDNSu32)sizeof(request->u.addrinfo));
    request->terminate = NULL;

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    mDNSBool trust_check_done = mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    if (request->signed_obj)
    {
        mdns_signed_resolve_result_t resolveResult = mdns_signed_resolve_result_downcast(request->signed_obj);
        if (resolveResult &&
            mdns_signed_resolve_result_contains(resolveResult, params.hostname, interfaceIndex))
        {
            if (mdns_system_is_signed_result_uuid_valid(mdns_signed_result_get_uuid(resolveResult)))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                       "[R%d] DNSServiceGetAddrInfo: Allowing signed result",
                          request->request_id);
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
                trust_check_done = mDNStrue;
#endif
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                       "[R%d] DNSServiceGetAddrInfo: Signed result UUID revoked.",
                          request->request_id);
                return mStatus_PolicyDenied;
            }
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                   "[R%d] DNSServiceGetAddrInfo: Signed result does not cover hostname: " PRI_S ", ifindex: %u.",
                      request->request_id, params.hostname, request->interfaceIndex);
            request->sign_result = mDNSfalse;
            mdns_forget(&request->signed_obj);
        }
    }
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    if (!trust_check_done && os_feature_enabled(mDNSResponder, bonjour_privacy))
    {
        err = _handle_addrinfo_request_with_trust(request, &params);
    }
    else
    {
        err = _handle_addrinfo_request_start(request, &params);
    }
#else
    err = _handle_addrinfo_request_start(request, &params);
#endif

exit:
    return(err);
}

// ***************************************************************************
// MARK: - Main Request Handler etc.

mDNSlocal request_state *NewRequest(void)
{
    request_state *request;
    request_state **p = &all_requests;
    request = (request_state *) callocL("request_state", sizeof(*request));
    if (!request) FatalError("ERROR: calloc");
    while (*p) p = &(*p)->next;
    *p = request;
    return(request);
}

// read_msg may be called any time when the transfer state (req->ts) is t_morecoming.
// if there is no data on the socket, the socket will be closed and t_terminated will be returned
mDNSlocal void read_msg(request_state *req)
{
    if (req->ts == t_terminated || req->ts == t_error)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                  "[R%u] ERROR: read_msg called with transfer state terminated or error", req->request_id);
        req->ts = t_error;
        return;
    }

    if (req->ts == t_complete)  // this must be death or something is wrong
    {
        char buf[4];    // dummy for death notification
        const ssize_t nread = udsSupportReadFD(req->sd, buf, 4, 0, req->platform_data);
        if (!nread) { req->ts = t_terminated; return; }
        if (nread < 0) goto rerror;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                  "[R%u] ERROR: read data from a completed request", req->request_id);
        req->ts = t_error;
        return;
    }

    if (req->ts != t_morecoming)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                  "[R%u] ERROR: read_msg called with invalid transfer state (%d)", req->request_id, req->ts);
        req->ts = t_error;
        return;
    }

    if (req->hdr_bytes < sizeof(ipc_msg_hdr))
    {
        const mDNSu32 nleft = sizeof(ipc_msg_hdr) - req->hdr_bytes;
        const ssize_t nread = udsSupportReadFD(req->sd, (char *)&req->hdr + req->hdr_bytes, nleft, 0, req->platform_data);
        if (nread == 0) { req->ts = t_terminated; return; }
        if (nread < 0) goto rerror;
        req->hdr_bytes += (mDNSu32)nread;
        if (req->hdr_bytes > sizeof(ipc_msg_hdr))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                      "[R%u] ERROR: read_msg - read too many header bytes", req->request_id);
            req->ts = t_error;
            return;
        }

        // only read data if header is complete
        if (req->hdr_bytes == sizeof(ipc_msg_hdr))
        {
            ConvertHeaderBytes(&req->hdr);
            if (req->hdr.version != VERSION)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                          "[R%u] ERROR: client version 0x%08X daemon version 0x%08X", req->request_id, req->hdr.version, VERSION);
                req->ts = t_error;
                return;
            }

            // Largest conceivable single request is a DNSServiceRegisterRecord() or DNSServiceAddRecord()
            // with 64kB of rdata. Adding 1009 byte for a maximal domain name, plus a safety margin
            // for other overhead, this means any message above 70kB is definitely bogus.
            if (req->hdr.datalen > 70000)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                          "[R%u] ERROR: read_msg: hdr.datalen %u (0x%X) > 70000", req->request_id, req->hdr.datalen, req->hdr.datalen);
                req->ts = t_error;
                return;
            }
            req->msgbuf = (uint8_t *)callocL("request_state msgbuf", req->hdr.datalen + MSG_PAD_BYTES);
            if (!req->msgbuf) { my_perror("ERROR: calloc"); req->ts = t_error; return; }
            req->msgptr = req->msgbuf;
            req->msgend = req->msgbuf + req->hdr.datalen;
        }
    }

    // If our header is complete, but we're still needing more body data, then try to read it now
    // Note: For cancel_request req->hdr.datalen == 0, but there's no error return socket for cancel_request
    // Any time we need to get the error return socket we know we'll have at least one data byte
    // (even if only the one-byte empty C string placeholder for the old ctrl_path parameter)
    if (req->hdr_bytes == sizeof(ipc_msg_hdr) && req->data_bytes < req->hdr.datalen)
    {
        size_t nleft = req->hdr.datalen - req->data_bytes;
        ssize_t nread;
#if !defined(_WIN32)
        struct iovec vec = { req->msgbuf + req->data_bytes, nleft };    // Tell recvmsg where we want the bytes put
        struct msghdr msg;
        struct cmsghdr *cmsg = NULL;
        char cbuf[CMSG_SPACE(4 * sizeof(dnssd_sock_t))];
        msg.msg_name       = 0;
        msg.msg_namelen    = 0;
        msg.msg_iov        = &vec;
        msg.msg_iovlen     = 1;
        msg.msg_control    = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        msg.msg_flags      = 0;
        nread = recvmsg(req->sd, &msg, 0);
#else
        nread = udsSupportReadFD(req->sd, (char *)req->msgbuf + req->data_bytes, nleft, 0, req->platform_data);
#endif
        if (nread == 0) { req->ts = t_terminated; return; }
        if (nread < 0) goto rerror;
        req->data_bytes += (size_t)nread;
        if (req->data_bytes > req->hdr.datalen)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                      "[R%u] ERROR: read_msg - read too many data bytes", req->request_id);
            req->ts = t_error;
            return;
        }
#if !defined(_WIN32)
        // There is no error sd if IPC_FLAGS_NOERRSD is set.
        if (!(req->hdr.ipc_flags & IPC_FLAGS_NOERRSD))
        {
            cmsg = CMSG_FIRSTHDR(&msg);
        }
#if defined(DEBUG_64BIT_SCM_RIGHTS) && DEBUG_64BIT_SCM_RIGHTS
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%u] Expecting %d %d %d %d", req->request_id, sizeof(cbuf), sizeof(cbuf), SOL_SOCKET, SCM_RIGHTS);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                  "[R%u] Got       %d %d %d %d", req->request_id, msg.msg_controllen, cmsg ? cmsg->cmsg_len : -1, cmsg ? cmsg->cmsg_level : -1, cmsg ? cmsg->cmsg_type : -1);
#endif // DEBUG_64BIT_SCM_RIGHTS
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
            req->errsd = *(dnssd_sock_t *)CMSG_DATA(cmsg);
#if defined(DEBUG_64BIT_SCM_RIGHTS) && DEBUG_64BIT_SCM_RIGHTS
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                      "[R%u] read req->errsd %d", req->request_id, req->errsd);
#endif // DEBUG_64BIT_SCM_RIGHTS
            if (req->data_bytes < req->hdr.datalen)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                          "[R%u] Client(PID [%d](" PUB_S ")) sent result code socket %d via SCM_RIGHTS with req->data_bytes %lu < req->hdr.datalen %d",
                          req->request_id, req->process_id, req->pid_name, req->errsd, (unsigned long)req->data_bytes, req->hdr.datalen);
                req->ts = t_error;
                return;
            }
        }
#endif
    }

    // If our header and data are both complete, see if we need to make our separate error return socket
    if (req->hdr_bytes == sizeof(ipc_msg_hdr) && req->data_bytes == req->hdr.datalen)
    {
        if (!(req->hdr.ipc_flags & IPC_FLAGS_NOERRSD) && req->terminate && req->hdr.op != cancel_request)
        {
            dnssd_sockaddr_t cliaddr;
#if defined(USE_TCP_LOOPBACK)
            mDNSOpaque16 port;
            u_long opt = 1;
            port.b[0] = req->msgptr[0];
            port.b[1] = req->msgptr[1];
            req->msgptr += 2;
            cliaddr.sin_family      = AF_INET;
            cliaddr.sin_port        = port.NotAnInteger;
            cliaddr.sin_addr.s_addr = inet_addr(MDNS_TCP_SERVERADDR);
#else
            char ctrl_path[MAX_CTLPATH];
            get_string(&req->msgptr, req->msgend, ctrl_path, MAX_CTLPATH);  // path is first element in message buffer
            mDNSPlatformMemZero(&cliaddr, sizeof(cliaddr));
            cliaddr.sun_family = AF_LOCAL;
            mDNSPlatformStrLCopy(cliaddr.sun_path, ctrl_path, sizeof(cliaddr.sun_path));
            // If the error return path UDS name is empty string, that tells us
            // that this is a new version of the library that's going to pass us
            // the error return path socket via sendmsg/recvmsg
            if (ctrl_path[0] == 0)
            {
                if (req->errsd == req->sd)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                              "[R%u] read_msg: ERROR failed to get errsd via SCM_RIGHTS", req->request_id);
                    req->ts = t_error;
                    return;
                }
                goto got_errfd;
            }
#endif

            req->errsd = socket(AF_DNSSD, SOCK_STREAM, 0);
            if (!dnssd_SocketValid(req->errsd))
            {
                my_throttled_perror("ERROR: socket");
                req->ts = t_error;
                return;
            }

            if (connect(req->errsd, (struct sockaddr *)&cliaddr, sizeof(cliaddr)) < 0)
            {
#if !defined(USE_TCP_LOOPBACK)
                struct stat sb;
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                          "[R%u] read_msg: Couldn't connect to error return path socket " PUB_S " errno %d (" PUB_S ")",
                          req->request_id, cliaddr.sun_path, dnssd_errno, dnssd_strerror(dnssd_errno));
                if (stat(cliaddr.sun_path, &sb) < 0)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                              "[R%u] read_msg: stat failed " PUB_S " errno %d (" PUB_S ")",
                              req->request_id, cliaddr.sun_path, dnssd_errno, dnssd_strerror(dnssd_errno));
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                              "[R%u] read_msg: file " PUB_S " mode %o (octal) uid %d gid %d",
                              req->request_id, cliaddr.sun_path, sb.st_mode, sb.st_uid, sb.st_gid);
                }
#endif
                req->ts = t_error;
                return;
            }

#if !defined(USE_TCP_LOOPBACK)
got_errfd:
#endif

#if defined(_WIN32)
            if (ioctlsocket(req->errsd, FIONBIO, &opt) != 0)
#else
            if (fcntl(req->errsd, F_SETFL, fcntl(req->errsd, F_GETFL, 0) | O_NONBLOCK) != 0)
#endif
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                          "[R%u] ERROR: could not set control socket to non-blocking mode errno %d (" PUB_S ")",
                          req->request_id, dnssd_errno, dnssd_strerror(dnssd_errno));
                req->ts = t_error;
                return;
            }
        }

        req->ts = t_complete;
    }

    return;

rerror:
    if (dnssd_errno == dnssd_EWOULDBLOCK || dnssd_errno == dnssd_EINTR) return;
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
              "[R%u] ERROR: read_msg errno %d (" PUB_S ")", req->request_id, dnssd_errno, dnssd_strerror(dnssd_errno));
    req->ts = t_error;
}

mDNSlocal void returnAsyncErrorCode(request_state *const request, const mStatus error)
{
    size_t len;
    const char *const emptystr = "\0";
    uint8_t *data;
    reply_state *rep;

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
       "[R%u] returnAsyncErrorCode: error code(%d)", request->request_id, error);

    //Do not call callback when there is no error, refer to rdar://88599677
    if (error == mStatus_NoError)
    {
        return;
    }
    // calculate reply length
    len = sizeof(DNSServiceFlags);
    len += sizeof(mDNSu32);  // interface index
    len += sizeof(DNSServiceErrorType);
    len += 2 * (strlen(emptystr) + 1); // empty name, empty target
    len += 2 * sizeof(mDNSu16);  // port, txtLen
    len += 0; //req->u.resolve.txt->rdlength;

    rep = create_reply(async_error_op, len, request);

    rep->rhdr->flags = 0;
    rep->rhdr->ifi   = 0;
    rep->rhdr->error = (DNSServiceErrorType)dnssd_htonl((mDNSu32)error);

    data = (uint8_t *)&rep->rhdr[1];

    // write reply data to message
    put_string(emptystr, &data); // name
    put_string(emptystr, &data); // target
    put_uint16(0,        &data); // port
    put_uint16(0,        &data); // txtLen

    append_reply(request, rep);
}

mDNSlocal mStatus handle_client_request(request_state *req)
{
    mStatus err = mStatus_NoError;
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
    SetupAuditTokenForRequest(req);
#endif
    switch(req->hdr.op)
    {
            // These are all operations that have their own first-class request_state object
        case connection_request:
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                   "[R%d] DNSServiceCreateConnection START PID[%d](" PUB_S ")",
                   req->request_id, req->process_id, req->pid_name);
            req->terminate = connection_termination;
            break;
        case connection_delegate_request:
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                   "[R%d] DNSServiceCreateDelegateConnection START PID[%d](" PRI_S ")",
                   req->request_id, req->process_id, req->pid_name);
            req->terminate = connection_termination;
            handle_connection_delegate_request(req);
            break;
        case resolve_request:              err = handle_resolve_request     (req);  break;
        case query_request:                err = handle_queryrecord_request (req);  break;
        case browse_request:               err = handle_browse_request      (req);  break;
        case reg_service_request:          err = handle_regservice_request  (req);  break;
        case enumeration_request:          err = handle_enum_request        (req);  break;
        case reconfirm_record_request:     err = handle_reconfirm_request   (req);  break;
        case setdomain_request:            err = handle_setdomain_request   (req);  break;
        case getproperty_request:                handle_getproperty_request (req);  break;
        case port_mapping_request:         err = handle_port_mapping_request(req);  break;
        case addrinfo_request:             err = handle_addrinfo_request    (req);  break;
        case send_bpf:                     /* Do nothing for send_bpf */            break;

            // These are all operations that work with an existing request_state object
        case reg_record_request:           err = handle_regrecord_request   (req);  break;
        case add_record_request:           err = handle_add_request         (req);  break;
        case update_record_request:        err = handle_update_request      (req);  break;
        case remove_record_request:        err = handle_removerecord_request(req);  break;
        case cancel_request:                     handle_cancel_request      (req);  break;
        case release_request:              err = handle_release_request     (req);  break;
        default: LogMsg("request_callback: %3d:ERROR: Unsupported UDS req:%d PID[%d][%s]",
                        req->sd, req->hdr.op, req->process_id, req->pid_name);
            err = mStatus_BadParamErr;
            break;
    }

    return err;
}

#define RecordOrientedOp(X) \
    ((X) == reg_record_request || (X) == add_record_request || (X) == update_record_request || (X) == remove_record_request)

// The lightweight operations are the ones that don't need a dedicated request_state structure allocated for them
#define LightweightOp(X) (RecordOrientedOp(X) || (X) == cancel_request)

mDNSlocal void request_callback(int fd, void *info)
{
    request_state *req = info;
    (void)fd; // Unused

    for (;;)
    {
        mStatus err = mStatus_NoError;
        mDNSs32 min_size = sizeof(DNSServiceFlags);

        read_msg(req);
        if (req->ts == t_morecoming)
            return;
        if (req->ts == t_terminated || req->ts == t_error)
        {
            AbortUnlinkAndFree(req);
            return;
        }
        if (req->ts != t_complete)
        {
            LogMsg("request_callback: req->ts %d != t_complete PID[%d][%s]", req->ts, req->process_id, req->pid_name);
            AbortUnlinkAndFree(req);
            return;
        }

        switch(req->hdr.op)            //          Interface       + other data
        {
            case connection_request:       min_size = 0;                                                                           break;
            case connection_delegate_request: min_size = 4; /* pid */                                                              break;
            case reg_service_request:      min_size += sizeof(mDNSu32) + 4 /* name, type, domain, host */ + 4 /* port, textlen */; break;
            case add_record_request:       min_size +=                   4 /* type, rdlen */              + 4 /* ttl */;           break;
            case update_record_request:    min_size +=                   2 /* rdlen */                    + 4 /* ttl */;           break;
            case remove_record_request:                                                                                            break;
            case browse_request:           min_size += sizeof(mDNSu32) + 2 /* type, domain */;                                     break;
            case resolve_request:          min_size += sizeof(mDNSu32) + 3 /* type, type, domain */;                               break;
            case query_request:            min_size += sizeof(mDNSu32) + 1 /* name */                     + 4 /* type, class*/;    break;
            case enumeration_request:      min_size += sizeof(mDNSu32);                                                            break;
            case reg_record_request:       min_size += sizeof(mDNSu32) + 1 /* name */ + 6 /* type, class, rdlen */ + 4 /* ttl */;  break;
            case reconfirm_record_request: min_size += sizeof(mDNSu32) + 1 /* name */ + 6 /* type, class, rdlen */;                break;
            case setdomain_request:        min_size +=                   1 /* domain */;                                           break;
            case getproperty_request:      min_size = 2;                                                                           break;
            case port_mapping_request:     min_size += sizeof(mDNSu32) + 4 /* udp/tcp */ + 4 /* int/ext port */    + 4 /* ttl */;  break;
            case addrinfo_request:         min_size += sizeof(mDNSu32) + 4 /* v4/v6 */   + 1 /* hostname */;                       break;
            case send_bpf:                 // Same as cancel_request below
            case cancel_request:           min_size = 0;                                                                           break;
            case release_request:          min_size += sizeof(mDNSu32) + 3 /* type, type, domain */;                               break;
            default: LogMsg("request_callback: ERROR: validate_message - unsupported req type: %d PID[%d][%s]",
                            req->hdr.op, req->process_id, req->pid_name);
                     min_size = -1;                                                                                                break;
        }

        if ((mDNSs32)req->data_bytes < min_size)
        {
            LogMsg("request_callback: Invalid message %d bytes; min for %d is %d PID[%d][%s]",
                    req->data_bytes, req->hdr.op, min_size, req->process_id, req->pid_name);
            AbortUnlinkAndFree(req);
            return;
        }
        if (LightweightOp(req->hdr.op) && !req->terminate)
        {
            LogMsg("request_callback: Reg/Add/Update/Remove %d require existing connection PID[%d][%s]",
                    req->hdr.op, req->process_id, req->pid_name);
            AbortUnlinkAndFree(req);
            return;
        }

        // If req->terminate is already set, this means this operation is sharing an existing connection
        if (req->terminate && !LightweightOp(req->hdr.op))
        {
            request_state *newreq = NewRequest();
            newreq->primary = req;
            newreq->sd      = req->sd;
            newreq->errsd   = req->errsd;
            newreq->uid     = req->uid;
            newreq->hdr     = req->hdr;
            newreq->msgbuf  = req->msgbuf;
            newreq->msgptr  = req->msgptr;
            newreq->msgend  = req->msgend;
            newreq->request_id = GetNewRequestID();
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
            newreq->audit_token = req->audit_token;
#endif
            // if the parent request is a delegate connection, copy the
            // relevant bits
            if (req->validUUID)
            {
                newreq->validUUID = mDNStrue;
                mDNSPlatformMemCopy(newreq->uuid, req->uuid, UUID_SIZE);
            }
            else
            {
                if (req->process_id)
                {
                    newreq->process_id = req->process_id;
                    mDNSPlatformStrLCopy(newreq->pid_name, req->pid_name, (mDNSu32)sizeof(newreq->pid_name));
                }
                else
                {
                    set_peer_pid(newreq);
                }
            }
            req = newreq;
        }

        // Check if the request wants no asynchronous replies.
        if (req->hdr.ipc_flags & IPC_FLAGS_NOREPLY) req->no_reply = 1;

        // If we're shutting down, don't allow new client requests
        // We do allow "cancel" and "getproperty" during shutdown
        if (mDNSStorage.ShutdownTime && req->hdr.op != cancel_request && req->hdr.op != getproperty_request)
            err = mStatus_ServiceNotRunning;
        else
            err = handle_client_request(req);

        // req->msgbuf may be NULL, e.g. for connection_request or remove_record_request
        if (req->msgbuf) freeL("request_state msgbuf", req->msgbuf);

        // There's no return data for a cancel request (DNSServiceRefDeallocate returns no result)
        // For a DNSServiceGetProperty call, the handler already generated the response, so no need to do it again here
        if (req->hdr.op != cancel_request && req->hdr.op != getproperty_request && req->hdr.op != send_bpf && req->hdr.op != getpid_request)
        {
            const mStatus err_netorder = (mStatus)dnssd_htonl((mDNSu32)err);
            if ((req->hdr.ipc_flags & IPC_FLAGS_NOERRSD))
            {
                returnAsyncErrorCode(req, err);
            }
            else
            {
                send_all(req->errsd, (const char *)&err_netorder, sizeof(err_netorder));
            }
            if (req->errsd != req->sd)
            {
                dnssd_close(req->errsd);
                req->errsd = req->sd;
                // Also need to reset the parent's errsd, if this is a subordinate operation
                if (req->primary) req->primary->errsd = req->primary->sd;
            }
        }

        // Reset ready to accept the next req on this pipe
        if (req->primary) req = req->primary;
        req->ts         = t_morecoming;
        req->hdr_bytes  = 0;
        req->data_bytes = 0;
        req->msgbuf     = mDNSNULL;
        req->msgptr     = mDNSNULL;
        req->msgend     = 0;
    }
}

mDNSlocal void connect_callback(int fd, void *info)
{
    dnssd_sockaddr_t cliaddr;
    dnssd_socklen_t len = (dnssd_socklen_t) sizeof(cliaddr);
    dnssd_sock_t sd = accept(fd, (struct sockaddr*) &cliaddr, &len);
#if defined(SO_NOSIGPIPE) || defined(_WIN32)
    unsigned long optval = 1;
#endif

    (void)info; // Unused

    if (!dnssd_SocketValid(sd))
    {
        if (dnssd_errno != dnssd_EWOULDBLOCK)
            my_throttled_perror("ERROR: accept");
        return;
    }

#ifdef SO_NOSIGPIPE
    // Some environments (e.g. OS X) support turning off SIGPIPE for a socket
    if (setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "%3d: WARNING: setsockopt - SO_NOSIGPIPE %d (" PUB_S ")", sd, dnssd_errno,
            dnssd_strerror(dnssd_errno));
    }

#endif

#if defined(_WIN32)
    if (ioctlsocket(sd, FIONBIO, &optval) != 0)
#else
    if (fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK) != 0)
#endif
    {
        my_perror("ERROR: fcntl(sd, F_SETFL, O_NONBLOCK) - aborting client");
        dnssd_close(sd);
        return;
    }
    else
    {
        request_state *request = NewRequest();
        request->ts    = t_morecoming;
        request->sd    = sd;
        request->errsd = sd;
        request->request_id = GetNewRequestID();
        set_peer_pid(request);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "%3d: connect_callback: Adding FD for uid %u", request->sd, request->uid);
        udsSupportAddFDToEventLoop(sd, request_callback, request, &request->platform_data);
    }
}

mDNSlocal mDNSBool uds_socket_setup(dnssd_sock_t skt)
{
#if defined(SO_NP_EXTENSIONS)
    struct      so_np_extensions sonpx;
    socklen_t optlen = sizeof(struct so_np_extensions);
    sonpx.npx_flags = SONPX_SETOPTSHUT;
    sonpx.npx_mask  = SONPX_SETOPTSHUT;
    if (setsockopt(skt, SOL_SOCKET, SO_NP_EXTENSIONS, &sonpx, optlen) < 0)
        my_perror("WARNING: could not set sockopt - SO_NP_EXTENSIONS");
#endif
#if defined(_WIN32)
    // SEH: do we even need to do this on windows?
    // This socket will be given to WSAEventSelect which will automatically set it to non-blocking
    u_long opt = 1;
    if (ioctlsocket(skt, FIONBIO, &opt) != 0)
#else
    if (fcntl(skt, F_SETFL, fcntl(skt, F_GETFL, 0) | O_NONBLOCK) != 0)
#endif
    {
        my_perror("ERROR: could not set listen socket to non-blocking mode");
        return mDNSfalse;
    }

    if (listen(skt, LISTENQ) != 0)
    {
        my_perror("ERROR: could not listen on listen socket");
        return mDNSfalse;
    }

    if (mStatus_NoError != udsSupportAddFDToEventLoop(skt, connect_callback, (void *) NULL, (void **) NULL))
    {
        my_perror("ERROR: could not add listen socket to event loop");
        return mDNSfalse;
    }
    else
    {
        LogOperation("%3d: Listening for incoming Unix Domain Socket client requests", skt);
        mDNSStorage.uds_listener_skt = skt;
    }
    return mDNStrue;
}

#if MDNS_MALLOC_DEBUGGING
mDNSlocal void udsserver_validatelists(void *context);
#endif

mDNSexport int udsserver_init(dnssd_sock_t skts[], const size_t count)
{
    dnssd_sockaddr_t laddr;
    int ret;

#ifndef NO_PID_FILE
    FILE *fp = fopen(PID_FILE, "w");
    if (fp != NULL)
    {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
#endif

#if MDNS_MALLOC_DEBUGGING
	static mDNSListValidator validator;
	mDNSPlatformAddListValidator(&validator, udsserver_validatelists, "udsserver_validatelists", NULL);
#endif

    if (skts)
    {
        size_t i;
        for (i = 0; i < count; i++)
            if (dnssd_SocketValid(skts[i]) && !uds_socket_setup(skts[i]))
                goto error;
    }
    else
    {
        listenfd = socket(AF_DNSSD, SOCK_STREAM, 0);
        if (!dnssd_SocketValid(listenfd))
        {
            my_perror("ERROR: socket(AF_DNSSD, SOCK_STREAM, 0); failed");
            goto error;
        }

        mDNSPlatformMemZero(&laddr, sizeof(laddr));

        #if defined(USE_TCP_LOOPBACK)
        {
            laddr.sin_family = AF_INET;
#ifdef WIN32_CENTENNIAL
            // sin_port = 0, use the first available port from the dynamic client port range (49152-65535)
            // (Used to be MDNS_TCP_SERVERPORT_CENTENNIAL)
#else
            laddr.sin_port = htons(MDNS_TCP_SERVERPORT);
#endif
            laddr.sin_addr.s_addr = inet_addr(MDNS_TCP_SERVERADDR);
            ret = bind(listenfd, (struct sockaddr *) &laddr, sizeof(laddr));
            if (ret < 0)
            {
                my_perror("ERROR: bind(listenfd, (struct sockaddr *) &laddr, sizeof(laddr)); failed");
                goto error;
            }

#ifdef WIN32_CENTENNIAL
            // Retrieve the port number assigned to the socket
            mDNSPlatformMemZero(&laddr, sizeof(laddr));
            int len = sizeof(laddr);

            ret = getsockname(listenfd, (struct sockaddr*)&laddr, &len);
            if (ret < 0)
            {
                my_perror("ERROR: getsockname(listenfd, (struct sockaddr*)&laddr, &len); failed");
                goto error;
            }

            char port[128];
            if (0 != _ultoa_s(ntohs(laddr.sin_port), port, sizeof(port), 10))
            {
                my_perror("ERROR: _itoa_s(ntohs(laddr.sin_port), &port); failed");
                goto error;
            }
            if (!SetEnvironmentVariableA("MDNS_TCP_SERVERPORT_CENTENNIAL", port))
            {
                my_perror("ERROR: SetEnvironmentVariableA(MDNS_TCP_SERVERPORT_CENTENNIAL, port); failed");
                goto error;
            }
#endif
        }
        #else
        {
            mode_t mask = umask(0);
            unlink(boundPath);  // OK if this fails
            laddr.sun_family = AF_LOCAL;
            #ifndef NOT_HAVE_SA_LEN
            // According to Stevens (section 3.2), there is no portable way to
            // determine whether sa_len is defined on a particular platform.
            laddr.sun_len = sizeof(struct sockaddr_un);
            #endif
            if (strlen(boundPath) >= sizeof(laddr.sun_path))
            {
                LogMsg("ERROR: MDNS_UDS_SERVERPATH must be < %d characters", (int)sizeof(laddr.sun_path));
                goto error;
            }
            mDNSPlatformStrLCopy(laddr.sun_path, boundPath, sizeof(laddr.sun_path));
            ret = bind(listenfd, (struct sockaddr *) &laddr, sizeof(laddr));
            umask(mask);
            if (ret < 0)
            {
                my_perror("ERROR: bind(listenfd, (struct sockaddr *) &laddr, sizeof(laddr)); failed");
                goto error;
            }
        }
        #endif

        if (!uds_socket_setup(listenfd)) goto error;
    }

#if !defined(PLATFORM_NO_RLIMIT)
    {
        // Set maximum number of open file descriptors
    #define MIN_OPENFILES 10240
        struct rlimit maxfds, newfds;

        // Due to bugs in OS X (<rdar://problem/2941095>, <rdar://problem/3342704>, <rdar://problem/3839173>)
        // you have to get and set rlimits once before getrlimit will return sensible values
        if (getrlimit(RLIMIT_NOFILE, &maxfds) < 0) { my_perror("ERROR: Unable to get file descriptor limit"); return 0; }
        if (setrlimit(RLIMIT_NOFILE, &maxfds) < 0) my_perror("ERROR: Unable to set maximum file descriptor limit");

        if (getrlimit(RLIMIT_NOFILE, &maxfds) < 0) { my_perror("ERROR: Unable to get file descriptor limit"); return 0; }
        newfds.rlim_max = (maxfds.rlim_max > MIN_OPENFILES) ? maxfds.rlim_max : MIN_OPENFILES;
        newfds.rlim_cur = (maxfds.rlim_cur > MIN_OPENFILES) ? maxfds.rlim_cur : MIN_OPENFILES;
        if (newfds.rlim_max != maxfds.rlim_max || newfds.rlim_cur != maxfds.rlim_cur)
            if (setrlimit(RLIMIT_NOFILE, &newfds) < 0) my_perror("ERROR: Unable to set maximum file descriptor limit");

        if (getrlimit(RLIMIT_NOFILE, &maxfds) < 0) { my_perror("ERROR: Unable to get file descriptor limit"); return 0; }
        debugf("maxfds.rlim_max %d", (long)maxfds.rlim_max);
        debugf("maxfds.rlim_cur %d", (long)maxfds.rlim_cur);
    }
#endif

    // We start a "LocalOnly" query looking for Automatic Browse Domain records.
    // When Domain Enumeration in uDNS.c finds an "lb" record from the network, its "FoundDomain" routine
    // creates a "LocalOnly" record, which results in our AutomaticBrowseDomainChange callback being invoked
    mDNS_GetDomains(&mDNSStorage, &mDNSStorage.AutomaticBrowseDomainQ_Internal, mDNS_DomainTypeBrowseAutomatic,
        mDNSNULL, mDNSInterface_LocalOnly, AutomaticBrowseDomainChange, mDNSNULL);

    // Add "local" as recommended registration domain ("dns-sd -E"), recommended browsing domain ("dns-sd -F"), and automatic browsing domain
    RegisterLocalOnlyDomainEnumPTR(&mDNSStorage, &localdomain, mDNS_DomainTypeRegistration);
    RegisterLocalOnlyDomainEnumPTR(&mDNSStorage, &localdomain, mDNS_DomainTypeBrowse);
    AddAutoBrowseDomain(0, &localdomain);

    udsserver_handle_configchange(&mDNSStorage);
    return 0;

error:

    my_perror("ERROR: udsserver_init");
    return -1;
}

mDNSexport int udsserver_exit(void)
{
    // Cancel all outstanding client requests
    while (all_requests) AbortUnlinkAndFree(all_requests);

    // Clean up any special mDNSInterface_LocalOnly records we created, both the entries for "local" we
    // created in udsserver_init, and others we created as a result of reading local configuration data
    while (LocalDomainEnumRecords)
    {
        ARListElem *rem = LocalDomainEnumRecords;
        LocalDomainEnumRecords = LocalDomainEnumRecords->next;
        mDNS_Deregister(&mDNSStorage, &rem->ar);
    }

    // If the launching environment created no listening socket,
    // that means we created it ourselves, so we should clean it up on exit
    if (dnssd_SocketValid(listenfd))
    {
        dnssd_close(listenfd);
#if !defined(USE_TCP_LOOPBACK)
        // Currently, we're unable to remove /var/run/mdnsd because we've changed to userid "nobody"
        // to give up unnecessary privilege, but we need to be root to remove this Unix Domain Socket.
        // It would be nice if we could find a solution to this problem
        if (unlink(boundPath))
            debugf("Unable to remove %s", MDNS_UDS_SERVERPATH);
#endif
    }

#ifndef NO_PID_FILE
    unlink(PID_FILE);
#endif

    return 0;
}

mDNSlocal void LogClientInfoToFD(int fd, request_state *req)
{
    char reqIDStr[14];
    char prefix[18];

    mDNS_snprintf(reqIDStr, sizeof(reqIDStr), "[R%u]", req->request_id);

    mDNS_snprintf(prefix, sizeof(prefix), "%-6s %2s", reqIDStr, req->primary ? "->" : "");

    if (!req->terminate)
        LogToFD(fd, "%s No operation yet on this socket", prefix);
    else if (req->terminate == connection_termination)
    {
        int num_records = 0, num_ops = 0;
        const registered_record_entry *p;
        request_state *r;
        for (p = req->u.reg_recs; p; p=p->next) num_records++;
        for (r = req->next; r; r=r->next) if (r->primary == req) num_ops++;
        LogToFD(fd, "%s DNSServiceCreateConnection: %d registered record%s, %d kDNSServiceFlagsShareConnection operation%s PID[%d](%s)",
                  prefix, num_records, num_records != 1 ? "s" : "", num_ops,     num_ops     != 1 ? "s" : "",
                  req->process_id, req->pid_name);
        for (p = req->u.reg_recs; p; p=p->next)
            LogToFD(fd, " ->  DNSServiceRegisterRecord   0x%08X %2d %3d %s PID[%d](%s)",
                      req->flags, req->interfaceIndex, p->key, ARDisplayString(&mDNSStorage, p->rr), req->process_id, req->pid_name);
        for (r = req->next; r; r=r->next) if (r->primary == req) LogClientInfoToFD(fd, r);
    }
    else if (req->terminate == regservice_termination_callback)
    {
        service_instance *ptr;
        for (ptr = req->u.servicereg.instances; ptr; ptr = ptr->next)
            LogToFD(fd, "%-9s DNSServiceRegister         0x%08X %2d %##s %u/%u PID[%d](%s)",
                      (ptr == req->u.servicereg.instances) ? prefix : "", req->flags, req->interfaceIndex, ptr->srs.RR_SRV.resrec.name->c,
                      mDNSVal16(req->u.servicereg.port),
                      SRS_PORT(&ptr->srs), req->process_id, req->pid_name);
    }
    else if (req->terminate == browse_termination_callback)
    {
        browser_t *blist;
        for (blist = req->u.browser.browsers; blist; blist = blist->next)
            LogToFD(fd, "%-9s DNSServiceBrowse           0x%08X %2d %##s PID[%d](%s)",
                      (blist == req->u.browser.browsers) ? prefix : "", req->flags, req->interfaceIndex, blist->q.qname.c,
                      req->process_id, req->pid_name);
    }
    else if (req->terminate == resolve_termination_callback)
        LogToFD(fd, "%s DNSServiceResolve          0x%08X %2d %##s PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex, req->u.resolve.qsrv.qname.c, req->process_id, req->pid_name);
    else if (req->terminate == queryrecord_termination_callback)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
        const bool redacted = (req->u.queryrecord.op.q.logPrivacyLevel == dnssd_log_privacy_level_private);
#endif

        LogToFD(fd, "%s DNSServiceQueryRecord      0x%08X %2d %##s (%s) PID[%d](%s)", prefix, req->flags,
            req->interfaceIndex,
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
            redacted ? PRIVATE_DOMAIN_NAME : QueryRecordClientRequestGetQName(&req->u.queryrecord),
#else
            QueryRecordClientRequestGetQName(&req->u.queryrecord),
#endif
            DNSTypeName(QueryRecordClientRequestGetType(&req->u.queryrecord)),
            req->process_id, req->pid_name);
    }
    else if (req->terminate == enum_termination_callback)
        LogToFD(fd, "%s DNSServiceEnumerateDomains 0x%08X %2d %##s PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex, req->u.enumeration.q_all.qname.c, req->process_id, req->pid_name);
    else if (req->terminate == port_mapping_termination_callback)
        LogToFD(fd, "%s DNSServiceNATPortMapping   0x%08X %2d %s%s Int %5d Req %5d Ext %.4a:%5d Req TTL %5d Granted TTL %5d PID[%d](%s)",
                  prefix,
                  req->flags,
                  req->interfaceIndex,
                  req->u.pm.NATinfo.Protocol & NATOp_MapTCP ? "TCP" : "   ",
                  req->u.pm.NATinfo.Protocol & NATOp_MapUDP ? "UDP" : "   ",
                  mDNSVal16(req->u.pm.NATinfo.IntPort),
                  mDNSVal16(req->u.pm.ReqExt),
                  &req->u.pm.NATinfo.ExternalAddress,
                  mDNSVal16(req->u.pm.NATinfo.ExternalPort),
                  req->u.pm.NATinfo.NATLease,
                  req->u.pm.NATinfo.Lifetime,
                  req->process_id, req->pid_name);
    else if (req->terminate == addrinfo_termination_callback)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
        const GetAddrInfoClientRequest *const request = &req->u.addrinfo;
        bool redacted = false;
        if (request->op4)
        {
            redacted = (request->op4->q.logPrivacyLevel == dnssd_log_privacy_level_private);
        }
        else if (request->op6)
        {
            redacted = (request->op6->q.logPrivacyLevel == dnssd_log_privacy_level_private);
        }
#endif

        LogToFD(fd, "%s DNSServiceGetAddrInfo      0x%08X %2d %s%s %##s PID[%d](%s)", prefix, req->flags,
            req->interfaceIndex,
            req->u.addrinfo.protocols & kDNSServiceProtocol_IPv4 ? "v4" : "  ",
            req->u.addrinfo.protocols & kDNSServiceProtocol_IPv6 ? "v6" : "  ",
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
            redacted ? PRIVATE_DOMAIN_NAME : GetAddrInfoClientRequestGetQName(&req->u.addrinfo),
#else
            GetAddrInfoClientRequestGetQName(&req->u.addrinfo),
#endif
            req->process_id, req->pid_name);
    }
    else
        LogToFD(fd, "%s Unrecognized operation %p", prefix, req->terminate);
}

mDNSlocal void LogClientInfo(request_state *req)
{
    char reqIDStr[14];
    char prefix[18];

    mDNS_snprintf(reqIDStr, sizeof(reqIDStr), "[R%u]", req->request_id);

    mDNS_snprintf(prefix, sizeof(prefix), "%-6s %2s", reqIDStr, req->primary ? "->" : "");

    if (!req->terminate)
    LogMsgNoIdent("%s No operation yet on this socket", prefix);
    else if (req->terminate == connection_termination)
    {
        int num_records = 0, num_ops = 0;
        const registered_record_entry *p;
        request_state *r;
        for (p = req->u.reg_recs; p; p=p->next) num_records++;
        for (r = req->next; r; r=r->next) if (r->primary == req) num_ops++;
        LogMsgNoIdent("%s DNSServiceCreateConnection: %d registered record%s, %d kDNSServiceFlagsShareConnection operation%s PID[%d](%s)",
                      prefix, num_records, num_records != 1 ? "s" : "", num_ops,     num_ops     != 1 ? "s" : "",
                      req->process_id, req->pid_name);
        for (p = req->u.reg_recs; p; p=p->next)
        LogMsgNoIdent(" ->  DNSServiceRegisterRecord   0x%08X %2d %3d %s PID[%d](%s)",
                      req->flags, req->interfaceIndex, p->key, ARDisplayString(&mDNSStorage, p->rr), req->process_id, req->pid_name);
        for (r = req->next; r; r=r->next) if (r->primary == req) LogClientInfo(r);
    }
    else if (req->terminate == regservice_termination_callback)
    {
        service_instance *ptr;
        for (ptr = req->u.servicereg.instances; ptr; ptr = ptr->next)
        LogMsgNoIdent("%-9s DNSServiceRegister         0x%08X %2d %##s %u/%u PID[%d](%s)",
                      (ptr == req->u.servicereg.instances) ? prefix : "", req->flags, req->interfaceIndex, ptr->srs.RR_SRV.resrec.name->c,
                      mDNSVal16(req->u.servicereg.port),
                      SRS_PORT(&ptr->srs), req->process_id, req->pid_name);
    }
    else if (req->terminate == browse_termination_callback)
    {
        browser_t *blist;
        for (blist = req->u.browser.browsers; blist; blist = blist->next)
        LogMsgNoIdent("%-9s DNSServiceBrowse           0x%08X %2d %##s PID[%d](%s)",
                      (blist == req->u.browser.browsers) ? prefix : "", req->flags, req->interfaceIndex, blist->q.qname.c,
                      req->process_id, req->pid_name);
    }
    else if (req->terminate == resolve_termination_callback)
    LogMsgNoIdent("%s DNSServiceResolve          0x%08X %2d %##s PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex, req->u.resolve.qsrv.qname.c, req->process_id, req->pid_name);
    else if (req->terminate == queryrecord_termination_callback)
    LogMsgNoIdent("%s DNSServiceQueryRecord      0x%08X %2d %##s (%s) PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex, QueryRecordClientRequestGetQName(&req->u.queryrecord), DNSTypeName(QueryRecordClientRequestGetType(&req->u.queryrecord)), req->process_id, req->pid_name);
    else if (req->terminate == enum_termination_callback)
    LogMsgNoIdent("%s DNSServiceEnumerateDomains 0x%08X %2d %##s PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex, req->u.enumeration.q_all.qname.c, req->process_id, req->pid_name);
    else if (req->terminate == port_mapping_termination_callback)
    LogMsgNoIdent("%s DNSServiceNATPortMapping   0x%08X %2d %s%s Int %5d Req %5d Ext %.4a:%5d Req TTL %5d Granted TTL %5d PID[%d](%s)",
                  prefix,
                  req->flags,
                  req->interfaceIndex,
                  req->u.pm.NATinfo.Protocol & NATOp_MapTCP ? "TCP" : "   ",
                  req->u.pm.NATinfo.Protocol & NATOp_MapUDP ? "UDP" : "   ",
                  mDNSVal16(req->u.pm.NATinfo.IntPort),
                  mDNSVal16(req->u.pm.ReqExt),
                  &req->u.pm.NATinfo.ExternalAddress,
                  mDNSVal16(req->u.pm.NATinfo.ExternalPort),
                  req->u.pm.NATinfo.NATLease,
                  req->u.pm.NATinfo.Lifetime,
                  req->process_id, req->pid_name);
    else if (req->terminate == addrinfo_termination_callback)
    LogMsgNoIdent("%s DNSServiceGetAddrInfo      0x%08X %2d %s%s %##s PID[%d](%s)",
                  prefix, req->flags, req->interfaceIndex,
                  req->u.addrinfo.protocols & kDNSServiceProtocol_IPv4 ? "v4" : "  ",
                  req->u.addrinfo.protocols & kDNSServiceProtocol_IPv6 ? "v6" : "  ",
                  GetAddrInfoClientRequestGetQName(&req->u.addrinfo), req->process_id, req->pid_name);
    else
    LogMsgNoIdent("%s Unrecognized operation %p", prefix, req->terminate);
}

mDNSlocal void GetMcastClients(request_state *req)
{
    if (req->terminate == connection_termination)
    {
        int num_records = 0, num_ops = 0;
        const registered_record_entry *p;
        request_state *r;
        for (p = req->u.reg_recs; p; p=p->next)
            num_records++;
        for (r = req->next; r; r=r->next)
            if (r->primary == req)
                num_ops++;
        for (p = req->u.reg_recs; p; p=p->next)
        {
            if (!AuthRecord_uDNS(p->rr))
                n_mrecords++;
        }
        for (r = req->next; r; r=r->next)
            if (r->primary == req)
                GetMcastClients(r);
    }
    else if (req->terminate == regservice_termination_callback)
    {
        service_instance *ptr;
        for (ptr = req->u.servicereg.instances; ptr; ptr = ptr->next)
        {
            if (!AuthRecord_uDNS(&ptr->srs.RR_SRV))
                n_mrecords++;
        }
    }
    else if (req->terminate == browse_termination_callback)
    {
        browser_t *blist;
        for (blist = req->u.browser.browsers; blist; blist = blist->next)
        {
            if (mDNSOpaque16IsZero(blist->q.TargetQID))
                n_mquests++;
        }
    }
    else if (req->terminate == resolve_termination_callback)
    {
        if ((mDNSOpaque16IsZero(req->u.resolve.qsrv.TargetQID)) && (req->u.resolve.qsrv.ThisQInterval > 0))
            n_mquests++;
    }
    else if (req->terminate == queryrecord_termination_callback)
    {
        if (QueryRecordClientRequestIsMulticast(&req->u.queryrecord))
            n_mquests++;
    }
    else if (req->terminate == addrinfo_termination_callback)
    {
        if (GetAddrInfoClientRequestIsMulticast(&req->u.addrinfo))
            n_mquests++;
    }
    else
    {
        return;
    }
}


mDNSlocal void LogMcastClientInfo(request_state *req)
{
    if (!req->terminate)
        LogMcastNoIdent("No operation yet on this socket");
    else if (req->terminate == connection_termination)
    {
        int num_records = 0, num_ops = 0;
        const registered_record_entry *p;
        request_state *r;
        for (p = req->u.reg_recs; p; p=p->next)
            num_records++;
        for (r = req->next; r; r=r->next)
            if (r->primary == req)
                num_ops++;
        for (p = req->u.reg_recs; p; p=p->next)
        {
            if (!AuthRecord_uDNS(p->rr))
                LogMcastNoIdent("R: ->  DNSServiceRegisterRecord:  %##s %s PID[%d](%s)", p->rr->resrec.name->c,
                                DNSTypeName(p->rr->resrec.rrtype), req->process_id, req->pid_name, i_mcount++);
        }
        for (r = req->next; r; r=r->next)
            if (r->primary == req)
                LogMcastClientInfo(r);
    }
    else if (req->terminate == regservice_termination_callback)
    {
        service_instance *ptr;
        for (ptr = req->u.servicereg.instances; ptr; ptr = ptr->next)
        {
            if (!AuthRecord_uDNS(&ptr->srs.RR_SRV))
                LogMcastNoIdent("R: DNSServiceRegister:  %##s %u/%u PID[%d](%s)", ptr->srs.RR_SRV.resrec.name->c, mDNSVal16(req->u.servicereg.port),
                                SRS_PORT(&ptr->srs), req->process_id, req->pid_name, i_mcount++);
        }
    }
    else if (req->terminate == browse_termination_callback)
    {
        browser_t *blist;
        for (blist = req->u.browser.browsers; blist; blist = blist->next)
        {
            if (mDNSOpaque16IsZero(blist->q.TargetQID))
                LogMcastNoIdent("Q: DNSServiceBrowse  %##s %s PID[%d](%s)", blist->q.qname.c, DNSTypeName(blist->q.qtype),
                                req->process_id, req->pid_name, i_mcount++);
        }
    }
    else if (req->terminate == resolve_termination_callback)
    {
        if ((mDNSOpaque16IsZero(req->u.resolve.qsrv.TargetQID)) && (req->u.resolve.qsrv.ThisQInterval > 0))
            LogMcastNoIdent("Q: DNSServiceResolve  %##s %s PID[%d](%s)", req->u.resolve.qsrv.qname.c, DNSTypeName(req->u.resolve.qsrv.qtype),
                            req->process_id, req->pid_name, i_mcount++);
    }
    else if (req->terminate == queryrecord_termination_callback)
    {
        if (QueryRecordClientRequestIsMulticast(&req->u.queryrecord))
        {
            LogMcastNoIdent("Q: DNSServiceQueryRecord  %##s %s PID[%d](%s)",
                          QueryRecordClientRequestGetQName(&req->u.queryrecord),
                          DNSTypeName(QueryRecordClientRequestGetType(&req->u.queryrecord)),
                          req->process_id, req->pid_name, i_mcount++);
        }
    }
    else if (req->terminate == addrinfo_termination_callback)
    {
        if (GetAddrInfoClientRequestIsMulticast(&req->u.addrinfo))
        {
            LogMcastNoIdent("Q: DNSServiceGetAddrInfo  %s%s %##s PID[%d](%s)",
                          req->u.addrinfo.protocols & kDNSServiceProtocol_IPv4 ? "v4" : "  ",
                          req->u.addrinfo.protocols & kDNSServiceProtocol_IPv6 ? "v6" : "  ",
                          GetAddrInfoClientRequestGetQName(&req->u.addrinfo), req->process_id, req->pid_name, i_mcount++);
        }
    }
}

mDNSlocal char *RecordTypeName(mDNSu8 rtype)
{
    switch (rtype)
    {
    case kDNSRecordTypeUnregistered:  return ("Unregistered ");
    case kDNSRecordTypeDeregistering: return ("Deregistering");
    case kDNSRecordTypeUnique:        return ("Unique       ");
    case kDNSRecordTypeAdvisory:      return ("Advisory     ");
    case kDNSRecordTypeShared:        return ("Shared       ");
    case kDNSRecordTypeVerified:      return ("Verified     ");
    case kDNSRecordTypeKnownUnique:   return ("KnownUnique  ");
    default: return("Unknown");
    }
}

mDNSlocal int LogEtcHostsToFD(int fd, mDNS *const m)
{
    mDNSBool showheader = mDNStrue;
    const AuthRecord *ar;
    mDNSu32 slot;
    AuthGroup *ag;
    int count = 0;
    int authslot = 0;
    mDNSBool truncated = 0;

    for (slot = 0; slot < AUTH_HASH_SLOTS; slot++)
    {
        if (m->rrauth.rrauth_hash[slot]) authslot++;
        for (ag = m->rrauth.rrauth_hash[slot]; ag; ag = ag->next)
            for (ar = ag->members; ar; ar = ar->next)
            {
                if (ar->RecordCallback != FreeEtcHosts) continue;
                if (showheader) { showheader = mDNSfalse; LogToFD(fd, "  State       Interface"); }

                // Print a maximum of 50 records
                if (count++ >= 50) { truncated = mDNStrue; continue; }
                if (ar->ARType == AuthRecordLocalOnly)
                {
                    if (ar->resrec.InterfaceID == mDNSInterface_LocalOnly)
                        LogToFD(fd, " %s   LO %s", RecordTypeName(ar->resrec.RecordType), ARDisplayString(m, ar));
                    else
                    {
                        mDNSu32 scopeid  = (mDNSu32)(uintptr_t)ar->resrec.InterfaceID;
                        LogToFD(fd, " %s   %u  %s", RecordTypeName(ar->resrec.RecordType), scopeid, ARDisplayString(m, ar));
                    }
                }
            }
    }

    if (showheader) LogToFD(fd, "<None>");
    else if (truncated) LogToFD(fd, "<Truncated: to 50 records, Total records %d, Total Auth Groups %d, Auth Slots %d>", count, m->rrauth.rrauth_totalused, authslot);
    return count;
}

mDNSlocal void LogLocalOnlyAuthRecordsToFD(int fd, mDNS *const m)
{
    mDNSBool showheader = mDNStrue;
    const AuthRecord *ar;
    mDNSu32 slot;
    AuthGroup *ag;

    for (slot = 0; slot < AUTH_HASH_SLOTS; slot++)
    {
        for (ag = m->rrauth.rrauth_hash[slot]; ag; ag = ag->next)
            for (ar = ag->members; ar; ar = ar->next)
            {
                if (ar->RecordCallback == FreeEtcHosts) continue;
                if (showheader) { showheader = mDNSfalse; LogToFD(fd, "  State       Interface"); }

                // Print a maximum of 400 records
                if (ar->ARType == AuthRecordLocalOnly)
                    LogToFD(fd, " %s   LO  %s", RecordTypeName(ar->resrec.RecordType), ARDisplayString(m, ar));
                else if (ar->ARType == AuthRecordP2P)
                {
                    if (ar->resrec.InterfaceID == mDNSInterface_BLE)
                        LogToFD(fd, " %s   BLE %s", RecordTypeName(ar->resrec.RecordType), ARDisplayString(m, ar));
                    else
                        LogToFD(fd, " %s   PP  %s", RecordTypeName(ar->resrec.RecordType), ARDisplayString(m, ar));
                }
            }
    }

    if (showheader) LogToFD(fd, "<None>");
}

mDNSlocal void LogOneAuthRecordToFD(int fd, const AuthRecord *ar, mDNSs32 now, const char *ifname)
{
    if (AuthRecord_uDNS(ar))
    {
        LogToFD(fd, "%7d %7d %7d %-7s %4d %s %s",
                  ar->ThisAPInterval / mDNSPlatformOneSecond,
                  (ar->LastAPTime + ar->ThisAPInterval - now) / mDNSPlatformOneSecond,
                  ar->expire ? (ar->expire - now) / mDNSPlatformOneSecond : 0,
                  "-U-",
                  ar->state,
                  ar->AllowRemoteQuery ? "☠" : " ",
                  ARDisplayString(&mDNSStorage, ar));
    }
    else
    {
        LogToFD(fd, "%7d %7d %7d %-7s 0x%02X %s %s",
                  ar->ThisAPInterval / mDNSPlatformOneSecond,
                  ar->AnnounceCount ? (ar->LastAPTime + ar->ThisAPInterval - now) / mDNSPlatformOneSecond : 0,
                  ar->TimeExpire    ? (ar->TimeExpire                      - now) / mDNSPlatformOneSecond : 0,
                  ifname ? ifname : "ALL",
                  ar->resrec.RecordType,
                  ar->AllowRemoteQuery ? "☠" : " ",
                  ARDisplayString(&mDNSStorage, ar));
    }
}

mDNSlocal void LogAuthRecordsToFD(int fd,
                                    const mDNSs32 now, AuthRecord *ResourceRecords, int *proxy)
{
    mDNSBool showheader = mDNStrue;
    const AuthRecord *ar;
    OwnerOptData owner = zeroOwner;
    for (ar = ResourceRecords; ar; ar=ar->next)
    {
        const char *const ifname = InterfaceNameForID(&mDNSStorage, ar->resrec.InterfaceID);
        if ((ar->WakeUp.HMAC.l[0] != 0) == (proxy != mDNSNULL))
        {
            if (showheader) { showheader = mDNSfalse; LogToFD(fd, "    Int    Next  Expire if     State"); }
            if (proxy) (*proxy)++;
            if (!mDNSPlatformMemSame(&owner, &ar->WakeUp, sizeof(owner)))
            {
                owner = ar->WakeUp;
                if (owner.password.l[0])
                    LogToFD(fd, "Proxying for H-MAC %.6a I-MAC %.6a Password %.6a seq %d", &owner.HMAC, &owner.IMAC, &owner.password, owner.seq);
                else if (!mDNSSameEthAddress(&owner.HMAC, &owner.IMAC))
                    LogToFD(fd, "Proxying for H-MAC %.6a I-MAC %.6a seq %d",               &owner.HMAC, &owner.IMAC,                  owner.seq);
                else
                    LogToFD(fd, "Proxying for %.6a seq %d",                                &owner.HMAC,                               owner.seq);
            }
            if (AuthRecord_uDNS(ar))
            {
                LogOneAuthRecordToFD(fd, ar, now, ifname);
            }
            else if (ar->ARType == AuthRecordLocalOnly)
            {
                LogToFD(fd, "                             LO %s", ARDisplayString(&mDNSStorage, ar));
            }
            else if (ar->ARType == AuthRecordP2P)
            {
                if (ar->resrec.InterfaceID == mDNSInterface_BLE)
                    LogToFD(fd, "                             BLE %s", ARDisplayString(&mDNSStorage, ar));
                else
                    LogToFD(fd, "                             PP %s", ARDisplayString(&mDNSStorage, ar));
            }
            else
            {
                LogOneAuthRecordToFD(fd, ar, now, ifname);
            }
        }
    }
    if (showheader) LogToFD(fd, "<None>");
}

mDNSlocal void PrintOneCacheRecordToFD(int fd, const CacheRecord *cr, mDNSu32 slot, const mDNSu32 remain, const char *ifname, mDNSu32 *CacheUsed)
{

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    char *dnssec_description = dnssec_obj_resource_record_member_copy_state_dump_description(cr->resrec.dnssec, NULL);
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
    const mDNSBool redacted = (cr->PrivacyLevel == CRLogPrivacyLevel_Private);
#endif

    LogToFD(fd, "%3d %s%8d %-7s%s %-6s"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
              "   %-40s"
#endif
              "%s",
              slot,
              cr->CRActiveQuestion ? "*" : " ",
              remain,
              ifname ? ifname : "-U-",
              (cr->resrec.RecordType == kDNSRecordTypePacketNegative)  ? "-" :
              (cr->resrec.RecordType & kDNSRecordTypePacketUniqueMask) ? " " : "+",
              DNSTypeName(cr->resrec.rrtype),
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
              dnssec_description,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
              redacted ? "     " PRIVATE_RECORD_DESCRIPTION : CRDisplayString(&mDNSStorage, cr)
#else
              CRDisplayString(&mDNSStorage, cr)
#endif
            );
    (*CacheUsed)++;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    mdns_free(dnssec_description);
#endif
}

mDNSlocal void PrintCachedRecordsToFD(int fd, const CacheRecord *cr, mDNSu32 slot, const mDNSu32 remain, const char *ifname, mDNSu32 *CacheUsed)
{
    CacheRecord *soa;

    soa = cr->soa;
    if (soa)
    {
        PrintOneCacheRecordToFD(fd, soa, slot, remain, ifname, CacheUsed);
    }
}

mDNSexport void LogMDNSStatisticsToFD(int fd, mDNS *const m)
{
    LogToFD(fd, "--- MDNS Statistics ---");

    LogToFD(fd, "Name Conflicts                 %u", m->mDNSStats.NameConflicts);
    LogToFD(fd, "KnownUnique Name Conflicts     %u", m->mDNSStats.KnownUniqueNameConflicts);
    LogToFD(fd, "Duplicate Query Suppressions   %u", m->mDNSStats.DupQuerySuppressions);
    LogToFD(fd, "KA Suppressions                %u", m->mDNSStats.KnownAnswerSuppressions);
    LogToFD(fd, "KA Multiple Packets            %u", m->mDNSStats.KnownAnswerMultiplePkts);
    LogToFD(fd, "Poof Cache Deletions           %u", m->mDNSStats.PoofCacheDeletions);
    LogToFD(fd, "--------------------------------");

    LogToFD(fd, "Multicast packets Sent         %u", m->MulticastPacketsSent);
    LogToFD(fd, "Multicast packets Received     %u", m->MPktNum);
    LogToFD(fd, "Remote Subnet packets          %u", m->RemoteSubnet);
    LogToFD(fd, "QU questions  received         %u", m->mDNSStats.UnicastBitInQueries);
    LogToFD(fd, "Normal multicast questions     %u", m->mDNSStats.NormalQueries);
    LogToFD(fd, "Answers for questions          %u", m->mDNSStats.MatchingAnswersForQueries);
    LogToFD(fd, "Unicast responses              %u", m->mDNSStats.UnicastResponses);
    LogToFD(fd, "Multicast responses            %u", m->mDNSStats.MulticastResponses);
    LogToFD(fd, "Unicast response Demotions     %u", m->mDNSStats.UnicastDemotedToMulticast);
    LogToFD(fd, "--------------------------------");

    LogToFD(fd, "Sleeps                         %u", m->mDNSStats.Sleeps);
    LogToFD(fd, "Wakeups                        %u", m->mDNSStats.Wakes);
    LogToFD(fd, "Interface UP events            %u", m->mDNSStats.InterfaceUp);
    LogToFD(fd, "Interface UP Flap events       %u", m->mDNSStats.InterfaceUpFlap);
    LogToFD(fd, "Interface Down events          %u", m->mDNSStats.InterfaceDown);
    LogToFD(fd, "Interface DownFlap events      %u", m->mDNSStats.InterfaceDownFlap);
    LogToFD(fd, "Cache refresh queries          %u", m->mDNSStats.CacheRefreshQueries);
    LogToFD(fd, "Cache refreshed                %u", m->mDNSStats.CacheRefreshed);
    LogToFD(fd, "Wakeup on Resolves             %u", m->mDNSStats.WakeOnResolves);
}

mDNSexport void udsserver_info_dump_to_fd(int fd)
{
    mDNS *const m = &mDNSStorage;
    const mDNSs32 now = mDNS_TimeNow(m);
    mDNSu32 CacheUsed = 0, CacheActive = 0, slot;
    int ProxyA = 0, ProxyD = 0;
    mDNSu32 groupCount = 0;
    mDNSu32 mcastRecordCount = 0;
    mDNSu32 ucastRecordCount = 0;
    const CacheGroup *cg;
    const CacheRecord *cr;
    const DNSQuestion *q;
    const DNameListElem *d;
    const SearchListElem *s;

    LogToFD(fd, "------------ Cache -------------");
    LogToFD(fd, "Slt Q     TTL if     U Type     DNSSEC                                   rdlen");
    for (slot = 0; slot < CACHE_HASH_SLOTS; slot++)
    {
        for (cg = m->rrcache_hash[slot]; cg; cg=cg->next)
        {
            groupCount++;   // Count one cache entity for the CacheGroup object
            for (cr = cg->members; cr; cr=cr->next)
            {
                const mDNSu32 remain = cr->resrec.rroriginalttl - (mDNSu32)((now - cr->TimeRcvd) / mDNSPlatformOneSecond);
                const char *ifname;
                mDNSInterfaceID InterfaceID = cr->resrec.InterfaceID;
                mDNSu32 *const countPtr = InterfaceID ? &mcastRecordCount : &ucastRecordCount;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
                if (!InterfaceID && cr->resrec.dnsservice &&
                    (mdns_dns_service_get_scope(cr->resrec.dnsservice) == mdns_dns_service_scope_interface))
                {
                    InterfaceID = (mDNSInterfaceID)(uintptr_t)mdns_dns_service_get_interface_index(cr->resrec.dnsservice);
                }
#else
                if (!InterfaceID && cr->resrec.rDNSServer && cr->resrec.rDNSServer->scopeType)
                    InterfaceID = cr->resrec.rDNSServer->interface;
#endif
                ifname = InterfaceNameForID(m, InterfaceID);
                if (cr->CRActiveQuestion) CacheActive++;
                PrintOneCacheRecordToFD(fd, cr, slot, remain, ifname, countPtr);
                PrintCachedRecordsToFD(fd, cr, slot, remain, ifname, countPtr);
            }
        }
    }

    CacheUsed = groupCount + mcastRecordCount + ucastRecordCount;
    if (m->rrcache_totalused != CacheUsed)
        LogToFD(fd, "Cache use mismatch: rrcache_totalused is %lu, true count %lu", m->rrcache_totalused, CacheUsed);
    if (m->rrcache_active != CacheActive)
        LogToFD(fd, "Cache use mismatch: rrcache_active is %lu, true count %lu", m->rrcache_active, CacheActive);
    LogToFD(fd, "Cache size %u entities; %u in use (%u group, %u multicast, %u unicast); %u referenced by active questions",
              m->rrcache_size, CacheUsed, groupCount, mcastRecordCount, ucastRecordCount, CacheActive);

    LogToFD(fd, "--------- Auth Records ---------");
    LogAuthRecordsToFD(fd, now, m->ResourceRecords, mDNSNULL);

    LogToFD(fd, "--------- LocalOnly, P2P Auth Records ---------");
    LogLocalOnlyAuthRecordsToFD(fd, m);

    LogToFD(fd, "--------- /etc/hosts ---------");
    LogEtcHostsToFD(fd, m);

    LogToFD(fd, "------ Duplicate Records -------");
    LogAuthRecordsToFD(fd, now, m->DuplicateRecords, mDNSNULL);

    LogToFD(fd, "----- Auth Records Proxied -----");
    LogAuthRecordsToFD(fd, now, m->ResourceRecords, &ProxyA);

    LogToFD(fd, "-- Duplicate Records Proxied ---");
    LogAuthRecordsToFD(fd, now, m->DuplicateRecords, &ProxyD);

    LogToFD(fd, "---------- Questions -----------");
    if (!m->Questions) LogToFD(fd, "<None>");
    else
    {
        CacheUsed = 0;
        CacheActive = 0;
        LogToFD(fd, "   Int  Next if     T NumAns "
    #if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
                "VDNS                               "
    #endif
                "Qptr               DupOf              SU SQ "
    #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
                "DNSSEC "
    #endif
                "Type    Name");
        for (q = m->Questions; q; q=q->next)
        {
            mDNSs32 i = q->ThisQInterval / mDNSPlatformOneSecond;
            mDNSs32 n = (NextQSendTime(q) - now) / mDNSPlatformOneSecond;
            char *ifname = InterfaceNameForID(m, q->InterfaceID);
            CacheUsed++;
            if (q->ThisQInterval) CacheActive++;

#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
            const mDNSBool redacted = (q->logPrivacyLevel == dnssd_log_privacy_level_private);
#endif

            LogToFD(fd, "%6d%6d %-7s%s %6d "
                #if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
                    "0x%08x%08x%08x%08x "
                #endif
                    "0x%p 0x%p %1d %2d  "
                #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
                    "%-7s"
                #endif
                    "%-8s%##s%s",
                      i, n,
                      ifname ? ifname : mDNSOpaque16IsZero(q->TargetQID) ? "" : "-U-",
                      mDNSOpaque16IsZero(q->TargetQID) ? (q->LongLived ? "l" : " ") : (q->LongLived ? "L" : "O"),
                      q->CurrentAnswers,
                #if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
                      q->validDNSServers.l[3], q->validDNSServers.l[2], q->validDNSServers.l[1], q->validDNSServers.l[0],
                #endif
                      q, q->DuplicateOf,
                      q->SuppressUnusable, q->Suppressed,
                #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
                      dns_question_is_dnssec_requestor(q) ? "YES" : "NO",
                #endif
                      DNSTypeName(q->qtype),
                #if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
                      redacted ? PRIVATE_DOMAIN_NAME->c : q->qname.c,
                #else
                      q->qname.c,
                #endif
                      q->DuplicateOf ? " (dup)" : "");
        }
        LogToFD(fd, "%lu question%s; %lu active", CacheUsed, CacheUsed > 1 ? "s" : "", CacheActive);
    }

    LogToFD(fd, "----- LocalOnly, P2P Questions -----");
    if (!m->LocalOnlyQuestions) LogToFD(fd, "<None>");
    else for (q = m->LocalOnlyQuestions; q; q=q->next)
        LogToFD(fd, "                 %3s   %5d  %-6s%##s%s",
                  q->InterfaceID == mDNSInterface_LocalOnly ? "LO ": q->InterfaceID == mDNSInterface_BLE ? "BLE": "P2P",
                  q->CurrentAnswers, DNSTypeName(q->qtype), q->qname.c, q->DuplicateOf ? " (dup)" : "");

    LogToFD(fd, "---- Active UDS Client Requests ----");
    if (!all_requests) LogToFD(fd, "<None>");
    else
    {
        request_state *req, *r;
        for (req = all_requests; req; req=req->next)
        {
            if (req->primary)   // If this is a subbordinate operation, check that the parent is in the list
            {
                for (r = all_requests; r && r != req; r=r->next) if (r == req->primary) goto foundparent;
                LogToFD(fd, "%3d: Orhpan operation %p; parent %p not found in request list", req->sd);
            }
            // For non-subbordinate operations, and subbordinate operations that have lost their parent, write out their info
            LogClientInfoToFD(fd, req);
        foundparent:;
        }
    }

    LogToFD(fd, "-------- NAT Traversals --------");
    LogToFD(fd, "ExtAddress %.4a Retry %d Interval %d",
              &m->ExtAddress,
              m->retryGetAddr ? (m->retryGetAddr - now) / mDNSPlatformOneSecond : 0,
              m->retryIntervalGetAddr / mDNSPlatformOneSecond);
    if (m->NATTraversals)
    {
        const NATTraversalInfo *nat;
        for (nat = m->NATTraversals; nat; nat=nat->next)
        {
            LogToFD(fd, "%p %s Int %5d %s Err %d Retry %5d Interval %5d Expire %5d Req %.4a:%d Ext %.4a:%d",
                      nat,
                      nat->Protocol ? (nat->Protocol == NATOp_MapTCP ? "TCP" : "UDP") : "ADD",
                      mDNSVal16(nat->IntPort),
                      (nat->lastSuccessfulProtocol == NATTProtocolNone    ? "None    " :
                       nat->lastSuccessfulProtocol == NATTProtocolNATPMP  ? "NAT-PMP " :
                       nat->lastSuccessfulProtocol == NATTProtocolUPNPIGD ? "UPnP/IGD" :
                       nat->lastSuccessfulProtocol == NATTProtocolPCP     ? "PCP     " :
                       /* else */                                           "Unknown " ),
                      nat->Result,
                      nat->retryPortMap ? (nat->retryPortMap - now) / mDNSPlatformOneSecond : 0,
                      nat->retryInterval / mDNSPlatformOneSecond,
                      nat->ExpiryTime ? (nat->ExpiryTime - now) / mDNSPlatformOneSecond : 0,
                      &nat->NewAddress, mDNSVal16(nat->RequestedPort),
                      &nat->ExternalAddress, mDNSVal16(nat->ExternalPort));
        }
    }

    LogToFD(fd, "--------- AuthInfoList ---------");
    if (!m->AuthInfoList) LogToFD(fd, "<None>");
    else
    {
        const DomainAuthInfo *a;
        for (a = m->AuthInfoList; a; a = a->next)
        {
            LogToFD(fd, "%##s %##s %##s %d %d",
                      a->domain.c, a->keyname.c,
                      a->hostname.c, (a->port.b[0] << 8 | a->port.b[1]),
                      (a->deltime ? (a->deltime - now) : 0));
        }
    }

    LogToFD(fd, "---------- Misc State ----------");

    LogToFD(fd, "PrimaryMAC:   %.6a", &m->PrimaryMAC);

    LogToFD(fd, "m->SleepState %d (%s) seq %d",
              m->SleepState,
              m->SleepState == SleepState_Awake        ? "Awake"        :
              m->SleepState == SleepState_Transferring ? "Transferring" :
              m->SleepState == SleepState_Sleeping     ? "Sleeping"     : "?",
              m->SleepSeqNum);

    if (!m->SPSSocket) LogToFD(fd, "Not offering Sleep Proxy Service");
#ifndef SPC_DISABLED
    else LogToFD(fd, "Offering Sleep Proxy Service: %#s", m->SPSRecords.RR_SRV.resrec.name->c);
#endif
    if (m->ProxyRecords == ProxyA + ProxyD) LogToFD(fd, "ProxyRecords: %d + %d = %d", ProxyA, ProxyD, ProxyA + ProxyD);
    else LogToFD(fd, "ProxyRecords: MISMATCH %d + %d = %d ≠ %d", ProxyA, ProxyD, ProxyA + ProxyD, m->ProxyRecords);

    LogToFD(fd, "------ Auto Browse Domains -----");
    if (!AutoBrowseDomains) LogToFD(fd, "<None>");
    else for (d=AutoBrowseDomains; d; d=d->next) LogToFD(fd, "%##s", d->name.c);

    LogToFD(fd, "--- Auto Registration Domains --");
    if (!AutoRegistrationDomains) LogToFD(fd, "<None>");
    else for (d=AutoRegistrationDomains; d; d=d->next) LogToFD(fd, "%##s", d->name.c);

    LogToFD(fd, "--- Search Domains --");
    if (!SearchList) LogToFD(fd, "<None>");
    else
    {
        for (s=SearchList; s; s=s->next)
        {
            char *ifname = InterfaceNameForID(m, s->InterfaceID);
            LogToFD(fd, "%##s %s", s->domain.c, ifname ? ifname : "");
        }
    }
    LogMDNSStatisticsToFD(fd, m);

    LogToFD(fd, "---- Task Scheduling Timers ----");

#if MDNSRESPONDER_SUPPORTS(APPLE, BONJOUR_ON_DEMAND)
    LogToFD(fd, "BonjourEnabled %d", m->BonjourEnabled);
#endif

    if (!m->NewQuestions)
        LogToFD(fd, "NewQuestion <NONE>");
    else
        LogToFD(fd, "NewQuestion DelayAnswering %d %d %##s (%s)",
                  m->NewQuestions->DelayAnswering, m->NewQuestions->DelayAnswering-now,
                  m->NewQuestions->qname.c, DNSTypeName(m->NewQuestions->qtype));

    if (!m->NewLocalOnlyQuestions)
        LogToFD(fd, "NewLocalOnlyQuestions <NONE>");
    else
        LogToFD(fd, "NewLocalOnlyQuestions %##s (%s)",
                  m->NewLocalOnlyQuestions->qname.c, DNSTypeName(m->NewLocalOnlyQuestions->qtype));

    if (!m->NewLocalRecords)
        LogToFD(fd, "NewLocalRecords <NONE>");
    else
        LogToFD(fd, "NewLocalRecords %02X %s", m->NewLocalRecords->resrec.RecordType, ARDisplayString(m, m->NewLocalRecords));

    LogToFD(fd, "SPSProxyListChanged%s", m->SPSProxyListChanged ? "" : " <NONE>");
    LogToFD(fd, "LocalRemoveEvents%s",   m->LocalRemoveEvents   ? "" : " <NONE>");
    LogToFD(fd, "m->WABBrowseQueriesCount %d", m->WABBrowseQueriesCount);
    LogToFD(fd, "m->WABLBrowseQueriesCount %d", m->WABLBrowseQueriesCount);
    LogToFD(fd, "m->WABRegQueriesCount %d", m->WABRegQueriesCount);
    LogToFD(fd, "m->AutoTargetServices %u", m->AutoTargetServices);
#if MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME)
    LogToFD(fd, "m->AutoTargetAWDLIncludedCount %u", m->AutoTargetAWDLIncludedCount);
    LogToFD(fd, "m->AutoTargetAWDLOnlyCount     %u", m->AutoTargetAWDLOnlyCount);
#endif

    LogToFD(fd, "                         ABS (hex)  ABS (dec)  REL (hex)  REL (dec)");
    LogToFD(fd, "m->timenow               %08X %11d", now, now);
    LogToFD(fd, "m->timenow_adjust        %08X %11d", m->timenow_adjust, m->timenow_adjust);
    LogTimerToFD(fd, "m->NextScheduledEvent   ", m->NextScheduledEvent);

#ifndef UNICAST_DISABLED
    LogTimerToFD(fd, "m->NextuDNSEvent        ", m->NextuDNSEvent);
    LogTimerToFD(fd, "m->NextSRVUpdate        ", m->NextSRVUpdate);
    LogTimerToFD(fd, "m->NextScheduledNATOp   ", m->NextScheduledNATOp);
    LogTimerToFD(fd, "m->retryGetAddr         ", m->retryGetAddr);
#endif

    LogTimerToFD(fd, "m->NextCacheCheck       ", m->NextCacheCheck);
    LogTimerToFD(fd, "m->NextScheduledSPS     ", m->NextScheduledSPS);
    LogTimerToFD(fd, "m->NextScheduledKA      ", m->NextScheduledKA);

#if MDNSRESPONDER_SUPPORTS(APPLE, BONJOUR_ON_DEMAND)
    LogTimerToFD(fd, "m->NextBonjourDisableTime ", m->NextBonjourDisableTime);
#endif

    LogTimerToFD(fd, "m->NextScheduledSPRetry ", m->NextScheduledSPRetry);
    LogTimerToFD(fd, "m->DelaySleep           ", m->DelaySleep);

    LogTimerToFD(fd, "m->NextScheduledQuery   ", m->NextScheduledQuery);
    LogTimerToFD(fd, "m->NextScheduledProbe   ", m->NextScheduledProbe);
    LogTimerToFD(fd, "m->NextScheduledResponse", m->NextScheduledResponse);

    LogTimerToFD(fd, "m->SuppressQueries      ", m->SuppressQueries);
    LogTimerToFD(fd, "m->SuppressResponses    ", m->SuppressResponses);
    LogTimerToFD(fd, "m->SuppressProbes       ", m->SuppressProbes);
    LogTimerToFD(fd, "m->ProbeFailTime        ", m->ProbeFailTime);
    LogTimerToFD(fd, "m->DelaySleep           ", m->DelaySleep);
    LogTimerToFD(fd, "m->SleepLimit           ", m->SleepLimit);
    LogTimerToFD(fd, "m->NextScheduledStopTime ", m->NextScheduledStopTime);
}

#if MDNS_MALLOC_DEBUGGING
mDNSlocal void udsserver_validatelists(void *context)
{
    const request_state *req, *p;
	(void)context; // unused
    for (req = all_requests; req; req=req->next)
    {
        if (req->next == (request_state *)~0 || (req->sd < 0 && req->sd != -2))
            LogMemCorruption("UDS request list: %p is garbage (%d)", req, req->sd);

        if (req->primary == req)
            LogMemCorruption("UDS request list: req->primary should not point to self %p/%d", req, req->sd);

        if (req->primary && req->replies)
            LogMemCorruption("UDS request list: Subordinate request %p/%d/%p should not have replies (%p)",
                             req, req->sd, req->primary && req->replies);

        p = req->primary;
        if ((long)p & 3)
            LogMemCorruption("UDS request list: req %p primary %p is misaligned (%d)", req, p, req->sd);
        else if (p && (p->next == (request_state *)~0 || (p->sd < 0 && p->sd != -2)))
            LogMemCorruption("UDS request list: req %p primary %p is garbage (%d)", req, p, p->sd);

        reply_state *rep;
        for (rep = req->replies; rep; rep=rep->next)
            if (rep->next == (reply_state *)~0)
                LogMemCorruption("UDS req->replies: %p is garbage", rep);

        if (req->terminate == connection_termination)
        {
            registered_record_entry *r;
            for (r = req->u.reg_recs; r; r=r->next)
                if (r->next == (registered_record_entry *)~0)
                    LogMemCorruption("UDS req->u.reg_recs: %p is garbage", r);
        }
        else if (req->terminate == regservice_termination_callback)
        {
            service_instance *s;
            for (s = req->u.servicereg.instances; s; s=s->next)
                if (s->next == (service_instance *)~0)
                    LogMemCorruption("UDS req->u.servicereg.instances: %p is garbage", s);
        }
        else if (req->terminate == browse_termination_callback)
        {
            browser_t *b;
            for (b = req->u.browser.browsers; b; b=b->next)
                if (b->next == (browser_t *)~0)
                    LogMemCorruption("UDS req->u.browser.browsers: %p is garbage", b);
        }
    }

    DNameListElem *d;
    for (d = SCPrefBrowseDomains; d; d=d->next)
        if (d->next == (DNameListElem *)~0 || d->name.c[0] > 63)
            LogMemCorruption("SCPrefBrowseDomains: %p is garbage (%d)", d, d->name.c[0]);

    ARListElem *b;
    for (b = LocalDomainEnumRecords; b; b=b->next)
        if (b->next == (ARListElem *)~0 || b->ar.resrec.name->c[0] > 63)
            LogMemCorruption("LocalDomainEnumRecords: %p is garbage (%d)", b, b->ar.resrec.name->c[0]);

    for (d = AutoBrowseDomains; d; d=d->next)
        if (d->next == (DNameListElem *)~0 || d->name.c[0] > 63)
            LogMemCorruption("AutoBrowseDomains: %p is garbage (%d)", d, d->name.c[0]);

    for (d = AutoRegistrationDomains; d; d=d->next)
        if (d->next == (DNameListElem *)~0 || d->name.c[0] > 63)
            LogMemCorruption("AutoRegistrationDomains: %p is garbage (%d)", d, d->name.c[0]);
}
#endif // MDNS_MALLOC_DEBUGGING

mDNSlocal transfer_state send_msg(request_state *const req)
{
    reply_state *const rep = req->replies;      // Send the first waiting reply
    ssize_t nwritten;
    const mDNSu32 len = rep->totallen - rep->nwritten;

    ConvertHeaderBytes(rep->mhdr);
    nwritten = send(req->sd, (char *)&rep->mhdr + rep->nwritten, len, 0);
    ConvertHeaderBytes(rep->mhdr);

    if (nwritten < 0)
    {
        if (dnssd_errno == dnssd_EINTR || dnssd_errno == dnssd_EWOULDBLOCK) nwritten = 0;
        else
        {
#if !defined(PLATFORM_NO_EPIPE)
            if (dnssd_errno == EPIPE)
                return(req->ts = t_terminated);
            else
#endif
            {
                LogMsg("send_msg ERROR: failed to write %u of %d bytes to fd %d errno %d (%s)",
                       len, rep->totallen, req->sd, dnssd_errno, dnssd_strerror(dnssd_errno));
                return(t_error);
            }
        }
    }
    rep->nwritten += (mDNSu32)nwritten;
    return (rep->nwritten == rep->totallen) ? t_complete : t_morecoming;
}

mDNSexport mDNSs32 udsserver_idle(mDNSs32 nextevent)
{
    mDNSs32 now = mDNS_TimeNow(&mDNSStorage);
    request_state **req = &all_requests;

    while (*req)
    {
        request_state *r = *req;

        if (r->terminate == resolve_termination_callback)
            if (r->u.resolve.ReportTime && now - r->u.resolve.ReportTime >= 0)
            {
                r->u.resolve.ReportTime = 0;
                // if client received results and resolve still active
                if (r->u.resolve.txt && r->u.resolve.srv)
                    LogMsgNoIdent("Client application PID[%d](%s) has received results for DNSServiceResolve(%##s) yet remains active over two minutes.", r->process_id, r->pid_name, r->u.resolve.qsrv.qname.c);
            }

        // Note: Only primary req's have reply lists, not subordinate req's.
        while (r->replies)      // Send queued replies
        {
            transfer_state result;
            if (r->replies->next)
                r->replies->rhdr->flags |= dnssd_htonl(kDNSServiceFlagsMoreComing);
            result = send_msg(r);   // Returns t_morecoming if buffer full because client is not reading
            if (result == t_complete)
            {
                reply_state *fptr = r->replies;
                r->replies = r->replies->next;
                freeL("reply_state/udsserver_idle", fptr);
                r->time_blocked = 0; // reset failure counter after successful send
                r->unresponsiveness_reports = 0;
                continue;
            }
            else if (result == t_terminated)
            {
                LogInfo("%3d: Could not write data to client PID[%d](%s) because connection is terminated by the client", r->sd, r->process_id, r->pid_name);
                abort_request(r);
            }
            else if (result == t_error)
            {
                LogMsg("%3d: Could not write data to client PID[%d](%s) because of error - aborting connection", r->sd, r->process_id, r->pid_name);
                LogClientInfo(r);
                abort_request(r);
            }
            break;
        }

        if (r->replies)     // If we failed to send everything, check our time_blocked timer
        {
            if (nextevent - now > mDNSPlatformOneSecond)
                nextevent = now + mDNSPlatformOneSecond;

            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
               "[R%u] Could not send all replies. Will try again in %d ticks.", r->request_id, nextevent - now);
            if (mDNSStorage.SleepState != SleepState_Awake)
                r->time_blocked = 0;
            else if (!r->time_blocked)
                r->time_blocked = NonZeroTime(now);
            else if (now - r->time_blocked >= 10 * mDNSPlatformOneSecond * (r->unresponsiveness_reports+1))
            {
                int num = 0;
                struct reply_state *x = r->replies;
                while (x)
                {
                    num++;
                    x=x->next;
                }
                LogMsg("%3d: Could not write data to client PID[%d](%s) after %ld seconds, %d repl%s waiting",
                       r->sd, r->process_id, r->pid_name, (now - r->time_blocked) / mDNSPlatformOneSecond, num, num == 1 ? "y" : "ies");
                if (++r->unresponsiveness_reports >= 60)
                {
                    LogMsg("%3d: Client PID[%d](%s) unresponsive; aborting connection", r->sd, r->process_id, r->pid_name);
                    LogClientInfo(r);
                    abort_request(r);
                }
            }
        }

        if (!dnssd_SocketValid(r->sd)) // If this request is finished, unlink it from the list and free the memory
        {
            // Since we're already doing a list traversal, we unlink the request directly instead of using AbortUnlinkAndFree()
            *req = r->next;
            freeL("request_state/udsserver_idle", r);
        }
        else
            req = &r->next;
    }
    return nextevent;
}

struct CompileTimeAssertionChecks_uds_daemon
{
    // Check our structures are reasonable sizes. Including overly-large buffers, or embedding
    // other overly-large structures instead of having a pointer to them, can inadvertently
    // cause structure sizes (and therefore memory usage) to balloon unreasonably.
    char sizecheck_request_state          [(sizeof(request_state)           <= 3888) ? 1 : -1];
    char sizecheck_registered_record_entry[(sizeof(registered_record_entry) <=   60) ? 1 : -1];
    char sizecheck_service_instance       [(sizeof(service_instance)        <= 6552) ? 1 : -1];
    char sizecheck_browser_t              [(sizeof(browser_t)               <= 1480) ? 1 : -1];
    char sizecheck_reply_hdr              [(sizeof(reply_hdr)               <=   12) ? 1 : -1];
    char sizecheck_reply_state            [(sizeof(reply_state)             <=   64) ? 1 : -1];
};

#ifdef UNIT_TEST
#include "../unittests/uds_daemon_ut.c"
#endif  //  UNIT_TEST
