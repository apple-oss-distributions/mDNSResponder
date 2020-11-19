/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#include "QuerierSupport.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "DebugServices.h"
#include "dns_sd_internal.h"
#include "mDNSMacOSX.h"
#include "mdns_xpc.h"
#include "uDNS.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
#include "Metrics.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec_v2.h"
#endif

#include <libproc.h>
#include <mach/mach_time.h>
#include "mdns_helpers.h"

int PQWorkaroundThreshold = 0;

extern mDNS mDNSStorage;

mDNSlocal void _Querier_LogDNSServices(const mdns_dns_service_manager_t manager)
{
    __block mDNSu32 count = 0;
    const mDNSu32 total = (mDNSu32)mdns_dns_service_manager_get_count(manager);
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Updated DNS services (%u)", total);
    mdns_dns_service_manager_iterate(manager,
    ^ bool (const mdns_dns_service_t service)
    {
        count++;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "DNS service (%u/%u) -- %@", count, total, service);
        return false;
    });
}

mDNSexport mdns_dns_service_manager_t Querier_GetDNSServiceManager(void)
{
    mDNS *const m = &mDNSStorage;
    static mdns_dns_service_manager_t sDNSServiceManager = NULL;
    if (sDNSServiceManager)
    {
        return sDNSServiceManager;
    }
    const mdns_dns_service_manager_t manager = mdns_dns_service_manager_create(dispatch_get_main_queue(), NULL);
    if (!manager)
    {
        return NULL;
    }
    mdns_dns_service_manager_set_report_symptoms(manager, true);
    mdns_dns_service_manager_enable_problematic_qtype_workaround(manager, PQWorkaroundThreshold);
    mdns_dns_service_manager_set_event_handler(manager,
    ^(mdns_event_t event, __unused OSStatus error)
    {
        KQueueLock();
        switch (event)
        {
            case mdns_event_error:
                mdns_dns_service_manager_invalidate(manager);
                if (sDNSServiceManager == manager)
                {
                    mdns_forget(&sDNSServiceManager);
                }
                break;

            case mdns_event_update:
                mdns_dns_service_manager_apply_pending_updates(manager);
                mDNS_Lock(m);
                Querier_ProcessDNSServiceChanges();
                _Querier_LogDNSServices(manager);
                mDNS_Unlock(m);
                break;

            case mdns_event_invalidated:
                mdns_release(manager);
                break;

            default:
                break;
        }
        KQueueUnlock("DNS Service Manager event handler");
    });
    sDNSServiceManager = manager;
    mdns_retain(sDNSServiceManager);
    mdns_dns_service_manager_activate(sDNSServiceManager);
    return sDNSServiceManager;
}

mDNSlocal mdns_dns_service_t _Querier_GetDNSService(const DNSQuestion *q)
{
    mdns_dns_service_t service;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (!manager)
    {
        return NULL;
    }
    if (!uuid_is_null(q->ResolverUUID))
    {
        service = mdns_dns_service_manager_get_uuid_scoped_service(manager, q->ResolverUUID);
    }
    else if (q->InterfaceID)
    {
        const uint32_t ifIndex = (uint32_t)((uintptr_t)q->InterfaceID);
        service = mdns_dns_service_manager_get_interface_scoped_service(manager, q->qname.c, ifIndex);
    }
    else if (q->ServiceID >= 0)
    {
        service = mdns_dns_service_manager_get_service_scoped_service(manager, q->qname.c, (uint32_t)q->ServiceID);
    }
    else
    {
        // Check for a matching discovered resolver for unscoped queries
        uuid_t discoveredResolverUUID = {};
        if (mdns_dns_service_manager_fillout_discovered_service_for_name(manager, q->qname.c, discoveredResolverUUID))
        {
            service = mdns_dns_service_manager_get_uuid_scoped_service(manager, discoveredResolverUUID);
        }
        else
        {
            service = mdns_dns_service_manager_get_unscoped_service(manager, q->qname.c);
        }
    }
    if (service && !mdns_dns_service_interface_is_vpn(service))
    {
        // Check for encryption, and if the service isn't encrypted, fallback or fail
        const mDNSBool lacksRequiredEncryption = q->RequireEncryption && !mdns_dns_service_is_encrypted(service);
        if (lacksRequiredEncryption || mdns_dns_service_has_connection_problems(service))
        {
            if (lacksRequiredEncryption)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
                    "[R%u->Q%u] DNS service %llu lacks required encryption",
                     q->request_id, mDNSVal16(q->TargetQID), mdns_dns_service_get_id(service));
                service = NULL;
            }
 
            // Check for a fallback service
            if (q->CustomID != 0)
            {
                service = mdns_dns_service_manager_get_custom_service(manager, q->CustomID);
            }
        }
    }
    return service;
}

mDNSlocal pid_t _Querier_GetMyPID(void)
{
    static dispatch_once_t sOnce = 0;
    static pid_t sPID = 0;
    dispatch_once(&sOnce,
    ^{
        sPID = getpid();
    });
    return sPID;
}

mDNSlocal const mDNSu8 *_Querier_GetMyUUID(void)
{
    static dispatch_once_t sOnce = 0;
    static mDNSu8 sUUID[16];
    dispatch_once(&sOnce,
    ^{
        uuid_clear(sUUID);
        struct proc_uniqidentifierinfo info;
        const int n = proc_pidinfo(_Querier_GetMyPID(), PROC_PIDUNIQIDENTIFIERINFO, 1, &info, sizeof(info));
        if (n == (int)sizeof(info))
        {
            uuid_copy(sUUID, info.p_uuid);
        }
    });
    return sUUID;
}

mDNSlocal mDNSBool _Querier_QuestionBelongsToSelf(const DNSQuestion *q)
{
    if (q->pid != 0)
    {
        return ((q->pid == _Querier_GetMyPID()) ? mDNStrue : mDNSfalse);
    }
    else
    {
        return ((uuid_compare(q->uuid, _Querier_GetMyUUID()) == 0) ? mDNStrue : mDNSfalse);
    }
}

mDNSlocal mDNSBool _Querier_DNSServiceIsUnscopedAndLacksPrivacy(const mdns_dns_service_t service)
{
    if ((mdns_dns_service_get_scope(service) == mdns_dns_service_scope_none) &&
        !mdns_dns_service_is_encrypted(service) && !mdns_dns_service_interface_is_vpn(service))
    {
        return mDNStrue;
    }
    else
    {
        return mDNSfalse;
    }
}

#define kQuerierLogFullDNSServicePeriodSecs 30

mDNSlocal mDNSBool _Querier_ShouldLogFullDNSService(const mdns_dns_service_t service)
{
    uint64_t *lastFullLogTicks = (uint64_t *)mdns_dns_service_get_context(service);
    if (lastFullLogTicks)
    {
        const uint64_t nowTicks = mach_continuous_time();
        const uint64_t diffTicks = nowTicks - *lastFullLogTicks;
        if ((diffTicks / mdns_mach_ticks_per_second()) < kQuerierLogFullDNSServicePeriodSecs)
        {
            return mDNSfalse;
        }
        *lastFullLogTicks = nowTicks;
    }
    else
    {
        lastFullLogTicks = (uint64_t *)malloc(sizeof(*lastFullLogTicks));
        if (lastFullLogTicks)
        {
            *lastFullLogTicks = mach_continuous_time();
            mdns_dns_service_set_context(service, lastFullLogTicks);
            mdns_dns_service_set_context_finalizer(service, free);
        }
    }
    return mDNStrue;
}

mDNSexport void Querier_SetDNSServiceForQuestion(DNSQuestion *q)
{
    // Thus far, UUID-scoped DNS services may be specified without any server IP addresses, just a hostname. In such a
    // case, the underlying nw_connection will need to resolve the DNS service's hostname. To avoid potential dependency
    // cycles because of mDNSResponder issuing GetAddrInfo requests to itself, we simply prevent DNSQuestions with
    // mDNSResponder's PID or Mach-O UUID from using UUID-scoped DNS services.
    if (!uuid_is_null(q->ResolverUUID) && _Querier_QuestionBelongsToSelf(q))
    {
        uuid_clear(q->ResolverUUID);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
            "[R%u->Q%u] Cleared resolver UUID for mDNSResponder's own question: " PRI_DM_NAME " (" PUB_S ")",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
    }
    mdns_forget(&q->dnsservice);
    mDNSBool retryPathEval = mDNSfalse;
    mdns_dns_service_t service = _Querier_GetDNSService(q);
    if (service)
    {
        // If path evaluation for the original QNAME was done by the client, but a CNAME restart has lead us to use a
        // DNS service that isn't identical to the previous DNS service, and the DNS service is unscoped and lacks
        // privacy, then retry path evaluation. A path evaluation with the new QNAME may result in using a DNS service
        // that offers privacy.
        if ((q->flags & kDNSServiceFlagsPathEvaluationDone) &&
            (q->lastDNSServiceID != 0) && (mdns_dns_service_get_id(service) != q->lastDNSServiceID) &&
            _Querier_DNSServiceIsUnscopedAndLacksPrivacy(service))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "[R%u->Q%u] Retrying path evaluation for " PRI_DM_NAME " (" PUB_S ") to avoid non-private DNS service",
                q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
            retryPathEval = mDNStrue;
        }
    }
    else if (!uuid_is_null(q->ResolverUUID))
    {
        // If the ResolverUUID is not null, but we didn't get a DNS service, then the ResolverUUID may be stale, i.e.,
        // the resolver configuration with that UUID may have been deleted, so retry path evaluation.
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
            "[R%u->Q%u] Retrying path evaluation for " PRI_DM_NAME " (" PUB_S ") because ResolverUUID may be stale",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
        retryPathEval = mDNStrue;
    }
    if (retryPathEval)
    {
        mDNSPlatformGetDNSRoutePolicy(q);
        service = _Querier_GetDNSService(q);
    }
    q->dnsservice = service;
    mdns_retain_null_safe(q->dnsservice);
    if (!q->dnsservice || _Querier_ShouldLogFullDNSService(q->dnsservice))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
            "[R%u->Q%u] Question for " PRI_DM_NAME " (" PUB_S ") assigned DNS service -- %@",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->dnsservice);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
            "[R%u->Q%u] Question for " PRI_DM_NAME " (" PUB_S ") assigned DNS service %llu",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
            mdns_dns_service_get_id(q->dnsservice));
    }
}

mDNSexport void Querier_RegisterPathResolver(const uuid_t resolverUUID)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_register_path_resolver(manager, resolverUUID);
    }
}

mDNSexport mdns_dns_service_id_t Querier_RegisterCustomDNSService(const xpc_object_t resolverConfigDict)
{
    mdns_dns_service_id_t ident = 0;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        ident = mdns_dns_service_manager_register_custom_service(manager, resolverConfigDict);
    }
    return ident;
}

mDNSexport mdns_dns_service_id_t Querier_RegisterCustomDNSServiceWithPListData(const uint8_t *dataPtr, size_t dataLen)
{
    mdns_dns_service_id_t ident = 0;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        xpc_object_t resolverConfigDict = mdns_xpc_create_dictionary_from_plist_data(dataPtr, dataLen, NULL);
        if (resolverConfigDict)
        {
            ident = mdns_dns_service_manager_register_custom_service(manager, resolverConfigDict);
            xpc_release(resolverConfigDict);
        }
    }
    return ident;
}

mDNSexport void Querier_DeregisterCustomDNSService(const mdns_dns_service_id_t ident)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_deregister_custom_service(manager, ident);
    }
}

mDNSexport void Querier_RegisterDoHURI(const char *doh_uri, const char *domain)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_register_doh_uri(manager, doh_uri, domain);
    }
}

mDNSexport void Querier_ApplyDNSConfig(const dns_config_t *config)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_apply_dns_config(manager, config);
        _Querier_LogDNSServices(manager);
    }
}

#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
mDNSlocal void _Querier_UpdateQuestionMetrics(DNSQuestion *const q)
{
    if (q->querier && (mdns_querier_get_resolver_type(q->querier) == mdns_resolver_type_normal))
    {
        q->metrics.querySendCount += mdns_querier_get_send_count(q->querier);
        if (q->metrics.dnsOverTCPState == DNSOverTCP_None)
        {
            switch (mdns_querier_get_over_tcp_reason(q->querier))
            {
                case mdns_query_over_tcp_reason_truncation:
                    q->metrics.dnsOverTCPState = DNSOverTCP_Truncated;
                    break;

                case mdns_query_over_tcp_reason_got_suspicious_reply:
                    q->metrics.dnsOverTCPState = DNSOverTCP_Suspicious;
                    break;

                case mdns_query_over_tcp_reason_in_suspicious_mode:
                    q->metrics.dnsOverTCPState = DNSOverTCP_SuspiciousDefense;
                    break;

                default:
                    break;
            }
        }
    }
}

mDNSlocal void _Querier_UpdateDNSMessageSizeMetrics(const mdns_querier_t querier)
{
    if (mdns_querier_get_resolver_type(querier) == mdns_resolver_type_normal)
    {
        if (mdns_querier_get_send_count(querier) > 0)
        {
            const mDNSu32 len = mdns_querier_get_query_length(querier);
            if (len > 0)
            {
                MetricsUpdateDNSQuerySize(len);
            }
        }
        if ((mdns_querier_get_result_type(querier) == mdns_querier_result_type_response) &&
            !mdns_querier_response_is_fabricated(querier))
        {
            const mDNSu32 len = mdns_querier_get_response_length(querier);
            if (len > 0)
            {
                MetricsUpdateDNSResponseSize(len);
            }
        }
    }
}
#endif

mDNSlocal mdns_set_t _Querier_GetOrphanedQuerierSet(void)
{
    static mdns_set_t sOrphanedQuerierSet = NULL;
    if (!sOrphanedQuerierSet)
    {
        sOrphanedQuerierSet = mdns_set_create();
    }
    return sOrphanedQuerierSet;
}

mDNSlocal void _Querier_HandleQuerierResponse(const mdns_querier_t querier, const mdns_dns_service_t dnsservice)
{
    KQueueLock();
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
        "[Q%u] Handling concluded querier: %@", mdns_querier_get_user_id(querier), querier);
#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
    _Querier_UpdateDNSMessageSizeMetrics(querier);
#endif
    const mdns_querier_result_type_t resultType = mdns_querier_get_result_type(querier);
    if (resultType == mdns_querier_result_type_response)
    {
        mDNS *const m = &mDNSStorage;
        if (!mdns_dns_service_is_defunct(dnsservice))
        {
            size_t copyLen = mdns_querier_get_response_length(querier);
            if (copyLen > sizeof(m->imsg.m))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
                    "[Q%u] Large %lu-byte response will be truncated to fit mDNSCore's %lu-byte message buffer",
                    mdns_querier_get_user_id(querier), (unsigned long)copyLen, (unsigned long)sizeof(m->imsg.m));
                copyLen = sizeof(m->imsg.m);
            }
            memcpy(&m->imsg.m, mdns_querier_get_response_ptr(querier), copyLen);
            const mDNSu8 *const end = ((mDNSu8 *)&m->imsg.m) + copyLen;
            mDNSCoreReceiveForQuerier(m, &m->imsg.m, end, querier, dnsservice);
        }
    }
    const mdns_set_t set = _Querier_GetOrphanedQuerierSet();
    if (set)
    {
        mdns_set_remove(set, (uintptr_t)dnsservice, querier);
    }
    DNSQuestion *const q = Querier_GetDNSQuestion(querier);
    if (q)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
        _Querier_UpdateQuestionMetrics(q);
#endif
        mdns_forget(&q->querier);
        // If the querier timed out, then the DNSQuestion was using an orphaned querier.
        // Querier_HandleUnicastQuestion() will attempt to give it a new querier.
        if (resultType == mdns_querier_result_type_timeout)
        {
            Querier_HandleUnicastQuestion(q);
        }
        else if (resultType == mdns_querier_result_type_error)
        {
            // The querier encountered a fatal error, which should be rare. There's nothing we can do but try again.
            // This usually happens if there's resource exhaustion, so be conservative and wait five seconds before
            // trying again.
            mDNS *const m = &mDNSStorage;
            q->ThisQInterval = 5 * mDNSPlatformOneSecond;
            q->LastQTime = m->timenow;
            SetNextQueryTime(m, q);
        }
    }
    KQueueUnlock("_Querier_HandleQuerierResponse");
}

mDNSexport void Querier_HandleUnicastQuestion(DNSQuestion *q)
{
    mDNS *const m = &mDNSStorage;
    mdns_querier_t querier = NULL;
    if (!q->dnsservice || q->querier) goto exit;

    const mdns_set_t set = _Querier_GetOrphanedQuerierSet();
    if (set)
    {
        __block mdns_querier_t orphan = NULL;
        mdns_set_iterate(set, (uintptr_t)q->dnsservice,
        ^ bool (mdns_object_t _Nonnull object)
        {
            const mdns_querier_t candidate = (mdns_querier_t)object;
            if (mdns_querier_match(candidate, q->qname.c, q->qtype, q->qclass))
            {
                orphan = candidate;
                return true;
            }
            else
            {
                return false;
            }
        });
        if (orphan)
        {
            q->querier = orphan;
            mdns_retain(q->querier);
            mdns_set_remove(set, (uintptr_t)q->dnsservice, q->querier);
            mdns_querier_set_time_limit_ms(q->querier, 0);
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
                "[Q%u->Q%u] Adopted orphaned querier", mDNSVal16(q->TargetQID), mdns_querier_get_user_id(q->querier));
        }
    }
    if (!q->querier)
    {
        querier = mdns_dns_service_create_querier(q->dnsservice, NULL);
        require_quiet(querier, exit);

        const OSStatus err = mdns_querier_set_query(querier, q->qname.c, q->qtype, q->qclass);
        require_noerr_quiet(err, exit);

        q->querier = querier;
        mdns_retain(q->querier);

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
        if (q->DNSSECStatus.enable_dnssec)
        {
            mdns_querier_set_dnssec_ok(querier, true);
            mdns_querier_set_checking_disabled(querier, true);
        }
#endif

        if (q->pid != 0)
        {
            mdns_querier_set_delegator_pid(q->querier, q->pid);
        }
        else
        {
            mdns_querier_set_delegator_uuid(q->querier, q->uuid);
        }
        mdns_querier_set_queue(querier, dispatch_get_main_queue());
        mdns_retain(querier);
        const mdns_dns_service_t dnsservice = q->dnsservice;
        mdns_retain(dnsservice);
        mdns_querier_set_result_handler(querier,
        ^{
            _Querier_HandleQuerierResponse(querier, dnsservice);
            mdns_release(querier);
            mdns_release(dnsservice);
        });
        mdns_querier_set_log_label(querier, "Q%u", mDNSVal16(q->TargetQID));
        mdns_querier_set_user_id(querier, mDNSVal16(q->TargetQID));
        mdns_querier_activate(querier);
    }
#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
    if (mdns_querier_get_resolver_type(q->querier) == mdns_resolver_type_normal)
    {
        if (q->metrics.answered)
        {
            uDNSMetricsClear(&q->metrics);
        }
        if (q->metrics.firstQueryTime == 0)
        {
            q->metrics.firstQueryTime = NonZeroTime(m->timenow);
        }
    }
    else
    {
        q->metrics.firstQueryTime = 0;
    }
#endif

exit:
    q->ThisQInterval = q->querier ? MaxQuestionInterval : mDNSPlatformOneSecond;
    q->LastQTime = m->timenow;
    SetNextQueryTime(m, q);
    mdns_release_null_safe(querier);
}

mDNSexport void Querier_ProcessDNSServiceChanges(void)
{
    mDNS *const m = &mDNSStorage;
    DNSQuestion *q;
    DNSQuestion *restartList = NULL;
    DNSQuestion **ptr = &restartList;
    mDNSu32 slot;
    CacheGroup *cg;
    CacheRecord *cr;
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    DNSPushNotificationServer **psp;
#endif

    m->RestartQuestion = m->Questions;
    while ((q = m->RestartQuestion) != mDNSNULL)
    {
        if (mDNSOpaque16IsZero(q->TargetQID))
        {
            m->RestartQuestion = q->next;
            continue;
        }
        mdns_dns_service_t newService = _Querier_GetDNSService(q);
        mDNSBool forcePathEval = mDNSfalse;
        if (q->dnsservice != newService)
        {
            // If the DNS service would change, but there is no new DNS service or it's unscoped and lacks privacy,
            // force a path evaluation when the DNSQuestion restarts to determine if there's a DNS service that offers
            // privacy that should be used. This DNSQuestion might have been unscoped so that it can use a VPN DNS
            // service, but that service may be defunct now.
            if (!newService || _Querier_DNSServiceIsUnscopedAndLacksPrivacy(newService))
            {
                forcePathEval = mDNStrue;
            }
        }
        else
        {
            // If the DNS service wouldn't change and the DNS service is UUID-scoped, perform a path evaluation now to
            // see if a DNS service change occurs. This might happen if a DNSQuestion was UUID-scoped to a DoH or DoT
            // service, but there's a new VPN DNS service that handles the DNSQuestion's QNAME.
            if (q->dnsservice && (mdns_dns_service_get_scope(q->dnsservice) == mdns_dns_service_scope_uuid))
            {
                mDNSPlatformGetDNSRoutePolicy(q);
                newService = _Querier_GetDNSService(q);
            }
        }
        mDNSBool restart = mDNSfalse;
        if (q->dnsservice != newService)
        {
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
            // If this question had a DNS Push server associated with it, substitute the new server for the
            // old one.   If there is no new server, then we'll clean up the push server later.
            if (!q->DuplicateOf && q->dnsPushServer)
            {
                if (q->dnsPushServer->dnsservice == q->dnsservice)
                {
                    mdns_replace(&q->dnsPushServer->dnsservice, newService);
                }
                // If it is null, do the accounting and drop the push server.
                if (!q->dnsPushServer->dnsservice)
                {
                    DNSPushReconcileConnection(m, q);
                }
            }
#endif
            restart = mDNStrue;
        }
        else
        {
            mDNSBool newSuppressed = ShouldSuppressUnicastQuery(q, newService);
            if (!q->Suppressed != !newSuppressed) restart = mDNStrue;
        }
        if (restart)
        {
            if (!q->Suppressed)
            {
                CacheRecordRmvEventsForQuestion(m, q);
                if (m->RestartQuestion == q) LocalRecordRmvEventsForQuestion(m, q);
            }
            if (m->RestartQuestion == q)
            {
                mDNS_StopQuery_internal(m, q);
                q->ForcePathEval = forcePathEval;
                q->next = mDNSNULL;
                *ptr = q;
                ptr = &q->next;
            }
        }
        if (m->RestartQuestion == q) m->RestartQuestion = q->next;
    }
    while ((q = restartList) != mDNSNULL)
    {
        restartList = q->next;
        q->next = mDNSNULL;
        mDNS_StartQuery_internal(m, q);
    }
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    // The above code may have found some DNS Push servers that are no longer valid.   Now that we
    // are done running through the code, we need to drop our connections to those servers.
    // When we get here, any such servers should have zero questions associated with them.
    for (psp = &m->DNSPushServers; *psp != mDNSNULL; )
    {
        DNSPushNotificationServer *server = *psp;

        // It's possible that a push server whose DNS server has been deleted could be still connected but
        // not referenced by any questions.  In this case, we just delete the push server rather than trying
        // to figure out with which DNS server (if any) to associate it.
        if (server->dnsservice && mdns_dns_service_is_defunct(server->dnsservice))
        {
            mdns_forget(&server->dnsservice);
        }
        if (!server->dnsservice)
        {
            // This would be a programming error, so should never happen.
            if (server->numberOfQuestions != 0)
            {
                LogInfo("uDNS_SetupDNSConfig: deleting push server %##s that has questions.", &server->serverName);
            }
            DNSPushServerDrop(server);
            *psp = server->next;
            mDNSPlatformMemFree(server);
        }
        else
        {
            psp = &(*psp)->next;
        }
    }
#endif
    FORALL_CACHERECORDS(slot, cg, cr)
    {
        if (cr->resrec.InterfaceID) continue;
        if (!cr->resrec.dnsservice || mdns_dns_service_is_defunct(cr->resrec.dnsservice))
        {
            mdns_forget(&cr->resrec.dnsservice);
            mDNS_PurgeCacheResourceRecord(m, cr);
        }
    }
}

mDNSexport DNSQuestion *Querier_GetDNSQuestion(const mdns_querier_t querier)
{
    DNSQuestion *q;
    for (q = mDNSStorage.Questions; q; q = q->next)
    {
        if (q->querier == querier)
        {
            return q;
        }
    }
    return mDNSNULL;
}

mDNSexport mDNSBool Querier_ResourceRecordIsAnswer(const ResourceRecord * const rr, const mdns_querier_t querier)
{
    const mDNSu16 qtype = mdns_querier_get_qtype(querier);
    const mDNSu8 *const qname = mdns_querier_get_qname(querier);
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    const mDNSBool enableDNSSEC = mdns_querier_get_dnssec_ok(querier);
#endif


    if ((RRTypeAnswersQuestionType(rr, qtype)
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
         || (enableDNSSEC && record_type_answers_dnssec_question(rr, qtype))
#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
         )
        && (rr->rrclass == mdns_querier_get_qclass(querier)) &&
        qname && SameDomainName(rr->name, (const domainname *)qname))
    {
        return mDNStrue;
    }
    else
    {
        return mDNSfalse;
    }
}

mDNSexport mDNSBool Querier_SameNameCacheRecordIsAnswer(const CacheRecord *const cr, const mdns_querier_t querier)
{
    const ResourceRecord *const rr = &cr->resrec;
    const mDNSu16 qtype = mdns_querier_get_qtype(querier);
    if (RRTypeAnswersQuestionType(rr, qtype) && (rr->rrclass == mdns_querier_get_qclass(querier)))
    {
        return mDNStrue;
    }
    else
    {
        return mDNSfalse;
    }
}

#define kOrphanedQuerierTimeLimitSecs       5
#define kOrphanedQuerierSubsetCountLimit    10

mDNSexport void Querier_HandleStoppedDNSQuestion(DNSQuestion *q)
{
    if (q->querier && !mdns_querier_has_concluded(q->querier) &&
        q->dnsservice && !mdns_dns_service_is_defunct(q->dnsservice))
    {
        const mdns_set_t set = _Querier_GetOrphanedQuerierSet();
        const uintptr_t subsetID = (uintptr_t)q->dnsservice;
        if (set && (mdns_set_get_count(set, subsetID) < kOrphanedQuerierSubsetCountLimit))
        {
            const OSStatus err = mdns_set_add(set, subsetID, q->querier);
            if (!err)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
                    "[Q%u] Keeping orphaned querier for up to " StringifyExpansion(kOrphanedQuerierTimeLimitSecs) " seconds",
                    mdns_querier_get_user_id(q->querier));
                mdns_querier_set_time_limit_ms(q->querier, kOrphanedQuerierTimeLimitSecs * 1000);
                mdns_forget(&q->querier);
            }
        }
    }
    mdns_querier_forget(&q->querier);
    mdns_forget(&q->dnsservice);
}

mDNSexport void Querier_PrepareQuestionForCNAMERestart(DNSQuestion *const q)
{
    q->lastDNSServiceID = q->dnsservice ? mdns_dns_service_get_id(q->dnsservice) : MDNS_DNS_SERVICE_MAX_ID;
#if MDNSRESPONDER_SUPPORTS(APPLE, METRICS)
    _Querier_UpdateQuestionMetrics(q);
#endif
}

mDNSexport void Querier_PrepareQuestionForUnwindRestart(DNSQuestion *const q)
{
    q->lastDNSServiceID = 0;
    q->ForcePathEval    = mDNStrue;
}

mDNSexport void Querier_HandleSleep(void)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_handle_sleep(manager);
    }
}

mDNSexport void Querier_HandleWake(void)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_handle_wake(manager);
    }
}
#endif // MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
