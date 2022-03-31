/*
 * Copyright (c) 2019-2022 Apple Inc. All rights reserved.
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
#include "dns_sd_internal.h"
#include "mDNSMacOSX.h"
#include "uDNS.h"

#include <CoreUtils/CommonServices.h>

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
#include "dnssd_analytics.h"
#endif


#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
#include "discover_resolver.h"
#endif

#include "mdns_strict.h"

#include <mach/mach_time.h>
#include <mdns/system.h>
#include <mdns/ticks.h>
#include <mdns/xpc.h>

int PQWorkaroundThreshold = 0;

extern mDNS mDNSStorage;

mDNSlocal mDNSBool _Querier_QuestionBelongsToSelf(const DNSQuestion *q);

mDNSlocal void _Querier_LogDNSServices(const mdns_dns_service_manager_t manager)
{
    __block mDNSu32 count = 0;
    const mDNSu32 total = (mDNSu32)mdns_dns_service_manager_get_count(manager);
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Updated DNS services (%u)", total);
    mdns_dns_service_manager_enumerate(manager,
    ^ bool (const mdns_dns_service_t service)
    {
        count++;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "DNS service (%u/%u) -- %@", count, total, service);
        return true;
    });
}

mDNSlocal dispatch_queue_t _Querier_InternalQueue(void)
{
    static dispatch_once_t sOnce = 0;
    static dispatch_queue_t sQueue = NULL;

    dispatch_once(&sOnce,
    ^{
        sQueue = dispatch_queue_create("com.apple.mDNSResponder.querier-support-queue", DISPATCH_QUEUE_SERIAL);
    });
    return sQueue;
}

mDNSexport mdns_dns_service_manager_t Querier_GetDNSServiceManager(void)
{
    mDNS *const m = &mDNSStorage;
    static mdns_dns_service_manager_t sDNSServiceManager = NULL;
    if (sDNSServiceManager)
    {
        return sDNSServiceManager;
    }
    const mdns_dns_service_manager_t manager = mdns_dns_service_manager_create(_Querier_InternalQueue(), NULL);
    if (!manager)
    {
        return NULL;
    }
    mdns_dns_service_manager_set_report_symptoms(manager, true);
    mdns_dns_service_manager_ignore_odoh_connection_problems(manager, true);
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
        }
        KQueueUnlock("DNS Service Manager event handler");
    });
    sDNSServiceManager = manager;
    mdns_retain(sDNSServiceManager);
    mdns_dns_service_manager_activate(sDNSServiceManager);
    return sDNSServiceManager;
}

mDNSlocal mdns_dns_service_t _Querier_GetNativeDNSService(const mdns_dns_service_manager_t manager,
    const DNSQuestion * const q)
{
    mdns_dns_service_t service;
    if (q->InterfaceID)
    {
        const uint32_t ifIndex = (uint32_t)((uintptr_t)q->InterfaceID);
        service = mdns_dns_service_manager_get_interface_scoped_native_service(manager, q->qname.c, ifIndex);
    }
    else
    {
        service = mdns_dns_service_manager_get_unscoped_native_service(manager, q->qname.c);
    }
    return service;
}

mDNSlocal mdns_dns_service_t _Querier_GetNonNativeDNSService(const mdns_dns_service_manager_t manager,
    const DNSQuestion * const q, const mDNSBool excludeNonStandardServices)
{
    mdns_dns_service_t service;
    const uint32_t ifIndex = (uint32_t)((uintptr_t)q->InterfaceID);
    const mdns_dns_service_opts_t options = excludeNonStandardServices ? mdns_dns_service_opt_none :
        mdns_dns_service_opt_prefer_discovered;
    if (!excludeNonStandardServices && !uuid_is_null(q->ResolverUUID))
    {
        service = mdns_dns_service_manager_get_uuid_scoped_service(manager, q->ResolverUUID, ifIndex);
        if (service && (mdns_dns_service_get_class(service) == nw_resolver_class_oblivious) && !q->InterfaceID)
        {
            mdns_dns_service_t discovered_service = mdns_dns_service_manager_get_discovered_service(manager, q->qname.c);
            if (discovered_service && (mdns_dns_service_get_class(discovered_service) == nw_resolver_class_designated))
            {
                // Prefer discovered resolver for unscoped queries that would use oblivious resolvers,
                // even if they have a resolver UUID.
                service = discovered_service;
            }
			else
			{
				mdns_dns_service_t oblivious_service = mdns_dns_service_manager_get_discovered_oblivious_service(manager, service, q->qname.c);
				if (oblivious_service && (mdns_dns_service_get_class(oblivious_service) == nw_resolver_class_oblivious))
				{
					// Prefer discovered oblivious resolver
					service = oblivious_service;
				}
			}
        }
    }
    else if (q->InterfaceID)
    {
        service = mdns_dns_service_manager_get_interface_scoped_system_service_with_options(manager, q->qname.c, ifIndex,
            options);
    }
    else if (q->ServiceID >= 0)
    {
        service = mdns_dns_service_manager_get_service_scoped_system_service(manager, q->qname.c, (uint32_t)q->ServiceID);
    }
    else
    {
        service = mDNSNULL;
        if (!excludeNonStandardServices)
        {
            // Check for a matching discovered resolver for unscoped queries
            service = mdns_dns_service_manager_get_discovered_service(manager, q->qname.c);
        }
        if (!service)
        {
            service = mdns_dns_service_manager_get_unscoped_system_service_with_options(manager, q->qname.c, options);
        }
    }
    if (!excludeNonStandardServices && service && !mdns_dns_service_interface_is_vpn(service))
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

mDNSlocal mDNSBool _Querier_QuestionIsEligibleForNonNativeDNSService(const DNSQuestion *const q)
{
    mDNSBool eligible = mDNStrue;

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
    if (IsSubdomain(&q->qname, THREAD_DOMAIN_NAME))
    {
        // We do not want the query ends with "openthread.thread.home.arpa." to choose a non-native DNS service to go
        // outside of the home network.
        eligible = mDNSfalse;
    }
#endif

    return eligible;
}

mDNSlocal mdns_dns_service_t _Querier_GetDNSService(const DNSQuestion *q, const mDNSBool excludeNonStandardServices)
{
    mdns_dns_service_t service = mDNSNULL;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (!manager)
    {
        return NULL;
    }

    service = _Querier_GetNativeDNSService(manager, q);
    if (!service && _Querier_QuestionIsEligibleForNonNativeDNSService(q))
    {
        service = _Querier_GetNonNativeDNSService(manager, q, excludeNonStandardServices);
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
        mdns_system_pid_to_uuid(_Querier_GetMyPID(), sUUID);
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

#define kQuerierLogFullDNSServicePeriodSecs 60

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
        lastFullLogTicks = (uint64_t *)mdns_malloc(sizeof(*lastFullLogTicks));
        if (lastFullLogTicks)
        {
            *lastFullLogTicks = mach_continuous_time();
            mdns_dns_service_set_context(service, lastFullLogTicks);
            mdns_dns_service_set_context_finalizer(service, mdns_free_context_finalizer);
        }
    }
    return mDNStrue;
}

mDNSlocal mDNSBool _Querier_VPNDNSServiceExistsForQName(const domainname *const qname)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        const mdns_dns_service_t service = mdns_dns_service_manager_get_unscoped_system_service(manager, qname->c);
        if (service && mdns_dns_service_interface_is_vpn(service))
        {
            return mDNStrue;
        }
    }
    return mDNSfalse;
}

// So far, ODoH/DoH/DoT DNS services may be specified without any server IP addresses, just a hostname. In such a case,
// the underlying nw_connection will need to resolve the DNS service's hostname. To avoid potential dependency cycles
// because of mDNSResponder issuing GAI requests to itself, we simply prevent DNSQuestions with mDNSResponder's PID or
// Mach-O UUID from using ODoH/DoH/DoT services.
//
// Also, if a DNSQuestion's QNAME is in a special-use mDNS local domain, and is being sent via unicast DNS as a
// workaround for private internal networks that incorrectly use these domains for their network's DNS, then
// ODoH/DoH/DoT should not be used. It only makes sense to send the DNS queries to DNS servers belonging to the network,
// e.g., those specified via DHCP.
mDNSlocal mDNSBool _Querier_ExcludeNonStandardServices(const DNSQuestion *const q)
{
    return (_Querier_QuestionBelongsToSelf(q) || IsLocalDomain(&q->qname));
}

mDNSexport void Querier_SetDNSServiceForQuestion(DNSQuestion *q)
{
    const mDNSBool excludeNonStandardServices = _Querier_ExcludeNonStandardServices(q);
    if (!uuid_is_null(q->ResolverUUID) && excludeNonStandardServices)
    {
        uuid_clear(q->ResolverUUID);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
            "[R%u->Q%u] Cleared resolver UUID for mDNSResponder's own question: " PRI_DM_NAME " (" PUB_S ")",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
    }
    mdns_forget(&q->dnsservice);
    mdns_dns_service_t service = _Querier_GetDNSService(q, excludeNonStandardServices);
    if (!excludeNonStandardServices)
    {
        mDNSBool retryPathEval = mDNSfalse;
        const char *retryReason = "<unspecified>";
        if (service)
        {
            // Check whether path evaluation needs to be retried if path evaluation for the original QNAME was done by the
            // client, a CNAME traversal has taken place, the DNSQuestion is not interface-scoped, and the current DNS
            // service is not native.
            if ((q->flags & kDNSServiceFlagsPathEvaluationDone) && (q->lastDNSServiceID != MDNS_DNS_SERVICE_INVALID_ID) &&
                !q->InterfaceID && !mdns_dns_service_is_native(service))
            {
                // If the current DNS service isn't identical to the previous DNS service, and the DNS service is unscoped
                // and lacks privacy, then retry path evaluation. A path evaluation with the new QNAME may result in using
                // a DNS service that offers privacy.
                if ((mdns_dns_service_get_id(service) != q->lastDNSServiceID) &&
                    _Querier_DNSServiceIsUnscopedAndLacksPrivacy(service))
                {
                    retryReason = "avoid non-private DNS service";
                    retryPathEval = mDNStrue;
                }
                // If the DNSQuestion is UUID-scoped, but there exists a VPN DNS service for its QNAME, then retry path
                // evaluation in case the VPN DNS service should be used for the new QNAME.
                else if (!uuid_is_null(q->ResolverUUID) && _Querier_VPNDNSServiceExistsForQName(&q->qname))
                {
                    retryReason = "QNAME is in a VPN DNS service's domain";
                    retryPathEval = mDNStrue;
                }
            }
        }
        else if (!uuid_is_null(q->ResolverUUID))
        {
            // If the ResolverUUID is not null, but we didn't get a DNS service, then the ResolverUUID may be stale, i.e.,
            // the resolver configuration with that UUID may have been deleted, so retry path evaluation.
            retryReason = "ResolverUUID may be stale";
            retryPathEval = mDNStrue;
        }
        if (retryPathEval)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "[R%u->Q%u] Retrying path evaluation -- qname: " PRI_DM_NAME ", qtype: " PUB_S ", reason: " PUB_S,
                q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), retryReason);
            mDNSPlatformGetDNSRoutePolicy(q);
            service = _Querier_GetDNSService(q, excludeNonStandardServices);
        }
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
            xpc_forget(&resolverConfigDict);
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

mDNSexport mdns_dns_service_id_t Querier_RegisterNativeDNSService(const mdns_dns_service_definition_t dns_service_definition)
{
    mdns_dns_service_id_t ident = MDNS_DNS_SERVICE_INVALID_ID;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        OSStatus err = kNoErr;
        ident = mdns_dns_service_manager_register_native_service(manager, dns_service_definition, &err);
        if (err != kNoErr)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "Failed to register native DNS service - error: %d.", (int)err);
        }
    }
    return ident;
}

mDNSexport void Querier_DeregisterNativeDNSService(const mdns_dns_service_id_t ident)
{
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        mdns_dns_service_manager_deregister_native_service(manager, ident);
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

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
mDNSlocal void _Querier_UpdateQuestionMetrics(DNSQuestion *const q, const mdns_querier_t querier)
{
 	if (querier && (mdns_querier_get_resolver_type(querier) != mdns_resolver_type_null))
	{
		q->metrics.querySendCount += mdns_querier_get_send_count(querier);
	}
}

mDNSlocal void _Querier_UpdateDNSMessageSizeAnalytics(const mdns_querier_t querier)
{
	const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(querier);
	bool is_cellular = mdns_dns_service_interface_is_cellular(dnsservice);
	dns_transport_t	transport = dnssd_analytics_dns_transport_for_resolver_type(mdns_querier_get_resolver_type(querier));
	if (mdns_querier_get_send_count(querier) > 0)
	{
		const mDNSu32 len = mdns_querier_get_query_length(querier);
		if (len > 0)
		{
			dnssd_analytics_update_dns_query_size(is_cellular, transport, len);
		}
	}
	if ((mdns_querier_get_result_type(querier) == mdns_querier_result_type_response) &&
		!mdns_querier_response_is_fabricated(querier))
	{
		const mDNSu32 len = mdns_querier_get_response_length(querier);
		if (len > 0)
		{
			dnssd_analytics_update_dns_reply_size(is_cellular, transport, len);
		}
	}
}
#endif

#define kOrphanedQuerierMaxCount 10

mDNSlocal mdns_set_t _Querier_GetOrphanedQuerierSet(void)
{
    static mdns_set_t sOrphanedQuerierSet = NULL;
    if (!sOrphanedQuerierSet)
    {
        sOrphanedQuerierSet = mdns_set_create(kOrphanedQuerierMaxCount);
    }
    return sOrphanedQuerierSet;
}

mDNSlocal void _Querier_HandleQuerierResponse(const mdns_querier_t querier)
{
    KQueueLock();
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
        "[Q%u] Handling concluded querier: %@", mdns_querier_get_user_id(querier), querier);
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
    _Querier_UpdateDNSMessageSizeAnalytics(querier);
#endif
    mDNS *const m = &mDNSStorage;
    const mdns_querier_result_type_t resultType = mdns_querier_get_result_type(querier);
    if (resultType == mdns_querier_result_type_response)
    {
        const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(querier);
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
        mdns_set_remove(set, querier);
    }
    mDNSBool qIsNew = mDNSfalse;
    DNSQuestion *const q = Querier_GetDNSQuestion(querier, &qIsNew);
    if (q)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
        _Querier_UpdateQuestionMetrics(q, q->querier);
#endif
        mdns_forget(&q->querier);
        const mDNSBool needUpdatedQuerier = q->NeedUpdatedQuerier;
        q->NeedUpdatedQuerier = mDNSfalse;
        // If the DNSQuestion became suppressed, then it doesn't need a new querier.
        // If the DNSQuestion is now on the m->NewQuestions sub-list (due to a restart), then it will be handled by the
        // normal AnswerNewQuestion() code path, so don't start a new querier.
        if (!q->Suppressed && !qIsNew)
        {
            mDNSBool startNewQuerier = mDNSfalse;
            switch (resultType)
            {
                case mdns_querier_result_type_response:
                    // If the querier was for a previous QNAME, then start a new querier for the new QNAME.
                    startNewQuerier = needUpdatedQuerier;
                    break;

                case mdns_querier_result_type_timeout:
                    // If the querier timed out, then the DNSQuestion was using an orphaned querier.
                    // Querier_HandleUnicastQuestion() will attempt to give it a new querier.
                    startNewQuerier = mDNStrue;
                    break;

                case mdns_querier_result_type_error:
                    // The querier encountered a fatal error, which should be rare. There's nothing we can do but try again.
                    // This usually happens if there's resource exhaustion, so be conservative and wait five seconds before
                    // trying again.
                    mDNS_Lock(m);
                    q->ThisQInterval = 5 * mDNSPlatformOneSecond;
                    q->LastQTime = m->timenow;
                    SetNextQueryTime(m, q);
                    mDNS_Unlock(m);
                    break;

                case mdns_querier_result_type_null:
                case mdns_querier_result_type_invalidation:
                case mdns_querier_result_type_resolver_invalidation:
                    break;
            }
            if (startNewQuerier)
            {
                mDNS_Lock(m);
                Querier_HandleUnicastQuestion(q);
                mDNS_Unlock(m);
            }
        }
    }
    KQueueUnlock("_Querier_HandleQuerierResponse");
}

mDNSexport void Querier_HandleUnicastQuestion(DNSQuestion *q)
{
    mDNS *const m = &mDNSStorage;
    mdns_querier_t querier = NULL;
    if (q->querier || !q->dnsservice)
    {
        if (q->querier)
        {
            q->NeedUpdatedQuerier = !mdns_querier_match(q->querier, q->qname.c, q->qtype, q->qclass);
        }
        goto exit;
    }
    const mdns_set_t set = _Querier_GetOrphanedQuerierSet();
    if (set)
    {
        __block mdns_querier_t orphan = NULL;
        mdns_set_iterate(set,
        ^ bool (mdns_object_t _Nonnull object)
        {
            bool stop = false;
            const mdns_querier_t candidate = (mdns_querier_t)object;
            const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(candidate);
            if ((dnsservice == q->dnsservice) && mdns_querier_match(candidate, q->qname.c, q->qtype, q->qclass))
            {
                orphan = candidate;
                stop = true;
            }
            return stop;
        });
        if (orphan)
        {
            q->querier = orphan;
            mdns_retain(q->querier);
            mdns_set_remove(set, q->querier);
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

        if (q->pid != 0)
        {
            mdns_querier_set_delegator_pid(querier, q->pid);
        }
        else
        {
            mdns_querier_set_delegator_uuid(querier, q->uuid);
        }
        mdns_retain(q->dnsservice);
        mdns_querier_set_context(querier, q->dnsservice);
        mdns_querier_set_context_finalizer(querier, mdns_object_context_finalizer);
        mdns_querier_set_queue(querier, _Querier_InternalQueue());
        mdns_retain(querier);
        mdns_querier_set_result_handler(querier,
        ^{
            _Querier_HandleQuerierResponse(querier);
            mdns_release(querier);
        });
        mdns_querier_set_log_label(querier, "Q%u", mDNSVal16(q->TargetQID));
        mdns_querier_set_user_id(querier, mDNSVal16(q->TargetQID));
        q->querier = querier;
        mdns_retain(q->querier);
        mdns_querier_activate(q->querier);
    }
    q->NeedUpdatedQuerier = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
    if (mdns_querier_get_resolver_type(q->querier) != mdns_resolver_type_null)
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
    q->ThisQInterval = (!q->dnsservice || q->querier) ? FutureTime : mDNSPlatformOneSecond;
    q->LastQTime = m->timenow;
    SetNextQueryTime(m, q);
    mdns_forget(&querier);
}

mDNSlocal mDNSu32 _Querier_GetQuestionCount(void)
{
    mDNSu32 count = 0;
    for (const DNSQuestion *q = mDNSStorage.Questions; q; q = q->next)
    {
        count++;
    }
    return count;
}

mDNSexport void Querier_ProcessDNSServiceChanges(void)
{
    mDNS *const m = &mDNSStorage;
    mDNSu32 slot;
    CacheGroup *cg;
    CacheRecord *cr;
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    DNSPushServer **psp;
#endif

    const mDNSu32 count = _Querier_GetQuestionCount();
    m->RestartQuestion = m->Questions;
    for (mDNSu32 i = 0; (i < count) && m->RestartQuestion; i++)
    {
        DNSQuestion *const q = m->RestartQuestion;
        if (mDNSOpaque16IsZero(q->TargetQID))
        {
            m->RestartQuestion = q->next;
            continue;
        }
        const mDNSBool excludeNonStandardServices = _Querier_ExcludeNonStandardServices(q);
        mdns_dns_service_t newService = _Querier_GetDNSService(q, excludeNonStandardServices);
        mDNSBool forcePathEval = mDNSfalse;
        if (q->dnsservice != newService)
        {
            // If the DNS service would change, the DNSQuestion is not interface-scoped, and either there is no new DNS
            // service or it lacks privacy, then force a path evaluation when the DNSQuestion restarts to determine if
            // there's a DNS service that offers privacy that should be used. This DNSQuestion's resolver UUID may have
            // been cleared so that it can use a VPN DNS service, but that service may have just become defunct.
            if (!q->InterfaceID && (!newService || _Querier_DNSServiceIsUnscopedAndLacksPrivacy(newService)))
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
                newService = _Querier_GetDNSService(q, excludeNonStandardServices);
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
                // If it is null, cancel the DNS push server.
                if (!q->dnsPushServer->dnsservice)
                {
                    DNSPushServerCancel(q->dnsPushServer, mDNSfalse);
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
            #if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
                // Since we are restarting the question, retain the resolver discovery object to prevent it from being
                // stopped and deallocated.
                const domainname *domain_to_discover_resolver = mDNSNULL;
                if (dns_question_requires_resolver_discovery(q, &domain_to_discover_resolver))
                {
                    resolver_discovery_add(domain_to_discover_resolver, mDNSfalse);
                }
            #endif
                mDNS_StopQuery_internal(m, q);
                q->ForcePathEval = forcePathEval;
                q->next = mDNSNULL;
                mDNS_StartQuery_internal(m, q);
            #if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
                // Release the resolver discovery object retained above so that the reference count of the object goes
                // back to its original value, after the restart process has finished.
                if (dns_question_requires_resolver_discovery(q, &domain_to_discover_resolver))
                {
                    resolver_discovery_remove(domain_to_discover_resolver, mDNSfalse);
                }
            #endif
            }
        }
        if (m->RestartQuestion == q) m->RestartQuestion = q->next;
    }
    m->RestartQuestion = mDNSNULL;
#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    // The above code may have found some DNS Push servers that are no longer valid.   Now that we
    // are done running through the code, we need to drop our connections to those servers.
    // When we get here, any such servers should have zero questions associated with them.
    for (psp = &m->DNSPushServers; *psp != mDNSNULL; )
    {
        DNSPushServer *server = *psp;

        // It's possible that a push server whose DNS server has been deleted could be still connected but
        // not referenced by any questions.  In this case, we just delete the push server rather than trying
        // to figure out with which DNS server (if any) to associate it.
        if (server->dnsservice == mDNSNULL || mdns_dns_service_is_defunct(server->dnsservice))
        {
            // Since we are changing the m->DNSPushServers that DNSPushServerCancel() will iterate later, we will do the
            // server removal for it. And tell it to not touch the m->DNSPushServers by passing alreadyRemovedFromSystem
            // == true.
            // Unlink from the m->DNSPushServers list.
            *psp = server->next;
            server->next = mDNSNULL;
            // Release all the DNS push zones that use this server from the m->DNSPushZones list.
            DNSPushZoneRemove(m, server);
            // Cancel the server.
            DNSPushServerCancel(server, mDNStrue);
            // Release the reference to the server that m->DNSPushServers list holds.
            DNS_PUSH_RELEASE(server, DNSPushServerFinalize);
        }
        else
        {
            psp = &(server->next);
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

mDNSexport DNSQuestion *Querier_GetDNSQuestion(const mdns_querier_t querier, mDNSBool *const outIsNew)
{
    DNSQuestion *q;
    mDNS *const m = &mDNSStorage;
    mDNSBool isNew = mDNSfalse;
    for (q = m->Questions; q; q = q->next)
    {
        if (!isNew && (q == m->NewQuestions))
        {
            isNew = mDNStrue;
        }
        if (q->querier == querier)
        {
            break;
        }
    }
    if (outIsNew)
    {
        *outIsNew = q ? isNew : mDNSfalse;
    }
    return q;
}

mDNSexport mDNSBool Querier_ResourceRecordIsAnswer(const ResourceRecord * const rr, const mdns_querier_t querier)
{
    const mDNSu16 qtype = mdns_querier_get_qtype(querier);
    const mDNSu8 *const qname = mdns_querier_get_qname(querier);


    if ((RRTypeAnswersQuestionType(rr, qtype)
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

#define kOrphanedQuerierTimeLimitSecs 5

mDNSexport void Querier_HandleStoppedDNSQuestion(DNSQuestion *q)
{
    if (q->querier && !mdns_querier_has_concluded(q->querier))
    {
        const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(q->querier);
        if (!mdns_dns_service_is_defunct(dnsservice))
        {
            const mdns_set_t set = _Querier_GetOrphanedQuerierSet();
            if (set && (mdns_set_get_count(set) < kOrphanedQuerierMaxCount))
            {
                mdns_set_add(set, q->querier);
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

mDNSexport mdns_querier_t Querier_HandlePreCNAMERestart(DNSQuestion *const q)
{
    q->lastDNSServiceID = q->dnsservice ? mdns_dns_service_get_id(q->dnsservice) : MDNS_DNS_SERVICE_MAX_ID;
    const mdns_querier_t querier = q->querier;
    q->querier = NULL;
    return querier;
}

mDNSexport void Querier_HandlePostCNAMERestart(DNSQuestion *const q, const mdns_querier_t querier)
{
    if (querier)
    {
        mDNSBool keptQuerier = mDNSfalse;
        if (!q->DuplicateOf && !q->querier && q->dnsservice)
        {
            const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(querier);
            if (mdns_dns_service_get_id(q->dnsservice) == mdns_dns_service_get_id(dnsservice))
            {
                q->querier = querier;
                mdns_retain(q->querier);
                keptQuerier = mDNStrue;
            }
        }
        if (!keptQuerier)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
            _Querier_UpdateQuestionMetrics(q, querier);
#endif
            mdns_querier_invalidate(querier);
        }
    }
}

mDNSexport void Querier_PrepareQuestionForUnwindRestart(DNSQuestion *const q)
{
    q->lastDNSServiceID = MDNS_DNS_SERVICE_INVALID_ID;
    // Force a path evaluation if the DNSQuestion isn't interface-scoped.
    if (!q->InterfaceID)
    {
        q->ForcePathEval = mDNStrue;
    }
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
