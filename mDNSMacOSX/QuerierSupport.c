/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
#include "dns_push_mdns_core.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
#include "dnssd_analytics.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec.h"
#include "dnssec_mdns_core.h"
#endif

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
#include "discover_resolver.h"
#endif

#include "cf_support.h"
#include <AssertMacros.h>
#include <mach/mach_time.h>
#include <mdns/message_builder.h>
#include <mdns/ne_dns_proxy_state_watch.h>
#include <mdns/preferences.h>
#include <mdns/system.h>
#include <mdns/ticks.h>
#include <mdns/xpc.h>
#include <os/feature_private.h>
#include <os/variant_private.h>
#include "mdns_strict.h"

int PQWorkaroundThreshold = 0;

extern mDNS mDNSStorage;

mDNSlocal void _Querier_ApplyUpdate(mdns_subscriber_t subscriber);

mDNSlocal void _Querier_HandleSubscriberInvalidation(mdns_subscriber_t subscriber);

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

static mDNSBool gNEDNSProxyIsRunning = mDNSfalse;

mDNSlocal void _Querier_StartNEDNSProxyStateWatch(void)
{
    mdns_ne_dns_proxy_state_watch_start(_Querier_InternalQueue(),
    ^(const bool isRunning)
    {
        KQueueLock();
        if (!isRunning != !gNEDNSProxyIsRunning)
        {
            gNEDNSProxyIsRunning = isRunning;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "NEDNSProxy state update -- running: " PUB_BOOL, BOOL_PARAM(gNEDNSProxyIsRunning));
            mDNS *const m = &mDNSStorage;
            mDNS_Lock(m);
            // Check if outstanding DNSQuestions need to switch to a different DNS service now that an NEDNSProxy is
            // running or no longer running.
            Querier_ProcessDNSServiceChanges();
            // When a NetworkExtension DNS proxy is running, all Do53 queries are diverted to the DNS proxy by the
            // kernel. Therefore, when there's a state change, we flush all records marked as having come from a Do53
            // service because of either of the following reasons:
            //
            //  1. When a DNS proxy starts running, we don't want records that came from Do53 services in the cache.
            //     This ensures that, going forward, any DNSQuestions that are assigned a Do53 service get answered by
            //     records that come from the DNS proxy.
            //
            //  2. When a DNS proxy stops running, we want to flush all records that came from a DNS proxy. This
            //     ensures that, going forward, any DNSQuestions that are assigned a Do53 service get answered by
            //     records that come directly from the Do53 service instead of those that came from the DNS proxy,
            //     which is no longer active.
            mDNSu32 slot;
            CacheGroup *cg;
            CacheRecord *cr;
            FORALL_CACHERECORDS(slot, cg, cr)
            {
                const mdns_dns_service_t dnsservice = mdns_cache_metadata_get_dns_service(cr->resrec.metadata);
                if (dnsservice && (mdns_dns_service_get_type(dnsservice) == mdns_dns_service_type_do53))
                {
                    mDNS_PurgeCacheResourceRecord(m, cr);
                }
            }
            mDNS_Unlock(m);
        }
        KQueueUnlock("NetworkExtension DNS proxy state update");
    });
}

mDNSlocal void _Querier_EnsureNEDNSProxyStateWatchHasStarted(void)
{
    static dispatch_once_t sOnce = 0;
    dispatch_once(&sOnce,
    ^{
        _Querier_StartNEDNSProxyStateWatch();
    });
}

mDNSexport mdns_dns_service_manager_t Querier_GetDNSServiceManager(void)
{
    mDNS *const m = &mDNSStorage;
    _Querier_EnsureNEDNSProxyStateWatchHasStarted();
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
    mdns_dns_service_manager_enable_fail_fast_mode_for_odoh(manager, true);
    mdns_dns_service_manager_enable_problematic_qtype_workaround(manager, PQWorkaroundThreshold);
    if (os_variant_has_internal_diagnostics(kMDNSResponderIDStr))
    {
        const CFStringRef key = CFSTR("DDRRetryIntervalSecs");
        const uint32_t intervalSecs = mdns_preferences_get_uint32_clamped(kMDNSResponderID, key, 0, NULL);
        if (intervalSecs != 0)
        {
            mdns_dns_service_manager_set_ddr_retry_interval(manager, intervalSecs);
        }
    }
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

mDNSlocal mdns_dns_service_t _Querier_GetDNSPushDNSService(const mdns_dns_service_manager_t manager,
    const domainname *const zone, const uint32_t ifIndex)
{
    mdns_dns_service_t service = NULL;

    static mdns_domain_name_t dnsPushSRVDotLocal = NULL;
    mdns_domain_name_t dnsPushSRV = NULL;

    const bool isLocalDomain = SameDomainName(zone, &localdomain);
    if (isLocalDomain)
    {
        if (!dnsPushSRVDotLocal)
        {
            dnsPushSRVDotLocal = mdns_domain_name_create("_dns‑push‑tls._tcp.local", mdns_domain_name_create_opts_none,
                NULL);
            require_quiet(dnsPushSRVDotLocal, exit);
        }
        dnsPushSRV = dnsPushSRVDotLocal;
        mdns_retain(dnsPushSRV);
    }
    else
    {
        // "_dns-push-tls._tcp"
        domainname dnsPushSRVToConstruct = {
            .c = {13, '_', 'd', 'n', 's', '-', 'p', 'u', 's', 'h', '-', 't', 'l', 's', 4, '_', 't', 'c', 'p', 0}
        };
        AppendDomainName(&dnsPushSRVToConstruct, zone);
        dnsPushSRV = mdns_domain_name_create_with_labels(dnsPushSRVToConstruct.c, NULL);
        require_quiet(dnsPushSRV, exit);
    }

    service = mdns_dns_service_manager_get_push_service(manager, dnsPushSRV, ifIndex);
    if (!service && isLocalDomain)
    {
        mdns_dns_service_manager_register_push_service(manager, dnsPushSRV, ifIndex, NULL);
        service = mdns_dns_service_manager_get_push_service(manager, dnsPushSRV, ifIndex);
    }
    // We don't register the DNS push service if it is not for local domain.

exit:
    mdns_forget(&dnsPushSRV);
    return service;
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
    const DNSQuestion * const q, const mDNSBool excludeEncryptedDNS)
{
    mdns_dns_service_t service;
    const uint32_t ifIndex = (uint32_t)((uintptr_t)q->InterfaceID);
    if (!excludeEncryptedDNS && !uuid_is_null(q->ResolverUUID))
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
        // Exclude discovered DoH and DoT alternatives to Do53 services if all encrypted DNS services are being excluded
        // or if an NEDNSProxy is running to avoid bypassing the NEDNSProxy.
        const mDNSBool excludeDiscovered = excludeEncryptedDNS || gNEDNSProxyIsRunning;
        service = mdns_dns_service_manager_get_interface_scoped_system_service_with_options(manager, q->qname.c, ifIndex,
            excludeDiscovered ? mdns_dns_service_opt_none : mdns_dns_service_opt_prefer_discovered);
    }
    else if (q->ServiceID >= 0)
    {
        service = mdns_dns_service_manager_get_service_scoped_system_service(manager, q->qname.c, (uint32_t)q->ServiceID);
    }
    else
    {
        service = mDNSNULL;
        // Exclude discovered DoH and DoT alternatives to Do53 services if all encrypted DNS services are being excluded
        // or if an NEDNSProxy is running to avoid bypassing the NEDNSProxy.
        const mDNSBool excludeDiscovered = excludeEncryptedDNS || gNEDNSProxyIsRunning;
        if (!excludeDiscovered)
        {
            // Check for a matching discovered resolver for unscoped queries
            service = mdns_dns_service_manager_get_discovered_service(manager, q->qname.c);
        }
        if (!service)
        {
            service = mdns_dns_service_manager_get_unscoped_system_service_with_options(manager, q->qname.c,
                excludeDiscovered ? mdns_dns_service_opt_none : mdns_dns_service_opt_prefer_discovered);
        }
    }
    if (!excludeEncryptedDNS && service && !mdns_dns_service_interface_is_vpn(service))
    {
        // Check for encryption, and if the service isn't encrypted, fallback or fail
        const mDNSBool lacksRequiredEncryption = q->RequireEncryption && !mdns_dns_service_is_encrypted(service);
        if (lacksRequiredEncryption || mdns_dns_service_has_connection_problems(service))
        {
            if (lacksRequiredEncryption)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
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
    // Check if the final service is a fail-fast service.
    if (service && mdns_dns_service_fail_fast_mode_enabled(service))
    {
        // If it's having connection problems and the DNSQuestion has already been used to probe if the service is back
        // up and running. This way the client requests can fail quicker.
        if (mdns_dns_service_has_connection_problems(service) && q->UsedAsFailFastProbe)
        {
            service = NULL;
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

mDNSlocal mdns_dns_service_t _Querier_GetDNSService(const DNSQuestion *q, const mDNSBool excludeEncryptedDNS)
{
    mdns_dns_service_t service = mDNSNULL;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (!manager)
    {
        return NULL;
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
    if (dns_question_enables_dns_push(q))
    {
        // Only get DNS push DNS service when the DNS push enabled question has finished discovery process.
        const dns_obj_domain_name_t zone = dns_question_get_authoritative_zone(q);
        if (zone)
        {
            const domainname *const zoneInDomainName = (const domainname *)(dns_obj_domain_name_get_labels(zone));
            // Always use interface index 0 for the normal DNS push operation.
            service = _Querier_GetDNSPushDNSService(manager, zoneInDomainName, 0);
        }
    }
    else
#endif
    {
        service = _Querier_GetNativeDNSService(manager, q);
        if (!service && _Querier_QuestionIsEligibleForNonNativeDNSService(q))
        {
            service = _Querier_GetNonNativeDNSService(manager, q, excludeEncryptedDNS);
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
        mdns_system_pid_to_uuid(_Querier_GetMyPID(), sUUID);
    });
    return sUUID;
}

mDNSlocal mDNSBool _Querier_QuestionBelongsToSelf(const DNSQuestion *q)
{
    if (q->ProxyQuestion)
    {
        return mDNSfalse;
    }
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
// A client may have explicitly requested that use of encrypted DNS protocols is prohibited for similar dependency cycle
// reasons. In this case, ProhibitEncryptedDNS will be set to true.
//
// Also, if a DNSQuestion's QNAME is in a special-use mDNS local domain, and is being sent via unicast DNS as a
// workaround for private internal networks that incorrectly use these domains for their network's DNS, then
// ODoH/DoH/DoT should not be used. It only makes sense to send the DNS queries to DNS servers belonging to the network,
// e.g., those specified via DHCP.
mDNSlocal mDNSBool _Querier_ExcludeEncryptedDNSServices(const DNSQuestion *const q)
{
    return (_Querier_QuestionBelongsToSelf(q) || q->ProhibitEncryptedDNS || IsLocalDomain(&q->qname));
}

mDNSexport void Querier_SetDNSServiceForQuestion(DNSQuestion *q)
{
    const mDNSBool excludeEncryptedDNS = _Querier_ExcludeEncryptedDNSServices(q);
    if (!uuid_is_null(q->ResolverUUID) && excludeEncryptedDNS)
    {
        uuid_clear(q->ResolverUUID);
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[R%u->Q%u] Cleared resolver UUID for question: " PRI_DM_NAME " (" PUB_S ")",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype));
    }
    mdns_forget(&q->dnsservice);
    mdns_dns_service_t service = _Querier_GetDNSService(q, excludeEncryptedDNS);
    if (!excludeEncryptedDNS)
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
            service = _Querier_GetDNSService(q, excludeEncryptedDNS);
        }
    }
    q->dnsservice = service;
    mdns_retain_null_safe(q->dnsservice);

    mDNSBool enablesDNSSEC = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    enablesDNSSEC = dns_question_is_dnssec_requestor(q);
#endif

    if (!q->dnsservice || _Querier_ShouldLogFullDNSService(q->dnsservice))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[R%u->Q%u] Question for " PRI_DM_NAME " (" PUB_S PUB_S ") assigned DNS service -- %@",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
            enablesDNSSEC ? ", DNSSEC" : "", q->dnsservice);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            "[R%u->Q%u] Question for " PRI_DM_NAME " (" PUB_S PUB_S ") assigned DNS service %llu",
            q->request_id, mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype),
            enablesDNSSEC ? ", DNSSEC" : "", mdns_dns_service_get_id(q->dnsservice));
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

mDNSlocal CFMutableSetRef _Querier_GetOrphanedQuerierSet(void)
{
    static CFMutableSetRef sOrphanedQuerierSet = NULL;
    if (!sOrphanedQuerierSet)
    {
        static const CFSetCallBacks sSetCallbacks =
        {
            .version         = 0,
            .retain          = mdns_cf_callback_retain,
            .release         = mdns_cf_callback_release,
            .copyDescription = mdns_cf_callback_copy_description
        };
        sOrphanedQuerierSet = CFSetCreateMutable(kCFAllocatorDefault, 0, &sSetCallbacks);
    }
    return sOrphanedQuerierSet;
}

#define _Querier_LogConcludedQuerierWitFormattedPrefix(QUERIER, SENSITIVE, PREFIX_FMT, ...)             \
    do                                                                                                  \
    {                                                                                                   \
        const mdns_querier_t _querier = (QUERIER);                                                      \
        char *_sensitiveQuerierDesc = (SENSITIVE) ? mdns_copy_private_description(_querier) : mDNSNULL; \
        if (_sensitiveQuerierDesc)                                                                      \
        {                                                                                               \
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, PREFIX_FMT PUB_S,                    \
                __VA_ARGS__, _sensitiveQuerierDesc);                                                    \
            ForgetMem(&_sensitiveQuerierDesc);                                                          \
        }                                                                                               \
        else                                                                                            \
        {                                                                                               \
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, PREFIX_FMT "%@",                     \
                __VA_ARGS__, _querier);                                                                 \
        }                                                                                               \
    } while (0)

mDNSlocal void _Querier_HandleQuerierResponse(const mdns_querier_t querier)
{
    KQueueLock();
    _Querier_LogConcludedQuerierWitFormattedPrefix(querier, mdns_querier_needs_sensitive_logging(querier),
        "[Q%u] Handling concluded querier: ", mdns_querier_get_user_id(querier));

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
    _Querier_UpdateDNSMessageSizeAnalytics(querier);
#endif
    mDNS *const m = &mDNSStorage;
    const mdns_querier_result_type_t resultType = mdns_querier_get_result_type(querier);
    const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(querier);
    if (resultType == mdns_querier_result_type_response)
    {
        if (!mdns_dns_service_is_defunct(dnsservice))
        {
            size_t copyLen = mdns_querier_get_response_length(querier);
            if (copyLen > sizeof(m->imsg.m))
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[Q%u] Large %lu-byte response will be truncated to fit mDNSCore's %lu-byte message buffer",
                    mdns_querier_get_user_id(querier), (unsigned long)copyLen, (unsigned long)sizeof(m->imsg.m));
                copyLen = sizeof(m->imsg.m);
            }
            memcpy(&m->imsg.m, mdns_querier_get_response_ptr(querier), copyLen);
            const mDNSu8 *const end = ((mDNSu8 *)&m->imsg.m) + copyLen;
            mDNSCoreReceiveForQuerier(m, &m->imsg.m, end, mdns_client_upcast(querier), dnsservice, mDNSInterface_Any);
        }
    }
    const CFMutableSetRef set = _Querier_GetOrphanedQuerierSet();
    if (set)
    {
		CFSetRemoveValue(set, querier);
    }
    mDNSBool qIsNew = mDNSfalse;
    DNSQuestion *q = Querier_GetDNSQuestion(querier, &qIsNew);
    if (q)
    {
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
        _Querier_UpdateQuestionMetrics(q, querier);
#endif
        mdns_forget(&q->client);
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

                case mdns_querier_result_type_connection_problem:
                    // If we haven't yet received the connection problem update from the DNS service manager, try to apply
                    // it now, so that the DNSQuestion restart can notice that the DNS service is indeed having connection
                    // problems. It could be that the overall connection problems status has cleared by the time we got
                    // this connection problem result. Either way, restart the DNSQuestion and all of its duplicates so
                    // that they can make progress.
                    if (!mdns_dns_service_has_connection_problems(dnsservice))
                    {
                        const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
                        if (manager)
                        {
                            mdns_dns_service_manager_apply_pending_connection_problem_updates(manager);
                        }
                    }
                    mDNS_Lock(m);
                    // Re-assign the querier, so that if the DNSQuestion is the leader of a set of duplicates, we can
                    // iteratively identify each subsequent duplicate as each member of the set gets restarted. This is
                    // because when a DNSQuestion is stopped, its querier gets passed to the next duplicate if one exists.
                    // If a duplicate doesn't exist, then the querier gets released.
                    mdns_client_replace(&q->client, querier);
                    while (q)
                    {
                        mDNS_StopQuery_internal(m, q);
                        q->UsedAsFailFastProbe = mDNStrue;
                        mDNS_StartQuery_internal(m, q);
                        q = Querier_GetDNSQuestion(querier, &qIsNew);
                        if (q && qIsNew)
                        {
                            // If we reach the NewQuestions sub-list, we're done. Just forget the querier because it has
                            // already concluded and is no longer useful. AnswerNewQuestion() will handle the new
                            // DNSQuestion as normal.
                            mdns_forget(&q->client);
                            q = mDNSNULL;
                        }
                    }
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
    mdns_subscriber_t subscriber = NULL;
    mdns_domain_name_t qname = NULL;

    if (q->client || !q->dnsservice)
    {
        const mdns_querier_t current_querier = mdns_querier_downcast(q->client);
        if (current_querier)
        {
            q->NeedUpdatedQuerier = !mdns_querier_match(current_querier, q->qname.c, q->qtype, q->qclass);
        }
        goto exit;
    }
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    const bool needDNSSEC = dns_question_is_primary_dnssec_requestor(q);
#endif
    const CFMutableSetRef set = _Querier_GetOrphanedQuerierSet();
    if (set)
    {
        __block mdns_querier_t orphan = NULL;
        mdns_cfset_enumerate(set,
        ^ bool (const mdns_querier_t _Nonnull candidate)
        {
            const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(candidate);
            if ((dnsservice == q->dnsservice) && mdns_querier_match(candidate, q->qname.c, q->qtype, q->qclass))
            {
            #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
                if ((mdns_querier_get_dnssec_ok(candidate) == needDNSSEC) &&
                    (mdns_querier_get_checking_disabled(candidate) == needDNSSEC))
            #endif
                {
                    orphan = candidate;
                }
            }
            const bool proceed = (orphan == NULL);
            return proceed;
        });
        if (orphan)
        {
            mdns_client_replace(&q->client, orphan);
            CFSetRemoveValue(set, orphan);
            mdns_querier_set_time_limit_ms(orphan, 0);
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[Q%u->Q%u] Adopted orphaned querier", mDNSVal16(q->TargetQID), mdns_querier_get_user_id(orphan));
        }
    }
    if (!q->client)
    {
        mdns_client_t client;
    #if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
        if (dns_question_enables_dns_push(q))
        {
            // We still need querier to discover the resolver if we are still in the discovery process.
            subscriber = mdns_dns_service_create_subscriber(q->dnsservice, NULL);
            mdns_require_quiet(subscriber, exit);
            client = mdns_client_upcast(subscriber);
        }
        else
    #endif
        {
            querier = mdns_dns_service_create_querier(q->dnsservice, NULL);
            require_quiet(querier, exit);

        #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
            if (needDNSSEC)
            {
                mdns_querier_set_dnssec_ok(querier, true);
                mdns_querier_set_checking_disabled(querier, true);
            }
        #endif
            // Set the identifier for the delegator relative to mDNSResponder, i.e., the identifier of the effective
            // client.
            //
            // Order of preference:
            //  1. q->DelegatorToken if available. This is the audit token of the immediate client's delegator, and
            //     therefore the audit token of the effective client.
            //  2. q->PeerToken if available and its PID is equal to a non-zero q->pid, which is the PID of the
            //     effective client. In this case, the immediate client is the effective client, so use its audit token,
            //     which is generally more informative than just a PID.
            //  3. q->pid if it's non-zero. This is the PID of the effective client.
            //  4. q->uuid. This is the UUID of the effective client.
            if (0) {}
        #if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
            else if (q->DelegatorToken)
            {
                mdns_querier_set_delegator_audit_token(querier, q->DelegatorToken);
            }
        #endif
            else if (q->pid != 0)
            {
            #if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
                if (mdns_audit_token_get_pid_null_safe(q->PeerToken, 0) == q->pid)
                {
                    mdns_querier_set_delegator_audit_token(querier, q->PeerToken);
                }
                else
            #endif
                {
                    mdns_querier_set_delegator_pid(querier, q->pid);
                }
            }
            else
            {
                mdns_querier_set_delegator_uuid(querier, q->uuid);
            }
        #if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
            if (DNSQuestionNeedsSensitiveLogging(q))
            {
                mdns_querier_enable_sensitive_logging(querier, true);
            }
        #endif
            client = mdns_client_upcast(querier);
        }

        qname = mdns_domain_name_create_with_labels(q->qname.c, NULL);
        require_quiet(qname, exit);

        mdns_client_set_query(client, qname, q->qtype, q->qclass);
        mdns_retain(q->dnsservice);
        mdns_client_set_context(client, q->dnsservice);
        mdns_client_set_context_finalizer(client, mdns_object_context_finalizer);
        mdns_client_set_queue(client, _Querier_InternalQueue());

        if (querier)
        {
            mdns_retain(querier);
            mdns_querier_set_result_handler(querier,
            ^{
                _Querier_HandleQuerierResponse(querier);
                mdns_release(querier);
            });
            mdns_querier_set_log_label(querier, "Q%u", mDNSVal16(q->TargetQID));
            mdns_querier_set_user_id(querier, mDNSVal16(q->TargetQID));
        }
        if (subscriber)
        {
            mdns_retain(subscriber);
            mdns_subscriber_set_event_handler(subscriber,
            ^(const mdns_subscriber_event_t event)
            {
                KQueueLock();
                switch (event)
                {
                    case mdns_subscriber_event_change:
                        _Querier_ApplyUpdate(subscriber);
                        break;

                    case mdns_subscriber_event_invalidated:
                        _Querier_HandleSubscriberInvalidation(subscriber);
                        mdns_release(subscriber);
                        break;
                }
                KQueueUnlock("Subscriber event handler");
            });
        }
        mdns_client_replace(&q->client, client);
        mdns_client_activate(q->client);
    }
    q->NeedUpdatedQuerier = mDNSfalse;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
    const mdns_querier_t current_querier = mdns_querier_downcast(q->client);
    if (current_querier && (mdns_querier_get_resolver_type(current_querier) != mdns_resolver_type_null))
    {
        if (q->metrics.answered)
        {
            DNSMetricsClear(&q->metrics);
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
    q->ThisQInterval = (!q->dnsservice || q->client) ? FutureTime : mDNSPlatformOneSecond;
    q->LastQTime = m->timenow;
    SetNextQueryTime(m, q);
    mdns_forget(&querier);
    mdns_forget(&subscriber);
    mdns_forget(&qname);
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
        const mDNSBool excludeEncryptedDNS = _Querier_ExcludeEncryptedDNSServices(q);
        mdns_dns_service_t newService = _Querier_GetDNSService(q, excludeEncryptedDNS);
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
                newService = _Querier_GetDNSService(q, excludeEncryptedDNS);
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
                mDNS_StopQuery_internal(m, q);
                q->ForcePathEval = forcePathEval;
                q->next = mDNSNULL;
                mDNS_StartQuery_internal(m, q);
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
        const mdns_dns_service_t dnsservice = mdns_cache_metadata_get_dns_service(cr->resrec.metadata);
        if (!dnsservice || mdns_dns_service_is_defunct(dnsservice))
        {
            mdns_forget(&cr->resrec.metadata);
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
        if (mdns_querier_downcast(q->client) == querier)
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
    mDNSBool isAnswer;
    const mDNSu16 qtype = mdns_querier_get_qtype(querier);
    const mDNSu8 *const qname = mdns_querier_get_qname(querier);

    if (qname == mDNSNULL)
    {
        isAnswer = mDNSfalse;
        goto exit;
    }

    if (rr->rrclass != mdns_querier_get_qclass(querier))
    {
        isAnswer = mDNSfalse;
        goto exit;
    }

    RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    const mDNSBool requiresRRToValidate = mdns_querier_get_dnssec_ok(querier) && mdns_querier_get_checking_disabled(querier);
    if (requiresRRToValidate)
    {
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
    }
#endif

    isAnswer = RRTypeAnswersQuestionType(rr, qtype, flags);
    if (!isAnswer)
    {
        goto exit;
    }

    isAnswer = SameDomainName(rr->name, (const domainname *)qname);

exit:
    return isAnswer;
}

mDNSexport mDNSBool Querier_SameNameCacheRecordIsAnswer(const CacheRecord *const cr, const mdns_querier_t querier)
{
    mDNSBool isAnswer;
    const ResourceRecord *const rr = &cr->resrec;
    const mDNSu16 qtype = mdns_querier_get_qtype(querier);

    if (rr->rrclass != mdns_querier_get_qclass(querier))
    {
        isAnswer = mDNSfalse;
        goto exit;
    }

    RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    const mDNSBool requiresRRToValidate = mdns_querier_get_dnssec_ok(querier) && mdns_querier_get_checking_disabled(querier);
    if (requiresRRToValidate)
    {
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
    }
#endif
    isAnswer = RRTypeAnswersQuestionType(rr, qtype, flags);

exit:
    return isAnswer;
}

#define kOrphanedQuerierTimeLimitSecs 5

mDNSexport void Querier_HandleStoppedDNSQuestion(DNSQuestion *q)
{
    const mdns_querier_t querier = mdns_querier_downcast(q->client);
    if (querier && !mdns_querier_has_concluded(querier))
    {
        const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_querier_get_context(querier);
        if (!mdns_dns_service_is_defunct(dnsservice))
        {
            const CFMutableSetRef set = _Querier_GetOrphanedQuerierSet();
            if (set && (CFSetGetCount(set) < kOrphanedQuerierMaxCount))
            {
				CFSetAddValue(set, querier);
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[Q%u] Keeping orphaned querier for up to " StringifyExpansion(kOrphanedQuerierTimeLimitSecs) " seconds",
                    mdns_querier_get_user_id(querier));
                mdns_querier_set_time_limit_ms(querier, kOrphanedQuerierTimeLimitSecs * 1000);
                mdns_forget(&q->client);
            }
        }
    }
    mdns_client_forget(&q->client);
    mdns_forget(&q->dnsservice);
}

mDNSexport mdns_client_t Querier_HandlePreCNAMERestart(DNSQuestion *const q)
{
    q->lastDNSServiceID = q->dnsservice ? mdns_dns_service_get_id(q->dnsservice) : MDNS_DNS_SERVICE_MAX_ID;
    const mdns_client_t client = q->client;
    q->client = NULL;
    return client;
}

mDNSexport void Querier_HandlePostCNAMERestart(DNSQuestion *const q, const mdns_client_t client)
{
    if (client)
    {
        mDNSBool keptQuerier = mDNSfalse;
        if (!q->DuplicateOf && !q->client && q->dnsservice)
        {
            const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_client_get_context(client);
            if (mdns_dns_service_get_id(q->dnsservice) == mdns_dns_service_get_id(dnsservice))
            {
                mdns_replace(&q->client, client);
                keptQuerier = mDNStrue;
            }
        }
        if (!keptQuerier)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
            const mdns_querier_t querier = mdns_querier_downcast(client);
            if (querier)
            {
                _Querier_UpdateQuestionMetrics(q, querier);
            }
#endif
            mdns_client_invalidate(client);
        }
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

mDNSlocal mdns_dns_service_t _Querier_GetDotLocalPushService(const uint32_t ifIndex)
{
    mdns_dns_service_t service = NULL;
    const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
    if (manager)
    {
        service = _Querier_GetDNSPushDNSService(manager, &localdomain, ifIndex);
    }

    return service;
}

mDNSlocal void _Querier_RemoveRecord(const mdns_resource_record_t record, const mDNSInterfaceID interface,
    const mDNSBool collective)
{
    const uint16_t rdlen = mdns_resource_record_get_rdata_length(record);
    require_quiet(rdlen <= MaximumRDSize, exit);

    mDNS *const m = &mDNSStorage;
    const mdns_domain_name_t name = mdns_resource_record_get_name(record);
    const domainname *const dname = (const domainname *)mdns_domain_name_get_labels(name);
    const CacheGroup *const cg = CacheGroupForName(m, DomainNameHashValue(dname), dname);
    if (cg)
    {
        const uint16_t type = mdns_resource_record_get_type(record);
        const uint16_t class = mdns_resource_record_get_class(record);
        const uint8_t *const rdata = mdns_resource_record_get_rdata_bytes_ptr(record);
        for (CacheRecord *cr = cg->members; cr; cr = cr->next)
        {
            const ResourceRecord *const rr = &cr->resrec;
            if (rr->InterfaceID != interface)
            {
                continue;
            }
            mDNSBool remove = mDNSfalse;
            if (collective)
            {
                if (class == kDNSQClass_ANY)
                {
                    remove = mDNStrue;
                }
                else if (rr->rrclass == class)
                {
                    if (rr->rrtype == kDNSQType_ANY)
                    {
                        remove = mDNStrue;
                    }
                    else if (rr->rrtype == type)
                    {
                        remove = mDNStrue;
                    }
                }
            }
            else
            {
                if ((rr->rrtype == type) && (rr->rrclass == class) && (rr->rdlength == rdlen))
                {
                    static mDNSu8 rdataBuf[MaximumRDSize];
                    memset(rdataBuf, 0, rdlen);
                    putRData(mDNSNULL, rdataBuf, rdataBuf + sizeof(rdataBuf), rr);
                    if (memcmp(rdataBuf, rdata, rdlen) == 0)
                    {
                        remove = mDNStrue;
                    }
                }
            }
            if (remove)
            {
                mDNS_PurgeCacheResourceRecord(m, cr);
                if (!collective)
                {
                    break;
                }
            }
        }
    }

exit:
    return;
}

mDNSlocal void _Querier_RemoveRecordSingle(const mdns_resource_record_t record, const mDNSInterfaceID interface)
{
	_Querier_RemoveRecord(record, interface, mDNSfalse);
}

mDNSlocal void _Querier_RemoveRecordCollective(const mdns_resource_record_t record, const mDNSInterfaceID interface)
{
	_Querier_RemoveRecord(record, interface, mDNStrue);
}

#if !defined(kDNSPushChangeNotificationTTL_RemoveSingle)
    #define kDNSPushChangeNotificationTTL_RemoveSingle     UINT32_C(0xFFFFFFFF)
    #define kDNSPushChangeNotificationTTL_RemoveCollective UINT32_C(0xFFFFFFFE)
#endif

static mdns_message_builder_t gMessageBuilder = NULL;

mDNSlocal void _Querier_ApplyUpdate(mdns_subscriber_t subscriber)
{
    CFArrayRef changeNotifications = mdns_subscriber_get_update(subscriber);
    require_quiet(changeNotifications, exit);

    const mdns_dns_service_t dnsservice = (mdns_dns_service_t)mdns_client_get_context(subscriber);
    const mDNSInterfaceID interface = (mDNSInterfaceID)(uintptr_t)mdns_dns_service_get_interface_index(dnsservice);
    mdns_cfarray_enumerate(changeNotifications,
    ^ bool (const mdns_resource_record_t record)
    {
        const uint32_t ttl = mdns_resource_record_get_ttl(record);
        if (ttl == kDNSPushChangeNotificationTTL_RemoveSingle)
        {
            _Querier_RemoveRecordSingle(record, interface);
        }
        else if (ttl == kDNSPushChangeNotificationTTL_RemoveCollective)
        {
            _Querier_RemoveRecordCollective(record, interface);
        }
        else
        {
            mdns_message_builder_reset(gMessageBuilder);
            mdns_message_builder_set_message_id(gMessageBuilder, 0);
            mdns_message_builder_set_qr_bit(gMessageBuilder, true);
            mdns_message_builder_set_aa_bit(gMessageBuilder, true);
            mdns_message_builder_append_answer_record(gMessageBuilder, record);
            mDNS *const m = &mDNSStorage;
            uint8_t *const msgBuf = (uint8_t *)&m->imsg.m;
            const size_t msgBufLen = sizeof(m->imsg.m);
            const size_t msgLen = mdns_message_builder_write_message(gMessageBuilder, msgBuf, msgBufLen);
            if (msgLen <= msgBufLen)
            {
                const mDNSu8 *const msgEnd = &msgBuf[msgLen];
                mDNSCoreReceiveForQuerier(m, &m->imsg.m, msgEnd, mdns_client_upcast(subscriber), dnsservice, interface);
            }
        }
        return true;
    });

exit:
    return;
}

mDNSlocal void _Querier_HandleSubscriberInvalidation(const mdns_subscriber_t subscriber)
{
    mDNS *const m = &mDNSStorage;
    const mdns_domain_name_t name = mdns_client_get_name(subscriber);
    const domainname *const dname = (const domainname *)mdns_domain_name_get_labels(name);
    const CacheGroup *const cg = CacheGroupForName(m, DomainNameHashValue(dname), dname);
    if (cg)
    {
        const mdns_subscriber_id_t ident = mdns_subscriber_get_id(subscriber);
        for (CacheRecord *cr = cg->members; cr; cr = cr->next)
        {
            if (cr->DNSPushSubscribed && (mdns_cache_metadata_get_subscriber_id(cr->resrec.metadata) == ident))
            {
                cr->DNSPushSubscribed = mDNSfalse;
                SetNextCacheCheckTimeForRecord(m, cr);
            }
        }
    }
}

mDNSexport void Querier_HandleMDNSQuestion(DNSQuestion *const q)
{
    mdns_subscriber_t subscriber = NULL;
    mdns_domain_name_t qname = NULL;
    const mDNSBool enabled = os_feature_enabled(mDNSResponder, dot_local_push);
    require_quiet(enabled, exit);

    if (mDNSOpaque16IsZero(q->TargetQID) && q->InterfaceID && !q->client)
    {
        if (!q->dnsservice)
        {
            const uint32_t ifIndex = (uint32_t)((uintptr_t)q->InterfaceID);
            q->dnsservice = _Querier_GetDotLocalPushService(ifIndex);
            require_quiet(q->dnsservice, exit);
        }
        if (!gMessageBuilder)
        {
            gMessageBuilder = mdns_message_builder_create();
            require_quiet(gMessageBuilder, exit);
        }
        subscriber = mdns_dns_service_create_subscriber(q->dnsservice, NULL);
        require_quiet(subscriber, exit);

        qname = mdns_domain_name_create_with_labels(q->qname.c, NULL);
        require_quiet(qname, exit);

        mdns_client_set_query(subscriber, qname, q->qtype, q->qclass);
        mdns_client_set_context(subscriber, q->dnsservice);
        mdns_client_set_context_finalizer(subscriber, mdns_object_context_finalizer);
        mdns_client_set_queue(subscriber, _Querier_InternalQueue());
        mdns_retain(subscriber);
        mdns_subscriber_set_event_handler(subscriber,
        ^(const mdns_subscriber_event_t event)
        {
            KQueueLock();
            switch (event)
            {
                case mdns_subscriber_event_change:
                    _Querier_ApplyUpdate(subscriber);
                    break;

                case mdns_subscriber_event_invalidated:
                    _Querier_HandleSubscriberInvalidation(subscriber);
                    mdns_release(subscriber);
                    break;
            }
            KQueueUnlock("Subscriber event handler");
        });
        mdns_client_replace(&q->client, subscriber);
        mdns_client_activate(q->client);
    }

exit:
    mdns_forget(&subscriber);
    mdns_forget(&qname);
}

mDNSlocal mdns_dns_service_id_t
_Querier_DNSServiceRegistrationStartHandler(const mdns_dns_service_definition_t definition)
{
    KQueueLock();
    const mdns_dns_service_id_t ident = Querier_RegisterNativeDNSService(definition);
    KQueueUnlock("DNS service registration start handler");
    return ident;
}

mDNSlocal void
_Querier_DNSServiceRegistrationStopHandler(const mdns_dns_service_id_t ident)
{
    KQueueLock();
    Querier_DeregisterNativeDNSService(ident);
    KQueueUnlock("DNS service registration stop handler");
}

const struct mrcs_server_dns_service_registration_handlers_s kMRCSServerDNSServiceRegistrationHandlers =
{
    .start = _Querier_DNSServiceRegistrationStartHandler,
    .stop = _Querier_DNSServiceRegistrationStopHandler,
};

#endif // MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
