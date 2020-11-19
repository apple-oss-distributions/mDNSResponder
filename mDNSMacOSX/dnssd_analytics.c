/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dnssd_analytics.h"
#include "mDNSMacOSX.h"
#include "uds_daemon.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)

#include <xpc/xpc.h>
#include <CoreAnalytics/CoreAnalytics.h>
typedef xpc_object_t COREANALYTICS_RETURNS_RETAINED
(^event_create_block_t)(void);

#define UNSET_STR	"unset"

#endif // ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)

// Local aggregate counters to track request counts

mDNSlocal uint64_t sCacheUsage_UnicastHitCount = 0;
mDNSlocal uint64_t sCacheUsage_UnicastMissCount = 0;
mDNSlocal uint64_t sCacheUsage_MulticastHitCount = 0;
mDNSlocal uint64_t sCacheUsage_MulticastMissCount = 0;

mDNSlocal uint64_t sCacheRequest_UnicastHitCount = 0;
mDNSlocal uint64_t sCacheRequest_UnicastMissCount = 0;
mDNSlocal uint64_t sCacheRequest_MulticastHitCount = 0;
mDNSlocal uint64_t sCacheRequest_MulticastMissCount = 0;

#if COMPILER_LIKES_PRAGMA_MARK
#pragma mark -
#pragma mark - Private CacheUsage Functions
#endif

mDNSlocal void
dnssd_analytics_post_cache_request_count(CacheRequestType inType, CacheState inState, uint64_t inRequestCount)
{
    event_create_block_t        create_event;
    bool                        posted;

    create_event = ^{
        xpc_object_t        dict;
        dict = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(dict, "requestType",  inType  == CacheRequestType_multicast    ? "multicast"   : "unicast");
        xpc_dictionary_set_string(dict, "cacheState",   inState == CacheState_hit                ? "hit"         : "miss");
        xpc_dictionary_set_uint64(dict, "requestCount", inRequestCount);
        return (dict);
    };
    posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.request", create_event);
    if (!posted) {
        LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.request:  Failed to post");
    }
}

mDNSlocal void
dnssd_analytics_post_cache_request_counts()
{
    if (sCacheRequest_UnicastHitCount > 0) {
        dnssd_analytics_post_cache_request_count(CacheRequestType_unicast, CacheState_hit, sCacheRequest_UnicastHitCount);
        sCacheRequest_UnicastHitCount = 0;
    }
    if (sCacheRequest_UnicastMissCount > 0) {
        dnssd_analytics_post_cache_request_count(CacheRequestType_unicast, CacheState_miss, sCacheRequest_UnicastMissCount);
        sCacheRequest_UnicastMissCount = 0;
    }
    if (sCacheRequest_MulticastHitCount > 0) {
        dnssd_analytics_post_cache_request_count(CacheRequestType_multicast, CacheState_hit, sCacheRequest_MulticastHitCount);
        sCacheRequest_MulticastHitCount = 0;
    }
    if (sCacheRequest_MulticastMissCount > 0) {
        dnssd_analytics_post_cache_request_count(CacheRequestType_multicast, CacheState_miss, sCacheRequest_MulticastMissCount);
        sCacheRequest_MulticastMissCount = 0;
    }
}

mDNSlocal void
dnssd_analytics_post_cache_usage_counts_for_type(CacheRequestType inType, uint64_t inHitCount, uint64_t inMissCount)
{
    event_create_block_t    create_event;
    bool                    posted;

    create_event = ^{
        xpc_object_t        dict;
        dict = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(dict, "requestType",  inType == CacheRequestType_multicast ? "multicast" : "unicast");
        xpc_dictionary_set_uint64(dict, "hitCount",     inHitCount);
        xpc_dictionary_set_uint64(dict, "missCount",    inMissCount);
        return (dict);
    };
    posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.entries", create_event);
    if (!posted) {
        LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.entries:  Failed to post");
    }
}

mDNSlocal void
dnssd_analytics_post_cache_usage_counts()
{
	if (sCacheUsage_MulticastHitCount || sCacheUsage_MulticastMissCount) {
		dnssd_analytics_post_cache_usage_counts_for_type(CacheRequestType_multicast, sCacheUsage_MulticastHitCount, sCacheUsage_MulticastMissCount);
		sCacheUsage_MulticastHitCount = 0;
		sCacheUsage_MulticastMissCount = 0;
	}
	if (sCacheUsage_UnicastHitCount || sCacheUsage_UnicastMissCount) {
		dnssd_analytics_post_cache_usage_counts_for_type(CacheRequestType_unicast, sCacheUsage_UnicastHitCount, sCacheUsage_UnicastMissCount);
		sCacheUsage_UnicastHitCount = 0;
		sCacheUsage_UnicastMissCount = 0;
	}
}

#if COMPILER_LIKES_PRAGMA_MARK
#pragma mark -
#pragma mark - Exported CacheUsage Functions
#endif

mDNSexport void
dnssd_analytics_update_cache_request(CacheRequestType inType, CacheState inState)
{
    if (inType == CacheRequestType_unicast) {
        if (inState == CacheState_hit) {
            sCacheRequest_UnicastHitCount++;
        } else if (inState == CacheState_miss) {
            sCacheRequest_UnicastMissCount++;
        } else {
			LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "dnssd_analytics_update_cache_request:  unknown CacheState %d for unicast", inState);
        }
    } else if (inType == CacheRequestType_multicast) {
        if (inState == CacheState_hit) {
            sCacheRequest_MulticastHitCount++;
        } else if (inState == CacheState_miss) {
            sCacheRequest_MulticastMissCount++;
        } else {
            LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "dnssd_analytics_update_cache_request:  unknown CacheState %d for multicast", inState);
        }
    } else {
        LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "dnssd_analytics_update_cache_request:  unknown CacheRequestType %d", inType);
    }
}

mDNSexport void
dnssd_analytics_update_cache_usage_counts(uint32_t inHitMulticastCount, uint32_t inMissMulticastCount, uint32_t inHitUnicastCount, uint32_t inMissUnicastCount)
{
	sCacheUsage_MulticastHitCount += inHitMulticastCount;
	sCacheUsage_MulticastMissCount += inMissMulticastCount;
	sCacheUsage_UnicastHitCount += inHitUnicastCount;
	sCacheUsage_UnicastMissCount += inMissUnicastCount;
}

#endif // CACHE_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, WAB_ANALYTICS)

#if COMPILER_LIKES_PRAGMA_MARK
#pragma mark -
#pragma mark - Exported WABUsage Functions
#endif

mDNSexport void
dnssd_analytics_post_WAB_usage_event_count(WABUsageKind inKind, WABUsageType inType, WABUsageEvent inEvent, uint64_t inEventCount)
{
    event_create_block_t    create_event;
    bool                    posted;
    char *                  kind  = UNSET_STR;
    char *                  type  = UNSET_STR;
    char *                  event = UNSET_STR;

	if (analytics_send_event_lazy) {
		switch (inKind) {
			case WABUsageKind_results: {
				kind = "results";
				break;
			}
			case WABUsageKind_session: {
				kind = "session";
				break;
			}
			case WABUsageKind_operation: {
				kind = "operation";
				break;
			}
		}

		switch (inType) {
			case WABUsageType_enumeration: {
				type = "enumeration";
				break;
			}
			case WABUsageType_query: {
				type = "query";
				break;
			}
			case WABUsageType_push: {
				type = "push";
				break;
			}
			case WABUsageType_llq: {
				type = "llq";
				break;
			}
		}

		switch (inEvent) {
			case WABUsageEvent_positive: {
				event = "positive";
				break;
			}
			case WABUsageEvent_negative: {
				event = "negative";
				break;
			}
			case WABUsageEvent_null: {
				event = "null";
				break;
			}
			case WABUsageEvent_error: {
				event = "error";
				break;
			}

			case WABUsageEvent_connected: {
				event = "connected";
				break;
			}
			case WABUsageEvent_session: {
				event = "session";
				break;
			}
			case WABUsageEvent_reset: {
				event = "reset";
				break;
			}
			case WABUsageEvent_idledOut: {
				event = "idledOut";
				break;
			}
			case WABUsageEvent_goAway: {
				event = "goAway";
				break;
			}
			case WABUsageEvent_resumedGood: {
				event = "resumedGood";
				break;
			}
			case WABUsageEvent_resumedBad: {
				event = "resumedBad";
				break;
			}

			case WABUsageEvent_succeeded: {
				event = "succeeded";
				break;
			}
			case WABUsageEvent_rejected: {
				event = "rejected";
				break;
			}
			case WABUsageEvent_dsoni: {
				event = "dsoni";
				break;
			}
			case WABUsageEvent_answered: {
				event = "answered";
				break;
			}
		}

		create_event = ^{
			xpc_object_t        dict;
			dict = xpc_dictionary_create(NULL, NULL, 0);
			xpc_dictionary_set_string(dict, "kind",         kind);
			xpc_dictionary_set_string(dict, "type",         type);
			xpc_dictionary_set_string(dict, "event",        event);
			xpc_dictionary_set_uint64(dict, "eventCount",   inEventCount);
			return (dict);
		};
		posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.entries", create_event);
		if (!posted) {
			LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.entries:  Failed to post");
		}
	}
}

#endif // WAB_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
#if COMPILER_LIKES_PRAGMA_MARK
#pragma mark -
#pragma mark - Exported Analytics Functions
#endif

mDNSexport void
dnssd_analytics_init()
{
	static dispatch_once_t	sInitAnalyticsOnce = 0;
	static dispatch_queue_t sAnalyticsQueue = NULL;
	dispatch_once(&sInitAnalyticsOnce, ^{
		sAnalyticsQueue = dispatch_queue_create("com.apple.mDNSResponder.analytics-reporting-queue", DISPATCH_QUEUE_SERIAL);
		xpc_object_t criteria = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_bool(criteria, XPC_ACTIVITY_REPEATING, true);
		xpc_dictionary_set_bool(criteria, XPC_ACTIVITY_ALLOW_BATTERY, true);
		xpc_dictionary_set_int64(criteria, XPC_ACTIVITY_DELAY, XPC_ACTIVITY_INTERVAL_1_DAY);
		xpc_dictionary_set_int64(criteria, XPC_ACTIVITY_GRACE_PERIOD, XPC_ACTIVITY_INTERVAL_5_MIN);
		xpc_dictionary_set_string(criteria, XPC_ACTIVITY_PRIORITY, XPC_ACTIVITY_PRIORITY_MAINTENANCE);

		xpc_activity_register("com.apple.mDNSResponder.analytics.daily", criteria, ^(xpc_activity_t activity) {
			if (xpc_activity_should_defer(activity)) {
			    if (xpc_activity_set_state(activity, XPC_ACTIVITY_STATE_DEFER)) {
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_INFO, "com.apple.mDNSResponder.analytics.daily: Asked to defer");
				} else {
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_ERROR, "com.apple.mDNSResponder.analytics.daily: Asked to defer but failed to set state");
				}
			} else {
				dispatch_async(sAnalyticsQueue, ^{
#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
					KQueueLock();
					mDNS_Lock(&mDNSStorage);
#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)
					dnssd_analytics_post_cache_request_counts();
					dnssd_analytics_post_cache_usage_counts();
#endif	//	CACHE_ANALYTICS
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_INFO, "Analytics Posted");
					mDNS_Unlock(&mDNSStorage);
					KQueueUnlock("Analytics Update");
#endif	//	ANALYTICS
				});
				if (!xpc_activity_set_state(activity, XPC_ACTIVITY_STATE_DONE)) {
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_ERROR, "com.apple.mDNSResponder.analytics.daily: Analytics XPC_ACTIVITY_STATE_DONE failed");
				}
			}
		});
		xpc_release(criteria);
	});
}

#endif // ANALYTICS
