/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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

#include "dnssd_analytics.h"
#include "mDNSMacOSX.h"
#include "uds_daemon.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)

#include <xpc/xpc.h>
#include <CoreAnalytics/CoreAnalytics.h>
#include <CoreUtils/DebugServices.h>
#include "mdns_strict.h"

#endif // ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)

// MARK:  - Private Types

enum : uint8_t {
	e_index_standard_noncell		= 0,
	e_index_standard_cell,
	e_index_encrypted_noncell,
	e_index_encrypted_cell,
	e_index_count,
	e_index_invalid = -1
};

typedef struct {
	uint64_t			queries;
	uint64_t			reply_pos;
	uint64_t			reply_neg;
} qtype_count_t;

typedef struct {
	uint64_t			latency_count;		// For calulating average
	uint64_t			latency_total;		// For calulating average
	uint64_t			query_bytes;
	uint64_t			reply_bytes;
	qtype_count_t 		v4;
	qtype_count_t 		v6;
	qtype_count_t 		https;
} dns_analytic_t;
static dns_analytic_t s_dns_analytics[e_index_count] = {};

// MARK:  - Private Functions

static inline const char *
_index_to_transport_string(uint8_t index)
{
	switch (index) {
		case e_index_standard_noncell:
		case e_index_standard_cell:
			return "standard";
		case e_index_encrypted_noncell:
		case e_index_encrypted_cell:
			return "encrypted";
	}
	return NULL;
}

static inline const char *
_index_to_network_string(uint8_t index)
{
	switch (index) {
		case e_index_standard_noncell:
		case e_index_encrypted_noncell:
			return "non-cell";
		case e_index_standard_cell:
		case e_index_encrypted_cell:
			return "cellular";
	}
	return NULL;
}

static void
_post_dns_analytic(dns_analytic_t * const _Nonnull analytic, const char * _Nonnull network, const char * _Nonnull transport)
{
	bool                        posted;
	posted = analytics_send_event_lazy("com.apple.mDNSResponder.dnsqueryinfo", ^{
		xpc_object_t        dict;
		dict = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_string(dict, "network",  		network);
		xpc_dictionary_set_string(dict, "transport",   		transport);
		xpc_dictionary_set_uint64(dict, "latency_ms", 		analytic->latency_total / analytic->latency_count);
		xpc_dictionary_set_uint64(dict, "query_bytes", 		analytic->query_bytes);
		xpc_dictionary_set_uint64(dict, "reply_bytes", 		analytic->reply_bytes);
		xpc_dictionary_set_uint64(dict, "v4_queries", 		analytic->v4.queries);
		xpc_dictionary_set_uint64(dict, "v4_reply_pos", 	analytic->v4.reply_pos);
		xpc_dictionary_set_uint64(dict, "v4_reply_neg",		analytic->v4.reply_neg);
		xpc_dictionary_set_uint64(dict, "v6_queries", 		analytic->v6.queries);
		xpc_dictionary_set_uint64(dict, "v6_reply_pos", 	analytic->v6.reply_pos);
		xpc_dictionary_set_uint64(dict, "v6_reply_neg",		analytic->v6.reply_neg);
		xpc_dictionary_set_uint64(dict, "https_queries",	analytic->https.queries);
		xpc_dictionary_set_uint64(dict, "https_reply_pos", 	analytic->https.reply_pos);
		xpc_dictionary_set_uint64(dict, "https_reply_neg",	analytic->https.reply_neg);
		return (dict);
	});
	if (!posted) {
		LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.dnsqueryinfo: Analytic not posted");
	}
}

static void
_post_dns_query_info(void)
{
	for (uint8_t i = 0 ; i < e_index_count ; i++ ) {
		if (s_dns_analytics[i].latency_count > 0) {
			_post_dns_analytic(&s_dns_analytics[i], _index_to_network_string(i), _index_to_transport_string(i));
		}
	}
	memset(&s_dns_analytics, 0, sizeof(s_dns_analytics));
}

static qtype_count_t*
_qtype_count_for_analytic(dns_analytic_t * const _Nonnull analytic, uint16_t qtype)
{
	qtype_count_t *qtype_ptr = NULL;
	switch (qtype) {
		case kDNSType_A:
			qtype_ptr = &analytic->v4;
			break;

		case kDNSType_AAAA:
			qtype_ptr = &analytic->v6;
			break;
			
		case kDNSType_HTTPS:
			qtype_ptr = &analytic->https;
			break;
	}
	return qtype_ptr;
}

static dns_analytic_t*
_analytic_for_event(bool is_cellular, dns_transport_t transport)
{
	dns_analytic_t *analytic = NULL;
	uint8_t			index = e_index_invalid;
	require_quiet(transport != dns_transport_Undefined, exit);

	if (is_cellular) {
		if (transport == dns_transport_Do53) {
			index = e_index_standard_cell;
		} else {
			index = e_index_encrypted_cell;
		}
	} else {
		if (transport == dns_transport_Do53) {
			index = e_index_standard_noncell;
		} else {
			index = e_index_encrypted_noncell;
		}
	}
	require_quiet(index != e_index_invalid && index < e_index_count, exit);
	analytic = &s_dns_analytics[index];
exit:
	return analytic;
}

// MARK:  - Public Functions

void
dnssd_analytics_update_dns_query_info(bool is_cellular, dns_transport_t transport, uint16_t qtype, uint32_t num_queries,
	uint32_t latency_ms, bool is_positive_answer)
{
	require_quiet(num_queries > 0, exit);

	dns_analytic_t *analytic = _analytic_for_event(is_cellular, transport);
	require_quiet(analytic, exit);

	qtype_count_t *qtype_count = _qtype_count_for_analytic(analytic, qtype);
	require_quiet(qtype_count, exit);

	analytic->latency_count++;
	analytic->latency_total += latency_ms;

	qtype_count->queries += num_queries;
	if (is_positive_answer) {
		qtype_count->reply_pos++;
	} else {
		qtype_count->reply_neg++;
	}

	LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_DEBUG, "dnssd_analytics_update_dns_query_info cell %d qtype %d queries %u latency %d pos %d",
			  is_cellular, qtype, num_queries, latency_ms, is_positive_answer);
exit:
	return;
}

void
dnssd_analytics_update_dns_query_size(bool is_cellular, dns_transport_t transport, uint32_t send_bytes)
{
	dns_analytic_t *analytic = _analytic_for_event(is_cellular, transport);
	require_quiet(analytic, exit);

	analytic->query_bytes += send_bytes;

exit:
	return;
}

void
dnssd_analytics_update_dns_reply_size(bool is_cellular, dns_transport_t transport, uint32_t recv_bytes)
{
	dns_analytic_t *analytic = _analytic_for_event(is_cellular, transport);
	require_quiet(analytic, exit);

	analytic->reply_bytes += recv_bytes;

exit:
	return;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)

dns_transport_t
dnssd_analytics_dns_transport_for_resolver_type(mdns_resolver_type_t type)
{
	dns_transport_t transport;
	switch (type) {
		case mdns_resolver_type_https:
			transport = dns_transport_DoH;
			break;

		case mdns_resolver_type_tls:
			transport = dns_transport_DoT;
			break;

		case mdns_resolver_type_normal:
		case mdns_resolver_type_tcp:
			transport = dns_transport_Do53;
			break;

		case mdns_resolver_type_null:
			transport = dns_transport_Undefined;
			break;
	}
	return transport;
}

#endif // QUERIER

#endif // DNS_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)

// Local aggregate counters to track request counts

static uint64_t sCacheUsage_UnicastHitCount = 0;
static uint64_t sCacheUsage_UnicastMissCount = 0;
static uint64_t sCacheUsage_MulticastHitCount = 0;
static uint64_t sCacheUsage_MulticastMissCount = 0;

static uint64_t sCacheRequest_UnicastHitCount = 0;
static uint64_t sCacheRequest_UnicastMissCount = 0;
static uint64_t sCacheRequest_MulticastHitCount = 0;
static uint64_t sCacheRequest_MulticastMissCount = 0;

// MARK:  - Private CacheUsage Functions

static void
_post_cache_request_count(CacheRequestType inType, CacheState inState, uint64_t inRequestCount)
{
    bool                        posted;
	posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.request", ^{
		xpc_object_t        dict;
		dict = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_string(dict, "requestType",  inType  == CacheRequestType_multicast    ? "multicast"   : "unicast");
		xpc_dictionary_set_string(dict, "cacheState",   inState == CacheState_hit                ? "hit"         : "miss");
		xpc_dictionary_set_uint64(dict, "requestCount", inRequestCount);
		return (dict);
	});
    if (!posted) {
        LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.request: Analytic not posted");
    }
}

static void
_post_cache_request_counts(void)
{
    if (sCacheRequest_UnicastHitCount > 0) {
		_post_cache_request_count(CacheRequestType_unicast, CacheState_hit, sCacheRequest_UnicastHitCount);
        sCacheRequest_UnicastHitCount = 0;
    }
    if (sCacheRequest_UnicastMissCount > 0) {
		_post_cache_request_count(CacheRequestType_unicast, CacheState_miss, sCacheRequest_UnicastMissCount);
        sCacheRequest_UnicastMissCount = 0;
    }
    if (sCacheRequest_MulticastHitCount > 0) {
		_post_cache_request_count(CacheRequestType_multicast, CacheState_hit, sCacheRequest_MulticastHitCount);
        sCacheRequest_MulticastHitCount = 0;
    }
    if (sCacheRequest_MulticastMissCount > 0) {
		_post_cache_request_count(CacheRequestType_multicast, CacheState_miss, sCacheRequest_MulticastMissCount);
        sCacheRequest_MulticastMissCount = 0;
    }
}

static void
_post_cache_usage_counts_for_type(CacheRequestType inType, uint64_t inHitCount, uint64_t inMissCount)
{
    bool                    posted;
	posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.entries", ^{
		xpc_object_t        dict;
		dict = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_string(dict, "requestType",  inType == CacheRequestType_multicast ? "multicast" : "unicast");
		xpc_dictionary_set_uint64(dict, "hitCount",     inHitCount);
		xpc_dictionary_set_uint64(dict, "missCount",    inMissCount);
		return (dict);
	});
    if (!posted) {
        LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.entries: Analytic not posted");
    }
}

static void
_post_cache_usage_counts(void)
{
	if (sCacheUsage_MulticastHitCount || sCacheUsage_MulticastMissCount) {
		_post_cache_usage_counts_for_type(CacheRequestType_multicast, sCacheUsage_MulticastHitCount, sCacheUsage_MulticastMissCount);
		sCacheUsage_MulticastHitCount = 0;
		sCacheUsage_MulticastMissCount = 0;
	}
	if (sCacheUsage_UnicastHitCount || sCacheUsage_UnicastMissCount) {
		_post_cache_usage_counts_for_type(CacheRequestType_unicast, sCacheUsage_UnicastHitCount, sCacheUsage_UnicastMissCount);
		sCacheUsage_UnicastHitCount = 0;
		sCacheUsage_UnicastMissCount = 0;
	}
}

// MARK:  - Exported CacheUsage Functions

void
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

void
dnssd_analytics_update_cache_usage_counts(uint32_t inHitMulticastCount, uint32_t inMissMulticastCount, uint32_t inHitUnicastCount, uint32_t inMissUnicastCount)
{
	sCacheUsage_MulticastHitCount += inHitMulticastCount;
	sCacheUsage_MulticastMissCount += inMissMulticastCount;
	sCacheUsage_UnicastHitCount += inHitUnicastCount;
	sCacheUsage_UnicastMissCount += inMissUnicastCount;
}

#endif // CACHE_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS)

static uint64_t sUnicastAssist_UnicastCount = 0;
static uint64_t sUnicastAssist_MulticastCount = 0;
static uint64_t sNonUnicastAssist_UnicastCount = 0;
static uint64_t sNonUnicastAssist_MulticastCount = 0;

static void
_post_unicast_assist(void)
{
	bool posted;
	posted = analytics_send_event_lazy("com.apple.mDNSResponder.unicastassist", ^{
		xpc_object_t dict;
		dict = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_uint64(dict, "unicast",			sUnicastAssist_UnicastCount);
		xpc_dictionary_set_uint64(dict, "multicast",		sUnicastAssist_MulticastCount);
		xpc_dictionary_set_uint64(dict, "non_unicast",		sNonUnicastAssist_UnicastCount);
		xpc_dictionary_set_uint64(dict, "non_multicast",	sNonUnicastAssist_MulticastCount);
		return (dict);
	});
	if (!posted) {
		LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.unicastassist: Analytic not posted");
	}
	sUnicastAssist_UnicastCount = 0;
	sUnicastAssist_MulticastCount = 0;
	sNonUnicastAssist_UnicastCount = 0;
	sNonUnicastAssist_MulticastCount = 0;
}

void
dnssd_analytics_update_unicast_assist(bool assist, bool unicast)
{
	if (assist) {
		if (unicast) {
			sUnicastAssist_UnicastCount++;
		} else {
			sUnicastAssist_MulticastCount++;
		}
	} else {
		if (unicast) {
			sNonUnicastAssist_UnicastCount++;
		} else {
			sNonUnicastAssist_MulticastCount++;
		}
	}
	LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_DEBUG,
			  "dnssd_analytics_update_unicast_assist Assist(unicast %s%lld, multicast %s%lld) "
			  "NonAssist(unicast %s%lld, multicast %s%lld)",
			  assist ? unicast ? "*" : "" : "", sUnicastAssist_UnicastCount,
			  assist ? unicast ? "" : "*" : "", sUnicastAssist_MulticastCount,
			  !assist ? unicast ? "*" : "" : "", sNonUnicastAssist_UnicastCount,
			  !assist ? unicast ? "" : "*" : "", sNonUnicastAssist_MulticastCount);
}

#endif // UNICAST_ASSIST_ANALYTICS


#if MDNSRESPONDER_SUPPORTS(APPLE, WAB_ANALYTICS)

#define UNSET_STR	"unset"

// MARK:  - Exported WABUsage Functions

void
dnssd_analytics_post_WAB_usage_event_count(WABUsageKind inKind, WABUsageType inType, WABUsageEvent inEvent, uint64_t inEventCount)
{
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

		posted = analytics_send_event_lazy("com.apple.mDNSResponder.CacheUsage.entries", ^{
			xpc_object_t        dict;
			dict = xpc_dictionary_create(NULL, NULL, 0);
			xpc_dictionary_set_string(dict, "kind",         kind);
			xpc_dictionary_set_string(dict, "type",         type);
			xpc_dictionary_set_string(dict, "event",        event);
			xpc_dictionary_set_uint64(dict, "eventCount",   inEventCount);
			return (dict);
		});
		if (!posted) {
			LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_WARNING, "com.apple.mDNSResponder.CacheUsage.entries: Analytic not posted");
		}
	}
}

#endif // WAB_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
// MARK:  - Exported Analytics Functions

void
dnssd_analytics_init(void)
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
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_DEFAULT, "com.apple.mDNSResponder.analytics.daily: Asked to defer");
				} else {
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_ERROR, "com.apple.mDNSResponder.analytics.daily: Asked to defer but failed to set state");
				}
			} else {
				dispatch_async(sAnalyticsQueue, ^{
#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
					KQueueLock();
					mDNS_Lock(&mDNSStorage);
#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)
					_post_cache_request_counts();
					_post_cache_usage_counts();
#endif	//	CACHE_ANALYTICS
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
					_post_dns_query_info();
#endif	//	DNS_ANALYTICS
#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS)
					_post_unicast_assist();
#endif	//	UNICAST_ASSIST_ANALYTICS
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_DEFAULT, "com.apple.mDNSResponder.analytics.daily Complete");
					mDNS_Unlock(&mDNSStorage);
					KQueueUnlock("Analytics Update");
#endif	//	ANALYTICS
				});
				if (!xpc_activity_set_state(activity, XPC_ACTIVITY_STATE_DONE)) {
					LogRedact(MDNS_LOG_CATEGORY_ANALYTICS, MDNS_LOG_ERROR, "com.apple.mDNSResponder.analytics.daily: Analytics XPC_ACTIVITY_STATE_DONE failed");
				}
			}
		});
		MDNS_DISPOSE_XPC(criteria);
	});
}

void
dnssd_analytics_log(int fd)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)
	LogToFD(fd, "----    DNS Cache Analytics     -----");
	LogToFD(fd, "----    Unicast Requests");
	LogToFD(fd, "Cache Hit: %llu", sCacheRequest_UnicastHitCount);
	LogToFD(fd, "Cache Miss: %llu", sCacheRequest_UnicastMissCount);
	LogToFD(fd, "----    Unicast Usage");
	LogToFD(fd, "Cache Hit: %llu", sCacheUsage_UnicastHitCount);
	LogToFD(fd, "Cache Miss: %llu", sCacheUsage_UnicastMissCount);
	LogToFD(fd, "----    Multicast Requests");
	LogToFD(fd, "Cache Hit: %llu", sCacheRequest_MulticastHitCount);
	LogToFD(fd, "Cache Miss: %llu", sCacheRequest_MulticastMissCount);
	LogToFD(fd, "----    Multicast Usage");
	LogToFD(fd, "Cache Hit: %llu", sCacheUsage_MulticastHitCount);
	LogToFD(fd, "Cache Miss: %llu", sCacheUsage_MulticastMissCount);
#endif // CACHE_ANALYTICS
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)
	LogToFD(fd, "----    DNS Query Analytics     -----");
	for (uint8_t i = 0 ; i < e_index_count ; i++ ) {
		if (s_dns_analytics[i].latency_count > 0) {
			LogToFD(fd, "----    Network:   %s\n        Transport: %s", _index_to_network_string(i), _index_to_transport_string(i));
			LogToFD(fd, "Latency: %llums", s_dns_analytics[i].latency_total / s_dns_analytics[i].latency_count);
			LogToFD(fd, "Query Bytes: %llu", s_dns_analytics[i].query_bytes);
			LogToFD(fd, "Reply Bytes: %llu", s_dns_analytics[i].reply_bytes);
			LogToFD(fd, "----    V4");
			LogToFD(fd, "Queries: %llu", s_dns_analytics[i].v4.queries);
			LogToFD(fd, "Reply Pos: %llu", s_dns_analytics[i].v4.reply_pos);
			LogToFD(fd, "Reply Neg: %llu", s_dns_analytics[i].v4.reply_neg);
			LogToFD(fd, "----    V6");
			LogToFD(fd, "Queries: %llu", s_dns_analytics[i].v6.queries);
			LogToFD(fd, "Reply Pos: %llu", s_dns_analytics[i].v6.reply_pos);
			LogToFD(fd, "Reply Neg: %llu", s_dns_analytics[i].v6.reply_neg);
			LogToFD(fd, "----    HTTPS");
			LogToFD(fd, "Queries: %llu", s_dns_analytics[i].https.queries);
			LogToFD(fd, "Reply Pos: %llu", s_dns_analytics[i].https.reply_pos);
			LogToFD(fd, "Reply Neg: %llu", s_dns_analytics[i].https.reply_neg);
		}
	}
#endif // DNS_ANALYTICS
#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS)
	LogToFD(fd, "----    Unicast Assist");
	LogToFD(fd, "Assist Unicast: %llu", sUnicastAssist_UnicastCount);
	LogToFD(fd, "Assist Multicast: %llu", sUnicastAssist_MulticastCount);
	LogToFD(fd, "Non-assist Unicast: %llu", sNonUnicastAssist_UnicastCount);
	LogToFD(fd, "Non-assist Multicast: %llu", sNonUnicastAssist_MulticastCount);
#endif // UNICAST_ASSIST_ANALYTICS
}

#endif // ANALYTICS
