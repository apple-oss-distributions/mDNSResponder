/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef __DNSSD_ANALYTICS_H__
#define __DNSSD_ANALYTICS_H__

#include "DNSCommon.h"

#ifdef  __cplusplus
extern "C" {
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)

extern void
dnssd_analytics_init(void);

#endif // ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)

typedef enum {
    CacheRequestType_multicast,
    CacheRequestType_unicast
} CacheRequestType;

typedef enum {
    CacheState_hit,
    CacheState_miss
} CacheState;

extern void
dnssd_analytics_update_cache_request(CacheRequestType inType, CacheState inState);

extern void
dnssd_analytics_update_cache_usage_counts(uint32_t inHitMulticastCount, uint32_t inMissMulticastCount, uint32_t inHitUnicastCount, uint32_t inMissUnicastCount);

#endif // CACHE_ANALYTICS

#if MDNSRESPONDER_SUPPORTS(APPLE, WAB_ANALYTICS)

typedef enum {
    WABUsageKind_results,
    WABUsageKind_session,
    WABUsageKind_operation
} WABUsageKind;

typedef enum {
    WABUsageType_enumeration,
    WABUsageType_query,
    WABUsageType_push,
    WABUsageType_llq
} WABUsageType;

typedef enum {
    // Kind: results
    // Type: enumeration, query, llq
    WABUsageEvent_positive,
    WABUsageEvent_negative,
    WABUsageEvent_null,
    WABUsageEvent_error,

    // Kind: session
    // Type: push, llq
    WABUsageEvent_connected,
    WABUsageEvent_session,
    WABUsageEvent_reset,
    WABUsageEvent_idledOut,
    WABUsageEvent_goAway,
    WABUsageEvent_resumedGood,
    WABUsageEvent_resumedBad,

    // Kind: operation
    // Type: push, llq
    WABUsageEvent_succeeded,
    WABUsageEvent_rejected,
    WABUsageEvent_dsoni,
    WABUsageEvent_answered
} WABUsageEvent;

extern void
dnssd_analytics_post_WAB_usage_event_count(WABUsageKind inKind, WABUsageType inType, WABUsageEvent inEvent, uint64_t inEventCount);

#endif // WAB_ANALYTICS

#ifdef  __cplusplus
}
#endif

#endif // __DNSSD_ANALYTICS_H__
