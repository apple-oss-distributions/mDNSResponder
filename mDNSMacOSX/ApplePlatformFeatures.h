/*
 * Copyright (c) 2018-2023 Apple Inc. All rights reserved.
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

#ifndef __ApplePlatformFeatures_h
#define __ApplePlatformFeatures_h

#include <TargetConditionals.h>

// Feature: Add audit token to questions
// Radar:   <rdar://problem/59042213>
// Enabled: On all Apple platforms

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_AUDIT_TOKEN)
    #define MDNSRESPONDER_SUPPORTS_APPLE_AUDIT_TOKEN                1
#endif

// Feature: Supports AWDL.
// Radar:   <rdar://problem/110094554>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_AWDL)
    #define MDNSRESPONDER_SUPPORTS_APPLE_AWDL                       1
#endif

// Feature: When flushing mDNS cache records received via AWDL, flush them immediately.
// Radar:   <rdar://problem/91523757>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_AWDL_FAST_CACHE_FLUSH)
    #define MDNSRESPONDER_SUPPORTS_APPLE_AWDL_FAST_CACHE_FLUSH      1
#endif

// Feature: Bonjour-On-Demand
// Radar:   <rdar://problem/23523784>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_BONJOUR_ON_DEMAND)
    #define MDNSRESPONDER_SUPPORTS_APPLE_BONJOUR_ON_DEMAND          1
#endif

// Feature: Support for Analytics For Cache
// Radar:   <rdar://problem/52206048>
// Enabled: iOS & macOS

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_CACHE_ANALYTICS)
    #if !(defined(TARGET_OS_IOS) && defined(TARGET_OS_OSX))
        #error "Expected TARGET_OS_IOS && TARGET_OS_OSX to be defined."
    #endif
    #if (TARGET_OS_IOS || TARGET_OS_OSX)
        #define MDNSRESPONDER_SUPPORTS_APPLE_CACHE_ANALYTICS        1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_CACHE_ANALYTICS        0
    #endif
#endif

// Feature: Cache memory limit
// Radar:   <rdar://problem/15629764>
// Enabled: Yes, but only for device OSes, such as iOS, tvOS, and watchOS, i.e., when TARGET_OS_IPHONE is 1.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_CACHE_MEM_LIMIT)
    #if !defined(TARGET_OS_IPHONE)
        #error "Expected TARGET_OS_IPHONE to be defined."
    #endif
    #if TARGET_OS_IPHONE
        #define MDNSRESPONDER_SUPPORTS_APPLE_CACHE_MEM_LIMIT        1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_CACHE_MEM_LIMIT        0
    #endif
#endif

// Feature: D2D
// Radar:   <rdar://problem/28062515>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_D2D)
    #define MDNSRESPONDER_SUPPORTS_APPLE_D2D                        1
#endif

// Feature: Support for DNS Analytics
// Radar:   <rdar://problem/57972792>, <rdar://problem/57970914>
// Enabled: iOS & macOS

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNS_ANALYTICS)
    #if !(defined(TARGET_OS_IOS) && defined(TARGET_OS_OSX))
        #error "Expected TARGET_OS_IOS && TARGET_OS_OSX to be defined."
    #endif
    #if (TARGET_OS_IOS || TARGET_OS_OSX)
        #define MDNSRESPONDER_SUPPORTS_APPLE_DNS_ANALYTICS          1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_DNS_ANALYTICS          0
    #endif
#endif

// Feature: DNS64 support for DNS proxy
// Radar:   <rdar://problem/56505415>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNS_PROXY_DNS64)
    #define MDNSRESPONDER_SUPPORTS_APPLE_DNS_PROXY_DNS64            1
#endif

// Feature: DNS push support for Apple platforms
// Radar:   <rdar://97679910>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNS_PUSH)
    #define MDNSRESPONDER_SUPPORTS_APPLE_DNS_PUSH                   1
#endif

// Feature: DNS64 IPv6 synthesis.
// Radar:   <rdar://problem/32297396>
// Enabled: Yes, but only for iOS and macOS, which support the DNS proxy network extension.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNS64)
    #if (!defined(TARGET_OS_IOS) || !defined(TARGET_OS_OSX))
        #error "Expected TARGET_OS_IOS and TARGET_OS_OSX to be defined."
    #endif
    #if (TARGET_OS_IOS || TARGET_OS_OSX)
        #define MDNSRESPONDER_SUPPORTS_APPLE_DNS64                  1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_DNS64                  0
    #endif
#endif

// Feature: DNS-SD XPC service
// Radar:   <rdar://problem/43866363>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNSSD_XPC_SERVICE)
    #define MDNSRESPONDER_SUPPORTS_APPLE_DNSSD_XPC_SERVICE          1
#endif

// Feature: DNSSEC support
// Radar:   <rdar://problem/55275552>
// Enabled: On all Apple platforms

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_DNSSECv2)
    #define MDNSRESPONDER_SUPPORTS_APPLE_DNSSECv2                   1
#endif

// Feature: Ignore /etc/hosts file on customer builds.
// Radar:   <rdar://problem/34745220>
// Enabled: Yes, except for macOS.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_IGNORE_HOSTS_FILE)
    #if !defined(TARGET_OS_OSX)
        #error "Expected TARGET_OS_OSX to be defined."
    #endif
    #if !TARGET_OS_OSX
        #define MDNSRESPONDER_SUPPORTS_APPLE_IGNORE_HOSTS_FILE      1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_IGNORE_HOSTS_FILE      0
    #endif
#endif

// Feature: Change privacy level of logs and state dump on the internal build.
// Radar:   <rdar://79636882>
// Enabled: On all internal Apple platforms.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_LOG_PRIVACY_LEVEL)
    #define MDNSRESPONDER_SUPPORTS_APPLE_LOG_PRIVACY_LEVEL          1
#endif

// Feature: Exclude interface ap1 from in-NIC sleep proxy offloading.
// Radar:   <rdar://109145606>
// Enabled: On all Apple platforms

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_NO_NETWAKE_FOR_AP1)
    #define MDNSRESPONDER_SUPPORTS_APPLE_NO_NETWAKE_FOR_AP1         1
#endif

// Feature: No system wake for network access.
// Radar:   <rdar://problem/28079659&55038229>
// Enabled: Yes, but only for iOS and watchOS, which shouldn't act as sleep-proxy clients.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_NO_WAKE_FOR_NET_ACCESS)
    #if (!defined(TARGET_OS_IOS) || !defined(TARGET_OS_WATCH))
        #error "Expected TARGET_OS_IOS and TARGET_OS_WATCH to be defined."
    #endif
    #if (TARGET_OS_IOS || TARGET_OS_WATCH)
        #define MDNSRESPONDER_SUPPORTS_APPLE_NO_WAKE_FOR_NET_ACCESS 1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_NO_WAKE_FOR_NET_ACCESS 0
    #endif
#endif

// Feature: Support for having finer granularity of log redaction, by using os_log based-log routine.
// Radar:   <rdar://problem/42814956>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_OS_LOG)
    #define MDNSRESPONDER_SUPPORTS_APPLE_OS_LOG                     1
#endif

// Radar:   <rdar://82445644>
// Enabled: On all Apple platforms.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_OS_UNFAIR_LOCK)
    #define MDNSRESPONDER_SUPPORTS_APPLE_OS_UNFAIR_LOCK             1
#endif

// Feature: Struct Padding Checks
// Radar:   <rdar://108600998&108931243>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_PADDING_CHECKS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_PADDING_CHECKS             1
#endif

// Feature: Powerlog mDNS client requests.
// Radar:   <rdar://112118989>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_POWERLOG_MDNS_REQUESTS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_POWERLOG_MDNS_REQUESTS     1
#endif

// Feature: Use mdns_querier objects for DNS transports.
// Radar:   <rdar://problem/55746371>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_QUERIER)
    #define MDNSRESPONDER_SUPPORTS_APPLE_QUERIER                    1
#endif

// Feature: Randomized AWDL Hostname
// Radar:   <rdar://problem/47525004>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_RANDOM_AWDL_HOSTNAME)
    #define MDNSRESPONDER_SUPPORTS_APPLE_RANDOM_AWDL_HOSTNAME       1
#endif

// Feature: Reachability trigger
// Radar:   <rdar://problem/11374446>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_REACHABILITY_TRIGGER)
    #define MDNSRESPONDER_SUPPORTS_APPLE_REACHABILITY_TRIGGER       1
#endif

// Feature: Collect mDNS metrics to gauge multicast quality on attached networks.
// Radar:   <rdar://108578861>
// Enabled: Yes

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_RUNTIME_MDNS_METRICS)
    #if !(defined(TARGET_OS_IOS) && defined(TARGET_OS_OSX) && defined(TARGET_OS_TV))
        #error "Expected TARGET_OS_IOS && TARGET_OS_OSX && TARGET_OS_TV to be defined."
    #endif
    #if (TARGET_OS_IOS || TARGET_OS_OSX || TARGET_OS_TV)
        #define MDNSRESPONDER_SUPPORTS_APPLE_RUNTIME_MDNS_METRICS   1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_RUNTIME_MDNS_METRICS   0
    #endif
#endif

// Feature: Support more secure TSIG HMAC algorithms.
// Radar:   <rdar://86257052>
// Enabled: All (but TSIG update feature that uses TSIG is only available on macOS)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_SECURE_HMAC_ALGORITHM_2022)
    #define MDNSRESPONDER_SUPPORTS_APPLE_SECURE_HMAC_ALGORITHM_2022 1
#endif

// Feature: Support validated/signed requests
// Radar:   <rdar://83999760>
// Enabled: All (depends on MDNSRESPONDER_SUPPORTS_APPLE_IPC_TLV)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_SIGNED_RESULTS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_SIGNED_RESULTS             1
#endif

// Feature: "SlowActivation" processing for flapping interfaces.
//          Disabled to address stale Bonjour record issues during flapping network interface transitions.
// Radar:   <rdar://problem/44694746>
// Enabled: No.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_SLOW_ACTIVATION)
    #define MDNSRESPONDER_SUPPORTS_APPLE_SLOW_ACTIVATION            0
#endif

// Feature: Symptoms Reporting
// Radar:   <rdar://problem/20194922>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_SYMPTOMS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_SYMPTOMS                   1
#endif

// Feature: Tracker Debugging
// Radar:   <rdar://problem/102778582>
// Enabled: Yes. (depends on MDNSRESPONDER_SUPPORTS_APPLE_TRACKER_STATE)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_TRACKER_DEBUGGING)
    #define MDNSRESPONDER_SUPPORTS_APPLE_TRACKER_DEBUGGING          1
#endif

// Feature: Tracker Reporting
// Radar:   <rdar://problem/70222299>, <rdar://problem/74789124>
// Enabled: Yes. (depends on MDNSRESPONDER_SUPPORTS_APPLE_AUDIT_TOKEN)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_TRACKER_STATE)
    #define MDNSRESPONDER_SUPPORTS_APPLE_TRACKER_STATE              1
#endif

// Feature: TLV support DNS-SD API's Unix domain socket IPC.
// Radar:   <rdar://problem/59295752>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_IPC_TLV)
    #define MDNSRESPONDER_SUPPORTS_APPLE_IPC_TLV                    1
#endif

// Feature: Enforce entitlements prompts
// Radar:   <rdar://problem/55922132>
// Enabled: iOS only (depends on MDNSRESPONDER_SUPPORTS_APPLE_AUDIT_TOKEN)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_TRUST_ENFORCEMENT)
    #if (TARGET_OS_IOS)
        #define MDNSRESPONDER_SUPPORTS_APPLE_TRUST_ENFORCEMENT      1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_TRUST_ENFORCEMENT      0
    #endif
#endif

// Feature: Unicast assist
// Radar:   <rdar://problem/100207072>
// Enabled: All

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_ASSIST)
    #define MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_ASSIST             1
#endif

// Feature: Unicast assist analytics
// Radar:   <rdar://problem/103121312>
// Enabled: All

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_ASSIST_ANALYTICS)
   #define MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_ASSIST_ANALYTICS    1
#endif

// Feature: Unicast device discovery
// Radar:   <rdar://problem/98406195>
// Enabled: iOS only (with dependencies)

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_DISCOVERY)
    #if (TARGET_OS_IOS)
        #define MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_DISCOVERY      1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_DISCOVERY      0
    #endif
#endif

// Feature: Support for performing dot-local queries via mDNS and DNS in parallel.
// Radar:   <rdar://problem/4786302>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_DOTLOCAL)
    #define MDNSRESPONDER_SUPPORTS_APPLE_UNICAST_DOTLOCAL           1
#endif

// Feature: Allow browses and registrations over interfaces that aren't ready yet.
// Radar:   <rdar://problem/20181903>
// Enabled: Yes.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_UNREADY_INTERFACES)
    #define MDNSRESPONDER_SUPPORTS_APPLE_UNREADY_INTERFACES         1
#endif


// Feature: Support for Analytics For WAB (Wide Area Bonjour)
// Radar:   <rdar://problem/52136688>
// Enabled: iOS & macOS

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_WAB_ANALYTICS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_WAB_ANALYTICS              0
#endif
// Feature: Support for Web Content Filter
// Radar:   <rdar://problem/7409981>
// Enabled: Yes, if SDK has <WebFilterDNS/WebFilterDNS.h>.

#if !defined(MDNSRESPONDER_SUPPORTS_APPLE_WEB_CONTENT_FILTER)
    #if __has_include(<WebFilterDNS/WebFilterDNS.h>)
        #define MDNSRESPONDER_SUPPORTS_APPLE_WEB_CONTENT_FILTER     1
    #else
        #define MDNSRESPONDER_SUPPORTS_APPLE_WEB_CONTENT_FILTER     0
    #endif
#endif

// Feature Groups
// These are pseudo-features that represent the logical OR of multiple similar features for convenience.

#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS) || \
    MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS)   || \
    MDNSRESPONDER_SUPPORTS(APPLE, WAB_ANALYTICS)   || \
    MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS)
    #define MDNSRESPONDER_SUPPORTS_APPLE_ANALYTICS                  1
#else
    #define MDNSRESPONDER_SUPPORTS_APPLE_ANALYTICS                  0
#endif

// Feature Dependency Checks

// MDNSRESPONDER_SUPPORTS(APPLE, QUERIER) should always be true if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
// is true, except for only one case, the Tests target that runs XCTest. In the XCTest,
// MDNSRESPONDER_SUPPORTS_APPLE_DNSSECv2 is predefined in the preprocess which does not check what
// MDNSRESPONDER_SUPPORTS checks. In order to test DNSSEC functions in XCtest without querier support, we
// will wrap all DNSSEC code that calls querier, since the code will never be executed in XCTest.

#if !defined(MDNSRESPONDER_DISABLE_DNSSECv2_DEPENDENCY_CHECK_FOR_QUERIER)
    #define MDNSRESPONDER_DISABLE_DNSSECv2_DEPENDENCY_CHECK_FOR_QUERIER  0
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, AWDL_FAST_CACHE_FLUSH)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AWDL)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, AWDL_FAST_CACHE_FLUSH) depends on MDNSRESPONDER_SUPPORTS(APPLE, AWDL)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER) && !MDNSRESPONDER_DISABLE_DNSSECv2_DEPENDENCY_CHECK_FOR_QUERIER
        #error "MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2) depends on MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AWDL)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS) depends on MDNSRESPONDER_SUPPORTS(APPLE, AWDL)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AWDL)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME) depends on MDNSRESPONDER_SUPPORTS(APPLE, AWDL)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS) depends on MDNSRESPONDER_SUPPORTS(APPLE, IPC_TLV)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_DEBUGGING)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_DEBUGGING) depends on MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)."
    #endif
    #if !MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_DEBUGGING) depends on MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE) depends on MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT) depends on MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST_ANALYTICS) depends on MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_ASSIST)."
    #endif
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY)
    #if !MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DOTLOCAL)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY) depends on MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DOTLOCAL)."
    #endif
    #if !MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY) depends on MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)."
    #endif
    #if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        #error "MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DISCOVERY) depends on MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)."
    #endif
#endif

#endif  // __ApplePlatformFeatures_h
