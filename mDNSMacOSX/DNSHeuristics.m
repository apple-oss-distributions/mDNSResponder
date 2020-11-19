/*
* Copyright (c) 2020 Apple Inc. All rights reserved.
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

#import "DNSHeuristicsInternal.h"
#import "DNSHeuristics.h"
#import "mdns_symptoms.h"
#import "mdns_helpers.h"
#import <os/log.h>

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)

MDNS_LOG_CATEGORY_DEFINE(heuristics, "heuristics");

#endif

#define DNS_MIN(A, B) ((A) < (B) ? (A) : (B))

/*
 * Persisted heuristic data model:
 *
 * "DNSFailures": {
 *    "LastFailureTimestamp": <>,
 *    "LongCount": <>,
 *    "BurstCount": <>,
 * },
 * "FilteredNetwork": <>
 */
const NSString *DNSFailureStateKey = @"DNSFailures";
const NSString *DNSHeuristicsLastFailureTimestamp = @"LastFailureTimestamp";
const NSString *DNSHeuristicsLongCounterKey = @"LongCount";
const NSString *DNSHeuristicsBurstCounterKey = @"BurstCount";
const NSString *DNSHeuristicsFilterFlagKey = @"FilteredNetwork";

/*
 * DNS resolution failures are tracked using two counters:
 *
 * 1. A "long" counter, tracking the total number of failures. If the total number of failures exceeds DNSHeuristicDefaultLongCounterThreshold
 *    the network is marked as an active filterer. After a cooldown period of DNSHeuristicDefaultLongCounterTimeWindow seconds
 *    since the last failure the network stops being marked as such and the counter is reset to zero.
 * 2. A "burst" counter, implemented as a token bucket. The token bucket is replenished every two minutes. Each failure
 *    removes a token from the bucket. If there are ever no tokens available, the network is marked as an active filterer.
 */
NSUInteger DNSHeuristicDefaultLongCounterThreshold = 10; // long counter
NSUInteger DNSHeuristicDefaultLongCounterTimeWindow = 24*60*60*1000; // one day
NSUInteger DNSHeuristicsDefaultBurstTokenBucketCapacity = 10; // token bucket
NSUInteger DNSHeuristicsDefaultBurstTokenBucketRefillTime = 2*60*1000; // refill every two minutes
NSUInteger DNSHeuristicsDefaultBurstTokenBucketRefillCount = 1; // put one token back in every epoch
NSUInteger DNSHeuristicsDefaultMultipleTimeoutWindow = 30*1000; // only penalize for one timeout every thirty seconds

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)
#import <Apple80211/Apple80211API.h>
#import <Kernel/IOKit/apple80211/apple80211_var.h>
#import <Kernel/IOKit/apple80211/apple80211_ioctl.h>
#import <MobileWiFi/WiFiTypes.h>
#import <MobileWiFi/WiFiManagerClient.h>
#import <MobileWiFi/WiFiDeviceClient.h>
#import <MobileWiFi/WiFiKeys.h>
#import <MobileWiFi/MobileWiFi.h>

static WiFiManagerClientRef
getNetworkManager(void)
{
    static WiFiManagerClientRef manager = NULL;
    if (manager == NULL) {
        manager = WiFiManagerClientCreate(kCFAllocatorDefault, kWiFiClientTypeNormal);
    }
    return manager;
}

static WiFiNetworkRef
copyCurrentWiFiNetwork(WiFiManagerClientRef manager)
{
    if (manager == NULL) {
        return NULL;
    }

    NSArray *interfaces = (__bridge_transfer NSArray *)WiFiManagerClientCopyInterfaces(manager);

    for (id interface in interfaces) {
        if (WiFiDeviceClientGetInterfaceRoleIndex((__bridge WiFiDeviceClientRef)interface) == WIFI_MANAGER_MAIN_INTERFACE_ROLE) {
            WiFiDeviceClientRef device = (__bridge WiFiDeviceClientRef)interface;
            WiFiNetworkRef network = WiFiDeviceClientCopyCurrentNetwork(device);
            if (network != NULL) {
                return network;
            }
        }
    }

    return WiFiManagerClientCopyCurrentSessionBasedNetwork(manager);
}

#endif /* TARGET_OS_IPHONE */

static dispatch_queue_t
copyHeuristicsQueue(void)
{
    static dispatch_queue_t queue = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("DNSHeuristicsQueue", NULL);
    });
    return queue;
}

@implementation DNSHeuristics

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)

+ (NSDictionary *)copyNetworkSettings:(WiFiNetworkRef)network NS_RETURNS_RETAINED
{
    if (network == NULL) {
        return nil;
    }

    NSDictionary *networkFailures = (__bridge NSDictionary *)WiFiNetworkGetProperty(network, (__bridge CFStringRef)DNSFailureStateKey);
    return [networkFailures copy];
}

+ (BOOL)setNetworkSettings:(WiFiManagerClientRef)manager
                   network:(WiFiNetworkRef)network
                     value:(NSDictionary *)value
{

    if (manager == NULL || network == NULL) {
        return NO;
    }

    return (BOOL)WiFiManagerClientSetNetworkProperty(manager, network, (__bridge CFStringRef)DNSFailureStateKey, (__bridge CFDictionaryRef)value);
}

+ (BOOL)getNetworkFilteredFlag:(WiFiNetworkRef)network
{
    if (network == NULL) {
        return NO;
    }
    CFBooleanRef value = WiFiNetworkGetProperty(network, (__bridge CFStringRef)DNSHeuristicsFilterFlagKey);
    return value == kCFBooleanTrue ? YES : NO;
}

+ (BOOL)setNetworkAsFiltered:(WiFiManagerClientRef)manager
                     network:(WiFiNetworkRef)network
{
    if (manager == NULL || network == NULL) {
        return NO;
    }
    return (BOOL)WiFiManagerClientSetNetworkProperty(manager, network, (__bridge CFStringRef)DNSHeuristicsFilterFlagKey, kCFBooleanTrue);
}

+ (BOOL)clearNetworkAsFiltered:(WiFiManagerClientRef)manager
                       network:(WiFiNetworkRef)network
{
    if (manager == NULL || network == NULL) {
        return NO;
    }
    return (BOOL)WiFiManagerClientSetNetworkProperty(manager, network, (__bridge CFStringRef)DNSHeuristicsFilterFlagKey, kCFBooleanFalse);
}

+ (BOOL)setNetworkAsFiltered:(WiFiManagerClientRef)manager
                     network:(WiFiNetworkRef)network
                    filtered:(BOOL)filtered
{
    if (filtered) {
        return [DNSHeuristics setNetworkAsFiltered:manager network:network];
    } else {
        return [DNSHeuristics clearNetworkAsFiltered:manager network:network];
    }
}

#endif // #if TARGET_OS_IPHONE

+ (BOOL)countersExceedThreshold:(NSUInteger)dailyCounter
                   burstCounter:(NSUInteger)burstCounter
{
    return (dailyCounter > DNSHeuristicDefaultLongCounterThreshold || burstCounter == 0);
}

+ (NSUInteger)currentTimeMs
{
    return (NSUInteger)([[NSDate date] timeIntervalSince1970] * 1000);
}

+ (NSDictionary *)copyEmptyHeuristicState NS_RETURNS_RETAINED
{
    return @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:0],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithUnsignedInteger:0],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
    };
}

+ (BOOL)updateHeuristicState:(BOOL)resolutionSuccess
				   isTimeout:(BOOL)isTimeout
{
    BOOL result = YES;

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)

    WiFiManagerClientRef manager = getNetworkManager();
    WiFiNetworkRef network = copyCurrentWiFiNetwork(manager);
    NSDictionary *heuristicState = [DNSHeuristics copyNetworkSettings:network];
    if (!heuristicState) {
        heuristicState = @{}; // Empty dictionary to start
    }
    if (![heuristicState objectForKey:DNSHeuristicsLastFailureTimestamp]) {
        heuristicState = [DNSHeuristics copyEmptyHeuristicState];
    }

    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSUInteger lastFailureTimestamp = [(NSNumber *)heuristicState[DNSHeuristicsLastFailureTimestamp] unsignedIntegerValue];
    NSUInteger longCounter = [(NSNumber *)heuristicState[DNSHeuristicsLongCounterKey] unsignedIntegerValue];
    NSUInteger burstCounter = [(NSNumber *)heuristicState[DNSHeuristicsBurstCounterKey] unsignedIntegerValue];
    BOOL filteredFlag = [DNSHeuristics getNetworkFilteredFlag:network];

    if (resolutionSuccess) {
        // Check to see if the network can be forgiven, i.e., if we've gone over a day since the last failure.
		if (filteredFlag) {
			if (lastFailureTimestamp + DNSHeuristicDefaultLongCounterTimeWindow < now) {
				const uint64_t delta = (now - lastFailureTimestamp);
				os_log(_mdns_heuristics_log(), "Logging DoH success after %llums, clearing filtered state", delta);
				result &= [DNSHeuristics setNetworkSettings:manager network:network value:[DNSHeuristics copyEmptyHeuristicState]];
				result &= [DNSHeuristics setNetworkAsFiltered:manager network:network filtered:NO];
			} else if (lastFailureTimestamp < now) {
				const uint64_t delta = (now - lastFailureTimestamp);
				os_log_info(_mdns_heuristics_log(), "Logging DoH success after %llums, keeping filtered state", delta);
			} else {
				os_log(_mdns_heuristics_log(), "Logging DoH success, invalid last failure, clearing filtered state");
				result &= [DNSHeuristics setNetworkSettings:manager network:network value:[DNSHeuristics copyEmptyHeuristicState]];
				result &= [DNSHeuristics setNetworkAsFiltered:manager network:network filtered:NO];
			}
		}
    } else if (isTimeout && lastFailureTimestamp < now &&
			   lastFailureTimestamp + DNSHeuristicsDefaultMultipleTimeoutWindow > now) {
		const uint64_t delta = (now - lastFailureTimestamp);
		os_log_info(_mdns_heuristics_log(), "Logging DoH timeout failure after only %llums, not incrementing failure counter", delta);
	} else {
        // The long counter always increases upon each failure.
        NSUInteger newLongCounter = (longCounter + 1);

        // Replenish the burst token bucket, and then compute the new bucket value.
        NSUInteger refillCount = (now - lastFailureTimestamp) / DNSHeuristicsDefaultBurstTokenBucketRefillTime;
        NSUInteger refillAmount = refillCount * DNSHeuristicsDefaultBurstTokenBucketRefillCount;
        NSUInteger refilledBucketValue = DNS_MIN(DNSHeuristicsDefaultBurstTokenBucketCapacity, burstCounter + refillAmount);
        NSUInteger newBucketValue = (refilledBucketValue > 0) ? (refilledBucketValue - 1) : 0;

        BOOL newFilteredFlag = filteredFlag || [DNSHeuristics countersExceedThreshold:newLongCounter burstCounter:newBucketValue];

		if (!filteredFlag && newFilteredFlag) {
			os_log(_mdns_heuristics_log(), "Logging DoH %sfailure %llu (bucket %llu), moving into filtered state",
				   isTimeout ? "timeout " : "", (uint64_t)newLongCounter, (uint64_t)newBucketValue);
		} else if (filteredFlag) {
			os_log_info(_mdns_heuristics_log(), "Logging DoH %sfailure %llu (bucket %llu), keeping filtered state",
						isTimeout ? "timeout " : "", (uint64_t)newLongCounter, (uint64_t)newBucketValue);
		} else {
			os_log_info(_mdns_heuristics_log(), "Logging DoH %sfailure %llu (bucket %llu), keeping unfiltered state",
						isTimeout ? "timeout " : "", (uint64_t)newLongCounter, (uint64_t)newBucketValue);
		}

        NSDictionary *newState = @{
            DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
            DNSHeuristicsLongCounterKey: [NSNumber numberWithUnsignedInteger:newLongCounter],
            DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:newBucketValue],
        };

        result &= [DNSHeuristics setNetworkSettings:manager network:network value:newState];
        result &= [DNSHeuristics setNetworkAsFiltered:manager network:network filtered:newFilteredFlag];
    }

    if (network) {
        CFRelease(network);
    }

#endif

    return result;
}

+ (BOOL)reportResolutionFailure:(NSURL *)url
					  isTimeout:(BOOL)isTimeout
{
#ifndef DNS_XCTEST // Skip this symptoms report in the XCTests
    NSString *urlHostname = [url host];
    const char *hostname = urlHostname ? [urlHostname UTF8String] : "";
    mdns_symptoms_report_encrypted_dns_connection_failure(hostname);
#endif // DNS_XCTEST

	return [DNSHeuristics updateHeuristicState:NO isTimeout:isTimeout];
}

@end

void
dns_heuristics_report_resolution_failure(NSURL *url, bool is_timeout)
{
    dispatch_async(copyHeuristicsQueue(), ^{
        [DNSHeuristics reportResolutionFailure:url isTimeout:!!is_timeout];
    });
}

void
dns_heuristics_report_resolution_success(void)
{
    dispatch_async(copyHeuristicsQueue(), ^{
		[DNSHeuristics updateHeuristicState:YES isTimeout:NO];
    });
}
