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

#ifndef __DNSHeuristicsInternal_h
#define __DNSHeuristicsInternal_h

#import "DNSHeuristics.h"
#import <Foundation/Foundation.h>

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)
#import <MobileWiFi/WiFiTypes.h>
#import <MobileWiFi/WiFiManagerClient.h>
#import <MobileWiFi/WiFiDeviceClient.h>
#import <MobileWiFi/WiFiKeys.h>
#import <MobileWiFi/MobileWiFi.h>
#endif // TARGET_OS_IPHONE

extern const NSString *DNSFailureStateKey;
extern const NSString *DNSHeuristicsLastFailureTimestamp;
extern const NSString *DNSHeuristicsFilterFlagKey;
extern const NSString *DNSHeuristicsLongCounterKey;
extern const NSString *DNSHeuristicsBurstCounterKey;

extern NSUInteger DNSHeuristicDefaultLongCounterThreshold;
extern NSUInteger DNSHeuristicDefaultLongCounterTimeWindow;
extern NSUInteger DNSHeuristicsDefaultBurstTokenBucketCapacity;
extern NSUInteger DNSHeuristicsDefaultBurstTokenBucketRefillTime;
extern NSUInteger DNSHeuristicsDefaultBurstTokenBucketRefillCount;

@interface DNSHeuristics : NSObject
#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST)
+ (BOOL)getNetworkFilteredFlag:(WiFiNetworkRef)network;
+ (NSDictionary *)copyNetworkSettings:(WiFiNetworkRef)network NS_RETURNS_RETAINED;
+ (BOOL)setNetworkSettings:(WiFiManagerClientRef)manager
                   network:(WiFiNetworkRef)network
                     value:(NSDictionary *)value;
+ (BOOL)setNetworkAsFiltered:(WiFiManagerClientRef)manager
                     network:(WiFiNetworkRef)network;
+ (BOOL)clearNetworkAsFiltered:(WiFiManagerClientRef)manager
                       network:(WiFiNetworkRef)network;
#endif // TARGET_OS_IPHONE
+ (BOOL)updateHeuristicState:(BOOL)success isTimeout:(BOOL)isTimeout;
+ (BOOL)reportResolutionFailure:(NSURL *)url isTimeout:(BOOL)isTimeout;
+ (NSUInteger)currentTimeMs;
@end

#endif /* DNSHeuristicsInternal_h */
