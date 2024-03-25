/*
 * Copyright (c) 2020-2023 Apple Inc. All rights reserved.
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

#import "unittest_common.h"
#import "DNSHeuristicsInternal.h"
#import <XCTest/XCTest.h>
#import <OCMock/OCMock.h>

@interface DNSHeuristicsTest : XCTestCase
@end

@implementation DNSHeuristicsTest

#if (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST && !TARGET_OS_XR)
- (void)testEmptyStateFailure {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(@{});
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);

    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMVerify(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureUnderThreshold {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithInt:1],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(NO),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);

    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMVerify(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureOverThreshold {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicDefaultLongCounterThreshold], // reporting an error will cause this count to exceed the threshold
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(NO),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);

    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMVerify(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureUnderThreshold_StickAfterFailure {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicDefaultLongCounterThreshold],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(YES),
    };
    OCMStub(ClassMethod([mockHeuristics getNetworkFilteredFlag:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + DNSHeuristicDefaultLongCounterTimeWindow * 2); // two days pass, we should reset

    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMReject(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureUnderThreshold_ResetAfterSuccess {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicDefaultLongCounterThreshold],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(YES),
    };
    OCMStub(ClassMethod([mockHeuristics getNetworkFilteredFlag:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + DNSHeuristicDefaultLongCounterTimeWindow * 2); // two days pass, we should reset

    XCTAssertTrue([DNSHeuristics updateHeuristicState:YES isTimeout:NO]);
    OCMVerify(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureDrainTokenBucket_NoReset {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithInt:0],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithInt:1],
        DNSHeuristicsFilterFlagKey: @(NO),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + 1); // within the same epoch -- overflow

    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMReject(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureDrainTokenBucket_Reset {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSURL *url = [NSURL URLWithString:@"https://example.com"];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithInt:0],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithInt:1],
        DNSHeuristicsFilterFlagKey: @(NO),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + DNSHeuristicsDefaultBurstTokenBucketRefillTime + 1); // allow the bucket to replenish

    XCTAssertTrue([DNSHeuristics reportResolutionFailure:url isTimeout:NO]);
    OCMReject(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureFilteredThenSuccessBeforeWindow {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:now],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithInt:0],
		DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(YES),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics getNetworkFilteredFlag:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + DNSHeuristicsDefaultBurstTokenBucketRefillTime + 1); // allow the bucket to replenish

    XCTAssertTrue([DNSHeuristics updateHeuristicState:YES isTimeout:NO]);
    OCMReject(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]]));
}

- (void)testStateFailureFilteredThenSuccessAfterWindow {
    id mockHeuristics = OCMClassMock([DNSHeuristics class]);
    NSUInteger now = [DNSHeuristics currentTimeMs];
    NSDictionary *existingState = @{
        DNSHeuristicsLastFailureTimestamp: [NSNumber numberWithUnsignedInteger:(now - DNSHeuristicDefaultLongCounterTimeWindow)],
        DNSHeuristicsLongCounterKey: [NSNumber numberWithInt:0],
        DNSHeuristicsBurstCounterKey: [NSNumber numberWithUnsignedInteger:DNSHeuristicsDefaultBurstTokenBucketCapacity],
        DNSHeuristicsFilterFlagKey: @(YES),
    };
    OCMStub(ClassMethod([mockHeuristics copyNetworkSettings:[OCMArg any]])).andReturn(existingState);
    OCMStub(ClassMethod([mockHeuristics getNetworkFilteredFlag:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkSettings:[OCMArg any] value:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics clearNetworkAsFiltered:[OCMArg any]])).andReturn(YES);
    OCMStub(ClassMethod([mockHeuristics currentTimeMs])).andReturn(now + DNSHeuristicsDefaultBurstTokenBucketRefillTime + 1); // allow the bucket to replenish

    XCTAssertTrue([DNSHeuristics updateHeuristicState:YES isTimeout:NO]);
    OCMReject(ClassMethod([mockHeuristics setNetworkAsFiltered:[OCMArg any]]));
}

#endif // (TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST && !TARGET_OS_XR)

@end
