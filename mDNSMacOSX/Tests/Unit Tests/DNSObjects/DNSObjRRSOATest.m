/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#import <XCTest/XCTest.h>
#include <CoreUtils/CoreUtils.h>

#include "ResourceRecordBytes.h"
#include "dns_obj_rr_soa.h"
#include "dns_obj_domain_name.h"
#include "dns_common.h"    // For kDNSRecordType_SOA.
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mdns_strict.h"

@interface DNSObjRRSOATest : XCTestCase

@end

@implementation DNSObjRRSOATest

- (void)testCreate
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_SOA) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_soa_t soa_allocated = dns_obj_rr_soa_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_soa_t soa = dns_obj_rr_soa_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(soa_allocated, soa));

		MDNS_DISPOSE_DNS_OBJ(soa);
		MDNS_DISPOSE_DNS_OBJ(soa_allocated);
	}
}

- (void)testGetMinimumTTL
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_SOA) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_soa_t soa = dns_obj_rr_soa_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_soa_result_t * const soa_result = &test_records[i].expected_result_u.soa;

		XCTAssertEqual(dns_obj_rr_soa_get_minimum_ttl(soa), soa_result->minimum_ttl);

		MDNS_DISPOSE_DNS_OBJ(soa);
	}
}

@end
