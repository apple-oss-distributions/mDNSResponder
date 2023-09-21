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

#include "dns_obj_rr_srv.h"
#include "ResourceRecordBytes.h"
#include "dns_obj_domain_name.h"
#include "domain_name_labels.h"
#include "dns_common.h"
#include <stdint.h>

#include "mdns_strict.h"

@interface DNSObjRRSRVTest : XCTestCase

@end

@implementation DNSObjRRSRVTest

- (void)testCreate
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_SRV) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_srv_t srv_allocated = dns_obj_rr_srv_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_srv_t srv = dns_obj_rr_srv_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(srv_allocated, srv));

		MDNS_DISPOSE_DNS_OBJ(srv);
		MDNS_DISPOSE_DNS_OBJ(srv_allocated);
	}
}

- (void)testGetters
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_SRV) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_srv_t srv = dns_obj_rr_srv_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertEqual(dns_obj_rr_srv_get_priority(srv), test_records[i].expected_result_u.srv.priority);
		XCTAssertEqual(dns_obj_rr_srv_get_weight(srv), test_records[i].expected_result_u.srv.weight);
		XCTAssertEqual(dns_obj_rr_srv_get_port(srv), test_records[i].expected_result_u.srv.port);

		dns_obj_domain_name_t target = dns_obj_rr_srv_get_target(srv);
		dns_obj_domain_name_t name_to_compare = dns_obj_domain_name_create_with_labels(test_records[i].expected_result_u.srv.target, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(target, name_to_compare));

		MDNS_DISPOSE_DNS_OBJ(srv);
		MDNS_DISPOSE_DNS_OBJ(target);
		MDNS_DISPOSE_DNS_OBJ(name_to_compare);
	}
}

@end
