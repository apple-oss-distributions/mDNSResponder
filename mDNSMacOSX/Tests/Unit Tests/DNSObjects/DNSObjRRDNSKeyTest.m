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

#include "dns_obj_rr_dnskey.h"
#include "ResourceRecordBytes.h"
#include "dns_common.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "mdns_strict.h"

@interface DNSObjRRDNSKeyTest : XCTestCase

@end

@implementation DNSObjRRDNSKeyTest

- (void)testCreate
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey_allocated = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(dnskey_allocated, dnskey));

		MDNS_DISPOSE_DNS_OBJ(dnskey);
		MDNS_DISPOSE_DNS_OBJ(dnskey_allocated);
	}
}

- (void)testGetFlags
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const uint16_t flags = dns_obj_rr_dnskey_get_flags(dnskey);
		XCTAssertEqual(expected_result->flags, flags);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testGetProtocol
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const uint8_t protocol = dns_obj_rr_dnskey_get_protocol(dnskey);
		XCTAssertEqual(expected_result->protocol, protocol);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testGetAlgorithm
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const uint8_t algorithm = dns_obj_rr_dnskey_get_algorithm(dnskey);
		XCTAssertEqual(expected_result->algorithm, algorithm);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testGetPublicKeyAndSize
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;

		const uint8_t *const public_key = dns_obj_rr_dnskey_get_public_key(dnskey);
		const uint16_t public_key_size = dns_obj_rr_dnskey_get_public_key_size(dnskey);
		XCTAssertEqual(expected_result->public_key_size, public_key_size);
		XCTAssertEqual(memcmp(expected_result->public_key, public_key, public_key_size), 0);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testGetKeyTag
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const uint16_t key_tag = dns_obj_rr_dnskey_get_key_tag(dnskey);
		XCTAssertEqual(expected_result->key_tag, key_tag);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testIsZoneKey
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const bool is_zone_key = dns_obj_rr_dnskey_is_zone_key(dnskey);
		XCTAssertEqual(expected_result->is_zone_key, is_zone_key);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testIsSecureEntryPoint
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const bool is_secure_entry_point = dns_obj_rr_dnskey_is_secure_entry_point(dnskey);
		XCTAssertEqual(expected_result->is_secure_entry_point, is_secure_entry_point);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testHasSupportedAlgorithm
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const bool has_supported_algorithm = dns_obj_rr_dnskey_has_supported_algorithm(dnskey);
		XCTAssertEqual(expected_result->has_supported_algorithm, has_supported_algorithm);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testIsValidForDNS
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const bool is_valid_for_dns = dns_obj_rr_dnskey_is_valid_for_dnssec(dnskey, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
		XCTAssertEqual(expected_result->is_valid_for_dnssec, is_valid_for_dns);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testGetPriority
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_dnskey_result_t * const expected_result = &test_records[i].expected_result_u.dnskey;
		const uint16_t priority = dns_obj_rr_dnskey_algorithm_get_priority(dns_obj_rr_dnskey_get_algorithm(dnskey));
		XCTAssertEqual(expected_result->priority, priority);

		MDNS_DISPOSE_DNS_OBJ(dnskey);
	}
}

- (void)testCompareEquality
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DNSKEY) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_dnskey_t dnskey_i = dns_obj_rr_dnskey_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(test_records); j++) {
			if (test_records[j].type != kDNSRecordType_DNSKEY) {
				continue;
			}

			dns_obj_rr_dnskey_t dnskey_j = dns_obj_rr_dnskey_create(test_records[j].name,
				test_records[j].class, test_records[j].rdata, test_records[j].rdata_len, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertEqual(dns_obj_equal(dnskey_i, dnskey_j), i == j);

			MDNS_DISPOSE_DNS_OBJ(dnskey_j);
		}

		MDNS_DISPOSE_DNS_OBJ(dnskey_i);
	}
}

@end
