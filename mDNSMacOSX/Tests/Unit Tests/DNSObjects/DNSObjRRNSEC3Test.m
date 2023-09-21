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
#include "dns_obj_rr_nsec3.h"
#include "dns_obj_domain_name.h"
#include "domain_name_labels.h"
#include "dns_common.h"	// For kDNSRecordType_NSEC3.
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mdns_strict.h"

@interface DNSObjRRNSEC3Test : XCTestCase

@end

@implementation DNSObjRRNSEC3Test

- (void)testCreate
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3_allocated = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(nsec3_allocated, nsec3));

		MDNS_DISPOSE_DNS_OBJ(nsec3);
		MDNS_DISPOSE_DNS_OBJ(nsec3_allocated);
	}
}

- (void)testGetCurrentOwnerName
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3_allocated = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		XCTAssert(dns_obj_domain_name_get_labels(dns_obj_rr_nsec3_get_current_owner_name(nsec3_allocated)) != nsec3_result->current_owner_name);
		if (domain_name_labels_contains_upper_case(test_records[i].name)) {
			XCTAssert(dns_obj_domain_name_get_labels(dns_obj_rr_nsec3_get_current_owner_name(nsec3)) != test_records[i].name);
		} else {
			XCTAssert(dns_obj_domain_name_get_labels(dns_obj_rr_nsec3_get_current_owner_name(nsec3)) == test_records[i].name);
		}
		XCTAssertTrue(dns_obj_equal(dns_obj_rr_nsec3_get_current_owner_name(nsec3_allocated),
									   dns_obj_rr_nsec3_get_current_owner_name(nsec3)));

		dns_obj_domain_name_t expected_current_owner_name =
		dns_obj_domain_name_create_with_labels(nsec3_result->current_owner_name, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(expected_current_owner_name,
									   dns_obj_rr_nsec3_get_current_owner_name(nsec3_allocated)));

		MDNS_DISPOSE_DNS_OBJ(expected_current_owner_name);
		MDNS_DISPOSE_DNS_OBJ(nsec3);
		MDNS_DISPOSE_DNS_OBJ(nsec3_allocated);
	}
}

- (void)testGetHashAlgorithm
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		XCTAssertEqual(dns_obj_rr_nsec3_get_hash_algorithm(nsec3), nsec3_result->hash_algorithm);

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetFlags
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		XCTAssertEqual(dns_obj_rr_nsec3_get_flags(nsec3), nsec3_result->flags);

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetIterations
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		XCTAssertEqual(dns_obj_rr_nsec3_get_iterations(nsec3), nsec3_result->iterations);

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetSaltLength
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		const uint8_t salt_len = dns_obj_rr_nsec3_get_salt_length(nsec3);

		XCTAssertEqual(salt_len, nsec3_result->salt_length);

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetSalt
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		uint8_t salt_len;
		const uint8_t * const salt = dns_obj_rr_nsec3_get_salt(nsec3, &salt_len);

		XCTAssertEqual(salt_len, nsec3_result->salt_length);
		if (salt_len > 0) {
			XCTAssertEqual(memcmp(salt, nsec3_result->salt, salt_len), 0);
		}

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetNextHashedOwnerNameInBinary
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		uint8_t next_hashed_owner_name_len;
		const uint8_t * const next_hashed_owner_name_in_binary =
			dns_obj_rr_nsec3_get_next_hashed_owner_name_in_binary(nsec3, &next_hashed_owner_name_len);

		XCTAssertEqual(next_hashed_owner_name_len, nsec3_result->hash_length);
		XCTAssertEqual(memcmp(next_hashed_owner_name_in_binary, nsec3_result->next_hashed_owner_name_in_binary, next_hashed_owner_name_len), 0);
	}
}

- (void)testGetNextHashedOwnerName
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;

		const dns_obj_domain_name_t next_hashed_owner_name = dns_obj_rr_nsec3_get_next_hashed_owner_name(nsec3);
		const uint8_t * const next_hashed_owner_name_labels = dns_obj_domain_name_get_labels(next_hashed_owner_name);

		const compare_result_t compare_result = domain_name_labels_canonical_compare(next_hashed_owner_name_labels,
			nsec3_result->next_hashed_owner_name, true);
		XCTAssertEqual(compare_result, compare_result_equal);

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testGetOptOutEnabled
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;
		XCTAssertEqual(dns_obj_rr_nsec3_get_opt_out_enabled(nsec3), (nsec3_result->flags == NSEC3_FLAG_OPT_OUT));


		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testCoversDNSType
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &test_records[i].expected_result_u.nsec3;
		for (size_t type_value = 0; type_value <= UINT16_MAX; type_value++) {
			bool expect_covered = false;
			const uint16_t type = (uint16_t)type_value;
			for (uint32_t j = 0; j < countof(nsec3_result->types_covered); j++) {
				if (nsec3_result->types_covered[j] == kDNSRecordType_Invalid) {
					break;
				}
				if (type == nsec3_result->types_covered[j]) {
					expect_covered = true;
					break;
				}
			}
			XCTAssertEqual(dns_obj_rr_nsec3_covers_dns_type(nsec3, type), expect_covered);
		}

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testHaveSameClosestParent
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		for (size_t j = 0; j < countof(test_records); j++) {
			if (test_records[j].type != kDNSRecordType_NSEC3) {
				continue;
			}

			dns_obj_error_t err;

			dns_obj_rr_nsec3_t nsec3_1 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
				test_records[i].rdata_len, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
			dns_obj_rr_nsec3_t nsec3_2 = dns_obj_rr_nsec3_create(test_records[j].name, test_records[j].rdata,
				test_records[j].rdata_len, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			const expected_nsec3_result_t * const nsec3_1_result = &test_records[i].expected_result_u.nsec3;
			const expected_nsec3_result_t * const nsec3_2_result = &test_records[j].expected_result_u.nsec3;

			const uint8_t * const expected_nsec3_1_parent = domain_name_labels_get_parent(nsec3_1_result->current_owner_name, 1);
			XCTAssertNotEqual(expected_nsec3_1_parent, NULL);
			const uint8_t * const expected_nsec3_2_parent = domain_name_labels_get_parent(nsec3_2_result->current_owner_name, 1);
			XCTAssertNotEqual(expected_nsec3_2_parent, NULL);

			const compare_result_t compare_result = domain_name_labels_canonical_compare(expected_nsec3_1_parent,
																						 expected_nsec3_2_parent, true);
			const bool same_parent = (compare_result == compare_result_equal);

			XCTAssertEqual(dns_obj_rr_nsec3_have_same_closest_parent(nsec3_1, nsec3_2), same_parent);

			MDNS_DISPOSE_DNS_OBJ(nsec3_2);
			MDNS_DISPOSE_DNS_OBJ(nsec3_1);
		}
	}
}

- (void)testHasSameNSEC3Parameters
{
	dns_obj_error_t err;

	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_rr_nsec3_t nsec3_i = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		dns_obj_domain_name_t nsec3_zone_i = NULL;
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const dns_obj_domain_name_t nsec3_name_i = dns_obj_rr_nsec3_get_current_owner_name(nsec3_i);
		if (dns_obj_domain_name_is_root(nsec3_name_i)) {
			goto for_loop_i_exit;
		}

		nsec3_zone_i = dns_obj_domain_name_copy_parent_domain(nsec3_name_i, 1, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(test_records); j++) {
			if (test_records[j].type != kDNSRecordType_NSEC3) {
				continue;
			}

			dns_obj_rr_nsec3_t nsec3_j = dns_obj_rr_nsec3_create(test_records[j].name, test_records[j].rdata,
				test_records[j].rdata_len, true, &err);
			dns_obj_domain_name_t nsec3_zone_j = NULL;
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			const dns_obj_domain_name_t nsec3_name_j = dns_obj_rr_nsec3_get_current_owner_name(nsec3_j);
			if (dns_obj_domain_name_is_root(nsec3_name_j)) {
				goto for_loop_j_exit;
			}

			nsec3_zone_j = dns_obj_domain_name_copy_parent_domain(nsec3_name_j, 1, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			if (dns_obj_equal(nsec3_zone_i, nsec3_zone_j)) {
				XCTAssertTrue(dns_obj_rr_nsec3_has_same_nsec3_parameters(nsec3_i, nsec3_j));
			}

		for_loop_j_exit:
			MDNS_DISPOSE_DNS_OBJ(nsec3_zone_j);
			MDNS_DISPOSE_DNS_OBJ(nsec3_j);
		}

	for_loop_i_exit:
		MDNS_DISPOSE_DNS_OBJ(nsec3_zone_i);
		MDNS_DISPOSE_DNS_OBJ(nsec3_i);
	}
}

- (void)testHasReasonableIterations
{
	dns_obj_error_t err;

	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
			test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_rr_nsec3_has_reasonable_iterations(nsec3));

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testShouldBeIgnored
{
	dns_obj_error_t err;

	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
																 test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertFalse(dns_obj_rr_nsec3_should_be_ignored(nsec3));

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testAssertsNameExists
{
#define MAX_NAME_COUNT 5
	typedef struct test_case_s {
		const resource_record_bytes_short_t record;
		const uint8_t name_exists[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
		const uint8_t name_does_not_exist[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
	} test_case_t;

	const test_case_t test_cases[] = {
		{
			.record = {
				.name = {
					32, 'B', '8', 'S', 'S', '5', 'R', '8', 'S', 'H', '4', 'H', 'N', 'L', 'L', 'S', 'V', '1', 'G', 'Q',
					'R', '3', '0', '9', '3', 'O', '8', 'V', 'P', '7', '7', 'I', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.class = kDNSClassType_IN,
				.type = kDNSRecordType_NSEC3,
				.rdata_len = 43,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x5a, 0x39,
					0xc2, 0xed, 0x1c, 0x89, 0x23, 0x7a, 0xd7, 0x9f, 0x0c, 0x35, 0xb1, 0x81, 0x23, 0xc2, 0x3f, 0x93,
					0x9e, 0x46, 0x00, 0x07, 0x22, 0x00, 0x00, 0x08, 0x00, 0x02, 0x90
				},
			},
			.name_exists = {
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
			},
			.name_does_not_exist = {
				{
					32, 'B', '8', 'S', 'S', '5', 'R', '8', 'S', 'H', '4', 'H', 'N', 'L', 'L', 'S', 'V', '1', 'G', 'Q',
					'R', '3', '0', '9', '3', 'O', '8', 'V', 'P', '7', '7', 'I', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				{6, 'q', 'i', 'b', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{2, 'm', 'e', 0},
				{
					16, 'n', 'a', 'm', 'e', 'd', 'o', 'e', 's', 'n', 'o', 't', 'e', 'x', 'i', 's', 't',
					6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
				},
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 3, 'c', 'o', 'm', 0},
			}
		},
		{
			.record = {
				.name = {
					32, 'B', '8', 'S', 'S', '5', 'R', '8', 'S', 'H', '4', 'H', 'N', 'L', 'L', 'S', 'V', '1', 'G', 'Q',
					'R', '3', '0', '9', '3', 'O', '8', 'V', 'P', '7', '7', 'I', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.class = kDNSClassType_IN,
				.type = kDNSRecordType_NSEC3,
				.rdata_len = 43,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x46, 0x1e,
					0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13, 0xdf, 0xf6,
					0x91, 0xb1, 0x00, 0x07, 0x22, 0x00, 0x00, 0x08, 0x00, 0x02, 0x90
				},
			},
			.name_exists = {
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{1, 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'G', 6, 'Q', 'i', 'a', 'O', 'Y', 'U', 2, 'M', 'e', 0},
			},
			.name_does_not_exist = {
				{
					32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2', 'c',
					'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				{1, 'B', 6, 'Q', 'I', 'A', 'O', 'y', 'U', 2, 'm', 'E', 0},
				{1, 'd', 6, 'q', 'I', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
				{1, 'E', 6, 'q', 'I', 'a', 'o', 'Y', 'U', 2, 'M', 'e', 0},
				{9, 'W', 'W', 'W', 'w', 'w', 'W', 'W', 'w', 'w', 6, 'q', 'i', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
			}
		},
	};

	dns_obj_error_t err;
	for (size_t i = 0; i < countof(test_cases); i++) {
		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(test_cases[i].record.name, test_cases[i].record.rdata,
			test_cases[i].record.rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(test_cases[i].name_exists); j++) {
			const uint8_t * const name_exists_in_labels = test_cases[i].name_exists[j];
			if (domain_name_labels_is_root(name_exists_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name_exists = dns_obj_domain_name_create_with_labels(name_exists_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_rr_nsec3_asserts_name_exists(nsec3, name_exists, test_cases[i].record.class));
			XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_exists(nsec3, name_exists, kDNSClassType_CHAOS));

			MDNS_DISPOSE_DNS_OBJ(name_exists);
		}

		for (size_t j = 0; j < countof(test_cases[i].name_does_not_exist); j++) {
			const uint8_t * const name_does_not_exists_in_labels = test_cases[i].name_does_not_exist[j];
			if (domain_name_labels_is_root(name_does_not_exists_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name_does_not_exists = dns_obj_domain_name_create_with_labels(name_does_not_exists_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_exists(nsec3, name_does_not_exists, (test_cases[i].record.class)));

			MDNS_DISPOSE_DNS_OBJ(name_does_not_exists);
		}

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testAssertsNameExistsDataDoesNotExist
{

#define MAX_NAME_COUNT 5
	typedef struct test_case_s {
		const resource_record_bytes_t record;
		const uint8_t name_exists_asserted_by_nsec3[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
		const uint8_t name_not_asserted_by_nsec3[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
	} test_case_t;

	const test_case_t test_cases[] = {
		// This NSEC3 proves "a.qiaoyu.me." exists.
		// This NSEC3 also proves only AAAA and RRSIG record exists for the name "a.qiaoyu.me.".
		{
			.record = {
				.name = {
					// Hash of a.qiaoyu.me.
					32, 'a', 's', 'n', '1', 'f', 'o', 'r', '6', 'j', '7', 'n', 's', 't', 'b', 'i', 'n', '9', 'i', 'm', 'i', 'g',
					'v', '6', 'p', 'h', 'g', '9', 'k', '2', 'g', 'd', 'p', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 42,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x5a, 0x39, 0xc2, 0xed,
					0x1c, 0x89, 0x23, 0x7a, 0xd7, 0x9f, 0x0c, 0x35, 0xb1, 0x81, 0x23, 0xc2, 0x3f, 0x93, 0x9e, 0x46, 0x00, 0x06,
					0x00, 0x00, 0x00, 0x08, 0x00, 0x02
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						32, 'a', 's', 'n', '1', 'f', 'o', 'r', '6', 'j', '7', 'n', 's', 't', 'b', 'i', 'n', '9', 'i', 'm', 'i', 'g',
						'v', '6', 'p', 'h', 'g', '9', 'k', '2', 'g', 'd', 'p', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x5a, 0x39, 0xc2, 0xed, 0x1c, 0x89, 0x23, 0x7a, 0xd7, 0x9f, 0x0c, 0x35, 0xb1, 0x81, 0x23, 0xc2, 0x3f,
						0x93, 0x9e, 0x46
					},
					.next_hashed_owner_name = {
						// Hash of qiaoyu.me.
						32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q', 'r',
						'3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_AAAA,
						kDNSRecordType_RRSIG,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{1, 'a', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'A', 6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{1, 'A', 6, 'Q', 'i', 'A', 'o', 'Y', 'U', 2, 'M', 'E', 0},
			},
			.name_not_asserted_by_nsec3 = {
				{
					32, 'a', 's', 'n', '1', 'f', 'o', 'r', '6', 'j', '7', 'n', 's', 't', 'b', 'i', 'n', '9', 'i', 'm', 'i',
					'g', 'v', '6', 'p', 'h', 'g', '9', 'k', '2', 'g', 'd', 'p', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				{1, 'B', 6, 'Q', 'I', 'A', 'O', 'y', 'U', 2, 'm', 'E', 0},
				{1, 'd', 6, 'q', 'I', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
				{1, 'E', 6, 'q', 'I', 'a', 'o', 'Y', 'U', 2, 'M', 'e', 0},
				{9, 'W', 'W', 'W', 'w', 'w', 'W', 'W', 'w', 'w', 6, 'q', 'i', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
			},
		},

		// This NSEC3 proves "g.qiaoyu.me." exists.
		// This NSEC3 also proves only AAAA and RRSIG record exists for the name "g.qiaoyu.me.".
		{
			.record = {
				.name = {
					// Hash of g.qiaoyu.me.
					32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2', 'c',
					'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 42,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x57, 0x2e,
					0x17, 0xe3, 0x66, 0x99, 0xef, 0xce, 0xae, 0x57, 0x4c, 0xad, 0x28, 0x7c, 0xd9, 0x8c, 0x13, 0x41,
					0x41, 0xb9, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2', 'c',
						'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x57, 0x2e, 0x17, 0xe3, 0x66, 0x99, 0xef, 0xce, 0xae, 0x57, 0x4c, 0xad, 0x28, 0x7c, 0xd9, 0x8c,
						0x13, 0x41, 0x41, 0xb9
					},
					.next_hashed_owner_name = {
						// Hash of a.qiaoyu.me.
						32, 'a', 's', 'n', '1', 'f', 'o', 'r', '6', 'j', '7', 'n', 's', 't', 'b', 'i', 'n', '9', 'i',
						'm', 'i', 'g', 'v', '6', 'p', 'h', 'g', '9', 'k', '2', 'g', 'd', 'p', 6, 'q', 'i', 'a', 'o',
						'y', 'u', 2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_AAAA,
						kDNSRecordType_RRSIG,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{1, 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'G', 6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{1, 'G', 6, 'Q', 'I', 'a', 'o', 'y', 'U', 2, 'm', 'e', 0},
			},
			.name_not_asserted_by_nsec3 = {
				{
					32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2', 'c',
					'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				{1, 'B', 6, 'Q', 'I', 'A', 'O', 'y', 'U', 2, 'm', 'E', 0},
				{1, 'd', 6, 'q', 'I', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
				{1, 'E', 6, 'q', 'I', 'a', 'o', 'Y', 'U', 2, 'M', 'e', 0},
				{9, 'W', 'W', 'W', 'w', 'w', 'W', 'W', 'w', 'w', 6, 'q', 'i', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
			},
		},

		// This NSEC3 proves "thisisacname.qiaoyu.me." exists.
		// This NSEC3 proves CNAME and RRSIG record exists for the name "thisisacname.qiaoyu.me.", but it does not prove
		// the nonexistence of other DNS data, because we must follow CNAME to verify that.
		{
			.record = {
				.name = {
					// Hash of thisisacname.qiaoyu.me.
					32, 'b', 'k', 'r', '5', 'r', 'o', '0', '5', 'b', '8', '6', 'k', 'i', '4', '3', 'a', 'r', '2', '0',
					'6', '8', '7', 'j', '9', 'v', 'f', 'b', 'm', 'e', 'p', 'p', 'c', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 42,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x46, 0x1e,
					0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13, 0xdf, 0xf6,
					0x91, 0xb1, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						// Hash of thisisacname.qiaoyu.me.
						32, 'b', 'k', 'r', '5', 'r', 'o', '0', '5', 'b', '8', '6', 'k', 'i', '4', '3', 'a', 'r', '2', '0',
						'6', '8', '7', 'j', '9', 'v', 'f', 'b', 'm', 'e', 'p', 'p', 'c', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x46, 0x1e, 0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d,
						0x13, 0xdf, 0xf6, 0x91, 0xb1
					},
					.next_hashed_owner_name = {
						// Hash of g.qiaoyu.me.
						32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2',
						'c', 'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h',
						6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_CNAME,
						kDNSRecordType_RRSIG,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{12, 't', 'h', 'i', 's', 'i', 's', 'a', 'c', 'n', 'a', 'm', 'e', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{12, 'T', 'H', 'I', 'S', 'I', 'S', 'A', 'C', 'N', 'A', 'M', 'E', 6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{12, 'T', 'h', 'i', 'S', 'i', 'S', 'A', 'C', 'N', 'A', 'M', 'e', 6, 'Q', 'I', 'a', 'O', 'Y', 'U', 2, 'm', 'e', 0},
			},
			.name_not_asserted_by_nsec3 = {
				{
					// Hash of thisisacname.qiaoyu.me.
					32, 'b', 'k', 'r', '5', 'r', 'o', '0', '5', 'b', '8', '6', 'k', 'i', '4', '3', 'a', 'r', '2', '0',
					'6', '8', '7', 'j', '9', 'v', 'f', 'b', 'm', 'e', 'p', 'p', 'c', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				{1, 'B', 6, 'Q', 'I', 'A', 'O', 'y', 'U', 2, 'm', 'E', 0},
				{1, 'd', 6, 'q', 'I', 'A', 'O', 'Y', 'U', 2, 'm', 'E', 0},
				{1, 'E', 6, 'q', 'I', 'a', 'o', 'Y', 'U', 2, 'M', 'e', 0},
				{1, 'a', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
			},
		},
	};

	dns_obj_error_t err;

	for (size_t i = 0; i < countof(test_cases); i++) {
		const resource_record_bytes_t * const record = &test_cases[i].record;

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(record->name, record->rdata, record->rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_nsec3_result_t * const nsec3_result = &record->expected_result_u.nsec3;

		for (size_t j = 0; j < countof(test_cases[i].name_exists_asserted_by_nsec3); j++) {
			const uint8_t * const name_in_labels = test_cases[i].name_exists_asserted_by_nsec3[j];
			if (domain_name_labels_is_root(name_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(name_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			for (size_t type_value = 0; type_value <= UINT16_MAX; type_value++) {
				bool expected_covered = false;
				const uint16_t type = (uint16_t)type_value;
				for (size_t k = 0; k < countof(nsec3_result->types_covered); k++) {
					if (nsec3_result->types_covered[k] == kDNSRecordType_Invalid) {
						break;
					}
					if (type == nsec3_result->types_covered[k]) {
						expected_covered = true;
						break;
					}
				}

				// If we did not ask for CNAME record, but the returned NSEC3 record covers CNAME, then this CNAME cannot be
				// used to assert the none-existence of any DNS type, because CNAME excludes any other DNS record under the
				// same owner name by definition. We have to follow the CNAME chain to the end, and use the NSEC3 there to
				// check for existence.
				if (type != kDNSRecordType_CNAME && dns_obj_rr_nsec3_covers_dns_type(nsec3, kDNSRecordType_CNAME)) {
					XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_exists_data_does_not_exist(nsec3, name, record->class, type));
				} else {
					XCTAssertEqual(dns_obj_rr_nsec3_asserts_name_exists_data_does_not_exist(nsec3, name, record->class, type), !expected_covered);
				}
				XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_exists_data_does_not_exist(nsec3, name, kDNSClassType_CHAOS, type));
			}
			MDNS_DISPOSE_DNS_OBJ(name);
		}

		for (size_t j = 0; j < countof(test_cases[i].name_not_asserted_by_nsec3); j++) {
			const uint8_t * const name_in_labels = test_cases[i].name_not_asserted_by_nsec3[j];
			if (domain_name_labels_is_root(name_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(name_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			for (size_t type_value = 0; type_value <= UINT16_MAX; type_value++) {
				bool expected_covered = false;
				const uint16_t type = (uint16_t)type_value;
				for (size_t k = 0; k < countof(nsec3_result->types_covered); k++) {
					if (nsec3_result->types_covered[k] == kDNSRecordType_Invalid) {
						break;
					}
					if (type == nsec3_result->types_covered[k]) {
						expected_covered = true;
						break;
					}
				}
				XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_exists_data_does_not_exist(nsec3, name, record->class, type));
			}
			MDNS_DISPOSE_DNS_OBJ(name);
		}
		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testAssertsNameDoesNotExist
{
#define MAX_NAME_COUNT 5
	typedef struct test_case_s {
		const resource_record_bytes_t record;
		const uint8_t name_exists_asserted_by_nsec3[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
		const uint8_t name_not_exists_asserted_by_nsec3[MAX_NAME_COUNT][MAX_DOMAIN_NAME];
	} test_case_t;

	const test_case_t test_cases[] = {
		// This NSEC3 proves "qiaoyu.me." and "g.qiaoyu.me." exist.
		{
			.record = {
				.name = {
					// Hash of qiaoyu.me.
					32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q',
					'r', '3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 43,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x46, 0x1e,
					0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13, 0xdf, 0xf6,
					0x91, 0xb1, 0x00, 0x07, 0x22, 0x00, 0x00, 0x08, 0x00, 0x02, 0x90
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						// Hash of qiaoyu.me.
						32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q',
						'r', '3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x46, 0x1e, 0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13,
						0xdf, 0xf6, 0x91, 0xb1
					},
					.next_hashed_owner_name = {
						// Hash of g.qiaoyu.me.
						32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2',
						'c', 'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h',
						6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_NS,
						kDNSRecordType_SOA,
						kDNSRecordType_AAAA,
						kDNSRecordType_RRSIG,
						kDNSRecordType_DNSKEY,
						kDNSRecordType_NSEC3PARAM,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{6, 'Q', 'i', 'a', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{1, 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'g', 6, 'Q', 'I', 'a', 'o', 'Y', 'U', 2, 'm', 'E', 0},
			},
			.name_not_exists_asserted_by_nsec3 = {
				{1, 'B', 6, 'q', 'i', 'a', 'o', 'Y', 'U', 2, 'm', 'e', 0},
				{1, 'D', 6, 'Q', 'I', 'A', 'o', 'y', 'u', 2, 'm', 'E', 0},
				{1, 'e', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{19, 'T', 'H', 'i', 's', 'I', 'S', 'a', 'v', 'e', 'r', 'y', 'l', 'o', 'n', 'g', 'N', 'A', 'M', 'e', 6, 'q', 'i', 'a', 'O', 'y', 'u', 2, 'M', 'e', 0},
				{1, 'H', 6, 'q', 'I', 'A', 'O', 'y', 'U', 2, 'M', 'e', 0},
			},
		},

		// This NSEC3 proves that only "qiaoyu.me." exists, because the current hashed name and the next hashed owner
		// name are equal.
		{
			.record = {
				.name = {
					// Hash of qiaoyu.me.
					32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q',
					'r', '3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 43,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x5a, 0x39,
					0xc2, 0xed, 0x1c, 0x89, 0x23, 0x7a, 0xd7, 0x9f, 0x0c, 0x35, 0xb1, 0x81, 0x23, 0xc2, 0x3f, 0x93,
					0x9e, 0x46, 0x00, 0x07, 0x22, 0x00, 0x00, 0x08, 0x00, 0x02, 0x90
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						// Hash of qiaoyu.me.
						32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q',
						'r', '3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x5a, 0x39, 0xc2, 0xed, 0x1c, 0x89, 0x23, 0x7a, 0xd7, 0x9f, 0x0c, 0x35, 0xb1, 0x81, 0x23, 0xc2,
						0x3f, 0x93, 0x9e, 0x46
					},
					.next_hashed_owner_name = {
						// Hash of qiaoyu.me.
						32, 'b', '8', 's', 's', '5', 'r', '8', 's', 'h', '4', 'h', 'n', 'l', 'l', 's', 'v', '1', 'g', 'q',
						'r', '3', '0', '9', '3', 'o', '8', 'v', 'p', '7', '7', 'i', '6', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_NS,
						kDNSRecordType_SOA,
						kDNSRecordType_AAAA,
						kDNSRecordType_RRSIG,
						kDNSRecordType_DNSKEY,
						kDNSRecordType_NSEC3PARAM,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{6, 'Q', 'i', 'a', 'O', 'Y', 'U', 2, 'M', 'E', 0},
			},
			.name_not_exists_asserted_by_nsec3 = {
				{1, 'B', 6, 'q', 'i', 'a', 'o', 'Y', 'U', 2, 'm', 'e', 0},
				{1, 'D', 6, 'Q', 'I', 'A', 'o', 'y', 'u', 2, 'm', 'E', 0},
				{1, 'e', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{19, 'T', 'H', 'i', 's', 'I', 'S', 'a', 'v', 'e', 'r', 'y', 'l', 'o', 'n', 'g', 'N', 'A', 'M', 'e', 6, 'q', 'i', 'a', 'O', 'y', 'u', 2, 'M', 'e', 0},
				{1, 'H', 6, 'q', 'I', 'A', 'O', 'y', 'U', 2, 'M', 'e', 0},
			},
		},

		// This NSEC3 proves that "d.qiaoyu.me." and "g.qiaoyu.me" exist.
		{
			.record = {
				.name = {
					// Hash of "d.qiaoyu.me.".
					32, 'v', '6', 'l', '4', 'b', '2', 'a', 's', 'a', 'q', '0', '2', 'd', 'r', 'o', '4', 'r', 'f', '5',
					'q', 'n', 'g', 'm', 'j', 'h', 'c', 'v', 'd', 'j', 'c', '0', 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u',
					2, 'm', 'e', 0
				},
				.type = kDNSRecordType_NSEC3,
				.class = kDNSClassType_IN,
				.rdata_len = 42,
				.rdata = {
					0x01, 0x01, 0x00, 0x0a, 0x08, 0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47, 0x14, 0x46, 0x1e,
					0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13, 0xdf, 0xf6,
					0x91, 0xb1, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02
				},
				.expected_result_u.nsec3 = {
					.current_owner_name = {
						// Hash of "d.qiaoyu.me.".
						32, 'v', '6', 'l', '4', 'b', '2', 'a', 's', 'a', 'q', '0', '2', 'd', 'r', 'o', '4', 'r', 'f', '5',
						'q', 'n', 'g', 'm', 'j', 'h', 'c', 'v', 'd', 'j', 'c', '0', 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u',
						2, 'm', 'e', 0
					},
					.hash_algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
					.flags = NSEC3_FLAG_OPT_OUT,
					.iterations = 10,
					.salt_length = 8,
					.salt = {0x68, 0x95, 0x35, 0xf8, 0xa4, 0xf4, 0x2d, 0x47},
					.hash_length = 20,
					.next_hashed_owner_name_in_binary = {
						0x46, 0x1e, 0xc9, 0x4b, 0xcf, 0xbf, 0xc2, 0x47, 0xaf, 0xb4, 0xa8, 0x98, 0xdd, 0x9a, 0x4d, 0x13,
						0xdf, 0xf6, 0x91, 0xb1
					},
					.next_hashed_owner_name = {
						// Hash of "g.qiaoyu.me."
						32, '8', 'o', 'f', 'c', 'i', 'i', 'u', 'f', 'n', 'v', '1', '4', 'f', 'b', 't', 'k', 'l', '2',
						'c', 'd', 'r', '6', 'i', 'd', '2', 'f', 'f', 'v', 'd', '4', 'd', 'h',
						6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0
					},
					.types_covered = {
						kDNSRecordType_NS,
						kDNSRecordType_SOA,
						kDNSRecordType_AAAA,
						kDNSRecordType_RRSIG,
						kDNSRecordType_DNSKEY,
						kDNSRecordType_NSEC3PARAM,
						kDNSRecordType_Invalid
					}
				},
			},
			.name_exists_asserted_by_nsec3 = {
				{1, 'd', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'D', 6, 'Q', 'I', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
				{1, 'd', 6, 'q', 'i', 'A', 'O', 'y', 'U', 2, 'M', 'e', 0},
				{1, 'g', 6, 'q', 'i', 'a', 'o', 'y', 'u', 2, 'm', 'e', 0},
				{1, 'G', 6, 'q', 'i', 'A', 'O', 'Y', 'U', 2, 'M', 'E', 0},
			},
			.name_not_exists_asserted_by_nsec3 = {
				{1, '3', 6, 'q', 'i', 'a', 'o', 'Y', 'U', 2, 'm', 'e', 0},
				{1, '4', 6, 'Q', 'I', 'A', 'o', 'y', 'u', 2, 'm', 'E', 0},
			},
		},
	};

	dns_obj_error_t err;
	for (size_t i = 0; i < countof(test_cases); i++) {
		const resource_record_bytes_t * const record = &test_cases[i].record;

		dns_obj_rr_nsec3_t nsec3 = dns_obj_rr_nsec3_create(record->name, record->rdata, record->rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(test_cases[i].name_exists_asserted_by_nsec3); j++) {
			const uint8_t * const name_in_labels = test_cases[i].name_exists_asserted_by_nsec3[j];
			if (domain_name_labels_is_root(name_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(name_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_does_not_exist(nsec3, name, record->class));
			XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_does_not_exist(nsec3, name, kDNSClassType_CHAOS));

			MDNS_DISPOSE_DNS_OBJ(name);
		}

		for (size_t j = 0; j < countof(test_cases[i].name_not_exists_asserted_by_nsec3); j++) {
			const uint8_t * const name_in_labels = test_cases[i].name_not_exists_asserted_by_nsec3[j];
			if (domain_name_labels_is_root(name_in_labels)) {
				continue;
			}

			dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(name_in_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_rr_nsec3_asserts_name_does_not_exist(nsec3, name, record->class), "i: %zu, j: %zu", i, j);
			XCTAssertFalse(dns_obj_rr_nsec3_asserts_name_does_not_exist(nsec3, name, kDNSClassType_CHAOS));

			MDNS_DISPOSE_DNS_OBJ(name);
		}

		MDNS_DISPOSE_DNS_OBJ(nsec3);
	}
}

- (void)testCompare
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_NSEC3) {
			continue;
		}

		for (size_t j = 0; j < countof(test_records); j++) {
			if (test_records[j].type != kDNSRecordType_NSEC3) {
				continue;
			}

			dns_obj_error_t err;

			dns_obj_rr_nsec3_t nsec3_1 = dns_obj_rr_nsec3_create(test_records[i].name, test_records[i].rdata,
				test_records[i].rdata_len, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
			dns_obj_rr_nsec3_t nsec3_2 = dns_obj_rr_nsec3_create(test_records[j].name, test_records[j].rdata,
				test_records[j].rdata_len, false, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
			const bool same_parent = dns_obj_rr_nsec3_have_same_closest_parent(nsec3_1, nsec3_2);

			const compare_result_t compare_result = dns_obj_compare(nsec3_1, nsec3_2);

			if (same_parent) {
				if (i == j) {
					XCTAssertEqual(compare_result, compare_result_equal);
				} else if (i < j) {
					XCTAssertEqual(compare_result, compare_result_less);
				} else { // i > j
					XCTAssertEqual(compare_result, compare_result_greater);
				}
			} else {
				XCTAssertEqual(compare_result, compare_result_notequal);
			}

			MDNS_DISPOSE_DNS_OBJ(nsec3_2);
			MDNS_DISPOSE_DNS_OBJ(nsec3_1);
		}
	}
}

@end
