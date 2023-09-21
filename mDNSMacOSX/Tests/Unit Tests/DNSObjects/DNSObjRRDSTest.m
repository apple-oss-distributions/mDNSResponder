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

#include "dns_obj_rr_ds.h"
#include "dns_obj_rr_dnskey.h"
#include "dns_obj_rr.h"
#include "ResourceRecordBytes.h"
#include "dns_common.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "mdns_strict.h"

@interface DNSObjRRDSTest : XCTestCase

@end

@implementation DNSObjRRDSTest

- (void)testCreate
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds_allocated = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(ds_allocated, ds));

		MDNS_DISPOSE_DNS_OBJ(ds);
		MDNS_DISPOSE_DNS_OBJ(ds_allocated);
	}
}

- (void)testGetKeyTag
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_ds_result_t * const expected_result = &test_records[i].expected_result_u.ds;
		const uint16_t key_tag = dns_obj_rr_ds_get_key_tag(ds);
		XCTAssertEqual(expected_result->key_tag, key_tag);

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

- (void)testGetAlgorithm
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_ds_result_t * const expected_result = &test_records[i].expected_result_u.ds;
		const uint8_t algorithm = dns_obj_rr_ds_get_algorithm(ds);
		XCTAssertEqual(expected_result->algorithm, algorithm);

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

- (void)testGetDigestType
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_ds_result_t * const expected_result = &test_records[i].expected_result_u.ds;
		const uint8_t digest_type = dns_obj_rr_ds_get_digest_type(ds);
		XCTAssertEqual(expected_result->digest_type, digest_type);

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

- (void)testGetDigest
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_ds_result_t * const expected_result = &test_records[i].expected_result_u.ds;
		const uint8_t * const digest = dns_obj_rr_ds_get_digest(ds);
		const uint16_t digest_length = dns_obj_rr_ds_get_digest_length(ds);
		XCTAssertEqual(expected_result->digest_length, digest_length);
		XCTAssertEqual(memcmp(expected_result->digest, digest, digest_length), 0);

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

- (void)testIsValidForDNS
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const expected_ds_result_t * const expected_result = &test_records[i].expected_result_u.ds;
		const bool is_valid_for_dnssec = dns_obj_rr_ds_is_valid_for_dnssec(ds, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
		XCTAssertEqual(expected_result->is_valid_for_dnssec, is_valid_for_dnssec);

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

- (void)testValidatesDNSKEY
{
	for (size_t i = 0; i < countof(test_records); i++) {
		if (test_records[i].type != kDNSRecordType_DS) {
			continue;
		}

		dns_obj_error_t err;
		dns_obj_rr_ds_t ds = dns_obj_rr_ds_create(test_records[i].name,
			test_records[i].class, test_records[i].rdata, test_records[i].rdata_len, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(test_records); j++) {
			if (test_records[j].type != kDNSRecordType_DNSKEY) {
				continue;
			}

			dns_obj_rr_dnskey_t dnskey = dns_obj_rr_dnskey_create(test_records[j].name,
				test_records[j].class, test_records[j].rdata, test_records[j].rdata_len, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			if (dns_obj_rr_ds_get_key_tag(ds) == dns_obj_rr_dnskey_get_key_tag(dnskey)&&
				dns_obj_equal(dns_obj_rr_get_name(ds), dns_obj_rr_get_name(dnskey)))
			{
				XCTAssertTrue(dns_obj_rr_ds_validates_dnskey(ds, dnskey, &err));
				XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
			} else {
				XCTAssertFalse(dns_obj_rr_ds_validates_dnskey(ds, dnskey, &err));
				XCTAssertNotEqual(err, DNS_OBJ_ERROR_NO_ERROR);
			}

			MDNS_DISPOSE_DNS_OBJ(dnskey);
		}

		MDNS_DISPOSE_DNS_OBJ(ds);
	}
}

@end
