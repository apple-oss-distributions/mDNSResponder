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

#include "dns_obj_domain_name.h"
#include "domain_name_labels.h"
#include "dns_obj_crypto.h"
#include "base_encoding.h"
#include "dns_common.h"
#include <stdint.h>

#include "mdns_strict.h"

@interface DNSObjDomainNameTest : XCTestCase

@end

@implementation DNSObjDomainNameTest

const uint8_t test_cases_dns_label[][MAX_DOMAIN_NAME] = {
	{0},																							// <root>
	{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},														// example.
	{1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},												// a.example.
	{8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// yljkjljk.a.example.
	{1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},										// Z.a.example.
	{4, 'z', 'A', 'B', 'C', 1, 'a', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0},						// zABC.a.EXAMPLE.
	{1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},												// z.example.
	{1, 1 , 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},										// \001.z.example.
	{1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},										// *.z.example.
	{3, 'a', 'a', 'a', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// aaa.z.z.example.
	{1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}										// \200.z.example.
};

- (void) testCreateWithLabels
{
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name1 = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t name2 = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], false, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(name1, name2));

		MDNS_DISPOSE_DNS_OBJ(name1);
		MDNS_DISPOSE_DNS_OBJ(name2);
	}
}

- (void) testCreateConcatenation
{
	dns_obj_error_t err;

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		const uint8_t * const labels = test_cases_dns_label[i];
		const size_t label_count = domain_name_labels_count_label(labels);
		for (size_t j = 0; j <= label_count; j++) {
			uint8_t front_labels[MAX_DOMAIN_NAME] = {0};
			const uint8_t * const end_labels = domain_name_labels_get_parent(labels, j);
			memcpy(front_labels, labels, (size_t)(end_labels - labels));

			dns_obj_domain_name_t front_name = dns_obj_domain_name_create_with_labels(front_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			dns_obj_domain_name_t end_name = dns_obj_domain_name_create_with_labels(end_labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			dns_obj_domain_name_t concatenation = dns_obj_domain_name_create_concatenation(front_name, end_name, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			dns_obj_domain_name_t expected_concatenation = dns_obj_domain_name_create_with_labels(labels, true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_equal(concatenation, expected_concatenation));

			MDNS_DISPOSE_DNS_OBJ(expected_concatenation);
			MDNS_DISPOSE_DNS_OBJ(concatenation);
			MDNS_DISPOSE_DNS_OBJ(end_name);
			MDNS_DISPOSE_DNS_OBJ(front_name);
		}
	}
}

- (void) testCreateCanonical
{
	const uint8_t domain_name_labels[] = {
		1, 'a', 1, 'B', 1, 'c', 1, 'D', 1, 'e', 1, 'F', 1, 'g', 1, 'h', 1, 'i', 3, 'C', 'o', 'M', 0
	};

	const uint8_t label_counts_to_test[] = {
		10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
	};

	const uint8_t expected_names[][MAX_DOMAIN_NAME] = {
		{1, 'a', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'b', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'c', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'd', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'e', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'f', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'g', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'h', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 1, 'i', 3, 'c', 'o', 'm', 0},
		{1, '*', 3, 'c', 'o', 'm', 0},
		{1, '*', 0},
	};

	check_compile_time_code(countof(label_counts_to_test) == countof(expected_names));

	dns_obj_error_t err;
	dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(domain_name_labels, false, &err);
	XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

	for (size_t i = 0; i < countof(label_counts_to_test); i++) {
		dns_obj_domain_name_t expected_name = dns_obj_domain_name_create_with_labels(expected_names[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t canonical_name = dns_obj_domain_name_create_canonical(name, label_counts_to_test[i], &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(canonical_name, expected_name));

		MDNS_DISPOSE_DNS_OBJ(canonical_name);
		MDNS_DISPOSE_DNS_OBJ(expected_name);
	}

	MDNS_DISPOSE_DNS_OBJ(name);
}

- (void) testCreateWithCString
{
	const char * test_cases[] = {
		".",
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"Z.a.example.",
		"zABC.a.EXAMPLE.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"aaa.z.z.example.",
		"\\200.z.example.",
	};
	check_compile_time_code(countof(test_cases_dns_label) == countof(test_cases));

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name_from_labels = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t name_from_cstring = dns_obj_domain_name_create_with_cstring(test_cases[i], &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(name_from_labels, name_from_cstring));

		MDNS_DISPOSE_DNS_OBJ(name_from_labels);
		MDNS_DISPOSE_DNS_OBJ(name_from_cstring);
	}
}

- (void) testCompare
{
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		for (size_t j = 0; j < countof(test_cases_dns_label); j++) {
			dns_obj_error_t err;

			dns_obj_domain_name_t name1 = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], ((i % 2) == 0), &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			dns_obj_domain_name_t name2 = dns_obj_domain_name_create_with_labels(test_cases_dns_label[j], ((j % 2) == 0), &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			if (i < j) {
				XCTAssertEqual(dns_obj_compare(name1, name2), compare_result_less);
				XCTAssertFalse(dns_obj_equal(name1, name2));
			} else if (i > j) {
				XCTAssertEqual(dns_obj_compare(name1, name2), compare_result_greater);
				XCTAssertFalse(dns_obj_equal(name1, name2));
			} else {
				XCTAssertEqual(dns_obj_compare(name1, name2), compare_result_equal);
				XCTAssertTrue(dns_obj_equal(name1, name2));
			}
			XCTAssertTrue(dns_obj_equal(name1, name1));
			XCTAssertTrue(dns_obj_equal(name2, name2));

			MDNS_DISPOSE_DNS_OBJ(name1);
			MDNS_DISPOSE_DNS_OBJ(name2);
		}
	}
}

- (void) testSort
{
	dns_obj_error_t err;
	dns_obj_domain_name_t domain_names_to_sort[countof(test_cases_dns_label)] = {NULL};
	check_compile_time_code(countof(domain_names_to_sort) == countof(test_cases_dns_label));

	for (size_t offset = 0; offset < countof(test_cases_dns_label); offset++) {
		for (size_t labels_index = 0; labels_index < countof(test_cases_dns_label); labels_index++) {
			domain_names_to_sort[((labels_index + offset) % countof(test_cases_dns_label))] = dns_obj_domain_name_create_with_labels(test_cases_dns_label[labels_index], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
		}

		dns_objs_sort(domain_names_to_sort, countof(domain_names_to_sort), sort_order_descending);
		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			dns_obj_domain_name_t expected_name =dns_obj_domain_name_create_with_labels(test_cases_dns_label[countof(test_cases_dns_label) - 1 - i], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_equal(domain_names_to_sort[i], expected_name));

			MDNS_DISPOSE_DNS_OBJ(expected_name);
		}

		dns_objs_sort(domain_names_to_sort, countof(domain_names_to_sort), sort_order_ascending);
		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			dns_obj_domain_name_t expected_name =dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_equal(domain_names_to_sort[i], expected_name));

			MDNS_DISPOSE_DNS_OBJ(expected_name);
		}

		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			MDNS_DISPOSE_DNS_OBJ(domain_names_to_sort[i]);
		}
	}

	for (size_t offset = 0; offset < countof(test_cases_dns_label); offset++) {
		for (size_t labels_index = 0; labels_index < countof(test_cases_dns_label); labels_index++) {
			domain_names_to_sort[((labels_index + offset) % countof(test_cases_dns_label))] = dns_obj_domain_name_create_with_labels(test_cases_dns_label[labels_index], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);
		}

		dns_objs_sort(domain_names_to_sort, countof(domain_names_to_sort), sort_order_ascending);
		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			dns_obj_domain_name_t expected_name =dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_equal(domain_names_to_sort[i], expected_name));

			MDNS_DISPOSE_DNS_OBJ(expected_name);
		}

		dns_objs_sort(domain_names_to_sort, countof(domain_names_to_sort), sort_order_descending);
		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			dns_obj_domain_name_t expected_name =dns_obj_domain_name_create_with_labels(test_cases_dns_label[countof(test_cases_dns_label) - 1 - i], true, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			XCTAssertTrue(dns_obj_equal(domain_names_to_sort[i], expected_name));

			MDNS_DISPOSE_DNS_OBJ(expected_name);
		}

		for (size_t i = 0; i < countof(domain_names_to_sort); i++) {
			MDNS_DISPOSE_DNS_OBJ(domain_names_to_sort[i]);
		}
	}
}

- (void) testGetLabelsAndGetLength
{
	const uint8_t expected_labels_len[countof(test_cases_dns_label)] = {
		1, 9, 11, 20, 13, 16, 11, 13, 13, 17, 13
	};

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		const bool allocate_name = ((i % 2) == 0);
		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], allocate_name, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const uint8_t * const labels = dns_obj_domain_name_get_labels(name);
		if (allocate_name || domain_name_labels_contains_upper_case(test_cases_dns_label[i])) {
			XCTAssert(labels != test_cases_dns_label[i]);
		} else {
			XCTAssert(labels == test_cases_dns_label[i]);
		}

		XCTAssertEqual(expected_labels_len[i], domain_name_labels_length(labels));
		XCTAssertEqual(expected_labels_len[i], dns_obj_domain_name_get_length(name));
		if (!allocate_name && !domain_name_labels_contains_upper_case(test_cases_dns_label[i])) {
			XCTAssertEqual(memcmp(labels, test_cases_dns_label[i], expected_labels_len[i]), 0);
		}

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void) testGetLabelCount
{
	const uint32_t expected_label_count[countof(test_cases_dns_label)] = {
		0, 1, 2, 3, 3, 3, 2, 3, 3, 4, 3
	};

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertEqual(dns_obj_domain_name_get_label_count(name), expected_label_count[i]);

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void) testToCString
{
	const char * test_cases[] = {
		".",
		"example.",
		"a.example.",
		"yljkjljk.a.example.",
		"z.a.example.",
		"zabc.a.example.",
		"z.example.",
		"\\001.z.example.",
		"*.z.example.",
		"aaa.z.z.example.",
		"\\200.z.example.",
	};
	check_compile_time_code(countof(test_cases_dns_label) == countof(test_cases));

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		char name_cstring[MAX_ESCAPED_DOMAIN_NAME];
		err = dns_obj_domain_name_to_cstring(name, name_cstring);

		XCTAssertEqual(strcmp(test_cases[i], name_cstring), 0);

		MDNS_DISPOSE_DNS_OBJ(name);
	}

}

- (void) testIsRoot
{
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertEqual(dns_obj_domain_name_is_root(name), test_cases_dns_label[i][0] == 0);

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void)testIsSubDomainOf
{
	typedef struct sub_domain_test_case_s {
		const uint8_t	subdomain[MAX_DOMAIN_NAME];
		const uint8_t	parent_domain[MAX_DOMAIN_NAME];
		const bool		is_subdomain;
	} sub_domain_test_case_t;

	const sub_domain_test_case_t test_cases[] = {
		{
			.subdomain = {
				// <root>
				0
			},
			.parent_domain = {
				// <root>
				0
			},
			.is_subdomain = false
		},
		{
			.subdomain = {
				// a.example.
				1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.parent_domain = {
				// example.
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.is_subdomain = true
		},
		{
			.subdomain = {
				// yljkjljk.a.example.
				8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.parent_domain = {
				// a.example.
				1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.is_subdomain = true
		},
		{
			.subdomain = {
				// zABC.a.EXAMPLE.
				4, 'z', 'A', 'B', 'C', 1, 'a', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0
			},
			.parent_domain = {
				// Z.a.example.
				1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.is_subdomain = false
		},
		{
			.subdomain = {
				// \200.z.example.
				1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.parent_domain = {
				// z.example.
				1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.is_subdomain = true
		},
		{
			.subdomain = {
				// yljkjljk.a.example.
				8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.parent_domain = {
				// yljkjljk.a.example.
				8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
			},
			.is_subdomain = false
		},
	};

	dns_obj_error_t err;

	for (uint32_t i = 0; i < countof(test_cases); i++) {
		const sub_domain_test_case_t * const test_case = &test_cases[i];

		dns_obj_domain_name_t subdomain = dns_obj_domain_name_create_with_labels(test_case->subdomain, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t parent_domain = dns_obj_domain_name_create_with_labels(test_case->parent_domain, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertEqual(dns_obj_domain_name_is_sub_domain_of(subdomain, parent_domain), test_case->is_subdomain);

		MDNS_DISPOSE_DNS_OBJ(parent_domain);
	}
}

- (void)testCopyParentDomain
{
	dns_obj_error_t err;
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		const size_t label_count = dns_obj_domain_name_get_label_count(name);

		for (size_t index = 0; index <= label_count; index++) {
			dns_obj_domain_name_t parent = dns_obj_domain_name_copy_parent_domain(name, index, &err);
			XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

			const uint8_t * const parent_labels = domain_name_labels_get_parent(test_cases_dns_label[i], index);
			dns_obj_domain_name_t expected_parent = dns_obj_domain_name_create_with_labels(parent_labels, true, &err);

			XCTAssertTrue(dns_obj_equal(parent, expected_parent));

			MDNS_DISPOSE_DNS_OBJ(expected_parent);
			MDNS_DISPOSE_DNS_OBJ(parent);
		}

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void) testCopyClosestCommonAncestor
{
	dns_obj_error_t err;

	// The closest common ancestor with the name itself.
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t name_copy = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t closest_common_ancestor = dns_obj_domain_name_copy_closest_common_ancestor(name, name, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t closest_common_ancestor_copy = dns_obj_domain_name_copy_closest_common_ancestor(name, name_copy, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(name, closest_common_ancestor));
		XCTAssertTrue(dns_obj_equal(closest_common_ancestor, closest_common_ancestor_copy));

		MDNS_DISPOSE_DNS_OBJ(closest_common_ancestor_copy);
		MDNS_DISPOSE_DNS_OBJ(closest_common_ancestor);
		MDNS_DISPOSE_DNS_OBJ(name_copy);
		MDNS_DISPOSE_DNS_OBJ(name);
	}

	// Normal test cases.
	const uint8_t closest_common_ancestor_test_cases[][3][MAX_DOMAIN_NAME] = {
		{
			{0},																							// <root>
			{1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},												// a.example.
			{0},																							// <root>
		},
		{
			{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},														// example.
			{1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},												// a.example.
			{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},														// example.
		},
		{
			{3, 'a', 'a', 'a', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// aaa.z.z.example.
			{1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},										// \200.z.example.
			{1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},												// z.example.
		},
		{
			{
				1, 'a', 8, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 6, 'd', 'n', 's', 's', 'e', 'c',
				5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0
			},																								// a.wildcard.dnssec.qdeng.io.
			{6, 'd', 'n', 's', 's', 'e', 'd', 5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0},					// dnssed.qdeng.io.
			{5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0},													// qdeng.io.
		},
		{
			{
				1, '*', 8, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 6, 'd', 'n', 's', 's', 'e', 'c',
				5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0
			},																								// *.wildcard.dnssec.qdeng.io.
			{
				1, 'a', 8, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 6, 'd', 'n', 's', 's', 'e', 'c',
				5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0
			},																								// a.wildcard.dnssec.qdeng.io.
			{
				8, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 6, 'd', 'n', 's', 's', 'e', 'c',
				5, 'q', 'd', 'e', 'n', 'g', 2, 'i', 'o', 0
			},																								// z.example.
		},
	};

	for (size_t i = 0; i < countof(closest_common_ancestor_test_cases); i++) {
		dns_obj_domain_name_t name1 = dns_obj_domain_name_create_with_labels(closest_common_ancestor_test_cases[i][0], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t name2 = dns_obj_domain_name_create_with_labels(closest_common_ancestor_test_cases[i][1], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t closest_common_ancestor = dns_obj_domain_name_copy_closest_common_ancestor(name1, name2, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t expected_closest_common_ancestor = dns_obj_domain_name_create_with_labels(closest_common_ancestor_test_cases[i][2], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(closest_common_ancestor, expected_closest_common_ancestor));

		MDNS_DISPOSE_DNS_OBJ(expected_closest_common_ancestor);
		MDNS_DISPOSE_DNS_OBJ(closest_common_ancestor);
		MDNS_DISPOSE_DNS_OBJ(name1);
		MDNS_DISPOSE_DNS_OBJ(name2);
	}
}

- (void) testIsWildcardDomainName
{
	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertEqual(dns_obj_domain_name_is_wildcard_domain_name(name),
					   (test_cases_dns_label[i][0] == 1 && test_cases_dns_label[i][1] == '*'));

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void) testIsWildcardExpansion
{
	typedef struct expected_wildcard_expansion_s {
		const uint8_t wildcard_name[MAX_DOMAIN_NAME];
		const bool is_wildcard_expansion;
	} expected_wildcard_expansion_t;

#define MAX_TEST_CASES_PER_NAME 10
	const expected_wildcard_expansion_t expected_wildcard_expansions[][MAX_TEST_CASES_PER_NAME] = {
		// <root>
		{
			{
				.wildcard_name = {0},
				.is_wildcard_expansion = false,
			},
		},
		// example.
		{
			{
				.wildcard_name = {1, '*', 0},
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},
				.is_wildcard_expansion = false,
			},
		},
		// a.example.
		{
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},
				.is_wildcard_expansion = false,
			},
		},
		// yljkjljk.a.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.a.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},												// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// yljkjljk.a.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},
				.is_wildcard_expansion = false,
			},
		},
		// Z.a.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.a.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},														// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// Z.a.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.Z.a.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.*.a.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																// <root>
				.is_wildcard_expansion = false,
			},
		},
		// zABC.a.EXAMPLE.
		{
			{
				.wildcard_name = {1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},							// *.a.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},									// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},																		// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {4, 'z', 'a', 'b', 'c', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// zABC.a.EXAMPLE.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 4, 'z', 'a', 'b', 'c', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.zABC.a.EXAMPLE.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'a', 1, '*', 0},														// *.a.*.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																				// <root>
				.is_wildcard_expansion = false,
			},
		},
		// z.example.
		{
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},												// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.*.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},														// <root>
				.is_wildcard_expansion = false,
			},
		},
		// \001.z.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.z.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},														// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, 1 , 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// \001.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 1 , 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.\001.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 1, '*', 0},										// *.z.*.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																// <root>
				.is_wildcard_expansion = false,
			},
		},
		// *.z.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// *.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 0},														// *.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, '*', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.*.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 1, '*', 0},										// *.z.*.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																// <root>
				.is_wildcard_expansion = false,
			},
		},
		// aaa.z.z.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},						// *.z.z.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},						// *.z.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},										// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},																			// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {3, 'a', 'a', 'a', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// aaa.z.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 3, 'a', 'a', 'a', 1, 'z', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.aaa.z.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 1, '*', 0},										// *.z.*.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																// <root>
				.is_wildcard_expansion = false,
			},
		},
		// \200.z.example.
		{
			{
				.wildcard_name = {1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// *.z.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// *.example.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, '*', 0},														// *.
				.is_wildcard_expansion = true,
			},
			{
				.wildcard_name = {1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},			// \200.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// *.\200.z.example.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {1, '*', 1, 'z', 1, '*', 0},										// *.z.*.
				.is_wildcard_expansion = false,
			},
			{
				.wildcard_name = {0},																// <root>
				.is_wildcard_expansion = false,
			},
		}
	};
	check_compile_time_code(countof(expected_wildcard_expansions) == countof(test_cases_dns_label));

	for (size_t i = 0; i < countof(test_cases_dns_label); i++) {
		dns_obj_error_t err;

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_cases_dns_label[i], true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		for (size_t j = 0; j < countof(expected_wildcard_expansions[i]); j++) {
			const expected_wildcard_expansion_t * const expected_result = &expected_wildcard_expansions[i][j];
			const uint8_t * const wildcard_in_labels = expected_result->wildcard_name;

			dns_obj_domain_name_t wildcard = dns_obj_domain_name_create_with_labels(wildcard_in_labels, true, &err);

			XCTAssertEqual(dns_obj_domain_name_is_a_wildcard_expansion(name, wildcard), expected_result->is_wildcard_expansion);

			MDNS_DISPOSE_DNS_OBJ(wildcard);
		}

		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

- (void) testSetGetClearNSEC3HashedNameWithParams
{
	typedef struct test_case_s {
		const uint8_t	name[MAX_DOMAIN_NAME];
		const uint8_t	algorithm;
		const uint16_t	iterations;
		const uint8_t	salt[MAX_DOMAIN_NAME];
		const uint8_t	salt_length;
		const uint8_t	zone_domain[MAX_DOMAIN_NAME];
		const uint8_t	output[MAX_DIGEST_OUTPUT_SIZE];
		const size_t	output_size;
	} test_case_t;

	const test_case_t test_cases[] = {
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 0,
			.salt_length = 0,
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0xe9, 0xf5, 0x3b, 0xa8, 0x4e, 0xc4, 0xff, 0xc6, 0x94, 0xd9, 0x20, 0x57, 0x61, 0x83, 0x69, 0x2b, 0x30, 0x0c, 0x6a, 0x29},
			.output_size = SHA1_OUTPUT_SIZE,
		},
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 100,
			.salt_length = 0,
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0x0b, 0x3a, 0xec, 0xba, 0xef, 0x64, 0x91, 0xe9, 0x79, 0xd3, 0xa8, 0x53, 0xd5, 0x3e, 0x6e, 0x0f, 0xde, 0x86, 0x24, 0x68},
			.output_size = SHA1_OUTPUT_SIZE,
		},
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 500,
			.salt_length = 0,
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0x85, 0x6d, 0xbc, 0xf0, 0x66, 0x08, 0x08, 0x88, 0x13, 0xe4, 0x46, 0x60, 0xdb, 0x62, 0x33, 0x62, 0xda, 0x34, 0x8d, 0x22},
			.output_size = SHA1_OUTPUT_SIZE,
		},
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 0,
			.salt_length = 1,
			.salt = {'s'},
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0xff, 0xb2, 0xfa, 0x87, 0x6c, 0xfc, 0x09, 0xe6, 0xc9, 0x38, 0x35, 0x4c, 0x87, 0xee, 0xbe, 0x68, 0x83, 0x06, 0xd1, 0x45},
			.output_size = SHA1_OUTPUT_SIZE,
		},
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 100,
			.salt_length = 4,
			.salt = {'s', 'a', 'l', 't'},
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0x00, 0xd6, 0x6e, 0xe0, 0xe5, 0xe4, 0xb4, 0xa1, 0x68, 0xec, 0x2b, 0x70, 0xd0, 0xda, 0xed, 0xf8, 0x13, 0x86, 0x9e, 0xb6},
			.output_size = SHA1_OUTPUT_SIZE,
		},
		{
			.name = {'\x03', 'w', 'w', 'w', '\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.algorithm = NSEC3_HASH_ALGORITHM_SHA_1,
			.iterations = 500,
			.salt_length = 8,
			.salt = {'s', 'a', 'l', 't', 's', 'a', 'l', 't'},
			.zone_domain = {'\x05', 'a', 'p', 'p', 'l', 'e', '\x03', 'c', 'o', 'm', '\x00'},
			.output = {0x72, 0x52, 0x0f, 0x3e, 0x99, 0xef, 0xf8, 0xa6, 0x26, 0xa4, 0xac, 0xe0, 0x70, 0x61, 0x9e, 0x45, 0xd0, 0x52, 0x92, 0x38},
			.output_size = SHA1_OUTPUT_SIZE,
		},
	};

	dns_obj_error_t err;
	for (size_t i = 0; i < countof(test_cases); i++) {
		const test_case_t * const test_case = &test_cases[i];

		dns_obj_domain_name_t name = dns_obj_domain_name_create_with_labels(test_case->name, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		err = dns_obj_domain_name_set_nsec3_hashed_name_with_params(name, test_case->algorithm,
			test_case->iterations, test_case->salt, test_case->salt_length, test_case->zone_domain);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

#define MAX_HASHED_NAME_OUTPUT_SIZE	MAX_DIGEST_OUTPUT_SIZE
		char base32_hex[1 + BASE32_HEX_OUTPUT_SIZE(MAX_HASHED_NAME_OUTPUT_SIZE)];
		base32_hex[0] = (char)base_x_get_encoded_string_length(base_encoding_type_base32_hex_without_padding, test_case->output_size);
		base_x_encode(base_encoding_type_base32_hex_without_padding, test_case->output,
			dns_obj_data_compute_digest_get_output_size(DIGEST_SHA_1), base32_hex + 1);
		const uint8_t * const base32_hex_as_labels = (uint8_t *)base32_hex;

		uint8_t expected_nsec3_hashed_name_in_labels[MAX_DOMAIN_NAME];
		domain_name_labels_concatenate(base32_hex_as_labels, test_case->zone_domain, expected_nsec3_hashed_name_in_labels,
			sizeof(expected_nsec3_hashed_name_in_labels), &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		dns_obj_domain_name_t expected_nsec3_hashed_name = dns_obj_domain_name_create_with_labels(expected_nsec3_hashed_name_in_labels, true, &err);
		XCTAssertEqual(err, DNS_OBJ_ERROR_NO_ERROR);

		XCTAssertTrue(dns_obj_equal(dns_obj_domain_name_get_nsec3_hashed_name(name, NULL), expected_nsec3_hashed_name));

		dns_obj_domain_name_clear_nsec3_hashed_name(name);
		XCTAssertEqual(dns_obj_domain_name_get_nsec3_hashed_name(name, NULL), NULL);

		MDNS_DISPOSE_DNS_OBJ(expected_nsec3_hashed_name);
		MDNS_DISPOSE_DNS_OBJ(name);
	}
}

@end
