//
//	ValidationMethodsTest.m
//	Tests
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "dnssec_v2_crypto.h"
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

@interface CanonicalMethodsTest : XCTestCase

@end

@implementation CanonicalMethodsTest

- (void)test_copy_canonical_name {
	mDNSu8 canonical_name[MAX_DOMAIN_NAME];
	mDNSu8 name_length;

	mDNSu8 name_1[MAX_DOMAIN_NAME] = {
		3,
		'w', 'W', 'w',
		5,
		'a', 'p', 'p', 'l', 'e',
		3,
		'c', 'O', 'm',
		0
	};
	mDNSu8 name_1_after_conversion[MAX_DOMAIN_NAME] = {
		3,
		'w', 'w', 'w',
		5,
		'a', 'p', 'p', 'l', 'e',
		3,
		'c', 'o', 'm',
		0
	};

	for (unsigned long i = 15; i < sizeof(name_1); i++) {
		name_1[i] = 255;
	}

	// basic test
	name_length = copy_canonical_name_ut(canonical_name, name_1);
	XCTAssertEqual(name_length, DomainNameLength((domainname *)name_1_after_conversion));
	XCTAssert(memcmp(canonical_name, name_1_after_conversion, name_length) == 0);
}

- (void)test_compare_canonical_dns_name {
	const unsigned char inputs[][256] = {
		{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},									// example.
		{1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},							// a.example.
		{8, 'y', 'l', 'j', 'k', 'j', 'l', 'j', 'k', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},	// yljkjljk.a.example.
		{1, 'Z', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// Z.a.example.
		{4, 'z', 'A', 'B', 'C', 1, 'a', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0},	// zABC.a.EXAMPLE.
		{1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},							// z.example.
		{1,	1 , 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// \001.z.example.
		{1, '*', 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},					// *.z.example
		{1, 200, 1, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}					// \200.z.example.
	};

	for (size_t i = 0; i < sizeof(inputs) / 256; i++) {
		for (size_t j = 0; j < sizeof(inputs) / 256; j++) {
			if (i < j) {
				XCTAssertTrue(compare_canonical_dns_name(inputs[i], inputs[j]) < 0);
			} else if (i > j) {
				XCTAssertTrue(compare_canonical_dns_name(inputs[i], inputs[j]) > 0);
			} else { // i == j
				XCTAssertTrue(compare_canonical_dns_name(inputs[i], inputs[j]) == 0);
			}
		}
	}
}

@end
#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
