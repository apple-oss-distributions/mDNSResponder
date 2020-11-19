//
//	BaseNEncodingDecodingTest.m
//	Tests
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "base_n.h"
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

@interface BaseNEncodingDecodingTest : XCTestCase

@end

@implementation BaseNEncodingDecodingTest

char * encoded_str = NULL;

- (void) testBase64Encoding {
	unsigned char	data_input[1024];
	char *			test_case_ptr;
	char *			answer_ptr;
	char *			test_cases[] = {
		"", "f", "fo", "foo", "foob", "fooba", "foobar"
	};
	char *			answers[] = {
		"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"
	};

	XCTAssertEqual(sizeof(test_cases), sizeof(answers));

	for (int i = 0, limit = sizeof(answers) / sizeof(char *); i < limit; i++) {
		test_case_ptr	= test_cases[i];
		answer_ptr		= answers[i];
		strlcpy((char *)data_input, test_case_ptr, sizeof(data_input));

		XCTAssertEqual(strlen(answer_ptr), get_base_n_encoded_str_length(DNSSEC_BASE_64, strlen(test_case_ptr)));

		encoded_str = base_n_encode(DNSSEC_BASE_64, data_input, strlen(test_case_ptr));
		XCTAssertTrue(encoded_str != NULL);
		XCTAssertTrue(strcmp(encoded_str, answer_ptr) == 0, "i: %d, input: %s, encoded_str: %s, answer_ptr: %s",
			i, test_case_ptr, encoded_str, answer_ptr);

		free(encoded_str);
		encoded_str = NULL;
	}
}

- (void) testBase32HexEncoding {
	unsigned char	data_input[1024];
	char *			test_case_ptr;
	char *			answer_ptr;
	char *			test_cases[] = {
		"", "f", "fo", "foo", "foob", "fooba", "foobar"
	};
	char *			answers[] = {
		"", "CO======", "CPNG====", "CPNMU===", "CPNMUOG=", "CPNMUOJ1", "CPNMUOJ1E8======"
	};

	XCTAssertEqual(sizeof(test_cases), sizeof(answers));

	for (int i = 0, limit = sizeof(answers) / sizeof(char *); i < limit; i++) {
		test_case_ptr			= test_cases[i];
		answer_ptr				= answers[i];
		strlcpy((char *)data_input, test_case_ptr, sizeof(data_input));

		XCTAssertEqual(strlen(answer_ptr), get_base_n_encoded_str_length(DNSSEC_BASE_32_HEX, strlen(test_case_ptr)));

		encoded_str = base_n_encode(DNSSEC_BASE_32_HEX, data_input, strlen(test_case_ptr));
		XCTAssertTrue(encoded_str != NULL);
		XCTAssertTrue(strcmp(encoded_str, answer_ptr) == 0, "i: %d, input: %s, encoded_str: %s, answer_ptr: %s",
			i, test_case_ptr, encoded_str, answer_ptr);

		free(encoded_str);
		encoded_str = NULL;
	}
}

- (void) tearDown {
	if (encoded_str != NULL) {
		free(encoded_str);
	}
}

@end
#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
