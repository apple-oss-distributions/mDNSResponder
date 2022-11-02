/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#include "unittest_common.h"
#include "ApplePlatformFeatures.h"		// For MDNSRESPONDER_SUPPORTS(APPLE, SECURE_HMAC_ALGORITHM_2022)
#include "mDNSEmbeddedAPI.h"			// For DNSDigest-related functions.
#include <CommonCrypto/CommonHMAC.h>	// For CCHmac* APIs.
#include <CoreUtils/Base64Utils.h>		// For base64 Base64Decode().
#import <XCTest/XCTest.h>

@interface DNSDigestTest : XCTestCase

@end

@implementation DNSDigestTest

- (void)setUp {
	// It is empty for now.
}

- (void)tearDown {
	// It is empty for now.
}

- (void)testHMACMD5 {
#if !MDNSRESPONDER_SUPPORTS(APPLE, SECURE_HMAC_ALGORITHM_2022)
	static const char * const message_to_sign[] = {"", "This is the message to be signed"};
	static const char hmac_md5_key_base64[] = "okaVQ4ACBE0IwKt+TJrR+w==";

	for (uint32_t i = 0; i < countof(message_to_sign); i++) {
		// First calculate the correct HMAC result using CommonCrypto.
		uint8_t key_bytes[1024];
		check_compile_time(Base64DecodedMaxSize(sizeof(hmac_md5_key_base64) - 1) <= sizeof(key_bytes));

		// Get key in bytes.
		size_t key_length;
		const OSStatus err = Base64Decode(hmac_md5_key_base64, sizeof(hmac_md5_key_base64) - 1, key_bytes,
										  sizeof(key_bytes), &key_length);
		XCTAssertEqual(err, kNoErr);

		CCHmacContext cc_hmac_md5_context;
		CCHmacInit(&cc_hmac_md5_context, kCCHmacAlgMD5, key_bytes, key_length);
		CCHmacUpdate(&cc_hmac_md5_context, message_to_sign[i], strlen(message_to_sign[i]));

		uint8_t cc_hmac[CC_MD5_DIGEST_LENGTH];
		CCHmacFinal(&cc_hmac_md5_context, cc_hmac);

		// Now calculate the HMAC using the functions in DNSDigest.c.
		DomainAuthInfo key_info;
		const mDNSs32 key_info_length = DNSDigest_ConstructHMACKeyfromBase64(&key_info, hmac_md5_key_base64);
		XCTAssertGreaterThan(key_info_length, 0);
		XCTAssertEqual((size_t)key_info_length, key_length);

		// Since MD5 has been deprecated, calling MD5 functions will generate a deprecation warning. To test it, ignore
		// the warning.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		// Digest inner key pad.
		MD5_CTX hmac_md5_context;
		MD5_Init(&hmac_md5_context);
		MD5_Update(&hmac_md5_context, key_info.keydata_ipad, HMAC_LEN);

		// Sign the actual data.
		MD5_Update(&hmac_md5_context, message_to_sign[i], strlen(message_to_sign[i]));
		uint8_t dnsdigest_hmac[MD5_LEN];
		MD5_Final(dnsdigest_hmac, &hmac_md5_context);

		// Digest outer MD5 (outer key pad, inner digest).
		MD5_Init(&hmac_md5_context);
		MD5_Update(&hmac_md5_context, key_info.keydata_opad, HMAC_LEN);
		MD5_Update(&hmac_md5_context, dnsdigest_hmac, MD5_LEN);
		MD5_Final(dnsdigest_hmac, &hmac_md5_context);
#pragma clang diagnostic pop

		check_compile_time(CC_MD5_DIGEST_LENGTH == MD5_LEN);
		// The actual test.
		XCTAssertTrue(memcmp(cc_hmac, dnsdigest_hmac, CC_MD5_DIGEST_LENGTH) == 0);
	}
#endif
}

@end
