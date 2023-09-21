/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
#include "DNSCommon.h"

#ifndef countof
#define countof(X) (sizeof(X) / sizeof(X[0]))
#endif

@interface UTF8ValidatorTest : XCTestCase

@end

@implementation UTF8ValidatorTest

- (void)testAreUTF8String {
    // Testing cases getting from https://www.cl.cam.ac.uk/%7Emgk25/ucs/examples/UTF-8-test.txt.
    const char * const good_utf8_strings[] = {
        "",
        "a",
        "ñ",
        "₡",
        "𐌼",
        "愿世界和平",
        "世界平和を願います",
        "세계 평화를 빕니다",
        "\xc2\x80",
        "𐀀",
        "\xee\x80\x80",
        "🤣",
        // Non-characters but valid UTF-8 See <http://www.unicode.org/versions/corrigendum9.html>
        "\xef\xbf\xbe",
        "\xef\xbf\xbf",
        "\xef\xb7\x90",
        "\xef\xb7\xaf"
    };

    const char * const bad_utf8_strings[] = {
        "\xc3\x28",
        "\xa0\xa1",
        "\xe2\x28\xa1",
        "\xe2\x82\x28",
        "\xf0\x28\x8c\xbc",
        "\xf0\x90\x28\xbc",
        "\xf0\x28\x8c\x28",
        "\xc0\x9f",
        "\xf5\xff\xff\xff",
        "\xed\xa0\x81",
        "\xf8\x90\x80\x80\x80",
        "123456789012345\xed",
        "123456789012345\xf1",
        "123456789012345\xc2",
        "\xC2\x7F",
        "\xce",
        "\xce\xba\xe1",
        "\xce\xba\xe1\xbd",
        "\xce\xba\xe1\xbd\xb9\xcf",
        "\xce\xba\xe1\xbd\xb9\xcf\x83\xce",
        "\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce",
        "\xdf",
        "\xef\xbf",
        "\xfe",
        "\xff",
        "\xfe\xfe\xff\xff",
        "\xc0\xaf",
        "\xe0\x80\xaf",
        "\xf0\x80\x80\xaf",
        "\xf8\x80\x80\x80\xaf",
        "\xfc\x80\x80\x80\x80\xaf",
        "\xc1\xbf",
        "\xe0\x9f\xbf",
        "\xf0\x8f\xbf\xbf",
        "\xf8\x87\xbf\xbf\xbf",
        "\xfc\x83\xbf\xbf\xbf\xbf",
        "\xc0\x80",
        "\xe0\x80\x80",
        "\xf0\x80\x80\x80",
        "\xf8\x80\x80\x80\x80",
        "\xfc\x80\x80\x80\x80\x80",
        "\xed\xa0\x80",
        "\xed\xad\xbf",
        "\xed\xae\x80",
        "\xed\xaf\xbf",
        "\xed\xb0\x80",
        "\xed\xbe\x80",
        "\xed\xbf\xbf",
        "\xed\xa0\x80\xed\xb0\x80",
        "\xed\xa0\x80\xed\xbf\xbf",
        "\xed\xad\xbf\xed\xb0\x80",
        "\xed\xad\xbf\xed\xbf\xbf",
        "\xed\xae\x80\xed\xb0\x80",
        "\xed\xae\x80\xed\xbf\xbf",
        "\xed\xaf\xbf\xed\xb0\x80",
        "\xed\xaf\xbf\xed\xbf\xbf"
    };

    for (size_t i = 0; i < countof(good_utf8_strings); i++) {
        const char *const str = good_utf8_strings[i];
        XCTAssertTrue(mDNSAreUTF8String(str), "i: %zu", i);
    }

    for (size_t i = 0; i < countof(bad_utf8_strings); i++) {
        const char *const str = bad_utf8_strings[i];
        XCTAssertFalse(mDNSAreUTF8String(str), "i: %zu", i);
    }
}

@end
