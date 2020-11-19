/*
* Copyright (c) 2019 Apple Inc. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#if !defined(__i386__)
#include "bundle_utilities.h"

#import <CoreServices/CoreServicesPriv.h>
#import <CoreUtils/SoftLinking.h>

SOFT_LINK_FRAMEWORK_EX(Frameworks, CoreServices);
SOFT_LINK_CLASS_EX(CoreServices, LSBundleRecord);
#define LSBundleRecordSoft getLSBundleRecordClass()

SOFT_LINK_FRAMEWORK_EX(Frameworks, Foundation);
SOFT_LINK_CLASS_EX(Foundation, NSString);
#define NSStringSoft getNSStringClass()

bool bundle_sdk_is_ios14_or_later(void)
{
#if TARGET_OS_OSX
	#define MIN_SDK_VERSION	"10.16"
#elif TARGET_OS_WATCH
	#define MIN_SDK_VERSION	"7.0"
#else
	#define MIN_SDK_VERSION	"14.0"
#endif
	BOOL result = NO;

	if (LSBundleRecordSoft && NSStringSoft) {
		@autoreleasepool {
			id rec = [LSBundleRecordSoft bundleRecordForCurrentProcess];
			if (rec) {
				NSString * min_vers = [NSStringSoft stringWithUTF8String:MIN_SDK_VERSION];
				NSComparisonResult compare_result = [[rec SDKVersion] compare:min_vers options:NSNumericSearch];
				result = ((compare_result == NSOrderedSame) || (compare_result == NSOrderedDescending));
			}
		}
	}

	return (result != NO);
}
#endif
