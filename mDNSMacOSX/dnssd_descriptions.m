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

#if !__has_feature(objc_arc)
#pragme "GCC error \"This file must be built with ARC\""
#endif

#import "dnssd_object.h"

#import <CoreFoundation/CoreFoundation.h>

#if 0
//======================================================================================================================
#pragma mark - Description Extensions
#endif

@interface OS_OBJECT_CLASS(dnssd_object);
@end

@implementation OS_OBJECT_CLASS(dnssd_object) (descriptions)

- (NSString *)description
{
	char * const desc = dnssd_object_copy_description((dnssd_any_t)self, false, false);
	if (desc) {
		NSString * const string = (__bridge_transfer NSString *)CFStringCreateWithCString(kCFAllocatorDefault, desc, kCFStringEncodingUTF8);
		free(desc);
		return string;
	} else {
		return nil;
	}
}

- (NSString *)debugDescription
{
	char * const desc = dnssd_object_copy_description((dnssd_any_t)self, true, false);
	if (desc) {
		NSString * const string = (__bridge_transfer NSString *)CFStringCreateWithCString(kCFAllocatorDefault, desc, kCFStringEncodingUTF8);
		free(desc);
		return string;
	} else {
		return nil;
	}
}

- (NSString *)redactedDescription
{
	char * const desc = dnssd_object_copy_description((dnssd_any_t)self, false, true);
	if (desc) {
		NSString * const string = (__bridge_transfer NSString *)CFStringCreateWithCString(kCFAllocatorDefault, desc, kCFStringEncodingUTF8);
		free(desc);
		return string;
	} else {
		return nil;
	}
}
@end
