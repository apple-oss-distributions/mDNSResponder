/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#undef MDNS_OBJECT_FORCE_NO_OBJC
#define MDNS_OBJECT_FORCE_NO_OBJC	0
#import "mdns_objects.h"

#import <CoreUtils/CoreUtils.h>
#import <Foundation/Foundation.h>
#import <os/object_private.h>

//======================================================================================================================
// MARK: - Class Definitions

#define MDNS_CLASS(NAME)	OS_OBJECT_CLASS(mdns_ ## NAME)

@implementation OS_OBJECT_CLASS(mdns_object)
- (void)dealloc
{
	mdns_object_finalize(self);
	arc_safe_super_dealloc();
}

- (NSString *)description
{
	NSString * const nsstr = (NSString *)CFBridgingTransfer(mdns_object_copy_description_as_cfstring(self));
	return arc_safe_autorelease(nsstr);
}

- (NSString *)debugDescription
{
	NSString * const nsstr = (NSString *)CFBridgingTransfer(mdns_object_copy_debug_description_as_cfstring(self));
	return arc_safe_autorelease(nsstr);
}

- (NSString *)redactedDescription
{
	NSString * const nsstr = (NSString *)CFBridgingTransfer(mdns_object_copy_redacted_description_as_cfstring(self));
	return arc_safe_autorelease(nsstr);
}

- (BOOL)isEqual:(id)other
{
	if (self == other) {
		return YES;
	}
	if (![other isKindOfClass:[MDNS_CLASS(object) class]]) {
		return NO;
	}
	return (mdns_equal(self, (mdns_object_t)other) ? YES : NO);
}
@end

#define MDNS_OBJECT_CLASS_DEFINE(NAME)													\
	_OS_OBJECT_DECL_SUBCLASS_INTERFACE(mdns_ ## NAME, mdns_object)						\
																						\
	@implementation MDNS_CLASS(NAME)													\
	@end																				\
																						\
	mdns_ ## NAME ## _t																	\
	mdns_ ## NAME ## _object_alloc(const size_t size)									\
	{																					\
		return (mdns_ ## NAME ## _t)_os_object_alloc([MDNS_CLASS(NAME) class], size);	\
	}																					\
	extern int _mdns_dummy_variable

MDNS_OBJECT_CLASS_DEFINE(address);
MDNS_OBJECT_CLASS_DEFINE(dns_service);
MDNS_OBJECT_CLASS_DEFINE(dns_service_manager);
MDNS_OBJECT_CLASS_DEFINE(interface_monitor);
MDNS_OBJECT_CLASS_DEFINE(message);
MDNS_OBJECT_CLASS_DEFINE(query_message);
MDNS_OBJECT_CLASS_DEFINE(querier);
MDNS_OBJECT_CLASS_DEFINE(resolver);
MDNS_OBJECT_CLASS_DEFINE(server);
MDNS_OBJECT_CLASS_DEFINE(session);
MDNS_OBJECT_CLASS_DEFINE(set);
MDNS_OBJECT_CLASS_DEFINE(trust);
