/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#import <mrc/dns_proxy.h>
#import <mrc/dns_service_registration.h>
#import <mrc/object.h>

#import "mdns_objc_support.h"
#import "mrc_internal.h"
#import "mdns_strict.h"

//======================================================================================================================
// MARK: - Objective-C Class Macros

#define MRC_OBJC_BASE_CLASS_INTERFACE(NAME)			MDNS_COMMON_OBJC_BASE_CLASS_INTERFACE(mrc_ ## NAME)
#define MRC_OBJC_BASE_CLASS_IMPLEMENTATION(NAME)	MDNS_COMMON_OBJC_BASE_CLASS_IMPLEMENTATION(mrc_ ## NAME)
#define MRC_OBJC_CLASS_IMPLEMENTATION(NAME)			MDNS_COMMON_OBJC_CLASS_IMPLEMENTATION(mrc_ ## NAME, mrc_object)

//======================================================================================================================
// MARK: - Objective-C Base Class Interface

MRC_OBJC_BASE_CLASS_INTERFACE(object);

//======================================================================================================================
// MARK: - Objective-C Class Implementations

MRC_OBJC_BASE_CLASS_IMPLEMENTATION(object);

MRC_OBJC_CLASS_IMPLEMENTATION(dns_proxy);
MRC_OBJC_CLASS_IMPLEMENTATION(dns_proxy_parameters);
MRC_OBJC_CLASS_IMPLEMENTATION(dns_proxy_state_inquiry);
MRC_OBJC_CLASS_IMPLEMENTATION(dns_service_registration);
MRC_OBJC_CLASS_IMPLEMENTATION(enabler);

// Workaround until libmrc.dylib can link libmds.dylib without a B&I circular dependency.
#define MRC_MDNS_WORKAROUND(NAME)					\
	MRC_DECL(mdns_ ## NAME);						\
	MRC_OBJC_CLASS_IMPLEMENTATION(mdns_ ## NAME);	\
	const mdns_class_t MDNS_OBJ_CLASS(mdns_ ## NAME) = MDNS_OBJ_CLASS(mrc_mdns_ ## NAME)

MRC_MDNS_WORKAROUND(string_builder);
