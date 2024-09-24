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

#import "mrcs_object.h"
#import "mrcs_dns_proxy.h"
#import "mrcs_server_internal.h"

#import "mdns_objc_support.h"
#import "mdns_strict.h"

//======================================================================================================================
// MARK: - Objective-C Class Macros

#define MRCS_OBJC_BASE_CLASS_INTERFACE(NAME)		MDNS_COMMON_OBJC_BASE_CLASS_INTERFACE(mrcs_ ## NAME)
#define MRCS_OBJC_BASE_CLASS_IMPLEMENTATION(NAME)	MDNS_COMMON_OBJC_BASE_CLASS_IMPLEMENTATION(mrcs_ ## NAME)
#define MRCS_OBJC_CLASS_IMPLEMENTATION(NAME)		MDNS_COMMON_OBJC_CLASS_IMPLEMENTATION(mrcs_ ## NAME, mrcs_object)

//======================================================================================================================
// MARK: - Objective-C Base Class Interface

MRCS_OBJC_BASE_CLASS_INTERFACE(object);

//======================================================================================================================
// MARK: - Objective-C Class Implementations

MRCS_OBJC_BASE_CLASS_IMPLEMENTATION(object);

MRCS_OBJC_CLASS_IMPLEMENTATION(dns_proxy);
MRCS_OBJC_CLASS_IMPLEMENTATION(dns_proxy_manager);
MRCS_OBJC_CLASS_IMPLEMENTATION(dns_proxy_request);
MRCS_OBJC_CLASS_IMPLEMENTATION(dns_service_registration_request);
MRCS_OBJC_CLASS_IMPLEMENTATION(session);
