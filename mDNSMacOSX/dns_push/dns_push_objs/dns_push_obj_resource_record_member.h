/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DNS_PUSH_OBJ_RESOURCE_RECORD_MEMBER_H
#define DNS_PUSH_OBJ_RESOURCE_RECORD_MEMBER_H

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_obj_rr_soa.h"
#include "dns_push_obj.h"
#include "dns_common.h"
#include <stdint.h>
#include <stdbool.h>

#include "nullability.h"

//======================================================================================================================
// MARK: - Object Reference Definition

DNS_PUSH_OBJECT_TYPEDEF_OPAQUE_POINTER(resource_record_member);

//======================================================================================================================
// MARK: - Object Methods

dns_push_obj_resource_record_member_t NULLABLE
dns_push_obj_resource_record_member_create(dns_obj_error_t * NULLABLE out_error);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_OBJ_RESOURCE_RECORD_MEMBER_H
