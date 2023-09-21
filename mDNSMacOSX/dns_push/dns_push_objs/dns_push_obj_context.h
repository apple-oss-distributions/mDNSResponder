/*
 * Copyright (c) 2022-2023 Apple Inc. All rights reserved.
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

#ifndef DNS_PUSH_OBJ_CONTEXT_H
#define DNS_PUSH_OBJ_CONTEXT_H

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_common.h"
#include "dns_obj_rr_soa.h"
#include "dns_push_obj.h"
#include "dns_push_obj_discovered_service_manager.h"
#include "general.h"
#include "mDNSEmbeddedAPI.h"
#include "nullability.h"

#include <stdint.h>
#include <stdbool.h>

//======================================================================================================================
// MARK: - Object Reference Definition

DNS_PUSH_OBJECT_TYPEDEF_OPAQUE_POINTER(context);

//======================================================================================================================
// MARK: - Object Methods

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

dns_push_obj_context_t NULLABLE
dns_push_obj_context_create(mDNS *m, DNSQuestion *q, dns_obj_error_t * NULLABLE out_error);

void
dns_push_obj_context_set_soa_question(dns_push_obj_context_t context, DNSQuestion * NULLABLE soa_question);

DNSQuestion *
dns_push_obj_context_get_soa_question(dns_push_obj_context_t context);

DNSQuestion *
dns_push_obj_context_get_original_question(dns_push_obj_context_t context);

void
dns_push_obj_context_set_authoritative_zone(dns_push_obj_context_t context, dns_obj_domain_name_t NULLABLE zone);

dns_obj_domain_name_t NULLABLE
dns_push_obj_context_get_authoritative_zone(dns_push_obj_context_t context);

void
dns_push_obj_context_set_service_manager(dns_push_obj_context_t context,
	dns_push_obj_discovered_service_manager_t NULLABLE manager);

dns_push_obj_discovered_service_manager_t NULLABLE
dns_push_obj_context_get_service_manager(dns_push_obj_context_t context);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_OBJ_CONTEXT_H
