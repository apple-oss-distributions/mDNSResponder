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

#ifndef DNS_PUSH_MDNS_CORE_H

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "mDNSEmbeddedAPI.h"

#include <stdbool.h>
#include <stdint.h>

#include "general.h"
#include "nullability.h"

//======================================================================================================================
// MARK: - Functions

NULLABILITY_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

bool
dns_question_enables_dns_push(const DNSQuestion *question);

dns_push_obj_context_t NULLABLE
dns_question_get_dns_push_context(const DNSQuestion *question);

dns_obj_domain_name_t NULLABLE
dns_question_get_authoritative_zone(const DNSQuestion *question);

__END_DECLS

NULLABILITY_ASSUME_NONNULL_END

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_MDNS_CORE_H
