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

/*!
 *	@brief
 *		Checks if the DNS question has requested DNS push and is allowed to use DNS push.
 *
 *	@param question
 *		The newly created DNS question.
 *
 *	@return
 *		True if the DNS question has requested DNS push and is allowed to use DNS push.
 *		Otherwise, false.
 *
 *	@discussion
 *		This function is different from the `dns_question_uses_dns_push` below, which checks if the DNS question is actively doing DNS push.
 *		This function is used to determine if the caller should start DNS push for the question.
 */
bool
dns_question_enables_dns_push(const DNSQuestion *question);

/*!
 *	@brief
 *		Checks if the DNS question is in the progress of doing DNS push.
 *
 *	@param question
 *		The DNS question.
 *
 *	@return
 *		True, if the DNS question is actively doing DNS push. Otherwise, false.
 */
bool
dns_question_uses_dns_push(const DNSQuestion *question);

/*!
 *	@brief
 *		Checks if the DNS question tries DNS push but eventually falls back to DNS polling.
 *
 *	@param question
 *		The DNS question.
 *
 *	@return
 *		True, if the DNS question falls back to DNS polling due to no DNS push service availability. Otherwise, false.
 */
bool
dns_question_uses_dns_polling(const DNSQuestion *question);

dns_push_obj_context_t NULLABLE
dns_question_get_dns_push_context(const DNSQuestion *question);

dns_obj_domain_name_t NULLABLE
dns_question_get_authoritative_zone(const DNSQuestion *question);

/*!
 *	@brief
 *		Check if the current DNS push question has finished the discovery process.
 *
 *	@param question
 *		The DNS question.
 *
 *	@result
 *		True if the discovery process has been finished, otherwise, false.
 */
bool
dns_question_finished_push_discovery(const DNSQuestion *question);

__END_DECLS

NULLABILITY_ASSUME_NONNULL_END

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_MDNS_CORE_H
