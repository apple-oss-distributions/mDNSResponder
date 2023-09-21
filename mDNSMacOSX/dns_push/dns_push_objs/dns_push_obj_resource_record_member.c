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

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_push_obj_resource_record_member.h"
#include "dns_obj_log.h"
#include "dns_push_obj_context.h"

#include "dns_assert_macros.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Push DNS Question Member Kind Definition

struct dns_push_obj_resource_record_member_s {
	struct ref_count_obj_s		base;					// The reference count and kind support base.
};

DNS_PUSH_OBJECT_DEFINE_FULL(resource_record_member);

//======================================================================================================================
// MARK: - DNS Push Resource Record Member Public Methods

dns_push_obj_resource_record_member_t
dns_push_obj_resource_record_member_create(dns_obj_error_t * const out_error)
{
	dns_push_obj_resource_record_member_t member = _dns_push_obj_resource_record_member_new();

	if (member == NULL && out_error != NULL) {
		*out_error = DNS_OBJ_ERROR_NO_MEMORY;
	}

	return member;
}

//======================================================================================================================
// MARK: - DNS Push Resource Record Member Private Methods

static compare_result_t
_dns_push_obj_resource_record_member_compare(const dns_push_obj_resource_record_member_t UNUSED me,
	const dns_push_obj_resource_record_member_t UNUSED other, const bool UNUSED check_equality_only)
{
	return compare_result_notequal;
}

//======================================================================================================================

static void
_dns_push_obj_resource_record_member_finalize(const dns_push_obj_resource_record_member_t me)
{
	(void)me;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
