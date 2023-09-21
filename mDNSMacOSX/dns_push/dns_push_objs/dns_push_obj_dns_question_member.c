/*
 * Copyright (c) 2022-2023 Apple Inc. All rights reserved.
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

#include "dns_push_obj_dns_question_member.h"

#include "dns_obj_log.h"
#include "dns_push_obj_context.h"
#include "general.h"

#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Push DNS Question Member Kind Definition

struct dns_push_obj_dns_question_member_s {
	struct ref_count_obj_s		base;					// The reference count and kind support base.
	dns_push_obj_context_t		context;
};

DNS_PUSH_OBJECT_DEFINE_FULL(dns_question_member);

//======================================================================================================================
// MARK: - DNS Push DNS Question Member Public Methods

dns_push_obj_dns_question_member_t
dns_push_obj_dns_question_member_create(dns_obj_error_t * const out_error)
{
	dns_obj_error_t err;
	dns_push_obj_dns_question_member_t member = NULL;
	dns_push_obj_dns_question_member_t obj = NULL;

	obj = _dns_push_obj_dns_question_member_new();
	mdns_require_action_quiet(obj != NULL, exit, err = DNS_OBJ_ERROR_NO_MEMORY);

	obj->context = NULL;

	member = obj;
	obj = NULL;
	err = DNS_OBJ_ERROR_NO_ERROR;

exit:
	mdns_assign(out_error, err);
	dns_push_obj_forget(&obj);
	return member;
}

//======================================================================================================================

void
dns_push_obj_dns_question_member_set_context(const dns_push_obj_dns_question_member_t member,
	const dns_push_obj_context_t context)
{
	dns_push_obj_replace(&member->context, context);
}

//======================================================================================================================

dns_push_obj_context_t
dns_push_obj_dns_question_member_get_context(const dns_push_obj_dns_question_member_t member)
{
	return member->context;
}

//======================================================================================================================
// MARK: - DNS Push DNS Question Member Private Methods

static compare_result_t
_dns_push_obj_dns_question_member_compare(const dns_push_obj_dns_question_member_t UNUSED me,
	const dns_push_obj_dns_question_member_t UNUSED other, const bool UNUSED check_equality_only)
{
	return compare_result_notequal;
}

//======================================================================================================================

static void
_dns_push_obj_dns_question_member_finalize(const dns_push_obj_dns_question_member_t me)
{
	MDNS_DISPOSE_DNS_PUSH_OBJ(me->context);
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
