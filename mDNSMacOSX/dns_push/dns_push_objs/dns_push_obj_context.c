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

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_push_obj_context.h"

#include "dns_common.h"
#include "dns_obj_domain_name.h"
#include "dns_obj_log.h"
#include "dns_push_obj.h"
#include "uDNS.h"

#include <stdint.h>
#include <stdlib.h>

#include "dns_assert_macros.h"
#include "general.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Push Context Kind Definition

struct dns_push_obj_context_s {
	struct ref_count_obj_s						base;					// The reference count and kind support base.
	dns_obj_rr_soa_t							authority_soa;
	dns_obj_domain_name_t						authoritative_zone;
	dns_push_obj_discovered_service_manager_t	service_manager;
	mDNS *										m;						// The mDNSStorage pointer for the mDNSCore.
	DNSQuestion *								original_question;		// The question that enables DNS push.
	DNSQuestion *								soa_question;			// The secondary question for authoritative zone
																		// discovery
};

DNS_PUSH_OBJECT_DEFINE_FULL(context);

//======================================================================================================================
// MARK: - DNS Push Question Context Public Methods

dns_push_obj_context_t
dns_push_obj_context_create(mDNS *const m, DNSQuestion * const q, dns_obj_error_t * const out_error)
{
	dns_obj_error_t err;
	dns_obj_domain_name_t q_name = NULL;
	dns_push_obj_context_t context = NULL;
	dns_push_obj_context_t obj = NULL;

	q_name = dns_obj_domain_name_create_with_labels(q->qname.c, true, &err);
	require_noerr(err, exit);

	const uint16_t q_type = q->qtype;

	const bool is_single_label = (dns_obj_domain_name_is_single_label(q_name));
	require_action(!is_single_label, exit,
		log_error("Unable to start DNS push server discovery for the single-label name (TLD) -- "
			"qname: " PRI_DNS_DM_NAME ", qtype: " PUB_DNS_TYPE, DNS_DM_NAME_PARAM(q_name), DNS_TYPE_PARAM(q_type));
			err = DNS_OBJ_ERROR_PARAM_ERR);

	obj = _dns_push_obj_context_new();
	require_action(obj != NULL, exit, err = DNS_OBJ_ERROR_NO_MEMORY);

	obj->m = m;
	obj->original_question = q;

	context = obj;
	obj = NULL;
	err = DNS_OBJ_ERROR_NO_ERROR;

exit:
	mdns_assign(out_error, err);
	MDNS_DISPOSE_DNS_OBJ(q_name);
	MDNS_DISPOSE_DNS_PUSH_OBJ(obj);
	return context;
}

//======================================================================================================================

void
dns_push_obj_context_set_soa_question(const dns_push_obj_context_t me, DNSQuestion * const soa_question)
{
	me->soa_question = soa_question;
}

//======================================================================================================================

DNSQuestion *
dns_push_obj_context_get_soa_question(const dns_push_obj_context_t me)
{
	return me->soa_question;
}

//======================================================================================================================

DNSQuestion *
dns_push_obj_context_get_original_question(const dns_push_obj_context_t me)
{
	return me->original_question;
}

//======================================================================================================================

void
dns_push_obj_context_set_authoritative_zone(const dns_push_obj_context_t me, const dns_obj_domain_name_t zone)
{
	dns_obj_replace(&me->authoritative_zone, zone);
}

//======================================================================================================================

dns_obj_domain_name_t NULLABLE
dns_push_obj_context_get_authoritative_zone(const dns_push_obj_context_t me)
{
	return me->authoritative_zone;
}

//======================================================================================================================

void
dns_push_obj_context_set_service_manager(const dns_push_obj_context_t me,
	const dns_push_obj_discovered_service_manager_t manager)
{
	dns_push_obj_replace(&me->service_manager, manager);
}

//======================================================================================================================

dns_push_obj_discovered_service_manager_t
dns_push_obj_context_get_service_manager(const dns_push_obj_context_t me)
{
	return me->service_manager;
}

//======================================================================================================================
// MARK: - DNS Push Question Context Private Methods

static compare_result_t
_dns_push_obj_context_compare(const dns_push_obj_context_t me, const dns_push_obj_context_t other, const bool UNUSED check_equality_only)
{
	// Context can only be checked for the equality.
	return me == other ? compare_result_equal : compare_result_notequal;
}

//======================================================================================================================

static void
_dns_push_obj_context_finalize(const dns_push_obj_context_t me)
{
	dns_obj_forget(&me->authority_soa);
	dns_obj_forget(&me->authoritative_zone);
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
