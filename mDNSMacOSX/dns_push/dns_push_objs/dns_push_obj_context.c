/*
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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
#include "QuerierSupport.h"
#include "uDNS.h"

#include <mdns/dns_service.h>
#include <mdns/interface_monitor.h>
#include <stdint.h>
#include <stdlib.h>

#include "dns_assert_macros.h"
#include "general.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Push Context Kind Definition

struct dns_push_obj_context_s {
	struct ref_count_obj_s						base;					// The reference count and kind support base.
	dns_obj_domain_name_t						authoritative_zone;		// The authoritative zone of the question.
	dns_obj_domain_name_t						push_service_name;		// The service name of the push service.
	mdns_dns_service_id_t						service_id;				// The ID of the push service registered.
	DNSQuestion *								original_question;		// The question that enables DNS push.
	DNSQuestion *								discovery_question;		// The question for the push service discovery.
	mdns_interface_monitor_t					interface_monitor;		// The interface monitor for network changes.
	uint32_t									if_index;				// The interface of the question uses.
	bool										dns_poll_enabled;		// If DNS polling is enabled for the push query.
};

DNS_PUSH_OBJECT_DEFINE_FULL(context);

//======================================================================================================================
// MARK: - DNS Push Question Context Public Methods

dns_push_obj_context_t
dns_push_obj_context_create(DNSQuestion * const q, dns_obj_error_t * const out_error)
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
		log_error("[Q%u] Unable to start DNS push server discovery for the single-label name (TLD) -- "
			"qname: " PRI_DNS_DM_NAME ", qtype: " PUB_DNS_TYPE, mDNSVal16(q->TargetQID), DNS_DM_NAME_PARAM(q_name),
			DNS_TYPE_PARAM(q_type));
			err = DNS_OBJ_ERROR_PARAM_ERR);

	obj = _dns_push_obj_context_new();
	require_action(obj != NULL, exit, err = DNS_OBJ_ERROR_NO_MEMORY);

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
dns_push_obj_context_set_discovery_question(const dns_push_obj_context_t me, DNSQuestion * const question)
{
	me->discovery_question = question;
}

//======================================================================================================================

DNSQuestion *
dns_push_obj_context_get_discovery_question(const dns_push_obj_context_t me)
{
	return me->discovery_question;
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

dns_obj_domain_name_t
dns_push_obj_context_get_push_service_name(const dns_push_obj_context_t me)
{
	dns_obj_error_t err;
	dns_obj_domain_name_t dns_push_service_type = NULL;
	dns_obj_domain_name_t dns_push_srv = NULL;

	if (me->push_service_name) {
		goto exit;
	}
	if (!me->authoritative_zone) {
		goto exit;
	}
	dns_push_service_type = dns_obj_domain_name_create_with_cstring("_dns-push-tls._tcp", &err);
	mdns_require_noerr_quiet(err, exit);

	dns_push_srv = dns_obj_domain_name_create_concatenation(dns_push_service_type, me->authoritative_zone, &err);
	mdns_require_noerr_quiet(err, exit);

	dns_obj_replace(&me->push_service_name, dns_push_srv);

exit:
	dns_obj_forget(&dns_push_service_type);
	dns_obj_forget(&dns_push_srv);
	return me->push_service_name;
}

//======================================================================================================================

void
dns_push_obj_context_set_service_id(const dns_push_obj_context_t me, const mdns_dns_service_id_t service_id)
{
	me->service_id = service_id;
}

//======================================================================================================================

mdns_dns_service_id_t
dns_push_obj_context_get_service_id(const dns_push_obj_context_t me)
{
	return me->service_id;
}

//======================================================================================================================

void
dns_push_obj_context_set_interface_index(const dns_push_obj_context_t me, const uint32_t if_index)
{
	me->if_index = if_index;
}

//======================================================================================================================

uint32_t
dns_push_obj_context_get_interface_index(const dns_push_obj_context_t me)
{
	return me->if_index;
}

//======================================================================================================================

void
dns_push_obj_context_set_interface_monitor(const dns_push_obj_context_t me, const mdns_interface_monitor_t monitor)
{
	mdns_replace(&me->interface_monitor, monitor);
}

//======================================================================================================================

mdns_interface_monitor_t
dns_push_obj_context_get_interface_monitor(const dns_push_obj_context_t me)
{
	return me->interface_monitor;
}

//======================================================================================================================

void
dns_push_obj_context_set_dns_polling_enabled(const dns_push_obj_context_t me, const bool dns_polling_enabled)
{
	me->dns_poll_enabled = dns_polling_enabled;
}

//======================================================================================================================

bool
dns_push_obj_context_get_dns_polling_enabled(const dns_push_obj_context_t me)
{
	return me->dns_poll_enabled;
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
	dns_obj_forget(&me->authoritative_zone);
	dns_obj_forget(&me->push_service_name);
	mdns_forget(&me->interface_monitor);
	if (me->service_id != MDNS_DNS_SERVICE_INVALID_ID) {
		const mdns_dns_service_manager_t manager = Querier_GetDNSServiceManager();
		if (manager) {
			mdns_dns_service_manager_deregister_discovered_push_service(manager, me->service_id);
		}
	}
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
