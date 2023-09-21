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

#include "dns_push_discovery.h"

#include "discover_resolver.h"
#include "dns_push_obj_discovered_service_manager.h"
#include "dns_push_obj_dns_question_member.h"
#include "dns_obj_rr.h"
#include "dns_obj_rr_srv.h"
#include "dns_push_obj_context.h"
#include "dns_push_mdns_core.h"
#include "dns_common.h"
#include "DNSCommon.h"
#include "uDNS.h"

#include "dns_assert_macros.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Local Structures

// g_discovered_service_managers is responsible for registering/deregistering DNS push service for non-local domain. It
// has a "use_count" that remembers how many questions are using the registered DNS push service, when the "use_count"
// becomes zero or the authoritative zone goes away, the corresponding service will be deregistered (no matter what value
// "use_count" has).

typedef struct discovered_service_manager_list_item_t discovered_service_manager_list_item_t;

struct discovered_service_manager_list_item_t {
	dns_push_obj_discovered_service_manager_t	manager;
	discovered_service_manager_list_item_t		*next;
	size_t										use_count;
};

static discovered_service_manager_list_item_t *g_discovered_service_managers;

//======================================================================================================================
// MARK: - Local Prototypes

static DNSQuestion *
_dns_push_discover_start_discovery(mDNS *m, const DNSQuestion *question, dns_push_obj_context_t context);

static void
_dns_push_discovery_soa_result_reply(mDNS *m, DNSQuestion *question, const ResourceRecord *answer, QC_result event);

static void
_dns_push_discovery_try_next_qname(mDNS *m, DNSQuestion *question, dns_obj_domain_name_t new_q_name);

static dns_obj_error_t
_dns_push_discovery_register_push_service(dns_push_obj_context_t context, dns_obj_domain_name_t name,
	uint32_t if_index);

static void
_dns_push_discovery_deregister_push_service(dns_push_obj_discovered_service_manager_t manager,
	bool deregister_unconditionally);

//======================================================================================================================
// MARK: - Public Functions

dns_obj_error_t
dns_push_handle_question_start(mDNS * const m, DNSQuestion * const question)
{
	dns_obj_error_t err;
	dns_push_obj_dns_question_member_t dns_question_member = NULL;
	dns_push_obj_context_t context = NULL;

	mdns_require_action_quiet(!question->enableDNSSEC, exit, err = DNS_OBJ_ERROR_PARAM_ERR);

	dns_question_member = dns_push_obj_dns_question_member_create(&err);
	mdns_require_action_quiet(dns_question_member != NULL, exit, err = DNS_OBJ_ERROR_NO_MEMORY);

	dns_push_obj_replace(&question->dns_push, dns_question_member);

	context = dns_push_obj_context_create(m, question, &err);
	mdns_require_noerr_quiet(err, exit);

	dns_push_obj_dns_question_member_set_context(dns_question_member, context);

	DNSQuestion * const soa_q = _dns_push_discover_start_discovery(m, question, context);
	mdns_require_action_quiet(soa_q, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	dns_push_obj_context_set_soa_question(context, soa_q);
	err = DNS_OBJ_ERROR_NO_ERROR;

exit:
	dns_push_obj_forget(&dns_question_member);
	dns_push_obj_forget(&context);
	if (err) {
		dns_push_handle_question_stop(m, question);
	}
	return err;
}

//======================================================================================================================

void
dns_push_handle_question_stop(mDNS * const m, DNSQuestion * const question)
{
	mdns_require_return(question->dns_push);

	const dns_push_obj_context_t context = dns_push_obj_dns_question_member_get_context(question->dns_push);
	mdns_require_return(context);

	// Stop the SOA question that is created to determine the authoritative zone.
	DNSQuestion *soa_question = dns_push_obj_context_get_soa_question(context);
	if (soa_question) {
		mDNS_StopQuery_internal(m, soa_question);
		mdns_free(soa_question);
		dns_push_obj_context_set_soa_question(context, NULL);
	}

	// Decrease the use count and release the service manager reference hold by the context.
	const dns_push_obj_discovered_service_manager_t service_manager = dns_push_obj_context_get_service_manager(context);
	if (service_manager) {
		_dns_push_discovery_deregister_push_service(service_manager, false);
		dns_push_obj_context_set_service_manager(context, NULL);
	}

	dns_push_obj_forget(&question->dns_push);
}

//======================================================================================================================
// MARK: - Private Functions

static DNSQuestion *
_dns_push_discover_start_discovery(mDNS * const m, const DNSQuestion * const q, const dns_push_obj_context_t context)
{
	DNSQuestion *soa_q = NULL;
	bool failed = false;

	soa_q = mdns_calloc(1, sizeof(*soa_q));
	mdns_require_quiet(soa_q, exit);

	// Set up a new SOA question for the original question name.
	soa_q->InterfaceID = q->InterfaceID;
	AssignDomainName(&soa_q->qname, &q->qname);
	soa_q->qtype = kDNSServiceType_SOA;
	soa_q->qclass = q->qclass;
	soa_q->pid = mDNSPlatformGetPID();
	soa_q->QuestionCallback = _dns_push_discovery_soa_result_reply;
	soa_q->QuestionContext = context;
	soa_q->ReturnIntermed = mDNStrue;

	const mStatus q_start_error = mDNS_StartQuery_internal(m, soa_q);
	mdns_require_noerr_action_quiet(q_start_error, exit, failed = true);

exit:
	if (failed) {
		mdns_free(soa_q);
	}
	return soa_q;
}

//======================================================================================================================

static void
_dns_push_discovery_soa_result_reply(mDNS * const m, DNSQuestion * const question, const ResourceRecord * const answer,
	const QC_result event)
{
	dns_obj_error_t err;
	dns_obj_domain_name_t zone_cut = NULL;
	dns_obj_domain_name_t current_qname = NULL;
	dns_obj_domain_name_t next_qname = NULL;

	// When the query is suppressed due to no DNS service, we return directly and wait for the DNS service being
	// configured by resolver discovery.
	if (event == QC_suppressed) {
		return;
	}

	const dns_push_obj_context_t context = (dns_push_obj_context_t) question->QuestionContext;
	const dns_push_obj_discovered_service_manager_t manager = dns_push_obj_context_get_service_manager(context);

	if (event == QC_add) {
		if (answer->RecordType == kDNSRecordTypePacketNegative) {
			// No Data or NXDomain.
			// The current name is not an authoritative zone, striping one label off and try the new name (Finished
			// below).
		} else {
			// Positive SOA.
			require(SameDomainName(&question->qname, answer->name), exit);
			require(answer->rrtype == kDNSRecordType_SOA, exit);

			zone_cut = dns_obj_domain_name_create_with_labels(answer->name->c, false, &err);
			require_noerr(err, exit);
		}

		if (zone_cut != NULL) {
			mdns_require_quiet(!manager, exit);

			// Have found the zone cut.
			dns_push_obj_context_set_authoritative_zone(context, zone_cut);

			const uint32_t if_index = (uint32_t)((uintptr_t)answer->InterfaceID);
			err = _dns_push_discovery_register_push_service(context, zone_cut, if_index);
			mdns_require_noerr_quiet(err, exit);

		} else {
			// Have not found the zone cut, try its parent label until root label.
			if (!next_qname) {
				mdns_require_quiet(!IsRootDomain(&question->qname), exit);
				const uint8_t * const next_qname_labels = (SecondLabel(&question->qname)->c);
				next_qname = dns_obj_domain_name_create_with_labels(next_qname_labels, true, &err);
				mdns_require_noerr_quiet(err, exit);
			}
			_dns_push_discovery_try_next_qname(m, question, next_qname);
		}
	} else {
		// If we received a remove event, then the authoritative zone has gone, so the corresponding DNS push service
		// should also be deregistered.
		mdns_require_quiet(event == QC_rmv, exit);
		mdns_require_quiet(manager, exit);

		dns_push_obj_context_set_authoritative_zone(context, NULL);

		_dns_push_discovery_deregister_push_service(manager, true);
		dns_push_obj_context_set_service_manager(context, NULL);
	}

exit:
	dns_obj_forget(&zone_cut);
	dns_obj_forget(&current_qname);
	dns_obj_forget(&next_qname);
}

//======================================================================================================================

static void
_dns_push_discovery_try_next_qname(mDNS * const m, DNSQuestion * const question, const dns_obj_domain_name_t new_q_name)
{
	m->RestartQuestion = question;
	mDNS_StopQuery(m, question);

	const uint8_t * const labels = dns_obj_domain_name_get_labels(new_q_name);
	const size_t labels_length = dns_obj_domain_name_get_length(new_q_name);
	require_return(labels_length < sizeof(question->qname.c));

	memcpy(question->qname.c, labels, labels_length);
	question->qnamehash = DomainNameHashValue(&question->qname);

	mDNS_StartQuery(m, question);
}

//======================================================================================================================

static dns_obj_error_t
_dns_push_discovery_register_push_service(const dns_push_obj_context_t context,
	const dns_obj_domain_name_t zone, const uint32_t if_index)
{
	dns_obj_error_t err;

	// Check if we already have a registered manager that manages the required DNS push service.
	dns_push_obj_discovered_service_manager_t manager = NULL;
	discovered_service_manager_list_item_t **pptr = &g_discovered_service_managers;
	while (*pptr) {
		if (dns_push_obj_discovered_service_manager_manages_this_zone((*pptr)->manager, zone, if_index)) {
			break;
		}
	}
	if ((*pptr)) {
		// If we have found an existing one, use it.
		manager = (*pptr)->manager;
		dns_push_obj_retain(manager);
	} else {
		// Otherwise, create a new one.
		manager = dns_push_obj_discovered_service_manager_create(zone, if_index, &err);
		mdns_require_noerr_quiet(err, exit);

		*pptr = mdns_calloc(1, sizeof(*(*pptr)));
		mdns_require_action_quiet(*pptr, exit, err = DNS_OBJ_ERROR_NO_MEMORY);

		(*pptr)->manager = manager;
		dns_push_obj_retain((*pptr)->manager);
	}
	// Increase the use count.
	(*pptr)->use_count++;
	dns_push_obj_context_set_service_manager(context, manager);
	err = DNS_OBJ_ERROR_NO_ERROR;

exit:
	dns_push_obj_forget(&manager);
	return err;
}

//======================================================================================================================

static void
_dns_push_discovery_deregister_push_service(const dns_push_obj_discovered_service_manager_t manager,
	const bool deregister_unconditionally)
{
	discovered_service_manager_list_item_t **pptr = &g_discovered_service_managers;
	while (*pptr) {
		if ((*pptr)->manager == manager) {

			if (!deregister_unconditionally) {
				(*pptr)->use_count--;
			} else {
				// If we deregister it unconditionally, set use count to 0 so that it will be removed immediately.
				(*pptr)->use_count = 0;
			}

			if ((*pptr)->use_count == 0) {
				dns_push_obj_forget(&(*pptr)->manager);
				discovered_service_manager_list_item_t *item_to_delete = *pptr;
				*pptr = (*pptr)->next;
				mdns_free(item_to_delete);
			}
			break;
		}
	}
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
