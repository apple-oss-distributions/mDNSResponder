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

#include "dns_push_discovery.h"

#include "discover_resolver.h"
#include "dns_push_obj_dns_question_member.h"
#include "dns_obj_log.h"
#include "dns_obj_rr.h"
#include "dns_obj_rr_srv.h"
#include "dns_push_obj_context.h"
#include "dns_push_mdns_core.h"
#include "dns_common.h"
#include "DNSCommon.h"
#include "mDNSMacOSX.h"
#include "QuerierSupport.h"
#include "uDNS.h"

#include "dns_assert_macros.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Local Structures

typedef struct interface_monitor_list_s interface_monitor_list_s;
struct interface_monitor_list_s {
	mdns_interface_monitor_t	monitor;	// The interface monitor object.
	size_t						use_count;	// The number active push questions that use this interface monitor.
	interface_monitor_list_s	*next;		// The next monitor in the list.
};
static interface_monitor_list_s *g_interface_monitors; // The global interface monitor list.

extern mDNS mDNSStorage;

//======================================================================================================================
// MARK: - Local Prototypes

static dispatch_queue_t
_dns_push_discovery_interface_monitor_queue(void);

static DNSQuestion *
_dns_push_discovery_start_soa(mDNS *m, const DNSQuestion *question, dns_push_obj_context_t context);

static DNSQuestion *
_dns_push_discovery_start_srv(mDNS *m, mDNSInterfaceID if_id, dns_push_obj_context_t context);

static void
_dns_push_discovery_stop(mDNS *m, DNSQuestion **q_pptr, dns_push_obj_context_t context, bool hold_lock);

static void
_dns_push_discovery_soa_result_reply(mDNS *m, DNSQuestion *question, const ResourceRecord *answer, QC_result event);

static void
_dns_push_discovery_srv_result_reply(mDNS *m, DNSQuestion *question, const ResourceRecord *answer, QC_result event);

static void
_dns_push_discovery_fallback_to_dns_polling(dns_push_obj_context_t context);

static void
_dns_push_discovery_stop_dns_polling(dns_push_obj_context_t context);

static void
_dns_push_discovery_try_next_qname(mDNS *m, DNSQuestion *question, dns_obj_domain_name_t new_q_name);

static mdns_interface_monitor_t
_dns_push_discovery_start_interface_monitor(uint32_t if_index);

static mdns_interface_monitor_t
_dns_push_discovery_start_mdns_interface_monitor(uint32_t if_index);

static void
_dns_push_discovery_process_interface_changes(mDNS *m, mdns_interface_monitor_t monitor);

static void
_dns_push_discovery_stop_interface_monitor(mdns_interface_monitor_t monitor);

static mdns_dns_service_id_t
_dns_push_discovery_register_push_service(dns_push_obj_context_t context, dns_obj_domain_name_t name,
	uint32_t if_index, bool *out_duplicate, dns_obj_error_t *out_error);

static void
_dns_push_discovery_deregister_push_service(dns_push_obj_context_t context);

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
	question->LongLived = false; // Disable old DNS push code.

	context = dns_push_obj_context_create(question, &err);
	mdns_require_noerr_quiet(err, exit);

	dns_push_obj_dns_question_member_set_context(dns_question_member, context);

	DNSQuestion * const soa_q = _dns_push_discovery_start_soa(m, question, context);
	mdns_require_action_quiet(soa_q, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	dns_push_obj_context_set_discovery_question(context, soa_q);
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
	const dns_push_obj_context_t context = dns_question_get_dns_push_context(question);
	mdns_require_return(context);

	// Stop the SOA or SRV question that is started to determine the authoritative zone and the push capability.
	DNSQuestion *discovery_question = dns_push_obj_context_get_discovery_question(context);
	if (discovery_question) {
		_dns_push_discovery_stop(m, &discovery_question, context, false);
		dns_push_obj_context_set_discovery_question(context, NULL);
	}
	_dns_push_discovery_deregister_push_service(context);

	const mdns_interface_monitor_t monitor = dns_push_obj_context_get_interface_monitor(context);
	if (monitor) {
		_dns_push_discovery_stop_interface_monitor(monitor);
		dns_push_obj_context_set_interface_monitor(context, NULL);
	}

	dns_push_obj_forget(&question->dns_push);
	question->LongLived = mDNStrue;
}

//======================================================================================================================
// MARK: - Private Functions

static dispatch_queue_t
_dns_push_discovery_interface_monitor_queue(void)
{
	static dispatch_once_t s_once = 0;
	static dispatch_queue_t s_queue = NULL;
	dispatch_once(&s_once,
	^{
		s_queue = dispatch_queue_create("com.apple.dns-push.interface-monitor", DISPATCH_QUEUE_SERIAL);
	});
	return s_queue;
}

static DNSQuestion *
_dns_push_discovery_start_soa(mDNS * const m, const DNSQuestion * const q, const dns_push_obj_context_t context)
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

	// Must not set soa_q->LongLived to true because we are in the process of preparing DNS push. Setting it to true
	// will cause infinite recursive call.
	soa_q->LongLived = mDNSfalse;

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
_dns_push_discovery_soa_result_reply(mDNS * const m, DNSQuestion *question, const ResourceRecord * const answer,
	const QC_result event)
{
	dns_obj_error_t err;
	dns_obj_domain_name_t zone_cut = NULL;
	dns_obj_domain_name_t next_qname = NULL;
	bool stop_discovery = true;

	const dns_push_obj_context_t context = ((dns_push_obj_context_t)question->QuestionContext);

	// We only handle the add event, for other events we ignore them, for example:
	// When the query is suppressed due to no DNS service, we return directly and wait for the DNS service being
	// configured by resolver discovery.
	if (event != QC_add) {
		stop_discovery = false;
		goto exit;
	}

	if (answer->RecordType == kDNSRecordTypePacketNegative) {
		// No Data or NXDomain.
		// The current name is not an authoritative zone, striping one label off and try the new name (Finished
		// below).
	} else {
		// Positive SOA.
		mdns_require_quiet(answer->rrtype == kDNSRecordType_SOA, exit);
		zone_cut = dns_obj_domain_name_create_with_labels(answer->name->c, true, &err);
		mdns_require_noerr_quiet(err, exit);
	}

	if (zone_cut != NULL) {
		// Have found the zone cut.
		dns_push_obj_context_set_authoritative_zone(context, zone_cut);

		// Stop SOA query.
		_dns_push_discovery_stop(m, &question, context, true);
		// Do not touch `question` because question has been freed by `_dns_push_discovery_stop` above.
		stop_discovery = false;

		mDNS_Lock(m);
		const uint32_t if_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, true);
		mDNS_Unlock(m);
		dns_push_obj_context_set_interface_index(context, if_index);

		// Query for the push capability of the server.
		DNSQuestion * const srv_question = _dns_push_discovery_start_srv(m, answer->InterfaceID, context);
		mdns_require_action_quiet(srv_question, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

		// We have found the zone cut, continue the SRV probing for discovery.
		dns_push_obj_context_set_discovery_question(context, srv_question);
	} else {
		// Have not found the zone cut, try its parent label until root label.
		mdns_require_quiet(!IsRootDomain(&question->qname), exit);

		const uint8_t * const next_qname_labels = (SecondLabel(&question->qname)->c);
		next_qname = dns_obj_domain_name_create_with_labels(next_qname_labels, true, &err);
		mdns_require_noerr_quiet(err, exit);

		_dns_push_discovery_try_next_qname(m, question, next_qname);
		stop_discovery = false;
	}

exit:
	dns_obj_forget(&zone_cut);
	dns_obj_forget(&next_qname);
	if (stop_discovery) {
		_dns_push_discovery_stop(m, &question, context, true);
	}
}

//======================================================================================================================

static void
_dns_push_discovery_srv_result_reply(mDNS * const m, DNSQuestion *question, const ResourceRecord * const answer,
	const QC_result event)
{
	dns_obj_error_t err;
	const dns_push_obj_context_t context = ((dns_push_obj_context_t)question->QuestionContext);
	DNSQuestion * const original_q = dns_push_obj_context_get_original_question(context);
	const mDNSu16 qid = mDNSVal16(original_q->TargetQID);

	mdns_require_quiet(event == QC_add, exit);
	if (answer->RecordType == kDNSRecordTypePacketNegative) {
		// No Data or NXDomain, the server does not supports DNS push for now, but keep monitoring changes in case the
		// network supports it.
		log_default("[Q%u] Current network does not support DNS push, falling back to DNS polling -- service ID: %llu",
			qid, mdns_dns_service_get_id(question->dnsservice));
		_dns_push_discovery_fallback_to_dns_polling(context);
		goto exit;
	}

	const dns_obj_domain_name_t authoritative_zone = dns_push_obj_context_get_authoritative_zone(context);
	mdns_require_quiet(authoritative_zone, exit);

	mDNS_Lock(m);
	const uint32_t if_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, true);
	mDNS_Unlock(m);

	bool re_registered;
	const mdns_dns_service_id_t ident = _dns_push_discovery_register_push_service(context, authoritative_zone,
		if_index, &re_registered, &err);
	if ((ident == MDNS_DNS_SERVICE_INVALID_ID) && err) {
		log_fault("[Q%u] Failed to register push service -- id: %llu"
			"authoritative zone: " PUB_DNS_DM_NAME ", interface index: %u, error: " PUB_OS_ERR,
			qid, ident, DNS_DM_NAME_PARAM(authoritative_zone), if_index, (long)err);
		goto exit;
	}
	if (re_registered) {
		log_default("[Q%u] DNS push discovery finished -- service id: %llu, re registered: " PUB_BOOL,
			qid, ident, BOOL_PARAM(re_registered));
	} else {
		log_default("[Q%u] DNS push discovery finished, using service with SRV name _dns-push-tls._tcp." PUB_DNS_DM_NAME
			" -- service id: %llu, re registered: " PUB_BOOL, qid, DNS_DM_NAME_PARAM(authoritative_zone), ident,
			BOOL_PARAM(re_registered));
	}
	// The current network supports DNS push, so stop the discovery.
	_dns_push_discovery_stop(m, &question, context, true);
	// If the question has been using DNS polling since last update, stop DNS polling because a push service is now
	// available.
	_dns_push_discovery_stop_dns_polling(context);

exit:
	return;
}

//======================================================================================================================

static void
_dns_push_discovery_fallback_to_dns_polling(const dns_push_obj_context_t context)
{
	const DNSQuestion *const q = dns_push_obj_context_get_original_question(context);
	const mDNSu32 request_id = q->request_id;
	const mDNSu16 question_id = mDNSVal16(q->TargetQID);

	log_default("[R%u->Q%u] Starting long-lived DNS polling -- "
		"polling interval: " STRINGIFY(LLQ_POLL_INTERVAL_MIN) " min", request_id, question_id);

	dns_push_obj_context_set_dns_polling_enabled(context, true);
	Querier_ProcessDNSServiceChangesAsync(mDNStrue);
}

//======================================================================================================================

static void
_dns_push_discovery_stop_dns_polling(const dns_push_obj_context_t context)
{
	const DNSQuestion *const q = dns_push_obj_context_get_original_question(context);
	const mDNSu32 request_id = q->request_id;
	const mDNSu16 question_id = mDNSVal16(q->TargetQID);

	log_default("[R%u->Q%u] Stopping long-lived DNS polling", request_id, question_id);

	dns_push_obj_context_set_dns_polling_enabled(context, false);
	Querier_ProcessDNSServiceChangesAsync(mDNStrue);
}

//======================================================================================================================

static void
_dns_push_discovery_try_next_qname(mDNS * const m, DNSQuestion * const question, const dns_obj_domain_name_t new_q_name)
{
	m->RestartQuestion = question;
	mDNS_StopQuery(m, question);
	// Must set RestartQuestion back to NULL once the restarting question has been stopped.
	m->RestartQuestion = mDNSNULL;

	const uint8_t * const labels = dns_obj_domain_name_get_labels(new_q_name);
	const size_t labels_length = dns_obj_domain_name_get_length(new_q_name);
	require_return(labels_length < sizeof(question->qname.c));

	memcpy(question->qname.c, labels, labels_length);
	question->qnamehash = DomainNameHashValue(&question->qname);

	mDNS_StartQuery(m, question);
}

//======================================================================================================================

static mdns_interface_monitor_t
_dns_push_discovery_start_interface_monitor(const uint32_t if_index)
{
	interface_monitor_list_s *monitor_in_list = NULL;
	mdns_interface_monitor_t monitor = NULL;

	// Search for any existing interface monitor for the same interface.
	monitor_in_list = g_interface_monitors;
	while (monitor_in_list) {
		if (mdns_interface_monitor_get_interface_index(monitor_in_list->monitor) == if_index) {
			break;
		}
		monitor_in_list = monitor_in_list->next;
	}
	if (monitor_in_list == NULL) {
		// If not found, create a new interface monitor and append it.
		monitor_in_list = mdns_calloc(1, sizeof(*monitor_in_list));
		mdns_require_quiet(monitor_in_list, exit);

		// Activate the monitor.
		monitor = _dns_push_discovery_start_mdns_interface_monitor(if_index);
		mdns_require_quiet(monitor, exit);

		monitor_in_list->monitor = monitor;
		mdns_retain(monitor_in_list->monitor);

		// Add the monitor to the list.
		interface_monitor_list_s **pptr = &g_interface_monitors;
		while (*pptr) {
			pptr = &((*pptr)->next);
		}
		*pptr = monitor_in_list;
	} else {
		// If found, retain it directly.
		monitor = monitor_in_list->monitor;
		mdns_retain(monitor);
	}
	monitor_in_list->use_count++;
	monitor_in_list = NULL;

exit:
	mdns_free(monitor_in_list);
	return monitor;
}

//======================================================================================================================

static mdns_interface_monitor_t
_dns_push_discovery_start_mdns_interface_monitor(const uint32_t if_index)
{
	mdns_interface_monitor_t monitor = NULL;
	mdns_interface_monitor_t obj = mdns_interface_monitor_create(if_index);
	mdns_require_quiet(obj, exit);

	mDNS * const m = &mDNSStorage;
	mdns_interface_monitor_set_queue(obj, _dns_push_discovery_interface_monitor_queue());

	mdns_retain(obj);
	mdns_interface_monitor_set_event_handler(obj,
	^(mdns_event_t event, __unused OSStatus error) {
		if (event == mdns_event_invalidated) {
			mdns_release(obj);
		} else if (event == mdns_event_error) {
			_dns_push_discovery_process_interface_changes(m, obj);
		}
	});
	mdns_interface_monitor_set_update_handler(obj,
	^(const mdns_interface_flags_t update_flags) {
		const bool network_changed = ((update_flags & mdns_interface_flag_network) != 0);
		// Only restart the push discovery when the network has changed due to interface changes.
		if (network_changed) {
			_dns_push_discovery_process_interface_changes(m, obj);
		}
	});
	mdns_interface_monitor_activate(obj);

	monitor = obj;
	obj = NULL;

exit:
	mdns_forget(&obj);
	return monitor;
}

//======================================================================================================================

static void
_dns_push_discovery_process_interface_changes(mDNS * const m, const mdns_interface_monitor_t monitor)
{
	const uint32_t if_index = mdns_interface_monitor_get_interface_index(monitor);

	KQueueLock();
	mDNS_Lock(m);

	const mdns_dns_service_manager_t service_manager = Querier_GetDNSServiceManager();

	size_t q_count = 0;
	for (const DNSQuestion *q = m->Questions; q; q = q->next) {
		q_count++;
	}
	size_t restarted_push_q_count = 0;
	// We are not trying to restart the push question itself here but we are using RestartQuestion pointer to indicate
	// that we are restarting push discovery.
	m->RestartQuestion = m->Questions;
	for (size_t i = 0; (i < q_count) && m->RestartQuestion; i++) {
		DNSQuestion *const q = m->RestartQuestion;

		const dns_push_obj_dns_question_member_t dns_push = q->dns_push;
		const dns_push_obj_context_t context =
			dns_push ? dns_push_obj_dns_question_member_get_context(dns_push) : NULL;
		const mdns_interface_monitor_t if_monitor =
			context ? dns_push_obj_context_get_interface_monitor(context) : NULL;
		if (if_monitor && (if_monitor == monitor)) {
			// The push question is managed by this interface monitor.
			restarted_push_q_count++;
		} else {
			m->RestartQuestion = q->next;
			continue;
		}
		const mdns_dns_service_id_t service_id = dns_push_obj_context_get_service_id(context);
		mdns_dns_service_manager_terminate_discovered_push_service(service_manager, service_id);

		// Restart push discovery.
		dns_push_handle_question_stop(m, q);
		dns_push_handle_question_start(m, q);

		if (m->RestartQuestion == q) {
			m->RestartQuestion = q->next;
		}
	}
	m->RestartQuestion = mDNSNULL;
	log_default("Network changes, restarting all push questions that are related to the changed interface -- "
		"if_index: %u, restarted count: %zu", if_index, restarted_push_q_count);

	mDNS_Unlock(m);
	KQueueUnlock("DNS push interface monitor");
}

//======================================================================================================================

static void
_dns_push_discovery_stop_interface_monitor(const mdns_interface_monitor_t monitor)
{
	interface_monitor_list_s **pptr = &g_interface_monitors;
	while (*pptr) {
		if ((*pptr)->monitor == monitor) {
			break;
		}
		pptr = &((*pptr)->next);
	}
	mdns_require_return(*pptr);

	(*pptr)->use_count--;
	if ((*pptr)->use_count == 0) {
		// If no active push question is using this interface monitor, then invalidate it completely.
		interface_monitor_list_s *if_monitor_to_delete = *pptr;
		*pptr = (*pptr)->next;

		mdns_interface_monitor_forget(&if_monitor_to_delete->monitor);
		mdns_free(if_monitor_to_delete);
	}
}

//======================================================================================================================

static DNSQuestion *
_dns_push_discovery_start_srv(mDNS * const m, const mDNSInterfaceID if_id, const dns_push_obj_context_t context)
{
	DNSQuestion *srv_q = NULL;
	mdns_interface_monitor_t if_monitor = NULL;
	bool failed = true;

	srv_q = mdns_calloc(1, sizeof(*srv_q));
	mdns_require_quiet(srv_q, exit);

	const dns_obj_domain_name_t push_srv = dns_push_obj_context_get_push_service_name(context);
	mdns_require_quiet(push_srv, exit);

	const domainname * const qname = (const domainname *)dns_obj_domain_name_get_labels(push_srv);
	AssignDomainName(&srv_q->qname, qname);

	const DNSQuestion * const original_question = dns_push_obj_context_get_original_question(context);
	mdns_require_quiet(original_question, exit);

	srv_q->qtype = kDNSServiceType_SRV;
	srv_q->qclass = original_question->qclass;
	srv_q->InterfaceID = if_id;
	srv_q->pid = mDNSPlatformGetPID();
	srv_q->QuestionCallback = _dns_push_discovery_srv_result_reply;
	srv_q->QuestionContext = context;
	srv_q->ReturnIntermed = mDNStrue;

	// Must not set soa_q->LongLived to true because we are in the process of preparing DNS push. Setting it to true
	// will cause infinite recursive call.
	srv_q->LongLived = mDNSfalse;

	// To monitor the network change and restart the discovery process when it happens, start interface monitor.
	const uint32_t if_index = dns_push_obj_context_get_interface_index(context);
	if_monitor = _dns_push_discovery_start_interface_monitor(if_index);
	mdns_require_quiet(if_monitor, exit);
	dns_push_obj_context_set_interface_monitor(context, if_monitor);

	const mStatus q_start_error = mDNS_StartQuery(m, srv_q);
	mdns_require_noerr_quiet(q_start_error, exit);
	failed = false;

exit:
	if (failed) {
		mdns_free(srv_q);
	}
	mdns_forget(&if_monitor);
	return srv_q;
}

//======================================================================================================================

static void
_dns_push_discovery_stop(mDNS * const m, DNSQuestion ** const q_pptr, const dns_push_obj_context_t context,
	const bool hold_lock)
{
	DNSQuestion *q = *q_pptr;
	if (q != dns_push_obj_context_get_discovery_question(context)) {
		log_fault("[Q%u] Question being stopped is not the currently active discovery question",
			mDNSVal16(q->TargetQID));
	}
	if (hold_lock) {
		mDNS_StopQuery(m, q);
	} else {
		mDNS_StopQuery_internal(m, q);
	}
	mdns_free(q);
	*q_pptr = mDNSNULL;
	dns_push_obj_context_set_discovery_question(context, NULL);
}

//======================================================================================================================

#define kOrphanedPushServiceTimeLimitMs 30 * 1000

static mdns_dns_service_id_t
_dns_push_discovery_register_push_service(const dns_push_obj_context_t context,
	const dns_obj_domain_name_t zone, const uint32_t if_index, bool * const out_duplicate,
	dns_obj_error_t * const out_error)
{
	mdns_dns_service_id_t service_id = MDNS_DNS_SERVICE_INVALID_ID;
	dns_obj_error_t err;
	dns_obj_domain_name_t dns_push_srv = NULL;
	mdns_domain_name_t mdns_dns_push_srv = NULL;
	bool duplicate = false;

	const mdns_dns_service_manager_t service_manager = Querier_GetDNSServiceManager();
	mdns_require_action_quiet(service_manager, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	static dns_obj_domain_name_t dns_push_service_type = NULL;
	if (!dns_push_service_type) {
		dns_push_service_type = dns_obj_domain_name_create_with_cstring("_dns-push-tls._tcp", &err);
		mdns_require_noerr_quiet(err, exit);
	}
	dns_push_srv = dns_obj_domain_name_create_concatenation(dns_push_service_type, zone, &err);
	mdns_require_noerr_quiet(err, exit);

	const uint8_t * const dns_push_srv_labels = dns_obj_domain_name_get_labels(dns_push_srv);
	mdns_dns_push_srv = mdns_domain_name_create_with_labels(dns_push_srv_labels, NULL);
	mdns_require_action_quiet(mdns_dns_push_srv, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	OSStatus os_err;
	service_id = mdns_dns_service_manager_register_discovered_push_service(service_manager, mdns_dns_push_srv, if_index,
		mdns_dns_service_interface_scope_unscoped_and_scoped, kOrphanedPushServiceTimeLimitMs, &duplicate, &os_err);
	mdns_require_action_quiet(service_id != MDNS_DNS_SERVICE_INVALID_ID, exit, err = (dns_obj_error_t)os_err);

	dns_push_obj_context_set_service_id(context, service_id);
	if (duplicate) {
		// If the push service has been registered before, then we need to manually trigger a service change so that
		// the push question that has finished discovery can start the push connection.
		Querier_ProcessDNSServiceChangesAsync(mDNStrue);
	}

exit:
	mdns_assign(out_duplicate, duplicate);
	mdns_assign(out_error, err);
	dns_obj_forget(&dns_push_srv);
	mdns_forget(&mdns_dns_push_srv);
	return service_id;
}

//======================================================================================================================

static void
_dns_push_discovery_deregister_push_service(const dns_push_obj_context_t context)
{
	const mdns_dns_service_id_t service_id = dns_push_obj_context_get_service_id(context);
	if (service_id != MDNS_DNS_SERVICE_INVALID_ID) {
		const mdns_dns_service_manager_t service_manager = Querier_GetDNSServiceManager();
		if (service_manager) {
			mdns_dns_service_manager_deregister_discovered_push_service(service_manager, service_id);
			dns_push_obj_context_set_service_id(context, MDNS_DNS_SERVICE_INVALID_ID);
		}
	}
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
