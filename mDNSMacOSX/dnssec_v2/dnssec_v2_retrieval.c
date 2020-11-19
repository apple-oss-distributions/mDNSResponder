//
//	dnssec_v2_retrieval.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <string.h>					// for strerror
#include <errno.h>					// for errno
#include "DNSCommon.h"
#include "dnssec_v2.h"
#include "dnssec_v2_helper.h"
#include "dnssec_v2_retrieval.h"
#include "dnssec_v2_client.h"


//======================================================================================================================
//	local functions prototypes
//======================================================================================================================

mDNSlocal response_type_t
determine_response_type(mDNSu16 rr_type, const mDNSu8 * const _Nullable rdata, const mDNSu16 question_type);

mDNSlocal mDNSBool
domain_name_end_with(const mDNSu8 * const _Nonnull longer, const mDNSu8 * const _Nonnull shorter);

mDNSlocal const mDNSu8 * _Nullable
get_parent_zone_name(const list_t * const _Nonnull zones, originals_with_rrsig_t * const _Nonnull original);

mDNSlocal mDNSBool
nsec_nsec3_contains_rrsigs_with_same_signer(const list_t * const nsec_nsec3_list, mDNSu16 type);

//======================================================================================================================
//	functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_status_t
//======================================================================================================================

mDNSexport mStatus
initialize_dnssec_status_t(dnssec_status_t * const _Nonnull status, const domainname * const _Nonnull qname,
	const mDNSu16 qtype, const mDNSu32 flags, void * const _Nonnull context) {

    // Query ends with ".local." and query for RRSIG or ANY type cannot be validated by DNSSEC even if the user sets the
    // kDNSServiceFlagsEnableDNSSEC flag.
	mDNSBool enable_dnssec = FLAGS_CONTAIN_DNSOK_BIT(flags) && is_eligible_for_dnssec(qname, qtype);

	if (enable_dnssec) {
		status->enable_dnssec				= mDNStrue;
		status->tried_dnssec_but_unsigned	= mDNSfalse;
		status->context						= context;
	} else {
		// if the question does not enable DNSSEC, only status->enable_dnssec is meaningful.
		status->enable_dnssec				= mDNSfalse;
		status->tried_dnssec_but_unsigned	= mDNSfalse;
		status->context						= mDNSNULL;
	}

	return mStatus_NoError;
}

//======================================================================================================================
//	uninitialize_dnssec_status_t
//======================================================================================================================

mDNSexport mStatus
uninitialize_dnssec_status_t(dnssec_status_t * const _Nonnull __unused status) {
	status->enable_dnssec				= mDNSfalse;
	status->tried_dnssec_but_unsigned	= mDNSfalse;
	status->context						= mDNSNULL;
	return mStatus_NoError;
}

#pragma mark - dnssec_context_t functions



#pragma mark create_dnssec_context_t
mDNSexport mStatus
create_dnssec_context_t(
	QueryRecordClientRequest * const	_Nullable	request,
	const mDNSu32									request_id,
	const domainname * const			_Nonnull	question_name,
	const mDNSu16									question_type,
	const mDNSu16									question_class,
	const mDNSInterfaceID				_Nullable	interface_id,
	const mDNSs32									service_id,
	const mDNSu32									flags,
	const mDNSBool									append_search_domains,
	const mDNSs32									pid,
	const mDNSu8 *						_Nullable	uuid,
	const mDNSs32									uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	const audit_token_t *				_Nullable	peer_audit_token_ptr,
	const audit_token_t *				_Nullable	delegate_audit_token_ptr,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	const mDNSu8 *						_Nullable	resolver_uuid,
	mDNSBool										need_encryption,
	const mdns_dns_service_id_t						custom_id,
#endif
	const QueryRecordResultHandler		_Nonnull	result_handler,
	void * const						_Nullable	result_context,
	dnssec_context_t * const			_Nullable	primary_dnssec_context,
	dnssec_context_t * _Nullable * const	_Nonnull	out_dnssec_context) {

	mStatus				error								= mStatus_NoError;
	dnssec_context_t *	context								= mDNSNULL;
	mDNSBool			context_created						= mDNSfalse;
	original_request_parameters_t	*parameters;

	context = calloc(1, sizeof(dnssec_context_t)); // must use calloc here to set context to all 0s
	require_action(context != mDNSNULL, exit, error = mStatus_NoMemoryErr; log_debug("calloc failed; error_description='%s'", strerror(errno)));
	context_created = mDNStrue;

	context->me = request;

	list_init(&context->zone_chain, sizeof(dnssec_zone_t));

	// initialize original request fields
	original_t * const original = &context->original;
	original->original_result_with_rrsig.type = unknown_response;

	parameters							= &original->original_parameters;
	parameters->request_id				= request_id;
	memcpy(parameters->question_name.c, question_name->c, DOMAIN_NAME_LENGTH(question_name->c));
	parameters->question_name_hash		= DomainNameHashValue(&parameters->question_name);
	parameters->question_type			= question_type;
	parameters->question_class			= question_class;
	parameters->interface_id			=	interface_id;
	parameters->service_id				= service_id;
	parameters->flags					= flags;
	parameters->append_search_domains	= append_search_domains;
	parameters->pid						= pid;
	if (uuid != mDNSNULL) {
		uuid_copy(parameters->uuid, uuid);
	} else {
		uuid_clear(parameters->uuid);
	}
	parameters->uid						= uid;
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	if (peer_audit_token_ptr != mDNSNULL) {
		parameters->peer_audit_token = *peer_audit_token_ptr;
		parameters->has_peer_audit_token = mDNStrue;
	} else {
		parameters->has_peer_audit_token = mDNSfalse;
	}
	if (delegate_audit_token_ptr != mDNSNULL) {
		parameters->delegate_audit_token = *delegate_audit_token_ptr;
		parameters->has_delegate_audit_token = mDNStrue;
	} else {
		parameters->has_delegate_audit_token = mDNSfalse;
	}
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	if (resolver_uuid != mDNSNULL) {
		uuid_copy(parameters->resolver_uuid, resolver_uuid);
	} else {
		uuid_clear(parameters->resolver_uuid);
	}
	parameters->need_encryption			= need_encryption;
	parameters->custom_id				= custom_id;
#endif
	parameters->user_handler			= result_handler;
	parameters->user_context			= result_context;

	original->original_trust_anchor		= mDNSNULL;
	original->last_time_add				= INT_MIN;
	original->last_time_rmv				= INT_MIN;

	// initialize returned_answers_t
	initialize_returned_answers_t(&context->returned_answers, dnssec_indeterminate, kDNSServiceErr_Invalid);

	// initialize denial of existence fields
	context->denial_of_existence_records	= mDNSNULL;

	context->primary_dnssec_context		= primary_dnssec_context;
	context->subtask_dnssec_context		= mDNSNULL;

	*out_dnssec_context = context;

exit:
	if (error != mStatus_NoError && context_created) free(context);
	return error;
}

#pragma mark print_dnssec_context_t
mDNSexport void
print_dnssec_context_t(const dnssec_context_t * const _Nonnull context) {
	mDNSu8 num_of_tabs = 0;

	log_debug("\n");
	log_debug(TAB_STR "DNSSEC Context:", TAB_PARAM(num_of_tabs));
	print_original_request_parameters_t(&context->original.original_parameters, num_of_tabs + 1);
	log_debug(TAB_STR "--------------------------------------------------", TAB_PARAM(num_of_tabs));

	log_debug(TAB_STR "Original Response:", TAB_PARAM(num_of_tabs));
	print_originals_with_rrsig_t(&context->original.original_result_with_rrsig, num_of_tabs + 1);
	log_debug(TAB_STR "--------------------------------------------------", TAB_PARAM(num_of_tabs));

	log_debug(TAB_STR "Zones:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(&context->zone_chain);
		!list_has_ended(&context->zone_chain, node);
		node = list_next(node)) {
		dnssec_zone_t *zone = (dnssec_zone_t *)node->data;
		print_dnssec_zone_t(zone, num_of_tabs + 1);
	}

	log_debug(TAB_STR "Returned Response:", TAB_PARAM(num_of_tabs));
	print_returned_answers_t(&context->returned_answers, num_of_tabs + 1);
	log_debug(TAB_STR "--------------------------------------------------", TAB_PARAM(num_of_tabs));
	log_debug("\n");
}

#pragma mark destroy_dnssec_context_t
mDNSexport void
destroy_dnssec_context_t(dnssec_context_t * const _Nonnull context) {
	list_uninit(&context->zone_chain);
	uninitialize_returned_answers_t(&context->returned_answers);
	free(context);
}

#pragma mark - add_no_error_records

mDNSlocal mDNSBool
is_response_for_original_request(
	const original_t * const		_Nonnull	original,
	const DNSQuestion * const		_Nonnull	question);

mDNSexport dnssec_retrieval_result_t
add_no_error_records(
	mDNS *const						_Nonnull	m,
	DNSQuestion *					_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context) {

	dnssec_retrieval_result_t result;

	dnssec_zone_t * const zone = find_dnssec_zone_t(&dnssec_context->zone_chain, question->qname.c);

	if (is_response_for_original_request(&dnssec_context->original, question)) {
		// original response requested by user
		result = update_original_from_cache_for_no_error_response(m, question, answer, add_record, dns_result_error,
			dnssec_context);
		require_quiet(result == dnssec_retrieval_no_error, exit);
	}

	// it is possible that user queries for A record for apple.com, and there is also a zone called "apple.com"
	if (zone != mDNSNULL) {
		// DS/DNSKEY response
		result = update_dnssec_zone_t_from_cache_for_no_error_response(m, question, answer, add_record, zone);
		require_quiet(result == dnssec_retrieval_no_error, exit);
	}

	result = dnssec_retrieval_no_error;
exit:
	return result;
}

#pragma mark is_response_for_original_request
mDNSlocal mDNSBool
is_response_for_original_request(
	const original_t * const		_Nonnull	original,
	const DNSQuestion * const		_Nonnull	question) {

	mDNSBool									is_original_request = mDNSfalse;
	const original_request_parameters_t * const parameters			= &original->original_parameters;

	if (parameters->question_name_hash != question->qnamehash) {
		goto exit;
	}

	if (parameters->question_type != question->qtype) {
		goto exit;
	}

	if (parameters->question_class != question->qclass) {
		goto exit;
	}

	if (!DOMAIN_NAME_EQUALS(parameters->question_name.c, question->qname.c)) {
		goto exit;
	}

	is_original_request = mDNStrue;
exit:
	return is_original_request;
}

#pragma mark - add_denial_of_existence_records
mDNSexport dnssec_retrieval_result_t
add_denial_of_existence_records(
	const mDNS *const				_Nonnull	m,
	const DNSQuestion *				_Nonnull	question,
	ResourceRecord * const			_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context) {

	dnssec_retrieval_result_t result;

	if (is_response_for_original_request(&dnssec_context->original, question)) {
		result = update_original_from_cache_for_denial_of_existence_response(m, question, answer, add_record, dns_result_error, dnssec_context);
		require_quiet(result == dnssec_retrieval_no_error, exit);
	} else {
		result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
		goto exit;
	}

exit:
	return result;
}

//======================================================================================================================
//	fetch_necessary_dnssec_records
//======================================================================================================================

mDNSexport dnssec_retrieval_result_t
fetch_necessary_dnssec_records(dnssec_context_t * const _Nonnull context, mDNSBool anchor_reached) {
	// if we reach here, it means we need at least 1 zone node to finish the validation process
	// or the current top parent node has a trust anchor that does not pass the validation
	mStatus							error				= mStatus_NoError;
	dnssec_retrieval_result_t		retrieval_result	= dnssec_retrieval_no_error;
	list_t *						zones				= &context->zone_chain;
	dnssec_zone_t *					zone				= mDNSNULL;
	original_request_parameters_t * params				= &context->original.original_parameters;
	const mDNSu8 *					parent_zone_name;
	const mDNSu32 request_id							= context->original.original_parameters.request_id;

	zone = list_empty(zones) ? mDNSNULL : (dnssec_zone_t *)list_get_last(zones)->data;

	mDNSBool is_root = (zone != mDNSNULL) ? (is_root_domain(zone->domain_name.c)) : mDNSfalse;
	require_action_quiet(!is_root, exit, retrieval_result = dnssec_retrieval_waiting_for_records);

	if (zone == mDNSNULL || zone->trust_anchor == mDNSNULL) {
		// normal case, get new records from the "Signer Name"
		parent_zone_name = get_parent_zone_name(zones, &context->original.original_result_with_rrsig);
		require_action_quiet(parent_zone_name != mDNSNULL, exit, retrieval_result = dnssec_retrieval_waiting_for_records);

		require_action(list_count_node(zones) < MAX_ZONES_ALLOWED, exit, retrieval_result = dnssec_retrieval_too_many_zones);

		error = list_append_uinitialized(zones, sizeof(dnssec_zone_t), (void **)&zone);
		require_action(error == mStatus_NoError, exit, retrieval_result = dnssec_retrieval_record_not_added;
			log_debug("list_add_front_uinitialized failed; error_description='%s'", mStatusDescription(error)));

		initialize_dnssec_zone_t(zone, parent_zone_name);

		if (trust_anchor_contains_dnskey(zone->trust_anchor)) {
			retrieval_result				= dnssec_retrieval_validate_again;
			zone->dnskey_request_started	= mDNSfalse;
			zone->ds_request_started		= mDNSfalse;
		} else if (trust_anchor_contains_ds(zone->trust_anchor)) {
			zone->dnskey_request_started	= mDNStrue;
			zone->ds_request_started		= mDNSfalse;
		} else {
			zone->dnskey_request_started	= mDNStrue;
			zone->ds_request_started		= mDNStrue;
		}

		if (zone->dnskey_request_started) {
			error = QueryRecordOpStartForClientRequest(
				&zone->dnskey_request.op, params->request_id, (const domainname *)parent_zone_name, kDNSType_DNSKEY,
				params->question_class, params->interface_id, params->service_id, params->flags, params->append_search_domains,
				params->pid, params->uuid, params->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
				params->has_peer_audit_token ? &params->peer_audit_token : mDNSNULL,
				params->has_delegate_audit_token ? &params->delegate_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
				params->resolver_uuid, params->need_encryption, params->custom_id,
#endif
				query_record_result_reply_with_dnssec, context);
			require_action(error == mStatus_NoError, exit, retrieval_result = dnssec_retrieval_query_failed;
							log_debug("QueryRecordOpStart failed; error_description='%s'", mStatusDescription(error)));
		}

		if (zone->ds_request_started) {
			error = QueryRecordOpStartForClientRequest(
				&zone->ds_request.op, params->request_id, (const domainname *)parent_zone_name, kDNSType_DS,
				params->question_class, params->interface_id, params->service_id, params->flags, params->append_search_domains,
				params->pid, params->uuid, params->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
				params->has_peer_audit_token ? &params->peer_audit_token : mDNSNULL,
				params->has_delegate_audit_token ? &params->delegate_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
				params->resolver_uuid, params->need_encryption, params->custom_id,
#endif
				query_record_result_reply_with_dnssec, context);
			require_action(error == mStatus_NoError, exit, retrieval_result = dnssec_retrieval_query_failed;
							log_debug("QueryRecordOpStart failed; error_description='%s'", mStatusDescription(error)));
		}
	} else {
		// special case where the trust anchor does not verify the records
		require_action_quiet(anchor_reached, exit,
			retrieval_result = dnssec_retrieval_waiting_for_records; log_default("[R%u] still waiting for the response from child zones", request_id));

		zone->trust_anchor = mDNSNULL;

		if (!zone->dnskey_request_started) {
			error = QueryRecordOpStartForClientRequest(
				&zone->dnskey_request.op, params->request_id, &zone->domain_name, kDNSType_DNSKEY,
				params->question_class, params->interface_id, params->service_id, params->flags, params->append_search_domains,
				params->pid, params->uuid, params->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
				params->has_peer_audit_token ? &params->peer_audit_token : mDNSNULL,
				params->has_delegate_audit_token ? &params->peer_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
				params->resolver_uuid, params->need_encryption, params->custom_id,
#endif
				query_record_result_reply_with_dnssec, context);
			require_action(error == mStatus_NoError, exit, retrieval_result = dnssec_retrieval_query_failed;
							log_debug("QueryRecordOpStart failed; error_description='%s'", mStatusDescription(error)));
			zone->dnskey_request_started = mDNStrue;
		}

		if (!zone->ds_request_started && !is_root_domain(zone->domain_name.c)) {
			error = QueryRecordOpStartForClientRequest(
				&zone->ds_request.op, params->request_id, &zone->domain_name, kDNSType_DS,
				params->question_class, params->interface_id, params->service_id, params->flags, params->append_search_domains,
				params->pid, params->uuid, params->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
				params->has_peer_audit_token ? &params->peer_audit_token : mDNSNULL,
				params->has_delegate_audit_token ? &params->delegate_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
				params->resolver_uuid, params->need_encryption, params->custom_id,
#endif
				query_record_result_reply_with_dnssec, context);
			require_action(error == mStatus_NoError, exit, retrieval_result = dnssec_retrieval_query_failed;
							log_debug("QueryRecordOpStart failed; error_description='%s'", mStatusDescription(error)));
			zone->ds_request_started = mDNStrue;
		}
	}

exit:
	if (retrieval_result < 0) {
		if (zone != mDNSNULL) {
			if (zone->dnskey_request_started || zone->ds_request_started) {
				// TODO: return correct error code to user and clean the dnssec related structure gracefully
			}
			uninitialize_dnssec_zone_t(zone);
			list_delete_node_with_data_ptr(zones, (void *)zone);
		}
	}

	return retrieval_result;
}

//======================================================================================================================
//	find_dnssec_zone_t
//======================================================================================================================

mDNSexport dnssec_zone_t * _Nullable
find_dnssec_zone_t(const list_t * const _Nonnull zones, const mDNSu8 * const _Nonnull name) {
	for (list_node_t *ptr = list_get_first(zones); !list_has_ended(zones, ptr); ptr = list_next(ptr)) {
		dnssec_zone_t *zone = (dnssec_zone_t *)ptr->data;
		if (DOMAIN_NAME_EQUALS(&zone->domain_name, name)) {
			return zone;
		}
	}

	return mDNSNULL;
}

//======================================================================================================================
//	add_to_cname_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cnames_with_rrisg, ResourceRecord * const _Nonnull rr) {
	mStatus error = mStatus_NoError;
	list_t *		cname_records	= &cnames_with_rrisg->cname_records;
	list_t *		rrsig_records	= &cnames_with_rrisg->rrsig_records;
	dnssec_cname_t *cname			= mDNSNULL;
	dnssec_rrsig_t *rrsig			= mDNSNULL;

	if (rr->rrtype == kDNSType_CNAME) {
		error = list_append_uinitialized(cname_records, sizeof(dnssec_cname_t), (void **)&cname);
		require_action(error == mStatus_NoError, exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

		initialize_dnssec_cname_t(cname, rr);
	} else {
		mDNSBool is_rrsig_valid = mDNSfalse;

		verify(rr->rrtype == kDNSType_RRSIG);
		error = list_append_uinitialized(&cnames_with_rrisg->rrsig_records, sizeof(dnssec_rrsig_t), (void **)&rrsig);
		require_action(error == mStatus_NoError, exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

		is_rrsig_valid = initialize_dnssec_rrsig_t(rrsig, rr);
		require_action_quiet(is_rrsig_valid, exit, error = mStatus_BadParamErr;
			log_debug("When adding RRSIG for CNAME, RRSIG does not pass validation"));
	}

exit:
	if (error != mStatus_NoError) {
		if (rrsig != mDNSNULL)			list_delete_node_with_data_ptr(rrsig_records, rrsig);
		if (cname != mDNSNULL)			list_delete_node_with_data_ptr(cname_records, cname);
	}
	return error;
}

//======================================================================================================================
//	add_to_nsec_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_nsec_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs_with_rrisg, ResourceRecord * const _Nonnull rr) {
	mStatus					error		= mStatus_NoError;
	list_t * const			nsec_list	= &nsecs_with_rrisg->nsec_and_rrsigs_same_name;
	const mDNSu8 * const	owner_name	= rr->name->c;
	const mDNSu32			name_hash	= DomainNameHashValue(rr->name);
	mDNSBool				is_valid 	= mDNSfalse;
	const mDNSu8 *			owner_name_to_compare;
	mDNSu32					name_hash_to_compare;

	if (rr->rrtype == kDNSType_NSEC) {
		one_nsec_with_rrsigs_t * new_one_nsec = mDNSNULL;
		for (list_node_t * nsec_node = list_get_first(nsec_list);
			!list_has_ended(nsec_list, nsec_node);
			nsec_node = list_next(nsec_node)) {
			one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t * const)nsec_node->data;
			if (one_nsec->owner_name != mDNSNULL) {
				owner_name_to_compare	= one_nsec->owner_name;
				name_hash_to_compare	= one_nsec->nsec_record.dnssec_rr.name_hash;

				require_action_quiet(name_hash_to_compare != name_hash || !DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name),
					insert_nsec_exit, error = mStatus_BadParamErr;
					log_debug("two NSEC records have the same owner name - owner name: " PRI_DM_NAME,
						DM_NAME_PARAM((const domainname *)owner_name))
				);

			} else {
				require_action(!list_empty(&one_nsec->rrsig_records), insert_nsec_exit, error = mStatus_Invalid;
					log_error("empty one_nsec_with_rrsigs_t created"));

				const dnssec_rrsig_t * const first_rrsig = (const dnssec_rrsig_t * const)(list_get_first(&one_nsec->rrsig_records)->data);
				owner_name_to_compare	= first_rrsig->dnssec_rr.name.c;
				name_hash_to_compare	= first_rrsig->dnssec_rr.name_hash;

				if (name_hash_to_compare != name_hash || !DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name)) {
					continue;
				}

				is_valid = initialize_dnssec_nsec_t(&one_nsec->nsec_record, rr);
				require_action_quiet(is_valid, insert_nsec_exit, error = mStatus_BadParamErr;
					log_debug("NSEC record initialization failed because of the malformated resource record"));
				one_nsec->owner_name = one_nsec->nsec_record.dnssec_rr.name.c;
				error = mStatus_NoError;
				goto insert_nsec_exit;
			}
		}

		// insert new one_nsec
		error = list_append_uinitialized(nsec_list, sizeof(one_nsec_with_rrsigs_t), (void **)&new_one_nsec);
		require_action(error == mStatus_NoError, insert_nsec_exit, log_error("list_append_uinitialized failed;"));

		is_valid = initialize_one_nsec_with_rrsigs_t(new_one_nsec, rr);
		require_action_quiet(is_valid, insert_nsec_exit, error = mStatus_BadParamErr;
			log_debug("One NSEC structure initialization failed because of malformated resource record - owner name: " PRI_DM_NAME,
				DM_NAME_PARAM(rr->name))
		);

		error = mStatus_NoError;
	insert_nsec_exit:
		if (error != mStatus_NoError) {
			if (new_one_nsec != mDNSNULL) {
				list_delete_node_with_data_ptr(nsec_list, new_one_nsec);
			}
		}
	} else if (rr->rrtype == kDNSType_RRSIG && get_covered_type_of_dns_type_rrsig_t(rr->rdata->u.data) == kDNSType_NSEC) {
		list_t *					list_to_insert	= mDNSNULL;
		one_nsec_with_rrsigs_t *	new_one_nsec	= mDNSNULL;
		dnssec_rrsig_t *			new_rrsig		= mDNSNULL;

		for (list_node_t * nsec_node = list_get_first(&nsecs_with_rrisg->nsec_and_rrsigs_same_name);
			!list_has_ended(nsec_list, nsec_node);
			nsec_node = list_next(nsec_node)) {
			one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t * const)nsec_node->data;

			if (one_nsec->owner_name != mDNSNULL) {
				owner_name_to_compare	= one_nsec->owner_name;
				name_hash_to_compare	= one_nsec->nsec_record.dnssec_rr.name_hash;
			} else if (!list_empty(&one_nsec->rrsig_records)) {
				const dnssec_rrsig_t * const first_rrsig = (const dnssec_rrsig_t * const)(list_get_first(&one_nsec->rrsig_records)->data);
				owner_name_to_compare	= first_rrsig->dnssec_rr.name.c;
				name_hash_to_compare	= first_rrsig->dnssec_rr.name_hash;
			} else {
				error = mStatus_Invalid;
				log_error("empty one_nsec_with_rrsigs_t created - rr owner name: " PRI_DM_NAME, DM_NAME_PARAM(rr->name));
				goto insert_rrsig_exit;
			}

			if (name_hash_to_compare == name_hash && DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name)) {
				list_to_insert = &one_nsec->rrsig_records;
				break;
			}
		}

		if (list_to_insert == mDNSNULL) {
			// insert new one_nsec
			error = list_append_uinitialized(nsec_list, sizeof(one_nsec_with_rrsigs_t), (void **)&new_one_nsec);
			require_action(error == mStatus_NoError, insert_rrsig_exit, log_error("list_append_uinitialized failed;"));

			new_one_nsec->owner_name = mDNSNULL;
			list_init(&new_one_nsec->rrsig_records, sizeof(dnssec_rrsig_t));

			list_to_insert = &new_one_nsec->rrsig_records;
		}

		// insert new rrsig
		error = list_append_uinitialized(list_to_insert, sizeof(dnssec_rrsig_t), (void **)&new_rrsig);
		require_action(error == mStatus_NoError, insert_rrsig_exit, log_error("list_append_uinitialized failed;"));

		is_valid = initialize_dnssec_rrsig_t(new_rrsig, rr);
		require_action_quiet(is_valid, insert_rrsig_exit, error = mStatus_BadParamErr;
			log_debug("When adding RRSIG for NSEC, RRSIG does not pass validation"));

	insert_rrsig_exit:
		if (error != mStatus_NoError) {
			if (new_rrsig != mDNSNULL) {
				list_delete_node_with_data_ptr(list_to_insert, new_rrsig);
			}
			if (new_one_nsec != mDNSNULL) {
				list_delete_node_with_data_ptr(nsec_list, new_one_nsec);
			}
		}
	} else {
		if (rr->rrtype != kDNSType_RRSIG) {
			// wildcard
			dnssec_rr_t *dnssec_rr = mDNSNULL;
			error = list_append_uinitialized(&nsecs_with_rrisg->wildcard_answers, sizeof(dnssec_rr_t), (void **)&dnssec_rr);
			require_action(error == mStatus_NoError, exit, log_error("list_append_uinitialized failed;"));

			initialize_dnssec_rr_t(dnssec_rr, rr);
		} else {
			// RRSIG
			dnssec_rrsig_t *dnssec_rrsig = mDNSNULL;
			error = list_append_uinitialized(&nsecs_with_rrisg->wildcard_rrsigs, sizeof(dnssec_rrsig_t), (void **)&dnssec_rrsig);
			require_action(error == mStatus_NoError, exit, log_error("list_append_uinitialized failed;"));

			is_valid = initialize_dnssec_rrsig_t(dnssec_rrsig, rr);
			require_action_quiet(is_valid, insert_wildcard_rrsig_exit, error = mStatus_BadParamErr;
				log_debug("When adding RRSIG for wildcard answer, RRSIG does not pass validation"));

		insert_wildcard_rrsig_exit:
			if (error != mStatus_NoError) {
				if (dnssec_rrsig != mDNSNULL) {
					list_delete_node_with_data_ptr(&nsecs_with_rrisg->wildcard_rrsigs, dnssec_rrsig);
				}
			}
		}
	}

exit:
	return error;
}

//======================================================================================================================
//	add_to_nsec3_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_nsec3_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s_with_rrisg, ResourceRecord * const _Nonnull rr) {
	mStatus					error		= mStatus_NoError;
	list_t * const			nsec3_list	= &nsec3s_with_rrisg->nsec3_and_rrsigs_same_name;
	const mDNSu8 * const	owner_name	= rr->name->c;
	const mDNSu32			name_hash	= DomainNameHashValue(rr->name);
	mDNSBool 				is_valid	= mDNStrue;
	const mDNSu8 *			owner_name_to_compare;
	mDNSu32					name_hash_to_compare;

	if (rr->rrtype == kDNSType_NSEC3) {
		one_nsec3_with_rrsigs_t * new_one_nsec3 = mDNSNULL;
		for (list_node_t *nsec3_node = list_get_first(nsec3_list); !list_has_ended(nsec3_list, nsec3_node); nsec3_node = list_next(nsec3_node)) {
			one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t * const)nsec3_node->data;
			if (one_nsec3->owner_name != mDNSNULL) {
				owner_name_to_compare	= one_nsec3->owner_name;
				name_hash_to_compare	= one_nsec3->nsec3_record.dnssec_rr.name_hash;

				require_action_quiet(name_hash_to_compare != name_hash || !DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name),
					insert_nsec3_exit, error = mStatus_BadParamErr;
					log_debug("two NSEC3 records have the same owner name - owner name: " PRI_DM_NAME,
						DM_NAME_PARAM((const domainname *)owner_name))
				);
			} else {
				require_action(!list_empty(&one_nsec3->rrsig_records), exit, error = mStatus_Invalid;
					log_error("empty one_nsec3_with_rrsigs_t created"));

				const dnssec_rrsig_t * const first_rrsig = (const dnssec_rrsig_t * const)(list_get_first(&one_nsec3->rrsig_records)->data);
				owner_name_to_compare	= first_rrsig->dnssec_rr.name.c;
				name_hash_to_compare	= first_rrsig->dnssec_rr.name_hash;

				if (name_hash_to_compare != name_hash || !DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name)) {
					continue;
				}

				is_valid = initialize_dnssec_nsec3_t(&one_nsec3->nsec3_record, rr);
				require_action_quiet(is_valid, insert_nsec3_exit, error = mStatus_BadParamErr;
					log_debug("NSEC record initialization failed because of the malformated resource record"));
				one_nsec3->owner_name = one_nsec3->nsec3_record.dnssec_rr.name.c;
				error = mStatus_NoError;
				goto insert_nsec3_exit;
			}
		}

		// insert new one_nsec3
		error = list_append_uinitialized(nsec3_list, sizeof(one_nsec3_with_rrsigs_t), (void **)&new_one_nsec3);
		require_action(error == mStatus_NoError, insert_nsec3_exit, log_error("list_append_uinitialized failed;"));

		is_valid = initialize_one_nsec3_with_rrsigs_t(new_one_nsec3, rr);
		require_action_quiet(is_valid, insert_nsec3_exit, error = mStatus_BadParamErr;
			log_debug("One NSEC3 structure initialization failed because of malformated resource record - owner name: " PRI_DM_NAME,
				DM_NAME_PARAM(rr->name))
		);

	insert_nsec3_exit:
		if (error != mStatus_NoError) {
			if (new_one_nsec3 != mDNSNULL) {
				list_delete_node_with_data_ptr(nsec3_list, new_one_nsec3);
			}
		}
	} else if (rr->rrtype == kDNSType_RRSIG && get_covered_type_of_dns_type_rrsig_t(rr->rdata->u.data) == kDNSType_NSEC3) {
		list_t *					list_to_insert	= mDNSNULL;
		one_nsec3_with_rrsigs_t *	new_one_nsec3	= mDNSNULL;
		dnssec_rrsig_t *			new_rrsig		= mDNSNULL;

		for (list_node_t *nsec3_node = list_get_first(nsec3_list); !list_has_ended(nsec3_list, nsec3_node); nsec3_node = list_next(nsec3_node)) {
			one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t * const)nsec3_node->data;

			if (one_nsec3->owner_name != mDNSNULL) {
				owner_name_to_compare	= one_nsec3->owner_name;
				name_hash_to_compare	= one_nsec3->nsec3_record.dnssec_rr.name_hash;
			} else if (!list_empty(&one_nsec3->rrsig_records)) {
				const dnssec_rrsig_t * const first_rrsig = (const dnssec_rrsig_t * const)(list_get_first(&one_nsec3->rrsig_records)->data);
				owner_name_to_compare	= first_rrsig->dnssec_rr.name.c;
				name_hash_to_compare	= first_rrsig->dnssec_rr.name_hash;
			} else {
				error = mStatus_Invalid;
				log_error("empty one_nsec3_with_rrsigs_t created - rr owner name: " PRI_DM_NAME, DM_NAME_PARAM(rr->name));
				goto insert_rrsig_exit;
			}

			if (name_hash_to_compare == name_hash && DOMAIN_NAME_EQUALS(owner_name_to_compare, owner_name)) {
				list_to_insert = &one_nsec3->rrsig_records;
			}
		}

		if (list_to_insert == mDNSNULL) {
			// insert new one_nsec3
			error = list_append_uinitialized(nsec3_list, sizeof(one_nsec3_with_rrsigs_t), (void **)&new_one_nsec3);
			require_action(error == mStatus_NoError, insert_rrsig_exit, log_error("list_append_uinitialized failed"));

			new_one_nsec3->owner_name = mDNSNULL;
			list_init(&new_one_nsec3->rrsig_records, sizeof(dnssec_rrsig_t));

			list_to_insert = &new_one_nsec3->rrsig_records;
		}

		// insert new rrsig
		error = list_append_uinitialized(list_to_insert, sizeof(dnssec_rrsig_t), (void **)&new_rrsig);
		require_action(error == mStatus_NoError, insert_rrsig_exit, log_error("list_append_uinitialized failed;"));

		is_valid = initialize_dnssec_rrsig_t(new_rrsig, rr);
		require_action_quiet(is_valid, insert_rrsig_exit, error = mStatus_BadParamErr;
			log_debug("When adding RRSIG for NSEC3, RRSIG does not pass validation"));

	insert_rrsig_exit:
		if (error != mStatus_NoError) {
			if (new_rrsig != mDNSNULL) {
				list_delete_node_with_data_ptr(list_to_insert, new_rrsig);
			}
			if (new_one_nsec3 != mDNSNULL) {
				list_delete_node_with_data_ptr(nsec3_list, new_one_nsec3);
			}
		}
	} else {
		if (rr->rrtype != kDNSType_RRSIG) {
			// wildcard
			dnssec_rr_t *dnssec_rr = mDNSNULL;
			error = list_append_uinitialized(&nsec3s_with_rrisg->wildcard_answers, sizeof(dnssec_rr_t), (void **)&dnssec_rr);
			require_action(error == mStatus_NoError, exit, log_error("list_append_uinitialized failed;"));

			initialize_dnssec_rr_t(dnssec_rr, rr);
		} else {
			// RRSIG
			dnssec_rrsig_t *dnssec_rrsig = mDNSNULL;
			error = list_append_uinitialized(&nsec3s_with_rrisg->wildcard_rrsigs, sizeof(dnssec_rrsig_t), (void **)&dnssec_rrsig);
			require_action(error == mStatus_NoError, exit, log_error("list_append_uinitialized failed;"));

			is_valid = initialize_dnssec_rrsig_t(dnssec_rrsig, rr);
			require_action_quiet(is_valid, insert_wildcard_rrsig_exit, error = mStatus_BadParamErr;
				log_debug("When adding RRSIG for wildcard answer, RRSIG does not pass validation"));

		insert_wildcard_rrsig_exit:
			if (error != mStatus_NoError) {
				if (dnssec_rrsig != mDNSNULL) {
					list_delete_node_with_data_ptr(&nsec3s_with_rrisg->wildcard_rrsigs, dnssec_rrsig);
				}
			}
		}
	}

exit:
	return error;
}

//======================================================================================================================
//	add_to_originals_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_originals_with_rrsig_t(
	originals_with_rrsig_t * const	_Nonnull	originals_with_rrisg,
	ResourceRecord * const	_Nonnull			rr,
	const mDNSBool								answer_from_cache,
	const DNSServiceErrorType					dns_error,
	const QC_result								qc_result) {

	mStatus		error			= mStatus_NoError;

	if (originals_with_rrisg->type == original_response) {
		dnssec_rrsig_t *	rrsig							= mDNSNULL;
		dnssec_original_t * original						= mDNSNULL;

		if (rr->rrtype == kDNSType_RRSIG) {
			// the corresponding RRISG that covers the requested RR, and RRSIG cannot be the requested
			error = list_append_uinitialized(&originals_with_rrisg->u.original.rrsig_records, sizeof(dnssec_rrsig_t), (void **)&rrsig);
			require_action(error == mStatus_NoError, original_response_exit, log_debug("list_add_front_uinitialized failed; error_description='%s'", mStatusDescription(error)));

			mDNSBool is_rrsig_valid= initialize_dnssec_rrsig_t(rrsig, rr);
			require_action_quiet(is_rrsig_valid, original_response_exit, error = mStatus_BadParamErr;
				log_debug("When adding RRSIG for original response, RRSIG does not pass validation"));
		} else {
			error = list_append_uinitialized(&originals_with_rrisg->u.original.original_records, sizeof(dnssec_original_t), (void **)&original);
			require_action(error == mStatus_NoError, original_response_exit, log_debug("list_add_front_uinitialized failed; error_description='%s'", mStatusDescription(error)));

			initialize_dnssec_original_t(original, rr, answer_from_cache, dns_error, qc_result);
		}

	original_response_exit:
		if (error != mStatus_NoError) {
			if (original != mDNSNULL)			list_delete_node_with_data_ptr(&originals_with_rrisg->u.original.original_records, (void *)original);
			if (rrsig != mDNSNULL)				list_delete_node_with_data_ptr(&originals_with_rrisg->u.original.rrsig_records, (void *)rrsig);
			goto exit;
		}
	} else if (originals_with_rrisg->type == cname_response) {
		error = add_to_cname_with_rrsig_t(&originals_with_rrisg->u.cname_with_rrsig, rr);
		require_action(error == mStatus_NoError, exit, log_debug("add_to_cname_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else if (originals_with_rrisg->type == nsec_response) {
		error = add_to_nsec_with_rrsig_t(&originals_with_rrisg->u.nsecs_with_rrsig, rr);
		require_action(error == mStatus_NoError, exit, log_debug("add_to_nsec_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else if (originals_with_rrisg->type == nsec3_response) {
		error = add_to_nsec3_with_rrsig_t(&originals_with_rrisg->u.nsec3s_with_rrsig, rr);
		require_action(error == mStatus_NoError, exit, log_debug("add_to_nsec3_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else {
		verify(mDNSfalse);
	}

exit:
	return error;
}

//======================================================================================================================
//	dnskeys_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	add_to_dnskeys_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskeys_with_rrsig, ResourceRecord * const _Nonnull rr) {
	// dnskeys_with_rrsig != mDNSNULL && rr != mDNSNULL
	mStatus error = mStatus_NoError;
	mDNSBool is_valid = mDNStrue;

	dnssec_dnskey_t *	dnskey						= mDNSNULL;
	dnssec_rrsig_t *	rrsig						= mDNSNULL;

	if (rr->rrtype == kDNSType_DNSKEY) {
		error = list_append_uinitialized(&dnskeys_with_rrsig->dnskey_records, sizeof(dnssec_dnskey_t), (void **)&dnskey);
		require_action(error == mStatus_NoError, original_response_exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

		is_valid = initialize_dnssec_dnskey_t(dnskey, rr);
		require_action_quiet(is_valid, original_response_exit, error = mStatus_BadParamErr;
			log_debug("When adding DNSKEY rdata for DNSKEY, rdata does not pass validation and does not get added"));
	} else {
		verify(rr->rrtype == kDNSType_RRSIG);
		error = list_append_uinitialized(&dnskeys_with_rrsig->rrsig_records, sizeof(dnssec_rrsig_t), (void **)&rrsig);
		require_action(error == mStatus_NoError, original_response_exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

		is_valid = initialize_dnssec_rrsig_t(rrsig, rr);
		require_action_quiet(is_valid, original_response_exit, error = mStatus_BadParamErr;
			log_debug("When adding RRSIG for DNSKEY, RRSIG does not pass validation and does not get added"));
	}

original_response_exit:
	if (error != mStatus_NoError) {
		if (dnskey != mDNSNULL)				list_delete_node_with_data_ptr(&dnskeys_with_rrsig->dnskey_records, dnskey);
		if (rrsig != mDNSNULL)				list_delete_node_with_data_ptr(&dnskeys_with_rrsig->rrsig_records, rrsig);
	}
	return error;
}

//======================================================================================================================
//	add_to_dses_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
add_to_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull dses_with_rrsig, ResourceRecord * const _Nonnull rr) {
	mStatus error = mStatus_NoError;
	mDNSBool is_valid = mDNSfalse;

	if (dses_with_rrsig->type == original_response) {
		dnssec_ds_t *	ds							= mDNSNULL;
		dnssec_rrsig_t *rrsig						= mDNSNULL;

		if (rr->rrtype == kDNSType_DS) {
			error = list_append_uinitialized(&dses_with_rrsig->u.original.ds_records, sizeof(dnssec_ds_t), (void **)&ds);
			require_action(error == mStatus_NoError, original_response_exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

			is_valid = initialize_dnssec_ds_t(ds, rr);
			require_action_quiet(is_valid, original_response_exit, error = mStatus_BadParamErr;
				log_debug("When adding DS rdata for DS, the rdata does not pass validation and does not get added"));
		} else {
			verify(rr->rrtype == kDNSType_RRSIG);
			error = list_append_uinitialized(&dses_with_rrsig->u.original.rrsig_records, sizeof(dnssec_rrsig_t), (void **)&rrsig);
			require_action(error == mStatus_NoError, original_response_exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

			is_valid = initialize_dnssec_rrsig_t(rrsig, rr);
			require_action_quiet(is_valid, original_response_exit, error = mStatus_BadParamErr;
				log_debug("When adding RRSIG for DS, RRSIG does not pass validation and does not get added"));
		}
	original_response_exit:
		if (error != mStatus_NoError) {
			if (ds != mDNSNULL)				list_delete_node_with_data_ptr(&dses_with_rrsig->u.original.ds_records, (void *)ds);
			if (rrsig != mDNSNULL)			list_delete_node_with_data_ptr(&dses_with_rrsig->u.original.rrsig_records, (void *)rrsig);
			goto exit;
		}
	}else if (dses_with_rrsig->type == nsec_response) {
		error = add_to_nsec_with_rrsig_t(&dses_with_rrsig->u.nsecs_with_rrsig, rr);
		require_action(error == mStatus_NoError, exit, log_debug("add_to_nsec_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else if (dses_with_rrsig->type == nsec3_response) {
		error = add_to_nsec3_with_rrsig_t(&dses_with_rrsig->u.nsec3s_with_rrsig, rr);
		require_action(error == mStatus_NoError, exit, log_debug("add_to_nsec3_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else{
		error = mStatus_Invalid;
		log_error("invalid response type for DS record");
	}

exit:
	return error;
}

//======================================================================================================================
//	initialize_denial_of_existence_records_t
//======================================================================================================================

mDNSexport denial_of_existence_records_t * _Nullable
create_denial_of_existence_records_t(void) {
	denial_of_existence_records_t *denial = malloc(sizeof(denial_of_existence_records_t));
	require_quiet(denial != mDNSNULL, exit);

	list_init(&denial->resource_records, sizeof(ResourceRecord));

exit:
	return denial;
}

//======================================================================================================================
//	destroy_denial_of_existence_records_t
//======================================================================================================================

mDNSexport void
destroy_denial_of_existence_records_t(denial_of_existence_records_t * const _Nonnull denial_of_existence_records) {
	list_t *denial_rrs = &denial_of_existence_records->resource_records;
	for (const list_node_t *rr_node = list_get_first(denial_rrs); !list_has_ended(denial_rrs, rr_node); rr_node = list_next(rr_node)) {
		ResourceRecord * const rr = (ResourceRecord *)rr_node->data;
		free_resource_record_deep_copied(rr);
	}
	list_uninit(denial_rrs);
	free(denial_of_existence_records);
}

mDNSexport void
destroy_denial_of_existence_records_t_if_nonnull(denial_of_existence_records_t * const _Nonnull denial_of_existence_records) {
	if (denial_of_existence_records == mDNSNULL) {
		return;
	}

	destroy_denial_of_existence_records_t(denial_of_existence_records);
}

//======================================================================================================================
//	add_to_denial_of_existence_records_t
//======================================================================================================================

mDNSexport mStatus
add_to_denial_of_existence_records_t(denial_of_existence_records_t * const _Nonnull denial_of_existence_records, const ResourceRecord * const _Nonnull rr) {
	mStatus			error				= mStatus_NoError;
	list_t *		resource_records	= &denial_of_existence_records->resource_records;
	ResourceRecord *rr_copy;

	error = list_append_uinitialized(resource_records, sizeof(ResourceRecord), (void **)&rr_copy);
	require_action(error == mStatus_NoError, exit, log_debug("list_append_uinitialized failed; error_description='%s'", mStatusDescription(error)));

	error = deep_copy_resource_record(rr_copy, rr);
	require_action(error == mStatus_NoError, exit, log_error("initialize_dnssec_rr_t failed"));

exit:
	return error;
}

//======================================================================================================================
//	add_to_dnssec_zone_t
//======================================================================================================================

mDNSexport mStatus
add_to_dnssec_zone_t(
	dnssec_zone_t * const			_Nonnull	zone,
	ResourceRecord * const			_Nonnull	rr,
	const mDNSu16								question_type) {

	mStatus		error = mStatus_NoError;

	if (question_type == kDNSType_DNSKEY) {
		error = add_to_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig, rr);
		require_action_quiet(error == mStatus_NoError, exit, log_debug("add_to_dnskeys_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else if (question_type == kDNSType_DS) {
		if (!zone->dses_initialized) {
			response_type_t type = determine_response_type(rr->rrtype, rr->rdata->u.data, question_type);
			require_action_quiet(type != unknown_response, exit, error = mStatus_Invalid;
				log_error("Unrelated response to current query; question_type=" PUB_S ", response_type=" PUB_S,
					DNS_TYPE_STR(question_type), DNS_TYPE_STR(rr->rrtype)));
			initialize_dses_with_rrsig_t(&zone->dses_with_rrsig, type);
			zone->dses_initialized = mDNStrue;
		}
		error = add_to_dses_with_rrsig_t(&zone->dses_with_rrsig, rr);
		require_action_quiet(error == mStatus_NoError, exit, log_debug("add_to_dses_with_rrsig_t failed; error_description='%s'", mStatusDescription(error)));
	} else {
		error = mStatus_Invalid;
		log_error("Non DS/DNSKEY query created for dnssec zone; qtype=" PUB_S, DNS_TYPE_STR(question_type));
	}

exit:
	return error;
}

#pragma mark - Update DNSSEC Records

#pragma mark - update_dnssec_zone_t_from_cache_for_no_error_response

mDNSlocal mDNSs32
get_time_received_for_answer(
	const CacheGroup * const		_Nonnull	cache_group,
	const ResourceRecord * const	_Nonnull	answer);

mDNSlocal mDNSu16
get_updated_type_from_answer(const ResourceRecord * const _Nonnull answer);

mDNSexport dnssec_retrieval_result_t
update_dnssec_zone_t_from_cache_for_no_error_response(
	const mDNS * const				_Nonnull	m,
	const DNSQuestion * const		_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	dnssec_zone_t * const			_Nonnull	zone) {

	dnssec_retrieval_result_t	result		= dnssec_retrieval_unknown_error;
	mStatus							error;
	const CacheGroup *				cache_group;
	mDNSs32							last_time_received;
	mDNSu16							updated_type;
	const dnssec_context_t * const	context 	= question->DNSSECStatus.context;
	mDNSu32							request_id	= context->original.original_parameters.request_id;
	mDNSu16							question_id = mDNSVal16(question->TargetQID);

	require_action_quiet(question->qtype == kDNSType_DS || question->qtype == kDNSType_DNSKEY, exit,
		result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
			log_error("Non DS/DNSKEY query created for dnssec zone; qtype=" PUB_S, DNS_TYPE_STR(question->qtype)));

	cache_group = CacheGroupForName(m, question->qnamehash, &question->qname);
	require_action_quiet(cache_group != mDNSNULL, exit,
		log_error("The question deos not have any corresponding cache group; qname=" PRI_DM_NAME,
			DM_NAME_PARAM(&question->qname)));

	last_time_received = get_time_received_for_answer(cache_group, answer);
	require_action_quiet(last_time_received != 0, exit,
		log_error("Did not find answer in the cache group; qname=" PRI_DM_NAME " answer_name=" PRI_DM_NAME,
			DM_NAME_PARAM(&question->qname), DM_NAME_PARAM(answer->name)));

	updated_type = get_updated_type_from_answer(answer);
	require_action_quiet(question->qtype == updated_type, exit, result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
		log_error("[R%u->%u] Record type is not what question asked for; qname=" PRI_DM_NAME ", qtype=" PUB_S ", rr_type=" PUB_S,
			request_id, question_id, DM_NAME_PARAM(&question->qname),
			DNS_TYPE_STR(question->qtype), DNS_TYPE_STR(updated_type)));

	if (updated_type == kDNSType_DS) {
		require_action_quiet(zone->ds_request_started, exit, result = dnssec_retrieval_invalid_internal_state;);

		if (add_record == QC_add && zone->last_time_ds_add < last_time_received) {
			// having new records added into the response
			zone->last_time_ds_add = last_time_received;
		} else if (add_record == QC_rmv && zone->last_time_ds_rmv < last_time_received) {
			// having old records removed from the response
			zone->last_time_ds_rmv = last_time_received;
			uninitialize_dses_with_rrsig_t(&zone->dses_with_rrsig);
			zone->dses_initialized = mDNSfalse;
			result = dnssec_retrieval_waiting_for_records;
			log_default("[R%u->Q%u] Removing DS record from the zone - hostname: " PRI_DM_NAME, request_id, question_id, DM_NAME_PARAM(&zone->domain_name));
			goto exit;
		} else {
			result = dnssec_retrieval_no_new_change;
			goto exit;
		}
	} else if (updated_type == kDNSType_DNSKEY) {
		require_action_quiet(zone->dnskey_request_started, exit, result = dnssec_retrieval_invalid_internal_state;);

		if (add_record == QC_add && zone->last_time_dnskey_add < last_time_received) {
			// having new records added into the response
			zone->last_time_dnskey_add = last_time_received;
		} else if (add_record == QC_rmv && zone->last_time_dnskey_rmv < last_time_received) {
			// having old records removed from the response
			zone->last_time_dnskey_rmv = last_time_received;
			// uninitialize and initialize to clear all the old contents in zone->dnskeys_with_rrsig
			uninitialize_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig);
			initialize_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig);
			result = dnssec_retrieval_waiting_for_records;
			log_default("[R%u->Q%u] Removing DNSKEY record from the zone - hostname: " PRI_DM_NAME, request_id, question_id, DM_NAME_PARAM(&zone->domain_name));
			goto exit;
		} else {
			result = dnssec_retrieval_no_new_change;
			goto exit;
		}
	} else {
		result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
		goto exit;
	}

	mDNSu32		now					= m->timenow;
	mDNSBool	new_record_added	= mDNSfalse;
	for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL; cache_record = cache_record->next) {
		ResourceRecord * const rr = &cache_record->resrec;
		mDNSBool cache_record_answers_question = SameNameCacheRecordAnswersQuestion(cache_record, question);
		if (!cache_record_answers_question) {
			continue;
		}

		ssize_t remaining_ttl = (size_t)rr->rroriginalttl - (now - cache_record->TimeRcvd) / mDNSPlatformOneSecond;
		if (remaining_ttl <= 0) {
			log_default("Ignoring record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
				DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);
			continue;
		}
		log_default("[R%u->Q%u] Adding record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
			request_id, question_id,
			DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);

		error = add_to_dnssec_zone_t(zone, rr, question->qtype);
		require_action_quiet(error == mStatus_NoError, exit, result = dnssec_retrieval_unknown_error);

		if (!new_record_added) {
			new_record_added	= mDNStrue;
		}
		last_time_received	= MAX(last_time_received, cache_record->TimeRcvd);
	}

	require_action_quiet(new_record_added, exit, result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
		log_error("[R%u->Q%u] No new record is being added into validation tree, while the TimeRcvd field has a greater value than the last update time of zone - "
			"returned rr name: " PRI_DM_NAME ", rr type: " PUB_S ", rr existence type: 0x%X, QC result: %u",
			request_id, question_id, DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->RecordType, add_record)
	);

	mDNSBool contains_rrsig = mDNSfalse;
	if (updated_type == kDNSType_DS) {
		if (new_record_added) {
			zone->dses_with_rrsig.set_completed = mDNStrue;
			zone->last_time_ds_add = last_time_received;
		}
		require_action_quiet(zone->dses_initialized, exit, result = dnssec_retrieval_invalid_internal_state;
			log_error("[R%u->Q%u] Have new records added into DS structure while the DS structure is not initialized"
				"returned rr name: " PRI_DM_NAME ", rr type: " PUB_S ", rr existence type: 0x%X, QC result: %u",
				request_id, question_id, DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->RecordType,
				add_record)
		);
		contains_rrsig = contains_rrsig_in_dses_with_rrsig_t(&zone->dses_with_rrsig);
	} else if (updated_type == kDNSType_DNSKEY) {
		if (new_record_added) {
			zone->dnskeys_with_rrsig.set_completed = mDNStrue;
			zone->last_time_dnskey_add = last_time_received;
		}
		contains_rrsig = contains_rrsig_in_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig);
	} else {
		result = dnssec_retrieval_non_dnskey_ds_record_for_zone;
		log_error("Non DS/DNSKEY response for DNSSEC zone; rr_type=" PUB_S, DNS_TYPE_STR(updated_type));
		goto exit;
	}
	require_action_quiet(contains_rrsig, exit, result = dnssec_retrieval_no_rrsig;
		log_error("No RRSIG records returned for DNSSEC query; qname=" PRI_DM_NAME ", qtype=" PUB_S,
			DM_NAME_PARAM(&question->qname), DNS_TYPE_STR(question->qtype)));

	result = dnssec_retrieval_no_error;
exit:
	return result;
}

#pragma mark get_time_received_for_answer
mDNSlocal mDNSs32
get_time_received_for_answer(
	const CacheGroup * const		_Nonnull	cache_group,
	const ResourceRecord * const	_Nonnull	answer) {

	mDNSs32 last_time_received = 0;

	for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL; cache_record = cache_record->next) {
		if (answer != &cache_record->resrec) {
			continue;
		}

		last_time_received	= cache_record->TimeRcvd;
		goto exit;
	}

exit:
	return last_time_received;
}

#pragma mark - update_original_from_cache_for_no_error_response

mDNSexport dnssec_retrieval_result_t
update_original_from_cache_for_no_error_response(
	mDNS * const					_Nonnull	m,
	const DNSQuestion * const		_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context) {

	dnssec_retrieval_result_t	result					= dnssec_retrieval_unknown_error;
	mStatus							error					= mStatus_UnknownErr;
	original_t * const				original				= &dnssec_context->original;
	originals_with_rrsig_t * const	originals_with_rrsig	= &original->original_result_with_rrsig;
	const CacheGroup *				cache_group;
	mDNSs32							last_time_received;
	mDNSu32							request_id				= dnssec_context->original.original_parameters.request_id;
	mDNSu16							question_id 			= mDNSVal16(question->TargetQID);

	cache_group = CacheGroupForName(m, question->qnamehash, &question->qname);
	require_action_quiet(cache_group != mDNSNULL, exit, result = dnssec_retrieval_invalid_internal_state;
		log_error("The question deos not have any corresponding cache group; qname=" PRI_DM_NAME,
			DM_NAME_PARAM(&question->qname)));

	last_time_received = get_time_received_for_answer(cache_group, answer);
	require_action_quiet(last_time_received != 0, exit, result = dnssec_retrieval_invalid_internal_state;
		log_error("Did not find answer in the cache group; qname=" PRI_DM_NAME " answer_name=" PRI_DM_NAME,
			DM_NAME_PARAM(&question->qname), DM_NAME_PARAM(answer->name)));

	if (add_record == QC_add && original->last_time_add < last_time_received) {
		// having new records added into the response
		original->last_time_add = last_time_received;

		if (originals_with_rrsig->type != unknown_response) {
			// the previous answer is NSEC, NSEC3 or suppressed fake negative cache
			uninitialize_originals_with_rrsig_t(&original->original_result_with_rrsig);
		}
	} else if (add_record == QC_rmv && original->last_time_rmv < last_time_received) {
		// having old records removed from the response
		response_type_t original_response_type = originals_with_rrsig->type;
		original->last_time_rmv = last_time_received;
		require_action_quiet(original_response_type != unknown_response, exit, result = dnssec_retrieval_invalid_internal_state);
		uninitialize_originals_with_rrsig_t(&original->original_result_with_rrsig);

		// check if there is still active sub CNAME request, if so, the CNAME request will be stopped by
		// handle_retrieval_result later.
		result = (original_response_type == cname_response) ?
			dnssec_retrieval_cname_removed : dnssec_retrieval_waiting_for_records;
		goto exit;
	} else {
		result = dnssec_retrieval_no_new_change;
		goto exit;
	}

	mDNSs32		now					= m->timenow;
	mDNSBool	new_record_added	= mDNSfalse;
	for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL; cache_record = cache_record->next) {
		ResourceRecord * const rr = &cache_record->resrec;
		mDNSBool cache_record_answers_question = SameNameCacheRecordAnswersQuestion(cache_record, question);
		if (!cache_record_answers_question) {
			continue;
		}

		ssize_t remaining_ttl = (size_t)rr->rroriginalttl - (now - cache_record->TimeRcvd) / mDNSPlatformOneSecond;
		if (remaining_ttl <= 0) {
			log_default("Ignoring record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
				DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);
			continue;
		}
		log_default("[R%u->Q%u] Adding record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
			request_id, question_id,
			DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);

		if (originals_with_rrsig->type == unknown_response) {
			// this is our first time to add the records into the list
			response_type_t type = determine_response_type(rr->rrtype, rr->rdata->u.data, question->qtype);
			require_action_quiet(type != unknown_response, exit, result = dnssec_retrieval_invalid_internal_state;
				log_error("Unrelated response to current query; question_type=" PUB_S ", response_type=" PUB_S,
					DNS_TYPE_STR(question->qtype), DNS_TYPE_STR(answer->rrtype)));
			initialize_originals_with_rrsig_t(&original->original_result_with_rrsig, type);

			if (type == cname_response) {
				QueryRecordClientRequest * const primary_request = GET_PRIMARY_REQUEST(dnssec_context);

				require_action_quiet(primary_request != mDNSNULL, exit,
					result = dnssec_retrieval_invalid_internal_state;
					log_error("[R%u] primary request has a NULL QueryRecordClientRequest", primary_request->op.reqID));

				// increment the referrals.
				primary_request->op.q.CNAMEReferrals++;
			}
		}

		error = add_to_originals_with_rrsig_t(originals_with_rrsig, rr, !question->InitialCacheMiss, dns_result_error, add_record);
		require_action_quiet(error == mStatus_NoError, exit, result = dnssec_retrieval_unknown_error);
		if (!new_record_added) {
			new_record_added	= mDNStrue;
		}
		last_time_received	= MAX(last_time_received, cache_record->TimeRcvd);
	}

	if (new_record_added) {
		original->last_time_add								= last_time_received;
	}
	mDNSBool contains_rrsig = mDNSfalse;
	contains_rrsig = contains_rrsig_in_originals_with_rrsig_t(&original->original_result_with_rrsig);
	require_action_quiet(contains_rrsig, exit, result = dnssec_retrieval_no_rrsig;
		log_error("No RRSIG records returned for DNSSEC query; qname=" PRI_DM_NAME ", qtype=" PUB_S,
			DM_NAME_PARAM(&question->qname), DNS_TYPE_STR(question->qtype)));

	result = dnssec_retrieval_no_error;
exit:
	return result;
}

#pragma mark get_updated_type_from_answer
mDNSlocal mDNSu16
get_updated_type_from_answer(const ResourceRecord * const _Nonnull answer) {
	mDNSu16 type = kDNSQType_ANY;

	if (answer->rrtype == kDNSType_RRSIG) {
		type = get_covered_type_of_dns_type_rrsig_t(answer->rdata->u.data);
	} else {
		type = answer->rrtype;
	}

	return type;
}

#pragma mark - update_original_from_cache_for_denial_of_existence_response

mDNSexport dnssec_retrieval_result_t
update_original_from_cache_for_denial_of_existence_response(
	const mDNS *const				_Nonnull	m,
	const DNSQuestion *				_Nonnull	question,
	ResourceRecord * const			_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context) {

	dnssec_retrieval_result_t		result = dnssec_retrieval_unknown_error;
	mStatus							error;
	original_t * const				original				= &dnssec_context->original;
	originals_with_rrsig_t * const	originals_with_rrsig	= &original->original_result_with_rrsig;
	const list_t *					denial_rrs; // list_t<dnssec_rr>
	const ResourceRecord *			first_rr				= mDNSNULL;
	const CacheGroup *				cache_group;
	mDNSs32							last_time_received;
	response_type_t					type;
	mDNSu32							request_id				= dnssec_context->original.original_parameters.request_id;
	mDNSu16							question_id 			= mDNSVal16(question->TargetQID);
	mDNSBool						suppressed				= add_record == QC_suppressed;

	if (dnssec_context->denial_of_existence_records != mDNSNULL) {
		denial_rrs = &dnssec_context->denial_of_existence_records->resource_records;
		require_action_quiet(!list_empty(denial_rrs), exit, result = dnssec_retrieval_invalid_internal_state);
	} else {
		denial_rrs = mDNSNULL;
	}

	cache_group = CacheGroupForName(m, question->qnamehash, &question->qname);
	require_action_quiet(cache_group != mDNSNULL || suppressed,
		exit, result = dnssec_retrieval_invalid_internal_state;
		log_error("The question deos not have any corresponding cache group; qname=" PRI_DM_NAME,
			DM_NAME_PARAM(&question->qname)));

	if (cache_group != mDNSNULL) {
		last_time_received = get_time_received_for_answer(cache_group, answer);
		require_action_quiet(last_time_received != 0, exit, result = dnssec_retrieval_invalid_internal_state;
			log_error("Did not find answer in the cache group; qname=" PRI_DM_NAME " answer_name=" PRI_DM_NAME,
				DM_NAME_PARAM(&question->qname), DM_NAME_PARAM(answer->name)));
	} else {
		last_time_received = INT_MIN;
	}

	if ((add_record == QC_add && original->last_time_add < last_time_received) || add_record == QC_suppressed) {
		// having new records added into the response, since negative answer is mutual exclusive, the previous answer
		// must be removed
		original->last_time_add = last_time_received;
		if (originals_with_rrsig->type != unknown_response) {
			uninitialize_originals_with_rrsig_t(&original->original_result_with_rrsig);
			original->last_time_rmv = last_time_received;
		}
	} else {
		result = dnssec_retrieval_no_new_change;
		goto exit;
	}

	require_action_quiet(add_record == QC_add || suppressed,
		exit, result = dnssec_retrieval_invalid_internal_state);

	if (denial_rrs != mDNSNULL && !list_empty(denial_rrs)) {
		first_rr = (ResourceRecord *)(list_get_first(denial_rrs)->data);
		type = determine_response_type(first_rr->rrtype, first_rr->rdata->u.data, question->qtype);
		require_action_quiet(type != unknown_response, exit, result = dnssec_retrieval_invalid_internal_state;
			log_error("Unrelated response to current query; question_type=" PUB_S ", response_type=" PUB_S,
				DNS_TYPE_STR(question->qtype), DNS_TYPE_STR(first_rr->rrtype)));
	} else {
		type = original_response;
	}

	initialize_originals_with_rrsig_t(originals_with_rrsig, type);

	if (type == nsec_response) {
		original->original_result_with_rrsig.u.nsecs_with_rrsig.negative_rr = answer;
		log_default("[R%u->Q%u] Adding negative answer verified by NSEC record; name=" PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, rdlength=%d",
			request_id, question_id,
			DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->rroriginalttl, answer->rdlength);
	} else if (type == nsec3_response) {
		original->original_result_with_rrsig.u.nsec3s_with_rrsig.negative_rr = answer;
		log_default("[R%u->Q%u] Adding negative answer verified by NSEC3 record; name=" PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, rdlength=%d",
			request_id, question_id,
			DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->rroriginalttl, answer->rdlength);
	} else if (type == original_response) {
		original->original_result_with_rrsig.u.original.negative_rr = answer;
		original->original_result_with_rrsig.u.original.suppressed_response = suppressed;
		if (!suppressed) {
			log_default("[R%u->Q%u] Adding negative answer not verified by any DNSSEC record; name=" PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, rdlength=%d",
				request_id, question_id,
				DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->rroriginalttl, answer->rdlength);
		} else {
			log_default("[R%u->Q%u] Adding negative answer suppressed by mDNSResponder; name=" PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, rdlength=%d",
				request_id, question_id,
				DM_NAME_PARAM(answer->name), DNSTypeName(answer->rrtype), answer->rroriginalttl, answer->rdlength);
			print_dnssec_context_t(dnssec_context);
		}
	} else {
		result = dnssec_retrieval_invalid_internal_state;
		goto exit;
	}

	if (denial_rrs != mDNSNULL) {
		for (const list_node_t *rr_node = list_get_first(denial_rrs); !list_has_ended(denial_rrs, rr_node); rr_node = list_next(rr_node)) {
			ResourceRecord * const rr = (ResourceRecord *)rr_node->data;

			log_default("[R%u->Q%u] Adding denial of existence record: name=" PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, rdlength=%d",
				request_id, question_id,
				DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, rr->rdlength);

			error = add_to_originals_with_rrsig_t(&original->original_result_with_rrsig, rr, !question->InitialCacheMiss, dns_result_error, add_record);
			require_action_quiet(error == mStatus_NoError, exit, result = dnssec_retrieval_unknown_error);
		}
	}

	mDNSBool contains_rrsig = mDNSfalse;
	contains_rrsig = contains_rrsig_in_originals_with_rrsig_t(&original->original_result_with_rrsig);
	require_action_quiet(contains_rrsig || suppressed, exit, result = dnssec_retrieval_no_rrsig;
		log_error("No RRSIG records returned for DNSSEC query; qname=" PRI_DM_NAME ", rr_type=" PUB_S,
			DM_NAME_PARAM(&question->qname),
			(first_rr != mDNSNULL) ? DNS_TYPE_STR(first_rr->rrtype) : DNS_TYPE_STR(question->qtype)));

	// add wildcard answer
	mDNSs32 now = m->timenow;
	if (answer->RecordType != kDNSRecordTypePacketNegative && cache_group != mDNSNULL) {
		for (CacheRecord *cache_record = cache_group->members; cache_record != mDNSNULL; cache_record = cache_record->next) {
			ResourceRecord * const rr = &cache_record->resrec;
			mDNSBool cache_record_answers_question = SameNameCacheRecordAnswersQuestion(cache_record, question);
			if (!cache_record_answers_question) {
				continue;
			}

			ssize_t remaining_ttl = (size_t)rr->rroriginalttl - (now - cache_record->TimeRcvd) / mDNSPlatformOneSecond;
			if (remaining_ttl <= 0) {
				log_default("Ignoring record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
					DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);
				continue;
			}
			log_default("[R%u->Q%u] Adding record: name="PRI_DM_NAME ", rr_type=" PUB_S ", original_ttl=%d, remaining_ttl=%zd, rdlength=%d",
				request_id, question_id,
				DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), rr->rroriginalttl, remaining_ttl, rr->rdlength);

			error = add_to_originals_with_rrsig_t(&original->original_result_with_rrsig, rr, !question->InitialCacheMiss, dns_result_error, add_record);
			require_action_quiet(error == mStatus_NoError, exit, result = dnssec_retrieval_record_not_added);
		}
	}

	result = suppressed ? dnssec_retrieval_suppressed : dnssec_retrieval_no_error;
exit:
	return result;
}


//======================================================================================================================
//	local function
//======================================================================================================================

//======================================================================================================================
//	determine_response_type
//======================================================================================================================

mDNSlocal response_type_t
determine_response_type(mDNSu16 rr_type, const mDNSu8 * const _Nullable rdata, const mDNSu16 question_type) {
	response_type_t response_type = unknown_response;

	switch (rr_type) {
		case kDNSType_CNAME:
			if (question_type != kDNSType_CNAME)	response_type	= cname_response;
			else									response_type	= original_response;
			break;
		case kDNSType_DS:
			verify(rr_type == question_type);
			response_type	= original_response;
			break;
		case kDNSType_RRSIG: {
			dns_type_rrsig_t *	rrsig_rdata		= (dns_type_rrsig_t *)rdata;
			mDNSu16				type_covered	= ntohs(rrsig_rdata->type_covered);
			require_action(type_covered != kDNSType_RRSIG, exit, response_type = unknown_response; log_error("Malformed RRSIG that covers RRSIG;"));
			response_type	= determine_response_type(type_covered, mDNSNULL, question_type);
		}
			break;
		case kDNSType_NSEC:
			response_type	= nsec_response;
			break;
		case kDNSType_DNSKEY:
			verify(rr_type == question_type);
			response_type	= original_response;
			break;
		case kDNSType_NSEC3:
			response_type	= nsec3_response;
			break;
		default:
			if (rr_type == question_type) {
				response_type = original_response;
			} else {
				response_type	= unknown_response;
			}
			break;
	}

exit:
	return response_type;
}

//======================================================================================================================
//	domain_name_end_with
//======================================================================================================================

mDNSlocal mDNSBool
domain_name_end_with(const mDNSu8 * const _Nonnull longer, const mDNSu8 * const _Nonnull shorter) {
	mDNSu32 longer_length	= DOMAIN_NAME_LENGTH(longer);
	mDNSu32 shorter_length	= DOMAIN_NAME_LENGTH(shorter);
	const mDNSu8 *longer_ptr;
	const mDNSu8 *shorter_ptr;

	if (longer_length < shorter_length) {
		return mDNSfalse;
	}

	longer_ptr	= longer + longer_length - 1;
	shorter_ptr = shorter + shorter_length - 1;

	for (mDNSu32 limit = shorter_length; limit > 0; limit--, longer_ptr--, shorter_ptr--) {
		if (*longer_ptr != *shorter_ptr) {
			return mDNSfalse;
		}
	}

	return mDNStrue;
}

//======================================================================================================================
//	get_parent_zone_name
//======================================================================================================================

mDNSlocal const mDNSu8 * _Nullable
get_parent_zone_name(const list_t * const _Nonnull zones, originals_with_rrsig_t * const _Nonnull original) {
	const list_t *				rrsig_records		= mDNSNULL;
	const dnssec_rrsig_t *		rrsig				= mDNSNULL;
	const mDNSu8 *				parent_zone_name	= mDNSNULL;

	if (list_empty(zones)) {
		switch (original->type) {
			case original_response:
				rrsig_records = &original->u.original.rrsig_records;
				break;
			case cname_response:
				rrsig_records = &original->u.cname_with_rrsig.rrsig_records;
				break;
			case nsec_response: {
				const list_t * const nsec_list = &original->u.nsecs_with_rrsig.nsec_and_rrsigs_same_name;
				const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)list_get_first(nsec_list)->data;
				rrsig_records = &one_nsec->rrsig_records;
				verify_action(nsec_nsec3_contains_rrsigs_with_same_signer(nsec_list, kDNSType_NSEC), return mDNSNULL);
				break;
			}
			case nsec3_response: {
				const list_t * const nsec3_list = &original->u.nsec3s_with_rrsig.nsec3_and_rrsigs_same_name;
				const one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t *)list_get_first(nsec3_list)->data;
				rrsig_records = &one_nsec3->rrsig_records;
				verify_action(nsec_nsec3_contains_rrsigs_with_same_signer(nsec3_list, kDNSType_NSEC3), return mDNSNULL);
				break;
			}
			default:
				break;
		}

		if (rrsig_records != mDNSNULL && !list_empty(rrsig_records)) {
			rrsig = (dnssec_rrsig_t *)list_get_first(rrsig_records)->data;
		}

	} else {
		dnssec_zone_t *			last_zone			= (dnssec_zone_t *)(list_get_last(zones)->data);
		dses_with_rrsig_t *		dses_with_rrsig		= &last_zone->dses_with_rrsig;

		if (last_zone->dses_initialized) {
			switch (dses_with_rrsig->type) {
				case original_response:
					rrsig_records = &dses_with_rrsig->u.original.rrsig_records;
					break;
				case nsec_response: {
					const list_t * const nsec_list = &dses_with_rrsig->u.nsecs_with_rrsig.nsec_and_rrsigs_same_name;
					const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)list_get_first(nsec_list)->data;
					rrsig_records = &one_nsec->rrsig_records;
					break;
				}
				case nsec3_response: {
					const list_t * const nsec3_list = &dses_with_rrsig->u.nsec3s_with_rrsig.nsec3_and_rrsigs_same_name;
					const one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t *)list_get_first(nsec3_list)->data;
					rrsig_records = &one_nsec3->rrsig_records;
					break;
				}
				default:
					break;
			}
		}

		if (rrsig_records != mDNSNULL && !list_empty(rrsig_records)) {
			rrsig = (dnssec_rrsig_t *)list_get_first(rrsig_records)->data;
		}
	}

	if (rrsig != mDNSNULL && domain_name_end_with(rrsig->dnssec_rr.name.c, rrsig->signer_name)) {
		parent_zone_name = rrsig->signer_name;
	}

	return parent_zone_name;
}

//======================================================================================================================
//	nsec_nsec3_contains_rrsigs_with_same_signer
//======================================================================================================================

mDNSlocal mDNSBool
nsec_nsec3_contains_rrsigs_with_same_signer(const list_t * const nsec_nsec3_list, mDNSu16 type)
{
	mDNSBool contains_the_same_signer = mDNSfalse;
	const list_t * first_rrsig_list = mDNSNULL;
	const dnssec_rrsig_t * first_rrsig = mDNSNULL;
	const mDNSu8 * signer_name = mDNSNULL;

	require_action_quiet(type == kDNSType_NSEC || type == kDNSType_NSEC3, exit, contains_the_same_signer = mDNSfalse;
		log_debug("NSEC/NSEC3 list contains records other than NSEC/NSEC3 - Type: " PUB_S, DNSTypeName(type)));

	require_action_quiet(!list_empty(nsec_nsec3_list), exit, contains_the_same_signer = mDNSfalse;
		log_debug("NSEC/NSEC3 list is empty, which should never happens"));

	if (type == kDNSType_NSEC) {
		const one_nsec_with_rrsigs_t * const first_one_nsec	= (one_nsec_with_rrsigs_t * )(list_get_first(nsec_nsec3_list)->data);
		first_rrsig_list = &first_one_nsec->rrsig_records;
	} else {
		// type == kDNSType_NSEC3
		const one_nsec3_with_rrsigs_t * const first_one_nsec3 = (one_nsec3_with_rrsigs_t * )(list_get_first(nsec_nsec3_list)->data);
		first_rrsig_list = &first_one_nsec3->rrsig_records;
	}

	require_action_quiet(!list_empty(first_rrsig_list), exit, contains_the_same_signer = mDNSfalse;
		log_debug("The RRSIG list of " PUB_S " is empty, such record should never be added into the list",
			DNSTypeName(type)));

	first_rrsig = (dnssec_rrsig_t *)(list_get_first(first_rrsig_list)->data);
	signer_name = first_rrsig->signer_name;

	for (const list_node_t * one_nsec_nsec3_node = list_get_first(nsec_nsec3_list);
		 !list_has_ended(nsec_nsec3_list, one_nsec_nsec3_node);
		 one_nsec_nsec3_node = list_next(one_nsec_nsec3_node)) {

		const list_t * rrsig_list = mDNSNULL;
		if (type == kDNSType_NSEC) {
			const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)one_nsec_nsec3_node->data;
			rrsig_list = &one_nsec->rrsig_records;
		} else { // type == kDNSType_NSEC3
			const one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t *)one_nsec_nsec3_node->data;
			rrsig_list = &one_nsec3->rrsig_records;
		}

		for (const list_node_t * rrsig_node = list_get_first(rrsig_list);
			 !list_has_ended(rrsig_list, rrsig_node);
			 rrsig_node = list_next(rrsig_node)) {

			const dnssec_rrsig_t * const dnssec_rrsig = (dnssec_rrsig_t *)(rrsig_node->data);
			const mDNSu8 * const signer_name_to_compare = dnssec_rrsig->signer_name;

			require_action_quiet(DOMAIN_NAME_EQUALS(signer_name, signer_name_to_compare), exit,
				contains_the_same_signer = mDNSfalse;
				log_debug("RRSIGs do not have the same signer name - Signer name 1: " PRI_DM_NAME ", Signer name 2: " PRI_DM_NAME,
					DM_NAME_PARAM((domainname *)signer_name), DM_NAME_PARAM((domainname *)signer_name_to_compare))
			);
		}
	}

	contains_the_same_signer = mDNStrue;
exit:
	return contains_the_same_signer;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
