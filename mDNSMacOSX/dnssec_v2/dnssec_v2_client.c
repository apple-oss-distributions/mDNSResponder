//
//	dnssec_v2_client.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "udns.h"
#include "dnssec_v2.h"
#include "dnssec_v2_client.h"
#include "dnssec_v2_retrieval.h"
#include "dnssec_v2_helper.h"

//======================================================================================================================
//	Local function prototype
//======================================================================================================================

// When calling remove_records_if_necessary/add_records_if_necessary, always check the boolean value stored in
// out_stop_immediately. If the value is true, then the caller should stop all the work immediately and return, because
// the functions might call the callback function which may cancel the current request and the question we are working
// on.

mDNSlocal mDNSBool
remove_records_if_necessary(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	mDNS * const							mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	mDNSBool * 					_Nonnull	out_stop_immediately);

mDNSlocal mDNSBool
add_records_if_necessary(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	const DNSServiceErrorType				dns_error_from_core,
	mDNS * const							mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	mDNSBool *					_Nonnull	out_stop_immediately);

mDNSlocal mStatus
handle_cname_response(dnssec_context_t * const _Nonnull context);

// Always check the return value of return_answer_to_user. If the value is true, then the caller should stop all the
// work immediately and return, because the functions may call the callback function which may cancel the current
// request and the question we are working on.
mDNSlocal mDNSBool
return_answer_to_user(
	QueryRecordResultHandler					user_handler,
	void * const								user_context,
	dnssec_result_t								result,
	ResourceRecord * const			_Nonnull	rr,
	const QC_result								add_or_remove,
	const DNSServiceErrorType					dns_error,
	mDNS * const					_Nonnull	m,
	DNSQuestion * const				_Nonnull	primary_question,
	const DNSQuestion * const		_Nonnull	current_question);

mDNSlocal mStatus
add_record_to_be_returned_to_returned_answers_t(returned_answers_t * const returned_asnwers, const ResourceRecord * const rr);

mDNSlocal mDNSBool
contains_rr_in_returned_rrs(const ResourceRecord * const rr, const list_t * const returned_rrs/* list_t<ResourceRecord *> */);

mDNSlocal DNSServiceErrorType
get_dnsservice_error_type_from_originals(const original_t * const _Nonnull original, DNSServiceErrorType type_from_mDNSCore);

#pragma mark - handle_validation_result

mDNSlocal void
handle_cname_retrieval_error(dnssec_context_t * const _Nonnull dnssec_context,
	mDNS * const _Nonnull mdnsresponder_context);

mDNSexport mDNSBool
handle_retrieval_result(
	DNSQuestion * const			_Nonnull	question,
	dnssec_context_t *			_Nonnull	original_dnssec_context,
	dnssec_retrieval_result_t				retrieval_result,
	const DNSServiceErrorType				dnssec_error,
	mDNS * const				_Nonnull	mdnsresponder_context) {

	mDNSBool			stop					= mDNSfalse;
	// We use a new variable here so that current_dnssec_context can be set to NULL when it is freed, to avoid corrupted
	// memory access.
	dnssec_context_t *	current_dnssec_context	= original_dnssec_context;
	mDNSu32				request_id				= current_dnssec_context->original.original_parameters.request_id;
	mDNSu16				question_id 			= mDNSVal16(question->TargetQID);
	dnssec_result_t		dnssec_result;
	mDNSBool			stop_immediately = mDNSfalse;

	switch (retrieval_result) {
		case dnssec_retrieval_no_error:
		case dnssec_retrieval_waiting_for_records:	// We are waiting for the response for some active queries.
		case dnssec_retrieval_validate_again:		// We have a trust anchor for the current root, and will use it to validate immediately.
			stop = mDNSfalse;
			break;

		case dnssec_retrieval_no_new_change:
			stop = mDNStrue;
			break;

		case dnssec_retrieval_no_rrsig: {				// The returned answer is missing some necessary records to finish DNSSEC, it usually means the domain is not signed, thus it is an insecure zone.
			mDNSu16			question_type = current_dnssec_context->original.original_parameters.question_type;
			response_type_t	response_type = current_dnssec_context->original.original_result_with_rrsig.type;

			dnssec_result = dnssec_insecure;
			stop = mDNStrue;

			if (response_type == cname_response && question_type != kDNSServiceType_CNAME) {
				// After calling handle_cname_retrieval_error, dnssec_context will be freed, and should never be used.
				handle_cname_retrieval_error(current_dnssec_context, mdnsresponder_context);
				// Set current_dnssec_context to NULL to avoid any further access.
				current_dnssec_context = NULL;
				goto exit;
			}

			remove_records_if_necessary(current_dnssec_context, dnssec_result, mdnsresponder_context, question,
				&stop_immediately);
			require_quiet(!stop_immediately, exit);

			add_records_if_necessary(current_dnssec_context, dnssec_result, dnssec_error, mdnsresponder_context,
				question, &stop_immediately);
			require_quiet(!stop_immediately, exit);
		}
			break;
		case dnssec_retrieval_suppressed: {
			// Suppressed answers are generated by mDNSResponder itself, and we do not have a way to validate this
			// generated record, thus the DNSSEC result should be indeterminate.
			dnssec_result	= dnssec_indeterminate;
			stop			= mDNStrue;

			remove_records_if_necessary(current_dnssec_context, dnssec_result, mdnsresponder_context, question,
				&stop_immediately);
			require_quiet(!stop_immediately, exit);
			add_records_if_necessary(current_dnssec_context, dnssec_result, dnssec_error, mdnsresponder_context,
				question, &stop_immediately);
			require_quiet(!stop_immediately, exit);
		}
			break;
		case dnssec_retrieval_cname_removed: {
			// if the CNAME is removed, then the sub request that follows this removed CNAME is no longer valid, and
			// we need to stop it. If the CNAME record does not exist anymore, there is nothing we could do to validate
			// the record(Maybe later we would get NSEC/NSEC3 records that denies the existence of this CNAME),
			// therefore, it is marked as indeterminate.
			dnssec_result = dnssec_indeterminate;
			stop = mDNStrue;

			remove_records_if_necessary(current_dnssec_context, dnssec_result, mdnsresponder_context, question,
				&stop_immediately);
			require_quiet(!stop_immediately, exit);

			require_action_quiet(current_dnssec_context->subtask_dnssec_context != mDNSNULL, exit, stop = mDNStrue;
				log_error("[R%u->Q%u] Get dnssec_retrieval_cname_removed error while the context of CNAME request is NULL",
					request_id, question_id));

			stop_immediately = stop_sub_cname_request_and_dnssec(question, current_dnssec_context, mDNStrue, mdnsresponder_context);
			require_quiet(!stop_immediately, exit);
			// Since the previous CNAME we rely on is removed, there is nothing we can do next, so we should stop the
			// current processing.

		}
			break;
		default:
			stop = mDNStrue;
			log_error("[R%u->Q%u] handle_retrieval_result not handling this type of error; retrieval_result=%d",
				request_id, question_id, retrieval_result);
			break;
	}

exit:
	return stop || stop_immediately;
}

//======================================================================================================================

mDNSlocal void
handle_cname_retrieval_error(dnssec_context_t * const _Nonnull dnssec_context,
	mDNS * const _Nonnull mdnsresponder_context)
{
	dnssec_context_t * const primary_dnssec_context = GET_PRIMARY_DNSSEC_CONTEXT(dnssec_context);
	QueryRecordClientRequest * const query_request = GET_PRIMARY_REQUEST(dnssec_context);
	DNSQuestion * const q = &query_request->op.q;
	QueryRecordResultHandler user_handler = primary_dnssec_context->original.original_parameters.user_handler;
	void * const user_context = primary_dnssec_context->original.original_parameters.user_context;
	cnames_with_rrsig_t *cname_ptr;
	list_node_t *cname_node;
	dnssec_cname_t * dnssec_cname;
	ResourceRecord * rr_ptr;

	// Get the CNAME that has no RRSIG
	cname_ptr = &dnssec_context->original.original_result_with_rrsig.u.cname_with_rrsig;
	cname_node = list_get_first(&cname_ptr->cname_records);
	// Should never be NULL, but add checking here to avoid invalid memory access.
	verify_action(cname_node != mDNSNULL, return);
	dnssec_cname = (dnssec_cname_t *)cname_node->data;
	rr_ptr = dnssec_cname->dnssec_rr.rr; // this pointer points to the cached resource record in mDNSCore.
	// Should never be NULL, since when dnssec_cname_t is initialized in initialize_dnssec_cname_t, the rr has to be non-NULL.
	verify_action(rr_ptr != mDNSNULL, return);

	// After calling this function, dnssec_context has been freed, and should never be used.
	stop_dnssec(query_request);

	query_request->op.resultHandler = user_handler; // change the user handler back to original one
	query_request->op.resultContext = user_context; // change the user context back to original one

	// Have to grab the lock to avoid any call when we are restarting the query.
	mDNS_Lock(mdnsresponder_context);
	AnswerQuestionByFollowingCNAME(mdnsresponder_context, q, rr_ptr);
	mDNS_Unlock(mdnsresponder_context);

	// Disable DNSSEC for the current request.
	q->DNSSECStatus.enable_dnssec				= mDNSfalse;
	q->DNSSECStatus.tried_dnssec_but_unsigned	= mDNStrue;
	q->DNSSECStatus.context						= mDNSNULL;
}

//======================================================================================================================
//	handle_validation_result
//		When error happens or validation succeeds while we are validating records, handle it such as return the answer to user
//======================================================================================================================

#pragma mark - handle_validation_result

mDNSlocal mStatus
handle_cname_response(dnssec_context_t * const _Nonnull context);

mDNSexport mDNSBool
handle_validation_result(
	DNSQuestion * const			_Nonnull	question,
	dnssec_context_t * const	_Nonnull	dnssec_context,
	dnssec_validation_result_t				validation_result,
	const DNSServiceErrorType				dnssec_error,
	mDNS * const				_Nonnull	mdnsresponder_context) {

	mStatus			error				= mStatus_NoError;
	mDNSBool		stop				= mDNSfalse;
	mDNSBool		stop_immediately	= mDNSfalse;
	dnssec_result_t	dnssec_result;

	switch (validation_result) {
		case dnssec_validation_trusted: {
			// return the secure answer to the user or continue the DNSSEC validation process if the verified answer is
			// CNAME and user is not querying for CNAME record
			mDNSu16			question_type = dnssec_context->original.original_parameters.question_type;
			response_type_t	response_type = dnssec_context->original.original_result_with_rrsig.type;
			dnssec_context_t * const cname_dnssec_context = dnssec_context->subtask_dnssec_context;
			dnssec_result = dnssec_secure;

			if (response_type == cname_response && question_type != kDNSType_CNAME) {
				if (cname_dnssec_context != mDNSNULL) {
					// stop the old CNAME request, if the reference has changed
					const list_t *			cnames		= &dnssec_context->original.original_result_with_rrsig.u.cname_with_rrsig.cname_records;
					const mDNSu8 * const	new_cname	= ((dnssec_cname_t *)list_get_first(cnames)->data)->cname;
					const mDNSu8 * const	old_cname	= cname_dnssec_context->original.original_parameters.question_name.c;

					if (DOMAIN_NAME_EQUALS(new_cname, old_cname)) {
						// CNAME reference does not change
						stop = mDNStrue;
						goto exit;
					}

					// stop CNAME request and also deliver RMV event for those records that are returned to the client.
					stop_immediately = stop_sub_cname_request_and_dnssec(question, dnssec_context, mDNStrue, mdnsresponder_context);
					require_quiet(!stop_immediately, exit);
				}
				error = handle_cname_response(dnssec_context);
				if (error != mStatus_NoError) {
					stop = mDNStrue;
					goto exit;
				}
				stop = mDNStrue;
				// if the user requries CNAME refrence to be returned
				mDNSBool return_intermediates = ((dnssec_context->original.original_parameters.flags & kDNSServiceFlagsReturnIntermediates) != 0);
				if (!return_intermediates) {
					goto exit;
				}
				// fall outside of it intentionally
			}
			stop = mDNStrue;
			remove_records_if_necessary(dnssec_context, dnssec_result, mdnsresponder_context, question,
				&stop_immediately);
			require_quiet(!stop_immediately, exit);
			add_records_if_necessary(dnssec_context, dnssec_result, dnssec_error, mdnsresponder_context, question,
				&stop_immediately);
			require_quiet(!stop_immediately, exit);
			goto exit;
		}
		case dnssec_validation_trust_anchor_does_not_macth: {
			const dnssec_zone_t * const zone = list_empty(&dnssec_context->zone_chain) ? mDNSNULL : (dnssec_zone_t *)list_get_last(&dnssec_context->zone_chain)->data;
			if (zone != mDNSNULL && is_root_domain(zone->domain_name.c) && !trust_anchor_contains_dnskey(zone->trust_anchor)) {
				// root DS trust anchor failed to validate the record, maybe update our trust anchor
				stop = mDNStrue;
				log_error("root trust anchor does not verifies the validation tree");
				break;
			} else {
				// tries to fetch records from the DNS server instead of using local trust anchor
				goto exit;
			}
		}
			break;
		default:
			stop = mDNStrue;
			log_error("handle_validation_result not hanlding this type of error; validation_result=%d", validation_result);
			break;
	}

exit:
	return stop || stop_immediately;
}


#pragma mark handle_cname_response
// follow the CNAME reference chain, create another DNSSEC request to finish the CNAME query
mDNSlocal mStatus
handle_cname_response(dnssec_context_t * const _Nonnull context) {
	response_type_t 				type = context->original.original_result_with_rrsig.type;
	domainname *					old_question_name;
	original_request_parameters_t * parameters;
	domainname						new_question_name;
	dnssec_context_t *				new_context = mDNSNULL;
	mStatus							error		= mStatus_NoError;

	// handle the cname referencing
	list_t *cnames = &context->original.original_result_with_rrsig.u.cname_with_rrsig.cname_records;
	verify(type == cname_response && list_count_node(cnames) == 1);
	old_question_name = (domainname *)(((dnssec_cname_t *)list_get_first(cnames)->data)->cname);
	AssignDomainName(&new_question_name, old_question_name);

	// Create new dnssec_context_t for the CNAME
	parameters = &context->original.original_parameters;
	error = create_dnssec_context_t(mDNSNULL, parameters->request_id, &new_question_name, parameters->question_type,
		parameters->question_class, parameters->interface_id, parameters->service_id, parameters->flags,
		parameters->append_search_domains, parameters->pid, parameters->uuid, parameters->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
		parameters->has_peer_audit_token ? &parameters->peer_audit_token : mDNSNULL,
		parameters->has_delegate_audit_token ? &parameters->delegate_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		parameters->resolver_uuid, parameters->need_encryption, parameters->custom_id,
#endif
		parameters->user_handler, parameters->user_context,
		context->primary_dnssec_context ? context->primary_dnssec_context : context,
		&new_context);
	require_action(error == mStatus_NoError, exit,
		log_error("create_dnssec_context_t failed; error_description='%s'", mStatusDescription(error)));

	new_context->me = &context->request_to_follow_cname;

	// start a new dnssec request with new_question_name
	error = QueryRecordOpStartForClientRequest(&new_context->me->op, parameters->request_id, &new_question_name,
		parameters->question_type, parameters->question_class, parameters->interface_id, parameters->service_id,
		parameters->flags, parameters->append_search_domains, parameters->pid, parameters->uuid, parameters->uid,
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
		parameters->has_peer_audit_token ? &parameters->peer_audit_token : mDNSNULL,
		parameters->has_delegate_audit_token ? &parameters->delegate_audit_token : mDNSNULL,
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		parameters->resolver_uuid, parameters->need_encryption, parameters->custom_id,
#endif
		query_record_result_reply_with_dnssec, new_context);
	require_action(error == mStatus_NoError, exit,
		log_error("QueryRecordOpStart failed; error_description='%s'", mStatusDescription(error)));

	context->subtask_dnssec_context = new_context;

exit:
	if (error != mStatus_NoError) {
		if (new_context != mDNSNULL) {
			destroy_dnssec_context_t(new_context);
		}
	}
	return error;
}

#pragma mark remove_records_if_necessary

mDNSlocal mDNSBool
deliver_remove_for_returned_records(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	mDNS * const				_Nonnull	mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	const response_type_t					type,
	mDNSBool *					_Nonnull	out_stop_immediately);

mDNSlocal mDNSBool
remove_records_if_necessary(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	mDNS * const				_Nonnull	mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	mDNSBool * 					_Nonnull	out_stop_immediately) {

	returned_answers_t * const		returned_answers		= &dnssec_context->returned_answers;
	const original_t * const		original				= &dnssec_context->original;
	mDNSBool						delivered_remove_all	= mDNSfalse;
	mDNSBool						delivered_remove_some	= mDNSfalse;

	// check if we ever returned answers back to the user
	if (returned_answers->error == kDNSServiceErr_Invalid) {
		// there is no previous returned anwers(which means this is our first time to return the answer to the user)
		goto exit;
	}

	// if we return No Error answer to the user
	if (returned_answers->error == kDNSServiceErr_NoError) {
		require_action_quiet(returned_answers->type == original_response || returned_answers->type == cname_response,
			exit, log_error("kDNSServiceErr_NoError must be matched with original_response or cname_response"));
		if (original->original_result_with_rrsig.type == returned_answers->type && dnssec_result == returned_answers->dnssec_result) {
			// No Error response with no DNSSEC result change
			delivered_remove_some = deliver_remove_for_returned_records(dnssec_context, dnssec_result,
				mdnsresponder_context, question, returned_answers->type, out_stop_immediately);
			require_quiet(!(*out_stop_immediately), exit);
		} else {
			// either the response is no longer the original response or the dnssec validation result has changed
			delivered_remove_all = mDNStrue;
		}
		goto exit;
	}

	// if we return No Such Name or No Such Record to deny the existence of some records
	if (returned_answers->error == kDNSServiceErr_NoSuchName || returned_answers->error == kDNSServiceErr_NoSuchRecord) {
		if (returned_answers->type == nsec_response) {
			if (original->original_result_with_rrsig.type == nsec_response && dnssec_result == dnssec_secure) {
				// unchanged NSEC response with no DNSSEC result change
				delivered_remove_some = deliver_remove_for_returned_records(dnssec_context, dnssec_result,
					mdnsresponder_context, question, nsec_response, out_stop_immediately);
				require_quiet(!(*out_stop_immediately), exit);
			} else {
				delivered_remove_all = mDNStrue;
			}
		} else if (returned_answers->type == nsec3_response) {
			if (original->original_result_with_rrsig.type == nsec3_response && dnssec_result == dnssec_secure) {
				// unchanged NSEC3 response with no DNSSEC result change
				delivered_remove_some = deliver_remove_for_returned_records(dnssec_context, dnssec_result,
					mdnsresponder_context, question, nsec3_response, out_stop_immediately);
				require_quiet(!(*out_stop_immediately), exit);
			} else {
				delivered_remove_all = mDNStrue;
			}
		} else if (returned_answers->type == original_response) {
			// The zone is unsigned
			if (original->original_result_with_rrsig.type == original_response && dnssec_result == dnssec_insecure) {
				// The zone is unsigned, and returns No Such Name or No Such Record, nothing has changed
				delivered_remove_some = deliver_remove_for_returned_records(dnssec_context, dnssec_result,
					mdnsresponder_context, question, original_response, out_stop_immediately);
				require_quiet(!(*out_stop_immediately), exit);
			} else {
				delivered_remove_all = mDNStrue;
			}
		} else {
			log_error("kDNSServiceErr_NoSuchName/kDNSServiceErr_NoSuchRecord must be matched with nsec_response/nsec3_response");
			goto exit;
		}

		goto exit;
	}

exit:
	if (delivered_remove_all) {
		*out_stop_immediately = deliver_remove_to_callback_with_all_returned_answers(dnssec_context, returned_answers,
			mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
		// Check if the callback in deliver_remove_to_callback_with_all_returned_answers has already deleted the
		// current request and question. If so we should not touch anything.
		if (!(*out_stop_immediately)) {
			uninitialize_returned_answers_t(returned_answers);
			initialize_returned_answers_t(returned_answers, dnssec_indeterminate, kDNSServiceErr_Invalid);
		}
	}
	return delivered_remove_all || delivered_remove_some;
}

#pragma mark return_answer_to_user
// return_answer_to_user returns whether the caller should stop the DNSSEC-related processing. If it returns true,
// it means that the callback has stopped the request and deleted the current question, and all the current work should
// be stopped because the callback has stopped the request and deleted the current question. If we continue to process
// more, we may access the memory that has already been freed.
mDNSlocal mDNSBool
return_answer_to_user(
	QueryRecordResultHandler					user_handler,
	void * const								user_context,
	dnssec_result_t								result,
	ResourceRecord * const			_Nonnull	rr,
	const QC_result								add_or_remove,
	const DNSServiceErrorType					dns_error,
	mDNS * const					_Nonnull	m,
	DNSQuestion * const				_Nonnull	primary_question,
	const DNSQuestion * const		_Nonnull	current_question) {

	rr->dnssec_result = result;
	user_handler(m, primary_question, rr, add_or_remove, dns_error, user_context);
	rr->dnssec_result = dnssec_indeterminate;

	return m->CurrentQuestion != current_question;
}

#pragma mark - add_records_if_necessary

mDNSlocal mDNSBool
add_records_if_necessary(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	const DNSServiceErrorType				dns_error_from_core,
	mDNS * const							mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	mDNSBool *					_Nonnull	out_stop_immediately) {

	originals_with_rrsig_t *	originals_with_rrsig	= &dnssec_context->original.original_result_with_rrsig;
	returned_answers_t * const	returned_answers		= &dnssec_context->returned_answers;
	list_t * const				returned_rrs			= &returned_answers->answers;
	mDNSBool					add_records				= mDNSfalse;
	QueryRecordResultHandler	user_handler			= dnssec_context->original.original_parameters.user_handler;
	void * const				user_context			= dnssec_context->original.original_parameters.user_context;
	DNSServiceErrorType			dns_error				= get_dnsservice_error_type_from_originals(&dnssec_context->original, dns_error_from_core);
	mDNSBool					stop_immediately		= mDNSfalse;
	mStatus						error;

	if (returned_answers->error == kDNSServiceErr_Invalid) {
		// It is our first time to return the response back to callback
		initialize_returned_answers_t(returned_answers, dnssec_result, dns_error);
	} else {
		returned_answers->error = dns_error_from_core;
	}

	switch (originals_with_rrsig->type) {
		case original_response: {
			list_t * const dnssec_originals = &originals_with_rrsig->u.original.original_records;
			if (originals_with_rrsig->u.original.negative_rr != mDNSNULL) {
				ResourceRecord * const rr = originals_with_rrsig->u.original.negative_rr;
				mDNSBool contained_in_returned_answer = contains_rr_in_returned_rrs(rr, returned_rrs);
				if (contained_in_returned_answer) {
					break;
				}

				error = add_record_to_be_returned_to_returned_answers_t(&dnssec_context->returned_answers, rr);
				require_quiet(error == mStatus_NoError, exit);

				stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_add,
					dns_error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
				add_records = mDNStrue;
				require_quiet(!stop_immediately, exit);
				returned_answers->type = original_response;
			} else {
				for (const list_node_t * dnssec_original_node = list_get_first(dnssec_originals);
					!list_has_ended(dnssec_originals, dnssec_original_node);
					dnssec_original_node = list_next(dnssec_original_node)) {

					dnssec_original_t * const dnssec_original = (dnssec_original_t *)dnssec_original_node->data;
					ResourceRecord * const rr = dnssec_original->dnssec_rr.rr;
					mDNSBool contained_in_returned_answer = contains_rr_in_returned_rrs(rr, returned_rrs);
					if (contained_in_returned_answer) {
						continue;
					}

					error = add_record_to_be_returned_to_returned_answers_t(returned_answers, rr);
					require_quiet(error == mStatus_NoError, exit);

					stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_add,
						dns_error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
					add_records = mDNStrue;
					require_quiet(!stop_immediately, exit);
				}
			}
			returned_answers->type = original_response;
		}
			break;
		case cname_response: {
			list_t * const dnssec_cnames = &originals_with_rrsig->u.cname_with_rrsig.cname_records;
			for (const list_node_t * dnssec_cname_node = list_get_first(dnssec_cnames);
				!list_has_ended(dnssec_cnames, dnssec_cname_node);
				dnssec_cname_node = list_next(dnssec_cname_node)) {

				dnssec_cname_t * const dnssec_cname		= (dnssec_cname_t *)dnssec_cname_node->data;
				ResourceRecord * const rr				= dnssec_cname->dnssec_rr.rr;
				mDNSBool contained_in_returned_answer 	= contains_rr_in_returned_rrs(rr, returned_rrs);
				if (contained_in_returned_answer) {
					continue;
				}

				error = add_record_to_be_returned_to_returned_answers_t(returned_answers, rr);
				require_quiet(error == mStatus_NoError, exit);

				stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_add,
					dns_error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
				add_records = mDNStrue;
				require_quiet(!stop_immediately, exit);
			}
			returned_answers->type = cname_response;
		}
			break;
		case nsec_response: {
			ResourceRecord * const rr = originals_with_rrsig->u.nsecs_with_rrsig.negative_rr;
			mDNSBool contained_in_returned_answer = contains_rr_in_returned_rrs(rr, returned_rrs);
			if (contained_in_returned_answer) {
				break;
			}

			error = add_record_to_be_returned_to_returned_answers_t(&dnssec_context->returned_answers, rr);
			require_quiet(error == mStatus_NoError, exit);

			stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_add, dns_error,
				mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
			add_records = mDNStrue;
			require_quiet(!stop_immediately, exit);
			returned_answers->type = nsec_response;
		}
			break;
		case nsec3_response: {
			ResourceRecord * const rr = originals_with_rrsig->u.nsec3s_with_rrsig.negative_rr;
			mDNSBool contained_in_returned_answer = contains_rr_in_returned_rrs(rr, returned_rrs);
			if (contained_in_returned_answer) {
				break;
			}

			error = add_record_to_be_returned_to_returned_answers_t(&dnssec_context->returned_answers, rr);
			require_quiet(error == mStatus_NoError, exit);

			stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_add, dns_error,
				mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
			add_records = mDNStrue;
			require_quiet(!stop_immediately, exit);
			returned_answers->type = nsec3_response;
		}
			break;
		default:
			goto exit;
	}

exit:
	if (out_stop_immediately != mDNSNULL) {
		*out_stop_immediately = stop_immediately;
	}
	return add_records;
}


#pragma mark - returned_answers_t



#pragma mark add_record_to_be_returned_to_returned_answers_t
mDNSlocal mStatus
add_record_to_be_returned_to_returned_answers_t(returned_answers_t * const returned_asnwers, const ResourceRecord * const rr) {
	const ResourceRecord ** inserted_rr;
	mStatus error;

	require_action_quiet(rr != mDNSNULL, exit, error = mStatus_BadReferenceErr);

	// No need to remember if we returned negative answer to the user since wo do not need to send RMV for negative record
	if (rr->RecordType == kDNSRecordTypePacketNegative) {
		error = mStatus_NoError;
		goto exit;
	}

	error = list_append_uinitialized(&returned_asnwers->answers, sizeof(ResourceRecord *), (void **)&inserted_rr);
	require_quiet(error == mStatus_NoError, exit);

	*inserted_rr = rr;

exit:
	return error;
}

#pragma mark get_dnsservice_error_type_from_originals
mDNSlocal DNSServiceErrorType
get_dnsservice_error_type_from_originals(const original_t * const _Nonnull original, DNSServiceErrorType type_from_mDNSCore) {
	response_type_t type		= original->original_result_with_rrsig.type;
	DNSServiceErrorType error	= kDNSServiceErr_Invalid;

	if (type == original_response) {
		if (original->original_result_with_rrsig.u.original.negative_rr != mDNSNULL) {
			error = type_from_mDNSCore;
		} else {
			error = kDNSServiceErr_NoError;
		}
	} else if (type == cname_response) {
		error = kDNSServiceErr_NoError;
	} else if (type == nsec_response) {
		dnssec_validation_result_t validation_result = original->original_result_with_rrsig.u.nsecs_with_rrsig.nsec_result;
		switch (validation_result) {
			case dnssec_validation_nsec_name_error:
				error = kDNSServiceErr_NoSuchName;
				break;
			case dnssec_validation_nsec_no_data:
				error = kDNSServiceErr_NoSuchRecord;
				break;
			case dnssec_validation_nsec_wildcard_answer:
			case dnssec_validation_nsec_wildcard_no_data:
				log_error("wildcard not handled");
			default:
				break;
		}
	} else if (type == nsec3_response) {
		dnssec_validation_result_t validation_result = original->original_result_with_rrsig.u.nsec3s_with_rrsig.nsec3_result;
		switch (validation_result) {
			case dnssec_validation_nsec3_name_error:
				error = kDNSServiceErr_NoSuchName;
				break;
			case dnssec_validation_nsec3_no_data_response:
				error = kDNSServiceErr_NoSuchRecord;
				break;
			case dnssec_validation_nsec3_wildcard_answer_response:
			case dnssec_validation_nsec3_wildcard_no_data:
				log_error("wildcard not handled");
				break;
			default:
				break;
		}
	} else {
		log_error("Original response has type other than 'original_response', 'cname_response', 'nsec_response', 'nsec3_response'");
	}

	return error;
}

#pragma mark deliver_remove_to_callback_with_all_returned_answer
// deliver_remove_to_callback_with_all_returned_answers returns whether the caller should stop the DNSSEC-related
// processing. If it returns true, it means that the callback has stopped the request and deleted the current question,
// and all the current work should be stopped because the callback has stopped the request and deleted the current
// question. If we continue to process more, we may access the memory that has already been freed.
mDNSexport mDNSBool
deliver_remove_to_callback_with_all_returned_answers(
	const dnssec_context_t * const		_Nonnull	context,
	const returned_answers_t * const	_Nonnull	returned_answers,
	mDNS * const						_Nonnull	m,
	DNSQuestion * const					_Nonnull	primary_question,
	const DNSQuestion * const			_Nonnull	current_question) {

	mDNSBool stop_immediately = mDNSfalse;

	require_quiet(returned_answers->error != kDNSServiceErr_Invalid, exit);

	const list_t * const		returned_rrs	= &returned_answers->answers;
	QueryRecordResultHandler	user_handler	= context->original.original_parameters.user_handler;
	void * const				user_context	= context->original.original_parameters.user_context;

	for (const list_node_t * rr_node = list_get_first(returned_rrs); !list_has_ended(returned_rrs, rr_node); rr_node = list_next(rr_node)) {
		ResourceRecord * const * const rr_ptr = (ResourceRecord * const * const)rr_node->data;
		ResourceRecord * const rr = *rr_ptr;
		// 1. No need to deliver RMV for negative answer, such as No Such Record.
		// 2. No need to deliver RMV for CNAME answer.
		if (rr->RecordType == kDNSRecordTypePacketNegative || rr->rrtype == kDNSType_CNAME) {
			continue;
		}
		stop_immediately = return_answer_to_user(user_handler, user_context, returned_answers->dnssec_result, rr,
			QC_rmv, returned_answers->error, m, primary_question, current_question);
		require_quiet(!stop_immediately, exit);
	}

exit:
	return stop_immediately;
}

#pragma mark deliver_remove_for_returned_records

mDNSlocal mDNSBool
contains_rr_in_original_records(const ResourceRecord * const rr, const list_t * const original_records/* list_t<dnssec_original_t> */) {
	mDNSBool contains = mDNSfalse;

	for (const list_node_t * original_record_node = list_get_first(original_records);
			!list_has_ended(original_records, original_record_node);
			original_record_node = list_next(original_record_node)) {

		const dnssec_original_t * const dnssec_original = (dnssec_original_t *)original_record_node->data;
		if (dnssec_original->dnssec_rr.rr == rr) {
			contains = mDNStrue;
			goto exit;
		}
	}

exit:
	return contains;
}

mDNSlocal mDNSBool
deliver_remove_for_returned_records(
	dnssec_context_t * const	_Nonnull	dnssec_context,
	const dnssec_result_t					dnssec_result,
	mDNS * const				_Nonnull	mdnsresponder_context,
	DNSQuestion * const			_Nonnull	question,
	const response_type_t					type,
	mDNSBool *					_Nonnull	out_stop_immediately) {

	returned_answers_t * const			returned_answers	= &dnssec_context->returned_answers;
	list_t * const						returned_rrs		= &returned_answers->answers;
	QueryRecordResultHandler			user_handler		= dnssec_context->original.original_parameters.user_handler;
	void * const						user_context		= dnssec_context->original.original_parameters.user_context;
	originals_with_rrsig_t * const		originals_with_rrsig = &dnssec_context->original.original_result_with_rrsig;
	mDNSu32								request_id			= dnssec_context->original.original_parameters.request_id;
	mDNSu16								question_id 		= mDNSVal16(question->TargetQID);
	mDNSBool							remove_some			= mDNSfalse;
	mDNSBool							stop_immediately	= mDNSfalse;

	if (type == original_response) {
		for (list_node_t * rr_node = list_get_first(returned_rrs), *next_node; !list_has_ended(returned_rrs, rr_node); rr_node = next_node) {
			ResourceRecord * const * const rr_ptr = (ResourceRecord * const * const)rr_node->data;
			ResourceRecord *rr = *rr_ptr;
			next_node = list_next(rr_node);
			mDNSBool contains = mDNStrue;
			if (returned_answers->error == kDNSServiceErr_NoError) {
				contains = contains_rr_in_original_records(rr, &originals_with_rrsig->u.original.original_records);
			} else if (returned_answers->error == kDNSServiceErr_NoSuchName || returned_answers->error == kDNSServiceErr_NoSuchRecord) {
				contains = (rr == originals_with_rrsig->u.original.negative_rr);
			} else {
				log_error("[R%u->Q%u] when the DNSSEC response is original response, only NoError, NoSuchName and NoSuchRecord are allowed"
					" - response type: " PUB_S ", kDNSServiceErr type: %u",
					request_id, question_id, response_type_value_to_string(type), returned_answers->error);
				goto exit;
			}
			if (!contains) {
				stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_rmv,
					returned_answers->error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
				remove_some = mDNStrue;
				require_quiet(!stop_immediately, exit);
				list_node_delete(rr_node);
			}
		}
	} else if (type == nsec_response) {
		require_action_quiet(
			returned_answers->error == kDNSServiceErr_NoSuchName || returned_answers->error == kDNSServiceErr_NoSuchRecord,
			exit,
			log_error("[R%u->Q%u] when the NSEC response is original response, only NoSuchName and NoSuchRecord are allowed"
				" - response type: " PUB_S ", kDNSServiceErr type: %u",
				request_id, question_id, response_type_value_to_string(type), returned_answers->error)
		);

		require_action_quiet(list_count_node(returned_rrs) == 1, exit,
			log_error("[R%u->Q%u] Denail of existence answer returns more than one negative answer with NSEC proof - number_of_records: %u",
				request_id, question_id, list_count_node(returned_rrs)));

		ResourceRecord * const * const rr_ptr = (ResourceRecord * const * const)(list_get_first(returned_rrs)->data);
		ResourceRecord *rr = *rr_ptr;
		if (rr != originals_with_rrsig->u.nsecs_with_rrsig.negative_rr) {
			stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_rmv,
				returned_answers->error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
			remove_some = mDNStrue;
			require_quiet(!stop_immediately, exit);
			// Deletes the removed record.
			list_node_delete_all(returned_rrs);
		}
	} else if (type == nsec3_response) {
		require_action_quiet(
			returned_answers->error == kDNSServiceErr_NoSuchName || returned_answers->error == kDNSServiceErr_NoSuchRecord,
			exit,
			log_error("[R%u->Q%u] when the NSEC3 response is original response, only NoSuchName and NoSuchRecord are allowed"
				" - response type: " PUB_S ", kDNSServiceErr type: %u",
				request_id, question_id, response_type_value_to_string(type), returned_answers->error)
		);

		require_action_quiet(list_count_node(returned_rrs) == 1, exit,
			log_error("[R%u->Q%u] Denail of existence answer returns more than one negative answer with NSEC3 proof - number_of_records: %u",
				request_id, question_id, list_count_node(returned_rrs)));

		ResourceRecord * const * const rr_ptr = (ResourceRecord * const * const)(list_get_first(returned_rrs)->data);
		ResourceRecord *rr = *rr_ptr;
		if (rr != originals_with_rrsig->u.nsec3s_with_rrsig.negative_rr) {
			stop_immediately = return_answer_to_user(user_handler, user_context, dnssec_result, rr, QC_rmv,
				returned_answers->error, mdnsresponder_context, GET_PRIMARY_QUESTION(dnssec_context), question);
			remove_some = mDNStrue;
			require_quiet(!stop_immediately, exit);
			// Deletes the removed record.
			list_node_delete_all(returned_rrs);
		}
	} else {
		// cname_response or other invalid value
		log_error("[R%u->Q%u] Invalid returned answers response type - response type: " PUB_S, request_id, question_id,
			response_type_value_to_string(type));
		goto exit;
	}

exit:
	if (out_stop_immediately != mDNSNULL) {
		*out_stop_immediately = stop_immediately;
	}
	return remove_some;
}

#pragma mark contains_rr_in_returned_rrs
mDNSlocal mDNSBool
contains_rr_in_returned_rrs(const ResourceRecord * const rr, const list_t * const returned_rrs/* list_t<ResourceRecord *> */) {
	mDNSBool contains = mDNSfalse;

	for (const list_node_t *rr_ptr_node = list_get_first(returned_rrs);
			!list_has_ended(returned_rrs, rr_ptr_node);
			rr_ptr_node = list_next(rr_ptr_node)) {

		const ResourceRecord * const * const	rr_to_compare_ptr	= (const ResourceRecord * const * const)rr_ptr_node->data;
		const ResourceRecord * const			rr_to_compare		= *rr_to_compare_ptr;

		if (rr == rr_to_compare) {
			contains = mDNStrue;
			goto exit;
		}
	}

exit:
	return contains;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
