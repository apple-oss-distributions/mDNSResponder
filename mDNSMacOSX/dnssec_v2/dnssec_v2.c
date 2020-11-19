//
//	dnssec_v2.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include <AssertMacros.h>		// for require_* macro
#include <os/feature_private.h> // for feature flag
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "uds_daemon.h"
#include "DNSCommon.h"
#include "dnssec_v2.h"
#include "dnssec_v2_helper.h"
#include "dnssec_v2_validation.h"
#include "dnssec_v2_trust_anchor.h"
#include "dnssec_v2_client.h"

// MARK: - Macros

#define DNSSEC_OK_BIT 0x8000

// MARK: - External Functions

mDNSexport mDNSBool
enables_dnssec_validation(const DNSQuestion * _Nonnull q) {
	return q->DNSSECStatus.enable_dnssec;
}

//======================================================================================================================

// Check if the question could be validated with DNSSEC.
mDNSexport mDNSBool
is_eligible_for_dnssec(const domainname * const _Nonnull name, mDNSu16 question_type) {
	mDNSBool is_eligible = mDNSfalse;

	require_quiet(!IsLocalDomain(name), exit);
	require_quiet(question_type != kDNSServiceType_RRSIG, exit);
	require_quiet(question_type != kDNSServiceType_ANY, exit);

	is_eligible = mDNStrue;
exit:
	return is_eligible;
}

//======================================================================================================================

mDNSexport void
get_denial_records_from_negative_cache_to_dnssec_context(
	const mDNSBool							enable_dnssec,
	dnssec_context_t * const	_Nonnull	context,
	CacheRecord * const			_Nonnull	rr) {

	if (enable_dnssec) {
		context->denial_of_existence_records = rr->denial_of_existence_records;
	}
}

//======================================================================================================================

mDNSexport void
set_denial_records_in_cache_record(
	CacheRecord * const 				_Nonnull				cache_record,
	denial_of_existence_records_t * 	_Nullable *	_Nonnull	denial_records_ptr) {

	cache_record->denial_of_existence_records = *denial_records_ptr;
	*denial_records_ptr = mDNSNULL;
}

//======================================================================================================================

mDNSexport void
release_denial_records_in_cache_record(CacheRecord * const _Nonnull cache_record) {
	if (cache_record->denial_of_existence_records != mDNSNULL) {
		destroy_denial_of_existence_records_t(cache_record->denial_of_existence_records);
		cache_record->denial_of_existence_records = mDNSNULL;
	}
}

//======================================================================================================================

mDNSexport void
update_denial_records_in_cache_record(
	CacheRecord * const 				_Nonnull 				cache_record,
	denial_of_existence_records_t * 	_Nullable *	_Nonnull	denial_records_ptr) {

	if (cache_record->denial_of_existence_records != mDNSNULL) {
		destroy_denial_of_existence_records_t(cache_record->denial_of_existence_records);
	}
	cache_record->denial_of_existence_records = *denial_records_ptr;
	*denial_records_ptr = mDNSNULL;
}

//======================================================================================================================

mDNSexport mDNSBool
adds_denial_records_in_cache_record(
	const ResourceRecord * 			_Nonnull const			rr,
	const mDNSBool 											enable_dnssec,
	denial_of_existence_records_t *	_Nullable * _Nonnull	denials_ptr) {

	mDNSBool not_answer_but_required_for_dnssec = mDNSfalse;
	mStatus error = mStatus_NoError;

	require_quiet(enable_dnssec, exit);
	require_quiet(record_denies_existence_of_dnssec_question(rr), exit);

	if (*denials_ptr == mDNSNULL) {
		*denials_ptr = create_denial_of_existence_records_t();
		require_quiet(*denials_ptr != mDNSNULL, exit);
	}

	error = add_to_denial_of_existence_records_t(*denials_ptr, rr);
	require_quiet(error == mStatus_NoError, exit);
	not_answer_but_required_for_dnssec = mDNStrue;

exit:
	if (error != mStatus_NoError) {
		if (*denials_ptr != mDNSNULL) destroy_denial_of_existence_records_t(*denials_ptr);
		*denials_ptr = mDNSNULL;
	}
	return not_answer_but_required_for_dnssec;
}

//======================================================================================================================

mDNSexport mDNSBool
are_records_in_the_same_cache_set_for_dnssec(
	const ResourceRecord * const _Nonnull left,
	const ResourceRecord * const _Nonnull right) {

	if (left->rrtype != kDNSType_RRSIG) {
		return mDNStrue;
	}

	return rrsig_records_cover_the_same_record_type(left, right);
}

//======================================================================================================================

// Check if the current record type belongs to the question that enables DNSSEC.
mDNSexport mDNSBool
record_type_answers_dnssec_question(const ResourceRecord * const _Nonnull record, const mDNSu16 qtype) {
	mDNSBool result = mDNSfalse;

	switch (record->rrtype) {
		case kDNSType_CNAME:
			result		= mDNStrue;
			break;
		case kDNSType_RRSIG: {
			mDNSu16 type_covered	= get_covered_type_of_dns_type_rrsig_t(record->rdata->u.data);

			if (qtype == kDNSType_RRSIG
				|| type_covered == qtype
				|| type_covered == kDNSType_CNAME) { // Returned RRSIG covers a CNAME for the current question.
				// RRSIG that covers NSEC/NSEC3 also answers question, but it provides non-existence proof.
				result = mDNStrue;
			}
		}
			break;
		// kDNSType_DS and kDNSType_DNSKEY also applies to the default case here.
		default:
			if (record->rrtype == qtype) {
				result = mDNStrue;
			}
			// NSEC/NSEC3 or RRSIG that covers NSEC/NSEC3 also answers question, but they provides non-existence proof,
			// so they do not answer the question positively, and the function should return false.
			break;
	}

	return result;
}

//======================================================================================================================

mDNSexport mDNSBool
rrsig_records_cover_the_same_record_type(const ResourceRecord * const _Nonnull left, const ResourceRecord * const _Nonnull right) {
	mDNSu16 type_covered_left	= get_covered_type_of_dns_type_rrsig_t(left->rdata->u.data);
	mDNSu16 type_covered_right	= get_covered_type_of_dns_type_rrsig_t(right->rdata->u.data);

	return type_covered_left == type_covered_right;
}

//======================================================================================================================

// Used by mDNSCoreReceiveResponse, to check if the current NSEC/NSEC3 record belongs to the question that enables DNSSEC
mDNSexport mDNSBool
record_denies_existence_of_dnssec_question(const ResourceRecord * const _Nonnull record) {
	const mDNSu16	rr_type							= record->rrtype;
	mDNSu16			type_covered;
	mDNSBool		acceptable_denial_of_existence	= mDNSfalse;

	// Temporarily disbale NSEC validation, it should also check if it is NSEC(or the corresponding RRSIG covers NSEC)
	if (rr_type == kDNSType_NSEC3) {
		acceptable_denial_of_existence = mDNStrue;
	} else if (rr_type == kDNSType_RRSIG) {
		type_covered = get_covered_type_of_dns_type_rrsig_t(record->rdata->u.data);
		// Same here, temporarily disbale NSEC validation.
		if (type_covered == kDNSType_NSEC3) {
			acceptable_denial_of_existence = mDNStrue;
		}
	}

	return acceptable_denial_of_existence;
}

//======================================================================================================================

// The main DNSSEC callback function, it replaces the original user callback function, and becomes a middle layer
// between the mDNSCore and user callback function, all the DNSSEC related operation happens here:
// 1. Records retrieval
// 2. Records validation
mDNSexport void
query_record_result_reply_with_dnssec(
	mDNS *const						_Null_unspecified	m,
	DNSQuestion *					_Null_unspecified	question,
	const ResourceRecord * const	_Null_unspecified	const_answer,
	QC_result											add_record,
	DNSServiceErrorType									dns_result_error,
	void *							_Null_unspecified	context) {

	dnssec_context_t *				dnssec_context		= (dnssec_context_t *)context;
	QueryRecordClientRequest *		primary_request		= GET_PRIMARY_REQUEST(dnssec_context);
	ResourceRecord * const			answer				= (ResourceRecord *)const_answer;
	mDNSBool						anchor_reached		= mDNSfalse;
	mDNSBool						stop_process		= mDNSfalse;
	dnssec_retrieval_result_t		retrieval_result	= dnssec_retrieval_no_error;
	dnssec_validation_result_t		validation_result;
	mDNSu32							request_id			= primary_request->op.reqID;
	returned_answers_t * const		returned_answers	= &dnssec_context->returned_answers;

	switch (add_record) {
		case QC_add:
		case QC_rmv:
		case QC_suppressed:
			break;
		// QC_addnocache and QC_forceresponse are all cases where the returned resource record is not in the cache.
		// We temporarily ignore those two cases.
		case QC_addnocache:
		case QC_forceresponse:
		default:
			log_error("[R%u] QC_result other than add, remove, suppressed is returned; add_record=%d",
				request_id, add_record);
			return;
	}

	if (dns_result_error == kDNSServiceErr_NoError) {
		retrieval_result = add_no_error_records(m, question, answer, add_record, dns_result_error, dnssec_context);
	} else {
		retrieval_result = add_denial_of_existence_records(m, question, answer, add_record, dns_result_error, dnssec_context);
	}

	do {
		// handle any error case when addign records
		stop_process = handle_retrieval_result(question, context, retrieval_result, dns_result_error, m);
		// WARNING: If stop_process is set to true here, we should not touch anything including dnssec_context, because
		// we might free the object related to the current dnssec request, and we would get memory fault if using it.

		// If we have error when adding record, then we should not continue.
		if (stop_process) {
			break;
		}

		// check if we could reach the trust anchor with the records we have currently
		anchor_reached = trust_anchor_can_be_reached(dnssec_context);
		if (anchor_reached) {
			// if so, validate the from the leaf to the root(trust anchor)
			validation_result = validate_dnssec(dnssec_context);

			// handle the validation result such as returning DNSSEC-secure answer to user, return error code to user
			stop_process = handle_validation_result(question, context, validation_result, dns_result_error, m);

			// If we already returned the answer/error to user, there is no more to do.
			if (stop_process) {
				break;
			}
		} else if (returned_answers->error != kDNSServiceErr_Invalid) {
			// previous verified record set cannot establish trust chain, deliver rmv event for all returned records
			if (returned_answers->type != cname_response) { // Do not deliver RMV for CNAME records.
				// Since here we are returning the records on the behave of the primary request, the question being
				// returned should be the question from the primary request instead of the possible CNAME question that
				// is started by the DNSSEC handler itself.
				stop_process = deliver_remove_to_callback_with_all_returned_answers(dnssec_context, returned_answers, m,
					GET_PRIMARY_QUESTION(dnssec_context), question);
				require_quiet(!stop_process, exit);
			}
			uninitialize_returned_answers_t(returned_answers);
			initialize_returned_answers_t(returned_answers, dnssec_indeterminate, kDNSServiceErr_Invalid);
		}

		// If the records we have currently is not enough to form a chian of trust, keep querying for more records until
		// the trust anchor
		retrieval_result = fetch_necessary_dnssec_records(dnssec_context, anchor_reached);

		// handle the result of fetch_necessary_dnssec_records such as returning error to user if some error occurs when
		// querying for more records
		stop_process =	handle_retrieval_result(question, context, retrieval_result, dns_result_error, m);
		if (stop_process) {
			break;
		}
	} while (retrieval_result == dnssec_retrieval_validate_again);

exit:
	return;
}

//======================================================================================================================

mDNSexport void
stop_dnssec_if_enable_dnssec(QueryRecordClientRequest * const _Nonnull request) {
	DNSQuestion * const q = &request->op.q;
	if (!q->DNSSECStatus.enable_dnssec) {
		return;
	}
	stop_dnssec(request);
}


//======================================================================================================================

mDNSexport void
stop_dnssec(QueryRecordClientRequest * const _Nonnull request) {
	DNSQuestion * const			q				= &request->op.q;
	mDNSu32						request_id		= request->op.reqID;
	if (!q->DNSSECStatus.enable_dnssec) {
		goto exit;
	}

	dnssec_context_t * const	dnssec_context	= (dnssec_context_t *)q->DNSSECStatus.context;
	list_t * const				zones			= &dnssec_context->zone_chain;
	original_t * const			original		= &dnssec_context->original;
	const original_request_parameters_t * const param = &original->original_parameters;

	log_default("[R%u] Stopping " PUB_S "DNSSEC request -- hostname: " PRI_DM_NAME ", type: " PUB_S, request_id,
		dnssec_context->primary_dnssec_context == mDNSNULL ? "primary " : "sub-",
		DM_NAME_PARAM(&param->question_name), DNSTypeName(param->question_type));

	// stop and clean zone, dnssec_zone_t node will be deleted in destroy_dnssec_context_t
	for (list_node_t * zone_node = list_get_first(zones); !list_has_ended(zones, zone_node); zone_node = list_next(zone_node)) {
		dnssec_zone_t * zone = (dnssec_zone_t *)zone_node->data;
		stop_and_clean_dnssec_zone_t(zone);
	}

	// Stop the sub CNAME request.
	if (dnssec_context->subtask_dnssec_context != mDNSNULL) {
		// Since we will not deliver RMV so there is no need to check if we should stop the request immediately because
		// the client cancels the request in the callback.
		stop_sub_cname_request_and_dnssec(q, dnssec_context, mDNSfalse, mDNSNULL);
	}

	// leave original->original_request to be released by QueryRecordClientRequestStop
	uninitialize_originals_with_rrsig_t(&original->original_result_with_rrsig);

	// undo create_dnssec_context_t
	destroy_dnssec_context_t(dnssec_context);

exit:
	return;
}

//======================================================================================================================

mDNSexport mDNSBool
stop_sub_cname_request_and_dnssec(DNSQuestion * const question, dnssec_context_t * const _Nonnull dnssec_context,
	const mDNSBool deliver_remove, mDNS * const _Nullable m) {

	dnssec_context_t * const cname_dnssec_context = dnssec_context->subtask_dnssec_context;
	DNSQuestion * const primary_question = GET_PRIMARY_QUESTION(dnssec_context);
	mDNSBool stop_immediately = mDNSfalse;
	require_quiet(cname_dnssec_context != mDNSNULL, exit);

	// If we call this function because the CNAME reference chain has changed, all the answers that
	// are returned to the client needs to be removed first.
	if (deliver_remove) {
		for (dnssec_context_t * context_i = cname_dnssec_context; context_i != mDNSNULL; context_i = context_i->subtask_dnssec_context) {
			// if it is not kDNSServiceErr_Invalid, it means that we have returned something.
			if (context_i->returned_answers.error == kDNSServiceErr_Invalid) {
				continue;
			}
			// Do not deliver RMV event for CNAME answer, since mDNSResponder never rewinds the CNAME chain, DNSSEC API
			// needs to follow the same behavior.
			if (context_i->returned_answers.type == cname_response) {
				continue;
			}
			stop_immediately = deliver_remove_to_callback_with_all_returned_answers(context_i,
				&context_i->returned_answers, m, primary_question, question);
			require_quiet(!stop_immediately, exit);
		}
	}

	QueryRecordClientRequest * cname_request = cname_dnssec_context->me;
	require_action_quiet(cname_request == &dnssec_context->request_to_follow_cname, exit, stop_immediately = mDNStrue;
		log_debug("cname request does not points back to the request_to_follow_cname"));
	QueryRecordOpStopForClientRequest(&cname_request->op);
	stop_dnssec(cname_request);
	dnssec_context->subtask_dnssec_context = mDNSNULL;

exit:
	return stop_immediately;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
