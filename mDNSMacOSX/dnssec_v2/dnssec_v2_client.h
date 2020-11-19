//
//	dnssec_v2_client.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_CLIENT_H
#define DNSSEC_V2_CLIENT_H

#include <stdio.h>
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec_v2_structs.h"
#include "dnssec_v2_retrieval.h"
#include "dnssec_v2_validation.h"

//======================================================================================================================
//    function prototypes
//======================================================================================================================

mDNSexport mDNSBool
handle_retrieval_result(
	DNSQuestion * const			_Nonnull	question,
	dnssec_context_t *			_Nonnull	original_dnssec_context,
	dnssec_retrieval_result_t				retrieval_result,
	const DNSServiceErrorType				dnssec_error,
	mDNS * const				_Nonnull	mdnsresponder_context);

mDNSexport mDNSBool
handle_validation_result(
	DNSQuestion * const			_Nonnull	question,
	dnssec_context_t * const	_Nonnull	dnssec_context,
	dnssec_validation_result_t				validation_result,
	const DNSServiceErrorType				dnssec_error,
	mDNS * const				_Nonnull	mdnsresponder_context);

/*!
 * @brief
 * 		Delivers RMV events to the callback function for all the  returned answers.
 *
 * @param context
 * 		A pointer to the DNSSEC context of the current request.
 *
 * @param returned_answers
 * 		A pointer to the structure that stores all the answers returned to the callback.
 *
 * @param m
 * 		A pointer to the mDNS structure.
 *
 * @param primary_question
 * 		A pointer to the question created by the primary request, which is started by the client.
 *
 * @param current_question
 * 		A pointer to the question that we are currently working on, it is used to determine if the question has been deleted by the callback.
 *
 * @return
 * 		A boolean value to indicate if the caller should stop all the work immediately. If it returns true, it means that the callback called by this function has canceled
 * 		the current request and its corresponding question, and the caller should assume that all the allocated memory it owns has already been freed, and it
 * 		should stop immediately to avoid invalid memory access.
 */
mDNSexport mDNSBool
deliver_remove_to_callback_with_all_returned_answers(
	const dnssec_context_t * const		_Nonnull	context,
	const returned_answers_t * const	_Nonnull	returned_answers,
	mDNS * const						_Nonnull	m,
	DNSQuestion * const					_Nonnull	primary_question,
	const DNSQuestion * const			_Nonnull	current_question);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_V2_CLIENT_H
