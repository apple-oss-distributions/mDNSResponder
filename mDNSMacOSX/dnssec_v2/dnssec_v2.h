//
//	dnssec_v2.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_H
#define DNSSEC_V2_H

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <os/feature_private.h>
#include "dnssec_v2_embedded.h"
#include "dnssec_v2_structs.h"
#include "dnssec_v2_retrieval.h"
#include "dnssec_v2_validation.h"
#include "dnssec_v2_trust_anchor.h"
#include "dnssec_v2_log.h"
#include "base_n.h"
#include "list.h"

//======================================================================================================================
//	Constants
//======================================================================================================================

#define EDNS0_SENDER_UDP_PAYLOAD_SIZE	512
#define MAX_ZONES_ALLOWED				10

//======================================================================================================================
//	Macros
//======================================================================================================================

#define FLAGS_CONTAIN_DNSOK_BIT(FLAGS) (((FLAGS) & kDNSServiceFlagsEnableDNSSEC) != 0)

//======================================================================================================================
//	functions
//======================================================================================================================

mDNSexport mDNSBool
enables_dnssec_validation(const DNSQuestion * _Nonnull q);

mDNSexport mDNSBool
is_eligible_for_dnssec(const domainname * const _Nonnull name, mDNSu16 question_type);

mDNSexport void
get_denial_records_from_negative_cache_to_dnssec_context(
	const mDNSBool							enable_dnssec,
	dnssec_context_t * const	_Nonnull	context,
	CacheRecord * const			_Nonnull	rr);

mDNSexport void
set_denial_records_in_cache_record(
	CacheRecord * const 				_Nonnull				cache_record,
	denial_of_existence_records_t * 	_Nullable *	_Nonnull	denial_records_ptr);

mDNSexport void
release_denial_records_in_cache_record(CacheRecord * const _Nonnull cache_record);

mDNSexport void
update_denial_records_in_cache_record(
	CacheRecord * const 				_Nonnull 				cache_record,
	denial_of_existence_records_t * 	_Nullable *	_Nonnull	denial_records_ptr);

mDNSexport mDNSBool
adds_denial_records_in_cache_record(
	const ResourceRecord * 			_Nonnull const			rr,
	const mDNSBool 											enable_dnssec,
	denial_of_existence_records_t *	_Nullable * _Nonnull	denials_ptr);

mDNSexport mDNSBool
are_records_in_the_same_cache_set_for_dnssec(
	const ResourceRecord * const _Nonnull left,
	const ResourceRecord * const _Nonnull right);

mDNSexport mDNSBool
record_type_answers_dnssec_question(const ResourceRecord * const _Nonnull record, const mDNSu16 qtype);

mDNSexport mDNSBool
rrsig_records_cover_the_same_record_type(const ResourceRecord * const _Nonnull left, const ResourceRecord * const _Nonnull right);

mDNSexport mDNSBool
record_denies_existence_of_dnssec_question(const ResourceRecord * const _Nonnull record);

mDNSexport void
query_record_result_reply_with_dnssec(
	mDNS *const						_Null_unspecified	__unused m,
	DNSQuestion *					_Null_unspecified	question,
	const ResourceRecord * const	_Null_unspecified	answer,
	QC_result											add_record,
	DNSServiceErrorType									dns_result_error,
	void *							_Null_unspecified	context);

mDNSexport void
stop_dnssec_if_enable_dnssec(QueryRecordClientRequest * const _Nonnull request);

mDNSexport void
stop_dnssec(QueryRecordClientRequest * const _Nonnull request);

/*!
 * @brief
 * 		Stops the sub request started by the current request, and also possibly delivers RMV events for all the returned answers.
 *
 * @param dnssec_context
 * 		A pointer to the DNSSEC context of the current request.
 *
 * @param deliver_remove
 * 		A boolean value to indicate if the function should deliver the RMV events for those records that have been returned to the client.
 *
 * @param m
 * 		A pointer to the mDNS structure.
 *
 * @return
 * 		A boolean value to indicate if the caller should stop all the work immediately. If it returns true, it means that the callback called by this function has canceled
 * 		the current request and its corresponding question, and the caller should assume that all the allocated memory it owns has already been freed, and it
 * 		should stop immediately to avoid invalid memory access.
 */
mDNSexport mDNSBool
stop_sub_cname_request_and_dnssec(DNSQuestion * const _Nonnull question, dnssec_context_t * const _Nonnull dnssec_context,
	const mDNSBool deliver_remove, mDNS * const _Nullable m);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_V2_H
