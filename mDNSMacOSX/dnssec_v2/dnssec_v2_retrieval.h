//
//	dnssec_v2_retrieval.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_v2_RETRIEVAL_H
#define DNSSEC_v2_RETRIEVAL_H

#include "mDNSEmbeddedAPI.h"	//	for mStatus
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "ClientRequests.h"		// QueryRecordOp
#include "dnssec_v2_embedded.h" //	for dnssec_status_t
#include "dnssec_v2_structs.h"

typedef enum dnssec_retrieval_result {
	// normal
	dnssec_retrieval_no_error						= 0,
	dnssec_retrieval_waiting_for_records			= 1,
	dnssec_retrieval_validate_again					= 2,
	dnssec_retrieval_no_new_change					= 3,
	dnssec_retrieval_suppressed						= 4,
	dnssec_retrieval_cname_removed					= 5,

	// error
	dnssec_retrieval_no_rrsig						= -65537,
	dnssec_retrieval_zone_not_found					= -65538,
	dnssec_retrieval_invalid_qtype					= -65539,
	dnssec_retrieval_record_not_added				= -65540,
	dnssec_retrieval_no_record						= -65541,
	dnssec_retrieval_not_qc_add						= -65542,
	dnssec_retrieval_too_many_zones					= -65543,
	dnssec_retrieval_query_failed					= -65544,
	dnssec_retrieval_unknown_error					= -65545,
	dnssec_retrieval_invalid_wildcard				= -65546,
	dnssec_retrieval_invalid_internal_state			= -65547,
	dnssec_retrieval_non_dnskey_ds_record_for_zone	= -65548
} dnssec_retrieval_result_t;

//======================================================================================================================
//	function prototypes
//======================================================================================================================

// dnssec_status_t
mDNSexport mStatus
initialize_dnssec_status_t(dnssec_status_t * const _Nonnull status, const domainname * const _Nonnull qname,
	const mDNSu16 qtype, const mDNSu32 flags, void * const _Nonnull context);

mDNSexport mStatus
uninitialize_dnssec_status_t(dnssec_status_t * const _Nonnull status);

#pragma mark - dnssec_context_t function prototypes
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
	dnssec_context_t * _Nullable * const	_Nonnull	out_dnssec_context);

mDNSexport void
print_dnssec_context_t(const dnssec_context_t * const _Nonnull context);

mDNSexport void
destroy_dnssec_context_t(dnssec_context_t * const _Nonnull context);

mDNSexport dnssec_retrieval_result_t
add_no_error_records(
	mDNS *const						_Nonnull	m,
	DNSQuestion *					_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context);

mDNSexport dnssec_retrieval_result_t
add_denial_of_existence_records(
	const mDNS *const				_Nonnull	m,
	const DNSQuestion *				_Nonnull	question,
	ResourceRecord * const			_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context);

mDNSexport dnssec_retrieval_result_t
fetch_necessary_dnssec_records(dnssec_context_t * const _Nonnull context, mDNSBool anchor_reached);

// list_t<dnssec_zone_t>
mDNSexport dnssec_zone_t * _Nullable
find_dnssec_zone_t(const list_t * const _Nonnull zones, const mDNSu8 * const _Nonnull name);

// cnames_with_rrsig_t
mDNSexport mStatus
add_to_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cnames_with_rrisg, ResourceRecord * const _Nonnull rr);

mDNSexport mDNSBool
remove_from_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cnames_with_rrisg, const ResourceRecord * const _Nonnull rr);

// nsecs_with_rrsig_t
mDNSexport mStatus
add_to_nsec_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs_with_rrisg, ResourceRecord * const _Nonnull rr);

mDNSexport mDNSBool
remove_from_nsec_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs_with_rrisg, const ResourceRecord * const _Nonnull rr);

// nsec3s_with_rrsig_t
mDNSexport mStatus
add_to_nsec3_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s_with_rrisg, ResourceRecord * const _Nonnull rr);

mDNSexport mDNSBool
remove_from_nsec3_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s_with_rrisg, const ResourceRecord * const _Nonnull rr);

// originals_with_rrsig_t
mDNSexport mStatus
add_to_originals_with_rrsig_t(
	originals_with_rrsig_t * const	_Nonnull	originals_with_rrisg,
	ResourceRecord * const			_Nonnull	rr,
	const mDNSBool								answer_from_cache,
	const DNSServiceErrorType					dns_error,
	const QC_result								qc_result);

mDNSexport void
remove_from_originals_with_rrsig_t(
	originals_with_rrsig_t * const	_Nonnull	originals_with_rrisg,
	const ResourceRecord * const	_Nonnull	rr);

// dnskeys_with_rrsig_t
mDNSexport mStatus
add_to_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskeys_with_rrsig, ResourceRecord * const _Nonnull rr);

mDNSexport void
remove_from_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskeys_with_rrsig, const ResourceRecord * const _Nonnull rr);

// dses_with_rrsig_t
mDNSexport mStatus
add_to_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull dses_with_rrsig, ResourceRecord * const _Nonnull rr);

mDNSexport void
remove_from_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull dses_with_rrsig, const ResourceRecord * const _Nonnull rr);

// denial_of_existence_records_t
mDNSexport denial_of_existence_records_t * _Nullable
create_denial_of_existence_records_t(void);

mDNSexport void
destroy_denial_of_existence_records_t(denial_of_existence_records_t * const _Nonnull denial_of_existence_records);

mDNSexport void
destroy_denial_of_existence_records_t_if_nonnull(denial_of_existence_records_t * const _Nonnull denial_of_existence_records);

mDNSexport mStatus
add_to_denial_of_existence_records_t(denial_of_existence_records_t * const _Nonnull denial_of_existence_records, const ResourceRecord * const _Nonnull rr);

// dnssec_zone_t
mDNSexport mStatus
add_to_dnssec_zone_t(
	dnssec_zone_t * const			_Nonnull	zone,
	ResourceRecord * const	_Nonnull	rr,
	const mDNSu16								question_type);

mDNSexport dnssec_retrieval_result_t
update_dnssec_zone_t_from_cache_for_no_error_response(
	const mDNS * const				_Nonnull	m,
	const DNSQuestion * const		_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	dnssec_zone_t * const			_Nonnull	zone);

mDNSexport dnssec_retrieval_result_t
update_original_from_cache_for_no_error_response(
	mDNS * const					_Nonnull	m,
	const DNSQuestion * const		_Nonnull	question,
	const ResourceRecord * const	_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context);

mDNSexport dnssec_retrieval_result_t
update_original_from_cache_for_denial_of_existence_response(
	const mDNS *const				_Nonnull	m,
	const DNSQuestion *				_Nonnull	question,
	ResourceRecord * const			_Nonnull	answer,
	const QC_result								add_record,
	const DNSServiceErrorType					dns_result_error,
	dnssec_context_t * const		_Nonnull	dnssec_context);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif /* DNSSEC_v2_RETRIEVAL_H */
