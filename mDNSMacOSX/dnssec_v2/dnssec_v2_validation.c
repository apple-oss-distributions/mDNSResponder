//
//	dnssec_v2_validation.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <string.h>					// for strerror
#include <errno.h>					// for errno
#include "DNSCommon.h"				// DomainNameHashValue
#include "dnssec_v2_structs.h"
#include "dnssec_v2_validation.h"
#include "dnssec_v2_retrieval.h"
#include "dnssec_v2_crypto.h"
#include "dnssec_v2_trust_anchor.h"
#include "dnssec_v2_log.h"
#include "dnssec_v2_helper.h"
#include "base_n.h"

//======================================================================================================================
// MARK: - macros
//======================================================================================================================

#define NSEC3_FLAG_OPT_OUT_BIT	1
#define NSEC3_FLAG_SET			NSEC3_FLAG_OPT_OUT_BIT

//======================================================================================================================
// MARK: - validator type define
//======================================================================================================================
typedef struct dnssec_validator_node dnssec_validator_node_t;
struct dnssec_validator_node {
	union {
		struct {
			response_type_t					rr_response_type;
		} rr;
		struct {
			const dnssec_dnskey_t *		_Nullable	key;
			const dnssec_rrsig_t *		_Nullable	sig;
		} zsk;
		struct {
			const dnssec_dnskey_t *	_Nullable	key;
			const dnssec_rrsig_t *	_Nullable	sig;
			const dnssec_ds_t *		_Nullable	ds;
		} ksk;
		struct {
			const dnssec_nsec_t	*	_Nullable	nsec;
		} nsec;
		struct {
			const dnssec_nsec3_t	* _Nullable	nsec3;
		} nsec3;
	}											u;
	dnssec_validator_node_type_t				type;
	const mDNSu8 *					_Nonnull	name;
	// type: resource_records, list_t<dnssec_original_t>; type: zone_signing_key, list<dnssec_dnskey_t>; type: key_signing_key, list<dnssec_dnskey_t>;
	// type: nsec, list_t<one_nsec_with_rrsigs>; type: nsec3, list_t<one_nsec3_wtih_rrsigs>
	const list_t *					_Nullable	siblings;
	const list_t *					_Nonnull	rrssigs_covering_it;
	mDNSBool									trusted;
};

//======================================================================================================================
// MARK: - local functions prototype
//======================================================================================================================


// MARK: NSEC validation

mDNSlocal dnssec_validation_result_t
validate_nsec_response(
	const mDNSu32									qname_hash,
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const nsecs_with_rrsig_t * const	_Nonnull	nsecs_with_rrsig,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_1,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_1,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_2,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_2);

mDNSlocal mDNSBool
nsec_proves_no_data(
	const mDNSu32									qname_hash,
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_data,
	const list_t * _Nullable *			_Nonnull	out_rrsigs);

mDNSlocal mDNSBool
nsec_proves_name_error(
	const mDNSu8 * const				_Nonnull	qname,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_wildcard,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_wildcard);

mDNSlocal mDNSBool
nsec_proves_wildcard_answer(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const list_t * const				_Nonnull	wildcard_answer,
	const list_t * const				_Nonnull	wildcard_rrsig,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match);

mDNSlocal mDNSBool
nsec_proves_wildcard_no_data(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_matching_stype,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_matching_stype);

// MARK: NSEC3 validation

mDNSlocal mDNSBool
is_nsec3_iteration_valid(const dnssec_context_t * const context);

mDNSlocal mDNSu16
get_maximum_nsec3_iteration_for_dnskey_length(mDNSu16 key_length);

mDNSlocal dnssec_validation_result_t
get_initial_children_to_validate(
	dnssec_context_t * const			_Nonnull	context,
	dnssec_validator_node_t * const		_Nonnull	child,
	mDNSu8 * const						_Nonnull	out_child_size);

mDNSlocal dnssec_validation_result_t
validate_nsec3_response(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qtype,
	const nsec3s_with_rrsig_t * const	_Nonnull	nsec3s_with_rrsig,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_1,
	const list_t * _Nullable *			_Nonnull	out_rrsig_1,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_2,
	const list_t * _Nullable *			_Nonnull	out_rrsig_2,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_3,
	const list_t * _Nullable *			_Nonnull	out_rrsig_3);

mDNSlocal dnssec_validation_result_t
nsec3_proves_closest_encloser(
	const mDNSu8 * const			_Nonnull			name,
	const list_t * const			_Nonnull			nsec3s,
	const mDNSu8 * const			_Nonnull			zone_name,
	mDNSu8												canonical_name[MAX_DOMAIN_NAME],
	const dnssec_nsec3_t *	_Nullable * const _Nonnull	out_nsec3_closest_encloser_proof,
	const list_t *			_Nullable * const _Nonnull	out_rrsig_closest_encloser_proof,
	const dnssec_nsec3_t *	_Nullable * const _Nonnull	out_nsec3_next_closer_proof,
	const list_t *			_Nullable * const _Nonnull	out_rrsig_next_closer_proof,
	const mDNSu8 *			_Nullable * const _Nonnull	out_closest_encloser_name,
	const mDNSu8 *			_Nullable * const _Nonnull	out_next_closer_name);

mDNSlocal mDNSBool
nsec3_contains_different_hash_iteration_salt(const list_t * const nsec3s);

mDNSlocal mDNSBool
ignore_this_nsec3_record(const dnssec_nsec3_t * const _Nonnull dnssec_nsec3);

// MARK: NSEC/NSEC3 helper function

mDNSlocal mDNSBool
bit_map_contain_dns_type(const mDNSu8 * const _Nonnull bit_maps, const mDNSu16 bit_maps_length, const mDNSu16 type);

// MARK: validator initializer

mDNSlocal void
initialize_validator_node_with_rr(
	dnssec_validator_node_t * const _Nonnull	node,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,
	const list_t * const			_Nonnull	rrsigs_covering_it, // list_t<dnssec_rrsig_t>
	response_type_t							response_type);		// list_t<dnssec_rrsig_t>

mDNSlocal void
initialize_validator_node_with_nsec(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_nsec_t	*			_Nullable	nsec,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	rrsig_covering_it );	// list_t<dnssec_rrsig_t>

mDNSlocal void
initialize_validator_node_with_nsec3(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_nsec3_t	*		_Nullable	nsec3,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	rrsig_covering_it);		// list_t<dnssec_rrsig_t>

mDNSlocal void
initialize_validator_node_with_zsk(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_dnskey_t * const	_Nonnull	key,
	const dnssec_rrsig_t * const	_Nonnull	sig,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,			// list<dnssec_dnskey_t>
	const list_t * const			_Nonnull	rrsig_covering_it,	// list_t<dnssec_rrsig_t>
	mDNSBool									trusted);

mDNSlocal void
initialize_validator_node_with_ksk(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_dnskey_t * const	_Nonnull	key,
	const dnssec_rrsig_t * const	_Nonnull	sig,
	const dnssec_ds_t * const		_Nullable	ds,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,				// list<dnssec_ds_t>
	const list_t * const			_Nonnull	rrsig_covering_it,		// list_t<dnssec_rrsig_t>
	mDNSBool									trusted);

mDNSlocal void
uninitialize_validator_node(dnssec_validator_node_t * const _Nonnull node);

// MARK: validation function

mDNSlocal dnssec_validation_result_t
build_trust_from_ksk_to_zsk(
	const mDNSu32								request_id,
	const dnssec_zone_t *	const	_Nonnull	zone,
	const list_t *			const	_Nonnull	dnskeys,
	const list_t *			const	_Nonnull	dses,
	const list_t * const			_Nonnull	rrsigs_covering_dnskey,
	dnssec_validator_node_t *		_Nonnull	children,
	const mDNSu8								child_size,
	dnssec_validator_node_t *		_Nonnull	parents,
	mDNSu8 * const					_Nonnull	out_parent_size);

mDNSlocal dnssec_validation_result_t
build_trust_from_zsk(
	const mDNSu32								request_id,
	const dnssec_zone_t *	const	_Nonnull	zone,
	const list_t *			const	_Nonnull	dnskey_list,
	const list_t *			const	_Nonnull	rrsig_list_covering_dnskey,
	dnssec_validator_node_t *		_Nonnull	children,
	const mDNSu8								child_size,
	dnssec_validator_node_t *		_Nonnull	parents,
	mDNSu8 * const					_Nonnull	out_parent_size);

mDNSlocal dnssec_validation_result_t
validate_validator_node(const dnssec_validator_node_t * const _Nonnull nodes, const mDNSu8 nodes_count);

mDNSlocal dnssec_validation_result_t
validate_validator_path_between_parents_and_children(
	const mDNSu32							request_id,
	dnssec_validator_node_t *	_Nonnull	children,
	dnssec_validator_node_t *	_Nonnull	parents,
	mDNSu8 * const				_Nonnull	out_parent_size);

mDNSlocal dnssec_validation_result_t
validate_validator_path(
	const mDNSu32									request_id,
	const dnssec_validator_node_t * const _Nonnull	child,
	const dnssec_validator_node_t * const _Nonnull	parent);

mDNSlocal dnssec_validation_result_t
check_trust_validator_node(const dnssec_validator_node_t * const _Nonnull node);

mDNSlocal void
dedup_validator_with_the_same_siblings(
	dnssec_validator_node_t *	_Nonnull	parents,
	mDNSu8 * const				_Nonnull	out_parent_size);

mDNSlocal void
print_ds_validation_progress(const dnssec_validator_node_t * const _Nonnull nodes, const mDNSu8 nodes_count);

mDNSlocal dnssec_validation_result_t
validate_zone_records_type(const dnssec_zone_t * const _Nonnull zone);

mDNSlocal dnssec_validation_result_t
validate_ds(const dnssec_ds_t * const _Nonnull ds);

mDNSlocal dnssec_validation_result_t
validate_dnskey(const dnssec_dnskey_t * const _Nonnull dnskey, mDNSBool security_entry_point);

mDNSlocal dnssec_validation_result_t
validate_rrsig(const dnssec_rrsig_t * const _Nonnull rrsig);

mDNSlocal dnssec_validation_result_t
validate_nsec(const dnssec_nsec_t * const _Nonnull nsec);

mDNSlocal dnssec_validation_result_t
validate_nsec3(const dnssec_nsec3_t * const _Nonnull nsec3);

mDNSlocal dnssec_validation_result_t
check_if_ds_ksk_matches(const dnssec_ds_t * const _Nonnull ds, const dnssec_dnskey_t * const _Nonnull ksk);

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_rr(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	originals /* list_t<dnssec_original_t> */,
	response_type_t								response_type);

mDNSlocal dnssec_validation_result_t
validate_path_from_ksk_to_zsk(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	zsks /* list_t<dnssec_dnskey_t> */);

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_ds(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	dses /* list_t<dnssec_dses_t> */);

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_nsec(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const dnssec_validator_node_t * const	_Nonnull	child);

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_nsec3(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const dnssec_validator_node_t * const	_Nonnull	child);

mDNSlocal dnssec_validation_result_t
check_rrsig_validity_with_dnssec_rr(
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const dnssec_rr_t * const		_Nonnull	rr);

mDNSlocal dnssec_validation_result_t
check_rrsig_validity_with_rrs(
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const list_t * const			_Nonnull	list_to_check,
	response_type_t							response_type_in_list,
	const mDNSu16								record_type_in_list);

// MARK: reconstruct signed data

mDNSlocal void *
reconstruct_signed_data_with_rrs(
	const list_t * const			_Nonnull	rr_set,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	const response_type_t					response_type,
	const mDNSu16								record_type,
	mDNSu32 * const					_Nonnull	out_signed_data_length);

mDNSlocal void *
reconstruct_signed_data_with_one_dnssec_rr(
	const dnssec_rr_t * const		_Nonnull	dnssec_rr,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	mDNSu32 * const					_Nonnull	out_signed_data_length);

mDNSlocal void *
reconstruct_signed_data_internal(
	const dnssec_rr_t * const				rr_array[],
	const mDNSu8							rr_count,
	const dnssec_rrsig_t * const _Nonnull	dnssec_rrsig,
	mDNSu32 * const _Nonnull				out_signed_data_length);

mDNSlocal mStatus
calculate_signed_data_length(
	const dnssec_rr_t * const					rr_array[_Nonnull],
	const mDNSu8								rr_count,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	mDNSu32 * const					_Nonnull	out_length);

mDNSlocal mDNSs16
calculate_name_length_in_signed_data(const mDNSu8 * const _Nonnull name, const mDNSu8 rrsig_labels);

mDNSlocal mDNSu16
calculate_rdata_length_in_signed_data(const dnssec_rr_t * const _Nonnull dnssec_rr);

mDNSlocal const mDNSu8 *
get_wildcard_name(const mDNSu8 * const _Nonnull name, mDNSu8 * const _Nonnull buffer, const mDNSu16 buffer_length);

mDNSlocal mDNSu32
copy_rr_for_signed_data(
	mDNSu8 *						_Nonnull	dst,
	const dnssec_rr_t * const		_Nonnull	rr,
	const dnssec_rrsig_t * const	_Nonnull	rrsig);

mDNSlocal mDNSu8
copy_name_in_rr_for_signed_data(
	mDNSu8 * const					_Nonnull	dst,
	const mDNSu8 * const			_Nonnull	name,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig);

mDNSlocal mDNSu16
copy_rdata_in_rr(mDNSu8 * const _Nonnull dst, const mDNSu8 * const rdata, const mDNSu16 rdata_length, const mDNSu8 rr_type);

// MARK: sort function

mDNSlocal void
sort_records_with_algorithm(dnssec_context_t * const _Nonnull context);

mDNSlocal mDNSs8
dnssec_ds_t_comparator(const list_node_t * _Nonnull const left, const list_node_t * _Nonnull const right);

mDNSlocal mDNSs8
dnssec_rrsig_t_comparator(const list_node_t * _Nonnull const left, const list_node_t * _Nonnull const right);

mDNSlocal void
sort_rr_array_canonically(const dnssec_rr_t * rr_array[_Nonnull], const mDNSu8 rr_count);

mDNSlocal mDNSs8
dnssec_rr_t_comparator(const dnssec_rr_t * const _Nonnull left, const dnssec_rr_t * const _Nonnull right);

mDNSlocal mDNSBool
rr_array_dedup(const dnssec_rr_t * rr_array[_Nonnull], const mDNSu8 rr_count);


//======================================================================================================================
// MARK: - function definations
//======================================================================================================================


// MARK: validate_dnssec

mDNSexport dnssec_validation_result_t
validate_dnssec(dnssec_context_t * const _Nonnull context) {
	dnssec_validator_node_t			child_node[4] = {0};	// 4 is big enough to hold: nsec3_1, nsec3_2, nsec3_3, wildcard
	dnssec_validator_node_t			parent_node[4] = {0};	// the same reason as the above
	dnssec_validator_node_t *		child = child_node;
	dnssec_validator_node_t *		parent = parent_node;
	mDNSu8							child_size = 0;
	mDNSu8							parent_size = 0;
	const mDNSu32					request_id = context->original.original_parameters.request_id;

	dnssec_validator_node_t *		temp_validator		= mDNSNULL;
	mDNSu8							temp_size			= 0;
	dnssec_validation_result_t	validation_result	= dnssec_validation_valid;
	mDNSBool						nsec3_iteration_valid;

	nsec3_iteration_valid = is_nsec3_iteration_valid(context);
	require_action_quiet(nsec3_iteration_valid, exit, validation_result = dnssec_validation_nsec3_invalid_hash_iteration);

	// sort records with most secure algorithm comes first
	sort_records_with_algorithm(context);

	// get the original records out
	validation_result = get_initial_children_to_validate(context, child, &child_size);
	require_quiet(validation_result == dnssec_validation_valid && child_size != 0, exit);

	// check if the original RRSET is valid
	validation_result = validate_validator_node(child, child_size);
	require_quiet(validation_result == dnssec_validation_valid, exit);

	// check if the original RRSET is trusted by our trusted anchor, it is only possbile when the user queryies for
	// DNSKEY record since trust anchor is used to trust DNSKEY
	validation_result = check_trust_validator_node(child);
	if (validation_result == dnssec_validation_trusted) {
		goto exit;
	}

	// Check the validation through the entire chain of trust
	for (list_node_t *zone_node = list_get_first(&context->zone_chain);
		!list_has_ended(&context->zone_chain, zone_node);
		zone_node = list_next(zone_node)) {

		// check for every zone
		dnssec_zone_t * zone			= (dnssec_zone_t *)zone_node->data;
		list_t *		dnskeys			= &zone->dnskeys_with_rrsig.dnskey_records;
		list_t *		dnskey_rrsigs	= &zone->dnskeys_with_rrsig.rrsig_records;
		list_t *		dses			= &zone->dses_with_rrsig.u.original.ds_records;
		list_t *		ds_rrsigs		= &zone->dses_with_rrsig.u.original.rrsig_records;

		// It is possible that some records in the critical path of trust chain is missing(NSEC/NSEC3) or redirected(CNAME)
		validation_result = validate_zone_records_type(zone);
		require_quiet(validation_result == dnssec_validation_valid, exit);

		//	Validate the previous records(DS or RR) with Zone Signing Key(ZSK)
		validation_result = build_trust_from_zsk(request_id, zone, dnskeys, dnskey_rrsigs, child, child_size, parent, &parent_size);

		if (validation_result != dnssec_validation_valid) {
			goto exit;
		}

		if (parent_size == 0) {
			validation_result = dnssec_validation_trusted;
			goto exit;
		}

		// validate Zone Signing Key(ZSK) with Key Signing Key(KSK)
		temp_validator	= parent;
		parent			= child;
		child			= temp_validator;
		temp_size		= parent_size;
		parent_size		= child_size;
		child_size		= temp_size;
		// TODO: test got NSEC/NSEC3 in the middle

		validation_result = build_trust_from_ksk_to_zsk(request_id, zone, dnskeys, dses, ds_rrsigs, child, child_size, parent, &parent_size);
		if (validation_result != dnssec_validation_valid) {
			goto exit;
		}

		// print_ds_validation_progress(parent, parent_size);

		if (parent_size == 0) {
			validation_result = dnssec_validation_trusted;
			goto exit;
		}

		// repeat the validation process until reaching trust anchor
		temp_validator	= parent;
		parent			= child;
		child			= temp_validator;
		temp_size		= parent_size;
		parent_size		= child_size;
		child_size		= temp_size;
	}

exit:
	return validation_result;
}

mDNSlocal dnssec_validation_result_t
validate_nsec_response(
	const mDNSu32									qname_hash,
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const nsecs_with_rrsig_t * const	_Nonnull	nsecs_with_rrsig,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_1,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_1,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_2,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_2) {

	const list_t * const nsecs = &nsecs_with_rrsig->nsec_and_rrsigs_same_name;

	// dnssec_validation_nsec_no_data
	if (nsec_proves_no_data(qname_hash, qname, qclass, qtype, nsecs, out_nsec_1, out_rrsigs_1)) {
		return dnssec_validation_nsec_no_data;
	}

	// dnssec_validation_nsec_name_error
	if (nsec_proves_name_error(qname, nsecs, out_nsec_1, out_rrsigs_1, out_nsec_2, out_rrsigs_2)) {
		return dnssec_validation_nsec_name_error;
	}

	// dnssec_validation_nsec_wildcard_answer
	if (nsec_proves_wildcard_answer(qname, qtype, nsecs, &nsecs_with_rrsig->wildcard_answers, &nsecs_with_rrsig->wildcard_rrsigs, out_nsec_1, out_rrsigs_2)) {
		return dnssec_validation_nsec_wildcard_answer;
	}

	// dnssec_validation_nsec_wildcard_no_data
	if (nsec_proves_wildcard_no_data(qname, qclass, qtype, nsecs, out_nsec_1, out_rrsigs_1, out_nsec_2, out_rrsigs_2)) {
		return dnssec_validation_nsec_wildcard_no_data;
	}

	return dnssec_validation_nsec_invalid_nsec_result;
}

// MARK: validate_dnssec
// According to https://tools.ietf.org/html/rfc5155#section-10.3 , the iteration field of NSEC3 should have an upper bound
// to prevent denial-of-service attacks
mDNSlocal mDNSBool
is_nsec3_iteration_valid(const dnssec_context_t * const context) {
	mDNSBool valid = mDNStrue;
	// check original response
	const originals_with_rrsig_t * const originals_with_rrsig = &context->original.original_result_with_rrsig;

	if (originals_with_rrsig->type == nsec3_response) {
		const nsec3s_with_rrsig_t * const	nsec3s_with_rrsig			= &originals_with_rrsig->u.nsec3s_with_rrsig;
		const list_t * const				nsec3_and_rrsigs_same_name	= &nsec3s_with_rrsig->nsec3_and_rrsigs_same_name; // list_t<one_nsec3_with_rrsigs_t>
		const dnssec_zone_t *				zone_with_dnskey;
		const dnskeys_with_rrsig_t *		dnskeys_with_rrsig;
		const list_t *						dnskeys;

		require_action_quiet(!list_empty(nsec3_and_rrsigs_same_name), exit, valid = mDNSfalse);

		require_quiet(!list_empty(&context->zone_chain), exit);
		zone_with_dnskey	= (dnssec_zone_t *)list_get_first(&context->zone_chain)->data;
		dnskeys_with_rrsig	= (dnskeys_with_rrsig_t *)&zone_with_dnskey->dnskeys_with_rrsig;

		dnskeys = &dnskeys_with_rrsig->dnskey_records;
		require_action_quiet(!list_empty(dnskeys), exit, valid = mDNSfalse);

		for (const list_node_t *one_nsec3_node = list_get_first(nsec3_and_rrsigs_same_name);
				!list_has_ended(nsec3_and_rrsigs_same_name, one_nsec3_node);
				one_nsec3_node = list_next(one_nsec3_node)) {

			const one_nsec3_with_rrsigs_t * const	one_nsec3		= (one_nsec3_with_rrsigs_t *)one_nsec3_node->data;
			const list_t * const					rrsigs			= &one_nsec3->rrsig_records; // list_t<dnssec_rrsig_t>
			const mDNSu16							nsec3_iteration = one_nsec3->nsec3_record.iterations;

			for (const list_node_t * rrsig_node = list_get_first(rrsigs);
					!list_has_ended(rrsigs, rrsig_node);
					rrsig_node = list_next(rrsig_node)) {

				const dnssec_rrsig_t * const	dnssec_rrsig		= (dnssec_rrsig_t *)rrsig_node->data;
				const mDNSu16					key_tag_from_rrsig	= dnssec_rrsig->key_tag;

				for (const list_node_t * dnskey_node = list_get_first(dnskeys);
						!list_has_ended(dnskeys, dnskey_node);
						dnskey_node = list_next(dnskey_node)) {

					const dnssec_dnskey_t * const	dnssec_dnskey		= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16					key_tag_from_dnskey = dnssec_dnskey->key_tag;
					mDNSu16							max_iteration;

					if (key_tag_from_rrsig != key_tag_from_dnskey) {
						continue;
					}

					max_iteration = get_maximum_nsec3_iteration_for_dnskey_length(dnssec_dnskey->public_key_length);
					require_action_quiet(nsec3_iteration <= max_iteration, exit, valid = mDNSfalse);
				}
			}
		}
	}

exit:
	return valid;
}

mDNSlocal mDNSu16
get_maximum_nsec3_iteration_for_dnskey_length(mDNSu16 key_length) {
	mDNSu16 max;
	mDNSs32 rounded_key_length_in_bits = key_length * 8;
	static const mDNSs32 fixed_key_size[] = {
		1024, 2048, 4096
	};
	static const mDNSs32 max_iteration_for_fixed_key_size[] = {
		150, 500, 2500
	};
	// use "sizeof(fixed_key_size) == sizeof(max_iteration_for_fixed_key_size) ? sizeof(fixed_key_size) / sizeof(mDNSu32) : -1" to check if two array have matched elements.
	mDNSu32 distance_to_fixed_key_size[sizeof(fixed_key_size) == sizeof(max_iteration_for_fixed_key_size) ? sizeof(fixed_key_size) / sizeof(mDNSu32) : -1];

	// get the closest key size from 102, 2048, 4096
	for (size_t i = 0; i < sizeof(fixed_key_size) / sizeof(mDNSu32); i++) {
		distance_to_fixed_key_size[i] = abs(fixed_key_size[i] - rounded_key_length_in_bits);
	}

	mDNSu32 min_distance		= UINT_MAX;
	size_t	min_distance_index	= -1;
	for (size_t i = 0; i < sizeof(fixed_key_size) / sizeof(mDNSu32); i++) {
		if (min_distance < distance_to_fixed_key_size[i]) {
			continue;
		}
		min_distance		= distance_to_fixed_key_size[i];
		min_distance_index	= i;
	}

	switch (fixed_key_size[min_distance_index]) {
		case 1024:
			max = 150;
			break;
		case 2048:
			max = 500;
			break;
		case 4096:
			max = 2500;
			break;
		default:
			max = 0;
			break;
	}

	return max;
}

mDNSlocal dnssec_validation_result_t
get_initial_children_to_validate(
	dnssec_context_t * const			_Nonnull			context,
	dnssec_validator_node_t * const	_Nonnull			child,
	mDNSu8 * const						_Nonnull			out_child_size) {

	const list_t *					original_siblings;
	mDNSu8							child_size			= 0;
	dnssec_validation_result_t		validation_result	= dnssec_validation_valid;
	const response_type_t			type				= context->original.original_result_with_rrsig.type;
	const mDNSu8 *					qname				= context->original.original_parameters.question_name.c;
	const mDNSu32					qname_hash			= DomainNameHashValue((domainname *)qname);
	const mDNSu16					qclass				= context->original.original_parameters.question_class;
	const mDNSu16					qtype				= context->original.original_parameters.question_type;
	const trust_anchors_t * const	orig_trust_anchor	= context->original.original_trust_anchor;
	mDNSu32							request_id			= GET_REQUEST_ID(context);
	mDNSu32							question_id			= GET_QUESTION_ID(context);

	switch (type) {
		case original_response: {
			// check if the trust anchor installed for the question name already trusts all the answers
			mDNSBool				trusted_original_response	= mDNStrue;
			const list_t * const	original_rr_list			= &context->original.original_result_with_rrsig.u.original.original_records;
			if (qtype == kDNSType_DNSKEY && trust_anchor_contains_dnskey(orig_trust_anchor)) {
				const list_t * const dnskey_trust_anchors	= &orig_trust_anchor->dnskey_trust_anchors;
				dnssec_dnskey_t left;

				for (list_node_t * dnssec_original_node = list_get_first(original_rr_list);
						!list_has_ended(original_rr_list, dnssec_original_node);
						dnssec_original_node = list_next(dnssec_original_node)) {

					const dnssec_original_t * const original = (dnssec_original_t *)dnssec_original_node->data;
					parse_dns_type_dnskey_t(original->dnssec_rr.rdata, original->dnssec_rr.rdata_length,
											&left.flags, &left.protocol, &left.algorithm, &left.public_key_length, &left.public_key);

					mDNSBool trust_anchor_matches = mDNSfalse;
					for (const list_node_t * dnskey_node = list_get_first(dnskey_trust_anchors);
							!list_has_ended(dnskey_trust_anchors, dnskey_node);
							dnskey_node = list_next(dnskey_node)) {
						const dnssec_dnskey_t * const right_ptr = (dnssec_dnskey_t *)dnskey_node->data;
						if (equals_dnssec_dnskey_t(&left, right_ptr)) {
							trust_anchor_matches = mDNStrue;
							break;
						}
					}

					if (!trust_anchor_matches) {
						trusted_original_response = mDNSfalse;
						break;
					}
				}
			} else if (qtype == kDNSType_DS && trust_anchor_contains_ds(orig_trust_anchor)) {
				const list_t * const ds_trust_anchors	= &orig_trust_anchor->ds_trust_anchors;
				dnssec_ds_t left;
				mDNSBool is_valid = mDNSfalse;

				for (list_node_t * dnssec_original_node = list_get_first(original_rr_list);
						!list_has_ended(original_rr_list, dnssec_original_node);
						dnssec_original_node = list_next(dnssec_original_node)) {

					const dnssec_original_t * const original = (dnssec_original_t *)dnssec_original_node->data;
					is_valid = parse_dns_type_ds_t(original->dnssec_rr.rdata, original->dnssec_rr.rdata_length,
						&left.key_tag, &left.algorithm, &left.digest_type, &left.digest_length, &left.digest);
					verify_action(is_valid,
						log_debug("[R%u->Q%u] The returned DS records are malformated", request_id, question_id);
						continue
					);

					mDNSBool trust_anchor_matches = mDNSfalse;
					for (const list_node_t * ds_node = list_get_first(ds_trust_anchors);
							!list_has_ended(ds_trust_anchors, ds_node);
							ds_node = list_next(ds_node)) {
						const dnssec_ds_t * const right_ptr = (dnssec_ds_t *)ds_node->data;
						if (equals_dnssec_ds_t(&left, right_ptr)) {
							trust_anchor_matches = mDNStrue;
							break;
						}
					}

					if (!trust_anchor_matches) {
						trusted_original_response = mDNSfalse;
						break;
					}
				}
			} else {
				trusted_original_response = mDNSfalse;
			}

			if (trusted_original_response) {
				validation_result = dnssec_validation_trusted;
				goto exit;
			}
		} // fall into case cname_response
		case cname_response: {
			const list_t *					rrsigs; // list_t<dnssec_rrsig_t>
			if (type == original_response) {
				original_siblings	= &context->original.original_result_with_rrsig.u.original.original_records;
				rrsigs				= &context->original.original_result_with_rrsig.u.original.rrsig_records;
			} else if (type == cname_response) {
				original_siblings	= &context->original.original_result_with_rrsig.u.cname_with_rrsig.cname_records;
				rrsigs				= &context->original.original_result_with_rrsig.u.cname_with_rrsig.rrsig_records;
			} else {
				validation_result = dnssec_validation_invalid_internal_state;
				goto exit;
			}
			initialize_validator_node_with_rr(&child[child_size], qname, original_siblings, rrsigs, type);
			child_size++;
			break;
		}
		case nsec_response: {
			// check the meaning of NSEC response: No Name, No Data, Wildcard Answer, Wildcard No Data
			const dnssec_nsec_t *	nsec_to_verify_1	= mDNSNULL;
			const list_t *			rrsigs_to_verify_1	= mDNSNULL;
			const dnssec_nsec_t *	nsec_to_verify_2	= mDNSNULL;
			const list_t *			rrsigs_to_verify_2	= mDNSNULL;
			nsecs_with_rrsig_t *	nsecs_with_rrsig	= &context->original.original_result_with_rrsig.u.nsecs_with_rrsig;

			nsecs_with_rrsig->nsec_result = validate_nsec_response(qname_hash, qname, qclass, qtype, nsecs_with_rrsig,
																	&nsec_to_verify_1, &rrsigs_to_verify_1, &nsec_to_verify_2, &rrsigs_to_verify_2);

			require_action_quiet(
									(nsecs_with_rrsig->nsec_result == dnssec_validation_nsec_no_data
									|| nsecs_with_rrsig->nsec_result == dnssec_validation_nsec_name_error
									|| nsecs_with_rrsig->nsec_result == dnssec_validation_nsec_wildcard_answer
									|| nsecs_with_rrsig->nsec_result == dnssec_validation_nsec_wildcard_no_data)
									&& rrsigs_to_verify_1 != mDNSNULL
									, exit, validation_result = nsecs_with_rrsig->nsec_result); // When the assertion holds, rrsigs_to_verify_1 must be nonnull.

			initialize_validator_node_with_nsec(&child[child_size], nsec_to_verify_1, qname, rrsigs_to_verify_1);
			child_size++;

			if (nsec_to_verify_2 != mDNSNULL) {
				initialize_validator_node_with_nsec(&child[child_size], nsec_to_verify_2, qname, rrsigs_to_verify_2);
				child_size++;
			}

			if (!list_empty(&nsecs_with_rrsig->wildcard_answers)) {
				// and nsecs_with_rrsig->wildcard_rrsigs is not empty either
				initialize_validator_node_with_rr(&child[child_size], qname, &nsecs_with_rrsig->wildcard_answers,
													&nsecs_with_rrsig->wildcard_rrsigs, original_response);
				child_size++;
			}
			break;
		}
		case nsec3_response: {
			const dnssec_nsec3_t *	nsec3_to_verify_1	= mDNSNULL;
			const list_t *			rrsigs_to_verify_1	= mDNSNULL;
			const dnssec_nsec3_t *	nsec3_to_verify_2	= mDNSNULL;
			const list_t *			rrsigs_to_verify_2	= mDNSNULL;
			const dnssec_nsec3_t *	nsec3_to_verify_3	= mDNSNULL;
			const list_t *			rrsigs_to_verify_3	= mDNSNULL;
			nsec3s_with_rrsig_t *	nsec3s_with_rrsig	= &context->original.original_result_with_rrsig.u.nsec3s_with_rrsig;

			nsec3s_with_rrsig->nsec3_result = validate_nsec3_response(qname, qtype, nsec3s_with_rrsig,
																		&nsec3_to_verify_1, &rrsigs_to_verify_1, &nsec3_to_verify_2, &rrsigs_to_verify_2, &nsec3_to_verify_3, &rrsigs_to_verify_3);

			require_action_quiet(
									nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_no_data_response
									|| nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_no_data_response
									|| nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_no_data_response_opt_out
									|| nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_wildcard_no_data
									|| nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_wildcard_answer_response
									|| nsec3s_with_rrsig->nsec3_result == dnssec_validation_nsec3_name_error
									, exit, validation_result = nsec3s_with_rrsig->nsec3_result);

			initialize_validator_node_with_nsec3(&child[child_size], nsec3_to_verify_1, qname,	rrsigs_to_verify_1);
			child_size++;

			if (nsec3_to_verify_2 != mDNSNULL) {
				initialize_validator_node_with_nsec3(&child[child_size], nsec3_to_verify_2, qname, rrsigs_to_verify_2);
				child_size++;
			}

			if (nsec3_to_verify_3 != mDNSNULL) {
				initialize_validator_node_with_nsec3(&child[child_size], nsec3_to_verify_3, qname, rrsigs_to_verify_3);
				child_size++;
			}

			if (!list_empty(&nsec3s_with_rrsig->wildcard_answers)) {
				// and nsecs_with_rrsig->wildcard_rrsigs is not empty either
				initialize_validator_node_with_rr(&child[child_size], qname, &nsec3s_with_rrsig->wildcard_answers,
													&nsec3s_with_rrsig->wildcard_rrsigs, rr_validator);
				child_size++;
			}
			break;
		}
		default:
			log_error("DNSSEC validation starts with unknown orginal resource record;");
			validation_result = dnssec_validation_invalid_internal_state;
			goto exit;
	}

exit:
	*out_child_size = child_size;
	return validation_result;
}

mDNSlocal dnssec_validation_result_t
validate_nsec3_response(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qtype,
	const nsec3s_with_rrsig_t * const	_Nonnull	nsec3s_with_rrsig,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_1,
	const list_t * _Nullable *			_Nonnull	out_rrsig_1,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_2,
	const list_t * _Nullable *			_Nonnull	out_rrsig_2,
	const dnssec_nsec3_t * _Nullable *	_Nonnull	out_nsec3_3,
	const list_t * _Nullable *			_Nonnull	out_rrsig_3) {

	dnssec_validation_result_t				validation_result	= dnssec_validation_validating;
	dnssec_validation_result_t				error;
	const list_t * const					nsec3s				= &nsec3s_with_rrsig->nsec3_and_rrsigs_same_name;
	const one_nsec3_with_rrsigs_t * const	first_one_nsec3		= (one_nsec3_with_rrsigs_t *)(list_get_first(nsec3s)->data);
	const dnssec_nsec3_t * const			first_dnssec_nsec3	= &first_one_nsec3->nsec3_record;
	const mDNSu8							hash_algorithm		= first_dnssec_nsec3->hash_algorithm;
	const mDNSu8 * const					salt				= first_dnssec_nsec3->salt;
	const mDNSu8							salt_length			= first_dnssec_nsec3->salt_length;
	const mDNSu16							iterations			= first_dnssec_nsec3->iterations;
	mDNSu8 *								qname_hash_b32		= mDNSNULL;
	mDNSu16									qname_length		= DOMAIN_NAME_LENGTH(qname);
	mDNSu8									canonical_name[MAX_DOMAIN_NAME];

	require_action(!list_empty(nsec3s), exit, validation_result = dnssec_validation_bogus;
		log_default("nsec3 list is empty"));

	require_action(!nsec3_contains_different_hash_iteration_salt(nsec3s), exit, validation_result = dnssec_validation_nsec3_different_hash_iteration_salt;
		log_default("NSEC3s with different algorithm, salt or iteration in the same response"));

	// check if there is any wildcard response
	if (!list_empty(&nsec3s_with_rrsig->wildcard_answers)) {
		// Wildcard Answer Responses
		const list_t * const	wildcard_answers = &nsec3s_with_rrsig->wildcard_answers; // list_t<dnssec_rr_t>
		const mDNSu8 *			closest_encloser_name;
		mDNSu8					closest_encloser_name_length;
		const dnssec_nsec3_t *	nsec3_closest_encloser_proof;
		const list_t *			rrsig_closest_encloser_proof;
		const mDNSu8 *			next_closer;
		const dnssec_nsec3_t *	nsec3_next_closer_proof;
		const list_t *			rrsig_next_closer_proof;

		error = nsec3_proves_closest_encloser(qname, nsec3s, qname, canonical_name, &nsec3_closest_encloser_proof,
			&rrsig_closest_encloser_proof, &nsec3_next_closer_proof, &rrsig_next_closer_proof, &closest_encloser_name,
			&next_closer);
		require_action(error == dnssec_validation_nsec3_provable_closest_encloser, exit,
			validation_result = dnssec_validation_bogus;log_default("Cannot find closest encloser;"));
		closest_encloser_name_length = DOMAIN_NAME_LENGTH(closest_encloser_name);

		// make sure that this closest encloser is the immediate ancestor to the generating wildcard
		for (list_node_t *node = list_get_first(wildcard_answers); !list_has_ended(wildcard_answers, node); node = list_next(node)) {
			const dnssec_rr_t * const	dnssec_rr	= (dnssec_rr_t *)node->data;
			const mDNSu8 *				name		= dnssec_rr->name.c;

			mDNSBool matches = memcmp(name + 1 + *name, closest_encloser_name,
				MIN(DOMAIN_NAME_LENGTH(name), closest_encloser_name_length));

			require_action(matches, exit, validation_result = dnssec_validation_bogus);
		}

		*out_nsec3_1		= nsec3_closest_encloser_proof;
		*out_rrsig_1		= rrsig_closest_encloser_proof;
		*out_nsec3_2		= nsec3_next_closer_proof;
		*out_rrsig_2		= rrsig_next_closer_proof;
		validation_result	= dnssec_validation_nsec3_wildcard_answer_response;

		goto exit;
	} else {
		// check if there is a matching NSEC3 that matches qname

		mDNSu8					qname_hash[MAX_HASH_OUTPUT_SIZE];
		mDNSu32					qname_hash_length;
		mDNSu8					qname_hash_b32_length;
		const dnssec_nsec3_t *	nsec3_that_matches_qname = mDNSNULL;

		// get the base32 format of qname hash

		qname_hash_length = get_hash_length_for_nsec3_hash_type(hash_algorithm);
		mDNSBool calculated = calculate_hash_for_nsec3(qname_hash, sizeof(qname_hash), hash_algorithm, qname, qname_length, salt, salt_length, iterations);
		require_action(calculated, exit, validation_result = dnssec_validation_invalid_internal_state);
		qname_hash_b32 = (mDNSu8 *)base_n_encode(DNSSEC_BASE_32_HEX, qname_hash, qname_hash_length);
		qname_hash_b32_length = strlen((char *)qname_hash_b32);

		for (list_node_t * one_nsec3_node = list_get_first(nsec3s);
			!list_has_ended(nsec3s, one_nsec3_node);
			one_nsec3_node = list_next(one_nsec3_node)) {

			const one_nsec3_with_rrsigs_t * const	one_nsec3				= (one_nsec3_with_rrsigs_t *)one_nsec3_node->data;
			const dnssec_nsec3_t * const			dnssec_nsec3			= &one_nsec3->nsec3_record;
			const mDNSu8 * const					frist_label_owner_name	= dnssec_nsec3->dnssec_rr.name.c + 1;
			const mDNSu8							first_label_length		= *dnssec_nsec3->dnssec_rr.name.c;

			if (compare_canonical_dns_label(qname_hash_b32, qname_hash_b32_length, frist_label_owner_name, first_label_length) == 0) {
				*out_nsec3_1 = dnssec_nsec3;
				*out_rrsig_1 = &one_nsec3->rrsig_records;
				nsec3_that_matches_qname = dnssec_nsec3;
				break;
			}
		}

		if (nsec3_that_matches_qname != mDNSNULL) {
			// No Data Responses, QTYPE is not DS
			// No Data Responses, QTYPE is DS

			// An NSEC3 RR that matches QNAME is present.
			mDNSBool contains_type;
			contains_type = bit_map_contain_dns_type(nsec3_that_matches_qname->type_bit_maps, nsec3_that_matches_qname->type_bit_maps_length, qtype);
			require_action(!contains_type, exit, validation_result = dnssec_validation_bogus;
				log_default("NSEC3 contains DNS type that should not exist;" PUB_S, DNS_TYPE_STR(qtype)));

			contains_type = bit_map_contain_dns_type(nsec3_that_matches_qname->type_bit_maps, nsec3_that_matches_qname->type_bit_maps_length, kDNSType_CNAME);
			require_action(!contains_type, exit, validation_result = dnssec_validation_bogus;
				log_default("NSEC3 contains DNS type that should not exist;" PUB_S, DNS_TYPE_STR(kDNSType_CNAME)));

			validation_result = dnssec_validation_nsec3_no_data_response;
			goto exit;
		} else {
			// Wildcard No Data Responses
			// Name Error Responses
			// No Data Responses, QTYPE is DS
			const mDNSu8 *			closest_encloser_name;
			mDNSu8					closest_encloser_name_length;
			const dnssec_nsec3_t *	nsec3_closest_encloser_proof;
			const list_t *			rrsig_closest_encloser_proof;
			const mDNSu8 *			next_closer;
			const dnssec_nsec3_t *	nsec3_next_closer_proof;
			const list_t *			rrsig_next_closer_proof;
			mDNSu8					wildcard_closest_encloser[MAX_DOMAIN_NAME];
			mDNSu8					wildcard_length;
			mDNSu8 *				wildcard_hash_b32 = mDNSNULL;
			mDNSu32					wildcard_hash_b32_length;

			// find closest encloser
			error = nsec3_proves_closest_encloser(qname, nsec3s, qname, canonical_name, &nsec3_closest_encloser_proof,
				&rrsig_closest_encloser_proof, &nsec3_next_closer_proof, &rrsig_next_closer_proof,
				&closest_encloser_name, &next_closer);
			require_action(error == dnssec_validation_nsec3_provable_closest_encloser, exit,
				validation_result = dnssec_validation_bogus;log_default("Cannot find closest encloser;"));
			closest_encloser_name_length = DOMAIN_NAME_LENGTH(closest_encloser_name);

			*out_nsec3_1 = nsec3_closest_encloser_proof;
			*out_rrsig_1 = rrsig_closest_encloser_proof;
			*out_nsec3_2 = nsec3_next_closer_proof;
			*out_rrsig_2 = rrsig_next_closer_proof;

			// check if it is "No Data Responses, QTYPE is DS" case, the "Opt-out" case
			if (qtype == kDNSType_DS) {
				if ((nsec3_closest_encloser_proof->flags & NSEC3_FLAG_OPT_OUT_BIT)) {
					validation_result = dnssec_validation_nsec3_no_data_response_opt_out;
				} else {
					validation_result = dnssec_validation_bogus;
				}
				goto exit;
			}

			require_action(closest_encloser_name_length + 2 <= sizeof(wildcard_closest_encloser), exit,
				validation_result = dnssec_validation_bogus; log_error("wildcard closest encloser length is invalid"));

			// check if wildcard exists
			// get wildcard name
			wildcard_closest_encloser[0] = 1;
			wildcard_closest_encloser[1] = '*';
			memcpy(wildcard_closest_encloser + 2, closest_encloser_name, closest_encloser_name_length);
			wildcard_length = DOMAIN_NAME_LENGTH(wildcard_closest_encloser);

			wildcard_hash_b32 = calculate_b32_hash_for_nsec3(wildcard_closest_encloser, wildcard_length,
				first_dnssec_nsec3->hash_algorithm, first_dnssec_nsec3->salt, first_dnssec_nsec3->salt_length, first_dnssec_nsec3->iterations);
			require_action(wildcard_hash_b32 != mDNSNULL, exit,
				validation_result = dnssec_validation_no_memory ;log_error("b32_encode failed"));

			wildcard_hash_b32_length = strlen((char *)wildcard_hash_b32);

			for (list_node_t *one_nsec3_node = list_get_first(nsec3s);
					!list_has_ended(nsec3s, one_nsec3_node);
					one_nsec3_node = list_next(one_nsec3_node)) {

				const one_nsec3_with_rrsigs_t * const	one_nsec3		= (one_nsec3_with_rrsigs_t *)one_nsec3_node->data;
				const dnssec_nsec3_t * const			dnssec_nsec3	= &one_nsec3->nsec3_record;
				const mDNSu8 *							current			= (mDNSu8 *)(dnssec_nsec3->dnssec_rr.name.c + 1);
				const mDNSu8							current_length	= *(dnssec_nsec3->dnssec_rr.name.c);
				const mDNSu8 *							next			= (mDNSu8 *)(dnssec_nsec3->next_hashed_owner_name_b32);
				const mDNSu8							next_length		= dnssec_nsec3->next_hashed_owner_name_b32_length;
				mDNSBool								last_nsec		= compare_canonical_dns_label(current, current_length, next, next_length) > 0;

				if (compare_canonical_dns_label(current, current_length, wildcard_hash_b32, wildcard_hash_b32_length) == 0) {
					// Wildcard No Data Responses
					*out_nsec3_2 = dnssec_nsec3;

					// check type map
					mDNSBool contains_type;
					contains_type = bit_map_contain_dns_type(dnssec_nsec3->type_bit_maps, dnssec_nsec3->type_bit_maps_length, qtype);
					require_action(!contains_type, for_loop_exit,
						validation_result = dnssec_validation_bogus;
						log_default("NSEC3 contains DNS type that should not exist;" PUB_S, DNS_TYPE_STR(qtype)));

					contains_type = bit_map_contain_dns_type(dnssec_nsec3->type_bit_maps, dnssec_nsec3->type_bit_maps_length, kDNSType_CNAME);
					require_action(!contains_type, for_loop_exit,
						validation_result = dnssec_validation_bogus;
						log_default("NSEC3 contains DNS type that should not exist;" PUB_S, DNS_TYPE_STR(kDNSType_CNAME)));

					*out_nsec3_3 = dnssec_nsec3;
					*out_rrsig_3 = &one_nsec3->rrsig_records;
					validation_result = dnssec_validation_nsec3_wildcard_no_data;

					goto for_loop_exit;
				}

				if (compare_canonical_dns_label(current, current_length, wildcard_hash_b32, wildcard_hash_b32_length) < 0
					&& (last_nsec || compare_canonical_dns_label(wildcard_hash_b32, wildcard_hash_b32_length, next, next_length) < 0)) {
					// Name Error Responses
					*out_nsec3_3 = dnssec_nsec3;
					*out_rrsig_3 = &one_nsec3->rrsig_records;
					validation_result = dnssec_validation_nsec3_name_error;

					goto for_loop_exit;
				}
			}
			validation_result = dnssec_validation_bogus;
		for_loop_exit:
			if (wildcard_hash_b32 != mDNSNULL) {
				free(wildcard_hash_b32);
				wildcard_hash_b32 = mDNSNULL;
			}
		}
	}

exit:
	if (qname_hash_b32 != mDNSNULL) {
		free(qname_hash_b32);
	}
	return validation_result;
}

mDNSexport mDNSu16
calculate_key_tag(const mDNSu8 key[_Nonnull], const mDNSu16 key_len, const mDNSu8 algorithm)
{
	if (algorithm == 1) {
		// The key tag is defined to be the most significant 16 bits of the least significant 24 bits in the public key modulus.
		// However, RSA/MD5 whose algorithm number is 1 is not supported by mDNSResponder, so we will not implement it.
		return 0;
	}

	mDNSu32 key_tag = 0;

	for (mDNSu32 i = 0; i < key_len; i++)
	{
		if (i & 1)	key_tag += key[i];
		else			key_tag += (mDNSu32)(key[i] << 8);
	}
	key_tag += (key_tag >> 16) & 0xFFFF;
	key_tag &= 0xFFFF;

	return key_tag;
}

//======================================================================================================================
//	Local functions
//======================================================================================================================

//======================================================================================================================
//	bit_map_contain_dns_type
//======================================================================================================================

mDNSlocal mDNSBool
bit_map_contain_dns_type(const mDNSu8 * const _Nonnull bit_maps, const mDNSu16 bit_maps_length, const mDNSu16 type) {
	const mDNSu8 window_index	= type / 256;
	const mDNSu8 offset			= type % 256;
	const mDNSu8 * ptr			= bit_maps;
	const mDNSu8 * ptr_limit	= ptr + bit_maps_length;

	for (;ptr < ptr_limit; ptr += 2 + *(ptr + 1)) {
		const mDNSu8	current_window_index	= *ptr;
		const mDNSu8	block_bit_map_length	= *(ptr + 1);
		const mDNSu32	bit_count				= block_bit_map_length * 8;
		const mDNSu8	mask					= 1 << (7 - (offset % 8));
		const mDNSu8 *	current_block			= ptr + 2;

		if (current_window_index != window_index) {
			continue;
		}

		if (offset >= bit_count) {
			continue;
		}

		if ((current_block[offset / 8] & mask) != 0) {
			return mDNStrue;
		}
	}

	return mDNSfalse;
}

//======================================================================================================================
//	NSEC result validation
//======================================================================================================================

//======================================================================================================================
//	nsec_proves_no_data
//======================================================================================================================

mDNSlocal mDNSBool
nsec_proves_no_data(
	const mDNSu32									qname_hash,
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_data,
	const list_t * _Nullable *			_Nonnull	out_rrsigs) {

	for (list_node_t *nsec_node = list_get_first(nsecs); !list_has_ended(nsecs, nsec_node); nsec_node = list_next(nsec_node)) {
		const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
		// have NSEC record
		const dnssec_nsec_t * const dnssec_nsec = &one_nsec->nsec_record;

		// with same SNAME
		if (qname_hash != dnssec_nsec->dnssec_rr.name_hash || !DOMAIN_NAME_EQUALS(qname, dnssec_nsec->exist_domain_name)) {
			continue;
		}

		// with same SCLASS
		if (qclass != dnssec_nsec->dnssec_rr.rr_class) {
			continue;
		}

		// does not contain the STYPE
		if (bit_map_contain_dns_type(dnssec_nsec->type_bit_maps, dnssec_nsec->type_bit_maps_length, qtype)) {
			continue;
		}

		// proves No Data;
		*out_nsec_no_data	= dnssec_nsec;
		*out_rrsigs			= &one_nsec->rrsig_records;
		return mDNStrue;
	}

	return mDNSfalse;
}

//======================================================================================================================
//	nsec_proves_name_error
//======================================================================================================================

mDNSlocal mDNSBool
nsec_proves_name_error(
	const mDNSu8 * const				_Nonnull	qname,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_wildcard,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_wildcard) {

	mDNSBool no_exact_match		= mDNSfalse;
	mDNSBool no_wildcard_match	= mDNSfalse;

	for (list_node_t *nsec_node = list_get_first(nsecs); !list_has_ended(nsecs, nsec_node); nsec_node = list_next(nsec_node)) {
		const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
		// have NSEC record
		const dnssec_nsec_t * const dnssec_nsec = &one_nsec->nsec_record;
		const mDNSu8 * const		prev = dnssec_nsec->exist_domain_name;
		const mDNSu8 * const		next = dnssec_nsec->next_domain_name;
		mDNSs8						name_compare_result;
		mDNSBool					last_nsec = compare_canonical_dns_name(next, prev) < 0;;

		// check if an NSEC RR proving that there is no exact match for <SNAME, SCLASS> exist
		while (!no_exact_match) {
			// prev < q_name
			name_compare_result = compare_canonical_dns_name(qname, prev);
			if (name_compare_result <= 0) {
				break;
			}

			// q_name < next
			name_compare_result = compare_canonical_dns_name(next, qname);
			if (!last_nsec && name_compare_result <= 0) {
				break;
			}

			*out_nsec_no_exact_match	= dnssec_nsec;
			*out_rrsigs_no_exact_match	= &one_nsec->rrsig_records;
			no_exact_match				= mDNStrue;
		}

		// check if an NSEC RR proving that the zone contains no RRsets that would match <SNAME, SCLASS>
		// via wildcard name expansion exists
		while (!no_wildcard_match) {
			mDNSu8 buffer[MAX_DOMAIN_NAME];
			const mDNSu8 * const wildcard_name = get_wildcard_name(qname, buffer, sizeof(buffer));
			if (wildcard_name == mDNSNULL) {
				break;
			}

			// prev < wildcard_name
			name_compare_result = compare_canonical_dns_name(wildcard_name, prev);
			if (name_compare_result <= 0) {
				break;
			}

			// wildcard_name < next
			name_compare_result = compare_canonical_dns_name(next, wildcard_name);
			if (!last_nsec && name_compare_result <= 0) {
				break;
			}

			*out_nsec_no_wildcard	= dnssec_nsec;
			*out_rrsigs_no_wildcard = &one_nsec->rrsig_records;
			no_wildcard_match		= mDNStrue;
		}

		if (no_exact_match && no_wildcard_match) {
			break;
		}
	}

	return no_exact_match && no_wildcard_match;
}

//======================================================================================================================
//	nsec_proves_wildcard_answer
//======================================================================================================================

mDNSlocal mDNSBool
nsec_proves_wildcard_answer(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const list_t * const				_Nonnull	wildcard_answer,
	const list_t * const				_Nonnull	wildcard_rrsig,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match) {

	mDNSBool no_exact_match					= mDNSfalse;
	mDNSBool contains_wildcard_answer		= mDNSfalse;
	mDNSBool contains_wildcard_rrsig		= mDNSfalse;

	for (list_node_t *nsec_node = list_get_first(nsecs); !list_has_ended(nsecs, nsec_node); nsec_node = list_next(nsec_node)) {
		const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
		// have NSEC record
		const dnssec_nsec_t * const dnssec_nsec = &one_nsec->nsec_record;
		const mDNSu8 * const		prev = dnssec_nsec->exist_domain_name;
		const mDNSu8 * const		next = dnssec_nsec->next_domain_name;
		mDNSs8						name_compare_result;
		mDNSBool					last_nsec = compare_canonical_dns_name(prev, next) > 0;

		// prev < q_name
		name_compare_result = compare_canonical_dns_name(qname, prev);
		if (name_compare_result <= 0) {
			continue;
		}

		// q_name < next
		name_compare_result = compare_canonical_dns_name(next, qname);
		if (!last_nsec && name_compare_result <= 0) {
			continue;
		}

		*out_nsec_no_exact_match	= dnssec_nsec;
		*out_rrsigs_no_exact_match	= &one_nsec->rrsig_records;
		no_exact_match = mDNStrue;
	}

	// contains wildcard answer
	contains_wildcard_answer = !list_empty(wildcard_answer);

	// contains wildcard RRSIG
	for (list_node_t *rrsig_node = list_get_first(wildcard_rrsig); !list_has_ended(wildcard_rrsig, rrsig_node); rrsig_node = list_next(rrsig_node)) {
		const dnssec_rrsig_t * const dnssec_rrsig = (dnssec_rrsig_t *)rrsig_node->data;
		// cover the wildcard
		if (dnssec_rrsig->type_covered != qtype) {
			continue;
		}

		// label is 1 less than the question name
		if (dnssec_rrsig->labels + 1 != get_number_of_labels(dnssec_rrsig->dnssec_rr.name.c)) {
			continue;
		}

		contains_wildcard_rrsig = mDNStrue;
	}

	return no_exact_match && contains_wildcard_answer && contains_wildcard_rrsig;
}

//======================================================================================================================
//	nsec_proves_wildcard_no_data
//======================================================================================================================

mDNSlocal mDNSBool
nsec_proves_wildcard_no_data(
	const mDNSu8 * const				_Nonnull	qname,
	const mDNSu16									qclass,
	const mDNSu16									qtype,
	const list_t * const				_Nonnull	nsecs,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_exact_match,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_exact_match,
	const dnssec_nsec_t * _Nullable *	_Nonnull	out_nsec_no_matching_stype,
	const list_t * _Nullable		*	_Nonnull	out_rrsigs_no_matching_stype){

	mDNSBool no_exact_match					= mDNSfalse;
	mDNSBool no_matching_stype				= mDNSfalse;

	for (list_node_t *nsec_node = list_get_first(nsecs); !list_has_ended(nsecs, nsec_node); nsec_node = list_next(nsec_node)) {
		const one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
		// have NSEC record
		const dnssec_nsec_t * const dnssec_nsec = &one_nsec->nsec_record;
		const mDNSu8 * const		prev = dnssec_nsec->exist_domain_name;
		const mDNSu8 * const		next = dnssec_nsec->next_domain_name;
		mDNSs8						name_compare_result;
		mDNSBool					last_nsec = compare_canonical_dns_name(prev, next) > 0;

		// check if an NSEC RR proving that there is no exact match for <SNAME, SCLASS> exist
		while (!no_exact_match) {
			// prev < q_name
			name_compare_result = compare_canonical_dns_name(qname, prev);
			if (name_compare_result <= 0) {
				break;
			}

			// q_name < next
			name_compare_result = compare_canonical_dns_name(next, qname);
			if (!last_nsec && name_compare_result <= 0) {
				break;
			}

			*out_nsec_no_exact_match	= dnssec_nsec;
			*out_rrsigs_no_exact_match	= &one_nsec->rrsig_records;
			no_exact_match				= mDNStrue;
		}

		// check if an NSEC RR proving that there are no RRsets matching STYPE at the wildcard owner name that matched
		// <SNAME, SCLASS> via wildcard expansion, exists
		while (!no_matching_stype) {
			// with same SNAME
			mDNSu8 wildcard_name[256];

			if (!DOMAIN_NAME_EQUALS(get_wildcard_name(qname, wildcard_name, sizeof(wildcard_name)), dnssec_nsec->exist_domain_name)) {
				break;
			}

			// with same SCLASS
			if (qclass != dnssec_nsec->dnssec_rr.rr_class) {
				break;
			}

			// does not contain the STYPE
			if (bit_map_contain_dns_type(dnssec_nsec->type_bit_maps, dnssec_nsec->type_bit_maps_length, qtype)) {
				break;
			}

			*out_nsec_no_matching_stype		= dnssec_nsec;
			*out_rrsigs_no_matching_stype	= &one_nsec->rrsig_records;
			no_matching_stype				= mDNStrue;
		}

		if (no_exact_match && no_matching_stype) {
			break;
		}
	}

	return no_exact_match && no_matching_stype;
}

//======================================================================================================================
//	NSEC3 result validation
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
nsec3_proves_closest_encloser(
	const mDNSu8 * const			_Nonnull				name,
	const list_t * const			_Nonnull				nsec3s,
	const mDNSu8 * const			_Nonnull				zone_name,
	mDNSu8													canonical_name[MAX_DOMAIN_NAME],
	const dnssec_nsec3_t *	_Nullable * const _Nonnull		out_nsec3_closest_encloser_proof,
	const list_t *			_Nullable * const _Nonnull		out_rrsig_closest_encloser_proof,
	const dnssec_nsec3_t *	_Nullable * const _Nonnull		out_nsec3_next_closer_proof,
	const list_t *			_Nullable * const _Nonnull		out_rrsig_next_closer_proof,
	const mDNSu8 *			_Nullable * const _Nonnull		out_closest_encloser_name,
	const mDNSu8 *			_Nullable * const _Nonnull		out_next_closer_name) {

	dnssec_validation_result_t				result				= dnssec_validation_validating;
	const one_nsec3_with_rrsigs_t * const	first_one_nsec3		= (one_nsec3_with_rrsigs_t *)list_get_first(nsec3s)->data;
	const dnssec_nsec3_t * const			first_dnssec_nsec3	= &first_one_nsec3->nsec3_record;
	const mDNSu8							hash_algorithm		= first_dnssec_nsec3->hash_algorithm;
	const mDNSu16							iterations			= first_dnssec_nsec3->iterations;
	const mDNSu8 * const					salt				= first_dnssec_nsec3->salt;
	const mDNSu8							salt_length			= first_dnssec_nsec3->salt_length;
	mDNSu8									checking_flag;
	mDNSu16									canonical_name_length;
	const mDNSu8 *							sname;
	mDNSu16									sname_length;
	mDNSBool								break_loop;

	copy_canonical_name(canonical_name, name);
	canonical_name_length = DOMAIN_NAME_LENGTH(canonical_name);

	sname			= canonical_name;
	sname_length	= canonical_name_length;
	checking_flag	= mDNSfalse;

	while (*sname != 0 && result == dnssec_validation_validating) {
		mDNSu8 * const hash_b32 = calculate_b32_hash_for_nsec3(sname, sname_length, hash_algorithm, salt, salt_length, iterations);
		require_action(hash_b32 != mDNSNULL, exit, result = dnssec_validation_no_memory);
		mDNSu8 hash_b32_length = strlen((char *)hash_b32);
		break_loop = mDNSfalse;

		for (list_node_t *one_nsec3_node = list_get_first(nsec3s);
				!list_has_ended(nsec3s, one_nsec3_node) && !break_loop;
				one_nsec3_node = list_next(one_nsec3_node)) {

			const one_nsec3_with_rrsigs_t * const	one_nsec3		= (one_nsec3_with_rrsigs_t *)one_nsec3_node->data;
			const dnssec_nsec3_t * const			dnssec_nsec3	= &one_nsec3->nsec3_record;
			const mDNSu8 *							current			= (mDNSu8 *)(dnssec_nsec3->dnssec_rr.name.c + 1);
			const mDNSu8							current_length	= *(dnssec_nsec3->dnssec_rr.name.c);
			const mDNSu8 *							next			= (mDNSu8 *)(dnssec_nsec3->next_hashed_owner_name_b32);
			const mDNSu8							next_length		= dnssec_nsec3->next_hashed_owner_name_b32_length;
			const mDNSBool							last_nsec3		= compare_canonical_dns_label(current, current_length, next, next_length) > 0;

			// ignore invalid NSEC3 record
			if (ignore_this_nsec3_record(dnssec_nsec3)) {
				continue;
			}

			// If there is an NSEC3 RR in the response that covers SNAME
			if (compare_canonical_dns_label(current, current_length, hash_b32, hash_b32_length) < 0
				&& (last_nsec3 || compare_canonical_dns_label(hash_b32, hash_b32_length, next, next_length) < 0)) { // SNAME is covered by this NSEC3 record.
				//, set the flag.
				checking_flag					= mDNStrue;
				*out_nsec3_next_closer_proof	= dnssec_nsec3;
				*out_rrsig_next_closer_proof	= &one_nsec3->rrsig_records;
				*out_next_closer_name			= sname;
				break_loop						= mDNStrue;
			} else if (compare_canonical_dns_label(current, current_length, hash_b32, hash_b32_length) == 0) {
				// If there is a matching NSEC3 RR in the response,
				// and the flag was set,
				require_action_quiet(checking_flag, exit, result = dnssec_validation_bogus);

				// and the nsec3 record comes from a proper zone,
				mDNSu8 subdomain = is_a_subdomain_of_b(sname, zone_name);
				require_action_quiet(subdomain, exit, result = dnssec_validation_nsec3_nsec3_not_from_the_zone);

				// then this NEC3 proves closest encloser
				*out_nsec3_closest_encloser_proof	= dnssec_nsec3;
				*out_rrsig_closest_encloser_proof	= &one_nsec3->rrsig_records;
				*out_closest_encloser_name			= sname;
				break_loop							= mDNStrue;
				result								= dnssec_validation_nsec3_provable_closest_encloser;
			}
		}

		free(hash_b32);
		sname_length	-= 1 + *sname;
		sname			+= 1 + *sname;
		if (!break_loop) {
			checking_flag	= mDNSfalse;
		}
	}

exit:
	return result;
}


//======================================================================================================================
//	nsec3_contains_different_hash_iteration_salt
//======================================================================================================================

mDNSlocal mDNSBool
nsec3_contains_different_hash_iteration_salt(const list_t * const nsec3s) {
	if (list_empty(nsec3s)) {
		return mDNStrue;
	}

	const one_nsec3_with_rrsigs_t * const	first_one_nsec3		= (one_nsec3_with_rrsigs_t *)(list_get_first(nsec3s)->data);
	const dnssec_nsec3_t * const			first_dnssec_nsec3	= &first_one_nsec3->nsec3_record;

	for (list_node_t *one_nsec3_node = list_get_first(nsec3s);
			!list_has_ended(nsec3s, one_nsec3_node);
			one_nsec3_node = list_next(one_nsec3_node)) {

		const one_nsec3_with_rrsigs_t * const	one_nsec3		= (one_nsec3_with_rrsigs_t *)one_nsec3_node->data;
		const dnssec_nsec3_t * const			dnssec_nsec3	= &one_nsec3->nsec3_record;

		if (dnssec_nsec3->hash_algorithm != first_dnssec_nsec3->hash_algorithm
			|| dnssec_nsec3->iterations != first_dnssec_nsec3->iterations
			|| dnssec_nsec3->salt_length != first_dnssec_nsec3->salt_length
			|| memcmp(dnssec_nsec3->salt, first_dnssec_nsec3->salt, dnssec_nsec3->salt_length) != 0) {
			return mDNStrue;
		}
	}

	return mDNSfalse;
}

//======================================================================================================================
//	ignore_this_nsec3_record
//======================================================================================================================

mDNSlocal mDNSBool
ignore_this_nsec3_record(const dnssec_nsec3_t * const _Nonnull dnssec_nsec3) {
	// ignore the NSEC3 with unknown hash type, right now we only support SHA1(1)
	if (dnssec_nsec3->hash_algorithm != 1) {
		return mDNStrue;
	}

	mDNSu8 flags	= dnssec_nsec3->flags;
	flags			= (flags & (~1));
	// ignore the NSEC3 with any flag bits set except for the least significant bit, which is used as Opt-out option
	if (flags != 0) {
		return mDNStrue;
	}

	return mDNSfalse;
}

//======================================================================================================================
//	build_trust_from_ksk_to_zsk
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
build_trust_from_ksk_to_zsk(
	const mDNSu32								request_id,
	const dnssec_zone_t *	const	_Nonnull	zone,
	const list_t *			const	_Nonnull	dnskeys,
	const list_t *			const	_Nonnull	dses,
	const list_t * const			_Nonnull	rrsigs_covering_dnskey,
	dnssec_validator_node_t *		_Nonnull	children,
	const mDNSu8								child_size,
	dnssec_validator_node_t *		_Nonnull	parents,
	mDNSu8 * const					_Nonnull	out_parent_size) {

	dnssec_validation_result_t		result	= dnssec_validation_invalid;
	dnssec_validation_result_t		error;
	const mDNSu8 * const			zone_name				= zone->domain_name.c;
	const list_t * const			dnskey_trust_anchors	= zone->trust_anchor ? &zone->trust_anchor->dnskey_trust_anchors : mDNSNULL;
	const list_t * const			ds_trust_anchors		= zone->trust_anchor ? &zone->trust_anchor->ds_trust_anchors : mDNSNULL;
	mDNSu8 parent_size = 0;

	for (mDNSu8 i = 0; i < child_size; i++) {
		dnssec_validator_node_t *		child			= &children[i];
		const list_t * const			rrsigs			= child->rrssigs_covering_it;

		for (const list_node_t * rrsig_node = list_get_first(rrsigs); !list_has_ended(rrsigs, rrsig_node); rrsig_node = list_next(rrsig_node)) {
			const dnssec_rrsig_t * const	dnssec_rrsig		= (dnssec_rrsig_t *)rrsig_node->data;
			const mDNSu16					key_tag_from_rrsig	= dnssec_rrsig->key_tag;

			verify_action(dnssec_rrsig->type_covered == kDNSType_DNSKEY, continue);

			const dnssec_dnskey_t *		dnssec_dnskey	= mDNSNULL;
			const dnssec_ds_t *			dnssec_ds		= mDNSNULL;
			dnssec_validator_node_t *	parent			= mDNSNULL;
			mDNSBool					find_trust_anchor = mDNSfalse;

			if (dnskey_trust_anchors != mDNSNULL && !list_empty(dnskey_trust_anchors)) {
				for (const list_node_t * dnskey_node = list_get_first(dnskey_trust_anchors);
						!list_has_ended(dnskey_trust_anchors, dnskey_node);
						dnskey_node = list_next(dnskey_node)) {

					dnssec_dnskey						= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16	key_tag_from_dnskey = dnssec_dnskey->key_tag;
					mDNSBool		entry_point			= (DNSKEY_FLAG_SECURITY_ENTRY_POINT & dnssec_dnskey->flags);

					if (key_tag_from_rrsig != key_tag_from_dnskey || !entry_point) {
						dnssec_dnskey = mDNSNULL;
						continue;
					}

					find_trust_anchor = mDNStrue;
					goto initialize_parent;
				}
			}

			if (!find_trust_anchor && ds_trust_anchors != mDNSNULL && !list_empty(ds_trust_anchors)) {
				for (const list_node_t * dnskey_node = list_get_first(dnskeys);
						!list_has_ended(dnskeys, dnskey_node);
						dnskey_node = list_next(dnskey_node)) {

					dnssec_dnskey						= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16 key_tag_from_dnskey	= dnssec_dnskey->key_tag;
					mDNSBool		entry_point			= (DNSKEY_FLAG_SECURITY_ENTRY_POINT & dnssec_dnskey->flags);

					if (key_tag_from_rrsig != key_tag_from_dnskey || !entry_point) {
						dnssec_dnskey = mDNSNULL;
						continue;
					}

					for (const list_node_t * ds_node = list_get_first(ds_trust_anchors);
							!list_has_ended(ds_trust_anchors, ds_node);
							ds_node = list_next(ds_node)) {

						dnssec_ds						= (dnssec_ds_t *)ds_node->data;
						const mDNSu16 key_tag_from_ds	= dnssec_ds->key_tag;

						if (key_tag_from_rrsig != key_tag_from_ds) {
							dnssec_ds = mDNSNULL;
							continue;
						}

						find_trust_anchor = mDNStrue;
						goto initialize_parent;
					}
				}
			}

			if (!find_trust_anchor) {
				for (const list_node_t * dnskey_node = list_get_first(dnskeys); !list_has_ended(dnskeys, dnskey_node); dnskey_node = list_next(dnskey_node)) {
					dnssec_dnskey						= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16 key_tag_from_dnskey	= dnssec_dnskey->key_tag;
					mDNSBool		entry_point			= (DNSKEY_FLAG_SECURITY_ENTRY_POINT & dnssec_dnskey->flags);

					if (key_tag_from_rrsig != key_tag_from_dnskey || !entry_point) {
						dnssec_dnskey = mDNSNULL;
						continue;
					}

					for (const list_node_t * ds_node = list_get_first(dses);
							!list_has_ended(dses, ds_node);
							ds_node = list_next(ds_node)) {

						dnssec_ds						= (dnssec_ds_t *)ds_node->data;
						const mDNSu16 key_tag_from_ds	= dnssec_ds->key_tag;

						if (key_tag_from_rrsig != key_tag_from_ds) {
							dnssec_ds = mDNSNULL;
							continue;
						}

						goto initialize_parent;
					}
				}
			}

			if (dnssec_dnskey == mDNSNULL && dnssec_ds == mDNSNULL) {
				continue;
			}

		initialize_parent:
			parent = &parents[parent_size];
			parent_size++;
			uninitialize_validator_node(parent);
			initialize_validator_node_with_ksk(parent, dnssec_dnskey, dnssec_rrsig, dnssec_ds, zone_name,
				dses, rrsigs_covering_dnskey, find_trust_anchor);

			break;
		}
	}

	require_action_quiet(parent_size == child_size, exit, result = dnssec_validation_no_matching_key_tag);

	error = validate_validator_node(parents, parent_size);
	require_action_quiet(error == dnssec_validation_valid, exit, result = error);

	error = validate_validator_path_between_parents_and_children(request_id, children, parents, &parent_size);
	require_action_quiet(error == dnssec_validation_valid, exit, result = error);

	dedup_validator_with_the_same_siblings(parents, &parent_size);

	*out_parent_size = parent_size;

	result = dnssec_validation_valid;

exit:
	return result;
}

//======================================================================================================================
//	build_trust_from_zsk
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
build_trust_from_zsk(
	const mDNSu32								request_id,
	const dnssec_zone_t *	const	_Nonnull	zone,
	const list_t *			const	_Nonnull	dnskeys,
	const list_t *			const	_Nonnull	rrsigs_covering_dnskeys,
	dnssec_validator_node_t *		_Nonnull	children,
	const mDNSu8								child_size,
	dnssec_validator_node_t *		_Nonnull	parents,
	mDNSu8 * const					_Nonnull	out_parent_size) {

	dnssec_validation_result_t		result					= dnssec_validation_invalid;
	dnssec_validation_result_t		error;
	const mDNSu8 * const			zone_name				= zone->domain_name.c;
	const trust_anchors_t * const	trust_anchor			= zone->trust_anchor;
	const list_t * const			dnskey_trust_anchors	= &trust_anchor->dnskey_trust_anchors;
	mDNSBool						contain_trust_anchor	= trust_anchor_contains_dnskey(zone->trust_anchor);
	mDNSu8 parent_size = 0;

	for (mDNSu8 i = 0; i < child_size; i++) {
		dnssec_validator_node_t *		child			= &children[i];
		const list_t * const			rrsigs			= child->rrssigs_covering_it;

		for (const list_node_t * rrsig_node = list_get_first(rrsigs); !list_has_ended(rrsigs, rrsig_node); rrsig_node = list_next(rrsig_node)) {
			const dnssec_rrsig_t * const	dnssec_rrsig		= (dnssec_rrsig_t *)rrsig_node->data;
			const mDNSu16					key_tag_from_rrsig	= dnssec_rrsig->key_tag;

			if (contain_trust_anchor) {
				// has saved dnskey as trust anchor
				for (const list_node_t * dnskey_node = list_get_first(dnskey_trust_anchors);
						!list_has_ended(dnskey_trust_anchors, dnskey_node);
						dnskey_node = list_next(dnskey_node)) {

					const dnssec_dnskey_t * const	dnssec_dnskey		= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16					key_tag_from_dnskey = dnssec_dnskey->key_tag;

					if (key_tag_from_rrsig != key_tag_from_dnskey) {
						continue;
					}

					dnssec_validator_node_t * const parent = &parents[parent_size];
					parent_size++;
					uninitialize_validator_node(parent);
					initialize_validator_node_with_zsk(parent, dnssec_dnskey, dnssec_rrsig, zone_name, dnskeys, rrsigs_covering_dnskeys, mDNStrue);

					goto find_matching_parent;
				}
			} else {
				for (const list_node_t * dnskey_node = list_get_first(dnskeys);
						!list_has_ended(dnskeys, dnskey_node);
						dnskey_node = list_next(dnskey_node)) {

					const dnssec_dnskey_t * const	dnssec_dnskey		= (dnssec_dnskey_t *)dnskey_node->data;
					const mDNSu16					key_tag_from_dnskey = dnssec_dnskey->key_tag;

					if (key_tag_from_rrsig != key_tag_from_dnskey) {
						continue;
					}

					dnssec_validator_node_t * const parent = &parents[parent_size];
					parent_size++;
					uninitialize_validator_node(parent);
					initialize_validator_node_with_zsk(parent, dnssec_dnskey, dnssec_rrsig, zone_name, dnskeys, rrsigs_covering_dnskeys, mDNSfalse);

					goto find_matching_parent;
				}
			}
		}
	find_matching_parent:
		continue;
	}
	if (contain_trust_anchor && parent_size != child_size) {
		// trust anchor cannot be used to verify this response, now going back to records retrieval
		result = dnssec_validation_trust_anchor_does_not_macth;
		goto exit;
	}
	require_action_quiet(parent_size == child_size, exit, result = dnssec_validation_no_matching_key_tag);

	error = validate_validator_node(parents, parent_size);
	require_action_quiet(error == dnssec_validation_valid, exit, result = error);

	error = validate_validator_path_between_parents_and_children(request_id, children, parents, &parent_size);
	require_action_quiet(error == dnssec_validation_valid, exit, result = error);

	dedup_validator_with_the_same_siblings(parents, &parent_size);

	*out_parent_size = parent_size;

	result = dnssec_validation_valid;

exit:
	return result;
}

//======================================================================================================================
//	initialize_validator_node_with_rr
//======================================================================================================================

mDNSlocal void
initialize_validator_node_with_rr(
	dnssec_validator_node_t * const _Nonnull	node,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,
	const list_t * const			_Nonnull	rrsigs_covering_it, // list_t<dnssec_rrsig_t>
	response_type_t								response_type) {	// list_t<dnssec_original_t>

	node->type					= rr_validator;
	node->u.rr.rr_response_type = response_type;
	node->name					= name;
	node->siblings				= siblings;
	node->rrssigs_covering_it	= rrsigs_covering_it;
	node->trusted				= mDNSfalse;
}

//======================================================================================================================
//	initialize_validator_node_with_nsec
//======================================================================================================================

mDNSlocal void
initialize_validator_node_with_nsec(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_nsec_t	*			_Nullable	nsec,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	rrsig_covering_it ) {	// list_t<dnssec_rrsig_t>

	node->type							= nsec_validator;
	node->u.nsec.nsec					= nsec;
	node->name							= name;
	node->siblings						= mDNSNULL;
	node->rrssigs_covering_it			= rrsig_covering_it;
	node->trusted						= mDNSfalse;
}

//======================================================================================================================
//	initialize_validator_node_with_nsec3
//======================================================================================================================

mDNSlocal void
initialize_validator_node_with_nsec3(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_nsec3_t	*			_Nullable	nsec3,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	rrsig_covering_it) {	// list_t<dnssec_rrsig_t>

	node->type						= nsec3_validator;
	node->u.nsec3.nsec3				= nsec3;
	node->name						= name;
	node->siblings					= mDNSNULL;
	node->rrssigs_covering_it		= rrsig_covering_it;
	node->trusted					= mDNSfalse;
}

//======================================================================================================================
//	initialize_validator_node_with_zsk
//======================================================================================================================

mDNSlocal void
initialize_validator_node_with_zsk(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_dnskey_t * const	_Nonnull	key,
	const dnssec_rrsig_t * const	_Nonnull	sig,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,			// list<dnssec_dnskey_t>
	const list_t * const			_Nonnull	rrsig_covering_it,	// list_t<dnssec_rrsig_t>
	mDNSBool									trusted) {

	node->type					= zsk_validator;
	node->u.zsk.key				= key;
	node->u.zsk.sig				= sig;
	node->name					= name;
	node->siblings				= siblings;
	node->rrssigs_covering_it	= rrsig_covering_it;
	node->trusted				= trusted;
}

//======================================================================================================================
//	initialize_validator_node_with_ksk
//======================================================================================================================

mDNSlocal void
initialize_validator_node_with_ksk(
	dnssec_validator_node_t * const _Nonnull	node,
	const dnssec_dnskey_t * const	_Nonnull	key,
	const dnssec_rrsig_t * const	_Nonnull	sig,
	const dnssec_ds_t * const		_Nullable	ds,
	const mDNSu8 * const			_Nonnull	name,
	const list_t * const			_Nonnull	siblings,				// list<dnssec_ds_t>
	const list_t * const			_Nonnull	rrsig_covering_it,		// list_t<dnssec_rrsig_t>
	mDNSBool									trusted) {

	node->type					= ksk_validator;
	node->u.ksk.key				= key;
	node->u.ksk.sig				= sig;
	node->u.ksk.ds				= ds;
	node->name					= name;
	node->siblings				= siblings;
	node->rrssigs_covering_it	= rrsig_covering_it;
	node->trusted				= trusted;
}

//======================================================================================================================
//	uninitialize_validator_node
//======================================================================================================================

mDNSlocal void
uninitialize_validator_node(dnssec_validator_node_t * const _Nonnull node) {
	bzero(node, sizeof(dnssec_validator_node_t));
}

//======================================================================================================================
//	is_validator_node_valid
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_validator_node(const dnssec_validator_node_t * const _Nonnull nodes, const mDNSu8 nodes_count) {

	dnssec_validation_result_t	result	= dnssec_validation_valid;

	for (mDNSu8 i = 0; i < nodes_count; i++) {
		const dnssec_validator_node_t * const node = &nodes[i];

		switch (node->type) {
			case rr_validator:
				break;
			case nsec_validator:
				result = validate_nsec(node->u.nsec.nsec);
				require_quiet(result == dnssec_validation_valid, exit);
				break;
			case nsec3_validator:
				result = validate_nsec3(node->u.nsec3.nsec3);
				require_quiet(result == dnssec_validation_valid, exit);
				break;
			case zsk_validator:
				result = validate_dnskey(node->u.zsk.key, mDNSfalse);
				require_quiet(result == dnssec_validation_valid, exit);

				result = validate_rrsig(node->u.zsk.sig);
				require_quiet(result == dnssec_validation_valid, exit);

				require_action(node->u.zsk.key->algorithm == node->u.zsk.sig->algorithm, exit,
								result = dnssec_validation_algorithm_number_not_equal);
				break;
			case ksk_validator:
				result = validate_dnskey(node->u.ksk.key, mDNStrue);
				require_quiet(result == dnssec_validation_valid, exit);

				result = validate_rrsig(node->u.ksk.sig);
				require_quiet(result == dnssec_validation_valid, exit);

				if (node->u.ksk.ds != mDNSNULL) {
					result = validate_ds(node->u.ksk.ds);
					require_quiet(result == dnssec_validation_valid, exit);
				} else{
					require_action_quiet(node->trusted, exit, result = dnssec_validation_invalid_internal_state);
				}

				if (node->u.ksk.ds != mDNSNULL) {
					require_action(node->u.ksk.key->algorithm == node->u.ksk.ds->algorithm, exit,
						result = dnssec_validation_algorithm_number_not_equal);
				}

				require_action(node->u.ksk.key->algorithm == node->u.ksk.sig->algorithm, exit,
								result = dnssec_validation_algorithm_number_not_equal);

				if (node->u.ksk.ds != mDNSNULL) {
					result = check_if_ds_ksk_matches(node->u.ksk.ds, node->u.ksk.key);
					require_quiet(result == dnssec_validation_valid, exit);
				}
				break;
			default:
				result = dnssec_validation_invalid_internal_state;
				break;
		}
	}

exit:
	return result;
}

//======================================================================================================================
//	validate_validator_path_between_parents_and_children
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_validator_path_between_parents_and_children(
	const mDNSu32							request_id,
	dnssec_validator_node_t *	_Nonnull	children,
	dnssec_validator_node_t *	_Nonnull	parents,
	mDNSu8 * const				_Nonnull	out_parent_size) {

	dnssec_validation_result_t	result;
	dnssec_validation_result_t	error;
	mDNSu8						parent_size = *out_parent_size;

	require_action_quiet(parent_size != 0, exit, result = dnssec_validation_invalid_internal_state);

	for (mDNSu8 i = 0; i < parent_size; i++) {
		const dnssec_validator_node_t * const child		= &children[i];
		const dnssec_validator_node_t * const parent	= &parents[i];

		error = validate_validator_path(request_id, child, parent);
		require_action_quiet(error == dnssec_validation_valid, exit, result = error);

		if (parent->type == ksk_validator) {
			const dnssec_dnskey_t * const	ksk = parent->u.ksk.key;
			const dnssec_ds_t * const		ds	= parent->u.ksk.ds;

			error = check_trust_validator_node(parent);
			if (error == dnssec_validation_trusted) {
				if (ds != mDNSNULL) {
					// ds trust anchor
					log_default("[R%u] " PRI_DM_NAME ": DS (digest_type=%u, tag=%u, trust_anchor) -----> " PRI_DM_NAME ": DNSKEY (KSK, alg=%u, tag=%u, length=%u)",
						request_id, DM_NAME_PARAM(&ds->dnssec_rr.name), ds->digest_type, ds->key_tag,
						DM_NAME_PARAM(&ksk->dnssec_rr.name), ksk->algorithm, ksk->key_tag, ksk->public_key_length);
				} else {
					// dnskey trust anchor
					log_default("[R%u] " PRI_DM_NAME ": DNSKEY (KSK, alg=%u, tag=%u, length=%u, trust_anchor)",
						request_id,
						DM_NAME_PARAM(&ksk->dnssec_rr.name), ksk->algorithm, ksk->key_tag, ksk->public_key_length);
				}

				// parent node is trusted by the policy, no need to verify it
				if (i < parent_size - 1) {
					children[i] = children[i + 1];
					parents[i]	= parents[i + 1];
					i--;
				}
				parent_size--;
			} else {
				log_default("[R%u] " PRI_DM_NAME ": DS (digest_type=%u, tag=%u) -----> " PRI_DM_NAME ": DNSKEY (KSK, alg=%u, tag=%u, length=%u)",
					request_id, DM_NAME_PARAM(&ds->dnssec_rr.name), ds->digest_type, ds->key_tag,
					DM_NAME_PARAM(&ksk->dnssec_rr.name), ksk->algorithm, ksk->key_tag, ksk->public_key_length);
			}
		}
	}

	*out_parent_size = parent_size;
	result = dnssec_validation_valid;

exit:
	return result;
}

//======================================================================================================================
//	validate_validator_path
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_validator_path(
	const mDNSu32									request_id,
	const dnssec_validator_node_t * const _Nonnull	child,
	const dnssec_validator_node_t * const _Nonnull	parent) {

	dnssec_validation_result_t result = dnssec_validation_valid;

	if (child->type == zsk_validator && parent->type == ksk_validator) {
		result = validate_path_from_ksk_to_zsk(request_id, parent, child->siblings);
	} else if (child->type == ksk_validator && parent->type == zsk_validator) {
		result = validate_path_from_zsk_to_ds(request_id, parent, child->siblings);
	} else if (child->type == rr_validator && parent->type == zsk_validator) {
		result = validate_path_from_zsk_to_rr(request_id, parent, child->siblings, child->u.rr.rr_response_type);
	} else if (child->type == nsec_validator && parent->type == zsk_validator) {
		result = validate_path_from_zsk_to_nsec(request_id, parent, child);
	} else if (child->type == nsec3_validator && parent->type == zsk_validator) {
		result = validate_path_from_zsk_to_nsec3(request_id, parent, child);
	} else {
		result = dnssec_validation_path_invalid_node_type;
	}

	return result;
}


//======================================================================================================================
//	check_trust_validator_node
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
check_trust_validator_node(const dnssec_validator_node_t * const _Nonnull node) {
	return node->trusted ? dnssec_validation_trusted : dnssec_validation_not_trusted;
}

//======================================================================================================================
//	dedup_validator_with_the_same_siblings
//======================================================================================================================

mDNSlocal void
dedup_validator_with_the_same_siblings(
	dnssec_validator_node_t *	_Nonnull	parents,
	mDNSu8 * const				_Nonnull	out_parent_size) {

	const dnssec_validator_node_t * temp_parents[4]		= {mDNSNULL};
	mDNSu8							temp_parent_size	= 0;
	mDNSu8							parent_size			= *out_parent_size;

	for (mDNSu8 i = 0; i < parent_size; i++) {
		const dnssec_validator_node_t * const	parent	= &parents[i];
		mDNSBool								duplicate = mDNSfalse;

		for (mDNSu8 j = 0; j < temp_parent_size; j++) {
			const dnssec_validator_node_t * const parent_nodup = temp_parents[j];
			// if two nodes to be verified have the same siblings to verify, they are the duplicates, since RRSIG signs the entire siblings
			if (parent_nodup->siblings == parent->siblings) {
				duplicate = mDNStrue;
			}
		}

		if (!duplicate) {
			temp_parents[temp_parent_size] = parent;
			temp_parent_size++;
		}
	}

	for (mDNSu8 i = 0; i < temp_parent_size; i++) {
		parents[i] = *temp_parents[i];
	}
	parent_size			= temp_parent_size;
	*out_parent_size	= parent_size;
}

//======================================================================================================================
//	dedup_validator_with_the_same_siblings
//======================================================================================================================

mDNSlocal void __unused
print_ds_validation_progress(const dnssec_validator_node_t * const _Nonnull nodes, const mDNSu8 nodes_count) {
	for (mDNSu8 i = 0; i < nodes_count; i++) {
		const dnssec_validator_node_t * const node = &nodes[i];
		verify_action(node->type == ksk_validator,
			log_error("validator type is not Key Signing Key; type=%u", node->type); continue);

		const dnssec_dnskey_t * const	ksk = node->u.ksk.key;
		const dnssec_ds_t * const		ds	= node->u.ksk.ds;

		log_default(PRI_DM_NAME ": DS (digest_type=%u, tag=%u) ----->" PRI_DM_NAME ": DNSKEY (KSK, alg=%u, tag=%u, length=%u)",
			DM_NAME_PARAM(&ds->dnssec_rr.name), ds->digest_type, ds->key_tag,
			DM_NAME_PARAM(&ksk->dnssec_rr.name), ksk->algorithm, ksk->key_tag, ksk->public_key_length);

	}
}

//======================================================================================================================
//	validate_zone_records_type
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_zone_records_type(const dnssec_zone_t * const _Nonnull zone) {
	dnssec_validation_result_t result = dnssec_validation_valid;

	if (zone->dnskey_request_started && zone->ds_request_started) {
		// the most common case where zone does not have any trust anchor.
		require_action_quiet(zone->dses_with_rrsig.type == original_response, exit, result = dnssec_validation_non_dnskey_ds_record_chain);
	} else if (!zone->dnskey_request_started && zone->ds_request_started) {
		// This is impossible because if dnskey request is not started that means we have trust anchor for DNSKEY, and there
		// is no need to send DS query, thus ds_request_started could not be true
		result = dnssec_validation_invalid_internal_state;
		goto exit;
	} else if (zone->dnskey_request_started && !zone->ds_request_started) {
		// It means the system has DS trust anchor installed, thus there is no need to query for DS record, only DNSKEY
		// record is required, and we must have DS trust anchor
		require_action_quiet(zone->trust_anchor != mDNSNULL && !list_empty(&zone->trust_anchor->ds_trust_anchors), exit, result = dnssec_validation_invalid_internal_state);
	} else { // !zone->dnskey_request_started && !zone->ds_request_started
		// The system has DNSKEY trust anchor, and there is no need to query for DNSKEY or DS record at all.
		// we must have DNSKEY trust anchor
		require_action_quiet(zone->trust_anchor != mDNSNULL && !list_empty(&zone->trust_anchor->dnskey_trust_anchors), exit, result = dnssec_validation_invalid_internal_state);
	}

exit:
	return result;
}

//======================================================================================================================
//	validate_ds
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_ds(const dnssec_ds_t * const _Nonnull ds) {
	dnssec_validation_result_t		result = dnssec_validation_valid;
	mDNSs16							digest_priority;
	mDNSs16							algorithm_priority;
	// TODO: print dnssec_ds_t when failing to pass validation

	// check digest type
	digest_priority = get_priority_of_ds_digest(ds->digest_type);
	require_action(digest_priority != -1, exit, result = dnssec_validation_ds_digest_not_supported;
		log_default("Unsupported or invalid DS digest type; digest_type=%u", ds->digest_type));

	// check algorithm type
	algorithm_priority = get_priority_of_dnskey_algorithm(ds->algorithm);
	require_action(algorithm_priority != -1, exit, result = dnssec_validation_dnskey_algorithm_not_supported;
					log_default("Unsupported or invalid DNSKEY algorithm type; algorithm=%u", ds->algorithm));
exit:
	return result;
}

//======================================================================================================================
//	validate_dnskey
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_dnskey(const dnssec_dnskey_t * const _Nonnull dnskey, mDNSBool security_entry_point) {
	dnssec_validation_result_t		result = dnssec_validation_valid;
	mDNSs16							algorithm_priority;

	// check zone key flag
	require_action((dnskey->flags & DNSKEY_FLAG_ZONE_KEY) != 0, exit, result = dnssec_validation_dnskey_invalid_flags;
		log_default("Not a DNSSEC DNSKEY in DNSKEY; flags=%x", dnskey->flags));

	// check the security entry point flag
	require_action(!security_entry_point || (dnskey->flags & DNSKEY_FLAG_SECURITY_ENTRY_POINT) != 0, exit,
		result = dnssec_validation_dnskey_invalid_flags);

	// check protocol
	require_action(dnskey->protocol == 3, exit, result = dnssec_validation_dnskey_wrong_protocol;
		log_default("Not a DNSSEC Protocol in DNSKEY; protocol=%u", dnskey->protocol));

	// check DNSKEY algorithm
	algorithm_priority = get_priority_of_dnskey_algorithm(dnskey->algorithm);
	require_action(algorithm_priority != -1, exit, result = dnssec_validation_dnskey_algorithm_not_supported;
		log_default("Unsupported or invalid DNSKEY algorithm type in DNSKEY; algorithm=%u", dnskey->algorithm));

exit:
	return result;
}

//======================================================================================================================
//	validate_rrsig
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_rrsig(const dnssec_rrsig_t * const _Nonnull rrsig) {
	dnssec_validation_result_t		result = dnssec_validation_valid;
	mDNSs16							algorithm_priority;
	int64_t							now;
	mDNSu32							now_u32;
	// TODO: print dnssec_rrsig_t when failing to pass validation

	// check DNSKEY algorithm
	algorithm_priority = get_priority_of_dnskey_algorithm(rrsig->algorithm);
	require_action(algorithm_priority != -1, exit, result = dnssec_validation_dnskey_algorithm_not_supported;
		log_default("Unsupported or invalid DNSKEY algorithm type in RRSIG; algorithm=%u", rrsig->algorithm));

	// TODO: check the label field for RRSIG

	// check inception and expiration time
	now = time(mDNSNULL);
	require_action(now <= UINT32_MAX, exit, result = dnssec_validation_invalid_internal_state;
		log_fault("the value of time(NULL) is now greater than UINT32_MAX"));

	now_u32 = (mDNSu32)now;
	require_action(now_u32 >= rrsig->signature_inception, exit, result = dnssec_validation_rrsig_use_before_inception;
		log_default("RRSIG incpetion time is greater than the current time; inception_time=%u, now=%d", rrsig->signature_inception, now_u32));

	require_action(now_u32 <= rrsig->signature_expiration, exit, result = dnssec_validation_rrsig_use_after_expiration;
		log_default("RRSIG expiration time is less than the current time; expiration_time=%u, now=%d", rrsig->signature_expiration, now_u32));

exit:
	return result;
}

//======================================================================================================================
//	validate_nsec
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_nsec(const dnssec_nsec_t * const _Nonnull nsec) {
	(void) nsec;

	return dnssec_validation_valid;
}

//======================================================================================================================
//	validate_nsec3
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
validate_nsec3(const dnssec_nsec3_t * const _Nonnull nsec3) {
	dnssec_validation_result_t result = dnssec_validation_valid;
	// check if hash algorithm is supported
	switch (nsec3->hash_algorithm) {
		case 1: // only SHA-1 is supported
			break;
		default:
			result = dnssec_validation_nsec3_unsupported_hash_algorithm;
			goto exit;
	}

	// check flags, only Opt-Out flag is defined, all undefined flags should be zero
	require_action((nsec3->flags & (~NSEC3_FLAG_SET)) == 0, exit, result = dnssec_validation_nsec3_unsupported_flag);

exit:
	return result;
}

//======================================================================================================================
//	check_if_ds_ksk_matches
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
check_if_ds_ksk_matches(const dnssec_ds_t * const _Nonnull ds, const dnssec_dnskey_t * const _Nonnull ksk) {
	// reconstruct the data that will be hashed
	dnssec_validation_result_t result = dnssec_validation_valid;
	mDNSBool				matches;
	const mDNSu8 * const	owner_name					= ksk->dnssec_rr.name.c;
	const mDNSu16			owner_name_length			= DOMAIN_NAME_LENGTH(owner_name);
	const mDNSu8 * const	dnskey_rdata				= ksk->dnssec_rr.rdata;
	const mDNSu16			rdata_length				= ksk->dnssec_rr.rdata_length;
	mDNSu8					digest_buffer[MAX_HASH_OUTPUT_SIZE];
	mDNSu32					digest_size;
	digest_type_t		digest_type;
	const mDNSu32			data_to_be_hashed_length	= owner_name_length + rdata_length;
	mDNSu8 * const			data_to_be_hashed			= malloc(data_to_be_hashed_length);
	require_action(data_to_be_hashed != mDNSNULL, exit, result = dnssec_validation_no_memory);

	memcpy(data_to_be_hashed, owner_name, owner_name_length);
	memcpy(data_to_be_hashed + owner_name_length, dnskey_rdata, rdata_length);

	switch (ds->digest_type) {
		case DS_DIGEST_SHA_1:
			digest_type = DIGEST_SHA_1;
			break;
		case DS_DIGEST_SHA_256:
			digest_type = DIGEST_SHA_256;
			break;
		case DS_DIGEST_SHA_384:
			digest_type = DIGEST_SHA_384;
			break;
		default:
			result		= dnssec_validation_ds_digest_not_supported;
			goto exit;
	}
	digest_size = get_digest_length_for_ds_digest_type(ds->digest_type);
	mDNSBool calculated = calculate_digest_for_data(data_to_be_hashed, data_to_be_hashed_length, digest_type, digest_buffer, sizeof(digest_buffer));
	require_action_quiet(calculated, exit, result = dnssec_validation_invalid_internal_state);
	require_action(digest_size == ds->digest_length, exit, result = dnssec_validation_bogus);

	matches = (memcmp(digest_buffer, ds->digest, digest_size) == 0);

	require_action(matches, exit, result = dnssec_validation_bogus);

exit:
	if (data_to_be_hashed != mDNSNULL) {
		free(data_to_be_hashed);
	}
	return result;
}

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_rr(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	originals /* list_t<dnssec_original_t> or list_t<dnssec_cname_t> */,
	response_type_t										response_type) {

	dnssec_validation_result_t	result				= dnssec_validation_valid;
	mDNSu8 *					signed_data			= mDNSNULL;
	mDNSu32						signed_data_length;
	mDNSBool					is_signed_data_valid;

	result = check_rrsig_validity_with_rrs(parent->u.zsk.sig, originals, response_type, kDNSQType_ANY);
	require_action(result == dnssec_validation_valid, exit, log_default("RRSIG is not valid for validation"));

	signed_data = reconstruct_signed_data_with_rrs(originals, parent->u.zsk.sig, response_type, kDNSQType_ANY, &signed_data_length);
	require_action(signed_data != mDNSNULL, exit, result = dnssec_validation_no_memory;
		log_default("No enough memory to allocate for signed data;"));

	is_signed_data_valid = validate_signed_data_with_rrsig_and_dnskey(request_id, signed_data, signed_data_length, parent->u.zsk.sig, parent->u.zsk.key);

	result = is_signed_data_valid ? dnssec_validation_valid : dnssec_validation_invalid;

exit:
	if (signed_data != mDNSNULL) {
		free(signed_data);
		signed_data = mDNSNULL;
	}
	return result;
}

mDNSlocal dnssec_validation_result_t
validate_path_from_ksk_to_zsk(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	zsks /* list_t<dnssec_dnskey_t> */) {

	dnssec_validation_result_t	result				= dnssec_validation_valid;
	mDNSu8 *					signed_data			= mDNSNULL;
	mDNSu32						signed_data_length;
	mDNSBool					is_signed_data_valid;

	// TODO: original_response could be nsec nsec3
	result = check_rrsig_validity_with_rrs(parent->u.ksk.sig, zsks, original_response, kDNSType_DNSKEY);
	require_quiet(result == dnssec_validation_valid, exit);

	signed_data = reconstruct_signed_data_with_rrs(zsks, parent->u.ksk.sig, original_response, kDNSType_DNSKEY, &signed_data_length);
	require_action(signed_data != mDNSNULL, exit, result = dnssec_validation_no_memory;
		log_default("No enough memory to allocate for signed data;"));

	is_signed_data_valid = validate_signed_data_with_rrsig_and_dnskey(request_id, signed_data, signed_data_length, parent->u.ksk.sig, parent->u.ksk.key);
	result = is_signed_data_valid ? dnssec_validation_valid : dnssec_validation_invalid;

exit:
	if (signed_data != mDNSNULL) {
		free(signed_data);
		signed_data = mDNSNULL;
	}
	return result;
}

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_ds(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const list_t * const					_Nonnull	dses /* list_t<dnssec_ds_t> */) {

	dnssec_validation_result_t	result				= dnssec_validation_valid;
	mDNSu8 *						signed_data			= mDNSNULL;
	mDNSu32							signed_data_length;
	mDNSBool						is_signed_data_valid;

	// TODO: original_response could be nsec nsec3
	result = check_rrsig_validity_with_rrs(parent->u.zsk.sig, dses, original_response, kDNSType_DS);
	require_quiet(result == dnssec_validation_valid, exit);

	signed_data = reconstruct_signed_data_with_rrs(dses, parent->u.zsk.sig, original_response, kDNSType_DS, &signed_data_length);
	require_action(signed_data != mDNSNULL, exit, result = dnssec_validation_no_memory;
					log_default("No enough memory to allocate for signed data;"));

	is_signed_data_valid = validate_signed_data_with_rrsig_and_dnskey(request_id, signed_data, signed_data_length, parent->u.zsk.sig, parent->u.zsk.key);
	result = is_signed_data_valid ? dnssec_validation_valid : dnssec_validation_invalid;

exit:
	if (signed_data != mDNSNULL) {
		free(signed_data);
		signed_data = mDNSNULL;
	}
	return result;

}

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_nsec(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const dnssec_validator_node_t * const	_Nonnull	child) {

	dnssec_validation_result_t	result;
	dnssec_validation_result_t	error;
	mDNSu8 *					signed_data			= mDNSNULL;
	mDNSu32						signed_data_length;
	mDNSBool					is_signed_data_valid;

	error = check_rrsig_validity_with_dnssec_rr(parent->u.zsk.sig, &child->u.nsec.nsec->dnssec_rr);
	require_action(error == dnssec_validation_valid, exit, result = error; log_default("RRSIG is invalid"));

	signed_data = reconstruct_signed_data_with_one_dnssec_rr(&child->u.nsec.nsec->dnssec_rr, parent->u.zsk.sig, &signed_data_length);
	require_action(signed_data != mDNSNULL, exit, result = dnssec_validation_no_memory;
					log_error("No enough memory to allocate for signed data;"));

	is_signed_data_valid = validate_signed_data_with_rrsig_and_dnskey(request_id, signed_data, signed_data_length, parent->u.zsk.sig, parent->u.zsk.key);
	result = is_signed_data_valid ? dnssec_validation_valid: dnssec_validation_invalid;

exit:
	if (signed_data != mDNSNULL) {
		free(signed_data);
		signed_data = mDNSNULL;
	}
	return result;
}

mDNSlocal dnssec_validation_result_t
validate_path_from_zsk_to_nsec3(
	const mDNSu32										request_id,
	const dnssec_validator_node_t * const	_Nonnull	parent,
	const dnssec_validator_node_t * const	_Nonnull	child) {

	dnssec_validation_result_t	result;
	dnssec_validation_result_t	error;
	mDNSu8 *					signed_data			= mDNSNULL;
	mDNSu32						signed_data_length;
	mDNSBool					is_signed_data_valid;

	error = check_rrsig_validity_with_dnssec_rr(parent->u.zsk.sig, &child->u.nsec3.nsec3->dnssec_rr);
	require_action(error == dnssec_validation_valid, exit, result = error; log_default("RRSIG is invalid"));

	signed_data = reconstruct_signed_data_with_one_dnssec_rr(&child->u.nsec3.nsec3->dnssec_rr, parent->u.zsk.sig, &signed_data_length);
	require_action(signed_data != mDNSNULL, exit, result = dnssec_validation_no_memory;
		log_error("No enough memory to allocate for signed data;"));

	is_signed_data_valid = validate_signed_data_with_rrsig_and_dnskey(request_id, signed_data, signed_data_length, parent->u.zsk.sig, parent->u.zsk.key);
	result = is_signed_data_valid ? dnssec_validation_valid: dnssec_validation_invalid;

exit:
	if (signed_data != mDNSNULL) {
		free(signed_data);
		signed_data = mDNSNULL;
	}
	return result;
}

//======================================================================================================================
//	check_rrsig_validity_with_rr
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
check_rrsig_validity_with_dnssec_rr(
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const dnssec_rr_t * const		_Nonnull	rr) {

	dnssec_validation_result_t	result				= dnssec_validation_valid;
	const mDNSu8 * const		owner_name			= rrsig->dnssec_rr.name.c;
	const mDNSu32				owner_name_hash		= rrsig->dnssec_rr.name_hash;
	const mDNSu16				class				= rrsig->dnssec_rr.rr_class;
	const mDNSu8 * const		signer_name			= rrsig->signer_name;
	const mDNSu16				type_covered		= rrsig->type_covered;
	const mDNSu8				labels_rrsig		= rrsig->labels;
	mDNSu8						labels_rr;

	// The RRSIG RR and the RRset MUST have the same owner name,
	require_action(owner_name_hash == rr->name_hash, exit, result = dnssec_validation_path_unmatched_owner_name;
					log_default("The owner names of RRSIG and records do not match; RRSIG=" PRI_DM_NAME ", RR=" PRI_DM_NAME,
								DM_NAME_PARAM((const domainname * const)owner_name), DM_NAME_PARAM(&rr->name)));
	require_action(DOMAIN_NAME_EQUALS(owner_name, rr->name.c), exit, result = dnssec_validation_path_unmatched_owner_name;
					log_default("The owner names of RRSIG and records do not match; RRSIG=" PRI_DM_NAME ", RR=" PRI_DM_NAME,
								DM_NAME_PARAM((const domainname * const)owner_name), DM_NAME_PARAM(&rr->name)));

	// and the same class.
	require_action(class == rr->rr_class, exit, result = dnssec_validation_path_unmatched_class;
					log_default("The classes of RRSIG and records do not match; RRSIG=%u, RR=%u", class, rr->rr_class));

	// TODO: The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset
	(void) signer_name;

	// The RRSIG RR's Type Covered field MUST equal the RRset's type.
	require_action(type_covered == rr->rr_type, exit, result = dnssec_validation_path_unmatched_type_covered;
					log_default("The RRSIG does not cover the current record; RRSIG=" PUB_S ", RR=" PUB_S,
								DNS_TYPE_STR(type_covered), DNS_TYPE_STR(rr->rr_type)));

	// The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
	labels_rr = get_number_of_labels(rr->name.c);
	require_action(labels_rrsig <= labels_rr, exit, result = dnssec_validation_path_invalid_label_count;
					log_default("the RRSIG's label is not less than or equal to the number of labels in RR's owner's name; RRSIG=%u, RR=%u",
								labels_rrsig, labels_rr));

exit:
	return result;
}

//======================================================================================================================
//	check_rrsig_validity_with_dnssec_rrs
//======================================================================================================================

mDNSlocal dnssec_validation_result_t
check_rrsig_validity_with_rrs(
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const list_t * const			_Nonnull	list_to_check,
	response_type_t								response_type_in_list,
	const mDNSu16								record_type_in_list) {

	dnssec_validation_result_t	result				= dnssec_validation_valid;
	const dnssec_rr_t *				rr;

	for (list_node_t *node = list_get_first(list_to_check); !list_has_ended(list_to_check, node); node = list_next(node)) {
		// get correct node from the list
		switch (response_type_in_list) {
			case original_response:
			{
				if (record_type_in_list == kDNSQType_ANY) {
					const dnssec_original_t * const original = (dnssec_original_t *)node->data;
					rr = &original->dnssec_rr;
				} else if (record_type_in_list == kDNSType_DNSKEY) {
					const dnssec_dnskey_t * const dnskey = (dnssec_dnskey_t *)node->data;
					rr = &dnskey->dnssec_rr;
				} else if (record_type_in_list == kDNSType_DS) {
					const dnssec_ds_t * const ds = (dnssec_ds_t *)node->data;
					rr = &ds->dnssec_rr;
				} else {
					result = dnssec_validation_path_invalid_node_type;
					goto exit;
				}
				break;
			}
			case cname_response:
			{
				const dnssec_cname_t * const cname = (dnssec_cname_t *)node->data;
				rr = &cname->dnssec_rr;
			}
				break;
			case nsec_response:
			{
				if (record_type_in_list == kDNSQType_ANY) {
					rr = (dnssec_rr_t *)node->data;
				} else if (record_type_in_list == kDNSType_NSEC) {
					const dnssec_nsec_t * const nsec = (dnssec_nsec_t *)node->data;
					rr = &nsec->dnssec_rr;
				} else {
					result = dnssec_validation_path_invalid_node_type;
					goto exit;
				}
				break;
			}
			case nsec3_response:
			{
				const dnssec_nsec3_t * const nsec3 = (dnssec_nsec3_t *)node->data;
				rr = &nsec3->dnssec_rr;
			}
				break;
			default:
			{
				result = dnssec_validation_path_invalid_node_type;
				goto exit;
			}
		}

		result = check_rrsig_validity_with_dnssec_rr(rrsig, rr);
		require_quiet(result == dnssec_validation_valid, exit);
	}

exit:
	return result;
}

//======================================================================================================================
//	reconstruct_signed_data_with_dnssec_rrs
//======================================================================================================================

mDNSlocal void *
reconstruct_signed_data_with_rrs(
	const list_t * const			_Nonnull	rr_set,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	const response_type_t						response_type,
	const mDNSu16								record_type,
	mDNSu32 * const					_Nonnull	out_signed_data_length) {

	mDNSu8					rr_count			= 0;
	const dnssec_rr_t *		rr_array[256]; // The maximum number of RR in one RRSET should be no more than 256

	// sort RRset in canonical order
	for (list_node_t *node = list_get_first(rr_set); !list_has_ended(rr_set, node); node = list_next(node)) {
		dnssec_rr_t *rr;

		switch (response_type) {
			case original_response:
				if (record_type == kDNSQType_ANY) {
					rr = &((dnssec_original_t *)node->data)->dnssec_rr;
				} else if (record_type == kDNSType_DNSKEY) {
					rr = &((dnssec_dnskey_t *)node->data)->dnssec_rr;
				} else if (record_type == kDNSType_DS) {
					rr = &((dnssec_ds_t *)node->data)->dnssec_rr;
				} else {
					// It should never happen.
					log_error("incorrect DNSSEC data type");
					goto exit;
				}
				break;
			case cname_response:
				rr = &((dnssec_cname_t *)node->data)->dnssec_rr;
				break;
			case nsec_response: {
				if (record_type == kDNSQType_ANY) {
					rr = (dnssec_rr_t *)node->data;
				} else if (record_type == kDNSType_NSEC) {
					rr = &((dnssec_nsec_t *)node->data)->dnssec_rr;
				} else {
					goto exit;
				}
				break;
			}
			case nsec3_response:
				rr = &((dnssec_nsec3_t *)node->data)->dnssec_rr;
				break;
			default:
				// It should never happen.
				log_error("signed data has unknown_response type");
				goto exit;
		}

		rr_array[rr_count] = rr;
		rr_count++;
	}
	sort_rr_array_canonically(rr_array, rr_count);

	// deduplicate RRs in RRSet
	rr_array_dedup(rr_array, rr_count);

	return reconstruct_signed_data_internal(rr_array, rr_count, dnssec_rrsig, out_signed_data_length);

exit:
	return mDNSNULL;
}

//======================================================================================================================
//	reconstruct_signed_data_with_one_dnssec_rr
//======================================================================================================================

mDNSlocal void *
reconstruct_signed_data_with_one_dnssec_rr(
	const dnssec_rr_t * const		_Nonnull	dnssec_rr,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	mDNSu32 * const					_Nonnull	out_signed_data_length) {

	mDNSu8			rr_count = 0;
	const dnssec_rr_t *rr_array[1];

	rr_array[0] = dnssec_rr;
	rr_count = 1;

	return reconstruct_signed_data_internal(rr_array, rr_count, dnssec_rrsig, out_signed_data_length);
}

//======================================================================================================================
//	reconstruct_signed_data_internal
//======================================================================================================================

mDNSlocal void *
reconstruct_signed_data_internal(
	const dnssec_rr_t * const				rr_array[],
	const mDNSu8							rr_count,
	const dnssec_rrsig_t * const _Nonnull	dnssec_rrsig,
	mDNSu32 * const _Nonnull				out_signed_data_length) {

	mStatus error = mStatus_NoError;
	mDNSu32			signed_data_length	= 0;
	mDNSu8 *		signed_data			= mDNSNULL;
	mDNSu8 *		data_ptr			= mDNSNULL;
	mDNSu8 *		data_limit			= mDNSNULL;
	mDNSu32			number_bytes_copied = 0;

	// calculate correct signed data length taking duplicates, domain name decompression and wildcard expansion into consideration
	error = calculate_signed_data_length(rr_array, rr_count, dnssec_rrsig, &signed_data_length);
	require_quiet(error == mStatus_NoError, exit);

	// allocate memory for the signed data
	signed_data = malloc(signed_data_length);
	require_action(signed_data != mDNSNULL, exit, error = mStatus_NoMemoryErr; log_fault("malloc failed; error_description='%s'", strerror(errno)));

	data_ptr	= signed_data;
	data_limit	= data_ptr + signed_data_length;

	// signed_data += RRSIG_RDATA
	memcpy(data_ptr, dnssec_rrsig->dnssec_rr.rdata, offsetof(dns_type_rrsig_t, signer_name));
	data_ptr += offsetof(dns_type_rrsig_t, signer_name);

	// signed_data += RRSIG_RDATA(signer's name)
	data_ptr += copy_canonical_name(data_ptr, dnssec_rrsig->signer_name);

	for (mDNSu8 i = 0; i < rr_count; i++) {
		const dnssec_rr_t * const rr = rr_array[i];
		if (rr == mDNSNULL) { // the current record is a duplicate one
			continue;
		}

		// signed_data+= RR(i)
		data_ptr += copy_rr_for_signed_data(data_ptr, rr, dnssec_rrsig);
	}

	*out_signed_data_length = signed_data_length;
	number_bytes_copied = data_ptr - signed_data;
	require_action(number_bytes_copied == signed_data_length, exit, error = mStatus_UnknownErr;
					log_error("reconstruct_signed_data failed, number of bytes copied is not equal to the size of memory allocated; copied=%u, allocated=%u",
								number_bytes_copied, signed_data_length));
	require_quiet(data_ptr == data_limit, exit);

exit:
	if (error != mStatus_NoError) {
		if (signed_data != mDNSNULL) {
			free(signed_data);
			signed_data = mDNSNULL;
		}
	}
	return signed_data;
}

//======================================================================================================================
//	calculate_signed_data_length
//======================================================================================================================

mDNSlocal mStatus
calculate_signed_data_length(
	const dnssec_rr_t * const					rr_array[_Nonnull],
	const mDNSu8								rr_count,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig,
	mDNSu32 * const					_Nonnull	out_length) {

	mStatus error = mStatus_NoError;
	mDNSu32 signed_data_length = 0;

	// signed_data += RRSIG_RDATA(before signer's name) + signer's name
	signed_data_length += offsetof(dns_type_rrsig_t, signer_name) + canonical_form_name_length(dnssec_rrsig->signer_name);

	// signed_data += RR(x)
	for (mDNSu8 i = 0; i < rr_count; i++) {
		const dnssec_rr_t * const	rr			= rr_array[i];
		mDNSu32						rr_length	= 0;
		mDNSs16						name_length = 0;
		if (rr == mDNSNULL) { // It is a duplicate records, now skips it.
			continue;
		}

		name_length = calculate_name_length_in_signed_data(rr->name.c, dnssec_rrsig->labels);
		require_action(name_length != -1, exit, error = mStatus_Invalid;
						log_default("rrsig label count is invalid, cannot be used to validate records;"));

		// RR(i) += name
		rr_length += name_length;

		// RR(i) += type + class + OrigTTL + RDATA length
		rr_length += sizeof(rr->rr_type) + sizeof(rr->rr_class) + sizeof(dnssec_rrsig->original_TTL) + sizeof(rr->rdata_length);

		// RR(i) += RDATA
		rr_length += calculate_rdata_length_in_signed_data(rr);

		signed_data_length += rr_length;
	}

	*out_length = signed_data_length;
exit:
	return error;
}

//======================================================================================================================
//	calculate_name_length_in_signed_data
//======================================================================================================================

// length is calculated based on RFC 4035 Section 5.3.2. Reconstructing the Signed Data
mDNSlocal mDNSs16
calculate_name_length_in_signed_data(const mDNSu8 * const _Nonnull name, const mDNSu8 rrsig_labels) {
	// assume that the domainname* is already fully qualified
	mDNSu8 name_labels = get_number_of_labels(name);
	if (name_labels == rrsig_labels) {
		return DOMAIN_NAME_LENGTH(name);
	} else if (name_labels > rrsig_labels) {
		// wild card case, ignore this case for now
		return DOMAIN_NAME_LENGTH(name);
	} else {
		// name_labels < rrsig_labels
		return -1;
	}
}

//======================================================================================================================
//	calculate_rdata_length_in_signed_data
//======================================================================================================================

// ref: https://tools.ietf.org/html/rfc4034#section-6.2
mDNSlocal mDNSu16
calculate_rdata_length_in_signed_data(const dnssec_rr_t * const _Nonnull dnssec_rr) {
	// assumption:
	// 1. All the name in the rr is fully expanded and fully qualified.
	// 2. There is no wildcard name.

	return dnssec_rr->rdata_length;
}

//======================================================================================================================
//	copy_canonical_name
//======================================================================================================================
mDNSlocal const mDNSu8 *
get_wildcard_name(const mDNSu8 * const _Nonnull name, mDNSu8 * const _Nonnull buffer, const mDNSu16 buffer_length) {
	const mDNSu8 *			ptr			= name;
	const mDNSu16			name_length = DOMAIN_NAME_LENGTH(ptr);
	const mDNSu8 * const	ptr_limit	= ptr + name_length;
	mDNSu8 *				buffer_ptr	= buffer;

	verify_action(name_length <= buffer_length , return mDNSNULL);

	while (ptr < ptr_limit) {
		const mDNSu8 * const	label = ptr + 1;
		const mDNSu8			label_length = *ptr;
		if (ptr == name) {
			buffer_ptr[0] = 1;
			buffer_ptr[1] = '*';
		} else {
			buffer_ptr[0] = label_length;
			memcpy(buffer_ptr + 1, label, label_length);
		}

		ptr			+= 1 + ptr[0];
		buffer_ptr	+= 1 + buffer_ptr[0];
	}

	return buffer;
}

//======================================================================================================================
//	copy_rr_for_signed_data
//======================================================================================================================

mDNSlocal mDNSu32
copy_rr_for_signed_data(
	mDNSu8 *						_Nonnull	dst,
	const dnssec_rr_t * const		_Nonnull	rr,
	const dnssec_rrsig_t * const	_Nonnull	rrsig) {

	mDNSu16			canonical_rdata_length;
	mDNSu8 * const	original_dst = dst;

	// RR(i) += name
	dst += copy_name_in_rr_for_signed_data(dst, rr->name.c, rrsig);

	// RR(i) += type
	mDNSu16 rr_type_net = htons(rr->rr_type);
	memcpy(dst, &rr_type_net, sizeof(rr_type_net));
	dst += sizeof(rr_type_net);

	// RR(i) += class
	mDNSu16 rr_class_net = htons(rr->rr_class);
	memcpy(dst, &rr_class_net, sizeof(rr_class_net));
	dst += sizeof(rr_class_net);

	// RR(i) += Original TTL
	mDNSu32 original_ttl_net = htonl(rrsig->original_TTL);
	memcpy(dst, &original_ttl_net, sizeof(original_ttl_net));
	dst += sizeof(original_ttl_net);

	// RR(i) += RDATA length (canonical form of RDATA)
	canonical_rdata_length =	calculate_rdata_length_in_signed_data(rr);
	mDNSu16 canonical_rdata_length_net = ntohs(canonical_rdata_length);
	memcpy(dst, &canonical_rdata_length_net, sizeof(canonical_rdata_length_net));
	dst += sizeof(canonical_rdata_length_net);

	// RR(i) += RDATA (canonical form)
	dst += copy_rdata_in_rr(dst, rr->rdata, rr->rdata_length, rr->rr_type);

	return dst - original_dst;
}

//======================================================================================================================
//	copy_name_in_rr_for_signed_data
//======================================================================================================================

mDNSlocal mDNSu8
copy_name_in_rr_for_signed_data(
	mDNSu8 * const					_Nonnull	dst,
	const mDNSu8 * const			_Nonnull	name,
	const dnssec_rrsig_t * const	_Nonnull	dnssec_rrsig) {

	mDNSu8 name_labels	= get_number_of_labels(name);
	mDNSu8 rrsig_labels = dnssec_rrsig->labels;
	mDNSu8 bytes_write;

	if (name_labels == rrsig_labels) {
		bytes_write = copy_canonical_name(dst, name);
	} else {
		// name_labels > rrsig_labels
		// It is impossible to have "name_labels < rrsig_labels", since the function calculate_signed_data_length
		// already checks the validity of the records.
		// TODO: wildcard domain name.
		bytes_write = 0;
	}

	return bytes_write;
}

//======================================================================================================================
//	copy_rdata_in_rr
//======================================================================================================================

// The rdata is in the canonical form. ref: https://tools.ietf.org/html/rfc4034#section-6.2
mDNSlocal mDNSu16
copy_rdata_in_rr(mDNSu8 * const _Nonnull dst, const mDNSu8 * const rdata, const mDNSu16 rdata_length, const mDNSu8 rr_type) {
	// TODO: First assume all the rdata is already in canonical form.
	(void) rr_type;

	memcpy(dst, rdata, rdata_length);

	return rdata_length;
}

//======================================================================================================================
//	sort function
//======================================================================================================================

//======================================================================================================================
//	sort_records_with_algorithm
//======================================================================================================================

mDNSlocal void
sort_records_with_algorithm(dnssec_context_t * const _Nonnull context) {
	list_t *					rrsigs;
	originals_with_rrsig_t *	originals_with_rrsig = &context->original.original_result_with_rrsig;
	response_type_t				type;

	type = originals_with_rrsig->type;
	// sort RRSIG in original response
	switch (type) {
		case original_response:
		case cname_response:
			if (type == original_response) {
				rrsigs = &originals_with_rrsig->u.original.rrsig_records;
			} else if (type == cname_response) {
				rrsigs = &originals_with_rrsig->u.cname_with_rrsig.rrsig_records;
			} else {
				goto invalid_type_exit;
			}
			list_sort(rrsigs, &dnssec_rrsig_t_comparator);
			break;
		case nsec_response:
		case nsec3_response:
			if (type == nsec_response) {
				list_t *nsec_list = &originals_with_rrsig->u.nsecs_with_rrsig.nsec_and_rrsigs_same_name;
				for (list_node_t *nsec_node = list_get_first(nsec_list); !list_has_ended(nsec_list, nsec_node); nsec_node = list_next(nsec_node)) {
					one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
					list_sort(&one_nsec->rrsig_records, &dnssec_rrsig_t_comparator);
				}
			} else if (type == nsec3_response) {
				list_t *nsec3_list = &originals_with_rrsig->u.nsec3s_with_rrsig.nsec3_and_rrsigs_same_name;
				for (list_node_t *nsec3_node = list_get_first(nsec3_list); !list_has_ended(nsec3_list, nsec3_node); nsec3_node = list_next(nsec3_node)) {
					one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t *)nsec3_node->data;
					list_sort(&one_nsec3->rrsig_records, &dnssec_rrsig_t_comparator);
				}
			} else {
				goto invalid_type_exit;
			}
			break;
		default:
			goto invalid_type_exit;
	}


	// sort RRSIG and DS in zone records
	for (list_node_t *node = list_get_first(&context->zone_chain); !list_has_ended(&context->zone_chain, node); node = list_next(node)) {
		dnssec_zone_t *			zone				= (dnssec_zone_t *)node->data;
		dnskeys_with_rrsig_t *	dnskeys_with_rrsig	= &zone->dnskeys_with_rrsig;
		dses_with_rrsig_t *		dses_with_rrsig		= &zone->dses_with_rrsig;

		// sort DNSKEY RRSIG
		if (zone->dnskey_request_started) {
			list_sort(&dnskeys_with_rrsig->rrsig_records, &dnssec_rrsig_t_comparator);
		}

		if (zone->ds_request_started)
		{
			// sort DS RRSIG
			type = dses_with_rrsig->type;
			switch (type) {
				case original_response:
					list_sort(&dses_with_rrsig->u.original.rrsig_records, &dnssec_rrsig_t_comparator);
					break;
				case nsec_response:
				case nsec3_response:
					if (type == nsec_response) {
						list_t *nsec_list = &dses_with_rrsig->u.nsecs_with_rrsig.nsec_and_rrsigs_same_name;
						for (list_node_t *nsec_node = list_get_first(nsec_list); !list_has_ended(nsec_list, nsec_node); nsec_node = list_next(nsec_node)) {
							one_nsec_with_rrsigs_t * const one_nsec = (one_nsec_with_rrsigs_t *)nsec_node->data;
							list_sort(&one_nsec->rrsig_records, &dnssec_rrsig_t_comparator);
						}
					} else if (type == nsec3_response) {
						list_t *nsec3_list = &dses_with_rrsig->u.nsec3s_with_rrsig.nsec3_and_rrsigs_same_name;
						for (list_node_t *nsec3_node = list_get_first(nsec3_list); !list_has_ended(nsec3_list, nsec3_node); nsec3_node = list_next(nsec3_node)) {
							one_nsec3_with_rrsigs_t * const one_nsec3 = (one_nsec3_with_rrsigs_t *)nsec3_node->data;
							list_sort(&one_nsec3->rrsig_records, &dnssec_rrsig_t_comparator);
						}
					} else {
						goto invalid_type_exit;
					}
					break;
				default:
					goto invalid_type_exit;
			}
		}
	}

	return;
invalid_type_exit:
	log_error("Invalid original response type; type=%d", type);
	return;
}

//======================================================================================================================
//	dnssec_ds_t_comparator
//======================================================================================================================
mDNSlocal mDNSs8 __unused
dnssec_ds_t_comparator(const list_node_t * _Nonnull const left, const list_node_t * _Nonnull const right) {
	mDNSs8			result;
	dnssec_ds_t *	left_ds			= (dnssec_ds_t *)left->data;
	dnssec_ds_t *	right_ds		= (dnssec_ds_t *)right->data;
	mDNSs16			left_priority	= get_priority_of_ds_digest(left_ds->digest_type);
	mDNSs16			right_priority	= get_priority_of_ds_digest(right_ds->digest_type);

	if (left_priority < right_priority) {
		result = -1;
	} else if (left_priority > right_priority) {
		result = 1;
	} else {
		// left_priority == right_priority
		result = 0;
	}

	return result;
}

//======================================================================================================================
//	dnssec_rrsig_t_comparator
//======================================================================================================================

mDNSlocal mDNSs8
dnssec_rrsig_t_comparator(const list_node_t * _Nonnull const left, const list_node_t * _Nonnull const right) {
	mDNSs8			result;
	dnssec_rrsig_t *left_rrsig		= (dnssec_rrsig_t *)left->data;
	dnssec_rrsig_t *right_rrsig		= (dnssec_rrsig_t *)right->data;
	mDNSs16			left_priority	= get_priority_of_dnskey_algorithm(left_rrsig->algorithm);
	mDNSs16			right_priority	= get_priority_of_dnskey_algorithm(right_rrsig->algorithm);

	if (left_priority < right_priority) {
		result = 1;
	} else if (left_priority > right_priority) {
		result = -1;
	} else {
		// left_priority == right_priority
		result = 0;
	}

	return result;
}

//======================================================================================================================
//	sort_rr_array
//======================================================================================================================

mDNSlocal void
sort_rr_array_canonically(const dnssec_rr_t * rr_array[_Nonnull], const mDNSu8 rr_count) {
	// insertion sort is good for partially sorted array
	for (mDNSs32 j, i = 1; i < rr_count; i++) {
		const dnssec_rr_t * dnssec_rr_to_insert = rr_array[i];
		j = i - 1;

		while (j >= 0 && dnssec_rr_t_comparator(dnssec_rr_to_insert, rr_array[j]) == -1) {
			rr_array[j + 1] = rr_array[j];
			j--;
		}
		rr_array[j + 1] = dnssec_rr_to_insert;
	}
}

//======================================================================================================================
//	sort_rr_array
//======================================================================================================================

mDNSlocal mDNSs8
dnssec_rr_t_comparator(const dnssec_rr_t * const _Nonnull left, const dnssec_rr_t * const _Nonnull right) {
	mDNSu16 left_length		= left->rdata_length;
	mDNSu16 right_length	= right->rdata_length;
	mDNSu16 min_length		= MIN(left_length, right_length);
	mDNSs32 memcmp_result	= memcmp(left->rdata, right->rdata, min_length);
	mDNSs8	result;
	if (memcmp_result < 0) {
		result = -1;
	} else if (memcmp_result > 0) {
		result = 1;
	} else {
		// memcmp_result == 0
		if (left_length > right_length) {
			result = 1;
		} else if (left_length < right_length) {
			result = -1;
		} else {
			// left_length == right_length
			log_error("two RR are canonically equal;");
			result = 0;
		}
	}
	return result;
}

//======================================================================================================================
//	rr_array_dedup
//======================================================================================================================

mDNSlocal mDNSBool
rr_array_dedup(const dnssec_rr_t * rr_array[_Nonnull], const mDNSu8 rr_count) {
	mDNSBool duplicate = mDNSfalse;
	for (int i = 0, n = (int)rr_count - 1; i < n; i++) {
		const dnssec_rr_t *prev = rr_array[i];
		const dnssec_rr_t *next = rr_array[i + 1];
		if (equal_dnssec_rr_t(prev, next)) {
			rr_array[i] = mDNSNULL;
			duplicate = mDNStrue;
		}
	}
	return duplicate;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
