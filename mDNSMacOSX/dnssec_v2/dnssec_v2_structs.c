//
//	dnssec_v2_structs.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <string.h>					// for strerror
#include <errno.h>					// for errno
#include "DNSCommon.h"
#include "dnssec_v2_helper.h"
#include "dnssec_v2_structs.h"
#include "dnssec_v2_log.h"
#include "dnssec_v2_validation.h"
#include "dnssec_v2_trust_anchor.h"
#include "base_n.h"

//======================================================================================================================
//	Local functions
//======================================================================================================================

mDNSlocal char *
type_bit_map_to_cstring(
	const mDNSu8 * const _Nonnull	bit_map,
	const mDNSu16					map_length,
	char *							buffer,
	mDNSu32							buffer_length);

//======================================================================================================================
//	functions
//======================================================================================================================

//======================================================================================================================
//	dns_type_*_t parse functions
//======================================================================================================================

mDNSexport void
parsse_dns_type_cname_t(const void * const _Nonnull rdata, mDNSu8 * _Nullable * const _Nonnull out_cname) {
	// rdata != mDNSNULL
	dns_type_cname_t *cname_struct = (dns_type_cname_t *)rdata;

	if (out_cname != mDNSNULL) *out_cname = cname_struct->cname;
}

mDNSexport mDNSBool
parse_dns_type_ds_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nullable	out_key_tag,
	mDNSu8 * const		_Nullable	out_algorithm,
	mDNSu8 * const		_Nullable	out_digest_type,
	mDNSu16 * const		_Nullable	out_digest_length,
	const mDNSu8 * _Nonnull * const _Nullable	out_digest) {

	mDNSBool is_valid = mDNSfalse;
	dns_type_ds_t *ds = (dns_type_ds_t *)rdata;

	require_action_quiet(rdata_length > offsetof(dns_type_ds_t, digest), exit, is_valid = mDNSfalse;
		log_debug("DS record parsing failed because of incorrect rdata length - rdata length: %u", rdata_length));

	if (out_key_tag != mDNSNULL)		*out_key_tag		= ntohs(ds->key_tag);
	if (out_algorithm != mDNSNULL)		*out_algorithm		= ds->algorithm;
	if (out_digest_type != mDNSNULL)	*out_digest_type	= ds->digest_type;
	if (out_digest != mDNSNULL)			*out_digest			= ds->digest;
	if (out_digest_length != mDNSNULL)	*out_digest_length	= rdata_length - offsetof(dns_type_ds_t, digest);

	is_valid = mDNStrue;
exit:
	return is_valid;
}

mDNSexport mDNSBool
parse_dns_type_dnskey_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nullable	out_flags,
	mDNSu8 * const		_Nullable	out_protocol,
	mDNSu8 * const		_Nullable	out_algorithm,
	mDNSu16 * const		_Nullable	out_public_key_length,
	mDNSu8 * _Nonnull * const _Nullable out_public_key) {

	mDNSBool is_valid = mDNSfalse;
	dns_type_dnskey_t *dnskey = (dns_type_dnskey_t *)rdata;
	require_action_quiet(rdata_length > offsetof(dns_type_dnskey_t, public_key), exit, is_valid = mDNSfalse;
		log_debug("DNSKEY record parsing failed because of incorrect rdata length - rdata length: %u", rdata_length));

	if (out_flags != mDNSNULL)				*out_flags				= ntohs(dnskey->flags);
	if (out_protocol != mDNSNULL)			*out_protocol			= dnskey->protocol;
	if (out_algorithm != mDNSNULL)			*out_algorithm			= dnskey->algorithm;
	if (out_public_key != mDNSNULL)			*out_public_key			= dnskey->public_key;
	if (out_public_key_length != mDNSNULL)	*out_public_key_length	= rdata_length - offsetof(dns_type_dnskey_t, public_key);

	is_valid = mDNStrue;
exit:
	return is_valid;
}

mDNSexport mDNSBool
parse_dns_type_rrsig_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nullable	out_type_covered,
	mDNSu8 * const		_Nullable	out_algorithm,
	mDNSu8 * const		_Nullable	out_labels,
	mDNSu32 * const		_Nullable	out_original_ttl,
	mDNSu32 * const		_Nullable	out_signature_expiration,
	mDNSu32 * const		_Nullable	out_signature_inception,
	mDNSu16 * const		_Nullable	out_key_tag,
	mDNSu16 * const		_Nullable	out_signature_length,
	mDNSu8 * _Nonnull * const _Nullable out_signer_name,
	mDNSu8 * _Nonnull * const _Nullable out_signature) {

	mDNSBool 			is_valid 			= mDNSfalse;
	dns_type_rrsig_t *	rrsig				= (dns_type_rrsig_t *)rdata;
	mDNSu16				signer_name_length	= DomainNameLengthLimit((const domainname *)rrsig->signer_name, rdata + rdata_length);
	require_action_quiet(signer_name_length != MAX_DOMAIN_NAME + 1, exit, is_valid = mDNSfalse;
		log_debug("RRSIG record parsing failed, because the signer name length goes out of RRSIG rdata"));
	require_action_quiet(rdata_length > offsetof(dns_type_rrsig_t, signer_name) + signer_name_length, exit,
		is_valid = mDNSfalse;
		log_debug("RRSIG record parsing failed because of incorrect rdata length - rdata length: %u", rdata_length));

	if (out_type_covered != mDNSNULL)			*out_type_covered			= ntohs(rrsig->type_covered);
	if (out_algorithm != mDNSNULL)				*out_algorithm				= rrsig->algorithm;
	if (out_labels != mDNSNULL)					*out_labels					= rrsig->labels;
	if (out_original_ttl != mDNSNULL)			*out_original_ttl			= ntohl(rrsig->original_TTL);
	if (out_signature_expiration != mDNSNULL)	*out_signature_expiration	= ntohl(rrsig->signature_expiration);
	if (out_signature_inception != mDNSNULL)	*out_signature_inception	= ntohl(rrsig->signature_inception);
	if (out_key_tag != mDNSNULL)				*out_key_tag				= ntohs(rrsig->key_tag);
	if (out_signer_name != mDNSNULL)			*out_signer_name			= rrsig->signer_name;
	if (out_signature != mDNSNULL)				*out_signature				= (mDNSu8 * const)rdata + offsetof(dns_type_rrsig_t, signer_name) + signer_name_length;
	if (out_signature_length != mDNSNULL)		*out_signature_length		= rdata_length - offsetof(dns_type_rrsig_t, signer_name) - signer_name_length;

	is_valid = mDNStrue;
exit:
	return is_valid;
}

mDNSexport mDNSBool
parse_dns_type_nsec_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nonnull	out_type_bit_maps_length,
	mDNSu8 * _Nonnull * const _Nullable out_next_domain_name,
	mDNSu8 * _Nonnull * const _Nullable out_type_bit_maps) {

	mDNSBool is_valid 				= mDNSfalse;
	dns_type_nsec_t *nsec			= (dns_type_nsec_t *)rdata;
	mDNSu16 next_domain_name_length = DomainNameLengthLimit((const domainname *)nsec->next_domain_name, rdata + rdata_length);
	require_action_quiet(next_domain_name_length != MAX_DOMAIN_NAME + 1 && rdata_length > next_domain_name_length, exit,
		is_valid = mDNSfalse;
		log_debug("NSEC record parsing failed because of incorrect rdata length - rdata length: %u", rdata_length));

	if (out_next_domain_name != mDNSNULL)		*out_next_domain_name		= nsec->next_domain_name;
	if (out_type_bit_maps != mDNSNULL)			*out_type_bit_maps			= (mDNSu8 *)rdata + next_domain_name_length;
	if (out_type_bit_maps_length != mDNSNULL)	*out_type_bit_maps_length	= rdata_length - next_domain_name_length;

	is_valid = mDNStrue;
exit:
	return is_valid;
}

mDNSexport mDNSBool
parse_dns_type_nsec3_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu8 * const		_Nullable	out_hash_algorithm,
	mDNSu8 * const		_Nullable	out_flags,
	mDNSu16 * const		_Nullable	out_iterations,
	mDNSu8 * const		_Nullable	out_salt_length,
	mDNSu8 * const		_Nullable	out_hash_length,
	mDNSu16 * const		_Nullable	out_type_bit_maps_length,
	mDNSu8 * _Nonnull * const _Nullable out_salt,
	mDNSu8 * _Nonnull * const _Nullable out_next_hashed_owner_name,
	mDNSu8 * _Nonnull * const _Nullable out_type_bit_maps) {

	mDNSBool is_valid = mDNSfalse;

	dns_type_nsec3_t *nsec3 = (dns_type_nsec3_t *)rdata;

	if (out_hash_algorithm != mDNSNULL)			*out_hash_algorithm			= nsec3->hash_algorithm;
	if (out_flags != mDNSNULL)					*out_flags					= nsec3->flags;
	if (out_iterations != mDNSNULL)				*out_iterations				= ntohs(nsec3->iterations);
	if (out_salt_length != mDNSNULL)			*out_salt_length			= nsec3->salt_length;
	if (out_salt != mDNSNULL)					*out_salt					= nsec3->salt;
	require_action_quiet(rdata_length > offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length, exit, is_valid = mDNSfalse);
	if (out_hash_length != mDNSNULL)			*out_hash_length			= *((mDNSu8 *)rdata + offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length);
	require_action_quiet(rdata_length > offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length + *out_hash_length + 1, exit, is_valid = mDNSfalse);
	if (out_next_hashed_owner_name != mDNSNULL) *out_next_hashed_owner_name = (mDNSu8 *)rdata + offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length + 1;
	if (out_type_bit_maps_length != mDNSNULL)	*out_type_bit_maps_length	= rdata_length - (offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length + *out_hash_length + 1);
	if (out_type_bit_maps != mDNSNULL)			*out_type_bit_maps			= (mDNSu8 *)rdata + offsetof(dns_type_nsec3_t, salt) + nsec3->salt_length + *out_hash_length + 1;

	is_valid = mDNStrue;
exit:
	if (!is_valid) {
		log_debug("NSEC3 record parsing failed because of incorrect rdata length - rdata length: %u", rdata_length);
	}
	return is_valid;
}

mDNSexport mDNSu16
get_covered_type_of_dns_type_rrsig_t(const void * const _Nonnull rdata) {
	mDNSu16 type_covered = ntohs(((dns_type_rrsig_t *)rdata)->type_covered);
	return type_covered;
}

//======================================================================================================================
//	dnssec_rr_t parse functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_rr_t
//======================================================================================================================

mDNSexport void
initialize_dnssec_rr_t(dnssec_rr_t * const _Nonnull dnssec_rr, ResourceRecord * const _Nonnull rr) {
	dnssec_rr->rr_type		= rr->rrtype;
	dnssec_rr->rr_class		= rr->rrclass;
	dnssec_rr->rdata_length = rr->rdlength;
	dnssec_rr->name_hash	= rr->namehash;
	dnssec_rr->rdata_hash	= rr->rdatahash;

	memcpy(dnssec_rr->name.c, rr->name->c, DomainNameLength(rr->name));

	dnssec_rr->rdata = rr->rdata->u.data;
	dnssec_rr->rr = rr;
}

//======================================================================================================================
//	unintialize_dnssec_rr_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_rr_t(dnssec_rr_t * const _Nonnull dnssec_rr) {
	(void)dnssec_rr;
}

//======================================================================================================================
//	equal_dnssec_rr_t
//======================================================================================================================

mDNSexport mDNSBool
equal_dnssec_rr_t(const dnssec_rr_t * const _Nonnull left, const dnssec_rr_t * const _Nonnull right) {
	return resource_records_equal(left->rr_type, right->rr_type, left->rr_class, right->rr_class,
				left->rdata_length, right->rdata_length, left->name_hash, right->name_hash, left->rdata_hash, right->rdata_hash,
				left->name.c, right->name.c, left->rdata, right->rdata);
}

//======================================================================================================================
//	print_dnssec_rr_t
//======================================================================================================================

mDNSexport void
print_dnssec_rr_t(const dnssec_rr_t * const _Nonnull dnssec_rr, mDNSu8 num_of_tabs) {
	char *	rdata_base64	= mDNSNULL;

	log_debug(TAB_STR PRI_DM_NAME " " PUB_S ":", TAB_PARAM(num_of_tabs),
		DM_NAME_PARAM(&dnssec_rr->name), DNS_TYPE_STR(dnssec_rr->rr_type));

	num_of_tabs += 1;
	rdata_base64 = base_n_encode(DNSSEC_BASE_64, dnssec_rr->rdata, dnssec_rr->rdata_length);

	log_debug(TAB_STR "Name Hash: %u, Rdata Hash: %u, Rdata Length: %u, Rdata: " BASE64_STR, TAB_PARAM(num_of_tabs),
		dnssec_rr->name_hash, dnssec_rr->rdata_hash, dnssec_rr->rdata_length, BASE64_PARAM(rdata_base64));

	free(rdata_base64);
}

//======================================================================================================================
//	dnssec_original_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_original_t
//======================================================================================================================

mDNSexport void
initialize_dnssec_original_t(
	dnssec_original_t * const		_Nonnull	original,
	ResourceRecord * const			_Nonnull	rr,
	const mDNSBool								answer_from_cache,
	const DNSServiceErrorType					dns_error,
	const QC_result								qc_result) {

	initialize_dnssec_rr_t(&original->dnssec_rr, rr);

	original->answer_from_cache = answer_from_cache;
	original->dns_error			= dns_error;
	original->qc_result			= qc_result;
}

//======================================================================================================================
//	uninitialize_dnssec_original_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_original_t(dnssec_original_t * const _Nonnull original) {
	uninitialize_dnssec_rr_t(&original->dnssec_rr);
}

//======================================================================================================================
//	print_dnssec_original_t
//======================================================================================================================

mDNSexport void
print_dnssec_original_t(const dnssec_original_t * const _Nonnull original, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR PUB_S
		"DNS Error: " PUB_S
		", QC Result: %u",
		TAB_PARAM(num_of_tabs),
		original->answer_from_cache ? "Answer from cache, " : "",
		mStatusDescription(original->dns_error),
		original->qc_result);

	print_dnssec_rr_t(&original->dnssec_rr, num_of_tabs);
}

//======================================================================================================================
//	dnssec_ds_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_cname_t
//======================================================================================================================

mDNSexport void
initialize_dnssec_cname_t(dnssec_cname_t * const _Nonnull cname, ResourceRecord * const _Nonnull rr) {
	initialize_dnssec_rr_t(&cname->dnssec_rr, rr);
	parsse_dns_type_cname_t(rr->rdata->u.data, &cname->cname);
}

//======================================================================================================================
//	uninitialize_dnssec_cname_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_cname_t(dnssec_cname_t * const _Nonnull cname) {
	uninitialize_dnssec_rr_t(&cname->dnssec_rr);
}

//======================================================================================================================
//	print_dnssec_cname_t
//======================================================================================================================

mDNSexport void
print_dnssec_cname_t(const dnssec_cname_t * const _Nonnull cname, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR "CNAME: " PRI_DM_NAME, TAB_PARAM(num_of_tabs), DM_NAME_PARAM((domainname *)cname->cname));
}

//======================================================================================================================
//	dnssec_ds_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_ds_t
//======================================================================================================================

mDNSexport mDNSBool
initialize_dnssec_ds_t(dnssec_ds_t * const _Nonnull ds, ResourceRecord * const _Nonnull rr) {
	mDNSBool is_valid = mDNSfalse;

	initialize_dnssec_rr_t(&ds->dnssec_rr, rr);
	is_valid = parse_dns_type_ds_t(ds->dnssec_rr.rdata, ds->dnssec_rr.rdata_length, &ds->key_tag, &ds->algorithm, &ds->digest_type,
		&ds->digest_length, &ds->digest);

	return is_valid;
}

//======================================================================================================================
//	initialize_dnssec_ds_t
//======================================================================================================================
mDNSexport mDNSBool
equals_dnssec_ds_t(const dnssec_ds_t * const left, const dnssec_ds_t * const right) {
	if (left->key_tag		!= right->key_tag)			return mDNSfalse;
	if (left->algorithm		!= right->algorithm)		return mDNSfalse;
	if (left->digest_type	!= right->digest_type)		return mDNSfalse;
	if (left->digest_length != right->digest_length)	return mDNSfalse;
	if (memcmp(left->digest, right->digest, left->digest_length) != 0) return mDNSfalse;

	return mDNStrue;
}

//======================================================================================================================
//	uninitialize_dnssec_ds_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_ds_t(dnssec_ds_t * const _Nonnull ds) {
	uninitialize_dnssec_rr_t(&ds->dnssec_rr);
}

//======================================================================================================================
//	print_dnssec_ds_t
//======================================================================================================================

mDNSexport void
print_dnssec_ds_t(const dnssec_ds_t * const _Nonnull ds, mDNSu8 num_of_tabs) {
	char *digest_base64 = base_n_encode(DNSSEC_BASE_64, ds->digest, ds->digest_length);

	log_debug(TAB_STR "Key Tag: %u, Algorithm: " PUB_S ", Digest Type: " PUB_S ", Digest Length: %u, Digest: " BASE64_STR, TAB_PARAM(num_of_tabs),
		ds->key_tag,
		dnssec_algorithm_value_to_string(ds->algorithm),
		dnssec_digest_type_value_to_string(ds->digest_type),
		ds->digest_length,
		BASE64_PARAM(digest_base64));

	free(digest_base64);
}

//======================================================================================================================
//	dnssec_dnskey_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_dnskey_t
//======================================================================================================================

mDNSexport mDNSBool
initialize_dnssec_dnskey_t(dnssec_dnskey_t * const _Nonnull dnskey, ResourceRecord * const _Nonnull rr) {
	mDNSBool is_valid = mDNSfalse;

	initialize_dnssec_rr_t(&dnskey->dnssec_rr, rr);

	is_valid = parse_dns_type_dnskey_t(dnskey->dnssec_rr.rdata, dnskey->dnssec_rr.rdata_length, &dnskey->flags,
		&dnskey->protocol, &dnskey->algorithm, &dnskey->public_key_length, &dnskey->public_key);
	require_quiet(is_valid, exit);

	dnskey->key_tag = calculate_key_tag(dnskey->dnssec_rr.rdata, dnskey->dnssec_rr.rdata_length, dnskey->algorithm);

	is_valid = mDNStrue;
exit:
	return is_valid;
}

//======================================================================================================================
//	uninitialize_dnssec_dnskey_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_dnskey_t(dnssec_dnskey_t * const _Nonnull dnskey) {
	uninitialize_dnssec_rr_t(&dnskey->dnssec_rr);
}

//======================================================================================================================
//	uninitialize_dnssec_dnskey_t
//======================================================================================================================

mDNSexport mDNSBool
equals_dnssec_dnskey_t(const dnssec_dnskey_t * const left, const dnssec_dnskey_t * const right) {
	if (left->flags				!= right->flags)				return mDNSfalse;
	if (left->protocol			!= right->protocol)				return mDNSfalse;
	if (left->algorithm			!= right->algorithm)			return mDNSfalse;
	if (left->key_tag			!= right->key_tag)				return mDNSfalse;
	if (left->public_key_length != right->public_key_length)	return mDNSfalse;
	if (memcmp(left->public_key, right->public_key, left->public_key_length) != 0)	return mDNSfalse;

	return mDNStrue;
}

//======================================================================================================================
//	print_dnssec_dnskey_t
//======================================================================================================================

mDNSexport void
print_dnssec_dnskey_t(const dnssec_dnskey_t * const _Nonnull dnskey, mDNSu8 num_of_tabs) {
	char *public_key_base64 = base_n_encode(DNSSEC_BASE_64, dnskey->public_key, dnskey->public_key_length);
	char flags_string[64]; // 64 is big enough to hold all flags

	log_debug(TAB_STR "Flags: " PUB_S ", Protocol: %u, Algorithm: " PUB_S ", Ket Tag: %u" ", Public Key Length: %u, Public Key: " BASE64_STR , TAB_PARAM(num_of_tabs),
		dnssec_dnskey_flags_to_string(dnskey->flags, flags_string, sizeof(flags_string)), dnskey->protocol,
		dnssec_algorithm_value_to_string(dnskey->algorithm), dnskey->key_tag, dnskey->public_key_length, BASE64_PARAM(public_key_base64));

	free(public_key_base64);
}

//======================================================================================================================
//	dnssec_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_rrsig_t
//======================================================================================================================

mDNSexport mDNSBool
initialize_dnssec_rrsig_t(dnssec_rrsig_t * const _Nonnull rrsig, ResourceRecord * const _Nonnull rr) {
	mDNSBool is_valid = mDNSfalse;

	initialize_dnssec_rr_t(&rrsig->dnssec_rr, rr);
	is_valid = parse_dns_type_rrsig_t(rrsig->dnssec_rr.rdata, rrsig->dnssec_rr.rdata_length, &rrsig->type_covered,
		&rrsig->algorithm, &rrsig->labels, &rrsig->original_TTL, &rrsig->signature_expiration,
		&rrsig->signature_inception, &rrsig->key_tag, &rrsig->signature_length, &rrsig->signer_name, &rrsig->signature);

	return is_valid;
}

//======================================================================================================================
//	uninitialize_dnssec_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_rrsig_t(dnssec_rrsig_t * const _Nonnull rrsig) {
	// rrsig != mDNSNULL;
	uninitialize_dnssec_rr_t(&rrsig->dnssec_rr);
}

//======================================================================================================================
//	print_dnssec_rrsig_t
//======================================================================================================================

mDNSexport void
print_dnssec_rrsig_t(const dnssec_rrsig_t * const _Nonnull rrsig, mDNSu8 num_of_tabs) {
	char	expiration_date_string[32]; // 32 is big enough to hold "1970-01-01 00:00:00-0800"
	char	inception_date_string[32];
	char *	signature_base64 = base_n_encode(DNSSEC_BASE_64, rrsig->signature, rrsig->signature_length);

	log_debug(TAB_STR
		"Type Covered: " PUB_S
		", Algorithm: " PUB_S
		", Labels: %u"
		", Original TTL: %u"
		", Signature Expiration: " PRI_S
		", Signature Inception: " PRI_S
		", Key Tag: %u"
		", Signature Length: %u"
		", Signer Name: " PRI_DM_NAME
		", Signature: " BASE64_STR,
		TAB_PARAM(num_of_tabs),
		DNS_TYPE_STR(rrsig->type_covered),
		dnssec_algorithm_value_to_string(rrsig->algorithm),
		rrsig->labels,
		rrsig->original_TTL,
		dnssec_epoch_time_to_date_string(rrsig->signature_expiration, expiration_date_string, sizeof(expiration_date_string)),
		dnssec_epoch_time_to_date_string(rrsig->signature_inception, inception_date_string, sizeof(inception_date_string)),
		rrsig->key_tag,
		rrsig->signature_length,
		DM_NAME_PARAM((domainname *)rrsig->signer_name),
		BASE64_PARAM(signature_base64));

	free(signature_base64);
}

//======================================================================================================================
//	dnssec_nsec_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_nsec_t
//======================================================================================================================

mDNSexport mDNSBool
initialize_dnssec_nsec_t(dnssec_nsec_t * const _Nonnull nsec, ResourceRecord * const _Nonnull rr) {
	mDNSBool is_valid = mDNSfalse;

	initialize_dnssec_rr_t(&nsec->dnssec_rr, rr);
	is_valid = parse_dns_type_nsec_t(nsec->dnssec_rr.rdata, nsec->dnssec_rr.rdata_length, &nsec->type_bit_maps_length, &nsec->next_domain_name, &nsec->type_bit_maps);
	require_quiet(is_valid, exit);
	nsec->exist_domain_name = nsec->dnssec_rr.name.c;

	is_valid = mDNStrue;
exit:
	return is_valid;
}

//======================================================================================================================
//	uninitialize_dnssec_nsec_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_nsec_t(dnssec_nsec_t * const _Nonnull nsec) {
	uninitialize_dnssec_rr_t(&nsec->dnssec_rr);
}

//======================================================================================================================
//	print_dnssec_nsec_t
//======================================================================================================================

mDNSexport void
print_dnssec_nsec_t(const dnssec_nsec_t * const _Nonnull nsec, mDNSu8 num_of_tabs) {
	char string_buffer[1024];

	log_debug(TAB_STR
		"Domain Name: " PRI_DM_NAME
		", Next Domain Name: " PRI_DM_NAME
		", Type Bit Maps Length: %u"
		", Type Bit Maps: " PUB_S,
		TAB_PARAM(num_of_tabs),
		DM_NAME_PARAM((domainname *)nsec->exist_domain_name),
		DM_NAME_PARAM((domainname *)nsec->next_domain_name),
		nsec->type_bit_maps_length,
		type_bit_map_to_cstring(nsec->type_bit_maps, nsec->type_bit_maps_length, string_buffer, sizeof(string_buffer)));
}

mDNSlocal char *
type_bit_map_to_cstring(
	const mDNSu8 * const _Nonnull	bit_map,
	const mDNSu16					map_length,
	char *							buffer,
	mDNSu32							buffer_length) {

	const mDNSu8 *			ptr						= bit_map;
	const mDNSu8 * const	ptr_limit				= ptr + map_length;
	char *					buffer_ptr				= buffer;
	const char * const		buffer_limit			= buffer + buffer_length - 4;

	for (; ptr < ptr_limit; ptr += 2 + *(ptr + 1)) {
		const mDNSu8	window_index			= *ptr;
		const mDNSu8	block_bit_map_length	= *(ptr + 1);
		const mDNSu32	bit_count				= block_bit_map_length * 8;
		const mDNSu8 *	current_block			= ptr + 2;

		for (mDNSu32 i = 0; i < bit_count; i++) {
			const mDNSu8 mask	= 1 << (7 - (i % 8));
			mDNSBool bit_set	= (current_block[i / 8] & mask) != 0;
			if (bit_set) {
				const char * const dns_type_cstring = DNS_TYPE_STR(window_index * 256 + i);
				const mDNSs32 bytes_will_be_written = snprintf(buffer_ptr, buffer_limit - buffer_ptr, "%s ", dns_type_cstring);
				if (bytes_will_be_written + buffer_ptr >= buffer_limit) {
					snprintf(buffer_ptr, buffer_limit - buffer_ptr + 4, "...");
					return buffer;
				}
				buffer_ptr += bytes_will_be_written;
			}
		}
	}

	return buffer;
}

//======================================================================================================================
//	dnssec_nsec3_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_nsec3_t
//======================================================================================================================

mDNSexport mDNSBool
initialize_dnssec_nsec3_t(dnssec_nsec3_t * const _Nonnull nsec3, ResourceRecord * const _Nonnull rr) {
	mDNSBool is_valid = mDNSfalse;

	initialize_dnssec_rr_t(&nsec3->dnssec_rr, rr);
	is_valid = parse_dns_type_nsec3_t(nsec3->dnssec_rr.rdata, nsec3->dnssec_rr.rdata_length, &nsec3->hash_algorithm, &nsec3->flags, &nsec3->iterations,
		&nsec3->salt_length, &nsec3->hash_length, &nsec3->type_bit_maps_length, &nsec3->salt,
		&nsec3->next_hashed_owner_name, &nsec3->type_bit_maps);
	require_action_quiet(is_valid, exit, is_valid = mDNSfalse);

	nsec3->next_hashed_owner_name_b32 = base_n_encode(DNSSEC_BASE_32_HEX, nsec3->next_hashed_owner_name, nsec3->hash_length);
	nsec3->next_hashed_owner_name_b32_length = strlen(nsec3->next_hashed_owner_name_b32);

	is_valid = mDNStrue;
exit:
	return is_valid;
}

//======================================================================================================================
//	uninitialize_dnssec_nsec3_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_nsec3_t(dnssec_nsec3_t * const _Nonnull nsec3) {
	uninitialize_dnssec_rr_t(&nsec3->dnssec_rr);
	free(nsec3->next_hashed_owner_name_b32);
}

//======================================================================================================================
//	print_dnssec_nsec3_t
//======================================================================================================================

mDNSexport void
print_dnssec_nsec3_t(const dnssec_nsec3_t * const _Nonnull nsec3, mDNSu8 num_of_tabs) {
	char	flags_string[32]; // 32 is big enough to hold the flag string
	char *	salt_base64 = base_n_encode(DNSSEC_BASE_64, nsec3->salt, nsec3->salt_length);
	char	string_buffer[1024];

	log_debug(TAB_STR
		"Hash Algorithm: " PUB_S
		", Flags: " PUB_S
		", Iterations: %u"
		", Salt Length: %u"
		", Hash Length: %u"
		", Type Bit Maps Length: %u"
		", Salt: " BASE64_STR
		", Next Hash Owner Name: " PRI_S
		", Type Bit Maps: " PUB_S,
		TAB_PARAM(num_of_tabs),
		dnssec_algorithm_value_to_string(nsec3->hash_algorithm),
		dnssec_nsec3_flags_to_string(nsec3->flags, flags_string, sizeof(flags_string)),
		nsec3->iterations,
		nsec3->salt_length,
		nsec3->hash_length,
		nsec3->type_bit_maps_length,
		BASE64_PARAM(salt_base64),
		nsec3->next_hashed_owner_name_b32,
		type_bit_map_to_cstring(nsec3->type_bit_maps, nsec3->type_bit_maps_length, string_buffer, sizeof(string_buffer)));

	free(salt_base64);
}

//======================================================================================================================
//	nsecs_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_nsecs_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
initialize_nsecs_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs) {
	list_init(&nsecs->nsec_and_rrsigs_same_name, sizeof(one_nsec_with_rrsigs_t));
	list_init(&nsecs->wildcard_answers, sizeof(dnssec_rr_t));
	list_init(&nsecs->wildcard_rrsigs, sizeof(dnssec_rrsig_t));
	nsecs->negative_rr = mDNSNULL;

	return mStatus_NoError;
}

//======================================================================================================================
//	uninitialize_nsecs_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_nsecs_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs) {
	for (list_node_t * one_nsec_with_rrsigs_node = list_get_first(&nsecs->nsec_and_rrsigs_same_name);
		 !list_has_ended(&nsecs->nsec_and_rrsigs_same_name, one_nsec_with_rrsigs_node);
		 one_nsec_with_rrsigs_node = list_next(one_nsec_with_rrsigs_node)) {

		one_nsec_with_rrsigs_t * one_nsec_with_rrsigs = (one_nsec_with_rrsigs_t *)one_nsec_with_rrsigs_node->data;
		uninitialize_one_nsec_with_rrsigs_t(one_nsec_with_rrsigs);
	}
	list_uninit(&nsecs->nsec_and_rrsigs_same_name);
	for (list_node_t * dnssec_rr_node = list_get_first(&nsecs->wildcard_answers);
		 !list_has_ended(&nsecs->wildcard_answers, dnssec_rr_node);
		 dnssec_rr_node = list_next(dnssec_rr_node)) {

		dnssec_rr_t * dnssec_rr = (dnssec_rr_t *)dnssec_rr_node->data;
		uninitialize_dnssec_rr_t(dnssec_rr);
	}
	list_uninit(&nsecs->wildcard_answers);
	for (list_node_t * dnssec_rrsig_node = list_get_first(&nsecs->wildcard_rrsigs);
		 !list_has_ended(&nsecs->wildcard_rrsigs, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&nsecs->wildcard_rrsigs);
	nsecs->negative_rr = mDNSNULL;
}

//======================================================================================================================
//	print_nsecs_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_nsecs_with_rrsig_t(const nsecs_with_rrsig_t * const _Nonnull nsecs, mDNSu8 num_of_tabs) {

	const list_t * list_ptr;

	list_ptr = &nsecs->wildcard_answers;
	log_debug(TAB_STR "Wildcard:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const dnssec_rr_t * const dnssec_rr = (dnssec_rr_t *) node->data;
		print_dnssec_rr_t(dnssec_rr, num_of_tabs + 1);
	}

	list_ptr = &nsecs->wildcard_rrsigs;
	log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const dnssec_rrsig_t * const dnssec_rrsig = (dnssec_rrsig_t *) node->data;
		print_dnssec_rrsig_t(dnssec_rrsig, num_of_tabs + 1);
	}

	list_ptr = &nsecs->nsec_and_rrsigs_same_name;
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const one_nsec_with_rrsigs_t * const one_nsec = (const one_nsec_with_rrsigs_t * const)node->data;
		log_debug(TAB_STR "Owner Name:" PRI_DM_NAME, TAB_PARAM(num_of_tabs), DM_NAME_PARAM((const domainname *)one_nsec->owner_name));

		log_debug(TAB_STR "NSEC:", TAB_PARAM(num_of_tabs));
		print_dnssec_nsec_t(&one_nsec->nsec_record, num_of_tabs + 1);

		log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
		for (list_node_t *rrsig_node = list_get_first(&one_nsec->rrsig_records);
			 !list_has_ended(&one_nsec->rrsig_records, rrsig_node);
			 rrsig_node = list_next(rrsig_node)) {
			const dnssec_rrsig_t * const rrsig = (const dnssec_rrsig_t * const)rrsig_node->data;
			print_dnssec_rrsig_t(rrsig, num_of_tabs + 1);
		}
	}
}

# pragma mark - one_nsec_with_rrsigs_t functions



# pragma mark initialize_one_nsec_with_rrsigs_t
mDNSexport mDNSBool
initialize_one_nsec_with_rrsigs_t(one_nsec_with_rrsigs_t * const one_nsec_with_rrsigs, ResourceRecord * const rr) {
	mDNSBool is_valid = mDNSfalse;

	is_valid = initialize_dnssec_nsec_t(&one_nsec_with_rrsigs->nsec_record, rr);
	require_quiet(is_valid, exit);
	one_nsec_with_rrsigs->owner_name = one_nsec_with_rrsigs->nsec_record.dnssec_rr.name.c;
	list_init(&one_nsec_with_rrsigs->rrsig_records, sizeof(dnssec_rrsig_t));

	is_valid = mDNStrue;
exit:
	return is_valid;
}

# pragma mark uninitialize_one_nsec_with_rrsigs_t
mDNSexport void
uninitialize_one_nsec_with_rrsigs_t(one_nsec_with_rrsigs_t * const	_Nonnull one_nsec_with_rrsigs) {
	for (list_node_t * dnssec_rrsig_node = list_get_first(&one_nsec_with_rrsigs->rrsig_records);
		 !list_has_ended(&one_nsec_with_rrsigs->rrsig_records, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&one_nsec_with_rrsigs->rrsig_records);
	uninitialize_dnssec_nsec_t(&one_nsec_with_rrsigs->nsec_record);
}
//======================================================================================================================
//	nsec3s_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_nsec3s_with_rrsig_t
//======================================================================================================================

mDNSexport mStatus
initialize_nsec3s_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s) {
	list_init(&nsec3s->nsec3_and_rrsigs_same_name, sizeof(one_nsec3_with_rrsigs_t));
	list_init(&nsec3s->wildcard_answers, sizeof(dnssec_rr_t));
	list_init(&nsec3s->wildcard_rrsigs, sizeof(dnssec_rrsig_t));
	nsec3s->negative_rr = mDNSNULL;

	return mStatus_NoError;
}

//======================================================================================================================
//	uninitialize_nsec3s_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_nsec3s_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s) {
	for (list_node_t * one_nsec3_with_rrsigs_node = list_get_first(&nsec3s->nsec3_and_rrsigs_same_name);
		 !list_has_ended(&nsec3s->nsec3_and_rrsigs_same_name, one_nsec3_with_rrsigs_node);
		 one_nsec3_with_rrsigs_node = list_next(one_nsec3_with_rrsigs_node)) {

		one_nsec3_with_rrsigs_t * one_nsec3_with_rrsigs = (one_nsec3_with_rrsigs_t *)one_nsec3_with_rrsigs_node->data;
		uninitialize_one_nsec3_with_rrsigs_t(one_nsec3_with_rrsigs);
	}
	list_uninit(&nsec3s->nsec3_and_rrsigs_same_name);
	for (list_node_t * dnssec_rr_node = list_get_first(&nsec3s->wildcard_answers);
		 !list_has_ended(&nsec3s->wildcard_answers, dnssec_rr_node);
		 dnssec_rr_node = list_next(dnssec_rr_node)) {

		dnssec_rr_t * dnssec_rr = (dnssec_rr_t *)dnssec_rr_node->data;
		uninitialize_dnssec_rr_t(dnssec_rr);
	}
	list_uninit(&nsec3s->wildcard_answers);
	for (list_node_t * dnssec_rrsig_node = list_get_first(&nsec3s->wildcard_rrsigs);
		 !list_has_ended(&nsec3s->wildcard_rrsigs, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&nsec3s->wildcard_rrsigs);
	nsec3s->negative_rr = mDNSNULL;
}

//======================================================================================================================
//	print_nsec3s_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_nsec3s_with_rrsig_t(const nsec3s_with_rrsig_t * const _Nonnull nsec3s, mDNSu8 num_of_tabs) {
	const list_t * list_ptr;

	list_ptr = &nsec3s->wildcard_answers;
	log_debug(TAB_STR "Wildcard:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const dnssec_rr_t * const dnssec_rr = (dnssec_rr_t *) node->data;
		print_dnssec_rr_t(dnssec_rr, num_of_tabs + 1);
	}

	list_ptr = &nsec3s->wildcard_rrsigs;
	log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const dnssec_rrsig_t * const dnssec_rrsig = (dnssec_rrsig_t *) node->data;
		print_dnssec_rrsig_t(dnssec_rrsig, num_of_tabs + 1);
	}

	list_ptr = &nsec3s->nsec3_and_rrsigs_same_name;
	for (list_node_t *node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = list_next(node)) {
		const one_nsec3_with_rrsigs_t * const one_nsec3 = (const one_nsec3_with_rrsigs_t * const)node->data;
		log_debug(TAB_STR "Owner Name:" PRI_DM_NAME, TAB_PARAM(num_of_tabs), DM_NAME_PARAM((const domainname *)one_nsec3->owner_name));

		log_debug(TAB_STR "NSEC3:", TAB_PARAM(num_of_tabs));
		print_dnssec_nsec3_t(&one_nsec3->nsec3_record, num_of_tabs + 1);

		log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
		for (list_node_t *rrsig_node = list_get_first(&one_nsec3->rrsig_records);
			 !list_has_ended(&one_nsec3->rrsig_records, rrsig_node);
			 rrsig_node = list_next(rrsig_node)) {
			const dnssec_rrsig_t * const rrsig = (const dnssec_rrsig_t * const)rrsig_node->data;
			print_dnssec_rrsig_t(rrsig, num_of_tabs + 1);
		}
	}
}

# pragma mark - one_nsec_with_rrsigs_t functions



# pragma mark initialize_one_nsec3_with_rrsigs_t
mDNSexport mDNSBool
initialize_one_nsec3_with_rrsigs_t(
	one_nsec3_with_rrsigs_t * const _Nonnull	one_nsec3_with_rrsigs,
	ResourceRecord * const 			_Nonnull	rr) {

	mDNSBool is_valid = mDNSfalse;

	is_valid = initialize_dnssec_nsec3_t(&one_nsec3_with_rrsigs->nsec3_record, rr);
	require_action_quiet(is_valid, exit, is_valid = mDNSfalse);
	one_nsec3_with_rrsigs->owner_name = one_nsec3_with_rrsigs->nsec3_record.dnssec_rr.name.c;
	list_init(&one_nsec3_with_rrsigs->rrsig_records, sizeof(dnssec_rrsig_t));

	is_valid = mDNStrue;
exit:
	return is_valid;
}

# pragma mark uninitialize_one_nsec3_with_rrsigs_t
mDNSexport void
uninitialize_one_nsec3_with_rrsigs_t(one_nsec3_with_rrsigs_t * const _Nonnull one_nsec3_with_rrsigs) {
	for (list_node_t * dnssec_rrsig_node = list_get_first(&one_nsec3_with_rrsigs->rrsig_records);
		 !list_has_ended(&one_nsec3_with_rrsigs->rrsig_records, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&one_nsec3_with_rrsigs->rrsig_records);
	uninitialize_dnssec_nsec3_t(&one_nsec3_with_rrsigs->nsec3_record);
}

//======================================================================================================================
//	cnames_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_cname_with_rrsig_t
//======================================================================================================================

mDNSexport void
initialize_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cname) {
	list_init(&cname->cname_records, sizeof(dnssec_cname_t));
	list_init(&cname->rrsig_records, sizeof(dnssec_rrsig_t));
}

//======================================================================================================================
//	uninitialize_cname_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cname) {
	for (list_node_t * dnssec_cname_node = list_get_first(&cname->cname_records);
		 !list_has_ended(&cname->cname_records, dnssec_cname_node);
		 dnssec_cname_node = list_next(dnssec_cname_node)) {

		dnssec_cname_t * dnssec_cname = (dnssec_cname_t *)dnssec_cname_node->data;
		uninitialize_dnssec_cname_t(dnssec_cname);
	}
	list_uninit(&cname->cname_records);
	for (list_node_t *dnssec_rrsig_node = list_get_first(&cname->rrsig_records);
		 !list_has_ended(&cname->rrsig_records, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&cname->rrsig_records);
}

//======================================================================================================================
//	print_cname_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_cname_with_rrsig_t(const cnames_with_rrsig_t * const _Nonnull cnames, mDNSu8 num_of_tabs) {
	const list_t * const cname_records = &cnames->cname_records;
	const list_t * const rrsig_records = &cnames->rrsig_records;


	log_debug(TAB_STR "CNAME:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(cname_records); !list_has_ended(cname_records, node); node = list_next(node)) {
		dnssec_cname_t *cname = (dnssec_cname_t *)node->data;
		print_dnssec_cname_t(cname, num_of_tabs + 1);
	}

	log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(rrsig_records); !list_has_ended(rrsig_records, node); node = list_next(node)) {
		dnssec_rrsig_t *rrsig = (dnssec_rrsig_t *)node->data;
		print_dnssec_rrsig_t(rrsig, num_of_tabs + 1);
	}
}

//======================================================================================================================
//	response_type_t functions
//======================================================================================================================

mDNSexport const char * _Nonnull
response_type_value_to_string(response_type_t type) {
	static const char * const string_table[] =
	{
		"Unknown Response",		// 0
		"Original Response",	// 1
		"CNAME Response",		// 2
		"NSEC Response",		// 3
		"NSEC3 Response"		// 4
	};
	if (type >= sizeof(string_table) / sizeof(char *)) {
		type = 0;
	}

	return string_table[type];
}

//======================================================================================================================
//	originals_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_originals_with_rrsig_t
//======================================================================================================================

mDNSexport void
initialize_originals_with_rrsig_t(originals_with_rrsig_t * const _Nonnull original, const response_type_t type) {
	original->type			= type;

	switch (type) {
		case original_response:
			list_init(&original->u.original.original_records, sizeof(dnssec_original_t));
			list_init(&original->u.original.rrsig_records, sizeof(dnssec_rrsig_t));
			original->u.original.negative_rr = mDNSNULL;
			original->u.original.suppressed_response = mDNSfalse;
			break;
		case cname_response:
			initialize_cname_with_rrsig_t(&original->u.cname_with_rrsig);
			break;
		case nsec_response:
			initialize_nsecs_with_rrsig_t(&original->u.nsecs_with_rrsig);
			break;
		case nsec3_response:
			initialize_nsec3s_with_rrsig_t(&original->u.nsec3s_with_rrsig);
			break;
		default:
			verify(mDNSfalse);
	}
}

//======================================================================================================================
//	uninitialize_originals_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_originals_with_rrsig_t(originals_with_rrsig_t * const _Nonnull original) {
	switch (original->type) {
		case original_response:
			for (list_node_t * dnssec_original_node = list_get_first(&original->u.original.original_records);
				 !list_has_ended(&original->u.original.original_records, dnssec_original_node);
				 dnssec_original_node = list_next(dnssec_original_node)) {

				dnssec_original_t * dnssec_original = (dnssec_original_t *)dnssec_original_node->data;
				uninitialize_dnssec_original_t(dnssec_original);
			}
			list_uninit(&original->u.original.original_records);
			for (list_node_t * dnssec_rrsig_node = list_get_first(&original->u.original.rrsig_records);
				 !list_has_ended(&original->u.original.rrsig_records, dnssec_rrsig_node);
				 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

				dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
				uninitialize_dnssec_rrsig_t(dnssec_rrsig);
			}
			list_uninit(&original->u.original.rrsig_records);
			original->u.original.negative_rr			= mDNSNULL;
			original->u.original.suppressed_response	= mDNSfalse;
			break;
		case cname_response:
			uninitialize_cname_with_rrsig_t(&original->u.cname_with_rrsig);
			break;
		case nsec_response:
			uninitialize_nsecs_with_rrsig_t(&original->u.nsecs_with_rrsig);
			break;
		case nsec3_response:
			uninitialize_nsec3s_with_rrsig_t(&original->u.nsec3s_with_rrsig);
			break;
		default:
			// it is possible that the DNSSEC rquest is stopped we receive any response
			break;
	}
	original->type			= unknown_response;
}

//======================================================================================================================
//	contains_rrsig_in_nsecs_with_rrsig_t
//======================================================================================================================

mDNSlocal mDNSBool
contains_rrsig_in_nsecs_with_rrsig_t(const nsecs_with_rrsig_t * const _Nonnull nsecs) {
	const list_t * const nsec_list = &nsecs->nsec_and_rrsigs_same_name;
	mDNSBool contains_non_empty_rrsig_list = mDNSfalse;
	for (list_node_t *nsec_node = list_get_first(nsec_list);
		 !list_has_ended(nsec_list, nsec_node);
		 nsec_node = list_next(nsec_node)) {
		const one_nsec_with_rrsigs_t * const	one_nsec	= (const one_nsec_with_rrsigs_t * const)nsec_node->data;
		const list_t * const					rrsig_list	= &one_nsec->rrsig_records;
		if (!list_empty(rrsig_list)) {
			contains_non_empty_rrsig_list = mDNStrue;
			break;
		}
	}
	if (!contains_non_empty_rrsig_list) {
		return mDNSfalse;
	}

	return mDNStrue;
}

//======================================================================================================================
//	contains_rrsig_in_nsecs_with_rrsig_t
//======================================================================================================================

mDNSlocal mDNSBool
contains_rrsig_in_nsec3s_with_rrsig_t(const nsec3s_with_rrsig_t * const _Nonnull nsec3s) {
	const list_t * const nsec3_list = &nsec3s->nsec3_and_rrsigs_same_name;
	mDNSBool contains_non_empty_rrsig_list = mDNSfalse;
	for (list_node_t *nsec3_node = list_get_first(nsec3_list);
		 !list_has_ended(nsec3_list, nsec3_node);
		 nsec3_node = list_next(nsec3_node)) {
		const one_nsec3_with_rrsigs_t * const	one_nsec3	= (const one_nsec3_with_rrsigs_t * const)nsec3_node->data;
		const list_t * const					rrsig_list	= &one_nsec3->rrsig_records;
		if (!list_empty(rrsig_list)) {
			contains_non_empty_rrsig_list = mDNStrue;
			break;
		}
	}
	if (!contains_non_empty_rrsig_list) {
		return mDNSfalse;
	}

	return mDNStrue;
}

//======================================================================================================================
//	contains_rrsig_in_originals_with_rrsig_t
//======================================================================================================================

mDNSexport mDNSBool
contains_rrsig_in_originals_with_rrsig_t(const originals_with_rrsig_t * const _Nonnull original) {
	const list_t *rrsig_list;
	const response_type_t type = original->type;

	if (type == original_response || type == cname_response) {
		if (type == original_response) {
			rrsig_list = &original->u.original.rrsig_records;
		} else { // type == cname_response
			rrsig_list = &original->u.cname_with_rrsig.rrsig_records;
		}

		if (rrsig_list == mDNSNULL) {
			log_error("originals_with_rrsig_t has unknown response, it should never heppen");
			return mDNSfalse;
		}

		if (list_empty(rrsig_list)) {
			return mDNSfalse;
		}
	} else if (type == nsec_response) {
		if (!contains_rrsig_in_nsecs_with_rrsig_t(&original->u.nsecs_with_rrsig)) {
			return mDNSfalse;
		}
	} else if (type == nsec3_response) {
		if (!contains_rrsig_in_nsec3s_with_rrsig_t(&original->u.nsec3s_with_rrsig)) {
			return mDNStrue;
		}
	} else {
		log_error("originals_with_rrsig_t has unknown response, it should never heppen");
		return mDNSfalse;
	}

	return mDNStrue;
}

//======================================================================================================================
//	print_originals_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_originals_with_rrsig_t(const originals_with_rrsig_t * const _Nonnull original, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR "Response Type: " PUB_S, TAB_PARAM(num_of_tabs),
			  response_type_value_to_string(original->type));

	switch (original->type) {
		case original_response: {
			const list_t * const original_records	= &original->u.original.original_records;
			const list_t * const rrsig_records		= &original->u.original.rrsig_records;

			log_debug(TAB_STR "Original:", TAB_PARAM(num_of_tabs));
			for (list_node_t *node = list_get_first(original_records); !list_has_ended(original_records, node); node = list_next(node)) {
				dnssec_original_t *dnssec_original = (dnssec_original_t *)node->data;
				print_dnssec_original_t(dnssec_original, num_of_tabs + 1);
			}

			log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
			for (list_node_t *node = list_get_first(rrsig_records); !list_has_ended(rrsig_records, node); node = list_next(node)) {
				dnssec_rrsig_t *dnssec_rrsig = (dnssec_rrsig_t *)node->data;
				print_dnssec_rrsig_t(dnssec_rrsig, num_of_tabs + 1);
			}
		}
			break;
		case cname_response:
			print_cname_with_rrsig_t(&original->u.cname_with_rrsig, num_of_tabs + 1);
			break;
		case nsec_response:
			print_nsecs_with_rrsig_t(&original->u.nsecs_with_rrsig, num_of_tabs + 1);
			break;
		case nsec3_response:
			print_nsec3s_with_rrsig_t(&original->u.nsec3s_with_rrsig, num_of_tabs + 1);
			break;
		case unknown_response:
			log_debug(TAB_STR "Unknown Response", TAB_PARAM(num_of_tabs));
			break;
		default:
			log_debug(TAB_STR "Invalid", TAB_PARAM(num_of_tabs));
			break;
	}
}

//======================================================================================================================
//	dses_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dses_with_rrsig_t
//======================================================================================================================

mDNSexport void
initialize_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull ds, const response_type_t type) {
	ds->type			= type;
	ds->set_completed	= mDNSfalse;

	switch (type) {
		case original_response:
			list_init(&ds->u.original.ds_records, sizeof(dnssec_ds_t));
			list_init(&ds->u.original.rrsig_records, sizeof(dnssec_rrsig_t));
			break;
		case nsec_response:
			initialize_nsecs_with_rrsig_t(&ds->u.nsecs_with_rrsig);
			break;
		case nsec3_response:
			initialize_nsec3s_with_rrsig_t(&ds->u.nsec3s_with_rrsig);
			break;
		default:
			break;
	}
}

//======================================================================================================================
//	uninitialize_dses_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull ds) {
	switch (ds->type) {
		case original_response: {
			list_t * ds_records 	= &ds->u.original.ds_records;
			list_t * rrsig_records	= &ds->u.original.rrsig_records;
			for (list_node_t * dnssec_ds_node = list_get_first(ds_records);
				 !list_has_ended(ds_records, dnssec_ds_node);
				 dnssec_ds_node = list_next(dnssec_ds_node)) {

				dnssec_ds_t * dnssec_ds = (dnssec_ds_t *)dnssec_ds_node->data;
				uninitialize_dnssec_ds_t(dnssec_ds);
			}
			list_uninit(ds_records);
			for (list_node_t * dnssec_rrsig_node = list_get_first(rrsig_records);
				 !list_has_ended(rrsig_records, dnssec_rrsig_node);
				 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

				dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
				uninitialize_dnssec_rrsig_t(dnssec_rrsig);
			}
			list_uninit(rrsig_records);
			break;
		}
		case nsec_response:
			uninitialize_nsecs_with_rrsig_t(&ds->u.nsecs_with_rrsig);
			break;
		case nsec3_response:
			uninitialize_nsec3s_with_rrsig_t(&ds->u.nsec3s_with_rrsig);
			break;
		default:
			break;
	}

	ds->type			= unknown_response;
	ds->set_completed	= mDNSfalse;
}

//======================================================================================================================
//	contains_rrsig_in_dses_with_rrsig_t
//======================================================================================================================

mDNSexport mDNSBool
contains_rrsig_in_dses_with_rrsig_t(const dses_with_rrsig_t * const _Nonnull ds) {
	const response_type_t type = ds->type;
	mDNSBool contains = mDNStrue;

	if (!ds->set_completed) {
		log_error("contains_rrsig_in_dses_with_rrsig_t called with incompleted ds records set");
		contains = mDNSfalse;
		goto exit;
	}

	if (type == original_response) {
		if (list_empty(&ds->u.original.rrsig_records)) {
			contains = mDNSfalse;
			goto exit;
		}
	} else if (type == nsec_response) {
		if (!contains_rrsig_in_nsecs_with_rrsig_t(&ds->u.nsecs_with_rrsig)) {
			contains = mDNSfalse;
			goto exit;
		}
	} else if (type == nsec3_response) {
		if (!contains_rrsig_in_nsec3s_with_rrsig_t(&ds->u.nsec3s_with_rrsig)) {
			contains = mDNSfalse;
			goto exit;
		}
	} else {
		log_error("dses_with_rrsig_t has unknown response, it should never heppen");
		contains = mDNSfalse;
		goto exit;
	}

exit:
	return contains;
}

//======================================================================================================================
//	print_dses_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_dses_with_rrsig_t(const dses_with_rrsig_t * const _Nonnull ds, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR "Response Type: " PUB_S PUB_S, TAB_PARAM(num_of_tabs),
			  response_type_value_to_string(ds->type), ds->set_completed ? ", Set Completed" : "");

	switch (ds->type) {
		case original_response: {
			const list_t * const ds_records		= &ds->u.original.ds_records;
			const list_t * const rrsig_records	= &ds->u.original.rrsig_records;

			log_debug(TAB_STR "DS:", TAB_PARAM(num_of_tabs));
			for (list_node_t *node = list_get_first(ds_records); !list_has_ended(ds_records, node); node = list_next(node)) {
				dnssec_ds_t *dnssec_ds = (dnssec_ds_t *)node->data;
				print_dnssec_ds_t(dnssec_ds, num_of_tabs + 1);
			}

			log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
			for (list_node_t *node = list_get_first(rrsig_records); !list_has_ended(rrsig_records, node); node = list_next(node)) {
				dnssec_rrsig_t *dnssec_rrsig = (dnssec_rrsig_t *)node->data;
				print_dnssec_rrsig_t(dnssec_rrsig, num_of_tabs + 1);
			}
		}
			break;
		case nsec_response:
			print_nsecs_with_rrsig_t(&ds->u.nsecs_with_rrsig, num_of_tabs + 1);
			break;
		case nsec3_response:
			print_nsec3s_with_rrsig_t(&ds->u.nsec3s_with_rrsig, num_of_tabs + 1);
			break;
		case unknown_response:
			log_debug(TAB_STR "Unknown Response", TAB_PARAM(num_of_tabs));
			break;
		default:
			log_debug(TAB_STR "Invalid", TAB_PARAM(num_of_tabs));
			break;
	}
}

//======================================================================================================================
//	dnskeys_with_rrsig_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnskeys_with_rrsig_t
//======================================================================================================================

mDNSexport void
initialize_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskey) {
	dnskey->set_completed = mDNSfalse;

	list_init(&dnskey->dnskey_records, sizeof(dnssec_dnskey_t));
	list_init(&dnskey->rrsig_records, sizeof(dnssec_rrsig_t));
}

//======================================================================================================================
//	uninitialize_dnskeys_with_rrsig_t
//======================================================================================================================

mDNSexport void
uninitialize_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskey) {
	for (list_node_t * dnssec_dnskey_node = list_get_first(&dnskey->dnskey_records);
		 !list_has_ended(&dnskey->dnskey_records, dnssec_dnskey_node);
		 dnssec_dnskey_node = list_next(dnssec_dnskey_node)) {

		dnssec_dnskey_t * dnssec_dnskey = (dnssec_dnskey_t *)dnssec_dnskey_node->data;
		uninitialize_dnssec_dnskey_t(dnssec_dnskey);
	}
	list_uninit(&dnskey->dnskey_records);
	for (list_node_t * dnssec_rrsig_node = list_get_first(&dnskey->rrsig_records);
		 !list_has_ended(&dnskey->rrsig_records, dnssec_rrsig_node);
		 dnssec_rrsig_node = list_next(dnssec_rrsig_node)) {

		dnssec_rrsig_t * dnssec_rrsig = (dnssec_rrsig_t *)dnssec_rrsig_node->data;
		uninitialize_dnssec_rrsig_t(dnssec_rrsig);
	}
	list_uninit(&dnskey->rrsig_records);
	dnskey->set_completed = mDNSfalse;
}

//======================================================================================================================
//	contains_rrsig_in_dnskeys_with_rrsig_t
//======================================================================================================================

mDNSexport mDNSBool
contains_rrsig_in_dnskeys_with_rrsig_t(const dnskeys_with_rrsig_t * const _Nonnull dnskey) {
	mDNSBool		contains	= mDNSfalse;

	verify_action(dnskey->set_completed,
		log_error("contains_rrsig_in_dnskeys_with_rrsig_t called with incompleted dnskey records set"); return mDNSfalse);

	if (list_empty(&dnskey->rrsig_records)) {
		goto exit;
	}

	contains = mDNStrue;
exit:
	return contains;
}

//======================================================================================================================
//	print_dnskeys_with_rrsig_t
//======================================================================================================================

mDNSexport void
print_dnskeys_with_rrsig_t(const dnskeys_with_rrsig_t * const _Nonnull dnskey, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR PUB_S, TAB_PARAM(num_of_tabs),
		dnskey->set_completed ? "Set Completed" : "");

	const list_t * const dnskey_records	= &dnskey->dnskey_records;
	const list_t * const rrsig_records	= &dnskey->rrsig_records;

	log_debug(TAB_STR "DNSKEY:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(dnskey_records); !list_has_ended(dnskey_records, node); node = list_next(node)) {
		dnssec_dnskey_t *dnssec_dnskey = (dnssec_dnskey_t *)node->data;
		print_dnssec_dnskey_t(dnssec_dnskey, num_of_tabs + 1);
	}

	log_debug(TAB_STR "RRSIG:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(rrsig_records); !list_has_ended(rrsig_records, node); node = list_next(node)) {
		dnssec_rrsig_t *dnssec_rrsig = (dnssec_rrsig_t *)node->data;
		print_dnssec_rrsig_t(dnssec_rrsig, num_of_tabs + 1);
	}
}

//======================================================================================================================
//	original_request_parameters_t functions
//======================================================================================================================

//======================================================================================================================
//	print_original_request_parameters_t
//======================================================================================================================

mDNSexport void
print_original_request_parameters_t(const original_request_parameters_t * const _Nonnull parameters, mDNSu8 num_of_tabs) {
	char uuid_hex[UUID_SIZE * 4];
	char *ptr	= uuid_hex;
	char *limit = ptr + sizeof(uuid_hex);

	for (size_t i = 0 ; i < sizeof(parameters->uuid); i++) {
		mDNSu32 num_of_char_write = snprintf(ptr, limit - ptr, "%x", parameters->uuid[i]);
		if (num_of_char_write + ptr > limit) {
			break;
		}
		ptr += num_of_char_write;
	}

	log_debug(TAB_STR "Original Parameters:", TAB_PARAM(num_of_tabs));
	log_debug(TAB_STR
		"Rquest ID: %u"
		", Q Name: " PRI_DM_NAME
		", Q Type: " PUB_S
		", Q Class: %u"
		", Interface ID: %p"
		", Service ID: %d"
		", Flags: %#04x"
		PUB_S
		", PID: %d"
		", UUID: " PRI_S
		", UID: %d"
		", Handler: %p"
		", Context: %p",
		TAB_PARAM(num_of_tabs),
		parameters->request_id,
		DM_NAME_PARAM(&parameters->question_name),
		DNS_TYPE_STR(parameters->question_type),
		parameters->question_class,
		parameters->interface_id,
		parameters->service_id,
		parameters->flags,
		parameters->append_search_domains ? "Append Search Domains, " : "",
		parameters->pid,
		uuid_hex,
		parameters->uid,
		parameters->user_handler,
		parameters->user_context);
}

//======================================================================================================================
//	dnssec_zone_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_dnssec_zone_t
//======================================================================================================================

mDNSexport void
initialize_dnssec_zone_t(
	dnssec_zone_t * const	_Nonnull	zone,
	const mDNSu8 * const	_Nonnull	domain_name) {

	memcpy(zone->domain_name.c, domain_name, DOMAIN_NAME_LENGTH(domain_name));
	zone->name_hash = DomainNameHashValue((domainname *)domain_name);

	bzero(&zone->ds_request,		sizeof(QueryRecordClientRequest));
	bzero(&zone->dnskey_request,	sizeof(QueryRecordClientRequest));
	zone->ds_request_started		= mDNSfalse;
	zone->dses_initialized			= mDNSfalse;
	zone->last_time_ds_add			= INT_MIN;
	zone->last_time_ds_rmv			= INT_MIN;
	zone->dnskey_request_started	= mDNSfalse;
	zone->last_time_dnskey_add		= INT_MIN;
	zone->last_time_dnskey_rmv		= INT_MIN;
	zone->trust_anchor				= get_trust_anchor_with_name(domain_name);

	initialize_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig);
}

//======================================================================================================================
//	uninitialize_dnssec_zone_t
//======================================================================================================================

mDNSexport void
uninitialize_dnssec_zone_t(dnssec_zone_t * const _Nonnull zone) {
	if (zone->dses_initialized) {
		uninitialize_dses_with_rrsig_t(&zone->dses_with_rrsig);
	}
	uninitialize_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig);
}

mDNSexport void
stop_and_clean_dnssec_zone_t(dnssec_zone_t * const _Nonnull zone) {
	if (zone->dnskey_request_started) {
		QueryRecordOpStopForClientRequest(&zone->dnskey_request.op);
	}
	if (zone->ds_request_started) {
		QueryRecordOpStopForClientRequest(&zone->ds_request.op);
	}

	uninitialize_dnssec_zone_t(zone);
}

//======================================================================================================================
//	print_dnssec_zone_t
//======================================================================================================================

mDNSexport void
print_dnssec_zone_t(const dnssec_zone_t * const _Nonnull zone, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR
		"Name: " PRI_DM_NAME
		", Name Hash: %u"
		,
		TAB_PARAM(num_of_tabs),
		DM_NAME_PARAM(&zone->domain_name),
		zone->name_hash);

	log_debug(TAB_STR "DNSKEYs:", TAB_PARAM(num_of_tabs));
	print_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig, num_of_tabs + 1);

	if (zone->dses_initialized) {
		log_debug(TAB_STR "DSs:", TAB_PARAM(num_of_tabs));
		print_dses_with_rrsig_t(&zone->dses_with_rrsig, num_of_tabs + 1);
	}

	if (zone->trust_anchor != mDNSNULL) {
		log_debug(TAB_STR "Trust Anchors:", TAB_PARAM(num_of_tabs));
		print_trust_anchors_t(zone->trust_anchor, num_of_tabs + 1);
	}

	log_debug(TAB_STR "--------------------------------------------------", TAB_PARAM(num_of_tabs));
}

#pragma mark - returned_answers_t



#pragma mark initialize_returned_answers_t
mDNSexport void
initialize_returned_answers_t(
	returned_answers_t * const	_Nonnull	returned_answers,
	const dnssec_result_t					dnssec_result,
	const DNSServiceErrorType				error) {

	list_init(&returned_answers->answers, sizeof(ResourceRecord *));
	returned_answers->dnssec_result		= dnssec_result;
	returned_answers->error				= error;
}

#pragma mark uninitialize_returned_answers_t
mDNSexport void
uninitialize_returned_answers_t(returned_answers_t * const _Nonnull returned_answers) {
	list_uninit(&returned_answers->answers);
}

#pragma mark print_returned_answers_t
mDNSexport void
print_returned_answers_t(const returned_answers_t * const _Nonnull returned_answers, mDNSu8 num_of_tabs) {

	log_debug(TAB_STR "dnssec_result:%d", TAB_PARAM(num_of_tabs), returned_answers->dnssec_result);
	log_debug(TAB_STR "error:%d", TAB_PARAM(num_of_tabs), returned_answers->error);
	log_debug(TAB_STR "type:%d", TAB_PARAM(num_of_tabs), returned_answers->type);

	log_debug(TAB_STR "Resource Record:", TAB_PARAM(num_of_tabs));
	dnssec_rr_t dnssec_rr;
	const list_t * const answers = &returned_answers->answers;
	for (list_node_t * rr_node = list_get_first(answers); !list_has_ended(answers, rr_node); rr_node = list_next(rr_node)) {
		ResourceRecord **	rr_ptr	= (ResourceRecord **)rr_node->data;
		ResourceRecord *	rr		= *rr_ptr;
		initialize_dnssec_rr_t(&dnssec_rr, rr);
		print_dnssec_rr_t(&dnssec_rr, num_of_tabs + 1);
		uninitialize_dnssec_rr_t(&dnssec_rr);
	}
}


#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
