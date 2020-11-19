//
//	dnssec_v2_helper.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#pragma mark - Includes
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec_v2_helper.h"
#include "dnssec_v2_log.h"
#include "dnssec_v2_crypto.h"
#include <errno.h>
#include <AssertMacros.h>

#pragma mark - Functions



#pragma mark - deep_copy_resource_record
mDNSexport mStatus
deep_copy_resource_record(ResourceRecord * const _Nonnull dst, const ResourceRecord * const _Nonnull src) {
	mStatus error = mStatus_NoError;

	RData * new_rdata = mDNSNULL;
	mDNSu16 name_length;
	mDNSu32 rdata_size;

	require_action(dst != mDNSNULL, exit, error = mStatus_Invalid; log_fault("ResourceRecord dst is NULL, unable to copy to"));
	memcpy(dst, src, sizeof(ResourceRecord));

	dst->name	= mDNSNULL;
	dst->rdata	= mDNSNULL;

	// copy name
	name_length = DOMAIN_NAME_LENGTH(src->name);
	dst->name = malloc(name_length);
	require_action(dst->name != mDNSNULL, exit, error = mStatus_NoMemoryErr;
		log_fault("malloc failed; error_description='%s'", strerror(errno)));
	memcpy((void *)dst->name, (void *)src->name, name_length);

	// copy rdata
	rdata_size		= MAX(src->rdlength, sizeof(RDataBody));
	new_rdata		= malloc(sizeof(RData) - sizeof(RDataBody) + rdata_size);
	require_action(new_rdata != mDNSNULL, exit, error = mStatus_NoMemoryErr;
		log_fault("malloc failed; error_description='%s'", strerror(errno)));
	new_rdata->MaxRDLength  = rdata_size;
	memcpy(new_rdata->u.data, src->rdata->u.data, rdata_size);
	dst->rdata = new_rdata;

exit:
	if (error != mStatus_NoError) {
		if (dst != mDNSNULL) {
			if (dst->name != mDNSNULL)  free((void *)dst->name);
			if (dst->rdata != mDNSNULL) free(dst->rdata);
		}
	}
	return error;
}

#pragma mark - free_resource_record_deep_copied
mDNSexport void
free_resource_record_deep_copied(ResourceRecord * const _Nonnull rr) {
	if (rr->name != mDNSNULL) {
		free((void *)rr->name);
	}

	if (rr->rdata != mDNSNULL) {
		free(rr->rdata);
	}
}

#pragma mark - is_root_domain
mDNSexport mDNSBool
is_root_domain(const mDNSu8 * const _Nonnull domain_name) {
	return *domain_name == 0;
}


#pragma mark - is_a_subdomain_of_b
mDNSexport mDNSBool
is_a_subdomain_of_b(const mDNSu8 * const a_name, const mDNSu8 * const b_name) {
	const mDNSu16 a_length = DOMAIN_NAME_LENGTH(a_name);
	const mDNSu16 b_length = DOMAIN_NAME_LENGTH(b_name);

	return memcmp(a_name + (a_length - b_length), b_name, b_length) == 0;
}

#pragma mark - resource_records_equal
mDNSexport mDNSBool
resource_records_equal(
	const mDNSu16 rr_type_0,				const mDNSu16 rr_type_1,
	const mDNSu16 rr_class_0,				const mDNSu16 rr_clasee_1,
	const mDNSu16 rdata_length_0,			const mDNSu16 rdata_length_1,
	const mDNSu32 name_hash_0,				const mDNSu32 name_hash_1,
	const mDNSu32 rdata_hash_0,				const mDNSu32 rdata_hash_1,
	const mDNSu8 * const _Nonnull name_0,	const mDNSu8 * const _Nonnull name_1,
	const mDNSu8 * const _Nonnull rdata_0,	const mDNSu8 * const _Nonnull rdata_1) {

	if (rr_type_0		!= rr_type_1)					return mDNSfalse;
	if (rr_class_0		!= rr_clasee_1)					return mDNSfalse;
	if (rdata_length_0	!= rdata_length_1)				return mDNSfalse;
	if (name_hash_0		!= name_hash_1)					return mDNSfalse;
	if (rdata_hash_0	!= rdata_hash_1)				return mDNSfalse;
	if (!DOMAIN_NAME_EQUALS(name_0, name_1))			return mDNSfalse;
	if (memcmp(rdata_0, rdata_1, rdata_length_0) != 0)	return mDNSfalse;

	return mDNStrue;
}

#pragma mark - dnssec_algorithm_value_to_string
mDNSexport const char * _Nonnull
dnssec_algorithm_value_to_string(const mDNSu8 algorithm) {
	const char *dnskey_algorithm_desp = mDNSNULL;
	switch (algorithm) {
		case DNSKEY_ALGORITHM_DELETE:
			dnskey_algorithm_desp = "DELETE";
			break;
		case DNSKEY_ALGORITHM_RSAMD5:
			dnskey_algorithm_desp = "RSAMD5";
			break;
		case DNSKEY_ALGORITHM_DH:
			dnskey_algorithm_desp = "DH";
			break;
		case DNSKEY_ALGORITHM_DSA:
			dnskey_algorithm_desp = "DSA";
			break;
		case DNSKEY_ALGORITHM_RSASHA1:
			dnskey_algorithm_desp = "DSA";
			break;
		case DNSKEY_ALGORITHM_DSA_NSEC3_SHA1:
			dnskey_algorithm_desp = "DSA_NSEC3_SHA1";
			break;
		case DNSKEY_ALGORITHM_RSASHA1_NSEC3_SHA1:
			dnskey_algorithm_desp = "RSASHA1_NSEC3_SHA1";
			break;
		case DNSKEY_ALGORITHM_RSASHA256:
			dnskey_algorithm_desp = "RSASHA256";
			break;
		case DNSKEY_ALGORITHM_RSASHA512:
			dnskey_algorithm_desp = "RSASHA512";
			break;
		case DNSKEY_ALGORITHM_ECC_GOST:
			dnskey_algorithm_desp = "ECC_GOST";
			break;
		case DNSKEY_ALGORITHM_ECDSAP256SHA256:
			dnskey_algorithm_desp = "ECDSAP256SHA256";
			break;
		case DNSKEY_ALGORITHM_ECDSAP384SHA384:
			dnskey_algorithm_desp = "ECDSAP384SHA384";
			break;
		case DNSKEK_ALGORITHM_ED25519:
			dnskey_algorithm_desp = "ED25519";
			break;
		case DNSKEY_ALGORITHM_ED448:
			dnskey_algorithm_desp = "ED448";
			break;
		case DNSKEY_ALGORITHM_INDIRECT:
			dnskey_algorithm_desp = "INDIRECT";
			break;
		case DNSKEY_ALGORITHM_PRIVATEDNS:
			dnskey_algorithm_desp = "PRIVATEDNS";
			break;
		case DNSKEY_ALGORITHM_PRIVATEOID:
			dnskey_algorithm_desp = "PRIVATEOID";
			break;
		default:
			dnskey_algorithm_desp = "UNKNOWN";
			break;
	}

	return dnskey_algorithm_desp;
}

#pragma mark - dnssec_digest_type_value_to_string
mDNSexport const char * _Nonnull
dnssec_digest_type_value_to_string(const mDNSu8 digest_type) {
	const char * ds_digest_type_desp = mDNSNULL;
	switch (digest_type) {
		case DS_DIGEST_SHA_1:
			ds_digest_type_desp = "SHA_1";
			break;
		case DS_DIGEST_SHA_256:
			ds_digest_type_desp = "SHA_256";
			break;
		case DS_DIGEST_GOST_R_34_11_94:
			ds_digest_type_desp = "GOST_R_34_11_94";
			break;
		case DS_DIGEST_SHA_384:
			ds_digest_type_desp = "SHA_384";
			break;
		default:
			ds_digest_type_desp = "UNKNOWN";
			break;
	}
	return ds_digest_type_desp;
}

#pragma mark - dnssec_dnskey_flags_to_string
mDNSexport const char * _Nonnull
dnssec_dnskey_flags_to_string(const mDNSu16 flags, char * const _Nonnull buffer, const mDNSu32 buffer_size) {
	char *	ptr					= buffer;
	char *	limit				= ptr + buffer_size;
	int		num_of_char_write;

	if ((flags & 0x100) != 0) { // bit 8
		num_of_char_write = snprintf(ptr, limit - ptr, "ZONE ");
		require(num_of_char_write + ptr < limit, exit);
		ptr += num_of_char_write;
	}

	if ((flags & 0x80) != 0) { // bit 7
		num_of_char_write = snprintf(ptr, limit - ptr, "REVOKE ");
		require(num_of_char_write + ptr < limit, exit);
		ptr += num_of_char_write;
	}

	if ((flags & 0x1) != 0) { // bit 15
		num_of_char_write = snprintf(ptr, limit - ptr, "Secure_Entry_Point ");
		require(num_of_char_write + ptr < limit, exit);
		ptr += num_of_char_write;
	}

exit:
	if (ptr > buffer) {
		ptr--;
		*ptr = '\0';
	}
	return buffer;
}

#pragma mark - dnssec_epoch_time_to_date_string
mDNSexport const char * _Nonnull
dnssec_epoch_time_to_date_string(const mDNSu32 epoch, char * const _Nonnull buffer, const mDNSu32 buffer_size) {
	time_t		t = epoch;
	struct tm	local_time;

	localtime_r(&t, &local_time);
	strftime(buffer, buffer_size, "%F %T%z", &local_time);

	return buffer;
}

#pragma mark - dnssec_nsec3_flags_to_string
mDNSexport const char * _Nonnull
dnssec_nsec3_flags_to_string(const mDNSu8 flags, char * const _Nonnull buffer, const mDNSu32 buffer_size) {
	char *	ptr		= buffer;
	char *	limit	= buffer + buffer_size;
	int		num_of_char_write;

	if ((flags & 0x1) != 0) { // bit 0
		num_of_char_write = snprintf(ptr, limit - ptr, "Opt-Out ");
		require(num_of_char_write + ptr < limit, exit);
		ptr += num_of_char_write;
	}

exit:
	if (ptr > buffer) {
		ptr--;
		*ptr = '\0';
	}
	return buffer;
}

#pragma mark - get_number_of_labels
mDNSexport mDNSu8
get_number_of_labels(const mDNSu8 * _Nonnull name) {
	mDNSu8 count = 0;

	while (*name != 0) {
		count++;
		name += *name + 1;
	}

	return count;
}

#pragma mark - to_lowercase_if_char
mDNSexport mDNSu8
to_lowercase_if_char(const mDNSu8 ch) {
	return IS_UPPER_CASE(ch) ? TO_LOWER_CASE(ch) : ch;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
