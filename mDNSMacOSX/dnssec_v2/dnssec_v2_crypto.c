//
//	dnssec_v2_crypto.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <stdio.h>
#include <CommonCrypto/CommonDigestSPI.h>
#include <Security/Security.h>
#include <Security/SecKeyPriv.h>
#include "dnssec_v2_crypto.h"
#include "dnssec_v2_helper.h"
#include "dnssec_v2_log.h"
#include "base_n.h"

mDNSlocal void
parse_rsa_pubkey(
	mDNSu8 * const		_Nonnull	public_key,
	const mDNSu16					key_length,
	uint8_t ** const	_Nonnull	out_modulus,
	signed long * const _Nonnull	out_modulus_length,
	uint8_t ** const	_Nonnull	out_exponent,
	signed long * const _Nonnull	out_exponent_length);

mDNSlocal void
print_validation_progress(const mDNSu32 request_id, const dnssec_dnskey_t * const dnskey, const dnssec_rrsig_t * const rrsig);

// The array index means the algorithm number, the array element value means the prefered order to use when there is
// multiple algorithms avaliable, the order is determined by "The most secure, the better", 0 is the lowest priority.

//======================================================================================================================
//	get_priority_of_ds_digest
//======================================================================================================================

mDNSexport mDNSs16
get_priority_of_ds_digest(mDNSu8 digest) {
	// ref 1: https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
	// ref 2: https://tools.ietf.org/html/draft-ietf-dnsop-algorithm-update-10
	mDNSs16 priority;

	switch (digest) {
		case DS_DIGEST_SHA_1:
			// Algorithm Number 1		SHA-1				MUST
			priority = 0;
			break;
		case DS_DIGEST_SHA_256:
			// Algorithm Number 2		SHA-256				MUST
			priority = 1;
			break;
		case DS_DIGEST_SHA_384:
			// Algorithm Number 4		SHA-384				RECOMMENDED
			priority = 2;
			break;
		default:
			// Algorithm Number 0		Reserved
			// Algorithm Number 3		GOST R 34.11-94		NOT SUPPORTED
			// Algorithm Number 5-255	Unassigned
			priority = -1;
			break;
	}

	return priority;
}

//======================================================================================================================
//	get_priority_of_dnskey_algorithm
//======================================================================================================================

mDNSexport mDNSs16
get_priority_of_dnskey_algorithm(mDNSu8 algorithm) {
	// ref 1: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
	// ref 2: https://tools.ietf.org/html/draft-ietf-dnsop-algorithm-update-10

	mDNSs16 priority;

	switch (algorithm) {
		case DNSKEY_ALGORITHM_RSASHA1:
			// Algorithm Number 5		RSA/SHA-1					MUST
			priority = 0;
			break;
		case DNSKEY_ALGORITHM_RSASHA1_NSEC3_SHA1:
			// Algorithm Number 7		RSASHA1-NSEC3-SHA1				MUST
			priority = 1;
			break;
		case DNSKEY_ALGORITHM_RSASHA256:
			// Algorithm Number 8		RSA/SHA-256						MUST
			priority = 2;
			break;
		case DNSKEY_ALGORITHM_RSASHA512:
			// Algorithm Number 10		RSA/SHA-512						MUST
			priority = 3;
			break;
		case DNSKEY_ALGORITHM_ECDSAP256SHA256:
			// Algorithm Number 13		ECDSA Curve P-256 with SHA-256	RECOMMENDED
			priority = 4;
			break;
		case DNSKEY_ALGORITHM_ECDSAP384SHA384:
			// Algorithm Number 14		ECDSA Curve P-384 with SHA-384	RECOMMENDED
			priority = 5;
			break;
		default:
			// Algorithm Number 0		Delete							N/A
			// Algorithm Number 1		RSA/MD5							MUST NOT
			// Algorithm Number 2		Diffie-Hellman					NOT SUPPORTED
			// Algorithm Number 3		DSA/SHA1						MUST NOT
			// Algorithm Number 4		Reserved
			// Algorithm Number 6		DSA-NSEC3-SHA1					MUST NOT
			// Algorithm Number 9		Reserved
			// Algorithm Number 11		Reserved
			// Algorithm Number 12		GOST R 34.10-2001				MAY
			// Algorithm Number 15		Ed25519							RECOMMENDED, but NOT SUPPORTED
			// Algorithm Number 16		Ed448							RECOMMENDED, but NOT SUPPORTED
			// Algorithm Number 17-122	Unassigned
			// Algorithm Number 123-251 Reserved
			// Algorithm Number 252		Reserved for Indirect Keys
			// Algorithm Number 253		private algorithm
			// Algorithm Number 254		private algorithm OID
			// Algorithm Number 255		Reserved
			priority = -1;
			break;
	}

	return priority;
}

//======================================================================================================================
//	validate_signed_data_with_rrsig_and_dnskey
//		the main function doing signature validation
//======================================================================================================================

mDNSexport mDNSBool
validate_signed_data_with_rrsig_and_dnskey(
	const mDNSu32								request_id,
	const mDNSu8 * const			_Nonnull	signed_data,
	const mDNSu32								signed_data_length,
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const dnssec_dnskey_t * const	_Nonnull	dnskey) {

	mDNSBool				valid						= mDNSfalse;
	const mDNSu8 *			data_or_digest_be_signed	= mDNSNULL;
	mDNSu32					data_or_digest_be_signed_length;
	SecKeyAlgorithm			verify_algorithm;
	const void *			public_key_type;
	CFErrorRef				cf_error					= mDNSNULL;
	CFDataRef				data_to_verify_CFData		= mDNSNULL;
	CFDataRef				sig_to_match_CFData			= mDNSNULL;
	SecKeyRef				key							= mDNSNULL;
	digest_type_t			digest_type					= DIGEST_UNSUPPORTED;

	// choose different signature validation algorithm and public key
	switch (dnskey->algorithm) {
		case DNSKEY_ALGORITHM_RSASHA1:
			verify_algorithm	= kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
			public_key_type		= kSecAttrKeyTypeRSA;
			break;
		case DNSKEY_ALGORITHM_RSASHA1_NSEC3_SHA1:
			verify_algorithm	= kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
			public_key_type		= kSecAttrKeyTypeRSA;
			break;
		case DNSKEY_ALGORITHM_RSASHA256:
			verify_algorithm	= kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
			public_key_type		= kSecAttrKeyTypeRSA;
			break;
		case DNSKEY_ALGORITHM_RSASHA512:
			verify_algorithm	= kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
			public_key_type		= kSecAttrKeyTypeRSA;
			break;
		case DNSKEY_ALGORITHM_ECDSAP256SHA256:
			verify_algorithm	= kSecKeyAlgorithmECDSASignatureRFC4754;
			public_key_type		= kSecAttrKeyTypeECSECPrimeRandom;
			digest_type			= DIGEST_SHA_256;
			data_or_digest_be_signed_length	= 32;
			break;
		case DNSKEY_ALGORITHM_ECDSAP384SHA384:
			verify_algorithm	= kSecKeyAlgorithmECDSASignatureRFC4754;
			public_key_type		= kSecAttrKeyTypeECSECPrimeRandom;
			digest_type			= DIGEST_SHA_384;
			data_or_digest_be_signed_length	= 48;
			break;
		default:
			log_error("Unsupported DNSKEY algorithm; algorithm=%d", dnskey->algorithm);
			goto exit;
	}

	// public key creation for RSA and ECDSA is different
	if (public_key_type == kSecAttrKeyTypeRSA) {
		// RSA
		// The format of public key is not the standard PEM DER ASN.1 PKCS#1 RSA Public key format, so we need to parse
		// the modulus and exponent explicitly.
		SecRSAPublicKeyParams params;
		parse_rsa_pubkey(dnskey->public_key, dnskey->public_key_length, &params.modulus, &params.modulusLength, &params.exponent, &params.exponentLength);
		key = SecKeyCreateRSAPublicKey(kCFAllocatorDefault, (const uint8_t *)&params, sizeof(params), kSecKeyEncodingRSAPublicParams);
		require_quiet(key != mDNSNULL, exit);

		data_or_digest_be_signed			= signed_data;
		data_or_digest_be_signed_length		= signed_data_length;
		// RSA uses original data to verify record.
	} else if (public_key_type == kSecAttrKeyTypeECSECPrimeRandom) {
		// ECDSA
		const void *	public_key_options_key[]	= {kSecAttrKeyType,						kSecAttrKeyClass};
		const void *	public_key_options_values[] = {kSecAttrKeyTypeECSECPrimeRandom,		kSecAttrKeyClassPublic};
		CFDataRef		public_key_CFData			= mDNSNULL;
		CFDictionaryRef public_key_options			= mDNSNULL;
		CFNumberRef		key_size_CFNumber			= mDNSNULL;
		mDNSu8 *		ecdsa_key_bytes_encoding	= mDNSNULL;
		mDNSu32			ecdsa_key_length			= dnskey->public_key_length + 1;
		mDNSu8			data_digest[MAX_HASH_OUTPUT_SIZE];

		// create security framework readable public key format
		ecdsa_key_bytes_encoding = malloc(ecdsa_key_length);
		require_quiet(ecdsa_key_bytes_encoding != mDNSNULL, ecdsa_exit);

		ecdsa_key_bytes_encoding[0] = 4;
		memcpy(ecdsa_key_bytes_encoding + 1, dnskey->public_key, dnskey->public_key_length);

		public_key_CFData = CFDataCreate(kCFAllocatorDefault, ecdsa_key_bytes_encoding, ecdsa_key_length);
		require_quiet(public_key_CFData != NULL, ecdsa_exit);

		public_key_options = CFDictionaryCreate(kCFAllocatorDefault, public_key_options_key,
			public_key_options_values, sizeof(public_key_options_key) / sizeof(void *),
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		require_quiet(public_key_options != NULL, ecdsa_exit);

		// create the public key
		key = SecKeyCreateWithData(public_key_CFData, public_key_options, &cf_error);
		require_action(key != mDNSNULL, ecdsa_exit, log_error("SecKeyCreateWithData failed: %@", CFErrorCopyDescription(cf_error)));

		// ECDSA uses digest to verify record.
		mDNSBool calculated = calculate_digest_for_data(signed_data, signed_data_length, digest_type, data_digest, sizeof(data_digest));
		require_action(calculated, ecdsa_exit, log_error("calculate_digest_for_data failed to return the digest;"));
		data_or_digest_be_signed = data_digest;
		// data_be_signed_length is set in the previous switch statement.

	ecdsa_exit:
		if (public_key_CFData			!= NULL) CFRelease(public_key_CFData);
		if (public_key_options			!= NULL) CFRelease(public_key_options);
		if (key_size_CFNumber			!= NULL) CFRelease(key_size_CFNumber);
		if (cf_error					!= NULL) {
			CFRelease(cf_error);
			cf_error = mDNSNULL;
		}
		if (ecdsa_key_bytes_encoding	!= mDNSNULL) free(ecdsa_key_bytes_encoding);
	} else {
		goto exit;
	}

	require_quiet(key != mDNSNULL, exit);

	// create data and signature to verify
	data_to_verify_CFData	= CFDataCreate(kCFAllocatorDefault, data_or_digest_be_signed, data_or_digest_be_signed_length);
	sig_to_match_CFData		= CFDataCreate(kCFAllocatorDefault, rrsig->signature, rrsig->signature_length);

	Boolean matches = SecKeyVerifySignature(key, verify_algorithm, data_to_verify_CFData, sig_to_match_CFData, &cf_error);
	if (matches) {
		print_validation_progress(request_id, dnskey, rrsig);
	} else {
		log_default("SecKeyVerifySignature error: %@", CFErrorCopyDescription(cf_error));
	}

	valid = matches ? mDNStrue : mDNSfalse;

exit:
	if (key						!= mDNSNULL)	CFRelease(key);
	if (data_to_verify_CFData	!= mDNSNULL)	CFRelease(data_to_verify_CFData);
	if (sig_to_match_CFData		!= mDNSNULL)	CFRelease(sig_to_match_CFData);
	if (cf_error				!= mDNSNULL)	CFRelease(cf_error);

	return valid;
}

//======================================================================================================================
//	Hash
//======================================================================================================================

//======================================================================================================================
//	calculate_digest_for_data
//		get the corresponding digest
//======================================================================================================================

mDNSexport mDNSBool
calculate_digest_for_data(
	const mDNSu8 * const	_Nonnull	data,
	const mDNSu32						data_length,
	const digest_type_t					digest_type,
	mDNSu8 * const			_Nonnull	digest_buffer,
	mDNSu32								buffer_size) {

	CCDigestAlgorithm cc_digest_algorithm;
	CCDigestCtx cc_digest_context;
	mDNSBool calculated = mDNSfalse;

	switch (digest_type) {
		case DIGEST_SHA_1: // SHA-1
			require_quiet(buffer_size >= SHA1_OUTPUT_SIZE, exit); // SHA-1 produces 20 bytes
#pragma clang diagnostic push // ignore the deprecation warning for SHA-1, since NSEC3 now only uses SHA-1 to get the digest.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
			cc_digest_algorithm = kCCDigestSHA1;
#pragma clang diagnostic pop
			break;
		case DIGEST_SHA_256: // SHA-256
			require_quiet(buffer_size >= SHA256_OUTPUT_SIZE, exit); // SHA-256 produces 256-bit(32-byte) digest
			cc_digest_algorithm = kCCDigestSHA256;
			break;
		case DIGEST_SHA_384: // SHA-384
			require_quiet(buffer_size >= SHA384_OUTPUT_SIZE, exit); // SHA-384 produces 384-bit(48-byte) digest
			cc_digest_algorithm = kCCDigestSHA384;
			break;
		case DIGEST_SHA_512: // SHA-512
			require_quiet(buffer_size >= SHA512_OUTPUT_SIZE, exit); // SHA-512 produces 512-bit(64-byte) digest
			cc_digest_algorithm = kCCDigestSHA512;
			break;
		default:
			goto exit;
	}

	CCDigestInit(cc_digest_algorithm, &cc_digest_context);
	CCDigestUpdate(&cc_digest_context, data, data_length);
	CCDigestFinal(&cc_digest_context, digest_buffer);
	calculated = mDNStrue;

exit:
	return calculated;
}

//======================================================================================================================
//	calculate_b32_hash_for_nsec3
//		get Base32 encoding from the digest of riginal data
//======================================================================================================================

mDNSexport mDNSu8 * _Nullable
calculate_b32_hash_for_nsec3(
	const mDNSu8 * const _Nonnull		name,
	const mDNSu16						name_length,
	const mDNSu8						hash_type,
	const mDNSu8 * const	_Nullable	salt,
	const mDNSu32						salt_length,
	const mDNSu16						iterations) {

	mDNSu8	name_hash[MAX_HASH_OUTPUT_SIZE];
	mDNSu32 name_hash_length;
	mDNSu8 *name_hash_b32 = mDNSNULL;

	name_hash_length = get_hash_length_for_nsec3_hash_type(hash_type);

	mDNSBool calculated = calculate_hash_for_nsec3(name_hash, sizeof(name_hash), hash_type, name, name_length, salt, salt_length, iterations);
	require_quiet(calculated, exit);

	name_hash_b32 = (mDNSu8 *)base_n_encode(DNSSEC_BASE_32_HEX, name_hash, name_hash_length);
	require_quiet(name_hash_b32 != mDNSNULL, exit);

exit:
	return name_hash_b32;
}

//======================================================================================================================
//	calculate_hash_for_nsec3
//		get the hash value for nsec3 which includes salt and multiple iteration
//======================================================================================================================

mDNSexport mDNSBool
calculate_hash_for_nsec3(
	mDNSu8 * const			_Nonnull	hash_buffer,
	const mDNSu32						buffer_size,
	const mDNSu8						hash_type,
	const mDNSu8 * const	_Nonnull	name,
	const mDNSu16						name_length,
	const mDNSu8 * const	_Nullable	salt,
	const mDNSu32						salt_length,
	const mDNSu16						iterations) {

	// data_to_be_hashed will be used to generate the hash, it should be big enough to hold 1) first hash iteration: name | salt, 2) the remaining iteration: hash_result_from_the_last_iteration | salt.
	mDNSu8			data_to_be_hashed[MAX(MAX_HASH_OUTPUT_SIZE, MAX_DOMAIN_NAME) + 256];
	mDNSu32			data_length;
	mDNSu32			hash_length;
	digest_type_t	digest_type;
	mDNSBool		calculated = mDNSfalse;

	memcpy(data_to_be_hashed, name, name_length);
	memcpy(data_to_be_hashed + name_length, salt, salt_length);
	data_length = name_length + salt_length;

	// choose correct hash algorithm to get digest
	switch (hash_type) {
		case NSEC3_HASH_ALGORITHM_SHA_1:
			digest_type		= DIGEST_SHA_1;
			hash_length		= 20;
			break;
		default:
			goto exit;
	}
	calculated = calculate_digest_for_data(data_to_be_hashed, data_length, digest_type, hash_buffer, buffer_size);
	require_quiet(calculated, exit);

	// do iteration
	for (mDNSs32 i = 0; i < iterations; i++) {
		memcpy(data_to_be_hashed, hash_buffer, hash_length);
		memcpy(data_to_be_hashed + hash_length, salt, salt_length);
		data_length = hash_length + salt_length;

		calculated = calculate_digest_for_data(data_to_be_hashed, data_length, hash_type, hash_buffer, buffer_size);
		require_quiet(calculated, exit);
	}

	calculated = mDNStrue;
exit:
	return calculated;
}

//======================================================================================================================
//	get_hash_length_for_nsec3_hash_type
//======================================================================================================================

mDNSexport mDNSu32
get_hash_length_for_nsec3_hash_type(const nsec3_hash_algorithm_type_t nsec3_hash_type) {
	digest_type_t digest_type;

	switch (nsec3_hash_type) {
		case NSEC3_HASH_ALGORITHM_SHA_1:
			digest_type = DIGEST_SHA_1;
			break;
		default:
			digest_type = DIGEST_UNSUPPORTED;
			break;
	}

	return get_digest_length_for_digest_type(digest_type);
}

//======================================================================================================================
//	get_digest_length_for_digest_type
//======================================================================================================================

mDNSexport mDNSu32
get_digest_length_for_ds_digest_type(const ds_digest_type_t ds_digest_type) {
	digest_type_t digest_type;

	switch (ds_digest_type) {
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
			digest_type = DIGEST_UNSUPPORTED;
			break;
	}

	return get_digest_length_for_digest_type(digest_type);
}

//======================================================================================================================
//	get_digest_length_for_digest_type
//======================================================================================================================

mDNSexport mDNSu32
get_digest_length_for_digest_type(const digest_type_t digest_type) {
	mDNSu32 digest_length;

	switch (digest_type) {
		case DIGEST_SHA_1:
			digest_length = SHA1_OUTPUT_SIZE;
			break;
		case DIGEST_SHA_256:
			digest_length = SHA256_OUTPUT_SIZE;
			break;
		case DIGEST_SHA_384:
			digest_length = SHA384_OUTPUT_SIZE;
			break;
		case DIGEST_SHA_512:
			digest_length = SHA512_OUTPUT_SIZE;
			break;
		default:
			digest_length = 0;
			break;
	}

	return digest_length;
}

//======================================================================================================================
//	parse_rsa_pubkey
//		parse RSA key according to https://tools.ietf.org/html/rfc3110
//======================================================================================================================

mDNSlocal void
parse_rsa_pubkey(
	mDNSu8 * const		_Nonnull	public_key,
	const mDNSu16					key_length,
	uint8_t ** const	_Nonnull	out_modulus,
	signed long * const _Nonnull	out_modulus_length,
	uint8_t ** const	_Nonnull	out_exponent,
	signed long * const _Nonnull	out_exponent_length) {

	mDNSu8			exponent_length_length;
	if (public_key[0] != 0) {
		*out_exponent_length = public_key[0];
		exponent_length_length	= 1;
	} else {
		*out_exponent_length = (((uint32_t)public_key[1] << 8) | (uint32_t)public_key[2]);
		exponent_length_length	= 3;
	}

	*out_exponent = public_key + exponent_length_length;

	*out_modulus_length = key_length - (*out_exponent_length + exponent_length_length);

	*out_modulus = public_key + exponent_length_length + *out_exponent_length;
}

//======================================================================================================================
//	Canonical order and form
//======================================================================================================================

//======================================================================================================================
//	canonical_form_name_length
//======================================================================================================================

mDNSexport mDNSu8
canonical_form_name_length(const mDNSu8 * const _Nonnull name) {
	// assume that domainname* is already in canonical form
	return DOMAIN_NAME_LENGTH(name);
}

//======================================================================================================================
//	compare_canonical_dns_name
//		compare the domain name from the right most label, and compare label by label
//======================================================================================================================

mDNSexport mDNSs8
compare_canonical_dns_name(const mDNSu8 * const _Nonnull left, const mDNSu8 * const _Nonnull right) {
	const mDNSu16	left_len			= DOMAIN_NAME_LENGTH(left);
	const mDNSu8 *	left_limit			= left + left_len - 1;
	const mDNSu16	right_len			= DOMAIN_NAME_LENGTH(right);
	const mDNSu8 *	right_limit			= right + right_len - 1;
	mDNSBool		result;

	const mDNSu8 *	left_label_length_ptrs[256];
	mDNSu32			left_ptrs_size = 0;
	const mDNSu8 *	right_label_length_ptrs[256];
	mDNSu32			right_ptrs_size = 0;

	// load the start of each label into an array
	for (const mDNSu8 * left_ptr = left; left_ptr < left_limit; left_ptr += 1 + *left_ptr) {
		left_label_length_ptrs[left_ptrs_size++] = left_ptr;
		require_action(left_ptrs_size < sizeof(left_label_length_ptrs), exit,
			result = 0; log_error("domain name has more than 255 labels, returning 0"));
	}

	for (const mDNSu8 * right_ptr = right; right_ptr < right_limit; right_ptr += 1 + *right_ptr) {
		right_label_length_ptrs[right_ptrs_size++] = right_ptr;
		require_action(right_ptrs_size < sizeof(right_label_length_ptrs), exit,
			result = 0; log_error("domain name has more than 255 labels, returning 0"));
	}

	// start comparing
	while (left_ptrs_size > 0 && right_ptrs_size > 0) {
		const mDNSu8 *	left_ptr			= left_label_length_ptrs[left_ptrs_size - 1];
		const mDNSu8 *	right_ptr			= right_label_length_ptrs[right_ptrs_size - 1];
		const mDNSu8	left_label_length	= *left_ptr;
		const mDNSu8	right_label_length	= *right_ptr;

		mDNSs8 compare_label = compare_canonical_dns_label(left_ptr + 1, left_label_length, right_ptr + 1, right_label_length);
		require_action_quiet(compare_label == 0, exit, result = compare_label);
		left_ptrs_size--;
		right_ptrs_size--;
	}

	// -1 -> <
	//	0 -> =
	// +1 -> >
	if (left_ptrs_size == 0 && right_ptrs_size == 0) {
		result = 0;
	} else if (left_ptrs_size == 0) {
		result = -1;
	} else if (right_ptrs_size == 0) {
		result = 1;
	} else {
		log_error("Impossible case here");
		result = 0;
	}

exit:
	return result;
}

//======================================================================================================================
//	copy_canonical_name
//		copy domain name to canonical form
//======================================================================================================================

mDNSexport mDNSu8
copy_canonical_name(mDNSu8 * const _Nonnull dst, const mDNSu8 * const _Nonnull name) {
	// assume that "name" is already fully expanded.
	mDNSu16	name_length = DOMAIN_NAME_LENGTH(name);
	mDNSu8 *ptr			= mDNSNULL;
	mDNSu32	bytes_convert = 0;

	require_action_quiet(name_length > 0 && name_length <= MAX_DOMAIN_NAME, exit, bytes_convert = 0;
		log_error("name is a malformed DNS name"));
	memcpy(dst, name, name_length);

	for (ptr = dst; *ptr != 0; ptr += *ptr + 1) {
		mDNSu8		label_length	= *ptr;
		mDNSu8 *	label_end		= ptr + label_length;
		for (mDNSu8 *ch_ptr = ptr + 1; ch_ptr <= label_end; ch_ptr++) {
			char ch = *ch_ptr;
			if (IS_UPPER_CASE(ch)) {
				*ch_ptr = TO_LOWER_CASE(ch);
			}
		}
	}

	bytes_convert = ptr + 1 - dst;
	verify_action(bytes_convert == name_length,
		log_error("convert more bytes than the actual name length; written=%u, name_length=%u", bytes_convert, name_length);
		bytes_convert = 0);

exit:
	return bytes_convert;
}

//======================================================================================================================
//	compare_canonical_dns_label
//======================================================================================================================

mDNSexport mDNSs8
compare_canonical_dns_label(
	const mDNSu8 * _Nonnull		left_label,
	const mDNSu8				left_label_length,
	const mDNSu8 * _Nonnull		right_label,
	const mDNSu8				right_label_length) {

	mDNSu8 length_limit = MIN(left_label_length, right_label_length);

	for (mDNSu8 i = 0; i < length_limit; i++) {
		mDNSu8 left_ch	= to_lowercase_if_char(*left_label);
		mDNSu8 right_ch = to_lowercase_if_char(*right_label);
		if (left_ch < right_ch)			return -1;
		else if (left_ch > right_ch)	return 1;
		left_label++;
		right_label++;
	}

	if (left_label_length < right_label_length) {
		return -1;
	} else if (left_label_length > right_label_length) {
		return 1;
	} else {
		// left_label_length == right_label_length
		return 0;
	}
}

#ifdef UNIT_TEST
mDNSexport mDNSu8
copy_canonical_name_ut(mDNSu8 * const _Nonnull dst, const mDNSu8 * const _Nonnull name) {
	return copy_canonical_name(dst, name);
}
#endif // UNIT_TEST

mDNSlocal void
print_validation_progress(const mDNSu32 request_id, const dnssec_dnskey_t * const dnskey, const dnssec_rrsig_t * const rrsig) {
	log_default("[R%u] "PRI_DM_NAME ": DNSKEY (alg=%u, tag=%u, length=%u) -----> " PRI_DM_NAME ": " PUB_S, request_id,
		DM_NAME_PARAM(&dnskey->dnssec_rr.name), dnskey->algorithm, dnskey->key_tag, dnskey->public_key_length,
		DM_NAME_PARAM(&rrsig->dnssec_rr.name), DNS_TYPE_STR(rrsig->type_covered));
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
