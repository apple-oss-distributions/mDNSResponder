//
//	dnssec_v2_crypto.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_CRYPTO_H
#define DNSSEC_V2_CRYPTO_H

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <stdio.h>
#include <corecrypto/ccsha1.h>
#include "dnssec_v2_structs.h"

#define SHA1_OUTPUT_SIZE		20
#define SHA256_OUTPUT_SIZE		32
#define SHA384_OUTPUT_SIZE		48
#define SHA512_OUTPUT_SIZE		64
#define MAX_HASH_OUTPUT_SIZE	SHA512_OUTPUT_SIZE // to ensure that the buffer has enough space to store digest

// Taken from https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
typedef enum dnskey_algorithm_type {
	DNSKEY_ALGORITHM_DELETE				= 0,
	DNSKEY_ALGORITHM_RSAMD5				= 1,
	DNSKEY_ALGORITHM_DH					= 2,
	DNSKEY_ALGORITHM_DSA				= 3,
	// Reserved 4
	DNSKEY_ALGORITHM_RSASHA1			= 5,
	DNSKEY_ALGORITHM_DSA_NSEC3_SHA1		= 6,
	DNSKEY_ALGORITHM_RSASHA1_NSEC3_SHA1 = 7,
	DNSKEY_ALGORITHM_RSASHA256			= 8,
	// Reserved 9
	DNSKEY_ALGORITHM_RSASHA512			= 10,
	// Reserved 11
	DNSKEY_ALGORITHM_ECC_GOST			= 12,
	DNSKEY_ALGORITHM_ECDSAP256SHA256	= 13,
	DNSKEY_ALGORITHM_ECDSAP384SHA384	= 14,
	DNSKEK_ALGORITHM_ED25519			= 15,
	DNSKEY_ALGORITHM_ED448				= 16,
	// Unassigned 17 - 122
	// Reserved 123 - 251
	DNSKEY_ALGORITHM_INDIRECT			= 252,
	DNSKEY_ALGORITHM_PRIVATEDNS			= 253,
	DNSKEY_ALGORITHM_PRIVATEOID			= 254
	// Reserved 255
} dnskey_algorithm_type_t;

// Taken from https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml too
typedef enum ds_digest_type {
	// Reserved 0
	DS_DIGEST_SHA_1				= 1,
	DS_DIGEST_SHA_256			= 2,
	DS_DIGEST_GOST_R_34_11_94	= 3,
	DS_DIGEST_SHA_384			= 4
	// Reserved 5 - 255
} ds_digest_type_t;

typedef enum nsec3_hash_algorithm_type {
	// Reserved 0
	NSEC3_HASH_ALGORITHM_SHA_1	= 1
	// Unassigned 2 - 255
} nsec3_hash_algorithm_type_t;

typedef enum digest_type {
	DIGEST_UNSUPPORTED,
	DIGEST_SHA_1,
	DIGEST_SHA_256,
	DIGEST_SHA_384,
	DIGEST_SHA_512
} digest_type_t;

mDNSexport mDNSs16
get_priority_of_ds_digest(mDNSu8 digest);

mDNSexport mDNSs16
get_priority_of_dnskey_algorithm(mDNSu8 algorithm);

mDNSexport mDNSBool
validate_signed_data_with_rrsig_and_dnskey(
	const mDNSu32								request_id,
	const mDNSu8 * const			_Nonnull	signed_data,
	const mDNSu32								signed_data_length,
	const dnssec_rrsig_t * const	_Nonnull	rrsig,
	const dnssec_dnskey_t * const	_Nonnull	dnskey);

mDNSexport mDNSBool
calculate_digest_for_data(
	const mDNSu8 * const	_Nonnull	data,
	const mDNSu32						data_length,
	const digest_type_t					digest_type,
	mDNSu8 * const			_Nonnull	digest_buffer,
	mDNSu32								buffer_size);

mDNSexport mDNSu8 * _Nullable
calculate_b32_hash_for_nsec3(
	const mDNSu8 * const _Nonnull		name,
	const mDNSu16						name_length,
	const mDNSu8						hash_type,
	const mDNSu8 * const	_Nullable	salt,
	const mDNSu32						salt_length,
	const mDNSu16						iterations);

mDNSexport mDNSBool
calculate_hash_for_nsec3(
	mDNSu8 * const			_Nonnull	hash_buffer,
	const mDNSu32						buffer_size,
	const mDNSu8						hash_type,
	const mDNSu8 * const	_Nonnull	name,
	const mDNSu16						name_length,
	const mDNSu8 * const	_Nullable	salt,
	const mDNSu32						salt_length,
	const mDNSu16						iterations);

mDNSexport mDNSu32
get_hash_length_for_nsec3_hash_type(const nsec3_hash_algorithm_type_t nsec3_hash_type);

mDNSexport mDNSu32
get_digest_length_for_ds_digest_type(const ds_digest_type_t ds_digest_type);

mDNSexport mDNSu32
get_digest_length_for_digest_type(const digest_type_t digest_type);

mDNSexport mDNSu8
canonical_form_name_length(const mDNSu8 * const _Nonnull name);

mDNSexport mDNSs8
compare_canonical_dns_name(const mDNSu8 * const _Nonnull left, const mDNSu8 * const _Nonnull right);

mDNSexport mDNSs8
compare_canonical_dns_label(
	const mDNSu8 * _Nonnull		left_label,
	const mDNSu8				left_label_length,
	const mDNSu8 * _Nonnull		right_label,
	const mDNSu8				right_label_length);

mDNSexport mDNSu8
copy_canonical_name(mDNSu8 * const _Nonnull dst, const mDNSu8 * const _Nonnull name);

#ifdef UNIT_TEST
mDNSexport mDNSu8
copy_canonical_name_ut(mDNSu8 * const _Nonnull dst, const mDNSu8 * const _Nonnull name);
#endif // UNIT_TEST

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_V2_CRYPTO_H
