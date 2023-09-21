/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RESOURCE_RECORD_BYTES_H
#define RESOURCE_RECORD_BYTES_H

#include "dns_common.h"
#include "dns_obj_crypto.h"

#define MAX_RDATA_LEN 2048

typedef struct expected_cname_result_s {
	const uint8_t	canonical_name[MAX_DOMAIN_NAME];
} expected_cname_result_t;

typedef struct expected_soa_result_s {
	const uint32_t	minimum_ttl;
} expected_soa_result_t;

typedef struct expected_srv_result_s {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	const uint8_t target[MAX_DOMAIN_NAME];
} expected_srv_result_t;

typedef struct expected_ds_result_s {
	const uint16_t	key_tag;
	const uint8_t	algorithm;
	const uint8_t	digest_type;
	const uint8_t	digest[MAX_DIGEST_OUTPUT_SIZE];
	const uint8_t	digest_length;
	const bool		is_valid_for_dnssec;
} expected_ds_result_t;

typedef struct expected_nsec_result_s {
	const uint8_t	current_owner_name[MAX_DOMAIN_NAME];
	const uint8_t	next_owner_name[MAX_DOMAIN_NAME];
	const uint16_t	types_covered[UINT16_MAX];
} expected_nsec_result_t;

typedef struct expected_rrsig_result_s {
	const uint16_t	type_covered;
	const uint8_t	algorithm;
	const uint8_t	labels;
	const uint32_t	original_ttl;
	const uint32_t	signature_expiration;
	const uint32_t	signature_inception;
	const uint16_t	key_tag;
	const uint8_t	signer_name[MAX_DOMAIN_NAME];
	const uint8_t	signature[MAX_RDATA_LEN];
} expected_rrsig_result_t;

typedef struct expected_dnskey_result_s {
	const uint16_t	flags;
	const uint8_t	protocol;
	const uint8_t	algorithm;
	const uint8_t	public_key[MAX_PUBLIC_KEY_BYTES];
	const uint16_t	public_key_size;
	const uint16_t	key_tag;
	const bool		is_zone_key;
	const bool		is_secure_entry_point;
	const bool		has_supported_algorithm;
	const bool		is_valid_for_dnssec;
	const uint16_t	priority;
} expected_dnskey_result_t;

typedef struct expected_nsec3_result_s {
	const uint8_t	current_owner_name[MAX_DOMAIN_NAME];
	const uint8_t	hash_algorithm;
	const uint8_t	flags;
	const uint16_t	iterations;
	const uint8_t	salt_length;
	const uint8_t	salt[UINT8_MAX];
	const uint8_t	hash_length;
	const uint8_t	next_hashed_owner_name_in_binary[UINT8_MAX];
	const uint8_t	next_hashed_owner_name[MAX_DOMAIN_LABEL];
	const uint16_t	types_covered[UINT16_MAX];
} expected_nsec3_result_t;

typedef struct resource_record_bytes_s {
	const uint8_t	name[MAX_DOMAIN_NAME];
	const uint16_t	type;
	const uint16_t	class;
	const uint16_t	rdata_len;
	const uint8_t	rdata[MAX_RDATA_LEN];
	union {
		expected_cname_result_t		cname;
		expected_soa_result_t		soa;
		expected_srv_result_t		srv;
		expected_ds_result_t		ds;
		expected_nsec_result_t		nsec;
		expected_rrsig_result_t		rrsig;
		expected_dnskey_result_t	dnskey;
		expected_nsec3_result_t		nsec3;
	} expected_result_u;
} resource_record_bytes_t;

typedef struct resource_record_bytes_short_s {
	const uint8_t	name[MAX_DOMAIN_NAME];
	const uint16_t	class;
	const uint16_t	type;
	const uint16_t	rdata_len;
	const uint8_t	rdata[MAX_RDATA_LEN];
} resource_record_bytes_short_t;

#undef MAX_RDATA_LEN

#define NUM_OF_RR_RECORDS 22
extern const resource_record_bytes_t test_records[NUM_OF_RR_RECORDS];

#endif // RESOURCE_RECORD_BYTES_H
