//
//	dnssec_v2_structs.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_v2_STRUCTS_H
#define DNSSEC_v2_STRUCTS_H

#pragma mark - Includes
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "list.h"
#include "mDNSEmbeddedAPI.h"
#include "ClientRequests.h"

#pragma mark - Enums



#pragma mark dnssec_validation_result_t
typedef enum dnssec_validation_result {
	// chain of trust validation error
	dnssec_validation_invalid,
	dnssec_validation_valid,
	dnssec_validation_not_trusted,
	dnssec_validation_trusted,
	dnssec_validation_invalid_internal_state,
	dnssec_validation_non_dnskey_ds_record_chain,
	dnssec_validation_no_matching_key_tag,

	// DNSSEC record general error
	dnssec_validation_algorithm_number_not_equal,

	// DS validation error
	dnssec_validation_ds_digest_not_supported,

	// DNSKEY validation error
	dnssec_validation_dnskey_algorithm_not_supported,
	dnssec_validation_dnskey_invalid_flags,
	dnssec_validation_dnskey_wrong_protocol,

	// RRSIG validation error
	dnssec_validation_rrsig_use_before_inception,
	dnssec_validation_rrsig_use_after_expiration,

	// NSEC validation error
	dnssec_validation_nsec_invalid_nsec_result,
	dnssec_validation_nsec_malformated_record,
	// Verifiable NSEC error
	dnssec_validation_nsec_name_error,
	dnssec_validation_nsec_no_data,
	dnssec_validation_nsec_wildcard_answer,
	dnssec_validation_nsec_wildcard_no_data,

	// NSEC3 validation error
	dnssec_validation_nsec3_invalid_hash_iteration,
	dnssec_validation_nsec3_unsupported_hash_algorithm,
	dnssec_validation_nsec3_unsupported_flag,
	dnssec_validation_nsec3_different_hash_iteration_salt,
	dnssec_validation_nsec3_provable_closest_encloser,
	dnssec_validation_nsec3_nsec3_not_from_the_zone,
	dnssec_validation_nsec3_malformated_record,
	// Verifiable NSEC3 error
	dnssec_validation_nsec3_name_error,
	dnssec_validation_nsec3_wildcard_no_data,
	dnssec_validation_nsec3_no_data_response,
	dnssec_validation_nsec3_no_data_response_opt_out,
	dnssec_validation_nsec3_wildcard_answer_response,

	// path validation error
	dnssec_validation_path_invalid_node_type,
	dnssec_validation_path_unmatched_owner_name,
	dnssec_validation_path_unmatched_class,
	dnssec_validation_path_unmatched_type_covered,
	dnssec_validation_path_invalid_label_count,

	// trust anchor error
	dnssec_validation_trust_anchor_not_available,
	dnssec_validation_trust_anchor_does_not_macth,

	// general error
	dnssec_validation_validating,
	dnssec_validation_no_memory,
	dnssec_validation_bogus
} dnssec_validation_result_t;

#pragma mark - Structures



#pragma mark - DNSSEC-related records wire format



#pragma mark dns_type_cname_t
// DNS CNAME record data fields (see <https://tools.ietf.org/html/rfc1035#section-3.3.1>)
typedef struct dns_type_cname dns_type_cname_t;
struct dns_type_cname {
	mDNSu8		cname[0];				// To CNAME rdata.
};

#pragma mark dns_type_ds_t
typedef struct dns_type_ds dns_type_ds_t;
// DNS DS record data fields (see <https://tools.ietf.org/html/rfc4034#section-5.1>)
struct dns_type_ds {
	mDNSu16		key_tag;				// key tag that identifies a specific DNSKEY.
	mDNSu8		algorithm;				// The DNSKEY algorithm that is used to sign the data.
	mDNSu8		digest_type;			// The type of the DS digest.
	mDNSu8		digest[0];				// To digest rdata.
};

#pragma mark dns_type_dnskey_t
// DNS DNSKEY record data fields (see <https://tools.ietf.org/html/rfc4034#section-2.1>)
typedef struct dns_type_dnskey dns_type_dnskey_t;
struct dns_type_dnskey {
	mDNSu16		flags;					// The DNSKEY flags.
	mDNSu8		protocol;				// Protocol that identifies DNSKEY as a key used in DNSSEC, it should always be 3.
	mDNSu8		algorithm;				// The DNSKEY algorithm that is used to sign the data.
	mDNSu8		public_key[0];			// To public rdata.
};

#pragma mark dns_type_rrsig_t
// DNS RRSIG record data fields (see <https://tools.ietf.org/html/rfc4034#section-3.1>)
typedef struct dns_type_rrsig dns_type_rrsig_t;
struct dns_type_rrsig {
	mDNSu16		type_covered;			// Indicates which DNS type RRSIG covers
	mDNSu8		algorithm;				// The DNSKEY algorithm that is used to sign the data.
	mDNSu8		labels;					// The number of labels in the RRSIG owner name, it is used to check wild matching.
	mDNSu32		original_TTL;			// The original TTL of the records that are covered by the RRSIG, it is used to reconstruct the signed data.
	mDNSu32		signature_expiration;	// The epoch time when the RRSIG expires.
	mDNSu32		signature_inception;	// The epoch time when the RRSIG should start to be valid to validate.
	mDNSu16		key_tag;				// The key tag that identifies which DNSKEY it uses to generate the current RRSIG.
	mDNSu8		signer_name[0];			// To the signer name.
	// mDNSu8	signature[0];			// To the signature rdata.
};

#pragma mark dns_type_nsec_t
// DNS NSEC record data fields (see <https://tools.ietf.org/html/rfc4034#section-2.1>)
typedef struct dns_type_nsec dns_type_nsec_t;
struct dns_type_nsec {
	mDNSu8		next_domain_name[0];	// The next domain that exists in the zone
	// mDNSu8	type_bit_maps[0];		// To the type bit map that indicates what DNS types are covered by the current NSEC record.
};

#pragma mark dns_type_nsec3_t
// DNS NSEC3 record data fields (see <https://tools.ietf.org/html/rfc5155#section-3.1>)
typedef struct dns_type_nsec3 dns_type_nsec3_t;
struct dns_type_nsec3 {
	mDNSu8		hash_algorithm;			// Which hash algorithm that NSEC3 uses to generate the hash.
	mDNSu8		flags;					// The NSEC3 flags
	mDNSu16		iterations;				// The iterations of hash operation on the data
	mDNSu8		salt_length;
	mDNSu8		salt[0];				// varied-size array
	// mDNSu8	hash_length;
	// mDNSu8	next_hashed_owner_name[0];// The next hashed domain that exists in the zone
	// mDNSu8 * type_bit_maps;			// To the type bit map that indicates what DNS types are covered by the current NSEC3 record.
};

#pragma mark - DNSSEC records in memory

#pragma mark dnssec_rr_t
typedef struct dnssec_rr dnssec_rr_t;
struct dnssec_rr {							// Represents a resource record
	mDNSu16						rr_type;				// The DNS type of the resource record.
	mDNSu16						rr_class;				// The internet class of the record, should be IN
	mDNSu16						rdata_length;			// The length of the rdata
	mDNSu32						name_hash;				// The hash of the owner name that is used to compare name quickly
	mDNSu32						rdata_hash;				// The hash of the rdata that is used to compare rdata quickly
	domainname					name;					// The owner name of the record
	mDNSu8 *	_Nullable		rdata;					// The rdata
	ResourceRecord * _Nullable	rr;						// Points to ResourceRecord in the mDNSCore cache
};

#pragma mark dnssec_original_t
typedef struct dnssec_original dnssec_original_t;
struct dnssec_original {						// The response that answers user's question.
	mDNSBool					answer_from_cache;		// Indicates If we get the answer from the cache, instead of refresh response from DNS server.
	DNSServiceErrorType			dns_error;				// DNSServiceErrorType when mDNSCore returns the answer.
	QC_result					qc_result;				// Event type for the current resource record including QC_add, QC_rmv, QC_supressed.
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark dnssec_cname_t
typedef struct dnssec_cname dnssec_cname_t;
struct dnssec_cname {							// The response that does not answer user's question, but provides a CNAME to continue the query
	mDNSu8 *	_Nullable		cname;					// The CNAME rdata.
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark dnssec_ds_t
typedef struct dnssec_ds dnssec_ds_t;
struct dnssec_ds {							// The response that answers DS query from mDNSResponder
	mDNSu16						key_tag;				// ID that identifies the DNSKEY that the current DS verifies.
	mDNSu8						algorithm;				// The algorithm of the DNSKEY that the current DS verifies.
	mDNSu8						digest_type;			// The digest type that is used to caluclate the current DS from the DNSKEY.
	mDNSu16						digest_length;			// The length of the digest.
	const mDNSu8 * _Nullable	digest;					// The DS rdata.
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

// DNSKEY flag bits
#define DNSKEY_FLAG_ZONE_KEY				0x100
#define DNSKEY_FLAG_SECURITY_ENTRY_POINT	0x1

#pragma mark dnssec_dnskey_t
typedef struct dnssec_dnskey dnssec_dnskey_t;
struct dnssec_dnskey {						// The response that answeres DNSKEY query from mDNSResponder.
	mDNSu16						flags;					// The bit flags for DNSKEY.
	mDNSu8						protocol;				// Should always be value 3.
	mDNSu8						algorithm;				// The type of crypoto algorithm that the current DNSKEY applies to.
	mDNSu16						key_tag;				// ID that identifies the current DNSKEY
	mDNSu16						public_key_length;		// The length of the DNSKEY.
	mDNSu8 * _Nullable			public_key;				// The DNSKEY rdata
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark dnssec_rrsig_t
typedef struct dnssec_rrsig dnssec_rrsig_t;
struct dnssec_rrsig {
	mDNSu16						type_covered;			// The DNS type that is covered by the current RRSIG
	mDNSu8						algorithm;				// The algorithm of DNSKEY that is used to generate the current RRSIG
	mDNSu8						labels;					// The number of labels of RRSIG's owner, used for wildcard matching
	mDNSu32						original_TTL;			// The original TTL of the records that are used to generate the current RRSIG, used to reconstruct the signed data
	mDNSu32						signature_expiration;	// The epoch time when the RRSIG expires.
	mDNSu32						signature_inception;	// The epoch time when the RRSIG should start to be valid to validate.
	mDNSu16						key_tag;				// The key tag that identifies which DNSKEY it uses to generate the current RRSIG.
	mDNSu16						signature_length;		// The length of the signature.
	mDNSu8 *	_Nullable		signer_name;			// The name of signer that signs the covered records
	mDNSu8 *	_Nullable		signature;				// The signature rdata
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark dnssec_nsec_t
typedef struct dnssec_nsec dnssec_nsec_t;
struct dnssec_nsec {
	mDNSu8 *	_Nullable		exist_domain_name;		// The owner name of records that exist before next_domain_name by canonical order in the zone.
	mDNSu8 *	_Nullable		next_domain_name;		// The owner name of records that exist after next_domain_name by canonical order in the zone.
	mDNSu8 *	_Nullable		type_bit_maps;			// The type bit map that indicates what DNS types are covered by the current NSEC record.
	mDNSu16						type_bit_maps_length;	// The length of the type bit map.
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark dnssec_nsec3_t
typedef struct dnssec_nsec3 dnssec_nsec3_t;
struct dnssec_nsec3 {
	mDNSu8						hash_algorithm;			// The hash algorithm that NSEC3 uses to generate the hash
	mDNSu8						flags;					// The NSEC3 flags
	mDNSu16						iterations;				// The iterations of hash operation on the data
	mDNSu8						salt_length;			// The length of the salt added when doing hash
	mDNSu8						hash_length;			// The length of the final hash result
	mDNSu16						type_bit_maps_length;	// The length of the type bit map.
	mDNSu8 *	_Nullable		salt;					// The salt added to the hash result for every iteration
	mDNSu8 *	_Nullable		next_hashed_owner_name;	// The binary-format hashed owner name of records that exist after the owner name of current NSEC3 record by canonical order in the zone.
	mDNSu8 *	_Nullable		type_bit_maps;			// The type bit map that indicates what DNS types are covered by the current NSEC3 record.
	char *		_Nullable		next_hashed_owner_name_b32;			// The b32-format string of hashed owner name
	mDNSu32						next_hashed_owner_name_b32_length;	// The length of next_hashed_owner_name_b32 string
	dnssec_rr_t					dnssec_rr;				// Store the answer returned from mDNSCore.
};

#pragma mark - Validation tree structures



#pragma mark nsecs_with_rrsig_t
typedef struct nsecs_with_rrsig nsecs_with_rrsig_t;
struct nsecs_with_rrsig {									// The NSEC response from DNS server that indicates the non-existence of the record in the query.
	list_t							nsec_and_rrsigs_same_name;		// list_t<one_nsec_with_rrsigs_t>, the list of one_nsec_with_rrsigs_t structure, each one_nsec_with_rrsigs_t represents one NSEC record with its corresponding RRSIG.
	list_t							wildcard_answers;				// list_t<dnssec_rr_t>, the list of dnssec_rr_t structure, each dnssec_rr_t represents one wildcard record.
	list_t							wildcard_rrsigs;				// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structure, each dnssec_rrsig_t represents one RRSIG that is used to validate the wildcard answer in wildcard_answers.
	ResourceRecord * 	_Nullable	negative_rr;					// The negative answer generated by mDNSResponder, that NSEC records try to prove.
	dnssec_validation_result_t		nsec_result;					// The validation result after validating the current NSEC records, it is only meaningful after we finish the validation.
};

#pragma mark one_nsec_with_rrsigs_t
typedef struct one_nsec_with_rrsigs one_nsec_with_rrsigs_t;
struct one_nsec_with_rrsigs {								// One NSEC record that form a complete NSEC response with other NSEC records.
	const mDNSu8 * _Nullable	owner_name;							// The onwer name of NSEC record, also indicates that this name does exist in the zone.
	dnssec_nsec_t				nsec_record;						// The dnssec_nsec_t that holds the NSEC record.
	list_t						rrsig_records;						// list_t<dnssec_rrsig_t>, the RRSIGs that generated from the current NSEC record.
};

#pragma mark nsec3s_with_rrsig_t
typedef struct nsec3s_with_rrsig nsec3s_with_rrsig_t;
struct nsec3s_with_rrsig {								// The NSEC3 response from DNS server that indicates the non-existence of the record in the query.
	list_t								nsec3_and_rrsigs_same_name; // list_t<one_nsec3_with_rrsigs_t>, the list of one_nsec3_with_rrsigs_t structure, each one_nsec3_with_rrsigs_t represents one NSEC3 record with its corresponding RRSIG.
	list_t								wildcard_answers;			// list_t<dnssec_rr_t>, the list of dnssec_rr_t structure, each dnssec_rr_t represents one wildcard record.
	list_t								wildcard_rrsigs;			// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structure, each dnssec_rrsig_t represents one RRSIG that is used to validate the wildcard answer in wildcard_answers.
	ResourceRecord *	_Nullable		negative_rr;				// The negative answer generated by mDNSResponder, that NSEC3 records try to prove.
	dnssec_validation_result_t			nsec3_result;				// The validation result after validating the current NSEC3 records, it is only meaningful after we finish the validation.
};

#pragma mark one_nsec3_with_rrsigs_t
typedef struct one_nsec3_with_rrsigs one_nsec3_with_rrsigs_t;
struct one_nsec3_with_rrsigs {							// One NSEC3 record that form a complete NSEC response with other NSEC records.
	const mDNSu8 * _Nullable	owner_name;							// The onwer name of NSEC3 record, also indicates that this name does exist in the zone.
	dnssec_nsec3_t				nsec3_record;						// The dnssec_nsec_t that holds the NSEC3 record.
	list_t						rrsig_records;						// list_t<dnssec_rrsig_t>, the RRSIGs that generated from the current NSEC3 record.
};

#pragma mark cnames_with_rrsig_t
typedef struct cnames_with_rrsig cnames_with_rrsig_t;
struct cnames_with_rrsig {			// The CNAME response from DNS server that indicates the current query name is a alias of another name.
	list_t						cname_records;	// list_t<dnssec_cname_t>, the list of dnssec_cname_t structure, each dnssec_cname_t represents one CNAME, in fact there should only be one CNAME in the list.
	list_t						rrsig_records;	// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structure, each dnssec_rrsig_t represents one RRSIG that i sused to validate the CNAME record in cname_records.
};

#pragma mark trust_anchor_t
typedef struct trust_anchors trust_anchors_t;
struct trust_anchors {			// The trust anchor structure that mDNSResponder loads during initialization, it stays unchanged during the life time of mDNSResponder.
	domainname	name;					// The owner name of the trust anchor
	mDNSu32		name_hash;				// The hash of the owner name, used to speed up name comparsion.
	list_t		dnskey_trust_anchors;	// list_t<dnssec_dnskey_t>, the list of dnssec_dnskey_t structures, the trust anchor could be a DNSKEY record. When mDNSResponder can use this trusted DNSKEY to validate the record, then the entire validation chain rooted in the validated record could be trusted.
	list_t		ds_trust_anchors;		// list_t<dnssec_ds_t>, the list of dnssec_ds_t structures, the trust anchor could also be a DS record. When mDNSResponder can use this trusted DS to match DNSKEY record, then the entire validation chain rooted in the validated DNSKEY record could be trusted.
};

#pragma mark response_type_t
typedef enum response_type {			// The response type for any DNS query in DNSSEC environment.
	unknown_response,			// The initial state, which means we have not received any response.
	original_response,			// The DNS server returns what the user expects, thus it is a original response for the query.
	cname_response,				// The DNS server returns a CNAME for user's NOn-CNAME query
	nsec_response,				// The DNS server returns a NSEC response trying to prove that the name or the record type does not exist.
	nsec3_response				// The DNS server returns a NSEC3 response trying to prove that the name or the record type does not exist.
} response_type_t;

#pragma mark originals_with_rrsig_t
typedef struct originals_with_rrsig originals_with_rrsig_t;
struct originals_with_rrsig {					// This structure holds the response that will be returned to the user after validation.
	union {												// The response can only be original_response/cname_response/nsec_response/nsec3_response.
		struct {
			list_t				original_records;		// list_t<dnssec_original_t>, the list of dnssec_original_t structures, each dnssec_original_t holds one response that user expects.
			list_t				rrsig_records;			// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structures, each dnssec_rrsig_t holds one RRSIG generated from the dnssec_original_t above.
			ResourceRecord * _Nullable negative_rr;		// The query may be suppressed by mDNSResponder, it is a denial of existence response that does not need NSEC/NSEC3 to validate, just put it in original.
			mDNSBool			suppressed_response;	// Indicates if the original response is a suppressed one.
		} original;										// Used when the type is original_response.
		cnames_with_rrsig_t		cname_with_rrsig;		// Used when the type is cname_response.
														// NSEC and NSEC3 RRs can not co-exist in a zone.
		nsecs_with_rrsig_t		nsecs_with_rrsig;		// Used when the type is nsec_response.
		nsec3s_with_rrsig_t		nsec3s_with_rrsig;		// Used when the type is nsec3_response.
	} u;
	response_type_t				type;					// original_response/cname_response/nsec_response/nsec3_response.
};

#pragma mark dses_with_rrsig_t
typedef struct dses_with_rrsig dses_with_rrsig_t;
struct dses_with_rrsig {						// This structure holds the DS response that DNSSEC handler queries for.
	union {												// The response can only be original_response/nsec_response/nsec3_response.
		struct {
			list_t				ds_records;				// list_t<dnssec_ds_t>, the list of dnssec_ds_t structure, each dnssec_ds_t holds one DS record that could be used to verifies one DNSKEY record
			list_t				rrsig_records;			// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structure, each dnssec_rrsig_t holds one RRSIG generated from the dnssec_ds_t above.
		} original;
														// NSEC and NSEC3 RRs can not co-exist in a zone.
		nsecs_with_rrsig_t		nsecs_with_rrsig;		// Used when the type is nsec_response.
		nsec3s_with_rrsig_t		nsec3s_with_rrsig;		// Used when the type is nsec3_response.
	} u;
	response_type_t				type;					// original_response/nsec_response/nsec3_response, CNAME can only be the leaf node, thus there should never be CNAME for DS query.
	mDNSBool					set_completed;			// Indicates if we have already get the DS records.
};

#pragma mark dnskeys_with_rrsig_t
typedef struct dnskeys_with_rrsig dnskeys_with_rrsig_t;
struct dnskeys_with_rrsig {					// This structure holds the DNSKEY response that DNSSEC handler queries for. The response can only be original_response, because both NSEC and NSEC3 indicate that DNSKEY does exist in order to validate the NSEC/NSEC3.
	list_t				dnskey_records;					// list_t<dnssec_dnskey_t>, the list of dnssec_dnskey_t structures, each dnssec_dnskey_t holds one DNSKEY that could be used to validate signer's records with the corresponding RRSIG.
	list_t				rrsig_records;					// list_t<dnssec_rrsig_t>, the list of dnssec_rrsig_t structures, each dnssec_rrsig_t holds one RRSIG generated from the dnssec_dnskey_t above.
	mDNSBool			set_completed;					// Indicates if we have already get the DNSKEY records.
};

#pragma mark dnssec_zone_t
// This structure represents one zone node in the validation tree. For example, if the user queries for the AAAA record
// of "www.internetsociety.org.", there will be 3 zone nodes at last:
// Root zone node:	"."							DNSKEY
// Zone node:		"org."						DNSKEY/DS
// Zone node:		"internetsociety.org."		DNSKEY/DS
// Response:		"www.internetsociety.org."	AAAA
// Each node contains 2 kinds of records: DNSKEY and DS records
typedef struct dnssec_zone dnssec_zone_t;
struct dnssec_zone {
	// general field that is used to fecth records
	domainname					domain_name;			// DNS representation of the zone name.
	mDNSu32						name_hash;				// The name hash to speed up name comparison.

	// dnssec resource records
	// DS record
	QueryRecordClientRequest	ds_request;				// The DS request handler
	mDNSBool					ds_request_started;		// Indicates if we issued the DS request, sometimes we do not want to issue query such as we are in root "." node, and root node does not have DS record.
	mDNSBool					dses_initialized;		// Indicate if the DS list is initialized
	dses_with_rrsig_t			dses_with_rrsig;		// list_t<dses_with_rrsig_t>, the list of dses_with_rrsig_t structures, each dses_with_rrsig_t holds the DS records and the corresponding RRSIG records for the current zone.
	mDNSs32						last_time_ds_add;		// last time that DS records are added
	mDNSs32						last_time_ds_rmv;		// last time that DS records are removed

	// DNSKEY record
	QueryRecordClientRequest	dnskey_request;			// The DNSKEY request handler
	mDNSBool					dnskey_request_started;	// Indicates if we issue the DNSKEY request, sometimes we do not issue the query because the current zone has a trust anchor for DNSKEY.
	dnskeys_with_rrsig_t		dnskeys_with_rrsig;		// list_t<dnssec_dnskey_t>, the list of dnskeys_with_rrsig structures, each dnssec_dnskey_t holds the DNSKEY records and the corresponding RRSIG records for the current zone.
	mDNSs32						last_time_dnskey_add;	// last time that DNSKEY records are added
	mDNSs32						last_time_dnskey_rmv;	// last time that DNSKEY records are removed

	// The current zone may have trust anchor installed in the system
	const trust_anchors_t * _Nullable	trust_anchor;	// list_t<trust_anchor_t>, the list of trust_anchor_t structures, each trust_anchor_t represent one trust anchor.
};

#pragma mark original_request_parameters_t
typedef struct original_request_parameters original_request_parameters_t;
struct original_request_parameters {			// This structure contains the original request paramters set by the user.
	mDNSu32						request_id;
	domainname					question_name;
	mDNSu32						question_name_hash;
	mDNSu16						question_type;
	mDNSu16						question_class;
	mDNSInterfaceID _Nullable	interface_id;
	mDNSs32						service_id;
	mDNSu32						flags;
	mDNSBool					append_search_domains;
	mDNSs32						pid;
	mDNSu8						uuid[UUID_SIZE];
	mDNSs32						uid;
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	audit_token_t				peer_audit_token;
	mDNSBool					has_peer_audit_token;
	audit_token_t				delegate_audit_token;
	mDNSBool					has_delegate_audit_token;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	mDNSu8						resolver_uuid[UUID_SIZE];
	mDNSBool					need_encryption;
	mdns_dns_service_id_t		custom_id;
#endif
	QueryRecordResultHandler _Nullable	user_handler;
	void *	_Nullable			user_context;
};

#pragma mark denial_of_existence_records_t
typedef struct denial_of_existence_records denial_of_existence_records_t;
struct denial_of_existence_records {
	list_t						resource_records;			//list_t<ResourceRecord>;
};

#pragma mark original_t
typedef struct original original_t;
struct original {													// This structure contains all the useful information about the user's original request.
	original_request_parameters_t				original_parameters;		// The original paramters getting from the user
	originals_with_rrsig_t						original_result_with_rrsig;	// The original response that will be returned to the user.
	const trust_anchors_t *			_Nullable	original_trust_anchor;		// It is possible that the returned original response is a trust anchor installed.
	mDNSs32										last_time_add;				// Last time that originals_with_rrsig_t records are added.
	mDNSs32										last_time_rmv;				// Last time that originals_with_rrsig_t records are removed.
};

#pragma mark returned_answers_t
typedef struct returned_answers returned_answers_t;
struct returned_answers {			// This structure contains all the records that are returned to the user, these information is tracked to properly deliver ADD/RMV event to the user
	list_t					answers; 		// list_t<ResourceRecord *>, the list of "ResourceRecord *" pointers, each pointer points to a ResourceRecord in the cache that has been returned to the user.
	dnssec_result_t			dnssec_result;	// The dnssec_result_t that has been returned to the user.
	DNSServiceErrorType		error;			// The returned DNSServiceErrorType
	response_type_t			type;			// The type of the returned answer, it could be original_response(including suppressed case)/nsec_response/nsec3_response
};

#pragma mark dnssec_context_t
// This structure contains the DNSSEC context that is needed to track additional information that is not provided by
// mDNSCore, each DNSSEC-enabled DNS request would have a seperated DNSSEC context.
typedef struct dnssec_context dnssec_context_t;
struct dnssec_context {
	// Necessary request
	QueryRecordClientRequest *		_Nonnull	me;								// The request of the question that we are currently working on.
	QueryRecordClientRequest					request_to_follow_cname;		// An idle request unless there is a need to follow the CNAME reference, and start a sub request.

	// Zone records that could be used to validate records.
	list_t										zone_chain;						// list_t<dnssec_zone_t>, the validation tree consists of zone nodes from root to leaf.

	// original request fields
	original_t original;														// Information about the user's original request.

	// denial of existence fields
	denial_of_existence_records_t * _Nullable	denial_of_existence_records;	// It is a temporary field that is used to pass the NSEC/NSEC3 records to the DNSSEC handler, will be cleared after running DNSSEC handler.

	// save the records that are returned to the user
	returned_answers_t							returned_answers;				// The records that have been returned to the user.

	// DNSSEC context pointer
	dnssec_context_t *				_Nullable	primary_dnssec_context;			// This points to the initial DNSSEC context of the first query coming from the user, i.e. the first name in the CNAME chain.
	dnssec_context_t *				_Nullable	subtask_dnssec_context;			// If the DNSSEC-enabled DNS query has CNAMEs, this field is used to create another new DNSSEC context that resolves and validates the new CNAME.
};


#pragma mark - Functions



#pragma mark - dns_type_*_t records parsing



#pragma mark parsse_dns_type_cname_t
mDNSexport void
parsse_dns_type_cname_t(const void * const _Nonnull rdata, mDNSu8 * _Nullable * const _Nonnull out_cname);

#pragma mark parse_dns_type_ds_t
mDNSexport mDNSBool
parse_dns_type_ds_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nullable	out_key_tag,
	mDNSu8 * const		_Nullable	out_algorithm,
	mDNSu8 * const		_Nullable	out_digest_type,
	mDNSu16 * const		_Nullable	out_digest_length,
	const mDNSu8 * _Nonnull * const _Nullable	out_digest);

#pragma mark parse_dns_type_dnskey_t
mDNSexport mDNSBool
parse_dns_type_dnskey_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nullable	out_flags,
	mDNSu8 * const		_Nullable	out_protocol,
	mDNSu8 * const		_Nullable	out_algorithm,
	mDNSu16 * const		_Nullable	out_public_key_length,
	mDNSu8 * _Nonnull * const _Nullable out_public_key);

#pragma mark parse_dns_type_rrsig_t
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
	mDNSu8 * _Nonnull * const _Nullable out_signature);

#pragma mark parse_dns_type_nsec_t
mDNSexport mDNSBool
parse_dns_type_nsec_t(
	const void * const	_Nonnull	rdata,
	const mDNSu16					rdata_length,
	mDNSu16 * const		_Nonnull	out_type_bit_maps_length,
	mDNSu8 * _Nonnull * const _Nullable out_next_domain_name,
	mDNSu8 * _Nonnull * const _Nullable out_type_bit_maps);

#pragma mark parse_dns_type_nsec3_t
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
	mDNSu8 * _Nonnull * const _Nullable out_type_bit_maps);

#pragma mark get_covered_type_of_dns_type_rrsig_t
mDNSexport mDNSu16
get_covered_type_of_dns_type_rrsig_t(const void * const _Nonnull rdata);

// dnssec_rr_t function prototypes
#pragma mark - dnssec_rr_t functions

mDNSexport void
initialize_dnssec_rr_t(dnssec_rr_t * const _Nonnull dnssec_rr, ResourceRecord * const _Nonnull rr);

mDNSexport void
uninitialize_dnssec_rr_t(dnssec_rr_t * const _Nonnull dnssec_rr);

mDNSexport mDNSBool
equal_dnssec_rr_t(const dnssec_rr_t * const _Nonnull left, const dnssec_rr_t * const _Nonnull right);

mDNSexport void
print_dnssec_rr_t(const dnssec_rr_t * const _Nonnull dnssec_rr, mDNSu8 num_of_tabs);

// dnssec_original_t function prototypes
#pragma mark - dnssec_original_t functions

mDNSexport void
initialize_dnssec_original_t(
	dnssec_original_t * const		_Nonnull	original,
	ResourceRecord * const			_Nonnull	rr,
	const mDNSBool								answer_from_cache,
	const DNSServiceErrorType					dns_error,
	const QC_result								qc_result);

mDNSexport void
uninitialize_dnssec_original_t(dnssec_original_t * const _Nonnull original);

mDNSexport void
print_dnssec_original_t(const dnssec_original_t * const _Nonnull original, mDNSu8 num_of_tabs);

#pragma mark - dnssec_cname_t functions

mDNSexport void
initialize_dnssec_cname_t(dnssec_cname_t * const _Nonnull cname, ResourceRecord * const _Nonnull rr);

mDNSexport void
uninitialize_dnssec_cname_t(dnssec_cname_t * const _Nonnull cname);

mDNSexport void
print_dnssec_cname_t(const dnssec_cname_t * const _Nonnull cname, mDNSu8 num_of_tabs);

#pragma mark - dnssec_ds_t functions

mDNSexport mDNSBool
initialize_dnssec_ds_t(dnssec_ds_t * const _Nonnull ds, ResourceRecord * const _Nonnull rr);

mDNSexport mDNSBool
equals_dnssec_ds_t(const dnssec_ds_t * const _Nonnull left, const dnssec_ds_t * const _Nonnull right);

mDNSexport void
uninitialize_dnssec_ds_t(dnssec_ds_t * const _Nonnull ds);

mDNSexport void
print_dnssec_ds_t(const dnssec_ds_t * const _Nonnull ds, mDNSu8 num_of_tabs);

#pragma mark - dnssec_dnskey_t functions

mDNSexport mDNSBool
initialize_dnssec_dnskey_t(dnssec_dnskey_t * const _Nonnull dnskey, ResourceRecord * const _Nonnull rr);

mDNSexport mDNSBool
equals_dnssec_dnskey_t(const dnssec_dnskey_t * const _Nonnull left, const dnssec_dnskey_t * const _Nonnull right);

mDNSexport void
uninitialize_dnssec_dnskey_t(dnssec_dnskey_t * const _Nonnull dnskey);

mDNSexport void
print_dnssec_dnskey_t(const dnssec_dnskey_t * const _Nonnull dnskey, mDNSu8 num_of_tabs);

#pragma mark - dnssec_rrsig_t functions

mDNSexport mDNSBool
initialize_dnssec_rrsig_t(dnssec_rrsig_t * const _Nonnull rrsig, ResourceRecord * const _Nonnull rr);

mDNSexport void
uninitialize_dnssec_rrsig_t(dnssec_rrsig_t * const _Nonnull rrsig);

mDNSexport void
print_dnssec_rrsig_t(const dnssec_rrsig_t * const _Nonnull rrsig, mDNSu8 num_of_tabs);

#pragma mark - dnssec_nsec_t functions

mDNSexport mDNSBool
initialize_dnssec_nsec_t(dnssec_nsec_t * const _Nonnull nsec, ResourceRecord * const _Nonnull rr);

mDNSexport void
uninitialize_dnssec_nsec_t(dnssec_nsec_t * const _Nonnull nsec);

mDNSexport void
print_dnssec_nsec_t(const dnssec_nsec_t * const _Nonnull nsec, mDNSu8 num_of_tabs);

#pragma mark - dnssec_nsec3_t functions

mDNSexport mDNSBool
initialize_dnssec_nsec3_t(dnssec_nsec3_t * const _Nonnull nsec3, ResourceRecord * const _Nonnull rr);

mDNSexport void
uninitialize_dnssec_nsec3_t(dnssec_nsec3_t * const _Nonnull nsec3);

mDNSexport void
print_dnssec_nsec3_t(const dnssec_nsec3_t * const _Nonnull nsec3, mDNSu8 num_of_tabs);

#pragma mark - nsecs_with_rrsig_t functions

mDNSexport mStatus
initialize_nsecs_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs);

mDNSexport void
uninitialize_nsecs_with_rrsig_t(nsecs_with_rrsig_t * const _Nonnull nsecs);

mDNSexport void
print_nsecs_with_rrsig_t(const nsecs_with_rrsig_t * const _Nonnull nsecs, mDNSu8 num_of_tabs);

# pragma mark - one_nsec_with_rrsigs_t functions

mDNSexport mDNSBool
initialize_one_nsec_with_rrsigs_t(
	one_nsec_with_rrsigs_t * const	_Nonnull	one_nsec_with_rrsigs,
	ResourceRecord * const 			_Nonnull	rr);

mDNSexport void
uninitialize_one_nsec_with_rrsigs_t(one_nsec_with_rrsigs_t * const	_Nonnull one_nsec_with_rrsigs);

# pragma mark - one_nsec3_with_rrsigs_t functions

mDNSexport mDNSBool
initialize_one_nsec3_with_rrsigs_t(
	one_nsec3_with_rrsigs_t * const _Nonnull	one_nsec3_with_rrsigs,
	ResourceRecord * const 			_Nonnull	rr);

mDNSexport void
uninitialize_one_nsec3_with_rrsigs_t(one_nsec3_with_rrsigs_t * const _Nonnull one_nsec3_with_rrsigs);

#pragma mark - nsec3s_with_rrsig_t functions

mDNSexport mStatus
initialize_nsec3s_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s);

mDNSexport void
uninitialize_nsec3s_with_rrsig_t(nsec3s_with_rrsig_t * const _Nonnull nsec3s);

mDNSexport void
print_nsec3s_with_rrsig_t(const nsec3s_with_rrsig_t * const _Nonnull nsec3s, mDNSu8 num_of_tabs);

#pragma mark - cnames_with_rrsig_t

mDNSexport void
initialize_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cname);

mDNSexport void
uninitialize_cname_with_rrsig_t(cnames_with_rrsig_t * const _Nonnull cname);

mDNSexport void
print_cname_with_rrsig_t(const cnames_with_rrsig_t * const _Nonnull cname, mDNSu8 num_of_tabs);

#pragma mark - response_type_t functions

mDNSexport const char * _Nonnull
response_type_value_to_string(response_type_t type);

#pragma mark - originals_with_rrsig_t

mDNSexport void
initialize_originals_with_rrsig_t(originals_with_rrsig_t * const _Nonnull original, const response_type_t type);

mDNSexport void
uninitialize_originals_with_rrsig_t(originals_with_rrsig_t * const _Nonnull original);

mDNSexport mDNSBool
contains_rrsig_in_originals_with_rrsig_t(const originals_with_rrsig_t * const _Nonnull original);

mDNSexport void
print_originals_with_rrsig_t(const originals_with_rrsig_t * const _Nonnull original, mDNSu8 num_of_tabs);

#pragma mark - dses_with_rrsig_t functions

mDNSexport void
initialize_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull ds, const response_type_t type);

mDNSexport void
uninitialize_dses_with_rrsig_t(dses_with_rrsig_t * const _Nonnull ds);

mDNSexport mDNSBool
contains_rrsig_in_dses_with_rrsig_t(const dses_with_rrsig_t * const _Nonnull ds);

mDNSexport void
print_dses_with_rrsig_t(const dses_with_rrsig_t * const _Nonnull ds, mDNSu8 num_of_tabs);

#pragma mark - dses_with_rrsig_t functions

mDNSexport void
initialize_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskey);

mDNSexport void
uninitialize_dnskeys_with_rrsig_t(dnskeys_with_rrsig_t * const _Nonnull dnskey);

mDNSexport mDNSBool
contains_rrsig_in_dnskeys_with_rrsig_t(const dnskeys_with_rrsig_t * const _Nonnull dnskey);

mDNSexport void
print_dnskeys_with_rrsig_t(const dnskeys_with_rrsig_t * const _Nonnull dnskey, mDNSu8 num_of_tabs);

mDNSexport void
print_original_request_parameters_t(const original_request_parameters_t * const _Nonnull parameters, mDNSu8 num_of_tabs);

#pragma mark - dnssec_zone_t functions

mDNSexport void
initialize_dnssec_zone_t(
	dnssec_zone_t * const	_Nonnull	zone,
	const mDNSu8 * const	_Nonnull	domain_name);

mDNSexport void
uninitialize_dnssec_zone_t(dnssec_zone_t * const _Nonnull zone);

mDNSexport void
stop_and_clean_dnssec_zone_t(dnssec_zone_t * const _Nonnull zone);

mDNSexport void
print_dnssec_zone_t(const dnssec_zone_t * const _Nonnull zone, mDNSu8 num_of_tabs);

#pragma mark - returned_answers_t

mDNSexport void
initialize_returned_answers_t(
	returned_answers_t * const	_Nonnull	returned_answers,
	const dnssec_result_t					dnssec_result,
	const DNSServiceErrorType				error);

mDNSexport void
uninitialize_returned_answers_t(returned_answers_t * const _Nonnull returned_answers);

mDNSexport void
print_returned_answers_t(const returned_answers_t * const _Nonnull returned_answers, mDNSu8 num_of_tabs);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_v2_STRUCTS_H
