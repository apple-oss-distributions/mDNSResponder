//
//	dnssec_v2_helper.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_v2_HELPER_H
#define DNSSEC_v2_HELPER_H

#pragma mark - Includes
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#pragma mark - Macros

// DNSSEC helper

// Used to get the primary question from the current request, it is possible that the current request is started by
// the DNSSEC handler to follow the CNAME, so the primary question should be get from primary_dnssec_context field.
#define GET_PRIMARY_DNSSEC_CONTEXT(C)			((C)->primary_dnssec_context == mDNSNULL) ? \
													(C) : ((C)->primary_dnssec_context)
#define GET_PRIMARY_REQUEST(C)					(GET_PRIMARY_DNSSEC_CONTEXT(C))->me
#define GET_PRIMARY_QUESTION(C)					(&((GET_PRIMARY_REQUEST(C))->op.q))
#define GET_REQUEST_ID(C)						((GET_PRIMARY_REQUEST(C))->op.reqID)
#define GET_QUESTION(C)							(&((C)->me->op.q))
#define GET_QUESTION_ID_FROM_Q(Q)				(mDNSVal16((Q)->TargetQID))
#define GET_QUESTION_ID(C)						(GET_QUESTION_ID_FROM_Q(GET_QUESTION(C)))

// string helper
#define DOMAIN_NAME_EQUALS(A, B)				SameDomainName((const domainname *)(A), (const domainname *)(B))
#define DOMAIN_NAME_LENGTH(NAME)				DomainNameLength((const domainname *)(NAME))
#define IS_UPPER_CASE(CH)						((CH) >= 'A') && ((CH) <= 'Z')
#define IS_LOWER_CASE(CH)						((CH) >= 'a') && ((CH) <= 'z')
#define TO_LOWER_CASE(CH)						((CH) + ('a' - 'A'))

// print helper
#define DNS_TYPE_STR(TYPE)						DNSTypeName((TYPE))
#define NUM_OF_SPACES_PER_TAB					4
#define TAB_STR									"%{public}*s"
#define TAB_PARAM(NUM_OF_TABS)					((NUM_OF_TABS) * (NUM_OF_SPACES_PER_TAB)), ""
// BASE64_STR should be used with BASE64_PARAM
#define BASE64_STR								"%{private, mask.hash}.10s%s"
#define BASE64_PARAM(BASE64)					(BASE64), strlen(BASE64) < 11 ? "" : "..."

#pragma mark - Functions



#pragma mark deep_copy_resource_record
/*!
 *	@brief
 *		Deep copy the record including the name and the rdata.
 *	@param dst
 *		The copy destination.
 *	@param src
 *		The copy source.
 *	@return
 *		Returns mStatus_NoError if no error occurs, other error codes if error occurs
 *	@discussion
 *		Remember to free the malloced ResourceRecord->name and ResourceRecord->rdata.
 */
mDNSexport mStatus
deep_copy_resource_record(ResourceRecord * const _Nonnull dst, const ResourceRecord * const _Nonnull src);

#pragma mark free_resource_record_deep_copied
/*!
 *	@brief
 *		Free the malloced memory in the ResourceRecord.
 *	@param rr
 *		The ResourceRecord that has malloced memory inside.
 *	@discussion
 *		It will only free malloced fields in ResourceRecord, remember to free ResourceRecord itself.
 */
mDNSexport void
free_resource_record_deep_copied(ResourceRecord * const _Nonnull rr);

#pragma mark is_root_domain
/*!
 *	@brief
 *		Given a  DNS format DNS name, determine if it is root.
 *	@param domain_name
 *		The DNS format domain name.
 *	@return
 *		Returns true if the domain is root, otherwise return false.
 */
mDNSexport mDNSBool
is_root_domain(const mDNSu8 * const _Nonnull domain_name);

#pragma mark is_a_subdomain_of_b
/*!
 *	@brief
 *		Determine if a_name is a sub domain of b_name
 *	@param a_name
 *		The child zone or sub domain.
 *	@param b_name
 *		The parent zone.
 *	@return
 *		Returns true if a_name is a subdomain of b_name
 */
mDNSexport mDNSBool
is_a_subdomain_of_b(const mDNSu8 * const _Nonnull a_name, const mDNSu8 * const _Nonnull b_name);

#pragma mark resource_records_equal
/*!
 *	@brief
 *		Determine if two records are identical.
 *	@return
 *		Returns true if two records are identical, false if they are not equal.
 */
mDNSexport mDNSBool
resource_records_equal(
	const mDNSu16 rr_type_0,				const mDNSu16 rr_type_1,
	const mDNSu16 rr_class_0,				const mDNSu16 rr_clasee_1,
	const mDNSu16 rdata_length_0,			const mDNSu16 rdata_length_1,
	const mDNSu32 name_hash_0,				const mDNSu32 name_hash_1,
	const mDNSu32 rdata_hash_0,				const mDNSu32 rdata_hash_1,
	const mDNSu8 * const _Nonnull name_0,	const mDNSu8 * const _Nonnull name_1,
	const mDNSu8 * const _Nonnull rdata_0,	const mDNSu8 * const _Nonnull rdata_1);

#pragma mark dnssec_algorithm_value_to_string
/*!
 *	@brief
 *		Convert DNSKEY type to string description.
 *	@param algorithm
 *		The DNSKEY type.
 *	@return
 *		The corresponding string description of the DNSKEY type.
 */
mDNSexport const char * _Nonnull
dnssec_algorithm_value_to_string(const mDNSu8 algorithm);

#pragma mark dnssec_dnskey_flags_to_string
/*!
 *	@brief
 *		Convert DS hash type to string description.
 *	@param digest_type
 *		The DS digest type.
 *	@return
 *		The corresponding string description of the DS digest type.
 */
mDNSexport const char * _Nonnull
dnssec_digest_type_value_to_string(const mDNSu8 digest_type);

#pragma mark deep_copy_resource_record
/*!
 *	@brief
 *		Convert DNSKEY flags to string description.
 *	@param flags
 *		The DNSKEY flags field
 *	@param buffer
 *		The string buffer that stores the converted string description.
 *	@param buffer_size
 *		The total size of the buffer.
 *	@return
 *		The pointer to the start of the buffer, aka the start of the description.
 */
mDNSexport const char * _Nonnull
dnssec_dnskey_flags_to_string(const mDNSu16 flags, char * const _Nonnull buffer, const mDNSu32 buffer_size);

#pragma mark dnssec_epoch_time_to_date_string
/*!
 *	@brief
 *		Convert epoch time field in RRSIG to string description.
 *	@param epoch
 *		The epoch time.
 *	@param buffer
 *		The string buffer that stores the converted string description.
 *	@param buffer_size
 *		The total size of the buffer.
 *	@return
 *		The pointer to the start of the buffer, aka the start of the description.
 */
mDNSexport const char * _Nonnull
dnssec_epoch_time_to_date_string(const mDNSu32 epoch, char * const _Nonnull buffer, const mDNSu32 buffer_size);

#pragma mark dnssec_nsec3_flags_to_string
/*!
 *	@brief
 *		Convert NSEC3 flags to string description.
 *	@param flags
 *		The DNSKEY flags field
 *	@param buffer
 *		The string buffer that stores the converted string description.
 *	@param buffer_size
 *		The total size of the buffer.
 *	@return
 *		The pointer to the start of the buffer, aka the start of the description.
 */
mDNSexport const char * _Nonnull
dnssec_nsec3_flags_to_string(const mDNSu8 flags, char * const _Nonnull buffer, const mDNSu32 buffer_size);

#pragma mark get_number_of_labels
/*!
 *	@brief
 *		Count the number of labels for the given DNS format name.
 *	@name
 *		The DNS format name.
 *	@return
 *		The number of labels.
 */
mDNSexport mDNSu8
get_number_of_labels(const mDNSu8 * _Nonnull name);

#pragma mark to_lowercase_if_char
/*!
 *	@brief
 *		Convert the character to lower string if it is alphbeta.
 *	@param ch
 *		The character.
 *	@return
 *		The converted character.
 */
mDNSexport mDNSu8
to_lowercase_if_char(const mDNSu8 ch);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_v2_HELPER_H
