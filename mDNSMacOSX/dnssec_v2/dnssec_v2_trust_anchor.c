//
//	dnssec_v2_trust_anchor.c
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "DNSCommon.h"
#include "dnssec_v2_trust_anchor.h"
#include "dnssec_v2_crypto.h"
#include "dnssec_v2_trust_anchor.h"
#include "dnssec_v2_helper.h"
#include "dnssec_v2_log.h"

static list_t trust_anchors; // list_t<trust_anchor_t>

// trust anchors egtting from https://www.iana.org/dnssec/files
typedef struct trust_anchor_ds trust_anchor_ds_t;
struct trust_anchor_ds {
	domainname	name;
	mDNSu16		key_tag;
	mDNSu8		algorithm;
	mDNSu8		digest_type;
	mDNSu16		digest_length;
	mDNSu8		digest[MAX_HASH_OUTPUT_SIZE];
};

// hard code root trust anchor
static const trust_anchor_ds_t trusted_trust_anchor[] = {
	{
		.name			= {
			.c 	= {
				0
			}
		},
		.key_tag		= 19036,
		.algorithm		= 8,
		.digest_type	= 2,
		.digest_length	= 32,
		.digest			= {
			0x49, 0xAA, 0xC1, 0x1D, 0x7B, 0x6F, 0x64, 0x46, 0x70, 0x2E, 0x54, 0xA1, 0x60, 0x73, 0x71, 0x60, 0x7A, 0x1A,
			0x41, 0x85, 0x52, 0x00, 0xFD, 0x2C, 0xE1, 0xCD, 0xDE, 0x32, 0xF2, 0x4E, 0x8F, 0xB5
		}
	},
	{
		.name			= {
			.c 	= {
				0
			}
		},
		.key_tag		= 20326,
		.algorithm		= 8,
		.digest_type	= 2,
		.digest_length	= 32,
		.digest			= {
			0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84, 0x58, 0xE8,
			0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D
		}
	},
	// This dnssec.test. trust anchor is set to run local DNSSEC test by using dnssdutil server
	{
		.name			= {
			.c 	= {
				6, 'd', 'n', 's', 's', 'e', 'c', 4, 't', 'e', 's' ,'t', 0
			}
		},
		.key_tag		= 36815,
		.algorithm		= 14,
		.digest_type	= 2,
		.digest_length	= 32,
		.digest			= {
			0x23, 0x51, 0xA5, 0x30, 0x3C, 0xD1, 0x68, 0x26, 0x70, 0x64, 0xF1, 0xED, 0x82, 0x53, 0x59, 0x82, 0x05, 0xE7,
			0xDF, 0xBE, 0xE1, 0x8E, 0xBA, 0xA9, 0x40, 0xDD, 0x1F, 0x3F, 0x49, 0x97, 0xE3, 0x20
		}
	}
};

//======================================================================================================================
//	trust_anchors_t functions
//======================================================================================================================

//======================================================================================================================
//	initialize_trust_anchors_t
//======================================================================================================================

mDNSexport void
initialize_trust_anchors_t(trust_anchors_t * const _Nonnull anchor, const mDNSu8 *const _Nonnull zone_name) {
	memcpy(anchor->name.c, zone_name, DOMAIN_NAME_LENGTH(zone_name));
	anchor->name_hash = DomainNameHashValue(&anchor->name);
	list_init(&anchor->dnskey_trust_anchors, sizeof(dnssec_dnskey_t));
	list_init(&anchor->ds_trust_anchors, sizeof(dnssec_ds_t));
}

//======================================================================================================================
//	uninitialize_trust_anchors_t
//======================================================================================================================

mDNSexport void
uninitialize_trust_anchors_t(trust_anchors_t * const _Nonnull anchor) {
	list_uninit(&anchor->dnskey_trust_anchors);
	list_uninit(&anchor->ds_trust_anchors);
}

//======================================================================================================================
//	print_trust_anchors_t
//======================================================================================================================

mDNSexport void
print_trust_anchors_t(const trust_anchors_t * const _Nonnull anchor, mDNSu8 num_of_tabs) {
	log_debug(TAB_STR "Name: " PRI_DM_NAME, TAB_PARAM(num_of_tabs), DM_NAME_PARAM(&anchor->name));
	log_debug(TAB_STR "Name Hash: %u", TAB_PARAM(num_of_tabs), anchor->name_hash);

	const list_t * const dnskey_records = &anchor->dnskey_trust_anchors;
	const list_t * const ds_records		= &anchor->ds_trust_anchors;

	log_debug(TAB_STR "DNSKEY Trust Anchor:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(dnskey_records); !list_has_ended(dnskey_records, node); node = list_next(node)) {
		const dnssec_dnskey_t * const dnssec_dnskey = (dnssec_dnskey_t *)node->data;
		print_dnssec_dnskey_t(dnssec_dnskey, num_of_tabs + 1);
	}

	log_debug(TAB_STR "DS Trust Anchor:", TAB_PARAM(num_of_tabs));
	for (list_node_t *node = list_get_first(ds_records); !list_has_ended(ds_records, node); node = list_next(node)) {
		const dnssec_ds_t * const dnssec_ds = (dnssec_ds_t *)node->data;
		print_dnssec_ds_t(dnssec_ds, num_of_tabs + 1);
	}
}

//======================================================================================================================
//	init_and_load_trust_anchors
//		load trust anchor when mDNSResponder initializes
//======================================================================================================================

mDNSexport mStatus
init_and_load_trust_anchors(void) {
	mStatus				error;
	list_t *			trust_anchor_list			= &trust_anchors;

	list_init(trust_anchor_list, sizeof(trust_anchors_t));

	for (int i = 0, limit = sizeof(trusted_trust_anchor) / sizeof(trust_anchor_ds_t); i < limit; i++) {
		const trust_anchor_ds_t * const hardcoded_trust_anchor_ds		= &trusted_trust_anchor[i];
		trust_anchors_t *				trust_anchors_from_same_zone	= get_trust_anchor_with_name(hardcoded_trust_anchor_ds->name.c);
		trust_anchors_t	*				new_trust_anchors_initialized	= mDNSNULL;
		dnssec_ds_t * 					ds_to_insert;
		if (trust_anchors_from_same_zone == mDNSNULL) {
			error = list_append_uinitialized(trust_anchor_list, sizeof(trust_anchors_t), (void **)&trust_anchors_from_same_zone);
			require_quiet(error == mStatus_NoError, for_loop_exit);

			initialize_trust_anchors_t(trust_anchors_from_same_zone, hardcoded_trust_anchor_ds->name.c);
			new_trust_anchors_initialized = trust_anchors_from_same_zone;
		}

		error = list_append_uinitialized(&trust_anchors_from_same_zone->ds_trust_anchors, sizeof(dnssec_ds_t), (void **)&ds_to_insert);
		require_quiet(error == mStatus_NoError, for_loop_exit);

		ds_to_insert->key_tag		= hardcoded_trust_anchor_ds->key_tag;
		ds_to_insert->algorithm		= hardcoded_trust_anchor_ds->algorithm;
		ds_to_insert->digest_type	= hardcoded_trust_anchor_ds->digest_type;
		ds_to_insert->digest_length = hardcoded_trust_anchor_ds->digest_length;
		ds_to_insert->digest		= hardcoded_trust_anchor_ds->digest;

		ds_to_insert->dnssec_rr.rr_type			= kDNSType_DS;
		ds_to_insert->dnssec_rr.rr_class		= 1; // IN_CLASS
		ds_to_insert->dnssec_rr.rdata_length	= 36; // 4 + 32
		ds_to_insert->dnssec_rr.name_hash		= DomainNameHashValue(&trust_anchors_from_same_zone->name);
		memcpy(ds_to_insert->dnssec_rr.name.c, trust_anchors_from_same_zone->name.c, DomainNameLength(&trust_anchors_from_same_zone->name));
		ds_to_insert->dnssec_rr.rdata_hash		= 0; // fake value
		ds_to_insert->dnssec_rr.rdata			= mDNSNULL; // fake value

	for_loop_exit:
		if (error != mStatus_NoError) {
			if (new_trust_anchors_initialized != mDNSNULL) {
				list_delete_node_with_data_ptr(trust_anchor_list, new_trust_anchors_initialized);
			}
			break;
		}
	}

	return error;
}

//======================================================================================================================
//	get_trust_anchor_with_name
//		get the trust anchor with the corresponding zone name
//======================================================================================================================

mDNSexport trust_anchors_t * _Nullable
get_trust_anchor_with_name(const mDNSu8 * _Nonnull const name) {
	list_t *trust_anchor_list = &trust_anchors;
	mDNSu32 name_hash = DomainNameHashValue((domainname *)name);

	for (list_node_t *trust_anchor_node = list_get_first(trust_anchor_list);
		!list_has_ended(trust_anchor_list, trust_anchor_node);
		trust_anchor_node = list_next(trust_anchor_node)) {

		trust_anchors_t * trust_anchor = (trust_anchors_t *)trust_anchor_node->data;

		if (trust_anchor->name_hash == name_hash && DOMAIN_NAME_EQUALS(name, trust_anchor->name.c)) {
			return trust_anchor;
		}
	}

	return mDNSNULL;
}

//======================================================================================================================
//	unint_trust_anchors
//		free the trust anchor list when mDNSResponder exits
//======================================================================================================================

mDNSexport void
uninit_trust_anchors(void) { // list_t <trust_anchors_t>
	list_t *trust_anchor_list = &trust_anchors;
	for (list_node_t *trust_anchor_node = list_get_first(trust_anchor_list);
			!list_has_ended(trust_anchor_list, trust_anchor_node);
			trust_anchor_node = list_next(trust_anchor_node)) {

		trust_anchors_t * trust_anchor = (trust_anchors_t *)trust_anchor_node->data;
		uninitialize_trust_anchors_t(trust_anchor);
	}

	list_uninit(trust_anchor_list);
}

//======================================================================================================================
//	trust_anchor_can_be_reached
//		check if there is a path in validation tree from leaf(the expected answer/NSEC/NSEC3) to the trust anchor.
//	If so, we can start the validation process.
//======================================================================================================================

mDNSexport mDNSBool
trust_anchor_can_be_reached(dnssec_context_t * const _Nonnull context) {
	list_t *					zones		= &context->zone_chain;
	dnssec_zone_t *				zone		= mDNSNULL;
	originals_with_rrsig_t *	original	= &context->original.original_result_with_rrsig;
	const list_node_t *			last_node;
	mDNSu32						request_id = context->original.original_parameters.request_id;

	// If the original response has trust anchor, just match itto see if it is trusted
	if (context->original.original_trust_anchor != mDNSNULL) {
		log_default("[R%u] trust_anchor_can_be_reached? Yes, trust anchor found for original response", request_id);
		return mDNStrue;
	}

	// Suppressed response comes from mDNSResponder intenal policy, it shold always be trusted
	if (original->type == original_response && original->u.original.suppressed_response) {
		log_default("[R%u] trust_anchor_can_be_reached? Yes, suppressed answer is always trusted", request_id);
		return mDNStrue;
	}

	if (original->type == unknown_response) {
		log_default("[R%u] trust_anchor_can_be_reached? No, did not get any original response", request_id);
		return mDNSfalse;
	}

	// needs at leaset one zone to reach the trust anchor
	if (list_empty(zones)) {
		log_default("[R%u] trust_anchor_can_be_reached? No, zone list is empty", request_id);
		return mDNSfalse;
	}

	// The first zone is leaf, the last one is root, the root must have trust anchor to be validated.
	last_node = list_get_last(zones);
	zone = (dnssec_zone_t *)last_node->data;
	if (zone->trust_anchor == mDNSNULL) {
		log_default("[R%u] trust_anchor_can_be_reached? No, no trust anchor found in the current root", request_id);
		return mDNSfalse;
	}

	// starting from the first zone node(which is leaf) to the last node(which is root), to see if they could be connected
	// through chain of trust
	for (list_node_t *node = list_get_first(zones); !list_has_ended(zones, node); node = list_next(node)) {
		zone = (dnssec_zone_t *)node->data;

		if (zone->trust_anchor == mDNSNULL) { // nodes below the root have no trust anchor
			verify(node != last_node);

			// if the data structure that caches the necessary records is not initialized, then the chain is not completed
			if (!zone->dses_initialized) {
				log_default("[R%u] trust_anchor_can_be_reached? No, not receiving DS reocrds; qname=" PRI_DM_NAME,
					request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNSfalse;
			}

			// if the response is not completely returned to the DNSSEC handler, then the chain is not completed
			if (!zone->dnskeys_with_rrsig.set_completed) {
				log_default("[R%u] trust_anchor_can_be_reached? No, DNSKEY Set is not completed; qname=" PRI_DM_NAME,
					request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNSfalse;
			}

			if (!contains_rrsig_in_dnskeys_with_rrsig_t(&zone->dnskeys_with_rrsig)) {
				log_default("[R%u] trust_anchor_can_be_reached? No, DNSKEY Set does not have any RRSIG; qname=" PRI_DM_NAME,
					request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNSfalse;
			}

			// if the response is not completely returned to the DNSSEC handler, then the chain is not completed
			if (!zone->dses_with_rrsig.set_completed) {
				log_default("[R%u] trust_anchor_can_be_reached? No, DS Set is not completed; qname=" PRI_DM_NAME,
					request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNSfalse;
			}

			if (!contains_rrsig_in_dses_with_rrsig_t(&zone->dses_with_rrsig)) {
				log_default("[R%u] trust_anchor_can_be_reached? No, DS Set does not have any RRSIG; qname=" PRI_DM_NAME,
					request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNSfalse;
			}

		} else {
			// zone->trust_anchor != mDNSNULL
			verify(node == last_node);

			// If the trust anchor is saved as DNSKEY, then we could use it to validate the records directly instead of
			// querying for it
			if (trust_anchor_contains_dnskey(zone->trust_anchor)) {
				// has DNSKEY trust anchor, can be used to establish chain of trust
				log_default("[R%u] trust_anchor_can_be_reached? Yes, it is DNSKEY trust anchor; qname=" PRI_DM_NAME, request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNStrue;
			}

			// If the trust anchor is saved as DS, we should wait for the DNSKEY response come back before doing validation
			if (trust_anchor_contains_ds(zone->trust_anchor) && zone->dnskeys_with_rrsig.set_completed) {
				log_default("[R%u] trust_anchor_can_be_reached? Yes, it is DS trust anchor; qname=" PRI_DM_NAME, request_id, DM_NAME_PARAM(&zone->domain_name));
				return mDNStrue;
			}

			// does not get enough dnskey records to verify
			log_default("[R%u] trust_anchor_can_be_reached? No, DNSKEY set is not complete; qname=" PRI_DM_NAME, request_id, DM_NAME_PARAM(&zone->domain_name));
			return mDNSfalse;
		}
	}

	log_error("should never reach here");
	return mDNSfalse;
}

//======================================================================================================================
//	trust_anchor_contains_deskey
//======================================================================================================================

mDNSexport mDNSBool
trust_anchor_contains_dnskey(const trust_anchors_t * const anchor) {
	return anchor ? (!list_empty(&anchor->dnskey_trust_anchors)) : mDNSfalse;
}

//======================================================================================================================
//	trust_anchor_contains_ds
//======================================================================================================================

mDNSexport mDNSBool
trust_anchor_contains_ds(const trust_anchors_t * const anchor) {
	return anchor ? (!list_empty(&anchor->ds_trust_anchors)) : mDNSfalse;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
