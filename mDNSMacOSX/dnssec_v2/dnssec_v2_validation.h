//
//	dnssec_v2_validation.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_VALIDATION_H
#define DNSSEC_V2_VALIDATION_H

#include <stdio.h>
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

typedef enum dnssec_validator_node_type {
	rr_validator,
	nsec_validator,
	nsec3_validator,
	zsk_validator,
	ksk_validator
} dnssec_validator_node_type_t;

//======================================================================================================================
//	functions prototype
//======================================================================================================================

mDNSexport dnssec_validation_result_t
validate_dnssec(dnssec_context_t * const _Nonnull context);

mDNSexport mDNSu16
calculate_key_tag(const mDNSu8 key[_Nonnull], const mDNSu16 key_len, const mDNSu8 algorithm);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#endif // DNSSEC_V2_VALIDATION_H
