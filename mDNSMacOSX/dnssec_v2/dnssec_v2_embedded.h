//
//  dnssec_v2_embedded.h
//  mDNSResponder
//
//  Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_v2_EMBEDDED_H
#define DNSSEC_v2_EMBEDDED_H

// These embedded structure is used in mDNSEmbedded.h, which is a base header file.
#pragma mark - structures

typedef struct dnssec_status dnssec_status_t;
struct dnssec_status {
	uint8_t	enable_dnssec;				// indicate if mDNSResponder should do DNSSEC validation for the current question
	uint8_t	tried_dnssec_but_unsigned;	// if a question does not enable DNSSEC but this boolean is set, it means the question that enables DNSSEC validation is restarted
	void *	context;					// dnssec_context_t
};

typedef enum dnssec_result {
	dnssec_indeterminate = 0,	// make dnssec_indeterminate as default so the uninitialized dnssec_result_t that usually has no data in it will yeild dnssec_indeterminate
	dnssec_secure,				// The answer returned to the user call back function is secure and validated through DNSSEC, and can be trusted.
	dnssec_insecure,			// The answer provided by the authority server is not signed by the zone, thus we are unable to validate, when it happens the unsigned answer will be returned with dnssec_insecure.
	dnssec_bogus				// The answer provided by the authority server has records to do the DNSSEC validation, but the validation fails for some reason, which may indicate an attack from network.
} dnssec_result_t;

#endif /* DNSSEC_v2_EMBEDDED_H */
