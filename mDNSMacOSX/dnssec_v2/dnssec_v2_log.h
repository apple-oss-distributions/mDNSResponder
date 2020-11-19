//
//	dnssec_v2_log.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_LOG_H
#define DNSSEC_V2_LOG_H

#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

// short version logging for DNSSEC-related functionality
#define log_debug(FORMAT, ...)		LogRedact(MDNS_LOG_CATEGORY_DNSSEC, MDNS_LOG_DEBUG, FORMAT, ## __VA_ARGS__)
#define log_default(FORMAT, ...)	LogRedact(MDNS_LOG_CATEGORY_DNSSEC, MDNS_LOG_DEFAULT, FORMAT, ## __VA_ARGS__)
#define log_error(FORMAT, ...)		LogRedact(MDNS_LOG_CATEGORY_DNSSEC, MDNS_LOG_ERROR, FORMAT, ## __VA_ARGS__)
#define log_fault(FORMAT, ...)		LogRedact(MDNS_LOG_CATEGORY_DNSSEC, MDNS_LOG_FAULT, FORMAT, ## __VA_ARGS__)

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#endif // DNSSEC_V2_LOG_H
