/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#ifndef __MDNS_TRUST_H__
#define __MDNS_TRUST_H__

#include "mdns_base.h"
#include <dispatch/dispatch.h>

MDNS_DECL(trust);

OS_CLOSED_ENUM(mdns_trust_status, int,
	mdns_trust_status_denied				= 0,
	/*! @const mdns_trust_status_deny The requested trust is denied. */
	mdns_trust_status_granted				= 1,
	/*! @const mdns_trust_status_granted The requested trust is granted. */
	mdns_trust_status_pending				= 2,
	/*! @const mdns_trust_status_pending The requested trust is pending user interaction. */
	mdns_trust_status_no_entitlement		= 3
	/*! @const mdns_trust_status_no_entitlement The requested trust did not have a proper entitlement. */
);

OS_CLOSED_OPTIONS(mdns_trust_flags, uint32_t,
	mdns_trust_flags_none					= 0,
	mdns_trust_flags_entitlement			= (1U << 0),
	/*! @const mdns_trust_flags_entitlement The app has a valid catch-all entitlement. */
);

MDNS_ASSUME_NONNULL_BEGIN

static inline const char *
mdns_trust_status_to_string(mdns_trust_status_t result)
{
	switch (result) {
		case mdns_trust_status_denied:				return "denied";
		case mdns_trust_status_granted:				return "granted";
		case mdns_trust_status_pending:				return "pending";
		case mdns_trust_status_no_entitlement:		return "no_entitlement";
		default:									return "<INVALID RESULT>";
	}
}

//======================================================================================================================
// MARK: - mdns_trust Initialization

void
mdns_trust_init(void);

//======================================================================================================================
// MARK: - mdns_trust Direct checks

mdns_trust_status_t
mdns_trust_check_bonjour(audit_token_t audit_token, const char * _Nullable service, mdns_trust_flags_t * _Nullable flags);

mdns_trust_status_t
mdns_trust_check_register_service(audit_token_t audit_token, const char * _Nullable service, mdns_trust_flags_t * _Nullable flags);

mdns_trust_status_t
mdns_trust_check_query(audit_token_t audit_token, const char * qname, const char * _Nullable service, uint16_t qtype, bool force_multicast, mdns_trust_flags_t * _Nullable flags);

mdns_trust_status_t
mdns_trust_check_getaddrinfo(audit_token_t audit_token, const char * hostname, mdns_trust_flags_t * _Nullable flags);

//======================================================================================================================
// MARK: - mdns_trust Object to receive status updates

MDNS_RETURNS_RETAINED mdns_trust_t _Nullable
mdns_trust_create(audit_token_t audit_token, const char *_Nullable query, mdns_trust_flags_t flags);

void
mdns_trust_set_context(mdns_trust_t trust, void *_Nullable context);

void *_Nullable
mdns_trust_get_context(mdns_trust_t trust);

void
mdns_trust_activate(mdns_trust_t trust);

void
mdns_trust_invalidate(mdns_trust_t trust);

void
mdns_trust_set_queue(mdns_trust_t trust, dispatch_queue_t queue);

OS_CLOSED_ENUM(mdns_trust_event, int,
	mdns_trust_event_result			= 0,
	mdns_trust_event_invalidated	= 1
);

static inline const char *
mdns_trust_event_to_string(const mdns_trust_event_t event)
{
	switch (event) {
		case mdns_trust_event_result:		return "result";
		case mdns_trust_event_invalidated:	return "invalidated";
		default:							return "<invalid event value>";
	}
}

typedef void
(^mdns_trust_event_handler_t)(mdns_trust_event_t event, mdns_trust_status_t status);

void
mdns_trust_set_event_handler(mdns_trust_t trust, mdns_trust_event_handler_t handler);

#define mdns_trust_forget(X)	mdns_forget_with_invalidation(X, trust)

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_TRUST_H__
