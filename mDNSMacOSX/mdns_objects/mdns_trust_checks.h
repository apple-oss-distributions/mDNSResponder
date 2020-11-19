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

#ifndef __MDNS_TRUST_CHECKS_H__
#define __MDNS_TRUST_CHECKS_H__

#include "mdns_base.h"
#include <dispatch/dispatch.h>

OS_CLOSED_ENUM(trust_policy_state, int,
	trust_policy_state_denied 				= 0,
	trust_policy_state_granted				= 1,
	trust_policy_state_pending				= 2
);

OS_CLOSED_ENUM(trust_request, int,
	trust_request_bonjour					= 0,
	trust_request_reg_service				= 1,
	trust_request_query						= 2
);

MDNS_ASSUME_NONNULL_BEGIN

static inline const char *
_mdns_trust_checks_policy_to_string(trust_policy_state_t state)
{
	switch (state) {
		case trust_policy_state_denied:		return "denied";
		case trust_policy_state_granted:	return "granted";
		case trust_policy_state_pending:	return "pending";
		default:							return "<INVALID STATE>";
	}
}

static inline const char *
_mdns_trust_checks_request_to_string(trust_request_t request)
{
	switch (request) {
		case trust_request_bonjour:			return "bonjour";
		case trust_request_reg_service:		return "reg_service";
		case trust_request_query:			return "query";
		default:							return "<INVALID REQUEST>";
	}
}

void
mdns_trust_checks_init(void);

typedef void
(^_mdns_trust_checks_update_handler_t)(trust_policy_state_t status);

void
mdns_trust_checks_local_network_access_policy_update(audit_token_t *auditToken, dispatch_queue_t queue,
	const char * _Nullable query, mdns_trust_flags_t flags, _mdns_trust_checks_update_handler_t handler);

mdns_trust_status_t
mdns_trust_checks_check(audit_token_t *audit_token, trust_request_t request, const char * _Nullable query_name,
	const char * _Nullable service_name, uint16_t qtype, bool force_multicast, mdns_trust_flags_t * _Nullable flags);

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_TRUST_CHECKS_H__
