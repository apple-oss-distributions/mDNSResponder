/*
 * Copyright (c) 2022-2024 Apple Inc. All rights reserved.
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

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_push_mdns_core.h"

#include "discover_resolver.h"
#include "dns_assert_macros.h"
#include "dns_obj_log.h"
#include "dns_push_obj_context.h"
#include "DNSCommon.h"
#include "mDNSEmbeddedAPI.h"
#include "QuerierSupport.h"

#include <os/feature_private.h>
#include <stdlib.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Public Functions

bool
dns_question_enables_dns_push(const DNSQuestion * const me)
{
	// LongLived needs to be enabled to enable DNS push.
	const mDNSBool dns_push_enabled = me->LongLived;
	// The question has to come from the client request directly.
	const mDNSBool client_request = !Querier_QuestionBelongsToSelf(me);
	// The question name must not end with a local domain.
	const mDNSBool dot_local_domain = IsLocalDomain(&me->qname);
	return (dns_push_enabled && client_request && !dot_local_domain);
}

//======================================================================================================================

bool
dns_question_uses_dns_push(const DNSQuestion * const me)
{
	return (me->dns_push != NULL);
}

//======================================================================================================================

bool
dns_question_uses_dns_polling(const DNSQuestion * const me)
{
	bool result;
	mdns_require_action_quiet(dns_question_uses_dns_push(me), exit, result = false);

	const dns_push_obj_context_t context = dns_question_get_dns_push_context(me);
	mdns_require_action_quiet(context, exit, result = false);

	result = dns_push_obj_context_get_dns_polling_enabled(context);

exit:
	return result;
}

//======================================================================================================================

dns_push_obj_context_t
dns_question_get_dns_push_context(const DNSQuestion * const question)
{
	if (question->dns_push) {
		return dns_push_obj_dns_question_member_get_context(question->dns_push);
	} else {
		return NULL;
	}
}

//======================================================================================================================

dns_obj_domain_name_t NULLABLE
dns_question_get_authoritative_zone(const DNSQuestion * const question)
{
	dns_obj_domain_name_t zone = NULL;

	require_quiet(dns_question_uses_dns_push(question), exit);

	const dns_push_obj_context_t context = dns_question_get_dns_push_context(question);
	require_quiet(context, exit);

	zone = dns_push_obj_context_get_authoritative_zone(context);

exit:
	return zone;
}

//======================================================================================================================

bool
dns_question_finished_push_discovery(const DNSQuestion * const question)
{
	bool finished = false;
	const dns_push_obj_context_t context = dns_question_get_dns_push_context(question);
	mdns_require_quiet(context, exit);

	finished = (dns_push_obj_context_get_service_id(context) != MDNS_DNS_SERVICE_INVALID_ID);

exit:
	return finished;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
