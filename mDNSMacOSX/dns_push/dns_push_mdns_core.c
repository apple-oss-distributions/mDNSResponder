/*
 * Copyright (c) 2022-2023 Apple Inc. All rights reserved.
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

#include <stdlib.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Public Functions

bool
dns_question_enables_dns_push(const DNSQuestion * const me)
{
	return (me->dns_push != NULL);
}

//======================================================================================================================

dns_push_obj_context_t
dns_question_get_dns_push_context(const DNSQuestion * const question)
{
	return dns_push_obj_dns_question_member_get_context(question->dns_push);
}

//======================================================================================================================

dns_obj_domain_name_t NULLABLE
dns_question_get_authoritative_zone(const DNSQuestion * const question)
{
	dns_obj_domain_name_t zone = NULL;

	require_quiet(dns_question_enables_dns_push(question), exit);

	const dns_push_obj_context_t context = dns_question_get_dns_push_context(question);
	require_quiet(context, exit);

	zone = dns_push_obj_context_get_authoritative_zone(context);

exit:
	return zone;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
