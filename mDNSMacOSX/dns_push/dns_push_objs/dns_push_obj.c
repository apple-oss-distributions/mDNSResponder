/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include "dns_push_obj.h"
#include "ref_count.h"
#include <stdint.h>
#include <stdbool.h>

#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Object Public Methods

dns_push_obj_t
dns_push_obj_retain(const dns_push_obj_t me)
{
	ref_count_obj_retain(me);
	return me;
}

//======================================================================================================================

void
dns_push_obj_release(const dns_push_obj_t me)
{
	ref_count_obj_release(me);
}

//======================================================================================================================

bool
dns_push_obj_equal(const dns_push_obj_t me, const dns_push_obj_t other)
{
	return ref_count_obj_compare(me, other, true) == compare_result_equal;
}

//======================================================================================================================

compare_result_t
dns_push_obj_compare(const dns_push_obj_t me, const dns_push_obj_t other)
{
	return ref_count_obj_compare(me, other, false);
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
