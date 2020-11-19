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

#include "mDNSFeatures.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)

#include "mdns_trust.h"
#include "mdns_trust_checks.h"
#include "mdns_objects.h"
#include "mdns_helpers.h"
#include "dns_sd.h"

#include <bsm/libbsm.h>
#include <CoreUtils/DebugServices.h>

//======================================================================================================================
// MARK: - mdns_trust Kind Definition

struct mdns_trust_s {
	struct mdns_object_s				base;					// Object base.
	bool								activated;				// True if the trust has been activated.
	bool								invalidated;			// True if the trust has bee invalidated.
	bool								user_activated;			// True if user called activate method.
	dispatch_queue_t					queue;					// Internal serial queue.
	dispatch_queue_t					user_queue;				// Users serial queue.
	mdns_trust_event_handler_t			handler;				// User's event handler.
	void * 								context;
	audit_token_t						audit_token;
	char *								query;
	mdns_trust_flags_t					flags;
};

MDNS_OBJECT_SUBKIND_DEFINE(trust);

//======================================================================================================================
// MARK: - mdns_trust check Public Functions

void
mdns_trust_init(void)
{
	mdns_trust_checks_init();
}

mdns_trust_status_t
mdns_trust_check_register_service(audit_token_t audit_token, const char * _Nullable service, mdns_trust_flags_t * _Nullable flags)
{
	return mdns_trust_checks_check(&audit_token, trust_request_reg_service, NULL, service, 0, false, flags);
}

mdns_trust_status_t
mdns_trust_check_bonjour(audit_token_t audit_token, const char * _Nullable service, mdns_trust_flags_t * _Nullable flags)
{
	return mdns_trust_checks_check(&audit_token, trust_request_bonjour, NULL, service, 0, true, flags);
}

mdns_trust_status_t
mdns_trust_check_query(audit_token_t audit_token, const char * qname, const char * _Nullable service, uint16_t qtype,
	bool force_multicast, mdns_trust_flags_t * _Nullable flags)
{
	return mdns_trust_checks_check(&audit_token, trust_request_query, qname, service, qtype, force_multicast, flags);
}

mdns_trust_status_t
mdns_trust_check_getaddrinfo(audit_token_t audit_token, const char * hostname, mdns_trust_flags_t * _Nullable flags)
{
	return mdns_trust_checks_check(&audit_token, trust_request_query, hostname, NULL, 0, false, flags);
}

//======================================================================================================================
// MARK: - mdns_trust Private Methods

static void
_mdns_trust_finalize(mdns_trust_t me)
{
	dispatch_forget(&me->queue);
	dispatch_release_null_safe(me->user_queue);
	ForgetMem(&me->query);
	BlockForget(&me->handler);
}

//======================================================================================================================

static char *
_mdns_trust_copy_description(mdns_trust_t me, const bool debug, const bool __unused privacy)
{
	char *				description = NULL;
	char				buffer[256];
	char *				dst = buffer;
	const char * const	lim = &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	n = mdns_snprintf_add(&dst, lim, "%s ", me->base.kind->name);
	require_quiet(n >= 0, exit);

	n = mdns_snprintf_add(&dst, lim, "for pid %d", audit_token_to_pid(me->audit_token));
	require_quiet(n >= 0, exit);

	description = strdup(buffer);

exit:
	return description;
}

static void
_mdns_trust_activate_internal(mdns_trust_t me)
{
	mdns_retain(me);
	mdns_trust_checks_local_network_access_policy_update(&me->audit_token, me->queue, me->query, me->flags,
		^(trust_policy_state_t state) {
		if (!me->invalidated) {
			me->invalidated = true;
			mdns_retain(me);
			dispatch_async(me->user_queue,
			^{
				if (me->handler) {
					mdns_trust_status_t status = (state != trust_policy_state_granted) ?
													mdns_trust_status_denied : mdns_trust_status_granted;
					me->handler(mdns_trust_event_result, status);
				}
				mdns_release(me);
			});
		}
		mdns_release(me);
	});
}

static void
_mdns_trust_invalidate_internal(mdns_trust_t me)
{
	require_quiet(!me->invalidated, exit);
	me->invalidated = true;
	if (me->handler) {
		me->handler(mdns_trust_event_invalidated, 0);
	}
exit:
	return;
}

static void
_mdns_trust_activate_if_ready(mdns_trust_t me)
{
	if (me->user_activated && me->user_queue && !me->activated) {
		mdns_retain(me);
		dispatch_async(me->queue,
		^{
			me->activated = true;
			_mdns_trust_activate_internal(me);
			mdns_release(me);
		});
	}
}

//======================================================================================================================
// MARK: - mdns_trust Public instance specific

mdns_trust_t
mdns_trust_create(audit_token_t audit_token, const char *_Nullable query, mdns_trust_flags_t flags)
{
	mdns_trust_t op = NULL;
	mdns_trust_t obj 	= _mdns_trust_alloc();
	obj->queue			= dispatch_queue_create("trust-internal", DISPATCH_QUEUE_SERIAL);
	obj->audit_token	= audit_token;
	obj->flags			= flags;
	if (query != NULL) {
		obj->query		= strdup(query);
	}
	op					= obj;
	return op;
}

void
mdns_trust_set_context(mdns_trust_t me, void *_Nullable context)
{
	require_quiet(me, exit);
	me->context = context;
exit:
	;
}

void *_Nullable
mdns_trust_get_context(mdns_trust_t me)
{
	require_quiet(me, exit);
	return me->context;
exit:
	return NULL;
}

void
mdns_trust_activate(mdns_trust_t me)
{
	if (!me->user_activated) {
		me->user_activated = true;
		_mdns_trust_activate_if_ready(me);
	}
}

void
mdns_trust_invalidate(mdns_trust_t me)
{
	mdns_retain(me);
	dispatch_async(me->queue,
	^{
		_mdns_trust_invalidate_internal(me);
		mdns_release(me);
	});
}

void
mdns_trust_set_queue(mdns_trust_t me, dispatch_queue_t queue)
{
	if (!me->user_activated || !me->user_queue)
	{
		if (queue) {
			dispatch_retain(queue);
		}
		dispatch_release_null_safe(me->user_queue);
		me->user_queue = queue;
		_mdns_trust_activate_if_ready(me);
	}
}

void
mdns_trust_set_event_handler(mdns_trust_t me, mdns_trust_event_handler_t handler)
{
	const mdns_trust_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	if (me->handler) {
		Block_release(me->handler);
	}
	me->handler = new_handler;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
