/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#include "mrcs_server_internal.h"

#include "helpers.h"
#include "mrc_xpc.h"
#include "mrcs_object_internal.h"
#include "mrcs_objects.h"

#include <CoreUtils/CoreUtils.h>
#include <mdns/DNSMessage.h>
#include <mdns/string_builder.h>
#include <mdns/xpc.h>
#include <xpc/xpc.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Constants

MDNS_CLOSED_ENUM(mrcs_command_t, uint8_t,
	mrcs_command_invalid						= 0,
	mrcs_command_dns_proxy_start				= 1,
	mrcs_command_dns_proxy_stop					= 2,
	mrcs_command_dns_proxy_get_state			= 3,
	mrcs_command_dns_service_registration_start	= 4,
	mrcs_command_dns_service_registration_stop	= 5,
	mrcs_command_discovery_proxy_start			= 6,
	mrcs_command_discovery_proxy_stop			= 7,
	mrcs_command_cached_local_record_inquiry	= 8,
	mrcs_command_record_cache_flush				= 9,
);

//======================================================================================================================
// MARK: - Session Kind

struct mrcs_session_s {
	struct mdns_obj_s						base;							// Object base.
	mrcs_session_t							next;							// Next session in list.
	xpc_connection_t						connection;						// Underlying XPC connection.
	mrcs_dns_proxy_request_t				dns_proxy_request_list;			// List of client requests.
	mrcs_dns_service_registration_request_t	dns_service_reg_request_list;	// List of DNS service requests.
};

MRCS_OBJECT_SUBKIND_DEFINE(session);

//======================================================================================================================
// MARK: - DNS Proxy Request Kind

struct mrcs_dns_proxy_request_s {
	struct mdns_obj_s			base;		// Object base.
	mrcs_dns_proxy_request_t	next;		// Next request in list.
	mrcs_dns_proxy_t			proxy;		// DNS proxy.
	uint64_t					command_id;	// Command ID.
};

MRCS_OBJECT_SUBKIND_DEFINE(dns_proxy_request);

//======================================================================================================================
// MARK: - DNS Service Registration Request Kind

struct mrcs_dns_service_registration_request_s {
	struct mdns_obj_s						base;				// Object base.
	mrcs_dns_service_registration_request_t	next;				// Next request in list.
	mdns_dns_service_definition_t			do53_definition;	// DNS over 53 service definition.
	mdns_dns_push_service_definition_t		push_definition;	// DNS push service definition.
	uint64_t								command_id;			// Command ID.
	mdns_dns_service_id_t					ident;				// DNS service ID.
};

MRCS_OBJECT_SUBKIND_DEFINE(dns_service_registration_request);

//======================================================================================================================
// MARK: - Local Prototypes

static dispatch_queue_t
_mrcs_server_queue(void);

static void
_mrcs_server_handle_new_connection(xpc_connection_t connection);

static mrcs_session_t
_mrcs_session_create(xpc_connection_t connection, OSStatus *out_error);

static void
_mrcs_session_activate(mrcs_session_t session);

static void
_mrcs_session_invalidate(mrcs_session_t session);

static void
_mrcs_session_register(mrcs_session_t session);

static void
_mrcs_session_deregister(mrcs_session_t session);

static void
_mrcs_session_handle_message(mrcs_session_t session, xpc_object_t msg);

static mrcs_dns_proxy_request_t
_mrcs_dns_proxy_request_create(mrcs_dns_proxy_t proxy, uint64_t command_id, OSStatus *out_error);

static mrcs_dns_proxy_t
_mrcs_create_dns_proxy_from_params_dictionary(xpc_object_t params, OSStatus *out_error);

//======================================================================================================================
// MARK: - Logging

MDNS_LOG_CATEGORY_DEFINE(server, "mrcs_server");

//======================================================================================================================
// MARK: - Globals

static mrcs_server_dns_proxy_handlers_t					g_dns_proxy_handlers				= NULL;
static mrcs_server_dns_service_registration_handlers_t	g_dns_service_registration_handlers	= NULL;
static mrcs_server_discovery_proxy_handlers_t			g_discovery_proxy_handlers			= NULL;
static mrcs_server_record_cache_handlers_t				g_record_cache_handlers				= NULL;
static mrcs_session_t									g_session_list						= NULL;
static mrcs_session_t									g_current_discovery_proxy_owner		= NULL;
static bool												g_activated							= false;

//======================================================================================================================
// MARK: - Public Server Functions

void
mrcs_server_set_dns_proxy_handlers(const mrcs_server_dns_proxy_handlers_t handlers)
{
	dispatch_async(_mrcs_server_queue(),
	^{
		mdns_require_return(!g_activated);
		g_dns_proxy_handlers = handlers;
	});
}

//======================================================================================================================

void
mrcs_server_set_dns_service_registration_handlers(const mrcs_server_dns_service_registration_handlers_t handlers)
{
	dispatch_async(_mrcs_server_queue(),
	^{
		mdns_require_return(!g_activated);
		g_dns_service_registration_handlers = handlers;
	});
}

//======================================================================================================================

void
mrcs_server_set_discovery_proxy_handlers(const mrcs_server_discovery_proxy_handlers_t handlers)
{
	dispatch_async(_mrcs_server_queue(),
	^{
		mdns_require_return(!g_activated);
		g_discovery_proxy_handlers = handlers;
	});
}

//======================================================================================================================

void
mrcs_server_set_record_cache_handlers(const mrcs_server_record_cache_handlers_t handlers)
{
	dispatch_async(_mrcs_server_queue(),
	^{
		mdns_require_return(!g_activated);
		g_record_cache_handlers = handlers;
	});
}

//======================================================================================================================

void
mrcs_server_activate(void)
{
	dispatch_async(_mrcs_server_queue(),
	^{
		static xpc_connection_t s_listener = NULL;
		mdns_require_return(!s_listener);

		const uint64_t flags = XPC_CONNECTION_MACH_SERVICE_LISTENER;
		s_listener = xpc_connection_create_mach_service(g_mrc_mach_service_name, _mrcs_server_queue(), flags);
		mdns_require_return_action(s_listener, os_log_fault(_mdns_server_log(),
			"Failed to create XPC listener for %{public}s", g_mrc_mach_service_name));

		xpc_connection_set_event_handler(s_listener,
		^(const xpc_object_t event)
		{
			if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
				_mrcs_server_handle_new_connection((xpc_connection_t)event);
			}
		});
		xpc_connection_activate(s_listener);
		g_activated = true;
	});
}

//======================================================================================================================
// MARK: - Private Server Functions

static dispatch_queue_t
_mrcs_server_queue(void)
{
	static dispatch_once_t s_once = 0;
	static dispatch_queue_t s_queue = NULL;
	dispatch_once(&s_once,
	^{
		s_queue = dispatch_queue_create("com.apple.mDNSResponder.control.server", DISPATCH_QUEUE_SERIAL);
	});
	return s_queue;
}

//======================================================================================================================

static void
_mrcs_server_handle_new_connection(const xpc_connection_t connection)
{
	mrcs_session_t session = _mrcs_session_create(connection, NULL);
	if (session) {
		_mrcs_session_register(session);
		_mrcs_session_activate(session);
		mrcs_forget(&session);
	} else {
		xpc_connection_cancel(connection);
	}
}

//======================================================================================================================

static OSStatus
_mrcs_server_dns_proxy_start(const mrcs_dns_proxy_t proxy)
{
	OSStatus err;
	if (g_dns_proxy_handlers->start) {
		err = g_dns_proxy_handlers->start(proxy);
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_server_dns_proxy_stop(const mrcs_dns_proxy_t proxy)
{
	OSStatus err;
	if (g_dns_proxy_handlers->stop) {
		err = g_dns_proxy_handlers->stop(proxy);
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static char *
_mrcs_server_dns_proxy_state(OSStatus * const out_error)
{
	char *state;
	OSStatus err;
	if (g_dns_proxy_handlers->get_state) {
		state = g_dns_proxy_handlers->get_state();
		err = state ? kNoErr : kNoMemoryErr;
	} else {
		state = NULL;
		err = kNotHandledErr;
	}
	if (out_error) {
		*out_error = err;
	}
	return state;
}

//======================================================================================================================

static OSStatus
_mrcs_server_discovery_proxy_start(const uint32_t ifindex, const CFArrayRef addresses, const CFArrayRef match_domains,
	const CFArrayRef server_certificates)
{
	OSStatus err;
	if (g_discovery_proxy_handlers->start) {
		err = g_discovery_proxy_handlers->start(ifindex, addresses, match_domains, server_certificates);
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_server_discovery_proxy_stop(void)
{
	OSStatus err;
	if (g_discovery_proxy_handlers->stop) {
		err = g_discovery_proxy_handlers->stop();
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static mdns_dns_service_id_t
_mrcs_server_dns_service_registration_start_with_connection_error_handler(
	const mdns_any_dns_service_definition_t definition, const dispatch_queue_t connection_error_queue,
	const mdns_event_handler_t connection_error_handler, OSStatus * const out_error)
{
	OSStatus err;
	mdns_dns_service_id_t ident;
	if (g_dns_service_registration_handlers->start) {
		ident = g_dns_service_registration_handlers->start(definition, connection_error_queue,
			connection_error_handler);
		err = (ident != MDNS_DNS_SERVICE_INVALID_ID) ? kNoErr : kUnknownErr;
	} else {
		ident = MDNS_DNS_SERVICE_INVALID_ID;
		err = kNotHandledErr;
	}
	mdns_assign(out_error, err);
	return ident;
}

//======================================================================================================================

static mdns_dns_service_id_t
_mrcs_server_dns_service_registration_start(const mdns_any_dns_service_definition_t definition,
	OSStatus * const out_error)
{
	return _mrcs_server_dns_service_registration_start_with_connection_error_handler(definition, NULL, NULL, out_error);
}

//======================================================================================================================

static OSStatus
_mrcs_server_dns_service_registration_stop(const mdns_dns_service_id_t ident)
{
	OSStatus err;
	if (g_dns_service_registration_handlers->stop) {
		g_dns_service_registration_handlers->stop(ident);
		err = kNoErr;
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_server_record_cache_enumerate_local_records(const mrcs_record_applier_t applier)
{
	OSStatus err;
	if (g_record_cache_handlers->enumerate_local_records) {
		g_record_cache_handlers->enumerate_local_records(applier);
		err = kNoErr;
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_server_record_cache_flush_by_name(const char * const record_name)
{
	OSStatus err;
	if (g_record_cache_handlers->flush_by_name) {
		g_record_cache_handlers->flush_by_name(record_name);
		err = kNoErr;
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_server_record_cache_flush_by_name_and_key_tag(const char * const record_name, const uint16_t key_tag)
{
	OSStatus err;
	if (g_record_cache_handlers->flush_by_name_and_key_tag) {
		g_record_cache_handlers->flush_by_name_and_key_tag(record_name, key_tag);
		err = kNoErr;
	} else {
		err = kNotHandledErr;
	}
	return err;
}

//======================================================================================================================

typedef struct {
	const char *	string;
	mrcs_command_t	code;
} mrcs_command_string_code_pair_t;

static mrcs_command_t
_mrcs_server_command_string_to_code(const char * const command_str)
{
#define MRCS_SERVER_COMMAND_STRING_CODE_PAIR(NAME)	{g_mrc_command_ ## NAME, mrcs_command_ ## NAME}
	const mrcs_command_string_code_pair_t pairs[] = {
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(cached_local_record_inquiry),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(discovery_proxy_start),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(discovery_proxy_stop),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(dns_proxy_start),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(dns_proxy_stop),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(dns_proxy_get_state),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(dns_service_registration_start),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(dns_service_registration_stop),
		MRCS_SERVER_COMMAND_STRING_CODE_PAIR(record_cache_flush),
	};
	for (size_t i = 0; i < mdns_countof(pairs); ++i) {
		const mrcs_command_string_code_pair_t * const pair = &pairs[i];
		if (strcmp(command_str, pair->string) == 0) {
			return pair->code;
		}
	}
	return mrcs_command_invalid;
}

//======================================================================================================================

static const char *
_mrcs_server_get_required_entitlement(const mrcs_command_t command)
{
	switch (command) {
		case mrcs_command_discovery_proxy_start:
		case mrcs_command_discovery_proxy_stop:
			return "com.apple.mDNSResponder.discovery-proxy";

		case mrcs_command_dns_proxy_start:
		case mrcs_command_dns_proxy_stop:
		case mrcs_command_dns_proxy_get_state:
			return "com.apple.mDNSResponder.dnsproxy";

		case mrcs_command_dns_service_registration_start:
		case mrcs_command_dns_service_registration_stop:
			return "com.apple.mDNSResponder.dns-service-registration";

		case mrcs_command_cached_local_record_inquiry:
			return "com.apple.mDNSResponder.record-cache.local-record-info";

		case mrcs_command_record_cache_flush:
			return "com.apple.private.mDNSResponder.record-cache.flush";

		case mrcs_command_invalid:
		MDNS_COVERED_SWITCH_DEFAULT:
			return NULL;
	}
}

//======================================================================================================================
// MARK: - Session Methods

static mrcs_session_t
_mrcs_session_create(const xpc_connection_t connection, OSStatus * const out_error)
{
	OSStatus err;
	mrcs_session_t session = NULL;
	mrcs_session_t obj = _mrcs_session_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->connection = connection;
	xpc_retain(obj->connection);
	session = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrcs_forget(&obj);
	return session;
}

//======================================================================================================================

static char *
_mrcs_session_copy_description(const mrcs_session_t me, __unused const bool debug, __unused const bool privacy)
{
	char *description = NULL;
	asprintf(&description, "<%s: %p>", me->base.kind->name, (void *)me);
	return description;
}

//======================================================================================================================

static void
_mrcs_session_finalize(const mrcs_session_t me)
{
	xpc_forget(&me->connection);
}

//======================================================================================================================

static void
_mrcs_session_activate(const mrcs_session_t me)
{
	mrcs_retain(me);
	xpc_connection_set_target_queue(me->connection, _mrcs_server_queue());
	xpc_connection_set_event_handler(me->connection,
	^(const xpc_object_t event)
	{
		const xpc_type_t type = xpc_get_type(event);
		if (type == XPC_TYPE_DICTIONARY) {
			if (me->connection) {
				_mrcs_session_handle_message(me, event);
			}
		} else if (event == XPC_ERROR_CONNECTION_INVALID) {
			_mrcs_session_deregister(me);
			_mrcs_session_invalidate(me);
			mrcs_release(me);
		} else {
			xpc_connection_forget(&me->connection);
		}
	});
	xpc_connection_activate(me->connection);
}

//======================================================================================================================

static void
_mrcs_session_invalidate(const mrcs_session_t me)
{
	xpc_connection_forget(&me->connection);
	while (me->dns_proxy_request_list) {
		mrcs_dns_proxy_request_t request = me->dns_proxy_request_list;
		me->dns_proxy_request_list = request->next;
		_mrcs_server_dns_proxy_stop(request->proxy);
		mrcs_forget(&request);
	}
	while (me->dns_service_reg_request_list) {
		mrcs_dns_service_registration_request_t request = me->dns_service_reg_request_list;
		me->dns_service_reg_request_list = request->next;
		_mrcs_server_dns_service_registration_stop(request->ident);
		mrcs_forget(&request);
	}
	// Handle discovery proxy invalidation.
	if (g_current_discovery_proxy_owner == me) {
		_mrcs_server_discovery_proxy_stop();
		mrcs_forget(&g_current_discovery_proxy_owner);
	}
}

//======================================================================================================================

static void
_mrcs_session_register(const mrcs_session_t me)
{
	mrcs_session_t *ptr = &g_session_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	me->next = NULL;
	*ptr = me;
	mrcs_retain(me);
}

//======================================================================================================================

static void
_mrcs_session_deregister(const mrcs_session_t me)
{
	mrcs_session_t *ptr = &g_session_list;
	while (*ptr && (*ptr != me)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		*ptr = me->next;
		me->next = NULL;
		mrcs_release(me);
	}
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_dns_proxy_start(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	mrcs_dns_proxy_t proxy = NULL;
	const uint64_t command_id = mrc_xpc_message_get_id(msg);
	mrcs_dns_proxy_request_t *ptr = &me->dns_proxy_request_list;
	while (*ptr && ((*ptr)->command_id != command_id)) {
		ptr = &(*ptr)->next;
	}
	require_action_quiet(!*ptr, exit, err = kStateErr);

	const xpc_object_t params = mrc_xpc_message_get_params(msg);
	require_action_quiet(params, exit, err = kParamErr);

	proxy = _mrcs_create_dns_proxy_from_params_dictionary(params, &err);
	require_noerr_quiet(err, exit);

	mrcs_dns_proxy_set_euid(proxy, xpc_connection_get_euid(me->connection));
	err = _mrcs_server_dns_proxy_start(proxy);
	require_noerr_quiet(err, exit);

	mrcs_dns_proxy_request_t request = _mrcs_dns_proxy_request_create(proxy, command_id, &err);
	require_noerr_quiet(err, exit);

	*ptr = request;
	request = NULL;

exit:
	mrcs_forget(&proxy);
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_dns_proxy_stop(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	const uint64_t command_id = mrc_xpc_message_get_id(msg);
	mrcs_dns_proxy_request_t *ptr = &me->dns_proxy_request_list;
	while (*ptr && ((*ptr)->command_id != command_id)) {
		ptr = &(*ptr)->next;
	}
	mrcs_dns_proxy_request_t request = *ptr;
	require_action_quiet(request, exit, err = kIDErr);

	*ptr = request->next;
	request->next = NULL;
	_mrcs_server_dns_proxy_stop(request->proxy);
	mrcs_forget(&request);
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

static mdns_xpc_dictionary_t
_mrcs_session_handle_dns_proxy_get_state(OSStatus * const out_error)
{
	OSStatus err;
	mdns_xpc_dictionary_t result = mdns_xpc_dictionary_create_empty();
	require_action_quiet(result, exit, err = kNoResourcesErr);

	char *state = _mrcs_server_dns_proxy_state(&err);
	if (state) {
		mrc_xpc_dns_proxy_state_result_set_description(result, state);
	}
	ForgetMem(&state);

exit:
	if (out_error) {
		*out_error = err;
	}
	return result;
}

//======================================================================================================================

static mrcs_dns_service_registration_request_t *
_mrcs_session_get_dns_service_registration(const mrcs_session_t me, const uint64_t command_id)
{
	mrcs_dns_service_registration_request_t *ptr = &me->dns_service_reg_request_list;
	while (*ptr && ((*ptr)->command_id != command_id)) {
		ptr = &(*ptr)->next;
	}
	return ptr;
}

//======================================================================================================================

static xpc_object_t
mrc_xpc_dns_service_registration_create_connection_error_notification(const uint64_t command_id,
	const OSStatus connection_error, OSStatus * const out_error)
{
	OSStatus err;
	xpc_object_t body = NULL;
	xpc_object_t notification = NULL;

	body = mrc_xpc_dns_service_registration_notification_create_connection_error_body(connection_error, &err);
	mdns_require_noerr_quiet(err, exit);

	notification = mrc_xpc_create_notification(command_id, body);
	mdns_require_action_quiet(notification, exit, err = kNoResourcesErr);
	err = kNoErr;

exit:
	mdns_assign(out_error, err);
	xpc_forget(&body);
	return notification;
}

//======================================================================================================================

static void
_mrcs_session_handle_dns_service_registration_connection_error(const mrcs_session_t me, const uint64_t command_id,
	const OSStatus connection_error)
{
	if (me->connection && _mrcs_session_get_dns_service_registration(me, command_id)) {
		OSStatus err;
		xpc_object_t notification =
			mrc_xpc_dns_service_registration_create_connection_error_notification(command_id, connection_error, &err);
		if (err == kNoErr) {
			xpc_connection_send_message(me->connection, notification);
		}
		mdns_forget(&notification);
	}
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_dns_service_registration_start(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	mrcs_dns_service_registration_request_t new_request = NULL;
	const uint64_t command_id = mrc_xpc_message_get_id(msg);
	mrcs_dns_service_registration_request_t * const ptr = _mrcs_session_get_dns_service_registration(me, command_id);
	mrcs_dns_service_registration_request_t request = *ptr;
	mdns_require_action_quiet(!request, exit, err = kAlreadyInUseErr);

	const xpc_object_t params = mrc_xpc_message_get_params(msg);
	mdns_require_action_quiet(params, exit, err = kParamErr);

	const mdns_xpc_dictionary_t def_dict = mrc_xpc_dns_service_registration_params_get_defintion_dictionary(params);
	mdns_require_action_quiet(def_dict, exit, err = kParamErr);

	bool type_valid = false;
	const mrc_dns_service_definition_type_t def_type =
		mrc_xpc_dns_service_registration_params_get_definition_type(params, &type_valid);
	mdns_require_action_quiet(type_valid, exit, err = kParamErr);

	new_request = _mrcs_dns_service_registration_request_new();
	require_action_quiet(new_request, exit, err = kNoMemoryErr);

	switch (def_type) {
		case mrc_dns_service_definition_type_do53:
			new_request->do53_definition = mdns_dns_service_definition_create_from_xpc_dictionary(def_dict, &err);
			mdns_require_noerr_quiet(err, exit);

			new_request->ident = _mrcs_server_dns_service_registration_start(new_request->do53_definition, &err);
			mdns_require_noerr_quiet(err, exit);
			break;

		case mrc_dns_service_definition_type_push:
		{
			new_request->push_definition = mdns_dns_push_service_definition_create_from_xpc_dictionary(def_dict, &err);
			mdns_require_noerr_quiet(err, exit);

			const bool reports_connection_errors =
				mrc_xpc_dns_service_registration_params_get_reports_connection_errors(params);

			dispatch_queue_t connection_error_queue = NULL;
			mdns_event_handler_t connection_error_handler = NULL;
			if (reports_connection_errors) {
				connection_error_queue = _mrcs_server_queue();
				connection_error_handler =
				^(const mdns_event_t event, const OSStatus error)
				{
					switch (event) {
						case mdns_event_invalidated:
							mrcs_release(me);
							break;

						case mdns_event_error:
							_mrcs_session_handle_dns_service_registration_connection_error(me, command_id, error);
							break;

						case mdns_event_update:
							// Not handled for now.
							break;
					}
				};
			}
			new_request->ident = _mrcs_server_dns_service_registration_start_with_connection_error_handler(
				new_request->push_definition, connection_error_queue, connection_error_handler, &err);
			mdns_require_noerr_quiet(err, exit);
			if (reports_connection_errors) {
				// Only retain the object if the registration has succeeded.
				mrcs_retain(me);
			}
			break;
		}

		MDNS_COVERED_SWITCH_DEFAULT:
			err = kParamErr;
			goto exit;
	}
	new_request->command_id = command_id;
	*ptr = new_request;
	new_request = NULL;

exit:
	mrcs_forget(&new_request);
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_dns_service_registration_stop(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	const uint64_t command_id = mrc_xpc_message_get_id(msg);
	mrcs_dns_service_registration_request_t * const ptr = _mrcs_session_get_dns_service_registration(me, command_id);
	mrcs_dns_service_registration_request_t request = *ptr;
	mdns_require_action_quiet(request, exit, err = kIDErr);

	*ptr = request->next;
	request->next = NULL;
	err = _mrcs_server_dns_service_registration_stop(request->ident);
	mrcs_forget(&request);
	mdns_require_noerr_quiet(err, exit);

exit:
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_discovery_proxy_start(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	CFMutableArrayRef addresses = NULL;
	CFMutableArrayRef domains = NULL;
	CFMutableArrayRef certificates = NULL;

	mdns_require_action_quiet(!g_current_discovery_proxy_owner, exit, err = kAlreadyInitializedErr);

	const xpc_object_t params = mrc_xpc_message_get_params(msg);
	mdns_require_action_quiet(params, exit, err = kParamErr);

	// Get interface index.
	bool valid;
	const uint32_t ifindex = mrc_xpc_discovery_proxy_params_get_interface(params, &valid);
	mdns_require_action_quiet(valid, exit, err = kParamErr);

	// Get address list.
	const xpc_object_t addr_str_array = mrc_xpc_discovery_proxy_params_get_ip_address_strings(params);
	mdns_require_action_quiet(addr_str_array, exit, err = kParamErr);

	const size_t addr_count = xpc_array_get_count(addr_str_array);
	mdns_require_action_quiet(addr_count > 0, exit, err = kParamErr);

	addresses = CFArrayCreateMutable(kCFAllocatorDefault, (CFIndex)addr_count, &mdns_cfarray_callbacks);
	mdns_require_action_quiet(addresses, exit, err = kNoResourcesErr);

	for (size_t i = 0; i < addr_count; ++i) {
		const char * const addr_str = xpc_array_get_string(addr_str_array, i);
		mdns_require_action_quiet(addr_str, exit, err = kParamErr);

		mdns_address_t addr = mdns_address_create_from_ip_address_string(addr_str);
		mdns_require_action_quiet(addr, exit, err = kParamErr);

		CFArrayAppendValue(addresses, addr);
		mdns_forget(&addr);
	}

	// Get domain list.
	const xpc_object_t domain_array = mrc_xpc_discovery_proxy_params_get_match_domains(params);
	mdns_require_action_quiet(domain_array, exit, err = kParamErr);

	const size_t domain_count = xpc_array_get_count(domain_array);
	mdns_require_action_quiet(domain_count > 0, exit, err = kParamErr);

	domains = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	mdns_require_action_quiet(domains, exit, err = kNoResourcesErr);

	for (size_t i = 0; i < domain_count; ++i) {
		const char * const domain_str = xpc_array_get_string(domain_array, i);
		mdns_require_action_quiet(domain_str, exit, err = kParamErr);

		mdns_domain_name_t domain = mdns_domain_name_create(domain_str, mdns_domain_name_create_opts_none, &err);
		mdns_require_noerr_quiet(err, exit);

		CFArrayAppendValue(domains, domain);
		mdns_forget(&domain);
	}

	// Get certificate list.
	const xpc_object_t cert_array = mrc_xpc_discovery_proxy_params_get_server_certificates(params);
	mdns_require_action_quiet(domain_array, exit, err = kParamErr);

	const size_t cert_count = xpc_array_get_count(cert_array);
	mdns_require_action_quiet(cert_count > 0, exit, err = kParamErr);

	certificates = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
	mdns_require_action_quiet(certificates, exit, err = kParamErr);

	for (size_t i = 0; i < cert_count; ++i) {
		size_t data_len = 0;
		const uint8_t * const data_ptr = xpc_array_get_data(cert_array, i, &data_len);
		mdns_require_action_quiet(data_ptr && (data_len > 0), exit, err = kParamErr);

		CFDataRef cert_cf_data = CFDataCreate(kCFAllocatorDefault, data_ptr, (CFIndex)data_len);
		mdns_require_action_quiet(cert_cf_data, exit, err = kNoResourcesErr);

		CFArrayAppendValue(certificates, cert_cf_data);
		CFForget(&cert_cf_data);
	}

	err = _mrcs_server_discovery_proxy_start(ifindex, addresses, domains, certificates);
	mdns_require_noerr_quiet(err, exit);

	g_current_discovery_proxy_owner = me;
	mrcs_retain(g_current_discovery_proxy_owner);

exit:
	CFForget(&addresses);
	CFForget(&domains);
	CFForget(&certificates);
	return err;
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_discovery_proxy_stop(const mrcs_session_t me, __unused const xpc_object_t msg)
{
	OSStatus err = kNotInitializedErr;
	if (g_current_discovery_proxy_owner == me) {
		err = _mrcs_server_discovery_proxy_stop();
		mrcs_forget(&g_current_discovery_proxy_owner);
	}
	return err;
}

//======================================================================================================================

static mdns_xpc_dictionary_t
_mrcs_session_handle_record_cache_local_record_inquiry(OSStatus * const out_error)
{
	OSStatus err;
	mdns_xpc_dictionary_t result = mdns_xpc_dictionary_create_empty();
	require_action_quiet(result, exit, err = kNoResourcesErr);

	err = _mrcs_server_record_cache_enumerate_local_records(
	^(const char * const name, const uint8_t * const rdata, const uint16_t rdlen, const sockaddr_ip * const source_addr)
	{
		char *txt_str = NULL;
		if (rdata) {
			const OSStatus txt_str_err = DNSRecordDataToString(rdata, rdlen, kDNSRecordType_TXT, &txt_str);
			if (!txt_str) {
				os_log_fault(_mdns_server_log(),
					"Failed to create device-info TXT RDATA string -- record name: '%{private}s', error: %{mdns:err}ld",
					name, (long)txt_str_err);
			}
		}
		const char *source_addr_str = NULL;
		char str_buf[Max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
		switch (source_addr->sa.sa_family) {
			case AF_INET:
				source_addr_str = inet_ntop(AF_INET, &source_addr->v4.sin_addr.s_addr, str_buf, sizeof(str_buf));
				break;

			case AF_INET6:
				source_addr_str = inet_ntop(AF_INET6, source_addr->v6.sin6_addr.s6_addr, str_buf, sizeof(str_buf));
				break;

			default:
				break;
		}
		mrc_xpc_cached_local_record_inquiry_result_add(result, name, txt_str, source_addr_str);
		ForgetMem(&txt_str);
	});
	mdns_require_noerr_quiet(err, exit);

exit:
	mdns_assign(out_error, err);
	return result;
}

//======================================================================================================================

static OSStatus
_mrcs_session_handle_record_cache_flush(__unused const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	const xpc_object_t params = mrc_xpc_message_get_params(msg);
	mdns_require_action_quiet(params, exit, err = kParamErr);

	const char * const record_name = mrc_xpc_record_cache_flush_params_get_record_name(params);
	mdns_require_action_quiet(record_name, exit, err = kParamErr);

	bool have_key_tag = false;
	const uint16_t key_tag = mrc_xpc_record_cache_flush_params_get_key_tag(params, &have_key_tag);
	if (have_key_tag) {
		err = _mrcs_server_record_cache_flush_by_name_and_key_tag(record_name, key_tag);
		mdns_require_noerr_quiet(err, exit);
	} else {
		err = _mrcs_server_record_cache_flush_by_name(record_name);
		mdns_require_noerr_quiet(err, exit);
	}

exit:
	return err;
}

//======================================================================================================================

static mdns_xpc_dictionary_t
_mrcs_session_handle_command(const mrcs_session_t me, const char * const command_str, const xpc_object_t msg,
	OSStatus * const out_error)
{
	OSStatus err;
	mdns_xpc_dictionary_t result = NULL;
	const mrcs_command_t command = _mrcs_server_command_string_to_code(command_str);
	const char * const entitlement = _mrcs_server_get_required_entitlement(command);
	mdns_require_action_quiet(entitlement, exit, err = kCommandErr);

	const bool entitled = mdns_xpc_connection_is_entitled(me->connection, entitlement);
	require_action_quiet(entitled, exit, err = kMissingEntitlementErr);

	switch (command) {
		case mrcs_command_dns_proxy_start:
			err = _mrcs_session_handle_dns_proxy_start(me, msg);
			break;

		case mrcs_command_dns_proxy_stop:
			err = _mrcs_session_handle_dns_proxy_stop(me, msg);
			break;

		case mrcs_command_dns_proxy_get_state:
			result = _mrcs_session_handle_dns_proxy_get_state(&err);
			break;

		case mrcs_command_dns_service_registration_start:
			err = _mrcs_session_handle_dns_service_registration_start(me, msg);
			break;

		case mrcs_command_dns_service_registration_stop:
			err = _mrcs_session_handle_dns_service_registration_stop(me, msg);
			break;

		case mrcs_command_discovery_proxy_start:
			err = _mrcs_session_handle_discovery_proxy_start(me, msg);
			break;

		case mrcs_command_discovery_proxy_stop:
			err = _mrcs_session_handle_discovery_proxy_stop(me, msg);
			break;

		case mrcs_command_cached_local_record_inquiry:
			result = _mrcs_session_handle_record_cache_local_record_inquiry(&err);
			break;

		case mrcs_command_record_cache_flush:
			err = _mrcs_session_handle_record_cache_flush(me, msg);
			break;

		case mrcs_command_invalid:
		MDNS_COVERED_SWITCH_DEFAULT:
			err = kCommandErr;
			break;
	}

exit:
	if (out_error) {
		*out_error = err;
	}
	return result;
}

//======================================================================================================================

static void
_mrcs_session_handle_message(const mrcs_session_t me, const xpc_object_t msg)
{
	OSStatus err;
	mdns_xpc_dictionary_t result = NULL;
	const char * const command = mrc_xpc_message_get_command(msg);
	require_action_quiet(command, exit, err = kCommandErr);

	result = _mrcs_session_handle_command(me, command, msg, &err);
	require_noerr_quiet(err, exit);

exit:;
	xpc_object_t reply = mrc_xpc_create_reply(msg, err, result);
	xpc_forget(&result);
	if (reply) {
		xpc_connection_send_message(me->connection, reply);
		xpc_forget(&reply);
	}
}

//======================================================================================================================
// MARK: - Session Methods

static mrcs_dns_proxy_request_t
_mrcs_dns_proxy_request_create(const mrcs_dns_proxy_t proxy, const uint64_t command_id, OSStatus * const out_error)
{
	OSStatus err;
	mrcs_dns_proxy_request_t request = NULL;
	mrcs_dns_proxy_request_t obj = _mrcs_dns_proxy_request_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->proxy = proxy;
	mrcs_retain(obj->proxy);
	obj->command_id = command_id;
	request = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrcs_forget(&obj);
	return request;
}

//======================================================================================================================

static char *
_mrcs_dns_proxy_request_copy_description(const mrcs_dns_proxy_request_t me, __unused const bool debug,
	__unused const bool privacy)
{
	char *description = NULL;
	asprintf(&description, "<%s: %p>", me->base.kind->name, (void *)me);
	return description;
}

//======================================================================================================================

static void
_mrcs_dns_proxy_request_finalize(const mrcs_dns_proxy_request_t me)
{
	mrcs_forget(&me->proxy);
}

//======================================================================================================================
// MARK: - DNS Service Registration Request Methods

static char *
_mrcs_dns_service_registration_request_copy_description(const mrcs_dns_service_registration_request_t me,
	const bool debug, const bool privacy)
{
	char *description = NULL;
	const mdns_description_options_t desp_opt = (privacy ? mdns_description_opt_privacy : mdns_description_opt_none);
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrcs_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	if (me->do53_definition) {
		mdns_string_builder_append_description(sb, me->do53_definition, desp_opt);
	} else if (me->push_definition) {
		mdns_string_builder_append_description(sb, me->push_definition, desp_opt);
	} else {
		mdns_string_builder_append_formatted(sb, "<empty dns service definition>");
	}
	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrcs_dns_service_registration_request_finalize(const mrcs_dns_service_registration_request_t me)
{
	mdns_forget(&me->do53_definition);
	mdns_forget(&me->push_definition);
}

//======================================================================================================================
// MARK: - Helpers

static mrcs_dns_proxy_t
_mrcs_create_dns_proxy_from_params_dictionary(const xpc_object_t params, OSStatus * const out_error)
{
	OSStatus err;
	mrcs_dns_proxy_t result = NULL;
	mrcs_dns_proxy_t proxy = mrcs_dns_proxy_create(&err);
	require_noerr_quiet(err, exit);

	// Set input interfaces.
	const xpc_object_t input_interfaces = mrc_xpc_dns_proxy_params_get_input_interfaces(params);
	require_action_quiet(input_interfaces, exit, err = kParamErr);

	const size_t input_interface_count = xpc_array_get_count(input_interfaces);
	require_action_quiet(input_interface_count > 0, exit, err = kParamErr);

	bool valid;
	for (size_t i = 0; i < input_interface_count; ++i) {
		const uint32_t ifindex = mdns_xpc_array_get_uint32(input_interfaces, i, &valid);
		require_action_quiet(valid, exit, err = kParamErr);

		mrcs_dns_proxy_add_input_interface(proxy, ifindex);
	}
	// Set output interface.
	const uint32_t output_ifindex = mrc_xpc_dns_proxy_params_get_output_interface(params, &valid);
	require_action_quiet(valid, exit, err = kParamErr);

	mrcs_dns_proxy_set_output_interface(proxy, output_ifindex);

	// Set optional NAT64 prefix.
	size_t nat64_prefix_bitlen;
	const uint8_t * const nat64_prefix = mrc_xpc_dns_proxy_params_get_nat64_prefix(params, &nat64_prefix_bitlen);
	if (nat64_prefix) {
		err = mrcs_dns_proxy_set_nat64_prefix(proxy, nat64_prefix, nat64_prefix_bitlen);
		require_noerr_quiet(err, exit);
	}
	const bool force_aaaa_synthesis = mrc_xpc_dns_proxy_params_get_force_aaaa_synthesis(params, &valid);
	require_action_quiet(valid, exit, err = kParamErr);

	mrcs_dns_proxy_enable_force_aaaa_synthesis(proxy, force_aaaa_synthesis);
	result = proxy;
	proxy = NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrcs_forget(&proxy);
	return result;
}
