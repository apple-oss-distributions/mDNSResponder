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

#include <mrc/private.h>

#include "cf_support.h"
#include "helpers.h"
#include "memory.h"
#include "mrc_cached_local_record_keys.h"
#include "mrc_internal.h"
#include "mrc_object_internal.h"
#include "mrc_objects.h"
#include "mrc_xpc.h"
#include "us_ascii.h"
#include "utf8.h"

#include <arpa/inet.h>
#include <CoreUtils/CoreUtils.h>
#include <mdns/dns_service.h>
#include <mdns/DNSMessage.h>
#include <mdns/string_builder.h>
#include <mdns/xpc.h>
#include <os/log.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Session Kind Definition

MDNS_CLOSED_ENUM(mrc_session_event_t, uint8_t,
	mrc_session_event_started		= 1,
	mrc_session_event_interruption	= 2,
	mrc_session_event_invalidated	= 3,
);

MDNS_CLOSED_ENUM(mrc_session_state_t, int8_t,
	mrc_session_state_invalidated	= -1,
	mrc_session_state_nascent		=  0,
	mrc_session_state_starting		=  1,
	mrc_session_state_started		=  2,
	mrc_session_state_done			=  3,
);

struct mrc_session_s {
	struct mdns_obj_s	base;			// Object base.
	uint64_t			cmd_id;			// Current command ID.
	mrc_session_t		next;			// Next session in list.
	mrc_client_t		client;			// Delegate object to use when invoking callbacks.
	const char *		entity_name;	// For logging purposes, the name of the entity that is to be enabled.
	mrc_session_state_t	state;			// Current state of the session.
};

MRC_OBJECT_SUBKIND_DEFINE(session);

//======================================================================================================================
// MARK: - Client Kind Definition

MDNS_CLOSED_ENUM(mrc_client_state_t, uint8_t,
	mrc_client_state_nascent		= 0,
	mrc_client_state_activated		= 1,
	mrc_client_state_invalidated	= 2,
);

struct mrc_client_s {
	struct mdns_obj_s	base;		// Object base.
	mrc_session_t		session;	// Used to enable the DNS proxy on mDNSResponder.
	dispatch_queue_t	user_queue;	// User's dispatch queue.
	mrc_client_state_t	state;		// Current state.
	bool				immutable;	// True if the DNS proxy is no longer externally mutable.
};

MRC_OBJECT_SUBKIND_DEFINE_ABSTRACT_MINIMAL_WITHOUT_ALLOC(client);

typedef union {
	MRC_UNION_MEMBER(client);
	MRC_UNION_MEMBER(cached_local_records_inquiry);
	MRC_UNION_MEMBER(discovery_proxy);
	MRC_UNION_MEMBER(dns_proxy);
	MRC_UNION_MEMBER(dns_service_registration);
	MRC_UNION_MEMBER(record_cache_flush);
} mrc_any_client_t __attribute__((__transparent_union__));

typedef xpc_object_t
(*mrc_client_create_start_message_f)(mrc_any_client_t any, uint64_t cmd_id);

typedef xpc_object_t
(*mrc_client_create_stop_message_f)(mrc_any_client_t any, uint64_t cmd_id);

typedef void
(*mrc_client_handle_start_f)(mrc_any_client_t any, xpc_object_t result);

typedef void
(*mrc_client_handle_interruption_f)(mrc_any_client_t any);

typedef void
(*mrc_client_handle_invalidation_f)(mrc_any_client_t any, OSStatus error);

typedef void
(*mrc_client_handle_notification_f)(mrc_any_client_t any, xpc_object_t notification);

typedef const struct mrc_client_kind_s *mrc_client_kind_t;
struct mrc_client_kind_s {
	struct mdns_kind_s					base;
	mrc_client_create_start_message_f	create_start_message;
	mrc_client_create_stop_message_f	create_stop_message;
	mrc_client_handle_start_f			handle_start;
	mrc_client_handle_interruption_f	handle_interruption;
	mrc_client_handle_invalidation_f	handle_invalidation;
	mrc_client_handle_notification_f	handle_notification;
	const char *						operation_name;
	bool								oneshot;
};

#define MRC_CLIENT_SUBKIND_DEFINE_CORE(NAME, OPERATION_NAME, ...)								\
	static char *																				\
	_mrc_ ## NAME ## _copy_description(mrc_ ## NAME ## _t client, bool debug, bool privacy);	\
																								\
	static void																					\
	_mrc_ ## NAME ## _finalize(mrc_ ## NAME ## _t client);										\
																								\
	static xpc_object_t																			\
	_mrc_ ## NAME ## _create_start_message(mrc_ ## NAME ## _t client, uint64_t cmd_id);			\
																								\
	static void																					\
	_mrc_ ## NAME ## _handle_start(mrc_ ## NAME ## _t client, xpc_object_t result);				\
																								\
	static void																					\
	_mrc_ ## NAME ## _handle_invalidation(mrc_ ## NAME ## _t client, OSStatus error);			\
																								\
	static const struct mrc_client_kind_s _mrc_ ## NAME ## _kind = {							\
		MDNS_CLANG_IGNORE_INCOMPATIBLE_FUNCTION_POINTER_TYPES_STRICT_WARNING_BEGIN()			\
		.base = {																				\
			.superkind			= &_mrc_client_kind,											\
			.name				= "mrc_" # NAME,												\
			.copy_description	= _mrc_ ## NAME ## _copy_description,							\
			.finalize			= _mrc_ ## NAME ## _finalize,									\
		},																						\
		.create_start_message	= _mrc_ ## NAME ## _create_start_message,						\
		.handle_start			= _mrc_ ## NAME ## _handle_start,								\
		.handle_invalidation	= _mrc_ ## NAME ## _handle_invalidation,						\
		.operation_name			= OPERATION_NAME,												\
		__VA_ARGS__																				\
		MDNS_CLANG_IGNORE_INCOMPATIBLE_FUNCTION_POINTER_TYPES_STRICT_WARNING_END()				\
	};																							\
	MRC_OBJECT_SUBKIND_DEFINE_ALLOC(NAME);														\
	MRC_OBJECT_SUBKIND_DEFINE_NEW_WITH_KIND(NAME, &_mrc_ ## NAME ## _kind.base);				\
	MRC_BASE_CHECK(NAME, client)

#define MRC_CLIENT_SUBKIND_DEFINE_EX(NAME, OPERATION_NAME, ...)							\
	static xpc_object_t																	\
	_mrc_ ## NAME ## _create_stop_message(mrc_ ## NAME ## _t client, uint64_t cmd_id);	\
																						\
	static void																			\
	_mrc_ ## NAME ## _handle_interruption(mrc_ ## NAME ## _t client);					\
																						\
	MRC_CLIENT_SUBKIND_DEFINE_CORE(NAME, OPERATION_NAME,								\
		.create_stop_message	= _mrc_ ## NAME ## _create_stop_message,				\
		.handle_interruption	= _mrc_ ## NAME ## _handle_interruption,				\
		.oneshot				= false,												\
		__VA_ARGS__																		\
	)

#define MRC_CLIENT_SUBKIND_DEFINE(NAME, OPERATION_NAME) \
	MRC_CLIENT_SUBKIND_DEFINE_EX(NAME, OPERATION_NAME)

#define MRC_CLIENT_SUBKIND_DEFINE_WITH_NOTIFICATION_HANDLING(NAME, OPERATION_NAME)					\
	static void																						\
	_mrc_ ## NAME ## _handle_notification(mrc_ ## NAME ## _t client, xpc_object_t notification);	\
																									\
	MRC_CLIENT_SUBKIND_DEFINE_EX(NAME, OPERATION_NAME,												\
		.handle_notification = _mrc_ ## NAME ## _handle_notification								\
	)

#define MRC_CLIENT_SUBKIND_DEFINE_ONE_SHOT(NAME, OPERATION_NAME)	\
	MRC_CLIENT_SUBKIND_DEFINE_CORE(NAME, OPERATION_NAME,			\
		.oneshot = true,											\
	)

//======================================================================================================================
// MARK: - DNS Proxy Kind Definition

struct mrc_dns_proxy_s {
	struct mrc_client_s				base;			// Object base.
	xpc_object_t					params;			// DNS proxy parameters.
	mrc_dns_proxy_event_handler_t	event_handler;	// User's event handler.
};

MRC_CLIENT_SUBKIND_DEFINE(dns_proxy, "DNS Proxy");

//======================================================================================================================

struct mrc_dns_proxy_parameters_s {
	struct mdns_obj_s	base;	// Object base.
	xpc_object_t		dict;	// DNS proxy parameters.
};

MRC_OBJECT_SUBKIND_DEFINE(dns_proxy_parameters);

//======================================================================================================================
// MARK: - DNS Proxy State Inquiry Kind Definition

OS_CLOSED_ENUM(mrc_dns_proxy_state_inquiry_state, int8_t,
	mrc_dns_proxy_state_inquiry_state_nascent		= 0,
	mrc_dns_proxy_state_inquiry_state_registered	= 1,
	mrc_dns_proxy_state_inquiry_state_in_progress	= 2,
	mrc_dns_proxy_state_inquiry_state_done			= 3
);

struct mrc_dns_proxy_state_inquiry_s {
	struct mdns_obj_s								base;		// Object base.
	mrc_dns_proxy_state_inquiry_t					next;		// Next inquiry in list.
	dispatch_queue_t								queue;		// User's dispatch queue.
	mrc_dns_proxy_state_inquiry_response_handler_t	handler;	// Response handler.
	uint64_t										cmd_id;		// Command ID.
	mrc_dns_proxy_state_inquiry_state_t				state;		// Current inquiry state.
	bool											immutable;	// True if this object is no longer externally mutable.
};

MRC_OBJECT_SUBKIND_DEFINE(dns_proxy_state_inquiry);

//======================================================================================================================
// MARK: - DNS Service Registration Kind Definition

struct mrc_dns_service_registration_s {
	struct mrc_client_s								base;						// Object base.
	xpc_object_t									definition_dict;			// DNS service definition as dictionary.
	mrc_dns_service_registration_event_handler_t	event_handler;				// Event handler.
	mrc_dns_service_definition_type_t				definition_type;			// The type of the DNS service.
	bool											reports_connection_errors;	// Whether to report connection error.
};

MRC_CLIENT_SUBKIND_DEFINE_WITH_NOTIFICATION_HANDLING(dns_service_registration, "DNS Service Registration");

//======================================================================================================================
// MARK: - Discovery Proxy Kind Definition

struct mrc_discovery_proxy_s {
	struct mrc_client_s					base;			// Object base.
	mrc_discovery_proxy_parameters_t	params;			// Discovery proxy parameters.
	mrc_discovery_proxy_event_handler_t	event_handler;	// Event handler.
};

MRC_CLIENT_SUBKIND_DEFINE(discovery_proxy, "Discovery Proxy");

//======================================================================================================================

struct mrc_discovery_proxy_parameters_s {
	struct mdns_obj_s	base;				// Object base.
	CFMutableArrayRef	server_addresses;	// Server IP addresses.
	CFMutableSetRef		domains;			// Domains to match in order to use the proxy.
	xpc_object_t		certs;				// Certificates that can be used as trust anchors for TLS evaluation.
	uint32_t			ifindex;			// Index of the interface where the proxy can be configured.
};

MRC_OBJECT_SUBKIND_DEFINE(discovery_proxy_parameters);

//======================================================================================================================
// MARK: - Cached Local Records Inquiry Kind Definition

struct mrc_cached_local_records_inquiry_s {
	struct mrc_client_s									base;		// Object base.
	mrc_cached_local_records_inquiry_result_handler_t	handler;	// User handler.
};

MRC_CLIENT_SUBKIND_DEFINE_ONE_SHOT(cached_local_records_inquiry, "Cached Local Records Inquiry");

// Keys for record info dictionaries.
const char * const mrc_cached_local_record_key_first_label		= MRC_CACHED_LOCAL_RECORD_KEY_FIRST_LABEL;
const char * const mrc_cached_local_record_key_name				= MRC_CACHED_LOCAL_RECORD_KEY_NAME;
const char * const mrc_cached_local_record_key_rdata			= MRC_CACHED_LOCAL_RECORD_KEY_RDATA;
const char * const mrc_cached_local_record_key_source_address	= MRC_CACHED_LOCAL_RECORD_KEY_SOURCE_ADDRESS;

//======================================================================================================================
// MARK: - Record Cache Flush Kind Definition

struct mrc_record_cache_flush_s {
	struct mrc_client_s						base;			// Object base.
	mdns_domain_name_t						record_name;	// Record name.
	mrc_record_cache_flush_result_handler_t	handler;		// User handler.
	uint16_t								key_tag;		// Key tag.
	bool									have_key_tag;	// True if the key tag value was set.
};

MRC_CLIENT_SUBKIND_DEFINE_ONE_SHOT(record_cache_flush, "Record Cache Flush");

//======================================================================================================================
// MARK: - Local Prototypes

static mrc_session_t
_mrc_session_create(mrc_client_t client);

static void
_mrc_session_activate_async(mrc_session_t session);

static void
_mrc_session_invalidate_async(mrc_session_t session, OSStatus error);

static void
_mrc_dns_proxy_state_inquiry_register(mrc_dns_proxy_state_inquiry_t inquiry);

static void
_mrc_dns_proxy_state_inquiry_deregister(mrc_dns_proxy_state_inquiry_t inquiry);

static void
_mrc_dns_proxy_state_inquiry_send_command(mrc_dns_proxy_state_inquiry_t inquiry);

static void
_mrc_dns_proxy_state_inquiry_terminate_with_error(mrc_dns_proxy_state_inquiry_t inquiry, OSStatus error);

static void
_mrc_dns_proxy_state_inquiry_terminate_with_state_description(mrc_dns_proxy_state_inquiry_t inquiry,
	mdns_xpc_string_t description);

static mrc_discovery_proxy_parameters_t
_mrc_discovery_proxy_parameters_create_or_copy(mrc_discovery_proxy_parameters_t original);

static xpc_object_t
_mrc_discovery_proxy_parameters_create_xpc_dictionary(mrc_discovery_proxy_parameters_t params);

static uint64_t
_mrc_client_get_new_command_id(void);

static os_log_t
_mrc_client_log(void);

static dispatch_queue_t
_mrc_client_queue(void);

static xpc_connection_t
_mrc_client_connection(void);

static OSStatus
_mrc_xpc_dns_proxy_params_print_description(xpc_object_t params, bool debug, bool privacy, char *buf, size_t buf_len,
	size_t *out_len, size_t *out_full_len);

//======================================================================================================================
// MARK: - Globals

static mrc_session_t g_session_list = NULL;
static mrc_dns_proxy_state_inquiry_t g_dns_proxy_state_inquiry_list = NULL;

//======================================================================================================================
// MARK: - Client Private Methods

static void
_mrc_client_finalize(const mrc_client_t me)
{
	dispatch_forget(&me->user_queue);
}

//======================================================================================================================

static void
_mrc_client_set_queue(const mrc_any_client_t any, const dispatch_queue_t queue)
{
	const mrc_client_t me = any._mrc_client;
	mdns_require_return(!me->immutable);

	if (queue) {
		dispatch_retain(queue);
	}
	dispatch_forget(&me->user_queue);
	me->user_queue = queue;
}

//======================================================================================================================

static mrc_client_kind_t
_mrc_client_get_client_kind(const mrc_client_t me)
{
	return (mrc_client_kind_t)mrc_get_kind(me);
}

//======================================================================================================================

static void
_mrc_client_invalidate_direct(const mrc_client_t me, const OSStatus error)
{
	require_return(me->state != mrc_client_state_invalidated);

	if (me->session) {
		_mrc_session_invalidate_async(me->session, kNoErr);
		mrc_forget(&me->session);
	}
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	kind->handle_invalidation(me, error);
	me->state = mrc_client_state_invalidated;
}

//======================================================================================================================

static void
_mrc_client_invalidate_async(const mrc_any_client_t any, const OSStatus error)
{
	const mrc_client_t me = any._mrc_client;
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_client_invalidate_direct(me, error);
		mrc_release(me);
	});
}

//======================================================================================================================

static void
_mrc_client_activate_direct(const mrc_client_t me)
{
	mdns_require_return(me->state == mrc_client_state_nascent);

	me->state = mrc_client_state_activated;
	me->session = _mrc_session_create(me);
	if (me->session) {
		_mrc_session_activate_async(me->session);
	} else {
		_mrc_client_invalidate_async(me, kNoResourcesErr);
	}
}

//======================================================================================================================

static void
_mrc_client_activate_async(const mrc_any_client_t any)
{
	const mrc_client_t me = any._mrc_client;
	me->immutable = true;
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_client_activate_direct(me);
		mrc_release(me);
	});
}

//======================================================================================================================

static xpc_object_t
_mrc_client_create_start_message(const mrc_client_t me, const uint64_t cmd_id)
{
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	return kind->create_start_message(me, cmd_id);
}

//======================================================================================================================

static xpc_object_t
_mrc_client_create_stop_message(const mrc_client_t me, const uint64_t cmd_id)
{
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	if (kind->create_stop_message) {
		return kind->create_stop_message(me, cmd_id);
	} else {
		return NULL;
	}
}

//======================================================================================================================

static const char *
_mrc_client_get_operation_name(const mrc_client_t me)
{
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	return kind->operation_name;
}

//======================================================================================================================

static void
_mrc_client_handle_start(const mrc_client_t me, xpc_object_t start_result)
{
	mdns_require_return(me->session);
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	kind->handle_start(me, start_result);
}

//======================================================================================================================

static void
_mrc_client_handle_interruption(const mrc_client_t me)
{
	mdns_require_return(me->session);
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	if (kind->handle_interruption) {
		kind->handle_interruption(me);
	}
}

//======================================================================================================================

static bool
_mrc_client_handle_notification(const mrc_client_t me, const xpc_object_t notification)
{
	bool handled = false;
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	if (kind->handle_notification) {
		kind->handle_notification(me, notification);
		handled = true;
	}
	return handled;
}

//======================================================================================================================

static void
_mrc_client_handle_error(const mrc_client_t me, const OSStatus error)
{
	mdns_require_return(me->session);
	_mrc_client_invalidate_async(me, error);
}

//======================================================================================================================

static bool
_mrc_client_is_oneshot(const mrc_client_t me)
{
	const mrc_client_kind_t kind = _mrc_client_get_client_kind(me);
	return kind->oneshot;
}

//======================================================================================================================

static dispatch_queue_t
_mrc_client_get_user_queue(const mrc_any_client_t any)
{
	const mrc_client_t me = any._mrc_client;
	return me->user_queue;
}

//======================================================================================================================

static bool
_mrc_client_is_immutable(const mrc_any_client_t any)
{
	const mrc_client_t me = any._mrc_client;
	return me->immutable;
}

//======================================================================================================================
// MARK: - Session Private Methods

static mrc_session_t
_mrc_session_create(const mrc_client_t client)
{
	mrc_session_t session = NULL;
	mrc_session_t obj = _mrc_session_new();
	mdns_require_quiet(obj, exit);

	obj->client = client;
	mrc_retain(obj->client);
	obj->entity_name = _mrc_client_get_operation_name(obj->client);
	session = obj;
	obj = NULL;

exit:
	mrc_forget(&obj);
	return session;
}

//======================================================================================================================

static char *
_mrc_session_copy_description(const mrc_session_t me, const bool debug, __unused const bool privacy)
{
	char *description = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	err = mdns_string_builder_append_formatted(sb, "entity: %s", me->entity_name);
	mdns_require_noerr_quiet(err, exit);

	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_session_finalize(const mrc_session_t me)
{
	mrc_forget(&me->client);
}

//======================================================================================================================

static void
_mrc_session_handle_stop_reply(const mrc_session_t me, const xpc_object_t reply)
{
	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		bool valid;
		OSStatus err = mrc_xpc_message_get_error(reply, &valid);
		if (!valid) {
			err = kResponseErr;
		}
		os_log_with_type(_mrc_client_log(), err ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
			"[S%" PRIu64 "] %{public}s stop reply -- error: %{mdns:err}ld", me->cmd_id, me->entity_name, (long)err);
	} else {
		char *description = xpc_copy_description(reply);
		os_log_error(_mrc_client_log(),
			"[S%" PRIu64 "] Abnormal %{public}s stop reply: %{public}s", me->cmd_id, me->entity_name, description);
		ForgetMem(&description);
	}
}

//======================================================================================================================

static void
_mrc_session_send_stop_message(const mrc_session_t me)
{
	xpc_object_t msg = _mrc_client_create_stop_message(me->client, me->cmd_id);
	mdns_require_return(msg);

	mrc_retain(me);
	xpc_connection_send_message_with_reply(_mrc_client_connection(), msg, _mrc_client_queue(),
	^(const xpc_object_t reply)
	{
		_mrc_session_handle_stop_reply(me, reply);
		mrc_release(me);
	});
	xpc_forget(&msg);
}

//======================================================================================================================

static void
_mrc_session_invalidate_direct(const mrc_session_t me, const OSStatus error)
{
	mdns_require_return(me->state != mrc_session_state_invalidated);

	mrc_session_t *ptr = &g_session_list;
	while (*ptr && (*ptr != me)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		mrc_release(*ptr);
		*ptr = me->next;
		me->next = NULL;
		switch (me->state) {
			case mrc_session_state_starting:
			case mrc_session_state_started:
				_mrc_session_send_stop_message(me);
				break;

			case mrc_session_state_done:
			case mrc_session_state_invalidated:
			case mrc_session_state_nascent:
			MDNS_COVERED_SWITCH_DEFAULT:
				break;
		}
		me->state = mrc_session_state_invalidated;
		_mrc_client_handle_error(me->client, error);
		mrc_forget(&me->client);
	}
}

//======================================================================================================================

static void
_mrc_session_invalidate_async(const mrc_session_t me, const OSStatus error)
{
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_session_invalidate_direct(me, error);
		mrc_release(me);
	});
}

//======================================================================================================================

static void
_mrc_session_terminate(const mrc_session_t me, const OSStatus error)
{
	me->state = mrc_session_state_done;
	_mrc_session_invalidate_async(me, error);
}

//======================================================================================================================

static void
_mrc_session_handle_start_reply(const mrc_session_t me, const uint64_t cmd_id, const xpc_object_t reply)
{
	mdns_require_return(me->state == mrc_session_state_starting);
	mdns_require_return(me->cmd_id == cmd_id);

	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		bool valid;
		OSStatus err = mrc_xpc_message_get_error(reply, &valid);
		if (!valid) {
			err = kResponseErr;
		}
		os_log_with_type(_mrc_client_log(), err ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
			"[S%" PRIu64 "] %{public}s start reply -- error: %{mdns:err}ld", me->cmd_id, me->entity_name, (long)err);
		if (!err) {
			_mrc_client_handle_start(me->client, mrc_xpc_message_get_result(reply));
		}
		if (err || _mrc_client_is_oneshot(me->client)) {
			_mrc_session_terminate(me, err);
		} else {
			me->state = mrc_session_state_started;
		}
	} else {
		char *description = xpc_copy_description(reply);
		os_log_error(_mrc_client_log(),
			"[S%" PRIu64 "] Abnormal %{public}s start reply: %{public}s", me->cmd_id, me->entity_name, description);
		ForgetMem(&description);
		if (reply != XPC_ERROR_CONNECTION_INTERRUPTED) {
			const OSStatus err = (reply == XPC_ERROR_CONNECTION_INVALID) ? kConnectionErr : kResponseErr;
			_mrc_session_terminate(me, err);
		}
	}
}

//======================================================================================================================

static void
_mrc_session_send_start_message(const mrc_session_t me)
{
	me->state = mrc_session_state_starting;
	me->cmd_id = _mrc_client_get_new_command_id();
	xpc_object_t msg = _mrc_client_create_start_message(me->client, me->cmd_id);
	mdns_require_quiet(msg, exit);

	mrc_retain(me);
	const uint64_t cmd_id = me->cmd_id;
	xpc_connection_send_message_with_reply(_mrc_client_connection(), msg, _mrc_client_queue(),
	^(const xpc_object_t reply)
	{
		_mrc_session_handle_start_reply(me, cmd_id, reply);
		mrc_release(me);
	});

exit:
	xpc_forget(&msg);
}

//======================================================================================================================

static void
_mrc_session_activate_direct(const mrc_session_t me)
{
	mdns_require_return(me->state == mrc_session_state_nascent);

	mrc_session_t *ptr = &g_session_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	*ptr = me;
	mrc_retain(*ptr);
	_mrc_session_send_start_message(me);
}

//======================================================================================================================

static void
_mrc_session_activate_async(const mrc_session_t me)
{
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_session_activate_direct(me);
		mrc_release(me);
	});
}

//======================================================================================================================

static void
_mrc_session_handle_connection_interruption(const mrc_session_t me)
{
	switch (me->state) {
		case mrc_session_state_starting:
		case mrc_session_state_started:
			if (me->state == mrc_session_state_started) {
				_mrc_client_handle_interruption(me->client);
			}
			_mrc_session_send_start_message(me);
			break;

		case mrc_session_state_done:
		case mrc_session_state_invalidated:
		case mrc_session_state_nascent:
		MDNS_COVERED_SWITCH_DEFAULT:
			break;
	}
}

//======================================================================================================================

static void
_mrc_session_handle_notification(const mrc_session_t me, const xpc_object_t notification)
{
	const xpc_object_t notification_body = mrc_xpc_notification_get_body(notification);
	if (notification_body) {
		const bool handled = _mrc_client_handle_notification(me->client, notification_body);
		if (!handled) {
			char *description = xpc_copy_description(notification_body);
			os_log_fault(_mrc_client_log(),
				"[S%" PRIu64 "] Notification for %{public}s was unhandled: %{private}s",
				me->cmd_id, me->entity_name, description);
			ForgetMem(&description);
		}
	} else {
		char *description = xpc_copy_description(notification);
		os_log_fault(_mrc_client_log(),
			"[S%" PRIu64 "] Notification for %{public}s is missing body: %{private}s",
			me->cmd_id, me->entity_name, description);
		ForgetMem(&description);
	}
}

//======================================================================================================================
// MARK: - DNS Proxy Public Methods

mrc_dns_proxy_t
mrc_dns_proxy_create(const mrc_dns_proxy_parameters_t params, OSStatus * const out_error)
{
	OSStatus err;
	mrc_dns_proxy_t proxy = NULL;
	mrc_dns_proxy_t obj = _mrc_dns_proxy_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->params = xpc_copy(params->dict);
	require_action_quiet(obj->params, exit, err = kNoResourcesErr);

	proxy = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrc_forget(&obj);
	return proxy;
}

//======================================================================================================================

void
mrc_dns_proxy_set_queue(const mrc_dns_proxy_t me, const dispatch_queue_t queue)
{
	_mrc_client_set_queue(me, queue);
}

//======================================================================================================================

void
mrc_dns_proxy_set_event_handler(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_handler_t handler)
{
	mdns_require_return(!_mrc_client_is_immutable(me));

	const mrc_dns_proxy_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->event_handler);
	me->event_handler = new_handler;
}

//======================================================================================================================

void
mrc_dns_proxy_activate(const mrc_dns_proxy_t me)
{
	_mrc_client_activate_async(me);
}

//======================================================================================================================

void
mrc_dns_proxy_invalidate(const mrc_dns_proxy_t me)
{
	_mrc_client_invalidate_async(me, kNoErr);
}

//======================================================================================================================
// MARK: - DNS Proxy Private Methods

static OSStatus
_mrc_dns_proxy_print_description(const mrc_dns_proxy_t me, const bool debug, const bool privacy, char * const buf,
	const size_t buf_len, size_t * const out_len, size_t * const out_full_len)
{
	OSStatus err;
	char *dst = buf;
	const char * const lim = &buf[buf_len];
	size_t full_len = 0;

#define _do_appendf(...)											\
	do {															\
		const int _n = mdns_snprintf_add(&dst, lim, __VA_ARGS__);	\
		require_action_quiet(_n >= 0, exit, err = kUnknownErr);		\
		full_len += (size_t)_n;										\
	} while(0)

	if (debug) {
		_do_appendf("<%s: %p>: ", mrc_get_kind(me)->name, me);
	}
#undef _do_appendf
	size_t wrote_len, desc_full_len;
	err = _mrc_xpc_dns_proxy_params_print_description(me->params, debug, privacy, dst, (size_t)(lim - dst), &wrote_len,
		&desc_full_len);
	require_noerr_quiet(err, exit);

	dst += wrote_len;
	full_len += desc_full_len;

	if (out_len) {
		*out_len = (size_t)(dst - buf);
	}
	if (out_full_len) {
		*out_full_len = full_len;
	}

exit:
	return err;
}

//======================================================================================================================

static char *
_mrc_dns_proxy_copy_description(const mrc_dns_proxy_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	char buf[128];
	size_t full_len;
	OSStatus err = _mrc_dns_proxy_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &full_len);
	require_noerr_quiet(err, exit);

	if (full_len < sizeof(buf)) {
		description = mdns_strdup(buf);
	} else {
		const size_t buf_len = full_len + 1;
		char *buf_ptr = (char *)mdns_malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mrc_dns_proxy_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		require_noerr_action_quiet(err, exit, ForgetMem(&buf_ptr));

		description = buf_ptr;
	}

exit:
	return description;
}

//======================================================================================================================

static void
_mrc_dns_proxy_finalize(const mrc_dns_proxy_t me)
{
	xpc_forget(&me->params);
}

//======================================================================================================================

static xpc_object_t
_mrc_dns_proxy_create_start_message(const mrc_dns_proxy_t me, const uint64_t cmd_id)
{
	return mrc_xpc_create_dns_proxy_start_command_message(cmd_id, me->params);
}

//======================================================================================================================

static xpc_object_t
_mrc_dns_proxy_create_stop_message(__unused const mrc_dns_proxy_t me, const uint64_t cmd_id)
{
	return mrc_xpc_create_dns_proxy_stop_command_message(cmd_id);
}

//======================================================================================================================

static void
_mrc_dns_proxy_generate_event_with_error(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_t event,
	const OSStatus error)
{
	const dispatch_queue_t user_queue = _mrc_client_get_user_queue(me);
	const mrc_dns_proxy_event_handler_t event_handler = me->event_handler;
	mdns_require_quiet(user_queue && event_handler, exit);

	dispatch_async(user_queue,
	^{
		event_handler(event, error);
	});

exit:
	if (event == mrc_dns_proxy_event_invalidation) {
		BlockForget(&me->event_handler);
	}
}

//======================================================================================================================

static void
_mrc_dns_proxy_generate_event(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_t event)
{
	_mrc_dns_proxy_generate_event_with_error(me, event, kNoErr);
}

//======================================================================================================================

static void
_mrc_dns_proxy_handle_start(const mrc_dns_proxy_t me, __unused const xpc_object_t result)
{
	_mrc_dns_proxy_generate_event(me, mrc_dns_proxy_event_started);
}

//======================================================================================================================

static void
_mrc_dns_proxy_handle_interruption(const mrc_dns_proxy_t me)
{
	_mrc_dns_proxy_generate_event(me, mrc_dns_proxy_event_interruption);
}

//======================================================================================================================

static void
_mrc_dns_proxy_handle_invalidation(const mrc_dns_proxy_t me, const OSStatus error)
{
	_mrc_dns_proxy_generate_event_with_error(me, mrc_dns_proxy_event_invalidation, error);
}

//======================================================================================================================
// MARK: - DNS Proxy Parameters Public Methods

mrc_dns_proxy_parameters_t
mrc_dns_proxy_parameters_create(OSStatus * const out_error)
{
	OSStatus err;
	mrc_dns_proxy_parameters_t params = NULL;
	mrc_dns_proxy_parameters_t obj = _mrc_dns_proxy_parameters_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->dict = xpc_dictionary_create(NULL, NULL, 0);
	require_action_quiet(obj->dict, exit, err = kNoResourcesErr);

	params = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrc_forget(&obj);
	return params;
}

//======================================================================================================================

void
mrc_dns_proxy_parameters_add_input_interface(const mrc_dns_proxy_parameters_t me, const uint32_t ifindex)
{
	mrc_xpc_dns_proxy_params_add_input_interface(me->dict, ifindex);
}

//======================================================================================================================

void
mrc_dns_proxy_parameters_set_output_interface(const mrc_dns_proxy_parameters_t me, const uint32_t ifindex)
{
	mrc_xpc_dns_proxy_params_set_output_interface(me->dict, ifindex);
}

//======================================================================================================================

void
mrc_dns_proxy_parameters_set_nat64_prefix(const mrc_dns_proxy_parameters_t me, const uint8_t * const prefix,
	const size_t prefix_bitlen)
{
	mrc_xpc_dns_proxy_params_set_nat64_prefix(me->dict, prefix, prefix_bitlen);
}

//======================================================================================================================

void
mrc_dns_proxy_parameters_set_force_aaaa_synthesis(const mrc_dns_proxy_parameters_t me, bool value)
{
	mrc_xpc_dns_proxy_params_set_force_aaaa_synthesis(me->dict, value);
}

//======================================================================================================================

bool
mrc_dns_proxy_parameters_enumerate_input_interfaces(const mrc_dns_proxy_parameters_t me,
	const mrc_dns_proxy_parameters_interface_applier_t applier)
{
	bool completed = false;
	const xpc_object_t interfaces = mrc_xpc_dns_proxy_params_get_input_interfaces(me->dict);
	const size_t n = interfaces ? xpc_array_get_count(interfaces) : 0;
	for (size_t i = 0; i < n; ++i) {
		const uint32_t ifindex = mdns_xpc_array_get_uint32(interfaces, i, NULL);
		const bool proceed = applier(ifindex);
		if (!proceed) {
			goto exit;
		}
	}
	completed = true;

exit:
	return completed;
}

//======================================================================================================================

uint32_t
mrc_dns_proxy_parameters_get_output_interface(const mrc_dns_proxy_parameters_t me)
{
	return mrc_xpc_dns_proxy_params_get_output_interface(me->dict, NULL);
}

//======================================================================================================================

bool
mrc_dns_proxy_parameters_get_force_aaaa_synthesis(const mrc_dns_proxy_parameters_t me)
{
	return mrc_xpc_dns_proxy_params_get_force_aaaa_synthesis(me->dict, NULL);
}

//======================================================================================================================
// MARK: - DNS Proxy Parameters Private Methods

static OSStatus
_mrc_dns_proxy_parameters_print_description(const mrc_dns_proxy_parameters_t me, const bool debug,
	const bool privacy, char * const buf, const size_t buf_len, size_t * const out_len, size_t * const out_full_len)
{
	OSStatus err;
	char *dst = buf;
	const char * const lim = &buf[buf_len];
	size_t full_len = 0;

#define _do_appendf(...)											\
	do {															\
		const int _n = mdns_snprintf_add(&dst, lim, __VA_ARGS__);	\
		require_action_quiet(_n >= 0, exit, err = kUnknownErr);		\
		full_len += (size_t)_n;										\
	} while(0)

	if (debug) {
		_do_appendf("<%s: %p>: ", me->base.kind->name, me);
	}
#undef _do_appendf
	size_t wrote_len, desc_full_len;
	err = _mrc_xpc_dns_proxy_params_print_description(me->dict, debug, privacy, dst, (size_t)(lim - dst), &wrote_len,
		&desc_full_len);
	require_noerr_quiet(err, exit);

	dst += wrote_len;
	full_len += desc_full_len;

	if (out_len) {
		*out_len = (size_t)(dst - buf);
	}
	if (out_full_len) {
		*out_full_len = full_len;
	}

exit:
	return err;
}

//======================================================================================================================

static char *
_mrc_dns_proxy_parameters_copy_description(const mrc_dns_proxy_parameters_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	char buf[128];
	size_t full_len;
	OSStatus err = _mrc_dns_proxy_parameters_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &full_len);
	require_noerr_quiet(err, exit);

	if (full_len < sizeof(buf)) {
		description = mdns_strdup(buf);
	} else {
		const size_t buf_len = full_len + 1;
		char *buf_ptr = (char *)mdns_malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mrc_dns_proxy_parameters_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		require_noerr_action_quiet(err, exit, ForgetMem(&buf_ptr));

		description = buf_ptr;
	}

exit:
	return description;
}

//======================================================================================================================

static void
_mrc_dns_proxy_parameters_finalize(const mrc_dns_proxy_parameters_t me)
{
	xpc_forget(&me->dict);
}

//======================================================================================================================
// MARK: - DNS Proxy State Inquiry Public Methods

mrc_dns_proxy_state_inquiry_t
mrc_dns_proxy_state_inquiry_create(void)
{
	return _mrc_dns_proxy_state_inquiry_new();
}

//======================================================================================================================

void
mrc_dns_proxy_state_inquiry_set_queue(const mrc_dns_proxy_state_inquiry_t me, const dispatch_queue_t queue)
{
	require_return(!me->immutable);
	if (queue) {
		dispatch_retain(queue);
	}
	dispatch_forget(&me->queue);
	me->queue = queue;
}

//======================================================================================================================

void
mrc_dns_proxy_state_inquiry_set_handler(const mrc_dns_proxy_state_inquiry_t me,
	const mrc_dns_proxy_state_inquiry_response_handler_t handler)
{
	require_return(!me->immutable);
	const mrc_dns_proxy_state_inquiry_response_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->handler);
	me->handler = new_handler;
}

//======================================================================================================================

void
mrc_dns_proxy_state_inquiry_activate(const mrc_dns_proxy_state_inquiry_t me)
{
	me->immutable = true;
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_dns_proxy_state_inquiry_register(me);
		_mrc_dns_proxy_state_inquiry_send_command(me);
		mrc_release(me);
	});
}

//======================================================================================================================

void
mrc_dns_proxy_state_inquiry_invalidate(const mrc_dns_proxy_state_inquiry_t me)
{
	me->immutable = true;
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_dns_proxy_state_inquiry_terminate_with_state_description(me, NULL);
		mrc_release(me);
	});
}

//======================================================================================================================
// MARK: - DNS Proxy State Inquiry Private Methods

static char *
_mrc_dns_proxy_state_inquiry_copy_description(const mrc_dns_proxy_state_inquiry_t me, __unused const bool debug,
	__unused const bool privacy)
{
	char *description = NULL;
	asprintf(&description, "<%s: %p>: ", me->base.kind->name, (void *)me);
	return description;
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_finalize(const mrc_dns_proxy_state_inquiry_t me)
{
	dispatch_forget(&me->queue);
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_register(const mrc_dns_proxy_state_inquiry_t me)
{
	require_return(me->state == mrc_dns_proxy_state_inquiry_state_nascent);

	me->state = mrc_dns_proxy_state_inquiry_state_registered;
	mrc_dns_proxy_state_inquiry_t *ptr = &g_dns_proxy_state_inquiry_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	*ptr = me;
	mrc_retain(*ptr);
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_deregister(const mrc_dns_proxy_state_inquiry_t me)
{
	mrc_dns_proxy_state_inquiry_t *ptr = &g_dns_proxy_state_inquiry_list;
	while (*ptr && (*ptr != me)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		mrc_release(*ptr);
		*ptr = me->next;
		me->next = NULL;
	}
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_handle_reply(const mrc_dns_proxy_state_inquiry_t me, const uint64_t cmd_id,
	const xpc_object_t reply)
{
	require_return(me->cmd_id == cmd_id);
	require_return(me->state == mrc_dns_proxy_state_inquiry_state_in_progress);

	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		bool valid;
		OSStatus err = mrc_xpc_message_get_error(reply, &valid);
		if (!valid) {
			err = kResponseErr;
		}
		mdns_xpc_string_t state = NULL;
		if (!err) {
			mdns_xpc_dictionary_t result = mrc_xpc_message_get_result(reply);
			if (result) {
				state = mrc_xpc_dns_proxy_state_result_get_description(result);
			}
			if (!state) {
				err = kResponseErr;
			}
		}
		os_log_with_type(_mrc_client_log(), err ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
			"[DP%llu] DNS proxy state reply -- error: %{mdns:err}ld", (unsigned long long)me->cmd_id, (long)err);
		if (err) {
			_mrc_dns_proxy_state_inquiry_terminate_with_error(me, err);
		} else {
			_mrc_dns_proxy_state_inquiry_terminate_with_state_description(me, state);
		}
	} else {
		char *description = xpc_copy_description(reply);
		os_log_error(_mrc_client_log(),
			"[DP%llu] Abnormal DNS proxy state reply: %{public}s", (unsigned long long)me->cmd_id, description);
		ForgetMem(&description);
		if (reply != XPC_ERROR_CONNECTION_INTERRUPTED) {
			const OSStatus err = (reply == XPC_ERROR_CONNECTION_INVALID) ? kConnectionErr : kResponseErr;
			_mrc_dns_proxy_state_inquiry_terminate_with_error(me, err);
		}
	}
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_send_command(const mrc_dns_proxy_state_inquiry_t me)
{
	require_return(
		(me->state == mrc_dns_proxy_state_inquiry_state_registered) ||
		(me->state == mrc_dns_proxy_state_inquiry_state_in_progress)
	);
	me->state = mrc_dns_proxy_state_inquiry_state_in_progress;
	me->cmd_id = _mrc_client_get_new_command_id();
	const uint64_t cmd_id = me->cmd_id;
	xpc_object_t msg = mrc_xpc_create_dns_proxy_get_state_command_message(cmd_id);
	mrc_retain(me);
	xpc_connection_send_message_with_reply(_mrc_client_connection(), msg, _mrc_client_queue(),
	^(const xpc_object_t reply)
	{
		_mrc_dns_proxy_state_inquiry_handle_reply(me, cmd_id, reply);
		mrc_release(me);
	});
	xpc_forget(&msg);
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_terminate_imp(const mrc_dns_proxy_state_inquiry_t me,
	const mdns_xpc_string_t state_description, const OSStatus error)
{
	require_return(me->state != mrc_dns_proxy_state_inquiry_state_done);

	_mrc_dns_proxy_state_inquiry_deregister(me);
	me->state = mrc_dns_proxy_state_inquiry_state_done;
	if (me->queue && me->handler) {
		const mrc_dns_proxy_state_inquiry_response_handler_t handler = me->handler;
		me->handler = NULL;
		if (state_description) {
			mdns_xpc_string_retain(state_description);
		}
		dispatch_async(me->queue,
		^{
			const char * const cstr = state_description ? mdns_xpc_string_get_string_ptr(state_description) : NULL;
			handler(cstr, error);
			mrc_dns_proxy_state_inquiry_response_handler_t tmp_handler = handler;
			BlockForget(&tmp_handler);
			mdns_xpc_string_t tmp = state_description;
			mdns_xpc_string_forget(&tmp);
		});
	}
	BlockForget(&me->handler);
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_terminate_with_error(const mrc_dns_proxy_state_inquiry_t me, const OSStatus error)
{
	_mrc_dns_proxy_state_inquiry_terminate_imp(me, NULL, error);
}

//======================================================================================================================

static void
_mrc_dns_proxy_state_inquiry_terminate_with_state_description(const mrc_dns_proxy_state_inquiry_t me,
	const mdns_xpc_string_t description)
{
	_mrc_dns_proxy_state_inquiry_terminate_imp(me, description, kNoErr);
}

//======================================================================================================================
// MARK: - DNS Service Registration Public Methods

mrc_dns_service_registration_t
mrc_dns_service_registration_create(const mdns_dns_service_definition_t definition)
{
	mrc_dns_service_registration_t registration = NULL;
	mrc_dns_service_registration_t obj = _mrc_dns_service_registration_new();
	mdns_require_quiet(obj, exit);

	obj->definition_dict = mdns_dns_service_definition_create_xpc_dictionary(definition);
	mdns_require_quiet(obj->definition_dict, exit);

	obj->definition_type = mrc_dns_service_definition_type_do53;
	registration = obj;
	obj = NULL;

exit:
	mrc_forget(&obj);
	return registration;
}

//======================================================================================================================

mrc_dns_service_registration_t
mrc_dns_service_registration_create_push(const mdns_dns_push_service_definition_t definition)
{
	mrc_dns_service_registration_t registration = NULL;
	mrc_dns_service_registration_t obj = _mrc_dns_service_registration_new();
	mdns_require_quiet(obj, exit);

	obj->definition_dict = mdns_dns_push_service_definition_create_xpc_dictionary(definition);
	mdns_require_quiet(obj->definition_dict, exit);

	obj->definition_type = mrc_dns_service_definition_type_push;
	registration = obj;
	obj = NULL;

exit:
	mrc_forget(&obj);
	return registration;
}

//======================================================================================================================

void
mrc_dns_service_registration_set_reports_connection_errors(const mrc_dns_service_registration_t me,
	const bool reports_connection_errors)
{
	mdns_require_return(!_mrc_client_is_immutable(me));
	me->reports_connection_errors = reports_connection_errors;
}

//======================================================================================================================

void
mrc_dns_service_registration_set_queue(const mrc_dns_service_registration_t me, const dispatch_queue_t queue)
{
	_mrc_client_set_queue(me, queue);
}

//======================================================================================================================

void
mrc_dns_service_registration_set_event_handler(const mrc_dns_service_registration_t me,
	const mrc_dns_service_registration_event_handler_t handler)
{
	mdns_require_return(!_mrc_client_is_immutable(me));

	const mrc_dns_service_registration_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->event_handler);
	me->event_handler = new_handler;
}

//======================================================================================================================

void
mrc_dns_service_registration_activate(const mrc_dns_service_registration_t me)
{
	_mrc_client_activate_async(me);
}

//======================================================================================================================

void
mrc_dns_service_registration_invalidate(const mrc_dns_service_registration_t me)
{
	_mrc_client_invalidate_async(me, kNoErr);
}

//======================================================================================================================
// MARK: - DNS Service Registration Private Methods

static char *
_mrc_dns_service_registration_copy_description(const mrc_dns_service_registration_t me, const bool debug,
	__unused const bool privacy)
{
	char *description = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_dns_service_registration_finalize(const mrc_dns_service_registration_t me)
{
	xpc_forget(&me->definition_dict);
}

//======================================================================================================================

static xpc_object_t
_mrc_dns_service_registration_create_start_message(const mrc_dns_service_registration_t me, const uint64_t cmd_id)
{
	xpc_object_t params = xpc_dictionary_create_empty();
	mrc_xpc_dns_service_registration_params_set_defintion_dictionary(params, me->definition_dict);
	mrc_xpc_dns_service_registration_params_set_definition_type(params, me->definition_type);
	mrc_xpc_dns_service_registration_params_set_reports_connection_errors(params,
		me->reports_connection_errors);
	const xpc_object_t msg = mrc_xpc_create_dns_service_registration_start_command_message(cmd_id, params);
	xpc_forget(&params);
	return msg;
}

//======================================================================================================================

static xpc_object_t
_mrc_dns_service_registration_create_stop_message(__unused const mrc_dns_service_registration_t me,
	const uint64_t cmd_id)
{
	return mrc_xpc_create_dns_service_registration_stop_command_message(cmd_id);
}

//======================================================================================================================

static void
_mrc_dns_service_registration_generate_event_with_error(const mrc_dns_service_registration_t me,
	const mrc_dns_service_registration_event_t event, const OSStatus error)
{
	const dispatch_queue_t user_queue = _mrc_client_get_user_queue(me);
	const mrc_dns_service_registration_event_handler_t event_handler = me->event_handler;
	mdns_require_quiet(user_queue && event_handler, exit);

	dispatch_async(user_queue,
	^{
		event_handler(event, error);
	});

exit:
	if (event == mrc_dns_service_registration_event_invalidation) {
		BlockForget(&me->event_handler);
	}
}

//======================================================================================================================

static void
_mrc_dns_service_registration_generate_event(const mrc_dns_service_registration_t me,
	const mrc_dns_service_registration_event_t event)
{
	_mrc_dns_service_registration_generate_event_with_error(me, event, kNoErr);
}

//======================================================================================================================

static void
_mrc_dns_service_registration_handle_start(const mrc_dns_service_registration_t me, __unused const xpc_object_t result)
{
	_mrc_dns_service_registration_generate_event(me, mrc_dns_service_registration_event_started);
}

//======================================================================================================================

static void
_mrc_dns_service_registration_handle_notification(const mrc_dns_service_registration_t me,
	const xpc_object_t notification)
{
	if (!me->reports_connection_errors) {
		char *description = xpc_copy_description(notification);
		os_log_fault(_mrc_client_log(),
			"Current DNS service registration didn't require error reporting, ignoring -- "
			"registration: %@, notification: %{private}s",	me, description);
		ForgetMem(&description);
		return;
	}

	bool valid;
	const OSStatus connection_error = mrc_xpc_dns_service_registration_notification_get_connection_error(notification,
		&valid);
	mdns_require_return(valid);

	_mrc_dns_service_registration_generate_event_with_error(me, mrc_dns_service_registration_event_connection_error,
		connection_error);
}

//======================================================================================================================

static void
_mrc_dns_service_registration_handle_interruption(const mrc_dns_service_registration_t me)
{
	_mrc_dns_service_registration_generate_event(me, mrc_dns_service_registration_event_interruption);
}

//======================================================================================================================

static void
_mrc_dns_service_registration_handle_invalidation(const mrc_dns_service_registration_t me, const OSStatus error)
{
	_mrc_dns_service_registration_generate_event_with_error(me, mrc_dns_service_registration_event_invalidation, error);
}

//======================================================================================================================
// MARK: - Discovery Proxy Public Methods

mrc_discovery_proxy_t
mrc_discovery_proxy_create(const mrc_discovery_proxy_parameters_t params)
{
	mrc_discovery_proxy_t proxy = NULL;
	mrc_discovery_proxy_t obj = _mrc_discovery_proxy_new();
	mdns_require_quiet(obj, exit);

	obj->params = _mrc_discovery_proxy_parameters_create_or_copy(params);
	mdns_require_quiet(obj->params, exit);

	proxy = obj;
	obj = NULL;

exit:
	mrc_forget(&obj);
	return proxy;
}

//======================================================================================================================

void
mrc_discovery_proxy_set_queue(const mrc_discovery_proxy_t me, const dispatch_queue_t queue)
{
	_mrc_client_set_queue(me, queue);
}

//======================================================================================================================

void
mrc_discovery_proxy_set_event_handler(const mrc_discovery_proxy_t me, const mrc_discovery_proxy_event_handler_t handler)
{
	mdns_require_return(!_mrc_client_is_immutable(me));

	const mrc_discovery_proxy_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->event_handler);
	me->event_handler = new_handler;
}

//======================================================================================================================

void
mrc_discovery_proxy_activate(const mrc_discovery_proxy_t me)
{
	_mrc_client_activate_async(me);
}

//======================================================================================================================

void
mrc_discovery_proxy_invalidate(const mrc_discovery_proxy_t me)
{
	_mrc_client_invalidate_async(me, kNoErr);
}

//======================================================================================================================
// MARK: - Discovery Proxy Private Methods

static char *
_mrc_discovery_proxy_copy_description(const mrc_discovery_proxy_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	char *params_desc = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	params_desc = _mrc_discovery_proxy_parameters_copy_description(me->params, false, privacy);
	mdns_require_quiet(params_desc, exit);

	err = mdns_string_builder_append_formatted(sb, "%s", params_desc);
	mdns_require_noerr_quiet(err, exit);

	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	ForgetMem(&params_desc);
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_discovery_proxy_finalize(const mrc_discovery_proxy_t me)
{
	mrc_forget(&me->params);
}

//======================================================================================================================

static xpc_object_t
_mrc_discovery_proxy_create_start_message(const mrc_discovery_proxy_t me, const uint64_t cmd_id)
{
	xpc_object_t start_msg = NULL;
	xpc_object_t params_dict = _mrc_discovery_proxy_parameters_create_xpc_dictionary(me->params);
	if (params_dict) {
		start_msg = mrc_xpc_create_discovery_proxy_start_command_message(cmd_id, params_dict);
		xpc_forget(&params_dict);
	}
	return start_msg;
}

//======================================================================================================================

static xpc_object_t
_mrc_discovery_proxy_create_stop_message(__unused const mrc_discovery_proxy_t me, const uint64_t cmd_id)
{
	return mrc_xpc_create_discovery_proxy_stop_command_message(cmd_id);
}

//======================================================================================================================

static void
_mrc_discovery_proxy_generate_event_with_error(const mrc_discovery_proxy_t me, const mrc_discovery_proxy_event_t event,
	const OSStatus error)
{
	const dispatch_queue_t user_queue = _mrc_client_get_user_queue(me);
	const mrc_discovery_proxy_event_handler_t event_handler = me->event_handler;
	mdns_require_quiet(user_queue && event_handler, exit);

	dispatch_async(user_queue,
	^{
		event_handler(event, error);
	});

exit:
	if (event == mrc_discovery_proxy_event_invalidation) {
		BlockForget(&me->event_handler);
	}
}

//======================================================================================================================

static void
_mrc_discovery_proxy_generate_event(const mrc_discovery_proxy_t me, const mrc_discovery_proxy_event_t event)
{
	_mrc_discovery_proxy_generate_event_with_error(me, event, kNoErr);
}

//======================================================================================================================

static void
_mrc_discovery_proxy_handle_start(const mrc_discovery_proxy_t me, __unused const xpc_object_t result)
{
	_mrc_discovery_proxy_generate_event(me, mrc_discovery_proxy_event_started);
}

//======================================================================================================================

static void
_mrc_discovery_proxy_handle_interruption(const mrc_discovery_proxy_t me)
{
	_mrc_discovery_proxy_generate_event(me, mrc_discovery_proxy_event_interruption);
}

//======================================================================================================================

static void
_mrc_discovery_proxy_handle_invalidation(const mrc_discovery_proxy_t me, const OSStatus error)
{
	_mrc_discovery_proxy_generate_event_with_error(me, mrc_discovery_proxy_event_invalidation, error);
}

//======================================================================================================================
// MARK: - Discovery Proxy Parameters Public Methods

mrc_discovery_proxy_parameters_t
mrc_discovery_proxy_parameters_create(void)
{
	return _mrc_discovery_proxy_parameters_create_or_copy(NULL);
}

//======================================================================================================================

void
mrc_discovery_proxy_parameters_set_interface(const mrc_discovery_proxy_parameters_t me, const uint32_t ifindex)
{
	me->ifindex = ifindex;
}

//======================================================================================================================

OSStatus
mrc_discovery_proxy_parameters_add_server_ipv4_address(const mrc_discovery_proxy_parameters_t me,
	const uint32_t ipv4_address, const uint16_t port)
{
	OSStatus err;
	mdns_address_t address = mdns_address_create_ipv4(ipv4_address, port);
	mdns_require_action_quiet(address, exit, err = kNoResourcesErr);

	CFArrayAppendValue(me->server_addresses, address);
	err = kNoErr;

exit:
	mdns_forget(&address);
	return err;
}

//======================================================================================================================

OSStatus
mrc_discovery_proxy_parameters_add_server_ipv6_address(const mrc_discovery_proxy_parameters_t me,
	const uint8_t ipv6_address[static 16], const uint16_t port, const uint32_t scope_id)
{
	OSStatus err;
	mdns_address_t address = mdns_address_create_ipv6(ipv6_address, port, scope_id);
	mdns_require_action_quiet(address, exit, err = kNoResourcesErr);

	CFArrayAppendValue(me->server_addresses, address);
	err = kNoErr;

exit:
	mdns_forget(&address);
	return err;
}

//======================================================================================================================

OSStatus
mrc_discovery_proxy_parameters_add_match_domain(const mrc_discovery_proxy_parameters_t me,
	const char * const domain_str)
{
	OSStatus err;
	mdns_domain_name_t domain = mdns_domain_name_create(domain_str, mdns_domain_name_create_opts_none, &err);
	mdns_require_noerr_quiet(err, exit);

	CFSetAddValue(me->domains, domain);

exit:
	mdns_forget(&domain);
	return err;
}

//======================================================================================================================

void
mrc_discovery_proxy_parameters_add_server_certificate(const mrc_discovery_proxy_parameters_t me,
	const uint8_t * const cert_data, const size_t cert_len)
{
	mdns_xpc_array_append_data(me->certs, cert_data, cert_len);
}

//======================================================================================================================
// MARK: - Discovery Proxy Parameters Private Methods

static mrc_discovery_proxy_parameters_t
_mrc_discovery_proxy_parameters_create_or_copy(const mrc_discovery_proxy_parameters_t original)
{
	mrc_discovery_proxy_parameters_t params = NULL;
	mrc_discovery_proxy_parameters_t obj = _mrc_discovery_proxy_parameters_new();
	mdns_require_quiet(obj, exit);

	if (original) {
		obj->ifindex = original->ifindex;
		obj->server_addresses = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, original->server_addresses);
		mdns_require_quiet(obj->server_addresses, exit);

		obj->domains = CFSetCreateMutableCopy(kCFAllocatorDefault, 0, original->domains);
		mdns_require_quiet(obj->domains, exit);

		obj->certs = xpc_copy(original->certs);
		mdns_require_quiet(obj->certs, exit);
	} else {
		obj->server_addresses = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
		mdns_require_quiet(obj->server_addresses, exit);

		obj->domains = CFSetCreateMutable(kCFAllocatorDefault, 0, &mdns_domain_name_cf_set_callbacks);
		mdns_require_quiet(obj->domains, exit);

		obj->certs = xpc_array_create_empty();
		mdns_require_quiet(obj->certs, exit);
	}
	params = obj;
	obj = NULL;

exit:
	mrc_forget(&obj);
	return params;
}

//======================================================================================================================

static char *
_mrc_discovery_proxy_parameters_copy_description(const mrc_discovery_proxy_parameters_t me, const bool debug,
	const bool privacy)
{
	char *description = NULL;
	__block OSStatus err;
	__block const char *prefix;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	// Print interface index.
	err = mdns_string_builder_append_formatted(sb, "interface index: %u, ", me->ifindex);
	mdns_require_noerr_quiet(err, exit);

	// Print server addresses.
	err = mdns_string_builder_append_formatted(sb, "server addresses: {");
	mdns_require_noerr_quiet(err, exit);

	prefix = NULL;
	const mdns_description_options_t desc_opts = privacy ? mdns_description_opt_privacy : mdns_description_opt_none;
	mdns_cfarray_enumerate(me->server_addresses,
	^ bool (const mdns_address_t address)
	{
		err = mdns_string_builder_append_description_with_prefix(sb, prefix, address, desc_opts);
		prefix = ", ";
		const bool proceed = !err;
		return proceed;
	});
	mdns_require_noerr_quiet(err, exit);

	err = mdns_string_builder_append_formatted(sb, "}");
	mdns_require_noerr_quiet(err, exit);

	// Print domains.
	err = mdns_string_builder_append_formatted(sb, ", domains: {");
	mdns_require_noerr_quiet(err, exit);

	prefix = NULL;
	mdns_cfset_enumerate(me->domains,
	^ bool (const mdns_domain_name_t domain)
	{
		err = mdns_string_builder_append_description_with_prefix(sb, prefix, domain, desc_opts);
		prefix = ", ";
		const bool proceed = !err;
		return proceed;
	});
	mdns_require_noerr_quiet(err, exit);

	err = mdns_string_builder_append_formatted(sb, "}");
	mdns_require_noerr_quiet(err, exit);

	// Print certificate summary.
	err = mdns_string_builder_append_formatted(sb, ", certificate count: %zu", xpc_array_get_count(me->certs));
	mdns_require_noerr_quiet(err, exit);

	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_discovery_proxy_parameters_finalize(const mrc_discovery_proxy_parameters_t me)
{
	CFForget(&me->server_addresses);
	CFForget(&me->domains);
	xpc_forget(&me->certs);
}

//======================================================================================================================

static xpc_object_t
_mrc_discovery_proxy_parameters_create_xpc_dictionary(const mrc_discovery_proxy_parameters_t me)
{
	xpc_object_t result = NULL;
	xpc_object_t dict = xpc_dictionary_create_empty();
	mdns_require_quiet(dict, exit);

	// Set interface index.
	mrc_xpc_discovery_proxy_params_set_interface(dict, me->ifindex);

	// Add server addresses.
	bool completed = mdns_cfarray_enumerate(me->server_addresses,
	^ bool (const mdns_address_t address)
	{
		bool proceed = false;
		char *address_str = mdns_copy_description(address);
		if (address_str) {
			mrc_xpc_discovery_proxy_params_add_server_address(dict, address_str);
			ForgetMem(&address_str);
			proceed = true;
		}
		return proceed;
	});
	mdns_require_quiet(completed, exit);

	// Add match domains.
	mdns_cfset_enumerate(me->domains,
	^ bool (const mdns_domain_name_t domain)
	{
		const char *domain_str = mdns_domain_name_get_presentation(domain);
		mrc_xpc_discovery_proxy_params_add_match_domain(dict, domain_str);
		return true;
	});

	// Add server certificates.
	const size_t cert_count = xpc_array_get_count(me->certs);
	for (size_t i = 0; i < cert_count; ++i) {
		size_t cert_len = 0;
		const uint8_t * const cert_data = xpc_array_get_data(me->certs, i, &cert_len);
		if (cert_data && (cert_len > 0)) {
			mrc_xpc_discovery_proxy_params_add_server_certificate(dict, cert_data, cert_len);
		}
	}
	result = dict;
	dict = NULL;

exit:
	xpc_forget(&dict);
	return result;
}

//======================================================================================================================
// MARK: - Cached Local Records Inquiry Public Methods

mrc_cached_local_records_inquiry_t
mrc_cached_local_records_inquiry_create(void)
{
	return _mrc_cached_local_records_inquiry_new();
}

//======================================================================================================================

void
mrc_cached_local_records_inquiry_set_queue(const mrc_cached_local_records_inquiry_t me, const dispatch_queue_t queue)
{
	_mrc_client_set_queue(me, queue);
}

//======================================================================================================================

void
mrc_cached_local_records_inquiry_set_result_handler(const mrc_cached_local_records_inquiry_t me,
	const mrc_cached_local_records_inquiry_result_handler_t handler)
{
	mdns_require_return(!_mrc_client_is_immutable(me));
	const mrc_cached_local_records_inquiry_result_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->handler);
	me->handler = new_handler;
}

//======================================================================================================================

void
mrc_cached_local_records_inquiry_activate(const mrc_cached_local_records_inquiry_t me)
{
	_mrc_client_activate_async(me);
}

//======================================================================================================================

void
mrc_cached_local_records_inquiry_invalidate(const mrc_cached_local_records_inquiry_t me)
{
	_mrc_client_invalidate_async(me, kNoErr);
}

//======================================================================================================================
// MARK: - Cached Local Records Inquiry Private Methods

static char *
_mrc_cached_local_records_inquiry_copy_description(const mrc_cached_local_records_inquiry_t me, const bool debug,
	__unused const bool privacy)
{
	char *description = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_finalize(__unused const mrc_cached_local_records_inquiry_t me)
{
	// Nothing to do for now.
}

//======================================================================================================================

static xpc_object_t
_mrc_cached_local_records_inquiry_create_start_message(__unused const mrc_cached_local_records_inquiry_t me,
	const uint64_t cmd_id)
{
	return mrc_xpc_create_cached_local_record_inquiry_command_message(cmd_id);
}

//======================================================================================================================

static char *
_mrc_cached_local_records_inquiry_create_cleansed_string(const uint8_t * const string, const size_t string_len,
	OSStatus * const out_error)
{
	OSStatus err;
	char *result = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_action_quiet(sb, exit, err = kNoResourcesErr);

	const uint8_t * ptr = string;
	const uint8_t * const end = &string[string_len];
	while (ptr < end) {
		const uint8_t c = *ptr;
		size_t processed_byte_count = 0;
		const size_t remaining_len = (size_t)(end - ptr);
		if (mdns_us_ascii(c)) {
			if (mdns_us_ascii_isprint(c)) {
				// Put printable ASCII characters in the destination string. But in the case of the backslash
				// character, which is used as an escape character, escape it with a backslash.
				if (c == '\\') {
					err = mdns_string_builder_append_formatted(sb, "\\");
					mdns_require_noerr_quiet(err, exit);
				}
				err = mdns_string_builder_append_formatted(sb, "%c", c);
				mdns_require_noerr_quiet(err, exit);

				processed_byte_count = 1;
			}
		} else {
			// If this non-ASCII character is the start of a valid UTF-8 sequence, then simply put it in the
			// destination string.
			const size_t utf8_char_len = mdns_utf8_length_of_first_character(ptr, remaining_len);
			if (utf8_char_len > 0) {
				err = mdns_string_builder_append_formatted(sb, "%.*s", (int)utf8_char_len, ptr);
				mdns_require_noerr_quiet(err, exit);

				processed_byte_count = utf8_char_len;
			}
		}
		// All other bytes, i.e., non-printable ASCII characters and those that aren't part of a valid UTF-8 byte
		// sequence, are written as the \xHH escape sequence, where HH is the hex value of the byte encoded as a
		// pair of ASCII hex digits.
		if (processed_byte_count == 0) {
			err = mdns_string_builder_append_formatted(sb, "\\x%02X", c);
			mdns_require_noerr_quiet(err, exit);

			processed_byte_count = 1;
		}
		ptr += Min(processed_byte_count, remaining_len);
	}
	result = mdns_string_builder_copy_string(sb);
	mdns_require_action_quiet(result, exit, err = kNoMemoryErr);

	err = kNoErr;

exit:
	mdns_assign(out_error, err);
	mdns_forget(&sb);
	return result;
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_enhance_record_info_dictionary(const xpc_object_t dict)
{
	char *first_label_str = NULL;
	const char * const name_str = xpc_dictionary_get_string(dict, mrc_cached_local_record_key_name);
	mdns_require_quiet(name_str, exit);

	uint8_t name[kDomainNameLengthMax];
	OSStatus err = DomainNameFromString(name, name_str, NULL);
	mdns_require_noerr_quiet(err, exit);

	const size_t first_label_len = name[0];
	mdns_require_quiet(first_label_len > 0, exit);

	const uint8_t * const first_label_data = &name[1];
	first_label_str = _mrc_cached_local_records_inquiry_create_cleansed_string(first_label_data, first_label_len, &err);
	mdns_require_action_quiet(first_label_str, exit, os_log_fault(_mrc_client_log(),
		"Failed to convert first label to UTF-8 string: %{mdns:err}ld", (long)err));

	xpc_dictionary_set_string(dict, mrc_cached_local_record_key_first_label, first_label_str);

exit:
	ForgetMem(&first_label_str);
}

//======================================================================================================================

static xpc_object_t
_mrc_cached_local_records_inquiry_process_create_enhanced_record_info_copy(const xpc_object_t record_info)
{
	xpc_object_t enhanced_record_info = xpc_copy(record_info);
	mdns_require_quiet(enhanced_record_info, exit);

	xpc_array_apply(enhanced_record_info,
	^ bool (__unused const size_t index, const xpc_object_t dict)
	{
		if (xpc_get_type(dict) == XPC_TYPE_DICTIONARY) {
			_mrc_cached_local_records_inquiry_enhance_record_info_dictionary(dict);
		}
		return true;
	});

exit:
	return enhanced_record_info;
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_invoke_user_handler(const mrc_cached_local_records_inquiry_t me,
	const xpc_object_t record_info, const OSStatus error)
{
	const dispatch_queue_t user_queue = _mrc_client_get_user_queue(me);
	if (user_queue && me->handler) {
		xpc_object_t record_info_copy = NULL;
		if (record_info) {
			record_info_copy = _mrc_cached_local_records_inquiry_process_create_enhanced_record_info_copy(record_info);
			if (!record_info_copy) {
				record_info_copy = record_info;
				xpc_retain(record_info_copy);
			}
		}
		const mrc_cached_local_records_inquiry_result_handler_t handler = me->handler;
		dispatch_async(user_queue,
		^{
			handler(record_info_copy, error);
			xpc_object_t tmp = record_info_copy;
			xpc_forget(&tmp);
		});
	}
	BlockForget(&me->handler);
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_invoke_user_handler_with_record_info(const mrc_cached_local_records_inquiry_t me,
	const xpc_object_t record_info)
{
	_mrc_cached_local_records_inquiry_invoke_user_handler(me, record_info, kNoErr);
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_invoke_user_handler_with_error(const mrc_cached_local_records_inquiry_t me,
	const OSStatus error)
{
	_mrc_cached_local_records_inquiry_invoke_user_handler(me, NULL, error);
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_handle_start(const mrc_cached_local_records_inquiry_t me, const xpc_object_t result)
{
	bool valid_result = false;
	xpc_object_t record_info = NULL;
	if (result) {
		record_info = mrc_xpc_cached_local_record_inquiry_result_get_record_info(result, &valid_result);
	}
	if (valid_result) {
		_mrc_cached_local_records_inquiry_invoke_user_handler_with_record_info(me, record_info);
	} else {
		_mrc_cached_local_records_inquiry_invoke_user_handler_with_error(me, kResponseErr);
	}
}

//======================================================================================================================

static void
_mrc_cached_local_records_inquiry_handle_invalidation(const mrc_cached_local_records_inquiry_t me, const OSStatus error)
{
	_mrc_cached_local_records_inquiry_invoke_user_handler_with_error(me, error);
}

//======================================================================================================================
// MARK: - Record Cache Flush Public Methods

mrc_record_cache_flush_t
mrc_record_cache_flush_create(void)
{
	return _mrc_record_cache_flush_new();
}

//======================================================================================================================

void
mrc_record_cache_flush_set_queue(const mrc_record_cache_flush_t me, const dispatch_queue_t queue)
{
	_mrc_client_set_queue(me, queue);
}

//======================================================================================================================

void
mrc_record_cache_flush_set_record_name(const mrc_record_cache_flush_t me, const mdns_domain_name_t record_name)
{
	mdns_require_return(!_mrc_client_is_immutable(me));
	mdns_replace(&me->record_name, record_name);
}

//======================================================================================================================

void
mrc_record_cache_flush_set_key_tag(const mrc_record_cache_flush_t me, const uint16_t key_tag)
{
	mdns_require_return(!_mrc_client_is_immutable(me));
	me->key_tag = key_tag;
	me->have_key_tag = true;
}

//======================================================================================================================

void
mrc_record_cache_flush_set_result_handler(const mrc_record_cache_flush_t me,
	const mrc_record_cache_flush_result_handler_t handler)
{
	mdns_require_return(!_mrc_client_is_immutable(me));
	const mrc_record_cache_flush_result_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->handler);
	me->handler = new_handler;
}

//======================================================================================================================

void
mrc_record_cache_flush_activate(const mrc_record_cache_flush_t me)
{
	_mrc_client_activate_async(me);
}

//======================================================================================================================

void
mrc_record_cache_flush_invalidate(const mrc_record_cache_flush_t me)
{
	_mrc_client_invalidate_async(me, kNoErr);
}

//======================================================================================================================
// MARK: - Record Cache Flush Private Methods

static char *
_mrc_record_cache_flush_copy_description(const mrc_record_cache_flush_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	mdns_string_builder_t sb = mdns_string_builder_create(0, NULL);
	mdns_require_quiet(sb, exit);

	OSStatus err;
	if (debug) {
		const mdns_kind_t kind = mrc_get_kind(me);
		err = mdns_string_builder_append_formatted(sb, "<%s: %p>: ", kind->name, (void *)me);
		mdns_require_noerr_quiet(err, exit);
	}
	err = mdns_string_builder_append_formatted(sb, "record name: ");
	mdns_require_noerr_quiet(err, exit);

	if (me->record_name) {
		const mdns_description_options_t desc_opts = privacy ? mdns_description_opt_privacy : mdns_description_opt_none;
		err = mdns_string_builder_append_description(sb, me->record_name, desc_opts);
		mdns_require_noerr_quiet(err, exit);
	} else {
		err = mdns_string_builder_append_formatted(sb, "«NO NAME»");
		mdns_require_noerr_quiet(err, exit);
	}
	if (me->have_key_tag) {
		err = mdns_string_builder_append_formatted(sb, ", key tag: %u", me->key_tag);
		mdns_require_noerr_quiet(err, exit);
	}
	description = mdns_string_builder_copy_string(sb);
	mdns_require_quiet(description, exit);

exit:
	mdns_forget(&sb);
	return description;
}

//======================================================================================================================

static void
_mrc_record_cache_flush_finalize(const mrc_record_cache_flush_t me)
{
	mdns_forget(&me->record_name);
}

//======================================================================================================================

static xpc_object_t
_mrc_record_cache_flush_create_start_message(const mrc_record_cache_flush_t me, const uint64_t cmd_id)
{
	xpc_object_t params = xpc_dictionary_create_empty();
	if (me->record_name) {
		mrc_xpc_record_cache_flush_params_set_record_name(params, mdns_domain_name_get_presentation(me->record_name));
	}
	if (me->have_key_tag) {
		mrc_xpc_record_cache_flush_params_set_key_tag(params, me->key_tag);
	}
	const xpc_object_t msg = mrc_xpc_create_record_cache_flush_command_message(cmd_id, params);
	xpc_forget(&params);
	return msg;
}

//======================================================================================================================

static void
_mrc_record_cache_flush_invoke_user_handler(const mrc_record_cache_flush_t me,
	const mrc_record_cache_flush_result_t result, const OSStatus error)
{
	const dispatch_queue_t user_queue = _mrc_client_get_user_queue(me);
	if (user_queue && me->handler) {
		const mrc_record_cache_flush_result_handler_t handler = me->handler;
		dispatch_async(user_queue,
		^{
			handler(result, error);
		});
	}
	BlockForget(&me->handler);
}

//======================================================================================================================

static void
_mrc_record_cache_flush_handle_start(const mrc_record_cache_flush_t me, __unused const xpc_object_t result)
{
	_mrc_record_cache_flush_invoke_user_handler(me, mrc_record_cache_flush_result_complete, kNoErr);
}

//======================================================================================================================

static void
_mrc_record_cache_flush_handle_invalidation(const mrc_record_cache_flush_t me, const OSStatus error)
{
	_mrc_record_cache_flush_invoke_user_handler(me, mrc_record_cache_flush_result_incomplete, error);
}

//======================================================================================================================
// MARK: - Internal Functions

static uint64_t
_mrc_client_get_new_command_id(void)
{
	static uint64_t last_command_id = 0;
	return ++last_command_id;
}

//======================================================================================================================

static os_log_t
_mrc_client_log(void)
{
	static dispatch_once_t s_once = 0;
	static os_log_t s_log = NULL;
	dispatch_once(&s_once,
	^{
		s_log = os_log_create("com.apple.mdns", "mrc");
	});
	return s_log;
}

//======================================================================================================================

static dispatch_queue_t
_mrc_client_queue(void)
{
	static dispatch_once_t s_once = 0;
	static dispatch_queue_t s_queue = NULL;
	dispatch_once(&s_once,
	^{
		s_queue = dispatch_queue_create("com.apple.mdns.mrc", DISPATCH_QUEUE_SERIAL);
	});
	return s_queue;	
}

//======================================================================================================================

static void
_mrc_client_handle_connection_interruption(void)
{
	for (mrc_session_t session = g_session_list; session; session = session->next) {
		_mrc_session_handle_connection_interruption(session);
	}
	for (mrc_dns_proxy_state_inquiry_t inquiry = g_dns_proxy_state_inquiry_list; inquiry; inquiry = inquiry->next) {
		switch (inquiry->state) {
			case mrc_dns_proxy_state_inquiry_state_in_progress:
				_mrc_dns_proxy_state_inquiry_send_command(inquiry);
				break;

			case mrc_dns_proxy_state_inquiry_state_nascent:
			case mrc_dns_proxy_state_inquiry_state_registered:
			case mrc_dns_proxy_state_inquiry_state_done:
			MDNS_COVERED_SWITCH_DEFAULT:
				break;
		}
	}
}

//======================================================================================================================

static void
_mrc_client_connection_handle_notification(const xpc_object_t notification)
{
	const uint64_t cmd_id = mrc_xpc_notification_get_id(notification);
	mrc_session_t session;
	for (session = g_session_list; session; session = session->next) {
		if (session->cmd_id == cmd_id) {
			break;
		}
	}
	if (!session) {
		os_log_fault(_mrc_client_log(), "Unrecognized notification ID: %" PRIu64, cmd_id);
		goto exit;
	}
	_mrc_session_handle_notification(session, notification);

exit:
	return;
}

//======================================================================================================================

static xpc_connection_t
_mrc_client_connection(void)
{
	static xpc_connection_t s_connection = NULL;
	require_quiet(!s_connection, exit);

	const uint64_t flags = XPC_CONNECTION_MACH_SERVICE_PRIVILEGED;
	s_connection = xpc_connection_create_mach_service(g_mrc_mach_service_name, _mrc_client_queue(), flags);
	xpc_connection_set_event_handler(s_connection,
	^(const xpc_object_t event)
	{
		const xpc_type_t type = xpc_get_type(event);
		if (type == XPC_TYPE_DICTIONARY) {
			_mrc_client_connection_handle_notification(event);
		} else if (type == XPC_TYPE_ERROR) {
			os_log_error(_mrc_client_log(),
				"Connection error: %{public}s", xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
		} else {
			char *description = xpc_copy_description(event);
			os_log(_mrc_client_log(),
				"Unexpected connection event: %s", description);
			ForgetMem(&description);
		}
		if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
			_mrc_client_handle_connection_interruption();
		}
	});
	xpc_connection_activate(s_connection);

exit:
	return s_connection;
}

//======================================================================================================================

static OSStatus
_mrc_xpc_dns_proxy_params_print_description(const xpc_object_t params, __unused const bool debug,
	__unused const bool privacy, char * const buf, const size_t buf_len, size_t * const out_len,
	size_t * const out_full_len)
{
	OSStatus err;
	char *dst = buf;
	const char * const lim = &buf[buf_len];
	size_t full_len = 0;

#define _do_appendf(...)											\
	do {															\
		const int _n = mdns_snprintf_add(&dst, lim, __VA_ARGS__);	\
		require_action_quiet(_n >= 0, exit, err = kUnknownErr);		\
		full_len += (size_t)_n;										\
	} while(0)
	_do_appendf("input interface indexes: {");
	const xpc_object_t input_interfaces = mrc_xpc_dns_proxy_params_get_input_interfaces(params);
	const size_t n = input_interfaces ? xpc_array_get_count(input_interfaces) : 0;
	for (size_t i = 0; i < n; ++i) {
		_do_appendf("%s%u", (i == 0) ? "" : ", ", mdns_xpc_array_get_uint32(input_interfaces, i, NULL));
	}
	_do_appendf("}, output interface index: %u", mrc_xpc_dns_proxy_params_get_output_interface(params, NULL));
	size_t bitlen;
	const uint8_t * const prefix = mrc_xpc_dns_proxy_params_get_nat64_prefix(params, &bitlen);
	if (prefix) {
		uint8_t ipv6_addr[16] = {0};
		mdns_memcpy_bits(ipv6_addr, prefix, Min(bitlen, sizeof(ipv6_addr) * 8));

		char addr_buf[INET6_ADDRSTRLEN];
		const char * const addr_str = inet_ntop(AF_INET6, ipv6_addr, addr_buf, (socklen_t)sizeof(addr_buf));
		err = map_global_value_errno(addr_str, addr_str);
		require_noerr_quiet(err, exit);

		_do_appendf(", nat64 prefix: %s/%zu", addr_str, bitlen);
	}
	const bool force_aaaa_synthesis = mrc_xpc_dns_proxy_params_get_force_aaaa_synthesis(params, NULL);
	_do_appendf(", forces AAAA synthesis: %s", YesNoStr(force_aaaa_synthesis));
#undef _do_appendf
	if (out_len) {
		*out_len = (size_t)(dst - buf);
	}
	if (out_full_len) {
		*out_full_len = full_len;
	}
	err = kNoErr;

exit:
	return err;
}
