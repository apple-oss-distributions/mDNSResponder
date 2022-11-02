/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#include <mrc/dns_proxy.h>

#include "helpers.h"
#include "mdns_memcpy_bits.h"
#include "mrc_objects.h"
#include "mrc_xpc.h"

#include <arpa/inet.h>
#include <CoreUtils/CoreUtils.h>
#include <mdns/xpc.h>
#include <os/log.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Proxy Kind Definition

OS_CLOSED_ENUM(mrc_dns_proxy_state, int8_t,
	mrc_dns_proxy_state_failed		= -2,
	mrc_dns_proxy_state_invalidated	= -1,
	mrc_dns_proxy_state_nascent		=  0,
	mrc_dns_proxy_state_starting	=  1,
	mrc_dns_proxy_state_started		=  2
);

struct mrc_dns_proxy_s {
	struct mdns_obj_s				base;			// Object base.
	mrc_dns_proxy_t					next;			// Next DNS proxy object in list.
	dispatch_queue_t				queue;			// User's dispatch queue.
	xpc_object_t					params;			// DNS proxy parameters.
	mrc_dns_proxy_event_handler_t	event_handler;	// Event handler.
	uint64_t						cmd_id;			// Command ID.
	mrc_dns_proxy_state_t			state;			// Current state.
	bool							immutable;		// True if the DNS proxy is no longer externally mutable.
};

MRC_OBJECT_SUBKIND_DEFINE(dns_proxy);

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
// MARK: - Local Prototypes

static void
_mrc_dns_proxy_activate(mrc_dns_proxy_t proxy);

static void
_mrc_dns_proxy_terminate_async(mrc_dns_proxy_t proxy, OSStatus error);

static void
_mrc_dns_proxy_register(mrc_dns_proxy_t proxy);

static void
_mrc_dns_proxy_deregister(mrc_dns_proxy_t proxy);

static void
_mrc_dns_proxy_start(mrc_dns_proxy_t proxy);

static void
_mrc_dns_proxy_stop(mrc_dns_proxy_t proxy);

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

static mrc_dns_proxy_t g_dns_proxy_list = NULL;
static mrc_dns_proxy_state_inquiry_t g_dns_proxy_state_inquiry_list = NULL;

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
	require_return(!me->immutable);
	if (queue) {
		dispatch_retain(queue);
	}
	dispatch_forget(&me->queue);
	me->queue = queue;
}

//======================================================================================================================

void
mrc_dns_proxy_set_event_handler(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_handler_t handler)
{
	require_return(!me->immutable);
	const mrc_dns_proxy_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
	BlockForget(&me->event_handler);
	me->event_handler = new_handler;
}

//======================================================================================================================

void
mrc_dns_proxy_activate(const mrc_dns_proxy_t me)
{
	me->immutable = true;
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_dns_proxy_activate(me);
		mrc_release(me);
	});
}

//======================================================================================================================

void
mrc_dns_proxy_invalidate(const mrc_dns_proxy_t me)
{
	me->immutable = true;
	_mrc_dns_proxy_terminate_async(me, kNoErr);
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
		_do_appendf("<%s: %p>: ", me->base.kind->name, me);
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
	dispatch_forget(&me->queue);
	xpc_forget(&me->params);
}

//======================================================================================================================

static void
_mrc_dns_proxy_activate(const mrc_dns_proxy_t me)
{
	require_return(me->state == mrc_dns_proxy_state_nascent);

	_mrc_dns_proxy_register(me);
	_mrc_dns_proxy_start(me);
}

//======================================================================================================================

static void
_mrc_dns_proxy_generate_event_with_error(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_t event,
	const OSStatus error)
{
	require_return(me->queue && me->event_handler);

	const mrc_dns_proxy_event_handler_t event_handler = Block_copy(me->event_handler);
	dispatch_async(me->queue,
	^{
		event_handler(event, error);
		mrc_dns_proxy_event_handler_t tmp = event_handler;
		BlockForget(&tmp);
	});
}

//======================================================================================================================

static void
_mrc_dns_proxy_generate_event(const mrc_dns_proxy_t me, const mrc_dns_proxy_event_t event)
{
	_mrc_dns_proxy_generate_event_with_error(me, event, kNoErr);
}

//======================================================================================================================

static uint64_t
_mrc_client_get_new_command_id(void)
{
	static uint64_t last_command_id = 0;
	return ++last_command_id;
}

//======================================================================================================================

static void
_mrc_dns_proxy_register(const mrc_dns_proxy_t me)
{
	require_return(me->cmd_id == 0);

	me->cmd_id = _mrc_client_get_new_command_id();
	mrc_dns_proxy_t *ptr = &g_dns_proxy_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	*ptr = me;
	mrc_retain(*ptr);
}

//======================================================================================================================

static void
_mrc_dns_proxy_deregister(const mrc_dns_proxy_t me)
{
	mrc_dns_proxy_t *ptr = &g_dns_proxy_list;
	while (*ptr && (*ptr != me)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		mrc_release(*ptr);
		*ptr = me->next;
		me->next = NULL;
	}
}

static void
_mrcs_dns_proxy_handle_dns_proxy_start_reply(const mrc_dns_proxy_t me, const uint64_t cmd_id, const xpc_object_t reply)
{
	require_return(me->cmd_id == cmd_id);
	require_return(me->state == mrc_dns_proxy_state_starting);

	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		bool valid;
		OSStatus err = mrc_xpc_message_get_error(reply, &valid);
		if (!valid) {
			err = kResponseErr;
		}
		os_log_with_type(_mrc_client_log(), err ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
			"[DP%llu] DNS proxy start reply -- error: %{mdns:err}ld", (unsigned long long)me->cmd_id, (long)err);
		if (!err) {
			me->state = mrc_dns_proxy_state_started;
			_mrc_dns_proxy_generate_event(me, mrc_dns_proxy_event_started);
		} else {
			me->state = mrc_dns_proxy_state_failed;
			_mrc_dns_proxy_terminate_async(me, err);
		}
	} else {
		char *description = xpc_copy_description(reply);
		os_log_error(_mrc_client_log(),
			"[DP%llu] Abnormal DNS proxy start reply: %{public}s", (unsigned long long)me->cmd_id, description);
		ForgetMem(&description);
		if (reply != XPC_ERROR_CONNECTION_INTERRUPTED) {
			const OSStatus err = (reply == XPC_ERROR_CONNECTION_INVALID) ? kConnectionErr : kResponseErr;
			me->state = mrc_dns_proxy_state_failed;
			_mrc_dns_proxy_terminate_async(me, err);
		}
	}
}

//======================================================================================================================

static void
_mrc_dns_proxy_start(const mrc_dns_proxy_t me)
{
	me->state = mrc_dns_proxy_state_starting;
	xpc_object_t msg = mrc_xpc_create_dns_proxy_start_command_message(me->cmd_id, me->params);
	mrc_retain(me);
	const uint64_t cmd_id = me->cmd_id;
	xpc_connection_send_message_with_reply(_mrc_client_connection(), msg, _mrc_client_queue(),
	^(const xpc_object_t reply)
	{
		_mrcs_dns_proxy_handle_dns_proxy_start_reply(me, cmd_id, reply);
		mrc_release(me);
	});
	xpc_forget(&msg);
}

//======================================================================================================================

static void
_mrcs_dns_proxy_handle_dns_proxy_stop_reply(const mrc_dns_proxy_t me, const xpc_object_t reply)
{
	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		bool valid;
		OSStatus err = mrc_xpc_message_get_error(reply, &valid);
		if (!valid) {
			err = kResponseErr;
		}
		os_log_with_type(_mrc_client_log(), err ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
			"[DP%llu] DNS proxy stop reply -- error: %{mdns:err}ld", (unsigned long long)me->cmd_id, (long)err);
	} else {
		char *description = xpc_copy_description(reply);
		os_log_error(_mrc_client_log(),
			"[DP%llu] Abnormal DNS proxy stop reply: %{public}s", (unsigned long long)me->cmd_id, description);
		ForgetMem(&description);
	}
}

//======================================================================================================================

static void
_mrc_dns_proxy_stop(const mrc_dns_proxy_t me)
{
	xpc_object_t msg = mrc_xpc_create_dns_proxy_stop_command_message(me->cmd_id);
	mrc_retain(me);
	xpc_connection_send_message_with_reply(_mrc_client_connection(), msg, _mrc_client_queue(),
	^(const xpc_object_t reply)
	{
		_mrcs_dns_proxy_handle_dns_proxy_stop_reply(me, reply);
		mrc_release(me);
	});
	xpc_forget(&msg);
}

//======================================================================================================================

static void
_mrc_dns_proxy_terminate_direct(const mrc_dns_proxy_t me, const OSStatus error)
{
	require_return(me->state != mrc_dns_proxy_state_invalidated);

	_mrc_dns_proxy_deregister(me);
	switch (me->state) {
		case mrc_dns_proxy_state_starting:
		case mrc_dns_proxy_state_started:
			_mrc_dns_proxy_stop(me);
			break;

		case mrc_dns_proxy_state_failed:
		case mrc_dns_proxy_state_invalidated:
		case mrc_dns_proxy_state_nascent:
			break;
	}
	me->state = mrc_dns_proxy_state_invalidated;
	_mrc_dns_proxy_generate_event_with_error(me, mrc_dns_proxy_event_invalidation, error);
	BlockForget(&me->event_handler);
}

//======================================================================================================================

static void
_mrc_dns_proxy_terminate_async(const mrc_dns_proxy_t me, const OSStatus error)
{
	mrc_retain(me);
	dispatch_async(_mrc_client_queue(),
	^{
		_mrc_dns_proxy_terminate_direct(me, error);
		mrc_release(me);
	});
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
mrc_dns_proxy_state_inquiry_create()
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
// MARK: - Internal Functions

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
	for (mrc_dns_proxy_t proxy = g_dns_proxy_list; proxy; proxy = proxy->next) {
		switch (proxy->state) {
			case mrc_dns_proxy_state_starting:
			case mrc_dns_proxy_state_started:
				if (proxy->state == mrc_dns_proxy_state_started) {
					_mrc_dns_proxy_generate_event(proxy, mrc_dns_proxy_event_interruption);
				}
				proxy->cmd_id = _mrc_client_get_new_command_id();
				_mrc_dns_proxy_start(proxy);
				break;

			case mrc_dns_proxy_state_failed:
			case mrc_dns_proxy_state_invalidated:
			case mrc_dns_proxy_state_nascent:
				break;
		}
	}
	for (mrc_dns_proxy_state_inquiry_t inquiry = g_dns_proxy_state_inquiry_list; inquiry; inquiry = inquiry->next) {
		switch (inquiry->state) {
			case mrc_dns_proxy_state_inquiry_state_in_progress:
				_mrc_dns_proxy_state_inquiry_send_command(inquiry);
				break;

			case mrc_dns_proxy_state_inquiry_state_nascent:
			case mrc_dns_proxy_state_inquiry_state_registered:
			case mrc_dns_proxy_state_inquiry_state_done:
				break;
		}
	}
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
		if (type == XPC_TYPE_ERROR) {
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
