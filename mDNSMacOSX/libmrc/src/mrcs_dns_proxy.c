/*
 * Copyright (c) 2021-2023 Apple Inc. All rights reserved.
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

#include "mrcs_dns_proxy.h"

#include "helpers.h"
#include "memory.h"
#include "mrcs_cf_support.h"
#include "mrcs_objects.h"

#include <arpa/inet.h>
#include <CoreUtils/CoreUtils.h>
#include <mdns/system.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Proxy Kind Definition

typedef struct {
	char *		name;	// Network interface's name.
	uint32_t	index;	// Network interface's index.
} mrcs_interface_t;

struct mrcs_dns_proxy_s {
	struct mdns_obj_s	base;					// Object base.
	nw_nat64_prefix_t	nat64_prefix;			// NAT64 prefix.
	mrcs_interface_t *	input_interfaces;		// Array of input interfaces.
	size_t				input_interface_count;	// Current number of input interface indexes.
	mrcs_interface_t	output_interface;		// Output interface.
	uid_t				euid;					// Effective user ID.
	bool				nat64_prefix_valid;		// True if the NAT64 prefix is currently valid.
	bool				force_aaaa_synthesis;	// True if the DNS proxy policy is to force AAAA synthesis.
};

MRCS_OBJECT_SUBKIND_DEFINE(dns_proxy);

//======================================================================================================================
// MARK: - DNS Proxy Kind Definition

struct mrcs_dns_proxy_manager_s {
	struct mdns_obj_s	base;		// Object base.
	CFMutableArrayRef	proxies;	// DNS proxy collection.
};

MRCS_OBJECT_SUBKIND_DEFINE(dns_proxy_manager);

//======================================================================================================================
// MARK: - Local Prototypes

static bool
_mrcs_dns_proxy_manager_conflicts_with_proxy(mrcs_dns_proxy_manager_t me, mrcs_dns_proxy_t proxy);

static bool
_mrcs_nat64_prefix_equal_null_safe(const nw_nat64_prefix_t *p1, const nw_nat64_prefix_t *p2);

static int
_mrcs_nat64_prefix_to_byte_length(const nw_nat64_prefix_t *prefix);

static const char *
_mrcs_string_or_empty(const char *string);

//======================================================================================================================
// MARK: - DNS Proxy Public Methods

mrcs_dns_proxy_t
mrcs_dns_proxy_create(OSStatus * const out_error)
{
	OSStatus err;
	mrcs_dns_proxy_t proxy = NULL;
	mrcs_dns_proxy_t obj = _mrcs_dns_proxy_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	proxy = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrcs_forget(&obj);
	return proxy;
}

//======================================================================================================================

OSStatus
mrcs_dns_proxy_add_input_interface(const mrcs_dns_proxy_t me, const uint32_t ifindex)
{
	OSStatus err;
	if (!mrcs_dns_proxy_contains_input_interface(me, ifindex)) {
		require_action_quiet(me->input_interface_count <= (SIZE_MAX - 1), exit, err = kCountErr);
		const size_t new_count = me->input_interface_count + 1;
		mrcs_interface_t *new_interfaces = (mrcs_interface_t *)mdns_calloc(new_count, sizeof(*new_interfaces));
		require_action_quiet(new_interfaces, exit, err = kNoMemoryErr);

		// Shallow copy the new interface array, but remember to NULL out the old allocated interface name pointer.
		for (size_t i = 0; i < me->input_interface_count; ++i) {
			new_interfaces[i] = me->input_interfaces[i];
			me->input_interfaces[i].name = NULL;
		}
		// Set the newest input interface.
		mrcs_interface_t * const interface = &new_interfaces[me->input_interface_count];
		interface->index = ifindex;
		interface->name = mdns_system_interface_index_to_name(interface->index, NULL);

		// Free the old input interface array and take ownership of the new one.
		ForgetMem(&me->input_interfaces);
		me->input_interfaces = new_interfaces;
		new_interfaces = NULL;
		me->input_interface_count = new_count;
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

void
mrcs_dns_proxy_set_output_interface(const mrcs_dns_proxy_t me, const uint32_t ifindex)
{
	mrcs_interface_t * const interface = &me->output_interface;
	interface->index = ifindex;
	ForgetMem(&interface->name);
	interface->name = mdns_system_interface_index_to_name(interface->index, NULL);
}

//======================================================================================================================

OSStatus
mrcs_dns_proxy_set_nat64_prefix(const mrcs_dns_proxy_t me, const uint8_t * const prefix, const size_t prefix_bitlen)
{
	OSStatus err;
	nw_nat64_prefix_length_t length;
	switch (prefix_bitlen) {
#define _nat64_prefix_bitlen_case(BITLEN)				\
		case BITLEN:									\
			length = nw_nat64_prefix_length_ ## BITLEN;	\
			break;
		_nat64_prefix_bitlen_case(32)
		_nat64_prefix_bitlen_case(40)
		_nat64_prefix_bitlen_case(48)
		_nat64_prefix_bitlen_case(56)
		_nat64_prefix_bitlen_case(64)
		_nat64_prefix_bitlen_case(96)
#undef _nat64_prefix_bitlen_case
		default:
			err = kSizeErr;
			goto exit;
	}
	memset(me->nat64_prefix.data, 0, sizeof(me->nat64_prefix.data));
	mdns_memcpy_bits(me->nat64_prefix.data, prefix, prefix_bitlen);
	me->nat64_prefix.length = length;
	me->nat64_prefix_valid = true;
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

void
mrcs_dns_proxy_enable_force_aaaa_synthesis(const mrcs_dns_proxy_t me, const bool enable)
{
	me->force_aaaa_synthesis = enable;
}

//======================================================================================================================

void
mrcs_dns_proxy_set_euid(const mrcs_dns_proxy_t me, const uid_t euid)
{
	me->euid = euid;
}

//======================================================================================================================

bool
mrcs_dns_proxy_contains_input_interface(const mrcs_dns_proxy_t me, const uint32_t ifindex)
{
	for (size_t i = 0; i < me->input_interface_count; ++i) {
		if (me->input_interfaces[i].index == ifindex) {
			return true;
		}
	}
	return false;
}

//======================================================================================================================

uint32_t
mrcs_dns_proxy_get_output_interface(const mrcs_dns_proxy_t me)
{
	return me->output_interface.index;
}

//======================================================================================================================

const nw_nat64_prefix_t *
mrcs_dns_proxy_get_nat64_prefix(const mrcs_dns_proxy_t me)
{
	return (me->nat64_prefix_valid ? &me->nat64_prefix : NULL);
}

//======================================================================================================================

bool
mrcs_dns_proxy_forces_aaaa_synthesis(const mrcs_dns_proxy_t me)
{
	return me->force_aaaa_synthesis;
}

//======================================================================================================================

uid_t
mrcs_dns_proxy_get_euid(const mrcs_dns_proxy_t me)
{
	return me->euid;
}

//======================================================================================================================
// MARK: - DNS Proxy Private Methods

static OSStatus
_mrcs_dns_proxy_print_description(const mrcs_dns_proxy_t me, const bool debug, __unused const bool privacy,
	char * const buf, const size_t buf_len, size_t * const out_len, size_t * const out_full_len)
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
	_do_appendf("input interfaces: {");
	const mrcs_interface_t *interface;
	const char *separator = "";
	for (size_t i = 0; i < me->input_interface_count; ++i) {
		interface = &me->input_interfaces[i];
		_do_appendf("%s%s/%u", separator, _mrcs_string_or_empty(interface->name), interface->index);
		separator = ", ";
	}
	interface = &me->output_interface;
	_do_appendf("}, output interface: %s/%u", _mrcs_string_or_empty(interface->name), interface->index);

	const nw_nat64_prefix_t * const prefix = mrcs_dns_proxy_get_nat64_prefix(me);
	if (prefix) {
		uint8_t ipv6_addr[16] = {0};
		check_compile_time_code(sizeof(prefix->data) <= sizeof(ipv6_addr));
		memcpy(ipv6_addr, prefix->data, sizeof(prefix->data));

		char addr_buf[INET6_ADDRSTRLEN];
		const char * const addr_str = inet_ntop(AF_INET6, ipv6_addr, addr_buf, (socklen_t)sizeof(addr_buf));
		err = map_global_value_errno(addr_str, addr_str);
		require_noerr_quiet(err, exit);

		const int byte_len = _mrcs_nat64_prefix_to_byte_length(prefix);
		const int bitlen = (byte_len >= 0) ? (byte_len * 8) : -1;
		_do_appendf(", nat64 prefix: %s/%d", addr_str, bitlen);
	}
	_do_appendf(", forces AAAA synthesis: %s", mrcs_dns_proxy_forces_aaaa_synthesis(me) ? "yes" : "no");
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

//======================================================================================================================

static char *
_mrcs_dns_proxy_copy_description(const mrcs_dns_proxy_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	char buf[128];
	size_t full_len;
	OSStatus err = _mrcs_dns_proxy_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &full_len);
	require_noerr_quiet(err, exit);

	if (full_len < sizeof(buf)) {
		description = mdns_strdup(buf);
	} else {
		const size_t buf_len = full_len + 1;
		char *buf_ptr = (char *)mdns_malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mrcs_dns_proxy_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		require_noerr_action_quiet(err, exit, ForgetMem(&buf_ptr));

		description = buf_ptr;
	}

exit:
	return description;
}

//======================================================================================================================

static void
_mrcs_dns_proxy_finalize(const mrcs_dns_proxy_t me)
{
	for (size_t i = 0; i < me->input_interface_count; ++i) {
		ForgetMem(&me->input_interfaces[i].name);
	}
	ForgetMem(&me->input_interfaces);
	ForgetMem(&me->output_interface.name);
}

//======================================================================================================================

static bool
_mrcs_dns_proxy_has_common_input_interface(const mrcs_dns_proxy_t me, const mrcs_dns_proxy_t other)
{
	for (size_t i = 0; i < me->input_interface_count; ++i) {
		if (mrcs_dns_proxy_contains_input_interface(other, me->input_interfaces[i].index)) {
			return true;
		}
	}
	return false;
}

//======================================================================================================================

static bool
_mrcs_dns_proxy_conflicts_with_other_proxy(const mrcs_dns_proxy_t me, const mrcs_dns_proxy_t other)
{
	if (_mrcs_dns_proxy_has_common_input_interface(me, other)) {
		if (me->output_interface.index != other->output_interface.index) {
			return true;
		}
		const nw_nat64_prefix_t * const prefix = mrcs_dns_proxy_get_nat64_prefix(me);
		const nw_nat64_prefix_t * const other_prefix = mrcs_dns_proxy_get_nat64_prefix(other);
		if (!_mrcs_nat64_prefix_equal_null_safe(prefix, other_prefix)) {
			return true;
		}
		if (prefix && other_prefix) {
			if (!!me->force_aaaa_synthesis != !!other->force_aaaa_synthesis) {
				return true;
			}
		}
	}
	return false;
}

//======================================================================================================================
// MARK: - DNS Proxy Manager Public Methods

mrcs_dns_proxy_manager_t
mrcs_dns_proxy_manager_create(OSStatus * const out_error)
{
	OSStatus err;
	mrcs_dns_proxy_manager_t manager = NULL;
	mrcs_dns_proxy_manager_t obj = _mrcs_dns_proxy_manager_new();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->proxies = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mrcs_cfarray_callbacks);
	require_action_quiet(obj->proxies, exit, err = kNoResourcesErr);

	manager = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mrcs_forget(&obj);
	return manager;
}

//======================================================================================================================

OSStatus
mrcs_dns_proxy_manager_add_proxy(const mrcs_dns_proxy_manager_t me, const mrcs_dns_proxy_t proxy)
{
	OSStatus err;
	const bool conflicts = _mrcs_dns_proxy_manager_conflicts_with_proxy(me, proxy);
	require_action_quiet(!conflicts, exit, err = kCollisionErr);

	CFArrayAppendValue(me->proxies, proxy);
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

OSStatus
mrcs_dns_proxy_manager_remove_proxy(const mrcs_dns_proxy_manager_t me, const mrcs_dns_proxy_t proxy)
{
	CFIndex i;
	const CFIndex n = CFArrayGetCount(me->proxies);
	for (i = 0; i < n; ++i) {
		if (CFArrayGetValueAtIndex(me->proxies, i) == proxy) {
			break;
		}
	}
	OSStatus err;
	require_action_quiet(i < n, exit, err = kNotFoundErr);

	CFArrayRemoveValueAtIndex(me->proxies, i);
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

size_t
mrcs_dns_proxy_manager_get_count(const mrcs_dns_proxy_manager_t me)
{
	return (size_t)CFArrayGetCount(me->proxies);
}

//======================================================================================================================

mrcs_dns_proxy_t
mrcs_dns_proxy_manager_get_proxy_by_input_interface(const mrcs_dns_proxy_manager_t me, const uint32_t ifindex)
{
	__block mrcs_dns_proxy_t result = NULL;
	mrcs_cfarray_enumerate(me->proxies,
	^ bool (const mrcs_dns_proxy_t proxy)
	{
		if (mrcs_dns_proxy_contains_input_interface(proxy, ifindex)) {
			result = proxy;
		}
		const bool proceed = (result == NULL);
		return proceed;
	});
	return result;
}

//======================================================================================================================
// MARK: - DNS Proxy Manager Private Methods

static OSStatus
_mrcs_dns_proxy_manager_print_description(const mrcs_dns_proxy_manager_t me, const bool debug, const bool privacy,
	char * const buf, const size_t buf_len, size_t * const out_len, size_t * const out_full_len)
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
	_do_appendf("{");
	const CFIndex n = CFArrayGetCount(me->proxies);
	for (CFIndex i = 0; i < n; ++i) {
		_do_appendf("%s\n\t", (i == 0) ? "" : ",");
		size_t wrote_len, desc_len;
		const mrcs_dns_proxy_t proxy = (mrcs_dns_proxy_t)CFArrayGetValueAtIndex(me->proxies, i);
		err = _mrcs_dns_proxy_print_description(proxy, false, privacy, dst, (size_t)(lim - dst), &wrote_len, &desc_len);
		require_noerr_quiet(err, exit);

		dst += wrote_len;
		full_len += desc_len;
	}
	_do_appendf("\n}");
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

//======================================================================================================================

static char *
_mrcs_dns_proxy_manager_copy_description(const mrcs_dns_proxy_manager_t me, const bool debug, const bool privacy)
{
	char *description = NULL;
	char buf[512];
	size_t full_len;
	OSStatus err = _mrcs_dns_proxy_manager_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &full_len);
	require_noerr_quiet(err, exit);

	if (full_len < sizeof(buf)) {
		description = mdns_strdup(buf);
	} else {
		const size_t buf_len = full_len + 1;
		char *buf_ptr = (char *)mdns_malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mrcs_dns_proxy_manager_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		require_noerr_action_quiet(err, exit, ForgetMem(&buf_ptr));

		description = buf_ptr;
	}

exit:
	return description;
}

//======================================================================================================================

static void
_mrcs_dns_proxy_manager_finalize(const mrcs_dns_proxy_manager_t me)
{
	CFForget(&me->proxies);
}

//======================================================================================================================

static bool
_mrcs_dns_proxy_manager_conflicts_with_proxy(const mrcs_dns_proxy_manager_t me, const mrcs_dns_proxy_t other)
{
	const bool conflict_free = mrcs_cfarray_enumerate(me->proxies,
	^ bool (const mrcs_dns_proxy_t proxy)
	{
		const bool proceed = !_mrcs_dns_proxy_conflicts_with_other_proxy(proxy, other);
		return proceed;
	});
	return !conflict_free;
}

//======================================================================================================================
// MARK: - Helpers

static bool
_mrcs_nat64_prefix_equal_null_safe(const nw_nat64_prefix_t * const p1, const nw_nat64_prefix_t * const p2)
{
	if (p1 == p2) {
		return true;
	}
	if (!p1 || !p2) {
		return false;
	}
	if (p1->length != p2->length) {
		return false;
	}
	const int byte_len = _mrcs_nat64_prefix_to_byte_length(p1);
	if (byte_len < 0) {
		return false;
	}
	return (memcmp(p1->data, p2->data, (size_t)byte_len) == 0);
}

//======================================================================================================================

static int
_mrcs_nat64_prefix_to_byte_length(const nw_nat64_prefix_t * const prefix)
{
	int len;
	switch (prefix->length) {
#define _nat64_prefix_length_case(BITLEN)					\
		case nw_nat64_prefix_length_ ## BITLEN: {			\
			check_compile_time_code(((BITLEN) % 8) == 0);	\
			len = (BITLEN) / 8;								\
			break;											\
		}
		_nat64_prefix_length_case(32)
		_nat64_prefix_length_case(40)
		_nat64_prefix_length_case(48)
		_nat64_prefix_length_case(56)
		_nat64_prefix_length_case(64)
		_nat64_prefix_length_case(96)
#undef _nat64_prefix_length_case
		CUClangWarningIgnoreBegin(-Wcovered-switch-default);
		default:
		CUClangWarningIgnoreEnd();
			len = -1;
			break;
	}
	return len;
}

//======================================================================================================================

static const char *
_mrcs_string_or_empty(const char * const string)
{
	return (string ? string : "");
}
