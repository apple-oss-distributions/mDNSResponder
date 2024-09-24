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

#include "mrc_xpc.h"

#include "memory.h"
#include "mrc_cached_local_record_keys.h"

#include <CoreUtils/CoreUtils.h>
#include <mdns/dns_service.h>
#include <mdns/xpc.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Local Prototypes

static xpc_object_t
_mrc_xpc_create_command_message(uint64_t ident, const char *command, xpc_object_t params);

static void
_mrc_xpc_message_set_id(xpc_object_t msg, uint64_t ident);

static void
_mrc_xpc_message_set_command(const xpc_object_t msg, const char * const command);

static void
_mrc_xpc_message_set_parameters(xpc_object_t msg, xpc_object_t params);

static void
_mrc_xpc_message_set_error(xpc_object_t msg, OSStatus error);

static void
_mrc_xpc_message_set_result(xpc_object_t msg, mdns_xpc_dictionary_t result);

//======================================================================================================================
// MARK: - Mach Service Name

const char * const g_mrc_mach_service_name = "com.apple.mDNSResponder.control";

//======================================================================================================================
// MARK: - Top-Level Dictionary Keys

static const char * const g_mrc_message_key_body	= "body";
static const char * const g_mrc_message_key_command	= "command";
static const char * const g_mrc_message_key_error	= "error";
static const char * const g_mrc_message_key_id		= "id";
static const char * const g_mrc_message_key_params	= "params";
static const char * const g_mrc_message_key_result	= "result";

//======================================================================================================================
// MARK: - Result Keys

static const char * const g_mrc_result_key_description = "description";

//======================================================================================================================
// MARK: - DNS Proxy Commands and Keys

// Commands
const char * const g_mrc_command_dns_proxy_start		= "dns_proxy.start";
const char * const g_mrc_command_dns_proxy_stop			= "dns_proxy.stop";
const char * const g_mrc_command_dns_proxy_get_state	= "dns_proxy.get_state";

// Keys
static const char * const g_mrc_dns_proxy_key_input_interfaces		= "input_interfaces";
static const char * const g_mrc_dns_proxy_key_nat64_prefix_bit_len	= "nat64_prefix.bit_len";
static const char * const g_mrc_dns_proxy_key_nat64_prefix_bits		= "nat64_prefix.bits";
static const char * const g_mrc_dns_proxy_key_output_interface		= "output_interface";
static const char * const g_mrc_dns_proxy_key_force_aaaa_synthesis	= "force_aaaa_synth";

//======================================================================================================================
// MARK: - DNS Service Registration Commands and Keys

// Commands
const char * const g_mrc_command_dns_service_registration_start	= "dns_service_registration.start";
const char * const g_mrc_command_dns_service_registration_stop	= "dns_service_registration.stop";

// Keys
static const char * const g_mrc_dns_service_registration_key_definition					= "definition";
static const char * const g_mrc_dns_service_registration_key_definition_type			= "definition_type";
static const char * const g_mrc_dns_service_registration_key_reports_connection_errors	= "reports_connection_errors";

// Notification key
static const char * const g_mrc_dns_service_registration_notification_key_connection_error = "connection_error";

//======================================================================================================================
// MARK: - Discovery Proxy Commands and Keys

// Commands
const char * const g_mrc_command_discovery_proxy_start	= "discovery_proxy.start";
const char * const g_mrc_command_discovery_proxy_stop	= "discovery_proxy.stop";

// Keys
static const char * const g_mrc_discovery_proxy_key_addresses			= "addresses";
static const char * const g_mrc_discovery_proxy_key_interface			= "interface";
static const char * const g_mrc_discovery_proxy_key_match_domains		= "match_domains";
static const char * const g_mrc_discovery_proxy_key_server_certificates	= "server_certificates";

//======================================================================================================================
// MARK: - Cached Local Record Inquiry Commands and Keys

// Commands
const char * const g_mrc_command_cached_local_record_inquiry = "record_cache.local_record_inquiry";

// Result Keys
static const char * const g_mrc_cached_local_record_inquiry_result_key_record_info = "record_info";

// Record Keys
static const char * const g_mrc_cached_local_record_key_name			= MRC_CACHED_LOCAL_RECORD_KEY_NAME;
static const char * const g_mrc_cached_local_record_key_rdata			= MRC_CACHED_LOCAL_RECORD_KEY_RDATA;
static const char * const g_mrc_cached_local_record_key_source_address	= MRC_CACHED_LOCAL_RECORD_KEY_SOURCE_ADDRESS;

//======================================================================================================================
// MARK: - Record Cache Flush Commands and Keys

// Commands
const char * const g_mrc_command_record_cache_flush = "record_cache.flush";

// Keys
static const char * const g_mrc_record_cache_flush_record_name	= "record_name";
static const char * const g_mrc_record_cache_flush_key_tag		= "key_tag";

//======================================================================================================================
// MARK: - External Message Functions

uint64_t
mrc_xpc_message_get_id(const xpc_object_t msg)
{
	return xpc_dictionary_get_uint64(msg, g_mrc_message_key_id);
}

//======================================================================================================================

const char *
mrc_xpc_message_get_command(const xpc_object_t msg)
{
	return xpc_dictionary_get_string(msg, g_mrc_message_key_command);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_message_get_params(const xpc_object_t msg)
{
	return mdns_xpc_dictionary_get_dictionary(msg, g_mrc_message_key_params);
}

//======================================================================================================================

check_compile_time(((OSStatus)-1) < 0); // Make sure OSStatus is indeed signed.

OSStatus
mrc_xpc_message_get_error(const xpc_object_t msg, bool * const out_valid)
{
	return (OSStatus)mdns_xpc_dictionary_get_int32(msg, g_mrc_message_key_error, out_valid);
}

//======================================================================================================================

mdns_xpc_dictionary_t
mrc_xpc_message_get_result(const xpc_object_t msg)
{
	return mdns_xpc_dictionary_get_dictionary(msg, g_mrc_message_key_result);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_reply(const xpc_object_t msg, const OSStatus error, const mdns_xpc_dictionary_t result)
{
	xpc_object_t reply = xpc_dictionary_create_reply(msg);
	require_quiet(reply, exit);

	const uint64_t ident = mrc_xpc_message_get_id(msg);
	_mrc_xpc_message_set_id(reply, ident);
	_mrc_xpc_message_set_error(reply, error);
	if (result) {
		_mrc_xpc_message_set_result(reply, result);
	}

exit:
	return reply;
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_notification(const uint64_t ident, const xpc_object_t body)
{
	xpc_object_t _Nonnull notification = xpc_dictionary_create_empty();
	_mrc_xpc_message_set_id(notification, ident);
	xpc_dictionary_set_value(notification, g_mrc_message_key_body, body);
	return notification;
}

//======================================================================================================================

uint64_t
mrc_xpc_notification_get_id(xpc_object_t notification)
{
	return xpc_dictionary_get_uint64(notification, g_mrc_message_key_id);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_notification_get_body(const xpc_object_t notification)
{
	return xpc_dictionary_get_dictionary(notification, g_mrc_message_key_body);
}

//======================================================================================================================
// MARK: - External DNS Proxy Functions

xpc_object_t
mrc_xpc_create_dns_proxy_start_command_message(const uint64_t ident, const xpc_object_t params)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_dns_proxy_start, params);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_dns_proxy_stop_command_message(const uint64_t ident)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_dns_proxy_stop, NULL);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_dns_proxy_get_state_command_message(const uint64_t ident)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_dns_proxy_get_state, NULL);
}

//======================================================================================================================

void
mrc_xpc_dns_proxy_params_add_input_interface(const xpc_object_t params, const uint32_t ifindex)
{
	bool already_present = false;
	xpc_object_t interfaces = mrc_xpc_dns_proxy_params_get_input_interfaces(params);
	if (interfaces) {
		const size_t n = xpc_array_get_count(interfaces);
		for (size_t i = 0; i < n; ++i) {
			bool valid;
			const uint32_t current_ifindex = mdns_xpc_array_get_uint32(interfaces, i, &valid);
			if (valid && (current_ifindex == ifindex)) {
				already_present = true;
				break;
			}
		}
	} else {
		xpc_object_t new_interfaces = xpc_array_create(NULL, 0);
		xpc_dictionary_set_value(params, g_mrc_dns_proxy_key_input_interfaces, new_interfaces);
		interfaces = new_interfaces;
		xpc_forget(&new_interfaces);
	}
	if (!already_present) {
		mdns_xpc_array_append_uint32(interfaces, ifindex);
	}
}

//======================================================================================================================

xpc_object_t
mrc_xpc_dns_proxy_params_get_input_interfaces(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_array(params, g_mrc_dns_proxy_key_input_interfaces);
}

//======================================================================================================================

void
mrc_xpc_dns_proxy_params_set_output_interface(const xpc_object_t params, const uint32_t ifindex)
{
	mdns_xpc_dictionary_set_uint32(params, g_mrc_dns_proxy_key_output_interface, ifindex);
}

//======================================================================================================================

uint32_t
mrc_xpc_dns_proxy_params_get_output_interface(const xpc_object_t params, bool * const out_valid)
{
	bool valid;
	const char * const key = g_mrc_dns_proxy_key_output_interface;
	const uint32_t ifindex = mdns_xpc_dictionary_get_uint32(params, key, &valid);
	if (out_valid) {
		if (!valid && !xpc_dictionary_get_value(params, key)) {
			valid = true;
		}
		*out_valid = valid;
	}
	return ifindex;
}

//======================================================================================================================

// Simply limit the bit length to the bit length of an IPv6 address. This code makes no assumptions about acceptable
// NAT64 prefix bit lengths, which is something that should be enforced by the server side.
#define MRC_NAT64_BIT_LEN_MAX	128
#define MRC_ROUND_BIT_LEN_UP_TO_BYTE_LEN(BITLEN)	(RoundUp(BITLEN, 8) / 8)

void
mrc_xpc_dns_proxy_params_set_nat64_prefix(const xpc_object_t params, const uint8_t * const prefix,
	const size_t prefix_bit_len)
{
	uint8_t buffer[16] = {0};
	check_compile_time(sizeof(buffer) == MRC_ROUND_BIT_LEN_UP_TO_BYTE_LEN(MRC_NAT64_BIT_LEN_MAX));
	const size_t bit_len = Min(prefix_bit_len, MRC_NAT64_BIT_LEN_MAX);
	mdns_memcpy_bits(buffer, prefix, bit_len);
	const size_t byte_len = MRC_ROUND_BIT_LEN_UP_TO_BYTE_LEN(bit_len);
	xpc_dictionary_set_data(params, g_mrc_dns_proxy_key_nat64_prefix_bits, buffer, byte_len);
	xpc_dictionary_set_uint64(params, g_mrc_dns_proxy_key_nat64_prefix_bit_len, bit_len);
}

//======================================================================================================================

const uint8_t *
mrc_xpc_dns_proxy_params_get_nat64_prefix(const xpc_object_t params, size_t * const out_bit_len)
{
	const uint8_t *result_bits = NULL;
	bool valid;
	const uint64_t bit_len = mdns_xpc_dictionary_get_uint64(params, g_mrc_dns_proxy_key_nat64_prefix_bit_len, &valid);
	require_quiet(valid, exit);
	require_quiet(bit_len <= MRC_NAT64_BIT_LEN_MAX, exit);

	const uint8_t *bits;
	if (bit_len > 0) {
		size_t byte_len = 0;
		bits = xpc_dictionary_get_data(params, g_mrc_dns_proxy_key_nat64_prefix_bits, &byte_len);
		require_quiet(bits, exit);
		require_quiet(byte_len >= MRC_ROUND_BIT_LEN_UP_TO_BYTE_LEN(bit_len), exit);
	} else {
		bits = (const uint8_t *)"";
	}
	result_bits = bits;
	if (out_bit_len) {
		*out_bit_len = (size_t)bit_len;
	}

exit:
	return result_bits;
}

//======================================================================================================================

void
mrc_xpc_dns_proxy_params_set_force_aaaa_synthesis(const xpc_object_t params, const bool value)
{
	xpc_dictionary_set_bool(params, g_mrc_dns_proxy_key_force_aaaa_synthesis, value);
}

//======================================================================================================================

bool
mrc_xpc_dns_proxy_params_get_force_aaaa_synthesis(const xpc_object_t params, bool * const out_valid)
{
	bool valid;
	const char * const key = g_mrc_dns_proxy_key_force_aaaa_synthesis;
	const bool force_aaaa_synthesis = mdns_xpc_dictionary_get_bool(params, key, &valid);
	if (out_valid) {
		if (!valid && !xpc_dictionary_get_value(params, key)) {
			valid = true;
		}
		*out_valid = valid;
	}
	return force_aaaa_synthesis;
}

//======================================================================================================================

void
mrc_xpc_dns_proxy_state_result_set_description(const mdns_xpc_dictionary_t result, const char * const description)
{
	xpc_dictionary_set_string(result, g_mrc_result_key_description, description);
}

//======================================================================================================================

mdns_xpc_string_t
mrc_xpc_dns_proxy_state_result_get_description(const mdns_xpc_dictionary_t result)
{
	return mdns_xpc_dictionary_get_string(result, g_mrc_result_key_description);
}

//======================================================================================================================
// MARK: - External DNS Service Registration Functions

xpc_object_t
mrc_xpc_create_dns_service_registration_start_command_message(const uint64_t ident, const xpc_object_t params)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_dns_service_registration_start, params);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_dns_service_registration_stop_command_message(const uint64_t ident)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_dns_service_registration_stop, NULL);
}

//======================================================================================================================

void
mrc_xpc_dns_service_registration_params_set_defintion_dictionary(const xpc_object_t params,
	const xpc_object_t dict)
{
	xpc_dictionary_set_value(params, g_mrc_dns_service_registration_key_definition, dict);
}

//======================================================================================================================

mdns_xpc_dictionary_t
mrc_xpc_dns_service_registration_params_get_defintion_dictionary(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_dictionary(params, g_mrc_dns_service_registration_key_definition);
}

//======================================================================================================================

void
mrc_xpc_dns_service_registration_params_set_definition_type(const xpc_object_t params,
	const mrc_dns_service_definition_type_t type)
{
	mdns_xpc_dictionary_set_uint8(params, g_mrc_dns_service_registration_key_definition_type, type);
}

//======================================================================================================================

mrc_dns_service_definition_type_t
mrc_xpc_dns_service_registration_params_get_definition_type(const xpc_object_t params, bool * const out_valid)
{
	bool valid;
	const mrc_dns_service_definition_type_t type_val = mdns_xpc_dictionary_get_uint8(params,
		g_mrc_dns_service_registration_key_definition_type, &valid);
	mdns_require_quiet(valid, exit);

	switch (type_val) {
		case mrc_dns_service_definition_type_do53:
		case mrc_dns_service_definition_type_push:
			valid = true;
			break;

		MDNS_COVERED_SWITCH_DEFAULT:
			valid = false;
			break;
	}

exit:
	mdns_assign(out_valid, valid);
	return type_val;
}

//======================================================================================================================

void
mrc_xpc_dns_service_registration_params_set_reports_connection_errors(const xpc_object_t params,
	const bool reports_connection_errors)
{
	xpc_dictionary_set_bool(params, g_mrc_dns_service_registration_key_reports_connection_errors,
		reports_connection_errors);
}

//======================================================================================================================

bool
mrc_xpc_dns_service_registration_params_get_reports_connection_errors(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_bool(params, g_mrc_dns_service_registration_key_reports_connection_errors,
		NULL);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_dns_service_registration_notification_create_connection_error_body(const OSStatus connection_error,
	OSStatus * const out_error)
{
	OSStatus err;
	mdns_xpc_dictionary_t notification = mdns_xpc_dictionary_create_empty();
	mdns_require_action_quiet(notification, exit, err = kNoResourcesErr);

	mdns_xpc_dictionary_set_int32(notification, g_mrc_dns_service_registration_notification_key_connection_error,
		connection_error);

	err = kNoErr;
exit:
	mdns_assign(out_error, err);
	return notification;
}

//======================================================================================================================

OSStatus
mrc_xpc_dns_service_registration_notification_get_connection_error(const xpc_object_t notification_body,
	bool * const out_valid)
{
	return (OSStatus)mdns_xpc_dictionary_get_int32(notification_body,
		g_mrc_dns_service_registration_notification_key_connection_error, out_valid);
}

//======================================================================================================================
// MARK: - External Discovery Proxy Functions

uint32_t
mrc_xpc_discovery_proxy_params_get_interface(const xpc_object_t params, bool * const out_valid)
{
	return mdns_xpc_dictionary_get_uint32(params, g_mrc_discovery_proxy_key_interface, out_valid);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_discovery_proxy_params_get_ip_address_strings(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_array(params, g_mrc_discovery_proxy_key_addresses);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_discovery_proxy_params_get_match_domains(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_array(params, g_mrc_discovery_proxy_key_match_domains);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_discovery_proxy_params_get_server_certificates(const xpc_object_t params)
{
	return mdns_xpc_dictionary_get_array(params, g_mrc_discovery_proxy_key_server_certificates);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_discovery_proxy_start_command_message(const uint64_t ident, const xpc_object_t params)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_discovery_proxy_start, params);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_create_discovery_proxy_stop_command_message(const uint64_t ident)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_discovery_proxy_stop, NULL);
}

//======================================================================================================================

void
mrc_xpc_discovery_proxy_params_set_interface(const xpc_object_t params, const uint32_t ifindex)
{
	mdns_xpc_dictionary_set_uint32(params, g_mrc_discovery_proxy_key_interface, ifindex);
}

//======================================================================================================================

void
mrc_xpc_discovery_proxy_params_add_server_address(const xpc_object_t params, const char * const address)
{
	xpc_object_t server_addresses = mrc_xpc_discovery_proxy_params_get_ip_address_strings(params);
	if (!server_addresses) {
		xpc_object_t new_server_addresses = xpc_array_create_empty();
		xpc_dictionary_set_value(params, g_mrc_discovery_proxy_key_addresses, new_server_addresses);
		server_addresses = new_server_addresses;
		xpc_forget(&new_server_addresses);
	}
	mdns_xpc_array_append_string(server_addresses, address);
}

//======================================================================================================================

void
mrc_xpc_discovery_proxy_params_add_match_domain(const xpc_object_t params, const char * const domain)
{
	xpc_object_t domains = mrc_xpc_discovery_proxy_params_get_match_domains(params);
	if (!domains) {
		xpc_object_t new_domains = xpc_array_create_empty();
		xpc_dictionary_set_value(params, g_mrc_discovery_proxy_key_match_domains, new_domains);
		domains = new_domains;
		xpc_forget(&new_domains);
	}
	mdns_xpc_array_append_string(domains, domain);
}

//======================================================================================================================

void
mrc_xpc_discovery_proxy_params_add_server_certificate(const xpc_object_t params, const uint8_t * const cert_data,
	const size_t cert_len)
{
	xpc_object_t certs = mrc_xpc_discovery_proxy_params_get_server_certificates(params);
	if (!certs) {
		xpc_object_t new_certs = xpc_array_create_empty();
		xpc_dictionary_set_value(params, g_mrc_discovery_proxy_key_server_certificates, new_certs);
		certs = new_certs;
		xpc_forget(&new_certs);
	}
	mdns_xpc_array_append_data(certs, cert_data, cert_len);
}

//======================================================================================================================
// MARK: - External Cached Local Record Inquiry Functions

xpc_object_t
mrc_xpc_create_cached_local_record_inquiry_command_message(const uint64_t ident)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_cached_local_record_inquiry, NULL);
}

//======================================================================================================================

void
mrc_xpc_cached_local_record_inquiry_result_add(const xpc_object_t result, const char * const name,
	const char * const rdata, const char * const source_address)
{
	xpc_object_t dict = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(dict, g_mrc_cached_local_record_key_name, name);
	if (rdata) {
		xpc_dictionary_set_string(dict, g_mrc_cached_local_record_key_rdata, rdata);
	}
	if (source_address) {
		xpc_dictionary_set_string(dict, g_mrc_cached_local_record_key_source_address, source_address);
	}
	mdns_xpc_dictionary_array_append_value(result, g_mrc_cached_local_record_inquiry_result_key_record_info, dict);
	xpc_forget(&dict);
}

//======================================================================================================================

xpc_object_t
mrc_xpc_cached_local_record_inquiry_result_get_record_info(const xpc_object_t result, bool * const out_valid)
{
	return mdns_xpc_dictionary_get_optional_array(result, g_mrc_cached_local_record_inquiry_result_key_record_info,
		out_valid);
}

//======================================================================================================================
// MARK: - External Record Cache Flush Functions

xpc_object_t
mrc_xpc_create_record_cache_flush_command_message(const uint64_t ident, const xpc_object_t params)
{
	return _mrc_xpc_create_command_message(ident, g_mrc_command_record_cache_flush, params);
}

//======================================================================================================================

void
mrc_xpc_record_cache_flush_params_set_record_name(const xpc_object_t params, const char * const record_name)
{
	xpc_dictionary_set_string(params, g_mrc_record_cache_flush_record_name, record_name);
}

//======================================================================================================================

const char *
mrc_xpc_record_cache_flush_params_get_record_name(const xpc_object_t params)
{
	return xpc_dictionary_get_string(params, g_mrc_record_cache_flush_record_name);
}

//======================================================================================================================

void
mrc_xpc_record_cache_flush_params_set_key_tag(const xpc_object_t params, const uint16_t key_tag)
{
	mdns_xpc_dictionary_set_uint16(params, g_mrc_record_cache_flush_key_tag, key_tag);
}

//======================================================================================================================

uint16_t
mrc_xpc_record_cache_flush_params_get_key_tag(const xpc_object_t params, bool * const out_valid)
{
	return mdns_xpc_dictionary_get_uint16(params, g_mrc_record_cache_flush_key_tag, out_valid);
}

//======================================================================================================================
// MARK: - Internal Message Functions

static xpc_object_t
_mrc_xpc_create_command_message(const uint64_t ident, const char * const command, const xpc_object_t params)
{
	xpc_object_t _Nonnull msg = xpc_dictionary_create(NULL, NULL, 0);
	_mrc_xpc_message_set_id(msg, ident);
	_mrc_xpc_message_set_command(msg, command);
	if (params) {
		_mrc_xpc_message_set_parameters(msg, params);
	}
	return msg;
}

//======================================================================================================================

static void
_mrc_xpc_message_set_id(const xpc_object_t msg, const uint64_t ident)
{
	xpc_dictionary_set_uint64(msg, g_mrc_message_key_id, ident);
}

//======================================================================================================================

static void
_mrc_xpc_message_set_command(const xpc_object_t msg, const char * const command)
{
	xpc_dictionary_set_string(msg, g_mrc_message_key_command, command);
}

//======================================================================================================================

static void
_mrc_xpc_message_set_parameters(const xpc_object_t msg, const xpc_object_t params)
{
	xpc_dictionary_set_value(msg, g_mrc_message_key_params, params);
}

//======================================================================================================================

void
_mrc_xpc_message_set_error(const xpc_object_t msg, const OSStatus error)
{
	mdns_xpc_dictionary_set_int32(msg, g_mrc_message_key_error, error);
}

//======================================================================================================================

static void
_mrc_xpc_message_set_result(const xpc_object_t msg, const mdns_xpc_dictionary_t result)
{
	xpc_dictionary_set_value(msg, g_mrc_message_key_result, result);
}
