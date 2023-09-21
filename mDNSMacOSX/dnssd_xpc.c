/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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

#include "dnssd_private.h"
#include "dnssd_xpc.h"

#include <mdns/xpc.h>
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - XPC Dictionary Helper Declarations

static xpc_object_t _Nullable
_dnssd_xpc_dictionary_get_value(xpc_object_t dict, const char *key, xpc_type_t type);

//======================================================================================================================
// MARK: - Top-Level Message Dictionaries

#define DNSSD_XPC_MESSAGE_KEY_COMMAND	"command"
#define DNSSD_XPC_MESSAGE_KEY_ERROR		"error"
#define DNSSD_XPC_MESSAGE_KEY_ID		"id"
#define DNSSD_XPC_MESSAGE_KEY_PARAMS	"params"
#define DNSSD_XPC_MESSAGE_KEY_RESULTS	"results"

//======================================================================================================================

const char * _Nullable
dnssd_xpc_message_get_command(xpc_object_t msg)
{
	return xpc_dictionary_get_string(msg, DNSSD_XPC_MESSAGE_KEY_COMMAND);
}

//======================================================================================================================

void
dnssd_xpc_message_set_command(xpc_object_t msg, const char *command)
{
	xpc_dictionary_set_string(msg, DNSSD_XPC_MESSAGE_KEY_COMMAND, command);
}

//======================================================================================================================

DNSServiceErrorType
dnssd_xpc_message_get_error(xpc_object_t msg, bool *out_valid)
{
	return mdns_xpc_dictionary_get_int32(msg, DNSSD_XPC_MESSAGE_KEY_ERROR, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_message_set_error(xpc_object_t msg, DNSServiceErrorType error)
{
	xpc_dictionary_set_int64(msg, DNSSD_XPC_MESSAGE_KEY_ERROR, error);
}

//======================================================================================================================

uint64_t
dnssd_xpc_message_get_id(xpc_object_t msg, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint64(msg, DNSSD_XPC_MESSAGE_KEY_ID, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_message_set_id(xpc_object_t msg, uint64_t ident)
{
	xpc_dictionary_set_uint64(msg, DNSSD_XPC_MESSAGE_KEY_ID, ident);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_message_get_parameters(xpc_object_t msg)
{
	return xpc_dictionary_get_dictionary(msg, DNSSD_XPC_MESSAGE_KEY_PARAMS);
}

//======================================================================================================================

void
dnssd_xpc_message_set_parameters(xpc_object_t msg, xpc_object_t params)
{
	xpc_dictionary_set_value(msg, DNSSD_XPC_MESSAGE_KEY_PARAMS, params);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_message_get_results(xpc_object_t msg)
{
	return xpc_dictionary_get_array(msg, DNSSD_XPC_MESSAGE_KEY_RESULTS);
}

//======================================================================================================================

void
dnssd_xpc_message_set_results(xpc_object_t msg, xpc_object_t results)
{
	xpc_dictionary_set_value(msg, DNSSD_XPC_MESSAGE_KEY_RESULTS, results);
}

//======================================================================================================================
// MARK: - Parameter Dictionaries

#define DNSSD_XPC_PARAMETERS_KEY_ACCOUNT_ID				"account_id"
#define DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID			"delegate_id"
#define DNSSD_XPC_PARAMETERS_KEY_FALLBACK_CONFIG		"fallback_config"
#define DNSSD_XPC_PARAMETERS_KEY_FLAGS					"flags"
#define DNSSD_XPC_PARAMETERS_KEY_HOSTNAME				"hostname"
#define DNSSD_XPC_PARAMETERS_KEY_INTERFACE_INDEX		"interface_index"
#define DNSSD_XPC_PARAMETERS_KEY_LOG_PRIVACY_LEVEL		"log_privacy_level"
#define DNSSD_XPC_PARAMETERS_KEY_NEED_ENCRYPTION		"need_encryption"
#define DNSSD_XPC_PARAMETERS_KEY_PROHIBIT_ENCRYPTED_DNS	"prohibit_encrypted_dns"
#define DNSSD_XPC_PARAMETERS_KEY_PROTOCOLS				"protocols"
#define DNSSD_XPC_PARAMETERS_KEY_RESOLVER_UUIDS			"resolver_uuids"
#define DNSSD_XPC_PARAMETERS_KEY_SERVICE_SCHEME			"service_scheme"
#define DNSSD_XPC_PARAMETERS_KEY_USE_FAILOVER			"use_failover"
#define DNSSD_XPC_PARAMETERS_KEY_VALIDATION_DATA		"validation_data"

//======================================================================================================================

pid_t
dnssd_xpc_parameters_get_delegate_pid(xpc_object_t params, bool *out_valid)
{
	return (pid_t)mdns_xpc_dictionary_get_int64(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_delegate_pid(xpc_object_t params, pid_t pid)
{
	xpc_dictionary_set_int64(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID, pid);
}

//======================================================================================================================

const uint8_t *
dnssd_xpc_parameters_get_delegate_uuid(xpc_object_t params)
{
	return xpc_dictionary_get_uuid(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_delegate_uuid(xpc_object_t params, uuid_t uuid)
{
	xpc_dictionary_set_uuid(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID, uuid);
}

//======================================================================================================================

audit_token_t * _Nullable
dnssd_xpc_parameters_get_delegate_audit_token(const xpc_object_t params, audit_token_t * const audit_token_storage)
{
	size_t size;
	const void * const data = xpc_dictionary_get_data(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID, &size);
	if (data && (size == sizeof(*audit_token_storage))) {
		memcpy(audit_token_storage, data, size);
		return audit_token_storage;
	} else {
		return NULL;
	}
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_delegate_audit_token(const xpc_object_t params, const audit_token_t * const audit_token)
{
	xpc_dictionary_set_data(params, DNSSD_XPC_PARAMETERS_KEY_DELEGATE_ID, audit_token, sizeof(*audit_token));
}

//======================================================================================================================

DNSServiceFlags
dnssd_xpc_parameters_get_flags(xpc_object_t params, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint32(params, DNSSD_XPC_PARAMETERS_KEY_FLAGS, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_flags(xpc_object_t params, DNSServiceFlags flags)
{
	xpc_dictionary_set_uint64(params, DNSSD_XPC_PARAMETERS_KEY_FLAGS, flags);
}

//======================================================================================================================

const char *
dnssd_xpc_parameters_get_account_id(xpc_object_t params)
{
	return xpc_dictionary_get_string(params, DNSSD_XPC_PARAMETERS_KEY_ACCOUNT_ID);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_account_id(xpc_object_t params, const char *account_id)
{
	xpc_dictionary_set_string(params, DNSSD_XPC_PARAMETERS_KEY_ACCOUNT_ID, account_id);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_parameters_get_hostname_object(xpc_object_t params)
{
	return _dnssd_xpc_dictionary_get_value(params, DNSSD_XPC_PARAMETERS_KEY_HOSTNAME, XPC_TYPE_STRING);
}

//======================================================================================================================

const char *
dnssd_xpc_parameters_get_hostname(xpc_object_t params)
{
	return xpc_dictionary_get_string(params, DNSSD_XPC_PARAMETERS_KEY_HOSTNAME);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_hostname(xpc_object_t params, const char *hostname)
{
	xpc_dictionary_set_string(params, DNSSD_XPC_PARAMETERS_KEY_HOSTNAME, hostname);
}

//======================================================================================================================

uint32_t
dnssd_xpc_parameters_get_interface_index(xpc_object_t params, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint32(params, DNSSD_XPC_PARAMETERS_KEY_INTERFACE_INDEX, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_interface_index(xpc_object_t params, uint32_t interface_index)
{
	xpc_dictionary_set_uint64(params, DNSSD_XPC_PARAMETERS_KEY_INTERFACE_INDEX, interface_index);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_need_encrypted_query(xpc_object_t params, bool need, _Nullable xpc_object_t fallback_config)
{
	xpc_dictionary_set_bool(params, DNSSD_XPC_PARAMETERS_KEY_NEED_ENCRYPTION, need);
	if (fallback_config != NULL) {
		xpc_dictionary_set_value(params, DNSSD_XPC_PARAMETERS_KEY_FALLBACK_CONFIG, fallback_config);
	}
}

//======================================================================================================================

bool
dnssd_xpc_parameters_get_need_encrypted_query(xpc_object_t params)
{
	return xpc_dictionary_get_bool(params, DNSSD_XPC_PARAMETERS_KEY_NEED_ENCRYPTION);
}

//======================================================================================================================

xpc_object_t _Nullable
dnssd_xpc_parameters_get_fallback_config(xpc_object_t params)
{
	return xpc_dictionary_get_value(params, DNSSD_XPC_PARAMETERS_KEY_FALLBACK_CONFIG);
}

//======================================================================================================================

xpc_object_t _Nullable
dnssd_xpc_parameters_get_resolver_uuid_array(xpc_object_t params)
{
	return xpc_dictionary_get_value(params, DNSSD_XPC_PARAMETERS_KEY_RESOLVER_UUIDS);
}

//======================================================================================================================

void
dnssd_xpc_parameters_add_resolver_uuid(xpc_object_t params, uuid_t _Nonnull uuid)
{
	xpc_object_t resolver_uuid_array = xpc_dictionary_get_value(params, DNSSD_XPC_PARAMETERS_KEY_RESOLVER_UUIDS);
	if (resolver_uuid_array == NULL) {
		resolver_uuid_array = xpc_array_create(NULL, 0);
		xpc_dictionary_set_value(params, DNSSD_XPC_PARAMETERS_KEY_RESOLVER_UUIDS, resolver_uuid_array);
		xpc_object_t tmp = resolver_uuid_array;
		xpc_forget(&tmp);
	}
	xpc_array_set_uuid(resolver_uuid_array, XPC_ARRAY_APPEND, uuid);
}

//======================================================================================================================

DNSServiceProtocol
dnssd_xpc_parameters_get_protocols(xpc_object_t params, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint32(params, DNSSD_XPC_PARAMETERS_KEY_PROTOCOLS, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_protocols(xpc_object_t params, DNSServiceProtocol protocols)
{
	xpc_dictionary_set_uint64(params, DNSSD_XPC_PARAMETERS_KEY_PROTOCOLS, protocols);
}

//======================================================================================================================

const char * _Nullable
dnssd_xpc_parameters_get_service_scheme(xpc_object_t params)
{
	return xpc_dictionary_get_string(params, DNSSD_XPC_PARAMETERS_KEY_SERVICE_SCHEME);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_service_scheme(xpc_object_t params, const char *service_scheme)
{
	xpc_dictionary_set_string(params, DNSSD_XPC_PARAMETERS_KEY_SERVICE_SCHEME, service_scheme);
}

//======================================================================================================================

bool
dnssd_xpc_parameters_get_use_failover(const xpc_object_t params)
{
	return xpc_dictionary_get_bool(params, DNSSD_XPC_PARAMETERS_KEY_USE_FAILOVER);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_use_failover(const xpc_object_t params, const bool use_failover)
{
	xpc_dictionary_set_bool(params, DNSSD_XPC_PARAMETERS_KEY_USE_FAILOVER, use_failover);
}

//======================================================================================================================

dnssd_log_privacy_level_t
dnssd_xpc_parameters_get_log_privacy_level(const xpc_object_t params)
{
	bool valid;
	// Make sure that dnssd_log_privacy_level_t is indeed an 8-bit signed integer.
	check_compile_time_code(sizeof(dnssd_log_privacy_level_t) == sizeof(int8_t));
	check_compile_time_code(((dnssd_log_privacy_level_t)-1) < 0);
	const dnssd_log_privacy_level_t level = mdns_xpc_dictionary_get_int8(params,
		DNSSD_XPC_PARAMETERS_KEY_LOG_PRIVACY_LEVEL, &valid);
	if (valid) {
		// A default case isn't used to allow the compiler to catch missing dnssd_log_privacy_level_t enum values.
		switch (level) {
			case dnssd_log_privacy_level_default:
			case dnssd_log_privacy_level_private:
				return level;
		}
	}
	return dnssd_log_privacy_level_default;
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_log_privacy_level(const xpc_object_t params, const dnssd_log_privacy_level_t level)
{
	mdns_xpc_dictionary_set_int8(params, DNSSD_XPC_PARAMETERS_KEY_LOG_PRIVACY_LEVEL, level);
}

//======================================================================================================================

const uint8_t *
dnssd_xpc_parameters_get_validation_data(const xpc_object_t params, size_t * const out_length)
{
	return (const uint8_t *)xpc_dictionary_get_data(params, DNSSD_XPC_PARAMETERS_KEY_VALIDATION_DATA, out_length);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_validation_data(const xpc_object_t params, const uint8_t * const data_ptr,
	const size_t data_len)
{
	xpc_dictionary_set_data(params, DNSSD_XPC_PARAMETERS_KEY_VALIDATION_DATA, data_ptr, data_len);
}

//======================================================================================================================

bool
dnssd_xpc_parameters_get_prohibit_encrypted_dns(const xpc_object_t params)
{
	return xpc_dictionary_get_bool(params, DNSSD_XPC_PARAMETERS_KEY_PROHIBIT_ENCRYPTED_DNS);
}

//======================================================================================================================

void
dnssd_xpc_parameters_set_prohibit_encrypted_dns(const xpc_object_t params, const bool prohibit)
{
	xpc_dictionary_set_bool(params, DNSSD_XPC_PARAMETERS_KEY_PROHIBIT_ENCRYPTED_DNS, prohibit);
}

//======================================================================================================================
// MARK: - Result Dictionaries

#define DNSSD_XPC_RESULT_KEY_CNAME_UPDATE				"cname_update"
#define DNSSD_XPC_RESULT_KEY_ERROR						"error"
#define DNSSD_XPC_RESULT_KEY_EXTENDED_DNS_ERROR			"extended_dns_error"
#define DNSSD_XPC_RESULT_KEY_FLAGS						"flags"
#define DNSSD_XPC_RESULT_KEY_INTERFACE_INDEX			"interface_index"
#define DNSSD_XPC_RESULT_KEY_NEGATIVE_REASON			"negative_reason"
#define DNSSD_XPC_RESULT_KEY_PROVIDER_NAME				"provider_name"
#define DNSSD_XPC_RESULT_KEY_RECORD_CLASS				"rclass"
#define DNSSD_XPC_RESULT_KEY_RECORD_DATA				"rdata"
#define DNSSD_XPC_RESULT_KEY_RECORD_NAME				"rname"
#define DNSSD_XPC_RESULT_KEY_RECORD_PROTOCOL			"rprotocol"
#define DNSSD_XPC_RESULT_KEY_RECORD_TYPE				"rtype"
#define DNSSD_XPC_RESULT_KEY_TRACKER_HOSTNAME			"tracker_hostname"
#define DNSSD_XPC_RESULT_KEY_TRACKER_OWNER				"tracker_owner"
#define DNSSD_XPC_RESULT_KEY_TRACKER_APPROVED			"tracker_approved"
#define DNSSD_XPC_RESULT_KEY_TRACKER_CAN_BLOCK_REQUEST	"tracker_can_block_request"
#define DNSSD_XPC_RESULT_KEY_VALIDATION_DATA			"validation_data"

#define DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_CODE	"code"
#define DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_TEXT	"text"

//======================================================================================================================

DNSServiceErrorType
dnssd_xpc_result_get_error(xpc_object_t result, bool *out_valid)
{
	return mdns_xpc_dictionary_get_int32(result, DNSSD_XPC_RESULT_KEY_ERROR, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_error(xpc_object_t result, DNSServiceErrorType error)
{
	xpc_dictionary_set_int64(result, DNSSD_XPC_RESULT_KEY_ERROR, error);
}

//======================================================================================================================

DNSServiceFlags
dnssd_xpc_result_get_flags(xpc_object_t result, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint32(result, DNSSD_XPC_RESULT_KEY_FLAGS, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_flags(xpc_object_t result, DNSServiceFlags flags)
{
	xpc_dictionary_set_uint64(result, DNSSD_XPC_RESULT_KEY_FLAGS, flags);
}

//======================================================================================================================

uint32_t
dnssd_xpc_result_get_interface_index(xpc_object_t result, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint32(result, DNSSD_XPC_RESULT_KEY_INTERFACE_INDEX, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_interface_index(xpc_object_t result, uint32_t interface_index)
{
	xpc_dictionary_set_uint64(result, DNSSD_XPC_RESULT_KEY_INTERFACE_INDEX, interface_index);
}

//======================================================================================================================

uint16_t
dnssd_xpc_result_get_record_class(xpc_object_t result, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint16(result, DNSSD_XPC_RESULT_KEY_RECORD_CLASS, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_record_class(xpc_object_t result, uint16_t class)
{
	xpc_dictionary_set_uint64(result, DNSSD_XPC_RESULT_KEY_RECORD_CLASS, class);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_result_get_record_data_object(xpc_object_t result)
{
	return _dnssd_xpc_dictionary_get_value(result, DNSSD_XPC_RESULT_KEY_RECORD_DATA, XPC_TYPE_DATA);
}

//======================================================================================================================

void
dnssd_xpc_result_set_record_data(xpc_object_t result, const void * const data_ptr, const size_t data_len)
{
	if (data_ptr || (data_len == 0)) {
		const void * const safe_data_ptr = data_ptr ? data_ptr : "";
		xpc_dictionary_set_data(result, DNSSD_XPC_RESULT_KEY_RECORD_DATA, safe_data_ptr, data_len);
	}
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_result_get_record_name_object(xpc_object_t result)
{
	return _dnssd_xpc_dictionary_get_value(result, DNSSD_XPC_RESULT_KEY_RECORD_NAME, XPC_TYPE_STRING);
}

//======================================================================================================================

void
dnssd_xpc_result_set_record_name(xpc_object_t result, const char *name)
{
	xpc_dictionary_set_string(result, DNSSD_XPC_RESULT_KEY_RECORD_NAME, name);
}

//======================================================================================================================

uint16_t
dnssd_xpc_result_get_record_type(xpc_object_t result, bool *out_valid)
{
	return mdns_xpc_dictionary_get_uint16(result, DNSSD_XPC_RESULT_KEY_RECORD_TYPE, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_record_type(xpc_object_t result, uint16_t type)
{
	xpc_dictionary_set_uint64(result, DNSSD_XPC_RESULT_KEY_RECORD_TYPE, type);
}

//======================================================================================================================

uint16_t
dnssd_xpc_result_get_record_protocol(xpc_object_t result, bool * out_valid)
{
	return mdns_xpc_dictionary_get_uint16(result, DNSSD_XPC_RESULT_KEY_RECORD_PROTOCOL, out_valid);
}

//======================================================================================================================

void
dnssd_xpc_result_set_record_protocol(xpc_object_t result, uint16_t protocol)
{
	xpc_dictionary_set_uint64(result, DNSSD_XPC_RESULT_KEY_RECORD_PROTOCOL, protocol);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_result_get_provider_name_object(xpc_object_t result)
{
	return _dnssd_xpc_dictionary_get_value(result, DNSSD_XPC_RESULT_KEY_PROVIDER_NAME, XPC_TYPE_STRING);
}

//======================================================================================================================

void
dnssd_xpc_result_set_provider_name(const xpc_object_t result, const mdns_xpc_string_t name)
{
	xpc_dictionary_set_value(result, DNSSD_XPC_RESULT_KEY_PROVIDER_NAME, mdns_xpc_string_to_xpc_object(name));
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_result_get_cname_update(xpc_object_t result)
{
	return xpc_dictionary_get_array(result, DNSSD_XPC_RESULT_KEY_CNAME_UPDATE);
}

//======================================================================================================================

void
dnssd_xpc_result_set_cname_update(xpc_object_t result, xpc_object_t cname_update)
{
	xpc_dictionary_set_value(result, DNSSD_XPC_RESULT_KEY_CNAME_UPDATE, cname_update);
}

//======================================================================================================================

mdns_xpc_string_t
dnssd_xpc_result_get_tracker_hostname(const xpc_object_t result)
{
	return mdns_xpc_dictionary_get_string(result, DNSSD_XPC_RESULT_KEY_TRACKER_HOSTNAME);
}

//======================================================================================================================

void
dnssd_xpc_result_set_tracker_hostname(const xpc_object_t result, const mdns_xpc_string_t hostname)
{
	xpc_dictionary_set_value(result, DNSSD_XPC_RESULT_KEY_TRACKER_HOSTNAME, mdns_xpc_string_to_xpc_object(hostname));
}

//======================================================================================================================

mdns_xpc_string_t
dnssd_xpc_result_get_tracker_owner(const xpc_object_t result)
{
	return mdns_xpc_dictionary_get_string(result, DNSSD_XPC_RESULT_KEY_TRACKER_OWNER);
}

//======================================================================================================================

void
dnssd_xpc_result_set_tracker_owner(const xpc_object_t result, const mdns_xpc_string_t owner)
{
	xpc_dictionary_set_value(result, DNSSD_XPC_RESULT_KEY_TRACKER_OWNER, mdns_xpc_string_to_xpc_object(owner));
}

//======================================================================================================================

bool
dnssd_xpc_result_get_tracker_is_approved(const xpc_object_t result)
{
	return xpc_dictionary_get_bool(result, DNSSD_XPC_RESULT_KEY_TRACKER_APPROVED);
}

//======================================================================================================================

void
dnssd_xpc_result_set_tracker_is_approved(const xpc_object_t result, const bool approved)
{
	xpc_dictionary_set_bool(result, DNSSD_XPC_RESULT_KEY_TRACKER_APPROVED, approved);
}

//======================================================================================================================

bool
dnssd_xpc_result_get_tracker_can_block_request(const xpc_object_t result)
{
	return xpc_dictionary_get_bool(result, DNSSD_XPC_RESULT_KEY_TRACKER_CAN_BLOCK_REQUEST);
}

//======================================================================================================================

void
dnssd_xpc_result_set_tracker_can_block_request(const xpc_object_t result, const bool can_block)
{
	xpc_dictionary_set_bool(result, DNSSD_XPC_RESULT_KEY_TRACKER_CAN_BLOCK_REQUEST, can_block);
}

//======================================================================================================================

dnssd_negative_reason_t
dnssd_xpc_result_get_negative_reason(const xpc_object_t result)
{
	bool valid;
	// Make sure that dnssd_negative_reason_t is indeed a 32-bit signed integer.
	check_compile_time_code(sizeof(dnssd_negative_reason_t) == sizeof(int32_t));
	check_compile_time_code(((dnssd_negative_reason_t)-1) < 0);
	const dnssd_negative_reason_t reason = mdns_xpc_dictionary_get_int32(result,
		DNSSD_XPC_RESULT_KEY_NEGATIVE_REASON, &valid);
	if (valid) {
		// A default case isn't used to allow the compiler to catch missing dnssd_negative_reason_t enum values.
		switch (reason) {
			case dnssd_negative_reason_none:
			case dnssd_negative_reason_no_data:
			case dnssd_negative_reason_nxdomain:
			case dnssd_negative_reason_query_suppressed:
			case dnssd_negative_reason_no_dns_service:
			case dnssd_negative_reason_server_error:
				return reason;
		}
	}
	return dnssd_negative_reason_none;
}

//======================================================================================================================

void
dnssd_xpc_result_set_negative_reason(const xpc_object_t result, const dnssd_negative_reason_t reason)
{
	xpc_dictionary_set_int64(result, DNSSD_XPC_RESULT_KEY_NEGATIVE_REASON, reason);
}

//======================================================================================================================

xpc_object_t
dnssd_xpc_result_get_validation_data_object(const xpc_object_t result)
{
	return _dnssd_xpc_dictionary_get_value(result, DNSSD_XPC_RESULT_KEY_VALIDATION_DATA, XPC_TYPE_DATA);
}

//======================================================================================================================

void
dnssd_xpc_result_set_validation_data(const xpc_object_t result, const uint8_t * const data_ptr,
	const size_t data_len)
{
	xpc_dictionary_set_data(result, DNSSD_XPC_RESULT_KEY_VALIDATION_DATA, data_ptr, data_len);
}

//======================================================================================================================

mdns_xpc_dictionary_t
dnssd_xpc_result_get_extended_dns_error(const xpc_object_t result)
{
	return _dnssd_xpc_dictionary_get_value(result, DNSSD_XPC_RESULT_KEY_EXTENDED_DNS_ERROR, XPC_TYPE_DICTIONARY);
}

//======================================================================================================================

void
dnssd_xpc_result_set_extended_dns_error(const xpc_object_t result, const uint16_t code, const mdns_xpc_string_t text)
{
	mdns_xpc_dictionary_t ede = mdns_xpc_dictionary_create_empty();
	if (ede) {
		mdns_xpc_dictionary_set_uint16(ede, DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_CODE, code);
		if (mdns_xpc_string_get_length(text) != 0) {
			xpc_dictionary_set_value(ede, DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_TEXT, text);
		}
	}
	xpc_dictionary_set_value(result, DNSSD_XPC_RESULT_KEY_EXTENDED_DNS_ERROR, ede);
	xpc_forget(&ede);
}

//======================================================================================================================

uint16_t
dnssd_xpc_extended_dns_error_get_code(const mdns_xpc_dictionary_t ede, bool * const out_valid)
{
	return mdns_xpc_dictionary_get_uint16(ede, DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_CODE, out_valid);
}

//======================================================================================================================

mdns_xpc_string_t
dnssd_xpc_extended_dns_error_get_text(const mdns_xpc_dictionary_t ede)
{
	return mdns_xpc_dictionary_get_string(ede, DNSSD_XPC_EXTENDED_DNS_ERROR_KEY_TEXT);
}

//======================================================================================================================
// MARK: - XPC Dictionary Helpers

static xpc_object_t
_dnssd_xpc_dictionary_get_value(xpc_object_t dict, const char *key, xpc_type_t type)
{
	xpc_object_t value = xpc_dictionary_get_value(dict, key);
	return (value && (xpc_get_type(value) == type)) ? value : NULL;
}
