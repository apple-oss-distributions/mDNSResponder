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

#ifndef __DNSSD_XPC_H__
#define __DNSSD_XPC_H__

#include "dnssd_private.h"

#include <CoreUtils/CommonServices.h>
#include <dns_sd.h>
#include <mdns/xpc.h>
#include <xpc/xpc.h>

#define DNSSD_MACH_SERVICE_NAME	"com.apple.dnssd.service"

#define DNSSD_COMMAND_GETADDRINFO	"getaddrinfo"
#define DNSSD_COMMAND_KEEPALIVE		"keepalive"
#define DNSSD_COMMAND_STOP			"stop"

CU_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Gets command as a C string from XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@result
 *		Command, if present. Otherwise, NULL.
 */
const char * _Nullable
dnssd_xpc_message_get_command(xpc_object_t msg);

/*!
 *	@brief
 *		Gets error code from XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Error code, if present. Otherwise, 0.
 */
DNSServiceErrorType
dnssd_xpc_message_get_error(xpc_object_t msg, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets command instance ID from XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		ID, if present. Otherwise, 0.
 */
uint64_t
dnssd_xpc_message_get_id(xpc_object_t msg, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets command parameter dictionary from XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@result
 *		Command parameter dictionary, if present. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_message_get_parameters(xpc_object_t msg);

/*!
 *	@brief
 *		Gets result array from XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@result
 *		Result array, if present. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_message_get_results(xpc_object_t msg);

/*!
 *	@brief
 *		Sets command in XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param command
 *		Command as a C string.
 */
void
dnssd_xpc_message_set_command(xpc_object_t msg, const char *command);

/*!
 *	@brief
 *		Sets error code in XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param error
 *		Error code.
 */
void
dnssd_xpc_message_set_error(xpc_object_t msg, DNSServiceErrorType error);

/*!
 *	@brief
 *		Sets command instance ID in XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param ident
 *		Command instance ID.
 */
void
dnssd_xpc_message_set_id(xpc_object_t msg, uint64_t ident);

/*!
 *	@brief
 *		Sets command parameters dictionary in XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param params
 *		Command parameters dictionary.
 */
void
dnssd_xpc_message_set_parameters(xpc_object_t msg, xpc_object_t params);

/*!
 *	@brief
 *		Sets command result array in XPC message.
 *
 *	@param msg
 *		XPC message.
 *
 *	@param results
 *		Command result array.
 */
void
dnssd_xpc_message_set_results(xpc_object_t msg, xpc_object_t results);

/*!
 *	@brief
 *		Gets delegate ID as a PID from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Delegate ID as PID, if present. Otherwise, 0.
 */
pid_t
dnssd_xpc_parameters_get_delegate_pid(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets delegate ID as a UUID from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		Delegate ID as UUID, if present. Otherwise, NULL.
 */
const uint8_t * _Nullable
dnssd_xpc_parameters_get_delegate_uuid(xpc_object_t params);

/*!
 *	@brief
 *		Gets a delegate audit token from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param audit_token_storage
 *		Pointer to an audit token to overwrite with parameters dictionary's delegate audit token data.
 *
 *	@result
 *		If the parameters dictionary contains a delegate audit token, this function copies it to
 *		audit_token_storage and returns audit_token_storage. Otherwise, it returns NULL.
 */
audit_token_t * _Nullable
dnssd_xpc_parameters_get_delegate_audit_token(xpc_object_t params, audit_token_t *audit_token_storage);

/*!
 *	@brief
 *		Gets flags from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Flags, if present. Otherwise, 0.
 */
DNSServiceFlags
dnssd_xpc_parameters_get_flags(xpc_object_t params, bool * _Nullable out_valid);

/*!
*	@brief
*		Gets account id from a command parameters dictionary.
*
*	@param params
*		Command parameters dictionary.
*
*	@result
*		Account, if present, as a const char *. Otherwise, NULL.
*/
const char * _Nullable
dnssd_xpc_parameters_get_account_id(xpc_object_t params);

/*!
 *	@brief
 *		Gets hostname from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		Hostname, if present, as an XPC string object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_parameters_get_hostname_object(xpc_object_t params);

/*!
 *	@brief
 *		Gets the hostname from a command parameters dictionary as a C string.
 *
 *	@param params
 *		The command parameters dictionary.
 *
 *	@result
 *		The hostname, if present, as C string. Otherwise, NULL.
 */
const char * _Nullable
dnssd_xpc_parameters_get_hostname(xpc_object_t params);

/*!
 *	@brief
 *		Gets interface index from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Interface index, if present. Otherwise, 0.
 */
uint32_t
dnssd_xpc_parameters_get_interface_index(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets need encryption boolean value from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		A boolean value.
 */
bool
dnssd_xpc_parameters_get_need_encrypted_query(xpc_object_t params);

/*!
 *	@brief
 *		Gets fallback resolver configuration dictionary from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		A dictionary containing resolver configuration to use in the absence of encrypted resolvers, or NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_parameters_get_fallback_config(xpc_object_t params);

/*!
 *	@brief
 *		Gets resolver UUID array from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		An array of UUIDs, or NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_parameters_get_resolver_uuid_array(xpc_object_t params);

/*!
 *	@brief
 *		Gets protocols from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Protocols, if present. Otherwise, 0.
 */
DNSServiceProtocol
dnssd_xpc_parameters_get_protocols(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets the service scheme from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		A string containing service scheme for the query, or NULL.
 */
const char * _Nullable
dnssd_xpc_parameters_get_service_scheme(xpc_object_t params);

/*!
 *	@brief
 *		Gets the truth value of whether DNS service failover should be used from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		True if DNS service failover should be used. Otherwise, false.
 */
bool
dnssd_xpc_parameters_get_use_failover(xpc_object_t params);

/*!
 *	@brief
 *		Gets the enum value of whether or not the private level logs and the content of state dump should be redacted,
 *		from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		The log privacy level.
 */
dnssd_log_privacy_level_t
dnssd_xpc_parameters_get_log_privacy_level(xpc_object_t params);

/*!
 *	@brief
 *		Gets the validation data from a command parameters dictionary
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param out_length
 *		Gets set to the length of the validation data.
 *
 *	@discussion
 *		The returned pointer, if non-NULL, is valid until the getaddrinfo result is released.
 */
const uint8_t * _Nullable
dnssd_xpc_parameters_get_validation_data(xpc_object_t params, size_t * _Nullable out_length);

/*!
 *	@brief
 *		Determines whether a command parameters dictionary specifies that use of encrypted DNS protocols is
 *		prohibited for the associated command.
 *
 *	@param params
 *		The command parameters dictionary.
 *
 *	@result
 *		True if use of encrypted DNS protocols is prohibited. Otherwise, false.
 */
bool
dnssd_xpc_parameters_get_prohibit_encrypted_dns(xpc_object_t params);

/*!
 *	@brief
 *		Sets delegate ID as a PID in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param pid
 *		PID.
 */
void
dnssd_xpc_parameters_set_delegate_pid(xpc_object_t params, pid_t pid);

/*!
 *	@brief
 *		Sets delegate ID as a UUID in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param uuid
 *		UUID.
 */
void
dnssd_xpc_parameters_set_delegate_uuid(xpc_object_t params, uuid_t _Nonnull uuid);

/*!
 *	@brief
 *		Sets the delegate audit token in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param audit_token
 *		The delegate audit token.
 */
void
dnssd_xpc_parameters_set_delegate_audit_token(xpc_object_t params, const audit_token_t *audit_token);

/*!
 *	@brief
 *		Sets flags in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param flags
 *		Flags.
 */
void
dnssd_xpc_parameters_set_flags(xpc_object_t params, DNSServiceFlags flags);

/*!
*	@brief
*		Sets account id in a command parameters dictionary.
*
*	@param params
*		Command parameters dictionary.
*
*	@param account_id
*		Account id.
*/
void
dnssd_xpc_parameters_set_account_id(xpc_object_t params, const char *account_id);

/*!
 *	@brief
 *		Sets hostname in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param hostname
 *		Hostname.
 */
void
dnssd_xpc_parameters_set_hostname(xpc_object_t params, const char *hostname);

/*!
 *	@brief
 *		Sets interface index in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param interface_index
 *		Interface index.
 */
void
dnssd_xpc_parameters_set_interface_index(xpc_object_t params, uint32_t interface_index);

/*!
 *	@brief
 *		Specifies whether or not queries must use encrypted transports to the next DNS server.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param need
 *		Pass <code>true</code> if encrypted queries are required, otherwise, pass <code>false</code>.
 *
 *	@param fallback_config
 *		If not NULL, specify a custom resolver configuration to use if no encrypted resolver configuation is otherwise
 *		available.
 */
void
dnssd_xpc_parameters_set_need_encrypted_query(xpc_object_t params, bool need, _Nullable xpc_object_t fallback_config);

/*!
 *	@brief
 *		Add a resolver UUID that represents a resolver configuration registered with the system that should
 *		be applied to this resolution. Multiple UUIDs can be set.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param uuid
 *		UUID of a resolver configuration registered with the system.
 */
void
dnssd_xpc_parameters_add_resolver_uuid(xpc_object_t params, uuid_t _Nonnull uuid);

/*!
 *	@brief
 *		Sets a service scheme in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param service_scheme
 *		Service scheme.
 */
void
dnssd_xpc_parameters_set_service_scheme(xpc_object_t params, const char *service_scheme);

/*!
 *	@brief
 *		Sets protocols in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param protocols
 *		Protocols.
 */
void
dnssd_xpc_parameters_set_protocols(xpc_object_t params, DNSServiceProtocol protocols);

/*!
 *	@brief
 *		Specifies in a command parameters dictionary whether or not DNS service failover should be used if
 *		necessary and applicable.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param use_failover
 *		Pass true if DNS service failover should be used, otherwise, pass false.
 */
void
dnssd_xpc_parameters_set_use_failover(xpc_object_t params, bool use_failover);

/*!
 *	@brief
 *		Specifies the log privacy level in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param level
 *		The log privacy level.
 */
void
dnssd_xpc_parameters_set_log_privacy_level(xpc_object_t params, dnssd_log_privacy_level_t level);

/*!
 *	@brief
 *		Sets the validation data in a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param data_ptr
 *		Pointer to the validation data.
 *
 *	@param data_len
 *		Length of the validation data.
 */
void
dnssd_xpc_parameters_set_validation_data(xpc_object_t params, const uint8_t *data_ptr, size_t data_len);

/*!
 *	@brief
 *		Specifies in a command parameters dictionary whether use of encrypted DNS protocols is prohibited for
 *		the associated command.
 *
 *	@param params
 *		The command parameters dictionary.
 *
 *	@param prohibit
 *		If use of encrypted DNS protocols is prohibited, pass true. Otherwise, pass false.
 *
 *	@discussion
 *		By default, use of encrypted DNS protocols is not prohibited.
 */
void
dnssd_xpc_parameters_set_prohibit_encrypted_dns(xpc_object_t params, bool prohibit);

/*!
 *	@brief
 *		Gets error code from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Error code, if present. Otherwise, 0.
 */
DNSServiceErrorType
dnssd_xpc_result_get_error(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets flags from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Flags, if present. Otherwise, 0.
 */
DNSServiceFlags
dnssd_xpc_result_get_flags(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets interface index from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Interface index, if present. Otherwise, 0.
 */
uint32_t
dnssd_xpc_result_get_interface_index(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets record class from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Record class, if present. Otherwise, 0.
 */
uint16_t
dnssd_xpc_result_get_record_class(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets record data from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		Record data, if present, as an XPC data object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_record_data_object(xpc_object_t result);

/*!
 *	@brief
 *		Gets record name from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		Record name, if present, as an XPC string object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_record_name_object(xpc_object_t result);

/*!
* @brief
*      Gets record canonical name from a command result dictionary.
*
*  @param result
*      The command result dictionary.
*
*  @result
*      Record canonical name, if present, as an XPC string object. Otherwise, NULL.
*/
xpc_object_t _Nullable
dnssd_xpc_result_get_record_cname_object(xpc_object_t result);

/*!
 *	@brief
 *		Gets record type from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Record type, if present. Otherwise, 0.
 */
uint16_t
dnssd_xpc_result_get_record_type(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets used record protocol from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Used record protocol, if present. Otherwise, 0.
 */
uint16_t
dnssd_xpc_result_get_record_protocol(xpc_object_t result, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets provider name from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		Provider name, if present, as an XPC string object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_provider_name_object(xpc_object_t result);

/*!
 *	@brief
 *		Gets canonical name updates from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		The canonical name update, if present, as an XPC array object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_cname_update(xpc_object_t result);

/*!
 *	@brief
 *		Gets the verified tracker hostname in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		The tracker hostname, if present, as an XPC string. Otherwise, NULL.
 *
 * @discussion
 *		No tracker hostname means that the result is not associated with a known tracker.
 */
mdns_xpc_string_t _Nullable
dnssd_xpc_result_get_tracker_hostname(xpc_object_t result);

/*!
 *	@brief
 *		Gets the tracker owner in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		The tracker owner, if present, as an XPC string. Otherwise, NULL.
 */
mdns_xpc_string_t _Nullable
dnssd_xpc_result_get_tracker_owner(xpc_object_t result);

/*!
 *	@brief
 *		Gets whether or not the tracker is an approved app domain.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		A boolean indiciating if the domain is approved for the app.
 */
bool
dnssd_xpc_result_get_tracker_is_approved(xpc_object_t result);

/*!
 *	@brief
 *		Gets whether or not we can block requests to this tracker.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		A boolean indicating whether we can block requests to this tracker.
 */
bool
dnssd_xpc_result_get_tracker_can_block_request(xpc_object_t result);

/*!
 *	@brief
 *		Gets the reason why a result is negative from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		The negative reason, if present. Otherwise, dnssd_negative_reason_none.
 */
dnssd_negative_reason_t
dnssd_xpc_result_get_negative_reason(xpc_object_t result);

/*!
 *	@brief
 *		Gets validation data from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		Validation data, if present, as an XPC data object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_validation_data_object(xpc_object_t result);

/*!
 *	@brief
 *		Gets the Extended DNS Error dictionary from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 * 	@result
 *		An Extended DNS Error dictionary, if present. Otherwise, NULL.
 */
mdns_xpc_dictionary_t _Nullable
dnssd_xpc_result_get_extended_dns_error(xpc_object_t result);

/*!
 *	@brief
 *		Sets the error code in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param error
 *		Error code.
 */
void
dnssd_xpc_result_set_error(xpc_object_t result, DNSServiceErrorType error);

/*!
 *	@brief
 *		Sets flags in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param flags
 *		Flags.
 */
void
dnssd_xpc_result_set_flags(xpc_object_t result, DNSServiceFlags flags);

/*!
 *	@brief
 *		Sets interface index in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param interface_index
 *		Interface index.
 */
void
dnssd_xpc_result_set_interface_index(xpc_object_t result, uint32_t interface_index);

/*!
 *	@brief
 *		Sets record class in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param class
 *		Record class.
 */
void
dnssd_xpc_result_set_record_class(xpc_object_t result, uint16_t class);

/*!
 *	@brief
 *		Sets the record data in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param data_ptr
 *		Pointer to the record data.
 *
 *	@param data_len
 *		Length of the record data.
 */
void
dnssd_xpc_result_set_record_data(xpc_object_t result, const void * _Nullable data_ptr, size_t data_len);

/*!
 *	@brief
 *		Sets record name in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param name
 *		Record name.
 */
void
dnssd_xpc_result_set_record_name(xpc_object_t result, const char *name);

/*!
* @brief
*      Sets record canonical name in a command result dictionary.
*
*  @param result
*      The command result dictionary.
*
*  @param cname
*      Record canonical name.
*/
void
dnssd_xpc_result_set_record_cname(xpc_object_t result, const char *cname);

/*!
 *	@brief
 *		Sets record type in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param type
 *		Record type.
 */
void
dnssd_xpc_result_set_record_type(xpc_object_t result, uint16_t type);

/*!
 *	@brief
 *		Sets record protocol in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param protocol
 *		Record protocol.
 */
void
dnssd_xpc_result_set_record_protocol(xpc_object_t result, uint16_t protocol);

/*!
 *	@brief
 *		Sets the DNS provider name in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param provider_name
 *		DNS provider name.
 */
void
dnssd_xpc_result_set_provider_name(xpc_object_t result, mdns_xpc_string_t provider_name);

/*!
 *	@brief
 *		Sets a canonical name update in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param cname_update
 *		The canonical name update as an array of canonical names as strings.
 */
void
dnssd_xpc_result_set_cname_update(xpc_object_t result, xpc_object_t cname_update);

/*!
 *	@brief
 *		Sets the tracker hostname in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param hostname
 *		The hostname that was verified.
 */
void
dnssd_xpc_result_set_tracker_hostname(xpc_object_t result, mdns_xpc_string_t hostname);

/*!
 *	@brief
 *		Sets the tracker owner in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param owner
 *		The tracker owner.
 */
void
dnssd_xpc_result_set_tracker_owner(xpc_object_t result, mdns_xpc_string_t owner);

/*!
 *	@brief
 *		Sets whether or not the tracker is an approved app domain.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param approved
 *		A boolean indiciating if the domain is approved for the app.
 */
void
dnssd_xpc_result_set_tracker_is_approved(xpc_object_t result, bool approved);

/*!
 *	@brief
 *		Sets whether or not we can safely block requests to this tracker.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param can_block
 *		A boolean indicating if we can block requests to this tracker.
 */
void
dnssd_xpc_result_set_tracker_can_block_request(xpc_object_t result, bool can_block);

/*!
 *	@brief
 *		Sets the reason why a result is negative in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param reason
 *		The negative reason.
 */
void
dnssd_xpc_result_set_negative_reason(xpc_object_t result, dnssd_negative_reason_t reason);

/*!
 *	@brief
 *		Sets the validation data in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param data_ptr
 *		Pointer to the validation data.
 *
 *	@param data_len
 *		Length of the validation data.
 */
void
dnssd_xpc_result_set_validation_data(xpc_object_t result, const uint8_t *data_ptr, size_t data_len);

/*!
 *	@brief
 *		Sets the Extended DNS Error code and text in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param code
 *		The Extended DNS Error code.
 *
 *	@param extra_text
 *		The Extended DNS Error code extra text.
 */
void
dnssd_xpc_result_set_extended_dns_error(xpc_object_t result, uint16_t code, mdns_xpc_string_t extra_text);

/*!
 *	@brief
 *		Gets the Extended DNS Error code from a dictionary.
 *
 *	@param ede
 *		An Extended DNS Error dictionary.
 *
 *	@param out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		The Extended DNS Error code, if valid, otherwise 0.
 */
uint16_t
dnssd_xpc_extended_dns_error_get_code(mdns_xpc_dictionary_t ede, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets the Extended DNS Error extra text from a dictionary.
 *
 *	@param ede
 *		An Extended DNS Error dictionary.
 *
 *	@result
 *		The Extended DNS Error extra text, if valid, otherwise NULL.
 */
mdns_xpc_string_t
dnssd_xpc_extended_dns_error_get_text(mdns_xpc_dictionary_t ede);

__END_DECLS

CU_ASSUME_NONNULL_END

#endif	// __DNSSD_XPC_H__
