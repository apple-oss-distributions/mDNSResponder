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

#ifndef __DNSSD_XPC_H__
#define __DNSSD_XPC_H__

#include <CoreUtils/CommonServices.h>
#include <dns_sd.h>
#include <xpc/xpc.h>

#define DNSSD_MACH_SERVICE_NAME	"com.apple.dnssd.service"

#define DNSSD_COMMAND_GETADDRINFO	"getaddrinfo"
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
 *		Gets interface index from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@para out_valid
 *		If non-NULL, set to true if value is present and of correct type, otherwise, set to false.
 *
 *	@result
 *		Interface index, if present. Otherwise, 0.
 */
uint32_t
dnssd_xpc_parameters_get_interface_index(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets need_auth_tags boolean value from a command parameters dictionary.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@result
 *		A boolean value.
 */
bool
dnssd_xpc_parameters_get_need_authentication_tags(xpc_object_t params);

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
 *		Sets whether mDNSResponder should include an authentication tag for each hostname resolution.
 *
 *	@param params
 *		Command parameters dictionary.
 *
 *	@param need
 *		Pass <code>true</code> to enable this behavior. Pass <code>false</code> to disable it.
 */
void
dnssd_xpc_parameters_set_need_authentication_tags(xpc_object_t params, bool need);

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
 *		Gets authentication tag from a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@result
 *		Authentication tag, if present, as an XPC data object. Otherwise, NULL.
 */
xpc_object_t _Nullable
dnssd_xpc_result_get_authentication_tag_object(xpc_object_t result);

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
 *		Sets the authentication tag in a command result dictionary.
 *
 *	@param result
 *		The command result dictionary.
 *
 *	@param auth_tag_ptr
 *		Pointer to the authentication tag.
 *
 *	@param auth_tag_len
 *		Length of the authentication tag.
 */
void
dnssd_xpc_result_set_authentication_tag(xpc_object_t result, const void *auth_tag_ptr, size_t auth_tag_len);

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
dnssd_xpc_result_set_provider_name(xpc_object_t result, const char *provider_name);

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

__END_DECLS

CU_ASSUME_NONNULL_END

#endif	// __DNSSD_XPC_H__
