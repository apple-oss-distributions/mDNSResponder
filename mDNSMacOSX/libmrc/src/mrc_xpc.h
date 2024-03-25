/*
 * Copyright (c) 2020-2024 Apple Inc. All rights reserved.
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

#ifndef MRC_XPC_H
#define MRC_XPC_H

#include <mdns/base.h>

#include <MacTypes.h>
#include <mdns/xpc.h>
#include <xpc/xpc.h>

MDNS_ASSUME_NONNULL_BEGIN

/*!
 *	@brief
 *		mDNSResponder control Mach service name.
 */
extern const char * const g_mrc_mach_service_name;

/*!
 *	@brief
 *		DNS proxy start command string.
 */
extern const char * const g_mrc_command_dns_proxy_start;

/*!
 *	@brief
 *		DNS proxy stop command string.
 */
extern const char * const g_mrc_command_dns_proxy_stop;

/*!
 *	@brief
 *		DNS proxy get state command string.
 */
extern const char * const g_mrc_command_dns_proxy_get_state;

/*!
 *	@brief
 *		DNS service registration start command string.
 */
extern const char * const g_mrc_command_dns_service_registration_start;

/*!
 *	@brief
 *		DNS service registration stop command string.
 */
extern const char * const g_mrc_command_dns_service_registration_stop;

__BEGIN_DECLS

/*!
 *	@brief
 *		Gets the ID number from an XPC message.
 *
 *	@param msg
 *		The message.
 *
 *	@result
 *		The ID number, if present. Otherwise, 0.
 */
uint64_t
mrc_xpc_message_get_id(xpc_object_t msg);

/*!
 *	@brief
 *		Gets the command name from an XPC message as a C string.
 *
 *	@param msg
 *		The message.
 *
 *	@result
 *		The command, if present. Otherwise, NULL.
 */
const char * _Nullable
mrc_xpc_message_get_command(xpc_object_t msg);

/*!
 *	@brief
 *		Gets the parameters dictionary from an XPC message.
 *
 *	@param msg
 *		The message.
 *
 *	@result
 *		The parameters, if present. Otherwise, NULL.
 */
xpc_object_t _Nullable
mrc_xpc_message_get_params(xpc_object_t msg);

/*!
 *	@brief
 *		Gets the error code from an XPC message.
 *
 *	@param msg
 *		The message.
 *
 *	@param out_valid
 *		Variable to set to true if the error code value was properly set in the message. Otherwise, the variable
 *		is set to false.
 *
 *	@result
 *		The error code, if properly set. Otherwise, 0.
 */
OSStatus
mrc_xpc_message_get_error(xpc_object_t msg, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Gets the result dictionary from an XPC message.
 *
 *	@param msg
 *		The message.
 *
 *	@result
 *		The result dictionary, if present. Otherwise, NULL.
 */
mdns_xpc_dictionary_t _Nullable
mrc_xpc_message_get_result(xpc_object_t msg);

/*!
 *	@brief
 *		Creates an XPC reply message from a received XPC command message.
 *
 *	@param error
 *		The error code to set in the reply message.
 *
 *	@param result
 *		The command-specific result dictionary to set in the reply message.
 *
 *	@result
 *		A reference to the reply message.
 */
XPC_RETURNS_RETAINED
xpc_object_t _Nullable
mrc_xpc_create_reply(xpc_object_t msg, OSStatus error, mdns_xpc_dictionary_t _Nullable result);

/*!
 *	@brief
 *		Creates an XPC message for the DNS proxy start command.
 *
 *	@param ident
 *		An ID number that uniquely identifies the new DNS proxy to start.
 *
 *	@param params
 *		The DNS proxy start command's parameters dictionary.
 *
 *	@result
 *		A reference to the message.
 */
XPC_RETURNS_RETAINED
xpc_object_t
mrc_xpc_create_dns_proxy_start_command_message(uint64_t ident, xpc_object_t params);

/*!
 *	@brief
 *		Creates an XPC message for the DNS proxy stop command.
 *
 *	@param ident
 *		An ID number that identifies the DNS proxy to stop.
 *
 *	@result
 *		A reference to the message.
 *
 *	@discussion
 *		The ID number should match the ID number used in the DNS proxy start command message.
 */
XPC_RETURNS_RETAINED
xpc_object_t
mrc_xpc_create_dns_proxy_stop_command_message(uint64_t ident);

/*!
 *	@brief
 *		Creates an XPC message for the DNS proxy get state command.
 *
 *	@param ident
 *		An ID number that uniquely identifies the command.
 *
 *	@result
 *		A reference to the message.
 */
XPC_RETURNS_RETAINED
xpc_object_t
mrc_xpc_create_dns_proxy_get_state_command_message(uint64_t ident);

/*!
 *	@brief
 *		Adds an input interface index to a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 */
void
mrc_xpc_dns_proxy_params_add_input_interface(xpc_object_t params, uint32_t ifindex);

/*!
 *	@brief
 *		Gets the internal array containing the input interface indexes from a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@result
 *		The array if present. Otherwise, NULL.
 *
 *	@discussion
 *		This function exists for the convenience of code that implements the client or server side of the XPC
 *		communication. Unfortunately, there is currently no such thing as an immutable XPC array reference. The
 *		array returned by this function must not be directly modified. Also, references to the array must never
 *		be shared beyond such implementation code since that risks the possibility of modification by external
 *		code.
 */
xpc_object_t
mrc_xpc_dns_proxy_params_get_input_interfaces(xpc_object_t params);

/*!
 *	@brief
 *		Sets the output interface index in a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param ifindex
 *		The output interface index.
 */
void
mrc_xpc_dns_proxy_params_set_output_interface(xpc_object_t params, uint32_t ifindex);

/*!
 *	@brief
 *		Gets the output interface index from a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param out_valid
 *		Variable to set to true if the output interface index was properly set or is missing. Otherwise, the
 *		variable is set to false.
 *
 *	@result
 *		The output interface index if properly set. Otherwise, 0.
 *
 *	@discussion
 *		The default output interface index is 0.
 */
uint32_t
mrc_xpc_dns_proxy_params_get_output_interface(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Sets the NAT64 IPv6 prefix in a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param prefix
 *		A pointer to the prefix.
 *
 *	@param prefix_bit_length
 *		The bit length of the prefix. Values greater than 128 will be treated as 128.
 */
void
mrc_xpc_dns_proxy_params_set_nat64_prefix(xpc_object_t params, const uint8_t *prefix, size_t prefix_bit_length);

/*!
 *	@brief
 *		Gets the NAT64 IPv6 prefix from a DNS proxy parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param out_bitlen
 *		A variable to set to the prefix's bit length if the prefix is present.
 *
 *	@result
 *		The prefix if present. Otherwise, NULL.
 */
const uint8_t * _Nullable
mrc_xpc_dns_proxy_params_get_nat64_prefix(xpc_object_t params, size_t * _Nullable out_bitlen);

/*!
 *	@brief
 *		Sets the truth value of whether or not AAAA synthesis should be forced in a DNS proxy parameters
 *		dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param value
 *		The truth value.
 */
void
mrc_xpc_dns_proxy_params_set_force_aaaa_synthesis(xpc_object_t params, bool value);

/*!
 *	@brief
 *		Gets the truth value of whether or not AAAA synthesis should be forced from a DNS proxy parameters
 *		dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@result
 *		The truth value.
 *
 *	@discussion
 *		The default value is false.
 */
bool
mrc_xpc_dns_proxy_params_get_force_aaaa_synthesis(xpc_object_t params, bool * _Nullable out_valid);

/*!
 *	@brief
 *		Sets the description in a DNS proxy state result dictionary.
 *
 *	@param result
 *		The result dictionary.
 *
 *	@param description
 *		A C string that contains the human-readable description of the DNS proxy state.
 */
void
mrc_xpc_dns_proxy_state_result_set_description(mdns_xpc_dictionary_t result, const char *description);

/*!
 *	@brief
 *		Gets the description from a DNS proxy state result dictionary.
 *
 *	@param result
 *		The result dictionary.
 *
 *	@result
 *		The description if present. Otherwise, NULL.
 */
mdns_xpc_string_t _Nullable
mrc_xpc_dns_proxy_state_result_get_description(mdns_xpc_dictionary_t result);

/*!
 *	@brief
 *		Creates an XPC message for the DNS service registration start command.
 *
 *	@param ident
 *		An ID number that uniquely identifies the new DNS service registration to start.
 *
 *	@param params
 *		The DNS service registration start command's parameters dictionary.
 *
 *	@result
 *		A reference to the message.
 */
XPC_RETURNS_RETAINED
xpc_object_t
mrc_xpc_create_dns_service_registration_start_command_message(uint64_t ident, xpc_object_t params);

/*!
 *	@brief
 *		Creates an XPC message for the DNS service registration stop command.
 *
 *	@param ident
 *		An ID number that identifies the DNS service registration to stop.
 *
 *	@result
 *		A reference to the message.
 *
 *	@discussion
 *		The ID number should match the ID number used in the DNS service registration start command message.
 */
XPC_RETURNS_RETAINED
xpc_object_t
mrc_xpc_create_dns_service_registration_stop_command_message(uint64_t ident);

/*!
 *	@brief
 *		Sets the DNS service definition dictionary in a DNS service registration parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@param dict
 *		The DNS service definition dictionary which should be created with
 *		mdns_dns_service_definition_create_xpc_dictionary().
 */
void
mrc_xpc_dns_service_registration_params_set_defintion_dictionary(xpc_object_t params, xpc_object_t dict);

/*!
 *	@brief
 *		Gets the DNS service definition dictionary from a DNS service registration parameters dictionary.
 *
 *	@param params
 *		The parameters dictionary.
 *
 *	@result
 *		The DNS service definition dictionary, if present. Otherwise, NULL.
 *
 *	@discussion
 *		The resulting DNS service definition dictionary is meant to be passed to
 *		mdns_dns_service_definition_create_from_xpc_dictionary() to create a DNS service definition.
 */
mdns_xpc_dictionary_t _Nullable
mrc_xpc_dns_service_registration_params_get_defintion_dictionary(xpc_object_t params);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_XPC_H
