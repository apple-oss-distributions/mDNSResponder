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

#ifndef MRCS_DNS_PROXY_H
#define MRCS_DNS_PROXY_H

#include "mrcs_object.h"

#include <MacTypes.h>
#include <mdns/base.h>
#include <nw/private.h>

MRCS_DECL(dns_proxy);
MRCS_DECL(dns_proxy_manager);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a DNS proxy object to represent an instance of a DNS proxy.
 *
 *	@param out_error
 *		A variable to set to either kNoErr if creation succeeds, or a non-zero error code if creation fails.
 *
 *	@result
 *		A reference to the new DNS proxy object, or NULL if creation failed.
 *
 *	@discussion
 *		If not using Objective-C ARC, use mrcs_retain() and mrcs_release() to retain and release references to
 *		the object.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrcs_dns_proxy_t _Nullable
mrcs_dns_proxy_create(OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Adds an input interface to a DNS proxy.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param ifindex
 *		The input interface's index.
 *
 *	@discussion
 *		This function can be called more than once to specify a set of multiple input interfaces.
 */
OSStatus
mrcs_dns_proxy_add_input_interface(mrcs_dns_proxy_t proxy, uint32_t ifindex);

/*!
 *	@brief
 *		Sets a DNS proxy's output interface.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param ifindex
 *		The output interface's index.
 *
 *	@discussion
 *		By default, the output interface index is 0, which means that the remote DNS proxy instance will use the
 *		most suitable interface for its DNS network traffic.
 */
void
mrcs_dns_proxy_set_output_interface(mrcs_dns_proxy_t proxy, uint32_t ifindex);

/*!
 *	@brief
 *		Sets a DNS proxy's NAT64 IPv6 prefix.
 *
 *	@param proxy
 *		The parameters.
 *
 *	@param prefix
 *		A pointer to the prefix.
 *
 *	@param prefix_bit_length
 *		The bit length of the prefix.
 *
 *	@result
 *		kNoErr if the NAT64 prefix was successfully set. Otherwise, a non-zero error code indicating why it
 *		wasn't set.
 *
 *	@discussion
 *		If a NAT64 prefix is set, then the DNS proxy instance will carry out DNS64 functionality using the
 *		specified NAT64 prefix. If not set, then no DNS64 functionality will be performed.
 */
OSStatus
mrcs_dns_proxy_set_nat64_prefix(mrcs_dns_proxy_t proxy, const uint8_t *prefix, size_t prefix_bit_length);

/*!
 *	@brief
 *		Enables a DNS proxy's option to force AAAA synthesis when performing DNS64 functionality.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param enable
 *		Pass true to enable the option. Pass false to disable the option.
 *
 *	@discussion
 *		This option is disabled by default and only applies when the DNS proxy's DNS64 functionality is enabled
 *		by specifying a NAT64 prefix.
 */
void
mrcs_dns_proxy_enable_force_aaaa_synthesis(mrcs_dns_proxy_t proxy, bool enable);

/*!
 *	@brief
 *		Sets a DNS proxy's effective user ID.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param euid
 *		The effective user ID.
 *
 *	@discussion
 *		Any policy decisions that need to be made for a DNS proxy's query that take a user ID into account, such
 *		as path evaluation, will use the DNS proxy's effective user ID.
 */
void
mrcs_dns_proxy_set_euid(mrcs_dns_proxy_t proxy, uid_t euid);

/*!
 *	@brief
 *		Determines whether a DNS proxy contains an input interface.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param ifindex
 *		The intput interface's index.
 *
 *	@result
 *		The truth value.
 */
bool
mrcs_dns_proxy_contains_input_interface(mrcs_dns_proxy_t proxy, uint32_t ifindex);

/*!
 *	@brief
 *		Gets a DNS proxy's output interface index.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		The output interface index.
 *
 *	@discussion
 *		By default, the output interface index is 0, which means that the DNS proxy instance will use the most
 *		suitable interface for its DNS network traffic.
 */
uint32_t
mrcs_dns_proxy_get_output_interface(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Gets a DNS proxy's NAT64 prefix.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		The NAT64 prefix if the DNS proxy has one. Otherwise, NULL.
 *
 *	@discussion
 *		The NAT64 prefix returned by this function is valid for the lifetime of the DNS proxy object and is
 *		guaranteed to not change until the next successful call to mrcs_dns_proxy_set_nat64_prefix().
 */
const nw_nat64_prefix_t * _Nullable
mrcs_dns_proxy_get_nat64_prefix(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Determines whether a DNS proxy forces AAAA synthesis when performing DNS64 functionality.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		The truth value.
 */
bool
mrcs_dns_proxy_forces_aaaa_synthesis(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Gets a DNS proxy's effective user ID.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		The effective user ID.
 */
uid_t
mrcs_dns_proxy_get_euid(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Creates a DNS proxy manager which can be uses to contain DNS proxy objects.
 *
 *	@param out_error
 *		A variable to set to either kNoErr if creation succeeds, or a non-zero error code if creation fails.
 *
 *	@result
 *		A reference to the new DNS proxy manager, or NULL if creation failed.
 *
 *	@discussion
 *		If not using Objective-C ARC, use mrcs_retain() and mrcs_release() to retain and release references to
 *		the object.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrcs_dns_proxy_manager_t _Nullable
mrcs_dns_proxy_manager_create(OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Adds a DNS proxy to a DNS proxy manager if it doesn't conflict with its current set of DNS proxies.
 *
 *	@param manager
 *		The DNS proxy manager.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		kNoErr if the DNS proxy was added. Otherwise, a non-zero error code if there was a conflict.
 *
 *	@discussion
 *		The DNS proxy manager will retain a reference to each DNS proxy that it successfully adds.
 *
 *		A DNS proxy is considered to conflict with another DNS proxy if they have at least one input interface
 *		in common and either their output interfaces don't match or their output interfaces do match, but their
 *		DNS64 settings do not.
 */
OSStatus
mrcs_dns_proxy_manager_add_proxy(mrcs_dns_proxy_manager_t manager, mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Removes a DNS proxy from a DNS proxy manager.
 *
 *	@param manager
 *		The DNS proxy manager.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@result
 *		kNoErr if the DNS proxy was successfully removed. Otherwise, a non-zero error code if the DNS proxy was
 *		not contained by the DNS proxy manager.
 *
 *	@discussion
 *		The DNS proxy manager will release its reference to each DNS proxy that gets removed.
 */
OSStatus
mrcs_dns_proxy_manager_remove_proxy(mrcs_dns_proxy_manager_t manager, mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		Gets the number of DNS proxies contained by a DNS proxy manager.
 *
 *	@param manager
 *		The DNS proxy manager.
 *
 *	@result
 *		The number or DNS proxies.
 */
size_t
mrcs_dns_proxy_manager_get_count(mrcs_dns_proxy_manager_t manager);

/*!
 *	@brief
 *		Gets a DNS proxy that contains the specified input interface from a DNS proxy manager if such a DNS
 *		proxy exists.
 *
 *	@param manager
 *		The DNS proxy manager.
 *
 *	@param ifindex
 *		The input interface's index.
 *
 *	@result
 *		The DNS proxy if such a DNS proxy exists. Otherwise, NULL.
 */
mrcs_dns_proxy_t _Nullable
mrcs_dns_proxy_manager_get_proxy_by_input_interface(mrcs_dns_proxy_manager_t manager, uint32_t ifindex);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRCS_DNS_PROXY_H
