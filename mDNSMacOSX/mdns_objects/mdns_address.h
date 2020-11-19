/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef __MDNS_ADDRESS_H__
#define __MDNS_ADDRESS_H__

#include "mdns_base.h"

#include <stdint.h>

MDNS_DECL(address);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates an address object that represents an IPv4 address and port number.
 *
 *	@param addr
 *		The IPv4 address as an unsigned 32-bit integer in host byte order.
 *
 *	@param port
 *		The port number in host byte order.
 *
 *	@result
 *		An address object or NULL if the system was out of memory.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT _Nullable
mdns_address_t
mdns_address_create_ipv4(uint32_t addr, uint16_t port);

/*!
 *	@brief
 *		Creates an address object that represents an IPv6 address and port number.
 *
 *	@param addr
 *		The IPv6 address as an array of octets in network byte order.
 *
 *	@param port
 *		The port number in host byte order.
 *
 *	@param scope_id
 *		The scope ID.
 *
 *	@result
 *		An address object or NULL if the system was out of memory.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT _Nullable
mdns_address_t
mdns_address_create_ipv6(const uint8_t addr[static 16], uint16_t port, uint32_t scope_id);

/*!
 *	@brief
 *		Creates an address object that represents the IPv4 or IPv6 address and optional port number specified by a
 *		string.
 *
 *	@param ip_addr_str
 *		The textual representation of the IPv4 or IPv6 address and optional port number as an ASCII C string.
 *
 *	@result
 *		An address object or NULL if the system was out of memory.
 *
 *	@discussion
 *		IPv4 addresses must be in dot-decimal notation, e.g., "192.0.2.1". A port can be specified for an IPv4 address
 *		by appending a ':' character followed by the port number in decimal notation, e.g., "192.0.2.1:443".
 *
 *		IPv6 addresses must be in any of the three conventional forms described by
 *		<https://tools.ietf.org/html/rfc3513#section-2.2>. For example, "2001:0db8:0000:0000:0000:0000:0000:0001",
 *		"2001:db8::1", or "::ffff:192.0.2.1".
 *
 *		A port can be specified for an IPv6 address by enclosing the IPv6 address's textual representation in square
 *		brackets, then appending a ':' character followed by the port number in decimal notation. For example,
 *		"[2001:db8::1]:443".
 *
 *		If a port is not specified, a port number of zero is assumed.
 */
MDNS_RETURNS_RETAINED mdns_address_t _Nullable
mdns_address_create_from_ip_address_string(const char *ip_addr_str);

/*!
 *	@brief
 *		Return a pointer to a sockaddr structure that represents an address object's IPv4 or IPv6 address and port.
 *
 *	@param address
 *		The address object.
 *
 *	@result
 *		A pointer to a sockaddr structure.
 *
 *	@discussion
 *		The pointer returned by this function can be safely cast to a pointer to a sockaddr_in structure if the value
 *		of the sockaddr structure's sa_family member variable is AF_INET, which is the case for IPv4 addresses.
 *
 *		Likewise, the pointer can be safely cast to a pointer to a sockaddr_in6 structure if the value of the sockaddr
 *		structure's sa_family member variable is AF_INET6, which is the case for IPv6 addresses.
 */
const struct sockaddr *
mdns_address_get_sockaddr(mdns_address_t address);

/*!
 *	@brief
 *		Returns an address's port number.
 *
 *	@param address
 *		The address.
 */
uint16_t
mdns_address_get_port(mdns_address_t address);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_ADDRESS_H__
