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

#include "mdns_address.h"

#include "mdns_helpers.h"
#include "mdns_internal.h"
#include "mdns_objects.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Address Kind Definition

struct mdns_address_s {
	struct mdns_object_s	base;		// Object base.
	sockaddr_ip				sip;		// Underlying sockaddr structure.
	char *					if_name;	// Interface name of IPv6 scope ID.
};

MDNS_OBJECT_SUBKIND_DEFINE_FULL(address);

//======================================================================================================================
// MARK: - Internals

MDNS_LOG_CATEGORY_DEFINE(address, "address");

//======================================================================================================================
// MARK: - Address Public Methods

mdns_address_t
mdns_address_create_ipv4(uint32_t addr, uint16_t port)
{
	mdns_address_t obj = _mdns_address_alloc();
	require_quiet(obj, exit);

	struct sockaddr_in * const sa = &obj->sip.v4;
	SIN_LEN_SET(sa);
	sa->sin_family		= AF_INET;
	sa->sin_port		= htons(port);
	sa->sin_addr.s_addr	= htonl(addr);

exit:
	return obj;
}

//======================================================================================================================

mdns_address_t
mdns_address_create_ipv6(const uint8_t addr[static 16], uint16_t port, uint32_t scope_id)
{
	mdns_address_t obj = _mdns_address_alloc();
	require_quiet(obj, exit);

	struct sockaddr_in6 * const sa = &obj->sip.v6;
	SIN6_LEN_SET(sa);
	sa->sin6_family		= AF_INET6;
	sa->sin6_port		= htons(port);
	memcpy(sa->sin6_addr.s6_addr, addr, 16);
	sa->sin6_scope_id	= scope_id;
	if (sa->sin6_scope_id != 0) {
		char name_buf[IF_NAMESIZE + 1];
		const char *name_ptr = if_indextoname(sa->sin6_scope_id, name_buf);
		const int name_err = map_global_value_errno(name_ptr, name_ptr);
		if (!name_err) {
			obj->if_name = strdup(name_ptr);
		} else {
			os_log_error(_mdns_address_log(), "if_indextoname() for %u failed with error %d: %s",
				sa->sin6_scope_id, name_err, strerror(name_err));
		}
	}

exit:
	return obj;
}

//======================================================================================================================

static OSStatus
_mdns_address_parse_ipv6(const char * const start, const char *end, uint8_t out_addr_bytes[16],
	uint32_t * const out_scope_id);

mdns_address_t
mdns_address_create_from_ip_address_string(const char *addr_str)
{
	mdns_address_t	address = NULL;
	const char *	port_str;
	uint32_t		scope_id;
	uint8_t			addr_bytes[16];
	bool			addr_is_ipv6;

	// An opening bracket implies an IPv6 address, e.g., "[<IPv6 address>]:<port>" or "[<IPv6 address>]".
	if (*addr_str == '[') {
		const char *ptr = &addr_str[1];

		// Look for closing bracket.
		const char *end_bracket = strchr(ptr, ']');
		require_quiet(end_bracket, exit);

		const OSStatus err = _mdns_address_parse_ipv6(ptr, end_bracket, addr_bytes, &scope_id);
		require_noerr_quiet(err, exit);

		// Check for a port delimiter immediately after the closing bracket.
		ptr = end_bracket + 1;
		if (*ptr == ':') {
			port_str = ++ptr;
		} else {
			require_quiet(*ptr == '\0', exit);
			port_str = NULL;
		}
		addr_is_ipv6 = true;
	} else {
		// Try to parse the string as an IPv6 address.
		const OSStatus err = _mdns_address_parse_ipv6(addr_str, NULL, addr_bytes, &scope_id);
		if (!err) {
			port_str = NULL;
			addr_is_ipv6 = true;
		} else {
			const char *addr_ptr;
			char addr_buf[128];

			// Look for port delimiter.
			const char *delim = strchr(addr_str, ':');
			if (delim) {
				// Copy the substring up to the port delimiter.
				const size_t addr_len = (size_t)(delim - addr_str);
				require_quiet(addr_len < sizeof(addr_buf), exit);

				memcpy(addr_buf, addr_str, addr_len);
				addr_buf[addr_len] = '\0';
				addr_ptr = addr_buf;
				port_str = ++delim;
			} else {
				addr_ptr = addr_str;
				port_str = NULL;
			}
			// Try to parse the string or substring as an IPv4 address.
			const int result = inet_pton(AF_INET, addr_ptr, addr_bytes);
			require_quiet(result == 1, exit);
			addr_is_ipv6 = false;
		}
	}
	// If there's a port substring, convert it to its numerical value.
	uint32_t port = 0;
	if (port_str) {
		require_quiet(*port_str != '\0', exit);
		const char *ptr;
		for (ptr = port_str; isdigit_safe(*ptr); ++ptr) {
			const int c = *ptr;
			port = (10 * port) + (uint32_t)(c - '0');
			require_quiet(port <= UINT16_MAX, exit);
		}
		require_quiet(*ptr == '\0', exit);
	}
	if (addr_is_ipv6) {
		address = mdns_address_create_ipv6(addr_bytes, (uint16_t)port, scope_id);
	} else {
		const uint32_t ipv4 = ReadBig32(addr_bytes);
		address = mdns_address_create_ipv4(ipv4, (uint16_t)port);
	}

exit:
	return address;
}

static OSStatus
_mdns_address_parse_ipv6(const char * const start, const char *end, uint8_t out_addr_bytes[16],
	uint32_t * const out_scope_id)
{
	OSStatus err;
	if (!end) {
		end = start;
		while (*end != '\0') {
			++end;
		}
	}
	// Look for zone separator.
	const char *ptr = start;
	while ((ptr < end) && (*ptr != '%')) {
		++ptr;
	}
	const char * const zone_separator = (ptr < end) ? ptr : NULL;

	// Copy substring enclosed in the brackets.
	const char * const	addr_lim = zone_separator ? zone_separator : end;
	const size_t		addr_len = (size_t)(addr_lim - start);
	char addr_buf[128];
	require_action_quiet(addr_len < sizeof(addr_buf), exit, err = kMalformedErr);

	memcpy(addr_buf, start, addr_len);
	addr_buf[addr_len] = '\0';

	// Try to parse substring as an IPv6 address.
	uint8_t addr_bytes[16];
	const int result = inet_pton(AF_INET6, addr_buf, addr_bytes);
	require_action_quiet(result == 1, exit, err = kMalformedErr);

	uint32_t scope_id;
	if (zone_separator) {
		const char * const	zone_id		= zone_separator + 1;
		const size_t		zone_id_len	= (size_t)(end - zone_id);
		char *				name_mem	= NULL;
		char				name_buf[IF_NAMESIZE + 1];

		char *name_ptr;
		if (zone_id_len < sizeof(name_buf)) {
			name_ptr = name_buf;
		} else {
			name_mem = malloc(zone_id_len + 1);
			require_action_quiet(name_mem, exit, err = kNoMemoryErr);
			name_ptr = name_mem;
		}
		memcpy(name_ptr, zone_id, zone_id_len);
		name_ptr[zone_id_len] = '\0';
		scope_id = if_nametoindex(name_ptr);
		ForgetMem(&name_mem);
		if (scope_id == 0) {
			uint64_t u64 = 0;
			for (ptr = zone_id; (ptr < end) && isdigit_safe(*ptr); ++ptr) {
				const int c = *ptr;
				u64 = (10 * u64) + (uint32_t)(c - '0');
				require_action_quiet(u64 <= UINT32_MAX, exit, err = kMalformedErr);
			}
			require_action_quiet((ptr == end) && (ptr != zone_id), exit, err = kMalformedErr);

			scope_id = (uint32_t)u64;
		}
	} else {
		scope_id = 0;
	}
	if (out_addr_bytes) {
		memcpy(out_addr_bytes, addr_bytes, 16);
	}
	if (out_scope_id) {
		*out_scope_id = scope_id;
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

const struct sockaddr *
mdns_address_get_sockaddr(mdns_address_t me)
{
	return &me->sip.sa;
}

//======================================================================================================================

uint16_t
mdns_address_get_port(const mdns_address_t me)
{
	switch (me->sip.sa.sa_family) {
		case AF_INET:
			return ntohs(me->sip.v4.sin_port);

		case AF_INET6:
			return ntohs(me->sip.v6.sin6_port);

		default:
			return 0;
	}
}

//======================================================================================================================
// MARK: - Address Private Methods

static char *
_mdns_address_copy_description(mdns_address_t me, const bool debug, const bool privacy)
{
	char *				description	= NULL;
	char				buffer[128];
	char *				dst			= buffer;
	const char * const	lim			= &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	switch (me->sip.sa.sa_family) {
		case AF_INET: {
			const struct sockaddr_in * const sa = &me->sip.v4;
			const char *addr_str;
			char addr_buf[INET_ADDRSTRLEN];

			if (privacy) {
				addr_str = "<REDACTED IPv4 ADDRESS>";
			} else {
				addr_str = inet_ntop(AF_INET, &sa->sin_addr.s_addr, addr_buf, (socklen_t)sizeof(addr_buf));
			}
			n = mdns_snprintf_add(&dst, lim, "%s", addr_str);
			require_quiet(n >= 0, exit);

			const int port = ntohs(sa->sin_port);
			if (port != 0) {
				n = mdns_snprintf_add(&dst, lim, ":%d", port);
				require_quiet(n >= 0, exit);
			}
			break;
		}
		case AF_INET6: {
			const struct sockaddr_in6 * const sa = &me->sip.v6;
			const char *addr_str;
			char addr_buf[INET6_ADDRSTRLEN];

			if (privacy) {
				addr_str = "<REDACTED IPv6 ADDRESS>";
			} else {
				addr_str = inet_ntop(AF_INET6, sa->sin6_addr.s6_addr, addr_buf, (socklen_t)sizeof(addr_buf));
			}
			const int port = ntohs(sa->sin6_port);
			if (port != 0) {
				n = mdns_snprintf_add(&dst, lim, "[");
				require_quiet(n >= 0, exit);
			}
			n = mdns_snprintf_add(&dst, lim, "%s", addr_str);
			require_quiet(n >= 0, exit);

			if (sa->sin6_scope_id != 0) {
				if (me->if_name) {
					n = mdns_snprintf_add(&dst, lim, "%%%s", me->if_name);
					require_quiet(n >= 0, exit);
				} else {
					n = mdns_snprintf_add(&dst, lim, "%%%u", sa->sin6_scope_id);
					require_quiet(n >= 0, exit);
				}
			}
			if (port != 0) {
				n = mdns_snprintf_add(&dst, lim, "]:%d", port);
				require_quiet(n >= 0, exit);
			}
			break;
		}
		default:
			n = mdns_snprintf_add(&dst, lim, "<INVALID ADDRESS TYPE>");
			require_quiet(n >= 0, exit);
			break;
	}
	description = strdup(buffer);

exit:
	return description;
}

//======================================================================================================================

static bool
_mdns_address_equal(mdns_address_t me, mdns_address_t other)
{
	const int family = me->sip.sa.sa_family;
	if (family == other->sip.sa.sa_family) {
		if (family == AF_INET) {
			const struct sockaddr_in * const me_sa		= &me->sip.v4;
			const struct sockaddr_in * const other_sa	= &other->sip.v4;
			if ((me_sa->sin_port        == other_sa->sin_port) &&
				(me_sa->sin_addr.s_addr == other_sa->sin_addr.s_addr)) {
				return true;
			}
		} else if (family == AF_INET6) {
			const struct sockaddr_in6 * const me_sa		= &me->sip.v6;
			const struct sockaddr_in6 * const other_sa	= &other->sip.v6;
			if ((me_sa->sin6_port == other_sa->sin6_port) &&
				(memcmp(me_sa->sin6_addr.s6_addr, other_sa->sin6_addr.s6_addr, 16) == 0)) {
				return true;
			}
		}
	}
	return false;
}

//======================================================================================================================

static void
_mdns_address_finalize(__unused mdns_address_t me)
{
	ForgetMem(&me->if_name);
}
