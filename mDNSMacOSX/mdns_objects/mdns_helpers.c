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

#include "mdns_helpers.h"

#include <CoreUtils/CoreUtils.h>
#include "DNSMessage.h"

//======================================================================================================================
// MARK: - Internals

MDNS_LOG_CATEGORY_DEFINE(helpers, "helpers");

//======================================================================================================================

int
mdns_snprintf_add(char **ptr, const char *lim, const char *fmt, ...)
{
	va_list args;
	char * const dst = ptr ? *ptr : NULL;
	const size_t len = (size_t)(lim - dst);
	va_start(args, fmt);
	const int n = vsnprintf(dst, len, fmt, args);
	va_end(args);
	require_quiet(n >= 0, exit);

	if (ptr) {
		if (((size_t)n) > len) {
			*ptr = dst + len;
		} else {
			*ptr = dst + n;
		}
	}

exit:
	return n;
}

//======================================================================================================================

OSStatus
mdns_replace_string(char **string_ptr, const char *replacement)
{
	OSStatus err;
	char *new_string;
	if (replacement) {
		new_string = strdup(replacement);
		require_action_quiet(new_string, exit, err = kNoMemoryErr);
	} else {
		new_string = NULL;
	}
	FreeNullSafe(*string_ptr);
	*string_ptr = new_string;
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

OSStatus
mdns_make_socket_nonblocking(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	flags |= O_NONBLOCK;
	OSStatus err = fcntl(sock, F_SETFL, flags);
	err = map_global_value_errno(err != -1, err);
    return err;
}

//======================================================================================================================

uint64_t
mdns_mach_ticks_per_second(void)
{
	static dispatch_once_t	s_once = 0;
	static uint64_t			s_ticks_per_second = 0;
	dispatch_once(&s_once,
	^{
		mach_timebase_info_data_t info;
		const kern_return_t err = mach_timebase_info(&info);
		if (!err && (info.numer != 0) && (info.denom != 0)) {
			s_ticks_per_second = (info.denom * UINT64_C_safe(kNanosecondsPerSecond)) / info.numer;
		} else {
			os_log_error(_mdns_helpers_log(),
				"Unexpected results from mach_timebase_info: err %d numer %u denom %u", err, info.numer, info.denom);
			s_ticks_per_second = kNanosecondsPerSecond;
		}
	});
	return s_ticks_per_second;
}

//======================================================================================================================

int
mdns_print_obfuscated_ip_address(char * const buf_ptr, const size_t buf_len, const struct sockaddr * const sa)
{
	int n;
	char strbuf[64];
	switch (sa->sa_family) {
		case AF_INET: {
			const struct sockaddr_in * const sin = (const struct sockaddr_in *)sa;
			n = DNSMessagePrintObfuscatedIPv4Address(strbuf, sizeof(strbuf), ntohl(sin->sin_addr.s_addr));
			require_return_value(n >= 0, n);
			return snprintf(buf_ptr, buf_len, "<IPv4:%s>", strbuf);
		}
		case AF_INET6: {
			const struct sockaddr_in6 * const sin6 = (const struct sockaddr_in6 *)sa;
			n = DNSMessagePrintObfuscatedIPv6Address(strbuf, sizeof(strbuf), sin6->sin6_addr.s6_addr);
			require_return_value(n >= 0, n);
			return snprintf(buf_ptr, buf_len, "<IPv6:%s>", strbuf);
		}
		default: {
			return kTypeErr;
		}
	}
}
