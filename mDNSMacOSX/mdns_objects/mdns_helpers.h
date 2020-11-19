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

#ifndef __MDNS_HELPERS_H__
#define __MDNS_HELPERS_H__

#include "mdns_base.h"

#include <MacTypes.h>
#include <netinet/in.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

int
mdns_snprintf_add(char * _Nonnull * _Nonnull ptr, const char * _Nullable lim, const char *fmt, ...);

OSStatus
mdns_replace_string(char * _Nullable * _Nonnull string_ptr, const char * _Nullable new_string);

OSStatus
mdns_make_socket_nonblocking(int sock);

uint64_t
mdns_mach_ticks_per_second(void);

int
mdns_print_obfuscated_ip_address(char *buf_ptr, size_t buf_len, const struct sockaddr *sa);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#define MDNS_LOG_CATEGORY_DEFINE(SHORT_NAME, CATEGORY_STR)			\
	static os_log_t													\
	_mdns_ ## SHORT_NAME ## _log(void)								\
	{																\
		static dispatch_once_t	s_once	= 0;						\
		static os_log_t			s_log	= NULL;						\
		dispatch_once(&s_once,										\
		^{															\
			s_log = os_log_create("com.apple.mdns", CATEGORY_STR);	\
		});															\
		return s_log;												\
	}																\
	extern int _mdns_dummy_variable

#if !defined(nw_forget)
	#define nw_forget(X)	ForgetCustom(X, nw_release)
#endif

#if !defined(nw_release_null_safe)
	#define nw_release_null_safe(X)	do { if (X) { nw_release(X); } } while (0)
#endif

#if !defined(nwi_state_release_null_safe)
	#define nwi_state_release_null_safe(X)	do { if (X) { nwi_state_release(X); } } while (0)
#endif

#define _mdns_socket_forget(PTR)		\
	do {								\
		if (IsValidSocket(*(PTR))) {	\
			close(*(PTR));				\
			*(PTR) = kInvalidSocketRef;	\
		}								\
	} while (0)

#endif	// __MDNS_HELPERS_H__
