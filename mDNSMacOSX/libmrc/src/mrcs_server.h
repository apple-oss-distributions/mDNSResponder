/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#ifndef MRCS_SERVER_H
#define MRCS_SERVER_H

#include "mrcs_dns_proxy.h"

#include <MacTypes.h>
#include <mdns/base.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		A handler that starts a specified DNS proxy.
 *
 *	@param proxy
 *		An object that describes the DNS proxy to start.
 *
 *	@result
 *		kNoErr if the DNS proxy was successfully started. Otherwise, a non-zero error code to indicate why the
 *		DNS proxy was not started.
 */
typedef OSStatus
(*mrcs_server_dns_proxy_start_handler_f)(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		A handler that stops a specified DNS proxy.
 *
 *	@param proxy
 *		A reference to the DNS proxy to stop.
 *
 *	@result
 *		kNoErr if the DNS proxy was successfully stopped. Otherwise, a non-zero error code to indicate why the
 *		DNS proxy was not stopped.
 */
typedef OSStatus
(*mrcs_server_dns_proxy_stop_handler_f)(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		A handler that gets the state of all active DNS proxies in human-readable text.
 *
 *	@result
 *		The text as an allocated C string.
 */
typedef char * _Nullable
(*mrcs_server_dns_proxy_get_state_handler_f)(void);

/*!
 *	@brief
 *		A structure containing handlers to be invoked an mDNSResponder control server.
 */
struct mrcs_server_handlers_s {
	mrcs_server_dns_proxy_start_handler_f		dns_proxy_start;
	mrcs_server_dns_proxy_stop_handler_f		dns_proxy_stop;
	mrcs_server_dns_proxy_get_state_handler_f	dns_proxy_get_state;
};

typedef const struct mrcs_server_handlers_s *mrcs_server_handlers_t;

/*!
 *	@brief
 *		Initializes mDNSResponder's control server.
 *
 *	@param handlers
 *		The handlers to be used by the control server.
 *
 *	@result
 *		kNoErr if the control server was successfully initialized. Otherwise, a non-zero error code to indicate
 *		why initialization failed.
 */
OSStatus
mrcs_server_init(mrcs_server_handlers_t handlers);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRCS_SERVER_H
