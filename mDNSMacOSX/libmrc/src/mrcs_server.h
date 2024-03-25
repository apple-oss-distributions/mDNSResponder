/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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
#include <mdns/dns_service.h>

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
 *		A handler that starts a DNS service registration.
 *
 *	@param definition
 *		The DNS service's definition.
 *
 *	@result
 *		A non-zero identifier for the DNS service if the registration was successful. Otherwise,
 *		MDNS_DNS_SERVICE_INVALID_ID.
 */
typedef mdns_dns_service_id_t
(*mrcs_server_dns_service_registration_start_handler_f)(mdns_dns_service_definition_t definition);

/*!
 *	@brief
 *		A handler that stops a DNS service registration.
 *
 *	@param ident
 *		The identifier returned by a mrcs_server_dns_service_registration_start_handler_f handler when the DNS
 *		service was registered.
 */
typedef void
(*mrcs_server_dns_service_registration_stop_handler_f)(mdns_dns_service_id_t ident);

/*!
 *	@brief
 *		A structure containing dns proxy handlers to be invoked by an mDNSResponder control server.
 */
struct mrcs_server_dns_proxy_handlers_s {
	mrcs_server_dns_proxy_start_handler_f		start;
	mrcs_server_dns_proxy_stop_handler_f		stop;
	mrcs_server_dns_proxy_get_state_handler_f	get_state;
};

typedef const struct mrcs_server_dns_proxy_handlers_s *mrcs_server_dns_proxy_handlers_t;

/*!
 *	@brief
 *		A structure containing dns service registration handlers to be invoked by an mDNSResponder control
 *		server.
 */
struct mrcs_server_dns_service_registration_handlers_s {
	mrcs_server_dns_service_registration_start_handler_f	start;
	mrcs_server_dns_service_registration_stop_handler_f		stop;
};

typedef const struct mrcs_server_dns_service_registration_handlers_s *mrcs_server_dns_service_registration_handlers_t;

/*!
 *	@brief
 *		Sets the mDNSResponder control server's DNS proxy handlers.
 *
 *	@param handlers
 *		The DNS proxy handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_dns_proxy_handlers(mrcs_server_dns_proxy_handlers_t handlers);

/*!
 *	@brief
 *		Sets the mDNSResponder control server's DNS service registration handlers.
 *
 *	@param handlers
 *		The DNS service registration handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_dns_service_registration_handlers(mrcs_server_dns_service_registration_handlers_t handlers);

/*!
 *	@brief
 *		Activates the mDNSResponder control server.
 */
void
mrcs_server_activate(void);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRCS_SERVER_H
