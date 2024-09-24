/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef MRC_DISCOVERY_PROXY_H
#define MRC_DISCOVERY_PROXY_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <mdns/base.h>

MRC_DECL(discovery_proxy);
MRC_DECL(discovery_proxy_parameters);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a discovery proxy based on the specified discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@result
 *		A reference to the new discovery proxy object, or NULL if creation failed.
 *
 *	@discussion
 *		The parameters are copied by the discovery proxy object during its creation, so the discovery proxy will
 *		not be affected by later changes to the parameters object.
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2024
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_discovery_proxy_t _Nullable
mrc_discovery_proxy_create(mrc_discovery_proxy_parameters_t params);

/*!
 *	@brief
 *		Sets a discovery proxy's dispatch queue on which to invoke the discovery proxy's event handler.
 *
 *	@param proxy
 *		The discovery proxy.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for the event handler to be invoked.
 *
 *		This function has no effect on a discovery proxy that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_set_queue(mrc_discovery_proxy_t proxy, dispatch_queue_t queue);

/*!
 *	@typedef mrc_discovery_proxy_event_t
 *
 *	@brief
 *		The event type to be delivered when discovery proxy's event handler is invoked.
 *
 *	@const mrc_discovery_proxy_event_invalidation
 *		The event that indicates that the discovery proxy has been invalidated.
 *
 *	@const mrc_discovery_proxy_event_none
 *		The default event is a placeholder event value, it will never be delivered to the event handler.
 *
 *	@const mrc_discovery_proxy_event_started
 *		The event that indicates that the discovery proxy has been started.
 *
 *	@const mrc_discovery_proxy_event_interruption
 *		The event that indicates that the discovery proxy has been interrupted.
 */
MDNS_CLOSED_ENUM(mrc_discovery_proxy_event_t, int,
	mrc_discovery_proxy_event_invalidation	= -1,
	mrc_discovery_proxy_event_none			=  0,
	mrc_discovery_proxy_event_started		=  1,
	mrc_discovery_proxy_event_interruption	=  2
);

/*!
 *	@brief
 *		A discovery proxy event handler.
 *
 *	@param event
 *		The event.
 *
 *	@param error
 *		An error code associated with the event.
 */
typedef void
(^mrc_discovery_proxy_event_handler_t)(mrc_discovery_proxy_event_t event, OSStatus error);

/*!
 *	@brief
 *		Sets a discovery proxy's event handler.
 *
 *	@param proxy
 *		The discovery proxy.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		The event handler will never be invoked before the first call to either mrc_discovery_proxy_activate()
 *		or mrc_discovery_proxy_invalidate().
 *
 *		The handler will be invoked with the mrc_discovery_proxy_event_invalidation event at most once if either
 *		a fatal error occurs or if the the discovery proxy was manually invalidated with
 *		mrc_discovery_proxy_invalidate(). If a fatal error occurred, the event handler's error code argument
 *		will be non-zero to indicate the error that occurred. If the discovery proxy was gracefully invalidated
 *		with mrc_discovery_proxy_invalidate(), then the event handler's error code will be kNoErr (0).
 *
 *		After the handler is invoked with the mrc_discovery_proxy_event_invalidation event, the handler will be
 *		released by the discovery proxy, and will never be invoked by the discovery proxy ever again.
 *
 *		The handler will be invoked with the mrc_discovery_proxy_event_started event when a remote instance of
 *		the discovery proxy has successfully started.
 *
 *		The handler will be invoked with the mrc_discovery_proxy_event_interruption event if the connection to
 *		the daemon was interrupted. For example, the daemon may have crashed. This event exists to inform the
 *		user that the remote instance of the discovery proxy may have suffered some downtime. The discovery
 *		proxy object will try to re-establish the connection as well as a new remote instance of the discovery
 *		proxy.
 *
 *		The mrc_discovery_proxy_event_none event simply exists as a placeholder event value. The event handler
 *		will never be invoked with the mrc_discovery_proxy_event_none event.
 *
 *		Currently, the event handler's error code argument is only meaningful for the
 *		mrc_discovery_proxy_event_invalidation event.
 *
 *		This function has no effect on a discovery proxy that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_set_event_handler(mrc_discovery_proxy_t proxy, mrc_discovery_proxy_event_handler_t handler);

/*!
 *	@brief
 *		Activates a discovery proxy.
 *
 *	@param proxy
 *		The discovery proxy.
 *
 *	@discussion
 *		Activating a discovery proxy object causes it to try to instantiate a remote instance of itself on the
 *		system daemon that implements discovery proxy.
 *
 *		Currently, the maximum number of discovery proxy that can be configured in the system at the same time
 *		is 1. If the system has already been configured with one, the second call to activate a new proxy will
 *		fail with error code `kAlreadyInitializedErr` to indicate that the discovery proxy has been started.
 *		Only when the previous registration is invalidated or the client is interrupted, for example, the client
 *		may have crashed, can the following registration activates a new discovery proxy.
 *
 *		This function has no effect on a discovery proxy that has already been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_activate(mrc_discovery_proxy_t proxy);

/*!
 *	@brief
 *		Invalidates a discovery proxy.
 *
 *	@param proxy
 *		The discovery proxy.
 *
 *	@discussion
 *		Invalidating a discovery proxy object causes it to tear down the remote instance of itself on the system
 *		daemon if such an instance exists.
 *
 *		This function exists to gracefully invalidate a discovery proxy. This function can safely be called even
 *		if the discovery proxy was already forcibly invalidated due to a fatal error.
 *
 *		This function has no effect on a discovery proxy that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_invalidate(mrc_discovery_proxy_t proxy);

/*!
 *	@brief
 *		Creates an empty modifiable set of discovery proxy parameters.
 *
 *	@result
 *		A reference to the new discovery proxy parameters, or NULL if creation failed.
 *
 *	@discussion
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2024
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_discovery_proxy_parameters_t _Nullable
mrc_discovery_proxy_parameters_create(void);

/*!
 *	@brief
 *		Sets the interface index in a set of discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param ifindex
 *		The interface index.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_parameters_set_interface(mrc_discovery_proxy_parameters_t params, uint32_t ifindex);

/*!
 *	@brief
 *		Adds an IPv4 address to an array of discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param address
 *		The IPv4 address as an unsigned 32-bit integer in host byte order.
 *
 *	@param port
 *		The port number in host byte order.
 *
 *	@result
 *		kNoErr if the IPv4 address were successfully added. Otherwise, a non-zero error code to indicate why the
 *		operation failed.
 *
 *	@discussion
 *		This function can be called more than once to specify an array of multiple IPv4 addresses.
 */
MDNS_SPI_AVAILABLE_FALL_2024
OSStatus
mrc_discovery_proxy_parameters_add_server_ipv4_address(mrc_discovery_proxy_parameters_t params, uint32_t address,
	uint16_t port);

/*!
 *	@brief
 *		Adds an IPv6 address to an array of discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param address
 *		The IPv6 address as an array of octets in network byte order.
 *
 *	@param port
 *		The port number in host byte order.
 *
 *	@param scope_id
 *		The scope ID.
 *
 *	@result
 *		kNoErr if the IPv6 address were successfully added. Otherwise, a non-zero error code to indicate why the
 *		operation failed.
 *
 *	@discussion
 *		This function can be called more than once to specify an array of multiple IPv6 addresses.
 */
MDNS_SPI_AVAILABLE_FALL_2024
OSStatus
mrc_discovery_proxy_parameters_add_server_ipv6_address(mrc_discovery_proxy_parameters_t params,
	const uint8_t address[static 16], uint16_t port, uint32_t scope_id);

/*!
 *	@brief
 *		Adds a matching domain to a set of discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param domain
 *		The domain name string.
 *
 *	@result
 *		kNoErr if the domain were successfully added. Otherwise, a non-zero error code to indicate why the
 *		operation failed.
 *
 *	@discussion
 *		This function can be called more than once to specify a set of multiple matching domains.
 *
 *		When discovery proxy is configured, queries under the specified domains will always use the proxy as the
 *		preferred service.
 */
MDNS_SPI_AVAILABLE_FALL_2024
OSStatus
mrc_discovery_proxy_parameters_add_match_domain(mrc_discovery_proxy_parameters_t params, const char *domain);

/*!
 *	@brief
 *		Adds a TLS certificate to an array of discovery proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param cert_data
 *		The data of the DER representation of an X.509 certificate.
 *
 *	@param cert_len
 *		The data length of the DER representation of an X.509 certificate.
 *
 *	@discussion
 *		This function can be called more than once to specify an array of multiple certificates.
 *
 *		When the client intends to use TLS to communicate with the discovery proxy, the certificates specified
 *		here can be used as additional trust anchors to perform TLS certificate evaluation.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_discovery_proxy_parameters_add_server_certificate(mrc_discovery_proxy_parameters_t params, const uint8_t *cert_data,
	size_t cert_len);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_DISCOVERY_PROXY_H
