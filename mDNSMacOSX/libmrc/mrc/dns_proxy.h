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

#ifndef MRC_DNS_PROXY_H
#define MRC_DNS_PROXY_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <mdns/base.h>

MRC_DECL(dns_proxy);
MRC_DECL(dns_proxy_parameters);
MRC_DECL(dns_proxy_state_inquiry);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a DNS proxy based on the specified DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param out_error
 *		A variable to set to either kNoErr if creation succeeds, or a non-zero error code to indicate why
 *		creation failed.
 *
 *	@result
 *		A reference to the new DNS proxy object, or NULL if creation failed.
 *
 *	@discussion
 *		The parameters are copied by the DNS proxy object during its creation, so the DNS proxy will not be
 *		affected by later changes to the parameters object.
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2022
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_dns_proxy_t _Nullable
mrc_dns_proxy_create(mrc_dns_proxy_parameters_t params, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Sets a DNS proxy's dispatch queue on which to invoke the DNS proxy's event handler.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for the event handler to be invoked.
 *
 *		This function has no effect on a DNS proxy that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_set_queue(mrc_dns_proxy_t proxy, dispatch_queue_t queue);

OS_CLOSED_ENUM(mrc_dns_proxy_event, int,
	mrc_dns_proxy_event_invalidation	= -1,
	mrc_dns_proxy_event_none			=  0,
	mrc_dns_proxy_event_started			=  1,
	mrc_dns_proxy_event_interruption	=  2
);

static inline const char *
mrc_dns_proxy_event_to_string(const mrc_dns_proxy_event_t event)
{
	switch (event) {
		case mrc_dns_proxy_event_invalidation:	return "invalidation";
		case mrc_dns_proxy_event_none:			return "none";
		case mrc_dns_proxy_event_started:		return "started";
		case mrc_dns_proxy_event_interruption:	return "interruption";
	}
	return "<INVALID EVENT>";
}

/*!
 *	@brief
 *		A DNS proxy event handler.
 *
 *	@param event
 *		The event.
 *
 *	@param error
 *		An error code associated with the event.
 */
typedef void
(^mrc_dns_proxy_event_handler_t)(mrc_dns_proxy_event_t event, OSStatus error);

/*!
 *	@brief
 *		Sets a DNS proxy's event handler.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		The event handler will never be invoked before the first call to either mrc_dns_proxy_activate()
 *		or mrc_dns_proxy_invalidate().
 *
 *		The handler will be invoked with the mrc_dns_proxy_event_invalidation event at most once if either a
 *		fatal error occurs or if the the DNS proxy was manually invalidated with mrc_dns_proxy_invalidate().
 *		If a fatal error occurred, the event handler's error code argument will be non-zero to indicate the
 *		error that occurred. If the DNS proxy was gracefully invalidated with mrc_dns_proxy_invalidate(), then
 *		the event handler's error code will be kNoErr (0).
 *
 *		After the handler is invoked with the mrc_dns_proxy_event_invalidation event, the handler will be
 *		released by the DNS proxy, and will never be invoked by the DNS proxy ever again.
 *
 *		The handler will be invoked with the mrc_dns_proxy_event_started event each time a remote instance of
 *		the DNS proxy has successfully started.
 *
 *		The handler will be invoked with the mrc_dns_proxy_event_interruption event if the connection to the
 *		daemon was interrupted. For example, the daemon may have crashed. This event exists to inform the user
 *		that the remote instance of the DNS proxy may have suffered some downtime. The DNS proxy object will try
 *		to re-establish the connection as well as a new remote instance of the DNS proxy.
 *
 *		The mrc_dns_proxy_event_none event simply exists as a placeholder event value. The event handler will
 *		never be invoked with the mrc_dns_proxy_event_none event.
 *
 *		Currently, the event handler's error code argument is only meaningful for the
 *		mrc_dns_proxy_event_invalidation event.
 *
 *		This function has no effect on a DNS proxy that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_set_event_handler(mrc_dns_proxy_t proxy, mrc_dns_proxy_event_handler_t handler);

/*!
 *	@brief
 *		Activates a DNS proxy.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@discussion
 *		Activating a DNS proxy object causes it to try to instantiate a remote instance of itself on the system
 *		daemon that implements DNS proxies.
 *
 *		This function has no effect on a DNS proxy that has already been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_activate(mrc_dns_proxy_t proxy);

/*!
 *	@brief
 *		Invalidates a DNS proxy.
 *
 *	@param proxy
 *		The DNS proxy.
 *
 *	@discussion
 *		Invalidating a DNS proxy object causes it to tear down the remote instance of itself on the system
 *		daemon if such an instance exists.
 *
 *		This function exists to gracefully invalidate a DNS proxy. This function can safely be called even if
 *		the DNS proxy was already forcibly invalidated due to a fatal error.
 *
 *		This function has no effect on a DNS proxy that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_invalidate(mrc_dns_proxy_t proxy);

/*!
 *	@brief
 *		Creates an empty modifiable set of DNS proxy parameters.
 *
 *	@param out_error
 *		A variable to set to either kNoErr if creation succeeds, or a non-zero error code to indicate why
 *		creation failed.
 *
 *	@result
 *		A reference to the new DNS proxy parameters, or NULL if creation failed.
 *
 *	@discussion
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2022
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_dns_proxy_parameters_t _Nullable
mrc_dns_proxy_parameters_create(OSStatus *out_error);

/*!
 *	@brief
 *		Adds an input interface to a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param ifindex
 *		The input interface's index.
 *
 *	@discussion
 *		This function can be called more than once to specify a set of multiple input interfaces.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_parameters_add_input_interface(mrc_dns_proxy_parameters_t params, uint32_t ifindex);

/*!
 *	@brief
 *		Sets the output interface in a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param ifindex
 *		The output interface's index.
 *
 *	@discussion
 *		By default, the output interface index is 0, which means that the remote DNS proxy instance will use the
 *		most suitable interface for its DNS network traffic.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_parameters_set_output_interface(mrc_dns_proxy_parameters_t params, uint32_t ifindex);

/*!
 *	@brief
 *		Sets the NAT64 IPv6 prefix in a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param prefix
 *		A pointer to the prefix.
 *
 *	@param prefix_bit_length
 *		The bit length of the prefix. Values greater than 128 will be treated as 128.
 *
 *	@discussion
 *		If a NAT64 prefix is set, then the remote instance of the DNS proxy will carry out DNS64 functionality
 *		using the specified NAT64 prefix. If it's not set, then no DNS64 functionality will be performed.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_parameters_set_nat64_prefix(mrc_dns_proxy_parameters_t params, const uint8_t *prefix,
	size_t prefix_bit_length);

/*!
 *	@brief
 *		Sets whether or not AAAA synthesis should be forced in a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param value
 *		The truth value.
 *
 *	@discussion
 *		Forcing AAAA synthesis only applies if the remote instance of the DNS proxy has DNS64 functionality
 *		enabled by specifying a NAT64 prefix with mrc_dns_proxy_parameters_set_nat64_prefix().
 *
 *		By default, AAAA synthesis is not forced.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_dns_proxy_parameters_set_force_aaaa_synthesis(mrc_dns_proxy_parameters_t params, bool value);

/*!
 *	@brief
 *		A block used for enumerating interface indexes.
 *
 *	@param ifindex
 *		An enumerated interface index.
 *
 *	@result
 *		True if enumeration should continue onto the next interface index, if any. False if enumeration should
 *		not continue.
 */
typedef bool
(^mrc_dns_proxy_parameters_interface_applier_t)(uint32_t ifindex);

/*!
 *	@brief
 *		Enumerates the input interface indexes in a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@param applier
 *		An applier to synchronously invoke once for each input interface index until either no interface indexes
 *		remains or the applier returns false. Note that if there are no input interface indexes, then the
 *		applier will not be invoked.
 *
 *	@result
 *		True if the applier never returned false during enumeration. Otherwise, false.
 */
MDNS_SPI_AVAILABLE_FALL_2022
bool
mrc_dns_proxy_parameters_enumerate_input_interfaces(mrc_dns_proxy_parameters_t params,
	mrc_dns_proxy_parameters_interface_applier_t applier);

/*!
 *	@brief
 *		Gets the output interface index from a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@result
 *		The output interface index.
 *
 *	@discussion
 *		By default, the output interface index is 0, which means that the remote DNS proxy instance will use the
 *		most suitable interface for its DNS network traffic.
 */
MDNS_SPI_AVAILABLE_FALL_2022
uint32_t
mrc_dns_proxy_parameters_get_output_interface(mrc_dns_proxy_parameters_t params);

/*!
 *	@brief
 *		Gets the truth value of whether or not AAAA synthesis should be forced in a set of DNS proxy parameters.
 *
 *	@param params
 *		The parameters.
 *
 *	@result
 *		The truth value.
 *
 *	@discussion
 *		By default, AAAA synthesis is not forced.
 */
MDNS_SPI_AVAILABLE_FALL_2022
bool
mrc_dns_proxy_parameters_get_force_aaaa_synthesis(mrc_dns_proxy_parameters_t params);

/*!
 *	@brief
 *		Creates a DNS proxy state inquiry object, whose purpose is to inquire about the current state of all of
 *		the system's DNS proxies.
 *
 *	@result
 *		A reference to the new inquiry, or NULL if creation failed.
 *
 *	@discussion
 *		The state that is obtained by this object is human-readable text meant for diagnostic purposes.
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_MIDFALL_2022
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_dns_proxy_state_inquiry_t
mrc_dns_proxy_state_inquiry_create(void);

/*!
 *	@brief
 *		Sets a DNS proxy state inquiry's queue on which to invoke its response handler.
 *
 *	@param inquiry
 *		The DNS proxy state inquiry.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for an inquiry's response handler to be invoked.
 *
 *		This function should be called before the inquiry is activated. This function has no effect on an
 *		inquiry that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_MIDFALL_2022
void
mrc_dns_proxy_state_inquiry_set_queue(mrc_dns_proxy_state_inquiry_t inquiry, dispatch_queue_t queue);

/*!
 *	@brief
 *		A DNS proxy state inquiry response handler.
 *
 *	@param state
 *		The state as a human-readable C string.
 *
 *	@param error
 *		An error code, which will be non-zero if a fatal error occurred, or zero, otherwise.
 *
 *	@discussion
 *		The lifetime of the state C string is not guaranteed beyond the invocation of this handler. If it is
 *		needed beyond the invocation of this handler, then it should be duplicated.
 */
typedef void
(^mrc_dns_proxy_state_inquiry_response_handler_t)(const char * _Nullable state, OSStatus error);

/*!
 *	@brief
 *		Sets a DNS proxy state inquiry's response handler.
 *
 *	@param inquiry
 *		The DNS proxy state inquiry.
 *
 *	@param handler
 *		The response handler.
 *
 *	@discussion
 *		The response handler will never be invoked before the first call to either
 *		mrc_dns_proxy_state_inquiry_activate() or mrc_dns_proxy_state_inquiry_invalidate().
 *
 *		The response handler will be submitted to the inquiry's queue no more than once for one of the following
 *		events, whichever occurs first:
 *
 *		1. The system daemon that implements DNS proxies responds with the current state of the DNS proxies. In
 *		   this case, the handler will be invoked with a non-NULL state string and a kNoErr error code.
 *
 *		2. A fatal error occurs that halts the inquiry's progress. In this case, the handler will be invoked
 *		   with a NULL state string and a non-zero error code that indicates the type of error that occurred.
 *
 *		3. The inquiry is invalidated with mrc_dns_proxy_state_inquiry_invalidate(). In this case, the handler
 *		   will be invoked with a NULL state string and a kNoErr error code.
 *
 *		This function should be called before the inquiry is activated. This function has no effect on an
 *		inquiry that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_MIDFALL_2022
void
mrc_dns_proxy_state_inquiry_set_handler(mrc_dns_proxy_state_inquiry_t inquiry,
	mrc_dns_proxy_state_inquiry_response_handler_t handler);

/*!
 *	@brief
 *		Activates a DNS proxy state inquiry.
 *
 *	@param inquiry
 *		The DNS proxy state inquiry.
 *
 *	@discussion
 *		Activating an inquiry causes it to ask the system daemon that implements DNS proxies about the current
 *		state of those proxies.
 *
 *		This function has no effect on an inquiry that has already been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_MIDFALL_2022
void
mrc_dns_proxy_state_inquiry_activate(mrc_dns_proxy_state_inquiry_t inquiry);

/*!
 *	@brief
 *		Invalidates a DNS proxy state inquiry.
 *
 *	@param inquiry
 *		The DNS proxy state inquiry.
 *
 *	@discussion
 *		This function exists to gracefully invalidate an inquiry.
 *
 *		If the inquiry's response handler hasn't already been invoked and isn't on its way to be invoked, then
 *		this function will force it to be invoked (asynchronously, of course) with a NULL state string. If the
 *		response handler has already been called, then calling this function is unnecessary, but harmless.
 *
 *		This function has no effect on an inquiry that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_MIDFALL_2022
void
mrc_dns_proxy_state_inquiry_invalidate(mrc_dns_proxy_state_inquiry_t inquiry);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_DNS_PROXY_H
