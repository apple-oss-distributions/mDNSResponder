/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef MRC_DNS_SERVICE_REGISTRATION_H
#define MRC_DNS_SERVICE_REGISTRATION_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <mdns/base.h>
#include <mdns/dns_service.h>

MRC_DECL(dns_service_registration);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a DNS service registration based on the specified DNS service definition.
 *
 *	@param definition
 *		The DNS service definition.
 *
 *	@result
 *		A reference to the new DNS service registration object, or NULL if creation failed.
 *
 *	@discussion
 *		The DNS service definition is copied by the DNS service registration object during its creation, so the
 *		registration will not be affected by later changes to the definition.
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_SPRING_2024
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_dns_service_registration_t _Nullable
mrc_dns_service_registration_create(mdns_dns_service_definition_t definition);

/*!
 *	@brief
 *		Sets a DNS service registration's dispatch queue on which to invoke the DNS service registration's event
 *		handler.
 *
 *	@param registration
 *		The DNS service registration.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for the event handler to be invoked.
 *
 *		This function has no effect on a DNS service registration that has already been activated or
 *		invalidated.
 */
MDNS_SPI_AVAILABLE_SPRING_2024
void
mrc_dns_service_registration_set_queue(mrc_dns_service_registration_t registration, dispatch_queue_t queue);

/*!
 *	@typedef mrc_dns_service_registration_event_t
 *
 *	@brief
 *		DNS service registration events.
 *
 *	@const mrc_dns_service_registration_event_invalidation
 *		Indicates that the DNS service registration has been invalidated.
 *
 *	@const mrc_dns_service_registration_event_started
 *		Indicates that the DNS service registration has started.
 *
 *	@const mrc_dns_service_registration_event_interruption
 *		Indicates that the DNS service registration has been interrupted.
 */
MDNS_CLOSED_ENUM(mrc_dns_service_registration_event_t, int,
	mrc_dns_service_registration_event_invalidation	= -1,
	mrc_dns_service_registration_event_started		=  1,
	mrc_dns_service_registration_event_interruption	=  2
);

/*!
 *	@brief
 *		A DNS service registration event handler.
 *
 *	@param event
 *		The event.
 *
 *	@param error
 *		An error code associated with the event.
 */
typedef void
(^mrc_dns_service_registration_event_handler_t)(mrc_dns_service_registration_event_t event, OSStatus error);

/*!
 *	@brief
 *		Sets a DNS service registration's event handler.
 *
 *	@param registration
 *		The DNS service registration.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		The event handler will never be invoked before the first call to either
 *		mrc_dns_service_registration_activate() or mrc_dns_service_registration_invalidate().
 *
 *		The handler will be invoked with the mrc_dns_service_registration_event_invalidation event at most once
 *		if either a fatal error occurs or if the the DNS service registration was manually invalidated with
 *		mrc_dns_service_registration_invalidate(). If a fatal error occurred, the event handler's error code
 *		argument will be non-zero to indicate the error that occurred. If the DNS service registration was
 *		gracefully invalidated with mrc_dns_service_registration_invalidate(), then the event handler's error
 *		code will be kNoErr (0).
 *
 *		After the handler is invoked with the mrc_dns_service_registration_event_invalidation event, the handler
 *		will be released by the DNS service registration, and will never be invoked by the DNS service
 *		registration ever again.
 *
 *		The handler will be invoked with the mrc_dns_service_registration_event_started event each time a remote
 *		instance of the DNS service registration has successfully started.
 *
 *		The handler will be invoked with the mrc_dns_service_registration_event_interruption event if the
 *		connection to the daemon was interrupted. For example, the daemon may have crashed. This event exists to
 *		inform the user that the remote instance of the DNS service registration may have suffered some
 *		downtime. The DNS service registration object will try to re-establish the connection as well as a new
 *		remote instance of the DNS service registration.
 *
 *		Currently, the event handler's error code argument is only meaningful for the
 *		mrc_dns_service_registration_event_invalidation event.
 *
 *		This function has no effect on a DNS service registration that has already been activated or
 *		invalidated.
 */
MDNS_SPI_AVAILABLE_SPRING_2024
void
mrc_dns_service_registration_set_event_handler(mrc_dns_service_registration_t registration,
	mrc_dns_service_registration_event_handler_t handler);

/*!
 *	@brief
 *		Activates a DNS service registration.
 *
 *	@param registration
 *		The DNS service registration.
 *
 *	@discussion
 *		Activating a DNS service registration object causes it to try to instantiate a remote instance of itself
 *		on the system daemon that implements DNS service registrations.
 *
 *		This function has no effect on a DNS service registration that has already been activated or
 *		invalidated.
 */
MDNS_SPI_AVAILABLE_SPRING_2024
void
mrc_dns_service_registration_activate(mrc_dns_service_registration_t registration);

/*!
 *	@brief
 *		Invalidates a DNS service registration.
 *
 *	@param registration
 *		The DNS service registration.
 *
 *	@discussion
 *		Invalidating a DNS service registration object causes it to tear down the remote instance of itself on
 *		the system daemon if such an instance exists.
 *
 *		This function exists to gracefully invalidate a DNS service registration. This function can safely be
 *		called even if the DNS service registration was already forcibly invalidated due to a fatal error.
 *
 *		This function has no effect on a DNS service registration that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_SPRING_2024
void
mrc_dns_service_registration_invalidate(mrc_dns_service_registration_t registration);

/*!
 *	@brief
 *		Invalidates and forgets a DNS service registration.
 *
 *	@param PTR
 *		The address of a DNS service registration pointer.
 *
 *	@discussion
 *		This is a convenience macro that combines the functionality of mrc_dns_service_registration_invalidate()
 *		and mrc_forget(). If the pointer is non-NULL, then the DNS service registration referenced by the pointer
 *		is invalidated with mrc_dns_service_registration_invalidate(). The address of the DNS service registration
 *		pointer is then treated as if it were passed to mrc_forget().
 */
#define mrc_dns_service_registration_forget(PTR)	mrc_forget_with_invalidation(PTR, dns_service_registration)

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_DNS_SERVICE_REGISTRATION_H
