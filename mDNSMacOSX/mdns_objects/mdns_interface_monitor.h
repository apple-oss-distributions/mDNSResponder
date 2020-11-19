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

#ifndef __MDNS_INTERFACE_MONITOR_H__
#define __MDNS_INTERFACE_MONITOR_H__

#include "mdns_base.h"
#include "mdns_object.h"

#include <stdint.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>

MDNS_DECL(interface_monitor);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates an interface monitor.
 *
 *	@param interface_index
 *		Index of the interface to monitor.
 *
 *	@result
 *		A new interface monitor or NULL if there was a lack of resources.
 *
 *	@discussion
 *		An interface monitor provides up-to-date information about an interface's properties, such as IPv4
 *		connectivity, IPv6 connectivity, whether the interface is expensive, and whether the interface is constrained.
 *
 *		If this function returns non-NULL, then the caller has an ownership reference to the newly created interface
 *		monitor, which can be relinquished with <code>mdns_release()</code>.
 */
MDNS_RETURNS_RETAINED mdns_interface_monitor_t _Nullable
mdns_interface_monitor_create(uint32_t interface_index);

/*!
 *	@brief
 *		Activates an interface monitor.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		Successful activation enables interface monitor updates.
 *
 *		This function has no effect on an interface monitor that has already been activated or one that has been
 *		invalidated.
 */
void
mdns_interface_monitor_activate(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Asynchronously invalidates an interface monitor.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		This function should be called when the interface monitor is no longer needed.
 *
 *		As a result of calling this function, the interface monitor's event handler will be invoked with a
 *		<code>mdns_event_invalidated</code> event, after which the interface monitor's event and update handlers will
 *		never be invoked again.
 *
 *		This function has no effect on an interface monitor that has already been invalidated.
 */
void
mdns_interface_monitor_invalidate(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Specifies the queue on which to invoke the interface monitor's event and update handlers.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@param queue
 *		A serial queue.
 *
 *	@discussion
 *		This function must be called before activating the interface monitor.
 *
 *		This function has no effect on an interface monitor that has been activated or invalidated.
 */
void
mdns_interface_monitor_set_queue(mdns_interface_monitor_t monitor, dispatch_queue_t queue);

/*!
 *	@brief
 *		Sets an interface monitor's event handler.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		The event handler will never be invoked prior to activation.
 *
 *		The event handler will be invoked on the dispatch queue specified by
 *		<code>mdns_interface_monitor_set_queue()</code> with event <code>mdns_event_error</code> when a fatal error
 *		occurs and with event <code>mdns_event_invalidated</code> when the interface monitor has been invalidated.
 *
 *		After an <code>mdns_event_invalidated</code> event, the event handler will never be invoked again.
 */
void
mdns_interface_monitor_set_event_handler(mdns_interface_monitor_t monitor, mdns_event_handler_t _Nullable handler);

/*!
 *	@brief
 *		Flags that represent the properties of a monitored interface.
 *
 *	@discussion
 *		These flags don't represent the actual values of properties. The meaning of these flags depends on the
 *		context in which they're used. For example, as a parameter of mdns_interface_monitor_update_handler_t, a set
 *		flag means that the value of a given property has changed.
 */
OS_CLOSED_OPTIONS(mdns_interface_flags, uint32_t,
	mdns_interface_flag_null				= 0,
	mdns_interface_flag_ipv4_connectivity	= (1U <<  0),
	mdns_interface_flag_ipv6_connectivity	= (1U <<  1),
	mdns_interface_flag_expensive			= (1U <<  2),
	mdns_interface_flag_constrained			= (1U <<  3),
	mdns_interface_flag_clat46				= (1U <<  4),
	mdns_interface_flag_vpn					= (1U <<  5),
	mdns_interface_flag_reserved			= (1U << 31)
);

/*!
 *	@brief
 *		Update handler for an interface monitor.
 *
 *	@param change_flags
 *		Each flag bit represents a property of a monitored interface. If the bit is set, then the value of that
 *		property has changed. If the bit is clear, then the value of that property has not changed.
 */
typedef void (^mdns_interface_monitor_update_handler_t)(mdns_interface_flags_t change_flags);

/*!
 *	@brief
 *		Sets an interface monitor's update handler.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@param handler
 *		The update handler.
 *
 *	@discussion
 *		The update handler will never be invoked prior to activation.
 *
 *		The update handler will be invoked on the dispatch queue specified by
 *		<code>mdns_interface_monitor_set_queue()</code> when any of the monitored interface's properties have been
 *		updated.
 *
 *		After an <code>mdns_event_invalidated</code> event, the update handler will ever be invoked again.
 */
void
mdns_interface_monitor_set_update_handler(mdns_interface_monitor_t monitor,
	mdns_interface_monitor_update_handler_t _Nullable handler);

/*!
 *	@brief
 *		Returns the index of the monitored interface.
 *
 *	@param monitor
 *		The interface monitor.
 */
uint32_t
mdns_interface_monitor_get_interface_index(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface currently has IPv4 connectivity.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_ipv4_connectivity will be set in the update handler's change_flags argument when the
 *		value of this property has changed.
 */
bool
mdns_interface_monitor_has_ipv4_connectivity(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface currently has IPv6 connectivity.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_ipv6_connectivity will be set in the update handler's change_flags argument when the
 *		value of this property has changed.
 */
bool
mdns_interface_monitor_has_ipv6_connectivity(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface is currently expensive.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_expensive will be set in the update handler's change_flags argument when the value
 *		of this property has changed.
 */
bool
mdns_interface_monitor_is_expensive(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface is currently constrained.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_constrained will be set in the update handler's change_flags argument when the value
 *		of this property has changed.
 */
bool
mdns_interface_monitor_is_constrained(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface has CLAT46 support.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_clat46 will be set in the update handler's change_flags argument when the value
 *		of this property has changed.
 */
bool
mdns_interface_monitor_is_clat46(mdns_interface_monitor_t monitor);

/*!
 *	@brief
 *		Determines whether the monitored interface is used for VPN.
 *
 *	@param monitor
 *		The interface monitor.
 *
 *	@discussion
 *		mdns_interface_flag_vpn will be set in the update handler's change_flags argument when the value of this
 *		property has changed.
 */
bool
mdns_interface_monitor_is_vpn(mdns_interface_monitor_t monitor);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#define mdns_interface_monitor_forget(X)	mdns_forget_with_invalidation(X, interface_monitor)

#endif	// __MDNS_INTERFACE_MONITOR_H__
