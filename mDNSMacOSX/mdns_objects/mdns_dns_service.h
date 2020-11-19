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

#ifndef __MDNS_DNS_SERVICE_H__
#define __MDNS_DNS_SERVICE_H__

#include "mdns_base.h"
#include "mdns_object.h"
#include "mdns_resolver.h"

#include <dnsinfo.h>
#include <MacTypes.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <xpc/xpc.h>

MDNS_DECL(dns_service);
MDNS_DECL(dns_service_manager);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a DNS service manager, which manages DNS services from a DNS configuration.
 *
 *	@param queue
 *		Dispatch queue for event handler.
 *
 *	@param out_error
 *		Pointer to an OSStatus variable, which will be set to the error that was encountered during creation.
 *
 *	@result
 *		A new DNS service manager object or NULL if there was a lack of resources.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mdns_dns_service_manager_t _Nullable
mdns_dns_service_manager_create(dispatch_queue_t queue, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Sets whether a DNS service manager is to report DNS server responsiveness symptoms.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param report_symptoms
 *		Whether or not a DNS service manager is to report DNS server responsiveness symptoms.
 *
 *	@discussion
 *		This function has no effect on a manager after a call to
 *		<code>mdns_dns_service_manager_activate()</code>.
 */
void
mdns_dns_service_manager_set_report_symptoms(mdns_dns_service_manager_t manager, bool report_symptoms);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
/*!
 *	@brief
 *		For each Do53 DNS service managed by a DNS service manager, enables or disables a workaround where the
 *		DNS service's queriers will refrain from sending queries of type SVCB and HTTPS to a server if the
 *		server has been determined to not respond to queries of those types.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param threshold
 *		If greater than zero, the workaround is enabled. Otherwise, the workaround is disabled.
 *
 *	@discussion
 *		This is a workaround for DNS servers that don't respond to SVCB and HTTPS queries and then become less
 *		responsive to queries of other types as more SVCB and HTTPS retry queries are sent.
 *
 *		The workaround is disabled by default.
 *
 *		This function has no effect on a DNS service manager afer a call to mdns_dns_service_manager_activate().
 */
void
mdns_dns_service_manager_enable_problematic_qtype_workaround(mdns_dns_service_manager_t manager, int threshold);
#endif

/*!
 *	@brief
 *		Sets a DNS service manager's event handler.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		The event handler will never be invoked prior to a call to either
 *		<code>mdns_dns_service_manager_activate()()</code> or
 *		<code>mdns_dns_service_manager_invalidate()</code>.
 *
 *		The event handler will be invoked on the dispatch queue specified by
 *		<code>mdns_dns_service_manager_create()</code> with event <code>mdns_event_error</code> when a fatal error
 *		occurs, with event <code>mdns_event_invalidated</code> when the interface monitor has been invalidated, and
 *		with <code>mdns_event_update</code> when there are pending DNS service updates.
 *
 *		After an <code>mdns_event_invalidated</code> event, the event handler will never be invoked again.
 */
void
mdns_dns_service_manager_set_event_handler(mdns_dns_service_manager_t manager, mdns_event_handler_t handler);

/*!
 *	@brief
 *		Activates a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@discussion
 *		This function should be called on a new DNS service manager after after setting its properties and event
 *		handler.
 */
void
mdns_dns_service_manager_activate(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		Synchronously processes a DNS configuration.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param config
 *		A dnsinfo DNS configuration. See <dnsinfo.h>.
 *
 *	@discussion
 *		This function ensures that a DNS service object is instantiated for each DNS service contained in this DNS
 *		configuration. DNS service objects that were created for previous DNS configurations, but that are not
 *		present in this configuration, are marked as defunct.
 */
void
mdns_dns_service_manager_apply_dns_config(mdns_dns_service_manager_t manager, const dns_config_t *config);

/*!
 *	@brief
 *		Add a dynamic resolver configuration to the service manager based on a resolver UUID.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param resolver_config_uuid
 *		A UUID of a resolver configuration registered with the system.
 *
 *	@discussion
 *		This function registers a UUID with the service manager if it does not exist already. The UUID will be used
 *		to look up the details of the resolver configuration.
 */
void
mdns_dns_service_manager_register_path_resolver(mdns_dns_service_manager_t manager,
	const uuid_t _Nonnull resolver_config_uuid);

/*!
 * @typedef mdns_dns_service_id_t
 *
 * @abstract
 *		A unique per-process identifier for DNS service objects.
 *
 * @discussion
 *		Useful as an alternative to a pointer to a DNS service when the DNS service itself isn't actually
 *		needed. This identifier can be used to safely distinguish one DNS service object from another even after
 *		one or both have been released.
 *
 *		The zero value is reserved as an invalid ID.
 */
typedef uint64_t mdns_dns_service_id_t;

#define MDNS_DNS_SERVICE_MAX_ID	((mdns_dns_service_id_t)-1)

/*!
 *	@brief
 *		Registers a custom DNS service based on an nw_resolver_config dictionary with a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param resolver_config_dict
 *		The nw_resolver_config dictionary.
 *
 *	@result
 *		If the registration is successful, this function returns a non-zero identifier for the custom DNS
 *		service.
 *
 *	@discussion
 *		When the custom DNS service is no longer needed by the entity that registered it, it should be
 *		deregistered with <code>mdns_dns_service_manager_deregister_custom_service()</code>.
 */
MDNS_WARN_RESULT
mdns_dns_service_id_t
mdns_dns_service_manager_register_custom_service(mdns_dns_service_manager_t manager, xpc_object_t resolver_config_dict);

/*!
 *	@brief
 *		Deregisters a custom DNS service from a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param ident
 *		The identifier returned by <code>mdns_dns_service_manager_register_custom_service()</code> when the
 *		custom DNS service was registered.
 */
void
mdns_dns_service_manager_deregister_custom_service(mdns_dns_service_manager_t manager, mdns_dns_service_id_t ident);

/*!
 *	@brief
 *		Add a custom resolver configuration to the service manager associated with a particular handle.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param doh_uri
 *		A URI of a DoH server, as a string.
 *
 *	@param domain
 *		A domain to link to a DoH server.
 *
 *	@discussion
 *		This function registers a DoH URI with the service manager if it does not exist already.
 */
void
mdns_dns_service_manager_register_doh_uri(const mdns_dns_service_manager_t manager,
	const char *doh_uri, const char * _Nullable domain);

/*!
 *	@brief
 *		Asynchronously invalidates a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@discussion
 *		This function should be called when a DNS service manager is no longer needed.
 *
 *		As a result of calling this function, the DNS service manager's event handler will be invoked with a
 *		<code>mdns_event_invalidated</code> event, after which the DNS service manager's event handler will never
 *		be invoked again.
 *
 *		This function has no effect on a DNS service manager that has already been invalidated.
 */
void
mdns_dns_service_manager_invalidate(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		Gets the most suitable unscoped DNS service that can be used to query for a record with the given domain
 *		name.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param name
 *		The domain name in label format.
 *
 *	@discussion
 *		This function returns the most suitable unscoped DNS service from the latest DNS configuration that can be
 *		used to query for a record with the given domain name if such a service even exists.
 *
 *		If a service is returned, there's no guarantee that the reference will be valid after the next call to
 *		either <code>mdns_dns_service_manager_apply_dns_config()</code> or
 *		<code>mdns_dns_service_manager_apply_pending_updates()</code> unless the service is retained by the caller.
 *
 *	@result
 *		A non-retained service if a suitable service exists. Otherwise, NULL.
 */
mdns_dns_service_t _Nullable
mdns_dns_service_manager_get_unscoped_service(mdns_dns_service_manager_t manager, const uint8_t *name);

/*!
 *	@brief
 *		Gets the most suitable interface-scoped DNS service that can be used to query for a record with the given
 *		domain name.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param name
 *		The domain name in label format.
 *
 *	@param if_index
 *		The index of the interface to which the interface-scoped service must be scoped.
 *
 *	@discussion
 *		This function returns the most suitable interface-scoped DNS service from the latest DNS configuration that
 *		can be used to query for a record with the given domain name if such a service even exists.
 *
 *		If a service is returned, there's no guarantee that the reference will be valid after the next call to
 *		either <code>mdns_dns_service_manager_apply_dns_config()</code> or
 *		<code>mdns_dns_service_manager_apply_pending_updates()</code> unless the service is retained by the caller.
 *
 *	@result
 *		A non-retained service if a suitable service exists. Otherwise, NULL.
 */
mdns_dns_service_t _Nullable
mdns_dns_service_manager_get_interface_scoped_service(mdns_dns_service_manager_t manager, const uint8_t *name,
	uint32_t if_index);

/*!
 *	@brief
 *		Gets the most suitable service-scoped DNS service that can be used to query for a record with the given
 *		domain name.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param name
 *		The domain name in label format.
 *
 *	@param service_id
 *		The ID of the service for which the service-scoped service must be scoped.
 *
 *	@discussion
 *		This function returns the most suitable service-scoped DNS service from the latest DNS configuration that
 *		can be used to query for a record with the given domain name if such a service even exists.
 *
 *		Note: service-scoped DNS services are for specialized VPN applications, such as Per-App VPN.
 *
 *		If a service is returned, there's no guarantee that the reference will be valid after the next call to
 *		either <code>mdns_dns_service_manager_apply_dns_config()</code> or
 *		<code>mdns_dns_service_manager_apply_pending_updates()</code> unless the service is retained by the caller.
 *
 *	@result
 *		A non-retained service if a suitable service exists. Otherwise, NULL.
 */
mdns_dns_service_t _Nullable
mdns_dns_service_manager_get_service_scoped_service(mdns_dns_service_manager_t manager, const uint8_t *name,
	uint32_t service_id);

/*!
 *	@brief
 *		Gets a custom DNS service with a given identifier from a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param ident
 *		The custom DNS service's identifier, i.e., the identifier returned by
 *		<code>mdns_dns_service_manager_register_custom_service()</code> when the custom DNS service was
 *		registered.
 *
 *	@result
 *		A non-retained reference to the custom DNS service if the custom DNS service is still registered.
 *		Otherwise, NULL.
 */
mdns_dns_service_t _Nullable
mdns_dns_service_manager_get_custom_service(mdns_dns_service_manager_t manager, mdns_dns_service_id_t ident);

/*!
 *	@brief
 *		Gets the config-specified DNS service that can be used to query for a record with the given
 *		domain name.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param uuid
 *		The UUID of the resolver config to select.
 *
 *	@discussion
 *		If a service is returned, there's no guarantee that the reference will be valid after the next call to
 *		either <code>mdns_dns_service_manager_apply_dns_config()</code> or
 *		<code>mdns_dns_service_manager_apply_pending_updates()</code> unless the service is retained by the caller.
 *
 *	@result
 *		A non-retained service if a suitable service exists. Otherwise, NULL.
 */
mdns_dns_service_t _Nullable
mdns_dns_service_manager_get_uuid_scoped_service(mdns_dns_service_manager_t manager, const uuid_t _Nonnull uuid);

/*!
 *	@brief
 *		Fills out the UUID of a DNS service that should be used to query for a record with the given
 *		domain name.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param name
 *		The domain name in label format.
 *
 *	@param out_uuid
 *		The UUID of the resolver config to select.
 *
 *	@result
 *		Returns true if the UUID was filled out.
 */
bool
mdns_dns_service_manager_fillout_discovered_service_for_name(mdns_dns_service_manager_t manager, const uint8_t * const name,
															 uuid_t _Nonnull out_uuid);

/*!
 *	@brief
 *		Applies pending updates to the DNS service manager's DNS services.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@discussion
 *		This function applies pending updates having to do with each managed DNS service's interface properties,
 *		e.g., expensive, constrained, and clat46.
 *
 *		This function should be called when handling an <code>mdns_event_update</code> event.
 */
void
mdns_dns_service_manager_apply_pending_updates(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		The type for a block that handles a DNS service when iterating over a DNS service manager's services.
 *
 *	@param service
 *		The DNS service.
 *
 *	@result
 *		If true, then iteration will stop prematurely. If false, then iteration will continue.
 */
typedef bool
(^mdns_dns_service_applier_t)(mdns_dns_service_t service);

/*!
 *	@brief
 *		Iterates over each DNS service managed by a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 *
 *	@param applier
 *		Block to invoke for each DNS service.
 */
void
mdns_dns_service_manager_iterate(mdns_dns_service_manager_t manager, mdns_dns_service_applier_t applier);

/*!
 *	@brief
 *		Returns the number of DNS services being managed by a DNS service manager.
 *
 *	@param manager
 *		The DNS service manager.
 */
size_t
mdns_dns_service_manager_get_count(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		Performs tasks necessary for a DNS service manager to prepare for system sleep.
 *
 *	@param manager
 *		The DNS service manager.
 */
void
mdns_dns_service_manager_handle_sleep(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		Performs tasks necessary for a DNS service manager to prepare for system wake.
 *
 *	@param manager
 *		The DNS service manager.
 */
void
mdns_dns_service_manager_handle_wake(mdns_dns_service_manager_t manager);

/*!
 *	@brief
 *		Sets a DNS service's user-defined context.
 *
 *	@param service
 *		The DNS service.
 *
 *	@param context
 *		The user-defined context.
 *
 *	@discussion
 *		The last context set with this function can be retrieved with mdns_dns_service_get_context().
 *
 *		A DNS service's context is NULL by default.
 */
void
mdns_dns_service_set_context(mdns_dns_service_t service, void *context);

/*!
 *	@brief
 *		Gets a DNS service's user-defined context.
 *
 *	@param service
 *		The DNS service.
 *
 *	@result
 *		Returns the last context set with mdns_dns_service_set_context().
 */
void * _Nonnull
mdns_dns_service_get_context(mdns_dns_service_t service);

/*!
 *	@brief
 *		The type for a function that finalizes a user-defined context.
 *
 *	@param context
 *		The user-defined context.
 */
typedef void
(*mdns_context_finalizer_t)(void *context);

/*!
 *	@brief
 *		Sets a DNS service's context finalizer function.
 *
 *	@param service
 *		The DNS service.
 *
 *	@param finalizer
 *		The finalizer.
 *
 *	@discussion
 *		If a DNS service's context finalizer is not NULL and the service's context, which can be set with
 *		mdns_dns_service_set_context(), is not NULL when the service's last reference is released, then the
 *		finalizer will be invoked exactly once using the DNS service's context as an argument. The finalizer
 *		will be invoked under no other conditions.
 */
void
mdns_dns_service_set_context_finalizer(mdns_dns_service_t service, mdns_context_finalizer_t _Nullable finalizer);

/*!
 *	@brief
 *		Creates a querier to query a DNS service represented by a DNS service object.
 *
 *	@param service
 *		The DNS service.
 *
 *	@param out_error
 *		Pointer to an OSStatus variable, which will be set to the error that was encountered during creation.
 *
 *	@discussion
 *		If the DNS service is defunct, then no querier will be created.
 *
 *	@result
 *		A new querier object if the DNS service is not defunct and resources are available. Otherwise, NULL.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mdns_querier_t _Nullable
mdns_dns_service_create_querier(mdns_dns_service_t service, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Indicates a DNS service's scoping.
 *
 *	@const mdns_dns_service_scope_null
 *		An invalid scope to be used only as a placeholder.
 *
 *	@const mdns_dns_service_scope_none
 *		For unscoped DNS services.
 *
 *	@const mdns_dns_service_scope_interface
 *		For interface-scoped DNS services.
 *
 *	@const mdns_dns_service_scope_service
 *		For services-scoped DNS services.
 *
 *	@const mdns_dns_service_scope_uuid
 *		For UUID-scoped DNS services.
 *
 *	@const mdns_dns_service_scope_custom
 *		For custom DNS services.
 */
OS_CLOSED_ENUM(mdns_dns_service_scope, int,
	mdns_dns_service_scope_null			= 0,
	mdns_dns_service_scope_none			= 1,
	mdns_dns_service_scope_interface	= 2,
	mdns_dns_service_scope_service		= 3,
	mdns_dns_service_scope_uuid			= 4,
	mdns_dns_service_scope_custom		= 5
);

/*!
 *	@brief
 *		Gets a DNS service's scope.
 *
 *	@param service
 *		The DNS service.
 */
mdns_dns_service_scope_t
mdns_dns_service_get_scope(mdns_dns_service_t service);

/*!
 *	@brief
 *		Gets the index of the network interface used to access a DNS service.
 *
 *	@param service
 *		The DNS service.
 */
uint32_t
mdns_dns_service_get_interface_index(mdns_dns_service_t service);

/*!
 *	@brief
 *		Gets a DNS service's unique per-process ID.
 *
 *	@param service
 *		The DNS service.
 *
 *	@result
 *		If service is non-NULL, then the service's ID is returned. Otherwise, 0, which is an invalid ID, is
 *		returned.
 */
mdns_dns_service_id_t
mdns_dns_service_get_id(mdns_dns_service_t _Nullable service);

/*!
 *	@brief
 *		Determines whether or not a DNS service is defunct.
 *
 *	@param service
 *		The DNS service.
 *
 *	@discussion
 *		A DNS service becomes defunct when the DNS service manager that created it later applies a DNS
 *		configuration (with <code>mdns_dns_service_manager_apply_dns_config()</code>) that doesn't contain the DNS
 *		service.
 *
 *		When a DNS service is defunct, it is no longer usable, i.e., it is no longer capable of creating queriers.
 */
bool
mdns_dns_service_is_defunct(mdns_dns_service_t service);

/*!
 *	@brief
 *		Check if a DNS service uses an encrypted protocol.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_is_encrypted(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not A record queries are advised for a DNS service.
 *
 *	@param service
 *		The DNS service.
 *
 *	@discussion
 *		Mirrors the meaning of the DNS_RESOLVER_FLAGS_REQUEST_A_RECORDS flag in a DNS configuration.
 */
bool
mdns_dns_service_a_queries_advised(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not AAAA record queries are advised for a DNS service.
 *
 *	@param service
 *		The DNS service.
 *
 *	@discussion
 *		Mirrors the meaning of the DNS_RESOLVER_FLAGS_REQUEST_AAAA_RECORDS flag in a DNS configuration.
 */
bool
mdns_dns_service_aaaa_queries_advised(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service is currently experiencing connection problems.
 *
 *	@param service
 *		The DNS service.
 *
 *	@discussion
 *		This function currently only applies to DNS services that use DNS over HTTPS.
 *
 *		Since connection problems may be transient, a service with connection problems may still be used to
 *		create queriers.
 */
bool
mdns_dns_service_has_connection_problems(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface has IPv4 connectivity.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_has_ipv4_connectivity(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface has IPv6 connectivity.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_has_ipv6_connectivity(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface is a cellular interface.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_is_cellular(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface is expensive.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_is_expensive(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface is constrained.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_is_constrained(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface is clat46.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_is_clat46(mdns_dns_service_t service);

/*!
 *	@brief
 *		Determines whether or not a DNS service's interface is a VPN interface.
 *
 *	@param service
 *		The DNS service.
 */
bool
mdns_dns_service_interface_is_vpn(mdns_dns_service_t service);

/*!
 *	@brief
 *		Access the provider name, if applicable, used by this service.
 *
 *	@param service
 *		The DNS service.
 */
const char * _Nullable
mdns_dns_service_get_provider_name(mdns_dns_service_t service);

/*!
 *	@brief
 *		Gets the resolver type used by a DNS service.
 *
 *	@param service
 *		The DNS service.
 */
mdns_resolver_type_t
mdns_dns_service_get_resolver_type(mdns_dns_service_t service);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_DNS_SERVICE_H__
