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

#include "mdns_internal.h"
#include "mdns_dns_service.h"
#include "mdns_helpers.h"
#include "mdns_interface_monitor.h"
#include "mdns_objects.h"
#include "mdns_resolver.h"

#include "HTTPUtilities.h"
#include "DNSMessage.h"
#include <CoreUtils/CoreUtils.h>
#include <stdatomic.h>

//======================================================================================================================
// MARK: - DNS Service Manager Kind Definition

struct mdns_dns_service_manager_s {
	struct mdns_object_s	base;				// Object base.
	CFMutableArrayRef		default_services;	// DNS services from configd.
	CFMutableArrayRef		path_services;		// DNS services from path clients.
	CFMutableArrayRef		discovered_services;// DNS services discovered from DNS records.
	CFMutableArrayRef		custom_services;	// DNS services created for custom use.
	CFMutableArrayRef		monitors;			// Interface monitors.
	dispatch_queue_t		queue;				// Serial queue for interface monitor events.
	dispatch_queue_t		user_queue;			// User's queue for invoking user's event handler.
	dispatch_source_t		update_source;		// Data source for triggering update events.
	mdns_event_handler_t	event_handler;		// User's event handler.
	bool					report_symptoms;	// True if resolvers should report DNS symptoms.
	bool					invalidated;		// True if the manager has been invalidated.
	bool					terminated;			// True if the manager has been terminated.
	bool					user_activated;		// True if user called mdns_dns_service_manager_activate().
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	int						pqw_threshold;		// Threshold value for problematic QTYPE workaround.
#endif
};

MDNS_OBJECT_SUBKIND_DEFINE(dns_service_manager);

#define MDNS_DNS_SERVICE_MANAGER_ARRAYS(MANAGER)	\
	(MANAGER)->default_services,					\
	(MANAGER)->path_services,						\
	(MANAGER)->discovered_services,					\
	(MANAGER)->custom_services

//======================================================================================================================
// MARK: - DNS Service Kind Definition

OS_CLOSED_ENUM(mdns_dns_service_source, int,
	mdns_dns_service_source_sc		= 1,	// For DNS services defined by SystemConfiguration.
	mdns_dns_service_source_nw		= 2,	// For DNS services defined system-wide by libnetwork.
	mdns_dns_service_source_dns		= 3,	// For DNS services defined by SVCB/HTTPS DNS records.
	mdns_dns_service_source_custom	= 4		// For DNS services defined by on a client using an XPC dictionary.
);

OS_CLOSED_OPTIONS(mdns_dns_service_flags, uint32_t,
	mdns_dns_service_flag_null					= 0,			// Null flag.
	mdns_dns_service_flag_defunct				= (1U <<  0),	// DNS service is defunct.
	mdns_dns_service_flag_a_queries_advised		= (1U <<  1),	// Querying for A records is advised.
	mdns_dns_service_flag_aaaa_queries_advised	= (1U <<  2),	// Querying for AAAA records is advised.
	mdns_dns_service_flag_cellular				= (1U <<  3),	// DNS service's interface is cellular.
	mdns_dns_service_flag_ipv4_connectivity		= (1U <<  4),	// DNS service's interface has IPv4 connectivity.
	mdns_dns_service_flag_ipv6_connectivity		= (1U <<  5),	// DNS service's interface has IPv6 connectivity.
	mdns_dns_service_flag_expensive				= (1U <<  6),	// DNS service's interface is expensive.
	mdns_dns_service_flag_constrained			= (1U <<  7),	// DNS service's interface is constrained.
	mdns_dns_service_flag_clat46				= (1U <<  8),	// DNS service's interface is CLAT46.
	mdns_dns_service_flag_vpn					= (1U <<  9),	// DNS service's interface is VPN.
	mdns_dns_service_flag_connection_problems	= (1U << 10)	// DNS service is currently having connection problems.
);

#define MDNS_DNS_SERVICE_FLAGS_FROM_DNS_CONFIG		\
	(mdns_dns_service_flag_a_queries_advised	|	\
	 mdns_dns_service_flag_aaaa_queries_advised	|	\
	 mdns_dns_service_flag_cellular)				\

#define MDNS_DNS_SERVICE_FLAGS_FROM_INTERFACE_MONITOR (	\
	mdns_dns_service_flag_ipv4_connectivity	|			\
	mdns_dns_service_flag_ipv6_connectivity	|			\
	mdns_dns_service_flag_expensive			|			\
	mdns_dns_service_flag_constrained		|			\
	mdns_dns_service_flag_clat46			|			\
	mdns_dns_service_flag_vpn							\
)

// Make sure that the two sets of flags are mutually exclusive.
check_compile_time((MDNS_DNS_SERVICE_FLAGS_FROM_DNS_CONFIG & MDNS_DNS_SERVICE_FLAGS_FROM_INTERFACE_MONITOR) == 0);

struct _discovered_detail_s {
	nw_endpoint_t				url_endpoint;	// URL endpoint for discovered DNS services.
	uint64_t					use_time;		// Recent use time for discovered DNS service.
	uint64_t					expire_time;	// Expire time for discovered DNS service.
	bool						squash_cnames;	// Should squash CNAMEs.
};

typedef struct _domain_item_s *	_domain_item_t;

struct mdns_dns_service_s {
	struct mdns_object_s		base;				// Object base.
	mdns_resolver_t				resolver;			// The DNS service's resolver.
	CFMutableArrayRef			addresses;			// Addresses of servers that implement the DNS service.
	_domain_item_t				domain_list;		// List of domains that this DNS service should be used for.
	nw_resolver_config_t		config;				// Resolver config from nw_path.
	char *						if_name;			// Name of DNS service's network interface (for logging).
	mdns_dns_service_id_t		ident;				// The DNS service's process-wide unique identifier.
	void *						context;			// User-defined context.
	mdns_context_finalizer_t	context_finalizer;	// Finalizer for user-defined context.
	uint32_t					if_index;			// Index of DNS service's network interface.
	uint32_t					service_id;			// Service ID for service-scoped DNS services.
	int32_t						reg_count;			// Count of outstanding registrations for a custom DNS service.
	struct _discovered_detail_s discovered;			// Details for discovered DNS services.
	mdns_dns_service_source_t	source;				// Service's source.
	mdns_dns_service_scope_t	scope;				// The DNS service's scope type.
	mdns_dns_service_flags_t	flags;				// Flags that represent the service's properties.
	mdns_resolver_type_t		resolver_type;		// The resolver's type.
	bool						defuncting;			// True if the service becoming defunct is imminent.
	bool						cannot_connect;		// True if we cannot connect to the DNS service.
	bool						config_needs_cancel;// True if the new_resolver_config updates need to be cancelled.
	bool						replace_resolver;	// True if resolver needs to be replaced on wake.
};

MDNS_OBJECT_SUBKIND_DEFINE_FULL(dns_service);

struct _domain_item_s {
	_domain_item_t	next;			// Next item in list.
	uint8_t *		name;			// Domain name in label format.
	char *			name_str;		// Domain name as a C string.
	int				label_count;	// Domain name's label count for longest parent domain matching.
	uint32_t		order;			// Order value from associated dns_resolver_t object, if any.
};

//======================================================================================================================
// MARK: - Local Prototypes

static void
_mdns_dns_service_manager_terminate(mdns_dns_service_manager_t manager, OSStatus error);

static void
_mdns_dns_service_manager_add_service(mdns_dns_service_manager_t manager, CFMutableArrayRef services,
	mdns_dns_service_t service);

static mdns_dns_service_t
_mdns_dns_service_manager_get_service(mdns_dns_service_manager_t manager, const uint8_t *name,
	mdns_dns_service_scope_t scope, uint32_t scoping_id);

static mdns_dns_service_t
_mdns_dns_service_manager_get_uuid_scoped_service(mdns_dns_service_manager_t manager, const uuid_t uuid);

static mdns_dns_service_t
_mdns_dns_service_manager_get_discovered_service(mdns_dns_service_manager_t manager, nw_endpoint_t url_endpoint);

static void
_mdns_dns_service_manager_update_interface_properties(mdns_dns_service_manager_t manager);

static void
_mdns_dns_service_manager_remove_unneeded_interface_monitors(mdns_dns_service_manager_t manager);

static void
_mdns_dns_service_manager_update_interface_properties_for_services(mdns_dns_service_manager_t manager,
	CFArrayRef services);

static void
_mdns_dns_service_manager_update_interface_properties_for_service(mdns_dns_service_manager_t manager,
	mdns_dns_service_t service);

static mdns_dns_service_t
_mdns_dns_service_create(mdns_dns_service_source_t source, mdns_dns_service_scope_t scope,
	mdns_resolver_type_t resolver_type, OSStatus *out_error);

static void
_mdns_dns_service_manager_prepare_resolver(mdns_dns_service_manager_t manager, mdns_dns_service_t service);

static void
_mdns_dns_service_manager_start_defuncting(mdns_dns_service_manager_t manager, mdns_dns_service_t service);

static mdns_dns_service_t
_mdns_dns_service_manager_prepare_service(mdns_dns_service_manager_t manager, mdns_dns_service_t service);

static void
_mdns_dns_service_manager_trigger_update(mdns_dns_service_manager_t manager);

typedef bool (^mdns_dns_service_array_applier_t)(CFMutableArrayRef service_array);

static void
_mdns_dns_service_manager_iterate_over_all_service_arrays(mdns_dns_service_manager_t manager,
	mdns_dns_service_array_applier_t applier);

static void
_mdns_dns_service_make_defunct(mdns_dns_service_t service);

static bool
_mdns_dns_service_equal_ex(mdns_dns_service_t service, mdns_dns_service_t other, bool ignore_domains);

static OSStatus
_mdns_dns_service_add_domain(mdns_dns_service_t service, const char *name, uint32_t order);

static int
_mdns_dns_service_handles_domain_name(mdns_dns_service_t service, const uint8_t *name, uint32_t *out_order);

static mdns_resolver_type_t
_mdns_dns_service_get_resolver_type_safe(mdns_dns_service_t service);

static CFMutableArrayRef
_mdns_create_dns_service_array_from_config(const dns_config_t *config, OSStatus *out_error);

static mdns_dns_service_t
_mdns_dns_service_create_from_resolver_config(nw_resolver_config_t config, mdns_dns_service_source_t source,
	OSStatus *out_error);

static mdns_dns_service_id_t
_mdns_dns_service_get_id_safe(mdns_dns_service_t service);

static const uint8_t *
_mdns_domain_name_get_parent(const uint8_t *name, int depth);

static void
_domain_item_free(_domain_item_t item);

static int
_domain_item_compare(const struct _domain_item_s *d1, const struct _domain_item_s *d2, bool ignore_order);

//======================================================================================================================
// MARK: - Internals

MDNS_LOG_CATEGORY_DEFINE(dns_service, "dns_service");

//======================================================================================================================
// MARK: - DNS Service Manager Public Methods

mdns_dns_service_manager_t
mdns_dns_service_manager_create(const dispatch_queue_t user_queue, OSStatus * const out_error)
{
	OSStatus err;
	mdns_dns_service_manager_t manager = NULL;
	mdns_dns_service_manager_t obj = _mdns_dns_service_manager_alloc();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->default_services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->default_services, exit, err = kNoResourcesErr);

	obj->path_services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->path_services, exit, err = kNoResourcesErr);

	obj->discovered_services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->discovered_services, exit, err = kNoResourcesErr);

	obj->custom_services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->custom_services, exit, err = kNoResourcesErr);

	obj->monitors = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->monitors, exit, err = kNoResourcesErr);

	obj->queue = dispatch_queue_create("com.apple.mdns.dns-service-manager", DISPATCH_QUEUE_SERIAL);
	require_action_quiet(obj->queue, exit, err = kNoResourcesErr);

	obj->user_queue = user_queue;
	dispatch_retain(obj->user_queue);

	manager = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mdns_release_null_safe(obj);
	return manager;
}

//======================================================================================================================

void
mdns_dns_service_manager_set_report_symptoms(const mdns_dns_service_manager_t me, const bool report_symptoms)
{
	if (!me->user_activated) {
		me->report_symptoms = report_symptoms;
	}
}

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
void
mdns_dns_service_manager_enable_problematic_qtype_workaround(const mdns_dns_service_manager_t me, const int threshold)
{
	require_return(!me->user_activated);
	me->pqw_threshold = threshold;
}
#endif

//======================================================================================================================

void
mdns_dns_service_manager_set_event_handler(const mdns_dns_service_manager_t me, const mdns_event_handler_t handler)
{
	if (!me->user_activated) {
		const mdns_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
		if (me->event_handler) {
			Block_release(me->event_handler);
		}
		me->event_handler = new_handler;
	}
}

//======================================================================================================================

void
_mdns_dns_service_manager_activate_internal(mdns_dns_service_manager_t manager);

void
mdns_dns_service_manager_activate(const mdns_dns_service_manager_t me)
{
	require_return(!me->user_activated);

	me->user_activated = true;
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_activate_internal(me);
	});
}

void
_mdns_dns_service_manager_activate_internal(const mdns_dns_service_manager_t me)
{
	require_return(!me->update_source);
	me->update_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, me->user_queue);
	if (me->update_source) {
		mdns_retain(me);
		dispatch_source_set_event_handler(me->update_source,
		^{
			if (me->event_handler) {
				me->event_handler(mdns_event_update, kNoErr);
			}
		});
		dispatch_source_set_cancel_handler(me->update_source,
		^{
			mdns_release(me);
		});
		dispatch_activate(me->update_source);
	} else {
		_mdns_dns_service_manager_terminate(me, kNoResourcesErr);
	}
}

//======================================================================================================================

static void
_mdns_dns_service_manager_apply_dns_config_internal(mdns_dns_service_manager_t manager, const dns_config_t *config);

void
mdns_dns_service_manager_apply_dns_config(const mdns_dns_service_manager_t me, const dns_config_t * const config)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_apply_dns_config_internal(me, config);
	});
}

#define MDNS_TARGET_DISCOVERED_SERVICE_COUNT 4

static CFComparisonResult
_mdns_dns_service_compare_time(const void *val1, const void *val2, __unused void *context)
{
	const mdns_dns_service_t service1 = (const mdns_dns_service_t)val1;
	const mdns_dns_service_t service2 = (const mdns_dns_service_t)val2;

	if (service1->discovered.use_time > service2->discovered.use_time) {
		return kCFCompareLessThan;
	} else if (service1->discovered.use_time < service2->discovered.use_time) {
		return kCFCompareGreaterThan;
	} else {
		return kCFCompareEqualTo;
	}
}

static void
_mdns_dns_service_manager_purge_discovered_services(const mdns_dns_service_manager_t me)
{
	const CFIndex n = CFArrayGetCount(me->discovered_services);
	if (n < MDNS_TARGET_DISCOVERED_SERVICE_COUNT) {
		return;
	}

	os_log(_mdns_dns_service_log(), "Purging %u discovered services down to 4", (uint32_t)n);

	// Create a new array to hold the remaining services
	CFMutableArrayRef remaining_services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);

	// Sort by recent use
	CFMutableArrayRef recent_services = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, me->discovered_services);
	CFArraySortValues(recent_services, CFRangeMake(0, n), _mdns_dns_service_compare_time, NULL);

	// Reduce number of services down to target by defuncting them
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(recent_services, i);
		if (i >= MDNS_TARGET_DISCOVERED_SERVICE_COUNT) {
			_mdns_dns_service_make_defunct(service);
		} else {
			CFArrayAppendValue(remaining_services, service);
		}
	}
	ForgetCF(&recent_services);

	ForgetCF(&me->discovered_services);
	me->discovered_services = remaining_services;
	remaining_services = NULL;
}

static void
_mdns_dns_service_manager_apply_dns_config_internal(const mdns_dns_service_manager_t me,
	const dns_config_t * const config)
{
	_mdns_dns_service_manager_purge_discovered_services(me);

	OSStatus err;
	CFMutableArrayRef new_services = _mdns_create_dns_service_array_from_config(config, &err);
	require_noerr_quiet(err, exit);

	// Keep DNS services that still exist, and mark those that no longer exist as defunct.
	const CFRange full_range = CFRangeMake(0, CFArrayGetCount(new_services));
	for (CFIndex i = CFArrayGetCount(me->default_services) - 1; i >= 0; --i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->default_services, i);
		const CFIndex j = CFArrayGetFirstIndexOfValue(new_services, full_range, service);
		if (j >= 0) {
			// The service still exists, but its flags may have changed.
			const mdns_dns_service_t new_service = (mdns_dns_service_t)CFArrayGetValueAtIndex(new_services, j);
			service->flags &= ~MDNS_DNS_SERVICE_FLAGS_FROM_DNS_CONFIG;
			service->flags |= (new_service->flags & MDNS_DNS_SERVICE_FLAGS_FROM_DNS_CONFIG);

			// Replace the new service object with the established one.
			CFArraySetValueAtIndex(new_services, j, service);
		} else {
			// The service no longer exists.
			_mdns_dns_service_make_defunct(service);
		}
	}
	CFRelease(me->default_services);
	me->default_services = new_services;
	new_services = NULL;

	_mdns_dns_service_manager_remove_unneeded_interface_monitors(me);
	_mdns_dns_service_manager_update_interface_properties_for_services(me, me->default_services);

exit:
	if (err) {
		_mdns_dns_service_manager_terminate(me, err);
	}
}

//======================================================================================================================

static void
_mdns_dns_service_manager_register_path_resolver_internal(mdns_dns_service_manager_t manager,
	const uuid_t resolver_config_uuid);

static void
_mdns_dns_service_manager_handle_resolver_config_removal(mdns_dns_service_manager_t manager,
	nw_resolver_config_t config);

static void
_mdns_dns_service_manager_cancel_resolver_config_updates(mdns_dns_service_manager_t manager,
	nw_resolver_config_t config);

void
mdns_dns_service_manager_register_path_resolver(const mdns_dns_service_manager_t me, const uuid_t resolver_config_uuid)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_register_path_resolver_internal(me, resolver_config_uuid);
	});
}

static void
_mdns_dns_service_manager_register_path_resolver_internal(const mdns_dns_service_manager_t me,
	const uuid_t config_uuid)
{
	mdns_dns_service_t service = _mdns_dns_service_manager_get_uuid_scoped_service(me, config_uuid);
	require_return_action(!service, os_log_debug(_mdns_dns_service_log(),
		"Already registered service -- service id: %llu, uuid: %{uuid_t}.16P", service->ident, config_uuid));

	// Need a new service in the path array.
	nw_resolver_config_t _Nonnull config = nw_resolver_config_create();
	nw_resolver_config_set_identifier(config, config_uuid);

	// Calling nw_resolver_config_watch_updates will fill out the contents of the resolver.
	mdns_retain(me);
	nw_retain(config);
	nw_resolver_config_watch_updates(config, me->queue,
	^(const bool removed)
	{
		if (removed) {
			_mdns_dns_service_manager_handle_resolver_config_removal(me, config);
		}
	});
	OSStatus err;
	service = _mdns_dns_service_create_from_resolver_config(config, mdns_dns_service_source_nw, &err);
	if (service) {
		service->config_needs_cancel = true;
		_mdns_dns_service_manager_add_service(me, me->path_services, service);
		os_log(_mdns_dns_service_log(), "Registered service -- %@", service);
		mdns_forget(&service);
	} else {
		_mdns_dns_service_manager_cancel_resolver_config_updates(me, config);
		os_log_error(_mdns_dns_service_log(),
			"Failed to register service -- uuid: %{uuid_t}.16P, config: %@, error: %{mdns:err}ld",
			config_uuid, config, (long)err);
	}
	nw_release(config);
}

static void
_mdns_dns_service_manager_handle_resolver_config_removal(const mdns_dns_service_manager_t me,
	const nw_resolver_config_t config)
{
	const CFIndex n = CFArrayGetCount(me->path_services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->path_services, i);
		if (service->config == config) {
			os_log(_mdns_dns_service_log(), "Removing service -- %@", service);
			// Cancel the config's updates now and mark the service as defuncting.
			// The service will ultimately be made defunct when the user accepts the next set of pending updates.
			if (service->config_needs_cancel) {
				service->config_needs_cancel = false;
				_mdns_dns_service_manager_cancel_resolver_config_updates(me, service->config);
			}
			_mdns_dns_service_manager_start_defuncting(me, service);
			break;
		}
	}
}

static void
_mdns_dns_service_manager_cancel_resolver_config_updates(const mdns_dns_service_manager_t me,
	const nw_resolver_config_t config)
{
	nw_resolver_config_cancel_updates(config, me->queue,
	^{
		mdns_release(me);
		nw_release(config);
	});
}

//======================================================================================================================

static mdns_dns_service_id_t
_mdns_dns_service_manager_register_custom_service_internal(mdns_dns_service_manager_t manager,
	xpc_object_t resolver_config_dict);

static mdns_dns_service_t
_mdns_dns_service_manager_get_custom_service_by_uuid(mdns_dns_service_manager_t manager, const uuid_t config_uuid);

mdns_dns_service_id_t
mdns_dns_service_manager_register_custom_service(const mdns_dns_service_manager_t me,
	const xpc_object_t resolver_config_dict)
{
	__block mdns_dns_service_id_t ident;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, ident = 0);
		ident = _mdns_dns_service_manager_register_custom_service_internal(me, resolver_config_dict);
	});
	return ident;
}

static mdns_dns_service_id_t
_mdns_dns_service_manager_register_custom_service_internal(const mdns_dns_service_manager_t me,
	const xpc_object_t resolver_config_dict)
{
	nw_resolver_config_t config = NULL;
	mdns_dns_service_t service = NULL;

	// Parse the dictionary
	config = nw_resolver_config_create_with_dictionary(resolver_config_dict);
	if (unlikely(!config)) {
		char *dict_desc = xpc_copy_description(resolver_config_dict);
		os_log_error(_mdns_dns_service_log(),
			"Failed to create nw_resolver_config for dictionary: %s", dict_desc ? dict_desc : "<NO DESC.>");
		ForgetMem(&dict_desc);
		goto exit;
	}
	uuid_t config_uuid = {0};
	nw_resolver_config_get_identifier(config, config_uuid);
	service = _mdns_dns_service_manager_get_custom_service_by_uuid(me, config_uuid);
	if (!service) {
		OSStatus err;
		service = _mdns_dns_service_create_from_resolver_config(config, mdns_dns_service_source_custom, &err);
		if (service) {
			_mdns_dns_service_manager_add_service(me, me->custom_services, service);
			os_log(_mdns_dns_service_log(), "Registered custom service -- %@", service);
			mdns_release(service);
		} else {
			os_log_error(_mdns_dns_service_log(),
				"Failed to register custom service -- uuid: %{uuid_t}.16P, config: %@, error: %{mdns:err}ld",
				config_uuid, config, (long)err);
		}
	}
	if (service) {
		if (service->reg_count++ != 0) {
			os_log_info(_mdns_dns_service_log(),
				"Registered custom service -- service id: %llu, registration count: %d",
				service->ident, service->reg_count);
		}
	}

exit:
	nw_forget(&config);
	return _mdns_dns_service_get_id_safe(service);
}

static mdns_dns_service_t
_mdns_dns_service_manager_get_custom_service_by_uuid(const mdns_dns_service_manager_t me, const uuid_t config_uuid)
{
	const CFIndex n = CFArrayGetCount(me->custom_services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->custom_services, i);
		if (service->config) {
			uuid_t match_uuid = {0};
			nw_resolver_config_get_identifier(service->config, match_uuid);
			if (uuid_compare(match_uuid, config_uuid) == 0) {
				return service;
			}
		}
	}
	return NULL;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_deregister_custom_service_internal(mdns_dns_service_manager_t manager,
	mdns_dns_service_id_t ident);

void
mdns_dns_service_manager_deregister_custom_service(const mdns_dns_service_manager_t me,
	const mdns_dns_service_id_t ident)
{
	require_return(ident != 0);
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_deregister_custom_service_internal(me, ident);
	});
}

static void
_mdns_dns_service_manager_deregister_custom_service_internal(const mdns_dns_service_manager_t me,
	const mdns_dns_service_id_t ident)
{
	const CFIndex n = CFArrayGetCount(me->custom_services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->custom_services, i);
		if (service->ident == ident) {
			--service->reg_count;
			os_log_with_type(_mdns_dns_service_log(),
				(service->reg_count == 0) ? OS_LOG_TYPE_DEFAULT : OS_LOG_TYPE_INFO,
				"Deregistered custom service -- service id: %llu, registration count: %d",
				service->ident, service->reg_count);
			if (service->reg_count == 0) {
				_mdns_dns_service_manager_start_defuncting(me, service);
			}
			break;
		}
	}
}

//======================================================================================================================

static void
_mdns_dns_service_manager_register_doh_uri_internal(mdns_dns_service_manager_t manager,
	const char *doh_uri, const char *domain);

static mdns_dns_service_t
_mdns_dns_service_create_from_doh_uri(nw_endpoint_t url_endpoint, OSStatus *out_error);

void
mdns_dns_service_manager_register_doh_uri(const mdns_dns_service_manager_t me,
	const char *doh_uri, const char *domain)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_register_doh_uri_internal(me, doh_uri, domain);
	});
}

static void
_mdns_dns_service_manager_fetch_trusted_name_pvd(const mdns_dns_service_manager_t me,
	mdns_dns_service_t service, nw_endpoint_t doh_endpoint,
	xpc_object_t dns_zone_array, const char *trusted_name)
{
	if (doh_endpoint == NULL || trusted_name == NULL ||
		dns_zone_array == NULL || xpc_get_type(dns_zone_array) != XPC_TYPE_ARRAY) {
		return;
	}

	char *trusted_name_suffix = NULL;
	asprintf(&trusted_name_suffix, ".%s", trusted_name);

	xpc_object_t candidate_dns_zones = xpc_array_create(NULL, 0);
	xpc_array_apply(dns_zone_array, ^bool(__unused size_t index, xpc_object_t _Nonnull array_value) {
		if (xpc_get_type(array_value) == XPC_TYPE_STRING) {
			const char *dns_zone = xpc_string_get_string_ptr(array_value);

			if (strcasecmp(trusted_name, dns_zone) == 0) {
				// Exact match
				xpc_array_append_value(candidate_dns_zones, array_value);
			} else {
				size_t trusted_name_suffix_length = strlen(trusted_name_suffix);
				size_t dns_zone_length = strlen(dns_zone);
				if (trusted_name_suffix_length <= dns_zone_length) {
					if (strcasecmp(trusted_name_suffix, dns_zone + (dns_zone_length - trusted_name_suffix_length)) == 0) {
						// Suffix match
						xpc_array_append_value(candidate_dns_zones, array_value);
					}
				}
			}
		}
		return true;
	});

	free(trusted_name_suffix);

	if (xpc_array_get_count(candidate_dns_zones) == 0) {
		xpc_forget(&candidate_dns_zones);
		return;
	}

	__block void *trusted_name_task = NULL;
	nw_retain(doh_endpoint);
	mdns_retain(service);
	// candidate_dns_zones is already retained
	nw_endpoint_t trusted_name_endpoint = nw_endpoint_create_host(trusted_name, "443");
	trusted_name_task = http_task_create_pvd_query(me->queue,
												   trusted_name, "", ^(xpc_object_t trusted_name_json) {
		do {
			if (trusted_name_json != NULL) {
				const char *trusted_doh_template = xpc_dictionary_get_string(trusted_name_json, "dohTemplate");
				if (trusted_doh_template == NULL) {
					os_log_error(_mdns_dns_service_log(), "Trusted name %@ missing DoH template", trusted_name_endpoint);
					break;
				}

				const char *inner_doh_string = nw_endpoint_get_url(doh_endpoint);
				if (inner_doh_string == NULL || strcasecmp(trusted_doh_template, inner_doh_string) != 0) {
					os_log_error(_mdns_dns_service_log(), "DoH resolver for %@ does not match trusted DoH template %s for %@",
								 doh_endpoint, trusted_doh_template, trusted_name_endpoint);
					break;
				}

				os_log(_mdns_dns_service_log(), "DoH resolver at %@ is trusted for %@",
					   doh_endpoint, trusted_name_endpoint);

				xpc_array_apply(candidate_dns_zones, ^bool(__unused size_t index, xpc_object_t _Nonnull array_value) {
					const char *dns_zone = xpc_string_get_string_ptr(array_value);

					os_log(_mdns_dns_service_log(), "Adding domain %s to discovered DoH resolver for %@",
						   dns_zone, doh_endpoint);
					_mdns_dns_service_add_domain(service, dns_zone, 0);
					return true;
				});
			} else {
				os_log_error(_mdns_dns_service_log(), "No PvD file found at %@ for DoH server %@",
							 trusted_name_endpoint, doh_endpoint);
			}
		} while (0);
		http_task_cancel(trusted_name_task);
		nw_release(trusted_name_endpoint);
		nw_release(doh_endpoint);
		xpc_release(candidate_dns_zones);
		mdns_release(service);
	});
	http_task_start(trusted_name_task);
}

static uint64_t
_mdns_get_future_continuous_time(uint64_t seconds)
{
	static dispatch_once_t onceToken;
	static mach_timebase_info_data_t time_base = {0, 0};
	dispatch_once(&onceToken, ^{
		mach_timebase_info(&time_base);
	});
	uint64_t delta = seconds * NSEC_PER_SEC;
	delta *= time_base.denom;
	delta /= time_base.numer;
	return mach_continuous_time() + delta;
}

static void
_mdns_dns_service_manager_fetch_doh_pvd(const mdns_dns_service_manager_t me,
	mdns_dns_service_t service)
{
	__block void *task = NULL;
	mdns_retain(service);

	nw_endpoint_t doh_endpoint = service->discovered.url_endpoint;
	nw_retain(doh_endpoint);
	task = http_task_create_pvd_query(me->queue,
									  nw_endpoint_get_hostname(doh_endpoint),
									  nw_endpoint_get_url_path(doh_endpoint), ^(xpc_object_t json_object) {
		do {
			if (json_object != NULL) {
				const char *doh_template = xpc_dictionary_get_string(json_object, "dohTemplate");
				if (doh_template == NULL) {
					os_log_error(_mdns_dns_service_log(), "DoH resolver for %@ missing DoH template", doh_endpoint);
					break;
				}

				// If the string is suffixed by a string like "{?dns}", trim off that variable template
				size_t template_length = strlen(doh_template);
				const char *template_portion = strchr(doh_template, '{');
				if (template_portion != NULL) {
					template_length = (size_t)(template_portion - doh_template);
				}

				const char *doh_string = nw_endpoint_get_url(doh_endpoint);
				if (doh_string == NULL ||
					strlen(doh_string) != template_length ||
					strncasecmp(doh_template, doh_string, template_length) != 0) {
					os_log_error(_mdns_dns_service_log(), "DoH resolver for %@ does not match DoH template %s",
								 doh_endpoint, doh_template);
					break;
				}

				uint64_t seconds_remaining = xpc_dictionary_get_uint64(json_object, "secondsRemaining");
				if (seconds_remaining == 0) {
					seconds_remaining = xpc_dictionary_get_uint64(json_object, "seconds-remaining");
				}
				if (seconds_remaining != 0) {
					os_log_info(_mdns_dns_service_log(), "DoH resolver for %@ will expire in %llu seconds",
								doh_endpoint, seconds_remaining);
					service->discovered.expire_time = _mdns_get_future_continuous_time(seconds_remaining);
				} else {
					os_log_info(_mdns_dns_service_log(), "DoH resolver for %@ does not specify an expiration",
								doh_endpoint);
					service->discovered.expire_time = 0;
				}

				xpc_object_t dns_zone_array = xpc_dictionary_get_value(json_object, "dnsZones");

				xpc_object_t trusted_names_array = xpc_dictionary_get_value(json_object, "trustedNames");
				if (trusted_names_array && xpc_get_type(trusted_names_array) == XPC_TYPE_ARRAY) {
					xpc_array_apply(trusted_names_array, ^bool(__unused size_t index, xpc_object_t _Nonnull array_value) {
						if (xpc_get_type(array_value) == XPC_TYPE_STRING) {
							const char *trusted_name = xpc_string_get_string_ptr(array_value);
							os_log(_mdns_dns_service_log(), "Query trusted name %s for DoH resolver for %@",
								   trusted_name, doh_endpoint);
							_mdns_dns_service_manager_fetch_trusted_name_pvd(me, service, doh_endpoint, dns_zone_array, trusted_name);
						}
						return true;
					});
				}
			}
		} while (0);
		http_task_cancel(task);
		mdns_release(service);
		nw_release(doh_endpoint);
	});
	http_task_start(task);
}

static void
_mdns_dns_service_manager_check_service_expiration(const mdns_dns_service_manager_t me,
	mdns_dns_service_t service)
{
	// Check if a service is expired
	if (service->discovered.expire_time != 0 &&
		service->discovered.expire_time < mach_continuous_time()) {

		os_log_info(_mdns_dns_service_log(), "DoH resolver for %@ has passed expiration",
					service->discovered.url_endpoint);

		service->discovered.expire_time = 0;

		// Clear out domain list, in case they have changed
		_domain_item_t item;
		while ((item = service->domain_list) != NULL) {
			service->domain_list = item->next;
			_domain_item_free(item);
		}

		// Refresh PvD to rebuild the list
		_mdns_dns_service_manager_fetch_doh_pvd(me, service);
	}
}

static void
_mdns_dns_service_manager_register_doh_uri_internal(const mdns_dns_service_manager_t me,
	const char *doh_uri, const char *domain)
{
	mdns_dns_service_t service = NULL;
	nw_endpoint_t doh_endpoint = NULL;
	char *uri_string;
	OSStatus err;

	// Make a copy of the string in case it needs to be sanitized
	uri_string = strdup(doh_uri);
	require_quiet(uri_string, exit);

	// If the string is suffixed by a string like "{?dns}", trim off that variable template
	char *template_portion = strchr(uri_string, '{');
	if (template_portion != NULL) {
		template_portion[0] = '\0';
	}

	doh_endpoint = nw_endpoint_create_url(uri_string);
	require_action_quiet(doh_endpoint, exit, err = kNoResourcesErr);

	const char *scheme = nw_endpoint_get_url_scheme(doh_endpoint);
	require_action_quiet((scheme != NULL && strcasecmp("https", scheme) == 0), exit, err = kMalformedErr);

	service = _mdns_dns_service_manager_get_discovered_service(me, doh_endpoint);
	if (service == NULL) {
		os_log(_mdns_dns_service_log(), "Registering discovered DoH resolver at %s", uri_string);

		service = _mdns_dns_service_create_from_doh_uri(doh_endpoint, NULL);
		if (service) {
			_mdns_dns_service_manager_add_service(me, me->discovered_services, service);
			mdns_release(service);
			_mdns_dns_service_manager_fetch_doh_pvd(me, service);
		}
	}

	if (service && domain) {
		os_log(_mdns_dns_service_log(), "Adding domain %s to DoH resolver at %s", domain, uri_string);
		_mdns_dns_service_add_domain(service, domain, 0);
	}

exit:
	free(uri_string);
	nw_forget(&doh_endpoint);
	return;
}

static mdns_dns_service_t
_mdns_dns_service_create_from_doh_uri(nw_endpoint_t url_endpoint, OSStatus * const out_error)
{
	nw_resolver_config_t config = nw_resolver_config_create();
	nw_resolver_config_set_class(config, nw_resolver_class_designated);
	nw_resolver_config_set_protocol(config, nw_resolver_protocol_doh);
	nw_resolver_config_set_provider_name(config, nw_endpoint_get_hostname(url_endpoint));
	nw_resolver_config_set_provider_path(config, nw_endpoint_get_url_path(url_endpoint));

	uuid_t new_identifier;
	uuid_generate(new_identifier);
	nw_resolver_config_set_identifier(config, new_identifier);

	OSStatus err;
	const mdns_dns_service_t service = _mdns_dns_service_create(mdns_dns_service_source_dns,
		mdns_dns_service_scope_uuid, mdns_resolver_type_null, &err);
	require_noerr_quiet(err, exit);

	service->discovered.url_endpoint = nw_retain(url_endpoint);
	service->discovered.squash_cnames = true;
	service->config = config;
	config = NULL;
	service->flags = (mdns_dns_service_flag_a_queries_advised | mdns_dns_service_flag_aaaa_queries_advised);

exit:
	if (out_error) {
		*out_error = err;
	}
	nw_forget(&config);
	return service;
}

//======================================================================================================================

void
mdns_dns_service_manager_invalidate(const mdns_dns_service_manager_t me)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->invalidated);
		_mdns_dns_service_manager_terminate(me, kNoErr);
		me->invalidated = true;
	});
}

//======================================================================================================================

mdns_dns_service_t
mdns_dns_service_manager_get_unscoped_service(const mdns_dns_service_manager_t me, const uint8_t * const name)
{
	__block mdns_dns_service_t result;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, result = NULL);
		const mdns_dns_service_scope_t scope = mdns_dns_service_scope_none;
		const mdns_dns_service_t service = _mdns_dns_service_manager_get_service(me, name, scope, 0);
		result = _mdns_dns_service_manager_prepare_service(me, service);
	});
	return result;
}

//======================================================================================================================

mdns_dns_service_t
mdns_dns_service_manager_get_interface_scoped_service(const mdns_dns_service_manager_t me, const uint8_t * const name,
	const uint32_t if_index)
{
	__block mdns_dns_service_t result;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, result = NULL);
		const mdns_dns_service_scope_t scope = mdns_dns_service_scope_interface;
		const mdns_dns_service_t service = _mdns_dns_service_manager_get_service(me, name, scope, if_index);
		result = _mdns_dns_service_manager_prepare_service(me, service);
	});
	return result;
}

//======================================================================================================================

mdns_dns_service_t
mdns_dns_service_manager_get_service_scoped_service(const mdns_dns_service_manager_t me, const uint8_t * const name,
	const uint32_t service_id)
{
	__block mdns_dns_service_t result;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, result = NULL);
		const mdns_dns_service_scope_t scope = mdns_dns_service_scope_service;
		const mdns_dns_service_t service = _mdns_dns_service_manager_get_service(me, name, scope, service_id);
		result = _mdns_dns_service_manager_prepare_service(me, service);
	});
	return result;
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_manager_get_custom_service(mdns_dns_service_manager_t manager, mdns_dns_service_id_t ident);

mdns_dns_service_t
mdns_dns_service_manager_get_custom_service(const mdns_dns_service_manager_t me, const mdns_dns_service_id_t ident)
{
	__block mdns_dns_service_t result;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, result = NULL);
		const mdns_dns_service_t service = _mdns_dns_service_manager_get_custom_service(me, ident);
		result = _mdns_dns_service_manager_prepare_service(me, service);
	});
	return result;
}

static mdns_dns_service_t
_mdns_dns_service_manager_get_custom_service(const mdns_dns_service_manager_t me, const mdns_dns_service_id_t ident)
{
	const CFIndex n = CFArrayGetCount(me->custom_services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->custom_services, i);
		if (service->ident == ident) {
			return service;
		}
	}
	return NULL;
}

//======================================================================================================================

mdns_dns_service_t
mdns_dns_service_manager_get_uuid_scoped_service(const mdns_dns_service_manager_t me, const uuid_t uuid)
{
	__block mdns_dns_service_t result;
	dispatch_sync(me->queue,
	^{
		require_return_action(!me->terminated, result = NULL);
		const mdns_dns_service_t service = _mdns_dns_service_manager_get_uuid_scoped_service(me, uuid);
		result = _mdns_dns_service_manager_prepare_service(me, service);
	});
	return result;
}

//======================================================================================================================

bool
_mdns_dns_service_manager_fillout_discovered_service_for_name(mdns_dns_service_manager_t manager,
	const uint8_t *name, uuid_t out_uuid);

bool
mdns_dns_service_manager_fillout_discovered_service_for_name(const mdns_dns_service_manager_t me,
	const uint8_t * const name, uuid_t out_uuid)
{
	__block bool success = false;
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		success = _mdns_dns_service_manager_fillout_discovered_service_for_name(me, name, out_uuid);
	});
	return success;
}

bool
_mdns_dns_service_manager_fillout_discovered_service_for_name(const mdns_dns_service_manager_t me,
	const uint8_t * const name, uuid_t out_uuid)
{
	mdns_dns_service_t	service				= NULL;
	int					best_label_count	= -1;
	const CFIndex n = CFArrayGetCount(me->discovered_services);
	for (CFIndex i = 0; i < n; ++i) {
		mdns_dns_service_t candidate = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->discovered_services, i);
		const int label_count = _mdns_dns_service_handles_domain_name(candidate, name, NULL);
		if (candidate->config && (label_count > best_label_count)) {
			service				= candidate;
			best_label_count	= label_count;
		}

		// Check if service details have expired while iterating the list
		_mdns_dns_service_manager_check_service_expiration(me, candidate);
	}

	if (service) {
		// Update the most recent use (approximate) time for this service
		service->discovered.use_time = mach_continuous_approximate_time();
		nw_resolver_config_get_identifier(service->config, out_uuid);
		return true;
	}
	return false;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_apply_pending_updates_internal(mdns_dns_service_manager_t manager);

static void
_mdns_dns_service_manager_finish_defuncting_services(CFMutableArrayRef services);

static void
_mdns_dns_service_manager_update_service_usability(CFMutableArrayRef services);

void
mdns_dns_service_manager_apply_pending_updates(const mdns_dns_service_manager_t me)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_apply_pending_updates_internal(me);
	});
}

static void
_mdns_dns_service_manager_apply_pending_updates_internal(const mdns_dns_service_manager_t me)
{
	_mdns_dns_service_manager_finish_defuncting_services(me->path_services);
	_mdns_dns_service_manager_finish_defuncting_services(me->custom_services);
	_mdns_dns_service_manager_update_service_usability(me->path_services);
	_mdns_dns_service_manager_update_service_usability(me->discovered_services);
	_mdns_dns_service_manager_update_service_usability(me->custom_services);
	_mdns_dns_service_manager_remove_unneeded_interface_monitors(me);
	_mdns_dns_service_manager_update_interface_properties(me);
}

static void
_mdns_dns_service_manager_finish_defuncting_services(const CFMutableArrayRef services)
{
	for (CFIndex i = CFArrayGetCount(services) - 1; i >= 0; --i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		if (service->defuncting) {
			_mdns_dns_service_make_defunct(service);
			CFArrayRemoveValueAtIndex(services, i);
		}
	}
}

static void
_mdns_dns_service_manager_update_service_usability(const CFMutableArrayRef services)
{
	const CFIndex n = CFArrayGetCount(services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		if (service->cannot_connect) {
			if (!(service->flags & mdns_dns_service_flag_connection_problems)) {
				service->flags |= mdns_dns_service_flag_connection_problems;
			}
		} else {
			if (service->flags & mdns_dns_service_flag_connection_problems) {
				service->flags &= ~mdns_dns_service_flag_connection_problems;
			}
		}
	}
}

//======================================================================================================================

void
mdns_dns_service_manager_iterate(const mdns_dns_service_manager_t me, const mdns_dns_service_applier_t applier)
{
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_iterate_over_all_service_arrays(me,
		^ bool (const CFMutableArrayRef service_array)
		{
			bool stop = false;
			const CFIndex n = CFArrayGetCount(service_array);
			for (CFIndex i = 0; i < n; ++i) {
				const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(service_array, i);
				stop = applier(service);
				if (stop) {
					break;
				}
			}
			return stop;
		});
	});
}

//======================================================================================================================

size_t
mdns_dns_service_manager_get_count(const mdns_dns_service_manager_t me)
{
	__block size_t count = 0;
	dispatch_sync(me->queue,
	^{
		require_return(!me->terminated);
		_mdns_dns_service_manager_iterate_over_all_service_arrays(me,
		^ bool (const CFMutableArrayRef service_array)
		{
			count += (size_t)CFArrayGetCount(service_array);
			return false;
		});
	});
	return count;
}

//======================================================================================================================

void
mdns_dns_service_manager_handle_sleep(const mdns_dns_service_manager_t me)
{
	mdns_dns_service_manager_iterate(me,
	^ bool (const mdns_dns_service_t service)
	{
		const mdns_resolver_type_t type = _mdns_dns_service_get_resolver_type_safe(service);
		if ((type == mdns_resolver_type_tls) || (type == mdns_resolver_type_https)) {
			if (service->resolver) {
				mdns_resolver_forget(&service->resolver);
				service->replace_resolver = true;
			}
		}
		return false;
	});
}

//======================================================================================================================

void
mdns_dns_service_manager_handle_wake(const mdns_dns_service_manager_t me)
{
	mdns_dns_service_manager_iterate(me,
	^ bool (const mdns_dns_service_t service)
	{
		if (service->replace_resolver) {
			_mdns_dns_service_manager_prepare_service(me, service);
			service->replace_resolver = false;
		}
		return false;
	});
}

//======================================================================================================================
// MARK: - DNS Service Manager Private Methods

static void
_mdns_dns_service_manager_finalize(mdns_dns_service_manager_t me)
{
	ForgetCF(&me->default_services);
	ForgetCF(&me->path_services);
	ForgetCF(&me->discovered_services);
	ForgetCF(&me->custom_services);
	ForgetCF(&me->monitors);
	dispatch_forget(&me->queue);
	dispatch_forget(&me->user_queue);
	BlockForget(&me->event_handler);
}

//======================================================================================================================

static OSStatus
_mdns_dns_service_manager_print_description(const mdns_dns_service_manager_t me, const bool debug, const bool privacy,
	char * const buf_ptr, const size_t buf_len, size_t *out_len, size_t *out_true_len);

static char *
_mdns_dns_service_manager_copy_description(const mdns_dns_service_manager_t me, const bool debug, const bool privacy)
{
	char *description = NULL;

	size_t true_len;
	char buf[1024];
	OSStatus err = _mdns_dns_service_manager_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &true_len);
	require_noerr_quiet(err, exit);

	if (true_len < sizeof(buf)) {
		description = strdup(buf);
	} else {
		const size_t buf_len = true_len + 1;
		char *buf_ptr = malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mdns_dns_service_manager_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		if (!err) {
			description = buf_ptr;
		} else {
			free(buf_ptr);
		}
	}

exit:
	return description;
}

static OSStatus
_mdns_dns_service_print_description(const mdns_dns_service_t service, const bool debug, const bool privacy,
	char * const buf_ptr, const size_t buf_len, size_t *out_len, size_t *out_true_len);

static OSStatus
_mdns_dns_service_manager_print_description(const mdns_dns_service_manager_t me, const bool debug, const bool privacy,
	char * const buf_ptr, const size_t buf_len, size_t *out_len, size_t *out_true_len)
{
	OSStatus			err;
	char *				dst			= buf_ptr;
	const char * const	lim			= &buf_ptr[buf_len];
	size_t				true_len	= 0;
	int					n;

#define _do_appendf(...)										\
	do {														\
		n = mdns_snprintf_add(&dst, lim, __VA_ARGS__);			\
		require_action_quiet(n >= 0, exit, err = kUnknownErr);	\
		true_len += (size_t)n;									\
	} while(0)

	if (debug) {
		_do_appendf("<%s: %p>: ", me->base.kind->name, me);
	}
	const CFArrayRef service_arrays[] = {
		MDNS_DNS_SERVICE_MANAGER_ARRAYS(me)
	};
	_do_appendf("{");
	const char *sep = "";
	for (size_t i = 0; i < countof(service_arrays); ++i) {
		const CFArrayRef services = service_arrays[i];
		const CFIndex service_count = CFArrayGetCount(services);
		for (CFIndex j = 0; j < service_count; ++j) {
			_do_appendf("%s\n\t", sep);
			size_t len, true_len2;
			const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, j);
			err = _mdns_dns_service_print_description(service, false, privacy, dst, (size_t)(lim - dst), &len,
				&true_len2);
			require_noerr_quiet(err, exit);

			dst += len;
			true_len += true_len2;
			sep = ",";
		}
	}
	_do_appendf("\n}");
#undef _do_appendf

	if (out_len) {
		*out_len = (size_t)(dst - buf_ptr);
	}
	if (out_true_len) {
		*out_true_len = true_len;
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_terminate_services(mdns_dns_service_manager_t manager, CFMutableArrayRef services);

static void
_mdns_dns_service_manager_terminate(const mdns_dns_service_manager_t me, const OSStatus error)
{
	require_return(!me->invalidated);

	me->terminated = true;
	dispatch_source_forget(&me->update_source);
	CFIndex n = CFArrayGetCount(me->monitors);
	for (CFIndex i = 0; i < n; ++i) {
		mdns_interface_monitor_invalidate((mdns_interface_monitor_t)CFArrayGetValueAtIndex(me->monitors, i));
	}
	CFArrayRemoveAllValues(me->monitors);

	_mdns_dns_service_manager_terminate_services(me, me->default_services);
	_mdns_dns_service_manager_terminate_services(me, me->path_services);
	_mdns_dns_service_manager_terminate_services(me, me->discovered_services);
	_mdns_dns_service_manager_terminate_services(me, me->custom_services);

	mdns_retain(me);
	dispatch_async(me->user_queue,
	^{
		if (me->event_handler) {
			me->event_handler(error ? mdns_event_error : mdns_event_invalidated, error);
		}
		mdns_release(me);
	});
}

static void
_mdns_dns_service_manager_terminate_services(const mdns_dns_service_manager_t me, const CFMutableArrayRef services)
{
	const CFIndex n = CFArrayGetCount(services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		if (service->config && service->config_needs_cancel) {
			_mdns_dns_service_manager_cancel_resolver_config_updates(me, service->config);
			service->config_needs_cancel = false;
		}
		_mdns_dns_service_make_defunct((mdns_dns_service_t)CFArrayGetValueAtIndex(services, i));
	}
	CFArrayRemoveAllValues(services);
}

//======================================================================================================================

static void
_mdns_dns_service_manager_add_service(const mdns_dns_service_manager_t me, const CFMutableArrayRef services,
	const mdns_dns_service_t service)
{
	CFArrayAppendValue(services, service);
	_mdns_dns_service_manager_update_interface_properties_for_service(me, service);
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_manager_get_service(const mdns_dns_service_manager_t me, const uint8_t * const name,
	const mdns_dns_service_scope_t scope, const uint32_t scoping_id)
{
	mdns_dns_service_t	best_service		= NULL;
	int					best_label_count	= -1;
	uint32_t			best_order			= 0;
	// Find the best service.
	const CFIndex n = CFArrayGetCount(me->default_services);
	for (CFIndex i = 0; i < n; ++i) {
		mdns_dns_service_t candidate = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->default_services, i);
		if (candidate->scope != scope) {
			continue;
		}
		switch (scope) {
			case mdns_dns_service_scope_interface:
				if (candidate->if_index != scoping_id) {
					continue;
				}
				break;

			case mdns_dns_service_scope_service:
				if (candidate->service_id != scoping_id) {
					continue;
				}
				break;

			default:
			case mdns_dns_service_scope_none:
				break;
		}
		uint32_t order = 0;
		const int label_count = _mdns_dns_service_handles_domain_name(candidate, name, &order);
		if (label_count < 0) {
			continue;
		}
		// The longer a service's parent domain match (in terms of label count), the better the service.
		// If a service has a parent domain match with a label count equal to that of the best service so far,
		// and its parent domain's order value is less than the current best service's parent domain's order
		// value (i.e., it has a higher priority), then it's a better service.
		if ((label_count > best_label_count) || ((label_count == best_label_count) && (order < best_order))) {
			best_service		= candidate;
			best_label_count	= label_count;
			best_order			= order;
		}
	}
	return best_service;
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_manager_get_service_by_config_uuid(CFArrayRef services, const uuid_t uuid);

static mdns_dns_service_t
_mdns_dns_service_manager_get_uuid_scoped_service(const mdns_dns_service_manager_t me, const uuid_t uuid)
{
	// First check in discovered services
	mdns_dns_service_t service = _mdns_dns_service_manager_get_service_by_config_uuid(me->discovered_services, uuid);
	if (!service) {
		service = _mdns_dns_service_manager_get_service_by_config_uuid(me->path_services, uuid);
	}
	return service;
}

static mdns_dns_service_t
_mdns_dns_service_manager_get_service_by_config_uuid(const CFArrayRef services, const uuid_t uuid)
{
	const CFIndex n = CFArrayGetCount(services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		if (service->config) {
			uuid_t config_uuid = {0};
			nw_resolver_config_get_identifier(service->config, config_uuid);
			if (uuid_compare(uuid, config_uuid) == 0) {
				return service;
			}
		}
	}
	return NULL;
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_manager_get_discovered_service(const mdns_dns_service_manager_t me, nw_endpoint_t url_endpoint)
{
	const char *hostname = nw_endpoint_get_hostname(url_endpoint);
	const char *path = nw_endpoint_get_url_path(url_endpoint);
	if (hostname == NULL || path == NULL) {
		return NULL;
	}

	const CFIndex n = CFArrayGetCount(me->discovered_services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(me->discovered_services, i);
		if (service->config &&
			nw_resolver_config_get_protocol(service->config) == nw_resolver_protocol_doh) {

			const char *config_hostname = nw_resolver_config_get_provider_name(service->config);
			const char *config_path = nw_resolver_config_get_provider_path(service->config);
			if (strcasecmp(hostname, config_hostname) == 0 &&
				strcasecmp(path, config_path) == 0) {
				return service;
			}
		}
	}
	return NULL;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_update_interface_properties(const mdns_dns_service_manager_t me)
{
	_mdns_dns_service_manager_update_interface_properties_for_services(me, me->default_services);
	_mdns_dns_service_manager_update_interface_properties_for_services(me, me->path_services);
	_mdns_dns_service_manager_update_interface_properties_for_services(me, me->discovered_services);
	_mdns_dns_service_manager_update_interface_properties_for_services(me, me->custom_services);
}

//======================================================================================================================

static bool
_mdns_dns_service_manager_uses_interface(mdns_dns_service_manager_t manager, uint32_t if_index);

static bool
_mdns_dns_services_use_interface(CFArrayRef services, uint32_t if_index);

static void
_mdns_dns_service_manager_remove_unneeded_interface_monitors(const mdns_dns_service_manager_t me)
{
	for (CFIndex i = CFArrayGetCount(me->monitors) - 1; i >= 0; --i) {
		const mdns_interface_monitor_t monitor = (mdns_interface_monitor_t)CFArrayGetValueAtIndex(me->monitors, i);
		const uint32_t if_index = mdns_interface_monitor_get_interface_index(monitor);
		const bool needed = _mdns_dns_service_manager_uses_interface(me, if_index);
		if (!needed) {
			mdns_interface_monitor_invalidate(monitor);
			CFArrayRemoveValueAtIndex(me->monitors, i);
		}
	}
}

static bool
_mdns_dns_service_manager_uses_interface(const mdns_dns_service_manager_t me, const uint32_t if_index)
{
	if (_mdns_dns_services_use_interface(me->default_services, if_index)	||
		_mdns_dns_services_use_interface(me->path_services, if_index)		||
		_mdns_dns_services_use_interface(me->discovered_services, if_index)	||
		_mdns_dns_services_use_interface(me->custom_services, if_index)) {
		return true;
	} else {
		return false;
	}
}

static bool
_mdns_dns_services_use_interface(const CFArrayRef services, const uint32_t if_index)
{
	const CFIndex n = CFArrayGetCount(services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		if (service->if_index == if_index) {
			return true;
		}
	}
	return false;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_update_interface_properties_for_services(const mdns_dns_service_manager_t me,
	const CFArrayRef services)
{
	const CFIndex n = CFArrayGetCount(services);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, i);
		_mdns_dns_service_manager_update_interface_properties_for_service(me, service);
	}
}

//======================================================================================================================

static mdns_interface_monitor_t
_mdns_dns_service_manager_get_interface_monitor(mdns_dns_service_manager_t manager, uint32_t if_index);

static void
_mdns_dns_service_manager_update_interface_properties_for_service(const mdns_dns_service_manager_t me,
	const mdns_dns_service_t service)
{
	require_quiet(service->if_index != 0, exit);

	const mdns_interface_monitor_t monitor = _mdns_dns_service_manager_get_interface_monitor(me, service->if_index);
	require_action_quiet(monitor, exit,
		os_log_error(_mdns_dns_service_log(), "Failed to get interface monitor for interface %{public}s/%u",
		service->if_name ? service->if_name : "", service->if_index));

	service->flags &= ~MDNS_DNS_SERVICE_FLAGS_FROM_INTERFACE_MONITOR;
	if (mdns_interface_monitor_has_ipv4_connectivity(monitor)) {
		service->flags |= mdns_dns_service_flag_ipv4_connectivity;
	}
	if (mdns_interface_monitor_has_ipv6_connectivity(monitor)) {
		service->flags |= mdns_dns_service_flag_ipv6_connectivity;
	}
	if (mdns_interface_monitor_is_expensive(monitor)) {
		service->flags |= mdns_dns_service_flag_expensive;
	}
	if (mdns_interface_monitor_is_constrained(monitor)) {
		service->flags |= mdns_dns_service_flag_constrained;
	}
	if (mdns_interface_monitor_is_clat46(monitor)) {
		service->flags |= mdns_dns_service_flag_clat46;
	}
	if (mdns_interface_monitor_is_vpn(monitor)) {
		service->flags |= mdns_dns_service_flag_vpn;
	}

exit:
	return;
}

static mdns_interface_monitor_t
_mdns_dns_service_manager_get_interface_monitor(const mdns_dns_service_manager_t me, const uint32_t if_index)
{
	mdns_interface_monitor_t monitor = NULL;
	const CFIndex n = CFArrayGetCount(me->monitors);
	for (CFIndex i = 0; i < n; ++i) {
		mdns_interface_monitor_t candidate = (mdns_interface_monitor_t)CFArrayGetValueAtIndex(me->monitors, i);
		if (mdns_interface_monitor_get_interface_index(candidate) == if_index) {
			monitor = candidate;
			break;
		}
	}
	if (monitor) {
		goto exit;
	}
	monitor = mdns_interface_monitor_create(if_index);
	require_quiet(monitor, exit);

	mdns_interface_monitor_set_queue(monitor, me->queue);
	mdns_retain(me);
	mdns_interface_monitor_set_update_handler(monitor,
	^(mdns_interface_flags_t change_flags)
	{
		const mdns_interface_flags_t relevant_flags =
			mdns_interface_flag_ipv4_connectivity	|
			mdns_interface_flag_ipv6_connectivity	|
			mdns_interface_flag_expensive			|
			mdns_interface_flag_constrained			|
			mdns_interface_flag_clat46				|
			mdns_interface_flag_vpn;
		if ((change_flags & relevant_flags) != 0) {
			const CFRange full_range = CFRangeMake(0, CFArrayGetCount(me->monitors));
			if (CFArrayContainsValue(me->monitors, full_range, monitor)) {
				_mdns_dns_service_manager_trigger_update(me);
			}
		}
	});
	mdns_interface_monitor_set_event_handler(monitor,
	^(mdns_event_t event, __unused OSStatus error)
	{
		switch (event) {
			case mdns_event_invalidated:
				mdns_release(monitor);
				mdns_release(me);
				break;

			case mdns_event_error: {
				const CFRange full_range = CFRangeMake(0, CFArrayGetCount(me->monitors));
				const CFIndex i = CFArrayGetFirstIndexOfValue(me->monitors, full_range, monitor);
				if (i >= 0) {
					CFArrayRemoveValueAtIndex(me->monitors, i);
				}
				mdns_interface_monitor_invalidate(monitor);
				break;
			}
			default:
				break;
		}
    });
	mdns_interface_monitor_activate(monitor);
	CFArrayAppendValue(me->monitors, monitor);

exit:
	return monitor;
}

//======================================================================================================================
// MARK: - DNS Service Public Methods

void
mdns_dns_service_set_context(const mdns_dns_service_t me, void * const context)
{
	me->context = context;
}

//======================================================================================================================

void *
mdns_dns_service_get_context(const mdns_dns_service_t me)
{
	return me->context;
}

//======================================================================================================================

void
mdns_dns_service_set_context_finalizer(const mdns_dns_service_t me, const mdns_context_finalizer_t finalizer)
{
	me->context_finalizer = finalizer;
}

//======================================================================================================================

mdns_querier_t
mdns_dns_service_create_querier(const mdns_dns_service_t me, OSStatus * const out_error)
{
	if (me->resolver) {
		return mdns_resolver_create_querier(me->resolver, out_error);
	} else {
		if (out_error) {
			*out_error = kNotInUseErr;
		}
		return NULL;
	}
}

//======================================================================================================================

mdns_dns_service_scope_t
mdns_dns_service_get_scope(const mdns_dns_service_t me)
{
	return me->scope;
}

//======================================================================================================================

uint32_t
mdns_dns_service_get_interface_index(const mdns_dns_service_t me)
{
	return me->if_index;
}

//======================================================================================================================

mdns_dns_service_id_t
mdns_dns_service_get_id(const mdns_dns_service_t me)
{
	return _mdns_dns_service_get_id_safe(me);
}

//======================================================================================================================

bool
mdns_dns_service_is_defunct(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_defunct) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_is_encrypted(mdns_dns_service_t me)
{
	return mdns_resolver_type_uses_encryption(_mdns_dns_service_get_resolver_type_safe(me));
}

//======================================================================================================================

bool
mdns_dns_service_a_queries_advised(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_a_queries_advised) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_aaaa_queries_advised(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_aaaa_queries_advised) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_has_connection_problems(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_connection_problems) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_has_ipv4_connectivity(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_ipv4_connectivity) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_has_ipv6_connectivity(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_ipv6_connectivity) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_is_cellular(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_cellular) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_is_expensive(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_expensive) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_is_constrained(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_constrained) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_is_clat46(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_clat46) ? true : false);
}

//======================================================================================================================

bool
mdns_dns_service_interface_is_vpn(const mdns_dns_service_t me)
{
	return ((me->flags & mdns_dns_service_flag_vpn) ? true : false);
}

//======================================================================================================================

const char *
mdns_dns_service_get_provider_name(const mdns_dns_service_t me)
{
	if (me->config) {
		const char *provider_name = nw_resolver_config_get_provider_name(me->config);
		if (provider_name) {
			return provider_name;
		}
	}
	return NULL;
}

//======================================================================================================================

mdns_resolver_type_t
mdns_dns_service_get_resolver_type(const mdns_dns_service_t me)
{
	return me->resolver_type;
}

//======================================================================================================================
// MARK: - DNS Service Private Methods

static void
_mdns_dns_service_finalize(const mdns_dns_service_t me)
{
	if (me->context) {
		if (me->context_finalizer) {
			me->context_finalizer(me->context);
		}
		me->context = NULL;
	}
	ForgetCF(&me->addresses);
	_domain_item_t item;
	while ((item = me->domain_list) != NULL) {
		me->domain_list = item->next;
		_domain_item_free(item);
	}
	nw_forget(&me->discovered.url_endpoint);
	nw_forget(&me->config);
	ForgetMem(&me->if_name);
}

//======================================================================================================================

static char *
_mdns_dns_service_copy_description(const mdns_dns_service_t me, const bool debug, const bool privacy)
{
	char *description = NULL;

	size_t true_len;
	char buf[512];
	OSStatus err = _mdns_dns_service_print_description(me, debug, privacy, buf, sizeof(buf), NULL, &true_len);
	require_noerr_quiet(err, exit);

	if (true_len < sizeof(buf)) {
		description = strdup(buf);
	} else {
		const size_t buf_len = true_len + 1;
		char *buf_ptr = malloc(buf_len);
		require_quiet(buf_ptr, exit);

		err = _mdns_dns_service_print_description(me, debug, privacy, buf_ptr, buf_len, NULL, NULL);
		if (!err) {
			description = buf_ptr;
		} else {
			free(buf_ptr);
		}
	}

exit:
	return description;
}

typedef struct {
	mdns_dns_service_flags_t	flag;
	const char *				desc;
} mdns_dns_service_flag_description_t;

#define MDNS_DNS_SERVICE_REDACTED_STR	"<REDACTED>"

static OSStatus
_mdns_dns_service_print_description(const mdns_dns_service_t me, const bool debug, const bool privacy,
	char * const buf_ptr, const size_t buf_len, size_t *out_len, size_t *out_true_len)
{
	OSStatus			err;
	char *				dst				= buf_ptr;
	const char * const	lim				= &buf_ptr[buf_len];
	size_t				true_len		= 0;
	char *				address_desc	= NULL;

#define _do_appendf(...)											\
	do {															\
		const int n = mdns_snprintf_add(&dst, lim, __VA_ARGS__);	\
		require_action_quiet(n >= 0, exit, err = kUnknownErr);		\
		true_len += (size_t)n;										\
	} while(0)

	if (debug) {
		_do_appendf("<%s: %p>: ", me->base.kind->name, me);
	}

	// Print ID.
	_do_appendf("id: %llu", me->ident);

	// Print DNS type.
	_do_appendf(", type: ");
	const mdns_resolver_type_t type = _mdns_dns_service_get_resolver_type_safe(me);
	switch (type) {
		case mdns_resolver_type_normal:
			_do_appendf("Do53");
			break;

		case mdns_resolver_type_tls:
			_do_appendf("DoT");
			break;

		case mdns_resolver_type_https:
			_do_appendf("DoH");
			break;

		default:
			_do_appendf("<unknown type %d>", (int)type);
			break;
	}

	// Print source.
	_do_appendf(", source: ");
	switch (me->source) {
		case mdns_dns_service_source_sc:
			_do_appendf("sc");
			break;

		case mdns_dns_service_source_nw:
			_do_appendf("nw");
			break;

		case mdns_dns_service_source_dns:
			_do_appendf("dns");
			break;

		case mdns_dns_service_source_custom: {
			_do_appendf("custom");
			break;
		}
		default:
			_do_appendf("<unknown source %d>", (int)me->source);
			break;
	}

	// Print scope.
	_do_appendf(", scope: ");
	switch (me->scope) {
		case mdns_dns_service_scope_none:
			_do_appendf("none");
			break;

		case mdns_dns_service_scope_interface:
			_do_appendf("interface");
			break;

		case mdns_dns_service_scope_service:
			_do_appendf("service (%u)", me->service_id);
			break;

		case mdns_dns_service_scope_uuid: {
			_do_appendf("uuid");
			if (!privacy) {
				uuid_t uuid = {0};
				nw_resolver_config_get_identifier(me->config, uuid);
				uuid_string_t uuid_str;
				uuid_unparse(uuid, uuid_str);
				_do_appendf(" (%s)", uuid_str);
			}
			break;
		}
		default:
			_do_appendf("<ERROR: unknown scope %d>", (int)me->scope);
			break;
	}

	// Print interface index.
	_do_appendf(", interface: %s/%u", me->if_name ? me->if_name : "", me->if_index);

	// Print server addresses.
	_do_appendf(", servers: {");

	const char *sep = "";
	const CFIndex address_count = CFArrayGetCount(me->addresses);
	for (CFIndex i = 0; i < address_count; ++i) {
		const mdns_address_t address = (mdns_address_t)CFArrayGetValueAtIndex(me->addresses, i);
		if (privacy) {
			const char *str;
			char strbuf[64];
			const struct sockaddr * const sa = mdns_address_get_sockaddr(address);
			const int family = sa->sa_family;
			if ((family == AF_INET) || (family == AF_INET6)) {
				const int n = mdns_print_obfuscated_ip_address(strbuf, sizeof(strbuf), sa);
				if (n >= 0) {
					str = strbuf;
				} else {
					str = (family == AF_INET) ? "<IPv4>" : "<IPv6>";
				}
			} else {
				str = "<IPv?>";
			}
			_do_appendf("%s%s", sep, str);
			const int port = mdns_address_get_port(address);
			if (port != 0) {
				_do_appendf(":%d", port);
			}
		} else {
			address_desc = mdns_object_copy_description(address, false, privacy);
			_do_appendf("%s%s", sep, address_desc ? address_desc : "<NO DESC.>");
			ForgetMem(&address_desc);
		}
		sep = ", ";
	}
	_do_appendf("}");

	// Print domains.
	_do_appendf(", domains: {");

	sep = "";
	for (const struct _domain_item_s *item = me->domain_list; item; item = item->next) {
		const char *str;
		char strbuf[64];
		if (privacy) {
			const int n = DNSMessagePrintObfuscatedString(strbuf, sizeof(strbuf), item->name_str);
			str = (n >= 0) ? strbuf : MDNS_DNS_SERVICE_REDACTED_STR;
		} else {
			str = item->name_str;
		}
		_do_appendf("%s%s", sep, str);
		if (item->order != 0) {
			_do_appendf(" (%u)", item->order);
		}
		sep = ", ";
	}
	_do_appendf("}");

	// Print attributes.
	_do_appendf(", attributes: {");

	const mdns_dns_service_flag_description_t mdns_dns_service_flag_service_descs[] = {
		{mdns_dns_service_flag_defunct,					"defunct"},
		{mdns_dns_service_flag_a_queries_advised,		"a-ok"},
		{mdns_dns_service_flag_aaaa_queries_advised,	"aaaa-ok"},
		{mdns_dns_service_flag_connection_problems,		"connection-problems"},
	};
	sep = "";
	for (size_t i = 0; i < countof(mdns_dns_service_flag_service_descs); ++i) {
		const mdns_dns_service_flag_description_t * const flag_desc = &mdns_dns_service_flag_service_descs[i];
		if (me->flags & flag_desc->flag) {
			_do_appendf("%s%s", sep, flag_desc->desc);
			sep = ", ";
		}
	}
	_do_appendf("}");

	// Print interface properties.
	_do_appendf(", interface properties: {");

	const mdns_dns_service_flag_description_t mdns_dns_service_flag_interface_descs[] = {
		{mdns_dns_service_flag_cellular,			"cellular"},
		{mdns_dns_service_flag_ipv4_connectivity,	"ipv4"},
		{mdns_dns_service_flag_ipv6_connectivity,	"ipv6"},
		{mdns_dns_service_flag_expensive,			"expensive"},
		{mdns_dns_service_flag_constrained,			"constrained"},
		{mdns_dns_service_flag_clat46,				"clat46"},
		{mdns_dns_service_flag_vpn,					"vpn"}
	};
	sep = "";
	for (size_t i = 0; i < countof(mdns_dns_service_flag_interface_descs); ++i) {
		const mdns_dns_service_flag_description_t * const flag_desc = &mdns_dns_service_flag_interface_descs[i];
		if (me->flags & flag_desc->flag) {
			_do_appendf("%s%s", sep, flag_desc->desc);
			sep = ", ";
		}
	}
	_do_appendf("}");

	// Print additional information from resolver config object that isn't already printed.
	if (me->config) {
		_do_appendf(", resolver config: {");
		const char *provider_name = nw_resolver_config_get_provider_name(me->config);
		_do_appendf("provider name: ");
		if (provider_name) {
			const char *str;
			char strbuf[64];
			if (privacy) {
				const int n = DNSMessagePrintObfuscatedString(strbuf, sizeof(strbuf), provider_name);
				str = (n >= 0) ? strbuf : MDNS_DNS_SERVICE_REDACTED_STR;
			} else {
				str = provider_name;
			}
			_do_appendf("%s", str);
		}
		const char *provider_path = nw_resolver_config_get_provider_path(me->config);
		_do_appendf(", provider path: ");
		if (provider_path) {
			const char *str;
			char strbuf[64];
			if (privacy) {
				const int n = DNSMessagePrintObfuscatedString(strbuf, sizeof(strbuf), provider_path);
				str = (n >= 0) ? strbuf : MDNS_DNS_SERVICE_REDACTED_STR;
			} else {
				str = provider_path;
			}
			_do_appendf("%s", str);
		}
		_do_appendf("}");
	}
#undef _do_appendf

	if (out_len) {
		*out_len = (size_t)(dst - buf_ptr);
	}
	if (out_true_len) {
		*out_true_len = true_len;
	}
	err = kNoErr;

exit:
	ForgetMem(&address_desc);
	return err;
}
//======================================================================================================================

static bool
_mdns_dns_service_equal(const mdns_dns_service_t me, const mdns_dns_service_t other)
{
	return _mdns_dns_service_equal_ex(me, other, false);
}

//======================================================================================================================

static mdns_dns_service_id_t
_mdns_get_next_dns_service_id(void);

static mdns_dns_service_t
_mdns_dns_service_create(const mdns_dns_service_source_t source, const mdns_dns_service_scope_t scope,
	const mdns_resolver_type_t resolver_type, OSStatus * const out_error)
{
	OSStatus err;
	mdns_dns_service_t service = NULL;
	mdns_dns_service_t obj = _mdns_dns_service_alloc();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	obj->ident			= _mdns_get_next_dns_service_id();
	obj->source			= source;
	obj->scope			= scope;
	obj->resolver_type	= resolver_type;

	obj->addresses = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->addresses, exit, err = kNoResourcesErr);

	service = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mdns_release_null_safe(obj);
	return service;
}

static mdns_dns_service_id_t
_mdns_get_next_dns_service_id(void)
{
	static _Atomic(mdns_dns_service_id_t) s_next_id = ATOMIC_VAR_INIT(1);
	return atomic_fetch_add_explicit(&s_next_id, 1, memory_order_relaxed);
}

//======================================================================================================================

#define MDNS_INITIAL_DGRAM_RTX_INTERVAL_NONCELLULAR_SECS	1
#define MDNS_INITIAL_DGRAM_RTX_INTERVAL_CELLULAR_SECS		2

static void
_mdns_dns_service_manager_handle_resolver_event(mdns_dns_service_manager_t me, mdns_dns_service_t service,
	mdns_resolver_t resolver, mdns_resolver_event_t event, xpc_object_t info);

static void
_mdns_dns_service_manager_prepare_resolver(const mdns_dns_service_manager_t me, const mdns_dns_service_t service)
{
	require_return(!service->resolver);

	// Determine the appropriate resolver type.
	const mdns_resolver_type_t type = _mdns_dns_service_get_resolver_type_safe(service);
	require_return(type != mdns_resolver_type_null);

	// Create the resolver.
	OSStatus err;
	mdns_resolver_t resolver = mdns_resolver_create(type, service->if_index, &err);
	require_action_quiet(resolver, exit, os_log_error(_mdns_dns_service_log(),
		"Failed to create resolver for service -- service id: %llu", service->ident));

	// Set up the resolver.
	if (service->config) {
		mdns_resolver_set_provider_name(resolver, nw_resolver_config_get_provider_name(service->config));
		mdns_resolver_set_url_path(resolver, nw_resolver_config_get_provider_path(service->config));
	}
	// Squash CNAMES if this discovered config requires it.
	if (service->discovered.squash_cnames) {
		mdns_resolver_set_squash_cnames(resolver, true);
	}
	const uint32_t interval_secs = mdns_dns_service_interface_is_cellular(service) ?
		MDNS_INITIAL_DGRAM_RTX_INTERVAL_CELLULAR_SECS : MDNS_INITIAL_DGRAM_RTX_INTERVAL_NONCELLULAR_SECS;
	mdns_resolver_set_initial_datagram_retransmission_interval(resolver, interval_secs);
	mdns_resolver_enable_symptom_reporting(resolver, me->report_symptoms);
	if (type == mdns_resolver_type_normal) {
		mdns_resolver_disable_connection_reuse(resolver, true);
	#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		mdns_resolver_enable_problematic_qtype_workaround(resolver, me->pqw_threshold);
	#endif
	}
	const CFIndex n = CFArrayGetCount(service->addresses);
	CFIndex add_count = 0;
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_address_t address = (mdns_address_t)CFArrayGetValueAtIndex(service->addresses, i);
		const OSStatus add_err = mdns_resolver_add_server_address(resolver, address);
		if (likely(!add_err)) {
			++add_count;
		} else {
			os_log_error(_mdns_dns_service_log(),
				"Failed to add address to resolver -- service id: %llu, address: %@, error: %{mdns:err}ld",
				service->ident, address, (long)add_err);
		}
	}
	require_quiet((n == 0) || (add_count > 0), exit);

	mdns_resolver_set_queue(resolver, me->queue);
	mdns_retain(me);
	mdns_retain(resolver);
	mdns_retain(service);
	mdns_resolver_set_event_handler(resolver,
	^(const mdns_resolver_event_t event, const xpc_object_t info)
	{
		_mdns_dns_service_manager_handle_resolver_event(me, service, resolver, event, info);
	});
	service->resolver = resolver;
	resolver = NULL;

	// Reset the "cannot connect" state if the service used to have a resolver that couldn't connect.
	if (service->cannot_connect) {
		service->cannot_connect = false;
		_mdns_dns_service_manager_trigger_update(me);
	}
	mdns_resolver_activate(service->resolver);

exit:
	mdns_release_null_safe(resolver);
}

static void
_mdns_dns_service_manager_handle_resolver_event(const mdns_dns_service_manager_t me,
	const mdns_dns_service_t service, const mdns_resolver_t resolver, const mdns_resolver_event_t event,
	const xpc_object_t info)
{
	switch (event) {
		case mdns_resolver_event_connection: {
			require_quiet(info, exit);
			require_quiet(service->resolver == resolver, exit);

			bool cannot_connect = xpc_dictionary_get_bool(info, MDNS_RESOLVER_EVENT_CONNECTION_INFO_KEY_CANNOT_CONNECT);
			os_log(_mdns_dns_service_log(),
				"Resolver can%{public}s connect -- service id: %llu, resolver: %@",
				cannot_connect ? "not" : "", service->ident, resolver);
			if (cannot_connect) {
				if (!service->cannot_connect) {
					service->cannot_connect = true;
					_mdns_dns_service_manager_trigger_update(me);
				}
			} else {
				if (service->cannot_connect) {
					service->cannot_connect = false;
					_mdns_dns_service_manager_trigger_update(me);
				}
			}
			break;
		}
		case mdns_resolver_event_invalidated: {
			os_log_info(_mdns_dns_service_log(),
				"Resolver has been invalidated -- service id: %llu, resolver: %@", service->ident, resolver);
			mdns_release(resolver);
			mdns_release(service);
			mdns_release(me);
			break;
		}
		default: {
			if (os_log_debug_enabled(_mdns_dns_service_log())) {
				char *info_desc = info ? xpc_copy_description(info) : NULL;
				os_log_debug(_mdns_dns_service_log(),
					"DNS service (%@) got unhandled event: %s info: %{public}s",
					service, mdns_resolver_event_to_string(event), info_desc);
				ForgetMem(&info_desc);
			}
			break;
		}
	}

exit:
	return;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_start_defuncting(const mdns_dns_service_manager_t me, const mdns_dns_service_t service)
{
	if (!service->defuncting) {
		service->defuncting = true;
		_mdns_dns_service_manager_trigger_update(me);
	}
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_manager_prepare_service(const mdns_dns_service_manager_t me, const mdns_dns_service_t service)
{
	require_return_value(service, NULL);
	_mdns_dns_service_manager_prepare_resolver(me, service);
	require_return_value_action(service->resolver, NULL,
		os_log_error(_mdns_dns_service_log(), "Failed to prepare resolver -- service id: %llu", service->ident));
	return service;
}

//======================================================================================================================

static void
_mdns_dns_service_manager_trigger_update(const mdns_dns_service_manager_t me)
{
	if (me->update_source) {
		dispatch_source_merge_data(me->update_source, 1);
	}
}

//======================================================================================================================

static void
_mdns_dns_service_manager_iterate_over_all_service_arrays(const mdns_dns_service_manager_t me,
	const mdns_dns_service_array_applier_t applier)
{
	const CFMutableArrayRef all_arrays[] = {
		MDNS_DNS_SERVICE_MANAGER_ARRAYS(me)
	};
	for (size_t i = 0; i < countof(all_arrays); ++i) {
		const bool stop = applier(all_arrays[i]);
		if (stop) {
			break;
		}
	}
}

//======================================================================================================================

static void
_mdns_dns_service_make_defunct(const mdns_dns_service_t me)
{
	me->flags |= mdns_dns_service_flag_defunct;
	mdns_resolver_forget(&me->resolver);
}

//======================================================================================================================

static bool
_mdns_dns_service_equal_ex(const mdns_dns_service_t me, const mdns_dns_service_t other, const bool ignore_domains)
{
	if (me == other) {
		return true;
	}
	if (me->scope != other->scope) {
		return false;
	}
	if (me->if_index != other->if_index) {
		return false;
	}
	if ((me->scope == mdns_dns_service_scope_service) && (me->service_id != other->service_id)) {
		return false;
	}
	if (!CFEqual(me->addresses, other->addresses)) {
		return false;
	}
	if (!ignore_domains) {
		const struct _domain_item_s *d1 = me->domain_list;
		const struct _domain_item_s *d2 = other->domain_list;
		while (d1 && d2) {
			if (_domain_item_compare(d1, d2, false) != 0) {
				return false;
			}
			d1 = d1->next;
			d2 = d2->next;
		}
		if (d1 || d2) {
			return false;
		}
	}
	return true;
}

//======================================================================================================================

static OSStatus
_mdns_dns_service_add_domain(const mdns_dns_service_t me, const char * const name_str, const uint32_t order)
{
	OSStatus err;
	_domain_item_t new_item = (_domain_item_t)calloc(1, sizeof(*new_item));
	require_action_quiet(new_item, exit, err = kNoMemoryErr);

	uint8_t name[kDomainNameLengthMax];
	err = DomainNameFromString(name, name_str, NULL);
	require_noerr_quiet(err, exit);

	char normalized_name_str[kDNSServiceMaxDomainName];
	err = DomainNameToString(name, NULL, normalized_name_str, NULL);
	require_noerr_quiet(err, exit);

	new_item->name_str = strdup(normalized_name_str);
	require_action_quiet(new_item->name_str, exit, err = kNoMemoryErr);

	err = DomainNameDup(name, &new_item->name, NULL);
	require_noerr_quiet(err, exit);

	new_item->label_count = DomainNameLabelCount(new_item->name);
	require_action_quiet(new_item->label_count >= 0, exit, err = kMalformedErr);

	new_item->order = order;
	_domain_item_t *ptr;
	_domain_item_t item;
	for (ptr = &me->domain_list; (item = *ptr) != NULL; ptr = &item->next) {
		// Compare domain items, but ignore their order values.
		const int cmp = _domain_item_compare(new_item, item, true);
		if (cmp < 0) {
			break;
		}
		if (cmp == 0) {
			// The domain items are equal, but may have different order values. Keep the smaller order
			// (higher priority) value. The domain item with the larger order (lower priority) value is redundant.
			if (new_item->order < item->order) {
				item->order = new_item->order;
			}
			goto exit;
		}
	}
	new_item->next = item;
	*ptr = new_item;
	new_item = NULL;

exit:
	if (new_item) {
		_domain_item_free(new_item);
	}
	return err;
}

//======================================================================================================================

static int
_mdns_dns_service_handles_domain_name(const mdns_dns_service_t me, const uint8_t * const name,
	uint32_t * const out_order)
{
	int result;
	const int label_count = DomainNameLabelCount(name);
	require_action_quiet(label_count >= 0, exit, result = -1);

	const struct _domain_item_s *item;
	for (item = me->domain_list; item; item = item->next) {
		if (label_count < item->label_count) {
			continue;
		}
		const uint8_t * const ptr = _mdns_domain_name_get_parent(name, label_count - item->label_count);
		if (DomainNameEqual(ptr, item->name)) {
			break;
		}
	}
	require_action_quiet(item, exit, result = -1);

	result = item->label_count;
	if (out_order) {
		*out_order = item->order;
	}

exit:
	return result;
}

//======================================================================================================================

static mdns_resolver_type_t
_mdns_dns_service_get_resolver_type_safe(const mdns_dns_service_t me)
{
	if (me->config && (me->resolver_type == mdns_resolver_type_null)) {
		const nw_resolver_protocol_t proto = nw_resolver_config_get_protocol(me->config);
		switch (proto) {
			case nw_resolver_protocol_dns53:
				return mdns_resolver_type_normal;

			case nw_resolver_protocol_dot:
				return mdns_resolver_type_tls;

			case nw_resolver_protocol_doh:
				return mdns_resolver_type_https;

			default:
				return mdns_resolver_type_null;
		}
	} else {
		return me->resolver_type;
	}
}

//======================================================================================================================
// MARK: - Local Helpers

static OSStatus
_mdns_append_dns_service_from_config_by_scope(CFMutableArrayRef services, const dns_config_t *config,
	mdns_dns_service_scope_t scope);

static CFMutableArrayRef
_mdns_create_dns_service_array_from_config(const dns_config_t * const config, OSStatus * const out_error)
{
	OSStatus			err;
	CFMutableArrayRef	result = NULL;

	CFMutableArrayRef services = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
	require_action_quiet(services, exit, err = kNoResourcesErr);

	err = _mdns_append_dns_service_from_config_by_scope(services, config, mdns_dns_service_scope_none);
	require_noerr_quiet(err, exit);

	err = _mdns_append_dns_service_from_config_by_scope(services, config, mdns_dns_service_scope_interface);
	require_noerr_quiet(err, exit);

	err = _mdns_append_dns_service_from_config_by_scope(services, config, mdns_dns_service_scope_service);
	require_noerr_quiet(err, exit);

	result = services;
	services = NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	CFReleaseNullSafe(services);
	return result;
}

#define MDNS_DNS_SERVICE_DNS_PORT	53
#define MDNS_DNS_SERVICE_MDNS_PORT	5353

static OSStatus
_mdns_append_dns_service_from_config_by_scope(const CFMutableArrayRef services, const dns_config_t * const config,
	const mdns_dns_service_scope_t scope)
{
	OSStatus					err;
	mdns_dns_service_t			new_service = NULL;
	dns_resolver_t * const *	resolver_array;
	int32_t						resolver_count;
	switch (scope) {
		case mdns_dns_service_scope_none:
			resolver_array = config->resolver;
			resolver_count = config->n_resolver;
			break;

		case mdns_dns_service_scope_interface:
			resolver_array = config->scoped_resolver;
			resolver_count = config->n_scoped_resolver;
			break;

		case mdns_dns_service_scope_service:
			resolver_array = config->service_specific_resolver;
			resolver_count = config->n_service_specific_resolver;
			break;

		default:
			err = kNoErr;
			goto exit;
	}
	for (int32_t i = 0; i < resolver_count; ++i) {
		const dns_resolver_t * const resolver = resolver_array[i];
		if ((resolver->port == MDNS_DNS_SERVICE_MDNS_PORT) || (resolver->n_nameserver == 0)) {
			continue;
		}
		// Don't let a malformed domain name prevent parsing the remaining config.
		if (resolver->domain) {
			uint8_t domain[kDomainNameLengthMax];
			if (DomainNameFromString(domain, resolver->domain, NULL) != kNoErr) {
				os_log_error(_mdns_dns_service_log(),
					"Encountered invalid dns_config_t resolver domain name: %s", resolver->domain);
				continue;
			}
		}
		new_service = _mdns_dns_service_create(mdns_dns_service_source_sc, scope, mdns_resolver_type_normal, &err);
		require_noerr_quiet(err, exit);

		const uint16_t port = (resolver->port == 0) ? MDNS_DNS_SERVICE_DNS_PORT : resolver->port;
		for (int32_t j = 0; j < resolver->n_nameserver; ++j) {
			const struct sockaddr * const sa = resolver->nameserver[j];
			mdns_address_t address;
			if (sa->sa_family == AF_INET) {
				const struct sockaddr_in * const sin = (const struct sockaddr_in *)sa;
				address = mdns_address_create_ipv4(ntohl(sin->sin_addr.s_addr), port);
				require_action_quiet(address, exit, err = kNoMemoryErr);
			} else if (sa->sa_family == AF_INET6) {
				struct sockaddr_in6 sin6_fixed;
				const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
				if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && (resolver->if_index != 0) &&
					(sin6->sin6_scope_id != resolver->if_index)) {
					sin6_fixed = *sin6;
					sin6_fixed.sin6_scope_id = resolver->if_index;
					os_log(_mdns_dns_service_log(),
						"Corrected scope ID of link-local server address %{network:sockaddr}.*P from %u to %u",
						(int)sizeof(*sin6), sin6, sin6->sin6_scope_id, sin6_fixed.sin6_scope_id);
					sin6 = &sin6_fixed;
				}
				address = mdns_address_create_ipv6(sin6->sin6_addr.s6_addr, port, sin6->sin6_scope_id);
				require_action_quiet(address, exit, err = kNoMemoryErr);
			} else {
				continue;
			}
			CFArrayAppendValue(new_service->addresses, address);
			mdns_forget(&address);
		}
		new_service->if_index	= resolver->if_index;
		new_service->service_id	= (scope == mdns_dns_service_scope_service) ? resolver->service_identifier : 0;
		new_service->flags		= mdns_dns_service_flag_null;

		// Check if a service object that's identical in every way except domains and flags already exists.
		const char * const domain_str = resolver->domain ? resolver->domain : ".";
		const CFIndex n = CFArrayGetCount(services);
		for (CFIndex j = 0; j < n; ++j) {
			const mdns_dns_service_t service = (mdns_dns_service_t)CFArrayGetValueAtIndex(services, j);
			if (_mdns_dns_service_equal_ex(service, new_service, true)) {
				// Simply add the domain to the existing service.
				err = _mdns_dns_service_add_domain(service, domain_str, resolver->search_order);
				require_noerr_quiet(err, exit);
				mdns_forget(&new_service);
				break;
			}
		}

		// If no existing service was found, add this one.
		if (new_service) {
			if (resolver->flags & DNS_RESOLVER_FLAGS_REQUEST_A_RECORDS) {
				new_service->flags |= mdns_dns_service_flag_a_queries_advised;
			}
			if (resolver->flags & DNS_RESOLVER_FLAGS_REQUEST_AAAA_RECORDS) {
				new_service->flags |= mdns_dns_service_flag_aaaa_queries_advised;
			}
		#if !(TARGET_OS_OSX)
			if (resolver->reach_flags & kSCNetworkReachabilityFlagsIsWWAN) {
				new_service->flags |= mdns_dns_service_flag_cellular;
			}
		#endif
			if (new_service->if_index != 0) {
				const char *name_ptr;
				char name_buf[IF_NAMESIZE + 1];
				name_ptr = if_indextoname(new_service->if_index, name_buf);
				const int name_err = map_global_value_errno(name_ptr, name_ptr);
				if (!name_err) {
					new_service->if_name = strdup(name_ptr);
				} else {
					os_log_error(_mdns_dns_service_log(),
						"if_indextoname() for %u failed: %{darwin.errno}d", new_service->if_index, name_err);
				}
			}
			err = _mdns_dns_service_add_domain(new_service, domain_str, resolver->search_order);
			require_noerr_quiet(err, exit);
			CFArrayAppendValue(services, new_service);
			mdns_forget(&new_service);
		}
	}
	err = kNoErr;

exit:
	mdns_release_null_safe(new_service);
	return err;
}

//======================================================================================================================

static mdns_dns_service_t
_mdns_dns_service_create_from_resolver_config(const nw_resolver_config_t config, const mdns_dns_service_source_t source,
	OSStatus * const out_error)
{
	OSStatus err;
	const mdns_dns_service_t service = _mdns_dns_service_create(source, mdns_dns_service_scope_uuid,
		mdns_resolver_type_null, &err);
	require_noerr_quiet(err, exit);

	nw_resolver_config_enumerate_name_servers(config,
	^ bool (const char * _Nonnull name_server)
	{
		mdns_address_t address = mdns_address_create_from_ip_address_string(name_server);
		if (address) {
			CFArrayAppendValue(service->addresses, address);
			mdns_forget(&address);
		}
		return true;
	});
	nw_resolver_config_enumerate_match_domains(config,
	^ bool (const char * _Nonnull match_domain)
	{
		_mdns_dns_service_add_domain(service, match_domain, 0);
		return true;
	});
	service->config = config;
	nw_retain(service->config);
	const char * const interface_name = nw_resolver_config_get_interface_name(config);
	if (interface_name) {
		service->if_name	= strdup(interface_name);
		service->if_index	= if_nametoindex(interface_name);
	}
	service->flags = (mdns_dns_service_flag_a_queries_advised | mdns_dns_service_flag_aaaa_queries_advised);
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return service;
}

//======================================================================================================================

static mdns_dns_service_id_t
_mdns_dns_service_get_id_safe(const mdns_dns_service_t me)
{
	require_return_value(me, 0);
	return me->ident;
}

//======================================================================================================================

static const uint8_t *
_mdns_domain_name_get_parent(const uint8_t * const name, const int depth)
{
	int current_depth = 0;
	const uint8_t *ptr = name;
	while ((*ptr != 0) && (current_depth < depth)) {
		ptr += (1 + *ptr);
		++current_depth;
	}
	return ptr;
}

//======================================================================================================================

static void
_domain_item_free(const _domain_item_t item)
{
	ForgetMem(&item->name);
	ForgetMem(&item->name_str);
	free(item);
}

//======================================================================================================================

static int
_domain_item_compare(const struct _domain_item_s * const d1, const struct _domain_item_s * const d2,
	const bool ignore_order)
{
	// The domain name with the greater label count precedes the other.
	int diff = d1->label_count - d2->label_count;
	if (diff > 0) {
		return -1;
	}
	if (diff < 0) {
		return 1;
	}
	// The domain name with the lexicographically lesser rightmost label precedes the other.
	// Compare each pair of non-root labels from right to left.
	for (int depth = d1->label_count; depth-- > 0; ) {
		const uint8_t * const label1 = _mdns_domain_name_get_parent(d1->name, depth);
		const uint8_t * const label2 = _mdns_domain_name_get_parent(d2->name, depth);
		const int length1 = label1[0];
		const int length2 = label2[0];
		const int n = Min(length1, length2);
		for (int i = 1; i <= n; ++i) {
			diff = tolower_safe(label1[i]) - tolower_safe(label2[i]);
			if (diff < 0) {
				return -1;
			}
			if (diff > 0) {
				return 1;
			}
		}
		diff = length1 - length2;
		if (diff < 0) {
			return -1;
		}
		if (diff > 0) {
			return 1;
		}
	}
	if (!ignore_order) {
		// The domain name with the smaller order (higher priority) precedes the other.
		if (d1->order < d2->order) {
			return -1;
		}
		if (d1->order > d2->order) {
			return 1;
		}
	}
	return 0;
}
