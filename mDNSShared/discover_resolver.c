/*
 * Copyright (c) 2020-2022 Apple Inc. All rights reserved.
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
 *
 * This file contains code to let mDNSResponder set up the resolver for
 * the automatic browsing domain learned from "lb._dns-sd._udp.local PTR"
 * query. To setup the resolver, it will get the NS record for the domain
 * and the A/AAAA record for the resolver name in the NS record rdata.
 * Once it knows about resolver's address, it will set the resolver with
 * configuration change to let mDNSResponder add it as a regular DNS resolver.
 */

#include "mDNSFeatures.h" // for MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)

//======================================================================================================================
// MARK: - Headers

#include <stdio.h>
#include <mdns/private.h>
#include "mDNSEmbeddedAPI.h"
#include "mdns_strict.h"
#include "uds_daemon.h"
#include "bsd_queue.h"			// For SLIST.
#include "discover_resolver.h"
#include "tls-keychain.h"		// For init_tls_cert().
#include "uDNS.h"				// For mDNS_StartQuery_internal() and mDNS_StopQuery_internal().


#include "DNSCommon.h"			// For mDNS_Lock() and mDNS_Unlock().

// for require_*
#if defined(__APPLE__)
	#include <AssertMacros.h>
#elif defined(POSIX_BUILD)
	#include "DebugServices.h"
#else
	#ifndef require
		#define require(assertion, exception_label)					\
			do {													\
				if (!(assertion)) {									\
					goto exception_label;							\
				}													\
			} while (false)
	#endif // #ifndef require

	#ifndef require_action
		#define require_action(assertion, exception_label, action)	\
			do {													\
				if (!(assertion)) {									\
					{												\
						action;										\
					}												\
					goto exception_label;							\
				}													\
			} while (false)
	#endif // #ifndef require_action
#endif

//======================================================================================================================
// MARK: - Macros

// Retain and release macros that are used to do reference counting for the discover_resolver_t object.
#define DISCOVER_RESOLVER_RETAIN(OBJ)															\
	do {																						\
		(OBJ)->ref_count++;																		\
		LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "discover_resolver_t retained "	\
			"- ref count after retaining: %u.", (OBJ)->ref_count); 								\
	} while (false)

#define DISCOVER_RESOLVER_RELEASE(OBJ)															\
	do {																						\
		(OBJ)->ref_count--;																		\
		LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "discover_resolver_t released "	\
			"- ref count after releasing: %u.", (OBJ)->ref_count); 								\
		if ((OBJ)->ref_count == 0) {															\
			_MDNS_STRICT_DISPOSE_TEMPLATE((OBJ), (OBJ)->finalizer);								\
		}																						\
	} while (false)

//======================================================================================================================
// MARK: - Structures

// the addresse of the discovered resolver get by resolving the resolver's name
typedef struct resolver_address resolver_address_t;
struct resolver_address {
	mDNSAddr addr;
	resolver_address_t * NULLABLE next;
};

// the name of the discovered resolver for the given domain.
typedef struct discover_resolver_name discover_resolver_name_t;
struct discover_resolver_name {
	domainname resolver_name; // the discovered resolver name for the given domain
	mDNSInterfaceID NULLABLE interface_id; // the interface id where the response was received
	DNSQuestion ipv4_question; // used to query for IPv4 address of the resolver name
	DNSQuestion ipv6_question; // used to query for IPv6 address of the resolver name

	resolver_address_t * NULLABLE addresses; // linked list of all addresses for the resolver name
	discover_resolver_name_t * NULLABLE next;
};

// the context of resolver discovery.
typedef struct discover_resolver_context discover_resolver_context_t;
struct discover_resolver_context {
	DNSQuestion ns_question; // used to query for the resolver name for the given domain
	discover_resolver_name_t * NULLABLE resolver_names; // linked list of all resolver names for the given domain
};

// This object is used by the caller to start or stop the resolver discovery.
typedef struct discover_resolver discover_resolver_t;
typedef void (* discover_resolver_finalizer_t)(discover_resolver_t * NULLABLE discover_resolver);
struct discover_resolver {
	domainname domain; // The domain that is used to discover the local DNS resolver.
	discover_resolver_context_t * NULLABLE context;
	// The finalizer that will be called to invalidate any ongoing activity and free the memory associated with this
	// object, when the reference count becomes 0.
	discover_resolver_finalizer_t NONNULL finalizer;
	uint32_t ref_count;
};

// The single-linked node type that contains discover_resolver_t.
typedef struct discover_resolver_node discover_resolver_node_t;
struct discover_resolver_node {
	SLIST_ENTRY(discover_resolver_node) __entries;
	discover_resolver_t * NULLABLE discover_resolver;
};

// The single-linked list that contains multiple discover_resolver_t objects.
typedef struct discover_resolver_slist discover_resolver_slist_t;
SLIST_HEAD(discover_resolver_slist, discover_resolver_node);

//======================================================================================================================
// MARK: - Globals

extern mDNS mDNSStorage;
static discover_resolver_slist_t * g_discover_resolvers = NULL;

//======================================================================================================================
// MARK: - Forward Declarations

discover_resolver_t *
discover_resolver_create(const domainname * NONNULL domain);

static void
discover_resolver_finalize(discover_resolver_t * NULLABLE discover_resolver);
#define MDNS_DISPOSE_DISCOVER_RESOLVER(obj) _MDNS_STRICT_DISPOSE_TEMPLATE(obj, discover_resolver_finalize)

static discover_resolver_context_t *
discover_resolver_context_create(void);

static void
discover_resolver_context_dispose(discover_resolver_context_t * NULLABLE context);
#define MDNS_DISPOSE_DISCOVER_RESOLVER_CONTEXT(obj) _MDNS_STRICT_DISPOSE_TEMPLATE(obj, discover_resolver_context_dispose)

static bool
discover_resolver_start(discover_resolver_context_t * NULLABLE context, const domainname * NONNULL domain);

void
discover_resolver_stop(discover_resolver_context_t * NULLABLE context);

//======================================================================================================================
// MARK: - Functions

// discover_resolver_slist_t

static discover_resolver_slist_t * NULLABLE
discover_resolver_slist_create(void)
{
	discover_resolver_slist_t * const me = mdns_calloc(1, sizeof(*me));
	require(me != NULL, exit);

	SLIST_INIT(me);

exit:
	return me;
}

//======================================================================================================================

static discover_resolver_node_t *
discover_resolver_slist_add_front(discover_resolver_slist_t * const NONNULL me,
								  discover_resolver_t * const NONNULL discover_resolver)
{
	discover_resolver_node_t * const n = mdns_calloc(1, sizeof(*n));
	require(n != NULL, exit);

	n->discover_resolver = discover_resolver;
	SLIST_INSERT_HEAD(me, n, __entries);

exit:
	return n;
}

//======================================================================================================================

static bool
discover_resolver_slist_empty(const discover_resolver_slist_t * const NONNULL me)
{
	return SLIST_EMPTY(me);
}

//======================================================================================================================

static void
discover_resolver_slist_dispose(discover_resolver_slist_t * const NONNULL me)
{
	discover_resolver_node_t * n;

	while (!SLIST_EMPTY(me)) {
		n = SLIST_FIRST(me);
		SLIST_REMOVE_HEAD(me, __entries);
		mdns_free(n);
	}

	discover_resolver_slist_t * temp_me = me;
	mdns_free(temp_me);
}
#define MDNS_DISPOSE_DISCOVER_RESOLVER_SLIST(obj) _MDNS_STRICT_DISPOSE_TEMPLATE(obj, discover_resolver_slist_dispose)

//======================================================================================================================

// resolver_address_t

static resolver_address_t *
resolver_address_create(const void * const NONNULL addr_data, mDNSAddr_Type addr_type)
{
	resolver_address_t * resolver_address = NULL;

	require(addr_type == mDNSAddrType_IPv4|| addr_type == mDNSAddrType_IPv6, exit);

	resolver_address = mdns_calloc(1, sizeof(*resolver_address));
	require(resolver_address != NULL, exit);

	if (addr_type == mDNSAddrType_IPv4) {
		memcpy(&resolver_address->addr.ip.v4, addr_data, sizeof(resolver_address->addr.ip.v4));
	} else { // sa_family == mDNSAddrType_IPv6
		memcpy(&resolver_address->addr.ip.v6, addr_data, sizeof(resolver_address->addr.ip.v6));
	}

	resolver_address->addr.type = addr_type;

exit:
	return resolver_address;
}

//======================================================================================================================

static void
resolver_address_delete(resolver_address_t * NONNULL to_be_deleted)
{
	resolver_address_t * temp = to_be_deleted;
	mdns_free(temp);
}

//======================================================================================================================

static resolver_address_t *
resolver_addresses_add(const void * const NONNULL addr_data, const mDNSAddr_Type addr_type,
	resolver_address_t * NULLABLE * const NONNULL out_addresses)
{
	resolver_address_t * resolver_address = resolver_address_create(addr_data, addr_type);
	require(resolver_address != NULL, exit);

	if (*out_addresses != NULL) {
		resolver_address->next = *out_addresses;
	}
	*out_addresses = resolver_address;

exit:
	return resolver_address;
}

//======================================================================================================================

static bool
resolver_addresses_remove(const void * const NONNULL addr_data, mDNSAddr_Type addr_type,
	resolver_address_t * NULLABLE * const NONNULL out_addresses)
{
	bool succeeded;

	require_action(addr_type == mDNSAddrType_IPv4 || addr_type == mDNSAddrType_IPv6, exit, succeeded = false);

	resolver_address_t * prev = NULL;
	resolver_address_t * current = NULL;
	resolver_address_t * next;

	for (current = *out_addresses; current != NULL; current = next) {
		bool found = false;
		next = current->next;
		if (current->addr.type != addr_type) {
			continue;
		}
		if (addr_type == mDNSAddrType_IPv4) {
			found = (memcmp(&current->addr.ip.v4, addr_data, sizeof(current->addr.ip.v4)) == 0);
		} else { // sa_family == AF_INET6
			found = (memcmp(&current->addr.ip.v6, addr_data, sizeof(current->addr.ip.v6)) == 0);
		}
		if (found) {
			break;
		}
		prev = current;
	}

	require_action(current != NULL, exit, succeeded = false);

	if (prev != NULL) {
		prev->next = current->next;
	} else {
		*out_addresses = current->next;
	}

	resolver_address_delete(current);

	succeeded = true;
exit:
	return succeeded;
}

//======================================================================================================================

static void
resolver_addresses_remove_all(resolver_address_t * const NONNULL addresses)
{
	resolver_address_t * current, * next;
	for (current = addresses; current != NULL; current = next) {
		next = current->next;
		resolver_address_delete(current);
	}
}

//======================================================================================================================

static resolver_address_t *
resolver_addresses_find(const void * const NONNULL addr_data, const mDNSAddr_Type addr_type,
	resolver_address_t * const addresses)
{
	resolver_address_t * current = NULL;

	require(addr_type == mDNSAddrType_IPv4 || addr_type == mDNSAddrType_IPv6, exit);

	for (current = addresses; current != NULL; current = current->next) {
		bool found = false;
		if (current->addr.type != mDNSAddrType_IPv6) {
			continue;
		}
		if (addr_type == mDNSAddrType_IPv4) {
			found = (memcmp(&current->addr.ip.v4, addr_data, sizeof(current->addr.ip.v4)) == 0);
		} else { // sa_family == AF_INET6
			found = (memcmp(&current->addr.ip.v6, addr_data, sizeof(current->addr.ip.v6)) == 0);
		}
		if (found) {
			break;
		}
	}

exit:
	return current;
}

//======================================================================================================================
// discover_resolver_name_t

static discover_resolver_name_t *
discover_resolver_name_create(const domainname * const NONNULL resolver_name, const mDNSInterfaceID interface_id)
{
	bool succeeded;
	discover_resolver_name_t * resolver = NULL;

	resolver = mdns_calloc(1, sizeof(*resolver));
	require_action(resolver != NULL, exit, succeeded = false);

	AssignDomainName(&resolver->resolver_name, resolver_name);
	resolver->interface_id = interface_id;

	succeeded = true;
exit:
	if (!succeeded) {
		mdns_free(resolver);
	}
	return resolver;
}

//======================================================================================================================

static void
discover_resolver_name_delete(discover_resolver_name_t * NONNULL to_be_deleted)
{
	if (to_be_deleted->addresses != NULL) {
		resolver_addresses_remove_all(to_be_deleted->addresses);
	}
	discover_resolver_name_t * NULLABLE temp_to_be_deleted = to_be_deleted;
	mdns_free(temp_to_be_deleted);
}

//======================================================================================================================

static discover_resolver_name_t *
discover_resolver_name_add(const domainname * const name, const mDNSInterfaceID interface_id,
		discover_resolver_name_t * NULLABLE * const NONNULL out_resolver_names)
{
	bool succeeded;
	discover_resolver_name_t * new_resolver_name = NULL;

	new_resolver_name = discover_resolver_name_create(name, interface_id);
	require_action(new_resolver_name != NULL, exit, succeeded = false);

	memset(&new_resolver_name->ipv4_question, 0, sizeof(new_resolver_name->ipv4_question));
	memset(&new_resolver_name->ipv6_question, 0, sizeof(new_resolver_name->ipv6_question));

	if (*out_resolver_names != NULL) {
		new_resolver_name->next = *out_resolver_names;
	}
	*out_resolver_names = new_resolver_name;

	succeeded = true;
exit:
	if (!succeeded) {
		if (new_resolver_name != NULL) {
			discover_resolver_name_delete(new_resolver_name);
		}
	}
	return new_resolver_name;
}

//======================================================================================================================

static bool
discover_resolver_name_remove(const domainname * const resolver_name, const mDNSInterfaceID interface_id,
	discover_resolver_name_t * NULLABLE * const NONNULL out_resolver_names)
{
	bool succeeded;
	discover_resolver_name_t * prev = NULL;
	discover_resolver_name_t * current, * next;

	for (current = *out_resolver_names; current != NULL; current = next) {
		next = current->next;
		if (SameDomainName(&current->resolver_name, resolver_name) && current->interface_id == interface_id) {
			break;
		}
		prev = current;
	}

	require_action(current != NULL, exit, succeeded = false);

	if (prev != NULL) {
		prev->next = current->next;
	} else {
		*out_resolver_names = current->next;
	}
	discover_resolver_name_delete(current);

	succeeded = true;
exit:
	return succeeded;
}

//======================================================================================================================

static discover_resolver_name_t *
discover_resolver_name_find(const domainname * const name, mDNSInterfaceID interface_id,
	discover_resolver_name_t * const NULLABLE resolver_names)
{
	discover_resolver_name_t * resolver_name = NULL;

	for (resolver_name = resolver_names; resolver_name != NULL; resolver_name = resolver_name->next) {
		if (SameDomainName(&resolver_name->resolver_name, name) && resolver_name->interface_id == interface_id) {
			break;
		}
	}

	return resolver_name;
}

//======================================================================================================================

bool
resolver_discovery_add(const domainname * const NONNULL domain_to_discover, const bool grab_mdns_lock)
{
	bool succeeded;
	discover_resolver_node_t * np;
	discover_resolver_t * discover_resolver_to_retain = NULL;

	// The list has not been initialized.
	if (g_discover_resolvers == NULL) {
		g_discover_resolvers = discover_resolver_slist_create();
		require_action(g_discover_resolvers != NULL, exit, succeeded = false);
	}

	// Looking for the existing resolver discovery.
	SLIST_FOREACH(np, g_discover_resolvers, __entries) {
		if (!SameDomainName(&np->discover_resolver->domain, domain_to_discover)) {
			continue;
		}
		discover_resolver_to_retain = np->discover_resolver;
		break;
	}

	// Retain the existing one if exists.
	if (discover_resolver_to_retain != NULL) {
		DISCOVER_RESOLVER_RETAIN(discover_resolver_to_retain);
		discover_resolver_to_retain = NULL;
		succeeded = true;
		goto exit;
	}

	// Or create and start a new resolver discovery for the given domain.
	discover_resolver_to_retain = discover_resolver_create(domain_to_discover);
	require_action(discover_resolver_to_retain != NULL, exit, succeeded = false);

	if (grab_mdns_lock) {
		mDNS_Lock(&mDNSStorage);
	}
	succeeded = discover_resolver_start(discover_resolver_to_retain->context, domain_to_discover);
	if (grab_mdns_lock) {
		mDNS_Unlock(&mDNSStorage);
	}
	require(succeeded, exit);

	// Add the new one to the list.
	np = discover_resolver_slist_add_front(g_discover_resolvers, discover_resolver_to_retain);
	require_action(np != NULL, exit, succeeded = false);

	discover_resolver_to_retain = NULL;

exit:
	if (discover_resolver_to_retain != NULL) {
		DISCOVER_RESOLVER_RELEASE(discover_resolver_to_retain);
	}

	return succeeded;
}

//======================================================================================================================

bool
resolver_discovery_remove(const domainname * const NONNULL domain_to_discover, const bool grab_mdns_lock)
{
	bool succeeded = false;
	discover_resolver_node_t * np, * np_temp;

	require_action(g_discover_resolvers != NULL, exit, LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
		"Trying to stop a domain resolver discovery that does not exist - domain: " PRI_DM_NAME ".",
		DM_NAME_PARAM(domain_to_discover)));

	SLIST_FOREACH_SAFE(np, g_discover_resolvers, __entries, np_temp) {
		if (!SameDomainName(&np->discover_resolver->domain, domain_to_discover)) {
			continue;
		}

		if (grab_mdns_lock) {
			mDNS_Lock(&mDNSStorage);
		}
		DISCOVER_RESOLVER_RELEASE(np->discover_resolver);
		if (grab_mdns_lock) {
			mDNS_Unlock(&mDNSStorage);
		}

		// If np->discover_resolver is finalized by DISCOVER_RESOLVER_RELEASE() above, np->discover_resolver will be
		// set to NULL. If so, delete this node from the list.
		if (np->discover_resolver == NULL) {
			SLIST_REMOVE(g_discover_resolvers, np, discover_resolver_node, __entries);
			mdns_free(np);
		}

		succeeded = true;
		break;
	}

	// If the entire list is now empty, delete the list.
	if (discover_resolver_slist_empty(g_discover_resolvers)) {
		MDNS_DISPOSE_DISCOVER_RESOLVER_SLIST(g_discover_resolvers);
	}

exit:
	return succeeded;
}

//======================================================================================================================

bool
dns_question_requires_resolver_discovery(const DNSQuestion * NONNULL q, const domainname ** const out_domain)
{
	// Currently, we only support discovering local resolvers for "openthread.thread.home.arpa."
	// We only do the discovery when the question is not forced to use multicast DNS, because mDNS does not use resolver.
	if (!q->ForceMCast && IsSubdomain(&q->qname, THREAD_DOMAIN_NAME)) {
		*out_domain = THREAD_DOMAIN_NAME;
		return true;
	} else {
		*out_domain = NULL;
		return false;
	}
}

//======================================================================================================================

discover_resolver_t * NULLABLE
discover_resolver_create(const domainname * const NONNULL domain)
{
	discover_resolver_t * returned_discover_resolver = NULL;
	discover_resolver_context_t * discover_resolver_context = NULL;

	discover_resolver_t * discover_resolver = mdns_calloc(1, sizeof(*discover_resolver));
	require(discover_resolver != NULL, exit);

	AssignDomainName(&discover_resolver->domain, domain);

	discover_resolver_context = discover_resolver_context_create();
	require(discover_resolver_context != NULL, exit);

	discover_resolver->context = discover_resolver_context;
	discover_resolver_context = NULL;

	discover_resolver->finalizer = discover_resolver_finalize;
	discover_resolver->ref_count = 1;

	returned_discover_resolver = discover_resolver;
	discover_resolver = NULL;
exit:
	MDNS_DISPOSE_DISCOVER_RESOLVER_CONTEXT(discover_resolver_context);
	MDNS_DISPOSE_DISCOVER_RESOLVER(discover_resolver);
	return returned_discover_resolver;
}

//======================================================================================================================

static void
discover_resolver_finalize(discover_resolver_t * const NULLABLE discover_resolver)
{
	if (discover_resolver == NULL) {
		return;
	}

	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Stopping the resolver discovery for domain - "
		"domain: " PRI_DM_NAME, DM_NAME_PARAM(&discover_resolver->domain));

	if (discover_resolver->context != NULL) {
		discover_resolver_stop(discover_resolver->context);
		MDNS_DISPOSE_DISCOVER_RESOLVER_CONTEXT(discover_resolver->context);
	}

	discover_resolver_t * temp_discover_resolver = discover_resolver;
	mdns_free(temp_discover_resolver);
}

//======================================================================================================================
// discover_resolver_context_t

static discover_resolver_context_t *
discover_resolver_context_create(void)
{
	discover_resolver_context_t * const context = mdns_calloc(1, sizeof(*context));

	memset(&context->ns_question, 0, sizeof(context->ns_question));
	context->resolver_names = NULL;

	return context;
}

//======================================================================================================================

static void
discover_resolver_context_dispose(discover_resolver_context_t * const NULLABLE context)
{
	if (context == NULL) {
		return;
	}

	if (context->resolver_names != NULL) {
		discover_resolver_name_t * current, * next;
		for (current = context->resolver_names; current != NULL; current = next) {
			next = current->next;
			discover_resolver_name_delete(current);
		}
		context->resolver_names = NULL;
	}
	discover_resolver_context_t * temp_context = context;
	mdns_free(temp_context);
}

//======================================================================================================================

static void
discover_resolver_setup_question(DNSQuestion * const NONNULL q, mDNSInterfaceID interface_id,
	const domainname * const NONNULL q_name, uint16_t q_type, bool force_multicast,
	mDNSQuestionCallback * const NULLABLE callback, void * const NONNULL context)
{
	q->InterfaceID = interface_id;
	q->flags = force_multicast ? kDNSServiceFlagsForceMulticast : 0;
	AssignDomainName(&q->qname, q_name);
	q->qtype = q_type;
	q->qclass = kDNSClass_IN;
	q->LongLived = false;
	q->ExpectUnique = false;
	q->ForceMCast = force_multicast;
	q->ReturnIntermed = false;
	q->SuppressUnusable = false;
	q->AppendSearchDomains = false;
	q->TimeoutQuestion = 0;
	q->WakeOnResolve = 0;
	q->UseBackgroundTraffic = false;
	q->pid = mDNSPlatformGetPID();
	q->euid = 0;
	q->QuestionCallback = callback;
	q->QuestionContext = context;
}


//======================================================================================================================

static bool
native_dns_service_register(const domainname * const NONNULL resolver_domain,
	const resolver_address_t * const NONNULL addrs, const uint32_t interface_index,
	const bool reinit_dns_service_definition, discover_resolver_name_t * const NONNULL out_resolver_name)
{
	(void)resolver_domain;
	(void)addrs;
	(void)interface_index;
	(void)reinit_dns_service_definition;
	(void)out_resolver_name;
	return false;
}

//======================================================================================================================

static bool
native_dns_service_deregister(discover_resolver_name_t * const NONNULL resolver_name)
{
	(void) resolver_name;
	return false;
}

//======================================================================================================================

static void
discover_resolver_addr_query_callback(mDNS * const NONNULL m, DNSQuestion * const NONNULL q,
	const ResourceRecord * const NONNULL answer, const QC_result change_event)
{
	bool succeeded;
	bool new_address_created = false;
	discover_resolver_context_t * context = q->QuestionContext;
	discover_resolver_name_t * resolver_name = NULL;
	const void * const addr_data = answer->rdata->u.data;
	const mDNSAddr_Type addr_type = answer->rrtype == kDNSType_A ? mDNSAddrType_IPv4 : mDNSAddrType_IPv6;
	const domainname * const browsing_domain = &context->ns_question.qname;
	mDNS_Lock(m);
	const char * const if_name = InterfaceNameForID(m, q->InterfaceID);
	const uint32_t if_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, q->InterfaceID, mDNSfalse);
	mDNS_Unlock(m);
	const char * action = NULL;
	mDNSAddr addr_changed;

	require_action(change_event == QC_add ||change_event == QC_rmv, exit, succeeded = false);
	require_action(answer->rrtype == kDNSType_A || answer->rrtype == kDNSType_AAAA, exit, succeeded = false);
	require_action(q->InterfaceID == answer->InterfaceID, exit, succeeded = false);

	// Find the corresponding discover_resolver_name_t that starts this address query.
	resolver_name = discover_resolver_name_find(&q->qname, q->InterfaceID, context->resolver_names);
	require_action(resolver_name, exit, succeeded = false);

	// Try to find if there is existing address in the list.
	resolver_address_t * resolver_addr = resolver_addresses_find(addr_data, addr_type, resolver_name->addresses);

	if (change_event == QC_add) {
		// Should have no duplicate addresses for the QC_add event.
		require_action(resolver_addr == NULL, exit, succeeded = false);

		if (resolver_name->addresses == NULL) {
			action = "newly added";
		} else {
			action = "added into the existing one";
		}

		// Add the address into list.
		resolver_addr = resolver_addresses_add(addr_data, addr_type, &resolver_name->addresses);
		require_action(resolver_addr != NULL, exit, succeeded = false);
		new_address_created = true;
		memcpy(&addr_changed, &resolver_addr->addr, sizeof(addr_changed));

		// Add new DNS configuration.
		succeeded = native_dns_service_register(browsing_domain, resolver_addr, if_index, false, resolver_name);
		require(succeeded, exit);

	} else {
		// Should be the added address in the list and should not be removed twice.
		require_action(resolver_addr != NULL, exit, succeeded = false);
		// Should already have configured resolver.

		memcpy(&addr_changed, &resolver_addr->addr, sizeof(addr_changed));

		// Remove the address from the list.
		succeeded = resolver_addresses_remove(addr_data, addr_type, &resolver_name->addresses);
		require(succeeded, exit);

		if (resolver_name->addresses != NULL) {
			succeeded = native_dns_service_register(browsing_domain, resolver_name->addresses, if_index, true,
													resolver_name);
			require(succeeded, exit);
			action = "removed from the existing one";
		} else {
			succeeded = native_dns_service_deregister(resolver_name);
			require(succeeded, exit);
			action = "removed entirely";
		}
	}

	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[Q%u] Resolver " PUB_S " - "
		"browsing domain: " PRI_DM_NAME ", resolver name: " PRI_DM_NAME ", address: " PRI_IP_ADDR
		", interface: " PUB_S ".", mDNSVal16(q->TargetQID), action,
		DM_NAME_PARAM(&context->ns_question.qname), DM_NAME_PARAM(&q->qname), &addr_changed, if_name);

exit:
	if (!succeeded) {
		if (new_address_created) {
			resolver_addresses_remove(addr_data, addr_type, &resolver_name->addresses);
		}
	}
	return;
}

//======================================================================================================================

static bool
discover_resolver_start_addr_query(discover_resolver_context_t * const NONNULL context,
	discover_resolver_name_t * const NONNULL resolver_name, const domainname * const name)
{
	bool succeeded;

	DNSQuestion * const ipv4 = &resolver_name->ipv4_question;
	DNSQuestion * const ipv6 = &resolver_name->ipv6_question;

	// Send address queries as normal
	discover_resolver_setup_question(ipv4, resolver_name->interface_id, name, kDNSType_A, false,
		discover_resolver_addr_query_callback, context);
	discover_resolver_setup_question(ipv6, resolver_name->interface_id, name, kDNSType_AAAA, false,
		discover_resolver_addr_query_callback, context);

	// discover_resolver_start_addr_query() is called as a callback, therefore, mDNSCore lock is not held.
	// mDNS_StartQuery() must be used here instead of mDNS_StartQuery_internal().
	mStatus mdns_err = mDNS_StartQuery(&mDNSStorage, ipv4);
	require_action(mdns_err == mStatus_NoError, exit, succeeded = false);

	mdns_err = mDNS_StartQuery(&mDNSStorage, ipv6);
	require_action(mdns_err == mStatus_NoError, exit, succeeded = false);

	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Starting A/AAAA queries for resolver - name: " PRI_DM_NAME,
		DM_NAME_PARAM(name));

	succeeded = true;
exit:
	return succeeded;
}

static bool
discover_resolver_stop_addr_query(discover_resolver_name_t * const NONNULL resolver_name)
{
	bool succeeded = true;

	// Remove the DNS config added by the resolved addresses.
	succeeded = native_dns_service_deregister(resolver_name);

	// Stop the address queries.
	// discover_resolver_stop_addr_query() is called with lock held, and the two mDNS_StopQuery_internal() below are
	// used to stop the two queries started by mDNS_StartQuery() in discover_resolver_start_addr_query().
	mStatus ipv4_err = mDNS_StopQuery_internal(&mDNSStorage, &resolver_name->ipv4_question);
	mStatus ipv6_err = mDNS_StopQuery_internal(&mDNSStorage, &resolver_name->ipv6_question);
	if (ipv4_err != mStatus_NoError || ipv6_err != mStatus_NoError) {
		succeeded = false;
	}

	return succeeded;
}

//======================================================================================================================

static void
discover_resolver_ns_query_callback(mDNS * const NONNULL UNUSED m, DNSQuestion * const NONNULL q,
	const ResourceRecord * const NONNULL answer, const QC_result change_event)
{
	bool succeeded;
	bool new_resolver_name_created = false;
	discover_resolver_context_t * context = q->QuestionContext;
	const mDNSInterfaceID if_id = answer->InterfaceID;
	const char * const if_name = InterfaceNameForID(&mDNSStorage, if_id);

	require_action(change_event == QC_add || change_event == QC_rmv, exit, succeeded = false);

	if (if_id == mDNSInterface_LocalOnly) {
		succeeded = true;
		goto exit;
	}

	// Find out the corresponding discover_resolver_name_t for resolver name, if exists.
	const domainname * const name = &answer->rdata->u.name;
	discover_resolver_name_t * resolver_name = discover_resolver_name_find(name, if_id, context->resolver_names);

	if (change_event == QC_add) {
		// If there is existing discover_resolver_name_t, do not start duplicate query.
		if (resolver_name != NULL) {
			succeeded = true;
			goto exit;
		}

		// Add current name into list.
		resolver_name = discover_resolver_name_add(name, if_id, &context->resolver_names);
		require_action(resolver_name != NULL, exit, succeeded = false);
		new_resolver_name_created = true;

		LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Name server found for the browsing domain - "
			PRI_DM_NAME " -NS-> " PRI_DM_NAME ", interface: " PUB_S, DM_NAME_PARAM(&q->qname), DM_NAME_PARAM(name),
			if_name ? if_name : "any");

		// Start to resolve the resolver name.
		succeeded = discover_resolver_start_addr_query(context, resolver_name, name);
		require_action(succeeded, exit, false);
	} else { // change_event == QC_rmv
		// Should have the added discover_resolver_name_t
		require_action(resolver_name != NULL, exit, succeeded = false);

		LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Name server disappeared for the browsing domain - "
			PRI_DM_NAME " -NS-> " PRI_DM_NAME ", interface: " PUB_S, DM_NAME_PARAM(&q->qname), DM_NAME_PARAM(name),
			if_name ? if_name : "any");

		// Stop all the address queries started by this resolver name.
		// Since discover_resolver_ns_query_callback() is always called as a callback function without mDNS_Lock held,
		// we need to grab the lock explicitly.
		mDNS_Lock(&mDNSStorage);
		discover_resolver_stop_addr_query(resolver_name);
		mDNS_Unlock(&mDNSStorage);

		// Remove the name from the list
		discover_resolver_name_remove(name, if_id, &context->resolver_names);
	}

	succeeded = true;
exit:
	if (!succeeded) {
		if (new_resolver_name_created) {
			discover_resolver_name_remove(name, if_id, &context->resolver_names);
		}
	}
	return;
}

//======================================================================================================================

static bool
discover_resolver_start_ns_query(discover_resolver_context_t * const NONNULL context,
	const domainname * const NONNULL domain)
{
	bool succeeded;

	// Start NS query with kDNSServiceFlagsForceMulticast.
	DNSQuestion * const q = &context->ns_question;

	discover_resolver_setup_question(q, mDNSInterface_Any, domain, kDNSType_NS, true,
		discover_resolver_ns_query_callback, context);

	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Sending NS query to discover name server - "
		"browsing domain: " PRI_DM_NAME, DM_NAME_PARAM(domain));

	// discover_resolver_start_ns_query() is called with lock held, therefore, mDNS_StartQuery_internal() must be used
	// here instead of mDNS_StartQuery().
	mStatus err = mDNS_StartQuery_internal(&mDNSStorage, q);
	require_action(err == mStatus_NoError, exit, succeeded = false);

	succeeded = true;
exit:
	return succeeded;
}

//======================================================================================================================

static void
discover_resolver_stop_ns_query(discover_resolver_context_t * const NONNULL context)
{
	// Stop all address subqueries.
	for (discover_resolver_name_t * current = context->resolver_names; current != NULL; current = current->next) {
		discover_resolver_stop_addr_query(current);
	}

	// Stop the original NS query.
	mDNS_StopQuery_internal(&mDNSStorage, &context->ns_question);
}

//======================================================================================================================

static bool
discover_resolver_start(discover_resolver_context_t * const NULLABLE context,
	const domainname * const NONNULL domain)
{
	bool succeeded;
	require_action(context != NULL, exit, succeeded = false);

	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Starting the resolver discovery for domain - "
		"domain: " PRI_DM_NAME, DM_NAME_PARAM(domain));
	// Start NS query with kDNSServiceFlagsForceMulticast to learn about the browsing domain with mDNS.
	succeeded = discover_resolver_start_ns_query(context, domain);

exit:
	return succeeded;
}

//======================================================================================================================

void
discover_resolver_stop(discover_resolver_context_t * const NULLABLE context)
{
	if (context == NULL) {
		return;
	}
	discover_resolver_stop_ns_query(context);
}

#else // MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)

// iso C requires a translation unit to contain at least one declaration
typedef int __make_iso_c_happy_about_no_declaration;

#endif // MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
