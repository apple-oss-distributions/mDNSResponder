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

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "dns_push_obj_discovered_service_manager.h"

#include "dns_service.h"
#include "dns_obj_log.h"
#include "dns_push_obj.h"
#include "QuerierSupport.h"

#include "mdns_strict.h"

//======================================================================================================================
// MARK: - DNS Push Discovered Service Manager Kind Definition

struct dns_push_obj_discovered_service_manager_s {
	struct ref_count_obj_s	base;	// The reference count and kind support base.
	dns_obj_domain_name_t	discovered_authoritative_zone;
	uint32_t				if_index;
	mdns_dns_service_id_t	service_id;
};

DNS_PUSH_OBJECT_DEFINE_WITH_INIT_WITHOUT_COMPARATOR(discovered_service_manager);

//======================================================================================================================
// MARK: - DNS Push Discovered Service Manager Public Methods

dns_push_obj_discovered_service_manager_t
dns_push_obj_discovered_service_manager_create(const dns_obj_domain_name_t discovered_authoritative_zone,
	const uint32_t if_index, dns_obj_error_t * const out_error)
{
	dns_obj_error_t err;
	dns_obj_domain_name_t dns_push_srv = NULL;
	mdns_domain_name_t mdns_dns_push_srv = NULL;
	dns_push_obj_discovered_service_manager_t manager = NULL;
	dns_push_obj_discovered_service_manager_t object = NULL;

	static dns_obj_domain_name_t dns_push_service_type = NULL;
	if (!dns_push_service_type) {
		dns_push_service_type = dns_obj_domain_name_create_with_cstring("_dns-push-tls._tcp", &err);
		mdns_require_noerr_quiet(err, exit);
	}
	mdns_require_action_quiet(dns_push_service_type, exit, err = DNS_OBJ_ERROR_UNEXPECTED_ERR);

	object = _dns_push_obj_discovered_service_manager_new();
	mdns_require_action_quiet(object, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	object->discovered_authoritative_zone = discovered_authoritative_zone;
	dns_obj_retain(object->discovered_authoritative_zone);
	object->if_index = if_index;

	const mdns_dns_service_manager_t mdns_manager = Querier_GetDNSServiceManager();
	mdns_require_action_quiet(mdns_manager, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	dns_push_srv = dns_obj_domain_name_create_concatenation(dns_push_service_type, discovered_authoritative_zone, &err);
	mdns_require_noerr_quiet(err, exit);

	const uint8_t * const dns_push_srv_labels = dns_obj_domain_name_get_labels(dns_push_srv);
	mdns_dns_push_srv = mdns_domain_name_create_with_labels(dns_push_srv_labels, NULL);
	mdns_require_action_quiet(mdns_dns_push_srv, exit, err = DNS_OBJ_ERROR_NO_RESOURCES);

	mdns_dns_service_t service = mdns_dns_service_manager_get_push_service(mdns_manager, mdns_dns_push_srv, if_index);
	mdns_require_action_quiet(!service, exit, err = DNS_OBJ_ERROR_ALREADY_INITIALIZED_ERR);

	const mdns_dns_service_id_t service_id = mdns_dns_service_manager_register_push_service(mdns_manager,
		mdns_dns_push_srv, if_index, NULL);
	mdns_require_action_quiet(service_id != MDNS_DNS_SERVICE_INVALID_ID, exit, err = DNS_OBJ_ERROR_UNEXPECTED_ERR);

	object->service_id = service_id;
	dns_push_obj_replace(&manager, object);
	err = DNS_OBJ_ERROR_NO_ERROR;

exit:
	dns_obj_forget(&dns_push_srv);
	mdns_forget(&mdns_dns_push_srv);
	dns_push_obj_forget(&object);
	mdns_assign(out_error, err);
	return manager;
}

//======================================================================================================================

bool
dns_push_obj_discovered_service_manager_manages_this_zone(dns_push_obj_discovered_service_manager_t me,
	const dns_obj_domain_name_t discovered_authoritative_zone, const uint32_t if_index)
{
	return (dns_obj_equal(me->discovered_authoritative_zone, discovered_authoritative_zone)
			&& me->if_index == if_index);
}

//======================================================================================================================
// MARK: - DNS Push Discovered Service Manager Private Methods

static void
_dns_push_obj_discovered_service_manager_initialize(dns_push_obj_discovered_service_manager_t me)
{
	me->service_id = MDNS_DNS_SERVICE_INVALID_ID;
}

//======================================================================================================================

static void
_dns_push_obj_discovered_service_manager_finalize(dns_push_obj_discovered_service_manager_t me)
{
	dns_obj_forget(&me->discovered_authoritative_zone);
	if (me->service_id != MDNS_DNS_SERVICE_INVALID_ID) {
		const mdns_dns_service_manager_t mdns_manager = Querier_GetDNSServiceManager();
		mdns_require_return(mdns_manager);

		mdns_dns_service_manager_deregister_native_service(mdns_manager, me->service_id);
	}
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
