/*
 * Copyright (c) 2023-2024 Apple Inc. All rights reserved.
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

#include "discovery_proxy.h"

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)

#include "general.h"
#include "mDNSMacOSX.h"
#include "QuerierSupport.h"
#include "tls-keychain.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreUtils/CommonServices.h>
#include <MacTypes.h>
#include <stdint.h>

#include "mdns_strict.h"

//======================================================================================================================

static mdns_dns_service_id_t g_discovery_proxy_service_id = MDNS_DNS_SERVICE_INVALID_ID;

//======================================================================================================================
// MARK: - Internal Functions

static void
_discovery_proxy_stop_internal(void)
{
	if (g_discovery_proxy_service_id != MDNS_DNS_SERVICE_INVALID_ID) {
		Querier_DeregisterCustomPushDNSService(g_discovery_proxy_service_id);
		LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "Discovery proxy service deregistered -- id: %" PRIu64,
			g_discovery_proxy_service_id);
		g_discovery_proxy_service_id = MDNS_DNS_SERVICE_INVALID_ID;
	}
}

static OSStatus
_discovery_proxy_stop_handler(void)
{
	OSStatus err = kNoErr;
	KQueueLock();
	_discovery_proxy_stop_internal();
	KQueueUnlock("discovery_proxy_stop_handler");
	return err;
}

//======================================================================================================================

static mdns_dns_push_service_definition_t
_discovery_proxy_create_push_service_definition(const uint32_t ifindex, const CFArrayRef addresses,
	const CFArrayRef match_domains, const CFArrayRef trusted_certs, OSStatus * const out_error)
{
	OSStatus err;
	mdns_dns_push_service_definition_t result = NULL;
	mdns_dns_push_service_definition_t service_definition;

	service_definition = mdns_dns_push_service_definition_create();
	mdns_require_action_quiet(service_definition, exit, err = kNoResourcesErr);

	// The interface index must be non-zero for the discovery proxy.
	mdns_require_action_quiet(ifindex != 0, exit, err = kParamErr);
	mdns_dns_push_service_definition_set_interface_index(service_definition, ifindex,
		mdns_dns_service_interface_scope_unscoped_and_scoped);

	mdns_dns_push_service_definition_set_local_purview(service_definition, true);
	mdns_dns_push_service_definition_set_mdns_alternative(service_definition, true);

	const CFIndex n_address = CFArrayGetCount(addresses);
	for (CFIndex i = 0; i < n_address; i++) {
		const mdns_address_t server_address = (mdns_address_t)CFArrayGetValueAtIndex(addresses, i);
		mdns_dns_push_service_definition_append_server_address(service_definition, server_address);
	}
	const CFIndex n_match_domains = CFArrayGetCount(match_domains);
	for (CFIndex i = 0; i < n_match_domains; i++) {
		const mdns_domain_name_t match_domain = (mdns_domain_name_t)CFArrayGetValueAtIndex(match_domains, i);
		mdns_dns_push_service_definition_add_domain(service_definition, match_domain);
	}
	const CFIndex n_trusted_certs = CFArrayGetCount(trusted_certs);
	for (CFIndex i = 0; i < n_trusted_certs; i++) {
		const CFDataRef trusted_cert = (CFDataRef)CFArrayGetValueAtIndex(trusted_certs, i);
		mdns_dns_push_service_definition_append_trusted_certificate(service_definition, trusted_cert);
	}
	result = service_definition;
	service_definition = NULL;
	err = kNoErr;

exit:
	mdns_forget(&service_definition);
	if (out_error) {
		*out_error = err;
	}
	return result;
}

//======================================================================================================================

static OSStatus
_discovery_proxy_start_handler(const uint32_t ifindex, const CFArrayRef addresses, const CFArrayRef match_domains,
	const CFArrayRef server_certificates)
{
	OSStatus err = 0;
	mdns_dns_push_service_definition_t service_definition = NULL;
	KQueueLock();

	_discovery_proxy_stop_internal();

	service_definition = _discovery_proxy_create_push_service_definition(ifindex, addresses, match_domains,
		server_certificates, &err);
	mdns_require_noerr_quiet(err, exit);

	g_discovery_proxy_service_id = Querier_RegisterCustomPushDNSService(service_definition);
	mdns_require_action_quiet(g_discovery_proxy_service_id != MDNS_DNS_SERVICE_INVALID_ID, exit, err = kNotHandledErr);

	LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_DEFAULT, "Discovery proxy service registered -- id: %" PRIu64,
		g_discovery_proxy_service_id);

exit:
	mdns_forget(&service_definition);
	KQueueUnlock("discovery_proxy_start_handler");
	return err;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)

//======================================================================================================================
// MARK: - External Variables

const struct mrcs_server_discovery_proxy_handlers_s kMRCSServerDiscoveryProxyHandlers =
{
#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)
	.start = _discovery_proxy_start_handler,
	.stop = _discovery_proxy_stop_handler,
#else
	.start = NULL,
	.stop = NULL,
#endif
};
