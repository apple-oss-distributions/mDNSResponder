/* thread-startup.c
 *
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
 *
 * Test to see that thread starts up and is configured correctly.
 */

#include "srp.h"
#include <dns_sd.h>
#include "srp-test-runner.h"
#include "srp-api.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "srp-mdns-proxy.h"
#include "test-api.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "test-dnssd.h"
#include "test.h"
#include "srp-replication.h"
#include "test-packet.h"
#include "srp-proxy.h"
#include "dns-msg.h"
#include "adv-ctl-server.h"
#include "cti-services.h"
#include "route.h"
#include "threadsim.h"

void
test_thread_startup(test_state_t *next_test)
{
    extern srp_server_t *srp_servers;
    const char *description =
        "  The goal of this test is to start a simulated thread network and see what happens.";
	test_state_t *state = test_state_create(srp_servers, "Thread Startup test", NULL, description, NULL);

    srp_proxy_init("local");
    state->primary->stub_router_enabled = true;
    srp_servers->srp_replication_enabled = true;
    srp_servers->route_state = route_state_create(srp_servers, "srp-test");
    TEST_FAIL_CHECK(state, srp_servers->route_state != NULL, "no memory for route state object");
    state->threadsim_network_state = threadsim_network_state_create();
    srp_servers->threadsim_node = threadsim_node_state_create(state->threadsim_network_state, srp_servers, kCTI_NCPState_Associated, kCTI_NetworkNodeType_Router);
    state->next = next_test;

    adv_proxy_wanted(srp_servers);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
