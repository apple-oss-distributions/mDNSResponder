/* registration-lease-expiry.c
 *
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
 *
 * This file contains the SRP server test runner.
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

#define LEASE_TIME 10

static void
test_lease_expiry_register_evaluate(test_state_t *state)
{
    adv_instance_t *instance = srp_test_server_find_instance(state, TEST_INSTANCE_NAME, TEST_SERVICE_TYPE);
    TEST_FAIL_CHECK(state, instance != NULL, "instance is not found in cache");
    dns_service_event_t *register_event = dns_service_find_first_register_event_by_name_and_type(state->primary,
                                                                                                 TEST_INSTANCE_NAME,
                                                                                                 TEST_SERVICE_TYPE);
    TEST_FAIL_CHECK(state, register_event != NULL, "failed to register service");
}

static void
test_lease_expiry_expire_evaluate(test_state_t *state)
{
    adv_instance_t *instance = srp_test_server_find_instance(state, TEST_INSTANCE_NAME, TEST_SERVICE_TYPE);
    TEST_FAIL_CHECK(state, instance == NULL, "instance is still in cache");
    dns_service_event_t *deallocate_event = dns_service_find_ref_deallocate_event(state->primary);
    TEST_FAIL_CHECK(state, deallocate_event != NULL, "failed to remove service");
    TEST_PASSED(state);
}

static void
test_lease_expiry_callback(DNSServiceRef sdref, DNSServiceFlags UNUSED flags, DNSServiceErrorType errorCode,
                                 const char *name, const char *regtype, const char *UNUSED domain, void *context)
{
    srp_server_t *server_state = context;
    test_state_t *state = server_state->test_state;

    INFO("Register Reply for %s . %s: %d", name, regtype, errorCode);
    INFO("state = %p", state);

    if (errorCode != kDNSServiceErr_NoError) {
        TEST_FAIL_STATUS(state, "registration failed: srp_client_register callback returned %d", errorCode);
    }

    // Allow time for the mDNS registration to finish
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 2), dispatch_get_main_queue(), ^{
        void *io_context = state->current_io_context;
        TEST_FAIL_CHECK(state, io_context != NULL, "NULL io_context");
        srp_cancel_wakeup(server_state, io_context);// cancel the lease renewal
        test_lease_expiry_register_evaluate(state);

        // Allow time for the lease to expire and check the registration again
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * LEASE_TIME), dispatch_get_main_queue(), ^{
            srp_client_ref_deallocate(sdref);
            test_lease_expiry_expire_evaluate(state);
        });
    });
}

static void
test_lease_expiry_ready(void *context, uint16_t UNUSED port)
{
    srp_server_t *state = context;

    int ret = srp_host_init(state);
    srp_set_lease_times(LEASE_TIME, LEASE_TIME);
    TEST_FAIL_CHECK(state->test_state, ret == kDNSServiceErr_NoError, "srp_host_init failed");

    DNSServiceRef ref;
    INFO("Lease expiry test");
    char txt_buf[128];
    TXTRecordRef txt;

    TXTRecordCreate(&txt, sizeof(txt_buf), txt_buf);
    TXTRecordSetValue(&txt, "foo", 1, "1");
    TXTRecordSetValue(&txt, "bar", 3, "1.1");
    const char *txt_data = TXTRecordGetBytesPtr(&txt);
    int txt_len = TXTRecordGetLength(&txt);

    // Create a DNSSD client
    ret = srp_client_register(&ref, 0 /* flags */, 0 /* interfaceIndex */,
                              TEST_INSTANCE_NAME /* name */, TEST_SERVICE_TYPE /* regType */,
                              NULL /* domain */, TEST_HOST_NAME /* host */, 1234, txt_len, txt_data,
                              test_lease_expiry_callback, state);
    TEST_FAIL_CHECK_STATUS(state->test_state, ret == kDNSServiceErr_NoError, "srp_client_register returned %d", ret);
    srp_test_network_localhost_start(state->test_state);
}

void
test_lease_expiry_start(test_state_t *next_state)
{
    extern srp_server_t *srp_servers;
    const char *description =
        "    The goal of this test is to validate that when the lease provided by the client expires,\n"
        "    the service and host entries are removed. The test first sets the lease time that the client\n"
        "    requests to 10 seconds. It then registers a host and service. Assuming that the registration\n"
        "    is successful, it stops further updates and then waits for the lease to expire. When the lease\n"
        "    expires, it checks to see that the records and service that were registered have all been\n"
        "    deallocated.";
    test_state_t *state = test_state_create(srp_servers, "Lease Expiry test", NULL, description, NULL);

    srp_proxy_init("local");
    srp_test_enable_stub_router(state, srp_servers);
    state->primary->min_lease_time = LEASE_TIME;
    state->srp_listener = srp_proxy_listen(NULL, 0, NULL, test_lease_expiry_ready, NULL, NULL, NULL, state->primary);
    TEST_FAIL_CHECK(state, state->srp_listener != NULL, "listener create failed");
    state->next = next_state;

    // Test should not take longer than 2*LEASE_TIME.
    srp_test_state_add_timeout(state, 2 * LEASE_TIME);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
