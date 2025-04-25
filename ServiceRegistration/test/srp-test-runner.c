/* srp-test-runner.c
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

ready_callback_t srp_test_dnssd_tls_listener_ready;
void *srp_test_tls_listener_context;
void (*srp_test_dso_message_finished)(void *context, message_t *message, dso_state_t *dso);

typedef struct test_startup_state test_startup_state_t;
struct test_startup_state {
    int variant;
    void (*test_func)(test_state_t *next_test);
    void (*test_variant_func)(test_state_t *next_test, int variant);
    const char *test_name;
};

static void
srp_test_server_start_test(void *context)
{
    test_startup_state_t *startup_state = context;
#if TARGET_OS_IOS || TARGET_OS_OSX || TARGET_OS_TV
    if (startup_state->test_func != NULL) {
        startup_state->test_func(NULL);
    } else if (startup_state->test_variant_func != NULL) {
        startup_state->test_variant_func(NULL, startup_state->variant);
    } else {
        INFO("no test function");
        exit(1);
    }
#else
    INFO("skipping test %s on limited device.", startup_state->test_name);
    exit(0);
#endif
}

bool
srp_test_server_run_test(const char *test_to_run)
{
    bool normal_startup = false;
    test_startup_state_t *startup_state = calloc(1, sizeof(*startup_state));
    if (startup_state == NULL) {
        ERROR("unable to allocate test startup state structure.");
        exit(1);
    }
    if (test_to_run != NULL) {
        startup_state->test_name = test_to_run;

        if (!strcmp(test_to_run, "change-text-record")) {
            startup_state->test_func = test_change_text_record_start;
        } else if (!strcmp(test_to_run, "multi-host-record")) {
            startup_state->test_func = test_multi_host_record_start;
        } else if (!strcmp(test_to_run, "lease-expiry")) {
            startup_state->test_func = test_lease_expiry_start;
        } else if (!strcmp(test_to_run, "lease-renewal")) {
            startup_state->test_func = test_lease_renewal_start;
        } else if (!strcmp(test_to_run, "single-srpl-update")) {
            startup_state->test_func = test_single_srpl_update;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_BOTH;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup-first")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_FIRST;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup-last")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_LAST;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup-add-first")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_FIRST;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup-add-last")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_LAST;
        } else if (!strcmp(test_to_run, "srpl-two-instances-dup-2keys")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_TWO_KEYS;
        } else if (!strcmp(test_to_run, "srpl-two-instances")) {
            startup_state->test_variant_func = test_srpl_host_2i;
            startup_state->variant = DUP_TEST_VARIANT_NO_DUP;
        } else if (!strcmp(test_to_run, "srpl-two-instances-one-remove")) {
            startup_state->test_func = test_srpl_host_2ir;
        } else if (!strcmp(test_to_run, "srpl-zero-instances-two-servers")) {
            startup_state->test_func = test_srpl_host_0i2s;
        } else if (!strcmp(test_to_run, "srpl-lease-time")) {
            startup_state->test_func = test_srpl_lease_time;
        } else if (!strcmp(test_to_run, "dns-dangling-query")) {
            startup_state->test_func = test_dns_dangling_query;
        } else if (!strcmp(test_to_run, "srpl-cycle-through-peers")) {
            startup_state->test_func = test_srpl_cycle_through_peers;
        } else if (!strcmp(test_to_run, "srpl-update-after-remove")) {
            startup_state->test_func = test_srpl_update_after_remove;
        } else if (!strcmp(test_to_run, "dns-push-hardwired")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_HARDWIRED;
        } else if (!strcmp(test_to_run, "dns-push-mdns")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_MDNS;
        } else if (!strcmp(test_to_run, "dns-hardwired")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_DNS_HARDWIRED;
        } else if (!strcmp(test_to_run, "dns-mdns")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_DNS_MDNS;
        } else if (!strcmp(test_to_run, "dns-push-crash")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_DAEMON_CRASH;
        } else if (!strcmp(test_to_run, "dns-crash")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_DNS_CRASH;
        } else if (!strcmp(test_to_run, "dns-two")) {
            startup_state->test_variant_func = test_dns_push;
            startup_state->variant = PUSH_TEST_VARIANT_TWO_QUESTIONS;
        } else if (!strcmp(test_to_run, "listener-longevity")) {
            startup_state->test_func = test_listen_longevity_start;
        } else if (!strcmp(test_to_run, "ifaddrs")) {
            startup_state->test_func = test_ifaddrs_start;
        } else if (!strcmp(test_to_run, "thread-startup")) {
            startup_state->test_func = test_thread_startup;
            normal_startup = true;
        } else {
            INFO("test to run: %s", test_to_run);
            exit(1);
        }
        ioloop_run_async(srp_test_server_start_test, startup_state, NULL);
    } else {
        INFO("no test to run");
        exit(1);
    }
    return normal_startup;
}

void *
srp_test_server_find_instance(void *state, const char *name, const char *regtype)
{
    test_state_t *test_state = (test_state_t *)state;
    srp_server_t *server = test_state->primary;
    adv_host_t *host;
    adv_instance_t *instance;

    for (host = server->hosts; host != NULL; host = host->next) {
        if (host->instances != NULL) {
            for (int i = 0; i < host->instances->num; i++) {
                if (host->instances->vec[i] != NULL) {
                    instance = host->instances->vec[i];
                    if (!strcmp(instance->instance_name, name) &&
                        !strcmp(instance->service_type, regtype))
                    {
                        return instance;
                    }
                }
            }
        }
    }
    return NULL;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
