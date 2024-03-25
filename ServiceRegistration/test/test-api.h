/* test-api.c
 *
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
 *
 * srp host API test harness
 */

typedef struct test_state test_state_t;
typedef struct io_context io_context_t;
typedef struct dns_service_event dns_service_event_t;
typedef struct test_packet_state test_packet_state_t;

struct test_state {
    test_state_t *NULLABLE next, *NULLABLE finished_tests;
    srp_server_t *NULLABLE primary;
    comm_t *NULLABLE srp_listener;
    io_context_t *NULLABLE current_io_context;
    test_packet_state_t *NULLABLE test_packet_state;
    dns_service_event_t *NULLABLE dns_service_events;
    const char *NONNULL title;
    const char *NULLABLE variant_title;
    const char *NONNULL explanation;
    const char *NULLABLE variant_info;
    void (*NULLABLE continue_testing)(test_state_t *NONNULL next_state);
    int variant;
    bool test_complete;
};

#define TEST_FAIL(test_state, message)                          \
    do {                                                        \
        srp_test_state_explain(test_state);                     \
        fprintf(stderr, "test failed: " message "\n\n");        \
        exit(1);                                                \
    } while (0)

#define TEST_FAIL_CHECK(test_state, success_condition, message) \
    do {                                                        \
        if (!(success_condition)) {                             \
            TEST_FAIL(test_state, message);                     \
        }                                                       \
    } while (0)

#define TEST_FAIL_STATUS(test_state, message, status)               \
    do {                                                            \
           srp_test_state_explain(test_state);                      \
           fprintf(stderr, "test failed: " message "\n\n", status); \
           exit(1);                                                 \
    } while (0)

#define TEST_FAIL_CHECK_STATUS(test_state, success_condition, message, status) \
    do {                                                                       \
       if (!(success_condition)) {                                             \
           TEST_FAIL_STATUS(test_state, message, status);                      \
       }                                                                       \
    } while (0)

#define TEST_PASSED(test_state)         \
    srp_test_state_explain(test_state); \
    INFO("test passed\n");              \
    srp_test_state_next(test_state);

void srp_test_set_local_example_address(test_state_t *NONNULL state);
void srp_test_network_localhost_start(test_state_t *NONNULL state);
test_state_t *NULLABLE test_state_create(srp_server_t *NONNULL primary,
                                         const char *NONNULL title, const char *NULLABLE variant_title,
                                         const char *NONNULL explanation, const char *NULLABLE variant_name);
void test_state_add_srp_server(test_state_t *NONNULL state, srp_server_t *NONNULL server);
void srp_test_state_explain(test_state_t *NULLABLE state);
void srp_test_state_next(test_state_t *NONNULL state);
void srp_test_state_add_timeout(test_state_t *NONNULL state, int timeout);

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
