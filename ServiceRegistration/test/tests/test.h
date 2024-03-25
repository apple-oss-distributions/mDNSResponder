/* test.h
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
 * This file contains the SRP server test runner.
 */

#define TEST_INSTANCE_NAME_3      "third-instance"
#define TEST_INSTANCE_NAME_2      "second-instance"
#define TEST_INSTANCE_NAME        "test-client"
#define TEST_SERVICE_TYPE         "_srp-test._udp"
#define TEST_HOST_NAME            "test-client"
#define TEST_HOST_NAME_REGISTERED "test-client.local."

#define DUP_TEST_VARIANT_BOTH      1
#define DUP_TEST_VARIANT_FIRST     2
#define DUP_TEST_VARIANT_LAST      3
#define DUP_TEST_VARIANT_ADD_FIRST 4
#define DUP_TEST_VARIANT_ADD_LAST  5
#define DUP_TEST_VARIANT_TWO_KEYS  6
#define DUP_TEST_VARIANT_NO_DUP    7

void test_change_text_record_start(test_state_t *NULLABLE next_state);
void test_lease_expiry_start(test_state_t *NULLABLE next_state);
void test_lease_renewal_start(test_state_t *NULLABLE next_state);
void test_multi_host_record_start(test_state_t *NULLABLE next_state);
void test_single_srpl_update(test_state_t *NULLABLE next_test);
void test_srpl_host_2i(test_state_t *NULLABLE next_test, int variant);
void test_srpl_host_2ir(test_state_t *NULLABLE next_test);
void test_srpl_host_0i2s(test_state_t *NULLABLE next_test);

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
