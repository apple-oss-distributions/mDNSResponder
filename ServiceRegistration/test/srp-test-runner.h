/* srp-test-runner.h
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
 * This file contains definitions for the srp test runner.
 */

#ifndef __SRP_TEST_RUNNER_H__
#define __SRP_TEST_RUNNER_H__ 1
DNSServiceErrorType srp_client_update_record(DNSServiceRef NONNULL sdRef, DNSRecordRef NULLABLE RecordRef,
                                             DNSServiceFlags flags, uint16_t rdlen, const void *NONNULL rdata,
                                             uint32_t ttl);
DNSServiceErrorType srp_client_register(DNSServiceRef NULLABLE *NONNULL sdRef, DNSServiceFlags flags,
                                        uint32_t interfaceIndex, const char *NULLABLE name,
                                        const char *NULLABLE regtype, const char *NULLABLE domain,
                                        const char *NULLABLE host, uint16_t port, uint16_t txtLen,
                                        const void *NONNULL txtRecord, DNSServiceRegisterReply NONNULL callBack,
                                        void *NULLABLE context);
void srp_client_ref_deallocate(DNSServiceRef NONNULL sdRef);
bool srp_test_server_run_test(const char *NONNULL test_to_run);
void *NULLABLE srp_test_server_find_instance(void *NONNULL state, const char *NONNULL name, const char *NONNULL regtype);
#endif

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
