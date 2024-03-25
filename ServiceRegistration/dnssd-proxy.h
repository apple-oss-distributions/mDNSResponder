/* dnssd-proxy.h
 *
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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
 * Discovery Proxy globals.
 */

#ifndef __DNSSD_PROXY_H__
#define __DNSSD_PROXY_H__

#include "srp-features.h"
#include "dns-msg.h"
#include "ioloop.h"

//======================================================================================================================
// MARK: - Macros

#define MAX_ADDRS 10

#if (!SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)
    // FIXME: set CERTWRITE_PROGRAM and GENKEY_PROGRAM to correct one.
    #ifndef CERTWRITE_PROGRAM
        #define CERTWRITE_PROGRAM "/bin/echo"
    #endif
    #ifndef GENKEY_PROGRAM
        #define GENKEY_PROGRAM "/bin/echo"
    #endif
#endif // #if (!SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)

#define AUTOMATIC_BROWSING_DOMAIN "lb._dns-sd._udp.local."
#define THREAD_NETWORK_NAME "openthread"
#define THREAD_BROWSING_DOMAIN THREAD_NETWORK_NAME ".thread.home.arpa."

//======================================================================================================================
// MARK: - Functions

// We can only initialize dnssd-proxy in srp-mdns-proxy if we combined it with srp-mdns-proxy.
#if (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY) && !defined(RA_TESTER)
bool init_dnssd_proxy(srp_server_t *NONNULL server_state);
bool delete_served_domain_by_interface_name(const char *const NONNULL interface_name);
void dns_proxy_input(comm_t *NONNULL comm, message_t *NONNULL message, void *NULLABLE context);
#endif // #if (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)

void dnssd_proxy_ifaddr_callback(void *NULLABLE context, const char *NONNULL name, const addr_t *NONNULL address,
                                 const addr_t *NONNULL mask, uint32_t UNUSED flags,
                                 enum interface_address_change event_type);
void dp_start_dropping(void);
void dns_proxy_input_for_server(comm_t *NONNULL comm,
                                srp_server_t *NONNULL server_state, message_t *NONNULL message, void *NULLABLE context);
#endif // #ifndef __DNSSD_PROXY_H__

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
