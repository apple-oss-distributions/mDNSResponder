/* dns_message_received.c
 *
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
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
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <netdb.h>              // For gethostbyname()
#include <sys/socket.h>         // For AF_INET, AF_INET6, etc.
#include <net/if.h>             // For IF_NAMESIZE
#include <netinet/in.h>         // For INADDR_NONE
#include <netinet/tcp.h>        // For SOL_TCP, TCP_NOTSENT_LOWAT
#include <arpa/inet.h>          // For inet_addr()
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "dns_sd.h"
#include "DNSCommon.h"
#include "mDNSEmbeddedAPI.h"
#include "dso.h"
#include "dso-transport.h"

#ifdef FUZZING_DNS_MESSAGE_RECEIVED

/*
typedef struct
{
    mDNSOpaque16 id;
    mDNSOpaque16 flags;
    mDNSu16 numQuestions;
    mDNSu16 numAnswers;
    mDNSu16 numAuthorities;
    mDNSu16 numAdditionals;
} DNSMessageHeader;
*/

/*
struct dso_state {
    dso_state_t *next;
    void *context;                   // The context of the next layer up (e.g., a Discovery Proxy)
    dso_event_callback_t cb;         // Called when an event happens

    // Transport state; handled separately for reusability
    dso_transport_t *transport;      // The transport (e.g., dso-transport.c or other).
    dso_transport_finalize_t transport_finalize;

    uint32_t serial;                 // Unique serial number which can be used after the DSO has been dropped.
    bool is_server;                  // True if the endpoint represented by this DSO state is a server
                                     // (according to the DSO spec)
    bool has_session;                // True if DSO session establishment has happened for this DSO endpoint
    event_time_t response_awaited;   // If we are waiting for a session-establishing response, when it's
                                     // expected; otherwise zero.
    uint32_t keepalive_interval;     // Time between keepalives (to be sent, on client, expected, on server)
    uint32_t inactivity_timeout;     // Session can't be inactive more than this amount of time.
    event_time_t keepalive_due;      // When the next keepalive is due (to be received or sent)
    event_time_t inactivity_due;     // When next activity has to happen for connection to remain active
    dso_activity_t *activities;      // Outstanding DSO activities.

    dso_tlv_t primary;               // Primary TLV for current message
    dso_tlv_t additl[MAX_ADDITLS];   // Additional TLVs
    int num_additls;                 // Number of additional TLVs in this message

    char *remote_name;

    dso_outstanding_query_state_t *outstanding_queries;
};
*/

dso_state_t *dso_state_create(bool is_server, int max_outstanding_queries, const char *remote_name,
                              dso_event_callback_t callback, void *const context,
                              const dso_life_cycle_context_callback_t context_callback,
                              dso_transport_t *transport);

void dns_message_received(dso_state_t *dso, const uint8_t *message, size_t message_length);

int
LLVMFuzzerTestOneInput
(
    const char      * Data,
    const size_t    Length
)
{
    if(Length < sizeof(DNSMessageHeader)) {
        return 0;
    }

    dso_state_t            *dso = dso_state_create(false, 1, "remote", 0, 0, 0, 0);
    DNSMessageHeader    message;

    memcpy(&message, Data, sizeof(message));

    // dns_message_received(dso, (char*) &message, Length);

    free(dso);

    return 0;
}



#endif /* ifdef FUZZING_DNS_MESSAGE_RECEIVED */
