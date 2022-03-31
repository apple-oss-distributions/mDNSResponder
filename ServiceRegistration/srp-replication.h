/* srp-replication.h
 *
 * Copyright (c) 2020-2021 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file contains structure definitions and external definitions for the SRP Replication code.
 */

#ifndef __SRP_REPLICATION_H__
#define __SRP_REPLICATION_H__

// States: each state has a function, which bears the name of the state. The function takes an
//         srpl_connection_t and an srpl_event_t. The function is called once on entering the
//         state, once on leaving the state, and once whenever an event arrives while in the state.
//
//         Whenever this function is called, it returns a next state. If the next state is
//         "invalid," that means that there is no state change.
//
// Events: Events can be triggered by connection activities, e.g. connect, disconnect, add_address, etc.
//         They can also be triggered by the arrival of messages on connections.
//         They can also be triggered by happenings on the srp server.
//         Events are never sent by state actions.
//         Each event has a single function which sends the event. That function may in some cases force
//         a state change (e.g., a disconnect event). This is the exception, not the rule. Events are
//         otherwise handled by the state action function for the current state.
//
// In some cases, an event that's expected to be delivered asynchronously arrives synchronously because
// no asynchronous action was required. In this case, the action that can trigger this synchronous event
// has to also handle the event. Since the event is normally expected to be delivered asynchronously,
// the right solution in this case is to queue the event for later delivery.
//
// An example of this pattern is in srpl_advertise_finished_event_defer. Because events are normally automatic
// variables, any event that needs to be deferred has to be allocated and its contents (if any) copied. The
// srpl_connection_t is stashed on the event; srpl_deferred_event_deliver is then called asynchronously to deliver the
// event, release the reference to the srpl_connection_t, and free the event data structure.

enum srpl_state {
    srpl_state_invalid = 0,  // Only as a return value, means do not move to a new state

    // Connection-related states
    srpl_state_disconnected,
    srpl_state_next_address_get,
    srpl_state_connect,
    srpl_state_idle,
    srpl_state_reconnect_wait,
    srpl_state_retry_delay_send,
    srpl_state_disconnect,
    srpl_state_disconnect_wait,
    srpl_state_connecting,

    // Session establishment
    srpl_state_server_id_send,
    srpl_state_server_id_response_wait,
    srpl_state_server_id_evaluate,
    srpl_state_server_id_regenerate,

    // Requesting and getting remote candidate list
    srpl_state_send_candidates_send,
    srpl_state_send_candidates_wait,

    // Waiting for candidate to arrive
    srpl_state_candidate_check,

    // Waiting for a host to arrive after requesting it
    srpl_state_candidate_host_wait,
    srpl_state_candidate_host_prepare,
    srpl_state_candidate_host_contention_wait,
    srpl_state_candidate_host_re_evaluate,
    srpl_state_candidate_host_apply,
    srpl_state_candidate_host_apply_wait,

    // Getting request for candidate list and sending them.
    srpl_state_send_candidates_received,
    srpl_state_send_candidates_remaining_check,
    srpl_state_next_candidate_send,
    srpl_state_next_candidate_send_wait,
    srpl_state_candidate_host_send,
    srpl_state_candidate_host_response_wait,

    // When we're done sending candidates
    srpl_state_send_candidates_response_send,

    // Ready states
    srpl_state_ready,
    srpl_state_srp_client_update_send,
    srpl_state_srp_client_ack_evaluate,
    srpl_state_stashed_host_check,
    srpl_state_stashed_host_apply,
    srpl_state_stashed_host_finished,

    // States for connections received by this server
    srpl_state_session_message_wait,
    srpl_state_session_response_send,
    srpl_state_send_candidates_message_wait,
};

enum srpl_event_type {
    srpl_event_invalid = 0,
    srpl_event_address_add,
    srpl_event_address_remove,
    srpl_event_server_disconnect,
    srpl_event_reconnect_timer_expiry,
    srpl_event_disconnected,
    srpl_event_connected,
    srpl_event_session_response_received,
    srpl_event_send_candidates_response_received,
    srpl_event_candidate_received,
    srpl_event_host_message_received,
    srpl_event_srp_client_update_finished,
    srpl_event_advertise_finished,
    srpl_event_candidate_response_received,
    srpl_event_host_response_received,
    srpl_event_session_message_received,
    srpl_event_send_candidates_message_received,
};
enum srpl_candidate_disposition { srpl_candidate_yes, srpl_candidate_no, srpl_candidate_conflict };

typedef struct srpl_connection srpl_connection_t;
typedef struct srpl_instance srpl_instance_t;
typedef struct srpl_domain srpl_domain_t;
typedef struct address_query address_query_t;
typedef struct unclaimed_connection unclaimed_connection_t;
typedef enum srpl_state srpl_state_t;
typedef enum srpl_event_type srpl_event_type_t;
typedef struct srpl_event srpl_event_t;
typedef struct srpl_candidate srpl_candidate_t;
typedef enum srpl_candidate_disposition srpl_candidate_disposition_t;
typedef struct srpl_srp_client_queue_entry srpl_srp_client_queue_entry_t;
typedef struct srpl_srp_client_update_result srpl_srp_client_update_result_t;
typedef struct srpl_host_update srpl_host_update_t;
typedef struct srpl_advertise_finished_result srpl_advertise_finished_result_t;

typedef void (*address_change_callback_t)(void *NULLABLE context, addr_t *NULLABLE address, bool added, int err);
typedef void (*address_query_cancel_callback_t)(void *NULLABLE context);
typedef enum {
    address_query_next_address_gotten, // success
    address_query_next_address_empty,  // no addresses at all
    address_query_cycle_complete       // all addresses have been tried
} address_query_result_t;

#define ADDRESS_QUERY_MAX_ADDRESSES 20
struct address_query {
    int ref_count;
    dnssd_txn_t *NULLABLE aaaa_query, *NULLABLE a_query;
    addr_t addresses[ADDRESS_QUERY_MAX_ADDRESSES]; // If there are more than this many viable addresses, too bad?
    uint32_t address_interface[ADDRESS_QUERY_MAX_ADDRESSES];
    int num_addresses, cur_address;
    address_change_callback_t NULLABLE change_callback;
    address_query_cancel_callback_t NULLABLE cancel_callback;
    void *NULLABLE context;
    char *NONNULL hostname;
};

struct srpl_candidate {
    dns_label_t *NULLABLE name;
    uint32_t key_id;                 // key id from adv_host_t
    uint32_t update_offset;          // Offset in seconds before the time candidate message was sent that update was received.
    time_t update_time;              // the time of registration received from remote
    time_t local_time;               // our time of registration when we fetched the host
    message_t *NULLABLE message;     // The SRP message.
    adv_host_t *NULLABLE host;       // the host, when it's been fetched
};

struct srpl_advertise_finished_result {
    char *NULLABLE hostname;
    int rcode;
};

typedef enum {
    srpl_event_content_type_none = 0,
    srpl_event_content_type_address,
    srpl_event_content_type_server_id,
    srpl_event_content_type_candidate,
    srpl_event_content_type_rcode,
    srpl_event_content_type_candidate_disposition,
    srpl_event_content_type_host_update,
    srpl_event_content_type_client_result,
    srpl_event_content_type_advertise_finished_result,
} srpl_event_content_type_t;

typedef srpl_state_t (*srpl_action_t)(srpl_connection_t *NONNULL connection, srpl_event_t *NULLABLE event);

struct srpl_srp_client_update_result {
    adv_host_t *NONNULL host;
    int rcode;
};

struct srpl_host_update {
    message_t *NULLABLE message;
    uint64_t server_stable_id;
    uint32_t update_offset;
    time_t update_time;
    dns_name_t *NULLABLE hostname;
    int rcode;
};

struct srpl_event {
    char *NONNULL name;
    srpl_event_content_type_t content_type;
    union {
        addr_t address;
        uint64_t server_id;
        srpl_srp_client_update_result_t client_result;
        srpl_candidate_t *NULLABLE candidate;
        int rcode;
        srpl_candidate_disposition_t disposition;
        srpl_host_update_t host_update;
        srpl_advertise_finished_result_t advertise_finished;
    } content;
    message_t *NULLABLE message;
    srpl_event_type_t event_type;
    srpl_connection_t *NULLABLE srpl_connection; // if the event's been deferred, otherwise ALWAYS NULL.
};

struct srpl_srp_client_queue_entry {
    srpl_srp_client_queue_entry_t *NULLABLE next;
    adv_host_t *NONNULL host;
    bool sent;
};

struct srpl_connection {
    int ref_count;
    uint64_t remote_server_id;
    char *NONNULL name;
    char *NONNULL state_name;
    comm_t *NULLABLE connection;
    addr_t connected_address;
    srpl_candidate_t *NULLABLE candidate;
    dso_state_t *NULLABLE dso;
    srpl_instance_t *NULLABLE instance;
    wakeup_t *NULLABLE reconnect_wakeup;
    message_t *NULLABLE message;
    adv_host_t *NULLABLE *NULLABLE candidates;
    srpl_host_update_t stashed_host;
    srpl_srp_client_queue_entry_t *NULLABLE client_update_queue;
    int num_candidates;
    int current_candidate;
    int retry_delay; // How long to send when we send a retry_delay message
    srpl_state_t state, next_state;
    bool is_server;
    bool database_synchronized;
    bool candidates_not_generated; // If this is true, we haven't generated a candidates list yet.
};

struct srpl_instance {
    int ref_count;
    dnssd_txn_t *NULLABLE resolve_txn;
    srpl_instance_t *NULLABLE next;
    srpl_domain_t *NONNULL domain;
    char *NULLABLE name;
    char *NULLABLE instance_name;
    srpl_connection_t *NULLABLE incoming, *NULLABLE outgoing;
    address_query_t *NULLABLE address_query;
    wakeup_t *NULLABLE discontinue_timeout;
    wakeup_t *NULLABLE reconnect_timeout;
    uint64_t server_id;
    uint16_t outgoing_port;
    int num_copies;     // Tracks adds and deletes from the DNSServiceBrowse for this instance.
    bool discontinuing; // True if we are in the process of discontinuing this instance.
    bool is_me;
    bool have_server_id;
};

struct srpl_domain {
    int ref_count;
    srpl_domain_t *NULLABLE next;
    char *NONNULL name;
    srpl_instance_t *NULLABLE instances;
    dnssd_txn_t *NULLABLE query;
};

struct unclaimed_connection {
    int ref_count;
    unclaimed_connection_t *NULLABLE next;
    wakeup_t *NULLABLE wakeup_timeout;
    dso_state_t *NULLABLE dso;
    message_t *NULLABLE message;
    addr_t address;
    comm_t *NULLABLE connection;
};

#define SRP_THREAD_DOMAIN "thread.home.arpa."

#define DSO_TLV_HEADER_SIZE 4 // opcode (u16) + length (u16)
#define DSO_MESSAGE_MIN_LENGTH DNS_HEADER_SIZE + DSO_TLV_HEADER_SIZE + 1


#define SRPL_RETRY_DELAY_LENGTH        DSO_MESSAGE_MIN_LENGTH + sizeof(uint32_t)
#define SRPL_SESSION_MESSAGE_LENGTH    DSO_MESSAGE_MIN_LENGTH + sizeof(uint64_t) // DSO header + 8 byte session ID
#define SRPL_SEND_CANDIDATES_LENGTH    DSO_MESSAGE_MIN_LENGTH
#define SRPL_CANDIDATE_MESSAGE_LENGTH  (DSO_MESSAGE_MIN_LENGTH + \
                                        DNS_MAX_NAME_SIZE + DSO_TLV_HEADER_SIZE + \
                                        sizeof(uint32_t) + DSO_TLV_HEADER_SIZE + \
                                        sizeof(uint32_t) + DSO_TLV_HEADER_SIZE)
#define SRPL_CANDIDATE_RESPONSE_LENGTH DSO_MESSAGE_MIN_LENGTH + DSO_TLV_HEADER_SIZE
#define SRPL_HOST_MESSAGE_LENGTH  (DSO_MESSAGE_MIN_LENGTH + \
                                   DNS_MAX_NAME_SIZE + DSO_TLV_HEADER_SIZE + \
                                   sizeof(uint32_t) + DSO_TLV_HEADER_SIZE + \
                                   sizeof(uint32_t) + DSO_TLV_HEADER_SIZE)
#define SRPL_HOST_RESPONSE_LENGTH      DSO_MESSAGE_MIN_LENGTH

#define SRPL_UPDATE_JITTER_WINDOW 10

// Exported functions...
void srpl_startup(void);
void srpl_dso_server_message(comm_t *NONNULL connection, message_t *NULLABLE message, dso_state_t *NONNULL dso);
void srpl_advertise_finished_event_send(char *NONNULL host, int rcode);
void srpl_srp_client_update_finished_event_send(adv_host_t *NONNULL host, int rcode);
#define srpl_connection_release(connection) srpl_connection_release_(connection, __FILE__, __LINE__)
void srpl_connection_release_(srpl_connection_t *NONNULL srpl_connection, const char *NONNULL file, int line);
#define srpl_connection_retain(connection) srpl_connection_retain_(connection, __FILE__, __LINE__)
void srpl_connection_retain_(srpl_connection_t *NONNULL srpl_connection, const char *NONNULL file, int line);
#endif // __SRP_REPLICATION_H__

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
