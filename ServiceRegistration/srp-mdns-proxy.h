/* srp-mdns-proxy.h
 *
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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
 * This file contains structure definitions used by the SRP Advertising Proxy.
 */

#ifndef __SRP_MDNS_PROXY_H__
#define __SRP_MDNS_PROXY_H__ 1

#include "ioloop-common.h" // for service_connection_t

typedef struct adv_instance adv_instance_t;
typedef struct adv_address_registration adv_address_t;
typedef struct adv_host adv_host_t;
typedef struct adv_update adv_update_t;
typedef struct client_update client_update_t;
typedef struct adv_instance_vec adv_instance_vec_t;
typedef struct adv_host_vec adv_host_vec_t;
typedef struct adv_address_vec adv_address_vec_t;
typedef struct srpl_connection srpl_connection_t;

struct adv_instance {
    int ref_count;
    service_connection_t *NULLABLE conn; // The connection handler to mDNSResponder that shares DNSServiceRef with others.
    adv_host_t *NULLABLE host;     // Host to which this service instance belongs
    adv_update_t *NULLABLE update; // Ongoing update that currently owns this instance, if any.
    char *NONNULL instance_name;   // Single label instance name (future: service instance FQDN)
    char *NONNULL service_type;    // Two label service type (e.g., _ipps._tcp)
    int port;                      // Port on which service can be found.
    char *NULLABLE txt_data;       // Contents of txt record
    uint16_t txt_length;           // length of txt record contents
    message_t *NULLABLE message;   // Message that produces the current value of this instance
    ptrdiff_t recent_message;      // Most recent message (never dereference--this is for comparison only).
    int64_t lease_expiry;          // Time when lease expires, relative to ioloop_timenow().
    bool removed;                  // True if this instance is being kept around for replication.
    bool update_pending;           // True if we got a conflict while updating and are waiting to try again
};

// An address registration
struct adv_address_registration {
    int ref_count;
    // dnssd_txn_t *txn;         // The registration
    adv_host_t *NONNULL host;    // The host this record belongs to
    uint16_t rrtype;             // A or AAAA
    uint16_t rdlen;              // 4 or 16
    uint8_t rdata[16];           // Room for either IPv4 or IPv6 address
};

struct adv_host {
    int ref_count;
    wakeup_t *NONNULL retry_wakeup;        // Wakeup for retry when we run into a temporary failure
    wakeup_t *NONNULL lease_wakeup;        // Wakeup at least expiry time
    service_connection_t *NULLABLE conn;   // Connection handler to mDNSResponder that shares DNSServiceRef with others.
    adv_host_t *NULLABLE next;             // Hosts are maintained in a linked list.
    adv_update_t *NULLABLE updates;        // Updates to this host, if any
    client_update_t *NULLABLE clients;     // Updates that clients have sent for which replies have not yet been sent.
    char *NONNULL name;                    // Name of host (without domain)
    char *NULLABLE registered_name;        // The name that is registered, which may be different due to mDNS conflict
    message_t *NULLABLE message;           // Most recent successful SRP update for this host
    srpl_connection_t *NULLABLE srpl_connection; // SRP replication server that is currently updating this host.
    int name_serial;                       // The number we are using to disambiguate the name.
    int num_addresses;                     // Number of addresses registered (we only actually support one)
    adv_address_t *NULLABLE *NULLABLE addresses; // One or more addresses
    adv_instance_vec_t *NULLABLE instances; // Zero or more service instances.
    dns_rr_t key;                          // The key data represented as an RR; key->name is NULL.
    uint32_t key_id;                       // A possibly-unique id that is computed across the key for brevity in
                                           // debugging
    int retry_interval;                    // Interval to wait before attempting to re-register after the daemon has
                                           // died.
    time_t update_time;                    // Time when the update completed.
    uint64_t update_server_id;             // Server ID from server that sent the update
    uint64_t server_stable_id;             // Stable ID of server that got update from client (we're using server ULA).
    uint16_t key_rdlen;                    // Length of key
    uint8_t *NULLABLE key_rdata;           // Raw KEY rdata, suitable for DNSServiceRegisterRecord().
    uint32_t lease_interval;               // Interval for address lease
    uint32_t key_lease;                    // Interval for key lease
    uint32_t serial_number;                // Client's serial number
    bool have_serial_number;               // True if we have received or generate a serial number.
    int64_t lease_expiry;                  // Time when lease expires, relative to ioloop_timenow().
    bool removed;                          // True if this host has been removed (and is being kept for replication)

    // True if we have a pending late conflict resolution. If we get a conflict after the update for the
    // host registration has expired, and there happens to be another update in progress, then we want
    // to defer the host registration.
    bool update_pending;
};

struct adv_update {
    adv_host_t *NULLABLE host;              // Host being updated

    // Ordinarily NULL, but may be non-NULL if we lost the server during an update and had
    // to construct an update to re-add the host.
    adv_update_t *NULLABLE next;

    // Connection state, if applicable, of the client request that produced this update.
    client_update_t *NULLABLE client;
    int num_outstanding_updates;   // Total count updates that have been issued but not yet confirmed.

    // Addresses to apply to the host.  At present only one address is ever advertised, but we remember all the
    // addresses that were registered.
    int num_remove_addresses;
    adv_address_t *NULLABLE *NULLABLE remove_addresses;
    int num_add_addresses;
    adv_address_t *NULLABLE *NONNULL add_addresses;

    // If non-null, this update is changing the advertised address of the host to the referenced address.
    adv_address_t *NULLABLE selected_addr;

    // The set of instances from the update that already exist but have changed.
    // This array mirrors the array of instances configured on the host; entries to be updated
    // are non-NULL, entries that don't need updated are NULL.
    adv_instance_vec_t *NONNULL update_instances;

    // The set of instances that exist and need to be removed.
    adv_instance_vec_t *NONNULL remove_instances;

    // The set of instances that exist and were renewed
    adv_instance_vec_t *NONNULL renew_instances;

    // The set of instances that need to be added.
    adv_instance_vec_t *NONNULL add_instances;

    // Outstanding instance updates
    int num_instances_started;
    int num_instances_completed;

    // Lease intervals for host entry and key entry.
    uint32_t host_lease, key_lease;

    // If nonzero, this is an explicit expiry time for the lease, because the update is restoring
    // a host after a server restart, or else renaming a host after a late name conflict. In this
    // case, we do not want to extend the lease--just get the host registration right.
    int64_t lease_expiry;

    // True if we are registering the key to hold the hostname.
    bool registering_key;
};

struct adv_instance_vec {
    int ref_count;
    int num;
    adv_instance_t * NULLABLE *NONNULL vec;
};

struct adv_host_vec {
    int ref_count;
    int num;
    adv_host_t * NULLABLE *NONNULL vec;
};

struct adv_address_vec {
    int ref_count;
    int num;
    adv_address_t * NULLABLE *NONNULL vec;
};

struct client_update {
    client_update_t *NULLABLE next;
    comm_t *NONNULL connection;               // Connection on which in-process update was received.
    dns_message_t *NONNULL parsed_message;    // Message that triggered the update.
    message_t *NONNULL message;               // Message that triggered the update.

    dns_host_description_t *NONNULL host;     // Host data parsed from message
    service_instance_t *NULLABLE instances;   // Service instances parsed from message
    service_t *NONNULL services;              // Services parsed from message
    delete_t *NULLABLE removes;               // Removes parsed from message
    dns_name_t *NONNULL update_zone;          // Zone being updated
    uint32_t host_lease, key_lease;           // Lease intervals for host entry and key entry.
    uint32_t serial_number;                   // Serial number sent by client, if one was sent
    bool serial_sent;                         // True if serial number was sent.

};

// Exported variables.
extern bool srp_replication_enabled;
extern adv_host_t *NULLABLE hosts;

// Exported functions.
#define srp_adv_host_release(host) srp_adv_host_release_(host, __FILE__, __LINE__)
void srp_adv_host_release_(adv_host_t *NONNULL host, const char *NONNULL file, int line);
#define srp_adv_host_retain(host) srp_adv_host_retain_(host, __FILE__, __LINE__)
void srp_adv_host_retain_(adv_host_t *NONNULL host, const char *NONNULL file, int line);
#define srp_adv_host_copy(name) srp_adv_host_copy_(name, __FILE__, __LINE__)
adv_host_t *NULLABLE srp_adv_host_copy_(dns_name_t *NONNULL name, const char *NONNULL file, int line);
bool srp_adv_host_is_homekit_accessory(addr_t *NONNULL address);
int srp_current_valid_host_count(void);
int srp_hosts_to_array(adv_host_t *NONNULL *NULLABLE host_array, int max_hosts);
bool srp_adv_host_valid(adv_host_t *NONNULL host);
#endif // __SRP_MDNS_PROXY_H__

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
