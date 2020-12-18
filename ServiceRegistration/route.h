/* route.h
 *
 * Copyright (c) 2019-2020 Apple Computer, Inc. All rights reserved.
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
 */

#ifndef __SERVICE_REGISTRATION_ROUTE_H
#define __SERVICE_REGISTRATION_ROUTE_H
#if defined(USE_IPCONFIGURATION_SERVICE)
#include <SystemConfiguration/SystemConfiguration.h>
#include "IPConfigurationService.h"
#endif

#define MIN_DELAY_BETWEEN_RAS 4000
#define MSEC_PER_SEC (NSEC_PER_SEC / NSEC_PER_MSEC)
#define MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE 600 * MSEC_PER_SEC

// Fix this
#ifndef IPV6_ROUTER_MODE_EXCLUSIVE
#define IPV6_ROUTER_MODE_DISABLED	0
#define IPV6_ROUTER_MODE_EXCLUSIVE	1
#define IPV6_ROUTER_MODE_HYBRID		2
#endif


typedef struct interface interface_t;
typedef struct icmp_message icmp_message_t;
typedef struct network_link network_link_t;
struct interface {
    int ref_count;

    interface_t *NULLABLE next;
    char *NONNULL name;

    // Wakeup event for next beacon.
    wakeup_t *NULLABLE beacon_wakeup;

    // Wakeup event called after we're done sending solicits.  At this point we delete all routes more than 10 minutes
    // old; if none are left, then we assume there's no IPv6 service on the interface.
    wakeup_t *NULLABLE post_solicit_wakeup;

    // Wakeup event to trigger the next router solicit to be sent.
    wakeup_t *NULLABLE router_solicit_wakeup;

    // Wakeup event to deconfigure the on-link prefix after it is no longer valid.
    wakeup_t *NULLABLE deconfigure_wakeup;

    // Wakeup event to detect that vicarious router discovery is complete
    wakeup_t *NULLABLE vicarious_discovery_complete;

    // List of ICMP messages from different routers.
    icmp_message_t *NULLABLE routers;

    // The link to which this interface is connected.
    network_link_t *NULLABLE link;

#if defined(USE_IPCONFIGURATION_SERVICE)
    // The service used to configure this interface with an address in the on-link prefix
    IPConfigurationServiceRef NULLABLE ip_configuration_service;

    // SCDynamicStoreRef
    SCDynamicStoreRef NULLABLE ip_configuration_store;
#endif

    struct in6_addr link_local;  // Link-local address
    struct in6_addr ipv6_prefix; // This is the prefix we advertise, if advertise_ipv6_prefix is true.

    // Absolute time of last beacon, and of next beacon.
    uint64_t last_beacon, next_beacon;

    // Absolute deadline for deprecating the on-link prefix we've been announcing
    uint64_t deprecate_deadline;

    // Preferred lifetime for the on-link prefix
    uint32_t preferred_lifetime;

    // Valid lifetime for the on-link prefix
    uint32_t valid_lifetime;

    // When the interface becomes active, we send up to three solicits.
    int num_solicits_sent;

    // The interface index according to the operating systme.
    int index;

    // Number of IPv4 addresses configured on link.
    int num_ipv4_addresses;

    // Number of beacons sent. After the first three, the inter-beacon interval goes up.
    int num_beacons_sent;

    // The interface link layer address, if known.
    uint8_t link_layer[6];

    // True if the interface is not usable.
    bool inactive;

    // True if this interface can never be used for routing to the thread network (e.g., loopback, tunnels, etc.)
    bool ineligible;

    // True if we've determined that it's the thread interface.
    bool is_thread;

    // True if we should advertise an on-link prefix.
    bool advertise_ipv6_prefix;

    // True if we've gotten a link-layer address.
    bool have_link_layer_address;

    // True if the on-link prefix is configured on the interface.
    bool on_link_prefix_configured;

    // True if we've sent our first beacon since the interface came up.
    bool sent_first_beacon;

    // Indicates whether or not router discovery has completed for this interface.
    bool router_discovery_complete;

    // Indicates whether we're currently doing router discovery, so that we don't
    // restart it when we're already doing it.
    bool router_discovery_in_progress;

    // Indicates that we've received a router discovery message from some other host,
    // and are waiting 20 seconds to snoop for replies to that RD message that are
    // multicast.   If we hear no replies during that time, we trigger router discovery.
    bool vicarious_router_discovery_in_progress;

    // Indicates that we have received an interface removal event, it is useful when srp-mdns-proxy is changed to a new
    // network where the network signature are the same and they both have no IPv6 service (so no IPv6 prefix will be
    // removed), in such case there will be no change from srp-mdns-proxy's point of view. However, configd may still
    // flush the IPv6 routing since changing network would cause interface up/down. When the flushing happens,
    // srp-mdns-proxy should be able to reconfigure the IPv6 routing by reconfiguring IPv6 prefix. By setting
    // need_reconfigure_prefix only when interface address removal happens and check it during the routing evaluation
    // srp-mdns-proxy can reconfigure it after the routing evaluation finishes, like router discovery.
    bool need_reconfigure_prefix;
};

typedef enum icmp_option_type {
    icmp_option_source_link_layer_address =  1,
    icmp_option_target_link_layer_address =  2,
    icmp_option_prefix_information        =  3,
    icmp_option_redirected_header         =  4,
    icmp_option_mtu                       =  5,
    icmp_option_route_information         = 24,
} icmp_option_type_t;

typedef enum icmp_type {
    icmp_type_echo_request           = 128,
    icmp_type_echo_reply             = 129,
    icmp_type_router_solicitation    = 133,
    icmp_type_router_advertisement   = 134,
    icmp_type_neighbor_solicitation  = 135,
    icmp_type_neighbor_advertisement = 136,
    icmp_type_redirect               = 137,
} icmp_type_t;

typedef struct link_layer_address {
    uint16_t length;
    uint8_t address[32];
} link_layer_address_t;

typedef struct prefix_information {
    struct in6_addr prefix;
    uint8_t length;
    uint8_t flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
} prefix_information_t;

typedef struct route_information {
    struct in6_addr prefix;
    uint8_t length;
    uint8_t flags;
    uint32_t route_lifetime;
} route_information_t;

typedef struct icmp_option {
    icmp_option_type_t type;
    union {
        link_layer_address_t link_layer_address;
        prefix_information_t prefix_information;
        route_information_t route_information;
    } option;
} icmp_option_t;

struct icmp_message {
    icmp_message_t *NULLABLE next;
    interface_t *NULLABLE interface;
    icmp_option_t *NULLABLE options;
    bool new_router;                // If this router information is a newly recevied one.
    bool received_time_already_adjusted;    // if the received time of the message is already adjusted by
                                                    // vicarious mode
    struct in6_addr source;
    struct in6_addr destination;

    uint64_t received_time;

    uint32_t reachable_time;
    uint32_t retransmission_timer;
    uint8_t cur_hop_limit;          // Current hop limit for Router Advertisement messages.
    uint8_t flags;
    uint8_t type;
    uint8_t code;
    uint16_t checksum;              // We hope the kernel figures this out for us.
    uint16_t router_lifetime;

    int num_options;
    int hop_limit;                  // Hop limit provided by the kernel, must be 255.
};

void ula_generate(void);
bool start_route_listener(void);
bool start_icmp_listener(void);
void icmp_leave_join(int sock, int ifindex, bool join);

#define interface_create(name, iface) interface_create_(name, iface, __FILE__, __LINE__)
interface_t *NULLABLE interface_create_(const char *NONNULL name, int ifindex,
                                                      const char *NONNULL file, int line);
#define interface_retain(interface) interface_retain_(interface, __FILE__, __LINE__)
void interface_retain_(interface_t *NONNULL interface, const char *NONNULL file, int line);
#define interface_release(interface) interface_release_(interface, __FILE__, __LINE__)
void interface_release_(interface_t *NONNULL interface, const char *NONNULL file, int line);
bool interface_monitor_start(void);
void thread_network_startup(void);
void thread_network_shutdown(void);
void partition_stop_advertising_pref_id(void);
void partition_start_srp_listener(void);
#endif // __SERVICE_REGISTRATION_ROUTE_H

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
