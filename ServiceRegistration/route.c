/* route.c
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
 *
 * This file contains the implementation for Thread Border Router routing.
 * The state of the Thread network is tracked, the state of the infrastructure
 * network is tracked, and policy decisions are made as to what to advertise
 * on both networks.
 */

#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <net/if_media.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <stdlib.h>

#ifdef IOLOOP_MACOS
#include <xpc/xpc.h>

#include <TargetConditionals.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <SystemConfiguration/SCPrivate.h>
#include <SystemConfiguration/SCNetworkConfigurationPrivate.h>
#include <SystemConfiguration/SCNetworkSignature.h>
#include <network_information.h>

#include <CoreUtils/CoreUtils.h>
#endif // IOLOOP_MACOS

#ifndef OPEN_SOURCE
// For now, we need backwards compatibility with old service type, only on the server.
#  define THREAD_SERVICE_SEND_BOTH 1
#endif

#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "route.h"
#if TARGET_OS_TV
#include "cti-services.h"
#endif
#include "srp-gw.h"
#include "srp-proxy.h"

typedef union {
    uint16_t len;
    struct rt_msghdr route;
    struct if_msghdr interface;
    struct if_msghdr2 if2;
    struct ifa_msghdr address;
    uint8_t bytes[512];
} route_message_t;

typedef struct icmp_listener {
    io_t *io_state;
    int sock;
    uint32_t unsolicited_interval;
} icmp_listener_t;

typedef struct thread_prefix thread_prefix_t;
struct thread_prefix {
    int ref_count;
    thread_prefix_t *next;
    struct in6_addr prefix;
    int prefix_len;
    bool user, ncp, stable;
    bool previous_user, previous_ncp, previous_stable;
};
struct thread_prefix *thread_prefixes, *published_thread_prefix, *adopted_thread_prefix;

typedef struct thread_pref_id thread_pref_id_t;
struct thread_pref_id {
    int ref_count;
    thread_pref_id_t *next;
    uint8_t partition_id[4]; // Partition id on which this prefix is claimed
    uint8_t prefix[5];       // 40-bit ULA prefix identifier (no need to keep the whole prefix)
    bool user, ncp, stable;
    bool previous_user, previous_ncp, previous_stable;
};
struct thread_pref_id *thread_pref_ids;

typedef struct thread_service thread_service_t;
struct thread_service {
    int ref_count;
    thread_service_t *next;
    uint8_t address[16]; // IPv6 address on which service is offered
    uint8_t port[2];     // Port (network byte order)
    bool user, ncp, stable;
    bool previous_user, previous_ncp, previous_stable;
};
struct thread_service *thread_services;

struct network_link {
    network_link_t *next;
    int ref_count;
    uint64_t last_seen;
    uint8_t *NULLABLE signature;
    long signature_length;
    int32_t prefix_number;
    interface_t *primary; // This is the interface on which this prefix is being advertised.
};

interface_t *interfaces;
network_link_t *network_links; // Our list of network links
CFMutableArrayRef network_link_array; // The same list as a CFArray, so that we can write it to preferences.
icmp_listener_t icmp_listener;
bool have_thread_prefix = false;
struct in6_addr my_thread_prefix;
struct in6_addr srp_listener_ip_address;
char thread_address_string[INET6_ADDRSTRLEN];
uint16_t srp_service_listen_port;
uint8_t thread_partition_id[4];
srp_proxy_listener_state_t *srp_listener;
struct in6_addr ula_prefix;
int num_thread_interfaces; // Should be zero or one.
int ula_serial = 1;
bool advertise_default_route_on_thread;
subproc_t *thread_interface_enumerator_process;
subproc_t *thread_prefix_adder_process;
subproc_t *link_route_adder_process;
subproc_t *thread_rti_setter_process;
subproc_t *thread_forwarding_setter_process;
subproc_t *thread_proxy_service_adder_process;
subproc_t *tcpdump_logger_process;
char *thread_interface_name;
char *home_interface_name;
bool thread_proxy_service_setup_done;
bool interface_state_stable = false;
bool have_non_thread_interface = false;

#ifndef RA_TESTER
cti_network_state_t current_thread_state = kCTI_NCPState_Uninitialized;
cti_network_node_type_t current_thread_role = kCTI_NetworkNodeType_Unknown;
cti_connection_t thread_role_context;
cti_connection_t thread_state_context;
cti_connection_t thread_service_context;
cti_connection_t thread_prefix_context;
cti_connection_t thread_partition_id_context;
#endif

nw_path_evaluator_t path_evaluator;


#define CONFIGURE_STATIC_INTERFACE_ADDRESSES 1
#define USE_IPCONFIGURATION_SERVICE 1

static void refresh_interface_list(void);
static void router_advertisement_send(interface_t *NONNULL interface);
static void icmp_send(uint8_t *NONNULL message, size_t length,
                      interface_t *NONNULL interface, const struct in6_addr *NONNULL destination);
static void interface_beacon_schedule(interface_t *NONNULL interface, unsigned when);
static void interface_prefix_configure(struct in6_addr prefix, interface_t *NONNULL interface);
static void interface_prefix_evaluate(interface_t *interface);
static void start_router_solicit(interface_t *interface);
#ifndef RA_TESTER
static void routing_policy_evaluate_all_interfaces(bool assume_changed);
#endif
static void routing_policy_evaluate(interface_t *interface, bool assume_changed);
static void post_solicit_policy_evaluate(void *context);

#ifndef RA_TESTER
static void partition_state_reset(void);
static void partition_unpublish_prefix(thread_prefix_t *NONNULL prefix);
static void partition_unpublish_adopted_prefix(bool wait);
static void partition_publish_my_prefix(void);
static void partition_adopt_prefix(thread_prefix_t *NONNULL prefix);
static bool partition_prefix_is_present(struct in6_addr *prefix_addr, int length);
static bool partition_pref_id_is_present(struct in6_addr *NONNULL prefix_addr);
static thread_prefix_t *NULLABLE partition_find_lowest_valid_prefix(void);
static thread_pref_id_t *NULLABLE partition_find_lowest_valid_pref_id(void);
static void partition_pref_id_timeout(void *__unused NULLABLE context);
static void partition_post_election_wakeup(void *__unused NULLABLE context);
static void partition_post_partition_timeout(void *__unused NULLABLE context);
static void partition_discontinue_srp_service(void);
static void partition_utun0_address_changed(const struct in6_addr *NONNULL addr, enum interface_address_change change);
static bool partition_wait_for_prefix_settling(wakeup_callback_t NONNULL callback, uint64_t now);
static void partition_got_tunnel_name(void);
static void partition_prefix_set_changed(void);
static void partition_pref_id_set_changed(void);
static void partition_id_changed(void);
static void partition_remove_service_done(void *__unused NULLABLE context, cti_status_t status);
static void partition_stop_advertising_service(void);
static void partition_proxy_listener_ready(void *__unused NULLABLE context, uint16_t port);
static void partition_maybe_advertise_service(void);
static void partition_service_set_changed(void);
static void partition_maybe_enable_services(void);
static void partition_disable_service(void);
static void partition_schedule_service_add_wakeup(void);

static uint64_t partition_last_prefix_set_change;
static uint64_t partition_last_pref_id_set_change;
static uint64_t partition_last_partition_id_change;
static uint64_t partition_last_role_change;
static uint64_t partition_last_state_change;
static uint64_t partition_settle_start;
static uint64_t partition_service_last_add_time;
static bool partition_id_is_known;
static bool partition_have_prefix_list;
static bool partition_have_pref_id_list;
static bool partition_tunnel_name_is_known;
static bool partition_can_advertise_service;
static bool partition_service_blocked;
static bool partition_can_provide_routing;
static bool partition_may_offer_service = false;
static bool partition_settle_satisfied = true;
static wakeup_t *partition_settle_wakeup;
static wakeup_t *partition_post_partition_wakeup;
static wakeup_t *partition_pref_id_wait_wakeup;
static wakeup_t *partition_service_add_pending_wakeup;
#endif

static void
interface_finalize(void *context)
{
    interface_t *interface = context;
    if (interface->name != NULL) {
        free(interface->name);
    }
    if (interface->beacon_wakeup != NULL) {
        ioloop_wakeup_release(interface->beacon_wakeup);
    }
    if (interface->post_solicit_wakeup != NULL) {
        ioloop_wakeup_release(interface->post_solicit_wakeup);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_wakeup_release(interface->router_solicit_wakeup);
    }
    if (interface->deconfigure_wakeup != NULL) {
        ioloop_wakeup_release(interface->deconfigure_wakeup);
    }
    free(interface);
}

void
interface_retain_(interface_t *interface, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(interface);
}

void
interface_release_(interface_t *interface, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(interface, interface_finalize);
}

interface_t *
interface_create_(const char *name, int ifindex, const char *file, int line)
{
    interface_t *ret;

    if (name == NULL) {
        ERROR("interface_create: missing name");
        return NULL;
    }

    ret = calloc(1, sizeof(*ret));
    if (ret) {
        RETAIN(ret);
        ret->name = strdup(name);
        if (ret->name == NULL) {
            ERROR("interface_create: no memory for name");
            RELEASE(ret, interface_finalize);
            return NULL;
        }
        ret->deconfigure_wakeup = ioloop_wakeup_create();
        if (ret->deconfigure_wakeup == NULL) {
            ERROR("No memory for interface deconfigure wakeup on " PUB_S_SRP ".", ret->name);
            RELEASE(ret, interface_finalize);
            return NULL;
        }

        ret->index = ifindex;
        ret->inactive = true;
        // Interfaces are ineligible for routing until explicitly identified as eligible.
        ret->ineligible = true;
    }
    return ret;
}

#ifndef RA_TESTER
static void
thread_prefix_finalize(thread_prefix_t *prefix)
{
    free(prefix);
}

#define thread_prefix_create(prefix, prefix_length) thread_prefix_create_(prefix, prefix_length, __FILE__, __LINE__)
static thread_prefix_t *
thread_prefix_create_(struct in6_addr *address, int prefix_length, const char *file, int line)
{
    thread_prefix_t *prefix;

    prefix = calloc(1, (sizeof *prefix));
    if (prefix != NULL) {
        memcpy(&prefix->prefix, address, 16);
        prefix->prefix_len = prefix_length;
        RETAIN(prefix);
    }
    return prefix;
}

static void
thread_service_finalize(thread_service_t *service)
{
    free(service);
}

#define thread_service_create(address, port) thread_service_create_(address, port, __FILE__, __LINE__)
static thread_service_t *
thread_service_create_(uint8_t *address, uint8_t *port, const char *file, int line)
{
    thread_service_t *service;

    service = calloc(1, sizeof(*service));
    if (service != NULL) {
        memcpy(&service->address, address, 16);
        memcpy(&service->port, port, 2);
        RETAIN(service);
    }
    return service;
}

static void
thread_pref_id_finalize(thread_pref_id_t *pref_id)
{
    free(pref_id);
}

#define thread_pref_id_create(partition_id, prefix) thread_pref_id_create_(partition_id, prefix, __FILE__, __LINE__)
static thread_pref_id_t *
thread_pref_id_create_(uint8_t *partition_id, uint8_t *prefix, const char *file, int line)
{
    thread_pref_id_t *pref_id;

    pref_id = calloc(1, sizeof(*pref_id));
    if (pref_id != NULL) {
        memcpy(&pref_id->partition_id, partition_id, 4);
        memcpy(&pref_id->prefix, prefix, 5);
        RETAIN(pref_id);
    }
    return pref_id;
}
#endif // RA_TESTER

static void
icmp_message_free(icmp_message_t *message)
{
    if (message->options != NULL) {
        free(message->options);
    }
    free(message);
}

static void
icmp_message_dump(icmp_message_t *message,
                  const struct in6_addr * const source_address, const struct in6_addr * const destination_address)
{
    link_layer_address_t *lladdr;
    prefix_information_t *prefix_info;
    route_information_t *route_info;
    int i;
    char retransmission_timer_buf[11]; // Maximum size of a uint32_t printed as decimal.
    char *retransmission_timer = "infinite";

    if (message->retransmission_timer != ND6_INFINITE_LIFETIME) {
        snprintf(retransmission_timer_buf, sizeof(retransmission_timer_buf), "%" PRIu32, message->retransmission_timer);
        retransmission_timer = retransmission_timer_buf;
    }

    SEGMENTED_IPv6_ADDR_GEN_SRP(source_address->s6_addr, src_addr_buf);
    SEGMENTED_IPv6_ADDR_GEN_SRP(destination_address->s6_addr, dst_addr_buf);
    if (message->type == icmp_type_router_advertisement) {
        INFO("router advertisement from " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP
             " hop_limit %d on " PUB_S_SRP ": checksum = %x "
             "cur_hop_limit = %d flags = %x router_lifetime = %d reachable_time = %" PRIu32
             " retransmission_timer = " PUB_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(source_address->s6_addr, src_addr_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(destination_address->s6_addr, dst_addr_buf),
             message->hop_limit, message->interface->name, message->checksum, message->cur_hop_limit, message->flags,
             message->router_lifetime, message->reachable_time, retransmission_timer);
    } else if (message->type == icmp_type_router_solicitation) {
        INFO("router solicitation from " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP
             " hop_limit %d on " PUB_S_SRP ": code = %d checksum = %x",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(source_address->s6_addr, src_addr_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(destination_address->s6_addr, dst_addr_buf),
             message->hop_limit, message->interface->name,
             message->code, message->checksum);
    } else {
        INFO("icmp message from " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP " hop_limit %d on "
             PUB_S_SRP ": type = %d code = %d checksum = %x",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(source_address->s6_addr, src_addr_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(destination_address->s6_addr, dst_addr_buf),
             message->hop_limit, message->interface->name, message->type,
             message->code, message->checksum);
    }

    for (i = 0; i < message->num_options; i++) {
        icmp_option_t *option = &message->options[i];
        switch(option->type) {
        case icmp_option_source_link_layer_address:
            lladdr = &option->option.link_layer_address;
            INFO("  source link layer address " PRI_MAC_ADDR_SRP, MAC_ADDR_PARAM_SRP(lladdr->address));
            break;
        case icmp_option_target_link_layer_address:
            lladdr = &option->option.link_layer_address;
            INFO("  destination link layer address " PRI_MAC_ADDR_SRP, MAC_ADDR_PARAM_SRP(lladdr->address));
            break;
        case icmp_option_prefix_information:
            prefix_info = &option->option.prefix_information;
            SEGMENTED_IPv6_ADDR_GEN_SRP(prefix_info->prefix.s6_addr, prefix_buf);
            INFO("  prefix info: " PRI_SEGMENTED_IPv6_ADDR_SRP "/%d %x %" PRIu32 " %" PRIu32,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix_info->prefix.s6_addr, prefix_buf), prefix_info->length,
                 prefix_info->flags, prefix_info->valid_lifetime, prefix_info->preferred_lifetime);
            break;
        case icmp_option_route_information:
            route_info = &option->option.route_information;
                SEGMENTED_IPv6_ADDR_GEN_SRP(route_info->prefix.s6_addr, router_prefix_buf);
            INFO("  route info: " PRI_SEGMENTED_IPv6_ADDR_SRP "/%d %x %d",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(route_info->prefix.s6_addr, router_prefix_buf), route_info->length,
                 route_info->flags, route_info->route_lifetime);
            break;
        default:
            INFO("  option type %d", option->type);
            break;
        }
    }
}

static bool
icmp_message_parse_options(icmp_message_t *message, uint8_t *icmp_buf, unsigned length, unsigned *offset)
{
    uint8_t option_type, option_length_8;
    unsigned option_length;
    unsigned scan_offset = *offset;
    icmp_option_t *option;
    uint32_t reserved32;
    prefix_information_t *prefix_information;
    route_information_t *route_information;
    int prefix_bytes;

    // Count the options and validate the lengths
    while (scan_offset < length) {
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_type)) {
            return false;
        }
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_length_8)) {
            return false;
        }
        if (scan_offset + option_length_8 * 8 - 2 > length) {
            ERROR("icmp_option_parse: option type %d length %d is longer than remaining available space %u",
                  option_type, option_length_8 * 8, length - scan_offset + 2);
            return false;
        }
        scan_offset += option_length_8 * 8 - 2;
        message->num_options++;
    }
    message->options = calloc(message->num_options, sizeof(*message->options));
    if (message->options == NULL) {
        ERROR("No memory for icmp options.");
        return false;
    }
    option = message->options;
    while (*offset < length) {
        scan_offset = *offset;
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_type)) {
            return false;
        }
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_length_8)) {
            return false;
        }
        // We already validated the length in the previous pass.
        option->type = option_type;
        option_length = option_length_8 * 8;

        switch(option_type) {
        case icmp_option_source_link_layer_address:
        case icmp_option_target_link_layer_address:
            // At this juncture we are assuming that everything we care about looks like an
            // ethernet interface.  So for this case, length should be 8.
            if (option_length != 8) {
                INFO("Ignoring unexpectedly long link layer address: %d", option_length);
                // Don't store the option.
                message->num_options--;
                *offset += option_length;
                continue;
            }
            option->option.link_layer_address.length = 6;
            memcpy(option->option.link_layer_address.address, &icmp_buf[scan_offset], 6);
            break;
        case icmp_option_prefix_information:
            prefix_information = &option->option.prefix_information;
            // Only a length of 32 is valid.  This is an invalid ICMP packet, not just misunderunderstood
            if (option_length != 32) {
                return false;
            }
            // prefix length 8
            if (!dns_u8_parse(icmp_buf, length, &scan_offset, &prefix_information->length)) {
                return false;
            }
            // flags 8a
            if (!dns_u8_parse(icmp_buf, length, &scan_offset, &prefix_information->flags)) {
                return false;
            }
            // valid lifetime 32
            if (!dns_u32_parse(icmp_buf, length, &scan_offset,
                               &prefix_information->valid_lifetime)) {
                return false;
            }
            // preferred lifetime 32
            if (!dns_u32_parse(icmp_buf, length, &scan_offset,
                               &prefix_information->preferred_lifetime)) {
                return false;
            }
            // reserved2 32
            if (!dns_u32_parse(icmp_buf, length, &scan_offset, &reserved32)) {
                return false;
            }
            // prefix 128
            memcpy(&prefix_information->prefix, &icmp_buf[scan_offset], 16);
            break;
        case icmp_option_route_information:
            route_information = &option->option.route_information;

            // route length 8
            if (!dns_u8_parse(icmp_buf, length, &scan_offset, &route_information->length)) {
                return false;
            }
            switch(option_length) {
            case 8:
                prefix_bytes = 0;
                break;
            case 16:
                prefix_bytes = 8;
                break;
            case 24:
                prefix_bytes = 16;
                break;
            default:
                ERROR("invalid route information option length %d for route length %d",
                      option_length, route_information->length);
                return false;
            }
            // flags 8
            if (!dns_u8_parse(icmp_buf, length, &scan_offset, &route_information->flags)) {
                return false;
            }
            // route lifetime 32
            if (!dns_u32_parse(icmp_buf, length, &scan_offset, &route_information->route_lifetime)) {
                return false;
            }
            // route (64, 96 or 128)
            if (prefix_bytes > 0) {
                memcpy(&route_information->prefix, &icmp_buf[scan_offset], prefix_bytes);
            }
            memset(&((uint8_t *)&route_information->prefix)[prefix_bytes], 0, 16 - prefix_bytes);
            break;
        default:
        case icmp_option_mtu:
        case icmp_option_redirected_header:
            // don't care
            break;
        }
        *offset += option_length;
        option++;
    }
    return true;
}

static void
set_router_mode(interface_t *interface, int mode)
{
    struct in6_ifreq router_interface;
    int sock, ret;

    sock = socket(PF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        ERROR("socket(PF_INET6, SOCK_DGRAM, 0) failed " PUB_S_SRP ": " PUB_S_SRP, interface->name, strerror(errno));
        return;
    }

    memset(&router_interface, 0, sizeof (router_interface));
    strlcpy(router_interface.ifr_name, interface->name, sizeof(interface->name));
    router_interface.ifr_ifru.ifru_intval = mode;
    // Fix this
#ifndef SIOCSETROUTERMODE_IN6
#define SIOCSETROUTERMODE_IN6   _IOWR('i', 136, struct in6_ifreq)
#endif /* SIOCSETROUTERMODE_IN6 */
    ret = ioctl(sock, SIOCSETROUTERMODE_IN6, &router_interface);
    if (ret < 0) {
        ERROR("Unable to enable router mode on " PUB_S_SRP ": " PUB_S_SRP, interface->name, strerror(errno));
    } else {
        INFO("enabled router mode for " PUB_S_SRP ": " PUB_S_SRP ".", interface->name,
             (mode == IPV6_ROUTER_MODE_DISABLED
                ? "disabled"
                : (mode == IPV6_ROUTER_MODE_EXCLUSIVE ? "exclusive" : "hybrid")));
    }
    close(sock);
}


static void
interface_wakeup_finalize(void *context)
{
    interface_t *interface = context;
    interface->beacon_wakeup = NULL;
}

static void
interface_deconfigure_finalize(void *context)
{
    interface_t *interface = context;
    interface->deconfigure_wakeup = NULL;
}

static void
interface_prefix_deconfigure(void *context)
{
    interface_t *interface = context;
    INFO("interface_prefix_deconfigure - ifname: " PUB_S_SRP ", prefix: "
         ", preferred time: %" PRIu32 ", valid time: %" PRIu32, interface->name, interface->preferred_lifetime,
         interface->valid_lifetime);

    // If our on-link prefix is still deprecated (preferred_lifetime == 0 means that the prefix is in deprecated state),
    // deconfigure it from the interface.
    if (interface->preferred_lifetime == 0 && interface->ip_configuration_service != NULL) {
        CFRelease(interface->ip_configuration_service);
        interface->ip_configuration_service = NULL;
        interface->valid_lifetime = 0;
        interface->on_link_prefix_configured = false;
        interface->advertise_ipv6_prefix = false;
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        INFO("interface_prefix_deconfigure: deconfigure the prefix immediately - prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
            SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
    }
    interface->deprecate_deadline = 0;
}

static void
interface_beacon(void *context)
{
    interface_t *interface = context;
    uint64_t now = ioloop_timenow();

    INFO("interface_beacon:" PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP,
         interface->deprecate_deadline > now ? " ddl>now" : "",
#ifdef RA_TESTER
         "",
#else
         partition_can_provide_routing ? " canpr" : " !canpr",
#endif
         interface->advertise_ipv6_prefix ? " pio" : " !pio",
         interface->sent_first_beacon ? "" : " first beacon");

    if (interface->deprecate_deadline > now) {
        // The remaining valid lifetime is the time left until the deadline.
        interface->valid_lifetime = (uint32_t)((interface->deprecate_deadline - now) / 1000);
        if (interface->valid_lifetime < icmp_listener.unsolicited_interval) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
            INFO("interface_beacon: prefix valid life time is less than the unsolicited interval, stop advertising it "
                 "and prepare to deconfigure the prefix - ifname: " PUB_S_SRP "prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP
                 ", preferred time: %" PRIu32 ", valid time: %" PRIu32 ", unsolicited interval: %" PRIu32,
                 interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf),
                 interface->preferred_lifetime, interface->valid_lifetime, icmp_listener.unsolicited_interval);
            interface->advertise_ipv6_prefix = false;
            ioloop_add_wake_event(interface->deconfigure_wakeup,
                                  interface, interface_prefix_deconfigure,
                                  interface_deconfigure_finalize, interface->valid_lifetime * 1000);
        }
    }

#ifndef RA_TESTER
    // If we have been beaconing, and router mode has been disabled, and we don't have
    // an on-link prefix to advertise, discontinue beaconing.
    if (partition_can_provide_routing || interface->advertise_ipv6_prefix) {
#endif

    // Send an RA.
        router_advertisement_send(interface);
        interface->sent_first_beacon = true;
        interface->last_beacon = ioloop_timenow();;
#ifndef RA_TESTER
    }
#endif
    if (interface->num_beacons_sent < 3) {
        // Schedule a beacon for between 8 and 16 seconds in the future (<MAX_INITIAL_RTR_ADVERT_INTERVAL)
        interface_beacon_schedule(interface, 8000 + srp_random16() % 8000);
    } else {
        interface_beacon_schedule(interface, icmp_listener.unsolicited_interval);
    }
    interface->num_beacons_sent++;
}

static void
interface_beacon_schedule(interface_t *interface, unsigned when)
{
    uint64_t now = ioloop_timenow();
    unsigned interval;

    // If we haven't sent our first beacon, now's a good time to configure router mode on the interface.
    if (!interface->sent_first_beacon) {
        int	mode;

#ifdef RA_TESTER
        mode = (strcmp(interface->name, thread_interface_name) == 0) ? IPV6_ROUTER_MODE_EXCLUSIVE
                                                                        : IPV6_ROUTER_MODE_HYBRID;
#else
        mode = IPV6_ROUTER_MODE_HYBRID;
#endif
        set_router_mode(interface, mode);
    }

    // Make sure we haven't send an RA too recently.
    if (when < MIN_DELAY_BETWEEN_RAS && now - interface->last_beacon < MIN_DELAY_BETWEEN_RAS) {
        when = MIN_DELAY_BETWEEN_RAS;
    }
    // Add up to a second of jitter.
    when += srp_random16() % 1024;
    interface->next_beacon = now + when;
    if (interface->beacon_wakeup == NULL) {
        interface->beacon_wakeup = ioloop_wakeup_create();
        if (interface->beacon_wakeup == NULL) {
            ERROR("Unable to allocate beacon wakeup for " PUB_S_SRP, interface->name);
            return;
        }
    } else {
        // We can reschedule a beacon for sooner if we get a router solicit; in this case, we
        // need to cancel the existing beacon wakeup, and if there is none scheduled, this will
        // be a no-op.
        ioloop_cancel_wake_event(interface->beacon_wakeup);
    }
    if (interface->next_beacon - now > UINT_MAX) {
        interval = UINT_MAX;
    } else {
        interval = (unsigned)(interface->next_beacon - now);
    }
    INFO("Scheduling " PUB_S_SRP "beacon on " PUB_S_SRP " for %u milliseconds in the future",
         interface->sent_first_beacon ? "first " : "", interface->name, interval);
    ioloop_add_wake_event(interface->beacon_wakeup, interface, interface_beacon, interface_wakeup_finalize, interval);
}

static void
router_discovery_start(interface_t *interface)
{
    INFO("Starting router discovery on " PUB_S_SRP, interface->name);

    // Immediately when an interface shows up, start doing router solicits.
    start_router_solicit(interface);

    if (interface->post_solicit_wakeup == NULL) {
        interface->post_solicit_wakeup = ioloop_wakeup_create();
        if (interface->post_solicit_wakeup == NULL) {
            ERROR("No memory for post-solicit RA wakeup on " PUB_S_SRP ".", interface->name);
        }
    } else {
        ioloop_cancel_wake_event(interface->post_solicit_wakeup);
    }

    // In 20 seconds, check the results of router discovery and update policy as needed.
    if (interface->post_solicit_wakeup) {
        ioloop_add_wake_event(interface->post_solicit_wakeup, interface, post_solicit_policy_evaluate,
                              NULL, 20 * 1000);
    }
    interface->router_discovery_in_progress = true;
}

static void
flush_stale_routers(interface_t *interface, uint64_t now)
{
    icmp_message_t *router, **p_router;

    // Flush stale routers.
    for (p_router = &interface->routers; *p_router != NULL; ) {
        router = *p_router;
        if (now - router->received_time > MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE)  {
            *p_router = router->next;
            SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_addr_buf);
            INFO("flush_stale_routers: flushing stale router - ifname: " PUB_S_SRP
                 ", router src: " PRI_SEGMENTED_IPv6_ADDR_SRP, interface->name,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_addr_buf));
            icmp_message_free(router);
        } else {
            p_router = &(*p_router)->next;
        }
    }
}

static void
router_discovery_stop(interface_t *interface, uint64_t now)
{
    if (!interface->router_discovery_complete) {
        INFO("router_discovery_stop: stopping router discovery on " PUB_S_SRP, interface->name);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->router_solicit_wakeup);
    }
    if (interface->post_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->post_solicit_wakeup);
    }
    if (interface->vicarious_discovery_complete != NULL) {
        ioloop_cancel_wake_event(interface->vicarious_discovery_complete);
        INFO("router_discovery_stop: stopping vicarious router discovery on " PUB_S_SRP, interface->name);
    }
    interface->router_discovery_complete = true;
    interface->router_discovery_in_progress = false;
    interface->vicarious_router_discovery_in_progress = false;
    flush_stale_routers(interface, now);

    // See if we need a new prefix on the interface.
    interface_prefix_evaluate(interface);
}

static void
adjust_router_received_time(interface_t *const interface, const uint64_t now, const int64_t time_adjusted)
{
    icmp_message_t *router;

    for (router = interface->routers; router != NULL; router = router->next) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_addr_buf);
        // Only adjust the received time once.
        if (router->received_time_already_adjusted) {
            DEBUG("adjust_router_received_time: received time already adjusted - remaining time: %llu, "
                  "router src: " PRI_SEGMENTED_IPv6_ADDR_SRP, (now - router->received_time) / MSEC_PER_SEC,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_addr_buf));
            continue;
        }
        require_action_quiet(
            (time_adjusted > 0 && (UINT64_MAX - now) > (uint64_t)time_adjusted) ||
            (time_adjusted < 0 && now > ((uint64_t)-time_adjusted)), exit,
            ERROR("adjust_router_received_time: invalid adjusted values is causing overflow - "
                  "now: %" PRIu64 ", time_adjusted: %" PRId64, now, time_adjusted));
        router->received_time = now + time_adjusted;
        router->received_time_already_adjusted = true; // Only adjust the icmp message received time once.
        DEBUG("adjust_router_received_time: router received time is adjusted - router src: " PRI_SEGMENTED_IPv6_ADDR_SRP
              ", adjusted value: %" PRId64,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_addr_buf), time_adjusted);
    }

exit:
    return;
}

static void
make_all_routers_nearly_stale(interface_t *interface, uint64_t now)
{
    // Make every router go stale in 19.999 seconds.   This means that if we don't get a response
    // to our solicit in 20 seconds, then when the timeout callback is called, there will be no
    // routers on the interface that aren't stale, which will trigger router discovery.
    adjust_router_received_time(interface, now, 19999 - 600 * MSEC_PER_SEC);
}

static void
vicarious_discovery_callback(void *context)
{
    interface_t *interface = context;
    INFO("Vicarious router discovery finished on " PUB_S_SRP ".", interface->name);
    interface->vicarious_router_discovery_in_progress = false;
    // At this point, policy evaluate will show all the routes that were present before vicarious
    // discovery as stale, so policy_evaluate will start router discovery if we didn't get any
    // RAs containing on-link prefixes.
    routing_policy_evaluate(interface, false);
}

#ifndef RA_TESTER
static void
routing_policy_evaluate_all_interfaces(bool assume_changed)
{
    interface_t *interface;

    for (interface = interfaces; interface; interface = interface->next) {
        routing_policy_evaluate(interface, assume_changed);
    }
}
#endif

static void
routing_policy_evaluate(interface_t *interface, bool assume_changed)
{
    icmp_message_t *router;
    bool new_prefix = false;    // new prefix means that srp-mdns-proxy received a new prefix from the wire, which it
                                // did not know before.
    bool on_link_prefix_present = false;
    bool something_changed = assume_changed;
    uint64_t now = ioloop_timenow();
    bool stale_routers_exist = false;

    // No action on interfaces that aren't eligible for routing or that isn't currently active.
    if (interface->ineligible || interface->inactive) {
        INFO("not evaluating policy on " PUB_S_SRP " because it's " PUB_S_SRP, interface->name,
             interface->ineligible ? "ineligible" : "inactive");
        return;
    }

    // See if we have a prefix from some other router
    for (router = interface->routers; router; router = router->next) {
        icmp_option_t *option = router->options;
        int i;
        if (now - router->received_time > MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE)  {
            stale_routers_exist = true;
            SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, router_src_addr_buf);
            INFO("Router " PRI_SEGMENTED_IPv6_ADDR_SRP " is stale by %" PRIu64 " milliseconds",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, router_src_addr_buf),
                 now - router->received_time);
        } else {
            for (i = 0; i < router->num_options; i++) {
                if (option->type == icmp_option_prefix_information) {
                    prefix_information_t *prefix = &option->option.prefix_information;
                    if ((prefix->flags & ND_OPT_PI_FLAG_ONLINK) &&
                        ((prefix->flags & ND_OPT_PI_FLAG_AUTO) || (router->flags & ND_RA_FLAG_MANAGED)) &&
                        prefix->preferred_lifetime > 0)
                    {
                        // If this is a new icmp_message received now and contains PIO.
                        if (router->new_router) {
                            new_prefix = true;
                            router->new_router = false; // clear the bit since srp-mdns-proxy already processed it.
                        }

                        // Right now all we need is to see if there is an on-link prefix.
                        on_link_prefix_present = true;
                        SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_add_buf);
                        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, __pio_prefix_buf);
                        DEBUG("routing_policy_evaluate: router has PIO - ifname: " PUB_S_SRP ", router src: " PRI_SEGMENTED_IPv6_ADDR_SRP
                             ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                             interface->name,
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_add_buf),
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, __pio_prefix_buf));
                    }
                }
                option++;
            }
        }
    }

    INFO("policy on " PUB_S_SRP ": " PUB_S_SRP "stale " /* stale_routers_exist ? */
         PUB_S_SRP "disco " /* interface->router_discovery_complete ? */
         PUB_S_SRP "present " /* on_link_prefix_present ? */
         PUB_S_SRP "advert " /* interface->advertise_ipv6_prefix ? */
         PUB_S_SRP "conf " /* interface->on_link_prefix_configured ? */
         PUB_S_SRP "new_prefix " /* new_prefix ? */
         "preferred = %" PRIu32 " valid = %" PRIu32 " deadline = %llu",
         interface->name, stale_routers_exist ? "" : "!", interface->router_discovery_complete ? "" : "!",
         on_link_prefix_present ? "" : "!", interface->advertise_ipv6_prefix ? "" : "!",
         interface->on_link_prefix_configured ? "" : "!", new_prefix ? "" : "!",
         interface->preferred_lifetime, interface->valid_lifetime, interface->deprecate_deadline);

    // If there are stale routers, start doing router discovery again to see if we can get them to respond.
    // Also, if we have not yet done router discovery, do it now.
    if ((!interface->router_discovery_complete || stale_routers_exist) && !on_link_prefix_present) {
        if (!interface->router_discovery_in_progress) {
            // Start router discovery.
            router_discovery_start(interface);
        } else {
            INFO("routing_policy_evaluate: router discovery in progress");
        }
    }
    // If we are advertising a prefix and there's another on-link prefix, deprecate the one we are
    // advertising.
    else if (interface->advertise_ipv6_prefix && on_link_prefix_present) {
        // If we have been advertising a preferred prefix, deprecate it.
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        if (interface->preferred_lifetime != 0) {
            INFO("routing_policy_evaluate: deprecating interface prefix in 30 minutes - prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
            interface->preferred_lifetime = 0;
            interface->deprecate_deadline = now + 1800 * 1000;
            something_changed = true;
        } else {
            INFO("routing_policy_evaluate: prefix deprecating in progress - prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
        }
    }
    // If there is no on-link prefix and we aren't advertising, or have deprecated, start advertising
    // again (or for the first time).
    else if (!on_link_prefix_present && interface->router_discovery_complete &&
             interface->link != NULL && interface->link->primary == interface &&
             (!interface->advertise_ipv6_prefix || interface->deprecate_deadline != 0 ||
              interface->preferred_lifetime == 0)) {

        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        INFO("routing_policy_evaluate: advertising prefix again - ifname: " PUB_S_SRP ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP, interface->name,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));

        // If we were deprecating, stop.
        ioloop_cancel_wake_event(interface->deconfigure_wakeup);
        interface->deprecate_deadline = 0;

        // Start advertising immediately, 30 minutes.
        interface->preferred_lifetime = interface->valid_lifetime = 1800;

        // If the on-link prefix isn't configured on the interface, do that.
        if (!interface->on_link_prefix_configured) {
#ifndef RA_TESTER
            if (!interface->is_thread) {
#endif
                interface_prefix_configure(interface->ipv6_prefix, interface);
#ifndef RA_TESTER
            } else {
                INFO("Not setting up " PUB_S_SRP " because it is the thread interface", interface->name);
            }
#endif
        } else {
            // Configuring the on-link prefix takes a while, so we want to re-evaluate after it's finished.
            interface->advertise_ipv6_prefix = true;
            something_changed = true;
        }
    }

    // If we've been looking to see if there's an on-link prefix, and we got one from the new router advertisement,
    // stop looking for new one.
    if (new_prefix) {
        router_discovery_stop(interface, now);
    }

    // If anything changed, do an immediate beacon; otherwise wait until the next one.
    // Also when something changed, set the number of transmissions back to zero so that
    // we send a few initial beacons quickly for reliability.
    if (something_changed) {
        INFO("change on " PUB_S_SRP ": " PUB_S_SRP "disco " PUB_S_SRP "present " PUB_S_SRP "advert " PUB_S_SRP
             "conf preferred = %" PRIu32 " valid = %" PRIu32 " deadline = %llu",
             interface->name, interface->router_discovery_complete ? "" : "!", on_link_prefix_present ? "" : "!",
             interface->advertise_ipv6_prefix ? "" : "!", interface->on_link_prefix_configured ? "" : "!",
             interface->preferred_lifetime,
             interface->valid_lifetime, interface->deprecate_deadline);
        interface->num_beacons_sent = 0;
        interface_beacon_schedule(interface, 0);
    }
}

static void
start_vicarious_router_discovery_if_appropriate(interface_t *const interface)
{
    if (!interface->advertise_ipv6_prefix &&
        !interface->vicarious_router_discovery_in_progress && !interface->router_discovery_in_progress)
    {
        if (interface->vicarious_discovery_complete == NULL) {
            interface->vicarious_discovery_complete = ioloop_wakeup_create();
        } else {
            ioloop_cancel_wake_event(interface->vicarious_discovery_complete);
        }
        if (interface->vicarious_discovery_complete != NULL) {
            ioloop_add_wake_event(interface->vicarious_discovery_complete,
                                  interface, vicarious_discovery_callback, NULL, 20 * 1000);
            interface->vicarious_router_discovery_in_progress = true;
        }
        // In order for vicarious router discovery to be useful, we need all of the routers
        // that were present when the first solicit was received to be stale when we give up
        // on vicarious discovery.  If we got any router advertisements, these will not be
        // stale, and that means vicarious discovery succeeded.
        make_all_routers_nearly_stale(interface, ioloop_timenow());
        INFO("start_vicarious_router_discovery_if_appropriate: Starting vicarious router discovery on " PUB_S_SRP,
             interface->name);
    }
}

static void
router_solicit(icmp_message_t *message)
{
    interface_t *iface, *interface;

    // Further validate the message
    if (message->hop_limit != 255 || message->code != 0) {
        ERROR("Invalid router solicitation, hop limit = %d, code = %d", message->hop_limit, message->code);
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&message->source)) {
        icmp_option_t *option = message->options;
        int i;
        for (i = 0; i < message->num_options; i++) {
            if (option->type == icmp_option_source_link_layer_address) {
                ERROR("source link layer address in router solicitation from unspecified IP address");
                return;
            }
            option++;
        }
    } else {
        // Make sure it's not from this host
        for (iface = interfaces; iface; iface = iface->next) {
            if (iface->have_link_layer_address && !memcmp(&message->source,
                                                          &iface->link_local, sizeof(message->source))) {
                INFO("dropping router solicitation sent from this host.");
                return;
            }
        }
    }
    interface = message->interface;

    // Schedule an immediate send, which will be delayed by up to a second.
    if (!interface->ineligible && !interface->inactive) {
        interface_beacon_schedule(interface, 0);
    }

    // When we receive a router solicit, it means that a host is looking for a router.   We should
    // expect to hear replies if they are multicast.   If we hear no replies, it could mean there is
    // no on-link prefix.   In this case, we restart our own router discovery process.  There is no
    // need to do this if we are the one advertising a prefix.
    start_vicarious_router_discovery_if_appropriate(interface);
}

static void
router_advertisement(icmp_message_t *message)
{
    interface_t *iface;
    icmp_message_t *router, **rp;
    if (message->hop_limit != 255 || message->code != 0 || !IN6_IS_ADDR_LINKLOCAL(&message->source)) {
        ERROR("Invalid router advertisement, hop limit = %d, code = %d", message->hop_limit, message->code);
        icmp_message_free(message);
        return;
    }
    for (iface = interfaces; iface != NULL; iface = iface->next) {
        if (iface->have_link_layer_address && !memcmp(&message->source,
                                                      &iface->link_local, sizeof(message->source))) {
            INFO("dropping router advertisement sent from this host.");
            icmp_message_free(message);
            return;
        }
    }

    // See if we've had other advertisements from this router.
    for (rp = &message->interface->routers; *rp != NULL; rp = &(*rp)->next) {
        router = *rp;
        if (!memcmp(&router->source, &message->source, sizeof(message->source))) {
            message->next = router->next;
            *rp = message;
            icmp_message_free(router);
            break;
        }
    }
    // If not, save it.
    if (*rp == NULL) {
        *rp = message;
    }

    // Something may have changed, so do a policy recalculation for this interface
    routing_policy_evaluate(message->interface, false);
}

static void
icmp_callback(io_t *NONNULL io, void *__unused context)
{
    ssize_t rv;
    uint8_t icmp_buf[1500];
    unsigned offset = 0, length = 0;
    uint32_t reserved32;
    int ifindex;
    addr_t src, dest;
    interface_t *interface;
    int hop_limit;

    rv = ioloop_recvmsg(io->fd, &icmp_buf[0], sizeof(icmp_buf), &ifindex, &hop_limit, &src, &dest);
    if (rv < 0) {
        ERROR("icmp_callback: can't read ICMP message: " PUB_S_SRP, strerror(errno));
        return;
    }

    icmp_message_t *message = calloc(1, sizeof(*message));
    if (message == NULL) {
        ERROR("Unable to allocate icmp_message_t for parsing");
        return;
    }

    message->source = src.sin6.sin6_addr;
    message->destination = dest.sin6.sin6_addr;
    message->hop_limit = hop_limit;
    for (interface = interfaces; interface; interface = interface->next) {
        if (interface->index == ifindex) {
            message->interface = interface;
            break;
        }
    }
    message->received_time = ioloop_timenow();
    message->received_time_already_adjusted = false;
    message->new_router = true;

    if (message->interface == NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(message->source.s6_addr, src_buf);
        SEGMENTED_IPv6_ADDR_GEN_SRP(message->destination.s6_addr, dst_buf);
        INFO("ICMP message type %d from " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP
             " on interface index %d, which isn't listed.",
             icmp_buf[0], SEGMENTED_IPv6_ADDR_PARAM_SRP(message->source.s6_addr, src_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(message->destination.s6_addr, dst_buf), ifindex);
        icmp_message_free(message);
        return;
    }

    length = (unsigned)rv;
    if (length < sizeof (struct icmp6_hdr)) {
        ERROR("Short ICMP message: length %zd is shorter than ICMP header length %zd", rv, sizeof(struct icmp6_hdr));
        icmp_message_free(message);
        return;
    }

    // The increasingly innaccurately named dns parse functions will work fine for this.
    if (!dns_u8_parse(icmp_buf, length, &offset, &message->type)) {
        goto out;
    }
    if (!dns_u8_parse(icmp_buf, length, &offset, &message->code)) {
        goto out;
    }
    // XXX check the checksum
    if (!dns_u16_parse(icmp_buf, length, &offset, &message->checksum)) {
        goto out;
    }
    switch(message->type) {
    case icmp_type_router_advertisement:
        if (!dns_u8_parse(icmp_buf, length, &offset, &message->cur_hop_limit)) {
            goto out;
        }
        if (!dns_u8_parse(icmp_buf, length, &offset, &message->flags)) {
            goto out;
        }
        if (!dns_u16_parse(icmp_buf, length, &offset, &message->router_lifetime)) {
            goto out;
        }
        if (!dns_u32_parse(icmp_buf, length, &offset, &message->reachable_time)) {
            goto out;
        }
        if (!dns_u32_parse(icmp_buf, length, &offset, &message->retransmission_timer)) {
            goto out;
        }

        if (!icmp_message_parse_options(message, icmp_buf, length, &offset)) {
            goto out;
        }
        icmp_message_dump(message, &message->source, &message->destination);
        router_advertisement(message);
        // router_advertisement() is ressponsible for freeing the messaage if it doesn't need it.
        return;
        break;

    case icmp_type_router_solicitation:
        if (!dns_u32_parse(icmp_buf, length, &offset, &reserved32)) {
            goto out;
        }
        if (!icmp_message_parse_options(message, icmp_buf, length, &offset)) {
            goto out;
        }
        icmp_message_dump(message, &message->source, &message->destination);
        router_solicit(message);
        break;
    case icmp_type_neighbor_advertisement:
    case icmp_type_neighbor_solicitation:
    case icmp_type_echo_request:
    case icmp_type_echo_reply:
    case icmp_type_redirect:
        break;
    }

out:
    icmp_message_free(message);
    return;
}

#ifdef MONITOR_ROUTING_SOCKET
static void
route_message(io_t *__unused rt, route_message_t *message)
{
    addr_t *addr;

    switch(message->route.rtm_type) {
        // When an interface goes up, or when an address is added, we get one of these.
    case RTM_NEWADDR:
        INFO("Message length %d, version %d, type RTM_NEWADDR, index %d",
             message->len, message->route.rtm_version, message->address.ifam_index);
        // ifa_msghdr followed by zero or more addresses
        // Addresses start on 32-bit boundaries and are sockaddrs with sa_len indicating the size.
        addr = (addr_t *)((&message->address) + 1);
        break;
        // When an interface goes down, we may get one of these.  Also when an address is deleted for some reason.
    case RTM_DELADDR:
        INFO("Message length %d, version %d, type RTM_DELADDR, index %d",
             message->len, message->route.rtm_version, message->address.ifam_index);
        // ifa_msghdr followed by zero or more addresses
        addr = (addr_t *)((&message->address) + 1);
        break;
        // When an interface goes up or down, we get one of these.
    case RTM_IFINFO:
        INFO("Message length %d, version %d, type RTM_IFINFO, index %d",
             message->len, message->route.rtm_version, message->interface.ifm_index);
        // if_msghdr followed by zero or more addresses
        addr = (addr_t *)((&message->interface) + 1);
        break;
    case RTM_IFINFO2:
        INFO("Message length %d, version %d, type RTM_IFINFO2, index %d",
             message->len, message->route.rtm_version, message->if2.ifm_index);
        addr = (addr_t *)((&message->if2) + 1);
        break;
    case RTM_ADD:
        INFO("Message length %d, version %d, type RTM_ADD, index %d",
             message->len, message->route.rtm_version, message->if2.ifm_index);
        addr = (addr_t *)((&message->if2) + 1);
        break;
    case RTM_DELETE:
        INFO("Message length %d, version %d, type RTM_DELETE, index %d",
             message->len, message->route.rtm_version, message->if2.ifm_index);
        addr = (addr_t *)((&message->if2) + 1);
        break;
    case RTM_CHANGE:
        INFO("Message length %d, version %d, type RTM_CHANGE, index %d",
             message->len, message->route.rtm_version, message->if2.ifm_index);
        addr = (addr_t *)((&message->if2) + 1);
        break;
    default:
        INFO("Message length %d, version %d, type %d", message->len, message->route.rtm_version,
             message->route.rtm_type);
        break;
    }
    return;
}

static void
route_callback(io_t *NONNULL io, void *__unused context)
{
    ssize_t rv;
    route_message_t message;

    rv = read(io->fd, &message, sizeof message);
    if (rv < 0) {
        ERROR("route_callback: read returned " PUB_S_SRP, strerror(errno));
        ioloop_close(io);
        return;
    } else if (rv == 0) {
        ERROR("route_callback: read returned 0");
        ioloop_close(io);
        return;
    } else {
        // Process the message.
        route_message(io, &message);
        return;
    }
}

static void
route_entry(struct rt_msghdr2 *route)
{
    (void)route;
}

static void
route_fetch(void)
{
    size_t table_size;
#define NUM_SYSCTL_ARGS 6
    int sysctl_args[NUM_SYSCTL_ARGS];
    char *table, *next_route, *end;
    struct rt_msghdr2 *route;
    int rv;

    sysctl_args[0] = CTL_NET;
    sysctl_args[1] = PF_ROUTE;
    sysctl_args[2] = 0;
    sysctl_args[3] = 0;
    sysctl_args[4] = NET_RT_DUMP2;
    sysctl_args[5] = 0;

    rv = sysctl(sysctl_args, NUM_SYSCTL_ARGS, NULL, &table_size, NULL, 0);
    if (rv < 0) {
        ERROR("route_fetch: sysctl failed getting routing table dump estimate: " PUB_S_SRP, strerror(errno));
        return;
    }

    table = malloc(table_size);
    if (table == NULL) {
        ERROR("No memory for routing table of size %zu", table_size);
        return;
    }

    rv = sysctl(sysctl_args, NUM_SYSCTL_ARGS, table, &table_size, NULL, 0);
    if (rv < 0) {
        ERROR("route_fetch: sysctl failed getting routing table dump: " PUB_S_SRP, strerror(errno));
        return;
    }

    end = table + table_size;
    for (next_route = table; next_route < end; next_route = next_route + route->rtm_msglen) {
        route = (struct rt_msghdr2 *)next_route;
        if (route->rtm_msglen + next_route > end) {
            INFO("Bogus routing table--last route goes past end of buffer.");
            break;
        }
        route_entry(route);
    }
}

bool
start_route_listener(void)
{
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (sock < 0) {
        ERROR("Unable to listen for link status change events: " PUB_S_SRP, strerror(errno));
        return false;
    }

    io_t *io = ioloop_file_descriptor_create(sock, NULL, NULL);
    if (io == NULL) {
        ERROR("No memory for route I/O structure.");
        close(sock);
        return false;
    }

#ifdef RO_MSGFILTER
    static uint8_t subscriptions[] = { RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO, RTM_IFINFO2 };
    if (setsockopt(routefd, PF_ROUTE, RO_MSGFILTER, &subscriptions, (socklen_t)sizeof(subscriptions)) < 0) {
        ERROR("Unable to set routing socket subscriptions.");
    }
#endif

    ioloop_add_reader(io, route_callback);

    route_fetch();
    return true;
}
#endif // MONITOR_ROUTING_SOCKET

#if defined(USE_IPCONFIGURATION_SERVICE)
static void
dict_add_string_as_array(CFMutableDictionaryRef dict, CFStringRef prop_name, const char * str)
{
    CFArrayRef        array;
    CFStringRef        prop_val;

    if (str == NULL) {
        return;
    }
    prop_val = CFStringCreateWithCString(NULL, str, kCFStringEncodingUTF8);
    array = CFArrayCreate(NULL, (const void **)&prop_val, 1, &kCFTypeArrayCallBacks);
    CFRelease(prop_val);
    CFDictionarySetValue(dict, prop_name, array);
    CFRelease(array);
    return;
}

static void
dict_add_int_as_array(CFMutableDictionaryRef dict, CFStringRef prop_name,
              int int_val)
{
    CFArrayRef        array;
    CFNumberRef        num;

    num = CFNumberCreate(NULL, kCFNumberIntType, &int_val);
    array = CFArrayCreate(NULL, (const void **)&num, 1, &kCFTypeArrayCallBacks);
    CFRelease(num);
    CFDictionarySetValue(dict, prop_name, array);
    CFRelease(array);
    return;
}

static CFDictionaryRef
ipconfig_options_dict_create(CFDictionaryRef config_dict)
{
    return CFDictionaryCreate(NULL, (const void **)&kIPConfigurationServiceOptionIPv6Entity,
                              (const void **)&config_dict, 1, &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

static void
ipconfig_service_changed(interface_t * interface)
{
    CFDictionaryRef     service_info;

    if (interface->ip_configuration_service == NULL) {
        INFO("ipconfig_service_changed: ip_configuration_service is NULL");
        return;
    }
    service_info = IPConfigurationServiceCopyInformation(interface->ip_configuration_service);
    if (service_info == NULL) {
        INFO("ipconfig_service_changed: IPConfigurationService on " PUB_S_SRP " is incomplete", interface->name);
    }
    else {
        INFO("ipconfig_service_changed: IPConfigurationService on " PUB_S_SRP " is ready", interface->name);
        CFRelease(service_info);

        // Now that the prefix is configured on the interface, we can start advertising it.
        interface->on_link_prefix_configured = true;
        routing_policy_evaluate(interface, true);
    }
    return;

}


static void
ipconfig_service_callback(SCDynamicStoreRef __unused session, CFArrayRef __unused changes,
                          void * info)
{
    interface_t *	interface = (interface_t *)info;

    ipconfig_service_changed(interface);
    return;
}

static void
monitor_ipconfig_service(interface_t * interface)
{
    SCDynamicStoreContext    context = {
                       .version = 0,
                       .info = NULL,
                       .retain = NULL,
                       .release = NULL,
                       .copyDescription = NULL
    };
    CFArrayRef            keys;
    SCDynamicStoreRef    store;
    CFStringRef            store_key;

    if (interface->ip_configuration_store != NULL) {
        INFO("Releasing old SCDynamicStore object for " PUB_S_SRP, interface->name);
        SCDynamicStoreSetDispatchQueue(interface->ip_configuration_store, NULL);
        CFRelease(interface->ip_configuration_store);
        interface->ip_configuration_store = NULL;
    }

#define OUR_IDENTIFIER    CFSTR("ThreadBorderRouter")
    context.info = interface;
    store = SCDynamicStoreCreate(NULL, OUR_IDENTIFIER,
                                 ipconfig_service_callback, &context);
    store_key = IPConfigurationServiceGetNotificationKey(interface->ip_configuration_service);
    keys = CFArrayCreate(NULL, (const void * *)&store_key,
                         1,
                         &kCFTypeArrayCallBacks);
    SCDynamicStoreSetNotificationKeys(store, keys, NULL);
    CFRelease(keys);

    /* avoid race with being notified */
    ipconfig_service_changed(interface);
    SCDynamicStoreSetDispatchQueue(store, dispatch_get_main_queue());
    interface->ip_configuration_store = (void *)store;
}

static Boolean
start_ipconfig_service(interface_t *interface, const char *ip6addr_str)
{
	CFMutableDictionaryRef config_dict;
    CFStringRef interface_name;
    CFDictionaryRef options;

    if (interface->ip_configuration_service != NULL) {
        INFO("start_ipconfig_service: releasing old IPConfigurationService object for " PUB_S_SRP, interface->name);
        CFRelease(interface->ip_configuration_service);
        interface->ip_configuration_service = NULL;
    }

    // Create an IPv6 entity dictionary with ConfigMethod, Addresses, and PrefixLength properties
    config_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(config_dict, kSCPropNetIPv6ConfigMethod, kSCValNetIPv6ConfigMethodManual);
#define PREFIX_LENGTH    64
    dict_add_string_as_array(config_dict, kSCPropNetIPv6Addresses, ip6addr_str);
    dict_add_int_as_array(config_dict, kSCPropNetIPv6PrefixLength, PREFIX_LENGTH);
    options = ipconfig_options_dict_create(config_dict);
    CFRelease(config_dict);
    interface_name = CFStringCreateWithCString(NULL, interface->name, kCFStringEncodingUTF8);
    interface->ip_configuration_service = IPConfigurationServiceCreate(interface_name, options);
    CFRelease(interface_name);
    CFRelease(options);
    if (interface->ip_configuration_service == NULL) {
        ERROR("start_ipconfig_service: IPConfigurationServiceCreate on " PUB_S_SRP " failed", interface->name);
    }
    else {
        monitor_ipconfig_service(interface);
        struct in6_addr ip6addr;
        int ret = inet_pton(AF_INET6, ip6addr_str, ip6addr.s6_addr);
        if (ret == 1) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(ip6addr.s6_addr, ip6addr_buf);
            INFO("start_ipconfig_service: IPConfigurationServiceCreate on " PRI_S_SRP "/" PRI_SEGMENTED_IPv6_ADDR_SRP
                  " succeeded", interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(ip6addr.s6_addr, ip6addr_buf));
        }
	}
    return (interface->ip_configuration_service != NULL);
}

#elif defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IPCONFIG)
static void
link_route_done(void *context, int status, const char *error)
{
    interface_t *interface = context;

    if (error != NULL) {
        ERROR("link_route_done on " PUB_S_SRP ": " PUB_S_SRP, interface->name, error);
    } else {
        INFO("link_route_done on " PUB_S_SRP ": %d.", interface->name, status);
    }
    ioloop_subproc_release(link_route_adder_process);
    // Now that the on-link prefix is configured, time for a policy re-evaluation.
    interface->on_link_prefix_configured = true;
    routing_policy_evaluate(interface, true);
}
#endif

static void
interface_prefix_configure(struct in6_addr prefix, interface_t *interface)
{
    int sock;

    sock = socket(PF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        ERROR("interface_prefix_configure: socket(PF_INET6, SOCK_DGRAM, 0) failed " PUB_S_SRP ": " PUB_S_SRP,
              interface->name, strerror(errno));
        return;
    }
#ifdef CONFIGURE_STATIC_INTERFACE_ADDRESSES
    struct in6_addr interface_address = prefix;
    char addrbuf[INET6_ADDRSTRLEN];
    interface_address.s6_addr[15] = 1;
    inet_ntop(AF_INET6, &interface_address, addrbuf, INET6_ADDRSTRLEN);
#if defined (USE_IPCONFIGURATION_SERVICE)
    if (!start_ipconfig_service(interface, addrbuf)) {
        close(sock);
        return;
    }
#elif defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IPCONFIG)
    char *args[] = { "set", interface->name, "MANUAL-V6", addrbuf, "64" };

    INFO("interface_prefix_configure: /sbin/ipconfig " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " "
         PUB_S_SRP, args[0], args[1], args[2], args[3], args[4]);
    link_route_adder_process = ioloop_subproc("/usr/sbin/ipconfig", args, 5, link_route_done, interface, NULL);
    if (link_route_adder_process == NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface_address.s6_addr, if_addr_buf);
        ERROR("interface_prefix_configure: unable to set interface address for " PUB_S_SRP " to "
              PRI_SEGMENTED_IPv6_ADDR_SRP ".", interface->name,
              SEGMENTED_IPv6_ADDR_PARAM_SRP(interface_address.s6_addr, if_addr_buf));
    }
#else
    struct in6_aliasreq alias_request;
    memset(&alias_request, 0, sizeof(alias_request));
    strlcpy(alias_request.ifra_name, interface->name, IFNAMSIZ);
    alias_request.ifra_addr.sin6_family = AF_INET6;
    alias_request.ifra_addr.sin6_len = sizeof(alias_request.ifra_addr);
    memcpy(&alias_request.ifra_addr.sin6_addr, &interface_address, sizeof(alias_request.ifra_addr.sin6_addr));
    alias_request.ifra_prefixmask.sin6_len = sizeof(alias_request.ifra_addr);
    alias_request.ifra_prefixmask.sin6_family = AF_INET6;
    memset(&alias_request.ifra_prefixmask.sin6_addr, 0xff, 8); // /64.
    alias_request.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME; // seconds, I hope?
    alias_request.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME; // seconds, I hope?
    ret = ioctl(sock, SIOCAIFADDR_IN6, &alias_request);
    if (ret < 0) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface_address.s6_addr, if_addr_buf);
        ERROR("interface_prefix_configure: can't configure static address " PRI_SEGMENTED_IPv6_ADDR_SRP " on " PUB_S_SRP
              ": " PUB_S_SRP, SEGMENTED_IPv6_ADDR_PARAM_SRP(interface_address.s6_addr, if_addr_buf), interface->name,
              strerror(errno));
    } else {
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface_address.s6_addr, if_addr_buf);
        INFO("interface_prefix_configure: added address " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PUB_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(interface_address.s6_addr, if_addr_buf), interface->name);
    }
#endif // CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IPCONFIG
#else
    (void)prefix;
#endif // CONFIGURE_STATIC_INTERFACE_ADDRESSES
}

#ifdef USE_SYSCTL_COMMMAND_TO_ENABLE_FORWARDING
static void
thread_forwarding_done(void *__unused context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_forwarding_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_forwarding_done: %d.", status);
    }
    ioloop_subproc_release(thread_forwarding_setter_process);
}

static void
set_thread_forwarding(void)
{
    char *args[] = { "-w", "net.inet6.ip6.forwarding=1" };

    INFO("/usr/sbin/sysctl " PUB_S_SRP " " PUB_S_SRP, args[0], args[1]);
    thread_forwarding_setter_process = ioloop_subproc("/usr/sbin/sysctl", args, 2, thread_forwarding_done,
                                                      NULL, NULL);
    if (thread_forwarding_setter_process == NULL) {
        ERROR("Unable to set thread forwarding enabled.");
    }
}

#else

static void
set_thread_forwarding(void)
{
    int wun = 1;
    int ret = sysctlbyname("net.inet6.ip6.forwarding", NULL, 0, &wun, sizeof(wun));
    if (ret < 0) {
        ERROR("set_thread_forwarding: " PUB_S_SRP, strerror(errno));
    } else {
        INFO("Enabled IPv6 forwarding.");
    }
}
#endif // USE_SYSCTL_COMMMAND_TO_ENABLE_FORWARDING

#ifdef NEED_THREAD_RTI_SETTER
static void
thread_rti_done(void *__unused context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_rti_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_rti_done: %d.", status);
    }
    ioloop_subproc_release(thread_rti_setter_process);
}

static void
set_thread_rti(void)
{
    char *args[] = { "-w", "net.inet6.icmp6.nd6_process_rti=1" };
    thread_rti_setter_process = ioloop_subproc("/usr/sbin/sysctl", args, 2, thread_rti_done,
                                               NULL, NULL);
    if (thread_rti_setter_process == NULL) {
        ERROR("Unable to set thread rti enabled.");
    }
}
#endif

#if TARGET_OS_TV && !defined(RA_TESTER)
#ifdef ADD_PREFIX_WITH_WPANCTL
static void
thread_prefix_done(void *__unused context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_prefix_done: " PUB_S_SRP, error);
    } else {
        interface_t *interface;

        INFO("thread_prefix_done: %d.", status);
        for (interface = interfaces; interface; interface = interface->next) {
            if (!interface->inactive) {
                interface_beacon_schedule(interface, 0);
            }
        }
    }
    ioloop_subproc_release(thread_prefix_adder_process);
}
#endif

static void
cti_add_prefix_callback(void *__unused context, cti_status_t status)
{
    interface_t *interface;
    INFO("cti_add_prefix_callback: %d", status);
    for (interface = interfaces; interface; interface = interface->next) {
        if (!interface->inactive) {
            interface_beacon_schedule(interface, 0);
        }
    }
}

static thread_prefix_t *
get_advertised_thread_prefix(void)
{
    if (published_thread_prefix != NULL) {
        return published_thread_prefix;
    } else {
        return adopted_thread_prefix;
    }
    return NULL;
}

static void
set_thread_prefix(void)
{
    char addrbuf[INET6_ADDRSTRLEN];
    thread_prefix_t *advertised_thread_prefix = get_advertised_thread_prefix();
    if (advertised_thread_prefix == NULL) {
        ERROR("set_thread_prefix: no advertised thread prefix.");
        return;
    }
    SEGMENTED_IPv6_ADDR_GEN_SRP(advertised_thread_prefix->prefix.s6_addr, thread_prefix_buf);
    inet_ntop(AF_INET6, &advertised_thread_prefix->prefix, addrbuf, sizeof addrbuf);
#ifdef ADD_PREFIX_WITH_WPANCTL
    char *args[] = { "add-prefix", "--stable", "--preferred", "--slaac", "--default-route", "--on-mesh", addrbuf };
    INFO("/usr/local/bin/wpanctl " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " "
         PRI_SEGMENTED_IPv6_ADDR_SRP, args[0], args[1], args[2], args[3], args[4], args[5],
         SEGMENTED_IPv6_ADDR_PARAM_SRP(advertised_thread_prefix->prefix.s6_addr, thread_prefix_buf));
    thread_prefix_adder_process = ioloop_subproc("/usr/local/bin/wpanctl", args, 7, thread_prefix_done,
                                                 NULL, NULL);
    if (thread_prefix_adder_process == NULL) {
        ERROR("Unable to add thread interface prefix.");
    }
#else
    INFO("add_prefix(true, true, true, true, " PRI_SEGMENTED_IPv6_ADDR_SRP ")",
         SEGMENTED_IPv6_ADDR_PARAM_SRP(advertised_thread_prefix->prefix.s6_addr, thread_prefix_buf));
    int status = cti_add_prefix(NULL, cti_add_prefix_callback, dispatch_get_main_queue(),
                                &advertised_thread_prefix->prefix, advertised_thread_prefix->prefix_len,
                                true, true, true, true);
    if (status) {
        ERROR("Unable to add thread interface prefix.");
    }
#endif
}
#endif // TARGET_OS_TV && !RA_TESTER

static void
router_advertisement_send(interface_t *interface)
{
    uint8_t *message;
    dns_towire_state_t towire;

    // Thread blocks RAs so no point sending them.
    if (interface->inactive
#ifndef RA_TESTER
        || interface->is_thread
#endif
        ) {
        return;
    }

#define MAX_ICMP_MESSAGE 1280
    message = malloc(MAX_ICMP_MESSAGE);
    if (message == NULL) {
        ERROR("Unable to construct ICMP Router Advertisement: no memory");
        return;
    }

    // Construct the ICMP header and options for each interface.
    memset(&towire, 0, sizeof towire);
    towire.p = message;
    towire.lim = message + MAX_ICMP_MESSAGE;

    // Construct the ICMP header.
    // We use the DNS message construction functions because it's easy; probably should just make
    // the towire functions more generic.
    dns_u8_to_wire(&towire, ND_ROUTER_ADVERT);  // icmp6_type
    dns_u8_to_wire(&towire, 0);                 // icmp6_code
    dns_u16_to_wire(&towire, 0);                // The kernel computes the checksum (we don't technically have it).
    dns_u8_to_wire(&towire, 0);                 // Hop limit, we don't set.
    dns_u8_to_wire(&towire, 0);                 // Flags.  We don't offer DHCP, so We set neither the M nor the O bit.
    // We are not a home agent, so no H bit.  Lifetime is 0, so Prf is 0.
#ifdef ROUTER_LIFETIME_HACK
    dns_u16_to_wire(&towire, 1800);             // Router lifetime, hacked.  This shouldn't ever be enabled.
#else
#ifdef RA_TESTER
    // Advertise a default route on the simulated thread network
    if (!strcmp(interface->name, thread_interface_name)) {
        dns_u16_to_wire(&towire, 1800);         // Router lifetime for default route
    } else {
#endif
        dns_u16_to_wire(&towire, 0);            // Router lifetime for non-default default route(s).
#ifdef RA_TESTER
    }
#endif // RA_TESTER
#endif // ROUTER_LIFETIME_HACK
    dns_u32_to_wire(&towire, 0);                // Reachable time for NUD, we have no opinion on this.
    dns_u32_to_wire(&towire, 0);                // Retransmission timer, again we have no opinion.

    // Send Source link-layer address option
    if (interface->have_link_layer_address) {
        dns_u8_to_wire(&towire, ND_OPT_SOURCE_LINKADDR);
        dns_u8_to_wire(&towire, 1); // length / 8
        dns_rdata_raw_data_to_wire(&towire, &interface->link_layer, sizeof(interface->link_layer));
        INFO("Advertising source lladdr " PRI_MAC_ADDR_SRP " on " PUB_S_SRP, MAC_ADDR_PARAM_SRP(interface->link_layer),
             interface->name);
    }

#ifndef RA_TESTER
    // Send MTU of 1280 for Thread?
    if (interface->is_thread) {
        dns_u8_to_wire(&towire, ND_OPT_MTU);
        dns_u8_to_wire(&towire, 1); // length / 8
        dns_u32_to_wire(&towire, 1280);
        INFO("Advertising MTU of 1280 on " PUB_S_SRP, interface->name);
    }
#endif

    // Send Prefix Information option if there's no IPv6 on the link.
    if (interface->advertise_ipv6_prefix) {
        dns_u8_to_wire(&towire, ND_OPT_PREFIX_INFORMATION);
        dns_u8_to_wire(&towire, 4); // length / 8
        dns_u8_to_wire(&towire, 64); // On-link prefix is always 64 bits
        dns_u8_to_wire(&towire, ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO); // On link, autoconfig
        dns_u32_to_wire(&towire, interface->valid_lifetime);
        dns_u32_to_wire(&towire, interface->preferred_lifetime);
        dns_u32_to_wire(&towire, 0); // Reserved
        dns_rdata_raw_data_to_wire(&towire, &interface->ipv6_prefix, sizeof interface->ipv6_prefix);
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, ipv6_prefix_buf);
        INFO("Advertising on-link prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " on " PUB_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, ipv6_prefix_buf), interface->name);
    }

#ifndef ND_OPT_ROUTE_INFORMATION
#define ND_OPT_ROUTE_INFORMATION 24
#endif
    // In principle we can either send routes to links that are reachable by this router,
    // or just advertise a router to the entire ULA /48.   In theory it doesn't matter
    // which we do; if we support HNCP at some point we probably need to be specific, but
    // for now being general is fine because we have no way to share a ULA.
    // Unfortunately, some RIO implementations do not work with specific routes, so for now
    // We are doing it the easy way and just advertising the /48.
#define SEND_INTERFACE_SPECIFIC_RIOS 1
#ifdef SEND_INTERFACE_SPECIFIC_RIOS

    // If neither ROUTE_BETWEEN_NON_THREAD_LINKS nor RA_TESTER are defined, then we never want to
    // send an RIO other than for the thread network prefix.
#if defined (ROUTE_BETWEEN_NON_THREAD_LINKS) || defined(RA_TESTER)
    interface_t *ifroute;
    // Send Route Information option for other interfaces.
    for (ifroute = interfaces; ifroute; ifroute = ifroute->next) {
        if (ifroute->inactive) {
            continue;
        }
        if (
#ifndef RA_TESTER
            partition_can_provide_routing &&
#endif
            ifroute->advertise_ipv6_prefix &&
#ifdef SEND_ON_LINK_ROUTE
            // In theory we don't want to send RIO for the on-link prefix, but there's this bug, see.
            true &&
#else
            ifroute != interface &&
#endif
#ifdef RA_TESTER
            // For the RA tester, we don't need to send an RIO to the thread network because we're the
            // default router for that network.
            strcmp(interface->name, thread_interface_name)
#else
            true
#endif
            )
        {
            dns_u8_to_wire(&towire, ND_OPT_ROUTE_INFORMATION);
            dns_u8_to_wire(&towire, 2); // length / 8
            dns_u8_to_wire(&towire, 64); // Interface prefixes are always 64 bits
            dns_u8_to_wire(&towire, 0); // There's no reason at present to prefer one Thread BR over another
            dns_u32_to_wire(&towire, 1800); // Route lifetime 1800 seconds (30 minutes)
            dns_rdata_raw_data_to_wire(&towire, &ifroute->ipv6_prefix, 8); // /64 requires 8 bytes.
            SEGMENTED_IPv6_ADDR_GEN_SRP(ifroute->ipv6_prefix.s6_addr, ipv6_prefix_buf);
            INFO("Sending route to " PRI_SEGMENTED_IPv6_ADDR_SRP "%%" PUB_S_SRP " on " PUB_S_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(ifroute->ipv6_prefix.s6_addr, ipv6_prefix_buf),
                 ifroute->name, interface->name);
        }
    }
#endif // ROUTE_BETWEEN_NON_THREAD_LINKS || RA_TESTER

#ifndef RA_TESTER
    // Send route information option for thread prefix
    thread_prefix_t *advertised_thread_prefix = get_advertised_thread_prefix();
    if (advertised_thread_prefix != NULL) {
        dns_u8_to_wire(&towire, ND_OPT_ROUTE_INFORMATION);
        dns_u8_to_wire(&towire, 2); // length / 8
        dns_u8_to_wire(&towire, 64); // Interface prefixes are always 64 bits
        dns_u8_to_wire(&towire, 0); // There's no reason at present to prefer one Thread BR over another
        dns_u32_to_wire(&towire, 1800); // Route lifetime 1800 seconds (30 minutes)
        dns_rdata_raw_data_to_wire(&towire, &advertised_thread_prefix->prefix, 8); // /64 requires 8 bytes.
        SEGMENTED_IPv6_ADDR_GEN_SRP(advertised_thread_prefix->prefix.s6_addr, thread_prefix_buf);
        INFO("Sending route to " PRI_SEGMENTED_IPv6_ADDR_SRP "%%" PUB_S_SRP " on " PUB_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(advertised_thread_prefix->prefix.s6_addr, thread_prefix_buf),
             thread_interface_name, interface->name);
    }
#endif
#else
#ifndef SKIP_SLASH_48
    dns_u8_to_wire(&towire, ND_OPT_ROUTE_INFORMATION);
    dns_u8_to_wire(&towire, 3); // length / 8
    dns_u8_to_wire(&towire, 48); // ULA prefixes are always 48 bits
    dns_u8_to_wire(&towire, 0); // There's no reason at present to prefer one Thread BR over another
    dns_u32_to_wire(&towire, 1800); // Route lifetime 1800 seconds (30 minutes)
    dns_rdata_raw_data_to_wire(&towire, &ula_prefix, 16); // /48 requires 16 bytes
#endif // SKIP_SLASH_48
#endif // SEND_INTERFACE_SPECIFIC_RIOS

    if (towire.error) {
        ERROR("No space in ICMP output buffer for " PUB_S_SRP " at route.c:%d", interface->name, towire.line);
        towire.error = 0;
    } else {
        icmp_send(message, towire.p - message, interface, &in6addr_linklocal_allnodes);
    }
    free(message);
}

static void
router_solicit_send(interface_t *interface)
{
    uint8_t *message;
    dns_towire_state_t towire;

    // Thread blocks RSs so no point sending them.
    if (interface->inactive
#ifndef RA_TESTER
        || interface->is_thread
#endif
        ) {
        return;
    }

#define MAX_ICMP_MESSAGE 1280
    message = malloc(MAX_ICMP_MESSAGE);
    if (message == NULL) {
        ERROR("Unable to construct ICMP Router Advertisement: no memory");
        return;
    }

    // Construct the ICMP header and options for each interface.
    memset(&towire, 0, sizeof towire);
    towire.p = message;
    towire.lim = message + MAX_ICMP_MESSAGE;

    // Construct the ICMP header.
    // We use the DNS message construction functions because it's easy; probably should just make
    // the towire functions more generic.
    dns_u8_to_wire(&towire, ND_ROUTER_SOLICIT);  // icmp6_type
    dns_u8_to_wire(&towire, 0);                  // icmp6_code
    dns_u16_to_wire(&towire, 0);                 // The kernel computes the checksum (we don't technically have it).
    dns_u32_to_wire(&towire, 0);                 // Reserved32

    // Send Source link-layer address option
    if (interface->have_link_layer_address) {
        dns_u8_to_wire(&towire, ND_OPT_SOURCE_LINKADDR);
        dns_u8_to_wire(&towire, 1); // length / 8
        dns_rdata_raw_data_to_wire(&towire, &interface->link_layer, sizeof(interface->link_layer));
    }

    if (towire.error) {
        ERROR("No space in ICMP output buffer for " PUB_S_SRP " at route.c:%d", interface->name, towire.line);
    } else {
        icmp_send(message, towire.p - message, interface, &in6addr_linklocal_allrouters);
    }
    free(message);
}

static void
icmp_send(uint8_t *message, size_t length, interface_t *interface, const struct in6_addr *destination)
{
    struct iovec iov;
    socklen_t cmsg_length = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof (int));
    uint8_t *cmsg_buffer;
    struct msghdr msg_header;
    struct cmsghdr *cmsg_pointer;
    struct in6_pktinfo *packet_info;
    int hop_limit = 255;
    ssize_t rv;
    struct sockaddr_in6 dest;

    // Make space for the control message buffer.
    cmsg_buffer = malloc(cmsg_length);
    if (cmsg_buffer == NULL) {
        ERROR("Unable to construct ICMP Router Advertisement: no memory");
        return;
    }

    // Send the message
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_scope_id = interface->index;
    dest.sin6_len = sizeof(dest);
    msg_header.msg_namelen = sizeof(dest);
    dest.sin6_addr = *destination;

    msg_header.msg_name = &dest;
    iov.iov_base = message;
    iov.iov_len = length;
    msg_header.msg_iov = &iov;
    msg_header.msg_iovlen = 1;
    msg_header.msg_control = cmsg_buffer;
    msg_header.msg_controllen = cmsg_length;

    // Specify the interface
    cmsg_pointer = CMSG_FIRSTHDR(&msg_header);
    cmsg_pointer->cmsg_level = IPPROTO_IPV6;
    cmsg_pointer->cmsg_type = IPV6_PKTINFO;
    cmsg_pointer->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    packet_info = (struct in6_pktinfo *)CMSG_DATA(cmsg_pointer);
    memset(packet_info, 0, sizeof(*packet_info));
    packet_info->ipi6_ifindex = interface->index;

    // Router advertisements and solicitations have a hop limit of 255
    cmsg_pointer = CMSG_NXTHDR(&msg_header, cmsg_pointer);
    cmsg_pointer->cmsg_level = IPPROTO_IPV6;
    cmsg_pointer->cmsg_type = IPV6_HOPLIMIT;
    cmsg_pointer->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg_pointer), &hop_limit, sizeof(hop_limit));

    // Send it
    rv = sendmsg(icmp_listener.io_state->fd, &msg_header, 0);
    if (rv < 0) {
        uint8_t *in6_addr_bytes = ((struct sockaddr_in6 *)(msg_header.msg_name))->sin6_addr.s6_addr;
        SEGMENTED_IPv6_ADDR_GEN_SRP(in6_addr_bytes, in6_addr_buf);
        ERROR("icmp_send: sending " PUB_S_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP " on interface " PUB_S_SRP
              " index %d: " PUB_S_SRP, message[0] == ND_ROUTER_SOLICIT ? "solicit" : "advertise",
              SEGMENTED_IPv6_ADDR_PARAM_SRP(in6_addr_bytes, in6_addr_buf),
              interface->name, interface->index, strerror(errno));
    } else if ((size_t)rv != iov.iov_len) {
        ERROR("icmp_send: short send to interface " PUB_S_SRP ": %zd < %zd", interface->name, rv, iov.iov_len);
    }
    free(cmsg_buffer);
}

static void
post_solicit_policy_evaluate(void *context)
{
    interface_t *interface = context;
    INFO("Done waiting for router discovery to finish on " PUB_S_SRP, interface->name);
    interface->router_discovery_complete = true;
    interface->router_discovery_in_progress = false;
    flush_stale_routers(interface, ioloop_timenow());

    // See if we need a new prefix on the interface.
    interface_prefix_evaluate(interface);

    routing_policy_evaluate(interface, true);
}

static void
dump_network_signature(char *buffer, size_t buffer_size, const uint8_t *signature, long length)
{
    char *hexp = buffer;
    int i;
    size_t left = buffer_size;
    size_t len;

    if (length == 0) {
        strlcpy(buffer, "<NULL>", buffer_size);
        return;
    }
    for (i = 0; i < length; i++) {
        snprintf(hexp, left, "%02x", signature[i]);
        len = strlen(hexp);
        hexp += len;
        left -= len;
    }
}

static void
network_link_finalize(network_link_t *link)
{
    if (link->signature != NULL) {
        free(link->signature);
    }
    free(link);
}

#define network_link_create(signature, length) network_link_create_(signature, length, __FILE__, __LINE__);
static network_link_t *
network_link_create_(const uint8_t *signature, int length, const char *file, int line)
{
    network_link_t *link = calloc(1, sizeof(*link));
    if (link != NULL) {
        if (signature != NULL) {
            if (length) {
                link->signature = malloc(length);
                if (link->signature == NULL) {
                    INFO("network_link_create: no memory for signature.");
                    free(link);
                    return NULL;
                }
                memcpy(link->signature, signature, length);
                link->signature_length = length;
            }
        }
        RETAIN(link);
    }
    return link;
}

static CFDictionaryRef
network_link_dictionary_copy(network_link_t *link)
{
    CFDictionaryRef dictionary = NULL;
    OSStatus err;
    err = CFPropertyListCreateFormatted(kCFAllocatorDefault, &dictionary,
                                        "{"
                                            "last-seen=%lli"
                                            "signature=%D"
                                            "prefix-number=%i"
                                        "}",
                                        link->last_seen,
                                        link->signature, (int)link->signature_length,
                                        link->prefix_number);
        if (err != 0) {
            dictionary = NULL;
            ERROR("CFPropertyListCreateFormatted failed: %d", err);
        }
    return dictionary;
}

typedef struct network_link_parse_state network_link_parse_state_t;
struct network_link_parse_state {
    network_link_t *NONNULL link;
    bool fail : 1;
    bool last_seen : 1;
    bool signature : 1;
    bool prefix_number : 1;
};

static void
network_link_parse(const void *key, const void *value, void *context)
{
    network_link_parse_state_t *parse_state = context;
    int64_t last_seen;

    if (parse_state->fail) {
        return;
    }
    if (CFGetTypeID(key) != CFStringGetTypeID()) {
        ERROR("network_link_parse: dictionary key not a string.");
        parse_state->fail = true;
        return;
    }

    if (CFStringCompare(key, CFSTR("last-seen"), 0) == kCFCompareEqualTo) {
        // We store the last-seen time as a uint64 encoded as a string, because there is no uint64 CFNumber type.
        // We store the prefix-number time as a CFNumber because it's a uint16_t.
        if (CFGetTypeID(value) != CFNumberGetTypeID() ||
            !CFNumberGetValue(value, kCFNumberSInt64Type, &last_seen))
        {
            ERROR("network_link_parse: last-seen is not a valid CFNumber");
            parse_state->fail = true;
        } else {
            // For some reason CFNumber doesn't support uint64_t, but we are assuming that since we are copying this
            // unchanged, there will be no error introduced by this case.
            // CFProperyListCreateFormatted supports uint64_t, probably by doing the same thing.
            parse_state->link->last_seen = (uint64_t)last_seen;
            parse_state->last_seen = true;
        }
    } else if (CFStringCompare(key, CFSTR("signature"), 0) == kCFCompareEqualTo) {
        const uint8_t *data_buffer;
        long data_length;

        // We store the signature as CFData.
        if (CFGetTypeID(value) != CFDataGetTypeID()) {
            ERROR("network_link_parse: Unable to get CFData for signature because it's not CFData.");
            parse_state->fail = true;
        } else {
            data_buffer = CFDataGetBytePtr(value);
            data_length = CFDataGetLength(value);
            if (data_length < 1) {
                parse_state->link->signature_length = 0;
                parse_state->link->signature = NULL;
                parse_state->signature = true;
            } else {
                parse_state->link->signature_length = data_length;
                parse_state->link->signature = malloc(data_length);
                if (parse_state->link->signature == NULL) {
                    ERROR("network_link_parse: No memory for signature.");
                    parse_state->fail = true;
                } else {
                    memcpy(parse_state->link->signature, data_buffer, data_length);
                    parse_state->signature = true;
                }
            }
        }
    } else if (CFStringCompare(key, CFSTR("prefix-number"), 0) == kCFCompareEqualTo) {
        // We store the prefix-number time as a CFNumber because it's a uint16_t.
        if (CFGetTypeID(value) != CFNumberGetTypeID() ||
            !CFNumberGetValue(value, kCFNumberSInt32Type, &parse_state->link->prefix_number))
        {
            ERROR("network_link_parse: prefix-number is not a valid CFNumber");
            parse_state->fail = true;
        } else if (parse_state->link->prefix_number < 0 || parse_state->link->prefix_number > UINT16_MAX) {
            ERROR("network_link_parse: Invalid prefix-number: %" PRIu32, parse_state->link->prefix_number);
            parse_state->fail = true;
        } else {
            parse_state->prefix_number = true;
        }
    } else {
        char key_buffer[64];
        if (!CFStringGetCString(key, key_buffer, sizeof(key_buffer), kCFStringEncodingUTF8)) {
            INFO("Unexpected network link element dictionary key, but can't decode key");
        } else {
            INFO("Unexpected network link element dictionary key " PUB_S_SRP, key_buffer);
        }
        parse_state->fail = true;
    }
}

static void
network_link_apply(const void *value, void *context)
{
    bool *success = context;
    CFDictionaryRef values = value;
    network_link_parse_state_t parse_state;
    char hexbuf[60];

    if (*success == false) {
        return;
    }

    memset(&parse_state, 0, sizeof parse_state);
    parse_state.link = network_link_create(NULL, 0);
    if (parse_state.link == NULL) {
        ERROR("network_link_apply: no memory for link");
        *success = false;
        return;
    }

    // Parse the dictionary into the structure.
    CFDictionaryApplyFunction(values, network_link_parse, &parse_state);

    // Should have gotten three fields: last_seen, signature, prefix_number
    if (!parse_state.last_seen) {
        ERROR("network_link_apply: expecting last-seen");
        parse_state.fail = true;
    }
    if (!parse_state.signature) {
        ERROR("network_link_apply: expecting signature");
        parse_state.fail = true;
    }
    if (!parse_state.prefix_number) {
        ERROR("network_link_apply: expecting prefix-number");
        parse_state.fail = true;
    }
    if (parse_state.fail) {
        *success = false;
        RELEASE_HERE(parse_state.link, network_link_finalize);
        return;
    }

    dump_network_signature(hexbuf, sizeof hexbuf, parse_state.link->signature, parse_state.link->signature_length);

    // If the link signature hasn't been seen in over a week, there is no need to remember it.  If no new links are
    // seen, an old signature could persist for much longer than a week, but this is okay--the goal here is to prevent
    // the link array from growing without bound, and whenver a link signature is added, the array is rewritte, at
    // which point the old link signatures will be erased.
    if (ioloop_timenow() - parse_state.link->last_seen > 1000 * 3600 * 24 * 7) {
        INFO("network_link_apply: discarding link signature " PRI_S_SRP
             ", prefix number %d, which is more than a week old", hexbuf, parse_state.link->prefix_number);
        RELEASE_HERE(parse_state.link, network_link_finalize);
        return;
    }

    parse_state.link->next = network_links;
    network_links = parse_state.link;
    INFO("network_link_apply: parsed link signature " PRI_S_SRP ", prefix number %d", hexbuf,
         network_links->prefix_number);
    // This is a temporary fix to clean up bogus link prefixes that may exist in preferences.
    if (network_links->prefix_number == 0) {
        network_links->prefix_number = ula_serial++;
    } else {
        if (network_links->prefix_number >= ula_serial) {
            ula_serial = network_links->prefix_number + 1;
        }
    }
}

static void
network_link_record(network_link_t *link)
{
    char hexbuf[60];
    CFDictionaryRef link_dictionary;
    if (network_link_array == NULL) {
        ERROR("network_link_record: no network_link_array, can't record new link.");
        return;
    }
    link_dictionary = network_link_dictionary_copy(link);
    if (link_dictionary == NULL) {
        ERROR("network_link_record: can't convert link into dictionary");
        return;
    }
    CFArrayAppendValue(network_link_array, link_dictionary);

    CFPreferencesSetValue(CFSTR("network-links"), network_link_array,
                          CFSTR("com.apple.srp-mdns-proxy.preferences"),
                          kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
    if (!CFPreferencesSynchronize(CFSTR("com.apple.srp-mdns-proxy.preferences"),
                                  kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)) {
        ERROR("network_link_record: CFPreferencesSynchronize: Unable to store network link array.");
    }
    CFRelease(link_dictionary);
    dump_network_signature(hexbuf, sizeof hexbuf, link->signature, link->signature_length);
    INFO("network_link_record: recording link signature " PRI_S_SRP ", prefix number %d", hexbuf, link->prefix_number);
}

void
ula_generate(void)
{
    char ula_prefix_buffer[INET6_ADDRSTRLEN];
    struct in6_addr old_ula_prefix;
    bool prefix_changed;

    // Already have a prefix?
    if (ula_prefix.s6_addr[0] == 0xfd) {
        old_ula_prefix = ula_prefix;
        prefix_changed = true;
    } else {
        prefix_changed = false;
    }

    memset(&ula_prefix, 0, sizeof(ula_prefix));
    ula_prefix.s6_addr[0] = 0xfd;
    arc4random_buf(&ula_prefix.s6_addr[1], 5); // 40 bits of randomness

    inet_ntop(AF_INET6, &ula_prefix, ula_prefix_buffer, sizeof ula_prefix_buffer);
    CFStringRef ula_string = CFStringCreateWithCString(NULL, ula_prefix_buffer, kCFStringEncodingUTF8);
    if (ula_string == NULL) {
        ERROR("ula_generate: unable to create a ULA prefix string to store in preferences.");
    } else {
        CFPreferencesSetValue(CFSTR("ula-prefix"), ula_string,
                              CFSTR("com.apple.srp-mdns-proxy.preferences"),
                              kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
        if (!CFPreferencesSynchronize(CFSTR("com.apple.srp-mdns-proxy.preferences"),
                                      kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)) {
            ERROR("CFPreferencesSynchronize: Unable to store ULA prefix.");
        }
        CFRelease(ula_string);
    }
    if (prefix_changed) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(old_ula_prefix.s6_addr, old_prefix_buf);
        SEGMENTED_IPv6_ADDR_GEN_SRP(ula_prefix.s6_addr, new_prefix_buf);
        INFO("ula-generate: prefix changed from " PRI_SEGMENTED_IPv6_ADDR_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(old_ula_prefix.s6_addr, old_prefix_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(ula_prefix.s6_addr, new_prefix_buf));
    } else {
        SEGMENTED_IPv6_ADDR_GEN_SRP(ula_prefix.s6_addr, new_prefix_buf);
        INFO("ula-generate: generated ULA prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(ula_prefix.s6_addr, new_prefix_buf));
    }

    // Set up the thread prefix.
    my_thread_prefix = ula_prefix;
    have_thread_prefix = true;
}

static void
ula_setup(void)
{
    char ula_prefix_buffer[INET6_ADDRSTRLEN];
    bool have_stored_ula_prefix = false;

    // Set up the ULA in case we need it.
    CFPropertyListRef plist = CFPreferencesCopyValue(CFSTR("ula-prefix"),
                                                     CFSTR("com.apple.srp-mdns-proxy.preferences"),
                                                     kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);
    if (plist != NULL) {
        if (CFGetTypeID(plist) == CFStringGetTypeID()) {
            if (CFStringGetCString((CFStringRef)plist, ula_prefix_buffer, sizeof(ula_prefix_buffer),
                                   kCFStringEncodingUTF8)) {
                if (inet_pton(AF_INET6, ula_prefix_buffer, &ula_prefix)) {
                    SEGMENTED_IPv6_ADDR_GEN_SRP(ula_prefix.s6_addr, ula_prefix_buf);
                    INFO("ula_setup: re-using stored prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(ula_prefix.s6_addr, ula_prefix_buf));
                    have_stored_ula_prefix = true;
                }
            }
        }
        CFRelease(plist);

        // Get the list of known network links (identified by network signature)
        plist = CFPreferencesCopyValue(CFSTR("network-links"),
                                       CFSTR("com.apple.srp-mdns-proxy.preferences"),
                                       kCFPreferencesCurrentUser, kCFPreferencesCurrentHost);

        if (plist != NULL) {
            if (CFGetTypeID(plist) == CFArrayGetTypeID()) {
                bool success = true;
                CFArrayApplyFunction(plist, CFRangeMake(0,CFArrayGetCount(plist)), network_link_apply, &success);
                if (success) {
                    network_link_array = CFArrayCreateMutableCopy(NULL, 0, plist);
                    if (network_link_array == NULL) {
                        ERROR("ula_setup: no memory for network link array!");
                    }
                }
            }
            CFRelease(plist);
        }
    }

    // If we didn't get any links, make an empty array.
    if (network_link_array == NULL) {
        network_link_array = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        if (network_link_array == NULL) {
            ERROR("ula_setup: unable to make network_link_array.");
        } else {
            INFO("ula_setup: created empty network_link_array.");
        }
    }

    // If we didn't already successfully fetch a stored prefix, try to store one.
    if (!have_stored_ula_prefix) {
        ula_generate();
    } else {
        // Set up the thread prefix.
        my_thread_prefix = ula_prefix;
        have_thread_prefix = true;
    }
}

static void
get_network_signature(interface_t *interface)
{
    nwi_state_t network_state;
    nwi_ifstate_t interface_state;
    int length = 0;
    const uint8_t *signature = NULL;
    network_link_t *link = NULL;
    char hexbuf[60];

    network_state = nwi_state_copy();
    if (network_state != NULL) {
        interface_state = nwi_state_get_ifstate(network_state, interface->name);
        if (interface_state != NULL) {
            signature = nwi_ifstate_get_signature(interface_state, AF_INET, &length);
            if (signature != NULL) {
                dump_network_signature(hexbuf, sizeof(hexbuf), signature, length);
                INFO("get_network_signature: interface " PUB_S_SRP " has ipv4 signature " PRI_S_SRP,
                     interface->name, hexbuf);
            } else {
                signature = nwi_ifstate_get_signature(interface_state, AF_INET6, &length);
                if (signature != NULL) {
                    dump_network_signature(hexbuf, sizeof(hexbuf), signature, length);
                    INFO("get_network_signature: interface " PUB_S_SRP " has ipv6 signature " PRI_S_SRP,
                         interface->name, hexbuf);
                } else {
                    INFO("get_network_signature: no signature on " PUB_S_SRP, interface->name);
                }
            }
        }
        if (signature == NULL) {
            length = 0;
        }
        for (link = network_links; link != NULL; link = link->next) {
            if (link->signature_length == length && (length == 0 || !memcmp(link->signature, signature, length))) {
                break;
            }
        }
        if (link == NULL) {
            link = network_link_create(signature, length);
        }
        nwi_state_release(network_state);
    } else {
        ERROR("get_network_signature: nwi_state_copy() failed on " PUB_S_SRP, interface->name);
    }

    // If we didn't get a network signature, we're going to treat that as a signature. The previous call to
    // network_link_create() can have the same effect.
    if (link == NULL) {
        link = network_link_create(NULL, 0);
    }

    if (link != NULL && link->prefix_number == 0) {
        // Assign a prefix number to the link.
        link->prefix_number = ula_serial++;
        link->last_seen = ioloop_timenow();

        // Save this link in memory.
        link->next = network_links;
        network_links = link;

        // Save this link signature in the preferences.
        network_link_record(link);
    }
    if (interface->link != link) {
#if defined(USE_IPCONFIGURATION_SERVICE)
        if (interface->on_link_prefix_configured) {
            interface_prefix_deconfigure(interface);
        }
#endif
        interface->link = link;
    }
}

bool
start_icmp_listener(void)
{
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    int true_flag = 1;
#ifdef CONFIGURE_STATIC_INTERFACE_ADDRESSES
    int false_flag = 0;
#endif
    struct icmp6_filter filter;
    ssize_t rv;

    if (sock < 0) {
        ERROR("Unable to listen for icmp messages: " PUB_S_SRP, strerror(errno));
        close(sock);
        return false;
    }

    // Only accept router advertisements and router solicits.
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
    rv = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    if (rv < 0) {
        ERROR("Can't set IPV6_RECVHOPLIMIT: " PUB_S_SRP ".", strerror(errno));
        close(sock);
        return false;
    }

    // We want a source address and interface index
    rv = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &true_flag, sizeof(true_flag));
    if (rv < 0) {
        ERROR("Can't set IPV6_RECVPKTINFO: " PUB_S_SRP ".", strerror(errno));
        close(sock);
        return false;
    }

    // We need to be able to reject RAs arriving from off-link.
    rv = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &true_flag, sizeof(true_flag));
    if (rv < 0) {
        ERROR("Can't set IPV6_RECVHOPLIMIT: " PUB_S_SRP ".", strerror(errno));
        close(sock);
        return false;
    }

#ifdef CONFIGURE_STATIC_INTERFACE_ADDRESSES
    // Prevent our router advertisements from updating our routing table.
    rv = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &false_flag, sizeof(false_flag));
    if (rv < 0) {
        ERROR("Can't set IPV6_RECVHOPLIMIT: " PUB_S_SRP ".", strerror(errno));
        close(sock);
        return false;
    }
#endif

    icmp_listener.io_state = ioloop_file_descriptor_create(sock, NULL, NULL);
    if (icmp_listener.io_state == NULL) {
        ERROR("No memory for ICMP I/O structure.");
        close(sock);
        return false;
    }

    // Beacon out a router advertisement every three minutes.
    icmp_listener.unsolicited_interval = 180 * 1000;
    ioloop_add_reader(icmp_listener.io_state, icmp_callback);

    // At this point we need to have a ULA prefix.
    ula_setup();

    return true;
}

static void
interface_router_solicit_finalize(void *context)
{
    interface_t *interface = context;
    interface->router_solicit_wakeup = NULL;
}

static void
router_solicit_callback(void *context)
{
    interface_t *interface = context;
    if (interface->is_thread) {
        INFO("discontinuing router solicitations on thread interface " PUB_S_SRP, interface->name);
        return;
    }
    if (interface->num_solicits_sent >= 3) {
        INFO("Done sending router solicitations on " PUB_S_SRP ".", interface->name);
        return;
    }
    INFO("sending router solicitation on " PUB_S_SRP , interface->name);
    router_solicit_send(interface);

    interface->num_solicits_sent++;
    ioloop_add_wake_event(interface->router_solicit_wakeup,
                          interface, router_solicit_callback, interface_router_solicit_finalize,
                          RTR_SOLICITATION_INTERVAL * 1000 + srp_random16() % 1024);
}

static void
start_router_solicit(interface_t *interface)
{
    if (interface->router_solicit_wakeup == NULL) {
        interface->router_solicit_wakeup = ioloop_wakeup_create();
        if (interface->router_solicit_wakeup == 0) {
            ERROR("No memory for router solicit wakeup on " PUB_S_SRP ".", interface->name);
            return;
        }
    } else {
        ioloop_cancel_wake_event(interface->router_solicit_wakeup);
    }
    interface->num_solicits_sent = 0;
    ioloop_add_wake_event(interface->router_solicit_wakeup, interface, router_solicit_callback,
                          interface_router_solicit_finalize, 128 + srp_random16() % 896);
}

static void
icmp_interface_subscribe(interface_t *interface, bool added)
{
    struct ipv6_mreq req;
    int rv;

    if (icmp_listener.io_state == NULL) {
        ERROR("Interface subscribe without ICMP listener.");
        return;
    }

    memset(&req, 0, sizeof req);
    if (interface->index == -1) {
        ERROR("icmp_interface_subscribe called before interface index fetch for " PUB_S_SRP, interface->name);
        return;
    }

    req.ipv6mr_multiaddr = in6addr_linklocal_allrouters;
    req.ipv6mr_interface = interface->index;
    rv = setsockopt(icmp_listener.io_state->fd, IPPROTO_IPV6, added ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &req,
                    sizeof req);
    if (rv < 0) {
        ERROR("Unable to " PUB_S_SRP " all-routers multicast group on " PUB_S_SRP ": " PUB_S_SRP,
              added ? "join" : "leave", interface->name, strerror(errno));
        return;
    } else {
        INFO("icmp_interface_subscribe: " PUB_S_SRP "subscribed on interface " PUB_S_SRP, added ? "" : "un",
             interface->name);
    }
}

static interface_t *
find_interface(const char *name, int ifindex)
{
    interface_t **p_interface, *interface = NULL;

    for (p_interface = &interfaces; *p_interface; p_interface = &(*p_interface)->next) {
        interface = *p_interface;
        if (!strcmp(name, interface->name)) {
            if (ifindex != -1 && interface->index != ifindex) {
                INFO("interface name " PUB_S_SRP " index changed from %d to %d", name, interface->index, ifindex);
                interface->index = ifindex;
            }
            break;
        }
    }

    // If it's a new interface, make a structure.
    // We could do a callback, but don't have a use case
    if (*p_interface == NULL) {
        interface = interface_create(name, ifindex);
        *p_interface = interface;
    }
    return interface;
}

NW_EXPORT_PROJECT NW_RETURNS_RETAINED nw_path_evaluator_t
nw_path_create_evaluator_for_listener(nw_parameters_t parameters,
                                      int *out_error);

static void
interface_shutdown(interface_t *interface)
{
    icmp_message_t *router, *next;
    INFO("Interface " PUB_S_SRP " went away.", interface->name);
    if (interface->beacon_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->beacon_wakeup);
    }
    if (interface->post_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->post_solicit_wakeup);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->router_solicit_wakeup);
    }
    if (interface->deconfigure_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->deconfigure_wakeup);
    }
    if (interface->vicarious_discovery_complete != NULL) {
        ioloop_cancel_wake_event(interface->vicarious_discovery_complete);
    }
    for (router = interface->routers; router; router = next) {
        next = router->next;
        icmp_message_free(router);
    }
    interface->routers = NULL;
    if (interface->ip_configuration_service != NULL) {
        CFRelease(interface->ip_configuration_service);
        interface->ip_configuration_service = NULL;
    }
    interface->last_beacon = interface->next_beacon = 0;
    interface->deprecate_deadline = 0;
    interface->preferred_lifetime = interface->valid_lifetime = 0;
    interface->num_solicits_sent = 0;
    interface->inactive = true;
    interface->ineligible = true;
    interface->advertise_ipv6_prefix = false;
    interface->have_link_layer_address = false;
    interface->on_link_prefix_configured = false;
    interface->sent_first_beacon = false;
    interface->num_beacons_sent = 0;
    interface->router_discovery_complete = false;
    interface->router_discovery_in_progress = false;
    interface->vicarious_router_discovery_in_progress = false;
    interface->link = NULL;
}

static void
interface_prefix_evaluate(interface_t *interface)
{
    char hexbuf[60];

    // We are assuming here that the network signature can't change without us seeing a state transition.
    // Cases where this assumption could be violated include unplugging a WiFi base station configured as
    // a bridge from one ethernet network and plugging it into a different one.  We could trigger a
    // re-evaluation when an IPv4 address on an interface changes, and also when there had been a prefix
    // advertised and no longer is.
    get_network_signature(interface);

    // This should only happen if we're really low on memory.
    if (interface->link == NULL) {
        INFO("interface_prefix_evaluate: newly active interface " PUB_S_SRP " has no link.", interface->name);
        return;
    } else {
        if (interface->link->primary != NULL &&
            (interface->link->primary->inactive || interface->link->primary->ineligible))
        {
            INFO("Removing primary interface " PUB_S_SRP " from link because it's inactive or ineligible.",
                 interface->link->primary->name);
            interface->link->primary = NULL;
        }

        if (interface->link->primary == NULL) {
            // Make this interface primary for the link.
            interface->link->primary = interface;

            // Set up the interface prefix using the prefix number for the link.
            interface->ipv6_prefix = ula_prefix;
            interface->ipv6_prefix.s6_addr[6] = interface->link->prefix_number >> 8;
            interface->ipv6_prefix.s6_addr[7] = interface->link->prefix_number & 255;

            dump_network_signature(hexbuf, sizeof(hexbuf), interface->link->signature,
                                   interface->link->signature_length);
            SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, ipv6_prefix_buf);
            INFO("Interface " PUB_S_SRP " is now primary for network " PRI_S_SRP " with prefix "
                 PRI_SEGMENTED_IPv6_ADDR_SRP, interface->name, hexbuf,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, ipv6_prefix_buf));
        } else {
            if (interface->link->primary != interface) {
                INFO("interface_prefix_evaluate: not setting up " PUB_S_SRP " because interface " PUB_S_SRP
                     " is primary for the link.", interface->name, interface->link->primary->name);
            }
        }
    }
}

static void
interface_active_state_evaluate(interface_t *interface, bool active_known, bool active)
{
    INFO("interface_active_state_evaluate: evaluating interface active status - ifname: " PUB_S_SRP
         ", active_known: " PUB_S_SRP ", active: " PUB_S_SRP ", inactive: " PUB_S_SRP,
         interface->name, active_known ? "true" : "false", active ? "true" : "false",
         interface->inactive ? "true" : "false");

    if (active_known && !active) {
        if (!interface->inactive) {
            // If we are the primary interface for the link to which we were connected, see if there's
            // another interface on the link and in any case make this interface not primary for that
             // link.
            if (interface->link != NULL && interface->link->primary == interface) {
                interface_t *scan;
                interface->link->primary = NULL;
                for (scan = interfaces; scan; scan = scan->next) {
                    if (scan != interface && scan->link == interface->link && !scan->inactive && !scan->ineligible) {
                        // Set up the thread-local prefix
                        interface_prefix_evaluate(scan);

                        // We need to reevaluate routing policy on the new primary interface now, because
                        // there may be no new event there to trigger one.
                        routing_policy_evaluate(scan, true);
                        break;
                    }
                }
            }

            // Clean the slate.
            icmp_interface_subscribe(interface, false);
            interface_shutdown(interface);

            // Zero IPv4 addresses.
            interface->num_ipv4_addresses = 0;

            INFO("interface_active_state_evaluate: interface went down - ifname: " PUB_S_SRP, interface->name);
        }
    } else if (active_known) {
        if (interface->inactive) {
            INFO("interface_active_state_evaluate: interface " PUB_S_SRP " showed up.", interface->name);
#ifdef RA_TESTER
            if (!strcmp(interface->name, thread_interface_name) || !strcmp(interface->name, home_interface_name)) {
#endif
                // Zero IPv4 addresses.
                interface->num_ipv4_addresses = 0;

                icmp_interface_subscribe(interface, true);
                interface->inactive = false;

                interface_prefix_evaluate(interface);
#ifndef RA_TESTER
                if (partition_can_provide_routing) {
#endif
                    router_discovery_start(interface);

                    // If we already have a thread prefix, trigger beaconing now.
                    if (published_thread_prefix != NULL || adopted_thread_prefix != NULL) {
                        interface_beacon_schedule(interface, 0);
                    } else {
                        INFO("No prefix on thread network, so not scheduling beacon.");
                    }
#ifndef RA_TESTER
                } else {
                    INFO("Can't provide routing, so not scheduling beacon.");
                }
#endif
#ifdef RA_TESTER
            } else {
                INFO("interface_active_state_evaluate: skipping interface " PUB_S_SRP
                     " because it's not home or thread.", interface->name);
            }
#endif
        }
    }
}

static void
nw_interface_state_changed(nw_interface_t iface, int sock, const char *name, bool ineligible)
{
    int ifindex = nw_interface_get_index(iface);
    bool active = true;
    bool active_known = false;
    interface_t *interface;
    struct ifmediareq media_request;

    interface = find_interface(name, ifindex);
    if (interface == NULL) {
        return;
    }

    if (ineligible) {
        return;
    }
    if (interface->ineligible) {
        INFO("nw_interface_state_changed: interface " PUB_S_SRP " is eligible to be used for routing.", name);
    }
    interface->ineligible = false;

    INFO("nw_interface_state_changed: interface " PUB_S_SRP " index %d: " PUB_S_SRP ", " PUB_S_SRP ")",
         name, ifindex, (active_known ? (active ? "active" : "inactive") : "unknown"),
         ineligible ? "ineligible" : "eligible");

    if (sock > 0) {
        memset(&media_request, 0, sizeof(media_request));
        strlcpy(media_request.ifm_name, name, sizeof(media_request.ifm_name));
        if (ioctl(sock, SIOCGIFXMEDIA, (caddr_t)&media_request) >= 0) {
            if (media_request.ifm_status & IFM_ACTIVE) {
                active = true;
                active_known = true;
            } else {
                active = false;
                active_known = true;
            }
        }
    } else {
        active = false;
        active_known = false;
    }

    if (interface->index == -1) {
        interface->index = ifindex;
    }
    interface_active_state_evaluate(interface, active_known, active);
}

static void
ifaddr_callback(void *__unused context, const char *name, const addr_t *address, const addr_t *mask,
                unsigned flags, enum interface_address_change change)
{
    char addrbuf[INET6_ADDRSTRLEN];
    const uint8_t *addrbytes, *maskbytes, *prefp;
    int preflen, i;
    interface_t *interface;
    bool is_thread_interface = false;

    interface = find_interface(name, -1);
    if (interface == NULL) {
        ERROR("ifaddr_callback: find_interface returned NULL for " PUB_S_SRP, name);
        return;
    }

    if (thread_interface_name != NULL && !strcmp(name, thread_interface_name)) {
        is_thread_interface = true;
    }

    if (address->sa.sa_family == AF_INET) {
        addrbytes = (uint8_t *)&address->sin.sin_addr;
        maskbytes = (uint8_t *)&mask->sin.sin_addr;
        prefp = maskbytes + 3;
        preflen = 32;
        if (change == interface_address_added) {
            // Just got an IPv4 address?
            if (!interface->num_ipv4_addresses) {
                interface_prefix_evaluate(interface);
            }
            interface->num_ipv4_addresses++;
        } else if (change == interface_address_deleted) {
            interface->num_ipv4_addresses--;
            // Just lost our last IPv4 address?
            if (!interface->num_ipv4_addresses) {
                interface_prefix_evaluate(interface);
            }
        }
    } else if (address->sa.sa_family == AF_INET6) {
        addrbytes = (uint8_t *)&address->sin6.sin6_addr;
        maskbytes = (uint8_t *)&mask->sin6.sin6_addr;
        prefp = maskbytes + 15;
        preflen = 128;
    } else if (address->sa.sa_family == AF_LINK) {
        snprintf(addrbuf, sizeof addrbuf, "%02x:%02x:%02x:%02x:%02x:%02x",
                 address->ether_addr.addr[0], address->ether_addr.addr[1],
                 address->ether_addr.addr[2], address->ether_addr.addr[3],
                 address->ether_addr.addr[4], address->ether_addr.addr[5]);
        prefp = (uint8_t *)&addrbuf[0]; maskbytes = prefp + 1; // Skip prefix length calculation
        preflen = 0;
        addrbytes = NULL;
    } else {
        INFO("ifaddr_callback: Unknown address type %d", address->sa.sa_family);
        return;
    }

    if (change != interface_address_unchanged) {
        if (address->sa.sa_family == AF_LINK) {
            if (!interface->ineligible) {
                INFO("ifaddr_callback: interface " PUB_S_SRP PUB_S_SRP " " PUB_S_SRP " " PRI_MAC_ADDR_SRP " flags %x",
                     name, is_thread_interface ? " (thread)" : "",
                     change == interface_address_added ? "added" : "removed",
                     MAC_ADDR_PARAM_SRP(address->ether_addr.addr), flags);
            }
        } else {
            for (; prefp >= maskbytes; prefp--) {
                if (*prefp) {
                    break;
                }
                preflen -= 8;
            }
            for (i = 0; i < 8; i++) {
                if (*prefp & (1<<i)) {
                    break;
                }
                --preflen;
            }
            inet_ntop(address->sa.sa_family, addrbytes, addrbuf, sizeof addrbuf);
            if (!interface->ineligible) {
                if (address->sa.sa_family == AF_INET) {
                    IPv4_ADDR_GEN_SRP(addrbytes, addr_buf);
                    INFO("ifaddr_callback: interface " PUB_S_SRP PUB_S_SRP " " PUB_S_SRP " " PRI_IPv4_ADDR_SRP
                         "/%d flags %x", name, is_thread_interface ? " (thread)" : "",
                         change == interface_address_added ? "added" : "removed",
                         IPv4_ADDR_PARAM_SRP(addrbytes, addr_buf), preflen, flags);
                } else if (address->sa.sa_family == AF_INET6) {
                    SEGMENTED_IPv6_ADDR_GEN_SRP(addrbytes, addr_buf);
                    INFO("ifaddr_callback: interface " PUB_S_SRP PUB_S_SRP " " PUB_S_SRP " " PRI_SEGMENTED_IPv6_ADDR_SRP
                         "/%d flags %x", name, is_thread_interface ? " (thread)" : "",
                         change == interface_address_added ? "added" : "removed",
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(addrbytes, addr_buf), preflen, flags);
                } else {
                    INFO("ifaddr_callback - invalid sa_family: %d", address->sa.sa_family);
                }

                // When new IP address is removed, it is possible that the existing router information, such as
                // PIO and RIO is no longer valid since srp-mdns-proxy is losing its IP address. In order to let it to
                // flush the stale router information as soon as possible, we mark all the router as stale immediately,
                // by setting the router received time to a value which is 601s ago (router will be stale if the router
                // information is received for more than 600s). And then do router discovery for 20s, so we can ensure
                // that all the stale router information will be updated during the discovery, or flushed away. If all
                // routers are flushed, then srp-mdns-proxy will advertise its own prefix and configure the new IPv6
                // address.
                if ((address->sa.sa_family == AF_INET || address->sa.sa_family == AF_INET6) &&
                    change == interface_address_deleted) {
                    INFO("ifaddr_callback: making all routers stale and start router discovery due to removed address");
                    adjust_router_received_time(interface, ioloop_timenow(),
                                                -(MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE + MSEC_PER_SEC));
                    routing_policy_evaluate(interface, false);
                }
            }
        }
    }

    // Not a broadcast interface
    if (flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) {
        // Not the thread interface
        if (!is_thread_interface) {
            return;
        }
    }

    // 169.254.*
    if (address->sa.sa_family == AF_INET && IN_LINKLOCAL(address->sin.sin_addr.s_addr)) {
        return;
    }

    if (interface->index == -1) {
        interface->index = address->ether_addr.index;
    }
    interface->is_thread = is_thread_interface;

#if TARGET_OS_TV && !defined(RA_TESTER)
    if (is_thread_interface && address->sa.sa_family == AF_INET6) {
        partition_utun0_address_changed(&address->sin6.sin6_addr, change);
    }
#endif

    if (address->sa.sa_family == AF_INET) {
    } else if (address->sa.sa_family == AF_INET6) {
        if (IN6_IS_ADDR_LINKLOCAL(&address->sin6.sin6_addr)) {
            interface->link_local = address->sin6.sin6_addr;
        }
    } else if (address->sa.sa_family == AF_LINK) {
        if (address->ether_addr.len == 6) {
            memcpy(interface->link_layer, address->ether_addr.addr, 6);
            interface->have_link_layer_address = true;
        }
    }
}

static void
refresh_interface_list(void)
{
    ioloop_map_interface_addresses(NULL, ifaddr_callback);
}

static void
nw_path_event(nw_path_t path)
{
    int sock = socket(PF_INET6, SOCK_DGRAM, 0);
    INFO("nw_path_event");
    nw_path_enumerate_interfaces(path, ^bool (nw_interface_t NONNULL iface) {
            const char *name = nw_interface_get_name(iface);
            CFStringRef sc_name = CFStringCreateWithCStringNoCopy(NULL, name, kCFStringEncodingUTF8, kCFAllocatorNull);
            if (sc_name != NULL) {
                SCNetworkInterfaceRef _SCNetworkInterfaceCreateWithBSDName(CFAllocatorRef allocator,
                                                                           CFStringRef bsdName, UInt32 flags);
                SCNetworkInterfaceRef sc_interface = _SCNetworkInterfaceCreateWithBSDName(NULL, sc_name, 0);
                CFRelease(sc_name);
                if (sc_interface == NULL) {
                    ERROR("SCNetworkInterfaceCreateWithBSDName failed");
                    nw_interface_state_changed(iface, sock, name, true);
                    goto out;
                } else {
                    CFStringRef sc_type = SCNetworkInterfaceGetInterfaceType(sc_interface);
                    if (sc_type == NULL) {
                        ERROR("Unable to get interface type on " PUB_S_SRP, name);
                        CFRelease(sc_interface);
                        goto out;
                    }
                    CFStringRef _SCNetworkInterfaceGetIOPath(SCNetworkInterfaceRef interface);
                    CFStringRef io_path = _SCNetworkInterfaceGetIOPath(sc_interface);
                    bool is_usb = false;
                    if (io_path == NULL) {
                        if (strncmp(name, "utun", 4)) {
                            ERROR("Unable to get interface I/O path.");
                        }
                    } else {
#ifdef DEBUG_VERBOSE
                        char pathname[1024];
                        CFStringGetCString(io_path, pathname, sizeof(pathname), kCFStringEncodingUTF8);
                        INFO("Interface " PUB_S_SRP " I/O Path: " PRI_S_SRP, name, pathname);
#endif
                        CFRange match = CFStringFind(io_path, CFSTR("AppleUSBDeviceNCMData"), 0);
                        if (match.location != kCFNotFound) {
                            is_usb = true;
                        }
                    }
                    if (CFEqual(sc_type, kSCNetworkInterfaceTypeIEEE80211) ||
                        (CFEqual(sc_type, kSCNetworkInterfaceTypeEthernet) && !is_usb))
                    {
                        nw_interface_state_changed(iface, sock, name, false);
                    } else {
                        nw_interface_state_changed(iface, sock, name, true);
                    }
                    CFRelease(sc_interface);
                out:
                    ;
                }
            } else {
                nw_interface_state_changed(iface, sock, name, true);
            }
            return true;
        });
    close(sock);

#if TARGET_OS_TV && !defined(RA_TESTER)
    // If we do not have an active interface, we can't be advertising SRP service.
    interface_t *interface;
    bool active = false;
    for (interface = interfaces; interface; interface = interface->next) {
        if (!interface->ineligible && !interface->inactive) {
            active = true;
        }
    }
    if (active && !have_non_thread_interface) {
        INFO("nw_path_event: we have an active interface");
        have_non_thread_interface = true;
        partition_can_advertise_service = true;
    } else if (!active && have_non_thread_interface) {
        INFO("nw_path_event: we no longer have an active interface");
        have_non_thread_interface = false;
        // Stop advertising the service, if we are doing so.
        partition_discontinue_srp_service();
    }
#endif // TARGET_OS_TV && !defined(RA_TESTER)

    refresh_interface_list();
}

#if TARGET_OS_TV && !defined(RA_TESTER)
#ifdef GET_TUNNEL_NAME_WITH_WPANCTL
static void
thread_interface_output(io_t *io, void *__unused context)
{
    char inbuf[512];
    ssize_t rv;
    char *s, *t;

    // We are assuming that wpanctl will never do partial-line writes.
    rv = read(io->fd, inbuf, sizeof(inbuf) - 1);
    if (rv < 0) {
        ERROR("thread_interface_output: " PUB_S_SRP, strerror(errno));
    }
    INFO("read %" PRIs64 " bytes from wpanctl output", rv);
    if (rv <= 0) {
        INFO("Done with thread interface output.");
        ioloop_close(io);
    } else {
        if (inbuf[rv - 1] == '\n') {
            inbuf[rv - 1] = 0;
            s = strchr(inbuf, '>');
            if (s == NULL) {
            bad:
                ERROR("Bad wpanctl output: " PUB_S_SRP, inbuf);
                return;
            }
            s = strchr(s, '(');
            if (s == NULL) {
                goto bad;
            }
            // We don't expect the end of string here.
            if (*++s == '\0') {
                goto bad;
            }
            t = strchr(s, ')');
            if (s == t || t == NULL) {
                goto bad;
            }
            *t = '\0';
            if (num_thread_interfaces != 0) {
                INFO("Already have a thread interface.");
            } else {
                num_thread_interfaces = 1;
                thread_interface_name = strdup(s);
                if (thread_interface_name == NULL) {
                    ERROR("No memory to save thread interface name " PUB_S_SRP, s);
                    return;
                }
                INFO("Thread interface at " PUB_S_SRP, thread_interface_name);
                partition_got_tunnel_name();
            }
        } else {
            goto bad;
        }
    }
}

static void
thread_interface_done(void *__unused context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_interface_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_interface_done: %d.", status);
    }
    ioloop_subproc_release(thread_interface_enumerator_process);
}
#endif // GET_TUNNEL_NAME_WITH_WPANCTL

static void
cti_get_tunnel_name_callback(void *__unused context, const char *name, cti_status_t status)
{
    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_tunnel_name_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    INFO("cti_get_tunnel_name_callback: " PUB_S_SRP " %d", name != NULL ? name : "<null>", status);
    if (status != kCTIStatus_NoError) {
        return;
    }
    num_thread_interfaces = 1;
    if (thread_interface_name != NULL) {
        free(thread_interface_name);
    }
    thread_interface_name = strdup(name);
    if (thread_interface_name == NULL) {
        ERROR("No memory to save thread interface name " PUB_S_SRP, name);
        return;
    }
    INFO("Thread interface at " PUB_S_SRP, thread_interface_name);
    partition_got_tunnel_name();
}

static void
cti_get_role_callback(void *__unused context, cti_network_node_type_t role, cti_status_t status)
{
    bool am_thread_router = false;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_role_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    partition_last_role_change = ioloop_timenow();

    if (status == kCTIStatus_NoError) {
        if (role == kCTI_NetworkNodeType_Router || role == kCTI_NetworkNodeType_Leader) {
            am_thread_router = true;
        }

        INFO("role is: " PUB_S_SRP " (%d)\n ", am_thread_router ? "router" : "not router", role);
    } else {
        ERROR("cti_get_role_callback: nonzero status %d", status);
    }

    // Our thread role doesn't actually matter, but it's useful to report it in the logs.
}

static void
cti_get_state_callback(void *__unused context, cti_network_state_t state, cti_status_t status)
{
    bool associated = false;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_state_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    partition_last_state_change = ioloop_timenow();

    if (status == kCTIStatus_NoError) {
        if ((state == kCTI_NCPState_Associated)     || (state == kCTI_NCPState_Isolated) ||
            (state == kCTI_NCPState_NetWake_Asleep) || (state == kCTI_NCPState_NetWake_Waking))
        {
            associated = true;
        }

        INFO("state is: " PUB_S_SRP " (%d)\n ", associated ? "associated" : "not associated", state);
    } else {
        ERROR("cti_get_state_callback: nonzero status %d", status);
    }

    if (current_thread_state != state) {
        if (associated) {
            current_thread_state = state;
            partition_maybe_enable_services(); // but probably not
        } else {
            current_thread_state = state;
            partition_disable_service();
        }
    }
}

static void
cti_get_partition_id_callback(void *__unused context, int32_t partition_id, cti_status_t status)
{
    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_partition_id_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    if (status == kCTIStatus_NoError) {
        INFO("Partition ID changed to %" PRIu32, partition_id);
        thread_partition_id[0] = (uint8_t)((partition_id >> 24) & 255);
        thread_partition_id[1] = (uint8_t)((partition_id >> 16) & 255);
        thread_partition_id[2] = (uint8_t)((partition_id >> 8) & 255);
        thread_partition_id[3] = (uint8_t)(partition_id & 255);

        partition_id_changed();
    } else {
        ERROR("cti_get_state_callback: nonzero status %d", status);
    }
}

static void
thread_service_note(thread_service_t *service, const char *event_description)
{
    uint16_t port;

    port = (service->port[0] << 8) | service->port[1];
    SEGMENTED_IPv6_ADDR_GEN_SRP(service->address, service_add_buf);
    INFO("SRP service " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d " PUB_S_SRP,
         SEGMENTED_IPv6_ADDR_PARAM_SRP(service->address, service_add_buf),
         port, event_description);
}

static void
thread_pref_id_note(thread_pref_id_t *pref_id, const char *event_description)
{
    struct in6_addr addr;

    addr.s6_addr[0] = 0xfd;
    memcpy(&addr.s6_addr[1], pref_id->prefix, 5);
    memset(&addr.s6_addr[6], 0, 10);
    SEGMENTED_IPv6_ADDR_GEN_SRP(addr.s6_addr, addr_buf);
    INFO("pref:id " PRI_SEGMENTED_IPv6_ADDR_SRP ":%02x%02x%02x%02x " PUB_S_SRP,
         SEGMENTED_IPv6_ADDR_PARAM_SRP(addr.s6_addr, addr_buf),
         pref_id->partition_id[0], pref_id->partition_id[1], pref_id->partition_id[2], pref_id->partition_id[3],
         event_description);
}

typedef struct state_debug_accumulator {
    char change[20]; // " +stable +user +ncp"
    char *p_change;
    size_t left;
    bool changed;
} accumulator_t;

static void
accumulator_init(accumulator_t *accumulator)
{
    memset(accumulator, 0, sizeof(*accumulator));
    accumulator->p_change = accumulator->change;
    accumulator->left = sizeof(accumulator->change);
}

static void
accumulate(accumulator_t *accumulator, bool previous, bool cur, const char *name)
{
    size_t len;
    if (previous != cur) {
        snprintf(accumulator->p_change, accumulator->left, "%s%s%s",
                 accumulator->p_change == accumulator->change ? "" : " ", cur ? "+" : "-", name);
        len = strlen(accumulator->p_change);
        accumulator->p_change += len;
        accumulator->left -= len;
        accumulator->changed = true;
    }
}

static void
cti_service_list_callback(void *__unused context, cti_service_vec_t *services, cti_status_t status)
{
    size_t i;
    thread_service_t **pservice = &thread_services, *service = NULL;
    thread_pref_id_t **ppref_id = &thread_pref_ids, *pref_id = NULL;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_service_list_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    if (status != kCTIStatus_NoError) {
        ERROR("cti_get_service_list_callback: %d", status);
    } else {
        // Delete any SRP services that are not in the list provided by Thread.
        while (*pservice != NULL) {
            service = *pservice;
            for (i = 0; i < services->num; i++) {
                cti_service_t *cti_service = services->services[i];
                // Is this a valid SRP service?
                if (IS_SRP_SERVICE(cti_service)) {
                    // Is this service still present?
                    if (!memcmp(&service->address, cti_service->server, 16) &&
                        !memcmp(&service->port, &cti_service->server[16], 2)) {
                        break;
                    }
                }
            }
            if (i == services->num) {
                thread_service_note(service, "went away");
                *pservice = service->next;
                RELEASE_HERE(service, thread_service_finalize);
            } else {
                // We'll re-initialize these flags from the service list when we check for duplicates.
                service->previous_user = service->user;
                service->user = false;
                service->previous_stable = service->stable;
                service->stable = false;
                service->previous_ncp = service->ncp;
                service->ncp = false;
                pservice = &service->next;
            }
        }
        // On exit, pservice is pointing to the end-of-list pointer.

        // Delete any pref_id services that are not in the list provided by Thread.
        while (*ppref_id != NULL) {
            pref_id = *ppref_id;
            for (i = 0; i < services->num; i++) {
                cti_service_t *cti_service = services->services[i];
                // Is this an SRP service?
                if (IS_PREF_ID_SERVICE(cti_service)) {
                    // Is this service still present?
                    if (!memcmp(&pref_id->partition_id, cti_service->server, 4) &&
                        !memcmp(pref_id->prefix, &cti_service->server[4], 5))
                    {
                        break;
                    }
                }
            }
            if (i == services->num) {
                thread_pref_id_note(pref_id, "went away");
                *ppref_id = pref_id->next;
                RELEASE_HERE(pref_id, thread_pref_id_finalize);
            } else {
                // We'll re-initialize these flags from the service list when we check for duplicates.
                pref_id->previous_user = pref_id->user;
                pref_id->user = false;
                pref_id->previous_stable = pref_id->stable;
                pref_id->stable = false;
                pref_id->previous_ncp = pref_id->ncp;
                pref_id->ncp = false;
                ppref_id = &pref_id->next;
            }
        }
        // On exit, pservice is pointing to the end-of-list pointer.

        // Add any services that are not present.
        for (i = 0; i < services->num; i++) {
            cti_service_t *cti_service = services->services[i];
            if (IS_SRP_SERVICE(cti_service)) {
                for (service = thread_services; service != NULL; service = service->next) {
                    if (!memcmp(&service->address, cti_service->server, 16) &&
                        !memcmp(&service->port, &cti_service->server[16], 2)) {
                        break;
                    }
                }
                if (service == NULL) {
                    service = thread_service_create(cti_service->server, &cti_service->server[16]);
                    if (service == NULL) {
                        ERROR("cti_service_list_callback: no memory for service.");
                    } else {
                        thread_service_note(service, "showed up");
                        *pservice = service;
                        pservice = &service->next;
                    }
                }
                // Also, since we're combing the list, update ncp, user and stable flags.   Note that a service can
                // appear more than once in the thread service list.
                if (service != NULL) {
                    if (cti_service->flags & kCTIFlag_NCP) {
                        service->ncp = true;
                    } else {
                        service->user = true;
                    }
                    if (cti_service->flags & kCTIFlag_Stable) {
                        service->stable = true;
                    }
                }
            } else if (IS_PREF_ID_SERVICE(cti_service)) {
                for (pref_id = thread_pref_ids; pref_id != NULL; pref_id = pref_id->next) {
                    if (!memcmp(&pref_id->partition_id, cti_service->server, 4) &&
                        !memcmp(pref_id->prefix, &cti_service->server[4], 5))
                    {
                        break;
                    }
                }
                if (pref_id == NULL) {
                    pref_id = thread_pref_id_create(cti_service->server, &cti_service->server[4]);
                    if (pref_id == NULL) {
                        ERROR("cti_service_list_callback: no memory for pref_id.");
                    } else {
                        thread_pref_id_note(pref_id, "showed up");
                        *ppref_id = pref_id;
                        ppref_id = &pref_id->next;
                    }
                }
                // Also, since we're combing the list, update ncp, user and stable flags.   Note that a pref_id can
                // appear more than once in the thread pref_id list.
                if (pref_id != NULL) {
                    if (!pref_id->ncp && (cti_service->flags & kCTIFlag_NCP)) {
                        pref_id->ncp = true;
                    } else if (!pref_id->user && !(cti_service->flags & kCTIFlag_NCP)) {
                        pref_id->user = true;
                    }
                    if (cti_service->flags & kCTIFlag_Stable) {
                        pref_id->stable = true;
                    }
                }
            }
        }

        accumulator_t accumulator;
        for (service = thread_services; service != NULL; service = service->next) {
            accumulator_init(&accumulator);
            accumulate(&accumulator, service->previous_ncp, service->ncp, "ncp");
            accumulate(&accumulator, service->previous_stable, service->ncp, "stable");
            accumulate(&accumulator, service->previous_user, service->user, "user");
            if (accumulator.changed) {
                thread_service_note(service, accumulator.change);
            }
        }
        for (pref_id = thread_pref_ids; pref_id != NULL; pref_id = pref_id->next) {
            accumulator_init(&accumulator);
            accumulate(&accumulator, pref_id->previous_ncp, pref_id->ncp, "ncp");
            accumulate(&accumulator, pref_id->previous_stable, pref_id->ncp, "stable");
            accumulate(&accumulator, pref_id->previous_user, pref_id->user, "user");
            if (accumulator.changed) {
                thread_pref_id_note(pref_id, accumulator.change);
            }
        }

        // At this point the thread prefix list contains the same information as what we just received.
        // Trigger a "prefix set changed" event.
        partition_service_set_changed();
    }
}

static void
cti_prefix_list_callback(void *__unused context, cti_prefix_vec_t *prefixes, cti_status_t status)
{
    size_t i;
    thread_prefix_t **ppref = &thread_prefixes, *prefix = NULL;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_prefix_list_callback: disconnected");
        adv_xpc_disconnect();
        return;
    }

    if (status != kCTIStatus_NoError) {
        ERROR("cti_get_prefix_list_callback: %d", status);
    } else {
        // Delete any prefixes that are not in the list provided by Thread.
        while (*ppref != NULL) {
            prefix = *ppref;
            for (i = 0; i < prefixes->num; i++) {
                cti_prefix_t *cti_prefix = prefixes->prefixes[i];
                // Is this prefix still present?
                if (!memcmp(&prefix->prefix, &cti_prefix->prefix, 8)) {
                    break;
                }
            }
            if (i == prefixes->num) {
                *ppref = prefix->next;
                SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
                INFO("cti_prefix_list_callback: prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " went away",
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
                RELEASE_HERE(prefix, thread_prefix_finalize);
            } else {
                // We'll re-initialize these flags from the prefix list when we check for duplicates.
                prefix->user = false;
                prefix->stable = false;
                prefix->ncp = false;
                ppref = &prefix->next;
            }
        }
        // On exit, ppref is pointing to the end-of-list pointer.

        // Add any prefixes that are not present.
        for (i = 0; i < prefixes->num; i++) {
            cti_prefix_t *cti_prefix = prefixes->prefixes[i];
            for (prefix = thread_prefixes; prefix != NULL; prefix = prefix->next) {
                if (!memcmp(&prefix->prefix, &cti_prefix->prefix, 16)) {
                    break;
                }
            }
            if (prefix == NULL) {
                prefix = thread_prefix_create(&cti_prefix->prefix, cti_prefix->prefix_length);
                if (prefix == NULL) {
                    ERROR("cti_prefix_list_callback: no memory for prefix.");
                } else {
                    SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
                    INFO("cti_prefix_list_callback: prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " showed up",
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
                    *ppref = prefix;
                    ppref = &prefix->next;
                }
            }
            // Also, since we're combing the list, update ncp, user and stable flags.   Note that a prefix can
            // appear more than once in the thread prefix list.
            if (prefix != NULL) {
                if (cti_prefix->flags & kCTIFlag_NCP) {
                    prefix->ncp = true;
                } else {
                    prefix->user = true;
                }
                if (cti_prefix->flags & kCTIFlag_Stable) {
                    prefix->stable = true;
                }
            }
        }

        // At this point the thread prefix list contains the same information as what we just received.
        // Trigger a "prefix set changed" event.
        partition_prefix_set_changed();
    }
}

static void
get_thread_interface_list(void)
{
#ifdef GET_TUNNEL_NAME_WITH_WPANCTL
    char *args[] = { "list" };
    INFO("/usr/local/bin/wpanctl list");
    thread_interface_enumerator_process = ioloop_subproc("/usr/local/bin/wpanctl", args, 1,
                                                         thread_interface_done,
                                                         thread_interface_output, NULL);
    if (thread_interface_enumerator_process == NULL) {
        ERROR("Unable to enumerate thread interfaces.");
    }
#endif

}
#endif // TARGET_OS_TV && !RA_TESTER

#ifdef TCPDUMP_LOGGER
static void
tcpdump_output(io_t *io, void *__unused context)
{
    static char inbuf[1024];
    static int offset;
    ssize_t rv;
    char *s;

    if (offset + 1 != sizeof(inbuf)) {
        rv = read(io->fd, &inbuf[offset], sizeof(inbuf) - 1 - offset);
        if (rv < 0) {
            ERROR("tcpdump_output: " PUB_S_SRP, strerror(errno));
            return;
        }
        if (rv <= 0) {
            INFO("Done with thread interface output.");
            ioloop_close(io);
            return;
        }
        offset += rv;
    }
    inbuf[offset] = 0;
    if (offset + 1 == sizeof(inbuf)) {
        s = &inbuf[offset];
    } else {
        s = strchr(inbuf, '\n');
        if (s == NULL) {
            return;
        }
        *s = 0;
    }
    INFO(PUB_S_SRP, inbuf);
    if (s != &inbuf[offset]) {
        memmove(inbuf, s, &inbuf[offset] - s);
    }
    offset = 0;
}

static void
tcpdump_done(void *__unused context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("tcpdump_done: " PUB_S_SRP, error);
    } else {
        INFO("tcpdump_done: %d.", status);
    }
    ioloop_subproc_release(tcpdump_logger_process);
}

static void
start_tcpdump_logger(void)
{
    char *args[] = { "-vv", "-s", "1500", "-n", "-e", "-i", "utun0", "-l", "udp", "port", "53" };
    INFO("/usr/sbin/tcpdump -vv -s 1500 -n -e -i utun0 udp port 53");
    tcpdump_logger_process = ioloop_subproc("/usr/sbin/tcpdump", args, 11, tcpdump_done,
                                            tcpdump_output, NULL);
    if (tcpdump_logger_process == NULL) {
        ERROR("Unable to start tcpdump logger.");
    }
}
#endif // TCPDUMP_LOGGER

void
thread_network_startup(void)
{
    INFO("thread_network_startup: Thread network started.");

#ifdef MONTIOR_ROUTING_SOCKET
    start_route_listener();
#else
    int error = 0;
    nw_parameters_t params = nw_parameters_create();
    if (path_evaluator != NULL) {
        nw_path_evaluator_cancel(path_evaluator);
        nw_release(path_evaluator);
    }
    path_evaluator = nw_path_create_evaluator_for_listener(params, &error);
    nw_release(params);
    if (path_evaluator == NULL || error != 0) {
        ERROR("thread_network_startup: Unable to create network path evaluator.");
        return;
    }
    nw_path_evaluator_set_update_handler(path_evaluator, dispatch_get_main_queue(), ^(nw_path_t path) {
            nw_path_event(path);
        });
    nw_path_t initial = nw_path_evaluator_copy_path(path_evaluator);
    nw_path_event(initial);
    nw_release(initial);
#endif // MONITOR_ROUTING_SOCKET
#if TARGET_OS_TV && !defined(RA_TESTER)
    get_thread_interface_list();
#endif
    set_thread_forwarding();
#ifdef TCPDUMP_LOGGER
    start_tcpdump_logger();
#endif

#ifndef RA_TESTER
    cti_get_state(&thread_state_context, NULL, cti_get_state_callback, dispatch_get_main_queue());
    cti_get_network_node_type(&thread_role_context, NULL, cti_get_role_callback, dispatch_get_main_queue());
    cti_get_service_list(&thread_service_context, NULL, cti_service_list_callback, dispatch_get_main_queue());
    cti_get_prefix_list(&thread_prefix_context, NULL, cti_prefix_list_callback, dispatch_get_main_queue());
    cti_get_tunnel_name(NULL, cti_get_tunnel_name_callback, dispatch_get_main_queue());
    cti_get_partition_id(&thread_partition_id_context, NULL, cti_get_partition_id_callback, dispatch_get_main_queue());
#endif
}

void
thread_network_shutdown(void)
{
    interface_t *interface;
    network_link_t *link;
#ifndef RA_TESTER
    if (thread_state_context) {
        INFO("thread_network_shutdown: discontinuing state events");
        cti_events_discontinue(thread_state_context);
    }
    if (thread_role_context) {
        INFO("thread_network_shutdown: discontinuing role events");
        cti_events_discontinue(thread_role_context);
    }
    if (thread_service_context) {
        INFO("thread_network_shutdown: discontinuing service events");
        cti_events_discontinue(thread_service_context);
    }
    if (thread_prefix_context) {
        INFO("thread_network_shutdown: discontinuing prefix events");
        cti_events_discontinue(thread_prefix_context);
    }
    if (thread_partition_id_context) {
        INFO("thread_network_shutdown: discontinuing partition ID events");
        cti_events_discontinue(thread_partition_id_context);
    }
#endif
    if (path_evaluator != NULL) {
        nw_path_evaluator_cancel(path_evaluator);
        nw_release(path_evaluator);
        path_evaluator = NULL;
    }
    INFO("thread_network_shutdown: Thread network shutdown.");
    // Stop all activity on interfaces.
    for (interface = interfaces; interface; interface = interface->next) {
        interface_shutdown(interface);
    }
    for (link = network_links; link; link = link->next) {
        link->primary = NULL;
    }

#ifndef RA_TESTER
    partition_state_reset();
#endif
}

#ifndef RA_TESTER
static void
partition_state_reset(void)
{
    thread_prefix_t *prefix, *next_prefix = NULL;
    thread_service_t *service, *next_service = NULL;
    thread_pref_id_t *pref_id, *next_pref_id = NULL;

    // Remove any saved state from the thread network.
    for (prefix = thread_prefixes; prefix != NULL; prefix = next_prefix) {
        next_prefix = prefix->next;
        RELEASE_HERE(prefix, thread_prefix_finalize);
    }
    thread_prefixes = NULL;

    if (published_thread_prefix != NULL) {
        RELEASE_HERE(published_thread_prefix, thread_prefix_finalize);
        published_thread_prefix = NULL;
    }
    if (adopted_thread_prefix != NULL) {
        RELEASE_HERE(adopted_thread_prefix, thread_prefix_finalize);
        adopted_thread_prefix = NULL;
    }

    for (service = thread_services; service != NULL; service = next_service) {
        next_service = service->next;
        RELEASE_HERE(service, thread_service_finalize);
    }
    thread_services = NULL;

    for (pref_id = thread_pref_ids; pref_id != NULL; pref_id = next_pref_id) {
        next_pref_id = pref_id->next;
        RELEASE_HERE(pref_id, thread_pref_id_finalize);
    }
    thread_pref_ids = NULL;

    current_thread_state = kCTI_NCPState_Uninitialized;
    current_thread_role = kCTI_NetworkNodeType_Unknown;

    partition_last_prefix_set_change = 0;
    partition_last_pref_id_set_change = 0;
    partition_last_partition_id_change = 0;
    partition_last_role_change = 0;
    partition_last_state_change = 0;
    partition_settle_start = 0;
    partition_service_last_add_time = 0;
    partition_id_is_known = false;
    partition_have_prefix_list = false;
    partition_have_pref_id_list = false;
    partition_tunnel_name_is_known = false;
    partition_can_advertise_service = false;
    partition_can_provide_routing = false;
    partition_may_offer_service = false;
    partition_settle_satisfied = true;

    if (partition_settle_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_settle_wakeup);
    }

    if (partition_post_partition_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_post_partition_wakeup);
    }

    if (partition_pref_id_wait_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_pref_id_wait_wakeup);
    }

    if (partition_service_add_pending_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_service_add_pending_wakeup);
    }
}

static int __unused
prefcmp(uint8_t *a, uint8_t *b, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void
partition_prefix_remove_callback(void *__unused context, cti_status_t status)
{
    if (status != kCTIStatus_NoError) {
        ERROR("partition_unpublish_my_prefix: failed to unpublish my prefix: %d.", status);
    } else {
        INFO("partition_unpublish_my_prefix: done unpublishing my prefix.");
    }
}

static void
partition_stop_advertising_pref_id_done(void *__unused context, cti_status_t status)
{
    INFO("partition_stop_advertising_pref_id_done: %d", status);
}

void
partition_stop_advertising_pref_id(void)
{
    // This should remove any copy of the service that this BR is advertising.
    uint8_t service_info[] = { 0, 0, 0, 1 };
    int status;

    INFO("partition_stop_advertising_pref_id: %" PRIu64 "/%02x" , THREAD_ENTERPRISE_NUMBER, service_info[0]);
    service_info[0] = THREAD_PREF_ID_OPTION & 255;
    status = cti_remove_service(NULL, partition_stop_advertising_pref_id_done,
                                    dispatch_get_main_queue(),
                                    THREAD_ENTERPRISE_NUMBER, service_info, 1);
    if (status != kCTIStatus_NoError) {
        INFO("partition_stop_advertising_pref_id: status %d", status);
    }
}

static void
partition_advertise_pref_id_done(void *__unused context, cti_status_t status)
{
    INFO("partition_advertise_pref_id_done: %d", status);
}

static void
partition_advertise_pref_id(uint8_t *prefix)
{
    // This should remove any copy of the service that this BR is advertising.
    uint8_t service_info[] = { 0, 0, 0, 1 };
    uint8_t pref_id[9];
    memcpy(pref_id, thread_partition_id, 4);
    memcpy(&pref_id[4], prefix, 5);
    uint8_t full_prefix[6] = {0xfd, prefix[0], prefix[1], prefix[2], prefix[3], prefix[4]};

    service_info[0] = THREAD_PREF_ID_OPTION & 255;
    IPv6_PREFIX_GEN_SRP(full_prefix, sizeof(full_prefix), prefix_buf);
    INFO("partition_advertise_pref_id: %" PRIu64 "/%02x/%02x%02x%02x%02x" PRI_IPv6_PREFIX_SRP,
         THREAD_ENTERPRISE_NUMBER, service_info[0], pref_id[0], pref_id[1], pref_id[2], pref_id[3],
         IPv6_PREFIX_PARAM_SRP(prefix_buf));
    int status = cti_add_service(NULL, partition_advertise_pref_id_done, dispatch_get_main_queue(),
                                 THREAD_ENTERPRISE_NUMBER, service_info, 1, pref_id, sizeof pref_id);
    if (status != kCTIStatus_NoError) {
        INFO("partition_advertise_pref_id: status %d", status);
    }
}

static void
partition_id_update(void)
{
    thread_prefix_t *advertised_prefix = get_advertised_thread_prefix();
    if (advertised_prefix == NULL) {
        INFO("partition_id_update: no advertised prefix, not advertising pref:id.");
    } else if (advertised_prefix == adopted_thread_prefix) {
        INFO("partition_id_update: not advertising pref:id for adopted prefix.");
        partition_stop_advertising_pref_id();
    } else {
        partition_advertise_pref_id(((uint8_t *)&advertised_prefix->prefix) + 1);
        INFO("partition_id_update: advertised pref:id for our prefix.");
    }
}

static void
partition_unpublish_prefix(thread_prefix_t *prefix)
{
    cti_status_t status = cti_remove_prefix(NULL, partition_prefix_remove_callback, dispatch_get_main_queue(),
                                            &prefix->prefix, 64);
    if (status != kCTIStatus_NoError) {
        ERROR("partition_unpublish_prefix: prefix remove failed: %d.", status);
    }
    partition_stop_advertising_pref_id();
}

static void
partition_refresh_and_re_evaluate(void)
{
    refresh_interface_list();
    routing_policy_evaluate_all_interfaces(true);
}

typedef struct unadvertised_prefix_remove_state  unadvertised_prefix_remove_state_t;
struct unadvertised_prefix_remove_state {
    int num_unadvertised_prefixes;
    int num_removals;
    void (*continuation)(void);
};

static void
partition_remove_all_prefixes_done(void *context, cti_status_t status)
{
    unadvertised_prefix_remove_state_t *state = context;
    state->num_removals++;
    if (state->num_removals == state->num_unadvertised_prefixes) {
        INFO("partition_remove_all_prefixes_done:  DONE: status = %d num_removals = %d num_unadvertised = %d",
             status, state->num_removals, state->num_unadvertised_prefixes);
        void (*continuation)(void) = state->continuation;
        free(state);
        if (continuation != NULL) {
            continuation();
        } else {
            INFO("partition_remove_all_prefixes_done: no continuation.");
        }
    } else {
        INFO("partition_remove_all_prefixes_done: !DONE: status = %d num_removals = %d num_unadvertised = %d",
             status, state->num_removals, state->num_unadvertised_prefixes);
    }
}

static void
partition_remove_all_unwanted_prefixes_inner(unadvertised_prefix_remove_state_t *state, thread_prefix_t *prefix)
{
    // Don't unpublish the adopted or published prefix.
    if ((published_thread_prefix == NULL || memcmp(&published_thread_prefix->prefix, &prefix->prefix, 8)) &&
        (adopted_thread_prefix == NULL || memcmp(&adopted_thread_prefix->prefix, &prefix->prefix, 8)))
    {
        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_remove_all_unwanted_prefixes: Removing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
        cti_status_t status = cti_remove_prefix(state, partition_remove_all_prefixes_done,
                                                dispatch_get_main_queue(), &prefix->prefix, 64);
        if (status != kCTIStatus_NoError) {
            ERROR("partition_remove_all_unwanted_prefixes: prefix remove failed: %d.", status);
        }
    }
}

static void
partition_remove_all_unwanted_prefixes(void (*continuation)(void), thread_prefix_t *prefix_1, thread_prefix_t *prefix_2)
{
    unadvertised_prefix_remove_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        INFO("partition_remove_all_unwanted_prefixes: no memory");
        return;
    }

    // It's possible for us to get into a state where a prefix is published by this BR, but doesn't
    // have a pref:id and isn't recognized as belonging to this BR.  This should never happen in practice,
    // but if it does happen, the only thing that will eliminate it is a reboot.   In case this happens,
    // we go through the list of prefixes that are marked ncp and unpublish them.
    thread_prefix_t *prefix;

    state->continuation = continuation;
    for (prefix = thread_prefixes; prefix; prefix = prefix->next) {
        if (!partition_pref_id_is_present(&prefix->prefix)) {
            // It's possible for partition_remove_all_unwanted_prefixes to get called before we have a full list of
            // recently-published prefixes. It is possible for either the published prefix or the adopted prefix to
            // not be on the list of prefixes. The caller may however have wanted to change either of those pointers;
            // in this case, it will pass in either or both of those pointers as prefix_1 and prefix_2; if we see those
            // prefixes on the list, we don't need to unpublish them twice.
            if (prefix_1 != NULL && !memcmp(&prefix->prefix, &prefix_1->prefix, 8)) {
                prefix_1 = NULL;
            }
            if (prefix_2 != NULL && !memcmp(&prefix->prefix, &prefix_2->prefix, 8)) {
                prefix_2 = NULL;
            }
            state->num_unadvertised_prefixes++;
        }
    }
    if (prefix_1 != NULL) {
        state->num_unadvertised_prefixes++;
    }
    if (prefix_2 != NULL) {
        state->num_unadvertised_prefixes++;
    }

    // Now actually remove the prefixes.
    for (prefix = thread_prefixes; prefix; prefix = prefix->next) {
        if (!partition_pref_id_is_present(&prefix->prefix)) {
            partition_remove_all_unwanted_prefixes_inner(state, prefix);
        }
    }
    if (prefix_1 != NULL) {
        partition_remove_all_unwanted_prefixes_inner(state, prefix_1);
    }
    if (prefix_2 != NULL) {
        partition_remove_all_unwanted_prefixes_inner(state, prefix_2);
    }

    // If we didn't remove any prefixes, continue immediately.
    if (state->num_unadvertised_prefixes == 0) {
        if (state->continuation) {
            state->continuation();
        }
        free(state);
    } else if (!state->continuation) {
        free(state);
#ifdef __clang_analyzer__ // clang_analyzer is unable to follow the reference through the cti code.
    } else {
        free(state);
#endif
    }
}

static void
partition_unpublish_adopted_prefix(bool wait)
{
    // Unpublish the adopted prefix
    if (adopted_thread_prefix != NULL) {
        partition_unpublish_prefix(adopted_thread_prefix);
        INFO("partition_unpublish_adopted_prefix: started to unadopt prefix.");
        RELEASE_HERE(adopted_thread_prefix, thread_prefix_finalize);
        adopted_thread_prefix = NULL;
    }

    // Something changed, so do a routing policy update unless wait==true
    if (!wait) {
        partition_refresh_and_re_evaluate();
    }
}

static void
partition_publish_prefix_finish(void)
{
    INFO("partition_publish_prefix_finish: prefix unpublishing has completed, time to update the prefix.");

    partition_id_update();
    set_thread_prefix();

    // Something changed, so do a routing policy update.
    partition_refresh_and_re_evaluate();
}

static void
partition_publish_my_prefix()
{
    void (*continuation)(void) = NULL;
    thread_prefix_t *prefix_1 = NULL;
    thread_prefix_t *prefix_2 = NULL;

    if (adopted_thread_prefix != NULL) {
        prefix_1 = adopted_thread_prefix;
        adopted_thread_prefix = NULL;
    }

    // If we already have a published thread prefix, it really should be my_thread_prefix.
    if (published_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf);
        // This should always be false.
        if (memcmp(&published_thread_prefix->prefix, &my_thread_prefix, 8)) {
            INFO("partition_publish_my_prefix: Published prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " is not my prefix",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf));
            prefix_2 = published_thread_prefix;
            published_thread_prefix = NULL;
            continuation = partition_publish_prefix_finish;
        } else {
            INFO("partition_publish_my_prefix: Published prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " is my prefix",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf));
        }
    }
    if (published_thread_prefix == NULL) {
        // Publish the prefix
        published_thread_prefix = thread_prefix_create(&my_thread_prefix, 64);
        if (published_thread_prefix == NULL) {
            ERROR("partition_publish_my_prefix: No memory for locally-advertised thread prefix");
            goto out;
        }
        continuation = partition_publish_prefix_finish;
        SEGMENTED_IPv6_ADDR_GEN_SRP(my_thread_prefix.s6_addr, prefix_buf);
        INFO("partition_publish_my_prefix: Publishing my prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(my_thread_prefix.s6_addr, prefix_buf));
    }
    partition_remove_all_unwanted_prefixes(continuation, prefix_1, prefix_2);
out:
    if (prefix_1 != NULL) {
        RELEASE_HERE(prefix_1, thread_prefix_finalize);
    }
    if (prefix_2 != NULL) {
        RELEASE_HERE(prefix_2, thread_prefix_finalize);
    }
}

static void
partition_adopt_prefix(thread_prefix_t *prefix)
{
    void (*continuation)(void) = NULL;
    thread_prefix_t *prefix_1 = NULL;
    thread_prefix_t *prefix_2 = NULL;

    if (published_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_adopt_prefix: Removing published prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf));
        prefix_1 = published_thread_prefix;
        published_thread_prefix = NULL;
    }

    // If we already have an advertised thread prefix, it might not have changed.
    if (adopted_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf);
        if (memcmp(&adopted_thread_prefix->prefix, &prefix->prefix, 8)) {
            INFO("partition_adopt_prefix: Removing previously adopted prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf));
            prefix_2 = adopted_thread_prefix;
            continuation = partition_publish_prefix_finish;
        } else {
            INFO("partition_adopt_prefix: Keeping previously adopted prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf));
        }
    }
    if (adopted_thread_prefix == NULL) {
        // Adopt the prefix
        adopted_thread_prefix = prefix;
        RETAIN_HERE(adopted_thread_prefix);
        continuation = partition_publish_prefix_finish;
        SEGMENTED_IPv6_ADDR_GEN_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_adopt_prefix: Adopting prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf));
    }
    partition_remove_all_unwanted_prefixes(continuation, prefix_1, prefix_2);

    if (prefix_1 != NULL) {
        RELEASE_HERE(prefix_1, thread_prefix_finalize);
    }
    if (prefix_2 != NULL) {
        RELEASE_HERE(prefix_2, thread_prefix_finalize);
    }
}

// Check to see if a specific prefix is still present.
static bool
partition_prefix_is_present(struct in6_addr *address, int length)
{
    thread_prefix_t *prefix;
    // For now we assume that the comparison is as a /64.
    for (prefix = thread_prefixes; prefix; prefix = prefix->next) {
        if (prefix->prefix_len == length && !memcmp((uint8_t *)&prefix->prefix, (uint8_t *)address, 8)) {
            return true;
        }
    }
    return false;
}

// Check to see if a valid pref:id for the specified prefix is present.
static bool
partition_pref_id_is_present(struct in6_addr *prefix_addr)
{
    thread_pref_id_t *pref_id;
    uint8_t *prefix_bytes = (uint8_t *)prefix_addr;

    INFO("partition_pref_id_is_present: published_thread_prefix = %p; prefix = %p", published_thread_prefix,
         prefix_addr);

    // The published prefix's pref:id is always considered present.
    if (published_thread_prefix != NULL && !memcmp(prefix_addr, &published_thread_prefix->prefix, 8)) {
        INFO("partition_pref_id_is_present: prefix is published prefix");
        return true;
    }

    for (pref_id = thread_pref_ids; pref_id; pref_id = pref_id->next) {
        // A pref:id is valid if the partition ID matches the current partition ID.
        // A pref:id matches a prefix if the 40 variable bits in the ULA /48 are the same.
        if (!memcmp(thread_partition_id, pref_id->partition_id, 4) &&
            !memcmp(prefix_bytes + 1, pref_id->prefix, 5))
        {
            INFO("partition_pref_id_is_present: pref:id is present");
            return true;
        } else {
            IPv6_PREFIX_GEN_SRP(pref_id->prefix, sizeof(pref_id->prefix), pref_id_prefix);
            if (memcmp(thread_partition_id, pref_id->partition_id, 4)) {
                INFO("partition_pref_id_is_present: "
                     "pref:id for " PRI_IPv6_PREFIX_SRP
                     ":%02x%02x%02x%02x does not match partition id %02x%02x%02x%02x",
                     IPv6_PREFIX_PARAM_SRP(pref_id_prefix),
                     pref_id->partition_id[0], pref_id->partition_id[1], pref_id->partition_id[2],
                     pref_id->partition_id[3],
                     thread_partition_id[0], thread_partition_id[1], thread_partition_id[2], thread_partition_id[3]);
            } else {
                INFO("partition_pref_id_is_present: "
                     "pref:id for " PRI_IPv6_PREFIX_SRP ":%02x%02x%02x%02x does not match prefix %02x%02x%02x%02x%02x",
                     IPv6_PREFIX_PARAM_SRP(pref_id_prefix),
                     pref_id->partition_id[0], pref_id->partition_id[1], pref_id->partition_id[2],
                     pref_id->partition_id[3],
                     prefix_bytes[1], prefix_bytes[2], prefix_bytes[3], prefix_bytes[4], prefix_bytes[5]);
            }
        }
    }
    return false;
}

// Find the lowest valid prefix present.  The return value may be the published prefix.
static thread_prefix_t *
partition_find_lowest_valid_prefix(void)
{
    thread_prefix_t *prefix, *lowest = published_thread_prefix;

    // Are there other prefixes published?
    for (prefix = thread_prefixes; prefix != NULL; prefix = prefix->next) {
        // The prefix we publish doesn't count.
        if (published_thread_prefix != NULL && !memcmp(&prefix->prefix, &published_thread_prefix->prefix, 8)) {
            continue;
        }
        if (partition_pref_id_is_present(&prefix->prefix)) {
            if (lowest == NULL || memcmp(&prefix->prefix, &lowest->prefix, 8) < 0) {
                lowest = prefix;
            }
            break;
        }
    }
    return lowest;
}

// Find the lowest valid pref:id.  The return value may be the pref:id for the published prefix.
static thread_pref_id_t *
partition_find_lowest_valid_pref_id(void)
{
    thread_pref_id_t *lowest = NULL;
    thread_pref_id_t *pref_id;

    for (pref_id = thread_pref_ids; pref_id != NULL; pref_id = pref_id->next) {
        if (lowest == NULL || memcmp(pref_id->prefix, lowest->prefix, 5) < 0) {
            lowest = pref_id;
        }
    }
    return lowest;
}

// The prefix ID timeout has gone off.  At this time we evaluate the state of the network: the fact that we
// got a wakeup means that there has been no partition event and nothing has changed about the set of
// prefixes published on the thread mesh since the wakeup was scheduled.  We don't schedule this wakeup unless
// there is more than one prefix on the thread mesh.   So that means that when the wakeup is called, there
// is still more than one prefix+pref:id pair active on the link--an undesirable situation.   So we now
// hold an election.  If we lose, we drop our prefix+pref:id pair in favor of the winner.  If we win,
// we do nothing--we are expecting the BR(s) publishing the other prefix+pref:id pair(s) to drop them.
static void
partition_pref_id_timeout(void *__unused context)
{
    thread_prefix_t *prefix = partition_find_lowest_valid_prefix();

    // This should never happen because we wouldn't have set the timeout.
    if (prefix == NULL) {
        INFO("partition_pref_id_timeout: no published prefix.");
        return;
    }

    // If we won, do nothing.
    if (published_thread_prefix != NULL && (prefix == published_thread_prefix ||
                                            !memcmp(&prefix->prefix, &published_thread_prefix->prefix, 8))) {
        INFO("partition_pref_id_timeout: published prefix is the lowest; keeping it.");
        return;
    }

    // published_thread_prefix should never be null here.
    // If our published prefix is not the lowest prefix, then we should drop it and adopt the lowest prefix.
    if (published_thread_prefix != NULL && memcmp(&prefix->prefix, &published_thread_prefix->prefix, 8)) {
        INFO("partition_pref_id_timeout: published prefix is not lowest valid prefix.  Adopting lowest valid prefix.");
        partition_adopt_prefix(prefix);
        return;
    }

    // We should never get here.
    if (adopted_thread_prefix != NULL) {
        if (!memcmp(&adopted_thread_prefix->prefix, &prefix->prefix, 8)) {
            ERROR("partition_pref_id_timeout: no published prefix.  Already adopted lowest.");
            return;
        }
        // Unadopt this prefix since it's not lowest.
        partition_unpublish_adopted_prefix(false);
        // adopted_thread_prefix is now NULL
    }

    // And we should never get here.
    ERROR("partition_pref_id_timeout: no published prefix.  Adopting lowest.");
    partition_adopt_prefix(prefix);
}

// When we see a new partition, if there isn't a prefix to adopt and we aren't publishing one,
// we wait n seconds to see if some other BR publishes a prefix, but also publish our own pref:id.
// If no router on the partition is publishing a prefix, then after n seconds we hold an election,
// choosing the pref:id with the lowest ULA.  If that's this router, then we will publish our prefix,
// but if not, we want to check after a bit to make sure a prefix /does/ get published.   If after
// another n seconds, we still don't see a valid prefix+pref:id pair, we publish our own; if this
// later turns out to have been a mistake, we will hold the election again and remove the one we
// published if we don't win.
static void
partition_post_election_wakeup(void *__unused context)
{
    thread_prefix_t *prefix = partition_find_lowest_valid_prefix();

    // There is no valid prefix published.   Publish ours.
    if (prefix == NULL) {
        INFO("partition_post_election_wakeup: no valid thread prefix present, publishing mine.");
        partition_publish_my_prefix();
        return;
    }

    // It's perfectly valid to not have adopted the lowest prefix at this point.
    // However, if we have adopted a prefix, we shouldn't be here because the timeout should have been
    // canceled.
    if (adopted_thread_prefix != NULL && memcmp(&adopted_thread_prefix->prefix, &prefix->prefix, 8)) {
        ERROR("partition_post_election_wakeup: adopted prefix is not lowest.");
    } else {
        ERROR("partition_post_election_wakeup: adopted prefix is lowest.");
    }
}

// This is the initial wakeup as described under partition_post_election_wakeup.   At this time
// if there is a valid published pref:id pair, we adopt it; if not, then we hold an election based
// on all of the on-partition pref:id pairs that we see.   If we win, we publish our prefix; otherwise
// give the winner time to publish its prefix.
static void
partition_post_partition_timeout(void *__unused context)
{
    thread_prefix_t *prefix = partition_find_lowest_valid_prefix();
    thread_pref_id_t *pref_id;

    // Is there a prefix+pref:id published?
    // Actually at this point we should already have adopted it and the wakeup should have been canceled.
    if (prefix != NULL) {
        ERROR("partition_post_partition_timeout: wakeup when there's a valid lowest prefix.");
        return;
    }

    // Are there pref:id services published that list a lower ULA than ours?
    pref_id = partition_find_lowest_valid_pref_id();

    if (pref_id == NULL) {
        INFO("There are no prefixes published, publishing my prefix.");
        partition_publish_my_prefix();
        return;
    }

    // If not, publish ours.
    if (memcmp(((uint8_t *)&my_thread_prefix) + 1, pref_id->prefix, 5) < 0) {
        INFO("partition_post_partition_timeout: my prefix id is lowest, publishing my prefix.");
        partition_publish_my_prefix();
        return;
    }

    // If so, wait another ten seconds to see if one of them publishes a prefix
    // If we have adopted a prefix, set a timer after which we will drop it and start advertising if nothing has
    // happened
    if (partition_post_partition_wakeup != NULL) {  // shouldn't be!
        ioloop_cancel_wake_event(partition_post_partition_wakeup);
    } else {
        partition_post_partition_wakeup = ioloop_wakeup_create();
        if (partition_post_partition_wakeup == NULL) {
            ERROR("partition_post_partition_timeout: can't allocate pref:id wait wakeup.");
            return;
        }
    }
    // Allow ten seconds for the services state to settle, after which time we should either have a pref:id backing
    // up a prefix, or should advertise a prefix.
    INFO("partition_post_partition_timeout: waiting for other BR to publish its prefixes.");
    ioloop_add_wake_event(partition_post_partition_wakeup, NULL, partition_post_election_wakeup, NULL, 10 * 1000);
}

static void
partition_proxy_listener_ready(void *__unused context, uint16_t port)
{
    INFO("partition_proxy_listener_ready: listening on port %d", port);
    srp_service_listen_port = port;
    if (have_non_thread_interface) {
        partition_can_advertise_service = true;
        partition_maybe_advertise_service();
    } else {
        partition_discontinue_srp_service();
    }
}

void
partition_start_srp_listener(void)
{
    const int max_avoid_ports = 100;
    uint16_t avoid_ports[max_avoid_ports];
    int num_avoid_ports = 0;
    thread_service_t *service;

    for (service = thread_services; service; service = service->next) {
        // Track the port regardless.
        if (num_avoid_ports < max_avoid_ports) {
            avoid_ports[num_avoid_ports] = (service->port[0] << 8) | (service->port[1]);
            num_avoid_ports++;
        }
    }

    INFO("partition_start_srp_listener: starting listener.");
    srp_listener = srp_proxy_listen("local", avoid_ports, num_avoid_ports, partition_proxy_listener_ready);
    if (srp_listener == NULL) {
        ERROR("partition_start_srp_listener: Unable to start SRP Proxy listener, so can't advertise it");
        return;
    }
}

static void
partition_discontinue_srp_service()
{
    if (srp_listener != NULL) {
        srp_proxy_listener_cancel(srp_listener);
        srp_listener = NULL;
    }

    // Won't match
    memset(&srp_listener_ip_address, 0, 16);
    srp_service_listen_port = 0;
    partition_can_advertise_service = false;

    // Stop advertising the service, if we are doing so.
    partition_stop_advertising_service();
}

// An address on utun0 has changed.  Evaluate what to do with our listener service.
// This gets called from ifaddr_callback().   If we don't yet have a thread service configured,
// it should be called for unchanged addresses as well as changed.
static void
partition_utun0_address_changed(const struct in6_addr *addr, enum interface_address_change change)
{
    thread_prefix_t *advertised_prefix = NULL;

    // Figure out what our current prefix is.
    if (published_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_utun0_address_changed: advertised prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " is my prefix.",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf));
        advertised_prefix = published_thread_prefix;
    } else if (adopted_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_utun0_address_changed: advertised prefix " PRI_SEGMENTED_IPv6_ADDR_SRP
             " is another router's prefix.",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf));
        advertised_prefix = adopted_thread_prefix;
    }

    SEGMENTED_IPv6_ADDR_GEN_SRP(addr, addr_buf);
    // Is this the address we are currently using?
    if (!memcmp(&srp_listener_ip_address, addr, 16)) {
        // Did it go away?   If so, drop the listener.
        if (change == interface_address_deleted) {
            INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP ": listener address removed.",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
            if (srp_listener != NULL) {
                INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
                     ": canceling listener on removed address.", SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
                partition_discontinue_srp_service();
            }
        } else {
            // This should never happen.
            if (change == interface_address_added) {
                ERROR("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
                      ": address we're listening on was added.", SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
            }

            // Is it on the prefix we're currently publishing?
            if (advertised_prefix != NULL && !memcmp(&advertised_prefix->prefix, addr, 8)) {
                INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
                     ": listener address is on the advertised prefix--no action needed.",
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
            } else {
                // In this case hopefully we'll get a new IP address we _can_ listen on in a subsequent call.
                INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
                     ": listener address is not on the advertised prefix--no action taken.",
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
            }
        }

        // In no case can we do anything further.
        return;
    }

    // If we have a prefix, see if we need to do anything.
    if (advertised_prefix != NULL) {
        // If this is not the address we are currently using, and it showed up, is it on the prefix we
        // are advertising?
        if (!memcmp(&advertised_prefix->prefix, addr, 8)) {
            // If we are not listening on an address, or we are listening on an address that isn't on the
            // prefix we are advertising, we need to stop, if needed, and start up a new listener.
            if (srp_listener_ip_address.s6_addr[0] == 0 ||
                memcmp(&advertised_prefix->prefix, &srp_listener_ip_address, 8))
            {
                // See if we already have a listener; if so, stop it.
                if (srp_listener_ip_address.s6_addr[0] != 0) {
                    INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP ": stopping old listener.",
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
                    srp_proxy_listener_cancel(srp_listener);
                    srp_listener = NULL;
                }
                if (srp_listener == NULL) {
                    if (!have_non_thread_interface) {
                        INFO("partition_utun0_address_changed: not starting a listener because we have no infrastructure");
                    } else {
                        INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP ": starting a new listener.",
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
                        memcpy(&srp_listener_ip_address, addr, 16);
                        srp_service_listen_port = 0;
                        partition_start_srp_listener();
                    }
                }
            }
        } else {
            INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
                 ": this address not on advertised prefix, so no action to take.",
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
        }
    } else {
        INFO("partition_utun0_address_changed: " PRI_SEGMENTED_IPv6_ADDR_SRP
             ": no advertised prefix, so no action to take.", SEGMENTED_IPv6_ADDR_PARAM_SRP(addr, addr_buf));
    }
}

// We call this function to see if we have a complete, recent set of information; if not, we wait a bit for the set
// to become complete, but after 500ms we assume it won't be and proceed.
static bool
partition_wait_for_prefix_settling(wakeup_callback_t callback, uint64_t now)
{
    // Remember when we started waiting for the partition data to settle.
    if (partition_settle_satisfied) {
        partition_settle_start = now;
        partition_settle_satisfied = false;
    }

    if (partition_settle_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_settle_wakeup);
    }

    // If we aren't able to offer service, just wait.
    if (!partition_may_offer_service) {
        INFO("partition_wait_for_prefix_settling: not able to offer service--deferring.");
        return true;
    }

    // If we've gotten updates on everything, we're good to go.   The reason for comparing against
    // partition_settle_start is that if we've been seriously throttled for some reason, it might take
    // more than 500ms to get a callback, even though all the events came in between when we asked
    // for the initial callback and when we got it.   Tunnel ID shouldn't change after startup.
    if (partition_last_prefix_set_change >= partition_settle_start &&
        partition_last_pref_id_set_change >= partition_settle_start &&
        partition_last_partition_id_change >= partition_settle_start &&
        partition_last_role_change >= partition_settle_start &&
        partition_last_state_change >= partition_settle_start && partition_tunnel_name_is_known)
    {
        partition_settle_satisfied = true;
        INFO("partition_wait_for_prefix_settling: satisfied after %llums.", now - partition_settle_start);
        return false; // means don't wait
    }

    // If we've waited longer than 500ms and aren't satisfied, complain, but then proceed.
    if (now - partition_settle_start >= 500) {
        ERROR("partition_wait_for_prefix_settling: unsatisfied after %llums", now - partition_settle_start);
        partition_settle_satisfied = true; // not really, but there's always next time.
        return false; // proceed if possible.
    }

    // Otherwise, wake up 500ms after we started waiting for things to settle, and reconnoiter.
    if (partition_settle_wakeup == NULL) {
        partition_settle_wakeup = ioloop_wakeup_create();
        if (partition_settle_wakeup == NULL) {
            ERROR("partition_wait_for_prefix_settling: Unable to postpone partition settlement wakeup: no memory.");
            partition_settle_satisfied = true;
            return false;
        }
    }
    ioloop_add_wake_event(partition_settle_wakeup, NULL, callback, NULL, 500 - (int)(now - partition_settle_start));
    return true;
}

static void
partition_got_tunnel_name(void)
{
    partition_tunnel_name_is_known = true;
    refresh_interface_list();
}

// We have a recent prefix list and either have a recent pref:id list or one probably isn't coming.
static void
partition_prefix_list_or_pref_id_list_changed(void *__unused context)
{
    // If we haven't had a pref:id update recently, wait a bit to see if one came with the most recent network data.
    if (partition_wait_for_prefix_settling(partition_prefix_list_or_pref_id_list_changed, ioloop_timenow())) {
        ERROR("partition_prefix_list_or_pref_id_list_changed: waiting for prefix info to settle.");
        return;
    }

    // If we aren't ready to advertise service, do nothing.
    if (!partition_may_offer_service) {
        INFO("partition_prefix_list_or_pref_id_list_changed can't offer service yet.");
        return;
    }

    // If there are no prefixes, then it doesn't matter what's on the prefix ID list: publish a prefix now.
    if (thread_prefixes == NULL) {
        INFO("partition_prefix_list_or_pref_id_list_changed have no prefixes, publishing my prefix");
        partition_publish_my_prefix();
        return;
    }

    // It is a failure of the thread network software for us to get to this point without knowing the thread
    // partition ID.   We should have received it on startup.   So the case where this would happen would be if
    // on startup we simply didn't get it, which should never happen.   What we'll do if this happens is make
    // one up.
    if (partition_id_is_known == false) {
        ERROR("partition_prefix_list_or_pref_id_list_changed: partition ID never showed up!");
    }

    // If we are already publishing a prefix and pref:id, we don't have to do anything to the prefix right now.
    if (published_thread_prefix != NULL) {
        // We do need to trigger an interface scan though.
        refresh_interface_list();

        // Also, if there's more than one prefix present, set a timer for an hour from now, at which point we will
        // consider dropping our prefix.
        if (thread_prefixes != NULL && thread_prefixes->next != NULL) {
            INFO("partition_prefix_list_or_pref_id_list_changed:"
                 "published prefix is unchanged, setting up the pref:id timer");
            if (partition_pref_id_wait_wakeup != NULL) {
                ioloop_cancel_wake_event(partition_pref_id_wait_wakeup);
            } else {
                partition_pref_id_wait_wakeup = ioloop_wakeup_create();
                if (partition_pref_id_wait_wakeup == NULL) {
                    ERROR("partition_prefix_list_or_pref_id_list_changed: "
                          "Unable to set a timer to wake up after the an hour to check the partition id.");
                    return;
                }
            }
            // The thread network can be pretty chaotic right after the BR comes up, so if we see a partition during the
            // first 60 seconds, don't treat it as a real partition event, and do the re-election in 60 seconds rather
            // than an hour.
            uint64_t time_since_zero = ioloop_timenow() - partition_last_state_change;
            uint32_t pref_id_timeout_time = 3600 * 1000;
            if (time_since_zero < 60 * 1000) {
                pref_id_timeout_time = 60 * 1000;
            }
            ioloop_add_wake_event(partition_pref_id_wait_wakeup, NULL, partition_pref_id_timeout, NULL,
                                  pref_id_timeout_time);
            INFO("added partition pref id timeout");
        } else {
            INFO("partition_prefix_list_or_pref_id_list_changed: published prefix is unchanged");
        }
        return;
    }

    // If we have adopted a prefix and the prefix and pref:id are still present, do nothing.
    if (adopted_thread_prefix != NULL) {
        if (partition_prefix_is_present(&adopted_thread_prefix->prefix, adopted_thread_prefix->prefix_len) &&
            partition_pref_id_is_present(&adopted_thread_prefix->prefix))
        {
            INFO("partition_prefix_list_or_pref_id_list_changed: adopted prefix is unchanged");
            return;
        }
        // If the adopted prefix is no longer present, stop using it.
        partition_unpublish_adopted_prefix(false);
        // adopted_thread_prefix is now NULL.
    }

    // If there is a prefix present for which there is already a matching pref:id, adopt that prefix and pref:id now.
    // drop the thread_post_partition_timeout timer.
    thread_prefix_t *prefix;
    for (prefix = thread_prefixes; prefix; prefix = prefix->next) {
        if (partition_pref_id_is_present(&prefix->prefix)) {
            INFO("partition_prefix_list_or_pref_id_list_changed: adopting new prefix");
            partition_adopt_prefix(prefix);
            // When we adopt a prefix, it was already on-link, and quite possibly we already have an address
            // configured on that prefix on utun0.  Calling refresh_interface_list() will trigger the listener
            // if in fact that's the case.   If the address hasn't come up on utun0 yet, then when it comes up
            // that will trigger the listener.
            refresh_interface_list();
            return;
        }
        if (partition_post_partition_wakeup != NULL) {
            ioloop_cancel_wake_event(partition_post_partition_wakeup);
        }
    }

    // At this point there is a prefix, but no pref:id, and it's /not/ the prefix that we published.  This
    // means that a partition has happened and the BR that published the prefix is on the other partition,
    // or else that the BR that published the prefix has gone offline and has been offline for at least
    // four minutes.
    // It's possible that either condition will heal, but in the meantime publish a prefix.   The reason for
    // the urgency is that if we have a partition, and both routers are still online, then routing will be
    // screwed up until we publish a new prefix and migrate all the accessories on our partition to the
    // new prefix.
    INFO("partition_publish_prefix: there is a prefix, but no pref:id, so it's stale. Publishing my prefix.");
    partition_publish_my_prefix();
}

// The list of published prefix has changed.  Evaluate what to do with our partition state.
// Mostly what we do when the prefix list changes is the same as what we do if the pref:id list
// changes, but if we get an empty prefix list, it doesn't matter what's on the pref:id list,
// so we act immediately.
static void
partition_prefix_set_changed(void)
{
    // Time stamp most recent prefix set update.
    partition_last_prefix_set_change = ioloop_timenow();

    // Otherwise, we have a prefix list and a pref:id list, so we can make decisions.
    partition_prefix_list_or_pref_id_list_changed(NULL);
}

// The set of published pref:id's changed.  Evaluate what to do with our pref:id
static void
partition_pref_id_set_changed(void)
{
    // Time stamp most recent prefix set update.
    partition_last_prefix_set_change = ioloop_timenow();

    // Otherwise, we have a prefix list and a pref:id list, so we can make decisions.
    partition_prefix_list_or_pref_id_list_changed(NULL);
}

// The partition ID changed.
static void
partition_id_changed(void)
{
    partition_last_partition_id_change = ioloop_timenow();

    // If we've never seen a partition ID before, this is not (necessarily) a partition.
    if (!partition_id_is_known) {
        INFO("partition_id_changed: first time through.");
        partition_id_is_known = true;
        return;
    }

    // If we get a partition ID when we aren't a router, we should (I think!) ignore it.
    if (!partition_can_provide_routing) {
        INFO("partition_id_changed: we aren't able to offer routing yet, so ignoring.");
        return;
    }

    // If we are advertising a prefix, update our pref:id
    if (published_thread_prefix != NULL) {
        INFO("partition_id_changed: updating advertised prefix id");
        partition_id_update();
        // In principle we didn't change anything material to the routing subsystem, so no need to re-evaluate current
        // policy.
        return;
    }

    // Propose our prefix as a possible lowest prefix in case there's an election.
    partition_stop_advertising_pref_id();
    partition_advertise_pref_id(((uint8_t *)(&my_thread_prefix)) + 1);

    // If we have adopted a prefix, set a timer after which we will drop it and start advertising if nothing has
    // happened
    if (partition_post_partition_wakeup != NULL) {
        ioloop_cancel_wake_event(partition_post_partition_wakeup);
    } else {
        partition_post_partition_wakeup = ioloop_wakeup_create();
        if (partition_post_partition_wakeup == NULL) {
            ERROR("partition_id_changed: can't allocate pref:id wait wakeup.");
            return;
        }
    }
    // Allow ten seconds for the services state to settle, after which time we should either have a pref:id backing
    // up a prefix, or should advertise a prefix.
    INFO("partition_id_changed: waiting for other BRs to propose their prefixes.");
    ioloop_add_wake_event(partition_post_partition_wakeup, NULL, partition_post_partition_timeout, NULL, 10 * 1000);
}

static void
partition_remove_service_done(void *context, cti_status_t status)
{
    INFO("partition_remove_service_done: %d", status);

    // Flush any advertisements we're currently doing, since the accessories that advertised them will
    // notice the service is gone and start advertising with a different service.
#ifndef OPEN_SOURCE
    // The conditional test is so that we don't do this twice when we are advertising both services.
#endif
    if (context != NULL) {
        srp_mdns_flush();
    }
}

static void
partition_stop_advertising_service(void)
{
    // This should remove any copy of the service that this BR is advertising.
    INFO("partition_stop_advertising_service: %" PRIu64 "/" PUB_S_SRP, THREAD_ENTERPRISE_NUMBER, "00010001");
    uint8_t service_info[] = { 0, 0, 0, 1 };
    int status;

    service_info[0] = THREAD_SRP_SERVER_OPTION & 255;
    status = cti_remove_service((void *)(ptrdiff_t)1, partition_remove_service_done, dispatch_get_main_queue(),
                                THREAD_ENTERPRISE_NUMBER, service_info, 1);
    if (status != kCTIStatus_NoError) {
        INFO("partition_stop_advertising_service: status %d", status);
    }
}

static void
partition_add_service_callback(void *__unused context, cti_status_t status)
{
    if (status != kCTIStatus_NoError) {
        INFO("partition_add_service_callback: status = %d", status);
    } else {
        INFO("partition_add_service_callback: status = %d", status);
    }
}

static void
partition_start_advertising_service(void)
{
    uint8_t service_info[] = {0, 0, 0, 1};
    uint8_t server_info[18];
    int ret;

    memcpy(&server_info, &srp_listener_ip_address, 16);
    server_info[16] = (srp_service_listen_port >> 8) & 255;
    server_info[17] = srp_service_listen_port & 255;

    service_info[0] = THREAD_SRP_SERVER_OPTION & 255;
    INFO("partition_add_srp_service: %" PRIu64 "/%02x/" PRI_SEGMENTED_IPv6_ADDR_SRP ":%d" ,
         THREAD_ENTERPRISE_NUMBER, service_info[0],
         SEGMENTED_IPv6_ADDR_PARAM_SRP(srp_listener_ip_address.s6_addr, server_ip_buf), srp_service_listen_port);

    ret = cti_add_service(NULL, partition_add_service_callback, dispatch_get_main_queue(),
                              THREAD_ENTERPRISE_NUMBER, service_info, 1, server_info, sizeof server_info);
    if (ret != kCTIStatus_NoError) {
        INFO("partition_add_srp_service: status %d", ret);
    }

    // Wait a while for the service add to be reflected in an event.
    partition_schedule_service_add_wakeup();
}

static void
partition_service_add_wakeup(void *__unused context)
{
    partition_service_last_add_time = 0;
    partition_maybe_advertise_service();
}

static void
partition_schedule_service_add_wakeup()
{
    if (partition_service_add_pending_wakeup == NULL) {
        partition_service_add_pending_wakeup = ioloop_wakeup_create();
        if (partition_service_add_pending_wakeup == NULL) {
            ERROR("Can't schedule service add pending wakeup: no memory!");
            return;
        }
    } else {
        ioloop_cancel_wake_event(partition_service_add_pending_wakeup);
    }
    // Wait ten seconds.
    ioloop_add_wake_event(partition_service_add_pending_wakeup, NULL, partition_service_add_wakeup, NULL, 10 * 1000);
}

static void
partition_maybe_advertise_service(void)
{
    thread_service_t *service, *lowest[2];
    int num_services = 0;
    int i;
    bool should_remove_service = false;
    bool should_advertise_service = false;
    int64_t last_add_time;

    // If we aren't ready to advertise a service, there's nothing to do.
    if (!partition_can_advertise_service) {
        INFO("partition_maybe_advertise_service: no service to advertise yet.");
        return;
    }

    if (partition_service_blocked) {
        INFO("partition_maybe_advertise_service: service advertising is disabled.");
        return;
    }

    for (i = 0; i < 16; i++) {
        if (srp_listener_ip_address.s6_addr[i] != 0) {
            break;
        }
    }
    if (i == 16) {
        INFO("partition_maybe_advertise_service: no listener.");
    }

    // The add service function requires a remove prior to the add, so if we are doing an add, we need to wait
    // for things to stabilize before allowing the removal of a service to trigger a re-evaluation.
    // Therefore, if we've done an add in the past ten seconds, wait ten seconds before trying another add.
    last_add_time = ioloop_timenow() - partition_service_last_add_time;
    INFO("partition_maybe_advertise_service: last_add_time = %" PRId64, last_add_time);
    if (last_add_time < 10 * 1000) {
        partition_schedule_service_add_wakeup();
        return;
    }
    lowest[0] = NULL;
    lowest[1] = NULL;

    for (service = thread_services; service; service = service->next) {
        int port = service->port[0] | (service->port[1] << 8);
        SEGMENTED_IPv6_ADDR_GEN_SRP(service->address, srv_addr_buf);

        // A service only counts if its prefix is present and its prefix id is present and matches the
        // current partition id.
        if (partition_prefix_is_present((struct in6_addr *)service->address, 64)) {
            if (partition_pref_id_is_present((struct in6_addr *)service->address)) {
                num_services++;
                for (i = 0; i < 2; i++) {
                    if (lowest[i] == NULL) {
                        lowest[i] = service;
                        INFO("service " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d goes in open slot %d.",
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(service->address, srv_addr_buf), port, i);
                        break;
                    } else if (memcmp(service->address, lowest[i]->address, 16) < 0) {
                        int lowport;

                        if (lowest[1] != NULL) {
                            lowport = (lowest[1]->port[0] << 8) | lowest[1]->port[1];
                            SEGMENTED_IPv6_ADDR_GEN_SRP(lowest[1]->address, lowest_1_buf);
                            INFO("Superseding " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d in slot 1",
                                 SEGMENTED_IPv6_ADDR_PARAM_SRP(lowest[1]->address, lowest_1_buf), lowport);
                        }
                        if (i == 0) {
                            lowport = (lowest[0]->port[0] << 8)| lowest[0]->port[1];
                            SEGMENTED_IPv6_ADDR_GEN_SRP(lowest[0]->address, lowest_0_buf);
                            INFO("Moving " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d from slot 0 to slot 1",
                                 SEGMENTED_IPv6_ADDR_PARAM_SRP(lowest[0]->address, lowest_0_buf), lowport);
                            lowest[1] = lowest[0];
                        }
                        INFO("service " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d goes in slot %d.",
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(service->address, srv_addr_buf), port, i);
                        lowest[i] = service;
                        break;
                    }
                }
            } else {
                INFO("service " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d doesn't count because the pref:id is not present.",
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(service->address, srv_addr_buf), port);
            }
        } else {
                INFO("service " PRI_SEGMENTED_IPv6_ADDR_SRP "%%%d doesn't count because the prefix is not present.",
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(service->address, srv_addr_buf), port);
        }
    }

    should_remove_service = true;
    for (i = 0; i < 2; i++) {
        if (lowest[i] == NULL) {
            INFO("partition_maybe_advertise_service: adding service because there's an open slot.");
            should_remove_service = false;
            should_advertise_service = true;
            break;
        } else {
            int sign = memcmp(((uint8_t *)(&srp_listener_ip_address)), lowest[i]->address, 16);
            if (sign == 0) {
                // We're already advertising the service and we win the election.
                // If the port hasn't changed, don't update the service
                uint16_t port = (lowest[i]->port[0] << 8) | lowest[i]->port[1];
                if (port != srp_service_listen_port) {
                    INFO("partition_maybe_advertise_service: old service was present and prefix would win election.");
                    should_remove_service = false;
                    should_advertise_service = true;
                } else {
                    INFO("partition_maybe_advertise_service: service already present and would win election.");
                    should_remove_service = false;
                    should_advertise_service = false;
                }
                break;
            } else if (sign < 0) {
                INFO("partition_maybe_advertise_service: service not present but wins election.");
                should_remove_service = false;
                should_advertise_service = true;
                break;
            } else {
                INFO("Service would not win election with lowest[%d]", i);
            }
        }
    }

    // Always remove service before adding it, but also remove it if it lost the election.
    if (should_remove_service) {
        partition_stop_advertising_service();
        partition_service_last_add_time = ioloop_timenow();
    }
    if (should_advertise_service) {
        partition_start_advertising_service();
        partition_service_last_add_time = ioloop_timenow();
    }
}

static void
partition_service_set_changed()
{
    partition_pref_id_set_changed();
    partition_maybe_advertise_service();
}

static void partition_maybe_enable_services()
{
    bool am_associated = current_thread_state == kCTI_NCPState_Associated;
    if (am_associated) {
        INFO("partition_maybe_enable_services: "
             "Enabling service, which was disabled because of the thread role or state.");
        partition_may_offer_service = true;
        partition_can_provide_routing = true;
        refresh_interface_list();
        partition_prefix_list_or_pref_id_list_changed(NULL);
        routing_policy_evaluate_all_interfaces(true);
    } else {
        INFO("partition_maybe_enable_services: Not enabling service: " PUB_S_SRP,
             am_associated ? "associated" : "!associated");
    }
}

static void partition_disable_service()
{
    bool done_something = false;

    // When our node type or state is such that we should no longer be publishing a prefix, the NCP will
    // automatically remove the published prefix.  In case this happens, we do not want to remember the
    // prefix as already having been published.  So drop our recollection of the adopted and published
    // prefixes; this will get cleaned up when the network comes back if there's an inconsistency.
    if (adopted_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_disable_service: unadopting prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(adopted_thread_prefix->prefix.s6_addr, prefix_buf));
        RELEASE_HERE(adopted_thread_prefix, thread_prefix_finalize);
        adopted_thread_prefix = NULL;
        done_something = true;
    }
    if (published_thread_prefix != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf);
        INFO("partition_disable_service: un-publishing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(published_thread_prefix->prefix.s6_addr, prefix_buf));
        RELEASE_HERE(published_thread_prefix, thread_prefix_finalize);
        published_thread_prefix = NULL;
        done_something = true;
    }

    // We want to always say something when we pass through this state.
    if (!done_something) {
	    INFO("partition_disable_service: nothing to do.");
    }

    partition_may_offer_service = false;
    partition_can_provide_routing = false;
}
#endif // RA_TESTER

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
