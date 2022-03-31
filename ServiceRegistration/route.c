/* route.c
 *
 * Copyright (c) 2019-2022 Apple Inc. All rights reserved.
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
 * This code adds border router support to 3rd party HomeKit Routers as part of Apple’s commitment to the CHIP project.
 *
 * This file contains an implementation of Thread Border Router routing.
 * The state of the Thread network is tracked, the state of the infrastructure
 * network is tracked, and policy decisions are made as to what to advertise
 * on both networks.
 */

#ifndef LINUX
#include <netinet/in.h>
#include <net/if.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <net/if_media.h>
#include <sys/stat.h>
#else
#define _GNU_SOURCE
#include <netinet/in.h>
#include <fcntl.h>
#include <bsd/stdlib.h>
#include <net/if.h>
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#if !USE_SYSCTL_COMMAND_TO_ENABLE_FORWARDING
#ifndef LINUX
#include <sys/sysctl.h>
#endif // LINUX
#endif // !USE_SYSCTL_COMMAND_TO_ENABLE_FORWARDING
#include <stdlib.h>
#include <stddef.h>
#include <dns_sd.h>
#include <inttypes.h>
#include <signal.h>

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

#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "route.h"
#include "adv-ctl-server.h"
#include "srp-crypto.h"

# define THREAD_DATA_DIR "/var/lib/openthread"
# define THREAD_ULA_FILE THREAD_DATA_DIR "/thread-mesh-ula"

#if STUB_ROUTER // Stub Router is true if we're building a Thread Border router or an RA tester.
#ifdef THREAD_BORDER_ROUTER
#include "cti-services.h"
#endif
#include "srp-gw.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "dnssd-proxy.h"
#if SRP_FEATURE_NAT64
#include "nat64-macos.h"
#endif

#ifdef LINUX
#define CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IFCONFIG 1
#endif

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


#ifdef LINUX
struct in6_addr in6addr_linklocal_allnodes = {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}};
struct in6_addr in6addr_linklocal_allrouters = {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}};
#endif

// If true, a prefix with L=1, A=0 in an RA with M=1 is treated as usable. The reason it's not treated as
// usable by default is that this will break Thread for Android phones on networks where IPv6 is present
// but only DHCPv6 is supported.
bool config_enable_dhcpv6_prefixes = false;

// If true, we actually want stub router functionality. If false, we don't (yet) have a need for it.
bool stub_router_needed = false;

interface_t *interfaces;
icmp_listener_t icmp_listener;
bool have_thread_prefix = false;
struct in6_addr my_thread_prefix;
struct in6_addr srp_listener_ip_address;
char thread_address_string[INET6_ADDRSTRLEN];
uint16_t srp_service_listen_port;
uint8_t thread_partition_id[4];
srp_proxy_listener_state_t *srp_listener;
struct in6_addr ula_prefix;
struct in6_addr xpanid_prefix;
bool have_xpanid_prefix = false;
int num_thread_interfaces; // Should be zero or one.
int ula_serial = 1;
bool advertise_default_route_on_thread;
subproc_t *thread_interface_enumerator_process;
subproc_t *thread_prefix_adder_process;
subproc_t *thread_rti_setter_process;
subproc_t *thread_forwarding_setter_process;
subproc_t *thread_proxy_service_adder_process;
subproc_t *tcpdump_logger_process;
char *thread_interface_name;
char *home_interface_name;
bool thread_proxy_service_setup_done;
bool interface_state_stable = false;
bool have_non_thread_interface = false;
uint64_t xpanid;

#ifndef RA_TESTER
cti_network_state_t current_thread_state = kCTI_NCPState_Uninitialized;
cti_connection_t thread_role_context;
cti_connection_t thread_state_context;
cti_connection_t thread_service_context;
cti_connection_t thread_prefix_context;
cti_connection_t thread_partition_id_context;
cti_connection_t thread_xpanid_context;
static bool thread_network_running = false;
#endif

#if !defined(RA_TESTER)
static wakeup_t *wpan_reconnect_wakeup;
#endif

#define CONFIGURE_STATIC_INTERFACE_ADDRESSES 1

static void refresh_interface_list(void);
static void router_advertisement_send(interface_t *NONNULL interface, const struct in6_addr *destination);
static void neighbor_solicit_send(interface_t *interface, struct in6_addr *destination);
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
static void interface_active_state_evaluate(interface_t *interface, bool active_known, bool active);
static void schedule_next_router_probe(interface_t *interface);

#ifndef RA_TESTER
static void thread_network_startup(void);
static void thread_network_shutdown(void);
static void partition_state_reset(void);
static void partition_unpublish_prefix(thread_prefix_t *NONNULL prefix);
static void partition_unpublish_adopted_prefix(bool wait);
static void partition_adopt_prefix(thread_prefix_t *NONNULL prefix);
static bool partition_prefix_is_present(struct in6_addr *prefix_addr, int length);
static bool partition_pref_id_is_present(struct in6_addr *NONNULL prefix_addr);
static thread_prefix_t *NULLABLE partition_find_lowest_valid_prefix(void);
static thread_pref_id_t *NULLABLE partition_find_lowest_valid_pref_id(void);
static void partition_pref_id_timeout(void *UNUSED NULLABLE context);
static void partition_post_election_wakeup(void *UNUSED NULLABLE context);
static void partition_post_partition_timeout(void *UNUSED NULLABLE context);
static void partition_discontinue_srp_service(void);
static void partition_utun0_address_changed(const struct in6_addr *NONNULL addr, enum interface_address_change change);
static bool partition_wait_for_prefix_settling(wakeup_callback_t NONNULL callback, uint64_t now);
static void partition_got_tunnel_name(void);
static void partition_prefix_set_changed(void);
static void partition_pref_id_set_changed(void);
static void partition_id_changed(void);
static void partition_remove_service_done(void *UNUSED NULLABLE context, cti_status_t status);
static void partition_stop_advertising_service(void);
static void partition_proxy_listener_ready(void *UNUSED NULLABLE context, uint16_t port);
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
static bool partition_has_xpanid;
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
    if (interface->stale_evaluation_wakeup != NULL) {
        ioloop_wakeup_release(interface->stale_evaluation_wakeup);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_wakeup_release(interface->router_solicit_wakeup);
    }
    if (interface->deconfigure_wakeup != NULL) {
        ioloop_wakeup_release(interface->deconfigure_wakeup);
    }
    if (interface->neighbor_solicit_wakeup != NULL) {
        ioloop_wakeup_release(interface->neighbor_solicit_wakeup);
    }
    if (interface->router_probe_wakeup != NULL) {
        ioloop_wakeup_release(interface->router_probe_wakeup);
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
        if (!strcmp(name, "lo") || !strcmp(name, "wpan0")) {
            ret->ineligible = true;
        } else {
            ret->ineligible = false;
        }
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
    if (message->wakeup != NULL) {
        ioloop_cancel_wake_event(message->wakeup);
        ioloop_wakeup_release(message->wakeup);
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
    message->num_options = 0;
    while (scan_offset < length) {
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_type)) {
            return false;
        }
        if (!dns_u8_parse(icmp_buf, length, &scan_offset, &option_length_8)) {
            return false;
        }
        if (option_length_8 == 0) { // RFC4191 section 4.6: The value 0 is invalid.
            ERROR("icmp_option_parse: option type %d length 0 is invalid.", option_type);
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
    // If there are no options, we're done. No options is valid, so return true.
    if (message->num_options == 0) {
        return true;
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
    INFO("interface_prefix_deconfigure: post solicit wakeup.");

    if (interface->preferred_lifetime != 0) {
        INFO("interface_prefix_deconfigure: PUT PREFIX DECONFIGURE CODE HERE!!");
        interface->valid_lifetime = 0;
    }
    interface->deprecate_deadline = 0;
}

static bool
want_routing(void)
{
#ifdef RA_TESTER
    return true;
#else
    return partition_can_provide_routing && partition_has_xpanid && stub_router_needed;
#endif
}

static void
interface_beacon_send(interface_t *interface, const struct in6_addr *destination)
{
    uint64_t now = ioloop_timenow();

    INFO(PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP,
         interface->deprecate_deadline > now ? " ddl>now" : "",
         stub_router_needed ? " stubn" : " !stubn",
#ifdef RA_TESTER
         "", "", "",
#else
         partition_can_provide_routing ? " canpr" : " !canpr",
         partition_has_xpanid ? " havexp" : " !havexp",
         interface->suppress_ipv6_prefix ? " suppress" : " !suppress",
#endif
         interface->our_prefix_advertised ? " advert" : " !advert",
         interface->sent_first_beacon ? "" : " first beacon");

    if (interface->deprecate_deadline > now) {
        // The remaining valid and preferred lifetimes is the time left until the deadline.
        interface->valid_lifetime = (uint32_t)((interface->deprecate_deadline - now) / 1000);
        interface->preferred_lifetime = (uint32_t)((interface->deprecate_deadline - now) / 1000);
        // When we're deprecating the prefix, we don't actually want to make the preferred lifetime zero, because
        // this will cause IP address flapping if we miss a router advertisement.
#define FIVE_MINUTES 5 * 60
        if (interface->preferred_lifetime > FIVE_MINUTES) {
            interface->preferred_lifetime = FIVE_MINUTES;
        }
        if (interface->valid_lifetime < icmp_listener.unsolicited_interval / 1000) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
            INFO("prefix valid life time is less than the unsolicited interval, stop advertising it "
                 "and prepare to deconfigure the prefix - ifname: " PUB_S_SRP "prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP
                 ", preferred time: %" PRIu32 ", valid time: %" PRIu32 ", unsolicited interval: %" PRIu32,
                 interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf),
                 interface->preferred_lifetime, interface->valid_lifetime, icmp_listener.unsolicited_interval / 1000);
            interface->our_prefix_advertised = false;
            ioloop_add_wake_event(interface->deconfigure_wakeup,
                                  interface, interface_prefix_deconfigure,
                                  interface_deconfigure_finalize, interface->valid_lifetime * 1000);
        }
    }

#ifndef RA_TESTER
    // If we have been beaconing, and router mode has been disabled, and we don't have
    // an on-link prefix to advertise, discontinue beaconing.
    if (want_routing() || interface->our_prefix_advertised) {
#endif

    // Send an RA.
        router_advertisement_send(interface, destination);
        if (destination == &in6addr_linklocal_allnodes) {
            interface->sent_first_beacon = true;
            interface->last_beacon = ioloop_timenow();;
        }
#ifndef CONTINUE_ADVERTISING_DURING_DEPRECATION
        // If we are deprecating, just send the initial deprecation to shorten the preferred lifetime, and then go silent.
        if (interface->deprecate_deadline > now && !interface->suppress_ipv6_prefix) {
            INFO("suppressing ipv6 prefix on " PUB_S_SRP, interface->name);
            interface->suppress_ipv6_prefix = true;
        }
#endif

#ifndef RA_TESTER
    } else {
        INFO("didn't send: " PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP,
             partition_can_provide_routing ? "canpr" : "!canpr",
             stub_router_needed ? " stubn" : " !stubn",
             partition_has_xpanid ? " xpanid" : " !xpanid",
             interface->our_prefix_advertised ? " advert" : " !advert");
    }
#endif
    if (destination == &in6addr_linklocal_allnodes) {
        if (interface->num_beacons_sent < MAX_RA_RETRANSMISSION - 1) {
            // Schedule a beacon for between 8 and 16 seconds in the future (<MAX_INITIAL_RTR_ADVERT_INTERVAL)
            interface_beacon_schedule(interface, 8000 + srp_random16() % 8000);
        } else {
            interface_beacon_schedule(interface, icmp_listener.unsolicited_interval);
        }
        interface->num_beacons_sent++;
    }
}

static void
interface_beacon(void *context)
{
    interface_t *interface = context;
    interface_beacon_send(interface, &in6addr_linklocal_allnodes);
}

static void
interface_beacon_schedule(interface_t *interface, unsigned when)
{
    uint64_t now = ioloop_timenow();
    unsigned interval;


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
         interface->sent_first_beacon ? "" : "first ", interface->name, interval);
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
    interface->router_discovery_started = true;
}

#ifdef FLUSH_STALE_ROUTERS
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
#endif // FLUSH_STALE_ROUTERS

static void
router_discovery_stop(interface_t *interface, uint64_t now)
{
    if (!interface->router_discovery_started) {
        INFO("router discovery not yet started.");
        return;
    }
    if (!interface->router_discovery_complete) {
        INFO("router_discovery_stop: stopping router discovery on " PUB_S_SRP, interface->name);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->router_solicit_wakeup);
    }
    if (interface->post_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->post_solicit_wakeup);
    }
#if SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
    if (interface->vicarious_discovery_complete != NULL) {
        ioloop_cancel_wake_event(interface->vicarious_discovery_complete);
        INFO("router_discovery_stop: stopping vicarious router discovery on " PUB_S_SRP, interface->name);
    }
    interface->vicarious_router_discovery_in_progress = false;
#endif // SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
    interface->router_discovery_complete = true;
    interface->router_discovery_in_progress = false;
    // clear out need_reconfigure_prefix when router_discovery_complete is set back to true.
    interface->need_reconfigure_prefix = false;
#ifdef FLUSH_STALE_ROUTERS
    flush_stale_routers(interface, now);
#else
    (void)now;
#endif // FLUSH_STALE_ROUTERS

    // See if we need a new prefix on the interface.
    interface_prefix_evaluate(interface);
}

#if SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
static void
adjust_router_received_time(interface_t *const interface, const uint64_t now, const int64_t time_adjusted)
{
    icmp_message_t *router;

    if (interface->routers == NULL) {
        if (interface->our_prefix_advertised) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __ipv6_prefix);
            INFO("adjust_router_received_time: No router information available for the interface - "
                 "ifname: " PUB_S_SRP ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __ipv6_prefix));
        } else {
            INFO("adjust_router_received_time: No router information available for the interface - "
                 "ifname: " PUB_S_SRP, interface->name);
        }

        goto exit;
    }

    for (router = interface->routers; router != NULL; router = router->next) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_addr_buf);
        // Only adjust the received time once.
        if (router->received_time_already_adjusted) {
            INFO("adjust_router_received_time: received time already adjusted - remaining time: %llu, "
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
        INFO("adjust_router_received_time: router received time is adjusted - router src: " PRI_SEGMENTED_IPv6_ADDR_SRP
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
#endif // SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY

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

#ifdef FLUSH_STALE_ROUTERS
static void
stale_router_policy_evaluate(void *context)
{
    interface_t *interface = context;
    INFO("Evaluating stale routers on " PUB_S_SRP, interface->name);

    flush_stale_routers(interface, ioloop_timenow());

    // See if we need a new prefix on the interface.
    interface_prefix_evaluate(interface);

    routing_policy_evaluate(interface, true);
}
#endif // FLUSH_STALE_ROUTERS

static bool
prefix_usable(icmp_message_t *router, prefix_information_t *prefix)
{
    return ((prefix->flags & ND_OPT_PI_FLAG_ONLINK) &&
            ((prefix->flags & ND_OPT_PI_FLAG_AUTO) ||
             (config_enable_dhcpv6_prefixes && (router->flags & ND_RA_FLAG_MANAGED))) &&
            prefix->preferred_lifetime > 0);
}

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
    uint64_t stale_refresh_time = 0;

    // No action on interfaces that aren't eligible for routing or that isn't currently active.
    if (interface->ineligible || interface->inactive) {
        INFO("not evaluating policy on " PUB_S_SRP " because it's " PUB_S_SRP, interface->name,
             interface->ineligible ? "ineligible" : "inactive");
        return;
    }

    // We can't tell whether any particular prefix is usable until we've gotten the xpanid.
    if (have_xpanid_prefix) {
        // Look at all the router advertisements we've seen to see if any contain a usable prefix which is not the
        // prefix we'd advertise. Routers advertising that prefix are all Thread BRs, and it's fine for more than
        // one router to advertise a prefix, so we will also advertise it for redundancy.
        for (router = interface->routers; router; router = router->next) {
            icmp_option_t *option = router->options;
            int i;
            bool usable = false;
            for (i = 0; i < router->num_options; i++, option++) {
                if (option->type == icmp_option_prefix_information) {
                    prefix_information_t *prefix = &option->option.prefix_information;
                    if (prefix_usable(router, prefix)) {
                        // We don't consider the prefix we would advertise to be infrastructure-provided if we see it
                        // advertised by another router, because that router is also a Thread BR, and we don't want
                        // to get into dueling prefixes with it.
                        if (memcmp(&option->option.prefix_information.prefix, &xpanid_prefix, 8))
                        {
                            uint32_t preferred_lifetime_offset = MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE / MSEC_PER_SEC;
                            uint32_t preferred_lifetime = prefix->preferred_lifetime;

                            // Infinite preferred lifetime. Bogus.
                            if (preferred_lifetime == UINT32_MAX) {
                                preferred_lifetime = 60 * 60;   // One hour
                            }

                            // If the remaining time on this prefix is less than the stale time gap, use an offset that's the
                            // valid lifetime minus sixty seconds so that we have time if the prefix expires.
                            if (preferred_lifetime < preferred_lifetime_offset + 60) {
                                // If the preferred lifetime is less than a minute, we're not going to count this as a valid
                                // on-link prefix.
                                if (preferred_lifetime < 60) {
                                    SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, router_src_addr_buf);
                                    SEGMENTED_IPv6_ADDR_GEN_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf);
                                    INFO("router " PRI_SEGMENTED_IPv6_ADDR_SRP " advertising " PRI_SEGMENTED_IPv6_ADDR_SRP
                                         " has a preferred lifetime of %d, which is not enough to count as usable.",
                                         SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, router_src_addr_buf),
                                         SEGMENTED_IPv6_ADDR_PARAM_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf),
                                         preferred_lifetime);
                                    continue;
                                }
                                preferred_lifetime_offset = preferred_lifetime - 60;
                            }

                            // Lifetimes are in seconds, but henceforth we will compare with clock times, which are in ms.
                            preferred_lifetime_offset *= MSEC_PER_SEC;

                            // If the prefix' preferred lifetime plus the time received is in the past, the prefix doesn't
                            // count as an on-link prefix that's present.
                            if (router->received_time + preferred_lifetime_offset < now) {
                                SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, router_src_addr_buf);
                                SEGMENTED_IPv6_ADDR_GEN_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf);
                                INFO("router " PRI_SEGMENTED_IPv6_ADDR_SRP " advertising " PRI_SEGMENTED_IPv6_ADDR_SRP
                                     " was received %d seconds ago with a preferred lifetime of %d.",
                                     SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, router_src_addr_buf),
                                     SEGMENTED_IPv6_ADDR_PARAM_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf),
                                     (int)((now - router->received_time) / 1000), preferred_lifetime);

                                continue;
                            }

                            // This prefix is in principle usable. It may not actually be usable if it is stale, but we mark it usable so it
                            // will continue to be probed.
                            usable = true;

                            // router->reachable will be true immediately after receiving a router advertisement until we do a
                            // probe and don't get a response. It will become true again if, during a later probe, we get a
                            // response.
                            if (!router->reachable) {
                                SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, router_src_addr_buf);
                                SEGMENTED_IPv6_ADDR_GEN_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf);
                                INFO("router %p " PRI_SEGMENTED_IPv6_ADDR_SRP " advertising %d %p " PRI_SEGMENTED_IPv6_ADDR_SRP
                                     " was last known to be reachable %d seconds ago.",
                                     router,
                                     SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, router_src_addr_buf),
                                     i, option,
                                     SEGMENTED_IPv6_ADDR_PARAM_SRP(option->option.prefix_information.prefix.s6_addr, pref_buf),
                                     (int)((now - router->latest_na) / 1000));
                                continue;
                            }

                            // Otherwise, if this router's on-link prefix will expire later than any other we've seen
                            if (stale_refresh_time < router->received_time + preferred_lifetime_offset) {
                                stale_refresh_time = router->received_time + preferred_lifetime_offset;
                            }

                            // If this is a new icmp_message received now and contains PIO.
                            if (router->new_router) {
                                new_prefix = true;
                                router->new_router = false; // clear the bit since srp-mdns-proxy already processed it.
                            }

                            // This router has a usable prefix.
                            usable = true;

                            // Right now all we need is to see if there is an on-link prefix.
                            on_link_prefix_present = true;
                            SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_add_buf);
                            SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, __pio_prefix_buf);
                            INFO("router has usable PIO - ifname: " PUB_S_SRP ", router src: " PRI_SEGMENTED_IPv6_ADDR_SRP
                                 ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                                 interface->name,
                                 SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_add_buf),
                                 SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, __pio_prefix_buf));
                        } else {
                            SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, router_src_addr_buf);
                            INFO("Router " PRI_SEGMENTED_IPv6_ADDR_SRP
                                 " is advertising the xpanid prefix: not counting as usable ",
                                 SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, router_src_addr_buf));
                        }
                    } else {
                        SEGMENTED_IPv6_ADDR_GEN_SRP(router->source.s6_addr, __router_src_add_buf);
                        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, __pio_prefix_buf);
                        INFO("router has unusable PIO - ifname: " PUB_S_SRP ", router src: " PRI_SEGMENTED_IPv6_ADDR_SRP
                             ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                             interface->name,
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(router->source.s6_addr, __router_src_add_buf),
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, __pio_prefix_buf));
                    }
                }
            }
            // Remember whether or not this router has a usable prefix.
            router->usable = usable;
        }
    }

    INFO("routing_policy_evaluate: policy on " PUB_S_SRP ": " PUB_S_SRP "stale " /* stale_routers_exist ? */
         PUB_S_SRP "started " /* interface->router_discovery_started ? */
         PUB_S_SRP "disco " /* interface->router_discovery_complete ? */
         PUB_S_SRP "present " /* on_link_prefix_present ? */
         PUB_S_SRP "advert " /* interface->our_prefix_advertised ? */
         PUB_S_SRP "conf " /* interface->on_link_prefix_configured ? */
         PUB_S_SRP "new_prefix " /* new_prefix ? */
         "preferred = %" PRIu32 " valid = %" PRIu32 " deadline = %" PRIu64,
         interface->name, stale_routers_exist ? "" : "!", interface->router_discovery_started ? "" : "!",
         interface->router_discovery_complete ? "" : "!",
         on_link_prefix_present ? "" : "!", interface->our_prefix_advertised ? "" : "!",
         interface->on_link_prefix_configured ? "" : "!", new_prefix ? "" : "!",
         interface->preferred_lifetime, interface->valid_lifetime, interface->deprecate_deadline);

    // If there are stale routers, start doing router discovery again to see if we can get them to respond.
    // Note that doing router discover just because we haven't seen an RA is actually not allowed in RFC 4861,
    // so this shouldn't be enabled.
    // Also, if we have not yet done router discovery, do it now.
    if ((!interface->router_discovery_started || !interface->router_discovery_complete
#if SRP_FEATURE_STALE_ROUTER_DISCOVERY
         || stale_routers_exist
#endif //SRP_FEATURE_STALE_ROUTER_DISCOVERY
            ) && !on_link_prefix_present) {
        if (!interface->router_discovery_in_progress) {
            // Start router discovery.
            INFO("starting router discovery");
            router_discovery_start(interface);
        } else {
            INFO("routing_policy_evaluate: router discovery in progress");
        }
    }
    // If we are advertising a prefix and there's another on-link prefix, deprecate the one we are
    // advertising.
    else if (interface->our_prefix_advertised && on_link_prefix_present) {
        // If we have been advertising a preferred prefix, deprecate it.
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        if (interface->preferred_lifetime == BR_PREFIX_LIFETIME) {
            INFO("routing_policy_evaluate: deprecating interface prefix in 30 minutes - prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
            interface->deprecate_deadline = now + BR_PREFIX_LIFETIME * 1000;
            something_changed = true;
            interface->preferred_lifetime = FIVE_MINUTES;
        } else {
            INFO("routing_policy_evaluate: prefix deprecating in progress - prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
        }
    }
    // If there is no on-link prefix and we aren't advertising, or have deprecated, start advertising
    // again (or for the first time).
    else if (!on_link_prefix_present && interface->router_discovery_complete &&
             (!interface->our_prefix_advertised || interface->deprecate_deadline != 0 ||
              interface->preferred_lifetime == 0)) {

        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        INFO("routing_policy_evaluate: advertising prefix again - ifname: " PUB_S_SRP
             ", prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP, interface->name,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));

        // If we were deprecating, stop.
        ioloop_cancel_wake_event(interface->deconfigure_wakeup);
        interface->deprecate_deadline = 0;

        // Start advertising immediately, 30 minutes.
        interface->preferred_lifetime = interface->valid_lifetime = BR_PREFIX_LIFETIME;

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
            interface->our_prefix_advertised = true;
            something_changed = true;
        }
    }
    // If there is no on-link prefix present, and srp-mdns-proxy itself is advertising the prefix, and it has configured
    // an on-link prefix, and the interface is not thread interface, and it just got an interface address removal event,
    // it is possible that the IPv6 routing has been flushed due to loss of address in configd, so here we explicitly
    // reconfigure the IPv6 prefix and the routing.
    else if (interface->need_reconfigure_prefix && !on_link_prefix_present && interface->our_prefix_advertised &&
             interface->on_link_prefix_configured && !interface->is_thread) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf);
        INFO("routing_policy_evaluate: reconfigure ipv6 prefix due to possible network changes -"
             " prefix: " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(interface->ipv6_prefix.s6_addr, __prefix_buf));
        interface_prefix_configure(interface->ipv6_prefix, interface);
        interface->need_reconfigure_prefix = false;
    }

    // If the on-link prefix goes away, stop suppressing the one we've been advertising (if it's still valid).
    if (!on_link_prefix_present && interface->suppress_ipv6_prefix) {
        INFO("un-suppressing ipv6 prefix.");
        interface->suppress_ipv6_prefix = false;
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
        INFO("change on " PUB_S_SRP ": " PUB_S_SRP "started " PUB_S_SRP "disco " PUB_S_SRP "present " PUB_S_SRP "advert " PUB_S_SRP
             "conf preferred = %" PRIu32 " valid = %" PRIu32 " deadline = %" PRIu64,
             interface->name, interface->router_discovery_started ? "" : "!",
             interface->router_discovery_complete ? "" : "!", on_link_prefix_present ? "" : "!",
             interface->our_prefix_advertised ? "" : "!", interface->on_link_prefix_configured ? "" : "!",
             interface->preferred_lifetime,
             interface->valid_lifetime, interface->deprecate_deadline);
        interface->num_beacons_sent = 0;
        interface_beacon_schedule(interface, 0);
    }

    // It's possible for us to start configuring the interface because there's no on-link prefix, and then see
    // an advertisement for an on-link prefix before interface configuration completes. When this happens, we
    // need to delete the address we just configured, because we're not going to be advertising it. We always
    // get a policy re-evaluation event when interface configuration completes, so this will happen immediately.
    // At this point we have not yet sent a router advertisement with the prefix, so even though it has a preferred
    // lifetime of about 1800 seconds here, we can safely set it to zero without leaving stale information
    // in any host's routing table.
    if (!interface->our_prefix_advertised && interface->on_link_prefix_configured) {
        INFO("on-link prefix appeared during interface configuration. removing");
        interface->preferred_lifetime = 0;
        interface_prefix_deconfigure(interface);
    }

#ifdef FLUSH_STALE_ROUTERS
    // If we have an on-link prefix, schedule a policy re-evaluation at the stale router interval.
    if (on_link_prefix_present) {
        if (stale_refresh_time < now) {
            ERROR("Stale refresh time is in the past: %" PRIu64 "!", stale_refresh_time);
        } else {
            // The math used to compute refresh timeout guarantees that refresh_timeout will be <10 minutes.
            int refresh_timeout = (int)(stale_refresh_time - now);

            if (interface->stale_evaluation_wakeup == NULL) {
                interface->stale_evaluation_wakeup = ioloop_wakeup_create();
                if (interface->stale_evaluation_wakeup == NULL) {
                    ERROR("No memory for stale router evaluation wakeup on " PUB_S_SRP ".", interface->name);
                }
            } else {
                ioloop_cancel_wake_event(interface->stale_evaluation_wakeup);
            }
            ioloop_add_wake_event(interface->stale_evaluation_wakeup,
                                  interface, stale_router_policy_evaluate, NULL, refresh_timeout);
        }
    }
#endif // FLUSH_STALE_ROUTERS

    // Once router discovery is complete, start doing aliveness checks on whatever we discovered (if anything).
    if (interface->last_router_probe == 0 && interface->router_discovery_started && interface->router_discovery_complete) {
        schedule_next_router_probe(interface);
    }
}

#if SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
static void
start_vicarious_router_discovery_if_appropriate(interface_t *const interface)
{
    if (!interface->our_prefix_advertised &&
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
#endif // SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY

static void
retransmit_unicast_beacon(void *context)
{
    icmp_message_t *message = context;

    // Schedule retranmsission
    interface_beacon_send(message->interface, &message->source);
    ioloop_add_wake_event(message->wakeup, message, retransmit_unicast_beacon, NULL,
                          MIN_DELAY_BETWEEN_RAS + srp_random16() % RA_FUZZ_TIME);

    // Discontinue retransmission after the third we've sent.
    if (message->messages_sent++ > 2) {
        icmp_message_t **sp = &message->interface->solicits;
        while (*sp != NULL) {
            if (*sp == message) {
                *sp = message->next;
                icmp_message_free(message);
                break;
            } else {
                sp = &(*sp)->next;
            }
        }
    }
}

// This gets called to check to see if any of the usable routers are still responding. It gets called whenever
// we get a router solicit, to ensure that the solicit gets a quick response, and also gets called once every
// minute so that we quickly notice when a router becomes unreachable.

static void
send_router_probes(void *context)
{
    interface_t *interface = context;

    // After sending three probes, do a policy evaluation.
    if (interface->num_solicits_sent++ > MAX_NS_RETRANSMISSIONS - 1) {
        // Mark routers from which we received neighbor advertises during the probe as reachable. Routers
        // that did not respond are no longer reachable.
        for (icmp_message_t *router = interface->routers; router != NULL; router = router->next) {
            router->reachable = router->reached;
        }
        routing_policy_evaluate(interface, false);
        schedule_next_router_probe(interface);
        return;
    }

    // Send Neighbor Solicits to any usable routers that haven't responded yet and schedule the next call to
    // send_router_probes...
    for (icmp_message_t *router = interface->routers; router != NULL; router = router->next) {
        // Don't probe routers that aren't usable, and don't re-probe a router that's already responded in this probe cycle.
        if (!router->usable || router->reached) {
            continue;
        }
        neighbor_solicit_send(router->interface, &router->source);
    }
    ioloop_add_wake_event(interface->neighbor_solicit_wakeup, interface, send_router_probes, NULL,
                          MIN_DELAY_BETWEEN_RAS + srp_random16() % RA_FUZZ_TIME);
}

static void
check_router_aliveness(void *context)
{
    interface_t *interface = context;

    if (!interface->probing) {
        interface->probing = true;
        if (interface->neighbor_solicit_wakeup == NULL) {
            interface->neighbor_solicit_wakeup = ioloop_wakeup_create();
        }
        if (interface->neighbor_solicit_wakeup != NULL) {
            interface->num_solicits_sent = 0;
            // Clear the reached flag on all routers
            for (icmp_message_t *router = interface->routers; router != NULL; router = router->next) {
                router->reached = false;
            }
            send_router_probes(interface);
        }
    }
}

static void
schedule_next_router_probe(interface_t *interface)
{
    if (interface->router_probe_wakeup == NULL) {
        interface->router_probe_wakeup = ioloop_wakeup_create();
    }
    if (interface->router_probe_wakeup != NULL) {
        INFO("scheduling router probe in 60 seconds.");
        ioloop_add_wake_event(interface->router_probe_wakeup, interface, check_router_aliveness, NULL, 60 * 1000);
        interface->probing = false;
        interface->last_router_probe = ioloop_timenow();
    }
}

static void
router_solicit(icmp_message_t *message)
{
    interface_t *iface, *interface;
    bool is_retransmission = false;

    // Further validate the message
    if (message->hop_limit != 255 || message->code != 0) {
        ERROR("Invalid router solicitation, hop limit = %d, code = %d", message->hop_limit, message->code);
        goto out;
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&message->source)) {
        icmp_option_t *option = message->options;
        int i;
        for (i = 0; i < message->num_options; i++) {
            if (option->type == icmp_option_source_link_layer_address) {
                ERROR("source link layer address in router solicitation from unspecified IP address");
                goto out;
            }
            option++;
        }
    } else {
        // Make sure it's not from this host
        for (iface = interfaces; iface; iface = iface->next) {
            if (iface->have_link_layer_address && !memcmp(&message->source,
                                                          &iface->link_local, sizeof(message->source))) {
                INFO("dropping router solicitation sent from this host.");
                goto out;
            }
        }
    }
    interface = message->interface;

    SEGMENTED_IPv6_ADDR_GEN_SRP(message->source.s6_addr, source_buf);
    INFO(PUB_S_SRP " solicit on " PUB_S_SRP ": source address is " PRI_SEGMENTED_IPv6_ADDR_SRP,
         is_retransmission ? "retransmitted" : "initial",
         message->interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(message->source.s6_addr, source_buf));

    // See if this is a retransmission...
    icmp_message_t **sp;
    sp = &interface->solicits;
    while (*sp != NULL) {
        icmp_message_t *solicit = *sp;
        // Same source? Not already found?
        if (!is_retransmission && !memcmp(&message->source, &solicit->source, sizeof(message->source))) {
            uint64_t now = ioloop_timenow();
            // RFC 4861 limits RS transmissions to 3, separated by four seconds. Allowing for a bit of slop,
            // if it was received in the past 15 seconds, this is a retransmission.
            if (now - solicit->received_time > 15 * 1000) {
                *sp = solicit->next;
                icmp_message_free(solicit);
            } else {
                solicit->retransmissions_received++;
                is_retransmission = true;

                // Since this is a retransmission, that hints that there might not be any live routers
                // on this link, so check to see if the routers we are aware of are alive.
                check_router_aliveness(interface);

                sp = &(*sp)->next;
            }
        } else {
            sp = &(*sp)->next;
        }
    }

    // Schedule an immediate send. If this is a retransmission, just let our retransmission schedule
    // dictate when to send the next one.
    if (!is_retransmission && !interface->ineligible && !interface->inactive) {
        message->wakeup = ioloop_wakeup_create();
        if (message->wakeup == NULL) {
            ERROR("no memory for solicit wakeup.");
        } else {
            // Save the message for later
            *sp = message;
            // Start the unicast RA transmission train for this RS.
            retransmit_unicast_beacon(message);
            message = NULL;
        }
    } else {
        INFO("not sending a router advertisement.");
    }

#if SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
    // When we receive a router solicit, it means that a host is looking for a router.   We should
    // expect to hear replies if they are multicast.   If we hear no replies, it could mean there is
    // no on-link prefix.   In this case, we restart our own router discovery process.  There is no
    // need to do this if we are the one advertising a prefix.
    start_vicarious_router_discovery_if_appropriate(interface);
#endif // SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
out:
    if (message != NULL) {
        icmp_message_free(message);
    }
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
    int num_ras_this_router = 0;
    for (rp = &message->interface->routers; *rp != NULL; rp = &(*rp)->next) {
        router = *rp;
        // The new RA is from the same router as this previous RA.
        if (!memcmp(&router->source, &message->source, sizeof(message->source))) {
            int router_usable_prefixes = 0, message_usable_prefixes = 0;
            int prefixes_withdrawn = 0;
            int prefixes_added = 0;
            int prefixes_unchanged = 0;
            icmp_option_t *router_option = router->options;
            int i, j;

            // Remember how many RAs we have from this router.
            num_ras_this_router++;

            // Count the number of usable prefixes retained, withdrawn, and revived, as well as the total number of
            // usable prefixes in the old RA.
            for (i = 0; i < router->num_options; i++, router_option++) {
                if (router_option->type == icmp_option_prefix_information) {
                    icmp_option_t *message_option = message->options;
                    prefix_information_t *router_prefix = &router_option->option.prefix_information;
                    bool router_usable = prefix_usable(router, router_prefix);

                    if (router_usable) {
                        router_usable_prefixes++;
                    }

                    for (j = 0; j < message->num_options; j++, message_option++) {
                        if (message_option->type == icmp_option_prefix_information) {
                            prefix_information_t *message_prefix = &message_option->option.prefix_information;

                            // Same prefix?
                            if (router_prefix->length == message_prefix->length &&
                                !memcmp(&router_prefix->prefix, &message_prefix->prefix, sizeof(router_prefix->prefix)))
                            {
                                // Is it still usable?
                                message_prefix->found = true;
                                bool message_usable = prefix_usable(message, message_prefix);
                                if (router_usable && !message_usable) {
                                    prefixes_withdrawn++;
                                } else if (!router_usable && message_usable) {
                                    prefixes_added++; // Added in the sense that it became usable.
                                } else {
                                    prefixes_unchanged++;
                                }
                            }
                        }
                    }
                }
            }
            // Count the number of /new/ usable prefixes added in the new RA, and the total number of usable prefixes in
            // the new RA.
            icmp_option_t *option = message->options;
            for (i = 0; i < message->num_options; i++, option++) {
                if (option->type == icmp_option_prefix_information) {
                    prefix_information_t *prefix = &option->option.prefix_information;
                    if (prefix_usable(message, prefix)) {
                        message_usable_prefixes++;
                        if (!prefix->found) {
                            prefixes_added++;
                        }
                    }
                }
            }
            INFO("router_usable: %d  message_usable: %d  withdrawn: %d  added: %d  unchanged: %d",
                 router_usable_prefixes, message_usable_prefixes,
                 prefixes_withdrawn, prefixes_added, prefixes_unchanged);
            if (
                // We have to discard the old RA if all its prefixes were withdrawn.
                (router_usable_prefixes > 0 && prefixes_withdrawn == router_usable_prefixes) ||
                // We don't need the old RA if all the prefixes that weren't withdrawn are also in the new RA
                // This is true even if there are no un-withdrawn prefixes in the new RA.
                (router_usable_prefixes - prefixes_withdrawn == message_usable_prefixes - prefixes_added))
            {
                message->next = router->next;
                *rp = message;
                icmp_message_free(router);
                break;
            }
            // We need both otherwise, so just continue down the list.
        }
    }
    // If we got rid of the old RA, *rp will be non-NULL. If we didn't find a match for the old RA, or if we
    // need to keep the old RA, then *rp will be NULL, meaning that we should keep the new RA.
    if (*rp == NULL) {
        *rp = message;
    }

    // Limit the number of RAs we'll retain from an individual router to five (arbitrarily). This prevents weird patterns
    // of prefix adds and withdrawals from causing the list to grow without bound. Because we lose information by doing this,
    // it's possible that we could wind up advertising a usable prefix when we don't need to, but this is a safe failure
    // mode.
#define MAX_RAS_PER_ROUTER 5
    if (num_ras_this_router > MAX_RAS_PER_ROUTER) {
        for (rp = &message->interface->routers; *rp != NULL; ) {
            router = *rp;
            if (!memcmp(&router->source, &message->source, sizeof(message->source))) {
                *rp = router->next;
                icmp_message_free(router);
                // This should always be true, but it's no problem if it's not.
                if (--num_ras_this_router <= MAX_RAS_PER_ROUTER) {
                    break;
                }
            } else {
                rp = &(*rp)->next;
            }
        }
    }

    // When we receive an RA, we can assume that the router is reachable, and skip immediately probing with a
    // neighbor solicit.
    message->latest_na = message->received_time;
    message->reachable = true;

    // Something may have changed, so do a policy recalculation for this interface
    routing_policy_evaluate(message->interface, false);
}

static void
neighbor_advertisement(icmp_message_t *message)
{
    if (message->hop_limit != 255 || message->code != 0) {
        ERROR("Invalid neighbor advertisement, hop limit = %d, code = %d", message->hop_limit, message->code);
        return;
    }

    // If this NA matches a router that has advertised a usable prefix, mark the router as alive by setting the
    // "latest_na" value to the current time. We don't care about NAs for routers that are not advertising a usable
    // prefix.
    for (icmp_message_t *router = message->interface->routers; router != NULL; router = router->next) {
        if (!memcmp(&message->source, &router->source, sizeof(message->source))) {
            if (router->usable) {
                SEGMENTED_IPv6_ADDR_GEN_SRP(message->source.s6_addr, source_buf);
                INFO("usable neighbor advertisement recieved on " PUB_S_SRP " from " PRI_SEGMENTED_IPv6_ADDR_SRP,
                     message->interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(message->source.s6_addr, source_buf));
                router->latest_na = ioloop_timenow();
                router->reached = true;
                return;
            } else {
                router->latest_na = ioloop_timenow();
                router->reached = true;
                return;
            }
        }
    }
    return;
}

#ifndef FUZZING
static
#endif
void
icmp_callback(io_t *NONNULL io, void *UNUSED context)
{
    ssize_t rv;
    uint8_t icmp_buf[1500];
    unsigned offset = 0, length = 0;
    uint32_t reserved32;
    int ifindex = 0;
    addr_t src, dest;
    interface_t *interface;
    int hop_limit = 0;

#ifndef FUZZING
    rv = ioloop_recvmsg(io->fd, &icmp_buf[0], sizeof(icmp_buf), &ifindex, &hop_limit, &src, &dest);
#else
    rv = read(io->fd, &icmp_buf, sizeof(icmp_buf));
#endif
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
    INFO("length %zd", rv);

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
        // router_advertisement() is given ownership of the message
        return;

    case icmp_type_router_solicitation:
        if (!dns_u32_parse(icmp_buf, length, &offset, &reserved32)) {
            goto out;
        }
        if (!icmp_message_parse_options(message, icmp_buf, length, &offset)) {
            goto out;
        }
        icmp_message_dump(message, &message->source, &message->destination);
        router_solicit(message);
        // router_solicit() is given ownership of the message.
        return;

    case icmp_type_neighbor_advertisement:
        icmp_message_dump(message, &message->source, &message->destination);
        neighbor_advertisement(message);
        break;

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

#if   defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IPCONFIG) || \
      defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IFCONFIG)
static void
link_route_done(void *context, int status, const char *error)
{
    interface_t *interface = context;

    if (error != NULL) {
        ERROR("link_route_done on " PUB_S_SRP ": " PUB_S_SRP, interface->name, error);
    } else {
        INFO("link_route_done on " PUB_S_SRP ": %d.", interface->name, status);
    }
    ioloop_subproc_release(interface->link_route_adder_process);
    interface->link_route_adder_process = NULL;
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
    char addrbuf[INET6_ADDRSTRLEN + 4];
    // Use our ULA prefix as the host identifier.
    memcpy(&interface_address.s6_addr[10], &ula_prefix.s6_addr[0], 6);
    inet_ntop(AF_INET6, &interface_address, addrbuf, INET6_ADDRSTRLEN);
#if   defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IPCONFIG)
    char *args[] = { "set", interface->name, "MANUAL-V6", addrbuf, "64" };

    if (interface->link_route_adder_process != NULL) {
        ERROR("interface_prefix_configure: " PUB_S_SRP " already configuring the route.", interface->name);
        return;
    }
    INFO("interface_prefix_configure: /sbin/ipconfig " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " " PUB_S_SRP " "
         PUB_S_SRP, args[0], args[1], args[2], args[3], args[4]);
    interface->link_route_adder_process = ioloop_subproc("/usr/sbin/ipconfig", args, 5, link_route_done, interface, NULL);
    if (interface->link_route_adder_process == NULL) {
        ERROR("interface_prefix_configure: unable to set interface address for %s to %s.", interface->name, addrbuf);
    }
#elif defined(CONFIGURE_STATIC_INTERFACE_ADDRESSES_WITH_IFCONFIG)
    char *eos = addrbuf + strlen(addrbuf);
    if (sizeof(addrbuf) - (eos - addrbuf) < 4) {
        ERROR("interface_prefix_configure: this shouldn't happen: no space in addrbuf");
        return;
    }
    strcpy(eos, "/64");
    char *args[] = { interface->name, "add", addrbuf };

    if (interface->link_route_adder_process != NULL) {
        ERROR("interface_prefix_configure: " PUB_S_SRP " already configuring the route.", interface->name);
        return;
    }
    INFO("interface_prefix_configure: /sbin/ifconfig %s %s %s", args[0], args[1], args[2]);
    interface->link_route_adder_process = ioloop_subproc("/sbin/ifconfig", args, 3, link_route_done, NULL, interface);
    if (interface->link_route_adder_process == NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface_address.s6_addr, if_addr_buf);
        ERROR("interface_prefix_configure: unable to set interface address for " PUB_S_SRP " to "
              PRI_SEGMENTED_IPv6_ADDR_SRP ".", interface->name,
              SEGMENTED_IPv6_ADDR_PARAM_SRP(interface_address.s6_addr, if_addr_buf));
    }
#else
    struct in6_aliasreq alias_request;
    int ret;

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
    close(sock);
}

#ifdef USE_SYSCTL_COMMAND_TO_ENABLE_FORWARDING
static void
thread_forwarding_done(void *UNUSED context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_forwarding_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_forwarding_done: %d.", status);
    }
    ioloop_subproc_release(thread_forwarding_setter_process);
    thread_forwarding_setter_process = NULL;
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
#ifdef LINUX
    const char *procfile = "/proc/sys/net/ipv6/conf/all/forwarding";
    int fd = open(procfile, O_WRONLY);
    if (fd < 0) {
        ERROR("set_thread_forwarding: %s: %s", procfile, strerror(errno));
    } else {
        ssize_t ret = write(fd, "1", 1);
        if (ret < 0) {
            ERROR("set_thread_forwarding: write: %s", strerror(errno));
        } else if (ret != 1) {
            ERROR("set_thread_forwarding: invalid write: %zd", ret);
        }
        close(fd);
    }
#else
    int wun = 1;
    int ret = sysctlbyname("net.inet6.ip6.forwarding", NULL, 0, &wun, sizeof(wun));
    if (ret < 0) {
        ERROR("set_thread_forwarding: " PUB_S_SRP, strerror(errno));
    } else {
        INFO("Enabled IPv6 forwarding.");
    }
#endif
}
#endif // USE_SYSCTL_COMMAND_TO_ENABLE_FORWARDING

#ifdef NEED_THREAD_RTI_SETTER
static void
thread_rti_done(void *UNUSED context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_rti_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_rti_done: %d.", status);
    }
    ioloop_subproc_release(thread_rti_setter_process);
    thread_rti_setter_process = NULL;
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

#if defined(THREAD_BORDER_ROUTER) && !defined(RA_TESTER)
#ifdef ADD_PREFIX_WITH_WPANCTL
static void
thread_prefix_done(void *UNUSED context, int status, const char *error)
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
    thread_prefix_adder_process = NULL;
}
#endif

static void
cti_add_prefix_callback(void *UNUSED context, cti_status_t status)
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
    int status = cti_add_prefix(NULL, cti_add_prefix_callback, NULL,
                                &advertised_thread_prefix->prefix, advertised_thread_prefix->prefix_len,
                                true, true, true, true);
    if (status != kCTIStatus_NoError) {
        ERROR("Unable to add thread interface prefix.");
    }
#endif
}
#endif // THREAD_BORDER_ROUTRER && !RA_TESTER

static void
router_advertisement_send(interface_t *interface, const struct in6_addr *destination)
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
        ERROR("router_advertisement_send: unable to construct ICMP Router Advertisement: no memory");
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
    dns_u16_to_wire(&towire, BR_PREFIX_LIFETIME); // Router lifetime, hacked.  This shouldn't ever be enabled.
#else
#ifdef RA_TESTER
    // Advertise a default route on the simulated thread network
    if (!strcmp(interface->name, thread_interface_name)) {
        dns_u16_to_wire(&towire, BR_PREFIX_LIFETIME); // Router lifetime for default route
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
        INFO("router_advertisement_send: advertising source lladdr " PRI_MAC_ADDR_SRP
             " on " PUB_S_SRP, MAC_ADDR_PARAM_SRP(interface->link_layer), interface->name);
    }

#ifndef RA_TESTER
    // Send MTU of 1280 for Thread?
    if (interface->is_thread) {
        dns_u8_to_wire(&towire, ND_OPT_MTU);
        dns_u8_to_wire(&towire, 1); // length / 8
        dns_u32_to_wire(&towire, 1280);
        INFO("router_advertisement_send: advertising MTU of 1280 on " PUB_S_SRP, interface->name);
    }
#endif

    // Send Prefix Information option if there's no IPv6 on the link.
    if (interface->our_prefix_advertised && !interface->suppress_ipv6_prefix) {
        dns_u8_to_wire(&towire, ND_OPT_PREFIX_INFORMATION);
        dns_u8_to_wire(&towire, 4); // length / 8
        dns_u8_to_wire(&towire, 64); // On-link prefix is always 64 bits
        dns_u8_to_wire(&towire, ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO); // On link, autoconfig
        dns_u32_to_wire(&towire, interface->valid_lifetime);
        dns_u32_to_wire(&towire, interface->preferred_lifetime);
        dns_u32_to_wire(&towire, 0); // Reserved
        dns_rdata_raw_data_to_wire(&towire, &interface->ipv6_prefix, sizeof interface->ipv6_prefix);
        SEGMENTED_IPv6_ADDR_GEN_SRP(interface->ipv6_prefix.s6_addr, ipv6_prefix_buf);
        INFO("router_advertisement_send: advertising on-link prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " on " PUB_S_SRP,
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
        if (want_routing() &&
            ifroute->our_prefix_advertised &&
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
            dns_u32_to_wire(&towire, BR_PREFIX_LIFETIME); // Route lifetime 1800 seconds (30 minutes)
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
        dns_u32_to_wire(&towire, BR_PREFIX_LIFETIME); // Route lifetime 1800 seconds (30 minutes)
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
    dns_u32_to_wire(&towire, BR_PREFIX_LIFETIME); // Route lifetime 1800 seconds (30 minutes)
    dns_rdata_raw_data_to_wire(&towire, &ula_prefix, 16); // /48 requires 16 bytes
#endif // SKIP_SLASH_48
#endif // SEND_INTERFACE_SPECIFIC_RIOS

    if (towire.error) {
        ERROR("No space in ICMP output buffer for " PUB_S_SRP " at route.c:%d", interface->name, towire.line);
        towire.error = 0;
    } else {
        SEGMENTED_IPv6_ADDR_GEN_SRP(destination->s6_addr, destination_buf);
        INFO("sending advertisement to " PRI_SEGMENTED_IPv6_ADDR_SRP " on " PUB_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(destination->s6_addr, destination_buf),
             interface->name);
        icmp_send(message, towire.p - message, interface, destination);
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
neighbor_solicit_send(interface_t *interface, struct in6_addr *destination)
{
    uint8_t *message;
    dns_towire_state_t towire;

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
    dns_u8_to_wire(&towire, ND_NEIGHBOR_SOLICIT);  // icmp6_type
    dns_u8_to_wire(&towire, 0);                    // icmp6_code
    dns_u16_to_wire(&towire, 0);                   // The kernel computes the checksum (we don't technically have it).
    dns_u32_to_wire(&towire, 0);                   // Reserved32
    dns_rdata_raw_data_to_wire(&towire, destination, sizeof(*destination)); // Target address of solicit

    // Send Source link-layer address option
    if (interface->have_link_layer_address) {
        dns_u8_to_wire(&towire, ND_OPT_SOURCE_LINKADDR);
        dns_u8_to_wire(&towire, 1); // length / 8
        dns_rdata_raw_data_to_wire(&towire, &interface->link_layer, sizeof(interface->link_layer));
    }

    if (towire.error) {
        ERROR("No space in ICMP output buffer for " PUB_S_SRP " at route.c:%d", interface->name, towire.line);
    } else {
        SEGMENTED_IPv6_ADDR_GEN_SRP(destination, dest_buf);
        INFO("sending neighbor solicit on " PUB_S_SRP " to " PRI_SEGMENTED_IPv6_ADDR_SRP,
             interface->name, SEGMENTED_IPv6_ADDR_PARAM_SRP(destination, dest_buf));
        icmp_send(message, towire.p - message, interface, destination);
    }
    free(message);
}

static void
icmp_send(uint8_t *message, size_t length, interface_t *interface, const struct in6_addr *destination)
{
#ifdef FUZZING
    char buffer[length];
    memcpy(buffer, message, length);
    return;
#endif
    struct iovec iov;
    struct in6_pktinfo *packet_info;
    socklen_t cmsg_length = CMSG_SPACE(sizeof(*packet_info)) + CMSG_SPACE(sizeof (int));
    uint8_t *cmsg_buffer;
    struct msghdr msg_header;
    struct cmsghdr *cmsg_pointer;
    int hop_limit = 255;
    ssize_t rv;
    struct sockaddr_in6 dest;

    // Make space for the control message buffer.
    cmsg_buffer = calloc(1, cmsg_length);
    if (cmsg_buffer == NULL) {
        ERROR("Unable to construct ICMP Router Advertisement: no memory");
        return;
    }

    // Send the message
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    dest.sin6_scope_id = interface->index;
#ifndef NOT_HAVE_SA_LEN
    dest.sin6_len = sizeof(dest);
#endif
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
    cmsg_pointer->cmsg_len = CMSG_LEN(sizeof(*packet_info));
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
#ifdef FLUSH_STALE_ROUTERS
    flush_stale_routers(interface, ioloop_timenow());
#endif // FLUSH_STALE_ROUTERS

    // See if we need a new prefix on the interface.
    interface_prefix_evaluate(interface);

    routing_policy_evaluate(interface, true);
    // Always clear out need_reconfigure_prefix when router_discovery_complete is set to true.
    interface->need_reconfigure_prefix = false;
}


static void
ula_record(const char *ula_printable)
{
    size_t len = strlen(ula_printable);
    if (access(THREAD_DATA_DIR, F_OK) < 0) {
        if (mkdir(THREAD_DATA_DIR, 0700) < 0) {
            ERROR("ula_record: " THREAD_DATA_DIR " not present and can't be created: %s", strerror(errno));
            return;
        }
    }
    srp_store_file_data(NULL, THREAD_ULA_FILE, (uint8_t *)ula_printable, len);
}

void
route_ula_generate(void)
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
    srp_randombytes(&ula_prefix.s6_addr[1], 5);
    ula_prefix.s6_addr[0] = 0xfd;

    inet_ntop(AF_INET6, &ula_prefix, ula_prefix_buffer, sizeof ula_prefix_buffer);

    ula_record(ula_prefix_buffer);
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
#if SRP_FEATURE_NAT64
    if (srp_nat64_enabled) {
        nat64_set_ula_prefix(&ula_prefix);
    }
#endif
}

void
route_ula_setup(void)
{
    bool have_stored_ula_prefix = false;

    char ula_buf[INET6_ADDRSTRLEN];
    uint16_t length;
    if (srp_load_file_data(NULL, THREAD_ULA_FILE, (uint8_t *)ula_buf, &length, sizeof(ula_buf) - 1)) {
        ula_buf[length] = 0;
        if (inet_pton(AF_INET6, ula_buf, &ula_prefix)) {
            have_stored_ula_prefix = true;
        } else {
            INFO("ula prefix %.*s is not valid", length, ula_buf);
        }
    } else {
        INFO("Couldn't open ULA file " THREAD_ULA_FILE ".");
    }

    // If we didn't already successfully fetch a stored prefix, try to store one.
    if (!have_stored_ula_prefix) {
        route_ula_generate();
    } else {
        // Set up the thread prefix.
        my_thread_prefix = ula_prefix;
        have_thread_prefix = true;
#if SRP_FEATURE_NAT64
        if (srp_nat64_enabled) {
            nat64_set_ula_prefix(&ula_prefix);
        }
#endif
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
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
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
    icmp_listener.unsolicited_interval = 3 * 60 * 1000;
    ioloop_add_reader(icmp_listener.io_state, icmp_callback);

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
        INFO(PUB_S_SRP "subscribed on interface " PUB_S_SRP, added ? "" : "un",
             interface->name);
    }

    req.ipv6mr_multiaddr = in6addr_linklocal_allnodes;
    req.ipv6mr_interface = interface->index;
    rv = setsockopt(icmp_listener.io_state->fd, IPPROTO_IPV6, added ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &req,
                    sizeof req);
    if (rv < 0) {
        ERROR("Unable to " PUB_S_SRP " all-nodes multicast group on " PUB_S_SRP ": " PUB_S_SRP,
              added ? "join" : "leave", interface->name, strerror(errno));
        return;
    } else {
        INFO(PUB_S_SRP "subscribed on interface " PUB_S_SRP, added ? "" : "un",
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
        if (interface != NULL) {
            if (thread_interface_name != NULL && !strcmp(name, thread_interface_name)) {
                interface->is_thread = true;
            }
            *p_interface = interface;
        }
    }
    return interface;
}


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
    if (interface->stale_evaluation_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->stale_evaluation_wakeup);
    }
    if (interface->router_solicit_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->router_solicit_wakeup);
    }
    if (interface->deconfigure_wakeup != NULL) {
        ioloop_cancel_wake_event(interface->deconfigure_wakeup);
    }
#if SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
    if (interface->vicarious_discovery_complete != NULL) {
        ioloop_cancel_wake_event(interface->vicarious_discovery_complete);
    }
    interface->vicarious_router_discovery_in_progress = false;
#endif // SRP_FEATURE_VICARIOUS_ROUTER_DISCOVERY
    for (router = interface->routers; router; router = next) {
        next = router->next;
        icmp_message_free(router);
    }
    interface->routers = NULL;
    interface->last_beacon = interface->next_beacon = 0;
    interface->deprecate_deadline = 0;
    interface->preferred_lifetime = interface->valid_lifetime = 0;
    interface->num_solicits_sent = 0;
    interface->inactive = true;
    interface->ineligible = true;
    interface->our_prefix_advertised = false;
    interface->suppress_ipv6_prefix = false;
    interface->have_link_layer_address = false;
    interface->on_link_prefix_configured = false;
    interface->sent_first_beacon = false;
    interface->num_beacons_sent = 0;
    interface->router_discovery_started = false;
    interface->router_discovery_complete = false;
    interface->router_discovery_in_progress = false;
    interface->need_reconfigure_prefix = false;
}

static void
interface_prefix_evaluate(interface_t *interface)
{
    // Set up the interface prefix using the prefix number for the link.
    interface->ipv6_prefix = xpanid_prefix;
}

static void
interface_active_state_evaluate(interface_t *interface, bool active_known, bool active)
{
    INFO("evaluating interface active status - ifname: " PUB_S_SRP
         ", active_known: " PUB_S_SRP ", active: " PUB_S_SRP ", inactive: " PUB_S_SRP,
         interface->name, active_known ? "true" : "false", active ? "true" : "false",
         interface->inactive ? "true" : "false");

    if (active_known && !active) {
        if (!interface->inactive) {
#ifndef RA_TESTER
            bool active_infrastructure = false;
            for (interface_t *scan = interfaces; scan != NULL; scan = scan->next) {
                if (scan != interface && !scan->inactive && !scan->ineligible) {
                    active_infrastructure = true;
                }
            }
            // Don't be a border router if there is no infrastructure interface left.
            if (thread_network_running && !active_infrastructure && !interface->inactive && !interface->ineligible) {
                INFO("interface " PUB_S_SRP " went away, and there is no other infrastructure interface: shutting down thread network",
                     interface->name);

                thread_network_shutdown();
            } else {
                INFO("interface " PUB_S_SRP " went away, "
                     PUB_S_SRP "thread " PUB_S_SRP "infra " PUB_S_SRP "inactive " PUB_S_SRP "ineligible.",
                     interface->name,
                     thread_network_running ? "" : "!", active_infrastructure ? "" : "!",
                     interface->inactive ? "" : "!", interface->ineligible ? "" : "!");
            }
#else // RA_TESTER
            INFO("interface " PUB_S_SRP " went away.", interface->name);
#endif
            // Set up the thread-local prefix
            interface_prefix_evaluate(interface);

            // We need to reevaluate routing policy on the new primary interface now, because
            // there may be no new event there to trigger one.
            routing_policy_evaluate(interface, true);

            // Clean the slate.
            icmp_interface_subscribe(interface, false);
            interface_shutdown(interface);

            // Zero IPv4 addresses.
            interface->num_ipv4_addresses = 0;

#if !defined(RA_TESTER) && SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY && SRP_FEATURE_DYNAMIC_CONFIGURATION
            // Clear the corresponding served_domain_t in dnssd-proxy that is associated with this removed interface.
            delete_served_domain_by_interface_name(interface->name);
#endif

            INFO("interface went down - ifname: " PUB_S_SRP, interface->name);
        }
    } else if (active_known) {
        if (interface->inactive) {
#ifndef RA_TESTER
            bool active_infrastructure = false;
            for (interface_t *scan = interfaces; scan != NULL; scan = scan->next) {
                if (scan != interface && !scan->inactive && !scan->ineligible) {
                    active_infrastructure = true;
                }
            }
            // If this is the first infrastructure interface to show up, start the thread network
            if (!thread_network_running && !active_infrastructure && interface->inactive && !interface->ineligible) {
                INFO("interface " PUB_S_SRP " showed up, and there is no other infrastructure interface: starting thread network",
                     interface->name);
                thread_network_startup();
            } else {
                INFO("interface " PUB_S_SRP " showed up, "
                     PUB_S_SRP "thread " PUB_S_SRP "infra " PUB_S_SRP "inactive " PUB_S_SRP "ineligible.",
                     interface->name,
                     thread_network_running ? "" : "!", active_infrastructure ? "" : "!",
                     interface->inactive ? "" : "!", interface->ineligible ? "" : "!");
            }
#else // !RA_TESTER
            INFO("interface " PUB_S_SRP " showed up.", interface->name);
#endif
#ifdef RA_TESTER
            if (!strcmp(interface->name, thread_interface_name) || !strcmp(interface->name, home_interface_name)) {
#endif
                // Zero IPv4 addresses.
                interface->num_ipv4_addresses = 0;

                icmp_interface_subscribe(interface, true);
                interface->inactive = false;

                interface_prefix_evaluate(interface);
                if (want_routing()) {
                    INFO("starting router discovery");
                    router_discovery_start(interface);

                    // If we already have a thread prefix, trigger beaconing now.
                    if (published_thread_prefix != NULL || adopted_thread_prefix != NULL) {
                        interface_beacon_schedule(interface, 0);
                    } else {
                        INFO("No prefix on thread network, so not scheduling beacon.");
                    }
                } else {
                    INFO("Can't provide routing, so not scheduling beacon.");
                }
#ifdef RA_TESTER
            } else {
                INFO("skipping interface " PUB_S_SRP " because it's not home or thread.", interface->name);
            }
#endif
        }
    }
}


static void
ifaddr_callback(void *UNUSED context, const char *name, const addr_t *address, const addr_t *mask,
                unsigned flags, enum interface_address_change change)
{
    char addrbuf[INET6_ADDRSTRLEN];
    const uint8_t *addrbytes, *maskbytes, *prefp;
    int preflen, i;
    interface_t *interface;

#ifndef POSIX_BUILD
    interface = find_interface(name, -1);
#else
    interface = find_interface(name, if_nametoindex(name));
#endif
    if (interface == NULL) {
        ERROR("ifaddr_callback: find_interface returned NULL for " PUB_S_SRP, name);
        return;
    }

    const bool is_thread_interface = interface->is_thread;

    if (address->sa.sa_family == AF_INET) {
        addrbytes = (uint8_t *)&address->sin.sin_addr;
        maskbytes = (uint8_t *)&mask->sin.sin_addr;
        prefp = maskbytes + 3;
        preflen = 32;
        if (change == interface_address_added) {
            // Just got an IPv4 address?
            if (!interface->num_ipv4_addresses) {
                if (!(flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) {
                    interface_prefix_evaluate(interface);
                }
            }
            interface->num_ipv4_addresses++;
        } else if (change == interface_address_deleted) {
            interface->num_ipv4_addresses--;
            // Just lost our last IPv4 address?
            if (!(flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) {
                if (!interface->num_ipv4_addresses) {
                    interface_prefix_evaluate(interface);
                }
            }
        }
    } else if (address->sa.sa_family == AF_INET6) {
        addrbytes = (uint8_t *)&address->sin6.sin6_addr;
        maskbytes = (uint8_t *)&mask->sin6.sin6_addr;
        prefp = maskbytes + 15;
        preflen = 128;
#ifndef LINUX
    } else if (address->sa.sa_family == AF_LINK) {
        snprintf(addrbuf, sizeof addrbuf, "%02x:%02x:%02x:%02x:%02x:%02x",
                 address->ether_addr.addr[0], address->ether_addr.addr[1],
                 address->ether_addr.addr[2], address->ether_addr.addr[3],
                 address->ether_addr.addr[4], address->ether_addr.addr[5]);
        prefp = (uint8_t *)&addrbuf[0]; maskbytes = prefp + 1; // Skip prefix length calculation
        preflen = 0;
        addrbytes = NULL;
#endif
    } else {
        INFO("ifaddr_callback: Unknown address type %d", address->sa.sa_family);
        return;
    }

    if (change != interface_address_unchanged) {
#ifndef LINUX
        if (address->sa.sa_family == AF_LINK) {
            if (!interface->ineligible) {
                INFO("ifaddr_callback: interface " PUB_S_SRP PUB_S_SRP " " PUB_S_SRP " " PRI_MAC_ADDR_SRP " flags %x",
                     name, is_thread_interface ? " (thread)" : "",
                     change == interface_address_added ? "added" : "removed",
                     MAC_ADDR_PARAM_SRP(address->ether_addr.addr), flags);
            }
        } else {
#endif
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

                // Only notify dnssd-proxy when srp-mdns-proxy and dnssd-proxy is combined together.
            #if !defined(RA_TESTER) && (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)
                // Notify dnssd-proxy that address is added or removed.
                if (!is_thread_interface) {
                    if (change == interface_address_added) {
                        if (!interface->inactive) {
                            dnssd_proxy_ifaddr_callback(context, name, address, mask, flags, change);
                        }
                    } else { // change == interface_address_removed
                        dnssd_proxy_ifaddr_callback(context, name, address, mask, flags, change);
                    }
                }
            #endif // #if !defined(RA_TESTER) && (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)

                // When new IP address is removed, it is possible that the existing router information, such as
                // PIO and RIO is no longer valid since srp-mdns-proxy is losing its IP address. In order to let it to
                // flush the stale router information as soon as possible, we mark all the router as stale immediately,
                // by setting the router received time to a value which is 601s ago (router will be stale if the router
                // information is received for more than 600s). And then do router discovery for 20s, so we can ensure
                // that all the stale router information will be updated during the discovery, or flushed away. If all
                // routers are flushed, then srp-mdns-proxy will advertise its own prefix and configure the new IPv6
                // address.
                if ((address->sa.sa_family == AF_INET || address->sa.sa_family == AF_INET6) &&
                    change == interface_address_deleted)
                {
#ifdef VICARIOUS_ROUTER_DISCOVERY
                    INFO("making all routers stale and start router discovery due to removed address");
                    adjust_router_received_time(interface, ioloop_timenow(),
                                                -(MAX_ROUTER_RECEIVED_TIME_GAP_BEFORE_STALE + MSEC_PER_SEC));
#endif
                    // Explicitly set router_discovery_complete to false so we can ensure that srp-mdns-proxy will start
                    // the router discovery immediately.
                    interface->router_discovery_complete = false;
                    interface->router_discovery_started = false;
                    // Set need_reconfigure_prefix to true to let routing_policy_evaluate know that the router discovery
                    // is caused by interface removal event, so when the router discovery finished and nothing changes,
                    // it can reconfigure the IPv6 routing in case configured does not handle it correctly.
                    interface->need_reconfigure_prefix = true;
                    routing_policy_evaluate(interface, false);
                }
            }
#ifndef LINUX
        }
#endif
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

#if defined(THREAD_BORDER_ROUTER) && !defined(RA_TESTER)
    if (is_thread_interface && address->sa.sa_family == AF_INET6) {
        partition_utun0_address_changed(&address->sin6.sin6_addr, change);
    }
#endif

    if (address->sa.sa_family == AF_INET) {
    } else if (address->sa.sa_family == AF_INET6) {
        if (IN6_IS_ADDR_LINKLOCAL(&address->sin6.sin6_addr)) {
            interface->link_local = address->sin6.sin6_addr;
        }
#ifndef LINUX
    } else if (address->sa.sa_family == AF_LINK) {
        if (address->ether_addr.len == 6) {
            memcpy(interface->link_layer, address->ether_addr.addr, 6);
            interface->have_link_layer_address = true;
        }
#endif
    }
#if defined(POSIX_BUILD)
    interface_active_state_evaluate(interface, true, true);
#endif
}

static void
refresh_interface_list(void)
{
    interface_t *interface;
    bool UNUSED have_active = false;
    ioloop_map_interface_addresses(NULL, NULL, ifaddr_callback);
    for (interface = interfaces; interface; interface = interface->next) {
        if (!interface->ineligible && !interface->inactive) {
            have_active = true;
        }
    }

#ifndef RA_TESTER
    // Notice if we have lost or gained infrastructure.
    if (have_active && !have_non_thread_interface) {
        INFO("we have an active interface");
        have_non_thread_interface = true;
        partition_can_advertise_service = true;
    } else if (!have_active && have_non_thread_interface) {
        INFO("we no longer have an active interface");
        have_non_thread_interface = false;
        // Stop advertising the service, if we are doing so.
        partition_discontinue_srp_service();
    }
#endif // RA_TESTER
}


#if defined(THREAD_BORDER_ROUTER) && !defined(RA_TESTER)
#ifdef GET_TUNNEL_NAME_WITH_WPANCTL
static void
thread_interface_output(io_t *io, void *UNUSED context)
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
thread_interface_done(void *UNUSED context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("thread_interface_done: " PUB_S_SRP, error);
    } else {
        INFO("thread_interface_done: %d.", status);
    }
    ioloop_subproc_release(thread_interface_enumerator_process);
    thread_interface_enumerator_process = NULL;
}
#endif // GET_TUNNEL_NAME_WITH_WPANCTL

#if !defined(RA_TESTER)
#if defined(POSIX_BUILD)
static void
wpan_reconnect_wakeup_callback(void *UNUSED context)
{
    if (wpan_reconnect_wakeup != NULL) {
        ioloop_wakeup_release(wpan_reconnect_wakeup);
        wpan_reconnect_wakeup = NULL;
    }
    // Attempt to restart the thread network...
    infrastructure_network_startup();
}
#endif

static void
attempt_wpan_reconnect(void)
{
#if defined(POSIX_BUILD)
    if (wpan_reconnect_wakeup == NULL) {
        wpan_reconnect_wakeup = ioloop_wakeup_create();
        if (wpan_reconnect_wakeup == NULL) {
            ERROR("attempt_wpan_reconnect: can't allocate wpan reconnect wait wakeup.");
            return;
        }
        INFO("attempt_wpan_reconnect: delaying for ten seconds before attempt to reconnect to thread daemon.");
        ioloop_add_wake_event(wpan_reconnect_wakeup, NULL, wpan_reconnect_wakeup_callback, NULL, 10 * 1000);
        partition_state_reset();
#endif
    }
}
#endif // RA_TESTER

static void
cti_get_tunnel_name_callback(void *UNUSED context, const char *name, cti_status_t status)
{
    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_tunnel_name_callback: disconnected");
        attempt_wpan_reconnect();
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
cti_get_role_callback(void *UNUSED context, cti_network_node_type_t role, cti_status_t status)
{
    bool am_thread_router = false;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_role_callback: disconnected");
        attempt_wpan_reconnect();
        return;
    }

    if (status == kCTIStatus_NoError) {
        partition_last_role_change = ioloop_timenow();

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
cti_get_state_callback(void *UNUSED context, cti_network_state_t state, cti_status_t status)
{
    bool associated = false;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_state_callback: disconnected");
        attempt_wpan_reconnect();
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
cti_get_partition_id_callback(void *UNUSED context, uint64_t partition_id, cti_status_t status)
{
    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("disconnected");
        attempt_wpan_reconnect();
        return;
    }

    if (status == kCTIStatus_NoError) {
        INFO("Partition ID changed to %" PRIu64, partition_id);
        // Partition ID is actually only 32 bits
        thread_partition_id[0] = (uint8_t)((partition_id >> 24) & 255);
        thread_partition_id[1] = (uint8_t)((partition_id >> 16) & 255);
        thread_partition_id[2] = (uint8_t)((partition_id >> 8) & 255);
        thread_partition_id[3] = (uint8_t)(partition_id & 255);

        partition_id_changed();
    } else {
        ERROR("nonzero status %d", status);
    }
}

static void
re_evaluate_interfaces(void)
{
    for (interface_t *interface = interfaces; interface != NULL; interface = interface->next) {
        interface_prefix_evaluate(interface);
    }

    partition_maybe_enable_services();
}

static void
cti_get_xpanid_callback(void *UNUSED context, uint64_t new_xpanid, cti_status_t status)
{
    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("disconnected");
        attempt_wpan_reconnect();
        return;
    }

    if (status == kCTIStatus_NoError) {
        if (partition_has_xpanid) {
            ERROR("Unexpected change to XPANID from %" PRIu64 " to %" PRIu64, xpanid, new_xpanid);
        } else {
            INFO("XPANID is now %" PRIu64, new_xpanid);
        }
    } else {
        ERROR("nonzero status %d", status);
        return;
    }

    xpanid = new_xpanid;
    partition_has_xpanid = true;
    memset(&xpanid_prefix, 0, sizeof(xpanid_prefix));
    xpanid_prefix.s6_addr[0] = 0xfd;
    for (int i = 1; i < 8; i++) {
        xpanid_prefix.s6_addr[i] = ((xpanid >> ((15 - i) * 8)) & 255);
    }
    have_xpanid_prefix = true;
    re_evaluate_interfaces();
}

void
route_evaluate_registration(int rrtype, const uint8_t *rdata, size_t rdlen)
{
    // If we've already enabled the stub router, or this isn't an aaaa record, do nothing.
    if (stub_router_needed || rrtype != dns_rrtype_aaaa || rdlen != 16) {
        return;
    }
    // See if the address being advertised is on a thread prefix
    for (thread_prefix_t *prefix = thread_prefixes; prefix != NULL; prefix = prefix->next) {
        if (!memcmp(&prefix->prefix, rdata, 8)) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(&prefix->prefix, prefix_buf);
            SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, rdata_buf);
            INFO("host address " PRI_SEGMENTED_IPv6_ADDR_SRP " is on thread prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, rdata_buf),
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(&prefix->prefix, prefix_buf));
            stub_router_needed = true;
            re_evaluate_interfaces();
            return;
        }
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
cti_service_list_callback(void *UNUSED context, cti_service_vec_t *services, cti_status_t status)
{
    size_t i;
    thread_service_t **pservice = &thread_services, *service = NULL;
    thread_pref_id_t **ppref_id = &thread_pref_ids, *pref_id = NULL;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_service_list_callback: disconnected");
        attempt_wpan_reconnect();
        return;
    }

    if (status != kCTIStatus_NoError) {
        ERROR("cti_service_list_callback: %d", status);
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
cti_prefix_list_callback(void *UNUSED context, cti_prefix_vec_t *prefixes, cti_status_t status)
{
    size_t i;
    thread_prefix_t **ppref = &thread_prefixes, *prefix = NULL;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_prefix_list_callback: disconnected");
        attempt_wpan_reconnect();
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
#endif // THREAD_BORDER_ROUTER && !RA_TESTER

#ifdef TCPDUMP_LOGGER
static void
tcpdump_output(io_t *io, void *UNUSED context)
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
tcpdump_done(void *UNUSED context, int status, const char *error)
{
    if (error != NULL) {
        ERROR("tcpdump_done: " PUB_S_SRP, error);
    } else {
        INFO("tcpdump_done: %d.", status);
    }
    ioloop_subproc_release(tcpdump_logger_process);
    tcpdump_logger_process = NULL;
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
infrastructure_network_startup(void)
{
    INFO("Thread network started.");

//    ioloop_network_watcher_start(network_watch_event);
    set_thread_forwarding();
#ifdef TCPDUMP_LOGGER
    start_tcpdump_logger();
#endif
}

#if defined(THREAD_BORDER_ROUTER) && !defined(RA_TESTER)
static void
thread_network_startup(void)
{
    get_thread_interface_list();

    int status = cti_get_state(&thread_state_context, NULL, cti_get_state_callback, NULL);
    if (status == kCTIStatus_NoError) {
        status = cti_get_network_node_type(&thread_role_context, NULL, cti_get_role_callback, NULL);
    }
    if (status == kCTIStatus_NoError) {
        status = cti_get_service_list(&thread_service_context, NULL, cti_service_list_callback, NULL);
    }
    if (status == kCTIStatus_NoError) {
        status = cti_get_prefix_list(&thread_prefix_context, NULL, cti_prefix_list_callback, NULL);
    }
    if (status == kCTIStatus_NoError) {
        status = cti_get_tunnel_name(NULL, cti_get_tunnel_name_callback, NULL);
    }
    if (status == kCTIStatus_NoError) {
        status = cti_get_partition_id(&thread_partition_id_context, NULL, cti_get_partition_id_callback, NULL);
    }
    if (status == kCTIStatus_NoError) {
        status = cti_get_extended_pan_id(&thread_xpanid_context, NULL, cti_get_xpanid_callback, NULL);
    }
    if (status != kCTIStatus_NoError) {
        if (status == kCTIStatus_DaemonNotRunning) {
            attempt_wpan_reconnect();
        } else {
            ERROR("initial network setup failed");
        }
    }
    thread_network_running = true;
}
#endif //  defined(THREAD_BORDER_ROUTER) && !defined(RA_TESTER)

#ifndef RA_TESTER
static void
thread_network_shutdown(void)
{
    // Stop publishing a default route on the Thread network.
    if (adopted_thread_prefix != NULL) {
        partition_unpublish_prefix(adopted_thread_prefix);
        INFO("removing adopted thread prefix to remove.");
    } else {
        INFO("no adopted thread prefix to remove.");
    }
    if (published_thread_prefix != NULL) {
        partition_unpublish_prefix(published_thread_prefix);
        INFO("removing published thread prefix to remove.");
    } else {
        INFO("no published thread prefix to remove.");
    }

    if (thread_state_context) {
        INFO("discontinuing state events");
        cti_events_discontinue(thread_state_context);
        thread_state_context = NULL;
    }
    if (thread_role_context) {
        INFO("discontinuing role events");
        cti_events_discontinue(thread_role_context);
        thread_role_context = NULL;
    }
    if (thread_service_context) {
        INFO("discontinuing service events");
        cti_events_discontinue(thread_service_context);
        thread_service_context = NULL;
    }
    if (thread_prefix_context) {
        INFO("discontinuing prefix events");
        cti_events_discontinue(thread_prefix_context);
        thread_prefix_context = NULL;
    }
    if (thread_partition_id_context) {
        INFO("discontinuing partition ID events");
        cti_events_discontinue(thread_partition_id_context);
        thread_partition_id_context = NULL;
    }
    partition_state_reset();
}
#endif // RA_TESTER

void
infrastructure_network_shutdown(void)
{
    interface_t *interface;

#ifndef RA_TESTER
    if (thread_network_running) {
        thread_network_shutdown();
    }
#endif
    INFO("Infrastructure network shutdown.");
    // Stop all activity on interfaces.
    for (interface = interfaces; interface; interface = interface->next) {
        interface_shutdown(interface);
    }
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
    partition_has_xpanid = false;
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

    thread_network_running = false;
}

static int UNUSED
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
partition_prefix_remove_callback(void *UNUSED context, cti_status_t status)
{
    if (status != kCTIStatus_NoError) {
        ERROR("partition_prefix_remove_callback: failed to unpublish my prefix: %d.", status);
    } else {
        INFO("partition_prefix_remove_callback: done unpublishing my prefix.");
    }
}

static void
partition_stop_advertising_pref_id_done(void *UNUSED context, cti_status_t status)
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
                                NULL,
                                THREAD_ENTERPRISE_NUMBER, service_info, 1);
    if (status != kCTIStatus_NoError) {
        INFO("partition_stop_advertising_pref_id: status %d", status);
    }
}

static void
partition_advertise_pref_id_done(void *UNUSED context, cti_status_t status)
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
    int status = cti_add_service(NULL, partition_advertise_pref_id_done, NULL,
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
    cti_status_t status = cti_remove_prefix(NULL, partition_prefix_remove_callback, NULL,
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
    int ref_count;
    int num_unadvertised_prefixes;
    int num_removals;
    void (*continuation)(void);
};

static void
unadvertised_prefix_remove_state_finalize(unadvertised_prefix_remove_state_t *state)
{
    void (*continuation)(void) = state->continuation;
    free(state);
    if (continuation != NULL) {
        continuation();
    } else {
        INFO("no continuation.");
    }
}

static void
partition_remove_all_prefixes_done(void *context, cti_status_t status)
{
    unadvertised_prefix_remove_state_t *state = context;
    state->num_removals++;
    if (state->num_removals == state->num_unadvertised_prefixes) {
        INFO("partition_remove_all_prefixes_done:  DONE: status = %d num_removals = %d num_unadvertised = %d",
             status, state->num_removals, state->num_unadvertised_prefixes);
    } else {
        INFO("partition_remove_all_prefixes_done: !DONE: status = %d num_removals = %d num_unadvertised = %d",
             status, state->num_removals, state->num_unadvertised_prefixes);
    }
#ifndef __clang_analyzer__ // clang_analyzer is unable to follow the reference through the cti code.
    RELEASE_HERE(state, unadvertised_prefix_remove_state_finalize);
#endif
}

static void
partition_remove_all_unwanted_prefixes_inner(unadvertised_prefix_remove_state_t *state,
                                             thread_prefix_t *prefix, bool check)
{
    // Retain a copy of state for the partition_remove_all_prefixes_done callback, which is either called
    // when the remove finishes or directly if we decide not to remove this prefix.
    RETAIN_HERE(state);

    // Don't unpublish the adopted or published prefix.
    if (!check ||
        ((published_thread_prefix == NULL || memcmp(&published_thread_prefix->prefix, &prefix->prefix, 8)) &&
         (adopted_thread_prefix == NULL || memcmp(&adopted_thread_prefix->prefix, &prefix->prefix, 8))))
    {
        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
        INFO("removing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
        cti_status_t status = cti_remove_prefix(state, partition_remove_all_prefixes_done,
                                                NULL, &prefix->prefix, 64);
        if (status != kCTIStatus_NoError) {
            partition_remove_all_prefixes_done(state, status);
        }
    } else {
        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
        INFO("not removing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " because it's the " PUB_S_SRP " prefix",
             published_thread_prefix == NULL ? "adopted" : "published",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
        // Do the accounting anyway.
        partition_remove_all_prefixes_done(state, kCTIStatus_NotPermitted);
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
    // Retain our copy of state
    RETAIN_HERE(state);

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
                prefix_1 = prefix;
            } else if (prefix_2 != NULL && !memcmp(&prefix->prefix, &prefix_2->prefix, 8)) {
                prefix_2 = prefix;
            } else {
                state->num_unadvertised_prefixes++;
            }
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
        if (prefix_1 != prefix && prefix_2 != prefix) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(prefix->prefix.s6_addr, prefix_buf);
            if (!partition_pref_id_is_present(&prefix->prefix)) {
                INFO("removing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP,
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
                partition_remove_all_unwanted_prefixes_inner(state, prefix, true);
            } else {
                INFO("not removing prefix " PRI_SEGMENTED_IPv6_ADDR_SRP " because pref id is present",
                     SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix->prefix.s6_addr, prefix_buf));
            }
        }
    }
    if (prefix_1 != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix_1->prefix.s6_addr, prefix_buf);
        INFO("removing prefix_1 " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix_1->prefix.s6_addr, prefix_buf));
        partition_remove_all_unwanted_prefixes_inner(state, prefix_1, false);
    }
    if (prefix_2 != NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(prefix_2->prefix.s6_addr, prefix_buf);
        INFO("removing prefix_2 " PRI_SEGMENTED_IPv6_ADDR_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(prefix_2->prefix.s6_addr, prefix_buf));
        partition_remove_all_unwanted_prefixes_inner(state, prefix_2, false);
    }

    RELEASE_HERE(state, unadvertised_prefix_remove_state_finalize);
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

void
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
partition_pref_id_timeout(void *UNUSED context)
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
partition_post_election_wakeup(void *UNUSED context)
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
partition_post_partition_timeout(void *UNUSED context)
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
partition_proxy_listener_ready(void *UNUSED context, uint16_t port)
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
    srp_listener = srp_proxy_listen(avoid_ports, num_avoid_ports, partition_proxy_listener_ready);
    if (srp_listener == NULL) {
        ERROR("partition_start_srp_listener: Unable to start SRP Proxy listener, so can't advertise it");
        return;
    }
}

static void
partition_discontinue_srp_service()
{
    if (srp_listener != NULL) {
        INFO("discontinuing proxy service on port %d", srp_service_listen_port);
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
                    memset(&srp_listener_ip_address, 0, sizeof(srp_listener_ip_address));
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
        INFO("partition_wait_for_prefix_settling: satisfied after %" PRIu64 "ms.", now - partition_settle_start);
        return false; // means don't wait
    }

    // If we've waited longer than 500ms and aren't satisfied, complain, but then proceed.
    if (now - partition_settle_start >= 500) {
        ERROR("partition_wait_for_prefix_settling: unsatisfied after %" PRIu64 "ms", now - partition_settle_start);
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
    for (interface_t *interface = interfaces; interface; interface = interface->next) {
        if (!strcmp(interface->name, thread_interface_name)) {
            interface->is_thread = true;
            break;
        }
    }
    refresh_interface_list();
}

// We have a recent prefix list and either have a recent pref:id list or one probably isn't coming.
static void
partition_prefix_list_or_pref_id_list_changed(void *UNUSED context)
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
        INFO("we aren't able to offer routing yet, so ignoring.");
        return;
    }

    // If we are advertising a prefix, update our pref:id
    if (published_thread_prefix != NULL) {
        INFO("updating advertised prefix id");
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
#if defined(SRP_FEATURE_REPLICATION)
    if (!srp_replication_enabled) {
#endif
        if (context != NULL) {
            srp_mdns_flush();
        }
#if defined(SRP_FEATURE_REPLICATION)
    }
#endif
}

static void
partition_stop_advertising_service(void)
{
    // This should remove any copy of the service that this BR is advertising.
    INFO("partition_stop_advertising_service: %" PRIu64 "/%x", THREAD_ENTERPRISE_NUMBER, THREAD_SRP_SERVER_OPTION);
    uint8_t service_info[] = { 0, 0, 0, 1 };
    int status;

    service_info[0] = THREAD_SRP_SERVER_OPTION & 255;
    status = cti_remove_service((void *)(ptrdiff_t)1, partition_remove_service_done, NULL,
                                THREAD_ENTERPRISE_NUMBER, service_info, 1);
    if (status != kCTIStatus_NoError) {
        INFO("partition_stop_advertising_service: status %d", status);
    }
}

static void
partition_add_service_callback(void *UNUSED context, cti_status_t status)
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

    SEGMENTED_IPv6_ADDR_GEN_SRP(srp_listener_ip_address.s6_addr, server_ip_buf);
    service_info[0] = THREAD_SRP_SERVER_OPTION & 255;
    INFO("partition_add_srp_service: %" PRIu64 "/%02x/" PRI_SEGMENTED_IPv6_ADDR_SRP ":%d" ,
         THREAD_ENTERPRISE_NUMBER, service_info[0],
         SEGMENTED_IPv6_ADDR_PARAM_SRP(srp_listener_ip_address.s6_addr, server_ip_buf), srp_service_listen_port);

    ret = cti_add_service(NULL, partition_add_service_callback, NULL,
                              THREAD_ENTERPRISE_NUMBER, service_info, 1, server_info, sizeof server_info);
    if (ret != kCTIStatus_NoError) {
        INFO("partition_add_srp_service: status %d", ret);
    }

    // Wait a while for the service add to be reflected in an event.
    partition_schedule_service_add_wakeup();
}

static void
partition_service_add_wakeup(void *UNUSED context)
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
        return;
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
        int port = (service->port[0] << 8) | service->port[1];
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
#endif // STUB_ROUTER

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
