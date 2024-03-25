/* service-publisher.c
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
 * This file contains code to queue and send updates for Thread services.
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
#include "srp-crypto.h"

#include "cti-services.h"
#include "srp-gw.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "adv-ctl-server.h"
#include "dnssd-proxy.h"
#include "srp-proxy.h"
#include "route.h"

#define STATE_MACHINE_IMPLEMENTATION 1
typedef enum {
    service_publisher_state_invalid,
    service_publisher_state_startup,
    service_publisher_state_waiting_to_publish,
    service_publisher_state_not_publishing,
    service_publisher_state_start_listeners,
    service_publisher_state_publishing,
} state_machine_state_t;
#define state_machine_state_invalid service_publisher_state_invalid

#include "state-machine.h"
#include "thread-service.h"
#include "service-tracker.h"

#include "service-publisher.h"
#include "thread-tracker.h"
#include "node-type-tracker.h"

// This is pretty short because our normal use case is connecting to a single device, so we don't actually anticipate
// normally seeing a service. But if we do, we don't suffer power events, so we don't need to desynchronize from other
// devices booting at the same time. So we just want to wait long enough that if there's already a service published,
// we see it and don't publish.
#define SERVICE_PUBLISHER_START_WAIT 750

// When a competing service is lost, we want to wait a bit longer.
#define SERVICE_PUBLISHER_LOST_WAIT 5000

// When the listener restarts, we don't actually want to wait.
#define SERVICE_PUBLISHER_LISTENER_RESTART_WAIT 1

struct service_publisher {
    int ref_count;
    state_machine_header_t state_header;
    char *id;
    srp_server_t *server_state;
    wakeup_t *NULLABLE wakeup_timer;
    comm_t *srp_listener;
    void (*reconnect_callback)(void *context);
    thread_service_t *published_unicast_service;
    thread_service_t *published_anycast_service;
    thread_service_t *publication_queue;
    cti_connection_t active_data_set_connection;
    struct in6_addr thread_mesh_local_address;
    int startup_delay_range;
    uint16_t srp_listener_port;
    bool have_ml_eid;
    bool first_time;
    bool force_publication;
    bool canceled;
    bool have_srp_listener;
    bool seen_service_list;
    bool stopped;
};

static uint64_t service_publisher_serial_number;

static void service_publisher_queue_run(service_publisher_t *publisher);

bool
service_publisher_is_address_mesh_local(service_publisher_t *publisher, addr_t *address)
{
    if (address->sa.sa_family == AF_INET) {
        IPv4_ADDR_GEN_SRP(&address->sin.sin_addr, addr_buf);
        if (!IN_LOOPBACK(address->sin.sin_addr.s_addr)) {
            INFO(PRI_IPv4_ADDR_SRP "is not mesh-local", IPv4_ADDR_PARAM_SRP(&address->sin.sin_addr, addr_buf));
            return false;
        }
        INFO(PRI_IPv4_ADDR_SRP "is the IPv4 loopback address", IPv4_ADDR_PARAM_SRP(&address->sin.sin_addr, addr_buf));
        return true;
    }
    if (address->sa.sa_family != AF_INET6) {
        INFO("address family %d can't be mesh-local", address->sa.sa_family);
        return false;
    }

    uint8_t *addr_ptr = (uint8_t *)&address->sin6.sin6_addr;
    SEGMENTED_IPv6_ADDR_GEN_SRP(addr_ptr, addr_buf);
    if (IN6_IS_ADDR_LOOPBACK(&address->sin6.sin6_addr)) {
        INFO(PRI_SEGMENTED_IPv6_ADDR_SRP " is the IPv6 loopback address.",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(addr_ptr, addr_buf));
        return true;
    }
    static const uint8_t ipv4mapped_loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
    if (!memcmp(&address->sin6.sin6_addr, ipv4mapped_loopback, sizeof(ipv4mapped_loopback))) {
        INFO(PRI_SEGMENTED_IPv6_ADDR_SRP " is the IPv4-mapped loopback address.",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(addr_ptr, addr_buf));
        return true;
    }

    if (!publisher->have_ml_eid) {
        INFO(PRI_SEGMENTED_IPv6_ADDR_SRP "is not mesh-local",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(addr_ptr, addr_buf));
        return false;
    }

    SEGMENTED_IPv6_ADDR_GEN_SRP(&publisher->thread_mesh_local_address, mle_buf);
    if (in6prefix_compare(&address->sin6.sin6_addr, &publisher->thread_mesh_local_address, 8)) {
        INFO(PRI_SEGMENTED_IPv6_ADDR_SRP
             " is not on the same prefix as mesh-local address " PRI_SEGMENTED_IPv6_ADDR_SRP ".",
             SEGMENTED_IPv6_ADDR_PARAM_SRP(addr_ptr, addr_buf),
             SEGMENTED_IPv6_ADDR_PARAM_SRP(&publisher->thread_mesh_local_address, mle_buf));
        return false;
    }
    INFO(PRI_SEGMENTED_IPv6_ADDR_SRP "is on the same prefix as mesh-local address " PRI_SEGMENTED_IPv6_ADDR_SRP ".",
         SEGMENTED_IPv6_ADDR_PARAM_SRP(addr_ptr, addr_buf),
         SEGMENTED_IPv6_ADDR_PARAM_SRP(&publisher->thread_mesh_local_address, mle_buf));
    return true;
}

static void
service_publisher_finalize(service_publisher_t *publisher)
{
    thread_service_release(publisher->published_unicast_service);
    thread_service_release(publisher->published_anycast_service);
    thread_service_list_release(&publisher->publication_queue);

    free(publisher->id);
    ioloop_wakeup_release(publisher->wakeup_timer);
    free(publisher);
}

RELEASE_RETAIN_FUNCS(service_publisher);

static void
service_publisher_context_release(void *context)
{
    service_publisher_t *publisher = context;
    RELEASE_HERE(publisher, service_publisher);
}

static void
service_publisher_update_callback(void *context, cti_status_t status)
{
    service_publisher_t *publisher = context;
    thread_service_t *service = publisher->publication_queue;

    if (publisher->canceled) {
        RELEASE_HERE(publisher, service_publisher);
        return;
    }

    if (service == NULL) {
        ERROR("no pending service update");
        return;
    }
    char status_buf[256];
    snprintf(status_buf, sizeof(status_buf), "is in state %s, status = %d",
             thread_service_publication_state_name_get(service->publication_state), status);
    thread_service_note(publisher->id, service, status_buf);
    if (status == kCTIStatus_NoError) {
        if (service->publication_state == add_pending) {
            service->publication_state = add_complete;
        } else if (service->publication_state == delete_pending) {
            service->publication_state = delete_complete;
        }
    } else {
        if (service->publication_state == add_pending) {
            service->publication_state = add_failed;
        } else if (service->publication_state == delete_pending) {
            service->publication_state = delete_failed;
        }
    }
    publisher->publication_queue = service->next;
    thread_service_release(service);
    if (!publisher->canceled) {
        service_publisher_queue_run(publisher);
    }
    RELEASE_HERE(publisher, service_publisher);
}

static cti_status_t
service_publisher_service_update(service_publisher_t *publisher, thread_service_t *service, bool add)
{
    uint8_t service_data[20];
    uint8_t server_data[20];
    size_t service_data_length, server_data_length;
    switch(service->service_type) {
    case unicast_service:
        service_data[0] = THREAD_SRP_SERVER_OPTION;
        service_data_length = 1;
        memcpy(server_data, &service->u.unicast.address, 16);
        memcpy(&server_data[16], service->u.unicast.port, 2);
        server_data_length = 18;
        break;
    case anycast_service:
        service_data[0] = THREAD_SRP_SERVER_ANYCAST_OPTION;
        service_data[1] = service->u.anycast.sequence_number;
        service_data_length = 2;
        server_data_length = 0;
        break;
    case pref_id:
        return kCTIStatus_BadParam; // Not supported anymore.
    }

    if (add) {
        return cti_add_service(publisher->server_state, publisher, service_publisher_update_callback, NULL,
                               THREAD_ENTERPRISE_NUMBER, service_data, service_data_length, server_data, server_data_length);
    } else {
        return cti_remove_service(publisher->server_state, publisher, service_publisher_update_callback, NULL,
                                  THREAD_ENTERPRISE_NUMBER, service_data, service_data_length);
    }
}

static void
service_publisher_queue_run(service_publisher_t *publisher)
{
    thread_service_t *service = publisher->publication_queue;
    if (service == NULL) {
        INFO("the queue is empty.");
        return;
    }
    if (service->publication_state == delete_pending || service->publication_state == add_pending) {
        INFO("there is a pending update at the head of the queue.");
        return;
    }
    if (service->publication_state == want_delete) {
        cti_status_t status = service_publisher_service_update(publisher, service, false);
        if (status != kCTIStatus_NoError) {
            ERROR("cti_remove_service failed: %d", status);
            // For removes, we'll leave it on the queue
        } else {
            service->publication_state = delete_pending;
            RETAIN_HERE(publisher, service_publisher); // for the callback
        }
    } else if (service->publication_state == want_add) {
        cti_status_t status = service_publisher_service_update(publisher, service, true);
        if (status != kCTIStatus_NoError) {
            ERROR("cti_add_service failed: %d", status);
            publisher->publication_queue = service->next;
            thread_service_release(service);
        } else {
            service->publication_state = add_pending;
            RETAIN_HERE(publisher, service_publisher); // for the callback
        }
    } else {
        char status_buf[256];
        snprintf(status_buf, sizeof(status_buf), "is in unexpected state %s on the publication queue",
                 thread_service_publication_state_name_get(service->publication_state));
        thread_service_note(publisher->id, service, status_buf);
        publisher->publication_queue = service->next;
        thread_service_release(service);
    }
}

static void
service_publisher_queue_update(service_publisher_t *publisher, thread_service_t *service,
                               thread_service_publication_state_t initial_state)
{
    thread_service_t **ppref;

    thread_service_t **p_published;
    if (service->service_type == unicast_service) {
        p_published = &publisher->published_unicast_service;
    } else if (service->service_type == unicast_service) {
        p_published = &publisher->published_unicast_service;
    } else {
        ERROR("unsupported service type %d", service->service_type);
        return;
    }
    if (thread_service_equal(*p_published, service)) {
        FAULT("published service still present: %p", *p_published);
    }
    service->publication_state = initial_state;
    if (initial_state == want_add) {
        *p_published = service;
        thread_service_retain(*p_published);
    }
    // Find the end of the queue
    for (ppref = &publisher->publication_queue; *ppref != NULL; ppref = &(*ppref)->next)
        ;
    *ppref = service;
    // Retain the service on the queue.
    thread_service_retain(*ppref);
    service_publisher_queue_run(publisher);
}

static thread_service_t *
service_publisher_create_service_for_queue(thread_service_t *service)
{
    switch(service->service_type) {
    case unicast_service:
        return thread_service_unicast_create(service->rloc16, service->u.unicast.address.s6_addr,
                                             service->u.unicast.port, service->service_id);
    case anycast_service:
        return thread_service_anycast_create(service->rloc16, service->u.anycast.sequence_number, service->service_id);
    case pref_id:
        return thread_service_pref_id_create(service->rloc16, service->u.pref_id.partition_id,
                                             service->u.pref_id.prefix, service->service_id);
    }
    return NULL;
}

static void UNUSED
service_publisher_service_publish(service_publisher_t *publisher, thread_service_t *service)
{
    service_publisher_queue_update(publisher, service, want_add);
}

static void UNUSED
service_publisher_service_unpublish(service_publisher_t *publisher, thread_service_type_t service_type)
{
    thread_service_t *service;

    if (service_type == unicast_service) {
        service = publisher->published_unicast_service;
        publisher->published_unicast_service = NULL;
    } else if (service_type == anycast_service) {
        service = publisher->published_anycast_service;
        publisher->published_anycast_service = NULL;
    } else {
        ERROR("unsupported service type %d", service_type);
        return;
    }
    if (service == NULL) {
        ERROR("request to unpublished service that's not present");
        return;
    }

    thread_service_t *to_delete = service_publisher_create_service_for_queue(service);
    service_publisher_queue_update(publisher, to_delete, want_delete);
    thread_service_release(to_delete); // service_publisher_queue_update explicitly retains the references it makes.
    thread_service_release(service); // No longer published.
}

static void
service_publisher_unpublish_stale_service(service_publisher_t *publisher, thread_service_t *service)
{
    // If there's a stale service, don't try to publish the real service until we see the stale service go away.
    INFO("setting seen_service_list to false");
    publisher->seen_service_list = false;

    thread_service_t *to_delete = service_publisher_create_service_for_queue(service);

    if (to_delete == NULL) {
        thread_service_note(publisher->id, service, "no memory for service to delete");
    } else {
        service_publisher_queue_update(publisher, to_delete, want_delete);
        thread_service_release(to_delete); // service_publisher_queue_update explicitly retains all the references it makes
        service->ignore = true;
    }
}

static bool
service_publisher_have_competing_unicast_service(service_publisher_t *publisher)
{
    thread_service_t *NULLABLE published_service = publisher->published_unicast_service;
    bool competing_service_present = false;

    for (thread_service_t *service = service_tracker_services_get(publisher->server_state->service_tracker);
         service != NULL; service = service->next)
    {
        if (service->ignore) {
            continue;
        }
        if (service->service_type == unicast_service) {
            if (published_service == NULL) {
                if (service->rloc16 == publisher->server_state->rloc16 ||
                    (publisher->have_ml_eid &&
                     !in6addr_compare(&service->u.unicast.address, &publisher->thread_mesh_local_address)))
                {
                    thread_service_note(publisher->id, service,
                                        "is on our ml-eid or rloc16 but we aren't publishing it, so it's stale.");
                    service_publisher_unpublish_stale_service(publisher, service);
                    continue;
                }
                thread_service_note(publisher->id, service, "is not ours and we aren't publishing.");
                competing_service_present = true;
            // First check to see if the other service is on the mesh-local prefix. If it's not, it wins.
            } else if (in6prefix_compare(&service->u.unicast.address, &published_service->u.unicast.address, 8)) {
                competing_service_present = true;
                thread_service_note(publisher->id, service, "is a competing service.");
            } else {
                int cmp = in6addr_compare(&service->u.unicast.address, &published_service->u.unicast.address);

                // If equal, compare ports...
                if (!cmp) {
                    cmp = memcmp(service->u.unicast.port, published_service->u.unicast.port,
                                 sizeof(service->u.unicast.port));
                    // If the port doesn't match our published service, it's a weird stale service (this probably can't
                    // happen);
                    if (cmp) {
                        thread_service_note(publisher->id, service,
                                            "is on our ml-eid but is not the one we are publishing, so it's stale.");
                        service_publisher_unpublish_stale_service(publisher, service);
                        continue;
                    } else {
                        thread_service_note(publisher->id, service, "is the one we are publishing.");
                    }
                } else {
                    // This is a stale service published on our RLOC16 with a different ML-EID.
                    if (service->rloc16 == publisher->server_state->rloc16) {
                        thread_service_note(publisher->id, service,
                                            "is a stale service published on our rloc16 with a different ml-eid.");
                        service_publisher_unpublish_stale_service(publisher, service);
                        continue;
                    } else if (cmp < 0) {
                        competing_service_present = true;
                        thread_service_note(publisher->id, service, "is not ours and wins against ours.");
                    } else {
                        thread_service_note(publisher->id, service, "is not ours and loses against ours.");
                    }
                }
            }
        }
    }
    return competing_service_present;
}

static bool
service_publisher_have_anycast_service(service_publisher_t *publisher)
{
    bool anycast_service_present = false;

    for (thread_service_t *service = service_tracker_services_get(publisher->server_state->service_tracker);
         service != NULL; service = service->next)
    {
        if (service->ignore) {
            continue;
        }
        if (service->service_type == anycast_service) {
            thread_service_note(publisher->id, service, "is present and supersedes our unicast service");
            anycast_service_present = true;
        }
    }
    return anycast_service_present;
}

static void
service_publisher_wait_expired(void *context)
{
    service_publisher_t *publisher = context;
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_timeout, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
service_publisher_service_tracker_callback(void *context)
{
    service_publisher_t *publisher = context;

    // If we get a service list update when we're associated, set the seen_service-list flag to true. This tells us we can proceed
    // with publishing a service if we just associated to the thread network.
    if (thread_tracker_associated_get(publisher->server_state->thread_tracker, false)) {
        INFO("setting seen_service_list to true");
        publisher->seen_service_list = true;
    }

    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_service_list_changed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
service_publisher_thread_tracker_callback(void *context)
{
    service_publisher_t *publisher = context;

    // This is a temporary hack because right now we won't get a prefix list event on associate, and we need
    // the (presumably empty) prefix list event to trigger an immediate service advertisement.
    // IMPORTANT: when this is fixed, make sure to start the service_tracker in thread-device.c again.
    // To work around this issue, we stop service list events in the service tracker when we dissociate, and
    // restart events when we re-associate.
    // Hack is tracked in rdar://109266343 (Optimize SRP registration time)
    if (!thread_tracker_associated_get(publisher->server_state->thread_tracker, false)) {
        service_tracker_stop(publisher->server_state->service_tracker);
    } else {
        service_tracker_start(publisher->server_state->service_tracker);
    }

    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_thread_network_state_changed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
service_publisher_node_type_tracker_callback(void *context)
{
    service_publisher_t *publisher = context;
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_thread_node_type_changed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

// Service publisher states
//
// <startup>
//      on entry: start timer for a random amount of time
//      timer event: -> <waiting to publish>
//      other events: ignore
// <waiting to publish>
//      on entry: check for service present
//                yes: -> <not publishing>
//                check for ML-EID present
//                yes: -> <start listeners>
//      ML-EID shows up: -> <start listeners>
//      service shows up: -> <not publishing>
// <not publishing>
//      on entry: do nothing
//      last service advertisement goes away: -> <waiting to publish>
// <start listeners>
//      on entry: start listeners
//      listener ready: -> <publishing>
// <publishing>
//      on entry: advertise service
//      winning service shows up: stop advertising
//                                -> <not publishing>

static state_machine_state_t service_publisher_action_startup(state_machine_header_t *state_header,
                                                              state_machine_event_t *event);
static state_machine_state_t service_publisher_action_waiting_to_publish(state_machine_header_t *state_header,
                                                                         state_machine_event_t *event);
static state_machine_state_t service_publisher_action_not_publishing(state_machine_header_t *state_header,
                                                                 state_machine_event_t *event);
static state_machine_state_t service_publisher_action_start_listeners(state_machine_header_t *state_header,
                                                                      state_machine_event_t *event);
static state_machine_state_t service_publisher_action_publishing(state_machine_header_t *state_header,
                                                                 state_machine_event_t *event);

#define SERVICE_PUB_NAME_DECL(name) service_publisher_state_##name, #name
static state_machine_decl_t service_publisher_states[] = {
    { SERVICE_PUB_NAME_DECL(invalid),                            NULL },
    { SERVICE_PUB_NAME_DECL(startup),                            service_publisher_action_startup },
    { SERVICE_PUB_NAME_DECL(waiting_to_publish),                 service_publisher_action_waiting_to_publish },
    { SERVICE_PUB_NAME_DECL(not_publishing),                     service_publisher_action_not_publishing },
    { SERVICE_PUB_NAME_DECL(start_listeners),                     service_publisher_action_start_listeners },
    { SERVICE_PUB_NAME_DECL(publishing),                         service_publisher_action_publishing },
};
#define SERVICE_PUBLISHER_NUM_STATES ((sizeof(service_publisher_states)) / (sizeof(state_machine_decl_t)))

#define STATE_MACHINE_HEADER_TO_PUBLISHER(state_header)                                                                \
    if (state_header->state_machine_type != state_machine_type_service_publisher) {                                    \
        ERROR("state header type isn't omr_publisher: %d", state_header->state_machine_type);                          \
        return service_publisher_state_invalid;                                                                        \
    }                                                                                                                  \
    service_publisher_t *publisher = state_header->state_object

// In the startup state, we wait for a timeout to expire before doing anything. This gives other devices on the Thread mesh
// an opportunity to publish as well.
static state_machine_state_t
service_publisher_action_startup(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_PUBLISHER(state_header);
    BR_STATE_ANNOUNCE(publisher, event);

    if (event == NULL) {
        if (publisher->wakeup_timer == NULL) {
            publisher->wakeup_timer = ioloop_wakeup_create();
        }
        if (publisher->wakeup_timer == NULL) {
            ERROR("unable to allocate a wakeup timer");
            return service_publisher_state_invalid;
        }
        // We only need a random startup delay for stub routers, which are generally powered devices that can synchronize
        // on restart after a power failure.
        if (publisher->server_state->stub_router_enabled) {
            ioloop_add_wake_event(publisher->wakeup_timer, publisher, service_publisher_wait_expired,
                                  service_publisher_context_release,
                                  publisher->startup_delay_range + srp_random16() % publisher->startup_delay_range);
            RETAIN_HERE(publisher, service_publisher); // For wakeup
            return service_publisher_state_invalid;
        }
        return service_publisher_state_waiting_to_publish;
    }

    // The only way out of the startup state is for the timer to expire--we don't care about prefixes showing up or
    // going away.
    if (event->type == state_machine_event_type_timeout) {
        INFO("startup timeout");
        return service_publisher_state_waiting_to_publish;
    }

    BR_UNEXPECTED_EVENT(publisher, event);
}

static bool
service_publisher_can_publish(service_publisher_t *publisher)
{
    bool no_anycast_service = true;
    bool no_competing_service = true;
    bool associated = true;
    bool router = true;
    bool have_ml_eid = true;
    bool can_publish = true;

    // Check the conditions that prevent publication.
    if (service_publisher_have_competing_unicast_service(publisher)) {
        no_competing_service = false;
        can_publish = false;
    }
    if (service_publisher_have_anycast_service(publisher)) {
        no_anycast_service = false;
        can_publish = false;
    }
    srp_server_t *server_state = publisher->server_state;
    if (!thread_tracker_associated_get(server_state->thread_tracker, false)) {
        associated = false;
        can_publish = false;
        INFO("setting seen_service_list to false");
        publisher->seen_service_list = false;
    }

    thread_node_type_t node_type = node_type_tracker_thread_node_type_get(server_state->node_type_tracker, false);
    if (node_type != node_type_router && node_type != node_type_leader) {
        router = false;
    }
    if (!publisher->have_ml_eid) {
        have_ml_eid = false;
        can_publish = false;
    }
    if (!publisher->seen_service_list) {
        can_publish = false;
    }
    if (publisher->stopped) {
        can_publish = false;
    }

    INFO(PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP PUB_S_SRP,
         can_publish ?                         "can publish" :  "can't publish",
         publisher->seen_service_list ?                   "" : " have not seen service list",
         no_competing_service ?                           "" : " competing service present",
         no_anycast_service ?                             "" : " anycast service present",
         associated ?                                     "" : " not associated ",
         router ?                                         "" : " not a router ",
         have_ml_eid ?                                    "" : " no ml-eid ",
         publisher->stopped ?                     " stopped" : "");
    return can_publish;
}

// This function tells the caller whether the service publisher could publish a service. This will be the case either
// because it actually is publishing a service, or because it's in the process of finding out if it can publish a
// service, or preparing to publish a service. In practice, this means that the only state for which the answer is false
// at present is the "not_publishing" state.
bool
service_publisher_could_publish(service_publisher_t *publisher)
{
    if (publisher == NULL) {
        return false;
    }
    if (publisher->state_header.state == service_publisher_state_startup ||
        publisher->state_header.state == service_publisher_state_waiting_to_publish ||
        publisher->state_header.state == service_publisher_state_start_listeners ||
        publisher->state_header.state == service_publisher_state_publishing)
    {
        return true;
    }
    return false;
}

void
service_publisher_stop_publishing(service_publisher_t *publisher)
{
    publisher->stopped = true;
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_stop, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

// We go to this state whenever we think we might need to publish, but are not yet publishing. So this state
// acts as a gatekeeper: if there is already a service published, we go straight to not_publishing. If we don't
// yet have an ML-EID, we have to wait until we get one to publish. If, while we are waiting for the ML-EID,
// we see a service show up, we go to not_publishing. Otherwise, when the ML-EID comes, we go to the listener_start
// page.
static state_machine_state_t
service_publisher_action_waiting_to_publish(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_PUBLISHER(state_header);
    BR_STATE_ANNOUNCE(publisher, event);

    // We do the same thing here whether we've gotten an event or just on entry, so no need to check.
    if (service_publisher_can_publish(publisher)) {
        return service_publisher_state_start_listeners;
    }
    if (service_publisher_have_competing_unicast_service(publisher)) {
        return service_publisher_state_not_publishing;
    }
    return service_publisher_state_invalid;
}

// We get into this state when there is a competing service that wins the election against our service.
// We only leave the state when there is no longer a competing prefix.
static state_machine_state_t
service_publisher_action_not_publishing(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_PUBLISHER(state_header);
    BR_STATE_ANNOUNCE(publisher, event);

    if (event == NULL) {
        if (publisher->published_unicast_service != NULL) {
            service_publisher_service_unpublish(publisher, unicast_service);
        }
        return service_publisher_state_invalid;
    }

    // We do the same thing here for any event we get, because we're just waiting for conditions to be right.
    if (service_publisher_can_publish(publisher)) {
        publisher->startup_delay_range = SERVICE_PUBLISHER_LOST_WAIT;
        return service_publisher_state_startup;
    }
    return service_publisher_state_invalid;
}

static void
service_publisher_listener_cancel_callback(comm_t *UNUSED listener, void *context)
{
    srp_server_t *server_state = context;
    service_publisher_t *publisher = server_state->service_publisher;
    if (publisher != NULL) {
        state_machine_event_t *event = state_machine_event_create(state_machine_event_type_listener_canceled, NULL);
        if (event == NULL) {
            ERROR("unable to allocate event to deliver");
            return;
        }
        state_machine_event_deliver(&publisher->state_header, event);
        RELEASE_HERE(event, state_machine_event);
    }
}

static void
service_publisher_listener_cancel(service_publisher_t *publisher)
{
    if (publisher->srp_listener != NULL) {
        ioloop_listener_cancel(publisher->srp_listener);
        ioloop_comm_release(publisher->srp_listener);
        publisher->srp_listener = NULL;
    }
    publisher->have_srp_listener = false;
    srp_mdns_flush(publisher->server_state);
}

static void
service_publisher_listener_ready(void *context, uint16_t port)
{
    srp_server_t *server_state = context;
    service_publisher_t *publisher = server_state->service_publisher;
    if (publisher != NULL) {
        state_machine_event_t *event = state_machine_event_create(state_machine_event_type_listener_ready, NULL);
        if (event == NULL) {
            ERROR("unable to allocate event to deliver");
            return;
        }
        publisher->have_srp_listener = true;
        publisher->srp_listener_port = port;
        state_machine_event_deliver(&publisher->state_header, event);
        RELEASE_HERE(event, state_machine_event);
    }
}

static void
service_publisher_listener_start(service_publisher_t *publisher)
{
    if (publisher->srp_listener) {
        FAULT("listener still present");
        service_publisher_listener_cancel(publisher);
    }
    publisher->srp_listener = srp_proxy_listen(NULL, 0, service_publisher_listener_ready,
                                               service_publisher_listener_cancel_callback, NULL,
                                               NULL, publisher->server_state);
    if (publisher->srp_listener == NULL) {
        ERROR("failed to setup SRP listener");
    }
}

// We go to this state when we have decided to publish, but perhaps do not currently have an SRP listener
// running.
static state_machine_state_t
service_publisher_action_start_listeners(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_PUBLISHER(state_header);
    BR_STATE_ANNOUNCE(publisher, event);

    if (event == NULL) {
        if (publisher->have_srp_listener) {
            if (publisher->srp_listener != NULL) {
                return service_publisher_state_publishing;
            }
            FAULT("have_srp_listener is true but there's no listener!");
            publisher->have_srp_listener = false;
        }
        service_publisher_listener_start(publisher);
        return service_publisher_state_invalid;
    }

    // If we get a competing service while we're waiting for the listener to start, cancel the listener.
    // We do the same thing here for any event we get, because we're just waiting for conditions to be right.
    if (!service_publisher_can_publish(publisher)) {
        service_publisher_listener_cancel(publisher);
        return service_publisher_state_not_publishing;
    }

    // If the listener is ready, we can publish.
    if (event->type == state_machine_event_type_listener_ready) {
        return service_publisher_state_publishing;
    }

    return service_publisher_state_invalid;
}

// We enter this state when we have an SRP listener and no competing unicast services. On entry, we publish our unicast service.
// If a competing service shows up that wins, we stop publishing and cancel the listener. Otherwise we remain in this state.
static state_machine_state_t
service_publisher_action_publishing(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_PUBLISHER(state_header);
    BR_STATE_ANNOUNCE(publisher, event);

    if (event == NULL) {
        if (publisher->published_unicast_service != NULL) {
            ERROR("unicast service still published!");
            service_publisher_service_unpublish(publisher, unicast_service);
        }
        uint8_t port[] = { publisher->srp_listener_port >> 8, publisher->srp_listener_port & 255 };
        thread_service_t *service = thread_service_unicast_create(publisher->server_state->rloc16,
                                                                  (uint8_t *)&publisher->thread_mesh_local_address,
                                                                  port, 0);

        service_publisher_service_publish(publisher, service);
        thread_service_release(service); // service_publisher_publish retains the references it keeps.
        return service_publisher_state_invalid;
    }

    // If the listener got canceled for some reason, restart it.
    if (event->type == state_machine_event_type_listener_canceled) {
        service_publisher_service_unpublish(publisher, unicast_service);
        publisher->startup_delay_range = SERVICE_PUBLISHER_LISTENER_RESTART_WAIT;
        return service_publisher_state_startup;
    }

    // Any other event triggers a re-evaluation.
    if (event->type == state_machine_event_type_ml_eid_changed) {
        service_publisher_listener_cancel(publisher);
        service_publisher_service_unpublish(publisher, unicast_service);
        return service_publisher_state_startup;
    }

    if (!service_publisher_can_publish(publisher)) {
        service_publisher_listener_cancel(publisher);
        service_publisher_service_unpublish(publisher, unicast_service);
        return service_publisher_state_not_publishing;
    }

    return service_publisher_state_invalid;
}

void
service_publisher_cancel(service_publisher_t *publisher)
{
    service_publisher_listener_cancel(publisher);
    service_tracker_callback_cancel(publisher->server_state->service_tracker, publisher);
    thread_tracker_callback_cancel(publisher->server_state->thread_tracker, publisher);
    node_type_tracker_callback_cancel(publisher->server_state->node_type_tracker, publisher);
    if (publisher->active_data_set_connection != NULL) {
        cti_events_discontinue(publisher->active_data_set_connection);
    }
    publisher->active_data_set_connection = NULL;
}

service_publisher_t *
service_publisher_create(srp_server_t *server_state)
{
    service_publisher_t *ret = NULL, *publisher = calloc(1, sizeof(*publisher));
    if (publisher == NULL) {
        return publisher;
    }
    RETAIN_HERE(publisher, service_publisher);
    publisher->wakeup_timer = ioloop_wakeup_create();
    if (publisher->wakeup_timer == NULL) {
        ERROR("wakeup timer alloc failed");
        goto out;
    }

    char server_id_buf[100];
    snprintf(server_id_buf, sizeof(server_id_buf), "[SP%lld]", ++service_publisher_serial_number);
    publisher->id = strdup(server_id_buf);
    if (publisher->id == NULL) {
        ERROR("no memory for server ID");
        goto out;
    }

    if (!state_machine_header_setup(&publisher->state_header,
                                    publisher, publisher->id,
                                    state_machine_type_service_publisher,
                                    service_publisher_states,
                                    SERVICE_PUBLISHER_NUM_STATES)) {
        ERROR("header setup failed");
        goto out;
    }

    publisher->server_state = server_state;
    if (!service_tracker_callback_add(server_state->service_tracker, service_publisher_service_tracker_callback,
                                      service_publisher_context_release, publisher))
    {
        goto out;
    }
    RETAIN_HERE(publisher, service_publisher); // for service tracker

    if (!thread_tracker_callback_add(server_state->thread_tracker, service_publisher_thread_tracker_callback,
                                     service_publisher_context_release, publisher))
    {
        goto out;
    }
    RETAIN_HERE(publisher, service_publisher); // for thread network state tracker

    if (!node_type_tracker_callback_add(server_state->node_type_tracker, service_publisher_node_type_tracker_callback,
                                        service_publisher_context_release, publisher))
    {
        goto out;
    }
    RETAIN_HERE(publisher, service_publisher); // for thread network state tracker

    // Set the first_time flag so that we'll know to remove any locally-published on-mesh prefixes.
    publisher->first_time = true;
    publisher->startup_delay_range = SERVICE_PUBLISHER_START_WAIT;
    ret = publisher;
    publisher = NULL;
out:
    if (publisher != NULL) {
        RELEASE_HERE(publisher, service_publisher);
    }
    return ret;
}

static void
service_publisher_get_mesh_local_address_callback(void *context, const char *address_string, cti_status_t status)
{
    service_publisher_t *publisher = context;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("disconnected");
        if (publisher->reconnect_callback != NULL) {
            publisher->reconnect_callback(publisher->server_state);
        }
        goto fail;
    }

    INFO(PUB_S_SRP " %d", address_string != NULL ? address_string : "<null>", status);
    if (status != kCTIStatus_NoError || address_string == NULL) {
        goto fail;
    }

    struct in6_addr new_mesh_local_address;
    if (!inet_pton(AF_INET6, address_string, &new_mesh_local_address)) {
        ERROR("address syntax incorrect: " PRI_S_SRP, address_string);
        goto fail;
    }

    if (publisher->have_ml_eid && !in6addr_compare(&new_mesh_local_address, &publisher->thread_mesh_local_address)) {
        INFO("address didn't change");
        return;
    }
    publisher->thread_mesh_local_address = new_mesh_local_address;
    publisher->have_ml_eid = true;

    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_ml_eid_changed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&publisher->state_header, event);
    RELEASE_HERE(event, state_machine_event);
    RELEASE_HERE(publisher, service_publisher); // callback held a reference.
    return;
fail:
    RELEASE_HERE(publisher, service_publisher); // callback held a reference.
    publisher->have_ml_eid = false;
    return;
}

static void
service_publisher_active_data_set_changed_callback(void *context, cti_status_t status)
{
    service_publisher_t *publisher = context;

    if (status != kCTIStatus_NoError) {
        ERROR("error %d", status);
        RELEASE_HERE(publisher, service_publisher); // no more callbacks
        cti_events_discontinue(publisher->active_data_set_connection);
        publisher->active_data_set_connection = NULL;
        return;
    }

    status = cti_get_mesh_local_address(publisher->server_state, publisher,
                                        service_publisher_get_mesh_local_address_callback, NULL);
    if (status != kCTIStatus_NoError) {
        ERROR("cti_get_mesh_local_address failed with status %d", status);
    } else {
        RETAIN_HERE(publisher, service_publisher); // for mesh-local callback
    }
}

void
service_publisher_start(service_publisher_t *publisher)
{
    cti_status_t status = cti_track_active_data_set(publisher->server_state, &publisher->active_data_set_connection,
                                                    publisher, service_publisher_active_data_set_changed_callback,
                                                    NULL);
    if (status != kCTIStatus_NoError) {
        ERROR("unable to start tracking active dataset: %d", status);
    } else {
        RETAIN_HERE(publisher, service_publisher); // for callback
    }
    service_publisher_active_data_set_changed_callback(publisher, kCTIStatus_NoError); // Get the initial state.
    state_machine_next_state(&publisher->state_header, service_publisher_state_startup);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
