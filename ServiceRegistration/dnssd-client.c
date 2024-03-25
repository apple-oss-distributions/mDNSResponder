/* dnssd-client.c
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
#include <mrc/private.h>
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
    dnssd_client_state_invalid,
    dnssd_client_state_startup,
    dnssd_client_state_not_client,
    dnssd_client_state_client,
} state_machine_state_t;
#define state_machine_state_invalid dnssd_client_state_invalid

#include "state-machine.h"
#include "thread-service.h"
#include "service-tracker.h"
#include "service-publisher.h"

#include "dnssd-client.h"
#include "thread-tracker.h"
#include "probe-srp.h"

struct dnssd_client {
    int ref_count;
    state_machine_header_t state_header;
    char *id;
    srp_server_t *server_state;
    cti_connection_t active_data_set_connection;
    struct in6_addr mesh_local_prefix;
	mrc_dns_service_registration_t dns_service_registration;
    bool have_mesh_local_prefix;
    bool first_time;
    bool canceled;
    dnssd_txn_t *shared_txn;
    thread_service_t *published_service;
    DNSServiceRef shared_connection;
    int interface_index;
};

static uint64_t dnssd_client_serial_number;

static void
dnssd_client_finalize(dnssd_client_t *client)
{
    thread_service_release(client->published_service);

    free(client->id);
    free(client);
}

RELEASE_RETAIN_FUNCS(dnssd_client);

static void
dnssd_client_context_release(void *context)
{
    dnssd_client_t *client = context;
    RELEASE_HERE(client, dnssd_client);
}

static void
dnssd_client_service_tracker_callback(void *context)
{
    dnssd_client_t *client = context;

    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_service_list_changed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&client->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
dnssd_client_probe_callback(thread_service_t *UNUSED service, void *context, bool UNUSED succeeded)
{
    dnssd_client_t *client = context;
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_probe_completed, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&client->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
dnssd_client_get_mesh_local_prefix_callback(void *context, const char *prefix_string, int status)
{
    dnssd_client_t *client = context;
    INFO(PUB_S_SRP " %d", prefix_string != NULL ? prefix_string : "<null>", status);
    if (status != kCTIStatus_NoError || prefix_string == NULL) {
        goto fail;
    }

    char prefix_buf[INET6_ADDRSTRLEN];

    const char *prefix_addr_string;
    char *slash = strchr(prefix_string, '/');
    if (slash != NULL) {
        size_t len = slash - prefix_string;
        if (len == 0) {
            ERROR("bogus prefix: " PRI_S_SRP, prefix_string);
            goto fail;
        }
        if (len - 1 > sizeof(prefix_buf)) {
            ERROR("prefix too long: " PRI_S_SRP, prefix_string);
            goto fail;
        }
        memcpy(prefix_buf, prefix_string, len);
        prefix_buf[len] = 0;
        prefix_addr_string = prefix_buf;
    } else {
        prefix_addr_string = prefix_string;
    }
    if (!inet_pton(AF_INET6, prefix_addr_string, &client->mesh_local_prefix)) {
        ERROR("prefix syntax incorrect: " PRI_S_SRP, prefix_addr_string);
        goto fail;
    }
    client->have_mesh_local_prefix = true;
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_got_mesh_local_prefix, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&client->state_header, event);
    RELEASE_HERE(event, state_machine_event);
fail:
    RELEASE_HERE(client, dnssd_client); // was retained for callback, can only get one callback
    return;
}

static state_machine_state_t
dnssd_client_remove_published_service(dnssd_client_t *client)
{
    if (client->dns_service_registration != NULL) {
        mrc_dns_service_registration_forget(&client->dns_service_registration);
    }
    return dnssd_client_state_not_client;
}

static state_machine_state_t
dnssd_client_service_unpublish(dnssd_client_t *client)
{
    if (client->dns_service_registration != NULL) {
        thread_service_note(client->id, client->published_service, "unpublishing service");
    }
    dnssd_client_remove_published_service(client);

    return dnssd_client_state_not_client;
}

static void
dnssd_client_dns_service_event_handler(const mrc_dns_service_registration_event_t mrc_event, const OSStatus event_err,
                                       dnssd_client_t *client)
{
    switch(mrc_event)
    {
    case mrc_dns_service_registration_event_started:
        INFO("DNS service registration started");
        break;
    case mrc_dns_service_registration_event_interruption:
        INFO("DNS service registration interrupted" );
        break;

    case mrc_dns_service_registration_event_invalidation:
        if (event_err) {
            ERROR("DNS service registration invalidated with error: %d", (int)event_err);
        } else {
            INFO("DNS service registration gracefully invalidated");
        }
        state_machine_event_t *event =
            state_machine_event_create(state_machine_event_type_dns_registration_invalidated, NULL);
        if (event == NULL) {
            ERROR("unable to allocate event to deliver");
        } else {
            state_machine_event_deliver(&client->state_header, event);
            RELEASE_HERE(event, state_machine_event);
        }
        // The invalidation event should be the last event we get.
        RELEASE_HERE(client, dnssd_client);
        break;
    }
}


static state_machine_state_t
dnssd_client_service_publish(dnssd_client_t *client)
{
    dnssd_client_service_unpublish(client);
    state_machine_state_t ret = dnssd_client_state_not_client;

    mdns_dns_service_definition_t definition = mdns_dns_service_definition_create();
    if (definition == NULL) {
        ERROR("unable to allocate mdns_dns_service_definition object");
        goto out;
    }

    OSStatus err;
    mdns_domain_name_t domain_name = mdns_domain_name_create("default.service.arpa.",
                                                             mdns_domain_name_create_opts_none, &err);
    if (err != kNoErr) {
        ERROR("failed to create domain name for default.service.arpa.: %d\n", (int)err);
        goto out;
    }

    err = mdns_dns_service_definition_add_domain(definition, domain_name);
    mdns_forget(&domain_name);

    uint8_t *aaaa_data;
    uint16_t port = 0;
    // Use the port we probed. We probe port 53 for anycast, and the advertised service port for unicast.
    if (client->published_service->service_type == unicast_service) {
        aaaa_data = &client->published_service->u.unicast.address.s6_addr[0];
        // Only use the advertised port if there's no anycast service--pre-2024 Apple BRs only answer DNS queries on
        // port 53.
        if (client->published_service->u.unicast.anycast_also_present) {
            port = 53;
        } else {
            port = (client->published_service->u.unicast.port[0] << 8) + client->published_service->u.unicast.port[1];
        }
    } else if (client->published_service->service_type == anycast_service) {
        aaaa_data = &client->published_service->u.anycast.address.s6_addr[0];
        port = 53;
    }
    mdns_address_t mdns_server_address = mdns_address_create_ipv6(aaaa_data, port, 0);
    if (mdns_server_address == NULL) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(aaaa_data, ipv6_addr_buf);
        ERROR("failed to create address object");
        goto out;
    }

    err = mdns_dns_service_definition_append_server_address(definition, mdns_server_address);
    mdns_forget(&mdns_server_address);
    if (err != kNoErr) {
        ERROR("couldn't append server address to service definition");
        goto out;
    }

    client->dns_service_registration = mrc_dns_service_registration_create(definition);
    if (client->dns_service_registration == NULL) {
        ERROR("unable to create client DNS service registration");
        goto out;
    }
    mrc_dns_service_registration_set_queue(client->dns_service_registration, dispatch_get_main_queue());

    RETAIN_HERE(client, dnssd_client); // For the handler
    mrc_dns_service_registration_set_event_handler(client->dns_service_registration,
                                                   ^(const mrc_dns_service_registration_event_t event, const OSStatus event_err)
                                                   { dnssd_client_dns_service_event_handler(event, event_err, client); });
    mrc_dns_service_registration_activate( client->dns_service_registration );
    ret = dnssd_client_state_invalid;
out:
    mdns_forget(&definition);
    return ret;
}

static state_machine_state_t dnssd_client_action_startup(state_machine_header_t *state_header,
                                                         state_machine_event_t *event);
static state_machine_state_t dnssd_client_action_not_client(state_machine_header_t *state_header,
                                                            state_machine_event_t *event);
static state_machine_state_t dnssd_client_action_client(state_machine_header_t *state_header,
                                                        state_machine_event_t *event);

// States:
// -- not_client: Not a client because server or because no service (in which case hopefully we are becoming server)
// --     client: Found a working service, configured as client

#define SERVICE_PUB_NAME_DECL(name) dnssd_client_state_##name, #name
static state_machine_decl_t dnssd_client_states[] = {
    { SERVICE_PUB_NAME_DECL(invalid),                            NULL },
    { SERVICE_PUB_NAME_DECL(startup),                            dnssd_client_action_startup },
    { SERVICE_PUB_NAME_DECL(not_client),                         dnssd_client_action_not_client },
    { SERVICE_PUB_NAME_DECL(client),                             dnssd_client_action_client },
};
#define DNSSD_CLIENT_NUM_STATES ((sizeof(dnssd_client_states)) / (sizeof(state_machine_decl_t)))

#define STATE_MACHINE_HEADER_TO_CLIENT(state_header)                                       \
    if (state_header->state_machine_type != state_machine_type_dnssd_client) {             \
        ERROR("state header type isn't omr_client: %d", state_header->state_machine_type); \
        return dnssd_client_state_invalid;                                                 \
    }                                                                                      \
    dnssd_client_t *client = state_header->state_object

static bool
dnssd_client_should_be_client(dnssd_client_t *client)
{
    bool might_publish = false;
    bool associated = true;
    bool should_be_client = false;
    srp_server_t *server_state = client->server_state;

    if (!service_publisher_could_publish(server_state->service_publisher)) {
        should_be_client = true;
        might_publish = true;
    }

    if (!thread_tracker_associated_get(server_state->thread_tracker, false)) {
        associated = false;
        should_be_client = false;
    }

    INFO(PUB_S_SRP PUB_S_SRP PUB_S_SRP,
         should_be_client ?                "could be client" : "can't be client",
         might_publish ?                    " might publish" : " won't publish",
         associated ?                                     "" : " not associated ");
    return should_be_client;
}

// We start in this state and remain here until we get a mesh-local prefix.
static state_machine_state_t
dnssd_client_action_startup(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_CLIENT(state_header);
    BR_STATE_ANNOUNCE(client, event);

    if (client->have_mesh_local_prefix) {
        return dnssd_client_state_not_client;
    }
    return dnssd_client_state_invalid;
}

// We get into this state when there is no SRP service published on the Thread network other than our own.
// If we stop publishing (because a BR-based service showed up), then we go to the probe state.
static state_machine_state_t
dnssd_client_action_not_client(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_CLIENT(state_header);
    BR_STATE_ANNOUNCE(client, event);

    if (event == NULL) {
        if (client->published_service != NULL) {
            dnssd_client_service_unpublish(client);
        }
    }

    // We do the same thing here for any event we get, because we're just waiting for conditions to be right.
    if (dnssd_client_should_be_client(client)) {
        thread_service_t *service;

        // See if we now have a service that's been successfully probed; if so, publish it.
        service = service_tracker_verified_service_get(client->server_state->service_tracker);
        if (service != NULL) {
            if (client->published_service != NULL) {
                thread_service_release(client->published_service);
            }
            client->published_service = service;
            thread_service_retain(client->published_service);
            return dnssd_client_state_client;
        }

        // Check to see if we can start a new probe
        service = service_tracker_unverified_service_get(client->server_state->service_tracker);
        if (service != NULL) {
            if (service->service_type == anycast_service) {
                memcpy(&service->u.anycast.address, &client->mesh_local_prefix, 8);
                memcpy(&service->u.anycast.address.s6_addr[8], thread_rloc_preamble, 6);
                service->u.anycast.address.s6_addr[14] = service->rloc16 >> 8;
                service->u.anycast.address.s6_addr[15] = service->rloc16 & 255;
            }
            RETAIN_HERE(client, dnssd_client); // For the probe
            probe_srp_service(service, client, dnssd_client_probe_callback, dnssd_client_context_release);
            return dnssd_client_state_invalid;
        }

        // This should only ever happen if we get the service list update before the service publisher gets it.
        INFO("no service to publish");
        return dnssd_client_state_invalid;
    }
    return dnssd_client_state_invalid;
}

// We get into this state when we've published a service.
static state_machine_state_t
dnssd_client_action_client(state_machine_header_t *state_header, state_machine_event_t *event)
{
    STATE_MACHINE_HEADER_TO_CLIENT(state_header);
    BR_STATE_ANNOUNCE(client, event);

    if (event == NULL) {
        // Publish the service.
        dnssd_client_service_publish(client);
        return dnssd_client_state_invalid;
    }

    // This can happen if the daemon disconnects.
    if (client->published_service == NULL) {
        return dnssd_client_state_not_client;
    }

    // If we should no longer be client, unpublish the service and wait
    if (!dnssd_client_should_be_client(client)) {
        return dnssd_client_state_not_client;
    }

    if (service_tracker_verified_service_still_exists(client->server_state->service_tracker,
                                                      client->published_service)) {
        return dnssd_client_state_invalid;
    }

    // If we get here, the service we have been publishing is no longer present.
    return dnssd_client_state_not_client;
}

void
dnssd_client_cancel(dnssd_client_t *client)
{
    service_tracker_callback_cancel(client->server_state->service_tracker, client);
    thread_tracker_callback_cancel(client->server_state->thread_tracker, client);
    if (client->active_data_set_connection != NULL) {
        cti_events_discontinue(client->active_data_set_connection);
        RELEASE_HERE(client, dnssd_client); // callback held reference
        client->active_data_set_connection = NULL;
    }
    dnssd_client_remove_published_service(client);
}

dnssd_client_t *
dnssd_client_create(srp_server_t *server_state)
{
    dnssd_client_t *ret = NULL, *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return client;
    }
    RETAIN_HERE(client, dnssd_client);

    char client_id_buf[100];
    snprintf(client_id_buf, sizeof(client_id_buf), "[SP%lld]", ++dnssd_client_serial_number);
    client->id = strdup(client_id_buf);
    if (client->id == NULL) {
        ERROR("no memory for client ID");
        goto out;
    }
    client->interface_index = -1;

    if (!state_machine_header_setup(&client->state_header,
                                    client, client->id,
                                    state_machine_type_dnssd_client,
                                    dnssd_client_states,
                                    DNSSD_CLIENT_NUM_STATES)) {
        ERROR("header setup failed");
        goto out;
    }

    client->server_state = server_state;
    if (!service_tracker_callback_add(server_state->service_tracker, dnssd_client_service_tracker_callback,
                                      dnssd_client_context_release, client))
    {
        goto out;
    }
    RETAIN_HERE(client, dnssd_client); // for service tracker

    ret = client;
    client = NULL;
out:
    if (client != NULL) {
        RELEASE_HERE(client, dnssd_client);
    }
    return ret;
}

static void
dnssd_client_get_tunnel_name_callback(void *context, const char *name, cti_status_t status)
{
    dnssd_client_t *client = context;
    if (status != kCTIStatus_NoError) {
        INFO("didn't get tunnel name, error code %d", status);
        goto fail;
    }
    client->interface_index = if_nametoindex(name);
fail:
    RELEASE_HERE(client, dnssd_client); // was retained for callback, can only get one callback
}

static void
dnssd_client_active_data_set_changed_callback(void *context, cti_status_t status)
{
    dnssd_client_t *client = context;

    if (status != kCTIStatus_NoError) {
        ERROR("error %d", status);
        RELEASE_HERE(client, dnssd_client); // no more callbacks
        cti_events_discontinue(client->active_data_set_connection);
        client->active_data_set_connection = NULL;
        return;
    }

    status = cti_get_mesh_local_prefix(client->server_state, client, dnssd_client_get_mesh_local_prefix_callback, NULL);
    if (status != kCTIStatus_NoError) {
        ERROR("cti_get_mesh_local_prefix failed with status %d", status);
    } else {
        RETAIN_HERE(client, dnssd_client); // for mesh-local callback
    }
    status = cti_get_tunnel_name(client->server_state, client, dnssd_client_get_tunnel_name_callback, NULL);
    if (status != kCTIStatus_NoError) {
        ERROR("cti_get_tunnel_name failed with status %d", status);
    } else {
        RETAIN_HERE(client, dnssd_client); // for tunnel name callback
    }
}

void
dnssd_client_start(dnssd_client_t *client)
{
    cti_track_active_data_set(client->server_state, &client->active_data_set_connection,
                              client, dnssd_client_active_data_set_changed_callback, NULL);
    RETAIN_HERE(client, dnssd_client); // for callback
    dnssd_client_active_data_set_changed_callback(client, kCTIStatus_NoError); // Get the initial state.
    state_machine_next_state(&client->state_header, dnssd_client_state_startup);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
