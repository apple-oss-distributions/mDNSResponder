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
#import <NetworkExtension/NEPolicySession.h>
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
#if PUBLISH_USING_DNSSERVICE_API
    DNSRecordRef aaaa_record_ref, ns_record_ref;
#else
    nw_resolver_config_t resolver_config;
    NEPolicySession *policy_session;
#endif
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
    RELEASE_HERE(client, dnssd_client);
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

#if PUBLISH_USING_DNSSERVICE_API
static void
dnssd_client_remove_published_service(dnssd_client_t *client)
{
    if (client->shared_txn != NULL) {
        ioloop_dnssd_txn_cancel(client->shared_txn);
        ioloop_dnssd_txn_release(client->shared_txn);
        client->shared_txn = NULL;
    }
    client->aaaa_record_ref = NULL;
    client->ns_record_ref = NULL;
    if (client->published_service != NULL) {
        thread_service_release(client->published_service);
        client->published_service = NULL;
    }
}

static void
dnssd_client_publish_failed(dnssd_client_t *client)
{
    dnssd_client_remove_published_service(client);
    state_machine_event_t *event = state_machine_event_create(state_machine_event_type_daemon_disconnect, NULL);
    if (event == NULL) {
        ERROR("unable to allocate event to deliver");
        return;
    }
    state_machine_event_deliver(&client->state_header, event);
    RELEASE_HERE(event, state_machine_event);
}

static void
dnssd_client_shared_connection_failed_callback(void *context, int UNUSED status)
{
    dnssd_client_t *client = context;
    ERROR("daemon connection failed");
    dnssd_client_publish_failed(client);
}

static state_machine_state_t
dnssd_client_service_unpublish(dnssd_client_t *client)
{
    if (client->aaaa_record_ref != NULL) {
        thread_service_note(client->id, client->published_service, "unpublishing service");
    }
    dnssd_client_remove_published_service(client);

    return dnssd_client_state_not_client;
}

static void dnssd_client_record_callback(DNSServiceRef UNUSED sdref, DNSRecordRef UNUSED rref,
                                         DNSServiceFlags UNUSED flags, DNSServiceErrorType error_code, void *context)
{
    dnssd_client_t *client = context;

    if (error_code != kDNSServiceErr_NoError) {
        if (rref == client->aaaa_record_ref) {
            ERROR("unable to register AAAA record: error code %d", error_code);
        } else {
            ERROR("unable to register NS record: error code %d", error_code);
        }
        dnssd_client_publish_failed(client);
        return;
    }
    if (rref == client->aaaa_record_ref) {
        ERROR("successfully registered AAAA record");
    } else {
        ERROR("successfully registered NS record");
    }
}

static state_machine_state_t
dnssd_client_service_publish(dnssd_client_t *client)
{
    int err;
    dns_towire_state_t towire;
    dns_wire_t message;

    thread_service_note(client->id, client->published_service, "publishing service");

    // Set up advertisement for the DNSSD server:

    // First we need a shared connection for DNSServiceRegisterRecord.
    err = DNSServiceCreateConnection(&client->shared_connection);
    if (err != kDNSServiceErr_NoError) {
        ERROR("DNSServiceCreateConnection failed");
        return dnssd_client_service_unpublish(client);
    }
    client->shared_txn = ioloop_dnssd_txn_add(client->shared_connection, client, dnssd_client_context_release,
                                              dnssd_client_shared_connection_failed_callback);
    if (client->shared_txn == NULL) {
        return dnssd_client_service_unpublish(client);
    }
    RETAIN_HERE(client, dnssd_client); // For the shared transaction's callbacks

    //   Set up AAAA record for dnssd-server.local
    uint8_t *aaaa_rdata;
    if (client->published_service->service_type == unicast_service) {
        aaaa_rdata = &client->published_service->u.unicast.address.s6_addr[0];
    } else if (client->published_service->service_type == anycast_service) {
        aaaa_rdata = &client->published_service->u.anycast.address.s6_addr[0];
    } else {
        ERROR("invalid service type for published service: %d", client->published_service->service_type);
        return dnssd_client_service_unpublish(client);
    }
    err = DNSServiceRegisterRecord(client->shared_connection, &client->aaaa_record_ref,
                                   kDNSServiceFlagsKnownUnique, client->interface_index,
                                   "dnssd-server.local", kDNSServiceType_AAAA, kDNSServiceClass_IN, 16, aaaa_rdata, 0,
                                   dnssd_client_record_callback, client);
    if (err != kDNSServiceErr_NoError) {
        ERROR("DNSServiceRegisterRecord failed - record: dnssd-server.local AAAA ");
        return dnssd_client_service_unpublish(client);
    }

    //   Set up default.service.arpa NS dnssd-server.local
    memset(&towire, 0, sizeof(towire));
    towire.message = &message;
    towire.lim = &message.data[DNS_DATA_SIZE];
    towire.p = message.data;

    dns_full_name_to_wire(NULL, &towire, "dnssd-server.local.");
    err = DNSServiceRegisterRecord(client->shared_connection, &client->ns_record_ref,
                                   kDNSServiceFlagsKnownUnique | kDNSServiceFlagsForceMulticast,
                                   client->interface_index,
                                   "default.service.arpa", kDNSServiceType_NS, kDNSServiceClass_IN,
                                   towire.p - message.data, message.data, 0, dnssd_client_record_callback, client);
    if (err != kDNSServiceErr_NoError) {
        ERROR("DNSServiceRegisterRecord failed - record: " "default.service.arpa" " NS " "dnssd-server.local");
        return dnssd_client_service_unpublish(client);
    }

#if PUBLISH_LEGACY_BROWSING_DOMAIN_FOR_THREAD_DEVICE

    memset(&towire, 0, sizeof(towire));
    towire.message = &message;
    towire.lim = &message.data[DNS_DATA_SIZE];
    towire.p = message.data;

    dns_full_name_to_wire(NULL, &towire, "default.service.arpa.");
    err = DNSServiceRegisterRecord(client->service_ref, &client->ptr_record_ref,
                                   kDNSServiceFlagsKnownUnique, server_state->advertise_interface, AUTOMATIC_BROWSING_DOMAIN,
                                   kDNSServiceType_PTR, kDNSServiceClass_IN, towire.p - message.data, message.data, 0,
                                   dnssd_client_record_callback, client);
    if (err != kDNSServiceErr_NoError) {
        ERROR("DNSServiceRegisterRecord failed - record: " AUTOMATIC_BROWSING_DOMAIN " PTR " "default.service.arpa");
        return dnssd_client_service_unpublish(client);
    }
#endif

    return dnssd_client_state_invalid;
}
#else
static state_machine_state_t
dnssd_client_remove_published_service(dnssd_client_t *client)
{
    if (client->resolver_config != NULL) {
        nw_release(client->resolver_config);
        client->resolver_config = NULL;
    }
    if (client->policy_session != NULL) {
        [client->policy_session release];
        client->policy_session = NULL;
    }
    return dnssd_client_state_not_client;
}

static state_machine_state_t
dnssd_client_service_unpublish(dnssd_client_t *client)
{
    if (client->resolver_config != NULL) {
        thread_service_note(client->id, client->published_service, "unpublishing service");
    }
    dnssd_client_remove_published_service(client);

    return dnssd_client_state_not_client;
}

static state_machine_state_t
dnssd_client_service_publish(dnssd_client_t *client)
{
    dnssd_client_service_unpublish(client);

    nw_resolver_config_t config = nw_resolver_config_create();
    nw_resolver_config_set_protocol(config, nw_resolver_protocol_dns53);
    nw_resolver_config_set_class(config, nw_resolver_class_designated_direct);
    uint8_t *aaaa_data;
    if (client->published_service->service_type == unicast_service) {
        aaaa_data = &client->published_service->u.unicast.address.s6_addr[0];
    } else if (client->published_service->service_type == anycast_service) {
        aaaa_data = &client->published_service->u.anycast.address.s6_addr[0];
    }
    char name_server_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, aaaa_data, name_server_address, sizeof(name_server_address));
    nw_resolver_config_add_name_server(config, name_server_address);

    NSUUID *uuid = [[NSUUID alloc] init];

    uuid_t uuid_bytes;
    [uuid getUUIDBytes:uuid_bytes];
    nw_resolver_config_set_identifier(config, uuid_bytes);

    bool published = nw_resolver_config_publish(config);
    if (published) {
        INFO("Registered resolver at " PRI_S_SRP " uuid %{uuid_t}.16P", name_server_address, uuid_bytes);
        client->resolver_config = config;
    } else {
        ERROR("Failed to register resolver");
        nw_release(config);
        return dnssd_client_state_not_client;
    }

    client->policy_session = [[NEPolicySession alloc] init];

    NEPolicy *policy = [[NEPolicy alloc] initWithOrder:1 result:[NEPolicyResult netAgentUUID:uuid]
                        conditions:@[ [NEPolicyCondition domain:@"default.service.arpa"] ]];
    [client->policy_session addPolicy: policy ];
    [policy release];
    [uuid release];

    client->policy_session.priority = NEPolicySessionPriorityHigh;
    [client->policy_session apply];

    return dnssd_client_state_invalid;
}
#endif // PUBLISH_USING_DNSSERVICE_API

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
            probe_srp_service(service, client, dnssd_client_probe_callback);
            RETAIN_HERE(client, dnssd_client); // For the callback
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
