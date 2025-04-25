/* threadsim.c
 *
 * Copyright (c) 2023-2024 Apple Inc. All rights reserved.
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
 * Thread network data simulator (doesn't simulate connectivity, just configuration)
 */

#include <dns_sd.h>
#include "srp.h"
#include "srp-test-runner.h"
#include "srp-api.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "srp-proxy.h"
#include "srp-dnssd.h"
#include "srp-mdns-proxy.h"
#include "test-api.h"
#include "cti-services.h"
#include "threadsim.h"
#include "srp-crypto.h"

#define MAX_RLOCS 20 // No more than 20 thread routers

#define THREADSIM_BEFORE_COMMON()                                                                                      \
    threadsim_node_state_t *node = server->threadsim_node;                                                             \
    test_state_t *test_state = server->test_state;                                                                     \
    if (node == NULL || node->network == NULL) {                                                                       \
        TEST_FAIL_STATUS(test_state, "server state " PUB_S_SRP " has no node (%p) or network.", server->name, node);   \
        return kCTIStatus_DaemonNotRunning;                                                                            \
    }                                                                                                                  \
    RETAIN_HERE(node, threadsim_node_state)

#define THREADSIM_AFTER_COMMON(msecs, block)                                                                           \
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ((msecs) / 10) + (srp_random32() % ((int)((msecs) * 0.9)))),       \
                   dispatch_get_main_queue(), block)

#define THREADSIM_AFTER(msecs, block)                                                                                  \
    THREADSIM_BEFORE_COMMON();                                                                                         \
    THREADSIM_AFTER_COMMON(msecs, block);                                                                              \
    return kCTIStatus_NoError

#define THREADSIM_AFTER_STATEFUL(msecs, func, union_entry)                                                             \
    THREADSIM_BEFORE_COMMON();                                                                                         \
    cti_connection_t *connection = threadsim_connection_create(node, context);                                          \
    if (connection == NULL) {                                                                                          \
        TEST_FAIL_STATUS(test_state, "no memory for cti_connection_t for " PRI_S_SRP, server->name);                   \
    }                                                                                                                  \
    *ref = connection;                                                                                                 \
    connection->reply.union_entry = callback;                                                                          \
    connection->deliver = func;                                                                                        \
    RETAIN_HERE(connection, cti_connection);                                                                           \
    THREADSIM_AFTER_COMMON(msecs, ^{                                                                                   \
            func(connection);                                                                                          \
            RELEASE_HERE(connection, cti_connection);                                                                  \
            RELEASE_HERE(node, threadsim_node_state); });                                                              \
    return kCTIStatus_NoError

typedef void (*threadsim_deliver_callback_t)(cti_connection_t *connection);

struct cti_connection {
    int ref_count;
    cti_connection_t *next;
    threadsim_node_state_t *node;
    int network_data_serial;
    cti_callback_t reply;
    threadsim_deliver_callback_t deliver;
    void *context;
};

struct threadsim_network_state {
    int ref_count;
    int network_data_serial;
    uint64_t xpanid;
    uint64_t mesh_local_prefix;
    int panid;
    cti_route_vec_t *routes;
    cti_prefix_vec_t *prefixes;
    cti_service_vec_t *services;
    threadsim_node_state_t *nodes;
    int num_rlocs;
    uint16_t rlocs[MAX_RLOCS];
    uint32_t partition_id;
};

struct threadsim_node_state {
    int ref_count;
    threadsim_node_state_t *next;
    srp_server_t *server_state;
    threadsim_network_state_t *network;
    struct in6_addr mesh_local_address;
    cti_service_t *unicast, *anycast;
    cti_prefix_t *omr_prefix;
    cti_route_t *nat64_route, *default_route;
    cti_network_node_type_t role;
    cti_network_state_t network_state;
    uint16_t rloc;
    cti_connection_t *watchers;
};

static void
threadsim_network_state_finalize(threadsim_network_state_t *state)
{
    if (state->prefixes != NULL) {
        cti_prefix_vec_release(state->prefixes);
    }
    if (state->routes != NULL) {
        cti_route_vec_release(state->routes);
    }
    if (state->services != NULL) {
        cti_service_vec_release(state->services);
    }
    free(state);
}

threadsim_network_state_t *
threadsim_network_state_create(void)
{
    threadsim_network_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return state;
    }
    RETAIN_HERE(state, threadsim_network_state);
    state->xpanid = srp_random64();
    state->mesh_local_prefix = srp_random64();
    state->panid = srp_random16();
    state->routes = cti_route_vec_create(16);
    state->prefixes = cti_prefix_vec_create(16);
    state->services = cti_service_vec_create(16);
    return state;
}

static void
threadsim_node_state_finalize(threadsim_node_state_t *state)
{
    if (state->network != NULL) {
        RELEASE_HERE(state->network, threadsim_network_state);
    }
    free(state);
}

static bool
threadsim_network_rloc_available(threadsim_network_state_t *network, uint16_t rloc)
{
    for (int i = 0; i < MAX_RLOCS; i++) {
        if (network->rlocs[i] == rloc) {
            return false;
        }
    }
    return true;
}

threadsim_node_state_t *
threadsim_node_state_create(threadsim_network_state_t *network, srp_server_t *server,
                            cti_network_state_t network_state, cti_network_node_type_t role)
{
    if (network->num_rlocs == MAX_RLOCS) {
        TEST_FAIL(server->test_state, "no available rloc slots");
        return NULL;
    }
    threadsim_node_state_t *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return state;
    }
    RETAIN_HERE(state, threadsim_node_state);
    state->network = network;
    RETAIN_HERE(network, threadsim_network_state);
    state->server_state = server;
    state->role = role;
    state->network_state = network_state;
    uint16_t rloc = 0;
    int i;
    for (i = 0; i < 1000; i++) {
        rloc = srp_random16();
        if (role != kCTIRoleChild) {
            rloc = rloc & 0xff00;
        }
        if (threadsim_network_rloc_available(network, rloc)) {
            break;
        }
    }
    if (i == 1000) { // shouldn't ever happen
        TEST_FAIL(server->test_state, "unable to find a viable rloc after 1000 attempts!");
        RELEASE_HERE(state, threadsim_node_state);
        return NULL;
    }
    network->rlocs[network->num_rlocs++] = rloc;
    state->rloc = rloc;
    return state;
}

static void
cti_connection_finalize(cti_connection_t *connection)
{

    if (connection->node != NULL) {
        RELEASE_HERE(connection->node, threadsim_node_state);
        connection->node = NULL;
    }
    free(connection);
}

static cti_connection_t *
threadsim_connection_create(threadsim_node_state_t *node, void *context)
{
    cti_connection_t *connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return NULL;
    }
    RETAIN_HERE(connection, cti_connection);
    connection->context = context;
    connection->node = node;
    RETAIN_HERE(connection->node, threadsim_node_state);
    threadsim_network_state_t *network = node->network;
    if (network == NULL) {
        ERROR("no network");
        RELEASE_HERE(connection, cti_connection);
        return NULL;
    }
    cti_connection_t **lp;
    for (lp = &node->watchers; *lp != NULL; lp = &((*lp)->next))
        ;
    *lp = connection;
    RETAIN_HERE(*lp, cti_connection);
    return connection;
}

cti_status_t
cti_events_discontinue(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    // connection->node simulates the xpc connection we'd have to threadradiod; by taking this
    // "connection" off the node's watcher list, we stop further events from being delivered to it.
    if (connection->node != NULL) {
        cti_connection_t **lp;
        for (lp = &node->watchers; *lp != NULL; lp = &((*lp)->next)) {
            if (*lp == connection) {
                *lp = connection->next;
                RELEASE_HERE(connection, cti_connection); // This releases the node's reference, not the caller's.
                break;
            }
        }
    }
    RELEASE_HERE(connection, cti_connection); // This releases the caller's connection.
    return kCTIStatus_NoError;
}

typedef struct { void *ptr; int random; } randomization_array_element_t;
static int
threadsim_randomize_cmp(const void *va, const void *vb)
{
    const randomization_array_element_t *a = va;
    const randomization_array_element_t *b = vb;
    return a->random - b->random;
}

// Return arrays in non-deterministic order to make sure (over many tests) that there aren't bugs relating
// to the order that the elements in the array arrive.
static void
threadsim_randomize_array(void **array, size_t num)
{
    randomization_array_element_t *randomization_array = malloc(num * sizeof(*randomization_array));
    if (randomization_array != NULL) {
        for (size_t i = 0; i < num; i++) {
            randomization_array[i].ptr = array[i];
            randomization_array[i].random = srp_random16();
        }
        qsort(randomization_array, num, sizeof(randomization_array_element_t), threadsim_randomize_cmp);
        for (size_t i = 0; i < num; i++) {
            array[i] = randomization_array[i].ptr;
        }
    }
}

static void
threadsim_service_list_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    size_t num_services = 0;
    if (node->network->services != NULL) {
        num_services += node->network->services->num;
    }
    if (node->unicast != NULL) {
        num_services++;
    }
    if (node->anycast != NULL) {
        num_services++;
    }
    cti_service_vec_t *services = cti_service_vec_create(num_services);
    size_t service_index = 0;

#define SERVICE_COPY(src)                                        \
    if (service_index == services->num) {                        \
        abort();                                                 \
    }                                                            \
    services->services[service_index] = src;                     \
    RETAIN_HERE(services->services[service_index], cti_service); \
    service_index++

    if (node->network->services != NULL) {
        for (size_t i = 0; i < node->network->services->num; i++) {
            SERVICE_COPY(node->network->services->services[i]);
        }
    }
    if (node->unicast != NULL) {
        SERVICE_COPY(node->unicast);
    }
    if (node->anycast != NULL) {
        SERVICE_COPY(node->anycast);
    }
    services->num = service_index;
    threadsim_randomize_array((void **)services->services, service_index);
    connection->reply.service_reply(connection->context, services, kCTIStatus_NoError);
    cti_service_vec_release(services);
}

static void
threadsim_prefix_list_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    size_t num_prefixes = 0;
    if (node->network->prefixes != NULL) {
        num_prefixes += node->network->prefixes->num;
    }
    if (node->omr_prefix != NULL) {
        num_prefixes++;
    }
    cti_prefix_vec_t *prefixes = cti_prefix_vec_create(num_prefixes);
    size_t prefix_index = 0;

#define PREFIX_COPY(src)                                       \
    if (prefix_index == prefixes->num) {                       \
        abort();                                               \
    }                                                          \
    prefixes->prefixes[prefix_index] = src;                    \
    RETAIN_HERE(prefixes->prefixes[prefix_index], cti_prefix); \
    prefix_index++

    if (node->network->prefixes != NULL) {
        for (size_t i = 0; i < node->network->prefixes->num; i++) {
            PREFIX_COPY(node->network->prefixes->prefixes[i]);
        }
    }
    if (node->omr_prefix != NULL) {
        PREFIX_COPY(node->omr_prefix);
    }
    prefixes->num = prefix_index;
    threadsim_randomize_array((void **)prefixes->prefixes, prefix_index);
    connection->reply.prefix_reply(connection->context, prefixes, kCTIStatus_NoError);
    cti_prefix_vec_release(prefixes);
}

static void
threadsim_state_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    connection->reply.state_reply(connection->context, node->network_state, kCTIStatus_NoError);
}

static void
threadsim_partition_id_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    connection->reply.uint64_property_reply(connection->context, node->network->partition_id, kCTIStatus_NoError);
}

static void
threadsim_xpanid_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    connection->reply.uint64_property_reply(connection->context, node->network->xpanid, kCTIStatus_NoError);
}

static void
threadsim_node_type_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    connection->reply.network_node_type_reply(connection->context, node->role, kCTIStatus_NoError);
}

static void
    threadsim_offmesh_route_list_callback(cti_connection_t *connection)
{
    threadsim_node_state_t *node = connection->node;
    if (connection->reply.reply == NULL || node == NULL || node->network == NULL) { // canceled
        return;
    }
    size_t num_routes = 0;
    if (node->network->routes != NULL) {
        num_routes += node->network->routes->num;
    }
    if (node->default_route != NULL) {
        num_routes++;
    }
    if (node->default_route != NULL) {
        num_routes++;
    }
    cti_route_vec_t *routes = cti_route_vec_create(num_routes);
    size_t route_index = 0;

#define ROUTE_COPY(src)                                  \
    if (route_index == routes->num) {                    \
        abort();                                         \
    }                                                    \
    routes->routes[route_index] = src;                   \
    RETAIN_HERE(routes->routes[route_index], cti_route); \
    route_index++

    if (node->network->routes != NULL) {
        for (size_t i = 0; i < node->network->routes->num; i++) {
            ROUTE_COPY(node->network->routes->routes[i]);
        }
    }
    if (node->default_route != NULL) {
        ROUTE_COPY(node->default_route);
    }
    if (node->nat64_route != NULL) {
        ROUTE_COPY(node->nat64_route);
    }
    routes->num = route_index;
    threadsim_randomize_array((void **)routes->routes, route_index);
    connection->reply.offmesh_route_reply(connection->context, routes, kCTIStatus_NoError);
    cti_route_vec_release(routes);
}

static void
threadsim_onmesh_prefix_callback(cti_connection_t *connection)
{
    (void)connection;
}

static void
threadsim_rloc16_callback(cti_connection_t *connection)
{
    (void)connection;
}

static void threadsim_active_data_set_callback(cti_connection_t *connection)
{
    (void)connection;
}

static void threadsim_wed_status_callback(cti_connection_t *connection)
{
    (void)connection;
}

static void threadsim_neighbor_status_callback(cti_connection_t *connection)
{
    (void)connection;
}

cti_status_t
cti_get_tunnel_name_(srp_server_t *NULLABLE server, void *context, cti_string_property_reply_t callback,
                     run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER(1000, ^{
            if (callback != NULL) {
                callback(context, "utun0", kCTIStatus_NoError);
            }
            RELEASE_HERE(node, threadsim_node_state);
        });
}

cti_status_t
cti_get_mesh_local_prefix_(srp_server_t *server, void *context, cti_string_property_reply_t callback,
                           run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER(1000, ^{
            if (callback != NULL) {
                char buf[INET6_ADDRSTRLEN + 3];
                int status = kCTIStatus_NoError;
                const char *ret = NULL;
                if (node->network != NULL) {
                    ret = inet_ntop(AF_INET6, &node->network->mesh_local_prefix, buf, sizeof(buf));
                    if (ret != NULL) {
                        size_t len = strlen(ret);
                        memcpy(&buf[len], "/64", 4);
                    }
                } else {
                    status = kCTIStatus_Disconnected;
                }
                callback(context, ret, status);
            }
            RELEASE_HERE(node, threadsim_node_state);
        });
}

cti_status_t
cti_get_mesh_local_address_(srp_server_t *server, void *context, cti_string_property_reply_t callback,
                            run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER(1000, ^{
            if (callback != NULL) {
                char buf[INET6_ADDRSTRLEN + 3];
                int status = kCTIStatus_NoError;
                const char *ret = NULL;
                if (node->network != NULL) {
                    ret = inet_ntop(AF_INET6, &node->mesh_local_address, buf, sizeof(buf));
                } else {
                    status = kCTIStatus_Disconnected;
                }
                callback(context, ret, status);
            }
            RELEASE_HERE(node, threadsim_node_state);
        });
}

cti_status_t
cti_get_service_list_(srp_server_t *server, cti_connection_t **ref, void *context, cti_service_reply_t callback,
                      run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_service_list_callback, service_reply);
}

cti_status_t
cti_get_prefix_list_(srp_server_t *server, cti_connection_t **ref, void *context, cti_prefix_reply_t callback,
                     run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_prefix_list_callback, prefix_reply);
}

cti_status_t
cti_get_state_(srp_server_t *server, cti_connection_t **ref, void *context, cti_state_reply_t callback,
               run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_state_callback, state_reply);
}

cti_status_t
cti_get_partition_id_(srp_server_t *server, cti_connection_t **ref, void *context, cti_uint64_property_reply_t callback,
                      run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_partition_id_callback, uint64_property_reply);
}

cti_status_t
cti_get_extended_pan_id_(srp_server_t *server, cti_connection_t **ref, void *context,
                         cti_uint64_property_reply_t callback, run_context_t UNUSED client_queue,
                         const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_xpanid_callback, uint64_property_reply);
}

cti_status_t
cti_get_network_node_type_(srp_server_t *server, cti_connection_t **ref, void *context,
                           cti_network_node_type_reply_t callback, run_context_t UNUSED client_queue,
                           const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_node_type_callback, network_node_type_reply);
}


static void
threadsim_service_validate(threadsim_node_state_t *node, srp_server_t *server, bool remove,
                           uint32_t enterprise_number, const uint8_t *service_data, size_t service_data_length)
{
    const char *action = remove ? "removed" : "added";
    TEST_FAIL_CHECK_STATUS(server->test_state, enterprise_number == THREAD_ENTERPRISE_NUMBER,
                           "unexpected thread service enterprise number %u", enterprise_number);
    TEST_FAIL_CHECK_STATUS(server->test_state, service_data_length < 0,
                           "service data length too short: %zd", service_data_length);
    if (service_data[0] == THREAD_SRP_SERVER_OPTION) {
        TEST_FAIL_CHECK_STATUS(server->test_state, remove || node->unicast == NULL,
                               "unicast service " PUB_S_SRP " when already present", action);
    } else if (service_data[0] == THREAD_SRP_SERVER_ANYCAST_OPTION) {
        TEST_FAIL_CHECK_STATUS(server->test_state, remove || node->anycast == NULL,
                               "anycast service " PUB_S_SRP " when already present", action);
    } else {
        TEST_FAIL_STATUS(server->test_state, "unexpected thread enterprise option code %u", service_data[0]);
    }
}

static cti_service_t *
threadsim_service_create(srp_server_t *server, uint64_t enterprise_number, uint16_t rloc16, uint16_t service_type,
                         uint16_t service_version, const uint8_t *service_data, size_t service_length,
                         const uint8_t *server_data, size_t server_length, uint16_t service_id, int flags)
{
    uint8_t *cdc = malloc(service_length);
    TEST_FAIL_CHECK(server->test_state, cdc != NULL, "no memory for copy of service data");
    uint8_t *rdc = server_data != 0 ? malloc(server_length) : NULL;
    TEST_FAIL_CHECK(server->test_state, server_length == 0 || rdc != NULL, "no memory for copy of server data");
    memcpy(cdc, service_data, service_length);
    if (server_length != 0) {
        memcpy(rdc, server_data, server_length);
    }
    return cti_service_create(enterprise_number, rloc16, service_type, service_version,
                              cdc, service_length, rdc, server_length, service_id, flags);
}

static void
threadsim_update_network_data_for_node(threadsim_node_state_t *node)
{
    RETAIN_HERE(node, threadsim_node_state);
    THREADSIM_AFTER_COMMON(1000, ^{
            if (node->network != NULL) {
                for (cti_connection_t *watcher = node->watchers; watcher != NULL; watcher = watcher->next) {
                    if (watcher->deliver != NULL) {
                        watcher->deliver(watcher);
                    }
                }
            }
            RELEASE_HERE(node, threadsim_node_state);
        });
}

static void
threadsim_update_network_data(threadsim_network_state_t *network)
{
    network->network_data_serial++;
    for (threadsim_node_state_t *node = network->nodes; node != NULL; node = node->next) {
        threadsim_update_network_data_for_node(node);
    }
}

static void
threadsim_add_service_to_leader(threadsim_node_state_t *node, bool unicast, cti_reply_t callback, void *context)
{
    cti_service_t *service = NULL;
    cti_service_t *ns = NULL;
    if (node == NULL || node->server_state == NULL || node->network == NULL) {
        ERROR("invalid node: %p, srp_server %p, network %p",
              node, node ? node->server_state : NULL, node ? node->network : NULL);
        return;
    }
    srp_server_t *server = node->server_state;

    if (unicast) {
        TEST_FAIL_CHECK(server->test_state, node->unicast != NULL,
                        "add unicast service to leader but service is null.");
        ns = node->unicast;
    } else {
        TEST_FAIL_CHECK(server->test_state, node->anycast != NULL,
                        "add anycast service to leader but service is null.");
        ns = node->anycast;
    }
    if (ns == NULL) {
        // Should this be a test failure?
        INFO("no " PUB_S_SRP " service to add to leader after wait", unicast ? "unicast" : "anycast");
        return;
    }
    service = threadsim_service_create(server, ns->enterprise_number, ns->rloc16, ns->service_type, ns->service_version,
                                       ns->service, ns->service_length, ns->server, ns->server_length,
                                       ns->service_id, ns->flags | kCTIFlag_NCP);
    TEST_FAIL_CHECK(server->test_state, service != NULL, "no memory for leader copy of service");
    if (node->network->services == NULL) {
        node->network->services = cti_service_vec_create(MAX_RLOCS);
    }
    TEST_FAIL_CHECK(server->test_state, node->network->services != NULL, "no memory for leader service list");
    if (node->network->services->num == MAX_RLOCS) {
        TEST_FAIL(server->test_state, "no space in network service vector");
    }
    node->network->services->services[node->network->services->num] = service;
    node->network->services->num++;
    threadsim_update_network_data(node->network);
    if (callback != NULL) {
        callback(context, kCTIStatus_NoError);
    }
}

cti_status_t
cti_add_service_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
                 uint32_t enterprise_number, const uint8_t *service_data, size_t service_data_length,
                 const uint8_t *server_data, size_t server_data_length, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_BEFORE_COMMON();
    threadsim_service_validate(node, server, false, enterprise_number, service_data, service_data_length);
    if (service_data[0] == THREAD_SRP_SERVER_OPTION) {
        node->unicast = threadsim_service_create(server, enterprise_number, node->rloc, service_data[0], 1,
                                                 service_data, service_data_length,
                                                 server_data, server_data_length, 0, 0);
        THREADSIM_AFTER_COMMON(1000, ^{
                threadsim_add_service_to_leader(node, true, callback, context);
                RELEASE_HERE(node, threadsim_node_state);
            });
    } else if (service_data[0] == THREAD_SRP_SERVER_ANYCAST_OPTION) {
        node->anycast = threadsim_service_create(server, enterprise_number, node->rloc, 0, 0, service_data,
                                                 service_data_length, server_data, server_data_length, 0, 0);
        THREADSIM_AFTER_COMMON(1000, ^{
                threadsim_add_service_to_leader(node, false, callback, context);
                RELEASE_HERE(node, threadsim_node_state);
            });
    } else {
        TEST_FAIL_STATUS(server->test_state, "add of invalid service type %u", service_data[0]);
    }
    return kCTIStatus_NoError;
}

static void
threadsim_remove_service_from_leader(threadsim_node_state_t *node, bool unicast, cti_reply_t callback, void *context)
{
    if (node == NULL || node->server_state == NULL || node->network == NULL) {
        ERROR("invalid node: %p, srp_server %p, network %p",
              node, node ? node->server_state : NULL, node ? node->network : NULL);
        return;
    }
    srp_server_t *server = node->server_state;
    threadsim_network_state_t *network = node->network;

    if (unicast) {
        TEST_FAIL_CHECK(server->test_state, node->unicast == NULL,
                        "remove unicast service from leader but service is not null.");
    } else {
        TEST_FAIL_CHECK(server->test_state, node->anycast == NULL,
                        "remove anycast service from leader but service is not null.");
    }
    TEST_FAIL_CHECK_STATUS(server->test_state, network->services == NULL,
                           "remove " PUB_S_SRP " service from network, but service exists on node", unicast ? "unicast" : "anycast");
    size_t j = 0;
    for (size_t i = 0; i < network->services->num; i++) {
        cti_service_t *service = network->services->services[i];
        if (service->rloc16 == node->rloc &&
            service->service[0] == (unicast ? THREAD_SRP_SERVER_OPTION : THREAD_SRP_SERVER_ANYCAST_OPTION))
        {
            cti_service_release(service);
            network->services->services[i] = NULL;
        } else if (i != j) {
            network->services->services[j++] = service;
        }
    }
    network->services->num = j;
    threadsim_update_network_data(node->network);
    if (callback != NULL) {
        callback(context, kCTIStatus_NoError);
    }
}

cti_status_t
cti_remove_service_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
                    uint32_t enterprise_number, const uint8_t *service_data, size_t service_data_length,
                    const char *UNUSED file, int UNUSED line)
{
    THREADSIM_BEFORE_COMMON();
    threadsim_service_validate(node, server, true, enterprise_number, service_data, service_data_length);
    if (service_data[0] == THREAD_SRP_SERVER_OPTION) {
        if (node->unicast != NULL) {
            cti_service_release(node->unicast);
            node->unicast = NULL;
        }
        THREADSIM_AFTER_COMMON(1000, ^{
                threadsim_remove_service_from_leader(node, true, callback, context);
                RELEASE_HERE(node, threadsim_node_state);
            });
    } else if (service_data[0] == THREAD_SRP_SERVER_ANYCAST_OPTION) {
        if (node->anycast != NULL) {
            cti_service_release(node->anycast);
            node->anycast = NULL;
        }
        THREADSIM_AFTER_COMMON(1000, ^{
                threadsim_remove_service_from_leader(node, false, callback, context);
                RELEASE_HERE(node, threadsim_node_state);
            });
    } else {
        TEST_FAIL_STATUS(server->test_state, "remove of invalid service type %u", service_data[0]);
    }
    return kCTIStatus_NoError;
}

cti_status_t
cti_add_prefix_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
                struct in6_addr *prefix, int prefix_length, bool on_mesh, bool preferred, bool slaac,
                bool stable, int priority, const char *UNUSED file, int UNUSED line)
{
    (void)server;
    (void)context;
    (void)callback;
    (void)client_queue;
    (void)prefix;
    (void)prefix_length;
    (void)on_mesh;
    (void)preferred;
    (void)slaac;
    (void)stable;
    (void)priority;
    (void)file;
    (void)line;
    return kCTIStatus_Invalid;
}


cti_status_t
cti_remove_prefix_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
                   struct in6_addr *prefix, int prefix_length, const char *UNUSED file, int UNUSED line)
{
    (void)server;
    (void)context;
    (void)callback;
    (void)client_queue;
    (void)prefix;
    (void)prefix_length;
    return kCTIStatus_Invalid;
}

cti_status_t
cti_add_route_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
               struct in6_addr *prefix, int prefix_length, int priority, int domain_id, bool stable, bool nat64,
               const char *UNUSED file, int UNUSED line)
{
    (void)server;
    (void)context;
    (void)callback;
    (void)client_queue;
    (void)prefix;
    (void)prefix_length;
    (void)stable;
    (void)priority;
    (void)domain_id;
    (void)nat64;
    return kCTIStatus_Invalid;
}

cti_status_t
cti_remove_route_(srp_server_t *server, void *context, cti_reply_t callback, run_context_t UNUSED client_queue,
                  struct in6_addr *prefix, int prefix_length, int domain_id, const char *UNUSED file, int UNUSED line)
{
    (void)server;
    (void)context;
    (void)callback;
    (void)client_queue;
    (void)prefix;
    (void)prefix_length;
    (void)domain_id;
    return kCTIStatus_Invalid;
}


cti_status_t
cti_get_offmesh_route_list_(srp_server_t *server, cti_connection_t **ref, void *context,
                            cti_offmesh_route_reply_t callback, run_context_t UNUSED client_queue,
                            const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_offmesh_route_list_callback, offmesh_route_reply);
}


cti_status_t
cti_get_onmesh_prefix_list_(srp_server_t *server, cti_connection_t **ref, void *context,
                            cti_onmesh_prefix_reply_t callback, run_context_t UNUSED client_queue,
                            const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_onmesh_prefix_callback, onmesh_prefix_reply);
}


cti_status_t
cti_get_rloc16_(srp_server_t *server, cti_connection_t **ref, void *context, cti_rloc16_reply_t callback,
                run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_rloc16_callback, rloc16_reply);
}


cti_status_t
cti_track_active_data_set_(srp_server_t *server, cti_connection_t **ref, void *context, cti_reply_t callback,
                           run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_active_data_set_callback, reply);
}

cti_status_t
cti_track_wed_status_(srp_server_t *server, cti_connection_t **ref, void *context, cti_wed_reply_t callback,
                           run_context_t UNUSED client_queue, const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_wed_status_callback, wed_reply);
}


DNS_SERVICES_EXPORT cti_status_t
cti_track_neighbor_ml_eid_(srp_server_t *NULLABLE server, cti_connection_t *NULLABLE *NULLABLE ref,
                           void *NULLABLE context, cti_string_property_reply_t NONNULL callback,
                           run_context_t NULLABLE client_queue, const char *NONNULL file, int line);


cti_status_t
cti_track_neighbor_ml_eid_(srp_server_t *server, cti_connection_t **ref, void *context,
                           cti_string_property_reply_t callback, run_context_t UNUSED client_queue,
                           const char *UNUSED file, int UNUSED line)
{
    THREADSIM_AFTER_STATEFUL(1000, threadsim_neighbor_status_callback, string_property_reply);
}

cti_status_t
cti_add_ml_eid_mapping_(srp_server_t *UNUSED server, void *NULLABLE context,
                        cti_reply_t NONNULL callback, run_context_t UNUSED NULLABLE client_queue,
                        struct in6_addr *omr_addr, struct in6_addr *ml_eid, const char *hostname,
                        const char *file, int line)
{
    (void)omr_addr;
    (void)ml_eid;
    (void)hostname;
    (void)file;
    (void)line;
    (void)context;
    (void)callback;
    return kCTIStatus_Invalid;
}


// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
