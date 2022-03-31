/* cti-services.c
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
 * This code adds border router support to 3rd party HomeKit Routers as part of Apple’s commitment to the CHIP project.
 *
 * Concise Thread Interface for Thread Border router control.
 */


#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>


#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "cti-services.h"

static void cti_message_parse(cti_connection_t connection);


//*************************************************************************************************************
// Globals

#include "cti-common.h"

#include "cti-proto.h"


// For configuration comments, we return success/failure.
static void
cti_internal_reply_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_reply_t callback;
    INFO("cti_internal_reply_callback: conn_ref = %p", conn_ref);
    callback = conn_ref->callback.reply;
    if (callback != NULL) {
        callback(conn_ref->context, status);
        // We only ever call this callback once.
        conn_ref->callback.reply = NULL;
    }
    cti_connection_close(conn_ref);
}

static void
cti_fd_finalize(void *context)
{
    cti_connection_t connection = context;
    connection->io_context = NULL;
    if (connection->callback.reply != NULL && connection->internal_callback != NULL) {
        connection->internal_callback(connection, NULL, kCTIStatus_Disconnected);
    }
    RELEASE_HERE(connection, cti_connection_finalize);
}

void
cti_connection_close(cti_connection_t connection)
{
    // The reason we test for NULL here is to save some typing: when a connection is closed remotely, we have call the
    // internal event handler for the event; this event handler closes the connection when we've just received a
    // successful reply. However, when the remote end closes the connection without that reply having been processed, we
    // get to the internal callback with connection->io_context set to NULL. Rather than checking in every event handler,
    // it's easier to check here.
    if (connection->io_context != NULL) {
        ioloop_close(connection->io_context);
        ioloop_file_descriptor_release(connection->io_context);
        connection->io_context = NULL;
    }
}

static void
cti_response_parse(cti_connection_t connection)
{
    uint16_t responding_to;
    int32_t status;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u16_parse(connection, &responding_to) &&
        cti_connection_i32_parse(connection, &status) &&
        cti_connection_parse_done(connection))
    {
        INFO("cti_response_parse: %d %d", responding_to, status);
        connection->internal_callback(connection, NULL, status);
    }
}

static void
cti_tunnel_response_parse(cti_connection_t connection)
{
    char *tunnel_name = NULL;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_string_parse(connection, &tunnel_name) &&
        cti_connection_parse_done(connection))
    {
        INFO("cti_tunnel_response_parse: %s", tunnel_name);
        connection->internal_callback(connection, tunnel_name, kCTIStatus_NoError);
    }
    if (tunnel_name != NULL) {
        free(tunnel_name);
    }
}

static void
cti_connection_read_callback(io_t *UNUSED io, void *context)
{
    cti_connection_t connection = context;

    cti_read(connection, cti_message_parse);
}

void
cti_connection_release_(cti_connection_t connection, const char *file, int line)
{
    RELEASE(connection, cti_connection_finalize);
}

static int
cti_connection_create(void *context, cti_callback_t callback,
                      cti_internal_callback_t internal_callback, cti_connection_t *retcon)
{
    cti_connection_t connection = cti_connection_allocate(500);
    if (connection == NULL) {
        ERROR("cti_connection_create: no memory for connection.");
        return kCTIStatus_NoMemory;
    }
    RETAIN_HERE(connection);

    connection->fd = cti_make_unix_socket(CTI_SERVER_SOCKET_NAME, sizeof(CTI_SERVER_SOCKET_NAME), false);
    if (connection->fd < 0) {
        int ret = errno == ECONNREFUSED ? kCTIStatus_DaemonNotRunning : EPERM ? kCTIStatus_NotPermitted : kCTIStatus_UnknownError;
        ERROR("cti_connection_create: socket: %s", strerror(errno));
        cti_connection_release(connection);
        return ret;
    }

    connection->io_context = ioloop_file_descriptor_create(connection->fd, connection, cti_fd_finalize);
    if (connection->io_context == NULL) {
        ERROR("cti_connection_create: can't create file descriptor object.");
        close(connection->fd);
        cti_connection_release(connection);
        return kCTIStatus_NoMemory;
    }
    ioloop_add_reader(connection->io_context, cti_connection_read_callback);
    connection->context = context;
    connection->callback = callback;
    connection->internal_callback = internal_callback;
    *retcon = connection;
    return kCTIStatus_NoError;
}

cti_status_t
cti_add_service_(void *context, cti_reply_t callback, run_context_t client_queue,
                 uint32_t enterprise_number, const uint8_t *NONNULL service_data, size_t service_data_length,
                 const uint8_t *NONNULL server_data, size_t server_data_length, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_reply_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        conn_ref->callback.reply = callback;
        if (cti_connection_message_create(conn_ref, kCTIMessageType_AddService,
                                          // sizeof(u32) + sizeof(length) + sizeof(length) = 8
                                          8 + service_data_length + server_data_length) &&
            cti_connection_u32_put(conn_ref, enterprise_number) &&
            cti_connection_data_put(conn_ref, service_data, service_data_length) &&
            cti_connection_data_put(conn_ref, server_data, server_data_length))
        {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

cti_status_t
cti_remove_service_(void *context, cti_reply_t callback, run_context_t client_queue,
                    uint32_t enterprise_number, const uint8_t *NONNULL service_data, size_t service_data_length,
                    const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_reply_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RemoveService,
                                          // sizeof(u32) + sizeof(length) = 6
                                          6 + service_data_length) &&
            cti_connection_u32_put(conn_ref, enterprise_number) &&
            cti_connection_data_put(conn_ref, service_data, service_data_length))
        {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}


cti_status_t
cti_add_prefix_(void *context, cti_reply_t callback, run_context_t client_queue,
                struct in6_addr *prefix, int prefix_length, bool on_mesh, bool preferred, bool slaac, bool stable,
                const char *file, int line)
{
    cti_callback_t app_callback;
    int ret;
    cti_connection_t conn_ref;
    app_callback.reply = callback;
    ret = cti_connection_create(context, app_callback, cti_internal_reply_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_AddPrefix,
                                          // sizeof(u32) * 2 + sizeof(prefix) (8) + sizeof(u8) + 3 * sizeof(bool) = 20
                                          20) &&
            cti_connection_u32_put(conn_ref, ND6_INFINITE_LIFETIME) &&
            cti_connection_u32_put(conn_ref, ND6_INFINITE_LIFETIME) &&
            cti_connection_data_put(conn_ref, prefix, 8) &&
            cti_connection_u8_put(conn_ref, prefix_length) &&
            cti_connection_bool_put(conn_ref, slaac) &&
            cti_connection_bool_put(conn_ref, on_mesh) &&
            cti_connection_bool_put(conn_ref, stable))
        {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

cti_status_t
cti_remove_prefix_(void *NULLABLE context, cti_reply_t NONNULL callback, run_context_t NULLABLE client_queue,
                   struct in6_addr *NONNULL prefix, int prefix_length, const char *file, int line)
{
    cti_callback_t app_callback;
    int ret;
    cti_connection_t conn_ref;
    app_callback.reply = callback;
    ret = cti_connection_create(context, app_callback, cti_internal_reply_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RemovePrefix,
                                          // sizeof(prefix) (8) + sizeof(u8) = 9
                                          9) &&
            cti_connection_data_put(conn_ref, prefix, 8) &&
            cti_connection_u8_put(conn_ref, prefix_length))
        {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

// For configuration comments, we return success/failure.
static void
cti_internal_tunnel_reply_callback(cti_connection_t conn_ref, void *tunnel_name, cti_status_t status)
{
    cti_tunnel_reply_t callback;
    INFO("cti_tunnel_internal_reply_callback: conn_ref = %p name = %s", conn_ref,
         tunnel_name == NULL ? "<NULL>" : (char *)tunnel_name);
    callback = conn_ref->callback.tunnel_reply;
    if (callback != NULL) {
        callback(conn_ref->context, tunnel_name, status);
        conn_ref->callback.reply = NULL;
    }
    cti_connection_close(conn_ref);
}

cti_status_t
cti_get_tunnel_name_(void *NULLABLE context, cti_tunnel_reply_t NONNULL callback, run_context_t NULLABLE client_queue,
                     const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.tunnel_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_tunnel_reply_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_GetTunnelName, 0))
        {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

// For event comamnds, we return failure and close; on success, we just wait for events to flow and return those.
static void
cti_internal_state_event_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_state_reply_t callback;
    INFO("cti_internal_state_event_callback: conn_ref = %p", conn_ref);
    if (status != kCTIStatus_NoError) {
        callback = conn_ref->callback.state_reply;
        if (callback != NULL) {
            callback(conn_ref->context, 0, status);
            // Only one error callback ever.
            conn_ref->callback.reply = NULL;
        }
        cti_connection_close(conn_ref);
    }
}

cti_status_t
cti_get_state_(cti_connection_t *ref, void *NULLABLE context, cti_state_reply_t NONNULL callback,
               run_context_t NULLABLE client_queue, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.state_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_state_event_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RequestStateEvents, 4)) {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

typedef uint32_t cti_property_name_t;

// For event commands, we return failure and close; on success, we just wait for events to flow and return those.
static void
cti_internal_uint64_property_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_uint64_property_reply_t callback = conn_ref->callback.uint64_property_reply;
    INFO("conn_ref = %p", conn_ref);
    if (status != kCTIStatus_NoError) {
        if (callback != NULL) {
            callback(conn_ref->context, 0, status);
            // Only one error callback ever.
            conn_ref->callback.reply = NULL;
        }
        cti_connection_close(conn_ref);
    }
}

static cti_status_t
cti_get_uint64_property(cti_connection_t *ref, void *NULLABLE context, cti_uint64_property_reply_t NONNULL callback,
                        run_context_t NULLABLE client_queue, cti_property_name_t property_name, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.uint64_property_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_uint64_property_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RequestUInt64PropEvents, 4)) {
            if (!cti_connection_u32_put(conn_ref, property_name) || !cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

cti_status_t
cti_get_partition_id_(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context,
                      cti_uint64_property_reply_t NONNULL callback, run_context_t NULLABLE client_queue,
                      const char *NONNULL file, int line)
{
    return cti_get_uint64_property(ref, context, callback, client_queue, kCTIPropertyPartitionID, file, line);
}

cti_status_t
cti_get_extended_pan_id_(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context,
                         cti_uint64_property_reply_t NONNULL callback, run_context_t NULLABLE client_queue,
                         const char *NONNULL file, int line)
{
    return cti_get_uint64_property(ref, context, callback, client_queue, kCTIPropertyExtendedPANID, file, line);
}

// For event commands, we return failure and close; on success, we just wait for events to flow and return those.
static void
cti_internal_node_type_event_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_network_node_type_reply_t callback;
    INFO("cti_internal_node_type_event_callback: conn_ref = %p", conn_ref);
    if (status != kCTIStatus_NoError) {
        callback = conn_ref->callback.network_node_type_reply;
        if (callback != NULL) {
            callback(conn_ref->context, 0, status);
            // Only one error callback ever.
            conn_ref->callback.reply = NULL;
        }
        cti_connection_close(conn_ref);
    }
}

cti_status_t
cti_get_network_node_type_(cti_connection_t *ref, void *NULLABLE context, cti_network_node_type_reply_t NONNULL callback,
                           run_context_t NULLABLE client_queue, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.network_node_type_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_node_type_event_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RequestRoleEvents, 4)) {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

static void
cti_service_finalize(cti_service_t *service)
{
    if (service->server != NULL) {
        free(service->server);
    }
    free(service);
}

static void
cti_service_vec_finalize(cti_service_vec_t *services)
{
    size_t i;

    if (services->services != NULL) {
        for (i = 0; i < services->num; i++) {
            if (services->services[i] != NULL) {
                RELEASE_HERE(services->services[i], cti_service_finalize);
            }
        }
        free(services->services);
    }
    free(services);
}

cti_service_vec_t *
cti_service_vec_create_(size_t num_services, const char *file, int line)
{
    cti_service_vec_t *services = calloc(1, sizeof(*services));
    if (services != NULL) {
        if (num_services != 0) {
            services->services = calloc(num_services, sizeof(cti_service_t *));
            if (services->services == NULL) {
                free(services);
                return NULL;
            }
        }
        services->num = num_services;
        RETAIN(services);
    }
    return services;
}

void
cti_service_vec_release_(cti_service_vec_t *services, const char *file, int line)
{
    RELEASE(services, cti_service_vec_finalize);
}

cti_service_t *
cti_service_create_(uint64_t enterprise_number, uint16_t service_type, uint16_t service_version,
                    uint8_t *server, size_t server_length, int flags, const char *file, int line)
{
    cti_service_t *service = calloc(1, sizeof(*service));
    if (service != NULL) {
        service->enterprise_number = enterprise_number;
        service->service_type = service_type;
        service->service_version = service_version;
        service->server = server;
        service->server_length = server_length;
        service->flags = flags;
        RETAIN(service);
    }
    return service;
}

void
cti_service_release_(cti_service_t *service, const char *file, int line)
{
    RELEASE(service, cti_service_finalize);
}

// For event comamnds, we return failure and close; on success, we just wait for events to flow and return those.
static void
cti_internal_service_event_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_service_reply_t callback;
    INFO("cti_internal_service_event_callback: conn_ref = %p", conn_ref);
    if (status != kCTIStatus_NoError) {
        callback = conn_ref->callback.service_reply;
        if (callback != NULL) {
            callback(conn_ref->context, 0, status);
            // Only one error callback ever.
            conn_ref->callback.reply = NULL;
        }
        cti_connection_close(conn_ref);
    }
}

cti_status_t
cti_get_service_list_(cti_connection_t *ref, void *NULLABLE context, cti_service_reply_t NONNULL callback,
                      run_context_t NULLABLE client_queue, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.service_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_service_event_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RequestServiceEvents, 4)) {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

static void
cti_prefix_finalize(cti_prefix_t *prefix)
{
    free(prefix);
}

static void
cti_prefix_vec_finalize(cti_prefix_vec_t *prefixes)
{
    size_t i;

    if (prefixes->prefixes != NULL) {
        for (i = 0; i < prefixes->num; i++) {
            if (prefixes->prefixes[i] != NULL) {
                RELEASE_HERE(prefixes->prefixes[i], cti_prefix_finalize);
            }
        }
        free(prefixes->prefixes);
    }
    free(prefixes);
}

cti_prefix_vec_t *
cti_prefix_vec_create_(size_t num_prefixes, const char *file, int line)
{
    cti_prefix_vec_t *prefixes = calloc(1, sizeof(*prefixes));
    if (prefixes != NULL) {
        if (num_prefixes != 0) {
            prefixes->prefixes = calloc(num_prefixes, sizeof(cti_prefix_t *));
            if (prefixes->prefixes == NULL) {
                free(prefixes);
                return NULL;
            }
        }
        prefixes->num = num_prefixes;
        RETAIN(prefixes);
    }
    return prefixes;
}

void
cti_prefix_vec_release_(cti_prefix_vec_t *prefixes, const char *file, int line)
{
    RELEASE(prefixes, cti_prefix_vec_finalize);
}

cti_prefix_t *
cti_prefix_create_(struct in6_addr *prefix, int prefix_length, int metric, int flags, const char *file, int line)
{
    cti_prefix_t *prefix_ret = calloc(1, sizeof(*prefix_ret));
    if (prefix != NULL) {
        prefix_ret->prefix = *prefix;
        prefix_ret->prefix_length = prefix_length;
        prefix_ret->metric = metric;
        prefix_ret->flags = flags;
        RETAIN(prefix_ret);
    }
    return prefix_ret;
}

void
cti_prefix_release_(cti_prefix_t *prefix, const char *file, int line)
{
    RELEASE(prefix, cti_prefix_finalize);
}

// For event comamnds, we return failure and close; on success, we just wait for events to flow and return those.
static void
cti_internal_prefix_event_callback(cti_connection_t conn_ref, void *UNUSED object, cti_status_t status)
{
    cti_prefix_reply_t callback;
    INFO("cti_internal_prefix_event_callback: conn_ref = %p", conn_ref);
    if (status != kCTIStatus_NoError) {
        callback = conn_ref->callback.prefix_reply;
        if (callback != NULL && conn_ref->context != NULL) {
            callback(conn_ref->context, 0, status);
            // Only one error callback ever.
            conn_ref->callback.reply = NULL;
        }
        cti_connection_close(conn_ref);
    }
}

cti_status_t
cti_get_prefix_list_(cti_connection_t *ref, void *NULLABLE context, cti_prefix_reply_t NONNULL callback,
                     run_context_t NULLABLE client_queue, const char *file, int line)
{
    cti_callback_t app_callback;
    app_callback.prefix_reply = callback;
    int ret;
    cti_connection_t conn_ref;
    ret = cti_connection_create(context, app_callback, cti_internal_prefix_event_callback, &conn_ref);
    if (ret == kCTIStatus_NoError) {
        if (cti_connection_message_create(conn_ref, kCTIMessageType_RequestPrefixEvents, 4)) {
            if (!cti_connection_message_send(conn_ref)) {
                ret = kCTIStatus_Disconnected;
            }
        } else {
            ret = kCTIStatus_NoMemory;
        }
        if (ret != kCTIStatus_NoError) {
            cti_connection_close(conn_ref);
        }
    }
    return ret;
}

cti_status_t
cti_events_discontinue(cti_connection_t connection)
{
    if (connection->io_context != NULL) {
        cti_connection_close(connection);
    }
    cti_connection_release(connection);
    return kCTIStatus_NoError;
}
static void
cti_role_event_parse(cti_connection_t connection)
{
    uint8_t role;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u8_parse(connection, &role) &&
        cti_connection_parse_done(connection))
    {
        INFO("cti_role_event_parse: %d", role);
        connection->callback.network_node_type_reply(connection, role, kCTIStatus_NoError);
    }
}

static void
cti_state_event_parse(cti_connection_t connection)
{
    uint8_t state;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u8_parse(connection, &state) &&
        cti_connection_parse_done(connection))
    {
        INFO("cti_state_event_parse: %d", state);
        connection->callback.state_reply(connection, state, kCTIStatus_NoError);
    }
}

static void
cti_uint64_property_event_parse(cti_connection_t connection)
{
    uint64_t property_value;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u64_parse(connection, &property_value) &&
        cti_connection_parse_done(connection))
    {
        INFO("%" PRIx64, property_value);
        connection->callback.uint64_property_reply(connection, property_value, kCTIStatus_NoError);
    }
}

static void
cti_service_event_parse(cti_connection_t connection)
{
    uint8_t service_count, i;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u8_parse(connection, &service_count)) {
        cti_service_vec_t *vec = cti_service_vec_create(service_count);
        if (vec == NULL) {
            ERROR("cti_service_event_parse: no memory for service vector.");
            return;
        }
        vec->num = 0;
        for (i = 0; i < service_count; i++) {
            uint32_t enterprise_number;
            void *service_data = NULL;
            uint16_t service_data_length;
            void *server_data = NULL;
            uint16_t server_data_length;
            if (!cti_connection_u32_parse(connection, &enterprise_number) ||
                !cti_connection_data_parse(connection, &service_data, &service_data_length) ||
                !cti_connection_data_parse(connection, &server_data, &server_data_length))
            {
                if (service_data != NULL) {
                    free(service_data);
                }
                cti_service_vec_release(vec);
                return;
            }
            char service_data_buf[13], server_data_buf[55];
            cti_service_t *service = NULL;
            dump_to_hex(service_data, service_data_length, service_data_buf, sizeof(service_data_buf));
            dump_to_hex(server_data, server_data_length, server_data_buf, sizeof(server_data_buf));
            INFO("cti_service_event_parse: %" PRIu32 " %" PRIu16 "[ %s ] %" PRIu16 "[ %s ]",
                 enterprise_number, service_data_length, service_data_buf, server_data_length, server_data_buf);
            if (enterprise_number == THREAD_ENTERPRISE_NUMBER) {
                if (service_data_length == 1) {
                    service = cti_service_create(enterprise_number,
                                                 ((uint8_t *)service_data)[0], 1, server_data, server_data_length, 0);
                }
            }
            if (service == NULL) {
                free(service_data);
                free(server_data);
            } else {
                vec->services[vec->num++] = service;
            }
        }

        if (!cti_connection_parse_done(connection)) {
            cti_service_vec_release(vec);
            return;
        }

        INFO("cti_service_event_parse: %zd", vec->num);
        connection->callback.service_reply(connection, vec, kCTIStatus_NoError);
    }
}

static void
cti_prefix_event_parse(cti_connection_t connection)
{
    uint16_t prefix_count, i;

    // And statement will fail as soon as anything fails to parse.
    if (cti_connection_u16_parse(connection, &prefix_count)) {
        if (prefix_count > 200) {
            ERROR("cti_prefix_event_parse: bogus number of prefixes returned: %d", prefix_count);
            cti_connection_close(connection);
            return;
        }
        cti_prefix_vec_t *vec = cti_prefix_vec_create(prefix_count);
        if (vec == NULL) {
            ERROR("cti_prefix_event_parse: no memory for prefix vector.");
            return;
        }
        vec->num = 0;
        for (i = 0; i < prefix_count; i++) {
            uint16_t flags;
            uint8_t prefix_length;
            void *prefix_data = NULL;
            uint16_t prefix_data_length;
            struct in6_addr *prefix_addr;
            if (!cti_connection_u16_parse(connection, &flags) ||
                !cti_connection_u8_parse(connection, &prefix_length) ||
                !cti_connection_data_parse(connection, &prefix_data, &prefix_data_length))
            {
                cti_prefix_vec_release(vec);
                return;
            }
            if (prefix_data_length != 8) {
                ERROR("cti_prefix_event_parse: wrong prefix length: %d", prefix_data_length);
                cti_prefix_vec_release(vec);
                return;
            }
            prefix_addr = calloc(1, sizeof(*prefix_addr));
            if (prefix_addr == NULL) {
                ERROR("cti_prefix_event_parse: no memory for prefix data.");
                cti_prefix_vec_release(vec);
                return;
            }
            memcpy(prefix_addr, prefix_data, prefix_data_length);
            free(prefix_data);
            cti_prefix_t *prefix = cti_prefix_create(prefix_addr, prefix_length, 0, flags);
            if (prefix == NULL) {
                ERROR("cti_prefix_event_parse: no memory for prefix object.");
                cti_prefix_vec_release(vec);
                return;
            }
            vec->prefixes[vec->num++] = prefix;
        }

        if (!cti_connection_parse_done(connection)) {
            cti_prefix_vec_release(vec);
            return;
        }

        INFO("cti_prefix_event_parse: %zd", vec->num);
        connection->callback.prefix_reply(connection, vec, kCTIStatus_NoError);
    }
}

static void
cti_message_parse(cti_connection_t connection)
{
    cti_connection_parse_start(connection);
    if (!cti_connection_u16_parse(connection, &connection->message_type)) {
        return;
    }
    switch(connection->message_type) {
    case kCTIMessageType_Response:
        cti_response_parse(connection);
        break;
    case kCTIMessageType_TunnelNameResponse:
        cti_tunnel_response_parse(connection);
        break;
    case kCTIMessageType_StateEvent:
        cti_state_event_parse(connection);
        break;
    case kCTIMessageType_UInt64PropEvent:
        cti_uint64_property_event_parse(connection);
        break;
    case kCTIMessageType_RoleEvent:
        cti_role_event_parse(connection);
        break;
    case kCTIMessageType_ServiceEvent:
        cti_service_event_parse(connection);
        break;
    case kCTIMessageType_PrefixEvent:
        cti_prefix_event_parse(connection);
        break;
    }
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
