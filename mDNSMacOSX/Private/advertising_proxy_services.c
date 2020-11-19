/* advertising_proxy_services.h
 *
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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
 * This file contains the implementation of the SRP Advertising Proxy management
 * API on MacOS, which is private API used to control and manage the advertising
 * proxy.
 */


#include <Block.h>
#include <os/log.h>
#include "xpc_clients.h"
#include "advertising_proxy_services.h"
#include "srp.h"

#if defined(TARGET_OS_TV)

//*************************************************************************************************************
// Globals

typedef struct _advertising_proxy_conn_ref_t
{
    int                        ref_count;     // This structure is refcounted
    xpc_connection_t           connection;    // xpc_connection between client and daemon
    advertising_proxy_reply    app_callback;  // Callback function ptr for Client
    dispatch_queue_t           client_queue;  // Queue specified by client for scheduling its Callback
    const char                *command_name;  // The advertising proxy command we've been given
} adv_conn_ref_t;

static void
advertising_proxy_ref_finalize(adv_conn_ref_t *conn_ref)
{
    free(conn_ref);
}

void advertising_proxy_ref_dealloc(adv_conn_ref_t *conn_ref)
{
    if (conn_ref == NULL)
    {
        os_log(OS_LOG_DEFAULT, "dns_services: advertising_proxy_ref_dealloc called with NULL advertising_proxy_conn_ref");
        return;
    }
    conn_ref->app_callback = NULL;
    if (conn_ref->connection != NULL) {
        xpc_connection_cancel(conn_ref->connection);
    }

    // This is releasing the caller's reference. We may still have an internal reference.
    RELEASE_HERE(conn_ref, advertising_proxy_ref_finalize);
    os_log(OS_LOG_DEFAULT, "dns_services: advertising_proxy_ref_dealloc successfully released conn_ref");
}

static void
adv_connection_finalize(void *v_conn_ref)
{
    adv_conn_ref_t *conn_ref = v_conn_ref;
    os_log(OS_LOG_DEFAULT, "adv_connection_finalize: releasing conn_ref at %d", conn_ref->ref_count);
    RELEASE_HERE(conn_ref, advertising_proxy_ref_finalize);
}

// Called for errors. The cancel argument is set to true if we need the callback to cancel the connection, as will be
// true for errors other than XPC_ERROR_CONNECTION_INVALID.  If the callback doesn't call advertising_proxy_ref_dealloc,
// which will cancel the connection, then adv_connection_call_callback cancels it.
static void
adv_connection_call_callback(adv_conn_ref_t *conn_ref, xpc_object_t *event, int status, bool cancel)
{
    int ref_count = conn_ref->ref_count;
    conn_ref->app_callback(conn_ref, event, status);
    if (conn_ref->ref_count > 1 && conn_ref->ref_count == ref_count) {
#ifndef __clang_analyzer__
        RELEASE_HERE(conn_ref, advertising_proxy_ref_finalize);
#endif
        if (cancel) {
            xpc_connection_cancel(conn_ref->connection);
        }
    }

    // We can never call the callback again after reporting an error.
    conn_ref->app_callback = NULL;
}

static void
adv_event_handler(xpc_object_t event, adv_conn_ref_t *conn_ref)
{
    if (event == XPC_ERROR_CONNECTION_INVALID) {
        os_log(OS_LOG_DEFAULT, "adv_event_handler (%s): cleanup %p %p", conn_ref->command_name, conn_ref, conn_ref->connection);
        if (conn_ref->app_callback != NULL) {
            adv_connection_call_callback(conn_ref, event, kDNSSDAdvertisingProxyStatus_Disconnected, false);
        } else {
            os_log(OS_LOG_DEFAULT, "No callback");
        }
        if (conn_ref->connection != NULL) {
            xpc_release(conn_ref->connection);
            conn_ref->connection = NULL;
        } else {
            ERROR("adv_event_handler(%s): cleanup: conn_ref->connection is NULL when it shouldn't be!",
                  conn_ref->command_name);
        }
    } else if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        if (conn_ref->app_callback != NULL) {
            conn_ref->app_callback(conn_ref, event, kDNSSDAdvertisingProxyStatus_NoError);
        } else {
            os_log(OS_LOG_DEFAULT, "adv_event_handler (%s): no callback", conn_ref->command_name);
        }
    } else {
        os_log(OS_LOG_DEFAULT, "adv_event_handler: Unexpected Connection Error [%s]",
               xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        if (conn_ref->app_callback) {
            adv_connection_call_callback(conn_ref, event, kDNSSDAdvertisingProxyStatus_DaemonNotRunning, true);
        } else {
            os_log(OS_LOG_DEFAULT, "adv_event_handler: no callback");
            xpc_connection_cancel(conn_ref->connection);
        }
    }
}

// Creates a new advertising_proxy_ Connection Reference(advertising_proxy_conn_ref)
static advertising_proxy_error_type
adv_init_connection(adv_conn_ref_t **ref, const char *servname, xpc_object_t dict,
                const char *command_name, advertising_proxy_reply app_callback, dispatch_queue_t client_queue,
                const char *file, int line)
{
    // Use an adv_conn_ref_t *on the stack to be captured in the blocks below, rather than
    // capturing the advertising_proxy_conn_ref* owned by the client
    adv_conn_ref_t *conn_ref = calloc(1, sizeof(adv_conn_ref_t));
    if (conn_ref == NULL) {
        os_log(OS_LOG_DEFAULT, "dns_services: init_connection() No memory to allocate!");
        return kDNSSDAdvertisingProxyStatus_NoMemory;
   }

    // Initialize the advertising_proxy_conn_ref
    dispatch_retain(client_queue);
    conn_ref->command_name = command_name;
    conn_ref->client_queue = client_queue;
    conn_ref->app_callback = app_callback;
    conn_ref->connection = xpc_connection_create_mach_service(servname, conn_ref->client_queue,
                                                              XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    if (conn_ref->connection == NULL)
    {
        os_log(OS_LOG_DEFAULT, "dns_services: init_connection() conn_ref/lib_q is NULL");
        if (conn_ref != NULL) {
            free(conn_ref);
        }
        return kDNSSDAdvertisingProxyStatus_NoMemory;
    }

    RETAIN_HERE(conn_ref); // For the event handler.
    xpc_connection_set_event_handler(conn_ref->connection, ^(xpc_object_t event) { adv_event_handler(event, conn_ref); });
    xpc_connection_set_finalizer_f(conn_ref->connection, adv_connection_finalize);
    xpc_connection_set_context(conn_ref->connection, conn_ref);
    xpc_connection_resume(conn_ref->connection);

    xpc_connection_send_message_with_reply(conn_ref->connection, dict, conn_ref->client_queue,
                                           ^(xpc_object_t event) { adv_event_handler(event, conn_ref); });

    if (ref) {
        *ref = conn_ref;
        // For the caller
        RETAIN(conn_ref);
    }
    return kDNSSDAdvertisingProxyStatus_NoError;
}

#define adv_send_command(ref, client_queue, command_name, dict, command, app_callback)  \
    adv_send_command_(ref, client_queue, command_name, dict, command, app_callback, __FILE__, __LINE__)
static advertising_proxy_error_type
adv_send_command_(adv_conn_ref_t **ref, dispatch_queue_t client_queue, const char *command_name,
                  xpc_object_t dict, const char *command, advertising_proxy_reply app_callback, const char *file, int line)
{
    advertising_proxy_error_type errx = kDNSSDAdvertisingProxyStatus_NoError;

    if (dict == NULL) {
        os_log(OS_LOG_DEFAULT, "adv_send_command(%s): no memory for command dictionary.", command_name);
        return kDNSSDAdvertisingProxyStatus_NoMemory;
    }

    // Sanity Checks
    if (app_callback == NULL || client_queue == NULL)
    {
        os_log(OS_LOG_DEFAULT, "%s: NULL cti_connection_t OR Callback OR Client_Queue parameter",
               command_name);
        return kDNSSDAdvertisingProxyStatus_BadParam;
    }

    xpc_dictionary_set_string(dict, kDNSAdvertisingProxyCommand, command);

    errx = adv_init_connection(ref, kDNSAdvertisingProxyService, dict, command_name, app_callback, client_queue, file, line);
    if (errx) // On error init_connection() leaves *conn_ref set to NULL
    {
        os_log(OS_LOG_DEFAULT,
               "%s: Since init_connection() returned %d error returning w/o sending msg",
               command_name, errx);
        return errx;
    }

    return errx;
}


advertising_proxy_error_type
advertising_proxy_enable(adv_conn_ref_t **conn_ref, dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_enable",
                            dict, kDNSAdvertisingProxyEnable, callback);
    xpc_release(dict);
    return errx;
}

advertising_proxy_error_type
advertising_proxy_flush_entries(adv_conn_ref_t **conn_ref,
                                dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_flush_entries",
                            dict, kDNSAdvertisingProxyFlushEntries, callback);
    xpc_release(dict);
    return errx;
}

advertising_proxy_error_type
advertising_proxy_get_service_list(adv_conn_ref_t **conn_ref,
                                   dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_get_service_list",
                            dict, kDNSAdvertisingProxyListServices, callback);
    xpc_release(dict);
    return errx;
}

advertising_proxy_error_type
advertising_proxy_block_service(adv_conn_ref_t **conn_ref,
                                dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_block_service",
                            dict, kDNSAdvertisingProxyBlockService, callback);
    xpc_release(dict);
    return errx;
}

advertising_proxy_error_type
advertising_proxy_unblock_service(adv_conn_ref_t **conn_ref,
                                  dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_unblock_service",
                            dict, kDNSAdvertisingProxyUnblockService, callback);
    xpc_release(dict);
    return errx;
}

advertising_proxy_error_type
advertising_proxy_regenerate_ula(adv_conn_ref_t **conn_ref,
                                 dispatch_queue_t client_queue, advertising_proxy_reply callback)
{
    advertising_proxy_error_type errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    errx = adv_send_command(conn_ref, client_queue, "advertising_proxy_regenerate_ula",
                            dict, kDNSAdvertisingProxyRegenerateULA, callback);
    xpc_release(dict);
    return errx;
}
#endif // defined(TARGET_OS_TV)

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
