/* cti_services.c
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
#include <netinet/in.h>
#include <net/if.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include "xpc_clients.h"

#define THREAD_SERVICE_SEND_BOTH 1

#include "cti-services.h"

//*************************************************************************************************************
// Globals

static int client_serial_number;

typedef union {
    cti_reply_t reply;
    cti_tunnel_reply_t tunnel_reply;
    cti_service_reply_t service_reply;
    cti_prefix_reply_t prefix_reply;
    cti_state_reply_t state_reply;
    cti_partition_id_reply_t partition_id_reply;
    cti_network_node_type_reply_t network_node_type_reply;
} cti_callback_t;

typedef void
(*cti_internal_callback_t)(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status);

struct _cti_connection_t
{
    int ref_count;

    // xpc_connection between client and daemon
    xpc_connection_t NULLABLE connection;

    // Callback function ptr for Client
    cti_callback_t callback;

    // Before we can send commands, we have to check in, so when starting up, we stash the initial command
    // here until we get an acknowledgment for the checkin.
    xpc_object_t *first_command;

    // For commands that fetch properties and also track properties, this will contain the name of the property
    // for which events are requested.
    const char *property_name;

    cti_internal_callback_t NONNULL internal_callback;

    // Queue specified by client for scheduling its Callback
    dispatch_queue_t NONNULL client_queue;

    // Client context
    void *NULLABLE context;

    // Printed when debugging the event handler
    const char *NONNULL command_name;

    // True if we've gotten a response to the check-in message.
    bool checked_in;
};

//*************************************************************************************************************
// Utility Functions

static void
cti_connection_finalize(cti_connection_t ref)
{
    free(ref);
}

#define cti_connection_release(ref) cti_connection_release_(ref, __FILE__, __LINE__)
static void
cti_connection_release_(cti_connection_t ref, const char *file, int line)
{
    ref->callback.reply = NULL;
    if (ref->connection != NULL) {
        xpc_connection_cancel(ref->connection);
    }
    RELEASE(ref, cti_connection_finalize);
}

static void
cti_xpc_connection_finalize(void *context)
{
    cti_connection_release(context);
}

static char *
cti_xpc_copy_description(xpc_object_t object)
{
    xpc_type_t type = xpc_get_type(object);
    if (type == XPC_TYPE_UINT64) {
        uint64_t num = xpc_uint64_get_value(object);
        char buf[23];
        snprintf(buf, sizeof buf, "%llu", num);
        return strdup(buf);
    } else if (type == XPC_TYPE_INT64) {
        int64_t num = xpc_int64_get_value(object);
        char buf[23];
        snprintf(buf, sizeof buf, "%lld", num);
        return strdup(buf);
    } else if (type == XPC_TYPE_STRING) {
        const char *str = xpc_string_get_string_ptr(object);
        size_t len = xpc_string_get_length(object);
        char *ret = malloc(len + 3);
        if (ret != NULL) {
            *ret = '"';
            strlcpy(ret + 1, str, len + 1);
            ret[len + 1] = '"';
            ret[len + 2] = 0;
            return ret;
        }
    } else if (type == XPC_TYPE_DATA) {
        const uint8_t *data = xpc_data_get_bytes_ptr(object);
        size_t i, len = xpc_data_get_length(object);
        char *ret = malloc(len * 2 + 3);
        if (ret != NULL) {
            ret[0] = '0';
            ret[1] = 'x';
            for (i = 0; i < len; i++) {
                snprintf(ret + i * 2, 3, "%02x", data[i]);
            }
            return ret;
        }
    } else if (type == XPC_TYPE_BOOL) {
        bool flag = xpc_bool_get_value(object);
        if (flag) {
            return strdup("true");
        } else {
            return strdup("false");
        }
    } else if (type == XPC_TYPE_ARRAY) {
        size_t avail, vlen, len = 0, i, count = xpc_array_get_count(object);
        char **values = malloc(count * sizeof(*values));
        char *ret, *p_ret;
        if (values == NULL) {
            return NULL;
        }
        xpc_array_apply(object, ^bool (size_t index, xpc_object_t value) {
                values[index] = cti_xpc_copy_description(value);
                return true;
            });
        for (i = 0; i < count; i++) {
            if (values[i] == NULL) {
                len += 6;
            } else {
                len += strlen(values[i]) + 2;
            }
        }
        ret = malloc(len + 3);
        p_ret = ret;
        avail = len + 1;
        *p_ret++ = '[';
        --avail;
        for (i = 0; i < count; i++) {
            if (p_ret != NULL) {
                snprintf(p_ret, avail, "%s%s%s", i == 0 ? "" : " ", values[i] != NULL ? values[i] : "NULL", (i + 1 == count) ? "" : ",");
                vlen = strlen(p_ret);
                p_ret += vlen;
                avail -= vlen;
            }
            if (values[i] != NULL) {
                free(values[i]);
            }
        }
        *p_ret++ = ']';
        *p_ret++ = 0;
        free(values);
        return ret;
    }
    return xpc_copy_description(object);
}

static void
cti_log_object(const char *context, const char *command, const char *preamble, const char *divide, xpc_object_t *object, char *indent)
{
    xpc_type_t type = xpc_get_type(object);
    static char no_indent[] = "";
    if (indent == NULL) {
        indent = no_indent;
    }
    char *new_indent;
    size_t depth;
    char *desc;
    char *compound_begin = "";
    char *compound_end = "";

    if (type == XPC_TYPE_DICTIONARY || type == XPC_TYPE_ARRAY) {
        bool compact = true;
        bool *p_compact = &compact;
        if (type == XPC_TYPE_DICTIONARY) {
            compound_begin = "{";
            compound_end = "}";
            xpc_dictionary_apply(object, ^bool (const char *__unused key, xpc_object_t value) {
                    xpc_type_t sub_type = xpc_get_type(value);
                    if (sub_type == XPC_TYPE_DICTIONARY) {
                        *p_compact = false;
                    } else if (sub_type == XPC_TYPE_ARRAY) {
                        xpc_array_apply(value, ^bool (size_t __unused index, xpc_object_t sub_value) {
                                xpc_type_t sub_sub_type = xpc_get_type(sub_value);
                                if (sub_sub_type == XPC_TYPE_DICTIONARY || sub_sub_type == XPC_TYPE_ARRAY) {
                                    *p_compact = false;
                                }
                                return true;
                            });
                    }
                    return true;
                });
        } else {
            compound_begin = "[";
            compound_end = "]";
            xpc_array_apply(object, ^bool (size_t __unused index, xpc_object_t value) {
                    xpc_type_t sub_type = xpc_get_type(value);
                    if (sub_type == XPC_TYPE_DICTIONARY || sub_type == XPC_TYPE_ARRAY) {
                        *p_compact = false;
                    }
                    return true;
                });
        }
        if (compact) {
            size_t i, count;
            const char **keys = NULL;
            char **values;
            char linebuf[160], *p_space;
            size_t space_avail = sizeof(linebuf);
            bool first = true;

            if (type == XPC_TYPE_DICTIONARY) {
                count = xpc_dictionary_get_count(object);
            } else {
                count = xpc_array_get_count(object);
            }

            values = malloc(count * sizeof(*values));
            if (values == NULL) {
                INFO("cti_log_object: no memory");
                return;
            }
            if (type == XPC_TYPE_DICTIONARY) {
                int index = 0, *p_index = &index;
                keys = malloc(count * sizeof(*keys));
                if (keys == NULL) {
                    free(values);
                    INFO("cti_log_object: no memory");
                }
                xpc_dictionary_apply(object, ^bool (const char *key, xpc_object_t value) {
                        values[*p_index] = cti_xpc_copy_description(value);
                        keys[*p_index] = key;
                        (*p_index)++;
                        return true;
                    });
            } else {
                xpc_array_apply(object, ^bool (size_t index, xpc_object_t value) {
                        values[index] = cti_xpc_copy_description(value);
                        return true;
                    });
            }
            p_space = linebuf;
            for (i = 0; i < count; i++) {
                char *str = values[i];
                size_t len;
                char *eol = "";
                bool emitted = false;
                if (str == NULL) {
                    str = "NULL";
                    len = 6;
                } else {
                    len = strlen(str) + 2;
                }
                if (type == XPC_TYPE_DICTIONARY) {
#ifdef __clang_analyzer__
                    len = 2;
#else
                    len += strlen(keys[i]) + 2; // "key: "
#endif
                }
                if (len + 1 > space_avail) {
                    if (i + 1 == count) {
                        eol = compound_end;
                    }
                    if (space_avail != sizeof(linebuf)) {
                        if (first) {
                            INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " " PUB_S_SRP PUB_S_SRP PUB_S_SRP,
                                 context, command, indent, preamble, divide, compound_begin, linebuf, eol);
                            first = false;
                        } else {
                            INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " +" PUB_S_SRP PUB_S_SRP,
                                 context, command, indent, preamble, divide, linebuf, eol);
                        }
                        space_avail = sizeof linebuf;
                        p_space = linebuf;
                    }
                    if (len + 1 > space_avail) {
                        if (type == XPC_TYPE_DICTIONARY) {
#ifndef __clang_analyzer__
                            if (first) {
                                INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " " PUB_S_SRP PUB_S_SRP ": " PUB_S_SRP PUB_S_SRP,
                                     context, command, indent, preamble, divide, compound_begin, keys[i], str, eol);
                                first = false;
                            } else {
                                INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " +" PUB_S_SRP ": " PUB_S_SRP PUB_S_SRP,
                                     context, command, indent, preamble, divide, keys[i], str, eol);
                            }
#endif
                        } else {
                            if (first) {
                                INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " " PUB_S_SRP PUB_S_SRP PUB_S_SRP,
                                     context, command, indent, preamble, divide, compound_begin, str, eol);
                                first = false;
                            } else {
                                INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " +" PUB_S_SRP PUB_S_SRP,
                                     context, command, indent, preamble, divide, str, eol);
                            }
                        }
                        emitted = true;
                    }
                }
                if (!emitted) {
                    if (type == XPC_TYPE_DICTIONARY) {
#ifndef __clang_analyzer__
                        snprintf(p_space, space_avail, "%s%s: %s%s", i == 0 ? "" : " ", keys[i], str, i + 1 == count ? "" : ",");
#endif
                    } else {
                        snprintf(p_space, space_avail, "%s%s%s", i == 0 ? "" : " ", str, i + 1 == count ? "" : ",");
                    }
                    len = strlen(p_space);
                    p_space += len;
                    space_avail -= len;
                }
                if (values[i] != NULL) {
                    free(values[i]);
                    values[i] = NULL;
                }
            }
            if (linebuf != p_space) {
                if (first) {
                    INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " " PUB_S_SRP PUB_S_SRP PUB_S_SRP,
                         context, command, indent, preamble, divide, compound_begin, linebuf, compound_end);
                } else {
                    INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " + " PUB_S_SRP PUB_S_SRP,
                         context, command, indent, preamble, divide, linebuf, compound_end);
                }
            }
            free(values);
            if (keys != NULL) {
                free(keys);
            }
        } else {
            depth = strlen(indent);
            new_indent = malloc(depth + 3);
            if (new_indent == NULL) {
                new_indent = indent;
            } else {
                memset(new_indent, ' ', depth + 2);
                new_indent[depth + 2] = 0;
            }
            if (type == XPC_TYPE_DICTIONARY) {
                xpc_dictionary_apply(object, ^bool (const char *key, xpc_object_t value) {
                    cti_log_object(context, command, key, ": ", value, new_indent);
                    return true;
                });
            } else {
                xpc_array_apply(object, ^bool (size_t index, xpc_object_t value) {
                    char numbuf[23];
                    snprintf(numbuf, sizeof(numbuf), "%zd", index);
                    cti_log_object(context, command, numbuf, ": ", value, new_indent);
                    return true;
                });
            }
            if (new_indent != indent) {
                free(new_indent);
            }
        }
    } else {
        desc = cti_xpc_copy_description(object);
        INFO(PUB_S_SRP "(" PUB_S_SRP "): " PUB_S_SRP PUB_S_SRP PUB_S_SRP " " PUB_S_SRP,
             context, command, indent, preamble, divide, desc);
        free(desc);
    }
}

static void
cti_event_handler(xpc_object_t event, cti_connection_t conn_ref)
{
    if (event == XPC_ERROR_CONNECTION_INVALID) {
        INFO("cti_event_handler (" PUB_S_SRP "): cleanup", conn_ref->command_name);
        if (conn_ref->callback.reply != NULL) {
            conn_ref->internal_callback(conn_ref, event, kCTIStatus_Disconnected);
        } else {
            INFO("No callback");
        }
        if (conn_ref->connection != NULL) {
            xpc_release(conn_ref->connection);
            conn_ref->connection = NULL;
        }
    } else if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        cti_log_object("cti_event_handler", conn_ref->command_name, "", "", event, "");
        if (!conn_ref->checked_in) {
            xpc_object_t command_result = xpc_dictionary_get_value(event, "commandResult");
            int status = 0;
            if (command_result != NULL) {
                status = (int)xpc_int64_get_value(command_result);
                if (status == 0) {
                    xpc_object_t command_data = xpc_dictionary_get_value(event, "commandData");
                    if (command_data == NULL) {
                        status = 0;
                    } else {
                        xpc_object_t ret_value = xpc_dictionary_get_value(command_data, "ret");
                        if (ret_value == NULL) {
                            status = 0;
                        } else {
                            status = (int)xpc_int64_get_value(ret_value);
                        }
                    }
                }
            }

            if (status != 0) {
                conn_ref->internal_callback(conn_ref, event, kCTIStatus_UnknownError);
                xpc_connection_cancel(conn_ref->connection);
            } else if (conn_ref->property_name != NULL) {
                // We're meant to both get the property and subscribe to events on it.
                xpc_object_t *dict = xpc_dictionary_create(NULL, NULL, 0);
                if (dict == NULL) {
                    ERROR("cti_event_handler(" PUB_S_SRP "): no memory.", conn_ref->command_name);
                    xpc_connection_cancel(conn_ref->connection);
                } else {
                    xpc_object_t *array = xpc_array_create(NULL, 0);
                    if (array == NULL) {
                        ERROR("cti_event_handler(" PUB_S_SRP "): no memory.", conn_ref->command_name);
                        xpc_connection_cancel(conn_ref->connection);
                    } else {
                        xpc_dictionary_set_string(dict, "command", "eventsOn");
                        xpc_dictionary_set_string(dict, "clientName", "wpanctl");
                        xpc_dictionary_set_value(dict, "eventList", array);
                        xpc_array_set_string(array, XPC_ARRAY_APPEND, conn_ref->property_name);
                        conn_ref->property_name = NULL;
                        cti_log_object("cti_event_handler/events on", conn_ref->command_name, "", "", dict, "");
                        xpc_connection_send_message_with_reply(conn_ref->connection, dict, conn_ref->client_queue,
                                                               ^(xpc_object_t in_event) {
                                                                   cti_event_handler(in_event, conn_ref);
                                                               });
                        xpc_release(array);
                    }
                    xpc_release(dict);
                }
            } else {
                xpc_object_t *message = conn_ref->first_command;
                conn_ref->first_command = NULL;
                cti_log_object("cti_event_handler/command is", conn_ref->command_name, "", "", message, "");
                conn_ref->checked_in = true;

                xpc_connection_send_message_with_reply(conn_ref->connection, message, conn_ref->client_queue,
                                                       ^(xpc_object_t in_event) {
                                                           cti_event_handler(in_event, conn_ref);
                                                       });
                xpc_release(message);
            }
        } else {
            conn_ref->internal_callback(conn_ref, event, kCTIStatus_NoError);
        }
    } else {
        cti_log_object("cti_event_handler/other", conn_ref->command_name, "", "", event, "");
        ERROR("cti_event_handler: Unexpected Connection Error [" PUB_S_SRP "]",
              xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        conn_ref->internal_callback(conn_ref, NULL, kCTIStatus_DaemonNotRunning);
        if (event != XPC_ERROR_CONNECTION_INTERRUPTED) {
            xpc_connection_cancel(conn_ref->connection);
        }
    }
}

// Creates a new cti_ Connection Reference(cti_connection_t)
static cti_status_t
init_connection(cti_connection_t *ref, const char *servname, xpc_object_t *dict, const char *command_name,
                const char *property_name, void *context, cti_callback_t app_callback,
                cti_internal_callback_t internal_callback, dispatch_queue_t client_queue, const char *file, int line)
{
    // Use an cti_connection_t on the stack to be captured in the blocks below, rather than
    // capturing the cti_connection_t* owned by the client
    cti_connection_t conn_ref = calloc(1, sizeof(struct _cti_connection_t));
    if (conn_ref == NULL) {
        ERROR("dns_services: init_connection() No memory to allocate!");
        return kCTIStatus_NoMemory;
   }

    // Initialize the cti_connection_t
    dispatch_retain(client_queue);
    conn_ref->command_name = command_name;
    conn_ref->property_name = property_name;
    conn_ref->context = context;
    conn_ref->client_queue = client_queue;
    conn_ref->callback = app_callback;
    conn_ref->internal_callback = internal_callback;
    conn_ref->connection = xpc_connection_create_mach_service(servname, conn_ref->client_queue,
                                                              XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    conn_ref->first_command = dict;
    xpc_retain(dict);

    cti_log_object("init_connection/command", conn_ref->command_name, "", "", dict, "");

    if (conn_ref->connection == NULL)
    {
        ERROR("dns_services: init_connection() conn_ref/lib_q is NULL");
        if (conn_ref != NULL) {
            free(conn_ref);
        }
        return kCTIStatus_NoMemory;
    }

    RETAIN_HERE(conn_ref); // For the event handler.
    xpc_connection_set_event_handler(conn_ref->connection, ^(xpc_object_t event) { cti_event_handler(event, conn_ref); });
    xpc_connection_set_finalizer_f(conn_ref->connection, cti_xpc_connection_finalize);
    xpc_connection_set_context(conn_ref->connection, conn_ref);
    xpc_connection_resume(conn_ref->connection);

    char srp_name[] = "srp-mdns-proxyd";
    char client_name[sizeof(srp_name) + 20];
    snprintf(client_name, sizeof client_name, "%s-%d", srp_name, client_serial_number);
    client_serial_number++;

    xpc_object_t checkin_command = xpc_dictionary_create(NULL, NULL, 0);

    xpc_dictionary_set_string(checkin_command, "command", "checkIn");
    xpc_dictionary_set_string(checkin_command, "clientName", client_name);

    cti_log_object("init_connection/checkin", conn_ref->command_name, "", "", checkin_command, "");
    xpc_connection_send_message_with_reply(conn_ref->connection, checkin_command, conn_ref->client_queue,
                                           ^(xpc_object_t event) { cti_event_handler(event, conn_ref); });

    xpc_release(checkin_command);
    if (ref) {
        *ref = conn_ref;
    }
    // We always retain a reference for the caller, even if the caller doesn't actually hold the reference.
    // Calls that do not result in repeated callbacks release this reference after calling the callback.
    // Such calls do not return a reference to the caller, so there is no chance of a double release.
    // Calls that result in repeated callbacks have to release the reference by calling cti_events_discontinue.
    // If this isn't done, the reference will never be released.
    RETAIN(conn_ref);

    return kCTIStatus_NoError;
}

#define setup_for_command(ref, client_queue, command_name, property_name, dict, command, \
                          context, app_callback, internal_callback)                      \
    setup_for_command_(ref, client_queue, command_name, property_name, dict, command,    \
                       context, app_callback, internal_callback, __FILE__, __LINE__)
static cti_status_t
setup_for_command_(cti_connection_t *ref, dispatch_queue_t client_queue, const char *command_name,
                   const char *property_name, xpc_object_t dict, const char *command, void *context,
                   cti_callback_t app_callback, cti_internal_callback_t internal_callback, const char *file, int line)
{
    cti_status_t errx = kCTIStatus_NoError;

    // Sanity Checks
    if (app_callback.reply == NULL || internal_callback == NULL || client_queue == NULL)
    {
        ERROR(PUB_S_SRP ": NULL cti_connection_t OR Callback OR Client_Queue parameter", command_name);
        return kCTIStatus_BadParam;
    }

    // Get conn_ref from init_connection()
    xpc_dictionary_set_string(dict, "command", command);

    errx = init_connection(ref, "com.apple.wpantund.xpc", dict, command_name, property_name,
                           context, app_callback, internal_callback, client_queue, file, line);
    if (errx) // On error init_connection() leaves *conn_ref set to NULL
    {
        ERROR(PUB_S_SRP ": Since init_connection() returned %d error returning w/o sending msg", command_name, errx);
        return errx;
    }

    return errx;
}

static void
cti_internal_reply_callback(cti_connection_t NONNULL conn_ref, xpc_object_t __unused reply, cti_status_t status)
{
    cti_reply_t callback;
    INFO("cti_internal_reply_callback: conn_ref = %p", conn_ref);
    callback = conn_ref->callback.reply;
    if (callback != NULL) {
        callback(conn_ref->context, status);
    }
    cti_connection_release(conn_ref);
}

cti_status_t
cti_add_service(void *context, cti_reply_t callback, dispatch_queue_t client_queue,
                uint32_t enterprise_number, const uint8_t *NONNULL service_data, size_t service_data_length,
                const uint8_t *NONNULL server_data, size_t server_data_length)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.reply = callback;

    xpc_dictionary_set_data(dict, "service_data", service_data, service_data_length);
    xpc_dictionary_set_data(dict, "server_data", server_data, server_data_length);
    xpc_dictionary_set_uint64(dict, "enterprise_number", enterprise_number);
    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "ServiceAdd");
    xpc_dictionary_set_bool(dict, "stable", true);

    errx = setup_for_command(NULL, client_queue, "add_service", NULL, dict, "WpanctlCmd",
                             context, app_callback, cti_internal_reply_callback);
    xpc_release(dict);

    return errx;
}

cti_status_t
cti_remove_service(void *context, cti_reply_t callback, dispatch_queue_t client_queue,
                   uint32_t enterprise_number, const uint8_t *NONNULL service_data, size_t service_data_length)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.reply = callback;

    xpc_dictionary_set_data(dict, "service_data", service_data, service_data_length);
    xpc_dictionary_set_uint64(dict, "enterprise_number", enterprise_number);
    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "ServiceRemove");

    errx = setup_for_command(NULL, client_queue, "remove_service", NULL, dict, "WpanctlCmd",
                             context, app_callback, cti_internal_reply_callback);
    xpc_release(dict);

    return errx;
}

static cti_status_t
cti_do_prefix(void *context, cti_reply_t callback, dispatch_queue_t client_queue,
              struct in6_addr *prefix, int prefix_length, bool on_mesh, bool preferred, bool slaac, bool stable, bool adding)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.reply = callback;

    if (dict == NULL) {
        ERROR("cti_do_prefix: no memory for command dictionary.");
        return kCTIStatus_NoMemory;
    }
    xpc_dictionary_set_bool(dict, "preferred", preferred);
    if (adding) {
        xpc_dictionary_set_uint64(dict, "preferredLifetime", ND6_INFINITE_LIFETIME);
        xpc_dictionary_set_uint64(dict, "validLifetime", ND6_INFINITE_LIFETIME);
    } else {
        xpc_dictionary_set_uint64(dict, "preferredLifetime", 0);
        xpc_dictionary_set_uint64(dict, "validLifetime", 0);
    }
    xpc_dictionary_set_int64(dict, "prefix_length", 16);
    xpc_dictionary_set_bool(dict, "dhcp", false);
    xpc_dictionary_set_data(dict, "prefix", prefix, sizeof(*prefix));
    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_uint64(dict, "prefix_len_in_bits", prefix_length);
    xpc_dictionary_set_bool(dict, "slaac", slaac);
    xpc_dictionary_set_bool(dict, "onMesh", on_mesh);
    xpc_dictionary_set_bool(dict, "configure", false);
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "ConfigGateway");
    xpc_dictionary_set_bool(dict, "stable", stable);
    xpc_dictionary_set_bool(dict, "defaultRoute", adding);
    xpc_dictionary_set_int64(dict, "priority", 0);

    errx = setup_for_command(NULL, client_queue, "add_prefix", NULL, dict, "WpanctlCmd",
                             context, app_callback, cti_internal_reply_callback);
    xpc_release(dict);

    return errx;
}

cti_status_t
cti_add_prefix(void *context, cti_reply_t callback, dispatch_queue_t client_queue,
               struct in6_addr *prefix, int prefix_length, bool on_mesh, bool preferred, bool slaac, bool stable)
{
    return cti_do_prefix(context, callback, client_queue, prefix, prefix_length, on_mesh, preferred, slaac, stable, true);
}

cti_status_t
cti_remove_prefix(void *NULLABLE context, cti_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue,
                  struct in6_addr *NONNULL prefix, int prefix_length)

{
    return cti_do_prefix(context, callback, client_queue, prefix, prefix_length, false, false, false, false, false);
}

static void
cti_internal_tunnel_reply_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_tunnel_reply_t callback = conn_ref->callback.tunnel_reply;
    xpc_retain(reply);
    cti_status_t status = status_in;
    const char *tunnel_name = NULL;
    uint64_t command_result = xpc_dictionary_get_int64(reply, "commandResult");
    if (command_result != 0) {
        ERROR("cti_internal_tunnel_reply_callback: nonzero result %llu", command_result);
        status = kCTIStatus_UnknownError;
    } else {
        xpc_object_t result_dictionary = xpc_dictionary_get_dictionary(reply, "commandData");
        if (status == kCTIStatus_NoError) {
            if (result_dictionary != NULL) {
                const char *property_name = xpc_dictionary_get_string(result_dictionary, "property_name");
                if (property_name == NULL || strcmp(property_name, "Config:TUN:InterfaceName")) {
                    status = kCTIStatus_UnknownError;
                } else {
                    tunnel_name = xpc_dictionary_get_string(result_dictionary, "value");
                    if (tunnel_name == NULL) {
                        status = kCTIStatus_UnknownError;
                    }
                }
            } else {
                status = kCTIStatus_UnknownError;
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, tunnel_name, status);
    }
    xpc_release(reply);
    conn_ref->callback.reply = NULL;
    if (conn_ref->connection != NULL) {
        xpc_connection_cancel(conn_ref->connection);
    }
}

cti_status_t
cti_get_tunnel_name(void *NULLABLE context, cti_tunnel_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.tunnel_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "Config:TUN:InterfaceName");

    errx = setup_for_command(NULL, client_queue, "get_tunnel_name", NULL, dict, "WpanctlCmd",
                             context, app_callback, cti_internal_tunnel_reply_callback);
    xpc_release(dict);

    return errx;
}

static cti_status_t
cti_event_or_response_extract(xpc_object_t *reply, xpc_object_t *result_dictionary)
{
    xpc_object_t *result = xpc_dictionary_get_dictionary(reply, "commandData");
    if (result == NULL) {
        result = xpc_dictionary_get_dictionary(reply, "eventData");
    } else {
        int command_status = (int)xpc_dictionary_get_int64(reply, "commandResult");
        if (command_status != 0) {
            INFO("cti_event_or_response_extract: nonzero status %d", command_status);
            return kCTIStatus_UnknownError;
        }
    }
    if (result != NULL) {
        *result_dictionary = result;
        return kCTIStatus_NoError;
    }
    INFO("cti_event_or_response_extract: null result");
    return kCTIStatus_UnknownError;
}

static void
cti_internal_state_reply_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_state_reply_t callback = conn_ref->callback.state_reply;
    cti_network_state_t state = kCTI_NCPState_Unknown;
    cti_status_t status = status_in;
    if (status == kCTIStatus_NoError) {
        xpc_object_t result_dictionary = NULL;
        status = cti_event_or_response_extract(reply, &result_dictionary);
        if (status == kCTIStatus_NoError) {
            const char *state_name = xpc_dictionary_get_string(result_dictionary, "value");
            if (state_name == NULL) {
                status = kCTIStatus_UnknownError;
            } else if (!strcmp(state_name, "uninitialized")) {
                state = kCTI_NCPState_Uninitialized;
            } else if (!strcmp(state_name, "uninitialized:fault")) {
                state = kCTI_NCPState_Fault;
            } else if (!strcmp(state_name, "uninitialized:upgrading")) {
                state = kCTI_NCPState_Upgrading;
            } else if (!strcmp(state_name, "offline:deep-sleep")) {
                state = kCTI_NCPState_DeepSleep;
            } else if (!strcmp(state_name, "offline")) {
                state = kCTI_NCPState_Offline;
            } else if (!strcmp(state_name, "offline:commissioned")) {
                state = kCTI_NCPState_Commissioned;
            } else if (!strcmp(state_name, "associating")) {
                state = kCTI_NCPState_Associating;
            } else if (!strcmp(state_name, "associating:credentials-needed")) {
                state = kCTI_NCPState_CredentialsNeeded;
            } else if (!strcmp(state_name, "associated")) {
                state = kCTI_NCPState_Associated;
            } else if (!strcmp(state_name, "associated:no-parent")) {
                state = kCTI_NCPState_Isolated;
            } else if (!strcmp(state_name, "associated:netwake-asleep")) {
                state = kCTI_NCPState_NetWake_Asleep;
            } else if (!strcmp(state_name, "associated:netwake-waking")) {
                state = kCTI_NCPState_NetWake_Waking;
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, state, status);
    }
}

cti_status_t
cti_get_state(cti_connection_t *ref, void *NULLABLE context, cti_state_reply_t NONNULL callback,
              dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.state_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "NCP:State");

    errx = setup_for_command(ref, client_queue, "get_state", "NCP:State", dict, "WpanctlCmd",
                             context, app_callback, cti_internal_state_reply_callback);
    xpc_release(dict);

    return errx;
}

static void
cti_internal_partition_id_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_partition_id_reply_t callback = conn_ref->callback.partition_id_reply;
    int32_t partition_id = -1;
    cti_status_t status = status_in;
    if (status == kCTIStatus_NoError) {
        xpc_object_t result_dictionary = NULL;
        status = cti_event_or_response_extract(reply, &result_dictionary);
        if (status == kCTIStatus_NoError) {
            xpc_object_t value = xpc_dictionary_get_value(result_dictionary, "value");
            if (value == NULL) {
                ERROR("cti_internal_partition_id_callback: No partition ID returned.");
            } else if (xpc_get_type(value) != XPC_TYPE_UINT64) {
                char *value_string = xpc_copy_description(value);
                ERROR("cti_internal_partition_id_callback: Partition ID is " PUB_S_SRP " instead if uint64_t.",
                      value_string);
                free(value_string);
            } else {
                partition_id = (int32_t)xpc_dictionary_get_uint64(result_dictionary, "value");
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, partition_id, status);
    }
}

cti_status_t
cti_get_partition_id(cti_connection_t *ref, void *NULLABLE context, cti_partition_id_reply_t NONNULL callback,
                     dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.partition_id_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "Network:PartitionId");

    errx = setup_for_command(ref, client_queue, "get_partition_id", "Network:PartitionId", dict, "WpanctlCmd",
                             context, app_callback, cti_internal_partition_id_callback);
    xpc_release(dict);

    return errx;
}

static void
cti_internal_network_node_type_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_network_node_type_reply_t callback = conn_ref->callback.network_node_type_reply;
    cti_network_node_type_t network_node_type = kCTI_NetworkNodeType_Unknown;
    cti_status_t status = status_in;
    if (status == kCTIStatus_NoError) {
        xpc_object_t result_dictionary = NULL;
        status = cti_event_or_response_extract(reply, &result_dictionary);
        if (status == kCTIStatus_NoError) {
            xpc_object_t value = xpc_dictionary_get_value(result_dictionary, "value");
            if (value == NULL) {
                ERROR("cti_internal_network_node_type_callback: No node type returned.");
            } else if (xpc_get_type(value) != XPC_TYPE_STRING) {
                char *value_string = xpc_copy_description(value);
                ERROR("cti_internal_network_node_type_callback: node type type is " PUB_S_SRP " instead of string.",
                      value_string);
                free(value_string);
            } else {
                const char *node_type_name = xpc_dictionary_get_string(result_dictionary, "value");
                if (!strcmp(node_type_name, "unknown")) {
                    network_node_type = kCTI_NetworkNodeType_Unknown;
                } else if (!strcmp(node_type_name, "router")) {
                        network_node_type = kCTI_NetworkNodeType_Router;
                } else if (!strcmp(node_type_name, "end-device")) {
                    network_node_type = kCTI_NetworkNodeType_EndDevice;
                } else if (!strcmp(node_type_name, "sleepy-end-device")) {
                    network_node_type = kCTI_NetworkNodeType_SleepyEndDevice;
                } else if (!strcmp(node_type_name, "nl-lurker")) {
                    network_node_type = kCTI_NetworkNodeType_NestLurker;
                } else if (!strcmp(node_type_name, "commissioner")) {
                    network_node_type = kCTI_NetworkNodeType_Commissioner;
                } else if (!strcmp(node_type_name, "leader")) {
                    network_node_type = kCTI_NetworkNodeType_Leader;
                }
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, network_node_type, status);
    }
}

cti_status_t
cti_get_network_node_type(cti_connection_t *ref, void *NULLABLE context, cti_network_node_type_reply_t NONNULL callback,
                     dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.network_node_type_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "Network:NodeType");

    errx = setup_for_command(ref, client_queue, "get_network_node_type", "Network:NodeType", dict, "WpanctlCmd",
                             context, app_callback, cti_internal_network_node_type_callback);
    xpc_release(dict);

    return errx;
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

static uint8_t *
cti_array_to_bytes(xpc_object_t array, size_t *length_ret, const char *log_name)
{
    size_t length = xpc_array_get_count(array);
    size_t i;
    uint8_t *ret;

    ret = malloc(length);
    if (ret == NULL) {
        ERROR(PUB_S_SRP ": no memory for return buffer", log_name);
        return NULL;
    }

    for (i = 0; i < length; i++) {
        uint64_t v = xpc_array_get_uint64(array, i);
        ret[i] = v;
    }
    *length_ret = length;
    return ret;
}

static cti_status_t
cti_parse_services_array(cti_service_vec_t **services, xpc_object_t services_array)
{
    size_t services_array_length = xpc_array_get_count(services_array);
    size_t i, j;
    cti_service_vec_t *service_vec;
    cti_service_t *service;
    cti_status_t status = kCTIStatus_NoError;

    service_vec = cti_service_vec_create(services_array_length);
    if (service_vec == NULL) {
        return kCTIStatus_NoMemory;
    }

    // Array of arrays
    for (i = 0; i < services_array_length; i++) {
        xpc_object_t service_array = xpc_array_get_value(services_array, i);
        int match_count = 0;
        bool matched[5] = { false, false, false, false, false};
        uint64_t enterprise_number = 0;
        uint8_t *server_data = NULL;
        size_t server_data_length = 0;
        uint8_t *service_data = NULL;
        size_t service_data_length = 0;
        int flags = 0;

        if (service_array == NULL) {
            ERROR("Unable to get service array %zd", i);
        } else {
            size_t service_array_length = xpc_array_get_count(service_array);
            for (j = 0; j < service_array_length; j++) {
                xpc_object_t *array_sub_dict = xpc_array_get_value(service_array, j);
                if (array_sub_dict == NULL) {
                    ERROR("can't get service_array %zd subdictionary %zd", i, j);
                    goto service_array_element_failed;
                } else {
                    const char *key = xpc_dictionary_get_string(array_sub_dict, "key");
                    if (key == NULL) {
                        ERROR("Invalid services array %zd subdictionary %zd: no key", i, j);
                        goto service_array_element_failed;
                    } else if (!strcmp(key, "EnterpriseNumber")) {
                        if (matched[0]) {
                            ERROR("services array %zd: Enterprise number appears twice.", i);
                            goto service_array_element_failed;
                        }
                        enterprise_number = xpc_dictionary_get_uint64(array_sub_dict, "value");
                        matched[0] = true;
                    } else if (!strcmp(key, "Origin")) {
                        if (matched[1]) {
                            ERROR("Services array %zd: Origin appears twice.", i);
                            goto service_array_element_failed;
                        }
                        const char *origin_string = xpc_dictionary_get_string(array_sub_dict, "value");
                        if (origin_string == NULL) {
                            ERROR("Unable to get origin string from services array %zd", i);
                            goto service_array_element_failed;
                        } else if (!strcmp(origin_string, "user")) {
                            // Not NCP
                        } else if (!strcmp(origin_string, "ncp")) {
                            flags |= kCTIFlag_NCP;
                        } else {
                            ERROR("unknown origin " PUB_S_SRP, origin_string);
                            goto service_array_element_failed;
                        }
                        matched[1] = true;
                    } else if (!strcmp(key, "ServerData")) {
                        if (matched[2]) {
                            ERROR("Services array %zd: Server data appears twice.", i);
                            goto service_array_element_failed;
                        }
                        server_data = cti_array_to_bytes(xpc_dictionary_get_array(array_sub_dict, "value"),
                                                         &server_data_length, "Server data");
                        if (server_data == NULL) {
                            goto service_array_element_failed;
                        }
                        matched[2] = true;
                    } else if (!strcmp(key, "ServiceData")) {
                        if (matched[3]) {
                            ERROR("Services array %zd: Service data appears twice.", i);
                            goto service_array_element_failed;
                        }
                        service_data = cti_array_to_bytes(xpc_dictionary_get_array(array_sub_dict, "value"),
                                                          &service_data_length, "Service data");
                        if (service_data == NULL) {
                            goto service_array_element_failed;
                        }
                        matched[3] = true;
                    } else if (!strcmp(key, "Stable")) {
                        if (matched[4]) {
                            ERROR("Services array %zd: Stable state appears twice.", i);
                            goto service_array_element_failed;
                        }
                        if (xpc_dictionary_get_bool(array_sub_dict, "value")) {
                            flags |= kCTIFlag_Stable;
                        }
                        matched[4] = true;
                    } else {
                        ERROR("Unknown key in service array %zd subdictionary %zd: " PUB_S_SRP, i, j, key);
                        goto service_array_element_failed;
                    }
                    match_count++;
                }
            }
            if (match_count != 5) {
                ERROR("expecting %d sub-dictionaries to service array %zd, but got %d.",
                      5, i, match_count);
                goto service_array_element_failed;
            }
            uint16_t service_type, service_version;
            if (enterprise_number == THREAD_ENTERPRISE_NUMBER) {
                if (service_data_length != 1) {
                    INFO("Invalid service data: length = %zd", service_data_length);
                    goto service_array_element_failed;
                }
                service_type = service_data[0];
                service_version = 1;
            } else {
                // We don't support any other enterprise numbers.
                service_type = service_version = 0;
            }

            service = cti_service_create(enterprise_number, service_type, service_version,
                                         server_data, server_data_length, flags);
            if (service == NULL) {
                ERROR("Unable to store service %lld %d %d: out of memory.", enterprise_number,
                      service_type, service_version);
            } else {
                server_data = NULL;
                service_vec->services[i] = service;
            }
            goto done_with_service_array;
        service_array_element_failed:
            if (status == kCTIStatus_NoError) {
                status = kCTIStatus_UnknownError;
            }
        done_with_service_array:
            if (server_data != NULL) {
                free(server_data);
            }
            if (service_data != NULL) {
                free(service_data);
            }
        }
    }
    if (status == kCTIStatus_NoError) {
        *services = service_vec;
    } else {
        if (service_vec != NULL) {
            RELEASE_HERE(service_vec, cti_service_vec_finalize);
        }
    }
    return status;
}

static void
cti_internal_service_reply_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_service_reply_t callback = conn_ref->callback.service_reply;
    cti_service_vec_t *vec = NULL;
    cti_status_t status = status_in;
    if (status == kCTIStatus_NoError) {
        xpc_object_t result_dictionary = NULL;
        status = cti_event_or_response_extract(reply, &result_dictionary);
        if (status == kCTIStatus_NoError) {
            xpc_object_t *value = xpc_dictionary_get_array(result_dictionary, "value");
            if (value == NULL) {
                INFO("cti_internal_service_reply_callback: services array not present in Thread:Services event.");
            } else {
                status = cti_parse_services_array(&vec, value);
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, vec, status);
    }
    if (vec != NULL) {
        RELEASE_HERE(vec, cti_service_vec_finalize);
    }
}

cti_status_t
cti_get_service_list(cti_connection_t *ref, void *NULLABLE context, cti_service_reply_t NONNULL callback,
                     dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.service_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "Thread:Services");

    errx = setup_for_command(ref, client_queue, "get_service_list", "Thread:Services", dict, "WpanctlCmd",
                             context, app_callback, cti_internal_service_reply_callback);
    xpc_release(dict);

    return errx;
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

static cti_status_t
cti_parse_prefixes_array(cti_prefix_vec_t **vec_ret, xpc_object_t prefixes_array)
{
    size_t prefixes_array_length = xpc_array_get_count(prefixes_array);
    size_t i, j;
    cti_prefix_vec_t *prefixes = cti_prefix_vec_create(prefixes_array_length);
    cti_status_t status = kCTIStatus_NoError;

    if (prefixes == NULL) {
        INFO("cti_parse_prefixes_array: no memory.");
        status = kCTIStatus_NoMemory;
    } else {
        // Array of arrays
        for (i = 0; i < prefixes_array_length; i++) {
            xpc_object_t prefix_array = xpc_array_get_value(prefixes_array, i);
            int match_count = 0;
            bool matched[5] = { false, false};
            const char *destination = NULL;
            int metric = 0;
            struct in6_addr prefix_addr;

            if (prefix_array == NULL) {
                ERROR("Unable to get prefix array %zu", i);
            } else {
                size_t prefix_array_length = xpc_array_get_count(prefix_array);
                for (j = 0; j < prefix_array_length; j++) {
                    xpc_object_t *array_sub_dict = xpc_array_get_value(prefix_array, j);
                    if (array_sub_dict == NULL) {
                        ERROR("can't get prefix_array %zu subdictionary %zu", i, j);
                        goto done_with_prefix_array;
                    } else {
                        const char *key = xpc_dictionary_get_string(array_sub_dict, "key");
                        if (key == NULL) {
                            ERROR("Invalid prefixes array %zu subdictionary %zu: no key", i, j);
                            goto done_with_prefix_array;
                        }
                        // Fix me: when <rdar://problem/59371674> is fixed, remove Addreess key test.
                        else if (!strcmp(key, "Addreess") || !strcmp(key, "Address")) {
                            if (matched[0]) {
                                ERROR("prefixes array %zu: Address appears twice.", i);
                                goto done_with_prefix_array;
                            }
                            destination = xpc_dictionary_get_string(array_sub_dict, "value");
                            if (destination == NULL) {
                                INFO("process_prefixes_array: null address");
                                goto done_with_prefix_array;
                            }
                            matched[0] = true;
                        } else if (!strcmp(key, "Metric")) {
                            if (matched[1]) {
                                ERROR("prefixes array %zu: Metric appears twice.", i);
                                goto done_with_prefix_array;
                            }
                            metric = (int)xpc_dictionary_get_uint64(array_sub_dict, "value");
                        } else {
                            ERROR("Unknown key in prefix array %zu subdictionary %zu: " PUB_S_SRP, i, j, key);
                            goto done_with_prefix_array;
                        }
                        match_count++;
                    }
                }
                if (match_count != 2) {
                    ERROR("expecting %d sub-dictionaries to prefix array %zu, but got %d.",
                          2, i, match_count);
                    goto done_with_prefix_array;
                }

                // The prefix is in IPv6 address presentation form, so convert it to bits.
                char prefix_buffer[INET6_ADDRSTRLEN];
                const char *slash = strchr(destination, '/');
                size_t prefix_pres_len = slash - destination;
                if (prefix_pres_len >= INET6_ADDRSTRLEN - 1) {
                    ERROR("prefixes array %zu: destination is longer than maximum IPv6 address string: " PUB_S_SRP,
                          j, destination);
                    goto done_with_prefix_array;
                }
#ifndef __clang_analyzer__ // destination is never null at this point
                memcpy(prefix_buffer, destination, prefix_pres_len);
#endif
                prefix_buffer[prefix_pres_len] = 0;
                inet_pton(AF_INET6, prefix_buffer, &prefix_addr);

                // Also convert the prefix.
                char *endptr = NULL;
                int prefix_len = (int)strtol(slash + 1, &endptr, 10);
                if (endptr == slash + 1 || *endptr != 0 || prefix_len != 64) {
                    INFO("bogus prefix length provided by thread: " PUB_S_SRP, destination);
                    prefix_len = 64;
                }

                cti_prefix_t *prefix = cti_prefix_create(&prefix_addr, prefix_len, metric, 0);
                if (prefix != NULL) {
                    prefixes->prefixes[i] = prefix;
                }
                continue;
            done_with_prefix_array:
                status = kCTIStatus_UnknownError;
            }
        }
    }
    if (status == kCTIStatus_NoError) {
        *vec_ret = prefixes;
    } else {
        if (prefixes != NULL) {
            RELEASE_HERE(prefixes, cti_prefix_vec_finalize);
        }
    }
    return status;
}

static void
cti_internal_prefix_reply_callback(cti_connection_t NONNULL conn_ref, xpc_object_t reply, cti_status_t status_in)
{
    cti_prefix_reply_t callback = conn_ref->callback.prefix_reply;
    cti_status_t status = status_in;
    cti_prefix_vec_t *vec = NULL;
    xpc_object_t result_dictionary = NULL;
    if (status == kCTIStatus_NoError) {
        status = cti_event_or_response_extract(reply, &result_dictionary);
        if (status == kCTIStatus_NoError) {
            xpc_object_t *value = xpc_dictionary_get_array(result_dictionary, "value");
            if (value == NULL) {
                INFO("cti_internal_prefix_reply_callback: prefixes array not present in IPv6:Routes event.");
            } else {
                status = cti_parse_prefixes_array(&vec, value);
            }
        }
    }
    if (callback != NULL) {
        callback(conn_ref->context, vec, status);
    } else {
        INFO("Not calling callback.");
    }
    if (vec != NULL) {
        RELEASE_HERE(vec, cti_prefix_vec_finalize);
    }
}

cti_status_t
cti_get_prefix_list(cti_connection_t *ref, void *NULLABLE context, cti_prefix_reply_t NONNULL callback,
                     dispatch_queue_t NONNULL client_queue)
{
    cti_status_t errx;
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);

    cti_callback_t app_callback;
    app_callback.prefix_reply = callback;

    xpc_dictionary_set_string(dict, "interface", "org.wpantund.v1");
    xpc_dictionary_set_string(dict, "path", "/org/wpantund/utun2");
    xpc_dictionary_set_string(dict, "method", "PropGet");
    xpc_dictionary_set_string(dict, "property_name", "IPv6:Routes");

    errx = setup_for_command(ref, client_queue, "get_prefix_list", "IPv6:Routes", dict, "WpanctlCmd",
                             context, app_callback, cti_internal_prefix_reply_callback);
    xpc_release(dict);

    return errx;
}

cti_status_t
cti_events_discontinue(cti_connection_t ref)
{
    cti_connection_release(ref);
    return kCTIStatus_NoError;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
