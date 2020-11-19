/* macos-ioloop.c
 *
 * Copyright (c) 2018-2020 Apple Computer, Inc. All rights reserved.
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
 * Simple event dispatcher for DNS.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <dns_sd.h>

#include <dispatch/dispatch.h>

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#include "xpc_client_advertising_proxy.h"

static bool connection_write_now(comm_t *NONNULL connection);

dispatch_queue_t ioloop_main_queue;

// Forward references
static void tcp_start(comm_t *NONNULL connection);

int64_t
ioloop_timenow(void)
{
    int64_t now;
    struct timeval tv;
    gettimeofday(&tv, 0);
    now = (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
    return now;
}

static void
wakeup_event(void *context)
{
    wakeup_t *wakeup = context;

    // All ioloop wakeups are one-shot.
    ioloop_cancel_wake_event(wakeup);

    // Call the callback, which mustn't be null.
    wakeup->wakeup(wakeup->context);
}

static void
wakeup_finalize(void *context)
{
    wakeup_t *wakeup = context;
    if (wakeup->ref_count == 0) {
        if (wakeup->dispatch_source != NULL) {
            dispatch_release(wakeup->dispatch_source);
            wakeup->dispatch_source = NULL;
        }
        if (wakeup->finalize != NULL) {
            wakeup->finalize(wakeup->context);
        }
        free(wakeup);
    }
}

void
ioloop_wakeup_retain_(wakeup_t *wakeup, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(wakeup);
}

void
ioloop_wakeup_release_(wakeup_t *wakeup, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(wakeup, wakeup_finalize);
}

wakeup_t *
ioloop_wakeup_create(void)
{
    wakeup_t *ret = calloc(1, sizeof(*ret));
    if (ret) {
        RETAIN_HERE(ret);
    }
    return ret;
}

bool
ioloop_add_wake_event(wakeup_t *wakeup, void *context, wakeup_callback_t callback, wakeup_callback_t finalize,
                      int milliseconds)
{
    if (callback == NULL) {
        ERROR("ioloop_add_wake_event called with null callback");
        return false;
    }
    if (wakeup->dispatch_source != NULL) {
        ioloop_cancel_wake_event(wakeup);
    }
    wakeup->wakeup = callback;
    wakeup->context = context;
    wakeup->finalize = finalize;

    wakeup->dispatch_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, ioloop_main_queue);
    if (wakeup->dispatch_source == NULL) {
        ERROR("dispatch_source_create failed in ioloop_add_wake_event().");
        return false;
    }
    dispatch_source_set_event_handler_f(wakeup->dispatch_source, wakeup_event);
    dispatch_set_context(wakeup->dispatch_source, wakeup);

    // libdispatch doesn't allow events that are scheduled to happen right now. But it is actually useful to be
    // able to trigger an event to happen immediately, and this is the easiest way to do it from ioloop-we
    // can't rely on just scheduling an asynchronous event on an event loop because that's specific to Mac.
    if (milliseconds <= 0) {
        ERROR("ioloop_add_wake_event: milliseconds = %d", milliseconds);
        milliseconds = 10;
    }
    dispatch_source_set_timer(wakeup->dispatch_source,
                              dispatch_time(DISPATCH_TIME_NOW, (uint64_t)milliseconds * NSEC_PER_SEC / 1000),
                              (uint64_t)milliseconds * NSEC_PER_SEC / 1000, NSEC_PER_SEC / 100);
    dispatch_resume(wakeup->dispatch_source);

    return true;
}

void
ioloop_cancel_wake_event(wakeup_t *wakeup)
{
    if (wakeup->dispatch_source != NULL) {
        dispatch_source_cancel(wakeup->dispatch_source);
        dispatch_release(wakeup->dispatch_source);
        wakeup->dispatch_source = NULL;
    }
}

bool
ioloop_init(void)
{
    ioloop_main_queue = dispatch_get_main_queue();
    dispatch_retain(ioloop_main_queue);
    return true;
}

int
ioloop(void)
{
    dispatch_main();
    return 0;
}

#define connection_cancel(conn) connection_cancel_(conn, __FILE__, __LINE__)
static void
connection_cancel_(nw_connection_t connection, const char *file, int line)
{
    if (connection == NULL) {
        INFO("connection_cancel: null connection at " PUB_S_SRP ":%d", file, line);
    } else {
        INFO("connection_cancel: " PUB_S_SRP ":%d", file, line);
        nw_connection_cancel(connection);
    }
}

static void
comm_finalize(comm_t *comm)
{
    ERROR("comm_finalize");
    if (comm->connection != NULL) {
        nw_release(comm->connection);
        comm->connection = NULL;
    }
    if (comm->listener != NULL) {
        nw_release(comm->listener);
        comm->listener = NULL;
    }
    if (comm->parameters) {
        nw_release(comm->parameters);
        comm->parameters = NULL;
    }
    if (comm->pending_write != NULL) {
        dispatch_release(comm->pending_write);
        comm->pending_write = NULL;
    }
    // If there is an nw_connection_t or nw_listener_t outstanding, then we will get an asynchronous callback
    // later on.  So we can't actually free the data structure yet, but the good news is that comm_finalize() will
    // be called again later when the last outstanding asynchronous cancel is done, and then all of the stuff
    // that follows this will happen.
#ifndef __clang_analyzer__
    if (comm->ref_count > 0) {
        return;
    }
#endif
    if (comm->idle_timer != NULL) {
        ioloop_cancel_wake_event(comm->idle_timer);
        RELEASE_HERE(comm->idle_timer, wakeup_finalize);
    }
    if (comm->name != NULL) {
        free(comm->name);
    }
    if (comm->finalize != NULL) {
        comm->finalize(comm->context);
    }
    free(comm);
}

void
ioloop_comm_retain_(comm_t *comm, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(comm);
}

void
ioloop_comm_release_(comm_t *comm, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(comm, comm_finalize);
}

static message_t *
message_create(size_t message_size)
{
    message_t *message;

    // Never should have a message shorter than this.
    if (message_size < DNS_HEADER_SIZE) {
        return NULL;
    }

    message = (message_t *)malloc(message_size + (sizeof (message_t)) - (sizeof (dns_wire_t)));
    if (message) {
        memset(message, 0, (sizeof (message_t)) - (sizeof (dns_wire_t)));
        RETAIN_HERE(message);
    }
    return message;
}

void
ioloop_comm_cancel(comm_t *connection)
{
    if (connection->connection != NULL) {
        connection_cancel(connection->connection);
    }
}

static void
message_finalize(message_t *message)
{
    free(message);
}

void
ioloop_message_retain_(message_t *message, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(message);
}

void
ioloop_message_release_(message_t *message, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(message, message_finalize);
}

bool
ioloop_send_message(comm_t *connection, message_t *responding_to, struct iovec *iov, int iov_len)
{
    dispatch_data_t data = NULL, new_data, combined;
    int i;
    uint16_t len = 0;

    // Not needed on OSX because UDP conversations are treated as "connections."
    (void)responding_to;

    if (connection->connection == NULL) {
        return false;
    }

    // Create a dispatch_data_t object that contains the data in the iov.
    for (i = 0; i < iov_len; i++) {
        new_data = dispatch_data_create(iov->iov_base, iov->iov_len,
                                        ioloop_main_queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        len += iov->iov_len;
        if (data != NULL) {
            if (new_data != NULL) {
                // Subsequent times through
                combined = dispatch_data_create_concat(data, new_data);
                dispatch_release(data);
                dispatch_release(new_data);
                data = combined;
            } else {
                // Fail
                dispatch_release(data);
                data = NULL;
            }
        } else {
            // First time through
            data = new_data;
        }
        if (data == NULL) {
            ERROR("ioloop_send_message: no memory.");
            return false;
        }
    }

    if (len == 0) {
        if (data) {
            dispatch_release(data);
        }
        return false;
    }

    // TCP requires a length as well as the payload.
    if (connection->tcp_stream) {
        len = htons(len);
        new_data = dispatch_data_create(&len, sizeof (len), ioloop_main_queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        if (new_data == NULL) {
            if (data != NULL) {
                dispatch_release(data);
            }
            return false;
        }
        // Length is at beginning.
        combined = dispatch_data_create_concat(new_data, data);
        dispatch_release(data);
        dispatch_release(new_data);
        if (combined == NULL) {
            return false;
        }
        data = combined;
    }

    if (connection->pending_write != NULL) {
        ERROR("Dropping pending write on " PRI_S_SRP, connection->name ? connection->name : "<null>");
    }
    connection->pending_write = data;
    if (connection->connection_ready) {
        return connection_write_now(connection);
    }
    return true;
}

static bool
connection_write_now(comm_t *connection)
{
    // Retain the connection once for each write that's pending, so that it's never finalized while
    // there's a write in progress.
    connection->writes_pending++;
    RETAIN_HERE(connection);
    nw_connection_send(connection->connection, connection->pending_write, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
                       ^(nw_error_t  _Nullable error) {
                           if (error != NULL) {
                               ERROR("ioloop_send_message: write failed: " PUB_S_SRP,
                                     strerror(nw_error_get_error_code(error)));
                               connection_cancel(connection->connection);
                           }
                           if (connection->writes_pending > 0) {
                               connection->writes_pending--;
                               RELEASE_HERE(connection, comm_finalize);
                           } else {
                               ERROR("ioloop_send_message: write callback reached with no writes marked pending.");
                           }
                       });
    // nw_connection_send should retain this, so let go of our reference to it.
    dispatch_release(connection->pending_write);
    connection->pending_write = NULL;
    return true;
}

static bool
datagram_read(comm_t *connection, size_t length, dispatch_data_t content, nw_error_t error)
{
    message_t *message = NULL;
    bool ret = true, *retp = &ret;

    if (error != NULL) {
        ERROR("datagram_read: " PUB_S_SRP, strerror(nw_error_get_error_code(error)));
        ret = false;
        goto out;
    }
    if (length > UINT16_MAX) {
        ERROR("datagram_read: oversized datagram length %zd", length);
        ret = false;
        goto out;
    }
    message = message_create(length);
    if (message == NULL) {
        ERROR("datagram_read: unable to allocate message.");
        ret = false;
        goto out;
    }
    message->length = (uint16_t)length;
    dispatch_data_apply(content,
                        ^bool (dispatch_data_t __unused region, size_t offset, const void *buffer, size_t size) {
            if (message->length < offset + size) {
                ERROR("datagram_read: data region %zd:%zd is out of range for message length %d",
                      offset, size, message->length);
                *retp = false;
                return false;
            }
            memcpy(((uint8_t *)&message->wire) + offset, buffer, size);
            return true;
        });
    if (ret == true) {
        // Process the message.
        connection->datagram_callback(connection, message, connection->context);
    }

    out:
    if (message != NULL) {
        ioloop_message_release(message);
    }
    if (!ret) {
        connection_cancel(connection->connection);
    }
    return ret;
}

static void
tcp_read(comm_t *connection, size_t length, dispatch_data_t content, nw_error_t error)
{
    if (error != NULL) {
        connection_cancel(connection->connection);
        return;
    }
    if (datagram_read(connection, length, content, error)) {
        // Wait for the next frame
        tcp_start(connection);
    }
}

static void
tcp_read_length(comm_t *connection, dispatch_data_t content, nw_error_t error)
{
    size_t length;
    uint32_t bytes_to_read;
    const uint8_t *lenbuf;
    dispatch_data_t map;

    if (error != NULL) {
        ERROR("tcp_read_length: " PUB_S_SRP, strerror(nw_error_get_error_code(error)));
    fail:
        connection_cancel(connection->connection);
        return;
    }
    if (connection->connection == NULL) {
        return;
    }
    if (content == NULL) {
        INFO("tcp_read_length: remote end closed connection.");
        goto fail;
    }

    map = dispatch_data_create_map(content, (const void **)&lenbuf, &length);
    if (map == NULL) {
        ERROR("tcp_read_length: map create failed");
        goto fail;
    } else if (length != 2) {
        ERROR("tcp_read_length: invalid length = %zu", length);
        goto fail;
    }
    bytes_to_read = ((unsigned)(lenbuf[0]) << 8) | ((unsigned)lenbuf[1]);
    nw_connection_receive(connection->connection, bytes_to_read, bytes_to_read,
                              ^(dispatch_data_t new_content, nw_content_context_t __unused new_context,
                                bool __unused is_complete, nw_error_t new_error) {
                                  tcp_read(connection, bytes_to_read, new_content, new_error);
                              });
}

static void __unused
connection_idle_wakeup_callback(void *context)
{
    comm_t *connection = context;
    ERROR("Connection " PRI_S_SRP " has gone idle", connection->name);
    connection_cancel(connection->connection);
}

static void __unused
connection_idle_wakeup_finalize(void *context)
{
    comm_t *connection = context;
    connection->idle_timer = NULL;
}

static void
tcp_start(comm_t *connection)
{
    if (connection->connection == NULL) {
        return;
    }
    // We want to disconnect if the connection is idle for more than a short while.
    if (connection->idle_timer == NULL) {
        connection->idle_timer = ioloop_wakeup_create();
        if (connection->idle_timer == NULL) {
            // If we can't set up a timer, drop the connection now.
            connection_cancel(connection->connection);
            return;
        }
    }
    ioloop_add_wake_event(connection->idle_timer, connection,
                          connection_idle_wakeup_callback, connection_idle_wakeup_finalize,
                          60 * 1000); // One minute
    nw_connection_receive(connection->connection, 2, 2,
                          ^(dispatch_data_t content, nw_content_context_t __unused context,
                            bool is_complete, nw_error_t error) {
                              // For TCP connections, is_complete means the other end closed the connection.
                              if (is_complete || content == NULL) {
                                  INFO("tcp_start: remote end closed connection.");
                                  connection_cancel(connection->connection);
                              } else {
                                  tcp_read_length(connection, content, error);
                              }
                          });
}

static void
udp_start(comm_t *connection)
{
    if (connection->connection == NULL) {
        return;
    }

    // UDP is connectionless; the "connection" is just a placeholder that allows us to reply to the source.
    // In principle, the five-tuple that is represented by the connection object should die as soon as the
    // client is done retransmitting, since a later transaction should come from a different source port.
    // Consequently, we set an idle timer: if we don't see any packets on this five-tuple after twenty seconds,
    // it's unlikely that we will see any more, so it's time to collect the connection.  If another packet
    // does come in after this, a new connection will be created. The only risk is that if the cancel comes
    // after a packet has arrived and been consumed by the nw_connection, but before we've called nw_connection_read,
    // it will be lost. This should never happen for an existing SRP client, since the longest retry interval
    // by default is 15 seconds; as the retry intervals get longer, it becomes safer to collect the connection
    // and allow it to be recreated.
    if (connection->server) {
        if (connection->idle_timer == NULL) {
            connection->idle_timer = ioloop_wakeup_create();
            if (connection->idle_timer == NULL) {
                // If we can't set up a timer, drop the connection now.
                connection_cancel(connection->connection);
                return;
            }
        }
        ioloop_add_wake_event(connection->idle_timer, connection,
                              connection_idle_wakeup_callback, connection_idle_wakeup_finalize,
                              20 * 1000); // 20 seconds (15 seconds is the SRP client retry interval)
    }

    connection->read_pending = true;    // When a read is pending, we have an extra refcount on the connection
    RETAIN_HERE(connection);
    nw_connection_receive_message(connection->connection,
                          ^(dispatch_data_t content, nw_content_context_t __unused context,
                            bool __unused is_complete, nw_error_t error) {
                              bool proceed = true;
                              if (content != NULL) {
                                  proceed = datagram_read(connection, dispatch_data_get_size(content),
                                                          content, error);
                              }
                              if (content == NULL || error != NULL) {
                                  connection_cancel(connection->connection);
                              }
                              // Once we have a five-tuple connection, we can't easily get rid of it, so keep
                              // reading.
                              else if (proceed) {
                                  udp_start(connection);
                              }
                              RELEASE_HERE(connection, comm_finalize);
                          });
}

static void
connection_state_changed(comm_t *connection, nw_connection_state_t state, nw_error_t error)
{
    (void)error;
    if (state == nw_connection_state_ready) {
        INFO("connection_state_changed: " PRI_S_SRP " state is ready; error = %p",
             connection->name != NULL ? connection->name : "<no name>", error);
        // Set up a reader.
        if (connection->tcp_stream) {
            tcp_start(connection);
        } else {
            udp_start(connection);
        }
        connection->connection_ready = true;
        // If there's a write pending, send it now.
        if (connection->pending_write) {
            connection_write_now(connection);
        }
    } else if (state == nw_connection_state_failed) {
        INFO("connection_state_changed: " PRI_S_SRP " state is failed; error = %p",
             connection->name != NULL ? connection->name : "<no name>", error);
        connection_cancel(connection->connection);
    } else if (state == nw_connection_state_cancelled) {
        INFO("connection_state_changed: " PRI_S_SRP " state is canceled; error = %p",
             connection->name != NULL ? connection->name : "<no name>", error);
        // This releases the final reference to the connection object, which was held by the nw_connection_t.
        RELEASE_HERE(connection, comm_finalize);
    } else {
        INFO("connection_state_changed: " PRI_S_SRP " state is %d; error = %p",
             connection->name != NULL ? connection->name : "<no name>", state, error);
    }
}

static void
connection_callback(comm_t *listener, nw_connection_t new_connection)
{
    comm_t *connection = calloc(1, sizeof *connection);
    if (connection == NULL) {
        ERROR("Unable to receive connection: no memory.");
        // Assuming that since we haven't retained the connection, it will be released?
        // XXX RefCount Check.
        return;
    }

    connection->connection = new_connection;
    nw_retain(connection->connection);

    connection->name = nw_connection_copy_description(connection->connection);
    if (connection->name != NULL) {
        INFO("Received connection from " PRI_S_SRP, connection->name);
    } else {
        ERROR("Unable to get description of new connection.");
    }
    connection->datagram_callback = listener->datagram_callback;
    connection->tcp_stream = listener->tcp_stream;
    connection->server = true;
    nw_connection_set_state_changed_handler(connection->connection,
                                            ^(nw_connection_state_t state, nw_error_t error)
                                            { connection_state_changed(connection, state, error); });
    nw_connection_set_queue(connection->connection, ioloop_main_queue);
    nw_connection_start(connection->connection);
    // new_connection holds a reference to the connection until it is canceled.
    RETAIN_HERE(connection);
    if (listener->connected != NULL) {
        listener->connected(connection, listener->context);
    }
}

static void
listener_finalize(comm_t *listener)
{
    if (listener->listener != NULL) {
        nw_release(listener->listener);
        listener->listener = NULL;
    }
    if (listener->name != NULL) {
        free(listener->name);
    }
    if (listener->parameters) {
        nw_release(listener->parameters);
    }
    if (listener->avoid_ports != NULL) {
        free(listener->avoid_ports);
    }
    if (listener->finalize) {
        listener->finalize(listener->context);
    }
    free(listener);
}

void
ioloop_listener_retain_(comm_t *listener, const char *file, int line)
{
    RETAIN(listener);
}

void
ioloop_listener_release_(comm_t *listener, const char *file, int line)
{
    RELEASE(listener, listener_finalize);
}

void
ioloop_listener_cancel(comm_t *connection)
{
    if (connection->listener != NULL) {
        nw_listener_cancel(connection->listener);
        nw_release(connection->listener);
        connection->listener = NULL;
    }
}

static void
ioloop_listener_state_changed_handler(comm_t *listener, nw_listener_state_t state, nw_error_t error)
{
    int i;
    if (error != NULL) {
        INFO("nw_listener_create:state changed: error");
    } else {
        if (state == nw_listener_state_waiting) {
            INFO("nw_listener_create: waiting");
            return;
        } else if (state == nw_listener_state_failed) {
            INFO("nw_listener_create: failed");
            nw_listener_cancel(listener->listener);
        } else if (state == nw_listener_state_ready) {
            INFO("nw_listener_create: ready");
            if (listener->avoiding) {
                listener->listen_port = nw_listener_get_port(listener->listener);
                if (listener->avoid_ports != NULL) {
                    for (i = 0; i < listener->num_avoid_ports; i++) {
                        if (listener->avoid_ports[i] == listener->listen_port) {
                            INFO("ioloop_listener_state_changed_handler: Got port %d, which we are avoiding.",
                                 listener->listen_port);
                            listener->avoiding = true;
                            listener->listen_port = 0;
                            nw_listener_cancel(listener->listener);
                            return;
                        }
                    }
                }
                INFO("ioloop_listener_state_changed_handler: Got port %d.", listener->listen_port);
                listener->avoiding = false;
                if (listener->ready) {
                    listener->ready(listener->context, listener->listen_port);
                }
            }
        } else if (state == nw_listener_state_cancelled) {
            INFO("ioloop_listener_state_changed_handler: cancelled");
            nw_release(listener->listener);
            listener->listener = NULL;
            if (listener->avoiding) {
                listener->listener = nw_listener_create(listener->parameters);
                if (listener->listener == NULL) {
                    ERROR("ioloop_listener_state_changed_handler: Unable to recreate listener.");
                    goto cancel;
                } else {
                    RETAIN_HERE(listener);
                    nw_listener_set_state_changed_handler(listener->listener,
                                                          ^(nw_listener_state_t ev_state, nw_error_t ev_error) {
                            ioloop_listener_state_changed_handler(listener, ev_state, ev_error);
                        });
                }
            } else {
                ;
            cancel:
                if (listener->cancel) {
                    listener->cancel(listener->context);
                }
                RELEASE_HERE(listener, listener_finalize);
            }
        }
    }
}

comm_t *
ioloop_listener_create(bool stream, bool tls, uint16_t *avoid_ports, int num_avoid_ports,
                       const addr_t *ip_address, const char *multicast, const char *name,
                       datagram_callback_t datagram_callback, connect_callback_t connected, cancel_callback_t cancel,
                       ready_callback_t ready, finalize_callback_t finalize, void *context)
{
    comm_t *listener;
    int family = (ip_address != NULL) ? ip_address->sa.sa_family : AF_UNSPEC;
    uint16_t port;
    char portbuf[10];
    nw_endpoint_t endpoint;

    if (ip_address == NULL) {
        port = 0;
    } else {
        port = (family == AF_INET) ? ip_address->sin.sin_port : ip_address->sin6.sin6_port;
    }

    if (multicast != NULL) {
        ERROR("ioloop_setup_listener: multicast not supported.");
        return NULL;
    }

    if (datagram_callback == NULL) {
        ERROR("ioloop_setup: no datagram callback provided.");
        return NULL;
    }

    sprintf(portbuf, "%d", port);
    listener = calloc(1, sizeof(*listener));
    if (listener == NULL) {
        if (ip_address == NULL) {
            ERROR("No memory for listener on <NULL>#%d", port);
        } else if (family == AF_INET) {
            IPv4_ADDR_GEN_SRP(&ip_address->sin.sin_addr.s_addr, ipv4_addr_buf);
            ERROR("No memory for listener on " PRI_IPv4_ADDR_SRP "#%d",
                  IPv4_ADDR_PARAM_SRP(&ip_address->sin.sin_addr.s_addr, ipv4_addr_buf), port);
        } else if (family == AF_INET6) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(ip_address->sin6.sin6_addr.s6_addr, ipv6_addr_buf);
            ERROR("No memory for listener on " PRI_SEGMENTED_IPv6_ADDR_SRP "#%d",
                  SEGMENTED_IPv6_ADDR_PARAM_SRP(ip_address->sin6.sin6_addr.s6_addr, ipv6_addr_buf), port);
        } else {
            ERROR("No memory for listener on <family address other than AF_INET or AF_INET6: %d>#%d", family, port);
        }
        return NULL;
    }
    if (avoid_ports != NULL) {
        listener->avoid_ports = malloc(num_avoid_ports * sizeof(uint16_t));
        if (listener->avoid_ports == NULL) {
            if (ip_address == NULL) {
                ERROR("No memory for listener avoid_ports on <NULL>#%d", port);
            } else if (family == AF_INET) {
                IPv4_ADDR_GEN_SRP(&ip_address->sin.sin_addr.s_addr, ipv4_addr_buf);
                ERROR("No memory for listener avoid_ports on " PRI_IPv4_ADDR_SRP "#%d",
                      IPv4_ADDR_PARAM_SRP(&ip_address->sin.sin_addr.s_addr, ipv4_addr_buf), port);
            } else if (family == AF_INET6) {
                SEGMENTED_IPv6_ADDR_GEN_SRP(ip_address->sin6.sin6_addr.s6_addr, ipv6_addr_buf);
                ERROR("No memory for listener avoid_ports on " PRI_SEGMENTED_IPv6_ADDR_SRP "#%d",
                      SEGMENTED_IPv6_ADDR_PARAM_SRP(ip_address->sin6.sin6_addr.s6_addr, ipv6_addr_buf), port);
            } else {
                ERROR("No memory for listener avoid_ports on <family address other than AF_INET or AF_INET6: %d>#%d",
                      family, port);
            }
            free(listener);
            return NULL;
        }
        listener->num_avoid_ports = num_avoid_ports;
        listener->avoiding = true;
    }
    RETAIN_HERE(listener);
    if (port == 0) {
        endpoint = NULL;
        // Even though we don't have any ports to avoid, we still want the "avoiding" behavior in this case, since that
        // is what triggers a call to the ready handler, which passes the port number that we got to it.
        listener->avoiding = true;
    } else {
        listener->listen_port = port;
        char ip_address_str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
        if (ip_address == NULL) {
            if (family == AF_INET) {
                snprintf(ip_address_str, sizeof(ip_address_str), "0.0.0.0");
            } else {
                // AF_INET6 or AF_UNSPEC
                snprintf(ip_address_str, sizeof(ip_address_str), "::");
            }
        } else {
            inet_ntop(family, ip_address->sa.sa_data, ip_address_str, sizeof(ip_address_str));
        }
        endpoint = nw_endpoint_create_host(ip_address_str, portbuf);
        if (endpoint == NULL) {
            ERROR("No memory for listener endpoint.");
            RELEASE_HERE(listener, listener_finalize);
            return NULL;
        }
    }

    if (stream) {
        listener->parameters = nw_parameters_create_secure_tcp(tls ? NW_PARAMETERS_DEFAULT_CONFIGURATION
                                                                    : NW_PARAMETERS_DISABLE_PROTOCOL,
                                                               NW_PARAMETERS_DEFAULT_CONFIGURATION);
    } else {
        if (tls) {
            ERROR("DTLS support not implemented.");
            nw_release(endpoint);
            RELEASE_HERE(listener, listener_finalize);
            return NULL;
        }
        listener->parameters = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                               NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    if (listener->parameters == NULL) {
        ERROR("No memory for listener parameters.");
        nw_release(endpoint);
        RELEASE_HERE(listener, listener_finalize);
        return NULL;
    }

    if (endpoint != NULL) {
        nw_parameters_set_local_endpoint(listener->parameters, endpoint);
        nw_release(endpoint);
    }

    if (tls) {
        nw_protocol_options_t tls_options = nw_tls_create_options();
        if (tls_options == NULL) {
            ERROR("No memory for tls protocol options.");
            RELEASE_HERE(listener, listener_finalize);
            return NULL;
        }
        // XXX set up the listener certificate(s).
        // XXX how to configure this onto the parameters object?
    }

    // Set SO_REUSEADDR.
    nw_parameters_set_reuse_local_address(listener->parameters, true);

    // Create the nw_listener_t.
    listener->listener = nw_listener_create(listener->parameters);
    if (listener->listener == NULL) {
        ERROR("no memory for nw_listener object");
        RELEASE_HERE(listener, listener_finalize);
        return NULL;
    }
    nw_listener_set_new_connection_handler(listener->listener,
                                           ^(nw_connection_t connection) { connection_callback(listener, connection); }
                                           );

    RETAIN_HERE(listener); // for the nw_listener_t
    nw_listener_set_state_changed_handler(listener->listener, ^(nw_listener_state_t state, nw_error_t error) {
            ioloop_listener_state_changed_handler(listener, state, error);
        });

    listener->name = strdup(name);
    listener->datagram_callback = datagram_callback;
    listener->cancel = cancel;
    listener->ready = ready;
    listener->finalize = finalize;
    listener->context = context;
    listener->connected = connected;
    listener->tcp_stream = stream;

    nw_listener_set_queue(listener->listener, ioloop_main_queue);
    nw_listener_start(listener->listener);
    // Listener has one refcount
    return listener;
}

comm_t *
ioloop_connection_create(addr_t *NONNULL remote_address, bool tls, bool stream,
                         datagram_callback_t datagram_callback, connect_callback_t connected,
                         disconnect_callback_t disconnected, finalize_callback_t finalize, void *context)
{
    comm_t *connection;
    char portbuf[10];
    nw_parameters_t parameters;
    nw_endpoint_t endpoint;
    char addrbuf[INET6_ADDRSTRLEN];

    inet_ntop(remote_address->sa.sa_family, (remote_address->sa.sa_family == AF_INET
                                             ? (void *)&remote_address->sin.sin_addr
                                             : (void *)&remote_address->sin6.sin6_addr), addrbuf, sizeof addrbuf);
    sprintf(portbuf, "%d", (remote_address->sa.sa_family == AF_INET
                            ? ntohs(remote_address->sin.sin_port)
                            : ntohs(remote_address->sin6.sin6_port)));
    connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        ERROR("No memory for connection");
        return NULL;
    }
    // If we don't release this because of an error, this is the caller's reference to the comm_t.
    RETAIN_HERE(connection);
    endpoint = nw_endpoint_create_host(addrbuf, portbuf);
    if (endpoint == NULL) {
        ERROR("No memory for connection endpoint.");
        RELEASE_HERE(connection, comm_finalize);
        return NULL;
    }

    if (stream) {
        parameters = nw_parameters_create_secure_tcp(tls ? NW_PARAMETERS_DEFAULT_CONFIGURATION
                                                            : NW_PARAMETERS_DISABLE_PROTOCOL,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    } else {
        if (tls) {
            ERROR("DTLS support not implemented.");
            nw_release(endpoint);
            RELEASE_HERE(connection, comm_finalize);
            return NULL;
        }
        parameters = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                     NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    if (parameters == NULL) {
        ERROR("No memory for connection parameters.");
        nw_release(endpoint);
        RELEASE_HERE(connection, comm_finalize);
        return NULL;
    }

    if (tls) {
#ifdef NOTYET
        nw_protocol_options_t tls_options = nw_tls_create_options();
        if (tls_options == NULL) {
            ERROR("No memory for tls protocol options.");
            RELEASE_HERE(connection, comm_finalize);
            return NULL;
        }
        // XXX set up the connection certificate(s).
        // XXX how to configure this onto the parameters object?
#endif
    }

    connection->name = strdup(addrbuf);

    // Create the nw_connection_t.
    connection->connection = nw_connection_create(endpoint, parameters);
    nw_release(endpoint);
    nw_release(parameters);
    if (connection->connection == NULL) {
        ERROR("no memory for nw_connection object");
        RELEASE_HERE(connection, comm_finalize);
        return NULL;
    }

    connection->datagram_callback = datagram_callback;
    connection->connected = connected;
    connection->disconnected = disconnected;
    connection->finalize = finalize;
    connection->tcp_stream = stream;
    connection->context = context;
    nw_connection_set_state_changed_handler(connection->connection,
                                            ^(nw_connection_state_t state, nw_error_t error)
                                            { connection_state_changed(connection, state, error); });
    nw_connection_set_queue(connection->connection, ioloop_main_queue);
    // Until we get the canceled callback in connection_state_changed, the nw_connection_t holds a reference to this
    // comm_t object.
    RETAIN_HERE(connection);
    nw_connection_start(connection->connection);
    return connection;
}

static void
subproc_finalize(subproc_t *subproc)
{
    int i;
    for (i = 0; i < subproc->argc; i++) {
        if (subproc->argv[i] != NULL) {
            free(subproc->argv[i]);
            subproc->argv[i] = NULL;
        }
    }
    if (subproc->dispatch_source != NULL) {
        dispatch_release(subproc->dispatch_source);
    }
    if (subproc->output_fd != NULL) {
        ioloop_file_descriptor_release(subproc->output_fd);
    }
    if (subproc->finalize != NULL) {
        subproc->finalize(subproc->context);
    }
    free(subproc);
}

static void subproc_cancel(void *context)
{
    subproc_t *subproc = context;
    subproc->dispatch_source = NULL;
    RELEASE_HERE(subproc, subproc_finalize);
}

static void
subproc_event(void *context)
{
    subproc_t *subproc = context;
    pid_t pid;
    int status;

    pid = waitpid(subproc->pid, &status, WNOHANG);
    if (pid <= 0) {
        return;
    }
    subproc->callback(subproc, status, NULL);
    if (!WIFSTOPPED(status)) {
        dispatch_source_cancel(subproc->dispatch_source);
    }
}

static void subproc_output_finalize(void *context)
{
    subproc_t *subproc = context;
    if (subproc->output_fd) {
        subproc->output_fd = NULL;
    }
}

void
ioloop_subproc_release_(subproc_t *subproc, const char *file, int line)
{
    RELEASE(subproc, subproc_finalize);
}

// Invoke the specified executable with the specified arguments.   Call callback when it exits.
// All failures are reported through the callback.
subproc_t *
ioloop_subproc(const char *exepath, char *NULLABLE *argv, int argc,
               subproc_callback_t callback, io_callback_t output_callback, void *context)
{
    subproc_t *subproc;
    int i, rv;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;

    if (callback == NULL) {
        ERROR("ioloop_add_wake_event called with null callback");
        return NULL;
    }

    if (argc > MAX_SUBPROC_ARGS) {
        callback(NULL, 0, "too many subproc args");
        return NULL;
    }

    subproc = calloc(1, sizeof *subproc);
    if (subproc == NULL) {
        callback(NULL, 0, "out of memory");
        return NULL;
    }
    RETAIN_HERE(subproc);
    if (output_callback != NULL) {
        rv = pipe(subproc->pipe_fds);
        if (rv < 0) {
            callback(NULL, 0, "unable to create pipe.");
            RELEASE_HERE(subproc, subproc_finalize);
            return NULL;
        }
        subproc->output_fd = ioloop_file_descriptor_create(subproc->pipe_fds[0], subproc, subproc_output_finalize);
        if (subproc->output_fd == NULL) {
            callback(NULL, 0, "out of memory.");
            close(subproc->pipe_fds[0]);
            close(subproc->pipe_fds[1]);
            RELEASE_HERE(subproc, subproc_finalize);
            return NULL;
        }
    }
                                                           
    subproc->argv[0] = strdup(exepath);
    if (subproc->argv[0] == NULL) {
        RELEASE_HERE(subproc, subproc_finalize);
        callback(NULL, 0, "out of memory");
        return NULL;
    }
    subproc->argc++;
    for (i = 0; i < argc; i++) {
        subproc->argv[i + 1] = strdup(argv[i]);
        if (subproc->argv[i + 1] == NULL) {
            RELEASE_HERE(subproc, subproc_finalize);
            callback(NULL, 0, "out of memory");
            return NULL;
        }
        subproc->argc++;
    }

    // Set up for posix_spawn
    posix_spawn_file_actions_init(&actions);
    if (output_callback != NULL) {
        posix_spawn_file_actions_adddup2(&actions, subproc->pipe_fds[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&actions, subproc->pipe_fds[0]);
        posix_spawn_file_actions_addclose(&actions, subproc->pipe_fds[1]);
    }
    posix_spawnattr_init(&attrs);
    extern char **environ;
    rv = posix_spawn(&subproc->pid, exepath, &actions, &attrs, subproc->argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attrs);
    if (rv < 0) {
        ERROR("posix_spawn failed for " PUB_S_SRP ": " PUB_S_SRP, subproc->argv[0], strerror(errno));
        callback(subproc, 0, strerror(errno));
        RELEASE_HERE(subproc, subproc_finalize);
        return NULL;
    }
    subproc->callback = callback;
    subproc->context = context;

    subproc->dispatch_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, subproc->pid, DISPATCH_PROC_EXIT,
                                                      ioloop_main_queue);
    if (subproc->dispatch_source == NULL) {
        ERROR("dispatch_source_create failed in ioloop_add_wake_event().");
        return false;
    }
    dispatch_retain(subproc->dispatch_source);
    dispatch_source_set_event_handler_f(subproc->dispatch_source, subproc_event);
    dispatch_source_set_cancel_handler_f(subproc->dispatch_source, subproc_cancel);
    dispatch_set_context(subproc->dispatch_source, subproc);
    dispatch_activate(subproc->dispatch_source);
    RETAIN_HERE(subproc); // Dispatch has a reference

    // Now that we have a viable subprocess, add the reader callback.
    if (output_callback != NULL && subproc->output_fd != NULL) {
        close(subproc->pipe_fds[1]);
        ioloop_add_reader(subproc->output_fd, output_callback);
    }
    return subproc;
}

void
ioloop_dnssd_txn_cancel(dnssd_txn_t *txn)
{
    if (txn->sdref != NULL) {
        DNSServiceRefDeallocate(txn->sdref);
        txn->sdref = NULL;
    } else {
        INFO("ioloop_dnssd_txn_cancel: dead transaction.");
    }
}

static void
dnssd_txn_finalize(dnssd_txn_t *txn)
{
    if (txn->sdref != NULL) {
        ioloop_dnssd_txn_cancel(txn);
    }
    if (txn->finalize_callback) {
        txn->finalize_callback(txn->context);
    }
    free(txn);
}

void
ioloop_dnssd_txn_retain_(dnssd_txn_t *dnssd_txn, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(dnssd_txn);
}

void
ioloop_dnssd_txn_release_(dnssd_txn_t *dnssd_txn, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(dnssd_txn, dnssd_txn_finalize);
}

dnssd_txn_t *
ioloop_dnssd_txn_add_(DNSServiceRef ref, void *context, finalize_callback_t finalize_callback, const char *file,
                      int line)
{
    dnssd_txn_t *txn = calloc(1, sizeof(*txn));
    (void)file; (void)line;

    if (txn != NULL) {
        RETAIN(txn);
        txn->sdref = ref;
        txn->context = context;
        txn->finalize_callback = finalize_callback;
        DNSServiceSetDispatchQueue(ref, ioloop_main_queue);
    }
    return txn;
}

void
ioloop_dnssd_txn_set_aux_pointer(dnssd_txn_t *NONNULL txn, void *aux_pointer)
{
    txn->aux_pointer = aux_pointer;
}

void *
ioloop_dnssd_txn_get_aux_pointer(dnssd_txn_t *NONNULL txn)
{
    return txn->aux_pointer;
}

void *
ioloop_dnssd_txn_get_context(dnssd_txn_t *NONNULL txn)
{
    return txn->context;
}

static bool
ioloop_xpc_client_is_entitled(xpc_connection_t conn, const char *entitlement_name)
{
    bool entitled = false;
    xpc_object_t entitled_obj = xpc_connection_copy_entitlement_value(conn, entitlement_name);

    if (entitled_obj) {
        if (xpc_get_type(entitled_obj) == XPC_TYPE_BOOL && xpc_bool_get_value(entitled_obj)) {
            entitled = true;
        }
        xpc_release(entitled_obj);
    } else {
        ERROR("ioloop_xpc_client_is_entitled: Client Entitlement is NULL");
    }

    if (!entitled) {
        ERROR("ioloop_xpc_client_is_entitled: Client is missing Entitlement!");
    }

    return entitled;
}

static void
ioloop_xpc_accept(xpc_connection_t conn, const char *name, ioloop_xpc_callback_t callback)
{
    struct state {
        xpc_connection_t conn;
        ioloop_xpc_callback_t callback;
    } *state;

    if (conn == NULL) {
        ERROR("ioloop_xpc_accept: listener has been canceled.");
        return;
    }

    state = calloc(1, sizeof(*state));
    if (state == NULL) {
        ERROR("ioloop_xpc_accept: no memory for xpc connection state.");
        return;
    }

    int pid = xpc_connection_get_pid(conn);
    int uid = xpc_connection_get_euid(conn);

    if (!ioloop_xpc_client_is_entitled(conn, name)) {
        ERROR("ioloop_xpc_accept: connection from uid %d pid %d is missing entitlement " PUB_S_SRP ".", uid, pid, name);
        xpc_connection_cancel(conn);
        free(state);
        return;
    }

    state->conn = conn;
    xpc_retain(conn);
    state->callback = callback;
    xpc_connection_set_target_queue(conn, ioloop_main_queue);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t request) {
            xpc_type_t type = xpc_get_type(request);

            if (request == XPC_ERROR_CONNECTION_INVALID) {
                INFO("ioloop_xpc_accept event handler: connection has been finalized.");
                if (state->callback != NULL) {
                    state->callback(state->conn, NULL);
                }
                // We are guaranteed that this is the last callback, so we can safely free state.
                if (state->conn != NULL) {
                    xpc_release(state->conn);
                    state->conn = NULL;
                }
                free(state);
            } else if (type == XPC_TYPE_DICTIONARY) {
                // If the callback returns false, that means that we're done.
                if (state->callback != NULL) {
                    if (!state->callback(state->conn, request)) {
                        INFO("ioloop_xpc_accept event handler: callback indicated done.");
                        xpc_connection_cancel(state->conn);
                        state->callback = NULL;
                    } else {
                        INFO("ioloop_xpc_accept event handler: continuing.");
                    }
                }
            } else {
                INFO("ioloop_xpc_accept event handler: client went away.");
                // Passing a null request to the callback means the client went away.
                xpc_connection_cancel(state->conn);
                if (state->callback != NULL) {
                    callback(state->conn, NULL);
                }
                state->callback = NULL;
            }
        });
    xpc_connection_resume(conn);
}    

xpc_connection_t
ioloop_create_xpc_service(const char *name, ioloop_xpc_callback_t callback)
{
    xpc_connection_t listener = xpc_connection_create_mach_service(name, ioloop_main_queue,
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL || xpc_get_type(listener) != XPC_TYPE_CONNECTION) {
        ERROR("ioloop_create_xpc_service: " PUB_S_SRP ": unable to create listener %p", name, listener);
        if (listener != NULL) {
            xpc_release(listener);
        }
        return NULL;
    }

    xpc_connection_set_event_handler(listener, ^(xpc_object_t eventmsg) {
            xpc_type_t type = xpc_get_type(eventmsg);

            if (type == XPC_TYPE_CONNECTION) {
                INFO("ioloop_create_xpc_service: New " PUB_S_SRP " Client %p", name, eventmsg);
                ioloop_xpc_accept((xpc_connection_t)eventmsg, name, callback);
            }
            else if (type == XPC_TYPE_ERROR) // Ideally, we would never hit these cases
            {
                ERROR("ioloop_create_xpc_service: XPCError: " PUB_S_SRP,
                      xpc_dictionary_get_string(eventmsg, XPC_ERROR_KEY_DESCRIPTION));
                callback(NULL, NULL);
            }
            else
            {
                INFO("ioloop_create_xpc_service: Unknown EventMsg type");
            }
        });
    xpc_connection_resume(listener);
    return listener;
}

static void
file_descriptor_finalize(void *context)
{
    io_t *file_descriptor = context;
    if (file_descriptor->ref_count == 0) {
        if (file_descriptor->finalize) {
            file_descriptor->finalize(file_descriptor->context);
        }
        free(file_descriptor);
    }
}

void
ioloop_file_descriptor_retain_(io_t *file_descriptor, const char *file, int line)
{
    (void)file; (void)line;
    RETAIN(file_descriptor);
}

void
ioloop_file_descriptor_release_(io_t *file_descriptor, const char *file, int line)
{
    (void)file; (void)line;
    RELEASE(file_descriptor, file_descriptor_finalize);
}

io_t *
ioloop_file_descriptor_create_(int fd, void *context, finalize_callback_t finalize, const char *file, int line)
{
    io_t *ret;
    ret = calloc(1, sizeof(*ret));
    if (ret) {
        ret->fd = fd;
        ret->context = context;
        ret->finalize = finalize;
        RETAIN(ret);
    }
    return ret;
}

static void
ioloop_read_cancel(void *context)
{
    io_t *io = context;

    if (io->read_source != NULL) {
        dispatch_release(io->read_source);
        io->read_source = NULL;
        // Release the reference count that dispatch was holding.
        RELEASE_HERE(io, file_descriptor_finalize);
    }
}

static void
ioloop_read_event(void *context)
{
    io_t *io = context;

    if (io->read_callback != NULL) {
        io->read_callback(io, io->context);
    }
}

void
ioloop_close(io_t *io)
{
    if (io->read_source != NULL) {
        dispatch_cancel(io->read_source);
    }
    if (io->write_source != NULL) {
        dispatch_cancel(io->write_source);
    }
    io->fd = -1;
}

void
ioloop_add_reader(io_t *NONNULL io, io_callback_t NONNULL callback)
{
    io->read_callback = callback;
    if (io->read_source == NULL) {
        io->read_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, io->fd, 0, ioloop_main_queue);
    }
    if (io->read_source == NULL) {
        ERROR("dispatch_source_create: unable to create read dispatch source.");
        return;
    }
    dispatch_source_set_event_handler_f(io->read_source, ioloop_read_event);
    dispatch_source_set_cancel_handler_f(io->read_source, ioloop_read_cancel);
    dispatch_set_context(io->read_source, io);
    RETAIN_HERE(io); // Dispatch will hold a reference.
    dispatch_resume(io->read_source);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
