/* srp-ioloop.c
 *
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
 * srp host API implementation for Posix using ioloop primitives.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dns_sd.h>
#include <errno.h>
#include <fcntl.h>

#include "srp.h"
#include "srp-api.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"

#include "cti-services.h"
#if !defined(OPEN_SOURCE) && defined(TARGET_OS_TV)
#define LIVE_TRANSACTION_CLEANUP 1
#include "advertising_proxy_services.h"
#endif

static int lease_time = 0;
static bool random_leases = false;
static bool delete_registrations = false;
static bool use_thread_services = false;
#ifdef LIVE_TRANSACTION_CLEANUP
static bool live_transaction_cleanup = false;
static int live_transaction_cleanup_time;
static wakeup_t *live_transaction_wakeup;
static advertising_proxy_conn_ref live_transaction_cref;
#endif
static int num_clients = 1;
static int bogusify_signatures = false;

const uint64_t thread_enterprise_number = 52627;

cti_connection_t thread_service_context;

#define SRP_IO_CONTEXT_MAGIC 0xFEEDFACEFADEBEEFULL  // BEES!   Everybody gets BEES!
typedef struct io_context {
    uint64_t magic_cookie1;
    wakeup_t *wakeup;
    void *NONNULL srp_context;
    comm_t *NULLABLE connection;
    srp_wakeup_callback_t wakeup_callback;
    srp_datagram_callback_t datagram_callback;
    uint64_t magic_cookie2;
} io_context_t;
wakeup_t *remove_wakeup;

typedef struct srp_client {
    DNSServiceRef sdref;
    int index;
    wakeup_t *wakeup;
    char *name;
} srp_client_t;

static int
validate_io_context(io_context_t **dest, void *src)
{
    io_context_t *context = src;
    if (context->magic_cookie1 == SRP_IO_CONTEXT_MAGIC &&
        context->magic_cookie2 == SRP_IO_CONTEXT_MAGIC)
   {
        *dest = context;
        return kDNSServiceErr_NoError;
    }
    return kDNSServiceErr_BadState;
}

static void
datagram_callback(comm_t *connection, message_t *message, void *context)
{
    (void)connection;
    io_context_t *io_context = context;
    io_context->datagram_callback(io_context->srp_context,
                                  &message->wire, message->length);
}

static void
wakeup_callback(void *context)
{
    io_context_t *io_context;
    if (validate_io_context(&io_context, context) == kDNSServiceErr_NoError) {
        INFO("wakeup on context %p srp_context %p", io_context, io_context->srp_context);
        io_context->wakeup_callback(io_context->srp_context);
    } else {
        INFO("wakeup with invalid context: %p", context);
    }
}

int
srp_deactivate_udp_context(void *host_context, void *in_context)
{
    io_context_t *io_context;
    int err;
    (void)host_context;

    err = validate_io_context(&io_context, in_context);
    if (err == kDNSServiceErr_NoError) {
        if (io_context->connection) {
            ioloop_comm_release(io_context->connection);
        }
        free(io_context);
    }
    return err;
}

int
srp_disconnect_udp(void *context)
{
    io_context_t *io_context;
    int err;

    err = validate_io_context(&io_context, context);
    if (err == kDNSServiceErr_NoError) {
        if (io_context->connection) {
            ioloop_comm_cancel(io_context->connection);
            ioloop_comm_release(io_context->connection);
            io_context->connection = NULL;
        }
    }
    return err;
}

int
srp_connect_udp(void *context, const uint8_t *port, uint16_t address_type, const uint8_t *address, uint16_t addrlen)
{
    io_context_t *io_context;
    addr_t remote;
    int err;

    err = validate_io_context(&io_context, context);
    if (err == kDNSServiceErr_NoError) {
        if (io_context->connection) {
            ERROR("srp_connect_udp called with non-null I/O context.");
            return kDNSServiceErr_Invalid;
        }

        if (address_type == dns_rrtype_a) {
            if (addrlen != 4) {
                return kDNSServiceErr_Invalid;
            }
            remote.sa.sa_family = AF_INET;
            memcpy(&remote.sin.sin_addr, address, addrlen);
#ifndef NOT_HAVE_SA_LEN
            remote.sa.sa_len = sizeof remote.sin;
#endif
            memcpy(&remote.sin.sin_port, port, 2);
        } else {
            if (addrlen != 16) {
                return kDNSServiceErr_Invalid;
            }
            remote.sa.sa_family = AF_INET6;
            memcpy(&remote.sin6.sin6_addr, address, addrlen);
#ifndef NOT_HAVE_SA_LEN
            remote.sa.sa_len = sizeof remote.sin;
#endif
            memcpy(&remote.sin6.sin6_port, port, 2);
        }

        io_context->connection = ioloop_connection_create(&remote, false, false, datagram_callback,
                                                          NULL, NULL, NULL, io_context);
        if (io_context->connection == NULL) {
            return kDNSServiceErr_NoMemory;
        }
    }
    return err;
}

int
srp_make_udp_context(void *host_context, void **p_context, srp_datagram_callback_t callback, void *context)
{
    (void)host_context;

    io_context_t *io_context = calloc(1, sizeof *io_context);
    if (io_context == NULL) {
        return kDNSServiceErr_NoMemory;
    }
    io_context->magic_cookie1 = io_context->magic_cookie2 = SRP_IO_CONTEXT_MAGIC;
    io_context->datagram_callback = callback;
    io_context->srp_context = context;

    io_context->wakeup = ioloop_wakeup_create();
    if (io_context->wakeup == NULL) {
        free(io_context);
        return kDNSServiceErr_NoMemory;
    }

    *p_context = io_context;
    return kDNSServiceErr_NoError;
}

int
srp_set_wakeup(void *host_context, void *context, int milliseconds, srp_wakeup_callback_t callback)
{
    int err;
    io_context_t *io_context;
    (void)host_context;

    err = validate_io_context(&io_context, context);
    if (err == kDNSServiceErr_NoError) {
        io_context->wakeup_callback = callback;
        INFO("srp_set_wakeup on context %p, srp_context %p", io_context, io_context->srp_context);
        ioloop_add_wake_event(io_context->wakeup, io_context, wakeup_callback, NULL, milliseconds);
    }
    return err;
}

int
srp_cancel_wakeup(void *host_context, void *context)
{
    int err;
    io_context_t *io_context;
    (void)host_context;

    err = validate_io_context(&io_context, context);
    if (err == kDNSServiceErr_NoError) {
        ioloop_cancel_wake_event(io_context->wakeup);
    }
    return err;
}

int
srp_send_datagram(void *host_context, void *context, void *message, size_t message_length)
{
    int err;
    struct iovec iov;
    io_context_t *io_context;
    (void)host_context;

    memset(&iov, 0, sizeof iov);
    iov.iov_base = message;
    iov.iov_len = message_length;

    if (bogusify_signatures) {
        ((uint8_t *)message)[message_length - 10] = ~(((uint8_t *)message)[message_length - 10]);
    }

    err = validate_io_context(&io_context, context);
    if (err == kDNSServiceErr_NoError) {
        if (!ioloop_send_message(io_context->connection, message, &iov, 1)) {
            return kDNSServiceErr_Unknown;
        }
    }
    return err;
}

static bool
srp_load_file_data(void *host_context, const char *filename, uint8_t *buffer, uint16_t *length, uint16_t buffer_size)
{
    off_t flen;
    ssize_t len;
    int file;
    (void)host_context;

    file = open(filename, O_RDONLY);
    if (file < 0) {
        ERROR("srp_load_file_data: %s: open: %s", filename, strerror(errno));
        return false;
    }

    // Get the length of the file.
    flen = lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    if (flen > buffer_size) {
        ERROR("srp_load_file_data: %s: lseek: %s", filename, strerror(errno));
        close(file);
        return false;
    }
    len = read(file, buffer, flen);
    if (len < 0 || len != flen) {
        if (len < 0) {
            ERROR("srp_load_file_data: %s: read: %s", filename, strerror(errno));
        } else {
            ERROR("srp_load_file_data: %s: short read %d out of %d", filename, (int)len, (int)flen);
        }
        close(file);
        return false;
    }
    close(file);
    *length = (uint16_t)len;
    return true;
}

static bool
srp_store_file_data(void *host_context, const char *filename, uint8_t *buffer, uint16_t length)
{
    ssize_t len;
    int file;
    (void)host_context;
    file = open(filename, O_WRONLY | O_CREAT, 0600);
    if (file < 0) {
        ERROR("srp_store_file_data: %s: %s", filename, strerror(errno));
        return false;
   }
    len = write(file, buffer, length);
    if (len < 0 || len != length) {
        if (len < 0) {
            ERROR("srp_store_file_data: " PUB_S_SRP ": " PUB_S_SRP, filename, strerror(errno));
        } else {
            ERROR("srp_store_file_data: short write %d out of %d on file %s", (int)len, (int)length, filename);
        }
        unlink(filename);
        close(file);
        return kDNSServiceErr_Unknown;
    }
    close(file);
    return kDNSServiceErr_NoError;
}


bool
srp_get_last_server(uint16_t *NONNULL rrtype, uint8_t *NONNULL rdata, uint16_t rdlim,
                    uint8_t *NONNULL port, void *NULLABLE host_context)
{
    uint8_t buffer[22];
    unsigned offset = 0;
    uint16_t length;
    uint16_t rdlength;

    if (!srp_load_file_data(host_context, "/var/run/srp-last-server", buffer, &length, sizeof(buffer))) {
        return false;
    }
    if (length < 10) { // rrtype + rdlength + ipv4 address + port
        ERROR("srp_get_last_server: stored server data is too short: %d", length);
        return false;
    }
    *rrtype = (((uint16_t)buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    rdlength = (((uint16_t)buffer[offset]) << 8) | buffer[offset + 1];
    offset += 2;
    if ((*rrtype == dns_rrtype_a && rdlength != 4) || (*rrtype == dns_rrtype_aaaa && rdlength != 16)) {
        ERROR("srp_get_last_server: invalid rdlength %d for %s record",
              rdlength, *rrtype == dns_rrtype_a ? "A" : "AAAA");
        return false;
    }
    if (length < rdlength + 6) { // rrtype + rdlength + address + port
        ERROR("srp_get_last_server: stored server data length %d is too short", length);
        return false;
    }
    if (rdlength > rdlim) {
        ERROR("srp_get_last_server: no space for %s data in provided buffer size %d",
              *rrtype == dns_rrtype_a ? "A" : "AAAA", rdlim);
        return false;
    }
    memcpy(rdata, &buffer[offset], rdlength);
    offset += rdlength;
    memcpy(port, &buffer[offset], 2);
    return true;
}

bool
srp_save_last_server(uint16_t rrtype, uint8_t *NONNULL rdata, uint16_t rdlength,
                     uint8_t *NONNULL port, void *NULLABLE host_context)
{
    dns_towire_state_t towire;
    uint8_t buffer[24];
    size_t length;
    memset(&towire, 0, sizeof(towire));
    towire.p = buffer;
    towire.lim = towire.p + sizeof(buffer);

    if (rdlength != 4 && rdlength != 16) {
        ERROR("srp_save_last_server: invalid IP address length %d", rdlength);
        return false;
    }
    dns_u16_to_wire(&towire, rrtype);
    dns_u16_to_wire(&towire, rdlength);
    dns_rdata_raw_data_to_wire(&towire, rdata, rdlength);
    dns_rdata_raw_data_to_wire(&towire, port, 2);

    if (towire.error) {
        ERROR("srp_save_last_server: " PUB_S_SRP " at %d (%p:%p:%p) while constructing output buffer",
              strerror(towire.error), towire.line, towire.p, towire.lim, buffer);
        return false;
    }

    length = towire.p - buffer;
    if (!srp_store_file_data(host_context, "/var/run/srp-last-server", buffer, length)) {
        return false;
    }
    return true;
}

#ifdef NO_KEYCHAIN
int
srp_load_key_data(void *host_context, const char *key_name, uint8_t *buffer, uint16_t *length, uint16_t buffer_size)
{
    if (srp_load_file_data(key_name, buffer, length, buffer_size)) {
        return kDNSServiceErr_NoError;
    }
    return kDNSServiceErr_Unknown;
}

int
srp_store_key_data(void *host_context, const char *key_name, uint8_t *buffer, uint16_t length)
{
    if (!srp_store_file_data(host_context, key_name, buffer, length)) {
        return kDNSServiceErr_Unknown;
    return kDNSServiceErr_NoError;
}
#endif // NO_KEYCHAIN

static void
interface_callback(void *context, const char *NONNULL name,
                   const addr_t *NONNULL address, const addr_t *NONNULL netmask,
                   uint32_t flags, enum interface_address_change event_type)
{
    bool drop = false;
    uint8_t *rdata;
    uint16_t rdlen;
    uint16_t rrtype;
    cti_service_vec_t *cti_services = context;

    (void)netmask;
    (void)index;
    (void)event_type;

    if (address->sa.sa_family == AF_INET) {
        rrtype = dns_rrtype_a;
        rdata = (uint8_t *)&address->sin.sin_addr;
        rdlen = 4;

        // Should use IN_LINKLOCAL and IN_LOOPBACK macros here, but for some reason they are not present on
        // OpenWRT.
        if (rdata[0] == 127) {
            drop = true;
        } else if (rdata[0] == 169 && rdata[1] == 254) {
            drop = true;
        }
    } else if (address->sa.sa_family == AF_INET6) {
        rrtype = dns_rrtype_aaaa;
        rdata = (uint8_t *)&address->sin6.sin6_addr;
        rdlen = 16;
        if (IN6_IS_ADDR_LOOPBACK(&address->sin6.sin6_addr)) {
            drop = true;
        } else if (IN6_IS_ADDR_LINKLOCAL(&address->sin6.sin6_addr)) {
            drop = true;
        }
    } else {
        return;
    }
    if (drop) {
        if (address->sa.sa_family == AF_INET) {
            IPv4_ADDR_GEN_SRP(rdata, ipv4_rdata_buf);
            DEBUG("interface_callback: ignoring " PUB_S_SRP " " PRI_IPv4_ADDR_SRP, name,
                  IPv4_ADDR_PARAM_SRP(rdata, ipv4_rdata_buf));
        } else if (address->sa.sa_family == AF_INET6) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, ipv6_rdata_buf);
            DEBUG("interface_callback: ignoring " PUB_S_SRP " " PRI_SEGMENTED_IPv6_ADDR_SRP, name,
                  SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, ipv6_rdata_buf));
        } else {
            INFO("interface_callback: ignoring with non-v4/v6 address" PUB_S_SRP, name);
        }
        return;
    }

    if (address->sa.sa_family == AF_INET) {
        IPv4_ADDR_GEN_SRP(rdata, ipv4_rdata_buf);
        DEBUG("interface_callback: " PUB_S_SRP " " PRI_IPv4_ADDR_SRP " %x", name,
              IPv4_ADDR_PARAM_SRP(rdata, ipv4_rdata_buf), flags);
    } else if (address->sa.sa_family == AF_INET6) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, ipv6_rdata_buf);
        DEBUG("interface_callback: " PUB_S_SRP " " PRI_SEGMENTED_IPv6_ADDR_SRP " %x", name,
              SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, ipv6_rdata_buf), flags);
    } else {
        DEBUG("interface_callback: " PUB_S_SRP "<none IPv4/IPv6 address> %x", name, flags);
    }

    // This is a workaround for a bug in the utun0 code, where packets sent to the IP address of the local
    // thread interface are dropped and do not reach the SRP server. To address this, if we find a service
    // that is on a local IPv6 address, we replace the address with ::1.
    if (cti_services != NULL && rrtype == dns_rrtype_aaaa) {
        size_t i;
        for (i = 0; i < cti_services->num; i++) {
            cti_service_t *cti_service = cti_services->services[i];
            // Look for SRP service advertisements only.
            if (IS_SRP_SERVICE(cti_service)) {
                // Local IP address?
                if (!memcmp(cti_service->server, rdata, 16)) {
                    // ::
                    memset(cti_service->server, 0, 15);
                    // 1
                    cti_service->server[15] = 1;
                }
            }
        }
    }

    srp_add_interface_address(rrtype, rdata, rdlen);
}

static void
remove_callback(void *context)
{
    srp_client_t *client = context;
    srp_deregister(client);
}

static void
register_callback(DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode,
                  const char *name, const char *regtype, const char *domain, void *context)
{
    srp_client_t *client = context;

    (void)sdRef;
    (void)regtype;
    (void)flags;
    (void)name;
    (void)regtype;
    (void)domain;
    INFO("Register Reply for %s: %d", client->name, errorCode);

    if (errorCode == kDNSServiceErr_NoError && delete_registrations) {
        client->wakeup = ioloop_wakeup_create();
        if (client->wakeup == NULL) {
            ERROR("Unable to allocate a wakeup for %s.", client->name);
            exit(1);
        }

        // Do a remove in five seconds.
        ioloop_add_wake_event(client->wakeup, client, remove_callback, NULL, 5000);
    }
}

static void
usage(void)
{
    fprintf(stderr,
            "srp-client [--lease-time <seconds>] [--client-count <client count>] [--server <address>%%<port>]\n"
#ifdef LIVE_TRANSACTION_CLEANUP
            "           [--live-transaction-cleanup <milliseconds>]\n"
#endif
            "           [--random-leases] [--delete-registrations] [--use-thread-services] [--bogusify-signatures]\n");
    exit(1);
}

#ifdef LIVE_TRANSACTION_CLEANUP
static void
flushed_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    INFO("flushed: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after flushing.
    exit(0);
}

static void
live_transaction_wakeup_callback(void *__unused context)
{
    int err = advertising_proxy_flush_entries(&live_transaction_cref, dispatch_get_main_queue(), flushed_callback);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        ERROR("live_transaction_wakeup_callback: advertising_proxy_flush_entries failed: %d", err);
    }
}

// This is a test to see if, if we have an update pending, we can safely remove all hosts without there being a
// problem.
static void
maybe_schedule_live_transaction_cleanup(void)
{
    if (live_transaction_cleanup) {
        live_transaction_wakeup = ioloop_wakeup_create();
        if (live_transaction_wakeup == NULL) {
            ERROR("maybe_schedule_live_transaction_cleanup: unable to allocate wakeup!");
            exit(1);
        }
        // Schedule the wakeup for 100ms in the future.
        ioloop_add_wake_event(live_transaction_wakeup, NULL, live_transaction_wakeup_callback, NULL, live_transaction_cleanup_time);
    }
}
#endif

static void
cti_service_list_callback(void *__unused context, cti_service_vec_t *services, cti_status_t status)
{
    size_t i;

    if (status == kCTIStatus_Disconnected || status == kCTIStatus_DaemonNotRunning) {
        INFO("cti_get_service_list_callback: disconnected");
        exit(1);
    }

    srp_start_address_refresh();
    ioloop_map_interface_addresses(services, interface_callback);
    for (i = 0; i < services->num; i++) {
        cti_service_t *cti_service = services->services[i];
        // Look for SRP service advertisements only.
        if (IS_SRP_SERVICE(cti_service)) {
            srp_add_server_address(&cti_service->server[16], dns_rrtype_aaaa, cti_service->server, 16);
        }
    }
    srp_finish_address_refresh();
    srp_network_state_stable();
#ifdef LIVE_TRANSACTION_CLEANUP
    maybe_schedule_live_transaction_cleanup();
#endif
}

int
main(int argc, char **argv)
{

    uint8_t server_address[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    uint8_t bogus_address[16] = { 0xfc,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        // { 0x26, 0x20, 0x01, 0x49, 0x00, 0x0f, 0x1a, 0x4d, 0x04, 0xff, 0x61, 0x5a, 0xa2, 0x2a, 0xab, 0xe8 };
    uint8_t port[2];
    uint16_t iport;
    int err;
    DNSServiceRef sdref;
    int *nump;
    char *end;
    (void)argc;
    (void)argv;
    int i;
    bool have_server_address = false;

    ioloop_init();

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--lease-time")) {
            nump = &lease_time;
        number:
            if (i + 1 == argc) {
                usage();
            }
            *nump = (uint32_t)strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || end[0] != 0) {
                usage();
            }
            i++;
        } else if (!strcmp(argv[i], "--client-count")) {
            nump = &num_clients;
            goto number;
        } else if (!strcmp(argv[i], "--server")) {
            char *percent;
            int server_port;
            uint8_t addrbuf[16];
            uint16_t addrtype = dns_rrtype_aaaa;
            int addrlen = 16;

            if (i + 1 == argc) {
                usage();
           }
            percent = strchr(argv[i + 1], '%');
            if (percent == NULL || percent[1] == 0) {
                usage();
            }
            *percent = 0;
            percent++;

            server_port = (uint32_t)strtoul(percent, &end, 10);
            if (end == percent || end[0] != 0) {
                usage();
            }
            port[0] = server_port >> 8;
            port[1] = server_port & 255;

            if (inet_pton(AF_INET6, argv[i + 1], addrbuf) < 1) {
                if (inet_pton(AF_INET, argv[i + 1], addrbuf) < 1) {
                    usage();
                } else {
                    addrtype = dns_rrtype_a;
                    addrlen = 4;
                }
            }
            srp_add_server_address(port, addrtype, addrbuf, addrlen);
            have_server_address = true;
            i++;
        } else if (!strcmp(argv[i], "--random-leases")) {
            random_leases = true;
        } else if (!strcmp(argv[i], "--delete-registrations")) {
            delete_registrations = true;
        } else if (!strcmp(argv[i], "--use-thread-services")) {
            use_thread_services = true;
        } else if (!strcmp(argv[i], "--bogusify-signatures")) {
            bogusify_signatures = true;
#ifdef LIVE_TRANSACTION_CLEANUP
        } else if (!strcmp(argv[i], "--live-transaction-cleanup")) {
            nump = &live_transaction_cleanup_time;
            live_transaction_cleanup = true;
            goto number;
#endif
        } else {
            usage();
        }
    }

    if (!use_thread_services) {
        ioloop_map_interface_addresses(NULL, interface_callback);
    }

    if (!have_server_address && !use_thread_services) {
        port[0] = 0;
        port[1] = 53;
        srp_add_server_address(port, dns_rrtype_aaaa, bogus_address, 16);
        srp_add_server_address(port, dns_rrtype_aaaa, server_address, 16);
    }

    for (i = 0; i < num_clients; i++) {
        srp_client_t *client;
        char hnbuf[128];

        client = calloc(1, sizeof(*client));
        if (client == NULL) {
            ERROR("no memory for client %d", i);
            exit(1);
        }

        if (num_clients == 1) {
            strcpy(hnbuf, "srp-api-test");
        } else {
            snprintf(hnbuf, sizeof(hnbuf), "srp-api-test-%d", i);
        }
        client->name = strdup(hnbuf);
        if (client->name == NULL) {
            ERROR("No memory for client name %s", hnbuf);
            exit(1);
        }
        client->index = i;

        srp_host_init(client);
        srp_set_hostname(hnbuf, NULL);

        if (random_leases) {
            int random_lease_time = 30 + srp_random16() % 1800; // random
            INFO("Client %d, lease time = %d", i, random_lease_time);
            srp_set_lease_times(random_lease_time, 7 * 24 * 3600); // random host lease, 7 day key lease
        } else if (lease_time > 0) {
            srp_set_lease_times(lease_time, 7 * 24 * 3600); // specified host lease, 7 day key lease
        }

        memcpy(&iport, port, 2);
        err = DNSServiceRegister(&sdref, 0, 0, hnbuf, "_ipps._tcp",
                                 NULL, NULL, iport, 0, NULL, register_callback, client);
        if (err != kDNSServiceErr_NoError) {
            ERROR("DNSServiceRegister failed: %d", err);
            exit(1);
        }
    }

    if (use_thread_services) {
        cti_get_service_list(&thread_service_context, NULL, cti_service_list_callback, dispatch_get_main_queue());
    } else {
        srp_network_state_stable();
#ifdef LIVE_TRANSACTION_CLEANUP
        maybe_schedule_live_transaction_cleanup();
#endif
    }
    ioloop();
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
