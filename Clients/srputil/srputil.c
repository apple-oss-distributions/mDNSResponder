/* srputil.c
 *
 * Copyright (c) 2020-2022 Apple Inc. All rights reserved.
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
 * SRP Advertising Proxy utility program, allows:
 *   start/stop advertising proxy
 *   get/track list of service types
 *   get/track list of services of a particular type
 *   get/track list of hosts
 *   get/track information about a particular host
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <dns_sd.h>
#include <net/if.h>
#include <inttypes.h>

void *main_queue = NULL;

#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "advertising_proxy_services.h"


static void
flushed_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("flushed: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after flushing.
    exit(0);
}

static void
block_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("blocked: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after blocking.
    exit(0);
}

static void
unblock_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("unblocked: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after unblocking.
    exit(0);
}

static void
regenerate_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("regenerated ula: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after unblocking.
    exit(0);
}

static void
prefix_advertise_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("advertise prefix: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after advertising prefix.
    exit(0);
}

static void
add_prefix_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("add prefix: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after advertising prefix.
    exit(0);
}

static void
remove_prefix_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("remove prefix: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after advertising prefix.
    exit(0);
}

static void
stop_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("stopped: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after stopping.
    exit(0);
}

static const char *
print_address(advertising_proxy_host_address_t *address, char *addrbuf, size_t addrbuf_size)
{
    if (address->rrtype == 0) {
        return (char *)address->rdata;
    } else if (address->rrtype == dns_rrtype_a && address->rdlen == 4) {
        inet_ntop(AF_INET, address->rdata, addrbuf, (socklen_t)addrbuf_size);
        return addrbuf;
    } else if (address->rrtype == dns_rrtype_aaaa && address->rdlen == 16) {
        inet_ntop(AF_INET6, address->rdata, addrbuf, (socklen_t)addrbuf_size);
        return addrbuf;
    } else {
        sprintf(addrbuf, "Family-%d", address->rrtype);
        return addrbuf;
    }
}

static void
services_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    int i;
    int64_t lease, hours, minutes, seconds;
    advertising_proxy_host_t *host = result;
    const char *address = "<no address>";
    char *addrbuf = NULL;
    size_t addrbuflen;
    uint64_t ula;

    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        INFO("services: cref %p  response %p   err %d.", cref, result, err);
        exit(1);
    }
    if (result == NULL) {
        INFO("services: cref %p  response %p   err %d.", cref, result, err);
        exit(0);
    }

    if (host->num_instances == 0) {
        i = -1;
    } else {
        i = 0;
    }
    for (; i < host->num_instances; i++) {
        const char *instance_name, *service_type;
        char port[6]; // uint16_t as ascii

        if (i == -1 || host->instances[i].instance_name == NULL) {
            instance_name = "<no instances>";
            service_type = "";
            port[0] = 0;
        } else {
            instance_name = host->instances[i].instance_name;
            service_type = host->instances[i].service_type;
            snprintf(port, sizeof(port), "%u", host->instances[i].port);
        }

        if (host->num_addresses > 0) {
            addrbuflen = host->num_addresses * (INET6_ADDRSTRLEN + 1);
            addrbuf = malloc(addrbuflen);
            if (addrbuf == NULL) {
                address = "<no memory for address buffer>";
            } else {
                char *ap = addrbuf;
                for (int j = 0; j < host->num_addresses; j++) {
                    *ap++ = ' ';
                    address = print_address(&host->addresses[j], ap, addrbuflen - (ap - addrbuf));
                    size_t len = strlen(address);
                    if (address != ap) {
                        if (len + ap + 1 > addrbuf + addrbuflen) {
                            len = addrbuflen - (ap - addrbuf) - 1;
                        }
                        memcpy(ap, address, len + 1); // Includes NUL
                    }
                    ap += len;
                }
                address = addrbuf;
            }
        }
        lease = host->lease_time;
        hours = lease / 3600 / 1000;
        lease -= hours * 3600 * 1000;
        minutes = lease / 60 / 1000;
        lease -= minutes * 60 * 1000;
        seconds = lease / 1000;
        lease -= seconds * 1000;

        // Our implementation of the stable server ID uses the server ULA, so just copy out those 48 bits,
        // which are in network byte order.
        ula = 0;
        for (int j = 1; j < 6; j++) {
            ula = ula << 8 | (((uint8_t *)&host->server_id)[j]);
        }
        printf("\"%s\" \"%s\" %s %s %s %" PRIu64 ":%" PRIu64 ":%" PRIu64 ".%" PRIu64 " \"%s\" %s %" PRIx64 "\n",
               host->regname, instance_name, service_type, port,
               address == NULL ? "" : address, hours, minutes, seconds, lease, host->hostname, host->removed ? "invalid" : "valid",
               ula);
        if (addrbuf != NULL) {
            free(addrbuf);
        }
    }
}

static void
ula_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("get_ula: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        fprintf(stderr, "ULA get failed: %d\n", err);
        exit(1);
    }
    uint64_t ula = *((uint64_t *)result);
    printf("ULA: %" PRIx64 "\n", ula);
    exit(0);
}

static void
disable_srp_replication_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("disable_srp_replication: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after SRP replication disabled.
    exit(0);
}

static void
drop_srpl_connection_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("drop_srpl_connection: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static void
undrop_srpl_connection_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("undrop_srpl_connection: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static void
drop_srpl_advertisement_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("drop_srpl_advertisement: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static void
undrop_srpl_advertisement_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("undrop_srpl_advertisement: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static void
start_dropping_push_connections_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("start_dropping_push_connections: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static void
start_breaking_time_validation_callback(advertising_proxy_conn_ref cref, void *result, advertising_proxy_error_type err)
{
    INFO("start_breaking_time_validation: cref %p  response %p   err %d.", cref, result, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    exit(0);
}

static comm_t *tcp_connection;
bool do_tcp_zero_test = false;
bool do_tcp_fin_length = false;
bool do_tcp_fin_payload = false;

static void
tcp_datagram_callback(comm_t *NONNULL comm, message_t *NONNULL message, void *NULLABLE context)
{
    (void)comm;
    (void)context;
    fprintf(stderr, "tcp datagram received, length %d", message->length);
}

static void
tcp_connect_callback(comm_t *NONNULL connection, void *NULLABLE context)
{
    fprintf(stderr, "tcp connection succeeded...\n");
    uint8_t length[2];
    struct iovec iov[2];
    char databuf[128];
    memset(databuf, 0, sizeof(databuf));
    memset(iov, 0, sizeof(iov));

    (void)context;

    if (do_tcp_zero_test) {
        memset(length, 0, sizeof(length));
        iov[0].iov_len = 2;
        iov[0].iov_base = length;
        ioloop_send_data(connection, NULL, iov, 1);
    } else if (do_tcp_fin_length) {
        memset(length, 0, sizeof(length));
        iov[0].iov_len = 1;
        iov[0].iov_base = &length;
        ioloop_send_final_data(connection, NULL, iov, 1);
    } else if (do_tcp_fin_payload) {
        length[0] = 0;
        length[1] = 255;
        iov[0].iov_len = 2;
        iov[0].iov_base = length;
        iov[1].iov_len = 128;
        iov[1].iov_base = databuf;
        ioloop_send_final_data(connection, NULL, iov, 2);
    }
}

static void
tcp_disconnect_callback(comm_t *NONNULL comm, void *NULLABLE context, int error)
{
    (void)comm;
    (void)context;
    (void)error;
    fprintf(stderr, "tcp remote close.\n");
    exit(0);
}

static int
start_tcp_test(void)
{
    addr_t address;
    memset(&address, 0, sizeof(address));
    address.sa.sa_family = AF_INET;
    address.sin.sin_addr.s_addr = htonl(0x7f000001);
    address.sin.sin_port = htons(53);
#ifndef NOT_HAVE_SA_LEN
    address.sin.sin_len = sizeof(address.sin);
#endif
    tcp_connection = ioloop_connection_create(&address, false, true, false, false, tcp_datagram_callback,
                                              tcp_connect_callback, tcp_disconnect_callback, NULL, NULL);
    if (tcp_connection == NULL) {
        return kDNSSDAdvertisingProxyStatus_NoMemory;
    }
    return kDNSSDAdvertisingProxyStatus_NoError;
}

static void
usage(void)
{
    fprintf(stderr, "srputil start                     -- start the SRP MDNS Proxy through launchd\n");
    fprintf(stderr,
            "        tcp-zero                  -- connect to port 53, send a DNS message that's got a zero-length payload\n");
    fprintf(stderr,
            "        tcp-fin-length            -- connect to port 53, send a DNS message that ends before length is complete\n");
    fprintf(stderr,
            "        tcp-fin-payload           -- connect to port 53, send a DNS message that ends before payload is complete\n");
    fprintf(stderr, "        services                  -- get the list of services currently being advertised\n");
    fprintf(stderr, "        block                     -- block the SRP listener\n");
    fprintf(stderr, "        unblock                   -- unblock the SRP listener\n");
    fprintf(stderr, "        regenerate-ula            -- generate a new ULA and restart the network\n");
    fprintf(stderr, "        adv-prefix                -- advertise prefix to thread network\n");
    fprintf(stderr, "        stop                      -- stop advertising as SRP server\n");
    fprintf(stderr, "        get-ula                   -- fetch the current ULA prefix configured on the SRP server\n");
    fprintf(stderr, "        disable-srpl              -- disable SRP replication\n");
    fprintf(stderr, "        add-prefix <ipv6 prefix>     -- add an OMR prefix\n");
    fprintf(stderr, "        remove-prefix <ipv6 prefix>  -- remove an OMR prefix\n");
    fprintf(stderr, "        drop-srpl-connection      -- drop existing srp replication connections\n");
    fprintf(stderr, "        undrop-srpl-connection    -- restart srp replication connections that were dropped \n");
    fprintf(stderr, "        drop-srpl-advertisement   -- stop advertising srpl service (but keep it around)\n");
    fprintf(stderr, "        undrop-srpl-advertisement -- resume advertising srpl service\n");
    fprintf(stderr, "        start-dropping-push       -- start repeatedly dropping any active push connections after 90 seconds\n");
    fprintf(stderr, "        start-breaking-time       -- start breaking time validation on replicated SRP registrations\n");
#ifdef NOTYET
    fprintf(stderr, "        flush                     -- flush all entries from the SRP proxy (for testing only)\n");
#endif
}

bool start_proxy = false;
bool flush_entries = false;
bool list_services = false;
bool block = false;
bool unblock = false;
bool regenerate_ula = false;
bool adv_prefix = false;
bool stop_proxy = false;
bool dump_stdin = false;
bool get_ula = false;
bool disable_srp_replication = false;
bool dso_test = false;
bool drop_srpl_connection;
bool undrop_srpl_connection;
bool drop_srpl_advertisement;
bool undrop_srpl_advertisement;
bool start_dropping_push_connections;
bool add_thread_prefix = false;
bool remove_thread_prefix = false;
bool start_breaking_time_validation = false;
uint8_t prefix_buf[16];
#ifdef NOTYET
bool watch = false;
bool get = false;
#endif

static void
start_activities(void *context)
{
    advertising_proxy_error_type err = kDNSSDAdvertisingProxyStatus_NoError;;
    advertising_proxy_conn_ref cref = NULL;
    (void)context;

    if (err == kDNSSDAdvertisingProxyStatus_NoError && flush_entries) {
        err = advertising_proxy_flush_entries(&cref, main_queue, flushed_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && (do_tcp_zero_test ||
                                                        do_tcp_fin_length || do_tcp_fin_payload)) {
        err = start_tcp_test();
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && list_services) {
        err = advertising_proxy_get_service_list(&cref, main_queue, services_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && block) {
        err = advertising_proxy_block_service(&cref, main_queue, block_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && unblock) {
        err = advertising_proxy_unblock_service(&cref, main_queue, unblock_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && regenerate_ula) {
        err = advertising_proxy_regenerate_ula(&cref, main_queue, regenerate_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && adv_prefix) {
        err = advertising_proxy_advertise_prefix(&cref, main_queue, prefix_advertise_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && stop_proxy) {
        err = advertising_proxy_stop(&cref, main_queue, stop_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && get_ula) {
        err = advertising_proxy_get_ula(&cref, main_queue, ula_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && disable_srp_replication) {
        err = advertising_proxy_disable_srp_replication(&cref, main_queue, disable_srp_replication_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && add_thread_prefix) {
        err = advertising_proxy_add_prefix(&cref, main_queue, add_prefix_callback, prefix_buf, sizeof(prefix_buf));
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && remove_thread_prefix) {
        err = advertising_proxy_remove_prefix(&cref, main_queue, remove_prefix_callback, prefix_buf, sizeof(prefix_buf));
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && drop_srpl_connection) {
        err = advertising_proxy_drop_srpl_connection(&cref, main_queue, drop_srpl_connection_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && undrop_srpl_connection) {
        err = advertising_proxy_undrop_srpl_connection(&cref, main_queue, undrop_srpl_connection_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && drop_srpl_advertisement) {
        err = advertising_proxy_drop_srpl_advertisement(&cref, main_queue, drop_srpl_advertisement_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && undrop_srpl_advertisement) {
        err = advertising_proxy_undrop_srpl_advertisement(&cref, main_queue, undrop_srpl_advertisement_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && start_dropping_push_connections) {
        err = advertising_proxy_start_dropping_push_connections(&cref, main_queue, start_dropping_push_connections_callback);
    }
    if (err == kDNSSDAdvertisingProxyStatus_NoError && start_breaking_time_validation) {
        err = advertising_proxy_start_breaking_time_validation(&cref, main_queue, start_breaking_time_validation_callback);
    }
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
}

static void
dump_packet(void)
{
    ssize_t len;
    dns_message_t *message = NULL;
    dns_wire_t wire;

    len = read(0, &wire, sizeof(wire));
    if (len < 0) {
        ERROR("stdin: %s", strerror(errno));
        return;
    }
    if (len < DNS_HEADER_SIZE) {
        ERROR("stdin: too short: %zd bytes", len);
        return;
    }
    if (!dns_wire_parse(&message, &wire, (unsigned)len, true)) {
        fprintf(stderr, "DNS message parse failed\n");
        return;
    }
}

int
main(int argc, char **argv)
{
    int i;
    bool something = false;
    bool log_stderr = false;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "start")) {
			start_proxy = true;
            something = true;
        } else if (!strcmp(argv[i], "tcp-zero")) {
            do_tcp_zero_test = true;
            something = true;
        } else if (!strcmp(argv[i], "tcp-fin-length")) {
            do_tcp_fin_length = true;
            something = true;
        } else if (!strcmp(argv[i], "tcp-fin-payload")) {
            do_tcp_fin_payload = true;
            something = true;
		} else if (!strcmp(argv[i], "flush")) {
            flush_entries = true;
            something = true;
		} else if (!strcmp(argv[i], "services")) {
            list_services = true;
            something = true;
		} else if (!strcmp(argv[i], "block")) {
            block = true;
            something = true;
		} else if (!strcmp(argv[i], "unblock")) {
            unblock = true;
            something = true;
		} else if (!strcmp(argv[i], "regenerate-ula")) {
            regenerate_ula = true;
            something = true;
        } else if (!strcmp(argv[i], "adv-prefix")) {
            adv_prefix = true;
            something = true;
        } else if (!strcmp(argv[i], "stop")) {
            stop_proxy = true;
            something = true;
        } else if (!strcmp(argv[i], "dump")) {
            dump_packet();
            exit(0);
        } else if (!strcmp(argv[i], "get-ula")) {
            get_ula = true;
            something = true;
        } else if (!strcmp(argv[i], "disable-srpl")) {
            disable_srp_replication = true;
            something = true;
        } else if (!strcmp(argv[i], "add-prefix")) {
            if (inet_pton(AF_INET6, argv[i + 1], prefix_buf) < 1) {
                fprintf(stderr, "Wrong ipv6 prefix.\n");
            } else {
                add_thread_prefix = true;
                something = true;
                i++;
            }
        } else if (!strcmp(argv[i], "remove-prefix")) {
            if (inet_pton(AF_INET6, argv[i + 1], prefix_buf) < 1) {
                fprintf(stderr, "Wrong ipv6 prefix.\n");
            } else {
                remove_thread_prefix = true;
                something = true;
                i++;
            }
        } else if (!strcmp(argv[i], "drop-srpl-connection")) {
            drop_srpl_connection = true;
            something = true;
        } else if (!strcmp(argv[i], "undrop-srpl-connection")) {
            undrop_srpl_connection = true;
            something = true;
        } else if (!strcmp(argv[i], "drop-srpl-advertisement")) {
            drop_srpl_advertisement = true;
            something = true;
        } else if (!strcmp(argv[i], "undrop-srpl-advertisement")) {
            undrop_srpl_advertisement = true;
            something = true;
        } else if (!strcmp(argv[i], "start-dropping-push")) {
            start_dropping_push_connections = true;
            something = true;
        } else if (!strcmp(argv[i], "start-breaking-time")) {
            start_breaking_time_validation = true;
            something = true;
#ifdef NOTYET
		} else if (!strcmp(argv[i], "watch")) {
            fprintf(stderr, "Watching not implemented yet.\n");
            exit(1);
		} else if (!strcmp(argv[i], "get")) {
            fprintf(stderr, "Getting not implemented yet.\n");
            exit(1);
#endif
        } else if (!strcmp(argv[i], "--debug")) {
            OPENLOG("srputil", true);
            log_stderr = true;
        } else {
            usage();
            exit(1);
        }
    }

    if (!something) {
        usage();
        exit(1);
    }

    if (log_stderr == false) {
        OPENLOG("srputil", log_stderr);
    }

    ioloop_init();
    // Start the queue, //then// do the work
    ioloop_run_async(start_activities, NULL);
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
