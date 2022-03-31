/* srputil.c
 *
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
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
    const char *address;
    char addrbuf[INET6_ADDRSTRLEN];
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

        if (host->num_addresses == 0) {
            address = "<no address>";
        } else {
            address = print_address(&host->addresses[0], addrbuf, sizeof(addrbuf));
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
    }
    // In case there's more than one address...
    for (i = 1; i < host->num_addresses; i++) {
        address = print_address(&host->addresses[i], addrbuf, sizeof(addrbuf));
        printf("\"%s\" additional address %s", host->regname, address);
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
usage(void)
{
    ERROR("srputil start          -- start the SRP MDNS Proxy through launchd");
    ERROR("        services       -- get the list of services currently being advertised");
    ERROR("        block          -- block the SRP listener");
    ERROR("        unblock        -- unblock the SRP listener");
    ERROR("        regenerate-ula -- generate a new ULA and restart the network");
    ERROR("        adv-prefix     -- advertise prefix to thread network");
    ERROR("        get-ula        -- fetch the current ULA prefix configured on the SRP server");
#ifdef NOTYET
    ERROR("        flush -- flush all entries from the SRP proxy (for testing only)");
#endif
}

bool start_proxy = false;
bool flush_entries = false;
bool list_services = false;
bool block = false;
bool unblock = false;
bool regenerate_ula = false;
bool adv_prefix = false;
bool get_ula = false;
bool dso_test = false;
#ifdef NOTYET
bool watch = false;
bool get = false;
#endif

static void
start_activities(void)
{
    advertising_proxy_error_type err = kDNSSDAdvertisingProxyStatus_NoError;;
    advertising_proxy_conn_ref cref = NULL;

    if (err == kDNSSDAdvertisingProxyStatus_NoError && flush_entries) {
        err = advertising_proxy_flush_entries(&cref, main_queue, flushed_callback);
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
    if (err == kDNSSDAdvertisingProxyStatus_NoError && get_ula) {
        err = advertising_proxy_get_ula(&cref, main_queue, ula_callback);
    }
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
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
        } else if (!strcmp(argv[i], "get-ula")) {
            get_ula = true;
            something = true;
#ifdef NOTYET
		} else if (!strcmp(argv[i], "watch")) {
            ERROR("Watching not implemented yet.");
            exit(1);
		} else if (!strcmp(argv[i], "get")) {
            ERROR("Getting not implemented yet.");
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

    start_activities();
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
