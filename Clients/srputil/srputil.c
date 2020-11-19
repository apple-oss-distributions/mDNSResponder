/* srputil.c
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
#include <sys/time.h>
#include <dns_sd.h>
#include <net/if.h>
#include <os/log.h>

#include "srp.h"
#include "advertising_proxy_services.h"

dispatch_queue_t main_queue;

static void
started_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    INFO("started: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
}

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
block_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    INFO("blocked: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after blocking.
    exit(0);
}

static void
unblock_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    INFO("unblocked: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after unblocking.
    exit(0);
}

static void
regenerate_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    INFO("regenerated ula: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    // We don't need to wait around after unblocking.
    exit(0);
}

static void
services_callback(advertising_proxy_conn_ref cref, xpc_object_t response, advertising_proxy_error_type err)
{
    size_t i, num;
    int64_t lease, hours, minutes, seconds;
    INFO("services: cref %p  response %p   err %d.", cref, response, err);
    if (err != kDNSSDAdvertisingProxyStatus_NoError) {
        exit(1);
    }
    xpc_object_t services = xpc_dictionary_get_value(response, "instances");
    if (services == NULL) {
        INFO("Non-error response doesn't contain an instances key");
        exit(1);
    }
    if (xpc_get_type(services) != XPC_TYPE_ARRAY) {
        INFO("Non-error response instances value is not an array");
        exit(1);
    }
    num = xpc_array_get_count(services);
    if (num == 0) {
        INFO("No registered services.");
    }
    for (i = 0; i < num; i++) {
        xpc_object_t dict = xpc_array_get_value(services, i);
        if (dict == NULL || xpc_get_type(dict) != XPC_TYPE_DICTIONARY) {
            INFO("services array[%d] is not a dictionary", i);
            exit(1);
        }
        const char *hostname, *instance_name, *service_type, *port, *address, *regname;
        regname = xpc_dictionary_get_string(dict, "regname");
        hostname = xpc_dictionary_get_string(dict, "hostname");
        instance_name = xpc_dictionary_get_string(dict, "name");
        if (instance_name == NULL) {
            instance_name = "<no instances>";
            service_type = "";
            port = "";
        } else {
            service_type = xpc_dictionary_get_string(dict, "type");
            port = xpc_dictionary_get_string(dict, "port");
        }
        address = xpc_dictionary_get_string(dict, "address");
        lease = xpc_dictionary_get_int64(dict, "lease");
        hours = lease / 3600 / 1000;
        lease -= hours * 3600 * 1000;
        minutes = lease / 60 / 1000;
        lease -= minutes * 60 * 1000;
        seconds = lease / 1000;
        lease -= seconds * 1000;

        printf("\"%s\" \"%s\" %s %s %s %qd:%qd:%qd.%qd \"%s\"\n", regname, instance_name, service_type, port,
               address == NULL ? "" : address, hours, minutes, seconds, lease, hostname);
    }
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
#ifdef NOTYET
    ERROR("        flush -- flush all entries from the SRP proxy (for testing only)");
#endif
}

int
main(int argc, char **argv)
{
    int i;
	bool start_proxy = false;
    bool flush_entries = false;
    bool list_services = false;
    bool block = false;
    bool unblock = false;
    bool regenerate_ula = false;
#ifdef NOTYET
	bool watch = false;
	bool get = false;
#endif

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "start")) {
			start_proxy = true;
		} else if (!strcmp(argv[i], "flush")) {
            flush_entries = true;
		} else if (!strcmp(argv[i], "services")) {
            list_services = true;
		} else if (!strcmp(argv[i], "block")) {
            block = true;
		} else if (!strcmp(argv[i], "unblock")) {
            unblock = true;
		} else if (!strcmp(argv[i], "regenerate-ula")) {
            regenerate_ula = true;
#ifdef NOTYET
		} else if (!strcmp(argv[i], "watch")) {
            ERROR("Watching not implemented yet.");
            exit(1);
		} else if (!strcmp(argv[i], "get")) {
            ERROR("Getting not implemented yet.");
            exit(1);
#endif
        } else {
            usage();
        }
    }

    main_queue = dispatch_get_main_queue();
    dispatch_retain(main_queue);

    // Start the queue, //then// do the work
    dispatch_async(main_queue, ^{
            advertising_proxy_error_type err = kDNSSDAdvertisingProxyStatus_NoError;;
            advertising_proxy_conn_ref cref = NULL;

            if (start_proxy) {
                err = advertising_proxy_enable(&cref, main_queue, started_callback);
            }
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
            if (err != kDNSSDAdvertisingProxyStatus_NoError) {
                exit(1);
            }
        });
    dispatch_main();
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
