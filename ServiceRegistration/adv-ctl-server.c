/* adv-ctl-proxy.c
 *
 * Copyright (c) 2019-2022 Apple Inc. All rights reserved.
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
 * This file contains the SRP Advertising Proxy control interface, which allows clients to control the advertising proxy
 * and discover information about its internal state. This is largely used for testing.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <dns_sd.h>
#include <net/if.h>
#include <inttypes.h>
#include <sys/resource.h>

#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "srp-gw.h"
#include "route.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "adv-ctl-server.h"

#include "cti-proto.h"
#include "adv-ctl-common.h"
#include "advertising_proxy_services.h"


static int
adv_ctl_block_service(bool enable)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
#if THREAD_BORDER_ROUTER
    extern srp_proxy_listener_state_t *srp_listener;

    if (enable) {
        if (srp_listener != NULL) {
            srp_proxy_listener_cancel(srp_listener);
            srp_listener = NULL;
        } else {
            status = kDNSSDAdvertisingProxyStatus_UnknownErr;
        }
    } else {
        if (srp_listener == NULL) {
            partition_start_srp_listener();
        } else {
            status = kDNSSDAdvertisingProxyStatus_UnknownErr;
        }
    }
#else
    (void)enable;
#endif // THREAD_BORDER_ROUTER
    return status;
}

static bool
adv_ctl_regenerate_ula(void)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if THREAD_BORDER_ROUTER
    partition_stop_advertising_pref_id();
    infrastructure_network_shutdown();
    route_ula_generate();
    infrastructure_network_startup();
#endif
    return status;
}

static int
adv_ctl_advertise_prefix(void)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if THREAD_BORDER_ROUTER
    partition_publish_my_prefix();
#endif
    return status;
}



static void
adv_ctl_fd_finalize(void *context)
{
    advertising_proxy_conn_ref connection = context;
    connection->io_context = NULL;
    RELEASE_HERE(connection, cti_connection_finalize);
}

static bool
adv_ctl_list_services(advertising_proxy_conn_ref connection)
{
    adv_host_t *host;
    int i;
    int64_t now = ioloop_timenow();
	int num_hosts = 0;

	for (host = hosts; host != NULL; host = host->next) {
		num_hosts++;
	}
	if (!cti_connection_message_create(connection, kDNSSDAdvertisingProxyResponse, 200) ||
		!cti_connection_u32_put(connection, (uint32_t)kDNSSDAdvertisingProxyStatus_NoError) ||
		!cti_connection_u32_put(connection, num_hosts))
	{
		ERROR("adv_ctl_list_services: error starting response");
		cti_connection_close(connection);
		return false;
	}
	for (host = hosts; host != NULL; host = host->next) {
		int num_addresses = 0;
		int num_instances = 0;
		if (!cti_connection_string_put(connection, host->name) ||
			!cti_connection_string_put(connection, host->registered_name) ||
			!cti_connection_u32_put(connection, host->lease_expiry >= now ? host->lease_expiry - now : 0) ||
			!cti_connection_bool_put(connection, host->removed) ||
			!cti_connection_u64_put(connection, host->update_server_id))
		{
			ERROR("adv_ctl_list_services: unable to write host info for host %s", host->name);
			cti_connection_close(connection);
			return false;
		}

        cti_connection_u64_put(connection, host->server_stable_id);

		for (i = 0; i < host->num_addresses; i++) {
			if (host->addresses[i] != NULL) {
				num_addresses++;
			}
		}
		cti_connection_u16_put(connection, num_addresses);
		for (i = 0; i < host->num_addresses; i++) {
			if (host->addresses[i] != NULL) {
				if (!cti_connection_u16_put(connection, host->addresses[i]->rrtype) ||
					!cti_connection_data_put(connection, host->addresses[i]->rdata, host->addresses[i]->rdlen))
				{
					ERROR("adv_ctl_list_services: unable to write address %d for host %s", i, host->name);
					cti_connection_close(connection);
					return false;
				}
			}
		}
		for (i = 0; i < host->instances->num; i++) {
			if (host->instances->vec[i] != NULL) {
				num_instances++;
			}
		}
		cti_connection_u16_put(connection, num_instances);
		for (i = 0; i < host->instances->num; i++) {
			adv_instance_t *instance = host->instances->vec[i];
			if (instance != NULL) {
				if (!cti_connection_string_put(connection, instance->instance_name) ||
					!cti_connection_string_put(connection, instance->service_type) ||
					!cti_connection_u16_put(connection, instance->port) ||
					!cti_connection_data_put(connection, instance->txt_data, instance->txt_length))
				{
					ERROR("adv_ctl_list_services: unable to write address %d for host %s", i, host->name);
					cti_connection_close(connection);
					return false;
				}
			}
		}
    }
	return cti_connection_message_send(connection);
}

static bool
adv_ctl_get_ula(advertising_proxy_conn_ref connection)
{
    if (!cti_connection_message_create(connection, kDNSSDAdvertisingProxyResponse, 200) ||
        !cti_connection_u32_put(connection, (uint32_t)kDNSSDAdvertisingProxyStatus_NoError))
    {
        ERROR("error starting response");
        cti_connection_close(connection);
        return false;
    }
    // Copy out just the global ID part of the ULA prefix.
    uint64_t ula = 0;
    for (int j = 1; j < 6; j++) {
        ula = ula << 8 | (((uint8_t *)&ula_prefix)[j]);
    }
    if (!cti_connection_u64_put(connection, ula)) {
        ERROR("error sending ula");
        cti_connection_close(connection);
        return false;
    }
    return cti_connection_message_send(connection);
}

static void
adv_ctl_message_parse(advertising_proxy_conn_ref connection)
{
	int status = kDNSSDAdvertisingProxyStatus_NoError;
	cti_connection_parse_start(connection);
	if (!cti_connection_u16_parse(connection, &connection->message_type)) {
		return;
	}
	switch(connection->message_type) {
    case kDNSSDAdvertisingProxyEnable:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyEnable request.",
			 connection->uid, connection->gid);
		break;
	case kDNSSDAdvertisingProxyListServiceTypes:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyListServiceTypes request.",
			 connection->uid, connection->gid);
		break;
	case kDNSSDAdvertisingProxyListServices:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyListServices request.",
			 connection->uid, connection->gid);
        adv_ctl_list_services(connection);
		return;
	case kDNSSDAdvertisingProxyListHosts:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyListHosts request.",
			 connection->uid, connection->gid);
		break;
	case kDNSSDAdvertisingProxyGetHost:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyGetHost request.",
			 connection->uid, connection->gid);
		break;
	case kDNSSDAdvertisingProxyFlushEntries:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyFlushEntries request.",
			 connection->uid, connection->gid);
        srp_mdns_flush();
		break;
	case kDNSSDAdvertisingProxyBlockService:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyBlockService request.",
			 connection->uid, connection->gid);
        adv_ctl_block_service(true);
		break;
	case kDNSSDAdvertisingProxyUnblockService:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyUnblockService request.",
			 connection->uid, connection->gid);
        adv_ctl_block_service(false);
		break;
	case kDNSSDAdvertisingProxyRegenerateULA:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyRegenerateULA request.",
			 connection->uid, connection->gid);
        adv_ctl_regenerate_ula();
		break;
	case kDNSSDAdvertisingProxyAdvertisePrefix:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyAdvertisePrefix request.",
			 connection->uid, connection->gid);
        adv_ctl_advertise_prefix();
		break;
    case kDNSSDAdvertisingProxyGetULA:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyULA request.",
             connection->uid, connection->gid);
        adv_ctl_get_ula(connection);
        return;

	default:
        ERROR("Client uid %d pid %d sent a request with unknown message type %d.",
			  connection->uid, connection->gid, connection->message_type);
        status = kDNSSDAdvertisingProxyStatus_Invalid;
		break;
	}
	cti_send_response(connection, status);
	cti_connection_close(connection);
}

static void
adv_ctl_read_callback(io_t *UNUSED io, void *context)
{
    advertising_proxy_conn_ref connection = context;

    cti_read(connection, adv_ctl_message_parse);
}

static io_t *listener;
static void
adv_ctl_listen_callback(io_t *UNUSED io, void *UNUSED context)
{
	uid_t uid;
	gid_t gid;
	pid_t pid;
	int fd = cti_accept(listener->fd, &uid, &gid, &pid);
	if (fd < 0) {
		return;
	}

    advertising_proxy_conn_ref connection = cti_connection_allocate(500);
    if (connection == NULL) {
        ERROR("cti_listen_callback: no memory for connection.");
		close(fd);
        return;
    }
    RETAIN_HERE(connection);

    connection->fd = fd;
	connection->uid = uid;
	connection->gid = gid;
	connection->pid = pid;
    connection->io_context = ioloop_file_descriptor_create(connection->fd, connection, adv_ctl_fd_finalize);
    if (connection->io_context == NULL) {
        ERROR("cti_listen_callback: no memory for io context.");
		close(fd);
		RELEASE_HERE(connection, cti_connection_finalize);
        return;
    }
    ioloop_add_reader(connection->io_context, adv_ctl_read_callback);
    connection->context = context;
    connection->callback.callback = NULL;
    connection->internal_callback = NULL;
    return;
}

static int
adv_ctl_listen(void)
{
    int fd = cti_make_unix_socket(ADV_CTL_SERVER_SOCKET_NAME, sizeof(ADV_CTL_SERVER_SOCKET_NAME), true);
    if (fd < 0) {
        int ret = (errno == ECONNREFUSED
				   ? kDNSSDAdvertisingProxyStatus_DaemonNotRunning
				   : errno == EPERM ? kDNSSDAdvertisingProxyStatus_NotPermitted : kDNSSDAdvertisingProxyStatus_UnknownErr);
        ERROR("adv_ctl_listener: socket: %s", strerror(errno));
        return ret;
    }

    listener = ioloop_file_descriptor_create(fd, NULL, NULL);
    if (listener == NULL) {
        ERROR("adv_ctl_listener: no memory for io_t object.");
		close(fd);
        return kDNSSDAdvertisingProxyStatus_NoMemory;
    }
    RETAIN_HERE(listener);

    ioloop_add_reader(listener, adv_ctl_listen_callback);
    return kDNSSDAdvertisingProxyStatus_NoError;
}

bool
adv_ctl_init(void)
{
	return adv_ctl_listen();
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
