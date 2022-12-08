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
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "cti-services.h"
#include "route.h"
#include "adv-ctl-server.h"
#include "srp-replication.h"
#include "dnssd-proxy.h"

#include "cti-proto.h"
#include "adv-ctl-common.h"
#include "advertising_proxy_services.h"


static int
adv_ctl_block_service(bool enable, void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
#if THREAD_BORDER_ROUTER
    srp_server_t *server_state = context;
    if (enable) {
        if (server_state->route_state->srp_listener != NULL) {
            srp_proxy_listener_cancel(server_state->route_state->srp_listener);
            server_state->route_state->srp_listener = NULL;
        } else {
            status = kDNSSDAdvertisingProxyStatus_UnknownErr;
        }
    } else {
        if (server_state->route_state->srp_listener == NULL) {
            partition_start_srp_listener(server_state->route_state);
        } else {
            status = kDNSSDAdvertisingProxyStatus_UnknownErr;
        }
    }
#else
    (void)enable;
    (void)context;
#endif // THREAD_BORDER_ROUTER
    return status;
}

static bool
adv_ctl_regenerate_ula(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
    srp_server_t *server_state = context;

#if THREAD_BORDER_ROUTER
    partition_stop_advertising_pref_id(server_state->route_state);
    infrastructure_network_shutdown(server_state->route_state);
    route_ula_generate(server_state->route_state);
    infrastructure_network_startup(server_state->route_state);
#endif
    return status;
}

static int
adv_ctl_advertise_prefix(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
    srp_server_t *server_state = context;

#if THREAD_BORDER_ROUTER
    partition_publish_my_prefix(server_state->route_state);
#endif
    return status;
}

static int
adv_ctl_prefix_add_remove(void *context, xpc_object_t request, bool add)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
    srp_server_t *server_state = context;
    const uint8_t *data;
    size_t data_len;

    data = xpc_dictionary_get_data(request, "data", &data_len);
    if (data != NULL && data_len == 16) {
        SEGMENTED_IPv6_ADDR_GEN_SRP(data, prefix_buf);
        INFO("got prefix " PRI_SEGMENTED_IPv6_ADDR_SRP, SEGMENTED_IPv6_ADDR_PARAM_SRP(data, prefix_buf));
#if THREAD_BORDER_ROUTER
        if (add) {
            adv_ctl_add_prefix(server_state->route_state, data);
        } else {
            adv_ctl_remove_prefix(server_state->route_state, data);
        }
#endif
    } else {
        ERROR("invalid request, data[%p], data_len[%ld]", data, data_len);
        status = kDNSSDAdvertisingProxyStatus_BadParam;
    }
    return status;
}

static int
adv_ctl_stop_advertising_service(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;
    srp_server_t *server_state = context;

#if THREAD_BORDER_ROUTER
    partition_discontinue_srp_service(server_state->route_state);
#endif
    return status;
}

static int
adv_ctl_disable_replication(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if SRP_FEATURE_REPLICATION
    srp_server_t *server_state = context;
    srpl_disable(server_state);
#else
    (void)context;
#endif
    return status;
}

static int
adv_ctl_drop_srpl_connection(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if SRP_FEATURE_REPLICATION
    srp_server_t *server_state = context;
    srpl_drop_srpl_connection(server_state);
#else
    (void)context;
#endif
    return status;
}

static int
adv_ctl_undrop_srpl_connection(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if SRP_FEATURE_REPLICATION
    srp_server_t *server_state = context;
    srpl_undrop_srpl_connection(server_state);
#else
    (void)context;
#endif
    return status;
}

static int
adv_ctl_drop_srpl_advertisement(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if SRP_FEATURE_REPLICATION
    srp_server_t *server_state = context;
    srpl_drop_srpl_advertisement(server_state);
#else
    (void)context;
#endif
    return status;
}

static int
adv_ctl_undrop_srpl_advertisement(void *context)
{
    int status = kDNSSDAdvertisingProxyStatus_NoError;

#if SRP_FEATURE_REPLICATION
    srp_server_t *server_state = context;
    srpl_undrop_srpl_advertisement(server_state);
#else
    (void)context;
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
adv_ctl_list_services(advertising_proxy_conn_ref connection, void *context)
{
    srp_server_t *server_state = context;
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
	for (host = server_state->hosts; host != NULL; host = host->next) {
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

        if (host->addresses != NULL) {
            for (i = 0; i < host->addresses->num; i++) {
                if (host->addresses->vec[i] != NULL) {
                    num_addresses++;
                }
            }
        }
		cti_connection_u16_put(connection, num_addresses);
        if (host->addresses != NULL) {
            for (i = 0; i < host->addresses->num; i++) {
                if (host->addresses->vec[i] != NULL) {
                    if (!cti_connection_u16_put(connection, host->addresses->vec[i]->rrtype) ||
                        !cti_connection_data_put(connection, host->addresses->vec[i]->rdata, host->addresses->vec[i]->rdlen))
                    {
                        ERROR("adv_ctl_list_services: unable to write address %d for host %s", i, host->name);
                        cti_connection_close(connection);
                        return false;
                    }
                }
            }
        }
        if (host->instances != NULL) {
            for (i = 0; i < host->instances->num; i++) {
                if (host->instances->vec[i] != NULL) {
                    num_instances++;
                }
            }
        }
		cti_connection_u16_put(connection, num_instances);
        if (host->instances != NULL) {
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
    }
	return cti_connection_message_send(connection);
}

static bool
adv_ctl_get_ula(advertising_proxy_conn_ref connection, void *context)
{
    srp_server_t *server_state = context;

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
        ula = ula << 8 | (((uint8_t *)&server_state->ula_prefix)[j]);
    }
    if (!cti_connection_u64_put(connection, ula)) {
        ERROR("error sending ula");
        cti_connection_close(connection);
        return false;
    }
    return cti_connection_message_send(connection);
}

static void
adv_ctl_message_parse(advertising_proxy_conn_ref connection, void *context)
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
        adv_ctl_list_services(connection, context);
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
        srp_mdns_flush(context);
		break;
	case kDNSSDAdvertisingProxyBlockService:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyBlockService request.",
			 connection->uid, connection->gid);
        adv_ctl_block_service(true, context);
		break;
	case kDNSSDAdvertisingProxyUnblockService:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyUnblockService request.",
			 connection->uid, connection->gid);
        adv_ctl_block_service(false, context);
		break;
	case kDNSSDAdvertisingProxyRegenerateULA:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyRegenerateULA request.",
			 connection->uid, connection->gid);
        adv_ctl_regenerate_ula(context);
		break;
    case kDNSSDAdvertisingProxyAdvertisePrefix:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyAdvertisePrefix request.",
             connection->uid, connection->gid);
        adv_ctl_advertise_prefix(context);
        break;
    case kDNSSDAdvertisingProxyAddPrefix:
        void *data = NULL;
        uint16_t data_len;
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyAddPrefix request.",
             connection->uid, connection->gid);
        if (!cti_connection_data_parse(connection, &data, &data_len)) {
            ERROR("faile to parse data for kDNSSDAdvertisingProxyAddPrefix request.");
            status = kDNSSDAdvertisingProxyStatus_BadParam;
        } else {
            if (data != NULL && data_len == 16) {
                SEGMENTED_IPv6_ADDR_GEN_SRP(data, prefix_buf);
                INFO("got prefix " PRI_SEGMENTED_IPv6_ADDR_SRP, SEGMENTED_IPv6_ADDR_PARAM_SRP(data, prefix_buf));
                status = adv_ctl_add_prefix(context, data);
            } else {
                ERROR("invalid add prefix request, data[%p], data_len[%ld]", data, data_len);
                status = kDNSSDAdvertisingProxyStatus_BadParam;
            }
        }
        break;
    case kDNSSDAdvertisingProxyRemovePrefix:
        void *data = NULL;
        uint16_t data_len;
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyRemovePrefix request.",
             connection->uid, connection->gid);
        if (!cti_connection_data_parse(connection, &data, &data_len)) {
            ERROR("faile to parse data for kDNSSDAdvertisingProxyRemovePrefix request.");
            status = kDNSSDAdvertisingProxyStatus_BadParam;
        } else {
            if (data != NULL && data_len == 16) {
                SEGMENTED_IPv6_ADDR_GEN_SRP(data, prefix_buf);
                INFO("got prefix " PRI_SEGMENTED_IPv6_ADDR_SRP, SEGMENTED_IPv6_ADDR_PARAM_SRP(data, prefix_buf));
                status = adv_ctl_add_prefix(context, data);
            } else {
                ERROR("invalid add prefix request, data[%p], data_len[%ld]", data, data_len);
                status = kDNSSDAdvertisingProxyStatus_BadParam;
            }
        }
        break;
    case kDNSSDAdvertisingProxyStop:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyStop request.",
             connection->uid, connection->gid);
        adv_ctl_stop_advertising_service(context);
        break;
    case kDNSSDAdvertisingProxyGetULA:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyULA request.",
             connection->uid, connection->gid);
        adv_ctl_get_ula(connection, context);
        break;
    case kDNSSDAdvertisingProxyDisableReplication:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyDisableReplication request.",
             connection->uid, connection->gid);
        adv_ctl_disable_replication(context);
        break;
    case kDNSSDAdvertisingProxyDropSrplConnection:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyDropSrplConnection request.",
             connection->uid, connection->gid);
        adv_ctl_drop_srpl_connection(context);
        break;
    case kDNSSDAdvertisingProxyUndropSrplConnection:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyUndropSrplConnection request.",
             connection->uid, connection->gid);
        adv_ctl_undrop_srpl_connection(context);
        break;
    case kDNSSDAdvertisingProxyDropSrplAdvertisement:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyDropSrplAdvertisement request.",
             connection->uid, connection->gid);
        adv_ctl_drop_srpl_advertisement(context);
        break;
    case kDNSSDAdvertisingProxyUndropSrplAdvertisement:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyUndropSrplAdvertisement request.",
             connection->uid, connection->gid);
        adv_ctl_undrop_srpl_advertisement(context);
        break;

    case kDNSSDAdvertisingProxyStartDroppingPushConnections:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyStartDroppingPushConnections request.",
             connection->uid, connection->gid);
        dp_start_smashing();
        break;

    case kDNSSDAdvertisingProxyStartBreakingTimeValidation:
        INFO("Client uid %d pid %d sent a kDNSSDAdvertisingProxyStartBreakingTimeValidation request.",
             connection->uid, connection->pid);
        adv_ctl_start_breaking_time(context);

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

static void
adv_ctl_listen_callback(io_t *UNUSED io, void *context)
{
    srp_server_t *server_state = context;
	uid_t uid;
	gid_t gid;
	pid_t pid;

	int fd = cti_accept(server_state->adv_ctl_listener->fd, &uid, &gid, &pid);
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
adv_ctl_listen(srp_server_t *server_state)
{
    int fd = cti_make_unix_socket(ADV_CTL_SERVER_SOCKET_NAME, sizeof(ADV_CTL_SERVER_SOCKET_NAME), true);
    if (fd < 0) {
        int ret = (errno == ECONNREFUSED
				   ? kDNSSDAdvertisingProxyStatus_DaemonNotRunning
				   : errno == EPERM ? kDNSSDAdvertisingProxyStatus_NotPermitted : kDNSSDAdvertisingProxyStatus_UnknownErr);
        ERROR("adv_ctl_listener: socket: %s", strerror(errno));
        return ret;
    }

    server_state->adv_ctl_listener = ioloop_file_descriptor_create(fd, server_state, NULL);
    if (server_state->listener == NULL) {
        ERROR("adv_ctl_listener: no memory for io_t object.");
		close(fd);
        return kDNSSDAdvertisingProxyStatus_NoMemory;
    }
    RETAIN_HERE(server_state->adv_ctl_listener);

    ioloop_add_reader(server_state->adv_ctl_listener, adv_ctl_listen_callback);
    return kDNSSDAdvertisingProxyStatus_NoError;
}

bool
adv_ctl_init(void *context)
{
    srp_server_t *server_state = context;
	return adv_ctl_listen(server_state);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
