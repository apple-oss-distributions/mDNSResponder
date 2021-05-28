/* srp-mdns-proxy.c
 *
 * Copyright (c) 2019-2020 Apple Computer, Inc. All rights reserved.
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
 * This file contains the SRP Advertising Proxy, which is an SRP Server
 * that offers registered addresses using mDNS.
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
#include <sys/time.h>
#include <dns_sd.h>
#include <net/if.h>
#include <sys/resource.h>

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#include "dnssd-proxy.h"
#include "srp-gw.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "config-parse.h"
#include "route.h"

#ifdef IOLOOP_MACOS
#include "xpc_client_advertising_proxy.h"
#include "advertising_proxy_services.h"
#include <os/transaction_private.h>
#endif

// Server internal state
struct {
    struct in6_addr addr;
    int width;
} *preferred_prefix;

typedef struct srp_xpc_client srp_xpc_client_t;
struct srp_xpc_client {
    srp_xpc_client_t *next;
    xpc_connection_t connection;
    bool connection_canceled; // If true, we've initiated an xpc_connection_cancel on this client.
    bool enabler; // If true, this client has asked to enable the proxy.
};

typedef struct srp_wanted_state srp_wanted_state_t;
struct srp_wanted_state {
    int ref_count;
    os_transaction_t transaction;
};

adv_host_t *hosts;
int advertise_interface = kDNSServiceInterfaceIndexAny;

const char local_suffix_ld[] = ".local";
const char *local_suffix = &local_suffix_ld[1];
uint32_t max_lease_time = 3600 * 27; // One day plus 20%
uint32_t min_lease_time = 30; // thirty seconds

static xpc_connection_t xpc_listener;

srp_wanted_state_t *srp_wanted;
srp_xpc_client_t *srp_xpc_clients;

// Forward references...
static void try_new_hostname(adv_host_t *host);
static void register_host_completion(DNSServiceRef sdref, DNSRecordRef rref,
                                     DNSServiceFlags flags, DNSServiceErrorType error_code, void *context);
static void register_instance_completion(DNSServiceRef sdref, DNSServiceFlags flags, DNSServiceErrorType error_code,
                                         const char *name, const char *regtype, const char *domain, void *context);
static void update_from_host(adv_host_t *host);
static void start_host_update(adv_host_t *host);
static void prepare_update(adv_host_t *host);
static void lease_callback(void *context);


static void
adv_address_finalize(adv_address_t *address)
{
    free(address);
}

static void
adv_instance_finalize(adv_instance_t *instance)
{
    if (instance->txn != NULL) {
        ioloop_dnssd_txn_release(instance->txn);
    }
    if (instance->txt_data != NULL) {
        free(instance->txt_data);
    }
    if (instance->instance_name != NULL) {
        free(instance->instance_name);
    }
    if (instance->service_type != NULL) {
        free(instance->service_type);
    }
    free(instance);
}

static adv_instance_vec_t *
adv_instance_vec_create(int size)
{
    adv_instance_vec_t *vec;

    vec = calloc(1, sizeof(*vec));
    if (vec != NULL) {
        if (size == 0) {
            size = 1;
        }
        vec->vec = calloc(size, sizeof (*(vec->vec)));
        if (vec->vec == NULL) {
            free(vec);
            vec = NULL;
        } else {
            RETAIN_HERE(vec);
        }
    }
    return vec;
}

static adv_instance_vec_t *
adv_instance_vec_copy(adv_instance_vec_t *vec)
{
    adv_instance_vec_t *new_vec;
    int i;

    new_vec = adv_instance_vec_create(vec->num);
    if (new_vec != NULL) {
        RETAIN_HERE(new_vec);
        for (i = 0; i < vec->num; i++) {
            if (vec->vec[i] != NULL) {
                new_vec->vec[i] = vec->vec[i];
                RETAIN_HERE(new_vec->vec[i]);
            }
        }
        new_vec->num = vec->num;
    }
    return new_vec;
}

static void
adv_instance_vec_finalize(adv_instance_vec_t *vec)
{
    int i;

    for (i = 0; i < vec->num; i++) {
        if (vec->vec[i] != NULL) {
            RELEASE_HERE(vec->vec[i], adv_instance_finalize);
            vec->vec[i] = NULL;
        }
    }
    free(vec->vec);
    free(vec);
}

static bool
same_prefix(void *ai, void *bi, int width)
{
    int bite;
    uint8_t *a = ai, *b = bi;
    static int masks[] = {0xff, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
    static int mask;
    for (bite = 0; bite * 8 < width; bite++) {
        if (a[bite] != b[bite]) {
            return false;
        }
    }
    if ((width % 8) == 0) {
        return true;
    }
    mask = masks[width % 8];
    if ((a[bite] & mask) == (b[bite] & mask)) {
        return true;
    }
    return false;
}

// We call advertise_finished when a client request has finished, successfully or otherwise.
static void
advertise_finished(comm_t *connection, message_t *message, int rcode, client_update_t *client)
{
    struct iovec iov;
    dns_wire_t response;
    INFO("advertise_finished: rcode = " PUB_S_SRP, dns_rcode_name(rcode));

    memset(&response, 0, DNS_HEADER_SIZE);
    response.id = message->wire.id;
    response.bitfield = message->wire.bitfield;
    dns_rcode_set(&response, rcode);
    dns_qr_set(&response, dns_qr_response);

    iov.iov_base = &response;
    // If this was a successful update, send back the lease time, which will either
    // be what the client asked for, or a shorter lease, depending on what limit has
    // been set.
    if (client != NULL) {
        dns_towire_state_t towire;
        memset(&towire, 0, sizeof towire);
        towire.p = &response.data[0];               // We start storing RR data here.
        towire.lim = &response.data[DNS_DATA_SIZE]; // This is the limit to how much we can store.
        towire.message = &response;
        response.qdcount = 0;
        response.ancount = 0;
        response.nscount = 0;
        response.arcount = htons(1);
        dns_edns0_header_to_wire(&towire, DNS_MAX_UDP_PAYLOAD, 0, 0, 1);
        dns_rdlength_begin(&towire);
        dns_u16_to_wire(&towire, dns_opt_update_lease);  // OPTION-CODE
        dns_edns0_option_begin(&towire);                 // OPTION-LENGTH
        dns_u32_to_wire(&towire, client->host_lease);    // LEASE (e.g. 1 hour)
        dns_u32_to_wire(&towire, client->key_lease);     // KEY-LEASE (7 days)
        dns_edns0_option_end(&towire);                   // Now we know OPTION-LENGTH
        dns_rdlength_end(&towire);
        // It should not be possible for this to happen; if it does, the client
        // might not renew its lease in a timely manner.
        if (towire.error) {
            ERROR("advertise_finished: unexpectedly failed to send EDNS0 lease option.");
            iov.iov_len = DNS_HEADER_SIZE;
        } else {
            iov.iov_len = towire.p - (uint8_t *)&response;
        }
    } else {
        iov.iov_len = DNS_HEADER_SIZE;
    }
    ioloop_send_message(connection, message, &iov, 1);
}

static void
host_txn_finalize_callback(void *context)
{
    adv_host_t *host = context;
    host->txn = NULL;
    host->rref = NULL;
}

static void
instance_txn_finalize_callback(void *context)
{
    adv_instance_t *instance = context;
    instance->txn = NULL;
}

static void
retry_callback(void *context)
{
    adv_host_t *host = (adv_host_t *)context;
    if (host->updates == NULL && host->clients == NULL) {
        update_from_host(host);
    } else {
        start_host_update(host);
    }
}

static void
wait_retry(adv_host_t *host)
{
#define MIN_HOST_RETRY_INTERVAL 15
#define MAX_HOST_RETRY_INTERVAL 120
    // If we've been retrying long enough for the lease to expire, give up.
    if (!host->lease_expiry || host->lease_expiry >= ioloop_timenow()) {
        lease_callback(host);
    }
    if (host->retry_interval == 0) {
        host->retry_interval = MIN_HOST_RETRY_INTERVAL;
    } else if (host->retry_interval < MAX_HOST_RETRY_INTERVAL) {
        host->retry_interval *= 2;
    }
    INFO("wait_retry: waiting %d seconds...", host->retry_interval);
    ioloop_add_wake_event(host->retry_wakeup, host, retry_callback, NULL, host->retry_interval * 1000);
}

// When the connection to mDNSResponder has died, the registration dies with it.
// In order to get back to where we were, we use the contents of the host to create an
// update.  We push that update in front of any update that was pending, and restart
// the registration.  There is no guarantee that this will succeed.   If it fails, then
// the registration is abandoned.

static void
service_disconnected(adv_host_t *host)
{
    // If we don't have any updates we can do, this host is dead.
    if (host->updates == NULL) {
        // lease_callback will get rid of this host.
        lease_callback(host);
    } else {
        wait_retry(host);
    }
}

static void
client_finalize(client_update_t *client)
{
    srp_update_free_parts(client->instances, NULL, client->services, client->host);
    if (client->parsed_message != NULL) {
        dns_message_free(client->parsed_message);
    }
    if (client->message != NULL) {
        ioloop_message_release(client->message);
    }
    if (client->connection != NULL) {
        ioloop_comm_release(client->connection);
    }
    free(client);
}

static void
update_finalize(adv_update_t *NONNULL update)
{
    adv_host_t *host = update->host;
    int i;
    if (host != NULL) {
        adv_update_t **p_updates = &host->updates;

        // Once the update is done, we want to make sure that any results that come in on the host registration do not
        // reference the update, which will we are about to free.  So get rid of the update pointer that's in the
        // host address transaction aux data.
        if (update->host->txn != NULL) {
            adv_update_t *host_txn_update = ioloop_dnssd_txn_get_aux_pointer(host->txn);
            // If we are retrying an update, the update on the host DNSServiceRegisterRecord transaction might not be
            // the transaction we are finalizing, but if it is, we definitely want to make it go away.
            if (host_txn_update == update) {
                ioloop_dnssd_txn_set_aux_pointer(host->txn, NULL);
            }
        }
        INFO("finalizing update %p for host " PRI_S_SRP, update, host->registered_name);

        // Take this update off the host's update list (it might already be gone)
        while (*p_updates != NULL) {
            if (*p_updates == update) {
                *p_updates = update->next;
                break;
            } else {
                p_updates = &((*p_updates)->next);
            }
        }
    } else {
        INFO("finalizing update with no host.");
    }

    // Release instances and instance vectors.
    if (update->add_instances != NULL) {
        RELEASE_HERE(update->add_instances, adv_instance_vec_finalize);
    }

    if (update->update_instances != NULL) {
        RELEASE_HERE(update->update_instances, adv_instance_vec_finalize);
    }

    if (update->remove_instances != NULL) {
        RELEASE_HERE(update->remove_instances, adv_instance_vec_finalize);
    }

    if (update->add_addresses != NULL) {
        for (i = 0; i < update->num_add_addresses; i++) {
            if (update->add_addresses[i] != NULL) {
                RELEASE_HERE(update->add_addresses[i], adv_address_finalize);
            }
        }
        free(update->add_addresses);
    }

    if (update->remove_addresses != NULL) {
        for (i = 0; i < update->num_remove_addresses; i++) {
            if (update->remove_addresses[i] != NULL) {
                RELEASE_HERE(update->remove_addresses[i], adv_address_finalize);
            }
        }
        free(update->remove_addresses);
    }

    if (update->selected_addr != NULL) {
        RELEASE_HERE(update->selected_addr, adv_address_finalize);
    }

    free(update);
}

static void
update_failed(adv_update_t *update, int rcode, bool expire)
{
    // If we still have a client waiting for the result of this update, tell it we failed.
    // Updates that have never worked are abandoned when the client is notified.
    if (update->client != NULL) {
        adv_host_t *host = update->host;
        client_update_t *client = update->client;
        advertise_finished(client->connection, client->message, rcode, NULL);
        update_finalize(update);
        client_finalize(client);
        // If we don't have a lease yet, or the old lease has expired, remove the host.
        // However, if the expire flag is false, it's because we're already finalizing the
        // host, so doing an expiry here would double free the host. In this case, we leave
        // it to the caller to do the expiry (really, to finalize the host).
        if (expire && (host->lease_expiry == 0 || host->lease_expiry <= ioloop_timenow())) {
            lease_callback(host);
        }
        return;
    }

    // The only time that we will not have a client waiting for a result from an update is if
    // we are trying to recover from an mDNSResponder crash.  mDNSResponder doesn't crash much,
    // so the likelihood of us even finding out if this behavior is correct is pretty low.
    // That said, we do take this possibility into account; if it happens, we try to restore
    // all the registrations that were present prior to the crash.

    // In the case of an update that previously succeeded, but that now has failed because of a naming
    // conflict (yxdomain), we have to abandon it, even though we have no way to notify the owner.
    if (rcode == dns_rcode_yxdomain) {
        update_finalize(update);
        return;
    }
}

static void
host_addr_free(adv_host_t *host)
{
    int i;

    if (host->addresses != NULL) {
       for (i = 0; i < host->num_addresses; i++) {
           if (host->addresses[i] != NULL) {
               RELEASE_HERE(host->addresses[i], adv_address_finalize);
           }
       }
       free(host->addresses);
    }
    host->addresses = NULL;
    host->num_addresses = 0;
}

static void
host_finalize(adv_host_t *host)
{
    int i;

    // Get rid of the host wake events.
    if (host->lease_wakeup != NULL) {
        ioloop_cancel_wake_event(host->lease_wakeup);
        ioloop_wakeup_release(host->lease_wakeup);
    }
    if (host->retry_wakeup != NULL) {
        ioloop_cancel_wake_event(host->retry_wakeup);
        ioloop_wakeup_release(host->retry_wakeup);
    }


    // Remove all the advertised address records (currently only one).
    if (host->txn != NULL) {
        if (host->txn->sdref == NULL) {
            INFO("host_finalize: releasing DNSSD transaction for " PRI_S_SRP ", but there's no sdref.", host->name);
        } else {
            INFO("host_finalize: removing AAAA record(s) for " PRI_S_SRP, host->registered_name);
        }
        ioloop_dnssd_txn_release(host->txn);
    } else {
        INFO("host_finalize: no host address transaction for " PRI_S_SRP, host->registered_name);
    }

    // Remove the address records.
    host_addr_free(host);

    // Remove the services.

    if (host->instances != NULL) {
        for (i = 0; i < host->instances->num; i++) {
            if (host->instances->vec[i] != NULL) {
                if (host->instances->vec[i]->txn) {
                    ioloop_dnssd_txn_release(host->instances->vec[i]->txn);
                }
            }
        }
        RELEASE_HERE(host->instances, adv_instance_vec_finalize);
    }

    // At this point we could claim the key, but for now just get rid of the host.
    if (host->key_rdata != NULL) {
        free(host->key_rdata);
    }
    INFO("host_finalize: removed " PRI_S_SRP ", key_id %x", host->name ? host->name : "<null>", host->key_id);

    // In the default case, host->name and host->registered_name point to the same memory: we don't want a double free.
    if (host->registered_name == host->name) {
        host->registered_name = NULL;
    }
    if (host->name != NULL) {
        free(host->name);
    }
    if (host->registered_name != NULL) {
        free(host->registered_name);
    }
    free(host);
}

static void
lease_callback(void *context)
{
    adv_host_t **p_hosts, *host = context;

    // Find the host on the list of hosts.
    for (p_hosts = &hosts; *p_hosts != NULL; p_hosts = &(*p_hosts)->next) {
        if (*p_hosts == host) {
            break;
        }
    }
    if (*p_hosts == NULL) {
        ERROR("lease-callback: called with nonexistent host.");
        return;
    }

    // It's possible that we got an update to this host, but haven't processed it yet.  In this
    // case, we don't want to get rid of the host, but we do want to get rid of it later if the
    // update fails.  So postpone the removal for another lease interval.
    if (host->updates != NULL || host->clients != NULL) {
        INFO("lease_callback: reached with pending updates on host " PRI_S_SRP ".", host->registered_name);
        ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, host->lease_interval * 1000);
        host->lease_expiry = ioloop_timenow() + host->lease_interval * 1000;
        return;
    }

    // De-link the host.
    *p_hosts = host->next;

    // Get rid of any transactions attached to the host, any timer events, and any other associated data.
    host_finalize(host);
}

static void
update_finished(adv_update_t *update)
{
    adv_host_t *host = update->host;
    client_update_t *client = update->client;
    int num_addresses = 0;
    adv_address_t **addresses = NULL;
    int num_instances = 0;
    adv_instance_vec_t *instances = NULL;
    int i, j;
    int num_host_addresses = 0;
    int num_add_addresses = 0;
    int num_host_instances = 0;
    int num_add_instances = 0;
    uint8_t *rdata;
    adv_update_t **p_update;

    // Reset the retry interval, since we succeeded in updating.
    host->retry_interval = 0;

    // Once an update has finished, we need to apply all of the proposed changes to the host object.
    if (host->addresses != NULL) {
        for (i = 0; i < host->num_addresses; i++) {
            if (host->addresses[i] != NULL &&
                (update->remove_addresses == NULL || update->remove_addresses[i] == NULL))
            {
                num_host_addresses++;
            }
        }
    }

    if (update->add_addresses != NULL) {
        for (i = 0; i < update->num_add_addresses; i++) {
            if (update->add_addresses[i] != NULL) {
                num_add_addresses++;
            }
        }
    }

    num_addresses = num_host_addresses + num_add_addresses;
    if (num_addresses > 0) {
        addresses = calloc(num_addresses, sizeof *addresses);
        if (addresses == NULL) {
            update_failed(update, dns_rcode_servfail, true);
            return;
        }

        j = 0;
        addresses[j] = update->selected_addr;
        RETAIN_HERE(addresses[j]);
        j++;

        rdata = update->selected_addr->rdata;
        SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, rdata_buf);
        INFO("update_finished: selected " PRI_SEGMENTED_IPv6_ADDR_SRP " on host " PRI_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, rdata_buf), host->registered_name);

        if (host->addresses != NULL) {
            for (i = 0; i < host->num_addresses; i++) {
                if (host->addresses[i] != NULL && host->addresses[i] != update->selected_addr &&
                    (update->remove_addresses == NULL || update->remove_addresses[i] == NULL))
                {
#ifdef DEBUG_VERBOSE
                    uint8_t *rdp = host->addresses[i]->rdata;
                    SEGMENTED_IPv6_ADDR_GEN_SRP(rdp, rdp_buf);
                    INFO("update_finished: retaining " PRI_SEGMENTED_IPv6_ADDR_SRP "on host " PRI_S_SRP,
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(rdp, rdp_buf), host->registered_name);
#endif
                    addresses[j] = host->addresses[i];
                    RETAIN_HERE(addresses[j]);
                    j++;
                }
            }
        }
        if (update->add_addresses != NULL) {
            for (i = 0; i < update->num_add_addresses; i++) {
                if (update->add_addresses[i] != NULL) {
                    if (update->add_addresses[i] != update->selected_addr) {
#ifdef DEBUG_VERBOSE
                        uint8_t *rdp = update->add_addresses[i]->rdata;
                        SEGMENTED_IPv6_ADDR_GEN_SRP(rdp, rdp_buf);
                        INFO("update_finished: adding " PRI_SEGMENTED_IPv6_ADDR_SRP "to host " PRI_S_SRP,
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(rdp, rdp_buf), host->registered_name);
#endif
                        addresses[j] = update->add_addresses[i];
                        RETAIN_HERE(addresses[j]);
                        j++;
                    }
                    RELEASE_HERE(update->add_addresses[i], adv_address_finalize);
                    update->add_addresses[i] = NULL;
                }
            }
        }
        if (update->selected_addr != NULL) {
            RELEASE_HERE(update->selected_addr, adv_address_finalize);
            update->selected_addr = NULL;
        }
    }

    // Do the same for instances.
    for (i = 0; i < host->instances->num; i++) {
        if (host->instances->vec[i] != NULL &&
            (update->remove_instances == NULL || update->remove_instances->vec[i] == NULL))
        {
            num_host_instances++;
        }
    }

    if (update->add_instances != NULL) {
        for (i = 0; i < update->add_instances->num; i++) {
            if (update->add_instances->vec[i] != NULL) {
                num_add_instances++;
            }
        }
    }

    num_instances = num_add_instances + num_host_instances;
    instances = adv_instance_vec_create(num_instances);
    if (instances == NULL) {
        if (addresses != NULL) {
            for (i = 0; i < num_addresses; i++) {
                if (addresses[i] != NULL) {
                    RELEASE_HERE(addresses[i], adv_address_finalize);
                }
            }
            free(addresses);
        }
        update_failed(update, dns_rcode_servfail, true);
        return;
    }
    instances->num = num_instances;

    j = 0;
    for (i = 0; i < host->instances->num; i++) {
        if (update->remove_instances != NULL && update->remove_instances->vec[i] == NULL) {
            if (update->update_instances->vec[i] != NULL) {
                adv_instance_t *instance = update->update_instances->vec[i];
                INFO("update_finished: updated instance " PRI_S_SRP " " PRI_S_SRP " %d",
                      instance->instance_name, instance->service_type, instance->port);
                // Implicit RETAIN/RELEASE
                instances->vec[j] = instance;
                update->update_instances->vec[i] = NULL;
            } else {
                if (host->instances->vec[i] != NULL) {
                    adv_instance_t *instance = host->instances->vec[i];
                    INFO("update_finished: retained instance " PRI_S_SRP " " PRI_S_SRP " %d",
                          instance->instance_name, instance->service_type, instance->port);
                    instances->vec[j++] = instance;
                    RETAIN_HERE(instance);
                }
            }
        }
    }
    if (update->add_instances != NULL) {
        for (i = 0; i < update->add_instances->num; i++) {
            adv_instance_t *instance = update->add_instances->vec[i];
            if (instance != NULL) {
                INFO("update_finished: added instance " PRI_S_SRP " " PRI_S_SRP " %d",
                      instance->instance_name, instance->service_type, instance->port);
                // Implicit RETAIN/RELEASE
                instances->vec[j++] = instance;
                update->add_instances->vec[i] = NULL;
            }
        }
    }

    // At this point we can safely modify the host object because we aren't doing any more
    // allocations.
    host_addr_free(host);
    RELEASE_HERE(host->instances, adv_instance_vec_finalize);

    host->addresses = addresses;
    host->num_addresses = num_addresses;
    host->instances = instances;

    if (client) {
        advertise_finished(client->connection, client->message, dns_rcode_noerror, client);
        client_finalize(client);
        update->client = NULL;
    }

    // The update should still be on the host.
    for (p_update = &host->updates; *p_update != NULL; p_update = &(*p_update)->next) {
        if (*p_update == update) {
            break;
        }
    }

    if (*p_update == NULL) {
        ERROR("update_finished: p_update is null.");
    } else {
        *p_update = update->next;
    }

    // If we have another prepared update to do, apply it first.
    if (host->updates) {
        start_host_update(host);
        goto out;
    }

    // If we have an update that hasn't yet been prepared, prepare it and apply it.
    if (host->clients) {
        prepare_update(host);
        goto out;
    }

    // If we got a late name conflict while processing the previous update, try to get a new hostname.
    // We won't get here if the update caused the host to be reregistered--in that case we will either
    // return a failure to the client and delete the host, or else we'll have resolved the conflict.
    if (host->hostname_update_pending) {
        try_new_hostname(host);
    }

    // Otherwise, there's no work left to do, so just wait until the lease expires.
    host->lease_interval = update->host_lease;
    host->key_lease = update->key_lease;

    if (update->lease_expiry != 0) {
        uint64_t now = ioloop_timenow();
        if (update->lease_expiry < now) {
            ERROR("update_finished: lease expiry for host %s happened %" PRIu64 " milliseconds ago.",
                  host->registered_name, now - update->lease_expiry);
            // Expire the lease in 1000 ms.
            ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, 1000);
        } else {
            uint64_t when = update->lease_expiry - now;
            if (when > INT32_MAX) {
                when = INT32_MAX;
            }
            ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, (uint32_t)when);
            host->lease_expiry = update->lease_expiry;
        }
    } else {
        ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, host->lease_interval * 1000);
        host->lease_expiry = ioloop_timenow() + host->lease_interval * 1000;
    }
out:
    update_finalize(update);
}

// When the host registration has completed, we get this callback.   Completion either means that we succeeded in
// registering the record, or that something went wrong and the registration has failed.
static void
register_instance_completion(DNSServiceRef sdref, DNSServiceFlags flags, DNSServiceErrorType error_code,
                             const char *name, const char *regtype, const char *domain, void *context)
{
    (void)flags;
    (void)sdref;
    (void)name;
    (void)regtype;
    adv_instance_t *instance = context;
    adv_update_t *update = instance->update;
    adv_host_t *host = instance->host;

    // It's possible that we could restart a host update due to an error while a callback is still pending on a stale
    // update.  In this case, we just cancel all of the work that's been done on the stale update (it's probably already
    // moot anyway.
    if (update != NULL && host->updates != update) {
        INFO("register_instance_completion: registration for service " PRI_S_SRP "." PRI_S_SRP
             " completed with invalid state.", name, regtype);
        update_finalize(update);
        return;
    }

    // We will generally get a callback on success or failure of the initial registration; this is what causes
    // the update to complete or fail. We may get subsequent callbacks because of name conflicts. So the first
    // time we get a callback, instance->update will always be valid; thereafter, it will not, so null it out.
    instance->update = NULL;

    if (error_code == kDNSServiceErr_NoError) {
        INFO("register_instance_completion: registration for service " PRI_S_SRP "." PRI_S_SRP "." PRI_S_SRP " -> "
             PRI_S_SRP " has completed.", instance->instance_name, instance->service_type, domain,
             host->registered_name);
        INFO("register_instance_completion: registration is under " PRI_S_SRP "." PRI_S_SRP PRI_S_SRP, name, regtype,
             domain);

        // In principle update->instance should always be non-NULL here because a no-error response should
        // only happen once or not at all. But just to be safe...
        if (update != NULL) {
            update->num_instances_completed++;
            if (update->num_instances_completed == update->num_instances_started) {
                // We have successfully advertised the service.
                update_finished(update);
            }
        } else {
            ERROR("register_instance_completion: no error, but update is NULL for instance " PRI_S_SRP " (" PRI_S_SRP
                  " " PRI_S_SRP " " PRI_S_SRP ")", instance->instance_name, name, regtype, domain);
        }
    } else {
        INFO("register_instance_completion: registration for service " PRI_S_SRP "." PRI_S_SRP "." PRI_S_SRP " -> "
             PRI_S_SRP " failed with code %d", instance->instance_name, instance->service_type, domain,
             host->registered_name, error_code);

        // If this is the immediate result of a registration, we can inform the SRP client that it failed.
        if (update != NULL) {
            // At present we will never get this error because mDNSResponder will just choose a new name.
            if (error_code == kDNSServiceErr_NameConflict) {
                update_failed(update, dns_rcode_yxdomain, true);
            } else {
                update_failed(update, dns_rcode_servfail, true);
            }
        } else {
            ERROR("Late failure for instance " PRI_S_SRP "--can't update client.", instance->instance_name);
        }

        if (error_code == kDNSServiceErr_ServiceNotRunning || error_code == kDNSServiceErr_DefunctConnection) {
            service_disconnected(host);
        }
    }
}

static void
extract_instance_name(char *instance_name, int instance_name_max,
                      char *service_name, int service_name_max, service_instance_t *instance)
{
    dns_name_t *end_of_service_name = instance->service->rr->name->next;
    if (end_of_service_name != NULL) {
        if (end_of_service_name->next != NULL) {
            end_of_service_name = end_of_service_name->next;
        }
    }
    dns_name_print_to_limit(instance->service->rr->name, end_of_service_name, service_name, service_name_max);

    // Make a presentation-format version of the service instance name.
    dns_name_print_to_limit(instance->name, instance->name != NULL ? instance->name->next : NULL,
                            instance_name, instance_name_max);
}

static bool
register_instance(adv_instance_t *instance)
{
    int err;
    DNSServiceRef sdref;

    INFO("DNSServiceRegister(" PRI_S_SRP ", " PRI_S_SRP ", " PRI_S_SRP ", %d)",
         instance->instance_name, instance->service_type, instance->host->registered_name, instance->port);
    err = DNSServiceRegister(&sdref, kDNSServiceFlagsUnique, advertise_interface,
                             instance->instance_name, instance->service_type, local_suffix,
                             instance->host->registered_name, htons(instance->port), instance->txt_length,
                             instance->txt_data, register_instance_completion, instance);
    // This would happen if we pass NULL for regtype, which we don't, or if we run out of memory, or if
    // the server isn't running; in the second two cases, we can always try again later.
    if (err != kDNSServiceErr_NoError) {
        // If we can, always send status to the client.
        if (instance->update != NULL) {
            if (instance->update->client == NULL &&
                (err == kDNSServiceErr_ServiceNotRunning || err == kDNSServiceErr_DefunctConnection))
            {
                INFO("DNSServiceRegister failed: " PUB_S_SRP ,
                     err == kDNSServiceErr_ServiceNotRunning ? "not running" : "defunct");
                service_disconnected(instance->host);
            } else {
                INFO("DNSServiceRegister failed: %d", err);
                update_failed(instance->update, dns_rcode_servfail, true);
            }
        }
        return false;
    }
    instance->txn = ioloop_dnssd_txn_add(sdref, instance, instance_txn_finalize_callback);
    if (instance->txn == NULL) {
        ERROR("register_instance: no memory.");
        DNSServiceRefDeallocate(sdref);
        return false;
    }
    if (instance->update != NULL) {
        instance->update->num_instances_started++;
    }
    return true;
}

#ifdef UNUSED
// When an update fails on some record, abandon_update is called to stop advertising the other records
// that were proposed in the update.  The state associated with the update is then freed.  The caller is
// responsible for sending the result back to the SRP client.   If anything was deleted by the update, it's
// also abandoned, which is somewhat problematic.
static void
abandon_update(adv_host_t *host)
{
    (void)host;
}

// When a registration that's been successfully added in the past is attempted, and fails in a way
// that indicates a conflict or unrecoverable error, we have to abandon it.  abandon_registration
// takes care of that.
static void
abandon_registration(adv_host_t *host)
{
    (void)host;
}
#endif

static void
start_service_updates(adv_host_t *host)
{
    int i;
    adv_update_t *update = host->updates;

    if (update == NULL) {
        ERROR("start_service_updates: no work to do.");
        return;
    }

    // For each service instance that's being added, register it.
    for (i = 0; i < update->add_instances->num; i++) {
        if (update->add_instances->vec[i] != NULL) {
            if (!register_instance(update->add_instances->vec[i])) {
                return;
            }
        }
    }
    // For each service instance that's being updated or deleted, delete it.
    if (update->update_instances->num != host->instances->num) {
        ERROR("start_service_updates: update instance count %d differs from host instance count %d",
              update->update_instances->num, host->instances->num);
        update_failed(update, dns_rcode_servfail, true);
        return;
    }
    if (update->remove_instances->num != host->instances->num) {
        ERROR("start_service_updates: delete instance count %d differs from host instance count %d",
              update->remove_instances->num, host->instances->num);
        update_failed(update, dns_rcode_servfail, true);
        return;
    }
    for (i = 0; i < host->instances->num; i++) {
        if (update->update_instances->vec[i] != NULL || update->remove_instances->vec[i] != NULL) {
            if (host->instances->vec[i]->txn != NULL) {
                ioloop_dnssd_txn_release(host->instances->vec[i]->txn);
                host->instances->vec[i]->txn = NULL;
            }
        }
        if (update->update_instances->vec[i] != NULL) {
            if (!register_instance(update->update_instances->vec[i])) {
                INFO("start_service_update: register instance failed.");
                return;
            }
        }
    }
    if (update->num_instances_started == 0) {
        INFO("start_service_update: no service updates, so we're finished.");
        update_finished(update);
    }
}

// When we get a late name conflict on the hostname, we need to update the host registration and all of the
// service registrations. To do this, we construct an update and then apply it. If there is already an update
// in progress, we put this update at the end of the list.
static void
update_from_host(adv_host_t *host)
{
    adv_update_t *update = NULL;
    int i;

    // Allocate the update structure.
    update = calloc(1, sizeof *update);
    if (update == NULL) {
        ERROR("update_from_host: no memory for update.");
        goto fail;
    }

    update->add_addresses = calloc(host->num_addresses, sizeof (*update->add_addresses));
    if (update->add_addresses == NULL) {
        ERROR("update_from_host: no memory for addresses");
        goto fail;
    }
    update->num_add_addresses = 0;

    // Copy all of the addresses in the host into add_addresses
    for (i = 0; i < host->num_addresses; i++) {
        if (host->addresses[i] != NULL) {
            update->add_addresses[update->num_add_addresses] = host->addresses[i];
            RETAIN_HERE(update->add_addresses[update->num_add_addresses]);
            update->num_add_addresses++;
        }
    }

    // We can never update more instances than currently exist for this host.
    update->update_instances = adv_instance_vec_copy(host->instances);
    for (i = 0; i < update->update_instances->num; i++) {
        if (update->update_instances->vec[i] != NULL) {
           update->update_instances->vec[i]->update = update;
        }
    }

    // We aren't actually adding or deleting any instances, but...
    update->remove_instances = adv_instance_vec_create(host->instances->num);
    if (update->remove_instances == NULL) {
        ERROR("update_from_host: no memory for remove_instances");
        goto fail;
    }
    update->remove_instances->num = host->instances->num;

    update->add_instances = adv_instance_vec_create(host->instances->num);
    if (update->add_instances == NULL) {
        ERROR("update_from_host: no memory for add_instances");
        goto fail;
    }
    update->add_instances->num = host->instances->num;

    // At this point we have figured out all the work we need to do, so hang it off an update structure.
    update->host = host;
    update->num_remove_addresses = 0;
    update->num_add_addresses = host->num_addresses;
    update->host_lease = host->lease_interval;
    update->key_lease = host->key_lease;
    update->lease_expiry = host->lease_expiry;

    // The only time we can expect this to happen is as a result of a retry, in which case we want to
    // get the host back to its correct state before continuing.
    update->next = host->updates;
    host->updates = update;
    start_host_update(host);
    return;

fail:
    update_finalize(update);
    wait_retry(host);
    return;
}

// If we get a name conflict, we need to choose a new name for the host.
static void
try_new_hostname(adv_host_t *host)
{
    char *s, *t;
    char separator = '-';
    char namebuf[DNS_MAX_LABEL_SIZE_ESCAPED];

    t = namebuf;
    for (s = host->name; *s; s++) {
        if (*s == '.') {
            *t = 0;
            break;
        }
        if (t - namebuf >= DNS_MAX_LABEL_SIZE_ESCAPED - 13) { // 13: "-12345.local\0"
            *t = 0;
            ERROR("try_new_hostname: truncating " PRI_S_SRP " to " PRI_S_SRP, host->name, namebuf);
            break;
        }
        if (*s == '\\') {
            if (s[1] == 0 || s[2] == 0 || s[3] == 0) {
                ERROR("try_new_hostname: escaped hostname " PRI_S_SRP " is invalid", host->name);
                *t = 0;
                break;
            }
            *t++ = *s++;
            *t++ = *s++;
            *t++ = *s++;
            *t++ = *s;
            continue;
        }
        if (*s == ' ' || *s == '-' || *s == '_') {
            separator = *s;
        }
        *t++ = *s;
    }
    INFO("try_new_hostname: using base name %s", namebuf);
    // Append a random number to the end of the name.
    host->name_serial = srp_random16();
    snprintf(t, 13, "-%d.local", host->name_serial);
    INFO("try_new_hostname: using full name %s", namebuf);

    if (host->registered_name != host->name) {
        free(host->registered_name);
    }
    host->registered_name = strdup(namebuf);
    if (host->registered_name == NULL) {
        ERROR("try_new_hostname: No memory for alternative name for " PRI_S_SRP ": " PRI_S_SRP, host->name, namebuf);
        // We pretty much can't do anything at this point.
        lease_callback(host);
        return;
    }

    // Generate an update from the host entry and do it.
    update_from_host(host);
}

// When the host registration has completed, we get this callback.   Completion either means that we succeeded in
// registering the record, or that something went wrong and the registration has failed.
static void
register_host_completion(DNSServiceRef sdref, DNSRecordRef rref,
                         DNSServiceFlags flags, DNSServiceErrorType error_code, void *context)
{
    dnssd_txn_t *txn = context;
    adv_update_t *update = ioloop_dnssd_txn_get_aux_pointer(txn);
    adv_host_t *host = ioloop_dnssd_txn_get_context(txn);
    (void)sdref;
    (void)rref;
    (void)error_code;
    (void)flags;

    // It's possible that we could restart a host update due to an error while a callback is still pending on a stale
    // update.  In this case, we just cancel all of the work that's been done on the stale update (it's probably already
    // moot anyway.
    if (update != NULL && (host == NULL || host->updates != update)) {
        INFO("register_host_completion: registration for host completed with invalid state.");
        update_finalize(update);
        return;
    }

    if (host == NULL) {
        ERROR("register_host_completion called on null host.");
        return;
    }

    if (error_code == kDNSServiceErr_NoError) {
        // If we get here while a hostname update is pending, it means that the conflict was resolved when
        // we re-registered the host as a side effect of the update, so we no longer need to update the
        // hostname.
        host->hostname_update_pending = false;

        // Now that the hostname has been registered, we can register services that point at it.
        INFO("register_host_completion: registration for host " PRI_S_SRP " has completed.", host->registered_name);
        start_service_updates(host);
    } else {
        INFO("register_host_completion: registration for host " PRI_S_SRP " failed, status = %d", host->registered_name,
             error_code);
        if (update == NULL) {
            // We shouldn't get any error here other than a name conflict or daemon not running.
            // If we get a name conflict, that means that some other BR or host on the network has
            // started advertising the hostname we chose, so we need to choose a new name and fix
            // all of the service registrations.
            if (error_code == kDNSServiceErr_NameConflict) {
                if (host->updates != NULL || host->clients != NULL) {
                    host->hostname_update_pending = true;
                } else {
                    try_new_hostname(host);
                }
            }
        } else {
            if (error_code == kDNSServiceErr_NameConflict) {
                update_failed(update, dns_rcode_yxdomain, true);
            } else {
                update_failed(update, dns_rcode_servfail, true);
            }
        }
    }
}

static adv_instance_t *
adv_instance_create(service_instance_t *raw, adv_host_t *host, adv_update_t *update)
{
    char service_type[DNS_MAX_LABEL_SIZE_ESCAPED * 2 + 2]; // sizeof '.' + sizeof '\0'.
    char instance_name[DNS_MAX_NAME_SIZE_ESCAPED + 1];
    char *txt_data;

    // Allocate the raw registration
    adv_instance_t *instance = calloc(1, sizeof *instance);
    if (instance == NULL) {
        ERROR("adv_instance:create: unable to allocate raw registration struct.");
        return NULL;
    }
    RETAIN_HERE(instance);
    instance->host = host;
    instance->update = update;
    // SRV records have priority, weight and port, but DNSServiceRegister only uses port.
    instance->port = (raw->srv == NULL) ? 0 : raw->srv->data.srv.port;

    // Make a presentation-format version of the service name.
    extract_instance_name(instance_name, sizeof instance_name, service_type, sizeof service_type, raw);
    instance->instance_name = strdup(instance_name);
    if (instance->instance_name == NULL) {
        ERROR("adv_instance:create: unable to allocate instance name.");
        RELEASE_HERE(instance, adv_instance_finalize);
        return NULL;
    }
    instance->service_type = strdup(service_type);
    if (instance->service_type == NULL) {
        ERROR("adv_instance:create: unable to allocate instance type.");
        RELEASE_HERE(instance, adv_instance_finalize);
        return NULL;
    }

    // Allocate the text record buffer
    if (raw->txt != NULL) {
    txt_data = malloc(raw->txt->data.txt.len);
        if (txt_data == NULL) {
            RELEASE_HERE(instance, adv_instance_finalize);
            ERROR("adv_instance:create: unable to allocate txt_data buffer");
            return NULL;
        }
        // Format the txt buffer as required by DNSServiceRegister().
        memcpy(txt_data, raw->txt->data.txt.data, raw->txt->data.txt.len);
        instance->txt_data = txt_data;
        instance->txt_length = raw->txt->data.txt.len;
    } else {
        instance->txt_data = NULL;
        instance->txt_length = 0;
    }
    return instance;
}

#define adv_address_create(addr, host) \
    adv_address_create_(addr, host, __FILE__, __LINE__)
static adv_address_t *
adv_address_create_(host_addr_t *addr, adv_host_t *host, const char *file, int line)
{

    adv_address_t *new_addr = calloc(1, sizeof *new_addr);
    if (new_addr == NULL) {
        ERROR("adv_address_create: no memory for new_addr");
        return NULL;
    }
    new_addr->host = host;
    new_addr->rrtype = addr->rr.type;
    new_addr->rdlen = addr->rr.type == dns_rrtype_a ? 4 : 16;
    memcpy(new_addr->rdata, &addr->rr.data, new_addr->rdlen);
    RETAIN(new_addr);
    return new_addr;
}

// When we need to register a host with mDNSResponder, start_host_update is called.   This can be either because
// we just got a new registration for a host, or if the daemon dies and we need to re-do the host registration.
// This just registers the host; if that succeeds, then we register the service instances.
static void
start_host_update(adv_host_t *host)
{
    adv_update_t *update = host->updates;
    int err;
    bool remove_preexisting;
    uint8_t *add_rdata;
    uint16_t add_rrtype;
    uint16_t add_rdlen;
    adv_address_t *selected_addr = NULL, *preferred_addr = NULL;
    int i;
    adv_address_t *addr;

    // No work to do?
    if (host->updates == NULL) {
        ERROR("start_host_update: no work to do for host " PRI_S_SRP, host->registered_name);
        return;
    }

    // If we haven't published an address yet, or if we are going to remove the currently published address,
    // or if we have new addresses to add, then choose the address that is best suited, preferring recently
    // added addresses over existing addresses.
    remove_preexisting = false;
    add_rdata = NULL;
    add_rrtype = 0;
    add_rdlen = 0;

    // If the host address isn't about to be removed, and is an IPv6 address on the preferred prefix,
    // store it in preferred_addr for comparison and possible retention.
    if (preferred_prefix != NULL &&
        host->num_addresses > 0 && host->addresses[0] != NULL &&
        update->remove_addresses != NULL && update->remove_addresses[0] == NULL &&
        host->addresses[0]->rrtype == dns_rrtype_aaaa &&
        same_prefix(host->addresses[0]->rdata, &preferred_prefix->addr, preferred_prefix->width))
    {
        preferred_addr = host->addresses[0];
    }

    if ((host->num_addresses != 0 && update->remove_addresses != NULL && update->remove_addresses[0] != NULL) ||
        update->num_add_addresses != 0)
    {
        if (preferred_prefix != NULL) {
            for (i = 0; i < update->num_add_addresses; i++) {
                addr = update->add_addresses[i];
                if (// there is an address
                    addr != NULL && addr->rrtype == dns_rrtype_aaaa &&
                    // it's on the preferred prefix
                    same_prefix(addr->rdata, &preferred_prefix->addr, preferred_prefix->width))
                {
                    // If this address is the same as the currently selected address, we don't need
                    // to add it.  Preferred_addr is always a AAAA.
                    if (preferred_addr != NULL && preferred_addr->rrtype == dns_rrtype_aaaa &&
                        !memcmp(addr->rdata, preferred_addr->rdata, 16))
                    {
                        selected_addr = preferred_addr;
                    }
                    // But if the current address is not preferred, or there isn't one, then choose this
                    // address.   If there's more than one address in the preferred prefix, we choose the first
                    // one we come to.  SRP client should not be sending temporary addresses or deprecated addresses.
                    else {
                        selected_addr = addr;
                        remove_preexisting = true;
                        break;
                    }
                }
            }
        }
    }

    // If none of the new addresses were different than the current address and in the preferred prefix,
    // keep the current address.
    if (selected_addr == NULL &&
        host->num_addresses > 0 && host->addresses[0] != NULL &&
        update->remove_addresses != NULL && update->remove_addresses[0] == NULL)
    {
        selected_addr = host->addresses[0];
        remove_preexisting = false;
        update->registering_key = false;
    }

    // If the current address is being removed, and we don't have a new address in the preferred
    // prefix, just use the first address in the add list.
    if (selected_addr == NULL) {
        for (i = 0; i < update->num_add_addresses; i++) {
            if (update->add_addresses[i] != NULL) {
                selected_addr = update->add_addresses[i];
                remove_preexisting = true;
                break;
            }
        }
        // If there's no new address, see if there's an old address we didn't use before.
        if (selected_addr == NULL) {
            for (i = 1; i < host->num_addresses; i++) {
                addr = host->addresses[i];
                if (addr != NULL)
                {
                    selected_addr = addr;
                    remove_preexisting = true;
                    break;
                }
            }
        }
    }

    // If we didn't find an address, we're just deleting the address.
    if (selected_addr == NULL) {
        INFO("start_host_update: No address was selected.");
        remove_preexisting = true;
        add_rdata = host->key_rdata;
        add_rrtype = dns_rrtype_key;
        add_rdlen = host->key_rdlen;
        update->registering_key = true;
    } else {
        // We don't need to update the host address if it didn't change.
        if (remove_preexisting) {
            if (host->num_addresses > 0) {
                INFO("start_host_update: Replacing existing address %p.", selected_addr);
            } else {
                INFO("start_host_update: Adding new address %p.", selected_addr);
            }
            add_rdata = selected_addr->rdata;
            add_rrtype = selected_addr->rrtype;
            add_rdlen = selected_addr->rdlen;
        } else {
            INFO("start_host_update: Retaining existing address.");
        }
        update->registering_key = false;
        if (update->selected_addr != NULL) {
            RELEASE_HERE(update->selected_addr, adv_address_finalize);
        }
        update->selected_addr = selected_addr;
        RETAIN_HERE(update->selected_addr);
    }
    INFO("update->selected_addr = %p", update->selected_addr);

    // At present, the DNSService* API doesn't provide a clean way to update a record registered with
    // DNSServiceRegisterRecord, because it assumes that you'd only ever want to update it with a record
    // of the same type.   We can't use that, so we just remove the record (if it exists) and then add
    // the intended record.
    if (remove_preexisting && host->txn != NULL) {
        ioloop_dnssd_txn_release(host->txn);
        host->txn = NULL;
    }

    // If we don't think we have a connection, make one.
    if (host->txn == NULL) {
        DNSServiceRef sdref;
        err = DNSServiceCreateConnection(&sdref);
        // In principle the only way this can fail is if the daemon isn't running.
        if (err != kDNSServiceErr_NoError) {
            // If this is a "no memory" error, that actually means that we've run out of file descriptors.
            // This should never happen, but if it does, we can't really continue to function; it's better to
            // exit and restart.
            if (err == kDNSServiceErr_NoMemory) {
                ERROR("Out of file descriptors--quitting.");
                abort(); // So that we get a crash report
            }
            // If this is a new update, just send a response to the client.  Otherwise maybe try to re-add it.
            if (update->client != NULL) {
                ERROR("DNSServiceCreateConnection: something went wrong: %d.", err);
                update_failed(update, dns_rcode_servfail, true);
            } else if (err == kDNSServiceErr_DefunctConnection || err == kDNSServiceErr_ServiceNotRunning) {
                ERROR("DNSServiceCreateConnection: " PUB_S_SRP ".",
                      err == kDNSServiceErr_DefunctConnection ? "defunct connection" : "service not running");
                service_disconnected(host);
            } else if (err != kDNSServiceErr_NoError) {
                ERROR("DNSServiceCreateConnection: something went wrong: %d.", err);
                wait_retry(host);
            }
            return;
        }
        INFO("Adding transaction %p", sdref);
        host->txn = ioloop_dnssd_txn_add(sdref, host, host_txn_finalize_callback);
        if (host->txn == NULL) {
            ERROR("start_host_update: no memory for host transaction");
            if (update->client != NULL) {
                update_failed(update, dns_rcode_servfail, true);
            } else {
                wait_retry(host);
            }
            return;
        }
    }

    if (add_rdata != NULL) {
        INFO("start_host_update: DNSServiceRegisterRecord(%p %p %d %d %p %d %d %d %p %d %p %p)",
             host ? (host->txn ? host->txn->sdref : 0) : 0, host ? &host->rref : 0,
             kDNSServiceFlagsUnique | kDNSServiceFlagsNoAutoRename,
             advertise_interface, host ? host->registered_name : 0,
             add_rrtype, dns_qclass_in, add_rdlen, add_rdata, 3600,
             register_host_completion, host ? host->txn : 0);
        ioloop_dnssd_txn_set_aux_pointer(host->txn, update);
        err = DNSServiceRegisterRecord(host->txn->sdref, &host->rref,
                                       kDNSServiceFlagsUnique | kDNSServiceFlagsNoAutoRename,
                                       advertise_interface, host->registered_name,
                                       add_rrtype, dns_qclass_in, add_rdlen, add_rdata, 3600,
                                       register_host_completion, host->txn);
        if (err != kDNSServiceErr_NoError) {
            ERROR("start_host_update: DNSServiceRegisterRecord failed on host: %d", err);
            if (update->client != NULL) {
                update_failed(update, dns_rcode_servfail, true);
                return;
            } else if (err == kDNSServiceErr_DefunctConnection || err == kDNSServiceErr_ServiceNotRunning) {
                service_disconnected(host);
                return;
            }
        }
    }
    // If we didn't have to do an add, start the service updates immediately.
    else {
        INFO("start_host_update: no host address rdata, so no host update");
        start_service_updates(host);
    }
    return;
}

// When a host has no update in progress, and there is a client update ready to process, we need to analyze
// the client update to see what work needs to be done.  This work is constructed as an translation from the
// raw update sent by the client (host->clients) into a prepared update that can be used directly to
// register the information with mDNSResponder.
//
// Normally a host will only have one prepared update in progress; however, if we lose our connection to
// mDNSResponder, then we need to re-create the host advertisement.  If there was an update in progress when
// this happened, we then need to reapply that as well.  In this case an update is constructed from the host, to
// get the host into the intended state, and the in-progress update is pushed below that; when the host has
// been re-created on the daemon, the pending update is popped back off the stack and restarted.
static void
prepare_update(adv_host_t *host)
{
    host_addr_t *addr;
    int i, j;
    service_instance_t *instance;
    adv_address_t **remove_addrs = NULL;
    int num_remove_addrs = 0;
    adv_address_t **add_addrs = NULL;
    int num_add_addrs = 0;
    int num_update_instances = 0;
    int num_add_instances = 0;
    int num_remove_instances = 0;
    adv_instance_vec_t *update_instances = NULL, *add_instances = NULL, *remove_instances = NULL;
    client_update_t *client_update = host->clients;
    adv_update_t *update = NULL;

    // Work to do:
    // - Figure out what address records to add and what address records to delete.
    // - Because we can only have one address record at a time currently, figure out which address record we want
    // - If we already have an address record published, and it's the same, do nothing
    //   - else if we already have an address record published, and it's changed to a different address, do an update
    //   - else if we have a new address record, publish it
    //   - else publish the key to hold the name
    // - Go through the set of service instances, identifying deletes, changes and adds
    //   - We don't currently allow deletes, but what that would look like would be an instance with no SRV or TXT
    //     record.
    //   - What about a delete that keeps the name but un-advertises the service?   How would we indicate that?
    //     Maybe if there's no service PTR for the service?
    //   - Changes means that the contents of the text record changed, or the contents of the SRV record
    //     changed (but not the hostname) or both.
    //   - New means that we don't have a service with that service instance name on the host (and we previously
    //     eliminated the possibility that it exists on some other host).

    // Allocate the update structure.
    update = calloc(1, sizeof *update);
    if (update == NULL) {
        ERROR("prepare_update: no memory for update.");
        goto fail;
    }

    // The maximum number of addresses we could be deleting is all the ones the host currently has.
    num_remove_addrs = host->num_addresses;
    if (num_remove_addrs != 0) {
        remove_addrs = calloc(num_remove_addrs, sizeof *remove_addrs);
        // If we can't allocate space, just wait a bit.
        if (remove_addrs == NULL) {
            ERROR("prepare_update: no memory for remove_addrs");
            goto fail;
        }
    } else {
        remove_addrs = NULL;
    }

    num_add_addrs = 0;
    for (addr = client_update->host->addrs; addr != NULL; addr = addr->next) {
        num_add_addrs++;
    }
    add_addrs = calloc(num_add_addrs, sizeof *add_addrs);
    if (add_addrs == NULL) {
        ERROR("prepare_update: no memory for add_addrs");
        goto fail;
    }

    // Copy all of the addresses in the update into add_addresses
    num_add_addrs = 0;
    for (addr = client_update->host->addrs; addr; addr = addr->next) {
        adv_address_t *prepared_address = adv_address_create(addr, host);
        if (prepared_address == NULL) {
            ERROR("prepare_update: No memory for prepared address");
            goto fail;
        }
        add_addrs[num_add_addrs++] = prepared_address;
    }

    // For every host address, see if it's in add_addresses.   If it's not, it needs to be removed.
    // If it is, it doesn't need to be added.
    if (num_remove_addrs != 0) {
        memcpy(remove_addrs, host->addresses, num_remove_addrs * sizeof *remove_addrs);
        for (i = 0; i < num_remove_addrs; i++) {
            if (host->addresses[i] != NULL) {
                remove_addrs[i] = host->addresses[i];
                RETAIN_HERE(remove_addrs[i]);
            }
            for (j = 0; j < num_add_addrs; j++) {
                // If the address is present in both places, remove it from the list of addresses to
                // add, and also remove it from the list of addresses to remove.   When we're done,
                // all that will be remaining in the list to remove will be addresses that weren't present
                // in the add list.
                if (remove_addrs[i] != NULL && add_addrs[j] != NULL &&
                    add_addrs[j]->rrtype == remove_addrs[i]->rrtype &&
                    !memcmp(&add_addrs[j]->rdata, remove_addrs[i]->rdata, remove_addrs[i]->rdlen))
                {
                    RELEASE_HERE(remove_addrs[i], adv_address_finalize);
                    remove_addrs[i] = NULL;
                    RELEASE_HERE(add_addrs[j], adv_address_finalize);
                    add_addrs[j] = NULL;
                }
            }
        }
    }

    // We can never update more instances than currently exist for this host.
    num_update_instances = host->instances->num;
    num_remove_instances = host->instances->num;

    update_instances = adv_instance_vec_create(num_update_instances);
    if (update_instances == NULL) {
        ERROR("prepare_update: no memory for update_instances");
        goto fail;
    }
    update_instances->num = num_update_instances;

    // We aren't actually deleting any instances, but...
    remove_instances = adv_instance_vec_create(num_remove_instances);
    if (remove_instances == NULL) {
        ERROR("prepare_update: no memory for remove_instances");
        goto fail;
    }
    remove_instances->num = num_remove_instances;

    // The number of instances to add can be as many as there are instances in the update.
    num_add_instances = 0;
    for (instance = client_update->instances; instance; instance = instance->next) {
        num_add_instances++;
    }
    add_instances = adv_instance_vec_create(num_add_instances);
    if (add_instances == NULL) {
        ERROR("prepare_update: no memory for add_instances");
        goto fail;
    }

    // Convert all of the instances in the client update to adv_instance_t structures for easy comparison.
    // Any that are unchanged will have to be freed--oh well.
    i = 0;
    for (instance = client_update->instances; instance != NULL; instance = instance->next) {
        adv_instance_t *prepared_instance = adv_instance_create(instance, host, update);
        if (prepared_instance == NULL) {
            // prepare_instance logs.
            goto fail;
        }
        if (i >= num_add_instances) {
            ERROR("prepare_update: while preparing client update instances, i >= num_add_instances");
            goto fail;
        }
        add_instances->vec[i++] = prepared_instance;
    }
    add_instances->num = i;

    // The instances in the update are now in add_instances.  If they are updates, move them to update_instances.
    // If they are unchanged, free them and null them out.   If they are adds, leave them.
    for (i = 0; i < num_add_instances; i++) {
        adv_instance_t *add_instance = add_instances->vec[i];

        if (add_instance != NULL) {
            for (j = 0; j < host->instances->num; j++) {
                adv_instance_t *host_instance = host->instances->vec[j];

                // See if the instance names match.
                if (host_instance != NULL &&
                    !strcmp(add_instance->instance_name, host_instance->instance_name) &&
                    !strcmp(add_instance->service_type, host_instance->service_type))
                {
                    // If the rdata is the same, it's not an add or an update.
                    if (add_instance->txt_length == host_instance->txt_length &&
                        add_instance->port == host_instance->port &&
                        (add_instance->txt_length == 0 ||
                         !memcmp(add_instance->txt_data, host_instance->txt_data, add_instance->txt_length)))
                    {
                        RELEASE_HERE(add_instance, adv_instance_finalize);
                    } else {
                        // Implicit RETAIN/RELEASE
                        update_instances->vec[j] = add_instance;
                    }
                    add_instances->vec[i] = NULL;
                    break;
                }
            }
        }
    }

    // At this point we have figured out all the work we need to do, so hang it off an update structure.
    update->host = host;
    update->client = client_update;
    host->clients = client_update->next;
    update->num_remove_addresses = num_remove_addrs;
    update->remove_addresses = remove_addrs;
    update->num_add_addresses = num_add_addrs;
    update->add_addresses = add_addrs;
    update->remove_instances = remove_instances;
    update->add_instances = add_instances;
    update->update_instances = update_instances;
    update->host_lease = client_update->host_lease;
    update->key_lease = client_update->key_lease;

    update->next = host->updates;
    host->updates = update;

    start_host_update(host);
    return;

fail:
    if (remove_addrs != NULL) {
        // Addresses in remove_addrs are owned by the host and don't need to be freed.
        free(remove_addrs);
    }
    if (add_addrs != NULL) {
        // Addresses in add_addrs are ours, so we have to free them.
        for (i = 0; i < num_add_addrs; i++) {
            if (add_addrs[i] != NULL) {
                RELEASE_HERE(add_addrs[i], adv_address_finalize);
            }
        }
        free(add_addrs);
    }
    if (add_instances != NULL) {
        RELEASE_HERE(add_instances, adv_instance_vec_finalize);
        add_instances = NULL;
    }
    if (remove_instances != NULL) {
        RELEASE_HERE(remove_instances, adv_instance_vec_finalize);
        remove_instances = NULL;
    }
    if (update_instances != NULL) {
        RELEASE_HERE(update_instances, adv_instance_vec_finalize);
        update_instances = NULL;
    }
    if (update) {
        if (update->client != NULL) {
            update->client->next = host->clients;
            host->clients = update->client;
        }
        free(update);
    }

    // Try again sometime later.
    wait_retry(host);
}

typedef enum { missed, match, conflict } instance_outcome_t;
static instance_outcome_t
compare_instance(adv_instance_t *instance,
                 dns_host_description_t *new_host, adv_host_t *host,
                 char *instance_name, char *service_type)
{
    if (instance == NULL) {
        return missed;
    }
    if (!strcmp(instance_name, instance->instance_name) && !strcmp(service_type, instance->service_type)) {
        if (!dns_names_equal_text(new_host->name, host->name)) {
            return conflict;
        }
        return match;
    }
    return missed;
}

bool
srp_update_start(comm_t *connection, dns_message_t *parsed_message, message_t *raw_message,
                 dns_host_description_t *new_host, service_instance_t *instances, service_t *services,
                 dns_name_t *update_zone, uint32_t lease_time, uint32_t key_lease_time)
{
    adv_host_t *host, **p_hosts = NULL;
    char pres_name[DNS_MAX_NAME_SIZE_ESCAPED + 1];
    int i;
    service_instance_t *new_instance, *client_instance;
    instance_outcome_t outcome = missed;
    adv_update_t *update;
    client_update_t *client_update, **p_client_update;
    char instance_name[DNS_MAX_LABEL_SIZE_ESCAPED + 1];
    char service_type[DNS_MAX_LABEL_SIZE_ESCAPED * 2 + 2];
    uint32_t key_id = 0;
    char new_host_name[DNS_MAX_NAME_SIZE_ESCAPED + 1];
    host_addr_t *addr;
    const bool remove = lease_time == 0;
    const char *updatestr = lease_time == 0 ? "remove" : "update";
    dns_name_print(new_host->name, new_host_name, sizeof new_host_name);

    // Compute a checksum on the key, ignoring up to three bytes at the end.
    for (i = 0; i < new_host->key->data.key.len; i += 4) {
        key_id += ((new_host->key->data.key.key[i] << 24) | (new_host->key->data.key.key[i + 1] << 16) |
                   (new_host->key->data.key.key[i + 2] << 8) | (new_host->key->data.key.key[i + 3]));
    }

    // Log the update info.
    INFO("srp_update_start: host update for " PRI_S_SRP ", key id %" PRIx32, new_host_name, key_id);
    for (addr = new_host->addrs; addr != NULL; addr = addr->next) {
        if (addr->rr.type == dns_rrtype_a) {
            IPv4_ADDR_GEN_SRP(&addr->rr.data.a.s_addr, addr_buf);
            INFO("srp_update_start: host " PUB_S_SRP " for " PRI_S_SRP ", address " PRI_IPv4_ADDR_SRP, updatestr,
                 new_host_name, IPv4_ADDR_PARAM_SRP(&addr->rr.data.a.s_addr, addr_buf));
        } else {
            SEGMENTED_IPv6_ADDR_GEN_SRP(addr->rr.data.aaaa.s6_addr, addr_buf);
            INFO("srp_update_start: host " PUB_S_SRP " for " PRI_S_SRP ", address " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 updatestr, new_host_name, SEGMENTED_IPv6_ADDR_PARAM_SRP(addr->rr.data.aaaa.s6_addr, addr_buf));
        }
    }
    for (new_instance = instances; new_instance != NULL; new_instance = new_instance->next) {
        extract_instance_name(instance_name, sizeof instance_name, service_type, sizeof service_type, new_instance);
        INFO("srp_update_start: host " PUB_S_SRP " for " PRI_S_SRP ", instance name " PRI_S_SRP ", type " PRI_S_SRP
             ", port %d", updatestr, new_host_name, instance_name, service_type,
             new_instance->srv != NULL ? new_instance->srv->data.srv.port : -1);
    }

    // SRP doesn't currently support removal.   I think it needs to, but I'm going to mostly leave that
    // out of this code for now.

    // Look for matching service instance names.   A service instance name that matches, but has a different
    // hostname, means that there is a conflict.   We have to look through all the entries; the presence of
    // a matching hostname doesn't mean we are done UNLESS there's a matching service instance name pointing
    // to that hostname.
    for (host = hosts; host; host = host->next) {
        // We need to look for matches both in the registered instances for this registration, and also in
        // the list of new instances, in case we get a duplicate update while a previous update is in progress.
        for (new_instance = instances; new_instance; new_instance = new_instance->next) {
            extract_instance_name(instance_name, sizeof instance_name, service_type, sizeof service_type, new_instance);

            // First check for a match or conflict in the host itself.
            for (i = 0; i < host->instances->num; i++) {
                outcome = compare_instance(host->instances->vec[i], new_host, host,
                                           instance_name, service_type);
                if (outcome != missed) {
                    goto found_something;
                }
            }
            // Then look for the same thing in any subsequent updates that have been baked.
            for (update = host->updates; update; update = update->next) {
                for (i = 0; i < update->add_instances->num; i++) {
                    outcome = compare_instance(update->add_instances->vec[i], new_host, host,
                                               instance_name, service_type);
                    if (outcome != missed) {
                        goto found_something;
                    }
                }
            }
            // Finally, look for it in any updates that _haven't_ been baked.
            for (client_update = host->clients; client_update; client_update = client_update->next) {
                for (client_instance = client_update->instances; client_instance;
                     client_instance = client_instance->next) {
                    if (dns_names_equal(client_instance->name, new_instance->name)) {
                        if (!dns_names_equal_text(new_host->name, host->name)) {
                            outcome = conflict;
                        } else {
                            outcome = match;
                        }
                        goto found_something;
                    }
                }
            }
        }
    }
found_something:
    if (outcome == conflict) {
        ERROR("srp_update_start: service instance name " PRI_S_SRP "/" PRI_S_SRP " already pointing to host "
              PRI_S_SRP ", not host " PRI_S_SRP, instance_name, service_type, host->name, new_host_name);
        advertise_finished(connection, raw_message, dns_rcode_yxdomain, NULL);
        goto cleanup;
    }

    // If we fall off the end looking for a matching service instance, there isn't a matching
    // service instance, but there may be a matching host, so look for that.
    if (outcome == missed) {
        for (p_hosts = &hosts; *p_hosts; p_hosts = &host->next) {
            host = *p_hosts;
            if (dns_names_equal_text(new_host->name, host->name)) {
                if (key_id == host->key_id && dns_keys_rdata_equal(new_host->key, &host->key)) {
                    outcome = match;
                    break;
                }
                ERROR("srp_update_start: update for host " PRI_S_SRP " has key id %" PRIx32
                      " which doesn't match host key id %" PRIx32 ".",
                      host->name, key_id, host->key_id);
                advertise_finished(connection, raw_message, dns_rcode_yxdomain, NULL);
                goto cleanup;
            }
        }
    } else {
        if (key_id != host->key_id || !dns_keys_rdata_equal(new_host->key, &host->key)) {
            ERROR("srp_update_start: new host with name " PRI_S_SRP " and key id %" PRIx32
                  " conflicts with existing host %s with key id %" PRIx32,
                  new_host_name, key_id, host->name, host->key_id);
            advertise_finished(connection, raw_message, dns_rcode_yxdomain, NULL);
            goto cleanup;
        }
    }

    // If we didn't find a matching host, we can make a new one.   When we create it, it just has
    // a name and no records.  The update that we then construct will have the missing records.
    // We don't want to do this for a remove, obviously.
    if (outcome == missed) {
        if (remove) {
            ERROR("Remove for host " PRI_S_SRP " which doesn't exist.", new_host_name);
            advertise_finished(connection, raw_message, dns_rcode_nxdomain, NULL);
            goto cleanup;
        }

        host = calloc(1, sizeof *host);
        if (host == NULL) {
            ERROR("srp_update_start: no memory for host data structure.");
            advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
            goto cleanup;
        }
        host->instances = adv_instance_vec_create(0);
        if (host->instances == NULL) {
            ERROR("srp_update_start: no memory for host instance vector.");
            advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
            host_finalize(host);
            goto cleanup;
        }

        host->retry_wakeup = ioloop_wakeup_create();
        if (host->retry_wakeup != NULL) {
            host->lease_wakeup = ioloop_wakeup_create();
        }
        if (host->lease_wakeup == NULL) {
            ERROR("srp_update_start: no memory for wake event on host");
            advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
            host_finalize(host);
            goto cleanup;
        }
        dns_name_print(new_host->name, pres_name, sizeof pres_name);
        host->name = strdup(pres_name);
        if (host->name == NULL) {
            host_finalize(host);
            ERROR("srp_update_start: no memory for hostname.");
            advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
            goto cleanup;
        }
        host->key = *new_host->key;
#ifndef __clang_analyzer__
        // Normally this would be invalid, but we never use the name of the key record.
        host->key.name = NULL;
#endif
        host->key_rdlen = new_host->key->data.key.len + 4;
        host->key_rdata = malloc(host->key_rdlen);
        if (host->key_rdata == NULL) {
            host_finalize(host);
            ERROR("srp_update_start: no memory for host key.");
            advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
            goto cleanup;
        }
        memcpy(host->key_rdata, &new_host->key->data.key.flags, 2);
        host->key_rdata[2] = new_host->key->data.key.protocol;
        host->key_rdata[3] = new_host->key->data.key.algorithm;
        memcpy(&host->key_rdata[4], new_host->key->data.key.key, new_host->key->data.key.len);
        host->key.data.key.key = &host->key_rdata[4];
        host->key_id = key_id;

        // Tack this on to the end of the list.  The if test is because the optimizer doesn't notice
        // that p_hosts can never be null here--it will always be pointing to the end of the list of
        // hosts if we get here.
        if (p_hosts != NULL) {
            *p_hosts = host;
        }
        p_hosts = NULL;
    }

    // See if this is a retransmission.
    for (update = host->updates; update; update = update->next) {
        if (update->client != NULL &&
            update->client->message->wire.id == raw_message->wire.id) {
        retransmission:
            INFO("srp_update_start: dropping retransmission of in-progress update for host " PRI_S_SRP, host->name);
        cleanup:
            srp_update_free_parts(instances, NULL, services, new_host);
            dns_message_free(parsed_message);
            return true;
        }
    }
    // Do the same for client updates.
    for (p_client_update = &host->clients; *p_client_update; p_client_update = &client_update->next) {
        client_update = *p_client_update;
        if (client_update->message->wire.id == raw_message->wire.id) {
            goto retransmission;
        }
    }

    // If this is a remove, just remove the host.
    if (remove) {
        lease_callback(host);
        advertise_finished(connection, raw_message, dns_rcode_noerror, NULL);
        goto cleanup;
    }

    // At this point we have an update and a host to which to apply it.  We may already be doing an earlier
    // update, or not.  Create a client update structure to hold the communication, so that when we are done,
    // we can respond.
    client_update = calloc(1, sizeof *client_update);
    if (client_update == NULL) {
        ERROR("srp_update_start: no memory for host data structure.");
        advertise_finished(connection, raw_message, dns_rcode_servfail, NULL);
        goto cleanup;
    }

    if (outcome == missed) {
        INFO("srp_update_start: New host " PRI_S_SRP ", key id %" PRIx32 , host->name, host->key_id);
    } else {
        if (host->registered_name != host->name) {
            INFO("srp_update_start: Renewing host " PRI_S_SRP ", alias %s, key id %" PRIx32,
                 host->name, host->registered_name, host->key_id);
        } else {
            INFO("srp_update_start: Renewing host " PRI_S_SRP ", key id %" PRIx32, host->name, host->key_id);
        }
    }

    if (host->registered_name == NULL) {
        host->registered_name = host->name;
    }

    client_update->connection = connection;
    ioloop_comm_retain(client_update->connection);
    client_update->parsed_message = parsed_message;
    client_update->message = raw_message;
    ioloop_message_retain(client_update->message);
    client_update->host = new_host;
    client_update->instances = instances;
    client_update->services = services;
    client_update->update_zone = update_zone;
    if (lease_time < max_lease_time) {
        if (lease_time < min_lease_time) {
            client_update->host_lease = min_lease_time;
        } else {
            client_update->host_lease = lease_time;
        }
    } else {
        client_update->host_lease = max_lease_time;
    }
    if (key_lease_time < max_lease_time * 7) {
        client_update->key_lease = key_lease_time;
    } else {
        client_update->key_lease = max_lease_time * 7;
    }
    *p_client_update = client_update;

    // If we aren't already applying an update to this host, apply this update now.
    if (host->updates == NULL) {
        INFO("srp_update_start: No ongoing host update: preparing this update to be applied.");
        prepare_update(host);
    } else {
        INFO("srp_update_start: waiting for existing update to complete on host " PRI_S_SRP " before applying another.",
             host->name);
    }
    return true;
}

#if defined(IOLOOP_MACOS)
static bool
adv_proxy_enable(xpc_object_t request, xpc_connection_t connection)
{
    srp_xpc_client_t *client, **p_client;
    xpc_object_t response;
    int err = kDNSSDAdvertisingProxyStatus_NoError;

    response = xpc_dictionary_create_reply(request);
    if (response == NULL) {
        ERROR("adv_proxy_enable: Unable to create reply dictionary.");
        return false;
    }

    client = calloc(1, sizeof(*client));
    if (client == NULL) {
        ERROR("adv_proxy_enable: unable to allocate client state structure.");
        err = kDNSSDAdvertisingProxyStatus_NoMemory;
        goto out;
    }
    if (srp_wanted == NULL) {
        srp_wanted = calloc(1, sizeof(*srp_wanted));
        if (srp_wanted == NULL) {
            free(client);
            ERROR("adv_proxy_enable: unable to allocate srp_wanted structure.");
            err = kDNSSDAdvertisingProxyStatus_NoMemory;
            goto out;
        }
        srp_wanted->transaction = os_transaction_create("com.apple.srp-mdns-proxy.ostransaction");
        INFO("Wanted.");
        thread_network_startup();
    }
    RETAIN_HERE(srp_wanted);

    client->connection = connection;
    xpc_retain(client->connection);
    client->enabler = true;

    INFO("adv_proxy_enable: connection from client: %p", client);

    // Find the end of the list.
    for (p_client = &srp_xpc_clients; *p_client != NULL; p_client = &(*p_client)->next) {
    }

    *p_client = client;
out:
    xpc_dictionary_set_uint64(response, kDNSAdvertisingProxyResponseStatus, err);
    xpc_connection_send_message(connection, response);
    xpc_release(response);
    if (err == kDNSSDAdvertisingProxyStatus_NoError) {
        return true;
    }
    return false;
}

static void
srp_wanted_finalize(srp_wanted_state_t *__unused wanted)
{
    INFO("adv_proxy_enable: No longer wanted.");
    os_release(srp_wanted->transaction);
    free(srp_wanted);
    srp_wanted = NULL;
    thread_network_shutdown();
}

static void
adv_xpc_connection_delete(xpc_connection_t connection)
{
    srp_xpc_client_t **p_client, *client;

    for (p_client = &srp_xpc_clients; *p_client != NULL; ) {
        client = *p_client;
        if (client->connection == connection) {
            xpc_release(client->connection);
            if (client->enabler) {
                RELEASE_HERE(srp_wanted, srp_wanted_finalize);
            }
            *p_client = client->next;
            INFO("adv_xpc_connection_delete: deleting client: %p", client);
            free(client);
            return;
        }
        p_client = &(*p_client)->next;
    }
}

void
adv_xpc_disconnect(void)
{
    srp_xpc_client_t *client;

    for (client = srp_xpc_clients; client != NULL; client = client->next) {
        if (client->connection != NULL && !client->connection_canceled) {
            INFO("adv_xpc_disconnect: disconnecting " PUB_S_SRP "client: %p", client->enabler ? "enabler " : "",
                 client);
            client->connection_canceled = true;
            xpc_connection_cancel(client->connection);
        }
    }
}

static bool adv_xpc_message(xpc_connection_t NULLABLE connection, xpc_object_t NULLABLE request);

static wakeup_t *adv_xpc_wakeup;

static void
adv_xpc_restart(void *__unused context)
{
    xpc_listener = ioloop_create_xpc_service(kDNSAdvertisingProxyService, adv_xpc_message);
    if (xpc_listener == NULL) {
        ioloop_add_wake_event(adv_xpc_wakeup, NULL, adv_xpc_restart, NULL, 10000);
    }
}

static bool
adv_xpc_list_services(xpc_connection_t request, xpc_object_t connection)
{
    xpc_object_t instances = xpc_array_create(NULL, 0);
    adv_host_t *host;
    xpc_object_t response;
    int i;
    char addrbuf[INET6_ADDRSTRLEN];
    int64_t now = ioloop_timenow();
    bool sent = false;
    adv_instance_t *instance = NULL;

    if (instances == NULL) {
        ERROR("adv_xpc_list_services: Unable to create service array");
        return false;
    }

    response = xpc_dictionary_create_reply(request);
    if (response == NULL) {
        ERROR("adv_xpc_list_services: Unable to create reply dictionary.");
        return false;
    }
    xpc_dictionary_set_uint64(response, kDNSAdvertisingProxyResponseStatus, kDNSSDAdvertisingProxyStatus_NoError);

    for (host = hosts; host != NULL; host = host->next) {
        if (host->num_addresses > 0) {
            inet_ntop(AF_INET6, host->addresses[0]->rdata, addrbuf, sizeof(addrbuf));
        }
        if (instances == NULL) {
            ERROR("adv_xpc_list_services: failed to allocate instance array for " PRI_S_SRP, host->name);
            goto fail;
        }
        sent = false;
        xpc_object_t *dict;
        for (i = 0; i < host->instances->num; i++) {
            if (host->instances->vec[i] != NULL) {
                instance = host->instances->vec[i];
            send_host:
                dict = xpc_dictionary_create(NULL, NULL, 0);
                if (dict == NULL) {
                    ERROR("adv_xpc_list_services: failed to allocate instance dictionary for " PRI_S_SRP, host->name);
                    goto fail;
                }
                xpc_dictionary_set_string(dict, "hostname", host->name);
                xpc_dictionary_set_string(dict, "regname", host->registered_name);
                if (instance) {
                    char portbuf[6];
                    xpc_dictionary_set_string(dict, "name", instance->instance_name);
                    xpc_dictionary_set_string(dict, "type", instance->service_type);
                    snprintf(portbuf, sizeof(portbuf), "%u", instance->port);
                    xpc_dictionary_set_string(dict, "port", portbuf);
                    xpc_dictionary_set_data(dict, "txt", instance->txt_data, instance->txt_length);
                }
                if (host->num_addresses > 0) {
                    xpc_dictionary_set_string(dict, "address", addrbuf);
                }
                xpc_dictionary_set_int64(dict, "lease", host->lease_expiry >= now ? host->lease_expiry - now : -1);
                xpc_array_append_value(instances, dict);
                xpc_release(dict);
                sent = true;
            }
        }
        if (!sent) {
            instance = NULL;
            goto send_host;
        }
    }

    xpc_dictionary_set_value(response, "instances", instances);
    xpc_release(instances);
    xpc_connection_send_message(connection, response);
    xpc_release(response);
    return true;
fail:
    if (instances != NULL) {
        xpc_release(instances);
    }
    if (response != NULL) {
        xpc_release(response);
    }
    return false;
}

static bool
adv_xpc_block_service(xpc_connection_t request, xpc_object_t connection, bool enable)
{
    xpc_object_t response;
    int status = kDNSSDAdvertisingProxyStatus_NoError;
    extern srp_proxy_listener_state_t *srp_listener;

    response = xpc_dictionary_create_reply(request);
    if (response == NULL) {
        ERROR("adv_xpc_list_services: Unable to create reply dictionary.");
        return false;
    }

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

    xpc_dictionary_set_uint64(response, kDNSAdvertisingProxyResponseStatus, status);
    xpc_connection_send_message(connection, response);
    xpc_release(response);
    return true;
}

static bool
adv_xpc_regenerate_ula(xpc_connection_t request, xpc_object_t connection)
{
    xpc_object_t response;
    int status = kDNSSDAdvertisingProxyStatus_NoError;

    response = xpc_dictionary_create_reply(request);
    if (response == NULL) {
        ERROR("adv_xpc_list_services: Unable to create reply dictionary.");
        return false;
    }

    partition_stop_advertising_pref_id();
    thread_network_shutdown();
    ula_generate();
    thread_network_startup();

    xpc_dictionary_set_uint64(response, kDNSAdvertisingProxyResponseStatus, status);
    xpc_connection_send_message(connection, response);
    xpc_release(response);

    return true;
}

void
srp_mdns_flush(void)
{
    adv_host_t *host, *host_next;

    INFO("srp_mdns_flush: flushing all host entries.");
    for (host = hosts; host; host = host_next) {
        INFO("srp_mdns_flush: Flushing services and host entry for " PRI_S_SRP " (" PRI_S_SRP ")",
             host->name, host->registered_name);
        // Get rid of the updates before calling lease_callback, which will fail if update is not NULL.
        if (host->updates != NULL) {
            adv_update_t *update_next, *update = host->updates->next;
            update_failed(host->updates, dns_rcode_refused, false);
            while (update != NULL) {
                update_next = update->next;
                update->host = NULL;
                update_finalize(update);
                update = update_next;
            }
            host->updates = NULL;
        }
        // Get rid of clients for the same reason.
        if (host->clients != NULL) {
            client_update_t *client, *client_next;
            for (client = host->clients; client; client = client_next) {
                client_next = client->next;
                client_finalize(client);
            }
            host->clients = NULL;
        }
        host_next = host->next;
        host_finalize(host);
    }
    hosts = NULL;
}

static bool
adv_xpc_message(xpc_connection_t connection, xpc_object_t request)
{
    int pid = -1;
    int uid = -1;

    // This means that the listener failed for some reason.   Try again in ten seconds.
    if (connection == NULL && request == NULL) {
        if (adv_xpc_wakeup == NULL) {
            adv_xpc_wakeup = ioloop_wakeup_create();
            if (adv_xpc_wakeup == NULL) {
                INFO("adv_xpc_message: can't create a wakeup to try to recover.");
                return false;
            }
        } else {
            ioloop_cancel_wake_event(adv_xpc_wakeup);
        }
        ioloop_add_wake_event(adv_xpc_wakeup, NULL, adv_xpc_restart, NULL, 10000);
        return false;
    }

    if (connection == NULL) {
        INFO("adv_xpc_message: disconnected.");
        return false;
    }

    pid = xpc_connection_get_pid(connection);
    uid = xpc_connection_get_euid(connection);

    if (request == NULL) {
        INFO("adv_xpc_message: Client uid %d pid %d disconnected.", uid, pid);
        adv_xpc_connection_delete(connection);
        return false;
    }

    const char *message_type = xpc_dictionary_get_string(request, kDNSAdvertisingProxyCommand);

    if (message_type == NULL) {
        ERROR("Client uid %d pid %d sent a request with no message type.", uid, pid);
        adv_xpc_connection_delete(connection);
        // Close the connection
        return false;
    }

    if (!strcmp(message_type, kDNSAdvertisingProxyEnable)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
        return adv_proxy_enable(request, connection);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyListServiceTypes)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyListServices)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
        return adv_xpc_list_services(request, connection);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyListHosts)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyGetHost)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyFlushEntries)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a %s request.", uid, pid, message_type);
        srp_mdns_flush();
    } else if (!strcmp(message_type, kDNSAdvertisingProxyBlockService)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
        adv_xpc_block_service(request, connection, true);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyUnblockService)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
        adv_xpc_block_service(request, connection, false);
    } else if (!strcmp(message_type, kDNSAdvertisingProxyRegenerateULA)) {
        INFO("adv_xpc_message: Client uid %d pid %d sent a " PUB_S_SRP " request.", uid, pid, message_type);
        adv_xpc_regenerate_ula(request, connection);
    } else {
        ERROR("Client uid %d pid %d sent a request with unknown message type " PUB_S_SRP ".", uid, pid, message_type);
        // Close the connection
        adv_xpc_connection_delete(connection);
        return false;
    }

    xpc_object_t response;
    response = xpc_dictionary_create_reply(request);
    if (response == NULL) {
        ERROR("adv_xpc_message: Unable to create reply dictionary.");
        return false;
    }
    xpc_dictionary_set_uint64(response, kDNSAdvertisingProxyResponseStatus, kDNSSDAdvertisingProxyStatus_NoError);
    xpc_connection_send_message(connection, response);
    xpc_release(response);
    return false;
}
#endif

static void
usage(void)
{
    ERROR("srp-mdns-proxy [--max-lease-time <seconds>] [--min-lease-time <seconds>] [--log-stderr]");
    exit(1);
}

int
main(int argc, char **argv)
{
    int i;
    char *end;
    int log_stderr = false;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--max-lease-time")) {
            if (i + 1 == argc) {
                usage();
            }
            max_lease_time = (uint32_t)strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || end[0] != 0) {
                usage();
            }
            i++;
        } else if (!strcmp(argv[i], "--min-lease-time")) {
            if (i + 1 == argc) {
                usage();
            }
            min_lease_time = (uint32_t)strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || end[0] != 0) {
                usage();
            }
            i++;
        } else if (!strcmp(argv[i], "--log-stderr")) {
            log_stderr = true;
        } else {
            usage();
        }
    }

    OPENLOG(log_stderr);
    INFO("--------------------------------srp-mdns-proxy starting--------------------------------");

    if (!ioloop_init()) {
        return 1;
    }

    if (!start_icmp_listener()) {
        return 1;
    }

#ifdef IOLOOP_MACOS
    // On MacOS, drop privileges once we have the ICMP listener.
#ifdef DROP_PRIVILEGES
    int ret;
    ssize_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize < 0) {
        bufsize = 1024;
    }
    char *getpwnam_r_buf = malloc(bufsize);
    struct passwd mdnsresponder_pwd;
    int mdnsresponder_uid = 65; // This is what's in /etc/passwd now.
    if (getpwnam_r_buf != NULL) {
        struct passwd *result;
        ret = getpwnam_r("_mdnsresponder", &mdnsresponder_pwd, getpwnam_r_buf, bufsize, &result);
        if (ret < 0 || result == NULL) {
            ERROR("getpwnam_r failed: " PUB_S_SRP, strerror(ret));
        } else {
            mdnsresponder_uid = mdnsresponder_pwd.pw_uid;
        }
        free(getpwnam_r_buf);
        endpwent();
    } else {
        ERROR("Unable to allocate getpwnam_r buffer.");
    }
    ret = setuid(mdnsresponder_uid);
    if (ret < 0) {
        ERROR("setuid failed: " PUB_S_SRP, strerror(errno));
    }
#endif

    // On MacOS, we can set up an XPC service to check on registrations and also to start the service
    // from launchd.
    xpc_listener = ioloop_create_xpc_service(kDNSAdvertisingProxyService, adv_xpc_message);
    if (xpc_listener == NULL) {
        return 1;
    }
#endif

    // We require one open file per service and one per instance.
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) < 0) {
        ERROR("getrlimit failed: " PUB_S_SRP, strerror(errno));
        return 1;
    }

    if (limits.rlim_cur < 1024) {
        if (limits.rlim_max < 1024) {
            INFO("getrlimit: file descriptor hard limit is %llu", limits.rlim_max);
            if (limits.rlim_cur != limits.rlim_max) {
                limits.rlim_cur = limits.rlim_max;
            }
        } else {
            limits.rlim_cur = 1024;
        }
        if (setrlimit(RLIMIT_NOFILE, &limits) < 0) {
            ERROR("setrlimit failed: " PUB_S_SRP, strerror(errno));
        }
    }

    do {
        int something = 0;
        ioloop();
        INFO("dispatched %d events.", something);
    } while (1);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
