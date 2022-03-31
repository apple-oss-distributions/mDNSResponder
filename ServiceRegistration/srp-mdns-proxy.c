/* srp-mdns-proxy.c
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
 * This file contains the SRP Advertising Proxy, which is an SRP Server
 * that offers registered addresses using mDNS.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
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
#include "srp-crypto.h"
#include "ioloop.h"
#include "dnssd-proxy.h"
#include "srp-gw.h"
#include "srp-proxy.h"
#include "srp-mdns-proxy.h"
#include "config-parse.h"
#include "route.h"
#include "adv-ctl-server.h"
#include "srp-replication.h"
#include "ioloop-common.h"


#if SRP_FEATURE_NAT64
#include "nat64-macos.h"
#endif

// Server internal state
struct {
    struct in6_addr addr;
    int width;
} *preferred_prefix;

adv_host_t *hosts;
int advertise_interface = kDNSServiceInterfaceIndexAny;

static const char local_suffix_ld[] = ".local";
static const char *local_suffix = &local_suffix_ld[1];
uint32_t max_lease_time = 3600 * 27; // One day plus 20%
uint32_t min_lease_time = 30; // thirty seconds
static dnssd_txn_t *shared_connection_for_registration = NULL;
bool srp_replication_enabled = false;
#if SRP_FEATURE_NAT64
bool srp_nat64_enabled = false;
#endif

//======================================================================================================================
// MARK: - Forward references

#if SRP_ALLOWS_MDNS_CONFLICTS
static void try_new_hostname(adv_host_t *host);
#endif // SRP_ALLOWS_MDNS_CONFLICTS
static void register_host_completion(DNSServiceRef sdref, DNSRecordRef rref,
                                     DNSServiceFlags flags, DNSServiceErrorType error_code, void *context);
static void register_instance_completion(DNSServiceRef sdref, DNSServiceFlags flags, DNSServiceErrorType error_code,
                                         const char *name, const char *regtype, const char *domain, void *context);
static void update_from_host(adv_host_t *host);
static void start_host_update(adv_host_t *host);
static void prepare_update(adv_host_t *host);
static void delete_host(void *context);
static void lease_callback(void *context);
static void host_finalize(adv_host_t *host);

//======================================================================================================================
// MARK: - Functions

static void
adv_address_finalize(adv_address_t *address)
{
    free(address);
}

static void
adv_instance_finalize(adv_instance_t *instance)
{
    if (instance->conn != NULL) {
        service_connection_cancel_and_release(instance->conn);
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
    if (instance->host != NULL) {
        RELEASE_HERE(instance->host, host_finalize);
        instance->host = NULL;
    }
    if (instance->message != NULL) {
        ioloop_message_release(instance->message);
        instance->message = NULL;
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
#if SRP_FEATURE_REPLICATION
static bool
srp_replication_advertise_finished(adv_host_t *host, char *hostname, void *context, comm_t *connection, int rcode)
{
	if (srp_replication_enabled) {
        INFO("hostname = " PRI_S_SRP "  host = %p  context = %p  connection = %p  rcode = " PUB_S_SRP,
             hostname, host, context, connection, dns_rcode_name(rcode));
        if (connection == NULL) {
            // connection is the SRP client connection on which an update arrived. If it's null,
            // this is an SRP replication update, not an actual client we're communicating with.
            INFO("replication advertise finished: host " PRI_S_SRP ": rcode = " PUB_S_SRP,
                 hostname, dns_rcode_name(rcode));
            if (context != NULL) {
                srpl_advertise_finished_event_send(hostname, rcode);

                if (host != NULL && host->srpl_connection != NULL) {
                    if (rcode == dns_rcode_noerror) {
                        host->update_server_id = host->srpl_connection->remote_server_id;
                        host->server_stable_id = host->srpl_connection->stashed_host.server_stable_id;
                        INFO("replicated host " PRI_S_SRP " server stable ID %" PRIx64, hostname, host->server_stable_id);
                    }

                    // This is the safest place to clear this pointer--we do not want the srpl_connection pointer to not
                    // get reset because of some weird sequence of events, leaving this host unable to be further updated
                    // or worse.
                    srpl_connection_release(host->srpl_connection);
                    host->srpl_connection = NULL;
                } else {
                    if (host != NULL) {
                        INFO("disconnected host " PRI_S_SRP " server stable ID %" PRIx64, hostname, host->server_stable_id);
                    }
                }
            } else {
                if (host != NULL) {
                    INFO("context-free host " PRI_S_SRP " server stable ID %" PRIx64, hostname, host->server_stable_id);
                }
            }
            return true;
        }

        if (host != NULL) {
            if (rcode == dns_rcode_noerror) {
                memcpy(&host->server_stable_id, &ula_prefix, sizeof(host->server_stable_id));
            }
            INFO("local host " PRI_S_SRP " server stable ID %" PRIx64, hostname, host->server_stable_id);
            srpl_srp_client_update_finished_event_send(host, rcode);
            host->update_server_id = 0;
        }
    }
    return false;
}
#endif // SRP_FEATURE_REPLICATION

// We call advertise_finished when a client request has finished, successfully or otherwise.
static void
advertise_finished(adv_host_t *host, char *hostname,
                   void *context, comm_t *connection, message_t *message, int rcode, client_update_t *client)
{
    struct iovec iov;
    dns_wire_t response;

#if SRP_FEATURE_REPLICATION
    if (srp_replication_advertise_finished(host, hostname, context, connection, rcode)) {
        return;
    }
#else
    (void)host;
#endif // SRP_FEATURE_REPLICATION
    INFO("advertise_finished: host " PRI_S_SRP ": rcode = " PUB_S_SRP, hostname, dns_rcode_name(rcode));

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
        if (!client->serial_sent) {
            dns_u16_to_wire(&towire, dns_opt_srp_serial);    // OPTION-CODE
            dns_edns0_option_begin(&towire);                 // OPTION-LENGTH
            dns_u32_to_wire(&towire, client->serial_number); // LEASE (e.g. 1 hour)
            dns_edns0_option_end(&towire);                   // Now we know OPTION-LENGTH
        }
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
    int64_t now = ioloop_timenow();
#define MIN_HOST_RETRY_INTERVAL 15
#define MAX_HOST_RETRY_INTERVAL 120
    // If we've been retrying long enough for the lease to expire, give up.
    if (!host->lease_expiry || host->lease_expiry < now) {
        INFO("host lease has expired, not retrying: lease_expiry = %" PRId64
             " now = %" PRId64 " difference = %" PRId64, host->lease_expiry, now, host->lease_expiry - now);
        delete_host(host);
        return;
    }
    if (host->retry_interval == 0) {
        host->retry_interval = MIN_HOST_RETRY_INTERVAL;
    } else if (host->retry_interval < MAX_HOST_RETRY_INTERVAL) {
        host->retry_interval *= 2;
    }
    INFO("waiting %d seconds...", host->retry_interval);
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
    // If mDNSResponder exits, we need to release the original shared connection (once) and try to create a new one.
    // In the case of multiple instances getting error and calling service_disconnected(), only the first call to
    // service_disconnected() should decrement the reference count, so we use
    // service_connection_uses_dnssd_connection() to check if the current shared connection is the one we own.
    if (service_connection_uses_dnssd_connection(host->conn, shared_connection_for_registration)) {
        ioloop_dnssd_txn_release(shared_connection_for_registration);
        shared_connection_for_registration = dnssd_txn_create_shared();
        if (shared_connection_for_registration == NULL) {
            ERROR("Failed to create new shared connection due to memory error, should never happen");
            // It should never happen.
            exit(1);
        }
    }

    // If we don't have any updates we can do, this host is dead.
    if (host->updates == NULL) {
        // delete_host will get rid of this host.
        delete_host(host);
    } else {
        wait_retry(host);
    }
}

static void
client_finalize(client_update_t *client)
{
    srp_update_free_parts(client->instances, NULL, client->services, client->removes, client->host);
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
        // context of service_connection_t.
        // If we are retrying an update, the update on the host DNSServiceRegisterRecord transaction might not be
        // the transaction we are finalizing, but if it is, we definitely want to make it go away.

        if (host->conn != NULL && service_connection_get_context(host->conn) == update) {
            service_connection_set_context(host->conn, NULL);
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

    if (update->renew_instances != NULL) {
        RELEASE_HERE(update->renew_instances, adv_instance_vec_finalize);
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

    if (update->host != NULL) {
        RELEASE_HERE(update->host, host_finalize);
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
        update_finalize(update);
        advertise_finished(host, host->name, host->srpl_connection, client->connection, client->message, rcode, NULL);
        client_finalize(client);
        // If we don't have a lease yet, or the old lease has expired, remove the host.
        // However, if the expire flag is false, it's because we're already finalizing the
        // host, so doing an expiry here would double free the host. In this case, we leave
        // it to the caller to do the expiry (really, to finalize the host).
        if (expire && (host->lease_expiry == 0 || host->lease_expiry <= ioloop_timenow())) {
            // This shouldn't be possible, although it can happen if you pause the process for a long time in the debugger.
            if (host->clients != NULL) {
                FAULT("host " PUB_S_SRP " has expired with client still present", host->name);
            } else {
                delete_host(host);
            }
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
               host->addresses[i] = NULL;
           }
       }
       free(host->addresses);
    }
    host->addresses = NULL;
    host->num_addresses = 0;
}

// Free just those parts that are no longer needed when the host is no longer valid.
static void
host_invalidate(adv_host_t *host)
{
    int i;

    // Get rid of the retry wake event.
    if (host->retry_wakeup != NULL) {
        ioloop_cancel_wake_event(host->retry_wakeup);
    }

    // Remove all the advertised address records (currently only one).
    if (host->conn != NULL) {
        INFO("Removing AAAA record(s) for " PRI_S_SRP, host->registered_name);
        service_connection_cancel_and_release(host->conn);
        host->conn = NULL;
    } else {
        INFO("No host address registration for " PRI_S_SRP, host->registered_name);
    }

    // Remove the address records.
    host_addr_free(host);

    // Remove the services.

    if (host->instances != NULL) {
        for (i = 0; i < host->instances->num; i++) {
            if (host->instances->vec[i] != NULL) {
                if (host->instances->vec[i] != NULL && host->instances->vec[i]->conn != NULL) {
                    service_connection_cancel_and_release(host->instances->vec[i]->conn);
                    host->instances->vec[i]->conn = NULL;
                }
            }
        }
        RELEASE_HERE(host->instances, adv_instance_vec_finalize);
        host->instances = NULL;
    }

    host->removed = true;
}

// Free everything associated with the host, including the host object.
static void
host_finalize(adv_host_t *host)
{
    // Just in case this hasn't happened yet, free the non-identifying host data and cancel any outstanding
    // transactions.
    host_invalidate(host);

    if (host->key_rdata != NULL) {
        free(host->key_rdata);
        host->key_rdata = NULL;
    }

    if (host->message != NULL) {
        ioloop_message_release(host->message);
        host->message = NULL;
    }

    // We definitely don't want a lease callback at this point.
    if (host->lease_wakeup != NULL) {
        ioloop_cancel_wake_event(host->lease_wakeup);
        ioloop_wakeup_release(host->lease_wakeup);
    }
    // Get rid of the retry wake event.
    if (host->retry_wakeup != NULL) {
        ioloop_cancel_wake_event(host->retry_wakeup);
        ioloop_wakeup_release(host->retry_wakeup);
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

void
srp_adv_host_release_(adv_host_t *host, const char *file, int line)
{
    RELEASE(host, host_finalize);
}

void
srp_adv_host_retain_(adv_host_t *host, const char *file, int line)
{
    RETAIN(host);
}

bool
srp_adv_host_valid(adv_host_t *host)
{
    // If the host has been removed, it's not valid.
    if (host->removed) {
        return false;
    }
    // If there is no key data, the host is invalid.
    if (host->key_rdata == NULL) {
        return false;
    }
    return true;
}

int
srp_current_valid_host_count(void)
{
    adv_host_t *host;
    int count = 0;
    for (host = hosts; host; host = host->next) {
        if (srp_adv_host_valid(host)) {
            count++;
        }
    }
    return count;
}

int
srp_hosts_to_array(adv_host_t **host_array, int max)
{
    int count = 0;
    for (adv_host_t *host = hosts; count < max && host != NULL; host = host->next) {
        if (srp_adv_host_valid(host)) {
            host_array[count] = host;
            RETAIN_HERE(host_array[count]);
            count++;
        }
    }
    return count;
}

adv_host_t *
srp_adv_host_copy_(dns_name_t *name, const char *file, int line)
{
    for (adv_host_t *host = hosts; host; host = host->next) {
        if (srp_adv_host_valid(host) && dns_names_equal_text(name, host->name)) {
            RETAIN(host);
            return host;
        }
    }
    return NULL;
}


static void
host_remove(adv_host_t *host)
{
    // This host is no longer valid. Get rid of the associated transactions and other stuff that's not required to
    // identify it, and then release the host list reference to it.
    host_invalidate(host);
    // Note that while host_finalize calls host_invalidate, host_finalize won't necessarily be called here because there
    // may be outstanding references on the host. It's okay to call host_invalidate twice--the second time it should be
    // a no-op.
    RELEASE_HERE(host, host_finalize);
}

static adv_host_t **
host_ready(adv_host_t *host)
{
    adv_host_t **p_hosts;

    // Find the host on the list of hosts.
    for (p_hosts = &hosts; *p_hosts != NULL; p_hosts = &(*p_hosts)->next) {
        if (*p_hosts == host) {
            break;
        }
    }
    if (*p_hosts == NULL) {
        ERROR("called with nonexistent host.");
        return NULL;
    }

    // It's possible that we got an update to this host, but haven't processed it yet.  In this
    // case, we don't want to get rid of the host, but we do want to get rid of it later if the
    // update fails.  So postpone the removal for a bit.
    if (host->updates != NULL || host->clients != NULL) {
        INFO("reached with pending updates on host " PRI_S_SRP ".", host->registered_name);
        ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, 10 * 1000);
        host->lease_expiry = ioloop_timenow() + 10 * 1000; // ten seconds
        return NULL;
    }


    return p_hosts;
}

static void
lease_callback(void *context)
{
    int64_t now = ioloop_timenow();
    adv_host_t **p_hosts, *host = context;
    int i, num_instances = 0;

    p_hosts = host_ready(host);
    if (p_hosts == NULL) {
        INFO("host expired");
        return;
    }

    INFO("host " PRI_S_SRP, host->name);

    // If the host entry lease has expired, any instance leases have also.
    if (host->lease_expiry < now) {
        delete_host(host);
        return;
    }

    INFO("host " PRI_S_SRP " is still alive", host->name);

    if (host->instances == NULL) {
        INFO("no instances");
        return;
    }

    // Find instances that have expired and release them.
    for (i = 0; i < host->instances->num; i++) {
        adv_instance_t *instance = host->instances->vec[i];
        if (instance == NULL) {
            continue;
        }
        if (instance->lease_expiry < now) {
            INFO("host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP " has expired",
                 host->name, instance->instance_name, instance->service_type);
            host->instances->vec[i] = NULL;
            RELEASE_HERE(instance, adv_instance_finalize);
            continue;
        } else {
            INFO("host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP " has not expired",
                 host->name, instance->instance_name, instance->service_type);
        }
        num_instances++;
    }

    int64_t next_lease_expiry = host->lease_expiry;

    // Get rid of holes in the host instance vector and compute the next lease callback time
    int j = 0;

    for (i = 0; i < host->instances->num; i++) {
        if (host->instances->vec[i] != NULL) {
            adv_instance_t *instance = host->instances->vec[i];
            host->instances->vec[j++] = instance;
            if (next_lease_expiry > instance->lease_expiry) {
                next_lease_expiry = instance->lease_expiry;
            }
        }
    }
    INFO("host " PRI_S_SRP " lost %d instances", host->name, host->instances->num - j);
    host->instances->num = j;

    // Now set a timer for the next lease expiry event
    uint64_t when = next_lease_expiry - now;
    if (when > INT32_MAX) {
        when = INT32_MAX;
    }

    ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, (uint32_t)when);
}

// Called when we definitely want to make all the advertisements associated with a host go away.
static void
delete_host(void *context)
{
    adv_host_t **p_hosts, *host = context;

    p_hosts = host_ready(host);
    if (p_hosts == NULL) {
        return;
    }

    INFO("deleting host " PRI_S_SRP, host->name);

    // De-link the host.
    *p_hosts = host->next;

    // Get rid of any transactions attached to the host, any timer events, and any other associated data.
    host_remove(host);
}

// Called from the dispatch loop if update_finished notices that there are more updates to process.
static void next_update(void *context)
{
    adv_host_t *host = context;
    if (host->updates != NULL) {
        // If we have another prepared update to do, apply it first.
        INFO("doing next update for host " PRI_S_SRP, host->name);
        start_host_update(host);
    } else if (host->clients != NULL) {
        // If we have an update that hasn't yet been prepared, prepare it and apply it.
        INFO("processing next client request for host " PRI_S_SRP, host->name);
        prepare_update(host);
    }
    // When the update is scheduled, we retain the host so that if it's released on the way back
    // to the dispatch loop, it doesn't get finalized.
    srp_adv_host_release(host);
}

// We remember the message that produced this instance so that if we get an update that doesn't update everything,
// we know which instances /were/ updated by this particular message. instance->recent_message is a copy of the pointer
// to the message that most recently updated this instance. When we set instance->recent_message, we don't yet know
// if the update is going to succeed; if it fails, we can't have changed update->message. If it succeeds, then when we
// get down to update_finished, we can compare the message that did the update to instance->recent_message; if they
// are the same, then we set the message on the instance.
// Note that we only set instance->recent_message during register_instance_completion, so there's no timing race that
// could happen as a result of receiving a second update to the same instance before the first has been processed.
static void
set_instance_message(adv_instance_t *instance, message_t *message)
{
    if (message != NULL && (ptrdiff_t)message == instance->recent_message) {
        if (instance->message != NULL) {
            ioloop_message_release(instance->message);
        }
        instance->message = message;
        ioloop_message_retain(instance->message);
        instance->recent_message = 0;
    }
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
    message_t *message = NULL;
    bool do_wait_retry = false;

    // Get the message that produced the update, if any
    if (client != NULL) {
        message = client->message;
    }

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
        INFO("selected " PRI_SEGMENTED_IPv6_ADDR_SRP " on host " PRI_S_SRP,
             SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, rdata_buf), host->registered_name);

        if (host->addresses != NULL) {
            for (i = 0; i < host->num_addresses; i++) {
                if (host->addresses[i] != NULL && host->addresses[i] != update->selected_addr &&
                    host->addresses[i] != update->add_addresses[i] &&
                    (update->remove_addresses == NULL || update->remove_addresses[i] == NULL))
                {
#ifdef DEBUG_VERBOSE
                    uint8_t *rdp = host->addresses[i]->rdata;
                    SEGMENTED_IPv6_ADDR_GEN_SRP(rdp, rdp_buf);
                    INFO("retaining " PRI_SEGMENTED_IPv6_ADDR_SRP "on host " PRI_S_SRP,
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
                        INFO("adding " PRI_SEGMENTED_IPv6_ADDR_SRP "to host " PRI_S_SRP,
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
    if (host->instances != NULL) {
        for (i = 0; i < host->instances->num; i++) {
            // We're counting the number of non-NULL instances in the host instance vector, which is probably always
            // going to be the same as host->instances->num, but we are not relying on this.
            if (host->instances->vec[i] != NULL) {
                num_host_instances++;
            }
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
                    // we have a analyzer here "Use of memory after it is freed"
                    // RETAIN_HERE(addresses[j]);
                    // RELEASE_HERE(update->add_addresses[i], adv_address_finalize);
                    // RELEASE_HERE(update->selected_addr, adv_address_finalize);
                    // The analyzer will try reference count 0, so "use after free happens", however it is impossible
                    // to have refcount 0 while update->selected_addr points to it.
                    // Therefore, the analyzer warning is incorrect here.
                #ifndef __clang_analyzer__
                    RELEASE_HERE(addresses[i], adv_address_finalize);
                #endif
                }
            }
            free(addresses);
        }
        update_failed(update, dns_rcode_servfail, true);
        return;
    }

    j = 0;
    if (host->instances != NULL) {
        for (i = 0; i < host->instances->num; i++) {
            if (j == num_instances) {
                FAULT("j (%d) == num_instances (%d)", j, num_instances);
                break;
            }
            if (update->update_instances != NULL && update->update_instances->vec[i] != NULL) {
                adv_instance_t *instance = update->update_instances->vec[i];
                if (update->remove_instances != NULL && update->remove_instances->vec[i] != NULL) {
                    adv_instance_t *removed_instance = update->remove_instances->vec[i];
                    INFO("removed instance " PRI_S_SRP " " PRI_S_SRP " %d",
                         removed_instance->instance_name, removed_instance->service_type, removed_instance->port);
                    INFO("added instance " PRI_S_SRP " " PRI_S_SRP " %d",
                         instance->instance_name, instance->service_type, instance->port);
                } else {
                    INFO("updated instance " PRI_S_SRP " " PRI_S_SRP " %d",
                         instance->instance_name, instance->service_type, instance->port);
                }
                // Implicit RETAIN/RELEASE
                instances->vec[j] = instance;
                RETAIN_HERE(instances->vec[j]);
                j++;
                RELEASE_HERE(update->update_instances->vec[i], adv_instance_finalize);
                update->update_instances->vec[i] = NULL;
                instance->update = NULL;
                set_instance_message(instance, message);
            } else {
                if (update->remove_instances != NULL && update->remove_instances->vec[i] != NULL) {
                    adv_instance_t *instance = update->remove_instances->vec[i];
                    INFO("removed instance " PRI_S_SRP " " PRI_S_SRP " %d",
                         instance->instance_name, instance->service_type, instance->port);
                    instances->vec[j] = instance;
                    RETAIN_HERE(instances->vec[j]);
                    j++;
                    instance->removed = true;
                    if (message != NULL) {
                        instance->message = message;
                        ioloop_message_retain(instance->message);
                    }
                    if (instance->conn == NULL) {
                        ERROR("instance " PRI_S_SRP "." PRI_S_SRP " for host " PRI_S_SRP " has no connection.",
                              instance->instance_name, instance->service_type, host->name);
                    } else {
                        service_connection_cancel_and_release(instance->conn);
                        instance->conn = NULL;
                    }
                } else {
                    if (host->instances->vec[i] != NULL) {
                        adv_instance_t *instance = host->instances->vec[i];
                        INFO("kept instance " PRI_S_SRP " " PRI_S_SRP " %d",
                             instance->instance_name, instance->service_type, instance->port);
                        instances->vec[j] = instance;
                        RETAIN_HERE(instances->vec[j]);
                        j++;
                        set_instance_message(instance, message);
                    }
                }
            }
        }
    }

    // Set the message on all of the instances that were renewed to the current message.
    if (update->renew_instances != NULL) {
        for (i = 0; i < update->renew_instances->num; i++) {
            adv_instance_t *instance = update->renew_instances->vec[i];
            if (instance != NULL) {
                if (instance->message != NULL) {
                    ioloop_message_release(instance->message);
                }
                instance->message = message;
                ioloop_message_retain(instance->message);
                instance->recent_message = 0;
                INFO("renewed instance " PRI_S_SRP " " PRI_S_SRP " %d",
                     instance->instance_name, instance->service_type, instance->port);
            }
        }
    }

    if (update->add_instances != NULL) {
        for (i = 0; i < update->add_instances->num; i++) {
            adv_instance_t *instance = update->add_instances->vec[i];
            if (instance != NULL) {
                INFO("added instance " PRI_S_SRP " " PRI_S_SRP " %d",
                      instance->instance_name, instance->service_type, instance->port);
                // Implicit RETAIN/RELEASE
                instances->vec[j++] = instance;
                update->add_instances->vec[i] = NULL;
                instance->update = NULL;
                set_instance_message(instance, message);
            }
        }
    }
    instances->num = j;

    for (i = 0; i < instances->num; i++) {
        if (instances->vec[i] != NULL && instances->vec[i]->update_pending) {
            do_wait_retry = true;
        }
    }

    // At this point we can safely modify the host object because we aren't doing any more
    // allocations.
    host_addr_free(host);
    if (host->instances != NULL) {
        for (i = 0; i < host->instances->num; i++) {
            adv_instance_t *instance = host->instances->vec[i];
            if (instance != NULL) {
                INFO("old host instance %d " PRI_S_SRP "." PRI_S_SRP " for host " PRI_S_SRP " has ref_count %d",
                     i, instance->instance_name, instance->service_type, host->name, instance->ref_count);
            } else {
                INFO("old host instance %d is NULL", i);
            }
        }
        RELEASE_HERE(host->instances, adv_instance_vec_finalize);
    }

    host->addresses = addresses;
    host->num_addresses = num_addresses;
    host->instances = instances;

    if (client) {
        // If this is an update from a client, do the serial number processing.
        if (client->serial_sent) {
            INFO("host " PRI_S_SRP " serial number %" PRIu32 "->%" PRIu32 " (from client)",
                 host->name, host->serial_number, client->serial_number);
            host->serial_number = client->serial_number;
            host->have_serial_number = true;
        } else {
            // When the client doesn't know its serial number, and we have a recorded serial number, we want to make up a new
            // serial number that's enough ahead of the old one that it's unlikely there's a higher number elsewhere from recent
            // communications between the client and a server we're not currently able to reach.
            if (host->have_serial_number) {
                INFO("host " PRI_S_SRP " serial number %" PRIu32 "->%" PRIu32 " (from history)",
                     host->name, host->serial_number, host->serial_number + 50);
                client->serial_number = host->serial_number + 50;
                host->have_serial_number = true;
            } else {
                host->serial_number = (uint32_t)time(NULL);
                client->serial_number = host->serial_number;
                INFO("host " PRI_S_SRP " serial number NONE->%" PRIu32 " (from time)",
                     host->name, client->serial_number);
                host->have_serial_number = true;
            }
        }

        if (host->message != NULL) {
            ioloop_message_release(host->message);
        }
        host->message = client->message;
        ioloop_message_retain(host->message);
        advertise_finished(host, host->name, host->srpl_connection, client->connection, client->message, dns_rcode_noerror, client);
        client_finalize(client);
        update->client = NULL;
        if (host->message->received_time != 0) {
            host->update_time = host->message->received_time;
        } else {
            host->update_time = time(NULL);
        }
    }

    // The update should still be on the host.
    for (p_update = &host->updates; *p_update != NULL; p_update = &(*p_update)->next) {
        if (*p_update == update) {
            break;
        }
    }

    if (*p_update == NULL) {
        ERROR("p_update is null.");
    } else {
        *p_update = update->next;
    }

    // If another update came in while we were processing this one, schedule it to be processed
    // next time we enter the dispatch loop, to make sure that all work related to this update has
    // completed.
    if (host->updates != NULL || host->clients != NULL) {
        // Retain a reference to the host for the dispatch callback.
        RETAIN_HERE(host);
        ioloop_run_async(next_update, host);
    }

    // If we got a late name conflict while processing the previous update, try to get a new hostname.
    // We won't get here if the update caused the host to be reregistered--in that case we will either
    // return a failure to the client and delete the host, or else we'll have resolved the conflict.
    // Note the "else if" here. We don't want to schedule a retry until we are done processing all
    // updates; if the last update succeeds, there's no need to retry.
    else if (host->update_pending) {
#if SRP_ALLOWS_MDNS_CONFLICTS
        try_new_hostname(host);
#else
        do_wait_retry = true;
#endif // SRP_ALLOWS_MDNS_CONFLICTS
    }

    if (!do_wait_retry) {
        // Reset the retry interval, since we succeeded in updating.
        host->retry_interval = 0;
    }

    // Set the lease time based on this update. Even if we scheduled an update for the next time we
    // enter the dispatch loop, we still want to schedule a lease expiry here, because it's possible
    // that in the process of returning to the dispatch loop, the scheduled update will be removed.
    host->lease_interval = update->host_lease;
    host->key_lease = update->key_lease;

    // We want the lease expiry event to fire the next time the lease on any instance expires, or
    // at the time the lease for the current update would expire, whichever is sooner.
    int64_t next_lease_expiry = INT64_MAX;
    int64_t now = ioloop_timenow();

    // update->lease_expiry is nonzero if we are re-doing a previous registration.
    if (update->lease_expiry != 0) {
        if (update->lease_expiry < now) {
#ifdef LEASE_EXPIRY_DEBUGGING
            ERROR("lease expiry for host " PRI_S_SRP " happened %" PRIu64 " milliseconds ago.",
                  host->registered_name, now - update->lease_expiry);
#endif
            // Expire the lease when next we hit the run loop
            next_lease_expiry = now;
        } else {
#ifdef LEASE_EXPIRY_DEBUGGING
            INFO("lease_expiry (1) for host " PRI_S_SRP " set to %" PRId64, host->name,
                 (int64_t)(update->lease_expiry - now));
#endif
            next_lease_expiry = update->lease_expiry;
        }
        host->lease_expiry = update->lease_expiry;
    }
    // This is the more usual case.
    else {
#ifdef LEASE_EXPIRY_DEBUGGING
        INFO("lease_expiry (2) for host " PRI_S_SRP " set to %d", host->name, host->lease_interval * 1000);
#endif
        next_lease_expiry = now + host->lease_interval * 1000;
        host->lease_expiry = next_lease_expiry;
    }

    // We're doing two things here: setting the lease expiry on instances that were touched by the current
    // update, and also finding the soonest update.
    for (i = 0; i < host->instances->num; i++) {
        adv_instance_t *instance = host->instances->vec[i];

        if (instance != NULL) {
            // This instance was updated by the current update, so set its lease time to
            // next_lease_expiry.
            if (instance->message == message) {
                if (instance->removed) {
#ifdef LEASE_EXPIRY_DEBUGGING
                    INFO("lease_expiry (7) for host " PRI_S_SRP " removed instance " PRI_S_SRP "." PRI_S_SRP
                         " left at %" PRId64, host->name, instance->instance_name, instance->service_type,
                         (int64_t)(instance->lease_expiry - now));
#endif
                } else {
#ifdef LEASE_EXPIRY_DEBUGGING
                    INFO("lease_expiry (4) for host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP " set to %" PRId64,
                         host->name, instance->instance_name, instance->service_type,
                         (int64_t)(host->lease_expiry - now));
#endif
                    instance->lease_expiry = host->lease_expiry;
                }
            }
            // Instance was not updated by this update, so see if it expires sooner than this update
            // (which is likely).
            else if (instance->lease_expiry > now && instance->lease_expiry < next_lease_expiry) {
#ifdef LEASE_EXPIRY_DEBUGGING
                INFO("lease_expiry (3) for host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP " set to %" PRId64,
                     host->name, instance->instance_name, instance->service_type,
                     (int64_t)(instance->lease_expiry - now));
#endif
                next_lease_expiry = instance->lease_expiry;
            } else {
                if (instance->lease_expiry <= now) {
#ifdef LEASE_EXPIRY_DEBUGGING
                    INFO("lease_expiry (5) for host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP
                         " in the past at %" PRId64,
                         host->name, instance->instance_name, instance->service_type,
                         (int64_t)(now - instance->lease_expiry));
#endif
                    next_lease_expiry = now;
#ifdef LEASE_EXPIRY_DEBUGGING
                } else {
                    INFO("lease_expiry (6) for host " PRI_S_SRP " instance " PRI_S_SRP "." PRI_S_SRP
                         " is later than next_lease_expiry by %" PRId64, host->name, instance->instance_name,
                         instance->service_type, (int64_t)(next_lease_expiry - instance->lease_expiry));

#endif
                }
            }
        }
    }

    // Now set a timer for the next lease expiry.
    uint64_t when = next_lease_expiry - now;
    if (when > INT32_MAX) {
        when = INT32_MAX;
    }

    if (next_lease_expiry == now) {
        INFO("scheduling immediate call to lease_callback in the run loop for " PRI_S_SRP, host->name);
        ioloop_run_async(lease_callback, host);
    } else {
        INFO("scheduling wakeup to lease_callback in %" PRIu64 " for host " PRI_S_SRP,
             when / 1000, host->name);
        ioloop_add_wake_event(host->lease_wakeup, host, lease_callback, NULL, (uint32_t)when);
    }

    update_finalize(update);

    // If any of the updates failed and we need to retry, schedule the retry.
    if (do_wait_retry) {
        wait_retry(host);
    }
}

// When the host registration has completed, we get this callback.   Completion either means that we succeeded in
// registering the record, or that something went wrong and the registration has failed.
static void
register_instance_completion(DNSServiceRef sdref, DNSServiceFlags flags, DNSServiceErrorType error_code,
                             const char *name, const char *regtype, const char *domain, void *context)
{
    (void)flags;
    (void)sdref;
    adv_instance_t *instance = context;
    adv_update_t *update = instance->update;
    adv_host_t *host = instance->host;

    // It's possible that we could restart a host update due to an error while a callback is still pending on a stale
    // update.  In this case, we just cancel all of the work that's been done on the stale update (it's probably already
    // moot anyway.
    if (update != NULL && host->updates != update) {
        INFO("register_instance_completion: registration for service " PRI_S_SRP "." PRI_S_SRP
             " completed with invalid state.", name, regtype);
        instance->update = NULL;
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
            instance->update_pending = false;
#if !SRP_ALLOWS_MDNS_CONFLICTS
        success:
#endif // !SRP_ALLOWS_MDNS_CONFLICTS
            // Remember the message
            if (update->client != NULL) {
                instance->recent_message = (ptrdiff_t)update->client->message; // for comparison later in update_finished
            }
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

        // If we still have an update object, either this is a fresh SRP registration, or the update came from
        // update_from_host. In the former case, update->client will be non-NULL; in the latter, it will be NULL.
        // In the former case, we inform the SRP client that it failed, which also frees the update object; in the
        // latter case, we have to free it here.
        if (update != NULL) {
#if SRP_ALLOWS_MDNS_CONFLICTS
            // At present we will never get this error because mDNSResponder will just choose a new name.
            if (error_code == kDNSServiceErr_NameConflict) {
                update_failed(update, dns_rcode_yxdomain, true);
            } else {
                update_failed(update, dns_rcode_servfail, true);
            }
            update = NULL;
#else
            // In the case of a name conflict, we're going to add the SRP client to the database and
            // schedule a retry; otherwise it's an actual failure; if we can notify the client, we do that;
            // otherwise we just schedule a retry--there's nothing else we can really do.
            if (error_code != kDNSServiceErr_NameConflict) {
                if (update->client != NULL) {
                    update_failed(update, dns_rcode_servfail, true);
                    goto no_finalize;
                }
            }
            if (instance->conn != NULL) {
                service_connection_cancel_and_release(instance->conn);
                instance->conn = NULL;
            }
            INFO("waiting for the conflict to resolve.");
            instance->update_pending = true;
            goto success;
        no_finalize:
            update = NULL;
#endif // SRP_ALLOWS_MDNS_CONFLICTS
        } else {
            ERROR("Late failure for instance " PRI_S_SRP "--can't update client.", instance->instance_name);
        }

        if (error_code == kDNSServiceErr_ServiceNotRunning || error_code == kDNSServiceErr_DefunctConnection) {
            service_disconnected(host);
        }
    }
}

static bool
extract_instance_name(char *instance_name, size_t instance_name_max,
                      char *service_name, size_t service_name_max, service_instance_t *instance)
{
    dns_name_t *end_of_service_name = instance->service->rr->name->next;
    size_t service_index;
    service_t *service, *base_type;
    if (end_of_service_name != NULL) {
        if (end_of_service_name->next != NULL) {
            end_of_service_name = end_of_service_name->next;
        }
    }
    dns_name_print_to_limit(instance->service->rr->name, end_of_service_name, service_name, service_name_max);

    // It's possible that the registration might include subtypes. If so, we need to convert them to the
    // format that DNSServiceRegister expects: service_type,subtype,subtype...
    service_index = strlen(service_name);
    base_type = instance->service->base_type;
    for (service = instance->service->next; service != NULL && service->base_type == base_type; service = service->next)
    {
        if (service_index + service->rr->name->len + 2 > service_name_max) {
            ERROR("service name: " PRI_S_SRP " is too long for additional subtype " PRI_S_SRP,
                  service_name, service->rr->name->data);
            return false;
        }
        service_name[service_index++] = ',';
        memcpy(&service_name[service_index], service->rr->name->data, service->rr->name->len + 1);
        service_index += service->rr->name->len;
    }

    // Make a presentation-format version of the service instance name.
    dns_name_print_to_limit(instance->name, instance->name != NULL ? instance->name->next : NULL,
                            instance_name, instance_name_max);
    return true;
}

static bool
register_instance(adv_instance_t *instance)
{
    int err = kDNSServiceErr_Unknown;
    service_connection_t *conn;
    bool exit_status = false;

    // DNSServiceRegister requires a copy of the shared DNSServiceRef.
    conn = service_connection_create(shared_connection_for_registration);
    if (conn == NULL) {
        ERROR("Failed to create new service_connection_t");
        goto exit;
    }

    INFO("DNSServiceRegister(" PRI_S_SRP ", " PRI_S_SRP ", " PRI_S_SRP ", %d)",
         instance->instance_name, instance->service_type, instance->host->registered_name, instance->port);

    DNSServiceRef service_ref = service_connection_get_service_ref(conn);
    err = DNSServiceRegister(&service_ref,
                             kDNSServiceFlagsShareConnection | kDNSServiceFlagsNoAutoRename | kDNSServiceFlagsShared,
                             advertise_interface, instance->instance_name, instance->service_type, local_suffix,
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
                instance = NULL;
            }
        }
        goto exit;
    }
    if (instance->update != NULL) {
        instance->update->num_instances_started++;
    }
    // After DNSServiceRegister succeeds, it creates a copy of DNSServiceRef that indirectly uses the shared connection,
    // so we update it here.
    service_connection_set_service_ref(conn, service_ref);
    instance->conn = conn;
    conn = NULL;
    exit_status = true;

exit:
    if (conn != NULL) {
        service_connection_cancel_and_release(conn);
    }
    return exit_status;
}

static void
start_service_updates(adv_host_t *host)
{
    int i;
    adv_update_t *update = host->updates;

    if (update == NULL) {
        ERROR("start_service_updates: no work to do.");
        return;
    }

    if (host->instances != NULL) {
        // For each service instance that's being added, register it.
        if (update->add_instances != NULL) {
            for (i = 0; i < update->add_instances->num; i++) {
                if (update->add_instances->vec[i] != NULL) {
                    if (!register_instance(update->add_instances->vec[i])) {
                        return;
                    }
                }
            }
        }

        // For each service instance that's being updated or deleted, delete it.
        if (update->update_instances != NULL && update->update_instances->num != host->instances->num) {
            FAULT("start_service_updates: update instance count %d differs from host instance count %d",
                  update->update_instances->num, host->instances->num);
            update_failed(update, dns_rcode_servfail, true);
            return;
        }
        if (update->remove_instances != NULL && update->remove_instances->num != host->instances->num) {
            FAULT("start_service_updates: delete instance count %d differs from host instance count %d",
                  update->remove_instances->num, host->instances->num);
            update_failed(update, dns_rcode_servfail, true);
            return;
        }
        for (i = 0; i < host->instances->num; i++) {
            if (update->update_instances->vec[i] != NULL && !update->update_instances->vec[i]->removed) {
                // Here we are removing a registration before we know that the update will succeed. We have no choice,
                // because mDNSResponder doesn't provide a way to do an atomic update--we have to remove and then add.
                // If the update as a whole fails, the host entry will remain, but the registration that we tried to
                // update will be lost, and we don't really have a way to recover it.
                if (host->instances->vec[i]->conn != NULL) {
                    service_connection_cancel_and_release(host->instances->vec[i]->conn);
                    host->instances->vec[i]->conn = NULL;
                }

                if (!register_instance(update->update_instances->vec[i])) {
                    INFO("start_service_update: register instance failed.");
                    return;
                }
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
        ERROR("no memory for update.");
        goto fail;
    }

    update->add_addresses = calloc(host->num_addresses, sizeof (*update->add_addresses));
    if (update->add_addresses == NULL) {
        ERROR("no memory for addresses");
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
    if (host->instances != NULL) {
        update->update_instances = adv_instance_vec_copy(host->instances);
        for (i = 0; i < update->update_instances->num; i++) {
            if (update->update_instances->vec[i] != NULL) {
                update->update_instances->vec[i]->update = update;
            }
        }

        // We aren't actually adding or deleting any instances, but...
        update->remove_instances = adv_instance_vec_create(host->instances->num);
        if (update->remove_instances == NULL) {
            ERROR("no memory for remove_instances");
            goto fail;
        }
        update->remove_instances->num = host->instances->num;

        update->add_instances = adv_instance_vec_create(host->instances->num);
        if (update->add_instances == NULL) {
            ERROR("no memory for add_instances");
            goto fail;
        }
        update->add_instances->num = host->instances->num;
    }


    // At this point we have figured out all the work we need to do, so hang it off an update structure.
    update->host = host;
    RETAIN_HERE(update->host);
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
    if (update != NULL) {
        update_finalize(update);
    }
    wait_retry(host);
    return;
}

// If we get a name conflict, we need to choose a new name for the host.
#if SRP_ALLOWS_MDNS_CONFLICTS
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
            ERROR("truncating " PRI_S_SRP " to " PRI_S_SRP, host->name, namebuf);
            break;
        }
        if (*s == '\\') {
            if (s[1] == 0 || s[2] == 0 || s[3] == 0) {
                ERROR("escaped hostname " PRI_S_SRP " is invalid", host->name);
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
    INFO("using base name " PRI_S_SRP, namebuf);
    // Append a random number to the end of the name.
    host->name_serial = srp_random16();
    snprintf(t, 13, "%c%d.local", separator, host->name_serial);
    INFO("using full name " PRI_S_SRP, namebuf);

    if (host->registered_name != host->name) {
        free(host->registered_name);
    }
    host->registered_name = strdup(namebuf);
    if (host->registered_name == NULL) {
        ERROR("no memory for alternative name for " PRI_S_SRP ": " PRI_S_SRP, host->name, namebuf);
        // We pretty much can't do anything at this point.
        delete_host(host);
        return;
    }

    // Generate an update from the host entry and do it.
    update_from_host(host);
}
#endif // SRP_ALLOWS_MDNS_CONFLICTS

// When the host registration has completed, we get this callback.   Completion either means that we succeeded in
// registering the record, or that something went wrong and the registration has failed.
static void
register_host_completion(DNSServiceRef sdref, DNSRecordRef rref,
                         DNSServiceFlags flags, DNSServiceErrorType error_code, void *context)
{
    adv_host_t *const host = context;
    adv_update_t *const update = service_connection_get_context(host->conn);
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
        host->update_pending = false;

        // Now that the hostname has been registered, we can register services that point at it.
        INFO("register_host_completion: registration for host " PRI_S_SRP " has completed.", host->registered_name);
        start_service_updates(host);
    } else {
        INFO("register_host_completion: registration for host " PRI_S_SRP " failed, status = %d", host->registered_name,
             error_code);
        if (update == NULL) {
            // We shouldn't get any error here other than a name conflict or daemon not running.
            // If we get a name conflict, that means that some other advertising proxy or host on the network has
            // started advertising the hostname we chose. Our policy is that SRP updates always win over mDNS, so
            // we will keep trying to get the name. In the case that it's a transient conflict, this will resolve
            // quickly; if it's a host that really thinks it owns its name, I'm not sure what happens next.
            if (error_code == kDNSServiceErr_NameConflict) {
                if (host->updates != NULL || host->clients != NULL) {
                    host->update_pending = true;
                } else {
#if SRP_ALLOWS_MDNS_CONFLICTS
                    try_new_hostname(host);
#else // SRP_ALLOWS_MDNS_CONFLICTS
                    wait_retry(host);
#endif // SRP_ALLOWS_MDNS_CONFLICTS
                }
            }
        } else {
#if SRP_ALLOWS_MDNS_CONFLICTS
            if (error_code == kDNSServiceErr_NameConflict) {
                update_failed(update, dns_rcode_yxdomain, true);
            } else {
                update_failed(update, dns_rcode_servfail, true);
            }
#else // SRP_ALLOWS_MDNS_CONFLICTS
            // This code relies on the fact that if we never call start_service_updates, but do call update_finished,
            // update_finished will blithely assume that all the updates succeeded, and update the host entry
            // accordingly.
            if (error_code == kDNSServiceErr_NameConflict) {
                if (host->conn != NULL) {
                    service_connection_cancel_and_release(host->conn);
                    host->conn = NULL;
                }
                update_finished(update);
                wait_retry(host);
            } else {
                update_failed(update, dns_rcode_servfail, true);
            }
#endif // SRP_ALLOWS_MDNS_CONFLICTS
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
    RETAIN_HERE(instance->host);
    instance->update = update;
    // SRV records have priority, weight and port, but DNSServiceRegister only uses port.
    instance->port = (raw->srv == NULL) ? 0 : raw->srv->data.srv.port;

    // Make a presentation-format version of the service name.
    if (!extract_instance_name(instance_name, sizeof instance_name, service_type, sizeof service_type, raw)) {
        RELEASE_HERE(instance, adv_instance_finalize);
        return NULL;
    }

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

// Given a base type, which might be _foo._tcp, and an instance type, which might also be _foo._tcp or
// might have subtypes, like _foo.tcp,bar, return true if base_type matches the base type of instance_type,
// without any subtypes.
static bool
service_types_equal(const char *base_type, const char *instance_type)
{
    size_t len;
    char *comma = strchr(instance_type, ',');
    if (comma == NULL) {
        len = strlen(instance_type);
    } else {
        len = comma - instance_type;
    }
    if (strlen(base_type) != len) {
        return false;
    }
    if (memcmp(base_type, instance_type, len)) {
        return false;
    }
    return true;
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
        // We don't need to update the host address if it didn't change. However, if we haven't yet
        // succeeded in registering it, we also need to register it.
        if (remove_preexisting || host->conn == NULL) {
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
    if (remove_preexisting && host->conn != NULL) {
        service_connection_cancel_and_release(host->conn);
        host->conn = NULL;
    }

    // If we don't think we have a connection, make one.
    if (host->conn == NULL) {
        // DNSServiceRegisterRecord requires the shared DNSServiceRef directly.
        host->conn = service_connection_create(shared_connection_for_registration);
        if (host->conn == NULL) {
            ERROR("start_host_update: no memory for host address registration");
            if (update->client != NULL) {
                update_failed(update, dns_rcode_servfail, true);
            } else {
                wait_retry(host);
            }
            return;
        }
    }

    if (add_rdata != NULL) {
        const DNSServiceRef service_ref = service_connection_get_service_ref(host->conn);

        INFO("start_host_update: DNSServiceRegisterRecord(%p %p %d %d %s %d %d %d %p %d %p %p)",
             service_ref, &host->conn->record_ref,
             kDNSServiceFlagsShared,
             advertise_interface, host->registered_name,
             add_rrtype, dns_qclass_in, add_rdlen, add_rdata, 3600,
             register_host_completion, host ? host : NULL);
        service_connection_set_context(host->conn, update);

        // Let the routing module evaluate whether this is a Thread address, which would mean we'd want
        // to start advertising the stub router on the infrastructure network.
        route_evaluate_registration(add_rrtype, add_rdata, add_rdlen);

        DNSRecordRef record_ref;
        err = DNSServiceRegisterRecord(service_ref, &record_ref,
                                       kDNSServiceFlagsShared,
                                       advertise_interface, host->registered_name,
                                       add_rrtype, dns_qclass_in, add_rdlen, add_rdata, 3600,
                                       register_host_completion, host);
        if (err != kDNSServiceErr_NoError) {
            ERROR("start_host_update: DNSServiceRegisterRecord failed on host: %d", err);
            if (update->client != NULL) {
                update_failed(update, dns_rcode_servfail, true);
                return;
            } else if (err == kDNSServiceErr_DefunctConnection || err == kDNSServiceErr_ServiceNotRunning) {
                service_disconnected(host);
                return;
            }
        } else {
            service_connection_set_record_ref(host->conn, record_ref);
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
    int num_renew_instances = 0;
    adv_instance_vec_t *update_instances = NULL, *add_instances = NULL;
    adv_instance_vec_t *remove_instances = NULL, *renew_instances = NULL;
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
    num_renew_instances = host->instances->num;

    update_instances = adv_instance_vec_create(num_update_instances);
    if (update_instances == NULL) {
        ERROR("prepare_update: no memory for update_instances");
        goto fail;
    }
    update_instances->num = num_update_instances;

    remove_instances = adv_instance_vec_create(num_remove_instances);
    if (remove_instances == NULL) {
        ERROR("prepare_update: no memory for remove_instances");
        goto fail;
    }
    remove_instances->num = num_remove_instances;

    renew_instances = adv_instance_vec_create(num_renew_instances);
    if (renew_instances == NULL) {
        ERROR("prepare_update: no memory for renew_instances");
        goto fail;
    }
    renew_instances->num = num_renew_instances;

    // Handle removes. Service instance removes have to remove the whole service instance, not some subset.
    for (delete_t *dp = client_update->removes; dp; dp = dp->next) {
        // Removes can be for services or service instances. Because we're acting as an
        // Advertising Proxy and not a regular name server, we don't track service instances,
        // and so we don't need to match them here. This if statement checks to see if the
        // name could possibly be a service instance name followed by a service type. We
        // can then extract the putative service instance name and service type and compare;
        // if they match, they are in fact those things, and if they don't, we don't care.
        if (dp->name != NULL && dp->name->next != NULL && dp->name->next->next != NULL) {
            char instance_name[DNS_MAX_LABEL_SIZE_ESCAPED + 1];
            char service_type[DNS_MAX_LABEL_SIZE_ESCAPED + 2];

            dns_name_print_to_limit(dp->name, dp->name->next, instance_name, sizeof(instance_name));
            dns_name_print_to_limit(dp->name->next, dp->name->next->next->next, service_type, sizeof(service_type));

            for (i = 0; i < host->instances->num; i++) {
                adv_instance_t *remove_instance = host->instances->vec[i];
                if (remove_instance != NULL) {
                    if (!strcmp(instance_name, remove_instance->instance_name) &&
                        service_types_equal(service_type, remove_instance->service_type))
                    {
                        remove_instances->vec[i] = remove_instance;
                        RETAIN_HERE(remove_instances->vec[i]);
                        break;
                    }
                }
            }
        }
    }

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
            FAULT("prepare_update: while preparing client update instances, i >= num_add_instances");
            RELEASE_HERE(prepared_instance, adv_instance_finalize);
            goto fail;
        }
        add_instances->vec[i++] = prepared_instance;
    }
    add_instances->num = i;

    // The instances in the update are now in add_instances.  If they are updates, move them to update_instances.  If
    // they are unchanged, free them and null them out, and remember the current instance in renew_instances.  If they
    // are adds, leave them.
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
                    // If the rdata is the same, and it's not deleted, it's not an add or an update.
                    if (!host_instance->removed && add_instance->txt_length == host_instance->txt_length &&
                        add_instance->port == host_instance->port &&
                        (add_instance->txt_length == 0 ||
                         !memcmp(add_instance->txt_data, host_instance->txt_data, add_instance->txt_length)))
                    {
                        RELEASE_HERE(add_instance, adv_instance_finalize);
                        renew_instances->vec[j] = host_instance;
                        RETAIN_HERE(host_instance);
                        INFO(PRI_S_SRP "." PRI_S_SRP " renewed for host " PRI_S_SRP,
                             host_instance->instance_name, host_instance->service_type, host->name);
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
    RETAIN_HERE(update->host);
    update->client = client_update;
    host->clients = client_update->next;
    update->num_remove_addresses = num_remove_addrs;
    update->remove_addresses = remove_addrs;
    update->num_add_addresses = num_add_addrs;
    update->add_addresses = add_addrs;
    update->remove_instances = remove_instances;
    update->add_instances = add_instances;
    update->update_instances = update_instances;
    update->renew_instances = renew_instances;
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
    if (host->removed) {
        return missed;
    }
    if (!strcmp(instance_name, instance->instance_name) && service_types_equal(service_type, instance->service_type)) {
        if (!dns_names_equal_text(new_host->name, host->name)) {
            return conflict;
        }
        return match;
    }
    return missed;
}

bool
srp_update_start(comm_t *connection, void *context, dns_message_t *parsed_message, message_t *raw_message,
                 dns_host_description_t *new_host, service_instance_t *instances, service_t *services,
                 delete_t *removes, dns_name_t *update_zone, uint32_t lease_time, uint32_t key_lease_time,
                 uint32_t serial_number, bool found_serial)
{
    adv_host_t *host, **p_hosts = NULL;
    char pres_name[DNS_MAX_NAME_SIZE_ESCAPED + 1];
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
    delete_t *dp;
    dns_name_print(new_host->name, new_host_name, sizeof new_host_name);

    // Compute a checksum on the key, ignoring up to three bytes at the end.
    for (unsigned i = 0; i < new_host->key->data.key.len; i += 4) {
        key_id += ((new_host->key->data.key.key[i] << 24) | (new_host->key->data.key.key[i + 1] << 16) |
                   (new_host->key->data.key.key[i + 2] << 8) | (new_host->key->data.key.key[i + 3]));
    }

    // Log the update info.
    if (found_serial) {
        INFO("srp_update_start: host update for " PRI_S_SRP ", key id %" PRIx32 ", serial number %" PRIu32,
             new_host_name, key_id, serial_number);
    } else {
        INFO("srp_update_start: host update for " PRI_S_SRP ", key id %" PRIx32, new_host_name, key_id);
    }
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

    // Look for matching service instance names.   A service instance name that matches, but has a different
    // hostname, means that there is a conflict.   We have to look through all the entries; the presence of
    // a matching hostname doesn't mean we are done UNLESS there's a matching service instance name pointing
    // to that hostname.
    for (host = hosts; host; host = host->next) {
        // If a host has been removed, it won't have any instances to compare against. Later on, if we find that
        // there is no matching host for this update, we look through the host list again and remove the
        // "removed" host if it has the same name, so we don't need to do anything further here.
        if (host->removed) {
            continue;
        }
        // We need to look for matches both in the registered instances for this registration, and also in
        // the list of new instances, in case we get a duplicate update while a previous update is in progress.
        for (new_instance = instances; new_instance; new_instance = new_instance->next) {
            extract_instance_name(instance_name, sizeof instance_name, service_type, sizeof service_type, new_instance);

            // First check for a match or conflict in the host itself.
            for (int i = 0; i < host->instances->num; i++) {
                outcome = compare_instance(host->instances->vec[i], new_host, host,
                                           instance_name, service_type);
                if (outcome != missed) {
                    goto found_something;
                }
            }

            // Then look for the same thing in any subsequent updates that have been baked.
            for (update = host->updates; update; update = update->next) {
                if (update->add_instances != NULL) {
                    for (int i = 0; i < update->add_instances->num; i++) {
                        outcome = compare_instance(update->add_instances->vec[i], new_host, host,
                                                   instance_name, service_type);
                        if (outcome != missed) {
                            goto found_something;
                        }
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
        advertise_finished(NULL, host->name, context, connection, raw_message, dns_rcode_yxdomain, NULL);
        goto cleanup;
    }

    // We may have received removes for individual records. In this case, we need to make sure they only remove
    // records that have been added to the host that matches.
    for (adv_host_t *rhp = hosts; rhp != NULL; rhp = rhp->next) {
        if (rhp->removed) {
            continue;
        }

        // Look for removes that conflict
        for (dp = removes; dp != NULL; dp = dp->next) {
            // We only need to do this for service instance names. We don't really know what is and isn't a
            // service instance name, but if it /could/ be a service instance name, we compare; if it matches,
            // it is a service instance name, and if not, no problem.
            if (dp->name != NULL && dp->name->next != NULL && dp->name->next->next != NULL) {
                dns_name_print_to_limit(dp->name, dp->name->next, instance_name, sizeof(instance_name));
                dns_name_print_to_limit(dp->name->next, dp->name->next->next->next, service_type, sizeof(service_type));

                // See if the delete deletes an instance on the host
                for (int i = 0; i < rhp->instances->num; i++) {
                    adv_instance_t *instance = rhp->instances->vec[i];
                    if (instance != NULL) {
                        if (!strcmp(instance_name, instance->instance_name) &&
                            service_types_equal(service_type, instance->service_type))
                        {
                            if (!strcmp(new_host_name, rhp->name)) {
                                ERROR("remove for " PRI_S_SRP "." PRI_S_SRP " matches instance on host " PRI_S_SRP,
                                      instance_name, service_type, rhp->name);
                                dp->consumed = true;
                            } else {
                                ERROR("remove for " PRI_S_SRP "." PRI_S_SRP " conflicts with instance on host " PRI_S_SRP,
                                      instance_name, service_type, rhp->name);
                                advertise_finished(NULL, rhp->name, context, connection, raw_message, dns_rcode_formerr, NULL);
                                goto cleanup;
                            }
                        }
                    }
                }

                // See if the remove removes an instance on an update on the host
                for (update = rhp->updates; update; update = update->next) {
                    if (update->add_instances != NULL) {
                        for (int i = 0; i < update->add_instances->num; i++) {
                            adv_instance_t *instance = update->add_instances->vec[i];
                            if (instance != NULL) {
                                if (!strcmp(instance_name, instance->instance_name) &&
                                    service_types_equal(service_type, instance->service_type))
                                {
                                    if (!strcmp(new_host_name, rhp->name)) {
                                        dp->consumed = true;
                                    } else {
                                        ERROR("remove for " PRI_S_SRP " conflicts with instance on update to host " PRI_S_SRP,
                                              instance->instance_name, rhp->name);
                                        advertise_finished(NULL, rhp->name, context,
                                                           connection, raw_message, dns_rcode_formerr, NULL);
                                        goto cleanup;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Finally, look for removes in any updates that _haven't_ been baked.
            for (client_update = rhp->clients; client_update; client_update = client_update->next) {
                for (client_instance = client_update->instances; client_instance;
                     client_instance = client_instance->next)
                {
                    if (dns_names_equal(dp->name, client_instance->name)) {
                        if (!strcmp(new_host_name, rhp->name)) {
                            dp->consumed = true;
                        } else {
                            DNS_NAME_GEN_SRP(dp->name, name_buf);
                            ERROR("remove for " PRI_DNS_NAME_SRP " conflicts with instance on client update to host "
                                  PRI_S_SRP, DNS_NAME_PARAM_SRP(dp->name, name_buf), rhp->name);
                            advertise_finished(NULL, rhp->name, context,
                                               connection, raw_message, dns_rcode_formerr, NULL);
                            goto cleanup;
                        }
                    }
                }
            }
        }
    }

    // Log any unmatched deletes, but we don't consider these to be errors.
    for (dp = removes; dp != NULL; dp = dp->next) {
        if (!dp->consumed) {
            DNS_NAME_GEN_SRP(dp->name, name_buf);
            INFO("remove for " PRI_DNS_NAME_SRP " doesn't match any instance on any host.",
                 DNS_NAME_PARAM_SRP(dp->name, name_buf));
        }
    }

    // If we fall off the end looking for a matching service instance, there isn't a matching
    // service instance, but there may be a matching host, so look for that.
    if (outcome == missed) {
        // Search for the new hostname in the list of hosts, which is sorted.
        for (p_hosts = &hosts; *p_hosts; p_hosts = &host->next) {
            host = *p_hosts;
            int comparison = strcasecmp(new_host_name, host->name);
            if (comparison == 0) {
                // If we get an update for a host that was removed, and it's not also a remove,
                // remove the host entry that's marking the remove. If this is a remove, just flag
                // it as a miss.
                if (host->removed) {
                    outcome = missed;
                    if (remove) {
                        break;
                    }
                    *p_hosts = host->next;
                    host_invalidate(host);
                    RELEASE_HERE(host, host_finalize);
                    host = NULL;
                    break;
                }
                if (key_id == host->key_id && dns_keys_rdata_equal(new_host->key, &host->key)) {
                    outcome = match;
                    break;
                }
                ERROR("srp_update_start: update for host " PRI_S_SRP " has key id %" PRIx32
                      " which doesn't match host key id %" PRIx32 ".",
                      host->name, key_id, host->key_id);
                advertise_finished(NULL, host->name, context, connection, raw_message, dns_rcode_yxdomain, NULL);
                goto cleanup;
            } else if (comparison < 0) {
                break;
            }
        }
    } else {
        if (key_id != host->key_id || !dns_keys_rdata_equal(new_host->key, &host->key)) {
            ERROR("srp_update_start: new host with name " PRI_S_SRP " and key id %" PRIx32
                  " conflicts with existing host " PRI_S_SRP " with key id %" PRIx32,
                  new_host_name, key_id, host->name, host->key_id);
            advertise_finished(NULL, host->name, context, connection, raw_message, dns_rcode_yxdomain, NULL);
            goto cleanup;
        }
    }

    // If we didn't find a matching host, we can make a new one.   When we create it, it just has
    // a name and no records.  The update that we then construct will have the missing records.
    // We don't want to do this for a remove, obviously.
    if (outcome == missed) {
        if (remove) {
            ERROR("Remove for host " PRI_S_SRP " which doesn't exist.", new_host_name);
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_noerror, NULL);
            goto cleanup;
        }

        host = calloc(1, sizeof *host);
        if (host == NULL) {
            ERROR("srp_update_start: no memory for host data structure.");
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
            goto cleanup;
        }
        host->ref_count = 1;
        host->instances = adv_instance_vec_create(0);
        if (host->instances == NULL) {
            ERROR("srp_update_start: no memory for host instance vector.");
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
            host_remove(host);
            goto cleanup;
        }

        host->retry_wakeup = ioloop_wakeup_create();
        if (host->retry_wakeup != NULL) {
            host->lease_wakeup = ioloop_wakeup_create();
        }
        if (host->lease_wakeup == NULL) {
            ERROR("srp_update_start: no memory for wake event on host");
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
            host_remove(host);
            goto cleanup;
        }
        dns_name_print(new_host->name, pres_name, sizeof pres_name);
        host->name = strdup(pres_name);
        if (host->name == NULL) {
            host_remove(host);
            ERROR("srp_update_start: no memory for hostname.");
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
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
            host_remove(host);
            ERROR("srp_update_start: no memory for host key.");
            advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
            goto cleanup;
        }
        memcpy(host->key_rdata, &new_host->key->data.key.flags, 2);
        host->key_rdata[2] = new_host->key->data.key.protocol;
        host->key_rdata[3] = new_host->key->data.key.algorithm;
        memcpy(&host->key_rdata[4], new_host->key->data.key.key, new_host->key->data.key.len);
        host->key.data.key.key = &host->key_rdata[4];
        host->key_id = key_id;

        // Insert this in the list where it would have sorted.  The if test is because the optimizer doesn't notice that
        // p_hosts can never be null here--it will always be pointing to the end of the list of hosts if we get here.
        if (p_hosts != NULL) {
            host->next = *p_hosts;
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
#if SRP_FEATURE_REPLICATION
            srp_replication_advertise_finished(host, host->name, context, connection, dns_rcode_servfail);
#endif
        cleanup:
            srp_update_free_parts(instances, NULL, services, removes, new_host);
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

    // If this is a remove, remove the host registrations and mark the host removed. We keep it around until the
    // lease expires to prevent replication accidentally re-adding a removed host as a result of a bad timing
    // coincidence.
    if (remove) {
        host_invalidate(host);
        // We need to propagate the remove message.
        if (host->message != NULL) {
            ioloop_message_release(host->message);
        }
        host->message = raw_message;
        ioloop_message_retain(host->message);
        advertise_finished(host, new_host_name, context, connection, raw_message, dns_rcode_noerror, NULL);
        goto cleanup;
    }

    // At this point we have an update and a host to which to apply it.  We may already be doing an earlier
    // update, or not.  Create a client update structure to hold the communication, so that when we are done,
    // we can respond.
    client_update = calloc(1, sizeof *client_update);
    if (client_update == NULL) {
        ERROR("srp_update_start: no memory for host data structure.");
        advertise_finished(NULL, new_host_name, context, connection, raw_message, dns_rcode_servfail, NULL);
        goto cleanup;
    }

    if (outcome == missed) {
        INFO("srp_update_start: New host " PRI_S_SRP ", key id %" PRIx32 , host->name, host->key_id);
    } else {
        if (host->registered_name != host->name) {
            INFO("srp_update_start: Renewing host " PRI_S_SRP ", alias " PRI_S_SRP ", key id %" PRIx32,
                 host->name, host->registered_name, host->key_id);
        } else {
            INFO("srp_update_start: Renewing host " PRI_S_SRP ", key id %" PRIx32, host->name, host->key_id);
        }
    }

    if (host->registered_name == NULL) {
        host->registered_name = host->name;
    }

    if (connection != NULL) {
        client_update->connection = connection;
        ioloop_comm_retain(client_update->connection);
    }
    client_update->parsed_message = parsed_message;
    client_update->message = raw_message;
    ioloop_message_retain(client_update->message);
    client_update->host = new_host;
    client_update->instances = instances;
    client_update->services = services;
    client_update->removes = removes;
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
    client_update->serial_number = serial_number;
    client_update->serial_sent = found_serial;
    *p_client_update = client_update;

#if SRP_FEATURE_REPLICATION
    if (context != NULL) {
        host->srpl_connection = (srpl_connection_t *)context;
        srpl_connection_retain(host->srpl_connection);
    }
#else
    (void)context;
#endif // SRP_FEATURE_REPLICATION

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

void
srp_mdns_flush(void)
{
    adv_host_t *host, *host_next;

    INFO("srp_mdns_flush: flushing all host entries.");
    for (host = hosts; host; host = host_next) {
        INFO("srp_mdns_flush: Flushing services and host entry for " PRI_S_SRP " (" PRI_S_SRP ")",
             host->name, host->registered_name);
        // Get rid of the updates before calling delete_host, which will fail if update is not NULL.
        if (host->updates != NULL) {
            adv_update_t *update_next, *update = host->updates->next;
            update_failed(host->updates, dns_rcode_refused, false);
            while (update != NULL) {
                update_next = update->next;
                if (update->host != NULL) {
                    RELEASE_HERE(update->host, host_finalize);
                    update->host = NULL;
                }
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
        host_remove(host);
    }
    hosts = NULL;
}

static void
usage(void)
{
    ERROR("srp-mdns-proxy [--max-lease-time <seconds>] [--min-lease-time <seconds>] [--log-stderr]");
    ERROR("               [--enable-replication | --disable-replication]");
#if SRP_FEATURE_NAT64
    ERROR("               [--enable-nat64 | --disable-nat64]");
#endif
    exit(1);
}

int
main(int argc, char **argv)
{
    int i;
    char *end;
    int log_stderr = false;

    srp_replication_enabled = true;
#  if SRP_FEATURE_NAT64
    srp_nat64_enabled = true;
#  endif

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
        } else if (!strcmp(argv[i], "--enable-replication")) {
            srp_replication_enabled = true;
        } else if (!strcmp(argv[i], "--disable-replication")) {
            srp_replication_enabled = false;
#if SRP_FEATURE_NAT64
        } else if (!strcmp(argv[i], "--enable-nat64")) {
            srp_nat64_enabled = true;
        } else if (!strcmp(argv[i], "--disable-nat64")) {
            srp_nat64_enabled = false;
#endif
        } else {
            usage();
        }
    }

    // Setup log category for srp-mdns-prox and dnssd-proxy.
    OPENLOG("srp-mdns-proxy", log_stderr);

    INFO("--------------------------------"
         "srp-mdns-proxy starting, compiled on " PUB_S_SRP ", " PUB_S_SRP
         "--------------------------------", __DATE__, __TIME__);

    if (!ioloop_init()) {
        return 1;
    }

    shared_connection_for_registration = dnssd_txn_create_shared();
    if (shared_connection_for_registration == NULL) {
        return 1;
    }

#if (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)
    if (!init_dnssd_proxy()) {
        ERROR("main: failed to setup dnssd-proxy");
        return 1;
    }
#endif // #if (SRP_FEATURE_COMBINED_SRP_DNSSD_PROXY)

#if STUB_ROUTER
    if (!start_icmp_listener()) {
        return 1;
    }
#endif

    infrastructure_network_startup();

    if (adv_ctl_init() != kDNSServiceErr_NoError) {
        ERROR("Can't start advertising proxy control server.");
        return 1;
    }

    // We require one open file per service and one per instance.
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) < 0) {
        ERROR("getrlimit failed: " PUB_S_SRP, strerror(errno));
        return 1;
    }

    if (limits.rlim_cur < 1024) {
        if (limits.rlim_max < 1024) {
            INFO("getrlimit: file descriptor hard limit is %llu", (unsigned long long)limits.rlim_max);
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

    // Set up the ULA early just in case we get an early registration.
    route_ula_setup();

    srp_proxy_init("local");

#if SRP_FEATURE_REPLICATION
	if (srp_replication_enabled) {
        srpl_startup();
    }
#endif // SRP_FEATURE_REPLICATION

#if SRP_FEATURE_NAT64
    if (srp_nat64_enabled) {
        nat64_startup(dispatch_get_main_queue());
    }
#endif // SRP_FEATURE_NAT64

    ioloop();
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
