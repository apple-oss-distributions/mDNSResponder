/* srp-replication.c
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
#include "cti-services.h"
#define DNSMessageHeader dns_wire_t
#include "dso.h"
#include "dso-utils.h"

#if SRP_FEATURE_REPLICATION
#include "srp-replication.h"

static char *current_thread_domain_name;
static srpl_domain_t *srpl_domains;
static unclaimed_connection_t *unclaimed_connections;
static uint64_t server_id;

#define srpl_event_content_type_set(event, content_type) \
    srpl_event_content_type_set_(event, content_type, __FILE__, __LINE__)
static bool srpl_event_content_type_set_(srpl_event_t *event,
                                         srpl_event_content_type_t content_type, const char *file, int line);
static srpl_state_t srpl_connection_drop_state_delay(srpl_instance_t *instance,
                                                     srpl_connection_t *srpl_connection, int delay);
static srpl_state_t srpl_connection_drop_state(srpl_instance_t *instance, srpl_connection_t *srpl_connection);
static void srpl_disconnect(srpl_connection_t *srpl_connection);
static void srpl_connection_discontinue(srpl_connection_t *srpl_connection);
static void srpl_connection_next_state(srpl_connection_t *srpl_connection, srpl_state_t state);
static void srpl_event_initialize(srpl_event_t *event, srpl_event_type_t event_type);
static void srpl_event_deliver(srpl_connection_t *srpl_connection, srpl_event_t *event);
static void srpl_domain_advertise(void);

#ifdef DEBUG
#define STATE_DEBUGGING_ABORT() abort();
#else
#define STATE_DEBUGGING_ABORT()
#endif

//
// 1. Enumerate all SRP servers that are participating in synchronization on infrastructure: This is done by looking up
//    NS records for <thread-network-name>.thread.home.arpa with the ForceMulticast flag set so that we use mDNS to
//    discover them.

// 2. For each identified server that is not this server, look up A and AAAA records for the server's hostname.

// 3. Maintain a state object with the list of IP addresses and an index to the current server being tried.

// 4. Try to connect to the first address on the list -> connection management state machine:

//   * When we have established an outgoing connection to a server, generate a random 64-bit unsigned number and send a
//     SRPLSession DSO message using that number as the server ID.

//   * When we receive an SRPLSession DSO message, see if we have an outgoing connection from the same server
//     for which we've sent a server ID. If so, and if the server id we received is less than the one we sent,
//     terminate the outgoing connection. If the server ids are equal, generate a new server id for the outgoing
//     connection and send another session establishment message.
//
//   * When we receive an acknowledgement to our SRPLSession DSO message, see if we have an incoming
//     connection from the same server from which we've received a server id. If the server id we received is less
//     than the one we sent, terminate the outgoing connection. If the server ids are equal, generate a new random
//     number for the outgoing connection and send another session establishment message.
//
//   * When a connection from a server is terminated, see if we have an established outgoing connection with that
//     server.  If not, attempt to connect to the next address we have for that server.
//
//   * When our connection to a server is terminated or fails, and there is no established incoming connection from that
//     server, attempt to connect to the next address we have for that server.
//
//   * When the NS record for a server goes away, drop any outgoing connection to that server and discontinue trying to
//     connect to it.
//
// 5. When we have established a session, meaning that we either got an acknowledgment to a SRPLSession DSO
//    message that we sent and _didn't_ drop the connection, or we got an SRPLSession DSO message on an
//    incoming connection with a lower server id than the outgoing connection, we begin the synchronization process.
//
//    * Immediately following session establishment, we generate a list of candidate hosts to send to the other server
//      from our internal list of SRP hosts (clients). Every non-expired host entry goes into the candidate list.
//
//    * Then, if we are the originator, we sent an SRPLSendCandidates message.
//
//    * If we are the recipient, we wait for an SRPLSendCandidates message.
//
//    * When we receive an SRPLSendCandidates message, we iterate across the candidates list, for each
//      candidate sending an SRPLCandidate message containing the host key, current time, and last message
//      received times, in seconds since the epoch. When we come to the end of the candidates list, we send an
//      acknowledgement to the SRPLSendCandidates message and discard the candidates list.
//
//    * When we receive an SRPLCandidate message, we look in our own candidate list, if there is one, to see
//      if the host key is present in the candidates list. If it is not present, or if it is present and the received
//      time from the SRPLCandidate message is later than the time we have recorded in our own candidate
//      list, we send an SRPLCandidateRequest message with the host key from the SRPLCandidate
//      message.
//
//    * When we receive an SRPLCandidateRequest message, we send an SRPLHost message which
//      encapsulates the SRP update for the host and includes the timestamp when we received the SRP update from that
//      host, which may have changed since we sent the SRPLCandidate message.
//
//    * When we receive an SRPLHost message, we look in our list of hosts (SRP clients) for a matching
//      host. If no such host exists, or if it exists and the timestamp is less than the timestamp in the
//      SRPLHost message, we process the SRP update from the SRPLHost message and mark the host as
//      "not received locally."  In other words, this message was not received directly from an SRP client, but rather
//      indirectly through our SRP replication partner. Note that this message cannot be assumed to be syntactically
//      correct and must be treated like any other data received from the network. If we are sent an invalid message,
//      this is an indication that our partner is broken in some way, since it should have validated the message before
//      accepting it.
//
//    * Whenever the SRP engine applies an SRP update from a host, it also delivers that update to each replication
//      server state engine.
//
//      * That replication server state engine first checks to see if it is connected to its partner; if not, no action
//        is taken.
//
//      * It then checks to see if there is a candidate list.
//        * If so, it checks to see if the host implicated in the update is already on the candidate list.
//          * If so, it updates that candidate's update time.
//          * If not, it adds the host to the end of the candidate list.
//        * If not, it sends an SRPLCandidate message to the other replication server, with the host
//          key and new timestamp.
//
// 6. When there is more than one SRP server participating in replication, only one server should advertise using
//    mDNS. All other servers should only advertise using DNS and DNS Push (SRP scalability feature). The SRP server
//    with the lowest numbered server ID is the one that acts as an advertising proxy for SRP. In practice this means
//    that if we have the lowest server ID of all the SRP servers we are connected to, we advertise mDNS. If two servers
//    on the same link can't connect to each other, they probably can't see each others' multicasts, so this is the
//    right outcome.

static bool
ip_addresses_equal(const addr_t *a, const addr_t *b)
{
    return (a->sa.sa_family == b->sa.sa_family &&
            ((a->sa.sa_family == AF_INET && !memcmp(&a->sin.sin_addr, &b->sin.sin_addr, 4)) ||
             (a->sa.sa_family == AF_INET6 && !memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr, 16))));
}

#define ADDR_NAME_LOGGER(log_type, address, preamble, conjunction, number, fullname, interfaceIndex)            \
    if ((address)->sa.sa_family == AF_INET6) {                                                                  \
        SEGMENTED_IPv6_ADDR_GEN_SRP(&(address)->sin6.sin6_addr, rdata_buf);                                     \
        log_type(PUB_S_SRP PRI_SEGMENTED_IPv6_ADDR_SRP PUB_S_SRP PRI_S_SRP PUB_S_SRP "%d", preamble,            \
                 SEGMENTED_IPv6_ADDR_PARAM_SRP(&(address)->sin6.sin6_addr, rdata_buf),                          \
                 conjunction, fullname, number, interfaceIndex);                                                \
    } else {                                                                                                    \
        IPv4_ADDR_GEN_SRP(&(address)->sin.sin_addr, rdata_buf);                                                 \
        log_type(PUB_S_SRP PRI_IPv4_ADDR_SRP PUB_S_SRP PRI_S_SRP PUB_S_SRP "%d", preamble,                      \
                 IPv4_ADDR_PARAM_SRP(&(address)->sin.sin_addr, rdata_buf),                                      \
                 conjunction, fullname, number, interfaceIndex);                                                \
    }

static void
address_query_callback(DNSServiceRef UNUSED sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                       DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype, uint16_t rrclass,
                       uint16_t rdlen, const void *rdata, uint32_t UNUSED ttl, void *context)
{
    address_query_t *address = context;
    addr_t addr;
    int i, j;
    if (errorCode != kDNSServiceErr_NoError) {
        ERROR("address resolution for " PRI_S_SRP " failed with %d", fullname, errorCode);
        address->change_callback(address->context, NULL, false, errorCode);
        return;
    }
    if (rrclass != dns_qclass_in || ((rrtype != dns_rrtype_a || rdlen != 4) &&
                                     (rrtype != dns_rrtype_aaaa || rdlen != 16))) {
        ERROR("Invalid response record type (%d) or class (%d) provided for " PRI_S_SRP, rrtype, rrclass, fullname);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    if (rrtype == dns_rrtype_a) {
#ifndef NOT_HAVE_SA_LEN
        addr.sa.sa_len = sizeof(struct sockaddr_in);
#endif
        addr.sa.sa_family = AF_INET;
        memcpy(&addr.sin.sin_addr, rdata, rdlen);
        if (IN_LINKLOCAL(addr.sin.sin_addr.s_addr)) {
            ADDR_NAME_LOGGER(INFO, &addr, "Skipping link-local address ", " received for instance ", " index ",
                             fullname, interfaceIndex);
            return;
        }
    } else {
#ifndef NOT_HAVE_SA_LEN
        addr.sa.sa_len = sizeof(struct sockaddr_in6);
#endif
        addr.sa.sa_family = AF_INET6;
        memcpy(&addr.sin6.sin6_addr, rdata, rdlen);
        if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6.sin6_addr)) {
            ADDR_NAME_LOGGER(INFO, &addr, "Skipping link-local address ", " received for instance ", " index ",
                             fullname, interfaceIndex);
            return;
        }
    }

    for (i = 0, j = 0; i < address->num_addresses; i++) {
        // Already in the list?
        if (!memcmp(&address->addresses[i], &addr, sizeof(addr))) {
            if (flags & kDNSServiceFlagsAdd) {
                if (address->address_interface[i] == interfaceIndex) {
                    ADDR_NAME_LOGGER(INFO, &addr, "Duplicate address ", " received for instance ", " index ",
                                                fullname, interfaceIndex);
                }
                return;
            } else {
                ADDR_NAME_LOGGER(INFO, &addr, "Removing address ", " from instance ", " index ",
                                            fullname, interfaceIndex);

                // If we're removing an address, we keep going through the array copying down.
                if (address->cur_address >= i) {
                    address->cur_address--;
                }
            }
        } else {
            // Copy down.
            if (i != j) {
                address->addresses[j] = address->addresses[i];
                address->address_interface[j] = address->address_interface[i];
            }
            j++;
        }
    }
    if (flags & kDNSServiceFlagsAdd) {
        if (i == ADDRESS_QUERY_MAX_ADDRESSES) {
            ADDR_NAME_LOGGER(ERROR, &addr, "No room for address ", " received for ", " index ",
                                         fullname, interfaceIndex);
            return;
        }
        ADDR_NAME_LOGGER(INFO, &addr, "Adding address ", " to ", " index ", fullname, interfaceIndex);

        address->addresses[i] = addr;
        address->address_interface[i] = interfaceIndex;
        address->num_addresses++;
        address->change_callback(address->context, &address->addresses[i], true, kDNSServiceErr_NoError);
    } else {
        if (i == j) {
            ADDR_NAME_LOGGER(ERROR, &addr, "Remove for unknown address ", " received for ", " index ",
                               fullname, interfaceIndex);
            return;
        } else {
            address->num_addresses--;
            address->change_callback(address->context, &addr, false, kDNSServiceErr_NoError);
        }
    }
}

static void
address_query_finalize(void *context)
{
    address_query_t *address = context;
    free(address->hostname);
    free(address);
}

static void
address_query_cancel(address_query_t *address)
{
    if (address->a_query != NULL) {
        ioloop_dnssd_txn_cancel(address->a_query);
        ioloop_dnssd_txn_release(address->a_query);
        address->a_query = NULL;
    }
    if (address->aaaa_query != NULL) {
        ioloop_dnssd_txn_cancel(address->aaaa_query);
        ioloop_dnssd_txn_release(address->aaaa_query);
        address->aaaa_query = NULL;
    }

    // Have whatever holds a reference to the address query let go of it.
    if (address->cancel_callback != NULL && address->context != NULL) {
        address->cancel_callback(address->context);
        address->context = NULL;
        address->cancel_callback = NULL;
    }
}

static void
address_query_txn_fail(void *context, int err)
{
    address_query_t *address = context;
    ERROR("address query " PRI_S_SRP " i/o failure: %d", address->hostname, err);
    address_query_cancel(address);
}

static address_query_t *
address_query_create(const char *hostname, void *context, address_change_callback_t change_callback,
                     address_query_cancel_callback_t cancel_callback)
{
    address_query_t *address = calloc(1, sizeof(*address));
    DNSServiceRef sdref;
    dnssd_txn_t **txn;

    require_action_quiet(address != NULL, exit_no_free, ERROR("No memory for address query."));
    address->hostname = strdup(hostname);
    require_action_quiet(address->hostname != NULL, exit, ERROR("No memory for address query hostname."));

    for (int i = 0; i < 2; i++) {
        int ret = DNSServiceQueryRecord(&sdref, kDNSServiceFlagsForceMulticast | kDNSServiceFlagsLongLivedQuery,
                                        kDNSServiceInterfaceIndexAny, hostname, (i
                                                                                 ? kDNSServiceType_A
                                                                                 : kDNSServiceType_AAAA),
                                        kDNSServiceClass_IN, address_query_callback, address);
        require_action_quiet(ret == kDNSServiceErr_NoError, exit,
                             ERROR("Unable to resolve instance hostname " PRI_S_SRP " addresses: %d",
                                   hostname, ret));

        txn = i ? &address->a_query : &address->aaaa_query;
        *txn = ioloop_dnssd_txn_add(sdref, address, NULL, address_query_txn_fail);
        require_action_quiet(*txn != NULL, exit,
                             ERROR("Unable to set up ioloop transaction for " PRI_S_SRP " query on " THREAD_BROWSING_DOMAIN,
                                   hostname);
                             DNSServiceRefDeallocate(sdref));
    }
    address->change_callback = change_callback;
    address->cancel_callback = cancel_callback;
    address->context = context;
    address->cur_address = -1;
    RETAIN_HERE(address);
    if (false) {
    exit:
        RELEASE_HERE(address, address_query_finalize);
        address = NULL;
    }
exit_no_free:
    return address;
}

static void
srpl_domain_finalize(srpl_domain_t *domain)
{
    free(domain->name);
    if (domain->query != NULL) {
        ioloop_dnssd_txn_cancel(domain->query);
        ioloop_dnssd_txn_release(domain->query);
    }
    free(domain);
}

static void
srpl_instance_finalize(srpl_instance_t *instance)
{
    if (instance->domain != NULL) {
        RELEASE_HERE(instance->domain, srpl_domain_finalize);
    }
    free(instance->instance_name);
    free(instance->name);
    free(instance);
}

#define srpl_connection_message_set(srpl_connection, message) \
    srpl_connection_message_set_(srpl_connection, message, __FILE__, __LINE__)
static void
srpl_connection_message_set_(srpl_connection_t *srpl_connection, message_t *message, const char *file, int line)
{
    if (srpl_connection->message != NULL) {
        ioloop_message_release_(srpl_connection->message, file, line);
        srpl_connection->message = NULL;
    }
    if (message != NULL) {
        srpl_connection->message = message;
        ioloop_message_retain_(srpl_connection->message, file, line);
    }
}

static message_t *
srpl_connection_message_get(srpl_connection_t *srpl_connection)
{
    return srpl_connection->message;
}

#define srpl_candidate_free(candidate) srpl_candidate_free_(candidate, __FILE__, __LINE__)
static void
srpl_candidate_free_(srpl_candidate_t *candidate, const char *file, int line)
{
    if (candidate != NULL) {
        if (candidate->name != NULL) {
            dns_name_free(candidate->name);
            candidate->name = NULL;
        }
        if (candidate->message != NULL) {
            ioloop_message_release_(candidate->message, file, line);
            candidate->message = NULL;
        }
        if (candidate->host != NULL) {
            srp_adv_host_release_(candidate->host, file, line);
            candidate->host = NULL;
        }
        free(candidate);
    }
}

static void
srpl_connection_candidates_free(srpl_connection_t *srpl_connection)
{
    if (srpl_connection->candidates == NULL) {
        goto out;
    }
    for (int i = 0; i < srpl_connection->num_candidates; i++) {
        if (srpl_connection->candidates[i] != NULL) {
            srp_adv_host_release(srpl_connection->candidates[i]);
        }
    }
    free(srpl_connection->candidates);
    srpl_connection->candidates = NULL;
out:
    srpl_connection->num_candidates = srpl_connection->current_candidate = 0;
    return;
}

static void
srpl_srp_client_update_queue_free(srpl_connection_t *srpl_connection)
{
    srpl_srp_client_queue_entry_t **cp = &srpl_connection->client_update_queue;
    while (*cp) {
        srpl_srp_client_queue_entry_t *entry = *cp;
        srp_adv_host_release(entry->host);
        *cp = entry->next;
        free(entry);
    }
}

static void
srpl_connection_candidate_set(srpl_connection_t *srpl_connection, srpl_candidate_t *candidate)
{
    if (srpl_connection->candidate != NULL) {
        srpl_candidate_free(srpl_connection->candidate);
    }
    srpl_connection->candidate = candidate;
}

static void
srpl_host_update_parts_free(srpl_host_update_t *update)
{
    if (update->message != NULL) {
        ioloop_message_release(update->message);
        update->message = NULL;
    }
    if (update->hostname != NULL) {
        dns_name_free(update->hostname);
        update->hostname = NULL;
    }
}

// Free up any temporarily retained or allocated objects on the connection (i.e., not the name).
static void
srpl_connection_reset(srpl_connection_t *srpl_connection)
{
    srpl_connection->candidates_not_generated = true;
    srpl_connection->database_synchronized = false;
    srpl_host_update_parts_free(&srpl_connection->stashed_host);
    srpl_connection_message_set(srpl_connection, NULL);
    if (srpl_connection->candidate != NULL) {
        srpl_candidate_free(srpl_connection->candidate);
        srpl_connection->candidate = NULL;
    }
    srpl_connection_candidates_free(srpl_connection);
    srpl_srp_client_update_queue_free(srpl_connection);
}

static void
srpl_connection_finalize(srpl_connection_t *srpl_connection)
{
    if (srpl_connection->instance) {
        RELEASE_HERE(srpl_connection->instance, srpl_instance_finalize);
        srpl_connection->instance = NULL;
    }
    if (srpl_connection->connection != NULL) {
        ioloop_comm_release(srpl_connection->connection);
        srpl_connection->connection = NULL;
    }
    if (srpl_connection->reconnect_wakeup != NULL) {
        ioloop_cancel_wake_event(srpl_connection->reconnect_wakeup);
        srpl_connection->reconnect_wakeup = NULL;
    }
    free(srpl_connection->name);
    srpl_connection_reset(srpl_connection);
    free(srpl_connection);
}

void
srpl_connection_release_(srpl_connection_t *srpl_connection, const char *file, int line)
{
    RELEASE(srpl_connection, srpl_connection_finalize);
}

void
srpl_connection_retain_(srpl_connection_t *srpl_connection, const char *file, int line)
{
    RETAIN(srpl_connection);
}

static srpl_connection_t *
srpl_connection_create(srpl_instance_t *instance, bool outgoing)
{
    srpl_connection_t *srpl_connection = calloc(1, sizeof (*srpl_connection));
    size_t srpl_connection_name_length;
    if (outgoing) {
        srpl_connection_name_length = strlen(instance->instance_name) + 2;
    } else {
        srpl_connection_name_length = strlen(instance->instance_name) + 2;
    }
    srpl_connection->name = malloc(srpl_connection_name_length);
    if (srpl_connection->name == NULL) {
        free(srpl_connection);
        return NULL;
    }
    snprintf(srpl_connection->name, srpl_connection_name_length, "%s%s", outgoing ? ">" : "<", instance->instance_name);
    srpl_connection->is_server = !outgoing;
    srpl_connection->instance = instance;
    RETAIN_HERE(instance);
    RETAIN_HERE(srpl_connection);
    return srpl_connection;
}

static void
srpl_instance_discontinue_timeout(void *context)
{
    srpl_instance_t **sp = NULL, *instance = context;

    INFO("discontinuing instance " PRI_S_SRP, instance->instance_name);
    for (sp = &instance->domain->instances; *sp; sp = &(*sp)->next) {
        if (*sp == instance) {
            *sp = instance->next;
            break;
        }
    }
    if (instance->discontinue_timeout != NULL) {
        ioloop_cancel_wake_event(instance->discontinue_timeout);
        ioloop_wakeup_release(instance->discontinue_timeout);
    }
    if (instance->address_query != NULL) {
        address_query_cancel(instance->address_query);
        RELEASE_HERE(instance->address_query, address_query_finalize);
        instance->address_query = NULL;
    }
    for (int i = 0; i < 2; i++) {
        srpl_connection_t *srpl_connection = i ? instance->incoming : instance->outgoing;
        if (srpl_connection == NULL) {
            continue;
        }
        RELEASE_HERE(srpl_connection->instance, srpl_instance_finalize);
        srpl_connection->instance = NULL;
        if (srpl_connection->connection != NULL) {
            srpl_connection_discontinue(srpl_connection);
        }
    }
    if (instance->resolve_txn != NULL) {
        ioloop_dnssd_txn_cancel(instance->resolve_txn);
        ioloop_dnssd_txn_release(instance->resolve_txn);
        instance->resolve_txn = NULL;
    }
    RELEASE_HERE(instance, srpl_instance_finalize);
}

static void
srpl_instance_discontinue(srpl_instance_t *instance)
{
    // Already discontinuing.
    if (instance->discontinuing) {
        INFO("Replication service instance " PRI_S_SRP " went away, already discontinuing", instance->instance_name);
        return;
    }
    if (instance->num_copies > 0) {
        INFO("Replication service instance " PRI_S_SRP " went away, %d still left", instance->name, instance->num_copies);
        return;
    }
    INFO("Replication service instance " PRI_S_SRP " went away, none left, discontinuing", instance->instance_name);
    instance->discontinuing = true;

    // DNSServiceResolve doesn't give us the kDNSServiceFlagAdd flag--apparently it's assumed that we know the
    // service was removed because we get a remove on the browse. So we need to restart the resolve if the
    // instance comes back, rather than continuing to use the old resolve transaction.
    if (instance->resolve_txn != NULL) {
        ioloop_dnssd_txn_cancel(instance->resolve_txn);
        ioloop_dnssd_txn_release(instance->resolve_txn);
        instance->resolve_txn = NULL;
    }

    // It's not uncommon for a name to drop and then come back immediately. Wait 30s before
    // discontinuing the instance.
    if (instance->discontinue_timeout == NULL) {
        instance->discontinue_timeout = ioloop_wakeup_create();
        // Oh well.
        if (instance->discontinue_timeout == NULL) {
            srpl_instance_discontinue_timeout(instance);
            return;
        }
    }
    ioloop_add_wake_event(instance->discontinue_timeout, instance, srpl_instance_discontinue_timeout, NULL, 30 * 1000);
}

static void
srpl_connection_context_release(void *context)
{
    srpl_connection_t *srpl_connection = context;

    RELEASE_HERE(srpl_connection, srpl_connection_finalize);
}

static void
srpl_instance_context_release(void *context)
{
    srpl_instance_t *instance = context;

    RELEASE_HERE(instance, srpl_instance_finalize);
}

// Copy from into to, and then NULL out the host pointer in from, which is not refcounted, so that we don't get a
// double free later. Add a reference to the message, since it is refcounted.
static void
srpl_host_update_steal_parts(srpl_host_update_t *to, srpl_host_update_t *from)
{
    *to = *from;
    ioloop_message_retain(to->message);
    from->hostname = NULL;
}

static bool
srpl_event_content_type_set_(srpl_event_t *event, srpl_event_content_type_t content_type, const char *file, int line)
{
    switch(event->content_type) {
    case srpl_event_content_type_none:
    case srpl_event_content_type_address:
    case srpl_event_content_type_server_id:
    case srpl_event_content_type_candidate_disposition:
    case srpl_event_content_type_rcode:
    case srpl_event_content_type_client_result: // pointers owned by caller
    case srpl_event_content_type_advertise_finished_result:
        break;

    case srpl_event_content_type_candidate:
        if (event->content.candidate != NULL) {
            srpl_candidate_free_(event->content.candidate, file, line);
            event->content.candidate = NULL;
        }
        break;
    case srpl_event_content_type_host_update:
        srpl_host_update_parts_free(&event->content.host_update);
        break;
    }
    memset(&event->content, 0, sizeof(event->content));
    if (content_type == srpl_event_content_type_candidate) {
        event->content.candidate = calloc(1, sizeof(srpl_candidate_t));
        if (event->content.candidate == NULL) {
            return false;
        }
    }
    event->content_type = content_type;
    return true;
}

// Return true if the client connection to us is functional.
static bool
srpl_incoming_connection_is_active(srpl_instance_t *instance)
{
    if (instance == NULL || instance->incoming == NULL) {
        return false;
    }
    switch(instance->incoming->state) {
    case srpl_state_session_message_wait:
        return false;
    default:
        return true;
    }
}

static void
srpl_disconnected_callback(comm_t *UNUSED comm, void *context, int UNUSED error)
{
    srpl_connection_t *srpl_connection = context;

    // No matter what state we are in, if we are disconnected, we can't continue with the existing connection.
    // Either we need to make a new connection, or go idle.

    srpl_instance_t *instance = srpl_connection->instance;

    // The connection would still be holding a reference; once that reference is released, if there's no instance
    // holding a reference, the srp_connection will be finalized.
    if (srpl_connection->connection != NULL) {
        comm_t *connection = srpl_connection->connection;
        srpl_connection->connection = NULL;
        ioloop_comm_release(connection);
    }

    // If there's no instance, this connection just needs to go away (and presumably has).
    if (instance == NULL) {
        return;
    }

    // Because instance is still holding a reference to srpl_connection, it's safe to keep using srpl_connection.

    // For server connections, we just dispose of the connection--the client is responsible for reconnecting
    if (srpl_connection->is_server) {
        instance->incoming = NULL;
        srpl_connection->instance = NULL;
        RELEASE_HERE(srpl_connection, srpl_connection_finalize);
#ifndef __clang_analyzer__
        RELEASE_HERE(instance, srpl_instance_finalize);
#endif
        return;
    }

    // If the connection is in the disconnect_wait state, deliver an event.
    if (srpl_connection->state == srpl_state_disconnect_wait) {
        srpl_event_t event;
        srpl_event_initialize(&event, srpl_event_disconnected);
        srpl_event_deliver(srpl_connection, &event);
        return;
    }

    // Clear old data from connection.
    srpl_connection_reset(srpl_connection);

    // For outgoing connections, we only need to reconnect if we don't have a confirmed incoming connection.
    if (srpl_incoming_connection_is_active(instance)) {
        INFO(PRI_S_SRP ": disconnect received, we have an active incoming connection, going idle.",
             srpl_connection->name);
        srpl_connection_next_state(srpl_connection, srpl_state_idle);
    } else {
        INFO(PRI_S_SRP ": disconnect received, reconnecting.", srpl_connection->name);
        srpl_connection_next_state(srpl_connection, srpl_state_next_address_get);
    }
}

static bool
srpl_dso_message_setup(dso_state_t *dso, dso_message_t *state, dns_towire_state_t *towire, uint8_t *buffer,
                       size_t buffer_size, message_t *message, bool response, int rcode, void *context)
{
    if (buffer_size < DNS_HEADER_SIZE) {
        ERROR("internal: invalid buffer size %zd", buffer_size);
        return false;
    }

    dso_make_message(state, buffer, buffer_size, dso, false, response, response ? message->wire.id : 0, rcode, context);
    memset(towire, 0, sizeof(*towire));
    towire->p = &buffer[DNS_HEADER_SIZE];
    towire->lim = towire->p + (buffer_size - DNS_HEADER_SIZE);
    towire->message = (dns_wire_t *)buffer;
    return true;
}

static bool
srpl_session_message_send(srpl_connection_t *srpl_connection, bool response)
{
    uint8_t dsobuf[SRPL_SESSION_MESSAGE_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire, dsobuf, sizeof(dsobuf),
                                srpl_connection_message_get(srpl_connection), response, 0, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLSession);
    dns_rdlength_begin(&towire);
    dns_u64_to_wire(&towire, server_id);
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLSession " PUB_S_SRP ", id %" PRIx64, srpl_connection->name,
         response ? "response" : "message", server_id);
    return true;
}

static bool
srpl_send_candidates_message_send(srpl_connection_t *srpl_connection, bool response)
{
    uint8_t dsobuf[SRPL_SEND_CANDIDATES_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire, dsobuf, sizeof(dsobuf),
                                srpl_connection_message_get(srpl_connection), response, 0, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLSendCandidates);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLSendCandidates " PUB_S_SRP, srpl_connection->name, response ? "response" : "query");
    return true;
}

static bool
srpl_candidate_message_send(srpl_connection_t *srpl_connection, adv_host_t *host)
{
    uint8_t dsobuf[SRPL_CANDIDATE_MESSAGE_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire,
                                dsobuf, sizeof(dsobuf), NULL, false, 0, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLCandidate);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLHostname);
    dns_rdlength_begin(&towire);
    dns_full_name_to_wire(NULL, &towire, host->name);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLTimeOffset);
    dns_rdlength_begin(&towire);
    dns_u32_to_wire(&towire, (uint32_t)(time(NULL) - host->update_time));
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLKeyID);
    dns_rdlength_begin(&towire);
    dns_u32_to_wire(&towire, host->key_id);
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLCandidate message on connection.", srpl_connection->name);
    return true;
}

static bool
srpl_candidate_response_send(srpl_connection_t *srpl_connection, dso_message_types_t response_type)
{
    uint8_t dsobuf[SRPL_CANDIDATE_RESPONSE_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire, dsobuf, sizeof(dsobuf),
                                srpl_connection_message_get(srpl_connection), true, 0, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLCandidate);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, response_type);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLCandidate response on connection.", srpl_connection->name);
    return true;
}

static bool
srpl_host_message_send(srpl_connection_t *srpl_connection, adv_host_t *host)
{
    uint8_t dsobuf[SRPL_HOST_MESSAGE_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov[2];

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire,
                                dsobuf, sizeof(dsobuf), NULL, false, 0, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLHost);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLHostname);
    dns_rdlength_begin(&towire);
    dns_full_name_to_wire(NULL, &towire, host->name);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLTimeOffset);
    dns_rdlength_begin(&towire);
    dns_u32_to_wire(&towire, (uint32_t)(time(NULL) - host->update_time));
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLServerStableID);
    dns_rdlength_begin(&towire);
    dns_u64_to_wire(&towire, host->server_stable_id);
    dns_rdlength_end(&towire);
    dns_u16_to_wire(&towire, kDSOType_SRPLHostMessage);
    dns_u16_to_wire(&towire, host->message->length);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_len = towire.p - dsobuf;
    iov[0].iov_base = dsobuf;
    iov[1].iov_len = host->message->length;
    iov[1].iov_base = &host->message->wire;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), iov, 2);

    INFO(PRI_S_SRP " sent SRPLHost message %02x%02x " PRI_S_SRP " stable ID %" PRIx64,
         srpl_connection->name, message.buf[0], message.buf[1], host->name, host->server_stable_id);
    return true;
}


static bool
srpl_host_response_send(srpl_connection_t *srpl_connection, int rcode)
{
    uint8_t dsobuf[SRPL_HOST_RESPONSE_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire, dsobuf, sizeof(dsobuf),
                                srpl_connection_message_get(srpl_connection), true, rcode, srpl_connection)) {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_SRPLHost);
    dns_rdlength_begin(&towire);
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLHost response %02x%02x rcode %d on connection.",
         srpl_connection->name, message.buf[0], message.buf[1], rcode);
    return true;
}

static bool
srpl_retry_delay_send(srpl_connection_t *srpl_connection, uint32_t delay)
{
    uint8_t dsobuf[SRPL_RETRY_DELAY_LENGTH];
    dns_towire_state_t towire;
    dso_message_t message;
    struct iovec iov;

    // If this isn't a server, there's no benefit to sending retry delay.
    if (!srpl_connection->is_server) {
        return true;
    }

    if (!srpl_dso_message_setup(srpl_connection->dso, &message, &towire, dsobuf, sizeof(dsobuf),
                                srpl_connection_message_get(srpl_connection), true, dns_rcode_noerror, srpl_connection))
    {
        return false;
    }
    dns_u16_to_wire(&towire, kDSOType_RetryDelay);
    dns_rdlength_begin(&towire);
    dns_u32_to_wire(&towire, delay); // One hour.
    dns_rdlength_end(&towire);
    if (towire.error) {
        ERROR("ran out of message space at " PUB_S_SRP ", :%d", __FILE__, towire.line);
        return false;
    }
    memset(&iov, 0, sizeof(iov));
    iov.iov_len = towire.p - dsobuf;
    iov.iov_base = dsobuf;
    ioloop_send_message(srpl_connection->connection, srpl_connection_message_get(srpl_connection), &iov, 1);

    INFO(PRI_S_SRP " sent SRPLHost response, id %" PRIx64, srpl_connection->name, server_id);
    return true;
}
static bool
srpl_find_dso_additionals(srpl_connection_t *srpl_connection, dso_state_t *dso,
                          const dso_message_types_t *additionals, bool *required, const char **names, int *indices,
                          int num, int min_additls, int max_additls, const char *message_name, void *context,
                          bool (*iterator)(int index, const uint8_t *buf, unsigned *offp, uint16_t len, void *context))
{
    int ret = true;
    int count = 0;

    for (int j = 0; j < num; j++) {
        indices[j] = -1;
    }
    for (int i = 0; i < dso->num_additls; i++) {
        bool found = false;
        for (int j = 0; j < num; j++) {
            if (dso->additl[i].opcode == additionals[j]) {
                if (indices[j] != -1) {
                    ERROR(PRI_S_SRP ": duplicate " PUB_S_SRP " for " PUB_S_SRP ".",
                          srpl_connection->name, names[j], message_name);
                    ret = false;
                    continue;
                }
                indices[j] = i;
                unsigned offp = 0;
                if (!iterator(j, dso->additl[i].payload, &offp, dso->additl[i].length, context) ||
                    offp != dso->additl[i].length) {
                    ERROR(PRI_S_SRP ": invalid " PUB_S_SRP " for " PUB_S_SRP ".",
                          srpl_connection->name, names[j], message_name);
                    found = true; // So we don't complain later.
                    count++;
                    ret = false;
                } else {
                    found = true;
                    count++;
                }
            }
        }
        if (!found) {
            ERROR(PRI_S_SRP ": unexpected opcode %x for " PUB_S_SRP ".",
                  srpl_connection->name, dso->additl[i].opcode, message_name);
            ret = false;
        }
    }
    for (int j = 0; j < num; j++) {
        if (required[j] && indices[j] == -1) {
            ERROR(PRI_S_SRP ": missing " PUB_S_SRP " for " PUB_S_SRP ".",
                  srpl_connection->name, names[j], message_name);
            ret = false;
        }
    }
    if (count < min_additls) {
        ERROR(PRI_S_SRP ": not enough additional TLVs (%d) for " PUB_S_SRP ".",
              srpl_connection->name, count, message_name);
        ret = false;
    } else if (count > max_additls) {
        ERROR(PRI_S_SRP ": too many additional TLVs (%d) for " PUB_S_SRP ".",
              srpl_connection->name, count, message_name);
        ret = false;
    }
    return ret;
}

static void
srpl_connection_discontinue(srpl_connection_t *srpl_connection)
{
    srpl_connection->candidates_not_generated = true;
    srpl_connection_reset(srpl_connection);
    srpl_connection_next_state(srpl_connection, srpl_state_disconnect);
}

static bool
srpl_session_message_parse(srpl_connection_t *srpl_connection,
                           srpl_event_t *event, dso_state_t *dso, const char *message_name)
{
    if (dso->primary.length != 8) {
        ERROR(PRI_S_SRP ": invalid DSO Primary length %d for " PUB_S_SRP ".",
              srpl_connection->name, dso->primary.length, message_name);
        return false;
    } else {
        unsigned offp = 0;
        srpl_event_content_type_set(event, srpl_event_content_type_server_id);
        if (!dns_u64_parse(dso->primary.payload, 8, &offp, &event->content.server_id)) {
            // This should be un-possible.
            ERROR(PRI_S_SRP ": invalid DSO Primary server id in " PRI_S_SRP ".",
                  srpl_connection->name, message_name);
            return false;
        }

        INFO(PRI_S_SRP " received " PUB_S_SRP ", id %" PRIx64,
             srpl_connection->name, message_name, event->content.server_id);
        return true;
    }
}

static void
srpl_session_message(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso)
{
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_session_message_received);

    if (!srpl_session_message_parse(srpl_connection, &event, dso, "SRPLSession message")) {
        srpl_disconnect(srpl_connection);
        return;
    }
    srpl_connection_message_set(srpl_connection, message);
    srpl_event_deliver(srpl_connection, &event);
}

static void
srpl_session_response(srpl_connection_t *srpl_connection, dso_state_t *dso)
{
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_session_response_received);
    if (!srpl_session_message_parse(srpl_connection, &event, dso, "SRPLSession response")) {
        srpl_disconnect(srpl_connection);
        return;
    }
    srpl_event_deliver(srpl_connection, &event);
}

static bool
srpl_send_candidates_message_parse(srpl_connection_t *srpl_connection, dso_state_t *dso, const char *message_name)
{
    if (dso->primary.length != 0) {
        ERROR(PRI_S_SRP ": invalid DSO Primary length %d for " PUB_S_SRP ".",
              srpl_connection->name, dso->primary.length, message_name);
        srpl_disconnect(srpl_connection);
        return false;
    }
    return true;
}

static void
srpl_send_candidates_message(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso)
{
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_send_candidates_message_received);

    if (srpl_send_candidates_message_parse(srpl_connection, dso, "SRPLSendCandidates message")) {
        INFO(PRI_S_SRP " received SRPLSendCandidates query", srpl_connection->name);

        srpl_connection_message_set(srpl_connection, message);
        srpl_event_deliver(srpl_connection, &event);
        return;
    }
}

static void
srpl_send_candidates_response(srpl_connection_t *srpl_connection, dso_state_t *dso)
{
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_send_candidates_response_received);

    if (srpl_send_candidates_message_parse(srpl_connection, dso, "SRPLSendCandidates message")) {
        INFO(PRI_S_SRP " received SRPLSendCandidates response", srpl_connection->name);
        srpl_event_deliver(srpl_connection, &event);
        return;
    }
}

static bool
srpl_candidate_message_parse_in(int index, const uint8_t *buffer, unsigned *offp, uint16_t length, void *context)
{
    srpl_candidate_t *candidate = context;

    switch(index) {
    case 0:
        return dns_name_parse(&candidate->name, buffer, length, offp, length);
    case 1:
        return dns_u32_parse(buffer, length, offp, &candidate->update_offset);
    case 2:
        return dns_u32_parse(buffer, length, offp, &candidate->key_id);
    }
    return false;
}

static void
srpl_candidate_message(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso)
{
    const char *names[3] = { "Candidate Name", "Time Offset", "Key ID" };
    dso_message_types_t additionals[3] = { kDSOType_SRPLHostname, kDSOType_SRPLTimeOffset, kDSOType_SRPLKeyID };
    bool required[3] = { true, true, true };
    int indices[3];

    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_candidate_received);
    if (!srpl_event_content_type_set(&event, srpl_event_content_type_candidate) ||
        !srpl_find_dso_additionals(srpl_connection, dso, additionals,
                                   required, names, indices, 3, 3, 3, "SRPLCandidate message",
                                   event.content.candidate, srpl_candidate_message_parse_in)) {
        goto fail;
    }

    srpl_connection_message_set(srpl_connection, message);
    event.content.candidate->update_time = time(NULL) - event.content.candidate->update_offset;
    srpl_event_deliver(srpl_connection, &event);
    srpl_event_content_type_set(&event, srpl_event_content_type_none);
    return;

fail:
    srpl_disconnect(srpl_connection);
}

static bool
srpl_candidate_response_parse_in(int index,
                                 const uint8_t *UNUSED buffer, unsigned *offp, uint16_t length, void *context)
{
    srpl_candidate_disposition_t *candidate_disposition = context;

    if (length != 0) {
        return false;
    }

    switch(index) {
    case 0:
        *candidate_disposition = srpl_candidate_yes;
        break;
    case 1:
        *candidate_disposition = srpl_candidate_no;
        break;
    case 2:
        *candidate_disposition = srpl_candidate_conflict;
        break;
    }
    *offp = 0;
    return true;
}

static void
srpl_candidate_response(srpl_connection_t *srpl_connection, dso_state_t *dso)
{
    const char *names[3] = { "Candidate Yes", "Candidate No", "Conflict" };
    dso_message_types_t additionals[3] = { kDSOType_SRPLCandidateYes, kDSOType_SRPLCandidateNo, kDSOType_SRPLConflict };
    bool required[3] = { false, false, false };
    int indices[3];
    srpl_event_t event;

    srpl_event_initialize(&event, srpl_event_candidate_response_received);
    srpl_event_content_type_set(&event, srpl_event_content_type_candidate_disposition);
    if (!srpl_find_dso_additionals(srpl_connection, dso, additionals,
                                   required, names, indices, 3, 1, 1, "SRPLCandidate reply",
                                   &event.content.disposition, srpl_candidate_response_parse_in)) {
        goto fail;
    }
    srpl_event_deliver(srpl_connection, &event);
    return;

fail:
    srpl_disconnect(srpl_connection);
}

static bool
srpl_host_message_parse_in(int index, const uint8_t *buffer, unsigned *offp, uint16_t length, void *context)
{
    srpl_host_update_t *update = context;

    switch(index) {
    case 0:
        return dns_name_parse(&update->hostname, buffer, length, offp, length);
    case 1:
        return dns_u32_parse(buffer, length, offp, &update->update_offset);
    case 2:
        update->message = ioloop_message_create(length);
        if (update->message == NULL) {
            return false;
        }
        memcpy(&update->message->wire, buffer, length);
        *offp = length;
        return true;
    case 3:
        return dns_u64_parse(buffer, length, offp, &update->server_stable_id);
    }
    return false;
}

static void
srpl_host_message(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso)
{
    if (dso->primary.length != 0) {
        ERROR(PRI_S_SRP ": invalid DSO Primary length %d for SRPLHost message.",
              srpl_connection->name, dso->primary.length);
        goto fail;
    } else {
        const char *names[4] = { "Host Name", "Time Offset", "Host Message", "Server Stable ID" };
        dso_message_types_t additionals[4] = { kDSOType_SRPLHostname, kDSOType_SRPLTimeOffset, kDSOType_SRPLHostMessage,
            kDSOType_SRPLServerStableID };
        bool required[4] = { true, true, true, false };
        int indices[4];
        srpl_event_t event;

        // Parse host message
        srpl_event_initialize(&event, srpl_event_host_message_received);
        srpl_event_content_type_set(&event, srpl_event_content_type_host_update);
        if (!srpl_find_dso_additionals(srpl_connection, dso, additionals,
                                       required, names, indices, 4, 3, 4, "SRPLHost message",
                                       &event.content.host_update, srpl_host_message_parse_in)) {
            goto fail;
        }
        DNS_NAME_GEN_SRP(event.content.host_update.hostname, hostname_buf);
        INFO(PRI_S_SRP " received SRPLHost message %x for " PRI_DNS_NAME_SRP " server stable ID %" PRIx64,
             srpl_connection->name, ntohs(message->wire.id),
             DNS_NAME_PARAM_SRP(event.content.host_update.hostname, hostname_buf),
             event.content.host_update.server_stable_id);
        event.content.host_update.update_time =
            time(NULL) - event.content.host_update.update_offset;
        event.content.host_update.message->received_time = event.content.host_update.update_time;
        srpl_connection_message_set(srpl_connection, message);
        srpl_event_deliver(srpl_connection, &event);
        srpl_event_content_type_set(&event, srpl_event_content_type_none);
    }
    return;
fail:
    INFO(PRI_S_SRP " received invalid SRPLHost message %x", srpl_connection->name, ntohs(message->wire.id));
    srpl_disconnect(srpl_connection);
    return;
}

static void
srpl_host_response(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso)
{
    if (dso->primary.length != 0) {
        ERROR(PRI_S_SRP ": invalid DSO Primary length %d for SRPLHost response.",
              srpl_connection->name, dso->primary.length);
        srpl_disconnect(srpl_connection);
        return;
    } else {
        srpl_event_t event;
        INFO(PRI_S_SRP " received SRPLHost response %x", srpl_connection->name, ntohs(message->wire.id));
        srpl_event_initialize(&event, srpl_event_host_response_received);
        srpl_event_content_type_set(&event, srpl_event_content_type_rcode);
        event.content.rcode = dns_rcode_get(&message->wire);
        srpl_event_deliver(srpl_connection, &event);
        srpl_event_content_type_set(&event, srpl_event_content_type_none);
        return;
    }
}

static void
srpl_dso_retry_delay(srpl_connection_t *srpl_connection, int reconnect_delay)
{
    if (srpl_connection->instance == NULL) {
        // If there's no instance, we're already disconnecting.
        INFO(PRI_S_SRP ": no instance", srpl_connection->name);
        return;
    }

    // Set things up to reconnect later.
    srpl_connection_drop_state_delay(srpl_connection->instance, srpl_connection, reconnect_delay);

    // Drop the connection
    srpl_connection_discontinue(srpl_connection);
}

static void
srpl_dso_message(srpl_connection_t *srpl_connection, message_t *message, dso_state_t *dso, bool response)
{
    switch(dso->primary.opcode) {
    case kDSOType_SRPLSession:
        if (response) {
            srpl_session_response(srpl_connection, dso);
        } else {
            srpl_session_message(srpl_connection, message, dso);
        }
        break;

    case kDSOType_SRPLSendCandidates:
        if (response) {
            srpl_send_candidates_response(srpl_connection, dso);
        } else {
            srpl_send_candidates_message(srpl_connection, message, dso);
        }
        break;

    case kDSOType_SRPLCandidate:
        if (response) {
            srpl_candidate_response(srpl_connection, dso);
        } else {
            srpl_candidate_message(srpl_connection, message, dso);
        }
        break;

    case kDSOType_SRPLHost:
        if (response) {
            srpl_host_response(srpl_connection, message, dso);
        } else {
            srpl_host_message(srpl_connection, message, dso);
        }
        break;

    default:
        INFO("dso_message: unexpected primary TLV %d", dso->primary.opcode);
        dso_simple_response(srpl_connection->connection, NULL, &message->wire, dns_rcode_dsotypeni);
        break;
    }

}

static void
srpl_unclaimed_finalize(void *context)
{
    unclaimed_connection_t *unclaimed = context;
    if (unclaimed->wakeup_timeout != NULL) {
        ioloop_wakeup_release(unclaimed->wakeup_timeout);
        unclaimed->wakeup_timeout = NULL;
    }
    if (unclaimed->message != NULL) {
        ioloop_message_release(unclaimed->message);
    }
    free(context);
}

static void
srpl_unclaimed_cancel(unclaimed_connection_t *unclaimed)
{
    unclaimed_connection_t **up;
    bool found = false;

    // Remove it from the list if it's on the list
    for (up = &unclaimed_connections; *up != NULL; up = &(*up)->next) {
        if (*up == unclaimed) {
            *up = unclaimed->next;
            found = true;
            break;
        }
    }
    ERROR("unclaimed connection " PRI_S_SRP " (%p) removed",
          unclaimed->connection == NULL ? "<NULL>" : unclaimed->connection->name, unclaimed);

    if (unclaimed->dso != NULL) {
        dso_state_cancel(unclaimed->dso);
        unclaimed->dso = NULL;
    }
    if (unclaimed->wakeup_timeout != NULL) {
        ioloop_cancel_wake_event(unclaimed->wakeup_timeout);
        ioloop_wakeup_release(unclaimed->wakeup_timeout);
        unclaimed->wakeup_timeout = NULL;
    }
    if (unclaimed->message != NULL) {
        ioloop_message_release(unclaimed->message);
        unclaimed->message = NULL;
    }
    if (unclaimed->connection) {
        ioloop_comm_cancel(unclaimed->connection);
        ioloop_comm_release(unclaimed->connection);
        unclaimed->connection = NULL;
    }
    // If we removed it from the list, release the reference.
    if (found) {
        RELEASE_HERE(unclaimed, srpl_unclaimed_finalize);
    }
    return;
}

static void
srpl_unclaimed_dispose_callback(void *context)
{
    unclaimed_connection_t *unclaimed = context;
    INFO("unclaimed connection " PRI_S_SRP " (%p) timed out", unclaimed->connection->name, unclaimed);
    srpl_unclaimed_cancel(unclaimed);
}

static void
srpl_unclaimed_disconnect_callback(comm_t *connection, void *context, int err)
{
    unclaimed_connection_t *unclaimed = context;
    INFO("unclaimed connection " PRI_S_SRP " (%p) disconnected (error code %d)", connection->name, unclaimed, err);
    srpl_unclaimed_cancel(unclaimed);
}

static void
srpl_unclaimed_datagram_callback(comm_t *comm, message_t *message, void *context)
{
    unclaimed_connection_t *unclaimed = context;
    INFO("unclaimed connection " PRI_S_SRP " (%p) received unexpected message type %d",
         comm->name, unclaimed, dns_opcode_get(&message->wire));
    srpl_unclaimed_cancel(unclaimed);
}

static void
srpl_unclaimed_context_release(void *context)
{
    unclaimed_connection_t *unclaimed = context;
    INFO("unclaimed connection %p context released", unclaimed);
    RELEASE_HERE(unclaimed, srpl_unclaimed_finalize);
}

static void
srpl_add_unclaimed_server(comm_t *connection, message_t *message, dso_state_t *dso)
{
    unclaimed_connection_t **up, *unclaimed = calloc(1, sizeof(*unclaimed));
    if (unclaimed == NULL) {
        ERROR("no memory to hold on to unclaimed " PRI_S_SRP, connection->name);
        dso_state_cancel(dso);
    } else {
        RETAIN_HERE(unclaimed);
        unclaimed->wakeup_timeout = ioloop_wakeup_create();
        // We want to reclaim the unclaimed connection after two minutes, if no matching advertisement has yet
        // been found.
        if (unclaimed->wakeup_timeout) {
            ioloop_add_wake_event(unclaimed->wakeup_timeout, unclaimed,
                                  srpl_unclaimed_dispose_callback, NULL, 120 * MSEC_PER_SEC);
        } else {
            ERROR("Unable to add wakeup event for unclaimed " PRI_S_SRP, connection->name);
        }
        unclaimed->dso = dso;
        unclaimed->message = message;
        ioloop_message_retain(message);
        unclaimed->connection = connection;
        unclaimed->address = connection->address;
        ioloop_comm_retain(unclaimed->connection);

        // We shouldn't get any further datagrams before a connection is established.
        connection->datagram_callback = srpl_unclaimed_datagram_callback;
        ioloop_comm_context_set(connection, unclaimed, srpl_unclaimed_context_release);
        RETAIN_HERE(unclaimed); // connection holds a reference.

        // If we get a disconnect, we have to handle that.
        ioloop_comm_disconnect_callback_set(connection, srpl_unclaimed_disconnect_callback);

        // Find the end of the list.
        for (up = &unclaimed_connections; *up != NULL; up = &(*up)->next) {
        }
        *up = unclaimed;
    }
}

static void
srpl_instance_dso_event_callback(void *context, void *event_context, dso_state_t *dso, dso_event_type_t eventType)
{
    message_t *message;
    dso_query_receive_context_t *response_context;
    dso_disconnect_context_t *disconnect_context;

    switch(eventType)
    {
    case kDSOEventType_DNSMessage:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("DNS Message (opcode=%d) received from " PRI_S_SRP, dns_opcode_get(&message->wire),
             dso->remote_name);
        break;
    case kDSOEventType_DNSResponse:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("DNS Response (opcode=%d) received from " PRI_S_SRP, dns_opcode_get(&message->wire),
             dso->remote_name);
        break;
    case kDSOEventType_DSOMessage:
        INFO("DSO Message (Primary TLV=%d) received from " PRI_S_SRP,
               dso->primary.opcode, dso->remote_name);
        message = event_context;
        srpl_dso_message((srpl_connection_t *)context, message, dso, false);
        break;
    case kDSOEventType_DSOResponse:
        INFO("DSO Response (Primary TLV=%d) received from " PRI_S_SRP,
               dso->primary.opcode, dso->remote_name);
        response_context = event_context;
        message = response_context->message_context;
        srpl_dso_message((srpl_connection_t *)context, message, dso, true);
        break;

    case kDSOEventType_Finalize:
        INFO("Finalize");
        break;

    case kDSOEventType_Connected:
        INFO("Connected to " PRI_S_SRP, dso->remote_name);
        break;

    case kDSOEventType_ConnectFailed:
        INFO("Connection to " PRI_S_SRP " failed", dso->remote_name);
        break;

    case kDSOEventType_Disconnected:
        INFO("Connection to " PRI_S_SRP " disconnected", dso->remote_name);
        break;
    case kDSOEventType_ShouldReconnect:
        INFO("Connection to " PRI_S_SRP " should reconnect (not for a server)", dso->remote_name);
        break;
    case kDSOEventType_Inactive:
        INFO("Inactivity timer went off, closing connection.");
        break;
    case kDSOEventType_Keepalive:
        INFO("should send a keepalive now.");
        break;
    case kDSOEventType_KeepaliveRcvd:
        INFO("keepalive received.");
        break;
    case kDSOEventType_RetryDelay:
        disconnect_context = event_context;
        INFO("retry delay received, %d seconds", disconnect_context->reconnect_delay);
        srpl_dso_retry_delay(context, disconnect_context->reconnect_delay);
        break;
    }
}

static void
srpl_datagram_callback(comm_t *comm, message_t *message, void *context)
{
    srpl_connection_t *srpl_connection = context;
    srpl_instance_t *instance = srpl_connection->instance;

    // If this is a DSO message, see if we have a session yet.
    switch(dns_opcode_get(&message->wire)) {
    case dns_opcode_dso:
        if (srpl_connection->dso == NULL) {
            INFO("dso message received with no DSO object on instance " PRI_S_SRP, instance->instance_name);
            srpl_disconnect(srpl_connection);
            return;
        }
        dso_message_received(srpl_connection->dso, (uint8_t *)&message->wire, message->length, message);
        return;
        break;
    }
    INFO("datagram on connection " PRI_S_SRP " not handled, type = %d.",
         comm->name, dns_opcode_get(&message->wire));
}

static void
srpl_associate_incoming_with_instance(comm_t *connection, message_t *message,
                                      dso_state_t *dso, srpl_instance_t *instance)
{
    srpl_connection_t *srpl_connection = srpl_connection_create(instance, false);
    if (srpl_connection == NULL) {
        ioloop_comm_cancel(connection);
        return;
    }
    instance->incoming = srpl_connection;
    RETAIN_HERE(instance->incoming);
    srpl_connection->connection = connection;
    ioloop_comm_retain(srpl_connection->connection);
    srpl_connection->dso = dso;
    srpl_connection->instance = instance;
    srpl_connection->connected_address = connection->address;
    srpl_connection->state = srpl_state_session_message_wait;
    dso_set_event_context(dso, srpl_connection);
    dso_set_event_callback(dso, srpl_instance_dso_event_callback);
    connection->datagram_callback = srpl_datagram_callback;
    connection->disconnected = srpl_disconnected_callback;
    ioloop_comm_context_set(connection, srpl_connection, srpl_connection_context_release);
    RETAIN_HERE(srpl_connection); // the connection has a reference.
    srpl_connection_next_state(srpl_connection, srpl_state_session_message_wait);
    srpl_instance_dso_event_callback(srpl_connection, message, dso, kDSOEventType_DSOMessage);
}

void
srpl_dso_server_message(comm_t *connection, message_t *message, dso_state_t *dso)
{
    srpl_domain_t *domain;
    srpl_instance_t *instance;
    address_query_t *address;
    int i;

    // Figure out from which instance this connection originated
    for (domain = srpl_domains; domain != NULL; domain = domain->next) {
        for (instance = domain->instances; instance != NULL; instance = instance->next) {
            address = instance->address_query;
            if (address == NULL) {
                continue;
            }
            for (i = 0; i < address->num_addresses; i++) {
                if (ip_addresses_equal(&connection->address, &address->addresses[i])) {
                    INFO("SRP Replication connection received from " PRI_S_SRP " on " PRI_S_SRP,
                         address->hostname, connection->name);
                    srpl_associate_incoming_with_instance(connection, message, dso, instance);
                    return;
                }
            }
        }
    }

    INFO("incoming SRP Replication server connection from unrecognized server " PRI_S_SRP, connection->name);
    srpl_add_unclaimed_server(connection, message, dso);
}

static void
srpl_connected(comm_t *connection, void *context)
{
    srpl_connection_t *srpl_connection = context;

    INFO(PRI_S_SRP " connected", connection->name);
    connection->dso = dso_state_create(false, 1, connection->name, srpl_instance_dso_event_callback,
                                       srpl_connection, NULL, connection);
    if (connection->dso == NULL) {
        ERROR(PRI_S_SRP " can't create dso state object.", srpl_connection->name);
        srpl_disconnect(srpl_connection);
        return;
    }
    srpl_connection->connection = connection;
    ioloop_comm_retain(srpl_connection->connection);
    srpl_connection->dso = connection->dso;

    // Generate an event indicating that we've been connected
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_connected);
    srpl_event_deliver(srpl_connection, &event);
}

static bool
srpl_connection_connect(srpl_connection_t *srpl_connection)
{
    if (srpl_connection->instance == NULL) {
        ERROR(PRI_S_SRP ": no instance to connect to", srpl_connection->name);
        return false;
    }
    int to_port = srpl_connection->instance->outgoing_port;
    if (srpl_connection->connected_address.sa.sa_family == AF_INET) {
        srpl_connection->connected_address.sin.sin_port = htons(to_port);
    } else {
        srpl_connection->connected_address.sin6.sin6_port = htons(to_port);
    }
    srpl_connection->connection = ioloop_connection_create(&srpl_connection->connected_address,
                                                           // tls, stream, stable, opportunistic
                                                             true,   true,   true, true,
                                                           srpl_datagram_callback, srpl_connected,
                                                           srpl_disconnected_callback, srpl_connection_context_release,
                                                           srpl_connection);
    if (srpl_connection->connection == NULL) {
        ADDR_NAME_LOGGER(ERROR, &srpl_connection->connected_address, "can't create connection to address ",
                         " for srpl connection ", " port ", srpl_connection->name, to_port);
        return false;
    }
    ADDR_NAME_LOGGER(INFO, &srpl_connection->connected_address, "connecting to address ", " for instance ", " port ",
                      srpl_connection->name, to_port);
    RETAIN_HERE(srpl_connection); // For the connection's reference
    return true;
}

static void
srpl_instance_is_me(srpl_instance_t *instance, const char *ifname, const addr_t *address)
{
    instance->is_me = true;
    if (ifname != NULL) {
        INFO(PRI_S_SRP "/" PUB_S_SRP ": name server for instance " PRI_S_SRP " is me.", instance->name, ifname, instance->instance_name);
    } else if (address != NULL) {
        ADDR_NAME_LOGGER(INFO, address, "", " instance ", " is me. ", instance->name, 0);
    } else {
        ERROR("srpl_instance_is_me with null ifname and address!");
        return;
    }

    // When we create the instance, we start an outgoing connection; when we discover that this is a connection
    // to me, we can discontinue that outgoing connection.
    if (instance->outgoing) {
        srpl_connection_discontinue(instance->outgoing);
    }
}

static bool
srpl_my_address_check(const addr_t *address)
{
    static interface_address_state_t *ifaddrs = NULL;
    interface_address_state_t *ifa;
    static time_t last_fetch = 0;
    // Update the interface address list every sixty seconds, but only if we're asked to check an address.
    const time_t now = time(NULL);
    if (now - last_fetch > 60) {
        last_fetch = now;
        ioloop_map_interface_addresses_here(&ifaddrs, NULL, NULL, NULL);
    }
    // See if there's a match.
    for (ifa = ifaddrs; ifa; ifa = ifa->next) {
        if (ip_addresses_equal(address, &ifa->addr)) {
            return true;
        }
    }
    return false;
}

static void
srpl_instance_address_callback(void *context, addr_t *address, bool added, int err)
{
    srpl_instance_t *instance = context;
    if (err != kDNSServiceErr_NoError) {
        ERROR("service instance address resolution for " PRI_S_SRP " failed with %d", instance->name, err);
        if (instance->address_query) {
            address_query_cancel(instance->address_query);
            instance->address_query = NULL;
        }
        return;
    }
    if (added) {
        unclaimed_connection_t **up = &unclaimed_connections;
        while (*up != NULL) {
            unclaimed_connection_t *unclaimed = *up;
            if (ip_addresses_equal(address, &unclaimed->address)) {
                INFO("Unclaimed connection " PRI_S_SRP " matches new address for " PRI_S_SRP, unclaimed->dso->remote_name,
                     instance->name);
                srpl_associate_incoming_with_instance(unclaimed->connection,
                                                      unclaimed->message, unclaimed->dso, instance);
                unclaimed->dso = NULL;
                *up = unclaimed->next;
                srpl_unclaimed_cancel(unclaimed);
                break;
            } else {
                if (unclaimed->address.sa.sa_family == AF_INET6) {
                    SEGMENTED_IPv6_ADDR_GEN_SRP(&unclaimed->address.sin6.sin6_addr, rdata_buf);
                    INFO("Unclaimed connection address is: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(&unclaimed->address.sin6.sin6_addr, rdata_buf));
                } else {
                    IPv4_ADDR_GEN_SRP(&unclaimed->address.sin.sin_addr, rdata_buf);
                    INFO("Unclaimed connection address is: " PRI_IPv4_ADDR_SRP,
                         IPv4_ADDR_PARAM_SRP(&unclaimed->address.sin.sin_addr, rdata_buf));
                }
                if (address->sa.sa_family == AF_INET6) {
                    SEGMENTED_IPv6_ADDR_GEN_SRP(&address->sin6.sin6_addr, rdata_buf);
                    INFO("Unclaimed connection address is: " PRI_SEGMENTED_IPv6_ADDR_SRP,
                         SEGMENTED_IPv6_ADDR_PARAM_SRP(&address->sin6.sin6_addr, rdata_buf));
                } else {
                    IPv4_ADDR_GEN_SRP(&address->sin.sin_addr, rdata_buf);
                    INFO("Unclaimed connection address is: " PRI_IPv4_ADDR_SRP,
                         IPv4_ADDR_PARAM_SRP(&address->sin.sin_addr, rdata_buf));
                }
                INFO("Unclaimed connection " PRI_S_SRP " does not match new address for " PRI_S_SRP, unclaimed->dso->remote_name,
                     instance->name);
                up = &(*up)->next;
            }
        }

        if (srpl_my_address_check(address)) {
            srpl_instance_is_me(instance, NULL, address);
        }

        // Generate an event indicating that we have a new address.
        if (instance->outgoing != NULL) {
            srpl_event_t event;
            srpl_event_initialize(&event, srpl_event_address_add);
            srpl_event_deliver(instance->outgoing, &event);
        }
    } else {
        srpl_event_t event;
        srpl_event_initialize(&event, srpl_event_address_remove);

        // Generate an event indicating that an address has been removed.
        if (instance->incoming != NULL) {
            srpl_event_deliver(instance->incoming, &event);
        }
        if (instance->outgoing != NULL) {
            srpl_event_deliver(instance->outgoing, &event);
        }
    }
}

static void
srpl_instance_add(const char *hostname, const char *instance_name,
                  const char *ifname, srpl_domain_t *domain, srpl_instance_t *instance,
                  bool have_server_id, uint64_t advertised_server_id)
{
    srpl_instance_t **sp;

    // Find the instance on the instance list for this domain.
    for (sp = &domain->instances; *sp != NULL; sp = &(*sp)->next) {
        if (instance == *sp) {
            break;
        }
    }

    if (*sp == NULL) {
        INFO("instance " PRI_S_SRP " for " PRI_S_SRP "/" PUB_S_SRP " " PUB_S_SRP "id %" PRIx64 " no longer on list",
             instance_name != NULL ? instance_name : "<NULL>", hostname, ifname, have_server_id ? "" : "!", advertised_server_id);
        if (instance->resolve_txn != NULL) {
            ioloop_dnssd_txn_cancel(instance->resolve_txn);
            ioloop_dnssd_txn_release(instance->resolve_txn);
            instance->resolve_txn = NULL;
        }
        return;
    }

    INFO("instance " PRI_S_SRP " for " PRI_S_SRP "/" PUB_S_SRP " " PUB_S_SRP "id %" PRIx64 " " PUB_S_SRP "found",
         instance_name != NULL ? instance_name : "<NULL>", hostname, ifname, have_server_id ? "" : "!", advertised_server_id,
         *sp == NULL ? "!" : "");


    // If the hostname changed, we need to restart the address query.
    if (instance->name == NULL || strcmp(instance->name, hostname)) {
        if (instance->address_query != NULL) {
            address_query_cancel(instance->address_query);
            instance->address_query = NULL;
        }

        if (instance->name != NULL) {
            INFO("name server name change from " PRI_S_SRP " to " PRI_S_SRP " for " PRI_S_SRP "/" PUB_S_SRP " in domain " PRI_S_SRP,
                 instance->name, hostname, instance_name == NULL ? "<NULL>" : instance_name, ifname, domain->name);
        } else {
            INFO("new name server " PRI_S_SRP " for " PRI_S_SRP "/" PUB_S_SRP " in domain " PRI_S_SRP,
                 hostname, instance_name == NULL ? "<NULL>" : instance_name, ifname, domain->name);
        }

        char *new_name = strdup(hostname);
        if (new_name == NULL) {
            // This should never happen, and if it does there's actually no clean way to recover from it.  This approach
            // will result in no crash, and since we don't start an address query in this case, we will just wind up in
            // a quiescent state for this replication peer until something changes.
            ERROR("no memory for instance name.");
            return;
        } else {
            free(instance->name);
            instance->name = new_name;
        }
        // The instance may be connected. It's possible its IP address hasn't changed. If it has changed, we should
        // get a disconnect due to a connection timeout or (if something else got the same address, a reset) if for
        // no other reason, and then we'll try to reconnect, so this should be harmless.
    }

    // The address query can be NULL either because we only just created the instance, or because the instance name changed (e.g.
    // as the result of a hostname conflict).
    if (instance->address_query == NULL) {
        instance->address_query = address_query_create(instance->name, instance,
                                                       srpl_instance_address_callback,
                                                       srpl_instance_context_release);
        if (instance->address_query == NULL) {
            INFO("unable to create address query");
        } else {
            RETAIN_HERE(instance->address_query);
            RETAIN_HERE(instance); // retain for the address query.
        }
    }

    if (instance->outgoing == NULL && !instance->is_me) {
        instance->outgoing = srpl_connection_create(instance, true);
        srpl_connection_next_state(instance->outgoing, srpl_state_disconnected);
    }

    if (instance->discontinue_timeout != NULL) {
        if (instance->discontinuing) {
            INFO("discontinue on instance " PRI_S_SRP " canceled.", instance->name);
        }
        ioloop_cancel_wake_event(instance->discontinue_timeout);
    }
    instance->num_copies++;
    instance->discontinuing = false;

    // If this add changed the server ID, we may want to re-attempt a connect.
    if (have_server_id && (!instance->have_server_id || instance->server_id != advertised_server_id)) {
        instance->have_server_id = true;
        instance->server_id = advertised_server_id;
        if (instance->outgoing != NULL && instance->outgoing->state == srpl_state_idle) {
            srpl_connection_next_state(instance->outgoing, srpl_state_disconnected);
        }
    }
}

static void
srpl_resolve_callback(DNSServiceRef UNUSED sdRef, DNSServiceFlags UNUSED flags, uint32_t interfaceIndex,
                      DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port,
                      uint16_t UNUSED txtLen, const unsigned char *UNUSED txtRecord, void *context)
{
    char ifname[IFNAMSIZ];
    srpl_instance_t *instance = context;
    srpl_domain_t *domain = instance->domain;
    const char *domain_name;
    uint8_t domain_len;
    const char *server_id_string;
    uint8_t server_id_string_len;
    char server_id_buf[INT64_HEX_STRING_MAX];
    uint64_t advertised_server_id = 0;
    bool have_server_id = false;

    if (errorCode != kDNSServiceErr_NoError) {
        ERROR("resolve for " PRI_S_SRP " failed with %d", fullname, errorCode);
        return;
    }

    domain_name = TXTRecordGetValuePtr(txtLen, txtRecord, "domain", &domain_len);
    if (domain_name == NULL) {
        INFO("resolve for " PRI_S_SRP " succeeded, but there is no domain name.", fullname);
        return;
    }

    if (domain_len != strlen(domain->name) || memcmp(domain_name, domain->name, domain_len)) {
        const char *domain_print;
        char *domain_terminated = malloc(domain_len + 1);
        if (domain_terminated == NULL) {
            domain_print = "<no memory for domain name>";
        } else {
            memcpy(domain_terminated, domain_name, domain_len);
            domain_terminated[domain_len] = 0;
            domain_print = domain_terminated;
        }
        INFO("domain (" PRI_S_SRP ") for " PRI_S_SRP " doesn't match expected domain " PRI_S_SRP,
             domain_print, fullname, domain->name);
        free(domain_terminated);
        return;
    }
    if (strcmp(domain->name, current_thread_domain_name)) {
        INFO("discovered srpl instance is not for current thread domain, so not setting up replication.");
        return;
    }

    server_id_string = TXTRecordGetValuePtr(txtLen, txtRecord, "server-id", &server_id_string_len);
    if (server_id_string != NULL && server_id_string_len < INT64_HEX_STRING_MAX) {
        char *endptr, *nulptr;
        unsigned long long num;
        memcpy(server_id_buf, server_id_string, server_id_string_len);
        nulptr = &server_id_buf[server_id_string_len];
        *nulptr = '\0';
        num = strtoull(server_id_buf, &endptr, 16);
        // On current architectures, unsigned long long and uint64_t are the same size, but we should have a check here
        // just in case, because the standard doesn't guarantee that this will be true.
        // If endptr == nulptr, that means we converted the entire buffer and didn't run into a NUL in the middle of it
        // somewhere.
        if (num < UINT64_MAX && endptr == nulptr) {
            advertised_server_id = num;
            have_server_id = true;
        }
    }

    instance->outgoing_port = ntohs(port);

    if (if_indextoname(interfaceIndex, ifname) == NULL) {
        snprintf(ifname, sizeof(ifname), "%d", interfaceIndex);
    }

    srpl_instance_add(hosttarget, fullname, ifname, instance->domain, instance, have_server_id, advertised_server_id);
}

static void
srpl_browse_callback(DNSServiceRef UNUSED sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                     DNSServiceErrorType errorCode, const char *serviceName, const char *regtype,
                     const char *replyDomain, void *context)
{
    DNSServiceRef sdref;
    srpl_domain_t *domain = context;
    if (errorCode != kDNSServiceErr_NoError) {
        ERROR("browse on domain " PRI_S_SRP " failed with %d", domain->name, errorCode);
        if (domain->query != NULL) {
            ioloop_dnssd_txn_cancel(domain->query);
            ioloop_dnssd_txn_release(domain->query);
            domain->query = NULL;
        }
        return;
    }

    char instance_name[kDNSServiceMaxDomainName];
    DNSServiceConstructFullName(instance_name, serviceName, regtype, replyDomain);

    if (flags & kDNSServiceFlagsAdd) {
        srpl_instance_t *instance = NULL, **sp;
        // See if we already have an instance going; if so, just increment the number of copies of the instance that we've found.
        for (sp = &domain->instances; *sp; sp = &(*sp)->next) {
            instance = *sp;
            if (!strcmp(instance->instance_name, instance_name) && instance->resolve_txn != NULL) {
                instance->num_copies++;
                INFO("duplicate add for " PRI_S_SRP, instance_name);
                return;
            }
        }

        if (*sp == NULL) {
            instance = calloc(1, sizeof(*instance));
            if (instance == NULL) {
                ERROR("no memory for instance" PRI_S_SRP, instance_name);
                return;
            }
            // Retain the instance object in case it gets removed while the resolve is still active. We do this here in case the
            // resolve_txn allocation fails. When the transaction is canceled, the reference to the instance object will be dropped.
            RETAIN_HERE(instance);
            instance->domain = domain;
            RETAIN_HERE(instance->domain);

            instance->instance_name = strdup(instance_name);
            if (instance->instance_name == NULL) {
                ERROR("no memory for instance " PRI_S_SRP, instance_name);
                RELEASE_HERE(instance, srpl_instance_finalize);
                return;
            }

            int err = DNSServiceResolve(&sdref, 0, interfaceIndex,
                                        serviceName, regtype, replyDomain, srpl_resolve_callback, instance);
            if (err != kDNSServiceErr_NoError) {
                ERROR("unable to resolve " PRI_S_SRP ": code %d", instance_name, err);
                RELEASE_HERE(instance, srpl_instance_finalize);
                return;
            }
            instance->resolve_txn = ioloop_dnssd_txn_add(sdref, instance, srpl_instance_context_release, NULL);
            if (instance->resolve_txn == NULL) {
                ERROR("unable to allocate dnssd_txn_t for " PRI_S_SRP, instance_name);
                DNSServiceRefDeallocate(sdref);
                RELEASE_HERE(instance, srpl_instance_finalize);
                return;
            }
            INFO("resolving " PRI_S_SRP, instance_name);
            *sp = instance;
            RETAIN_HERE(instance);
        }
    } else {
        INFO("_srpl-tls._tcp service instance " PRI_S_SRP " went away.", instance_name);
        for (srpl_instance_t *instance = domain->instances; instance; instance = instance->next) {
            if (!strcmp(instance->instance_name, instance_name)) {
                instance->num_copies--;
                srpl_instance_discontinue(instance);
                break;
            }
        }
    }
}

static void
srpl_domain_context_release(void *context)
{
    srpl_domain_t *domain = context;
    RELEASE_HERE(domain, srpl_domain_finalize);
}

static void
srpl_dnssd_txn_fail(void *context, int err)
{
    srpl_domain_t *domain = context;
    ERROR("service browse " PRI_S_SRP " i/o failure: %d", domain->name, err);
}

static void
srpl_domain_add(const char *domain_name)
{
    srpl_domain_t **dp, *domain;
    DNSServiceRef sdref;
    int ret;

    // Find the domain, if it's already there.
    for (dp = &srpl_domains; *dp; dp = &(*dp)->next) {
        domain = *dp;
        if (!strcasecmp(domain->name, domain_name)) {
            break;
        }
    }

    // If not there, make it.
    if (*dp == NULL) {
        domain = calloc(1, sizeof(*domain));
        if (domain == NULL || (domain->name = strdup(domain_name)) == NULL) {
            ERROR("Unable to allocate replication structure for domain " PRI_S_SRP, domain_name);
            free(domain);
            return;
        }
        *dp = domain;
        // Hold a reference for the domain list
        RETAIN_HERE(domain);
        INFO("New service replication browsing domain: " PRI_S_SRP, domain->name);
    } else {
        ERROR("Unexpected duplicate replication domain: " PRI_S_SRP, domain_name);
        return;
    }

    // Look for an NS record for the specified domain using mDNS, not DNS.
    ret = DNSServiceBrowse(&sdref, kDNSServiceFlagsLongLivedQuery,
                                kDNSServiceInterfaceIndexAny, "_srpl-tls._tcp", NULL, srpl_browse_callback, domain);
    if (ret != kDNSServiceErr_NoError) {
        ERROR("Unable to query for NS records for " PRI_S_SRP, domain_name);
        return;
    }
    domain->query = ioloop_dnssd_txn_add(sdref, srpl_domain_context_release, NULL, srpl_dnssd_txn_fail);
    if (domain->query == NULL) {
        ERROR("Unable to set up ioloop transaction for NS query on " PRI_S_SRP, domain_name);
        DNSServiceRefDeallocate(sdref);
        return;
    }
    RETAIN_HERE(domain);
}

static void
srpl_domain_rename(const char *current_name, const char *new_name)
{
    ERROR("replication domain " PRI_S_SRP " renamed to " PRI_S_SRP ", not currently handled.", current_name, new_name);
}

// Note that when this is implemented, it has the potential to return new thread domain names more than once, so
// in principle we need to change the name of the domain we are advertising.
static cti_status_t
cti_get_thread_network_name(void *context, cti_tunnel_reply_t NONNULL callback,
                            run_context_t NULLABLE UNUSED client_queue)
{
    callback(context, "openthread", kCTIStatus_NoError);
    return kCTIStatus_NoError;
}

//
// Event apply functions, print functions, and state actions, generally in order
//

static bool
event_is_message(srpl_event_t *event)
{
    switch(event->event_type) {
    case srpl_event_invalid:
    case srpl_event_address_add:
    case srpl_event_address_remove:
    case srpl_event_server_disconnect:
    case srpl_event_reconnect_timer_expiry:
    case srpl_event_disconnected:
    case srpl_event_connected:
    case srpl_event_advertise_finished:
    case srpl_event_srp_client_update_finished:
        return false;

    case srpl_event_session_response_received:
    case srpl_event_send_candidates_response_received:
    case srpl_event_candidate_received:
    case srpl_event_host_message_received:
    case srpl_event_candidate_response_received:
    case srpl_event_host_response_received:
    case srpl_event_session_message_received:
    case srpl_event_send_candidates_message_received:
        return true;
    }
    return false;
}

// States that require an instance (most states)
#define REQUIRE_SRPL_INSTANCE(srpl_connection)                                                              \
    do {                                                                                                    \
        if ((srpl_connection)->instance == NULL) {                                                          \
            ERROR(PRI_S_SRP ": no instance in state " PUB_S_SRP, srpl_connection->name,                     \
                  srpl_connection->state_name);                                                             \
            return srpl_state_invalid;                                                                      \
        }                                                                                                   \
    } while(false)

// For states that never receive events.
#define REQUIRE_SRPL_EVENT_NULL(srpl_connection, event)                                      \
    do {                                                                                     \
        if ((event) != NULL) {                                                               \
            ERROR(PRI_S_SRP ": received unexpected " PUB_S_SRP " event in state " PUB_S_SRP, \
                  srpl_connection->name, event->name, srpl_connection->state_name);          \
            return srpl_state_invalid;                                                       \
        }                                                                                    \
    } while (false)

// Announce that we have entered a state that takes no events
#define STATE_ANNOUNCE_NO_EVENTS(srpl_connection)                                                          \
    do {                                                                                                   \
        INFO(PRI_S_SRP ": entering state " PUB_S_SRP, srpl_connection->name, srpl_connection->state_name); \
    } while (false)

// Announce that we have entered a state that takes no events
#define STATE_ANNOUNCE_NO_EVENTS_NAME(connection, fqdn)                                                    \
    do {                                                                                                   \
        char hostname[kDNSServiceMaxDomainName];                                                           \
        dns_name_print(fqdn, hostname, sizeof(hostname));                                                  \
        INFO(PRI_S_SRP ": entering state " PUB_S_SRP " with host " PRI_S_SRP,                              \
            connection->name, connection->state_name, hostname);                                           \
    } while (false)

// Announce that we have entered a state that takes no events
#define STATE_ANNOUNCE(srpl_connection, event)                                                       \
    do {                                                                                             \
        if (event != NULL)  {                                                                        \
            INFO(PRI_S_SRP ": event " PUB_S_SRP " received in state " PUB_S_SRP,                     \
                 srpl_connection->name, event->name, srpl_connection->state_name);                   \
        } else {                                                                                     \
            INFO(PRI_S_SRP ": entering state " PUB_S_SRP,                                            \
            srpl_connection->name, srpl_connection->state_name);                                     \
        }                                                                                            \
    } while (false)

#define UNEXPECTED_EVENT_MAIN(srpl_connection, event, bad)                             \
    do {                                                                               \
        if (event_is_message(event)) {                                                 \
            INFO(PRI_S_SRP ": invalid event " PUB_S_SRP " in state " PUB_S_SRP,        \
                 (srpl_connection)->name, (event)->name, srpl_connection->state_name); \
            return bad;                                                                \
        }                                                                              \
        INFO(PRI_S_SRP ": unexpected event " PUB_S_SRP " in state " PUB_S_SRP,         \
            (srpl_connection)->name, (event)->name,                                    \
             srpl_connection->state_name);                                             \
        return srpl_state_invalid;                                                     \
    } while (false)

// UNEXPECTED_EVENT flags the response as bad on a protocol level, triggering a retry delay
// UNEXPECTED_EVENT_NO_ERROR doesn't.
#define UNEXPECTED_EVENT(srpl_connection, event) UNEXPECTED_EVENT_MAIN(srpl_connection, event, srpl_state_invalid)
#define UNEXPECTED_EVENT_NO_ERROR(srpl_connection, event) \
    UNEXPECTED_EVENT_MAIN(srpl_connection, event, srpl_connection_drop_state(srpl_connection->instance, srpl_connection))

static void
srpl_instance_reconnect(void *context)
{
    srpl_instance_t *instance = context;
    srpl_event_t event;

    // If we have a new connection, no need to reconnect.
    if (instance->incoming != NULL && instance->incoming->state != srpl_state_idle) {
        INFO(PRI_S_SRP ": we now have a valid connection.", instance->name);
        return;
    }
    // We shouldn't have an outgoing connection.
    if (instance->outgoing != NULL && instance->outgoing->state != srpl_state_idle) {
        FAULT(PRI_S_SRP ": got to srpl_instance_reconnect with a non-idle outgoing connection.", instance->name);
        return;
    }

    // We don't get rid of the outgoing connection when it's idle, so we shouldn't be able to get here.
    if (instance->outgoing == NULL) {
        FAULT(PRI_S_SRP "instance->outgoing is NULL!", instance->name);
        return;
    }

    // Trigger a reconnect.
    srpl_event_initialize(&event, srpl_event_reconnect_timer_expiry);
    srpl_event_deliver(instance->outgoing, &event);
}

static srpl_state_t
srpl_connection_drop_state_delay(srpl_instance_t *instance, srpl_connection_t *srpl_connection, int delay)
{
    // Schedule a reconnect.
    if (instance->reconnect_timeout == NULL) {
        instance->reconnect_timeout = ioloop_wakeup_create();
    }
    if (instance->reconnect_timeout == NULL) {
        FAULT(PRI_S_SRP "disconnecting, but can't reconnect!", srpl_connection->name);
    } else {
        ioloop_add_wake_event(instance->reconnect_timeout, instance, srpl_instance_reconnect, NULL, delay * MSEC_PER_SEC);
    }

    if (srpl_connection == instance->incoming) {
        srpl_connection->retry_delay = delay;
        return srpl_state_retry_delay_send;
    } else {
        return srpl_state_disconnect;
    }
}

static srpl_state_t
srpl_connection_drop_state(srpl_instance_t *instance, srpl_connection_t *srpl_connection)
{
    return srpl_connection_drop_state_delay(instance, srpl_connection, 300);
}

// Call when there's a protocol error, so that we don't start reconnecting over and over.
static void
srpl_disconnect(srpl_connection_t *srpl_connection)
{
    const int delay = 300; // five minutes
    srpl_instance_t *instance = srpl_connection->instance;
    if (instance != NULL) {
        srpl_state_t state = srpl_connection_drop_state_delay(instance, srpl_connection, delay);
        if (state == srpl_state_retry_delay_send) {
            srpl_retry_delay_send(srpl_connection, delay);
        }
    }
    srpl_connection_discontinue(srpl_connection);
}

// We arrive at the disconnected state when there is no connection to make, or no need to make a connection.
// This state takes no action, but waits for events. If we get an add event and we don't have a viable incoming
// connection, we go to the next_address_get event.
static srpl_state_t
srpl_disconnected_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_address_add) {
        return srpl_state_next_address_get;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// This state takes the action of looking for an address to try. This can have three outcomes:
//
// * No addresses available: go to the disconnected state
// * End of address list: go to the reconnect_wait state
// * Address found: got to the connect state

static srpl_state_t
srpl_next_address_get_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    address_query_t *address_query = NULL;
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);

    address_query = srpl_connection->instance->address_query;

    // Get the next address
    // Return an event, one of "next address", "end of address list" or "no addresses"
    if (address_query == NULL || address_query->num_addresses == 0) {
        return srpl_state_disconnected;
    } else {
        // Go to the next address, if there is a next address.
        if (address_query->cur_address == address_query->num_addresses ||
            ++address_query->cur_address == address_query->num_addresses)
        {
            address_query->cur_address = -1;
            return srpl_state_reconnect_wait;
        } else {
            memcpy(&srpl_connection->connected_address,
                   &address_query->addresses[address_query->cur_address], sizeof(addr_t));
            return srpl_state_connect;
        }
    }
}

// This state takes the action of connecting to the connection's current address, which is expected to have
// been set. This can have two outcomes:
//
// * The connect attempt fails immediately: go to the next_address_get state
// * The connection attempt is in progress: go to the connecting state
static srpl_state_t
srpl_connect_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);

    // Connect to the address from the event.
    if (!srpl_connection_connect(srpl_connection)) {
        return srpl_state_next_address_get;
    } else {
        return srpl_state_connecting;
    }
}

// We reach this state when we are disconnected and don't need to reconnect because we have an active server
// connection. If we get a server disconnect here, then we go to the next_address_get state.
static srpl_state_t
srpl_idle_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);
    if (event == NULL) {
        return srpl_state_invalid; // Wait for events
    } else if (event->event_type == srpl_event_server_disconnect ||
               event->event_type == srpl_event_reconnect_timer_expiry)
    {
        INFO(PRI_S_SRP ": event " PUB_S_SRP " received in state " PUB_S_SRP,
             srpl_connection->name, event->name, srpl_connection->state_name);
        return srpl_state_next_address_get;
    } else {
        // We don't log unhandled events in the idle state because it creates a lot of noise.
        return srpl_state_invalid;
    }
}

// We've received a timeout event on the reconnect timer. Generate a reconnect_timeout event and send it to the
// connection.
static void
srpl_connection_reconnect_timeout(void *context)
{
    srpl_connection_t *srpl_connection = context;
    srpl_event_t event;
    srpl_event_initialize(&event, srpl_event_reconnect_timer_expiry);
    srpl_event_deliver(srpl_connection, &event);
}

// We reach the set_reconnect_timer state when we have tried to connect to all the known addresses.  Once we have set a
// timer, we wait for events. If we get a reconnect_timeout event, we go to the next_address_get state. If we get an
// add_adress event, we cancel the retransmit timer and go to the next_address_get state.
static srpl_state_t
srpl_reconnect_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        // Create a reconnect timer on the srpl_connection_t
        if (srpl_connection->reconnect_wakeup == NULL) {
            srpl_connection->reconnect_wakeup = ioloop_wakeup_create();
            if (srpl_connection->reconnect_wakeup == NULL) {
                ERROR("no memory for reconnect_wakeup for service instance " PRI_S_SRP, srpl_connection->name);
                return srpl_state_invalid;
            }
        } else {
            ioloop_cancel_wake_event(srpl_connection->reconnect_wakeup);
        }
        ioloop_add_wake_event(srpl_connection->reconnect_wakeup, srpl_connection, srpl_connection_reconnect_timeout,
                              srpl_connection_context_release, 60 * 1000);
        RETAIN_HERE(srpl_connection); // the timer has a reference.
        return srpl_state_invalid;
    }
    if (event->event_type == srpl_event_reconnect_timer_expiry) {
        return srpl_state_next_address_get;
    } else if (event->event_type == srpl_event_address_add) {
        ioloop_cancel_wake_event(srpl_connection->reconnect_wakeup);
        return srpl_state_next_address_get;
    }
    UNEXPECTED_EVENT(srpl_connection, event);
}

// We get to this state when the remote end has sent something bogus; in this case we send a retry_delay message to
// tell the client not to reconnect for a while.
static srpl_state_t
srpl_retry_delay_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    srpl_retry_delay_send(srpl_connection, srpl_connection->retry_delay);
    return srpl_state_disconnect;
}

// We go to the disconnect state when the connection needs to be dropped either because we lost the session ID
// coin toss or something's gone wrong. In either case, we do not attempt to reconnect--we either go to the idle state
// or the disconnect_wait state, depending on whether or not the connection has already been closed.
static srpl_state_t
srpl_disconnect_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Any ongoing state needs to be discarded.
    srpl_connection_reset(srpl_connection);

    // Disconnect the srpl_connection_t
    if (srpl_connection->connection == NULL) {
        return srpl_state_idle;
    }
    ioloop_comm_cancel(srpl_connection->connection);
    return srpl_state_disconnect_wait;
}

// We enter disconnect_wait when we are waiting for a disconnect event after cancelling a connection.
// There is no action for this event. The only event we are interested in is the disconnect event.
static srpl_state_t
srpl_disconnect_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    STATE_ANNOUNCE(srpl_connection, event);
    if (event == NULL) {
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_disconnected) {
        return srpl_state_idle;
    } else {
        UNEXPECTED_EVENT_NO_ERROR(srpl_connection, event);
    }
    return srpl_state_invalid;
}

// We enter the connecting state when we've attempted a connection to some address.
// This state has no action. If a connected event is received, we move to the connected state.
// If a disconnected event is received, we move to the next_address_get state.
static srpl_state_t
srpl_connecting_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    STATE_ANNOUNCE(srpl_connection, event);
    if (event == NULL) {
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_disconnected) {
        return srpl_state_idle;
    } else if (event->event_type == srpl_event_connected) {
        return srpl_state_server_id_send;
    } else {
        UNEXPECTED_EVENT_NO_ERROR(srpl_connection, event);
    }
    return srpl_state_invalid;
}

// This state sends a server id and then goes to server_id_response_wait, unless the send failed, in which
// case it goes to the disconnect state.
static srpl_state_t
srpl_server_id_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Send a server id message
    // Now we say hello.
    if (!srpl_session_message_send(srpl_connection, false)) {
        return srpl_state_disconnect;
    }
    return srpl_state_server_id_response_wait;
}

// This state waits for a session response with the remote server ID.
// When the response arrives, it goes to the send_candidates_send state.
static srpl_state_t
srpl_server_id_response_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    STATE_ANNOUNCE(srpl_connection, event);
    if (event == NULL) {
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_session_response_received) {
        srpl_connection->remote_server_id = event->content.server_id;
        return srpl_state_send_candidates_send;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
    return srpl_state_invalid;
}

// When evaluating the incoming ID, we've decided to continue (called by srpl_evaluate_incoming_id_action).
static srpl_state_t
srpl_evaluate_incoming_continue(srpl_connection_t *srpl_connection)
{
    INFO(PRI_S_SRP ": our server id %" PRIx64 " < remote server id %" PRIx64,
         srpl_connection->name, server_id, srpl_connection->remote_server_id);
    if (srpl_connection->is_server) {
        return srpl_state_session_response_send;
    } else {
        return srpl_state_send_candidates_send;
    }
}

// When evaluating the incoming ID, we've decided to disconnect (called by srpl_evaluate_incoming_id_action).
static srpl_state_t
srpl_evaluate_incoming_disconnect(srpl_connection_t *srpl_connection, bool bad)
{
    INFO(PRI_S_SRP ": our server id %" PRIx64 " > remote server id %" PRIx64,
         srpl_connection->name, server_id, srpl_connection->remote_server_id);
    if (srpl_connection->instance->is_me) {
        return srpl_evaluate_incoming_continue(srpl_connection);
    } else {
        if (bad) {
            // bad is set if the server send back the same ID we sent, which means it's misbehaving.
            return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
        }
        return srpl_state_disconnect;
    }
}

// This state's action is to evaluate the server ID that we received. If ours is greater than theirs,
// a server connection generated a new ID; a client connection disconnects.
static srpl_state_t
srpl_server_id_evaluate_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Compare the server id we received to our own
    // Return one of "outgoing id equal", "outgoing id less" or "outgoing id more"
    if (server_id > srpl_connection->remote_server_id) {
        return srpl_evaluate_incoming_disconnect(srpl_connection, false);
    } else if (server_id < srpl_connection->remote_server_id) {
        return srpl_evaluate_incoming_continue(srpl_connection);
    } else {
        INFO(PRI_S_SRP ": our server id %" PRIx64 " == remote server id %" PRIx64,
             srpl_connection->name, server_id, srpl_connection->remote_server_id);
        if (srpl_connection->is_server) {
            return srpl_state_server_id_regenerate;
        } else {
            return srpl_evaluate_incoming_disconnect(srpl_connection, true);
        }
    }
}

// This state's action is to regenerate the server ID, and then go back to evaluate_incoming_id.
static srpl_state_t
srpl_server_id_regenerate_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Generate a new server id
    server_id = srp_random64();
    INFO(PRI_S_SRP ": new server id %" PRIx64, srpl_connection->name, server_id);

    // Re-advertise the domain with the new server ID.
    srpl_domain_advertise();

    // return the server id in a "new server id" event.
    return srpl_state_server_id_evaluate;
}

// This state's action is to send the "send candidates" message, and then go to the send_candidates_wait state.
static srpl_state_t
srpl_send_candidates_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Send "send candidates" message
    // Return no event
    srpl_send_candidates_message_send(srpl_connection, false);
    return srpl_state_send_candidates_wait;
}

// Used by srpl_send_candidates_wait_action and srpl_host_wait_action
static srpl_state_t
srpl_send_candidates_wait_event_process(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    if (event->event_type == srpl_event_send_candidates_response_received) {
        if (srpl_connection->is_server) {
            srpl_connection->database_synchronized = true;
            return srpl_state_ready;
        } else {
            return srpl_state_send_candidates_message_wait;
        }
    } else if (event->event_type == srpl_event_candidate_received) {
        srpl_connection_candidate_set(srpl_connection, event->content.candidate);
        event->content.candidate = NULL; // steal!
        return srpl_state_candidate_check;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// We reach this state after having sent a "send candidates" message, so we can in principle get either a
// "candidate" message or a "send candidates" response here, leading either to send_candidates check or one
// of two states depending on whether this connection is an incoming or outgoing connection. Outgoing
// connections send the "send candidates" message first, so when they get a "send candidates" reply, they
// need to wait for a "send candidates" message from the remote. Incoming connections send the "send candidates"
// message last, so when they get the "send candidates" reply, the database sync is done and it's time to
// just deal with ongoing updates. In this case we go to the check_for_srp_client_updates state, which
// looks to see if any updates came in from SRP clients while we were syncing the databases.
static srpl_state_t
srpl_send_candidates_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    }
    return srpl_send_candidates_wait_event_process(srpl_connection, event);
}

static srpl_candidate_disposition_t
srpl_candidate_host_check(srpl_connection_t *srpl_connection, adv_host_t *host)
{
    // Evaluate candidate
    // Return "host candidate wanted" or "host candidate not wanted" event
    if (host == NULL) {
        return srpl_candidate_yes;
    } else {
        if (host->removed) {
            return srpl_candidate_yes;
        } else if (host->key_id != srpl_connection->candidate->key_id) {
            return srpl_candidate_conflict;
        } else {
            // We allow for a bit of jitter. Bear in mind that candidates only happen on startup, so
            // even if a previous run of the SRP server on this device was responsible for registering
            // the candidate, we don't have it, so we still need it.
            if (host->update_time - srpl_connection->candidate->update_time > SRPL_UPDATE_JITTER_WINDOW) {
                return srpl_candidate_no;
            } else {
                return srpl_candidate_yes;
            }
        }
    }
}

// We enter this state after we've received a "candidate" message, and check to see if we want the host the candidate
// represents. We then send an appropriate response.
static srpl_state_t
srpl_candidate_check_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS_NAME(srpl_connection, srpl_connection->candidate->name);

    adv_host_t *host = srp_adv_host_copy(srpl_connection->candidate->name);
    srpl_candidate_disposition_t disposition = srpl_candidate_host_check(srpl_connection, host);
    if (host != NULL) {
        srp_adv_host_release(host);
    }
    switch(disposition) {
    case srpl_candidate_yes:
        srpl_candidate_response_send(srpl_connection, kDSOType_SRPLCandidateYes);
        return srpl_state_candidate_host_wait;
    case srpl_candidate_no:
        srpl_candidate_response_send(srpl_connection, kDSOType_SRPLCandidateNo);
        return srpl_state_send_candidates_wait;
    case srpl_candidate_conflict:
        srpl_candidate_response_send(srpl_connection, kDSOType_SRPLConflict);
        return srpl_state_send_candidates_wait;
    }
    return srpl_state_invalid;
}

// In candidate_host_send_wait, we take no action and wait for events. We're hoping for a "host" message, leading to
// candidate_host_prepare. We could also receive a "candidate" message, leading to candidate_received, or a "send
// candidates" reply, leading to candidate_reply_received.

static srpl_state_t
srpl_candidate_host_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_host_message_received) {
        // Copy the update information, retain what's refcounted, and free what's not on the event.
        srpl_host_update_steal_parts(&srpl_connection->stashed_host, &event->content.host_update);
        return srpl_state_candidate_host_prepare;
    } else {
        return srpl_send_candidates_wait_event_process(srpl_connection, event);
    }
}

// Here we want to see if we can do an immediate update; if so, we go to candidate_host_re_evaluate; otherwise
// we go to candidate_host_contention_wait
static srpl_state_t
srpl_candidate_host_prepare_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS_NAME(srpl_connection, srpl_connection->candidate->name);

    // Apply the host from the event to the current host list
    // Return no event
    adv_host_t *host = srp_adv_host_copy(srpl_connection->candidate->name);
    if (host == NULL) {
        // If we don't have this host, we can apply the update immediately.
        return srpl_state_candidate_host_apply;
    }
    if (host->srpl_connection != NULL || host->updates != NULL) {
        // We are processing an update from a different srpl server.
        INFO(PRI_S_SRP ": host->srpl_connection = %p  host->updates=%p--going into contention",
             srpl_connection->name, host->srpl_connection, host->updates);
        srp_adv_host_release(host);
        return srpl_state_candidate_host_contention_wait;
    } else {
        srpl_connection->candidate->host = host;
        return srpl_state_candidate_host_re_evaluate;
    }
}

static adv_host_t *
srpl_client_update_matches(dns_name_t *hostname, srpl_event_t *event)
{
    adv_host_t *host = event->content.client_result.host;
    if (event->content.client_result.rcode == dns_rcode_noerror && dns_names_equal_text(hostname, host->name)) {
        INFO("returning host " PRI_S_SRP, host->name);
        return host;
    }
    char name[kDNSServiceMaxDomainName];
    dns_name_print(hostname, name, sizeof(name));
    INFO("returning NULL: rcode = " PUB_S_SRP "  hostname = " PRI_S_SRP "  host->name = " PRI_S_SRP,
         dns_rcode_name(event->content.client_result.rcode), name, host->name);
    return NULL;
}

// and wait for a srp_client_update_finished event for the host, which
// will trigger us to move to candidate_host_re_evaluate.
static srpl_state_t
srpl_candidate_host_contention_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_srp_client_update_finished) {
        adv_host_t *host = srpl_client_update_matches(srpl_connection->candidate->name, event);
        if (host != NULL) {
            srpl_connection->candidate->host = host;
            srp_adv_host_retain(srpl_connection->candidate->host);
            return srpl_state_candidate_host_re_evaluate;
        }
        return srpl_state_invalid; // Keep waiting
    } else if (event->event_type == srpl_event_advertise_finished) {
        // See if this is an event on the host we were waiting for.
        if (event->content.advertise_finished.hostname != NULL &&
            dns_names_equal_text(srpl_connection->candidate->name, event->content.advertise_finished.hostname))
        {
            return srpl_state_candidate_host_re_evaluate;
        }
        return srpl_state_invalid;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// At this point we've either waited for the host to no longer be in contention, or else it wasn't in contention.
// There was a time gap between when we sent the candidate response and when the host message arrived, so an update
// may have arrived locally for that SRP client. We therefore re-evaluate at this point.
static srpl_state_t
srpl_candidate_host_re_evaluate_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS_NAME(srpl_connection, srpl_connection->candidate->name);

    adv_host_t *host = srpl_connection->candidate->host;
    // The host we retained may have become invalid; if so, discard it
    if (host != NULL && !srp_adv_host_valid(host)) {
        srp_adv_host_release(srpl_connection->candidate->host);
        srpl_connection->candidate->host = host = NULL;
    }
    // If it was invalidated, or if we got here directly, look up the host by name
    if (host == NULL) {
        host = srp_adv_host_copy(srpl_connection->candidate->name);
        srpl_connection->candidate->host = host;
    }
    // It's possible that the host is gone; in this case we definitely want the update.
    if (host == NULL) {
        return srpl_state_candidate_host_apply;
    }

    // At this point we know that the host we were looking for is valid. Now check to see if we still want to apply it.
    srpl_state_t ret = srpl_state_invalid;
    srpl_candidate_disposition_t disposition = srpl_candidate_host_check(srpl_connection, host);
    switch(disposition) {
    case srpl_candidate_yes:
        ret = srpl_state_candidate_host_apply;
        break;
    case srpl_candidate_no:
        // This happens if we got a candidate and wanted it, but then got an SRP update on that candidate while waiting
        // for events. In this case, there's no real problem, and the successful update should trigger an update to be
        // sent to the remote.
        srpl_host_response_send(srpl_connection, dns_rcode_noerror);
        ret = srpl_state_send_candidates_wait;
        break;
    case srpl_candidate_conflict:
        srpl_host_response_send(srpl_connection, dns_rcode_yxdomain);
        ret = srpl_state_send_candidates_wait;
        break;
    }
    return ret;
}

static bool
srpl_connection_host_apply(srpl_connection_t *srpl_connection)
{
    if (!srp_dns_evaluate(NULL, srpl_connection, srpl_connection->stashed_host.message)) {
        srpl_host_response_send(srpl_connection, dns_rcode_formerr);
        return false;
    }
    return true;
}

// At this point we know there is no contention on the host, and we want to update it, so start the update by passing the
// host message to dns_evaluate.
static srpl_state_t
srpl_candidate_host_apply_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    // Apply the host from the event to the current host list
    // Return no event
    // Note that we set host->srpl_connection _after_ we call dns_evaluate. This ensures that any "advertise_finished"
    // calls that are done during the call to dns_evaluate do not deliver an event here.
    if (event == NULL) {
        if (!srpl_connection_host_apply(srpl_connection)) {
            return srpl_state_send_candidates_wait;
        }
        return srpl_state_candidate_host_apply_wait;
    } else if (event->event_type == srpl_event_advertise_finished) {
        // This shouldn't be possible anymore, but I'm putting a FAULT in here in case I'm mistaken.
        FAULT(PRI_S_SRP ": advertise_finished event!", srpl_connection->name);
        return srpl_state_invalid;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// Called by the SRP server when an advertise has finished for an update recevied on a connection.
static void
srpl_deferred_advertise_finished_event_deliver(void *context)
{
    srpl_event_t *event = context;

    for (srpl_domain_t *domain = srpl_domains; domain != NULL; domain = domain->next) {
        for (srpl_instance_t *instance = domain->instances; instance != NULL; instance = instance->next) {
            if (instance->outgoing != NULL) {
                srpl_event_deliver(instance->outgoing, event);
            }
            if (instance->incoming != NULL) {
                srpl_event_deliver(instance->incoming, event);
            }
        }
    }

    free(event->content.advertise_finished.hostname);
    free(event);
}

// Send an advertise_finished event for the specified hostname to all connections. Because this is called from
// advertise_finished, we do not want any state machine to advance immediately, so we defer delivery of this
// event until the next time we return to the main event loop.
void
srpl_advertise_finished_event_send(char *hostname, int rcode)
{
    srpl_event_t *event = calloc(1, sizeof(*event));
    if (event == NULL) {
        ERROR("No memory to defer advertise_finished event for " PUB_S_SRP, hostname);
        return;
    }

    srpl_event_initialize(event, srpl_event_advertise_finished);
    event->content.advertise_finished.rcode = rcode;
    event->content.advertise_finished.hostname = strdup(hostname);
    if (event->content.advertise_finished.hostname == NULL) {
        INFO(PRI_S_SRP ": no memory for hostname", hostname);
        free(event);
        return;
    }
    ioloop_run_async(srpl_deferred_advertise_finished_event_deliver, event);
}


// We enter this state to wait for the application of a host update to complete.
// We exit the state for the send_candidates_wait state when we receive an advertise_finished event.
// Additionally when we receive an advertise_finished event we send a "host" response with the rcode
// returned in the advertise_finished event.
static srpl_state_t
srpl_candidate_host_apply_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_advertise_finished) {
        srpl_host_response_send(srpl_connection, event->content.advertise_finished.rcode);
        srpl_host_update_parts_free(&srpl_connection->stashed_host);
        return srpl_state_send_candidates_wait;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// This marks the end of states that occur as a result of sending a "send candidates" message.
// This marks the beginning of states that occur as a result of receiving a send_candidates message.

// We have received a "send candidates" message; the action is to create a candidates list.
static srpl_state_t
srpl_send_candidates_received_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    int num_candidates;
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Make sure we don't have a candidate list.
    if (srpl_connection->candidates != NULL) {
        srpl_connection_candidates_free(srpl_connection);
        srpl_connection->candidates = NULL;
        // Just in case we exit due to a failure...
        srpl_connection->num_candidates = 0;
        srpl_connection->current_candidate = -1;
    }
    // Generate a list of candidates from the current host list.
    // Return no event
    num_candidates = srp_current_valid_host_count();
    if (num_candidates > 0) {
        adv_host_t **candidates = calloc(num_candidates, sizeof(*candidates));
        int copied_candidates;
        if (candidates == NULL) {
            ERROR("unable to allocate candidates list.");
            return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
        }
        copied_candidates = srp_hosts_to_array(candidates, num_candidates);
        if (copied_candidates > num_candidates) {
            FAULT("copied_candidates %d > num_candidates %d",
                  copied_candidates, num_candidates);
            return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
        }
        if (num_candidates != copied_candidates) {
            INFO("srp_hosts_to_array returned the wrong number of hosts: copied_candidates %d > num_candidates %d",
                 copied_candidates, num_candidates);
            num_candidates = copied_candidates;
        }
        srpl_connection->candidates = candidates;
        srpl_connection->candidates_not_generated = false;
    }
    srpl_connection->num_candidates = num_candidates;
    srpl_connection->current_candidate = -1;
    return srpl_state_send_candidates_remaining_check;
}

// See if there are candidates remaining; if not, send "send candidates" response.
static srpl_state_t
srpl_candidates_remaining_check_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // Get the next candidate out of the candidate list
    // Return "no candidates left" or "next candidate"
    if (srpl_connection->current_candidate + 1 < srpl_connection->num_candidates) {
        srpl_connection->current_candidate++;
        return srpl_state_next_candidate_send;
    } else {
        return srpl_state_send_candidates_response_send;
    }
}

// Send the next candidate.
static srpl_state_t
srpl_next_candidate_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    srpl_candidate_message_send(srpl_connection, srpl_connection->candidates[srpl_connection->current_candidate]);
    return srpl_state_next_candidate_send_wait;
}

// Wait for a "candidate" response.
static srpl_state_t
srpl_next_candidate_send_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_candidate_response_received) {
        switch (event->content.disposition) {
        case srpl_candidate_yes:
            return srpl_state_candidate_host_send;
        case srpl_candidate_no:
        case srpl_candidate_conflict:
            return srpl_state_send_candidates_remaining_check;
        }
        return srpl_state_invalid;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// Send the host for the candidate.
static srpl_state_t
srpl_candidate_host_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    // It's possible that the host that we put on the candidates list has become invalid. If so, just go back and send
    // the next candidate (or finish).
    adv_host_t *host = srpl_connection->candidates[srpl_connection->current_candidate];
    if (!srp_adv_host_valid(host) || host->message == NULL) {
        return srpl_state_send_candidates_remaining_check;
    }
    srpl_host_message_send(srpl_connection, host);
    return srpl_state_candidate_host_response_wait;
}

// Wait for a "host" response.
static srpl_state_t
srpl_candidate_host_response_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_host_response_received) {
        // The only failure case we care about is a conflict, and we don't have a way to handle that, so just
        // continue without checking the status.
        return srpl_state_send_candidates_remaining_check;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// At this point we're done sending candidates, so we send a "send candidates" response.
static srpl_state_t
srpl_send_candidates_response_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    srpl_send_candidates_message_send(srpl_connection, true);
    // When the server has sent its candidate response, it's immediately ready to send a "send candidate" message
    // When the client has sent its candidate response, the database synchronization is done on the client.
    if (srpl_connection->is_server) {
        return srpl_state_send_candidates_send;
    } else {
        srpl_connection->database_synchronized = true;
        return srpl_state_ready;
    }
}

// The ready state is where we land when there's no remaining work to do. We wait for events, and when we get one,
// we handle it, ultimately returning to this state.
static srpl_state_t
srpl_ready_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        // Whenever we newly land in this state, see if there is an unsent client update at the head of the
        // queue, and if so, send it.
        if (srpl_connection->client_update_queue != NULL && !srpl_connection->client_update_queue->sent) {
            adv_host_t *host = srpl_connection->client_update_queue->host;
            if (host == NULL || host->name == NULL) {
                INFO(PRI_S_SRP ": we have an update to send for bogus host %p.", srpl_connection->name, host);
            } else {
                INFO(PRI_S_SRP ": we have an update to send for host " PRI_S_SRP, srpl_connection->name,
                     srpl_connection->client_update_queue->host->name);
            }
            return srpl_state_srp_client_update_send;
        } else {
            if (srpl_connection->client_update_queue != NULL) {
                adv_host_t *host = srpl_connection->client_update_queue->host;
                if (host == NULL || host->name == NULL) {
                    INFO(PRI_S_SRP ": there is anupdate that's marked sent for bogus host %p.",
                         srpl_connection->name, host);
                } else {
                    INFO(PRI_S_SRP ": there is an update on the queue that's marked sent for host " PRI_S_SRP,
                         srpl_connection->name, host->name);
                }
            } else {
                INFO(PRI_S_SRP ": the client update queue is empty.", srpl_connection->name);
            }
        }
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_host_message_received) {
        if (srpl_connection->stashed_host.message != NULL) {
            FAULT(PRI_S_SRP ": stashed host present but host message received", srpl_connection->name);
            return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
        }
        // Copy the update information, retain what's refcounted, and NULL out what's not, on the event.
        srpl_host_update_steal_parts(&srpl_connection->stashed_host, &event->content.host_update);
        return srpl_state_stashed_host_check;
    } else if (event->event_type == srpl_event_host_response_received) {
        return srpl_state_srp_client_ack_evaluate;
    } else if (event->event_type == srpl_event_advertise_finished) {
        if (srpl_connection->stashed_host.hostname != NULL &&
            event->content.advertise_finished.hostname != NULL &&
            dns_names_equal_text(srpl_connection->stashed_host.hostname, event->content.advertise_finished.hostname))
        {
            srpl_connection->stashed_host.rcode = event->content.advertise_finished.rcode;
            return srpl_state_stashed_host_finished;
        }
        return srpl_state_invalid;
    } else if (event->event_type == srpl_event_srp_client_update_finished) {
        // When we receive a client update in ready state, we just need to re-run the state's action.
        return srpl_state_ready;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// We get here when there is at least one client update queued up to send
static srpl_state_t
srpl_srp_client_update_send_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    srpl_srp_client_queue_entry_t *update = srpl_connection->client_update_queue;
    if (update != NULL) {
        // If the host has a message, send it. Note that this host may well be removed, but if it had been removed
        // through a lease expiry we wouldn't have got here, because the host object would have been removed from
        // the list. So if it has a message attached to it, that means that either it's been removed explicitly by
        // the client, which we need to propagate, or else it is still valid, and so we need to propagate the most
        // recent update we got.
        if (update->host->message != NULL) {
            srpl_host_message_send(srpl_connection, update->host);
            update->sent = true;
        } else {
            ERROR(PRI_S_SRP ": no host message to send for host " PRI_S_SRP ".",
                  srpl_connection->name, update->host->name);

            // We're not going to send this update, so take it off the queue.
            srpl_connection->client_update_queue = update->next;
            srp_adv_host_release(update->host);
            free(update);
        }
    }
    return srpl_state_ready;
}

// We go here when we get a "host" response; all we do is remove the host from the top of the queue.
static srpl_state_t
srpl_srp_client_ack_evaluate_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    if (srpl_connection->client_update_queue == NULL) {
        FAULT(PRI_S_SRP ": update queue empty in ready, but host_response_received event received.",
              srpl_connection->name);
        return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
    }
    if (!srpl_connection->client_update_queue->sent) {
        FAULT(PRI_S_SRP ": top of update queue not sent, but host_response_received event received.",
              srpl_connection->name);
        return srpl_connection_drop_state(srpl_connection->instance, srpl_connection);
    }
    srpl_srp_client_queue_entry_t *finished_update = srpl_connection->client_update_queue;
    srpl_connection->client_update_queue = finished_update->next;
    if (finished_update->host != NULL) {
        srp_adv_host_release(finished_update->host);
    }
    free(finished_update);
    return srpl_state_ready;
}

// We go here when we get a "host" message
static srpl_state_t
srpl_stashed_host_check_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS_NAME(srpl_connection, srpl_connection->stashed_host.hostname);

    adv_host_t *host = srp_adv_host_copy(srpl_connection->stashed_host.hostname);
    // No contention...
    if (host == NULL) {
        INFO("applying host because it doesn't exist locally.");
        return srpl_state_stashed_host_apply;
    } else if (host->updates == NULL && host->srpl_connection == NULL && host->clients == NULL) {
        INFO("applying host because there's no contention.");
        srp_adv_host_release(host);
        return srpl_state_stashed_host_apply;
    } else {
        INFO("not applying host because there is contention. host->updates %p   host->srpl_connection: %p  host->clients: %p",
             host->updates, host->srpl_connection, host->clients);
    }
    srp_adv_host_release(host);
    return srpl_state_ready; // Wait for something to happen
}

// We go here when we have a stashed host to apply.
static srpl_state_t
srpl_stashed_host_apply_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        if (!srpl_connection_host_apply(srpl_connection)) {
            srpl_connection->stashed_host.rcode = dns_rcode_servfail;
            return srpl_state_stashed_host_finished;
        }
        return srpl_state_ready; // Wait for something to happen
    } else if (event->event_type == srpl_event_advertise_finished) {
        // This shouldn't be possible anymore, but I'm putting a FAULT in here in case I'm mistaken.
        FAULT(PRI_S_SRP ": advertise_finished event!", srpl_connection->name);
        return srpl_state_invalid;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// We go here when a host update advertise finishes.
static srpl_state_t
srpl_stashed_host_finished_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    if (srpl_connection->stashed_host.hostname == NULL) {
        FAULT(PRI_S_SRP ": stashed host not present, but advertise_finished event received.", srpl_connection->name);
        return srpl_state_ready;
    }
    srpl_host_response_send(srpl_connection, srpl_connection->stashed_host.rcode);
    srpl_host_update_parts_free(&srpl_connection->stashed_host);
    return srpl_state_ready;
}

// We land here immediately after a server connection is received.
static srpl_state_t
srpl_session_message_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_session_message_received) {
        srpl_connection->remote_server_id = event->content.server_id;
        return srpl_state_server_id_evaluate;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// Send a server id response
static srpl_state_t
srpl_session_response_send(srpl_connection_t *UNUSED srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_EVENT_NULL(srpl_connection, event);
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE_NO_EVENTS(srpl_connection);

    if (!srpl_session_message_send(srpl_connection, true)) {
        return srpl_state_disconnect;
    }
    return srpl_state_send_candidates_message_wait;
}

// We land here immediately after a server connection is received.
static srpl_state_t
srpl_send_candidates_message_wait_action(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    REQUIRE_SRPL_INSTANCE(srpl_connection);
    STATE_ANNOUNCE(srpl_connection, event);

    if (event == NULL) {
        return srpl_state_invalid; // Wait for events.
    } else if (event->event_type == srpl_event_send_candidates_message_received) {
        return srpl_state_send_candidates_received;
    } else {
        UNEXPECTED_EVENT(srpl_connection, event);
    }
}

// Check to see if host is on the list of remaining candidates to send. If so, no need to do anything--it'll go out soon.
static bool
srpl_reschedule_candidate(srpl_connection_t *srpl_connection, adv_host_t *host)
{
    // We don't need to queue new updates if we haven't yet generated a candidates list.
    if (srpl_connection->candidates_not_generated) {
        INFO("returning true because we haven't generated candidates.");
        return true;
    }
    if (srpl_connection->candidates == NULL) {
        INFO("returning false because we have no candidates.");
        return false;
    }
    for (int i = srpl_connection->current_candidate + 1; i < srpl_connection->num_candidates; i++) {
        if (srpl_connection->candidates[i] == host) {
            INFO("returning true because the host is on the candidate list.");
            return true;
        }
    }
    INFO("returning false because the host is not on the candidate list.");
    return false;
}

static void
srpl_queue_srp_client_update(srpl_connection_t *srpl_connection, adv_host_t *host)
{
    srpl_srp_client_queue_entry_t *new_entry, **qp;
    // Find the end of the queue
    for (qp = &srpl_connection->client_update_queue; *qp; qp = &(*qp)->next) {
        srpl_srp_client_queue_entry_t *entry = *qp;
        // No need to re-queue if we're already on the queue
        if (!entry->sent && entry->host == host) {
            INFO("host " PRI_S_SRP " is already on the update queue for connection " PRI_S_SRP,
                 host->name, srpl_connection->name);
            return;
        }
    }
    new_entry = calloc(1, sizeof(*new_entry));
    if (new_entry == NULL) {
        ERROR(PRI_S_SRP ": no memory to queue SRP client update.", srpl_connection->name);
        return;
    }
    INFO("adding host " PRI_S_SRP " to the update queue for connection " PRI_S_SRP, host->name, srpl_connection->name);
    new_entry->host = host;
    srp_adv_host_retain(new_entry->host);
    *qp = new_entry;
}

// Client update events are interesting in two cases. First, we might have received a host update for a
// host that was in contention when the update was received; in this case, we want to now apply the update,
// assuming that the contention is no longer present (it's possible that there are multiple sources of
// contention).
//
// The second case is where a client update succeeded; in this case we want to send that update to all of
// the remotes.
//
// We do not receive this event when an update that was triggered by an SRP Replication update; in that
// case we get an "apply finished" event instead of a "client update finished" event.
static void
srpl_srp_client_update_send_event_to_connection(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    if (event->content.client_result.rcode == dns_rcode_noerror) {
        adv_host_t *host = event->content.client_result.host;
        if (!srpl_reschedule_candidate(srpl_connection, host)) {
            srpl_queue_srp_client_update(srpl_connection, host);
        }
    }
    srpl_event_deliver(srpl_connection, event);
}

static void
srpl_deferred_srp_client_update_finished_event_deliver(void *context)
{
    srpl_event_t *event = context;
    for (srpl_domain_t *domain = srpl_domains; domain != NULL; domain = domain->next) {
        for (srpl_instance_t *instance = domain->instances; instance != NULL; instance = instance->next) {
            if (instance->outgoing != NULL) {
                srpl_srp_client_update_send_event_to_connection(instance->outgoing, event);
            }
            if (instance->incoming != NULL) {
                srpl_srp_client_update_send_event_to_connection(instance->incoming, event);
            }
        }
    }
    srp_adv_host_release(event->content.client_result.host);
    free(event);
}

// When an SRP client update finished, we need to deliver an event to all connections indicating that this has
// occurred. This event must be delivered from the main run loop, to avoid starting an update before advertise_finish
// has completed its work.
void
srpl_srp_client_update_finished_event_send(adv_host_t *host, int rcode)
{
    srpl_event_t *event;
    event = malloc(sizeof(*event));
    if (event == NULL) {
        FAULT(PRI_S_SRP ": unable to allocate memory to defer event", host->name);
        return;
    }
    srpl_event_initialize(event, srpl_event_srp_client_update_finished);
    srpl_event_content_type_set(event, srpl_event_content_type_client_result);
    event->content.client_result.host = host;
    srp_adv_host_retain(event->content.client_result.host);
    event->content.client_result.rcode = rcode;
    ioloop_run_async(srpl_deferred_srp_client_update_finished_event_deliver, event);
}

typedef struct {
    srpl_state_t state;
    char *name;
    srpl_action_t action;
} srpl_connection_state_t;

#define STATE_NAME_DECL(name) srpl_state_##name, #name
static srpl_connection_state_t srpl_connection_states[] = {
    { STATE_NAME_DECL(invalid),                              NULL },
    { STATE_NAME_DECL(disconnected),                         srpl_disconnected_action },
    { STATE_NAME_DECL(next_address_get),                     srpl_next_address_get_action },
    { STATE_NAME_DECL(connect),                              srpl_connect_action },
    { STATE_NAME_DECL(idle),                                 srpl_idle_action },
    { STATE_NAME_DECL(reconnect_wait),                       srpl_reconnect_wait_action },
    { STATE_NAME_DECL(retry_delay_send),                     srpl_retry_delay_send_action },
    { STATE_NAME_DECL(disconnect),                           srpl_disconnect_action },
    { STATE_NAME_DECL(disconnect_wait),                      srpl_disconnect_wait_action },
    { STATE_NAME_DECL(connecting),                           srpl_connecting_action },
    { STATE_NAME_DECL(server_id_send),                       srpl_server_id_send_action },
    { STATE_NAME_DECL(server_id_response_wait),              srpl_server_id_response_wait_action },
    { STATE_NAME_DECL(server_id_evaluate),                   srpl_server_id_evaluate_action },
    { STATE_NAME_DECL(server_id_regenerate),                 srpl_server_id_regenerate_action },

    // Here we are the endpoint that has send the "send candidates message" and we are cycling through the candidates
    // we receive until we get a "send candidates" reply.

    { STATE_NAME_DECL(send_candidates_send),                 srpl_send_candidates_send_action },
    { STATE_NAME_DECL(send_candidates_wait),                 srpl_send_candidates_wait_action },

    // Got a "candidate" message, need to check it and send the right reply.
    { STATE_NAME_DECL(candidate_check),                      srpl_candidate_check_action },

    // At this point we've send a candidate reply, so we're waiting for a host message. It's possible that the host
    // went away in the interim, in which case we will get a "candidate" message or a "send candidate" reply.

    { STATE_NAME_DECL(candidate_host_wait),                  srpl_candidate_host_wait_action },
    { STATE_NAME_DECL(candidate_host_prepare),               srpl_candidate_host_prepare_action },
    { STATE_NAME_DECL(candidate_host_contention_wait),       srpl_candidate_host_contention_wait_action },
    { STATE_NAME_DECL(candidate_host_re_evaluate),           srpl_candidate_host_re_evaluate_action },

    // Here we've gotten the host message (the SRP message), and need to apply it and send a response
    { STATE_NAME_DECL(candidate_host_apply),                 srpl_candidate_host_apply_action },
    { STATE_NAME_DECL(candidate_host_apply_wait),            srpl_candidate_host_apply_wait_action },

    // We've received a "send candidates" message. Make a list of candidates to send, and then start sending them.
    { STATE_NAME_DECL(send_candidates_received),             srpl_send_candidates_received_action },
    // See if there are any candidates left to send; if not, go to send_candidates_response_send
    { STATE_NAME_DECL(send_candidates_remaining_check),      srpl_candidates_remaining_check_action },
    // Send a "candidate" message for the next candidate
    { STATE_NAME_DECL(next_candidate_send),                  srpl_next_candidate_send_action },
    // Wait for a response to the "candidate" message
    { STATE_NAME_DECL(next_candidate_send_wait),             srpl_next_candidate_send_wait_action },
    // The candidate requested, so send its host info
    { STATE_NAME_DECL(candidate_host_send),                  srpl_candidate_host_send_action },
    // We're waiting for the remote to acknowledge the host update
    { STATE_NAME_DECL(candidate_host_response_wait),         srpl_candidate_host_response_wait_action },

    // When we've run out of candidates to send, we send the candidates response.
    { STATE_NAME_DECL(send_candidates_response_send),        srpl_send_candidates_response_send_action },

    // This is the quiescent state for servers and clients after session establishment database sync.
    // Waiting for updates received locally, or updates sent by remote
    { STATE_NAME_DECL(ready),                                srpl_ready_action },
    // An update was received locally
    { STATE_NAME_DECL(srp_client_update_send),               srpl_srp_client_update_send_action },
    // We've gotten an ack
    { STATE_NAME_DECL(srp_client_ack_evaluate),              srpl_srp_client_ack_evaluate_action },
    // See if we have an update from the remote that we stashed because it arrived while we were sending one
    { STATE_NAME_DECL(stashed_host_check),                   srpl_stashed_host_check_action },
    // Apply a stashed update (which may have been stashed in the ready state or the client_update_ack_wait state
    { STATE_NAME_DECL(stashed_host_apply),                   srpl_stashed_host_apply_action },
    // A stashed update finished; check the results
    { STATE_NAME_DECL(stashed_host_finished),                srpl_stashed_host_finished_action },

    // Initial startup state for server
    { STATE_NAME_DECL(session_message_wait),                 srpl_session_message_wait_action },
    // Send a response once we've figured out that we're going to continue
    { STATE_NAME_DECL(session_response_send),                srpl_session_response_send },
    // Wait for a "send candidates" message.
    { STATE_NAME_DECL(send_candidates_message_wait),         srpl_send_candidates_message_wait_action },
};
#define SRPL_NUM_CONNECTION_STATES (sizeof(srpl_connection_states) / sizeof(srpl_connection_state_t))

static srpl_connection_state_t *
srpl_state_get(srpl_state_t state)
{
    static bool once = false;
    if (!once) {
        for (unsigned i = 0; i < SRPL_NUM_CONNECTION_STATES; i++) {
            if (srpl_connection_states[i].state != (srpl_state_t)i) {
                ERROR("srpl connection state %d doesn't match " PUB_S_SRP, i, srpl_connection_states[i].name);
                STATE_DEBUGGING_ABORT();
                return NULL;
            }
        }
        once = true;
    }
    if (state < 0 || state > SRPL_NUM_CONNECTION_STATES) {
        STATE_DEBUGGING_ABORT();
        return NULL;
    }
    return &srpl_connection_states[state];
}

static void
srpl_connection_next_state(srpl_connection_t *srpl_connection, srpl_state_t state)
{
    srpl_state_t next_state = state;

    do {
        srpl_connection_state_t *new_state = srpl_state_get(next_state);

        if (new_state == NULL) {
            ERROR(PRI_S_SRP " next state is invalid: %d", srpl_connection->name, next_state);
            STATE_DEBUGGING_ABORT();
            return;
        }
        srpl_connection->state = next_state;
        srpl_connection->state_name = new_state->name;
        srpl_action_t action = new_state->action;
        if (action != NULL) {
            next_state = action(srpl_connection, NULL);
        }
    } while (next_state != srpl_state_invalid);
}

//
// Event functions
//

typedef struct {
    srpl_event_type_t event_type;
    char *name;
} srpl_event_configuration_t;

#define EVENT_NAME_DECL(name) { srpl_event_##name, #name }

srpl_event_configuration_t srpl_event_configurations[] = {
    EVENT_NAME_DECL(invalid),
    EVENT_NAME_DECL(address_add),
    EVENT_NAME_DECL(address_remove),
    EVENT_NAME_DECL(server_disconnect),
    EVENT_NAME_DECL(reconnect_timer_expiry),
    EVENT_NAME_DECL(disconnected),
    EVENT_NAME_DECL(connected),
    EVENT_NAME_DECL(session_response_received),
    EVENT_NAME_DECL(send_candidates_response_received),
    EVENT_NAME_DECL(candidate_received),
    EVENT_NAME_DECL(host_message_received),
    EVENT_NAME_DECL(srp_client_update_finished),
    EVENT_NAME_DECL(advertise_finished),
    EVENT_NAME_DECL(candidate_response_received),
    EVENT_NAME_DECL(host_response_received),
    EVENT_NAME_DECL(session_message_received),
    EVENT_NAME_DECL(send_candidates_message_received),
};
#define SRPL_NUM_EVENT_TYPES (sizeof(srpl_event_configurations) / sizeof(srpl_event_configuration_t))

static srpl_event_configuration_t *
srpl_event_configuration_get(srpl_event_type_t event)
{
    static bool once = false;
    if (!once) {
        for (unsigned i = 0; i < SRPL_NUM_EVENT_TYPES; i++) {
            if (srpl_event_configurations[i].event_type != (srpl_event_type_t)i) {
                ERROR("srpl connection event %d doesn't match " PUB_S_SRP, i, srpl_event_configurations[i].name);
                STATE_DEBUGGING_ABORT();
                return NULL;
            }
        }
        once = true;
    }
    if (event < 0 || event > SRPL_NUM_EVENT_TYPES) {
        STATE_DEBUGGING_ABORT();
        return NULL;
    }
    return &srpl_event_configurations[event];
}

static void
srpl_event_initialize(srpl_event_t *event, srpl_event_type_t event_type)
{
    memset(event, 0, sizeof(*event));
    srpl_event_configuration_t *event_config = srpl_event_configuration_get(event_type);
    if (event_config == NULL) {
        ERROR("invalid event type %d", event_type);
        STATE_DEBUGGING_ABORT();
        return;
    }
    event->event_type = event_type;
    event->name = event_config->name;
}

static void
srpl_event_deliver(srpl_connection_t *srpl_connection, srpl_event_t *event)
{
    srpl_connection_state_t *state = srpl_state_get(srpl_connection->state);
    if (state == NULL) {
        ERROR(PRI_S_SRP ": event " PUB_S_SRP " received in invalid state %d",
              srpl_connection->name, event->name, srpl_connection->state);
        STATE_DEBUGGING_ABORT();
        return;
    }
    if (state->action == NULL) {
        FAULT(PRI_S_SRP": event " PUB_S_SRP " received in state " PUB_S_SRP " with NULL action",
              srpl_connection->name, event->name, state->name);
        return;
    }
    srpl_state_t next_state = state->action(srpl_connection, event);
    if (next_state != srpl_state_invalid) {
        srpl_connection_next_state(srpl_connection, next_state);
    }
}

dnssd_txn_t *srpl_advertise_txn;

static void
srpl_register_completion(DNSServiceRef UNUSED sdref, DNSServiceFlags UNUSED flags, DNSServiceErrorType error_code,
                         const char *name, const char *regtype, const char *domain, void *UNUSED context)
{
    if (error_code != kDNSServiceErr_NoError) {
        ERROR("unable to advertise _srpl-tls._tcp service: %d", error_code);

        return;
    }
    INFO("registered SRP Replication instance name " PRI_S_SRP "." PUB_S_SRP "." PRI_S_SRP, name, regtype, domain);
}

static void
srpl_domain_advertise(void)
{
    DNSServiceRef sdref = NULL;
    TXTRecordRef txt_record;
    char server_id_buf[INT64_HEX_STRING_MAX];

    TXTRecordCreate(&txt_record, 0, NULL);

    int err = TXTRecordSetValue(&txt_record, "domain", strlen(current_thread_domain_name), current_thread_domain_name);
    if (err != kDNSServiceErr_NoError) {
        ERROR("unable to set domain in TXT record for _srpl-tls._tcp to " PRI_S_SRP, current_thread_domain_name);
        goto exit;
    }

    snprintf(server_id_buf, sizeof(server_id_buf), "%" PRIx64, server_id);
    err = TXTRecordSetValue(&txt_record, "server-id", strlen(server_id_buf), server_id_buf);
    if (err != kDNSServiceErr_NoError) {
        ERROR("unable to set server-id in TXT record for _srpl-tls._tcp to " PUB_S_SRP, server_id_buf);
        goto exit;
    }

    // If there is already a registration, get rid of it
    if (srpl_advertise_txn != NULL) {
        ioloop_dnssd_txn_cancel(srpl_advertise_txn);
        ioloop_dnssd_txn_release(srpl_advertise_txn);
        srpl_advertise_txn = NULL;
    }

    err = DNSServiceRegister(&sdref, kDNSServiceFlagsUnique,
                             kDNSServiceInterfaceIndexAny, NULL, "_srpl-tls._tcp", NULL,
                             NULL, htons(853), TXTRecordGetLength(&txt_record), TXTRecordGetBytesPtr(&txt_record),
                             srpl_register_completion, NULL);
    if (err != kDNSServiceErr_NoError) {
        ERROR("unable to advertise _srpl-tls._tcp service");
        goto exit;
    }
    srpl_advertise_txn = ioloop_dnssd_txn_add(sdref, NULL, NULL, NULL);
    if (srpl_advertise_txn == NULL) {
        ERROR("unable to set up a dnssd_txn_t for _srpl-tls._tcp advertisement.");
        goto exit;
    }
    sdref = NULL; // srpl_advertise_txn holds the reference.
exit:
    if (sdref != NULL) {
        DNSServiceRefDeallocate(sdref);
    }
    TXTRecordDeallocate(&txt_record);
    return;
}

static void
srpl_thread_network_name_callback(void *UNUSED NULLABLE context, const char *NULLABLE thread_network_name, cti_status_t status)
{
    size_t thread_domain_size;
    char domain_buf[kDNSServiceMaxDomainName];
    char *new_thread_domain_name;

    if (thread_network_name == NULL || status != kCTIStatus_NoError) {
        ERROR("unable to get thread network name.");
        return;
    }
    thread_domain_size = snprintf(domain_buf, sizeof(domain_buf),
                                  "%s.%s", thread_network_name, SRP_THREAD_DOMAIN);
    if (thread_domain_size < 0 || thread_domain_size >= sizeof (domain_buf) ||
        (new_thread_domain_name = strdup(domain_buf)) == NULL)
    {
        ERROR("no memory for new thread network name: " PRI_S_SRP, thread_network_name);
        return;
    }

    if (current_thread_domain_name != NULL) {
        srpl_domain_rename(current_thread_domain_name, new_thread_domain_name);
    }
    srpl_domain_add(new_thread_domain_name);
    free(current_thread_domain_name);
    current_thread_domain_name = new_thread_domain_name;

    srpl_domain_advertise();
}

void
srpl_startup(void)
{
    server_id = srp_random64();
    cti_get_thread_network_name(NULL, srpl_thread_network_name_callback, NULL);
}
#endif // SRP_FEATURE_REPLICATION

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
