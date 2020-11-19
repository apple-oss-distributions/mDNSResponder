/* dnssd-proxy.c
 *
 * Copyright (c) 2018-2019 Apple Computer, Inc. All rights reserved.
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
 * This is a Discovery Proxy module for the SRP gateway.
 *
 * The motivation here is that it makes sense to co-locate the SRP relay and the Discovery Proxy because
 * these functions are likely to co-exist on the same node, listening on the same port.  For homenet-style
 * name resolution, we need a DNS proxy that implements DNSSD Discovery Proxy for local queries, but
 * forwards other queries to an ISP resolver.  The SRP gateway is already expecting to do this.
 * This module implements the functions required to allow the SRP gateway to also do Discovery Relay.
 *
 * The Discovery Proxy relies on Apple's DNS-SD library and the mDNSResponder DNSSD server, which is included
 * in Apple's open source mDNSResponder package, available here:
 *
 *            https://opensource.apple.com/tarballs/mDNSResponder/
 */

#define __APPLE_USE_RFC_3542

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
#include <ctype.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>

#include "dns_sd.h"
#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#define DNSMessageHeader dns_wire_t
#include "dso.h"
#include "ioloop.h"
#include "srp-tls.h"
#include "config-parse.h"

// Enumerate the list of interfaces, map them to interface indexes, give each one a name
// Have a tree of subdomains for matching

// Configuration file settings
uint16_t udp_port;
uint16_t tcp_port;
uint16_t tls_port;
char *my_name = "discoveryproxy.home.arpa.";
#define MAX_ADDRS 10
char *listen_addrs[MAX_ADDRS];
int num_listen_addrs = 0;
char *publish_addrs[MAX_ADDRS];
int num_publish_addrs = 0;
char *tls_cacert_filename = NULL;
char *tls_cert_filename = "/etc/dnssd-proxy/server.crt";
char *tls_key_filename = "/etc/dnssd-proxy/server.key";
comm_t *listener[4 + MAX_ADDRS];
int num_listeners = 0;

typedef struct hardwired hardwired_t;
struct hardwired {
    hardwired_t *next;
    uint16_t type;
    char *name;
    char *fullname;
    uint8_t *rdata;
    uint16_t rdlen;
};

typedef struct interface_addr interface_addr_t;
struct interface_addr {
    interface_addr_t *next;
    addr_t addr, mask;
};

typedef struct interface interface_t;
struct interface {
    int ifindex;                        // The interface index (for use with sendmsg() and recvmsg().
    bool no_push;                       // If true, don't set up DNS Push for this domain
    char *name;                         // The name of the interface
    interface_addr_t *addresses;        // Addresses on this interface.
};

typedef struct served_domain served_domain_t;
struct served_domain {
    served_domain_t *next;              // Active configurations, used for identifying a domain that matches
    char *domain;                       // The domain name of the interface, represented as a text string.
    char *domain_ld;                    // The same name, with a leading dot (if_domain_lp == if_domain + 1)
    dns_name_t *domain_name;            // The domain name, parsed into labels.
    hardwired_t *hardwired_responses;   // Hardwired responses for this interface
    struct interface *interface;        // Interface to which this domain applies (may be NULL).
} *served_domains;

typedef struct dnssd_query {
    dnssd_txn_t *txn;
    wakeup_t *wakeup;
    char *name;                     // The name we are looking up.
    served_domain_t *served_domain; // If this query matches an enclosing domain, the domain that matched.

                                    // If we've already copied out the enclosing domain once in a DNS message.
    dns_name_pointer_t enclosing_domain_pointer;

    message_t *question;
    comm_t *connection;
    dso_activity_t *activity;
    int serviceFlags;               // Service flags to use with this query.
    bool is_dns_push;
    bool is_edns0;
    uint16_t type, qclass;          // Original query type and class.
    dns_towire_state_t towire;
    uint8_t *p_dso_length;          // Where to store the DSO length just before we write out a push notification.
    dns_wire_t *response;
    size_t data_size;		        // Size of the data payload of the response
} dnssd_query_t;

const char push_subscription_activity_type[] = "push subscription";

const char local_suffix[] = ".local.";

#define TOWIRE_CHECK(note, towire, func) { func; if ((towire)->error != 0 && failnote == NULL) failnote = (note); }

// Forward references
static served_domain_t *NULLABLE new_served_domain(interface_t *NULLABLE interface, char *NONNULL domain);

// Code

int64_t dso_transport_idle(void *context, int64_t now, int64_t next_event)
{
    return next_event;
}

void dnssd_query_cancel(dnssd_query_t *query)
{
    if (query->txn != NULL) {
        ioloop_dnssd_txn_cancel(query->txn);
        ioloop_dnssd_txn_release(query->txn);
        query->txn = NULL;
    }
    query->connection = NULL;
}

void dnssd_query_close_callback(void *context, int status)
{
    dnssd_query_t *query = context;

    ERROR("DNSServiceProcessResult on %s%s returned %d",
          query->name, (query->served_domain != NULL
                      ? (query->served_domain->interface != NULL ? ".local" : query->served_domain->domain_ld)
                      : ""), status);
    if (query->activity != NULL && query->connection != NULL) {
        dso_drop_activity(query->connection->dso, query->activity);
    } else {
        dnssd_query_cancel(query);
    }
}

void
dns_push_finalize(dso_activity_t *activity)
{
    dnssd_query_t *query = (dnssd_query_t *)activity->context;
    INFO("dnssd_push_finalize: " PUB_S_SRP, activity->name);
    dnssd_query_cancel(query);
}

void
dnssd_query_finalize_callback(void *context)
{
    dnssd_query_t *query = context;
    INFO("dnssd_query_finalize on " PRI_S_SRP PUB_S_SRP,
         query->name, (query->served_domain
                       ? (query->served_domain->interface ? ".local" : query->served_domain->domain_ld)
                       : ""));
    if (query->txn) {
        ioloop_dnssd_txn_cancel(query->txn);
        ioloop_dnssd_txn_release(query->txn);
        query->txn = NULL;
    }
    if (query->question) {
        message_free(query->question);
    }
    free(query->name);
    free(query);
}

void
dp_simple_response(comm_t *comm, int rcode)
{
    if (comm->send_response) {
        struct iovec iov;
        dns_wire_t response;
        memset(&response, 0, DNS_HEADER_SIZE);

        // We take the ID and the opcode from the incoming message, because if the
        // header has been mangled, we (a) wouldn't have gotten here and (b) don't
        // have any better choice anyway.
        response.id = comm->message->wire.id;
        dns_qr_set(&response, dns_qr_response);
        dns_opcode_set(&response, dns_opcode_get(&comm->message->wire));
        dns_rcode_set(&response, rcode);
        iov.iov_base = &response;
        iov.iov_len = DNS_HEADER_SIZE; // No RRs
        comm->send_response(comm, comm->message, &iov, 1);
    }
}

bool
dso_send_formerr(dso_state_t *dso, const dns_wire_t *header)
{
    comm_t *transport = dso->transport;
    (void)header;
    dp_simple_response(transport, dns_rcode_formerr);
    return true;
}

served_domain_t *
dp_served(dns_name_t *name, char *buf, size_t bufsize)
{
    served_domain_t *sdt;
    dns_label_t *lim;

    for (sdt = served_domains; sdt; sdt = sdt->next) {
        if ((lim = dns_name_subdomain_of(name, sdt->domain_name))) {
            dns_name_print_to_limit(name, lim, buf, bufsize);
            return sdt;
        }
    }
    return NULL;
}

// Utility function to find "local" on the end of a string of labels.
bool
truncate_local(dns_name_t *name)
{
    dns_label_t *lp, *prev, *prevprev;

    prevprev = prev = NULL;
    // Find the root label.
    for (lp = name; lp && lp->len; lp = lp->next) {
        prevprev = prev;
        prev = lp;
    }
    if (lp && prev && prevprev) {
        if (prev->len == 5 && dns_labels_equal(prev->data, "local", 5)) {
            dns_name_free(prev);
            prevprev->next = NULL;
            return true;
        }
    }
    return false;
}

void
dp_query_add_data_to_response(dnssd_query_t *query, const char *fullname,
                              uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, int32_t ttl)
{
    dns_towire_state_t *towire = &query->towire;
    const char *failnote = NULL;
    const uint8_t *rd = rdata;
    char pbuf[DNS_MAX_NAME_SIZE + 1];
    char rbuf[DNS_MAX_NAME_SIZE + 1];
    uint8_t *revert = query->towire.p; // Remember where we were in case there's no room.
    bool local;

    if (rdlen == 0) {
        INFO("Eliding zero-length response for " PRI_S_SRP " %d %d", fullname, rrtype, rrclass);
        return;
    }
    // Don't send A records for 127.* nor AAAA records for ::1
    if (rrtype == dns_rrtype_a && rdlen == 4) {
        // Should use IN_LINKLOCAL and IN_LOOPBACK macros here, but for some reason they are not present on
        // OpenWRT.
        if (rd[0] == 127) {
            IPv4_ADDR_GEN_SRP(rd, rd_buf);
            INFO("Eliding localhost response for " PRI_S_SRP ": " PRI_IPv4_ADDR_SRP, fullname,
                  IPv4_ADDR_PARAM_SRP(rd, rd_buf));
            return;
        }
        if (rd[0] == 169 && rd[1] == 254) {
            IPv4_ADDR_GEN_SRP(rd, rd_buf);
            INFO("Eliding link-local response for " PRI_S_SRP ": " PRI_IPv4_ADDR_SRP, fullname,
                 IPv4_ADDR_PARAM_SRP(rd, rd_buf));
            return;
        }
    } else if (rrtype == dns_rrtype_aaaa && rdlen == 16) {
        struct in6_addr addr = *(struct in6_addr *)rdata;
        if (IN6_IS_ADDR_LOOPBACK(&addr)) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, rdata_buf);
            INFO("Eliding localhost response for " PRI_S_SRP ": " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 fullname, SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, rdata_buf));
            return;
        }
        if (IN6_IS_ADDR_LINKLOCAL(&addr)) {
            SEGMENTED_IPv6_ADDR_GEN_SRP(rdata, rdata_buf);
            INFO("Eliding link-local response for " PRI_S_SRP ": " PRI_SEGMENTED_IPv6_ADDR_SRP,
                 fullname, SEGMENTED_IPv6_ADDR_PARAM_SRP(rdata, rdata_buf));
            return;
        }
    }
    INFO("dp_query_add_data_to_response: survived for rrtype %d rdlen %d", rrtype, rdlen);

    // Rewrite the domain if it's .local.
    if (query->served_domain != NULL) {
        TOWIRE_CHECK("concatenate_name_to_wire", towire,
                     dns_concatenate_name_to_wire(towire, NULL, query->name, query->served_domain->domain));
        INFO(PUB_S_SRP " answer:  type %02d class %02d " PRI_S_SRP "." PRI_S_SRP, query->is_dns_push ? "PUSH" : "DNS ",
             rrtype, rrclass, query->name, query->served_domain->domain);
    } else {
        TOWIRE_CHECK("compress_name_to_wire", towire, dns_concatenate_name_to_wire(towire, NULL, NULL, query->name));
        INFO(PUB_S_SRP " answer:  type %02d class %02d " PRI_S_SRP " (p)",
             query->is_dns_push ? "push" : " dns", rrtype, rrclass, query->name);
    }
    TOWIRE_CHECK("rrtype", towire, dns_u16_to_wire(towire, rrtype));
    TOWIRE_CHECK("rrclass", towire, dns_u16_to_wire(towire, rrclass));
    TOWIRE_CHECK("ttl", towire, dns_ttl_to_wire(towire, ttl));

    if (rdlen > 0) {
        // If necessary, correct domain names inside of rrdata.
        dns_rr_t answer;
        dns_name_t *name;
        unsigned offp = 0;

        answer.type = rrtype;
        answer.qclass = rrclass;
        if (dns_rdata_parse_data(&answer, rdata, &offp, rdlen, rdlen, 0)) {
            switch(rrtype) {
            case dns_rrtype_cname:
            case dns_rrtype_ptr:
            case dns_rrtype_ns:
            case dns_rrtype_md:
            case dns_rrtype_mf:
            case dns_rrtype_mb:
            case dns_rrtype_mg:
            case dns_rrtype_mr:
            case dns_rrtype_nsap_ptr:
            case dns_rrtype_dname:
                name = answer.data.ptr.name;
                TOWIRE_CHECK("rdlength begin", towire, dns_rdlength_begin(towire));
                break;
            case dns_rrtype_srv:
                name = answer.data.srv.name;
                TOWIRE_CHECK("rdlength begin", towire, dns_rdlength_begin(towire));
                TOWIRE_CHECK("answer.data.srv.priority", towire, dns_u16_to_wire(towire, answer.data.srv.priority));
                TOWIRE_CHECK("answer.data.srv.weight", towire, dns_u16_to_wire(towire, answer.data.srv.weight));
                TOWIRE_CHECK("answer.data.srv.port", towire, dns_u16_to_wire(towire, answer.data.srv.port));
                break;
            default:
                INFO("record type %d not translated", rrtype);
                goto raw;
            }

            dns_name_print(name, rbuf, sizeof rbuf);

            // If the name ends in .local, truncate it.
            if ((local = truncate_local(name))) {
                dns_name_print(name, pbuf, sizeof pbuf);
            }

            // If the name ended in .local, concatenate the interface domain name to the end.
            if (local) {
                TOWIRE_CHECK("concatenate_name_to_wire 2", towire,
                             dns_concatenate_name_to_wire(towire, name, NULL, query->served_domain->domain));
                INFO("translating " PRI_S_SRP " to " PRI_S_SRP " . " PRI_S_SRP, rbuf, pbuf,
                     query->served_domain->domain);
            } else {
                TOWIRE_CHECK("concatenate_name_to_wire 2", towire,
                             dns_concatenate_name_to_wire(towire, name, NULL, NULL));
                INFO("compressing " PRI_S_SRP, rbuf);
            }
            dns_name_free(name);
            dns_rdlength_end(towire);
        } else {
            ERROR("dp_query_add_data_to_response: rdata from mDNSResponder didn't parse!!");
        raw:
            TOWIRE_CHECK("rdlen", towire, dns_u16_to_wire(towire, rdlen));
            TOWIRE_CHECK("rdata", towire, dns_rdata_raw_data_to_wire(towire, rdata, rdlen));
        }
    } else {
        TOWIRE_CHECK("rdlen", towire, dns_u16_to_wire(towire, rdlen));
    }
    if (towire->truncated || failnote) {
        ERROR("RR ADD FAIL: dp_query_add_data_to_response: " PUB_S_SRP, failnote);
        query->towire.p = revert;
    }
}

void
dnssd_hardwired_add(served_domain_t *sdt,
                    const char *name, const char *domain, size_t rdlen, uint8_t *rdata, uint16_t type)
{
    hardwired_t *hp, **hrp;
    int namelen = strlen(name);
    size_t total = sizeof *hp;
    uint8_t *trailer;
    total += rdlen; // Space for RDATA
    total += namelen; // Space for name
    total += 1; // NUL
    total += namelen;// space for FQDN
    total += strlen(domain);
    total += 1; // NUL

    hp = calloc(1, total + 4);
    if (hp == NULL) {
        ERROR("no memory for %s %s", name, domain);
        return;
    }
    trailer = ((uint8_t *)hp) + total;
    memcpy(trailer, "abcd", 4);
    hp->rdata = (uint8_t *)(hp + 1);
    hp->rdlen = rdlen;
    memcpy(hp->rdata, rdata, rdlen);
    hp->name = (char *)hp->rdata + rdlen;
    strcpy(hp->name, name);
    hp->fullname = hp->name + namelen + 1;
    if (namelen != 0) {
        strcpy(hp->fullname, name);
        strcpy(hp->fullname + namelen, domain);
    } else {
        strcpy(hp->fullname, domain);
    }
    if (hp->fullname + strlen(hp->fullname) + 1 != (char *)hp + total) {
        ERROR("%p != %p", hp->fullname + strlen(hp->fullname) + 1, ((char *)hp) + total);
        return;
    }
    if (memcmp(trailer, "abcd", 4)) {
        ERROR("ran off the end.");
        return;
    }
    hp->type = type;
    hp->next = NULL;

    // Store this new hardwired_t at the end of the list unless a hardwired_t with the same name
    // is already on the list.   If it is, splice it in.
    for (hrp = &sdt->hardwired_responses; *hrp != NULL; hrp = &(*hrp)->next) {
        hardwired_t *old = *hrp;
        if (!strcmp(old->fullname, hp->name) && old->type == hp->type) {
            INFO("hardwired_add: superseding " PRI_S_SRP " name " PRI_S_SRP " type %d rdlen %d", old->fullname,
                 old->name, old->type, old->rdlen);
            hp->next = old->next;
            free(old);
            break;
        }
    }
    *hrp = hp;

    INFO("hardwired_add: fullname " PRI_S_SRP " name " PRI_S_SRP " type %d rdlen %d",
         hp->fullname, hp->name, hp->type, hp->rdlen);
}

void dnssd_hardwired_lbdomains_setup(dns_towire_state_t *towire, dns_wire_t *wire)
{
    served_domain_t *ip6 = NULL, *ipv4 = NULL, *addr_domain, *interface_domain;
    char name[DNS_MAX_NAME_SIZE + 1];

#define RESET \
    memset(towire, 0, sizeof *towire); \
    towire->message = wire; \
    towire->p = wire->data; \
    towire->lim = towire->p + sizeof wire->data

    for (addr_domain = served_domains; addr_domain; addr_domain = addr_domain->next) {
        interface_t *interface = addr_domain->interface;
        interface_addr_t *ifaddr;
        if (interface == NULL) {
            INFO("Domain " PRI_S_SRP " has no interface", addr_domain->domain);
            continue;
        }
        INFO("Interface " PUB_S_SRP, interface->name);
        // Add lb domain support for link domain
        for (ifaddr = interface->addresses; ifaddr != NULL; ifaddr = ifaddr->next) {
            if (ifaddr->addr.sa.sa_family == AF_INET) {
                uint8_t *address = (uint8_t *)&(ifaddr->addr.sin.sin_addr);
                uint8_t *mask = (uint8_t *)&(ifaddr->mask.sin.sin_addr);
                char *bp;
                int space = sizeof name;
                int i;

                if (address[0] == 127) {
                    INFO("Skipping IPv4 loopback address on " PRI_S_SRP " (" PUB_S_SRP ")",
                          addr_domain->domain, interface->name);
                    continue;
                }

                if (address[0] == 169 && address[1] == 254) {
                    INFO("Skipping IPv4 link local address on " PRI_S_SRP " (" PUB_S_SRP ")",
                         addr_domain->domain, interface->name);
                    continue;
                }

                snprintf(name, space, "lb._dns-sd._udp");
                bp = name + strlen(name);
                for (i = 3; i >= 0; i--) {
                    snprintf(bp, space - (bp - name), ".%d", address[i] & mask[i]);
                    bp += strlen(bp);
                }
                if (ipv4 == NULL) {
                    ipv4 = new_served_domain(NULL, "in-addr.arpa.");
                    if (ipv4 == NULL) {
                        ERROR("No space for in-addr.arpa.");
                        return;
                    }
                }

                INFO("Adding PTRs for " PRI_S_SRP, name);
                for (interface_domain = served_domains; interface_domain != NULL;
                     interface_domain = interface_domain->next) {
                    if (interface_domain->interface == NULL || interface_domain->interface->ifindex == 0) {
                        continue;
                    }
                    RESET;
                    INFO("Adding PTR from " PRI_S_SRP " to " PRI_S_SRP, name, interface_domain->domain);
                    dns_full_name_to_wire(NULL, towire, interface_domain->domain);
                    dnssd_hardwired_add(ipv4, name, ipv4->domain_ld, towire->p - wire->data, wire->data,
                                        dns_rrtype_ptr);
                }
            } else if (ifaddr->addr.sa.sa_family == AF_INET6) {
                uint8_t *address = (uint8_t *)&(ifaddr->addr.sin6.sin6_addr);
                uint8_t *mask = (uint8_t *)&(ifaddr->mask.sin6.sin6_addr);
                char *bp;
                int space = sizeof name;
                int i, word, shift;

                if (IN6_IS_ADDR_LOOPBACK(&ifaddr->addr.sin6.sin6_addr)) {
                    INFO("Skipping IPv6 link local address on " PRI_S_SRP " (" PUB_S_SRP ")", addr_domain->domain,
                         interface->name);
                    continue;
                }
                if (IN6_IS_ADDR_LINKLOCAL(&ifaddr->addr.sin6.sin6_addr)) {
                    INFO("Skipping IPv6 link local address on " PRI_S_SRP " (" PUB_S_SRP ")", addr_domain->domain,
                         interface->name);
                    continue;
                }
                snprintf(name, space, "lb._dns-sd._udp");
                bp = name + strlen(name);
                for (i = 16; i >= 0; i--) {
                    word = i;
                    for (shift = 0; shift < 8; shift += 4) {
                        snprintf(bp, (sizeof name) - (bp - name), ".%x",
                                (address[word] >> shift) & (mask[word] >> shift) & 15);
                        bp += strlen(bp);
                    }
                }
                if (ip6 == NULL) {
                    ip6 = new_served_domain(NULL, "ip6.arpa.");
                    if (ip6 == NULL) {
                        ERROR("No space for ip6.arpa.");
                        return;
                    }
                }
                INFO("Adding PTRs for " PRI_S_SRP, name);
                for (interface_domain = served_domains; interface_domain != NULL;
                     interface_domain = interface_domain->next) {
                    if (interface_domain->interface == NULL || interface_domain->interface->ifindex == 0) {
                        continue;
                    }
                    INFO("Adding PTR from " PRI_S_SRP " to " PRI_S_SRP, name, interface_domain->domain);
                    RESET;
                    dns_full_name_to_wire(NULL, towire, interface_domain->domain);
                    dnssd_hardwired_add(ip6, name, ip6->domain_ld, towire->p - wire->data, wire->data, dns_rrtype_ptr);
                }
            } else {
                char buf[INET6_ADDRSTRLEN];
                IOLOOP_NTOP(&ifaddr->addr, buf);
                INFO("Skipping " PRI_S_SRP, buf);
            }
        }
    }
#undef RESET
}

void
dnssd_hardwired_setup(void)
{
    dns_wire_t wire;
    dns_towire_state_t towire;
    served_domain_t *sdt;
    int i;
    dns_name_t *my_name_parsed = my_name == NULL ? NULL : dns_pres_name_parse(my_name);
    char namebuf[DNS_MAX_NAME_SIZE + 1];
    const char *local_name = my_name;
    addr_t addr;

#define RESET \
    memset(&towire, 0, sizeof towire); \
    towire.message = &wire; \
    towire.p = wire.data; \
    towire.lim = towire.p + sizeof wire.data

    // For each interface, set up the hardwired names.
    for (sdt = served_domains; sdt; sdt = sdt->next) {
        if (sdt->interface == NULL) {
            continue;
        }

        // SRV
        // _dns-llq._udp
        // _dns-llq-tls._tcp
        // _dns-update._udp
        // _dns-update-tls._udp
        // We deny the presence of support for LLQ, because we only support DNS Push
        RESET;
        dnssd_hardwired_add(sdt, "_dns-llq._udp", sdt->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        dnssd_hardwired_add(sdt, "_dns-llq-tls._tcp", sdt->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);

        // We deny the presence of support for DNS Update, because a Discovery Proxy zone is stateless.
        dnssd_hardwired_add(sdt, "_dns-update._udp", sdt->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);
        dnssd_hardwired_add(sdt, "_dns-update-tls._tcp", sdt->domain_ld, towire.p - wire.data, wire.data,
                            dns_rrtype_srv);

        // Until we set up the DNS Push listener, we deny its existence.   If TLS is ready to go, this will be
        // overwritten immediately; otherwise it will be overwritten when the TLS key has been generated and signed.
        dnssd_hardwired_add(sdt, "_dns-push-tls._tcp", sdt->domain_ld, towire.p - wire.data, wire.data, dns_rrtype_srv);

        // If my_name wasn't set, or if my_name is in this interface's domain, we need to answer
        // for it when queried.
        if (my_name == NULL || my_name_parsed != NULL) {
            const char *local_domain = NULL;
            if (my_name == NULL) {
                local_name = "ns";
                local_domain = sdt->domain_ld;
            } else {
                dns_name_t *lim;
                local_name = NULL;

                // See if my_name is a subdomain of this interface's domain
                if ((lim = dns_name_subdomain_of(my_name_parsed, sdt->domain_name)) != NULL) {
                    dns_name_print_to_limit(my_name_parsed, lim, namebuf, sizeof namebuf);
                    local_name = namebuf;
                    dns_name_free(my_name_parsed);
                    my_name_parsed = NULL;
                    if (local_name[0] == '\0') {
                        local_domain = sdt->domain;
                    } else {
                        local_domain = sdt->domain_ld;
                    }
                }
            }
            if (local_name != NULL) {
                for (i = 0; i < num_publish_addrs; i++) {
                    RESET;
                    memset(&addr, 0, sizeof addr);
                    getipaddr(&addr, publish_addrs[i]);
                    if (addr.sa.sa_family == AF_INET) {
                        // A
                        // ns
                        dns_rdata_raw_data_to_wire(&towire, &addr.sin.sin_addr, sizeof addr.sin.sin_addr);
                        dnssd_hardwired_add(sdt, local_name, local_domain, towire.p - wire.data, wire.data,
                                            dns_rrtype_a);
                    } else {
                        // AAAA
                        RESET;
                        dns_rdata_raw_data_to_wire(&towire, &addr.sin6.sin6_addr, sizeof addr.sin6.sin6_addr);
                        dnssd_hardwired_add(sdt, local_name, local_domain, towire.p - wire.data, wire.data,
                                            dns_rrtype_aaaa);
                    }
                }
            }
        }

        // NS
        RESET;
        if (my_name != NULL) {
            dns_full_name_to_wire(NULL, &towire, my_name);
        } else {
            dns_name_to_wire(NULL, &towire, "ns");
            dns_full_name_to_wire(NULL, &towire, sdt->domain);
        }
        dnssd_hardwired_add(sdt, "", sdt->domain, towire.p - wire.data, wire.data, dns_rrtype_ns);

        // SOA (piggybacking on what we already did for NS, which starts the same.
        dns_name_to_wire(NULL, &towire, "postmaster");
        dns_full_name_to_wire(NULL, &towire, sdt->domain);
        dns_u32_to_wire(&towire, 0);     // serial
        dns_ttl_to_wire(&towire, 7200);  // refresh
        dns_ttl_to_wire(&towire, 3600);  // retry
        dns_ttl_to_wire(&towire, 86400); // expire
        dns_ttl_to_wire(&towire, 120);    // minimum
        dnssd_hardwired_add(sdt, "", sdt->domain, towire.p - wire.data, wire.data, dns_rrtype_soa);
    }

    if (my_name_parsed != NULL) {
        dns_name_free(my_name_parsed);
        my_name_parsed = NULL;

        sdt = new_served_domain(NULL, my_name);
        if (sdt == NULL) {
            ERROR("Unable to allocate domain for %s", my_name);
        } else {
            for (i = 0; i < num_publish_addrs; i++) {
                // AAAA
                // A
                RESET;
                memset(&addr, 0, sizeof addr);
                getipaddr(&addr, publish_addrs[i]);
                if (addr.sa.sa_family == AF_INET) {
                    dns_rdata_raw_data_to_wire(&towire, &addr.sin.sin_addr, sizeof addr.sin.sin_addr);
                    dnssd_hardwired_add(sdt, "", sdt->domain, towire.p - wire.data, wire.data, dns_rrtype_a);
                } else {
                    dns_rdata_raw_data_to_wire(&towire, &addr.sin6.sin6_addr, sizeof addr.sin6.sin6_addr);
                    dnssd_hardwired_add(sdt, "", sdt->domain, towire.p - wire.data, wire.data, dns_rrtype_aaaa);
                }
            }
        }
    }
    dnssd_hardwired_lbdomains_setup(&towire, &wire);
}

void
dnssd_hardwired_push_setup(void)
{
    dns_wire_t wire;
    dns_towire_state_t towire;
    served_domain_t *sdt;

#define RESET \
    memset(&towire, 0, sizeof towire); \
    towire.message = &wire; \
    towire.p = wire.data; \
    towire.lim = towire.p + sizeof wire.data

    // For each interface, set up the hardwired names.
    for (sdt = served_domains; sdt; sdt = sdt->next) {
        if (sdt->interface == NULL) {
            continue;
        }

        if (!sdt->interface->no_push) {
            // SRV
            // _dns-push-tls._tcp
            RESET;
            dns_u16_to_wire(&towire, 0); // priority
            dns_u16_to_wire(&towire, 0); // weight
            dns_u16_to_wire(&towire, 853); // port
            // Define my_name in the config file to reference a name for this server in a different zone.
            if (my_name == NULL) {
                dns_name_to_wire(NULL, &towire, "ns");
                dns_full_name_to_wire(NULL, &towire, sdt->domain);
            } else {
                dns_full_name_to_wire(NULL, &towire, my_name);
            }
            dnssd_hardwired_add(sdt, "_dns-push-tls._tcp", sdt->domain_ld, towire.p - wire.data, wire.data,
                                dns_rrtype_srv);
            // This will probably never be used, but existing open source mDNSResponder code can be
            // configured to do DNS queries over TLS for specific domains, so we might as well support it,
            // since we do have TLS support.
            dnssd_hardwired_add(sdt, "_dns-query-tls._udp", sdt->domain_ld, towire.p - wire.data, wire.data,
                                dns_rrtype_srv);
        }
    }
}

bool
embiggen(dnssd_query_t *query)
{
    dns_wire_t *nr = malloc(query->data_size + sizeof *nr); // increments wire size by DNS_DATA_SIZE
    if (nr == NULL) {
        return false;
    }
    memcpy(nr, query->response, DNS_HEADER_SIZE + query->data_size);
    query->data_size += DNS_DATA_SIZE;
#define RELOCATE(x) (x) = &nr->data[0] + ((x) - &query->response->data[0])
    RELOCATE(query->towire.p);
    query->towire.lim = &nr->data[0] + query->data_size;
    query->towire.p_rdlength = NULL;
    query->towire.p_opt = NULL;
    query->towire.message = nr;
    free(query->response);
    query->response = nr;
    return true;
}

void
dp_query_send_dns_response(dnssd_query_t *query)
{
    struct iovec iov;
    dns_towire_state_t *towire = &query->towire;
    const char *failnote = NULL;
    uint8_t *revert = towire->p;
    uint16_t tc = towire->truncated ? dns_flags_tc : 0;
    uint16_t bitfield = ntohs(query->response->bitfield);
    uint16_t mask = 0;

    // Send an SOA record if it's a .local query.
    if (query->served_domain != NULL && query->served_domain->interface != NULL && !towire->truncated) {
    redo:
        // DNSSD Hybrid, Section 6.1.
        TOWIRE_CHECK("&query->enclosing_domain_pointer 1", towire,
                     dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
        TOWIRE_CHECK("dns_rrtype_soa", towire,
                     dns_u16_to_wire(towire, dns_rrtype_soa));
        TOWIRE_CHECK("dns_qclass_in", towire,
                     dns_u16_to_wire(towire, dns_qclass_in));
        TOWIRE_CHECK("ttl", towire, dns_ttl_to_wire(towire, 3600));
        TOWIRE_CHECK("rdlength_begin ", towire, dns_rdlength_begin(towire));
        if (my_name != NULL) {
            TOWIRE_CHECK(my_name, towire, dns_full_name_to_wire(NULL, towire, my_name));
        } else {
            TOWIRE_CHECK("\"ns\"", towire, dns_name_to_wire(NULL, towire, "ns"));
            TOWIRE_CHECK("&query->enclosing_domain_pointer 2", towire,
                         dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
        }
        TOWIRE_CHECK("\"postmaster\"", towire,
                     dns_name_to_wire(NULL, towire, "postmaster"));
        TOWIRE_CHECK("&query->enclosing_domain_pointer 3", towire,
                     dns_pointer_to_wire(NULL, towire, &query->enclosing_domain_pointer));
        TOWIRE_CHECK("serial", towire,dns_u32_to_wire(towire, 0));     // serial
        TOWIRE_CHECK("refresh", towire, dns_ttl_to_wire(towire, 7200));  // refresh
        TOWIRE_CHECK("retry", towire, dns_ttl_to_wire(towire, 3600));  // retry
        TOWIRE_CHECK("expire", towire, dns_ttl_to_wire(towire, 86400)); // expire
        TOWIRE_CHECK("minimum", towire, dns_ttl_to_wire(towire, 120));    // minimum
        dns_rdlength_end(towire);
        if (towire->truncated) {
            query->towire.p = revert;
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.error = 0;
                    towire->truncated = false;
                    goto redo;
                }
            } else {
                tc = dns_flags_tc;
            }
        } else {
            query->response->nscount = htons(1);
        }

        // Response is authoritative and not recursive.
        mask = ~dns_flags_ra;
        bitfield = bitfield | dns_flags_aa | tc;
        bitfield = bitfield & mask;
    } else {
        // Response is recursive and not authoritative.
        mask = ~dns_flags_aa;
        bitfield = bitfield | dns_flags_ra | tc;
        bitfield = bitfield & mask;
    }
    // Not authentic, checking not disabled.
    mask = ~(dns_flags_rd | dns_flags_ad | dns_flags_cd);
    bitfield = bitfield & mask;
    query->response->bitfield = htons(bitfield);

    // This is a response
    dns_qr_set(query->response, dns_qr_response);

    // Send an OPT RR if we got one
    // XXX reserve space so we can always send an OPT RR?
    if (query->is_edns0) {
    redo_edns0:
        TOWIRE_CHECK("Root label", towire, dns_u8_to_wire(towire, 0));     // Root label
        TOWIRE_CHECK("dns_rrtype_opt", towire, dns_u16_to_wire(towire, dns_rrtype_opt));
        TOWIRE_CHECK("UDP Payload size", towire, dns_u16_to_wire(towire, 4096)); // UDP Payload size
        TOWIRE_CHECK("extended-rcode", towire, dns_u8_to_wire(towire, 0));     // extended-rcode
        TOWIRE_CHECK("EDNS version 0", towire, dns_u8_to_wire(towire, 0));     // EDNS version 0
        TOWIRE_CHECK("No extended flags", towire, dns_u16_to_wire(towire, 0));    // No extended flags
        TOWIRE_CHECK("No payload", towire, dns_u16_to_wire(towire, 0));    // No payload
        if (towire->truncated) {
            query->towire.p = revert;
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.error = false;
                    query->towire.truncated = false;
                    goto redo_edns0;
                }
            }
        } else {
            query->response->arcount = htons(1);
        }
    }

    if (towire->error) {
        ERROR("dp_query_send_dns_response failed on %s", failnote);
        if (tc == dns_flags_tc) {
            dns_rcode_set(query->response, dns_rcode_noerror);
        } else {
            dns_rcode_set(query->response, dns_rcode_servfail);
        }
    } else {
        // No error.
        dns_rcode_set(query->response, dns_rcode_noerror);
    }

    iov.iov_len = (query->towire.p - (uint8_t *)query->response);
    iov.iov_base = query->response;
    INFO("dp_query_send_dns_response: " PRI_S_SRP " (len %zd)", query->name, iov.iov_len);

    if (query->connection != NULL) {
        query->connection->send_response(query->connection, query->question, &iov, 1);
    }

    // Free up state
    // Query will be freed automatically next time through the io loop.
    dnssd_query_cancel(query);
}

void
dp_query_towire_reset(dnssd_query_t *query)
{
    query->towire.p = &query->response->data[0];  // We start storing RR data here.
    query->towire.lim = &query->response->data[0] + query->data_size; // This is the limit to how much we can store.
    query->towire.message = query->response;
    query->towire.p_rdlength = NULL;
    query->towire.p_opt = NULL;
    query->p_dso_length = NULL;
}

void
dns_push_start(dnssd_query_t *query)
{
    const char *failnote = NULL;

    // If we don't have a dso header yet, start one.
    if (query->p_dso_length == NULL) {
        memset(query->response, 0, (sizeof *query->response) - DNS_DATA_SIZE);
        dns_opcode_set(query->response, dns_opcode_dso);
        // This is a unidirectional DSO message, which is marked as a query
        dns_qr_set(query->response, dns_qr_query);
        // No error cuz not a response.
        dns_rcode_set(query->response, dns_rcode_noerror);

        TOWIRE_CHECK("kDSOType_DNSPushUpdate", &query->towire,
                     dns_u16_to_wire(&query->towire, kDSOType_DNSPushUpdate));
        if (query->towire.p + 2 > query->towire.lim) {
            ERROR("No room for dso length in DNS Push notification message.");
            dp_query_towire_reset(query);
            return;
        }
        query->p_dso_length = query->towire.p;
        query->towire.p += 2;
    }
    if (failnote != NULL) {
        ERROR("dns_push_start: couldn't start update: %s", failnote);
    }
}

void
dp_push_response(dnssd_query_t *query)
{
    struct iovec iov;

    if (query->p_dso_length != NULL) {
        int16_t dso_length = query->towire.p - query->p_dso_length - 2;
        iov.iov_len = (query->towire.p - (uint8_t *)query->response);
        iov.iov_base = query->response;
        INFO("dp_push_response: " PRI_S_SRP " (len %zd)", query->name, iov.iov_len);

        query->towire.p = query->p_dso_length;
        dns_u16_to_wire(&query->towire, dso_length);
        if (query->connection != NULL) {
            query->connection->send_response(query->connection, query->question, &iov, 1);
        }
        dp_query_towire_reset(query);
    }
}

bool
dnssd_hardwired_response(dnssd_query_t *query, DNSServiceQueryRecordReply callback)
{
    hardwired_t *hp;
    bool got_response = false;

    for (hp = query->served_domain->hardwired_responses; hp; hp = hp->next) {
        if ((query->type == hp->type || query->type == dns_rrtype_any) &&
            query->qclass == dns_qclass_in && !strcasecmp(hp->name, query->name)) {
            if (query->is_dns_push) {
                dns_push_start(query);
                dp_query_add_data_to_response(query, hp->fullname, hp->type, dns_qclass_in, hp->rdlen, hp->rdata, 3600);
            } else {
                // Store the response
                if (!query->towire.truncated) {
                    dp_query_add_data_to_response(query, hp->fullname, hp->type, dns_qclass_in, hp->rdlen, hp->rdata,
                                                  3600);
                    if (!query->towire.truncated) {
                        query->response->ancount = htons(ntohs(query->response->ancount) + 1);
                    }
                }
            }
            got_response = true;
        }
    }
    if (got_response) {
        if (query->is_dns_push) {
            dp_push_response(query);
        } else {
            // Steal the question
            query->question = query->connection->message;
            query->connection->message = NULL;
            // Send the answer(s).
            dp_query_send_dns_response(query);
        }
        return true;
    }
    return false;
}

// This is the callback for dns query results.
void
dns_query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                   const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata,
                   uint32_t ttl, void *context)
{
    dnssd_query_t *query = context;

    INFO(PRI_S_SRP " %d %d %x %d", fullname, rrtype, rrclass, rdlen, errorCode);

    if (errorCode == kDNSServiceErr_NoError) {
    re_add:
        dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata,
                                      ttl > 10 ? 10 : ttl); // Per dnssd-hybrid 5.5.1, limit ttl to 10 seconds
        if (query->towire.truncated) {
            if (query->connection->tcp_stream) {
                if (embiggen(query)) {
                    query->towire.truncated = false;
                    query->towire.error = false;
                    goto re_add;
                } else {
                    dns_rcode_set(query->response, dns_rcode_servfail);
                    dp_query_send_dns_response(query);
                    return;
                }
            }
        } else {
            query->response->ancount = htons(ntohs(query->response->ancount) + 1);
        }
        // If there isn't more coming, send the response now
        if (!(flags & kDNSServiceFlagsMoreComing) || query->towire.truncated) {
            // When we get a CNAME response, we may not get the record it points to with the MoreComing
            // flag set, so don't respond yet.
            if (query->type != dns_rrtype_cname && rrtype == dns_rrtype_cname) {
            } else {
                dp_query_send_dns_response(query);
            }
        }
    } else if (errorCode == kDNSServiceErr_NoSuchRecord) {
        // If we get "no such record," we can't really do much except return the answer.
        dp_query_send_dns_response(query);
    } else {
        dns_rcode_set(query->response, dns_rcode_servfail);
        dp_query_send_dns_response(query);
    }
}

void
dp_query_wakeup(void *context)
{
    dnssd_query_t *query = context;
    char name[DNS_MAX_NAME_SIZE + 1];
    int namelen = strlen(query->name);

    // Should never happen.
    if (namelen + (query->served_domain
                   ? (query->served_domain->interface != NULL
                      ? sizeof local_suffix
                      : strlen(query->served_domain->domain_ld))
                   : 0) > sizeof name) {
        ERROR("db_query_wakeup: no space to construct name.");
        dnssd_query_cancel(query);
    }

    strcpy(name, query->name);
    if (query->served_domain != NULL) {
        strcpy(name + namelen, local_suffix);
    }
    dp_query_send_dns_response(query);
}

bool
dp_query_start(comm_t *comm, dnssd_query_t *query, int *rcode, DNSServiceQueryRecordReply callback)
{
    char name[DNS_MAX_NAME_SIZE + 1];
    char *np;
    bool local = false;
    int len;
    DNSServiceRef sdref;

    // If a query has a served domain, query->name is the subdomain of the served domain that is
    // being queried; otherwise query->name is the whole name.
    if (query->served_domain != NULL) {
        if (dnssd_hardwired_response(query, callback)) {
            *rcode = dns_rcode_noerror;
            return true;
        }
        len = strlen(query->name);
        if (query->served_domain->interface != NULL) {
            if (len + sizeof local_suffix > sizeof name) {
                *rcode = dns_rcode_servfail;
                free(query->name);
                free(query);
                ERROR("question name %s is too long for .local.", name);
                return false;
            }
            memcpy(name, query->name, len);
            memcpy(&name[len], local_suffix, sizeof local_suffix);
        } else {
            int dlen = strlen(query->served_domain->domain_ld) + 1;
            if (len + dlen > sizeof name) {
                *rcode = dns_rcode_servfail;
                free(query->name);
                free(query);
                ERROR("question name %s is too long for %s.", name, query->served_domain->domain);
                return false;
            }
            memcpy(name, query->name, len);
            memcpy(&name[len], query->served_domain->domain_ld, dlen);
        }
        np = name;
        local = true;
    } else {
        np = query->name;
    }

    // If we get an SOA query for record that's under a zone cut we're authoritative for, which
    // is the case of query->served_domain->interface != NULL, then answer with a negative response that includes
    // our authority records, rather than waiting for the query to time out.
    if (query->served_domain != NULL && query->served_domain->interface != NULL &&
        (query->type == dns_rrtype_soa ||
         query->type == dns_rrtype_ns ||
         query->type == dns_rrtype_ds) && query->qclass == dns_qclass_in && query->is_dns_push == false) {
        query->question = comm->message;
        comm->message = NULL;
        dp_query_send_dns_response(query);
        return true;
    }

    // Issue a DNSServiceQueryRecord call
    int err = DNSServiceQueryRecord(&sdref, query->serviceFlags,
                                    kDNSServiceInterfaceIndexAny, np, query->type,
                                    query->qclass, callback, query);
    if (err != kDNSServiceErr_NoError) {
        ERROR("dp_query_start: DNSServiceQueryRecord failed for '%s': %d", np, err);
        *rcode = dns_rcode_servfail;
        return false;
    } else {
        query->txn = ioloop_dnssd_txn_add(sdref, dnssd_query_finalize_callback, dnssd_query_close_callback);
        if (query->txn == NULL) {
            return false;
        }
        INFO("dp_query_start: DNSServiceQueryRecord started for '" PRI_S_SRP "': %d", np, err);
    }

    // If this isn't a DNS Push subscription, we need to respond quickly with as much data as we have.  It
    // turns out that dig gives us a second, but also that responses seem to come back in on the order of a
    // millisecond, so we'll wait 100ms.
    if (!query->is_dns_push && local) {
        // [mDNSDP 5.6 p. 25]
        if (query->wakeup == NULL) {
            query->wakeup = ioloop_wakeup_create();
            if (query->wakeup == NULL) {
                *rcode = dns_rcode_servfail;
                return false;
            }
        }
        ioloop_add_wake_event(query->wakeup, query, dp_query_wakeup, ioloop_timenow() + IOLOOP_SECOND * 6);
    }
    return true;
}

dnssd_query_t *
dp_query_generate(comm_t *comm, dns_rr_t *question, bool dns_push, int *rcode)
{
    char name[DNS_MAX_NAME_SIZE + 1];
    served_domain_t *sdt = dp_served(question->name, name, sizeof name);

    // If it's a query for a name served by the local discovery proxy, do an mDNS lookup.
    if (sdt) {
        INFO(PUB_S_SRP " question: type %d class %d " PRI_S_SRP "." PRI_S_SRP " -> " PRI_S_SRP ".local",
             dns_push ? "push" : " dns", question->type, question->qclass, name, sdt->domain, name);
    } else {
        dns_name_print(question->name, name, sizeof name);
        INFO(PUB_S_SRP " question: type %d class %d " PRI_S_SRP,
             dns_push ? "push" : " dns", question->type, question->qclass, name);
    }

    dnssd_query_t *query = calloc(1,sizeof *query);
    if (query == NULL) {
    nomem:
        ERROR("Unable to allocate memory for query on %s", name);
        *rcode = dns_rcode_servfail;
        return NULL;
    }
    query->response = malloc(sizeof *query->response);
    if (query->response == NULL) {
        goto nomem;
    }
    query->data_size = DNS_DATA_SIZE;

    // Zero out the DNS header, but not the data.
    memset(query->response, 0, DNS_HEADER_SIZE);

    // Steal the data from the question.   If subdomain is not null, this is a local mDNS query; otherwise
    // we are recursing.
    INFO("name = " PRI_S_SRP, name);
    query->name = strdup(name);
    if (!query->name) {
        *rcode = dns_rcode_servfail;
        free(query);
        ERROR("unable to allocate memory for question name on %s", name);
        return NULL;
    }
    // It is safe to assume that enclosing domain will not be freed out from under us.
    query->served_domain = sdt;
    query->serviceFlags = 0;

    // If this is a local query, add ".local" to the end of the name and require multicast.
    if (sdt != NULL && sdt->interface) {
        query->serviceFlags |= kDNSServiceFlagsForceMulticast;
    } else {
        query->serviceFlags |= kDNSServiceFlagsReturnIntermediates;
    }
    // Name now contains the name we want mDNSResponder to look up.

    // XXX make sure finalize does the right thing.
    query->connection = comm;

    // Remember whether this is a long-lived query.
    query->is_dns_push = dns_push;

    // Start writing the response
    dp_query_towire_reset(query);

    query->type = question->type;
    query->qclass = question->qclass;

    *rcode = dns_rcode_noerror;
    return query;
}

// This is the callback for DNS push query results, as opposed to push updates.
void
dns_push_query_callback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
                        DNSServiceErrorType errorCode,const char *fullname, uint16_t rrtype, uint16_t rrclass,
                        uint16_t rdlen, const void *rdata, uint32_t ttl, void *context)
{
    dnssd_query_t *query = context;
    uint8_t *revert = query->towire.p;

    // From DNSSD-Hybrid, for mDNS queries:
    // If we have cached answers, respond immediately, because we probably have all the answers.
    // If we don't have cached answers, respond as soon as we get an answer (presumably more-coming will be false).

    // The spec says to not query if we have cached answers.   We trust the DNSServiceQueryRecord call to handle this.

    // If we switch to using a single connection to mDNSResponder, we could have !more-coming trigger a flush of
    // all outstanding queries that aren't waiting on a time trigger.   This is because more-coming isn't
    // query-specific

    INFO("PUSH " PRI_S_SRP " %d %d %x %d", fullname, rrtype, rrclass, rdlen, errorCode);

    // query_state_waiting means that we're answering a regular DNS question
    if (errorCode == kDNSServiceErr_NoError) {
        dns_push_start(query);

        // If kDNSServiceFlagsAdd is set, it's an add, otherwise a delete.
        re_add:
        if (flags & kDNSServiceFlagsAdd) {
            dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata, ttl);
        } else {
	    // There was a verion of the code that used different semantics, we use those semantics on non-tls
	    // connections for now, but should delete this soon.
	    if (query->connection->tls_context != NULL) {
                // I think if this happens it means delete all RRs of this type.
                if (rdlen == 0) {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_any, rdlen, rdata, -2);
                } else {
                    if (rdlen == 0) {
			dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_none, rdlen, rdata, -2);
		    } else {
                        dp_query_add_data_to_response(query, fullname, rrtype, rrclass, rdlen, rdata, -1);
		    }
                }
            } else {
                if (rdlen == 0) {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_any, rdlen, rdata, 0);
                } else {
                    dp_query_add_data_to_response(query, fullname, rrtype, dns_qclass_none, rdlen, rdata, 0);
                }
            }
        }
        if (query->towire.truncated) {
            query->towire.truncated = false;
            query->towire.p = revert;
            query->towire.error = 0;
            dp_push_response(query);
            dns_push_start(query);
            goto re_add;
        }

        // If there isn't more coming, send a DNS Push notification now.
        // XXX If enough comes to fill the response, send the message.
        if (!(flags & kDNSServiceFlagsMoreComing)) {
            dp_push_response(query);
        }
    } else {
        ERROR("dns_push_query_callback: unexpected error code %d", errorCode);
        if (query->connection != NULL) {
            dso_drop_activity(query->connection->dso, query->activity);
        }
    }
}

void
dns_push_subscribe(comm_t *comm, const dns_wire_t *header, dso_state_t *dso, dns_rr_t *question,
                   const char *activity_name, const char *opcode_name)
{
    int rcode;
    dnssd_query_t *query = dp_query_generate(comm, question, true, &rcode);

    if (!query) {
        dp_simple_response(comm, rcode);
        return;
    }

    dso_activity_t *activity = dso_add_activity(dso, activity_name, push_subscription_activity_type, query,
                                                dns_push_finalize);
    query->activity = activity;
    if (!dp_query_start(comm, query, &rcode, dns_push_query_callback)) {
        dso_drop_activity(dso, activity);
        dp_simple_response(comm, rcode);
        return;
    }
    dp_simple_response(comm, dns_rcode_noerror);
}

void
dns_push_reconfirm(comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    dns_rr_t question;
    char name[DNS_MAX_NAME_SIZE + 1];
    uint16_t rdlen;

    // The TLV offset should always be pointing into the message.
    unsigned offp = dso->primary.payload - &header->data[0];
    int len = offp + dso->primary.length;

    // Parse the name, rrtype and class.   We say there's no rdata even though there is
    // because there's no ttl and also we want the raw rdata, not parsed rdata.
    if (!dns_rr_parse(&question, header->data, len, &offp, false) ||
        !dns_u16_parse(header->data, len, &offp, &rdlen)) {
        dp_simple_response(comm, dns_rcode_formerr);
        ERROR("dns_push_reconfirm: RR parse from %s failed", dso->remote_name);
        return;
    }
    if (rdlen + offp != len) {
        dp_simple_response(comm, dns_rcode_formerr);
        ERROR("dns_push_reconfirm: RRdata parse from %s failed: length mismatch (%d != %d)",
              dso->remote_name, rdlen + offp, len);
        return;
    }

    if ((dp_served(question.name, name, sizeof name))) {
        int len = strlen(name);
        if (len + sizeof local_suffix > sizeof name) {
            dp_simple_response(comm, dns_rcode_formerr);
            ERROR("dns_push_reconfirm: name is too long for .local suffix: %s", name);
            return;
        }
        memcpy(&name[len], local_suffix, sizeof local_suffix);
    } else {
        dns_name_print(question.name, &name[8], sizeof name - 8);
    }
    // transmogrify name.
    DNSServiceReconfirmRecord(0, kDNSServiceInterfaceIndexAny, name,
                              question.type, question.qclass, rdlen, &header->data[offp]);
    dp_simple_response(comm, dns_rcode_noerror);
}

void
dns_push_unsubscribe(comm_t *comm, const dns_wire_t *header, dso_state_t *dso, dns_rr_t *question,
                   dso_activity_t *activity, const char *opcode_name)
{
    dso_drop_activity(dso, activity);
    // No response, unsubscribe is unidirectional.
}

void
dns_push_subscription_change(const char *opcode_name, comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    // type-in-hex/class-in-hex/name-to-subscribe
    char activity_name[DNS_MAX_NAME_SIZE_ESCAPED + 3 + 4 + 4];
    dso_activity_t *activity;

    // The TLV offset should always be pointing into the message.
    unsigned offp = dso->primary.payload - &header->data[0];
    // Get the question
    dns_rr_t question;

    if (!dns_rr_parse(&question, header->data, offp + dso->primary.length, &offp, false)) {
        // Unsubscribes are unidirectional, so no response can be sent
        if (dso->primary.opcode != kDSOType_DNSPushUnsubscribe) {
            dp_simple_response(comm, dns_rcode_formerr);
        }
        ERROR("RR parse for %s from %s failed", dso->remote_name, opcode_name);
        return;
    }

    // Concoct an activity name.
    snprintf(activity_name, sizeof activity_name, "%04x%04x", question.type, question.qclass);
    if ((dp_served(question.name, &activity_name[8], (sizeof activity_name) - 8))) {
        int len = strlen(activity_name);
        if (len + sizeof local_suffix + 8 > sizeof (activity_name)) {
            ERROR("activity name overflow for %s", activity_name);
            return;
        }
        const int lslen = sizeof local_suffix;
        strncpy(&activity_name[len], local_suffix, lslen);
    } else {
        dns_name_print(question.name, &activity_name[8], (sizeof activity_name) - 8);
    }

    activity = dso_find_activity(dso, activity_name, push_subscription_activity_type, NULL);
    if (activity == NULL) {
        // Unsubscribe with no activity means no work to do; just return noerror.
        if (dso->primary.opcode != kDSOType_DNSPushSubscribe) {
            ERROR("dso_message: %s for %s when no subscription exists.", opcode_name, activity_name);
            if (dso->primary.opcode == kDSOType_DNSPushReconfirm) {
                dp_simple_response(comm, dns_rcode_noerror);
            }
        } else {
            // In this case we have a push subscribe for which no subscription exists, which means we can do it.
            dns_push_subscribe(comm, header, dso, &question, activity_name, opcode_name);
        }
    } else {
        // Subscribe with a matching activity means no work to do; just return noerror.
        if (dso->primary.opcode == kDSOType_DNSPushSubscribe) {
            dp_simple_response(comm, dns_rcode_noerror);
        }
        // Otherwise cancel the subscription.
        else {
            dns_push_unsubscribe(comm, header, dso, &question, activity, opcode_name);
        }
    }
}

static void dso_message(comm_t *comm, const dns_wire_t *header, dso_state_t *dso)
{
    switch(dso->primary.opcode) {
    case kDSOType_DNSPushSubscribe:
        dns_push_subscription_change("DNS Push Subscribe", comm, header, dso);
        break;
    case kDSOType_DNSPushUnsubscribe:
        dns_push_subscription_change("DNS Push Unsubscribe", comm, header, dso);
        break;

    case kDSOType_DNSPushReconfirm:
        dns_push_reconfirm(comm, header, dso);
        break;

    case kDSOType_DNSPushUpdate:
        INFO("dso_message: bogus push update message %d", dso->primary.opcode);
        dso_drop(dso);
        break;

    default:
        INFO("dso_message: unexpected primary TLV %d", dso->primary.opcode);
        dp_simple_response(comm, dns_rcode_dsotypeni);
        break;
    }
    // XXX free the message if we didn't consume it.
}

static void dns_push_callback(void *context, const void *event_context,
                              dso_state_t *dso, dso_event_type_t eventType)
{
    const dns_wire_t *message;
    switch(eventType)
    {
    case kDSOEventType_DNSMessage:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("dns_push_callback: DNS Message (opcode=%d) received from " PRI_S_SRP, dns_opcode_get(message),
             dso->remote_name);
        break;
    case kDSOEventType_DNSResponse:
        // We shouldn't get here because we already handled any DNS messages
        message = event_context;
        INFO("dns_push_callback: DNS Response (opcode=%d) received from " PRI_S_SRP, dns_opcode_get(message),
             dso->remote_name);
        break;
    case kDSOEventType_DSOMessage:
        INFO("dns_push_callback: DSO Message (Primary TLV=%d) received from " PRI_S_SRP,
               dso->primary.opcode, dso->remote_name);
        message = event_context;
        dso_message((comm_t *)context, message, dso);
        break;
    case kDSOEventType_DSOResponse:
        INFO("dns_push_callback: DSO Response (Primary TLV=%d) received from " PRI_S_SRP,
               dso->primary.opcode, dso->remote_name);
        break;

    case kDSOEventType_Finalize:
        INFO("dns_push_callback: Finalize");
        break;

    case kDSOEventType_Connected:
        INFO("dns_push_callback: Connected to " PRI_S_SRP, dso->remote_name);
        break;

    case kDSOEventType_ConnectFailed:
        INFO("dns_push_callback: Connection to " PRI_S_SRP " failed", dso->remote_name);
        break;

    case kDSOEventType_Disconnected:
        INFO("dns_push_callback: Connection to " PRI_S_SRP " disconnected", dso->remote_name);
        break;
    case kDSOEventType_ShouldReconnect:
        INFO("dns_push_callback: Connection to " PRI_S_SRP " should reconnect (not for a server)", dso->remote_name);
        break;
    case kDSOEventType_Inactive:
        INFO("dns_push_callback: Inactivity timer went off, closing connection.");
        break;
    case kDSOEventType_Keepalive:
        INFO("dns_push_callback: should send a keepalive now.");
        break;
    case kDSOEventType_KeepaliveRcvd:
        INFO("dns_push_callback: keepalive received.");
        break;
    case kDSOEventType_RetryDelay:
        INFO("dns_push_callback: keepalive received.");
        break;
    }
}

void
dp_dns_query(comm_t *comm, dns_rr_t *question)
{
    int rcode;
    dnssd_query_t *query = dp_query_generate(comm, question, false, &rcode);
    const char *failnote = NULL;
    if (!query) {
        dp_simple_response(comm, rcode);
        return;
    }

    // For regular DNS queries, copy the ID, etc.
    query->response->id = comm->message->wire.id;
    query->response->bitfield = comm->message->wire.bitfield;
    dns_rcode_set(query->response, dns_rcode_noerror);

    // For DNS queries, we need to return the question.
    query->response->qdcount = htons(1);
    if (query->served_domain != NULL) {
        TOWIRE_CHECK("name", &query->towire, dns_name_to_wire(NULL, &query->towire, query->name));
        TOWIRE_CHECK("enclosing_domain", &query->towire,
                     dns_full_name_to_wire(&query->enclosing_domain_pointer,
                                           &query->towire, query->served_domain->domain));
    } else {
        TOWIRE_CHECK("full name", &query->towire, dns_full_name_to_wire(NULL, &query->towire, query->name));
    }
    TOWIRE_CHECK("TYPE", &query->towire, dns_u16_to_wire(&query->towire, question->type));    // TYPE
    TOWIRE_CHECK("CLASS", &query->towire, dns_u16_to_wire(&query->towire, question->qclass));  // CLASS
    if (failnote != NULL) {
        ERROR("dp_dns_query: failure encoding question: %s", failnote);
        goto fail;
    }

    // We should check for OPT RR, but for now assume it's there.
    query->is_edns0 = true;

    if (!dp_query_start(comm, query, &rcode, dns_query_callback)) {
    fail:
        dp_simple_response(comm, rcode);
        free(query->name);
        free(query);
        return;
    }

    // XXX make sure that finalize frees this.
    if (comm->message) {
        query->question = comm->message;
        comm->message = NULL;
    }
}

void dso_transport_finalize(comm_t *comm)
{
    dso_state_t *dso = comm->dso;
    INFO("dso_transport_finalize: " PRI_S_SRP, dso->remote_name);
    if (comm) {
        ioloop_close(&comm->io);
    }
    free(dso);
    comm->dso = NULL;
}

void dns_evaluate(comm_t *comm)
{
    dns_rr_t question;
    unsigned offset = 0;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&comm->message->wire) == dns_qr_response) {
        return;
    }

    // If this is a DSO message, see if we have a session yet.
    switch(dns_opcode_get(&comm->message->wire)) {
    case dns_opcode_dso:
        if (!comm->tcp_stream) {
            ERROR("DSO message received on non-tcp socket %s", comm->name);
            dp_simple_response(comm, dns_rcode_notimp);
            return;
        }

        if (!comm->dso) {
            comm->dso = dso_create(true, 0, comm->name, dns_push_callback, comm, comm);
            if (!comm->dso) {
                ERROR("Unable to create a dso context for %s", comm->name);
                dp_simple_response(comm, dns_rcode_servfail);
                ioloop_close(&comm->io);
                return;
            }
            comm->dso->transport_finalize = dso_transport_finalize;
        }
        dso_message_received(comm->dso, (uint8_t *)&comm->message->wire, comm->message->length);
        break;

    case dns_opcode_query:
        // In theory this is permitted but it can't really be implemented because there's no way
        // to say "here's the answer for this, and here's why that failed.
        if (ntohs(comm->message->wire.qdcount) != 1) {
            dp_simple_response(comm, dns_rcode_formerr);
            return;
        }
        if (!dns_rr_parse(&question, comm->message->wire.data, comm->message->length, &offset, 0)) {
            dp_simple_response(comm, dns_rcode_formerr);
            return;
        }
        dp_dns_query(comm, &question);
        dns_rrdata_free(&question);
        break;

        // No support for other opcodes yet.
    default:
        dp_simple_response(comm, dns_rcode_notimp);
        break;
    }
}

void dns_input(comm_t *comm)
{
    dns_evaluate(comm);
    if (comm->message != NULL) {
        message_free(comm->message);
        comm->message = NULL;
    }
}

static int
usage(const char *progname)
{
    ERROR("usage: %s", progname);
    ERROR("ex: dnssd-proxy");
    return 1;
}

// Called whenever we get a connection.
void
connected(comm_t *comm)
{
    INFO("connection from " PRI_S_SRP, comm->name);
    return;
}

static bool config_string_handler(char **ret, const char *filename, const char *string, int lineno, bool tdot,
                                  bool ldot)
{
    char *s;
    int add_trailing_dot = 0;
    int add_leading_dot = ldot ? 1 : 0;
    int len = strlen(string);

    // Space for NUL and leading dot.
    if (tdot && len > 0 && string[len - 1] != '.') {
        add_trailing_dot = 1;
    }
    s = malloc(strlen(string) + add_leading_dot + add_trailing_dot + 1);
    if (s == NULL) {
        ERROR("Unable to allocate domain name %s", string);
        return false;
    }
    *ret = s;
    if (ldot) {
        *s++ = '.';
    }
    strcpy(s, string);
    if (add_trailing_dot) {
        s[len] = '.';
        s[len + 1] = 0;
    }
    return true;
}

static served_domain_t *
new_served_domain(interface_t *interface, char *domain)
{
    served_domain_t *sdt = calloc(1, sizeof *sdt);
    if (sdt == NULL) {
        ERROR("Unable to allocate served domain %s", domain);
        return NULL;
    }
    sdt->domain_ld = malloc(strlen(domain) + 2);
    if (sdt->domain_ld == NULL) {
        ERROR("Unable to allocate served domain name %s", domain);
        free(sdt);
        return NULL;
    }
    sdt->domain_ld[0] = '.';
    sdt->domain = sdt->domain_ld + 1;
    strcpy(sdt->domain, domain);
    sdt->domain_name = dns_pres_name_parse(sdt->domain);
    sdt->interface = interface;
    if (sdt->domain_name == NULL) {
        if (interface != NULL) {
            ERROR("invalid domain name for interface %s: %s", interface->name, sdt->domain);
        } else {
            ERROR("invalid domain name: %s", sdt->domain);
        }
        free(sdt);
        return NULL;
    }
    sdt->next = served_domains;
    served_domains = sdt;
    return sdt;
}

// Dynamic interface detection...
// This is called whenever a new interface address is encountered.  At present, this is only called
// once for each interface address, on startup, but in principle it _could_ be called whenever an
// interface is added or deleted, or is assigned or loses an address.
void
ifaddr_callback(void *context, const char *name, const addr_t *address, const addr_t *mask,
                int ifindex, enum interface_address_change event_type)
{
    served_domain_t *sd;

    if (address->sa.sa_family == AF_INET) {
        IPv4_ADDR_GEN_SRP((const uint8_t *)&address->sin.sin_addr, addr_buf);
        IPv4_ADDR_GEN_SRP((const uint8_t *)&mask->sin.sin_addr, mask_buf);
        INFO("Interface " PUB_S_SRP " address " PRI_IPv4_ADDR_SRP " mask " PRI_IPv4_ADDR_SRP " index %d " PUB_S_SRP,
             name, IPv4_ADDR_PARAM_SRP((const uint8_t *)&address->sin.sin_addr, addr_buf),
             IPv4_ADDR_PARAM_SRP((const uint8_t *)&mask->sin.sin_addr, mask_buf), ifindex,
             event_type == interface_address_added ? "added" : "removed");
    } else if (address->sa.sa_family == AF_INET6) {
        IPv6_ADDR_GEN_SRP((const uint8_t *)&address->sin.sin_addr, addr_buf);
        IPv6_ADDR_GEN_SRP((const uint8_t *)&mask->sin.sin_addr, mask_buf);
        INFO("Interface " PUB_S_SRP " address " PRI_IPv6_ADDR_SRP " mask " PRI_IPv6_ADDR_SRP " index %d " PUB_S_SRP,
             name, IPv6_ADDR_PARAM_SRP((const uint8_t *)&address->sin.sin_addr, addr_buf),
             IPv6_ADDR_PARAM_SRP((const uint8_t *)&mask->sin.sin_addr, mask_buf), ifindex,
             event_type == interface_address_added ? "added" : "removed");
    } else {
        INFO("Interface " PUB_S_SRP " address type %d index %d " PUB_S_SRP, name, address->sa.sa_family, ifindex,
             event_type == interface_address_added ? "added" : "removed");
    }

    for (sd = *((served_domain_t **)context); sd; sd = sd->next) {
        if (sd->interface != NULL && !strcmp(sd->interface->name, name)) {
            interface_addr_t **app, *ifaddr;
            if (event_type == interface_address_added) {
                for (app = &sd->interface->addresses; *app; app = &(*app)->next)
                    ;
                ifaddr = calloc(1, sizeof *ifaddr);
                sd->interface->ifindex = ifindex;
                if (ifaddr != NULL) {
                    ifaddr->addr = *address;
                    ifaddr->mask = *mask;
                    *app = ifaddr;
                }
            } else if (event_type == interface_address_deleted) {
                for (app = &sd->interface->addresses; *app; ) {
                    ifaddr = *app;
                    if (ifaddr->addr.sa.sa_family == address->sa.sa_family &&
                        ((address->sa.sa_family == AF_INET &&
                          ifaddr->addr.sin.sin_addr.s_addr == address->sin.sin_addr.s_addr &&
                          ifaddr->mask.sin.sin_addr.s_addr == address->sin.sin_addr.s_addr) ||
                         (address->sa.sa_family == AF_INET6 &&
                          !memcmp(&ifaddr->addr.sin6.sin6_addr, &address->sin6.sin6_addr, sizeof address->sin6.sin6_addr) &&
                          !memcmp(&ifaddr->mask.sin6.sin6_addr, &mask->sin6.sin6_addr, sizeof mask->sin6.sin6_addr))))
                    {
                        *app = ifaddr->next;
                        free(ifaddr);
                    } else {
                        app = &ifaddr->next;
                    }
                }
                if (sd->interface->addresses == NULL) {
                    sd->interface->ifindex = 0;
                }
            }
        }
    }
}

// Config file parsing...
static bool
interface_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    interface_t *interface = calloc(1, sizeof *interface);
    if (interface == NULL) {
        ERROR("Unable to allocate interface %s", hunks[1]);
        return false;
    }

    interface->name = strdup(hunks[1]);
    if (interface->name == NULL) {
        ERROR("Unable to allocate interface name %s", hunks[1]);
        free(interface);
        return false;
    }

    if (!strcmp(hunks[0], "nopush")) {
        interface->no_push = true;
    }

    if (new_served_domain(interface, hunks[2]) == NULL) {
        free(interface->name);
        free(interface);
        return false;
    }
    return true;
}

static bool port_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    char *ep = NULL;
    long port = strtol(hunks[1], &ep, 10);
    if (port < 0 || port > 65535 || *ep != 0) {
        ERROR("Invalid port number: %s", hunks[1]);
        return false;
    }
    if (!strcmp(hunks[0], "udp-port")) {
        udp_port = port;
    } else if (!strcmp(hunks[0], "tcp-port")) {
        tcp_port = port;
    } else if (!strcmp(hunks[0], "tls-port")) {
        tls_port = port;
    }
    return true;
}

static bool my_name_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&my_name, filename, hunks[1], lineno, true, false);
}

static bool listen_addr_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    if (num_listen_addrs == MAX_ADDRS) {
        ERROR("Only %d IPv4 listen addresses can be configured.", MAX_ADDRS);
        return false;
    }
    return config_string_handler(&listen_addrs[num_listen_addrs++], filename, hunks[1], lineno, false, false);
}

static bool publish_addr_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    if (num_publish_addrs == MAX_ADDRS) {
        ERROR("Only %d addresses can be published.", MAX_ADDRS);
        return false;
    }
    return config_string_handler(&publish_addrs[num_publish_addrs++], filename, hunks[1], lineno, false, false);
}

static bool tls_key_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&tls_key_filename, filename, hunks[1], lineno, false, false);
}

static bool tls_cert_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&tls_cert_filename, filename, hunks[1], lineno, false, false);
}

static bool tls_cacert_handler(void *context, const char *filename, char **hunks, int num_hunks, int lineno)
{
    return config_string_handler(&tls_cacert_filename, filename, hunks[1], lineno, false, false);
}

config_file_verb_t dp_verbs[] = {
    { "interface",    3, 3, interface_handler },    // interface <name> <domain>
    { "nopush",       3, 3, interface_handler },    // nopush <name> <domain>
    { "udp-port",     2, 2, port_handler },         // udp-port <number>
    { "tcp-port",     2, 2, port_handler },         // tcp-port <number>
    { "tls-port",     2, 2, port_handler },         // tls-port <number>
    { "my-name",      2, 2, my_name_handler },      // my-name <domain name>
    { "tls-key",      2, 2, tls_key_handler },      // tls-key <filename>
    { "tls-cert",     2, 2, tls_cert_handler },     // tls-cert <filename>
    { "tls-cacert",   2, 2, tls_cacert_handler },   // tls-cacert <filename>
    { "listen-addr",  2, 2, listen_addr_handler },  // listen-addr <IP address>
    { "publish-addr", 2, 2, publish_addr_handler }  // publish-addr <IP address>
};
#define NUMCFVERBS ((sizeof dp_verbs) / sizeof (config_file_verb_t))

void
dnssd_push_setup()
{
    listener[num_listeners] = ioloop_setup_listener(AF_INET, true, true, tls_port, NULL, NULL,
                                                    "IPv4 DNS Push Listener", dns_input, NULL, NULL, NULL, NULL, NULL);
    if (listener[num_listeners] == NULL) {
        ERROR("IPv4 DNS Push listener: fail.");
        return;
    }
    num_listeners++;

    listener[num_listeners] = ioloop_setup_listener(AF_INET6, true, true,
                                                    "IPv6 DNS Push Listener", dns_input, NULL, NULL, NULL, NULL, NULL);
    if (listener[num_listeners] == NULL) {
        ERROR("IPv6 DNS Push listener: fail.");
        return;
    }
    num_listeners++;

    dnssd_hardwired_push_setup();
}

// Start a key generation or cert signing program.   Arguments are key=value pairs.
// Arguments that can be constant should be <"key=value", NULL>.   Arguments that
// have a variable component should be <"key", value">.  References to arguments
// will be held, except that if the rhs of the pair is variable, memory is allocated
// to store the key=value pair, so the neither the key nor the value is retained.
// The callback is called when the program exits.

void
keyprogram_start(const char *program, subproc_callback_t callback, ...)
{
#define MAX_SUBPROC_VARS 3
    size_t lens[MAX_SUBPROC_VARS];
    char *vars[MAX_SUBPROC_VARS];
    int num_vars = 0;
    char *argv[MAX_SUBPROC_ARGS + 1];
    int argc = 0;
    va_list vl;
    int i;

    va_start(vl, callback);
    while (true) {
        char *vname, *value;
        char *arg;

        vname = va_arg(vl, char *);
        if (vname == NULL) {
            break;
        }
        value = va_arg(vl, char *);

        if (argc >= MAX_SUBPROC_ARGS) {
            ERROR("keyprogram_start: too many arguments.");
        }

        if (value == NULL) {
            arg = vname;
        } else {
            if (num_vars >= MAX_SUBPROC_VARS) {
                ERROR("Too many variable args: %s %s", vname, value);
                goto out;
            }
            lens[num_vars] = strlen(vname) + strlen(value) + 2;
            vars[num_vars] = malloc(lens[num_vars]);
            if (vars[num_vars] == NULL) {
                ERROR("No memory for variable key=value %s %s", vname, value);
                goto out;
            }
            snprintf(vars[num_vars], lens[num_vars], "%s=%s", vname, value);
            arg = vars[num_vars];
            num_vars++;
        }
        argv[argc++] = arg;
    }
    argv[argc] = NULL;
    ioloop_subproc(program, argv, argc, callback);
out:
    for (i = 0; i < num_vars; i++) {
        free(vars[i]);
    }
}

bool
finished_okay(const char *context, int status, const char *error)
{
    // If we get an error, something failed before the program had been successfully started.
    if (error != NULL) {
        ERROR("%s failed on startup: %s", context, error);
    }

    // The key file generation process completed
    else if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) != 0) {
            ERROR("%s program exited with status %d", context, status);
            // And that means we don't have DNS Push--sorry!
        } else {
            return true;
        }
    } else if (WIFSIGNALED(status)) {
        ERROR("%s program exited on signal %d", context, WTERMSIG(status));
        // And that means we don't have DNS Push--sorry!
    } else if (WIFSTOPPED(status)) {
        ERROR("%s program stopped on signal %d", context, WSTOPSIG(status));
        // And that means we don't have DNS Push--sorry!
    } else {
        ERROR("%s program exit status unknown: %d", context, status);
        // And that means we don't have DNS Push--sorry!
    }
    return false;
}

// Called after the cert has been generated.
void
certfile_finished_callback(subproc_t *subproc, int status, const char *error)
{
    // If we were able to generate a cert, we can start DNS Push service and start advertising it.
    if (finished_okay("Certificate signing", status, error)) {
        int i = num_listeners;

        dnssd_push_setup();

        for (; i < num_listeners; i++) {
            INFO("Started " PUB_S_SRP, listener[i]->name);
        }
    }
}

// Called after the key has been generated.
void
keyfile_finished_callback(subproc_t *subproc, int status, const char *error)
{
    if (finished_okay("Keyfile generation", status, error)) {
            INFO("Keyfile generation completed.");

            // XXX dates need to not be constant!!!
            keyprogram_start(CERTWRITE_PROGRAM, certfile_finished_callback,
                             "selfsign=1", NULL, "issuer_key", tls_key_filename, "issuer_name=CN", my_name,
                             "not_before=20190226000000", NULL, "not_after=20211231235959", NULL, "is_ca=1", NULL,
                             "max_pathlen=0", NULL, "output_file", tls_cert_filename, NULL);
    }

}

int
main(int argc, char **argv)
{
    int i;
    bool tls_fail = false;

    udp_port = tcp_port = 53;
    tls_port = 853;

    // Parse command line arguments
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tls-fail")) {
            tls_fail = true;
        } else {
            return usage(argv[0]);
        }
    }

    // Read the config file
    if (!config_parse(NULL, "/etc/dnssd-proxy.cf", dp_verbs, NUMCFVERBS)) {
        return 1;
    }

    // Insist that we have at least one address we're listening on.
    if (num_listen_addrs == 0 && num_publish_addrs == 0) {
        ERROR("Please configure at least one my-ipv4-addr and/or one my-ipv6-addr.");
        return 1;
    }

    ioloop_map_interface_addresses(&served_domains, ifaddr_callback);

    // Set up hardwired answers
    dnssd_hardwired_setup();

#ifndef EXCLUDE_TLS
    if (!srp_tls_init()) {
        return 1;
    }

    // The tls_fail flag allows us to run the proxy in such a way that TLS connections will fail.
    // This is never what you want in production, but is useful for testing.
    if (!tls_fail) {
        if (access(tls_key_filename, R_OK) < 0) {
            keyprogram_start(GENKEY_PROGRAM, keyfile_finished_callback,
                             "type=rsa", NULL, "rsa_keysize=4096", NULL, "filename", tls_key_filename, NULL);
        } else if (access(tls_cert_filename, R_OK) < 0) {
            keyfile_finished_callback(NULL, 0, NULL);
        } else if (srp_tls_server_init(NULL, tls_cert_filename, tls_key_filename)) {
            // If we've been able to set up TLS, then we can do DNS push.
            dnssd_push_setup();
        }
    }
#endif

    if (!ioloop_init()) {
        return 1;
    }

    for (i = 0; i < num_listen_addrs; i++) {
        listener[num_listeners] = ioloop_setup_listener(AF_UNSPEC, false, false, udp_port, listen_addrs[i], NULL,
                                                        "DNS UDP Listener", dns_input, NULL, NULL, NULL, NULL, NULL);
        if (listener[num_listeners] == NULL) {
            ERROR("UDP listener %s: fail.", listen_addrs[i]);
            return 1;
        }
        num_listeners++;
    }

    listener[num_listeners] = ioloop_setup_listener(AF_INET, true, false, tcp_port, NULL, NULL,
                                                    "IPv4 TCP DNS Listener", dns_input, NULL, NULL, NULL, NULL, NULL);
    if (listener[num_listeners] == NULL) {
        ERROR("TCPv4 listener: fail.");
        return 1;
    } else {
        num_listeners++;
    }

    listener[num_listeners] = ioloop_setup_listener(AF_INET6, true, false, tcp_port, NULL, NULL,
                                                    "IPv6 TCP DNS Listener", dns_input, NULL, NULL, NULL, NULL, NULL);
    if (listener[num_listeners] == NULL) {
        ERROR("TCPv6 listener: fail.");
        return 1;
    } else {
        num_listeners++;
    }

    // If we haven't been given any addresses to listen on, listen on an IPv4 address and an IPv6 address.
    if (num_listen_addrs == 0) {
        listener[num_listeners] = ioloop_setup_listener(AF_INET, IPPROTO_UDP, false, udp_port, NULL, NULL,
                                                        "IPv4 DNS UDP Listener", dns_input, NULL, NULL, NULL, NULL,
                                                        NULL);
        if (listener[num_listeners] == NULL) {
            ERROR("UDP4 listener: fail.");
            return 1;
        }
        num_listeners++;

        listener[num_listeners] = ioloop_setup_listener(AF_INET6, IPPROTO_UDP, false, udp_port, NULL, NULL,
                                                        "IPv6 DNS UDP Listener", dns_input, NULL, NULL, NULL, NULL,
                                                        NULL);
       if (listener[num_listeners] == NULL) {
            ERROR("UDP6 listener: fail.");
            return 1;
        }
        num_listeners++;
    }

    for (i = 0; i < num_listeners; i++) {
        INFO("Started " PUB_S_SRP, listener[i]->name);
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
