/* srp-parse.c
 *
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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
 * This file contains support routines for the DNSSD SRP update and mDNS proxies.
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
#include <inttypes.h>

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#include "dnssd-proxy.h"
#include "srp-gw.h"
#include "config-parse.h"
#include "srp-proxy.h"

static dns_name_t *service_update_zone; // The zone to update when we receive an update for default.service.arpa.

// Free the data structures into which the SRP update was parsed.   The pointers to the various DNS objects that these
// structures point to are owned by the parsed DNS message, and so these do not need to be freed here.
void
srp_update_free_parts(service_instance_t *service_instances, service_instance_t *added_instances,
                      service_t *services, delete_t *removes, dns_host_description_t *host_description)
{
    service_instance_t *sip;
    service_t *sp;
    delete_t *dp;

    for (sip = service_instances; sip; ) {
        service_instance_t *next = sip->next;
        free(sip);
        sip = next;
    }
    for (sip = added_instances; sip; ) {
        service_instance_t *next = sip->next;
        free(sip);
        sip = next;
    }
    for (sp = services; sp; ) {
        service_t *next = sp->next;
        free(sp);
        sp = next;
    }
    for (dp = removes; dp != NULL; ) {
        delete_t *next = dp->next;
        free(dp);
        dp = next;
    }
    if (host_description != NULL) {
        host_addr_t *host_addr, *next;
        for (host_addr = host_description->addrs; host_addr; host_addr = next) {
            next = host_addr->next;
            free(host_addr);
        }
        free(host_description);
    }
}

static bool
add_host_addr(host_addr_t **dest, dns_rr_t *rr)
{
    host_addr_t *addr = calloc(1, sizeof *addr);
    if (addr == NULL) {
        ERROR("add_host_addr: no memory for record");
        return false;
    }

    while (*dest) {
        dest = &(*dest)->next;
    }
    *dest = addr;
    addr->rr = *rr;
    return true;
}

static bool
replace_zone_name(dns_name_t **nzp_in, dns_name_t *uzp, dns_name_t *replacement_zone)
{
    dns_name_t **nzp = nzp_in;
    while (*nzp != NULL && *nzp != uzp) {
        nzp = &((*nzp)->next);
    }
    if (*nzp == NULL) {
        ERROR("replace_zone: dns_name_subdomain_of returned bogus pointer.");
        return false;
    }

    // Free the suffix we're replacing
    dns_name_free(*nzp);

    // Replace it.
    *nzp = dns_name_copy(replacement_zone);
    if (*nzp == NULL) {
        ERROR("replace_zone_name: no memory for replacement zone");
        return false;
    }
    return true;
}

// We call advertise_finished when a client request has finished, successfully or otherwise.
static void
send_fail_response(comm_t *connection, message_t *message, int rcode)
{
    struct iovec iov;
    dns_wire_t response;

    memset(&response, 0, DNS_HEADER_SIZE);
    response.id = message->wire.id;
    response.bitfield = message->wire.bitfield;
    dns_rcode_set(&response, rcode);
    dns_qr_set(&response, dns_qr_response);

    iov.iov_base = &response;
    iov.iov_len = DNS_HEADER_SIZE;

    ioloop_send_message(connection, message, &iov, 1);
}

static int
make_delete(delete_t **delete_list, delete_t **delete_out, dns_rr_t *rr, dns_name_t *update_zone)
{
    int status = dns_rcode_noerror;
    delete_t *dp, **dpp;

    for (dpp = delete_list; *dpp;) {
        dp = *dpp;
        if (dns_names_equal(dp->name, rr->name)) {
            DNS_NAME_GEN_SRP(rr->name, name_buf);
            ERROR("two deletes for the same name: " PRI_DNS_NAME_SRP,
                  DNS_NAME_PARAM_SRP(rr->name, name_buf));
            return dns_rcode_formerr;
        }
        dpp = &dp->next;
    }
    dp = calloc(1, sizeof *dp);
    if (!dp) {
        ERROR("no memory.");
        return dns_rcode_servfail;
    }
    // Add to the deletes list
    *dpp = dp;

    // Make sure the name is a subdomain of the zone being updated.
    dp->zone = dns_name_subdomain_of(rr->name, update_zone);
    if (dp->zone == NULL) {
        DNS_NAME_GEN_SRP(update_zone, update_zone_buf);
        DNS_NAME_GEN_SRP(rr->name, name_buf);
        ERROR("delete for record not in update zone " PRI_DNS_NAME_SRP ": " PRI_DNS_NAME_SRP,
              DNS_NAME_PARAM_SRP(update_zone, update_zone_buf), DNS_NAME_PARAM_SRP(rr->name, name_buf));
        status = dns_rcode_formerr;
        goto out;
    }
    dp->name = rr->name;
    if (delete_out != NULL) {
        *delete_out = dp;
    }
out:
    if (status != dns_rcode_noerror) {
        free(dp);
    }
    return status;
}

// Find a delete in the delete list that has target as its target.
static delete_t *
srp_find_delete(delete_t *deletes, dns_rr_t *target)
{
    for (delete_t *dp = deletes; dp; dp = dp->next) {
        if (dns_names_equal(dp->name, target->name)) {
            return dp;
        }
    }
    return NULL;
}

bool
srp_evaluate(comm_t *connection, void *context, dns_message_t *message, message_t *raw_message)
{
    unsigned i;
    dns_host_description_t *host_description = NULL;
    delete_t *deletes = NULL, *dp, **dpp = NULL, **rpp = NULL, *removes = NULL;
    service_instance_t *service_instances = NULL, *sip, **sipp = &service_instances;
    service_t *services = NULL, *sp, **spp = &services;
    dns_rr_t *signature;
    bool ret = false;
    struct timeval now;
    dns_name_t *update_zone, *replacement_zone;
    dns_name_t *uzp;
    dns_rr_t *key = NULL;
    dns_rr_t **keys = NULL;
    unsigned num_keys = 0;
    unsigned max_keys = 1;
    bool found_key = false;
    uint32_t lease_time, key_lease_time, serial_number;
    dns_edns0_t *edns0;
    int rcode = dns_rcode_servfail;
    bool found_lease = false;
    bool found_serial = false;
    char namebuf1[DNS_MAX_NAME_SIZE], namebuf2[DNS_MAX_NAME_SIZE];

    // Update requires a single SOA record as the question
    if (message->qdcount != 1) {
        ERROR("update received with qdcount > 1");
        return false;
    }

    // Update should contain zero answers.
    if (message->ancount != 0) {
        ERROR("update received with ancount > 0");
        return false;
    }

    if (message->questions[0].type != dns_rrtype_soa) {
        ERROR("update received with rrtype %d instead of SOA in question section.",
              message->questions[0].type);
        return false;
    }

    update_zone = message->questions[0].name;
    if (service_update_zone != NULL && dns_names_equal_text(update_zone, "default.service.arpa.")) {
        INFO(PRI_S_SRP " is in default.service.arpa, using replacement zone: " PUB_S_SRP,
             dns_name_print(update_zone, namebuf2, sizeof(namebuf2)),
             dns_name_print(service_update_zone, namebuf1, sizeof(namebuf1)));
        replacement_zone = service_update_zone;
    } else {
        INFO(PRI_S_SRP " is not in default.service.arpa, or no replacement zone (%p)",
             dns_name_print(update_zone, namebuf2, sizeof(namebuf2)), service_update_zone);
        replacement_zone = NULL;
    }

    // Scan over the authority RRs; do the delete consistency check.  We can't do other consistency checks
    // because we can't assume a particular order to the records other than that deletes have to come before
    // adds.
    for (i = 0; i < message->nscount; i++) {
        dns_rr_t *rr = &message->authority[i];

        // If this is a delete for all the RRs on a name, record it in the list of deletes.
        if (rr->type == dns_rrtype_any && rr->qclass == dns_qclass_any && rr->ttl == 0) {
            int status = make_delete(&deletes, NULL, rr, update_zone);
            if (status != dns_rcode_noerror) {
                rcode = status;
                goto out;
            }
        }

        // The update should really only contain one key, but it's allowed for keys to appear on
        // service instance names as well, since that's what will be stored in the zone.   So if
        // we get one key, we'll assume it's a host key until we're done scanning, and then check.
        // If we get more than one, we allocate a buffer and store all the keys so that we can
        // check them all later.
        else if (rr->type == dns_rrtype_key) {
            if (num_keys < 1) {
                key = rr;
                num_keys++;
            } else {
                if (num_keys == 1) {
                    // We can't have more keys than there are authority records left, plus
                    // one for the key we already have, so allocate a buffer that large.
                    max_keys = message->nscount - i + 1;
                    keys = calloc(max_keys, sizeof *keys);
                    if (keys == NULL) {
                        ERROR("no memory");
                        goto out;
                    }
                    keys[0] = key;
                }
                if (num_keys >= max_keys) {
                    ERROR("coding error in key allocation");
                    goto out;
                }
                keys[num_keys++] = rr;
            }
        }

        // Otherwise if it's an A or AAAA record, it's part of a hostname entry.
        else if (rr->type == dns_rrtype_a || rr->type == dns_rrtype_aaaa) {
            // Allocate the hostname record
            if (!host_description) {
                host_description = calloc(1, sizeof *host_description);
                if (!host_description) {
                    ERROR("no memory");
                    goto out;
                }
            }

            // Make sure it's preceded by a deletion of all the RRs on the name.
            if (!host_description->delete) {
                dp = srp_find_delete(deletes, rr);
                if (dp == NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("ADD for hostname " PRI_DNS_NAME_SRP " without a preceding delete.",
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                host_description->delete = dp;
                host_description->name = dp->name;
                dp->consumed = true; // This delete is accounted for.

                // In principle, we should be checking this name to see that it's a subdomain of the update
                // zone.  However, it turns out we don't need to, because the /delete/ has to be a subdomain
                // of the update zone, and we won't find that delete if it's not present.
            }

            if (rr->type == dns_rrtype_a || rr->type == dns_rrtype_aaaa) {
                if (!add_host_addr(&host_description->addrs, rr)) {
                    goto out;
                }
            }
        }

        // Otherwise if it's an SRV entry, that should be a service instance name.
        else if (rr->type == dns_rrtype_srv || rr->type == dns_rrtype_txt) {
            // Should be a delete that precedes this service instance.
            dp = srp_find_delete(deletes, rr);
            if (dp == NULL) {
                DNS_NAME_GEN_SRP(rr->name, name_buf);
                ERROR("ADD for service instance not preceded by delete: " PRI_DNS_NAME_SRP,
                      DNS_NAME_PARAM_SRP(rr->name, name_buf));
                rcode = dns_rcode_formerr;
                goto out;
            }
            for (sip = service_instances; sip; sip = sip->next) {
                if (dns_names_equal(sip->name, rr->name)) {
                    break;
                }
            }
            if (!sip) {
                sip = calloc(1, sizeof *sip);
                if (sip == NULL) {
                    ERROR("no memory");
                    goto out;
                }
                sip->delete = dp;
                dp->consumed = true;
                sip->name = dp->name;
                // Add to the service instances list
                *sipp = sip;
                sipp = &sip->next;
            }
            if (rr->type == dns_rrtype_srv) {
                if (sip->srv != NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("more than one SRV rr received for service instance: " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                sip->srv = rr;
            } else if (rr->type == dns_rrtype_txt) {
                if (sip->txt != NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("more than one TXT rr received for service instance: " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                sip->txt = rr;
            }
        }

        // Otherwise if it's a PTR entry, that should be a service name
        else if (rr->type == dns_rrtype_ptr) {
            service_t *base_type = NULL;

            // See if the service is a subtype. If it is, it should be preceded in the list of RRs in
            // the update by a PTR record for the base service type. E.g., if there is a PTR for
            // _foo._sub._ipps._tcp.default.service.arpa, there should, earlier in the SRP update,
            // be a PTR for _ipps._tcp.default.service.arpa. Both the base type and the subtype PTR
            // records must have the same target.
            if (rr->name != NULL &&
                rr->name->next != NULL && rr->name->next->next != NULL && !strcmp(rr->name->next->data, "_sub"))
            {
                dns_name_t *base_type_name = rr->name->next->next;
                for (base_type = services; base_type != NULL; base_type = base_type->next) {
                    if (dns_names_equal(base_type->rr->name, base_type_name)) {
                        break;
                    }
                }
                if (base_type == NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    DNS_NAME_GEN_SRP(rr->data.ptr.name, target_name_buf);
                    ERROR("service subtype " PRI_DNS_NAME_SRP " for " PRI_DNS_NAME_SRP
                          " has no preceding base type ", DNS_NAME_PARAM_SRP(rr->name, name_buf),
                          DNS_NAME_PARAM_SRP(rr->data.ptr.name, target_name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                if (!dns_names_equal(base_type->rr->data.ptr.name, rr->data.ptr.name)) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    DNS_NAME_GEN_SRP(rr->data.ptr.name, target_name_buf);
                    DNS_NAME_GEN_SRP(base_type->rr->data.ptr.name, base_target_name_buf);
                    ERROR("service subtype " PRI_DNS_NAME_SRP " for " PRI_DNS_NAME_SRP
                          " doesn't match base type service " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf),
                          DNS_NAME_PARAM_SRP(rr->data.ptr.name, target_name_buf),
                          DNS_NAME_PARAM_SRP(base_type->rr->data.ptr.name, base_target_name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
            }

            // If qclass is none and ttl is zero, this is a delete specific RR from RRset, not an add RR to RRset.
            if (rr->qclass == dns_qclass_none && rr->ttl == 0) {
                int status = make_delete(&deletes, &dp, rr, update_zone);
                if (status != dns_rcode_noerror) {
                    rcode = status;
                    goto out;
                }
            } else {
                sp = calloc(1, sizeof *sp);
                if (sp == NULL) {
                    ERROR("no memory");
                    goto out;
                }

                // Add to the services list
                *spp = sp;
                spp = &sp->next;
                sp->rr = rr;
                if (base_type != NULL) {
                    sp->base_type = base_type;
                } else {
                    sp->base_type = sp;
                }

                // Make sure the service name is in the update zone.
                sp->zone = dns_name_subdomain_of(sp->rr->name, update_zone);
                if (sp->zone == NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    DNS_NAME_GEN_SRP(rr->data.ptr.name, data_name_buf);
                    ERROR("service name " PRI_DNS_NAME_SRP " for " PRI_DNS_NAME_SRP
                          " is not in the update zone", DNS_NAME_PARAM_SRP(rr->name, name_buf),
                          DNS_NAME_PARAM_SRP(rr->data.ptr.name, data_name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
            }
        }

        // Otherwise it's not a valid update
        else {
            DNS_NAME_GEN_SRP(rr->name, name_buf);
            ERROR("unexpected rrtype %d on " PRI_DNS_NAME_SRP " in update.", rr->type,
                  DNS_NAME_PARAM_SRP(rr->name, name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }

    // Now that we've scanned the whole update, do the consistency checks for updates that might
    // not have come in order.

    // Get the lease time. We need this to differentiate between a mass host deletion and an add.
    lease_time = 3600;
    key_lease_time = 604800;
    serial_number = 0;
    for (edns0 = message->edns0; edns0; edns0 = edns0->next) {
        if (edns0->type == dns_opt_update_lease) {
            unsigned off = 0;
            if (edns0->length != 4 && edns0->length != 8) {
                ERROR("edns0 update-lease option length bogus: %d", edns0->length);
                rcode = dns_rcode_formerr;
                goto out;
            }
            dns_u32_parse(edns0->data, edns0->length, &off, &lease_time);
            if (edns0->length == 8) {
                dns_u32_parse(edns0->data, edns0->length, &off, &key_lease_time);
            } else {
                key_lease_time = 7 * lease_time;
            }
            found_lease = true;
        } else if (edns0->type == dns_opt_srp_serial) {
            unsigned off = 0;
            if (edns0->length != 4) {
                ERROR("edns0 srp serial number length bogus: %d", edns0->length);
                rcode = dns_rcode_formerr;
                goto out;
            }
            dns_u32_parse(edns0->data, edns0->length, &off, &serial_number);
            found_serial = true;
        }
    }

    // If we don't yet have a host description, but this is a delete of the entire host registration (lease_time == 0) and
    // we do have a delete record and a key record for the host, create a host description with no addresses here.
    if (host_description == NULL && lease_time == 0) {
        // If we get here and we have a key, then that suggests that this SRP update is a host remove with a KEY RR to
        // authenticate it (and possibly leave behind).
        if (key != NULL) {
            dp = srp_find_delete(deletes, key);
            if (dp != NULL) {
                host_description = calloc(1, sizeof *host_description);
                if (host_description == NULL) {
                    ERROR("no memory");
                    goto out;
                }
                host_description->delete = dp;
                host_description->name = dp->name;
                dp->consumed = true; // This delete is accounted for.
            }
        }
    }
    // Make sure there's a host description.
    if (!host_description) {
        ERROR("SRP update does not include a host description.");
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure that each service add references a service instance that's in the same update.
    for (sp = services; sp; sp = sp->next) {
        // A service instance can never point to a service subtype--it has to point to the base type.
        if (sp->base_type != sp) {
            continue;
        }
        for (sip = service_instances; sip; sip = sip->next) {
            if (dns_names_equal(sip->name, sp->rr->data.ptr.name)) {
                // Note that we have already verified that there is only one service instance
                // with this name, so this could only ever happen once in this loop even without
                // the break statement.
                sip->service = sp;
                sip->num_instances++;
                break;
            }
        }
        // If this service doesn't point to a service instance that's in the update, then the
        // update fails validation.
        if (sip == NULL) {
            DNS_NAME_GEN_SRP(sp->rr->name, name_buf);
            ERROR("service points to an instance that's not included: " PRI_DNS_NAME_SRP,
                  DNS_NAME_PARAM_SRP(sp->rr->name, name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }

    for (sip = service_instances; sip; sip = sip->next) {
        // For each service instance, make sure that at least one service references it
        if (sip->num_instances == 0) {
            DNS_NAME_GEN_SRP(sip->name, name_buf);
            ERROR("service instance update for " PRI_DNS_NAME_SRP
                  " is not referenced by a service update.", DNS_NAME_PARAM_SRP(sip->name, name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }

        // For each service instance, make sure that it references the host description
        if (dns_names_equal(host_description->name, sip->srv->data.srv.name)) {
            sip->host = host_description;
            host_description->num_instances++;
        }
    }

    // Make sure that at least one service instance references the host description, unless the update is deleting the host address records.
    if (host_description->num_instances == 0 && host_description->addrs != NULL) {
        DNS_NAME_GEN_SRP(host_description->name, name_buf);
        ERROR("host description " PRI_DNS_NAME_SRP " is not referenced by any service instances.",
              DNS_NAME_PARAM_SRP(host_description->name, name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure the host description has at least one address record, unless we're deleting the host.
    if (host_description->addrs == NULL && host_description->num_instances != 0 && lease_time != 0) {
        DNS_NAME_GEN_SRP(host_description->name, name_buf);
        ERROR("host description " PRI_DNS_NAME_SRP " doesn't contain any IP addresses, but services are being added.",
              DNS_NAME_PARAM_SRP(host_description->name, name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    for (i = 0; i < num_keys; i++) {
        // If this isn't the only key, make sure it's got the same contents as the other keys.
        if (i > 0) {
            if (!dns_keys_rdata_equal(key, keys[i])) {
                ERROR("more than one key presented");
                rcode = dns_rcode_formerr;
                goto out;
            }
            // This is a hack so that if num_keys == 1, we don't have to allocate keys[].
            // At the bottom of this if statement, key is always the key we are looking at.
            key = keys[i];
        }
        // If there is a key, and the host description doesn't currently have a key, check
        // there first since that's the default.
        if (host_description->key == NULL && dns_names_equal(key->name, host_description->name)) {
            host_description->key = key;
            found_key = true;
        } else {
            for (sip = service_instances; sip != NULL; sip = sip->next) {
                if (dns_names_equal(sip->name, key->name)) {
                    found_key = true;
                    break;
                }
            }
        }
        if (!found_key) {
            DNS_NAME_GEN_SRP(key->name, key_name_buf);
            ERROR("key present for name " PRI_DNS_NAME_SRP
                  " which is neither a host nor an instance name.", DNS_NAME_PARAM_SRP(key->name, key_name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }
    if (keys != NULL) {
        free(keys);
        keys = NULL;
    }

    // And make sure it has a key record
    if (host_description->key == NULL) {
        DNS_NAME_GEN_SRP(host_description->name, host_name_buf);
        ERROR("host description " PRI_DNS_NAME_SRP " doesn't contain a key.",
              DNS_NAME_PARAM_SRP(host_description->name, host_name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Find any deletes that weren't consumed. These will be presumed to be removes of service instances previously
    // registered. These can't be validated here--we have to actually go look at the database.
    dpp = &deletes;
    rpp = &removes;
    while (*dpp) {
        dp = *dpp;
        if (!dp->consumed) {
            DNS_NAME_GEN_SRP(dp->name, delete_name_buf);
            INFO("delete for presumably previously-registered instance which is being withdrawn: " PRI_DNS_NAME_SRP,
                  DNS_NAME_PARAM_SRP(dp->name, delete_name_buf));
            *rpp = dp;
            rpp = &dp->next;
            *dpp = dp->next;
            dp->next = NULL;
        } else {
            dpp = &dp->next;
        }
    }

    // The signature should be the last thing in the additional section.   Even if the signature
    // is valid, if it's not at the end we reject it.   Note that we are just checking for SIG(0)
    // so if we don't find what we're looking for, we forward it to the DNS auth server which
    // will either accept or reject it.
    if (message->arcount < 1) {
        ERROR("signature not present");
        rcode = dns_rcode_formerr;
        goto out;
    }
    signature = &message->additional[message->arcount -1];
    if (signature->type != dns_rrtype_sig) {
        ERROR("signature is not at the end or is not present");
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure that the signer name is the hostname.   If it's not, it could be a legitimate
    // update with a different key, but it's not an SRP update, so we pass it on.
    if (!dns_names_equal(signature->data.sig.signer, host_description->name)) {
        DNS_NAME_GEN_SRP(signature->data.sig.signer, signer_name_buf);
        DNS_NAME_GEN_SRP(host_description->name, host_name_buf);
        ERROR("signer " PRI_DNS_NAME_SRP " doesn't match host " PRI_DNS_NAME_SRP,
              DNS_NAME_PARAM_SRP(signature->data.sig.signer, signer_name_buf),
              DNS_NAME_PARAM_SRP(host_description->name, host_name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure we're in the time limit for the signature.   Zeroes for the inception and expiry times
    // mean the host that send this doesn't have a working clock.   One being zero and the other not isn't
    // valid unless it's 1970.
    if (signature->data.sig.inception != 0 || signature->data.sig.expiry != 0) {
        if (raw_message->received_time != 0) {
            now.tv_sec = raw_message->received_time;
            now.tv_usec = 0;
        } else {
            gettimeofday(&now, NULL);
        }
        // The sender does the bracketing, so we can just do a simple comparison.
        if ((uint32_t)(now.tv_sec & UINT32_MAX) > signature->data.sig.expiry ||
            (uint32_t)(now.tv_sec & UINT32_MAX) < signature->data.sig.inception) {
            ERROR("signature is not timely: %lu < %lu < %lu does not hold",
                  (unsigned long)signature->data.sig.inception, (unsigned long)now.tv_sec,
                  (unsigned long)signature->data.sig.expiry);
            goto badsig;
        }
    }

    // Now that we have the key, we can validate the signature.   If the signature doesn't validate,
    // there is no need to pass the message on.
    if (!srp_sig0_verify(&raw_message->wire, host_description->key, signature)) {
        ERROR("signature is not valid");
        goto badsig;
    }

    // Now that we have validated the SRP message, go through and fix up all instances of
    // *default.service.arpa to use the replacement zone, if this update is for
    // default.services.arpa and there is a replacement zone.
    if (replacement_zone != NULL) {
        // All of the service instances and the host use the name from the delete, so if
        // we update these, the names for those are taken care of.   We already found the
        // zone for which the delete is a subdomain, so we can just replace it without
        // finding it again.
        for (dp = deletes; dp; dp = dp->next) {
            replace_zone_name(&dp->name, dp->zone, replacement_zone);
        }

        // All services have PTR records, which point to names.   Both the service name and the
        // PTR name have to be fixed up.
        for (sp = services; sp; sp = sp->next) {
            replace_zone_name(&sp->rr->name, sp->zone, replacement_zone);
            uzp = dns_name_subdomain_of(sp->rr->data.ptr.name, update_zone);
            // We already validated that the PTR record points to something in the zone, so this
            // if condition should always be false.
            if (uzp == NULL) {
                ERROR("service PTR record zone match fail!!");
                goto out;
            }
            replace_zone_name(&sp->rr->data.ptr.name, uzp, replacement_zone);
        }

        // All service instances have SRV records, which point to names.  The service instance
        // name is already fixed up, because it's the same as the delete, but the name in the
        // SRV record must also be fixed.
        for (sip = service_instances; sip; sip = sip->next) {
            uzp = dns_name_subdomain_of(sip->srv->data.srv.name, update_zone);
            // We already validated that the SRV record points to something in the zone, so this
            // if condition should always be false.
            if (uzp == NULL) {
                ERROR("service instance SRV record zone match fail!!");
                goto out;
            }
            replace_zone_name(&sip->srv->data.srv.name, uzp, replacement_zone);
        }

        // We shouldn't need to replace the hostname zone because it's actually pointing to
        // the name of a delete.
    }

    // Start the update.
    DNS_NAME_GEN_SRP(host_description->name, host_description_name_buf);
    INFO("update for " PRI_DNS_NAME_SRP " xid %x validates, lease time %d%s, serial %" PRIu32 "%s.",
         DNS_NAME_PARAM_SRP(host_description->name, host_description_name_buf), raw_message->wire.id,
         lease_time, found_lease ? " (found)" : "", serial_number, found_serial ? " (found)" : " (not sent)");
    rcode = dns_rcode_noerror;
    ret = srp_update_start(connection, context, message, raw_message, host_description, service_instances,
                           services, removes, replacement_zone == NULL ? update_zone : replacement_zone,
                           lease_time, key_lease_time, serial_number, found_serial);
    if (ret) {
        goto success;
    }
    ERROR("update start failed");
    goto out;

badsig:
    // True means it was intended for us, and shouldn't be forwarded.
    ret = true;
    // We're not actually going to return this; it simply indicates that we aren't sending a fail response.
    rcode = dns_rcode_noerror;
    // Because we're saying this is ours, we have to free the parsed message.
    dns_message_free(message);

out:
    // free everything we allocated but (it turns out) aren't going to use
    if (keys != NULL) {
        free(keys);
    }
    srp_update_free_parts(service_instances, NULL, services, removes, host_description);

success:
    // No matter how we get out of this, we free the delete structures that weren't dangling removes,
    // because they are not used to do the update.
    for (dp = deletes; dp; ) {
        delete_t *next = dp->next;
        free(dp);
        dp = next;
    }

    if (ret == true && rcode != dns_rcode_noerror) {
        if (connection != NULL) {
            send_fail_response(connection, raw_message, rcode);
        }
    }
    return ret;
}

bool
srp_dns_evaluate(comm_t *connection, void *context, message_t *message)
{
    dns_message_t *parsed_message;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&message->wire) == dns_qr_response) {
        ERROR("dns_evaluate: received a message that was a DNS response: %d", dns_opcode_get(&message->wire));
        return false;
    }

    // Forward incoming messages that are queries but not updates.
    // XXX do this later--for now we operate only as a translator, not a proxy.
    if (dns_opcode_get(&message->wire) != dns_opcode_update) {
        if (connection != NULL) {
            send_fail_response(connection, message, dns_rcode_refused);
        }
        ERROR("dns_evaluate: received a message that was not a DNS update: %d", dns_opcode_get(&message->wire));
        return false;
    }

    // Parse the UPDATE message.
    if (!dns_wire_parse(&parsed_message, &message->wire, message->length)) {
        if (connection != NULL) {
            send_fail_response(connection, message, dns_rcode_servfail);
        }
        ERROR("dns_wire_parse failed.");
        return false;
    }

    // We need the wire message to validate the signature...
    if (!srp_evaluate(connection, context, parsed_message, message)) {
        // The message wasn't invalid, but wasn't an SRP message.
        dns_message_free(parsed_message);
        // dns_forward(connection)
        if (connection != NULL) {
            send_fail_response(connection, message, dns_rcode_refused);
        }
        return false;
    }
    return true;
}

void
dns_input(comm_t *comm, message_t *message, void *context)
{
    (void)context;
    srp_dns_evaluate(comm, NULL, message);
}

struct srp_proxy_listener_state {
    comm_t *NULLABLE tcp_listener;
    comm_t *NULLABLE tls_listener;
    comm_t *NULLABLE udp_listener;
};

void
srp_proxy_listener_cancel(srp_proxy_listener_state_t *listener_state)
{
    if (listener_state->tcp_listener != NULL) {
        ioloop_listener_cancel(listener_state->tcp_listener);
        ioloop_listener_release(listener_state->tcp_listener);
    }
    if (listener_state->tls_listener != NULL) {
        ioloop_listener_cancel(listener_state->tls_listener);
        ioloop_listener_release(listener_state->tls_listener);
    }
    if (listener_state->udp_listener != NULL) {
        ioloop_listener_cancel(listener_state->udp_listener);
        ioloop_listener_release(listener_state->udp_listener);
    }
    free(listener_state);
}

srp_proxy_listener_state_t *
srp_proxy_listen(uint16_t *avoid_ports, int num_avoid_ports, ready_callback_t ready)
{
#if SRP_STREAM_LISTENER_ENABLED
    uint16_t tcp_listen_port;
#ifndef EXCLUDE_TLS
    uint16_t tls_listen_port;
#endif
#endif
    srp_proxy_listener_state_t *listeners = calloc(1, sizeof *listeners);
    if (listeners == NULL) {
        ERROR("srp_proxy_listen: no memory for listeners structure.");
        return NULL;
    }
    (void)avoid_ports;
    (void)num_avoid_ports;

#if SRP_STREAM_LISTENER_ENABLED
    tcp_listen_port = 53;
    tls_listen_port = 853;
#endif

    // Set up listeners
    // XXX UDP listeners should bind to interface addresses, not INADDR_ANY.
    listeners->udp_listener = ioloop_listener_create(false, false, avoid_ports,
                                                     num_avoid_ports, NULL, NULL, "UDP listener", dns_input,
                                                     NULL, NULL, ready, NULL, NULL, NULL);
    if (listeners->udp_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("UDP listener: fail.");
        return 0;
    }
#ifdef SRP_STREAM_LISTENER_ENABLED
    listeners->tcp_listener = ioloop_listener_create(true, false, NULL, 0, NULL, NULL,
                                                     "TCP listener", dns_input, NULL, NULL, ready, NULL, NULL, NULL);
    if (listeners->tcp_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("TCP listener: fail.");
        return 0;
    }
#ifndef EXCLUDE_TLS
    listeners->tls_listener = ioloop_listener_create(true, true, NULL, 0, NULL, NULL,
                                                     "TLS listener", dns_input, NULL, NULL, ready, NULL, NULL. NULL);
    if (listeners->tls_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("TLS listener: fail.");
        return 0;
    }
#endif
#endif

    return listeners;
}

void
srp_proxy_init(const char *update_zone)
{
    // For now, hardcoded, should be configurable
    if (service_update_zone != NULL) {
        dns_name_free(service_update_zone);
    }
    service_update_zone = dns_pres_name_parse(update_zone);

}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
