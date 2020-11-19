/* srp-parse.c
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
                      service_t *services, dns_host_description_t *host_description)
{
    service_instance_t *sip;
    service_t *sp;

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

bool
srp_evaluate(comm_t *connection, dns_message_t *message, message_t *raw_message)
{
    int i;
    dns_host_description_t *host_description = NULL;
    delete_t *deletes = NULL, *dp, **dpp = &deletes;
    service_instance_t *service_instances = NULL, *sip, **sipp = &service_instances;
    service_t *services = NULL, *sp, **spp = &services;
    dns_rr_t *signature;
    bool ret = false;
    struct timeval now;
    dns_name_t *update_zone, *replacement_zone;
    dns_name_t *uzp;
    dns_rr_t *key = NULL;
    dns_rr_t **keys = NULL;
    int num_keys = 0;
    int max_keys = 1;
    bool found_key = false;
    uint32_t lease_time, key_lease_time;
    dns_edns0_t *edns0;
    int rcode = dns_rcode_servfail;
    bool found_lease = false;

    // Update requires a single SOA record as the question
    if (message->qdcount != 1) {
        ERROR("srp_evaluate: update received with qdcount > 1");
        return false;
    }

    // Update should contain zero answers.
    if (message->ancount != 0) {
        ERROR("srp_evaluate: update received with ancount > 0");
        return false;
    }

    if (message->questions[0].type != dns_rrtype_soa) {
        ERROR("srp_evaluate: update received with rrtype %d instead of SOA in question section.",
              message->questions[0].type);
        return false;
    }

    update_zone = message->questions[0].name;
    if (service_update_zone != NULL && dns_names_equal_text(update_zone, "default.service.arpa.")) {
        replacement_zone = service_update_zone;
    } else {
        replacement_zone = NULL;
    }

    // Scan over the authority RRs; do the delete consistency check.  We can't do other consistency checks
    // because we can't assume a particular order to the records other than that deletes have to come before
    // adds.
    for (i = 0; i < message->nscount; i++) {
        dns_rr_t *rr = &message->authority[i];

        // If this is a delete for all the RRs on a name, record it in the list of deletes.
        if (rr->type == dns_rrtype_any && rr->qclass == dns_qclass_any && rr->ttl == 0) {
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("srp_evaluate: two deletes for the same name: " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
            }
            dp = calloc(1, sizeof *dp);
            if (!dp) {
                ERROR("srp_evaluate: no memory.");
                goto out;
            }
            *dpp = dp;
            dpp = &dp->next;

            // Make sure the name is a subdomain of the zone being updated.
            dp->zone = dns_name_subdomain_of(rr->name, update_zone);
            if (dp->zone == NULL) {
                DNS_NAME_GEN_SRP(update_zone, update_zone_buf);
                DNS_NAME_GEN_SRP(rr->name, name_buf);
                ERROR("srp_evaluate: delete for record not in update zone " PRI_DNS_NAME_SRP ": " PRI_DNS_NAME_SRP,
                      DNS_NAME_PARAM_SRP(update_zone, update_zone_buf), DNS_NAME_PARAM_SRP(rr->name, name_buf));
                rcode = dns_rcode_formerr;
                goto out;
            }
            dp->name = rr->name;
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
                        ERROR("srp_evaluate: no memory");
                        goto out;
                    }
                    keys[0] = key;
                }
                if (num_keys >= max_keys) {
                    ERROR("srp_evaluate: coding error in key allocation");
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
                    ERROR("srp_evaluate: no memory");
                    goto out;
                }
            }

            // Make sure it's preceded by a deletion of all the RRs on the name.
            if (!host_description->delete) {
                for (dp = deletes; dp; dp = dp->next) {
                    if (dns_names_equal(dp->name, rr->name)) {
                        break;
                    }
                }
                if (dp == NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("srp_evaluate: ADD for hostname " PRI_DNS_NAME_SRP " without a preceding delete.",
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
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    break;
                }
            }
            if (dp == NULL) {
                DNS_NAME_GEN_SRP(rr->name, name_buf);
                ERROR("srp_evaluate: ADD for service instance not preceded by delete: " PRI_DNS_NAME_SRP,
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
                    ERROR("srp_evaluate: no memory");
                    goto out;
                }
                sip->delete = dp;
                dp->consumed = true;
                sip->name = dp->name;
                *sipp = sip;
                sipp = &sip->next;
            }
            if (rr->type == dns_rrtype_srv) {
                if (sip->srv != NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("srp_evaluate: more than one SRV rr received for service instance: " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                sip->srv = rr;
            } else if (rr->type == dns_rrtype_txt) {
                if (sip->txt != NULL) {
                    DNS_NAME_GEN_SRP(rr->name, name_buf);
                    ERROR("srp_evaluate: more than one TXT rr received for service instance: " PRI_DNS_NAME_SRP,
                          DNS_NAME_PARAM_SRP(rr->name, name_buf));
                    rcode = dns_rcode_formerr;
                    goto out;
                }
                sip->txt = rr;
            }
        }

        // Otherwise if it's a PTR entry, that should be a service name
        else if (rr->type == dns_rrtype_ptr) {
            sp = calloc(1, sizeof *sp);
            if (sp == NULL) {
                ERROR("srp_evaluate: no memory");
                goto out;
            }
            *spp = sp;
            spp = &sp->next;
            sp->rr = rr;

            // Make sure the service name is in the update zone.
            sp->zone = dns_name_subdomain_of(sp->rr->name, update_zone);
            if (sp->zone == NULL) {
                DNS_NAME_GEN_SRP(rr->name, name_buf);
                DNS_NAME_GEN_SRP(rr->data.ptr.name, data_name_buf);
                ERROR("srp_evaluate: service name " PRI_DNS_NAME_SRP " for " PRI_DNS_NAME_SRP
                      " is not in the update zone", DNS_NAME_PARAM_SRP(rr->name, name_buf),
                      DNS_NAME_PARAM_SRP(rr->data.ptr.name, data_name_buf));
                rcode = dns_rcode_formerr;
                goto out;
            }
        }

        // Otherwise it's not a valid update
        else {
            DNS_NAME_GEN_SRP(rr->name, name_buf);
            ERROR("srp_evaluate: unexpected rrtype %d on " PRI_DNS_NAME_SRP " in update.", rr->type,
                  DNS_NAME_PARAM_SRP(rr->name, name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }

    // Now that we've scanned the whole update, do the consistency checks for updates that might
    // not have come in order.

    // First, make sure there's a host description.
    if (host_description == NULL) {
        ERROR("srp_evaluate: SRP update does not include a host description.");
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure that each service add references a service instance that's in the same update.
    for (sp = services; sp; sp = sp->next) {
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
            ERROR("srp_evaluate: service points to an instance that's not included: " PRI_DNS_NAME_SRP,
                  DNS_NAME_PARAM_SRP(sp->rr->name, name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }

    for (sip = service_instances; sip; sip = sip->next) {
        // For each service instance, make sure that at least one service references it
        if (sip->num_instances == 0) {
            DNS_NAME_GEN_SRP(sip->name, name_buf);
            ERROR("srp_evaluate: service instance update for " PRI_DNS_NAME_SRP
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

    // Make sure that at least one service instance references the host description
    if (host_description->num_instances == 0) {
        DNS_NAME_GEN_SRP(host_description->name, name_buf);
        ERROR("srp_evaluate: host description " PRI_DNS_NAME_SRP " is not referenced by any service instances.",
              DNS_NAME_PARAM_SRP(host_description->name, name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure the host description has at least one address record.
    if (host_description->addrs == NULL) {
        DNS_NAME_GEN_SRP(host_description->name, name_buf);
        ERROR("srp_evaluate: host description " PRI_DNS_NAME_SRP " doesn't contain any IP addresses.",
              DNS_NAME_PARAM_SRP(host_description->name, name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    for (i = 0; i < num_keys; i++) {
        // If this isn't the only key, make sure it's got the same contents as the other keys.
        if (i > 0) {
            if (!dns_keys_rdata_equal(key, keys[i])) {
                ERROR("srp_evaluate: more than one key presented");
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
            ERROR("srp_evaluate: key present for name " PRI_DNS_NAME_SRP
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
        ERROR("srp_evaluate: host description " PRI_DNS_NAME_SRP " doesn't contain a key.",
              DNS_NAME_PARAM_SRP(host_description->name, host_name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure that all the deletes are for things that are then added.
    for (dp = deletes; dp; dp = dp->next) {
        if (!dp->consumed) {
            DNS_NAME_GEN_SRP(host_description->name, host_name_buf);
            ERROR("srp_evaluate: delete for which there is no subsequent add: " PRI_DNS_NAME_SRP,
                  DNS_NAME_PARAM_SRP(host_description->name, host_name_buf));
            rcode = dns_rcode_formerr;
            goto out;
        }
    }

    // The signature should be the last thing in the additional section.   Even if the signature
    // is valid, if it's not at the end we reject it.   Note that we are just checking for SIG(0)
    // so if we don't find what we're looking for, we forward it to the DNS auth server which
    // will either accept or reject it.
    if (message->arcount < 1) {
        ERROR("srp_evaluate: signature not present");
        rcode = dns_rcode_formerr;
        goto out;
    }
    signature = &message->additional[message->arcount -1];
    if (signature->type != dns_rrtype_sig) {
        ERROR("srp_evaluate: signature is not at the end or is not present");
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure that the signer name is the hostname.   If it's not, it could be a legitimate
    // update with a different key, but it's not an SRP update, so we pass it on.
    if (!dns_names_equal(signature->data.sig.signer, host_description->name)) {
        DNS_NAME_GEN_SRP(signature->data.sig.signer, signer_name_buf);
        DNS_NAME_GEN_SRP(host_description->name, host_name_buf);
        ERROR("srp_evaluate: signer " PRI_DNS_NAME_SRP " doesn't match host " PRI_DNS_NAME_SRP,
              DNS_NAME_PARAM_SRP(signature->data.sig.signer, signer_name_buf),
              DNS_NAME_PARAM_SRP(host_description->name, host_name_buf));
        rcode = dns_rcode_formerr;
        goto out;
    }

    // Make sure we're in the time limit for the signature.   Zeroes for the inception and expiry times
    // mean the host that send this doesn't have a working clock.   One being zero and the other not isn't
    // valid unless it's 1970.
    if (signature->data.sig.inception != 0 || signature->data.sig.expiry != 0) {
        gettimeofday(&now, NULL);
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
                ERROR("srp_evaluate: service PTR record zone match fail!!");
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
                ERROR("srp_evaluate: service instance SRV record zone match fail!!");
                goto out;
            }
            replace_zone_name(&sip->srv->data.srv.name, uzp, replacement_zone);
        }

        // We shouldn't need to replace the hostname zone because it's actually pointing to
        // the name of a delete.
    }

    // Get the lease time.
    lease_time = 3600;
    key_lease_time = 604800;
    for (edns0 = message->edns0; edns0; edns0 = edns0->next) {
        if (edns0->type == dns_opt_update_lease) {
            unsigned off = 0;
            if (edns0->length != 4 && edns0->length != 8) {
                ERROR("srp_evaluate: edns0 update-lease option length bogus: %d", edns0->length);
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
            break;
        }
    }

    // Start the update.
    DNS_NAME_GEN_SRP(host_description->name, host_description_name_buf);
    INFO("srp_evaluate: update for " PRI_DNS_NAME_SRP " xid %x validates.",
         DNS_NAME_PARAM_SRP(host_description->name, host_description_name_buf), raw_message->wire.id);
    rcode = dns_rcode_noerror;
    ret = srp_update_start(connection, message, raw_message, host_description, service_instances, services,
                           replacement_zone == NULL ? update_zone : replacement_zone,
                           lease_time, key_lease_time);
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
    srp_update_free_parts(service_instances, NULL, services, host_description);

success:
    // No matter how we get out of this, we free the delete structures, because they are not
    // used to do the update.
    for (dp = deletes; dp; ) {
        delete_t *next = dp->next;
        free(dp);
        dp = next;
    }

    if (ret == true && rcode != dns_rcode_noerror) {
        send_fail_response(connection, raw_message, rcode);
    }
    return ret;
}

static void
dns_evaluate(comm_t *connection, message_t *message)
{
    dns_message_t *parsed_message;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&message->wire) == dns_qr_response) {
        ERROR("dns_evaluate: received a message that was a DNS response: %d", dns_opcode_get(&message->wire));
        return;
    }

    // Forward incoming messages that are queries but not updates.
    // XXX do this later--for now we operate only as a translator, not a proxy.
    if (dns_opcode_get(&message->wire) != dns_opcode_update) {
        send_fail_response(connection, message, dns_rcode_refused);
        ERROR("dns_evaluate: received a message that was not a DNS update: %d", dns_opcode_get(&message->wire));
        return;
    }

    // Parse the UPDATE message.
    if (!dns_wire_parse(&parsed_message, &message->wire, message->length)) {
        send_fail_response(connection, message, dns_rcode_servfail);
        ERROR("dns_wire_parse failed.");
        return;
    }

    // We need the wire message to validate the signature...
    if (!srp_evaluate(connection, parsed_message, message)) {
        // The message wasn't invalid, but wasn't an SRP message.
        dns_message_free(parsed_message);
        // dns_forward(connection)
        send_fail_response(connection, message, dns_rcode_refused);
    }
}

void
dns_input(comm_t *comm, message_t *message, void *context)
{
    (void)context;
    dns_evaluate(comm, message);
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
srp_proxy_listen(const char *update_zone, uint16_t *avoid_ports, int num_avoid_ports, ready_callback_t ready)
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
                                                     NULL, NULL, ready, NULL, NULL);
    if (listeners->udp_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("UDP listener: fail.");
        return 0;
    }
#ifdef SRP_STREAM_LISTENER_ENABLED
    listeners->tcp_listener = ioloop_listener_create(true, false, NULL, 0, NULL, NULL,
                                                     "TCP listener", dns_input, NULL, NULL, ready, NULL, NULL);
    if (listeners->tcp_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("TCP listener: fail.");
        return 0;
    }
#ifndef EXCLUDE_TLS
    listeners->tls_listener = ioloop_listener_create(true, true, NULL, 0, NULL, NULL,
                                                     "TLS listener", dns_input, NULL, NULL, ready, NULL, NULL);
    if (listeners->tls_listener == NULL) {
        srp_proxy_listener_cancel(listeners);
        ERROR("TLS listener: fail.");
        return 0;
    }
#endif
#endif

    // For now, hardcoded, should be configurable
    if (service_update_zone != NULL) {
        dns_name_free(service_update_zone);
    }
    service_update_zone = dns_pres_name_parse(update_zone);

    return listeners;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
