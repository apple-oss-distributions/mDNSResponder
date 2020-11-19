/* fromwire.c
 *
 * Copyright (c) 2018, 2019 Apple Computer, Inc. All rights reserved.
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
 * DNS wire-format functions.
 *
 * These are really simple functions for constructing DNS messages wire format.
 * The flow is that there is a transaction structure which contains pointers to both
 * a message output buffer and a response input buffer.   The structure is initialized,
 * and then the various wire format functions are called repeatedly to store data.
 * If an error occurs during this process, it's okay to just keep going, because the
 * error is recorded in the transaction; once all of the copy-in functions have been
 * called, the error status can be checked once at the end.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include "srp.h"
#include "dns-msg.h"

bool
dns_opt_parse(dns_edns0_t *NONNULL *NULLABLE ret, dns_rr_t *rr)
{
    dns_edns0_t *edns0, **p_edns0 = ret;
    unsigned offset = 0;
    dns_rdata_unparsed_t opt;

    // This would be a weird coding error.
    if (rr->type != dns_rrtype_opt) {
        return false;
    }
    opt = rr->data.unparsed;

    // RDATA is a series of TLVs
    while (offset < opt.len) {
        uint16_t tlv_type, tlv_len;

        // Parse the TLV type and length.
        if (!dns_u16_parse(opt.data, opt.len, &offset, &tlv_type) ||
            !dns_u16_parse(opt.data, opt.len, &offset, &tlv_len))
        {
            return false;
        }

        // Range check the contents.
        if (offset + tlv_len > opt.len) {
            return false;
        }

        edns0 = calloc(1, tlv_len + sizeof(*edns0));
        if (edns0 == NULL) {
            return false;
        }
        // Stash the record.
        edns0->length = tlv_len;
        edns0->type = tlv_type;
        memcpy(edns0->data, &opt.data[offset], tlv_len);
        *p_edns0 = edns0;
        p_edns0 = &edns0->next;
        offset += tlv_len;
    }
    return true;
}

dns_label_t * NULLABLE
dns_label_parse(const uint8_t *buf, unsigned mlen, unsigned *NONNULL offp)
{
    uint8_t llen = buf[*offp];
    dns_label_t *rv;

    // Make sure that we got the data this label claims to encompass.
    if (*offp + llen + 1 > mlen) {
        DEBUG("claimed length of label is too long: %u > %u.\n", *offp + llen + 1, mlen);
        return NULL;
    }

    rv = calloc(1, (sizeof(*rv) - DNS_MAX_LABEL_SIZE) + llen + 1);
    if (rv == NULL) {
        DEBUG("memory allocation for %u byte label (%.*s) failed.\n",
              *offp + llen + 1, *offp + llen + 1, &buf[*offp + 1]);
        return NULL;
    }

    rv->len = llen;
    memcpy(rv->data, &buf[*offp + 1], llen);
    rv->data[llen] = 0; // We NUL-terminate the label for convenience
    *offp += llen + 1;
    return rv;
}

static bool
dns_name_parse_in(dns_label_t *NONNULL *NULLABLE ret, const uint8_t *buf, unsigned len,
                  unsigned *NONNULL offp, unsigned base)
{
    dns_label_t *rv;

    if (*offp == len) {
        return false;
    }

    // A pointer?
    if ((buf[*offp] & 0xC0) == 0xC0) {
        unsigned pointer;
        if (*offp + 2 > len) {
            DEBUG("incomplete compression pointer: %u > %u", *offp + 2, len);
            return false;
        }
        pointer = (((unsigned)buf[*offp] & 0x3f) << 8) | (unsigned)buf[*offp + 1];
        *offp += 2;
        if (pointer < DNS_HEADER_SIZE) {
            // Don't allow pointers into the header.
            DEBUG("compression pointer points into header: %u.\n", pointer);
            return false;
        }
        pointer -= DNS_HEADER_SIZE;
        if (pointer >= base) {
            // Don't allow a pointer forward, or to a pointer we've already visited.
            DEBUG("compression pointer points forward: %u >= %u.\n", pointer, base);
            return false;
        }
        if (buf[pointer] & 0xC0) {
            // If this is a pointer to a pointer, it's not valid.
            DEBUG("compression pointer points into pointer: %u %02x%02x.\n", pointer,
                  buf[pointer], pointer + 1 < len ? buf[pointer + 1] : 0xFF);
            return false;
        }
        if (buf[pointer] + pointer >= base || buf[pointer] + pointer >= *offp) {
            // Possibly this isn't worth checking.
            DEBUG("compression pointer points to something that goes past current position: %u %u\n",
                  pointer, buf[pointer]);
            return false;
        }
        return dns_name_parse_in(ret, buf, len, &pointer, pointer);
    }
    // We don't support binary labels, which are historical, and at this time there are no other valid
    // DNS label types.
    if (buf[*offp] & 0xC0) {
        DEBUG("invalid label type: %x\n", buf[*offp]);
        return false;
    }

    rv = dns_label_parse(buf, len, offp);
    if (rv == NULL) {
        return false;
    }

    *ret = rv;

    if (rv->len == 0) {
        return true;
    }
    return dns_name_parse_in(&rv->next, buf, len, offp, base);
}

bool
dns_name_parse(dns_label_t *NONNULL *NULLABLE ret, const uint8_t *buf,
               unsigned len, unsigned *NONNULL offp, unsigned base)
{
    dns_label_t *rv = NULL, *next;

    if (!dns_name_parse_in(&rv, buf, len, offp, base)) {
        for (; rv != NULL; rv = next) {
            next = rv->next;
            free(rv);
        }
        return false;
    }
    *ret = rv;
    return true;
}

bool
dns_u8_parse(const uint8_t *buf, unsigned len, unsigned *NONNULL offp, uint8_t *NONNULL ret)
{
    uint8_t rv;
    if (*offp + 1 > len) {
        DEBUG("dns_u8_parse: not enough room: %u > %u.\n", *offp + 1, len);
        return false;
    }

    rv = buf[*offp];
    *offp += 1;
    *ret = rv;
    return true;
}

bool
dns_u16_parse(const uint8_t *buf, unsigned len, unsigned *NONNULL offp, uint16_t *NONNULL ret)
{
    uint16_t rv;
    if (*offp + 2 > len) {
        DEBUG("dns_u16_parse: not enough room: %u > %u.\n", *offp + 2, len);
        return false;
    }

    rv = ((uint16_t)(buf[*offp]) << 8) | (uint16_t)(buf[*offp + 1]);
    *offp += 2;
    *ret = rv;
    return true;
}

bool
dns_u32_parse(const uint8_t *buf, unsigned len, unsigned *NONNULL offp, uint32_t *NONNULL ret)
{
    uint32_t rv;
    if (*offp + 4 > len) {
        DEBUG("dns_u32_parse: not enough room: %u > %u.\n", *offp + 4, len);
        return false;
    }

    rv = (((uint32_t)(buf[*offp]) << 24) | ((uint32_t)(buf[*offp + 1]) << 16) |
          ((uint32_t)(buf[*offp + 2]) << 8) | (uint32_t)(buf[*offp + 3]));
    *offp += 4;
    *ret = rv;
    return true;
}

static void
dns_rrdata_dump(dns_rr_t *rr)
{
    int i;
    char nbuf[INET6_ADDRSTRLEN];
    char buf[DNS_MAX_NAME_SIZE_ESCAPED + 1];
    char outbuf[2048];
    char *obp;
    ssize_t output_len, avail = 2048;

#define ADVANCE(result, start, remaining) \
    output_len = strlen(start);           \
    result = start + output_len;          \
    avail = (remaining) - output_len
#define DEPCHAR(ch)     \
    do {                     \
        if (avail > 1) {     \
            *obp++ = (ch);   \
            *obp = 0;        \
            --avail;         \
        }                    \
    } while (0)


    switch(rr->type) {
    case dns_rrtype_key:
        snprintf(outbuf, sizeof(outbuf),
                 "KEY <AC %d> <Z %d> <XT %d> <ZZ %d> <NAMTYPE %d> <ZZZZ %d> <ORY %d> %d %d ",
                 ((rr->data.key.flags & 0xC000) >> 14 & 3), ((rr->data.key.flags & 0x2000) >> 13) & 1,
                 ((rr->data.key.flags & 0x1000) >> 12) & 1, ((rr->data.key.flags & 0xC00) >> 10) & 3,
                 ((rr->data.key.flags & 0x300) >> 8) & 3, ((rr->data.key.flags & 0xF0) >> 4) & 15,
                 rr->data.key.flags & 15, rr->data.key.protocol, rr->data.key.algorithm);
        ADVANCE(obp, outbuf, sizeof outbuf);

        for (i = 0; i < rr->data.key.len; i++) {
            if (i == 0) {
                snprintf(obp, avail, "%d [%02x", rr->data.key.len, rr->data.key.key[i]);
                ADVANCE(obp, obp, avail);
            } else {
                snprintf(obp, avail, " %02x", rr->data.key.key[i]);
                ADVANCE(obp, obp, avail);
            }
        }
        DEPCHAR(']');
        break;

    case dns_rrtype_sig:
        dns_name_print(rr->data.sig.signer, buf, sizeof(buf));
        snprintf(outbuf, sizeof(outbuf), "SIG %d %d %d %lu %lu %lu %d %s",
                 rr->data.sig.type, rr->data.sig.algorithm, rr->data.sig.label,
                 (unsigned long)rr->data.sig.rrttl, (unsigned long)rr->data.sig.expiry,
                 (unsigned long)rr->data.sig.inception, rr->data.sig.key_tag, buf);
        ADVANCE(obp, outbuf, sizeof outbuf);
        for (i = 0; i < rr->data.sig.len; i++) {
            if (i == 0) {
                snprintf(obp, avail, "%d [%02x", rr->data.sig.len, rr->data.sig.signature[i]);
                ADVANCE(obp, obp, avail);
            } else {
                snprintf(obp, avail, " %02x", rr->data.sig.signature[i]);
                ADVANCE(obp, obp, avail);
            }
        }
        DEPCHAR(']');
        break;

    case dns_rrtype_srv:
        dns_name_print(rr->data.srv.name, buf, sizeof(buf));
        snprintf(outbuf, sizeof(outbuf), "SRV %d %d %d %s", rr->data.srv.priority, rr->data.srv.weight,
                 rr->data.srv.port, buf);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        break;

    case dns_rrtype_ptr:
        dns_name_print(rr->data.ptr.name, buf, sizeof(buf));
        snprintf(outbuf, sizeof(outbuf), "PTR %s", buf);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        break;

    case dns_rrtype_cname:
        dns_name_print(rr->data.cname.name, buf, sizeof(buf));
        snprintf(outbuf, sizeof(outbuf), "CNAME %s", buf);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        break;

    case dns_rrtype_a:
        inet_ntop(AF_INET, &rr->data.a, nbuf, sizeof(nbuf));
        snprintf(outbuf, sizeof(outbuf), "A %s", nbuf);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        break;

    case dns_rrtype_aaaa:
        inet_ntop(AF_INET6, &rr->data.aaaa, nbuf, sizeof(nbuf));
        snprintf(outbuf, sizeof(outbuf), "AAAA %s", nbuf);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        break;

    case dns_rrtype_txt:
        strcpy(outbuf, "TXT ");
        ADVANCE(obp, outbuf, sizeof(outbuf));
        for (i = 0; i < rr->data.txt.len; i++) {
            if (isascii(rr->data.txt.data[i]) && isprint(rr->data.txt.data[i])) {
                DEPCHAR(rr->data.txt.data[i]);
            } else {
                snprintf(obp, avail, "<%x>", rr->data.txt.data[i]);
                ADVANCE(obp, obp, avail);
            }
        }
        DEPCHAR('"');
        break;

    default:
        snprintf(outbuf, sizeof(outbuf), "<rrtype %d>:", rr->type);
        ADVANCE(obp, outbuf, sizeof(outbuf));
        if (rr->data.unparsed.len == 0) {
            snprintf(obp, avail, " <none>");
            ADVANCE(obp, obp, avail);
        } else {
            for (i = 0; i < rr->data.unparsed.len; i++) {
                snprintf(obp, avail, " %02x", rr->data.unparsed.data[i]);
                ADVANCE(obp, obp, avail);
            }
        }
        break;
    }
    DEBUG(PUB_S_SRP, outbuf);
}

bool
dns_rdata_parse_data(dns_rr_t *NONNULL rr, const uint8_t *buf, unsigned *NONNULL offp, unsigned target, unsigned rdlen,
                     unsigned rrstart)
{
    switch(rr->type) {
    case dns_rrtype_key:
        if (!dns_u16_parse(buf, target, offp, &rr->data.key.flags) ||
            !dns_u8_parse(buf, target, offp, &rr->data.key.protocol) ||
            !dns_u8_parse(buf, target, offp, &rr->data.key.algorithm)) {
            return false;
        }
        rr->data.key.len = target - *offp;
        rr->data.key.key = malloc(rr->data.key.len);
        if (!rr->data.key.key) {
            return false;
        }
        memcpy(rr->data.key.key, &buf[*offp], rr->data.key.len);
        *offp += rr->data.key.len;
        break;

    case dns_rrtype_sig:
        rr->data.sig.start = rrstart;
        if (!dns_u16_parse(buf, target, offp, &rr->data.sig.type) ||
            !dns_u8_parse(buf, target, offp, &rr->data.sig.algorithm) ||
            !dns_u8_parse(buf, target, offp, &rr->data.sig.label) ||
            !dns_u32_parse(buf, target, offp, &rr->data.sig.rrttl) ||
            !dns_u32_parse(buf, target, offp, &rr->data.sig.expiry) ||
            !dns_u32_parse(buf, target, offp, &rr->data.sig.inception) ||
            !dns_u16_parse(buf, target, offp, &rr->data.sig.key_tag) ||
            !dns_name_parse(&rr->data.sig.signer, buf, target, offp, *offp)) {
            return false;
        }
        // The signature is what's left of the RRDATA.  It covers the message up to the signature, so we
        // remember where it starts so as to know what memory to cover to validate it.
        rr->data.sig.len = target - *offp;
        rr->data.sig.signature = malloc(rr->data.sig.len);
        if (!rr->data.sig.signature) {
            return false;
        }
        memcpy(rr->data.sig.signature, &buf[*offp], rr->data.sig.len);
        *offp += rr->data.sig.len;
        break;

    case dns_rrtype_srv:
        if (!dns_u16_parse(buf, target, offp, &rr->data.srv.priority) ||
            !dns_u16_parse(buf, target, offp, &rr->data.srv.weight) ||
            !dns_u16_parse(buf, target, offp, &rr->data.srv.port)) {
            return false;
        }
        // This fallthrough assumes that the first element in the srv, ptr and cname structs is
        // a pointer to a domain name.

    case dns_rrtype_ns:
    case dns_rrtype_ptr:
    case dns_rrtype_cname:
        if (!dns_name_parse(&rr->data.ptr.name, buf, target, offp, *offp)) {
            return false;
        }
        break;

    case dns_rrtype_a:
        if (rdlen != 4) {
            DEBUG("dns_rdata_parse: A rdlen is not 4: %u", rdlen);
            return false;
        }
        memcpy(&rr->data.a, &buf[*offp], rdlen);
        *offp = target;
        break;

    case dns_rrtype_aaaa:
        if (rdlen != 16) {
            DEBUG("dns_rdata_parse: AAAA rdlen is not 16: %u", rdlen);
            return false;
        }
        memcpy(&rr->data.aaaa, &buf[*offp], rdlen);
        *offp = target;
        break;

    case dns_rrtype_txt:
        rr->data.txt.len = target - *offp;
        rr->data.txt.data = malloc(rr->data.txt.len);
        if (rr->data.txt.data == NULL) {
            DEBUG("dns_rdata_parse: no memory for TXT RR");
            return false;
        }
        memcpy(rr->data.txt.data, &buf[*offp], rr->data.txt.len);
        *offp = target;
        break;

    default:
        if (rdlen > 0) {
            rr->data.unparsed.data = malloc(rdlen);
            if (rr->data.unparsed.data == NULL) {
                return false;
            }
            memcpy(rr->data.unparsed.data, &buf[*offp], rdlen);
        }
        rr->data.unparsed.len = rdlen;
        *offp = target;
        break;
    }
    if (*offp != target) {
        DEBUG("dns_rdata_parse: parse for rrtype %d not fully contained: %u %u", rr->type, target, *offp);
        return false;
    }
    return true;
}

static bool
dns_rdata_parse(dns_rr_t *NONNULL rr,
                const uint8_t *buf, unsigned len, unsigned *NONNULL offp, unsigned rrstart)
{
    uint16_t rdlen;
    unsigned target;

    if (!dns_u16_parse(buf, len, offp, &rdlen)) {
        return false;
    }
    target = *offp + rdlen;
    if (target > len) {
        return false;
    }
    return dns_rdata_parse_data(rr, buf, offp, target, rdlen, rrstart);
}

bool
dns_rr_parse(dns_rr_t *NONNULL rr,
             const uint8_t *buf, unsigned len, unsigned *NONNULL offp, bool rrdata_expected)
{
    int rrstart = *offp; // Needed to mark the start of the SIG RR for SIG(0).

    memset(rr, 0, sizeof(*rr));
    if (!dns_name_parse(&rr->name, buf, len, offp, *offp)) {
        return false;
    }

    if (!dns_u16_parse(buf, len, offp, &rr->type)) {
        return false;
    }

    if (!dns_u16_parse(buf, len, offp, &rr->qclass)) {
        return false;
    }

    if (rrdata_expected) {
        if (!dns_u32_parse(buf, len, offp, &rr->ttl)) {
            return false;
        }
        if (!dns_rdata_parse(rr, buf, len, offp, rrstart)) {
            return false;
        }
    }

    DNS_NAME_GEN_SRP(rr->name, name_buf);
    DEBUG("rrtype: %u  qclass: %u  name: " PRI_DNS_NAME_SRP PUB_S_SRP,
          rr->type, rr->qclass, DNS_NAME_PARAM_SRP(rr->name, name_buf), rrdata_expected ? "  rrdata:" : "");
    if (rrdata_expected) {
        dns_rrdata_dump(rr);
    }
    return true;
}

void
dns_rrdata_free(dns_rr_t *rr)
{
    switch(rr->type) {
    case dns_rrtype_a:
    case dns_rrtype_aaaa:
        break;

    case dns_rrtype_key:
        free(rr->data.key.key);
        break;

    case dns_rrtype_sig:
        dns_name_free(rr->data.sig.signer);
        free(rr->data.sig.signature);
        break;

    case dns_rrtype_srv:
    case dns_rrtype_ptr:
    case dns_rrtype_cname:
        dns_name_free(rr->data.ptr.name);
#ifndef __clang_analyzer__
        rr->data.ptr.name = NULL;
#endif
            break;

    case dns_rrtype_txt:
        free(rr->data.txt.data);
#ifndef __clang_analyzer__
        rr->data.txt.data = NULL;
#endif
        break;

    default:
        if (rr->data.unparsed.len > 0 && rr->data.unparsed.data != NULL) {
            free(rr->data.unparsed.data);
        }
        rr->data.unparsed.data = NULL;
    }
}

void
dns_message_free(dns_message_t *message)
{
    int i;
    dns_edns0_t *edns0, *next;

#define FREE(count, sets)                           \
    if (message->sets) {                            \
        for (i = 0; i < message->count; i++) {      \
            dns_rr_t *set = &message->sets[i];      \
            if (set->name) {                        \
                dns_name_free(set->name);           \
            }                                       \
            dns_rrdata_free(set);                   \
        }                                           \
        free(message->sets);                        \
    }
    FREE(qdcount, questions);
    FREE(ancount, answers);
    FREE(nscount, authority);
    FREE(arcount, additional);
#undef FREE
    for (edns0 = message->edns0; edns0 != NULL; edns0 = next) {
        next = edns0->next;
        free(edns0);
    }
    free(message);
}

bool
dns_wire_parse(dns_message_t *NONNULL *NULLABLE ret, dns_wire_t *message, unsigned len)
{
    unsigned offset = 0;
    unsigned data_len = len - DNS_HEADER_SIZE;
    dns_message_t *rv = calloc(1, sizeof(*rv));
    int i;

    if (rv == NULL) {
        return false;
    }

#define PARSE(count, sets, name, rrdata_expected)                                   \
    rv->count = ntohs(message->count);                                              \
    if (rv->count > 50) {                                                           \
        rv->count = 0;                                                              \
        dns_message_free(rv);                                                       \
        return false;                                                               \
    }                                                                               \
    DEBUG("Section %s, %d records", name, rv->count);                               \
                                                                                    \
    if (rv->count != 0) {                                                           \
        rv->sets = calloc(rv->count, sizeof(*rv->sets));                            \
        if (rv->sets == NULL) {                                                     \
            dns_message_free(rv);                                                   \
            return false;                                                           \
        }                                                                           \
    }                                                                               \
                                                                                    \
    for (i = 0; i < rv->count; i++) {                                               \
        if (!dns_rr_parse(&rv->sets[i], message->data, data_len, &offset, rrdata_expected)) {    \
            dns_message_free(rv);                                                   \
            ERROR(name " %d RR parse failed.\n", i);                                \
            return false;                                                           \
        }                                                                           \
    }
    PARSE(qdcount,  questions, "question", false);
    PARSE(ancount,    answers, "answers", true);
    PARSE(nscount,  authority, "authority", true);
    PARSE(arcount, additional, "additional", true);
#undef PARSE

    for (i = 0; i < rv->arcount; i++) {
        // Parse EDNS(0)
        if (rv->additional[i].type == dns_rrtype_opt) {
            if (!dns_opt_parse(&rv->edns0, &rv->additional[i])) {
                dns_message_free(rv);
                return false;
            }
        }
    }
    *ret = rv;
    return true;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
