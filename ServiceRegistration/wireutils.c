/* wireutils.c
 *
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
 * DNS wire-format utility functions.
 *
 * Functions that are neither necessary for very simple DNS packet generation, nor required for parsing
 * a message, e.g. compression, name printing, etc.
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

#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"

#undef LogMsg
#define LogMsg(...)

// We need the compression routines from DNSCommon.c, but we can't link to it because that
// pulls in a _lot_ of stuff we don't want.   The solution?   Define STANDALONE (this is done
// in the Makefile, and include DNSCommon.c.
//
// The only functions that aren't excluded by STANDALONE are FindCompressionPointer and
// putDomainNameAsLabels.

#define STANDALONE
#include "../mDNSCore/DNSCommon.c"

void dns_name_free(dns_label_t *name)
{
    dns_label_t *next;
    if (name == NULL) {
        return;
    }
    next = name->next;
    free(name);
    if (next != NULL) {
        return dns_name_free(next);
    }
}

dns_name_t *
dns_name_copy(dns_name_t *original)
{
    dns_name_t *ret = NULL, **cur = &ret;
    dns_name_t *next;

    for (next = original; next; next = next->next) {
        *cur = calloc(1, 1 + next->len + (sizeof (dns_name_t)) - DNS_MAX_LABEL_SIZE);
        if (*cur == NULL) {
            if (ret != NULL) {
                dns_name_free(ret);
            }
            return NULL;
        }
        if (next->len) {
            memcpy((*cur)->data, next->data, next->len + 1);
        }
        (*cur)->len = next->len;
        cur = &((*cur)->next);
    }
    return ret;
}

// Needed for TSIG (RFC2845).
void
dns_u48_to_wire_(dns_towire_state_t *NONNULL txn,
                 uint64_t val, int line)
{
    if (!txn->error) {
        if (txn->p + 6 >= txn->lim) {
            txn->error = ENOBUFS;
            txn->truncated = true;
            txn->line = line;
            return;
        }
        *txn->p++ = (val >> 40) & 0xff;
        *txn->p++ = (val >> 32) & 0xff;
        *txn->p++ = (val >> 24) & 0xff;
        *txn->p++ = (val >> 16) & 0xff;
        *txn->p++ = (val >> 8) & 0xff;
        *txn->p++ = val & 0xff;
    }
}

void
dns_concatenate_name_to_wire_(dns_towire_state_t *towire, dns_name_t *labels_prefix, const char *prefix,
                              const char *suffix, int line)
{
    dns_wire_t namebuf;
    dns_towire_state_t namewire;
    mDNSu8 *ret;
    namebuf.data[0] = 0;

    // Don't do all this work if we're already past an error.
    if (towire->error) {
        return;
    }
    memset(&namewire, 0, sizeof namewire);
    namewire.message = &namebuf;
    namewire.lim = &namebuf.data[DNS_DATA_SIZE];
    namewire.p = namebuf.data;
    if (prefix != NULL) {
        dns_name_to_wire(NULL, &namewire, prefix);
    } else if (labels_prefix != NULL) {
        size_t bytes_written;

        if (!namewire.error) {
            bytes_written = namewire.lim - namewire.p;
            if (bytes_written > INT16_MAX) {
                towire->error = true;
                towire->line = __LINE__;
                return;
            }
            bytes_written = dns_name_to_wire_canonical(namewire.p,  (int)bytes_written, labels_prefix);
            // This can never occur with a valid name.
            if (bytes_written == 0) {
                namewire.truncated = true;
            } else {
                namewire.p += bytes_written;
            }
        }
    }
    if (suffix != NULL) {
        dns_full_name_to_wire(NULL, &namewire, suffix);
    }
    if (namewire.error) {
        towire->truncated = namewire.truncated;
        towire->error = namewire.error;
        towire->line = line;
    }

    ret = putDomainNameAsLabels((DNSMessage *)towire->message, towire->p, towire->lim, (domainname *)namebuf.data);
    if (ret == NULL) {
        towire->error = ENOBUFS;
        towire->truncated = true;
        towire->line = line;
        return;
    }

    // Shouldn't happen
    if (ret > towire->lim) {
        towire->error = ENOBUFS;
        towire->truncated = true;
        towire->line = line;
    } else {
        towire->p = ret;
    }
}

// Convert a dns_name_t to presentation format.   Stop conversion at the specified limit.
// A trailing dot is only written if a null label is present.
const char *NONNULL
dns_name_print_to_limit(dns_name_t *NONNULL name, dns_name_t *NULLABLE limit, char *buf, int bufmax)
{
    dns_label_t *lp;
    int ix = 0;
    int i;

    // Copy the labels in one at a time, putting a dot between each one; if there isn't room
    // in the buffer (shouldn't be the case), copy as much as will fit, leaving room for a NUL
    // termination.
    for (lp = name; lp != limit && lp != NULL; lp = lp->next) {
        if (ix != 0) {
            if (ix + 2 >= bufmax) {
                break;
            }
            buf[ix++] = '.';
        }
        for (i = 0; i < lp->len; i++) {
            if (isascii(lp->data[i]) && (lp->data[i] == ' ' || isprint(lp->data[i]))) {
                if (ix + 2 >= bufmax) {
                    break;
                }
                buf[ix++] = lp->data[i];
            } else {
                if (ix + 5 >= bufmax) {
                    break;
                }
                buf[ix++] = '\\';
                buf[ix++] = '0' + (lp->data[i] / 100);
                buf[ix++] = '0' + (lp->data[i] /  10) % 10;
                buf[ix++] = '0' + lp->data[i]         % 10;
            }
        }
        if (i != lp->len) {
            break;
        }
    }
    buf[ix++] = 0;
    return buf;
}

const char *NONNULL
dns_name_print(dns_name_t *NONNULL name, char *buf, int bufmax)
{
    return dns_name_print_to_limit(name, NULL, buf, bufmax);
}

bool
dns_labels_equal(const char *label1, const char *label2, size_t len)
{
    unsigned i;
    for (i = 0; i < len; i++) {
        if (isascii(label1[i]) && isascii(label2[i])) {
            if (tolower(label1[i]) != tolower(label2[i])) {
                return false;
            }
        }
        else {
            if (label1[i] != label2[i]) {
                return false;
            }
        }
    }
    return true;
}

bool
dns_names_equal(dns_label_t *NONNULL name1, dns_label_t *NONNULL name2)
{
    if (name1->len != name2->len) {
        return false;
    }
    if (name1->len != 0 && !dns_labels_equal(name1->data, name2->data, name1->len) != 0) {
        return false;
    }
    if (name1->next != NULL && name2->next != NULL) {
        return dns_names_equal(name1->next, name2->next);
    }
    if (name1->next == NULL && name2->next == NULL) {
        return true;
    }
    return false;
}

// Note that "foo.arpa" is not the same as "foo.arpa."
bool
dns_names_equal_text(dns_label_t *NONNULL name1, const char *NONNULL name2)
{
    const char *ndot;
    const char *s, *t;
    int tlen = 0;
    ndot = strchr(name2, '.');
    if (ndot == NULL) {
        ndot = name2 + strlen(name2);
    }
    for (s = name2; s < ndot; s++) {
        if (*s == '\\') {
            if (s + 4 <= ndot) {
                tlen++;
                s += 3;
            } else {
                return false;  // An invalid name can't be equal to anything.
            }
        } else {
            tlen++;
        }
    }
    if (name1->len != tlen) {
        return false;
    }
    if (name1->len != 0) {
        t = name1->data;
        for (s = name2; s < ndot; s++, t++) {
            if (*s == '\\') { // already bounds checked
                int v0 = s[1] - '0';
                int v1 = s[2] - '0';
                int v2 = s[3] - '0';
                int val = v0 * 100 + v1 * 10 + v2;
                if (val > 255) {
                    return false;
                } else if (isascii(*s) && isascii(*t)) {
                    if (tolower(*s) != tolower(*t)) {
                        return false;
                    }
                } else if (val != *t) {
                    return false;
                }
                s += 3;
            } else {
                if (*s != *t) {
                    return false;
                }
            }
        }
    }
    if (name1->next != NULL && *ndot == '.') {
        return dns_names_equal_text(name1->next, ndot + 1);
    }
    if (name1->next == NULL && *ndot == 0) {
        return true;
    }
    return false;
}

// Find the length of a name in uncompressed wire format.
static size_t
dns_name_wire_length_in(dns_label_t *NONNULL name, size_t ret)
{
    // Root label.
    if (name == NULL)
        return ret;
    return dns_name_wire_length_in(name->next, ret + name->len + 1);
}

size_t
dns_name_wire_length(dns_label_t *NONNULL name)
{
    return dns_name_wire_length_in(name, 0);
}

// Copy a name we've parsed from a message out in canonical wire format so that we can
// use it to verify a signature.   As above, not actually needed for copying to a message
// we're going to send, since in that case we want to try to compress.
static size_t
dns_name_to_wire_canonical_in(uint8_t *NONNULL buf, size_t max, size_t ret, dns_label_t *NONNULL name)
{
    if (name == NULL) {
        return ret;
    }
    if (max < name->len + 1) {
        return 0;
    }
    *buf = name->len;
    memcpy(buf + 1, name->data, name->len);
    return dns_name_to_wire_canonical_in(buf + name->len + 1,
                                         max - name->len - 1, ret + name->len + 1, name->next);
}

size_t
dns_name_to_wire_canonical(uint8_t *NONNULL buf, size_t max, dns_label_t *NONNULL name)
{
    return dns_name_to_wire_canonical_in(buf, max, 0, name);
}

// Parse a NUL-terminated text string into a sequence of labels.
dns_name_t *
dns_pres_name_parse(const char *pname)
{
    const char *dot, *s, *label;
    dns_label_t *next, *ret, **prev = &ret;
    size_t len;
    char *t;
    char buf[DNS_MAX_LABEL_SIZE];
    ret = NULL;

    label = pname;
    dot = strchr(label, '.');
    while (true) {
        if (dot == NULL) {
            dot = label + strlen(label);
        }
        len = dot - label;
        if (len > 0) {
            t = buf;
            for (s = label; s < dot; s++) {
                if (*s == '\\') { // already bounds checked
                    int v0 = s[1] - '0';
                    int v1 = s[2] - '0';
                    int v2 = s[3] - '0';
                    int val = v0 * 100 + v1 * 10 + v2;
                    if (val > 255) {
                        goto fail;
                    }
                    s += 3;
                    *t++ = val;
                } else {
                    *t++ = *s;
                }
            }
            len = t - buf;
        }
        next = calloc(1, len + 1 + (sizeof *next) - DNS_MAX_LABEL_SIZE);
        if (next == NULL) {
            goto fail;
        }
        *prev = next;
        prev = &next->next;
        next->len = len;
        if (next->len > 0) {
            memcpy(next->data, buf, next->len);
        }
        next->data[next->len] = 0;
        if (dot[0] == '.' && len > 0) {
            dot = dot + 1;
        }
        if (*dot == '\0') {
            if (len > 0) {
                label = dot;
            } else {
                break;
            }
        } else {
            label = dot;
            dot = strchr(label, '.');
        }
    }
    return ret;

fail:
    if (ret) {
        dns_name_free(ret);
    }
    return NULL;
}

// See if name is a subdomain of domain.   If so, return a pointer to the label in name
// where the match to domain begins.
dns_name_t *
dns_name_subdomain_of(dns_name_t *name, dns_name_t *domain)
{
    int dnum = 0, nnum = 0;
    dns_name_t *np, *dp;

    for (dp = domain; dp; dp = dp->next) {
        dnum++;
    }
    for (np = name; np; np = np->next) {
        nnum++;
    }
    if (nnum < dnum) {
        return NULL;
    }
    for (np = name; np; np = np->next) {
        if (nnum-- == dnum) {
            break;
        }
    }
    if (np != NULL && dns_names_equal(np, domain)) {
        return np;
    }
    return NULL;
}

const char *
dns_rcode_name(int rcode)
{
    switch(rcode) {
    case dns_rcode_noerror:
        return "No Error";
    case dns_rcode_formerr:
        return "Format Error";
    case dns_rcode_servfail:
        return "Server Failure";
    case dns_rcode_nxdomain:
        return "Non-Existent Domain";
    case dns_rcode_notimp:
        return "Not Implemented";
    case dns_rcode_refused:
        return "Query Refused";
    case dns_rcode_yxdomain:
        return "RFC6672] Name Exists when it should not";
    case dns_rcode_yxrrset:
        return "RR Set Exists when it should not";
    case dns_rcode_nxrrset:
        return "RR Set that should exist does not";
    case dns_rcode_notauth:
        return "Not Authorized";
    case dns_rcode_notzone:
        return "Name not contained in zone";
    case dns_rcode_dsotypeni:
        return "DSO-Type Not Implemented";
    case dns_rcode_badvers:
        return "TSIG Signature Failure";
    case dns_rcode_badkey:
        return "Key not recognized";
    case dns_rcode_badtime:
        return "Signature out of time window";
    case dns_rcode_badmode:
        return "Bad TKEY Mode";
    case dns_rcode_badname:
        return "Duplicate key name";
    case dns_rcode_badalg:
        return "Algorithm not supported";
    case dns_rcode_badtrunc:
        return "Bad Truncation";
    case dns_rcode_badcookie:
        return "Bad/missing Server Cookie";
    default:
        return "Unknown rcode.";
    }
}

bool
dns_keys_rdata_equal(dns_rr_t *key1, dns_rr_t *key2)
{
    if ((key1->type == dns_rrtype_key && key2->type == dns_rrtype_key) &&
        key1->data.key.flags == key2->data.key.flags &&
        key1->data.key.protocol == key2->data.key.protocol &&
        key1->data.key.algorithm == key2->data.key.algorithm &&
        key1->data.key.len == key2->data.key.len &&
        !memcmp(key1->data.key.key, key2->data.key.key, key1->data.key.len))
    {
        return true;
    }
    return false;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
