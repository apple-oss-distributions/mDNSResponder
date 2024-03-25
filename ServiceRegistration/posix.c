/* posix.c
 *
 * Copyright (c) 2018-2021 Apple, Inc. All rights reserved.
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
 * utility functions common to all posix implementations (e.g., MacOS, Linux).
 */

#define _GNU_SOURCE

#include <netinet/in.h>
#include <net/if.h>
#ifndef LINUX
#include <netinet/in_var.h>
#include <net/if_dl.h>
#endif
#include <sys/ioctl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "dns_sd.h"
#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"

#undef OBJECT_TYPE
#define OBJECT_TYPE(x) int x##_created, x##_finalized, old_##x##_created, old_##x##_finalized;
#include "object-types.h"

void
ioloop_dump_object_allocation_stats(void)
{
#undef OBJECT_TYPE
#define OBJECT_TYPE(x) || (x ## _created != old_ ## x ## _created) || (x ## _finalized != old_ ## x ## _finalized)
    if (false
#include "object-types.h"
        )
    {
        char outbuf[1000];
        char *obp = outbuf;
        size_t len;
#undef OBJECT_TYPE
#define OBJECT_TYPE_STR(x) #x
#define OBJECT_TYPE(x)                                                                                  \
        len = snprintf(obp, (sizeof(outbuf)) - (obp - outbuf), OBJECT_TYPE_STR(x) " %d %d %d %d|",      \
             old_ ## x ##_created, x ## _created, old_ ## x ## _finalized, x ## _finalized);            \
        obp += len;                                                                                     \
        old_ ## x ## _created = x ## _created;                                                          \
        old_ ## x ## _finalized = x ## _finalized;                                                      \
        if (obp - outbuf > 900) {                                                                       \
            INFO(PUB_S_SRP, outbuf);                                                                    \
            obp = outbuf;                                                                               \
            len = 0;                                                                                    \
        }
#include "object-types.h"
        if (len > 0) {
            INFO(PUB_S_SRP, outbuf);
        }
    }
    int num_fds = get_num_fds();
    if (num_fds < 0) {
        FAULT("out of file descriptors!!");
        abort();
    }
    INFO("%d file descriptors in use", num_fds);
}

interface_address_state_t *interface_addresses;

void
ioloop_strcpy(char *dest, const char *src, size_t lim)
{
    size_t len = strlen(src);
    if (len >= lim - 1) {
      len = lim - 1;
    }
    memcpy(dest, src, len);
    dest[len] = 0;
}

bool
ioloop_map_interface_addresses(const char *ifname, void *context, interface_callback_t callback)
{
    return ioloop_map_interface_addresses_here(&interface_addresses, ifname, context, callback);
}

bool
ioloop_map_interface_addresses_here_(interface_address_state_t **here, const char *ifname, void *context,
                                     interface_callback_t callback, const char *file, int line)
{
    struct ifaddrs *ifaddrs, *ifp;
    interface_address_state_t *kept_ifaddrs = NULL, **ki_end = &kept_ifaddrs;
    interface_address_state_t *new_ifaddrs = NULL, **ni_end = &new_ifaddrs;
    interface_address_state_t **ip, *nif;

    if (getifaddrs(&ifaddrs) < 0) {
        ERROR("getifaddrs failed: " PUB_S_SRP, strerror(errno));
        return false;
    }

    for (ifp = ifaddrs; ifp; ifp = ifp->ifa_next) {
        bool remove = false;
        bool keep = true;

        // It is impossible to have an interface without interface name.
        if (ifp->ifa_name == NULL) {
            continue;
        }
        if (ifname != NULL && strcmp(ifname, ifp->ifa_name)) {
            continue;
        }

#ifndef LINUX
        // Check for temporary addresses, etc.
        if (ifp->ifa_addr != NULL && ifp->ifa_addr->sa_family == AF_INET6) {
            struct in6_ifreq ifreq;
            int sock;
            size_t len;
            len = strlen(ifp->ifa_name);
            if (len >= sizeof(ifreq.ifr_name)) {
                len = sizeof(ifreq.ifr_name) - 1;
            }
            memcpy(ifreq.ifr_name, ifp->ifa_name, len);
            ifreq.ifr_name[len] = 0;
            if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
                ERROR("socket(AF_INET6, SOCK_DGRAM): " PUB_S_SRP, strerror(errno));
                continue;
            }
            memcpy(&ifreq.ifr_addr, ifp->ifa_addr, sizeof ifreq.ifr_addr);
            if (ioctl(sock, SIOCGIFAFLAG_IN6, &ifreq) < 0) {
                ERROR("ioctl(SIOCGIFAFLAG_IN6): " PUB_S_SRP, strerror(errno));
                close(sock);
                continue;
            }
            int flags = ifreq.ifr_ifru.ifru_flags6;
            if (flags & (IN6_IFF_ANYCAST | IN6_IFF_TENTATIVE | IN6_IFF_DETACHED | IN6_IFF_TEMPORARY)) {
                keep = false;
            }
            if (flags & IN6_IFF_DEPRECATED) {
                remove = true;
            }
            close(sock);
        }

#ifdef DEBUG_AF_LINK
        if (ifp->ifa_addr != NULL && ifp->ifa_addr->sa_family != AF_INET && ifp->ifa_addr->sa_family != AF_INET6) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifp->ifa_addr;
            const uint8_t *addr = (uint8_t *)LLADDR(sdl);
            INFO("%.*s index %d alen %d dlen %d SDL: %02x:%02x:%02x:%02x:%02x:%02x",
                 sdl->sdl_nlen, sdl->sdl_data, sdl->sdl_index, sdl->sdl_alen, sdl->sdl_slen,
                 addr[0],  addr[1],  addr[2], addr[3],  addr[4],  addr[5]);
        }
#endif // DEBUG_AF_LINK
#endif // LINUX

        // Is this an interface address we can use?
        if (keep && ifp->ifa_addr != NULL && (
#ifndef LINUX
                ifp->ifa_addr->sa_family == AF_LINK ||
#endif
             ((ifp->ifa_addr->sa_family == AF_INET6 || ifp->ifa_addr->sa_family == AF_INET) && ifp->ifa_netmask != NULL)) &&
            (ifp->ifa_flags & IFF_UP))
        {
            keep = false;
            for (ip = here; *ip != NULL; ) {
                interface_address_state_t *ia = *ip;
                // Same interface and address?
                if (!remove && !strcmp(ia->name, ifp->ifa_name) &&
                    ifp->ifa_addr->sa_family == ia->addr.sa.sa_family &&
                    (
#ifndef LINUX
                        ifp->ifa_addr->sa_family == AF_LINK ||
#endif
                     (((ifp->ifa_addr->sa_family == AF_INET &&
                        ((struct sockaddr_in *)ifp->ifa_addr)->sin_addr.s_addr == ia->addr.sin.sin_addr.s_addr) ||
                       (ifp->ifa_addr->sa_family == AF_INET6 &&
                        !memcmp(&((struct sockaddr_in6 *)ifp->ifa_addr)->sin6_addr,
                                &ia->addr.sin6.sin6_addr, sizeof ia->addr.sin6.sin6_addr))) &&
                      ((ifp->ifa_netmask->sa_family == AF_INET &&
                        ((struct sockaddr_in *)ifp->ifa_netmask)->sin_addr.s_addr == ia->mask.sin.sin_addr.s_addr) ||
                       (ifp->ifa_netmask->sa_family == AF_INET6 &&
                        !memcmp(&((struct sockaddr_in6 *)ifp->ifa_netmask)->sin6_addr,
                                &ia->mask.sin6.sin6_addr, sizeof ia->mask.sin6.sin6_addr))))))
                {
                    *ip = ia->next;
                    *ki_end = ia;
                    ki_end = &ia->next;
                    ia->next = NULL;
                    keep = true;
                    break;
                } else {
                    ip = &ia->next;
                }
            }
            // If keep is false, this is a new interface/address.
            if (!keep) {
                size_t len = strlen(ifp->ifa_name);
#ifdef MALLOC_DEBUG_LOGGING
                nif = debug_calloc(1, len + 1 + sizeof(*nif), file, line);
#else
                (void)file;
                (void)line;
                nif = calloc(1, len + 1 + sizeof(*nif));
#endif
                // We don't have a way to fix nif being null; what this means is that we don't detect a new
                // interface address.
                if (nif != NULL) {
                    nif->name = (char *)(nif + 1);
                    memcpy(nif->name, ifp->ifa_name, len);
                    nif->name[len] = 0;
                    if (ifp->ifa_addr->sa_family == AF_INET) {
                        nif->addr.sin = *((struct sockaddr_in *)ifp->ifa_addr);
                        nif->mask.sin = *((struct sockaddr_in *)ifp->ifa_netmask);

                        IPv4_ADDR_GEN_SRP(&nif->addr.sin.sin_addr.s_addr, __new_interface_ipv4_addr);
                        INFO("new IPv4 interface address added - ifname: " PUB_S_SRP
                             ", addr: " PRI_IPv4_ADDR_SRP, nif->name,
                             IPv4_ADDR_PARAM_SRP(&nif->addr.sin.sin_addr.s_addr, __new_interface_ipv4_addr));
                    } else if (ifp->ifa_addr->sa_family == AF_INET6) {
                        nif->addr.sin6 = *((struct sockaddr_in6 *)ifp->ifa_addr);
                        nif->mask.sin6 = *((struct sockaddr_in6 *)ifp->ifa_netmask);

                        SEGMENTED_IPv6_ADDR_GEN_SRP(nif->addr.sin6.sin6_addr.s6_addr, __new_interface_ipv6_addr);
                        INFO("new IPv6 interface address added - ifname: " PUB_S_SRP
                             ", addr: " PRI_SEGMENTED_IPv6_ADDR_SRP, nif->name,
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(nif->addr.sin6.sin6_addr.s6_addr,
                                                           __new_interface_ipv6_addr));
                    } else {
#ifndef LINUX
                        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifp->ifa_addr;
                        memset(&nif->mask, 0, sizeof(nif->mask));
                        if (sdl->sdl_alen == 6) {
                            nif->addr.ether_addr.len = 6;
                            memcpy(nif->addr.ether_addr.addr, LLADDR(sdl), 6);
                        } else {
                            nif->addr.ether_addr.len = 0;
                        }
                        nif->addr.ether_addr.index = sdl->sdl_index;
                        nif->addr.ether_addr.family = AF_LINK;
#endif // LINUX
                    }
                    nif->flags = ifp->ifa_flags;
                    *ni_end = nif;
                    ni_end = &nif->next;
                }
            }
        }
    }

#ifndef LINUX
    // Get rid of any link-layer addresses for which there is no other address on that interface
    // This is clunky, but we can't assume that the AF_LINK address will come after some other
    // address, so there's no more efficient way to do this that I can think of.
    for (ip = &new_ifaddrs; *ip; ) {
        if ((*ip)->addr.sa.sa_family == AF_LINK) {
            bool drop = true;
            for (nif = new_ifaddrs; nif; nif = nif->next) {
                if (nif != *ip && !strcmp(nif->name, (*ip)->name)) {
                    drop = false;
                    break;
                }
            }
            if (drop) {
                nif = *ip;
                *ip = nif->next;
                free(nif);
            } else {
                ip = &(*ip)->next;
            }
        } else {
            ip = &(*ip)->next;
        }
    }
#endif // LINUX

#ifdef TOO_MUCH_INFO
    char infobuf[1000];
    int i;
    for (i = 0; i < 3; i++) {
        char *infop = infobuf;
        int len, lim = sizeof infobuf;
        const char *title;
        switch(i) {
        case 0:
            title = "deleted";
            nif = *here;
            break;
        case 1:
            title = "   kept";
            nif = kept_ifaddrs;
            break;
        case 2:
            title = "    new";
            nif = new_ifaddrs;
            break;
        default:
            abort();
        }
        for (; nif; nif = nif->next) {
            snprintf(infop, lim, " %p (", nif);
            len = (int)strlen(infop);
            lim -= len;
            infop += len;
            inet_ntop(AF_INET6, &nif->addr.sin6.sin6_addr, infop, lim);
            len = (int)strlen(infop);
            lim -= len;
            infop += len;
            if (lim > 1) {
                *infop++ = ')';
                lim--;
            }
        }
        *infop = 0;
        INFO(PUB_S_SRP ":" PUB_S_SRP, title, infobuf);
    }
#endif

    // Report and free deleted interface addresses...
    for (ip = here; *ip; ) {
        nif = *ip;
        *ip = nif->next;
        if (callback != NULL) {
            callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_deleted);
        }
        free(nif);
    }

    // Report added interface addresses...
    for (nif = new_ifaddrs; nif; nif = nif->next) {
        if (callback != NULL) {
            callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_added);
        }
    }

    // Report unchanged interface addresses...
    for (nif = kept_ifaddrs; nif; nif = nif->next) {
        if (callback != NULL) {
            callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_unchanged);
        }
    }

    // Restore kept interface addresses and append new addresses to the list.
    *here = kept_ifaddrs;
    for (ip = here; *ip; ip = &(*ip)->next)
        ;
    *ip = new_ifaddrs;
    freeifaddrs(ifaddrs);
    return true;
}

ssize_t
ioloop_recvmsg(int sock, uint8_t *buffer, size_t buffer_length, int *ifindex, int *hop_limit, addr_t *source,
               addr_t *destination)
{
    ssize_t rv;
    struct msghdr msg;
    struct iovec bufp;
    char cmsgbuf[128];
    struct cmsghdr *cmh;

    bufp.iov_base = buffer;
    bufp.iov_len = buffer_length;
    msg.msg_iov = &bufp;
    msg.msg_iovlen = 1;
    msg.msg_name = source;
    msg.msg_namelen = sizeof(*source);
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    rv = recvmsg(sock, &msg, 0);
    if (rv < 0) {
        return rv;
    }

    // For UDP, we use the interface index as part of the validation strategy, so go get
    // the interface index.
    for (cmh = CMSG_FIRSTHDR(&msg); cmh; cmh = CMSG_NXTHDR(&msg, cmh)) {
        if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_PKTINFO &&
            cmh->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
        {
            struct in6_pktinfo pktinfo;

            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            *ifindex = (int)pktinfo.ipi6_ifindex;

            /* Get the destination address, for use when replying. */
            destination->sin6.sin6_family = AF_INET6;
            destination->sin6.sin6_port = 0;
            destination->sin6.sin6_addr = pktinfo.ipi6_addr;
#ifndef NOT_HAVE_SA_LEN
            destination->sin6.sin6_len = sizeof(destination->sin6);
#endif
        } else if (cmh->cmsg_level == IPPROTO_IP && cmh->cmsg_type == IP_PKTINFO &&
                   cmh->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo))) {
            struct in_pktinfo pktinfo;

            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            *ifindex = (int)pktinfo.ipi_ifindex;

            destination->sin.sin_family = AF_INET;
            destination->sin.sin_port = 0;
            destination->sin.sin_addr = pktinfo.ipi_addr;
#ifndef NOT_HAVE_SA_LEN
            destination->sin.sin_len = sizeof(destination->sin);
#endif
        } else if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_HOPLIMIT &&
                   cmh->cmsg_len == CMSG_LEN(sizeof(int))) {
            *hop_limit = *(int *)CMSG_DATA(cmh);
        }
    }
    return rv;
}

message_t *
ioloop_message_create_(size_t message_size, const char *file, int line)
{
    message_t *message;

    // Never should have a message shorter than this.
    if (message_size < DNS_HEADER_SIZE || message_size > UINT16_MAX) {
        return NULL;
    }

    message = (message_t *)malloc(message_size + (sizeof(message_t)) - (sizeof(dns_wire_t)));
    if (message) {
        memset(message, 0, (sizeof(message_t)) - (sizeof(dns_wire_t)));
        RETAIN(message, message);
        message->length = (uint16_t)message_size;
    }
    return message;
}

// Return continuous time, if provided by O.S., otherwise unadjusted time.
time_t srp_time(void)
{
#ifdef CLOCK_BOOTTIME
    // CLOCK_BOOTTIME is a Linux-specific constant that indicates a monotonic time that includes time asleep
    const int clockid = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC_RAW)
    // On MacOS, CLOCK_MONOTONIC_RAW is a monotonic time that includes time asleep and is not adjusted.
    // According to the man page, CLOCK_MONOTONIC on MacOS violates the POSIX spec in that it can be adjusted.
    const int clockid = CLOCK_MONOTONIC_RAW;
#else
    // On other Posix systems, CLOCK_MONOTONIC should be the right thing, at least according to the POSIX spec.
    const int clockid = CLOCK_MONOTONIC;
#endif
    struct timespec tm;
    clock_gettime(clockid, &tm);

    // We are only accurate to the second.
    return tm.tv_sec;
}

// Return continuous time, if provided by O.S., otherwise unadjusted time, in seconds, with six digits of
// fractional accuracy.
double
srp_fractional_time(void)
{
#ifdef CLOCK_BOOTTIME
    // CLOCK_BOOTTIME is a Linux-specific constant that indicates a monotonic time that includes time asleep
    const int clockid = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC_RAW)
    // On MacOS, CLOCK_MONOTONIC_RAW is a monotonic time that includes time asleep and is not adjusted.
    // According to the man page, CLOCK_MONOTONIC on MacOS violates the POSIX spec in that it can be adjusted.
    const int clockid = CLOCK_MONOTONIC_RAW;
#else
    // On other Posix systems, CLOCK_MONOTONIC should be the right thing, at least according to the POSIX spec.
    const int clockid = CLOCK_MONOTONIC;
#endif
    struct timespec tm;
    clock_gettime(clockid, &tm);

    return (double)tm.tv_sec + (double)tm.tv_nsec / 1.0e9;
}

int
get_num_fds(void)
{
    int num = 0;
    DIR *dirfd = opendir("/dev/fd");
    if (dirfd == NULL) {
        if (errno == EMFILE) {
            FAULT("per-process open file limit reached.");
            return -1;
        } else if (errno == ENFILE) {
            FAULT("per-system open file limit reached.");
            return -1;
        } else {
            ERROR("errno %d " PUB_S_SRP, errno, strerror(errno));
            return 0;
        }
    }
    while (readdir(dirfd) != NULL) {
        num++;
    }
    closedir(dirfd);
    return num;
}

#ifdef MALLOC_DEBUG_LOGGING
#undef malloc
#undef calloc
#undef strdup
#undef free

void *
debug_malloc(size_t len, const char *file, int line)
{
    void *ret = malloc(len);
    INFO("%p: malloc(%zu) at " PUB_S_SRP ":%d", ret, len, file, line);
    return ret;
}

void *
debug_calloc(size_t count, size_t len, const char *file, int line)
{
    void *ret = calloc(count, len);
    INFO("%p: calloc(%zu, %zu) at " PUB_S_SRP ":%d", ret, count, len, file, line);
    return ret;
}

char *
debug_strdup(const char *s, const char *file, int line)
{
    char *ret = strdup(s);
    INFO("%p: strdup(%p) at " PUB_S_SRP ":%d", ret, s, file, line);
    return ret;
}

void
debug_free(void *p, const char *file, int line)
{
    INFO("%p: free() at " PUB_S_SRP ":%d", p, file, line);
    free(p);
}
#endif

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
