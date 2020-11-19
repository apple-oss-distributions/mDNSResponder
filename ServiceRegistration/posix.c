/* posix.c
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
 * utility functions common to all posix implementations (e.g., MacOS, Linux).
 */

#define _GNU_SOURCE

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "dns_sd.h"
#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"

typedef struct interface_addr interface_addr_t;
struct interface_addr {
    interface_addr_t *next;
    char *name;
    addr_t addr;
    addr_t mask;
    uint32_t flags;
};
interface_addr_t *interface_addresses;

bool
ioloop_map_interface_addresses(void *context, interface_callback_t callback)
{
    struct ifaddrs *ifaddrs, *ifp;
    interface_addr_t *kept_ifaddrs = NULL, **ki_end = &kept_ifaddrs;
    interface_addr_t *new_ifaddrs = NULL, **ni_end = &new_ifaddrs;
    interface_addr_t **ip, *nif;

    if (getifaddrs(&ifaddrs) < 0) {
        ERROR("getifaddrs failed: " PUB_S_SRP, strerror(errno));
        return false;
    }

    for (ifp = ifaddrs; ifp; ifp = ifp->ifa_next) {
        bool remove = false;
        bool keep = true;

        // Check for temporary addresses, etc.
        if (ifp->ifa_addr != NULL && ifp->ifa_addr->sa_family == AF_INET6) {
            struct in6_ifreq ifreq;
            int sock;
            strlcpy(ifreq.ifr_name, ifp->ifa_name, sizeof(ifp->ifa_name));
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
            uint32_t flags = ifreq.ifr_ifru.ifru_flags6;
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

        // Is this an interface address we can use?
        if (keep && ifp->ifa_addr != NULL &&
            (ifp->ifa_addr->sa_family == AF_LINK ||
             ((ifp->ifa_addr->sa_family == AF_INET6 || ifp->ifa_addr->sa_family == AF_INET) && ifp->ifa_netmask != NULL)
             ) &&
            (ifp->ifa_flags & IFF_UP))
        {
            keep = false;
            for (ip = &interface_addresses; *ip != NULL; ) {
                interface_addr_t *ia = *ip;
                // Same interface and address?
                if (!remove && !strcmp(ia->name, ifp->ifa_name) &&
                    ifp->ifa_addr->sa_family == ia->addr.sa.sa_family &&
                    (ifp->ifa_addr->sa_family == AF_LINK ||
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
                nif = calloc(1, len + 1 + sizeof *nif);
                // We don't have a way to fix nif being null; what this means is that we don't detect a new
                // interface address.
                if (nif != NULL) {
                    nif->name = (char *)(nif + 1);
                    strlcpy(nif->name, ifp->ifa_name, len + 1);
                    if (ifp->ifa_addr->sa_family == AF_INET) {
                        nif->addr.sin = *((struct sockaddr_in *)ifp->ifa_addr);
                        nif->mask.sin = *((struct sockaddr_in *)ifp->ifa_netmask);

                        IPv4_ADDR_GEN_SRP(&nif->mask.sin.sin_addr.s_addr, __new_interface_ipv4_addr);
                        INFO("ioloop_map_interface_addresses: new IPv4 interface address added - ifname: " PUB_S_SRP
                             ", addr: " PRI_IPv4_ADDR_SRP, nif->name,
                             IPv4_ADDR_PARAM_SRP(&nif->mask.sin.sin_addr.s_addr, __new_interface_ipv4_addr));
                    } else if (ifp->ifa_addr->sa_family == AF_INET6) {
                        nif->addr.sin6 = *((struct sockaddr_in6 *)ifp->ifa_addr);
                        nif->mask.sin6 = *((struct sockaddr_in6 *)ifp->ifa_netmask);

                        SEGMENTED_IPv6_ADDR_GEN_SRP(nif->addr.sin6.sin6_addr.s6_addr, __new_interface_ipv6_addr);
                        INFO("ioloop_map_interface_addresses: new IPv6 interface address added - ifname: " PUB_S_SRP
                             ", addr: " PRI_SEGMENTED_IPv6_ADDR_SRP, nif->name,
                             SEGMENTED_IPv6_ADDR_PARAM_SRP(nif->addr.sin6.sin6_addr.s6_addr,
                                                           __new_interface_ipv6_addr));
                    } else {
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
                    }
                    nif->flags = ifp->ifa_flags;
                    *ni_end = nif;
                    ni_end = &nif->next;
                }
            }
        }
    }

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
            nif = interface_addresses;
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
    for (nif = interface_addresses; nif; ) {
        interface_addr_t *next = nif->next;
        callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_deleted);
        free(nif);
        nif = next;
    }

    // Report added interface addresses...
    for (nif = new_ifaddrs; nif; nif = nif->next) {
        callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_added);
    }

    // Report unchanged interface addresses...
    for (nif = kept_ifaddrs; nif; nif = nif->next) {
        callback(context, nif->name, &nif->addr, &nif->mask, nif->flags, interface_address_unchanged);
    }

    // Restore kept interface addresses and append new addresses to the list.
    interface_addresses = kept_ifaddrs;
    for (ip = &interface_addresses; *ip; ip = &(*ip)->next)
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
            *ifindex = pktinfo.ipi6_ifindex;

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
            *ifindex = pktinfo.ipi_ifindex;

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

#ifdef DEBUG_FD_LEAKS
int
get_num_fds(void)
{
    DIR *dirfd = opendir("/dev/fd");
    int num = 0;
    if (dirfd == NULL) {
        return -1;
    }
    while (readdir(dirfd) != NULL) {
        num++;
    }
    closedir(dirfd);
    return num;
}
#endif // DEBUG_VERBOSE

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
