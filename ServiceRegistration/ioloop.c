/* ioloop.c
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
 * Simple event dispatcher for DNS.
 */

#define __APPLE_USE_RFC_3542
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef USE_KQUEUE
#include <sys/event.h>
#endif
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "dns_sd.h"

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#ifndef EXCLUDE_TLS
#include "srp-tls.h"
#endif

io_t *ios;
wakeup_t *wakeups;
subproc_t *subprocesses;
int64_t ioloop_now;

#ifdef USE_KQUEUE
int kq;
#endif

int
getipaddr(addr_t *addr, const char *p)
{
    if (inet_pton(AF_INET, p, &addr->sin.sin_addr)) {
        addr->sa.sa_family = AF_INET;
#ifndef NOT_HAVE_SA_LEN
        addr->sa.sa_len = sizeof addr->sin;
#endif
        return sizeof addr->sin;
    }  else if (inet_pton(AF_INET6, p, &addr->sin6.sin6_addr)) {
        addr->sa.sa_family = AF_INET6;
#ifndef NOT_HAVE_SA_LEN
        addr->sa.sa_len = sizeof addr->sin6;
#endif
        return sizeof addr->sin6;
    } else {
        return 0;
    }
}

int64_t
ioloop_timenow()
{
    int64_t now;
    struct timeval tv;
    gettimeofday(&tv, 0);
    now = (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
    return now;
}

message_t *
message_allocate(size_t message_size)
{
    message_t *message = (message_t *)malloc(message_size + (sizeof (message_t)) - (sizeof (dns_wire_t)));
    if (message)
        memset(message, 0, (sizeof (message_t)) - (sizeof (dns_wire_t)));
    return message;
}

void
message_free(message_t *message)
{
    free(message);
}

void
comm_free(comm_t *comm)
{
    if (comm->name) {
        free(comm->name);
        comm->name = NULL;
    }
    if (comm->message) {
        message_free(comm->message);
        comm->message = NULL;
        comm->buf = NULL;
    }
    free(comm);
}

void
ioloop_close(io_t *io)
{
    close(io->sock);
    io->sock = -1;
}

static void
add_io(io_t *io)
{
    io_t **iop;

    // Add the new reader to the end of the list if it's not on the list.
    for (iop = &ios; *iop != NULL && *iop != io; iop = &((*iop)->next))
        ;
    if (*iop == NULL) {
        *iop = io;
        io->next = NULL;
    }
}

void
ioloop_add_reader(io_t *io, io_callback_t callback, io_callback_t finalize)
{
    add_io(io);

    io->read_callback = callback;
    io->finalize = finalize;
#ifdef USE_SELECT
    io->want_read = true;
#endif
#ifdef USE_EPOLL
#endif
#ifdef USE_KQUEUE
    struct kevent ev;
    int rv;
    EV_SET(&ev, io->sock, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, io);
    rv = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rv < 0) {
        ERROR("kevent add: %s", strerror(errno));
        return;
    }
#endif // USE_EPOLL
}

void
ioloop_add_writer(io_t *io, io_callback_t callback, io_callback_t finalize)
{
    add_io(io);

    io->write_callback = callback;
#ifdef USE_SELECT
    io->want_write = true;
#endif
#ifdef USE_EPOLL
#endif
#ifdef USE_KQUEUE
    struct kevent ev;
    int rv;
    EV_SET(&ev, io->sock, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, io);
    rv = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rv < 0) {
        ERROR("kevent add: %s", strerror(errno));
        return;
    }
#endif // USE_EPOLL
}

void
drop_writer(io_t *io)
{
#ifdef USE_SELECT
    io->want_write = false;
#endif
#ifdef USE_EPOLL
#endif
#ifdef USE_KQUEUE
    struct kevent ev;
    int rv;
    EV_SET(&ev, io->sock, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, io);
    rv = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rv < 0) {
        ERROR("kevent add: %s", strerror(errno));
        return;
    }
#endif // USE_EPOLL
}

static void
add_remove_wakeup(wakeup_t *io, bool remove)
{
    wakeup_t **p_wakeups;

    // Add the new reader to the end of the list if it's not on the list.
    for (p_wakeups = &wakeups; *p_wakeups != NULL && *p_wakeups != io; p_wakeups = &((*p_wakeups)->next))
        ;
    if (remove) {
        if (*p_wakeups != NULL) {
            *p_wakeups = io->next;
            io->next = NULL;
        }
    } else {
        if (*p_wakeups == NULL) {
            *p_wakeups = io;
            io->next = NULL;
        }
    }
}

void
ioloop_add_wake_event(wakeup_t *wakeup, void *context, wakeup_callback_t callback, int milliseconds)
{
    add_remove_wakeup(wakeup, false);
    wakeup->wakeup_time = ioloop_timenow() + milliseconds;
    wakeup->wakeup = callback;
    wakeup->context = context;
}

void
ioloop_cancel_wake_event(wakeup_t *wakeup)
{
    add_remove_wakeup(wakeup, true);
    wakeup->wakeup_time = 0;
}

static void
subproc_free(subproc_t *subproc)
{
    int i;
    for (i = 0; i < subproc->argc; i++) {
        free(subproc->argv[i]);
    }
    free(subproc);
}

bool
ioloop_init(void)
{
    signal(SIGPIPE, SIG_IGN); // because why ever?
#ifdef USE_KQUEUE
    kq = kqueue();
    if (kq < 0) {
        ERROR("kqueue(): %s", strerror(errno));
        return false;
    }
#endif
    return true;
}

int
ioloop_events(int64_t timeout_when)
{
    io_t *io, **iop;
    wakeup_t *wakeup, **p_wakeup;
    int nev = 0, rv;
    int64_t now = ioloop_timenow();
    int64_t next_event = timeout_when;
    int64_t timeout = 0;

    if (ioloop_now != 0) {
        INFO("%lld.%03lld seconds have passed on entry to ioloop_events",
             (long long)((now - ioloop_now) / 1000), (long long)((now - ioloop_now) % 1000));
    }
    ioloop_now = now;

    // A timeout of zero means don't time out.
    if (timeout_when == 0) {
        next_event = INT64_MAX;
    } else {
        next_event = timeout_when;
    }

#ifdef USE_SELECT
    int nfds = 0;
    fd_set reads, writes, errors;
    struct timeval tv;

    FD_ZERO(&reads);
    FD_ZERO(&writes);
    FD_ZERO(&errors);
#endif
#ifdef USE_KQUEUE
    struct timespec ts;
#endif
    p_wakeup = &wakeups;
    while (*p_wakeup) {
        wakeup = *p_wakeup;
        if (wakeup->wakeup_time != 0) {
            // We loop here in case the wakeup callback sets another wakeup--if it does, we check
            // again.
            while (wakeup->wakeup_time <= ioloop_now) {
                wakeup->wakeup_time = 0;
                wakeup->wakeup(wakeup->context);
                ++nev;
                if (wakeup->wakeup_time == 0) {
                    // Take the wakeup off the list.
                    *p_wakeup = wakeup->next;
                    wakeup->next = NULL;
                    break;
                }
            }
            if (wakeup->wakeup_time < next_event) {
                next_event = wakeup->wakeup_time;
            }
        }
    }

    iop = &ios;
    while (*iop) {
        io = *iop;
        // If the I/O is dead, finalize or free it.
        if (io->sock == -1) {
            *iop = io->next;
            if (io->finalize) {
                io->finalize(io);
            } else {
                free(io);
            }
            continue;
        }

        iop = &io->next;
    }

    // INFO("now: %ld  io %d wakeup_time %ld  next_event %ld", ioloop_now, io->sock, io->wakeup_time, next_event);

    // If we were given a timeout in the future, or told to wait indefinitely, wait until the next event.
    if (timeout_when == 0 || timeout_when > ioloop_now) {
        timeout = next_event - ioloop_now;
        // Don't choose a time so far in the future that it might overflow some math in the kernel.
        if (timeout > IOLOOP_DAY * 100) {
            timeout = IOLOOP_DAY * 100;
        }
#ifdef USE_SELECT
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
#endif
#ifdef USE_KQUEUE
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000 * 1000;
#endif
    }

    while (subprocesses != NULL) {
        int status;
        pid_t pid;
        pid = waitpid(-1, &status, WNOHANG);
        if (pid <= 0) {
            break;
        }
        subproc_t **sp, *subproc;
        for (sp = &subprocesses; (*sp) != NULL; sp = &(*sp)->next) {
            subproc = *sp;
            if (subproc->pid == pid) {
                if (!WIFSTOPPED(status)) {
                    *sp = subproc->next;
                }
                subproc->callback(subproc, status, NULL);
                if (!WIFSTOPPED(status)) {
                    subproc_free(subproc);
                    break;
                }
            }
        }
    }

#ifdef USE_SELECT
    for (io = ios; io; io = io->next) {
        if (io->sock != -1 && (io->want_read || io->want_write)) {
            if (io->sock >= nfds) {
                nfds = io->sock + 1;
            }
            if (io->want_read) {
                FD_SET(io->sock, &reads);
            }
            if (io->want_write) {
                FD_SET(io->sock, &writes);
            }
        }
    }
#endif

#ifdef USE_SELECT
    INFO("waiting %lld %lld seconds", (long long)tv.tv_sec, (long long)tv.tv_usec);
    rv = select(nfds, &reads, &writes, &errors, &tv);
    if (rv < 0) {
        ERROR("select: %s", strerror(errno));
        exit(1);
    }
    now = ioloop_timenow();
    INFO("%lld.%03lld seconds passed waiting, got %d events", (long long)((now - ioloop_now) / 1000),
         (long long)((now - ioloop_now) % 1000), rv);
    ioloop_now = now;
    for (io = ios; io; io = io->next) {
        if (io->sock != -1) {
            if (FD_ISSET(io->sock, &reads)) {
                io->read_callback(io);
            } else if (FD_ISSET(io->sock, &writes)) {
                io->write_callback(io);
            }
        }
    }
    nev += rv;
#endif // USE_SELECT
#ifdef USE_KQUEUE
#define KEV_MAX 20
    struct kevent evs[KEV_MAX];
    int i;

    INFO("waiting %lld/%lld seconds", (long long)ts.tv_sec, (long long)ts.tv_nsec);
    do {
        rv = kevent(kq, NULL, 0, evs, KEV_MAX, &ts);
        now = ioloop_timenow();
        INFO("%lld.%03lld seconds passed waiting, got %d events", (long long)((now - ioloop_now) / 1000),
             (long long)((now - ioloop_now) % 1000), rv);
        ioloop_now = now;
        ts.tv_sec = 0;
        ts.tv_nsec = 0;
        if (rv < 0) {
            if (errno == EINTR) {
                rv = 0;
            } else {
                ERROR("kevent poll: %s", strerror(errno));
                exit(1);
            }
        }
        for (i = 0; i < rv; i++) {
            io = evs[i].udata;
            if (evs[i].filter == EVFILT_WRITE) {
                io->write_callback(io);
            } else if (evs[i].filter == EVFILT_READ) {
                io->read_callback(io);
            }
        }
        nev += rv;
    } while (rv == KEV_MAX);
#endif
    return nev;
}

static void
udp_read_callback(io_t *io)
{
    comm_t *connection = (comm_t *)io;
    addr_t src;
    int rv;
    struct msghdr msg;
    struct iovec bufp;
    uint8_t msgbuf[DNS_MAX_UDP_PAYLOAD];
    char cmsgbuf[128];
    struct cmsghdr *cmh;
    message_t *message;

    bufp.iov_base = msgbuf;
    bufp.iov_len = DNS_MAX_UDP_PAYLOAD;
    msg.msg_iov = &bufp;
    msg.msg_iovlen = 1;
    msg.msg_name = &src;
    msg.msg_namelen = sizeof src;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof cmsgbuf;

    rv = recvmsg(connection->io.sock, &msg, 0);
    if (rv < 0) {
        ERROR("udp_read_callback: %s", strerror(errno));
        return;
    }
    message = message_allocate(rv);
    if (!message) {
        ERROR("udp_read_callback: out of memory");
        return;
    }
    memcpy(&message->src, &src, sizeof src);
    message->length = rv;
    memcpy(&message->wire, msgbuf, rv);

    // For UDP, we use the interface index as part of the validation strategy, so go get
    // the interface index.
    for (cmh = CMSG_FIRSTHDR(&msg); cmh; cmh = CMSG_NXTHDR(&msg, cmh)) {
        if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pktinfo;

            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            message->ifindex = pktinfo.ipi6_ifindex;

            /* Get the destination address, for use when replying. */
            message->local.sin6.sin6_family = AF_INET6;
            message->local.sin6.sin6_port = 0;
            message->local.sin6.sin6_addr = pktinfo.ipi6_addr;
#ifndef NOT_HAVE_SA_LEN
            message->local.sin6.sin6_len = sizeof message->local;
#endif
        } else if (cmh->cmsg_level == IPPROTO_IP && cmh->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pktinfo;

            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            message->ifindex = pktinfo.ipi_ifindex;

            message->local.sin.sin_family = AF_INET;
            message->local.sin.sin_port = 0;
            message->local.sin.sin_addr = pktinfo.ipi_addr;
#ifndef NOT_HAVE_SA_LEN
            message->local.sin.sin_len = sizeof message->local;
#endif
        }
    }
    connection->message = message;
    connection->datagram_callback(connection);
}

static void
tcp_read_callback(io_t *context)
{
    uint8_t *read_ptr;
    size_t read_len;
    comm_t *connection = (comm_t *)context;
    ssize_t rv;
    if (connection->message_length_len < 2) {
        read_ptr = connection->message_length_bytes;
        read_len = 2 - connection->message_length_len;
    } else {
        read_ptr = &connection->buf[connection->message_cur];
        read_len = connection->message_length - connection->message_cur;
    }

    if (connection->tls_context != NULL) {
#ifndef EXCLUDE_TLS
        rv = srp_tls_read(connection, read_ptr, read_len);
        if (rv == 0) {
            // This isn't an EOF: that's returned as an error status.   This just means that
            // whatever data was available to be read was consumed by the TLS protocol without
            // producing anything to read at the app layer.
            return;
        } else if (rv < 0) {
            ERROR("TLS return that we can't handle.");
            close(connection->io.sock);
            connection->io.sock = -1;
            srp_tls_context_free(connection);
            return;
        }
#else
        ERROR("tls context with TLS excluded in tcp_read_callback.");
        return;
#endif
    } else {
        rv = read(connection->io.sock, read_ptr, read_len);

        if (rv < 0) {
            ERROR("tcp_read_callback: %s", strerror(errno));
            close(connection->io.sock);
            connection->io.sock = -1;
            // connection->io.finalize() will be called from the io loop.
            return;
        }

        // If we read zero here, the remote endpoint has closed or shutdown the connection.  Either case is
        // effectively the same--if we are sensitive to read events, that means that we are done processing
        // the previous message.
        if (rv == 0) {
            ERROR("tcp_read_callback: remote end (%s) closed connection on %d", connection->name, connection->io.sock);
            close(connection->io.sock);
            connection->io.sock = -1;
            // connection->io.finalize() will be called from the io loop.
            return;
        }
    }
    if (connection->message_length_len < 2) {
        connection->message_length_len += rv;
        if (connection->message_length_len == 2) {
            connection->message_length = (((uint16_t)connection->message_length_bytes[0] << 8) |
                                          ((uint16_t)connection->message_length_bytes[1]));

            if (connection->message == NULL) {
                connection->message = message_allocate(connection->message_length);
                if (!connection->message) {
                    ERROR("udp_read_callback: out of memory");
                    return;
                }
                connection->buf = (uint8_t *)&connection->message->wire;
                connection->message->length = connection->message_length;
                memset(&connection->message->src, 0, sizeof connection->message->src);
            }
        }
    } else {
        connection->message_cur += rv;
        if (connection->message_cur == connection->message_length) {
            connection->message_cur = 0;
            connection->datagram_callback(connection);
            // Caller is expected to consume the message, we are immediately ready for the next read.
            connection->message_length = connection->message_length_len = 0;
        }
    }
}


static void
tcp_send_response(comm_t *comm, message_t *responding_to, struct iovec *iov, int iov_len)
{
    struct msghdr mh;
    struct iovec iovec[4];
    char lenbuf[2];
    ssize_t status;
    size_t payload_length = 0;
    int i;

    // We don't anticipate ever needing more than four hunks, but if we get more, handle then?
    if (iov_len > 3) {
        ERROR("tcp_send_response: too many io buffers");
        close(comm->io.sock);
        comm->io.sock = -1;
        return;
    }

    iovec[0].iov_base = &lenbuf[0];
    iovec[0].iov_len = 2;
    for (i = 0; i < iov_len; i++) {
        iovec[i + 1] = iov[i];
        payload_length += iov[i].iov_len;
    }
    lenbuf[0] = payload_length / 256;
    lenbuf[1] = payload_length & 0xff;
    payload_length += 2;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
    if (comm->tls_context != NULL) {
#ifndef EXCLUDE_TLS
        status = srp_tls_write(comm, iovec, iov_len + 1);
#else
        ERROR("TLS context not null with TLS excluded.");
        status = -1;
        errno = ENOTSUP;
#endif
    } else {
        memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iovec[0];
        mh.msg_iovlen = iov_len + 1;
        mh.msg_name = 0;

        status = sendmsg(comm->io.sock, &mh, MSG_NOSIGNAL);
    }
    if (status < 0 || status != payload_length) {
        if (status < 0) {
            ERROR("tcp_send_response: write failed: %s", strerror(errno));
        } else {
            ERROR("tcp_send_response: short write (%zd out of %zu bytes)", status, payload_length);
        }
        close(comm->io.sock);
        comm->io.sock = -1;
    }
}

static void
udp_send_message(comm_t *comm, addr_t *source, addr_t *dest, int ifindex, struct iovec *iov, int iov_len)
{
    struct msghdr mh;
    uint8_t cmsg_buf[128];
    struct cmsghdr *cmsg;
    int status;

    memset(&mh, 0, sizeof mh);
    mh.msg_iov = iov;
    mh.msg_iovlen = iov_len;
    mh.msg_name = dest;
    mh.msg_control = cmsg_buf;
    if (source == NULL && ifindex == 0) {
        mh.msg_controllen = 0;
    } else {
        mh.msg_controllen = sizeof cmsg_buf;
        cmsg = CMSG_FIRSTHDR(&mh);

        if (source->sa.sa_family == AF_INET) {
            struct in_pktinfo *inp;
            mh.msg_namelen = sizeof (struct sockaddr_in);
            mh.msg_controllen = CMSG_SPACE(sizeof *inp);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof *inp);
            inp = (struct in_pktinfo *)CMSG_DATA(cmsg);
            memset(inp, 0, sizeof *inp);
            inp->ipi_ifindex = ifindex;
            if (source) {
                inp->ipi_spec_dst = source->sin.sin_addr;
                inp->ipi_addr = source->sin.sin_addr;
            }
        } else if (source->sa.sa_family == AF_INET6) {
            struct in6_pktinfo *inp;
            mh.msg_namelen = sizeof (struct sockaddr_in6);
            mh.msg_controllen = CMSG_SPACE(sizeof *inp);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof *inp);
            inp = (struct in6_pktinfo *)CMSG_DATA(cmsg);
            memset(inp, 0, sizeof *inp);
            inp->ipi6_ifindex = ifindex;
            if (source) {
                inp->ipi6_addr = source->sin6.sin6_addr;
            }
        } else {
            ERROR("udp_send_response: unknown family %d", source->sa.sa_family);
            abort();
        }
    }
    status = sendmsg(comm->io.sock, &mh, 0);
    if (status < 0) {
        ERROR("udp_send_message: %s", strerror(errno));
    }
}

static void
udp_send_response(comm_t *comm, message_t *responding_to, struct iovec *iov, int iov_len)
{
    udp_send_message(comm, &responding_to->local, &responding_to->src, responding_to->ifindex, iov, iov_len);
}

static void
udp_send_multicast(comm_t *comm, int ifindex, struct iovec *iov, int iov_len)
{
    udp_send_message(comm, NULL, &comm->multicast, ifindex, iov, iov_len);
}

static void
udp_send_connected_response(comm_t *comm, message_t *responding_to, struct iovec *iov, int iov_len)
{
    int status = writev(comm->io.sock, iov, iov_len);
    (void)responding_to;
    if (status < 0) {
        ERROR("udp_send_connected: %s", strerror(errno));
    }
}

// When a communication is closed, scan the io event list to see if any other ios are referencing this one.
void
comm_finalize(io_t *io_in)
{
    comm_t *comm = (comm_t *)io_in;
    comm_free(comm);
}

bool
comm_valid(comm_t *comm)
{
    if (comm->io.sock != -1) {
        return true;
    }
    return false;
}

void
comm_close(comm_t *comm)
{
    close(comm->io.sock);
    comm->io.sock = -1;
}

static void
listen_callback(io_t *context)
{
    comm_t *listener = (comm_t *)context;
    int rv;
    addr_t addr;
    socklen_t addr_len = sizeof addr;
    comm_t *comm;
    char addrbuf[INET6_ADDRSTRLEN + 7];
    int addrlen;

    rv = accept(listener->io.sock, &addr.sa, &addr_len);
    if (rv < 0) {
        ERROR("accept: %s", strerror(errno));
        close(listener->io.sock);
        listener->io.sock = -1;
        return;
    }
    inet_ntop(addr.sa.sa_family, (addr.sa.sa_family == AF_INET
                                  ? (void *)&addr.sin.sin_addr
                                  : (void *)&addr.sin6.sin6_addr), addrbuf, sizeof addrbuf);
    addrlen = strlen(addrbuf);
    snprintf(&addrbuf[addrlen], (sizeof addrbuf) - addrlen, "%%%d",
             ntohs((addr.sa.sa_family == AF_INET ? addr.sin.sin_port : addr.sin6.sin6_port)));
    comm = calloc(1, sizeof *comm);
    comm->name = strdup(addrbuf);
    comm->io.sock = rv;
    comm->io.container = comm;
    comm->address = addr;
    comm->datagram_callback = listener->datagram_callback;
    comm->send_response = tcp_send_response;
    comm->tcp_stream = true;

    if (listener->tls_context == (tls_context_t *)-1) {
#ifndef EXCLUDE_TLS
        if (!srp_tls_listen_callback(comm)) {
            ERROR("TLS  setup failed.");
            close(comm->io.sock);
            free(comm);
            return;
        }
#else
        ERROR("TLS context not null in listen_callback when TLS excluded.");
        return;
#endif
    }
    if (listener->connected) {
        listener->connected(comm);
    }
    ioloop_add_reader(&comm->io, tcp_read_callback, listener->connection_finalize);

#ifdef SO_NOSIGPIPE
    int one = 1;
    rv = setsockopt(comm->io.sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    if (rv < 0) {
        ERROR("SO_NOSIGPIPE failed: %s", strerror(errno));
    }
#endif
}

comm_t *
ioloop_setup_listener(int family, bool stream, bool tls, uint16_t port, const char *ip_address, const char *multicast,
                      const char *name, comm_callback_t datagram_callback,
                      comm_callback_t connected, comm_callback_t disconnected,
                      io_callback_t finalize, io_callback_t connection_finalize, void *context)
{
    comm_t *listener;
    socklen_t sl;
    int rv;
    int false_flag = 0;
    int true_flag = 1;

    listener = calloc(1, sizeof *listener);
    if (listener == NULL) {
        return NULL;
    }
    listener->io.container = listener;
    listener->name = strdup(name);
    if (!listener->name) {
        free(listener);
        return NULL;
    }
    listener->io.sock = socket(family, stream ? SOCK_STREAM : SOCK_DGRAM, stream ? IPPROTO_TCP : IPPROTO_UDP);
    if (listener->io.sock < 0) {
        ERROR("Can't get socket: %s", strerror(errno));
        goto out;
    }
    rv = setsockopt(listener->io.sock, SOL_SOCKET, SO_REUSEADDR, &true_flag, sizeof true_flag);
    if (rv < 0) {
        ERROR("SO_REUSEADDR failed: %s", strerror(errno));
        goto out;
    }

    rv = setsockopt(listener->io.sock, SOL_SOCKET, SO_REUSEPORT, &true_flag, sizeof true_flag);
    if (rv < 0) {
        ERROR("SO_REUSEPORT failed: %s", strerror(errno));
        goto out;
    }

    if (ip_address != NULL) {
        sl = getipaddr(&listener->address, ip_address);
        if (sl == 0) {
            goto out;
        }
        if (family == AF_UNSPEC) {
            family = listener->address.sa.sa_family;
        } else if (listener->address.sa.sa_family != family) {
            ERROR("%s is not a %s address.", ip_address, family == AF_INET ? "IPv4" : "IPv6");
            goto out;
        }
    }

    if (multicast != 0) {
        if (stream) {
            ERROR("Unable to do non-datagram multicast.");
            goto out;
        }
        sl = getipaddr(&listener->multicast, multicast);
        if (sl == 0) {
            goto out;
        }
        if (listener->multicast.sa.sa_family != family) {
            ERROR("multicast address %s from different family than listen address %s.", multicast, ip_address);
            goto out;
        }
        listener->is_multicast = true;

        if (family == AF_INET) {
            struct ip_mreq im;
            int ttl = 255;
            im.imr_multiaddr = listener->multicast.sin.sin_addr;
            im.imr_interface.s_addr = 0;
            rv = setsockopt(listener->io.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &im, sizeof im);
            if (rv < 0) {
                ERROR("Unable to join %s multicast group: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
            if (rv < 0) {
                ERROR("Unable to set IP multicast TTL to 255 for %s: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl);
            if (rv < 0) {
                ERROR("Unable to set IP TTL to 255 for %s: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IP, IP_MULTICAST_LOOP, &false_flag, sizeof false_flag);
            if (rv < 0) {
                ERROR("Unable to set IP Multcast loopback to false for %s: %s", multicast, strerror(errno));
                goto out;
            }
        } else {
            struct ipv6_mreq im;
            int hops = 255;
            im.ipv6mr_multiaddr = listener->multicast.sin6.sin6_addr;
            im.ipv6mr_interface = 0;
            rv = setsockopt(listener->io.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &im, sizeof im);
            if (rv < 0) {
                ERROR("Unable to join %s multicast group: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops);
            if (rv < 0) {
                ERROR("Unable to set IPv6 multicast hops to 255 for %s: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof hops);
            if (rv < 0) {
                ERROR("Unable to set IPv6 hops to 255 for %s: %s", multicast, strerror(errno));
                goto out;
            }
            rv = setsockopt(listener->io.sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &false_flag, sizeof false_flag);
            if (rv < 0) {
                ERROR("Unable to set IPv6 Multcast loopback to false for %s: %s", multicast, strerror(errno));
                goto out;
            }
        }
    }

    if (family == AF_INET) {
        sl = sizeof listener->address.sin;
        listener->address.sin.sin_port = port ? htons(port) : htons(53);
    } else {
        sl = sizeof listener->address.sin6;
        listener->address.sin6.sin6_port = port ? htons(port) : htons(53);
        // Don't use a dual-stack socket.
        rv = setsockopt(listener->io.sock, IPPROTO_IPV6, IPV6_V6ONLY, &true_flag, sizeof true_flag);
        if (rv < 0) {
            ERROR("Unable to set IPv6-only flag on %s socket for %s",
                  tls ? "TLS" : (stream ? "TCP" : "UDP"), ip_address == NULL ? "<0>" : ip_address);
            goto out;
        }
    }

    listener->address.sa.sa_family = family;
#ifndef NOT_HAVE_SA_LEN
    listener->address.sa.sa_len = sl;
#endif
    if (bind(listener->io.sock, &listener->address.sa, sl) < 0) {
        ERROR("Can't bind to %s#%d/%s%s: %s", ip_address == NULL ? "<0>" : ip_address, port,
                stream ? "tcp" : "udp", family == AF_INET ? "v4" : "v6",
                strerror(errno));
    out:
        close(listener->io.sock);
        free(listener);
        return NULL;
    }

    if (tls) {
#ifndef EXCLUDE_TLS
        if (!stream) {
            ERROR("Asked to do TLS over UDP, which we don't do yet.");
            goto out;
        }
        listener->tls_context = (tls_context_t *)-1;
#else
        ERROR("TLS requested when TLS is excluded.");
        goto out;
#endif
    }

    if (stream) {
        if (listen(listener->io.sock, 5 /* xxx */) < 0) {
            ERROR("Can't listen on %s#%d/%s%s: %s", ip_address == NULL ? "<0>" : ip_address, ntohs(port),
                    tls ? "tls" : "tcp", family == AF_INET ? "v4" : "v6",
                    strerror(errno));
            goto out;
        }
        listener->connection_finalize = connection_finalize;
        ioloop_add_reader(&listener->io, listen_callback, finalize);
    } else {
        rv = setsockopt(listener->io.sock, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                        family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO, &true_flag, sizeof true_flag);
        if (rv < 0) {
            ERROR("Can't set %s: %s.", family == AF_INET ? "IP_PKTINFO" : "IPV6_RECVPKTINFO",
                    strerror(errno));
            goto out;
        }
        ioloop_add_reader(&listener->io, udp_read_callback, finalize);
        listener->send_response = udp_send_response;
        listener->send_message = udp_send_message;
        if (listener->is_multicast) {
            listener->send_multicast = udp_send_multicast;
        }
    }
    listener->datagram_callback = datagram_callback;
    listener->connected = connected;
    return listener;
}

static void
connect_callback(io_t *context)
{
    int result;
    socklen_t len = sizeof result;
    comm_t *connection = (comm_t *)context;

    // If connect failed, indicate that it failed.
    if (getsockopt(context->sock, SOL_SOCKET, SO_ERROR, &result, &len) < 0) {
        ERROR("connect_callback: unable to get connect error: socket %d: Error %d (%s)",
              context->sock, result, strerror(result));
        connection->disconnected(connection, result);
        comm_close(connection);
        return;
    }

    // If this is a TLS connection, set up TLS.
    if (connection->tls_context == (tls_context_t *)-1) {
#ifndef EXCLUDE_TLS
        srp_tls_connect_callback(connection);
#else
        ERROR("connect_callback: tls_context triggered with TLS excluded.");
        connection->disconnected(connection, 0);
        comm_close(connection);
        return;
#endif
    }

    connection->send_response = tcp_send_response;
    connection->connected(connection);
    drop_writer(&connection->io);
    ioloop_add_reader(&connection->io, tcp_read_callback, connection->io.finalize);
}

// Currently we don't do DNS lookups, despite the host identifier being an IP address.
comm_t *
ioloop_connect(addr_t *NONNULL remote_address, bool tls, bool stream,
               comm_callback_t datagram_callback, comm_callback_t connected,
               disconnect_callback_t disconnected, io_callback_t finalize, void *context)
{
    comm_t *connection;
    socklen_t sl;
    char buf[INET6_ADDRSTRLEN + 7];
    char *s;

    if (!stream && (connected != NULL || disconnected != NULL)) {
        ERROR("connected and disconnected callbacks not valid for datagram connections");
        return NULL;
    }
    if (stream && (connected == NULL || disconnected == NULL)) {
        ERROR("connected and disconnected callbacks are required for stream connections");
        return NULL;
    }
    connection = calloc(1, sizeof *connection);
    if (connection == NULL) {
        ERROR("No memory for connection structure.");
        return NULL;
    }
    connection->io.container = connection;
    if (inet_ntop(remote_address->sa.sa_family, (remote_address->sa.sa_family == AF_INET
                                                 ? (void *)&remote_address->sin.sin_addr
                                                 : (void *)&remote_address->sin6.sin6_addr), buf,
                  INET6_ADDRSTRLEN) == NULL) {
        ERROR("inet_ntop failed to convert remote address: %s", strerror(errno));
        free(connection);
        return NULL;
    }
    s = buf + strlen(buf);
    sprintf(s, "%%%hu", ntohs(remote_address->sa.sa_family == AF_INET
                              ? remote_address->sin.sin_port
                              : remote_address->sin6.sin6_port));
    connection->name = strdup(buf);
    if (!connection->name) {
        free(connection);
        return NULL;
    }
    connection->io.sock = socket(remote_address->sa.sa_family,
                                 stream ? SOCK_STREAM : SOCK_DGRAM, stream ? IPPROTO_TCP : IPPROTO_UDP);
    if (connection->io.sock < 0) {
        ERROR("Can't get socket: %s", strerror(errno));
        comm_free(connection);
        return NULL;
    }
    connection->address = *remote_address;
    if (fcntl(connection->io.sock, F_SETFL, O_NONBLOCK) < 0) {
        ERROR("connect_to_host: %s: Can't set O_NONBLOCK: %s", connection->name, strerror(errno));
        comm_free(connection);
        return NULL;
    }
#ifdef NOT_HAVE_SA_LEN
    sl = (remote_address->sa.sa_family == AF_INET
          ? sizeof remote_address->sin
          : sizeof remote_address->sin6);
#else
    sl = remote_address->sa.sa_len;
#endif
    // Connect to the host
    if (connect(connection->io.sock, &connection->address.sa, sl) < 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) {
            ERROR("Can't connect to %s: %s", connection->name, strerror(errno));
            comm_free(connection);
            return NULL;
        }
    }
    // At this point if we are doing TCP, we do not yet have a connection, but the connection should be in
    // progress, and we should get a write select event when the connection succeeds or fails.
    // UDP is connectionless, so the connect() call just sets the default destination for send() on
    // the socket.

    if (tls) {
#ifndef TLS_EXCLUDED
        connection->tls_context = (tls_context_t *)-1;
#else
        ERROR("connect_to_host: tls requested when excluded.");
        comm_free(connection);
        return NULL;
#endif
    }

    connection->connected = connected;
    connection->disconnected = disconnected;
    connection->datagram_callback = datagram_callback;
    connection->context = context;
    if (!stream) {
        connection->send_response = udp_send_connected_response;
        ioloop_add_reader(&connection->io, udp_read_callback, finalize);
    } else {
        ioloop_add_writer(&connection->io, connect_callback, finalize);
    }

    return connection;
}

typedef struct interface_addr interface_addr_t;
struct interface_addr {
    interface_addr_t *next;
    char *name;
    addr_t addr;
    addr_t mask;
    int index;
};
interface_addr_t *interface_addresses;

bool
ioloop_map_interface_addresses(void *context, interface_callback_t callback)
{
    struct ifaddrs *ifaddrs, *ifp;
    interface_addr_t *kept_ifaddrs = NULL, **ki_end = &kept_ifaddrs;
    interface_addr_t *new_ifaddrs = NULL, **ni_end = &new_ifaddrs;
    interface_addr_t **ip, *nif;
    char *ifname = NULL;
    int ifindex = 0;

    if (getifaddrs(&ifaddrs) < 0) {
        ERROR("getifaddrs failed: %s", strerror(errno));
        return false;
    }

    for (ifp = ifaddrs; ifp; ifp = ifp->ifa_next) {
        // Is this an interface address we can use?
        if (ifp->ifa_addr != NULL && ifp->ifa_netmask != NULL &&
            (ifp->ifa_addr->sa_family == AF_INET ||
             ifp->ifa_addr->sa_family == AF_INET6) &&
            (ifp->ifa_flags & IFF_UP) &&
            !(ifp->ifa_flags & IFF_POINTOPOINT))
        {
            bool keep = false;
            for (ip = &interface_addresses; *ip != NULL; ) {
                interface_addr_t *ia = *ip;
                // Same interface and address?
                if (!strcmp(ia->name, ifp->ifa_name) &&
                    ifp->ifa_addr->sa_family == ia->addr.sa.sa_family &&
                    ((ifp->ifa_addr->sa_family == AF_INET &&
                      ((struct sockaddr_in *)ifp->ifa_addr)->sin_addr.s_addr == ia->addr.sin.sin_addr.s_addr) ||
                     (ifp->ifa_addr->sa_family == AF_INET6 &&
                      !memcmp(&((struct sockaddr_in6 *)ifp->ifa_addr)->sin6_addr,
                              &ia->addr.sin6.sin6_addr, sizeof ia->addr.sin6.sin6_addr))) &&
                    ((ifp->ifa_netmask->sa_family == AF_INET &&
                      ((struct sockaddr_in *)ifp->ifa_netmask)->sin_addr.s_addr == ia->mask.sin.sin_addr.s_addr) ||
                     (ifp->ifa_netmask->sa_family == AF_INET6 &&
                      !memcmp(&((struct sockaddr_in6 *)ifp->ifa_netmask)->sin6_addr,
                              &ia->mask.sin6.sin6_addr, sizeof ia->mask.sin6.sin6_addr))))
                {
                    *ki_end = ia;
                    ki_end = &ia->next;
                    keep = true;
                    break;
                } else {
                    ip = &ia->next;
                }
            }
            // If keep is false, this is a new interface.
            if (!keep) {
                nif = calloc(1, strlen(ifp->ifa_name) + 1 + sizeof *nif);
                // We don't have a way to fix nif being null; what this means is that we don't detect a new
                // interface address.
                if (nif != NULL) {
                    nif->name = (char *)(nif + 1);
                    strcpy(nif->name, ifp->ifa_name);
                    if (ifp->ifa_addr->sa_family == AF_INET) {
                        nif->addr.sin = *((struct sockaddr_in *)ifp->ifa_addr);
                        nif->mask.sin = *((struct sockaddr_in *)ifp->ifa_netmask);
                    } else {
                        nif->addr.sin6 = *((struct sockaddr_in6 *)ifp->ifa_addr);
                        nif->mask.sin6 = *((struct sockaddr_in6 *)ifp->ifa_netmask);
                    }
                    *ni_end = nif;
                    ni_end = &nif->next;
                }
            }
        }
    }

    // Report and free deleted interface addresses...
    for (nif = interface_addresses; nif; ) {
        interface_addr_t *next = nif->next;
        callback(context, nif->name, &nif->addr, &nif->mask, nif->index, interface_address_deleted);
        free(nif);
        nif = next;
    }

    // Report added interface addresses...
    for (nif = new_ifaddrs; nif; nif = nif->next) {
        // Get interface index using standard API if AF_LINK didn't work.
        if (nif->index == 0) {
            if (ifindex != 0 && ifname != NULL && !strcmp(ifname, nif->name)) {
                nif->index = ifindex;
            } else {
                ifname = nif->name;
                ifindex = if_nametoindex(nif->name);
                nif->index = ifindex;
                INFO("Got interface index for " PUB_S_SRP " the hard way: %d", nif->name, nif->index);
            }
        }
        callback(context, nif->name, &nif->addr, &nif->mask, nif->index, interface_address_added);
    }

    // Restore kept interface addresses and append new addresses to the list.
    interface_addresses = kept_ifaddrs;
    for (ip = &new_ifaddrs; *ip; ip = &(*ip)->next)
        ;
    *ip = new_ifaddrs;
    return true;
}

// Invoke the specified executable with the specified arguments.   Call callback when it exits.
// All failures are reported through the callback.
subproc_t *
ioloop_subproc(const char *exepath, char *NULLABLE *argv, int argc, subproc_callback_t callback)
{
    subproc_t *subproc = calloc(1, sizeof *subproc);
    int i;
    pid_t pid;

    if (subproc == NULL) {
        callback(NULL, 0, "out of memory");
        return NULL;
    }
    if (argc > MAX_SUBPROC_ARGS) {
        callback(NULL, 0, "too many subproc args");
        subproc_free(subproc);
        return NULL;
    }

    subproc->argv[0] = strdup(exepath);
    if (subproc->argv[0] == NULL) {
        subproc_free(subproc);
        return NULL;
    }
    subproc->argc++;
    for (i = 0; i < argc; i++) {
        subproc->argv[i + 1] = strdup(argv[i]);
        if (subproc->argv[i + 1] == NULL) {
            subproc_free(subproc);
            return NULL;
        }
        subproc->argc++;
    }
    pid = vfork();
    if (pid == 0) {
        execv(exepath, subproc->argv);
        _exit(errno);
        // NOTREACHED
    }
    if (pid == -1) {
        callback(subproc, 0, strerror(errno));
        subproc_free(subproc);
        return NULL;
    }

    subproc->callback = callback;
    subproc->pid = pid;
    subproc->next = subprocesses;
    subprocesses = subproc;
    return subproc;
}

static void
dnssd_txn_callback(io_t *io)
{
    dnssd_txn_t *txn = (dnssd_txn_t *)io;
    int status = DNSServiceProcessResult(txn->sdref);
    if (status != kDNSServiceErr_NoError) {
        if (txn->close_callback != NULL) {
            txn->close_callback(txn->context, status);
        }
    }
}

void
dnssd_txn_finalize(io_t *io)
{
    dnssd_txn_t *txn = (dnssd_txn_t *)io;

    if (txn->finalize_callback) {
        txn->finalize_callback(txn->context);
    }
}

dnssd_txn_t *
ioloop_dnssd_txn_add(DNSServiceRef ref,
                     dnssd_txn_finalize_callback_t finalize_callback, dnssd_txn_close_callback_t close_callback)
{
    dnssd_txn_t *txn = calloc(1, sizeof(*txn));
    if (txn != NULL) {
        RETAIN(txn);
        io->sdref = sdref;
        txn->io.sock = DNSServiceRefSockFD(txn->sdref);
        txn->finalize_callback = finalize_callback;
        txn->close_callback = close_callback;
        ioloop_add_reader(&txn->io, dnssd_txn_callback, dnssd_txn_finalize);
    }
    return txn;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
