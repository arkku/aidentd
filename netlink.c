/*
 * netlink.c: Discovering local connections via netlink.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#include "netlink.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pwd.h>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/// The sequence assigned to the last `send_request`, i.e., the
/// field `nlmsg_seq`.
static uint32_t sequence = 0;

/// Send the query to the netlink socket `sockfd`. Return the
/// sequence number assigned to the request, or 0 on error.
/// The number should be passed to `read_responses`.
static uint32_t
send_request(const int sockfd, const ident_query * const q) {
    debug("NL sending netlink request...");

    struct inet_diag_req req = {
        .idiag_family = AF_INET,
        .idiag_states = 0xFFFF,
        .idiag_ext = 1 << (INET_DIAG_INFO - 1),
        .id = {
            .idiag_sport = htons((uint16_t) q->local_port),
            .idiag_dport = htons((uint16_t) q->remote_port)
        }
    };

    struct nlmsghdr nlh = {
        .nlmsg_type= TCPDIAG_GETSOCK,
        .nlmsg_seq = ++sequence,
        .nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof req)),
        .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
    };

    if (q->address_family == AF_INET6) {
        req.idiag_family = AF_INET6;
    }

    if (q->address_family && q->socket_address) {
        switch (q->address_family) {
        case AF_INET:
            assert(sizeof(req.id.idiag_dst) >= sizeof(struct in_addr));
            (void) memcpy(req.id.idiag_dst, q->socket_address, sizeof(struct in_addr));
            break;
        case AF_INET6:
            assert(sizeof(req.id.idiag_dst) >= sizeof(struct in6_addr));
            (void) memcpy(req.id.idiag_dst, q->socket_address, sizeof(struct in6_addr));
            break;
        default:
            notice("Unknown address family for netlink: %u", (unsigned) q->address_family);
            break;
        }
    }

    //req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    //req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

    struct iovec iov[2] = {
        { .iov_base = &nlh, .iov_len = sizeof nlh },
        { .iov_base = &req, .iov_len = sizeof req }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };

    struct msghdr msg = {
        .msg_name = &sa, .msg_namelen = sizeof sa,
        .msg_iov = iov, .msg_iovlen = 2
    };

    if (sendmsg(sockfd, &msg, 0) < 0) {
        warning("sendmsg");
        return 0;
    }

    return nlh.nlmsg_seq;
}

/// Check the netlink response `msg` against the query `q`.
/// Returns the matching username or `NULL` if no match.
static char *
check_response(struct inet_diag_msg *msg, const ident_query * const q) {
    char srcbuf[INET6_ADDRSTRLEN] = { '\0' };
    char dstbuf[INET6_ADDRSTRLEN] = { '\0' };
    struct passwd *uid_info = NULL;

    unsigned local_port = (unsigned) ntohs(msg->id.idiag_sport);
    unsigned remote_port = (unsigned) ntohs(msg->id.idiag_dport);

    bool match = (local_port == q->local_port && remote_port == q->remote_port);

    (void) inet_ntop(msg->idiag_family, &(msg->id.idiag_src), srcbuf, sizeof srcbuf);
    (void) inet_ntop(msg->idiag_family, &(msg->id.idiag_dst), dstbuf, sizeof dstbuf);

    if (match && q->socket_address && q->address_family == msg->idiag_family) {
        unsigned address_size = 0;
        switch (q->address_family) {
        case AF_INET:
            address_size = sizeof(struct in_addr);
            break;
        case AF_INET6:
            address_size = sizeof(struct in6_addr);
            break;
        default:
            break;
        }

        if (address_size && memcmp(q->socket_address, msg->id.idiag_dst, address_size)) {
            match = false;
            debug("NL IP address mismatch: %s expected %s", dstbuf, q->ip_address);
        }
    }

    if (match) {
        uid_info = getpwuid(msg->idiag_uid);
    }

    debug("NL user %s (%u) %s port %u -> %s port %u (%s)",
          uid_info ? uid_info->pw_name : "?", msg->idiag_uid,
          srcbuf, local_port,
          dstbuf, remote_port,
          match ? "MATCH" : "no match");

    if (!match) {
        return NULL;
    }

    cancel_timeout();

    char *username = NULL;
    if (uid_info && uid_info->pw_name) {
        username = strdup(uid_info->pw_name);
    }
    if (!username) {
        const unsigned uid_bufsize = 16;
        username = malloc(uid_bufsize);
        if (!username) {
            error("malloc");
        }
        (void) snprintf(username, uid_bufsize, "%u", (unsigned) msg->idiag_uid);
    }

    notice("Connection matched: %s from %s port %u to %s port %u",
           username, srcbuf, local_port, dstbuf, remote_port);

    return username;
}

#define NL_BUF_SIZE 4096
#define NL_BUF_ALIGN 4

/// Read responses to the netlink query from `sockfd`, corresponding to the
/// sequence number `seq`. Returns the username matching the connection in
/// the query `q`, or `NULL` if no match.
static char *
read_responses(const int sockfd, const uint32_t seq, const ident_query * const q) {
    debug("NL reading responses...");

    unsigned char buf[NL_BUF_SIZE + NL_BUF_ALIGN] = { '\0' };
    unsigned char *aligned_buf = buf;
    {
        const int offset = aligned_buf % NL_BUF_ALIGN;
        if (offset) {
            aligned_buf += NL_BUF_ALIGN - offset;
        }
    }

    for (;;) {
        ssize_t len = recv(sockfd, aligned_buf, NL_BUF_SIZE, 0);
        struct nlmsghdr * const nlh = (struct nlmsghdr *) aligned_buf;

        if (len < 0) {
            warning("netlink recv");
            return NULL;
        }
        debug("NL read %lu bytes", (unsigned long) len);

        if (nlh->nlmsg_seq != seq) {
            debug("NL message seq mismatch: %u, expecting %u", nlh->nlmsg_seq, seq);
            continue;
        }

        while (NLMSG_OK(nlh, len)) {
            switch (nlh->nlmsg_type) {
            case NLMSG_DONE:
                debug("NL done.");
                return NULL;
            case NLMSG_ERROR:
                errno = EIO;
                warning("NL returned error!");
                return NULL;
            default: {
                    struct inet_diag_msg *msg = (struct inet_diag_msg *) NLMSG_DATA(nlh);
                    if (msg) {
                        char *result = check_response(msg, q);
                        if (result) {
                            return result;
                        }
                    }
                    break;
                }
            }

            nlh = NLMSG_NEXT(nlh, len); 
        }
    }

    return NULL;
}

char *
netlink(const ident_query * const query) {
    if ((query_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) < 0) {
        warning("socket");
        return NULL;
    }

    const uint32_t seq = send_request(query_fd, query);
    char * const result = seq ? read_responses(query_fd, seq, query) : NULL;

    debug("NL closing");
    block_timeout();
    (void) close(query_fd);
    query_fd = -1;
    unblock_timeout();

    return result;
}
