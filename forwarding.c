/*
 * forwarding.c: Forwarding queries to other ident servers.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#include "forwarding.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned ident_port = 113;

/// Close `query_fd` if it's non-negative, and assign -1 to it.
static void
close_query_fd(void) {
    if (query_fd >= 0) {
        block_timeout();
        debug("FWD closing socket");
        (void) close(query_fd);
        query_fd = -1;
        unblock_timeout();
    }
}

/// The address info for forwarding the connection.
/// This is in global scope in order to be freed by the call to
/// `clean_up_forwarding`.
static struct addrinfo *forward_address = NULL;

bool forwarding_attempted = false;

char *additional_info = NULL;

/// Fields in the ident response
enum fields {
    FIELD_PORTS = 0,
    FIELD_REPLY_TYPE,
    FIELD_INFO,
    FIELD_USERID,
    FIELD_EOL
};

char *
forward_query(const ident_query * const query, const char * const destination) {
    char buf[513]; // RFC1413: 512 characters maximum user id
    char *response = NULL;

    if (snprintf(buf, sizeof buf, "%u", ident_port) <= 0) {
        error("FWD snprintf port");
    }

    debug("FWD to %s port %s", destination, buf);

    {
        struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        };

        const int error_result = getaddrinfo(destination, buf, &hints, &forward_address);
        if (error_result) {
            errno = EIO;
            error(gai_strerror(error_result));
        }
    }

    close_query_fd();
    for (struct addrinfo *rp = forward_address; rp; rp = rp->ai_next) {
        if ((query_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
            debug("FWD socket: %s", strerror(errno));
            continue;
        }

        debug("FWD connecting to %s...", destination);
        if (connect(query_fd, rp->ai_addr, rp->ai_addrlen) < 0) {
            debug("FWD connect: %s", strerror(errno));
            close_query_fd();
            continue;
        }
    }
    clean_up_forwarding();
    forwarding_attempted = true;

    if (query_fd < 0) {
        debug("FWD to %s failed", destination);
        return NULL;
    }

    {
        bool with_ip = query->ip_in_query_extension && (query->ip_address != NULL);
        int to_send = snprintf(buf, sizeof buf, "%u,%u%s%s\r\n",
                               query->local_port, query->remote_port,
                               with_ip ? " : " : "",
                               with_ip ? query->ip_address : "");
        if (to_send <= 0 || to_send >= sizeof buf) {
            error("FWD snprintf query");
        }

        int bytes_sent = 0;
        do {
            int sent = send(query_fd, buf + bytes_sent, to_send - bytes_sent, MSG_NOSIGNAL);
            if (sent <= 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                }
                notice("FWD send: %s", strerror(errno));
                break;
            }
            bytes_sent += sent;
        } while (bytes_sent > to_send);

        if (bytes_sent < to_send) {
            debug("FWD query not written: %s", buf);
            goto clean_up;
        }
    }

    {
        enum fields field = FIELD_PORTS;
        char *p = buf;
        char *end_of_buffer = buf + (sizeof(buf) - 2);
        bool is_error = false;
        do {
            if (recv(query_fd, p, 1, 0) != 1) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                }
                notice("FWD to %s recv error: %s", destination, strerror(errno));
                break;
            }

            const char c = *p;
            if (c == '\0') {
                notice("FWD to %s received NUL character", destination);
                break;
            }

            if ((field != FIELD_USERID && c == ':') || c == '\r' || c == '\n') {
                *p = '\0';
                switch (field++) {
                case FIELD_PORTS:
                    // should echo the ports but let's not bother to check
                    break;
                case FIELD_REPLY_TYPE:
                    is_error = strcmp(buf, "USERID") ? true : false;
                    debug("FWD received response type: %s", buf);
                    break;
                case FIELD_INFO:
                    if (*buf) {
                        block_timeout();
                        additional_info = strdup(buf);
                        unblock_timeout();
                    }
                    if (is_error) {
                        debug("FWD %s gave error: %s", destination, buf);
                        goto clean_up;
                    } else {
                        debug("FWD received system type: %s", buf);
                    }
                    break;
                case FIELD_USERID:
                    response = buf;
                    debug("FWD received userid: %s", response);
                case FIELD_EOL:
                    break;
                }
                p = buf;

                if (!response && (c == '\r' || c == '\n')) {
                    debug("FWD to %s got premature EOL", destination);
                    break;
                }
            } else if (field == FIELD_USERID || !(c == ' ' || c == '\t' || c < ' ' || c >= 127)) {
                // ignore space except in the user id
                ++p;
            }
        } while (!(response || p == end_of_buffer));

        if (!(response || is_error) && field == FIELD_USERID && p != buf) {
            debug("FWD to %s: userid truncated before EOL", destination);
            *p = '\0';
            response = buf;
        }
    }

clean_up:
    close_query_fd();

    if (response) {
        cancel_timeout();
        char * const username = strdup(response);
        if (!username) {
            error("strdup");
        }
        notice("Forwarded query (%u, %u) to %s returned user: %s",
               query->local_port, query->remote_port, destination, username);
        return username;
    } else if (additional_info) {
        notice("Forwarded query (%u, %u) to %s returned status: %s",
               query->local_port, query->remote_port, destination, additional_info);
    } else {
        debug("FWD to %s did not return a result", destination);
    }

    return NULL;
}

void
clean_up_forwarding(void) {
    if (forward_address) {
        block_timeout();
        freeaddrinfo(forward_address);
        forward_address = NULL;
        unblock_timeout();
    }

    if (additional_info) {
        block_timeout();
        free(additional_info);
        unblock_timeout();
    }
}
