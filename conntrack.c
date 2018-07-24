/*
 * conntrack.c: Connection tracking for forwarding to masqueraded hosts.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#include "conntrack.h"
#include "forwarding.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *conntrack_path = "/usr/sbin/conntrack";

char *
conntrack(const ident_query * const q) {
    char buf[512];
    int bufsize = sizeof buf;

    forwarding_attempted = false;

    {
        int written = snprintf(buf, bufsize,
                               "%s -L -p tcp --reply-port-src=%u --reply-port-dst=%u 2>/dev/null",
                               conntrack_path ? conntrack_path : "conntrack",
                               q->remote_port, q->local_port);
        if (written < 0 || written >= bufsize) {
            if (!errno) {
                errno = ERANGE;
            }
            error("CT command buffer");
        }

        if (q->ip_address && q->ip_address[0]) {
            int result = snprintf(buf + written, bufsize - written, " --reply-src=%s", q->ip_address);
            if (result < 0 || result >= (bufsize - written)) {
                if (!errno) {
                    errno = ERANGE;
                }
                error("CT command buffer");
            }
        }
    }

    debug("CT command: %s", buf);
    if (!(query_pipe = popen(buf, "r"))) {
        warning(buf);
        return NULL;
    }

    debug("CT reading responses...");

    bool match = false;
    const char *client = NULL;
    const char *server = NULL;
    const char *source = NULL;
    unsigned client_port = 0;

    while (!match && fgets(buf, bufsize, query_pipe)) {
        char * const lan_side = strstr(buf, "src=");
        if (!lan_side) {
            debug("CT skipping: %s", buf);
            continue;
        }
        *(lan_side - 1) = '\0';

        char * const nat_side = strstr(lan_side + 4, "src=");
        if (!nat_side) {
            debug("CT skipping: %s", buf);
            continue;
        }
        *(nat_side - 1) = '\0';

        char *p;
        client = NULL;
        server = NULL;
        source = NULL;

        p = strstr(lan_side, "sport=");
        client_port = p ? (unsigned) strtol(p + 6, NULL, 10) : 0;

        p = strstr(nat_side, "sport=");
        const unsigned server_port = p ? (unsigned) strtol(p + 6, NULL, 10) : 0;

        p = strstr(nat_side, "dport=");
        const unsigned router_port = p ? (unsigned) strtol(p + 6, NULL, 10) : 0;

        p = strchr(lan_side + 4, ' ');
        if (p) {
            *p = '\0';
            client = lan_side + 4;
        }

        p = strstr(nat_side, "dst=");
        if (p) {
            source = p + 4;
            p = strchr(source, ' ');
            if (p) {
                *p = '\0';
            }
        }
        p = strchr(nat_side + 4, ' ');
        if (p) {
            *p = '\0';
            server = nat_side + 4;
        }

        match = client && source && q->remote_port == server_port && q->local_port == router_port;
        if (match && strcmp(client, source) == 0) {
            // Local connection, do not forward to ourselves
            // (Normally matched in netlink, but it may be disabled.)
            debug("CT found matching local connection");
            match = false;
        }

        if (server && q->ip_address && strcmp(q->ip_address, server)) {
            notice("%s returned a non-matching IP: %s expected %s",
                   conntrack_path, server, q->ip_address);
            // In theory this should not happen, so it is safer to ignore
            // the error here as it may be due to non-canonical IP
            // representation. Logging as notice as it may indicate
            // changes in conntrack behaviour and/or syntax.
            //match = false;
        }

        debug("CT %s:%u -> %s:%u -> %s:%u (%s)",
              server ? server : "", server_port,
              source ? source : "", router_port,
              client ? client : "", client_port,
              match ? "FORWARD" : "no forward");
    }

    debug("CT closing");

    block_timeout();
    (void) pclose(query_pipe);
    query_pipe = NULL;
    unblock_timeout();

    char *result = NULL;

    if (match) {
        notice("Matched connection from %s port %u to %s port %u, forwarding to %s as port %u",
               source ? source : "router", q->local_port,
               server ? server : "server", q->remote_port,
               client, client_port);
        ident_query forwarded_query = {
            .local_port = client_port,
            .remote_port = q->remote_port,
        };
        if (q->ip_in_query_extension && (server || q->ip_address)) {
            forwarded_query.ip_in_query_extension = true;
            forwarded_query.ip_address = server ? server : q->ip_address;
        }
        result = forward_query(&forwarded_query, client);
    }

    return result;
}
