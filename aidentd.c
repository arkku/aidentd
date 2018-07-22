/*
 * aidentd.c: Arkku's identd for Linux, with forwarding/NAT support.
 * aidentd
 *
 * See enclosed README and LICENSE.
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#include "aidentd.h"
#include "privileges.h"
#include "conntrack.h"
#include "netlink.h"
#include "forwarding.h"

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <setjmp.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

const static char * const PROGRAM_NAME = "aidentd";
const static char * const VERSION_STRING = "1.0.2";

/// Prints the usage to `stderr` and exits.
NORETURN static void
usage(void) {
    (void) fprintf(stderr,
        "%s %s - Copyright (c) 2018 Kimmo Kulovesi <http://arkku.com/>\n\n"
        "Intended to be run by inetd; the query is done on stdin/stdout.\n\n"
        "Options:\n"
        "  -i           IP validation: instead of matching only the ports\n"
        "               require the destination to have the same IP as the\n"
        "               client asking for ident. This should not be enabled\n"
        "               on hosts _receiving_ forwarded queries (without -a).\n"
        "  -A           Put the original IP address in forwarded requests.\n"
        "               This is a non-standard protocol extension and may not\n"
        "               be compatible with all non-%s recipients. Any\n"
        "               receiving %s must use the option '-a' for the\n"
        "               address to be actually used (see below).\n"
        "  -a           Accept custom address in incoming queries (see above).\n"
        "               This allows matching connections behind NAT based on\n"
        "               IP address and not just the port pair. Set this option\n"
        "               on host receiving forwards from a router with '-A'.\n"
        "  -t seconds   Timeout for the lookup (including forwarding).\n"
        "  -u user      Run as user (default is to drop root).\n"
        "  -g group     Run as group (default is to drop root).\n"
        "  -k           Keep uid/gid and all privileges unchanged.\n\n"
        "  -f string    Fixed response to local (non-forwarded) queries.\n"
        "  -f !         Do not respond to non-forwarded queries at all.\n"
        "  -f *         Respond with error NO-USER to non-forwarded queries.\n"
        "  -f ?         Respond with error HIDDEN-USER to non-forwarded queries.\n\n"
        "  -l           Local only (disable forwarding).\n"
        "  -c path      Set path to conntrack executable (needed for forwarding).\n"
        "               (The default is \"%s\").\n"
        "  -v           Increase logging verbosity (can be repeated for more).\n"
        "  -q           Decrease logging verbosity (can be repeated for more).\n"
        "  -e           Output log to stderr instead of syslog. Debugging only;\n"
        "               this may be sent by inetd to the remote!\n",
            PROGRAM_NAME, VERSION_STRING, PROGRAM_NAME, PROGRAM_NAME, conntrack_path
    );
    (void) fputc('\n', stderr);
    exit(EXIT_SUCCESS);
}

/// Resolves `username` into its user id, returns `fallback` on failure.
static uid_t
uid_for_name(const char * const username, const uid_t fallback) {
    struct passwd * const p = getpwnam(username);
    return p ? p->pw_uid : fallback;
}

/// Resolves `groupname` into its group id, returns `fallback` on failure.
static gid_t
gid_for_name(const char * const groupname, const gid_t fallback) {
    struct group * const g = getgrnam(groupname);
    return g ? g->gr_gid : fallback;
}


/// The jump buffer for timeout alarm.
static sigjmp_buf timeout_jump;

/// Handle the timeout alarm by jumping out of any sub-queries.
NORETURN static void
handle_alarm(int sig) {
    siglongjmp(timeout_jump, sig);
}

/// Start the timer for `seconds`.
static int
timeout(const unsigned seconds) {
    struct sigaction sa = { .sa_flags = SA_RESETHAND };
    sa.sa_handler = (handle_alarm);

    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        warning("sigaction");
    }

    if (sigsetjmp(timeout_jump, 1) == 0) {
        (void) alarm(seconds);
        return 0;
    } else {
        return 1;
    }
}

void
cancel_timeout(void) {
    (void) alarm(0);
    (void) signal(SIGALRM, SIG_IGN);
}

void
block_timeout(void) {
    sigset_t set;
    (void) sigemptyset(&set);
    (void) sigaddset(&set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &set, NULL) < 0) {
        warning("sigprocmask (block)");
    }
}

void
unblock_timeout(void) {
    sigset_t set;
    (void) sigemptyset(&set);
    (void) sigaddset(&set, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &set, NULL) < 0) {
        warning("sigprocmask (unblock)");
    }
}

/// Read a single port from `p`, simply ignoring any non-digits.
/// If no digits are found, or the resulting value is not in the
/// range 1..65535, returns `0`.
static unsigned
read_port(const char *p, char **endptr) {
    while (*p && !isdigit(*p)) { ++p; }
    if (*p == '\0') {
        return 0;
    }
    long result = strtol(p, endptr, 10);
    if (result < 1U || result > 65535U) {
        return 0;
    }
    return (unsigned) result;
}

/// Reads an ident query from `input` to `query`.
/// Returns `true` on success, `false` on failure.
static bool
read_query(FILE * const input, ident_query *query, bool * got_address) {
    char buf[1004]; // RFC1413: 1000 characters maximum without EOL

    if (got_address) {
        *got_address = false;
    }

    if (!fgets(buf, sizeof buf, input)) {
        warning("Reading query failed");
        return query;
    }

    char *p = buf;
    if ((query->local_port = read_port(buf, &p)) == 0) {
        debug("Malformed query: could not read local port.");
        return false;
    }
    assert(p != NULL);
    if (!(p = strchr(p, ','))) {
        debug("Malformed query: no comma separator.");
        query->local_port = 0;
        return false;
    }
    ++p;
    if ((query->remote_port = read_port(p, NULL)) == 0) {
        debug("Malformed query: could not read remote port.");
        query->local_port = 0;
        return false;
    }

    if (!(query->ip_in_query_extension && (p = strchr(p, ':')))) {
        return true;
    }

    ++p;
    while (isspace(*p)) { ++p; };

    char * const address_from_query = p++;
    while (*p && !(isspace(*p) || iscntrl(*p)) ) { ++p; };
    *p = '\0';

    int af = AF_INET;
    static char ip_address[INET6_ADDRSTRLEN] = { '\0' };
    static union {
        struct in6_addr ipv6;
        struct in_addr ipv4;
    } addr;
    void *sockaddr = &(addr.ipv4);

    if (inet_pton(af, address_from_query, sockaddr) != 1) {
        af = AF_INET6;
        sockaddr = &(addr.ipv6);
        if (inet_pton(af, address_from_query, sockaddr) != 1) {
            debug("Could not parse IP from query: %s", address_from_query);
            return true;
        }
    }

    if (!inet_ntop(af, sockaddr, buf, sizeof ip_address)) {
        return true;
    }

    (void) strcpy(ip_address, buf);

    query->address_family = af;
    query->socket_address = sockaddr;
    query->ip_address = ip_address;

    if (got_address) {
        *got_address = true;
    }

    return true;
}

int query_fd = -1;
FILE *query_pipe = NULL;

int
main(int argc, char *argv[]) {
    ident_query query = { .local_port = 0, .remote_port = 0 };

    uid_t run_as_user = geteuid();
    gid_t run_as_group = getegid();
    unsigned timeout_seconds = 5;
    bool forwarding_enabled = true;
    bool validate_ip = false;
    bool keep_privileges = false;
    bool use_syslog = true;
    bool forward_original_ip = false;

    static char ip_address[INET6_ADDRSTRLEN] = { '\0' };
    struct sockaddr_storage peer;

    const char *fixed_local_result = NULL;
    char * volatile found_result = NULL;
    const char *error_result = "NO-USER";

    if (run_as_user == 0) {
        // If run as root, change uid/gid by default ("-u 0 -g 0" to keep)
        run_as_user = uid_for_name(PROGRAM_NAME, uid_for_name("nobody", 65534));
        run_as_group = gid_for_name(PROGRAM_NAME, gid_for_name("nogroup", 65534));
    }

    // Parse command-line arguments

    while (--argc) {
        const char *arg = *(++argv);

        if (arg[0] != '-') {
            errno = EINVAL;
            error(arg);
            continue;
        }

        if (arg[1] == '-') {
            arg += 2;
            if (strcmp(arg, "help") == 0) {
                usage();
            } else if (strcmp(arg, "version") == 0) {
                (void) fprintf(stderr, "%s %s\n", PROGRAM_NAME, VERSION_STRING);
                return EXIT_SUCCESS;
            } else {
                errno = EINVAL;
                error(arg);
            }
            continue;
        }

        int insufficient_values = 0;

        while (*(++arg)) {
            switch (*arg) {
            case 'k': // keep privileges
                keep_privileges = true;
                break;
            case 'u': // uid
                if (--argc > 0) {
                    ++argv;
                    struct passwd * const p = getpwnam(*argv);
                    if (p) {
                        run_as_user = p->pw_uid;
                    } else {
                        errno = 0;
                        long uid = strtol(*argv, NULL, 10);
                        if (!errno && uid >= 0) {
                            run_as_user = (uid_t) uid;
                        } else {
                            errno = EINVAL;
                            error(*argv);
                        }
                    }
                } else {
                    ++insufficient_values;
                }
                break;
            case 'g': // gid
                if (--argc > 0) {
                    ++argv;
                    struct group * const g = getgrnam(*argv);
                    if (g) {
                        run_as_group = g->gr_gid;
                    } else {
                        errno = 0;
                        long gid = strtol(*argv, NULL, 10);
                        if (!errno && gid >= 0) {
                            run_as_group = (gid_t) gid;
                        } else {
                            errno = EINVAL;
                            error(*argv);
                        }
                    }
                } else {
                    ++insufficient_values;
                }
                break;
            case 't': // timeout
                if (--argc > 0) {
                    int seconds = atoi(*(++argv));
                    if (seconds > 0) {
                        timeout_seconds = (unsigned) seconds;
                    } else {
                        timeout_seconds = 0;
                    }
                } else {
                    ++insufficient_values;
                }
                break;
            case 'f': // fixed local result
                if (--argc > 0) {
                    fixed_local_result = *(++argv);
                } else {
                    ++insufficient_values;
                }
                break;
            case 'a': // accept IP from query
                query.ip_in_query_extension = true;
                break;
            case 'A': // forward IP in query
                forward_original_ip = true;
                break;
            case 'i': // IP validation
                validate_ip = true;
                break;
            case 'l': // local only
                forwarding_enabled = false;
                break;
            case 'c': // conntrack path
                if (--argc > 0) {
                    conntrack_path = *(++argv);
                } else {
                    ++insufficient_values;
                }
                break;
            case 'v': // verbose
                ++verbosity;
                break;
            case 'q': // quiet
                if (verbosity  > 0) {
                    --verbosity;
                }
                break;
            case 'e': // stderr logging
                use_syslog = false;
                break;
            case '?':
            case 'h':
                usage();
                break;
            default: {
                    char unknown[2] = { *arg, '\0' };
                    errno = EINVAL;
                    error(unknown);
                    break;
                }
            }
        }

        if (insufficient_values) {
            errno = EINVAL;
            error("Missing values");
        }
    }

    open_log(PROGRAM_NAME, use_syslog);

    // Drop privileges

    if (!keep_privileges) {
        minimal_privileges_as(run_as_user, run_as_group, forwarding_enabled);
    }

    // Obtain peer IP

    {
        void *sockaddr = NULL;
        socklen_t peersize = sizeof peer;

        if (getpeername(STDIN_FILENO, (struct sockaddr *) &peer, &peersize) < 0) {
            if (validate_ip) {
                warning("getpeername failed (not run from inetd?)");
            } else {
                debug("%s: %s",
                      "getpeername failed (not run from inetd?)",
                      strerror(errno));
            }
        } else if (peer.ss_family == AF_INET) {
            sockaddr = &(((struct sockaddr_in *) &peer)->sin_addr);
            query.address_family = AF_INET;
        } else if (peer.ss_family == AF_INET6) {
            sockaddr = &(((struct sockaddr_in6 *) &peer)->sin6_addr);
            query.address_family = AF_INET6;
        } else {
            notice("Unknown address family %u", (unsigned) peer.ss_family);
        }
        if (sockaddr) {
            if (inet_ntop(peer.ss_family, sockaddr, ip_address, sizeof ip_address)) {
                if (validate_ip) {
                    query.socket_address = sockaddr;
                    query.address_family = peer.ss_family;
                    query.ip_address = ip_address;
                }
            } else {
                warning("inet_ntop");
            }
        } else {
            query.ip_in_query_extension = false;
        }
    }

    // Read the query

    {
        bool got_address = false;

        if (timeout(timeout_seconds)) {
            errno = ETIMEDOUT;
            error("Reading query");
        } else if (!read_query(stdin, &query, &got_address)) {
            notice("Invalid query from %s", *ip_address ? ip_address : "client");
            error_result = "INVALID-PORT";
            goto send_response;
        }
        cancel_timeout();

        notice("Ident query from %s: our port %u to remote port %u%s%s%s",
               *ip_address ? ip_address : "client",
               query.local_port, query.remote_port,
               got_address ? " (forwarded from " : "",
               got_address ? query.ip_address : "",
               got_address ? ")" : "");
    }

    // Try to resolve the query

    query.ip_in_query_extension = forward_original_ip;

    if (timeout(timeout_seconds)) {
        notice("Query timed out (%u, %u)!", query.local_port, query.remote_port);
        clean_up_forwarding();
        error_result = "UNKNOWN-ERROR";
    } else {
        if (!fixed_local_result) {
            found_result = netlink(&query);
        }

        if (!found_result && forwarding_enabled) {
            found_result = conntrack(&query);
        }
    }
    cancel_timeout();

    // Clean up resources that may have been left due to timeout

    if (query_fd >= 0) {
        (void) close(query_fd);
        query_fd = -1;
    }
    if (query_pipe) {
        (void) pclose(query_pipe);
        query_pipe = NULL;
    }

    // Send the response

send_response:
    if (!(found_result || forwarding_attempted) && fixed_local_result) {
        switch (*fixed_local_result) {
        case '\0':
        case '*':
            break;
        case '!':
            debug("Quitting without any result (option -f '%s').", fixed_local_result);
            goto clean_up;
        case '?':
            error_result = "HIDDEN-USER";
            break;
        default:
            found_result = strdup(fixed_local_result);
            break;
        }
    }

    if (timeout(timeout_seconds)) {
        errno = ETIMEDOUT;
        error("Writing response");
    } else {
        (void) printf("%u,%u:", query.local_port, query.remote_port);

        if (found_result) {
            (void) printf("USERID:%s:%s\r\n",
                          additional_info ? additional_info : "UNIX",
                          found_result);
        } else {
            (void) printf("ERROR:%s\r\n", additional_info ? additional_info : error_result);
        }
        (void) fflush(stdout);
    }

    // Clean up

clean_up:
    clean_up_forwarding();
    if (found_result) {
        free(found_result);
        found_result = NULL;
    }

    return EXIT_SUCCESS;
}
