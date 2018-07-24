/*
 * log.c: Logging to syslog or stderr.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#include "aidentd.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

int verbosity = 2;

static bool log_to_syslog = false;

void
open_log(const char * const name, bool use_syslog) {
    log_to_syslog = use_syslog;
    if (log_to_syslog) {
        openlog(name, LOG_PID, LOG_DAEMON);
    }
}

void
debug(const char * restrict format, ...) {
    if (verbosity < 3) {
        return;
    }
    va_list args;
    va_start(args, format);
    if (log_to_syslog) {
        vsyslog((verbosity > 3) ? LOG_NOTICE : LOG_DEBUG, format, args);
    } else {
        (void) fputs("# ", stderr);
        (void) vfprintf(stderr, format, args);
        (void) fputc('\n', stderr);
    }
    va_end(args);
}

void
notice(const char * restrict format, ...) {
    if (verbosity < 2) {
        return;
    }
    va_list args;
    va_start(args, format);
    if (log_to_syslog) {
        vsyslog(LOG_NOTICE, format, args);
    } else {
        (void) fputs("Notice: ", stderr);
        (void) vfprintf(stderr, format, args);
        (void) fputc('\n', stderr);
    }
    va_end(args);
}

void
warning(const char * const msg) {
    if (verbosity < 1) {
        return;
    }
    if (log_to_syslog) {
        syslog(LOG_WARNING, "Warning: %s: %s", msg, strerror(errno));
    } else {
        (void) fputs("Warning: ", stderr);
        perror(msg);
    }
}

NORETURN void
error(const char * const msg) {
    if (log_to_syslog) {
        syslog(LOG_ERR, "ERROR: %s: %s", msg, strerror(errno));
    } else {
        (void) fputs("ERROR: ", stderr);
        perror(msg);
    }
    closelog();
    exit(EXIT_FAILURE);
}
