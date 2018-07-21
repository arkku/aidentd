/*
 * log.h: Logging to syslog or stderr.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#ifndef AIDENTD_LOG_H
#define AIDENTD_LOG_H

#include "aidentd.h"

/// Initialise logging. Must be called before anything is logged.
void open_log(const char * const name, _Bool use_syslog);

/// Verbosity of logging; 0 is errors only and 3 is the maximum.
extern int verbosity;

/// Log an error based on `errno` (as per `perror`) and exit the
/// program with a failure code.
NORETURN void error(const char * const msg);

/// Log a warning based on `errno` (as per `perror`).
void warning(const char * const msg);

/// Log a notice formatted as with `printf`.
void notice(const char * restrict format, ...);

/// Log a debug message formatted as with `printf`.
void debug(const char * restrict format, ...);

#endif
