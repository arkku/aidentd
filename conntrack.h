/*
 * conntrack.h: Connection tracking for forwarding to masqueraded hosts.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#ifndef AIDENTD_CONNTRACK_H
#define AIDENTD_CONNTRACK_H

#include "aidentd.h"

extern const char *conntrack_path;

/// Query the conntrack program at `conntrack_path` and forward the
/// query to any discovered masqueraded connection.
///
/// Returns the discovered username for the connection matching `query`,
/// or `NULL` otherwise. Any returned username must be freed with `free`.
/// If forwarding was attempted (even if no match was returned), the
/// flag `forwarding_attempted` will be set (see `forwarding.h`).
char *conntrack(const ident_query * const query);

#endif
