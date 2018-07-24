/*
 * forwarding.h: Forwarding queries to other ident servers.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#ifndef AIDENTD_FORWARDING_H
#define AIDENTD_FORWARDING_H

#include "aidentd.h"

// Forwards `query` to host `destination`, port (global) `ident_port`.
///
/// Returns the discovered username for the connection matching `query`,
/// or `NULL` otherwise. Any returned username must be freed with `free`.
/// If forwarding was attempted (even if no match was returned), the
/// flag `forwarding_attempted` will be set. See also `additional_info`.
char *forward_query(const ident_query * const query, const char * const destination);

/// Free any resources allocated by forwarding (including `additional_info`).
void clean_up_forwarding(void);

/// A copy of the "additional info" (usually system type) returned by the
/// previous successful `forward_query`, or the error response returned by
/// the previous query where the remote system sent an error status.
extern char *additional_info;

/// The port to which forwarded identd queries are directed (default 113).
extern unsigned ident_port;

/// Has forwarding been attempted?
/// 
/// This is used to distinguish cases where no connection was found from
/// cases where forwarding was unsuccesful.
extern _Bool forwarding_attempted;

#endif
