/*
 * netlink.h: Discovering local connections via netlink.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#ifndef AIDENTD_NETLINK_H
#define AIDENTD_NETLINK_H

#include "aidentd.h"

/// Query netlink for local connections matching `query`. This is
/// specific to Linux, but considerably faster than iterating through
/// all entries in `/proc/net/tcp` . However, it is possible that
/// future versions of Linux may break compatibility, so this is the
/// first thing to check when encountering failed local queries.
///
/// Returns the discovered username for the connection matching `query`,
/// or `NULL` otherwise. Any returned username must be freed with `free`.
char *netlink(const ident_query * const query);

#endif
