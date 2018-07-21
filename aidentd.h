/*
 * aidentd.h: Arkku's identd for Linux, with forwarding/NAT support.
 * aidentd
 *
 * See enclosed README and LICENSE.
 *
 * Copyright (c) 2018 Kimmo Kulovesi, http://arkku.com
 */

#ifndef AIDENTD_H
#define AIDENTD_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef noreturn
#if __STDC_VERSION__ >= 201112L
#define noreturn _Noreturn // C11
#else
#ifdef __GNUC__
#define noreturn __attribute__((noreturn))
#endif
#endif
#endif // ifndef noreturn

#include "log.h"
#include <stdio.h>

/// The arguments of the ident query.
typedef struct ident_query {
    unsigned local_port;
    unsigned remote_port;
    const char *ip_address;
    void *socket_address;
    int address_family;
    _Bool ip_in_query_extension;
} ident_query;

/// Block the query timeout from occurring until `unblock_timeout` is called.
void block_timeout(void);

/// Unblock the query timeout after having been blocked by `block_timeout`.
void unblock_timeout(void);

/// Cancel the query timeout.
void cancel_timeout(void);

/// A file descriptor for use by sub-queries. Will be closed on timeout.
extern int query_fd;

/// A pipe handle for use by sub-queries. Will be closed on timeout.
extern FILE *query_pipe;

#endif
