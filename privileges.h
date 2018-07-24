/*
 * privileges.h: Running with minimal privileges and capabilities.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#ifndef AIDENTD_PRIVILEGES_H
#define AIDENTD_PRIVILEGES_H

#include <sys/types.h>
#include <stdbool.h>

/// Run with minimal privileges as user `uid` and group `gid`.
/// If both `uid` and `gid` are `0`, no change is made.
/// The argument `need_admin` indicates whether `CAP_NET_ADMIN`
/// is needed (it is for `conntrack`).
void minimal_privileges_as(const uid_t uid, const gid_t gid, const bool need_admin);

#endif
