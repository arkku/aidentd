/*
 * privileges.c: Running with minimal privileges and capabilities.
 * aidentd
 *
 * Copyright (c) 2018 Kimmo Kulovesi, https://arkku.com
 */

#include "aidentd.h"
#include "conntrack.h"
#include "privileges.h"

#include <fcntl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof(*(arr)))

/// Retain `num_caps` capabilities from `caps` across `seteuid`.
static void
retain_capabilities(const int num_caps, const cap_value_t * const caps) {
    if (num_caps < 1) { return; }

    debug("Retaining %d capabilities...", num_caps);

    cap_t capabilities;
    capabilities = cap_get_proc();

    if (cap_clear(capabilities)) {
        error("cap_clear");
    }
    if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, caps, CAP_SET)) {
        error("cap_set_flag (effective set)");
    }
    if (cap_set_flag(capabilities, CAP_PERMITTED, num_caps, caps, CAP_SET)) {
        error("cap_set_flag (permitted set)");
    }
    if (cap_set_proc(capabilities)) {
        error("cap_set_proc (retain)");
    }
    (void) cap_free(capabilities);

    if (prctl(PR_SET_KEEPCAPS, 1L)) {
        error("prctl (keep caps on)");
    }
}

/// Make `num_caps` capabilities from `caps` inheritable and effective.
static void
inheritable_capabilities(const int num_caps, const cap_value_t * const caps) {
    if (num_caps < 1) { return; }

    debug("Making %d capabilities inheritable...", num_caps);

    cap_t capabilities;
    capabilities = cap_get_proc();

    if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, caps, CAP_SET)) {
        error("cap_set_flag (effective set)");
    }
    if (cap_set_flag(capabilities, CAP_INHERITABLE, num_caps, caps, CAP_SET)) {
        error("cap_set_flag (inheritable set)");
    }
    if (cap_set_proc(capabilities)) {
        error("cap_set_proc (inheritable)");
    }

    (void) cap_free(capabilities);
}

/// Discord `num_caps` capabilities from `caps` (unset effective and
/// permitted).
static void
discard_capabilities(const int num_caps, const cap_value_t * const caps) {
    if (num_caps < 1) { return; }

    cap_t capabilities;
    capabilities = cap_get_proc();

    debug("Dropping %d capabilities...", num_caps);

    if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, caps, CAP_CLEAR)) {
        warning("cap_set_flag (effective clear)");
    }
    if (cap_set_flag(capabilities, CAP_PERMITTED, num_caps, caps, CAP_CLEAR)) {
        warning("cap_set_flag (permitted clear)");
    }
    if (cap_set_proc(capabilities)) {
        warning("cap_set_proc (discard)");
    }
    (void) cap_free(capabilities);

    if (prctl(PR_SET_KEEPCAPS, 0L)) {
        warning("prctl (keep caps on)");
    }
}

/// Does `capabilities` contain as effective and inheritable all `num_caps`
/// capabilities from `caps`?
static bool
already_have_capabilities(const cap_t capabilities, const int num_caps, const cap_value_t * const caps) {
    for (int i = 0; i < num_caps; ++i) {
        cap_flag_value_t inheritable, effective;
        const cap_value_t cap = caps[i];

        if (cap_get_flag(capabilities, cap, CAP_INHERITABLE, &inheritable)) {
            error("cap_get_flag");
        }
        if (cap_get_flag(capabilities, cap, CAP_EFFECTIVE, &effective)) {
            error("cap_get_flag");
        }

        if (inheritable != CAP_SET || effective != CAP_SET) {
            return false;
        }
    }
    return true;
}

/// Set the capabilities of `file` to have inheritable and effictive all
/// `num_caps` capabilities from `caps`.
static void
set_file_capabilites(const char * const file, const int num_caps, const cap_value_t * const caps) {
    if (num_caps < 1) { return; }

    cap_t capabilities;
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        error(file);
    }
    if (!(capabilities = cap_get_fd(fd))) {
        if (errno != ENODATA) {
            warning("get file capabilities");
        }
        if ((capabilities = cap_init()) == NULL) {
            error("cap_init");
            return;
        }
    }

    if (!already_have_capabilities(capabilities, num_caps, caps)) {
        // Obtain needed effective capabilities
        cap_t needed = cap_get_proc();
        const cap_value_t needed_caps[] = { CAP_SETFCAP, CAP_FOWNER };
        if (cap_set_flag(needed, CAP_EFFECTIVE, ARRAY_SIZE(needed_caps), needed_caps, CAP_SET)) {
            error("cap_set_flag (needed effective)");
        }
        if (cap_set_proc(needed)) {
            error("cap_set_proc (needed)");
        }
        (void) cap_free(needed);

        // Set the file capabilities
        if (cap_set_flag(capabilities, CAP_INHERITABLE, num_caps, caps, CAP_SET)) {
            error("cap_set_flag (inheritable set)");
        }
        if (cap_set_flag(capabilities, CAP_EFFECTIVE, num_caps, caps, CAP_SET)) {
            error("cap_set_flag (effective set)");
        }

        char *text = cap_to_text(capabilities, NULL);
        notice("Setting capabilities: %s %s", file, text);
        (void) cap_free(text);

        if (cap_set_fd(fd, capabilities)) {
            warning(file);
        }
    }

    (void) cap_free(capabilities);
}

void
minimal_privileges_as(const uid_t uid, const gid_t gid, const bool need_admin) {
    const cap_value_t cap_list[] = {
        CAP_NET_ADMIN,
        CAP_SETPCAP, CAP_SETGID, CAP_SETUID
    };
    const cap_value_t *all_caps = cap_list;
    int num_caps = (int) ARRAY_SIZE(cap_list);
    int needed_caps = 1;
    bool change_user = true;

    if (!need_admin) {
        --needed_caps;
        --num_caps;
        ++all_caps;
    }

    if ((uid == 0 && gid == 0) || (uid == geteuid() && gid == getegid())) {
        num_caps -= 2; // no need to change
        change_user = false;
    }

    // Set file capabilities of the target executable
    set_file_capabilites(conntrack_path, needed_caps, all_caps);

    if (change_user) {
        debug("Changing to uid:gid = %u:%u", (unsigned) uid, (unsigned) gid);

        // Keep the necessary capabilities over uid/gid change
        retain_capabilities(num_caps, all_caps);

        if (setregid(gid, gid)) {
            error("could not run as group");
        }
        if (setreuid(uid, uid)) {
            error("could not run as user");
        }
    }

    cap_t current = cap_get_proc();
    if (!already_have_capabilities(current, needed_caps, all_caps)) {
        // Make the needed capabilities inheritable
        inheritable_capabilities(needed_caps, all_caps);
    }
    (void) cap_free(current);

    // Drop the capabilities that are not needed
    discard_capabilities(num_caps - needed_caps, all_caps + needed_caps);
}
