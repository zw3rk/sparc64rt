/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_FILE_RECOVERY_H
#define SPARC64RT_RUNTIME_FAMILY_FILE_RECOVERY_H

#include "runtime/family.h"
#include "runtime/family_file_completion.h"

/* Canonical component only, not guest syscall admission. Hold the exact
 * source-family guard and borrow the writable ordinary target. Reject private
 * family inodes without opening/duplicating them. The selected provider is
 * immutable for the image, and unknown identities conservatively select all
 * potentially aliasing source descriptions. Access modes/credentials/limits
 * must satisfy the independent service's documented native-context contract.
 *
 * Return0 only after the native result and all canonical reconciliation are
 * complete, including a native failure reported in *out_native_errno. A -1
 * after intent publication is infrastructure-uncertain, not an ordinary guest
 * errno: never resume stale execution. Output changes only on completion.
 * Absolute payload targets and cursor share one redo; retained unmapped COW
 * keys participate, and a partial COW tail survives a shrink. */
int sparc64_family_file_truncate(sparc64_family_guard_t *guard, int borrowed_target,
                              uint64_t length, sparc64_file_identity_policy_t policy,
                              int *out_native_errno);

/* Bounded positional-write component. The same exact-guard,
 * private-inode, identity and infrastructure-failure rules apply. Stage up to
 * SPARC64_FILE_CAPS_MAX_WRITE_BYTES immutable bytes before publishing the intent;
 * the independent service executes once and retains its exact short outcome.
 * Reconcile actual positive bytes before success, including retained unmapped
 * clean payloads. Known aliases use the actual byte intersection; unknown or
 * incomparable aliases conservatively refresh/charge whole clean pages. COW
 * payloads stay private. Output changes only after full reconciliation. This
 * does not authorize a guest syscall or unsynchronized native F_SETFL aliases.
 * O_APPEND selects a distinct staged operation at the frozen preflight EOF,
 * preserving the shared OFD cursor. As for sequential writes below, the
 * complete family guard excludes every admitted writer/resize/F_SETFL alias;
 * external/native writers are excluded. Validate the original caller offset
 * and its count range before replacing it with the append EOF. */
int sparc64_family_file_pwrite(sparc64_family_guard_t *guard, int borrowed_target,
                            uint64_t offset, const void *bytes, size_t count,
                            sparc64_file_identity_policy_t policy,
                            sparc64_file_caps_write_result_t *out);

/* Same bounded canonical reconciliation for one native sequential write.
 * Freeze cursor (or append EOF) and O_APPEND before headroom preflight; the
 * service validates the same pair before its first effect. Caller must hold
 * the complete family guard across every admitted write/resize/F_SETFL alias
 * and OFD cursor change, including read/readv, lseek and source-side copies.
 * External/native writers are excluded. One native write advances the
 * shared OFD cursor and handles append; cached recovery never advances it a
 * second time. No temporary seek/restore or positional-write emulation. */
int sparc64_family_file_write(sparc64_family_guard_t *guard, int borrowed_target,
                           const void *bytes, size_t count,
                           sparc64_file_identity_policy_t policy,
                           sparc64_file_caps_write_result_t *out);

/* Attributed counterparts freeze process limits and the existing
 * incarnation/MM/guest-TID tuple before staging. The owner must be this
 * guard's incarnation. No task pointer or reused numeric TID is authority.
 * Output is unchanged on failure; uncertain completion is still fatal. */
int sparc64_family_file_truncate_attributed(sparc64_family_guard_t *guard, int borrowed_target,
    uint64_t length, sparc64_file_identity_policy_t policy,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out);
int sparc64_family_file_pwrite_attributed(sparc64_family_guard_t *guard, int borrowed_target,
    uint64_t offset, const void *bytes, size_t count, sparc64_file_identity_policy_t policy,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out);
int sparc64_family_file_write_attributed(sparc64_family_guard_t *guard, int borrowed_target,
    const void *bytes, size_t count, sparc64_file_identity_policy_t policy,
    const sparc64_file_caps_call_context_t *caller, sparc64_family_file_completion_t *out);

/* Built-in guard-entry drain. The provisional exact guard is already held,
 * ordinary family redo has replayed, and no caller can observe this guard yet.
 * Do not enter recursively, use callbacks, or expose a guard after failure.
 * Every source-family entry checks intent, even after graceful leave. */
int sparc64_family_file_recover(sparc64_family_guard_t *guard);

#endif
