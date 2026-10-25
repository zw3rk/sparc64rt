/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/file_runtime_binding.h"

#include "linux/error.h"
#include "runtime/family_file_recovery.h"

#include <errno.h>
#include <string.h>

int sparc64_runtime_file_call_prepare(sparc64_runtime_file_call_t *call,
    sparc64_family_guard_t *guard, uint64_t mm_id, uint32_t guest_tid,
    sparc64_runtime_file_limits_t *limits, sparc64_linux_signals_t *signals,
    sparc64_file_identity_policy_t policy)
{
    if (call != NULL && call->fatal) {
        errno = EIO;
        return -1;
    }
    if (call == NULL || guard == NULL || !guard->held ||
        call->pending || call->ticket.operation_id != 0 ||
        guard->incarnation == 0 || mm_id == 0 || guest_tid == 0 ||
        limits == NULL || signals == NULL || signals->process == NULL ||
        signals->guest_tid != guest_tid ||
        !sparc64_file_identity_policy_valid(policy)) {
        errno = EINVAL;
        return -1;
    }
    if (sparc64_family_sources(guard) == NULL)
        return -1;
    sparc64_runtime_file_limit_values_t values;
    if (sparc64_runtime_file_limits_snapshot(limits, &values) != 0)
        return -1;
    sparc64_file_caps_call_context_t caller = {
        .owner_incarnation = guard->incarnation,
        .mm_id = mm_id,
        .worker_id = guest_tid,
        .fsize_soft = values.soft,
        .fsize_hard = values.hard
    };
    if (!sparc64_file_caps_call_context_valid(&caller)) {
        errno = EINVAL;
        return -1;
    }
    *call = (sparc64_runtime_file_call_t){
        .guard = guard, .signals = signals, .policy = policy, .caller = caller
    };
    return 0;
}

static bool record(sparc64_runtime_file_call_t *call)
{
    if (call == NULL || call->pending || call->fatal ||
        call->ticket.operation_id == 0 ||
        !sparc64_file_caps_call_context_equal(&call->ticket.caller, &call->caller)) {
        if (call != NULL)
            call->fatal = true;
        errno = EIO;
        return false;
    }
    const sparc64_file_caps_mutation_result_t *native = &call->ticket.native;
    if (native->native_errno != 0)
        call->guest_result = UINT64_C(0) - sparc64_linux_errno(native->native_errno);
    else
        call->guest_result = (uint64_t)native->transferred;
    call->pending = true;
    return true;
}

static ssize_t pwrite_attributed(int fd, const void *bytes, size_t count,
                                 uint64_t offset, void *opaque)
{
    sparc64_runtime_file_call_t *call = opaque;
    if (call == NULL || call->pending || call->fatal ||
        sparc64_family_file_pwrite_attributed(call->guard, fd, offset, bytes, count,
            call->policy, &call->caller, &call->ticket) != 0 || !record(call)) {
        if (call != NULL)
            call->fatal = true;
        errno = EIO;
        return -1;
    }
    if (call->ticket.native.native_errno != 0) {
        errno = call->ticket.native.native_errno;
        return -1;
    }
    return (ssize_t)call->ticket.native.transferred;
}

static ssize_t write_attributed(int fd, const sparc64_linux_write_request_t *request,
                                void *opaque)
{
    sparc64_runtime_file_call_t *call = opaque;
    if (call == NULL || request == NULL || call->pending || call->fatal ||
        sparc64_family_file_write_attributed(call->guard, fd, request->bytes,
            request->valid_size, call->policy, &call->caller, &call->ticket) != 0 ||
        !record(call)) {
        if (call != NULL)
            call->fatal = true;
        errno = EIO;
        return -1;
    }
    if (call->ticket.native.native_errno != 0) {
        errno = call->ticket.native.native_errno;
        return -1;
    }
    return (ssize_t)call->ticket.native.transferred;
}

static int truncate_attributed(int fd, uint64_t length, int *native_errno,
                               void *opaque)
{
    sparc64_runtime_file_call_t *call = opaque;
    if (call == NULL || native_errno == NULL || call->pending || call->fatal ||
        sparc64_family_file_truncate_attributed(call->guard, fd, length, call->policy,
            &call->caller, &call->ticket) != 0 || !record(call)) {
        if (call != NULL)
            call->fatal = true;
        errno = EIO;
        return -1;
    }
    *native_errno = call->ticket.native.native_errno;
    call->truncate_result = true;
    return 0;
}

static int open_result_attributed(uint32_t reserved_guest_fd,
                                  uint64_t guest_result, void *opaque)
{
    sparc64_runtime_file_call_t *call = opaque;
    bool linux_error = guest_result >= UINT64_MAX - UINT64_C(4094);
    if (call == NULL || call->fatal || !call->pending ||
        !call->truncate_result || call->open_result ||
        reserved_guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        (guest_result != reserved_guest_fd && !linux_error) ||
        (call->ticket.native.native_errno != 0 &&
         guest_result != call->guest_result) ||
        (call->ticket.native.native_errno == 0 &&
         call->ticket.native.transferred != 0)) {
        if (call != NULL)
            call->fatal = true;
        errno = EIO;
        return -1;
    }
    call->guest_result = guest_result;
    call->open_result = true;
    return 0;
}

void sparc64_runtime_file_call_bind(sparc64_runtime_file_call_t *call,
                               sparc64_linux_file_io_t *io)
{
    if (call == NULL || io == NULL)
        return;
    io->pwrite = pwrite_attributed;
    io->pwrite_context = call;
    io->max_pwrite = SPARC64_FILE_CAPS_MAX_WRITE_BYTES;
    io->canonical_write_request = write_attributed;
    io->canonical_write_request_context = call;
    io->max_canonical_write = SPARC64_FILE_CAPS_MAX_WRITE_BYTES;
    io->truncate = truncate_attributed;
    io->truncate_context = call;
    io->open_truncate_result = open_result_attributed;
    io->open_truncate_result_context = call;
}

int sparc64_runtime_file_call_complete(sparc64_runtime_file_call_t *call,
    uint64_t guest_result, uint64_t committed_pc, uint64_t expected_pc)
{
    if (call == NULL || call->fatal) {
        errno = EIO;
        return -1;
    }
    if (!call->pending)
        return 0;
    if (committed_pc != expected_pc || guest_result != call->guest_result ||
        call->guard == NULL || !call->guard->held ||
        call->guard->incarnation != call->caller.owner_incarnation ||
        sparc64_family_sources(call->guard) == NULL ||
        call->signals == NULL || call->signals->process == NULL ||
        call->signals->guest_tid != call->caller.worker_id) {
        errno = EIO;
        return -1;
    }
    sparc64_file_caps_mutation_result_t native = {0};
    if (sparc64_family_file_completion_take(&call->ticket, &call->caller, &native) != 0)
        return -1;
    call->pending = false;
    if (native.generated_sigxfsz &&
        !sparc64_linux_signal_enqueue_fsize(call->signals)) {
        call->fatal = true;
        errno = EIO;
        return -1;
    }
    return 0;
}
