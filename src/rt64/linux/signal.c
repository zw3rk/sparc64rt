/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/signal.h"

#include <errno.h>
#include <string.h>

#define SA_ONSTACK UINT64_C(0x08000000)
#define SA_RESTART UINT64_C(0x10000000)
#define SA_NODEFER UINT64_C(0x40000000)
#define SA_RESETHAND UINT64_C(0x80000000)
#define SA_KNOWN UINT64_C(0xd8000807)
#define SS_ONSTACK UINT32_C(1)
#define SS_DISABLE UINT32_C(2)
#define SS_AUTODISARM UINT32_C(0x80000000)
#define UNBLOCKABLE ((UINT64_C(1) << 8) | (UINT64_C(1) << 18))

static uint64_t fail(unsigned int error)
{
    return UINT64_C(0) - error;
}

static uint64_t get64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

static uint32_t get32(const unsigned char *bytes)
{
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i)
        value |= (uint32_t)bytes[i] << (8 * i);
    return value;
}

static void put64(unsigned char *bytes, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        bytes[i] = (unsigned char)(value >> (8 * i));
}

static void put32(unsigned char *bytes, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        bytes[i] = (unsigned char)(value >> (8 * i));
}

static uint64_t signal_bit(unsigned int signal)
{
    return UINT64_C(1) << (signal - 1);
}

static bool default_ignore(unsigned int signal)
{
    return signal == 17 || signal == 23 || signal == 28;
}

static bool ignored(unsigned int signal, const sparc64_signal_action_t *action)
{
    return action->handler == 1 || (action->handler == 0 && default_ignore(signal));
}

/* Process-directed ignored-signal admission uses the PID task's current
 * blocked mask. rt_sigsuspend's saved mask is not Linux real_blocked state. */
static uint64_t thread_admission_mask(const sparc64_linux_signals_t *signals)
{
    return signals->thread.blocked;
}

static uint64_t process_admission_mask(const sparc64_signal_process_t *process)
{
    for (const sparc64_linux_signals_t *worker = process->workers;
         worker != NULL; worker = worker->next)
        if (worker->guest_tid == process->pid)
            return thread_admission_mask(worker);
    return process->leader_blocked;
}

/* Keep a value snapshot because the leader view may detach while the guest
 * process and its sibling views remain alive. */
static void update_leader_masks(sparc64_linux_signals_t *signals)
{
    if (signals != NULL && signals->process != NULL &&
        signals->guest_tid == signals->process->pid) {
        signals->process->leader_blocked = signals->thread.blocked;
    }
}

static void sync_child_mask(sparc64_linux_signals_t *signals)
{
    if (signals->process->child_mask_sync != NULL)
        signals->process->child_mask_sync(
            signals->process->child_action_context,
            (signals->thread.blocked & signal_bit(17)) != 0);
}

bool sparc64_linux_signal_wait_mask_begin(sparc64_linux_signals_t *signals,
                                      uint64_t temporary_mask)
{
    if (signals == NULL || signals->process == NULL ||
        signals->thread.restore_mask) {
        errno = EINVAL;
        return false;
    }
    signals->thread.saved_mask = signals->thread.blocked;
    signals->thread.restore_mask = true;
    signals->thread.blocked = temporary_mask & ~UNBLOCKABLE;
    update_leader_masks(signals);
    sync_child_mask(signals);
    return true;
}

bool sparc64_linux_signal_wait_mask_finish(sparc64_linux_signals_t *signals,
                                       bool interrupted_for_delivery)
{
    if (signals == NULL || signals->process == NULL ||
        !signals->thread.restore_mask) {
        errno = EINVAL;
        return false;
    }
    if (!interrupted_for_delivery) {
        signals->thread.blocked = signals->thread.saved_mask;
        signals->thread.saved_mask = 0;
        signals->thread.restore_mask = false;
        update_leader_masks(signals);
        sync_child_mask(signals);
    }
    return true;
}

/* Match Linux dequeue_signal: inspect the directed queue before the shared
 * queue, with synchronous-class signals first within the selected queue. */
static bool next_candidate(const sparc64_linux_signals_t *signals,
                           uint64_t thread_pending, uint64_t process_pending,
                           bool *directed, unsigned int *signal)
{
    uint64_t available = thread_pending & ~signals->thread.blocked;
    *directed = available != 0;
    if (!*directed)
        available = process_pending & ~signals->thread.blocked;
    if (available == 0)
        return false;
    if ((available & UINT64_C(0x400004d8)) != 0)
        available &= UINT64_C(0x400004d8);
    *signal = 1;
    while ((available & signal_bit(*signal)) == 0)
        ++*signal;
    return true;
}

static bool enqueue_standard(sparc64_linux_signals_t *signals, unsigned int signal,
                             int32_t code, uint32_t pid, uint32_t uid,
                             bool directed, uint64_t admission_mask,
                             bool *queued)
{
    if (queued != NULL)
        *queued = false;
    uint64_t bit = signal_bit(signal);
    if ((admission_mask & bit) == 0 &&
        ignored(signal, &signals->process->actions[signal - 1]))
        return true;
    uint64_t *pending = directed ? &signals->thread.pending :
                                   &signals->process->pending;
    if ((*pending & bit) != 0)
        return true; /* Standard signals keep the first siginfo. */
    unsigned char *info = directed ? signals->thread.information[signal - 1] :
                                     signals->process->information[signal - 1];
    memset(info, 0, 128);
    put32(info, signal);
    put32(info + 8, (uint32_t)code);
    put32(info + 16, pid);
    put32(info + 20, uid);
    *pending |= bit;
    if (queued != NULL)
        *queued = true;
    return true;
}

bool sparc64_linux_signal_enqueue_external(sparc64_linux_signals_t *signals,
                                       unsigned int signal, int32_t code,
                                       uint32_t sender_pid, uint32_t sender_uid)
{
    if (signals == NULL || signals->process == NULL || signals->process->space == NULL ||
        (signal != 10 && signal != 12 && signal != 15) ||
        (code != 0 && code != -6))
        return false;
    bool directed = code == -6;
    uint64_t admission_mask = directed ? thread_admission_mask(signals) :
                                        process_admission_mask(signals->process);
    return enqueue_standard(signals, signal, code, sender_pid, sender_uid,
                            directed, admission_mask, NULL);
}

bool sparc64_linux_signal_enqueue_pipe(sparc64_linux_signals_t *signals)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL)
        return false;
    return enqueue_standard(signals, 13, 0, signals->process->pid,
                            signals->process->uid, true,
                            thread_admission_mask(signals), NULL);
}

bool sparc64_linux_signal_enqueue_fsize(sparc64_linux_signals_t *signals)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL)
        return false;
    return enqueue_standard(signals, 25, 0, signals->process->pid,
                            signals->process->uid, true,
                            thread_admission_mask(signals), NULL);
}

bool sparc64_linux_signal_enqueue_child(sparc64_linux_signals_t *signals,
                                    int32_t code, uint32_t child_pid,
                                    uint32_t child_uid, int32_t status)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL || child_pid == 0 ||
        (code != 1 && code != 2 && code != 3))
        return false;
    bool queued = false;
    if (!enqueue_standard(signals, 17, code, child_pid, child_uid, false,
                          process_admission_mask(signals->process), &queued))
        return false;
    if (queued)
        put32(signals->process->information[16] + 24, (uint32_t)status);
    return true;
}

bool sparc64_linux_signal_next(const sparc64_linux_signals_t *signals,
                          sparc64_signal_next_t *next)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL || next == NULL)
        return false;
    *next = (sparc64_signal_next_t){0};
    uint64_t thread_pending = signals->thread.pending;
    uint64_t process_pending = signals->process->pending;
    bool directed;
    unsigned int signal;
    while (next_candidate(signals, thread_pending, process_pending,
                          &directed, &signal)) {
        uint64_t bit = signal_bit(signal);
        sparc64_signal_action_t action = signals->process->actions[signal - 1];
        if (!ignored(signal, &action)) {
            *next = (sparc64_signal_next_t){
                action.handler == 0 ? SPARC64_SIGNAL_FATAL : SPARC64_SIGNAL_CAUGHT,
                signal,
                action.handler != 0 && (action.flags & SA_RESTART) != 0
            };
            return true;
        }
        if (directed)
            thread_pending &= ~bit;
        else
            process_pending &= ~bit;
    }
    return true;
}

static bool on_stack(const sparc64_signal_stack_t *stack, uint64_t sp)
{
    return (stack->flags & SS_AUTODISARM) == 0 && sp > stack->sp &&
           sp - stack->sp <= stack->size;
}

static sparc64_signal_stack_t reported_stack(const sparc64_signal_stack_t *stack, uint64_t sp)
{
    sparc64_signal_stack_t result = *stack;
    result.flags = (stack->flags & SS_AUTODISARM) |
                   (stack->size == 0 ? SS_DISABLE : (on_stack(stack, sp) ? SS_ONSTACK : 0));
    return result;
}

static unsigned int set_stack(sparc64_signal_thread_t *thread, uint64_t sp,
                               const sparc64_signal_stack_t *stack)
{
    if (on_stack(&thread->alternate, sp))
        return 1; /* EPERM precedes input-flag/size checks. */
    uint32_t mode = stack->flags & ~SS_AUTODISARM;
    if (mode != 0 && mode != SS_ONSTACK && mode != SS_DISABLE)
        return 22;
    if (mode == SS_DISABLE) {
        thread->alternate = (sparc64_signal_stack_t){.flags = stack->flags};
        return 0;
    }
    if (stack->size < 2048)
        return 12;
    thread->alternate = *stack;
    return 0;
}

bool sparc64_linux_signal_process_init(sparc64_signal_process_t *process, sparc64_space_t *space,
                                   uint32_t guest_pid, uint32_t guest_uid)
{
    if (process == NULL || space == NULL || guest_pid == 0 ||
        space->limit <= UINT64_C(0x10000000000))
        return false;
    memset(process, 0, sizeof(*process));
    process->space = space;
    process->pid = guest_pid;
    process->uid = guest_uid;
    uint64_t trampoline;
    if (!sparc64_space_find_hole(space, UINT64_C(0x10000000000), SPARC64_PAGE_SIZE, &trampoline) ||
        !sparc64_space_map(space, trampoline, SPARC64_PAGE_SIZE, SPARC64_MEM_READ | SPARC64_MEM_EXEC, false))
        return false;
    const unsigned char code[8] = {0x93, 0x08, 0xb0, 0x08, 0x73, 0, 0, 0};
    if (!sparc64_space_write_initial(space, trampoline, code, sizeof(code)))
        return false;
    process->trampoline = trampoline;
    return true;
}

bool sparc64_linux_signal_worker_attach(sparc64_linux_signals_t *signals,
                                    sparc64_signal_process_t *process,
                                    const sparc64_linux_signals_t *parent,
                                    uint32_t guest_tid)
{
    if (signals == NULL || process == NULL || process->space == NULL ||
        process->trampoline == 0 || guest_tid == 0 ||
        (parent != NULL && (parent == signals || parent->process != process)))
        return false;
    bool parent_attached = parent == NULL;
    for (const sparc64_linux_signals_t *worker = process->workers;
         worker != NULL; worker = worker->next) {
        if (worker == signals || worker->guest_tid == guest_tid)
            return false;
        if (worker == parent)
            parent_attached = true;
    }
    if (!parent_attached)
        return false;
    uint64_t blocked = parent == NULL ? 0 : parent->thread.blocked;
    memset(signals, 0, sizeof(*signals));
    signals->process = process;
    signals->guest_tid = guest_tid;
    signals->thread.blocked = blocked;
    signals->thread.alternate.flags = SS_DISABLE;
    signals->next = process->workers;
    process->workers = signals;
    update_leader_masks(signals);
    return true;
}

bool sparc64_linux_signal_fork_child_init(sparc64_signal_process_t *child_process,
                                      sparc64_linux_signals_t *child_worker,
                                      const sparc64_signal_process_t *parent_process,
                                      const sparc64_linux_signals_t *calling_worker,
                                      sparc64_space_t *child_space, uint32_t child_pid)
{
    if (child_process == NULL || child_worker == NULL || parent_process == NULL ||
        calling_worker == NULL || child_space == NULL || child_pid == 0 ||
        child_process == parent_process || child_worker == calling_worker ||
        calling_worker->process != parent_process || parent_process->space == NULL ||
        parent_process->trampoline == 0)
        return false;
    bool found = false;
    for (const sparc64_linux_signals_t *worker = parent_process->workers;
         worker != NULL; worker = worker->next) {
        if (worker == child_worker)
            return false;
        found = found || worker == calling_worker;
    }
    if (!found)
        return false;
    memset(child_process, 0, sizeof(*child_process));
    memset(child_worker, 0, sizeof(*child_worker));
    child_process->space = child_space;
    child_process->trampoline = parent_process->trampoline;
    child_process->pid = child_pid;
    child_process->uid = parent_process->uid;
    memcpy(child_process->actions, parent_process->actions,
             sizeof(child_process->actions));
    child_worker->process = child_process;
    child_worker->guest_tid = child_pid;
    child_worker->thread.blocked = calling_worker->thread.blocked;
    child_worker->thread.alternate = calling_worker->thread.alternate;
    child_worker->thread.saved_mask = calling_worker->thread.saved_mask;
    child_worker->thread.restore_mask = calling_worker->thread.restore_mask;
    child_process->leader_blocked = child_worker->thread.blocked;
    child_process->workers = child_worker;
    return true;
}

bool sparc64_linux_signal_clone_vm_child_reset_altstack(sparc64_linux_signals_t *child)
{
    if (child == NULL || child->process == NULL ||
        child->process->workers != child)
        return false;
    child->thread.alternate = (sparc64_signal_stack_t){.flags = SS_DISABLE};
    return true;
}

bool sparc64_linux_signal_worker_detach(sparc64_linux_signals_t *signals)
{
    if (signals == NULL || signals->process == NULL)
        return false;
    sparc64_linux_signals_t **link = &signals->process->workers;
    while (*link != NULL && *link != signals)
        link = &(*link)->next;
    if (*link == NULL)
        return false;
    update_leader_masks(signals);
    *link = signals->next;
    memset(signals, 0, sizeof(*signals));
    return true;
}

static uint64_t action_call(sparc64_linux_signals_t *signals, const uint64_t args[6])
{
    unsigned int signal = (uint32_t)args[0];
    if (args[3] != 8)
        return fail(22);
    unsigned char input[24];
    if (args[1] != 0 &&
        !sparc64_space_read(signals->process->space, args[1], input, sizeof(input), SPARC64_MEM_READ))
        return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
    if (signal == 0 || signal > 64)
        return fail(22);
    sparc64_signal_action_t old = signals->process->actions[signal - 1];
    if (args[1] != 0) {
        if (signal == 9 || signal == 19)
            return fail(22);
        sparc64_signal_action_t action = {get64(input), get64(input + 8) & SA_KNOWN,
                                     get64(input + 16) & ~UNBLOCKABLE};
        if (signal == 17 && signals->process->child_action_sync != NULL)
            signals->process->child_action_sync(
                signals->process->child_action_context, &action,
                (signals->thread.blocked & signal_bit(17)) != 0, true);
        signals->process->actions[signal - 1] = action;
        if (ignored(signal, &action)) {
            signals->process->pending &= ~signal_bit(signal);
            for (sparc64_linux_signals_t *worker = signals->process->workers;
                 worker != NULL; worker = worker->next)
                worker->thread.pending &= ~signal_bit(signal);
        }
    }
    if (args[2] != 0) {
        unsigned char bytes[24];
        put64(bytes, old.handler);
        put64(bytes + 8, old.flags);
        put64(bytes + 16, old.mask);
        if (!sparc64_space_write(signals->process->space, args[2], bytes, sizeof(bytes)))
            return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
    }
    return 0;
}

static uint64_t mask_call(sparc64_linux_signals_t *signals, const uint64_t args[6])
{
    if (args[3] != 8)
        return fail(22);
    uint64_t old = signals->thread.blocked;
    if (args[1] != 0) {
        unsigned char bytes[8];
        if (!sparc64_space_read(signals->process->space, args[1], bytes, sizeof(bytes), SPARC64_MEM_READ))
            return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
        uint64_t mask = get64(bytes) & ~UNBLOCKABLE;
        switch ((uint32_t)args[0]) {
        case 0: signals->thread.blocked |= mask; break;
        case 1: signals->thread.blocked &= ~mask; break;
        case 2: signals->thread.blocked = mask; break;
        default: return fail(22);
        }
        update_leader_masks(signals);
        sync_child_mask(signals);
    }
    if (args[2] != 0) {
        unsigned char bytes[8];
        put64(bytes, old);
        if (!sparc64_space_write(signals->process->space, args[2], bytes, sizeof(bytes)))
            return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
    }
    return 0;
}

static uint64_t stack_call(sparc64_linux_signals_t *signals, const sparc64_cpu_t *cpu,
                           const uint64_t args[6])
{
    sparc64_signal_stack_t old = reported_stack(&signals->thread.alternate, cpu->x[2]);
    if (args[0] != 0) {
        unsigned char bytes[24];
        if (!sparc64_space_read(signals->process->space, args[0], bytes, sizeof(bytes), SPARC64_MEM_READ))
            return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
        sparc64_signal_stack_t stack = {.sp = get64(bytes), .flags = get32(bytes + 8),
                                   .size = get64(bytes + 16)};
        unsigned int error = set_stack(&signals->thread, cpu->x[2], &stack);
        if (error != 0)
            return fail(error);
    }
    if (args[1] != 0) {
        unsigned char bytes[24] = {0};
        put64(bytes, old.sp);
        put32(bytes + 8, old.flags);
        put64(bytes + 16, old.size);
        if (!sparc64_space_write(signals->process->space, args[1], bytes, sizeof(bytes)))
            return fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
    }
    return 0;
}

static void force_bad_frame(sparc64_linux_signals_t *signals)
{
    uint64_t bit = signal_bit(11);
    sparc64_signal_action_t *action = &signals->process->actions[10];
    if ((signals->thread.blocked & bit) != 0 || action->handler == 1)
        action->handler = 0;
    signals->thread.blocked &= ~bit;
    update_leader_masks(signals);
    sync_child_mask(signals);
    signals->thread.pending |= bit;
    unsigned char *information = signals->thread.information[10];
    memset(information, 0, 128);
    put32(information, 11);
    put32(information + 8, 128); /* SI_KERNEL, as force_sig(SIGSEGV). */
}

static void return_call(sparc64_linux_signals_t *signals, sparc64_cpu_t *cpu)
{
    uint64_t frame = cpu->x[2], mask;
    /* Linux syscall entry has already advanced EPC. A valid context replaces
     * it; a failed return recovered by a SIGSEGV handler resumes after ECALL. */
    cpu->pc += 4;
    signals->process->space->fault_reason = SPARC64_FAULT_NONE;
    if (!sparc64_signal_frame_read_mask(signals->process->space, frame, &mask)) {
        if (sparc64_fault_is_runtime(signals->process->space->fault_reason)) {
            signals->process->space->internal_failure = true;
            return;
        }
        cpu->x[10] = 0;
        force_bad_frame(signals);
        return;
    }
    signals->thread.blocked = mask & ~UNBLOCKABLE;
    update_leader_masks(signals);
    sync_child_mask(signals);
    sparc64_signal_stack_t alternate;
    if (!sparc64_signal_frame_read_context(signals->process->space, frame, cpu) ||
        !sparc64_signal_frame_read_stack(signals->process->space, frame, &alternate)) {
        if (sparc64_fault_is_runtime(signals->process->space->fault_reason)) {
            signals->process->space->internal_failure = true;
            return;
        }
        cpu->x[10] = 0;
        force_bad_frame(signals);
        return;
    }
    /* Linux ignores altstack EPERM/EINVAL/ENOMEM on sigreturn. The required
     * fields were readable; an invalid setting preserves the current one. */
    (void)set_stack(&signals->thread, cpu->x[2], &alternate);
}

static uint64_t kill_call(sparc64_linux_signals_t *signals, const uint64_t args[6],
                          sparc64_signal_syscall_t *result)
{
    unsigned int signal = (uint32_t)args[1];
    if (signal > 64)
        return fail(22);
    if ((uint32_t)args[0] != signals->process->pid)
        return fail(95); /* No native/external or group signaling. */
    if (signal == 0)
        return 0;
    if (signal >= 32 || (signal >= 18 && signal <= 22))
        return fail(95); /* No fake RT queue or job-control success. */
    bool queued;
    (void)enqueue_standard(signals, signal, 0, signals->process->pid,
                           signals->process->uid, false,
                           process_admission_mask(signals->process), &queued);
    if (queued) {
        result->notify = true;
        result->notify_tid = 0;
    }
    return 0;
}

static uint64_t thread_kill_call(sparc64_linux_signals_t *signals,
                                 const uint64_t args[6], bool group,
                                 sparc64_signal_syscall_t *result)
{
    uint32_t tid = (uint32_t)args[group ? 1 : 0];
    unsigned int signal = (uint32_t)args[group ? 2 : 1];
    uint32_t tgid = (uint32_t)args[0];
    if (tid == 0 || tid > INT32_MAX ||
        (group && (tgid == 0 || tgid > INT32_MAX)))
        return fail(22);
    if (signal > 64)
        return fail(22);
    if (group && tgid != signals->process->pid)
        return fail(3); /* ESRCH: target thread group does not exist here. */
    sparc64_linux_signals_t *target = signals->process->workers;
    while (target != NULL && target->guest_tid != tid)
        target = target->next;
    if (target == NULL)
        return fail(3); /* ESRCH: no live view has this guest TID. */
    if (signal == 0)
        return 0;
    if (signal >= 32 || (signal >= 18 && signal <= 22))
        return fail(95);
    if (target != signals && signal != 10 && signal != 12 && signal != 15)
        return fail(95); /* Cross-view routing is scoped to USR1/USR2/TERM. */
    bool queued;
    (void)enqueue_standard(target, signal, -6, signals->process->pid,
                           signals->process->uid, true,
                           thread_admission_mask(target), &queued);
    if (queued && target != signals &&
        (target->thread.blocked & signal_bit(signal)) == 0) {
        result->notify = true;
        result->notify_tid = tid;
    }
    return 0;
}

bool sparc64_linux_signal_dispatch(sparc64_linux_signals_t *signals, sparc64_cpu_t *cpu,
                               uint64_t number, const uint64_t args[6],
                               sparc64_signal_syscall_t *result)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL || cpu == NULL ||
        cpu->xlen != 64 || args == NULL || result == NULL)
        return false;
    *result = (sparc64_signal_syscall_t){0};
    switch (number) {
    case 129: result->value = kill_call(signals, args, result); break;
    case 130: result->value = thread_kill_call(signals, args, false, result); break;
    case 131: result->value = thread_kill_call(signals, args, true, result); break;
    case 132: result->value = stack_call(signals, cpu, args); break;
    case 133: {
        unsigned char bytes[8];
        if (args[1] != sizeof(bytes))
            result->value = fail(22);
        else if (!sparc64_space_read(signals->process->space, args[0], bytes, sizeof(bytes), SPARC64_MEM_READ))
            result->value = fail(sparc64_fault_is_runtime(signals->process->space->fault_reason) ? 12 : 14);
        else {
            signals->thread.saved_mask = signals->thread.blocked;
            signals->thread.restore_mask = true;
            signals->thread.blocked = get64(bytes) & ~UNBLOCKABLE;
            update_leader_masks(signals);
            sync_child_mask(signals);
            result->value = fail(4); /* NOHAND: a caught handler always gets EINTR. */
            result->waiting = true;
        }
        break;
    }
    case 134: result->value = action_call(signals, args); break;
    case 135: result->value = mask_call(signals, args); break;
    case 136: {
        if (args[1] > 8)
            result->value = fail(22);
        else if (args[1] != 0) {
            unsigned char bytes[8];
            uint64_t pending = signals->process->pending |
                               signals->thread.pending;
            if (signals->process->child_pending != NULL &&
                signals->process->child_pending(
                    signals->process->child_action_context))
                pending |= signal_bit(17);
            put64(bytes, pending & signals->thread.blocked);
            if (!sparc64_space_write(signals->process->space, args[0], bytes, (size_t)args[1]))
                result->value = fail(14);
        }
        break;
    }
    case 139:
        return_call(signals, cpu);
        result->context_restored = true;
        break;
    default: return false;
    }
    return true;
}

bool sparc64_linux_signal_deliver(sparc64_linux_signals_t *signals, sparc64_cpu_t *cpu,
                             unsigned int *fatal_signal)
{
    if (fatal_signal == NULL)
        return false;
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL || cpu == NULL || cpu->xlen != 64) {
        *fatal_signal = 11;
        return false;
    }
    for (;;) {
        bool directed;
        unsigned int signal;
        if (!next_candidate(signals, signals->thread.pending,
                            signals->process->pending, &directed, &signal))
            return true;
        uint64_t *pending = directed ? &signals->thread.pending :
                                       &signals->process->pending;
        *pending &= ~signal_bit(signal);
        const unsigned char *information = directed ?
            signals->thread.information[signal - 1] :
            signals->process->information[signal - 1];
        unsigned char selected_information[128];
        /* A one-shot SIGCHLD reset can rendezvous with native workers and
         * release the family guard. The just-dequeued queue slot is then
         * free for a newer child event; retain this instance's siginfo on
         * the caller stack until its frame is committed. */
        memcpy(selected_information, information, sizeof(selected_information));
        sparc64_signal_action_t action = signals->process->actions[signal - 1];
        if (ignored(signal, &action))
            continue;
        if (action.handler == 0) {
            *fatal_signal = signal;
            return false;
        }
        if ((action.flags & SA_RESETHAND) != 0) {
            if (signal == 17 && signals->process->child_action_sync != NULL) {
                sparc64_signal_action_t reset = action;
                reset.handler = 0;
                /* The selected handler's mask takes effect before guest
                 * execution resumes. Keep a blocked native DEFAULT pending
                 * across the automatic reset until that effective mask is
                 * installed; SA_NODEFER intentionally leaves it unblocked. */
                uint64_t delivery_mask = signals->thread.blocked | action.mask;
                if ((action.flags & SA_NODEFER) == 0)
                    delivery_mask |= signal_bit(signal);
                signals->process->child_action_sync(
                    signals->process->child_action_context, &reset,
                    (delivery_mask & signal_bit(17)) != 0, false);
            }
            signals->process->actions[signal - 1].handler = 0;
        }
        sparc64_signal_stack_t stack = signals->thread.alternate;
        uint64_t sp = cpu->x[2];
        bool already_on_stack = on_stack(&stack, sp);
        bool use_alternate = (action.flags & SA_ONSTACK) != 0 &&
                             !already_on_stack && stack.size != 0;
        bool valid = true;
        if (use_alternate) {
            valid = stack.size <= UINT64_MAX - stack.sp;
            sp = valid ? stack.sp + stack.size : 0;
        }
        valid = valid && sp >= SPARC64_SIGNAL_FRAME_SIZE;
        uint64_t frame = valid ? (sp - SPARC64_SIGNAL_FRAME_SIZE) & ~UINT64_C(15) : 0;
        if (already_on_stack)
            valid = valid && on_stack(&stack, sp - SPARC64_SIGNAL_FRAME_SIZE);
        sparc64_signal_stack_t saved_stack = stack; /* __save_altstack uses raw flags. */
        signals->process->space->fault_reason = SPARC64_FAULT_NONE;
        uint64_t saved_mask = signals->thread.restore_mask ?
                              signals->thread.saved_mask : signals->thread.blocked;
        if (!valid || !sparc64_signal_frame_write(signals->process->space, frame, cpu,
                          saved_mask, &saved_stack,
                          selected_information)) {
            if (valid && sparc64_fault_is_runtime(signals->process->space->fault_reason)) {
                signals->process->space->internal_failure = true;
                *fatal_signal = 0; /* Host failure, not a guest SIGSEGV. */
                return false;
            }
            if (signal == 11) {
                *fatal_signal = 11;
                return false;
            }
            force_bad_frame(signals);
            continue;
        }
        signals->thread.restore_mask = false;
        signals->thread.blocked |= action.mask;
        if ((action.flags & SA_NODEFER) == 0)
            signals->thread.blocked |= signal_bit(signal);
        signals->thread.blocked &= ~UNBLOCKABLE;
        if ((stack.flags & SS_AUTODISARM) != 0)
            signals->thread.alternate = (sparc64_signal_stack_t){.flags = SS_DISABLE};
        update_leader_masks(signals);
        sync_child_mask(signals);
        cpu->reservation_valid = false;
        cpu->x[0] = 0;
        cpu->x[1] = signals->process->trampoline;
        cpu->x[2] = frame;
        cpu->x[10] = signal;
        cpu->x[11] = frame;
        cpu->x[12] = frame + 128;
        cpu->pc = action.handler;
        return true;
    }
}

bool sparc64_linux_signal_raise_trap(sparc64_linux_signals_t *signals,
                                 const sparc64_step_result_t *step)
{
    if (signals == NULL || signals->process == NULL ||
        signals->process->space == NULL || step == NULL ||
        step->kind != SPARC64_STEP_TRAP ||
        step->memory_reason == SPARC64_MEM_FAULT_INTERNAL ||
        step->memory_reason == SPARC64_MEM_FAULT_RESOURCE)
        return false;
    unsigned int signal, code;
    uint64_t address = step->pc;
    switch (step->cause) {
    case SPARC64_TRAP_ILLEGAL:
        signal = 4; code = 1; break; /* SIGILL, ILL_ILLOPC. */
    case SPARC64_TRAP_BREAKPOINT:
        signal = 5; code = 1; break; /* SIGTRAP, TRAP_BRKPT. */
    case SPARC64_TRAP_INST_MISALIGNED:
    case SPARC64_TRAP_LOAD_MISALIGNED:
    case SPARC64_TRAP_STORE_MISALIGNED:
        signal = 7; code = 1; break; /* SIGBUS, BUS_ADRALN. */
    case SPARC64_TRAP_INST_ACCESS:
    case SPARC64_TRAP_LOAD_ACCESS:
    case SPARC64_TRAP_STORE_ACCESS:
        /* The hardware access-exception path reports EPC. Translation page
         * faults and backing faults report the faulting address instead. */
        switch (step->memory_reason) {
        case SPARC64_MEM_FAULT_NONE:
            address = step->pc;
            signal = 11; code = 2; /* Hardware access: SEGV_ACCERR. */
            break;
        case SPARC64_MEM_FAULT_BUS:
            address = step->tval;
            signal = 7; code = 2; /* SIGBUS, BUS_ADRERR. */
            break;
        case SPARC64_MEM_FAULT_UNMAPPED:
        case SPARC64_MEM_FAULT_RANGE:
            address = step->tval;
            signal = 11; code = 1; /* SIGSEGV, SEGV_MAPERR. */
            break;
        case SPARC64_MEM_FAULT_PERMISSION:
            address = step->tval;
            signal = 11; code = 2; /* SIGSEGV, SEGV_ACCERR. */
            break;
        case SPARC64_MEM_FAULT_INTERNAL:
        case SPARC64_MEM_FAULT_RESOURCE:
            return false;
        default:
            return false;
        }
        break;
    default:
        return false;
    }
    uint64_t bit = signal_bit(signal);
    sparc64_signal_action_t *action = &signals->process->actions[signal - 1];
    if ((signals->thread.blocked & bit) != 0 || action->handler == 1) {
        action->handler = 0;
        signals->thread.blocked &= ~bit;
        update_leader_masks(signals);
    }
    unsigned char *information = signals->thread.information[signal - 1];
    memset(information, 0, 128);
    put32(information, signal);
    put32(information + 8, code);
    put64(information + 16, address);
    signals->thread.pending |= bit;
    return true;
}
