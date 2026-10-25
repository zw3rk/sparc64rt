/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "futex_split.h"


uint64_t linux_error(int host_error)
{
    return UINT64_C(0) - sparc64_linux_errno(host_error);
}

static uint32_t little32(const unsigned char bytes[4])
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static uint64_t little64(const unsigned char bytes[8])
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (i * 8);
    return value;
}

/* Direct Linux clock syscall avoids the cached libc/vDSO timestamp observed
 * through HL. Darwin native units use the ordinary portable clock. */
bool clock_now(bool realtime, uint64_t *nanoseconds)
{
    struct timespec now = {0};
    clockid_t id = realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC;
#if defined(__linux__)
    if (syscall(SYS_clock_gettime, id, &now) != 0)
        return false;
#else
    if (clock_gettime(id, &now) != 0)
        return false;
#endif
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec >
            (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000))
        return false;
    *nanoseconds = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                   (uint64_t)now.tv_nsec;
    return true;
}

static bool guest_range(const sparc64_space_t *space, uint64_t address)
{
    return address <= space->limit && UINT64_C(4) <= space->limit - address;
}

static bool read_error(sparc64_linux_futex_t *futex, uint64_t *result)
{
    switch (futex->space->fault_reason) {
    case SPARC64_FAULT_RESOURCE:
        *result = linux_error(ENOMEM);
        return true;
    case SPARC64_FAULT_RANGE:
    case SPARC64_FAULT_UNMAPPED:
    case SPARC64_FAULT_PERMISSION:
    case SPARC64_FAULT_BUS:
        *result = linux_error(EFAULT);
        return true;
    case SPARC64_FAULT_NONE:
    case SPARC64_FAULT_INTERNAL:
    default:
        futex->space->internal_failure = true;
        futex->space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
}

bool family_context(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_context_t *context)
{
    if (futex->family_context == NULL ||
        !futex->family_context(futex->context, context) ||
        context->memory == NULL || context->memory->space != futex->space ||
        context->mm_id == 0 || context->worker_id == 0 ||
        !sparc64_family_backing_guard_matches(context->backing, context->guard)) {
        futex->space->internal_failure = true;
        futex->space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
    return true;
}

static bool same_key(sparc64_family_wait_key_t a, sparc64_family_wait_key_t b)
{
    return a.kind == b.kind && a.identity == b.identity && a.offset == b.offset;
}

/* A replay allocation failure after COMMITTED poisons the family. Never turn
 * that failure into an ordinary guest ENOMEM based on errno alone. */
static bool family_error(sparc64_linux_futex_t *futex,
                          sparc64_linux_futex_context_t *context, uint64_t *result)
{
    if ((errno == ENOMEM || errno == ENOSPC) &&
        sparc64_family_backing_guard_matches(context->backing, context->guard)) {
        *result = linux_error(ENOMEM);
        return true;
    }
    futex->space->internal_failure = true;
    futex->space->fault_reason = SPARC64_FAULT_INTERNAL;
    return false;
}

int family_snapshot(sparc64_linux_futex_context_t *context,
                            sparc64_family_wait_table_t *table)
{
    if (sparc64_family_wait_table_read(context->guard, table) != 0)
        return -1;
    return sparc64_family_wait_table_sweep(context->guard, table);
}

static void table_remove(sparc64_family_wait_table_t *table, size_t index)
{
    memmove(&table->rows[index], &table->rows[index + 1],
            (table->count - index - 1u) * sizeof(*table->rows));
    --table->count;
}

/* Scheduler pointers never enter shared rows. This is only a local latency
 * hint; remote owners discover authoritative WOKEN rows on guarded admission. */
bool family_notify(sparc64_linux_futex_t *futex,
                           const sparc64_family_wait_table_t *table)
{
    for (sparc64_linux_futex_waiter_t *entry = futex->head;
         entry != NULL; entry = entry->next) {
        for (size_t i = 0; i < table->count; ++i) {
            const sparc64_family_wait_row_t *row = &table->rows[i];
            if (row->wait_id == entry->wait_id && row->state == SPARC64_FAMILY_WOKEN) {
                atomic_store_explicit(&entry->woken, true, memory_order_release);
                if (sparc64_scheduler_wake(futex->scheduler, entry->ticket) < 0)
                    return false;
                break;
            }
        }
    }
    return true;
}

uint32_t table_wake(sparc64_family_wait_table_t *table,
                            sparc64_family_wait_key_t key, uint32_t count,
                            uint32_t bitset)
{
    uint32_t limit = count == 0 || count > INT32_MAX ? 1u : count;
    uint32_t woken = 0;
    for (size_t i = 0; i < table->count && woken < limit; ++i) {
        sparc64_family_wait_row_t *row = &table->rows[i];
        if (row->state == SPARC64_FAMILY_WAITING && same_key(row->key, key) &&
            (row->bitset & bitset) != 0) {
            row->state = SPARC64_FAMILY_WOKEN;
            ++woken;
        }
    }
    return woken;
}

static bool family_wake(sparc64_linux_futex_t *futex, uint64_t address,
                         bool private_key, uint32_t count, uint32_t bitset,
                         uint64_t *result)
{
    sparc64_linux_futex_context_t context;
    sparc64_family_wait_key_t key;
    if (!family_context(futex, &context) ||
        !sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             address, private_key, false, &key, result))
        return false;
    if (*result != 0)
        return true;
    sparc64_family_wait_table_t table = {0};
    bool success;
    if (family_snapshot(&context, &table) != 0) {
        success = family_error(futex, &context, result);
    } else {
        uint32_t woken = table_wake(&table, key, count, bitset);
        if (sparc64_family_wait_table_commit(context.guard, &table, NULL, 0) != 0)
            success = family_error(futex, &context, result);
        else {
            *result = woken;
            success = family_notify(futex, &table);
        }
    }
    sparc64_family_wait_table_destroy(&table);
    return success;
}

static bool family_requeue(sparc64_linux_futex_t *futex, const uint64_t args[6],
                            bool private_key, bool compare, uint64_t *result)
{
    uint32_t wake_count = (uint32_t)args[2], move_count = (uint32_t)args[3];
    if (wake_count > INT32_MAX || move_count > INT32_MAX) {
        *result = linux_error(EINVAL);
        return true;
    }
    sparc64_linux_futex_context_t context;
    sparc64_family_wait_key_t source, destination;
    if (!family_context(futex, &context) ||
        !sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             args[0], private_key, false, &source, result))
        return false;
    if (*result != 0)
        return true;
    if (!sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             args[4], private_key, false, &destination, result))
        return false;
    if (*result != 0)
        return true;
    if (compare) {
        unsigned char bytes[4];
        if (!sparc64_space_read(futex->space, args[0], bytes, sizeof(bytes), SPARC64_MEM_READ))
            return read_error(futex, result);
        if (little32(bytes) != (uint32_t)args[5]) {
            *result = linux_error(EAGAIN);
            return true;
        }
    }
    sparc64_family_wait_table_t table = {0};
    bool success;
    if (family_snapshot(&context, &table) != 0) {
        success = family_error(futex, &context, result);
    } else {
        uint32_t woken = 0, moved = 0;
        for (size_t i = 0; i < table.count &&
             (woken < wake_count || moved < move_count); ++i) {
            sparc64_family_wait_row_t *row = &table.rows[i];
            if (row->state != SPARC64_FAMILY_WAITING || !same_key(row->key, source))
                continue;
            if (woken < wake_count) {
                row->state = SPARC64_FAMILY_WOKEN;
                ++woken;
            } else {
                row->key = destination;
                ++moved;
            }
        }
        if (sparc64_family_wait_table_commit(context.guard, &table, NULL, 0) != 0)
            success = family_error(futex, &context, result);
        else {
            *result = (uint64_t)woken + moved;
            success = family_notify(futex, &table);
        }
    }
    sparc64_family_wait_table_destroy(&table);
    return success;
}

bool family_wait_state(sparc64_linux_futex_t *futex,
                               const sparc64_linux_futex_waiter_t *waiter,
                               bool remove, bool *woken)
{
    sparc64_linux_futex_context_t context;
    sparc64_family_wait_table_t table = {0};
    if (!family_context(futex, &context))
        return false;
    bool success = false;
    if (context.guard->incarnation != waiter->owner_incarnation ||
        context.mm_id != waiter->mm_id || context.worker_id != waiter->worker_id ||
        sparc64_family_wait_table_read(context.guard, &table) != 0)
        goto done;
    for (size_t i = 0; i < table.count; ++i) {
        const sparc64_family_wait_row_t *row = &table.rows[i];
        if (row->wait_id != waiter->wait_id)
            continue;
        if (row->owner_incarnation != waiter->owner_incarnation ||
            row->mm_id != waiter->mm_id || row->worker_id != waiter->worker_id)
            break;
        *woken = row->state == SPARC64_FAMILY_WOKEN;
        if (remove) {
            table_remove(&table, i);
            if (sparc64_family_wait_table_commit(context.guard, &table, NULL, 0) != 0)
                break;
        }
        success = true;
        break;
    }
done:
    sparc64_family_wait_table_destroy(&table);
    if (!success) {
        futex->space->internal_failure = true;
        futex->space->fault_reason = SPARC64_FAULT_INTERNAL;
    }
    return success;
}

static bool family_enqueue(sparc64_linux_futex_t *futex,
                            sparc64_linux_futex_waiter_t *waiter, uint64_t address,
                            bool private_key, uint32_t bitset, uint64_t *result)
{
    sparc64_linux_futex_context_t context;
    sparc64_family_wait_key_t key;
    if (!family_context(futex, &context) ||
        !sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             address, private_key, false, &key, result))
        return false;
    if (*result != 0)
        return true;
    sparc64_family_wait_table_t table = {0};
    bool success = false;
    uint64_t id;
    if (family_snapshot(&context, &table) != 0) {
        success = family_error(futex, &context, result);
        goto done;
    }
    if (table.count == SPARC64_FAMILY_WAIT_MAX_ROWS) {
        *result = linux_error(ENOMEM);
        success = true;
        goto done;
    }
    if (sparc64_family_wait_table_reserve(&table, table.count + 1u) != 0 ||
        sparc64_family_wait_id(context.guard, &id) != 0) {
        success = family_error(futex, &context, result);
        goto done;
    }
    table.rows[table.count++] = (sparc64_family_wait_row_t){
        .wait_id = id, .owner_incarnation = context.guard->incarnation,
        .mm_id = context.mm_id, .worker_id = context.worker_id,
        .key = key, .bitset = bitset, .state = SPARC64_FAMILY_WAITING
    };
    if (sparc64_family_wait_table_commit(context.guard, &table, NULL, 0) != 0) {
        success = family_error(futex, &context, result);
        goto done;
    }
    waiter->wait_id = id;
    waiter->owner_incarnation = context.guard->incarnation;
    waiter->mm_id = context.mm_id;
    waiter->worker_id = context.worker_id;
    *result = 0;
    success = true;
done:
    sparc64_family_wait_table_destroy(&table);
    return success;
}

bool family_word_commit(void *opaque,
                                const sparc64_managed_page_update_t *updates,
                                size_t count)
{
    family_word_context_t *context = opaque;
    return sparc64_family_backing_commit_wait(context->backing, context->table,
                                          updates, count);
}

static int32_t signed12(uint32_t value)
{
    value &= 0xfffu;
    return value >= 0x800u ? (int32_t)value - 4096 : (int32_t)value;
}

static bool family_wake_op(sparc64_linux_futex_t *futex, const uint64_t args[6],
                            bool private_key, uint64_t *result)
{
    sparc64_linux_futex_context_t context;
    sparc64_family_wait_key_t first, second;
    if (!family_context(futex, &context) ||
        !sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             args[0], private_key, false, &first, result))
        return false;
    if (*result != 0)
        return true;
    if (!sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                             args[4], private_key, true, &second, result))
        return false;
    if (*result != 0)
        return true;
    uint32_t encoded = (uint32_t)args[5];
    uint32_t operation = (encoded >> 28) & 7u;
    if (operation > 4) {
        *result = linux_error(ENOSYS);
        return true;
    }
    uint32_t operand = (uint32_t)signed12(encoded >> 12);
    /* Linux v6.18 retains legacy masking for out-of-range shift operands. */
    if ((encoded & UINT32_C(0x80000000)) != 0)
        operand = UINT32_C(1) << (operand & 31u);
    unsigned char bytes[4];
    if (!sparc64_space_read(futex->space, args[4], bytes, sizeof(bytes), SPARC64_MEM_WRITE))
        return read_error(futex, result);
    uint32_t old = little32(bytes), value = old;
    switch (operation) {
    case 0: value = operand; break;
    case 1: value = old + operand; break;
    case 2: value = old | operand; break;
    case 3: value = old & ~operand; break;
    case 4: value = old ^ operand; break;
    default: return false;
    }
    int64_t signed_old = old <= INT32_MAX ? (int64_t)old :
                         (int64_t)old - INT64_C(4294967296);
    int32_t compare = signed12(encoded);
    uint32_t comparison = (encoded >> 24) & 15u;
    bool match = false;
    switch (comparison) {
    case 0: match = signed_old == compare; break;
    case 1: match = signed_old != compare; break;
    case 2: match = signed_old < compare; break;
    case 3: match = signed_old <= compare; break;
    case 4: match = signed_old > compare; break;
    case 5: match = signed_old >= compare; break;
    default: break;
    }
    sparc64_family_wait_table_t table = {0};
    if (family_snapshot(&context, &table) != 0) {
        bool success = family_error(futex, &context, result);
        sparc64_family_wait_table_destroy(&table);
        return success;
    }
    uint64_t woken = 0;
    /* An invalid comparison still follows the arithmetic store, but selects
     * no waiters. The word and selected rows share one committed redo root. */
    if (comparison <= 5) {
        woken = table_wake(&table, first, (uint32_t)args[2], UINT32_MAX);
        if (match)
            woken += table_wake(&table, second, (uint32_t)args[3], UINT32_MAX);
    }
    for (unsigned int i = 0; i < 4; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8u));
    family_word_context_t commit = {context.backing, &table};
    bool success = sparc64_space_write_word_commit(futex->space, args[4], bytes,
                                               family_word_commit, &commit);
    if (!success)
        success = read_error(futex, result);
    else {
        *result = comparison > 5 ? linux_error(ENOSYS) : woken;
        success = family_notify(futex, &table);
    }
    sparc64_family_wait_table_destroy(&table);
    return success;
}

static sparc64_page_t *find_page(sparc64_space_t *space, uint64_t address)
{
    uint64_t base = address & ~(SPARC64_PAGE_SIZE - 1);
    size_t first = 0, last = space->count;
    while (first < last) {
        size_t middle = first + (last - first) / 2;
        if (space->pages[middle].address < base)
            first = middle + 1;
        else
            last = middle;
    }
    return first < space->count && space->pages[first].address == base ?
           &space->pages[first] : NULL;
}

static bool address_key(sparc64_linux_futex_t *futex, uint64_t address,
                        bool private_key, uint64_t *result)
{
    if ((address & 3) != 0) {
        *result = linux_error(EINVAL);
        return true;
    }
    if (!guest_range(futex->space, address)) {
        *result = linux_error(EFAULT);
        return true;
    }
    if (!private_key) {
        /* Anonymous FUT_OFF_MMSHARED keys require a present writable page.
         * PRIVATE keys only need numeric access_ok, even for WAKE on a hole. */
        sparc64_page_t *page = find_page(futex->space, address);
        if (page == NULL) {
            *result = linux_error(EFAULT);
            return true;
        }
        /* A MAP_PRIVATE file page needs Linux's FOLL_WRITE/COW or inode-key
         * resolution. Neither is represented by this anonymous-only key. */
        if (page->backing->file != NULL) {
            *result = linux_error(EOPNOTSUPP);
            return true;
        }
        unsigned char ignored[4];
        if (!sparc64_space_read(futex->space, address, ignored, sizeof(ignored),
                           SPARC64_MEM_WRITE)) {
            return read_error(futex, result);
        }
    }
    *result = 0;
    return true;
}

static bool read_timeout(sparc64_linux_futex_t *futex, uint64_t pointer,
                         bool relative, bool realtime, uint64_t *deadline,
                         uint64_t *error)
{
    unsigned char bytes[16];
    if (!sparc64_space_read(futex->space, pointer, bytes, sizeof(bytes), SPARC64_MEM_READ)) {
        return read_error(futex, error);
    }
    uint64_t seconds = little64(bytes);
    uint64_t fraction = little64(bytes + 8);
    if (seconds > INT64_MAX || fraction >= UINT64_C(1000000000)) {
        *error = linux_error(EINVAL);
        return true;
    }
    /* Linux v6.18 timespec64_to_ktime/ktime_set saturates at signed KTIME_MAX,
     * including the entire boundary second, rather than at unsigned64 max. */
    uint64_t maximum = (uint64_t)INT64_MAX;
    uint64_t interval = seconds >= maximum / UINT64_C(1000000000) ?
        maximum : seconds * UINT64_C(1000000000) + fraction;
    if (relative) {
        uint64_t now;
        if (!clock_now(false, &now))
            return false;
        *deadline = now >= maximum || interval > maximum - now ?
                    maximum : now + interval;
    } else
        *deadline = interval;
    (void)realtime;
    *error = 0;
    return true;
}

static void queue_remove(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter)
{
    sparc64_linux_futex_waiter_t **position = &futex->head;
    while (*position != NULL && *position != waiter)
        position = &(*position)->next;
    if (*position == NULL)
        return;
    *position = waiter->next;
    if (futex->tail == waiter) {
        futex->tail = NULL;
        for (sparc64_linux_futex_waiter_t *entry = futex->head;
             entry != NULL; entry = entry->next)
            futex->tail = entry;
    }
    waiter->next = NULL;
    waiter->queued = false;
}

void waiter_finish(sparc64_linux_futex_t *futex, sparc64_linux_futex_waiter_t *waiter)
{
    if (waiter->queued)
        queue_remove(futex, waiter);
    if (waiter->backing != NULL)
        sparc64_backing_release(waiter->backing);
    waiter->backing = NULL;
    waiter->ticket = NULL;
    waiter->has_deadline = false;
    waiter->wait_id = 0;
    waiter->owner_incarnation = 0;
    waiter->mm_id = 0;
    waiter->worker_id = 0;
    atomic_store_explicit(&waiter->woken, false, memory_order_release);
}

bool wake_key(sparc64_linux_futex_t *futex, uint64_t address,
                     bool private_key, uint32_t count, uint32_t bitset,
                     uint64_t *result)
{
    if (futex->family_context != NULL)
        return family_wake(futex, address, private_key, count, bitset, result);
    if (!address_key(futex, address, private_key, result))
        return false;
    if (*result != 0)
        return true;
    /* Legacy FUTEX_WAKE(0) wakes one if there is a waiter: v6.18 tests
     * ++ret >= nr_wake after the first match, without FLAGS_STRICT. */
    uint32_t limit = count == 0 || count > INT32_MAX ? 1 : count;
    uint32_t woken = 0;
    sparc64_linux_futex_waiter_t *entry = futex->head;
    while (entry != NULL && woken < limit) {
        sparc64_linux_futex_waiter_t *next = entry->next;
        if (entry->address == address && entry->private_key == private_key &&
            (entry->bitset & bitset) != 0) {
            queue_remove(futex, entry);
            atomic_store_explicit(&entry->woken, true, memory_order_release);
            if (sparc64_scheduler_wake(futex->scheduler, entry->ticket) < 0)
                return false;
            ++woken;
        }
        entry = next;
    }
    *result = woken;
    return true;
}

static bool requeue_key(sparc64_linux_futex_t *futex, const uint64_t args[6],
                        bool private_key, bool compare, uint64_t *result)
{
    if (futex->family_context != NULL)
        return family_requeue(futex, args, private_key, compare, result);
    /* Legacy syscall arguments are int counts, despite a3 also occupying
     * the timeout-pointer slot for WAIT. Reject negative low32 values before
     * touching either key. See Linux v6.18 futex_requeue(). */
    uint32_t wake_count = (uint32_t)args[2];
    uint32_t move_count = (uint32_t)args[3];
    if (wake_count > INT32_MAX || move_count > INT32_MAX) {
        *result = linux_error(EINVAL);
        return true;
    }
    if (!address_key(futex, args[0], private_key, result))
        return false;
    if (*result != 0)
        return true;
    if (!address_key(futex, args[4], private_key, result))
        return false;
    if (*result != 0)
        return true;
    if (compare) {
        unsigned char bytes[4];
        if (!sparc64_space_read(futex->space, args[0], bytes, sizeof(bytes), SPARC64_MEM_READ))
            return read_error(futex, result);
        if (little32(bytes) != (uint32_t)args[5]) {
            *result = linux_error(EAGAIN);
            return true;
        }
    }

    uint32_t woken = 0, moved = 0;
    sparc64_linux_futex_waiter_t *entry = futex->head;
    while (entry != NULL && (woken < wake_count || moved < move_count)) {
        sparc64_linux_futex_waiter_t *next = entry->next;
        if (entry->address == args[0] && entry->private_key == private_key) {
            if (woken < wake_count) {
                queue_remove(futex, entry);
                atomic_store_explicit(&entry->woken, true, memory_order_release);
                if (sparc64_scheduler_wake(futex->scheduler, entry->ticket) < 0)
                    return false;
                ++woken;
            } else {
                /* A normal same-key requeue is legal. Rewrite in place and
                 * visit each original waiter once, without waking it. Keep
                 * its original backing as a lifetime anchor, not as its key:
                 * PRIVATE destination keys need not have a mapped page.
                 * Bitset, deadline and original WAIT restart args survive. */
                entry->address = args[4];
                ++moved;
            }
        }
        entry = next;
    }
    *result = (uint64_t)woken + moved;
    return true;
}

void sparc64_linux_futex_init(sparc64_linux_futex_t *futex, sparc64_space_t *space,
                         sparc64_scheduler_t *scheduler)
{
    *futex = (sparc64_linux_futex_t){
        .space = space, .scheduler = scheduler, .owner_pid = getpid()
    };
}

void sparc64_linux_futex_bind_family(sparc64_linux_futex_t *futex,
    bool (*context)(void *, sparc64_linux_futex_context_t *), void *opaque)
{
    futex->family_context = context;
    futex->context = opaque;
}

bool sparc64_linux_futex_dispatch(sparc64_linux_futex_t *futex,
                              sparc64_linux_futex_waiter_t *waiter,
                              sparc64_sched_ticket_t *ticket,
                              const uint64_t args[6], uint64_t *result,
                              bool *waiting)
{
    if (futex == NULL || futex->space == NULL || futex->scheduler == NULL ||
        waiter == NULL || ticket == NULL || args == NULL || result == NULL ||
        waiting == NULL || futex->space->internal_failure) {
        errno = EINVAL;
        return false;
    }
    *waiting = false;
    uint32_t op = (uint32_t)args[1]; /* Linux syscall argument is int. */
    unsigned int command = op & ~(FUTEX_PRIVATE_BIT | FUTEX_REALTIME_BIT);
    bool private_key = (op & FUTEX_PRIVATE_BIT) != 0;
    bool realtime = (op & FUTEX_REALTIME_BIT) != 0;
    if (command == FUTEX_WAKE_OPERATION) {
        if (realtime || futex->family_context == NULL) {
            *result = linux_error(ENOSYS);
            return true;
        }
        return family_wake_op(futex, args, private_key, result);
    }
    if (command == FUTEX_REQUEUE_OP || command == FUTEX_CMP_REQUEUE_OP) {
        if (realtime) {
            *result = linux_error(ENOSYS);
            return true;
        }
        return requeue_key(futex, args, private_key,
                           command == FUTEX_CMP_REQUEUE_OP, result);
    }
    bool wait = command == FUTEX_WAIT_OP || command == FUTEX_WAIT_BITSET_OP;
    bool wake = command == FUTEX_WAKE_OP || command == FUTEX_WAKE_BITSET_OP;
    if (!wait && !wake) {
        *result = linux_error(ENOSYS);
        return true;
    }
    uint32_t bitset = command == FUTEX_WAIT_BITSET_OP ||
                      command == FUTEX_WAKE_BITSET_OP ? (uint32_t)args[5] : UINT32_MAX;
    if (wake) {
        if (realtime) {
            *result = linux_error(ENOSYS);
            return true;
        }
        if (bitset == 0) {
            *result = linux_error(EINVAL);
            return true;
        }
        return wake_key(futex, args[0], private_key, (uint32_t)args[2],
                        bitset, result);
    }
    if (waiter->queued || waiter->backing != NULL) {
        errno = EBUSY;
        return false;
    }

    bool has_deadline = args[3] != 0;
    uint64_t deadline = 0;
    if (has_deadline) {
        if (!read_timeout(futex, args[3], command == FUTEX_WAIT_OP, realtime,
                          &deadline, result))
            return false;
        if (*result != 0)
            return true;
    }
    if (realtime && command != FUTEX_WAIT_BITSET_OP) {
        *result = linux_error(ENOSYS);
        return true;
    }
    if (bitset == 0) {
        *result = linux_error(EINVAL);
        return true;
    }
    if (futex->family_context != NULL) {
        sparc64_linux_futex_context_t context;
        sparc64_family_wait_key_t key;
        if (!family_context(futex, &context) ||
            !sparc64_linux_futex_key(context.memory, context.backing, context.mm_id,
                                 args[0], private_key, false, &key, result))
            return false;
    } else if (!address_key(futex, args[0], private_key, result))
        return false;
    if (*result != 0)
        return true;
    unsigned char bytes[4];
    if (!sparc64_space_read(futex->space, args[0], bytes, sizeof(bytes), SPARC64_MEM_READ)) {
        return read_error(futex, result);
    }
    if (little32(bytes) != (uint32_t)args[2]) {
        *result = linux_error(EAGAIN);
        return true;
    }
    if (has_deadline) {
        uint64_t now;
        if (!clock_now(realtime, &now))
            return false;
        if (now >= deadline) {
            *result = linux_error(ETIMEDOUT);
            return true;
        }
    }
    sparc64_page_t *page = find_page(futex->space, args[0]);
    if (page == NULL || !sparc64_backing_retain(page->backing)) {
        futex->space->fault_reason = SPARC64_FAULT_INTERNAL;
        futex->space->internal_failure = true;
        return false;
    }
    if (futex->family_context != NULL) {
        bool success = family_enqueue(futex, waiter, args[0], private_key,
                                        bitset, result);
        if (!success || *result != 0) {
            sparc64_backing_release(page->backing);
            return success;
        }
    }
    waiter->address = args[0];
    waiter->private_key = private_key;
    waiter->bitset = bitset;
    waiter->has_deadline = has_deadline;
    waiter->deadline_ns = deadline;
    waiter->realtime = realtime;
    waiter->ticket = ticket;
    waiter->backing = page->backing;
    waiter->queued = true;
    waiter->next = NULL;
    atomic_store_explicit(&waiter->woken, false, memory_order_release);
    if (futex->tail == NULL)
        futex->head = waiter;
    else
        futex->tail->next = waiter;
    futex->tail = waiter;
    *result = 0;
    *waiting = true;
    return true;
}
