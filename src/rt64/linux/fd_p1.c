/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "fd_split.h"


static int commit_description(sparc64_fd_table_t *table, unsigned int guest_fd,
                              int owned_host_fd, bool cloexec,
                              uint32_t hidden_status_flags,
                              bool logical_read_only, bool pipe_endpoint,
                              bool pipe_writer, bool managed_fifo,
                              bool fifo_writer);

int sparc64_fd_reserve(sparc64_fd_table_t *table)
{
    if (lock_table(table) != 0)
        return -1;
    int guest = free_guest_slot(table, 0);
    if (guest < 0) {
        int saved_errno = errno;
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    uint64_t description_id;
    if (add_description(table, &description_id) != 0) {
        int saved_errno = errno;
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    sparc64_fd_description_t *description = new_description(-1, description_id);
    if (description == NULL) {
        int saved_errno = errno;
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    int placeholder = create_placeholder();
    int saved_errno = errno;
    if (placeholder < 0) {
        free(description);
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    description->host_fd = placeholder;
    table->entries[guest] = make_entry(description, false, true, 0);
    unlock_table(table);
    return guest;
}

static int replace_placeholder(int source_fd, int placeholder_fd)
{
#if defined(__linux__)
    int result;
    do {
        result = dup3(source_fd, placeholder_fd, O_CLOEXEC);
    } while (result < 0 && errno == EINTR);
    return result;
#else
    int result;
    do {
        result = dup2(source_fd, placeholder_fd);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
        return -1;
    int flags;
    do {
        flags = fcntl(placeholder_fd, F_SETFD, FD_CLOEXEC);
    } while (flags < 0 && errno == EINTR);
    return flags < 0 ? -1 : result;
#endif
}

int sparc64_fd_commit(sparc64_fd_table_t *table, unsigned int guest_fd,
                 int owned_host_fd, bool cloexec,
                 uint32_t hidden_status_flags)
{
    return sparc64_fd_commit_with_access(table, guest_fd, owned_host_fd, cloexec,
                                     hidden_status_flags, false);
}

int sparc64_fd_commit_with_access(sparc64_fd_table_t *table, unsigned int guest_fd,
                              int owned_host_fd, bool cloexec,
                              uint32_t hidden_status_flags,
                              bool logical_read_only)
{
    return commit_description(table, guest_fd, owned_host_fd, cloexec,
                              hidden_status_flags, logical_read_only,
                              false, false, false, false);
}

int sparc64_fd_commit_managed_fifo(sparc64_fd_table_t *table, unsigned int guest_fd,
                               int owned_host_fd, bool cloexec,
                               uint32_t hidden_status_flags,
                               bool logical_read_only, bool writer)
{
    return commit_description(table, guest_fd, owned_host_fd, cloexec,
                              hidden_status_flags, logical_read_only,
                              false, false, true, writer);
}

int sparc64_fd_commit_pipe_reader(sparc64_fd_table_t *table, unsigned int guest_fd,
                             int owned_host_fd, bool cloexec)
{
    return commit_description(table, guest_fd, owned_host_fd, cloexec,
                              0, false, true, false, false, false);
}

int sparc64_fd_commit_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd,
                             int owned_host_fd, bool cloexec)
{
    return commit_description(table, guest_fd, owned_host_fd, cloexec,
                              0, false, true, true, false, false);
}

int sparc64_fd_is_pipe_writer(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    int result = table->entries[guest_fd].description->owned_pipe_writer ? 1 : 0;
    unlock_table(table);
    return result;
}

int sparc64_fd_is_pipe_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    int result = table->entries[guest_fd].description->owned_pipe_endpoint ? 1 : 0;
    unlock_table(table);
    return result;
}

static int inspect_fifo(sparc64_fd_table_t *table, unsigned int guest_fd,
                        bool require_writer)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    /* Holding the table mutex pins this native description against guest
     * close/dup3. fstat/fcntl inspect it; neither opens or closes an alias. */
    int host = table->entries[guest_fd].description->host_fd;
    struct stat status;
    int flags = fcntl(host, F_GETFL);
    int saved = errno;
    if (flags >= 0 && fstat(host, &status) < 0) {
        flags = -1;
        saved = errno;
    }
    int result = 0;
    if (flags >= 0) {
#ifdef O_PATH
        bool path_only = (flags & O_PATH) != 0;
#else
        bool path_only = false;
#endif
        result = !path_only && S_ISFIFO(status.st_mode) &&
                 (!require_writer || (flags & O_ACCMODE) != O_RDONLY);
    }
    unlock_table(table);
    if (flags < 0)
        errno = saved;
    return flags < 0 ? -1 : result;
}

int sparc64_fd_is_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    return inspect_fifo(table, guest_fd, true);
}

int sparc64_fd_is_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    return inspect_fifo(table, guest_fd, false);
}

static int inspect_managed_fifo(sparc64_fd_table_t *table, unsigned int guest_fd,
                                bool writer)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    const sparc64_fd_description_t *description =
        table->entries[guest_fd].description;
    int result = writer ? description->managed_fifo_writer :
                          description->managed_fifo_endpoint;
    unlock_table(table);
    return result;
}

int sparc64_fd_is_managed_fifo_writer(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    return inspect_managed_fifo(table, guest_fd, true);
}

int sparc64_fd_is_managed_fifo_endpoint(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    return inspect_managed_fifo(table, guest_fd, false);
}

static int commit_description(sparc64_fd_table_t *table, unsigned int guest_fd,
                              int owned_host_fd, bool cloexec,
                              uint32_t hidden_status_flags,
                              bool logical_read_only, bool pipe_endpoint,
                              bool pipe_writer, bool managed_fifo,
                              bool fifo_writer)
{
    if (owned_host_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (lock_table(table) != 0) {
        int saved_errno = errno;
        (void)close(owned_host_fd);
        errno = saved_errno;
        return -1;
    }
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !table->entries[guest_fd].reserved ||
        table->entries[guest_fd].host_fd < 3) {
        unlock_table(table);
        (void)close(owned_host_fd);
        errno = EBADF;
        return -1;
    }

    sparc64_fd_description_t *description = table->entries[guest_fd].description;
    int placeholder_fd = description->host_fd;

    int replacement = replace_placeholder(owned_host_fd, placeholder_fd);
    int saved_errno = errno;
    (void)close(owned_host_fd);
    if (replacement < 0) {
        table->entries[guest_fd] = (sparc64_fd_entry_t){.host_fd = -1};
        unlock_table(table);
        (void)destroy_description(description);
        errno = saved_errno;
        return -1;
    }
    description->logical_read_only = logical_read_only;
    description->owned_pipe_writer = pipe_writer;
    description->owned_pipe_endpoint = pipe_endpoint;
    description->managed_fifo_endpoint = managed_fifo;
    description->managed_fifo_writer = managed_fifo && fifo_writer;
    table->entries[guest_fd] = make_entry(description, cloexec, false,
                                          hidden_status_flags);
    unlock_table(table);
    return 0;
}

int sparc64_fd_cancel(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !table->entries[guest_fd].reserved ||
        table->entries[guest_fd].host_fd < 3) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    sparc64_fd_description_t *description = table->entries[guest_fd].description;
    table->entries[guest_fd] = (sparc64_fd_entry_t){.host_fd = -1};
    unlock_table(table);
    return destroy_description(description);
}

int sparc64_fd_acquire(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    uint32_t hidden_status_flags;
    return sparc64_fd_acquire_status(table, guest_fd, &hidden_status_flags);
}

int sparc64_fd_acquire_status(sparc64_fd_table_t *table, unsigned int guest_fd,
                         uint32_t *hidden_status_flags)
{
    bool logical_read_only;
    return sparc64_fd_acquire_mode(table, guest_fd, hidden_status_flags,
                              &logical_read_only);
}

int sparc64_fd_acquire_mode(sparc64_fd_table_t *table, unsigned int guest_fd,
                       uint32_t *hidden_status_flags, bool *logical_read_only)
{
    if (hidden_status_flags == NULL || logical_read_only == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    int lease = duplicate_private(table->entries[guest_fd].description->host_fd);
    int saved_errno = errno;
    if (lease >= 0) {
        *hidden_status_flags = table->entries[guest_fd].hidden_status_flags;
        *logical_read_only = table->entries[guest_fd].description->logical_read_only;
    }
    unlock_table(table);
    if (lease < 0)
        errno = saved_errno;
    return lease;
}

int sparc64_fd_release(int lease_fd)
{
    if (lease_fd < 3) {
        errno = EINVAL;
        return -1;
    }
    return close(lease_fd);
}

int sparc64_fd_borrow(sparc64_fd_table_t *table, unsigned int guest_fd,
                 sparc64_fd_borrow_t *borrow)
{
    if (borrow == NULL || borrow->description != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    sparc64_fd_description_t *description = table->entries[guest_fd].description;
    if (description->refs == SIZE_MAX || table->active_borrows == SIZE_MAX) {
        unlock_table(table);
        errno = EOVERFLOW;
        return -1;
    }
    ++description->refs;
    ++table->active_borrows;
    *borrow = (sparc64_fd_borrow_t){
        .table = table, .description = description, .host_fd = description->host_fd,
        .hidden_status_flags = table->entries[guest_fd].hidden_status_flags,
        .logical_read_only = description->logical_read_only
    };
    unlock_table(table);
    return 0;
}

int sparc64_fd_unborrow(sparc64_fd_borrow_t *borrow)
{
    if (borrow == NULL || borrow->description == NULL || borrow->table == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_fd_table_t *table = borrow->table;
    if (lock_table(table) != 0)
        return -1;
    assert(table->active_borrows != 0);
    --table->active_borrows;
    sparc64_fd_description_t *retired = drop_reference(borrow->description);
    *borrow = (sparc64_fd_borrow_t){.host_fd = -1};
    unlock_table(table);
    return destroy_description(retired);
}

int sparc64_fd_close(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    sparc64_fd_description_t *retired =
        drop_reference(table->entries[guest_fd].description);
    table->entries[guest_fd] = (sparc64_fd_entry_t){.host_fd = -1};
    unlock_table(table);
    return destroy_description(retired);
}

int sparc64_fd_dup(sparc64_fd_table_t *table, unsigned int old_fd,
              unsigned int minimum, bool cloexec)
{
    if (lock_table(table) != 0)
        return -1;
    if (old_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[old_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    if (minimum >= SPARC64_FD_TABLE_LIMIT) {
        unlock_table(table);
        errno = EINVAL;
        return -1;
    }
    int guest = free_guest_slot(table, minimum);
    if (guest < 0) {
        int saved_errno = errno;
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    sparc64_fd_description_t *description = table->entries[old_fd].description;
    if (description->refs == SIZE_MAX) {
        unlock_table(table);
        errno = EOVERFLOW;
        return -1;
    }
    ++description->refs;
    table->entries[guest] = make_entry(description, cloexec, false,
                                       table->entries[old_fd].hidden_status_flags);
    unlock_table(table);
    return guest;
}

int sparc64_fd_dup3(sparc64_fd_table_t *table, unsigned int old_fd,
               unsigned int new_fd, bool cloexec)
{
    if (old_fd == new_fd) {
        errno = EINVAL;
        return -1;
    }
    if (new_fd >= SPARC64_FD_TABLE_LIMIT) {
        errno = EBADF;
        return -1;
    }
    if (lock_table(table) != 0)
        return -1;
    if (old_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[old_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    if (table->entries[new_fd].reserved) {
        unlock_table(table);
        errno = EBUSY;
        return -1;
    }
    sparc64_fd_description_t *description = table->entries[old_fd].description;
    if (description->refs == SIZE_MAX) {
        unlock_table(table);
        errno = EOVERFLOW;
        return -1;
    }
    ++description->refs;
    sparc64_fd_description_t *retired = table->entries[new_fd].description == NULL ?
                                   NULL : drop_reference(table->entries[new_fd].description);
    table->entries[new_fd] = make_entry(description, cloexec, false,
                                        table->entries[old_fd].hidden_status_flags);
    unlock_table(table);
    (void)destroy_description(retired);
    return (int)new_fd;
}

int sparc64_fd_get_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    int result = table->entries[guest_fd].guest_cloexec ? 1 : 0;
    unlock_table(table);
    return result;
}

int sparc64_fd_set_cloexec(sparc64_fd_table_t *table, unsigned int guest_fd,
                      bool cloexec)
{
    if (lock_table(table) != 0)
        return -1;
    if (guest_fd >= SPARC64_FD_TABLE_LIMIT ||
        !entry_is_guest(&table->entries[guest_fd])) {
        unlock_table(table);
        errno = EBADF;
        return -1;
    }
    table->entries[guest_fd].guest_cloexec = cloexec;
    unlock_table(table);
    return 0;
}
