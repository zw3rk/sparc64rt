/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "fd_split.h"


sparc64_fd_description_t *new_description(int host_fd, uint64_t id)
{
    sparc64_fd_description_t *description = malloc(sizeof(*description));
    if (description == NULL)
        return NULL;
    *description = (sparc64_fd_description_t){.host_fd = host_fd, .refs = 1, .id = id};
    return description;
}

sparc64_fd_entry_t make_entry(sparc64_fd_description_t *description,
                                bool cloexec, bool reserved, uint32_t hidden)
{
    return (sparc64_fd_entry_t){
        .host_fd = description->host_fd, .guest_cloexec = cloexec,
        .reserved = reserved, .hidden_status_flags = hidden,
        .description_id = description->id, .description = description
    };
}

/* Must run under table mutex; caller closes/frees the final object afterward. */
sparc64_fd_description_t *drop_reference(sparc64_fd_description_t *description)
{
    assert(description != NULL && description->refs != 0);
    return --description->refs == 0 ? description : NULL;
}

int destroy_description(sparc64_fd_description_t *description)
{
    if (description == NULL)
        return 0;
    int result = close(description->host_fd);
    int saved = errno;
    free(description);
    errno = saved;
    return result;
}

int duplicate_private(int host_fd)
{
    return fcntl(host_fd, F_DUPFD_CLOEXEC, 3);
}

static void snapshot_free(sparc64_fd_snapshot_t *snapshot)
{
    if (snapshot == NULL)
        return;
    if (snapshot->leases != NULL) {
        for (uint32_t i = 0; i < snapshot->description_count; ++i) {
            bool already_closed = false;
            for (uint32_t previous = 0; previous < i; ++previous)
                if (snapshot->leases[previous] == snapshot->leases[i]) {
                    already_closed = true;
                    break;
                }
            if (!already_closed && snapshot->leases[i] >= 3)
                (void)close(snapshot->leases[i]);
        }
    }
    free(snapshot->leases);
    free(snapshot->descriptions);
    free(snapshot->entries);
    free(snapshot);
}

void sparc64_fd_snapshot_destroy(sparc64_fd_snapshot_t *snapshot)
{
    snapshot_free(snapshot);
}

static int snapshot_description_index(const sparc64_fd_snapshot_t *snapshot,
                                     uint64_t id)
{
    for (uint32_t i = 0; i < snapshot->description_count; ++i)
        if (snapshot->descriptions[i].id == id)
            return (int)i;
    return -1;
}

int sparc64_fd_snapshot_create(sparc64_fd_table_t *table, sparc64_fd_snapshot_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    if (lock_table(table) != 0)
        return -1;
    if (table->active_borrows != 0) {
        unlock_table(table);
        errno = EBUSY;
        return -1;
    }
    if (table->next_description_id == 0) {
        unlock_table(table);
        errno = EINVAL;
        return -1;
    }

    uint32_t entry_count = 0;
    uint32_t description_count = 0;
    for (uint32_t guest = 0; guest < SPARC64_FD_TABLE_LIMIT; ++guest) {
        const sparc64_fd_entry_t *entry = &table->entries[guest];
        if (entry->reserved) {
            unlock_table(table);
            errno = EBUSY;
            return -1;
        }
        if (!entry_is_guest(entry))
            continue;
        if (entry->description == NULL || entry->description->host_fd < 3 ||
            entry->description_id != entry->description->id ||
            entry->description_id == 0 ||
            entry->description_id >= table->next_description_id ||
            entry->host_fd != entry->description->host_fd) {
            unlock_table(table);
            errno = EINVAL;
            return -1;
        }
        ++entry_count;
        bool found = false;
        for (uint32_t previous = 0; previous < guest; ++previous) {
            const sparc64_fd_entry_t *prior = &table->entries[previous];
            if (entry_is_guest(prior) &&
                prior->description_id == entry->description_id) {
                if (prior->description != entry->description) {
                    unlock_table(table);
                    errno = EINVAL;
                    return -1;
                }
                found = true;
                break;
            }
        }
        if (!found)
            ++description_count;
    }

    sparc64_fd_snapshot_t *snapshot = calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) {
        int saved_errno = errno;
        unlock_table(table);
        errno = saved_errno;
        return -1;
    }
    snapshot->version = SPARC64_FD_SNAPSHOT_VERSION;
    snapshot->entry_count = entry_count;
    snapshot->description_count = description_count;
    snapshot->next_description_id = table->next_description_id;
    if (entry_count != 0)
        snapshot->entries = calloc(entry_count, sizeof(*snapshot->entries));
    if (description_count != 0) {
        snapshot->descriptions = calloc(description_count,
                                         sizeof(*snapshot->descriptions));
        snapshot->leases = malloc((size_t)description_count * sizeof(*snapshot->leases));
        if (snapshot->leases != NULL)
            for (uint32_t i = 0; i < description_count; ++i)
                snapshot->leases[i] = -1;
    }
    if ((entry_count != 0 && snapshot->entries == NULL) ||
        (description_count != 0 && (snapshot->descriptions == NULL ||
                                    snapshot->leases == NULL))) {
        int saved_errno = errno;
        unlock_table(table);
        snapshot_free(snapshot);
        errno = saved_errno;
        return -1;
    }
    uint32_t next_entry = 0;
    uint32_t next_description = 0;
    int failure = 0;
    for (uint32_t guest = 0; guest < SPARC64_FD_TABLE_LIMIT; ++guest) {
        const sparc64_fd_entry_t *entry = &table->entries[guest];
        if (!entry_is_guest(entry))
            continue;
        int index = snapshot_description_index(snapshot,
                                                entry->description_id);
        if (index < 0) {
            index = (int)next_description++;
            const sparc64_fd_description_t *description = entry->description;
            snapshot->descriptions[index] = (sparc64_fd_snapshot_description_t){
                .id = description->id,
                .logical_read_only = description->logical_read_only ? 1u : 0u,
                .pipe_writer = description->owned_pipe_writer ? 1u : 0u,
                .pipe_endpoint = description->owned_pipe_endpoint ? 1u : 0u,
                .fifo_writer = description->managed_fifo_writer ? 1u : 0u,
                .fifo_endpoint = description->managed_fifo_endpoint ? 1u : 0u
            };
            snapshot->leases[index] = duplicate_private(description->host_fd);
            if (snapshot->leases[index] < 0) {
                failure = errno;
                break;
            }
        }
        snapshot->entries[next_entry++] = (sparc64_fd_snapshot_entry_t){
            .guest_fd = guest,
            .description_index = (uint32_t)index,
            .hidden_status_flags = entry->hidden_status_flags,
            .guest_cloexec = entry->guest_cloexec ? 1u : 0u
        };
    }
    unlock_table(table);
    if (failure != 0) {
        snapshot_free(snapshot);
        errno = failure;
        return -1;
    }
    *out = snapshot;
    return 0;
}

static int snapshot_validate(const sparc64_fd_snapshot_t *snapshot,
                             uint32_t *description_refs)
{
    if (snapshot == NULL || snapshot->version != SPARC64_FD_SNAPSHOT_VERSION ||
        snapshot->reserved != 0 || snapshot->entry_count > SPARC64_FD_TABLE_LIMIT ||
        snapshot->description_count > snapshot->entry_count ||
        (snapshot->entry_count != 0 && snapshot->entries == NULL) ||
        (snapshot->description_count != 0 &&
         (snapshot->descriptions == NULL || snapshot->leases == NULL)) ||
        snapshot->next_description_id == 0) {
        errno = EINVAL;
        return -1;
    }
    if (snapshot->description_count != 0)
        memset(description_refs, 0,
               (size_t)snapshot->description_count * sizeof(*description_refs));
    for (uint32_t i = 0; i < snapshot->description_count; ++i) {
        const sparc64_fd_snapshot_description_t *description =
            &snapshot->descriptions[i];
        if (description->id == 0 ||
            description->id >= snapshot->next_description_id ||
            description->logical_read_only > 1u ||
            description->pipe_writer > 1u || description->pipe_endpoint > 1u ||
            (description->pipe_writer != 0 && description->pipe_endpoint == 0) ||
            description->fifo_writer > 1u || description->fifo_endpoint > 1u ||
            (description->fifo_writer != 0 && description->fifo_endpoint == 0) ||
            (description->fifo_writer != 0 &&
             description->logical_read_only != 0) ||
            (description->fifo_endpoint != 0 &&
             description->pipe_endpoint != 0) ||
            description->reserved[0] != 0 || description->reserved[1] != 0 ||
            description->reserved[2] != 0 ||
            snapshot->leases[i] < 3) {
            errno = EINVAL;
            return -1;
        }
        for (uint32_t j = 0; j < i; ++j)
            if (snapshot->descriptions[j].id == description->id ||
                snapshot->leases[j] == snapshot->leases[i]) {
                errno = EINVAL;
                return -1;
            }
        int flags = fcntl(snapshot->leases[i], F_GETFD);
        if (flags < 0)
            return -1;
        if ((flags & FD_CLOEXEC) == 0) {
            errno = EINVAL;
            return -1;
        }
        if (description->fifo_endpoint != 0 || description->pipe_endpoint != 0) {
            struct stat status;
            int file_flags = fcntl(snapshot->leases[i], F_GETFL);
            if (fstat(snapshot->leases[i], &status) < 0 || file_flags < 0)
                return -1;
#ifdef O_PATH
            if ((file_flags & O_PATH) != 0) {
                errno = EINVAL;
                return -1;
            }
#endif
            if (!S_ISFIFO(status.st_mode) ||
                ((description->fifo_writer != 0 || description->pipe_writer != 0) &&
                 (file_flags & O_ACCMODE) == O_RDONLY)) {
                errno = EINVAL;
                return -1;
            }
        }
    }
    for (uint32_t i = 0; i < snapshot->entry_count; ++i) {
        const sparc64_fd_snapshot_entry_t *entry = &snapshot->entries[i];
        if (entry->guest_fd >= SPARC64_FD_TABLE_LIMIT ||
            entry->description_index >= snapshot->description_count ||
            entry->guest_cloexec > 1u || entry->reserved[0] != 0 ||
            entry->reserved[1] != 0 || entry->reserved[2] != 0) {
            errno = EINVAL;
            return -1;
        }
        for (uint32_t j = 0; j < i; ++j)
            if (snapshot->entries[j].guest_fd == entry->guest_fd) {
                errno = EINVAL;
                return -1;
            }
        if (description_refs[entry->description_index] == UINT32_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
        ++description_refs[entry->description_index];
    }
    for (uint32_t i = 0; i < snapshot->description_count; ++i)
        if (description_refs[i] == 0) {
            errno = EINVAL;
            return -1;
        }
    if ((snapshot->entry_count == 0) != (snapshot->description_count == 0)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int sparc64_fd_snapshot_restore(const sparc64_fd_snapshot_t *snapshot,
                           sparc64_fd_table_t *destination)
{
    if (destination == NULL || destination->initialized) {
        errno = EINVAL;
        return -1;
    }
    uint32_t *description_refs = NULL;
    sparc64_fd_description_t **descriptions = NULL;
    int *host_fds = NULL;
    if (snapshot == NULL || snapshot->description_count > SPARC64_FD_TABLE_LIMIT) {
        errno = EINVAL;
        return -1;
    }
    if (snapshot->description_count != 0) {
        description_refs = calloc(snapshot->description_count,
                                  sizeof(*description_refs));
        descriptions = calloc(snapshot->description_count, sizeof(*descriptions));
        host_fds = malloc((size_t)snapshot->description_count * sizeof(*host_fds));
        if (description_refs == NULL || descriptions == NULL || host_fds == NULL) {
            int saved_errno = errno;
            free(description_refs);
            free(descriptions);
            free(host_fds);
            errno = saved_errno;
            return -1;
        }
        for (uint32_t i = 0; i < snapshot->description_count; ++i)
            host_fds[i] = -1;
    }
    if (snapshot_validate(snapshot, description_refs) != 0)
        goto fail;

    /* Allocate the complete replacement state before initializing the mutex. */
    for (uint32_t i = 0; i < snapshot->description_count; ++i) {
        host_fds[i] = duplicate_private(snapshot->leases[i]);
        if (host_fds[i] < 0)
            goto fail;
        descriptions[i] = calloc(1, sizeof(*descriptions[i]));
        if (descriptions[i] == NULL)
            goto fail;
        const sparc64_fd_snapshot_description_t *record = &snapshot->descriptions[i];
        *descriptions[i] = (sparc64_fd_description_t){
            .host_fd = host_fds[i],
            .refs = description_refs[i],
            .id = record->id,
            .logical_read_only = record->logical_read_only != 0,
            .owned_pipe_writer = record->pipe_writer != 0,
            .owned_pipe_endpoint = record->pipe_endpoint != 0,
            .managed_fifo_writer = record->fifo_writer != 0,
            .managed_fifo_endpoint = record->fifo_endpoint != 0
        };
    }
    int mutex_result = pthread_mutex_init(&destination->mutex, NULL);
    if (mutex_result != 0) {
        errno = mutex_result;
        goto fail;
    }
    for (uint32_t i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        destination->entries[i] = (sparc64_fd_entry_t){.host_fd = -1};
    for (uint32_t i = 0; i < snapshot->entry_count; ++i) {
        const sparc64_fd_snapshot_entry_t *entry = &snapshot->entries[i];
        sparc64_fd_description_t *description = descriptions[entry->description_index];
        destination->entries[entry->guest_fd] = make_entry(
            description, entry->guest_cloexec != 0, false,
            entry->hidden_status_flags);
    }
    destination->next_description_id = snapshot->next_description_id;
    destination->active_borrows = 0;
    destination->owner_pid = getpid();
    destination->initialized = true;
    free(description_refs);
    free(descriptions);
    free(host_fds);
    return 0;

fail: {
        int saved_errno = errno;
        if (host_fds != NULL) {
            for (uint32_t i = 0; i < snapshot->description_count; ++i)
                if (host_fds[i] >= 3)
                    (void)close(host_fds[i]);
        }
        if (descriptions != NULL) {
            for (uint32_t i = 0; i < snapshot->description_count; ++i)
                free(descriptions[i]);
        }
        free(description_refs);
        free(descriptions);
        free(host_fds);
        errno = saved_errno;
        return -1;
    }
}

int sparc64_fd_fork_child_prepare(sparc64_fd_table_t *table, sparc64_fd_fork_child_t **out)
{
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out = NULL;
    sparc64_fd_snapshot_t *snapshot = NULL;
    if (sparc64_fd_snapshot_create(table, &snapshot) != 0)
        return -1;
    sparc64_fd_fork_child_t *owner = calloc(1, sizeof(*owner));
    if (owner == NULL) {
        int saved = errno;
        sparc64_fd_snapshot_destroy(snapshot);
        errno = saved;
        return -1;
    }
    *owner = (sparc64_fd_fork_child_t){
        .source = table, .snapshot = snapshot, .creator_pid = getpid()
    };
    *out = owner;
    return 0;
}

void sparc64_fd_fork_child_destroy(sparc64_fd_fork_child_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    sparc64_fd_fork_child_t *owner = *owned;
    *owned = NULL;
    sparc64_fd_snapshot_destroy(owner->snapshot);
    free(owner);
}

/* The child may inspect, but must never lock, the inherited table. Validate
 * every alias and both sets of native FDs before the first irreversible close.
 * The prepared snapshot contains the full table, including CLOEXEC entries. */
static int fork_child_validate(sparc64_fd_table_t *table,
                               const sparc64_fd_snapshot_t *snapshot,
                               sparc64_fd_description_t *descriptions[SPARC64_FD_TABLE_LIMIT])
{
    uint32_t expected_refs[SPARC64_FD_TABLE_LIMIT] = {0};
    uint32_t observed_refs[SPARC64_FD_TABLE_LIMIT] = {0};
    if (snapshot_validate(snapshot, expected_refs) != 0)
        return -1;
    if (!table->initialized || table->active_borrows != 0 ||
        table->next_description_id != snapshot->next_description_id) {
        errno = EBUSY;
        return -1;
    }
    memset(descriptions, 0, SPARC64_FD_TABLE_LIMIT * sizeof(*descriptions));
    uint32_t observed_entries = 0;
    for (uint32_t guest = 0; guest < SPARC64_FD_TABLE_LIMIT; ++guest) {
        const sparc64_fd_entry_t *entry = &table->entries[guest];
        const sparc64_fd_snapshot_entry_t *record = NULL;
        for (uint32_t j = 0; j < snapshot->entry_count; ++j)
            if (snapshot->entries[j].guest_fd == guest) {
                record = &snapshot->entries[j];
                break;
            }
        if (record == NULL) {
            if (entry->host_fd != -1 || entry->description != NULL ||
                entry->reserved) {
                errno = EBUSY;
                return -1;
            }
            continue;
        }
        ++observed_entries;
        uint32_t index = record->description_index;
        const sparc64_fd_snapshot_description_t *saved =
            &snapshot->descriptions[index];
        sparc64_fd_description_t *description = entry->description;
        if (entry->reserved || description == NULL ||
            entry->host_fd < 3 || entry->host_fd != description->host_fd ||
            entry->description_id != saved->id || description->id != saved->id ||
            entry->guest_cloexec != (record->guest_cloexec != 0) ||
            entry->hidden_status_flags != record->hidden_status_flags ||
            description->logical_read_only != (saved->logical_read_only != 0) ||
            description->owned_pipe_writer != (saved->pipe_writer != 0) ||
            description->owned_pipe_endpoint != (saved->pipe_endpoint != 0) ||
            description->managed_fifo_writer != (saved->fifo_writer != 0) ||
            description->managed_fifo_endpoint != (saved->fifo_endpoint != 0) ||
            (descriptions[index] != NULL && descriptions[index] != description)) {
            errno = EINVAL;
            return -1;
        }
        descriptions[index] = description;
        ++observed_refs[index];
    }
    if (observed_entries != snapshot->entry_count) {
        errno = EINVAL;
        return -1;
    }
    for (uint32_t i = 0; i < snapshot->description_count; ++i) {
        sparc64_fd_description_t *description = descriptions[i];
        if (description == NULL || description->refs != expected_refs[i] ||
            observed_refs[i] != expected_refs[i]) {
            errno = EINVAL;
            return -1;
        }
        if (fcntl(description->host_fd, F_GETFD) < 0)
            return -1;
        for (uint32_t j = 0; j < snapshot->description_count; ++j) {
            if (description->host_fd == snapshot->leases[j] ||
                (j < i && description->host_fd == descriptions[j]->host_fd)) {
                errno = EINVAL;
                return -1;
            }
        }
    }
    return 0;
}

int sparc64_fd_fork_child_rebase(sparc64_fd_fork_child_t **owned,
                           sparc64_fd_table_t *copied_table)
{
    if (owned == NULL || *owned == NULL || copied_table == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_fd_fork_child_t *owner = *owned;
    if (owner->creator_pid == getpid() ||
        owner->source != copied_table ||
        copied_table->owner_pid != owner->creator_pid) {
        errno = EPERM;
        return -1;
    }
    sparc64_fd_description_t *descriptions[SPARC64_FD_TABLE_LIMIT];
    if (fork_child_validate(copied_table, owner->snapshot, descriptions) != 0)
        return -1;

    /* Native leases and description heaps are private process copies. The
     * copied mutex is never unlocked or destroyed, even if its parent held it. */
    for (uint32_t i = 0; i < owner->snapshot->description_count; ++i) {
        if (close(descriptions[i]->host_fd) != 0)
            _exit(125); /* Partial disposal cannot be rolled back. */
        free(descriptions[i]);
    }
    memset(copied_table, 0, sizeof(*copied_table));
    int result = sparc64_fd_snapshot_restore(owner->snapshot, copied_table);
    int saved = errno;
    sparc64_fd_fork_child_destroy(owned);
    errno = saved;
    return result;
}

int lock_table(sparc64_fd_table_t *table)
{
    if (table == NULL || !table->initialized) {
        errno = EINVAL;
        return -1;
    }
    if (table->owner_pid != getpid()) {
        errno = EPERM; /* Never enter a mutex copied from another process. */
        return -1;
    }
    int result = pthread_mutex_lock(&table->mutex);
    if (result != 0) {
        errno = result;
        return -1;
    }
    return 0;
}

void unlock_table(sparc64_fd_table_t *table)
{
    (void)pthread_mutex_unlock(&table->mutex);
}

int add_description(sparc64_fd_table_t *table, uint64_t *description_id)
{
    if (table->next_description_id == UINT64_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    *description_id = table->next_description_id++;
    return 0;
}

int free_guest_slot(const sparc64_fd_table_t *table, unsigned int minimum)
{
    for (unsigned int guest = minimum; guest < SPARC64_FD_TABLE_LIMIT; ++guest)
        if (table->entries[guest].host_fd < 0)
            return (int)guest;
    errno = EMFILE;
    return -1;
}

bool entry_is_guest(const sparc64_fd_entry_t *entry)
{
    return entry->host_fd >= 0 && !entry->reserved;
}

int create_placeholder(void)
{
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    int root_fd = open("/", flags);
    if (root_fd < 0)
        return -1;
    int placeholder = duplicate_private(root_fd);
    int saved_errno = errno;
    (void)close(root_fd);
    if (placeholder < 0)
        errno = saved_errno;
    return placeholder;
}

static int table_init_empty(sparc64_fd_table_t *table)
{
    if (table == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(table, 0, sizeof(*table));
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        table->entries[i].host_fd = -1;
    int result = pthread_mutex_init(&table->mutex, NULL);
    if (result != 0) {
        errno = result;
        return -1;
    }
    table->initialized = true;
    table->owner_pid = getpid();
    table->next_description_id = 1;
    return 0;
}

int sparc64_fd_table_init_initial(sparc64_fd_table_t *table, sparc64_fd_initial_t **owned)
{
    if (owned == NULL || *owned == NULL) { errno = EINVAL; return -1; }
    if (table_init_empty(table) != 0)
        return -1;
    sparc64_fd_initial_t *initial = *owned;
    sparc64_fd_description_t *staged[SPARC64_FD_TABLE_LIMIT] = {0};
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i) {
        int fd = initial->descriptors[i];
        if (fd < 0)
            continue;
        if (fd < 3) { errno = EINVAL; goto failed; }
        staged[i] = new_description(fd, table->next_description_id++);
        if (staged[i] == NULL)
            goto failed;
    }
    /* No allocation or failure remains: move plain native capabilities into
     * their prepared descriptions. The table's mutex was initialized here. */
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i) {
        if (staged[i] == NULL)
            continue;
        table->entries[i] = make_entry(staged[i], false, false, 0);
        initial->descriptors[i] = -1;
    }
    free(initial);
    *owned = NULL;
    return 0;
failed:;
    int saved = errno;
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i)
        free(staged[i]); /* Initial owner still owns every native cap. */
    sparc64_fd_table_destroy(table);
    errno = saved;
    return -1;
}

int sparc64_fd_table_init(sparc64_fd_table_t *table)
{
    if (table_init_empty(table) != 0)
        return -1;
    for (unsigned int guest = 0; guest < 3; ++guest) {
        int private_fd = duplicate_private((int)guest);
        if (private_fd < 0) {
            if (errno == EBADF)
                continue;
            int saved_errno = errno;
            sparc64_fd_table_destroy(table);
            errno = saved_errno;
            return -1;
        }
        uint64_t description_id;
        if (add_description(table, &description_id) != 0) {
            int saved_errno = errno;
            (void)close(private_fd);
            sparc64_fd_table_destroy(table);
            errno = saved_errno;
            return -1;
        }
        sparc64_fd_description_t *description = new_description(private_fd, description_id);
        if (description == NULL) {
            int saved_errno = errno;
            (void)close(private_fd);
            sparc64_fd_table_destroy(table);
            errno = saved_errno;
            return -1;
        }
        table->entries[guest] = make_entry(description, false, false, 0);
    }
    return 0;
}

void sparc64_fd_table_destroy(sparc64_fd_table_t *table)
{
    if (table == NULL || !table->initialized)
        return;
    if (table->owner_pid != getpid())
        _exit(125); /* Void cleanup must never pretend copied mutex release. */
    int result = pthread_mutex_lock(&table->mutex);
    if (result != 0)
        return;
    assert(table->active_borrows == 0);
    for (unsigned int i = 0; i < SPARC64_FD_TABLE_LIMIT; ++i) {
        sparc64_fd_description_t *description = table->entries[i].description;
        if (description != NULL)
            (void)destroy_description(drop_reference(description));
        table->entries[i] = (sparc64_fd_entry_t){.host_fd = -1};
    }
    table->initialized = false;
    (void)pthread_mutex_unlock(&table->mutex);
    (void)pthread_mutex_destroy(&table->mutex);
}

int sparc64_fd_install(sparc64_fd_table_t *table, int owned_host_fd, bool cloexec)
{
    if (owned_host_fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (table == NULL || !table->initialized) {
        int saved_errno = EINVAL;
        (void)close(owned_host_fd);
        errno = saved_errno;
        return -1;
    }
    sparc64_fd_description_t *description = new_description(-1, 0);
    if (description == NULL) {
        int saved_errno = errno;
        (void)close(owned_host_fd);
        errno = saved_errno;
        return -1;
    }
    int private_fd = duplicate_private(owned_host_fd);
    int duplicate_errno = errno;
    (void)close(owned_host_fd);
    if (private_fd < 0) {
        free(description);
        errno = duplicate_errno;
        return -1;
    }
    if (lock_table(table) != 0) {
        int saved_errno = errno;
        (void)close(private_fd);
        free(description);
        errno = saved_errno;
        return -1;
    }
    int guest = free_guest_slot(table, 0);
    if (guest < 0) {
        int saved_errno = errno;
        unlock_table(table);
        (void)close(private_fd);
        free(description);
        errno = saved_errno;
        return -1;
    }
    uint64_t description_id;
    if (add_description(table, &description_id) != 0) {
        int saved_errno = errno;
        unlock_table(table);
        (void)close(private_fd);
        free(description);
        errno = saved_errno;
        return -1;
    }
    description->host_fd = private_fd;
    description->id = description_id;
    table->entries[guest] = make_entry(description, cloexec, false, 0);
    unlock_table(table);
    return guest;
}
