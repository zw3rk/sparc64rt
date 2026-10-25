/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


bool key_equal(sparc64_family_page_key_t left, sparc64_family_page_key_t right)
{
    return left.object_id == right.object_id && left.page_index == right.page_index;
}

bool authority_valid(sparc64_family_storage_authority_t authority)
{
    return authority == SPARC64_FAMILY_AUTHORITY_AUTO ||
           authority == SPARC64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1;
}

bool family_authorize_fd(int fd, bool directory,
                                sparc64_family_storage_authority_t authority)
{
    sparc64_aot_authority_policy_t checked = authority ==
        SPARC64_FAMILY_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 ?
        SPARC64_AOT_AUTHORITY_HYPER_LINUX_APFS_ACL_V1 : SPARC64_AOT_AUTHORITY_AUTO;
    return authority_valid(authority) &&
           sparc64_aot_authorize_fd(fd, directory, checked);
}

int family_control_extent(const sparc64_family_t *family, uint64_t *out)
{
    if (family->zero_backing) {
        *out = family->zero_control.payload_size +
               family->zero_fragment_count * SPARC64_ZERO_CONTROL_FRAGMENT_SIZE;
        return 0;
    }
    struct stat status;
    int result;
    do {
        result = fstat(family->control_fd, &status);
    } while (result != 0 && errno == EINTR);
    if (result != 0)
        return -1;
    if (status.st_size < 0) {
        errno = EIO;
        return -1;
    }
    *out = (uint64_t)status.st_size;
    return 0;
}

static sparc64_zero_object_segment_t *find_zero_object(sparc64_family_t *family,
                                                   uint64_t object_id)
{
    for (sparc64_zero_object_segment_t *entry = family->zero_objects;
         entry != NULL; entry = entry->next)
        if (entry->object_id == object_id)
            return entry;
    return NULL;
}

void close_owned_fds(int control_fd, int dir_fd)
{
    if (control_fd >= 0)
        (void)close(control_fd);
    if (dir_fd >= 0 && dir_fd != control_fd)
        (void)close(dir_fd);
}

void close_family_sources(int control_fd, int dir_fd, sparc64_inode_pins_t pins,
                                  sparc64_file_caps_client_t sources)
{
    int descriptors[6] = {control_fd, dir_fd, pins.sender, pins.receiver,
                          sources.request_fd, sources.lifetime_fd};
    for (size_t i = 0; i < 6; ++i) {
        bool seen = false;
        for (size_t j = 0; j < i; ++j)
            seen = seen || descriptors[i] == descriptors[j];
        if (descriptors[i] >= 0 && !seen)
            (void)close(descriptors[i]);
    }
}

void sparc64_family_close_capabilities(int control_fd, int dir_fd, sparc64_inode_pins_t pins)
{
    close_family_sources(control_fd, dir_fd, pins,
                           (sparc64_file_caps_client_t)SPARC64_FILE_CAPS_CLIENT_INITIALIZER);
}

void sparc64_family_close_source_capabilities(int control_fd, int dir_fd,
                                          sparc64_inode_pins_t pins,
                                          sparc64_file_caps_client_t sources)
{
    close_family_sources(control_fd, dir_fd, pins, sources);
}

bool source_caps_present(sparc64_file_caps_client_t sources)
{
    return sources.request_fd >= 3 && sources.lifetime_fd >= 3;
}

bool distinct_source_fds(int control_fd, int dir_fd, sparc64_inode_pins_t pins,
                                sparc64_file_caps_client_t sources)
{
    bool absent = sources.request_fd == -1 && sources.lifetime_fd == -1;
    int descriptors[6] = {control_fd, dir_fd, pins.sender, pins.receiver,
                          sources.request_fd, sources.lifetime_fd};
    size_t count = absent ? 4u : 6u;
    for (size_t i = 0; i < count; ++i) {
        if (descriptors[i] < 3)
            return false;
        for (size_t j = 0; j < i; ++j)
            if (descriptors[i] == descriptors[j])
                return false;
    }
    return true;
}

void family_fds(const sparc64_family_t *family, int descriptors[4])
{
    descriptors[0] = family->control_fd;
    descriptors[1] = family->dir_fd;
    descriptors[2] = family->pins.sender;
    descriptors[3] = family->pins.receiver;
}

size_t family_all_fds(const sparc64_family_t *family, int descriptors[6])
{
    family_fds(family, descriptors);
    descriptors[4] = family->sources.request_fd;
    descriptors[5] = family->sources.lifetime_fd;
    return source_caps_present(family->sources) ? 6u : 4u;
}

int lock_file(int fd, short type)
{
    struct flock lock = {
        .l_type = type,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 1
    };
    int result;
    do {
        result = fcntl(fd, F_SETLKW, &lock);
    } while (result < 0 && errno == EINTR);
    return result;
}

/* Byte zero is the execution token. A nonreused incarnation owns one later
 * byte for its complete attachment lifetime, even while not executing guest
 * code. Locks beyond EOF are POSIX byte locks; no guest data lives here.
 * Never use another control descriptor: closing any such descriptor drops
 * ALL this process's POSIX locks for the inode. */
bool owner_lease_offset(uint64_t incarnation, off_t *offset)
{
    if (incarnation == 0 || incarnation > (uint64_t)INT64_MAX - 1u)
        return false;
    off_t converted = (off_t)(incarnation + 1u);
    if (converted < 0 || (uint64_t)converted != incarnation + 1u)
        return false;
    *offset = converted;
    return true;
}

int acquire_owner_lease(sparc64_family_t *family, uint64_t incarnation)
{
    off_t offset;
    if (!owner_lease_offset(incarnation, &offset)) {
        errno = EOVERFLOW;
        return -1;
    }
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
                          .l_start = offset, .l_len = 1};
    int result;
    do { result = fcntl(family->control_fd, F_SETLK, &lock); }
    while (result < 0 && errno == EINTR);
    return result;
}

int unlock_family_file(sparc64_family_t *family)
{
#ifdef SPARC64_FAMILY_TESTING
    if (family->test_fail_unlock_once) {
        family->test_fail_unlock_once = false;
        errno = EIO;
        return -1;
    }
#endif
    return lock_file(family->control_fd, F_UNLCK);
}

bool guard_valid_observed(const sparc64_family_guard_t *guard,
                                 sparc64_measure_observer_t *measure)
{
    if (guard == NULL || !guard->held || guard->family == NULL ||
        !guard->family->initialized || guard->family->poisoned ||
        guard->family->exec_active || guard->family->active_guard != guard)
        return false;
    sparc64_measure_stamp_t pid_stamp = sparc64_measure_begin(measure, SPARC64_MEASURE_FAMILY_PID);
    bool local_pid = guard->family->local_pid == getpid();
    sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_PID, pid_stamp);
    return local_pid && guard->incarnation == guard->family->incarnation &&
           pthread_equal(guard->owner_thread, pthread_self()) != 0;
}

bool guard_valid(const sparc64_family_guard_t *guard)
{
    return guard_valid_observed(guard, NULL);
}

void refresh_acquire(sparc64_family_t *family, sparc64_family_guard_t *guard)
{
    if (family->refresh_reuse_disabled ||
        family->refresh_next_acquisition == UINT64_MAX) {
        family->refresh_reuse_disabled = true;
        family->refresh_active_acquisition = 0;
        guard->refresh_acquisition = 0;
        return;
    }
    ++family->refresh_next_acquisition;
    family->refresh_active_acquisition = family->refresh_next_acquisition;
    guard->refresh_acquisition = family->refresh_active_acquisition;
}

void refresh_invalidate(sparc64_family_t *family)
{
    family->refresh_active_acquisition = 0;
}

void refresh_mutate(sparc64_family_t *family)
{
    if (family->refresh_reuse_disabled)
        return;
    if (family->refresh_mutation == UINT64_MAX) {
        family->refresh_reuse_disabled = true;
        return;
    }
    ++family->refresh_mutation;
}

int recover_file_state(sparc64_family_guard_t *guard)
{
#ifdef SPARC64_FAMILY_TESTING
    if (guard->family->test_fail_file_recovery_once) {
        guard->family->test_fail_file_recovery_once = false;
        errno = ENOMEM;
        return -1;
    }
#endif
    return sparc64_family_file_recover(guard);
}

bool sparc64_family_guard_matches(const sparc64_family_guard_t *guard,
                             const sparc64_family_t *family)
{
    return family != NULL && guard_valid(guard) && guard->family == family;
}

bool sparc64_family_guard_matches_observed(const sparc64_family_guard_t *guard,
                                      const sparc64_family_t *family,
                                      sparc64_measure_observer_t *measure)
{
    return family != NULL && guard_valid_observed(guard, measure) &&
           guard->family == family;
}

int sparc64_family_refresh_observation(const sparc64_family_guard_t *guard,
                                  const sparc64_family_t *family,
                                  sparc64_family_refresh_stamp_t *out,
                                  bool *reusable)
{
    return sparc64_family_refresh_observation_observed(guard, family, out,
                                                  reusable, NULL);
}

int sparc64_family_refresh_observation_observed(const sparc64_family_guard_t *guard,
                                           const sparc64_family_t *family,
                                           sparc64_family_refresh_stamp_t *out,
                                           bool *reusable,
                                           sparc64_measure_observer_t *measure)
{
    if (out == NULL || reusable == NULL) {
        errno = EINVAL;
        return -1;
    }
    sparc64_measure_stamp_t guard_stamp = sparc64_measure_begin(measure,
                                                     SPARC64_MEASURE_FAMILY_GUARD);
    bool valid = sparc64_family_guard_matches_observed(guard, family, measure);
    sparc64_measure_end(measure, SPARC64_MEASURE_FAMILY_GUARD, guard_stamp);
    if (!valid) {
        errno = EINVAL;
        return -1;
    }
    *out = (sparc64_family_refresh_stamp_t){0};
    *reusable = false;
    if (family->refresh_reuse_disabled ||
        family->refresh_active_acquisition == 0 ||
        guard->refresh_acquisition == 0 ||
        guard->refresh_acquisition != family->refresh_active_acquisition)
        return 0;
    *out = (sparc64_family_refresh_stamp_t){
        .acquisition = family->refresh_active_acquisition,
        .mutation = family->refresh_mutation
    };
    *reusable = true;
    return 0;
}

int normalize_owned_fd(int *fd_pointer)
{
    int fd = *fd_pointer;
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    if (fd >= 3) {
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
            return -1;
        return 0;
    }
    int replacement = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (replacement < 0)
        return -1;
    int close_result = close(fd);
    int close_errno = errno;
    *fd_pointer = -1;
    if (close_result != 0) {
        (void)close(replacement);
        errno = close_errno;
        return -1;
    }
    *fd_pointer = replacement;
    return 0;
}

int page_name(sparc64_family_page_key_t key, char output[48])
{
    int length = snprintf(output, 48, "page-%016llx-%016llx",
                          (unsigned long long)key.object_id,
                          (unsigned long long)key.page_index);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

int object_name(uint64_t object_id, char output[48])
{
    int length = snprintf(output, 48, "object-%016llx",
                          (unsigned long long)object_id);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

int control_fragment_name(size_t index, char output[48])
{
    if (index >= SPARC64_ZERO_CONTROL_MAX_FRAGMENTS) {
        errno = EOVERFLOW;
        return -1;
    }
    int length = snprintf(output, 48, "control-frag-%02x", (unsigned)index);
    if (length < 0 || length >= 48) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

bool object_file_size(uint32_t slot_count, size_t *size)
{
    if (slot_count == 0 || slot_count > SPARC64_FAMILY_OBJECT_MAX_SLOTS)
        return false;
    size_t header = SPARC64_OBJECT_HEADER_SIZE;
    if (slot_count > (SIZE_MAX - header - (SPARC64_OBJECT_HEADER_SIZE - 1u)) /
                     SPARC64_OBJECT_SLOT_SIZE)
        return false;
    size_t end = header + (size_t)slot_count * SPARC64_OBJECT_SLOT_SIZE;
    *size = (end + SPARC64_OBJECT_HEADER_SIZE - 1u) & ~(size_t)(SPARC64_OBJECT_HEADER_SIZE - 1u);
    return true;
}

int observe_open_inode(sparc64_family_t *family, int fd)
{
    if (family->inode_observer == NULL)
        return 0;
    struct stat status;
    if (fstat(fd, &status) != 0)
        return -1;
    if (family->inode_observer(family->inode_observer_context, &status) != 0) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

/* A zero-size inode is an identity/authority handle, never the payload. Keep
 * one family attachment for every named object, including between short-lived
 * views and redo replay. The first phase has no cross-process family attach. */
sparc64_family_object_t *map_zero_object(sparc64_family_t *family,
                                           uint64_t object_id,
                                           uint32_t requested_count, int fd,
                                           bool initialize)
{
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        status.st_size != 0 ||
        !family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        return NULL;
    }
    size_t size = 0;
    sparc64_zero_object_segment_t *entry = find_zero_object(family, object_id);
    bool new_entry = false;
    if (initialize) {
        if (entry != NULL || !object_file_size(requested_count, &size)) {
            errno = EINVAL;
            return NULL;
        }
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL)
            return NULL;
        if (sparc64_family_zero_segment_create(SPARC64_FAMILY_ZERO_SEGMENT_OBJECT,
                                           object_id, size, &entry->segment) != 0 ||
            sparc64_family_zero_segment_publish_fd(fd, &entry->segment) != 0) {
            int saved = errno;
            sparc64_family_zero_segment_detach(&entry->segment);
            free(entry);
            errno = saved;
            return NULL;
        }
        entry->object_id = object_id;
        entry->size = size;
        new_entry = true;
    } else {
        if (entry == NULL) {
            errno = EIDRM;
            return NULL;
        }
        size = entry->size;
        sparc64_family_zero_segment_t checked = {0};
        if (sparc64_family_zero_segment_attach_fd(fd, SPARC64_FAMILY_ZERO_SEGMENT_OBJECT,
                                              object_id, size, &checked) != 0)
            return NULL;
        bool same = memcmp(checked.descriptor, entry->segment.descriptor,
                           SPARC64_FAMILY_ZERO_SEGMENT_WIRE_SIZE) == 0;
        sparc64_family_zero_segment_detach(&checked);
        if (!same) {
            errno = EIO;
            return NULL;
        }
    }
    sparc64_family_object_file_t *mapping = entry->segment.payload;
    if (initialize) {
        memset(mapping, 0, size);
        mapping->magic = SPARC64_OBJECT_MAGIC;
        mapping->version = SPARC64_FAMILY_VERSION;
        mapping->header_size = SPARC64_OBJECT_HEADER_SIZE;
        mapping->object_id = object_id;
        mapping->slot_count = requested_count;
        atomic_thread_fence(memory_order_release);
    } else if (mapping->magic != SPARC64_OBJECT_MAGIC ||
               mapping->version != SPARC64_FAMILY_VERSION ||
               mapping->header_size != SPARC64_OBJECT_HEADER_SIZE ||
               mapping->object_id != object_id || mapping->reserved != 0 ||
               !object_file_size(mapping->slot_count, &size) ||
               size != entry->size) {
        errno = EIO;
        return NULL;
    }
    sparc64_family_object_t *object = calloc(1, sizeof(*object));
    if (object == NULL) {
        if (new_entry) {
            int saved = errno;
            sparc64_family_zero_segment_detach(&entry->segment);
            free(entry);
            errno = saved;
        }
        return NULL;
    }
    object->family = family;
    object->fd = fd;
    object->mapping_size = size;
    object->mapping = mapping;
    object->object_id = object_id;
    object->slot_count = mapping->slot_count;
    if (new_entry) {
        entry->next = family->zero_objects;
        family->zero_objects = entry;
    }
    (void)atomic_fetch_add_explicit(&family->live_views, 1,
                                    memory_order_relaxed);
    return object;
}
