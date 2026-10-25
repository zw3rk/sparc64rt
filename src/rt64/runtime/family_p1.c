/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "family_split.h"


sparc64_family_object_t *map_object(sparc64_family_t *family, uint64_t object_id,
                                      uint32_t requested_count, int fd,
                                      bool initialize)
{
    if (fd < 3 || object_id == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (family->zero_backing)
        return map_zero_object(family, object_id, requested_count, fd,
                               initialize);
    size_t size = 0;
    if (initialize) {
        if (!object_file_size(requested_count, &size)) {
            errno = EINVAL;
            return NULL;
        }
        if (ftruncate(fd, (off_t)size) != 0)
            return NULL;
    }
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1) {
        errno = EIO;
        return NULL;
    }
    if (!initialize) {
        sparc64_family_object_header_t header;
        /* Only the fixed header is read before validating the file extent.
         * No mapping is dereferenced across a malformed short file. */
        ssize_t got = pread(fd, &header, sizeof(header), 0);
        if (got != (ssize_t)sizeof(header)) {
            errno = EIO;
            return NULL;
        }
        if (header.magic != SPARC64_OBJECT_MAGIC || header.version != SPARC64_FAMILY_VERSION ||
            header.header_size != SPARC64_OBJECT_HEADER_SIZE ||
            header.object_id != object_id || header.reserved != 0 ||
            !object_file_size(header.slot_count, &size)) {
            errno = EIO;
            return NULL;
        }
    }
    if (status.st_size != (off_t)size) {
        errno = EIO;
        return NULL;
    }
    size_t mapped_size = size;
    void *address = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED)
        return NULL;
    sparc64_family_object_file_t *mapping = address;
    if (initialize) {
        memset(mapping, 0, mapped_size);
        mapping->magic = SPARC64_OBJECT_MAGIC;
        mapping->version = SPARC64_FAMILY_VERSION;
        mapping->header_size = SPARC64_OBJECT_HEADER_SIZE;
        mapping->object_id = object_id;
        mapping->slot_count = requested_count;
        if (msync(mapping, mapped_size, MS_SYNC) != 0) {
            int saved = errno;
            (void)munmap(mapping, mapped_size);
            errno = saved;
            return NULL;
        }
    } else if (mapping->magic != SPARC64_OBJECT_MAGIC ||
               mapping->version != SPARC64_FAMILY_VERSION ||
               mapping->header_size != SPARC64_OBJECT_HEADER_SIZE ||
               mapping->object_id != object_id || mapping->reserved != 0 ||
               !object_file_size(mapping->slot_count, &size) ||
               mapped_size != size) {
        (void)munmap(mapping, mapped_size);
        errno = EIO;
        return NULL;
    }
    sparc64_family_object_t *object = calloc(1, sizeof(*object));
    if (object == NULL) {
        int saved = errno;
        (void)munmap(mapping, mapped_size);
        errno = saved;
        return NULL;
    }
    object->family = family;
    object->fd = fd;
    object->mapping_size = mapped_size;
    object->mapping = mapping;
    object->object_id = object_id;
    object->slot_count = mapping->slot_count;
    (void)atomic_fetch_add_explicit(&family->live_views, 1, memory_order_relaxed);
    return object;
}

sparc64_family_page_t *map_page(sparc64_family_t *family, sparc64_family_page_key_t key,
                                  int fd, bool initialize)
{
    size_t size = sizeof(sparc64_family_page_file_t);
    if (fd < 3) {
        errno = EBADF;
        return NULL;
    }
    if (initialize && ftruncate(fd, (off_t)size) != 0)
        return NULL;
    struct stat status;
    if (fstat(fd, &status) != 0)
        return NULL;
    if (!S_ISREG(status.st_mode) || (status.st_mode & 07777) != 0600 ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        status.st_size != (off_t)size) {
        errno = EIO;
        return NULL;
    }
    void *address = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED)
        return NULL;
    sparc64_family_page_file_t *mapping = address;
    if (initialize) {
        memset(mapping, 0, size);
        mapping->magic = SPARC64_PAGE_MAGIC;
        mapping->version = SPARC64_FAMILY_VERSION;
        mapping->size = (uint32_t)size;
        mapping->key = key;
        if (msync(mapping, size, MS_SYNC) != 0) {
            int saved = errno;
            (void)munmap(mapping, size);
            errno = saved;
            return NULL;
        }
    } else if (mapping->magic != SPARC64_PAGE_MAGIC ||
               mapping->version != SPARC64_FAMILY_VERSION ||
               mapping->size != size || !key_equal(mapping->key, key)) {
        (void)munmap(mapping, size);
        errno = EIO;
        return NULL;
    }
    sparc64_family_page_t *page = calloc(1, sizeof(*page));
    if (page == NULL) {
        int saved = errno;
        (void)munmap(mapping, size);
        errno = saved;
        return NULL;
    }
    page->family = family;
    page->fd = fd;
    page->mapping_size = size;
    page->mapping = mapping;
    page->key = key;
    (void)atomic_fetch_add_explicit(&family->live_views, 1, memory_order_relaxed);
    return page;
}

void apply_absolute_state(sparc64_family_page_state_t *destination,
                                 const sparc64_family_page_state_t *target,
                                 sparc64_family_t *family, bool recovery)
{
    refresh_mutate(family);
    destination->content_generation = target->content_generation;
    memcpy(destination->epochs, target->epochs, sizeof(target->epochs));
    memcpy(destination->notified, target->notified, sizeof(target->notified));
    destination->private_cow = target->private_cow;
    atomic_thread_fence(memory_order_seq_cst);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(recovery ? SPARC64_FAMILY_TEST_RECOVERY_EPOCHS_APPLIED
                              : SPARC64_FAMILY_TEST_EPOCHS_APPLIED,
                     family->hook_context);
#else
    (void)family;
    (void)recovery;
#endif
    memcpy(destination->bytes, target->bytes, sizeof(target->bytes));
    atomic_thread_fence(memory_order_seq_cst);
#ifdef SPARC64_FAMILY_TESTING
    if (family->hook != NULL)
        family->hook(SPARC64_FAMILY_TEST_BYTES_APPLIED, family->hook_context);
#endif
}

sparc64_family_object_t *open_logged_object(sparc64_family_t *family,
                                               sparc64_family_page_key_t key)
{
    if (key.object_id == 0 || key.page_index >= SPARC64_FAMILY_OBJECT_MAX_SLOTS) {
        errno = EIO;
        return NULL;
    }
    char name[48];
    if (object_name(key.object_id, name) != 0)
        return NULL;
    if (sparc64_family_reject_control_alias(family->control_fd, family->dir_fd, name) != 0)
        return NULL;
    int fd = openat(family->dir_fd, name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (normalize_owned_fd(&fd) != 0) {
        int saved = errno;
        if (fd >= 0)
            (void)close(fd);
        errno = saved;
        return NULL;
    }
    sparc64_family_object_t *object = map_object(family, key.object_id, 0, fd, false);
    if (object == NULL) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return NULL;
    }
    if (key.page_index >= object->slot_count || observe_open_inode(family, fd) != 0) {
        int saved = key.page_index >= object->slot_count ? EIO : errno;
        sparc64_family_object_close(object);
        errno = saved;
        return NULL;
    }
    return object;
}

uint64_t wait_checksum(const void *data, size_t size)
{
    const unsigned char *bytes = data;
    uint64_t value = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < size; ++i) {
        value ^= bytes[i];
        value *= UINT64_C(1099511628211);
    }
    return value;
}

bool wait_bank_size(uint64_t capacity, size_t *size)
{
    if (capacity == 0 || capacity > SPARC64_WAIT_MAX_ROWS ||
        capacity > (SIZE_MAX - sizeof(sparc64_family_wait_bank_header_t)) /
                       sizeof(sparc64_family_wait_row_t))
        return false;
    size_t raw = sizeof(sparc64_family_wait_bank_header_t) +
                 (size_t)capacity * sizeof(sparc64_family_wait_row_t);
    if (raw > SIZE_MAX - (SPARC64_FAMILY_PAGE_SIZE - 1u))
        return false;
    *size = (raw + SPARC64_FAMILY_PAGE_SIZE - 1u) & ~(size_t)(SPARC64_FAMILY_PAGE_SIZE - 1u);
    return true;
}

bool wait_pair_end(uint64_t base, uint64_t capacity, uint64_t *end)
{
    size_t bank_size = 0;
    if (!wait_bank_size(capacity, &bank_size) || base > (uint64_t)INT64_MAX ||
        bank_size > (size_t)(((uint64_t)INT64_MAX - base) / 2u))
        return false;
    *end = base + (uint64_t)bank_size * 2u;
    return true;
}

bool wait_offset(uint64_t base, uint32_t index, uint64_t capacity,
                        uint64_t *offset)
{
    size_t bank_size = 0;
    if (index > 1 || !wait_bank_size(capacity, &bank_size) ||
        base > (uint64_t)INT64_MAX || bank_size > (uint64_t)INT64_MAX - base)
        return false;
    *offset = base + (uint64_t)bank_size * index;
    return *offset <= (uint64_t)INT64_MAX;
}

static int wait_pread_full(int fd, void *buffer, size_t size, uint64_t offset)
{
    unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        if (offset > (uint64_t)INT64_MAX - done) {
            errno = EOVERFLOW;
            return -1;
        }
        ssize_t got = pread(fd, bytes + done, size - done, (off_t)(offset + done));
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            if (got == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

static int wait_pwrite_full(int fd, const void *buffer, size_t size, uint64_t offset)
{
    const unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < size) {
        if (offset > (uint64_t)INT64_MAX - done) {
            errno = EOVERFLOW;
            return -1;
        }
        ssize_t put = pwrite(fd, bytes + done, size - done, (off_t)(offset + done));
        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0) {
            if (put == 0)
                errno = EIO;
            return -1;
        }
        done += (size_t)put;
    }
    return 0;
}

/* Every fragment has its own zero-length authority inode and one marked
 * segment. Keep the attachment until family destruction: the descriptor is
 * only a locator and cannot revive a segment after its final detach. */
static int create_control_fragment(sparc64_family_t *family)
{
    size_t index = family->zero_fragment_count;
    char name[48];
    if (control_fragment_name(index, name) != 0)
        return -1;
    if (!family_authorize_fd(family->dir_fd, true,
                              family->storage_authority)) {
        errno = EACCES;
        return -1;
    }
    int fd = openat(family->dir_fd, name, O_CREAT | O_EXCL | O_RDWR |
                    O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0)
        return -1;
    struct stat created = {0};
    bool identified = fstat(fd, &created) == 0;
    sparc64_family_zero_segment_t segment = {0};
    bool published = false;
    int result = -1;
    if (!identified || normalize_owned_fd(&fd) != 0 || fchmod(fd, 0600) != 0)
        goto fragment_done;
    if (!family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        goto fragment_done;
    }
    if (sparc64_family_zero_segment_create(SPARC64_FAMILY_ZERO_SEGMENT_CONTROL_FRAGMENT,
            index + 1u, SPARC64_ZERO_CONTROL_FRAGMENT_SIZE, &segment) != 0 ||
        sparc64_family_zero_segment_publish_fd(fd, &segment) != 0)
        goto fragment_done;
    if (!family_authorize_fd(fd, false, family->storage_authority)) {
        errno = EACCES;
        goto fragment_done;
    }
    /* The observer may retain this inode even if it reports failure. Once
     * published, keep the fragment and its name for the next guarded scan. */
    family->zero_fragments[index] = segment;
    family->zero_fragment_count = index + 1u;
    published = true;
    if (observe_open_inode(family, fd) != 0) {
        /* The callback may have retained this identity. Keep the exact fd
         * until it accepts a later guarded retry; never reuse the name. */
        family->zero_fragment_pending_fd = fd;
        fd = -1;
        goto fragment_done;
    }
    result = 0;
fragment_done:
    ;
    int saved = errno;
    if (fd >= 0 && close(fd) != 0 && result == 0) {
        result = -1;
        saved = errno;
    }
    if (result != 0) {
        if (!published)
            sparc64_family_zero_segment_detach(&segment);
        if (!published && identified) {
            struct stat named;
            if (fstatat(family->dir_fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
                named.st_dev == created.st_dev && named.st_ino == created.st_ino)
                (void)unlinkat(family->dir_fd, name, 0);
        }
        errno = saved != 0 ? saved : EIO;
        return -1;
    }
    return 0;
}

int ensure_control_extent(sparc64_family_t *family, uint64_t end)
{
    if (!family->zero_backing)
        return 0;
    if (family->zero_fragment_pending_fd >= 0) {
        if (family->inode_observer == NULL) {
            errno = EIO;
            return -1;
        }
        if (observe_open_inode(family, family->zero_fragment_pending_fd) != 0)
            return -1;
        int pending_fd = family->zero_fragment_pending_fd;
        family->zero_fragment_pending_fd = -1;
        if (close(pending_fd) != 0)
            return -1;
    }
    off_t maximum;
    if (!wait_control_max_size(&maximum) || end > (uint64_t)maximum) {
        errno = ENOSPC;
        return -1;
    }
    while (end > SPARC64_ZERO_CONTROL_HEAD_SIZE +
                 family->zero_fragment_count * SPARC64_ZERO_CONTROL_FRAGMENT_SIZE)
        if (create_control_fragment(family) != 0)
            return -1;
    return 0;
}

static int control_span(sparc64_family_t *family, uint64_t offset,
                        unsigned char **address, size_t *available)
{
    uint64_t extent;
    if (family_control_extent(family, &extent) != 0 || offset >= extent) {
        errno = EIO;
        return -1;
    }
    if (offset < SPARC64_ZERO_CONTROL_HEAD_SIZE) {
        *address = (unsigned char *)family->zero_control.payload + offset;
        *available = SPARC64_ZERO_CONTROL_HEAD_SIZE - (size_t)offset;
        return 0;
    }
    uint64_t relative = offset - SPARC64_ZERO_CONTROL_HEAD_SIZE;
    size_t index = (size_t)(relative / SPARC64_ZERO_CONTROL_FRAGMENT_SIZE);
    size_t within = (size_t)(relative % SPARC64_ZERO_CONTROL_FRAGMENT_SIZE);
    if (index >= family->zero_fragment_count ||
        family->zero_fragments[index].payload == NULL) {
        errno = EIO;
        return -1;
    }
    *address = (unsigned char *)family->zero_fragments[index].payload + within;
    *available = SPARC64_ZERO_CONTROL_FRAGMENT_SIZE - within;
    return 0;
}

int family_control_read(sparc64_family_t *family, void *buffer,
                               size_t size, uint64_t offset)
{
    if (!family->zero_backing)
        return wait_pread_full(family->control_fd, buffer, size, offset);
    uint64_t extent;
    if (family_control_extent(family, &extent) != 0 || offset > extent ||
        size > extent - offset) {
        errno = EIO;
        return -1;
    }
    unsigned char *target = buffer;
    while (size != 0) {
        unsigned char *source;
        size_t available;
        if (control_span(family, offset, &source, &available) != 0)
            return -1;
        size_t count = size < available ? size : available;
        memcpy(target, source, count);
        target += count;
        offset += count;
        size -= count;
    }
    return 0;
}

int family_control_write(sparc64_family_t *family, const void *buffer,
                                size_t size, uint64_t offset)
{
    if (!family->zero_backing)
        return wait_pwrite_full(family->control_fd, buffer, size, offset);
    uint64_t extent;
    if (family_control_extent(family, &extent) != 0 || offset > extent ||
        size > extent - offset) {
        errno = ENOSPC;
        return -1;
    }
    const unsigned char *source = buffer;
    while (size != 0) {
        unsigned char *target;
        size_t available;
        if (control_span(family, offset, &target, &available) != 0)
            return -1;
        size_t count = size < available ? size : available;
        memcpy(target, source, count);
        source += count;
        offset += count;
        size -= count;
    }
    atomic_thread_fence(memory_order_release);
    return 0;
}

int read_wait_bank(sparc64_family_t *family, uint64_t base, uint32_t index,
                          uint64_t capacity, uint64_t count, uint64_t revision,
                          sparc64_family_wait_row_t **rows_out)
{
    if (rows_out == NULL || count > capacity || capacity > SPARC64_WAIT_MAX_ROWS) {
        errno = EIO;
        return -1;
    }
    uint64_t offset = 0;
    if (!wait_offset(base, index, capacity, &offset)) {
        errno = EIO;
        return -1;
    }
    sparc64_family_wait_bank_header_t header;
    if (family_control_read(family, &header, sizeof(header), offset) != 0)
        return -1;
    if (header.magic != SPARC64_WAIT_BANK_MAGIC || header.version != SPARC64_WAIT_BANK_VERSION ||
        header.header_size != sizeof(header) || header.capacity != capacity ||
        header.count != count || header.revision != revision) {
        errno = EIO;
        return -1;
    }
    size_t bytes_size = (size_t)capacity * sizeof(sparc64_family_wait_row_t);
    sparc64_family_wait_row_t *bank_rows = malloc(bytes_size);
    if (bank_rows == NULL)
        return -1;
    if (family_control_read(family, bank_rows, bytes_size,
                            offset + sizeof(header)) != 0) {
        int saved = errno;
        free(bank_rows);
        errno = saved;
        return -1;
    }
    if (wait_checksum(bank_rows, bytes_size) != header.checksum) {
        free(bank_rows);
        errno = EIO;
        return -1;
    }
    *rows_out = bank_rows;
    return 0;
}
