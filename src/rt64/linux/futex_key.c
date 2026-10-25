/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/futex_key.h"
#include "linux/error.h"
#include "memory/file_backing.h"

#include <errno.h>

static const sparc64_page_t *page_at(const sparc64_space_t *space, uint64_t address)
{
    uint64_t page = address & ~(SPARC64_PAGE_SIZE - 1u);
    size_t low = 0, high = space->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        if (space->pages[middle].address < page)
            low = middle + 1u;
        else
            high = middle;
    }
    return low < space->count && space->pages[low].address == page ?
           &space->pages[low] : NULL;
}

static const sparc64_vma_t *vma_at(const sparc64_linux_memory_t *memory, uint64_t address)
{
    for (size_t i = 0; i < memory->count; ++i)
        if (memory->vmas[i].start <= address && address < memory->vmas[i].end)
            return &memory->vmas[i];
    return NULL;
}

static bool access_error(sparc64_space_t *space, uint64_t *error)
{
    switch (space->fault_reason) {
    case SPARC64_FAULT_RESOURCE:
        *error = UINT64_C(0) - sparc64_linux_errno(ENOMEM);
        return true;
    case SPARC64_FAULT_RANGE:
    case SPARC64_FAULT_UNMAPPED:
    case SPARC64_FAULT_PERMISSION:
    case SPARC64_FAULT_BUS:
        *error = UINT64_C(0) - sparc64_linux_errno(EFAULT);
        return true;
    case SPARC64_FAULT_NONE:
    case SPARC64_FAULT_INTERNAL:
    default:
        space->internal_failure = true;
        space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
}

bool sparc64_linux_futex_key(sparc64_linux_memory_t *memory,
                         sparc64_family_backing_t *backing, uint64_t mm_id,
                         uint64_t address, bool private_key, bool write,
                         sparc64_family_wait_key_t *key, uint64_t *error)
{
    if (memory == NULL || memory->space == NULL || backing == NULL ||
        mm_id == 0 || key == NULL || error == NULL || memory->space->internal_failure) {
        errno = EINVAL;
        return false;
    }
    sparc64_space_t *space = memory->space;
    *key = (sparc64_family_wait_key_t){0};
    if ((address & 3u) != 0) {
        *error = UINT64_C(0) - sparc64_linux_errno(EINVAL);
        return true;
    }
    if (address > space->limit || UINT64_C(4) > space->limit - address) {
        *error = UINT64_C(0) - sparc64_linux_errno(EFAULT);
        return true;
    }
    if (private_key) {
        *key = (sparc64_family_wait_key_t){SPARC64_FAMILY_WAIT_PRIVATE, mm_id, address};
        *error = 0;
        return true;
    }
    const sparc64_page_t *page = page_at(space, address);
    if (page == NULL) {
        *error = UINT64_C(0) - sparc64_linux_errno(EFAULT);
        return true;
    }
    const sparc64_vma_t *vma = vma_at(memory, address);
    if (vma == NULL || page->backing == NULL) {
        space->internal_failure = true;
        space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
    if (page->backing->file != NULL && !page->backing->private_cow) {
        /* Linux first requests FOLL_WRITE even for WAIT/WAKE. A writable
         * MAP_PRIVATE file page therefore becomes anonymous before keying,
         * including a WAKE selecting nobody or a WAIT returning EAGAIN. */
        if ((page->permissions & SPARC64_MEM_WRITE) != 0) {
            if (!sparc64_space_cow_file_page(space, address))
                return access_error(space, error);
        } else {
            if (write) {
                *error = UINT64_C(0) - sparc64_linux_errno(EFAULT);
                return true;
            }
            unsigned char ignored[4];
            if (!sparc64_space_read(space, address, ignored, sizeof(ignored), SPARC64_MEM_READ))
                return access_error(space, error);
            sparc64_file_identity_t identity;
            int fd;
            uint64_t file_id, within = address & (SPARC64_PAGE_SIZE - 1u);
            if (page->backing->file_offset > UINT64_MAX - within ||
                sparc64_file_source_identity(page->backing->file, &identity, &fd) != 0) {
                space->internal_failure = true;
                space->fault_reason = SPARC64_FAULT_INTERNAL;
                space->fault_address = address;
                return false;
            }
            if (sparc64_family_backing_file_intern(backing, &identity, fd, &file_id) != 0) {
                if (errno == EIO || errno == EBADF || errno == EINVAL) {
                    space->internal_failure = true;
                    space->fault_reason = SPARC64_FAULT_INTERNAL;
                    space->fault_address = address;
                    return false;
                }
                *error = UINT64_C(0) - sparc64_linux_errno(errno);
                return true;
            }
            *key = (sparc64_family_wait_key_t){SPARC64_FAMILY_WAIT_FILE, file_id,
                                           page->backing->file_offset + within};
            *error = 0;
            return true;
        }
    }
    bool shared = vma->kind == SPARC64_VMA_ANONYMOUS_SHARED;
    /* Linux's nonprivate private-anon key requires a writable pin even for
     * WAKE. A shared-object READ key can instead use a read-only mapping.
     * WAIT's separate value comparison still requires actual read access. */
    unsigned int access = SPARC64_MEM_WRITE;
    if (shared && !write && (page->permissions & SPARC64_MEM_WRITE) == 0)
        access = SPARC64_MEM_READ;
    unsigned char ignored[4];
    if (!sparc64_space_read(space, address, ignored, sizeof(ignored), access))
        return access_error(space, error);
    if (!shared) {
        *key = (sparc64_family_wait_key_t){SPARC64_FAMILY_WAIT_MM_SHARED, mm_id, address};
        *error = 0;
        return true;
    }
    sparc64_family_page_key_t packed;
    if (!sparc64_family_backing_key(backing, page->backing->payload, &packed) ||
        packed.object_id == 0 ||
        packed.page_index > (UINT64_MAX - (address & (SPARC64_PAGE_SIZE - 1u))) /
                            SPARC64_PAGE_SIZE) {
        space->internal_failure = true;
        space->fault_reason = SPARC64_FAULT_INTERNAL;
        return false;
    }
    *key = (sparc64_family_wait_key_t){SPARC64_FAMILY_WAIT_OBJECT, packed.object_id,
              packed.page_index * SPARC64_PAGE_SIZE + (address & (SPARC64_PAGE_SIZE - 1u))};
    *error = 0;
    return true;
}
