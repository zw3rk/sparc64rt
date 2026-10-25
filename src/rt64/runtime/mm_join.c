/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "runtime/mm_join.h"
#include "runtime/mm_view_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct sparc64_mm_join_image {
    sparc64_family_mm_t mm;
    sparc64_family_identity_t family;
    uint64_t parent_incarnation;
    pid_t parent_pid;
};

int sparc64_mm_join_prepare(sparc64_mm_view_t *parent, sparc64_family_guard_t *guard,
                        sparc64_mm_join_image_t **out)
{
    if (parent == NULL || guard == NULL || out == NULL || *out != NULL ||
        parent->space == NULL || parent->space->internal_failure ||
        !sparc64_family_backing_guard_matches(parent->backing, guard)) {
        errno = EINVAL; return -1;
    }
    sparc64_family_identity_t identity;
    if (sparc64_family_identity(guard, &identity) != 0 ||
        sparc64_family_sources(guard) == NULL)
        return -1;
    sparc64_family_mm_state_t current = {0};
    if (sparc64_family_mm_read(guard, parent->mm, &current) != 0)
        return -1;
    bool member = false;
    for (size_t i = 0; i < current.member_count; ++i)
        if (current.members[i].owner_incarnation == guard->incarnation)
            member = true;
    int failure = current.revision != parent->applied.revision ? EAGAIN :
                  !member ? EINVAL : 0;
    sparc64_family_mm_state_destroy(&current);
    if (failure != 0) { errno = failure; return -1; }
    sparc64_mm_join_image_t *image = calloc(1, sizeof(*image));
    if (image == NULL)
        return -1;
    *image = (sparc64_mm_join_image_t){parent->mm, identity, guard->incarnation, getpid()};
    *out = image;
    return 0;
}

static bool join_same_family(sparc64_family_identity_t a, sparc64_family_identity_t b)
{
    return a.control_device == b.control_device &&
           a.control_inode == b.control_inode &&
           a.directory_device == b.directory_device &&
           a.directory_inode == b.directory_inode;
}

static int join_member_order(sparc64_family_mm_member_t a, sparc64_family_mm_member_t b)
{
    if (a.owner_incarnation != b.owner_incarnation)
        return (a.owner_incarnation > b.owner_incarnation) -
               (a.owner_incarnation < b.owner_incarnation);
    return (a.task_id > b.task_id) - (a.task_id < b.task_id);
}

int sparc64_mm_join_child_adopt(sparc64_mm_join_image_t **owned,
                            sparc64_family_guard_t *guard,
                            sparc64_family_backing_t *backing,
                            sparc64_space_t *space, sparc64_linux_memory_t *memory,
                            sparc64_file_identity_policy_t policy,
                            uint64_t task_id, sparc64_mm_view_t **out)
{
    if (owned == NULL || *owned == NULL || guard == NULL || backing == NULL ||
        space == NULL || memory == NULL || out == NULL || *out != NULL ||
        task_id == 0 || getpid() == (*owned)->parent_pid ||
        !sparc64_family_backing_guard_matches(backing, guard)) {
        errno = EINVAL; return -1;
    }
    sparc64_family_identity_t identity;
    if (sparc64_family_identity(guard, &identity) != 0)
        return -1;
    if (!join_same_family(identity, (*owned)->family)) {
        errno = EXDEV; return -1;
    }
    if (guard->incarnation == (*owned)->parent_incarnation) {
        errno = EINVAL; return -1;
    }
    sparc64_mm_view_t *view = NULL;
    sparc64_family_mm_state_t state = {0};
    sparc64_mm_view_plan_t plan = {0};
    int result = -1;
    if (sparc64_mm_view_create(&view, (*owned)->mm, backing, space, memory) != 0 ||
        sparc64_mm_view_bind_family_sources(view, guard, policy) != 0 ||
        sparc64_family_mm_read(guard, (*owned)->mm, &state) != 0)
        goto done;
    if (state.limit != space->limit) { errno = EINVAL; goto done; }
    sparc64_family_mm_member_t member = {guard->incarnation, task_id};
    size_t at = 0;
    while (at < state.member_count && join_member_order(state.members[at], member) < 0)
        ++at;
    if (at < state.member_count && join_member_order(state.members[at], member) == 0) {
        errno = EEXIST; goto done;
    }
    if (state.member_count == SPARC64_FAMILY_MM_MAX_RECORDS) {
        errno = ENOSPC; goto done;
    }
    sparc64_family_mm_member_t *rows = realloc(state.members,
        (state.member_count + 1u) * sizeof(*rows));
    if (rows == NULL)
        goto done;
    state.members = rows;
    memmove(&rows[at + 1u], &rows[at], (state.member_count - at) * sizeof(*rows));
    rows[at] = member;
    ++state.member_count;
    if (sparc64_mm_view_plan_prepare(view, &state, &plan) != 0)
        goto done;
    if (sparc64_family_mm_commit(guard, (*owned)->mm, &plan.state) != 0) {
        result = -2; goto done;
    }
    sparc64_mm_view_plan_apply(view, &plan);
    *out = view;
    view = NULL;
    sparc64_mm_join_image_destroy(owned);
    result = 0;
done: {
        int saved = errno;
        sparc64_mm_view_plan_discard(&plan);
        sparc64_family_mm_state_destroy(&state);
        sparc64_mm_view_destroy(&view);
        errno = saved;
        return result;
    }
}

void sparc64_mm_join_image_destroy(sparc64_mm_join_image_t **owned)
{
    if (owned == NULL || *owned == NULL)
        return;
    free(*owned);
    *owned = NULL;
}

int sparc64_mm_retire_exec_owner(sparc64_family_guard_t *guard, sparc64_family_mm_t mm,
                            uint64_t caller_task_id)
{
    if (guard == NULL || caller_task_id == 0) { errno = EINVAL; return -1; }
    sparc64_family_mm_state_t state = {0};
    if (sparc64_family_mm_read(guard, mm, &state) != 0)
        return -1;
    bool caller_found = false;
    size_t local = 0, retained = 0;
    for (size_t i = 0; i < state.member_count; ++i) {
        if (state.members[i].owner_incarnation == guard->incarnation) {
            ++local;
            if (state.members[i].task_id == caller_task_id)
                caller_found = true;
        } else
            state.members[retained++] = state.members[i];
    }
    if (!caller_found || local > 4096) {
        sparc64_family_mm_state_destroy(&state);
        errno = EINVAL;
        return -1;
    }
    state.member_count = retained;
    int result = sparc64_family_mm_commit(guard, mm, &state);
    int saved = errno;
    sparc64_family_mm_state_destroy(&state);
    errno = saved;
    return result;
}
