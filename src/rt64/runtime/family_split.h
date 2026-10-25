/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FAMILY_SPLIT_H
#define SPARC64RT_RUNTIME_FAMILY_SPLIT_H

/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime/family.h"
#include "runtime/family_wait.h"
#include "runtime/file_catalog.h"
#include "runtime/family_file_index.h"
#include "runtime/family_file_index_internal.h"
#include "runtime/family_file_recovery.h"
#include "runtime/family_zero_segment.h"
#include "aot/authority.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <dirent.h>

#define SPARC64_FAMILY_MAGIC UINT64_C(0x5256525446414d31)
#define SPARC64_PAGE_MAGIC UINT64_C(0x5256525447504731)
#define SPARC64_OBJECT_MAGIC UINT64_C(0x52565254474f4232)
#define SPARC64_FAMILY_VERSION 11u
#define SPARC64_LOG_EMPTY 0u
#define SPARC64_LOG_PREPARED 1u
#define SPARC64_LOG_COMMITTED 2u
#define SPARC64_LOG_PAGE 0u
#define SPARC64_LOG_OBJECT 1u
#define SPARC64_LOG_OBJECT_PAIR 2u
#define SPARC64_LOG_WAIT 3u
#define SPARC64_LOG_WAIT_OBJECT 4u
#define SPARC64_LOG_WAIT_PAIR 5u
#define SPARC64_LOG_FILE 6u
#define SPARC64_OBJECT_HEADER_SIZE 16384u
#define SPARC64_OBJECT_SLOT_SIZE 8192u
#define SPARC64_WAIT_BANK_MAGIC UINT64_C(0x5256525457414954)
#define SPARC64_WAIT_BANK_VERSION 1u
#define SPARC64_WAIT_INITIAL_CAPACITY 64u
#define SPARC64_WAIT_MAX_ROWS 65536u
#define SPARC64_ZERO_CONTROL_HEAD_SIZE (1024u * 1024u)
#define SPARC64_ZERO_CONTROL_FRAGMENT_SIZE (2u * 1024u * 1024u)
#define SPARC64_ZERO_CONTROL_MAX_FRAGMENTS 16u

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t size;
    uint64_t next_incarnation;
    uint64_t next_object_id;
    uint64_t recovery_epoch;
    uint64_t active_incarnation;
    uint32_t active;
    uint32_t retired;
    _Alignas(8) _Atomic uint32_t log_marker;
    uint32_t log_kind;
    sparc64_family_page_key_t log_key;
    sparc64_family_page_state_t log_target;
    sparc64_family_page_key_t log_second_key;
    sparc64_family_page_state_t log_second_target;
    uint64_t next_wait_id;
    uint64_t next_mm_id;
    uint64_t wait_bank_base;
    uint64_t wait_bank_capacity;
    uint64_t wait_count;
    uint64_t wait_revision;
    uint32_t wait_bank_index;
    uint32_t wait_bank_reserved;
    uint64_t wait_target_base;
    uint64_t wait_target_capacity;
    uint64_t wait_target_count;
    uint64_t wait_target_revision;
    uint32_t wait_target_index;
    uint32_t wait_reserved;
    uint64_t inode_pin_attempts;
    uint64_t file_count;
    uint64_t next_file_id;
    uint64_t file_target_slot;
    uint64_t file_target_count;
    sparc64_file_catalog_record_t file_target;
    uint64_t next_source_id;
    uint64_t source_attempts;
    uint32_t source_mode, source_reserved;
    uint64_t file_index_object;
} sparc64_family_control_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t capacity;
    uint64_t count;
    uint64_t revision;
    uint64_t checksum;
    uint64_t reserved;
} sparc64_family_wait_bank_header_t;

typedef struct {
    sparc64_family_page_state_t state;
    uint64_t magic;
    uint32_t version;
    uint32_t size;
    sparc64_family_page_key_t key;
} sparc64_family_page_file_t;

typedef struct {
    sparc64_family_page_state_t state;
    unsigned char padding[SPARC64_OBJECT_SLOT_SIZE - sizeof(sparc64_family_page_state_t)];
} sparc64_family_object_slot_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t object_id;
    uint32_t slot_count;
    uint32_t reserved;
} sparc64_family_object_header_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint64_t object_id;
    uint32_t slot_count;
    uint32_t reserved;
    unsigned char header_padding[SPARC64_OBJECT_HEADER_SIZE - 32u];
    sparc64_family_object_slot_t slots[];
} sparc64_family_object_file_t;

_Static_assert(sizeof(sparc64_family_page_state_t) == 6192,
               "family page state is a fixed-width record");
_Static_assert(offsetof(sparc64_family_control_t, log_marker) == 56,
               "commit marker must retain its aligned control offset");
_Static_assert(offsetof(sparc64_family_control_t, file_count) % 8 == 0 &&
               offsetof(sparc64_family_control_t, next_file_id) % 8 == 0,
               "catalog publication counters retain native aligned64 stores");
_Static_assert(offsetof(sparc64_family_control_t, next_source_id) % 8 == 0 &&
               offsetof(sparc64_family_control_t, source_attempts) % 8 == 0,
               "source admission counters are aligned64 stores");
_Static_assert(sizeof(sparc64_family_control_t) % 8 == 0,
               "family control record is naturally aligned");
_Static_assert(sizeof(sparc64_family_wait_row_t) == 64,
               "wait rows are fixed-width pointer-free records");
_Static_assert(sizeof(sparc64_family_wait_bank_header_t) == 56,
               "wait bank header is a fixed-width record");
_Static_assert(sizeof(sparc64_family_page_file_t) == 6224,
               "managed page file is a fixed-width versioned record");
_Static_assert(offsetof(sparc64_family_page_file_t, state) == 0,
               "managed guest payload starts at the host-page-aligned view");
_Static_assert(sizeof(sparc64_family_object_slot_t) == SPARC64_OBJECT_SLOT_SIZE,
               "packed slot is a fixed-width page-aligned record");
_Static_assert(SPARC64_OBJECT_HEADER_SIZE % SPARC64_FAMILY_PAGE_SIZE == 0 &&
               SPARC64_OBJECT_SLOT_SIZE % SPARC64_FAMILY_PAGE_SIZE == 0,
               "every packed guest page begins at a guest-page file offset");
_Static_assert(sizeof(sparc64_family_object_header_t) == 32,
               "packed header prefix is a fixed-width record");
_Static_assert(offsetof(sparc64_family_object_slot_t, state.bytes) == 0,
               "packed guest bytes begin at the slot boundary");
_Static_assert(offsetof(sparc64_family_object_file_t, slots) == SPARC64_OBJECT_HEADER_SIZE,
               "packed object header is a fixed-width versioned record");

struct sparc64_family {
    int control_fd;
    int dir_fd;
    sparc64_inode_pins_t pins;
    sparc64_file_caps_client_t sources;
    sparc64_family_control_t *control;
    sparc64_family_zero_segment_t zero_control;
    sparc64_family_zero_segment_t zero_fragments[SPARC64_ZERO_CONTROL_MAX_FRAGMENTS];
    size_t zero_fragment_count;
    int zero_fragment_pending_fd;
    struct sparc64_zero_object_segment *zero_objects;
    bool zero_backing;
    sparc64_family_storage_authority_t storage_authority;
    pthread_mutex_t local_mutex;
    sparc64_family_guard_t *active_guard;
    pid_t local_pid;
    uint64_t incarnation;
    uint64_t refresh_next_acquisition;
    uint64_t refresh_active_acquisition;
    uint64_t refresh_mutation;
    bool refresh_reuse_disabled;
    bool initialized;
    bool creator;
    bool destroying;
    bool cleaned;
    bool poisoned;
    bool exec_active;
    sparc64_family_exec_t *exec_prepared;
    sparc64_family_inode_observer_t inode_observer;
    void *inode_observer_context;
    atomic_size_t live_views;
    char directory[64];
#ifdef SPARC64_FAMILY_TESTING
    sparc64_family_test_hook_t hook;
    void *hook_context;
    bool test_fail_file_recovery_once;
    bool test_fail_unlock_once;
    bool test_fail_child_transfer_attach;
    bool test_fail_exec_activation;
    size_t test_fail_exec_activation_index;
    bool test_fail_wait_replay_once;
#endif
};

typedef struct sparc64_zero_object_segment {
    struct sparc64_zero_object_segment *next;
    sparc64_family_zero_segment_t segment;
    uint64_t object_id;
    size_t size;
} sparc64_zero_object_segment_t;

typedef struct {
    sparc64_family_zero_segment_t control;
    sparc64_zero_object_segment_t root;
    sparc64_family_storage_authority_t storage_authority;
} sparc64_zero_service_retained_t;

struct sparc64_family_exec {
    sparc64_family_t *family;
    sparc64_family_guard_t *guard;
    sparc64_family_exec_state_t state;
    int flags[6];
    size_t capability_count;
    bool active;
};

struct sparc64_family_page {
    sparc64_family_t *family;
    int fd;
    size_t mapping_size;
    sparc64_family_page_file_t *mapping;
    sparc64_family_page_key_t key;
};

struct sparc64_family_object {
    sparc64_family_t *family;
    int fd;
    size_t mapping_size;
    sparc64_family_object_file_t *mapping;
    uint64_t object_id;
    uint32_t slot_count;
};
bool wait_control_max_size(off_t *size_out);
int validate_target(const sparc64_family_page_state_t *current,
                           const sparc64_family_page_state_t *target);
bool catalog_reserved_end(uint64_t *end);
int replay_file_record(sparc64_family_t *family);
int catalog_wait_keys(sparc64_family_t *family,
                               const sparc64_family_wait_row_t *rows, size_t count);

/* Cross-part declarations (generated L0a split). */
bool key_equal(sparc64_family_page_key_t left, sparc64_family_page_key_t right);
bool authority_valid(sparc64_family_storage_authority_t authority);
bool family_authorize_fd(int fd, bool directory, sparc64_family_storage_authority_t authority);
int family_control_extent(const sparc64_family_t *family, uint64_t *out);
void close_owned_fds(int control_fd, int dir_fd);
void close_family_sources(int control_fd, int dir_fd, sparc64_inode_pins_t pins, sparc64_file_caps_client_t sources);
void sparc64_family_close_capabilities(int control_fd, int dir_fd, sparc64_inode_pins_t pins);
void sparc64_family_close_source_capabilities(int control_fd, int dir_fd, sparc64_inode_pins_t pins, sparc64_file_caps_client_t sources);
bool source_caps_present(sparc64_file_caps_client_t sources);
bool distinct_source_fds(int control_fd, int dir_fd, sparc64_inode_pins_t pins, sparc64_file_caps_client_t sources);
void family_fds(const sparc64_family_t *family, int descriptors[4]);
size_t family_all_fds(const sparc64_family_t *family, int descriptors[6]);
int lock_file(int fd, short type);
bool owner_lease_offset(uint64_t incarnation, off_t *offset);
int acquire_owner_lease(sparc64_family_t *family, uint64_t incarnation);
int unlock_family_file(sparc64_family_t *family);
bool guard_valid_observed(const sparc64_family_guard_t *guard, sparc64_measure_observer_t *measure);
bool guard_valid(const sparc64_family_guard_t *guard);
void refresh_acquire(sparc64_family_t *family, sparc64_family_guard_t *guard);
void refresh_invalidate(sparc64_family_t *family);
void refresh_mutate(sparc64_family_t *family);
int recover_file_state(sparc64_family_guard_t *guard);
bool sparc64_family_guard_matches(const sparc64_family_guard_t *guard, const sparc64_family_t *family);
bool sparc64_family_guard_matches_observed(const sparc64_family_guard_t *guard, const sparc64_family_t *family, sparc64_measure_observer_t *measure);
int sparc64_family_refresh_observation(const sparc64_family_guard_t *guard, const sparc64_family_t *family, sparc64_family_refresh_stamp_t *out, bool *reusable);
int sparc64_family_refresh_observation_observed(const sparc64_family_guard_t *guard, const sparc64_family_t *family, sparc64_family_refresh_stamp_t *out, bool *reusable, sparc64_measure_observer_t *measure);
int normalize_owned_fd(int *fd_pointer);
int page_name(sparc64_family_page_key_t key, char output[48]);
int object_name(uint64_t object_id, char output[48]);
int control_fragment_name(size_t index, char output[48]);
bool object_file_size(uint32_t slot_count, size_t *size);
int observe_open_inode(sparc64_family_t *family, int fd);
sparc64_family_object_t *map_zero_object(sparc64_family_t *family, uint64_t object_id, uint32_t requested_count, int fd, bool initialize);
sparc64_family_object_t *map_object(sparc64_family_t *family, uint64_t object_id, uint32_t requested_count, int fd, bool initialize);
sparc64_family_page_t *map_page(sparc64_family_t *family, sparc64_family_page_key_t key, int fd, bool initialize);
void apply_absolute_state(sparc64_family_page_state_t *destination, const sparc64_family_page_state_t *target, sparc64_family_t *family, bool recovery);
sparc64_family_object_t *open_logged_object(sparc64_family_t *family, sparc64_family_page_key_t key);
uint64_t wait_checksum(const void *data, size_t size);
bool wait_bank_size(uint64_t capacity, size_t *size);
bool wait_pair_end(uint64_t base, uint64_t capacity, uint64_t *end);
bool wait_offset(uint64_t base, uint32_t index, uint64_t capacity, uint64_t *offset);
int ensure_control_extent(sparc64_family_t *family, uint64_t end);
int family_control_read(sparc64_family_t *family, void *buffer, size_t size, uint64_t offset);
int family_control_write(sparc64_family_t *family, const void *buffer, size_t size, uint64_t offset);
int read_wait_bank(sparc64_family_t *family, uint64_t base, uint32_t index, uint64_t capacity, uint64_t count, uint64_t revision, sparc64_family_wait_row_t **rows_out);
int write_wait_bank(sparc64_family_t *family, uint64_t base, uint32_t index, uint64_t capacity, uint64_t count, uint64_t revision, const sparc64_family_wait_row_t *rows);
int replay_committed(sparc64_family_t *family);
int initialize_family(sparc64_family_t **out, int control_fd, int dir_fd, sparc64_inode_pins_t pins, sparc64_file_caps_client_t sources, bool creator, const char *directory, bool terminal_sources, sparc64_family_storage_authority_t authority);
int sparc64_family_attach(sparc64_family_t **out, int owned_control_fd, int owned_dir_fd, sparc64_inode_pins_t owned_pins);
int sparc64_family_attach_with_sources(sparc64_family_t **out, int owned_control_fd, int owned_dir_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources);
bool exec_guard_valid(const sparc64_family_exec_t *exec);
bool exec_identity_matches(int control_fd, int dir_fd, const sparc64_family_identity_t *identity);
int sparc64_family_exec_prepare(sparc64_family_guard_t *guard, sparc64_family_exec_t **out);
int sparc64_family_exec_prepare_sources(sparc64_family_guard_t *guard, sparc64_family_exec_t **out);
const sparc64_family_exec_state_t *sparc64_family_exec_state(const sparc64_family_exec_t *exec);
int sparc64_family_exec_capabilities(const sparc64_family_exec_t *exec, int output[4]);
int sparc64_family_exec_source_capabilities(const sparc64_family_exec_t *exec, int output[6]);
int exec_restore_flags(sparc64_family_exec_t *exec);
int sparc64_family_exec_activate(sparc64_family_exec_t *exec);
int sparc64_family_exec_deactivate(sparc64_family_exec_t *exec);
int sparc64_family_exec_destroy(sparc64_family_exec_t **owned);
int sparc64_family_exec_receive(sparc64_family_t **out, sparc64_family_guard_t *guard, int owned_control_fd, int owned_dir_fd, sparc64_inode_pins_t owned_pins, const sparc64_family_exec_state_t *state);
int sparc64_family_exec_receive_sources(sparc64_family_t **out, sparc64_family_guard_t *guard, int owned_control_fd, int owned_dir_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state);
int sparc64_family_exec_receive_sources_terminal(sparc64_family_t **out, sparc64_family_guard_t *guard, int owned_control_fd, int owned_dir_fd, sparc64_inode_pins_t owned_pins, sparc64_file_caps_client_t owned_sources, const sparc64_family_exec_state_t *state);
int sparc64_family_fork_child_transfer(sparc64_family_t **inherited, sparc64_family_t **attached);
int sparc64_family_create_with_authority(sparc64_family_t **out, sparc64_family_storage_authority_t authority);
int sparc64_family_create(sparc64_family_t **out);
int sparc64_family_create_with_sources_authority(sparc64_family_t **out, sparc64_file_caps_client_t *owned, sparc64_family_storage_authority_t authority);
int sparc64_family_create_with_sources(sparc64_family_t **out, sparc64_file_caps_client_t *owned);
int family_enter_internal(sparc64_family_t *family, sparc64_family_guard_t *guard, bool allow_retired);
int sparc64_family_enter(sparc64_family_t *family, sparc64_family_guard_t *guard);
int sparc64_family_leave(sparc64_family_guard_t *guard);
int sparc64_family_leave_with_cleanup(sparc64_family_guard_t *guard, void (*after_unlock)(void *context), void *context);
uint64_t sparc64_family_incarnation(const sparc64_family_t *family);
bool sparc64_family_zero_backing(const sparc64_family_t *family);
int sparc64_family_owner_alive(const sparc64_family_guard_t *guard, uint64_t incarnation, bool *alive);
int sparc64_family_identity(const sparc64_family_guard_t *guard, sparc64_family_identity_t *out);
int sparc64_family_pin_file(sparc64_family_guard_t *guard, int source_fd);
const sparc64_file_caps_client_t *sparc64_family_sources(const sparc64_family_guard_t *guard);
uint64_t sparc64_family_file_index_object(const sparc64_family_guard_t *guard);
int sparc64_family_file_target_check(sparc64_family_guard_t *guard, int source_fd);
int sparc64_family_source_register(sparc64_family_guard_t *guard, int source_fd, uint64_t *source_id);
int read_file_catalog(sparc64_family_t *family, size_t count, sparc64_file_catalog_record_t **out);
int replay_file_record(sparc64_family_t *family);
int sparc64_family_file_intern(sparc64_family_guard_t *guard, const sparc64_file_identity_t *identity, int source_fd, uint64_t *file_id);
int catalog_wait_keys(sparc64_family_t *family, const sparc64_family_wait_row_t *rows, size_t count);
uint64_t sparc64_family_recovery_epoch(const sparc64_family_guard_t *guard);
const char *sparc64_family_private_directory(const sparc64_family_t *family);
int sparc64_family_observe_inodes(sparc64_family_guard_t *guard, sparc64_family_inode_observer_t observer, void *context);
int sparc64_family_unobserve_inodes(sparc64_family_guard_t *guard);
int sparc64_family_page_create(sparc64_family_guard_t *guard, sparc64_family_page_t **out);
int sparc64_family_page_open(sparc64_family_guard_t *guard, sparc64_family_page_key_t key, sparc64_family_page_t **out);
void sparc64_family_page_close(sparc64_family_page_t *page);
sparc64_family_page_key_t sparc64_family_page_key(const sparc64_family_page_t *page);
const sparc64_family_page_state_t *sparc64_family_page_readonly(const sparc64_family_guard_t *guard, const sparc64_family_page_t *page);
int validate_target(const sparc64_family_page_state_t *current, const sparc64_family_page_state_t *target);
int commit_states(sparc64_family_guard_t *guard, uint32_t kind, size_t count, const sparc64_family_page_key_t keys[2], sparc64_family_page_state_t *const destinations[2], const sparc64_family_page_state_t *const targets[2], bool file_refresh);
int validate_wait_root(sparc64_family_t *family, sparc64_family_wait_row_t **rows_out);
int sparc64_family_wait_backend_read(sparc64_family_guard_t *guard, sparc64_family_wait_table_t *table);
bool catalog_reserved_end(uint64_t *end);
bool wait_aligned_control_end(uint64_t *end);
bool wait_control_max_size(off_t *size_out);
void truncate_growth_tail(sparc64_family_t *family, uint64_t old_end);
int sparc64_family_wait_backend_commit(sparc64_family_guard_t *guard, sparc64_family_wait_table_t *table, const sparc64_family_object_update_t *updates, size_t update_count);
int sparc64_family_wait_backend_id(sparc64_family_guard_t *guard, bool mm_id, uint64_t *out);
int sparc64_family_page_commit(sparc64_family_guard_t *guard, sparc64_family_page_t *page, const sparc64_family_page_state_t *target);
int sparc64_family_object_create(sparc64_family_guard_t *guard, uint32_t slot_count, sparc64_family_object_t **out);
int sparc64_family_object_open(sparc64_family_guard_t *guard, uint64_t object_id, sparc64_family_object_t **out);
void sparc64_family_object_close(sparc64_family_object_t *object);
uint64_t sparc64_family_object_id(const sparc64_family_object_t *object);
uint32_t sparc64_family_object_count(const sparc64_family_object_t *object);
int sparc64_family_object_snapshot_observed(const sparc64_family_guard_t *guard, const sparc64_family_object_t *object, uint32_t page_index, sparc64_family_page_state_t *out, sparc64_measure_observer_t *measure);
int sparc64_family_object_snapshot(const sparc64_family_guard_t *guard, const sparc64_family_object_t *object, uint32_t page_index, sparc64_family_page_state_t *out);
int sparc64_family_object_snapshot_for_observed(const sparc64_family_guard_t *guard, const sparc64_family_t *expected_family, const sparc64_family_object_t *object, uint32_t page_index, sparc64_family_page_state_t *out, sparc64_measure_observer_t *measure);
int sparc64_family_object_commitv(sparc64_family_guard_t *guard, const sparc64_family_object_update_t *updates, size_t count);
int sparc64_family_object_commit(sparc64_family_guard_t *guard, sparc64_family_object_t *object, uint32_t page_index, const sparc64_family_page_state_t *target);
int sparc64_family_object_commit_file_refresh(sparc64_family_guard_t *guard, sparc64_family_object_t *object, uint32_t page_index, const sparc64_family_page_state_t *target);
int cleanup_held(sparc64_family_guard_t *guard, bool fresh_scan);
int sparc64_family_cleanup(sparc64_family_t *family);
int sparc64_family_cleanup_held_terminal(sparc64_family_guard_t *guard, bool sole_family_owner);
int sparc64_family_register_service_cleanup(sparc64_family_guard_t *guard, bool *may_have_delegated);
void sparc64_family_cleanup_service_release(void *retained);
int sparc64_family_cleanup_service_prepare_authority(int borrowed_control_fd, int borrowed_directory_fd, const char *directory, void **out, sparc64_family_storage_authority_t authority);
int sparc64_family_cleanup_service_prepare(int borrowed_control_fd, int borrowed_directory_fd, const char *directory, void **out);
int sparc64_family_cleanup_service_prepare_context(int borrowed_control_fd, int borrowed_directory_fd, const char *directory, void **out, void *context);
int sparc64_family_cleanup_service(int borrowed_control_fd, int borrowed_directory_fd, const char *directory);
int sparc64_family_cleanup_service_retained(int borrowed_control_fd, int borrowed_directory_fd, const char *directory, void *retained);
int sparc64_family_destroy(sparc64_family_t *family);
#ifdef SPARC64_FAMILY_TESTING
void sparc64_family_test_set_hook(sparc64_family_t *family, sparc64_family_test_hook_t hook, void *context);
void sparc64_family_test_point(sparc64_family_guard_t *guard, sparc64_family_test_point_t point);
void sparc64_family_test_fail_next_file_recovery(sparc64_family_t *family);
void sparc64_family_test_set_refresh_counters(sparc64_family_t *family, uint64_t next_acquisition, uint64_t mutation);
void sparc64_family_test_fail_next_unlock(sparc64_family_t *family);
void sparc64_family_test_fail_child_transfer_attach(sparc64_family_t *family);
void sparc64_family_test_fail_exec_activation(sparc64_family_t *family);
void sparc64_family_test_fail_exec_activation_at(sparc64_family_t *family, size_t index);
void sparc64_family_test_fail_next_wait_replay(sparc64_family_t *family);
void sparc64_family_test_descriptors(const sparc64_family_t *family, int *control_fd, int *dir_fd);
void sparc64_family_test_pin_state(const sparc64_family_t *family, sparc64_inode_pins_t *pins, uint64_t *attempts);
#endif

#endif /* SPARC64RT_RUNTIME_FAMILY_SPLIT_H */
