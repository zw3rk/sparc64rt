/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_CAPS_H
#define SPARC64RT_RUNTIME_FILE_CAPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

/* Trusted, process-inherited service capabilities. The datagram endpoint
 * carries one atomic request and the stream endpoint keeps the service alive
 * while any client alias or queued SCM_RIGHTS alias exists. These native FDs
 * are private: callers must never publish them as guest descriptors. */
typedef struct {
    int request_fd;
    int lifetime_fd;
} sparc64_file_caps_client_t;

typedef struct {
    int request_fd;
    int lifetime_fd;
} sparc64_file_caps_server_t;

typedef int (*sparc64_file_caps_terminal_cleanup_fn)(int control_fd,
                                                 int directory_fd,
                                                 const char *directory);

/* Optional service-owned backing retained before the second cleanup ACK.
 * Prepare runs while the registering client still holds its family guard;
 * it must not acquire that guard's POSIX record lock. A failed prepare leaves
 * *out unchanged and receives no success ACK. Terminal runs after final EOF and
 * queued requests drain. Release runs on every service outcome. */
typedef struct {
    int (*prepare)(int control_fd, int directory_fd,
                   const char *directory, void **out);
    int (*prepare_context)(int control_fd, int directory_fd,
                           const char *directory, void **out, void *context);
    void *context;
    int (*terminal)(int control_fd, int directory_fd,
                    const char *directory, void *retained);
    void (*release)(void *retained);
} sparc64_file_caps_retained_cleanup_t;

/* Linear, thread-bound departure handle. A successful begin has a server
 * admission ACK while this caller still owns its source lifetime cap. The
 * caller then drains local work, closes every family/source alias, and calls
 * finish with only this handle alive. Finish reports exactly one of NONLAST
 * or LAST; only LAST may wait for the service's clean terminal observer.
 * Keep cancellation disabled from begin through finish and owner retirement,
 * then call end exactly once to restore the captured prior state. Do not copy,
 * fork, or exec with an admitted handle. An uncertain error is process-fatal. */
typedef struct {
    int reply_fd;
    pthread_t owner_thread;
    int prior_cancel_state;
    bool active;
    bool finished;
} sparc64_file_caps_departure_t;

#define SPARC64_FILE_CAPS_DEPARTURE_INITIALIZER {-1, (pthread_t)0, 0, false, false}

int sparc64_file_caps_departure_begin(const sparc64_file_caps_client_t *client,
                                 sparc64_file_caps_departure_t *out);
int sparc64_file_caps_departure_finish(sparc64_file_caps_departure_t *handle,
                                  bool *last);
int sparc64_file_caps_departure_end(sparc64_file_caps_departure_t *handle);

#define SPARC64_FILE_CAPS_CLIENT_INITIALIZER {-1, -1}
#define SPARC64_FILE_CAPS_SERVER_INITIALIZER {-1, -1}
#define SPARC64_FILE_CAPS_MAX_ATTEMPTS UINT64_C(4096)
#define SPARC64_FILE_CAPS_MAX_WRITE_BYTES ((size_t)65536)

typedef struct {
    int64_t transferred;
    int native_errno;
} sparc64_file_caps_write_result_t;

/* Immutable identity and process-owned FSIZE values for one attributed
 * mutation. The caller holds the family guard and supplies its existing
 * incarnation/MM/guest-thread lifetime tuple. These fields bind a cached
 * outcome to its original caller; they do not grant file authority. */
typedef struct {
    uint64_t owner_incarnation;
    uint64_t mm_id;
    uint64_t worker_id;
    uint64_t fsize_soft;
    uint64_t fsize_hard;
} sparc64_file_caps_call_context_t;

typedef struct {
    int64_t transferred;
    int native_errno;
    bool generated_sigxfsz;
} sparc64_file_caps_mutation_result_t;

bool sparc64_file_caps_call_context_valid(const sparc64_file_caps_call_context_t *context);
bool sparc64_file_caps_call_context_equal(const sparc64_file_caps_call_context_t *a,
                                     const sparc64_file_caps_call_context_t *b);

/* Version-3 attributed operations preserve all version-1/2 calls and wire
 * frames. The same exact retained FD and one-effect/cached-outcome rules
 * apply. A generated SIGXFSZ is observed from the native operation itself,
 * never inferred from EFBIG. A repeat EXECUTE returns the original result
 * and event without rechecking the current limit or target state. The
 * caller must deliver the cached event only to the original live guest
 * task after canonical result/PC commit; recovery alone never delivers it.
 * The service's inherited native hard ceiling remains a separate limit. */
int sparc64_file_caps_truncate_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, int borrowed_fd, uint64_t length,
    const sparc64_file_caps_call_context_t *context);
int sparc64_file_caps_truncate_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result);
int sparc64_file_caps_pwrite_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, int borrowed_fd, uint64_t offset,
    const void *bytes, size_t count, const sparc64_file_caps_call_context_t *context);
int sparc64_file_caps_pwrite_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result);
int sparc64_file_caps_append_pwrite_stage_attributed(
    const sparc64_file_caps_client_t *client, uint64_t operation_id, int borrowed_fd,
    uint64_t expected_eof, const void *bytes, size_t count,
    const sparc64_file_caps_call_context_t *context);
int sparc64_file_caps_append_pwrite_execute_attributed(
    const sparc64_file_caps_client_t *client, uint64_t operation_id,
    const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result);
int sparc64_file_caps_write_stage_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, int borrowed_fd, uint64_t expected_offset,
    bool expected_append, const void *bytes, size_t count,
    const sparc64_file_caps_call_context_t *context);
int sparc64_file_caps_write_execute_attributed(const sparc64_file_caps_client_t *client,
    uint64_t operation_id, const sparc64_file_caps_call_context_t *context,
    sparc64_file_caps_mutation_result_t *result);

/* Create both roles with distinct >=3, CLOEXEC native descriptors. A forked
 * service closes the client role; every client closes the server role. */
int sparc64_file_caps_pair_create(sparc64_file_caps_client_t *client,
                             sparc64_file_caps_server_t *server);
/* Consume two trusted inherited client FDs on every outcome. The caller must
 * have obtained this exact pair from create/duplicate/fork/exec, not discover
 * a service by pathname, PID, inode number or guest-controlled bytes. */
int sparc64_file_caps_client_adopt(sparc64_file_caps_client_t *out,
                              int request_fd, int lifetime_fd);
/* Terminal same-PID exec recovery only: consume the exact inherited pair
 * after the service has died. Validate native UNIX role kinds and private
 * descriptor flags without requiring a live peer. Never submit an RPC through
 * a pair admitted this way or publish it as a normal family client. */
int sparc64_file_caps_client_adopt_terminal(sparc64_file_caps_client_t *out,
                                       int request_fd, int lifetime_fd);
/* Non-consuming health probe for an already trusted pair. The lifetime
 * stream carries no data; EOF or data means it cannot serve new requests. */
bool sparc64_file_caps_client_live(const sparc64_file_caps_client_t *client);
int sparc64_file_caps_client_duplicate(const sparc64_file_caps_client_t *source,
                                  sparc64_file_caps_client_t *out);
void sparc64_file_caps_client_close(sparc64_file_caps_client_t *client);
void sparc64_file_caps_server_close(sparc64_file_caps_server_t *server);

/* Consume the server role and all registered source FDs before returning.
 * The caller runs this in a controlled child and owns its exact waitpid.
 * The service retires after the final client lifetime cap and queued request
 * reference close, independently of the creator's PID. */
int sparc64_file_caps_serve(sparc64_file_caps_server_t *server);

/* Source-family startup only, before the first guest turn. Borrow the exact
 * control and directory descriptions; the server retains distinct SCM rights
 * but no client lifetime alias. Each of two admission packets owns its queued
 * sender/lifetime pins and gets an ACK. Failure is fatal to source startup:
 * an uncertain ACK must never be retried after guest work begins. */
int sparc64_file_caps_register_terminal_cleanup(const sparc64_file_caps_client_t *client,
                                            int borrowed_control_fd,
                                            int borrowed_directory_fd,
                                            const char *directory,
                                            bool *may_have_delegated);

/* The callback runs only after the final lifetime EOF and every queued
 * request has been drained. A callback failure preserves family evidence and
 * makes service retirement fail; the service sends no success observation. */
int sparc64_file_caps_serve_with_cleanup(sparc64_file_caps_server_t *server,
                                    sparc64_file_caps_terminal_cleanup_fn cleanup);
int sparc64_file_caps_serve_with_retained_cleanup(
    sparc64_file_caps_server_t *server,
    const sparc64_file_caps_retained_cleanup_t *cleanup);

/* Caller holds its family guard. source_id is a monotonic, nonzero family
 * source ID, not a catalog equivalence ID. attempts points at the family's
 * shared persistent counter. A charge is nonrefundable and happens before
 * request submission. A successful ACK proves service retention before the
 * caller publishes metadata. A lost/malformed ACK returns EIO: never retry
 * that source ID or refund the charge. source_fd remains caller-owned. */
int sparc64_file_caps_register(const sparc64_file_caps_client_t *client,
                          int source_fd, uint64_t source_id,
                          uint64_t *attempts);

/* Return a new >=3, CLOEXEC FD for the exact registered open description.
 * Leave *out_fd unchanged on every failure. The caller owns a success FD. */
int sparc64_file_caps_fetch(const sparc64_file_caps_client_t *client,
                       uint64_t source_id, int *out_fd);

/* Trusted family-guard-only mutation capability. Stage retains an exact
 * writable regular FD (including O_WRONLY), without executing or consuming it.
 * operation_id is a fresh monotonic family object ID. One service slot is
 * bounded: a greater ID replaces a previous orphan/completed slot only when
 * the caller has established that no canonical intent still needs it. Equal
 * or older stage IDs fail; delayed older executions can never apply again.
 * Publish a canonical intent only after the stage ACK. Uncertain submission
 * must not be restaged with the same ID or treated as an acknowledged stage. */
int sparc64_file_caps_truncate_stage(const sparc64_file_caps_client_t *client,
                                 uint64_t operation_id, int borrowed_fd,
                                 uint64_t length);
/* Execute this staged operation at most once in the independent service.
 * The service caches its native errno before sending the reply. A repeat
 * returns the retained outcome without another ftruncate. Return0 means a
 * complete outcome, including a native failure in *out_native_errno; -1 is a
 * protocol/transport failure and leaves output unchanged. Service death is
 * infrastructure-fatal, not a promise to recover from the filesystem's size.
 * Native credentials/limits are the service's; future guest admission must
 * explicitly preserve caller limit and SIGXFSZ behavior. The service consumes
 * only its newly generated failure signal and survives a native EFBIG.
 * Retain the intent until canonical reconciliation is complete. */
int sparc64_file_caps_truncate_execute(const sparc64_file_caps_client_t *client,
                                   uint64_t operation_id, int *out_native_errno);

/* Caller holds the exact family guard/cancellation exclusion and must
 * serialize F_SETFL changes to O_APPEND through every alias until execute
 * returns; the service's append recheck is not atomic against foreign flag
 * writers. The service
 * retains a private immutable copy after a successful SEAL. The caller's
 * buffer may change or disappear after stage returns. Offset/count are bounded
 * to signed 64-bit file positions; count is at most 65536 bytes. The staged FD
 * must be a writable regular file without O_APPEND, both when staged and when
 * executed. Execution is one pwrite: short counts and EINTR are returned as
 * native outcomes, never filled or retried. The OFD shared cursor is unchanged.
 * Mutation IDs share the monotonic order with truncate operations. */
int sparc64_file_caps_pwrite_stage(const sparc64_file_caps_client_t *client,
                              uint64_t operation_id, int borrowed_fd,
                              uint64_t offset, const void *bytes, size_t count);
/* One execution per operation ID. A native failure is returned in result
 * (transferred=-1, native_errno set); -1 from this API means protocol or
 * transport failure and leaves *result unchanged. */
int sparc64_file_caps_pwrite_execute(const sparc64_file_caps_client_t *client,
                                uint64_t operation_id,
                                sparc64_file_caps_write_result_t *result);

/* Caller holds the complete family guard across stage, intent publication,
 * and execute. It has already validated the guest's supplied positional
 * offset, then frozen O_APPEND and the exact target's EOF before preflight.
 * Every admitted writer, resize, F_SETFL and cursor alias uses that guard;
 * external/native writers are excluded. Stage retains the exact writable
 * O_APPEND description and an immutable payload at expected_eof. Execute
 * checks the frozen append state and EOF again before one native pwrite.
 * Linux appends through O_APPEND; Darwin writes at expected_eof. Both leave
 * the shared OFD cursor unchanged under this contract. A duplicate execute
 * returns the cached native result without another state check or effect.
 * The returned result/error and uncertain transport policy match pwrite. */
int sparc64_file_caps_append_pwrite_stage(const sparc64_file_caps_client_t *client,
                                      uint64_t operation_id, int borrowed_fd,
                                      uint64_t expected_eof,
                                      const void *bytes, size_t count);
int sparc64_file_caps_append_pwrite_execute(const sparc64_file_caps_client_t *client,
                                        uint64_t operation_id,
                                        sparc64_file_caps_write_result_t *result);

/* Caller holds one family guard that serializes every admitted write and OFD
 * cursor change across aliases through execute, including read/readv, lseek,
 * source-side copy operations and F_SETFL(O_APPEND). The
 * native service excludes uncoordinated external writers only by contract.
 * expected_offset is the OFD cursor for nonappend files and the file EOF for
 * O_APPEND files. Stage freezes that origin and an immutable payload. Execute
 * revalidates them, performs exactly one native write (never pwrite+seek), and
 * caches even short/error outcomes before replying. A lost reply or requester
 * death never replays the native write. The cursor advances by the native
 * result exactly once; O_APPEND retains native atomic-append behavior. */
int sparc64_file_caps_write_stage(const sparc64_file_caps_client_t *client,
                             uint64_t operation_id, int borrowed_fd,
                             uint64_t expected_offset, bool expected_append,
                             const void *bytes, size_t count);
int sparc64_file_caps_write_execute(const sparc64_file_caps_client_t *client,
                               uint64_t operation_id,
                               sparc64_file_caps_write_result_t *result);

#ifdef SPARC64_FILE_CAPS_TESTING
typedef enum {
    SPARC64_FILE_CAPS_TEST_REGISTER_SENT,
    SPARC64_FILE_CAPS_TEST_FETCH_SENT,
    SPARC64_FILE_CAPS_TEST_REPLY_QUEUED,
    SPARC64_FILE_CAPS_TEST_REGISTER_RETAINED,
    SPARC64_FILE_CAPS_TEST_TRUNCATE_STAGE_SENT,
    SPARC64_FILE_CAPS_TEST_TRUNCATE_EXECUTE_SENT,
    SPARC64_FILE_CAPS_TEST_TRUNCATE_RETAINED,
    SPARC64_FILE_CAPS_TEST_TRUNCATE_EXECUTED,
    SPARC64_FILE_CAPS_TEST_PWRITE_BEGIN_SENT,
    SPARC64_FILE_CAPS_TEST_PWRITE_CHUNK_SENT,
    SPARC64_FILE_CAPS_TEST_PWRITE_SEAL_SENT,
    SPARC64_FILE_CAPS_TEST_PWRITE_EXECUTE_SENT,
    SPARC64_FILE_CAPS_TEST_PWRITE_RETAINED,
    SPARC64_FILE_CAPS_TEST_PWRITE_SEALED,
    SPARC64_FILE_CAPS_TEST_PWRITE_EXECUTED,
    SPARC64_FILE_CAPS_TEST_WRITE_BEGIN_SENT,
    SPARC64_FILE_CAPS_TEST_WRITE_EXECUTE_SENT,
    SPARC64_FILE_CAPS_TEST_WRITE_RETAINED,
    SPARC64_FILE_CAPS_TEST_WRITE_SEALED,
    SPARC64_FILE_CAPS_TEST_WRITE_EXECUTED,
    SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_BEGIN_SENT,
    SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_EXECUTE_SENT,
    SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_RETAINED,
    SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_SEALED,
    SPARC64_FILE_CAPS_TEST_APPEND_PWRITE_EXECUTED,
    SPARC64_FILE_CAPS_TEST_CLEANUP_DIRECTORY_SENT,
    SPARC64_FILE_CAPS_TEST_DEPARTURE_PREPARE_SENT,
    SPARC64_FILE_CAPS_TEST_DEPARTURE_ADMITTED_SENT
} sparc64_file_caps_test_point_t;
typedef void (*sparc64_file_caps_test_hook_t)(sparc64_file_caps_test_point_t, void *);
void sparc64_file_caps_test_set_hook(sparc64_file_caps_test_hook_t hook, void *context);
#endif

#endif
