/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LOADER_IMAGE_H
#define SPARC64RT_LOADER_IMAGE_H
#include "linux/resolve.h"
#include "memory/space.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t entry, phdr, program_break;
    uint16_t phnum;
    uint32_t flags;
    uint64_t start_pc, load_bias, interpreter_base;
} sparc64_image_info_t;

typedef struct sparc64_prepared_program sparc64_prepared_program_t;
struct sparc64_linux_exec_args;

/* Consumes image_fd when nonnegative. Both the target and PT_INTERP are
 * validated, including their joint placement in a fresh RV64 space, and
 * copied into private snapshots before this returns. The path and original
 * files are never consulted by map_prepared. */
bool sparc64_program_prepare(const char *path, int image_fd, const char *sysroot,
                        sparc64_prepared_program_t **out, char *error,
                        size_t error_size);
/* Runtime guest path consumes owned_target_fd on every outcome when it is
 * nonnegative. The target must have been opened through the borrowed protected
 * resolver with O_NONBLOCK. PT_INTERP is opened through that resolver after
 * sysroot translation, never with a raw host open. Native errno remains for
 * diagnostics. Optional linux_error receives the Linux errno number (zero on
 * success): invalid target ELF ENOEXEC, invalid interpreter ELF ELIBBAD,
 * nonregular files EACCES, resource failures ENOMEM, and translated native
 * open/read/stat/close errors. Changed snapshots return ETXTBSY. */
bool sparc64_program_prepare_guest(const char *path, int owned_target_fd,
                              const char *sysroot,
                              sparc64_path_resolver_t *borrowed_resolver,
                              sparc64_prepared_program_t **out, char *error,
                              size_t error_size, unsigned int *linux_error);
/* Guest execve: same consuming/protected contract, plus Linux script
 * interpreter recursion. Rewrites only the owned staged argv; original
 * args.path/AT_EXECFN and envp remain. Destroy args after any failure. Scripts
 * read only the first256 bytes; final ELF is snapshotted from that same FD. */
bool sparc64_program_prepare_guest_exec(const char *host_path, int owned_target_fd,
                                    const char *sysroot,
                                    sparc64_path_resolver_t *resolver,
                                    struct sparc64_linux_exec_args *args,
                                    sparc64_prepared_program_t **out,
                                    char *error, size_t error_size,
                                    unsigned int *linux_error);
/* The caller supplies a fresh candidate space and discards it on failure.
 * Repeated maps of one prepared program use the same immutable bytes. */
bool sparc64_program_map_prepared(const sparc64_prepared_program_t *prepared,
                             sparc64_space_t *space, sparc64_image_info_t *info,
                             char *error, size_t error_size);
void sparc64_program_prepared_destroy(sparc64_prepared_program_t *prepared);

/* Borrow the exact immutable target bytes loaded by map_prepared. The
 * prepared owner must outlive this borrow; no pathname or source FD is read. */
bool sparc64_program_prepared_target(const sparc64_prepared_program_t *prepared,
                                const uint8_t **bytes, size_t *size,
                                bool *has_interpreter);
/* Borrow the exact immutable PT_INTERP bytes mapped by map_prepared. This
 * succeeds only for a prepared program with an interpreter. */
bool sparc64_program_prepared_interpreter(const sparc64_prepared_program_t *prepared,
                                     const uint8_t **bytes, size_t *size);
/* Return the exclusive image-relative end of the executable PT_LOAD that
 * contains the selected image's entry. The caller supplies the mapped entry
 * offset to bind this immutable span to the image_info used at startup. */
bool sparc64_program_prepared_entry_exec_end(const sparc64_prepared_program_t *prepared,
                                        bool interpreter, uint64_t entry_offset,
                                        uint64_t *end_offset);
/* Borrow the immutable executable PT_LOAD span containing an image-relative
 * PC. Outputs are image-relative and unchanged on failure. This does not
 * authorize a live mapping or validate mutable guest instruction bytes. */
bool sparc64_program_prepared_exec_span(const sparc64_prepared_program_t *prepared,
                                    bool interpreter, uint64_t relative_pc,
                                    uint64_t *start_offset, uint64_t *end_offset);

typedef struct sparc64_program_export sparc64_program_export_t;

/* Under complete guest/native-I/O quiescence, copy the prepared target and
 * interpreter bytes into an unlinked owner-only metadata file. The borrowed
 * resolver protects its inode until export destruction, which must precede
 * resolver teardown. No path or native FD number appears in the record. */
int sparc64_program_export_create(const sparc64_prepared_program_t *prepared,
                              sparc64_path_resolver_t *resolver,
                              sparc64_program_export_t **out);
int sparc64_program_export_fd(const sparc64_program_export_t *owner); /* Borrowed >=3. */
/* Clear only this capability's CLOEXEC for native self-exec. On failure,
 * activation rolls back. Deactivate before resuming workers after failed exec;
 * a failed rollback is fatal to that runtime. */
int sparc64_program_export_activate(sparc64_program_export_t *owner);
int sparc64_program_export_deactivate(sparc64_program_export_t *owner);
void sparc64_program_export_destroy(sparc64_program_export_t **owner);
/* Early self-exec startup: consume the explicit owned FD >=3 on every
 * outcome, restore CLOEXEC before parsing, and revalidate both private byte
 * snapshots jointly. No original target/interpreter pathname is reopened.
 * This same-UID native transport does not authenticate arbitrary callers. */
bool sparc64_program_import(int owned_fd, sparc64_prepared_program_t **out,
                        char *error, size_t error_size);

/* Consumes image_fd when nonnegative, otherwise opens path. All validation and
 * mapping use one private byte snapshot. On failure discard the space. */
bool sparc64_image_load(const char *path, int image_fd, sparc64_space_t *space,
                    sparc64_image_info_t *info, char *error, size_t error_size);
/* Explicit target path is runtime-visible and opened literally. Absolute
 * guest PT_INTERP paths are prefixed with sysroot, relative ones use cwd.
 * Prefixing is path translation, not filesystem confinement. */
bool sparc64_program_load(const char *path, int image_fd, const char *sysroot,
                      sparc64_space_t *space, sparc64_image_info_t *info,
                      char *error, size_t error_size);
bool sparc64_stack_build(sparc64_space_t *space, const sparc64_image_info_t *image,
                     const char *path, int argc, char *const argv[],
                     char *const envp[], uint64_t *stack_pointer,
                     char *error, size_t error_size);
#endif
