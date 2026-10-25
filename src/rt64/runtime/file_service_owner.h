/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_FILE_SERVICE_OWNER_H
#define SPARC64RT_RUNTIME_FILE_SERVICE_OWNER_H

#include "runtime/file_caps.h"
#include "runtime/family_authority.h"

/* Internal Linux runtime only. The service is an orphan after its short-lived
 * clone(0) bootstrap has been reaped. Its own typed pidfd supplies exact
 * signal authority; a separate STREAM endpoint observes service death.
 * Neither descriptor belongs in the guest FD table. */
typedef struct {
    int pidfd;
    int observer_fd;
} sparc64_file_service_owner_t;

#define SPARC64_FILE_SERVICE_OWNER_INITIALIZER {-1, -1}

/* Start before guest workers. The caller supplies an empty owner and client;
 * success transfers the client pair to the caller. No service PID is exposed
 * to guest wait or to the native SIGCHLD collector. */
int sparc64_file_service_owner_start(sparc64_file_service_owner_t *owner,
                                sparc64_file_caps_client_t *client);
int sparc64_file_service_owner_start_with_authority(
    sparc64_file_service_owner_t *owner, sparc64_file_caps_client_t *client,
    sparc64_family_storage_authority_t authority);
/* The private exec vector must transfer BOTH exact caps before native exec.
 * Adoption consumes them even on failure and never starts a new service. */
int sparc64_file_service_owner_adopt(sparc64_file_service_owner_t *owner,
                                int owned_pidfd, int owned_observer_fd);
/* Exec failure cleanup needs to retain final-death authority for a service
 * already dead at receipt. Return 0 live, 1 unexpected death with both caps
 * retained in owner, or -1 invalid/normalization failure with supplied caps
 * consumed. A caller receiving 1 must never start guest work. */
int sparc64_file_service_owner_adopt_classified(sparc64_file_service_owner_t *owner,
                                int owned_pidfd, int owned_observer_fd);
/* An unexpected service exit is fatal, regardless of guest signal state. */
int sparc64_file_service_owner_check(const sparc64_file_service_owner_t *owner);
/* Process-local exit closes only this process's observation/signal caps.
 * A forked family member may still own client lifetime aliases. */
void sparc64_file_service_owner_close_local(sparc64_file_service_owner_t *owner);
/* Call only after proving that the last family client lifetime alias has
 * closed. Wait for normal EOF and then pidfd POLLHUP (fully reaped) within the
 * existing monotonic deadline; kill through the exact pidfd if protocol
 * retirement stalls. EOF alone does not prove process death. No numeric-PID
 * kill or wait is used. Unsupported pidfd poll fails without an EOF fallback. */
int sparc64_file_service_owner_retire_last(sparc64_file_service_owner_t *owner);

#endif
