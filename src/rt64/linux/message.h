/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_MESSAGE_H
#define SPARC64RT_LINUX_MESSAGE_H

#include "linux/file.h"
#include <stdbool.h>
#include <stdint.h>

/* Bounded RV64 sendmsg/recvmsg for unnamed Unix stream sockets. */
bool sparc64_linux_message_dispatch(sparc64_linux_file_t *files, uint64_t number,
                               const uint64_t arguments[6], uint64_t *result);

#endif
