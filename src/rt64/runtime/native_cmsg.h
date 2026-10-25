/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_RUNTIME_NATIVE_CMSG_H
#define SPARC64RT_RUNTIME_NATIVE_CMSG_H

#include <sys/socket.h>

/* musl 1.2.5's CMSG_NXTHDR macro compares size_t with a pointer difference.
 * Clang diagnoses that libc expansion at its project call site even when the
 * header is a system include. Limit suppression to this exact libc operation;
 * callers retain all project warnings and the native platform's traversal. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#endif
static inline struct cmsghdr *sparc64_native_cmsg_next(struct msghdr *message,
                                                 struct cmsghdr *header)
{
    return CMSG_NXTHDR(message, header);
}
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#endif
