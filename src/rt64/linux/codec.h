/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPARC64RT_LINUX_CODEC_H
#define SPARC64RT_LINUX_CODEC_H

#include <sys/stat.h>

/* Encode the 128-byte RV64 asm-generic Linux v6.18 struct stat wire form.
 * The host struct is never copied directly. Output is unchanged on failure. */
int sparc64_codec_stat64(unsigned char output[128], const struct stat *status);

#endif
