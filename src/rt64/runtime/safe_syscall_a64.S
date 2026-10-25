/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
.text
.p2align 2
.global sparc64_native_safe_syscall
.hidden sparc64_native_safe_syscall
.type sparc64_native_safe_syscall, %function
sparc64_native_safe_syscall:
    mov x9, x0
    mov x8, x1
    mov x10, x2
    mov x12, x3
.global sparc64_native_safe_syscall_begin
.hidden sparc64_native_safe_syscall_begin
sparc64_native_safe_syscall_begin:
    ldar w11, [x9]
    cbnz w11, sparc64_native_safe_syscall_abort
    ldp x0, x1, [x10]
    ldp x2, x3, [x10, #16]
    ldp x4, x5, [x10, #32]
    svc #0
.global sparc64_native_safe_syscall_after_svc
.hidden sparc64_native_safe_syscall_after_svc
sparc64_native_safe_syscall_after_svc:
    ret
.global sparc64_native_safe_syscall_abort
.hidden sparc64_native_safe_syscall_abort
sparc64_native_safe_syscall_abort:
    mov x0, #-4
    cbz x12, 1f
    mov w11, #1
    stlr w11, [x12]
1:
    ret
.size sparc64_native_safe_syscall, .-sparc64_native_safe_syscall
.section .note.GNU-stack,"",%progbits
