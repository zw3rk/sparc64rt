/* tests/libh4.h -- H4 cross-DSO RTTI/exception surface (lane H4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Class definitions with out-of-line virtuals: the vtable and typeinfo
 * for H4Derived/H4Other live only in libh4.so, so every dynamic_cast
 * and catch in the main guest resolves RTTI across the DSO boundary
 * through the real ld.so link_map (no static typeinfo fallback).
 */

#ifndef SPARC64RT_TESTS_LIBH4_H
#define SPARC64RT_TESTS_LIBH4_H

struct H4Base {
    virtual ~H4Base();
    virtual int kind() const = 0;
};

struct H4Derived : H4Base {
    int value;
    explicit H4Derived(int v);
    ~H4Derived() override;
    int kind() const override;
};

struct H4Other : H4Base {
    ~H4Other() override;
    int kind() const override;
};

/* Plain (non-polymorphic) payload thrown by h4_throw_err; the catch in
 * the main guest matches it by cross-DSO typeinfo name comparison. */
struct H4Err {
    int code;
};

H4Base *h4_make_derived(int v);
void h4_throw_err(int code);

/* Synchronous signal raiser for the SIGNAL leg. Must stay a genuine
 * cross-DSO call (never inlined into the guest): the compiler emits a
 * call-site record with the catch action for this opaque call, which
 * is what lets the SIGUSR1-handler throw unwind to main's catch.
 * Calling the noexcept raise() directly in the try would emit no
 * record and the unwinder would terminate instead. Returns raise()'s
 * result so the guest can report setup failures deterministically. */
int h4_raise_sig(int sig);

#endif
