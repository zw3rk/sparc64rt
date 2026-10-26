/* tests/libh4.cc -- H4 cross-DSO RTTI/exception definitions (lane H4).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Out-of-line virtuals pin the vtables/typeinfo of H4Base, H4Derived
 * and H4Other to this shared object. Built with:
 *   sparc64-linux-gnu-g++ -std=c++17 -O2 -fPIC -shared \
 *     -Wl,-soname,libh4.so -o _build/libh4.so tests/libh4.cc
 */

#include "libh4.h"

#include <signal.h>

H4Base::~H4Base()
{
}

H4Derived::H4Derived(int v) : value(v)
{
}

H4Derived::~H4Derived()
{
}

int H4Derived::kind() const
{
    return 1;
}

H4Other::~H4Other()
{
}

int H4Other::kind() const
{
    return 2;
}

H4Base *h4_make_derived(int v)
{
    return new H4Derived(v);
}

int h4_raise_sig(int sig)
{
    return raise(sig);
}

void h4_throw_err(int code)
{
    H4Err err;
    err.code = code;
    throw err;
}
