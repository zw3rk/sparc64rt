/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "linux/error.h"

#include <errno.h>

/* Linux numbers follow v6.18 asm-generic/errno-base.h and errno.h. */
unsigned int sparc64_linux_errno(int host_errno) {
    switch (host_errno) {
    case 0: return 0;
#ifdef EPERM
    case EPERM: return 1;
#endif
#ifdef ENOENT
    case ENOENT: return 2;
#endif
#ifdef ESRCH
    case ESRCH: return 3;
#endif
#ifdef EINTR
    case EINTR: return 4;
#endif
#ifdef EIO
    case EIO: return 5;
#endif
#ifdef ENXIO
    case ENXIO: return 6;
#endif
#ifdef E2BIG
    case E2BIG: return 7;
#endif
#ifdef ENOEXEC
    case ENOEXEC: return 8;
#endif
#ifdef EBADF
    case EBADF: return 9;
#endif
#ifdef ECHILD
    case ECHILD: return 10;
#endif
#ifdef EAGAIN
    case EAGAIN: return 11;
#endif
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK: return 11;
#endif
#ifdef ENOMEM
    case ENOMEM: return 12;
#endif
#ifdef EACCES
    case EACCES: return 13;
#endif
#ifdef EFAULT
    case EFAULT: return 14;
#endif
#ifdef EBUSY
    case EBUSY: return 16;
#endif
#ifdef EEXIST
    case EEXIST: return 17;
#endif
#ifdef EXDEV
    case EXDEV: return 18;
#endif
#ifdef ENODEV
    case ENODEV: return 19;
#endif
#ifdef ENOTDIR
    case ENOTDIR: return 20;
#endif
#ifdef EISDIR
    case EISDIR: return 21;
#endif
#ifdef EINVAL
    case EINVAL: return 22;
#endif
#ifdef ENFILE
    case ENFILE: return 23;
#endif
#ifdef EMFILE
    case EMFILE: return 24;
#endif
#ifdef ENOTTY
    case ENOTTY: return 25;
#endif
#ifdef ETXTBSY
    case ETXTBSY: return 26;
#endif
#ifdef EFBIG
    case EFBIG: return 27;
#endif
#ifdef ENOSPC
    case ENOSPC: return 28;
#endif
#ifdef ESPIPE
    case ESPIPE: return 29;
#endif
#ifdef EROFS
    case EROFS: return 30;
#endif
#ifdef EMLINK
    case EMLINK: return 31;
#endif
#ifdef EPIPE
    case EPIPE: return 32;
#endif
#ifdef ERANGE
    case ERANGE: return 34;
#endif
#ifdef EDEADLK
    case EDEADLK: return 35;
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG: return 36;
#endif
#ifdef ENOLCK
    case ENOLCK: return 37;
#endif
#ifdef ENOSYS
    case ENOSYS: return 38;
#endif
#ifdef ENOTEMPTY
    case ENOTEMPTY: return 39;
#endif
#ifdef ELOOP
    case ELOOP: return 40;
#endif
#ifdef ENOMSG
    case ENOMSG: return 42;
#endif
#ifdef EIDRM
    case EIDRM: return 43;
#endif
#ifdef EPROTO
    case EPROTO: return 71;
#endif
#ifdef EOVERFLOW
    case EOVERFLOW: return 75;
#endif
#ifdef EOPNOTSUPP
    case EOPNOTSUPP: return 95;
#endif
#if defined(ENOTSUP) && ENOTSUP != EOPNOTSUPP
    case ENOTSUP: return 95;
#endif
#ifdef ENOTSOCK
    case ENOTSOCK: return 88;
#endif
#ifdef EDESTADDRREQ
    case EDESTADDRREQ: return 89;
#endif
#ifdef EMSGSIZE
    case EMSGSIZE: return 90;
#endif
#ifdef EPROTOTYPE
    case EPROTOTYPE: return 91;
#endif
#ifdef ENOPROTOOPT
    case ENOPROTOOPT: return 92;
#endif
#ifdef EPROTONOSUPPORT
    case EPROTONOSUPPORT: return 93;
#endif
#ifdef EAFNOSUPPORT
    case EAFNOSUPPORT: return 97;
#endif
#ifdef EADDRINUSE
    case EADDRINUSE: return 98;
#endif
#ifdef EADDRNOTAVAIL
    case EADDRNOTAVAIL: return 99;
#endif
#ifdef ENETDOWN
    case ENETDOWN: return 100;
#endif
#ifdef ENETUNREACH
    case ENETUNREACH: return 101;
#endif
#ifdef ENETRESET
    case ENETRESET: return 102;
#endif
#ifdef ECONNABORTED
    case ECONNABORTED: return 103;
#endif
#ifdef ECONNRESET
    case ECONNRESET: return 104;
#endif
#ifdef ENOBUFS
    case ENOBUFS: return 105;
#endif
#ifdef EISCONN
    case EISCONN: return 106;
#endif
#ifdef ENOTCONN
    case ENOTCONN: return 107;
#endif
#ifdef ETIMEDOUT
    case ETIMEDOUT: return 110;
#endif
#ifdef ECONNREFUSED
    case ECONNREFUSED: return 111;
#endif
#ifdef EHOSTUNREACH
    case EHOSTUNREACH: return 113;
#endif
#ifdef EINPROGRESS
    case EINPROGRESS: return 115;
#endif
#ifdef ESTALE
    case ESTALE: return 116;
#endif
#ifdef EDQUOT
    case EDQUOT: return 122;
#endif
#ifdef ECANCELED
    case ECANCELED: return 125;
#endif
    default: return 5;
    }
}
