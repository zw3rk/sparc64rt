/*
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "runtime/host_smoke.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static _Thread_local int thread_value;
static volatile sig_atomic_t interrupt_seen;

static void
report(const char *name, int ok)
{
    (void)printf("host-smoke: %s %s\n", name, ok ? "PASS" : "FAIL");
}

static void
handle_signal(int signal_number)
{
    if (signal_number == SIGUSR1) {
        interrupt_seen = 1;
    }
}

static void *
check_thread_local(void *argument)
{
    int *result = argument;

    thread_value = 41;
    *result = thread_value;
    return NULL;
}

struct interrupt_request {
    pthread_t target;
    int write_fd;
};

static void *
send_interrupt(void *argument)
{
    const struct interrupt_request *request = argument;
    const struct timespec interval = { 0, 10000000L };
    char byte = 'x';
    int result = 0;
    unsigned int attempt;

    for (attempt = 0; attempt < 20U; attempt++) {
        int error = pthread_kill(request->target, SIGUSR1);
        if (error != 0) {
            result = error;
            break;
        }
        (void)nanosleep(&interval, NULL);
    }
    if (write(request->write_fd, &byte, sizeof(byte)) != (ssize_t)sizeof(byte)) {
        result = errno != 0 ? errno : EIO;
    }
    return (void *)(intptr_t)result;
}

static int
check_auxv_page_size(void)
{
    unsigned long page_size = getauxval(AT_PAGESZ);

    return page_size >= 1024UL && page_size <= 1048576UL &&
        (page_size & (page_size - 1UL)) == 0UL;
}

static int
check_mapping(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *mapping;
    volatile uint32_t *word;
    int ok;

    if (page_size <= 0) {
        return 0;
    }
    mapping = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        return 0;
    }
    word = mapping;
    *word = UINT32_C(0x72767274);
    ok = *word == UINT32_C(0x72767274);
    if (munmap(mapping, (size_t)page_size) != 0) {
        ok = 0;
    }
    return ok;
}

static int
check_interrupted_read(void)
{
    struct sigaction action;
    struct sigaction previous;
    struct interrupt_request request;
    pthread_t sender;
    int descriptors[2] = { -1, -1 };
    int action_installed = 0;
    int sender_started = 0;
    int ok = 0;
    int read_errno = 0;
    int sender_error = 0;
    char byte;
    ssize_t amount = -2;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGUSR1, &action, &previous) != 0) {
        return 0;
    }
    action_installed = 1;
    interrupt_seen = 0;
    if (pipe(descriptors) != 0) {
        goto cleanup;
    }
    request.target = pthread_self();
    request.write_fd = descriptors[1];
    if (pthread_create(&sender, NULL, send_interrupt, &request) != 0) {
        goto cleanup;
    }
    sender_started = 1;
    amount = read(descriptors[0], &byte, sizeof(byte));
    read_errno = errno;
    ok = amount == -1 && read_errno == EINTR && interrupt_seen != 0;

cleanup:
    if (sender_started) {
        void *thread_result = NULL;
        int join_result = pthread_join(sender, &thread_result);
        sender_error = (intptr_t)thread_result;
        if (join_result != 0 || sender_error != 0) {
            ok = 0;
        }
    }
    if (descriptors[0] >= 0 && close(descriptors[0]) != 0) {
        ok = 0;
    }
    if (descriptors[1] >= 0 && close(descriptors[1]) != 0) {
        ok = 0;
    }
    if (action_installed && sigaction(SIGUSR1, &previous, NULL) != 0) {
        ok = 0;
    }
    if (!ok) {
        (void)fprintf(stderr,
                      "host-smoke-detail: interrupted-read amount=%zd errno=%d "
                      "signal=%d sender=%d\n",
                      amount, read_errno, (int)interrupt_seen, sender_error);
    }
    return ok;
}

int
sparc64rt_host_smoke(void)
{
    pthread_t thread;
    int thread_result = 0;
    int thread_created = 0;
    int auxv_ok = check_auxv_page_size();
    int mapping_ok = check_mapping();
    int tls_ok;
    int interrupted_read_ok;

    report("auxv-pagesize", auxv_ok);
    report("anonymous-mmap", mapping_ok);
    if (pthread_create(&thread, NULL, check_thread_local, &thread_result) == 0) {
        thread_created = 1;
    }
    tls_ok = thread_created && pthread_join(thread, NULL) == 0 &&
        thread_result == 41 && thread_value == 0;
    report("pthread-tls", tls_ok);
    interrupted_read_ok = check_interrupted_read();
    report("interrupted-read", interrupted_read_ok);
    return auxv_ok && mapping_ok && tls_ok && interrupted_read_ok ? 0 : 1;
}
