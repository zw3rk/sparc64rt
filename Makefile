# Self-documenting Makefile for sparc64rt — SPARC V9 -> AArch64 user-mode translator
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Cross-compiles _build/sparc64rt with:
#   PATH=/nix/store/82ac69jwkpj68v4mx22yxnwzqj0ql4l5-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH \
#     make build check-line-limits
# or: nix build .#sparc64rt (uses the configured aarch64-linux builder).

.DEFAULT_GOAL := help
.PHONY: help all build check check-line-limits check-abi-invariants check-thr-granule clean
MAKEFLAGS += -j8

BUILD_DIR := _build
A64_CC ?= aarch64-unknown-linux-musl-gcc
HOST_CC ?= cc

# Curated C11, no VLAs, no Annex K, no <threads.h>, no _Generic.
CFLAGS ?= -O2
CFLAGS += -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra
CPPFLAGS += -Isrc -Iinclude
LDFLAGS_STATIC_PIE := -static-pie

# Wave U1/U2: the src/rt64 donor tree is gone; everything under src/
# builds for the Linux static-PIE target except the Darwin backend TU
# (src/os/backend_darwin.c, built by build-darwin instead).
EXCLUDED_SRCS := \
	src/os/backend_darwin.c

ALL_C_SRCS := $(shell find src -name '*.c')
LINUX_C_SRCS := $(filter-out $(EXCLUDED_SRCS),$(ALL_C_SRCS))
ASM_SRCS := $(shell find src -name '*.S')
SRCS := $(LINUX_C_SRCS) $(ASM_SRCS)

all: build ## Build the translator (default cross target)

build: $(BUILD_DIR)/sparc64rt ## Cross-compile _build/sparc64rt (static-PIE aarch64-musl)

# Per-object compilation: one translation unit per cc1 keeps host memory
# bounded (the single-shot link of ~150 TUs OOMs the compiler).
OBJ_DIR := $(BUILD_DIR)/obj
OBJS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(filter %.c,$(SRCS))) \
        $(patsubst src/%.S,$(OBJ_DIR)/%.o,$(filter %.S,$(SRCS)))

$(BUILD_DIR)/sparc64rt: $(OBJS)
	$(A64_CC) $(CFLAGS) $(CPPFLAGS) -fPIE $(LDFLAGS_STATIC_PIE) \
		$(OBJS) -o $@

$(OBJ_DIR)/%.o: src/%.c Makefile $(shell find src include -name '*.h')
	@mkdir -p $(dir $@)
	$(A64_CC) $(CFLAGS) $(CPPFLAGS) -fPIE -c $< -o $@

$(OBJ_DIR)/%.o: src/%.S Makefile $(shell find src include -name '*.h')
	@mkdir -p $(dir $@)
	$(A64_CC) $(CFLAGS) $(CPPFLAGS) -fPIE -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

check: build check-line-limits check-abi-invariants check-thr-granule ## Build plus all Phase 0 gates

check-line-limits: ## Fail if any src .c/.h/.S exceeds 900 lines
	@dirs="src"; test -d include && dirs="src include"; \
	over=$$(wc -l $$(find $$dirs -name '*.c' -o -name '*.h' -o -name '*.S') | \
		awk '$$2 != "total" && $$1 > 900 {print $$2}'); \
	if [ -n "$$over" ]; then \
		echo "files over 900 lines:"; \
		wc -l $$over; \
		exit 1; \
	fi; \
	echo "line limits ok (all src/include .c/.h/.S <= 900 lines)"

check-abi-invariants: ## Build and run tests/check_abi_invariants.c when present (Lane L0b)
	@if [ -f tests/check_abi_invariants.c ]; then \
		$(HOST_CC) $(CFLAGS) -Isrc tests/check_abi_invariants.c \
			-o $(BUILD_DIR)/check_abi_invariants && \
		./$(BUILD_DIR)/check_abi_invariants; \
	else \
		echo "check-abi-invariants: no tests/check_abi_invariants.c yet (Lane L0b), pass"; \
	fi

check-thr-granule: ## Build and run the host-atomic 4K-granule regression test (Wave U2)
	$(HOST_CC) $(CFLAGS) -Isrc tests/test_thr_resolve_granule.c \
		src/os/threads.c src/os/mem_space.c src/os/mem_space_write.c \
		-o $(BUILD_DIR)/test_thr_resolve_granule -pthread && \
	./$(BUILD_DIR)/test_thr_resolve_granule

clean: ## Remove build outputs
	rm -rf $(BUILD_DIR)

help: ## Show available targets
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_-]+: .*## ' Makefile | \
		sed 's/: .*## / — /'

# ---- Darwin standalone (Lane S1) -------------------------------------------
# Native macOS arm64 Mach-O link (clang -target arm64-apple-macos13):
# every src/*.c except the Linux-only backend, plus the DBT trampoline.
# safe_syscall_a64.S stays Linux-only and is excluded. -D_DARWIN_C_SOURCE
# exposes the full <sys/resource.h> rusage and <unistd.h> mkdtemp that
# the (frozen) host-contract TUs use.
.PHONY: build-darwin

DARWIN_CC ?= clang
DARWIN_TARGET ?= arm64-apple-macos13
# Frozen host-contract TUs carry Linux-only static helpers that are dead
# code on Darwin; keep them warnings (not errors) without touching the
# files or weakening -Werror elsewhere.
DARWIN_CFLAGS := -O2 -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra \
	-D_DARWIN_C_SOURCE -Wno-error=unused-function
DARWIN_CPPFLAGS := -Isrc -Iinclude
DARWIN_OBJ_DIR := $(BUILD_DIR)/darwin-obj
DARWIN_BIN := $(BUILD_DIR)/sparc64rt-darwin-arm64
DARWIN_C_SRCS := $(filter-out src/os/backend_linux.c,$(shell find src -name '*.c'))
DARWIN_S_SRCS := src/dbt/trampoline_a64.S
DARWIN_OBJS := $(patsubst src/%.c,$(DARWIN_OBJ_DIR)/%.o,$(DARWIN_C_SRCS)) \
	$(patsubst src/%.S,$(DARWIN_OBJ_DIR)/%.o,$(DARWIN_S_SRCS))

build-darwin: $(DARWIN_BIN) ## Link _build/sparc64rt-darwin-arm64 (native macOS arm64)

$(DARWIN_BIN): $(DARWIN_OBJS)
	@mkdir -p $(dir $@)
	$(DARWIN_CC) -target $(DARWIN_TARGET) $(DARWIN_OBJS) -o $@

$(DARWIN_OBJ_DIR)/%.o: src/%.c Makefile $(shell find src include -name '*.h')
	@mkdir -p $(dir $@)
	$(DARWIN_CC) -target $(DARWIN_TARGET) $(DARWIN_CFLAGS) \
		$(DARWIN_CPPFLAGS) -c $< -o $@

$(DARWIN_OBJ_DIR)/%.o: src/%.S Makefile $(shell find src include -name '*.h')
	@mkdir -p $(dir $@)
	$(DARWIN_CC) -target $(DARWIN_TARGET) $(DARWIN_CFLAGS) \
		$(DARWIN_CPPFLAGS) -c $< -o $@
