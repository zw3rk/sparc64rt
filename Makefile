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
.PHONY: help all build check check-line-limits check-abi-invariants clean

BUILD_DIR := _build
A64_CC ?= aarch64-unknown-linux-musl-gcc
HOST_CC ?= cc

# Curated C11, no VLAs, no Annex K, no <threads.h>, no _Generic.
CFLAGS ?= -O2
CFLAGS += -std=c11 -Werror -Werror=vla -pedantic -Wall -Wextra
CPPFLAGS += -Isrc -Isrc/rt64
LDFLAGS_STATIC_PIE := -static-pie

# Four carried files stay out of the Phase 0 link until their later lanes
# provide the missing definitions; everything else under src/ builds. The
# frozen CPU/step contract in src/core/cpu.h already resolves the context
# types, and loader/ plus the jit/a64.h metadata surface are wired in.
# Engine-retry (Phase 1 interp) is omitted, not excluded: the file does
# not exist in the Phase 0 tree.
#   runtime/aot_discover.c (Phase 6): root discovery through call sequences
#     is ISA-specific and still follows the donor's RISC-V AUIPC/JALR walk.
#   runtime/aot_cache.c + runtime/pretranslate.c (Phase 2/6): the cache
#     needs the DBT emitter backend
#     (sparc64_jit_emit_relocatable/source_validate/publish_relocated) and
#     the Phase 6 discovery above; pretranslate drives the cache.
#   linux/signal.c (Phase 4): handler-entry register setup still follows
#     the donor convention (integer register file x0-style spill); V9
#     enters with the signal in %o0, siginfo in %o1, ucontext in %o2.
#   runtime/file_runtime_binding.c (Phase 4): needs signal.c's
#     sparc64_linux_signal_enqueue_fsize.
EXCLUDED_SRCS := \
	src/rt64/runtime/aot_discover.c \
	src/rt64/runtime/aot_cache.c \
	src/rt64/runtime/pretranslate.c \
	src/rt64/runtime/file_runtime_binding.c \
	src/rt64/linux/signal.c

ALL_C_SRCS := $(shell find src -name '*.c')
RT64_SRCS := $(filter-out $(EXCLUDED_SRCS),$(ALL_C_SRCS))
ASM_SRCS := $(shell find src -name '*.S')
SRCS := $(RT64_SRCS) $(ASM_SRCS)

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

$(OBJ_DIR)/%.o: src/%.c Makefile
	@mkdir -p $(dir $@)
	$(A64_CC) $(CFLAGS) $(CPPFLAGS) -fPIE -c $< -o $@

$(OBJ_DIR)/%.o: src/%.S Makefile
	@mkdir -p $(dir $@)
	$(A64_CC) $(CFLAGS) $(CPPFLAGS) -fPIE -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

check: build check-line-limits check-abi-invariants ## Build plus all Phase 0 gates

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

clean: ## Remove build outputs
	rm -rf $(BUILD_DIR)

help: ## Show available targets
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_-]+: .*## ' Makefile | \
		sed 's/: .*## / — /'
