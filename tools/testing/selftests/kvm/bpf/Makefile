# SPDX-License-Identifier: GPL-2.0-only
#
# KVM-BPF selftests — BPF program compilation
#
# Compiles ple_db_policy.bpf.c into a BPF ELF object that can be
# loaded by kvm-bpfctl. Requires clang with BPF target support.
#
# Usage:
#   make                  — compile BPF program
#   make clean            — remove generated files
#

CLANG         ?= clang
LLVM_STRIP    ?= llvm-strip
BPF_CFLAGS    := -g -O2 -target bpf -mcpu=v3 \
                 -I. \
                 -I$(KBUILD_OUTPUT)/tools/include/uapi \
                 -I$(KBURILD_OUTPUT)/include/uapi \
                 -D__TARGET_ARCH_x86 \
                 -Wall -Werror \
                 --sysroot=$(SYSROOT)

# If KBUILD_OUTPUT is not set, try to find kernel headers
ifndef KBUILD_OUTPUT
KBUILD_OUTPUT := /lib/modules/$(shell uname -r)/build
endif
BPF_CFLAGS += -I$(KBUILD_OUTPUT)/tools/include/uapi
BPF_CFLAGS += -I$(KBUILD_OUTPUT)/tools/lib

all: ple_db_policy.bpf.o

ple_db_policy.bpf.o: ple_db_policy.bpf.c kvm_bpf_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@  # strip debug info while preserving BTF

clean:
	rm -f *.bpf.o

.PHONY: all clean
