# SPDX-License-Identifier: GPL-2.0-only
#
# kvm-bpfctl — build system
#
# Compiles the KVM-BPF policy loader and manager tool.
# Requires libbpf development headers (libbpf-dev on Debian/Ubuntu,
# libbpf-devel on Fedora/RHEL).
#
# Usage:
#   make             — build kvm-bpfctl
#   make clean       — remove compiled artifacts
#   make install     — install to /usr/local/sbin
#

CC             ?= gcc
CFLAGS         := -g -O2 -Wall -Wextra -Werror
LDFLAGS        :=
LDLIBS         := -lbpf -lelf -lz

# Installation prefix
PREFIX         ?= /usr/local
SBINDIR        := $(DESTDIR)$(PREFIX)/sbin

# Try pkg-config for libbpf flags, fall back to direct
LIBS := $(LDLIBS)
PC_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
ifneq ($(PC_CFLAGS),)
CFLAGS += $(PC_CFLAGS)
endif

all: kvm-bpfctl

kvm-bpfctl: kvm-bpfctl.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

kvm-bpfctl.o: kvm-bpfctl.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f kvm-bpfctl kvm-bpfctl.o

install: kvm-bpfctl
	install -d $(SBINDIR)
	install -m 755 kvm-bpfctl $(SBINDIR)/kvm-bpfctl

.PHONY: all clean install
