// SPDX-License-Identifier: GPL-2.0-only
/*
 * kvm-bpfctl — KVM-BPF policy loader and manager
 *
 * Loads BPF_PROG_TYPE_KVM_SCHED programs and attaches them to KVM
 * coordination hooks via the debugfs interface.
 *
 * Usage:
 *   kvm-bpfctl load ple_db_policy.bpf.o   — load and attach PLE policy
 *   kvm-bpfctl unload                      — detach PLE policy
 *   kvm-bpfctl list                        — show loaded policies
 *   kvm-bpfctl help                        — show usage
 *
 * Copyright (C) 2026 Sebastian
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/*
 * Debugfs path for PLE policy attachment.
 * Must match the path created by virt/kvm/kvm_bpf.c.
 */
#define KVM_BPF_DEBUGFS_DIR	"/sys/kernel/debug/kvm-bpf"
#define KVM_BPF_PLE_PROG_PATH	KVM_BPF_DEBUGFS_DIR "/ple_prog"

/* ── Utility helpers ─────────────────────────────────────────── */

static void die(const char *msg)
{
	fprintf(stderr, "Error: %s: %s\n", msg, strerror(errno));
	exit(1);
}

static void die_verbose(const char *msg, int err)
{
	fprintf(stderr, "Error: %s: %s\n", msg, strerror(-err));
	exit(1);
}

static void info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* ── Debugfs operations ──────────────────────────────────────── */

static int debugfs_write_fd(int fd)
{
	char buf[16];
	int len;
	int dfd;

	dfd = open(KVM_BPF_PLE_PROG_PATH, O_WRONLY);
	if (dfd < 0) {
		if (errno == ENOENT)
			fprintf(stderr,
				"Error: %s not found — is KVM-BPF loaded?\n"
				"  Try: modprobe kvm_intel && dmesg | grep KVM-BPF\n",
				KVM_BPF_PLE_PROG_PATH);
		else
			die("open " KVM_BPF_PLE_PROG_PATH);
		return -errno;
	}

	len = snprintf(buf, sizeof(buf), "%d", fd);
	if (write(dfd, buf, len) != len) {
		close(dfd);
		die("write " KVM_BPF_PLE_PROG_PATH);
	}

	close(dfd);
	return 0;
}

/* ── Commands ─────────────────────────────────────────────────── */

static int cmd_load(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	const char *filename;
	int prog_fd;
	int err;

	if (argc < 1) {
		fprintf(stderr, "Usage: kvm-bpfctl load <file.bpf.o>\n");
		return 1;
	}
	filename = argv[0];

	/* Open BPF object file */
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Error: failed to open %s\n", filename);
		return 1;
	}

	/* Find and configure the KVM-SCHED program */
	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		fprintf(stderr, "Error: no BPF program found in %s\n", filename);
		bpf_object__close(obj);
		return 1;
	}

	/* Set program type to BPF_PROG_TYPE_KVM_SCHED.
	 * The SEC("kvm_sched") in .bpf.c is a convention;
	 * we explicitly set the type here to ensure correct
	 * program type assignment regardless of libbpf's SEC handler.
	 */
	bpf_program__set_type(prog, BPF_PROG_TYPE_KVM_SCHED);

	/* Load the program into the kernel */
	err = bpf_object__load(obj);
	if (err) {
		die_verbose("bpf_object__load", err);
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: invalid program fd\n");
		bpf_object__close(obj);
		return 1;
	}

	/* Check if a program is already loaded */
	{
		char buf[16] = {};
		int check_fd = open(KVM_BPF_PLE_PROG_PATH, O_RDONLY);
		if (check_fd >= 0) {
			if (read(check_fd, buf, sizeof(buf) - 1) > 0 &&
			    buf[0] != '\0' && buf[0] != '0' && buf[0] != '\n') {
				fprintf(stderr,
					"Warning: a BPF program is already attached.\n"
					"  Overwrite? Use 'kvm-bpfctl unload' first to detach.\n");
				/* Continue anyway — debugfs write replaces the existing prog */
			}
			close(check_fd);
		}
	}

	/* Attach via debugfs */
	err = debugfs_write_fd(prog_fd);
	if (err) {
		bpf_object__close(obj);
		return 1;
	}

	info("KVM-BPF: loaded policy from %s (fd=%d)\n", filename, prog_fd);
	info("KVM-BPF: program attached via %s\n", KVM_BPF_PLE_PROG_PATH);

	/* Keep the object alive so the program stays loaded */
	info("KVM-BPF: program %p kept loaded\n", (void *)obj);

	return 0;
}

static int cmd_unload(int argc, char **argv)
{
	int err;

	err = debugfs_write_fd(0);  /* Write 0 to detach */
	if (err)
		return 1;

	info("KVM-BPF: policy detached\n");
	return 0;
}

static int cmd_list(int argc, char **argv)
{
	char buf[64];
	int fd;
	ssize_t n;

	fd = open(KVM_BPF_PLE_PROG_PATH, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			printf("KVM-BPF: not loaded (no debugfs interface)\n");
			return 0;
		}
		die("open " KVM_BPF_PLE_PROG_PATH);
	}

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0) {
		printf("KVM-BPF: no policy attached\n");
	} else {
		buf[n] = '\0';
		/* Remove trailing newline */
		if (n > 0 && buf[n-1] == '\n')
			buf[n-1] = '\0';
		printf("KVM-BPF: PLE policy fd=%s\n", buf);
	}

	return 0;
}

static void cmd_help(void)
{
	printf("KVM-BPF Policy Manager — kvm-bpfctl\n\n");
	printf("Usage:\n");
	printf("  kvm-bpfctl load <file.bpf.o>   — Load and attach PLE policy\n");
	printf("  kvm-bpfctl unload               — Detach PLE policy\n");
	printf("  kvm-bpfctl list                 — Show attached policies\n");
	printf("  kvm-bpfctl help                 — Show this help\n");
	printf("\n");
	printf("Debugfs paths:\n");
	printf("  %s\n", KVM_BPF_PLE_PROG_PATH);
	printf("\n");
	printf("Files:\n");
	printf("  ple_db_policy.bpf.o  — Adaptive PLE window policy\n");
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2) {
		cmd_help();
		return 0;
	}

	/* Set libbpf to strict mode for cleaner error reporting */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	cmd = argv[1];

	if (strcmp(cmd, "load") == 0)
		return cmd_load(argc - 2, argv + 2);
	else if (strcmp(cmd, "unload") == 0)
		return cmd_unload(argc - 2, argv + 2);
	else if (strcmp(cmd, "list") == 0)
		return cmd_list(argc - 2, argv + 2);
	else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0)
		cmd_help();
	else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		fprintf(stderr, "Try: kvm-bpfctl help\n");
		return 1;
	}

	return 0;
}
