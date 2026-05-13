/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KVM-BPF: PLE window dynamic policy (Phase 1 prototype)
 *
 * Adaptive PLE window adjustment based on PAUSE exit ratio:
 *
 *   PLE ratio > 40%  →  double PLE window (max 2048)
 *   PLE ratio < 10%  →  halve PLE window   (min 32)
 *   Otherwise        →  keep current window
 *
 * This simple threshold policy demonstrates the KVM-BPF hook-first
 * programmability model: KVM calls the BPF program, BPF returns a
 * suggested window, and KVM clamps/sanitizes before applying.
 *
 * Copyright (C) 2026 Sebastian
 */
#include "kvm_bpf_common.h"

/*
 * Adaptive PLE window policy.
 *
 * Input:  struct kvm_bpf_ctx (read-only)
 * Output: u32 — suggested PLE window, or 0 = defer to KVM default
 *
 * The BPF program runs in the kvm_vcpu context with RCU lock held.
 * Only allow reads from the context; no BPF helper calls needed.
 *
 * SEC("kvm_sched") — handled by kvm-bpfctl which sets the program
 * type to BPF_PROG_TYPE_KVM_SCHED at load time.
 */
SEC("kvm_sched")
int ple_db_policy(struct kvm_bpf_ctx *ctx)
{
	__u32 current = ctx->current_ple_window;
	__u64 ple = ctx->ple_exits;
	__u64 total = ctx->total_exits;
	__u32 ratio;

	/*
	 * Compute PLE exit ratio as percentage.
	 * Guard against division by zero (no exits yet).
	 */
	if (total == 0)
		return 0;

	ratio = (__u32)((ple * 100ULL) / total);

	/*
	 * High PLE ratio → contention → increase window.
	 * BPF program suggests the value; KVM clamps to [32, 2048].
	 */
	if (ratio > 40) {
		__u32 suggested = current * 2;
		if (suggested > KVM_BPF_PLE_MAX)
			suggested = KVM_BPF_PLE_MAX;
		return suggested;
	}

	/*
	 * Low PLE ratio → low contention → decrease window.
	 * Smaller window means we detect PAUSE storms faster.
	 */
	if (ratio < 10) {
		__u32 suggested = current / 2;
		if (suggested < KVM_BPF_PLE_MIN)
			suggested = KVM_BPF_PLE_MIN;
		return suggested;
	}

	/*
	 * Normal range: return 0 to tell KVM to keep current window.
	 */
	return 0;
}

char _license[] SEC("license") = "GPL";
