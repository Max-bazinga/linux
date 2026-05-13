/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KVM-BPF: shared context definitions for BPF programs and userspace loader.
 *
 * This header mirrors struct kvm_bpf_ctx from include/linux/kvm_host.h.
 * It is used by both the BPF-side program (ple_db_policy.bpf.c) and the
 * userspace loader (kvm-bpfctl.c) to ensure consistent struct layout.
 *
 * NOTE: Keep in sync with include/linux/kvm_host.h when adding fields.
 */
#ifndef __KVM_BPF_COMMON_H
#define __KVM_BPF_COMMON_H

#include <linux/types.h>

/*
 * KVM-BPF context — passed to BPF_PROG_TYPE_KVM_SCHED programs.
 * All fields are read-only in the BPF program.
 */
struct kvm_bpf_ctx {
	__u32 vm_id;
	__u32 vcpu_id;
	__u32 cpu;
	__u32 numa_node;
	__u64 timestamp_ns;

	/* Coordination state snapshot */
	__u64 ple_exits;
	__u64 total_exits;
	__u64 yield_attempts;
	__u64 yield_successes;

	/* Current event / PLE-specific */
	__u32 exit_reason;
	__u32 current_ple_window;
} __attribute__((preserve_access_index));

/*
 * PLE window clamp range (must match KVM's clamp range).
 * BPF programs should return values within this range,
 * or 0 to defer to KVM's default logic.
 */
#define KVM_BPF_PLE_MIN	32U
#define KVM_BPF_PLE_MAX	2048U

/*
 * KVM-BPF hook return value constants
 * (for Phase 3+ yield hooks; included here for completeness)
 */
#define KVM_BPF_YIELD_NORMAL		0
#define KVM_BPF_SKIP_YIELD		1
#define KVM_BPF_YIELD_PREFER_LOCK_HOLDER	2

#endif /* __KVM_BPF_COMMON_H */
