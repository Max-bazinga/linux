// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM-BPF: Programmable Hypervisor Coordination with eBPF
 *
 * Exposes virtualization-aware coordination hooks as eBPF programs,
 * enabling workload-specific vCPU scheduling policies without kernel
 * modification.
 *
 * Copyright (C) 2026 Sebastian
 */

#include <linux/kvm_host.h>
#include <linux/bpf.h>
#include <linux/jump_label.h>

/*
 * Static key: when no BPF policy is loaded, all hooks are no-ops.
 * This ensures zero overhead in the default (no BPF) configuration.
 */
DEFINE_STATIC_KEY_FALSE(kvm_bpf_enabled_key);

/* Track whether any hook is registered */
static bool kvm_bpf_ple_hook_loaded;
static bool kvm_bpf_spin_hook_loaded;
static bool kvm_bpf_yield_hook_loaded;

/* Module parameters */
static bool kvm_bpf_enable __read_mostly = true;
module_param_named(bpf_enable, kvm_bpf_enable, bool, 0644);
MODULE_PARM_DESC(bpf_enable, "Enable KVM-BPF programmable coordination hooks");

/*
 * Build BPF context from current vCPU state.
 * Called before invoking a hook; the context is read-only for BPF programs.
 */
static void kvm_bpf_build_ctx(struct kvm_vcpu *vcpu,
			       struct kvm_bpf_ctx *ctx)
{
	ctx->vm_id = vcpu->kvm->userspace_pid;
	ctx->vcpu_id = vcpu->vcpu_id;
	ctx->cpu = raw_smp_processor_id();
#ifdef CONFIG_NUMA
	ctx->numa_node = cpu_to_node(ctx->cpu);
#else
	ctx->numa_node = -1;
#endif
	ctx->timestamp_ns = ktime_get_ns();

	ctx->ple_exits = vcpu->bpf_stats.ple_exits;
	ctx->total_exits = vcpu->bpf_stats.total_exits;
	ctx->yield_attempts = vcpu->bpf_stats.yield_attempts;
	ctx->yield_successes = vcpu->bpf_stats.yield_successes;
}

/*
 * Lightweight per-vCPU accounting on coordination-relevant VM exits.
 * Called from arch-specific exit handlers (e.g., vmx_handle_exit()).
 * The arch code categorizes exit reasons before calling this function.
 *
 * Only tracks events that matter for coordination decisions:
 *   - KVM_BPF_EVENT_PAUSE: lock contention (PLE exit)
 *   - KVM_BPF_EVENT_HLT:   vCPU idle
 *   - KVM_BPF_EVENT_IPI:   wakeup patterns
 *
 * @event: one of KVM_BPF_EVENT_* constants (defined in kvm_host.h)
 */
void kvm_bpf_account_exit(struct kvm_vcpu *vcpu, u32 event)
{
	if (!static_branch_unlikely(&kvm_bpf_enabled_key))
		return;

	vcpu->bpf_stats.total_exits++;

	switch (event) {
	case KVM_BPF_EVENT_PAUSE:
		vcpu->bpf_stats.ple_exits++;
		break;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_bpf_account_exit);

/*
 * PLE window hook: called when KVM is about to adjust the PLE window.
 * Returns the recommended PLE window, or 0 to use KVM's default logic.
 *
 * BPF programs can register via BPF_PROG_TYPE_KVM_SCHED to override
 * this decision point.
 */
u32 kvm_bpf_get_ple_window(struct kvm_vcpu *vcpu, u32 current_window)
{
	struct kvm_bpf_ctx ctx;

	if (!static_branch_unlikely(&kvm_bpf_enabled_key))
		return 0;

	if (!kvm_bpf_ple_hook_loaded)
		return 0;

	kvm_bpf_build_ctx(vcpu, &ctx);

	/*
	 * TODO Phase 1: Invoke registered BPF program here.
	 * For now, return 0 to fall through to KVM's default logic.
	 */
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_bpf_get_ple_window);

/*
 * Spin hook: called when a vCPU enters a spin-wait loop (PAUSE storm).
 * Returns:
 *   BPF_YIELD_NORMAL       — use KVM's default yield logic
 *   BPF_SKIP_YIELD         — skip yield, let vCPU spin
 *   BPF_YIELD_PREFER_LOCK_HOLDER — aggressively yield to known lock holder
 */
int kvm_bpf_on_spin(struct kvm_vcpu *vcpu)
{
	struct kvm_bpf_ctx ctx;

	if (!static_branch_unlikely(&kvm_bpf_enabled_key))
		return BPF_YIELD_NORMAL;

	if (!kvm_bpf_spin_hook_loaded)
		return BPF_YIELD_NORMAL;

	kvm_bpf_build_ctx(vcpu, &ctx);

	/*
	 * TODO Phase 3: Invoke registered BPF program here.
	 */
	return BPF_YIELD_NORMAL;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_bpf_on_spin);

/*
 * Yield target selection hook: called when deciding which vCPU to yield to.
 * Returns the recommended target vCPU index, or -1 for KVM default.
 */
int kvm_bpf_select_target(struct kvm_vcpu *vcpu)
{
	struct kvm_bpf_ctx ctx;

	if (!static_branch_unlikely(&kvm_bpf_enabled_key))
		return -1;

	if (!kvm_bpf_yield_hook_loaded)
		return -1;

	kvm_bpf_build_ctx(vcpu, &ctx);

	/*
	 * TODO Phase 3: Invoke registered BPF program here.
	 */
	return -1;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_bpf_select_target);

/*
 * Module init/exit — nothing to do yet; hooks are loaded dynamically.
 * Static key starts as disabled (false), ensuring zero overhead
 * until a BPF program is loaded.
 */
static int __init kvm_bpf_init(void)
{
	if (!kvm_bpf_enable)
		return 0;

	pr_info("KVM-BPF: programmable hypervisor coordination framework loaded (disabled)\n");
	pr_info("KVM-BPF: load a BPF policy to activate hooks\n");
	return 0;
}

static void __exit kvm_bpf_exit(void)
{
	pr_info("KVM-BPF: unloaded\n");
}

module_init(kvm_bpf_init);
module_exit(kvm_bpf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION("KVM-BPF: Programmable Hypervisor Coordination with eBPF");
