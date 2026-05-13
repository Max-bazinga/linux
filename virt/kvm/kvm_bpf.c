// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM-BPF: Programmable Hypervisor Coordination with eBPF
 *
 * Exposes virtualization-aware coordination hooks as eBPF programs,
 * enabling workload-specific vCPU scheduling policies without kernel
 * modification.
 *
 * Phase 1: PLE policy hook with BPF_PROG_TYPE_KVM_SCHED
 *   - Registers BPF_PROG_TYPE_KVM_SCHED for KVM coordination hooks
 *   - Implements kvm_bpf_get_ple_window() calling BPF programs
 *   - Advisory-only safety model: KVM clamps BPF return values
 *   - Per-vCPU statistics cache for hotpath efficiency
 *   - Debugfs interface for BPF program attach/detach
 *
 * Copyright (C) 2026 Sebastian
 */

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/jump_label.h>
#include <linux/debugfs.h>
#include <linux/filter.h>
#include <linux/kstrtox.h>

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

/* ── BPF program storage (RCU-protected) ─────────────────────── */

/*
 * Per-hook BPF programs stored as RCU-protected pointers.
 * Readers (hook functions) use rcu_dereference() in an RCU read-side
 * critical section; writers serialize via ple_prog_mutex.
 *
 * Phase 1: only PLE hook. Yield hooks added in Phase 3.
 */
static struct bpf_prog __rcu *kvm_bpf_ple_prog __read_mostly;
static DEFINE_MUTEX(ple_prog_mutex);	/* serialises attach/detach */

/*
 * PLE window limits (KVM final authority — advisory-only model).
 * BPF may suggest any value; KVM clamps to this range.
 */
#define KVM_BPF_PLE_MIN	32U
#define KVM_BPF_PLE_MAX	2048U

/* ── Debugfs interface ───────────────────────────────────────── */

static struct dentry *kvm_bpf_debugfs_dir;

/*
 * Write a BPF program fd to attach the PLE policy hook.
 * Write 0 (or any negative value) to detach.
 *
 * Usage:
 *   # Attach: echo 42 > /sys/kernel/debug/kvm-bpf/ple_prog
 *   # Detach: echo 0 > /sys/kernel/debug/kvm-bpf/ple_prog
 */
static ssize_t ple_prog_write(struct file *file, const char __user *ubuf,
			      size_t len, loff_t *ppos)
{
	struct bpf_prog *old, *new = NULL;
	int fd;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtoint_from_user(ubuf, len, 10, &fd);
	if (ret)
		return ret;

	if (fd > 0) {
		new = bpf_prog_get(fd);
		if (IS_ERR(new))
			return PTR_ERR(new);

		if (new->type != BPF_PROG_TYPE_KVM_SCHED) {
			bpf_prog_put(new);
			return -EINVAL;
		}
	}
	/* fd <= 0 → detach (new stays NULL) */

	mutex_lock(&ple_prog_mutex);
	old = rcu_replace_pointer(kvm_bpf_ple_prog, new, mutex_is_locked(&ple_prog_mutex));
	mutex_unlock(&ple_prog_mutex);

	/* Update static key and hook-loaded flag */
	kvm_bpf_ple_hook_loaded = (new != NULL);
	static_branch_enable(&kvm_bpf_enabled_key);

	if (old) {
		/* Wait for existing RCU readers to finish */
		synchronize_rcu();
		bpf_prog_put(old);
	}

	/* If no programs remain loaded, disable the static key */
	if (!kvm_bpf_ple_hook_loaded && !kvm_bpf_spin_hook_loaded &&
	    !kvm_bpf_yield_hook_loaded)
		static_branch_disable(&kvm_bpf_enabled_key);

	return len;
}

static const struct file_operations ple_prog_fops = {
	.write	= ple_prog_write,
	.llseek = noop_llseek,
};

/* ── Context builder ─────────────────────────────────────────── */

/*
 * Build BPF context from current vCPU state.
 * Called before invoking a hook; the context is read-only for BPF programs.
 * PLE-specific fields are computed here to reduce per-hook overhead.
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

/* ── Hook implementations ────────────────────────────────────── */

/*
 * PLE window hook: called when KVM is about to determine the PLE window.
 *
 * Hook-first design: KVM calls the registered BPF program and uses
 * its return value as an advisory suggestion. KVM retains final authority
 * by clamping the result to [KVM_BPF_PLE_MIN, KVM_BPF_PLE_MAX].
 *
 * Returns: suggested PLE window (0 = use KVM's default).
 *          KVM clamps non-zero results to [32, 2048].
 */
u32 kvm_bpf_get_ple_window(struct kvm_vcpu *vcpu, u32 current_window)
{
	struct bpf_prog *prog;
	struct kvm_bpf_ctx ctx;
	u32 suggested;

	if (!static_branch_unlikely(&kvm_bpf_enabled_key))
		return 0;

	rcu_read_lock();

	prog = rcu_dereference(kvm_bpf_ple_prog);
	if (!prog) {
		rcu_read_unlock();
		return 0;
	}

	kvm_bpf_build_ctx(vcpu, &ctx);
	ctx.current_ple_window = current_window;

	/* Run the BPF program; return value is the suggested window */
	suggested = bpf_prog_run(prog, &ctx);

	rcu_read_unlock();

	if (suggested == 0)
		return 0;			/* BPF defers to KVM default */

	/* Advisory-only: KVM clamps to safe range */
	suggested = clamp(suggested, KVM_BPF_PLE_MIN, KVM_BPF_PLE_MAX);

	return suggested;
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

/* ── BPF verifier ops ────────────────────────────────────────── */

/*
 * Context access verification for BPF_PROG_TYPE_KVM_SCHED.
 *
 * BPF programs may read any field of struct kvm_bpf_ctx.
 * All fields are read-only; writes are rejected by the verifier.
 * Offset and alignment are validated against the struct layout.
 */
static bool kvm_bpf_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	/* Only read access */
	if (type != BPF_READ)
		return false;

	/* Must be within context bounds */
	if (off < 0 || off + size > sizeof(struct kvm_bpf_ctx))
		return false;

	/* Must be naturally aligned */
	if (off % size != 0)
		return false;

	/* Switch on offset to validate individual field access.
	 * The verifier tracks these to ensure safe memory operations.
	 * All fields are readable; we just verify the boundaries.
	 */
	switch (off) {
	case offsetof(struct kvm_bpf_ctx, vm_id):
	case offsetof(struct kvm_bpf_ctx, vcpu_id):
	case offsetof(struct kvm_bpf_ctx, cpu):
	case offsetof(struct kvm_bpf_ctx, numa_node):
	case offsetof(struct kvm_bpf_ctx, exit_reason):
	case offsetof(struct kvm_bpf_ctx, current_ple_window):
		/* u32 fields: 4-byte access */
		if (size != 4)
			return false;
		break;

	case offsetof(struct kvm_bpf_ctx, timestamp_ns):
	case offsetof(struct kvm_bpf_ctx, ple_exits):
	case offsetof(struct kvm_bpf_ctx, total_exits):
	case offsetof(struct kvm_bpf_ctx, yield_attempts):
	case offsetof(struct kvm_bpf_ctx, yield_successes):
		/* u64 fields: 8-byte access */
		if (size != 8)
			return false;
		break;

	default:
		return false;
	}

	return true;
}

static const struct bpf_verifier_ops kvm_bpf_verifier_ops = {
	.is_valid_access	= kvm_bpf_is_valid_access,
};

const struct bpf_prog_ops kvm_bpf_prog_ops = {
	.test_run		= NULL,	/* Phase 1: no test_run yet */
};

/* ── Module init/exit ────────────────────────────────────────── */

static int __init kvm_bpf_init(void)
{
	struct dentry *file;

	if (!kvm_bpf_enable)
		return 0;

	pr_info("KVM-BPF: programmable hypervisor coordination framework loaded (disabled)\n");
	pr_info("KVM-BPF: load a BPF policy via /sys/kernel/debug/kvm-bpf/ple_prog\n");

	/* Create debugfs directory */
	kvm_bpf_debugfs_dir = debugfs_create_dir("kvm-bpf", NULL);
	if (IS_ERR_OR_NULL(kvm_bpf_debugfs_dir)) {
		pr_warn("KVM-BPF: failed to create debugfs directory, continuing without debugfs\n");
		kvm_bpf_debugfs_dir = NULL;
		return 0;
	}

	file = debugfs_create_file("ple_prog", 0200, kvm_bpf_debugfs_dir,
				   NULL, &ple_prog_fops);
	if (IS_ERR_OR_NULL(file))
		pr_warn("KVM-BPF: failed to create ple_prog debugfs file\n");

	return 0;
}

static void __exit kvm_bpf_exit(void)
{
	struct bpf_prog *prog;

	/* Detach any loaded BPF program */
	mutex_lock(&ple_prog_mutex);
	prog = rcu_replace_pointer(kvm_bpf_ple_prog, NULL,
				   mutex_is_locked(&ple_prog_mutex));
	mutex_unlock(&ple_prog_mutex);

	if (prog) {
		synchronize_rcu();
		bpf_prog_put(prog);
	}

	debugfs_remove_recursive(kvm_bpf_debugfs_dir);

	pr_info("KVM-BPF: unloaded\n");
}

module_init(kvm_bpf_init);
module_exit(kvm_bpf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sebastian");
MODULE_DESCRIPTION("KVM-BPF: Programmable Hypervisor Coordination with eBPF");
