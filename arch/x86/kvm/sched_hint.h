/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kvm_sched_hint — vCPU scheduling event abstraction
 *
 * Copyright (C) 2026, Nous Research
 *
 * This header defines the types and API for the KVM scheduling hint
 * framework, which unifies PLE exits, HLT exits, and PV sched-yield
 * hypercalls into a common event pipeline with lightweight policy
 * and safety net.
 */

#ifndef __KVM_SCHED_HINT_H
#define __KVM_SCHED_HINT_H

#include <linux/types.h>

/* Event sources that feed into the scheduling hint pipeline */
enum kvm_sched_event_type {
	KVM_SCHED_EVT_PLE,		/* PAUSE-loop exit (PLE) */
	KVM_SCHED_EVT_HLT,		/* HLT instruction exit */
	KVM_SCHED_EVT_PV_YIELD,	/* PV sched-yield hypercall */
	NR_KVM_SCHED_EVT,
};

/* Actions the policy may recommend */
enum kvm_sched_action {
	KVM_SCHED_ACT_NONE = 0,	/* no special action */
	KVM_SCHED_ACT_YIELD,		/* yield to another vCPU */
	KVM_SCHED_ACT_PAUSE_VCPU,	/* pause this vCPU briefly */
	KVM_SCHED_ACT_WARN,		/* log warning, take no action */
	NR_KVM_SCHED_ACT,
};

/* Safety net guard levels */
enum kvm_sched_guard_level {
	KVM_SCHED_GUARD_OK = 0,	/* normal operation */
	KVM_SCHED_GUARD_RATE_LIMIT,	/* throttle policy application */
	KVM_SCHED_GUARD_DISABLE,	/* disable policy for this vCPU */
};

/* Per-vCPU scheduling hint statistics */
struct kvm_sched_hint_stats {
	/* Event counts */
	u64 events[NR_KVM_SCHED_EVT];
	/* Yield tracking */
	u64 yield_attempts;
	u64 yield_success;
	u64 yield_miss;
	/* Guard state */
	enum kvm_sched_guard_level guard_level;
	u64 guard_trigger_count;
	unsigned int consecutive_bad_windows;
	/* Rate tracking (EMAs) */
	unsigned long ple_rate_ema;		/* PLE exits/sec * 100 */
	unsigned long steal_time_ema;		/* steal time pct * 100 */
	unsigned long yield_miss_rate_ema;	/* yield miss rate * 100 */
	unsigned long last_sample_jiffies;
};

/* Policy configuration (module parameters) */
struct kvm_sched_hint_config {
	unsigned int policy;		/* 0=off, 1=basic */
	unsigned int ple_rate_threshold;	/* PLE/s * 100 threshold */
	unsigned int guard_ple_rate_limit;	/* PLE/s * 100 for guard */
	unsigned int guard_yield_miss_pct;	/* yield miss % * 100 */
	unsigned int guard_steal_low_pct;	/* steal time % * 100 */
	unsigned int sample_interval_ms;	/* sampling window (ms) */
	unsigned int guard_windows;		/* consecutive windows to trip */
};

#ifdef CONFIG_KVM_X86

int kvm_sched_hint_init(struct kvm_vcpu *vcpu);
void kvm_sched_hint_destroy(struct kvm_vcpu *vcpu);
enum kvm_sched_action kvm_sched_event(struct kvm_vcpu *vcpu,
				      enum kvm_sched_event_type type);

#endif /* CONFIG_KVM_X86 */

#endif /* __KVM_SCHED_HINT_H */
