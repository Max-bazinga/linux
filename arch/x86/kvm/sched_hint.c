// SPDX-License-Identifier: GPL-2.0
/*
 * kvm_sched_hint — vCPU scheduling event abstraction
 *
 * Unifies PLE exits, HLT exits, and PV sched-yield hypercalls
 * into a common event pipeline with lightweight policy.
 *
 * Copyright (C) 2026, Nous Research
 */

#include <linux/kvm_host.h>
#include <linux/sched/stat.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "trace.h"
#include "sched_hint.h"

/*
 * Module parameters — base configuration with safety net guard.
 */
static unsigned int sched_policy = 1;	/* 0=off, 1=basic */
module_param(sched_policy, uint, 0644);

static unsigned int ple_rate_threshold = 10000;	/* PLE/s * 100 */
module_param(ple_rate_threshold, uint, 0644);

static unsigned int sample_interval_ms = 100;	/* 100ms sampling window */
module_param(sample_interval_ms, uint, 0644);

/* Safety net guard thresholds */
static unsigned int guard_ple_rate_limit = 50000;	/* PLE/s * 100 */
module_param(guard_ple_rate_limit, uint, 0644);

static unsigned int guard_yield_miss_pct = 5000;	/* yield miss % * 100 (50%) */
module_param(guard_yield_miss_pct, uint, 0644);

static unsigned int guard_steal_low_pct = 1000;		/* steal time % * 100 (10%)  */
module_param(guard_steal_low_pct, uint, 0644);

static unsigned int guard_windows = 5;			/* consecutive bad windows */
module_param(guard_windows, uint, 0644);

/*
 * EMA alpha factor.  Higher = more weight on recent samples.
 * new_ema = (old_ema * (256 - alpha) + sample * alpha) >> 8
 */
#define SCHED_HINT_EMA_ALPHA	32

static inline unsigned long sched_ema_update(unsigned long old_ema,
					     unsigned long sample)
{
	return (old_ema * (256 - SCHED_HINT_EMA_ALPHA) +
		sample * SCHED_HINT_EMA_ALPHA) >> 8;
}

static bool is_overcommitted(struct kvm *kvm)
{
	unsigned long online_vcpus = atomic_read(&kvm->online_vcpus);
	unsigned long online_cpus = num_online_cpus();

	return online_vcpus > online_cpus;
}

static void sched_sample_stats(struct kvm_vcpu *vcpu,
			       struct kvm_sched_hint_stats *stats)
{
	unsigned long now = jiffies;
	unsigned long delta = now - stats->last_sample_jiffies;
	unsigned long delta_ms;
	unsigned long ple_rate, steal_time, yield_miss_pct;

	if (!delta)
		return;

	delta_ms = jiffies_to_msecs(delta);

	/* Rate computations (events per second * 100) */
	ple_rate = stats->events[KVM_SCHED_EVT_PLE] * 100000UL / delta_ms;
	steal_time = 0; /* Filled by tracepoint/steal_time_msr in later patches */
	yield_miss_pct = stats->yield_attempted ?
		(stats->yield_miss * 10000UL / stats->yield_attempted) : 0;

	/* Update EMAs */
	stats->ple_rate_ema = sched_ema_update(stats->ple_rate_ema, ple_rate);
	stats->steal_time_ema = sched_ema_update(stats->steal_time_ema,
						  steal_time);
	stats->yield_miss_rate_ema = sched_ema_update(stats->yield_miss_rate_ema,
						       yield_miss_pct);

	stats->last_sample_jiffies = now;
}

/*
 * sched_guard_check — safety net guard against pathological spin
 *
 * Examines per-vCPU EMA rates and detects abnormal spin patterns:
 *   (1) PLE exits above threshold    → excessive contention
 *   (2) Steal time below threshold   → vCPU not actually preempted
 *   (3) Yield miss rate above threshold → yields failing
 *
 * When all three conditions persist for @guard_windows consecutive
 * sampling windows, the guard escalates:
 *   OK → RATE_LIMIT (throttle policy)
 *   RATE_LIMIT sustained → DISABLE (kill policy for this vCPU)
 *
 * Returns the current guard level.
 */
static enum kvm_sched_guard_level
sched_guard_check(struct kvm_sched_hint_stats *stats)
{
	bool bad_pattern;

	bad_pattern = stats->ple_rate_ema > guard_ple_rate_limit &&
		      stats->steal_time_ema < guard_steal_low_pct &&
		      stats->yield_miss_rate_ema > guard_yield_miss_pct;

	if (bad_pattern) {
		stats->consecutive_bad_windows++;
	} else {
		/* Good window: decay the counter */
		if (stats->consecutive_bad_windows)
			stats->consecutive_bad_windows--;
		return KVM_SCHED_GUARD_OK;
	}

	if (stats->consecutive_bad_windows >= guard_windows) {
		if (stats->guard_level == KVM_SCHED_GUARD_OK) {
			stats->guard_level = KVM_SCHED_GUARD_RATE_LIMIT;
			stats->guard_trigger_count++;
		} else if (stats->guard_level == KVM_SCHED_GUARD_RATE_LIMIT) {
			/*
			 * Still bad after rate-limiting → disable
			 * policy entirely for this vCPU.
			 */
			stats->guard_level = KVM_SCHED_GUARD_DISABLE;
			stats->guard_trigger_count++;
		}
	}

	return stats->guard_level;
}

/*
 * kvm_sched_event — main entry point for scheduling events
 *
 * Called from VM-exit handlers (PLE, HLT, PV yield) to collect
 * statistics and apply lightweight scheduling policy.
 *
 * Returns an action recommendation for the caller.
 */
enum kvm_sched_action kvm_sched_event(struct kvm_vcpu *vcpu,
				      enum kvm_sched_event_type type)
{
	struct kvm_sched_hint_stats *stats;
	enum kvm_sched_action action = KVM_SCHED_ACT_NONE;

	if (!sched_policy)
		return KVM_SCHED_ACT_NONE;

	if (WARN_ON_ONCE(type >= NR_KVM_SCHED_EVT))
		return KVM_SCHED_ACT_NONE;

	stats = vcpu->arch.sched_hint_stats;
	if (unlikely(!stats))
		return KVM_SCHED_ACT_NONE;

	/* 1. Record the event */
	stats->events[type]++;

	/* 1a. Trace the event */
	trace_kvm_sched_event(vcpu->vcpu_id, type, stats->events[type]);

	/* 2. Periodic rate sampling */
	if (time_after(jiffies, stats->last_sample_jiffies +
		       msecs_to_jiffies(sample_interval_ms))) {
		sched_sample_stats(vcpu, stats);

		/* 2a. Safety net guard check */
		sched_guard_check(stats);

		/* 2b. Trace guard state when active */
		if (stats->guard_level != KVM_SCHED_GUARD_OK)
			trace_kvm_sched_guard(vcpu->vcpu_id,
					      stats->guard_level,
					      stats->ple_rate_ema,
					      stats->steal_time_ema,
					      stats->yield_miss_rate_ema);
	}

	/* 3. Check guard level */
	if (stats->guard_level == KVM_SCHED_GUARD_DISABLE)
		return KVM_SCHED_ACT_NONE;

	/* 4. Basic policy: PLE + overcommit -> yield */
	if (type == KVM_SCHED_EVT_PLE && is_overcommitted(vcpu->kvm))
		action = KVM_SCHED_ACT_YIELD;

	trace_kvm_sched_action(vcpu->vcpu_id, action, KVM_SCHED_ACT_NONE);

	return action;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_sched_event);

/*
 * kvm_sched_hint_init — allocate and initialize per-vCPU stats
 */
int kvm_sched_hint_init(struct kvm_vcpu *vcpu)
{
	struct kvm_sched_hint_stats *stats;

	stats = kzalloc(sizeof(*stats), GFP_KERNEL_ACCOUNT);
	if (!stats)
		return -ENOMEM;

	stats->last_sample_jiffies = jiffies;
	vcpu->arch.sched_hint_stats = stats;
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_sched_hint_init);

/*
 * kvm_sched_hint_destroy — free per-vCPU stats
 */
void kvm_sched_hint_destroy(struct kvm_vcpu *vcpu)
{
	kfree(vcpu->arch.sched_hint_stats);
	vcpu->arch.sched_hint_stats = NULL;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_sched_hint_destroy);
