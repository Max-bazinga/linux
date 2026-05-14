.. SPDX-License-Identifier: GPL-2.0

=======================================
KVM Scheduling Hint (kvm_sched_hint)
=======================================

Overview
========

The scheduling hint framework (``kvm_sched_hint``) unifies three vCPU
scheduling exit sources — PLE exits (``PAUSE``-loop exiting), HLT exits,
and PV sched-yield hypercalls — into a common event pipeline with
lightweight policy and a graded safety net.

The primary goal is to detect overcommit contention patterns early and
recommend the appropriate action (yield, rate-limit, or disable) without
requiring guest modifications or new hypercalls.

Architecture
============

::

  vCPU exits (PLE/HLT/PV yield)
          │
          ▼
  kvm_sched_event(type)         ← Entry point (sched_hint.c)
          │
          ├── 1. Record event counter
          ├── 2. Periodic EMA rate sampling (every sample_interval_ms)
          ├── 3. Safety net guard check (sched_guard_check)
          │        │
          │        ├── OK        → continue
          │        ├── RATE_LIMIT → throttle policy
          │        └── DISABLE   → return NONE
          │
          └── 4. Basic policy (PLE + overcommit → YIELD)
                    │
                    ▼
          Action: NONE | YIELD
                    │
                    ▼
          Caller (handle_pause, etc.) acts on recommendation

Module Parameters
=================

Base configuration:

=========================== ======== =========================================
Parameter                   Default  Description
=========================== ======== =========================================
sched_policy                1        0=off, 1=basic
ple_rate_threshold          10000    PLE/s * 100 threshold for policy
sample_interval_ms          100      Rate sampling window (ms)
guard_ple_rate_limit        50000    PLE/s * 100 for guard detection
guard_yield_miss_pct        5000     Yield miss % * 100 (50%)
guard_steal_low_pct         1000     Steal time % * 100 (10%)
guard_windows               5        Consecutive bad windows to escalate
=========================== ======== =========================================

All parameters are writable via ``/sys/module/kvm/parameters/`` at runtime.

Safety Net Guard
================

The guard detects abnormal spin patterns where the basic policy would
cause thrashing rather than help.  Three conditions must hold
simultaneously:

1. PLE rate > ``guard_ple_rate_limit`` (excessive contention)
2. Steal time < ``guard_steal_low_pct`` (vCPU not actually preempted)
3. Yield miss rate > ``guard_yield_miss_pct`` (yields are failing)

When all three persist for ``guard_windows`` consecutive sampling windows,
the guard escalates:

  OK
    → RATE_LIMIT (throttle policy application)
    → DISABLE (per-vCPU policy disabled entirely)

On good windows the bad-window counter decays by 1.

Debugfs Interface
=================

Each vCPU with allocated scheduling hint stats exposes a ``sched-hint``
file under its debugfs directory::

  /sys/kernel/debug/kvm/<vm>-<vcpu>/sched-hint

Example output::

  ple_events       12345
  hlt_events       5678
  pv_yield_events  9012
  yield_attempts   345
  yield_success    120
  yield_miss       225
  guard_level      0
  guard_triggers   0
  bad_windows      0
  ple_rate_ema     15000
  steal_time_ema   500
  yield_miss_ema   6520

Tracepoints
===========

Three tracepoints are available under the ``kvm`` system:

- ``kvm_sched_event``: every recorded event (vcpu_id, type, count)
- ``kvm_sched_action``: action returned to caller (vcpu_id, action, prev)
- ``kvm_sched_guard``: guard activation (vcpu_id, level, EMAs)

Usage::

  # perf top -e kvm:kvm_sched_event
  # perf record -e kvm:kvm_sched_guard -a

Insertion Points
================

+---------------------+-------------------+-------------------------------+
| Source              | Handler           | Event type                    |
+=====================+===================+===============================+
| PLE (PAUSE loop)    | vmx:handle_pause  | ``KVM_SCHED_EVT_PLE``         |
+---------------------+-------------------+-------------------------------+
| HLT instruction     | x86:__kvm_emu...  | ``KVM_SCHED_EVT_HLT``         |
+---------------------+-------------------+-------------------------------+
| PV sched-yield      | x86:kvm_sched...  | ``KVM_SCHED_EVT_PV_YIELD``    |
+---------------------+-------------------+-------------------------------+

Lifecycle
=========

- ``kvm_sched_hint_init()``: called from ``kvm_arch_vcpu_create()``.
  Allocates and zeroes a per-vCPU ``kvm_sched_hint_stats`` struct.
- ``kvm_sched_hint_destroy()``: called from ``kvm_arch_vcpu_destroy()``.
  Frees the per-vCPU stats.
