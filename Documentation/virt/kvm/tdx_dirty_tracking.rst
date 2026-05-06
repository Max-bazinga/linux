.. SPDX-License-Identifier: GPL-2.0

==============================================
TDX Dirty Page Tracking Accelerator (tdx_dirty)
==============================================

:Copyright: 2026
:Authors: Hermes Agent (concept & prototype)

Overview
========

Intel TDX (Trust Domain Extensions) presents a unique challenge for KVM
live migration: the VMM cannot write-protect private guest pages in the
Secure EPT (SEPT) tables. All private pages are always mapped RWX,
making traditional dirty-bit-based tracking impossible.

This module keeps the dirty-log correctness source separate from the
performance hints:

- **Direction 1**: Trusted hardware batch scanning, once a ratified
  TDX module dirty-scan ABI is wired in, with concurrent multi-range
  workqueue dispatch.
- **Direction 2**: Heuristic hot-page prediction using page type
  classification, AUG tracking, and temporal decay.  This is a hint
  source only.

The KVM dirty bitmap must not have false negatives.  Hardware scan results
may provide the correctness bitmap.  Heuristics may add conservative false
positives or drive transmission priority, but must never mark a page clean.
If trusted hardware scan is unavailable or fails, the whole private memslot
is marked dirty.

Architecture
============

::

   +---------------------------------------------------------------+
   |                    tdx_sync_dirty_log()                       |
   |                (KVM dirty-log correctness path)               |
   +----------------------------+----------------------------------+
                                |
              +-----------------+------------------+
              |                                    |
   +---------v----------+              +-----------v-----------+
   |  Direction 1       |              |  Direction 2          |
   |  Hardware Scanner  |     +------->|  Heuristic Predictor  |
   |                    |     |        |                       |
   |  TDH_MEM_PAGE_SCAN |     |        |  Page Type Classifier |
   |  Batch Batching    |     |        |  AUG History Tracking |
   |  Concurrent WQs    |     |        |  Temporal LRU Decay   |
   +--------------------+     |        +-----------------------+
                              |
   +--------------------------v----------------------------------+
   |              tdx_hybrid_collect()                            |
   |  Phase 1: trusted HW scan                                   |
   |  Phase 2: OR heuristic hot-page hints only                  |
   |  Phase 3: never clear scan-confirmed dirty pages            |
   +-------------------------------------------------------------+

Direction 1: Batch HW Scan
===========================

Trusted SEAMCALL ABI
--------------------

The current code does not enable hardware scanning until a ratified TDX
module ABI is available.  A guessed leaf number or register layout is not
safe for live migration because an ABI mismatch can create false negatives.
The scan implementation must be replaced with a wrapper matching the final
TDX module specification, including the target TD context.

Prototype Leaf: TDH_MEM_PAGE_SCAN (Leaf 46)
-------------------------------------------

The following is retained as prototype documentation only and must not be
treated as a stable ABI:

:Input:
  - ``RCX``: Start GPA
  - ``RDX``: End GPA (exclusive)
  - ``R8``:  Max pages to scan per call
  - ``R9``:  Physical address of output bitmap
:Output:
  - ``RCX``: Next GPA to scan (for partial results)
  - ``RDX``: Actual end GPA scanned
  - Bitmap:  1 bit per 4KB page (set = dirty)
:Returns: ``TDX_SCAN_DONE`` (0), ``TDX_SCAN_PARTIAL`` (1),
          ``TDX_SCAN_BUSY`` (2), or error code

Batching
--------
A single SEAMCALL scans up to 512 pages at once (``TDX_SCAN_BATCH_MAX_PAGES``).
Larger ranges are split into batches. Each batch allocates a temporary
bitmap, calls the SEAMCALL, merges into the main result bitmap, then
frees the temporary bitmap.

Concurrent Scanning
-------------------
The GPA range is divided into ``nr_workers`` chunks and dispatched via
``alloc_workqueue()`` with ``WQ_UNBOUND | WQ_HIGHPRI``. Workers run in
parallel across available CPUs. Results are merged after all workers
complete via ``flush_workqueue()``.

Direction 2: Heuristic Hot-Page Hints
=====================================

Page Type Classification
------------------------
Based on typical x86_64 Linux guest address layout:

- **Code** (GPA < 0x20000000): Rarely dirty after loading.
  Skipped unless AUG activity detected.
- **Heap** (0x20000000 <= GPA < 0x80000000): Most frequently
  written. Highest prediction priority.
- **Stack** (GPA >= 0x7f00000000): Moderately written.
  Moderate prediction priority.

AUG Event Tracking
-------------------
The only observable signal from the VMM side is ``TDH_MEM_PAGE_AUG`` —
the guest allocating a new private page. Each AUG event marks the
corresponding 4MB region as "recently touched" in a compressed
history bitmap.

Scoring Model
-------------
Each page's dirty probability is computed as::

  score = freq_score * 40 + recency_score * 35 + type_score * 25

Where all sub-scores are normalized to 0-255. Pages scoring above
``dirty_threshold`` (default: 128) are flagged as hot-page hints.  These
hints may increase priority or add false-positive dirty bits, but they are
not a correctness dirty log.

Temporal Decay
--------------
History entries decay on every scan pass. Entries with scores below
``dirty_threshold / 2`` are cleared, preventing stale predictions.

Conservative Dirty Collection
=============================

Pre-copy Iteration Strategy
----------------------------

If trusted hardware scan is unavailable, every sync marks the entire private
memslot dirty.  Once trusted scan is available, the scan result is copied to
the dirty bitmap and heuristics are allowed only to OR additional bits.
No heuristic path is allowed to clear a page from the dirty bitmap.

Priority Tiers
--------------
- **Tier 0** (Correctness): HW-confirmed dirty, once a trusted scan ABI is
  wired in.
- **Tier 1** (Hint): Heuristic hot pages.  These may be sent earlier or added
  as false positives.
- **Tier 2** (Fallback): All remaining pages when scan is unavailable or
  fails.

Performance Expectations
========================

+------------------------+------------+------------+------------+
| Metric                 | Standard   | TDX (no    | TDX (with  |
|                        | KVM        | tracking)  | tdx_dirty) |
+========================+============+============+============+
| Pre-copy convergence   | 3-5 rounds | full-slot  | depends on |
|                        |            | dirty      | trusted    |
|                        |            | fallback   | scan ABI   |
| Per-round data (4GB VM)| ~100MB     | ~4GB       | scan result|
| Total data transferred | ~300MB     | high       | workload   |
| Stop-copy downtime     | ~100ms     | high       | dependent  |
+------------------------+------------+------------+------------+

Integration Points
==================

1. Hook ``tdx_dirty_record_aug()`` into ``tdx_sept_set_private_spte()``
2. Use ``tdx_sync_dirty_log()`` from the x86 vendor dirty-log callback
3. Keep all-dirty fallback until the trusted TDX scan wrapper is implemented

Configuration
=============

Module parameters (via ``/sys/module/kvm_intel/parameters/``)::

  tdx_dirty_enable      - Enable TDX dirty tracking accelerator (default: 1)
  tdx_dirty_workers     - Number of concurrent scan workers (default: 2)
  tdx_dirty_batch       - Pages per SEAMCALL batch (default: 512)
  tdx_dirty_threshold   - Heuristic score threshold (default: 128)
  tdx_dirty_heuristic   - Enable heuristic prediction (default: 1)

Files
=====

::

  arch/x86/kvm/vmx/tdx_dirty.h   - Data structures and API declarations
  arch/x86/kvm/vmx/tdx_dirty.c   - Core implementation
  Documentation/virt/kvm/tdx_dirty_tracking.rst - This document
