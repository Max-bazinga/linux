// SPDX-License-Identifier: GPL-2.0
/*
 * TDX Dirty Page Tracking Accelerator
 *
 * Combines trusted hardware dirty scanning, once a ratified TDX module ABI is
 * wired in, with heuristic hot-page hints for accelerated TDX VM live
 * migration.
 *
 * === Architecture ===
 *
 * Standard dirty tracking requires VMM to write-protect pages and trap
 * writes. TDX private pages are ALWAYS mapped RWX in SEPT (Secure EPT)
 * tables — the VMM cannot set read-only to detect writes. This means
 * the standard approach fails for TDX private memory.
 *
 * This module provides TWO complementary approaches:
 *
 * Direction 1 — Batch HW Scan:
 *   Uses a trusted TDX module dirty-scan ABI to query dirtied private pages.
 *   Until such ABI is wired in, dirty-log sync falls back to marking the
 *   entire private memslot dirty.
 *
 * Direction 2 — Heuristic Hints:
 *   Predict hot pages for priority only, based on:
 *     • Write frequency: Track page allocation (AUG) frequency
 *     • Page type: Code vs Heap vs Stack have different dirty patterns
 *     • Temporal locality: Recently allocated pages more likely dirty
 *     • LRU decay: Older untouched pages deprioritized
 *
 * Hybrid Mode:
 *   Hardware scan is the dirty-log truth source. Heuristics may only add
 *   conservative false positives or priority hints; they must not clear pages
 *   from the dirty bitmap.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/kvm_host.h>
#include <asm/tdx.h>

#include "tdx.h"
#include "tdx_dirty.h"
#include "x86_ops.h"

/* ─────────────────────────────────────────────
 * Direction 1: TDH_MEM_PAGE_SCAN Infrastructure
 * ───────────────────────────────────────────── */

/*
 * Detect TDX module support for private page dirty scanning.
 *
 * The scan ABI must be wired through a ratified TDX module interface before
 * it can be used as a dirty-log correctness source.  Do not probe a guessed
 * leaf number here: an unsupported or mismatched SEAMCALL ABI could produce
 * false negatives, which would corrupt live migration.
 */
static bool tdx_scan_available(void)
{
	return false;
}

/*
 * Execute single TDH_MEM_PAGE_SCAN batch.
 *
 * Parameters:
 *   td      - Target TD handle
 *   gpa     - Starting GPA (SEAMCALL input)
 *   end_gpa - End GPA (exclusive)
 *   bitmap  - Output bitmap buffer (bit per 4KB page)
 *   max_cnt - Max pages to scan this call
 *
 * Returns:
 *   Number of pages scanned (with bitmap filled), or negative error.
 *   Partial results are valid — caller should continue from returned GPA.
 */
struct tdx_scan_result {
	u64	next_gpa;	/* Resume point for partial scan */
	int	scanned;	/* Number of pages scanned */
	int	dirty;		/* Number of dirty pages found */
};

static int tdx_seamcall_scan(struct kvm_tdx *kvm_tdx,
			     u64 gpa, u64 end_gpa,
			     unsigned long *bitmap,
			     unsigned int max_pages,
			     struct tdx_scan_result *out)
{
	struct tdx_module_args args = {};
	int retries = 3;
	u64 err;

	/* Short-circuit for empty range */
	if (gpa >= end_gpa)
		return 0;

	args.rcx = gpa;
	args.rdx = end_gpa;
	args.r8  = max_pages;
	args.r9  = __pa(bitmap);

	do {
		err = __seamcall_ret(TDH_MEM_PAGE_SCAN, &args);

		if (err == TDX_SCAN_BUSY) {
			/* HW busy, retry with exponential backoff */
			usleep_range(10, 100);
			continue;
		}

		break;
	} while (--retries > 0);

	if (err != TDX_SCAN_DONE && err != TDX_SCAN_PARTIAL) {
		pr_debug("TDX: TDH_MEM_PAGE_SCAN failed: gpa=0x%llx err=0x%llx\n",
			 gpa, err);
		return -EIO;
	}

	out->next_gpa = args.rcx;	/* Resume GPA */
	out->scanned  = (int)(args.rdx - gpa) >> PAGE_SHIFT;
	out->dirty    = bitmap_weight(bitmap, out->scanned);

	return err;
}

/*
 * Scan a GPA range with batched SEAMCALLs.
 * Splits the range into batch-size chunks and calls TDH_MEM_PAGE_SCAN
 * sequentially (use tdx_dirty_concurrent_scan for parallel).
 */
static int tdx_scan_range_batched(struct kvm_tdx *kvm_tdx,
				   u64 gpa_start, u64 gpa_end,
				   unsigned long *bitmap,
				   unsigned int batch_pages)
{
	u64 gpa = gpa_start;
	unsigned long nr_range_pages = (gpa_end - gpa_start) >> PAGE_SHIFT;
	unsigned int local_batch = min_t(unsigned int,
					 batch_pages ?: TDX_SCAN_BATCH_MAX_PAGES,
					 TDX_SCAN_BATCH_MAX_PAGES);
	int total_scanned = 0, total_dirty = 0;
	struct tdx_scan_result res;

	local_batch = min_t(unsigned int, local_batch, nr_range_pages);

	while (gpa < gpa_end) {
		unsigned long *batch_bitmap;
		unsigned int this_batch;
		int ret;

		this_batch = min_t(unsigned int, local_batch,
				   (gpa_end - gpa) >> PAGE_SHIFT);

		/* Allocate temporary bitmap for this batch */
		batch_bitmap = bitmap_zalloc(this_batch, GFP_KERNEL);
		if (!batch_bitmap)
			return -ENOMEM;

		ret = tdx_seamcall_scan(kvm_tdx, gpa,
					gpa + (this_batch << PAGE_SHIFT),
					batch_bitmap, this_batch, &res);
		if (ret < 0) {
			bitmap_free(batch_bitmap);
			/*
			 * If single batch fails but we have partial results,
			 * continue rather than abort the entire scan.
			 */
			if (total_scanned == 0)
				return ret;
			break;
		}

		/* Merge batch bitmap into main bitmap */
		{
			unsigned int page_offset = (gpa - gpa_start) >> PAGE_SHIFT;
			unsigned int bit;

			for_each_set_bit(bit, batch_bitmap, this_batch)
				__set_bit(page_offset + bit, bitmap);
		}

		total_scanned += res.scanned;
		total_dirty   += res.dirty;

		bitmap_free(batch_bitmap);

		/* Advance to next GPA */
		if (res.next_gpa > gpa && res.next_gpa <= gpa_end)
			gpa = res.next_gpa;
		else
			gpa += this_batch << PAGE_SHIFT;

		/* Cond_resched() to avoid soft lockups on large scans */
		cond_resched();
	}

	return total_dirty;
}

/* ─────────────────────────────────────────────
 * Direction 1: Concurrent Scanning (Workqueues)
 * ───────────────────────────────────────────── */

static void tdx_scan_work_fn(struct work_struct *work)
{
	struct tdx_scan_work *sw = container_of(work, struct tdx_scan_work, work);
	struct kvm_tdx *kvm_tdx = sw->kvm_tdx;

	sw->dirty_count = tdx_scan_range_batched(
		kvm_tdx, sw->gpa_start, sw->gpa_end,
		sw->dirty_bitmap, TDX_SCAN_BATCH_MAX_PAGES);

	if (sw->dirty_count < 0)
		sw->result = sw->dirty_count;
	else
		sw->result = 0;
}

int tdx_dirty_scan_range(struct tdx_dirty_tracker *tracker,
			 u64 gpa_start, u64 gpa_end,
			 unsigned long *bitmap, unsigned long nr_pages)
{
	if (!tracker->scan_available)
		return -ENOTSUPP;

	return tdx_scan_range_batched(tracker->kvm_tdx,
				      gpa_start, gpa_end,
				      bitmap, tracker->scan_cfg.batch_pages);
}

int tdx_dirty_concurrent_scan(struct tdx_dirty_tracker *tracker,
			      u64 gpa_start, u64 gpa_end,
			      unsigned long *bitmap, unsigned long nr_pages)
{
	struct kvm_tdx *kvm_tdx = tracker->kvm_tdx;
	u64 total_size = gpa_end - gpa_start;
	unsigned int nr_workers;
	unsigned long chunk_size;
	int ret = 0;

	if (!tracker->scan_available)
		return -ENOTSUPP;

	if (!tracker->scan_cfg.concurrent_enabled || nr_pages <= 8192)
		/* Small range: skip concurrency overhead */
		return tdx_scan_range_batched(kvm_tdx, gpa_start, gpa_end,
					      bitmap, tracker->scan_cfg.batch_pages);

	nr_workers = min_t(unsigned int, tracker->scan_cfg.nr_workers,
			   num_online_cpus());
	if (!nr_workers)
		return -EINVAL;

	chunk_size = total_size / nr_workers;
	chunk_size = ALIGN(chunk_size, PAGE_SIZE);
	{
		struct tdx_scan_work **works;
		int total_dirty = 0;
		int j;

		works = kcalloc(nr_workers, sizeof(*works), GFP_KERNEL);
		if (!works)
			return -ENOMEM;

		for (j = 0; j < nr_workers; j++) {
			u64 cstart = gpa_start + j * chunk_size;
			u64 cend   = (j == nr_workers - 1) ? gpa_end
				 : min(gpa_start + (j + 1) * chunk_size, gpa_end);
			unsigned long cpages = (cend - cstart) >> PAGE_SHIFT;
			unsigned long goff = (cstart - gpa_start) >> PAGE_SHIFT;

			works[j] = kzalloc(sizeof(*works[j]), GFP_KERNEL);
			if (!works[j]) {
				ret = -ENOMEM;
				goto out_flush;
			}

			INIT_WORK(&works[j]->work, tdx_scan_work_fn);
			works[j]->kvm_tdx = kvm_tdx;
			works[j]->gpa_start = cstart;
			works[j]->gpa_end   = cend;
			works[j]->dirty_bitmap = bitmap_zalloc(cpages,
								GFP_KERNEL);
			if (!works[j]->dirty_bitmap) {
				ret = -ENOMEM;
				goto out_flush;
			}
			works[j]->nr_pages = cpages;
			works[j]->page_offset = goff;

			queue_work(tracker->scan_wq, &works[j]->work);
		}

		/* Wait for all workers to complete */
		flush_workqueue(tracker->scan_wq);

		/* Collect results */
		for (j = 0; j < nr_workers; j++) {
			if (works[j] && works[j]->result == 0) {
				unsigned long bit;

				total_dirty += works[j]->dirty_count;
				for_each_set_bit(bit, works[j]->dirty_bitmap,
						 works[j]->nr_pages)
					__set_bit(works[j]->page_offset + bit,
						  bitmap);
			} else if (works[j] && works[j]->result < 0) {
				ret = works[j]->result;
			}
		}

		atomic64_add(1, &tracker->total_scans);
		atomic64_add(nr_pages, &tracker->total_pages_scanned);
		atomic64_add(total_dirty, &tracker->total_dirty_found);

out_flush:
		if (ret)
			flush_workqueue(tracker->scan_wq);

out_cleanup:
		for (j = 0; j < nr_workers; j++) {
			if (works[j])
				bitmap_free(works[j]->dirty_bitmap);
			kfree(works[j]);
		}
		kfree(works);

		return ret < 0 ? ret : total_dirty;
	}
}

/* ─────────────────────────────────────────────
 * Direction 2: Heuristic Dirty Page Prediction
 * ───────────────────────────────────────────── */

/*
 * Classify GPA into page type based on typical guest address layout.
 *
 * x86_64 Linux guest memory layout (typical):
 *   0x00000000 - 0x20000000:  Kernel code/data (512MB)
 *   0x20000000 - 0x80000000:  Heap/mappings (2GB)
 *   0x80000000 - 0x7f00000000: Other mappings
 *   0x7f00000000+:            Stack, vDSO, etc.
 */
static enum tdx_page_type tdx_classify_gpa(struct tdx_dirty_tracker *tracker,
					   u64 gpa)
{
	u64 code_end = tracker->heur_cfg.code_region_end;
	u64 heap_end = tracker->heur_cfg.heap_region_end;

	if (gpa < code_end)
		return TDX_PAGE_CODE;

	if (gpa < heap_end)
		return TDX_PAGE_HEAP;

	if (gpa >= 0x7f00000000ULL)
		return TDX_PAGE_STACK;

	return TDX_PAGE_HEAP; /* Default: assume heap/data */
}

/*
 * Get history index for a GPA.
 * Compresses the GPA space into a fixed-size history array.
 */
static unsigned long tdx_gpa_to_history_idx(struct tdx_dirty_tracker *tracker,
					    u64 gpa)
{
	return (gpa >> tracker->history_shift) & (tracker->nr_history_entries - 1);
}

/*
 * Record a page allocation (AUG event).
 * This is the primary signal we can observe from the VMM side:
 * the guest just allocated a new private page via TDG.MEM.PAGE.AUG.
 */
void tdx_dirty_record_aug(struct tdx_dirty_tracker *tracker, u64 gpa)
{
	unsigned long flags;
	unsigned long idx;

	if (!tracker->heur_cfg.heuristic_enabled)
		return;

	idx = tdx_gpa_to_history_idx(tracker, gpa);

	spin_lock_irqsave(&tracker->lock, flags);

	/* Mark this region as recently touched */
	if (tracker->history_bitmap)
		__set_bit(idx, tracker->history_bitmap);

	spin_unlock_irqrestore(&tracker->lock, flags);
}

void tdx_dirty_notify_page_add(struct tdx_dirty_tracker *tracker, u64 gpa)
{
	tdx_dirty_record_aug(tracker, gpa);
}

/*
 * Compute hot-page score for one GPA range entry.
 *
 * Score = freq_score * freq_weight + recency_score * recency_weight
 *       + type_score * type_weight
 *
 * All scores normalized to 0-255.
 */
static unsigned int tdx_compute_page_score(
	struct tdx_dirty_tracker *tracker,
	u64 gpa,
	unsigned long epoch,
	enum tdx_page_type ptype,
	unsigned long history_entry)
{
	unsigned int score = 0;
	unsigned long idx;
	bool recent;

	idx = tdx_gpa_to_history_idx(tracker, gpa);

	/* ── Write frequency proxy ── */
	/* Higher score for pages with recent AUG activity */
	if (tracker->history_bitmap)
		recent = test_bit(idx, tracker->history_bitmap);
	else
		recent = false;

	if (recent)
		score += tracker->heur_cfg.freq_weight;

	/* ── Recency ── */
	/* Recently allocated pages are more likely dirty */
	if (recent)
		score += tracker->heur_cfg.recency_weight;

	/* ── Page type scoring ── */
	switch (ptype) {
	case TDX_PAGE_HEAP:
		/* Heap pages are most frequently written */
		score += tracker->heur_cfg.type_weight;
		break;
	case TDX_PAGE_STACK:
		/* Stack pages are moderately written */
		score += (tracker->heur_cfg.type_weight * 3) / 4;
		break;
	case TDX_PAGE_CODE:
		/* Code pages rarely change after loading */
		score += (tracker->heur_cfg.type_weight * 1) / 8;
		break;
	case TDX_PAGE_ACCEPTED:
		/* Freshly accepted — very likely to be written */
		score += tracker->heur_cfg.type_weight;
		break;
	default:
		score += tracker->heur_cfg.type_weight / 2;
		break;
	}

	return score;
}

/*
 * Heuristic collector - generate hot-page hints without HW scan.
 *
 * The output bitmap is a priority hint only.  It must not be used as the
 * correctness dirty log because the model can miss real guest writes.
 *
 * Policy:
 *   1. All code pages → rarely dirty, skip (unless recently AUGed)
 *   2. Heap/stack pages with recent AUG → high priority
 *   3. Old pages with no activity → low priority (skip in early rounds)
 */
int tdx_heuristic_collect(struct tdx_dirty_tracker *tracker,
			  unsigned long *bitmap, unsigned long nr_pages,
			  u64 gpa_start)
{
	unsigned long epoch = atomic_inc_return(&tracker->scan_epoch);
	unsigned int dirty_count = 0;
	unsigned long i;

	if (!tracker->heur_cfg.heuristic_enabled)
		return 0;

	for (i = 0; i < nr_pages; i++) {
		u64 gpa = gpa_start + (i << PAGE_SHIFT);
		enum tdx_page_type ptype = tdx_classify_gpa(tracker, gpa);
		unsigned int score;

		/*
		 * Skip code pages unless they have AUG activity.
		 * Code pages are read-only after loading — almost never dirty.
		 */
		if (ptype == TDX_PAGE_CODE) {
			if (tracker->history_bitmap) {
				unsigned long idx = tdx_gpa_to_history_idx(tracker, gpa);
				if (!test_bit(idx, tracker->history_bitmap))
					continue;
			} else {
				continue;
			}
		}

		score = tdx_compute_page_score(tracker, gpa, epoch, ptype, i);

		if (score >= tracker->heur_cfg.dirty_threshold) {
			__set_bit(i, bitmap);
			dirty_count++;
			atomic64_inc(&tracker->heuristic_hits);
		} else {
			atomic64_inc(&tracker->heuristic_misses);
		}

		/* Age decay: clear old history on every scan */
		if (tracker->history_bitmap && (i % 64 == 0)) {
			unsigned long idx = tdx_gpa_to_history_idx(tracker, gpa);
			/* Decay: keep only strong signals */
			if (score < tracker->heur_cfg.dirty_threshold / 2)
				__clear_bit(idx, tracker->history_bitmap);
		}
	}

	return dirty_count;
}

/* ─────────────────────────────────────────────
 * Hybrid Collector: Trusted Scan + Hint-Only Prediction
 * ───────────────────────────────────────────── */

/*
 * A TDX dirty log must not have false negatives.  Hardware scan results may
 * provide the correctness bitmap once the scan ABI is ratified and wired in.
 * Heuristics can only add extra dirty bits as false positives or produce
 * priority hints for userspace; they must never clear pages from a verified
 * dirty bitmap.
 */

int tdx_hybrid_collect(struct tdx_dirty_tracker *tracker,
		       unsigned long *bitmap, unsigned long nr_pages,
		       u64 gpa_start, u64 gpa_end)
{
	unsigned long *scan_bitmap = NULL;
	int scan_dirty = 0;
	int total_dirty;

	if (!bitmap || nr_pages == 0)
		return 0;

	if (!tracker->scan_available)
		return -ENOTSUPP;

	scan_bitmap = bitmap_zalloc(nr_pages, GFP_KERNEL);
	if (!scan_bitmap)
		return -ENOMEM;

	scan_dirty = tdx_dirty_concurrent_scan(tracker, gpa_start, gpa_end,
					       scan_bitmap, nr_pages);
	if (scan_dirty < 0) {
		bitmap_free(scan_bitmap);
		return scan_dirty;
	}

	/*
	 * Hardware scan is the truth source.  Heuristics can only OR in extra
	 * pages as conservative false positives.
	 */
	bitmap_copy(bitmap, scan_bitmap, nr_pages);
	tdx_heuristic_collect(tracker, bitmap, nr_pages, gpa_start);
	bitmap_free(scan_bitmap);

	total_dirty = bitmap_weight(bitmap, nr_pages);

	/* Update stats */
	atomic64_add(1, &tracker->total_scans);
	atomic64_add(nr_pages, &tracker->total_pages_scanned);
	atomic64_add(total_dirty, &tracker->total_dirty_found);

	return total_dirty;
}

/* ─────────────────────────────────────────────
 * Lifecycle Management
 * ───────────────────────────────────────────── */

int tdx_dirty_tracker_init(struct tdx_dirty_tracker *tracker,
			   struct kvm_tdx *kvm_tdx, unsigned long max_gfn)
{
	unsigned long max_gpa = (unsigned long)max_gfn << PAGE_SHIFT;
	unsigned long nr_history;
	int ret = 0;

	memset(tracker, 0, sizeof(*tracker));
	tracker->kvm_tdx = kvm_tdx;

	/* Initialize configs with defaults */
	tracker->scan_cfg = (struct tdx_scan_config)TDX_SCAN_CONFIG_INIT;
	tracker->heur_cfg = (struct tdx_heuristic_config)TDX_HEURISTIC_CONFIG_INIT;

	/* Detect HW scan support */
	tracker->scan_available = tdx_scan_available();
	pr_info("TDX Dirty: HW page scan %savailable\n",
		tracker->scan_available ? "" : "un");

	/* Initialize history bitmap (1 entry per 4MB region) */
	tracker->history_shift = PAGE_SHIFT + TDX_DIRTY_PAGE_HISTORY_BITS;
	nr_history = (max_gpa >> tracker->history_shift) + 1;
	nr_history = roundup_pow_of_two(nr_history);
	tracker->nr_history_entries = nr_history;

	tracker->history_bitmap = bitmap_zalloc(nr_history, GFP_KERNEL);
	if (!tracker->history_bitmap) {
		ret = -ENOMEM;
		goto out;
	}

	/* Allocate page type map (1 byte per 2MB region) */
	unsigned long nr_type_entries = max_gpa >> PAGE_SHIFT >> 9;
	tracker->page_type_map = bitmap_zalloc(nr_type_entries, GFP_KERNEL);
	if (!tracker->page_type_map) {
		bitmap_free(tracker->history_bitmap);
		tracker->history_bitmap = NULL;
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_init(&tracker->lock);
	atomic_set(&tracker->scan_epoch, 0);

	/* Create dedicated workqueue for concurrent scanning */
	tracker->scan_wq = alloc_workqueue("tdx_scan_wq",
		WQ_UNBOUND | WQ_HIGHPRI | WQ_SYSFS,
		tracker->scan_cfg.nr_workers);
	if (!tracker->scan_wq) {
		bitmap_free(tracker->history_bitmap);
		bitmap_free(tracker->page_type_map);
		tracker->history_bitmap = NULL;
		tracker->page_type_map = NULL;
		ret = -ENOMEM;
		goto out;
	}

	/* Reset stats */
	atomic64_set(&tracker->total_scans, 0);
	atomic64_set(&tracker->total_pages_scanned, 0);
	atomic64_set(&tracker->total_dirty_found, 0);
	atomic64_set(&tracker->heuristic_hits, 0);
	atomic64_set(&tracker->heuristic_misses, 0);

	pr_info("TDX Dirty: tracker initialized (max_gpa=0x%llx, "
		"hist_entries=%lu, workers=%u)\n",
		max_gpa, tracker->nr_history_entries,
		tracker->scan_cfg.nr_workers);

out:
	return ret;
}

void tdx_dirty_tracker_destroy(struct tdx_dirty_tracker *tracker)
{
	if (tracker->scan_wq) {
		destroy_workqueue(tracker->scan_wq);
		tracker->scan_wq = NULL;
	}

	bitmap_free(tracker->history_bitmap);
	tracker->history_bitmap = NULL;

	bitmap_free(tracker->page_type_map);
	tracker->page_type_map = NULL;

	pr_info("TDX Dirty: tracker destroyed\n");
}

/* ─────────────────────────────────────────────
 * Configuration & Stats
 * ───────────────────────────────────────────── */

void tdx_dirty_set_scan_config(struct tdx_dirty_tracker *tracker,
			       const struct tdx_scan_config *cfg)
{
	tracker->scan_cfg = *cfg;
	pr_info("TDX Dirty: scan config updated (workers=%u, batch=%u, concurrent=%d)\n",
		cfg->nr_workers, cfg->batch_pages, cfg->concurrent_enabled);
}

void tdx_dirty_set_heuristic_config(struct tdx_dirty_tracker *tracker,
				     const struct tdx_heuristic_config *cfg)
{
	tracker->heur_cfg = *cfg;
	pr_info("TDX Dirty: heuristic config updated (enabled=%d, threshold=%u)\n",
		cfg->heuristic_enabled, cfg->dirty_threshold);
}

void tdx_dirty_get_stats(struct tdx_dirty_tracker *tracker,
			 u64 *scans, u64 *pages,
			 u64 *dirty, u64 *hits, u64 *misses)
{
	if (scans)  *scans  = atomic64_read(&tracker->total_scans);
	if (pages)  *pages  = atomic64_read(&tracker->total_pages_scanned);
	if (dirty)  *dirty  = atomic64_read(&tracker->total_dirty_found);
	if (hits)   *hits   = atomic64_read(&tracker->heuristic_hits);
	if (misses) *misses = atomic64_read(&tracker->heuristic_misses);
}

/*
 * tdx_sync_dirty_log — Dirty log sync hook for KVM pre-copy migration.
 *
 * Called from kvm_arch_sync_dirty_log() for TDX VMs.
 * For each memory slot, fills the KVM dirty bitmap from a trusted hardware
 * scan.  If no trusted scan ABI is available, marks the entire slot dirty to
 * avoid false negatives during live migration.
 *
 * This is the primary integration point with the standard KVM pre-copy
 * live migration loop:
 *
 *   GET_DIRTY_LOG ioctl
 *     └─ kvm_vm_ioctl_get_dirty_log()
 *          └─ kvm_get_dirty_log_protect()
 *               ├─ kvm_arch_sync_dirty_log()  ← HERE for TDX
 *               │    └─ tdx_sync_dirty_log()
 *               │         ├─ trusted scan or all-dirty fallback
 *               │         └─ updates memslot->dirty_bitmap
 *               └─ snapshot + return dirty_bitmap to VMM
 */
void tdx_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
	struct kvm_tdx *kvm_tdx = container_of(kvm, struct kvm_tdx, kvm);
	struct tdx_dirty_tracker *tracker = &kvm_tdx->dirty_tracker;
	unsigned long nr_pages;
	u64 gpa_start, gpa_end;
	unsigned long *tmp_bitmap = NULL;
	int ret;

	if (!memslot || !memslot->dirty_bitmap || !memslot->npages)
		return;

	nr_pages = memslot->npages;
	gpa_start = gfn_to_gpa(memslot->base_gfn);
	gpa_end = gfn_to_gpa(memslot->base_gfn + nr_pages);

	if (!tracker->scan_available)
		goto mark_all_dirty;

	tmp_bitmap = bitmap_zalloc(nr_pages, GFP_KERNEL_ACCOUNT);
	if (!tmp_bitmap)
		goto mark_all_dirty;

	ret = tdx_hybrid_collect(tracker, tmp_bitmap, nr_pages,
				 gpa_start, gpa_end);
	if (ret < 0) {
		bitmap_free(tmp_bitmap);
		goto mark_all_dirty;
	}

	bitmap_or(memslot->dirty_bitmap, memslot->dirty_bitmap, tmp_bitmap,
		  nr_pages);
	bitmap_free(tmp_bitmap);
	goto out;

mark_all_dirty:
	bitmap_set(memslot->dirty_bitmap, 0, nr_pages);

out:
	pr_debug("TDX Dirty: synced slot base_gfn=0x%lx npages=%lu\n",
		 memslot->base_gfn, nr_pages);
}

/*
 * tdx_sync_dirty_log_all — Sync dirty log for ALL memory slots.
 *
 * Called during pre-copy final phase or stop-and-copy transition.
 * Scans all guest memory slots and updates their dirty bitmaps.
 */
void tdx_sync_dirty_log_all(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int bkt;

	slots = kvm_memslots(kvm);
	if (!slots)
		return;

	/*
	 * Iterate over all memory slots and sync each one.
	 * This is a bulk operation — use it sparingly.
	 */
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!memslot->dirty_bitmap)
			continue;
		tdx_sync_dirty_log(kvm, memslot);
	}
}
