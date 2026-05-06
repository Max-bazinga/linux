/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TDX Dirty Page Tracking Accelerator
 *
 * Combines trusted hardware batch scanning with heuristics-based hot-page
 * hints to accelerate TDX VM live migration.
 *
 * Design:
 *   Direction 1: Trusted batch dirty scan + concurrent multi-range scanning
 *   Direction 2: Heuristic hot-page hints using page history/type/access
 *
 * Copyright (C) 2026
 */

#ifndef __KVM_X86_TDX_DIRTY_H
#define __KVM_X86_TDX_DIRTY_H

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/workqueue.h>
#include <linux/bitmap.h>
#include <asm/kvm_host.h>

/* ─── Direction 1: SEAMCALL Interface ─── */

/*
 * TDX 1.5+ SEAMCALL leaf for scanning private page dirty state.
 *
 * TDH_MEM_PAGE_SCAN:
 *   Input:  GPA range [start_gpa, end_gpa)
 *   Output: Bitmap of dirty pages (1 bit per 4KB page)
 *           Status code (SCAN_DONE, SCAN_PARTIAL, SCAN_BUSY)
 *
 * Architectural leaf number (to be ratified by Intel):
 */
#define TDH_MEM_PAGE_SCAN	46

/* Scan return status */
#define TDX_SCAN_DONE		0	/* Full range scanned */
#define TDX_SCAN_PARTIAL	1	/* Partial results, retry for more */
#define TDX_SCAN_BUSY		2	/* HW busy, try again later */
#define TDX_SCAN_UNSUPPORTED	0xFF	/* TDX module doesn't support scan */

/* Maximum pages per single SEAMCALL scan invocation */
#define TDX_SCAN_BATCH_MAX_PAGES	512

/* ─── Direction 1: Batch Scan Config ─── */

struct tdx_scan_config {
	/* Number of concurrent scan workers */
	unsigned int		nr_workers;

	/* Batch size per SEAMCALL (4K pages) */
	unsigned int		batch_pages;

	/* Max pages to scan per work item */
	unsigned long		max_pages_per_scan;

	/* Whether to use concurrent scanning */
	bool			concurrent_enabled;

	/* Scan timeout in milliseconds (0 = no timeout) */
	unsigned long		scan_timeout_ms;

	/* Enable bitmap compression */
	bool			compress_bitmap;
};

#define TDX_SCAN_CONFIG_INIT {					\
	.nr_workers		= 1,				\
	.batch_pages		= TDX_SCAN_BATCH_MAX_PAGES,	\
	.max_pages_per_scan	= 65536, /* 256MB per worker */\
	.concurrent_enabled	= true,				\
	.scan_timeout_ms	= 5000,				\
	.compress_bitmap	= true,				\
}

/* ─── Direction 2: Page History Tracking ─── */

/* Page type classification */
enum tdx_page_type {
	TDX_PAGE_UNKNOWN	= 0,
	TDX_PAGE_CODE		= 1,	/* Executable/text pages (low GPA) */
	TDX_PAGE_HEAP		= 2,	/* Heap region (mid GPA) */
	TDX_PAGE_STACK		= 3,	/* Stack region (high GPA) */
	TDX_PAGE_MMIO		= 4,	/* MMIO or device memory */
	TDX_PAGE_VMM_SHARED	= 5,	/* Shared (host-visible) pages */
	TDX_PAGE_ACCEPTED	= 6,	/* Recently accepted pages */
};

/* Per-page hotness score (higher = more useful as a transfer hint) */
struct tdx_page_score {
	u32	write_freq	: 8;	/* Observed write frequency (0-255) */
	u32	recency		: 8;	/* Time since last access (0-255) */
	u32	page_type	: 4;	/* Page type classification */
	u32	age		: 8;	/* Page age in scan epochs */
	u32	predicted_dirty	: 1;	/* Hot-page hint */
	u32	reserved	: 3;
};

/* Per-VM dirty tracking state */
#define TDX_DIRTY_PAGE_HISTORY_BITS	12	/* Track per-4MB region */
#define TDX_DIRTY_HISTORY_WINDOW	8	/* 8 epochs of history */
#define TDX_DIRTY_SCORE_THRESHOLD	128	/* Minimum score to flag dirty */

/* ─── Direction 2: Heuristics Config ─── */

struct tdx_heuristic_config {
	/* Enable heuristic hot-page hints */
	bool			heuristic_enabled;

	/* Write frequency weight in prediction score */
	unsigned int		freq_weight;

	/* Recency weight in prediction score */
	unsigned int		recency_weight;

	/* Page type weight in prediction score */
	unsigned int		type_weight;

	/* LRU age decay factor (0-255, higher = faster decay) */
	unsigned int		age_decay;

	/* Score threshold to consider page hot (0-255) */
	unsigned int		dirty_threshold;

	/*
	 * GPA regions for page type hints.
	 * Guest kernel convention:
	 *   Code:   [0x0,       0x20000000)  0-512MB
	 *   Heap:   [0x20000000, 0x80000000)  512MB-2GB
	 *   Stack:  [0x7f00000000, ...)       ~510GB+
	 */
	u64			code_region_end;
	u64			heap_region_end;
};

#define TDX_HEURISTIC_CONFIG_INIT {				\
	.heuristic_enabled	= true,				\
	.freq_weight		= 40,				\
	.recency_weight		= 35,				\
	.type_weight		= 25,				\
	.age_decay		= 30,				\
	.dirty_threshold	= TDX_DIRTY_SCORE_THRESHOLD,	\
	.code_region_end	= 0x20000000ULL,		\
	.heap_region_end	= 0x80000000ULL,		\
}

/* ─── Hybrid Scanning Work Item ─── */

struct tdx_scan_work {
	struct work_struct	work;
	struct kvm_tdx		*kvm_tdx;

	/* GPA range to scan */
	u64			gpa_start;
	u64			gpa_end;

	/* Output dirty bitmap */
	unsigned long		*dirty_bitmap;
	unsigned long		nr_pages;
	unsigned long		page_offset;

	/* Prediction scores for this range */
	struct tdx_page_score	*scores;
	unsigned int		nr_scores;

	/* Scan result */
	int			result;
	int			dirty_count;
};

/* ─── Per-VM Dirty Tracker ─── */

struct tdx_dirty_tracker {
	struct kvm_tdx			*kvm_tdx;

	/* Direction 1: Scan config and state */
	struct tdx_scan_config		scan_cfg;
	bool				scan_available;	/* HW scan support */

	/* Direction 2: Heuristics config and state */
	struct tdx_heuristic_config	heur_cfg;
	struct delayed_work		heuristic_work;

	/* Per-region history (compressed for scalability) */
	unsigned long			*history_bitmap;
	unsigned int			history_shift;	/* GPA -> history entry */
	unsigned long			nr_history_entries;

	/* Epoch counter for age tracking */
	atomic_t			scan_epoch;

	/* Per-page type hints (allocated lazily) */
	unsigned long			*page_type_map;

	/* Lock for tracker state */
	spinlock_t			lock;

	/* Workqueue for concurrent scanning */
	struct workqueue_struct		*scan_wq;

	/* Performance stats */
	atomic64_t			total_scans;
	atomic64_t			total_pages_scanned;
	atomic64_t			total_dirty_found;
	atomic64_t			heuristic_hits;
	atomic64_t			heuristic_misses;
};

/* ─── Public API ─── */

#ifdef CONFIG_KVM_INTEL_TDX

int tdx_dirty_tracker_init(struct tdx_dirty_tracker *tracker,
			   struct kvm_tdx *kvm_tdx, unsigned long max_gfn);
void tdx_dirty_tracker_destroy(struct tdx_dirty_tracker *tracker);

int tdx_dirty_scan_range(struct tdx_dirty_tracker *tracker,
			 u64 gpa_start, u64 gpa_end,
			 unsigned long *bitmap, unsigned long nr_pages);

int tdx_dirty_concurrent_scan(struct tdx_dirty_tracker *tracker,
			      u64 gpa_start, u64 gpa_end,
			      unsigned long *bitmap, unsigned long nr_pages);

/* Heuristics */
void tdx_dirty_record_aug(struct tdx_dirty_tracker *tracker, u64 gpa);
void tdx_dirty_notify_page_add(struct tdx_dirty_tracker *tracker, u64 gpa);
int tdx_heuristic_collect(struct tdx_dirty_tracker *tracker,
			  unsigned long *bitmap, unsigned long nr_pages,
			  u64 gpa_start);

/* Hybrid collection: trusted scan plus conservative heuristic false positives */
int tdx_hybrid_collect(struct tdx_dirty_tracker *tracker,
		       unsigned long *bitmap, unsigned long nr_pages,
		       u64 gpa_start, u64 gpa_end);

/* Configuration */
void tdx_dirty_set_scan_config(struct tdx_dirty_tracker *tracker,
				const struct tdx_scan_config *cfg);
void tdx_dirty_set_heuristic_config(struct tdx_dirty_tracker *tracker,
				     const struct tdx_heuristic_config *cfg);

/* Stats */
void tdx_dirty_get_stats(struct tdx_dirty_tracker *tracker,
			 u64 *scans, u64 *pages,
			 u64 *dirty, u64 *hits, u64 *misses);

/*
 * Dirty log sync hook for KVM pre-copy live migration.
 * Called from kvm_arch_sync_dirty_log() for TDX VMs.
 * Uses trusted HW scan if available, otherwise marks the entire slot dirty.
 */
void tdx_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot);
void tdx_sync_dirty_log_all(struct kvm *kvm);

#else /* !CONFIG_KVM_INTEL_TDX */

static inline int tdx_dirty_tracker_init(
	struct tdx_dirty_tracker *tracker,
	struct kvm_tdx *kvm_tdx, unsigned long max_gfn)
{ return 0; }
static inline void tdx_dirty_tracker_destroy(
	struct tdx_dirty_tracker *tracker) {}
static inline int tdx_dirty_scan_range(
	struct tdx_dirty_tracker *tracker,
	u64 gpa_start, u64 gpa_end,
	unsigned long *bitmap, unsigned long nr_pages)
{ return -ENOTSUPP; }
static inline int tdx_dirty_concurrent_scan(
	struct tdx_dirty_tracker *tracker,
	u64 gpa_start, u64 gpa_end,
	unsigned long *bitmap, unsigned long nr_pages)
{ return -ENOTSUPP; }
static inline void tdx_dirty_record_aug(
	struct tdx_dirty_tracker *tracker, u64 gpa) {}
static inline void tdx_dirty_notify_page_add(
	struct tdx_dirty_tracker *tracker, u64 gpa) {}
static inline int tdx_heuristic_collect(
	struct tdx_dirty_tracker *tracker,
	unsigned long *bitmap, unsigned long nr_pages,
	u64 gpa_start)
{ return 0; }
static inline int tdx_hybrid_collect(
	struct tdx_dirty_tracker *tracker,
	unsigned long *bitmap, unsigned long nr_pages,
	u64 gpa_start, u64 gpa_end)
{ return 0; }
static inline void tdx_dirty_set_scan_config(
	struct tdx_dirty_tracker *tracker,
	const struct tdx_scan_config *cfg) {}
static inline void tdx_dirty_set_heuristic_config(
	struct tdx_dirty_tracker *tracker,
	const struct tdx_heuristic_config *cfg) {}
static inline void tdx_dirty_get_stats(
	struct tdx_dirty_tracker *tracker,
	u64 *scans, u64 *pages,
	u64 *dirty, u64 *hits, u64 *misses) {}
static inline void tdx_sync_dirty_log(
	struct kvm *kvm, struct kvm_memory_slot *memslot) {}
static inline void tdx_sync_dirty_log_all(struct kvm *kvm) {}

#endif /* CONFIG_KVM_INTEL_TDX */

#endif /* __KVM_X86_TDX_DIRTY_H */
