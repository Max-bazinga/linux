// SPDX-License-Identifier: GPL-2.0
/*
 * KVM remote TLB flush statistics test
 *
 * Copyright (C) 2024
 *
 * Tests the remote_tlb_flush_requests and remote_tlb_flush statistics.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#define MEM_REGION_SIZE		(64 * 1024 * 1024ULL)
#define MEM_REGION_SLOT		10
#define MEM_REGION_GPA		0x40000000ULL
#define MEM_REGION_GVA		MEM_REGION_GPA
#define TEST_PAGES		16
#define NR_VCPUS		4

struct test_stats {
	uint64_t remote_tlb_flush_requests;
	uint64_t remote_tlb_flush;
};

static size_t dirty_log_bytes(uint64_t npages)
{
	size_t bits_per_long = 8 * sizeof(unsigned long);

	return ((npages + bits_per_long - 1) / bits_per_long) * sizeof(unsigned long);
}

static void read_flush_stats(struct kvm_vm *vm, struct test_stats *stats)
{
	struct kvm_binary_stats kvm_stats;
	int stats_fd;

	stats_fd = vm_get_stats_fd(vm);
	kvm_stats.fd = stats_fd;

	read_stats_header(stats_fd, &kvm_stats.header);
	kvm_stats.desc = read_stats_descriptors(stats_fd, &kvm_stats.header);

	kvm_get_stat(&kvm_stats, "remote_tlb_flush_requests",
		     &stats->remote_tlb_flush_requests, 1);
	kvm_get_stat(&kvm_stats, "remote_tlb_flush",
		     &stats->remote_tlb_flush, 1);

	free(kvm_stats.desc);
	close(stats_fd);
}

#define diff_stats(before, after, field) ((after)->field - (before)->field)

static void guest_code(void)
{
	volatile char *test_mem = (volatile char *)MEM_REGION_GVA;
	uint64_t i;

	for (i = 0; i < TEST_PAGES; i++) {
		test_mem[i * PAGE_SIZE] = (char)i;
		asm volatile("" ::: "memory");
	}

	ucall(UCALL_SYNC, 0);
}

static void add_test_memslot(struct kvm_vm *vm)
{
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    MEM_REGION_GPA, MEM_REGION_SLOT,
				    MEM_REGION_SIZE / vm->page_size,
				    KVM_MEM_LOG_DIRTY_PAGES);
	virt_map(vm, MEM_REGION_GVA, MEM_REGION_GPA, MEM_REGION_SIZE / vm->page_size);
}

static void run_vcpu_and_expect_sync(struct kvm_vcpu *vcpu)
{
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, NULL) == UCALL_SYNC,
		    "Invalid guest sync status: exit_reason=%s",
		    exit_reason_str(vcpu->run->exit_reason));
}

static void collect_dirty_log(struct kvm_vm *vm)
{
	size_t nbytes = dirty_log_bytes(MEM_REGION_SIZE / vm->page_size);
	unsigned long *bitmap = calloc(1, nbytes);

	TEST_ASSERT(bitmap, "Failed to allocate dirty bitmap");
	kvm_vm_get_dirty_log(vm, MEM_REGION_SLOT, bitmap);
	free(bitmap);
}

static void test_basic_single_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct test_stats before, after;
	uint64_t requests, flushes;

	pr_info("Test 1: Single vCPU dirty-log flush path\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	add_test_memslot(vm);

	read_flush_stats(vm, &before);
	run_vcpu_and_expect_sync(vcpu);
	collect_dirty_log(vm);
	read_flush_stats(vm, &after);

	requests = diff_stats(&before, &after, remote_tlb_flush_requests);
	flushes = diff_stats(&before, &after, remote_tlb_flush);

	pr_info("  remote_tlb_flush_requests: %" PRIu64 "\n", requests);
	pr_info("  remote_tlb_flush: %" PRIu64 "\n", flushes);

	TEST_ASSERT(requests >= 1,
		    "Expected at least one remote TLB flush request, got %" PRIu64,
		    requests);
	TEST_ASSERT(flushes <= requests,
		    "flushes (%" PRIu64 ") should be <= requests (%" PRIu64 ")",
		    flushes, requests);

	kvm_vm_free(vm);
	pr_info("Test 1: PASSED\n\n");
}

static void test_multi_vcpu_tlb_flush(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct test_stats before, after;
	uint64_t requests, flushes;
	int i;

	pr_info("Test 2: Multi-vCPU dirty-log flush path\n");

	vm = vm_create_with_vcpus(NR_VCPUS, guest_code, vcpus);
	add_test_memslot(vm);

	read_flush_stats(vm, &before);

	for (i = 0; i < NR_VCPUS; i++)
		run_vcpu_and_expect_sync(vcpus[i]);

	collect_dirty_log(vm);
	read_flush_stats(vm, &after);

	requests = diff_stats(&before, &after, remote_tlb_flush_requests);
	flushes = diff_stats(&before, &after, remote_tlb_flush);

	pr_info("  remote_tlb_flush_requests: %" PRIu64 "\n", requests);
	pr_info("  remote_tlb_flush: %" PRIu64 "\n", flushes);

	TEST_ASSERT(requests >= 1,
		    "Expected at least one remote TLB flush request, got %" PRIu64,
		    requests);
	TEST_ASSERT(flushes <= requests,
		    "flushes (%" PRIu64 ") should be <= requests (%" PRIu64 ")",
		    flushes, requests);

	kvm_vm_free(vm);
	pr_info("Test 2: PASSED\n\n");
}

static void test_counter_relationship(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct test_stats before, after;
	uint64_t requests, flushes;
	int i;

	pr_info("Test 3: Counter relationship verification\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	add_test_memslot(vm);

	read_flush_stats(vm, &before);

	for (i = 0; i < 10; i++) {
		run_vcpu_and_expect_sync(vcpu);
		collect_dirty_log(vm);
	}

	read_flush_stats(vm, &after);

	requests = diff_stats(&before, &after, remote_tlb_flush_requests);
	flushes = diff_stats(&before, &after, remote_tlb_flush);

	pr_info("  Total remote_tlb_flush_requests: %" PRIu64 "\n", requests);
	pr_info("  Total remote_tlb_flush: %" PRIu64 "\n", flushes);

	TEST_ASSERT(flushes <= requests,
		    "VIOLATION: remote_tlb_flush (%" PRIu64 ") > remote_tlb_flush_requests (%" PRIu64 ")",
		    flushes, requests);
	TEST_ASSERT(requests >= 1,
		    "Expected at least one flush request in loop, got %" PRIu64,
		    requests);

	kvm_vm_free(vm);
	pr_info("Test 3: PASSED\n\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_BINARY_STATS_FD));

	ksft_print_header();
	ksft_set_plan(3);

	pr_info("KVM remote TLB flush statistics test\n");
	pr_info("=====================================\n\n");

	test_basic_single_vcpu();
	test_multi_vcpu_tlb_flush();
	test_counter_relationship();

	ksft_finished();
}
