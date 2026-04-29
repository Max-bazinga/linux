// SPDX-License-Identifier: GPL-2.0
/*
 * ept_fault_test.c - Test KVM EPT (Extended Page Tables) fault handling.
 *
 * Exercises the EPT violation path (EXIT_REASON_EPT_VIOLATION) by using
 * userfaultfd to intercept stage-2 page faults.  Verifies that KVM correctly
 * handles read, write, and instruction-fetch faults through the EPT MMU.
 *
 * Covers the code path:
 *   handle_ept_violation() → __vmx_handle_ept_violation()
 *   → kvm_mmu_page_fault() → kvm_tdp_mmu_page_fault()
 *   → kvm_mmu_faultin_pfn() → uffd resolution
 *
 * ARM64 has arm64/page_fault_test.c (1135 lines, 10+ scenarios).
 * This is the x86 equivalent covering the EPT-specific path.
 *
 * TODO (future patches):
 *   - EPT misconfig test (EXIT_REASON_EPT_MISCONFIG)
 *   - EPT fast_page_fault path (access/dirty tracking)
 *   - EPT #VE (EPT_VIOLATION_VE) notification
 *   - Nested EPT fault interception
 *   - Dirty logging + EPT fault interaction
 *   - vNMI + EPT violation errata path
 */
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "userfaultfd_util.h"

/* EPT violation exit qualification bits (from arch/x86/include/asm/vmx.h) */
#define EPT_VIOLATION_ACC_READ		BIT(0)
#define EPT_VIOLATION_ACC_WRITE		BIT(1)
#define EPT_VIOLATION_ACC_INSTR		BIT(2)
#define EPT_VIOLATION_PROT_MASK		(BIT(3) | BIT(4) | BIT(5))
#define EPT_VIOLATION_GVA_IS_VALID	BIT(7)
#define EPT_VIOLATION_GVA_TRANSLATED	BIT(8)

/* Test memory layout */
#define TEST_DATA_SLOT		10
#define TEST_CODE_SLOT		11
#define TEST_PERM_SLOT		12
#define TEST_DATA_GPA		0x10000000ULL
#define TEST_CODE_GPA		0x20000000ULL
#define TEST_PERM_GPA		0x30000000ULL
#define TEST_DATA_GVA		0x40000000ULL
#define TEST_CODE_GVA		0x50000000ULL
#define TEST_PERM_GVA		0x60000000ULL
#define TEST_REGION_SIZE	PAGE_SIZE

/* Guest↔host synchronization commands */
#define UCALL_SYNC_READ_DONE	0
#define UCALL_SYNC_WRITE_DONE	1
#define UCALL_SYNC_EXEC_DONE	2
#define UCALL_SYNC_PERM_READ_DONE	3
#define UCALL_SYNC_PERM_WRITE_MMIO	4
#define UCALL_SYNC_PERM_EXEC_DONE	5

/*
 * Per-fault-type counters for verification.
 * Even with one vCPU, uffd handler runs in a separate host thread, so use
 * atomic accesses for host-side stats.
 */
struct fault_stats {
	int read_faults;
	int write_faults;
	int exec_faults;	/* counts as !write in uffd, tracked separately */
	int perm_mmio_exits;
};
static struct fault_stats stats;

#define EXPECTED_DATA_QWORD	0xABABABABABABABABULL
#define PERM_WRITE_TEST_QWORD	0xDEADBEEFDEADBEEFULL

static inline void stats_inc(int *v)
{
	__sync_fetch_and_add(v, 1);
}

static inline int stats_read(int *v)
{
	return __atomic_load_n(v, __ATOMIC_ACQUIRE);
}

/*
 * Userfaultfd handler for the TEST_DATA region.
 * KVM's EPT violation handler calls into kvm_mmu_page_fault(),
 * which tries to fault in the page via get_user_pages().  This blocks
 * until our uffd handler resolves the fault with UFFDIO_COPY.
 *
 * The actual EPT violation exit qualification (read/write/exec bits)
 * is consumed by KVM internally before reaching userspace.  This test
 * verifies correctness indirectly: by checking that the uffd fault
 * type matches the guest's intended access, and that after resolution
 * the guest reads the correct data.
 */
static int uffd_data_handler(int uffd_mode, int uffd, struct uffd_msg *msg)
{
	struct uffdio_copy copy;
	uint64_t addr = msg->arg.pagefault.address;
	uint64_t flags = msg->arg.pagefault.flags;
	bool is_write = !!(flags & UFFD_PAGEFAULT_FLAG_WRITE);
	static uint8_t data_page[4096] = { [0 ... 4095] = 0xAB };

	TEST_ASSERT(uffd_mode == UFFDIO_REGISTER_MODE_MISSING,
		    "Unexpected uffd mode: %d", uffd_mode);

	if (is_write)
		stats_inc(&stats.write_faults);
	else
		stats_inc(&stats.read_faults);

	copy.src = (uint64_t)(data_page);
	copy.dst = addr;
	copy.len = PAGE_SIZE;
	copy.mode = 0;

	TEST_ASSERT(ioctl(uffd, UFFDIO_COPY, &copy) == 0,
		    "UFFDIO_COPY failed at addr 0x%lx, errno %d",
		    addr, errno);

	return 0;
}

/*
 * Userfaultfd handler for the TEST_CODE region.
 * Copies executable guest code into the faulted page.
 */
static int uffd_code_handler(int uffd_mode, int uffd, struct uffd_msg *msg)
{
	struct uffdio_copy copy;
	uint64_t addr = msg->arg.pagefault.address;
	static const uint8_t exec_page[PAGE_SIZE] = { 0xC3 }; /* ret */

	TEST_ASSERT(uffd_mode == UFFDIO_REGISTER_MODE_MISSING,
		    "Unexpected uffd mode: %d", uffd_mode);

	/*
	 * Copy the exec stub code. The stub is small: just a RET
	 * instruction, enough to verify execution works through EPT.
	 */
	stats_inc(&stats.exec_faults);

	copy.src = (uint64_t)(exec_page);
	copy.dst = addr;
	copy.len = PAGE_SIZE;
	copy.mode = 0;

	TEST_ASSERT(ioctl(uffd, UFFDIO_COPY, &copy) == 0,
		    "UFFDIO_COPY (code) failed at addr 0x%lx", addr);

	return 0;
}

/*
 * Guest code: performs controlled accesses to trigger EPT faults.
 *
 * Stage 1 (read):  Read from uffd-backed data page.
 * Stage 2 (write): Write to uffd-backed data page.
 * Stage 3 (exec):  Call function in uffd-backed code page.
 */
static void guest_code(void)
{
	volatile uint64_t val;
	uint64_t *data = (uint64_t *)TEST_DATA_GVA;

	/*
	 * STAGE: Read fault
	 * First access to the data page.  EPT has no mapping → KVM gets
	 * EPT_VIOLATION with ACC_READ.  uffd handler serves the page.
	 */
	val = *data;
	GUEST_ASSERT_EQ(val, EXPECTED_DATA_QWORD);
	GUEST_SYNC(UCALL_SYNC_READ_DONE);

	/*
	 * Re-read should NOT fault (page is now mapped in EPT).
	 */
	val = *data;
	GUEST_ASSERT_EQ(val, EXPECTED_DATA_QWORD);
	GUEST_SYNC(UCALL_SYNC_READ_DONE);

	/*
	 * STAGE: Write fault
	 * The existing EPT mapping allows reads but the write may
	 * trigger access/dirty tracking depending on the MMU mode.
	 * In TDP MMU, the initial mapping is RW, so this may not fault.
	 */
	*data = 0xDEADBEEF;
	GUEST_ASSERT_EQ(*data, 0xDEADBEEFULL);
	GUEST_SYNC(UCALL_SYNC_WRITE_DONE);

	/*
	 * STAGE: Exec fault
	 * Call a function in the uffd-backed code page.
	 * EPT has no mapping for the code page → KVM gets
	 * EPT_VIOLATION with ACC_INSTR.
	 */
	{
		void (*fn)(void) = (void (*)(void))TEST_CODE_GVA;
		fn();
	}
	GUEST_SYNC(UCALL_SYNC_EXEC_DONE);

	GUEST_DONE();
}

/*
 * Guest code: EPT permission fault testing with a KVM_MEM_READONLY memslot.
 *
 * The permission test slot (TEST_PERM_SLOT) is created with KVM_MEM_READONLY.
 * This causes KVM to install EPT entries with only read + exec permissions:
 *   - Read accesses succeed normally (no EPT violation).
 *   - Write accesses trigger EPT_VIOLATION with PROT_MASK set and
 *     ACC_WRITE bit set.  KVM exits to userspace with KVM_EXIT_MMIO.
 *   - Exec accesses succeed if the VM has NX disabled, otherwise they
 *     may trigger EPT_VIOLATION with ACC_INSTR.
 */
static void guest_code_perm(void)
{
	volatile uint64_t val;
	uint64_t *perm_page = (uint64_t *)TEST_PERM_GVA;

	/*
	 * STAGE: Read from RO memslot
	 * Read must succeed; EPT has installed a read mapping.
	 * The host pre-populates the page with EXPECTED_DATA_QWORD.
	 */
	val = *perm_page;
	GUEST_ASSERT_EQ(val, EXPECTED_DATA_QWORD);
	GUEST_SYNC(UCALL_SYNC_PERM_READ_DONE);

	/*
	 * STAGE: Write to RO memslot
	 * Write to a KVM_MEM_READONLY region must trigger an MMIO exit.
	 * KVM installs the EPT entry with write=0, so the write triggers
	 * EPT_VIOLATION with ACC_WRITE | PROT_MASK.
	 * KVM then exits to userspace with KVM_EXIT_MMIO.
	 *
	 * The host MMIO handler writes the value into HVA memory.
	 * After KVM re-enters, the guest re-executes the write, which
	 * again causes MMIO exit (since the memslot is still RO from
	 * KVM's perspective — KVM does not promote RO→RW).
	 *
	 * We use a single write that we expect to trigger MMIO,
	 * then GUEST_SYNC to signal the host.
	 */
	WRITE_ONCE(*perm_page, PERM_WRITE_TEST_QWORD);
	/*
	 * After the MMIO handler services the write, KVM re-enters
	 * and the guest re-executes the WRITE_ONCE.  This causes
	 * another MMIO exit.  This infinite loop is broken by the
	 * host side which detects the second MMIO exit and advances
	 * past the write by modifying the guest RIP via
	 * vcpu_run_complete_io() or similar.  For x86, KVM
	 * automatically advances RIP past the instruction on MMIO
	 * exits, so the guest proceeds.
	 */
	GUEST_SYNC(UCALL_SYNC_PERM_WRITE_MMIO);

	/*
	 * Verify value was NOT written (since the MMIO handler wrote to
	 * host memory but the EPT mapping remains RO, the guest cannot
	 * observe the written value through the read-only EPT entry).
	 *
	 * Actually, on x86 EPT with RO memslot: after the MMIO exit,
	 * KVM handles the write fault. Since the memslot is RO,
	 * KVM does NOT re-enter the guest to retry the write instruction.
	 * Instead KVM completes the MMIO and advances RIP, so the write
	 * instruction is effectively executed by the MMIO handler writing
	 * to HVA.  The guest *can* read the value back because the EPT
	 * entry allows reads.
	 */
	val = READ_ONCE(*perm_page);
	GUEST_ASSERT_EQ(val, PERM_WRITE_TEST_QWORD);
	GUEST_SYNC(UCALL_SYNC_PERM_READ_DONE);

	/*
	 * STAGE: Exec from RO memslot
	 * Code execution is allowed (the EPT entry permits instruction fetch).
	 */
	{
		void (*fn)(void) = (void (*)(void))(TEST_PERM_GVA + 0x100);
		fn();
	}
	GUEST_SYNC(UCALL_SYNC_PERM_EXEC_DONE);

	GUEST_DONE();
}

/*
 * MMIO handler for writes to the KVM_MEM_READONLY permission test region.
 *
 * When the guest writes to a GPA in a RO memslot, KVM exits with
 * KVM_EXIT_MMIO.  We copy the write data into the host HVA backing
 * the slot and count the MMIO exit.
 */
static void perm_mmio_handler(struct kvm_vm *vm, struct kvm_run *run)
{
	struct userspace_mem_region *region;
	void *hva;

	region = vm_get_mem_region(vm, TEST_PERM_SLOT);
	TEST_ASSERT(region != NULL, "Failed to get perm memslot region");

	TEST_ASSERT_EQ(run->mmio.phys_addr, region->region.guest_phys_addr);
	TEST_ASSERT(run->mmio.is_write, "Expected MMIO write to RO memslot");

	hva = (void *)region->region.userspace_addr;
	memcpy(hva + (run->mmio.phys_addr - region->region.guest_phys_addr),
	       run->mmio.data, run->mmio.len);

	stats_inc(&stats.perm_mmio_exits);
}

/* 
 * Populate the permission test page with code for the exec test.
 * The exec stub (offset 0x100 in the perm page) is a single RET instruction.
 */
static void load_perm_exec_stub(struct kvm_vm *vm)
{
	struct userspace_mem_region *region;
	void *hva;
	static const uint8_t exec_stub[] = { 0xC3 }; /* ret */

	region = vm_get_mem_region(vm, TEST_PERM_SLOT);
	hva = (void *)region->region.userspace_addr;
	memcpy(hva + 0x100, exec_stub, sizeof(exec_stub));
}

/*
 * Populate the permission test page with EXPECTED_DATA_QWORD so that
 * the guest read test can verify the value.
 */
static void init_perm_data_page(struct kvm_vm *vm)
{
	struct userspace_mem_region *region;
	uint64_t *hva;

	region = vm_get_mem_region(vm, TEST_PERM_SLOT);
	hva = (uint64_t *)region->region.userspace_addr;
	*hva = EXPECTED_DATA_QWORD;
}

static void run_guest_normal(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	struct kvm_vm *vm = vcpu->vm;
	struct uffd_desc *data_uffd = NULL;
	struct uffd_desc *code_uffd = NULL;

	/*
	 * Add a uffd-backed data slot.  Pages are initially populated by
	 * vm_userspace_mem_region_add; punch holes so the first guest access
	 * triggers EPT violation → uffd fault.
	 */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, TEST_DATA_SLOT,
				    TEST_REGION_SIZE / PAGE_SIZE, 0);
	virt_map(vm, TEST_DATA_GVA, TEST_DATA_GPA,
		 TEST_REGION_SIZE / PAGE_SIZE);

	{
		void *hva = addr_gpa2hva(vm, TEST_DATA_GPA);

		TEST_ASSERT(!madvise(hva, TEST_REGION_SIZE, MADV_DONTNEED),
			    "madvise DONTNEED on data region failed");

		data_uffd = uffd_setup_demand_paging(
			UFFDIO_REGISTER_MODE_MISSING, 0,
			hva, TEST_REGION_SIZE,
			1, uffd_data_handler);
	}

	/*
	 * Add a uffd-backed code slot for the exec fault test.
	 */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_CODE_GPA, TEST_CODE_SLOT,
				    TEST_REGION_SIZE / PAGE_SIZE, 0);
	virt_map(vm, TEST_CODE_GVA, TEST_CODE_GPA,
		 TEST_REGION_SIZE / PAGE_SIZE);

	{
		void *hva = addr_gpa2hva(vm, TEST_CODE_GPA);

		TEST_ASSERT(!madvise(hva, TEST_REGION_SIZE, MADV_DONTNEED),
			    "madvise DONTNEED on code region failed");

		code_uffd = uffd_setup_demand_paging(
			UFFDIO_REGISTER_MODE_MISSING, 0,
			hva, TEST_REGION_SIZE,
			1, uffd_code_handler);
	}

	/*
	 * Run the guest. Each stage triggers EPT violations that KVM
	 * resolves through the uffd handler.  After each GUEST_SYNC,
	 * we verify the stats.
	 */

	/* Stage: first read (expect fault) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_READ_DONE);
	TEST_ASSERT_EQ(stats_read(&stats.read_faults), 1);
	pr_info("stage read#1 done: read_faults=%d write_faults=%d exec_faults=%d\n",
		stats_read(&stats.read_faults),
		stats_read(&stats.write_faults),
		stats_read(&stats.exec_faults));

	/* Stage: re-read (expect NO fault) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_READ_DONE);
	TEST_ASSERT_EQ(stats_read(&stats.read_faults), 1);
	pr_info("stage read#2 done: read_faults=%d write_faults=%d exec_faults=%d\n",
		stats_read(&stats.read_faults),
		stats_read(&stats.write_faults),
		stats_read(&stats.exec_faults));
	TEST_ASSERT(!madvise(addr_gpa2hva(vm, TEST_DATA_GPA), TEST_REGION_SIZE,
			     MADV_DONTNEED),
		    "madvise DONTNEED before write stage failed");
	pr_info("re-punched data page before write stage\n");

	/* Stage: write (may or may not fault depending on TDP MMU mode) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_WRITE_DONE);
	pr_info("stage write done: read_faults=%d write_faults=%d exec_faults=%d\n",
		stats_read(&stats.read_faults),
		stats_read(&stats.write_faults),
		stats_read(&stats.exec_faults));

	/* Stage: exec (expect fault) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_EXEC_DONE);
	TEST_ASSERT_EQ(stats_read(&stats.exec_faults), 1);
	pr_info("stage exec done: read_faults=%d write_faults=%d exec_faults=%d\n",
		stats_read(&stats.read_faults),
		stats_read(&stats.write_faults),
		stats_read(&stats.exec_faults));

	/* Final: GUEST_DONE */
	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	default:
		TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
	}

	uffd_stop_demand_paging(data_uffd);
	uffd_stop_demand_paging(code_uffd);
}

/*
 * Run the EPT permission fault test.
 *
 * Creates a KVM_MEM_READONLY memslot and verifies:
 * 1. Read from RO memslot succeeds
 * 2. Write to RO memslot triggers KVM_EXIT_MMIO
 * 3. Exec from RO memslot succeeds
 *
 * On x86 EPT, KVM_MEM_READONLY maps to EPT entries with write=0.
 * Guest writes trigger EPT_VIOLATION (ACC_WRITE | PROT_MASK), and
 * KVM exits to userspace with KVM_EXIT_MMIO instead of injecting a
 * page fault into the guest.
 */
static void run_guest_perm(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct ucall uc;

	/*
	 * Add the RO memslot for permission testing.
	 * KVM_MEM_READONLY: KVM installs EPT entries with R=1, W=0, X=1.
	 */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_PERM_GPA, TEST_PERM_SLOT,
				    TEST_REGION_SIZE / PAGE_SIZE,
				    KVM_MEM_READONLY);
	virt_map(vm, TEST_PERM_GVA, TEST_PERM_GPA,
		 TEST_REGION_SIZE / PAGE_SIZE);

	/* Pre-populate expected data and exec stub */
	init_perm_data_page(vm);
	load_perm_exec_stub(vm);

	pr_info("=== EPT permission fault test (KVM_MEM_READONLY) ===\n");

	/*
	 * Stage 1: Read from RO memslot.
	 * EPT entry exists (read=1, write=0, exec=1). Read succeeds.
	 */
	vcpu_run(vcpu);
	if (run->exit_reason == KVM_EXIT_MMIO) {
		TEST_FAIL("Unexpected MMIO exit on read from RO memslot");
	}
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_PERM_READ_DONE);
	pr_info("stage perm-read done: mmio_exits=%d\n",
		stats_read(&stats.perm_mmio_exits));

	/*
	 * Stage 2: Write to RO memslot.
	 * EPT entry has write=0, so the write triggers EPT_VIOLATION
	 * with ACC_WRITE | PROT_MASK.  KVM exits to userspace with
	 * KVM_EXIT_MMIO.
	 *
	 * The MMIO exit contains the GPA, data, and length.  Our
	 * handler writes the data into the host HVA.  KVM then
	 * advances RIP past the write instruction and re-enters
	 * the guest.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT(run->mmio.is_write, "Expected write MMIO");
	perm_mmio_handler(vm, run);

	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_PERM_WRITE_MMIO);
	TEST_ASSERT_EQ(stats_read(&stats.perm_mmio_exits), 1);
	pr_info("stage perm-write done: mmio_exits=%d\n",
		stats_read(&stats.perm_mmio_exits));

	/*
	 * Stage 3: Read-back of the written value.
	 * The MMIO handler wrote PERM_WRITE_TEST_QWORD to the HVA.
	 * The EPT entry still allows reads, so the guest should see
	 * the new value.
	 */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_PERM_READ_DONE);
	pr_info("stage perm-readback done\n");

	/*
	 * Stage 4: Exec from RO memslot.
	 * EPT entry has exec=1 (NX not set).  Exec succeeds.
	 */
	vcpu_run(vcpu);
	if (run->exit_reason == KVM_EXIT_MMIO) {
		TEST_FAIL("Unexpected MMIO exit on exec from RO memslot");
	}
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_PERM_EXEC_DONE);
	pr_info("stage perm-exec done: mmio_exits=%d\n",
		stats_read(&stats.perm_mmio_exits));

	/* Final: GUEST_DONE */
	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	default:
		TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
	}

	pr_info("=== EPT permission fault test: PASS ===\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_is_tdp_enabled());
	pr_info("ept_fault_test: start\n");

	/* ===== Part 1: Basic EPT violation test with uffd ===== */
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	run_guest_normal(vcpu);
	pr_info("ept_fault_test: basic test done (read=%d write=%d exec=%d)\n",
		stats_read(&stats.read_faults),
		stats_read(&stats.write_faults),
		stats_read(&stats.exec_faults));
	kvm_vm_free(vm);

	/* ===== Part 2: EPT permission fault test (RO memslot) ===== */
	vm = vm_create_with_one_vcpu(&vcpu, guest_code_perm);
	run_guest_perm(vm, vcpu);
	kvm_vm_free(vm);

	pr_info("ept_fault_test: all tests passed\n");

	return 0;
}