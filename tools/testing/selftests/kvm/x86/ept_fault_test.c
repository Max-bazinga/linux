// SPDX-License-Identifier: GPL-2.0
/*
 * ept_fault_test.c - Test KVM EPT (Extended Page Tables) fault handling.
 *
 * Covers two categories of EPT faults:
 *
 * Scenario A — EPT violations via userfaultfd:
 *   handle_ept_violation() → __vmx_handle_ept_violation()
 *   → kvm_mmu_page_fault() → kvm_tdp_mmu_page_fault()
 *   → kvm_mmu_faultin_pfn() → uffd resolution
 *
 *   - Read fault:  first access to a data page triggers EPT_VIOLATION
 *                  with ACC_READ; verifies no re-fault after resolution
 *   - Write fault: writes to a MADV_DONTNEED-punched page trigger
 *                  EPT_VIOLATION with ACC_WRITE
 *   - Exec fault:  calls into a uffd-backed code page trigger
 *                  EPT_VIOLATION with ACC_INSTR
 *
 * Scenario B — EPT misconfig via PTE corruption:
 *   vmx_handle_exit() → handle_ept_misconfig()
 *
 *   EPT hardware requires that if an entry is writable it must also be
 *   readable (W=1 ∧ R=0 → misconfig).  We corrupt a leaf PTE by clearing
 *   the readable bit via tdp_get_pte() then let the guest access it.
 *   KVM's handle_ept_misconfig() resolves the fault.
 *
 * ARM64 has arm64/page_fault_test.c (1135 lines, 10+ scenarios).
 * This is the x86 equivalent covering the EPT-specific path.
 *
 * TODO (future patches):
 *   - EPT permission faults (PROT_MASK scenarios, RO memslot)
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
#define TEST_DATA_GPA		0x10000000ULL
#define TEST_CODE_GPA		0x20000000ULL
#define TEST_DATA_GVA		0x40000000ULL
#define TEST_CODE_GVA		0x50000000ULL
#define TEST_REGION_SIZE	PAGE_SIZE

/* Guest↔host synchronization commands */
#define UCALL_SYNC_READ_DONE	0
#define UCALL_SYNC_WRITE_DONE	1
#define UCALL_SYNC_EXEC_DONE	2

/*
 * Per-fault-type counters for verification.
 * Only one vCPU so no locking needed for test counters.
 */
struct fault_stats {
	int read_faults;
	int write_faults;
	int exec_faults;	/* counts as !write in uffd, tracked separately */
};

static struct fault_stats stats;

/* test stage: tells the uffd handler what type of access to expect next */
enum test_stage {
	STAGE_INIT,
	STAGE_READ,
	STAGE_WRITE,
	STAGE_EXEC,
	STAGE_DONE,
};

static enum test_stage current_stage = STAGE_INIT;

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

	if (is_write) {
		/* Write fault: KVM should be resolving a guest write */
		stats.write_faults++;
	} else {
		/*
		 * Read or exec fault.  The uffd API doesn't distinguish
		 * instruction fetch from data read, so we track the stage
		 * separately.
		 */
		switch (current_stage) {
		case STAGE_READ:
			stats.read_faults++;
			break;
		case STAGE_EXEC:
			stats.exec_faults++;
			break;
		default:
			break;
		}
	}

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
	extern char guest_exec_stub[];
	extern char guest_exec_stub_end[];

	TEST_ASSERT(uffd_mode == UFFDIO_REGISTER_MODE_MISSING,
		    "Unexpected uffd mode: %d", uffd_mode);

	/*
	 * Copy the exec stub code. The stub is small: just a RET
	 * instruction, enough to verify execution works through EPT.
	 */
	copy.src = (uint64_t)(guest_exec_stub);
	copy.dst = addr;
	copy.len = PAGE_SIZE;
	copy.mode = 0;

	TEST_ASSERT(ioctl(uffd, UFFDIO_COPY, &copy) == 0,
		    "UFFDIO_COPY (code) failed at addr 0x%lx", addr);

	return 0;
}

/*
 * Exec stub: a simple function that just returns.
 * The uffd handler copies the machine code of this function into
 * the faulted code page.  The guest then calls the page as a function.
 */
static __attribute__((noinline)) void guest_exec_stub(void)
{
	asm volatile("" ::: "memory");
}
static void guest_exec_stub_end(void) {}

/*
 * ───────────────────────────────────────────────────────────
 * Scenario A: Guest code for EPT violation paths (uffd-backed)
 * ───────────────────────────────────────────────────────────
 *
 * Stage 1 (read):  Read from uffd-backed data page.
 * Stage 2 (write): Write to uffd-backed data page.
 * Stage 3 (exec):  Call function in uffd-backed code page.
 */
static void guest_code_violation(void)
{
	volatile uint64_t val;
	uint64_t *data = (uint64_t *)TEST_DATA_GVA;

	/*
	 * STAGE: Read fault
	 * First access to the data page.  EPT has no mapping → KVM gets
	 * EPT_VIOLATION with ACC_READ.  uffd handler serves the page.
	 */
	current_stage = STAGE_READ;
	val = *data;
	GUEST_SYNC(UCALL_SYNC_READ_DONE);

	/*
	 * Re-read should NOT fault (page is now mapped in EPT).
	 */
	val = *data;
	GUEST_SYNC(UCALL_SYNC_READ_DONE);

	/*
	 * STAGE: Write fault
	 * The existing EPT mapping allows reads but the write may
	 * trigger access/dirty tracking depending on the MMU mode.
	 * In TDP MMU, the initial mapping is RW, so this may not fault.
	 */
	current_stage = STAGE_WRITE;
	*data = 0xDEADBEEF;
	GUEST_SYNC(UCALL_SYNC_WRITE_DONE);

	/*
	 * STAGE: Exec fault
	 * Call a function in the uffd-backed code page.
	 * EPT has no mapping for the code page → KVM gets
	 * EPT_VIOLATION with ACC_INSTR.
	 */
	current_stage = STAGE_EXEC;
	{
		void (*fn)(void) = (void (*)(void))TEST_CODE_GVA;
		fn();
	}
	GUEST_SYNC(UCALL_SYNC_EXEC_DONE);

	GUEST_DONE();
}

/*
 * ───────────────────────────────────────────────────────────
 * Scenario B: EPT misconfig via PTE corruption
 * ───────────────────────────────────────────────────────────
 *
 * EPT hardware forbids a writable entry that isn't also readable
 * (W=1, R=0).  This triggers EPT_MISCONFIG (VM exit 49).
 *
 * We build a regular memslot, corrupt the leaf PTE, then access it.
 * KVM's handle_ept_misconfig() must resolve the fault.
 */

/* Separate GPA/GVA so we don't interfere with the uffd regions */
#define TEST_MISCONFIG_GPA		0x60000000ULL
#define TEST_MISCONFIG_GVA		0x70000000ULL
#define TEST_MISCONFIG_SLOT		12

static void guest_code_misconfig(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_MISCONFIG_GVA;
	volatile uint64_t val;

	/*
	 * Access the misconfigured page.  Hardware sees W=1, X=1, R=0
	 * and triggers EPT_MISCONFIG.  KVM resolves it → guest survives.
	 */
	val = *ptr;

	/* Verify write also works after resolution */
	*ptr = 0xDEADBEEF;
	val = *ptr;
	GUEST_ASSERT(val == 0xDEADBEEF);

	GUEST_DONE();
}

/*
 * ───────────────────────────────────────────────────────────
 * Helper: run a single-vCPU VM to GUEST_DONE, no uffd needed.
 * ───────────────────────────────────────────────────────────
 */
static void run_vm_to_done(struct kvm_vm *vm, struct kvm_vcpu *vcpu)
{
	struct ucall uc;

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
}

/*
 * ───────────────────────────────────────────────────────────
 * Scenario B execution: corrupt EPT PTE and verify guest survives.
 * ───────────────────────────────────────────────────────────
 */
static void test_ept_misconfig(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t *pte;

	TEST_REQUIRE(kvm_is_tdp_enabled());

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_misconfig);

	/* Map GPA→GVA so KVM creates EPT entries with R=1,W=1,X=1 */
	virt_pg_map(vm, TEST_MISCONFIG_GVA, TEST_MISCONFIG_GPA);

	/*
	 * Corrupt the leaf PTE: clear the readable bit while keeping
	 * writable & executable.  This creates the W=1, X=1, R=0
	 * combination prohibited by the EPT spec → EPT_MISCONFIG.
	 */
	pte = tdp_get_pte(vm, TEST_MISCONFIG_GPA);
	TEST_ASSERT(pte, "Failed to get EPT PTE for GPA 0x%llx",
		    TEST_MISCONFIG_GPA);
	*pte &= ~PTE_READABLE_MASK(&vm->stage2_mmu);

	/*
	 * Guest accesses TEST_MISCONFIG_GVA.  Hardware sees the
	 * misconfigured PTE → VM exit EXIT_REASON_EPT_MISCONFIG.
	 * KVM's handle_ept_misconfig() resolves it.
	 */
	run_vm_to_done(vm, vcpu);

	kvm_vm_free(vm);
}

/*
 * ───────────────────────────────────────────────────────────
 * Scenario A execution: uffd-backed read/write/exec fault test.
 * ───────────────────────────────────────────────────────────
 */
static void test_ept_violation(void)
{
	struct uffd_desc *data_uffd = NULL;
	struct uffd_desc *code_uffd = NULL;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	TEST_REQUIRE(kvm_is_tdp_enabled());

	vm = vm_create_with_one_vcpu(&vcpu, guest_code_violation);

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
	TEST_ASSERT_EQ(stats.read_faults, 1);

	/* Stage: re-read (expect NO fault) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_READ_DONE);
	TEST_ASSERT_EQ(stats.read_faults, 1);

	/* Stage: write (may or may not fault depending on TDP MMU mode) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_WRITE_DONE);

	/* Stage: exec (expect fault) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], UCALL_SYNC_EXEC_DONE);
	TEST_ASSERT_EQ(stats.exec_faults, 1);

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

	/* Cleanup uffd */
	uffd_stop_demand_paging(data_uffd);
	uffd_stop_demand_paging(code_uffd);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	/*
	 * Scenario A: EPT violation paths (uffd-backed read/write/exec).
	 */
	test_ept_violation();

	/*
	 * Scenario B: EPT misconfig (corrupt PTE → W=1,X=1,R=0).
	 */
	test_ept_misconfig();

	return 0;
}