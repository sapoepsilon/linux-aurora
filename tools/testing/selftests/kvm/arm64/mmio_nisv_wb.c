// SPDX-License-Identifier: GPL-2.0-only
/*
 * mmio_nisv_wb - Test NISV MMIO load/store-immediate writeback emulation and
 * KVM_CAP_ARM_NISV_TO_USER precedence.
 *
 * Verifies:
 *  1. Pre-index and post-index MMIO writeback on userspace-handled MMIO:
 *     base register Rn is unchanged while stopped in KVM_EXIT_MMIO and updated
 *     strictly once on completion.
 *  2. Pre-index and post-index MMIO writeback on in-kernel MMIO (vGICv3):
 *     completes in-kernel without KVM_EXIT_MMIO and updates Rn strictly once.
 *  3. Aborted MMIO (userspace injects SEA via KVM_SET_VCPU_EVENTS):
 *     Rn is never modified and the guest exception handler sees original Rn.
 *  4. Replayed MMIO (userspace clears exit_reason to re-execute the faulting
 *     instruction, and immediate_exit re-entry): Rn is never double-applied.
 *  5. CONSTRAINED UNPREDICTABLE writeback forms with Rt == Rn (both loads and
 *     stores, pre-index and post-index) are rejected cleanly without mutating
 *     Rn.
 *  6. KVM_CAP_ARM_NISV_TO_USER takes precedence over in-kernel NISV
 *     load/store-immediate decoding on both userspace and in-kernel MMIO
 *     addresses.
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <linux/sizes.h>

#include "processor.h"
#include "test_util.h"
#include "gic.h"
#include "gic_v3.h"
#include "vgic.h"

#define MMIO_ADDR		0x8000000ULL
#define MMIO_STRIDE_OFF		0x10ULL
#define MMIO_NEG_OFF		0x8ULL

static u64 expected_abort_pc;
static u64 expected_abort_x8;

static void expect_sea_wb_handler(struct ex_regs *regs)
{
	u64 esr = read_sysreg(esr_el1);

	GUEST_ASSERT_EQ(regs->pc, expected_abort_pc);
	GUEST_ASSERT_EQ(regs->regs[8], expected_abort_x8);
	GUEST_ASSERT_EQ(ESR_ELx_EC(esr), ESR_ELx_EC_DABT_CUR);
	GUEST_ASSERT_EQ(esr & ESR_ELx_FSC_TYPE, ESR_ELx_FSC_EXTABT);

	GUEST_DONE();
}

static void unexpected_dabt_handler(struct ex_regs *regs)
{
	GUEST_FAIL("Unexpected data abort at PC: %lx", regs->pc);
}

static struct kvm_vm *vm_create_mmio(struct kvm_vcpu **vcpu, void *guest_code,
				     handler_fn dabt_handler)
{
	struct kvm_vm *vm = vm_create_with_one_vcpu(vcpu, guest_code);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(*vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT, ESR_ELx_EC_DABT_CUR,
				dabt_handler);
	virt_map(vm, MMIO_ADDR, MMIO_ADDR, 1);

	return vm;
}

static void vcpu_inject_sea(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_events events = {};

	events.exception.ext_dabt_pending = true;
	vcpu_events_set(vcpu, &events);
}

static u64 vcpu_get_x(struct kvm_vcpu *vcpu, unsigned int reg)
{
	return vcpu_get_reg(vcpu, ARM64_CORE_REG(regs.regs[reg]));
}

static void expect_ucall_sync2(struct kvm_vcpu *vcpu, u64 arg0, u64 arg1)
{
	struct ucall uc;

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_SYNC:
		TEST_ASSERT_EQ(uc.args[1], arg0);
		TEST_ASSERT_EQ(uc.args[2], arg1);
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	default:
		TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
	}
}

static void expect_ucall_done(struct kvm_vcpu *vcpu)
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
		TEST_FAIL("Expected UCALL_DONE, got %lu", uc.cmd);
	}
}

/* --- 1. Pre-index userspace MMIO (load + store, positive & negative imm) --- */

static void guest_pre_index_user(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9") = 0x1122334455667788ULL;

	/* Pre-index store (+16): writes to MMIO_ADDR + 16, x8 -> MMIO_ADDR + 16 */
	asm volatile("str x9, [x8, #16]!"
		     : "+r"(base) : "r"(val) : "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	/* Pre-index load (-8): reads MMIO_ADDR + 8, x8 -> MMIO_ADDR + 8 */
	asm volatile("ldr x9, [x8, #-8]!"
		     : "+r"(base), "=r"(val) :: "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	GUEST_DONE();
}

static void test_pre_index_userspace(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_mmio(&vcpu, guest_pre_index_user,
					   unexpected_dabt_handler);
	struct kvm_run *run = vcpu->run;
	u64 stored = 0, ret_val = 0xdeadbeefcafebabeULL;

	/* Pre-index store exit */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(run->mmio.is_write, "Expected MMIO write");
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + MMIO_STRIDE_OFF);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	memcpy(&stored, run->mmio.data, 8);
	TEST_ASSERT_EQ(stored, 0x1122334455667788ULL);
	/* Base register MUST NOT be updated before completion */
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	expect_ucall_sync2(vcpu, MMIO_ADDR + MMIO_STRIDE_OFF,
			   0x1122334455667788ULL);

	/* Pre-index negative-offset load exit */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(!run->mmio.is_write, "Expected MMIO read");
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + MMIO_NEG_OFF);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	/* Base register MUST NOT be updated before completion */
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR + MMIO_STRIDE_OFF);
	memcpy(run->mmio.data, &ret_val, 8);

	expect_ucall_sync2(vcpu, MMIO_ADDR + MMIO_NEG_OFF, ret_val);
	expect_ucall_done(vcpu);

	kvm_vm_free(vm);
	ksft_test_result_pass("pre_index_userspace\n");
}

/* --- 2. Post-index userspace MMIO (load + store, positive & negative imm) --- */

static void guest_post_index_user(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9") = 0xaabbccdd11223344ULL;

	/* Post-index store (+16): writes MMIO_ADDR, x8 -> MMIO_ADDR + 16 */
	asm volatile("str x9, [x8], #16"
		     : "+r"(base) : "r"(val) : "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	/* Post-index load (-8): reads MMIO_ADDR + 16, x8 -> MMIO_ADDR + 8 */
	asm volatile("ldr x9, [x8], #-8"
		     : "+r"(base), "=r"(val) :: "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	GUEST_DONE();
}

static void test_post_index_userspace(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_mmio(&vcpu, guest_post_index_user,
					   unexpected_dabt_handler);
	struct kvm_run *run = vcpu->run;
	u64 stored = 0, ret_val = 0xfeedface01234567ULL;

	/* Post-index store exit */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(run->mmio.is_write, "Expected MMIO write");
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	memcpy(&stored, run->mmio.data, 8);
	TEST_ASSERT_EQ(stored, 0xaabbccdd11223344ULL);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	expect_ucall_sync2(vcpu, MMIO_ADDR + MMIO_STRIDE_OFF,
			   0xaabbccdd11223344ULL);

	/* Post-index negative-offset load exit */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT(!run->mmio.is_write, "Expected MMIO read");
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + MMIO_STRIDE_OFF);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR + MMIO_STRIDE_OFF);
	memcpy(run->mmio.data, &ret_val, 8);

	expect_ucall_sync2(vcpu, MMIO_ADDR + MMIO_NEG_OFF, ret_val);
	expect_ucall_done(vcpu);

	kvm_vm_free(vm);
	ksft_test_result_pass("post_index_userspace\n");
}

/* --- 3. In-kernel MMIO (vGICv3) pre-index and post-index writeback --- */

static void guest_inkernel_vgic(void)
{
	register u64 base asm("x8") = GICD_BASE_GPA;
	register u32 typer1 asm("w9");
	register u32 typer2 asm("w10");

	/* Pre-index: reads GICD_BASE_GPA + GICD_TYPER (0x4), x8 -> +4 */
	asm volatile("ldr w9, [x8, #4]!"
		     : "+r"(base), "=r"(typer1) :: "memory");
	GUEST_SYNC_ARGS(0, base, typer1, 0, 0);

	/* Post-index: reads GICD_BASE_GPA + GICD_TYPER (0x4), x8 -> +8 */
	asm volatile("ldr w10, [x8], #4"
		     : "+r"(base), "=r"(typer2) :: "memory");
	GUEST_SYNC_ARGS(0, base, typer2, 0, 0);

	GUEST_ASSERT_EQ(typer1, typer2);
	GUEST_DONE();
}

static void test_inkernel_vgic_writeback(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	int gic_fd;
	u64 typer1, typer2;

	if (!kvm_supports_vgic_v3()) {
		ksft_test_result_skip("inkernel_vgic_writeback (no vGICv3)\n");
		return;
	}

	vm = vm_create_mmio(&vcpu, guest_inkernel_vgic,
			    unexpected_dabt_handler);
	gic_fd = vgic_v3_setup(vm, 1, 64);
	TEST_ASSERT(gic_fd >= 0, "Failed to create vGICv3");

	/* Both reads must be handled in-kernel (no KVM_EXIT_MMIO) */
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], GICD_BASE_GPA + GICD_TYPER);
	typer1 = uc.args[2];

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], GICD_BASE_GPA + GICD_IIDR);
	typer2 = uc.args[2];
	TEST_ASSERT_EQ(typer1, typer2);

	expect_ucall_done(vcpu);

	close(gic_fd);
	kvm_vm_free(vm);
	ksft_test_result_pass("inkernel_vgic_writeback\n");
}

/* --- 4. Aborted MMIO (SEA injection) must leave Rn untouched --- */

extern char abort_pre_insn, abort_post_insn;

static void guest_abort_pre(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9") = 0x55aa55aaULL;

	WRITE_ONCE(expected_abort_pc, (u64)&abort_pre_insn);
	WRITE_ONCE(expected_abort_x8, MMIO_ADDR);

	asm volatile("abort_pre_insn:\n\t"
		     "str x9, [x8, #16]!\n\t"
		     : "+r"(base) : "r"(val) : "memory");
	GUEST_FAIL("Aborted pre-index store must not retire");
}

static void guest_abort_post(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9");

	WRITE_ONCE(expected_abort_pc, (u64)&abort_post_insn);
	WRITE_ONCE(expected_abort_x8, MMIO_ADDR);

	asm volatile("abort_post_insn:\n\t"
		     "ldr x9, [x8], #16\n\t"
		     : "+r"(base), "=r"(val) :: "memory");
	GUEST_FAIL("Aborted post-index load must not retire");
}

static void run_abort_case(void *guest_fn, const char *name, u64 expect_ipa,
			   bool expect_write)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_mmio(&vcpu, guest_fn,
					   expect_sea_wb_handler);
	struct kvm_run *run = vcpu->run;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, expect_ipa);
	TEST_ASSERT_EQ(!!run->mmio.is_write, expect_write);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	vcpu_inject_sea(vcpu);
	expect_ucall_done(vcpu);

	kvm_vm_free(vm);
	ksft_test_result_pass("%s\n", name);
}

/* --- 5. Replayed MMIO (abandoned exit + re-execute) applies wb strictly once --- */

static void guest_replay_wb(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9") = 0xcafe0001ULL;

	asm volatile("str x9, [x8, #16]!"
		     : "+r"(base) : "r"(val) : "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	asm volatile("ldr x9, [x8], #16"
		     : "+r"(base), "=r"(val) :: "memory");
	GUEST_SYNC_ARGS(0, base, val, 0, 0);

	GUEST_DONE();
}

static void test_replay_single_writeback(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_mmio(&vcpu, guest_replay_wb,
					   unexpected_dabt_handler);
	struct kvm_run *run = vcpu->run;
	u64 load_val = 0x123456789abcdef0ULL;

	/* First exit for pre-index store -> replay without completing */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + 16);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + 16);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	/* Complete store once; x8 must be MMIO_ADDR + 16 (not +32) */
	expect_ucall_sync2(vcpu, MMIO_ADDR + 16, 0xcafe0001ULL);

	/* First exit for post-index load -> replay without completing */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + 16);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR + 16);

	run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, MMIO_ADDR + 16);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR + 16);

	/* Complete load with immediate_exit=1 first to test idempotent return */
	memcpy(run->mmio.data, &load_val, 8);
	run->immediate_exit = 1;
	TEST_ASSERT(_vcpu_run(vcpu) == -1 && errno == EINTR,
		    "Expected EINTR with immediate_exit");
	run->immediate_exit = 0;

	/* x8 must be MMIO_ADDR + 32 (not +48) */
	expect_ucall_sync2(vcpu, MMIO_ADDR + 32, load_val);
	expect_ucall_done(vcpu);

	kvm_vm_free(vm);
	ksft_test_result_pass("replay_single_writeback\n");
}

/* --- 6. Writeback with Rt == Rn rejected (loads & stores, pre & post) --- */

static void guest_rt_eq_rn_str_pre(void)
{
	register u64 base asm("x8") = MMIO_ADDR;

	/* .inst 0xf8008d08 = str x8, [x8, #8]! */
	asm volatile(".inst 0xf8008d08" : "+r"(base) :: "memory");
	GUEST_FAIL("CONSTRAINED UNPREDICTABLE str x8, [x8, #8]! must not retire");
}

static void guest_rt_eq_rn_str_post(void)
{
	register u64 base asm("x8") = MMIO_ADDR;

	/* .inst 0xf8008508 = str x8, [x8], #8 */
	asm volatile(".inst 0xf8008508" : "+r"(base) :: "memory");
	GUEST_FAIL("CONSTRAINED UNPREDICTABLE str x8, [x8], #8 must not retire");
}

static void guest_rt_eq_rn_ldr_pre(void)
{
	register u64 base asm("x8") = MMIO_ADDR;

	/* .inst 0xf8408d08 = ldr x8, [x8, #8]! */
	asm volatile(".inst 0xf8408d08" : "+r"(base) :: "memory");
	GUEST_FAIL("CONSTRAINED UNPREDICTABLE ldr x8, [x8, #8]! must not retire");
}

static void guest_rt_eq_rn_ldr_post(void)
{
	register u64 base asm("x8") = MMIO_ADDR;

	/* .inst 0xf8408508 = ldr x8, [x8], #8 */
	asm volatile(".inst 0xf8408508" : "+r"(base) :: "memory");
	GUEST_FAIL("CONSTRAINED UNPREDICTABLE ldr x8, [x8], #8 must not retire");
}

static void run_rt_eq_rn_case(void *guest_fn, const char *name)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm = vm_create_mmio(&vcpu, guest_fn,
					   unexpected_dabt_handler);

	TEST_ASSERT(_vcpu_run(vcpu) == -1 && errno == ENOSYS,
		    "%s: expected -ENOSYS", name);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	kvm_vm_free(vm);
	ksft_test_result_pass("%s\n", name);
}

/* --- 7. KVM_CAP_ARM_NISV_TO_USER precedence over emulate_nisv_ldst --- */

extern char nisv_user_pre_insn, nisv_vgic_post_insn;

static void guest_nisv_precedence_user(void)
{
	register u64 base asm("x8") = MMIO_ADDR;
	register u64 val asm("x9") = 0x42;

	WRITE_ONCE(expected_abort_pc, (u64)&nisv_user_pre_insn);
	WRITE_ONCE(expected_abort_x8, MMIO_ADDR);

	asm volatile("nisv_user_pre_insn:\n\t"
		     "str x9, [x8, #16]!\n\t"
		     : "+r"(base) : "r"(val) : "memory");
	GUEST_FAIL("Expected KVM_EXIT_ARM_NISV, not silent emulation");
}

static void guest_nisv_precedence_vgic(void)
{
	register u64 base asm("x8") = GICD_BASE_GPA + GICD_TYPER;
	register u32 val asm("w9");

	WRITE_ONCE(expected_abort_pc, (u64)&nisv_vgic_post_insn);
	WRITE_ONCE(expected_abort_x8, GICD_BASE_GPA + GICD_TYPER);

	asm volatile("nisv_vgic_post_insn:\n\t"
		     "ldr w9, [x8], #4\n\t"
		     : "+r"(base), "=r"(val) :: "memory");
	GUEST_FAIL("Expected KVM_EXIT_ARM_NISV on vGIC, not in-kernel emulation");
}

static void test_nisv_to_user_precedence(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct kvm_run *run;
	int gic_fd;

	/* Userspace MMIO range with KVM_CAP_ARM_NISV_TO_USER */
	vm = vm_create_mmio(&vcpu, guest_nisv_precedence_user,
			    expect_sea_wb_handler);
	vm_enable_cap(vm, KVM_CAP_ARM_NISV_TO_USER, 1);
	run = vcpu->run;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_ARM_NISV);
	TEST_ASSERT_EQ(run->arm_nisv.fault_ipa, MMIO_ADDR + 16);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), MMIO_ADDR);

	vcpu_inject_sea(vcpu);
	expect_ucall_done(vcpu);
	kvm_vm_free(vm);
	ksft_test_result_pass("nisv_to_user_precedence_user_mmio\n");

	/* In-kernel vGIC range with KVM_CAP_ARM_NISV_TO_USER */
	if (!kvm_supports_vgic_v3()) {
		ksft_test_result_skip("nisv_to_user_precedence_vgic (no vGICv3)\n");
		return;
	}

	vm = vm_create_mmio(&vcpu, guest_nisv_precedence_vgic,
			    expect_sea_wb_handler);
	gic_fd = vgic_v3_setup(vm, 1, 64);
	TEST_ASSERT(gic_fd >= 0, "Failed to create vGICv3");
	vm_enable_cap(vm, KVM_CAP_ARM_NISV_TO_USER, 1);
	run = vcpu->run;

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_ARM_NISV);
	TEST_ASSERT_EQ(run->arm_nisv.fault_ipa, GICD_BASE_GPA + GICD_TYPER);
	TEST_ASSERT_EQ(vcpu_get_x(vcpu, 8), GICD_BASE_GPA + GICD_TYPER);

	vcpu_inject_sea(vcpu);
	expect_ucall_done(vcpu);
	close(gic_fd);
	kvm_vm_free(vm);
	ksft_test_result_pass("nisv_to_user_precedence_vgic\n");
}

int main(void)
{
	ksft_print_header();
	ksft_set_plan(12);

	test_pre_index_userspace();
	test_post_index_userspace();
	test_inkernel_vgic_writeback();
	run_abort_case(guest_abort_pre, "abort_pre_index_no_wb",
		       MMIO_ADDR + 16, true);
	run_abort_case(guest_abort_post, "abort_post_index_no_wb",
		       MMIO_ADDR, false);
	test_replay_single_writeback();
	run_rt_eq_rn_case(guest_rt_eq_rn_str_pre, "rt_eq_rn_str_pre_rejected");
	run_rt_eq_rn_case(guest_rt_eq_rn_str_post, "rt_eq_rn_str_post_rejected");
	run_rt_eq_rn_case(guest_rt_eq_rn_ldr_pre, "rt_eq_rn_ldr_pre_rejected");
	run_rt_eq_rn_case(guest_rt_eq_rn_ldr_post, "rt_eq_rn_ldr_post_rejected");
	test_nisv_to_user_precedence();

	ksft_finished();
}
