// SPDX-License-Identifier: GPL-2.0
/*
 * Check for KVM_GET_REG_LIST regressions on x86.
 *
 * Copyright (C) 2025, [Author]
 *
 * x86's KVM_GET_REG_LIST currently enumerates a very small set of registers
 * compared to other architectures. The majority of x86 registers are accessed
 * via architecture-specific ioctls (e.g. KVM_GET_MSRS, KVM_GET_REGS). This
 * test covers the registers that ARE enumerable via KVM_GET_REG_LIST to ensure
 * there are no regressions in migration compatibility.
 */
#include <stdio.h>
#include "kvm_util.h"
#include "test_util.h"
#include "processor.h"

static __u64 base_regs[] = {
	0,
};

static struct vcpu_reg_list base_config = {
	.sublists = {
		{
			.name	= "base",
			.regs	= base_regs,
			.regs_n	= ARRAY_SIZE(base_regs),
		},
		{0},
	},
};

struct vcpu_reg_list *vcpu_configs[] = {
	&base_config,
};
int vcpu_configs_n = ARRAY_SIZE(vcpu_configs);

void finalize_vcpu(struct kvm_vcpu *vcpu, struct vcpu_reg_list *c)
{
	(void)c;
	base_regs[0] = KVM_X86_REG_KVM(KVM_REG_GUEST_SSP);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
}

bool check_supported_reg(struct kvm_vcpu *vcpu, __u64 reg)
{
	if (reg == KVM_X86_REG_KVM(KVM_REG_GUEST_SSP))
		return vcpu_cpuid_has(vcpu, X86_FEATURE_SHSTK);

	return true;
}

void print_reg(const char *prefix, __u64 id)
{
	(void)prefix;
	if (id == KVM_X86_REG_KVM(KVM_REG_GUEST_SSP))
		printf("\tKVM_X86_REG_KVM(KVM_REG_GUEST_SSP),\n");
	else
		printf("\t0x%llx,\n", id);
}
