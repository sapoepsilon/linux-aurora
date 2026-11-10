// SPDX-License-Identifier: GPL-2.0-only
/*
 * Contains implementation-defined CPU feature definitions.
 */

#define pr_fmt(fmt) "CPU features: " fmt

#include <asm/cpufeature.h>
#include <asm/apple_cpufeature.h>
#include <asm/virt.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/printk.h>

#ifdef CONFIG_ARM64_MEMORY_MODEL_CONTROL
static bool has_apple_feature(const struct arm64_cpu_capabilities *entry, int scope)
{
	u64 val;
	WARN_ON(scope == SCOPE_LOCAL_CPU && preemptible());

	if (read_cpuid_implementor() != ARM_CPU_IMP_APPLE)
		return false;

	val = read_sysreg(aidr_el1);
	return cpufeature_matches(val, entry);
}

static bool has_apple_tso(const struct arm64_cpu_capabilities *entry, int scope)
{
	u64 val;

	if (!has_apple_feature(entry, scope))
		return false;

	/*
	 * KVM and old versions of the macOS hypervisor will advertise TSO in
	 * AIDR_EL1, but then ignore writes to ACTLR_EL1. Test that the bit is
	 * actually writable before enabling TSO.
	 */

	val = read_sysreg(actlr_el1);
	write_sysreg(val ^ ACTLR_APPLE_TSO, actlr_el1);
	if (!((val ^ read_sysreg(actlr_el1)) & ACTLR_APPLE_TSO)) {
		pr_info_once("CPU advertises Apple TSO but it is broken, ignoring\n");
		return false;
	}

	write_sysreg(val, actlr_el1);
	return true;
}

static bool has_tso_fixed(const struct arm64_cpu_capabilities *entry, int scope)
{
	/* List of CPUs that always use the TSO memory model */
	static const struct midr_range fixed_tso_list[] = {
		MIDR_ALL_VERSIONS(MIDR_NVIDIA_DENVER),
		MIDR_ALL_VERSIONS(MIDR_NVIDIA_CARMEL),
		MIDR_ALL_VERSIONS(MIDR_FUJITSU_A64FX),
		{ /* sentinel */ }
	};

	return is_midr_in_range_list(fixed_tso_list);
}
#endif

static bool has_apple_actlr_virt_impdef(const struct arm64_cpu_capabilities *entry, int scope)
{
	u64 midr = read_cpuid_id() & MIDR_CPU_MODEL_MASK;

	return midr >= MIDR_APPLE_M1_ICESTORM && midr <= MIDR_APPLE_M1_FIRESTORM_MAX;
}

static bool has_apple_actlr_virt(const struct arm64_cpu_capabilities *entry, int scope)
{
	u64 midr = read_cpuid_id() & MIDR_CPU_MODEL_MASK;

	return midr >= MIDR_APPLE_M2_BLIZZARD && midr <= MIDR_CPU_MODEL(ARM_CPU_IMP_APPLE, 0xfff);
}

/*
 * The Apple pointer authentication registers that a hypervisor needs to
 * run guests (APCTL, KERNKEY, APSTS, APVMKEY) are accessible at EL2 on M1
 * and M2. No ID register advertises them, so match the parts by MIDR.
 * This is the M1 and M2 part of m1n1's table of CPUs whose Apple system
 * registers are unlocked; t6002 and t6022 report t6001 and t6021 parts.
 */
static const struct midr_range apple_pauth_virt_cpus[] = {
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM_PRO),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM_PRO),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_ICESTORM_MAX),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M1_FIRESTORM_MAX),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_BLIZZARD),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_AVALANCHE),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_BLIZZARD_PRO),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_AVALANCHE_PRO),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_BLIZZARD_MAX),
	MIDR_ALL_VERSIONS(MIDR_APPLE_M2_AVALANCHE_MAX),
	{},
};

static bool has_apple_pauth_virt(const struct arm64_cpu_capabilities *entry, int scope)
{
	return is_kernel_in_hyp_mode() &&
	       is_midr_in_range_list(apple_pauth_virt_cpus);
}

static const struct arm64_cpu_capabilities arm64_impdef_features[] = {
#ifdef CONFIG_ARM64_MEMORY_MODEL_CONTROL
	{
		.desc = "TSO memory model (Apple)",
		.capability = ARM64_HAS_TSO_APPLE,
		.type = ARM64_CPUCAP_EARLY_LOCAL_CPU_FEATURE,
		.matches = has_apple_tso,
		.field_pos = AIDR_APPLE_TSO_SHIFT,
		.field_width = 1,
		.sign = FTR_UNSIGNED,
		.min_field_value = 1,
		.max_field_value = 1,
	},
	{
		.desc = "TSO memory model (Fixed)",
		.capability = ARM64_HAS_TSO_FIXED,
		.type = ARM64_CPUCAP_EARLY_LOCAL_CPU_FEATURE,
		.matches = has_tso_fixed,
	},
#endif
	{
		.desc = "ACTLR virtualization (IMPDEF, Apple)",
		.capability = ARM64_HAS_ACTLR_VIRT_APPLE,
		.type = ARM64_CPUCAP_EARLY_LOCAL_CPU_FEATURE,
		.matches = has_apple_actlr_virt_impdef,
	},
	{
		.desc = "ACTLR virtualization (architectural?)",
		.capability = ARM64_HAS_ACTLR_VIRT,
		.type = ARM64_CPUCAP_EARLY_LOCAL_CPU_FEATURE,
		.matches = has_apple_actlr_virt,
	},
	{
		.desc = "PAuth virtualization (IMPDEF, Apple)",
		.capability = ARM64_HAS_PAUTH_VIRT_APPLE,
		.type = ARM64_CPUCAP_EARLY_LOCAL_CPU_FEATURE,
		.matches = has_apple_pauth_virt,
	},
	{},
};

void __init init_cpucap_indirect_list_impdef(void)
{
	init_cpucap_indirect_list_from_array(arm64_impdef_features);
}
