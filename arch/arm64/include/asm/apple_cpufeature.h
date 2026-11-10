// SPDX-License-Identifier: GPL-2.0

#ifndef __ASM_APPLE_CPUFEATURES_H
#define __ASM_APPLE_CPUFEATURES_H

#include <linux/bits.h>
#include <asm/sysreg.h>

#define AIDR_APPLE_TSO_SHIFT	9
#define AIDR_APPLE_TSO		BIT(9)

#define ACTLR_APPLE_TSO_SHIFT	1
#define ACTLR_APPLE_TSO		BIT(1)

/*
 * Apple pointer authentication extension (M1/M2), encodings as in m1n1.
 * EL1 registers, and their EL12 aliases for a VHE hypervisor:
 */
#define SYS_IMP_APL_APCTL_EL1		sys_reg(3, 4, 15, 0, 4)
#define SYS_IMP_APL_KERNKEYLO_EL1	sys_reg(3, 4, 15, 1, 0)
#define SYS_IMP_APL_KERNKEYHI_EL1	sys_reg(3, 4, 15, 1, 1)
#define SYS_IMP_APL_APSTS_EL1		sys_reg(3, 6, 15, 12, 4)
#define SYS_IMP_APL_APCTL_EL12		sys_reg(3, 6, 15, 15, 0)
#define SYS_IMP_APL_KERNKEYLO_EL12	sys_reg(3, 6, 15, 2, 3)
#define SYS_IMP_APL_KERNKEYHI_EL12	sys_reg(3, 6, 15, 2, 4)
#define SYS_IMP_APL_APSTS_EL12		sys_reg(3, 6, 15, 14, 7)
/* EL2 only: the VM key, which a guest's effective keys depend on */
#define SYS_IMP_APL_APVMKEYLO_EL2	sys_reg(3, 6, 15, 14, 4)
#define SYS_IMP_APL_APVMKEYHI_EL2	sys_reg(3, 6, 15, 14, 5)

/* APSTS_EL12: select the virtualized PAuth state for the guest */
#define APSTS_APPLE_VM_KEY		BIT(0)

#endif
