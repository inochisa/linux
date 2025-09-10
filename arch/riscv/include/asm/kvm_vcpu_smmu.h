/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_VCPU_SMMU_H
#define __KVM_VCPU_SMMU_H

#include <linux/mm.h>
#include <linux/kvm_types.h>
#include <asm/page.h>

#define SEPGD_OFFSET		PAGE_SIZE
#define SPGD_GPGD_PTR		(SEPGD_OFFSET + 0x000)
#define SPGD_FLAG		(SEPGD_OFFSET + 0x008)
#define SPGD_VALID_MAP		(SEPGD_OFFSET + 0x200)
#define SPGD_GLOBAL_MAP		(SEPGD_OFFSET + 0x400)

#define SPGD_SIZE		(PAGE_SIZE * 2)

#define SPGD_FLAG_LEAF		BIT(0)

#define SPGD_GET(_base, _offset)		\
	((void *)((unsigned long)(_base) + (_offset)))

struct kvm_spte {
	struct {
		unsigned long _[PAGE_SIZE / sizeof(unsigned long)];
	} spgt;

	struct {
		union {
#if __riscv_xlen == 32
			u32 gpte_ptr;
			u32 _reserve;
#else
			u64 gpte_ptr;
#endif
		};
		u32 _reserve2[126];
#if __riscv_xlen == 32
		u32 valid_map[PAGE_SIZE / sizeof(unsigned long) / 32];
		u32 _reserve3[96];
#else
		u64 valid_map[PAGE_SIZE / sizeof(unsigned long) / 64];
		u32 _reserve3[112];
#endif

		u32 _[0x300];
	} espgt;
};

static const unsigned long kvm_spte_size = sizeof(struct kvm_spte);

struct kvm_spte_context {
	spinlock_t smmu_lock;
	void *spgd;
	phys_addr_t spgd_phys;
	int mmu_level;
};

int kvm_riscv_vcpu_smmu_init(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_smmu_deinit(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_smmu_put(struct kvm_vcpu *vcpu);
int kvm_riscv_handle_smmu_fault(struct kvm_vcpu *vcpu, struct kvm_run *run,
				unsigned long fault_addr);
void kvm_riscv_vcpu_smmu_reset(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_smmu_show_pte(struct kvm_vcpu *vcpu, unsigned long addr);

#endif
