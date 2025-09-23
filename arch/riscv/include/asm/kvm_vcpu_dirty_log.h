/* SPDX-License-Identifier: GPL-2.0-only */


#ifndef __KVM_VCPU_RISCV_DIRTY_LOG_H
#define __KVM_VCPU_RISCV_DIRTY_LOG_H

#include <linux/kvm_types.h>
#include <linux/bits.h>
#include <asm/csr.h>

#define KVM_VCPU_DIRTY_LOG_BUFFER_MAX_SIZE		0x400000

#define DIRTY_LOG_ENTRY32_PFN		GENMASK(31, 10)
#define DIRTY_LOG_ENTRY32_PTEADDR	GENMASK(31, 0)
#define DIRTY_LOG_ENTRY64_PFN		GENMASK_ULL(53, 10)
#define DIRTY_LOG_ENTRY64_PTEADDR	GENMASK_ULL(55, 0)
#define DIRTY_LOG_ENTRY_PTE_SHIFT	2

#ifdef CONFIG_64BIT
#define DIRTY_LOG_ENTRY_PFN		DIRTY_LOG_ENTRY64_PFN
#define DIRTY_LOG_ENTRY_PTEADDR		DIRTY_LOG_ENTRY64_PTEADDR
#define DIRTY_LOG_ENTRY_SIZE		16
#define DIRTY_LOG_BUFFER_SIZE(order)	(1 << ((order) + 12 - 4))
#else
#define DIRTY_LOG_ENTRY_PFN		DIRTY_LOG_ENTRY32_PFN
#define DIRTY_LOG_ENTRY_PTEADDR		DIRTY_LOG_ENTRY32_PTEADDR
#define DIRTY_LOG_ENTRY_SIZE		8
#define DIRTY_LOG_BUFFER_SIZE(order)	(1 << ((order) + 12 - 3))
#endif

struct kvm_vcpu_dirty_log_csr {
	unsigned long status;
};

struct kvm_vcpu_dirty_log {
	struct kvm_vcpu_dirty_log_csr	csr;

	unsigned long			*buffer;
	phys_addr_t			buffer_phys;
	int				order;
};

int kvm_riscv_vcpu_alloc_dirty_buffer(struct kvm_vcpu *vcpu, int size);
void kvm_riscv_vcpu_dirty_log_deinit(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_dirty_log_load(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_dirty_log_put(struct kvm_vcpu *vcpu);
void kvm_riscv_vcpu_flush_dirty_buffer(struct kvm_vcpu *vcpu);

#endif /* __KVM_VCPU_RISCV_DIRTY_LOG_H */
