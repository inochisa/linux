// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <asm/csr.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_vcpu_dirty_log.h>

void kvm_riscv_vcpu_dirty_log_deinit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_dirty_log *dirty_log = &vcpu->arch.dirty_log;

	if (dirty_log->order < 0)
		return;

	free_pages((unsigned long)dirty_log->buffer, dirty_log->order);
	dirty_log->buffer = NULL;
	dirty_log->order = -1;
}

int kvm_riscv_vcpu_alloc_dirty_buffer(struct kvm_vcpu *vcpu, int size)
{
	struct kvm_vcpu_dirty_log *dirty_log = &vcpu->arch.dirty_log;
	struct page* dirty_buffer;
	unsigned int order;

	dirty_log->buffer = NULL;
	dirty_log->buffer_phys = 0;
	dirty_log->order = -1;
	dirty_log->csr.status = 0;

	// if (size < 0 || size > KVM_VCPU_DIRTY_LOG_BUFFER_MAX_SIZE)
	// 	return -EINVAL;

	// if (size == 0)
	// 	return 0;

	// order = get_order(size);
	order = 1;

	dirty_buffer = alloc_pages(GFP_KERNEL, order);
	if (!dirty_buffer)
		return -ENOMEM;

	dirty_log->buffer = page_to_virt(dirty_buffer);
	dirty_log->buffer_phys = page_to_phys(dirty_buffer);
	dirty_log->order = order;

	return 0;
}

void kvm_riscv_vcpu_dirty_log_load(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_dirty_log *dirty_log = &vcpu->arch.dirty_log;
	unsigned long ctrl;

	if (dirty_log->order < 0)
		return;

	ctrl = FIELD_PREP(HGDTCTL_PPN, dirty_log->buffer_phys >> PAGE_SHIFT) |
	       FIELD_PREP(HGDTCTL_SIZE, dirty_log->order - 1) |
	       HGDTCTL_EN;

	ncsr_write(CSR_HGDTCTL, ctrl);
	ncsr_write(CSR_HGDTS, dirty_log->csr.status);
}

void kvm_riscv_vcpu_dirty_log_put(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_dirty_log *dirty_log = &vcpu->arch.dirty_log;

	if (dirty_log->order < 0)
		return;

	dirty_log->csr.status = ncsr_read(CSR_HGDTS);
}

void kvm_riscv_vcpu_flush_dirty_buffer(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_dirty_log *dirty_log = &vcpu->arch.dirty_log;
	unsigned long size, i;

	if (!riscv_isa_extension_available(vcpu->arch.isa, SVADU))
		return;

	if (dirty_log->order < 0)
		return;

	size = FIELD_GET(HGDTS_INDEX, dirty_log->csr.status);

	if (size == 0)
		return;

	for (i = 0; i < size; i++) {
		gfn_t gpa = READ_ONCE(dirty_log->buffer[i]);

		kvm_vcpu_mark_page_dirty(vcpu, gpa >> PAGE_SHIFT);
	}

	dirty_log->csr.status = 0;
}
