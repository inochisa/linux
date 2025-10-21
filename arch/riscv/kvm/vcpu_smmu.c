// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/csr.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_vcpu_smmu.h>
#include <asm/kvm_nacl.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#define VSATP_MODE_MASK		_AC(0xF000000000000000, UL)
#define VSATP_MODE_39		0x8
#define VSATP_MODE_48		0x9
#define VSATP_MODE_57		0xa

#ifdef CONFIG_64BIT
#define sstage_index_bits	9
#else
#define sstage_index_bits	10
#endif

static int kvm_riscv_satp_level(unsigned long mode)
{
	switch (mode) {
	case VSATP_MODE_39:
		return 3;
	case VSATP_MODE_48:
		return 4;
	case VSATP_MODE_57:
		return 5;
	case 0:
		return 0;
	}

	return -1;
}

static inline unsigned long sstage_pte_index(gva_t addr, u32 maxlevel, u32 level)
{
	u32 now_level = maxlevel - level - 1;
	unsigned long shift = PAGE_SHIFT + (sstage_index_bits * now_level);
	unsigned long mask = PTRS_PER_PTE - 1;

	return (addr >> shift) & mask;
}

static void kvm_riscv_remove_smmu_context(struct kvm_spte_context* spte,
					  pte_t *spgd,
					  int level, int maxlevel)
{
	int i;

	/* spte is leaf */
	for (i = 0; i < PTRS_PER_PTE && level < maxlevel - 1; i++) {
		pte_t *ptep = &spgd[i];
		unsigned long pfn = pte_pfn(ptep_get(ptep));
		void *next_spgd;

		/* spte is not allocate */
		if (pfn == 0)
			continue;

		next_spgd = pfn_to_virt(pfn);

		kvm_info("SMMU enter 0x%016lx at %d of 0x%016lx (level %d)", (unsigned long)next_spgd, i, (unsigned long)spgd, level);

		kvm_riscv_remove_smmu_context(spte, (pte_t *)next_spgd, level + 1, maxlevel);

		set_pte(ptep, __pte(0));
	}

	free_pages((unsigned long)spgd, 1);
}

static int kvm_riscv_setup_smmu_context(struct kvm_spte_context* spte)
{
	struct page *spte_page;

	spte_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!spte_page)
		return -ENOMEM;

	spte->spgd = page_to_virt(spte_page);
	spte->spgd_phys = page_to_phys(spte_page);
	spin_lock_init(&spte->smmu_lock);

	kvm_info("SMMU allocate spgd_phys 0x%016llx\n", spte->spgd_phys);

	spte->mmu_level = 0;
	return 0;
}

int kvm_riscv_handle_smmu_fault(struct kvm_vcpu *vcpu, struct kvm_run *run,
				unsigned long fault_addr)
{
	struct kvm_spte_context* spte = &vcpu->arch.spte_context;
	unsigned long vsatp = csr_read(CSR_VSATP);
	unsigned long mode = FIELD_GET(VSATP_MODE_MASK, vsatp);
	int maxlevel = kvm_riscv_satp_level(mode);
	pte_t *spgt = spte->spgd;
	int level = 0;
	struct page *pte_page;

	kvm_debug("SMMU check vsatp 0x%016lx with level %d\n", vsatp, maxlevel);
	spte->mmu_level = max(spte->mmu_level, maxlevel);

	guard(spinlock)(&spte->smmu_lock);
	for (level = 0; level < (maxlevel - 1); level++) {
		int idx = sstage_pte_index(fault_addr, maxlevel, level);
		pte_t *ptep = &spgt[idx];
		unsigned long pfn = pte_pfn(ptep_get(ptep));

		kvm_debug("0x%016lx %d/%d: 0x%016lx", (unsigned long)(spgt), level,
			  maxlevel, pte_val(ptep_get(ptep)));

		if (pfn != 0) {
			spgt = pfn_to_virt(pfn);
			continue;
		}

		pte_page = alloc_pages(GFP_ATOMIC | __GFP_ZERO, 1);
		if (!pte_page)
			return -ENOMEM;

		spgt = page_to_virt(pte_page);

		set_pte(ptep, mk_pte(pte_page,  __pgprot(0)));
	}

	kvm_debug("handled 0x%016lx with level %d\n", fault_addr, maxlevel);

	return 1;
}

int kvm_riscv_vcpu_smmu_init(struct kvm_vcpu *vcpu)
{
	unsigned long hssatp;
	int ret;

	ret = kvm_riscv_setup_smmu_context(&vcpu->arch.spte_context);
	if (ret < 0)
		return ret;

	hssatp = FIELD_PREP(SATP_PPN, PFN_DOWN(vcpu->arch.spte_context.spgd_phys));

	kvm_info("SMMU hssatp value 0x%016lx\n", hssatp);

	return 0;
}

void kvm_riscv_vcpu_smmu_load(struct kvm_vcpu *vcpu)
{
	struct kvm_spte_context* spte = &vcpu->arch.spte_context;

	unsigned long hssatp = FIELD_PREP(SATP_PPN, PFN_DOWN(spte->spgd_phys));

	csr_write(CSR_HSSATP, hssatp);
}

void kvm_riscv_vcpu_smmu_put(struct kvm_vcpu *vcpu)
{
	csr_write(CSR_HSSATP, 0);
}

void kvm_riscv_vcpu_smmu_deinit(struct kvm_vcpu *vcpu)
{
	struct kvm_spte_context* spte = &vcpu->arch.spte_context;

	kvm_info("SMMU free spgd_phys 0x%016llx with level %d\n",
		 spte->spgd_phys, spte->mmu_level);

	guard(spinlock)(&spte->smmu_lock);
	kvm_riscv_remove_smmu_context(spte, spte->spgd, 0, spte->mmu_level);
}

void kvm_riscv_vcpu_smmu_reset(struct kvm_vcpu *vcpu)
{
	kvm_riscv_vcpu_smmu_deinit(vcpu);
	kvm_riscv_vcpu_smmu_init(vcpu);
}

static bool kvm_riscv_vcpu_smmu_check_valid(void *spgt, unsigned int idx)
{
	unsigned int offset = SPGD_VALID_MAP + (idx & 63) / 8;
	unsigned long volatile *ptr = (void *)((unsigned long)(spgt) + offset);

	return READ_ONCE(*ptr) & BIT(idx % 64);
}

void kvm_riscv_vcpu_smmu_show_pte(struct kvm_vcpu *vcpu, unsigned long addr)
{
	struct kvm_spte_context* spte = &vcpu->arch.spte_context;
	pte_t *spgt = spte->spgd;
	int maxlevel = spte->mmu_level;
	int level;

	if (spte->mmu_level == 0)
		return;

	kvm_err("Currect shadow page table %lx\n", (unsigned long)spte->spgd_phys);

	for (level = 0; level < (maxlevel - 1); ++level) {
		int idx = sstage_pte_index(addr, maxlevel, level);
		pte_t *ptep = &spgt[idx];
		unsigned long pfn = pte_pfn(ptep_get(ptep));

		if (!kvm_riscv_vcpu_smmu_check_valid(spgt, idx)) {
			kvm_err("SMMU: Invalid page table at level %d\n", idx);
			return;
		}

		if (pte_val(*ptep) & _PAGE_PRESENT) {
			unsigned long *ptr = pfn_to_virt(virt_to_pfn(spgt) + 1);
			unsigned long gptr = READ_ONCE(*ptr);

			kvm_err("SMMU: Find huge page table at level %d, pos %d, addr 0x%lx\n",
				level, idx, gptr);
			return;
		}

		kvm_err("SMMU: valid page table at level %d, pos %d, addr 0x%llx\n",
			level, idx, pfn_to_phys(pfn));

		spgt = pfn_to_virt(pfn);
	}
}
