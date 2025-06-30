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

static inline unsigned long sstage_pte_index(gpa_t addr, u32 maxlevel, u32 level)
{
	u32 now_level = maxlevel - level - 1;
	unsigned long shift = PAGE_SHIFT + (sstage_index_bits * now_level);
	unsigned long mask = PTRS_PER_PTE - 1;

	return (addr >> shift) & mask;
}

static void kvm_riscv_remove_smmu_context(struct kvm_spte_context* spte,
					  pte_t *next_spgd,
					  int level, int maxlevel)
{
	struct page *page;
	int i;

	/* spte is leaf */
	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte_t *now = &next_spgd[i];
		phys_addr_t addr = pte_pfn(ptep_get(now));

		/* spte is not allocate */
		if (addr == 0)
			continue;

		if (level < maxlevel - 1) {
			page = pte_page(*now);

			kvm_riscv_remove_smmu_context(spte, (pte_t *)page_to_virt(page), level + 1, maxlevel);
		}

		set_pte(now, __pte(0));
	}

	page = virt_to_page(next_spgd);

	__free_pages(page, 1);
}

static int kvm_riscv_setup_smmu_context(struct kvm_spte_context* spte)
{
	struct page *spte_page;
	// int ret, i;

	spte_page = alloc_pages(GFP_KERNEL, 1);
	if (!spte_page)
		return -ENOMEM;

	spte->spgd = page_to_virt(spte_page);
	spte->spgd_phys = page_to_phys(spte_page);

	memset(spte->spgd, 0x00, SPGD_SIZE);

	kvm_info("SMMU allocate spgd_phys 0x%016llx\n", spte->spgd_phys);

	spte->mmu_level = 0;

	// for (i = 0; i < PTRS_PER_PTE; i++) {
	// 	struct page *pte_page = alloc_pages(GFP_KERNEL, 1);
	// 	pte_t *next_spgd = (pte_t *)spte->spgd;
	// 	pte_t *now = &next_spgd[i];

	// 	if (!pte_page) {
	// 		ret = -ENOMEM;
	// 		goto failed;
	// 	}

	// 	memset(page_to_virt(pte_page), 0x00, SPGD_SIZE);

	// 	*now = mk_pte(pte_page,  __pgprot(0));
	// }

	return 0;

// failed:
// 	while (i--) {
// 		pte_t *next_spgd = (pte_t *)spte->spgd;
// 		pte_t *now = &next_spgd[i];
// 		struct page * page = pte_page(*now);

// 		__free_pages(page, 1);
// 	}

// 	__free_pages(virt_to_page(spte->spgd), 1);

// 	return ret;
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

	while (level < (maxlevel - 1)) {
		int idx = sstage_pte_index(fault_addr, maxlevel, level);
		pte_t *now = &spgt[idx];
		phys_addr_t addr = pte_pfn(ptep_get(now));

		kvm_debug("now at 0x%016lx %d/%d", (unsigned long)(spgt), level,
			  maxlevel);

		if (addr != 0) {
			spgt = pfn_to_virt(addr);
			level++;
			continue;
		}

		pte_page = alloc_pages(GFP_KERNEL, 1);
		if (!pte_page)
			return -ENOMEM;

		spgt = page_to_virt(pte_page);

		memset(spgt, 0x00, SPGD_SIZE);

		if (level + 1 == maxlevel - 1)
			*(unsigned long*)(spgt + SPGD_FLAG) = SPGD_FLAG_LEAF;

		*now = mk_pte(pte_page,  __pgprot(0));
		level++;
	}

	kvm_debug("handled 0x%016lx with level %d\n", fault_addr, maxlevel);

	return 1;
}

int kvm_riscv_vcpu_smmu_init(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = kvm_riscv_setup_smmu_context(&vcpu->arch.spte_context);
	if (ret < 0)
		return ret;

	vcpu->arch.cfg.hssatp = FIELD_PREP(SATP_PPN, (vcpu->arch.spte_context.spgd_phys >> PAGE_SHIFT));

	kvm_info("SMMU hssatp value 0x%016lx\n", vcpu->arch.cfg.hssatp);

	return 0;
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

	kvm_riscv_remove_smmu_context(spte, spte->spgd, 1, spte->mmu_level);
}
