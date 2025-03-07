// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/kvm_nacl.h>
#include <asm/kvm_vcpu_smmu.h>
#include <asm/kvm_nacl.h>
#include <asm/page.h>
#include <asm/pgtable.h>

static void kvm_riscv_remove_smmu_context(struct kvm_spte_context* spte,
					  pte_t *next_spgd,
					  int level, int maxlevel)
{
	struct page *page;
	int i;

	/* spte is leaf */
	for (i = 0; i < PTRS_PER_PTE && level != maxlevel; i++) {
		pte_t *now = &next_spgd[i];
		if (!pte_val(ptep_get(now)))
			continue;

		page = pte_page(*now);

		kvm_riscv_remove_smmu_context(spte, (pte_t *)page_to_virt(page), level + 1, maxlevel);

		set_pte(now, __pte(0));
	}

	page = virt_to_page(next_spgd);

	__free_pages(page, 1);
}


static int kvm_riscv_setup_smmu_context(struct kvm_spte_context* spte)
{
	struct page *spte_page;
	int ret, i;

	spte_page = alloc_pages(GFP_KERNEL, 1);
	if (!spte_page)
		return -ENOMEM;

	spte->spgd = page_to_virt(spte_page);
	spte->spgd_phys = page_to_phys(spte_page);

	memset(spte->spgd, 0x00, SPGD_SIZE);

	for (i = 0; i < PTRS_PER_PTE; i++) {
		struct page *pte_page = alloc_pages(GFP_KERNEL, 1);
		pte_t *next_spgd = (pte_t *)spte->spgd;
		pte_t *now = &next_spgd[i];

		if (!pte_page) {
			ret = -ENOMEM;
			goto failed;
		}

		memset(page_to_virt(pte_page), 0x00, SPGD_SIZE);

		*now = mk_pte(pte_page,  __pgprot(0));
	}

	return 0;

failed:
	while (i--) {
		pte_t *next_spgd = (pte_t *)spte->spgd;
		pte_t *now = &next_spgd[i];
		struct page * page = pte_page(*now);

		__free_pages(page, 1);
	}

	__free_pages(virt_to_page(spte->spgd), 1);

	return ret;
}

int kvm_riscv_vcpu_smmu_init(struct kvm_vcpu *vcpu)
{
	return kvm_riscv_setup_smmu_context(&vcpu->arch.spte_context);
}

#define SATP_MODE_MASK		_AC(0xF000000000000000, UL)

static int kvm_riscv_satp_level(unsigned long mode)
{
	switch (mode) {
	case SATP_MODE_39:
		return 3;
	case SATP_MODE_48:
		return 4;
	case SATP_MODE_57:
		return 3;
	case 0:
		return 0;
	}

	return -1;
}

void kvm_riscv_vcpu_smmu_deinit(struct kvm_vcpu *vcpu)
{
	struct kvm_spte_context* spte = &vcpu->arch.spte_context;
	unsigned long mode = FIELD_GET(SATP_MODE_MASK, vcpu->arch.guest_csr.vsatp);

	int maxlevel = kvm_riscv_satp_level(mode);

	if (maxlevel < 3)
		maxlevel = 3;

	kvm_riscv_remove_smmu_context(spte, spte->spgd, 1, maxlevel);

	csr_write(CSR_HSSATP, 0);
}
