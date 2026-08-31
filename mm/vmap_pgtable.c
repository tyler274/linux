// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel page-table map/unmap used by the Rust vmalloc replacement.
 * Architecture PTE encoding stays in C; the VA allocator lives in Rust.
 */

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>
#include <linux/kasan.h>
#include <linux/kmsan.h>
#include <linux/io.h>
#include <linux/export.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>

#include "vmalloc.h"

struct vmap_pages_arg {
	struct page **pages;
	unsigned int idx;
	pgprot_t prot;
};

struct vmap_phys_arg {
	u64 pfn;
	pgprot_t prot;
};

static int vmap_set_page_pte(pte_t *pte, unsigned long addr, void *data)
{
	struct vmap_pages_arg *a = data;
	struct page *page = a->pages[a->idx++];

	set_pte_at(&init_mm, addr, pte, mk_pte(page, a->prot));
	return 0;
}

static int vmap_set_phys_pte(pte_t *pte, unsigned long addr, void *data)
{
	struct vmap_phys_arg *a = data;

	set_pte_at(&init_mm, addr, pte, pfn_pte(a->pfn++, a->prot));
	return 0;
}

static int vunmap_clear_pte(pte_t *pte, unsigned long addr, void *data)
{
	(void)data;
	if (!pte_none(ptep_get(pte)))
		pte_clear(&init_mm, addr, pte);
	return 0;
}

int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
			       pgprot_t prot, struct page **pages,
			       unsigned int page_shift)
{
	struct vmap_pages_arg arg = {
		.pages = pages,
		.idx = 0,
		.prot = pgprot_nx(prot),
	};

	(void)page_shift;
	if (WARN_ON_ONCE(addr >= end || !PAGE_ALIGNED(addr) || !PAGE_ALIGNED(end)))
		return -EINVAL;
	return apply_to_page_range(&init_mm, addr, end - addr, vmap_set_page_pte,
				   &arg);
}

int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
			     pgprot_t prot, struct page **pages,
			     unsigned int page_shift, gfp_t gfp_mask)
{
	int ret;

	(void)gfp_mask;
	ret = kmsan_vmap_pages_range_noflush(addr, end, prot, pages, page_shift,
					     gfp_mask);
	if (ret)
		return ret;
	return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
}

int vmap_pages_range(unsigned long addr, unsigned long end, pgprot_t prot,
		     struct page **pages, unsigned int page_shift)
{
	int err;

	err = vmap_pages_range_noflush(addr, end, prot, pages, page_shift,
				       GFP_KERNEL);
	if (!err)
		flush_cache_vmap(addr, end);
	return err;
}

int vmap_page_range(unsigned long addr, unsigned long end,
		    phys_addr_t phys_addr, pgprot_t prot)
{
	struct vmap_phys_arg arg = {
		.pfn = phys_addr >> PAGE_SHIFT,
		.prot = pgprot_nx(prot),
	};
	int err;

	if (WARN_ON_ONCE(addr >= end))
		return -EINVAL;
	err = apply_to_page_range(&init_mm, addr, end - addr, vmap_set_phys_pte,
				  &arg);
	if (!err) {
		flush_cache_vmap(addr, end);
		err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
					       PAGE_SHIFT);
	}
	return err;
}

int ioremap_page_range(unsigned long addr, unsigned long end,
		       phys_addr_t phys_addr, pgprot_t prot)
{
	struct vm_struct *area;

	area = find_vm_area((void *)addr);
	if (!area || !(area->flags & VM_IOREMAP)) {
		WARN_ONCE(1, "vm_area at addr %lx is not marked as VM_IOREMAP\n",
			  addr);
		return -EINVAL;
	}
	return vmap_page_range(addr, end, phys_addr, prot);
}

void __vunmap_range_noflush(unsigned long start, unsigned long end)
{
	if (WARN_ON_ONCE(start >= end))
		return;
	apply_to_existing_page_range(&init_mm, start, end - start,
				     vunmap_clear_pte, NULL);
}

void vunmap_range_noflush(unsigned long start, unsigned long end)
{
	kmsan_vunmap_range_noflush(start, end);
	__vunmap_range_noflush(start, end);
}

void vunmap_range(unsigned long addr, unsigned long end)
{
	flush_cache_vunmap(addr, end);
	vunmap_range_noflush(addr, end);
	flush_tlb_kernel_range(addr, end);
}

int vm_area_map_pages(struct vm_struct *area, unsigned long start,
		      unsigned long end, struct page **pages)
{
	(void)area;
	return vmap_pages_range(start, end, PAGE_KERNEL, pages, PAGE_SHIFT);
}

void vm_area_unmap_pages(struct vm_struct *area, unsigned long start,
			 unsigned long end)
{
	(void)area;
	vunmap_range(start, end);
}

bool is_vmalloc_addr(const void *x)
{
	unsigned long addr = (unsigned long)kasan_reset_tag(x);

	return addr >= VMALLOC_START && addr < VMALLOC_END;
}
EXPORT_SYMBOL(is_vmalloc_addr);

int is_vmalloc_or_module_addr(const void *x)
{
#if defined(CONFIG_EXECMEM) && defined(MODULES_VADDR)
	unsigned long addr = (unsigned long)kasan_reset_tag(x);

	if (addr >= MODULES_VADDR && addr < MODULES_END)
		return 1;
#endif
	return is_vmalloc_addr(x);
}
EXPORT_SYMBOL_GPL(is_vmalloc_or_module_addr);

struct page *vmalloc_to_page(const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long)vmalloc_addr;
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));

	if (pgd_none(*pgd) || WARN_ON_ONCE(pgd_leaf(*pgd) || pgd_bad(*pgd)))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	if (p4d_leaf(*p4d))
		return p4d_page(*p4d) + ((addr & ~P4D_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(p4d_bad(*p4d)))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud))
		return pud_page(*pud) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pud_bad(*pud)))
		return NULL;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd))
		return pmd_page(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (WARN_ON_ONCE(pmd_bad(*pmd)))
		return NULL;
	ptep = pte_offset_kernel(pmd, addr);
	pte = ptep_get(ptep);
	if (!pte_present(pte))
		return NULL;
	return pte_page(pte);
}
EXPORT_SYMBOL(vmalloc_to_page);

unsigned long vmalloc_to_pfn(const void *vmalloc_addr)
{
	return page_to_pfn(vmalloc_to_page(vmalloc_addr));
}
EXPORT_SYMBOL(vmalloc_to_pfn);
