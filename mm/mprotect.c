// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/mprotect.c
 *
 *  (C) Copyright 1994 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 *
 *  Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 *  (C) Copyright 2002 Red Hat Inc, All Rights Reserved
 */

#include <linux/pagewalk.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/personality.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/perf_event.h>
#include <linux/pkeys.h>
#include <linux/ksm.h>
#include <linux/uaccess.h>
#include <linux/mm_inline.h>
#include <linux/pgtable.h>
#include <linux/userfaultfd_k.h>
#include <uapi/linux/mman.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>

#include "internal.h"

static bool maybe_change_pte_writable(struct vm_area_struct *vma, pte_t pte)
{
	if (WARN_ON_ONCE(!vma_test(vma, VMA_WRITE_BIT)))
		return false;

	/* Don't touch entries that are not even readable. */
	if (pte_protnone(pte))
		return false;

	/* Do we need write faults for softdirty tracking? */
	if (pte_needs_soft_dirty_wp(vma, pte))
		return false;

	/* Do we need write faults for uffd-wp tracking? */
	if (userfaultfd_pte_wp(vma, pte))
		return false;

	return true;
}

static bool can_change_private_pte_writable(struct vm_area_struct *vma,
					    unsigned long addr, pte_t pte)
{
	struct page *page;

	if (!maybe_change_pte_writable(vma, pte))
		return false;

	/*
	 * Writable MAP_PRIVATE mapping: We can only special-case on
	 * exclusive anonymous pages, because we know that our
	 * write-fault handler similarly would map them writable without
	 * any additional checks while holding the PT lock.
	 */
	page = vm_normal_page(vma, addr, pte);
	return page && PageAnon(page) && PageAnonExclusive(page);
}

static bool can_change_shared_pte_writable(struct vm_area_struct *vma,
					   pte_t pte)
{
	if (!maybe_change_pte_writable(vma, pte))
		return false;

	VM_WARN_ON_ONCE(is_zero_pfn(pte_pfn(pte)) && pte_dirty(pte));

	/*
	 * Writable MAP_SHARED mapping: "clean" might indicate that the FS still
	 * needs a real write-fault for writenotify
	 * (see vma_wants_writenotify()). If "dirty", the assumption is that the
	 * FS was already notified and we can simply mark the PTE writable
	 * just like the write-fault handler would do.
	 */
	return pte_dirty(pte);
}

bool can_change_pte_writable(struct vm_area_struct *vma, unsigned long addr,
			     pte_t pte)
{
	if (!vma_test(vma, VMA_SHARED_BIT))
		return can_change_private_pte_writable(vma, addr, pte);

	return can_change_shared_pte_writable(vma, pte);
}

static int mprotect_folio_pte_batch(struct folio *folio, pte_t *ptep,
				    pte_t pte, int max_nr_ptes, fpb_t flags)
{
	/* No underlying folio, so cannot batch */
	if (!folio)
		return 1;

	if (!folio_test_large(folio))
		return 1;

	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr_ptes, flags);
}

/* Set nr_ptes number of ptes, starting from idx */
static __always_inline void prot_commit_flush_ptes(struct vm_area_struct *vma,
		unsigned long addr, pte_t *ptep, pte_t oldpte, pte_t ptent,
		int nr_ptes, int idx, bool set_write, struct mmu_gather *tlb)
{
	/*
	 * Advance the position in the batch by idx; note that if idx > 0,
	 * then the nr_ptes passed here is <= batch size - idx.
	 */
	addr += idx * PAGE_SIZE;
	ptep += idx;
	oldpte = pte_advance_pfn(oldpte, idx);
	ptent = pte_advance_pfn(ptent, idx);

	if (set_write)
		ptent = pte_mkwrite(ptent, vma);

	modify_prot_commit_ptes(vma, addr, ptep, oldpte, ptent, nr_ptes);
	if (pte_needs_flush(oldpte, ptent))
		tlb_flush_pte_range(tlb, addr, nr_ptes * PAGE_SIZE);
}

/*
 * Get max length of consecutive ptes pointing to PageAnonExclusive() pages or
 * !PageAnonExclusive() pages, starting from start_idx. Caller must enforce
 * that the ptes point to consecutive pages of the same anon large folio.
 */
static __always_inline int page_anon_exclusive_batch(int start_idx, int max_len,
		struct page *first_page, bool expected_anon_exclusive)
{
	int idx;

	for (idx = start_idx + 1; idx < start_idx + max_len; ++idx) {
		if (expected_anon_exclusive != PageAnonExclusive(first_page + idx))
			break;
	}
	return idx - start_idx;
}

/*
 * This function is a result of trying our very best to retain the
 * "avoid the write-fault handler" optimization. In can_change_pte_writable(),
 * if the vma is a private vma, and we cannot determine whether to change
 * the pte to writable just from the vma and the pte, we then need to look
 * at the actual page pointed to by the pte. Unfortunately, if we have a
 * batch of ptes pointing to consecutive pages of the same anon large folio,
 * the anon-exclusivity (or the negation) of the first page does not guarantee
 * the anon-exclusivity (or the negation) of the other pages corresponding to
 * the pte batch; hence in this case it is incorrect to decide to change or
 * not change the ptes to writable just by using information from the first
 * pte of the batch. Therefore, we must individually check all pages and
 * retrieve sub-batches.
 */
static __always_inline void commit_anon_folio_batch(struct vm_area_struct *vma,
		struct folio *folio, struct page *first_page, unsigned long addr, pte_t *ptep,
		pte_t oldpte, pte_t ptent, int nr_ptes, struct mmu_gather *tlb)
{
	bool expected_anon_exclusive;
	int batch_idx = 0;
	int len;

	while (nr_ptes) {
		expected_anon_exclusive = PageAnonExclusive(first_page + batch_idx);
		len = page_anon_exclusive_batch(batch_idx, nr_ptes,
					first_page, expected_anon_exclusive);
		prot_commit_flush_ptes(vma, addr, ptep, oldpte, ptent, len,
				       batch_idx, expected_anon_exclusive, tlb);
		batch_idx += len;
		nr_ptes -= len;
	}
}

static __always_inline void set_write_prot_commit_flush_ptes(struct vm_area_struct *vma,
		struct folio *folio, struct page *page, unsigned long addr, pte_t *ptep,
		pte_t oldpte, pte_t ptent, int nr_ptes, struct mmu_gather *tlb)
{
	bool set_write;

	if (vma_test(vma, VMA_SHARED_BIT)) {
		set_write = can_change_shared_pte_writable(vma, ptent);
		prot_commit_flush_ptes(vma, addr, ptep, oldpte, ptent, nr_ptes,
				       /* idx = */ 0, set_write, tlb);
		return;
	}

	set_write = maybe_change_pte_writable(vma, ptent) &&
		    (folio && folio_test_anon(folio));
	if (!set_write) {
		prot_commit_flush_ptes(vma, addr, ptep, oldpte, ptent, nr_ptes,
				       /* idx = */ 0, set_write, tlb);
		return;
	}
	commit_anon_folio_batch(vma, folio, page, addr, ptep, oldpte, ptent, nr_ptes, tlb);
}

static long change_softleaf_pte(struct vm_area_struct *vma,
	unsigned long addr, pte_t *pte, pte_t oldpte, unsigned long cp_flags)
{
	const bool uffd_prot = cp_flags & (MM_CP_UFFD_WP | MM_CP_UFFD_RWP);
	const bool uffd_prot_resolve = cp_flags &
		(MM_CP_UFFD_WP_RESOLVE | MM_CP_UFFD_RWP_RESOLVE);
	softleaf_t entry = softleaf_from_pte(oldpte);
	pte_t newpte;

	if (softleaf_is_migration_write(entry)) {
		const struct folio *folio = softleaf_to_folio(entry);

		/*
		 * A protection check is difficult so
		 * just be safe and disable write
		 */
		if (folio_test_anon(folio))
			entry = make_readable_exclusive_migration_entry(swp_offset(entry));
		else
			entry = make_readable_migration_entry(swp_offset(entry));
		newpte = swp_entry_to_pte(entry);
		if (pte_swp_soft_dirty(oldpte))
			newpte = pte_swp_mksoft_dirty(newpte);
	} else if (softleaf_is_device_private_write(entry)) {
		/*
		 * We do not preserve soft-dirtiness. See
		 * copy_nonpresent_pte() for explanation.
		 */
		entry = make_readable_device_private_entry(swp_offset(entry));
		newpte = swp_entry_to_pte(entry);
		if (pte_swp_uffd(oldpte))
			newpte = pte_swp_mkuffd(newpte);
	} else if (softleaf_is_marker(entry)) {
		/*
		 * Ignore error swap entries unconditionally,
		 * because any access should sigbus/sigsegv
		 * anyway.
		 */
		if (softleaf_is_poison_marker(entry) ||
		    softleaf_is_guard_marker(entry))
			return 0;
		/*
		 * If this is uffd-wp pte marker and we'd like
		 * to unprotect it, drop it; the next page
		 * fault will trigger without uffd trapping.
		 */
		if (uffd_prot_resolve) {
			pte_clear(vma->vm_mm, addr, pte);
			return 1;
		}
		return 0;
	} else {
		newpte = oldpte;
	}

	if (uffd_prot)
		newpte = pte_swp_mkuffd(newpte);
	else if (uffd_prot_resolve)
		newpte = pte_swp_clear_uffd(newpte);

	if (!pte_same(oldpte, newpte)) {
		set_pte_at(vma->vm_mm, addr, pte, newpte);
		return 1;
	}
	return 0;
}

static __always_inline void change_present_ptes(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long addr, pte_t *ptep,
		int nr_ptes, unsigned long end, pgprot_t newprot,
		struct folio *folio, struct page *page, unsigned long cp_flags)
{
	const bool uffd_prot = cp_flags & (MM_CP_UFFD_WP | MM_CP_UFFD_RWP);
	const bool uffd_prot_resolve = cp_flags &
		(MM_CP_UFFD_WP_RESOLVE | MM_CP_UFFD_RWP_RESOLVE);
	pte_t ptent, oldpte;

	oldpte = modify_prot_start_ptes(vma, addr, ptep, nr_ptes);
	ptent = pte_modify(oldpte, newprot);

	if (uffd_prot)
		ptent = pte_mkuffd(ptent);
	else if (uffd_prot_resolve)
		ptent = pte_clear_uffd(ptent);

	/*
	 * The uffd bit on a VM_UFFD_RWP VMA carries PROT_NONE
	 * semantics. If mprotect() or NUMA hinting changed the
	 * base protection, restore PAGE_NONE so the PTE still
	 * traps on any access. pte_modify() preserves
	 * _PAGE_UFFD.
	 */
	if (userfaultfd_rwp(vma) && pte_uffd(ptent))
		ptent = pte_modify(ptent, PAGE_NONE);

	/*
	 * In some writable, shared mappings, we might want
	 * to catch actual write access -- see
	 * vma_wants_writenotify().
	 *
	 * In all writable, private mappings, we have to
	 * properly handle COW.
	 *
	 * In both cases, we can sometimes still change PTEs
	 * writable and avoid the write-fault handler, for
	 * example, if a PTE is already dirty and no other
	 * COW or special handling is required.
	 */
	if ((cp_flags & MM_CP_TRY_CHANGE_WRITABLE) &&
	     !pte_write(ptent))
		set_write_prot_commit_flush_ptes(vma, folio, page,
			addr, ptep, oldpte, ptent, nr_ptes, tlb);
	else
		prot_commit_flush_ptes(vma, addr, ptep, oldpte, ptent,
			nr_ptes, /* idx = */ 0, /* set_write = */ false, tlb);
}

static long change_pte_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, pmd_t *pmd, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
{
	pte_t *pte, oldpte;
	spinlock_t *ptl;
	long pages = 0;
	bool is_private_single_threaded;
	bool prot_numa = cp_flags & MM_CP_PROT_NUMA;
	bool uffd_rwp = cp_flags & MM_CP_UFFD_RWP;
	bool uffd_wp = cp_flags & MM_CP_UFFD_WP;
	int nr_ptes;

	tlb_change_page_size(tlb, PAGE_SIZE);
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!pte)
		return -EAGAIN;

	if (prot_numa)
		is_private_single_threaded = vma_is_single_threaded_private(vma);

	flush_tlb_batched_pending(vma->vm_mm);
	lazy_mmu_mode_enable();
	do {
		nr_ptes = 1;
		oldpte = ptep_get(pte);
		if (pte_present(oldpte)) {
			const fpb_t flags = FPB_RESPECT_SOFT_DIRTY | FPB_RESPECT_WRITE;
			int max_nr_ptes = (end - addr) >> PAGE_SHIFT;
			struct folio *folio = NULL;
			struct page *page;

			/* Already in the desired state. */
			if (prot_numa && pte_protnone(oldpte))
				continue;
			/*
			 * RWP-protected PTEs carry _PAGE_UFFD as a marker on
			 * top of PROT_NONE. Skip only entries already in that
			 * exact state; plain PROT_NONE from mprotect() still needs
			 * to be promoted so future faults can be distinguished.
			 */
			if (uffd_rwp && pte_protnone(oldpte) && pte_uffd(oldpte))
				continue;

			page = vm_normal_page(vma, addr, oldpte);
			if (page)
				folio = page_folio(page);

			/*
			 * Avoid trapping faults against the zero or KSM
			 * pages. See similar comment in change_huge_pmd.
			 * Skip this filter for uffd RWP which
			 * must set protnone regardless of NUMA placement.
			 */
			if (prot_numa &&
			    !folio_can_map_prot_numa(folio, vma,
						is_private_single_threaded)) {

				/* determine batch to skip */
				nr_ptes = mprotect_folio_pte_batch(folio,
					  pte, oldpte, max_nr_ptes, /* flags = */ 0);
				continue;
			}

			nr_ptes = mprotect_folio_pte_batch(folio, pte, oldpte, max_nr_ptes, flags);

			/*
			 * Optimize for the small-folio common case by
			 * special-casing it here. Compiler constant propagation
			 * plus copious amounts of __always_inline does wonders.
			 */
			if (likely(nr_ptes == 1)) {
				change_present_ptes(tlb, vma, addr, pte, 1,
					end, newprot, folio, page, cp_flags);
			} else {
				change_present_ptes(tlb, vma, addr, pte,
					nr_ptes, end, newprot, folio, page,
					cp_flags);
			}

			pages += nr_ptes;
		} else if (pte_none(oldpte)) {
			/*
			 * Nobody plays with any none ptes besides
			 * userfaultfd when applying the protections.
			 */
			if (likely(!uffd_wp))
				continue;

			if (userfaultfd_wp_use_markers(vma)) {
				/*
				 * For file-backed mem, we need to be able to
				 * wr-protect a none pte, because even if the
				 * pte is none, the page/swap cache could
				 * exist.  Doing that by install a marker.
				 */
				set_pte_at(vma->vm_mm, addr, pte,
					   make_pte_marker(PTE_MARKER_UFFD_WP));
				pages++;
			}
		} else  {
			pages += change_softleaf_pte(vma, addr, pte, oldpte, cp_flags);
		}
	} while (pte += nr_ptes, addr += nr_ptes * PAGE_SIZE, addr != end);
	lazy_mmu_mode_disable();
	pte_unmap_unlock(pte - 1, ptl);

	return pages;
}

/*
 * Return true if we want to split THPs into PTE mappings in change
 * protection procedure, false otherwise.
 */
static inline bool
pgtable_split_needed(struct vm_area_struct *vma, unsigned long cp_flags)
{
	/*
	 * pte markers only resides in pte level, if we need pte markers,
	 * we need to split.  For example, we cannot wr-protect a file thp
	 * (e.g. 2M shmem) because file thp is handled differently when
	 * split by erasing the pmd so far.
	 */
	return (cp_flags & (MM_CP_UFFD_WP | MM_CP_UFFD_RWP)) && !vma_is_anonymous(vma);
}

/*
 * Return true if we want to populate pgtables in change protection
 * procedure, false otherwise
 */
static inline bool
pgtable_populate_needed(struct vm_area_struct *vma, unsigned long cp_flags)
{
	/* If not within ioctl(UFFDIO_WRITEPROTECT), then don't bother */
	if (!(cp_flags & MM_CP_UFFD_WP))
		return false;

	/* Populate if the userfaultfd mode requires pte markers */
	return userfaultfd_wp_use_markers(vma);
}

/*
 * Populate the pgtable underneath for whatever reason if requested.
 * When {pte|pmd|...}_alloc() failed we treat it the same way as pgtable
 * allocation failures during page faults by kicking OOM and returning
 * error.
 */
#define  change_pmd_prepare(vma, pmd, cp_flags)				\
	({								\
		long err = 0;						\
		if (unlikely(pgtable_populate_needed(vma, cp_flags))) {	\
			if (pte_alloc(vma->vm_mm, pmd))			\
				err = -ENOMEM;				\
		}							\
		err;							\
	})

/*
 * This is the general pud/p4d/pgd version of change_pmd_prepare(). We need to
 * have separate change_pmd_prepare() because pte_alloc() returns 0 on success,
 * while {pmd|pud|p4d}_alloc() returns the valid pointer on success.
 */
#define  change_prepare(vma, high, low, addr, cp_flags)			\
	  ({								\
		long err = 0;						\
		if (unlikely(pgtable_populate_needed(vma, cp_flags))) {	\
			low##_t *p = low##_alloc(vma->vm_mm, high, addr); \
			if (p == NULL)					\
				err = -ENOMEM;				\
		}							\
		err;							\
	})

static inline long change_pmd_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, pud_t *pud, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
{
	pmd_t *pmd;
	unsigned long next;
	long pages = 0;
	unsigned long nr_huge_updates = 0;

	pmd = pmd_offset(pud, addr);
	do {
		long ret;
		pmd_t _pmd;
again:
		next = pmd_addr_end(addr, end);

		ret = change_pmd_prepare(vma, pmd, cp_flags);
		if (ret) {
			pages = ret;
			break;
		}

		if (pmd_none(*pmd))
			goto next;

		_pmd = pmdp_get_lockless(pmd);
		if (pmd_is_huge(_pmd)) {
			if ((next - addr != HPAGE_PMD_SIZE) ||
			    pgtable_split_needed(vma, cp_flags)) {
				__split_huge_pmd(vma, pmd, addr, false);
				/*
				 * For file-backed, the pmd could have been
				 * cleared; make sure pmd populated if
				 * necessary, then fall-through to pte level.
				 */
				ret = change_pmd_prepare(vma, pmd, cp_flags);
				if (ret) {
					pages = ret;
					break;
				}
			} else {
				ret = change_huge_pmd(tlb, vma, pmd,
						addr, newprot, cp_flags);
				if (ret) {
					if (ret == HPAGE_PMD_NR) {
						pages += HPAGE_PMD_NR;
						nr_huge_updates++;
					}

					/* huge pmd was handled */
					goto next;
				}
			}
			/* fall through, the trans huge pmd just split */
		}

		ret = change_pte_range(tlb, vma, pmd, addr, next, newprot,
				       cp_flags);
		if (ret < 0)
			goto again;
		pages += ret;
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	if (nr_huge_updates)
		count_vm_numa_events(NUMA_HUGE_PTE_UPDATES, nr_huge_updates);
	return pages;
}

static inline long change_pud_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, p4d_t *p4d, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
{
	struct mmu_notifier_range range;
	pud_t *pudp, pud;
	unsigned long next;
	long pages = 0, ret;

	range.start = 0;

	pudp = pud_offset(p4d, addr);
	do {
again:
		next = pud_addr_end(addr, end);
		ret = change_prepare(vma, pudp, pmd, addr, cp_flags);
		if (ret) {
			pages = ret;
			break;
		}

		pud = pudp_get(pudp);
		if (pud_none(pud))
			continue;

		if (!range.start) {
			mmu_notifier_range_init(&range,
						MMU_NOTIFY_PROTECTION_VMA, 0,
						vma->vm_mm, addr, end);
			mmu_notifier_invalidate_range_start(&range);
		}

		if (pud_leaf(pud)) {
			if ((next - addr != PUD_SIZE) ||
			    pgtable_split_needed(vma, cp_flags)) {
				__split_huge_pud(vma, pudp, addr);
				goto again;
			} else {
				ret = change_huge_pud(tlb, vma, pudp,
						      addr, newprot, cp_flags);
				if (ret == 0)
					goto again;
				/* huge pud was handled */
				if (ret == HPAGE_PUD_NR)
					pages += HPAGE_PUD_NR;
				continue;
			}
		}

		pages += change_pmd_range(tlb, vma, pudp, addr, next, newprot,
					  cp_flags);
	} while (pudp++, addr = next, addr != end);

	if (range.start)
		mmu_notifier_invalidate_range_end(&range);

	return pages;
}

static inline long change_p4d_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, pgd_t *pgd, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
{
	p4d_t *p4d;
	unsigned long next;
	long pages = 0, ret;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		ret = change_prepare(vma, p4d, pud, addr, cp_flags);
		if (ret)
			return ret;
		if (p4d_none_or_clear_bad(p4d))
			continue;
		pages += change_pud_range(tlb, vma, p4d, addr, next, newprot,
					  cp_flags);
	} while (p4d++, addr = next, addr != end);

	return pages;
}

static long change_protection_range(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long addr,
		unsigned long end, pgprot_t newprot, unsigned long cp_flags)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	unsigned long next;
	long pages = 0, ret;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	tlb_start_vma(tlb, vma);
	do {
		next = pgd_addr_end(addr, end);
		ret = change_prepare(vma, pgd, p4d, addr, cp_flags);
		if (ret) {
			pages = ret;
			break;
		}
		if (pgd_none_or_clear_bad(pgd))
			continue;
		pages += change_p4d_range(tlb, vma, pgd, addr, next, newprot,
					  cp_flags);
	} while (pgd++, addr = next, addr != end);

	tlb_end_vma(tlb, vma);

	return pages;
}

#define CP_DONE			0
#define CP_HUGE			1
#define CP_RANGE		2

struct rust_cp_state {
	struct mmu_gather *tlb;
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long end;
	unsigned long cp_flags;
	pgprot_t newprot;
};

static int cp_classify(struct rust_cp_state *s, long *out)
{
	*out = 0;
	s->newprot = s->vma->vm_page_prot;

	/*
	 * MM_CP_UFFD_{WP,RWP} and _RESOLVE are mutually exclusive within one
	 * change, and WP and RWP cannot mix. Miswired callers get a warn and
	 * a no-op; userspace cannot reach this state.
	 */
	if (WARN_ON_ONCE((s->cp_flags & MM_CP_UFFD_WP_ALL) == MM_CP_UFFD_WP_ALL ||
			 (s->cp_flags & MM_CP_UFFD_RWP_ALL) == MM_CP_UFFD_RWP_ALL ||
			 ((s->cp_flags & MM_CP_UFFD_WP_ALL) &&
			  (s->cp_flags & MM_CP_UFFD_RWP_ALL))))
		return CP_DONE;

#ifdef CONFIG_NUMA_BALANCING
	/*
	 * Ordinary protection updates (mprotect, uffd-wp, softdirty tracking)
	 * are expected to reflect their requirements via VMA flags such that
	 * vma_set_page_prot() will adjust vma->vm_page_prot accordingly.
	 */
	if (s->cp_flags & MM_CP_PROT_NUMA)
		s->newprot = PAGE_NONE;
#else
	WARN_ON_ONCE(s->cp_flags & MM_CP_PROT_NUMA);
#endif

	if (IS_ENABLED(CONFIG_ARCH_HAS_PTE_PROTNONE) &&
	    (s->cp_flags & MM_CP_UFFD_RWP))
		s->newprot = PAGE_NONE;

	if (is_vm_hugetlb_page(s->vma))
		return CP_HUGE;
	return CP_RANGE;
}

static long cp_huge(struct rust_cp_state *s)
{
	return hugetlb_change_protection(s->vma, s->start, s->end, s->newprot,
					 s->cp_flags);
}

static long cp_range(struct rust_cp_state *s)
{
	return change_protection_range(s->tlb, s->vma, s->start, s->end,
				       s->newprot, s->cp_flags);
}

#ifdef CONFIG_RUST_MMAP
int rust_cp_classify(struct rust_cp_state *s, long *out)
{
	return cp_classify(s, out);
}

long rust_cp_huge(struct rust_cp_state *s)
{
	return cp_huge(s);
}

long rust_cp_range(struct rust_cp_state *s)
{
	return cp_range(s);
}
#endif

static long finish_cp(struct rust_cp_state *s)
{
	long out = 0;

	switch (cp_classify(s, &out)) {
	case CP_DONE:
		return out;
	case CP_HUGE:
		return cp_huge(s);
	default:
		return cp_range(s);
	}
}

long change_protection(struct mmu_gather *tlb,
		       struct vm_area_struct *vma, unsigned long start,
		       unsigned long end, unsigned long cp_flags)
{
	struct rust_cp_state s = {
		.tlb = tlb,
		.vma = vma,
		.start = start,
		.end = end,
		.cp_flags = cp_flags,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		long rust_ret;

		rust_ret = rust_cp_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_cp(&s);
}

static int prot_none_pte_entry(pte_t *pte, unsigned long addr,
			       unsigned long next, struct mm_walk *walk)
{
	return pfn_modify_allowed(pte_pfn(ptep_get(pte)),
				  *(pgprot_t *)(walk->private)) ?
		0 : -EACCES;
}

#ifdef CONFIG_HUGETLB_PAGE
static int prot_none_hugetlb_entry(pte_t *pte, unsigned long hmask,
				   unsigned long addr, unsigned long next,
				   struct mm_walk *walk)
{
	const pte_t entry = huge_ptep_get(walk->mm, addr, pte);

	if (pfn_modify_allowed(pte_pfn(entry), *(pgprot_t *)(walk->private)))
		return 0;
	return -EACCES;
}
#else
#define prot_none_hugetlb_entry	NULL
#endif

static const struct mm_walk_ops prot_none_walk_ops = {
	.pte_entry		= prot_none_pte_entry,
	.hugetlb_entry		= prot_none_hugetlb_entry,
	.walk_lock		= PGWALK_WRLOCK,
};

#define MPFIX_DONE		0
#define MPFIX_MODIFY		1
#define MPFIX_APPLY		2

struct rust_mpfix_state {
	struct vma_iterator *vmi;
	struct mmu_gather *tlb;
	struct vm_area_struct *vma;
	struct vm_area_struct **pprev;
	unsigned long start;
	unsigned long end;
	vm_flags_t newflags;
	vma_flags_t old_vma_flags;
	vma_flags_t new_vma_flags;
	unsigned long charged;
	long nrpages;
};

static int mpfix_prepare(struct rust_mpfix_state *s, int *out)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = vma->vm_mm;
	int error;

	*out = 0;
	s->charged = 0;
	s->old_vma_flags = READ_ONCE(vma->flags);
	s->new_vma_flags = legacy_to_vma_flags(s->newflags);
	s->nrpages = (s->end - s->start) >> PAGE_SHIFT;

	if (vma_is_sealed(vma)) {
		*out = -EPERM;
		return MPFIX_DONE;
	}

	if (vma_flags_same_pair(&s->old_vma_flags, &s->new_vma_flags)) {
		*s->pprev = vma;
		return MPFIX_DONE;
	}

	/*
	 * Do PROT_NONE PFN permission checks here when we can still
	 * bail out without undoing a lot of state. This is a rather
	 * uncommon case, so doesn't need to be very optimized.
	 */
	if (arch_has_pfn_modify_check() &&
	    vma_flags_test_any(&s->old_vma_flags, VMA_PFNMAP_BIT,
			       VMA_MIXEDMAP_BIT) &&
	    !vma_flags_test_any_mask(&s->new_vma_flags, VMA_ACCESS_FLAGS)) {
		pgprot_t new_pgprot = vm_get_page_prot(s->newflags);

		error = walk_page_range_vma(vma, s->start, s->end,
				&prot_none_walk_ops, &new_pgprot);
		if (error) {
			*out = error;
			return MPFIX_DONE;
		}
	}

	/*
	 * If we make a private mapping writable we increase our commit;
	 * but (without finer accounting) cannot reduce our commit if we
	 * make it unwritable again except in the anonymous case where no
	 * anon_vma has yet to be assigned.
	 *
	 * hugetlb mapping were accounted for even if read-only so there is
	 * no need to account for them here.
	 */
	if (vma_flags_test(&s->new_vma_flags, VMA_WRITE_BIT)) {
		/* Check space limits when area turns into data. */
		if (!may_expand_vm(mm, &s->new_vma_flags, s->nrpages) &&
		    may_expand_vm(mm, &s->old_vma_flags, s->nrpages)) {
			*out = -ENOMEM;
			return MPFIX_DONE;
		}
		if (!vma_flags_test_any(&s->old_vma_flags,
				VMA_ACCOUNT_BIT, VMA_WRITE_BIT, VMA_HUGETLB_BIT,
				VMA_SHARED_BIT, VMA_NORESERVE_BIT)) {
			s->charged = s->nrpages;
			if (security_vm_enough_memory_mm(mm, s->charged)) {
				*out = -ENOMEM;
				return MPFIX_DONE;
			}
			vma_flags_set(&s->new_vma_flags, VMA_ACCOUNT_BIT);
		}
	} else if (vma_flags_test(&s->old_vma_flags, VMA_ACCOUNT_BIT) &&
		   vma_is_anonymous(vma) && !vma->anon_vma) {
		vma_flags_clear(&s->new_vma_flags, VMA_ACCOUNT_BIT);
	}

	return MPFIX_MODIFY;
}

static int mpfix_modify(struct rust_mpfix_state *s, int *out)
{
	struct vm_area_struct *vma;

	*out = 0;
	vma = vma_modify_flags(s->vmi, *s->pprev, s->vma, s->start, s->end,
			       &s->new_vma_flags);
	if (IS_ERR(vma)) {
		vm_unacct_memory(s->charged);
		*out = PTR_ERR(vma);
		return MPFIX_DONE;
	}
	s->vma = vma;
	*s->pprev = vma;
	return MPFIX_APPLY;
}

static int mpfix_apply(struct rust_mpfix_state *s)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = vma->vm_mm;
	unsigned int mm_cp_flags = 0;
	vm_flags_t newflags;

	/*
	 * vm_flags and vm_page_prot are protected by the mmap_lock
	 * held in write mode.
	 */
	vma_start_write(vma);
	vma_flags_reset_once(vma, &s->new_vma_flags);
	if (vma_wants_manual_pte_write_upgrade(vma))
		mm_cp_flags |= MM_CP_TRY_CHANGE_WRITABLE;
	vma_set_page_prot(vma);

	change_protection(s->tlb, vma, s->start, s->end, mm_cp_flags);

	if (vma_flags_test(&s->old_vma_flags, VMA_ACCOUNT_BIT) &&
	    !vma_flags_test(&s->new_vma_flags, VMA_ACCOUNT_BIT))
		vm_unacct_memory(s->nrpages);

	/*
	 * Private VMA_LOCKED_BIT VMA becoming writable: trigger COW to avoid
	 * major fault on access.
	 */
	if (vma_flags_test(&s->new_vma_flags, VMA_WRITE_BIT) &&
	    vma_flags_test(&s->old_vma_flags, VMA_LOCKED_BIT) &&
	    !vma_flags_test_any(&s->old_vma_flags, VMA_WRITE_BIT, VMA_SHARED_BIT))
		populate_vma_page_range(vma, s->start, s->end, NULL);

	vm_stat_account(mm, vma_flags_to_legacy(s->old_vma_flags), -s->nrpages);
	newflags = vma_flags_to_legacy(s->new_vma_flags);
	vm_stat_account(mm, newflags, s->nrpages);
	perf_event_mmap(vma);
	return 0;
}

static int finish_mpfix(struct rust_mpfix_state *s)
{
	int out = 0;
	int kind;

	kind = mpfix_prepare(s, &out);
	if (kind == MPFIX_DONE)
		return out;
	kind = mpfix_modify(s, &out);
	if (kind == MPFIX_DONE)
		return out;
	return mpfix_apply(s);
}

#ifdef CONFIG_RUST_MMAP
int rust_mpfix_prepare(struct rust_mpfix_state *s, int *out)
{
	return mpfix_prepare(s, out);
}

int rust_mpfix_modify(struct rust_mpfix_state *s, int *out)
{
	return mpfix_modify(s, out);
}

int rust_mpfix_apply(struct rust_mpfix_state *s)
{
	return mpfix_apply(s);
}
#endif

int
mprotect_fixup(struct vma_iterator *vmi, struct mmu_gather *tlb,
	       struct vm_area_struct *vma, struct vm_area_struct **pprev,
	       unsigned long start, unsigned long end, vm_flags_t newflags)
{
	struct rust_mpfix_state s = {
		.vmi = vmi,
		.tlb = tlb,
		.vma = vma,
		.pprev = pprev,
		.start = start,
		.end = end,
		.newflags = newflags,
	};

#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_mpfix_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mpfix(&s);
}

/*
 * pkey==-1 when doing a legacy mprotect()
 */
#define MPROTECT_DONE		0
#define MPROTECT_APPLY		1

#ifndef CONFIG_RUST_MMAP
struct rust_mprotect_req {
	unsigned long start;
	size_t len;
	unsigned long prot;
	int pkey;
	unsigned long end;
	unsigned long reqprot;
	int grows;
	int rier;
};
#endif

static int mprotect_validate(struct rust_mprotect_req *req, int *out)
{
	unsigned long start;
	size_t len;
	unsigned long prot;
	int grows;
	int rier;

	*out = 0;
	start = untagged_addr(req->start);
	len = req->len;
	prot = req->prot;
	grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
	rier = (current->personality & READ_IMPLIES_EXEC) && (prot & PROT_READ);

	prot &= ~(PROT_GROWSDOWN | PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN | PROT_GROWSUP)) {
		*out = -EINVAL;
		return MPROTECT_DONE;
	}

	if (start & ~PAGE_MASK) {
		*out = -EINVAL;
		return MPROTECT_DONE;
	}
	if (!len) {
		*out = 0;
		return MPROTECT_DONE;
	}
	len = PAGE_ALIGN(len);
	req->end = start + len;
	if (req->end <= start) {
		*out = -ENOMEM;
		return MPROTECT_DONE;
	}
	if (!arch_validate_prot(prot, start)) {
		*out = -EINVAL;
		return MPROTECT_DONE;
	}

	req->start = start;
	req->len = len;
	req->prot = prot;
	req->reqprot = prot;
	req->grows = grows;
	req->rier = rier;
	return MPROTECT_APPLY;
}

#define MPWALK_DONE		0
#define MPWALK_WALK		1

struct rust_mprot_walk {
	struct rust_mprotect_req *req;
	struct vma_iterator vmi;
	struct vm_area_struct *vma;
	struct vm_area_struct *prev;
};

static int mprotect_lock(struct rust_mprot_walk *s, int *out)
{
	struct rust_mprotect_req *req = s->req;
	unsigned long start = req->start;
	unsigned long end = req->end;
	const int grows = req->grows;
	int pkey = req->pkey;
	int error;
	struct vm_area_struct *vma;

	*out = 0;
	if (mmap_write_lock_killable(current->mm)) {
		*out = -EINTR;
		return MPWALK_DONE;
	}

	/*
	 * If userspace did not allocate the pkey, do not let
	 * them use it here.
	 */
	error = -EINVAL;
	if ((pkey != -1) && !mm_pkey_is_allocated(current->mm, pkey))
		goto out_unlock;

	vma_iter_init(&s->vmi, current->mm, start);
	vma = vma_find(&s->vmi, end);
	error = -ENOMEM;
	if (!vma)
		goto out_unlock;

	if (unlikely(grows & PROT_GROWSDOWN)) {
		if (vma->vm_start >= end)
			goto out_unlock;
		start = vma->vm_start;
		error = -EINVAL;
		if (!vma_test(vma, VMA_GROWSDOWN_BIT))
			goto out_unlock;
	} else {
		if (vma->vm_start > start)
			goto out_unlock;
		if (unlikely(grows & PROT_GROWSUP)) {
			end = vma->vm_end;
			error = -EINVAL;
			if (!vma_test_single_mask(vma, VMA_GROWSUP))
				goto out_unlock;
		}
	}

	s->prev = vma_prev(&s->vmi);
	if (start > vma->vm_start)
		s->prev = vma;
	s->vma = vma;
	req->start = start;
	req->end = end;
	return MPWALK_WALK;

out_unlock:
	mmap_write_unlock(current->mm);
	*out = error;
	return MPWALK_DONE;
}

static int mprotect_walk(struct rust_mprot_walk *s)
{
	struct rust_mprotect_req *req = s->req;
	unsigned long nstart, end, tmp, reqprot, prot;
	struct vm_area_struct *vma, *prev;
	int error = 0;
	const bool rier = req->rier;
	int pkey = req->pkey;
	struct mmu_gather tlb;

	end = req->end;
	prot = req->prot;
	reqprot = req->reqprot;
	vma = s->vma;
	prev = s->prev;
	nstart = req->start;
	tmp = vma->vm_start;

	tlb_gather_mmu(&tlb, current->mm);
	for_each_vma_range(s->vmi, vma, end) {
		vm_flags_t mask_off_old_flags;
		vma_flags_t new_vma_flags;
		vm_flags_t newflags;
		int new_vma_pkey;

		if (vma->vm_start != tmp) {
			error = -ENOMEM;
			break;
		}

		/* Does the application expect PROT_READ to imply PROT_EXEC */
		if (rier && vma_test(vma, VMA_MAYEXEC_BIT))
			prot |= PROT_EXEC;

		/*
		 * Each mprotect() call explicitly passes r/w/x permissions.
		 * If a permission is not passed to mprotect(), it must be
		 * cleared from the VMA.
		 */
		mask_off_old_flags = VM_ACCESS_FLAGS | VM_FLAGS_CLEAR;

		new_vma_pkey = arch_override_mprotect_pkey(vma, prot, pkey);
		newflags = calc_vm_prot_bits(prot, new_vma_pkey);
		newflags |= (vma->vm_flags & ~mask_off_old_flags);
		new_vma_flags = legacy_to_vma_flags(newflags);

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
		if ((newflags & ~(newflags >> 4)) & VM_ACCESS_FLAGS) {
			error = -EACCES;
			break;
		}

		if (map_deny_write_exec(&vma->flags, &new_vma_flags)) {
			error = -EACCES;
			break;
		}

		/* Allow architectures to sanity-check the new flags */
		if (!arch_validate_flags(newflags)) {
			error = -EINVAL;
			break;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			break;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;

		if (vma->vm_ops && vma->vm_ops->mprotect) {
			error = vma->vm_ops->mprotect(vma, nstart, tmp, newflags);
			if (error)
				break;
		}

		error = mprotect_fixup(&s->vmi, &tlb, vma, &prev, nstart, tmp,
				       newflags);
		if (error)
			break;

		tmp = vma_iter_end(&s->vmi);
		nstart = tmp;
		prot = reqprot;
	}
	tlb_finish_mmu(&tlb);

	if (!error && tmp < end)
		error = -ENOMEM;

	mmap_write_unlock(current->mm);
	return error;
}

#ifdef CONFIG_RUST_MMAP
int rust_mprot_lock(struct rust_mprot_walk *s, int *out)
{
	return mprotect_lock(s, out);
}

int rust_mprot_walk(struct rust_mprot_walk *s)
{
	return mprotect_walk(s);
}

void rust_mprot_unlock(void)
{
	mmap_write_unlock(current->mm);
}
#endif

static int finish_mprot(struct rust_mprot_walk *s)
{
	int out = 0;
	int kind;

	kind = mprotect_lock(s, &out);
	if (kind == MPWALK_DONE)
		return out;
	return mprotect_walk(s);
}

static int mprotect_apply(struct rust_mprotect_req *req)
{
	struct rust_mprot_walk s = {
		.req = req,
	};

#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_mprot_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mprot(&s);
}

#ifdef CONFIG_RUST_MMAP
int rust_mprotect_validate(struct rust_mprotect_req *req, int *out)
{
	return mprotect_validate(req, out);
}

int rust_mprotect_apply(struct rust_mprotect_req *req)
{
	return mprotect_apply(req);
}
#endif

static int finish_mprotect_pkey(unsigned long start, size_t len,
		unsigned long prot, int pkey)
{
	struct rust_mprotect_req req;
	int out = 0;

	req.start = start;
	req.len = len;
	req.prot = prot;
	req.pkey = pkey;
	if (mprotect_validate(&req, &out) == MPROTECT_DONE)
		return out;
	return mprotect_apply(&req);
}

static int do_mprotect_pkey(unsigned long start, size_t len,
		unsigned long prot, int pkey)
{
#ifdef CONFIG_RUST_MMAP
	struct rust_mprotect_req req;
	int handled = 0;
	int rust_ret;

	req.start = start;
	req.len = len;
	req.prot = prot;
	req.pkey = pkey;
	rust_ret = rust_mprotect_dispatch(&req, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mprotect_pkey(start, len, prot, pkey);
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	return do_mprotect_pkey(start, len, prot, -1);
}

#ifdef CONFIG_ARCH_HAS_PKEYS

SYSCALL_DEFINE4(pkey_mprotect, unsigned long, start, size_t, len,
		unsigned long, prot, int, pkey)
{
	return do_mprotect_pkey(start, len, prot, pkey);
}

SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
{
	int pkey;
	int ret;

	/* No flags supported yet. */
	if (flags)
		return -EINVAL;
	/* check for unsupported init values */
	if (init_val & ~PKEY_ACCESS_MASK)
		return -EINVAL;

	mmap_write_lock(current->mm);
	pkey = mm_pkey_alloc(current->mm);

	ret = -ENOSPC;
	if (pkey == -1)
		goto out;

	ret = arch_set_user_pkey_access(pkey, init_val);
	if (ret) {
		mm_pkey_free(current->mm, pkey);
		goto out;
	}
	ret = pkey;
out:
	mmap_write_unlock(current->mm);
	return ret;
}

SYSCALL_DEFINE1(pkey_free, int, pkey)
{
	int ret;

	mmap_write_lock(current->mm);
	ret = mm_pkey_free(current->mm, pkey);
	mmap_write_unlock(current->mm);

	/*
	 * We could provide warnings or errors if any VMA still
	 * has the pkey set here.
	 */
	return ret;
}

#endif /* CONFIG_ARCH_HAS_PKEYS */
