// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * VMA-specific functions.
 */

/*
 * To allow for userland testing we place internal dependencies in
 * vma_internal.h and external VMA API declarations in vma.h.
 */
#include "vma_internal.h"
#include "vma.h"

struct mmap_state {
	struct mm_struct *mm;
	struct vma_iterator *vmi;

	unsigned long addr;
	unsigned long end;
	pgoff_t pgoff;
	pgoff_t anon_pgoff;
	unsigned long pglen;
	union {
		vm_flags_t vm_flags;
		vma_flags_t vma_flags;
	};
	struct file *file;
	pgprot_t page_prot;

	/* User-defined fields, perhaps updated by .mmap_prepare(). */
	const struct vm_operations_struct *vm_ops;
	void *vm_private_data;

	unsigned long charged;

	struct vm_area_struct *prev;
	struct vm_area_struct *next;

	/* Unmapping state. */
	struct vma_munmap_struct vms;
	struct ma_state mas_detach;
	struct maple_tree mt_detach;

	/* Determine if we can check KSM flags early in mmap() logic. */
	bool check_ksm_early :1;
	/* If .mmap_prepare changed the file, we don't need to pin. */
	bool file_doesnt_need_get :1;
};

#define MMAP_STATE(name, mm_, vmi_, addr_, len_, pgoff_, anon_pgoff_, vma_flags_, file_) \
	struct mmap_state name = {					\
		.mm = mm_,						\
		.vmi = vmi_,						\
		.addr = addr_,						\
		.end = (addr_) + (len_),				\
		.pgoff = pgoff_,					\
		.anon_pgoff = anon_pgoff_,				\
		.pglen = PHYS_PFN(len_),				\
		.vma_flags = vma_flags_,				\
		.file = file_,						\
		.page_prot = vma_flags_to_page_prot(vma_flags_),	\
	}

#define VMG_MMAP_STATE(name, map_, vma_)				\
	struct vma_merge_struct name = {				\
		.mm = (map_)->mm,					\
		.vmi = (map_)->vmi,					\
		.start = (map_)->addr,					\
		.end = (map_)->end,					\
		.vma_flags = (map_)->vma_flags,				\
		.pgoff = (map_)->pgoff,					\
		.anon_pgoff = (map_)->anon_pgoff,			\
		.file = (map_)->file,					\
		.prev = (map_)->prev,					\
		.middle = vma_,						\
		.next = (vma_) ? NULL : (map_)->next,			\
		.state = VMA_MERGE_START,				\
	}

static void __vma_set_range(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end)
{
	vma->vm_start = start;
	vma->vm_end = end;
}

static void vma_set_range(struct vm_area_struct *vma, unsigned long start,
			  unsigned long end, pgoff_t pgoff, pgoff_t anon_pgoff)
{
	__vma_set_range(vma, start, end);
	vma_set_pgoff(vma, pgoff);
	vma_set_anon_pgoff(vma, anon_pgoff);
}

/* Was this VMA ever forked from a parent, i.e. maybe contains CoW mappings? */
static bool vma_is_fork_child(struct vm_area_struct *vma)
{
	/*
	 * The list_is_singular() test is to avoid merging VMA cloned from
	 * parents. This can improve scalability caused by the anon_vma root
	 * lock.
	 */
	return vma && vma->anon_vma && !list_is_singular(&vma->anon_vma_chain);
}

static inline bool is_mergeable_vma(struct vma_merge_struct *vmg, bool merge_next)
{
	struct vm_area_struct *vma = merge_next ? vmg->next : vmg->prev;
	vma_flags_t diff;

	if (!mpol_equal(vmg->policy, vma_policy(vma)))
		return false;

	diff = vma_flags_diff_pair(&vma->flags, &vmg->vma_flags);
	vma_flags_clear_mask(&diff, VMA_IGNORE_MERGE_FLAGS);

	if (!vma_flags_empty(&diff))
		return false;
	if (vma->vm_file != vmg->file)
		return false;
	if (!is_mergeable_vm_userfaultfd_ctx(vma, vmg->uffd_ctx))
		return false;
	if (!anon_vma_name_eq(anon_vma_name(vma), vmg->anon_name))
		return false;
	return true;
}

static bool is_mergeable_anon_vma(struct vma_merge_struct *vmg, bool merge_next)
{
	struct vm_area_struct *tgt = merge_next ? vmg->next : vmg->prev;
	struct vm_area_struct *src = vmg->middle; /* existing merge case. */
	struct anon_vma *tgt_anon = tgt->anon_vma;
	struct anon_vma *src_anon = vmg->anon_vma;

	/*
	 * We _can_ have !src, vmg->anon_vma via copy_vma(). In this instance we
	 * will remove the existing VMA's anon_vma's so there's no scalability
	 * concerns.
	 */
	VM_WARN_ON(src && src_anon != src->anon_vma);

	/* Case 1 - we will dup_anon_vma() from src into tgt. */
	if (!tgt_anon && src_anon) {
		struct vm_area_struct *copied_from = vmg->copied_from;

		if (vma_is_fork_child(src))
			return false;
		if (vma_is_fork_child(copied_from))
			return false;

		return true;
	}
	/* Case 2 - we will simply use tgt's anon_vma. */
	if (tgt_anon && !src_anon)
		return !vma_is_fork_child(tgt);
	/* Case 3 - the anon_vma's are already shared. */
	return src_anon == tgt_anon;
}

/*
 * init_multi_vma_prep() - Initializer for struct vma_prepare
 * @vp: The vma_prepare struct
 * @vma: The vma that will be altered once locked
 * @vmg: The merge state that will be used to determine adjustment and VMA
 *       removal.
 */
static void init_multi_vma_prep(struct vma_prepare *vp,
				struct vm_area_struct *vma,
				struct vma_merge_struct *vmg)
{
	struct vm_area_struct *adjust;
	struct vm_area_struct **remove = &vp->remove;

	memset(vp, 0, sizeof(struct vma_prepare));
	vp->vma = vma;
	vp->anon_vma = vma->anon_vma;

	if (vmg && vmg->__remove_middle) {
		*remove = vmg->middle;
		remove = &vp->remove2;
	}
	if (vmg && vmg->__remove_next)
		*remove = vmg->next;

	if (vmg && vmg->__adjust_middle_start)
		adjust = vmg->middle;
	else if (vmg && vmg->__adjust_next_start)
		adjust = vmg->next;
	else
		adjust = NULL;

	vp->adj_next = adjust;
	if (!vp->anon_vma && adjust)
		vp->anon_vma = adjust->anon_vma;

	VM_WARN_ON(vp->anon_vma && adjust && adjust->anon_vma &&
		   vp->anon_vma != adjust->anon_vma);

	vp->file = vma->vm_file;
	if (vp->file)
		vp->mapping = vma->vm_file->f_mapping;

	if (vmg && vmg->skip_vma_uprobe)
		vp->skip_vma_uprobe = true;
}

/*
 * Does this merge require that adjacent VMAs must have adjacent anonymous page
 * offsets in addition to having adjacent vma->vm_pgoff?
 *
 * This is only required for MAP_PRIVATE-file backed mappings as the page offset
 * for pure anonymous VMAs is equal to the anonymous page offset.
 *
 * Read-only shared mappings (with VMA_SHARED_BIT cleared) are always unfaulted
 * so automatically have correct anonymous page offset (as it is always updated
 * on remap).
 *
 * 'Special' mappings in the sense of VDSO, VVAR etc. have !file but would in
 * any case not be candidates for merge nor be mergeable.
 */
static bool needs_adjacent_anon_pgoff(const struct vma_merge_struct *vmg)
{
	return vmg->file && vma_flags_is_cow_mapping(&vmg->vma_flags);
}

/*
 * Return true if we can merge this (vma_flags,anon_vma,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We don't check here for the merged mmap wrapping around the end of pagecache
 * indices (16TB on ia32) because do_mmap() does not permit mmap's which
 * wrap, nor mmaps which cover the final page at index -1UL.
 *
 * We assume the vma may be removed as part of the merge.
 */
static bool can_vma_merge_before(struct vma_merge_struct *vmg)
{
	if (!is_mergeable_vma(vmg, /* merge_next = */ true))
		return false;
	if (!is_mergeable_anon_vma(vmg, /* merge_next = */ true))
		return false;
	if (vmg_end_pgoff(vmg) != vma_start_pgoff(vmg->next))
		return false;
	if (needs_adjacent_anon_pgoff(vmg) &&
	    vmg_end_anon_pgoff(vmg) != vma_start_anon_pgoff(vmg->next))
		return false;
	return true;
}

/*
 * Return true if we can merge this (vma_flags,anon_vma,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We assume that vma is not removed as part of the merge.
 */
static bool can_vma_merge_after(struct vma_merge_struct *vmg)
{
	if (!is_mergeable_vma(vmg, /* merge_next = */ false))
		return false;
	if (!is_mergeable_anon_vma(vmg, /* merge_next = */ false))
		return false;
	if (vma_end_pgoff(vmg->prev) != vmg_start_pgoff(vmg))
		return false;
	if (needs_adjacent_anon_pgoff(vmg) &&
	    vma_end_anon_pgoff(vmg->prev) != vmg_start_anon_pgoff(vmg))
		return false;
	return true;
}

static void __vma_link_file(struct vm_area_struct *vma,
			    struct address_space *mapping)
{
	if (vma_is_shared_maywrite(vma))
		mapping_allow_writable(mapping);

	flush_dcache_mmap_lock(mapping);
	mapping_rmap_tree_insert(vma, mapping);
	flush_dcache_mmap_unlock(mapping);
}

/*
 * Requires inode->i_mapping->i_mmap_rwsem
 */
static void __remove_shared_vm_struct(struct vm_area_struct *vma,
				      struct address_space *mapping)
{
	if (vma_is_shared_maywrite(vma))
		mapping_unmap_writable(mapping);

	flush_dcache_mmap_lock(mapping);
	mapping_rmap_tree_remove(vma, mapping);
	flush_dcache_mmap_unlock(mapping);
}

/*
 * vma has some anon_vma assigned, and is already inserted on that
 * anon_vma's interval trees.
 *
 * Before updating the vma's vm_start / vm_end / vm_pgoff fields, the
 * vma must be removed from the anon_vma's interval trees using
 * anon_rmap_tree_pre_update_vma().
 *
 * After the update, the vma will be reinserted using
 * anon_rmap_tree_post_update_vma().
 *
 * The entire update must be protected by exclusive mmap_lock and by
 * the root anon_vma's mutex.
 */
static void
anon_rmap_tree_pre_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		anon_rmap_tree_remove(avc, avc->anon_vma);
}

static void
anon_rmap_tree_post_update_vma(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;

	list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
		anon_rmap_tree_insert(avc, avc->anon_vma);
}

/*
 * vma_prepare() - Helper function for handling locking VMAs prior to altering
 * @vp: The initialized vma_prepare struct
 */
static void vma_prepare(struct vma_prepare *vp)
{
	if (vp->file) {
		uprobe_munmap(vp->vma, vp->vma->vm_start, vp->vma->vm_end);

		if (vp->adj_next)
			uprobe_munmap(vp->adj_next, vp->adj_next->vm_start,
				      vp->adj_next->vm_end);

		i_mmap_lock_write(vp->mapping);
		if (vp->insert && vp->insert->vm_file) {
			/*
			 * Put into interval tree now, so instantiated pages
			 * are visible to arm/parisc __flush_dcache_page
			 * throughout; but we cannot insert into address
			 * space until vma start or end is updated.
			 */
			__vma_link_file(vp->insert,
					vp->insert->vm_file->f_mapping);
		}
	}

	if (vp->anon_vma) {
		anon_vma_lock_write(vp->anon_vma);
		anon_rmap_tree_pre_update_vma(vp->vma);
		if (vp->adj_next)
			anon_rmap_tree_pre_update_vma(vp->adj_next);
	}

	if (vp->file) {
		flush_dcache_mmap_lock(vp->mapping);
		mapping_rmap_tree_remove(vp->vma, vp->mapping);
		if (vp->adj_next)
			mapping_rmap_tree_remove(vp->adj_next, vp->mapping);
	}

}

/*
 * vma_complete- Helper function for handling the unlocking after altering VMAs,
 * or for inserting a VMA.
 *
 * @vp: The vma_prepare struct
 * @vmi: The vma iterator
 * @mm: The mm_struct
 */
static void vma_complete(struct vma_prepare *vp, struct vma_iterator *vmi,
			 struct mm_struct *mm)
{
	if (vp->file) {
		if (vp->adj_next)
			mapping_rmap_tree_insert(vp->adj_next, vp->mapping);
		mapping_rmap_tree_insert(vp->vma, vp->mapping);
		flush_dcache_mmap_unlock(vp->mapping);
	}

	if (vp->remove && vp->file) {
		__remove_shared_vm_struct(vp->remove, vp->mapping);
		if (vp->remove2)
			__remove_shared_vm_struct(vp->remove2, vp->mapping);
	} else if (vp->insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		vma_iter_store_new(vmi, vp->insert);
		mm->map_count++;
	}

	if (vp->anon_vma) {
		anon_rmap_tree_post_update_vma(vp->vma);
		if (vp->adj_next)
			anon_rmap_tree_post_update_vma(vp->adj_next);
		anon_vma_unlock_write(vp->anon_vma);
	}

	if (vp->file) {
		i_mmap_unlock_write(vp->mapping);

		if (!vp->skip_vma_uprobe) {
			uprobe_mmap(vp->vma);

			if (vp->adj_next)
				uprobe_mmap(vp->adj_next);
		}
	}

	if (vp->remove) {
again:
		vma_mark_detached(vp->remove);
		if (vp->file) {
			uprobe_munmap(vp->remove, vp->remove->vm_start,
				      vp->remove->vm_end);
			fput(vp->file);
		}
		if (vp->remove->anon_vma)
			unlink_anon_vmas(vp->remove);
		mm->map_count--;
		mpol_put(vma_policy(vp->remove));
		if (!vp->remove2)
			WARN_ON_ONCE(vp->vma->vm_end < vp->remove->vm_end);
		vm_area_free(vp->remove);

		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we are removing both mid and next vmas
		 */
		if (vp->remove2) {
			vp->remove = vp->remove2;
			vp->remove2 = NULL;
			goto again;
		}
	}
	if (vp->insert && vp->file)
		uprobe_mmap(vp->insert);
}

/*
 * init_vma_prep() - Initializer wrapper for vma_prepare struct
 * @vp: The vma_prepare struct
 * @vma: The vma that will be altered once locked
 */
static void init_vma_prep(struct vma_prepare *vp, struct vm_area_struct *vma)
{
	init_multi_vma_prep(vp, vma, NULL);
}

/*
 * Can the proposed VMA be merged with the left (previous) VMA taking into
 * account the start position of the proposed range.
 */
static bool can_vma_merge_left(struct vma_merge_struct *vmg)

{
	return vmg->prev && vmg->prev->vm_end == vmg->start &&
		can_vma_merge_after(vmg);
}

/*
 * Can the proposed VMA be merged with the right (next) VMA taking into
 * account the end position of the proposed range.
 *
 * In addition, if we can merge with the left VMA, ensure that left and right
 * anon_vma's are also compatible.
 */
static bool can_vma_merge_right(struct vma_merge_struct *vmg,
				bool can_merge_left)
{
	struct vm_area_struct *next = vmg->next;
	struct vm_area_struct *prev;

	if (!next || vmg->end != next->vm_start || !can_vma_merge_before(vmg))
		return false;

	if (!can_merge_left)
		return true;

	/*
	 * If we can merge with prev (left) and next (right), indicating that
	 * each VMA's anon_vma is compatible with the proposed anon_vma, this
	 * does not mean prev and next are compatible with EACH OTHER.
	 *
	 * We therefore check this in addition to mergeability to either side.
	 */
	prev = vmg->prev;
	return !prev->anon_vma || !next->anon_vma ||
		prev->anon_vma == next->anon_vma;
}

/*
 * Close a vm structure and free it.
 */
void remove_vma(struct vm_area_struct *vma)
{
	might_sleep();
	vma_close(vma);
	if (vma->vm_file)
		fput(vma->vm_file);
	mpol_put(vma_policy(vma));
	vm_area_free(vma);
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the mm semaphore held.
 */
#define UR_DONE			0
#define UR_APPLY		1

struct rust_ur_state {
	struct unmap_desc *unmap;
	struct mm_struct *mm;
	struct mmu_gather tlb;
	bool gathered;
};

static int ur_classify(struct rust_ur_state *s)
{
	s->mm = s->unmap->first->vm_mm;
	s->gathered = false;
	tlb_gather_mmu(&s->tlb, s->mm);
	s->gathered = true;
	update_hiwater_rss(s->mm);
	return UR_APPLY;
}

static void ur_apply(struct rust_ur_state *s)
{
	unmap_vmas(&s->tlb, s->unmap);
	mas_set(s->unmap->mas, s->unmap->tree_reset);
	free_pgtables(&s->tlb, s->unmap);
	tlb_finish_mmu(&s->tlb);
	s->gathered = false;
}

static void ur_abort(struct rust_ur_state *s)
{
	if (s->gathered) {
		tlb_finish_mmu(&s->tlb);
		s->gathered = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_ur_classify(struct rust_ur_state *s)
{
	return ur_classify(s);
}

void rust_ur_apply(struct rust_ur_state *s)
{
	ur_apply(s);
}

void rust_ur_abort(struct rust_ur_state *s)
{
	ur_abort(s);
}
#endif

static void finish_ur(struct rust_ur_state *s)
{
	if (ur_classify(s) == UR_DONE)
		return;
	ur_apply(s);
}

void unmap_region(struct unmap_desc *unmap)
{
	struct rust_ur_state s = {
		.unmap = unmap,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;

		rust_ur_dispatch(&s, &handled);
		if (handled)
			return;
	}
#endif
	finish_ur(&s);
}

/*
 * __split_vma() bypasses sysctl_max_map_count checking.  We use this where it
 * has already been checked or doesn't make sense to fail.
 * VMA Iterator will point to the original VMA.
 */
#define SVMA_DONE		0
#define SVMA_APPLY		1

struct rust_svma_state {
	struct vma_iterator *vmi;
	struct vm_area_struct *vma;
	unsigned long addr;
	int new_below;
	struct vm_area_struct *new;
};

static int svma_classify(struct rust_svma_state *s, int *out)
{
	struct vm_area_struct *vma = s->vma;
	struct vm_area_struct *new;
	int err;

	s->new = NULL;
	*out = 0;

	WARN_ON(vma->vm_start >= s->addr);
	WARN_ON(vma->vm_end <= s->addr);

	if (vma->vm_ops && vma->vm_ops->may_split) {
		err = vma->vm_ops->may_split(vma, s->addr);
		if (err) {
			*out = err;
			return SVMA_DONE;
		}
	}

	new = vm_area_dup(vma);
	if (!new) {
		*out = -ENOMEM;
		return SVMA_DONE;
	}

	if (s->new_below) {
		new->vm_end = s->addr;
	} else {
		new->vm_start = s->addr;
		vma_add_pgoff(new, linear_page_delta(vma, s->addr));
	}

	vma_iter_config(s->vmi, new->vm_start, new->vm_end);
	if (vma_iter_prealloc(s->vmi, new)) {
		vm_area_free(new);
		*out = -ENOMEM;
		return SVMA_DONE;
	}
	s->new = new;
	return SVMA_APPLY;
}

static int svma_apply(struct rust_svma_state *s)
{
	struct vma_iterator *vmi = s->vmi;
	struct vm_area_struct *vma = s->vma;
	struct vm_area_struct *new = s->new;
	unsigned long addr = s->addr;
	struct vma_prepare vp;
	int err = -ENOMEM;

	err = vma_dup_policy(vma, new);
	if (err)
		goto out_free_vmi;

	err = anon_vma_clone(new, vma, VMA_OP_SPLIT);
	if (err)
		goto out_free_mpol;

	if (new->vm_file)
		get_file(new->vm_file);

	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	vma_start_write(vma);
	vma_start_write(new);

	init_vma_prep(&vp, vma);
	vp.insert = new;
	vma_prepare(&vp);

	/*
	 * Get rid of huge pages and shared page tables straddling the split
	 * boundary.
	 */
	vma_adjust_trans_huge(vma, vma->vm_start, addr, NULL);
	if (is_vm_hugetlb_page(vma))
		hugetlb_split(vma, addr);

	if (s->new_below) {
		vma->vm_start = addr;
		vma_add_pgoff(vma, linear_page_delta(new, addr));
	} else {
		vma->vm_end = addr;
	}

	/* vma_complete stores the new vma */
	vma_complete(&vp, vmi, vma->vm_mm);
	validate_mm(vma->vm_mm);
	s->new = NULL;

	/* Success. */
	if (s->new_below)
		vma_next(vmi);
	else
		vma_prev(vmi);

	return 0;

out_free_mpol:
	mpol_put(vma_policy(new));
out_free_vmi:
	vma_iter_free(vmi);
	vm_area_free(new);
	s->new = NULL;
	return err;
}

static void svma_abort(struct rust_svma_state *s)
{
	if (s->new) {
		vma_iter_free(s->vmi);
		vm_area_free(s->new);
		s->new = NULL;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_svma_classify(struct rust_svma_state *s, int *out)
{
	return svma_classify(s, out);
}

int rust_svma_apply(struct rust_svma_state *s)
{
	return svma_apply(s);
}

void rust_svma_abort(struct rust_svma_state *s)
{
	svma_abort(s);
}
#endif

static int finish_svma(struct rust_svma_state *s)
{
	int out = 0;

	if (svma_classify(s, &out) == SVMA_DONE)
		return out;
	return svma_apply(s);
}

static __must_check int
__split_vma(struct vma_iterator *vmi, struct vm_area_struct *vma,
	    unsigned long addr, int new_below)
{
	struct rust_svma_state s = {
		.vmi = vmi,
		.vma = vma,
		.addr = addr,
		.new_below = new_below,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_svma_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_svma(&s);
}

/*
 * Split a vma into two pieces at address 'addr', a new vma is allocated
 * either for the first part or the tail.
 */
static int split_vma(struct vma_iterator *vmi, struct vm_area_struct *vma,
		     unsigned long addr, int new_below)
{
	if (vma->vm_mm->map_count >= get_sysctl_max_map_count())
		return -ENOMEM;

	return __split_vma(vmi, vma, addr, new_below);
}

/*
 * dup_anon_vma() - Helper function to duplicate anon_vma on VMA merge in the
 * instance that the destination VMA has no anon_vma but the source does.
 *
 * @dst: The destination VMA
 * @src: The source VMA
 * @dup: Pointer to the destination VMA when successful.
 *
 * Returns: 0 on success.
 */
static int dup_anon_vma(struct vm_area_struct *dst,
			struct vm_area_struct *src, struct vm_area_struct **dup)
{
	/*
	 * There are three cases to consider for correctly propagating
	 * anon_vma's on merge.
	 *
	 * The first is trivial - neither VMA has anon_vma, we need not do
	 * anything.
	 *
	 * The second where both have anon_vma is also a no-op, as they must
	 * then be the same, so there is simply nothing to copy.
	 *
	 * Here we cover the third - if the destination VMA has no anon_vma,
	 * that is it is unfaulted, we need to ensure that the newly merged
	 * range is referenced by the anon_vma's of the source.
	 */
	if (src->anon_vma && !dst->anon_vma) {
		int ret;

		vma_assert_write_locked(dst);
		dst->anon_vma = src->anon_vma;
		ret = anon_vma_clone(dst, src, VMA_OP_MERGE_UNFAULTED);
		if (ret)
			return ret;

		*dup = dst;
	}

	return 0;
}

#ifdef CONFIG_DEBUG_VM_MAPLE_TREE
void validate_mm(struct mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	mt_validate(&mm->mm_mt);
	for_each_vma(vmi, vma) {
#ifdef CONFIG_DEBUG_VM_RB
		struct anon_vma *anon_vma = vma->anon_vma;
		struct anon_vma_chain *avc;
#endif
		unsigned long vmi_start, vmi_end;
		bool warn = 0;

		vmi_start = vma_iter_addr(&vmi);
		vmi_end = vma_iter_end(&vmi);
		if (VM_WARN_ON_ONCE_MM(vma->vm_end != vmi_end, mm))
			warn = 1;

		if (VM_WARN_ON_ONCE_MM(vma->vm_start != vmi_start, mm))
			warn = 1;

		if (warn) {
			pr_emerg("issue in %s\n", current->comm);
			dump_stack();
			dump_vma(vma);
			pr_emerg("tree range: %px start %lx end %lx\n", vma,
				 vmi_start, vmi_end - 1);
			vma_iter_dump_tree(&vmi);
		}

#ifdef CONFIG_DEBUG_VM_RB
		if (anon_vma) {
			anon_vma_lock_read(anon_vma);
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				anon_rmap_tree_verify(avc);
			anon_vma_unlock_read(anon_vma);
		}
#endif
		/* Check for a infinite loop */
		if (++i > mm->map_count + 10) {
			i = -1;
			break;
		}
	}
	if (i != mm->map_count) {
		pr_emerg("map_count %d vma iterator %d\n", mm->map_count, i);
		bug = 1;
	}
	VM_BUG_ON_MM(bug, mm);
}
#endif /* CONFIG_DEBUG_VM_MAPLE_TREE */

/*
 * Based on the vmg flag indicating whether we need to adjust the vm_start field
 * for the middle or next VMA, we calculate what the range of the newly adjusted
 * VMA ought to be, and set the VMA's range accordingly.
 */
static void vmg_adjust_set_range(struct vma_merge_struct *vmg)
{
	if (vmg->__adjust_middle_start) {
		/*
		 * vmg->start    vmg->end
		 * |             |
		 * v    merge    v
		 * <------------->
		 *         delta
		 *        <------>
		 * |------|----------------|
		 * | prev |    middle      |
		 * |------|----------------|
		 *        ^
		 *        |
		 *        middle->vm_start
		 */
		struct vm_area_struct *middle = vmg->middle;
		const unsigned long delta = vmg->end - middle->vm_start;

		__vma_set_range(middle, vmg->end, middle->vm_end);
		vma_add_pgoff(middle, delta >> PAGE_SHIFT);
	} else if (vmg->__adjust_next_start) {
		/*
		 *                Originally:
		 *
		 *            vmg->start   vmg->end
		 *            |            |
		 *            v    merge   v
		 *            <------------>
		 *            .            .
		 * merge_existing_range() updates to:
		 *            .            .
		 * vmg->start vmg->end     .
		 * |          |            .
		 * v  retain  v            .
		 * <---------->            .
		 *             delta       .
		 *            <----->      .
		 * |----------------|------|
		 * |    middle      | next |
		 * |----------------|------|
		 *                  ^
		 *                  |
		 *                  next->vm_start
		 */
		struct vm_area_struct *next = vmg->next;
		const unsigned long delta = next->vm_start - vmg->end;

		__vma_set_range(next, vmg->end, next->vm_end);
		vma_sub_pgoff(next, delta >> PAGE_SHIFT);
	}
}

/*
 * Actually perform the VMA merge operation.
 *
 * IMPORTANT: We guarantee that, should vmg->give_up_on_oom is set, to not
 * modify any VMAs or cause inconsistent state should an OOM condition arise.
 *
 * Returns 0 on success, or an error value on failure.
 */
#define CMERGE_DONE		0
#define CMERGE_APPLY		1

struct rust_cmerge_state {
	struct vma_merge_struct *vmg;
	struct vm_area_struct *vma;
};

static int cmerge_classify(struct rust_cmerge_state *s, int *out)
{
	struct vma_merge_struct *vmg = s->vmg;

	*out = 0;
	if (vmg->__adjust_next_start) {
		/* We manipulate middle and adjust next, which is the target. */
		s->vma = vmg->middle;
		vma_iter_config(vmg->vmi, vmg->end, vmg->next->vm_end);
	} else {
		s->vma = vmg->target;
		 /* Note: vma iterator must be pointing to 'start'. */
		vma_iter_config(vmg->vmi, vmg->start, vmg->end);
	}

	/*
	 * If vmg->give_up_on_oom is set, we're safe, because we don't actually
	 * manipulate any VMAs until we succeed at preallocation.
	 *
	 * Past this point, we will not return an error.
	 */
	if (vma_iter_prealloc(vmg->vmi, s->vma)) {
		*out = -ENOMEM;
		return CMERGE_DONE;
	}
	return CMERGE_APPLY;
}

static int cmerge_apply(struct rust_cmerge_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *vma = s->vma;
	struct vma_prepare vp;

	init_multi_vma_prep(&vp, vma, vmg);
	vma_prepare(&vp);
	/*
	 * THP pages may need to do additional splits if we increase
	 * middle->vm_start.
	 */
	vma_adjust_trans_huge(vma, vmg->start, vmg->end,
			      vmg->__adjust_middle_start ? vmg->middle : NULL);
	vma_set_range(vma, vmg->start, vmg->end, vmg_start_pgoff(vmg),
		      vmg_start_anon_pgoff(vmg));
	vmg_adjust_set_range(vmg);
	vma_iter_store_overwrite(vmg->vmi, vmg->target);

	vma_complete(&vp, vmg->vmi, vma->vm_mm);
	return 0;
}

#ifdef CONFIG_RUST_MMAP
int rust_cmerge_classify(struct rust_cmerge_state *s, int *out)
{
	return cmerge_classify(s, out);
}

int rust_cmerge_apply(struct rust_cmerge_state *s)
{
	return cmerge_apply(s);
}
#endif

static int finish_cmerge(struct rust_cmerge_state *s)
{
	int out = 0;

	if (cmerge_classify(s, &out) == CMERGE_DONE)
		return out;
	return cmerge_apply(s);
}

static int commit_merge(struct vma_merge_struct *vmg)
{
	struct rust_cmerge_state s = {
		.vmg = vmg,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_cmerge_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_cmerge(&s);
}

/* We can only remove VMAs when merging if they do not have a close hook. */
static bool can_merge_remove_vma(struct vm_area_struct *vma)
{
	return !vma->vm_ops || !vma->vm_ops->close;
}

/*
 * vma_merge_existing_range - Attempt to merge VMAs based on a VMA having its
 * attributes modified.
 *
 * @vmg: Describes the modifications being made to a VMA and associated
 *       metadata.
 *
 * When the attributes of a range within a VMA change, then it might be possible
 * for immediately adjacent VMAs to be merged into that VMA due to having
 * identical properties.
 *
 * This function checks for the existence of any such mergeable VMAs and updates
 * the maple tree describing the @vmg->middle->vm_mm address space to account
 * for this, as well as any VMAs shrunk/expanded/deleted as a result of this
 * merge.
 *
 * As part of this operation, if a merge occurs, the @vmg object will have its
 * vma, start, end, and pgoff fields modified to execute the merge. Subsequent
 * calls to this function should reset these fields.
 *
 * Returns: The merged VMA if merge succeeds, or NULL otherwise.
 *
 * ASSUMPTIONS:
 * - The caller must assign the VMA to be modified to @vmg->middle.
 * - The caller must have set @vmg->prev to the previous VMA, if there is one.
 * - The caller must not set @vmg->next, as we determine this.
 * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
 * - vmi must be positioned within [@vmg->middle->vm_start, @vmg->middle->vm_end).
 */
#define VEX_NONE		0
#define VEX_BOTH		1
#define VEX_LEFT		2
#define VEX_RIGHT		3

struct rust_vex_state {
	struct vma_merge_struct *vmg;
	vma_flags_t sticky_flags;
	struct vm_area_struct *middle;
	struct vm_area_struct *prev;
	struct vm_area_struct *next;
	struct vm_area_struct *anon_dup;
	unsigned long start;
};

static int vex_classify(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *middle;
	struct vm_area_struct *prev;
	struct vm_area_struct *next;
	unsigned long start;
	unsigned long end;
	bool left_side, right_side;
	bool merge_left, merge_right, merge_both;

	s->anon_dup = NULL;
	s->next = NULL;
	middle = s->middle = vmg->middle;
	prev = s->prev = vmg->prev;
	start = s->start = vmg->start;
	end = vmg->end;
	s->sticky_flags = vma_flags_and_mask(&vmg->vma_flags, VMA_STICKY_FLAGS);
	left_side = middle && start == middle->vm_start;
	right_side = middle && end == middle->vm_end;

	mmap_assert_write_locked(vmg->mm);
	VM_WARN_ON_VMG(!middle, vmg); /* We are modifying a VMA, so caller must specify. */
	VM_WARN_ON_VMG(vmg->next, vmg); /* We set this. */
	VM_WARN_ON_VMG(prev && start <= prev->vm_start, vmg);
	VM_WARN_ON_VMG(start >= end, vmg);

	/*
	 * If middle == prev, then we are offset into a VMA. Otherwise, if we are
	 * not, we must span a portion of the VMA.
	 */
	VM_WARN_ON_VMG(middle &&
		       ((middle != prev && vmg->start != middle->vm_start) ||
			vmg->end > middle->vm_end), vmg);
	/* The vmi must be positioned within vmg->middle. */
	VM_WARN_ON_VMG(middle &&
		       !(vma_iter_addr(vmg->vmi) >= middle->vm_start &&
			 vma_iter_addr(vmg->vmi) < middle->vm_end), vmg);
	/* An existing merge can never be used by the mremap() logic. */
	VM_WARN_ON_VMG(vmg->copied_from, vmg);

	vmg->state = VMA_MERGE_NOMERGE;

	/*
	 * If a special mapping or if the range being modified is neither at the
	 * furthermost left or right side of the VMA, then we have no chance of
	 * merging and should abort.
	 */
	if (vma_flags_test_any_mask(&vmg->vma_flags, VMA_SPECIAL_FLAGS) ||
	    (!left_side && !right_side))
		return VEX_NONE;

	if (left_side)
		merge_left = can_vma_merge_left(vmg);
	else
		merge_left = false;

	if (right_side) {
		next = vmg->next = vma_iter_next_range(vmg->vmi);
		vma_iter_prev_range(vmg->vmi);

		merge_right = can_vma_merge_right(vmg, merge_left);
	} else {
		merge_right = false;
		next = NULL;
	}
	s->next = next;

	if (merge_left)		/* If merging prev, position iterator there. */
		vma_prev(vmg->vmi);
	else if (!merge_right)	/* If we have nothing to merge, abort. */
		return VEX_NONE;

	merge_both = merge_left && merge_right;
	/* If we span the entire VMA, a merge implies it will be deleted. */
	vmg->__remove_middle = left_side && right_side;

	/*
	 * If we need to remove middle in its entirety but are unable to do so,
	 * we have no sensible recourse but to abort the merge.
	 */
	if (vmg->__remove_middle && !can_merge_remove_vma(middle))
		return VEX_NONE;

	/*
	 * If we merge both VMAs, then next is also deleted. This implies
	 * merge_will_delete_vma also.
	 */
	vmg->__remove_next = merge_both;

	/*
	 * If we cannot delete next, then we can reduce the operation to merging
	 * prev and middle (thereby deleting middle).
	 */
	if (vmg->__remove_next && !can_merge_remove_vma(next)) {
		vmg->__remove_next = false;
		merge_right = false;
		merge_both = false;
	}

	/* No matter what happens, we will be adjusting middle. */
	vma_start_write(middle);

	if (merge_right) {
		vma_flags_t next_sticky;

		vma_start_write(next);
		vmg->target = next;
		next_sticky = vma_flags_and_mask(&next->flags, VMA_STICKY_FLAGS);
		vma_flags_set_mask(&s->sticky_flags, next_sticky);
	}

	if (merge_left) {
		vma_flags_t prev_sticky;

		vma_start_write(prev);
		vmg->target = prev;

		prev_sticky = vma_flags_and_mask(&prev->flags, VMA_STICKY_FLAGS);
		vma_flags_set_mask(&s->sticky_flags, prev_sticky);
	}

	if (merge_both)
		return VEX_BOTH;
	if (merge_left)
		return VEX_LEFT;
	return VEX_RIGHT;
}

static int vex_both(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *prev = s->prev;
	struct vm_area_struct *next = s->next;
	struct vm_area_struct *middle = s->middle;

	/*
	 * |<-------------------->|
	 * |-------********-------|
	 *   prev   middle   next
	 *  extend  delete  delete
	 */
	vmg->start = prev->vm_start;
	vmg->end = next->vm_end;
	vmg->pgoff = vma_start_pgoff(prev);
	vmg->anon_pgoff = vma_start_anon_pgoff(prev);

	/*
	 * We already ensured anon_vma compatibility above, so now it's
	 * simply a case of, if prev has no anon_vma object, which of
	 * next or middle contains the anon_vma we must duplicate.
	 */
	return dup_anon_vma(prev, next->anon_vma ? next : middle, &s->anon_dup);
}

static int vex_left(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *prev = s->prev;
	struct vm_area_struct *middle = s->middle;

	/*
	 * |<------------>|      OR
	 * |<----------------->|
	 * |-------*************
	 *   prev     middle
	 *  extend shrink/delete
	 */
	vmg->start = prev->vm_start;
	vmg->pgoff = vma_start_pgoff(prev);
	vmg->anon_pgoff = vma_start_anon_pgoff(prev);

	if (!vmg->__remove_middle)
		vmg->__adjust_middle_start = true;

	return dup_anon_vma(prev, middle, &s->anon_dup);
}

static int vex_right(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *middle = s->middle;
	struct vm_area_struct *prev = s->prev;
	struct vm_area_struct *next = s->next;
	const pgoff_t pglen = vmg_pages(vmg);

	/*
	 *     |<------------->| OR
	 * |<----------------->|
	 * *************-------|
	 *    middle     next
	 * shrink/delete extend
	 */
	VM_WARN_ON_VMG(vmg->start > middle->vm_start && prev && middle != prev, vmg);

	if (vmg->__remove_middle) {
		vmg->end = next->vm_end;
		vmg->pgoff = vma_start_pgoff(next) - pglen;
		vmg->anon_pgoff = vma_start_anon_pgoff(next) - pglen;
	} else {
		/* We shrink middle and expand next. */
		vmg->__adjust_next_start = true;
		vmg->start = middle->vm_start;
		vmg->end = s->start;
		vmg->pgoff = vma_start_pgoff(middle);
		vmg->anon_pgoff = vma_start_anon_pgoff(middle);
	}

	return dup_anon_vma(next, middle, &s->anon_dup);
}

static struct vm_area_struct *vex_commit(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;

	if (commit_merge(vmg))
		return NULL;

	vma_set_flags_mask(vmg->target, s->sticky_flags);
	khugepaged_enter_vma(vmg->target, vmg->vm_flags);
	vmg->state = VMA_MERGE_SUCCESS;
	return vmg->target;
}

static void vex_abort(struct rust_vex_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;

	vma_iter_set(vmg->vmi, s->start);
	vma_iter_load(vmg->vmi);

	if (s->anon_dup)
		unlink_anon_vmas(s->anon_dup);
	s->anon_dup = NULL;

	/*
	 * This means we have failed to clone anon_vma's correctly, but no
	 * actual changes to VMAs have occurred, so no harm no foul - if the
	 * user doesn't want this reported and instead just wants to give up on
	 * the merge, allow it.
	 */
	if (!vmg->give_up_on_oom)
		vmg->state = VMA_MERGE_ERROR_NOMEM;
}

#ifdef CONFIG_RUST_MMAP
int rust_vex_classify(struct rust_vex_state *s)
{
	return vex_classify(s);
}

int rust_vex_both(struct rust_vex_state *s)
{
	return vex_both(s);
}

int rust_vex_left(struct rust_vex_state *s)
{
	return vex_left(s);
}

int rust_vex_right(struct rust_vex_state *s)
{
	return vex_right(s);
}

struct vm_area_struct *rust_vex_commit(struct rust_vex_state *s)
{
	return vex_commit(s);
}

void rust_vex_abort(struct rust_vex_state *s)
{
	vex_abort(s);
}
#endif

static struct vm_area_struct *finish_vex(struct rust_vex_state *s)
{
	int kind;
	int err;

	kind = vex_classify(s);
	if (kind == VEX_NONE)
		return NULL;
	if (kind == VEX_BOTH)
		err = vex_both(s);
	else if (kind == VEX_LEFT)
		err = vex_left(s);
	else
		err = vex_right(s);
	if (err) {
		vex_abort(s);
		return NULL;
	}
	if (!vex_commit(s)) {
		vex_abort(s);
		return NULL;
	}
	return s->vmg->target;
}

static __must_check struct vm_area_struct *vma_merge_existing_range(
		struct vma_merge_struct *vmg)
{
	struct rust_vex_state s = {
		.vmg = vmg,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	struct vm_area_struct *rust_ret;

	rust_ret = rust_vex_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vex(&s);
}

/*
 * vma_merge_new_range - Attempt to merge a new VMA into address space
 *
 * @vmg: Describes the VMA we are adding, in the range @vmg->start to @vmg->end
 *       (exclusive), which we try to merge with any adjacent VMAs if possible.
 *
 * We are about to add a VMA to the address space starting at @vmg->start and
 * ending at @vmg->end. There are three different possible scenarios:
 *
 * 1. There is a VMA with identical properties immediately adjacent to the
 *    proposed new VMA [@vmg->start, @vmg->end) either before or after it -
 *    EXPAND that VMA:
 *
 * Proposed:       |-----|  or  |-----|
 * Existing:  |----|                  |----|
 *
 * 2. There are VMAs with identical properties immediately adjacent to the
 *    proposed new VMA [@vmg->start, @vmg->end) both before AND after it -
 *    EXPAND the former and REMOVE the latter:
 *
 * Proposed:       |-----|
 * Existing:  |----|     |----|
 *
 * 3. There are no VMAs immediately adjacent to the proposed new VMA or those
 *    VMAs do not have identical attributes - NO MERGE POSSIBLE.
 *
 * In instances where we can merge, this function returns the expanded VMA which
 * will have its range adjusted accordingly and the underlying maple tree also
 * adjusted.
 *
 * Returns: In instances where no merge was possible, NULL. Otherwise, a pointer
 *          to the VMA we expanded.
 *
 * This function adjusts @vmg to provide @vmg->next if not already specified,
 * and adjusts [@vmg->start, @vmg->end) to span the expanded range.
 *
 * ASSUMPTIONS:
 * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
 * - The caller must have determined that [@vmg->start, @vmg->end) is empty,
     other than VMAs that will be unmapped should the operation succeed.
 * - The caller must have specified the previous vma in @vmg->prev.
 * - The caller must have specified the next vma in @vmg->next.
 * - The caller must have positioned the vmi at or before the gap.
 */
#define VMERGE_NONE		0
#define VMERGE_EXPAND		1

static int vmerge_classify(struct vma_merge_struct *vmg)
{
	struct vm_area_struct *prev = vmg->prev;
	struct vm_area_struct *next = vmg->next;
	unsigned long end = vmg->end;
	bool can_merge_left, can_merge_right;

	mmap_assert_write_locked(vmg->mm);
	VM_WARN_ON_VMG(vmg->middle, vmg);
	VM_WARN_ON_VMG(vmg->target, vmg);
	/* vmi must point at or before the gap. */
	VM_WARN_ON_VMG(vma_iter_addr(vmg->vmi) > end, vmg);

	vmg->state = VMA_MERGE_NOMERGE;

	/* Special VMAs are unmergeable, also if no prev/next. */
	if (vma_flags_test_any_mask(&vmg->vma_flags, VMA_SPECIAL_FLAGS) ||
	    (!prev && !next))
		return VMERGE_NONE;

	can_merge_left = can_vma_merge_left(vmg);
	can_merge_right = !vmg->just_expand && can_vma_merge_right(vmg, can_merge_left);

	/* If we can merge with the next VMA, adjust vmg accordingly. */
	if (can_merge_right) {
		vmg->end = next->vm_end;
		vmg->target = next;
	}

	/* If we can merge with the previous VMA, adjust vmg accordingly. */
	if (can_merge_left) {
		vmg->start = prev->vm_start;
		vmg->target = prev;
		vmg->pgoff = vma_start_pgoff(prev);
		vmg->anon_pgoff = vma_start_anon_pgoff(prev);

		/*
		 * If this merge would result in removal of the next VMA but we
		 * are not permitted to do so, reduce the operation to merging
		 * prev and vma.
		 */
		if (can_merge_right && !can_merge_remove_vma(next))
			vmg->end = end;

		/* In expand-only case we are already positioned at prev. */
		if (!vmg->just_expand) {
			/* Equivalent to going to the previous range. */
			vma_prev(vmg->vmi);
		}
	}

	if (vmg->target)
		return VMERGE_EXPAND;
	return VMERGE_NONE;
}

static struct vm_area_struct *vmerge_expand(struct vma_merge_struct *vmg)
{
	/*
	 * Now try to expand adjacent VMA(s). This takes care of removing the
	 * following VMA if we have VMAs on both sides.
	 */
	if (vmg->target && !vma_expand(vmg)) {
		khugepaged_enter_vma(vmg->target, vmg->vm_flags);
		vmg->state = VMA_MERGE_SUCCESS;
		return vmg->target;
	}

	return NULL;
}

#ifdef CONFIG_RUST_MMAP
int rust_vmerge_classify(struct vma_merge_struct *vmg)
{
	return vmerge_classify(vmg);
}

struct vm_area_struct *rust_vmerge_expand(struct vma_merge_struct *vmg)
{
	return vmerge_expand(vmg);
}
#endif

static struct vm_area_struct *finish_vmerge(struct vma_merge_struct *vmg)
{
	if (vmerge_classify(vmg) == VMERGE_EXPAND)
		return vmerge_expand(vmg);
	return NULL;
}

struct vm_area_struct *vma_merge_new_range(struct vma_merge_struct *vmg)
{
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	struct vm_area_struct *rust_ret;

	rust_ret = rust_vmerge_dispatch(vmg, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vmerge(vmg);
}

/*
 * vma_merge_copied_range - Attempt to merge a VMA that is being copied by
 * mremap()
 *
 * @vmg: Describes the VMA we are adding, in the copied-to range @vmg->start to
 *       @vmg->end (exclusive), which we try to merge with any adjacent VMAs if
 *       possible.
 *
 * vmg->prev, next, start, end, pgoff should all be relative to the COPIED TO
 * range, i.e. the target range for the VMA.
 *
 * Returns: In instances where no merge was possible, NULL. Otherwise, a pointer
 *          to the VMA we expanded.
 *
 * ASSUMPTIONS: Same as vma_merge_new_range(), except vmg->middle must contain
 *              the copied-from VMA.
 */
static struct vm_area_struct *vma_merge_copied_range(struct vma_merge_struct *vmg)
{
	/* We must have a copied-from VMA. */
	VM_WARN_ON_VMG(!vmg->middle, vmg);

	vmg->copied_from = vmg->middle;
	vmg->middle = NULL;
	return vma_merge_new_range(vmg);
}

/*
 * vma_expand - Expand an existing VMA
 *
 * @vmg: Describes a VMA expansion operation.
 *
 * Expand @vma to vmg->start and vmg->end.  Can expand off the start and end.
 * Will expand over vmg->next if it's different from vmg->target and vmg->end ==
 * vmg->next->vm_end.  Checking if the vmg->target can expand and merge with
 * vmg->next needs to be handled by the caller.
 *
 * Returns: 0 on success.
 *
 * ASSUMPTIONS:
 * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
 * - The caller must have set @vmg->target and @vmg->next.
 */
#define VEXP_DONE		0
#define VEXP_COMMIT		1

struct rust_vexp_state {
	struct vma_merge_struct *vmg;
	struct vm_area_struct *anon_dup;
	struct vm_area_struct *target;
	struct vm_area_struct *next;
	vma_flags_t sticky_flags;
	bool remove_next;
};

static int vexp_classify(struct rust_vexp_state *s, int *out)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *target = vmg->target;
	struct vm_area_struct *next = vmg->next;
	vma_flags_t target_sticky;
	int ret = 0;

	*out = 0;
	s->anon_dup = NULL;
	s->target = target;
	s->next = next;
	s->remove_next = false;
	s->sticky_flags = vma_flags_and_mask(&vmg->vma_flags, VMA_STICKY_FLAGS);

	mmap_assert_write_locked(vmg->mm);
	vma_start_write(target);

	target_sticky = vma_flags_and_mask(&target->flags, VMA_STICKY_FLAGS);

	if (next && target != next && vmg->end == next->vm_end)
		s->remove_next = true;

	/* We must have a target. */
	VM_WARN_ON_VMG(!target, vmg);
	/* This should have already been checked by this point. */
	VM_WARN_ON_VMG(s->remove_next && !can_merge_remove_vma(next), vmg);
	/* Not merging but overwriting any part of next is not handled. */
	VM_WARN_ON_VMG(next && !s->remove_next &&
		       next != target && vmg->end > next->vm_start, vmg);
	/* Only handles expanding. */
	VM_WARN_ON_VMG(target->vm_start < vmg->start ||
		       target->vm_end > vmg->end, vmg);

	vma_flags_set_mask(&s->sticky_flags, target_sticky);

	/*
	 * If we are removing the next VMA or copying from a VMA
	 * (e.g. mremap()'ing), we must propagate anon_vma state.
	 *
	 * Note that, by convention, callers ignore OOM for this case, so
	 * we don't need to account for vmg->give_up_on_mm here.
	 */
	if (s->remove_next)
		ret = dup_anon_vma(target, next, &s->anon_dup);
	if (!ret && vmg->copied_from)
		ret = dup_anon_vma(target, vmg->copied_from, &s->anon_dup);
	if (ret) {
		*out = ret;
		return VEXP_DONE;
	}
	return VEXP_COMMIT;
}

static int vexp_commit(struct rust_vexp_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;

	if (s->remove_next) {
		vma_flags_t next_sticky;

		vma_start_write(s->next);
		vmg->__remove_next = true;

		next_sticky = vma_flags_and_mask(&s->next->flags, VMA_STICKY_FLAGS);
		vma_flags_set_mask(&s->sticky_flags, next_sticky);
	}
	if (commit_merge(vmg))
		return -ENOMEM;

	vma_set_flags_mask(s->target, s->sticky_flags);
	return 0;
}

static void vexp_abort(struct rust_vexp_state *s)
{
	if (s->anon_dup)
		unlink_anon_vmas(s->anon_dup);
	/*
	 * If the user requests that we just give upon OOM, we are safe to do so
	 * here, as commit merge provides this contract to us. Nothing has been
	 * changed - no harm no foul, just don't report it.
	 */
	if (!s->vmg->give_up_on_oom)
		s->vmg->state = VMA_MERGE_ERROR_NOMEM;
}

#ifdef CONFIG_RUST_MMAP
int rust_vexp_classify(struct rust_vexp_state *s, int *out)
{
	return vexp_classify(s, out);
}

int rust_vexp_commit(struct rust_vexp_state *s)
{
	return vexp_commit(s);
}

void rust_vexp_abort(struct rust_vexp_state *s)
{
	vexp_abort(s);
}
#endif

static int finish_vexp(struct rust_vexp_state *s)
{
	int out = 0;

	if (vexp_classify(s, &out) == VEXP_DONE)
		return out;
	if (vexp_commit(s)) {
		vexp_abort(s);
		return -ENOMEM;
	}
	return 0;
}

int vma_expand(struct vma_merge_struct *vmg)
{
	struct rust_vexp_state s = {
		.vmg = vmg,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_vexp_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vexp(&s);
}

/**
 * vma_shrink() - Shrink the end of a VMA
 * @vmi: The vma iterator
 * @vma: The VMA to modify
 * @end: The new end
 *
 * Note that the caller may only shrink the end of the VMA.
 *
 * Returns: 0 on success, -ENOMEM otherwise
 */
#define VSH_DONE		0
#define VSH_APPLY		1

struct rust_vsh_state {
	struct vma_iterator *vmi;
	struct vm_area_struct *vma;
	unsigned long end;
};

static int vsh_classify(struct rust_vsh_state *s, int *out)
{
	*out = 0;
	VM_WARN_ON_ONCE(s->end > s->vma->vm_end);

	vma_iter_config(s->vmi, s->end, s->vma->vm_end);
	if (vma_iter_prealloc(s->vmi, NULL)) {
		*out = -ENOMEM;
		return VSH_DONE;
	}
	return VSH_APPLY;
}

static int vsh_apply(struct rust_vsh_state *s)
{
	struct vma_prepare vp;

	vma_start_write(s->vma);

	init_vma_prep(&vp, s->vma);
	vma_prepare(&vp);
	vma_adjust_trans_huge(s->vma, s->vma->vm_start, s->end, NULL);

	vma_iter_clear(s->vmi);
	__vma_set_range(s->vma, s->vma->vm_start, s->end);
	vma_complete(&vp, s->vmi, s->vma->vm_mm);
	validate_mm(s->vma->vm_mm);
	return 0;
}

#ifdef CONFIG_RUST_MMAP
int rust_vsh_classify(struct rust_vsh_state *s, int *out)
{
	return vsh_classify(s, out);
}

int rust_vsh_apply(struct rust_vsh_state *s)
{
	return vsh_apply(s);
}
#endif

static int finish_vsh(struct rust_vsh_state *s)
{
	int out = 0;

	if (vsh_classify(s, &out) == VSH_DONE)
		return out;
	return vsh_apply(s);
}

int vma_shrink(struct vma_iterator *vmi, struct vm_area_struct *vma,
	       unsigned long end)
{
	struct rust_vsh_state s = {
		.vmi = vmi,
		.vma = vma,
		.end = end,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_vsh_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vsh(&s);
}

static inline void vms_clear_ptes(struct vma_munmap_struct *vms,
		    struct ma_state *mas_detach, bool mm_wr_locked)
{
	struct unmap_desc unmap = {
		.mas = mas_detach,
		.first = vms->vma,
		/* start and end may be different if there is no prev or next vma. */
		.pg_start = vms->unmap_start,
		.pg_end = vms->unmap_end,
		.vma_start = vms->start,
		.vma_end = vms->end,
		/*
		 * The tree limits and reset differ from the normal case since it's a
		 * side-tree
		 */
		.tree_reset = 1,
		.tree_end = vms->vma_count,
		/*
		 * We can free page tables without write-locking mmap_lock because VMAs
		 * were isolated before we downgraded mmap_lock.
		 */
		.mm_wr_locked = mm_wr_locked,
	};

	if (!vms->clear_ptes) /* Nothing to do */
		return;

	mas_set(mas_detach, 1);
	unmap_region(&unmap);
	vms->clear_ptes = false;
}

static void vms_clean_up_area(struct vma_munmap_struct *vms,
		struct ma_state *mas_detach)
{
	struct vm_area_struct *vma;

	if (!vms->nr_pages)
		return;

	vms_clear_ptes(vms, mas_detach, true);
	mas_set(mas_detach, 0);
	mas_for_each(mas_detach, vma, ULONG_MAX)
		vma_close(vma);
}

/*
 * vms_complete_munmap_vmas() - Finish the munmap() operation
 * @vms: The vma munmap struct
 * @mas_detach: The maple state of the detached vmas
 *
 * This updates the mm_struct, unmaps the region, frees the resources
 * used for the munmap() and may downgrade the lock - if requested.  Everything
 * needed to be done once the vma maple tree is updated.
 */
#define VCOMP_DONE		0
#define VCOMP_UNMAP		1

struct rust_vcomp_state {
	struct vma_munmap_struct *vms;
	struct ma_state *mas_detach;
	struct mm_struct *mm;
	bool need_unmap;
};

static int vcomp_classify(struct rust_vcomp_state *s)
{
	struct vma_munmap_struct *vms = s->vms;
	struct mm_struct *mm = current->mm;

	s->mm = mm;
	s->need_unmap = false;
	mm->map_count -= vms->vma_count;
	mm->locked_vm -= vms->locked_vm;
	if (vms->unlock)
		mmap_write_downgrade(mm);

	if (!vms->nr_pages)
		return VCOMP_DONE;

	s->need_unmap = true;
	return VCOMP_UNMAP;
}

static void vcomp_unmap(struct rust_vcomp_state *s)
{
	struct vma_munmap_struct *vms = s->vms;
	struct ma_state *mas_detach = s->mas_detach;
	struct mm_struct *mm = s->mm;
	struct vm_area_struct *vma;

	vms_clear_ptes(vms, mas_detach, !vms->unlock);
	/* Update high watermark before we lower total_vm */
	update_hiwater_vm(mm);
	/* Stat accounting */
	WRITE_ONCE(mm->total_vm, READ_ONCE(mm->total_vm) - vms->nr_pages);
	/* Paranoid bookkeeping */
	VM_WARN_ON(vms->exec_vm > mm->exec_vm);
	VM_WARN_ON(vms->stack_vm > mm->stack_vm);
	VM_WARN_ON(vms->data_vm > mm->data_vm);
	mm->exec_vm -= vms->exec_vm;
	mm->stack_vm -= vms->stack_vm;
	mm->data_vm -= vms->data_vm;

	/* Remove and clean up vmas */
	mas_set(mas_detach, 0);
	mas_for_each(mas_detach, vma, ULONG_MAX)
		remove_vma(vma);

	vm_unacct_memory(vms->nr_accounted);
	validate_mm(mm);
	if (vms->unlock)
		mmap_read_unlock(mm);

	__mt_destroy(mas_detach->tree);
	s->need_unmap = false;
}

static void vcomp_abort(struct rust_vcomp_state *s)
{
	if (s->need_unmap)
		vcomp_unmap(s);
}

#ifdef CONFIG_RUST_MMAP
int rust_vcomp_classify(struct rust_vcomp_state *s)
{
	return vcomp_classify(s);
}

void rust_vcomp_unmap(struct rust_vcomp_state *s)
{
	vcomp_unmap(s);
}

void rust_vcomp_abort(struct rust_vcomp_state *s)
{
	vcomp_abort(s);
}
#endif

static void finish_vcomp(struct rust_vcomp_state *s)
{
	if (vcomp_classify(s) == VCOMP_DONE)
		return;
	vcomp_unmap(s);
}

static void vms_complete_munmap_vmas(struct vma_munmap_struct *vms,
		struct ma_state *mas_detach)
{
	struct rust_vcomp_state s = {
		.vms = vms,
		.mas_detach = mas_detach,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;

		rust_vcomp_dispatch(&s, &handled);
		if (handled)
			return;
	}
#endif
	finish_vcomp(&s);
}

/*
 * reattach_vmas() - Undo any munmap work and free resources
 * @mas_detach: The maple state with the detached maple tree
 *
 * Reattach any detached vmas and free up the maple tree used to track the vmas.
 */
static void reattach_vmas(struct ma_state *mas_detach)
{
	struct vm_area_struct *vma;

	mas_set(mas_detach, 0);
	mas_for_each(mas_detach, vma, ULONG_MAX)
		vma_mark_attached(vma);

	__mt_destroy(mas_detach->tree);
}

/*
 * vms_gather_munmap_vmas() - Put all VMAs within a range into a maple tree
 * for removal at a later date.  Handles splitting first and last if necessary
 * and marking the vmas as isolated.
 *
 * @vms: The vma munmap struct
 * @mas_detach: The maple state tracking the detached tree
 *
 * Return: 0 on success, error otherwise
 */
#define GATHER_DONE		0
#define GATHER_LOOP		1

struct rust_gather_state {
	struct vma_munmap_struct *vms;
	struct ma_state *mas_detach;
};

static int gather_classify(struct rust_gather_state *s, int *out)
{
	struct vma_munmap_struct *vms = s->vms;
	int error;

	*out = 0;
	/*
	 * If we need to split any vma, do it now to save pain later.
	 * Does it split the first one?
	 */
	if (vms->start > vms->vma->vm_start) {
		/*
		 * Make sure that map_count on return from munmap() will
		 * not exceed its limit; but let map_count go just above
		 * its limit temporarily, to help free resources as expected.
		 */
		if (vms->end < vms->vma->vm_end &&
		    vms->vma->vm_mm->map_count >= get_sysctl_max_map_count()) {
			*out = -ENOMEM;
			return GATHER_DONE;
		}

		/* Don't bother splitting the VMA if we can't unmap it anyway */
		if (vma_is_sealed(vms->vma)) {
			*out = -EPERM;
			return GATHER_DONE;
		}

		error = __split_vma(vms->vmi, vms->vma, vms->start, 1);
		if (error) {
			*out = error;
			return GATHER_DONE;
		}
	}
	vms->prev = vma_prev(vms->vmi);
	if (vms->prev)
		vms->unmap_start = vms->prev->vm_end;
	return GATHER_LOOP;
}

static int gather_loop(struct rust_gather_state *s)
{
	struct vma_munmap_struct *vms = s->vms;
	struct ma_state *mas_detach = s->mas_detach;
	struct vm_area_struct *next = NULL;
	int error;
	long nrpages;

	/*
	 * Detach a range of VMAs from the mm. Using next as a temp variable as
	 * it is always overwritten.
	 */
	for_each_vma_range(*(vms->vmi), next, vms->end) {
		if (vma_is_sealed(next)) {
			error = -EPERM;
			goto modify_vma_failed;
		}
		/* Does it split the end? */
		if (next->vm_end > vms->end) {
			error = __split_vma(vms->vmi, next, vms->end, 0);
			if (error)
				goto end_split_failed;
		}
		vma_start_write(next);
		mas_set(mas_detach, vms->vma_count++);
		error = mas_store_gfp(mas_detach, next, GFP_KERNEL);
		if (error)
			goto munmap_gather_failed;

		vma_mark_detached(next);
		nrpages = vma_pages(next);

		vms->nr_pages += nrpages;
		if (vma_test(next, VMA_LOCKED_BIT))
			vms->locked_vm += nrpages;

		if (vma_test(next, VMA_ACCOUNT_BIT))
			vms->nr_accounted += nrpages;

		if (is_exec_mapping(next->vm_flags))
			vms->exec_vm += nrpages;
		else if (is_stack_mapping(next->vm_flags))
			vms->stack_vm += nrpages;
		else if (is_data_mapping_vma_flags(&next->flags))
			vms->data_vm += nrpages;

		if (vms->uf) {
			/*
			 * If userfaultfd_unmap_prep returns an error the vmas
			 * will remain split, but userland will get a
			 * highly unexpected error anyway. This is no
			 * different than the case where the first of the two
			 * __split_vma fails, but we don't undo the first
			 * split, despite we could. This is unlikely enough
			 * failure that it's not worth optimizing it for.
			 */
			error = userfaultfd_unmap_prep(next, vms->start,
						       vms->end, vms->uf);
			if (error)
				goto userfaultfd_error;
		}
#ifdef CONFIG_DEBUG_VM_MAPLE_TREE
		BUG_ON(next->vm_start < vms->start);
		BUG_ON(next->vm_start > vms->end);
#endif
	}

	vms->next = vma_next(vms->vmi);
	if (vms->next)
		vms->unmap_end = vms->next->vm_start;

#if defined(CONFIG_DEBUG_VM_MAPLE_TREE)
	/* Make sure no VMAs are about to be lost. */
	{
		MA_STATE(test, mas_detach->tree, 0, 0);
		struct vm_area_struct *vma_mas, *vma_test;
		int test_count = 0;

		vma_iter_set(vms->vmi, vms->start);
		rcu_read_lock();
		vma_test = mas_find(&test, vms->vma_count - 1);
		for_each_vma_range(*(vms->vmi), vma_mas, vms->end) {
			BUG_ON(vma_mas != vma_test);
			test_count++;
			vma_test = mas_next(&test, vms->vma_count - 1);
		}
		rcu_read_unlock();
		BUG_ON(vms->vma_count != test_count);
	}
#endif

	while (vma_iter_addr(vms->vmi) > vms->start)
		vma_iter_prev_range(vms->vmi);

	vms->clear_ptes = true;
	return 0;

userfaultfd_error:
munmap_gather_failed:
end_split_failed:
modify_vma_failed:
	reattach_vmas(mas_detach);
	return error;
}

static void gather_abort(struct rust_gather_state *s)
{
	if (s->vms->vma_count)
		reattach_vmas(s->mas_detach);
}

#ifdef CONFIG_RUST_MMAP
int rust_gather_classify(struct rust_gather_state *s, int *out)
{
	return gather_classify(s, out);
}

int rust_gather_loop(struct rust_gather_state *s)
{
	return gather_loop(s);
}

void rust_gather_abort(struct rust_gather_state *s)
{
	gather_abort(s);
}
#endif

static int finish_gather(struct rust_gather_state *s)
{
	int out = 0;

	if (gather_classify(s, &out) == GATHER_DONE)
		return out;
	return gather_loop(s);
}

static int vms_gather_munmap_vmas(struct vma_munmap_struct *vms,
		struct ma_state *mas_detach)
{
	struct rust_gather_state s = {
		.vms = vms,
		.mas_detach = mas_detach,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_gather_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_gather(&s);
}

/*
 * init_vma_munmap() - Initializer wrapper for vma_munmap_struct
 * @vms: The vma munmap struct
 * @vmi: The vma iterator
 * @vma: The first vm_area_struct to munmap
 * @start: The aligned start address to munmap
 * @end: The aligned end address to munmap
 * @uf: The userfaultfd list_head
 * @unlock: Unlock after the operation.  Only unlocked on success
 */
static void init_vma_munmap(struct vma_munmap_struct *vms,
		struct vma_iterator *vmi, struct vm_area_struct *vma,
		unsigned long start, unsigned long end, struct list_head *uf,
		bool unlock)
{
	vms->vmi = vmi;
	vms->vma = vma;
	if (vma) {
		vms->start = start;
		vms->end = end;
	} else {
		vms->start = vms->end = 0;
	}
	vms->unlock = unlock;
	vms->uf = uf;
	vms->vma_count = 0;
	vms->nr_pages = vms->locked_vm = vms->nr_accounted = 0;
	vms->exec_vm = vms->stack_vm = vms->data_vm = 0;
	vms->unmap_start = FIRST_USER_ADDRESS;
	vms->unmap_end = USER_PGTABLES_CEILING;
	vms->clear_ptes = false;
}

/*
 * do_vmi_align_munmap() - munmap the aligned region from @start to @end.
 * @vmi: The vma iterator
 * @vma: The starting vm_area_struct
 * @mm: The mm_struct
 * @start: The aligned start address to munmap.
 * @end: The aligned end address to munmap.
 * @uf: The userfaultfd list_head
 * @unlock: Set to true to drop the mmap_lock.  unlocking only happens on
 * success.
 *
 * Return: 0 on success and drops the lock if so directed, error and leaves the
 * lock held otherwise.
 */
#define AMUNMAP_DONE		0
#define AMUNMAP_COMPLETE	1

struct rust_amunmap_state {
	struct vma_iterator *vmi;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
	struct list_head *uf;
	bool unlock;
	struct maple_tree mt_detach;
	struct ma_state mas_detach;
	struct vma_munmap_struct vms;
	bool gathered;
};

static int amunmap_classify(struct rust_amunmap_state *s, int *out)
{
	int error;

	*out = 0;
	s->gathered = false;
	mt_init_flags(&s->mt_detach,
		      s->vmi->mas.tree->ma_flags & MT_FLAGS_LOCK_MASK);
	mt_on_stack(s->mt_detach);
	mas_init(&s->mas_detach, &s->mt_detach, 0);

	init_vma_munmap(&s->vms, s->vmi, s->vma, s->start, s->end, s->uf,
			s->unlock);
	error = vms_gather_munmap_vmas(&s->vms, &s->mas_detach);
	if (error)
		goto gather_failed;

	error = vma_iter_clear_gfp(s->vmi, s->start, s->end, GFP_KERNEL);
	if (error)
		goto clear_tree_failed;

	/* Point of no return */
	s->gathered = true;
	return AMUNMAP_COMPLETE;

clear_tree_failed:
	reattach_vmas(&s->mas_detach);
gather_failed:
	validate_mm(s->mm);
	*out = error;
	return AMUNMAP_DONE;
}

static int amunmap_complete(struct rust_amunmap_state *s)
{
	vms_complete_munmap_vmas(&s->vms, &s->mas_detach);
	s->gathered = false;
	return 0;
}

static void amunmap_abort(struct rust_amunmap_state *s)
{
	if (s->gathered) {
		vms_complete_munmap_vmas(&s->vms, &s->mas_detach);
		s->gathered = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_amunmap_classify(struct rust_amunmap_state *s, int *out)
{
	return amunmap_classify(s, out);
}

int rust_amunmap_complete(struct rust_amunmap_state *s)
{
	return amunmap_complete(s);
}

void rust_amunmap_abort(struct rust_amunmap_state *s)
{
	amunmap_abort(s);
}
#endif

static int finish_amunmap(struct rust_amunmap_state *s)
{
	int out = 0;

	if (amunmap_classify(s, &out) == AMUNMAP_DONE)
		return out;
	return amunmap_complete(s);
}

int do_vmi_align_munmap(struct vma_iterator *vmi, struct vm_area_struct *vma,
		struct mm_struct *mm, unsigned long start, unsigned long end,
		struct list_head *uf, bool unlock)
{
	struct rust_amunmap_state s = {
		.vmi = vmi,
		.vma = vma,
		.mm = mm,
		.start = start,
		.end = end,
		.uf = uf,
		.unlock = unlock,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_amunmap_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_amunmap(&s);
}

/*
 * do_vmi_munmap() - munmap a given range.
 * @vmi: The vma iterator
 * @mm: The mm_struct
 * @start: The start address to munmap
 * @len: The length of the range to munmap
 * @uf: The userfaultfd list_head
 * @unlock: set to true if the user wants to drop the mmap_lock on success
 *
 * This function takes a @mas that is either pointing to the previous VMA or set
 * to MA_START and sets it up to remove the mapping(s).  The @len will be
 * aligned.
 *
 * Return: 0 on success and drops the lock if so directed, error and leaves the
 * lock held otherwise.
 */
#ifdef CONFIG_RUST_MMAP
int rust_munmap_classify(struct vma_iterator *vmi, struct mm_struct *mm,
			 unsigned long start, size_t len, bool unlock, int *out,
			 struct vm_area_struct **vma_out, unsigned long *end_out)
{
	unsigned long end;
	struct vm_area_struct *vma;

	*out = 0;
	*vma_out = NULL;
	*end_out = 0;

	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start) {
		*out = -EINVAL;
		return RUST_MUNMAP_DONE;
	}

	end = start + PAGE_ALIGN(len);
	if (end == start) {
		*out = -EINVAL;
		return RUST_MUNMAP_DONE;
	}

	vma = vma_find(vmi, end);
	if (!vma) {
		if (unlock)
			mmap_write_unlock(mm);
		return RUST_MUNMAP_DONE;
	}

	*vma_out = vma;
	*end_out = end;
	return RUST_MUNMAP_ALIGN;
}

int rust_munmap_align(struct vma_iterator *vmi, struct vm_area_struct *vma,
		      struct mm_struct *mm, unsigned long start,
		      unsigned long end, struct list_head *uf, bool unlock)
{
	return do_vmi_align_munmap(vmi, vma, mm, start, end, uf, unlock);
}
#endif

int do_vmi_munmap(struct vma_iterator *vmi, struct mm_struct *mm,
		  unsigned long start, size_t len, struct list_head *uf,
		  bool unlock)
{
	unsigned long end;
	struct vm_area_struct *vma;
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_munmap_dispatch(vmi, mm, start, len, uf, unlock,
					&handled);
	if (handled)
		return rust_ret;
#endif

	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

	end = start + PAGE_ALIGN(len);
	if (end == start)
		return -EINVAL;

	/* Find the first overlapping VMA */
	vma = vma_find(vmi, end);
	if (!vma) {
		if (unlock)
			mmap_write_unlock(mm);
		return 0;
	}

	return do_vmi_align_munmap(vmi, vma, mm, start, end, uf, unlock);
}

/*
 * We are about to modify one or multiple of a VMA's flags, policy, userfaultfd
 * context and anonymous VMA name within the range [start, end).
 *
 * As a result, we might be able to merge the newly modified VMA range with an
 * adjacent VMA with identical properties.
 *
 * If no merge is possible and the range does not span the entirety of the VMA,
 * we then need to split the VMA to accommodate the change.
 *
 * The function returns either the merged VMA, the original VMA if a split was
 * required instead, or an error if the split failed.
 */
#define VMOD_DONE		0
#define VMOD_SPLIT		1

struct rust_vmod_state {
	struct vma_merge_struct *vmg;
};

static int vmod_classify(struct rust_vmod_state *s,
			 struct vm_area_struct **ret)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *merged;

	*ret = NULL;
	merged = vma_merge_existing_range(vmg);
	if (merged) {
		*ret = merged;
		return VMOD_DONE;
	}
	if (vmg_nomem(vmg)) {
		*ret = ERR_PTR(-ENOMEM);
		return VMOD_DONE;
	}
	return VMOD_SPLIT;
}

static struct vm_area_struct *vmod_split(struct rust_vmod_state *s)
{
	struct vma_merge_struct *vmg = s->vmg;
	struct vm_area_struct *vma = vmg->middle;
	unsigned long start = vmg->start;
	unsigned long end = vmg->end;
	int err;

	/*
	 * Split can fail for reasons other than OOM, so if the user requests
	 * this it's probably a mistake.
	 */
	VM_WARN_ON(vmg->give_up_on_oom &&
		   (vma->vm_start != start || vma->vm_end != end));

	/* Split any preceding portion of the VMA. */
	if (vma->vm_start < start) {
		err = split_vma(vmg->vmi, vma, start, 1);
		if (err)
			return ERR_PTR(err);
	}

	/* Split any trailing portion of the VMA. */
	if (vma->vm_end > end) {
		err = split_vma(vmg->vmi, vma, end, 0);
		if (err)
			return ERR_PTR(err);
	}

	return vma;
}

#ifdef CONFIG_RUST_MMAP
int rust_vmod_classify(struct rust_vmod_state *s, struct vm_area_struct **ret)
{
	return vmod_classify(s, ret);
}

struct vm_area_struct *rust_vmod_split(struct rust_vmod_state *s)
{
	return vmod_split(s);
}
#endif

static struct vm_area_struct *finish_vmod(struct rust_vmod_state *s)
{
	struct vm_area_struct *ret = NULL;

	if (vmod_classify(s, &ret) == VMOD_DONE)
		return ret;
	return vmod_split(s);
}

static struct vm_area_struct *vma_modify(struct vma_merge_struct *vmg)
{
	struct rust_vmod_state s = {
		.vmg = vmg,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	struct vm_area_struct *rust_ret;

	rust_ret = rust_vmod_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vmod(&s);
}

struct vm_area_struct *vma_modify_flags(struct vma_iterator *vmi,
		struct vm_area_struct *prev, struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		vma_flags_t *vma_flags_ptr)
{
	VMG_VMA_STATE(vmg, vmi, prev, vma, start, end);
	const vma_flags_t vma_flags = *vma_flags_ptr;
	struct vm_area_struct *ret;

	vmg.vma_flags = vma_flags;

	ret = vma_modify(&vmg);
	if (IS_ERR(ret))
		return ret;

	/*
	 * For a merge to succeed, the flags must match those
	 * requested. However, sticky flags may have been retained, so propagate
	 * them to the caller.
	 */
	if (vmg.state == VMA_MERGE_SUCCESS)
		*vma_flags_ptr = ret->flags;
	return ret;
}

struct vm_area_struct *vma_modify_name(struct vma_iterator *vmi,
		struct vm_area_struct *prev, struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		struct anon_vma_name *new_name)
{
	VMG_VMA_STATE(vmg, vmi, prev, vma, start, end);

	vmg.anon_name = new_name;

	return vma_modify(&vmg);
}

struct vm_area_struct *vma_modify_policy(struct vma_iterator *vmi,
		struct vm_area_struct *prev, struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		struct mempolicy *new_pol)
{
	VMG_VMA_STATE(vmg, vmi, prev, vma, start, end);

	vmg.policy = new_pol;

	return vma_modify(&vmg);
}

struct vm_area_struct *vma_modify_flags_uffd(struct vma_iterator *vmi,
		struct vm_area_struct *prev, struct vm_area_struct *vma,
		unsigned long start, unsigned long end,
		const vma_flags_t *vma_flags, struct vm_userfaultfd_ctx new_ctx,
		bool give_up_on_oom)
{
	VMG_VMA_STATE(vmg, vmi, prev, vma, start, end);

	vmg.vma_flags = *vma_flags;
	vmg.uffd_ctx = new_ctx;
	if (give_up_on_oom)
		vmg.give_up_on_oom = true;

	return vma_modify(&vmg);
}

/*
 * Expand vma by delta bytes, potentially merging with an immediately adjacent
 * VMA with identical properties.
 */
struct vm_area_struct *vma_merge_extend(struct vma_iterator *vmi,
					struct vm_area_struct *vma,
					unsigned long delta)
{
	VMG_VMA_STATE(vmg, vmi, vma, vma, vma->vm_end, vma->vm_end + delta);

	vmg.next = vma_iter_next_rewind(vmi, NULL);
	vmg.middle = NULL; /* We use the VMA to populate VMG fields only. */

	return vma_merge_new_range(&vmg);
}

void unlink_file_vma_batch_init(struct unlink_vma_file_batch *vb)
{
	vb->count = 0;
}

static void unlink_file_vma_batch_process(struct unlink_vma_file_batch *vb)
{
	struct address_space *mapping;
	int i;

	mapping = vb->vmas[0]->vm_file->f_mapping;
	i_mmap_lock_write(mapping);
	for (i = 0; i < vb->count; i++) {
		VM_WARN_ON_ONCE(vb->vmas[i]->vm_file->f_mapping != mapping);
		__remove_shared_vm_struct(vb->vmas[i], mapping);
	}
	i_mmap_unlock_write(mapping);

	unlink_file_vma_batch_init(vb);
}

void unlink_file_vma_batch_add(struct unlink_vma_file_batch *vb,
			       struct vm_area_struct *vma)
{
	if (vma->vm_file == NULL)
		return;

	if ((vb->count > 0 && vb->vmas[0]->vm_file != vma->vm_file) ||
	    vb->count == ARRAY_SIZE(vb->vmas))
		unlink_file_vma_batch_process(vb);

	vb->vmas[vb->count] = vma;
	vb->count++;
}

void unlink_file_vma_batch_final(struct unlink_vma_file_batch *vb)
{
	if (vb->count > 0)
		unlink_file_vma_batch_process(vb);
}

static void vma_link_file(struct vm_area_struct *vma, bool hold_rmap_lock)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping;

	if (file) {
		mapping = file->f_mapping;
		i_mmap_lock_write(mapping);
		__vma_link_file(vma, mapping);
		if (!hold_rmap_lock)
			i_mmap_unlock_write(mapping);
	}
}

#define VLINK_DONE		0
#define VLINK_STORE		1

struct rust_vlink_state {
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct vma_iterator vmi;
	bool prealloced;
};

static int vlink_classify(struct rust_vlink_state *s, int *out)
{
	*out = 0;
	s->prealloced = false;
	vma_iter_init(&s->vmi, s->mm, 0);
	vma_iter_config(&s->vmi, s->vma->vm_start, s->vma->vm_end);
	if (vma_iter_prealloc(&s->vmi, s->vma)) {
		*out = -ENOMEM;
		return VLINK_DONE;
	}
	s->prealloced = true;
	return VLINK_STORE;
}

static int vlink_store(struct rust_vlink_state *s)
{
	vma_start_write(s->vma);
	vma_iter_store_new(&s->vmi, s->vma);
	s->prealloced = false;
	vma_link_file(s->vma, /* hold_rmap_lock= */false);
	s->mm->map_count++;
	validate_mm(s->mm);
	return 0;
}

static void vlink_abort(struct rust_vlink_state *s)
{
	if (s->prealloced) {
		vma_iter_free(&s->vmi);
		s->prealloced = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_vlink_classify(struct rust_vlink_state *s, int *out)
{
	return vlink_classify(s, out);
}

int rust_vlink_store(struct rust_vlink_state *s)
{
	return vlink_store(s);
}

void rust_vlink_abort(struct rust_vlink_state *s)
{
	vlink_abort(s);
}
#endif

static int finish_vlink(struct rust_vlink_state *s)
{
	int out = 0;

	if (vlink_classify(s, &out) == VLINK_DONE)
		return out;
	return vlink_store(s);
}

static int vma_link(struct mm_struct *mm, struct vm_area_struct *vma)
{
	struct rust_vlink_state s = {
		.mm = mm,
		.vma = vma,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_vlink_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_vlink(&s);
}

/*
 * Copy the vma structure to a new location in the same mm,
 * prior to moving page table entries, to effect an mremap move.
 */
#define CVMA_DONE		0
#define CVMA_DUP		1

struct rust_cvma_state {
	struct vm_area_struct **vmap;
	unsigned long addr;
	unsigned long len;
	pgoff_t pgoff;
	pgoff_t anon_pgoff;
	bool *need_rmap_locks;
	struct vm_area_struct *vma;
	unsigned long old_vma_start;
	bool can_self_merge;
};

static int cvma_classify(struct rust_cvma_state *s,
			 struct vm_area_struct **ret)
{
	struct vm_area_struct *vma;
	struct vm_area_struct *new_vma;
	struct mm_struct *mm;
	struct vma_iterator vmi;
	struct vma_merge_struct vmg;

	*ret = NULL;
	s->vma = vma = *s->vmap;
	s->old_vma_start = vma->vm_start;
	s->can_self_merge = false;
	mm = vma->vm_mm;

	/*
	 * If a vma has not yet been faulted, update its anonymous pgoff to
	 * match the new location to increase its chance of merging.
	 */
	if (!vma->anon_vma) {
		s->anon_pgoff = s->addr >> PAGE_SHIFT;

		if (vma_is_anonymous(vma)) {
			s->pgoff = s->anon_pgoff;
			s->can_self_merge = true;
		}
	}

	vma_iter_init(&vmi, mm, s->addr);
	vmg = (struct vma_merge_struct) {
		.mm = vma->vm_mm,
		.vmi = &vmi,
		.prev = NULL,
		.middle = vma,
		.next = NULL,
		.start = s->addr,
		.end = s->addr + s->len,
		.vm_flags = vma->vm_flags,
		.pgoff = linear_page_index(vma, s->addr),
		.anon_pgoff = __linear_anon_page_index(vma, s->addr),
		.file = vma->vm_file,
		.anon_vma = vma->anon_vma,
		.policy = vma_policy(vma),
		.uffd_ctx = vma->vm_userfaultfd_ctx,
		.anon_name = anon_vma_name(vma),
		.state = VMA_MERGE_START,
	};

	/*
	 * If the VMA we are copying might contain a uprobe PTE, ensure
	 * that we do not establish one upon merge. Otherwise, when mremap()
	 * moves page tables, it will orphan the newly created PTE.
	 */
	if (vma->vm_file)
		vmg.skip_vma_uprobe = true;

	new_vma = find_vma_prev(mm, s->addr, &vmg.prev);
	if (new_vma && new_vma->vm_start < s->addr + s->len)
		return CVMA_DONE;	/* should never get here */

	vmg.pgoff = s->pgoff;
	vmg.anon_pgoff = s->anon_pgoff;
	vmg.next = vma_iter_next_rewind(&vmi, NULL);
	new_vma = vma_merge_copied_range(&vmg);

	if (new_vma) {
		/* Self-merged and VMA replaced. */
		if (unlikely(new_vma->vm_start < s->old_vma_start &&
			     new_vma->vm_end > s->old_vma_start)) {
			/*
			 * The only way a VMA can both self-merge and be
			 * replaced is if the remap places the new VMA
			 * immediately prior to its old self ('next') and
			 * immediately after another VMA ('prev') causing the
			 * next to be removed and prev to be expanded to cover
			 * the entire range.
			 *
			 * This should only be possible if the anonymous page
			 * offset was updated, i.e. the VMA is unfaulted.
			 */
			VM_WARN_ON_ONCE_VMA(!s->can_self_merge, new_vma);
			*s->vmap = s->vma = vma = new_vma;
		}
		*s->need_rmap_locks =
			(vma_start_pgoff(new_vma) <= vma_start_pgoff(vma));
		*ret = new_vma;
		return CVMA_DONE;
	}
	return CVMA_DUP;
}

static struct vm_area_struct *cvma_dup(struct rust_cvma_state *s)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma;

	new_vma = vm_area_dup(vma);
	if (!new_vma)
		goto out;
	vma_set_range(new_vma, s->addr, s->addr + s->len, s->pgoff,
		      s->anon_pgoff);
	if (vma_dup_policy(vma, new_vma))
		goto out_free_vma;
	if (anon_vma_clone(new_vma, vma, VMA_OP_REMAP))
		goto out_free_mempol;
	if (new_vma->vm_file)
		get_file(new_vma->vm_file);
	if (new_vma->vm_ops && new_vma->vm_ops->open)
		new_vma->vm_ops->open(new_vma);
	if (vma_link(mm, new_vma))
		goto out_vma_link;
	*s->need_rmap_locks = false;
	return new_vma;

out_vma_link:
	fixup_hugetlb_reservations(new_vma);
	vma_close(new_vma);

	if (new_vma->vm_file)
		fput(new_vma->vm_file);

	unlink_anon_vmas(new_vma);
out_free_mempol:
	mpol_put(vma_policy(new_vma));
out_free_vma:
	vm_area_free(new_vma);
out:
	return NULL;
}

#ifdef CONFIG_RUST_MMAP
int rust_cvma_classify(struct rust_cvma_state *s, struct vm_area_struct **ret)
{
	return cvma_classify(s, ret);
}

struct vm_area_struct *rust_cvma_dup(struct rust_cvma_state *s)
{
	return cvma_dup(s);
}
#endif

static struct vm_area_struct *finish_cvma(struct rust_cvma_state *s)
{
	struct vm_area_struct *ret = NULL;

	if (cvma_classify(s, &ret) == CVMA_DONE)
		return ret;
	return cvma_dup(s);
}

struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
	unsigned long addr, unsigned long len, pgoff_t pgoff,
	pgoff_t anon_pgoff, bool *need_rmap_locks)
{
	struct rust_cvma_state s = {
		.vmap = vmap,
		.addr = addr,
		.len = len,
		.pgoff = pgoff,
		.anon_pgoff = anon_pgoff,
		.need_rmap_locks = need_rmap_locks,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		struct vm_area_struct *rust_ret;

		rust_ret = rust_cvma_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_cvma(&s);
}

/*
 * Rough compatibility check to quickly see if it's even worth looking
 * at sharing an anon_vma.
 *
 * They need to have the same vm_file, and the flags can only differ
 * in things that mprotect may change.
 *
 * NOTE! The fact that we share an anon_vma doesn't _have_ to mean that
 * we can merge the two vma's. For example, we refuse to merge a vma if
 * there is a vm_ops->close() function, because that indicates that the
 * driver is doing some kind of reference counting. But that doesn't
 * really matter for the anon_vma sharing case.
 */
static int anon_vma_compatible(struct vm_area_struct *a, struct vm_area_struct *b)
{
	vma_flags_t diff = vma_flags_diff_pair(&a->flags, &b->flags);

	/* Ignore flags that mprotect() can change. */
	vma_flags_clear_mask(&diff, VMA_ACCESS_FLAGS);
	/* Ignore flags that do not impact merging. */
	vma_flags_clear_mask(&diff, VMA_IGNORE_MERGE_FLAGS);

	/* Must be adjacent. */
	if (a->vm_end != b->vm_start)
		return false;
	/* Must have matching policy. */
	if (!mpol_equal(vma_policy(a), vma_policy(b)))
		return false;
	/* Must both be anon or map the same file (MAP_PRIVATE case). */
	if (a->vm_file != b->vm_file)
		return false;
	/* Flags must be equivalent modulo mprotect(). */
	if (!vma_flags_empty(&diff))
		return false;
	/* Page offset must align. */
	if (vma_end_pgoff(a) != vma_start_pgoff(b))
		return false;
	/* Only reached from anon path, so either MAP_PRIVATE file or anon. */
	if (vma_end_anon_pgoff(a) != vma_start_anon_pgoff(b))
		return false;
	return true;
}

/*
 * Do some basic sanity checking to see if we can re-use the anon_vma
 * from 'old'. The 'a'/'b' vma's are in VM order - one of them will be
 * the same as 'old', the other will be the new one that is trying
 * to share the anon_vma.
 *
 * NOTE! This runs with mmap_lock held for reading, so it is possible that
 * the anon_vma of 'old' is concurrently in the process of being set up
 * by another page fault trying to merge _that_. But that's ok: if it
 * is being set up, that automatically means that it will be a singleton
 * acceptable for merging, so we can do all of this optimistically. But
 * we do that READ_ONCE() to make sure that we never re-load the pointer.
 *
 * IOW: that the "list_is_singular()" test on the anon_vma_chain only
 * matters for the 'stable anon_vma' case (ie the thing we want to avoid
 * is to return an anon_vma that is "complex" due to having gone through
 * a fork).
 *
 * We also make sure that the two vma's are compatible (adjacent,
 * and with the same memory policies). That's all stable, even with just
 * a read lock on the mmap_lock.
 */
static struct anon_vma *reusable_anon_vma(struct vm_area_struct *old,
					  struct vm_area_struct *a,
					  struct vm_area_struct *b)
{
	if (anon_vma_compatible(a, b)) {
		struct anon_vma *anon_vma = READ_ONCE(old->anon_vma);

		if (anon_vma && list_is_singular(&old->anon_vma_chain))
			return anon_vma;
	}
	return NULL;
}

/*
 * find_mergeable_anon_vma is used by anon_vma_prepare, to check
 * neighbouring vmas for a suitable anon_vma, before it goes off
 * to allocate a new anon_vma.  It checks because a repetitive
 * sequence of mprotects and faults may otherwise lead to distinct
 * anon_vmas being allocated, preventing vma merge in subsequent
 * mprotect.
 */
struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = NULL;
	struct vm_area_struct *prev, *next;
	VMA_ITERATOR(vmi, vma->vm_mm, vma->vm_end);

	/* Try next first. */
	next = vma_iter_load(&vmi);
	if (next) {
		anon_vma = reusable_anon_vma(next, vma, next);
		if (anon_vma)
			return anon_vma;
	}

	prev = vma_prev(&vmi);
	VM_BUG_ON_VMA(prev != vma, vma);
	prev = vma_prev(&vmi);
	/* Try prev next. */
	if (prev)
		anon_vma = reusable_anon_vma(prev, prev, vma);

	/*
	 * We might reach here with anon_vma == NULL if we can't find
	 * any reusable anon_vma.
	 * There's no absolute need to look only at touching neighbours:
	 * we could search further afield for "compatible" anon_vmas.
	 * But it would probably just be a waste of time searching,
	 * or lead to too many vmas hanging off the same anon_vma.
	 * We're trying to allow mprotect remerging later on,
	 * not trying to minimize memory used for anon_vmas.
	 */
	return anon_vma;
}

static bool vm_ops_needs_writenotify(const struct vm_operations_struct *vm_ops)
{
	return vm_ops && (vm_ops->page_mkwrite || vm_ops->pfn_mkwrite);
}

static bool vma_is_shared_writable(struct vm_area_struct *vma)
{
	return vma_test_all(vma, VMA_WRITE_BIT, VMA_SHARED_BIT);
}

static bool vma_fs_can_writeback(struct vm_area_struct *vma)
{
	/* No managed pages to writeback. */
	if (vma_test(vma, VMA_PFNMAP_BIT))
		return false;

	return vma->vm_file && vma->vm_file->f_mapping &&
		mapping_can_writeback(vma->vm_file->f_mapping);
}

/*
 * Does this VMA require the underlying folios to have their dirty state
 * tracked?
 */
bool vma_needs_dirty_tracking(struct vm_area_struct *vma)
{
	/* Only shared, writable VMAs require dirty tracking. */
	if (!vma_is_shared_writable(vma))
		return false;

	/* Does the filesystem need to be notified? */
	if (vm_ops_needs_writenotify(vma->vm_ops))
		return true;

	/*
	 * Even if the filesystem doesn't indicate a need for writenotify, if it
	 * can writeback, dirty tracking is still required.
	 */
	return vma_fs_can_writeback(vma);
}

/*
 * Some shared mappings will want the pages marked read-only
 * to track write events. If so, we'll downgrade vm_page_prot
 * to the private version (using protection_map[] without the
 * VM_SHARED bit).
 */
bool vma_wants_writenotify(struct vm_area_struct *vma, pgprot_t vm_page_prot)
{
	/* If it was private or non-writable, the write bit is already clear */
	if (!vma_is_shared_writable(vma))
		return false;

	/* The backer wishes to know when pages are first written to? */
	if (vm_ops_needs_writenotify(vma->vm_ops))
		return true;

	/* The open routine did something to the protections that pgprot_modify
	 * won't preserve? */
	if (pgprot_val(vm_page_prot) !=
	    pgprot_val(vma_pgprot_modify(vm_page_prot, vma->flags)))
		return false;

	/*
	 * Do we need to track softdirty? hugetlb does not support softdirty
	 * tracking yet.
	 */
	if (vma_soft_dirty_enabled(vma) && !is_vm_hugetlb_page(vma))
		return true;

	/* Do we need write faults for uffd-wp tracking? */
	if (userfaultfd_wp(vma))
		return true;

	/* Can the mapping track the dirty pages? */
	return vma_fs_can_writeback(vma);
}

static DEFINE_MUTEX(mm_all_locks_mutex);

static void vm_lock_anon_vma(struct mm_struct *mm, struct anon_vma *anon_vma)
{
	if (!test_bit(0, (unsigned long *) &anon_vma->root->rb_root.rb_root.rb_node)) {
		/*
		 * The LSB of head.next can't change from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		down_write_nest_lock(&anon_vma->root->rwsem, &mm->mmap_lock);
		/*
		 * We can safely modify head.next after taking the
		 * anon_vma->root->rwsem. If some other vma in this mm shares
		 * the same anon_vma we won't take it again.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us thanks to the
		 * anon_vma->root->rwsem.
		 */
		if (__test_and_set_bit(0, (unsigned long *)
				       &anon_vma->root->rb_root.rb_root.rb_node))
			BUG();
	}
}

static void vm_lock_mapping(struct mm_struct *mm, struct address_space *mapping)
{
	if (!test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change from under us because
		 * we hold the mm_all_locks_mutex.
		 *
		 * Operations on ->flags have to be atomic because
		 * even if AS_MM_ALL_LOCKS is stable thanks to the
		 * mm_all_locks_mutex, there may be other cpus
		 * changing other bitflags in parallel to us.
		 */
		if (test_and_set_bit(AS_MM_ALL_LOCKS, &mapping->flags))
			BUG();
		down_write_nest_lock(&mapping->i_mmap_rwsem, &mm->mmap_lock);
	}
}

/*
 * This operation locks against the VM for all pte/vma/mm related
 * operations that could ever happen on a certain mm. This includes
 * vmtruncate, try_to_unmap, and all page faults.
 *
 * The caller must take the mmap_lock in write mode before calling
 * mm_take_all_locks(). The caller isn't allowed to release the
 * mmap_lock until mm_drop_all_locks() returns.
 *
 * mmap_lock in write mode is required in order to block all operations
 * that could modify pagetables and free pages without need of
 * altering the vma layout. It's also needed in write mode to avoid new
 * anon_vmas to be associated with existing vmas.
 *
 * A single task can't take more than one mm_take_all_locks() in a row
 * or it would deadlock.
 *
 * The LSB in anon_vma->rb_root.rb_node and the AS_MM_ALL_LOCKS bitflag in
 * mapping->flags avoid to take the same lock twice, if more than one
 * vma in this mm is backed by the same anon_vma or address_space.
 *
 * We take locks in following order, accordingly to comment at beginning
 * of mm/rmap.c:
 *   - all hugetlbfs_i_mmap_rwsem_key locks (aka mapping->i_mmap_rwsem for
 *     hugetlb mapping);
 *   - all vmas marked locked
 *   - all i_mmap_rwsem locks;
 *   - all anon_vma->rwseml
 *
 * We can take all locks within these types randomly because the VM code
 * doesn't nest them and we protected from parallel mm_take_all_locks() by
 * mm_all_locks_mutex.
 *
 * mm_take_all_locks() and mm_drop_all_locks are expensive operations
 * that may have to take thousand of locks.
 *
 * mm_take_all_locks() can fail if it's interrupted by signals.
 */
int mm_take_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct anon_vma_chain *avc;
	VMA_ITERATOR(vmi, mm, 0);

	mmap_assert_write_locked(mm);

	mutex_lock(&mm_all_locks_mutex);

	/*
	 * vma_start_write() does not have a complement in mm_drop_all_locks()
	 * because vma_start_write() is always asymmetrical; it marks a VMA as
	 * being written to until mmap_write_unlock() or mmap_write_downgrade()
	 * is reached.
	 */
	for_each_vma(vmi, vma) {
		if (signal_pending(current))
			goto out_unlock;
		vma_start_write(vma);
	}

	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->vm_file && vma->vm_file->f_mapping &&
				is_vm_hugetlb_page(vma))
			vm_lock_mapping(mm, vma->vm_file->f_mapping);
	}

	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->vm_file && vma->vm_file->f_mapping &&
				!is_vm_hugetlb_page(vma))
			vm_lock_mapping(mm, vma->vm_file->f_mapping);
	}

	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->anon_vma)
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				vm_lock_anon_vma(mm, avc->anon_vma);
	}

	return 0;

out_unlock:
	mm_drop_all_locks(mm);
	return -EINTR;
}

static void vm_unlock_anon_vma(struct anon_vma *anon_vma)
{
	if (test_bit(0, (unsigned long *) &anon_vma->root->rb_root.rb_root.rb_node)) {
		/*
		 * The LSB of head.next can't change to 0 from under
		 * us because we hold the mm_all_locks_mutex.
		 *
		 * We must however clear the bitflag before unlocking
		 * the vma so the users using the anon_vma->rb_root will
		 * never see our bitflag.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us until we release the
		 * anon_vma->root->rwsem.
		 */
		if (!__test_and_clear_bit(0, (unsigned long *)
					  &anon_vma->root->rb_root.rb_root.rb_node))
			BUG();
		anon_vma_unlock_write(anon_vma);
	}
}

static void vm_unlock_mapping(struct address_space *mapping)
{
	if (test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change to 0 from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		i_mmap_unlock_write(mapping);
		if (!test_and_clear_bit(AS_MM_ALL_LOCKS,
					&mapping->flags))
			BUG();
	}
}

/*
 * The mmap_lock cannot be released by the caller until
 * mm_drop_all_locks() returns.
 */
void mm_drop_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct anon_vma_chain *avc;
	VMA_ITERATOR(vmi, mm, 0);

	mmap_assert_write_locked(mm);
	BUG_ON(!mutex_is_locked(&mm_all_locks_mutex));

	for_each_vma(vmi, vma) {
		if (vma->anon_vma)
			list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
				vm_unlock_anon_vma(avc->anon_vma);
		if (vma->vm_file && vma->vm_file->f_mapping)
			vm_unlock_mapping(vma->vm_file->f_mapping);
	}

	mutex_unlock(&mm_all_locks_mutex);
}

/*
 * We account for memory if it's a private writeable mapping,
 * not hugepages and VM_NORESERVE wasn't set.
 */
static bool accountable_mapping(struct mmap_state *map)
{
	const struct file *file = map->file;

	/*
	 * hugetlb has its own accounting separate from the core VM
	 * VM_HUGETLB may not be set yet so we cannot check for that flag.
	 */
	if (file && is_file_hugepages(file))
		return false;

	return vma_flags_test(&map->vma_flags, VMA_WRITE_BIT) &&
		!vma_flags_test_any(&map->vma_flags, VMA_NORESERVE_BIT,
				    VMA_SHARED_BIT);
}

/*
 * vms_abort_munmap_vmas() - Undo as much as possible from an aborted munmap()
 * operation.
 * @vms: The vma unmap structure
 * @mas_detach: The maple state with the detached maple tree
 *
 * Reattach any detached vmas, free up the maple tree used to track the vmas.
 * If that's not possible because the ptes are cleared (and vm_ops->closed() may
 * have been called), then a NULL is written over the vmas and the vmas are
 * removed (munmap() completed).
 */
static void vms_abort_munmap_vmas(struct vma_munmap_struct *vms,
		struct ma_state *mas_detach)
{
	struct ma_state *mas = &vms->vmi->mas;

	if (!vms->nr_pages)
		return;

	if (vms->clear_ptes)
		return reattach_vmas(mas_detach);

	/*
	 * Aborting cannot just call the vm_ops open() because they are often
	 * not symmetrical and state data has been lost.  Resort to the old
	 * failure method of leaving a gap where the MAP_FIXED mapping failed.
	 */
	mas_set_range(mas, vms->start, vms->end - 1);
	mas_store_gfp(mas, NULL, GFP_KERNEL|__GFP_NOFAIL);
	/* Clean up the insertion of the unfortunate gap */
	vms_complete_munmap_vmas(vms, mas_detach);
}

static void update_ksm_flags(struct mmap_state *map)
{
	map->vma_flags = ksm_vma_flags(map->mm, map->file, map->vma_flags);
}

static void set_desc_from_map(struct vm_area_desc *desc,
		const struct mmap_state *map)
{
	desc->start = map->addr;
	desc->end = map->end;

	desc->pgoff = map->pgoff;
	desc->vm_file = map->file;
	desc->vma_flags = map->vma_flags;
	desc->page_prot = map->page_prot;
}

/*
 * __mmap_setup() - Prepare to gather any overlapping VMAs that need to be
 * unmapped once the map operation is completed, check limits, account mapping
 * and clean up any pre-existing VMAs.
 *
 * As a result it sets up the @map and @desc objects.
 *
 * @map: Mapping state.
 * @desc: VMA descriptor
 * @uf:  Userfaultfd context list.
 *
 * Returns: 0 on success, error code otherwise.
 */
static int __mmap_setup(struct mmap_state *map, struct vm_area_desc *desc,
			struct list_head *uf)
{
	int error;
	struct vma_iterator *vmi = map->vmi;
	struct vma_munmap_struct *vms = &map->vms;

	/* Find the first overlapping VMA and initialise unmap state. */
	vms->vma = vma_find(vmi, map->end);
	init_vma_munmap(vms, vmi, vms->vma, map->addr, map->end, uf,
			/* unlock = */ false);

	/* OK, we have overlapping VMAs - prepare to unmap them. */
	if (vms->vma) {
		mt_init_flags(&map->mt_detach,
			      vmi->mas.tree->ma_flags & MT_FLAGS_LOCK_MASK);
		mt_on_stack(map->mt_detach);
		mas_init(&map->mas_detach, &map->mt_detach, /* addr = */ 0);
		/* Prepare to unmap any existing mapping in the area */
		error = vms_gather_munmap_vmas(vms, &map->mas_detach);
		if (error) {
			/* On error VMAs will already have been reattached. */
			vms->nr_pages = 0;
			return error;
		}

		map->next = vms->next;
		map->prev = vms->prev;
	} else {
		map->next = vma_iter_next_rewind(vmi, &map->prev);
	}

	/* Check against address space limit. */
	if (!may_expand_vm(map->mm, &map->vma_flags, map->pglen - vms->nr_pages))
		return -ENOMEM;

	/* Private writable mapping: check memory availability. */
	if (accountable_mapping(map)) {
		map->charged = map->pglen;
		map->charged -= vms->nr_accounted;
		if (map->charged) {
			error = security_vm_enough_memory_mm(map->mm, map->charged);
			if (error)
				return error;
		}

		vms->nr_accounted = 0;
		vma_flags_set(&map->vma_flags, VMA_ACCOUNT_BIT);
	}

	/*
	 * Clear PTEs while the vma is still in the tree so that rmap
	 * cannot race with the freeing later in the truncate scenario.
	 * This is also needed for mmap_file(), which is why vm_ops
	 * close function is called.
	 */
	vms_clean_up_area(vms, &map->mas_detach);

	set_desc_from_map(desc, map);
	return 0;
}


static int __mmap_new_file_vma(struct mmap_state *map,
			       struct vm_area_struct *vma)
{
	struct vma_iterator *vmi = map->vmi;
	int error;

	vma->vm_file = map->file;
	if (!map->file_doesnt_need_get)
		get_file(map->file);

	if (!map->file->f_op->mmap)
		return 0;

	error = mmap_file(vma->vm_file, vma);
	if (error) {
		UNMAP_STATE(unmap, vmi, vma, vma->vm_start, vma->vm_end,
			    map->prev, map->next);
		fput(vma->vm_file);
		vma->vm_file = NULL;

		vma_iter_set(vmi, vma->vm_end);
		/* Undo any partial mapping done by a device driver. */
		unmap_region(&unmap);
		return error;
	}

	/* Drivers cannot alter the address of the VMA. */
	WARN_ON_ONCE(map->addr != vma->vm_start);
	/*
	 * Drivers should not permit writability when previously it was
	 * disallowed.
	 */
	VM_WARN_ON_ONCE(!vma_flags_same_pair(&map->vma_flags, &vma->flags) &&
			!vma_flags_test(&map->vma_flags, VMA_MAYWRITE_BIT) &&
			vma_test(vma, VMA_MAYWRITE_BIT));

	map->file = vma->vm_file;
	map->vma_flags = vma->flags;

	return 0;
}

/*
 * __mmap_new_vma() - Allocate a new VMA for the region, as merging was not
 * possible.
 *
 * @map:  Mapping state.
 * @vmap: Output pointer for the new VMA.
 * @action: Any mmap_prepare action that is still to complete.
 *
 * Returns: Zero on success, or an error.
 */
#define MNVA_DONE		0
#define MNVA_FILE		1
#define MNVA_SHMEM		2
#define MNVA_STORE		3

struct rust_mnva_state {
	struct mmap_state *map;
	struct mmap_action *action;
	struct vm_area_struct **vmap;
	struct vm_area_struct *vma;
};

static int mnva_classify(struct rust_mnva_state *s, int *out)
{
	struct mmap_state *map = s->map;
	struct vma_iterator *vmi = map->vmi;
	const bool is_anon = !map->file &&
		!vma_flags_test(&map->vma_flags, VMA_SHARED_BIT);

	*out = 0;
	s->vma = NULL;

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	s->vma = vm_area_alloc(map->mm);
	if (!s->vma) {
		*out = -ENOMEM;
		return MNVA_DONE;
	}

	vma_iter_config(vmi, map->addr, map->end);

	if (is_anon)
		vma_set_anonymous(s->vma);

	vma_set_range(s->vma, map->addr, map->end, map->pgoff, map->anon_pgoff);
	s->vma->flags = map->vma_flags;
	s->vma->vm_page_prot = map->page_prot;

	if (vma_iter_prealloc(vmi, s->vma)) {
		vm_area_free(s->vma);
		s->vma = NULL;
		*out = -ENOMEM;
		return MNVA_DONE;
	}

	if (map->file)
		return MNVA_FILE;
	if (!is_anon)
		return MNVA_SHMEM;
	return MNVA_STORE;
}

static int mnva_file(struct rust_mnva_state *s)
{
	return __mmap_new_file_vma(s->map, s->vma);
}

static int mnva_shmem(struct rust_mnva_state *s)
{
	return shmem_zero_setup(s->vma);
}

static int mnva_store(struct rust_mnva_state *s)
{
	struct mmap_state *map = s->map;
	struct vm_area_struct *vma = s->vma;

	if (!map->check_ksm_early) {
		update_ksm_flags(map);
		vma->flags = map->vma_flags;
	}

#ifdef CONFIG_SPARC64
	/* TODO: Fix SPARC ADI! */
	WARN_ON_ONCE(!arch_validate_flags(map->vm_flags));
#endif

	/* Lock the VMA since it is modified after insertion into VMA tree */
	vma_start_write(vma);
	vma_iter_store_new(map->vmi, vma);
	map->mm->map_count++;
	vma_link_file(vma, s->action->hide_from_rmap_until_complete);

	/*
	 * vma_merge_new_range() calls khugepaged_enter_vma() too, the below
	 * call covers the non-merge case.
	 */
	if (!vma_is_anonymous(vma))
		khugepaged_enter_vma(vma, map->vm_flags);
	*s->vmap = vma;
	return 0;
}

static void mnva_abort(struct rust_mnva_state *s)
{
	vma_iter_free(s->map->vmi);
	vm_area_free(s->vma);
	s->vma = NULL;
}

#ifdef CONFIG_RUST_MMAP
int rust_mnva_classify(struct rust_mnva_state *s, int *out)
{
	return mnva_classify(s, out);
}

int rust_mnva_file(struct rust_mnva_state *s)
{
	return mnva_file(s);
}

int rust_mnva_shmem(struct rust_mnva_state *s)
{
	return mnva_shmem(s);
}

int rust_mnva_store(struct rust_mnva_state *s)
{
	return mnva_store(s);
}

void rust_mnva_abort(struct rust_mnva_state *s)
{
	mnva_abort(s);
}
#endif

static int finish_mnva(struct rust_mnva_state *s)
{
	int out = 0;
	int kind;
	int error;

	kind = mnva_classify(s, &out);
	if (kind == MNVA_DONE)
		return out;
	if (kind == MNVA_FILE)
		error = mnva_file(s);
	else if (kind == MNVA_SHMEM)
		error = mnva_shmem(s);
	else
		error = 0;
	if (error) {
		mnva_abort(s);
		return error;
	}
	return mnva_store(s);
}

static int __mmap_new_vma(struct mmap_state *map, struct vm_area_struct **vmap,
	struct mmap_action *action)
{
	struct rust_mnva_state s = {
		.map = map,
		.action = action,
		.vmap = vmap,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_mnva_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mnva(&s);
}

/*
 * __mmap_complete() - Unmap any VMAs we overlap, account memory mapping
 *                     statistics, handle locking and finalise the VMA.
 *
 * @map: Mapping state.
 * @vma: Merged or newly allocated VMA for the mmap()'d region.
 */
static void __mmap_complete(struct mmap_state *map, struct vm_area_struct *vma)
{
	struct mm_struct *mm = map->mm;

	perf_event_mmap(vma);

	/* Unmap any existing mapping in the area. */
	vms_complete_munmap_vmas(&map->vms, &map->mas_detach);

	vm_stat_account(mm, vma->vm_flags, map->pglen);
	if (vma_test(vma, VMA_LOCKED_BIT)) {
		if (!vma_supports_mlock(vma))
			vma_clear_flags_mask(vma, VMA_LOCKED_MASK);
		else
			mm->locked_vm += map->pglen;
	}

	if (vma->vm_file)
		uprobe_mmap(vma);

	/*
	 * New (or expanded) vma always get soft dirty status.
	 * Otherwise user-space soft-dirty page tracker won't
	 * be able to distinguish situation when vma area unmapped,
	 * then new mapped in-place (which must be aimed as
	 * a completely new data area).
	 */
	if (pgtable_supports_soft_dirty())
		vma_set_flags(vma, VMA_SOFTDIRTY_BIT);

	vma_set_page_prot(vma);
}

static int call_action_prepare(struct mmap_state *map,
			       struct vm_area_desc *desc)
{
	int err;

	err = mmap_action_prepare(desc);
	if (err)
		return err;

	return 0;
}

/*
 * Invoke the f_op->mmap_prepare() callback for a file-backed mapping that
 * specifies it.
 *
 * This is called prior to any merge attempt, and updates whitelisted fields
 * that are permitted to be updated by the caller.
 *
 * All but user-defined fields will be pre-populated with original values.
 *
 * Returns 0 on success, or an error code otherwise.
 */
static int call_mmap_prepare(struct mmap_state *map,
		struct vm_area_desc *desc)
{
	int err;

	/* Invoke the hook. */
	err = vfs_mmap_prepare(map->file, desc);
	if (err)
		return err;

	err = call_action_prepare(map, desc);
	if (err)
		return err;

	/* Update fields permitted to be changed. */
	map->pgoff = desc->pgoff;
	if (desc->vm_file != map->file) {
		map->file_doesnt_need_get = true;
		map->file = desc->vm_file;
	}
	map->vma_flags = desc->vma_flags;
	map->page_prot = desc->page_prot;
	/* User-defined fields. */
	map->vm_ops = desc->vm_ops;
	map->vm_private_data = desc->private_data;

	return 0;
}

static void set_vma_user_defined_fields(struct vm_area_struct *vma,
		struct mmap_state *map)
{
	if (map->vm_ops)
		vma->vm_ops = map->vm_ops;
	else	/* Only /dev/zero should do this. */
		vma_set_anonymous(vma);
	vma->vm_private_data = map->vm_private_data;
}

/*
 * Are we guaranteed no driver can change state such as to preclude KSM merging?
 * If so, let's set the KSM mergeable flag early so we don't break VMA merging.
 */
static bool can_set_ksm_flags_early(struct mmap_state *map)
{
	struct file *file = map->file;

	/* Anonymous mappings have no driver which can change them. */
	if (!file)
		return true;

	/*
	 * If .mmap_prepare() is specified, then the driver will have already
	 * manipulated state prior to updating KSM flags. So no need to worry
	 * about mmap callbacks modifying VMA flags after the KSM flag has been
	 * updated here, which could otherwise affect KSM eligibility.
	 */
	if (file->f_op->mmap_prepare)
		return true;

	/* shmem is safe. */
	if (shmem_file(file))
		return true;

	/* Any other .mmap callback is not safe. */
	return false;
}

#define MMAPREG_DONE		0
#define MMAPREG_INSTALL		1
#define MMAPREG_CONT		2
#define MMAPREG_NEW		3
#define MMAPREG_COMPLETE	4

static int mmapreg_setup(struct mmap_state *map, struct vm_area_desc *desc,
			 struct list_head *uf, int have_mmap_prepare,
			 unsigned long *out)
{
	int error;

	*out = 0;
	error = __mmap_setup(map, desc, uf);
	if (!error && have_mmap_prepare)
		error = call_mmap_prepare(map, desc);
	if (error) {
		*out = error;
		return MMAPREG_DONE;
	}
	if (map->check_ksm_early)
		update_ksm_flags(map);
	return MMAPREG_CONT;
}

static int mmapreg_merge(struct mmap_state *map, struct vm_area_struct **vma)
{
	*vma = NULL;
	if (map->prev || map->next) {
		VMG_MMAP_STATE(vmg, map, /* vma = */ NULL);

		*vma = vma_merge_new_range(&vmg);
	}
	if (*vma)
		return MMAPREG_COMPLETE;
	return MMAPREG_NEW;
}

static int mmapreg_new(struct mmap_state *map, struct vm_area_desc *desc,
		       struct vm_area_struct **vma, unsigned long *out)
{
	int error;

	*out = 0;
	error = __mmap_new_vma(map, vma, &desc->action);
	if (error) {
		*out = error;
		return MMAPREG_DONE;
	}
	return MMAPREG_COMPLETE;
}

static unsigned long mmapreg_complete(struct mmap_state *map,
				      struct vm_area_struct *vma,
				      struct vm_area_desc *desc,
				      int have_mmap_prepare, int allocated_new)
{
	int error;

	if (have_mmap_prepare)
		set_vma_user_defined_fields(vma, map);

	__mmap_complete(map, vma);

	if (have_mmap_prepare && allocated_new) {
		error = mmap_action_complete(vma, &desc->action,
					     /*is_compat=*/false);
		if (error)
			return error;
	}
	return map->addr;
}

static void mmapreg_abort(struct mmap_state *map)
{
	/*
	 * This indicates that .mmap_prepare has set a new file, differing from
	 * desc->vm_file. But since we're aborting the operation, only the
	 * original file will be cleaned up. Ensure we clean up both.
	 */
	if (map->file_doesnt_need_get)
		fput(map->file);
	vms_abort_munmap_vmas(&map->vms, &map->mas_detach);
}

static void mmapreg_unacct_abort(struct mmap_state *map)
{
	if (map->charged)
		vm_unacct_memory(map->charged);
	mmapreg_abort(map);
}

static unsigned long finish_mmap_install(struct mmap_state *map,
					 struct vm_area_desc *desc,
					 struct list_head *uf,
					 int have_mmap_prepare)
{
	unsigned long out = 0;
	struct vm_area_struct *vma = NULL;
	int kind;
	int allocated = 0;

	kind = mmapreg_setup(map, desc, uf, have_mmap_prepare, &out);
	if (kind == MMAPREG_DONE) {
		mmapreg_abort(map);
		return out;
	}
	kind = mmapreg_merge(map, &vma);
	if (kind == MMAPREG_NEW) {
		kind = mmapreg_new(map, desc, &vma, &out);
		if (kind == MMAPREG_DONE) {
			mmapreg_unacct_abort(map);
			return out;
		}
		allocated = 1;
	}
	return mmapreg_complete(map, vma, desc, have_mmap_prepare, allocated);
}

#ifdef CONFIG_RUST_MMAP
int rust_mmapreg_setup(struct mmap_state *map, struct vm_area_desc *desc,
		       struct list_head *uf, int have_mmap_prepare,
		       unsigned long *out)
{
	return mmapreg_setup(map, desc, uf, have_mmap_prepare, out);
}

int rust_mmapreg_merge(struct mmap_state *map, struct vm_area_struct **vma)
{
	return mmapreg_merge(map, vma);
}

int rust_mmapreg_new(struct mmap_state *map, struct vm_area_desc *desc,
		     struct vm_area_struct **vma, unsigned long *out)
{
	return mmapreg_new(map, desc, vma, out);
}

unsigned long rust_mmapreg_complete(struct mmap_state *map,
				    struct vm_area_struct *vma,
				    struct vm_area_desc *desc,
				    int have_mmap_prepare, int allocated_new)
{
	return mmapreg_complete(map, vma, desc, have_mmap_prepare,
				allocated_new);
}

void rust_mmapreg_abort(struct mmap_state *map)
{
	mmapreg_abort(map);
}

void rust_mmapreg_unacct_abort(struct mmap_state *map)
{
	mmapreg_unacct_abort(map);
}
#endif

static unsigned long __mmap_region(struct file *file, unsigned long addr,
		unsigned long len, vma_flags_t vma_flags,
		unsigned long pgoff, struct list_head *uf)
{
	struct mm_struct *mm = current->mm;
	int have_mmap_prepare;
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	unsigned long rust_ret;
#endif
	VMA_ITERATOR(vmi, mm, addr);
	const pgoff_t anon_pgoff = addr >> PAGE_SHIFT;
	MMAP_STATE(map, mm, &vmi, addr, len, pgoff, anon_pgoff, vma_flags, file);
	struct vm_area_desc desc = {
		.mm = mm,
		.file = file,
		.action = {
			.type = MMAP_NOTHING, /* Default to no further action. */
		},
		.vm_ops = &vma_dummy_vm_ops,
	};

	have_mmap_prepare = file && file->f_op->mmap_prepare ? 1 : 0;
	map.check_ksm_early = can_set_ksm_flags_early(&map);

#ifdef CONFIG_RUST_MMAP
	rust_ret = rust_mmapreg_inner_dispatch(&map, &desc, uf,
					       have_mmap_prepare, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mmap_install(&map, &desc, uf, have_mmap_prepare);
}

/**
 * mmap_region() - Actually perform the userland mapping of a VMA into
 * current->mm with known, aligned and overflow-checked @addr and @len, and
 * correctly determined VMA flags @vm_flags and page offset @pgoff.
 *
 * This is an internal memory management function, and should not be used
 * directly.
 *
 * The caller must write-lock current->mm->mmap_lock.
 *
 * @file: If a file-backed mapping, a pointer to the struct file describing the
 * file to be mapped, otherwise NULL.
 * @addr: The page-aligned address at which to perform the mapping.
 * @len: The page-aligned, non-zero, length of the mapping.
 * @vma_flags: The VMA flags which should be applied to the mapping.
 * @pgoff: If @file is specified, the page offset into the file, if not then
 * the virtual page offset in memory of the anonymous mapping.
 * @uf: Optionally, a pointer to a list head used for tracking userfaultfd unmap
 * events.
 *
 * Returns: Either an error, or the address at which the requested mapping has
 * been performed.
 */
static int mmap_region_check(struct file *file, vma_flags_t *vma_flags,
			     int *writable, unsigned long *out)
{
	int error;

	*out = 0;
	*writable = 0;
	mmap_assert_write_locked(current->mm);

	/* Check to see if MDWE is applicable. */
	if (map_deny_write_exec(vma_flags, vma_flags)) {
		*out = -EACCES;
		return MMAPREG_DONE;
	}

	/* Allow architectures to sanity-check the vm_flags. */
	if (!arch_validate_flags(vma_flags_to_legacy(*vma_flags))) {
		*out = -EINVAL;
		return MMAPREG_DONE;
	}

	/* Map writable and ensure this isn't a sealed memfd. */
	if (file && is_shared_maywrite(vma_flags)) {
		error = mapping_map_writable(file->f_mapping);
		if (error) {
			*out = error;
			return MMAPREG_DONE;
		}
		*writable = 1;
	}
	return MMAPREG_INSTALL;
}

static unsigned long mmap_region_exit(struct file *file, int writable,
				      unsigned long ret)
{
	/* Clear our write mapping regardless of error. */
	if (writable)
		mapping_unmap_writable(file->f_mapping);

	validate_mm(current->mm);
	return ret;
}

static unsigned long finish_mmap_region(struct file *file, unsigned long addr,
					unsigned long len, vma_flags_t vma_flags,
					unsigned long pgoff, struct list_head *uf)
{
	unsigned long out = 0;
	int writable = 0;
	int kind;

	kind = mmap_region_check(file, &vma_flags, &writable, &out);
	if (kind == MMAPREG_DONE)
		return out;
	out = __mmap_region(file, addr, len, vma_flags, pgoff, uf);
	return mmap_region_exit(file, writable, out);
}

#ifdef CONFIG_RUST_MMAP
int rust_mmapreg_check(struct file *file, vma_flags_t *vma_flags, int *writable,
		       unsigned long *out)
{
	return mmap_region_check(file, vma_flags, writable, out);
}

unsigned long rust_mmapreg_install(struct file *file, unsigned long addr,
				   unsigned long len, vma_flags_t *vma_flags,
				   unsigned long pgoff, struct list_head *uf)
{
	return __mmap_region(file, addr, len, *vma_flags, pgoff, uf);
}

unsigned long rust_mmapreg_exit(struct file *file, int writable,
				unsigned long ret)
{
	return mmap_region_exit(file, writable, ret);
}
#endif

unsigned long mmap_region(struct file *file, unsigned long addr,
			  unsigned long len, vma_flags_t vma_flags,
			  unsigned long pgoff, struct list_head *uf)
{
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	unsigned long rust_ret;

	rust_ret = rust_mmap_region_dispatch(file, addr, len, &vma_flags, pgoff,
					     uf, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mmap_region(file, addr, len, vma_flags, pgoff, uf);
}

/**
 * do_brk_flags() - Increase the brk vma if the flags match.
 * @vmi: The vma iterator
 * @addr: The start address
 * @len: The length of the increase
 * @vma: The vma,
 * @vma_flags: The VMA Flags
 *
 * Extend the brk VMA from addr to addr + len.  If the VMA is NULL or the flags
 * do not match then create a new anonymous VMA.  Eventually we may be able to
 * do some brk-specific accounting here.
 *
 * Returns: %0 on success, or otherwise an error.
 */
#define BRK_DONE	0
#define BRK_CONT	1
#define BRK_NEW		2
#define BRK_ACCT	3

static int brk_prepare(vma_flags_t *vma_flags, unsigned long len, int *out)
{
	struct mm_struct *mm = current->mm;

	*out = 0;

	/*
	 * Check against address space limits by the changed size
	 * Note: This happens *after* clearing old mappings in some code paths.
	 */
	vma_flags_set_mask(vma_flags, VMA_DATA_DEFAULT_FLAGS);
	vma_flags_set(vma_flags, VMA_ACCOUNT_BIT);
	vma_flags_set_mask(vma_flags, mm->def_vma_flags);

	*vma_flags = ksm_vma_flags(mm, NULL, *vma_flags);
	if (!may_expand_vm(mm, vma_flags, len >> PAGE_SHIFT)) {
		*out = -ENOMEM;
		return BRK_DONE;
	}

	if (mm->map_count > get_sysctl_max_map_count()) {
		*out = -ENOMEM;
		return BRK_DONE;
	}

	if (security_vm_enough_memory_mm(mm, len >> PAGE_SHIFT)) {
		*out = -ENOMEM;
		return BRK_DONE;
	}

	return BRK_CONT;
}

static int brk_expand(struct vma_iterator *vmi, struct vm_area_struct *vma,
		      unsigned long addr, unsigned long len,
		      vma_flags_t *vma_flags, int *out)
{
	struct mm_struct *mm = current->mm;
	const pgoff_t pgoff = addr >> PAGE_SHIFT;

	*out = 0;
	if (!(vma && vma->vm_end == addr))
		return BRK_NEW;

	/*
	 * Expand the existing vma if possible; Note that singular lists do not
	 * occur after forking, so the expand will only happen on new VMAs.
	 */
	{
		VMG_STATE(vmg, mm, vmi, addr, addr + len, *vma_flags, pgoff,
			  pgoff);

		vmg.prev = vma;
		/* vmi is positioned at prev, which this mode expects. */
		vmg.just_expand = true;

		if (vma_merge_new_range(&vmg))
			return BRK_ACCT;
		if (vmg_nomem(&vmg)) {
			vm_unacct_memory(len >> PAGE_SHIFT);
			*out = -ENOMEM;
			return BRK_DONE;
		}
	}
	return BRK_NEW;
}

static int brk_new(struct vma_iterator *vmi, struct vm_area_struct **vmap,
		   unsigned long addr, unsigned long len, vma_flags_t *vma_flags,
		   int *out)
{
	struct mm_struct *mm = current->mm;
	const pgoff_t pgoff = addr >> PAGE_SHIFT;
	struct vm_area_struct *vma;

	*out = 0;
	if (*vmap)
		vma_iter_next_range(vmi);
	/* create a vma struct for an anonymous mapping */
	vma = vm_area_alloc(mm);
	if (!vma)
		goto unacct_fail;

	vma_set_anonymous(vma);
	vma_set_range(vma, addr, addr + len, pgoff, pgoff);
	vma->flags = *vma_flags;
	vma->vm_page_prot = vm_get_page_prot(vma_flags_to_legacy(*vma_flags));
	vma_start_write(vma);
	if (vma_iter_store_gfp(vmi, vma, GFP_KERNEL))
		goto mas_store_fail;

	mm->map_count++;
	validate_mm(mm);
	*vmap = vma;
	return BRK_ACCT;

mas_store_fail:
	vm_area_free(vma);
unacct_fail:
	vm_unacct_memory(len >> PAGE_SHIFT);
	*out = -ENOMEM;
	return BRK_DONE;
}

static void brk_account(struct vm_area_struct *vma, unsigned long len,
			vma_flags_t *vma_flags)
{
	struct mm_struct *mm = current->mm;

	perf_event_mmap(vma);
	mm->total_vm += len >> PAGE_SHIFT;
	mm->data_vm += len >> PAGE_SHIFT;
	if (vma_flags_test(vma_flags, VMA_LOCKED_BIT))
		mm->locked_vm += (len >> PAGE_SHIFT);
	if (pgtable_supports_soft_dirty())
		vma_set_flags(vma, VMA_SOFTDIRTY_BIT);
}

#ifdef CONFIG_RUST_MMAP
int rust_brk_prepare(vma_flags_t *vma_flags, unsigned long len, int *out)
{
	return brk_prepare(vma_flags, len, out);
}

int rust_brk_expand(struct vma_iterator *vmi, struct vm_area_struct *vma,
		    unsigned long addr, unsigned long len,
		    vma_flags_t *vma_flags, int *out)
{
	return brk_expand(vmi, vma, addr, len, vma_flags, out);
}

int rust_brk_new(struct vma_iterator *vmi, struct vm_area_struct **vma,
		 unsigned long addr, unsigned long len, vma_flags_t *vma_flags,
		 int *out)
{
	return brk_new(vmi, vma, addr, len, vma_flags, out);
}

void rust_brk_account(struct vm_area_struct *vma, unsigned long len,
		      vma_flags_t *vma_flags)
{
	brk_account(vma, len, vma_flags);
}
#endif

static int finish_brk_flags(struct vma_iterator *vmi, struct vm_area_struct *vma,
			    unsigned long addr, unsigned long len,
			    vma_flags_t vma_flags)
{
	int out = 0;
	int kind;

	kind = brk_prepare(&vma_flags, len, &out);
	if (kind == BRK_DONE)
		return out;
	kind = brk_expand(vmi, vma, addr, len, &vma_flags, &out);
	if (kind == BRK_DONE)
		return out;
	if (kind == BRK_NEW) {
		kind = brk_new(vmi, &vma, addr, len, &vma_flags, &out);
		if (kind == BRK_DONE)
			return out;
	}
	brk_account(vma, len, &vma_flags);
	return 0;
}

int do_brk_flags(struct vma_iterator *vmi, struct vm_area_struct *vma,
		 unsigned long addr, unsigned long len, vma_flags_t vma_flags)
{
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_brk_dispatch(vmi, vma, addr, len, &vma_flags, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_brk_flags(vmi, vma, addr, len, vma_flags);
}

/**
 * unmapped_area() - Find an area between the low_limit and the high_limit with
 * the correct alignment and offset, all from @info. Note: current->mm is used
 * for the search.
 *
 * @info: The unmapped area information including the range [low_limit -
 * high_limit), the alignment offset and mask.
 *
 * Return: A memory address or -ENOMEM.
 */
unsigned long unmapped_area(struct vm_unmapped_area_info *info)
{
	unsigned long length, gap;
	unsigned long low_limit, high_limit;
	struct vm_area_struct *tmp;
	VMA_ITERATOR(vmi, current->mm, 0);

	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask + info->start_gap;
	if (length < info->length)
		return -ENOMEM;

	low_limit = info->low_limit;
	if (low_limit < mmap_min_addr)
		low_limit = mmap_min_addr;
	high_limit = info->high_limit;
retry:
	if (vma_iter_area_lowest(&vmi, low_limit, high_limit, length))
		return -ENOMEM;

	/*
	 * Adjust for the gap first so it doesn't interfere with the later
	 * alignment. The first step is the minimum needed to fulfill the start
	 * gap, the next step is the minimum to align that. It is the minimum
	 * needed to fulfill both.
	 */
	gap = vma_iter_addr(&vmi) + info->start_gap;
	gap += (info->align_offset - gap) & info->align_mask;
	tmp = vma_next(&vmi);
	/* Avoid prev check if possible */
	if (tmp && vma_test_any_mask(tmp, VMA_STARTGAP_FLAGS)) {
		if (vm_start_gap(tmp) < gap + length - 1) {
			low_limit = tmp->vm_end;
			vma_iter_reset(&vmi);
			goto retry;
		}
	} else {
		tmp = vma_prev(&vmi);
		if (tmp && vm_end_gap(tmp) > gap) {
			low_limit = vm_end_gap(tmp);
			vma_iter_reset(&vmi);
			goto retry;
		}
	}

	return gap;
}

/**
 * unmapped_area_topdown() - Find an area between the low_limit and the
 * high_limit with the correct alignment and offset at the highest available
 * address, all from @info. Note: current->mm is used for the search.
 *
 * @info: The unmapped area information including the range [low_limit -
 * high_limit), the alignment offset and mask.
 *
 * Return: A memory address or -ENOMEM.
 */
unsigned long unmapped_area_topdown(struct vm_unmapped_area_info *info)
{
	unsigned long length, gap, gap_end;
	unsigned long low_limit, high_limit;
	struct vm_area_struct *tmp;
	VMA_ITERATOR(vmi, current->mm, 0);

	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask + info->start_gap;
	if (length < info->length)
		return -ENOMEM;

	low_limit = info->low_limit;
	if (low_limit < mmap_min_addr)
		low_limit = mmap_min_addr;
	high_limit = info->high_limit;
retry:
	if (vma_iter_area_highest(&vmi, low_limit, high_limit, length))
		return -ENOMEM;

	gap = vma_iter_end(&vmi) - info->length;
	gap -= (gap - info->align_offset) & info->align_mask;
	gap_end = vma_iter_end(&vmi);
	tmp = vma_next(&vmi);
	 /* Avoid prev check if possible */
	if (tmp && vma_test_any_mask(tmp, VMA_STARTGAP_FLAGS)) {
		if (vm_start_gap(tmp) < gap_end) {
			high_limit = vm_start_gap(tmp);
			vma_iter_reset(&vmi);
			goto retry;
		}
	} else {
		tmp = vma_prev(&vmi);
		if (tmp && vm_end_gap(tmp) > gap) {
			high_limit = tmp->vm_start;
			vma_iter_reset(&vmi);
			goto retry;
		}
	}

	return gap;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
#define ASG_DONE		0
#define ASG_SEC			1

struct rust_asg_state {
	struct vm_area_struct *vma;
	unsigned long size;
	unsigned long grow;
};

static int asg_classify(struct rust_asg_state *s, int *out)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long new_start;

	*out = 0;

	/* address space limit tests */
	if (!may_expand_vm(mm, &vma->flags, s->grow)) {
		*out = -ENOMEM;
		return ASG_DONE;
	}

	/* Stack limit test */
	if (s->size > rlimit(RLIMIT_STACK)) {
		*out = -ENOMEM;
		return ASG_DONE;
	}

	/* mlock limit tests */
	if (!mlock_future_ok(mm, vma_test(vma, VMA_LOCKED_BIT),
			     s->grow << PAGE_SHIFT)) {
		*out = -ENOMEM;
		return ASG_DONE;
	}

	/* Check to ensure the stack will not grow into a hugetlb-only region */
	new_start = vma->vm_end - s->size;
#ifdef CONFIG_STACK_GROWSUP
	if (vma_test(vma, VMA_GROWSUP_BIT))
		new_start = vma->vm_start;
#endif
	if (is_hugepage_only_range(vma->vm_mm, new_start, s->size)) {
		*out = -EFAULT;
		return ASG_DONE;
	}
	return ASG_SEC;
}

static int asg_sec(struct rust_asg_state *s)
{
	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (security_vm_enough_memory_mm(s->vma->vm_mm, s->grow))
		return -ENOMEM;
	return 0;
}

static void asg_abort(struct rust_asg_state *s)
{
	(void)s;
}

#ifdef CONFIG_RUST_MMAP
int rust_asg_classify(struct rust_asg_state *s, int *out)
{
	return asg_classify(s, out);
}

int rust_asg_sec(struct rust_asg_state *s)
{
	return asg_sec(s);
}

void rust_asg_abort(struct rust_asg_state *s)
{
	asg_abort(s);
}
#endif

static int finish_asg(struct rust_asg_state *s)
{
	int out = 0;

	if (asg_classify(s, &out) == ASG_DONE)
		return out;
	return asg_sec(s);
}

static int acct_stack_growth(struct vm_area_struct *vma,
			     unsigned long size, unsigned long grow)
{
	struct rust_asg_state s = {
		.vma = vma,
		.size = size,
		.grow = grow,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_asg_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_asg(&s);
}

#ifdef CONFIG_STACK_GROWSUP
/*
 * PA-RISC uses this for its stack.
 * vma is the last one with address > vma->vm_end.  Have to extend vma.
 */
int expand_upwards(struct vm_area_struct *vma, unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next;
	unsigned long gap_addr;
	int error = 0;
	VMA_ITERATOR(vmi, mm, vma->vm_start);

	if (!vma_test(vma, VMA_GROWSUP_BIT))
		return -EFAULT;

	mmap_assert_write_locked(mm);

	/* Guard against exceeding limits of the address space. */
	address &= PAGE_MASK;
	if (address >= (TASK_SIZE & PAGE_MASK))
		return -ENOMEM;
	address += PAGE_SIZE;

	/* Enforce stack_guard_gap */
	gap_addr = address + stack_guard_gap;

	/* Guard against overflow */
	if (gap_addr < address || gap_addr > TASK_SIZE)
		gap_addr = TASK_SIZE;

	next = find_vma_intersection(mm, vma->vm_end, gap_addr);
	if (next && vma_is_accessible(next)) {
		if (!vma_test(next, VMA_GROWSUP_BIT))
			return -ENOMEM;
		/* Check that both stack segments have the same anon_vma? */
	}

	if (next)
		vma_iter_prev_range_limit(&vmi, address);

	vma_iter_config(&vmi, vma->vm_start, address);
	if (vma_iter_prealloc(&vmi, vma))
		return -ENOMEM;

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(anon_vma_prepare(vma))) {
		vma_iter_free(&vmi);
		return -ENOMEM;
	}

	/* Lock the VMA before expanding to prevent concurrent page faults */
	vma_start_write(vma);
	/* We update the anon VMA tree. */
	anon_vma_lock_write(vma->anon_vma);

	/* Somebody else might have raced and expanded it already */
	if (address > vma->vm_end) {
		const unsigned long size = address - vma->vm_start;
		const unsigned long grow = (address - vma->vm_end) >> PAGE_SHIFT;
		const pgoff_t pgoff = vma_start_pgoff(vma);

		error = -ENOMEM;
		if (pgoff + (size >> PAGE_SHIFT) >= pgoff) {
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				if (vma_test(vma, VMA_LOCKED_BIT))
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);
				anon_rmap_tree_pre_update_vma(vma);
				vma->vm_end = address;
				/* Overwrite old entry in mtree. */
				vma_iter_store_overwrite(&vmi, vma);
				anon_rmap_tree_post_update_vma(vma);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	vma_iter_free(&vmi);
	validate_mm(mm);
	return error;
}
#endif /* CONFIG_STACK_GROWSUP */

/*
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 * mmap_lock held for writing.
 */
#define EXDN_DONE		0
#define EXDN_APPLY		1

struct rust_exdn_state {
	struct vm_area_struct *vma;
	unsigned long address;
	struct mm_struct *mm;
	struct vma_iterator vmi;
	bool prealloced;
};

static int exdn_classify(struct rust_exdn_state *s, int *out)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *prev;

	s->mm = mm;
	s->prealloced = false;
	*out = 0;

	if (!vma_test(vma, VMA_GROWSDOWN_BIT)) {
		*out = -EFAULT;
		return EXDN_DONE;
	}

	mmap_assert_write_locked(mm);

	s->address &= PAGE_MASK;
	if (s->address < mmap_min_addr || s->address < FIRST_USER_ADDRESS) {
		*out = -EPERM;
		return EXDN_DONE;
	}

	vma_iter_init(&s->vmi, mm, vma->vm_start);

	/* Enforce stack_guard_gap */
	prev = vma_prev(&s->vmi);
	/* Check that both stack segments have the same anon_vma? */
	if (prev) {
		if (!vma_test(prev, VMA_GROWSDOWN_BIT) &&
		    vma_is_accessible(prev) &&
		    (s->address - prev->vm_end < stack_guard_gap)) {
			*out = -ENOMEM;
			return EXDN_DONE;
		}
	}

	if (prev)
		vma_iter_next_range_limit(&s->vmi, vma->vm_start);

	vma_iter_config(&s->vmi, s->address, vma->vm_end);
	if (vma_iter_prealloc(&s->vmi, vma)) {
		*out = -ENOMEM;
		return EXDN_DONE;
	}
	s->prealloced = true;

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(anon_vma_prepare(vma))) {
		vma_iter_free(&s->vmi);
		s->prealloced = false;
		*out = -ENOMEM;
		return EXDN_DONE;
	}
	return EXDN_APPLY;
}

static int exdn_apply(struct rust_exdn_state *s)
{
	struct vm_area_struct *vma = s->vma;
	struct mm_struct *mm = s->mm;
	unsigned long address = s->address;
	int error = 0;

	/* Lock the VMA before expanding to prevent concurrent page faults */
	vma_start_write(vma);
	/* We update the anon VMA tree. */
	anon_vma_lock_write(vma->anon_vma);

	/* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		const unsigned long size = vma->vm_end - address;
		const unsigned long grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (grow <= vma_start_pgoff(vma)) {
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				if (vma_test(vma, VMA_LOCKED_BIT))
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);
				anon_rmap_tree_pre_update_vma(vma);
				vma->vm_start = address;
				vma_sub_pgoff(vma, grow);
				/* Overwrite old entry in mtree. */
				vma_iter_store_overwrite(&s->vmi, vma);
				anon_rmap_tree_post_update_vma(vma);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	vma_iter_free(&s->vmi);
	s->prealloced = false;
	validate_mm(mm);
	return error;
}

static void exdn_abort(struct rust_exdn_state *s)
{
	if (s->prealloced) {
		vma_iter_free(&s->vmi);
		s->prealloced = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_exdn_classify(struct rust_exdn_state *s, int *out)
{
	return exdn_classify(s, out);
}

int rust_exdn_apply(struct rust_exdn_state *s)
{
	return exdn_apply(s);
}

void rust_exdn_abort(struct rust_exdn_state *s)
{
	exdn_abort(s);
}
#endif

static int finish_exdn(struct rust_exdn_state *s)
{
	int out = 0;

	if (exdn_classify(s, &out) == EXDN_DONE)
		return out;
	return exdn_apply(s);
}

int expand_downwards(struct vm_area_struct *vma, unsigned long address)
{
	struct rust_exdn_state s = {
		.vma = vma,
		.address = address,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_exdn_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_exdn(&s);
}

int __vm_munmap(unsigned long start, size_t len, bool unlock)
{
	int ret;
	struct mm_struct *mm = current->mm;
	LIST_HEAD(uf);
	VMA_ITERATOR(vmi, mm, start);

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = do_vmi_munmap(&vmi, mm, start, len, &uf, unlock);
	if (ret || !unlock)
		mmap_write_unlock(mm);

	userfaultfd_unmap_complete(mm, &uf);
	return ret;
}

/*
 * Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree if file-backed.
 */
#define IVS_DONE		0
#define IVS_LINK		1

struct rust_ivs_state {
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long charged;
	bool acct;
};

static int ivs_classify(struct rust_ivs_state *s, int *out)
{
	*out = 0;
	s->charged = vma_pages(s->vma);
	s->acct = false;

	if (find_vma_intersection(s->mm, s->vma->vm_start, s->vma->vm_end)) {
		*out = -ENOMEM;
		return IVS_DONE;
	}

	if (vma_test(s->vma, VMA_ACCOUNT_BIT)) {
		if (security_vm_enough_memory_mm(s->mm, s->charged)) {
			*out = -ENOMEM;
			return IVS_DONE;
		}
		s->acct = true;
	}

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap and in do_brk_flags.
	 */
	if (vma_is_anonymous(s->vma)) {
		WARN_ON_ONCE(s->vma->anon_vma);
		vma_set_pgoff(s->vma, s->vma->vm_start >> PAGE_SHIFT);
	}
	vma_set_anon_pgoff(s->vma, s->vma->vm_start >> PAGE_SHIFT);
	return IVS_LINK;
}

static int ivs_link(struct rust_ivs_state *s)
{
	if (vma_link(s->mm, s->vma)) {
		if (s->acct)
			vm_unacct_memory(s->charged);
		s->acct = false;
		return -ENOMEM;
	}
	s->acct = false;
	return 0;
}

static void ivs_abort(struct rust_ivs_state *s)
{
	if (s->acct) {
		vm_unacct_memory(s->charged);
		s->acct = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_ivs_classify(struct rust_ivs_state *s, int *out)
{
	return ivs_classify(s, out);
}

int rust_ivs_link(struct rust_ivs_state *s)
{
	return ivs_link(s);
}

void rust_ivs_abort(struct rust_ivs_state *s)
{
	ivs_abort(s);
}
#endif

static int finish_ivs(struct rust_ivs_state *s)
{
	int out = 0;

	if (ivs_classify(s, &out) == IVS_DONE)
		return out;
	return ivs_link(s);
}

int insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma)
{
	struct rust_ivs_state s = {
		.mm = mm,
		.vma = vma,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_ivs_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_ivs(&s);
}

/**
 * vma_mmu_pagesize - Default MMU page size granularity for this VMA.
 * @vma: The user mapping.
 *
 * In the common case, the default page size used by the MMU matches the
 * default page size used by the kernel (see vma_kernel_pagesize()). On
 * architectures where it differs, an architecture-specific 'strong' version
 * of this symbol is required.
 *
 * The default MMU page size is not affected by Transparent Huge Pages
 * being in effect, or any usage of larger MMU page sizes (either through
 * architectural huge-page mappings or other explicit/implicit coalescing of
 * virtual ranges performed by the MMU).
 *
 * Return: The default MMU page size granularity for this VMA.
 */
__weak unsigned long vma_mmu_pagesize(struct vm_area_struct *vma)
{
	return vma_kernel_pagesize(vma);
}

#define ISM_DONE		0
#define ISM_LINK		1

struct rust_ism_state {
	struct mm_struct *mm;
	unsigned long addr;
	unsigned long len;
	vm_flags_t vm_flags;
	void *priv;
	const struct vm_operations_struct *ops;
	struct vm_area_struct *vma;
};

static int ism_classify(struct rust_ism_state *s, struct vm_area_struct **ret)
{
	vma_flags_t vma_flags = legacy_to_vma_flags(s->vm_flags);

	*ret = NULL;
	s->vma = vm_area_alloc(s->mm);
	if (unlikely(!s->vma)) {
		*ret = ERR_PTR(-ENOMEM);
		return ISM_DONE;
	}

	vma_flags_set_mask(&vma_flags, s->mm->def_vma_flags);
	vma_flags_set(&vma_flags, VMA_DONTEXPAND_BIT);
	if (pgtable_supports_soft_dirty())
		vma_flags_set(&vma_flags, VMA_SOFTDIRTY_BIT);
	vma_flags_clear_mask(&vma_flags, VMA_LOCKED_MASK);
	s->vma->flags = vma_flags;
	s->vma->vm_page_prot = vma_get_page_prot(s->vma);

	s->vma->vm_ops = s->ops;
	s->vma->vm_private_data = s->priv;
	vma_set_range(s->vma, s->addr, s->addr + s->len, 0, s->addr >> PAGE_SHIFT);
	return ISM_LINK;
}

static struct vm_area_struct *ism_link(struct rust_ism_state *s)
{
	int ret;

	ret = insert_vm_struct(s->mm, s->vma);
	if (ret)
		goto out;

	vm_stat_account(s->mm, s->vma->vm_flags, s->len >> PAGE_SHIFT);
	perf_event_mmap(s->vma);
	return s->vma;

out:
	vm_area_free(s->vma);
	s->vma = NULL;
	return ERR_PTR(ret);
}

static void ism_abort(struct rust_ism_state *s)
{
	if (s->vma) {
		vm_area_free(s->vma);
		s->vma = NULL;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_ism_classify(struct rust_ism_state *s, struct vm_area_struct **ret)
{
	return ism_classify(s, ret);
}

struct vm_area_struct *rust_ism_link(struct rust_ism_state *s)
{
	return ism_link(s);
}

void rust_ism_abort(struct rust_ism_state *s)
{
	ism_abort(s);
}
#endif

static struct vm_area_struct *finish_ism(struct rust_ism_state *s)
{
	struct vm_area_struct *ret = NULL;

	if (ism_classify(s, &ret) == ISM_DONE)
		return ret;
	return ism_link(s);
}

struct vm_area_struct *__install_special_mapping(
	struct mm_struct *mm,
	unsigned long addr, unsigned long len,
	vm_flags_t vm_flags, void *priv,
	const struct vm_operations_struct *ops)
{
	struct rust_ism_state s = {
		.mm = mm,
		.addr = addr,
		.len = len,
		.vm_flags = vm_flags,
		.priv = priv,
		.ops = ops,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		struct vm_area_struct *rust_ret;

		rust_ret = rust_ism_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_ism(&s);
}
