// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/mmap.c
 *
 * Written by obz.
 *
 * Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/shmem_fs.h>
#include <linux/profile.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/mmdebug.h>
#include <linux/perf_event.h>
#include <linux/audit.h>
#include <linux/khugepaged.h>
#include <linux/uprobes.h>
#include <linux/notifier.h>
#include <linux/memory.h>
#include <linux/printk.h>
#include <linux/userfaultfd_k.h>
#include <linux/moduleparam.h>
#include <linux/pkeys.h>
#include <linux/oom.h>
#include <linux/sched/mm.h>
#include <linux/ksm.h>
#include <linux/memfd.h>

#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mmap.h>

#include "internal.h"

#ifndef arch_mmap_check
#define arch_mmap_check(addr, len, flags)	(0)
#endif

#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
const int mmap_rnd_bits_min = CONFIG_ARCH_MMAP_RND_BITS_MIN;
int mmap_rnd_bits_max __ro_after_init = CONFIG_ARCH_MMAP_RND_BITS_MAX;
int mmap_rnd_bits __read_mostly = CONFIG_ARCH_MMAP_RND_BITS;
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
const int mmap_rnd_compat_bits_min = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN;
const int mmap_rnd_compat_bits_max = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX;
int mmap_rnd_compat_bits __read_mostly = CONFIG_ARCH_MMAP_RND_COMPAT_BITS;
#endif

static bool ignore_rlimit_data;
core_param(ignore_rlimit_data, ignore_rlimit_data, bool, 0644);

/* Update vma->vm_page_prot to reflect vma->vm_flags. */
void vma_set_page_prot(struct vm_area_struct *vma)
{
	vma_flags_t vma_flags = vma->flags;
	pgprot_t vm_page_prot;

	vm_page_prot = vma_pgprot_modify(vma->vm_page_prot, vma_flags);
	if (vma_wants_writenotify(vma, vm_page_prot)) {
		vma_flags_clear(&vma_flags, VMA_SHARED_BIT);
		vm_page_prot = vma_pgprot_modify(vm_page_prot, vma_flags);
	}
	/* remove_protection_ptes reads vma->vm_page_prot without mmap_lock */
	WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}

/*
 * check_brk_limits() - Use platform specific check of range & verify mlock
 * limits.
 * @addr: The address to check
 * @len: The size of increase.
 *
 * Return: 0 on success.
 */
static int check_brk_limits(unsigned long addr, unsigned long len)
{
	const struct mm_struct *mm = current->mm;
	const bool is_def_locked =
		vma_flags_test(&mm->def_vma_flags, VMA_LOCKED_BIT);
	unsigned long mapped_addr;

	mapped_addr = get_unmapped_area(NULL, addr, len, 0, MAP_FIXED);
	if (IS_ERR_VALUE(mapped_addr))
		return mapped_addr;

	return mlock_future_ok(mm, is_def_locked, len) ? 0 : -EAGAIN;
}

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < mmap_min_addr))
		return PAGE_ALIGN(mmap_min_addr);
	return hint;
}

#define SYSBRK_DONE		0
#define SYSBRK_EXIT		1

struct rust_sysbrk_state {
	unsigned long brk;
	unsigned long origbrk;
	unsigned long newbrk;
	unsigned long oldbrk;
	struct mm_struct *mm;
	struct vm_area_struct *brkvma;
	struct vm_area_struct *next;
	struct vma_iterator vmi;
	struct list_head uf;
	bool populate;
	bool locked;
};

static int sysbrk_classify(struct rust_sysbrk_state *s, unsigned long *out)
{
	unsigned long min_brk;
	struct mm_struct *mm = current->mm;

	s->mm = mm;
	s->populate = false;
	s->locked = false;
	s->next = NULL;
	INIT_LIST_HEAD(&s->uf);
	*out = 0;

	if (mmap_write_lock_killable(mm)) {
		*out = -EINTR;
		return SYSBRK_DONE;
	}
	s->locked = true;

	s->origbrk = mm->brk;

	min_brk = mm->start_brk;
#ifdef CONFIG_COMPAT_BRK
	/*
	 * CONFIG_COMPAT_BRK can still be overridden by setting
	 * randomize_va_space to 2, which will still cause mm->start_brk
	 * to be arbitrarily shifted
	 */
	if (!current->brk_randomized)
		min_brk = mm->end_data;
#endif
	if (s->brk < min_brk)
		goto fail;

	/*
	 * Check against rlimit here. If this check is done later after the test
	 * of oldbrk with newbrk then it can escape the test and let the data
	 * segment grow beyond its set limit the in case where the limit is
	 * not page aligned -Ram Gupta
	 */
	if (check_data_rlimit(rlimit(RLIMIT_DATA), s->brk, mm->start_brk,
			      mm->end_data, mm->start_data))
		goto fail;

	s->newbrk = PAGE_ALIGN(s->brk);
	s->oldbrk = PAGE_ALIGN(mm->brk);
	if (s->oldbrk == s->newbrk) {
		mm->brk = s->brk;
		return SYSBRK_EXIT;
	}

	/* Always allow shrinking brk. */
	if (s->brk <= mm->brk) {
		/* Search one past newbrk */
		vma_iter_init(&s->vmi, mm, s->newbrk);
		s->brkvma = vma_find(&s->vmi, s->oldbrk);
		if (!s->brkvma || s->brkvma->vm_start >= s->oldbrk)
			goto fail; /* mapping intersects with an existing non-brk vma. */
		/*
		 * mm->brk must be protected by write mmap_lock.
		 * do_vmi_align_munmap() will drop the lock on success,  so
		 * update it before calling do_vma_munmap().
		 */
		mm->brk = s->brk;
		if (do_vmi_align_munmap(&s->vmi, s->brkvma, mm, s->newbrk,
					s->oldbrk, &s->uf,
					/* unlock = */ true))
			goto fail;

		s->locked = false;
		return SYSBRK_EXIT;
	}

	if (check_brk_limits(s->oldbrk, s->newbrk - s->oldbrk))
		goto fail;

	/*
	 * Only check if the next VMA is within the stack_guard_gap of the
	 * expansion area
	 */
	vma_iter_init(&s->vmi, mm, s->oldbrk);
	s->next = vma_find(&s->vmi, s->newbrk + PAGE_SIZE + stack_guard_gap);
	if (s->next && s->newbrk + PAGE_SIZE > vm_start_gap(s->next))
		goto fail;

	s->brkvma = vma_prev_limit(&s->vmi, mm->start_brk);
	/* Ok, looks good - let it rip. */
	if (do_brk_flags(&s->vmi, s->brkvma, s->oldbrk, s->newbrk - s->oldbrk,
			 EMPTY_VMA_FLAGS) < 0)
		goto fail;

	mm->brk = s->brk;
	if (vma_flags_test(&mm->def_vma_flags, VMA_LOCKED_BIT))
		s->populate = true;

	return SYSBRK_EXIT;

fail:
	mm->brk = s->origbrk;
	mmap_write_unlock(mm);
	s->locked = false;
	*out = s->origbrk;
	return SYSBRK_DONE;
}

static unsigned long sysbrk_exit(struct rust_sysbrk_state *s)
{
	if (s->locked)
		mmap_write_unlock(s->mm);
	s->locked = false;
	userfaultfd_unmap_complete(s->mm, &s->uf);
	if (s->populate)
		mm_populate(s->oldbrk, s->newbrk - s->oldbrk);
	return s->brk;
}

static void sysbrk_abort(struct rust_sysbrk_state *s)
{
	if (s->locked) {
		s->mm->brk = s->origbrk;
		mmap_write_unlock(s->mm);
		s->locked = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_sysbrk_classify(struct rust_sysbrk_state *s, unsigned long *out)
{
	return sysbrk_classify(s, out);
}

unsigned long rust_sysbrk_exit(struct rust_sysbrk_state *s)
{
	return sysbrk_exit(s);
}

void rust_sysbrk_abort(struct rust_sysbrk_state *s)
{
	sysbrk_abort(s);
}
#endif

static unsigned long finish_sysbrk(struct rust_sysbrk_state *s)
{
	unsigned long out = 0;

	if (sysbrk_classify(s, &out) == SYSBRK_EXIT)
		return sysbrk_exit(s);
	return out;
}

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	struct rust_sysbrk_state s = {
		.brk = brk,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	unsigned long rust_ret;

	rust_ret = rust_sysbrk_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_sysbrk(&s);
}

bool mlock_future_ok(const struct mm_struct *mm, bool is_vma_locked,
		     unsigned long bytes)
{
	unsigned long locked_pages, limit_pages;

	if (!is_vma_locked || capable(CAP_IPC_LOCK))
		return true;

	locked_pages = bytes >> PAGE_SHIFT;
	locked_pages += mm->locked_vm;

	limit_pages = rlimit(RLIMIT_MEMLOCK);
	limit_pages >>= PAGE_SHIFT;

	return locked_pages <= limit_pages;
}

static inline u64 file_mmap_size_max(struct file *file, struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISBLK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	if (S_ISSOCK(inode->i_mode))
		return MAX_LFS_FILESIZE;

	/* Special "we do even unsigned file positions" case */
	if (file->f_op->fop_flags & FOP_UNSIGNED_OFFSET)
		return 0;

	/* Yes, random drivers might want more. But I'm tired of buggy drivers */
	return ULONG_MAX;
}

static inline bool file_mmap_ok(struct file *file, struct inode *inode,
				unsigned long pgoff, unsigned long len)
{
	u64 maxsize = file_mmap_size_max(file, inode);

	if (maxsize && len > maxsize)
		return false;
	maxsize -= len;
	if (pgoff > maxsize >> PAGE_SHIFT)
		return false;
	return true;
}

/**
 * do_mmap() - Perform a userland memory mapping into the current process
 * address space of length @len with protection bits @prot, mmap flags @flags
 * (from which VMA flags will be inferred), and any additional VMA flags to
 * apply @vma_flags. If this is a file-backed mapping then the file is specified
 * in @file and page offset into the file via @pgoff.
 *
 * This function does not perform security checks on the file and assumes, if
 * @uf is non-NULL, the caller has provided a list head to track unmap events
 * for userfaultfd @uf.
 *
 * It also simply indicates whether memory population is required by setting
 * @populate, which must be non-NULL, expecting the caller to actually perform
 * this task itself if appropriate.
 *
 * This function will invoke architecture-specific (and if provided and
 * relevant, file system-specific) logic to determine the most appropriate
 * unmapped area in which to place the mapping if not MAP_FIXED.
 *
 * Callers which require userland mmap() behaviour should invoke vm_mmap(),
 * which is also exported for module use.
 *
 * Those which require this behaviour less security checks, userfaultfd and
 * populate behaviour, and who handle the mmap write lock themselves, should
 * call this function.
 *
 * Note that the returned address may reside within a merged VMA if an
 * appropriate merge were to take place, so it doesn't necessarily specify the
 * start of a VMA, rather only the start of a valid mapped range of length
 * @len bytes, rounded down to the nearest page size.
 *
 * The caller must write-lock current->mm->mmap_lock.
 *
 * @file: An optional struct file pointer describing the file which is to be
 * mapped, if a file-backed mapping.
 * @addr: If non-zero, hints at (or if @flags has MAP_FIXED set, specifies) the
 * address at which to perform this mapping. See mmap (2) for details. Must be
 * page-aligned.
 * @len: The length of the mapping. Will be page-aligned and must be at least 1
 * page in size.
 * @prot: Protection bits describing access required to the mapping. See mmap
 * (2) for details.
 * @flags: Flags specifying how the mapping should be performed, see mmap (2)
 * for details.
 * @vma_flags: VMA flags which should be set by default, or EMPTY_VMA_FLAGS
 * otherwise.
 * @pgoff: Page offset into the @file if file-backed, should be 0 otherwise.
 * @populate: A pointer to a value which will be set to 0 if no population of
 * the range is required, or the number of bytes to populate if it is. Must be
 * non-NULL. See mmap (2) for details as to under what circumstances population
 * of the range occurs.
 * @uf: An optional pointer to a list head to track userfaultfd unmap events
 * should unmapping events arise. If provided, it is up to the caller to manage
 * this.
 *
 * Returns: Either an error, or the address at which the requested mapping has
 * been performed.
 */
#define MMAP_PREP_DONE		0
#define MMAP_PREP_REGION	1

static int mmap_prepare(struct file *file, unsigned long *addrp,
			unsigned long *lenp, unsigned long *protp,
			unsigned long *flagsp, vma_flags_t *vma_flagsp,
			unsigned long *pgoffp, unsigned long *out)
{
	struct mm_struct *mm = current->mm;
	int pkey = 0;
	unsigned long addr = *addrp;
	unsigned long len = *lenp;
	unsigned long prot = *protp;
	unsigned long flags = *flagsp;
	unsigned long pgoff = *pgoffp;
	vma_flags_t vma_flags = *vma_flagsp;

	*out = 0;

	mmap_assert_write_locked(mm);

	if (!len) {
		*out = -EINVAL;
		return MMAP_PREP_DONE;
	}

	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we don't add PROT_EXEC.)
	 */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && path_noexec(&file->f_path)))
			prot |= PROT_EXEC;

	/* force arch specific MAP_FIXED handling in get_unmapped_area */
	if (flags & MAP_FIXED_NOREPLACE)
		flags |= MAP_FIXED;

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len) {
		*out = -ENOMEM;
		return MMAP_PREP_DONE;
	}

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff) {
		*out = -EOVERFLOW;
		return MMAP_PREP_DONE;
	}

	/* Too many mappings? */
	if (mm->map_count > get_sysctl_max_map_count()) {
		*out = -ENOMEM;
		return MMAP_PREP_DONE;
	}

	/*
	 * addr is returned from get_unmapped_area,
	 * There are two cases:
	 * 1> MAP_FIXED == false
	 *	unallocated memory, no need to check sealing.
	 * 1> MAP_FIXED == true
	 *	sealing is checked inside mmap_region when
	 *	do_vmi_munmap is called.
	 */

	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(mm);
		if (pkey < 0)
			pkey = 0;
	}

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vma_flags_set_mask(&vma_flags,
			   legacy_to_vma_flags(calc_vm_prot_bits(prot, pkey)));
	vma_flags_set_mask(&vma_flags,
			   legacy_to_vma_flags(calc_vm_flag_bits(file, flags)));
	vma_flags_set_mask(&vma_flags, mm->def_vma_flags);
	vma_flags_set(&vma_flags, VMA_MAYREAD_BIT, VMA_MAYWRITE_BIT,
		      VMA_MAYEXEC_BIT);

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = __get_unmapped_area(file, addr, len, pgoff, flags, vma_flags);
	if (IS_ERR_VALUE(addr)) {
		*out = addr;
		return MMAP_PREP_DONE;
	}

	if (flags & MAP_FIXED_NOREPLACE) {
		if (find_vma_intersection(mm, addr, addr + len)) {
			*out = -EEXIST;
			return MMAP_PREP_DONE;
		}
	}

	if (flags & MAP_LOCKED)
		if (!can_do_mlock()) {
			*out = -EPERM;
			return MMAP_PREP_DONE;
		}

	if (!mlock_future_ok(mm, vma_flags_test(&vma_flags, VMA_LOCKED_BIT), len)) {
		*out = -EAGAIN;
		return MMAP_PREP_DONE;
	}

	if (file) {
		struct inode *inode = file_inode(file);
		unsigned long flags_mask;
		int err;

		if (!file_mmap_ok(file, inode, pgoff, len)) {
			*out = -EOVERFLOW;
			return MMAP_PREP_DONE;
		}

		flags_mask = LEGACY_MAP_MASK;
		if (file->f_op->fop_flags & FOP_MMAP_SYNC)
			flags_mask |= MAP_SYNC;

		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			/*
			 * Force use of MAP_SHARED_VALIDATE with non-legacy
			 * flags. E.g. MAP_SYNC is dangerous to use with
			 * MAP_SHARED as you don't know which consistency model
			 * you will get. We silently ignore unsupported flags
			 * with MAP_SHARED to preserve backward compatibility.
			 */
			flags &= LEGACY_MAP_MASK;
			fallthrough;
		case MAP_SHARED_VALIDATE:
			if (flags & ~flags_mask) {
				*out = -EOPNOTSUPP;
				return MMAP_PREP_DONE;
			}
			if (prot & PROT_WRITE) {
				if (!(file->f_mode & FMODE_WRITE)) {
					*out = -EACCES;
					return MMAP_PREP_DONE;
				}
				if (IS_SWAPFILE(file->f_mapping->host)) {
					*out = -ETXTBSY;
					return MMAP_PREP_DONE;
				}
			}

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE)) {
				*out = -EACCES;
				return MMAP_PREP_DONE;
			}

			vma_flags_set(&vma_flags, VMA_SHARED_BIT, VMA_MAYSHARE_BIT);
			if (!(file->f_mode & FMODE_WRITE))
				vma_flags_clear(&vma_flags, VMA_MAYWRITE_BIT,
						VMA_SHARED_BIT);
			fallthrough;
		case MAP_PRIVATE:
			if (!(file->f_mode & FMODE_READ)) {
				*out = -EACCES;
				return MMAP_PREP_DONE;
			}
			if (path_noexec(&file->f_path)) {
				if (vma_flags_test(&vma_flags, VMA_EXEC_BIT)) {
					*out = -EPERM;
					return MMAP_PREP_DONE;
				}
				vma_flags_clear(&vma_flags, VMA_MAYEXEC_BIT);
			}

			if (!can_mmap_file(file)) {
				*out = -ENODEV;
				return MMAP_PREP_DONE;
			}
			if (vma_flags_can_grow(&vma_flags)) {
				*out = -EINVAL;
				return MMAP_PREP_DONE;
			}
			break;

		default:
			*out = -EINVAL;
			return MMAP_PREP_DONE;
		}

		/*
		 * Check to see if we are violating any seals and update VMA
		 * flags if necessary to avoid future seal violations.
		 */
		err = memfd_check_seals_mmap(file, &vma_flags);
		if (err) {
			*out = (unsigned long)err;
			return MMAP_PREP_DONE;
		}
	} else {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if (vma_flags_can_grow(&vma_flags)) {
				*out = -EINVAL;
				return MMAP_PREP_DONE;
			}
			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vma_flags_set(&vma_flags, VMA_SHARED_BIT, VMA_MAYSHARE_BIT);
			break;
		case MAP_DROPPABLE: {
			vma_flags_t droppable = VMA_DROPPABLE;

			if (vma_flags_empty(&droppable)) {
				*out = -EOPNOTSUPP;
				return MMAP_PREP_DONE;
			}
			vma_flags_set_mask(&vma_flags, droppable);

			/*
			 * A locked or stack area makes no sense to be droppable.
			 *
			 * Also, since droppable pages can just go away at any time
			 * it makes no sense to copy them on fork or dump them.
			 *
			 * And don't attempt to combine with hugetlb for now.
			 */
			if (flags & (MAP_LOCKED | MAP_HUGETLB)) {
				*out = -EINVAL;
				return MMAP_PREP_DONE;
			}
			if (vma_flags_can_grow(&vma_flags)) {
				*out = -EINVAL;
				return MMAP_PREP_DONE;
			}

			/*
			 * If the pages can be dropped, then it doesn't make
			 * sense to reserve them.
			 */
			vma_flags_set(&vma_flags, VMA_NORESERVE_BIT);

			/*
			 * Likewise, they're volatile enough that they
			 * shouldn't survive forks or coredumps.
			 */
			vma_flags_set(&vma_flags, VMA_WIPEONFORK_BIT,
				      VMA_DONTDUMP_BIT);

			fallthrough;
		}
		case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			*out = -EINVAL;
			return MMAP_PREP_DONE;
		}
	}

	/*
	 * Set VMA_NORESERVE_BIT if we should not account for the memory use
	 * of this mapping.
	 */
	if (flags & MAP_NORESERVE) {
		/* We honor MAP_NORESERVE if allowed to overcommit */
		if (sysctl_overcommit_memory != OVERCOMMIT_NEVER)
			vma_flags_set(&vma_flags, VMA_NORESERVE_BIT);

		/* hugetlb applies strict overcommit unless MAP_NORESERVE */
		if (file && is_file_hugepages(file))
			vma_flags_set(&vma_flags, VMA_NORESERVE_BIT);
	}

	*addrp = addr;
	*lenp = len;
	*protp = prot;
	*flagsp = flags;
	*pgoffp = pgoff;
	*vma_flagsp = vma_flags;
	return MMAP_PREP_REGION;
}

static void mmap_maybe_populate(unsigned long addr, unsigned long flags,
				vma_flags_t *vma_flags, unsigned long len,
				unsigned long *populate)
{
	if (!IS_ERR_VALUE(addr) &&
	    (vma_flags_test(vma_flags, VMA_LOCKED_BIT) ||
	     (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
		*populate = len;
}

#ifdef CONFIG_RUST_MMAP
int rust_dommap_prepare(struct file *file, unsigned long *addr,
			unsigned long *len, unsigned long *prot,
			unsigned long *flags, vma_flags_t *vma_flags,
			unsigned long *pgoff, unsigned long *out)
{
	return mmap_prepare(file, addr, len, prot, flags, vma_flags, pgoff,
			    out);
}

unsigned long rust_dommap_region(struct file *file, unsigned long addr,
				 unsigned long len, vma_flags_t *vma_flags,
				 unsigned long pgoff, struct list_head *uf)
{
	return mmap_region(file, addr, len, *vma_flags, pgoff, uf);
}

void rust_dommap_populate(unsigned long addr, unsigned long flags,
			  vma_flags_t *vma_flags, unsigned long len,
			  unsigned long *populate)
{
	mmap_maybe_populate(addr, flags, vma_flags, len, populate);
}
#endif

static unsigned long finish_mmap(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vma_flags_t vma_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf)
{
	unsigned long out = 0;

	*populate = 0;
	if (mmap_prepare(file, &addr, &len, &prot, &flags, &vma_flags, &pgoff,
			 &out) == MMAP_PREP_DONE)
		return out;
	addr = mmap_region(file, addr, len, vma_flags, pgoff, uf);
	mmap_maybe_populate(addr, flags, &vma_flags, len, populate);
	return addr;
}

unsigned long do_mmap(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, vma_flags_t vma_flags,
			unsigned long pgoff, unsigned long *populate,
			struct list_head *uf)
{
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	unsigned long rust_ret;

	rust_ret = rust_dommap_dispatch(file, &addr, &len, &prot, &flags,
					&vma_flags, &pgoff, populate, uf,
					&handled);
	if (handled)
		return rust_ret;
#endif
	return finish_mmap(file, addr, len, prot, flags, vma_flags, pgoff,
			   populate, uf);
}

#define KMP_DONE		0
#define KMP_MMAP		1

struct rust_kmp_state {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long pgoff;
	struct file *file;
};

static int kmp_classify(struct rust_kmp_state *s, unsigned long *out)
{
	*out = 0;
	s->file = NULL;

	if (!(s->flags & MAP_ANONYMOUS)) {
		audit_mmap_fd(s->fd, s->flags);
		s->file = fget(s->fd);
		if (!s->file) {
			*out = -EBADF;
			return KMP_DONE;
		}
		if (is_file_hugepages(s->file)) {
			s->len = ALIGN(s->len,
				       huge_page_size(hstate_file(s->file)));
		} else if (unlikely(s->flags & MAP_HUGETLB)) {
			*out = -EINVAL;
			fput(s->file);
			s->file = NULL;
			return KMP_DONE;
		}
		return KMP_MMAP;
	}

	if (s->flags & MAP_HUGETLB) {
		struct hstate *hs;

		hs = hstate_sizelog((s->flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (!hs) {
			*out = -EINVAL;
			return KMP_DONE;
		}

		s->len = ALIGN(s->len, huge_page_size(hs));
		/*
		 * VM_NORESERVE is used because the reservations will be
		 * taken when vm_ops->mmap() is called
		 */
		s->file = hugetlb_file_setup(HUGETLB_ANON_FILE, s->len,
				mk_vma_flags(VMA_NORESERVE_BIT),
				HUGETLB_ANONHUGE_INODE,
				(s->flags >> MAP_HUGE_SHIFT) & MAP_HUGE_MASK);
		if (IS_ERR(s->file)) {
			*out = PTR_ERR(s->file);
			s->file = NULL;
			return KMP_DONE;
		}
	}
	return KMP_MMAP;
}

static unsigned long kmp_mmap(struct rust_kmp_state *s)
{
	unsigned long retval;

	retval = vm_mmap_pgoff(s->file, s->addr, s->len, s->prot, s->flags,
			       s->pgoff);
	if (s->file) {
		fput(s->file);
		s->file = NULL;
	}
	return retval;
}

static void kmp_abort(struct rust_kmp_state *s)
{
	if (s->file) {
		fput(s->file);
		s->file = NULL;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_kmp_classify(struct rust_kmp_state *s, unsigned long *out)
{
	return kmp_classify(s, out);
}

unsigned long rust_kmp_mmap(struct rust_kmp_state *s)
{
	return kmp_mmap(s);
}

void rust_kmp_abort(struct rust_kmp_state *s)
{
	kmp_abort(s);
}
#endif

static unsigned long finish_kmp(struct rust_kmp_state *s)
{
	unsigned long out = 0;

	if (kmp_classify(s, &out) == KMP_DONE)
		return out;
	return kmp_mmap(s);
}

unsigned long ksys_mmap_pgoff(unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd, unsigned long pgoff)
{
	struct rust_kmp_state s = {
		.addr = addr,
		.len = len,
		.prot = prot,
		.flags = flags,
		.fd = fd,
		.pgoff = pgoff,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		unsigned long rust_ret;

		rust_ret = rust_kmp_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_kmp(&s);
}

SYSCALL_DEFINE6(mmap_pgoff, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, pgoff)
{
	return ksys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}

#ifdef __ARCH_WANT_SYS_OLD_MMAP
struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

SYSCALL_DEFINE1(old_mmap, struct mmap_arg_struct __user *, arg)
{
	struct mmap_arg_struct a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	if (offset_in_page(a.offset))
		return -EINVAL;

	return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd,
			       a.offset >> PAGE_SHIFT);
}
#endif /* __ARCH_WANT_SYS_OLD_MMAP */

/*
 * Determine if the allocation needs to ensure that there is no
 * existing mapping within it's guard gaps, for use as start_gap.
 */
static inline unsigned long stack_guard_placement(vma_flags_t vma_flags)
{
	if (vma_flags_test_single_mask(&vma_flags, VMA_SHADOW_STACK))
		return PAGE_SIZE;

	return 0;
}

/*
 * Search for an unmapped address range.
 *
 * We are looking for a range that:
 * - does not intersect with any VMA;
 * - is contained within the [low_limit, high_limit) interval;
 * - is at least the desired size.
 * - satisfies (begin_addr & align_mask) == (align_offset & align_mask)
 */
unsigned long vm_unmapped_area(struct vm_unmapped_area_info *info)
{
	unsigned long addr;

#ifdef CONFIG_RUST_MMAP
	addr = rust_vm_unmapped_area(info);
#else
	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		addr = unmapped_area_topdown(info);
	else
		addr = unmapped_area(info);
#endif

	trace_vm_unmapped_area(addr, info);
	return addr;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
unsigned long
generic_get_unmapped_area(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags, vma_flags_t vma_flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	struct vm_unmapped_area_info info = {};
	const unsigned long mmap_end = arch_get_mmap_end(addr, len, flags);

	if (len > mmap_end - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (mmap_end - len >= addr && addr >= mmap_min_addr &&
		    (!vma || addr + len <= vm_start_gap(vma)) &&
		    (!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.length = len;
	info.low_limit = mm->mmap_base;
	info.high_limit = mmap_end;
	info.start_gap = stack_guard_placement(vma_flags);
	if (filp && is_file_hugepages(filp))
		info.align_mask = huge_page_mask_align(filp);
	return vm_unmapped_area(&info);
}

#ifndef HAVE_ARCH_UNMAPPED_AREA
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		       unsigned long len, unsigned long pgoff,
		       unsigned long flags, vm_flags_t vm_flags)
{
	return generic_get_unmapped_area(filp, addr, len, pgoff, flags,
					 legacy_to_vma_flags(vm_flags));
}
#endif

/*
 * This mmap-allocator allocates new areas top-down from below the
 * stack's low limit (the base):
 */
unsigned long
generic_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
				  unsigned long len, unsigned long pgoff,
				  unsigned long flags, vma_flags_t vma_flags)
{
	struct vm_area_struct *vma, *prev;
	struct mm_struct *mm = current->mm;
	struct vm_unmapped_area_info info = {};
	const unsigned long mmap_end = arch_get_mmap_end(addr, len, flags);

	/* requested length too big for entire address space */
	if (len > mmap_end - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma_prev(mm, addr, &prev);
		if (mmap_end - len >= addr && addr >= mmap_min_addr &&
				(!vma || addr + len <= vm_start_gap(vma)) &&
				(!prev || addr >= vm_end_gap(prev)))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = arch_get_mmap_base(addr, mm->mmap_base);
	info.start_gap = stack_guard_placement(vma_flags);
	if (filp && is_file_hugepages(filp))
		info.align_mask = huge_page_mask_align(filp);
	addr = vm_unmapped_area(&info);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (offset_in_page(addr)) {
		VM_BUG_ON(addr != -ENOMEM);
		info.flags = 0;
		info.low_limit = TASK_UNMAPPED_BASE;
		info.high_limit = mmap_end;
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

#ifndef HAVE_ARCH_UNMAPPED_AREA_TOPDOWN
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			       unsigned long len, unsigned long pgoff,
			       unsigned long flags, vm_flags_t vm_flags)
{
	return generic_get_unmapped_area_topdown(filp, addr, len, pgoff, flags,
						 legacy_to_vma_flags(vm_flags));
}
#endif

unsigned long mm_get_unmapped_area_vmaflags(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags,
		vma_flags_t vma_flags)
{
	if (mm_flags_test(MMF_TOPDOWN, current->mm))
		return arch_get_unmapped_area_topdown(filp, addr, len, pgoff,
				flags, vma_flags_to_legacy(vma_flags));
	return arch_get_unmapped_area(filp, addr, len, pgoff, flags,
			vma_flags_to_legacy(vma_flags));
}

unsigned long
__get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags, vma_flags_t vma_flags)
{
	unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long)
				  = NULL;

	unsigned long error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	/* Careful about overflows.. */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (file) {
		if (file->f_op->get_unmapped_area)
			get_area = file->f_op->get_unmapped_area;
	} else if (flags & MAP_SHARED) {
		/*
		 * mmap_region() will call shmem_zero_setup() to create a file,
		 * so use shmem's get_unmapped_area in case it can be huge.
		 */
		get_area = shmem_get_unmapped_area;
	}

	/* Always treat pgoff as zero for anonymous memory. */
	if (!file)
		pgoff = 0;

	if (get_area) {
		addr = get_area(file, addr, len, pgoff, flags);
	} else if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) && !file
		   && !addr /* no hint */
		   && IS_ALIGNED(len, PMD_SIZE)) {
		/* Ensures that larger anonymous mappings are THP aligned. */
		addr = thp_get_unmapped_area_vmaflags(file, addr, len,
						      pgoff, flags, vma_flags);
	} else {
		addr = mm_get_unmapped_area_vmaflags(file, addr, len,
						     pgoff, flags, vma_flags);
	}
	if (IS_ERR_VALUE(addr))
		return addr;

	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (offset_in_page(addr))
		return -EINVAL;

	error = security_mmap_addr(addr);
	return error ? error : addr;
}

unsigned long
mm_get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		     unsigned long pgoff, unsigned long flags)
{
	return mm_get_unmapped_area_vmaflags(file, addr, len, pgoff, flags,
					     EMPTY_VMA_FLAGS);
}
EXPORT_SYMBOL(mm_get_unmapped_area);

/**
 * find_vma_intersection() - Look up the first VMA which intersects the interval
 * @mm: The process address space.
 * @start_addr: The inclusive start user address.
 * @end_addr: The exclusive end user address.
 *
 * Returns: The first VMA within the provided range, %NULL otherwise.  Assumes
 * start_addr < end_addr.
 */
struct vm_area_struct *find_vma_intersection(struct mm_struct *mm,
					     unsigned long start_addr,
					     unsigned long end_addr)
{
	unsigned long index = start_addr;

	mmap_assert_locked(mm);
	return mt_find(&mm->mm_mt, &index, end_addr - 1);
}
EXPORT_SYMBOL(find_vma_intersection);

/**
 * find_vma() - Find the VMA for a given address, or the next VMA.
 * @mm: The mm_struct to check
 * @addr: The address
 *
 * Returns: The VMA associated with addr, or the next VMA.
 * May return %NULL in the case of no VMA at addr or above.
 */
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
	unsigned long index = addr;

	mmap_assert_locked(mm);
	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
}
EXPORT_SYMBOL(find_vma);

#define FVP_HIT			0
#define FVP_NEXT		1

struct rust_fvp_state {
	struct mm_struct *mm;
	unsigned long addr;
	struct vm_area_struct **pprev;
	struct vma_iterator vmi;
	struct vm_area_struct *vma;
};

static int fvp_classify(struct rust_fvp_state *s)
{
	mmap_assert_locked(s->mm);
	vma_iter_init(&s->vmi, s->mm, s->addr);
	s->vma = vma_iter_load(&s->vmi);
	*s->pprev = vma_prev(&s->vmi);
	if (s->vma)
		return FVP_HIT;
	return FVP_NEXT;
}

static struct vm_area_struct *fvp_hit(struct rust_fvp_state *s)
{
	return s->vma;
}

static struct vm_area_struct *fvp_next(struct rust_fvp_state *s)
{
	return vma_next(&s->vmi);
}

static void fvp_abort(struct rust_fvp_state *s)
{
	(void)s;
}

#ifdef CONFIG_RUST_MMAP
int rust_fvp_classify(struct rust_fvp_state *s)
{
	return fvp_classify(s);
}

struct vm_area_struct *rust_fvp_hit(struct rust_fvp_state *s)
{
	return fvp_hit(s);
}

struct vm_area_struct *rust_fvp_next(struct rust_fvp_state *s)
{
	return fvp_next(s);
}

void rust_fvp_abort(struct rust_fvp_state *s)
{
	fvp_abort(s);
}
#endif

static struct vm_area_struct *finish_fvp(struct rust_fvp_state *s)
{
	if (fvp_classify(s) == FVP_HIT)
		return fvp_hit(s);
	return fvp_next(s);
}

/**
 * find_vma_prev() - Find the VMA for a given address, or the next vma and
 * set %pprev to the previous VMA, if any.
 * @mm: The mm_struct to check
 * @addr: The address
 * @pprev: The pointer to set to the previous VMA
 *
 * Note that RCU lock is missing here since the external mmap_lock() is used
 * instead.
 *
 * Returns: The VMA associated with @addr, or the next vma.
 * May return %NULL in the case of no vma at addr or above.
 */
struct vm_area_struct *
find_vma_prev(struct mm_struct *mm, unsigned long addr,
			struct vm_area_struct **pprev)
{
	struct rust_fvp_state s = {
		.mm = mm,
		.addr = addr,
		.pprev = pprev,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		struct vm_area_struct *rust_ret;

		rust_ret = rust_fvp_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_fvp(&s);
}

/* enforced gap between the expanding stack and other mappings. */
unsigned long stack_guard_gap = 256UL<<PAGE_SHIFT;

static int __init cmdline_parse_stack_guard_gap(char *p)
{
	unsigned long val;
	char *endptr;

	val = simple_strtoul(p, &endptr, 10);
	if (!*endptr)
		stack_guard_gap = val << PAGE_SHIFT;

	return 1;
}
__setup("stack_guard_gap=", cmdline_parse_stack_guard_gap);

#ifdef CONFIG_STACK_GROWSUP
int expand_stack_locked(struct vm_area_struct *vma, unsigned long address)
{
	return expand_upwards(vma, address);
}

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma, *prev;

	addr &= PAGE_MASK;
	vma = find_vma_prev(mm, addr, &prev);
	if (vma && (vma->vm_start <= addr))
		return vma;
	if (!prev)
		return NULL;
	if (expand_stack_locked(prev, addr))
		return NULL;
	if (vma_test(prev, VMA_LOCKED_BIT))
		populate_vma_page_range(prev, addr, prev->vm_end, NULL);
	return prev;
}
#else
int expand_stack_locked(struct vm_area_struct *vma, unsigned long address)
{
	return expand_downwards(vma, address);
}

struct vm_area_struct *find_extend_vma_locked(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;
	unsigned long start;

	addr &= PAGE_MASK;
	vma = find_vma(mm, addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	start = vma->vm_start;
	if (expand_stack_locked(vma, addr))
		return NULL;
	if (vma_test(vma, VMA_LOCKED_BIT))
		populate_vma_page_range(vma, addr, start, NULL);
	return vma;
}
#endif

#if defined(CONFIG_STACK_GROWSUP)

#define vma_expand_up(vma,addr) expand_upwards(vma, addr)
#define vma_expand_down(vma, addr) (-EFAULT)

#else

#define vma_expand_up(vma,addr) (-EFAULT)
#define vma_expand_down(vma, addr) expand_downwards(vma, addr)

#endif

/*
 * expand_stack(): legacy interface for page faulting. Don't use unless
 * you have to.
 *
 * This is called with the mm locked for reading, drops the lock, takes
 * the lock for writing, tries to look up a vma again, expands it if
 * necessary, and downgrades the lock to reading again.
 *
 * If no vma is found or it can't be expanded, it returns NULL and has
 * dropped the lock.
 */
#define ESTK_DONE		0
#define ESTK_DOWNGRADE		1

struct rust_estk_state {
	struct mm_struct *mm;
	unsigned long addr;
	struct vm_area_struct *vma;
	bool locked;
};

static int estk_classify(struct rust_estk_state *s)
{
	struct vm_area_struct *vma, *prev;

	s->vma = NULL;
	s->locked = false;

	mmap_read_unlock(s->mm);
	if (mmap_write_lock_killable(s->mm))
		return ESTK_DONE;
	s->locked = true;

	vma = find_vma_prev(s->mm, s->addr, &prev);
	if (vma && vma->vm_start <= s->addr) {
		s->vma = vma;
		return ESTK_DOWNGRADE;
	}

	if (prev && !vma_expand_up(prev, s->addr)) {
		s->vma = prev;
		return ESTK_DOWNGRADE;
	}

	if (vma && !vma_expand_down(vma, s->addr)) {
		s->vma = vma;
		return ESTK_DOWNGRADE;
	}

	mmap_write_unlock(s->mm);
	s->locked = false;
	return ESTK_DONE;
}

static struct vm_area_struct *estk_downgrade(struct rust_estk_state *s)
{
	mmap_write_downgrade(s->mm);
	s->locked = false;
	return s->vma;
}

static void estk_abort(struct rust_estk_state *s)
{
	if (s->locked)
		mmap_write_unlock(s->mm);
	s->locked = false;
}

#ifdef CONFIG_RUST_MMAP
int rust_estk_classify(struct rust_estk_state *s)
{
	return estk_classify(s);
}

struct vm_area_struct *rust_estk_downgrade(struct rust_estk_state *s)
{
	return estk_downgrade(s);
}

void rust_estk_abort(struct rust_estk_state *s)
{
	estk_abort(s);
}
#endif

static struct vm_area_struct *finish_estk(struct rust_estk_state *s)
{
	if (estk_classify(s) == ESTK_DOWNGRADE)
		return estk_downgrade(s);
	return NULL;
}

struct vm_area_struct *expand_stack(struct mm_struct *mm, unsigned long addr)
{
	struct rust_estk_state s = {
		.mm = mm,
		.addr = addr,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	struct vm_area_struct *rust_ret;

	rust_ret = rust_estk_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_estk(&s);
}

#define DMUNMAP_APPLY		0

struct rust_dmunmap_state {
	struct mm_struct *mm;
	unsigned long start;
	size_t len;
	struct list_head *uf;
	struct vma_iterator vmi;
};

static int dmunmap_classify(struct rust_dmunmap_state *s)
{
	vma_iter_init(&s->vmi, s->mm, s->start);
	return DMUNMAP_APPLY;
}

static int dmunmap_apply(struct rust_dmunmap_state *s)
{
	return do_vmi_munmap(&s->vmi, s->mm, s->start, s->len, s->uf, false);
}

static void dmunmap_abort(struct rust_dmunmap_state *s)
{
	(void)s;
}

#ifdef CONFIG_RUST_MMAP
int rust_dmunmap_classify(struct rust_dmunmap_state *s)
{
	return dmunmap_classify(s);
}

int rust_dmunmap_apply(struct rust_dmunmap_state *s)
{
	return dmunmap_apply(s);
}

void rust_dmunmap_abort(struct rust_dmunmap_state *s)
{
	dmunmap_abort(s);
}
#endif

static int finish_dmunmap(struct rust_dmunmap_state *s)
{
	dmunmap_classify(s);
	return dmunmap_apply(s);
}

/**
 * do_munmap() - Wrapper around do_vmi_munmap() with a VMA iterator.
 * @mm: The mm_struct to check
 * @start: The start address to munmap
 * @len: The length to be munmapped.
 * @uf: The userfaultfd list_head
 *
 * Return: 0 on success, error otherwise.
 */
int do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
	      struct list_head *uf)
{
	struct rust_dmunmap_state s = {
		.mm = mm,
		.start = start,
		.len = len,
		.uf = uf,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		int rust_ret;

		rust_ret = rust_dmunmap_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_dmunmap(&s);
}

int vm_munmap(unsigned long start, size_t len)
{
	return __vm_munmap(start, len, false);
}
EXPORT_SYMBOL(vm_munmap);

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	addr = untagged_addr(addr);
	return __vm_munmap(addr, len, true);
}


/*
 * Emulation of deprecated remap_file_pages() syscall.
 */
#define RFP_DONE		0
#define RFP_SEC			1
#define RFP_APPLY		2

struct rust_rfp_state {
	unsigned long start;
	unsigned long size;
	unsigned long prot;
	unsigned long pgoff;
	unsigned long flags;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct file *file;
	vm_flags_t vm_flags;
	unsigned long populate;
	bool write_locked;
};

static int rfp_classify(struct rust_rfp_state *s, long *out)
{
	*out = -EINVAL;
	s->mm = current->mm;
	s->vma = NULL;
	s->file = NULL;
	s->populate = 0;
	s->write_locked = false;

	if (s->prot)
		return RFP_DONE;
	s->start &= PAGE_MASK;
	s->size &= PAGE_MASK;

	if (s->start + s->size <= s->start)
		return RFP_DONE;

	/* Does pgoff wrap? */
	if (s->pgoff + (s->size >> PAGE_SHIFT) < s->pgoff)
		return RFP_DONE;

	if (mmap_read_lock_killable(s->mm)) {
		*out = -EINTR;
		return RFP_DONE;
	}

	/*
	 * Look up VMA under read lock first so we can perform the security
	 * without holding locks (which can be problematic). We reacquire a
	 * write lock later and check nothing changed underneath us.
	 */
	s->vma = vma_lookup(s->mm, s->start);

	if (!s->vma || !vma_test(s->vma, VMA_SHARED_BIT)) {
		mmap_read_unlock(s->mm);
		return RFP_DONE;
	}

	s->prot |= vma_test(s->vma, VMA_READ_BIT) ? PROT_READ : 0;
	s->prot |= vma_test(s->vma, VMA_WRITE_BIT) ? PROT_WRITE : 0;
	s->prot |= vma_test(s->vma, VMA_EXEC_BIT) ? PROT_EXEC : 0;

	s->flags &= MAP_NONBLOCK;
	s->flags |= MAP_SHARED | MAP_FIXED | MAP_POPULATE;
	if (vma_test(s->vma, VMA_LOCKED_BIT))
		s->flags |= MAP_LOCKED;

	/* Save vm_flags used to calculate prot and flags, and recheck later. */
	s->vm_flags = s->vma->vm_flags;
	s->file = get_file(s->vma->vm_file);

	mmap_read_unlock(s->mm);
	*out = 0;
	return RFP_SEC;
}

static int rfp_security(struct rust_rfp_state *s, long *out)
{
	long ret;

	/* Call outside mmap_lock to be consistent with other callers. */
	ret = security_mmap_file(s->file, s->prot, s->flags);
	if (ret) {
		fput(s->file);
		s->file = NULL;
		*out = ret;
		return RFP_DONE;
	}
	return RFP_APPLY;
}

static long rfp_apply(struct rust_rfp_state *s)
{
	struct mm_struct *mm = s->mm;
	struct vm_area_struct *vma;
	unsigned long start = s->start;
	unsigned long size = s->size;
	unsigned long ret = -EINVAL;

	/* OK security check passed, take write lock + let it rip. */
	if (mmap_write_lock_killable(mm)) {
		fput(s->file);
		s->file = NULL;
		return -EINTR;
	}
	s->write_locked = true;

	vma = vma_lookup(mm, start);

	if (!vma)
		goto out;

	/* Make sure things didn't change under us. */
	if (vma->vm_flags != s->vm_flags)
		goto out;
	if (vma->vm_file != s->file)
		goto out;

	if (start + size > vma->vm_end) {
		VMA_ITERATOR(vmi, mm, vma->vm_end);
		struct vm_area_struct *next, *prev = vma;

		for_each_vma_range(vmi, next, start + size) {
			/* hole between vmas ? */
			if (next->vm_start != prev->vm_end)
				goto out;

			if (next->vm_file != vma->vm_file)
				goto out;

			if (next->vm_flags != vma->vm_flags)
				goto out;

			if (start + size <= next->vm_end)
				break;

			prev = next;
		}

		if (!next)
			goto out;
	}

	ret = do_mmap(vma->vm_file, start, size,
			s->prot, s->flags, EMPTY_VMA_FLAGS, s->pgoff,
			&s->populate, NULL);
out:
	mmap_write_unlock(mm);
	s->write_locked = false;
	fput(s->file);
	s->file = NULL;
	if (s->populate)
		mm_populate(ret, s->populate);
	if (!IS_ERR_VALUE(ret))
		ret = 0;
	return ret;
}

static void rfp_abort(struct rust_rfp_state *s)
{
	if (s->write_locked) {
		mmap_write_unlock(s->mm);
		s->write_locked = false;
	}
	if (s->file) {
		fput(s->file);
		s->file = NULL;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_rfp_classify(struct rust_rfp_state *s, long *out)
{
	return rfp_classify(s, out);
}

int rust_rfp_security(struct rust_rfp_state *s, long *out)
{
	return rfp_security(s, out);
}

long rust_rfp_apply(struct rust_rfp_state *s)
{
	return rfp_apply(s);
}

void rust_rfp_abort(struct rust_rfp_state *s)
{
	rfp_abort(s);
}
#endif

static long finish_rfp(struct rust_rfp_state *s)
{
	long out = 0;
	int kind;

	kind = rfp_classify(s, &out);
	if (kind == RFP_DONE)
		return out;
	kind = rfp_security(s, &out);
	if (kind == RFP_DONE)
		return out;
	return rfp_apply(s);
}

SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
		unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
{
	struct rust_rfp_state s = {
		.start = start,
		.size = size,
		.prot = prot,
		.pgoff = pgoff,
		.flags = flags,
	};

	pr_warn_once("%s (%d) uses deprecated remap_file_pages() syscall. See Documentation/mm/remap_file_pages.rst.\n",
		     current->comm, current->pid);

#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;
		long rust_ret;

		rust_ret = rust_rfp_dispatch(&s, &handled);
		if (handled)
			return rust_ret;
	}
#endif
	return finish_rfp(&s);
}

#define VMBRK_DONE		0
#define VMBRK_EXIT		1

struct rust_vmbrk_state {
	unsigned long addr;
	unsigned long request;
	bool is_exec;
	vma_flags_t vma_flags;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long len;
	int ret;
	bool populate;
	bool locked;
	struct vma_iterator vmi;
	struct list_head uf;
};

static int vmbrk_classify(struct rust_vmbrk_state *s, int *out)
{
	int ret;

	s->mm = current->mm;
	s->vma = NULL;
	s->populate = false;
	s->locked = false;
	s->ret = 0;
	INIT_LIST_HEAD(&s->uf);
	s->vma_flags = s->is_exec ?
		mk_vma_flags(VMA_EXEC_BIT) : EMPTY_VMA_FLAGS;
	*out = 0;

	s->len = PAGE_ALIGN(s->request);
	if (s->len < s->request) {
		*out = -ENOMEM;
		return VMBRK_DONE;
	}
	if (!s->len)
		return VMBRK_DONE;

	if (mmap_write_lock_killable(s->mm)) {
		*out = -EINTR;
		return VMBRK_DONE;
	}
	s->locked = true;
	vma_iter_init(&s->vmi, s->mm, s->addr);

	ret = check_brk_limits(s->addr, s->len);
	if (ret)
		goto fail;

	ret = do_vmi_munmap(&s->vmi, s->mm, s->addr, s->len, &s->uf, 0);
	if (ret)
		goto fail;

	s->vma = vma_prev(&s->vmi);
	s->ret = do_brk_flags(&s->vmi, s->vma, s->addr, s->len, s->vma_flags);
	s->populate = vma_flags_test(&s->mm->def_vma_flags, VMA_LOCKED_BIT);
	mmap_write_unlock(s->mm);
	s->locked = false;
	*out = s->ret;
	return VMBRK_EXIT;

fail:
	mmap_write_unlock(s->mm);
	s->locked = false;
	*out = ret;
	return VMBRK_DONE;
}

static int vmbrk_exit(struct rust_vmbrk_state *s)
{
	userfaultfd_unmap_complete(s->mm, &s->uf);
	if (s->populate && !s->ret)
		mm_populate(s->addr, s->len);
	return s->ret;
}

static void vmbrk_abort(struct rust_vmbrk_state *s)
{
	if (s->locked) {
		mmap_write_unlock(s->mm);
		s->locked = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_vmbrk_classify(struct rust_vmbrk_state *s, int *out)
{
	return vmbrk_classify(s, out);
}

int rust_vmbrk_exit(struct rust_vmbrk_state *s)
{
	return vmbrk_exit(s);
}

void rust_vmbrk_abort(struct rust_vmbrk_state *s)
{
	vmbrk_abort(s);
}
#endif

static int finish_vmbrk(struct rust_vmbrk_state *s)
{
	int out = 0;

	if (vmbrk_classify(s, &out) == VMBRK_EXIT)
		return vmbrk_exit(s);
	return out;
}

int vm_brk_flags(unsigned long addr, unsigned long request, bool is_exec)
{
	struct rust_vmbrk_state s = {
		.addr = addr,
		.request = request,
		.is_exec = is_exec,
	};
#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_vmbrk_dispatch(&s, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_vmbrk(&s);
}

static
unsigned long tear_down_vmas(struct mm_struct *mm, struct vma_iterator *vmi,
		struct vm_area_struct *vma, unsigned long end)
{
	unsigned long nr_accounted = 0;
	int count = 0;

	mmap_assert_write_locked(mm);
	vma_iter_set(vmi, vma->vm_end);
	do {
		if (vma_test(vma, VMA_ACCOUNT_BIT))
			nr_accounted += vma_pages(vma);
		vma_mark_detached(vma);
		remove_vma(vma);
		count++;
		cond_resched();
		vma = vma_next(vmi);
	} while (vma && vma->vm_end <= end);

	VM_WARN_ON_ONCE(count != mm->map_count);
	return nr_accounted;
}

#define EMMAP_EMPTY		0
#define EMMAP_UNMAP		1

struct rust_emmap_state {
	struct mm_struct *mm;
	struct mmu_gather tlb;
	struct vm_area_struct *vma;
	unsigned long nr_accounted;
	struct vma_iterator vmi;
	struct unmap_desc unmap;
	bool read_locked;
	bool write_locked;
	bool tlb_gathered;
};

static int emmap_classify(struct rust_emmap_state *s)
{
	struct vm_area_struct *vma;

	s->nr_accounted = 0;
	s->vma = NULL;
	s->read_locked = false;
	s->write_locked = false;
	s->tlb_gathered = false;

	/* mm's last user has gone, and its about to be pulled down */
	mmu_notifier_release(s->mm);

	mmap_read_lock(s->mm);
	s->read_locked = true;
	arch_exit_mmap(s->mm);

	vma_iter_init(&s->vmi, s->mm, 0);
	vma = vma_next(&s->vmi);
	if (!vma) {
		/* Can happen if dup_mmap() received an OOM */
		mmap_read_unlock(s->mm);
		s->read_locked = false;
		mmap_write_lock(s->mm);
		s->write_locked = true;
		return EMMAP_EMPTY;
	}
	s->vma = vma;
	return EMMAP_UNMAP;
}

static void emmap_destroy(struct rust_emmap_state *s)
{
	__mt_destroy(&s->mm->mm_mt);
	trace_exit_mmap(s->mm);
	mmap_write_unlock(s->mm);
	s->write_locked = false;
	vm_unacct_memory(s->nr_accounted);
}

static void emmap_empty(struct rust_emmap_state *s)
{
	emmap_destroy(s);
}

static void emmap_unmap(struct rust_emmap_state *s)
{
	unmap_all_init(&s->unmap, &s->vmi, s->vma);
	flush_cache_mm(s->mm);
	tlb_gather_mmu_fullmm(&s->tlb, s->mm);
	s->tlb_gathered = true;
	/* update_hiwater_rss(mm) here? but nobody should be looking */
	/* Use ULONG_MAX here to ensure all VMAs in the mm are unmapped */
	unmap_vmas(&s->tlb, &s->unmap);
	mmap_read_unlock(s->mm);
	s->read_locked = false;

	/*
	 * Set MMF_OOM_SKIP to hide this task from the oom killer/reaper
	 * because the memory has been already freed.
	 */
	mm_flags_set(MMF_OOM_SKIP, s->mm);
	mmap_write_lock(s->mm);
	s->write_locked = true;
	s->unmap.mm_wr_locked = true;
	mt_clear_in_rcu(&s->mm->mm_mt);
	unmap_pgtable_init(&s->unmap, &s->vmi);
	free_pgtables(&s->tlb, &s->unmap);
	tlb_finish_mmu(&s->tlb);
	s->tlb_gathered = false;

	/*
	 * Walk the list again, actually closing and freeing it, with preemption
	 * enabled, without holding any MM locks besides the unreachable
	 * mmap_write_lock.
	 */
	s->nr_accounted = tear_down_vmas(s->mm, &s->vmi, s->vma, ULONG_MAX);
	emmap_destroy(s);
}

static void emmap_abort(struct rust_emmap_state *s)
{
	if (s->tlb_gathered) {
		tlb_finish_mmu(&s->tlb);
		s->tlb_gathered = false;
	}
	if (s->read_locked) {
		mmap_read_unlock(s->mm);
		s->read_locked = false;
	}
	if (s->write_locked) {
		mmap_write_unlock(s->mm);
		s->write_locked = false;
	}
}

#ifdef CONFIG_RUST_MMAP
int rust_emmap_classify(struct rust_emmap_state *s)
{
	return emmap_classify(s);
}

void rust_emmap_empty(struct rust_emmap_state *s)
{
	emmap_empty(s);
}

void rust_emmap_unmap(struct rust_emmap_state *s)
{
	emmap_unmap(s);
}

void rust_emmap_abort(struct rust_emmap_state *s)
{
	emmap_abort(s);
}
#endif

static void finish_emmap(struct rust_emmap_state *s)
{
	if (emmap_classify(s) == EMMAP_EMPTY)
		emmap_empty(s);
	else
		emmap_unmap(s);
}

/* Release all mmaps. */
void exit_mmap(struct mm_struct *mm)
{
	struct rust_emmap_state s = {
		.mm = mm,
	};
#ifdef CONFIG_RUST_MMAP
	{
		int handled = 0;

		rust_emmap_dispatch(&s, &handled);
		if (handled)
			return;
	}
#endif
	finish_emmap(&s);
}

/*
 * Return true if the calling process may expand its vm space by the passed
 * number of pages
 */
bool may_expand_vm(struct mm_struct *mm, const vma_flags_t *vma_flags,
		   unsigned long npages)
{
	if (mm->total_vm + npages > rlimit(RLIMIT_AS) >> PAGE_SHIFT)
		return false;

	if (is_data_mapping_vma_flags(vma_flags) &&
	    mm->data_vm + npages > rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
		/* Workaround for Valgrind */
		if (rlimit(RLIMIT_DATA) == 0 &&
		    mm->data_vm + npages <= rlimit_max(RLIMIT_DATA) >> PAGE_SHIFT)
			return true;

		pr_warn_once("%s (%d): VmData %lu exceed data ulimit %lu. Update limits%s.\n",
			     current->comm, current->pid,
			     (mm->data_vm + npages) << PAGE_SHIFT,
			     rlimit(RLIMIT_DATA),
			     ignore_rlimit_data ? "" : " or use boot option ignore_rlimit_data");

		if (!ignore_rlimit_data)
			return false;
	}

	return true;
}

void vm_stat_account(struct mm_struct *mm, vm_flags_t flags, long npages)
{
	WRITE_ONCE(mm->total_vm, READ_ONCE(mm->total_vm)+npages);

	if (is_exec_mapping(flags))
		mm->exec_vm += npages;
	else if (is_stack_mapping(flags))
		mm->stack_vm += npages;
	else if (is_data_mapping(flags))
		mm->data_vm += npages;
}

static vm_fault_t special_mapping_fault(struct vm_fault *vmf);

/*
 * Close hook, called for unmap() and on the old vma for mremap().
 *
 * Having a close hook prevents vma merging regardless of flags.
 */
static void special_mapping_close(struct vm_area_struct *vma)
{
	const struct vm_special_mapping *sm = vma->vm_private_data;

	if (sm->close)
		sm->close(sm, vma);
}

static const char *special_mapping_name(struct vm_area_struct *vma)
{
	return ((struct vm_special_mapping *)vma->vm_private_data)->name;
}

static int special_mapping_mremap(struct vm_area_struct *new_vma)
{
	struct vm_special_mapping *sm = new_vma->vm_private_data;

	if (WARN_ON_ONCE(current->mm != new_vma->vm_mm))
		return -EFAULT;

	if (sm->mremap)
		return sm->mremap(sm, new_vma);

	return 0;
}

static int special_mapping_split(struct vm_area_struct *vma, unsigned long addr)
{
	/*
	 * Forbid splitting special mappings - kernel has expectations over
	 * the number of pages in mapping. Together with VMA_DONTEXPAND_BIT
	 * the size of vma should stay the same over the special mapping's
	 * lifetime.
	 */
	return -EINVAL;
}

static const struct vm_operations_struct special_mapping_vmops = {
	.close = special_mapping_close,
	.fault = special_mapping_fault,
	.mremap = special_mapping_mremap,
	.name = special_mapping_name,
	/* vDSO code relies that VVAR can't be accessed remotely */
	.access = NULL,
	.may_split = special_mapping_split,
};

static vm_fault_t special_mapping_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	pgoff_t pgoff;
	struct page **pages;
	struct vm_special_mapping *sm = vma->vm_private_data;

	if (sm->fault)
		return sm->fault(sm, vmf->vma, vmf);

	pages = sm->pages;

	for (pgoff = vmf->pgoff; pgoff && *pages; ++pages)
		pgoff--;

	if (*pages) {
		struct page *page = *pages;
		get_page(page);
		vmf->page = page;
		return 0;
	}

	return VM_FAULT_SIGBUS;
}

bool vma_is_special_mapping(const struct vm_area_struct *vma,
	const struct vm_special_mapping *sm)
{
	return vma->vm_private_data == sm &&
		vma->vm_ops == &special_mapping_vmops;
}

/*
 * Called with mm->mmap_lock held for writing.
 * Insert a new vma covering the given region, with the given flags.
 * Its pages are supplied by the given array of struct page *.
 * The array can be shorter than len >> PAGE_SHIFT if it's null-terminated.
 * The region past the last page supplied will always produce SIGBUS.
 * The array pointer and the pages it points to are assumed to stay alive
 * for as long as this mapping might exist.
 */
struct vm_area_struct *_install_special_mapping(
	struct mm_struct *mm,
	unsigned long addr, unsigned long len,
	vm_flags_t vm_flags, const struct vm_special_mapping *spec)
{
	return __install_special_mapping(mm, addr, len, vm_flags, (void *)spec,
					&special_mapping_vmops);
}

#ifdef CONFIG_SYSCTL
#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
		defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
int sysctl_legacy_va_layout;
#endif

static const struct ctl_table mmap_table[] = {
		{
				.procname       = "max_map_count",
				.data           = &sysctl_max_map_count,
				.maxlen         = sizeof(sysctl_max_map_count),
				.mode           = 0644,
				.proc_handler   = proc_dointvec_minmax,
				.extra1         = SYSCTL_ZERO,
		},
#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
		defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
		{
				.procname       = "legacy_va_layout",
				.data           = &sysctl_legacy_va_layout,
				.maxlen         = sizeof(sysctl_legacy_va_layout),
				.mode           = 0644,
				.proc_handler   = proc_dointvec_minmax,
				.extra1         = SYSCTL_ZERO,
		},
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
		{
				.procname       = "mmap_rnd_bits",
				.data           = &mmap_rnd_bits,
				.maxlen         = sizeof(mmap_rnd_bits),
				.mode           = 0600,
				.proc_handler   = proc_dointvec_minmax,
				.extra1         = (void *)&mmap_rnd_bits_min,
				.extra2         = (void *)&mmap_rnd_bits_max,
		},
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
		{
				.procname       = "mmap_rnd_compat_bits",
				.data           = &mmap_rnd_compat_bits,
				.maxlen         = sizeof(mmap_rnd_compat_bits),
				.mode           = 0600,
				.proc_handler   = proc_dointvec_minmax,
				.extra1         = (void *)&mmap_rnd_compat_bits_min,
				.extra2         = (void *)&mmap_rnd_compat_bits_max,
		},
#endif
};
#endif /* CONFIG_SYSCTL */

/*
 * initialise the percpu counter for VM, initialise VMA state.
 */
void __init mmap_init(void)
{
	int ret;

	ret = percpu_counter_init(&vm_committed_as, 0, GFP_KERNEL);
	VM_BUG_ON(ret);
#ifdef CONFIG_SYSCTL
	register_sysctl_init("vm", mmap_table);
#endif
	vma_state_init();
}

/*
 * Initialise sysctl_user_reserve_kbytes.
 *
 * This is intended to prevent a user from starting a single memory hogging
 * process, such that they cannot recover (kill the hog) in OVERCOMMIT_NEVER
 * mode.
 *
 * The default value is min(3% of free memory, 128MB)
 * 128MB is enough to recover with sshd/login, bash, and top/kill.
 */
static int init_user_reserve(void)
{
	unsigned long free_kbytes;

	free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

	sysctl_user_reserve_kbytes = min(free_kbytes / 32, SZ_128K);
	return 0;
}
subsys_initcall(init_user_reserve);

/*
 * Initialise sysctl_admin_reserve_kbytes.
 *
 * The purpose of sysctl_admin_reserve_kbytes is to allow the sys admin
 * to log in and kill a memory hogging process.
 *
 * Systems with more than 256MB will reserve 8MB, enough to recover
 * with sshd, bash, and top in OVERCOMMIT_GUESS. Smaller systems will
 * only reserve 3% of free pages by default.
 */
static int init_admin_reserve(void)
{
	unsigned long free_kbytes;

	free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

	sysctl_admin_reserve_kbytes = min(free_kbytes / 32, SZ_8K);
	return 0;
}
subsys_initcall(init_admin_reserve);

/*
 * Reinititalise user and admin reserves if memory is added or removed.
 *
 * The default user reserve max is 128MB, and the default max for the
 * admin reserve is 8MB. These are usually, but not always, enough to
 * enable recovery from a memory hogging process using login/sshd, a shell,
 * and tools like top. It may make sense to increase or even disable the
 * reserve depending on the existence of swap or variations in the recovery
 * tools. So, the admin may have changed them.
 *
 * If memory is added and the reserves have been eliminated or increased above
 * the default max, then we'll trust the admin.
 *
 * If memory is removed and there isn't enough free memory, then we
 * need to reset the reserves.
 *
 * Otherwise keep the reserve set by the admin.
 */
static int reserve_mem_notifier(struct notifier_block *nb,
			     unsigned long action, void *data)
{
	unsigned long tmp, free_kbytes;

	switch (action) {
	case MEM_ONLINE:
		/* Default max is 128MB. Leave alone if modified by operator. */
		tmp = sysctl_user_reserve_kbytes;
		if (tmp > 0 && tmp < SZ_128K)
			init_user_reserve();

		/* Default max is 8MB.  Leave alone if modified by operator. */
		tmp = sysctl_admin_reserve_kbytes;
		if (tmp > 0 && tmp < SZ_8K)
			init_admin_reserve();

		break;
	case MEM_OFFLINE:
		free_kbytes = K(global_zone_page_state(NR_FREE_PAGES));

		if (sysctl_user_reserve_kbytes > free_kbytes) {
			init_user_reserve();
			pr_info("vm.user_reserve_kbytes reset to %lu\n",
				sysctl_user_reserve_kbytes);
		}

		if (sysctl_admin_reserve_kbytes > free_kbytes) {
			init_admin_reserve();
			pr_info("vm.admin_reserve_kbytes reset to %lu\n",
				sysctl_admin_reserve_kbytes);
		}
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int __meminit init_reserve_notifier(void)
{
	if (hotplug_memory_notifier(reserve_mem_notifier, DEFAULT_CALLBACK_PRI))
		pr_err("Failed registering memory add/remove notifier for admin reserve\n");

	return 0;
}
subsys_initcall(init_reserve_notifier);

/*
 * Obtain a read lock on mm->mmap_lock, if the specified address is below the
 * start of the VMA, the intent is to perform a write, and it is a
 * downward-growing stack, then attempt to expand the stack to contain it.
 *
 * This function is intended only for obtaining an argument page from an ELF
 * image, and is almost certainly NOT what you want to use for any other
 * purpose.
 *
 * IMPORTANT - VMA fields are accessed without an mmap lock being held, so the
 * VMA referenced must not be linked in any user-visible tree, i.e. it must be a
 * new VMA being mapped.
 *
 * The function assumes that addr is either contained within the VMA or below
 * it, and makes no attempt to validate this value beyond that.
 *
 * Returns true if the read lock was obtained and a stack was perhaps expanded,
 * false if the stack expansion failed.
 *
 * On stack expansion the function temporarily acquires an mmap write lock
 * before downgrading it.
 */
bool mmap_read_lock_maybe_expand(struct mm_struct *mm,
				 struct vm_area_struct *new_vma,
				 unsigned long addr, bool write)
{
	if (!write || addr >= new_vma->vm_start) {
		mmap_read_lock(mm);
		return true;
	}

	if (!vma_test(new_vma, VMA_GROWSDOWN_BIT))
		return false;

	mmap_write_lock(mm);
	if (expand_downwards(new_vma, addr)) {
		mmap_write_unlock(mm);
		return false;
	}

	mmap_write_downgrade(mm);
	return true;
}

__latent_entropy int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp;
	int retval;
	unsigned long charge = 0;
	LIST_HEAD(uf);
	VMA_ITERATOR(vmi, mm, 0);

	if (mmap_write_lock_killable(oldmm))
		return -EINTR;
	flush_cache_dup_mm(oldmm);
	uprobe_dup_mmap(oldmm, mm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	mmap_write_lock_nested(mm, SINGLE_DEPTH_NESTING);

	/* No ordering required: file already has been exposed. */
	dup_mm_exe_file(mm, oldmm);

	mm->total_vm = oldmm->total_vm;
	mm->data_vm = oldmm->data_vm;
	mm->exec_vm = oldmm->exec_vm;
	mm->stack_vm = oldmm->stack_vm;

	/* Use __mt_dup() to efficiently build an identical maple tree. */
	retval = __mt_dup(&oldmm->mm_mt, &mm->mm_mt, GFP_KERNEL);
	if (unlikely(retval))
		goto out;

	mt_clear_in_rcu(vmi.mas.tree);
	for_each_vma(vmi, mpnt) {
		struct file *file;

		retval = vma_start_write_killable(mpnt);
		if (retval < 0)
			goto loop_out;
		if (vma_test(mpnt, VMA_DONTCOPY_BIT)) {
			retval = vma_iter_clear_gfp(&vmi, mpnt->vm_start,
						    mpnt->vm_end, GFP_KERNEL);
			if (retval)
				goto loop_out;

			vm_stat_account(mm, mpnt->vm_flags, -vma_pages(mpnt));
			continue;
		}
		charge = 0;
		if (vma_test(mpnt, VMA_ACCOUNT_BIT)) {
			unsigned long len = vma_pages(mpnt);

			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */
				goto fail_nomem;
			charge = len;
		}

		tmp = vm_area_dup(mpnt);
		if (!tmp)
			goto fail_nomem;
		retval = vma_dup_policy(mpnt, tmp);
		if (retval)
			goto fail_nomem_policy;
		tmp->vm_mm = mm;
		retval = dup_userfaultfd(tmp, &uf);
		if (retval)
			goto fail_nomem_anon_vma_fork;

		if (vma_test(tmp, VMA_WIPEONFORK_BIT)) {
			/*
			 * VMA_WIPEONFORK_BIT gets a clean slate in the child.
			 * Don't prepare anon_vma until fault since we don't
			 * copy page for current vma.
			 */
			tmp->anon_vma = NULL;
		} else if (anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;

		vma_start_write(tmp);
		vma_clear_flags_mask(tmp, VMA_LOCKED_MASK);
		/*
		 * Copy/update hugetlb private vma information.
		 */
		if (is_vm_hugetlb_page(tmp))
			hugetlb_dup_vma_private(tmp);

		/*
		 * Link the vma into the MT. After using __mt_dup(), memory
		 * allocation is not necessary here, so it cannot fail.
		 */
		vma_iter_bulk_store(&vmi, tmp);

		mm->map_count++;

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		file = tmp->vm_file;
		if (file) {
			struct address_space *mapping = file->f_mapping;

			get_file(file);
			i_mmap_lock_write(mapping);
			if (vma_is_shared_maywrite(tmp))
				mapping_allow_writable(mapping);
			flush_dcache_mmap_lock(mapping);
			/* insert tmp into the share list, just after mpnt */
			mapping_rmap_tree_insert_after(tmp, mpnt, mapping);
			flush_dcache_mmap_unlock(mapping);
			i_mmap_unlock_write(mapping);
		}

		if (!vma_test(tmp, VMA_WIPEONFORK_BIT))
			retval = copy_page_range(tmp, mpnt);

		if (retval) {
			mpnt = vma_next(&vmi);
			goto loop_out;
		}
	}
	/* a new mm has just been created */
	retval = arch_dup_mmap(oldmm, mm);
loop_out:
	vma_iter_free(&vmi);
	if (!retval) {
		mt_set_in_rcu(vmi.mas.tree);
		ksm_fork(mm, oldmm);
		khugepaged_fork(mm, oldmm);
	} else {
		unsigned long end;

		/*
		 * The entire maple tree has already been duplicated, but
		 * replacing the vmas failed at mpnt (which could be NULL if
		 * all were allocated but the last vma was not fully set up).
		 * Use the start address of the failure point to clean up the
		 * partially initialized tree.
		 */
		if (!mm->map_count) {
			/* zero vmas were written to the new tree. */
			end = 0;
		} else if (mpnt) {
			/* partial tree failure */
			end = mpnt->vm_start;
		} else {
			/* All vmas were written to the new tree */
			end = ULONG_MAX;
		}

		/* Hide mm from oom killer because the memory is being freed */
		mm_flags_set(MMF_OOM_SKIP, mm);
		if (end) {
			vma_iter_set(&vmi, 0);
			tmp = vma_next(&vmi);
			UNMAP_STATE(unmap, &vmi, /* first = */ tmp,
				    /* vma_start = */ 0, /* vma_end = */ end,
				    /* prev = */ NULL, /* next = */ NULL);

			/*
			 * Don't iterate over vmas beyond the failure point for
			 * both unmap_vma() and free_pgtables().
			 */
			unmap.tree_end = end;
			flush_cache_mm(mm);
			unmap_region(&unmap);
			charge = tear_down_vmas(mm, &vmi, tmp, end);
			vm_unacct_memory(charge);
		}
		__mt_destroy(&mm->mm_mt);
		/*
		 * The mm_struct is going to exit, but the locks will be dropped
		 * first.  Set the mm_struct as unstable is advisable as it is
		 * not fully initialised.
		 */
		mm_flags_set(MMF_UNSTABLE, mm);
	}
out:
	mmap_write_unlock(mm);
	flush_tlb_mm(oldmm);
	mmap_write_unlock(oldmm);
	if (!retval)
		dup_userfaultfd_complete(&uf);
	else
		dup_userfaultfd_fail(&uf);
	return retval;

fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	vm_area_free(tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto loop_out;
}
