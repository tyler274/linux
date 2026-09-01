// SPDX-License-Identifier: GPL-2.0
/*
 *	linux/mm/msync.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * The msync() system call.
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/sched.h>

/*
 * MS_SYNC syncs the entire file - including mappings.
 *
 * MS_ASYNC does not start I/O (it used to, up to 2.5.67).
 * Nor does it marks the relevant pages dirty (it used to up to 2.6.17).
 * Now it doesn't do anything, since dirty pages are properly tracked.
 *
 * The application may now run fsync() to
 * write out the dirty pages and wait on the writeout and check the result.
 * Or the application may run fadvise(FADV_DONTNEED) against the fd to start
 * async writeout immediately.
 * So by _not_ starting I/O in MS_ASYNC we provide complete flexibility to
 * applications.
 */
#define MSYNC_DONE		0
#define MSYNC_APPLY		1

#ifndef CONFIG_RUST_MMAP
struct rust_msync_req {
	unsigned long start;
	size_t len;
	int flags;
	unsigned long end;
};
#endif

static int msync_validate(struct rust_msync_req *req, int *out)
{
	unsigned long start;
	size_t len;
	unsigned long end;
	int flags = req->flags;

	*out = -EINVAL;
	start = untagged_addr(req->start);
	if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC))
		return MSYNC_DONE;
	if (offset_in_page(start))
		return MSYNC_DONE;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		return MSYNC_DONE;

	*out = -ENOMEM;
	len = (req->len + ~PAGE_MASK) & PAGE_MASK;
	end = start + len;
	if (end < start)
		return MSYNC_DONE;

	*out = 0;
	if (end == start)
		return MSYNC_DONE;

	req->start = start;
	req->len = len;
	req->end = end;
	return MSYNC_APPLY;
}

static int msync_apply(struct rust_msync_req *req)
{
	unsigned long start = req->start;
	unsigned long end = req->end;
	int flags = req->flags;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int unmapped_error = 0;
	int error = 0;

	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end. Besides, if the
	 * flag is MS_ASYNC (w/o MS_INVALIDATE) the result would be -ENOMEM
	 * anyway and there is nothing left to do, so return immediately.
	 */
	mmap_read_lock(mm);
	vma = find_vma(mm, start);
	for (;;) {
		struct file *file;
		loff_t fstart, fend;

		/* Still start < end. */
		error = -ENOMEM;
		if (!vma)
			goto out_unlock;
		/* Here start < vma->vm_end. */
		if (start < vma->vm_start) {
			if (flags == MS_ASYNC)
				goto out_unlock;
			start = vma->vm_start;
			if (start >= end)
				goto out_unlock;
			unmapped_error = -ENOMEM;
		}
		/* Here vma->vm_start <= start < vma->vm_end. */
		if ((flags & MS_INVALIDATE) &&
				(vma->vm_flags & VM_LOCKED)) {
			error = -EBUSY;
			goto out_unlock;
		}
		file = vma->vm_file;
		fstart = (loff_t)linear_page_index(vma, start) << PAGE_SHIFT;
		fend = fstart + (min(end, vma->vm_end) - start) - 1;
		start = vma->vm_end;
		if ((flags & MS_SYNC) && file &&
				(vma->vm_flags & VM_SHARED)) {
			get_file(file);
			mmap_read_unlock(mm);
			error = vfs_fsync_range(file, fstart, fend, 1);
			fput(file);
			if (error || start >= end)
				goto out;
			mmap_read_lock(mm);
			vma = find_vma(mm, start);
		} else {
			if (start >= end) {
				error = 0;
				goto out_unlock;
			}
			vma = find_vma(mm, vma->vm_end);
		}
	}
out_unlock:
	mmap_read_unlock(mm);
out:
	return error ? : unmapped_error;
}

#ifdef CONFIG_RUST_MMAP
int rust_msync_validate(struct rust_msync_req *req, int *out)
{
	return msync_validate(req, out);
}

int rust_msync_apply(struct rust_msync_req *req)
{
	return msync_apply(req);
}
#endif

static int finish_msync(struct rust_msync_req *req)
{
	int out = 0;
	int kind;

	kind = msync_validate(req, &out);
	if (kind == MSYNC_DONE)
		return out;
	return msync_apply(req);
}

static int do_msync(unsigned long start, size_t len, int flags)
{
	struct rust_msync_req req = {
		.start = start,
		.len = len,
		.flags = flags,
	};

#ifdef CONFIG_RUST_MMAP
	int handled = 0;
	int rust_ret;

	rust_ret = rust_msync_dispatch(&req, &handled);
	if (handled)
		return rust_ret;
#endif
	return finish_msync(&req);
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	return do_msync(start, len, flags);
}
