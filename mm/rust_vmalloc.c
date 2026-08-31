// SPDX-License-Identifier: GPL-2.0
/*
 * C ABI for the Rust vmalloc replacement (CONFIG_RUST_VMALLOC).
 *
 * Virtual-address allocation lives in rust/kernel/alloc/vmalloc.rs.
 * Page-table map/unmap is mm/vmap_pgtable.c.
 */

#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/llist.h>
#include <linux/workqueue.h>
#include <linux/io.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/uio.h>
#include <linux/notifier.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/sched/mm.h>
#include <asm/shmparam.h>

#include "internal.h"
#include "vmalloc.h"

#if defined(CONFIG_ZONE_DMA32) && defined(CONFIG_64BIT)
#define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
#elif defined(CONFIG_ZONE_DMA)
#define GFP_VMALLOC32 (GFP_DMA | GFP_KERNEL)
#else
#define GFP_VMALLOC32 GFP_KERNEL
#endif

void rust_vmap_init(unsigned long start, unsigned long end);
int rust_vmap_insert(unsigned long addr, unsigned long size, struct vm_struct *vm);
unsigned long rust_vmap_alloc(unsigned long size, unsigned long align,
			      unsigned long start, unsigned long end,
			      unsigned long flags);
struct vm_struct *rust_vmap_find(unsigned long addr);
struct vm_struct *rust_vmap_remove(unsigned long addr);
int rust_vmap_span(unsigned long addr, unsigned long *start, unsigned long *end);

#ifdef CONFIG_RUST_BUDDY
struct page *rust_buddy_alloc_page(gfp_t gfp, int nid);
void rust_buddy_free_page(struct page *page);
#endif

static struct vm_struct *early_vmlist __initdata;
static bool vmap_ready;

static struct page *rv_alloc_page(gfp_t gfp, int nid)
{
#ifdef CONFIG_RUST_BUDDY
	struct page *p = rust_buddy_alloc_page(gfp, nid);

	if (p)
		return p;
#endif
	return alloc_pages_node(nid, gfp, 0);
}

static void rv_free_page(struct page *page)
{
#ifdef CONFIG_RUST_BUDDY
	rust_buddy_free_page(page);
	return;
#endif
	__free_pages(page, 0);
}

static void rv_free_pages(struct vm_struct *vm)
{
	unsigned long i;

	if (!vm || !vm->pages)
		return;
	if (vm->flags & VM_MAP_PUT_PAGES) {
		for (i = 0; i < vm->nr_pages; i++) {
			if (vm->pages[i])
				put_page(vm->pages[i]);
		}
		kvfree(vm->pages);
		return;
	}
	for (i = 0; i < vm->nr_pages; i++) {
		if (vm->pages[i])
			rv_free_page(vm->pages[i]);
	}
	kfree(vm->pages);
}

static struct vm_struct *rv_new_vm(unsigned long size, unsigned long flags,
				   const void *caller, gfp_t gfp)
{
	struct vm_struct *vm = kzalloc(sizeof(*vm), gfp);

	if (!vm)
		return NULL;
	vm->size = size;
	vm->flags = flags;
	vm->caller = caller;
	vm->requested_size = size;
	if (!(flags & VM_NO_GUARD))
		vm->size += PAGE_SIZE;
	return vm;
}

struct vm_struct *__get_vm_area_node(unsigned long size, unsigned long align,
				     unsigned long shift, unsigned long flags,
				     unsigned long start, unsigned long end,
				     int node, gfp_t gfp_mask, const void *caller)
{
	struct vm_struct *vm;
	unsigned long addr, need;

	(void)shift;
	(void)node;
	if (!size || !vmap_ready)
		return NULL;
	if (!align)
		align = 1;
	size = PAGE_ALIGN(size);
	need = size;
	if (!(flags & VM_NO_GUARD))
		need += PAGE_SIZE;

	vm = rv_new_vm(size, flags, caller, GFP_KERNEL);
	if (!vm)
		return NULL;
	/* rv_new_vm already added a guard to vm->size when needed. */
	vm->size = need;

	addr = rust_vmap_alloc(need, align, start, end, flags);
	if (!addr) {
		kfree(vm);
		return NULL;
	}
	vm->addr = (void *)addr;
	if (rust_vmap_insert(addr, need, vm)) {
		rust_vmap_remove(addr);
		kfree(vm);
		return NULL;
	}
	return vm;
}

struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
				       unsigned long start, unsigned long end,
				       const void *caller)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
				  NUMA_NO_NODE, GFP_KERNEL, caller);
}

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, VMALLOC_START,
				  VMALLOC_END, NUMA_NO_NODE, GFP_KERNEL,
				  __builtin_return_address(0));
}
EXPORT_SYMBOL_GPL(get_vm_area);

struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
				     const void *caller)
{
	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, VMALLOC_START,
				  VMALLOC_END, NUMA_NO_NODE, GFP_KERNEL, caller);
}

struct vm_struct *find_vm_area(const void *addr)
{
	if (!addr)
		return NULL;
	return rust_vmap_find((unsigned long)addr);
}

struct vm_struct *remove_vm_area(const void *addr)
{
	struct vm_struct *vm;
	unsigned long start, size;

	if (!addr)
		return NULL;
	vm = rust_vmap_remove((unsigned long)addr);
	if (!vm)
		return NULL;
	start = (unsigned long)vm->addr;
	size = get_vm_area_size(vm);
	vunmap_range(start, start + size);
	return vm;
}

struct vmap_area *find_vmap_area(unsigned long addr)
{
	static DEFINE_PER_CPU(struct vmap_area, lookup);
	struct vmap_area *va = this_cpu_ptr(&lookup);
	unsigned long start, end;
	struct vm_struct *vm;

	vm = rust_vmap_find(addr);
	if (!vm || rust_vmap_span(addr, &start, &end))
		return NULL;
	va->va_start = start;
	va->va_end = end;
	va->vm = vm;
	va->flags = 0;
	return va;
}

void free_vm_area(struct vm_struct *area)
{
	struct vm_struct *ret = remove_vm_area(area->addr);

	BUG_ON(ret != area);
	kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);

unsigned int get_vm_area_page_order(struct vm_struct *vm)
{
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
	return vm->page_order;
#else
	(void)vm;
	return 0;
#endif
}

void clear_vm_uninitialized_flag(struct vm_struct *vm)
{
	smp_wmb();
	vm->flags &= ~VM_UNINITIALIZED;
}

static void *__rv_vmalloc(unsigned long size, unsigned long align,
			  unsigned long start, unsigned long end, gfp_t gfp,
			  pgprot_t prot, unsigned long vm_flags, int nid,
			  const void *caller)
{
	struct vm_struct *area;
	struct page **pages;
	unsigned long n, i;
	int err;

	if (!size)
		return NULL;
	size = PAGE_ALIGN(size);
	n = size >> PAGE_SHIFT;
	if (n > totalram_pages())
		return NULL;

	area = __get_vm_area_node(size, align ? align : 1, PAGE_SHIFT,
				  VM_ALLOC | VM_UNINITIALIZED | vm_flags, start,
				  end, nid, gfp, caller);
	if (!area)
		return NULL;

	pages = kmalloc_array(n, sizeof(*pages), (gfp | __GFP_NOWARN) &
						     ~__GFP_ZERO);
	if (!pages) {
		free_vm_area(area);
		return NULL;
	}
	memset(pages, 0, n * sizeof(*pages));

	for (i = 0; i < n; i++) {
		pages[i] = rv_alloc_page(gfp, nid);
		if (!pages[i])
			goto fail;
	}

	err = vmap_pages_range((unsigned long)area->addr,
			       (unsigned long)area->addr + size, prot, pages,
			       PAGE_SHIFT);
	if (err)
		goto fail;

	area->pages = pages;
	area->nr_pages = n;
	area->requested_size = size;
	clear_vm_uninitialized_flag(area);
	if (gfp & __GFP_ZERO)
		memset(area->addr, 0, size);
	kmemleak_vmalloc(area, size, gfp);
	return area->addr;

fail:
	for (i = 0; i < n; i++) {
		if (pages[i])
			rv_free_page(pages[i]);
	}
	kfree(pages);
	free_vm_area(area);
	return NULL;
}

void *__vmalloc_node_range_noprof(unsigned long size, unsigned long align,
				  unsigned long start, unsigned long end,
				  gfp_t gfp_mask, pgprot_t prot,
				  unsigned long vm_flags, int node,
				  const void *caller)
{
	return __rv_vmalloc(size, align, start, end, gfp_mask, prot, vm_flags,
			    node, caller);
}

void *__vmalloc_node_noprof(unsigned long size, unsigned long align,
			    gfp_t gfp_mask, int node, const void *caller)
{
	return __vmalloc_node_range_noprof(size, align, VMALLOC_START,
					   VMALLOC_END, gfp_mask, PAGE_KERNEL, 0,
					   node, caller);
}
EXPORT_SYMBOL_GPL(__vmalloc_node_noprof);

void *__vmalloc_noprof(unsigned long size, gfp_t gfp_mask)
{
	return __vmalloc_node_noprof(size, 1, gfp_mask, NUMA_NO_NODE,
				     __builtin_return_address(0));
}
EXPORT_SYMBOL(__vmalloc_noprof);

void *vmalloc_noprof(unsigned long size)
{
	return __vmalloc_node_noprof(size, 1, GFP_KERNEL, NUMA_NO_NODE,
				     __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_noprof);

void *vmalloc_huge_node_noprof(unsigned long size, gfp_t gfp_mask, int node)
{
	return __vmalloc_node_range_noprof(size, 1, VMALLOC_START, VMALLOC_END,
					   gfp_mask, PAGE_KERNEL,
					   VM_ALLOW_HUGE_VMAP, node,
					   __builtin_return_address(0));
}
EXPORT_SYMBOL_GPL(vmalloc_huge_node_noprof);

void *vzalloc_noprof(unsigned long size)
{
	return __vmalloc_node_noprof(size, 1, GFP_KERNEL | __GFP_ZERO,
				     NUMA_NO_NODE, __builtin_return_address(0));
}
EXPORT_SYMBOL(vzalloc_noprof);

void *vmalloc_user_noprof(unsigned long size)
{
	return __vmalloc_node_range_noprof(size, SHMLBA, VMALLOC_START,
					   VMALLOC_END, GFP_KERNEL | __GFP_ZERO,
					   PAGE_KERNEL, VM_USERMAP, NUMA_NO_NODE,
					   __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_user_noprof);

void *vmalloc_node_noprof(unsigned long size, int node)
{
	return __vmalloc_node_noprof(size, 1, GFP_KERNEL, node,
				     __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_node_noprof);

void *vzalloc_node_noprof(unsigned long size, int node)
{
	return __vmalloc_node_noprof(size, 1, GFP_KERNEL | __GFP_ZERO, node,
				     __builtin_return_address(0));
}
EXPORT_SYMBOL(vzalloc_node_noprof);

void *vmalloc_32_noprof(unsigned long size)
{
	return __vmalloc_node_noprof(size, 1, GFP_VMALLOC32, NUMA_NO_NODE,
				     __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_32_noprof);

void *vmalloc_32_user_noprof(unsigned long size)
{
	return __vmalloc_node_range_noprof(size, SHMLBA, VMALLOC_START,
					   VMALLOC_END, GFP_VMALLOC32 | __GFP_ZERO,
					   PAGE_KERNEL, VM_USERMAP, NUMA_NO_NODE,
					   __builtin_return_address(0));
}
EXPORT_SYMBOL(vmalloc_32_user_noprof);

void *vmap(struct page **pages, unsigned int count, unsigned long flags,
	   pgprot_t prot)
{
	struct vm_struct *area;
	unsigned long size;
	int err;

	if (!count)
		return NULL;
	size = (unsigned long)count << PAGE_SHIFT;
	area = get_vm_area_caller(size, flags | VM_MAP,
				  __builtin_return_address(0));
	if (!area)
		return NULL;
	err = vmap_pages_range((unsigned long)area->addr,
			       (unsigned long)area->addr + size, prot, pages,
			       PAGE_SHIFT);
	if (err) {
		free_vm_area(area);
		return NULL;
	}
	if (flags & VM_MAP_PUT_PAGES) {
		area->pages = pages;
		area->nr_pages = count;
	}
	return area->addr;
}
EXPORT_SYMBOL(vmap);

void vunmap(const void *addr)
{
	struct vm_struct *vm;

	BUG_ON(in_interrupt());
	might_sleep();
	if (!addr)
		return;
	vm = remove_vm_area(addr);
	if (WARN(!vm, "Trying to vunmap() nonexistent vm area (%p)\n", addr))
		return;
	kfree(vm);
}
EXPORT_SYMBOL(vunmap);

void vfree(const void *addr)
{
	struct vm_struct *vm;

	if (unlikely(in_interrupt())) {
		vfree_atomic(addr);
		return;
	}
	BUG_ON(in_nmi());
	kmemleak_free(addr);
	might_sleep();
	if (!addr)
		return;
	vm = remove_vm_area(addr);
	if (WARN(!vm, "Trying to vfree() nonexistent vm area (%p)\n", addr))
		return;
	rv_free_pages(vm);
	kfree(vm);
}
EXPORT_SYMBOL(vfree);

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};
static DEFINE_PER_CPU(struct vfree_deferred, vfree_deferred);

static void delayed_vfree_work(struct work_struct *w)
{
	struct vfree_deferred *p = container_of(w, struct vfree_deferred, wq);
	struct llist_node *t, *llnode;

	llist_for_each_safe(llnode, t, llist_del_all(&p->list))
		vfree(llnode);
}

void vfree_atomic(const void *addr)
{
	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);

	BUG_ON(in_nmi());
	kmemleak_free(addr);
	if (addr && llist_add((struct llist_node *)addr, &p->list))
		schedule_work(&p->wq);
}

void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned long align,
				 gfp_t flags, int nid)
{
	void *n;
	size_t old = 0;
	struct vm_struct *vm;

	if (!size) {
		vfree(p);
		return NULL;
	}
	if (p) {
		vm = find_vm_area(p);
		if (WARN(!vm, "Trying to vrealloc() nonexistent vm area (%p)\n", p))
			return NULL;
		old = vm->requested_size;
		if (size <= get_vm_area_size(vm)) {
			if ((flags & __GFP_ZERO) && size > old)
				memset((void *)p + old, 0, size - old);
			vm->requested_size = size;
			return (void *)p;
		}
	}
	n = __vmalloc_node_noprof(size, align, flags, nid,
				  __builtin_return_address(0));
	if (!n)
		return NULL;
	if (p) {
		memcpy(n, p, min(old, size));
		vfree(p);
	}
	return n;
}
EXPORT_SYMBOL(vrealloc_node_align_noprof);

void *vmap_pfn(unsigned long *pfns, unsigned int count, pgprot_t prot)
{
	struct page **pages;
	unsigned int i;
	void *addr;

	pages = kmalloc_array(count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return NULL;
	for (i = 0; i < count; i++) {
		if (WARN_ON_ONCE(pfn_valid(pfns[i]))) {
			kfree(pages);
			return NULL;
		}
		pages[i] = pfn_to_page(pfns[i]);
	}
	addr = vmap(pages, count, VM_MAP, prot);
	kfree(pages);
	return addr;
}
EXPORT_SYMBOL_GPL(vmap_pfn);

void vm_unmap_aliases(void)
{
}
EXPORT_SYMBOL_GPL(vm_unmap_aliases);

void vm_unmap_ram(const void *mem, unsigned int count)
{
	(void)count;
	vunmap(mem);
}
EXPORT_SYMBOL(vm_unmap_ram);

void *vm_map_ram(struct page **pages, unsigned int count, int node)
{
	(void)node;
	return vmap(pages, count, VM_MAP, PAGE_KERNEL);
}
EXPORT_SYMBOL(vm_map_ram);

int remap_vmalloc_range_partial(struct vm_area_struct *vma, unsigned long uaddr,
				void *kaddr, unsigned long pgoff,
				unsigned long size)
{
	struct vm_struct *area;
	unsigned long off;
	unsigned long end;

	if (check_shl_overflow(pgoff, PAGE_SHIFT, &off))
		return -EINVAL;
	size = PAGE_ALIGN(size);
	if (!PAGE_ALIGNED(uaddr) || !PAGE_ALIGNED(kaddr))
		return -EINVAL;
	area = find_vm_area(kaddr);
	if (!area || !(area->flags & (VM_USERMAP | VM_DMA_COHERENT)))
		return -EINVAL;
	if (check_add_overflow(size, off, &end) || end > get_vm_area_size(area))
		return -EINVAL;
	kaddr += off;
	do {
		struct page *page = vmalloc_to_page(kaddr);
		int ret;

		if (!page)
			return -ENOMEM;
		ret = vm_insert_page(vma, uaddr, page);
		if (ret)
			return ret;
		uaddr += PAGE_SIZE;
		kaddr += PAGE_SIZE;
		size -= PAGE_SIZE;
	} while (size > 0);
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	return 0;
}

int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
			unsigned long pgoff)
{
	return remap_vmalloc_range_partial(vma, vma->vm_start, addr, pgoff,
					   vma->vm_end - vma->vm_start);
}
EXPORT_SYMBOL(remap_vmalloc_range);

unsigned int memalloc_apply_gfp_scope(gfp_t gfp_mask)
{
	unsigned int flags = 0;

	if (!gfpflags_allow_blocking(gfp_mask) ||
	    (gfp_mask & (__GFP_RETRY_MAYFAIL | __GFP_NORETRY)))
		flags = memalloc_noreclaim_save();
	else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
		flags = memalloc_nofs_save();
	else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
		flags = memalloc_noio_save();

	return flags;
}

void memalloc_restore_scope(unsigned int flags)
{
	if (flags)
		memalloc_flags_restore(flags);
}

#if defined(CONFIG_PRINTK)
bool vmalloc_dump_obj(void *object)
{
	struct vm_struct *vm;
	unsigned long addr = PAGE_ALIGN((unsigned long)object);

	vm = rust_vmap_find(addr);
	if (!vm)
		return false;
	pr_cont(" %lu-page vmalloc region starting at %#lx allocated at %pS\n",
		vm->nr_pages, (unsigned long)vm->addr, vm->caller);
	return true;
}
#endif

long vread_iter(struct iov_iter *iter, const char *addr, size_t count)
{
	size_t copied = 0;

	while (count) {
		struct page *page;
		size_t n = min(count, PAGE_SIZE - offset_in_page(addr));
		const char *m;

		page = vmalloc_to_page(addr);
		if (!page) {
			if (!iov_iter_zero(n, iter))
				break;
		} else {
			m = kmap_local_page(page);
			n = copy_to_iter(m + offset_in_page(addr), n, iter);
			kunmap_local(m);
			if (!n)
				break;
		}
		copied += n;
		addr += n;
		count -= n;
	}
	return copied;
}

int register_vmap_purge_notifier(struct notifier_block *nb)
{
	(void)nb;
	return 0;
}
EXPORT_SYMBOL_GPL(register_vmap_purge_notifier);

int unregister_vmap_purge_notifier(struct notifier_block *nb)
{
	(void)nb;
	return 0;
}
EXPORT_SYMBOL_GPL(unregister_vmap_purge_notifier);

#if defined(CONFIG_MMU) && defined(CONFIG_SMP)
struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
				     const size_t *sizes, int nr_vms,
				     size_t align, gfp_t gfp)
{
	struct vm_struct **vms;
	struct vm_struct *span;
	unsigned long last_end = 0, base;
	int area;

	if (!nr_vms)
		return NULL;
	for (area = 0; area < nr_vms; area++) {
		unsigned long end = offsets[area] + sizes[area];

		if (end > last_end)
			last_end = end;
	}
	vms = kcalloc(nr_vms, sizeof(*vms), gfp);
	span = kzalloc(sizeof(*span), gfp);
	if (!vms || !span)
		goto err_nomem;
	base = rust_vmap_alloc(last_end, align, VMALLOC_START, VMALLOC_END, 0);
	if (!base)
		goto err_nomem;
	span->addr = (void *)base;
	span->size = last_end;
	span->flags = VM_ALLOC;
	if (rust_vmap_insert(base, last_end, span)) {
		rust_vmap_remove(base);
		goto err_nomem;
	}
	for (area = 0; area < nr_vms; area++) {
		vms[area] = kzalloc(sizeof(*vms[0]), gfp);
		if (!vms[area]) {
			pcpu_free_vm_areas(vms, nr_vms);
			return NULL;
		}
		vms[area]->addr = (void *)(base + offsets[area]);
		vms[area]->size = sizes[area];
		vms[area]->flags = VM_ALLOC;
		vms[area]->caller = span;
	}
	return vms;
err_nomem:
	kfree(span);
	kfree(vms);
	return NULL;
}

void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms)
{
	struct vm_struct *span = NULL;
	unsigned long base;
	int i;

	if (!vms || !nr_vms)
		return;
	base = (unsigned long)vms[0]->addr;
	if (vms[0]->caller) {
		span = (struct vm_struct *)vms[0]->caller;
		base = (unsigned long)span->addr;
	}
	rust_vmap_remove(base);
	kfree(span);
	for (i = 0; i < nr_vms; i++)
		kfree(vms[i]);
	kfree(vms);
}
#endif

void __init vm_area_add_early(struct vm_struct *vm)
{
	struct vm_struct *tmp, **p;

	BUG_ON(vmap_ready);
	for (p = &early_vmlist; (tmp = *p) != NULL; p = &tmp->next) {
		if (tmp->addr >= vm->addr) {
			BUG_ON(tmp->addr < vm->addr + vm->size);
			break;
		}
		BUG_ON(tmp->addr + tmp->size > vm->addr);
	}
	vm->next = *p;
	*p = vm;
}

void __init vm_area_register_early(struct vm_struct *vm, size_t align)
{
	unsigned long addr = ALIGN(VMALLOC_START, align);
	struct vm_struct *cur, **p;

	BUG_ON(vmap_ready);
	for (p = &early_vmlist; (cur = *p) != NULL; p = &cur->next) {
		if ((unsigned long)cur->addr - addr >= vm->size)
			break;
		addr = ALIGN((unsigned long)cur->addr + cur->size, align);
	}
	BUG_ON(addr > VMALLOC_END - vm->size);
	vm->addr = (void *)addr;
	vm->next = *p;
	*p = vm;
	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
}

void __init vmalloc_init(void)
{
	struct vm_struct *tmp;
	int cpu;

	rust_vmap_init(VMALLOC_START, VMALLOC_END);
	for (tmp = early_vmlist; tmp; tmp = tmp->next)
		rust_vmap_insert((unsigned long)tmp->addr, tmp->size, tmp);

	for_each_possible_cpu(cpu) {
		struct vfree_deferred *p = &per_cpu(vfree_deferred, cpu);

		init_llist_head(&p->list);
		INIT_WORK(&p->wq, delayed_vfree_work);
	}
	vmap_ready = true;
	pr_info("rust-vmalloc: replaced mm/vmalloc.c [%lx, %lx)\n",
		(unsigned long)VMALLOC_START, (unsigned long)VMALLOC_END);
}
