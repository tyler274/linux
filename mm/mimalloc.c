// SPDX-License-Identifier: GPL-2.0
/*
 * C ABI for the Rust mimalloc-inspired slab (CONFIG_SLAB_MIMALLOC).
 *
 * Object storage lives in rust/kernel/alloc/mi/. This file implements the
 * kmalloc / kmem_cache surface expected by slab_common.c and the rest of
 * the kernel.
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/llist.h>
#include <linux/workqueue.h>
#include <linux/reciprocal_div.h>
#include <linux/tracepoint.h>
#include <linux/sched/mm.h>
#include <linux/sprintf.h>
#include <linux/overflow.h>

#include "internal.h"
#include "slab.h"

#include <trace/events/kmem.h>

void *rust_mi_alloc(size_t size, unsigned long align, gfp_t flags, int nid,
		    void *cache);
bool rust_mi_free(void *ptr);
size_t rust_mi_usable_size(const void *ptr);
void *rust_mi_realloc(void *ptr, size_t new_size, unsigned long align,
		      gfp_t flags, int nid);
void rust_mi_init(void);

static void *mi_alloc(size_t size, unsigned long align, gfp_t flags, int nid,
		      struct kmem_cache *s)
{
	void *p;

	if (flags & GFP_SLAB_BUG_MASK)
		flags = kmalloc_fix_flags(flags);

	p = rust_mi_alloc(size, align ? align : ARCH_KMALLOC_MINALIGN, flags,
			  nid, s);
	if (p && s && s->ctor && !(flags & __GFP_ZERO))
		s->ctor(p);
	return p;
}

int do_kmem_cache_create(struct kmem_cache *s, const char *name,
			 unsigned int size, struct kmem_cache_args *args,
			 slab_flags_t flags)
{
	unsigned int align = args && args->align ? args->align : ARCH_SLAB_MINALIGN;

	if (!size)
		return -EINVAL;

	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;
	size = ALIGN(size, align);

	s->name = name;
	s->size = s->object_size = size;
	s->inuse = size;
	s->flags = flags;
	s->align = align;
	s->ctor = args ? args->ctor : NULL;
	s->refcount = 1;
	s->sheaf_capacity = 0;
	s->allocflags = GFP_KERNEL;
	s->reciprocal_size = reciprocal_value(size);
	s->mi_priv = s;
	return 0;
}

slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name)
{
	(void)name;
	return flags;
}

void __init kmem_cache_init(void)
{
	static struct kmem_cache boot_kmem_cache;

	rust_mi_init();
	hash_pointers_finalize(false);
	kmem_cache = &boot_kmem_cache;
	create_boot_cache(kmem_cache, "kmem_cache", sizeof(struct kmem_cache),
			  SLAB_HWCACHE_ALIGN | SLAB_NO_SHEAVES | SLAB_NO_OBJ_EXT,
			  0, 0);
	slab_state = PARTIAL;
	setup_kmalloc_cache_index_table();
	create_kmalloc_caches();
	pr_info("mimalloc-slab: Rust size-class allocator\n");
}

void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}

void __kmem_cache_release(struct kmem_cache *s)
{
	s->mi_priv = NULL;
}

bool __kmem_cache_empty(struct kmem_cache *s)
{
	return true;
}

int __kmem_cache_shutdown(struct kmem_cache *s)
{
	return 0;
}

int __kmem_cache_shrink(struct kmem_cache *s)
{
	return 0;
}

void *kmem_cache_alloc_noprof(struct kmem_cache *s, gfp_t gfpflags)
{
	void *ret = mi_alloc(s->object_size, s->align, gfpflags, NUMA_NO_NODE, s);

	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_noprof);

void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
				  gfp_t gfpflags)
{
	(void)lru;
	return kmem_cache_alloc_noprof(s, gfpflags);
}
EXPORT_SYMBOL(kmem_cache_alloc_lru_noprof);

bool kmem_cache_charge(void *objp, gfp_t gfpflags)
{
	return true;
}
EXPORT_SYMBOL(kmem_cache_charge);

void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int node)
{
	void *ret = mi_alloc(s->object_size, s->align, gfpflags, node, s);

	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, node);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);

static void *do_kmalloc(size_t size, gfp_t flags, int node)
{
	struct kmem_cache *s;

	if (unlikely(!size))
		return ZERO_SIZE_PTR;

	if (size > KMALLOC_MAX_CACHE_SIZE)
		return mi_alloc(size, ARCH_KMALLOC_MINALIGN, flags, node, NULL);

	s = kmalloc_slab(size, NULL, flags, __kmalloc_token(size),
			 SLAB_ALLOC_DEFAULT);
	if (WARN_ON_ONCE(!s))
		return mi_alloc(size, ARCH_KMALLOC_MINALIGN, flags, node, NULL);

	return mi_alloc(s->object_size, s->align, flags, node, s);
}

void *__kmalloc_large_noprof(size_t size, gfp_t flags)
{
	void *ret = mi_alloc(size, PAGE_SIZE, flags, NUMA_NO_NODE, NULL);

	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size), flags,
		      NUMA_NO_NODE);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_large_noprof);

void *__kmalloc_large_node_noprof(size_t size, gfp_t flags, int node)
{
	void *ret = mi_alloc(size, PAGE_SIZE, flags, node, NULL);

	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size), flags, node);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_large_node_noprof);

void *__kmalloc_node_noprof(DECL_KMALLOC_PARAMS(size, b, token), gfp_t flags, int node)
{
	void *ret = do_kmalloc(size, flags, node);

	trace_kmalloc(_RET_IP_, ret, size, size, flags, node);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_node_noprof);

void *__kmalloc_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t flags)
{
	void *ret = do_kmalloc(size, flags, NUMA_NO_NODE);

	trace_kmalloc(_RET_IP_, ret, size, size, flags, NUMA_NO_NODE);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_noprof);

void *_kmalloc_nolock_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t gfp_flags, int node)
{
	gfp_flags |= __GFP_NOWARN | __GFP_NOMEMALLOC;
	if (unlikely(!size) || size > KMALLOC_MAX_CACHE_SIZE)
		return size ? NULL : ZERO_SIZE_PTR;
	return do_kmalloc(size, gfp_flags, node);
}
EXPORT_SYMBOL_GPL(_kmalloc_nolock_noprof);

void *__kmalloc_node_track_caller_noprof(DECL_KMALLOC_PARAMS(size, b, token), gfp_t flags,
					 int node, unsigned long caller)
{
	void *ret = do_kmalloc(size, flags, node);

	trace_kmalloc(caller, ret, size, size, flags, node);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_node_track_caller_noprof);

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
	void *ret = mi_alloc(s->object_size, s->align, gfpflags, NUMA_NO_NODE, s);

	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_cache_noprof);

void *__kmalloc_cache_node_noprof(struct kmem_cache *s, gfp_t gfpflags,
				  int node, size_t size)
{
	void *ret = mi_alloc(s->object_size, s->align, gfpflags, node, s);

	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
	return ret;
}
EXPORT_SYMBOL(__kmalloc_cache_node_noprof);

void *__kmalloc_flags_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t flags,
			     unsigned int alloc_flags, int node)
{
	if (!alloc_flags_allow_spinning(alloc_flags))
		return _kmalloc_nolock_noprof(PASS_TOKEN_PARAMS(size, token), flags, node);
	return __kmalloc_node_noprof(PASS_KMALLOC_PARAMS(size, NULL, token), flags, node);
}

void kmem_cache_free(struct kmem_cache *s, void *x)
{
	if (ZERO_OR_NULL_PTR(x))
		return;
	trace_kmem_cache_free(_RET_IP_, x, s);
	rust_mi_free(x);
}
EXPORT_SYMBOL(kmem_cache_free);

size_t ksize(const void *objp)
{
	if (unlikely(ZERO_OR_NULL_PTR(objp)))
		return 0;
	if (is_vmalloc_addr(objp))
		return 0;
	return rust_mi_usable_size(objp);
}
EXPORT_SYMBOL(ksize);

void kfree(const void *object)
{
	trace_kfree(_RET_IP_, object);
	if (unlikely(ZERO_OR_NULL_PTR(object)))
		return;
	if (is_vmalloc_addr(object)) {
		WARN_ON_ONCE(1);
		vfree(object);
		return;
	}
	rust_mi_free((void *)object);
}
EXPORT_SYMBOL(kfree);

void kfree_nolock(const void *object)
{
	if (unlikely(ZERO_OR_NULL_PTR(object)))
		return;
	rust_mi_free((void *)object);
}
EXPORT_SYMBOL_GPL(kfree_nolock);

void *krealloc_node_align_noprof(const void *p, DECL_TOKEN_PARAMS(new_size, token),
				 unsigned long align, gfp_t flags, int nid)
{
	void *ret;

	if (unlikely(!new_size)) {
		kfree(p);
		return ZERO_SIZE_PTR;
	}
	ret = rust_mi_realloc((void *)p, new_size, align ? align : 1, flags, nid);
	return ret;
}
EXPORT_SYMBOL(krealloc_node_align_noprof);

static gfp_t kmalloc_gfp_adjust(gfp_t flags, size_t size)
{
	if (size > PAGE_SIZE) {
		flags |= __GFP_NOWARN;
		if (!(flags & __GFP_RETRY_MAYFAIL))
			flags &= ~__GFP_DIRECT_RECLAIM;
		flags &= ~__GFP_NOFAIL;
	}
	return flags;
}

void *__kvmalloc_node_noprof(DECL_KMALLOC_PARAMS(size, b, token), unsigned long align,
			     gfp_t flags, int node)
{
	void *ret;
	bool allow_block;

	ret = do_kmalloc(size, kmalloc_gfp_adjust(flags, size), node);
	if (ret || size <= PAGE_SIZE)
		return ret;
	if (unlikely(size > INT_MAX)) {
		WARN_ON_ONCE(!(flags & __GFP_NOWARN));
		return NULL;
	}
	allow_block = gfpflags_allow_blocking(flags);
	return __vmalloc_node_range_noprof(size, align, VMALLOC_START, VMALLOC_END,
			flags, PAGE_KERNEL, allow_block ? VM_ALLOW_HUGE_VMAP : 0,
			node, __builtin_return_address(0));
}
EXPORT_SYMBOL(__kvmalloc_node_noprof);

void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
EXPORT_SYMBOL(kvfree);

void kvfree_atomic(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree_atomic(addr);
	else
		kfree(addr);
}
EXPORT_SYMBOL(kvfree_atomic);

void kvfree_sensitive(const void *addr, size_t len)
{
	if (likely(!ZERO_OR_NULL_PTR(addr))) {
		memzero_explicit((void *)addr, len);
		kvfree(addr);
	}
}
EXPORT_SYMBOL(kvfree_sensitive);

void *kvrealloc_node_align_noprof(const void *p, DECL_TOKEN_PARAMS(size, token),
				  unsigned long align, gfp_t flags, int nid)
{
	void *n;

	if (is_vmalloc_addr(p))
		return vrealloc_node_align_noprof(p, size, align, flags, nid);

	n = krealloc_node_align_noprof(p, PASS_TOKEN_PARAMS(size, token), align,
				       kmalloc_gfp_adjust(flags, size), nid);
	if (!n) {
		n = __kvmalloc_node_noprof(PASS_KMALLOC_PARAMS(size, NULL, token),
					   align, flags, nid);
		if (!n)
			return NULL;
		if (p) {
			memcpy(n, p, min(size, ksize(p)));
			kfree(p);
		}
	}
	return n;
}
EXPORT_SYMBOL(kvrealloc_node_align_noprof);

void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
{
	size_t i;

	for (i = 0; i < size; i++)
		kmem_cache_free(s, p[i]);
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

bool kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags,
				  size_t size, void **p)
{
	size_t i;

	for (i = 0; i < size; i++) {
		p[i] = kmem_cache_alloc_noprof(s, flags);
		if (!p[i]) {
			kmem_cache_free_bulk(s, i, p);
			return false;
		}
	}
	return true;
}
EXPORT_SYMBOL(kmem_cache_alloc_bulk_noprof);

void get_slabinfo(struct kmem_cache *s, struct slabinfo *sinfo)
{
	memset(sinfo, 0, sizeof(*sinfo));
	sinfo->objects_per_slab = s->size ? (PAGE_SIZE / s->size) : 0;
}

#ifdef SLAB_SUPPORTS_SYSFS
void sysfs_slab_unlink(struct kmem_cache *s) { }
void sysfs_slab_release(struct kmem_cache *s) { }
int sysfs_slab_alias(struct kmem_cache *s, const char *name)
{
	return 0;
}
#endif

void *fixup_red_left(struct kmem_cache *s, void *p)
{
	return p;
}

#ifdef CONFIG_SLUB_DEBUG
void skip_orig_size_check(struct kmem_cache *s, const void *object)
{
}
#endif

void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
{
	kmem_cache_free(cache, x);
}

bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj, unsigned int free_flags)
{
	return false;
}

void flush_all_rcu_sheaves(void)
{
}

void flush_rcu_sheaves_on_cache(struct kmem_cache *s)
{
}

static LLIST_HEAD(mi_deferred_rcu);
static void mi_deferred_work_fn(struct work_struct *w);
static DECLARE_WORK(mi_deferred_work, mi_deferred_work_fn);

static void mi_deferred_work_fn(struct work_struct *w)
{
	struct llist_node *list, *pos, *n;

	synchronize_rcu();
	list = llist_del_all(&mi_deferred_rcu);
	llist_for_each_safe(pos, n, list)
		kvfree(pos);
}

void defer_kfree_rcu(struct kvfree_rcu_head *head)
{
	if (llist_add((struct llist_node *)head, &mi_deferred_rcu))
		schedule_work(&mi_deferred_work);
}

void deferred_work_barrier(void)
{
	flush_work(&mi_deferred_work);
}

void kvfree_rcu_cb(struct rcu_head *head)
{
	void *obj = kvmalloc_obj_start_addr(head);

	kvfree(obj);
}

#ifdef CONFIG_PRINTK
void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
{
	kpp->kp_ptr = object;
	kpp->kp_slab = slab;
	kpp->kp_slab_cache = slab ? slab->slab_cache : NULL;
	kpp->kp_objp = object;
}
#endif

void __check_heap_object(const void *ptr, unsigned long n,
			 const struct slab *slab, bool to_user)
{
	(void)ptr;
	(void)n;
	(void)slab;
	(void)to_user;
}

#define MI_SHEAF_MAX 128

struct slab_sheaf {
	struct kmem_cache *cache;
	unsigned int size;
	unsigned int count;
	void *objs[];
};

static void mi_sheaf_free_objs(struct slab_sheaf *sheaf)
{
	unsigned int i;

	for (i = 0; i < sheaf->count; i++)
		kmem_cache_free(sheaf->cache, sheaf->objs[i]);
	sheaf->count = 0;
}

static int mi_sheaf_fill(struct slab_sheaf *sheaf, gfp_t gfp, unsigned int want)
{
	unsigned int i;

	if (want > sheaf->size)
		want = sheaf->size;
	for (i = sheaf->count; i < want; i++) {
		sheaf->objs[i] = kmem_cache_alloc_noprof(sheaf->cache, gfp);
		if (!sheaf->objs[i])
			return sheaf->count ? 0 : -ENOMEM;
		sheaf->count++;
	}
	return 0;
}

struct slab_sheaf *
kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
{
	struct slab_sheaf *sheaf;
	unsigned int n;

	if (!s || !size)
		return NULL;
	n = min_t(unsigned int, size, MI_SHEAF_MAX);
	sheaf = kmalloc(struct_size(sheaf, objs, n), gfp | __GFP_NOWARN);
	if (!sheaf)
		return NULL;
	sheaf->cache = s;
	sheaf->size = n;
	sheaf->count = 0;
	if (mi_sheaf_fill(sheaf, gfp, n)) {
		kfree(sheaf);
		return NULL;
	}
	return sheaf;
}

int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
			    struct slab_sheaf **sheafp, unsigned int size)
{
	struct slab_sheaf *new;

	if (*sheafp && (*sheafp)->count >= size)
		return 0;
	if (*sheafp && !mi_sheaf_fill(*sheafp, gfp, (*sheafp)->size) &&
	    (*sheafp)->count >= size)
		return 0;

	new = kmem_cache_prefill_sheaf(s, gfp, size);
	if (!new)
		return -ENOMEM;
	if (*sheafp)
		kmem_cache_return_sheaf(s, gfp, *sheafp);
	*sheafp = new;
	return 0;
}

void kmem_cache_return_sheaf(struct kmem_cache *s, gfp_t gfp,
			     struct slab_sheaf *sheaf)
{
	(void)s;
	(void)gfp;
	if (!sheaf)
		return;
	mi_sheaf_free_objs(sheaf);
	kfree(sheaf);
}

void *kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *cachep, gfp_t gfp,
					 struct slab_sheaf *sheaf)
{
	if (sheaf && sheaf->count)
		return sheaf->objs[--sheaf->count];
	return kmem_cache_alloc_noprof(cachep, gfp);
}

unsigned int kmem_cache_sheaf_size(struct slab_sheaf *sheaf)
{
	return sheaf ? sheaf->count : 0;
}
