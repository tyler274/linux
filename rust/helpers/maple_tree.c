// SPDX-License-Identifier: GPL-2.0

#include <linux/maple_tree.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>

__rust_helper void rust_helper_mt_init_flags(struct maple_tree *mt,
					     unsigned int flags)
{
	mt_init_flags(mt, flags);
}

#ifdef CONFIG_RUST_MMAP
struct rust_mt_header {
	struct rcu_head rcu;
	u32 n;
	u32 cap;
};

__rust_helper void *rust_helper_mt_kvmalloc(size_t size, gfp_t gfp)
{
	return kvmalloc(size, gfp);
}

__rust_helper void rust_helper_mt_kvfree(const void *ptr)
{
	kvfree(ptr);
}

__rust_helper void rust_helper_mt_kvfree_rcu(void *ptr)
{
	struct rust_mt_header *h = ptr;

	kvfree_rcu(h, rcu);
}

__rust_helper void *rust_helper_mt_rcu_deref_root(const struct maple_tree *mt)
{
	return rcu_dereference_check(mt->ma_root, mt_lock_is_held(mt));
}

__rust_helper void rust_helper_mt_rcu_assign_root(struct maple_tree *mt,
						  void *root)
{
	rcu_assign_pointer(mt->ma_root, root);
}
__rust_helper void rust_helper_mas_set_err(struct ma_state *mas, int err)
{
	mas->node = MA_ERROR(err);
	mas->status = ma_error;
}
#endif
