// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/slab.h>

#include "../../mm/slab.h"

__rust_helper void rust_helper_mi_set_page_private(struct page *page,
						   unsigned long val)
{
	set_page_private(page, val);
}

__rust_helper unsigned long rust_helper_mi_page_private(const struct page *page)
{
	return page_private(page);
}

/*
 * Store MiPage metadata. `page_private` overlays slab inuse/objects once the
 * folio is tagged PGTY_slab, so Stage B hangs the pointer off slab->freelist
 * (unused by this allocator). Stage A is not a system slab: page_private is OK.
 */
__rust_helper void rust_helper_mi_set_meta(struct page *page, void *meta)
{
#ifdef CONFIG_SLAB_MIMALLOC
	struct slab *slab = page_slab(page);

	if (slab)
		slab->freelist = meta;
	else
		set_page_private(page, (unsigned long)meta);
#else
	set_page_private(page, (unsigned long)meta);
#endif
}

__rust_helper void *rust_helper_mi_get_meta(const struct page *page)
{
#ifdef CONFIG_SLAB_MIMALLOC
	const struct slab *slab = page_slab(page);

	if (slab)
		return slab->freelist;
	return (void *)page_private(page);
#else
	return (void *)page_private(page);
#endif
}

__rust_helper void rust_helper_mi_setup_slab(struct page *page, void *cache,
					     unsigned int objects)
{
	struct slab *slab;

	__SetPageSlab(page);
	slab = page_slab(page);
	if (!slab)
		return;
	slab->slab_cache = cache;
	slab->objects = objects;
	slab->inuse = objects;
	slab->freelist = NULL;
}

__rust_helper void rust_helper_mi_teardown_slab(struct page *page)
{
	struct slab *slab = page_slab(page);

	if (slab) {
		slab->slab_cache = NULL;
		slab->freelist = NULL;
	}
	__ClearPageSlab(page);
	set_page_private(page, 0);
}

__rust_helper void rust_helper_mi_set_large_kmalloc(struct page *page)
{
	__SetPageLargeKmalloc(page);
}

__rust_helper void rust_helper_mi_clear_large_kmalloc(struct page *page)
{
	__ClearPageLargeKmalloc(page);
}

__rust_helper bool rust_helper_mi_page_is_slab(const struct page *page)
{
	return PageSlab(page);
}

__rust_helper bool rust_helper_gfpflags_allow_blocking(gfp_t flags)
{
	return gfpflags_allow_blocking(flags);
}
