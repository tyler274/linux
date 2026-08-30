// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/page-flags.h>
#include <linux/page_ref.h>

__rust_helper struct page *rust_helper_alloc_pages(gfp_t gfp_mask,
						   unsigned int order)
{
	return alloc_pages(gfp_mask, order);
}

__rust_helper struct page *rust_helper_alloc_pages_node(int nid, gfp_t gfp_mask,
							unsigned int order)
{
	return alloc_pages_node(nid, gfp_mask, order);
}

__rust_helper struct page *rust_helper_virt_to_page(const void *addr)
{
	return virt_to_page(addr);
}

__rust_helper struct page *rust_helper_virt_to_head_page(const void *addr)
{
	return virt_to_head_page(addr);
}

__rust_helper void *rust_helper_page_address(const struct page *page)
{
	return page_address(page);
}

__rust_helper unsigned int rust_helper_compound_order(const struct page *page)
{
	return compound_order(page);
}

__rust_helper void *rust_helper_kmap_local_page(struct page *page)
{
	return kmap_local_page(page);
}

__rust_helper void rust_helper_kunmap_local(const void *addr)
{
	kunmap_local(addr);
}

#ifndef NODE_NOT_IN_PAGE_FLAGS
__rust_helper int rust_helper_page_to_nid(const struct page *page)
{
	return page_to_nid(page);
}
#endif

__rust_helper unsigned long rust_helper_page_to_pfn(const struct page *page)
{
	return page_to_pfn(page);
}

__rust_helper struct page *rust_helper_pfn_to_page(unsigned long pfn)
{
	return pfn_to_page(pfn);
}

/*
 * Undo prep_compound_page so a stolen C folio can be split into order-0
 * pages (or a smaller compound) by the Rust buddy. Does not return the
 * pages to the C allocator.
 */
__rust_helper void rust_helper_destroy_compound_page(struct page *page)
{
	unsigned int order = compound_order(page);
	unsigned int i, nr;

	if (!order)
		return;

	nr = 1u << order;
	folio_reset_order((struct folio *)page);
	for (i = 0; i < nr; i++) {
		ClearPageHead(page + i);
		clear_compound_head(page + i);
		set_page_count(page + i, 1);
	}
}
