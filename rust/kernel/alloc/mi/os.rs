// SPDX-License-Identifier: GPL-2.0

//! Page-allocator backend for the mimalloc-inspired slab.
//!
//! Folios come from the C buddy (`alloc_pages_node` / `__free_pages`). GFP
//! flags are passed through; callers must not hold IRQ-disabled locks across a
//! blocking `alloc_pages` call.

use crate::{
    alloc::Flags,
    bindings,
    ffi::c_ulong,
    page::PAGE_SIZE, //
};

/// Allocate a compound folio of `1 << order` pages.
///
/// Returns the head `struct page` pointer, or null on failure.
pub(super) unsafe fn alloc_folio(order: u32, gfp: Flags, nid: i32) -> *mut bindings::page {
    let mut flags = gfp.as_raw();
    if order > 0 {
        flags |= bindings::__GFP_COMP;
    }
    // SAFETY: `alloc_pages_node` is safe for any GFP combination the buddy accepts.
    unsafe { bindings::alloc_pages_node(nid, flags, order) }
}

/// Free a folio previously obtained from [`alloc_folio`].
///
/// # Safety
///
/// `page` must be a head page from [`alloc_folio`] with the same `order`.
pub(super) unsafe fn free_folio(page: *mut bindings::page, order: u32) {
    // SAFETY: Caller guarantees ownership of this folio.
    unsafe { bindings::__free_pages(page, order) };
}

/// Linear-map address of `page`.
///
/// # Safety
///
/// `page` must be a valid lowmem page.
pub(super) unsafe fn page_address(page: *mut bindings::page) -> *mut u8 {
    // SAFETY: Caller guarantees a valid page in the linear map.
    unsafe { bindings::page_address(page).cast() }
}

/// Head page containing `ptr`.
///
/// # Safety
///
/// `ptr` must be a kernel linear-map address of a live page.
pub(super) unsafe fn virt_to_head_page(ptr: *const u8) -> *mut bindings::page {
    // SAFETY: Caller guarantees a valid kernel pointer into a mapped page.
    unsafe { bindings::virt_to_head_page(ptr.cast()) }
}

pub(super) fn page_size_bytes(order: u32) -> usize {
    PAGE_SIZE << order
}

pub(super) fn gfp_may_block(gfp: Flags) -> bool {
    // SAFETY: Always safe; inspects bits only.
    unsafe { bindings::gfpflags_allow_blocking(gfp.as_raw()) }
}

pub(super) fn current_cpu() -> usize {
    // SAFETY: `raw_smp_processor_id` is always safe to read.
    (unsafe { bindings::raw_smp_processor_id() }) as usize
}

/// IRQ-save guard for a per-CPU heap critical section.
pub(super) struct IrqSave(c_ulong);

impl IrqSave {
    pub(super) fn save() -> Self {
        // SAFETY: Saving and later restoring IRQ flags is always valid.
        Self(unsafe { bindings::local_irq_save() })
    }
}

impl Drop for IrqSave {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from [`IrqSave::save`] on this CPU.
        unsafe { bindings::local_irq_restore(self.0) };
    }
}

pub(super) unsafe fn set_meta(page: *mut bindings::page, meta: *mut u8) {
    // SAFETY: `page` is a valid `struct page`.
    unsafe { bindings::mi_set_meta(page, meta.cast()) };
}

pub(super) unsafe fn get_meta(page: *const bindings::page) -> *mut u8 {
    // SAFETY: `page` is a valid `struct page`.
    unsafe { bindings::mi_get_meta(page).cast() }
}

#[cfg(CONFIG_SLAB_MIMALLOC)]
pub(super) unsafe fn setup_slab(page: *mut bindings::page, cache: *mut u8, objects: u32) {
    // SAFETY: `page` was just allocated for use as a slab.
    unsafe { bindings::mi_setup_slab(page, cache.cast(), objects) };
}

#[cfg(CONFIG_SLAB_MIMALLOC)]
pub(super) unsafe fn teardown_slab(page: *mut bindings::page) {
    // SAFETY: `page` is a slab folio we own.
    unsafe { bindings::mi_teardown_slab(page) };
}
