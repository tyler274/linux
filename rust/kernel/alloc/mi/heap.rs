// SPDX-License-Identifier: GPL-2.0

//! Per-CPU heaps: local free lists under IRQ disable, CAS for remote frees.

use super::os::{self, IrqSave};
use super::page::{self, MiPage};
use crate::{
    alloc::Flags,
    page::PAGE_SIZE,
    sync::atomic::{
        Atomic,
        Relaxed,
        Release, //
    },
};
use core::cell::UnsafeCell;
use core::ptr;

const HEAP_COUNT: usize = 64;
const BIN_COUNT: usize = 16;

/// Size classes matching common kmalloc buckets, plus a huge sentinel (0).
static BINS: [u32; BIN_COUNT] = [
    8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192, 0,
];

#[repr(C, align(64))]
struct CpuHeap {
    lock: Atomic<i32>,
    current: [*mut MiPage; BIN_COUNT],
    lists: [*mut MiPage; BIN_COUNT],
}

impl CpuHeap {
    const fn new() -> Self {
        Self {
            lock: Atomic::new(0),
            current: [ptr::null_mut(); BIN_COUNT],
            lists: [ptr::null_mut(); BIN_COUNT],
        }
    }
}

struct HeapArray([UnsafeCell<CpuHeap>; HEAP_COUNT]);

// SAFETY: Each heap is accessed only while its TAS lock is held (and IRQs are
// saved on that CPU), so concurrent `&mut` aliases do not occur.
unsafe impl Sync for HeapArray {}

static HEAPS: HeapArray = HeapArray([const { UnsafeCell::new(CpuHeap::new()) }; HEAP_COUNT]);

fn heap_index() -> usize {
    os::current_cpu() % HEAP_COUNT
}

fn heap() -> *mut CpuHeap {
    HEAPS.0[heap_index()].get()
}

struct HeapGuard {
    h: *mut CpuHeap,
    _irq: IrqSave,
}

impl HeapGuard {
    fn acquire(allow_fail: bool) -> Option<Self> {
        let irq = IrqSave::save();
        let h = heap();
        loop {
            // SAFETY: `h` is a valid per-CPU heap; TAS serializes `&mut` use.
            match unsafe { (*h).lock.cmpxchg(0, 1, Relaxed) } {
                Ok(_) => {
                    return Some(Self { h, _irq: irq });
                }
                Err(_) => {
                    if allow_fail {
                        drop(irq);
                        return None;
                    }
                    core::hint::spin_loop();
                }
            }
        }
    }

    fn heap(&mut self) -> &mut CpuHeap {
        // SAFETY: We hold the TAS lock for this heap.
        unsafe { &mut *self.h }
    }
}

impl Drop for HeapGuard {
    fn drop(&mut self) {
        // SAFETY: We hold the TAS lock; Release publishes local-list writes.
        unsafe { (*self.h).lock.store(0, Release) };
    }
}

pub(super) fn bin_for_size(size: usize, align: usize) -> Option<usize> {
    let need = size.max(align).max(core::mem::size_of::<usize>());
    let max_cache = PAGE_SIZE * 2;
    if need > max_cache {
        return None;
    }
    for (i, &b) in BINS.iter().enumerate() {
        if b == 0 {
            break;
        }
        if b as usize >= need && (b as usize) % align.max(1) == 0 {
            return Some(i);
        }
    }
    None
}

pub(super) fn bin_size(bin: usize) -> u32 {
    BINS[bin]
}

/// Allocate `size` bytes with `align` from a size-class page or a huge folio.
///
/// # Safety
///
/// GFP must be valid for the buddy. The returned pointer, if non-null, must be
/// passed to [`free`] (or [`realloc`]) and not aliased mutably.
pub(super) unsafe fn malloc(
    size: usize,
    align: usize,
    gfp: Flags,
    nid: i32,
    cache: *mut u8,
) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    let align = align.max(1).next_power_of_two();
    match bin_for_size(size, align) {
        // SAFETY: Same as this function.
        Some(bin) => unsafe { malloc_bin(bin, gfp, nid, cache) },
        // SAFETY: Same as this function.
        None => unsafe { malloc_huge(size, align, gfp, nid, cache) },
    }
}

unsafe fn malloc_bin(bin: usize, gfp: Flags, nid: i32, cache: *mut u8) -> *mut u8 {
    let allow_fail = !os::gfp_may_block(gfp);
    let mut guard = match HeapGuard::acquire(allow_fail) {
        Some(g) => g,
        None => return ptr::null_mut(),
    };
    let h = guard.heap();
    let mut page = h.current[bin];
    if !page.is_null() {
        // SAFETY: `page` is a live size-class page on this heap.
        let p = unsafe { page::pop(page) };
        if !p.is_null() {
            return p;
        }
    }
    // SAFETY: Heap lock is held.
    page = unsafe { find_page(h, bin) };
    if !page.is_null() {
        h.current[bin] = page;
        // SAFETY: `page` has a free object.
        let p = unsafe { page::pop(page) };
        if !p.is_null() {
            return p;
        }
    }
    drop(guard);

    // SAFETY: GFP is forwarded; heap lock is not held (may sleep).
    let page = unsafe { page::create(bin_size(bin), gfp, nid, cache) };
    if page.is_null() {
        return ptr::null_mut();
    }
    let mut guard = match HeapGuard::acquire(allow_fail) {
        Some(g) => g,
        None => {
            // SAFETY: Nobody linked this page yet.
            unsafe { page::destroy(page) };
            return ptr::null_mut();
        }
    };
    let h = guard.heap();
    // SAFETY: Fresh page, heap lock held.
    unsafe {
        (*page).next = h.lists[bin];
        h.lists[bin] = page;
        h.current[bin] = page;
        page::pop(page)
    }
}

unsafe fn find_page(h: &mut CpuHeap, bin: usize) -> *mut MiPage {
    let mut cur = h.lists[bin];
    while !cur.is_null() {
        // SAFETY: `cur` is a page on this heap's list.
        unsafe {
            page::collect(cur);
            if !(*cur).local_free.is_null() {
                return cur;
            }
            cur = (*cur).next;
        }
    }
    ptr::null_mut()
}

unsafe fn malloc_huge(size: usize, align: usize, gfp: Flags, nid: i32, cache: *mut u8) -> *mut u8 {
    let need = size.max(align);
    let mut order: u32 = 0;
    while os::page_size_bytes(order) < need && order < 10 {
        order += 1;
    }
    if os::page_size_bytes(order) < need {
        return ptr::null_mut();
    }
    // SAFETY: GFP is forwarded to the buddy.
    let page = unsafe { page::create(os::page_size_bytes(order) as u32, gfp, nid, cache) };
    if page.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: The huge page has a single object.
    unsafe { page::pop(page) }
}

/// Free an object previously returned by [`malloc`].
///
/// Returns `false` on double-free or invalid pointer.
///
/// # Safety
///
/// `ptr` must be null or a pointer from [`malloc`] /
/// [`realloc`] that has not already been freed (except for the double-free
/// detect path, which may pass an already-freed pointer).
pub(super) unsafe fn free(ptr: *mut u8) -> bool {
    if ptr.is_null() {
        return true;
    }
    let page = page::from_ptr(ptr);
    if page.is_null() {
        return false;
    }
    if let Some(_guard) = HeapGuard::acquire(true) {
        // SAFETY: Heap lock held; `ptr` belongs to `page`.
        if unsafe { !page::push_local(page, ptr) } {
            return false;
        }
        // SAFETY: Heap lock held.
        unsafe { maybe_release_empty(page) };
        true
    } else {
        // SAFETY: Concurrent free list is lock-free.
        unsafe { page::push_thread(page, ptr) }
    }
}

unsafe fn maybe_release_empty(page: *mut MiPage) {
    // SAFETY: Caller holds the heap lock or otherwise owns `page`.
    unsafe {
        if (*page).used != 0 {
            return;
        }
        page::collect(page);
        if (*page).used != 0 {
            return;
        }
    }
    // Keep empty pages as a cache. Unlinking races are avoided by never
    // destroying from the free path in v1.
}

/// Usable size of an object from this allocator.
///
/// # Safety
///
/// `ptr` must be an object from [`malloc`] (or null / zero-size).
pub(super) unsafe fn usable_size(ptr: *const u8) -> usize {
    let page = page::from_ptr(ptr);
    if page.is_null() {
        return 0;
    }
    // SAFETY: `from_ptr` validated the `MiPage`.
    unsafe { (*page).block_size as usize }
}

/// Reallocate an object.
///
/// # Safety
///
/// Same as [`malloc`] for `ptr` being null; otherwise `ptr` is from this
/// allocator.
pub(super) unsafe fn realloc(
    ptr: *mut u8,
    new_size: usize,
    align: usize,
    gfp: Flags,
    nid: i32,
) -> *mut u8 {
    if ptr.is_null() {
        // SAFETY: Same as [`malloc`].
        return unsafe { malloc(new_size, align, gfp, nid, ptr::null_mut()) };
    }
    if new_size == 0 {
        // SAFETY: `ptr` is a live allocation.
        let _ = unsafe { free(ptr) };
        return ptr::null_mut();
    }
    // SAFETY: `ptr` is a live allocation.
    let old = unsafe { usable_size(ptr) };
    if new_size <= old && (ptr as usize) % align.max(1) == 0 {
        return ptr;
    }
    // SAFETY: Same as [`malloc`].
    let n = unsafe { malloc(new_size, align, gfp, nid, ptr::null_mut()) };
    if n.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Both regions are valid; `old.min(new_size)` fits in both.
    unsafe {
        ptr::copy_nonoverlapping(ptr, n, old.min(new_size));
        let _ = free(ptr);
    }
    n
}
