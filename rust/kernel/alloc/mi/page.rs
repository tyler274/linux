// SPDX-License-Identifier: GPL-2.0

//! Mimalloc-style size-class page: local free list plus concurrent CAS list.

use super::os;
use crate::{
    alloc::Flags,
    bindings,
    sync::atomic::{
        Atomic,
        Relaxed,
        Release, //
    },
};
use core::ptr;

const PAGE_MAGIC: u32 = 0x4D49_5041; // 'MIPA'
const FREED_CANARY: u32 = 0xFEEE_FEEE;
const ALLOC_CANARY: u32 = 0xA110_C8ED;

/// One size-class folio. Metadata lives off-folio (bootstrap bump); objects
/// occupy the whole mapping so `slab_address` is the first object.
#[repr(C)]
pub(super) struct MiPage {
    pub magic: u32,
    pub block_size: u32,
    pub capacity: u32,
    pub used: u32,
    pub order: u32,
    pub local_free: *mut u8,
    pub thread_free: Atomic<*mut u8>,
    pub next: *mut MiPage,
    pub key: usize,
    pub area: *mut u8,
    pub folio: *mut bindings::page,
    pub cache: *mut u8,
}

static KEY_SEQ: Atomic<u64> = Atomic::new(0x9E37_79B9);

fn next_key(page: *mut MiPage) -> usize {
    let n = KEY_SEQ.fetch_add(0x9E37, Relaxed) as usize;
    (page as usize)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(n)
        | 1
}

#[inline]
fn encode(addr: usize, key: usize) -> usize {
    addr.rotate_left(7) ^ key
}

#[inline]
fn decode(enc: usize, key: usize) -> usize {
    (enc ^ key).rotate_right(7)
}

#[inline]
unsafe fn block_next(block: *mut u8, key: usize) -> *mut u8 {
    let enc = unsafe { ptr::read(block.cast::<usize>()) };
    decode(enc, key) as *mut u8
}

#[inline]
unsafe fn set_block_next(block: *mut u8, next: *mut u8, key: usize) {
    unsafe { ptr::write(block.cast::<usize>(), encode(next as usize, key)) };
}

#[inline]
unsafe fn write_canary(block: *mut u8, block_size: u32, val: u32) {
    if block_size as usize >= 16 {
        unsafe { ptr::write(block.add(8).cast::<u32>(), val) };
    }
}

#[inline]
unsafe fn read_canary(block: *mut u8, block_size: u32) -> u32 {
    if block_size as usize >= 16 {
        unsafe { ptr::read(block.add(8).cast::<u32>()) }
    } else {
        0
    }
}

impl MiPage {
    pub(super) fn is_valid(page: *const MiPage) -> bool {
        !page.is_null() && unsafe { (*page).magic == PAGE_MAGIC }
    }

    /// True if `ptr` is a double-free of a block on this page.
    pub(super) unsafe fn is_double_free(&self, ptr: *mut u8) -> bool {
        unsafe { read_canary(ptr, self.block_size) == FREED_CANARY }
    }
}

/// Allocate a new size-class page.
///
/// # Safety
///
/// `block_size` must be at least `size_of::<usize>()` and a multiple of that.
pub(super) unsafe fn create(block_size: u32, gfp: Flags, nid: i32, cache: *mut u8) -> *mut MiPage {
    let need = block_size as usize;
    if need == 0 {
        return ptr::null_mut();
    }
    let mut order: u32 = 0;
    while os::page_size_bytes(order) < need && order < 10 {
        order += 1;
    }
    if os::page_size_bytes(order) < need {
        return ptr::null_mut();
    }
    // Pack at least two small objects when a slightly larger folio is cheap.
    if os::page_size_bytes(order) / need < 2 && order < 3 {
        order += 1;
    }

    // SAFETY: GFP is forwarded to the buddy. Caller must not hold IRQ locks if
    // this GFP combination may sleep.
    let folio = unsafe { os::alloc_folio(order, gfp, nid) };
    if folio.is_null() {
        return ptr::null_mut();
    }

    let meta = meta_alloc();
    if meta.is_null() {
        // SAFETY: We own `folio`.
        unsafe { os::free_folio(folio, order) };
        return ptr::null_mut();
    }

    // SAFETY: Fresh folio in the linear map.
    let area = unsafe { os::page_address(folio) };
    let bytes = os::page_size_bytes(order);
    let capacity = (bytes / need) as u32;
    if capacity == 0 {
        unsafe {
            os::free_folio(folio, order);
            meta_free(meta);
        }
        return ptr::null_mut();
    }

    unsafe {
        ptr::write(
            meta,
            MiPage {
                magic: PAGE_MAGIC,
                block_size,
                capacity,
                used: 0,
                order,
                local_free: ptr::null_mut(),
                thread_free: Atomic::new(ptr::null_mut()),
                next: ptr::null_mut(),
                key: 0,
                area,
                folio,
                cache,
            },
        );
        (*meta).key = next_key(meta);
        init_freelist(meta);
        #[cfg(CONFIG_SLAB_MIMALLOC)]
        os::setup_slab(folio, cache, capacity);
        os::set_meta(folio, meta.cast());
    }
    meta
}

unsafe fn init_freelist(page: *mut MiPage) {
    // SAFETY: `page` is a freshly written `MiPage` with a valid `area`.
    unsafe {
        let p = &*page;
        let mut prev: *mut u8 = ptr::null_mut();
        let mut i = p.capacity;
        while i > 0 {
            i -= 1;
            let block = p.area.add(i as usize * p.block_size as usize);
            set_block_next(block, prev, p.key);
            write_canary(block, p.block_size, FREED_CANARY);
            prev = block;
        }
        (*page).local_free = prev;
    }
}

pub(super) unsafe fn destroy(page: *mut MiPage) {
    if !MiPage::is_valid(page) {
        return;
    }
    // SAFETY: `page` is a valid `MiPage` we own.
    unsafe {
        let p = &mut *page;
        #[cfg(CONFIG_SLAB_MIMALLOC)]
        os::teardown_slab(p.folio);
        os::set_meta(p.folio, ptr::null_mut());
        os::free_folio(p.folio, p.order);
        p.magic = 0;
    }
    meta_free(page);
}

pub(super) unsafe fn pop(page: *mut MiPage) -> *mut u8 {
    // SAFETY: Caller owns `page` (heap lock or exclusive huge page).
    unsafe {
        collect(page);
        let p = &mut *page;
        let block = p.local_free;
        if block.is_null() {
            return ptr::null_mut();
        }
        p.local_free = block_next(block, p.key);
        p.used = p.used.saturating_add(1);
        write_canary(block, p.block_size, ALLOC_CANARY);
        block
    }
}

pub(super) unsafe fn push_local(page: *mut MiPage, block: *mut u8) -> bool {
    // SAFETY: Caller owns `page`; `block` is an object on it.
    unsafe {
        if (*page).is_double_free(block) {
            return false;
        }
        let p = &mut *page;
        set_block_next(block, p.local_free, p.key);
        write_canary(block, p.block_size, FREED_CANARY);
        p.local_free = block;
        p.used = p.used.saturating_sub(1);
        true
    }
}

/// Concurrent free from another CPU / IRQ. Single CAS, no heap lock.
pub(super) unsafe fn push_thread(page: *mut MiPage, block: *mut u8) -> bool {
    // SAFETY: `page` is a live `MiPage`; `block` is an object on it.
    unsafe {
        if (*page).is_double_free(block) {
            return false;
        }
        let p = &*page;
        write_canary(block, p.block_size, FREED_CANARY);
        let mut old = p.thread_free.load(Relaxed);
        loop {
            set_block_next(block, old, p.key);
            match p.thread_free.cmpxchg(old, block, Release) {
                Ok(_) => return true,
                Err(cur) => old = cur,
            }
        }
    }
}

pub(super) unsafe fn collect(page: *mut MiPage) {
    // SAFETY: Caller owns `page` (heap lock).
    unsafe {
        let p = &mut *page;
        let mut old = p.thread_free.load(Relaxed);
        let stolen = loop {
            match p.thread_free.cmpxchg(old, ptr::null_mut(), Relaxed) {
                Ok(_) => break old,
                Err(cur) => old = cur,
            }
        };
        let mut cur = stolen;
        while !cur.is_null() {
            let next = block_next(cur, p.key);
            set_block_next(cur, p.local_free, p.key);
            p.local_free = cur;
            p.used = p.used.saturating_sub(1);
            cur = next;
        }
    }
}

pub(super) fn from_ptr(ptr: *const u8) -> *mut MiPage {
    if ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller must pass a heap object or we return null on mismatch.
    let folio = unsafe { os::virt_to_head_page(ptr) };
    if folio.is_null() {
        return ptr::null_mut();
    }
    let meta = unsafe { os::get_meta(folio) }.cast::<MiPage>();
    if MiPage::is_valid(meta) {
        let p = unsafe { &*meta };
        let bytes = os::page_size_bytes(p.order);
        let addr = ptr as usize;
        let base = p.area as usize;
        if addr >= base && addr < base + bytes {
            return meta;
        }
    }
    ptr::null_mut()
}

const META_CHUNK: usize = 64 * 1024;
static META_LOCK: Atomic<i32> = Atomic::new(0);
static mut BOOT_META: [u8; META_CHUNK] = [0; META_CHUNK];
static mut META_BUMP: *mut u8 = ptr::null_mut();
static mut META_END: *mut u8 = ptr::null_mut();
static mut META_FREE_LIST: *mut MiPage = ptr::null_mut();

fn meta_lock() {
    while META_LOCK.cmpxchg(0, 1, Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

fn meta_unlock() {
    META_LOCK.store(0, Release);
}

#[allow(static_mut_refs)]
fn meta_alloc() -> *mut MiPage {
    meta_lock();
    let p = unsafe {
        if !META_FREE_LIST.is_null() {
            let p = META_FREE_LIST;
            META_FREE_LIST = (*p).next;
            p
        } else {
            let need = core::mem::size_of::<MiPage>();
            if META_BUMP.is_null() {
                META_BUMP = BOOT_META.as_mut_ptr();
                META_END = META_BUMP.add(META_CHUNK);
            }
            if META_BUMP.add(need) > META_END {
                let folio = os::alloc_folio(4, crate::alloc::flags::GFP_ATOMIC, -1);
                if folio.is_null() {
                    ptr::null_mut()
                } else {
                    META_BUMP = os::page_address(folio);
                    META_END = META_BUMP.add(os::page_size_bytes(4));
                    let p = META_BUMP.cast::<MiPage>();
                    META_BUMP = META_BUMP.add(need);
                    p
                }
            } else {
                let p = META_BUMP.cast::<MiPage>();
                META_BUMP = META_BUMP.add(need);
                p
            }
        }
    };
    meta_unlock();
    p
}

#[allow(static_mut_refs)]
fn meta_free(page: *mut MiPage) {
    meta_lock();
    unsafe {
        (*page).next = META_FREE_LIST;
        META_FREE_LIST = page;
    }
    meta_unlock();
}
