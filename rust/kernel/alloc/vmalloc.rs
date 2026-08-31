// SPDX-License-Identifier: GPL-2.0

//! Virtual-address allocator for the Rust vmalloc replacement.
//!
//! This is the system vmalloc when `CONFIG_RUST_VMALLOC=y`: `mm/vmalloc.c` is
//! not linked. First-fit over `[VMALLOC_START, VMALLOC_END)` with a guard
//! page, off-tree metadata in BSS so it can run before kmalloc.

use crate::{
    bindings,
    ffi::c_ulong,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed,
        Release, //
    },
};
use core::ptr;

/// Maximum number of free+busy fragments in the vmalloc VA space.
const MAX_SLOTS: usize = 4096;

struct Slot {
    start: u64,
    end: u64,
    vm: *mut bindings::vm_struct,
    busy: bool,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            vm: ptr::null_mut(),
            busy: false,
        }
    }
}

struct Vmap {
    lock: Atomic<i32>,
    n: usize,
    slots: [Slot; MAX_SLOTS],
}

impl Vmap {
    const fn new() -> Self {
        Self {
            lock: Atomic::new(0),
            n: 0,
            slots: [const { Slot::empty() }; MAX_SLOTS],
        }
    }
}

struct VmapCell(core::cell::UnsafeCell<Vmap>);

// SAFETY: All mutating access is under [`Vmap::lock`].
unsafe impl Sync for VmapCell {}

static VMAP: VmapCell = VmapCell(core::cell::UnsafeCell::new(Vmap::new()));

fn vmap() -> *mut Vmap {
    VMAP.0.get()
}

fn lock() {
    loop {
        // SAFETY: Process-lifetime TAS on the VA map.
        match unsafe { (*vmap()).lock.cmpxchg(0, 1, Relaxed) } {
            Ok(_) => return,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

fn unlock() {
    // SAFETY: We hold the TAS lock.
    unsafe { (*vmap()).lock.store(0, Release) };
}

fn align_up(addr: u64, align: u64) -> u64 {
    let a = align.max(1);
    (addr + a - 1) & !(a - 1)
}

/// Initialise the free range `[start, end)`.
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_init(start: c_ulong, end: c_ulong) {
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &mut *vmap() };
    v.n = 1;
    v.slots[0] = Slot {
        start: start as u64,
        end: end as u64,
        vm: ptr::null_mut(),
        busy: false,
    };
    unlock();
}

fn insert_slot(v: &mut Vmap, idx: usize, slot: Slot) -> bool {
    if v.n >= MAX_SLOTS {
        return false;
    }
    for i in (idx + 1..=v.n).rev() {
        v.slots[i] = Slot {
            start: v.slots[i - 1].start,
            end: v.slots[i - 1].end,
            vm: v.slots[i - 1].vm,
            busy: v.slots[i - 1].busy,
        };
    }
    v.slots[idx] = slot;
    v.n += 1;
    true
}

fn remove_slot(v: &mut Vmap, idx: usize) {
    for i in idx..v.n - 1 {
        v.slots[i] = Slot {
            start: v.slots[i + 1].start,
            end: v.slots[i + 1].end,
            vm: v.slots[i + 1].vm,
            busy: v.slots[i + 1].busy,
        };
    }
    v.n -= 1;
    v.slots[v.n] = Slot::empty();
}

fn coalesce(v: &mut Vmap) {
    let mut i = 0;
    while i + 1 < v.n {
        if !v.slots[i].busy && !v.slots[i + 1].busy && v.slots[i].end == v.slots[i + 1].start {
            v.slots[i].end = v.slots[i + 1].end;
            remove_slot(v, i + 1);
        } else {
            i += 1;
        }
    }
}

/// Reserve `size` bytes in `[range_start, range_end)` aligned to `align`.
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_alloc(
    size: c_ulong,
    align: c_ulong,
    range_start: c_ulong,
    range_end: c_ulong,
    _flags: c_ulong,
) -> c_ulong {
    if size == 0 {
        return 0;
    }
    let size = size as u64;
    let align = (align as u64).max(crate::page::PAGE_SIZE as u64);
    let range_start = range_start as u64;
    let range_end = range_end as u64;
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &mut *vmap() };
    let mut found = 0u64;
    for i in 0..v.n {
        if v.slots[i].busy {
            continue;
        }
        let lo = v.slots[i].start.max(range_start);
        let hi = v.slots[i].end.min(range_end);
        let start = align_up(lo, align);
        if start < lo || start + size < start || start + size > hi {
            continue;
        }
        let end = start + size;
        // Prefix free fragment.
        if start > v.slots[i].start {
            let prefix = Slot {
                start: v.slots[i].start,
                end: start,
                vm: ptr::null_mut(),
                busy: false,
            };
            v.slots[i].start = start;
            if !insert_slot(v, i, prefix) {
                unlock();
                return 0;
            }
        }
        // `i` may have shifted by the prefix insert.
        let mut idx = i;
        if v.slots[idx].start != start {
            idx += 1;
        }
        if end < v.slots[idx].end {
            let suffix = Slot {
                start: end,
                end: v.slots[idx].end,
                vm: ptr::null_mut(),
                busy: false,
            };
            v.slots[idx].end = end;
            if !insert_slot(v, idx + 1, suffix) {
                unlock();
                return 0;
            }
        }
        v.slots[idx].busy = true;
        v.slots[idx].vm = ptr::null_mut();
        found = start;
        break;
    }
    unlock();
    found as c_ulong
}

/// Bind a reserved range starting at `addr` to `vm`.
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_insert(
    addr: c_ulong,
    size: c_ulong,
    vm: *mut bindings::vm_struct,
) -> i32 {
    let addr = addr as u64;
    let size = size as u64;
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &mut *vmap() };
    let mut rc = -1i32;
    for i in 0..v.n {
        if v.slots[i].start == addr && v.slots[i].end >= addr + size {
            v.slots[i].busy = true;
            v.slots[i].vm = vm;
            rc = 0;
            break;
        }
    }
    // Early import: punch a busy hole out of a free slot.
    if rc != 0 {
        for i in 0..v.n {
            if v.slots[i].busy {
                continue;
            }
            if v.slots[i].start <= addr && addr + size <= v.slots[i].end {
                let slot_end = v.slots[i].end;
                if addr > v.slots[i].start {
                    let prefix = Slot {
                        start: v.slots[i].start,
                        end: addr,
                        vm: ptr::null_mut(),
                        busy: false,
                    };
                    v.slots[i].start = addr;
                    if !insert_slot(v, i, prefix) {
                        unlock();
                        return -1;
                    }
                }
                let mut idx = i;
                if v.slots[idx].start != addr {
                    idx += 1;
                }
                if addr + size < slot_end && addr + size < v.slots[idx].end {
                    let suffix = Slot {
                        start: addr + size,
                        end: v.slots[idx].end,
                        vm: ptr::null_mut(),
                        busy: false,
                    };
                    v.slots[idx].end = addr + size;
                    if !insert_slot(v, idx + 1, suffix) {
                        unlock();
                        return -1;
                    }
                }
                v.slots[idx].busy = true;
                v.slots[idx].vm = vm;
                v.slots[idx].end = addr + size;
                rc = 0;
                break;
            }
        }
    }
    unlock();
    rc
}

/// Look up the `vm_struct` covering `addr`.
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_find(addr: c_ulong) -> *mut bindings::vm_struct {
    let addr = addr as u64;
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &*vmap() };
    let mut vm = ptr::null_mut();
    for i in 0..v.n {
        if v.slots[i].busy && addr >= v.slots[i].start && addr < v.slots[i].end {
            vm = v.slots[i].vm;
            break;
        }
    }
    unlock();
    vm
}

/// Unreserve the range that starts at `addr` (or contains it if it is a base).
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_remove(addr: c_ulong) -> *mut bindings::vm_struct {
    let addr = addr as u64;
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &mut *vmap() };
    let mut vm = ptr::null_mut();
    for i in 0..v.n {
        if v.slots[i].busy && v.slots[i].start == addr {
            vm = v.slots[i].vm;
            v.slots[i].busy = false;
            v.slots[i].vm = ptr::null_mut();
            coalesce(v);
            break;
        }
    }
    unlock();
    vm
}

/// Return the `[start, end)` span covering `addr`.
#[no_mangle]
pub unsafe extern "C" fn rust_vmap_span(
    addr: c_ulong,
    start: *mut c_ulong,
    end: *mut c_ulong,
) -> i32 {
    let addr = addr as u64;
    lock();
    // SAFETY: Lock held.
    let v = unsafe { &*vmap() };
    let mut rc = -1i32;
    for i in 0..v.n {
        if v.slots[i].busy && addr >= v.slots[i].start && addr < v.slots[i].end {
            // SAFETY: Caller provides valid out pointers.
            unsafe {
                *start = v.slots[i].start as c_ulong;
                *end = v.slots[i].end as c_ulong;
            }
            rc = 0;
            break;
        }
    }
    unlock();
    rc
}

/// Allocate, free, or grow a Rust [`Vmalloc`](crate::alloc::allocator::Vmalloc) buffer.
///
/// # Safety
///
/// Same as [`crate::alloc::Allocator::realloc`].
pub unsafe fn realloc(
    ptr: Option<core::ptr::NonNull<u8>>,
    layout: core::alloc::Layout,
    old_layout: core::alloc::Layout,
    flags: crate::alloc::Flags,
    nid: crate::alloc::NumaNode,
) -> Result<core::ptr::NonNull<[u8]>, crate::alloc::AllocError> {
    use crate::alloc::{dangling_from_layout, AllocError};
    use core::ptr::NonNull;

    let size = layout.size();
    if size == 0 {
        if let Some(p) = ptr {
            if old_layout.size() != 0 {
                // SAFETY: `p` is a Vmalloc allocation.
                unsafe { bindings::vfree(p.as_ptr().cast()) };
            }
        }
        return Ok(NonNull::slice_from_raw_parts(
            dangling_from_layout(layout),
            0,
        ));
    }
    let old = match ptr {
        Some(p) if old_layout.size() != 0 => p.as_ptr(),
        _ => ptr::null_mut(),
    };
    // SAFETY: Forwards to the system `vrealloc` we implement.
    let raw = unsafe {
        bindings::vrealloc_node_align(old.cast(), size, layout.align() as _, flags.as_raw(), nid.0)
    };
    NonNull::new(raw.cast::<u8>())
        .map(|p| NonNull::slice_from_raw_parts(p, size))
        .ok_or(AllocError)
}

/// Log that the Rust vmalloc backend replaced `mm/vmalloc.c`.
pub fn announce() {
    pr_info!("rust-vmalloc: page+vmap backend active\n");
}
