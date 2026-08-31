// SPDX-License-Identifier: GPL-2.0

//! Userspace VA search used when `CONFIG_RUST_MMAP=y`.
//!
//! Replaces the maple-tree walk in `unmapped_area()` / `unmapped_area_topdown()`
//! with a first-fit (bottom-up or top-down) walk of existing VMAs. Maple-tree
//! storage, `do_mmap`, and page-fault handling stay in C. The mmap lock is
//! already held by the C caller.

use crate::{
    bindings,
    error::code::ENOMEM,
    ffi::c_ulong,
    mm::virt::VmaRef,
    prelude::*,
};
use core::ptr;

/// Matches `VM_UNMAPPED_AREA_TOPDOWN` in [`struct vm_unmapped_area_info`].
const TOPDOWN: c_ulong = 1;

/// Cap on VMA visits so a corrupt tree cannot livelock mmap.
const MAX_ITERS: u32 = 1_000_000;

fn enomem() -> c_ulong {
    ENOMEM.to_errno() as c_ulong
}

fn mmap_min() -> u64 {
    // SAFETY: C reads this global without a lock in `unmapped_area()`.
    unsafe { bindings::mmap_min_addr as u64 }
}

fn vma_start(vma: *mut bindings::vm_area_struct) -> u64 {
    // SAFETY: `vma` is live and the mmap lock is held (C `vm_unmapped_area` contract).
    unsafe { VmaRef::from_raw(vma).start() as u64 }
}

fn vma_end(vma: *mut bindings::vm_area_struct) -> u64 {
    // SAFETY: Same as [`vma_start`].
    unsafe { VmaRef::from_raw(vma).end() as u64 }
}

fn start_gap(vma: *mut bindings::vm_area_struct) -> u64 {
    // SAFETY: Inline C helper; `vma` is live under the mmap lock.
    unsafe { bindings::vm_start_gap(vma) as u64 }
}

fn end_gap(vma: *mut bindings::vm_area_struct) -> u64 {
    // SAFETY: Same as [`start_gap`].
    unsafe { bindings::vm_end_gap(vma) as u64 }
}

fn find_vma(mm: *mut bindings::mm_struct, addr: u64) -> *mut bindings::vm_area_struct {
    // SAFETY: `mm` is `current->mm`; mmap lock held.
    unsafe { bindings::find_vma(mm, addr as c_ulong) }
}

fn find_vma_prev(
    mm: *mut bindings::mm_struct,
    addr: u64,
) -> (
    *mut bindings::vm_area_struct,
    *mut bindings::vm_area_struct,
) {
    let mut prev = ptr::null_mut();
    // SAFETY: Same as [`find_vma`]; `prev` is a stack out-parameter.
    let vma = unsafe { bindings::find_vma_prev(mm, addr as c_ulong, &mut prev) };
    (vma, prev)
}

fn align_up_off(addr: u64, align_mask: u64, align_offset: u64) -> u64 {
    addr.wrapping_add(align_offset.wrapping_sub(addr) & align_mask)
}

fn align_down_off(addr: u64, align_mask: u64, align_offset: u64) -> u64 {
    addr.wrapping_sub(addr.wrapping_sub(align_offset) & align_mask)
}

struct Search {
    length: u64,
    align_mask: u64,
    align_offset: u64,
    start_gap: u64,
    low: u64,
    high: u64,
}

fn search_from(info: &bindings::vm_unmapped_area_info) -> Option<Search> {
    let length = info.length as u64;
    let align_mask = info.align_mask as u64;
    let start_gap = info.start_gap as u64;
    let worst = length.wrapping_add(align_mask).wrapping_add(start_gap);
    if worst < length {
        return None;
    }
    let low = (info.low_limit as u64).max(mmap_min());
    let high = info.high_limit as u64;
    if low >= high || length == 0 || high - low < length {
        return None;
    }
    Some(Search {
        length,
        align_mask,
        align_offset: info.align_offset as u64,
        start_gap,
        low,
        high,
    })
}

fn place_bottom(gap_start: u64, gap_end: u64, s: &Search) -> Option<u64> {
    if gap_end <= gap_start {
        return None;
    }
    let addr = align_up_off(
        gap_start.wrapping_add(s.start_gap),
        s.align_mask,
        s.align_offset,
    );
    let end = addr.checked_add(s.length)?;
    if addr >= gap_start && end <= gap_end && end <= s.high {
        Some(addr)
    } else {
        None
    }
}

fn place_top(gap_start: u64, gap_end: u64, s: &Search) -> Option<u64> {
    if gap_end <= gap_start || gap_end - gap_start < s.length {
        return None;
    }
    let addr = align_down_off(gap_end - s.length, s.align_mask, s.align_offset);
    let end = addr.checked_add(s.length)?;
    if addr >= gap_start && addr >= s.low && end <= gap_end {
        Some(addr)
    } else {
        None
    }
}

fn unmapped_bottom(mm: *mut bindings::mm_struct, s: &Search) -> Option<u64> {
    let (mut vma, prev) = find_vma_prev(mm, s.low);
    let mut gap_start = s.low;
    if !prev.is_null() {
        gap_start = gap_start.max(end_gap(prev));
    }
    if !vma.is_null() && s.low >= vma_start(vma) && s.low < vma_end(vma) {
        gap_start = gap_start.max(end_gap(vma));
        vma = find_vma(mm, vma_end(vma));
    }

    for _ in 0..MAX_ITERS {
        let gap_end = if vma.is_null() {
            s.high
        } else {
            s.high.min(start_gap(vma))
        };
        if let Some(addr) = place_bottom(gap_start, gap_end, s) {
            return Some(addr);
        }
        if vma.is_null() {
            return None;
        }
        let next = end_gap(vma);
        if next > gap_start {
            gap_start = next;
        } else {
            let ve = vma_end(vma);
            if ve <= gap_start {
                return None;
            }
            gap_start = ve;
        }
        if gap_start >= s.high {
            return None;
        }
        vma = find_vma(mm, gap_start);
    }
    None
}

fn unmapped_topdown(mm: *mut bindings::mm_struct, s: &Search) -> Option<u64> {
    let hint = s.high.saturating_sub(1).max(s.low);
    let (mut vma, mut prev) = find_vma_prev(mm, hint);

    for _ in 0..MAX_ITERS {
        let gap_end = if vma.is_null() {
            s.high
        } else {
            s.high.min(start_gap(vma))
        };
        let gap_start = if prev.is_null() {
            s.low
        } else {
            s.low.max(end_gap(prev))
        };
        if let Some(addr) = place_top(gap_start, gap_end, s) {
            return Some(addr);
        }
        if prev.is_null() {
            return None;
        }
        vma = prev;
        (_, prev) = find_vma_prev(mm, vma_start(vma));
    }
    None
}

/// Log that Rust is serving `vm_unmapped_area`.
pub fn announce() {
    pr_info!("rust-mmap: vm_unmapped_area first-fit/topdown\n");
}

/// C ABI for [`vm_unmapped_area`]: first-fit bottom-up or top-down.
///
/// # Safety
///
/// `info` must be a valid `vm_unmapped_area_info`. The caller must hold the
/// mmap lock on `current->mm` (or the search is for that mm).
#[no_mangle]
pub unsafe extern "C" fn rust_vm_unmapped_area(
    info: *mut bindings::vm_unmapped_area_info,
) -> c_ulong {
    if info.is_null() {
        return enomem();
    }
    // SAFETY: Caller guarantees `info` is a valid unmapped-area request.
    let info = unsafe { &*info };
    let Some(search) = search_from(info) else {
        return enomem();
    };
    let mm = {
        let current = crate::current!();
        match current.mm() {
            Some(mm) => mm.as_raw(),
            None => return enomem(),
        }
    };
    let found = if info.flags & TOPDOWN != 0 {
        unmapped_topdown(mm, &search)
    } else {
        unmapped_bottom(mm, &search)
    };
    found.map(|a| a as c_ulong).unwrap_or_else(enomem)
}
