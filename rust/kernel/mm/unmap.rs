// SPDX-License-Identifier: GPL-2.0

//! Userspace VA search and mmap-family dispatch when `CONFIG_RUST_MMAP=y`.
//!
//! Replaces the maple-tree walk in `unmapped_area()` / `unmapped_area_topdown()`
//! with a first-fit (bottom-up or top-down) walk of existing VMAs, and
//! sequences `do_mmap` (prepare vs `mmap_region`), `do_vmi_munmap` (range
//! check vs maple-tree unmap), `do_brk_flags` (expand vs new anonymous VMA),
//! `do_mprotect_pkey` (validate vs VMA walk), `do_mremap` (move vs
//! `mremap_to` vs `mremap_at`), and `do_madvise` (validate vs lock/walk).
//! Maple-tree storage and the `mmap_region` / `mprotect_fixup` /
//! page-table move / madvise VMA-walk bodies stay in C. The mmap lock is
//! already held by the C caller except for mprotect, mremap, and madvise,
//! which take it in apply / lock.

use crate::{
    bindings,
    error::code::{EINVAL, ENOMEM},
    ffi::{c_int, c_ulong},
    mm::virt::VmaRef,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};
use core::ptr;

/// Matches `VM_UNMAPPED_AREA_TOPDOWN` in [`struct vm_unmapped_area_info`].
const TOPDOWN: c_ulong = 1;

/// Cap on VMA visits so a corrupt tree cannot livelock mmap.
const MAX_ITERS: u32 = 1_000_000;

/// Matches `RUST_MUNMAP_*` in `include/linux/mm.h`.
const MUNMAP_DONE: i32 = 0;
/// Overlapping VMA found; maple-tree unmap.
const MUNMAP_ALIGN: i32 = 1;

/// Matches `RUST_DOMMAP_*` in `include/linux/mm.h`.
const DOMMAP_DONE: i32 = 0;
/// Flags and VA chosen; install via `mmap_region`.
const DOMMAP_REGION: i32 = 1;

/// Matches `RUST_BRK_*` in `include/linux/mm.h`.
const BRK_DONE: i32 = 0;
/// Limits passed; try expand or new.
const BRK_CONT: i32 = 1;
/// Need a new anonymous VMA.
const BRK_NEW: i32 = 2;
/// Merge or new succeeded; account the mapping.
const BRK_ACCT: i32 = 3;

/// Matches `RUST_MPROTECT_*` in `include/linux/mm.h`.
const MPROTECT_DONE: i32 = 0;
/// Range is valid; lock and walk VMAs.
const MPROTECT_APPLY: i32 = 1;

/// Matches `RUST_MREMAP_*` in `include/linux/mm.h`.
const MREMAP_DONE: i32 = 0;
/// Params ok, or mmap write lock taken.
const MREMAP_CONT: i32 = 1;
/// Batched multi-VMA move (`remap_move`).
const MREMAP_MOVE: i32 = 2;
/// Move or grow to a new address (`mremap_to`).
const MREMAP_TO: i32 = 3;
/// Shrink or expand in place (`mremap_at`).
const MREMAP_AT: i32 = 4;

/// Matches `RUST_MADVISE_*` in `include/linux/mm.h`.
const MADVISE_DONE: i32 = 0;
/// Range is valid; lock, walk VMAs, unlock.
const MADVISE_APPLY: i32 = 1;

static N_MUNMAP: Atomic<u32> = Atomic::new(0);
static N_DOMMAP: Atomic<u32> = Atomic::new(0);
static N_BRK: Atomic<u32> = Atomic::new(0);
static N_MPROTECT: Atomic<u32> = Atomic::new(0);
static N_MREMAP: Atomic<u32> = Atomic::new(0);
static N_MADVISE: Atomic<u32> = Atomic::new(0);

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

/// Log that Rust is serving `vm_unmapped_area` and mmap-family sequencing.
pub fn announce() {
    pr_info!("rust-mmap: vm_unmapped_area first-fit/topdown and mmap/munmap/brk/mprotect/mremap/madvise sequencer\n");
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

/// C ABI: sequence `do_vmi_munmap` after C checks the range.
///
/// Sets `*handled` once classify has walked the VMA iterator (or
/// rejected the range). Maple-tree split/unmap stays in C.
///
/// # Safety
///
/// mmap write lock held as for `do_vmi_munmap`. `vmi` and `mm` must be
/// live. `handled` must be a valid out-parameter. `uf` may be null.
#[no_mangle]
pub unsafe extern "C" fn rust_munmap_dispatch(
    vmi: *mut bindings::vma_iterator,
    mm: *mut bindings::mm_struct,
    start: c_ulong,
    len: usize,
    uf: *mut bindings::list_head,
    unlock: bool,
    handled: *mut c_int,
) -> c_int {
    if vmi.is_null() || mm.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    let mut vma = ptr::null_mut();
    let mut end: c_ulong = 0;
    // SAFETY: Same lock as `do_vmi_munmap`; iterator positioned at `start`.
    let kind = unsafe {
        bindings::rust_munmap_classify(
            vmi, mm, start, len, unlock, &mut out, &mut vma, &mut end,
        )
    };
    // Classify may advance `vmi` or drop the mmap lock on an empty range.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MUNMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first munmap sequenced\n");
    }

    match kind {
        MUNMAP_DONE => out,
        // SAFETY: Overlapping VMA; mmap write lock still held.
        MUNMAP_ALIGN => unsafe {
            bindings::rust_munmap_align(vmi, vma, mm, start, end, uf, unlock)
        },
        _ => {
            pr_err!("rust-mmap: unknown munmap kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `do_mmap` after C prepares flags and the VA.
///
/// Sets `*handled` once prepare has run (including early errors).
/// `mmap_region` installs the VMA.
///
/// # Safety
///
/// mmap write lock held as for `do_mmap`. Pointer arguments except
/// `file` and `uf` must be live. `handled` must be a valid
/// out-parameter. `file` and `uf` may be null.
#[no_mangle]
pub unsafe extern "C" fn rust_dommap_dispatch(
    file: *mut bindings::file,
    addr: *mut c_ulong,
    len: *mut c_ulong,
    prot: *mut c_ulong,
    flags: *mut c_ulong,
    vma_flags: *mut bindings::vma_flags_t,
    pgoff: *mut c_ulong,
    populate: *mut c_ulong,
    uf: *mut bindings::list_head,
    handled: *mut c_int,
) -> c_ulong {
    if addr.is_null()
        || len.is_null()
        || prot.is_null()
        || flags.is_null()
        || vma_flags.is_null()
        || pgoff.is_null()
        || populate.is_null()
        || handled.is_null()
    {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies writable out-parameters.
    unsafe {
        *handled = 0;
        *populate = 0;
    }

    let mut out: c_ulong = 0;
    // SAFETY: Same lock as `do_mmap`; in/out pointers are live.
    let kind = unsafe {
        bindings::rust_dommap_prepare(
            file, addr, len, prot, flags, vma_flags, pgoff, &mut out,
        )
    };
    // Prepare may have chosen a VA and mutated flags. C must not re-prepare.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_DOMMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mmap sequenced\n");
    }

    match kind {
        DOMMAP_DONE => out,
        DOMMAP_REGION => {
            // SAFETY: Prepare succeeded; mmap write lock still held.
            let mapped = unsafe {
                bindings::rust_dommap_region(
                    file,
                    *addr,
                    *len,
                    vma_flags,
                    *pgoff,
                    uf,
                )
            };
            // SAFETY: `populate` is the live out-parameter from `do_mmap`.
            unsafe {
                bindings::rust_dommap_populate(
                    mapped, *flags, vma_flags, *len, populate,
                );
            }
            mapped
        }
        _ => {
            pr_err!("rust-mmap: unknown mmap kind {kind}\n");
            EINVAL.to_errno() as c_ulong
        }
    }
}

/// C ABI: sequence `do_brk_flags` after C checks limits.
///
/// Sets `*handled` once prepare has run. Expand vs new VMA and
/// accounting stay in C helpers.
///
/// # Safety
///
/// mmap write lock held as for `do_brk_flags`. `vmi` and `vma_flags`
/// must be live. `vma` may be null. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_brk_dispatch(
    vmi: *mut bindings::vma_iterator,
    mut vma: *mut bindings::vm_area_struct,
    addr: c_ulong,
    len: c_ulong,
    vma_flags: *mut bindings::vma_flags_t,
    handled: *mut c_int,
) -> c_int {
    if vmi.is_null() || vma_flags.is_null() || handled.is_null() {
        return ENOMEM.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: Same lock as `do_brk_flags`; `vma_flags` is the live bitmap.
    let kind = unsafe { bindings::rust_brk_prepare(vma_flags, len, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_BRK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first brk sequenced\n");
    }

    if kind == BRK_DONE {
        return out;
    }
    if kind != BRK_CONT {
        pr_err!("rust-mmap: unknown brk prepare kind {kind}\n");
        return ENOMEM.to_errno();
    }

    // SAFETY: Limits passed; try to grow the previous VMA.
    let kind = unsafe { bindings::rust_brk_expand(vmi, vma, addr, len, vma_flags, &mut out) };
    match kind {
        BRK_DONE => return out,
        BRK_ACCT => {}
        BRK_NEW => {
            // SAFETY: Need a new anonymous VMA; may advance `vmi`.
            let kind = unsafe {
                bindings::rust_brk_new(vmi, &mut vma, addr, len, vma_flags, &mut out)
            };
            if kind == BRK_DONE {
                return out;
            }
            if kind != BRK_ACCT {
                pr_err!("rust-mmap: unknown brk new kind {kind}\n");
                return ENOMEM.to_errno();
            }
        }
        _ => {
            pr_err!("rust-mmap: unknown brk expand kind {kind}\n");
            return ENOMEM.to_errno();
        }
    }

    // SAFETY: Expand or new succeeded; `vma` is the live mapping.
    unsafe { bindings::rust_brk_account(vma, len, vma_flags) };
    0
}

/// C ABI: sequence `do_mprotect_pkey` after C validates the range.
///
/// Sets `*handled` once validate has run. The mmap lock and VMA walk
/// stay in C.
///
/// # Safety
///
/// `req` must be a live request filled by `do_mprotect_pkey`. `handled`
/// must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mprotect_dispatch(
    req: *mut bindings::rust_mprotect_req,
    handled: *mut c_int,
) -> c_int {
    if req.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `req` holds the syscall arguments.
    let kind = unsafe { bindings::rust_mprotect_validate(req, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MPROTECT.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mprotect sequenced\n");
    }

    match kind {
        MPROTECT_DONE => out,
        // SAFETY: Range is valid; apply takes the mmap write lock.
        MPROTECT_APPLY => unsafe { bindings::rust_mprotect_apply(req) },
        _ => {
            pr_err!("rust-mmap: unknown mprotect kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `do_mremap` after C aligns lengths and takes the lock.
///
/// Sets `*handled` once prepare has run. Lock-fail and map-count-fail
/// return without `notify_uffd`. Prep-fail and the move/to/at paths
/// go through `mremap_exit` (unlock + populate + uffd).
///
/// # Safety
///
/// `vrm` must be the live `vma_remap_struct` from `do_mremap`. `handled`
/// must be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mremap_dispatch(
    vrm: *mut bindings::vma_remap_struct,
    handled: *mut c_int,
) -> c_ulong {
    if vrm.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    // SAFETY: No mmap lock yet; `vrm` holds the syscall arguments.
    let kind = unsafe { bindings::rust_mremap_prepare(vrm, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MREMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mremap sequenced\n");
    }

    if kind == MREMAP_DONE {
        return out;
    }
    if kind != MREMAP_CONT {
        pr_err!("rust-mmap: unknown mremap prepare kind {kind}\n");
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: Params passed; take the mmap write lock.
    let kind = unsafe { bindings::rust_mremap_lock(vrm, &mut out) };
    if kind == MREMAP_DONE {
        return out;
    }
    if kind != MREMAP_CONT {
        pr_err!("rust-mmap: unknown mremap lock kind {kind}\n");
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: mmap write lock held; classify move vs to vs at.
    let kind = unsafe { bindings::rust_mremap_classify(vrm, &mut out) };
    let res = match kind {
        MREMAP_DONE => out,
        // SAFETY: Locked; batched move of equal-length mappings.
        MREMAP_MOVE => unsafe { bindings::rust_mremap_move(vrm) },
        // SAFETY: Locked; grow or relocate to a new address.
        MREMAP_TO => unsafe { bindings::rust_mremap_to(vrm) },
        // SAFETY: Locked; shrink or expand in place.
        MREMAP_AT => unsafe { bindings::rust_mremap_at(vrm) },
        _ => {
            pr_err!("rust-mmap: unknown mremap classify kind {kind}\n");
            EINVAL.to_errno() as c_ulong
        }
    };
    // SAFETY: Lock was taken; unlock, maybe populate, always notify uffd.
    unsafe { bindings::rust_mremap_exit(vrm, res) }
}

/// C ABI: sequence `do_madvise` after C validates behavior and range.
///
/// Sets `*handled` once prepare has run. Lock, TLB gather, VMA walk,
/// and unlock stay in C apply.
///
/// # Safety
///
/// `mm` must be a live mm. `handled` must be a valid out-parameter.
/// No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_madvise_dispatch(
    mm: *mut bindings::mm_struct,
    start: c_ulong,
    len_in: usize,
    behavior: c_int,
    handled: *mut c_int,
) -> c_int {
    if mm.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; range and behavior are syscall args.
    let kind = unsafe { bindings::rust_madvise_prepare(start, len_in, behavior, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MADVISE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise sequenced\n");
    }

    match kind {
        MADVISE_DONE => out,
        // SAFETY: Range is valid; apply takes the appropriate mmap lock.
        MADVISE_APPLY => unsafe { bindings::rust_madvise_apply(mm, start, len_in, behavior) },
        _ => {
            pr_err!("rust-mmap: unknown madvise kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}
