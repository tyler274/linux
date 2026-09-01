// SPDX-License-Identifier: GPL-2.0

//! Userspace VA search and mmap-family dispatch when `CONFIG_RUST_MMAP=y`.
//!
//! Replaces the maple-tree walk in `unmapped_area()` / `unmapped_area_topdown()`
//! with a first-fit (bottom-up or top-down) walk of existing VMAs, and
//! sequences `do_mmap` (prepare vs `mmap_region`), `mmap_region` (MDWE /
//! writable vs merge vs new VMA vs complete), `do_vmi_munmap` (range
//! check vs maple-tree unmap), `do_brk_flags` (expand vs new anonymous VMA),
//! `do_mprotect_pkey` (validate vs VMA walk), `mprotect_fixup` (prepare vs
//! `vma_modify_flags` vs `change_protection`), `do_mremap` (move vs
//! `mremap_to` vs `mremap_at`), `do_madvise` (validate vs lock/walk),
//! `mseal` (validate vs lock/seal), `do_mlock` (prepare vs lock/apply vs
//! populate), `mlock_fixup` (filter vs `vma_modify_flags` vs pages),
//! mprotect VMA walk (lock/pkey/grows vs per-VMA `mprotect_fixup`),
//! `munlock`, `mlockall`, and `munlockall`, `msync` (validate vs VMA
//! walk), `mincore` (validate vs residency walk),
//! `vector_madvise` (lock vs per-iov walk), `madvise_do_behavior`
//! (poison vs populate vs VMA walk), `madvise_walk_vmas`
//! (single-VMA readlock vs iter), `madvise_vma_behavior`
//! (direct action vs ENOMEM convert vs `madvise_update_vma`), and
//! `madvise_dontneed_free` (validate vs zap vs `MADV_FREE`), and
//! `madvise_update_vma` (no-op vs name vs flags), `vma_merge_new_range`
//! (no-merge vs expand), and `__mmap_new_vma` (file vs shmem vs store).
//! Maple-tree expand/store and the merge / new-VMA file mmap/shmem /
//! `change_protection` / page-table move / madvise per-hint / seal-range /
//! mlock page-walk / msync / mincore walk bodies stay in C. The mmap lock is already
//! held by the C caller except for mprotect, mremap, madvise, mseal,
//! mlock, munlock, mlockall, munlockall, msync, mincore, and
//! vector_madvise, which take it in apply / lock.

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

/// Matches `RUST_MMAPREG_*` in `include/linux/mm.h`.
const MMAPREG_DONE: i32 = 0;
/// MDWE and writable checks passed; install then exit.
const MMAPREG_INSTALL: i32 = 1;
/// Setup succeeded; try merge or new.
const MMAPREG_CONT: i32 = 2;
/// Could not merge; allocate a new VMA.
const MMAPREG_NEW: i32 = 3;
/// Have a VMA; complete accounting and unmap.
const MMAPREG_COMPLETE: i32 = 4;

/// Matches `RUST_VMERGE_*` in `include/linux/mm.h`.
const VMERGE_NONE: i32 = 0;
/// Adjacent VMA selected; maple-tree expand.
const VMERGE_EXPAND: i32 = 1;

/// Matches `RUST_MNVA_*` in `include/linux/mm.h`.
const MNVA_DONE: i32 = 0;
/// File-backed; `mmap` callback then store.
const MNVA_FILE: i32 = 1;
/// Shared anonymous; `shmem_zero_setup` then store.
const MNVA_SHMEM: i32 = 2;
/// Anonymous private; maple-tree store.
const MNVA_STORE: i32 = 3;

/// Matches `RUST_MPFIX_*` in `include/linux/mm.h`.
const MPFIX_DONE: i32 = 0;
/// Charge and flag checks passed; split/merge via `vma_modify_flags`.
const MPFIX_MODIFY: i32 = 1;
/// VMA updated; apply protection and accounting.
const MPFIX_APPLY: i32 = 2;

/// Matches `RUST_MSEAL_*` in `include/linux/mm.h`.
#[cfg(CONFIG_64BIT)]
const MSEAL_DONE: i32 = 0;
/// Range is valid; lock and seal VMAs.
#[cfg(CONFIG_64BIT)]
const MSEAL_APPLY: i32 = 1;

/// Matches `RUST_MLOCK_*` in `include/linux/mm.h`.
const MLOCK_DONE: i32 = 0;
/// Capability and alignment passed; lock, apply flags, unlock.
const MLOCK_CONT: i32 = 1;
/// Flags applied; populate the range.
const MLOCK_POPULATE: i32 = 2;

/// Matches `RUST_MLFIX_*` in `include/linux/mm.h`.
const MLFIX_DONE: i32 = 0;
/// Filter passed; split/merge via `vma_modify_flags`.
const MLFIX_MODIFY: i32 = 1;
/// VMA updated; account locked pages and walk PTEs.
const MLFIX_PAGES: i32 = 2;

/// Matches `RUST_MPWALK_*` in `include/linux/mm.h`.
const MPWALK_DONE: i32 = 0;
/// mmap write lock held; walk VMAs then unlock.
const MPWALK_WALK: i32 = 1;

/// Matches `RUST_MUNLOCK_*` in `include/linux/mm.h`.
const MUNLOCK_DONE: i32 = 0;
/// Range aligned; lock and apply unlock flags.
const MUNLOCK_APPLY: i32 = 1;

/// Matches `RUST_MLOCKALL_*` in `include/linux/mm.h`.
const MLOCKALL_DONE: i32 = 0;
/// Flags and capability passed; lock and apply.
const MLOCKALL_CONT: i32 = 1;
/// Applied with `MCL_CURRENT`; populate the address space.
const MLOCKALL_POPULATE: i32 = 2;

/// Matches `RUST_MSYNC_*` in `include/linux/mm.h`.
const MSYNC_DONE: i32 = 0;
/// Flags and range are valid; lock and walk VMAs.
const MSYNC_APPLY: i32 = 1;

/// Matches `RUST_MINCORE_*` in `include/linux/mm.h`.
const MINCORE_DONE: i32 = 0;
/// Range is valid; walk residency into the user vector.
const MINCORE_APPLY: i32 = 1;

/// Matches `RUST_VMADV_*` in `include/linux/mm.h`.
const VMADV_DONE: i32 = 0;
/// mmap lock taken; walk each iovec then unlock.
const VMADV_WALK: i32 = 1;

/// Matches `RUST_MDO_*` in `include/linux/mm.h`.
const MDO_DONE: i32 = 0;
/// Prefault via `madvise_populate`.
const MDO_POPULATE: i32 = 1;
/// Walk VMAs via `madvise_walk_vmas`.
const MDO_WALK: i32 = 2;

/// Matches `RUST_MWALK_*` in `include/linux/mm.h`.
const MWALK_DONE: i32 = 0;
/// Need the multi-VMA iterator.
const MWALK_ITER: i32 = 1;

/// Matches `RUST_MVMA_*` in `include/linux/mm.h`.
const MVMA_DIRECT: i32 = 0;
/// Helper error; convert `-ENOMEM` to `-EAGAIN` and skip `madvise_update_vma`.
const MVMA_CONVERT: i32 = 1;
/// Flag change; `madvise_update_vma` then convert.
const MVMA_UPDATE: i32 = 2;

/// Matches `RUST_MDNF_*` in `include/linux/mm.h`.
const MDNF_DONE: i32 = 0;
/// Zap via `madvise_dontneed_single_vma`.
const MDNF_DONTNEED: i32 = 1;
/// Lazy free via `madvise_free_single_vma`.
const MDNF_FREE: i32 = 2;

/// Matches `RUST_MUPD_*` in `include/linux/mm.h`.
const MUPD_DONE: i32 = 0;
/// Split/merge via `vma_modify_name` then set the anon name.
const MUPD_NAME: i32 = 1;
/// Split/merge via `vma_modify_flags`.
const MUPD_FLAGS: i32 = 2;

static N_MUNMAP: Atomic<u32> = Atomic::new(0);
static N_DOMMAP: Atomic<u32> = Atomic::new(0);
static N_BRK: Atomic<u32> = Atomic::new(0);
static N_MPROTECT: Atomic<u32> = Atomic::new(0);
static N_MREMAP: Atomic<u32> = Atomic::new(0);
static N_MADVISE: Atomic<u32> = Atomic::new(0);
static N_MMAPREG: Atomic<u32> = Atomic::new(0);
static N_VMERGE: Atomic<u32> = Atomic::new(0);
static N_MNVA: Atomic<u32> = Atomic::new(0);
static N_MPFIX: Atomic<u32> = Atomic::new(0);
#[cfg(CONFIG_64BIT)]
static N_MSEAL: Atomic<u32> = Atomic::new(0);
static N_MLOCK: Atomic<u32> = Atomic::new(0);
static N_MLFIX: Atomic<u32> = Atomic::new(0);
static N_MPWALK: Atomic<u32> = Atomic::new(0);
static N_MUNLOCK: Atomic<u32> = Atomic::new(0);
static N_MLOCKALL: Atomic<u32> = Atomic::new(0);
static N_MUNLOCKALL: Atomic<u32> = Atomic::new(0);
static N_MSYNC: Atomic<u32> = Atomic::new(0);
static N_MINCORE: Atomic<u32> = Atomic::new(0);
static N_VMADV: Atomic<u32> = Atomic::new(0);
static N_MDO: Atomic<u32> = Atomic::new(0);
static N_MWALK: Atomic<u32> = Atomic::new(0);
static N_MVMA: Atomic<u32> = Atomic::new(0);
static N_MDNF: Atomic<u32> = Atomic::new(0);
static N_MUPD: Atomic<u32> = Atomic::new(0);

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
    pr_info!("rust-mmap: vm_unmapped_area first-fit/topdown and mmap/munmap/brk/mprotect/mremap/madvise/mmap_region/mprotect_fixup/mseal/mlock/mlock_fixup/mprotect_walk/munlock/mlockall/msync/mincore/vector_madvise/madvise_do/madvise_walk/madvise_vma/madvise_dontneed/madvise_update/vma_merge/mmap_new sequencer\n");
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

/// C ABI: sequence `mmap_region` after C checks MDWE and writable mappings.
///
/// Sets `*handled` once check has run. Install (merge vs new VMA) and
/// writable-mapping cleanup stay in C helpers. Early check errors skip
/// `validate_mm`, matching the original `mmap_region` returns.
///
/// # Safety
///
/// mmap write lock held as for `mmap_region`. `vma_flags` must be live.
/// `file` and `uf` may be null. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mmap_region_dispatch(
    file: *mut bindings::file,
    addr: c_ulong,
    len: c_ulong,
    vma_flags: *mut bindings::vma_flags_t,
    pgoff: c_ulong,
    uf: *mut bindings::list_head,
    handled: *mut c_int,
) -> c_ulong {
    if vma_flags.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    let mut writable: c_int = 0;
    // SAFETY: mmap write lock held; `vma_flags` is the live bitmap.
    let kind = unsafe { bindings::rust_mmapreg_check(file, vma_flags, &mut writable, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MMAPREG.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mmap_region sequenced\n");
    }

    if kind == MMAPREG_DONE {
        return out;
    }
    if kind != MMAPREG_INSTALL {
        pr_err!("rust-mmap: unknown mmap_region check kind {kind}\n");
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: Checks passed; maple-tree install may nest inner dispatch.
    let mapped = unsafe {
        bindings::rust_mmapreg_install(file, addr, len, vma_flags, pgoff, uf)
    };
    // SAFETY: Writable mapping (if any) must be dropped; always validate.
    unsafe { bindings::rust_mmapreg_exit(file, writable, mapped) }
}

/// C ABI: sequence `__mmap_region` setup vs merge vs new vs complete.
///
/// Sets `*handled` once setup has run (it may gather overlapping VMAs).
/// Merge classify vs expand and new-VMA file/shmem vs store are nested.
///
/// # Safety
///
/// mmap write lock held. `map` and `desc` must be the live stack state
/// from `__mmap_region`. `uf` may be null. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mmapreg_inner_dispatch(
    map: *mut bindings::mmap_state,
    desc: *mut bindings::vm_area_desc,
    uf: *mut bindings::list_head,
    have_mmap_prepare: c_int,
    handled: *mut c_int,
) -> c_ulong {
    if map.is_null() || desc.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    // SAFETY: `map`/`desc` are live stack objects; may unmap overlaps.
    let kind =
        unsafe { bindings::rust_mmapreg_setup(map, desc, uf, have_mmap_prepare, &mut out) };
    // Setup gathers overlapping VMAs; C must not re-setup.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    if kind == MMAPREG_DONE {
        // SAFETY: Setup failed; abort gathered unmaps.
        unsafe { bindings::rust_mmapreg_abort(map) };
        return out;
    }
    if kind != MMAPREG_CONT {
        pr_err!("rust-mmap: unknown mmap_region setup kind {kind}\n");
        unsafe { bindings::rust_mmapreg_abort(map) };
        return EINVAL.to_errno() as c_ulong;
    }

    let mut vma = ptr::null_mut();
    // SAFETY: Setup succeeded; try to merge with adjacent VMAs.
    let kind = unsafe { bindings::rust_mmapreg_merge(map, &mut vma) };
    let mut allocated: c_int = 0;
    if kind == MMAPREG_NEW {
        // SAFETY: Need a new VMA; maple-tree store stays in C.
        let kind = unsafe { bindings::rust_mmapreg_new(map, desc, &mut vma, &mut out) };
        if kind == MMAPREG_DONE {
            // SAFETY: New VMA failed after accounting; uncharge and abort.
            unsafe { bindings::rust_mmapreg_unacct_abort(map) };
            return out;
        }
        if kind != MMAPREG_COMPLETE {
            pr_err!("rust-mmap: unknown mmap_region new kind {kind}\n");
            unsafe { bindings::rust_mmapreg_unacct_abort(map) };
            return EINVAL.to_errno() as c_ulong;
        }
        allocated = 1;
    } else if kind != MMAPREG_COMPLETE {
        pr_err!("rust-mmap: unknown mmap_region merge kind {kind}\n");
        unsafe { bindings::rust_mmapreg_unacct_abort(map) };
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: `vma` is the merged or newly stored mapping.
    unsafe {
        bindings::rust_mmapreg_complete(map, vma, desc, have_mmap_prepare, allocated)
    }
}

/// C ABI: sequence `mprotect_fixup` after C checks seal, flags, and charge.
///
/// Sets `*handled` once prepare has run. Maple-tree split/merge stays
/// in `vma_modify_flags`; PTE updates stay in `change_protection`.
///
/// # Safety
///
/// mmap write lock held as for `mprotect_fixup`. `s` must be the live
/// state filled by `mprotect_fixup`. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mpfix_dispatch(
    s: *mut bindings::rust_mpfix_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: mmap write lock held; `s` holds the VMA range and new flags.
    let kind = unsafe { bindings::rust_mpfix_prepare(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MPFIX.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mprotect_fixup sequenced\n");
    }

    if kind == MPFIX_DONE {
        return out;
    }
    if kind != MPFIX_MODIFY {
        pr_err!("rust-mmap: unknown mprotect_fixup prepare kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Charge/flags passed; split or merge the VMA.
    let kind = unsafe { bindings::rust_mpfix_modify(s, &mut out) };
    if kind == MPFIX_DONE {
        return out;
    }
    if kind != MPFIX_APPLY {
        pr_err!("rust-mmap: unknown mprotect_fixup modify kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: `s->vma` is the live mapping after modify.
    unsafe { bindings::rust_mpfix_apply(s) }
}

/// C ABI: sequence `mseal` after C validates flags and alignment.
///
/// Sets `*handled` once validate has run. The mmap lock and VMA seal
/// walk stay in C.
///
/// # Safety
///
/// `req` must be a live request filled by `do_mseal`. `handled` must
/// be a valid out-parameter. No mmap lock is held on entry.
#[cfg(CONFIG_64BIT)]
#[no_mangle]
pub unsafe extern "C" fn rust_mseal_dispatch(
    req: *mut bindings::rust_mseal_req,
    handled: *mut c_int,
) -> c_int {
    if req.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `req` holds the syscall arguments.
    let kind = unsafe { bindings::rust_mseal_validate(req, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MSEAL.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mseal sequenced\n");
    }

    match kind {
        MSEAL_DONE => out,
        // SAFETY: Range is valid; apply takes the mmap write lock.
        MSEAL_APPLY => unsafe { bindings::rust_mseal_apply(req) },
        _ => {
            pr_err!("rust-mmap: unknown mseal kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `do_mlock` after C checks capability and alignment.
///
/// Sets `*handled` once prepare has run. Lock-fail and apply-fail
/// return without populate. Success unlocks, then populates.
///
/// # Safety
///
/// `start`, `len`, `flags`, and `handled` must be valid. No mmap lock
/// is held on entry. Prepare may rewrite `*start` and `*len`.
#[no_mangle]
pub unsafe extern "C" fn rust_mlock_dispatch(
    start: *mut c_ulong,
    len: *mut usize,
    flags: *mut bindings::vma_flags_t,
    handled: *mut c_int,
) -> c_int {
    if start.is_null() || len.is_null() || flags.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; pointers are the syscall arguments.
    let kind = unsafe { bindings::rust_mlock_prepare(start, len, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MLOCK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mlock sequenced\n");
    }

    if kind == MLOCK_DONE {
        return out;
    }
    if kind != MLOCK_CONT {
        pr_err!("rust-mmap: unknown mlock prepare kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Aligned range; apply takes the mmap write lock.
    let kind = unsafe { bindings::rust_mlock_apply(*start, *len, flags, &mut out) };
    if kind == MLOCK_DONE {
        return out;
    }
    if kind != MLOCK_POPULATE {
        pr_err!("rust-mmap: unknown mlock apply kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Flags applied and mmap lock dropped; populate the range.
    unsafe { bindings::rust_mlock_populate(*start, *len) }
}

/// C ABI: sequence `mlock_fixup` after C filters special VMAs.
///
/// Sets `*handled` once prepare has run. Maple-tree split/merge stays
/// in `vma_modify_flags`; PTE mlock/munlock stays in C.
///
/// # Safety
///
/// mmap write lock held as for `mlock_fixup`. `s` must be the live
/// state filled by `mlock_fixup`. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mlfix_dispatch(
    s: *mut bindings::rust_mlfix_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: mmap write lock held; `s` holds the VMA range and new flags.
    let kind = unsafe { bindings::rust_mlfix_prepare(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MLFIX.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mlock_fixup sequenced\n");
    }

    if kind == MLFIX_DONE {
        return out;
    }
    if kind != MLFIX_MODIFY {
        pr_err!("rust-mmap: unknown mlock_fixup prepare kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Filter passed; split or merge the VMA.
    let kind = unsafe { bindings::rust_mlfix_modify(s, &mut out) };
    if kind == MLFIX_DONE {
        return out;
    }
    if kind != MLFIX_PAGES {
        pr_err!("rust-mmap: unknown mlock_fixup modify kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: `s->vma` is the live mapping after modify.
    unsafe { bindings::rust_mlfix_pages(s) }
}

/// C ABI: sequence the `mprotect` VMA walk after C takes the mmap lock.
///
/// Sets `*handled` once lock/pkey/grows setup has run. Failure paths
/// unlock before returning `DONE`. The per-VMA flag calc and
/// `mprotect_fixup` stay in C.
///
/// # Safety
///
/// `s` must be live stack state from `mprotect_apply`. `handled` must
/// be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mprot_dispatch(
    s: *mut bindings::rust_mprot_walk,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `s->req` holds the validated range.
    let kind = unsafe { bindings::rust_mprot_lock(s, &mut out) };
    // SAFETY: `handled` is valid. Lock-fail already dropped the lock.
    unsafe { *handled = 1 };

    let prev = N_MPWALK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mprotect walk sequenced\n");
    }

    if kind == MPWALK_DONE {
        return out;
    }
    if kind != MPWALK_WALK {
        pr_err!("rust-mmap: unknown mprotect lock kind {kind}\n");
        // SAFETY: Unexpected kind after a successful lock; drop it.
        unsafe { bindings::rust_mprot_unlock() };
        return EINVAL.to_errno();
    }

    // SAFETY: mmap write lock held; iterator is positioned on the range.
    unsafe { bindings::rust_mprot_walk(s) }
}

/// C ABI: sequence `munlock` after C aligns the range.
///
/// Sets `*handled` once prepare has run. The mmap lock and VMA walk
/// stay in C.
///
/// # Safety
///
/// `start`, `len`, and `handled` must be valid. Prepare may rewrite
/// `*start` and `*len`. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_munlock_dispatch(
    start: *mut c_ulong,
    len: *mut usize,
    handled: *mut c_int,
) -> c_int {
    if start.is_null() || len.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; pointers are the syscall arguments.
    let kind = unsafe { bindings::rust_munlock_prepare(start, len, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MUNLOCK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first munlock sequenced\n");
    }

    match kind {
        MUNLOCK_DONE => out,
        // SAFETY: Range is aligned; apply takes the mmap write lock.
        MUNLOCK_APPLY => unsafe { bindings::rust_munlock_apply(*start, *len) },
        _ => {
            pr_err!("rust-mmap: unknown munlock kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `mlockall` after C validates flags and capability.
///
/// Sets `*handled` once prepare has run. Lock-fail and apply-fail skip
/// populate. `MCL_CURRENT` success populates after unlock.
///
/// # Safety
///
/// `handled` must be a valid out-parameter. No mmap lock is held on
/// entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mlockall_dispatch(flags: c_int, handled: *mut c_int) -> c_int {
    if handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `flags` is the syscall argument.
    let kind = unsafe { bindings::rust_mlockall_prepare(flags, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MLOCKALL.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mlockall sequenced\n");
    }

    if kind == MLOCKALL_DONE {
        return out;
    }
    if kind != MLOCKALL_CONT {
        pr_err!("rust-mmap: unknown mlockall prepare kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Flags ok; apply takes the mmap write lock.
    let kind = unsafe { bindings::rust_mlockall_apply(flags, &mut out) };
    if kind == MLOCKALL_DONE {
        return out;
    }
    if kind != MLOCKALL_POPULATE {
        pr_err!("rust-mmap: unknown mlockall apply kind {kind}\n");
        return EINVAL.to_errno();
    }

    // SAFETY: Applied with MCL_CURRENT; mmap lock already dropped.
    unsafe { bindings::rust_mlockall_populate() };
    0
}

/// C ABI: sequence `munlockall` (lock, clear VMA lock flags, unlock).
///
/// Sets `*handled` before apply. The mmap lock stays in C.
///
/// # Safety
///
/// `handled` must be a valid out-parameter. No mmap lock is held on
/// entry.
#[no_mangle]
pub unsafe extern "C" fn rust_munlockall_dispatch(handled: *mut c_int) -> c_int {
    if handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MUNLOCKALL.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first munlockall sequenced\n");
    }

    // SAFETY: Apply takes and drops the mmap write lock.
    unsafe { bindings::rust_munlockall_apply() }
}

/// C ABI: sequence `msync` after C validates flags and alignment.
///
/// Sets `*handled` once validate has run. The mmap lock and VMA walk
/// (including dropping the lock around `vfs_fsync_range`) stay in C.
///
/// # Safety
///
/// `req` must be a live request filled by `do_msync`. `handled` must
/// be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_msync_dispatch(
    req: *mut bindings::rust_msync_req,
    handled: *mut c_int,
) -> c_int {
    if req.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `req` holds the syscall arguments.
    let kind = unsafe { bindings::rust_msync_validate(req, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MSYNC.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first msync sequenced\n");
    }

    match kind {
        MSYNC_DONE => out,
        // SAFETY: Range is valid; apply takes the mmap read lock.
        MSYNC_APPLY => unsafe { bindings::rust_msync_apply(req) },
        _ => {
            pr_err!("rust-mmap: unknown msync kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `mincore` after C validates alignment and access.
///
/// Sets `*handled` once validate has run. The mmap lock, page-table
/// residency walk, and `copy_to_user` stay in C.
///
/// # Safety
///
/// `req` must be a live request filled by `do_mincore_sys`. `handled`
/// must be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mincore_dispatch(
    req: *mut bindings::rust_mincore_req,
    handled: *mut c_int,
) -> c_long {
    if req.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_long;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `req` holds the syscall arguments.
    let kind = unsafe { bindings::rust_mincore_validate(req, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MINCORE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mincore sequenced\n");
    }

    match kind {
        MINCORE_DONE => out as c_long,
        // SAFETY: Range is valid; apply walks under the mmap read lock.
        MINCORE_APPLY => unsafe { bindings::rust_mincore_apply(req) },
        _ => {
            pr_err!("rust-mmap: unknown mincore kind {kind}\n");
            EINVAL.to_errno() as c_long
        }
    }
}

/// C ABI: sequence `vector_madvise` after C takes the madvise lock.
///
/// Sets `*handled` once lock/init-tlb has run. Lock-fail returns
/// without walking. The per-iov `madvise_do_behavior` body stays in C.
///
/// # Safety
///
/// `s` must be live stack state from `vector_madvise`. `handled` must
/// be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_vmadvise_dispatch(
    s: *mut bindings::rust_vmadvise_state,
    handled: *mut c_int,
) -> isize {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as isize;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: No mmap lock yet; `s` holds mm, iov, and behavior.
    let kind = unsafe { bindings::rust_vmadvise_lock(s, &mut out) };
    // SAFETY: `handled` is valid. Lock-fail never took the lock.
    unsafe { *handled = 1 };

    let prev = N_VMADV.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vector_madvise sequenced\n");
    }

    if kind == VMADV_DONE {
        return out as isize;
    }
    if kind != VMADV_WALK {
        pr_err!("rust-mmap: unknown vector_madvise lock kind {kind}\n");
        // SAFETY: Unexpected kind after a successful lock; drop tlb/lock.
        unsafe { bindings::rust_vmadvise_abort(s) };
        return EINVAL.to_errno() as isize;
    }

    // SAFETY: Lock held and tlb initialized; walk iovecs then unlock.
    unsafe { bindings::rust_vmadvise_walk(s) }
}

/// C ABI: sequence `madvise_do_behavior` after C classifies the hint.
///
/// Sets `*handled` once classify has run. Hardware-poison returns
/// immediately. Populate and VMA-walk stay in C (with `blk_plug`).
///
/// # Safety
///
/// `m` must be the live `madvise_behavior` from `madvise_apply` or
/// `vector_madvise`. `handled` must be a valid out-parameter. The
/// madvise mmap lock is already held as for `madvise_do_behavior`.
#[no_mangle]
pub unsafe extern "C" fn rust_mdo_dispatch(
    start: c_ulong,
    len_in: usize,
    m: *mut bindings::madvise_behavior,
    handled: *mut c_int,
) -> c_int {
    if m.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `m` is live; classify may run inject_error for poison.
    let kind = unsafe { bindings::rust_mdo_classify(start, len_in, m, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MDO.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise_do sequenced\n");
    }

    match kind {
        MDO_DONE => out,
        // SAFETY: Prefault hint; populate under the existing lock.
        MDO_POPULATE => unsafe { bindings::rust_mdo_populate(m) },
        // SAFETY: Range set; walk VMAs (may nest `rust_mwalk_dispatch`).
        MDO_WALK => unsafe { bindings::rust_mdo_walk(m) },
        _ => {
            pr_err!("rust-mmap: unknown madvise_do kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `madvise_walk_vmas` after C tries a single-VMA lock.
///
/// Sets `*handled` once start has run. The single-VMA readlock path
/// returns without iterating. Per-VMA `madvise_vma_behavior` is
/// sequenced separately.
///
/// # Safety
///
/// `m` must be live with `range` filled. `handled` must be a valid
/// out-parameter. mmap lock held as for `madvise_walk_vmas`.
#[no_mangle]
pub unsafe extern "C" fn rust_mwalk_dispatch(
    m: *mut bindings::madvise_behavior,
    handled: *mut c_int,
) -> c_int {
    if m.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `m` is live; may take a per-VMA read lock.
    let kind = unsafe { bindings::rust_mwalk_start(m, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MWALK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise_walk sequenced\n");
    }

    match kind {
        MWALK_DONE => out,
        // SAFETY: Need the multi-VMA iterator; find_vma stays in C.
        MWALK_ITER => unsafe { bindings::rust_mwalk_iter(m) },
        _ => {
            pr_err!("rust-mmap: unknown madvise_walk kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `madvise_vma_behavior` after C classifies the hint.
///
/// Sets `*handled` once classify has run. Direct helpers (`DONTNEED`,
/// `REMOVE`, ...) return as-is. KSM/THP errors convert `-ENOMEM` to
/// `-EAGAIN` without updating the VMA. Flag-update hints call
/// `madvise_update_vma` in C.
///
/// # Safety
///
/// `s` must be a live `rust_mvma_state` with `m` filled. `handled`
/// must be a valid out-parameter. mmap lock held as for
/// `madvise_vma_behavior`.
#[no_mangle]
pub unsafe extern "C" fn rust_mvma_dispatch(
    s: *mut bindings::rust_mvma_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may call per-hint helpers.
    let kind = unsafe { bindings::rust_mvma_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MVMA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise_vma sequenced\n");
    }

    match kind {
        MVMA_DIRECT => out,
        // SAFETY: Helper failed; convert ENOMEM without updating flags.
        MVMA_CONVERT => unsafe { bindings::rust_mvma_convert(out) },
        // SAFETY: Flags updated in classify; split/merge stays in C.
        MVMA_UPDATE => unsafe { bindings::rust_mvma_update(s) },
        _ => {
            pr_err!("rust-mmap: unknown madvise_vma kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `madvise_dontneed_free` after C validates the VMA.
///
/// Sets `*handled` once classify has run (including the optional
/// userfaultfd lock drop and re-lookup). Zap and lazy-free stay in C.
///
/// # Safety
///
/// `m` must be the live `madvise_behavior` from `madvise_vma_behavior`.
/// `handled` must be a valid out-parameter. mmap lock held as for
/// `madvise_dontneed_free`.
#[no_mangle]
pub unsafe extern "C" fn rust_mdnf_dispatch(
    m: *mut bindings::madvise_behavior,
    handled: *mut c_int,
) -> c_long {
    if m.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_long;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_long = 0;
    // SAFETY: `m` is live; classify may drop and retake the mmap lock.
    let kind = unsafe { bindings::rust_mdnf_classify(m, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MDNF.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise_dontneed sequenced\n");
    }

    match kind {
        MDNF_DONE => out,
        // SAFETY: Discard pages; zap stays in C.
        MDNF_DONTNEED => unsafe { bindings::rust_mdnf_dontneed(m) },
        // SAFETY: Lazy free; page walk stays in C.
        MDNF_FREE => unsafe { bindings::rust_mdnf_free(m) },
        _ => {
            pr_err!("rust-mmap: unknown madvise_dontneed kind {kind}\n");
            EINVAL.to_errno() as c_long
        }
    }
}

/// C ABI: sequence `madvise_update_vma` after C compares flags/name.
///
/// Sets `*handled` once classify has run. Maple-tree split/merge via
/// `vma_modify_name` / `vma_modify_flags` stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_mupd_state` with `m` and `new_flags`
/// filled. `handled` must be a valid out-parameter. mmap write lock
/// held as for `madvise_update_vma`.
#[no_mangle]
pub unsafe extern "C" fn rust_mupd_dispatch(
    s: *mut bindings::rust_mupd_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify only compares flags and name.
    let kind = unsafe { bindings::rust_mupd_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MUPD.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first madvise_update sequenced\n");
    }

    match kind {
        MUPD_DONE => out,
        // SAFETY: Anon name change; vma_modify_name stays in C.
        MUPD_NAME => unsafe { bindings::rust_mupd_name(s) },
        // SAFETY: Flag change; vma_modify_flags stays in C.
        MUPD_FLAGS => unsafe { bindings::rust_mupd_flags(s) },
        _ => {
            pr_err!("rust-mmap: unknown madvise_update kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `vma_merge_new_range` after C classifies adjacency.
///
/// Sets `*handled` once classify has adjusted `vmg`. Maple-tree
/// expand stays in C.
///
/// # Safety
///
/// `vmg` must be a live merge request with mmap write lock held.
/// `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vmerge_dispatch(
    vmg: *mut bindings::vma_merge_struct,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if vmg.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `vmg` is live; classify may adjust start/end/target.
    let kind = unsafe { bindings::rust_vmerge_classify(vmg) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VMERGE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_merge sequenced\n");
    }

    match kind {
        VMERGE_NONE => ptr::null_mut(),
        // SAFETY: Target selected; `vma_expand` stays in C.
        VMERGE_EXPAND => unsafe { bindings::rust_vmerge_expand(vmg) },
        _ => {
            pr_err!("rust-mmap: unknown vma_merge kind {kind}\n");
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `__mmap_new_vma` after C allocates and preallocates.
///
/// Sets `*handled` once classify has run. File `mmap`, shmem setup,
/// and maple-tree store stay in C. Unknown kind after a successful
/// prealloc aborts the iterator and frees the VMA.
///
/// # Safety
///
/// `s` must be a live `rust_mnva_state` from `__mmap_new_vma`. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mnva_dispatch(
    s: *mut bindings::rust_mnva_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may alloc a VMA and prealloc the iterator.
    let kind = unsafe { bindings::rust_mnva_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MNVA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mmap_new sequenced\n");
    }

    let callback_err = match kind {
        MNVA_DONE => return out,
        // SAFETY: File-backed mapping; driver mmap stays in C.
        MNVA_FILE => unsafe { bindings::rust_mnva_file(s) },
        // SAFETY: Shared anonymous; shmem setup stays in C.
        MNVA_SHMEM => unsafe { bindings::rust_mnva_shmem(s) },
        MNVA_STORE => 0,
        _ => {
            pr_err!("rust-mmap: unknown mmap_new kind {kind}\n");
            // SAFETY: Prealloc succeeded; drop the iterator and VMA.
            unsafe { bindings::rust_mnva_abort(s) };
            return EINVAL.to_errno();
        }
    };
    if callback_err != 0 {
        // SAFETY: File/shmem failed after prealloc; free iterator and VMA.
        unsafe { bindings::rust_mnva_abort(s) };
        return callback_err;
    }
    // SAFETY: Callbacks succeeded (or anon); insert into the maple tree.
    unsafe { bindings::rust_mnva_store(s) }
}
