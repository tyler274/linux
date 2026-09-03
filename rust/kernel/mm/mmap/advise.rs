// SPDX-License-Identifier: GPL-2.0

//! `madvise` sequencers (`do_madvise`, `vector_madvise`, walk helpers).
//!
//! Per-hint bodies stay in C.

use crate::{
    bindings,
    error::code::EINVAL,
    ffi::{c_int, c_long},
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};


/// Matches `RUST_PMAD_*` in `include/linux/mm.h`.
const PMAD_DONE: i32 = 0;
/// pidfd and iovec acquired; run `vector_madvise` then release.
const PMAD_APPLY: i32 = 1;

/// Matches `RUST_MADVISE_*` in `include/linux/mm.h`.
const MADVISE_DONE: i32 = 0;
/// Range is valid; lock, walk VMAs, unlock.
const MADVISE_APPLY: i32 = 1;

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
static N_MADVISE: Atomic<u32> = Atomic::new(0);
static N_VMADV: Atomic<u32> = Atomic::new(0);
static N_MDO: Atomic<u32> = Atomic::new(0);
static N_MWALK: Atomic<u32> = Atomic::new(0);
static N_MVMA: Atomic<u32> = Atomic::new(0);
static N_MDNF: Atomic<u32> = Atomic::new(0);
static N_MUPD: Atomic<u32> = Atomic::new(0);
static N_PMAD: Atomic<u32> = Atomic::new(0);
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

/// C ABI: sequence `process_madvise` after C imports the iovec and pidfd.
///
/// Sets `*handled` once classify has run. `vector_madvise` stays in C.
/// Unknown kind after acquiring mm/task/iovec releases them.
///
/// # Safety
///
/// `s` must be a live `rust_pmad_state` filled from the syscall args.
/// `handled` must be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_pmad_dispatch(
    s: *mut bindings::rust_pmad_state,
    handled: *mut c_int,
) -> isize {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as isize;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: isize = 0;
    // SAFETY: `s` is live; classify may take a task/mm reference.
    let kind = unsafe { bindings::rust_pmad_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_PMAD.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first process_madvise sequenced\n");
    }

    match kind {
        PMAD_DONE => out,
        // SAFETY: Resources held; walk then mmput/put_task/kfree.
        PMAD_APPLY => unsafe { bindings::rust_pmad_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown process_madvise kind {kind}\n");
            // SAFETY: Drop task/mm/iovec acquired by classify.
            unsafe { bindings::rust_pmad_abort(s) };
            EINVAL.to_errno() as isize
        }
    }
}
