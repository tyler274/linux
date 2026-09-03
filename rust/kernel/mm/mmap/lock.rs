// SPDX-License-Identifier: GPL-2.0

//! `mlock` / `munlock` sequencers.
//!
//! PTE walks stay in C.

use crate::{
    bindings,
    error::code::EINVAL,
    ffi::c_int,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};


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
static N_MLOCK: Atomic<u32> = Atomic::new(0);
static N_MLFIX: Atomic<u32> = Atomic::new(0);
static N_MUNLOCK: Atomic<u32> = Atomic::new(0);
static N_MLOCKALL: Atomic<u32> = Atomic::new(0);
static N_MUNLOCKALL: Atomic<u32> = Atomic::new(0);
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
