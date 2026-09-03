// SPDX-License-Identifier: GPL-2.0

//! `msync` and `mincore` sequencers.
//!
//! VMA and residency walks stay in C.

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


/// Matches `RUST_MSYNC_*` in `include/linux/mm.h`.
const MSYNC_DONE: i32 = 0;
/// Flags and range are valid; lock and walk VMAs.
const MSYNC_APPLY: i32 = 1;

/// Matches `RUST_MINCORE_*` in `include/linux/mm.h`.
const MINCORE_DONE: i32 = 0;
/// Range is valid; walk residency into the user vector.
const MINCORE_APPLY: i32 = 1;
static N_MSYNC: Atomic<u32> = Atomic::new(0);
static N_MINCORE: Atomic<u32> = Atomic::new(0);
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
