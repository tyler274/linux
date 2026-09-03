// SPDX-License-Identifier: GPL-2.0

//! Protection sequencers (`mprotect`, `mseal`, `change_protection`).
//!
//! Page-table walks and hugetlb bodies stay in C.

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


/// Matches `RUST_CP_*` in `include/linux/mm.h`.
const CP_DONE: i32 = 0;
/// Hugetlb VMA; `hugetlb_change_protection`.
const CP_HUGE: i32 = 1;
/// Regular mapping; PGD-to-PTE walk.
const CP_RANGE: i32 = 2;

/// Matches `RUST_MPROTECT_*` in `include/linux/mm.h`.
const MPROTECT_DONE: i32 = 0;
/// Range is valid; lock and walk VMAs.
const MPROTECT_APPLY: i32 = 1;

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

/// Matches `RUST_MPWALK_*` in `include/linux/mm.h`.
const MPWALK_DONE: i32 = 0;
/// mmap write lock held; walk VMAs then unlock.
const MPWALK_WALK: i32 = 1;
static N_MPROTECT: Atomic<u32> = Atomic::new(0);
static N_CP: Atomic<u32> = Atomic::new(0);
static N_MPFIX: Atomic<u32> = Atomic::new(0);
#[cfg(CONFIG_64BIT)]
static N_MSEAL: Atomic<u32> = Atomic::new(0);
static N_MPWALK: Atomic<u32> = Atomic::new(0);
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

/// C ABI: sequence `mprotect_fixup` after C checks seal, flags, and charge.
///
/// Sets `*handled` once prepare has run. Maple-tree split/merge stays
/// in `vma_modify_flags`; `change_protection` is sequenced separately.
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

/// C ABI: sequence `change_protection` after C picks `newprot`.
///
/// Sets `*handled` once classify has run. Hugetlb and the PGD-to-PTE
/// walk stay in C. Unknown kind is a no-op error.
///
/// # Safety
///
/// `s` must be a live `rust_cp_state` with `tlb`/`vma`/`start`/`end`/
/// `cp_flags` filled. mmap lock held as for `change_protection`.
/// `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_cp_dispatch(
    s: *mut bindings::rust_cp_state,
    handled: *mut c_int,
) -> c_long {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_long;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_long = 0;
    // SAFETY: `s` is live; classify only inspects flags and the VMA.
    let kind = unsafe { bindings::rust_cp_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_CP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first change_protection sequenced\n");
    }

    match kind {
        CP_DONE => out,
        // SAFETY: Hugetlb VMA; walk huge PTEs in C.
        CP_HUGE => unsafe { bindings::rust_cp_huge(s) },
        // SAFETY: Regular mapping; PGD-to-PTE walk in C.
        CP_RANGE => unsafe { bindings::rust_cp_range(s) },
        _ => {
            pr_err!("rust-mmap: unknown change_protection kind {kind}\n");
            EINVAL.to_errno() as c_long
        }
    }
}
