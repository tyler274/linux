// SPDX-License-Identifier: GPL-2.0

//! brk sequencers (`do_brk_flags`, `brk`, `vm_brk_flags`).

use crate::{
    bindings,
    error::code::EINVAL,
    ffi::{c_int, c_ulong},
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};


/// Matches `RUST_BRK_*` in `include/linux/mm.h`.
const BRK_DONE: i32 = 0;
/// Limits passed; try expand or new.
const BRK_CONT: i32 = 1;
/// Need a new anonymous VMA.
const BRK_NEW: i32 = 2;
/// Merge or new succeeded; account the mapping.
const BRK_ACCT: i32 = 3;

/// Matches `RUST_SYSBRK_*` in `include/linux/mm.h`.
const SYSBRK_DONE: i32 = 0;
/// brk updated; unlock if needed, then uffd and maybe populate.
const SYSBRK_EXIT: i32 = 1;

/// Matches `RUST_VMBRK_*` in `include/linux/mm.h`.
const VMBRK_DONE: i32 = 0;
/// Unlocked; uffd complete and maybe populate.
const VMBRK_EXIT: i32 = 1;
static N_BRK: Atomic<u32> = Atomic::new(0);
static N_SYSBRK: Atomic<u32> = Atomic::new(0);
static N_VMBRK: Atomic<u32> = Atomic::new(0);
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

/// C ABI: sequence `brk` after C takes the mmap lock and classifies shrink vs expand.
///
/// Sets `*handled` once classify has run. Successful shrink may already
/// have dropped the lock. uffd complete and `mm_populate` stay in C.
/// Unknown kind after a held lock restores `origbrk` and unlocks.
///
/// # Safety
///
/// `s` must be a live `rust_sysbrk_state` with `brk` filled. `handled`
/// must be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_sysbrk_dispatch(
    s: *mut bindings::rust_sysbrk_state,
    handled: *mut c_int,
) -> c_ulong {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    // SAFETY: `s` is live; classify takes the mmap write lock.
    let kind = unsafe { bindings::rust_sysbrk_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_SYSBRK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first sys_brk sequenced\n");
    }

    match kind {
        SYSBRK_DONE => out,
        // SAFETY: brk updated; unlock if needed, then uffd/populate.
        SYSBRK_EXIT => unsafe { bindings::rust_sysbrk_exit(s) },
        _ => {
            pr_err!("rust-mmap: unknown sys_brk kind {kind}\n");
            // SAFETY: Drop a leftover write lock without applying brk.
            unsafe { bindings::rust_sysbrk_abort(s) };
            EINVAL.to_errno() as c_ulong
        }
    }
}

/// C ABI: sequence `vm_brk_flags` after C takes the mmap lock.
///
/// Sets `*handled` once classify has run. Limits/munmap failures
/// unlock without uffd. Success unlocks, then uffd and maybe populate.
///
/// # Safety
///
/// `s` must be a live `rust_vmbrk_state` with addr/request/is_exec
/// filled. `handled` must be a valid out-parameter. No mmap lock is
/// held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_vmbrk_dispatch(
    s: *mut bindings::rust_vmbrk_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify takes the mmap write lock.
    let kind = unsafe { bindings::rust_vmbrk_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VMBRK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vm_brk sequenced\n");
    }

    match kind {
        VMBRK_DONE => out,
        // SAFETY: Unlocked; complete uffd and maybe populate.
        VMBRK_EXIT => unsafe { bindings::rust_vmbrk_exit(s) },
        _ => {
            pr_err!("rust-mmap: unknown vm_brk kind {kind}\n");
            // SAFETY: Drop a leftover write lock.
            unsafe { bindings::rust_vmbrk_abort(s) };
            EINVAL.to_errno()
        }
    }
}
