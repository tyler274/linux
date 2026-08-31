// SPDX-License-Identifier: GPL-2.0

//! Anonymous write-fault and copy-on-write when `CONFIG_RUST_FAULT=y`.
//!
//! Private anonymous write faults and `wp_page_copy` are sequenced here.
//! Page-table install, rmap, user copy, and the zero-page read path stay
//! in C (`rust_anon_*` / `rust_wp_*` in `mm/memory.c`). File, swap, THP,
//! and userfaultfd faults stay in C.

use crate::{
    bindings,
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};

/// `VM_FAULT_OOM` from [`enum vm_fault_reason`].
const VM_FAULT_OOM: u32 = 1;

static N_FAULTS: Atomic<u32> = Atomic::new(0);
static N_COW: Atomic<u32> = Atomic::new(0);

/// Log that Rust is serving anonymous write faults and COW.
pub fn announce() {
    pr_info!("rust-fault: anonymous write-fault and COW handler active\n");
}

/// C ABI: try to finish a private anonymous write fault.
///
/// Sets `*handled` if this path consumed the fault (including OOM / retry).
///
/// # Safety
///
/// `vmf` must be the live fault descriptor; mmap or VMA lock held as for
/// `do_anonymous_page`. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_do_anonymous_page(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    // SAFETY: `vmf` is the C fault descriptor; mmap/VMA lock held.
    if unsafe { bindings::rust_anon_write_prepare(vmf, &mut out) } != 0 {
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return out;
    }

    // SAFETY: Same lock as `do_anonymous_page`; PTE table exists.
    let folio = unsafe { bindings::rust_anon_alloc_folio(vmf) };
    if folio.is_null() {
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return VM_FAULT_OOM;
    }

    // SAFETY: `folio` is a freshly allocated anonymous folio.
    unsafe { bindings::rust_anon_folio_uptodate(folio) };
    // SAFETY: Consumes `folio`; still under the mmap/VMA lock.
    let ret = unsafe { bindings::rust_anon_install_folio(vmf, folio) };

    let prev = N_FAULTS.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first anonymous write fault mapped\n");
    }

    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };
    ret
}

/// C ABI: try to finish a private copy-on-write or unshare.
///
/// Sets `*handled` if this path consumed the fault (including OOM / retry).
///
/// # Safety
///
/// `vmf` must be the live fault descriptor after `do_wp_page` dropped the
/// PTE lock and took a reference on `vmf->page` if present. `handled` must
/// be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_wp_page_copy(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    // SAFETY: Same lock as `wp_page_copy`; old page referenced if present.
    if unsafe { bindings::rust_wp_prepare(vmf, &mut out) } != 0 {
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return out;
    }

    // SAFETY: PTE still describes the COW source in `orig_pte`.
    let folio = unsafe { bindings::rust_wp_alloc_folio(vmf) };
    if folio.is_null() {
        // SAFETY: Drops the `do_wp_page` reference on the old page.
        unsafe { bindings::rust_wp_put_old(vmf) };
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return VM_FAULT_OOM;
    }

    // SAFETY: `folio` is the new COW target; copy or skip if zero PFN.
    if unsafe { bindings::rust_wp_copy_user(vmf, folio, &mut out) } != 0 {
        // SAFETY: `handled` is valid; helper already dropped both folios.
        unsafe { *handled = 1 };
        return out;
    }

    // SAFETY: `folio` contents are up to date (copied or pre-zeroed).
    unsafe { bindings::rust_anon_folio_uptodate(folio) };
    // SAFETY: Consumes `folio` and the old-page reference.
    let ret = unsafe { bindings::rust_wp_install_folio(vmf, folio) };

    let prev = N_COW.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first copy-on-write mapped\n");
    }

    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };
    ret
}
