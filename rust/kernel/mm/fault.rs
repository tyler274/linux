// SPDX-License-Identifier: GPL-2.0

//! PTE fault dispatch when `CONFIG_RUST_FAULT=y`.
//!
//! `handle_pte_fault` is sequenced here: missing, swap, NUMA, uffd-rwp,
//! write-protect, and access-flag update. Private anonymous read (zero-page)
//! and write faults and `wp_page_copy` are also sequenced here. Page-table
//! lookup, arch PTE encoding, rmap, user copy, and the file/swap/THP/uffd
//! bodies stay in C (`rust_pte_*` / `rust_wp_*` / `rust_anon_*` in
//! `mm/memory.c`). Write-protect reuse vs copy is sequenced here.

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

static N_PTE: Atomic<u32> = Atomic::new(0);
static N_FAULTS: Atomic<u32> = Atomic::new(0);
static N_ZERO: Atomic<u32> = Atomic::new(0);
static N_COW: Atomic<u32> = Atomic::new(0);
static N_REUSE: Atomic<u32> = Atomic::new(0);

/// Matches `RUST_PTE_*` in `include/linux/mm.h`.
const PTE_DONE: i32 = 0;
/// Missing PTE: anonymous or file `do_fault`.
const PTE_MISSING: i32 = 1;
/// Non-present PTE: swap, migration, or marker.
const PTE_SWAP: i32 = 2;
/// uffd read-write-protect on a protnone PTE.
const PTE_RWP: i32 = 3;
/// NUMA hinting fault.
const PTE_NUMA: i32 = 4;
/// Present PTE, write/unshare without write permission; PTL held.
const PTE_WP: i32 = 5;

/// Matches `RUST_WP_*` in `include/linux/mm.h`.
const WP_DONE: i32 = 0;
/// Shared PFNMAP/MIXEDMAP/DAX: `wp_pfn_shared`, PTL held.
const WP_SHARED_PFN: i32 = 1;
/// Shared file folio: `wp_page_shared`, PTL held.
const WP_SHARED: i32 = 2;
/// Exclusive anon folio: reuse in place, PTL held.
const WP_REUSE: i32 = 3;
/// Must copy; PTL dropped and old page referenced if present.
const WP_COPY: i32 = 4;

/// Log that Rust is serving PTE dispatch, anonymous faults, and COW.
pub fn announce() {
    pr_info!("rust-fault: PTE sequencer and anonymous/COW handler active\n");
}

/// C ABI: sequence `handle_pte_fault` after C classifies the PTE.
///
/// Sets `*handled` once classify has mutated `vmf` (PTE map / PTL).
///
/// # Safety
///
/// `vmf` must be the live fault descriptor; mmap or VMA lock held as for
/// `handle_pte_fault`. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_handle_pte_fault(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    // SAFETY: Same lock as `handle_pte_fault`; classify maps the PTE.
    let kind = unsafe { bindings::rust_pte_classify(vmf, &mut out) };
    // Classify mutates `vmf`. C must not re-run lookup.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_PTE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first PTE fault sequenced\n");
    }

    match kind {
        PTE_DONE => out,
        PTE_MISSING => {
            // SAFETY: Missing PTE; mmap/VMA lock held; `vmf->pte` is NULL.
            if unsafe { bindings::rust_vma_is_anonymous(vmf) } != 0 {
                // SAFETY: Anonymous VMA; pte unmapped.
                unsafe { bindings::rust_do_missing_anon(vmf) }
            } else {
                // SAFETY: File VMA; pte unmapped.
                unsafe { bindings::rust_do_missing_file(vmf) }
            }
        }
        // SAFETY: Non-present PTE; `orig_pte` cached.
        PTE_SWAP => unsafe { bindings::rust_do_swap_page(vmf) },
        // SAFETY: Protnone uffd-rwp PTE; pte still mapped, PTL not held.
        PTE_RWP => unsafe { bindings::rust_do_uffd_rwp(vmf) },
        // SAFETY: Protnone NUMA PTE; pte still mapped, PTL not held.
        PTE_NUMA => unsafe { bindings::rust_do_numa_page(vmf) },
        // SAFETY: Present PTE, write/unshare; PTL held.
        PTE_WP => unsafe { bindings::rust_do_wp_page(vmf) },
        _ => {
            pr_err!("rust-fault: unknown PTE kind {kind}\n");
            0
        }
    }
}

/// C ABI: sequence `do_wp_page` after C classifies reuse vs copy.
///
/// Sets `*handled` once classify has mutated `vmf` (uffd bit, PTL, refs).
///
/// # Safety
///
/// `vmf` must be the live fault descriptor with the PTE mapped and PTL
/// held as for `do_wp_page`. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_wp_dispatch(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    // SAFETY: Same lock as `do_wp_page`; PTL held, PTE mapped.
    let kind = unsafe { bindings::rust_wp_classify(vmf, &mut out) };
    // Classify may drop the PTL or take a folio reference.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    match kind {
        WP_DONE => out,
        // SAFETY: Shared PFNMAP/DAX; PTL held; `vmf->page` is NULL.
        WP_SHARED_PFN => unsafe { bindings::rust_wp_pfn_shared(vmf) },
        // SAFETY: Shared file folio; PTL held; `vmf->page` is live.
        WP_SHARED => unsafe { bindings::rust_wp_page_shared(vmf) },
        WP_REUSE => {
            // SAFETY: Exclusive anon folio; PTL held.
            unsafe { bindings::rust_wp_reuse(vmf) };
            let prev = N_REUSE.fetch_add(1, Relaxed);
            if prev == 0 {
                pr_info!("rust-fault: first write-protect reuse\n");
            }
            0
        }
        // SAFETY: PTL dropped; old page referenced if present.
        WP_COPY => unsafe { bindings::rust_wp_do_copy(vmf) },
        _ => {
            pr_err!("rust-fault: unknown WP kind {kind}\n");
            0
        }
    }
}

/// C ABI: try to finish a private anonymous fault (zero-page or write).
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
    if unsafe { bindings::rust_anon_pte_alloc(vmf, &mut out) } != 0 {
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return out;
    }

    // SAFETY: PTE table exists; decide zero-page vs private folio.
    if unsafe { bindings::rust_anon_use_zeropage(vmf) } != 0 {
        // SAFETY: Non-present PTE; mmap/VMA lock held.
        let ret = unsafe { bindings::rust_anon_install_zeropage(vmf) };
        let prev = N_ZERO.fetch_add(1, Relaxed);
        if prev == 0 {
            pr_info!("rust-fault: first anonymous zero-page mapped\n");
        }
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return ret;
    }

    // SAFETY: Write fault or zeropage is forbidden; need anon_vma.
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
