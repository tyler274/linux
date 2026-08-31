// SPDX-License-Identifier: GPL-2.0

//! PTE and mm-fault dispatch when `CONFIG_RUST_FAULT=y`.
//!
//! `handle_mm_fault` (hugetlb vs regular), `__handle_mm_fault`
//! (PUD/PMD/THP vs PTE), and `handle_pte_fault` are sequenced here:
//! missing, swap, NUMA, uffd-rwp, write-protect, and access-flag update.
//! Private anonymous read (zero-page) and write faults, `wp_page_copy`,
//! write-protect reuse, and file read/COW/shared faults are also sequenced
//! here. Sanitize, memcg, LRU-gen, accounting, page-table walk, arch PTE
//! encoding, rmap, user copy, and the filemap/swap/THP/hugetlb/uffd bodies
//! stay in C.

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
static N_FILE: Atomic<u32> = Atomic::new(0);
static N_MMF: Atomic<u32> = Atomic::new(0);
static N_HMF: Atomic<u32> = Atomic::new(0);

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

/// Matches `RUST_FILE_*` in `include/linux/mm.h`.
const FILE_DONE: i32 = 0;
/// File read fault (`do_read_fault`).
const FILE_READ: i32 = 1;
/// Private file write: COW from the file page.
const FILE_COW: i32 = 2;
/// Shared file write (`do_shared_fault`).
const FILE_SHARED: i32 = 3;

/// Matches `RUST_MMF_*` in `include/linux/mm.h`.
const MMF_DONE: i32 = 0;
/// Continue from PUD/PMD classify to the next step.
const MMF_CONT: i32 = 1;
/// `pmd_alloc` raced with a huge PUD; retry PUD.
const MMF_RETRY_PUD: i32 = 2;
/// Empty PUD that may take a huge page.
const MMF_HUGE_PUD: i32 = 3;
/// Write fault on a huge PUD.
const MMF_WP_HUGE_PUD: i32 = 4;
/// Empty PMD that may take a THP.
const MMF_HUGE_PMD: i32 = 5;
/// Device-private huge PMD.
const MMF_DEV_PRIVATE: i32 = 6;
/// uffd-rwp on a huge PMD.
const MMF_UFFD_RWP: i32 = 7;
/// NUMA hinting on a huge PMD.
const MMF_NUMA: i32 = 8;
/// Write/unshare on a huge PMD without write permission.
const MMF_WP_HUGE_PMD: i32 = 9;
/// Fall back to `handle_pte_fault`.
const MMF_PTE: i32 = 10;

/// Matches `RUST_HMF_*` in `include/linux/mm.h`.
const HMF_DONE: i32 = 0;
/// Hugetlb VMA: `hugetlb_fault`.
const HMF_HUGETLB: i32 = 1;
/// Regular VMA: `__handle_mm_fault`.
const HMF_REGULAR: i32 = 2;

/// `VM_FAULT_FALLBACK` from [`enum vm_fault_reason`].
const VM_FAULT_FALLBACK: u32 = 0x800;

/// Log that Rust is serving handle_mm_fault, PTE dispatch, anonymous faults, and COW.
pub fn announce() {
    pr_info!("rust-fault: handle_mm_fault sequencer and anonymous/COW handler active\n");
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

/// C ABI: sequence `do_fault` after C classifies read / COW / shared.
///
/// Always frees unused `prealloc_pte`. Sets `*handled` once classify
/// has inspected `vm_ops`.
///
/// # Safety
///
/// `vmf` must be the live fault descriptor; mmap or VMA lock held as for
/// `do_fault`. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_file_dispatch(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    // SAFETY: Same lock as `do_fault`; missing file PTE.
    let kind = unsafe { bindings::rust_file_classify(vmf, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_FILE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first file fault sequenced\n");
    }

    let ret = match kind {
        FILE_DONE => out,
        // SAFETY: File VMA with `->fault`; read fault.
        FILE_READ => unsafe { bindings::rust_do_read_fault(vmf) },
        // SAFETY: Private file write; COW from the file page.
        FILE_COW => unsafe { bindings::rust_do_cow_fault(vmf) },
        // SAFETY: Shared file write.
        FILE_SHARED => unsafe { bindings::rust_do_shared_fault(vmf) },
        _ => {
            pr_err!("rust-fault: unknown file kind {kind}\n");
            0
        }
    };
    // SAFETY: Matches C `do_fault` freeing unused preallocated PTE.
    unsafe { bindings::rust_file_free_prealloc(vmf) };
    ret
}

/// C ABI: sequence `__handle_mm_fault` after C walks PGD/P4D/PUD/PMD.
///
/// Sets `*handled` once page-table setup has run (including OOM).
///
/// # Safety
///
/// `vmf` must be initialized as in `__handle_mm_fault` (VMA, address,
/// flags, pgoff, gfp). mmap or VMA lock held. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_handle_mm_fault(
    vmf: *mut bindings::vm_fault,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vmf.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: Same lock as `__handle_mm_fault`; allocates P4D/PUD.
    if unsafe { bindings::rust_mmf_setup(vmf) } != 0 {
        // SAFETY: `handled` is valid.
        unsafe { *handled = 1 };
        return VM_FAULT_OOM;
    }
    // Setup mutated `vmf`. C must not re-walk.
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MMF.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first mm-fault sequenced\n");
    }

    loop {
        let mut out = 0u32;
        // SAFETY: PUD exists; mmap/VMA lock held.
        let pud_kind = unsafe { bindings::rust_mmf_classify_pud(vmf, &mut out) };
        match pud_kind {
            MMF_DONE => return out,
            MMF_HUGE_PUD => {
                // SAFETY: Empty PUD that may take a huge mapping.
                let ret = unsafe { bindings::rust_create_huge_pud(vmf) };
                if ret & VM_FAULT_FALLBACK == 0 {
                    return ret;
                }
            }
            MMF_WP_HUGE_PUD => {
                // SAFETY: Write fault on a transhuge PUD.
                let ret = unsafe { bindings::rust_wp_huge_pud(vmf) };
                if ret & VM_FAULT_FALLBACK == 0 {
                    return ret;
                }
            }
            MMF_CONT => {}
            _ => {
                pr_err!("rust-fault: unknown mm-fault PUD kind {pud_kind}\n");
                return 0;
            }
        }

        // SAFETY: PUD handling finished or fell back; allocate PMD.
        let pmd_alloc = unsafe { bindings::rust_mmf_alloc_pmd(vmf, &mut out) };
        match pmd_alloc {
            MMF_DONE => return out,
            MMF_RETRY_PUD => continue,
            MMF_CONT => {}
            _ => {
                pr_err!("rust-fault: unknown mm-fault PMD alloc {pmd_alloc}\n");
                return 0;
            }
        }

        // SAFETY: PMD pointer is live; classify THP vs PTE.
        let pmd_kind = unsafe { bindings::rust_mmf_classify_pmd(vmf, &mut out) };
        return match pmd_kind {
            MMF_DONE => out,
            MMF_HUGE_PMD => {
                // SAFETY: Empty PMD that may take a THP.
                let ret = unsafe { bindings::rust_create_huge_pmd(vmf) };
                if ret & VM_FAULT_FALLBACK != 0 {
                    unsafe { bindings::rust_finish_pte_fault(vmf) }
                } else {
                    ret
                }
            }
            // SAFETY: Device-private swap PMD.
            MMF_DEV_PRIVATE => unsafe { bindings::rust_do_huge_pmd_device_private(vmf) },
            // SAFETY: uffd-rwp huge PMD.
            MMF_UFFD_RWP => unsafe { bindings::rust_do_huge_pmd_uffd_rwp(vmf) },
            // SAFETY: NUMA hinting huge PMD.
            MMF_NUMA => unsafe { bindings::rust_do_huge_pmd_numa_page(vmf) },
            MMF_WP_HUGE_PMD => {
                // SAFETY: Write/unshare on a huge PMD; `orig_pmd` cached.
                let ret = unsafe { bindings::rust_wp_huge_pmd(vmf) };
                if ret & VM_FAULT_FALLBACK != 0 {
                    unsafe { bindings::rust_finish_pte_fault(vmf) }
                } else {
                    ret
                }
            }
            // SAFETY: Regular or none PMD; PTE fault.
            MMF_PTE => unsafe { bindings::rust_finish_pte_fault(vmf) },
            _ => {
                pr_err!("rust-fault: unknown mm-fault PMD kind {pmd_kind}\n");
                0
            }
        };
    }
}

/// C ABI: sequence `handle_mm_fault` after C sanitizes flags.
///
/// Sets `*handled` once prepare has run. C still accounts the fault
/// (`mm_account_fault` needs `pt_regs`).
///
/// # Safety
///
/// mmap or VMA lock held as for `handle_mm_fault`. `vma` and `flags`
/// must be live. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mm_fault(
    vma: *mut bindings::vm_area_struct,
    address: crate::ffi::c_ulong,
    flags: *mut crate::ffi::c_uint,
    handled: *mut crate::ffi::c_int,
) -> u32 {
    if vma.is_null() || flags.is_null() || handled.is_null() {
        return VM_FAULT_OOM;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out = 0u32;
    let mut droppable = 0;
    // SAFETY: Same lock as `handle_mm_fault`; may enter memcg/LRU-gen.
    let kind = unsafe { bindings::rust_hmf_prepare(vma, flags, &mut out, &mut droppable) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_HMF.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-fault: first handle_mm_fault sequenced\n");
    }

    if kind == HMF_DONE {
        return out;
    }

    // SAFETY: `flags` is the live in/out parameter from C.
    let flags_val = unsafe { *flags };
    let ret = match kind {
        // SAFETY: Hugetlb VMA; mmap/VMA lock held.
        HMF_HUGETLB => unsafe { bindings::rust_hugetlb_fault(vma, address, flags_val) },
        // SAFETY: Regular VMA; mmap/VMA lock held.
        HMF_REGULAR => unsafe { bindings::rust_do_handle_mm_fault(vma, address, flags_val) },
        _ => {
            pr_err!("rust-fault: unknown handle_mm_fault kind {kind}\n");
            0
        }
    };
    let mut ret = ret;
    // SAFETY: Handler finished; vma may no longer be dereferenced.
    unsafe { bindings::rust_hmf_exit(flags_val, &mut ret, droppable) };
    ret
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
