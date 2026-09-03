// SPDX-License-Identifier: GPL-2.0

//! Unmap and teardown sequencers (`munmap`, `unmap_region`, `exit_mmap`).
//!
//! Maple-tree holes, TLB gather, and page-table free stay in C.

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
use core::ptr;


/// Matches `RUST_MUNMAP_*` in `include/linux/mm.h`.
const MUNMAP_DONE: i32 = 0;
/// Overlapping VMA found; maple-tree unmap.
const MUNMAP_ALIGN: i32 = 1;

/// Matches `RUST_AMUNMAP_*` in `include/linux/mm.h`.
const AMUNMAP_DONE: i32 = 0;
/// Gathered and maple hole cleared; complete zap.
const AMUNMAP_COMPLETE: i32 = 1;

/// Matches `RUST_UR_*` in `include/linux/mm.h`.
const UR_DONE: i32 = 0;
/// TLB gathered; zap VMAs and free page tables.
const UR_APPLY: i32 = 1;

/// Matches `RUST_GATHER_*` in `include/linux/mm.h`.
const GATHER_DONE: i32 = 0;
/// Start split done (or not needed); detach remaining VMAs.
const GATHER_LOOP: i32 = 1;

/// Matches `RUST_VCOMP_*` in `include/linux/mm.h`.
const VCOMP_DONE: i32 = 0;
/// Stats updated; zap, free, and destroy the detach tree.
const VCOMP_UNMAP: i32 = 1;

/// Matches `RUST_CLEAN_*` in `include/linux/mm.h`.
const CLEAN_DONE: i32 = 0;
/// Have pages; zap PTEs and close VMAs.
const CLEAN_CLOSE: i32 = 1;

/// Matches `RUST_VABORT_*` in `include/linux/mm.h`.
const VABORT_DONE: i32 = 0;
/// PTEs still present; reattach detached VMAs.
const VABORT_REATTACH: i32 = 1;
/// PTEs already cleared; leave a gap and complete munmap.
const VABORT_GAP: i32 = 2;

/// Matches `RUST_VMUNMAP_*` in `include/linux/mm.h`.
const VMUNMAP_DONE: i32 = 0;
/// mmap write lock held; unmap the range.
const VMUNMAP_APPLY: i32 = 1;

/// Matches `RUST_UBADD_*` in `include/linux/mm.h`.
const UBADD_DONE: i32 = 0;
/// Different file or full batch; flush then add.
const UBADD_PROCESS: i32 = 1;
/// Same file and room; append to the batch.
const UBADD_ADD: i32 = 2;

/// Matches `RUST_EMMAP_*` in `include/linux/mm.h`.
const EMMAP_EMPTY: i32 = 0;
/// At least one VMA; unmap then destroy.
const EMMAP_UNMAP: i32 = 1;

static N_MUNMAP: Atomic<u32> = Atomic::new(0);
static N_AMUNMAP: Atomic<u32> = Atomic::new(0);
static N_UR: Atomic<u32> = Atomic::new(0);
static N_GATHER: Atomic<u32> = Atomic::new(0);
static N_VCOMP: Atomic<u32> = Atomic::new(0);
static N_CLEAN: Atomic<u32> = Atomic::new(0);
static N_VABORT: Atomic<u32> = Atomic::new(0);
static N_VMUNMAP: Atomic<u32> = Atomic::new(0);
static N_UBADD: Atomic<u32> = Atomic::new(0);
static N_EMMAP: Atomic<u32> = Atomic::new(0);
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

/// C ABI: sequence `do_vmi_align_munmap` after C gathers VMAs.
///
/// Sets `*handled` once classify has run. Zap/free stays in C. Unknown
/// kind completes a gathered munmap so detached VMAs are not leaked.
///
/// # Safety
///
/// `s` must be a live `rust_amunmap_state` with `vmi`/`vma`/`mm`/`start`/
/// `end`/`uf`/`unlock` filled. mmap write lock held. `handled` must be a
/// valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_amunmap_dispatch(
    s: *mut bindings::rust_amunmap_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may split and detach VMAs.
    let kind = unsafe { bindings::rust_amunmap_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_AMUNMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first do_vmi_align_munmap sequenced\n");
    }

    match kind {
        AMUNMAP_DONE => out,
        // SAFETY: Gathered and hole cleared; complete zap in C.
        AMUNMAP_COMPLETE => unsafe { bindings::rust_amunmap_complete(s) },
        _ => {
            pr_err!("rust-mmap: unknown do_vmi_align_munmap kind {kind}\n");
            // SAFETY: Complete a gathered munmap.
            unsafe { bindings::rust_amunmap_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `unmap_region` after C gathers the TLB.
///
/// Sets `*handled` once classify has run. Zap and page-table free stay
/// in C. Unknown kind finishes a leftover TLB gather.
///
/// # Safety
///
/// `s` must be a live `rust_ur_state` with `unmap` filled. mmap write
/// lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_ur_dispatch(
    s: *mut bindings::rust_ur_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify gathers the TLB.
    let kind = unsafe { bindings::rust_ur_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_UR.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first unmap_region sequenced\n");
    }

    match kind {
        UR_DONE => {}
        // SAFETY: TLB gathered; zap and free page tables in C.
        UR_APPLY => unsafe { bindings::rust_ur_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown unmap_region kind {kind}\n");
            // SAFETY: Finish a leftover TLB gather.
            unsafe { bindings::rust_ur_abort(s) };
        }
    }
}

/// C ABI: sequence `vms_gather_munmap_vmas` after C splits the start.
///
/// Sets `*handled` once classify has run. Detach loop stays in C.
/// Unknown kind reattaches any detached VMAs.
///
/// # Safety
///
/// `s` must be a live `rust_gather_state` with `vms`/`mas_detach`
/// filled. mmap write lock held. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_gather_dispatch(
    s: *mut bindings::rust_gather_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may split the first VMA.
    let kind = unsafe { bindings::rust_gather_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_GATHER.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vms_gather_munmap_vmas sequenced\n");
    }

    match kind {
        GATHER_DONE => out,
        // SAFETY: Start split done; detach remaining VMAs in C.
        GATHER_LOOP => unsafe { bindings::rust_gather_loop(s) },
        _ => {
            pr_err!("rust-mmap: unknown vms_gather_munmap_vmas kind {kind}\n");
            // SAFETY: Reattach any detached VMAs.
            unsafe { bindings::rust_gather_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `vms_complete_munmap_vmas` after C updates counts.
///
/// Sets `*handled` once classify has run. Zap/free stay in C. Unknown
/// kind completes a leftover unmap so detached VMAs are not leaked.
///
/// # Safety
///
/// `s` must be a live `rust_vcomp_state` with `vms`/`mas_detach`
/// filled. mmap write lock held unless already downgraded. `handled`
/// must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vcomp_dispatch(
    s: *mut bindings::rust_vcomp_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify may downgrade the mmap lock.
    let kind = unsafe { bindings::rust_vcomp_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VCOMP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vms_complete_munmap_vmas sequenced\n");
    }

    match kind {
        VCOMP_DONE => {}
        // SAFETY: Counts updated; zap and free in C.
        VCOMP_UNMAP => unsafe { bindings::rust_vcomp_unmap(s) },
        _ => {
            pr_err!("rust-mmap: unknown vms_complete_munmap_vmas kind {kind}\n");
            // SAFETY: Complete a leftover unmap.
            unsafe { bindings::rust_vcomp_abort(s) };
        }
    }
}

/// C ABI: sequence `vms_clean_up_area` after C checks for pages.
///
/// Sets `*handled` once classify has run. Zap and `vma_close` stay in C.
///
/// # Safety
///
/// `s` must be a live `rust_clean_state` with `vms`/`mas_detach` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_clean_dispatch(
    s: *mut bindings::rust_clean_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify checks whether any pages were gathered.
    let kind = unsafe { bindings::rust_clean_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_CLEAN.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vms_clean_up_area sequenced\n");
    }

    match kind {
        CLEAN_DONE => {}
        // SAFETY: Have pages; zap PTEs and close VMAs in C.
        CLEAN_CLOSE => unsafe { bindings::rust_clean_close(s) },
        _ => {
            pr_err!("rust-mmap: unknown vms_clean_up_area kind {kind}\n");
            unsafe { bindings::rust_clean_abort(s) };
        }
    }
}

/// C ABI: sequence `vms_abort_munmap_vmas` after C classifies reattach vs gap.
///
/// Sets `*handled` once classify has run. Reattach and complete stay in C.
///
/// # Safety
///
/// `s` must be a live `rust_vabort_state` with `vms`/`mas_detach` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vabort_dispatch(
    s: *mut bindings::rust_vabort_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify inspects gathered munmap state.
    let kind = unsafe { bindings::rust_vabort_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VABORT.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vms_abort_munmap_vmas sequenced\n");
    }

    match kind {
        VABORT_DONE => {}
        // SAFETY: PTEs still present; reattach in C.
        VABORT_REATTACH => unsafe { bindings::rust_vabort_reattach(s) },
        // SAFETY: PTEs cleared; leave a gap and complete in C.
        VABORT_GAP => unsafe { bindings::rust_vabort_gap(s) },
        _ => {
            pr_err!("rust-mmap: unknown vms_abort_munmap_vmas kind {kind}\n");
            unsafe { bindings::rust_vabort_abort(s) };
        }
    }
}

/// C ABI: sequence `__vm_munmap` after C takes the mmap write lock.
///
/// Sets `*handled` once classify has run. Maple unmap stays in C.
/// Unknown kind drops a leftover mmap write lock.
///
/// # Safety
///
/// `s` must be a live `rust_vmunmap_state` with `start`/`len`/`unlock`
/// filled. No mmap lock is held on entry. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vmunmap_dispatch(
    s: *mut bindings::rust_vmunmap_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may take the mmap write lock.
    let kind = unsafe { bindings::rust_vmunmap_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VMUNMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first __vm_munmap sequenced\n");
    }

    match kind {
        VMUNMAP_DONE => out,
        // SAFETY: Lock held; unmap in C.
        VMUNMAP_APPLY => unsafe { bindings::rust_vmunmap_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown __vm_munmap kind {kind}\n");
            // SAFETY: Drop a leftover mmap write lock.
            unsafe { bindings::rust_vmunmap_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `unlink_file_vma_batch_add` after C classifies the VMA.
///
/// Sets `*handled` once classify has run. Batch flush stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_ubadd_state` with `vb`/`vma` filled. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_ubadd_dispatch(
    s: *mut bindings::rust_ubadd_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify checks `vma->vm_file`.
    let kind = unsafe { bindings::rust_ubadd_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_UBADD.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first unlink_file_vma_batch_add sequenced\n");
    }

    match kind {
        UBADD_DONE => {}
        // SAFETY: Flush the current batch, then append this VMA.
        UBADD_PROCESS => unsafe {
            bindings::rust_ubadd_process(s);
            bindings::rust_ubadd_add(s);
        },
        // SAFETY: Same file and room; append.
        UBADD_ADD => unsafe { bindings::rust_ubadd_add(s) },
        _ => {
            pr_err!("rust-mmap: unknown unlink_file_vma_batch_add kind {kind}\n");
            unsafe { bindings::rust_ubadd_abort(s) };
        }
    }
}

/// C ABI: sequence `exit_mmap` after C takes the mmap read lock.
///
/// Sets `*handled` once classify has run. Unmap/destroy stay in C.
/// Unknown kind drops leftover mmap locks and a gathered TLB.
///
/// # Safety
///
/// `s` must be a live `rust_emmap_state` with `mm` filled. No mmap
/// lock is held on entry. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_emmap_dispatch(
    s: *mut bindings::rust_emmap_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify takes mmap locks and may find a VMA.
    let kind = unsafe { bindings::rust_emmap_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_EMMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first exit_mmap sequenced\n");
    }

    match kind {
        // SAFETY: Write lock held; destroy an empty tree.
        EMMAP_EMPTY => unsafe { bindings::rust_emmap_empty(s) },
        // SAFETY: Read lock held; unmap then destroy.
        EMMAP_UNMAP => unsafe { bindings::rust_emmap_unmap(s) },
        _ => {
            pr_err!("rust-mmap: unknown exit_mmap kind {kind}\n");
            // SAFETY: Drop leftover mmap locks / TLB gather.
            unsafe { bindings::rust_emmap_abort(s) };
        }
    }
}

/// Matches `RUST_DMUNMAP_*` in `include/linux/mm.h`.
const DMUNMAP_APPLY: i32 = 0;

static N_DMUNMAP: Atomic<u32> = Atomic::new(0);

/// C ABI: sequence `do_munmap` after C initializes the VMA iterator.
///
/// Sets `*handled` once classify has run. `do_vmi_munmap` stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_dmunmap_state` with `mm`/`start`/`len`/`uf`
/// filled. mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_dmunmap_dispatch(
    s: *mut bindings::rust_dmunmap_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify initializes the iterator.
    let kind = unsafe { bindings::rust_dmunmap_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_DMUNMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first do_munmap sequenced\n");
    }

    match kind {
        // SAFETY: Iterator ready; unmap in C.
        DMUNMAP_APPLY => unsafe { bindings::rust_dmunmap_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown do_munmap kind {kind}\n");
            unsafe { bindings::rust_dmunmap_abort(s) };
            EINVAL.to_errno()
        }
    }
}
