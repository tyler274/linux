// SPDX-License-Identifier: GPL-2.0

//! mmap install sequencers (`do_mmap`, `mmap_region`, `ksys_mmap_pgoff`).
//!
//! File mmap, shmem setup, and maple-tree store bodies stay in C.

use crate::{
    bindings,
    error::code::EINVAL,
    ffi::{c_int, c_long, c_ulong},
    prelude::*,
    sync::atomic::{
        Atomic,
        Relaxed, //
    },
};
use core::ptr;


/// Matches `RUST_DOMMAP_*` in `include/linux/mm.h`.
const DOMMAP_DONE: i32 = 0;
/// Flags and VA chosen; install via `mmap_region`.
const DOMMAP_REGION: i32 = 1;

/// Matches `RUST_RFP_*` in `include/linux/mm.h`.
const RFP_DONE: i32 = 0;
/// Range and shared VMA found; LSM check outside the mmap lock.
const RFP_SEC: i32 = 1;
/// LSM passed; write-lock and `do_mmap`.
const RFP_APPLY: i32 = 2;

/// Matches `RUST_ISM_*` in `include/linux/mm.h`.
const ISM_DONE: i32 = 0;
/// VMA allocated; insert via `insert_vm_struct`.
const ISM_LINK: i32 = 1;

/// Matches `RUST_MSET_*` in `include/linux/mm.h`.
const MSET_DONE: i32 = 0;
/// Overlapping VMAs; gather into the detach tree.
const MSET_GATHER: i32 = 1;
/// No overlap (or gather done); check limits and clean up.
const MSET_LIMITS: i32 = 2;

/// Matches `RUST_MNF_*` in `include/linux/mm.h`.
const MNF_DONE: i32 = 0;
/// File has `.mmap`; invoke the driver callback.
const MNF_MMAP: i32 = 1;

/// Matches `RUST_KMP_*` in `include/linux/mm.h`.
const KMP_DONE: i32 = 0;
/// File/anon setup done; call `vm_mmap_pgoff`.
const KMP_MMAP: i32 = 1;

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

/// Matches `RUST_MNVA_*` in `include/linux/mm.h`.
const MNVA_DONE: i32 = 0;
/// File-backed; `mmap` callback then store.
const MNVA_FILE: i32 = 1;
/// Shared anonymous; `shmem_zero_setup` then store.
const MNVA_SHMEM: i32 = 2;
/// Anonymous private; maple-tree store.
const MNVA_STORE: i32 = 3;
static N_DOMMAP: Atomic<u32> = Atomic::new(0);
static N_MMAPREG: Atomic<u32> = Atomic::new(0);
static N_RFP: Atomic<u32> = Atomic::new(0);
static N_ISM: Atomic<u32> = Atomic::new(0);
static N_MSET: Atomic<u32> = Atomic::new(0);
static N_MNF: Atomic<u32> = Atomic::new(0);
static N_KMP: Atomic<u32> = Atomic::new(0);
static N_MNVA: Atomic<u32> = Atomic::new(0);
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

/// C ABI: sequence `remap_file_pages` after C validates the range.
///
/// Sets `*handled` once classify has run. LSM `security_mmap_file` and
/// the write-locked `do_mmap` stay in C. Unknown kind drops a leftover
/// file ref and mmap write lock.
///
/// # Safety
///
/// `s` must be a live `rust_rfp_state` with syscall fields filled. No
/// mmap lock is held on entry. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_rfp_dispatch(
    s: *mut bindings::rust_rfp_state,
    handled: *mut c_int,
) -> c_long {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_long;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_long = 0;
    // SAFETY: `s` is live; classify may take the mmap read lock.
    let kind = unsafe { bindings::rust_rfp_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_RFP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first remap_file_pages sequenced\n");
    }

    match kind {
        RFP_DONE => out,
        RFP_SEC => {
            // SAFETY: Shared VMA found; LSM check outside the mmap lock.
            let kind = unsafe { bindings::rust_rfp_security(s, &mut out) };
            match kind {
                RFP_DONE => out,
                // SAFETY: LSM passed; write-lock and `do_mmap` in C.
                RFP_APPLY => unsafe { bindings::rust_rfp_apply(s) },
                _ => {
                    pr_err!("rust-mmap: unknown remap_file_pages security kind {kind}\n");
                    // SAFETY: Drop a leftover file ref.
                    unsafe { bindings::rust_rfp_abort(s) };
                    EINVAL.to_errno() as c_long
                }
            }
        }
        _ => {
            pr_err!("rust-mmap: unknown remap_file_pages kind {kind}\n");
            // SAFETY: Drop a leftover file ref or write lock.
            unsafe { bindings::rust_rfp_abort(s) };
            EINVAL.to_errno() as c_long
        }
    }
}

/// C ABI: sequence `__install_special_mapping` after C allocates the VMA.
///
/// Sets `*handled` once classify has run. `insert_vm_struct` stays in C.
/// Unknown kind frees a leftover VMA.
///
/// # Safety
///
/// `s` must be a live `rust_ism_state` with `mm`/`addr`/`len`/`vm_flags`/
/// `priv`/`ops` filled. mmap write lock held. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_ism_dispatch(
    s: *mut bindings::rust_ism_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_ptr();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut ret = ptr::null_mut();
    // SAFETY: `s` is live; classify may allocate a VMA.
    let kind = unsafe { bindings::rust_ism_classify(s, &mut ret) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_ISM.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first __install_special_mapping sequenced\n");
    }

    match kind {
        ISM_DONE => ret,
        // SAFETY: VMA allocated; insert in C.
        ISM_LINK => unsafe { bindings::rust_ism_link(s) },
        _ => {
            pr_err!("rust-mmap: unknown __install_special_mapping kind {kind}\n");
            // SAFETY: Free a leftover VMA.
            unsafe { bindings::rust_ism_abort(s) };
            EINVAL.to_ptr()
        }
    }
}

/// C ABI: sequence `__mmap_setup` after C finds overlapping VMAs.
///
/// Sets `*handled` once classify has run. Gather and limit checks stay
/// in C. Setup failure is aborted by the `mmap_region` caller.
///
/// # Safety
///
/// `s` must be a live `rust_mset_state` with `map`/`desc`/`uf` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mset_dispatch(
    s: *mut bindings::rust_mset_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may initialise munmap state.
    let kind = unsafe { bindings::rust_mset_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MSET.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first __mmap_setup sequenced\n");
    }

    match kind {
        MSET_DONE => out,
        MSET_GATHER => {
            // SAFETY: Overlapping VMAs; gather into the detach tree in C.
            let err = unsafe { bindings::rust_mset_gather(s) };
            if err != 0 {
                return err;
            }
            // SAFETY: Gathered (or empty); check limits and clean up in C.
            unsafe { bindings::rust_mset_limits(s) }
        }
        // SAFETY: No overlap; check limits and clean up in C.
        MSET_LIMITS => unsafe { bindings::rust_mset_limits(s) },
        _ => {
            pr_err!("rust-mmap: unknown __mmap_setup kind {kind}\n");
            unsafe { bindings::rust_mset_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `__mmap_new_file_vma` after C attaches the file.
///
/// Sets `*handled` once classify has run. Driver `mmap` stays in C.
/// Unknown kind drops a leftover file reference.
///
/// # Safety
///
/// `s` must be a live `rust_mnf_state` with `map`/`vma` filled. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_mnf_dispatch(
    s: *mut bindings::rust_mnf_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may take a file reference.
    let kind = unsafe { bindings::rust_mnf_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MNF.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first __mmap_new_file_vma sequenced\n");
    }

    match kind {
        MNF_DONE => out,
        // SAFETY: File has `.mmap`; invoke the driver in C.
        MNF_MMAP => unsafe { bindings::rust_mnf_mmap(s) },
        _ => {
            pr_err!("rust-mmap: unknown __mmap_new_file_vma kind {kind}\n");
            // SAFETY: Drop a leftover file reference.
            unsafe { bindings::rust_mnf_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `ksys_mmap_pgoff` after C looks up the file.
///
/// Sets `*handled` once classify has run. `vm_mmap_pgoff` stays in C.
/// Unknown kind drops a leftover file ref.
///
/// # Safety
///
/// `s` must be a live `rust_kmp_state` with `addr`/`len`/`prot`/`flags`/
/// `fd`/`pgoff` filled. No mmap lock is held on entry. `handled` must
/// be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_kmp_dispatch(
    s: *mut bindings::rust_kmp_state,
    handled: *mut c_int,
) -> c_ulong {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    // SAFETY: `s` is live; classify may `fget` or set up hugetlb.
    let kind = unsafe { bindings::rust_kmp_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_KMP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first ksys_mmap_pgoff sequenced\n");
    }

    match kind {
        KMP_DONE => out,
        // SAFETY: File (if any) is held; mmap in C then fput.
        KMP_MMAP => unsafe { bindings::rust_kmp_mmap(s) },
        _ => {
            pr_err!("rust-mmap: unknown ksys_mmap_pgoff kind {kind}\n");
            // SAFETY: Drop a leftover file ref.
            unsafe { bindings::rust_kmp_abort(s) };
            EINVAL.to_errno() as c_ulong
        }
    }
}
