// SPDX-License-Identifier: GPL-2.0

//! VMA tree sequencers (merge, split, link, expand, copy, anon_vma).
//!
//! Maple store, rmap, and policy bodies stay in C.

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
use core::ptr;


/// Matches `RUST_VEX_*` in `include/linux/mm.h`.
const VEX_NONE: i32 = 0;
/// Merge prev and next around middle.
const VEX_BOTH: i32 = 1;
/// Merge prev into middle.
const VEX_LEFT: i32 = 2;
/// Merge next into middle.
const VEX_RIGHT: i32 = 3;

/// Matches `RUST_VEXP_*` in `include/linux/mm.h`.
const VEXP_DONE: i32 = 0;
/// Anon vmas cloned; maple-tree `commit_merge`.
const VEXP_COMMIT: i32 = 1;

/// Matches `RUST_ESTK_*` in `include/linux/mm.h`.
const ESTK_DONE: i32 = 0;
/// VMA found or grown; downgrade write to read.
const ESTK_DOWNGRADE: i32 = 1;

/// Matches `RUST_VMOD_*` in `include/linux/mm.h`.
const VMOD_DONE: i32 = 0;
/// Merge failed; split preceding and/or trailing.
const VMOD_SPLIT: i32 = 1;

/// Matches `RUST_VSH_*` in `include/linux/mm.h`.
const VSH_DONE: i32 = 0;
/// Prealloc ok; shrink the VMA.
const VSH_APPLY: i32 = 1;

/// Matches `RUST_CMERGE_*` in `include/linux/mm.h`.
const CMERGE_DONE: i32 = 0;
/// Prealloc ok; prepare, THP, range, maple store.
const CMERGE_APPLY: i32 = 1;

/// Matches `RUST_EXDN_*` in `include/linux/mm.h`.
const EXDN_DONE: i32 = 0;
/// Prealloc and anon_vma ready; grow the VMA.
const EXDN_APPLY: i32 = 1;

/// Matches `RUST_IVS_*` in `include/linux/mm.h`.
const IVS_DONE: i32 = 0;
/// Checks passed; `vma_link` into the maple tree.
const IVS_LINK: i32 = 1;

/// Matches `RUST_SVMA_*` in `include/linux/mm.h`.
const SVMA_DONE: i32 = 0;
/// Dup and prealloc ok; policy/THP/complete.
const SVMA_APPLY: i32 = 1;

/// Matches `RUST_VLINK_*` in `include/linux/mm.h`.
const VLINK_DONE: i32 = 0;
/// Prealloc ok; store and link file.
const VLINK_STORE: i32 = 1;

/// Matches `RUST_CVMA_*` in `include/linux/mm.h`.
const CVMA_DONE: i32 = 0;
/// Could not merge; dup and `vma_link`.
const CVMA_DUP: i32 = 1;

/// Matches `RUST_ASG_*` in `include/linux/mm.h`.
const ASG_DONE: i32 = 0;
/// Limits passed; `security_vm_enough_memory_mm`.
const ASG_SEC: i32 = 1;

/// Matches `RUST_DAV_*` in `include/linux/mm.h`.
const DAV_DONE: i32 = 0;
/// Destination has no anon_vma; clone from source.
const DAV_CLONE: i32 = 1;

/// Matches `RUST_FMA_*` in `include/linux/mm.h`.
const FMA_DONE: i32 = 0;
/// Next was missing or not reusable; try the previous VMA.
const FMA_PREV: i32 = 1;

/// Matches `RUST_VLF_*` in `include/linux/mm.h`.
const VLF_DONE: i32 = 0;
/// File-backed; lock i_mmap and insert.
const VLF_LINK: i32 = 1;

/// Matches `RUST_SPW_*` in `include/linux/mm.h`.
const SPW_DONE: i32 = 0;
/// Under `max_map_count`; call `__split_vma`.
const SPW_APPLY: i32 = 1;

/// Matches `RUST_VMERGE_*` in `include/linux/mm.h`.
const VMERGE_NONE: i32 = 0;
/// Adjacent VMA selected; maple-tree expand.
const VMERGE_EXPAND: i32 = 1;
static N_VMERGE: Atomic<u32> = Atomic::new(0);
static N_VEXP: Atomic<u32> = Atomic::new(0);
static N_ESTK: Atomic<u32> = Atomic::new(0);
static N_VMOD: Atomic<u32> = Atomic::new(0);
static N_VSH: Atomic<u32> = Atomic::new(0);
static N_CMERGE: Atomic<u32> = Atomic::new(0);
static N_EXDN: Atomic<u32> = Atomic::new(0);
static N_IVS: Atomic<u32> = Atomic::new(0);
static N_SVMA: Atomic<u32> = Atomic::new(0);
static N_VLINK: Atomic<u32> = Atomic::new(0);
static N_CVMA: Atomic<u32> = Atomic::new(0);
static N_ASG: Atomic<u32> = Atomic::new(0);
static N_DAV: Atomic<u32> = Atomic::new(0);
static N_FMA: Atomic<u32> = Atomic::new(0);
static N_VLF: Atomic<u32> = Atomic::new(0);
static N_SPW: Atomic<u32> = Atomic::new(0);
static N_VEX: Atomic<u32> = Atomic::new(0);
/// C ABI: sequence `vma_merge_new_range` after C classifies adjacency.
///
/// Sets `*handled` once classify has adjusted `vmg`. Maple-tree
/// expand stays in C.
///
/// # Safety
///
/// `vmg` must be a live merge request with mmap write lock held.
/// `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vmerge_dispatch(
    vmg: *mut bindings::vma_merge_struct,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if vmg.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `vmg` is live; classify may adjust start/end/target.
    let kind = unsafe { bindings::rust_vmerge_classify(vmg) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VMERGE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_merge sequenced\n");
    }

    match kind {
        VMERGE_NONE => ptr::null_mut(),
        // SAFETY: Target selected; nested `vma_expand` is Rust-sequenced.
        VMERGE_EXPAND => unsafe { bindings::rust_vmerge_expand(vmg) },
        _ => {
            pr_err!("rust-mmap: unknown vma_merge kind {kind}\n");
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `vma_merge_existing_range` after C classifies adjacency.
///
/// Sets `*handled` once classify has run. `dup_anon_vma` and
/// `commit_merge` stay in C. Unknown kind or a failed dup/commit aborts
/// the iterator and unlinks a partial anon_vma clone.
///
/// # Safety
///
/// `s` must be a live `rust_vex_state` with `vmg` filled. mmap write
/// lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vex_dispatch(
    s: *mut bindings::rust_vex_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify may take VMA write locks.
    let kind = unsafe { bindings::rust_vex_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VEX.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_merge_existing sequenced\n");
    }

    if kind == VEX_NONE {
        return ptr::null_mut();
    }

    let err = match kind {
        // SAFETY: Merge prev+next; dup_anon_vma stays in C.
        VEX_BOTH => unsafe { bindings::rust_vex_both(s) },
        // SAFETY: Merge prev; dup_anon_vma stays in C.
        VEX_LEFT => unsafe { bindings::rust_vex_left(s) },
        // SAFETY: Merge next; dup_anon_vma stays in C.
        VEX_RIGHT => unsafe { bindings::rust_vex_right(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_merge_existing kind {kind}\n");
            // SAFETY: Classify already locked VMAs; reset the iterator.
            unsafe { bindings::rust_vex_abort(s) };
            return ptr::null_mut();
        }
    };
    if err != 0 {
        // SAFETY: dup_anon_vma failed; unlink and reset the iterator.
        unsafe { bindings::rust_vex_abort(s) };
        return ptr::null_mut();
    }
    // SAFETY: Anon vmas cloned; `commit_merge` runs from C.
    let committed = unsafe { bindings::rust_vex_commit(s) };
    if committed.is_null() {
        // SAFETY: commit_merge failed; reset the iterator.
        unsafe { bindings::rust_vex_abort(s) };
        return ptr::null_mut();
    }
    committed
}

/// C ABI: sequence `vma_expand` after C clones anon_vmas.
///
/// Sets `*handled` once classify has run. `commit_merge` is sequenced
/// separately. Unknown kind or a failed commit unlinks a partial
/// anon_vma clone.
///
/// # Safety
///
/// `s` must be a live `rust_vexp_state` with `vmg` filled. mmap write
/// lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vexp_dispatch(
    s: *mut bindings::rust_vexp_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may take VMA write locks and dup.
    let kind = unsafe { bindings::rust_vexp_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VEXP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_expand sequenced\n");
    }

    match kind {
        VEXP_DONE => out,
        VEXP_COMMIT => {
            // SAFETY: Anon vmas cloned; `commit_merge` runs from C.
            let err = unsafe { bindings::rust_vexp_commit(s) };
            if err != 0 {
                // SAFETY: commit_merge failed; unlink the clone.
                unsafe { bindings::rust_vexp_abort(s) };
            }
            err
        }
        _ => {
            pr_err!("rust-mmap: unknown vma_expand kind {kind}\n");
            // SAFETY: Classify may have cloned anon_vma.
            unsafe { bindings::rust_vexp_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `expand_stack` after C drops the mmap read lock.
///
/// Sets `*handled` once classify has taken the write lock (or failed
/// to). Grow-up / grow-down stay in C. Unknown kind drops a leftover
/// write lock.
///
/// # Safety
///
/// `s` must be a live `rust_estk_state` with `mm` and `addr` filled.
/// mmap read lock held on entry. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_estk_dispatch(
    s: *mut bindings::rust_estk_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify drops the read lock and may grow.
    let kind = unsafe { bindings::rust_estk_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_ESTK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first expand_stack sequenced\n");
    }

    match kind {
        ESTK_DONE => ptr::null_mut(),
        // SAFETY: Write lock held; downgrade to read.
        ESTK_DOWNGRADE => unsafe { bindings::rust_estk_downgrade(s) },
        _ => {
            pr_err!("rust-mmap: unknown expand_stack kind {kind}\n");
            // SAFETY: Drop a leftover write lock.
            unsafe { bindings::rust_estk_abort(s) };
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `vma_modify` after C tries a merge.
///
/// Sets `*handled` once classify has run. Split stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_vmod_state` with `vmg` filled. mmap write
/// lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vmod_dispatch(
    s: *mut bindings::rust_vmod_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut merged = ptr::null_mut();
    // SAFETY: `s` is live; classify may merge existing VMAs.
    let kind = unsafe { bindings::rust_vmod_classify(s, &mut merged) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VMOD.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_modify sequenced\n");
    }

    match kind {
        VMOD_DONE => merged,
        // SAFETY: Merge failed; split preceding/trailing in C.
        VMOD_SPLIT => unsafe { bindings::rust_vmod_split(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_modify kind {kind}\n");
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `vma_shrink` after C preallocates.
///
/// Sets `*handled` once classify has run. THP adjust, maple clear,
/// and `vma_complete` stay in C.
///
/// # Safety
///
/// `s` must be a live `rust_vsh_state` with `vmi`/`vma`/`end` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vsh_dispatch(
    s: *mut bindings::rust_vsh_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may preallocate maple nodes.
    let kind = unsafe { bindings::rust_vsh_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VSH.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_shrink sequenced\n");
    }

    match kind {
        VSH_DONE => out,
        // SAFETY: Prealloc ok; shrink the VMA in C.
        VSH_APPLY => unsafe { bindings::rust_vsh_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_shrink kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `commit_merge` after C preallocates maple nodes.
///
/// Sets `*handled` once classify has run. THP adjust, range update,
/// maple store, and `vma_complete` stay in C.
///
/// # Safety
///
/// `s` must be a live `rust_cmerge_state` with `vmg` filled. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_cmerge_dispatch(
    s: *mut bindings::rust_cmerge_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may preallocate maple nodes.
    let kind = unsafe { bindings::rust_cmerge_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_CMERGE.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first commit_merge sequenced\n");
    }

    match kind {
        CMERGE_DONE => out,
        // SAFETY: Prealloc ok; prepare/store/complete in C.
        CMERGE_APPLY => unsafe { bindings::rust_cmerge_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown commit_merge kind {kind}\n");
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `expand_downwards` after C preallocates.
///
/// Sets `*handled` once classify has run. Anon rmap and maple store
/// stay in C. Unknown kind frees leftover maple prealloc.
///
/// # Safety
///
/// `s` must be a live `rust_exdn_state` with `vma`/`address` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_exdn_dispatch(
    s: *mut bindings::rust_exdn_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may preallocate maple nodes.
    let kind = unsafe { bindings::rust_exdn_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_EXDN.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first expand_downwards sequenced\n");
    }

    match kind {
        EXDN_DONE => out,
        // SAFETY: Prealloc ok; grow the stack VMA in C.
        EXDN_APPLY => unsafe { bindings::rust_exdn_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown expand_downwards kind {kind}\n");
            // SAFETY: Drop leftover maple prealloc.
            unsafe { bindings::rust_exdn_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `insert_vm_struct` after C accounts the VMA.
///
/// Sets `*handled` once classify has run. `vma_link` stays in C.
/// Unknown kind unaccounts a leftover charge.
///
/// # Safety
///
/// `s` must be a live `rust_ivs_state` with `mm`/`vma` filled. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_ivs_dispatch(
    s: *mut bindings::rust_ivs_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may charge committed memory.
    let kind = unsafe { bindings::rust_ivs_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_IVS.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first insert_vm_struct sequenced\n");
    }

    match kind {
        IVS_DONE => out,
        // SAFETY: Checks passed; link the VMA in C.
        IVS_LINK => unsafe { bindings::rust_ivs_link(s) },
        _ => {
            pr_err!("rust-mmap: unknown insert_vm_struct kind {kind}\n");
            // SAFETY: Unaccount a leftover charge.
            unsafe { bindings::rust_ivs_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `__split_vma` after C dups and preallocates.
///
/// Sets `*handled` once classify has run. Policy, THP, and maple store
/// stay in C. Unknown kind frees the dup and maple prealloc.
///
/// # Safety
///
/// `s` must be a live `rust_svma_state` with `vmi`/`vma`/`addr`/
/// `new_below` filled. mmap write lock held. `handled` must be a
/// valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_svma_dispatch(
    s: *mut bindings::rust_svma_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may dup the VMA and preallocate.
    let kind = unsafe { bindings::rust_svma_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_SVMA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first split_vma sequenced\n");
    }

    match kind {
        SVMA_DONE => out,
        // SAFETY: Dup and prealloc ok; split in C.
        SVMA_APPLY => unsafe { bindings::rust_svma_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown split_vma kind {kind}\n");
            // SAFETY: Free dup and maple prealloc.
            unsafe { bindings::rust_svma_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `vma_link` after C preallocates maple nodes.
///
/// Sets `*handled` once classify has run. Store and file rmap stay in
/// C. Unknown kind frees leftover maple prealloc.
///
/// # Safety
///
/// `s` must be a live `rust_vlink_state` with `mm`/`vma` filled. mmap
/// write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vlink_dispatch(
    s: *mut bindings::rust_vlink_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify may preallocate maple nodes.
    let kind = unsafe { bindings::rust_vlink_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VLINK.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_link sequenced\n");
    }

    match kind {
        VLINK_DONE => out,
        // SAFETY: Prealloc ok; store and link file in C.
        VLINK_STORE => unsafe { bindings::rust_vlink_store(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_link kind {kind}\n");
            // SAFETY: Drop leftover maple prealloc.
            unsafe { bindings::rust_vlink_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `copy_vma` after C tries a merge.
///
/// Sets `*handled` once classify has run. Dup, policy, and `vma_link`
/// stay in C.
///
/// # Safety
///
/// `s` must be a live `rust_cvma_state` with `vmap`/`addr`/`len`/
/// `pgoff`/`need_rmap_locks` filled. mmap write lock held. `handled`
/// must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_cvma_dispatch(
    s: *mut bindings::rust_cvma_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut merged = ptr::null_mut();
    // SAFETY: `s` is live; classify may merge into an adjacent VMA.
    let kind = unsafe { bindings::rust_cvma_classify(s, &mut merged) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_CVMA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first copy_vma sequenced\n");
    }

    match kind {
        CVMA_DONE => merged,
        // SAFETY: Could not merge; dup and link in C.
        CVMA_DUP => unsafe { bindings::rust_cvma_dup(s) },
        _ => {
            pr_err!("rust-mmap: unknown copy_vma kind {kind}\n");
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `acct_stack_growth` after C checks VMA limits.
///
/// Sets `*handled` once classify has run. Overcommit accounting stays
/// in C.
///
/// # Safety
///
/// `s` must be a live `rust_asg_state` with `vma`/`size`/`grow` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_asg_dispatch(
    s: *mut bindings::rust_asg_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify checks stack growth limits.
    let kind = unsafe { bindings::rust_asg_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_ASG.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first acct_stack_growth sequenced\n");
    }

    match kind {
        ASG_DONE => out,
        // SAFETY: Limits passed; overcommit account in C.
        ASG_SEC => unsafe { bindings::rust_asg_sec(s) },
        _ => {
            pr_err!("rust-mmap: unknown acct_stack_growth kind {kind}\n");
            // SAFETY: Nothing to roll back.
            unsafe { bindings::rust_asg_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `dup_anon_vma` after C decides a clone is needed.
///
/// Sets `*handled` once classify has run. `anon_vma_clone` stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_dav_state` with `dst`/`src`/`dup` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_dav_dispatch(
    s: *mut bindings::rust_dav_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify inspects anon_vma pointers.
    let kind = unsafe { bindings::rust_dav_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_DAV.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first dup_anon_vma sequenced\n");
    }

    match kind {
        DAV_DONE => out,
        // SAFETY: Destination is unfaulted; clone in C.
        DAV_CLONE => unsafe { bindings::rust_dav_clone(s) },
        _ => {
            pr_err!("rust-mmap: unknown dup_anon_vma kind {kind}\n");
            unsafe { bindings::rust_dav_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// C ABI: sequence `find_mergeable_anon_vma` after C tries the next VMA.
///
/// Sets `*handled` once classify has run. Previous-VMA lookup stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_fma_state` with `vma` filled. mmap lock
/// held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_fma_dispatch(
    s: *mut bindings::rust_fma_state,
    handled: *mut c_int,
) -> *mut bindings::anon_vma {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut ret = ptr::null_mut();
    // SAFETY: `s` is live; classify may walk the next VMA.
    let kind = unsafe { bindings::rust_fma_classify(s, &mut ret) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_FMA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first find_mergeable_anon_vma sequenced\n");
    }

    match kind {
        FMA_DONE => ret,
        // SAFETY: Next was missing or not reusable; try prev in C.
        FMA_PREV => unsafe { bindings::rust_fma_prev(s) },
        _ => {
            pr_err!("rust-mmap: unknown find_mergeable_anon_vma kind {kind}\n");
            unsafe { bindings::rust_fma_abort(s) };
            ptr::null_mut()
        }
    }
}

/// C ABI: sequence `vma_link_file` after C checks for a backing file.
///
/// Sets `*handled` once classify has run. i_mmap insert stays in C.
/// Unknown kind drops a leftover i_mmap write lock.
///
/// # Safety
///
/// `s` must be a live `rust_vlf_state` with `vma`/`hold_rmap_lock`
/// filled. mmap write lock held. `handled` must be a valid
/// out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vlf_dispatch(
    s: *mut bindings::rust_vlf_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify checks `vma->vm_file`.
    let kind = unsafe { bindings::rust_vlf_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VLF.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_link_file sequenced\n");
    }

    match kind {
        VLF_DONE => {}
        // SAFETY: File-backed; lock and insert in C.
        VLF_LINK => unsafe { bindings::rust_vlf_link(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_link_file kind {kind}\n");
            unsafe { bindings::rust_vlf_abort(s) };
        }
    }
}

/// C ABI: sequence `split_vma` after C checks `max_map_count`.
///
/// Sets `*handled` once classify has run. `__split_vma` stays in C.
///
/// # Safety
///
/// `s` must be a live `rust_spw_state` with `vmi`/`vma`/`addr`/
/// `new_below` filled. mmap write lock held. `handled` must be a
/// valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_spw_dispatch(
    s: *mut bindings::rust_spw_state,
    handled: *mut c_int,
) -> c_int {
    if s.is_null() || handled.is_null() {
        return EINVAL.to_errno();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_int = 0;
    // SAFETY: `s` is live; classify checks `map_count`.
    let kind = unsafe { bindings::rust_spw_classify(s, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_SPW.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first split_vma limit sequenced\n");
    }

    match kind {
        SPW_DONE => out,
        // SAFETY: Under the map-count cap; split in C.
        SPW_APPLY => unsafe { bindings::rust_spw_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown split_vma limit kind {kind}\n");
            unsafe { bindings::rust_spw_abort(s) };
            EINVAL.to_errno()
        }
    }
}

/// Matches `RUST_RVMA_*` in `include/linux/mm.h`.
const RVMA_ANON: i32 = 0;
/// File-backed VMA; `fput` after close.
const RVMA_FILE: i32 = 1;

/// Matches `RUST_VME_*` in `include/linux/mm.h`.
const VME_APPLY: i32 = 0;

static N_RVMA: Atomic<u32> = Atomic::new(0);
static N_VME: Atomic<u32> = Atomic::new(0);

/// C ABI: sequence `remove_vma` after C checks for a file.
///
/// Sets `*handled` once classify has run. Close, `fput`, and free stay
/// in C.
///
/// # Safety
///
/// `s` must be a live `rust_rvma_state` with `vma` filled. `handled`
/// must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_rvma_dispatch(
    s: *mut bindings::rust_rvma_state,
    handled: *mut c_int,
) {
    if s.is_null() || handled.is_null() {
        return;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify checks `vma->vm_file`.
    let kind = unsafe { bindings::rust_rvma_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_RVMA.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first remove_vma sequenced\n");
    }

    match kind {
        // SAFETY: Anonymous; close and free in C.
        RVMA_ANON => unsafe { bindings::rust_rvma_anon(s) },
        // SAFETY: File-backed; close, fput, and free in C.
        RVMA_FILE => unsafe { bindings::rust_rvma_file(s) },
        _ => {
            pr_err!("rust-mmap: unknown remove_vma kind {kind}\n");
            unsafe { bindings::rust_rvma_abort(s) };
        }
    }
}

/// C ABI: sequence `vma_merge_extend` after C sets up the merge request.
///
/// Sets `*handled` once classify has run. `vma_merge_new_range` stays
/// in C.
///
/// # Safety
///
/// `s` must be a live `rust_vme_state` with `vmi`/`vma`/`delta` filled.
/// mmap write lock held. `handled` must be a valid out-parameter.
#[no_mangle]
pub unsafe extern "C" fn rust_vme_dispatch(
    s: *mut bindings::rust_vme_state,
    handled: *mut c_int,
) -> *mut bindings::vm_area_struct {
    if s.is_null() || handled.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    // SAFETY: `s` is live; classify fills `vmg` and looks up `next`.
    let kind = unsafe { bindings::rust_vme_classify(s) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_VME.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first vma_merge_extend sequenced\n");
    }

    match kind {
        // SAFETY: Merge request ready; expand in C.
        VME_APPLY => unsafe { bindings::rust_vme_apply(s) },
        _ => {
            pr_err!("rust-mmap: unknown vma_merge_extend kind {kind}\n");
            unsafe { bindings::rust_vme_abort(s) };
            ptr::null_mut()
        }
    }
}
