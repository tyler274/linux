// SPDX-License-Identifier: GPL-2.0

//! `mremap` sequencer (`do_mremap`).
//!
//! Maple-tree moves stay in C.

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


/// Matches `RUST_MREMAP_*` in `include/linux/mm.h`.
const MREMAP_DONE: i32 = 0;
/// Params ok, or mmap write lock taken.
const MREMAP_CONT: i32 = 1;
/// Batched multi-VMA move (`remap_move`).
const MREMAP_MOVE: i32 = 2;
/// Move or grow to a new address (`mremap_to`).
const MREMAP_TO: i32 = 3;
/// Shrink or expand in place (`mremap_at`).
const MREMAP_AT: i32 = 4;
static N_MREMAP: Atomic<u32> = Atomic::new(0);
/// C ABI: sequence `do_mremap` after C aligns lengths and takes the lock.
///
/// Sets `*handled` once prepare has run. Lock-fail and map-count-fail
/// return without `notify_uffd`. Prep-fail and the move/to/at paths
/// go through `mremap_exit` (unlock + populate + uffd).
///
/// # Safety
///
/// `vrm` must be the live `vma_remap_struct` from `do_mremap`. `handled`
/// must be a valid out-parameter. No mmap lock is held on entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mremap_dispatch(
    vrm: *mut bindings::vma_remap_struct,
    handled: *mut c_int,
) -> c_ulong {
    if vrm.is_null() || handled.is_null() {
        return EINVAL.to_errno() as c_ulong;
    }
    // SAFETY: Caller supplies a writable out-parameter.
    unsafe { *handled = 0 };

    let mut out: c_ulong = 0;
    // SAFETY: No mmap lock yet; `vrm` holds the syscall arguments.
    let kind = unsafe { bindings::rust_mremap_prepare(vrm, &mut out) };
    // SAFETY: `handled` is valid.
    unsafe { *handled = 1 };

    let prev = N_MREMAP.fetch_add(1, Relaxed);
    if prev == 0 {
        pr_info!("rust-mmap: first mremap sequenced\n");
    }

    if kind == MREMAP_DONE {
        return out;
    }
    if kind != MREMAP_CONT {
        pr_err!("rust-mmap: unknown mremap prepare kind {kind}\n");
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: Params passed; take the mmap write lock.
    let kind = unsafe { bindings::rust_mremap_lock(vrm, &mut out) };
    if kind == MREMAP_DONE {
        return out;
    }
    if kind != MREMAP_CONT {
        pr_err!("rust-mmap: unknown mremap lock kind {kind}\n");
        return EINVAL.to_errno() as c_ulong;
    }

    // SAFETY: mmap write lock held; classify move vs to vs at.
    let kind = unsafe { bindings::rust_mremap_classify(vrm, &mut out) };
    let res = match kind {
        MREMAP_DONE => out,
        // SAFETY: Locked; batched move of equal-length mappings.
        MREMAP_MOVE => unsafe { bindings::rust_mremap_move(vrm) },
        // SAFETY: Locked; grow or relocate to a new address.
        MREMAP_TO => unsafe { bindings::rust_mremap_to(vrm) },
        // SAFETY: Locked; shrink or expand in place.
        MREMAP_AT => unsafe { bindings::rust_mremap_at(vrm) },
        _ => {
            pr_err!("rust-mmap: unknown mremap classify kind {kind}\n");
            EINVAL.to_errno() as c_ulong
        }
    };
    // SAFETY: Lock was taken; unlock, maybe populate, always notify uffd.
    unsafe { bindings::rust_mremap_exit(vrm, res) }
}
