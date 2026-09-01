// SPDX-License-Identifier: GPL-2.0

//! Rust VMA maple tree: an RCU-safe sorted range array.
//!
//! When `MT_FLAGS_RUST` is set on a `maple_tree` (the mm VMA tree), store /
//! load / walk / fork copy go through this module instead of `lib/maple_tree.c`.
//! Adjacent identical pointers are coalesced so each VMA is one range.

use crate::{
    bindings,
    error::code::{EBUSY, EEXIST, EINVAL, ENOMEM},
    ffi::{c_int, c_ulong, c_void},
    prelude::*,
    sync::atomic::{Atomic, Relaxed},
};

const MA_ACTIVE: u32 = 0;
const MA_START: u32 = 1;
const MA_NONE: u32 = 3;
const MA_PAUSE: u32 = 4;
const MA_OVERFLOW: u32 = 5;
const MA_UNDERFLOW: u32 = 6;
const MA_ERROR: u32 = 7;
const MA_STATE_PREALLOC: u8 = 1;

static ANNOUNCED: Atomic<u32> = Atomic::new(0);

#[repr(C, align(8))]
struct Header {
    rcu: bindings::callback_head,
    n: u32,
    cap: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Ent {
    start: usize,
    last: usize,
    ptr: *mut c_void,
}

fn header_size() -> usize {
    core::mem::size_of::<Header>()
}

fn ent_size() -> usize {
    core::mem::size_of::<Ent>()
}

fn snap_size(cap: u32) -> usize {
    header_size() + cap as usize * ent_size()
}

unsafe fn ents(h: *mut Header) -> *mut Ent {
    unsafe { h.add(1).cast() }
}

unsafe fn ents_ref<'a>(h: *const Header) -> &'a [Ent] {
    if h.is_null() {
        return &[];
    }
    let n = unsafe { (*h).n as usize };
    unsafe { core::slice::from_raw_parts(ents(h as *mut Header), n) }
}

unsafe fn root_of(mt: *const bindings::maple_tree) -> *mut Header {
    unsafe { bindings::mt_rcu_deref_root(mt as *mut bindings::maple_tree).cast() }
}

unsafe fn publish(mt: *mut bindings::maple_tree, new: *mut Header, old: *mut Header) {
    unsafe { bindings::mt_rcu_assign_root(mt, new.cast()) };
    if !old.is_null() {
        unsafe { bindings::mt_kvfree_rcu(old.cast()) };
    }
}

unsafe fn alloc_snap(cap: u32, gfp: bindings::gfp_t) -> *mut Header {
    let cap = cap.max(1);
    let p = unsafe { bindings::mt_kvmalloc(snap_size(cap), gfp) }.cast::<Header>();
    if p.is_null() {
        return p;
    }
    unsafe {
        (*p).rcu = bindings::callback_head {
            next: core::ptr::null_mut(),
            func: None,
        };
        (*p).n = 0;
        (*p).cap = cap;
        core::ptr::write_bytes(ents(p), 0, cap as usize);
    }
    p
}

fn store_need(old: &[Ent], index: usize, last: usize, entry: *mut c_void) -> usize {
    let mut n = 0usize;
    let mut o = 0usize;
    while o < old.len() && old[o].last < index {
        n += 1;
        o += 1;
    }
    if o < old.len() && old[o].start < index {
        n += 1;
    }
    let mut right = false;
    while o < old.len() && old[o].start <= last {
        if old[o].last > last && last != usize::MAX {
            right = true;
        }
        o += 1;
    }
    if !entry.is_null() {
        n += 1;
    }
    if right {
        n += 1;
    }
    n + (old.len() - o)
}

unsafe fn fill_store(
    dst: *mut Ent,
    cap: u32,
    old: &[Ent],
    index: usize,
    last: usize,
    entry: *mut c_void,
) -> Option<u32> {
    let mut d = 0usize;
    let mut o = 0usize;
    let cap = cap as usize;
    let mut push = |e: Ent| -> bool {
        if d >= cap {
            return false;
        }
        unsafe { *dst.add(d) = e };
        d += 1;
        true
    };

    while o < old.len() && old[o].last < index {
        if !push(old[o]) {
            return None;
        }
        o += 1;
    }

    if o < old.len() && old[o].start < index {
        if !push(Ent {
            start: old[o].start,
            last: index - 1,
            ptr: old[o].ptr,
        }) {
            return None;
        }
    }

    let mut right: Option<Ent> = None;
    while o < old.len() && old[o].start <= last {
        if old[o].last > last && last != usize::MAX {
            right = Some(Ent {
                start: last + 1,
                last: old[o].last,
                ptr: old[o].ptr,
            });
        }
        o += 1;
    }

    if !entry.is_null()
        && !push(Ent {
            start: index,
            last,
            ptr: entry,
        })
    {
        return None;
    }
    if let Some(r) = right {
        if !push(r) {
            return None;
        }
    }
    while o < old.len() {
        if !push(old[o]) {
            return None;
        }
        o += 1;
    }
    Some(d as u32)
}

fn covering(es: &[Ent], index: usize) -> Option<usize> {
    let i = first_ge(es, index)?;
    if es[i].start <= index {
        Some(i)
    } else {
        None
    }
}

fn first_ge(es: &[Ent], index: usize) -> Option<usize> {
    let mut lo = 0usize;
    let mut hi = es.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if es[mid].last < index {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo < es.len() {
        Some(lo)
    } else {
        None
    }
}

fn last_lt(es: &[Ent], index: usize) -> Option<usize> {
    if es.is_empty() || index == 0 {
        return None;
    }
    first_ge(es, index).map_or(Some(es.len() - 1), |i| {
        if i == 0 {
            None
        } else {
            Some(i - 1)
        }
    })
}

unsafe fn set_entry(mas: *mut bindings::ma_state, e: Ent, idx: usize) {
    unsafe {
        (*mas).index = e.start;
        (*mas).last = e.last;
        (*mas).status = core::mem::transmute(MA_ACTIVE);
        (*mas).offset = idx as u8;
        (*mas).node = core::ptr::null_mut();
    }
}

unsafe fn set_none(mas: *mut bindings::ma_state, start: usize, last: usize) {
    unsafe {
        (*mas).index = start;
        (*mas).last = last;
        (*mas).status = core::mem::transmute(MA_NONE);
        (*mas).node = core::ptr::null_mut();
    }
}

unsafe fn set_overflow(mas: *mut bindings::ma_state) {
    unsafe {
        (*mas).status = core::mem::transmute(MA_OVERFLOW);
        (*mas).node = core::ptr::null_mut();
    }
}

unsafe fn set_underflow(mas: *mut bindings::ma_state) {
    unsafe {
        (*mas).status = core::mem::transmute(MA_UNDERFLOW);
        (*mas).node = core::ptr::null_mut();
    }
}

fn status(mas: *const bindings::ma_state) -> u32 {
    unsafe { (*mas).status as u32 }
}

fn announce() {
    if ANNOUNCED.fetch_add(1, Relaxed) == 0 {
        pr_info!("rust-mmap: VMA maple tree is a Rust RCU range array\n");
    }
}

unsafe fn do_walk(mas: *mut bindings::ma_state) -> *mut c_void {
    let mt = unsafe { (*mas).tree };
    let index = unsafe { (*mas).index };
    let h = unsafe { root_of(mt) };
    let es = unsafe { ents_ref(h) };
    if es.is_empty() {
        unsafe { set_none(mas, 0, usize::MAX) };
        return core::ptr::null_mut();
    }
    if let Some(i) = covering(es, index) {
        unsafe { set_entry(mas, es[i], i) };
        return es[i].ptr;
    }
    let next = first_ge(es, index);
    let gap_last = next.map_or(usize::MAX, |i| es[i].start.saturating_sub(1));
    let gap_start = last_lt(es, index).map_or(0, |i| {
        if es[i].last == usize::MAX {
            usize::MAX
        } else {
            es[i].last + 1
        }
    });
    unsafe { set_none(mas, gap_start.max(index), gap_last) };
    core::ptr::null_mut()
}

unsafe fn next_entry(mas: *mut bindings::ma_state, max: usize, empty: bool) -> *mut c_void {
    let mt = unsafe { (*mas).tree };
    let h = unsafe { root_of(mt) };
    let es = unsafe { ents_ref(h) };
    let after = unsafe { (*mas).last };
    if after >= max {
        unsafe { set_overflow(mas) };
        return core::ptr::null_mut();
    }
    let start = if after == usize::MAX {
        unsafe { set_overflow(mas) };
        return core::ptr::null_mut();
    } else {
        after + 1
    };
    if start > max {
        unsafe { set_overflow(mas) };
        return core::ptr::null_mut();
    }
    match first_ge(es, start) {
        None => {
            if empty {
                unsafe { set_none(mas, start, max.min(usize::MAX)) };
            } else {
                unsafe { set_overflow(mas) };
            }
            core::ptr::null_mut()
        }
        Some(i) => {
            if es[i].start > max {
                if empty {
                    unsafe { set_none(mas, start, max) };
                } else {
                    unsafe { set_overflow(mas) };
                }
                return core::ptr::null_mut();
            }
            if empty && es[i].start > start {
                unsafe { set_none(mas, start, es[i].start - 1) };
                return core::ptr::null_mut();
            }
            if es[i].start > max {
                unsafe { set_overflow(mas) };
                return core::ptr::null_mut();
            }
            unsafe { set_entry(mas, es[i], i) };
            es[i].ptr
        }
    }
}

unsafe fn prev_entry(mas: *mut bindings::ma_state, min: usize, empty: bool) -> *mut c_void {
    let mt = unsafe { (*mas).tree };
    let h = unsafe { root_of(mt) };
    let es = unsafe { ents_ref(h) };
    let index = unsafe { (*mas).index };
    if index <= min {
        unsafe { set_underflow(mas) };
        return core::ptr::null_mut();
    }
    let before = index - 1;
    match last_lt(es, index) {
        None => {
            if empty {
                unsafe { set_none(mas, min, before) };
            } else {
                unsafe { set_underflow(mas) };
            }
            core::ptr::null_mut()
        }
        Some(i) => {
            if es[i].last < min {
                unsafe { set_underflow(mas) };
                return core::ptr::null_mut();
            }
            if empty && es[i].last < before {
                let gap_start = es[i].last + 1;
                unsafe { set_none(mas, gap_start.max(min), before) };
                return core::ptr::null_mut();
            }
            unsafe { set_entry(mas, es[i], i) };
            es[i].ptr
        }
    }
}

unsafe fn do_store(mas: *mut bindings::ma_state, entry: *mut c_void, gfp: bindings::gfp_t) -> c_int {
    announce();
    let mt = unsafe { (*mas).tree };
    let index = unsafe { (*mas).index };
    let last = unsafe { (*mas).last };
    if index > last {
        unsafe { bindings::mas_set_err(mas, EINVAL.to_errno()) };
        return EINVAL.to_errno();
    }
    let old = unsafe { root_of(mt) };
    let old_es = unsafe { ents_ref(old) };
    let cap = store_need(old_es, index, last, entry).max(1) as u32;
    let pre = unsafe { (*mas).alloc as *mut Header };
    let use_pre = unsafe { (*mas).mas_flags & MA_STATE_PREALLOC != 0 }
        && !pre.is_null()
        && unsafe { (*pre).cap >= cap };
    let dst = if use_pre {
        pre
    } else {
        let p = unsafe { alloc_snap(cap, gfp) };
        if p.is_null() {
            unsafe { bindings::mas_set_err(mas, ENOMEM.to_errno()) };
            return ENOMEM.to_errno();
        }
        p
    };
    let Some(n) = (unsafe { fill_store(ents(dst), (*dst).cap, old_es, index, last, entry) }) else {
        if !use_pre {
            unsafe { bindings::mt_kvfree(dst.cast()) };
        }
        unsafe { bindings::mas_set_err(mas, ENOMEM.to_errno()) };
        return ENOMEM.to_errno();
    };
    if n == 0 {
        if use_pre {
            unsafe { bindings::mt_kvfree(dst.cast()) };
        } else {
            unsafe { bindings::mt_kvfree(dst.cast()) };
        }
        unsafe {
            (*mas).alloc = core::ptr::null_mut();
            (*mas).mas_flags &= !MA_STATE_PREALLOC;
        }
        unsafe { publish(mt, core::ptr::null_mut(), old) };
        unsafe { set_none(mas, index, last) };
        return 0;
    }
    unsafe { (*dst).n = n };
    unsafe {
        (*mas).alloc = core::ptr::null_mut();
        (*mas).mas_flags &= !MA_STATE_PREALLOC;
    }
    unsafe { publish(mt, dst, old) };
    if entry.is_null() {
        unsafe { set_none(mas, index, last) };
    } else if let Some(i) = covering(unsafe { ents_ref(dst) }, index) {
        unsafe { set_entry(mas, *ents(dst).add(i), i) };
    } else {
        unsafe { (*mas).status = core::mem::transmute(MA_START) };
    }
    0
}

/// Log that the VMA tree is served from Rust.
pub fn announce_once() {
    announce();
}

/// C ABI: `mtree_load` for a Rust VMA tree.
///
/// # Safety
///
/// `mt` must be a live maple tree with `MT_FLAGS_RUST`. RCU or the mmap lock
/// held.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_load(
    mt: *mut bindings::maple_tree,
    index: c_ulong,
) -> *mut c_void {
    if mt.is_null() {
        return core::ptr::null_mut();
    }
    announce();
    let h = unsafe { root_of(mt) };
    let es = unsafe { ents_ref(h) };
    covering(es, index).map_or(core::ptr::null_mut(), |i| es[i].ptr)
}

/// C ABI: `mas_walk` for a Rust VMA tree.
///
/// # Safety
///
/// `mas` must point at a live state for a Rust tree.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_walk(mas: *mut bindings::ma_state) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    announce();
    unsafe { do_walk(mas) }
}

/// C ABI: `mas_store` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store(
    mas: *mut bindings::ma_state,
    entry: *mut c_void,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    let err = unsafe { do_store(mas, entry, bindings::GFP_KERNEL) };
    if err != 0 {
        return core::ptr::null_mut();
    }
    core::ptr::null_mut()
}

/// C ABI: `mas_store_gfp` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store_gfp(
    mas: *mut bindings::ma_state,
    entry: *mut c_void,
    gfp: bindings::gfp_t,
) -> c_int {
    if mas.is_null() {
        return EINVAL.to_errno();
    }
    unsafe { do_store(mas, entry, gfp) }
}

/// C ABI: `mas_store_prealloc` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` has a preallocated snapshot or store
/// allocates with `GFP_KERNEL`.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_store_prealloc(
    mas: *mut bindings::ma_state,
    entry: *mut c_void,
) {
    if mas.is_null() {
        return;
    }
    let _ = unsafe { do_store(mas, entry, bindings::GFP_KERNEL) };
}

/// C ABI: `mas_preallocate` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_preallocate(
    mas: *mut bindings::ma_state,
    _entry: *mut c_void,
    gfp: bindings::gfp_t,
) -> c_int {
    if mas.is_null() {
        return EINVAL.to_errno();
    }
    announce();
    let mt = unsafe { (*mas).tree };
    let old = unsafe { root_of(mt) };
    let n = if old.is_null() {
        0
    } else {
        unsafe { (*old).n }
    };
    let cap = n.saturating_add(2).max(1);
    let p = unsafe { alloc_snap(cap, gfp) };
    if p.is_null() {
        unsafe { bindings::mas_set_err(mas, ENOMEM.to_errno()) };
        return ENOMEM.to_errno();
    }
    unsafe {
        (*mas).alloc = p.cast();
        (*mas).mas_flags |= MA_STATE_PREALLOC;
    }
    0
}

/// C ABI: `mas_destroy` for a Rust VMA tree.
///
/// # Safety
///
/// `mas` live. Drops an unused preallocation.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_destroy(mas: *mut bindings::ma_state) {
    if mas.is_null() {
        return;
    }
    let pre = unsafe { (*mas).alloc as *mut Header };
    if !pre.is_null() {
        unsafe { bindings::mt_kvfree(pre.cast()) };
    }
    unsafe {
        (*mas).alloc = core::ptr::null_mut();
        (*mas).mas_flags &= !MA_STATE_PREALLOC;
    }
}

/// C ABI: `mas_find` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find(
    mas: *mut bindings::ma_state,
    max: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    announce();
    match status(mas) {
        MA_ERROR => return core::ptr::null_mut(),
        MA_ACTIVE => {
            if unsafe { (*mas).last } >= max {
                return core::ptr::null_mut();
            }
            return unsafe { next_entry(mas, max, false) };
        }
        MA_OVERFLOW => {
            if unsafe { (*mas).last } >= max {
                return core::ptr::null_mut();
            }
        }
        MA_UNDERFLOW => {
            if unsafe { (*mas).index } >= max {
                unsafe { set_overflow(mas) };
                return core::ptr::null_mut();
            }
        }
        MA_NONE | MA_PAUSE => {
            if unsafe { (*mas).last } >= max {
                return core::ptr::null_mut();
            }
            unsafe { (*mas).index = (*mas).last };
        }
        MA_START => {
            if unsafe { (*mas).index } > max {
                return core::ptr::null_mut();
            }
        }
        _ => {}
    }
    let e = unsafe { do_walk(mas) };
    if !e.is_null() {
        return e;
    }
    unsafe { next_entry(mas, max, false) }
}

/// C ABI: `mas_find_range` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_range(
    mas: *mut bindings::ma_state,
    max: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    match status(mas) {
        MA_START | MA_PAUSE | MA_NONE => {
            let e = unsafe { do_walk(mas) };
            if !e.is_null() {
                return e;
            }
        }
        MA_ERROR => return core::ptr::null_mut(),
        _ => {}
    }
    unsafe { next_entry(mas, max, true) }
}

/// C ABI: `mas_next` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_next(
    mas: *mut bindings::ma_state,
    max: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    if status(mas) == MA_START {
        let _ = unsafe { do_walk(mas) };
    }
    unsafe { next_entry(mas, max, false) }
}

/// C ABI: `mas_next_range` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_next_range(
    mas: *mut bindings::ma_state,
    max: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    if status(mas) == MA_START {
        let _ = unsafe { do_walk(mas) };
    }
    unsafe { next_entry(mas, max, true) }
}

/// C ABI: `mas_prev` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_prev(
    mas: *mut bindings::ma_state,
    min: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    if status(mas) == MA_START {
        let _ = unsafe { do_walk(mas) };
    }
    unsafe { prev_entry(mas, min, false) }
}

/// C ABI: `mas_prev_range` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_prev_range(
    mas: *mut bindings::ma_state,
    min: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    let old_index = unsafe { (*mas).index };
    match status(mas) {
        MA_START | MA_NONE | MA_PAUSE => {
            let _ = unsafe { do_walk(mas) };
        }
        _ => {}
    }
    let e = unsafe { prev_entry(mas, min, true) };
    if unsafe { (*mas).index } >= old_index && old_index > min {
        unsafe {
            (*mas).index = min;
            set_underflow(mas);
        }
        return core::ptr::null_mut();
    }
    e
}

/// C ABI: `mas_find_rev` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_rev(
    mas: *mut bindings::ma_state,
    min: c_ulong,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    match status(mas) {
        MA_START | MA_PAUSE | MA_NONE | MA_UNDERFLOW => {
            let e = unsafe { do_walk(mas) };
            if !e.is_null() {
                return e;
            }
        }
        MA_ERROR => return core::ptr::null_mut(),
        MA_ACTIVE => {
            if unsafe { (*mas).index } <= min {
                return core::ptr::null_mut();
            }
        }
        _ => {}
    }
    unsafe { prev_entry(mas, min, false) }
}

/// C ABI: `mas_find_range_rev` for a Rust VMA tree.
///
/// # Safety
///
/// RCU or mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_find_range_rev(
    mas: *mut bindings::ma_state,
    min: c_ulong,
) -> *mut c_void {
    unsafe { rust_mas_prev_range(mas, min) }
}

/// C ABI: `mas_insert` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` live. Fails with `-EEXIST` if `[index, last]`
/// already holds an entry.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_insert(
    mas: *mut bindings::ma_state,
    entry: *mut c_void,
) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    let index = unsafe { (*mas).index };
    let last = unsafe { (*mas).last };
    let es = unsafe { ents_ref(root_of((*mas).tree)) };
    if let Some(i) = first_ge(es, index) {
        if es[i].start <= last {
            unsafe {
                bindings::mas_set_err(mas, EEXIST.to_errno());
                set_entry(mas, es[i], i);
            }
            return es[i].ptr;
        }
    }
    let err = unsafe { do_store(mas, entry, bindings::GFP_KERNEL) };
    if err != 0 {
        return core::ptr::null_mut();
    }
    core::ptr::null_mut()
}

/// C ABI: `mas_erase` for a Rust VMA tree.
///
/// # Safety
///
/// mmap write lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_erase(mas: *mut bindings::ma_state) -> *mut c_void {
    if mas.is_null() {
        return core::ptr::null_mut();
    }
    let e = unsafe { do_walk(mas) };
    if e.is_null() {
        return core::ptr::null_mut();
    }
    let _ = unsafe { do_store(mas, core::ptr::null_mut(), bindings::GFP_KERNEL) };
    e
}

fn gap_ok(start: usize, end: usize, size: usize) -> Option<usize> {
    if end < start {
        return None;
    }
    let len = end - start + 1;
    if len >= size {
        Some(start)
    } else {
        None
    }
}

/// C ABI: `mas_empty_area` for a Rust VMA tree.
///
/// # Safety
///
/// mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_empty_area(
    mas: *mut bindings::ma_state,
    min: c_ulong,
    max: c_ulong,
    size: c_ulong,
) -> c_int {
    if mas.is_null() {
        return EINVAL.to_errno();
    }
    if min > max || size == 0 || max - min < size - 1 {
        return EINVAL.to_errno();
    }
    let h = unsafe { root_of((*mas).tree) };
    let es = unsafe { ents_ref(h) };
    let mut pos = min;
    for e in es {
        if e.last < min {
            continue;
        }
        if e.start > pos {
            let gap_end = e.start - 1;
            if let Some(s) = gap_ok(pos, gap_end.min(max), size) {
                if s <= max {
                    unsafe {
                        (*mas).index = s;
                        (*mas).last = s + size - 1;
                        (*mas).status = core::mem::transmute(MA_ACTIVE);
                    }
                    return 0;
                }
            }
        }
        if e.last >= max {
            return EBUSY.to_errno();
        }
        pos = e.last + 1;
        if pos < min {
            pos = min;
        }
    }
    if let Some(s) = gap_ok(pos, max, size) {
        unsafe {
            (*mas).index = s;
            (*mas).last = s + size - 1;
            (*mas).status = core::mem::transmute(MA_ACTIVE);
        }
        return 0;
    }
    EBUSY.to_errno()
}

/// C ABI: `mas_empty_area_rev` for a Rust VMA tree.
///
/// # Safety
///
/// mmap lock held. `mas` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mas_empty_area_rev(
    mas: *mut bindings::ma_state,
    min: c_ulong,
    max: c_ulong,
    size: c_ulong,
) -> c_int {
    if mas.is_null() {
        return EINVAL.to_errno();
    }
    if min > max || size == 0 || max - min < size - 1 {
        return EINVAL.to_errno();
    }
    let h = unsafe { root_of((*mas).tree) };
    let es = unsafe { ents_ref(h) };
    let mut pos = max;
    for e in es.iter().rev() {
        if e.start > max {
            continue;
        }
        if e.last < pos {
            let gap_start = e.last + 1;
            let gap_end = pos;
            if gap_end >= gap_start {
                let len = gap_end - gap_start + 1;
                if len >= size {
                    let s = gap_end - size + 1;
                    if s >= min {
                        unsafe {
                            (*mas).index = s;
                            (*mas).last = s + size - 1;
                            (*mas).status = core::mem::transmute(MA_ACTIVE);
                        }
                        return 0;
                    }
                }
            }
        }
        if e.start == 0 {
            break;
        }
        pos = e.start - 1;
        if pos < min {
            return EBUSY.to_errno();
        }
    }
    if pos >= min {
        let len = pos - min + 1;
        if len >= size {
            let s = pos - size + 1;
            if s >= min {
                unsafe {
                    (*mas).index = s;
                    (*mas).last = s + size - 1;
                    (*mas).status = core::mem::transmute(MA_ACTIVE);
                }
                return 0;
            }
        }
    }
    EBUSY.to_errno()
}

/// C ABI: `__mt_destroy` for a Rust VMA tree.
///
/// # Safety
///
/// Write lock held. `mt` live.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_destroy(mt: *mut bindings::maple_tree) {
    if mt.is_null() {
        return;
    }
    let old = unsafe { root_of(mt) };
    unsafe { bindings::mt_rcu_assign_root(mt, core::ptr::null_mut()) };
    if !old.is_null() {
        unsafe { bindings::mt_kvfree_rcu(old.cast()) };
    }
}

/// C ABI: `__mt_dup` for a Rust VMA tree.
///
/// # Safety
///
/// Both trees locked. `new` empty.
#[no_mangle]
pub unsafe extern "C" fn rust_mt_dup(
    mt: *mut bindings::maple_tree,
    new: *mut bindings::maple_tree,
    gfp: bindings::gfp_t,
) -> c_int {
    if mt.is_null() || new.is_null() {
        return EINVAL.to_errno();
    }
    announce();
    if !unsafe { root_of(new) }.is_null() {
        return EINVAL.to_errno();
    }
    let old = unsafe { root_of(mt) };
    if old.is_null() {
        return 0;
    }
    let n = unsafe { (*old).n };
    if n == 0 {
        return 0;
    }
    let p = unsafe { alloc_snap(n, gfp) };
    if p.is_null() {
        return ENOMEM.to_errno();
    }
    unsafe {
        (*p).n = n;
        core::ptr::copy_nonoverlapping(ents(old), ents(p), n as usize);
        bindings::mt_rcu_assign_root(new, p.cast());
    }
    0
}
