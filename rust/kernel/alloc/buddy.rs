// SPDX-License-Identifier: GPL-2.0

//! Experimental Rust buddy that owns memblock spans (with C steal as fill-in).
//!
//! With `CONFIG_RUST_BUDDY`, `alloc_pages` / `__free_pages` try this pool
//! first (see `mm/page_alloc.c`). Spans are reserved from memblock before
//! `memblock_free_all` so they never enter the C buddy. Any remaining slots
//! are stolen with `alloc_pages` (`__GFP_COMP`). Split/coalesce uses
//! off-`struct page` metadata so `PageBuddy` is never set. GFP_DMA, orders
//! above [`MAX_ORDER`], and pool misses fall through to C.

use crate::{
    alloc::{
        flags::{
            __GFP_COMP,
            __GFP_NOWARN, //
            GFP_KERNEL,
        },
        Flags, //
    },
    bindings,
    prelude::*,
    sync::atomic::{
        Acquire,
        Atomic,
        Relaxed,
        Release, //
    },
};
use core::cell::UnsafeCell;
use core::ptr;

/// Highest order managed inside a span (2 MiB with 4 KiB pages).
pub const MAX_ORDER: u32 = 9;
/// Number of order buckets, `0..=MAX_ORDER`.
const NR_ORDERS: usize = (MAX_ORDER as usize) + 1;
/// Pages per span.
const SPAN_PAGES: usize = 1 << MAX_ORDER;
/// Maximum number of spans (128 * 2 MiB = 256 MiB).
const NR_SPANS: usize = 128;
const NONE: u16 = 0xFFFF;
const STATE_NONE: u8 = 0xFF;
const STATE_FREE: u8 = 0x80;
/// Per-CPU order-0 cache depth.
const PCP_BATCH: usize = 32;
/// Compile-time cap; skip PCP if `raw_smp_processor_id` is above this.
const MAX_CPUS: usize = 64;

struct Span {
    base_pfn: u64,
    n_pages: u32,
    free_head: [u16; NR_ORDERS],
    next: [u16; SPAN_PAGES],
    state: [u8; SPAN_PAGES],
}

impl Span {
    const fn empty() -> Self {
        Self {
            base_pfn: 0,
            n_pages: 0,
            free_head: [NONE; NR_ORDERS],
            next: [NONE; SPAN_PAGES],
            state: [STATE_NONE; SPAN_PAGES],
        }
    }

    fn contains(&self, pfn: u64) -> bool {
        self.n_pages != 0 && pfn >= self.base_pfn && pfn < self.base_pfn + u64::from(self.n_pages)
    }

    fn rel(&self, pfn: u64) -> u16 {
        (pfn - self.base_pfn) as u16
    }

    fn page(&self, rel: u16) -> *mut bindings::page {
        // SAFETY: `rel` is in-range for a live span; `base_pfn` came from C.
        unsafe { bindings::pfn_to_page((self.base_pfn + u64::from(rel)) as _) }
    }

    fn push_free(&mut self, rel: u16, order: u32) {
        let o = order as usize;
        let idx = rel as usize;
        self.state[idx] = STATE_FREE | (order as u8);
        self.next[idx] = self.free_head[o];
        self.free_head[o] = rel;
        let n = 1usize << order;
        for i in 1..n {
            self.state[idx + i] = STATE_NONE;
        }
    }

    fn pop_free(&mut self, order: u32) -> Option<u16> {
        let o = order as usize;
        let rel = self.free_head[o];
        if rel == NONE {
            return None;
        }
        let idx = rel as usize;
        self.free_head[o] = self.next[idx];
        self.next[idx] = NONE;
        self.state[idx] = order as u8;
        Some(rel)
    }

    fn unlink_free(&mut self, rel: u16, order: u32) {
        let o = order as usize;
        let mut prev = NONE;
        let mut cur = self.free_head[o];
        while cur != NONE {
            if cur == rel {
                let next = self.next[rel as usize];
                if prev == NONE {
                    self.free_head[o] = next;
                } else {
                    self.next[prev as usize] = next;
                }
                self.next[rel as usize] = NONE;
                return;
            }
            prev = cur;
            cur = self.next[cur as usize];
        }
    }

    fn alloc(&mut self, want: u32) -> Option<u16> {
        let mut order = want;
        while order <= MAX_ORDER {
            if let Some(rel) = self.pop_free(order) {
                while order > want {
                    order -= 1;
                    let buddy = rel ^ (1u16 << order);
                    self.push_free(buddy, order);
                }
                self.state[rel as usize] = want as u8;
                let n = 1usize << want;
                for i in 1..n {
                    self.state[rel as usize + i] = STATE_NONE;
                }
                return Some(rel);
            }
            order += 1;
        }
        None
    }

    fn free(&mut self, mut rel: u16, mut order: u32) {
        while order < MAX_ORDER {
            let buddy = rel ^ (1u16 << order);
            if u32::from(buddy) >= self.n_pages {
                break;
            }
            let st = self.state[buddy as usize];
            if st != (STATE_FREE | order as u8) {
                break;
            }
            self.unlink_free(buddy, order);
            rel &= !(1u16 << order);
            order += 1;
        }
        self.push_free(rel, order);
    }
}

struct Buddy {
    lock: Atomic<i32>,
    spans: [Span; NR_SPANS],
}

impl Buddy {
    const fn new() -> Self {
        Self {
            lock: Atomic::new(0),
            spans: [const { Span::empty() }; NR_SPANS],
        }
    }
}

struct BuddyCell(UnsafeCell<Buddy>);

// SAFETY: All mutating access goes through [`LockGuard`]'s TAS + IRQ-save.
unsafe impl Sync for BuddyCell {}

static BUDDY: BuddyCell = BuddyCell(UnsafeCell::new(Buddy::new()));
static READY: Atomic<i32> = Atomic::new(0);
static STEALING: Atomic<i32> = Atomic::new(0);
static N_SPANS: Atomic<i32> = Atomic::new(0);
static N_MEMBLOCK: Atomic<i32> = Atomic::new(0);

struct Pcp {
    n: u16,
    pages: [*mut bindings::page; PCP_BATCH],
}

impl Pcp {
    const fn empty() -> Self {
        Self {
            n: 0,
            pages: [ptr::null_mut(); PCP_BATCH],
        }
    }
}

struct PcpCell(UnsafeCell<[Pcp; MAX_CPUS]>);

// SAFETY: Each slot is only mutated on its CPU with IRQs off.
unsafe impl Sync for PcpCell {}

static PCPS: PcpCell = PcpCell(UnsafeCell::new([const { Pcp::empty() }; MAX_CPUS]));

fn current_cpu() -> usize {
    // SAFETY: `raw_smp_processor_id` is always safe to read.
    (unsafe { bindings::raw_smp_processor_id() }) as usize
}

fn pcp_this() -> Option<*mut Pcp> {
    let cpu = current_cpu();
    if cpu >= MAX_CPUS {
        return None;
    }
    // SAFETY: `cpu` is in range; IRQs off on this CPU for mutation.
    Some(unsafe { (*PCPS.0.get()).as_mut_ptr().add(cpu) })
}

fn freeze_block(page: *mut bindings::page, order: u32) {
    let nr = 1usize << order;
    for j in 0..nr {
        // SAFETY: `page` is the start of `nr` pages we own.
        unsafe { bindings::set_page_count(page.add(j), 0) };
    }
}

fn pcp_pop() -> *mut bindings::page {
    let _irq = IrqSave::save();
    let Some(p) = pcp_this() else {
        return ptr::null_mut();
    };
    // SAFETY: IRQs off; this CPU owns the slot.
    let pcp = unsafe { &mut *p };
    if pcp.n == 0 {
        return ptr::null_mut();
    }
    pcp.n -= 1;
    let page = pcp.pages[pcp.n as usize];
    pcp.pages[pcp.n as usize] = ptr::null_mut();
    page
}

fn pcp_push(page: *mut bindings::page) -> bool {
    let _irq = IrqSave::save();
    let Some(p) = pcp_this() else {
        return false;
    };
    // SAFETY: IRQs off; this CPU owns the slot.
    let pcp = unsafe { &mut *p };
    if pcp.n as usize >= PCP_BATCH {
        return false;
    }
    pcp.pages[pcp.n as usize] = page;
    pcp.n += 1;
    true
}

fn pcp_refill() {
    let _irq = IrqSave::save();
    let Some(p) = pcp_this() else {
        return;
    };
    // SAFETY: IRQs off; this CPU owns the slot.
    let pcp = unsafe { &mut *p };
    if pcp.n as usize >= PCP_BATCH / 2 {
        return;
    }
    let mut guard = LockGuard::acquire();
    let b = guard.inner();
    let n = N_SPANS.load(Relaxed) as usize;
    while (pcp.n as usize) < PCP_BATCH / 2 {
        let mut got = ptr::null_mut();
        for i in 0..n {
            if let Some(rel) = b.spans[i].alloc(0) {
                got = b.spans[i].page(rel);
                break;
            }
        }
        if got.is_null() {
            break;
        }
        freeze_block(got, 0);
        pcp.pages[pcp.n as usize] = got;
        pcp.n += 1;
    }
}

fn buddy() -> *mut Buddy {
    BUDDY.0.get()
}

struct IrqSave(crate::ffi::c_ulong);

impl IrqSave {
    fn save() -> Self {
        // SAFETY: Saving IRQ flags is always valid.
        Self(unsafe { bindings::local_irq_save() })
    }
}

impl Drop for IrqSave {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from [`IrqSave::save`] on this CPU.
        unsafe { bindings::local_irq_restore(self.0) };
    }
}

struct LockGuard {
    b: *mut Buddy,
    _irq: IrqSave,
}

impl LockGuard {
    fn acquire() -> Self {
        let irq = IrqSave::save();
        let b = buddy();
        loop {
            // SAFETY: `b` is the process-lifetime buddy; TAS serializes `&mut`.
            match unsafe { (*b).lock.cmpxchg(0, 1, Relaxed) } {
                Ok(_) => return Self { b, _irq: irq },
                Err(_) => core::hint::spin_loop(),
            }
        }
    }

    fn inner(&mut self) -> &mut Buddy {
        // SAFETY: We hold the TAS lock.
        unsafe { &mut *self.b }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // SAFETY: We hold the TAS lock; Release publishes list updates.
        unsafe { (*self.b).lock.store(0, Release) };
    }
}

fn gfp_may_block(gfp: Flags) -> bool {
    // SAFETY: Inspects GFP bits only.
    unsafe { bindings::gfpflags_allow_blocking(gfp.as_raw()) }
}

fn steal_span(gfp: Flags) -> *mut bindings::page {
    let flags = (gfp | __GFP_COMP | __GFP_NOWARN).as_raw();
    // SAFETY: GFP is a sleeping combination; caller does not hold the buddy lock.
    unsafe { bindings::alloc_pages_node(bindings::NUMA_NO_NODE, flags, MAX_ORDER) }
}

fn add_span_at(pfn: u64) -> bool {
    let mut guard = LockGuard::acquire();
    let b = guard.inner();
    let n = N_SPANS.load(Relaxed) as usize;
    if n >= NR_SPANS {
        return false;
    }
    let span = &mut b.spans[n];
    *span = Span::empty();
    span.base_pfn = pfn;
    span.n_pages = SPAN_PAGES as u32;
    span.push_free(0, MAX_ORDER);
    N_SPANS.store((n as i32) + 1, Release);
    true
}

fn add_span(page: *mut bindings::page) -> bool {
    // SAFETY: `page` is a compound folio of `MAX_ORDER` we own from C.
    unsafe { bindings::destroy_compound_page(page) };
    // SAFETY: `page` remains a valid `struct page` after destroying compound.
    let pfn = unsafe { bindings::page_to_pfn(page) } as u64;
    add_span_at(pfn)
}

/// Import a memblock-reserved span. The C side has already cleared
/// `PageReserved` and set refcounts to zero.
///
/// Returns 0 on success, `-1` if the table is full.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_add_span(pfn: crate::ffi::c_ulong) -> i32 {
    if add_span_at(pfn as u64) {
        N_MEMBLOCK.store(N_MEMBLOCK.load(Relaxed) + 1, Relaxed);
        0
    } else {
        -1
    }
}

fn announce() {
    if N_SPANS.load(Relaxed) == 0 {
        return;
    }
    pr_info!(
        "rust-buddy: {} memblock + {} stolen order-{} spans ({} KiB), pcp {}\n",
        N_MEMBLOCK.load(Relaxed),
        N_SPANS.load(Relaxed) - N_MEMBLOCK.load(Relaxed),
        MAX_ORDER,
        (N_SPANS.load(Relaxed) as usize) * SPAN_PAGES * crate::page::PAGE_SIZE / 1024,
        PCP_BATCH
    );
}

fn return_span_to_c(page: *mut bindings::page) {
    // SAFETY: We still own this folio; restore compound before C free.
    unsafe {
        bindings::prep_compound_page(page, MAX_ORDER);
        bindings::__free_pages(page, MAX_ORDER);
    }
}

/// Steal spans from the C buddy. Safe to call more than once.
///
/// Does nothing if `gfp` cannot sleep (IRQ / `GFP_ATOMIC`). Sets [`STEALING`]
/// so a nested `alloc_pages` from this CPU falls through to C.
pub fn maybe_init(gfp: Flags) {
    if READY.load(Acquire) != 0 {
        return;
    }
    if !gfp_may_block(gfp) {
        return;
    }
    if STEALING.cmpxchg(0, 1, Relaxed).is_err() {
        return;
    }

    let steal_gfp = GFP_KERNEL | __GFP_COMP | __GFP_NOWARN;
    while (N_SPANS.load(Relaxed) as usize) < NR_SPANS {
        let page = steal_span(steal_gfp);
        if page.is_null() {
            break;
        }
        if !add_span(page) {
            return_span_to_c(page);
            break;
        }
    }
    READY.store(1, Release);
    STEALING.store(0, Release);
    announce();
}

/// Initialise the pool with a sleeping GFP. Called from `rust_mi_init`.
pub fn init(gfp: Flags) {
    maybe_init(gfp);
}

/// True if `page` lies in a stolen span.
///
/// # Safety
///
/// `page` must be a live `struct page`.
pub unsafe fn owns(page: *mut bindings::page) -> bool {
    if page.is_null() {
        return false;
    }
    // SAFETY: Caller guarantees a valid page.
    let pfn = unsafe { bindings::page_to_pfn(page) } as u64;
    let n = N_SPANS.load(Acquire) as usize;
    // SAFETY: Spans `0..n` are immutable after publish.
    let b = unsafe { &*buddy() };
    for i in 0..n {
        if b.spans[i].contains(pfn) {
            return true;
        }
    }
    false
}

/// Allocate `1 << order` contiguous pages from the pool, or null.
///
/// The returned pages are frozen (`refcount == 0`) and not compound.
/// Falls through (null) when the pool is empty or `order > MAX_ORDER`.
fn alloc_block(order: u32, gfp: Flags) -> *mut bindings::page {
    maybe_init(gfp);
    if order > MAX_ORDER || N_SPANS.load(Acquire) == 0 {
        return ptr::null_mut();
    }

    if order == 0 {
        let page = pcp_pop();
        if !page.is_null() {
            freeze_block(page, 0);
            return page;
        }
    }

    let mut guard = LockGuard::acquire();
    let b = guard.inner();
    let n = N_SPANS.load(Relaxed) as usize;
    for i in 0..n {
        if let Some(rel) = b.spans[i].alloc(order) {
            let page = b.spans[i].page(rel);
            drop(guard);
            freeze_block(page, order);
            if order == 0 {
                pcp_refill();
            }
            return page;
        }
    }
    ptr::null_mut()
}

/// Allocate a counted folio for slab / vmalloc, or null.
///
/// Falls through (null) when the pool is empty or `order > MAX_ORDER`.
pub fn alloc(order: u32, gfp: Flags) -> *mut bindings::page {
    let page = alloc_block(order, gfp);
    if page.is_null() {
        return page;
    }
    // SAFETY: Frozen page from [`alloc_block`]; slab wants refcount 1.
    unsafe { bindings::set_page_count(page, 1) };
    if order > 0 {
        // SAFETY: `page` is the start of `1 << order` pages we own.
        unsafe { bindings::prep_compound_page(page, order) };
    }
    page
}

/// C ABI: frozen pages for `mm/page_alloc.c`. Returns null to fall back to C.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_alloc_pages(
    gfp: u32,
    order: u32,
    _nid: i32,
) -> *mut bindings::page {
    if STEALING.load(Acquire) != 0 {
        return ptr::null_mut();
    }
    alloc_block(order, crate::alloc::Flags(gfp))
}

/// C ABI: true if `page` lies in a stolen span.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_owns_page(page: *const bindings::page) -> bool {
    // SAFETY: Caller passes a live `struct page` or null.
    unsafe { owns(page.cast_mut()) }
}

/// C ABI: return a frozen block to the pool.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_free_pages(page: *mut bindings::page, order: u32) {
    if page.is_null() {
        return;
    }
    // SAFETY: Frozen block from [`rust_buddy_alloc_pages`] or an equivalent
    // counted alloc whose refcount already dropped to zero.
    unsafe { free(page, order) };
}

/// C ABI used by `mm/rust_vmalloc.c`.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_alloc_page(gfp: u32, _nid: i32) -> *mut bindings::page {
    alloc(0, crate::alloc::Flags(gfp))
}

/// C ABI used by `mm/rust_vmalloc.c`.
#[no_mangle]
pub unsafe extern "C" fn rust_buddy_free_page(page: *mut bindings::page) {
    if page.is_null() {
        return;
    }
    // SAFETY: Live page from the C or Rust buddy.
    if unsafe { owns(page) } {
        // SAFETY: `owns` confirmed this is a stolen span page.
        unsafe { free(page, 0) };
        return;
    }
    // SAFETY: Foreign order-0 page from `alloc_pages`.
    unsafe { bindings::__free_pages(page, 0) };
}

/// Return a block previously obtained from [`alloc`].
///
/// # Safety
///
/// `page` must be a block from [`alloc`] with the same `order`.
pub unsafe fn free(page: *mut bindings::page, order: u32) {
    if page.is_null() || order > MAX_ORDER {
        return;
    }
    if order > 0 {
        // SAFETY: Alloc path called `prep_compound_page` for `order > 0`.
        unsafe { bindings::destroy_compound_page(page) };
    } else if pcp_push(page) {
        return;
    }
    // SAFETY: `page` is a valid page in a stolen span.
    let pfn = unsafe { bindings::page_to_pfn(page) } as u64;
    let mut guard = LockGuard::acquire();
    let b = guard.inner();
    let n = N_SPANS.load(Relaxed) as usize;
    for i in 0..n {
        if b.spans[i].contains(pfn) {
            let rel = b.spans[i].rel(pfn);
            b.spans[i].free(rel, order);
            return;
        }
    }
}

#[cfg(CONFIG_RUST_ALLOCATOR_KUNIT_TEST)]
#[macros::kunit_tests(rust_buddy)]
mod tests {
    use super::*;
    use crate::alloc::flags::GFP_KERNEL;
    use core::ptr;

    #[test]
    fn order0_write_free() -> Result {
        init(GFP_KERNEL);
        let page = alloc(0, GFP_KERNEL);
        if page.is_null() {
            return Ok(());
        }
        unsafe {
            let addr = bindings::page_address(page).cast::<u8>();
            ptr::write(addr, 0x5A);
            assert_eq!(ptr::read(addr), 0x5A);
            free(page, 0);
        }
        Ok(())
    }

    #[test]
    fn order2_compound() -> Result {
        init(GFP_KERNEL);
        let page = alloc(2, GFP_KERNEL);
        if page.is_null() {
            return Ok(());
        }
        unsafe {
            assert_eq!(bindings::compound_order(page), 2);
            free(page, 2);
        }
        Ok(())
    }

    #[test]
    fn split_and_coalesce() -> Result {
        init(GFP_KERNEL);
        let hi = alloc(1, GFP_KERNEL);
        if hi.is_null() {
            return Ok(());
        }
        unsafe { free(hi, 1) };

        let a = alloc(0, GFP_KERNEL);
        let b = alloc(0, GFP_KERNEL);
        if a.is_null() || b.is_null() {
            if !a.is_null() {
                unsafe { free(a, 0) };
            }
            if !b.is_null() {
                unsafe { free(b, 0) };
            }
            return Ok(());
        }
        unsafe {
            free(a, 0);
            free(b, 0);
        }
        let again = alloc(1, GFP_KERNEL);
        if !again.is_null() {
            unsafe { free(again, 1) };
        }
        Ok(())
    }

    #[test]
    fn owns_roundtrip() -> Result {
        init(GFP_KERNEL);
        let page = alloc(0, GFP_KERNEL);
        if page.is_null() {
            return Ok(());
        }
        unsafe {
            assert!(owns(page));
            free(page, 0);
        }
        Ok(())
    }
}
