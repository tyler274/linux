// SPDX-License-Identifier: GPL-2.0

//! Mimalloc-inspired slab: size-class pages with local + concurrent freelists.
//!
//! Stage A: [`MiKmalloc`] implements [`crate::alloc::Allocator`] on top of the
//! buddy, usable while C SLUB remains the system allocator.
//!
//! Stage B (`CONFIG_SLAB_MIMALLOC`): C glue in `mm/mimalloc.c` calls the
//! `rust_mi_*` entry points to serve `kmalloc` / `kmem_cache_*`.

mod heap;
mod os;
mod page;

use crate::{
    alloc::{
        dangling_from_layout,
        flags::__GFP_ZERO,
        AllocError,
        Allocator,
        Flags,
        NumaNode, //
    },
    prelude::*,
};

use core::{
    alloc::Layout,
    ptr::{
        self,
        NonNull, //
    },
};

/// Contiguous allocator using mimalloc-style size-class pages.
///
/// Backed by the page allocator (`alloc_pages_node`). Safe to use after the
/// buddy is up. Does not call `kmalloc`.
pub struct MiKmalloc;

/// [`Box`](crate::alloc::Box) allocated with [`MiKmalloc`].
pub type MiBox<T> = crate::alloc::Box<T, MiKmalloc>;
/// [`Vec`](crate::alloc::Vec) allocated with [`MiKmalloc`].
pub type MiVec<T> = crate::alloc::Vec<T, MiKmalloc>;

const ARCH_KMALLOC_MINALIGN: usize = crate::bindings::ARCH_KMALLOC_MINALIGN;

fn nid_raw(nid: NumaNode) -> i32 {
    nid.0
}

// SAFETY: Allocations remain valid until `free`/`realloc`. Any pointer from
// this allocator may be passed to its other methods. GFP flags are forwarded
// to the buddy.
unsafe impl Allocator for MiKmalloc {
    const MIN_ALIGN: usize = ARCH_KMALLOC_MINALIGN;

    unsafe fn realloc(
        ptr: Option<NonNull<u8>>,
        layout: Layout,
        old_layout: Layout,
        flags: Flags,
        nid: NumaNode,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let align = layout.align().max(Self::MIN_ALIGN);
        let size = layout.size();

        if size == 0 {
            if let Some(p) = ptr {
                if old_layout.size() != 0 {
                    // SAFETY: Caller guarantees `p` is our allocation.
                    unsafe { heap::free(p.as_ptr()) };
                }
            }
            return Ok(NonNull::slice_from_raw_parts(
                dangling_from_layout(layout),
                0,
            ));
        }

        let raw = match ptr {
            None => unsafe { heap::malloc(size, align, flags, nid_raw(nid), ptr::null_mut()) },
            Some(_) if old_layout.size() == 0 => unsafe {
                heap::malloc(size, align, flags, nid_raw(nid), ptr::null_mut())
            },
            Some(p) => unsafe { heap::realloc(p.as_ptr(), size, align, flags, nid_raw(nid)) },
        };

        let p = NonNull::new(raw).ok_or(AllocError)?;
        if flags.contains(__GFP_ZERO) && (ptr.is_none() || old_layout.size() == 0) {
            unsafe { ptr::write_bytes(p.as_ptr(), 0, size) };
        } else if flags.contains(__GFP_ZERO) && size > old_layout.size() {
            unsafe {
                ptr::write_bytes(
                    p.as_ptr().add(old_layout.size()),
                    0,
                    size - old_layout.size(),
                );
            }
        }
        Ok(NonNull::slice_from_raw_parts(p, size))
    }
}

/// C ABI used by `mm/mimalloc.c` when `CONFIG_SLAB_MIMALLOC=y`.
#[no_mangle]
pub unsafe extern "C" fn rust_mi_init() {}

/// Allocate `size` bytes (C `kmalloc` backend).
///
/// # Safety
///
/// GFP flags must be valid for the buddy. `cache` may be null.
#[no_mangle]
pub unsafe extern "C" fn rust_mi_alloc(
    size: usize,
    align: usize,
    gfp_flags: u32,
    nid: i32,
    cache: *mut u8,
) -> *mut u8 {
    if size == 0 {
        return 16 as *mut u8; // ZERO_SIZE_PTR
    }
    let flags = Flags(gfp_flags);
    // SAFETY: GFP is forwarded; size is non-zero.
    let p = unsafe { heap::malloc(size, align.max(1), flags, nid, cache) };
    if !p.is_null() && flags.contains(__GFP_ZERO) {
        // SAFETY: `p` is a fresh allocation of at least `size` bytes.
        unsafe { ptr::write_bytes(p, 0, size) };
    }
    p
}

/// Free a pointer from [`rust_mi_alloc`]. Returns `false` on double-free.
///
/// # Safety
///
/// `ptr` is null, `ZERO_SIZE_PTR`, or from this allocator.
#[no_mangle]
pub unsafe extern "C" fn rust_mi_free(ptr: *mut u8) -> bool {
    if ptr.is_null() || (ptr as usize) <= 16 {
        return true;
    }
    // SAFETY: `ptr` is a heap object (or double-free, which we detect).
    unsafe { heap::free(ptr) }
}

/// Usable size of a heap object.
///
/// # Safety
///
/// `ptr` is null, `ZERO_SIZE_PTR`, or from this allocator.
#[no_mangle]
pub unsafe extern "C" fn rust_mi_usable_size(ptr: *const u8) -> usize {
    if ptr.is_null() || (ptr as usize) <= 16 {
        return 0;
    }
    // SAFETY: `ptr` is a heap object.
    unsafe { heap::usable_size(ptr) }
}

/// Reallocate a heap object.
///
/// # Safety
///
/// `ptr` is null, `ZERO_SIZE_PTR`, or from this allocator. GFP flags must be
/// valid for the buddy.
#[no_mangle]
pub unsafe extern "C" fn rust_mi_realloc(
    ptr: *mut u8,
    new_size: usize,
    align: usize,
    gfp_flags: u32,
    nid: i32,
) -> *mut u8 {
    if new_size == 0 {
        // SAFETY: Same as [`rust_mi_free`].
        unsafe { rust_mi_free(ptr) };
        return 16 as *mut u8;
    }
    let flags = Flags(gfp_flags);
    if ptr.is_null() || (ptr as usize) <= 16 {
        // SAFETY: Same as [`rust_mi_alloc`].
        return unsafe { rust_mi_alloc(new_size, align, gfp_flags, nid, ptr::null_mut()) };
    }
    // SAFETY: `ptr` is a live heap object.
    unsafe { heap::realloc(ptr, new_size, align.max(1), flags, nid) }
}

#[cfg(CONFIG_RUST_ALLOCATOR_KUNIT_TEST)]
#[macros::kunit_tests(rust_mi_allocator)]
mod tests {
    use super::*;
    use crate::alloc::flags::GFP_KERNEL;
    use core::mem::MaybeUninit;

    #[test]
    fn malloc_write_free() -> Result {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let p = MiKmalloc::alloc(layout, GFP_KERNEL, NumaNode::NO_NODE).map_err(|_| ENOMEM)?;
        unsafe {
            let raw = p.cast::<u8>();
            ptr::write_bytes(raw.as_ptr(), 0xAB, 64);
            assert_eq!(*raw.as_ptr(), 0xAB);
            MiKmalloc::free(raw, layout);
        }
        Ok(())
    }

    #[test]
    fn realloc_preserves() -> Result {
        let old = Layout::from_size_align(32, 8).unwrap();
        let new = Layout::from_size_align(128, 8).unwrap();
        let p = MiKmalloc::alloc(old, GFP_KERNEL, NumaNode::NO_NODE).map_err(|_| ENOMEM)?;
        unsafe {
            ptr::write_bytes(p.cast::<u8>().as_ptr(), 0xCD, 32);
            let q = MiKmalloc::realloc(Some(p.cast()), new, old, GFP_KERNEL, NumaNode::NO_NODE)
                .map_err(|_| ENOMEM)?;
            assert_eq!(*q.cast::<u8>().as_ptr(), 0xCD);
            MiKmalloc::free(q.cast(), new);
        }
        Ok(())
    }

    #[test]
    fn zeroed() -> Result {
        let layout = Layout::from_size_align(48, 8).unwrap();
        let p = MiKmalloc::alloc(layout, GFP_KERNEL | __GFP_ZERO, NumaNode::NO_NODE)
            .map_err(|_| ENOMEM)?;
        unsafe {
            let raw = p.cast::<u8>().as_ptr();
            for i in 0..48 {
                assert_eq!(*raw.add(i), 0);
            }
            MiKmalloc::free(p.cast(), layout);
        }
        Ok(())
    }

    #[test]
    fn alignment() -> Result {
        let box_ = MiBox::<MaybeUninit<[u8; 64]>>::new_uninit(GFP_KERNEL)?;
        let addr = (&*box_ as *const MaybeUninit<[u8; 64]>) as usize;
        assert_eq!(addr & 7, 0);
        Ok(())
    }

    #[test]
    fn double_free_detected() -> Result {
        let layout = Layout::from_size_align(32, 8).unwrap();
        let p = MiKmalloc::alloc(layout, GFP_KERNEL, NumaNode::NO_NODE).map_err(|_| ENOMEM)?;
        unsafe {
            MiKmalloc::free(p.cast(), layout);
            assert!(!heap::free(p.cast::<u8>().as_ptr()));
        }
        Ok(())
    }

    #[test]
    fn gfp_atomic() -> Result {
        use crate::alloc::flags::GFP_ATOMIC;
        let layout = Layout::from_size_align(16, 8).unwrap();
        // May fail under memory pressure; success path is what we check.
        if let Ok(p) = MiKmalloc::alloc(layout, GFP_ATOMIC, NumaNode::NO_NODE) {
            unsafe { MiKmalloc::free(p.cast(), layout) };
        }
        Ok(())
    }

    #[test]
    fn numa_default() -> Result {
        let layout = Layout::from_size_align(24, 8).unwrap();
        let p = MiKmalloc::alloc(layout, GFP_KERNEL, NumaNode::NO_NODE).map_err(|_| ENOMEM)?;
        unsafe { MiKmalloc::free(p.cast(), layout) };
        Ok(())
    }
}
