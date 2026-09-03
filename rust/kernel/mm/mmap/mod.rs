// SPDX-License-Identifier: GPL-2.0

//! Userspace mmap-family sequencing when `CONFIG_RUST_MMAP=y`.
//!
//! Submodules follow C file responsibility: VA search, mmap install, unmap /
//! teardown, brk, mprotect, mremap, madvise, mlock, msync/mincore, and VMA
//! tree ops. File mmap/shmem, page-table walks, madvise per-hint, seal-range,
//! mlock page-walk, msync, and mincore bodies stay in C. `find_vma_prev`,
//! `do_munmap`, `remove_vma`, and `vma_merge_extend` are also sequenced.
//!
//! The VMA maple tree is a Rust RCU range array. The mmap lock is already
//! held by the C caller except for mprotect, mremap, madvise, mseal, mlock,
//! munlock, mlockall, munlockall, msync, mincore, `vector_madvise`, and
//! `expand_stack`, which take it in apply / lock.

pub mod advise;
pub mod brk;
pub mod lock;
pub mod map;
pub mod protect;
pub mod remap;
pub mod sync;
pub mod unmap;
pub mod unmapped;
pub mod vma;

use crate::prelude::*;

/// Log that Rust is serving `vm_unmapped_area` and mmap-family sequencing.
pub fn announce() {
    pr_info!("rust-mmap: vm_unmapped_area first-fit/topdown and mmap/munmap/brk/mprotect/mremap/madvise/mmap_region/mprotect_fixup/mseal/mlock/mlock_fixup/mprotect_walk/munlock/mlockall/msync/mincore/vector_madvise/madvise_do/madvise_walk/madvise_vma/madvise_dontneed/madvise_update/vma_merge/mmap_new/sys_brk/process_madvise/vm_brk/vma_merge_existing/vma_expand/expand_stack/vma_modify/vma_shrink/commit_merge/remap_file_pages/change_protection/expand_downwards/insert_vm_struct/split_vma/vma_link/copy_vma/do_vmi_align_munmap/unmap_region/install_special_mapping/vms_gather/vms_complete/acct_stack_growth/vms_clean_up/vms_abort/mmap_setup/mmap_new_file/dup_anon_vma/find_mergeable_anon_vma/vma_link_file/vm_munmap/ksys_mmap_pgoff/split_vma_limit/unlink_file_vma_batch_add/exit_mmap/find_vma_prev/do_munmap/remove_vma/vma_merge_extend sequencer\n");
    crate::mm::mtree::announce_once();
}
