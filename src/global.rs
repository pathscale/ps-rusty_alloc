//! `RustyAlloc`: the `GlobalAlloc` front end of this crate.
//!
//! The same routing as the published `rusty_alloc-api` 2.2.6 `RustyAlloc`
//! (MIT), so a Rust program gets the exact path the benchmarks measure. With
//! the `debug_checks` feature every call goes through [`crate::debug`]
//! instead; without it this file is the whole story and the debug layer does
//! not exist in the binary.

use core::alloc::{GlobalAlloc, Layout};

/// The global allocator. `#[global_allocator] static A: RustyAlloc = RustyAlloc;`
pub struct RustyAlloc;

const WORD: usize = core::mem::size_of::<usize>();
const NATURAL_ALIGN: usize = 2 * WORD;

// SAFETY: every method forwards to the core allocator, which returns blocks of
// at least the requested size and alignment, or null.
unsafe impl GlobalAlloc for RustyAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= WORD {
            crate::alloc::malloc(layout.size())
        } else if layout.align() <= NATURAL_ALIGN {
            crate::alloc::malloc(layout.size().max(NATURAL_ALIGN))
        } else {
            // SAFETY: `Layout` guarantees a power-of-two alignment.
            unsafe { crate::alloc::malloc_aligned_pow2(layout.size(), layout.align()) }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: the caller passes a live pointer from this allocator.
        unsafe {
            core::hint::assert_unchecked(!ptr.is_null());
            crate::alloc::free_inline(ptr)
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= WORD {
            crate::alloc::zalloc(layout.size())
        } else if layout.align() <= NATURAL_ALIGN {
            crate::alloc::zalloc(layout.size().max(NATURAL_ALIGN))
        } else {
            crate::alloc::zalloc_aligned(layout.size(), layout.align())
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= NATURAL_ALIGN {
            let new_size = if layout.align() <= WORD {
                new_size
            } else {
                new_size.max(NATURAL_ALIGN)
            };
            // SAFETY: the caller passes a live pointer from this allocator.
            unsafe {
                core::hint::assert_unchecked(!ptr.is_null());
                crate::alloc::realloc(ptr, new_size)
            }
        } else {
            // SAFETY: the caller passes a live pointer from this allocator.
            let usable = unsafe { crate::alloc::usable_size(ptr) };
            if new_size <= usable && new_size >= usable / 2 {
                return ptr;
            }
            // SAFETY: `new_size` with the old power-of-two alignment is a valid
            // layout per the `GlobalAlloc::realloc` contract; the copy stays
            // inside both blocks.
            unsafe {
                let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
                let np = GlobalAlloc::alloc(self, new_layout);
                if !np.is_null() {
                    core::ptr::copy_nonoverlapping(ptr, np, layout.size().min(new_size));
                    GlobalAlloc::dealloc(self, ptr, layout);
                }
                np
            }
        }
    }
}
