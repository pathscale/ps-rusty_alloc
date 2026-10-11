//! GlobalAlloc over the local ps-rusty_alloc core. Same logic as the published
//! rusty_alloc-api 2.2.6 RustyAlloc impl (MIT, remade-with-rust), so the bench
//! measures the exact path a Rust user gets, but against the local fork.

use core::alloc::{GlobalAlloc, Layout};

pub struct RustyAlloc;

const WORD: usize = core::mem::size_of::<usize>();
const NATURAL_ALIGN: usize = 2 * WORD;

unsafe impl GlobalAlloc for RustyAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= WORD {
            rusty_alloc::alloc::malloc(layout.size())
        } else if layout.align() <= NATURAL_ALIGN {
            rusty_alloc::alloc::malloc(layout.size().max(NATURAL_ALIGN))
        } else {
            unsafe { rusty_alloc::alloc::malloc_aligned_pow2(layout.size(), layout.align()) }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            core::hint::assert_unchecked(!ptr.is_null());
            rusty_alloc::alloc::free_inline(ptr)
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= WORD {
            rusty_alloc::alloc::zalloc(layout.size())
        } else if layout.align() <= NATURAL_ALIGN {
            rusty_alloc::alloc::zalloc(layout.size().max(NATURAL_ALIGN))
        } else {
            rusty_alloc::alloc::zalloc_aligned(layout.size(), layout.align())
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= NATURAL_ALIGN {
            let new_size = if layout.align() <= WORD { new_size } else { new_size.max(NATURAL_ALIGN) };
            unsafe {
                core::hint::assert_unchecked(!ptr.is_null());
                rusty_alloc::alloc::realloc(ptr, new_size)
            }
        } else {
            let usable = unsafe { rusty_alloc::alloc::usable_size(ptr) };
            if new_size <= usable && new_size >= usable / 2 {
                return ptr;
            }
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
