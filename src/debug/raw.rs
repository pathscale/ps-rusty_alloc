//! The raw allocation API (`crate::alloc::malloc`, `free`, `realloc`,
//! `usable_size`, the aligned, zeroing and heap variants) in debug mode.
//!
//! Each public entry of `crate::alloc` calls in here first under
//! `debug_checks`, so a program that allocates through the raw API (the C
//! side of an FFI boundary, a `malloc` shim) gets the same header, canary,
//! fills, quarantine, call sites and leak tracking as `RustyAlloc`, and every
//! free gets the same checks: foreign and interior pointers, double frees,
//! overflows, writes after free. The blocks are marked as raw, so a
//! `RustyAlloc::dealloc` of one is reported as `NotFromGlobalAlloc`.
//!
//! A pointer at the start of a core block carries no debug header: it came
//! from the core directly (`Heap::malloc` and friends, or the debug layer
//! itself handing back a core block). Those are left to the core; that is
//! the `None` (or `false`) these functions return.
//!
//! Allocation entries always answer (`Some`); the `Option` is the shape the
//! call sites in `crate::alloc` share with the entries that may decline.

use super::{
    HDR, Inspect, StackId, Violation, ViolationKind, alloc_block, count, here, inspect, release,
    thread_debug,
};
use crate::init::HeapBox;

/// `malloc` / `zalloc` (and `heap_malloc` / `heap_zalloc` with `hb`).
#[inline(never)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "shared call shape, see the module doc"
)]
pub fn malloc(hb: *mut HeapBox, size: usize, zero: bool) -> Option<*mut u8> {
    let st = here();
    // SAFETY: `hb` is null or, per the heap API's contract, the caller's own.
    Some(unsafe { alloc_block(hb, size, 16, 0, zero, true, st) })
}

/// `malloc_aligned_at` / `zalloc_aligned_at` and their heap variants.
#[inline(never)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "shared call shape, see the module doc"
)]
pub fn malloc_aligned_at(
    hb: *mut HeapBox,
    size: usize,
    align: usize,
    offset: usize,
    zero: bool,
) -> Option<*mut u8> {
    let st = here();
    // SAFETY: as [`malloc`].
    Some(unsafe { alloc_block(hb, size, align, offset, zero, true, st) })
}

/// The checks of a free through the raw API (no layout to compare).
///
/// # Safety
/// `p` is non-null.
unsafe fn check(p: *mut u8, st: StackId) -> Inspect {
    let mut v = Violation::new(ViolationKind::ForeignPointer, p.addr());
    v.stack = st;
    // SAFETY: forwarded.
    unsafe { inspect(&mut v) }
}

/// `free`: true when handled here (checked, and released unless a check
/// failed), false for null or a plain core block, which the core frees.
///
/// # Safety
/// `free`'s contract, which this checks.
#[inline(never)]
pub unsafe fn free(p: *mut u8) -> bool {
    if p.is_null() {
        return false;
    }
    let st = here();
    // SAFETY: forwarded; `release` gets a block `inspect` accepted.
    unsafe {
        match check(p, st) {
            Inspect::Plain => false,
            Inspect::Rejected => true,
            Inspect::Block(h) => {
                release(p, h, st);
                true
            }
        }
    }
}

/// `usable_size`: the requested size of a debug block (its canary starts
/// right after), 0 for a pointer that fails a check, `None` for null or a
/// plain core block.
///
/// # Safety
/// `usable_size`'s contract, which this checks.
pub unsafe fn usable_size(p: *mut u8) -> Option<usize> {
    if p.is_null() {
        return None;
    }
    // SAFETY: forwarded.
    match unsafe { check(p, StackId::NONE) } {
        Inspect::Plain => None,
        Inspect::Rejected => Some(0),
        Inspect::Block(h) => Some(h.size as usize),
    }
}

/// `realloc` and its aligned, zeroing and heap forms. Always moves (so a
/// stale pointer to the old block is caught as a write after free); the
/// new block has `(np + offset) % align == 0`, and with `zero_tail` the bytes
/// past the old size read zero. `None` for a plain core block, which the
/// core reallocates.
///
/// # Safety
/// `realloc`'s contract, which this checks.
#[inline(never)]
pub unsafe fn realloc(
    hb: *mut HeapBox,
    p: *mut u8,
    new_size: usize,
    align: usize,
    offset: usize,
    zero_tail: bool,
) -> Option<*mut u8> {
    let st = here();
    // SAFETY: forwarded; the copy stays inside both blocks.
    unsafe {
        if p.is_null() {
            return Some(alloc_block(
                hb, new_size, align, offset, zero_tail, true, st,
            ));
        }
        let h = match check(p, st) {
            Inspect::Plain => return None,
            Inspect::Rejected => return Some(core::ptr::null_mut()),
            Inspect::Block(h) => h,
        };
        let np = alloc_block(hb, new_size, align, offset, false, true, st);
        if np.is_null() {
            return Some(np);
        }
        let old = h.size as usize;
        core::ptr::copy_nonoverlapping(p, np, old.min(new_size));
        if zero_tail && new_size > old {
            core::ptr::write_bytes(np.add(old), 0, new_size - old);
        }
        if let Some(d) = thread_debug() {
            count(d, |c| c.on_realloc(old, new_size));
        }
        release(p, h, st);
        Some(np)
    }
}

/// `expand`: in place only, so `p` when `new_size` fits the requested size,
/// null otherwise. `None` for null or a plain core block.
///
/// # Safety
/// `expand`'s contract, which this checks.
pub unsafe fn expand(p: *mut u8, new_size: usize) -> Option<*mut u8> {
    if p.is_null() {
        return None;
    }
    // SAFETY: forwarded.
    match unsafe { check(p, StackId::NONE) } {
        Inspect::Plain => None,
        Inspect::Block(h) if new_size <= h.size as usize => Some(p),
        Inspect::Block(_) | Inspect::Rejected => Some(core::ptr::null_mut()),
    }
}

const _: () = assert!(HDR.is_multiple_of(16));
