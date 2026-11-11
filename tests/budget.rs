//! One isolated process for the process-wide budget and its configuration.

use rusty_alloc::{alloc, arena, budget, segment};
use rusty_alloc::types::{LARGE_OBJ_SIZE_MAX, SEGMENT_SIZE};

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        budget::set(0);
        budget::set_reserve(256 * 1024 * 1024);
        budget::clear();
    }
}

#[test]
fn segment_budget_admission_release_and_huge_allocations() {
    let _reset = Reset;
    budget::set(0);
    budget::clear();
    let baseline = budget::committed();

    // Reserve an exclusive arena first: idle backing is not live segments.
    let id = arena::reserve_os_memory_ex(3 * SEGMENT_SIZE, true, false, true)
        .expect("reserve test arena");
    assert_eq!(budget::committed(), baseline);
    budget::set(baseline + 1);
    budget::set_reserve(SEGMENT_SIZE);
    let seg = segment::segment_alloc(id).expect("soft crossing succeeds");
    assert_eq!(budget::committed(), baseline + SEGMENT_SIZE);
    assert!(budget::exceeded());
    assert!(budget::peak() >= baseline + SEGMENT_SIZE);
    budget::clear();
    assert!(!budget::exceeded());
    let before_peak = budget::peak();
    assert!(segment::segment_alloc(id).is_err());
    assert_eq!(budget::committed(), baseline + SEGMENT_SIZE);
    assert_eq!(budget::peak(), before_peak);
    assert!(!budget::exceeded());
    // SAFETY: seg is a live Normal segment with no allocated pages.
    unsafe { segment::segment_free(seg) }.expect("return segment");
    assert_eq!(budget::committed(), baseline);

    // The denied claim was returned too: all three arena chunks remain usable.
    budget::set(0);
    budget::set_reserve(0);
    let a = segment::segment_alloc(id).expect("reuse first chunk");
    let b = segment::segment_alloc(id).expect("reuse denied chunk");
    let c = segment::segment_alloc(id).expect("reuse final chunk");
    assert_eq!(budget::committed(), baseline + 3 * SEGMENT_SIZE);
    assert!(!budget::exceeded());
    // SAFETY: all three are distinct, live, empty Normal segments, freed once.
    unsafe {
        segment::segment_free(a).unwrap();
        segment::segment_free(b).unwrap();
        segment::segment_free(c).unwrap();
    }
    assert_eq!(budget::committed(), baseline);

    // A real public huge allocation crosses the soft budget and is writable.
    let size = 2 * LARGE_OBJ_SIZE_MAX;
    budget::set(baseline + 1);
    budget::set_reserve(4 * SEGMENT_SIZE);
    let p = alloc::malloc(size);
    assert!(!p.is_null());
    assert!(budget::committed() > baseline);
    assert!(budget::exceeded());
    // SAFETY: p owns at least size writable bytes and is freed exactly once.
    unsafe {
        core::ptr::write_bytes(p, 0x5A, size);
        alloc::free(p);
    }
    alloc::collect(true);
    assert_eq!(budget::committed(), baseline);

    // Denial reaches the public allocator's ordinary null return.
    budget::clear();
    budget::set_reserve(0);
    let peak = budget::peak();
    assert!(alloc::malloc(size).is_null());
    assert_eq!(budget::committed(), baseline);
    assert_eq!(budget::peak(), peak);

    // Placement overflow is another unpublished failure, never charged.
    budget::set(0);
    assert!(segment::huge_alloc(size, 16, usize::MAX, -1).is_err());
    assert_eq!(budget::committed(), baseline);
    assert_eq!(budget::peak(), peak);
    budget::clear();
    let p = alloc::malloc(size);
    assert!(!p.is_null());
    assert!(!budget::exceeded());
    // SAFETY: p is live and freed once.
    unsafe { alloc::free(p) };
    alloc::collect(true);
    assert_eq!(budget::committed(), baseline);
}
