//! Integration tests for `--features audit_trace`.

use core::alloc::{GlobalAlloc, Layout};

use rusty_alloc::alloc::{
    free, free_aligned_sized, free_sized, malloc, malloc_aligned, realloc,
};
use rusty_alloc::{
    AuditEvent, AuditOp, AuditViolationKind, RustyAlloc, ra_audit_clear_altstack,
    ra_audit_enable, ra_audit_is_active, ra_audit_last_violation, ra_audit_recent_events,
    ra_audit_register_altstack, ra_audit_set_abort_on_violation, ra_audit_violation_count,
};

#[test]
fn audit_trace_end_to_end() {
    ra_audit_set_abort_on_violation(false);
    assert!(!ra_audit_is_active(), "audit_trace must default to disabled");

    // 1. Runtime enable/disable + flight-recorder event capture.
    ra_audit_enable(true);
    assert!(ra_audit_is_active());

    let p = malloc(64);
    assert!(!p.is_null());
    // SAFETY: `p` was just allocated with size 64.
    unsafe { p.write_bytes(0xAB, 64) };
    // SAFETY: `p` is live and matches size 64.
    unsafe { free_sized(p, 64) };

    let mut events = [AuditEvent {
        seq: 0,
        op: AuditOp::Alloc,
        ptr: 0,
        req_size: 0,
        req_align: 0,
        thread_id: 0,
        generation: 0,
    }; 16];
    let n = ra_audit_recent_events(&mut events);
    assert!(n >= 2, "expected at least 2 flight-recorder events, got {n}");
    assert!(events[..n].iter().any(|e| e.op == AuditOp::Alloc && e.ptr == p.addr() && e.req_size == 64));
    assert!(events[..n].iter().any(|e| e.op == AuditOp::Free && e.ptr == p.addr()));

    // 2. Double-free detection on quarantined block.
    let v_before = ra_audit_violation_count();
    // SAFETY: deliberate double-free under non-aborting audit test mode.
    unsafe { free(p) };
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("double free violation");
    assert_eq!(last.kind, AuditViolationKind::DoubleFree);
    assert_eq!(last.ptr, p.addr());

    // 3. (size, align) mismatch detection via free_sized / free_aligned_sized / GlobalAlloc.
    let p2 = malloc(64);
    assert!(!p2.is_null());
    let v_before = ra_audit_violation_count();
    // SAFETY: deliberate size mismatch under non-aborting audit test mode.
    unsafe { free_sized(p2, 32) };
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("size mismatch violation");
    assert_eq!(last.kind, AuditViolationKind::LayoutMismatch);
    assert_eq!(last.expected_size, 64);
    assert_eq!(last.actual_size, 32);

    let p3 = malloc_aligned(128, 64);
    assert!(!p3.is_null());
    let v_before = ra_audit_violation_count();
    // SAFETY: deliberate align mismatch under non-aborting audit test mode.
    unsafe { free_aligned_sized(p3, 128, 16) };
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("align mismatch violation");
    assert_eq!(last.kind, AuditViolationKind::LayoutMismatch);
    assert_eq!(last.expected_align, 64);
    assert_eq!(last.actual_align, 16);

    let ga = RustyAlloc;
    let l_alloc = Layout::from_size_align(48, 32).expect("valid layout");
    let l_wrong = Layout::from_size_align(48, 64).expect("valid layout");
    // SAFETY: `l_alloc` is valid and non-zero.
    let gp = unsafe { ga.alloc(l_alloc) };
    assert!(!gp.is_null());
    let v_before = ra_audit_violation_count();
    // SAFETY: deliberate GlobalAlloc layout mismatch under non-aborting audit mode.
    unsafe { ga.dealloc(gp, l_wrong) };
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("GlobalAlloc layout mismatch");
    assert_eq!(last.kind, AuditViolationKind::LayoutMismatch);

    // 4. Realloc in-place + move.
    let rp = malloc(64);
    assert!(!rp.is_null());
    // SAFETY: `rp` is live; 48 stays in-place for 64-byte bin.
    let rp2 = unsafe { realloc(rp, 48) };
    assert_eq!(rp2, rp);
    // SAFETY: `rp2` is live.
    unsafe { free_sized(rp2, 48) };

    // 5. Quarantine write-after-free detection (flushed on ra_audit_enable(false)).
    let waf_ptr = malloc(64);
    assert!(!waf_ptr.is_null());
    // SAFETY: `waf_ptr` is live.
    unsafe { free(waf_ptr) };
    // SAFETY: deliberate write-after-free while `waf_ptr` sits in 0xDE quarantine.
    unsafe { waf_ptr.add(7).write(0x42) };
    let v_before = ra_audit_violation_count();
    ra_audit_enable(false);
    assert!(!ra_audit_is_active());
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("write-after-free violation");
    assert_eq!(last.kind, AuditViolationKind::WriteAfterFree);
    assert_eq!(last.ptr, waf_ptr.addr());
    assert_eq!(last.offset, 7);

    // 6. sigaltstack unmap hazard detection (huge segment unmap > 32 MiB).
    ra_audit_enable(true);
    let huge = malloc(36 * 1024 * 1024);
    assert!(!huge.is_null());
    ra_audit_register_altstack(huge, 4096);
    let v_before = ra_audit_violation_count();
    // Freeing >4 MiB default quarantine evicts or releases immediately on flush.
    // SAFETY: `huge` is live.
    unsafe { free(huge) };
    ra_audit_enable(false);
    assert!(ra_audit_violation_count() > v_before);
    let last = ra_audit_last_violation().expect("altstack unmap hazard");
    assert_eq!(last.kind, AuditViolationKind::AltstackUnmapHazard);
    ra_audit_clear_altstack();
}
