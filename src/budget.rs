//! A process-wide budget for bytes of segments in use.
//!
//! This counts complete live segments, including unused space inside them.
//! It does not measure committed pages, physical memory, or idle reservations.
//! Configuration changes do not revoke segments already handed out. Operations
//! allocate no memory and take no lock. Concurrent admissions use a checked CAS
//! so a fixed budget and reserve cannot be oversubscribed.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static LIMIT: AtomicUsize = AtomicUsize::new(0);
static RESERVE: AtomicUsize = AtomicUsize::new(256 * 1024 * 1024);
static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static EXCEEDED: AtomicBool = AtomicBool::new(false);

/// Set the segment-byte budget. Zero disables budget refusals and signalling.
/// Existing live segments remain counted. Lowering below current use raises
/// the sticky flag; disabling the budget does not clear an existing flag.
pub fn set(bytes: usize) {
    LIMIT.store(bytes, Ordering::SeqCst);
    if bytes != 0 && committed() > bytes {
        EXCEEDED.store(true, Ordering::SeqCst);
    }
}

/// Set bytes allowed past the budget, initially 256 MiB.
/// Lowering this does not revoke existing segments.
pub fn set_reserve(bytes: usize) {
    RESERVE.store(bytes, Ordering::SeqCst);
}

/// Bytes of segments currently in use, including their unused portions.
/// The caller-facing name is historical: this is not committed-page usage.
pub fn committed() -> usize {
    IN_USE.load(Ordering::SeqCst)
}

/// Highest segment-byte usage observed, including when the budget is disabled.
pub fn peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}

/// Whether usage has crossed an enabled budget since the last clear.
pub fn exceeded() -> bool {
    EXCEEDED.load(Ordering::SeqCst)
}

/// Clear the sticky flag without changing usage, peak, or configuration.
/// A subsequent admission above the budget raises it again.
pub fn clear() {
    EXCEEDED.store(false, Ordering::SeqCst);
}

pub(crate) fn limit() -> usize {
    LIMIT.load(Ordering::SeqCst)
}

/// Admit a fully prepared segment immediately before infallible publication.
pub(crate) fn try_take(bytes: usize) -> bool {
    let mut old = IN_USE.load(Ordering::SeqCst);
    loop {
        let Some(next) = old.checked_add(bytes) else {
            return false;
        };
        let limit = LIMIT.load(Ordering::SeqCst);
        let reserve = RESERVE.load(Ordering::SeqCst);
        if limit != 0 && next > limit.saturating_add(reserve) {
            return false;
        }
        match IN_USE.compare_exchange_weak(old, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                PEAK.fetch_max(next, Ordering::SeqCst);
                if limit != 0 && next > limit {
                    EXCEEDED.store(true, Ordering::SeqCst);
                }
                return true;
            }
            Err(current) => old = current,
        }
    }
}

/// Release exactly one published segment, before recycling its backing.
pub(crate) fn release(bytes: usize) {
    IN_USE.fetch_sub(bytes, Ordering::SeqCst);
}
