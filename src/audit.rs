//! Zero-default-cost `audit_trace` security mode (`--features audit_trace`).
//!
//! When runtime tracing is disabled (`RUSTY_ALLOC_AUDIT_TRACE=0`, the default),
//! `malloc` and `free` fast paths execute zero extra branches. When enabled
//! via `RUSTY_ALLOC_AUDIT_TRACE=1` or [`ra_audit_enable`], `Heap` keeps
//! `direct[]` pointed at the empty sentinel and stamps `pflags::AUDIT_TRACED`
//! on pages so allocations and frees route through the slow paths into:
//! - a lock-free OS-mmap'd flight-recorder ring (`AuditRing`),
//! - an OS-mmap'd shadow `(size, align, generation)` side-table,
//! - a bounded `0xDE` poison quarantine ring with write-after-free offset
//!   detection, and
//! - FORGE Pattern C lifecycle guards (`sigaltstack` unmap/atexit hazard and
//!   `pthread_atfork` lock-held hazard).

use core::cell::{Cell, UnsafeCell};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crate::page::pflags;
use crate::types::{BIN_FULL, BIN_HUGE};

/// Capacity of the lock-free flight-recorder ring (power of two).
const RING_CAP: usize = 4096;
/// Capacity of the open-addressed shadow table (power of two).
const SHADOW_CAP: usize = 65536;
/// Capacity of the bounded poison quarantine ring (power of two).
const QUARANTINE_CAP: usize = 4096;
/// Default quarantine byte budget (4 MiB).
const DEFAULT_QUARANTINE_BYTES: usize = 4 * 1024 * 1024;
/// Poison byte written to quarantined blocks.
const POISON_BYTE: u8 = 0xDE;

/// Operation kind recorded in the flight-recorder ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditOp {
    /// Allocation (`malloc`, `zalloc`, `malloc_aligned`, etc.).
    Alloc = 1,
    /// Deallocation (`free`, `dealloc`, `free_sized`, `free_aligned_sized`).
    Free = 2,
    /// In-place reallocation (`realloc`, etc.).
    Realloc = 3,
    /// Quarantine eviction (poison verified and block released).
    QuarantineEvict = 4,
    /// Security or lifecycle violation detected.
    Violation = 5,
}

/// Single event in the lock-free flight-recorder ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AuditEvent {
    /// Monotonic 1-based sequence number.
    pub seq: u64,
    /// Operation kind.
    pub op: AuditOp,
    /// Pointer associated with the operation.
    pub ptr: usize,
    /// Requested size in bytes.
    pub req_size: usize,
    /// Requested alignment in bytes.
    pub req_align: usize,
    /// Calling thread identifier.
    pub thread_id: usize,
    /// Allocation generation counter for this pointer slot.
    pub generation: u32,
}

impl AuditEvent {
    const fn empty() -> Self {
        Self {
            seq: 0,
            op: AuditOp::Alloc,
            ptr: 0,
            req_size: 0,
            req_align: 0,
            thread_id: 0,
            generation: 0,
        }
    }
}

/// Kind of security or lifecycle violation detected by `audit_trace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditViolationKind {
    /// Freeing a block that is already freed or sitting in quarantine.
    DoubleFree = 1,
    /// Freeing a pointer that was never recorded or is not live.
    InvalidFree = 2,
    /// Deallocation `(size, align)` does not match the recorded allocation.
    LayoutMismatch = 3,
    /// A quarantined block's `0xDE` poison bytes were modified after free.
    WriteAfterFree = 4,
    /// An active `sigaltstack` range was unmapped or remained active at `atexit`.
    AltstackUnmapHazard = 5,
    /// `fork()` occurred while audit/quarantine locks were held.
    MultithreadedForkHazard = 6,
}

impl AuditViolationKind {
    /// Alias for [`AuditViolationKind::WriteAfterFree`] highlighting quarantine poison corruption.
    #[allow(non_upper_case_globals)]
    pub const QuarantineWriteCorrupted: Self = Self::WriteAfterFree;

    const fn name(self) -> &'static str {
        match self {
            Self::DoubleFree => "double_free",
            Self::InvalidFree => "invalid_free",
            Self::LayoutMismatch => "layout_mismatch",
            Self::WriteAfterFree => "write_after_free",
            Self::AltstackUnmapHazard => "altstack_unmap_hazard",
            Self::MultithreadedForkHazard => "multithreaded_fork_hazard",
        }
    }
}

/// Violation record captured by `audit_trace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AuditViolation {
    /// Violation classification.
    pub kind: AuditViolationKind,
    /// Pointer associated with the violation.
    pub ptr: usize,
    /// Expected/recorded size (or `sigaltstack` length).
    pub expected_size: usize,
    /// Expected/recorded alignment.
    pub expected_align: usize,
    /// Actual size passed at deallocation (0 if N/A).
    pub actual_size: usize,
    /// Actual alignment passed at deallocation (0 if N/A).
    pub actual_align: usize,
    /// Byte offset of corruption for `WriteAfterFree` (0 otherwise).
    pub offset: usize,
    /// Allocation generation at the time of the violation.
    pub generation: u32,
    /// Thread ID that observed the violation.
    pub thread_id: usize,
}

impl AuditViolation {
    const fn empty() -> Self {
        Self {
            kind: AuditViolationKind::InvalidFree,
            ptr: 0,
            expected_size: 0,
            expected_align: 0,
            actual_size: 0,
            actual_align: 0,
            offset: 0,
            generation: 0,
            thread_id: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Global runtime state (zero heap allocation, zero re-entrancy)
// ---------------------------------------------------------------------------

/// Lazy initialization state: 0 = uninit, 1 = initializing, 2 = initialized.
static INIT_STATE: AtomicU8 = AtomicU8::new(0);
/// Runtime active flag.
static AUDIT_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Whether violations abort the process (false when `RUSTY_ALLOC_AUDIT_KEEP_GOING=1`).
static ABORT_ON_VIOLATION: AtomicBool = AtomicBool::new(true);
/// Whether `ra_audit_set_abort_on_violation` explicitly overrode env default.
static ABORT_OVERRIDDEN: AtomicBool = AtomicBool::new(false);
/// Bounded quarantine byte budget.
static QUARANTINE_BUDGET: AtomicUsize = AtomicUsize::new(DEFAULT_QUARANTINE_BYTES);

/// Total violations recorded.
static VIOLATION_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Per-kind atomic anomaly counters.
static DOUBLE_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
static INVALID_FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAYOUT_MISMATCH_COUNT: AtomicUsize = AtomicUsize::new(0);
static QUARANTINE_WRITE_CORRUPTED_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALTSTACK_HAZARD_COUNT: AtomicUsize = AtomicUsize::new(0);
static FORK_HAZARD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Snapshot of atomic anomaly counts recorded by `audit_trace`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditAnomalyCounts {
    /// Total violations recorded across all categories.
    pub total: usize,
    /// Double-free or stale-generation quarantine violations.
    pub double_free: usize,
    /// Invalid/untracked pointer free or realloc violations.
    pub invalid_free: usize,
    /// Deallocation or realloc `(size, align)` mismatches.
    pub layout_mismatch: usize,
    /// Quarantined `0xDE` poison-byte corruption (use-after-free write).
    pub quarantine_write_corrupted: usize,
    /// `sigaltstack` unmap/atexit lifecycle hazards.
    pub altstack_unmap_hazard: usize,
    /// Multithreaded `fork()` lock-held hazards.
    pub multithreaded_fork_hazard: usize,
}

/// Capacity of the anonymous-mmap'd anomaly drain ring (power of two).
const ANOMALY_RING_CAP: usize = 1024;

struct AnomalyQueue {
    buf: *mut AuditViolation,
    head: usize,
    tail: usize,
    len: usize,
}

impl AnomalyQueue {
    const fn new() -> Self {
        Self {
            buf: ptr::null_mut(),
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// # Safety
    /// Caller must hold `VIOLATION_LOCK`.
    unsafe fn ensure_init(&mut self) -> bool {
        if !self.buf.is_null() {
            return true;
        }
        let bytes = ANOMALY_RING_CAP * core::mem::size_of::<AuditViolation>();
        // SAFETY: `bytes` is nonzero; `os_mmap_zeroed` returns zeroed pages or null.
        let mem = unsafe { os_mmap_zeroed(bytes) };
        if mem.is_null() {
            return false;
        }
        self.buf = mem.cast();
        true
    }

    /// # Safety
    /// Caller must hold `VIOLATION_LOCK`.
    unsafe fn push(&mut self, v: AuditViolation) {
        // SAFETY: caller holds `VIOLATION_LOCK`.
        if !unsafe { self.ensure_init() } {
            return;
        }
        if self.len == ANOMALY_RING_CAP {
            // Overwrite oldest entry when full.
            self.head = (self.head + 1) & (ANOMALY_RING_CAP - 1);
            self.len -= 1;
        }
        // SAFETY: `self.tail < ANOMALY_RING_CAP` and `self.buf` is initialized.
        unsafe {
            self.buf.add(self.tail).write(v);
        }
        self.tail = (self.tail + 1) & (ANOMALY_RING_CAP - 1);
        self.len += 1;
    }

    /// # Safety
    /// Caller must hold `VIOLATION_LOCK`.
    unsafe fn drain(&mut self, out: &mut [AuditViolation]) -> usize {
        if self.buf.is_null() || self.len == 0 || out.is_empty() {
            return 0;
        }
        let n = self.len.min(out.len());
        for slot in out.iter_mut().take(n) {
            // SAFETY: `self.head < ANOMALY_RING_CAP` and `self.buf` is initialized.
            *slot = unsafe { self.buf.add(self.head).read() };
            self.head = (self.head + 1) & (ANOMALY_RING_CAP - 1);
            self.len -= 1;
        }
        n
    }
}

struct SyncAnomalyQueueCell(UnsafeCell<AnomalyQueue>);
// SAFETY: all accesses to `ANOMALY_QUEUE` are serialized by `VIOLATION_LOCK`.
unsafe impl Sync for SyncAnomalyQueueCell {}

static ANOMALY_QUEUE: SyncAnomalyQueueCell =
    SyncAnomalyQueueCell(UnsafeCell::new(AnomalyQueue::new()));

/// Lock protecting `LAST_VIOLATION` and `ANOMALY_QUEUE`.
static VIOLATION_LOCK: AtomicBool = AtomicBool::new(false);
struct SyncViolationCell(UnsafeCell<AuditViolation>);
// SAFETY: all accesses to `LAST_VIOLATION` are serialized by `VIOLATION_LOCK`.
unsafe impl Sync for SyncViolationCell {}

/// Most recent violation observed.
static LAST_VIOLATION: SyncViolationCell = SyncViolationCell(UnsafeCell::new(AuditViolation::empty()));
/// Whether `LAST_VIOLATION` holds a valid entry.
static HAS_LAST_VIOLATION: AtomicBool = AtomicBool::new(false);

/// Registered `sigaltstack` base address (0 = none).
static ALTSTACK_BASE: AtomicUsize = AtomicUsize::new(0);
/// Registered `sigaltstack` length in bytes (0 = none).
static ALTSTACK_LEN: AtomicUsize = AtomicUsize::new(0);

/// Spinlock guarding the shadow table and quarantine ring.
static AUDIT_LOCK: AtomicBool = AtomicBool::new(false);

// Thread-local recursion/suppression depth so internal allocations in
// `malloc_aligned_at_slow` do not double-record.
ra_thread_local! {
    static SUPPRESS_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// RAII guard suppressing nested `on_alloc` recording on the current thread.
pub(crate) struct SuppressGuard;

impl SuppressGuard {
    #[inline]
    pub(crate) fn new() -> Self {
        SUPPRESS_DEPTH.with(|c| c.set(c.get().saturating_add(1)));
        Self
    }
}

impl Drop for SuppressGuard {
    #[inline]
    fn drop(&mut self) {
        SUPPRESS_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

// ---------------------------------------------------------------------------
// OS anonymous mmap helpers (never routes through rusty_alloc)
// ---------------------------------------------------------------------------

unsafe fn os_mmap_zeroed(bytes: usize) -> *mut u8 {
    #[cfg(unix)]
    {
        use eko::libc_lite as libc;
        // SAFETY: anonymous private mapping with null hint; zero-filled by OS.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            ptr::null_mut()
        } else {
            p.cast()
        }
    }
    #[cfg(not(unix))]
    {
        crate::os::alloc_aligned(bytes, crate::os::page_size(), true, false)
            .map(|b| b.ptr)
            .unwrap_or(ptr::null_mut())
    }
}

// ---------------------------------------------------------------------------
// Lock-free anonymous-mmap Flight Recorder (`AuditRing`)
// ---------------------------------------------------------------------------

#[repr(C)]
struct RingSlot {
    stamp: AtomicU64,
    event: UnsafeCell<AuditEvent>,
}

/// Lock-free power-of-two ring buffer backed by anonymous `mmap`.
struct AuditRing {
    slots: AtomicUsize,
    write_idx: AtomicU64,
}

// SAFETY: `slots` points to an `mmap`ped array of `RingSlot`s synchronized via
// per-slot sequence stamps.
unsafe impl Sync for AuditRing {}

impl AuditRing {
    const fn new() -> Self {
        Self {
            slots: AtomicUsize::new(0),
            write_idx: AtomicU64::new(0),
        }
    }

    fn ensure_init(&self) -> *mut RingSlot {
        let p = self.slots.load(Ordering::Acquire);
        if p != 0 {
            return ptr::with_exposed_provenance_mut(p);
        }
        let bytes = RING_CAP * core::mem::size_of::<RingSlot>();
        // SAFETY: `bytes` is nonzero; `os_mmap_zeroed` returns zeroed pages or null.
        let mem = unsafe { os_mmap_zeroed(bytes) };
        if mem.is_null() {
            return ptr::null_mut();
        }
        let addr = mem.expose_provenance();
        if self
            .slots
            .compare_exchange(0, addr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            mem.cast()
        } else {
            // Another thread initialized first; release our redundant mapping.
            #[cfg(unix)]
            // SAFETY: `mem` was just mapped with `bytes` by `os_mmap_zeroed`.
            unsafe {
                eko::libc_lite::munmap(mem.cast(), bytes);
            }
            ptr::with_exposed_provenance_mut(self.slots.load(Ordering::Acquire))
        }
    }

    fn push(&self, op: AuditOp, ptr_val: usize, req_size: usize, req_align: usize, generation: u32) {
        let slots = self.ensure_init();
        if slots.is_null() {
            return;
        }
        let idx = self.write_idx.fetch_add(1, Ordering::Relaxed);
        let seq = idx + 1;
        let slot_idx = (idx as usize) & (RING_CAP - 1);
        let tid = crate::init::thread_id();
        // SAFETY: `slot_idx < RING_CAP` and `slots` points to `RING_CAP` slots.
        unsafe {
            let slot = slots.add(slot_idx);
            let odd = seq * 2 - 1;
            (*slot).stamp.store(odd, Ordering::Release);
            (*slot).event.get().write(AuditEvent {
                seq,
                op,
                ptr: ptr_val,
                req_size,
                req_align,
                thread_id: tid,
                generation,
            });
            (*slot).stamp.store(seq * 2, Ordering::Release);
        }
    }

    fn recent(&self, out: &mut [AuditEvent]) -> usize {
        if out.is_empty() {
            return 0;
        }
        let p = self.slots.load(Ordering::Acquire);
        if p == 0 {
            return 0;
        }
        let slots: *const RingSlot = ptr::with_exposed_provenance(p);
        let head = self.write_idx.load(Ordering::Acquire);
        let avail = (head as usize).min(RING_CAP).min(out.len());
        let mut written = 0;
        for i in 0..avail {
            let idx = head - 1 - (i as u64);
            let slot_idx = (idx as usize) & (RING_CAP - 1);
            // SAFETY: `slot_idx < RING_CAP` and `slots` is valid for process life.
            unsafe {
                let slot = slots.add(slot_idx);
                let s1 = (*slot).stamp.load(Ordering::Acquire);
                if s1 == 0 || (s1 & 1) != 0 {
                    continue;
                }
                let ev = (*slot).event.get().read();
                let s2 = (*slot).stamp.load(Ordering::Acquire);
                if s1 == s2 && ev.seq == idx + 1 {
                    out[written] = ev;
                    written += 1;
                }
            }
        }
        written
    }
}

static RING: AuditRing = AuditRing::new();

// ---------------------------------------------------------------------------
// Shadow `(size, align, generation)` Side-Table & Bounded Poison Quarantine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum EntryState {
    Empty = 0,
    Live = 1,
    Quarantined = 2,
    Tombstone = 3,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ShadowEntry {
    ptr: usize,
    req_size: usize,
    req_align: usize,
    usable_size: usize,
    generation: u32,
    state: EntryState,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct QuarantineEntry {
    user_ptr: usize,
    block_ptr: usize,
    len: usize,
    generation: u32,
}

struct AuditTables {
    shadow: *mut ShadowEntry,
    quarantine: *mut QuarantineEntry,
    q_head: usize,
    q_tail: usize,
    q_count: usize,
    q_bytes: usize,
}

impl AuditTables {
    const fn new() -> Self {
        Self {
            shadow: ptr::null_mut(),
            quarantine: ptr::null_mut(),
            q_head: 0,
            q_tail: 0,
            q_count: 0,
            q_bytes: 0,
        }
    }

    fn ensure_init(&mut self) -> bool {
        if !self.shadow.is_null() && !self.quarantine.is_null() {
            return true;
        }
        if self.shadow.is_null() {
            let bytes = SHADOW_CAP * core::mem::size_of::<ShadowEntry>();
            // SAFETY: OS anonymous zeroed mapping; `EntryState::Empty == 0`.
            let mem = unsafe { os_mmap_zeroed(bytes) };
            if mem.is_null() {
                return false;
            }
            self.shadow = mem.cast();
        }
        if self.quarantine.is_null() {
            let bytes = QUARANTINE_CAP * core::mem::size_of::<QuarantineEntry>();
            // SAFETY: OS anonymous zeroed mapping.
            let mem = unsafe { os_mmap_zeroed(bytes) };
            if mem.is_null() {
                return false;
            }
            self.quarantine = mem.cast();
        }
        true
    }

    #[inline]
    fn hash_ptr(ptr: usize) -> usize {
        (ptr >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15usize) & (SHADOW_CAP - 1)
    }

    unsafe fn find_slot(&self, ptr: usize) -> Option<usize> {
        let start = Self::hash_ptr(ptr);
        for step in 0..SHADOW_CAP {
            let idx = (start + step) & (SHADOW_CAP - 1);
            // SAFETY: `idx < SHADOW_CAP` and `self.shadow` is initialized.
            let entry = unsafe { &*self.shadow.add(idx) };
            match entry.state {
                EntryState::Empty => return None,
                EntryState::Tombstone => {}
                EntryState::Live | EntryState::Quarantined => {
                    if entry.ptr == ptr {
                        return Some(idx);
                    }
                }
            }
        }
        None
    }

    unsafe fn insert(
        &mut self,
        ptr: usize,
        req_size: usize,
        req_align: usize,
        usable_size: usize,
    ) -> u32 {
        let start = Self::hash_ptr(ptr);
        let mut first_tomb: Option<usize> = None;
        for step in 0..SHADOW_CAP {
            let idx = (start + step) & (SHADOW_CAP - 1);
            // SAFETY: `idx < SHADOW_CAP` and `self.shadow` is initialized.
            let entry = unsafe { &mut *self.shadow.add(idx) };
            match entry.state {
                EntryState::Empty => {
                    let target_idx = first_tomb.unwrap_or(idx);
                    // SAFETY: `target_idx < SHADOW_CAP`.
                    let target = unsafe { &mut *self.shadow.add(target_idx) };
                    let generation_id = target.generation.wrapping_add(1).max(1);
                    *target = ShadowEntry {
                        ptr,
                        req_size,
                        req_align,
                        usable_size,
                        generation: generation_id,
                        state: EntryState::Live,
                    };
                    return generation_id;
                }
                EntryState::Tombstone => {
                    if first_tomb.is_none() {
                        first_tomb = Some(idx);
                    }
                }
                EntryState::Live | EntryState::Quarantined => {
                    if entry.ptr == ptr {
                        let generation_id = entry.generation.wrapping_add(1).max(1);
                        *entry = ShadowEntry {
                            ptr,
                            req_size,
                            req_align,
                            usable_size,
                            generation: generation_id,
                            state: EntryState::Live,
                        };
                        return generation_id;
                    }
                }
            }
        }
        if let Some(tidx) = first_tomb {
            // SAFETY: `tidx < SHADOW_CAP`.
            let target = unsafe { &mut *self.shadow.add(tidx) };
            let generation_id = target.generation.wrapping_add(1).max(1);
            *target = ShadowEntry {
                ptr,
                req_size,
                req_align,
                usable_size,
                generation: generation_id,
                state: EntryState::Live,
            };
            return generation_id;
        }
        1
    }

    unsafe fn pop_quarantine(&mut self) -> Option<QuarantineEntry> {
        if self.q_count == 0 {
            return None;
        }
        // SAFETY: `q_head < QUARANTINE_CAP` and `self.quarantine` is initialized.
        let item = unsafe { *self.quarantine.add(self.q_head) };
        self.q_head = (self.q_head + 1) & (QUARANTINE_CAP - 1);
        self.q_count -= 1;
        self.q_bytes = self.q_bytes.saturating_sub(item.len);
        Some(item)
    }

    unsafe fn push_quarantine(&mut self, item: QuarantineEntry) {
        // SAFETY: `q_tail < QUARANTINE_CAP` and `self.quarantine` is initialized.
        unsafe {
            self.quarantine.add(self.q_tail).write(item);
        }
        self.q_tail = (self.q_tail + 1) & (QUARANTINE_CAP - 1);
        self.q_count += 1;
        self.q_bytes = self.q_bytes.saturating_add(item.len);
    }
}

struct AuditStateCell(UnsafeCell<AuditTables>);
// SAFETY: all accesses to `TABLES` are serialized by `AUDIT_LOCK`.
unsafe impl Sync for AuditStateCell {}

static TABLES: AuditStateCell = AuditStateCell(UnsafeCell::new(AuditTables::new()));

#[inline]
fn lock_tables() {
    while AUDIT_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn unlock_tables() {
    AUDIT_LOCK.store(false, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Violation reporting
// ---------------------------------------------------------------------------

struct StackBuf {
    buf: [u8; 256],
    len: usize,
}

impl core::fmt::Write for StackBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let avail = self.buf.len().saturating_sub(self.len);
        let mut n = s.len().min(avail);
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

fn record_violation(v: AuditViolation) {
    VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
    match v.kind {
        AuditViolationKind::DoubleFree => {
            DOUBLE_FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        AuditViolationKind::InvalidFree => {
            INVALID_FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        AuditViolationKind::LayoutMismatch => {
            LAYOUT_MISMATCH_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        AuditViolationKind::WriteAfterFree => {
            QUARANTINE_WRITE_CORRUPTED_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        AuditViolationKind::AltstackUnmapHazard => {
            ALTSTACK_HAZARD_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        AuditViolationKind::MultithreadedForkHazard => {
            FORK_HAZARD_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
    while VIOLATION_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `VIOLATION_LOCK` serializes writes to `LAST_VIOLATION` and `ANOMALY_QUEUE`.
    unsafe {
        LAST_VIOLATION.0.get().write(v);
        (*ANOMALY_QUEUE.0.get()).push(v);
    }
    HAS_LAST_VIOLATION.store(true, Ordering::Release);
    VIOLATION_LOCK.store(false, Ordering::Release);

    RING.push(
        AuditOp::Violation,
        v.ptr,
        v.expected_size,
        v.expected_align,
        v.generation,
    );

    let mut msg = StackBuf {
        buf: [0; 256],
        len: 0,
    };
    let _ = core::fmt::write(
        &mut msg,
        format_args!(
            "rusty_alloc audit_trace violation: {} ptr=0x{:x} exp=({},{}) act=({},{}) off={} gen={}\n",
            v.kind.name(),
            v.ptr,
            v.expected_size,
            v.expected_align,
            v.actual_size,
            v.actual_align,
            v.offset,
            v.generation,
        ),
    );
    if let Ok(s) = core::str::from_utf8(&msg.buf[..msg.len]) {
        crate::options::out_fmt(s);
    }

    if ABORT_ON_VIOLATION.load(Ordering::Acquire) {
        crate::abort();
    }
}

// ---------------------------------------------------------------------------
// Lazy environment initialization & Pattern C lifecycle hooks
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(miri)))]
unsafe extern "C" {
    fn atexit(cb: extern "C" fn()) -> core::ffi::c_int;
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> core::ffi::c_int;
}

#[cfg(all(unix, not(miri)))]
extern "C" fn on_atexit() {
    if !is_active() {
        return;
    }
    let base = ALTSTACK_BASE.load(Ordering::Acquire);
    let len = ALTSTACK_LEN.load(Ordering::Acquire);
    if len > 0 && base != 0 {
        record_violation(AuditViolation {
            kind: AuditViolationKind::AltstackUnmapHazard,
            ptr: base,
            expected_size: len,
            expected_align: 0,
            actual_size: 0,
            actual_align: 0,
            offset: 0,
            generation: 0,
            thread_id: crate::init::thread_id(),
        });
    }
}

#[cfg(all(unix, not(miri)))]
unsafe extern "C" fn atfork_prepare() {
    if !is_active() {
        return;
    }
    if AUDIT_LOCK.load(Ordering::Acquire) {
        record_violation(AuditViolation {
            kind: AuditViolationKind::MultithreadedForkHazard,
            ptr: 0,
            expected_size: 0,
            expected_align: 0,
            actual_size: 0,
            actual_align: 0,
            offset: 0,
            generation: 0,
            thread_id: crate::init::thread_id(),
        });
    }
}

#[cfg(all(unix, not(miri)))]
unsafe extern "C" fn atfork_parent() {}

#[cfg(all(unix, not(miri)))]
unsafe extern "C" fn atfork_child() {
    AUDIT_LOCK.store(false, Ordering::Release);
    VIOLATION_LOCK.store(false, Ordering::Release);
}

fn read_env_bytes(key_nul: &[u8], out: &mut [u8]) -> Option<usize> {
    #[cfg(unix)]
    {
        // SAFETY: `key_nul` is NUL-terminated; `getenv` returns a pointer into
        // the process environment or null, read up to NUL or `out.len()`.
        unsafe {
            let v: *const u8 = eko::libc_lite::getenv(key_nul.as_ptr().cast()).cast();
            if v.is_null() {
                return None;
            }
            let mut n = 0;
            while n < out.len() {
                let b = *v.add(n);
                if b == 0 {
                    return Some(n);
                }
                out[n] = b;
                n += 1;
            }
            None
        }
    }
    #[cfg(not(unix))]
    {
        crate::prim::getenv(key_nul, out)
    }
}

fn parse_usize_ascii(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(usize::from(b - b'0'))?;
    }
    Some(acc)
}

fn ensure_env_init() {
    if INIT_STATE.load(Ordering::Acquire) == 2 {
        return;
    }
    if INIT_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let mut buf = [0u8; 64];
        if let Some(n) = read_env_bytes(b"RUSTY_ALLOC_AUDIT_TRACE\0", &mut buf)
            && &buf[..n] == b"1"
        {
            AUDIT_ACTIVE.store(true, Ordering::Release);
        }
        if let Some(n) = read_env_bytes(b"RUSTY_ALLOC_QUARANTINE_BYTES\0", &mut buf)
            && let Some(bytes) = parse_usize_ascii(&buf[..n])
        {
            QUARANTINE_BUDGET.store(bytes, Ordering::Release);
        }
        if !ABORT_OVERRIDDEN.load(Ordering::Acquire)
            && let Some(n) = read_env_bytes(b"RUSTY_ALLOC_AUDIT_KEEP_GOING\0", &mut buf)
            && &buf[..n] == b"1"
        {
            ABORT_ON_VIOLATION.store(false, Ordering::Release);
        }
        #[cfg(all(unix, not(miri)))]
        // SAFETY: registering static C-ABI process lifecycle hooks once.
        unsafe {
            let _ = atexit(on_atexit);
            let _ = pthread_atfork(
                Some(atfork_prepare),
                Some(atfork_parent),
                Some(atfork_child),
            );
        }
        INIT_STATE.store(2, Ordering::Release);
    } else {
        while INIT_STATE.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable or disable `audit_trace` at runtime.
pub fn ra_audit_enable(on: bool) {
    ensure_env_init();
    if !on {
        AUDIT_ACTIVE.store(false, Ordering::Release);
        flush_quarantine();
        return;
    }
    AUDIT_ACTIVE.store(true, Ordering::Release);
    // Route any already-initialized calling-thread heap away from `direct[]`
    // and stamp existing pages with `AUDIT_TRACED`.
    let hb = crate::init::heap_box_fast();
    if hb != crate::init::empty_heap_box_ptr() {
        // SAFETY: `hb` is this thread's live `HeapBox`.
        unsafe {
            let h = (*hb).heap.get();
            (*h).direct.fill(crate::page::empty_page_ptr());
            for bin in 1..=BIN_HUGE {
                let mut pg = (*h).pages[bin].first;
                while !pg.is_null() {
                    (*pg).flags.fetch_or(pflags::AUDIT_TRACED, Ordering::Relaxed);
                    pg = (*pg).next;
                }
            }
            let mut pg = (*h).pages[BIN_FULL].first;
            while !pg.is_null() {
                (*pg).flags.fetch_or(pflags::AUDIT_TRACED, Ordering::Relaxed);
                pg = (*pg).next;
            }
        }
    }
}

/// Return whether `audit_trace` is currently active.
#[inline]
pub fn ra_audit_is_active() -> bool {
    is_active()
}

/// Configure whether violations abort the process (`true`) or only record (`false`).
pub fn ra_audit_set_abort_on_violation(abort: bool) {
    ABORT_OVERRIDDEN.store(true, Ordering::Release);
    ABORT_ON_VIOLATION.store(abort, Ordering::Release);
}

/// Copy up to `out.len()` most recent flight-recorder events (newest first).
pub fn ra_audit_recent_events(out: &mut [AuditEvent]) -> usize {
    RING.recent(out)
}

/// Return the total number of violations recorded so far.
pub fn ra_audit_violation_count() -> usize {
    VIOLATION_COUNT.load(Ordering::Acquire)
}

/// Return a snapshot of per-category atomic anomaly counters.
pub fn audit_anomaly_counts() -> AuditAnomalyCounts {
    AuditAnomalyCounts {
        total: VIOLATION_COUNT.load(Ordering::Acquire),
        double_free: DOUBLE_FREE_COUNT.load(Ordering::Acquire),
        invalid_free: INVALID_FREE_COUNT.load(Ordering::Acquire),
        layout_mismatch: LAYOUT_MISMATCH_COUNT.load(Ordering::Acquire),
        quarantine_write_corrupted: QUARANTINE_WRITE_CORRUPTED_COUNT.load(Ordering::Acquire),
        altstack_unmap_hazard: ALTSTACK_HAZARD_COUNT.load(Ordering::Acquire),
        multithreaded_fork_hazard: FORK_HAZARD_COUNT.load(Ordering::Acquire),
    }
}

/// Drain up to `out.len()` buffered [`AuditViolation`] anomaly records in FIFO order.
pub fn drain_audit_anomalies(out: &mut [AuditViolation]) -> usize {
    if out.is_empty() {
        return 0;
    }
    while VIOLATION_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `VIOLATION_LOCK` serializes access to `ANOMALY_QUEUE`.
    let n = unsafe { (*ANOMALY_QUEUE.0.get()).drain(out) };
    VIOLATION_LOCK.store(false, Ordering::Release);
    n
}

/// Return the most recently recorded violation, if any.
pub fn ra_audit_last_violation() -> Option<AuditViolation> {
    if !HAS_LAST_VIOLATION.load(Ordering::Acquire) {
        return None;
    }
    while VIOLATION_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `VIOLATION_LOCK` guards `LAST_VIOLATION`.
    let v = unsafe { LAST_VIOLATION.0.get().read() };
    VIOLATION_LOCK.store(false, Ordering::Release);
    Some(v)
}

/// Register an active `sigaltstack` memory range for FORGE Pattern C unmap/atexit checks.
pub fn ra_audit_register_altstack(base: *const u8, len: usize) {
    ALTSTACK_BASE.store(base.addr(), Ordering::Release);
    ALTSTACK_LEN.store(len, Ordering::Release);
}

/// Clear the registered `sigaltstack` memory range.
pub fn ra_audit_clear_altstack() {
    ALTSTACK_BASE.store(0, Ordering::Release);
    ALTSTACK_LEN.store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Internal hooks called by heap / alloc / segment slow paths
// ---------------------------------------------------------------------------

/// Fast inline check used by slow paths; lazily reads environment once.
#[inline]
pub(crate) fn is_active() -> bool {
    if INIT_STATE.load(Ordering::Acquire) != 2 {
        ensure_env_init();
    }
    AUDIT_ACTIVE.load(Ordering::Acquire)
}

/// Record an allocation if not suppressed by an outer `malloc_aligned_at_slow`.
///
/// # Safety
/// `p` must be a newly allocated, non-null live block from this allocator.
pub(crate) unsafe fn on_alloc(p: *mut u8, req_size: usize, req_align: usize) {
    if SUPPRESS_DEPTH.with(|c| c.get() != 0) {
        return;
    }
    // SAFETY: forwarded contract.
    unsafe { on_alloc_explicit(p, req_size, req_align) };
}

/// Record an allocation unconditionally (ignoring `SUPPRESS_DEPTH`).
///
/// # Safety
/// `p` must be a newly allocated, non-null live block from this allocator.
pub(crate) unsafe fn on_alloc_explicit(p: *mut u8, req_size: usize, req_align: usize) {
    // SAFETY: `p` is a live block from this allocator.
    let usable = unsafe { crate::alloc::usable_size(p) };
    let addr = p.addr();
    lock_tables();
    // SAFETY: `AUDIT_LOCK` is held.
    let generation_id = unsafe {
        let t = &mut *TABLES.0.get();
        if t.ensure_init() {
            t.insert(addr, req_size, req_align, usable)
        } else {
            1
        }
    };
    unlock_tables();
    RING.push(AuditOp::Alloc, addr, req_size, req_align, generation_id);
}

/// Validate that a live block's recorded `(size, align)` matches `(expected_size, expected_align)`
/// before `realloc` proceeds.
///
/// # Safety
/// `p` must be a non-null pointer.
pub(crate) unsafe fn check_live_layout(
    p: *mut u8,
    expected_size: usize,
    expected_align: usize,
) {
    let addr = p.addr();
    let tid = crate::init::thread_id();
    let mut violation: Option<AuditViolation> = None;
    let mut waf: Option<AuditViolation> = None;
    lock_tables();
    // SAFETY: `AUDIT_LOCK` is held.
    unsafe {
        let t = &mut *TABLES.0.get();
        if t.ensure_init() {
            if let Some(idx) = t.find_slot(addr) {
                let entry = &mut *t.shadow.add(idx);
                if entry.state == EntryState::Quarantined {
                    let poison_len = entry.usable_size.max(entry.req_size);
                    for off in 0..poison_len {
                        if p.add(off).read() != POISON_BYTE {
                            waf = Some(AuditViolation {
                                kind: AuditViolationKind::WriteAfterFree,
                                ptr: addr,
                                expected_size: poison_len,
                                expected_align: 0,
                                actual_size: 0,
                                actual_align: 0,
                                offset: off,
                                generation: entry.generation,
                                thread_id: tid,
                            });
                            break;
                        }
                    }
                    violation = Some(AuditViolation {
                        kind: AuditViolationKind::DoubleFree,
                        ptr: addr,
                        expected_size: entry.req_size,
                        expected_align: entry.req_align,
                        actual_size: expected_size,
                        actual_align: expected_align,
                        offset: 0,
                        generation: entry.generation,
                        thread_id: tid,
                    });
                } else if entry.req_size != expected_size || entry.req_align != expected_align {
                    violation = Some(AuditViolation {
                        kind: AuditViolationKind::LayoutMismatch,
                        ptr: addr,
                        expected_size: entry.req_size,
                        expected_align: entry.req_align,
                        actual_size: expected_size,
                        actual_align: expected_align,
                        offset: 0,
                        generation: entry.generation,
                        thread_id: tid,
                    });
                }
            } else {
                violation = Some(AuditViolation {
                    kind: AuditViolationKind::InvalidFree,
                    ptr: addr,
                    expected_size: 0,
                    expected_align: 0,
                    actual_size: expected_size,
                    actual_align: expected_align,
                    offset: 0,
                    generation: 0,
                    thread_id: tid,
                });
            }
        }
    }
    unlock_tables();
    if let Some(v) = violation {
        record_violation(v);
    }
    if let Some(v) = waf {
        record_violation(v);
    }
}

/// Validate and update a live block during an in-place `realloc`.
///
/// # Safety
/// `p` must be non-null.
pub(crate) unsafe fn on_realloc_in_place(p: *mut u8, new_size: usize) {
    let addr = p.addr();
    let tid = crate::init::thread_id();
    let mut violation: Option<AuditViolation> = None;
    let mut generation_id = 0u32;
    lock_tables();
    // SAFETY: `AUDIT_LOCK` is held.
    unsafe {
        let t = &mut *TABLES.0.get();
        if t.ensure_init() {
            if let Some(idx) = t.find_slot(addr) {
                let entry = &mut *t.shadow.add(idx);
                generation_id = entry.generation;
                if entry.state == EntryState::Quarantined {
                    violation = Some(AuditViolation {
                        kind: AuditViolationKind::DoubleFree,
                        ptr: addr,
                        expected_size: entry.req_size,
                        expected_align: entry.req_align,
                        actual_size: new_size,
                        actual_align: 0,
                        offset: 0,
                        generation: generation_id,
                        thread_id: tid,
                    });
                } else {
                    entry.req_size = new_size;
                }
            } else {
                violation = Some(AuditViolation {
                    kind: AuditViolationKind::InvalidFree,
                    ptr: addr,
                    expected_size: 0,
                    expected_align: 0,
                    actual_size: new_size,
                    actual_align: 0,
                    offset: 0,
                    generation: 0,
                    thread_id: tid,
                });
            }
        }
    }
    unlock_tables();
    if let Some(v) = violation {
        record_violation(v);
    } else {
        RING.push(AuditOp::Realloc, addr, new_size, 0, generation_id);
    }
}

/// Outcome of `on_free`: whether the caller should release the underlying block now.
pub(crate) enum FreeAction {
    /// Block is quarantined; do not release to underlying allocator yet.
    Quarantined,
    /// Release `block` to underlying allocator now.
    ReleaseNow,
    /// Invalid or already-quarantined pointer; skip underlying release.
    Skip,
}

/// Check `user_ptr` against the shadow table, detect double-free / invalid-free /
/// `(size, align)` mismatch, poison into quarantine, and evict oldest entries
/// above `QUARANTINE_BUDGET`.
///
/// # Safety
/// `block` is the underlying block start for `user_ptr` when `user_ptr` is a
/// valid pointer in a segment of this allocator.
pub(crate) unsafe fn on_free(
    block: *mut u8,
    user_ptr: *mut u8,
    expected_size: Option<usize>,
    expected_align: Option<usize>,
) -> FreeAction {
    let addr = user_ptr.addr();
    let tid = crate::init::thread_id();
    let budget = QUARANTINE_BUDGET.load(Ordering::Acquire);

    let mut evicted: [usize; 16] = [0; 16];
    let mut evicted_len: usize = 0;
    let mut wafs: [AuditViolation; 16] = [AuditViolation::empty(); 16];
    let mut wafs_len: usize = 0;
    let mut immediate_violation: Option<AuditViolation> = None;
    let mut action = FreeAction::ReleaseNow;
    let mut generation_id = 0u32;
    let mut rec_size = 0usize;
    let mut rec_align = 0usize;

    lock_tables();
    // SAFETY: `AUDIT_LOCK` is held.
    unsafe {
        let t = &mut *TABLES.0.get();
        if t.ensure_init() {
            if let Some(idx) = t.find_slot(addr) {
                let entry = &mut *t.shadow.add(idx);
                generation_id = entry.generation;
                rec_size = entry.req_size;
                rec_align = entry.req_align;

                if entry.state == EntryState::Quarantined {
                    let poison_len = entry.usable_size.max(entry.req_size);
                    for off in 0..poison_len {
                        if user_ptr.add(off).read() != POISON_BYTE {
                            if wafs_len < wafs.len() {
                                wafs[wafs_len] = AuditViolation {
                                    kind: AuditViolationKind::WriteAfterFree,
                                    ptr: addr,
                                    expected_size: poison_len,
                                    expected_align: 0,
                                    actual_size: 0,
                                    actual_align: 0,
                                    offset: off,
                                    generation: generation_id,
                                    thread_id: tid,
                                };
                                wafs_len += 1;
                            }
                            break;
                        }
                    }
                    immediate_violation = Some(AuditViolation {
                        kind: AuditViolationKind::DoubleFree,
                        ptr: addr,
                        expected_size: rec_size,
                        expected_align: rec_align,
                        actual_size: expected_size.unwrap_or(0),
                        actual_align: expected_align.unwrap_or(0),
                        offset: 0,
                        generation: generation_id,
                        thread_id: tid,
                    });
                    action = FreeAction::Skip;
                } else {
                    let size_bad = expected_size.is_some_and(|s| s != rec_size);
                    let align_bad = expected_align.is_some_and(|a| a != rec_align);
                    if size_bad || align_bad {
                        immediate_violation = Some(AuditViolation {
                            kind: AuditViolationKind::LayoutMismatch,
                            ptr: addr,
                            expected_size: rec_size,
                            expected_align: rec_align,
                            actual_size: expected_size.unwrap_or(0),
                            actual_align: expected_align.unwrap_or(0),
                            offset: 0,
                            generation: generation_id,
                            thread_id: tid,
                        });
                    }

                    if budget > 0 {
                        let poison_len = entry.usable_size.max(entry.req_size);
                        if poison_len > 0 {
                            ptr::write_bytes(user_ptr, POISON_BYTE, poison_len);
                        }
                        entry.state = EntryState::Quarantined;
                        t.push_quarantine(QuarantineEntry {
                            user_ptr: addr,
                            block_ptr: block.expose_provenance(),
                            len: poison_len,
                            generation: generation_id,
                        });
                        action = FreeAction::Quarantined;

                        while (t.q_bytes > budget || t.q_count >= QUARANTINE_CAP - 1)
                            && evicted_len < evicted.len()
                        {
                            let Some(q) = t.pop_quarantine() else {
                                break;
                            };
                            let qptr: *const u8 = ptr::with_exposed_provenance(q.user_ptr);
                            for off in 0..q.len {
                                if qptr.add(off).read() != POISON_BYTE {
                                    if wafs_len < wafs.len() {
                                        wafs[wafs_len] = AuditViolation {
                                            kind: AuditViolationKind::WriteAfterFree,
                                            ptr: q.user_ptr,
                                            expected_size: q.len,
                                            expected_align: 0,
                                            actual_size: 0,
                                            actual_align: 0,
                                            offset: off,
                                            generation: q.generation,
                                            thread_id: tid,
                                        };
                                        wafs_len += 1;
                                    }
                                    break;
                                }
                            }
                            if let Some(sidx) = t.find_slot(q.user_ptr) {
                                let se = &mut *t.shadow.add(sidx);
                                se.state = EntryState::Tombstone;
                                se.ptr = 0;
                            }
                            RING.push(AuditOp::QuarantineEvict, q.user_ptr, q.len, 0, q.generation);
                            evicted[evicted_len] = q.block_ptr;
                            evicted_len += 1;
                        }
                    } else {
                        entry.state = EntryState::Tombstone;
                        entry.ptr = 0;
                        action = FreeAction::ReleaseNow;
                    }
                }
            } else {
                immediate_violation = Some(AuditViolation {
                    kind: AuditViolationKind::InvalidFree,
                    ptr: addr,
                    expected_size: 0,
                    expected_align: 0,
                    actual_size: expected_size.unwrap_or(0),
                    actual_align: expected_align.unwrap_or(0),
                    offset: 0,
                    generation: 0,
                    thread_id: tid,
                });
                action = FreeAction::Skip;
            }
        }
    }
    unlock_tables();

    if let Some(v) = immediate_violation {
        record_violation(v);
    } else {
        RING.push(AuditOp::Free, addr, rec_size, rec_align, generation_id);
    }
    for v in &wafs[..wafs_len] {
        record_violation(*v);
    }
    for &baddr in &evicted[..evicted_len] {
        // SAFETY: `baddr` came from a valid live block start quarantined above.
        unsafe {
            crate::alloc::free_bypass_audit(ptr::with_exposed_provenance_mut(baddr));
        }
    }
    action
}

/// Drain all quarantined blocks, checking poison bytes and releasing them.
fn flush_quarantine() {
    let tid = crate::init::thread_id();
    loop {
        let mut evicted: [usize; 32] = [0; 32];
        let mut evicted_len: usize = 0;
        let mut wafs: [AuditViolation; 32] = [AuditViolation::empty(); 32];
        let mut wafs_len: usize = 0;

        lock_tables();
        // SAFETY: `AUDIT_LOCK` is held.
        unsafe {
            let t = &mut *TABLES.0.get();
            if t.ensure_init() {
                while evicted_len < evicted.len() {
                    let Some(q) = t.pop_quarantine() else {
                        break;
                    };
                    let qptr: *const u8 = ptr::with_exposed_provenance(q.user_ptr);
                    for off in 0..q.len {
                        if qptr.add(off).read() != POISON_BYTE {
                            if wafs_len < wafs.len() {
                                wafs[wafs_len] = AuditViolation {
                                    kind: AuditViolationKind::WriteAfterFree,
                                    ptr: q.user_ptr,
                                    expected_size: q.len,
                                    expected_align: 0,
                                    actual_size: 0,
                                    actual_align: 0,
                                    offset: off,
                                    generation: q.generation,
                                    thread_id: tid,
                                };
                                wafs_len += 1;
                            }
                            break;
                        }
                    }
                    if let Some(sidx) = t.find_slot(q.user_ptr) {
                        let se = &mut *t.shadow.add(sidx);
                        se.state = EntryState::Tombstone;
                        se.ptr = 0;
                    }
                    RING.push(AuditOp::QuarantineEvict, q.user_ptr, q.len, 0, q.generation);
                    evicted[evicted_len] = q.block_ptr;
                    evicted_len += 1;
                }
            }
        }
        unlock_tables();

        for v in &wafs[..wafs_len] {
            record_violation(*v);
        }
        for &baddr in &evicted[..evicted_len] {
            // SAFETY: `baddr` came from a valid quarantined block start.
            unsafe {
                crate::alloc::free_bypass_audit(ptr::with_exposed_provenance_mut(baddr));
            }
        }
        if evicted_len == 0 {
            break;
        }
    }
}

/// Check whether an unmapped/released segment `[base, base + len)` overlaps a
/// registered `sigaltstack` range (FORGE Pattern C).
pub(crate) fn check_altstack_unmap(base: *const u8, len: usize) {
    if !is_active() {
        return;
    }
    let alt_base = ALTSTACK_BASE.load(Ordering::Acquire);
    let alt_len = ALTSTACK_LEN.load(Ordering::Acquire);
    if alt_base == 0 || alt_len == 0 || len == 0 {
        return;
    }
    let seg_start = base.addr();
    let seg_end = seg_start.saturating_add(len);
    let alt_end = alt_base.saturating_add(alt_len);
    if alt_base < seg_end && seg_start < alt_end {
        record_violation(AuditViolation {
            kind: AuditViolationKind::AltstackUnmapHazard,
            ptr: alt_base,
            expected_size: alt_len,
            expected_align: 0,
            actual_size: len,
            actual_align: 0,
            offset: 0,
            generation: 0,
            thread_id: crate::init::thread_id(),
        });
    }
}
