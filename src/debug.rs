//! Debug mode: the `debug_checks` feature.
//!
//! One allocator for both modes. With the feature off this module does not
//! exist and [`crate::RustyAlloc`] is the plain fast path; with it on every
//! `GlobalAlloc` call is checked here. See `docs/debugging.md` for the design,
//! the survey it follows and the defaults.
//!
//! A failed check builds a [`Violation`] and hands it to the handler. The
//! default handler prints the finding with its call stacks to stderr
//! (through the output hook, see `options::register_output`) and aborts,
//! which is what mimalloc's debug build does on heap corruption.
//! [`set_handler`] replaces it, for example to log and continue, as
//! `mi_register_error` does.
//!
//! Every block records the call stack that allocated it, and a freed block
//! the stack that freed it ([`stack`]), so leak and violation reports name
//! call sites the way AddressSanitizer and heaptrack do.

use core::fmt;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

pub(crate) mod raw;
pub mod stack;

pub use stack::StackId;

/// What a check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// `dealloc` of a pointer outside every segment this allocator owns:
    /// memory from another allocator (an FFI mismatch, e.g. a C `malloc`
    /// block handed to a Rust `Box`).
    ForeignPointer,
    /// `dealloc` of a block this allocator owns that was not allocated
    /// through [`crate::RustyAlloc`] (the raw `alloc::malloc` / `mi_malloc`
    /// API, typically the C side of an FFI boundary). The other direction,
    /// a raw `free` of a `RustyAlloc` block, is allowed, as Scudo allows it
    /// by default: both reach the same allocator.
    NotFromGlobalAlloc,
    /// A free of a pointer into the middle of a block.
    InteriorPointer,
    /// A free of a block that is already freed (still in quarantine).
    DoubleFree,
    /// `dealloc` with a `Layout` size different from the allocation's.
    SizeMismatch,
    /// `dealloc` with a `Layout` alignment different from the allocation's.
    AlignMismatch,
    /// The canary after the block was overwritten: a write past the end.
    BufferOverflow,
    /// The block header failed its checksum: a write before the start of the
    /// block (underflow) or a wild write.
    CorruptHeader,
    /// A freed block's poison changed while it sat in quarantine: a write
    /// after free.
    UseAfterFree,
    /// An allocation came back without the requested alignment (an allocator
    /// bug, checked on every debug allocation).
    Misaligned,
}

impl ViolationKind {
    /// Stable short name, e.g. `"double_free"`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ForeignPointer => "foreign_pointer",
            Self::NotFromGlobalAlloc => "not_from_global_alloc",
            Self::InteriorPointer => "interior_pointer",
            Self::DoubleFree => "double_free",
            Self::SizeMismatch => "size_mismatch",
            Self::AlignMismatch => "align_mismatch",
            Self::BufferOverflow => "buffer_overflow",
            Self::CorruptHeader => "corrupt_header",
            Self::UseAfterFree => "use_after_free",
            Self::Misaligned => "misaligned",
        }
    }
}

/// One failed check. Fields that do not apply to a kind are 0 (stacks
/// [`StackId::NONE`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Violation {
    /// What was found.
    pub kind: ViolationKind,
    /// The pointer the caller passed (or the block, for checks on eviction).
    pub ptr: usize,
    /// Size the caller passed in its `Layout`.
    pub size: usize,
    /// Alignment the caller passed in its `Layout`.
    pub align: usize,
    /// Size recorded when the block was allocated.
    pub block_size: usize,
    /// Alignment recorded when the block was allocated.
    pub block_align: usize,
    /// Byte offset of the finding: into the block for interior pointers,
    /// first overwritten byte for overflows and writes after free.
    pub offset: usize,
    /// The block's allocation number on its thread (counted per thread from 1).
    pub seq: u64,
    /// Thread that found it (debug thread number, from 1; 0 unknown).
    pub thread: u32,
    /// Where it was found: the call into the allocator (or the eviction from
    /// quarantine, for a write after free).
    pub stack: StackId,
    /// Where the block was allocated, when the block is known.
    pub alloc_stack: StackId,
    /// Thread that allocated the block.
    pub alloc_thread: u32,
    /// Where the block was freed: double frees and writes after free.
    pub free_stack: StackId,
    /// Thread that freed the block.
    pub free_thread: u32,
}

impl Violation {
    pub(crate) const fn new(kind: ViolationKind, ptr: usize) -> Self {
        Self {
            kind,
            ptr,
            size: 0,
            align: 0,
            block_size: 0,
            block_align: 0,
            offset: 0,
            seq: 0,
            thread: 0,
            stack: StackId::NONE,
            alloc_stack: StackId::NONE,
            alloc_thread: 0,
            free_stack: StackId::NONE,
            free_thread: 0,
        }
    }

    /// Take the block's recorded size, alignment, number and call sites.
    const fn block(&mut self, h: &Header) {
        self.block_size = h.size as usize;
        self.block_align = h.align();
        self.seq = h.seq;
        self.alloc_stack = StackId(h.alloc_stack);
        self.alloc_thread = h.alloc_tid;
        if h.state == FREED {
            self.free_stack = StackId(h.free_stack);
            self.free_thread = h.free_tid;
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.ptr;
        match self.kind {
            ViolationKind::ForeignPointer => write!(
                f,
                "dealloc of {p:#x}, which this allocator never returned (size {}, align {})",
                self.size, self.align
            ),
            ViolationKind::NotFromGlobalAlloc => write!(
                f,
                "dealloc of {p:#x}, a block from the raw malloc API, not from RustyAlloc"
            ),
            ViolationKind::InteriorPointer => write!(
                f,
                "dealloc of {p:#x}, an interior pointer {} bytes into a block",
                self.offset
            ),
            ViolationKind::DoubleFree => write!(
                f,
                "double free of block {p:#x} (size {}, align {})",
                self.block_size, self.block_align
            ),
            ViolationKind::SizeMismatch => write!(
                f,
                "dealloc of block {p:#x} with size {}, allocated with size {}",
                self.size, self.block_size
            ),
            ViolationKind::AlignMismatch => write!(
                f,
                "dealloc of block {p:#x} with align {}, allocated with align {}",
                self.align, self.block_align
            ),
            ViolationKind::BufferOverflow => write!(
                f,
                "buffer overflow in heap block {p:#x} of size {}: write after {} bytes",
                self.block_size, self.offset
            ),
            ViolationKind::CorruptHeader => write!(
                f,
                "corrupted header of heap block {p:#x} (write before the block, or a wild write)"
            ),
            ViolationKind::UseAfterFree => write!(
                f,
                "use after free: block {p:#x} of size {} was written at offset {} after it was freed",
                self.block_size, self.offset
            ),
            ViolationKind::Misaligned => write!(
                f,
                "allocation {p:#x} of size {} is not aligned to {}",
                self.size, self.align
            ),
        }
    }
}

/// A violation handler. If it returns, the allocator continues: a free it
/// cannot do safely (foreign, raw-API, interior, corrupt header, double free)
/// is skipped and the block leaks; a free of a known block (size or align
/// mismatch, overflow, write after free) completes with the recorded layout.
pub type Handler = fn(&Violation);

static HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install `h` as the violation handler (`None` restores the default:
/// report and abort). Returns the previous handler. Process-wide.
pub fn set_handler(h: Option<Handler>) -> Option<Handler> {
    let new = h.map_or(core::ptr::null_mut(), |f| f as *mut ());
    let old = HANDLER.swap(new, Ordering::AcqRel);
    if old.is_null() {
        None
    } else {
        // SAFETY: only `set_handler` stores into `HANDLER`, and only a
        // `Handler` cast to a data pointer.
        Some(unsafe { core::mem::transmute::<*mut (), Handler>(old) })
    }
}

/// The default handler: print the report ([`print_violation`]) and abort.
pub fn default_handler(v: &Violation) {
    print_violation(v);
    crate::abort();
}

/// Print a violation through the output hook, without allocating: the line
/// `rusty_alloc: error: <violation>`, then, in AddressSanitizer's order, the
/// stack where it was found, the stack that freed the block and the stack
/// that allocated it, each that is known. Frames are raw return addresses
/// with their image and offset; `tools/symbolize.ts` resolves them.
pub fn print_violation(v: &Violation) {
    line(format_args!("rusty_alloc: error: {v}\n"));
    if !v.stack.is_none() {
        line(format_args!(
            "rusty_alloc:   found by thread T{} here:\n",
            v.thread
        ));
        stack::print_stack(v.stack);
    }
    if !v.free_stack.is_none() {
        line(format_args!(
            "rusty_alloc:   freed by thread T{} here:\n",
            v.free_thread
        ));
        stack::print_stack(v.free_stack);
    }
    if !v.alloc_stack.is_none() {
        line(format_args!(
            "rusty_alloc:   previously allocated by thread T{} here:\n",
            v.alloc_thread
        ));
        stack::print_stack(v.alloc_stack);
    }
}

/// Hand `v` to the handler. Returns only if the handler returned. Fills in
/// the finding thread, and the stack where it was found when the caller did
/// not capture one.
#[cold]
#[inline(never)]
pub(crate) fn report(v: &Violation) {
    let mut v = *v;
    if v.thread == 0 {
        v.thread = thread_debug().map_or(0, thread_no);
    }
    if v.stack.is_none() {
        v.stack = here();
    }
    let h = HANDLER.load(Ordering::Acquire);
    if h.is_null() {
        default_handler(&v);
    } else {
        // SAFETY: see `set_handler`.
        let f = unsafe { core::mem::transmute::<*mut (), Handler>(h) };
        f(&v);
    }
}

/// A fixed stack buffer for one formatted line: reports must not allocate,
/// they run inside the allocator. Output past the end is cut.
pub(crate) struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        // Only whole `&str` pieces are copied in (cut on a char boundary).
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-thread state
// ---------------------------------------------------------------------------

/// Debug state of one thread, kept in its heap box (`init::HeapBox::dbg`) so
/// it lives exactly as long as the heap and is still there during thread
/// teardown, when Rust's own thread-locals may already be gone. Every field
/// is a `Cell` and all-zero is the initial state.
pub(crate) struct ThreadDebug {
    /// Allocation number of the last block this thread allocated.
    seq: core::cell::Cell<u64>,
    /// Quarantine FIFO of freed blocks (user pointers), linked through
    /// their headers, oldest first.
    q_head: core::cell::Cell<*mut u8>,
    q_tail: core::cell::Cell<*mut u8>,
    /// Bytes (requested sizes) in the quarantine.
    q_bytes: core::cell::Cell<usize>,
    /// Debug thread number, from 1; 0 until first needed.
    tid: core::cell::Cell<u32>,
    /// This thread's stack bounds for the frame walk; `hi == 0` until first
    /// needed.
    stack_lo: core::cell::Cell<usize>,
    stack_hi: core::cell::Cell<usize>,
    /// Set while the bounds are looked up: a lookup that allocates (the C
    /// library on Linux may) does not capture again.
    in_capture: core::cell::Cell<bool>,
    /// Counters, merged across threads only when a report asks.
    c: core::cell::UnsafeCell<DebugStats>,
}

impl ThreadDebug {
    pub(crate) const fn new() -> Self {
        Self {
            seq: core::cell::Cell::new(0),
            q_head: core::cell::Cell::new(core::ptr::null_mut()),
            q_tail: core::cell::Cell::new(core::ptr::null_mut()),
            q_bytes: core::cell::Cell::new(0),
            tid: core::cell::Cell::new(0),
            stack_lo: core::cell::Cell::new(0),
            stack_hi: core::cell::Cell::new(0),
            in_capture: core::cell::Cell::new(false),
            c: core::cell::UnsafeCell::new(DebugStats::new()),
        }
    }
}

/// The calling thread's debug state. `None` on a thread with no heap (none
/// created yet, creation failed, or teardown is over).
fn thread_debug() -> Option<&'static ThreadDebug> {
    // Never bootstrap a heap from here: a free on a thread with no heap yet
    // (or one already torn down, as in the teardown loop of
    // `init::thread_done`) is checked and released directly. Creating a heap
    // during teardown would leave the exit hook pointing at a box that the
    // same teardown then releases.
    let hb = crate::init::heap_box_fast();
    if hb.is_null() || hb == crate::init::empty_heap_box_ptr() {
        return None;
    }
    // SAFETY: a live heap box of this thread; it is released only by this
    // thread's teardown, after which `heap_box` no longer returns it. The
    // reference is used transiently, never across that point.
    Some(unsafe { &(*hb).dbg })
}

static NEXT_TID: AtomicU32 = AtomicU32::new(0);

/// The debug number of the thread owning `d`: 1, 2, ... in the order threads
/// first need one.
fn thread_no(d: &ThreadDebug) -> u32 {
    let t = d.tid.get();
    if t != 0 {
        return t;
    }
    let t = NEXT_TID
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
        .max(1);
    d.tid.set(t);
    t
}

/// The calling thread's debug number (0 if it has no heap).
pub fn thread_number() -> u32 {
    thread_debug().map_or(0, thread_no)
}

/// The calling thread's stack bounds, looked up once per thread.
fn stack_bounds() -> (usize, usize) {
    let Some(d) = thread_debug() else {
        return stack::thread_stack_bounds();
    };
    if d.stack_hi.get() == 0 {
        if d.in_capture.get() {
            return (0, 0);
        }
        d.in_capture.set(true);
        let (lo, hi) = stack::thread_stack_bounds();
        d.in_capture.set(false);
        d.stack_lo.set(lo);
        d.stack_hi.set(hi.max(1));
    }
    (d.stack_lo.get(), d.stack_hi.get())
}

/// Where the program called into the allocator. Inlined into a debug entry
/// point, it walks from that function's own frame, so the first entry is the
/// return address into whoever called the entry. Starting from a frame
/// rather than skipping a fixed count cannot drop a program frame, however
/// the entry was reached (`__rust_alloc`, a direct `GlobalAlloc` call or
/// the raw API); at worst a report starts with an allocator frame, as an
/// ASan report starts with `free`.
#[inline(always)]
fn here() -> StackId {
    if !stack::SUPPORTED || stack::stack_depth() == 0 {
        return StackId::NONE;
    }
    let fp = stack::frame_pointer();
    let (lo, hi) = stack_bounds();
    // SAFETY: `fp` is the frame of the running function, live on this
    // thread's stack; `lo..hi` are its bounds.
    unsafe { stack::capture_from(fp, lo, hi) }
}

/// Capture the calling function's stack into the depot (debug mode keeps
/// the bounds per thread). For tagging your own events; the allocator
/// records its own call sites.
#[inline(never)]
pub fn capture() -> StackId {
    if !stack::SUPPORTED || stack::stack_depth() == 0 {
        return StackId::NONE;
    }
    let (lo, hi) = stack_bounds();
    stack::capture_in(lo, hi, 1)
}

// ---------------------------------------------------------------------------
// Block layout: [header 64 B][user size B][canary 8 B]
// ---------------------------------------------------------------------------

/// Header bytes in front of every debug block.
const HDR: usize = 64;
/// Canary bytes after every debug block.
const TRAILER: usize = 8;
/// Fill of a fresh, non-zeroed allocation (mimalloc's `MI_DEBUG_UNINIT`).
pub const UNINIT_BYTE: u8 = 0xD0;
/// Fill of a freed block (mimalloc's `MI_DEBUG_FREED`).
pub const FREED_BYTE: u8 = 0xDF;
/// Fill of the canary after a block (mimalloc's `MI_DEBUG_PADDING`).
pub const CANARY_BYTE: u8 = 0xDE;

/// A live block from `RustyAlloc`.
const LIVE: u32 = 0x4c49_5645;
/// A live block from the raw API (`crate::alloc`).
const LIVE_RAW: u32 = 0x4c49_5652;
const FREED: u32 = 0x4652_4545;

/// The header. A live block is linked into its registry shard through
/// `prev`/`next`; a freed one into its thread's quarantine through `next`,
/// which is why a FREED header's checksum leaves the links out.
#[derive(Clone, Copy)]
#[repr(C)]
struct Header {
    prev: *mut u8,
    next: *mut u8,
    seq: u64,
    size: u64,
    alloc_stack: u32,
    free_stack: u32,
    alloc_tid: u32,
    free_tid: u32,
    state: u32,
    align_log2: u16,
    /// Registry shard epoch the block was linked in (see [`Shard`]).
    epoch: u16,
    check: u64,
}

const _: () = assert!(core::mem::size_of::<Header>() <= HDR);

impl Header {
    const fn live(seq: u64, size: usize, align: usize, stack: StackId, tid: u32) -> Self {
        Self {
            prev: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            seq,
            size: size as u64,
            alloc_stack: stack.0,
            free_stack: 0,
            alloc_tid: tid,
            free_tid: 0,
            state: LIVE,
            align_log2: align.trailing_zeros() as u16,
            epoch: 0,
            check: 0,
        }
    }

    const fn align(&self) -> usize {
        1usize << (self.align_log2 & 63)
    }
}

/// Header checksum, keyed by the block address so a header copied or left
/// behind at another address does not validate (Scudo's chunk checksum).
fn checksum(user: usize, h: &Header) -> u64 {
    let links = if h.state == FREED {
        0
    } else {
        (h.prev.addr() as u64).rotate_left(17) ^ h.next.addr() as u64
    };
    let mut x = (user as u64) ^ 0x7275_7374_795f_6462;
    x = (x ^ h.seq).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ h.size).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ ((u64::from(h.align_log2) << 48) | (u64::from(h.epoch) << 32) | u64::from(h.state)))
        .wrapping_mul(0x94D0_49BB_1331_11EB);
    x = (x ^ ((u64::from(h.alloc_stack) << 32) | u64::from(h.free_stack)))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ ((u64::from(h.alloc_tid) << 32) | u64::from(h.free_tid)))
        .wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ links).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Live,
    Freed,
    Bad,
}

/// # Safety
/// `user - HDR .. user` is readable.
unsafe fn read_header(user: *mut u8) -> (State, Header) {
    // SAFETY: per contract; unaligned-safe read.
    let h = unsafe { user.sub(HDR).cast::<Header>().read_unaligned() };
    let ok = h.check == checksum(user.addr(), &h);
    let st = match h.state {
        LIVE | LIVE_RAW if ok => State::Live,
        FREED if ok => State::Freed,
        _ => State::Bad,
    };
    (st, h)
}

/// Write `h` with a fresh checksum.
///
/// # Safety
/// `user - HDR .. user` is writable and ours.
unsafe fn write_header(user: *mut u8, mut h: Header) {
    h.check = checksum(user.addr(), &h);
    // SAFETY: per contract.
    unsafe { user.sub(HDR).cast::<Header>().write_unaligned(h) };
}

/// Start of the core block holding `p`, from its page; `None` when `p` is not
/// inside a carved page.
///
/// # Safety
/// `p` lies in a segment window this allocator owns.
unsafe fn block_start(p: *mut u8) -> Option<*mut u8> {
    // SAFETY: per contract the segment and its page table are ours.
    unsafe {
        let pg = crate::segment::page_of(crate::segment::segment_of(p), p);
        let bs = (*pg).block_size;
        let area = (*pg).area;
        if bs == 0 || area.is_null() || p.addr() < area.addr() {
            return None;
        }
        Some(area.add((p.addr() - area.addr()) / bs * bs))
    }
}

/// First byte in `p .. p + n` that is not `b`.
///
/// # Safety
/// The range is readable.
unsafe fn first_not(p: *const u8, b: u8, n: usize) -> Option<usize> {
    // SAFETY: per contract.
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    s.iter().position(|&x| x != b)
}

// ---------------------------------------------------------------------------
// Live-block registry
// ---------------------------------------------------------------------------
//
// Every live debug block, from every thread, is on one of `SHARDS` doubly
// linked lists threaded through the block headers and picked by address,
// each under its own lock: the busy list of Windows PageHeap, Valgrind's
// table of live blocks. A leak report walks the lists and so sees every
// thread's blocks, live threads and exited ones alike, without stopping any
// thread and without touching the core allocator's page lists, which their
// owners change without locks. A block is linked before `alloc` returns it
// and unlinked, under the same lock, before it is poisoned and quarantined,
// so the walk only ever reads headers of live, allocated blocks. Links are
// covered by the header checksum, and a link is followed only out of a
// header that validates, so a header damaged by the program ends the walk
// of its shard instead of sending it into freed or unmapped memory.

const SHARDS: usize = 256;

/// One registry list. `epoch` restarts the list when a damaged neighbor
/// makes it unsafe to keep: blocks of an older epoch are no longer on it and
/// are unlinked without touching anything.
#[repr(align(64))]
struct Shard {
    lock: core::sync::atomic::AtomicBool,
    /// Holder of `lock` (`init::thread_id`), to catch re-entry.
    owner: core::sync::atomic::AtomicUsize,
    head: core::cell::Cell<*mut u8>,
    count: core::cell::Cell<usize>,
    epoch: core::cell::Cell<u16>,
    /// Blocks dropped from the list by restarts.
    lost: core::cell::Cell<usize>,
}

// SAFETY: every `Cell` is touched only by the holder of `lock`.
unsafe impl Sync for Shard {}

impl Shard {
    const fn new() -> Self {
        Self {
            lock: core::sync::atomic::AtomicBool::new(false),
            owner: core::sync::atomic::AtomicUsize::new(0),
            head: core::cell::Cell::new(core::ptr::null_mut()),
            count: core::cell::Cell::new(0),
            epoch: core::cell::Cell::new(0),
            lost: core::cell::Cell::new(0),
        }
    }

    fn lock(&self) {
        let me = crate::init::thread_id();
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if self.owner.load(Ordering::Relaxed) == me {
                // A `leak_report` visitor called into the allocator.
                crate::options::out_fmt(
                    "rusty_alloc: error: the leak_report visitor allocated or freed; it must not\n",
                );
                crate::abort();
            }
            core::hint::spin_loop();
        }
        self.owner.store(me, Ordering::Relaxed);
    }

    fn unlock(&self) {
        self.owner.store(0, Ordering::Relaxed);
        self.lock.store(false, Ordering::Release);
    }

    /// Drop every block from the list (lock held).
    fn restart(&self) {
        self.lost.set(self.lost.get() + self.count.get());
        self.count.set(0);
        self.head.set(core::ptr::null_mut());
        self.epoch.set(self.epoch.get().wrapping_add(1));
    }
}

#[allow(
    clippy::declare_interior_mutable_const,
    reason = "array initialiser only"
)]
const SHARD: Shard = Shard::new();
static REGISTRY: [Shard; SHARDS] = [SHARD; SHARDS];

fn shard_of(user: *mut u8) -> &'static Shard {
    let h = ((user.addr() >> 4) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    &REGISTRY[(h >> 56) as usize % SHARDS]
}

/// Read a header under its shard's lock, so that no neighbor update is
/// half-written.
///
/// # Safety
/// As [`read_header`].
unsafe fn locked_read(user: *mut u8) -> (State, Header) {
    let s = shard_of(user);
    s.lock();
    // SAFETY: per contract.
    let r = unsafe { read_header(user) };
    s.unlock();
    r
}

/// Point a neighbor's `prev` or `next` at `to` (lock held). False when the
/// neighbor's header does not validate as a block of this list.
///
/// # Safety
/// `nb` is null or a block reached through a validated link of `s`.
unsafe fn relink(s: &Shard, nb: *mut u8, set_prev: bool, to: *mut u8) -> bool {
    if nb.is_null() {
        return true;
    }
    // SAFETY: per contract `nb` is a live block on this list.
    unsafe {
        let (st, mut h) = read_header(nb);
        if st != State::Live || h.epoch != s.epoch.get() {
            return false;
        }
        if set_prev {
            h.prev = to;
        } else {
            h.next = to;
        }
        write_header(nb, h);
    }
    true
}

/// Link a new block in and write its header.
///
/// # Safety
/// `user` is a fresh debug block, not yet visible to anyone.
unsafe fn track(user: *mut u8, mut h: Header) {
    let s = shard_of(user);
    s.lock();
    let head = s.head.get();
    // SAFETY: `head` is the list head, a live block of this list.
    let ok = unsafe { relink(s, head, true, user) };
    if !ok {
        s.restart();
    }
    h.prev = core::ptr::null_mut();
    h.next = s.head.get();
    h.epoch = s.epoch.get();
    // SAFETY: per contract.
    unsafe { write_header(user, h) };
    s.head.set(user);
    s.count.set(s.count.get() + 1);
    s.unlock();
    if !ok {
        report(&Violation::new(ViolationKind::CorruptHeader, head.addr()));
    }
}

/// Unlink a live block and write its FREED header `fh`, in one step under
/// the lock, so a racing second free sees FREED. `Err` with what the header
/// holds now when it is no longer the live block `seq` (freed meanwhile, or
/// damaged).
///
/// # Safety
/// `user` passed [`validate`].
unsafe fn untrack(user: *mut u8, seq: u64, fh: Header) -> Result<(), (State, Header)> {
    let s = shard_of(user);
    s.lock();
    // SAFETY: per contract the block is ours; neighbors are reached only
    // through its validated links.
    let bad = unsafe {
        let (st, h) = read_header(user);
        if st != State::Live || h.seq != seq {
            s.unlock();
            return Err((st, h));
        }
        let mut bad = core::ptr::null_mut();
        if h.epoch == s.epoch.get() {
            let ok_prev = if h.prev.is_null() {
                s.head.set(h.next);
                true
            } else {
                relink(s, h.prev, false, h.next)
            };
            let ok_next = relink(s, h.next, true, h.prev);
            if !ok_prev || !ok_next {
                bad = if ok_prev { h.next } else { h.prev };
                s.restart();
            } else {
                s.count.set(s.count.get().saturating_sub(1));
            }
        }
        write_header(user, fh);
        bad
    };
    s.unlock();
    if !bad.is_null() {
        report(&Violation::new(ViolationKind::CorruptHeader, bad.addr()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GlobalAlloc paths
// ---------------------------------------------------------------------------

/// Debug `GlobalAlloc::alloc` / `alloc_zeroed`.
///
/// Entry points stay out of line, so the call site is always the frame right
/// above them.
///
/// # Safety
/// `GlobalAlloc::alloc` contract.
#[inline(never)]
pub(crate) unsafe fn alloc(layout: core::alloc::Layout, zero: bool) -> *mut u8 {
    let st = here();
    // SAFETY: forwarded.
    unsafe { alloc_at(layout, zero, st) }
}

/// [`alloc`] with the call site already captured.
///
/// # Safety
/// `GlobalAlloc::alloc` contract.
unsafe fn alloc_at(layout: core::alloc::Layout, zero: bool, st: StackId) -> *mut u8 {
    // SAFETY: the calling thread's heap; `Layout` alignments are powers of two.
    unsafe {
        alloc_block(
            core::ptr::null_mut(),
            layout.size(),
            layout.align(),
            0,
            zero,
            false,
            st,
        )
    }
}

/// Allocate a debug block of `size` bytes with `(user + offset) % align ==
/// 0` from `hb` (null: the calling thread's heap): junk or zero fill,
/// canary, header, linked into the registry. `raw` marks a block of the raw
/// API. Null on a bad alignment or when the core is out of memory.
///
/// # Safety
/// `hb` is null or a heap box owned by the calling thread.
unsafe fn alloc_block(
    hb: *mut crate::init::HeapBox,
    size: usize,
    align: usize,
    offset: usize,
    zero: bool,
    raw: bool,
    st: StackId,
) -> *mut u8 {
    at_exit_register();
    if !align.is_power_of_two() {
        return core::ptr::null_mut();
    }
    let Some(total) = size.checked_add(HDR + TRAILER + 15) else {
        return core::ptr::null_mut();
    };
    // SAFETY: per contract.
    let base = unsafe {
        if align <= 16 && offset == 0 {
            // A 16-multiple request lands in a 16-aligned bin, so the user
            // pointer (`base + HDR`, HDR a multiple of 16) is 16-aligned too.
            crate::alloc::core_alloc(hb, total & !15, 16, 0)
        } else {
            let Some(at) = offset.checked_add(HDR) else {
                return core::ptr::null_mut();
            };
            crate::alloc::core_alloc(hb, total - 15, align, at)
        }
    };
    if base.is_null() {
        return base;
    }
    // SAFETY: `base` holds HDR + size + TRAILER bytes.
    unsafe {
        let user = base.add(HDR);
        if !user.addr().wrapping_add(offset).is_multiple_of(align) {
            let mut v = Violation::new(ViolationKind::Misaligned, user.addr());
            v.size = size;
            v.align = align;
            v.stack = st;
            report(&v);
        }
        core::ptr::write_bytes(user, if zero { 0 } else { UNINIT_BYTE }, size);
        core::ptr::write_bytes(user.add(size), CANARY_BYTE, TRAILER);
        let (seq, tid) = thread_debug().map_or((0, 0), |d| {
            count(d, |c| c.on_alloc(size));
            let s = d.seq.get() + 1;
            d.seq.set(s);
            (s, thread_no(d))
        });
        let mut h = Header::live(seq, size, align, st, tid);
        if raw {
            h.state = LIVE_RAW;
        }
        track(user, h);
        user
    }
}

/// What [`inspect`] found at a pointer handed to a free.
enum Inspect {
    /// A live debug block; its canary was checked.
    Block(Header),
    /// The start of a core block with no debug header: a block from
    /// `Heap::malloc` and friends, or the debug layer's own core block.
    Plain,
    /// Reported; releasing it would be unsafe.
    Rejected,
}

/// The checks every free makes, whatever the API: ownership, block start,
/// header, double free, canary. Reports each finding through `v` (which
/// carries the caller's pointer, layout and call site).
///
/// # Safety
/// None beyond `v.ptr` being non-null: every read is bounds-checked first.
unsafe fn inspect(v: &mut Violation) -> Inspect {
    let a = v.ptr;
    let p: *mut u8 = core::ptr::with_exposed_provenance_mut(a);
    if !crate::segment_map::contains(p) {
        v.kind = ViolationKind::ForeignPointer;
        report(v);
        return Inspect::Rejected;
    }
    // SAFETY: `p` is in a window we own; reads stay inside its core block.
    unsafe {
        let Some(start) = block_start(p) else {
            v.kind = ViolationKind::ForeignPointer;
            report(v);
            return Inspect::Rejected;
        };
        let off = a - start.addr();
        if off == 0 {
            return Inspect::Plain;
        }
        if off < HDR {
            v.kind = ViolationKind::InteriorPointer;
            v.offset = off;
            report(v);
            return Inspect::Rejected;
        }
        let (state, h) = locked_read(p);
        match state {
            State::Live => {}
            State::Freed => {
                v.kind = ViolationKind::DoubleFree;
                v.block(&h);
                report(v);
                return Inspect::Rejected;
            }
            State::Bad => {
                // A debug block whose header sits at the start of this core
                // block (every block with align <= 16) tells an interior
                // pointer from a damaged header.
                let u = start.add(HDR);
                let (ust, uh) = locked_read(u);
                if off == HDR {
                    v.kind = ViolationKind::CorruptHeader;
                } else if ust == State::Bad {
                    v.kind = ViolationKind::InteriorPointer;
                    v.offset = off;
                } else {
                    v.kind = ViolationKind::InteriorPointer;
                    v.offset = a - u.addr();
                    v.block(&uh);
                }
                report(v);
                return Inspect::Rejected;
            }
        }
        v.block(&h);
        if let Some(i) = first_not(p.add(h.size as usize), CANARY_BYTE, TRAILER) {
            v.kind = ViolationKind::BufferOverflow;
            v.offset = h.size as usize + i;
            report(v);
        }
        Inspect::Block(h)
    }
}

/// Check a pointer handed to `dealloc`/`realloc` against `layout`. Reports
/// every finding; returns the header when the block is ours and may be
/// released, `None` when releasing it would be unsafe. `st` is the call
/// site.
///
/// # Safety
/// None beyond `p` being non-null: every read is bounds-checked first.
unsafe fn validate(p: *mut u8, layout: core::alloc::Layout, st: StackId) -> Option<Header> {
    let mut v = Violation::new(ViolationKind::ForeignPointer, p.addr());
    v.size = layout.size();
    v.align = layout.align();
    v.stack = st;
    // SAFETY: forwarded.
    match unsafe { inspect(&mut v) } {
        Inspect::Rejected => None,
        Inspect::Plain => {
            v.kind = ViolationKind::NotFromGlobalAlloc;
            report(&v);
            None
        }
        Inspect::Block(h) if h.state == LIVE_RAW => {
            v.kind = ViolationKind::NotFromGlobalAlloc;
            report(&v);
            None
        }
        Inspect::Block(h) => {
            if h.size as usize != layout.size() {
                v.kind = ViolationKind::SizeMismatch;
                report(&v);
            } else if h.align() != layout.align() {
                v.kind = ViolationKind::AlignMismatch;
                report(&v);
            }
            Some(h)
        }
    }
}

// ---------------------------------------------------------------------------
// Quarantine (delayed free)
// ---------------------------------------------------------------------------

/// Default quarantine budget per thread, in bytes.
pub const QUARANTINE_DEFAULT: usize = 1 << 20;

/// Per-thread quarantine budget; `usize::MAX` until first resolved.
static QUARANTINE_LIMIT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);

/// Set the per-thread quarantine budget in bytes (0 turns the quarantine
/// off). Takes effect on each thread's next free.
pub fn set_quarantine_limit(bytes: usize) {
    QUARANTINE_LIMIT.store(bytes.min(usize::MAX - 1), Ordering::Relaxed);
}

/// The per-thread quarantine budget: [`set_quarantine_limit`], else the
/// environment variable `RUSTY_ALLOC_DEBUG_QUARANTINE_KIB`, else
/// [`QUARANTINE_DEFAULT`].
pub fn quarantine_limit() -> usize {
    let l = QUARANTINE_LIMIT.load(Ordering::Relaxed);
    if l != usize::MAX {
        return l;
    }
    let mut l = QUARANTINE_DEFAULT;
    #[cfg(all(any(windows, unix), not(miri)))]
    {
        let mut buf = [0u8; 24];
        if let Some(n) = crate::prim::getenv(b"RUSTY_ALLOC_DEBUG_QUARANTINE_KIB\0", &mut buf)
            && let Some(kib) = core::str::from_utf8(&buf[..n.min(buf.len())])
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
        {
            l = kib.saturating_mul(1024).min(usize::MAX - 1);
        }
    }
    QUARANTINE_LIMIT.store(l, Ordering::Relaxed);
    l
}

/// Hand the core block under a debug block back to the core.
///
/// # Safety
/// `p` is a debug block that is unlinked and owned by the caller.
unsafe fn core_free(p: *mut u8) {
    // SAFETY: per contract; the core block start frees the whole block, also
    // when the block was placed at an offset for its alignment.
    unsafe { crate::alloc::free(block_start(p).unwrap_or_else(|| p.sub(HDR))) };
}

/// Hand a validated block back: unlink it, record where it was freed,
/// poison it and park it in this thread's quarantine, releasing the oldest
/// blocks past the budget.
///
/// # Safety
/// `p` passed [`validate`], which returned `h`.
unsafe fn release(p: *mut u8, h: Header, st: StackId) {
    let size = h.size as usize;
    let d = thread_debug();
    let mut fh = h;
    fh.state = FREED;
    fh.prev = core::ptr::null_mut();
    fh.next = core::ptr::null_mut();
    fh.free_stack = st.0;
    fh.free_tid = d.map_or(0, thread_no);
    // SAFETY: per contract the block is ours and live until handed on.
    unsafe {
        if let Err((state, now)) = untrack(p, h.seq, fh) {
            // Freed (or damaged) by another thread since `validate`.
            let mut v = Violation::new(
                if state == State::Freed {
                    ViolationKind::DoubleFree
                } else {
                    ViolationKind::CorruptHeader
                },
                p.addr(),
            );
            v.stack = st;
            if state == State::Freed {
                v.block(&now);
            }
            report(&v);
            return;
        }
        core::ptr::write_bytes(p, FREED_BYTE, size);
        if let Some(d) = d {
            count(d, |c| c.on_free(size));
        }
        let limit = quarantine_limit();
        let Some(d) = d.filter(|_| size <= limit) else {
            core_free(p);
            return;
        };
        let tail = d.q_tail.get();
        if tail.is_null() {
            d.q_head.set(p);
        } else {
            set_q_next(tail, p);
        }
        d.q_tail.set(p);
        d.q_bytes.set(d.q_bytes.get() + size);
        while d.q_bytes.get() > limit && evict_one(d) {}
    }
}

/// Set the quarantine link of a FREED block (outside its checksum).
///
/// # Safety
/// `p` is a FREED block in the calling thread's quarantine.
unsafe fn set_q_next(p: *mut u8, next: *mut u8) {
    // SAFETY: per contract; the field lies inside the header.
    unsafe {
        p.sub(HDR)
            .add(core::mem::offset_of!(Header, next))
            .cast::<*mut u8>()
            .write_unaligned(next);
    }
}

/// Release the oldest quarantined block after checking its poison and
/// canary. False when the quarantine is empty.
fn evict_one(d: &ThreadDebug) -> bool {
    let p = d.q_head.get();
    if p.is_null() {
        return false;
    }
    // SAFETY: quarantined blocks are ours and stay allocated in the core
    // until this call frees them.
    unsafe {
        let (st, h) = read_header(p);
        if st != State::Freed {
            // The header (and with it the link) was overwritten: report and
            // abandon the rest of the queue rather than follow a bad link.
            let v = Violation::new(ViolationKind::CorruptHeader, p.addr());
            d.q_head.set(core::ptr::null_mut());
            d.q_tail.set(core::ptr::null_mut());
            d.q_bytes.set(0);
            report(&v);
            return true;
        }
        let size = h.size as usize;
        d.q_head.set(h.next);
        if h.next.is_null() {
            d.q_tail.set(core::ptr::null_mut());
        }
        d.q_bytes.set(d.q_bytes.get().saturating_sub(size));
        let hit = first_not(p, FREED_BYTE, size)
            .or_else(|| first_not(p.add(size), CANARY_BYTE, TRAILER).map(|i| size + i));
        if let Some(off) = hit {
            let mut v = Violation::new(ViolationKind::UseAfterFree, p.addr());
            v.block(&h);
            v.offset = off;
            report(&v);
        }
        core_free(p);
    }
    true
}

/// Check and release every block in the calling thread's quarantine.
pub fn flush_quarantine() {
    if let Some(d) = thread_debug() {
        while evict_one(d) {}
    }
}

/// Thread teardown: empty the dying thread's quarantine while its heap is
/// still live.
///
/// # Safety
/// `hb` is the calling thread's live heap box.
pub(crate) unsafe fn thread_done(hb: *mut crate::init::HeapBox) {
    // SAFETY: per contract.
    let d = unsafe { &(*hb).dbg };
    while evict_one(d) {}
    // SAFETY: per contract.
    unsafe { retire_counters(hb) };
}

/// Debug `GlobalAlloc::dealloc`.
///
/// # Safety
/// `GlobalAlloc::dealloc` contract (which this checks).
#[inline(never)]
pub(crate) unsafe fn dealloc(p: *mut u8, layout: core::alloc::Layout) {
    let st = here();
    // SAFETY: forwarded.
    unsafe {
        if let Some(h) = validate(p, layout, st) {
            release(p, h, st);
        }
    }
}

/// Debug `GlobalAlloc::realloc`: always moves, so a stale pointer to the old
/// block is caught as a use after free.
///
/// # Safety
/// `GlobalAlloc::realloc` contract (which this checks).
#[inline(never)]
pub(crate) unsafe fn realloc(p: *mut u8, layout: core::alloc::Layout, new_size: usize) -> *mut u8 {
    let st = here();
    // SAFETY: forwarded; the copy stays inside both blocks.
    unsafe {
        let Some(h) = validate(p, layout, st) else {
            return core::ptr::null_mut();
        };
        let nl = core::alloc::Layout::from_size_align_unchecked(new_size, layout.align());
        let np = alloc_at(nl, false, st);
        if np.is_null() {
            return np;
        }
        let old = h.size as usize;
        core::ptr::copy_nonoverlapping(p, np, old.min(new_size));
        if let Some(d) = thread_debug() {
            count(d, |c| c.on_realloc(old, new_size));
        }
        release(p, h, st);
        np
    }
}

// ---------------------------------------------------------------------------
// Leaks
// ---------------------------------------------------------------------------

/// A live block found by [`leak_report`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leak {
    /// The pointer `alloc` returned.
    pub ptr: usize,
    /// Requested size.
    pub size: usize,
    /// Requested alignment.
    pub align: usize,
    /// Allocation number on the allocating thread, counted from 1: blocks
    /// with a number at or past a mark taken with [`alloc_seq`] on that
    /// thread were allocated after it.
    pub seq: u64,
    /// Thread that allocated it (debug thread number, see [`thread_number`]).
    pub thread: u32,
    /// Where it was allocated ([`stack::frames`], [`stack::print_stack`]).
    pub stack: StackId,
}

/// Totals of a [`leak_report`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeakSummary {
    /// Live blocks listed.
    pub blocks: usize,
    /// Their requested bytes.
    pub bytes: usize,
    /// Live blocks that could not be listed: on a registry list behind a
    /// header the program damaged, or dropped from a list restarted after
    /// such damage (reported as `CorruptHeader` when a free or allocation
    /// met it). 0 in a clean run.
    pub unlisted: usize,
}

/// The calling thread's allocation number so far: a mark for
/// [`leak_report`] (its blocks with `seq > mark` came later).
pub fn alloc_seq() -> u64 {
    thread_debug().map_or(0, |d| d.seq.get())
}

/// Every live debug block in the process, from every thread (running or
/// exited), each handed to `f`, with its allocation call site. Blocks in a
/// quarantine are freed and not listed.
///
/// Walks the live-block registry one shard at a time, each under its lock,
/// so it runs while other threads allocate and free: a block allocated or
/// freed during the walk may or may not be listed, every block live for the
/// whole walk is listed once, and only headers of live blocks are read.
/// LeakSanitizer stops the world for this; without `std` there is no way to,
/// and none is needed. `f` runs under a shard lock and must not allocate or
/// free through this allocator (that is caught and aborts).
pub fn leak_report(f: &mut dyn FnMut(&Leak)) -> LeakSummary {
    let mut sum = LeakSummary::default();
    for s in &REGISTRY {
        s.lock();
        let ep = s.epoch.get();
        let mut cur = s.head.get();
        let mut seen = 0;
        while !cur.is_null() {
            // SAFETY: `cur` is the head or came from a validated link of
            // this list, under its lock: a live, allocated block.
            let (st, h) = unsafe { read_header(cur) };
            if st != State::Live || h.epoch != ep {
                break;
            }
            seen += 1;
            sum.blocks += 1;
            sum.bytes += h.size as usize;
            f(&Leak {
                ptr: cur.addr(),
                size: h.size as usize,
                align: h.align(),
                seq: h.seq,
                thread: h.alloc_tid,
                stack: StackId(h.alloc_stack),
            });
            cur = h.next;
        }
        sum.unlisted += s.lost.get() + s.count.get().saturating_sub(seen);
        s.unlock();
    }
    sum
}

/// Most distinct call sites [`print_leaks`] groups; leaks from further sites
/// are counted together.
const LEAK_SITES: usize = 64;

/// Print the leaks grouped by the call site that allocated them, largest
/// first, as LeakSanitizer does: for each of the first `max` sites the line
/// `rusty_alloc: leak of <bytes> bytes in <blocks> blocks allocated from:`
/// and its stack, then the summary line
/// `rusty_alloc: leaks: <blocks> blocks, <bytes> bytes still allocated`.
pub fn print_leaks(max: usize) -> LeakSummary {
    let mut sites = [(StackId::NONE, 0usize, 0usize); LEAK_SITES];
    let mut used = 0;
    let mut other = (0usize, 0usize);
    let sum = leak_report(&mut |l| {
        if let Some(s) = sites[..used].iter_mut().find(|s| s.0 == l.stack) {
            s.1 += 1;
            s.2 += l.size;
        } else if used < LEAK_SITES {
            sites[used] = (l.stack, 1, l.size);
            used += 1;
        } else {
            other.0 += 1;
            other.1 += l.size;
        }
    });
    let sites = &mut sites[..used];
    sites.sort_unstable_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
    for s in sites.iter().take(max) {
        line(format_args!(
            "rusty_alloc: leak of {} bytes in {} blocks allocated from:\n",
            s.2, s.1
        ));
        stack::print_stack(s.0);
    }
    for s in sites.iter().skip(max) {
        other.0 += s.1;
        other.1 += s.2;
    }
    if other.0 > 0 {
        line(format_args!(
            "rusty_alloc: leak of {} bytes in {} blocks from further call sites\n",
            other.1, other.0
        ));
    }
    if sum.unlisted > 0 {
        line(format_args!(
            "rusty_alloc: {} live blocks not listed (their registry list was restarted after a corrupted header)\n",
            sum.unlisted
        ));
    }
    line(format_args!(
        "rusty_alloc: leaks: {} blocks, {} bytes still allocated\n",
        sum.blocks, sum.bytes
    ));
    sum
}

// ---------------------------------------------------------------------------
// At exit
// ---------------------------------------------------------------------------

#[cfg(all(unix, not(miri)))]
static AT_EXIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// With `show_stats` on (`RUSTY_ALLOC_SHOW_STATS=1` or
/// `MIMALLOC_SHOW_STATS=1`), print the report at process exit, as
/// mimalloc does. Registered on the first debug allocation.
#[inline]
fn at_exit_register() {
    #[cfg(all(unix, not(miri)))]
    if !AT_EXIT.load(Ordering::Relaxed) && !AT_EXIT.swap(true, Ordering::Relaxed) {
        extern "C" fn at_exit() {
            if crate::options::is_enabled(1) {
                print_report();
            }
        }
        // SAFETY: registers a plain `extern "C"` function.
        unsafe {
            libc::atexit(at_exit);
        }
    }
}

/// Everything debug mode knows, to the output hook: the leak summary with
/// the first 16 leaks.
pub fn print_report() {
    print_leaks(16);
    print_stats();
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

use crate::bins::BIN_COUNT;

/// Counters of one size class (mimalloc's bins; the class of the REQUESTED
/// size, i.e. the bin the performance build would use).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BinStats {
    /// Block size of the class (0 for the huge class).
    pub block_size: usize,
    /// Allocations.
    pub allocs: u64,
    /// Frees.
    pub frees: u64,
    /// Requested bytes live now.
    pub live_bytes: i64,
    /// Highest `live_bytes` seen (merged: the largest of any thread).
    pub peak_bytes: i64,
    /// Bytes lost to size-class rounding on the live blocks (block size
    /// minus requested size, as the performance build would pay).
    pub waste_bytes: i64,
}

/// Debug-mode counters, per thread and merged by [`stats`]. Byte counts are
/// signed: a block freed on another thread than the one that allocated it
/// lowers the freeing thread's count, and only the merged sum is exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugStats {
    /// Per size class, indexed by bin.
    pub bins: [BinStats; BIN_COUNT],
    /// Allocations through `RustyAlloc`.
    pub allocs: u64,
    /// Frees through `RustyAlloc`.
    pub frees: u64,
    /// Requested bytes live now.
    pub live_bytes: i64,
    /// Highest `live_bytes` (merged: the largest of any thread).
    pub peak_bytes: i64,
    /// Size-class rounding waste of the live blocks.
    pub waste_bytes: i64,
    /// `realloc` calls.
    pub reallocs: u64,
    /// Reallocs that grew the block.
    pub realloc_grows: u64,
    /// Reallocs that shrank it.
    pub realloc_shrinks: u64,
    /// Grows by at most max(16 bytes, 1/8 of the old size): the
    /// grow-one-step-at-a-time pattern that a reserve would avoid.
    pub realloc_small_grows: u64,
    /// Reallocs that undid the previous realloc on the same thread
    /// (A to B, then B to A).
    pub realloc_ping_pongs: u64,
    /// Allocations above `LARGE_OBJ_SIZE_MAX`, each its own OS mapping or
    /// arena chunks.
    pub huge_allocs: u64,
    /// Frees of those.
    pub huge_frees: u64,
    /// Huge allocations of exactly the size this thread last freed: map,
    /// unmap, map again.
    pub huge_repeats: u64,
    /// Segments and huge blocks claimed from arena chunks.
    pub arena_claims: u64,
    /// Segments and huge blocks reserved fresh from the OS.
    pub os_reserves: u64,
    /// Freed chunks kept resident under the resident budget.
    pub chunk_parks: u64,
    /// Freed chunks purged because the budget was full.
    pub chunk_purges: u64,
    /// Threads whose counters are in this total (live and exited).
    pub threads: u64,
    last_old: usize,
    last_new: usize,
    last_huge_free: usize,
}

const BIN_ZERO: BinStats = BinStats {
    block_size: 0,
    allocs: 0,
    frees: 0,
    live_bytes: 0,
    peak_bytes: 0,
    waste_bytes: 0,
};

impl DebugStats {
    const fn new() -> Self {
        Self {
            bins: [BIN_ZERO; BIN_COUNT],
            allocs: 0,
            frees: 0,
            live_bytes: 0,
            peak_bytes: 0,
            waste_bytes: 0,
            reallocs: 0,
            realloc_grows: 0,
            realloc_shrinks: 0,
            realloc_small_grows: 0,
            realloc_ping_pongs: 0,
            huge_allocs: 0,
            huge_frees: 0,
            huge_repeats: 0,
            arena_claims: 0,
            os_reserves: 0,
            chunk_parks: 0,
            chunk_purges: 0,
            threads: 0,
            last_old: 0,
            last_new: 0,
            last_huge_free: 0,
        }
    }

    fn on_alloc(&mut self, size: usize) {
        let b = crate::bins::bin(size);
        let waste = if size > crate::types::MEDIUM_OBJ_SIZE_MAX {
            0
        } else {
            (crate::bins::good_size(size) - size) as i64
        };
        let s = &mut self.bins[b];
        s.allocs += 1;
        s.live_bytes += size as i64;
        s.peak_bytes = s.peak_bytes.max(s.live_bytes);
        s.waste_bytes += waste;
        self.allocs += 1;
        self.live_bytes += size as i64;
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        self.waste_bytes += waste;
        if size > crate::types::LARGE_OBJ_SIZE_MAX {
            self.huge_allocs += 1;
            if size == self.last_huge_free {
                self.huge_repeats += 1;
            }
        }
    }

    fn on_free(&mut self, size: usize) {
        let b = crate::bins::bin(size);
        let waste = if size > crate::types::MEDIUM_OBJ_SIZE_MAX {
            0
        } else {
            (crate::bins::good_size(size) - size) as i64
        };
        let s = &mut self.bins[b];
        s.frees += 1;
        s.live_bytes -= size as i64;
        s.waste_bytes -= waste;
        self.frees += 1;
        self.live_bytes -= size as i64;
        self.waste_bytes -= waste;
        if size > crate::types::LARGE_OBJ_SIZE_MAX {
            self.huge_frees += 1;
            self.last_huge_free = size;
        }
    }

    fn on_realloc(&mut self, old: usize, new: usize) {
        self.reallocs += 1;
        if new > old {
            self.realloc_grows += 1;
            if new - old <= (old / 8).max(16) {
                self.realloc_small_grows += 1;
            }
        } else if new < old {
            self.realloc_shrinks += 1;
        }
        if old != new && old == self.last_new && new == self.last_old {
            self.realloc_ping_pongs += 1;
        }
        self.last_old = old;
        self.last_new = new;
    }

    fn merge(&mut self, o: &Self) {
        for (a, b) in self.bins.iter_mut().zip(o.bins.iter()) {
            a.allocs += b.allocs;
            a.frees += b.frees;
            a.live_bytes += b.live_bytes;
            a.peak_bytes = a.peak_bytes.max(b.peak_bytes);
            a.waste_bytes += b.waste_bytes;
        }
        self.allocs += o.allocs;
        self.frees += o.frees;
        self.live_bytes += o.live_bytes;
        self.peak_bytes = self.peak_bytes.max(o.peak_bytes);
        self.waste_bytes += o.waste_bytes;
        self.reallocs += o.reallocs;
        self.realloc_grows += o.realloc_grows;
        self.realloc_shrinks += o.realloc_shrinks;
        self.realloc_small_grows += o.realloc_small_grows;
        self.realloc_ping_pongs += o.realloc_ping_pongs;
        self.huge_allocs += o.huge_allocs;
        self.huge_frees += o.huge_frees;
        self.huge_repeats += o.huge_repeats;
        self.arena_claims += o.arena_claims;
        self.os_reserves += o.os_reserves;
        self.chunk_parks += o.chunk_parks;
        self.chunk_purges += o.chunk_purges;
        self.threads += o.threads.max(1);
    }
}

/// Update this thread's counters. Never nests: `f` only does arithmetic.
fn count(d: &ThreadDebug, f: impl FnOnce(&mut DebugStats)) {
    // SAFETY: owner thread; the only `&mut` to the counters, and `f` calls
    // nothing that could reach here again.
    f(unsafe { &mut *d.c.get() });
}

/// What happened to an arena chunk, counted from the segment paths.
#[derive(Clone, Copy)]
pub(crate) enum Chunk {
    ArenaClaim,
    OsReserve,
    Park,
    Purge,
}

/// Count a chunk event on the calling thread, if it has a heap (the chunk
/// paths run under the heap; a thread without one is not counted).
pub(crate) fn count_chunk(k: Chunk) {
    let hb = crate::init::heap_box_fast();
    if hb.is_null() || hb == crate::init::empty_heap_box_ptr() {
        return;
    }
    // SAFETY: the calling thread's live heap box.
    let d = unsafe { &(*hb).dbg };
    count(d, |c| match k {
        Chunk::ArenaClaim => c.arena_claims += 1,
        Chunk::OsReserve => c.os_reserves += 1,
        Chunk::Park => c.chunk_parks += 1,
        Chunk::Purge => c.chunk_purges += 1,
    });
}

/// Counters of exited threads, folded in by their teardown. Written and read
/// only under the heap registry lock.
struct Retired(core::cell::UnsafeCell<DebugStats>);

// SAFETY: every access holds the heap registry lock (`init::debug_locked`).
unsafe impl Sync for Retired {}

static RETIRED: Retired = Retired(core::cell::UnsafeCell::new(DebugStats::new()));

/// Fold a dying thread's counters into the retired total.
///
/// # Safety
/// `hb` is the calling thread's live heap box.
unsafe fn retire_counters(hb: *mut crate::init::HeapBox) {
    crate::init::debug_locked(&mut |_| {
        // SAFETY: registry lock held (RETIRED); `hb` is ours and live.
        unsafe {
            (*RETIRED.0.get()).merge(&*(*hb).dbg.c.get());
            *(*hb).dbg.c.get() = DebugStats::new();
        }
    });
}

/// Process-wide counters: exited threads plus every live thread, merged now.
/// Live threads are read without stopping them (like `stats::merged`), so a
/// thread that is allocating at this moment may be a few counts off.
#[allow(
    clippy::volatile_composites,
    reason = "racy diagnostic snapshot of a live thread's counters, as in init::for_each_heap"
)]
pub fn stats() -> DebugStats {
    let mut t = DebugStats::new();
    crate::init::debug_locked(&mut |head| {
        // SAFETY: registry lock held: RETIRED is ours to read and every box
        // on the list is live; the counter read is a racy snapshot.
        unsafe {
            t.merge(&*RETIRED.0.get());
            t.threads = (*RETIRED.0.get()).threads;
            let mut hb = head;
            while !hb.is_null() {
                let c = core::ptr::read_volatile((*hb).dbg.c.get());
                if c.allocs + c.frees + c.arena_claims + c.os_reserves > 0 {
                    t.merge(&c);
                }
                hb = (*hb).next_box.load(Ordering::Acquire);
            }
        }
    });
    for (i, b) in t.bins.iter_mut().enumerate() {
        b.block_size = if i >= crate::types::BIN_HUGE {
            0
        } else {
            crate::bins::bin_size(i)
        };
    }
    t
}

/// Where memory goes, for the calling thread's heap and the process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fragmentation {
    /// Process resident set now (0 where the OS does not say).
    pub rss: usize,
    /// Peak resident set.
    pub peak_rss: usize,
    /// Requested bytes live, process-wide (from [`stats`]).
    pub live_bytes: i64,
    /// Size-class rounding waste of those, process-wide.
    pub waste_bytes: i64,
    /// Pages of this thread's heap.
    pub pages: usize,
    /// Committed bytes of those pages.
    pub page_bytes: usize,
    /// Bytes in use in them (blocks in use times block size).
    pub used_bytes: usize,
    /// Pages less than a quarter used: held, mostly empty.
    pub sparse_pages: usize,
    /// Committed but unused bytes of those pages.
    pub sparse_free_bytes: usize,
    /// Bytes in this thread's quarantine.
    pub quarantine_bytes: usize,
    /// Freed arena chunks parked resident now (the resident budget).
    pub parked_chunks: usize,
}

/// Fragmentation of the calling thread's heap, with process totals.
pub fn fragmentation_report() -> Fragmentation {
    let s = stats();
    let (_, _, _, rss, peak_rss, _, _, _) = crate::stats::process_info();
    let mut f = Fragmentation {
        rss,
        peak_rss,
        live_bytes: s.live_bytes,
        waste_bytes: s.waste_bytes,
        parked_chunks: crate::arena::parked_resident().0,
        ..Fragmentation::default()
    };
    let hb = crate::init::heap_box();
    if hb.is_null() || hb == crate::init::empty_heap_box_ptr() {
        return f;
    }
    let mut visit = |a: &crate::heap::AreaInfo, block: *mut u8, _: usize| -> bool {
        if block.is_null() {
            let used = a.used * a.block_size;
            f.pages += 1;
            f.page_bytes += a.committed;
            f.used_bytes += used;
            if used * 4 < a.committed {
                f.sparse_pages += 1;
                f.sparse_free_bytes += a.committed - used;
            }
        }
        true
    };
    // SAFETY: the calling thread's own live heap; the visitor only counts.
    unsafe {
        (*(*hb).heap.get()).visit_blocks(false, &mut visit);
        f.quarantine_bytes = (*hb).dbg.q_bytes.get();
    }
    f
}

fn line(args: fmt::Arguments<'_>) {
    let mut b = Line::new();
    let _ = fmt::write(&mut b, args);
    crate::options::out_fmt(b.as_str());
}

/// Print [`stats`] and [`fragmentation_report`] to the output hook, in the
/// spirit of `mi_stats_print`: totals, then one row per size class used.
pub fn print_stats() {
    let s = stats();
    line(format_args!(
        "rusty_alloc: stats: threads {} allocs {} frees {} live {} B peak {} B waste {} B\n",
        s.threads, s.allocs, s.frees, s.live_bytes, s.peak_bytes, s.waste_bytes
    ));
    line(format_args!(
        "rusty_alloc: realloc: {} (grow {} shrink {} small-grow {} ping-pong {})\n",
        s.reallocs, s.realloc_grows, s.realloc_shrinks, s.realloc_small_grows, s.realloc_ping_pongs
    ));
    line(format_args!(
        "rusty_alloc: huge: allocs {} frees {} same-size repeats {}; chunks: arena {} os {} parked {} purged {}\n",
        s.huge_allocs,
        s.huge_frees,
        s.huge_repeats,
        s.arena_claims,
        s.os_reserves,
        s.chunk_parks,
        s.chunk_purges
    ));
    for b in s.bins.iter().filter(|b| b.allocs > 0) {
        line(format_args!(
            "rusty_alloc: bin {:>8}: allocs {} frees {} live {} B peak {} B waste {} B\n",
            b.block_size, b.allocs, b.frees, b.live_bytes, b.peak_bytes, b.waste_bytes
        ));
    }
    let f = fragmentation_report();
    line(format_args!(
        "rusty_alloc: memory: rss {} B (peak {}) live {} B; this thread: {} pages, {} B committed, {} B used, {} sparse pages holding {} B free, quarantine {} B; parked chunks {}\n",
        f.rss,
        f.peak_rss,
        f.live_bytes,
        f.pages,
        f.page_bytes,
        f.used_bytes,
        f.sparse_pages,
        f.sparse_free_bytes,
        f.quarantine_bytes,
        f.parked_chunks
    ));
}
