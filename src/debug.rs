//! Debug mode: the `debug_checks` feature.
//!
//! One allocator for both modes. With the feature off this module does not
//! exist and [`crate::RustyAlloc`] is the plain fast path; with it on every
//! `GlobalAlloc` call is checked here. See `docs/debugging.md` for the design,
//! the survey it follows and the defaults.
//!
//! A failed check builds a [`Violation`] and hands it to the handler. The
//! default handler prints one line to stderr (through the output hook, see
//! `options::register_output`) and aborts, which is what mimalloc's debug
//! build does on heap corruption. [`set_handler`] replaces it, for example
//! to log and continue, as `mi_register_error` does.

use core::fmt;
use core::sync::atomic::{AtomicPtr, Ordering};

/// What a check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// `dealloc` of a pointer outside every segment this allocator owns:
    /// memory from another allocator (an FFI mismatch, e.g. a C `malloc`
    /// block handed to a Rust `Box`).
    ForeignPointer,
    /// `dealloc` of a block this allocator owns that was not allocated
    /// through [`crate::RustyAlloc`] (the raw `alloc::malloc` / `mi_malloc`
    /// API, typically the C side of an FFI boundary).
    NotFromGlobalAlloc,
    /// `dealloc` of a pointer into the middle of a block.
    InteriorPointer,
    /// `dealloc` of a block that is already freed (still in quarantine).
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

/// One failed check. Fields that do not apply to a kind are 0.
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

/// The default handler: print `rusty_alloc: error: <violation>` and abort.
pub fn default_handler(v: &Violation) {
    print_violation(v);
    crate::abort();
}

/// Print one violation line through the output hook, without allocating.
pub fn print_violation(v: &Violation) {
    let mut b = Line::new();
    let _ = fmt::write(&mut b, format_args!("rusty_alloc: error: {v}\n"));
    crate::options::out_fmt(b.as_str());
}

/// Hand `v` to the handler. Returns only if the handler returned.
#[cold]
#[inline(never)]
pub(crate) fn report(v: &Violation) {
    let h = HANDLER.load(Ordering::Acquire);
    if h.is_null() {
        default_handler(v);
    } else {
        // SAFETY: see `set_handler`.
        let f = unsafe { core::mem::transmute::<*mut (), Handler>(h) };
        f(v);
    }
}

/// A fixed stack buffer for one formatted line: reports must not allocate,
/// they run inside the allocator. Output past the end is cut.
pub(crate) struct Line {
    buf: [u8; 256],
    len: usize,
}

impl Line {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; 256],
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
}

impl ThreadDebug {
    pub(crate) const fn new() -> Self {
        Self {
            seq: core::cell::Cell::new(0),
        }
    }
}

/// The calling thread's debug state, creating its heap if needed. `None` on
/// a thread whose heap cannot exist (creation failed, or teardown is over).
fn thread_debug() -> Option<&'static ThreadDebug> {
    let hb = crate::init::heap_box();
    if hb.is_null() || hb == crate::init::empty_heap_box_ptr() {
        return None;
    }
    // SAFETY: a live heap box of this thread; it is released only by this
    // thread's teardown, after which `heap_box` no longer returns it. The
    // reference is used transiently, never across that point.
    Some(unsafe { &(*hb).dbg })
}

// ---------------------------------------------------------------------------
// Block layout: [header 32 B][user size B][canary 8 B]
// ---------------------------------------------------------------------------

/// Header bytes in front of every debug block.
const HDR: usize = 32;
/// Canary bytes after every debug block.
const TRAILER: usize = 8;
/// Fill of a fresh, non-zeroed allocation (mimalloc's `MI_DEBUG_UNINIT`).
pub const UNINIT_BYTE: u8 = 0xD0;
/// Fill of a freed block (mimalloc's `MI_DEBUG_FREED`).
pub const FREED_BYTE: u8 = 0xDF;
/// Fill of the canary after a block (mimalloc's `MI_DEBUG_PADDING`).
pub const CANARY_BYTE: u8 = 0xDE;

const LIVE: u32 = 0x4c49_5645;
const FREED: u32 = 0x4652_4545;

/// The header. `seq` doubles as the quarantine link once the block is freed,
/// which is why a FREED header's checksum leaves it out.
#[derive(Clone, Copy)]
#[repr(C)]
struct Header {
    seq: u64,
    size: usize,
    align: u32,
    state: u32,
    check: u64,
}

const _: () = assert!(core::mem::size_of::<Header>() == HDR);

/// Header checksum, keyed by the block address so a header copied or left
/// behind at another address does not validate (Scudo's chunk checksum).
const fn checksum(user: usize, seq: u64, size: usize, align: u32, state: u32) -> u64 {
    let mut x = (user as u64) ^ 0x7275_7374_795f_6462;
    x = (x ^ seq).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ size as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (((align as u64) << 32) | state as u64)).wrapping_mul(0x94D0_49BB_1331_11EB);
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
    let a = user.addr();
    let st = if h.state == LIVE && h.check == checksum(a, h.seq, h.size, h.align, LIVE) {
        State::Live
    } else if h.state == FREED && h.check == checksum(a, 0, h.size, h.align, FREED) {
        State::Freed
    } else {
        State::Bad
    };
    (st, h)
}

/// # Safety
/// `user - HDR .. user` is writable and ours.
unsafe fn write_header(user: *mut u8, seq: u64, size: usize, align: usize, state: u32) {
    let align = align as u32;
    let check = if state == LIVE {
        checksum(user.addr(), seq, size, align, LIVE)
    } else {
        checksum(user.addr(), 0, size, align, FREED)
    };
    let h = Header {
        seq,
        size,
        align,
        state,
        check,
    };
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
// GlobalAlloc paths
// ---------------------------------------------------------------------------

/// Debug `GlobalAlloc::alloc` / `alloc_zeroed`.
///
/// # Safety
/// `GlobalAlloc::alloc` contract.
pub(crate) unsafe fn alloc(layout: core::alloc::Layout, zero: bool) -> *mut u8 {
    let size = layout.size();
    let align = layout.align();
    let Some(total) = size.checked_add(HDR + TRAILER + 15) else {
        return core::ptr::null_mut();
    };
    let raw = if align <= 16 {
        // A 16-multiple request lands in a 16-aligned bin, so the user
        // pointer (`raw + 32`) is 16-aligned as well.
        let t = total & !15;
        if zero {
            crate::alloc::zalloc(t)
        } else {
            crate::alloc::malloc(t)
        }
    } else {
        let t = total - 15;
        if zero {
            crate::alloc::zalloc_aligned_at(t, align, HDR)
        } else {
            crate::alloc::malloc_aligned_at(t, align, HDR)
        }
    };
    if raw.is_null() {
        return raw;
    }
    // SAFETY: `raw` holds HDR + size + TRAILER bytes.
    unsafe {
        let user = raw.add(HDR);
        if !user.addr().is_multiple_of(align) {
            let mut v = Violation::new(ViolationKind::Misaligned, user.addr());
            v.size = size;
            v.align = align;
            report(&v);
        }
        if !zero {
            core::ptr::write_bytes(user, UNINIT_BYTE, size);
        }
        core::ptr::write_bytes(user.add(size), CANARY_BYTE, TRAILER);
        let seq = thread_debug().map_or(0, |d| {
            let s = d.seq.get() + 1;
            d.seq.set(s);
            s
        });
        write_header(user, seq, size, align, LIVE);
        user
    }
}

/// Check a pointer handed to `dealloc`/`realloc` against `layout`. Reports
/// every finding; returns the header when the block is ours and may be
/// released, `None` when releasing it would be unsafe.
///
/// # Safety
/// None beyond `p` being non-null: every read is bounds-checked first.
unsafe fn validate(p: *mut u8, layout: core::alloc::Layout) -> Option<Header> {
    let a = p.addr();
    let mut v = Violation::new(ViolationKind::ForeignPointer, a);
    v.size = layout.size();
    v.align = layout.align();
    if !crate::segment_map::contains(p) {
        report(&v);
        return None;
    }
    // SAFETY: `p` is in a window we own; reads stay inside its core block.
    unsafe {
        let Some(start) = block_start(p) else {
            report(&v);
            return None;
        };
        let off = a - start.addr();
        if off < HDR {
            v.kind = if off == 0 {
                ViolationKind::NotFromGlobalAlloc
            } else {
                ViolationKind::InteriorPointer
            };
            v.offset = off;
            report(&v);
            return None;
        }
        let (st, h) = read_header(p);
        match st {
            State::Live => {}
            State::Freed => {
                v.kind = ViolationKind::DoubleFree;
                v.block_size = h.size;
                v.block_align = h.align as usize;
                report(&v);
                return None;
            }
            State::Bad => {
                // A debug block whose header sits at the start of this core
                // block (every block with align <= 16) tells an interior
                // pointer from a damaged header.
                let u = start.add(HDR);
                let (ust, uh) = read_header(u);
                if off == HDR {
                    v.kind = ViolationKind::CorruptHeader;
                } else if ust == State::Bad {
                    v.kind = ViolationKind::InteriorPointer;
                    v.offset = off;
                } else {
                    v.kind = ViolationKind::InteriorPointer;
                    v.offset = a - u.addr();
                    v.block_size = uh.size;
                    v.block_align = uh.align as usize;
                }
                report(&v);
                return None;
            }
        }
        v.block_size = h.size;
        v.block_align = h.align as usize;
        v.seq = h.seq;
        if h.size != layout.size() {
            v.kind = ViolationKind::SizeMismatch;
            report(&v);
        } else if h.align as usize != layout.align() {
            v.kind = ViolationKind::AlignMismatch;
            report(&v);
        }
        if let Some(i) = first_not(p.add(h.size), CANARY_BYTE, TRAILER) {
            v.kind = ViolationKind::BufferOverflow;
            v.offset = h.size + i;
            report(&v);
        }
        Some(h)
    }
}

/// Hand a validated block back.
///
/// # Safety
/// `p` passed [`validate`], which returned `h`.
unsafe fn release(p: *mut u8, h: Header) {
    // SAFETY: per contract the block is ours and live.
    unsafe {
        write_header(p, 0, h.size, h.align as usize, FREED);
        crate::alloc::free(p.sub(HDR));
    }
}

/// Debug `GlobalAlloc::dealloc`.
///
/// # Safety
/// `GlobalAlloc::dealloc` contract (which this checks).
pub(crate) unsafe fn dealloc(p: *mut u8, layout: core::alloc::Layout) {
    // SAFETY: forwarded.
    unsafe {
        if let Some(h) = validate(p, layout) {
            release(p, h);
        }
    }
}

/// Debug `GlobalAlloc::realloc`: always moves, so a stale pointer to the old
/// block is caught as a use after free.
///
/// # Safety
/// `GlobalAlloc::realloc` contract (which this checks).
pub(crate) unsafe fn realloc(p: *mut u8, layout: core::alloc::Layout, new_size: usize) -> *mut u8 {
    // SAFETY: forwarded; the copy stays inside both blocks.
    unsafe {
        let Some(h) = validate(p, layout) else {
            return core::ptr::null_mut();
        };
        let nl = core::alloc::Layout::from_size_align_unchecked(new_size, layout.align());
        let np = alloc(nl, false);
        if np.is_null() {
            return np;
        }
        core::ptr::copy_nonoverlapping(p, np, h.size.min(new_size));
        release(p, h);
        np
    }
}
