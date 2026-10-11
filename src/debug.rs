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
