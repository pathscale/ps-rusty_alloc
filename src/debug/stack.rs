//! Call stacks for debug mode: a frame-pointer walk and a stack depot.
//!
//! Capture is the fast unwinder of AddressSanitizer and heaptrack: follow
//! the chain of frame records (`[fp]` is the caller's frame pointer,
//! `[fp + 8]` the return address) on aarch64 and x86-64, inside the bounds
//! of the calling thread's stack, so a frame built without a frame pointer
//! ends the walk instead of faulting. Nothing is allocated: the frames land
//! in a fixed array on the stack.
//!
//! The depot is ASan's `StackDepot`: each distinct stack is stored once, in
//! entries carved from raw OS pages (never from the allocator being
//! debugged), found again through a lock-free hash table, and named by a
//! 32-bit [`StackId`] that a block header can carry. Entries are never freed,
//! so a [`StackId`] stays valid for the life of the process.
//!
//! Symbolizing needs no `std` either: [`print_stack`] writes each return
//! address with the image it falls in and its offset from the image's load
//! address (`dladdr`), which is what `atos -l` and `addr2line` take. See
//! `tools/symbolize.ts` and `docs/debugging.md`.
//!
//! Full stacks need frame pointers in the code being walked. aarch64 macOS
//! always keeps them; elsewhere build the consumer with
//! `-C force-frame-pointers=yes`, as heaptrack and ASan's fast unwinder ask.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

/// Most return addresses kept per stack.
pub const MAX_FRAMES: usize = 16;

/// A stack in the depot. `StackId::NONE` (0) means no stack was recorded:
/// capture is off, the platform has no walker, or the depot is full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StackId(pub u32);

impl StackId {
    /// No stack.
    pub const NONE: Self = Self(0);

    /// Whether this names no stack.
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// Depth
// ---------------------------------------------------------------------------

/// Frames to capture per stack; `usize::MAX` until first resolved.
static DEPTH: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set how many frames debug mode records per allocation and free (at most
/// [`MAX_FRAMES`]; 0 turns capture off). Process-wide, takes effect at once.
pub fn set_stack_depth(frames: usize) {
    DEPTH.store(frames.min(MAX_FRAMES), Ordering::Relaxed);
}

/// Frames recorded per stack: [`set_stack_depth`], else the environment
/// variable `RUSTY_ALLOC_DEBUG_STACK_DEPTH`, else [`MAX_FRAMES`].
pub fn stack_depth() -> usize {
    let d = DEPTH.load(Ordering::Relaxed);
    if d != usize::MAX {
        return d;
    }
    #[allow(unused_mut, reason = "only targets with an environment change it")]
    let mut d = MAX_FRAMES;
    #[cfg(all(any(windows, unix), not(miri)))]
    {
        let mut buf = [0u8; 24];
        if let Some(n) = crate::prim::getenv(b"RUSTY_ALLOC_DEBUG_STACK_DEPTH\0", &mut buf)
            && let Some(v) = core::str::from_utf8(&buf[..n.min(buf.len())])
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
        {
            d = v.min(MAX_FRAMES);
        }
    }
    DEPTH.store(d, Ordering::Relaxed);
    d
}

// ---------------------------------------------------------------------------
// Frame-pointer walk
// ---------------------------------------------------------------------------

/// Whether this target has a walker.
pub const SUPPORTED: bool = cfg!(all(
    not(miri),
    any(target_arch = "aarch64", target_arch = "x86_64"),
    any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android"
    )
));

/// The frame pointer of the calling function.
#[cfg(all(not(miri), target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: reads a register; touches no memory.
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags));
    }
    fp
}

/// The frame pointer of the calling function.
#[cfg(all(not(miri), target_arch = "x86_64"))]
#[inline(always)]
pub(crate) fn frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: reads a register; touches no memory.
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
    }
    fp
}

/// The frame pointer of the calling function (no walker on this target).
#[cfg(any(miri, not(any(target_arch = "aarch64", target_arch = "x86_64"))))]
#[inline(always)]
pub(crate) const fn frame_pointer() -> usize {
    0
}

/// Lowest and one-past-highest address of the calling thread's stack, or
/// `(0, 0)` where the platform cannot say. Does not allocate on macOS; on
/// Linux `pthread_getattr_np` may call the C library's `malloc` for the main
/// thread (not this allocator, unless it is also the C `malloc`; callers
/// guard re-entry and cache the result per thread).
pub fn thread_stack_bounds() -> (usize, usize) {
    #[cfg(all(not(miri), target_vendor = "apple"))]
    // SAFETY: plain queries about the calling thread.
    unsafe {
        let me = libc::pthread_self();
        let hi = libc::pthread_get_stackaddr_np(me).addr();
        let size = libc::pthread_get_stacksize_np(me);
        (hi.saturating_sub(size), hi)
    }
    #[cfg(all(not(miri), any(target_os = "linux", target_os = "android")))]
    // SAFETY: `attr` is initialised by `pthread_getattr_np` before it is
    // read and destroyed once.
    unsafe {
        let mut attr: libc::pthread_attr_t = core::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
            return (0, 0);
        }
        let mut addr: *mut libc::c_void = core::ptr::null_mut();
        let mut size: libc::size_t = 0;
        let r = libc::pthread_attr_getstack(&attr, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut attr);
        if r != 0 {
            return (0, 0);
        }
        (addr.addr(), addr.addr().saturating_add(size))
    }
    #[cfg(not(all(
        not(miri),
        any(target_vendor = "apple", target_os = "linux", target_os = "android")
    )))]
    {
        (0, 0)
    }
}

/// Follow the frame records from `fp` and store up to `out.len()` return
/// addresses, after skipping the first `skip`. A record must lie inside
/// `lo..hi`, be 8-aligned, and each next record must sit higher on the stack
/// than the last; the first one that does not ends the walk. Returns the
/// number stored.
///
/// # Safety
/// `lo..hi` is the calling thread's stack (every address in it readable),
/// and `fp` is a frame pointer of a frame still live on it (or any value
/// outside the range, which stores nothing).
pub unsafe fn walk(fp: usize, lo: usize, hi: usize, skip: usize, out: &mut [usize]) -> usize {
    let mut fp = fp;
    let mut n = 0;
    let mut skip = skip;
    while n < out.len() {
        if fp < lo || hi < 16 || fp > hi - 16 || !fp.is_multiple_of(8) {
            break;
        }
        // SAFETY: per contract `fp .. fp + 16` is inside the live stack.
        let (next, ret) = unsafe {
            (
                core::ptr::with_exposed_provenance::<usize>(fp).read_volatile(),
                core::ptr::with_exposed_provenance::<usize>(fp + 8).read_volatile(),
            )
        };
        // Pointer-authentication bits (arm64e) and tag bits are not part of
        // the address.
        #[cfg(target_arch = "aarch64")]
        let ret = ret & 0x0000_FFFF_FFFF_FFFF;
        if ret == 0 {
            break;
        }
        if skip > 0 {
            skip -= 1;
        } else {
            out[n] = ret;
            n += 1;
        }
        if next <= fp {
            break;
        }
        fp = next;
    }
    n
}

// ---------------------------------------------------------------------------
// Depot
// ---------------------------------------------------------------------------

#[repr(C)]
struct Entry {
    next: AtomicPtr<Entry>,
    hash: u64,
    id: u32,
    len: u32,
    frames: [usize; MAX_FRAMES],
}

const BUCKETS: usize = 1 << 14;
const CHUNK_BYTES: usize = 1 << 20;
const PER_CHUNK: usize = CHUNK_BYTES / core::mem::size_of::<Entry>();
const MAX_CHUNKS: usize = 1024;

#[allow(
    clippy::declare_interior_mutable_const,
    reason = "array initialiser only"
)]
const NULL_ENTRY: AtomicPtr<Entry> = AtomicPtr::new(core::ptr::null_mut());

/// Hash buckets: heads of lock-free singly linked lists, pushed under `LOCK`.
static TABLE: [AtomicPtr<Entry>; BUCKETS] = [NULL_ENTRY; BUCKETS];
/// OS chunks the entries are carved from, in id order.
static CHUNKS: [AtomicPtr<Entry>; MAX_CHUNKS] = [NULL_ENTRY; MAX_CHUNKS];
/// Entries stored so far (the next id minus one).
static COUNT: AtomicU32 = AtomicU32::new(0);
/// Serialises inserts; lookups never take it.
static LOCK: AtomicBool = AtomicBool::new(false);

fn hash(frames: &[usize]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64 ^ frames.len() as u64;
    for &f in frames {
        h = (h ^ f as u64).wrapping_mul(0x0100_0000_01b3);
        h ^= h >> 29;
    }
    h
}

fn find(head: *mut Entry, h: u64, frames: &[usize]) -> Option<StackId> {
    let mut e = head;
    while !e.is_null() {
        // SAFETY: entries are published with Release after they are fully
        // written and are never freed or changed again.
        let r = unsafe { &*e };
        if r.hash == h && r.len as usize == frames.len() && &r.frames[..frames.len()] == frames {
            return Some(StackId(r.id));
        }
        e = r.next.load(Ordering::Acquire);
    }
    None
}

/// Store `frames` (at most [`MAX_FRAMES`]) once and return its id; the same
/// frames always give the same id. [`StackId::NONE`] for an empty stack or
/// when the depot cannot grow (out of memory, or 2^32 distinct stacks).
pub fn intern(frames: &[usize]) -> StackId {
    let frames = &frames[..frames.len().min(MAX_FRAMES)];
    if frames.is_empty() {
        return StackId::NONE;
    }
    let h = hash(frames);
    let bucket = &TABLE[(h as usize) & (BUCKETS - 1)];
    if let Some(id) = find(bucket.load(Ordering::Acquire), h, frames) {
        return id;
    }
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let head = bucket.load(Ordering::Acquire);
    let id = find(head, h, frames).unwrap_or_else(|| insert(bucket, head, h, frames));
    LOCK.store(false, Ordering::Release);
    id
}

/// Carve an entry and publish it. Caller holds `LOCK`.
fn insert(bucket: &AtomicPtr<Entry>, head: *mut Entry, h: u64, frames: &[usize]) -> StackId {
    let n = COUNT.load(Ordering::Relaxed) as usize;
    let (chunk, slot) = (n / PER_CHUNK, n % PER_CHUNK);
    if chunk >= MAX_CHUNKS {
        return StackId::NONE;
    }
    let mut base = CHUNKS[chunk].load(Ordering::Acquire);
    if base.is_null() {
        // SAFETY: a fresh committed mapping that this depot owns for good.
        match unsafe { crate::prim::alloc(CHUNK_BYTES, crate::os::page_size(), true, false) } {
            Ok(a) => base = a.ptr.cast(),
            Err(_) => return StackId::NONE,
        }
        CHUNKS[chunk].store(base, Ordering::Release);
    }
    let id = StackId(n as u32 + 1);
    let mut f = [0usize; MAX_FRAMES];
    f[..frames.len()].copy_from_slice(frames);
    // SAFETY: slot `slot` of a chunk of PER_CHUNK entries, never handed out
    // before (COUNT only grows, under LOCK).
    unsafe {
        let e = base.add(slot);
        e.write(Entry {
            next: AtomicPtr::new(head),
            hash: h,
            id: id.0,
            len: frames.len() as u32,
            frames: f,
        });
        COUNT.store(n as u32 + 1, Ordering::Release);
        bucket.store(e, Ordering::Release);
    }
    id
}

/// The return addresses of `id`, innermost first; empty for
/// [`StackId::NONE`] or an id this depot never gave out.
pub fn frames(id: StackId) -> &'static [usize] {
    if id.is_none() || id.0 > COUNT.load(Ordering::Acquire) {
        return &[];
    }
    let n = id.0 as usize - 1;
    let base = CHUNKS[n / PER_CHUNK].load(Ordering::Acquire);
    if base.is_null() {
        return &[];
    }
    // SAFETY: entry `n` was written before COUNT passed it (Release/Acquire)
    // and is never changed or freed.
    unsafe {
        let e = &*base.add(n % PER_CHUNK);
        &e.frames[..e.len as usize]
    }
}

/// Stacks in the depot and the bytes of OS memory holding them.
pub fn depot_usage() -> (usize, usize) {
    let n = COUNT.load(Ordering::Acquire) as usize;
    (n, n.div_ceil(PER_CHUNK) * CHUNK_BYTES)
}

/// Capture the stack of the caller of this function (it is not part of the
/// stack) and store it, without allocating. `lo..hi` are the calling
/// thread's stack bounds ([`thread_stack_bounds`]). Honors [`stack_depth`].
///
/// Prefer [`crate::debug::capture`], which caches the bounds per thread.
#[inline(never)]
pub fn capture_in(lo: usize, hi: usize, skip: usize) -> StackId {
    let depth = stack_depth();
    if !SUPPORTED || depth == 0 || lo >= hi {
        return StackId::NONE;
    }
    let mut f = [0usize; MAX_FRAMES];
    // SAFETY: `frame_pointer()` is this function's own live frame, and
    // `lo..hi` is the caller's claim about this thread's stack; `walk`
    // stays inside it.
    let n = unsafe { walk(frame_pointer(), lo, hi, skip, &mut f[..depth]) };
    intern(&f[..n])
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

/// The image holding `addr` and its load address, through `dladdr`:
/// `(path, base)`, or `None` where unknown.
pub fn image_of(addr: usize) -> Option<(&'static str, usize)> {
    #[cfg(all(unix, not(miri)))]
    // SAFETY: `dladdr` only reads the loader's tables and fills `info`; the
    // file name it points to lives as long as the image stays loaded.
    unsafe {
        let mut info: libc::Dl_info = core::mem::zeroed();
        if libc::dladdr(core::ptr::with_exposed_provenance(addr), &mut info) == 0
            || info.dli_fname.is_null()
        {
            return None;
        }
        let p = info.dli_fname.cast::<u8>();
        let mut len = 0;
        while *p.add(len) != 0 && len < 4096 {
            len += 1;
        }
        let name = core::str::from_utf8(core::slice::from_raw_parts(p, len)).ok()?;
        Some((name, info.dli_fbase.addr()))
    }
    #[cfg(not(all(unix, not(miri))))]
    {
        let _ = addr;
        None
    }
}

/// Print the frames of `id` through the output hook, one per line, as
/// AddressSanitizer does before symbolizing:
/// `rusty_alloc:     #0 0x000000010003a2c4 (/path/to/app+0x3a2c4)`.
/// `tools/symbolize.ts` turns these lines into function, file and line.
pub fn print_stack(id: StackId) {
    let fr = frames(id);
    if fr.is_empty() {
        super::line(format_args!(
            "rusty_alloc:     <no stack: frame pointers off, capture off, or unsupported target>\n"
        ));
        return;
    }
    for (i, &a) in fr.iter().enumerate() {
        match image_of(a) {
            Some((name, base)) => super::line(format_args!(
                "rusty_alloc:     #{i} {a:#018x} ({name}+{:#x})\n",
                a - base
            )),
            None => super::line(format_args!("rusty_alloc:     #{i} {a:#018x}\n")),
        }
    }
}
