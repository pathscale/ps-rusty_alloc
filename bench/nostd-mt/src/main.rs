//! A `#![no_std]`, `#![no_main]` binary that proves ps-rusty_alloc works as the
//! global allocator of a multi-threaded program that links no Rust `std`.
//!
//! Every round spawns `THREADS` pthreads. Each churns `OPS` blocks of varying
//! size (some large, some grown through `realloc`), writes a pattern into each
//! and checks it when the block is freed. Every `HANDOFF`-th block goes to the
//! next thread, which frees it while its owner is still running: a
//! cross-thread free. When a thread ends it leaves `LEAVE` blocks behind, and
//! the next round frees them after their owner has exited: frees into an
//! abandoned heap. After the last round the main thread frees what is left.
//!
//! The summary on stdout is deterministic; `../nostd.ts` compares it byte for
//! byte with `../fixtures/nostd_mt.expected`. With the `debug` feature,
//! `nostd-mt doublefree` frees a block twice on a spawned thread and must be
//! stopped by the debug layer.

#![no_std]
#![no_main]
#![cfg_attr(panic = "unwind", feature(lang_items))]
#![cfg_attr(panic = "unwind", allow(internal_features))]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

#[global_allocator]
static GLOBAL: rusty_alloc::RustyAlloc = rusty_alloc::RustyAlloc;

const THREADS: usize = 16;
const ROUNDS: usize = 8;
const OPS: usize = 20_000;
const RING: usize = 64;
const HANDOFF: u64 = 7;
const LEAVE: usize = 16;
const LARGE_EVERY: u64 = 997;

struct Block {
    next: *mut Block,
    owner: usize,
    seq: usize,
    data: Vec<u64>,
}

/// Per thread slot: blocks pushed by the previous slot, freed by this one.
static MAILBOX: [AtomicPtr<Block>; THREADS] = [const { AtomicPtr::new(ptr::null_mut()) }; THREADS];
/// Per thread slot: blocks left by this round, freed by the next.
static LEFT: [AtomicPtr<Block>; THREADS] = [const { AtomicPtr::new(ptr::null_mut()) }; THREADS];

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static VALIDATED: AtomicUsize = AtomicUsize::new(0);
static WORDS: AtomicUsize = AtomicUsize::new(0);
static HANDED: AtomicUsize = AtomicUsize::new(0);
static LEFT_BEHIND: AtomicUsize = AtomicUsize::new(0);
static LARGE: AtomicUsize = AtomicUsize::new(0);
static CORRUPT: AtomicUsize = AtomicUsize::new(0);

fn word(owner: usize, seq: usize, k: usize) -> u64 {
    let x = ((owner as u64) << 40) ^ ((seq as u64) << 8) ^ (k as u64);
    x.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (x >> 29)
}

fn make(owner: usize, seq: usize, len: usize, grow: bool) -> Box<Block> {
    let data = if grow {
        // Grown one push at a time: the realloc path.
        let mut v = Vec::new();
        for k in 0..len {
            v.push(word(owner, seq, k));
        }
        v
    } else {
        let mut v = Vec::with_capacity(len);
        v.extend((0..len).map(|k| word(owner, seq, k)));
        v
    };
    ALLOCATED.fetch_add(1, Ordering::Relaxed);
    Box::new(Block {
        next: ptr::null_mut(),
        owner,
        seq,
        data,
    })
}

// By value: dropping the Box is the free under test.
#[allow(clippy::boxed_local)]
fn retire(b: Box<Block>) {
    let ok = b
        .data
        .iter()
        .enumerate()
        .all(|(k, &w)| w == word(b.owner, b.seq, k));
    if !ok {
        CORRUPT.fetch_add(1, Ordering::Relaxed);
    }
    VALIDATED.fetch_add(1, Ordering::Relaxed);
    WORDS.fetch_add(b.data.len(), Ordering::Relaxed);
}

/// Treiber push. Consumers take the whole stack with one swap, so there is no
/// pop and no ABA.
fn push(stack: &AtomicPtr<Block>, b: Box<Block>) {
    let p = Box::into_raw(b);
    let mut head = stack.load(Ordering::Relaxed);
    loop {
        // SAFETY: `p` is ours until the exchange publishes it.
        unsafe { (*p).next = head };
        match stack.compare_exchange_weak(head, p, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(h) => head = h,
        }
    }
}

fn drain(stack: &AtomicPtr<Block>) {
    let mut p = stack.swap(ptr::null_mut(), Ordering::Acquire);
    while !p.is_null() {
        // SAFETY: every node came from `Box::into_raw` in `push`, and the swap
        // made this thread its only owner.
        let b = unsafe { Box::from_raw(p) };
        p = b.next;
        retire(b);
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    let id = arg as usize;
    let me = id % THREADS;
    // The previous round's thread in this slot has exited: its blocks are
    // freed into an abandoned heap, or one this thread has reclaimed.
    drain(&LEFT[me]);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ ((id as u64 + 1) << 17));
    let mut ring: Vec<Option<Box<Block>>> = (0..RING).map(|_| None).collect();
    for seq in 0..OPS {
        let r = rng.next();
        let len = if r.is_multiple_of(LARGE_EVERY) {
            LARGE.fetch_add(1, Ordering::Relaxed);
            32_768 + (r >> 20) as usize % 524_288
        } else {
            1 + (r >> 8) as usize % 128
        };
        let b = make(id, seq, len, r & 4 == 0);
        if r.is_multiple_of(HANDOFF) {
            HANDED.fetch_add(1, Ordering::Relaxed);
            push(&MAILBOX[(me + 1) % THREADS], b);
        } else if let Some(old) = ring[(r >> 32) as usize % RING].replace(b) {
            retire(old);
        }
        if seq % 64 == 63 {
            drain(&MAILBOX[me]);
        }
    }
    let mut left = 0;
    for b in ring.iter_mut().filter_map(Option::take) {
        if left < LEAVE {
            push(&LEFT[me], b);
            left += 1;
            LEFT_BEHIND.fetch_add(1, Ordering::Relaxed);
        } else {
            retire(b);
        }
    }
    ptr::null_mut()
}

/// A fixed buffer for output: no allocation, no `std::io`.
struct Out {
    b: [u8; 1024],
    n: usize,
}

impl Out {
    const fn new() -> Self {
        Self { b: [0; 1024], n: 0 }
    }
    fn flush(&self, fd: c_int) {
        // SAFETY: writes our own initialised bytes.
        unsafe { libc::write(fd, self.b.as_ptr().cast(), self.n) };
    }
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let k = s.len().min(self.b.len() - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

fn spawn_join(f: extern "C" fn(*mut c_void) -> *mut c_void, first: usize, n: usize) {
    let mut tids = [const { MaybeUninit::<libc::pthread_t>::uninit() }; THREADS];
    for (i, t) in tids.iter_mut().enumerate().take(n) {
        // SAFETY: `t` is a live out-param; `f` has the pthread signature.
        let rc = unsafe {
            libc::pthread_create(t.as_mut_ptr(), ptr::null(), f, (first + i) as *mut c_void)
        };
        if rc != 0 {
            fail("pthread_create failed");
        }
    }
    for t in tids.iter().take(n) {
        // SAFETY: initialised by the successful create above, joined once.
        unsafe { libc::pthread_join(t.assume_init(), ptr::null_mut()) };
    }
}

fn fail(msg: &str) -> ! {
    let mut o = Out::new();
    let _ = writeln!(o, "nostd-mt: {msg}");
    o.flush(2);
    // SAFETY: no preconditions.
    unsafe { libc::abort() }
}

#[cfg(feature = "debug")]
fn double_free() -> c_int {
    extern "C" fn twice(_: *mut c_void) -> *mut c_void {
        let l = core::alloc::Layout::new::<[u64; 8]>();
        // Through the allocator itself, not `alloc::alloc`: the compiler may
        // delete an allocation nothing reads, frees included.
        // SAFETY: a valid non-zero layout; the second free is the bug under test.
        unsafe {
            use core::alloc::GlobalAlloc;
            let p = GLOBAL.alloc(l);
            GLOBAL.dealloc(p, l);
            GLOBAL.dealloc(p, l);
        }
        ptr::null_mut()
    }
    spawn_join(twice, 0, 1);
    fail("double free was not detected")
}

/// # Safety
/// Called by the C runtime with its `argc` and `argv`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    if argc > 1 {
        // SAFETY: argv[1] is a NUL-terminated C string when argc > 1.
        let arg = unsafe { core::ffi::CStr::from_ptr(*argv.add(1)) };
        #[cfg(feature = "debug")]
        if arg.to_bytes() == b"doublefree" {
            return double_free();
        }
        let _ = arg;
        fail("unknown argument");
    }
    for round in 0..ROUNDS {
        spawn_join(worker, round * THREADS, THREADS);
    }
    for i in 0..THREADS {
        drain(&MAILBOX[i]);
        drain(&LEFT[i]);
    }
    let allocated = ALLOCATED.load(Ordering::Relaxed);
    let validated = VALIDATED.load(Ordering::Relaxed);
    let corrupt = CORRUPT.load(Ordering::Relaxed);
    let ok = corrupt == 0 && validated == allocated;
    let mut o = Out::new();
    let _ = writeln!(o, "profile: no_std, multi-threaded");
    let _ = writeln!(
        o,
        "threads: {THREADS} per round, {ROUNDS} rounds, {} spawned",
        THREADS * ROUNDS
    );
    let _ = writeln!(o, "blocks_allocated: {allocated}");
    let _ = writeln!(o, "blocks_validated: {validated}");
    let _ = writeln!(
        o,
        "cross_thread_handoffs: {}",
        HANDED.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        o,
        "freed_after_owner_exit: {}",
        LEFT_BEHIND.load(Ordering::Relaxed)
    );
    let _ = writeln!(o, "large_blocks: {}", LARGE.load(Ordering::Relaxed));
    let _ = writeln!(o, "words_checked: {}", WORDS.load(Ordering::Relaxed));
    let _ = writeln!(o, "corrupt: {corrupt}");
    let _ = writeln!(o, "result: {}", if ok { "ok" } else { "FAIL" });
    o.flush(1);
    if ok { 0 } else { 1 }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut o = Out::new();
    let _ = writeln!(o, "nostd-mt: panic: {}", info.message());
    o.flush(2);
    // SAFETY: no preconditions.
    unsafe { libc::abort() }
}

/// The `panic = "unwind"` build needs a personality routine to link. This
/// binary never unwinds (its panic handler aborts, and the allocator aborts
/// rather than unwind), so a stub stands in for the one a real no_std unwind
/// runtime provides.
#[cfg(panic = "unwind")]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
