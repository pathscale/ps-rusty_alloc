//! rusty_alloc core — a pure-Rust remake of mimalloc v2.4.5.
//!
//! Plan of record: `docs/plans/rusty_alloc_v1.md`. Module map mirrors upstream C
//! files 1:1 (plan §6) so every diff-vs-oracle conversation has a shared map.
//!
//! Milestone status: **M4** — per-thread heaps, lock-free cross-thread frees
//! (the loom-modeled xthread/delayed protocol), thread-exit abandonment and
//! segment reclaim. No global lock anywhere on the alloc/free paths.
//!
//! std note: M4's TLS fast path uses `thread_local!` (const-init, !Drop — the
//! R1 spike measured it at atomic-load parity). Without `std` on unix the
//! thread-locals are pthread keys and the crate is fully multi-threaded; see
//! `docs/no_std.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

// ---------------------------------------------------------------------------
// P3 of `docs/plans/small-metal.md`: the three things the crate used `std` FOR.
//
// These live here, above the `mod` lines, because `macro_rules!` is TEXTUALLY
// scoped — a macro defined after a module is invisible inside it.
// ---------------------------------------------------------------------------

/// End the process immediately, without unwinding.
///
/// A double free, a corrupted free list and a failed TLS slot all reach this:
/// the allocator's contract is that it aborts rather than continues, and
/// unwinding out of `free` into a C caller is not an option (which is why the
/// release profile is `panic = "abort"`).
///
/// Without `std` on unix this is `libc::abort`, the same call upstream's
/// `_mi_error_message` path ends in: it raises `SIGABRT` and never unwinds,
/// so a `no_std` consumer built with `panic = "unwind"` gets the same
/// guarantee as one built with `panic = "abort"`.
///
/// On a target with no OS (`prim::fixed`, wasm without `std`) there is no
/// abort to call, so this panics and relies on the deliverable's panic
/// strategy. **Such a consumer MUST build with `panic = "abort"`**, as every
/// firmware profile already does, or an abort becomes an unwind and the
/// guarantee is gone.
#[cold]
#[inline(never)]
pub(crate) fn abort() -> ! {
    #[cfg(feature = "std")]
    {
        std::process::abort()
    }
    #[cfg(all(not(feature = "std"), unix))]
    // SAFETY: `abort` has no preconditions and does not return.
    unsafe {
        libc::abort()
    }
    #[cfg(all(not(feature = "std"), not(unix)))]
    {
        panic!("rusty_alloc: abort (build a no_std consumer with panic = \"abort\")")
    }
}

/// A `thread_local!` that survives `no_std`. Three arms, by build:
///
/// * **`std`**: expands to `std::thread_local!` unchanged, so the shipped
///   build keeps the const-init, `!Drop`, initial-exec fast path M10c
///   measured.
/// * **`no_std` on unix** (macOS, Linux, the BSDs): a [`key_local::KeyLocal`],
///   one pthread key per variable. Sound with any number of threads; no
///   `std`, no allocation, no nightly feature. This is the multi-threaded
///   `no_std` profile (`docs/no_std.md`).
/// * **single thread**: a plain `static` ([`SingleThreadCell`]). Taken by a
///   `no_std` build that opts in with `--cfg ra_single_threaded` (required
///   where there is no OS, optional on unix), and by `wasm32-unknown-unknown`
///   without the atomics proposal, which has exactly one thread.
///
/// The single-thread arm is not a compromise but the point of that profile:
/// one heap, no TLS lookup at all, a SHORTER fast path than the threaded one.
/// On `wasm32-unknown-unknown` a `std::thread_local!` would still link lazy
/// initialisation, destructor registration and the "accessed during or after
/// destruction" panic, none of which can ever run. `target_feature =
/// "atomics"` is the precise switch: it is what `-C target-feature=+atomics`
/// sets to build wasm WITH threads, and such a build keeps real TLS.
///
/// Every variable is a `Cell` of one word (`bool`, `usize` or a pointer),
/// accessed only as `.with(|c| c.get())` and `.with(|c| c.set(v))`, which all
/// three arms provide.
macro_rules! ra_thread_local {
    ($($(#[$m:meta])* static $N:ident: Cell<$T:ty> = const { Cell::new($init:expr) };)*) => {
        #[cfg(all(feature = "std", not(all(target_arch = "wasm32", target_os = "unknown", not(target_feature = "atomics")))))]
        std::thread_local! {
            $($(#[$m])* static $N: Cell<$T> = const { Cell::new($init) };)*
        }
        $(
            #[cfg(all(not(feature = "std"), unix, not(ra_single_threaded)))]
            $(#[$m])*
            static $N: $crate::key_local::KeyLocal<$T> =
                $crate::key_local::KeyLocal::new(Cell::new($init));
        )*
        $(
            #[cfg(any(all(not(feature = "std"), any(not(unix), ra_single_threaded)), all(target_arch = "wasm32", target_os = "unknown", not(target_feature = "atomics"))))]
            $(#[$m])*
            static $N: $crate::SingleThreadCell<Cell<$T>> =
                $crate::SingleThreadCell::new(Cell::new($init));
        )*
    };
}

// A `no_std` build on a target with no OS asserts single-threadedness, so it
// must be OPTED INTO.
//
// Three things are sound there only because there is exactly one thread:
// [`SingleThreadCell`]'s `unsafe impl Sync`, `prim::fixed`'s constant thread
// id and never-contended spin lock, and `options`' 64-bit atomics split into
// `AtomicU32` halves where the target has no 64-bit atomics. None of them is
// checkable at compile time, and none of them fails loudly if the assumption
// breaks: they corrupt quietly.
//
// A doc comment is not a guard. Such a build therefore requires
// `--cfg ra_single_threaded`, so that using this allocator on a bare-metal
// target is a decision somebody wrote down rather than a default they
// inherited:
//
// ```text
// RUSTFLAGS="--cfg ra_single_threaded" cargo build --no-default-features
// ```
//
// On unix none of the three applies without that cfg: thread-locals are
// pthread keys ([`key_local`]), the thread id is the thread pointer
// (`init::thread_id`), the locks are the hosted ones, and the 64-bit atomics
// are native (and refused below where they are not). So a `no_std` build on
// unix is multi-threaded by default and needs no cfg; `ra_single_threaded`
// there remains an explicit opt-in to the single-`static` thread-locals.
#[cfg(all(not(feature = "std"), not(unix), not(ra_single_threaded), not(doc)))]
compile_error!(
    "rusty_alloc's no_std build on a target without an OS assumes a SINGLE \
     THREAD (SingleThreadCell's `unsafe impl Sync`, prim::fixed's constant \
     thread id and spin lock, and options' split 64-bit atomics all depend on \
     it). Confirm that is true of your target and opt in with \
     `--cfg ra_single_threaded`, or enable the `std` feature. no_std on unix \
     is multi-threaded and needs neither. See docs/no_std.md."
);

// Internal assertions. With `std` these are `assert!` and `debug_assert!`,
// token for token, so a std build is unchanged. Without `std` a failed check
// reports and aborts through [`fatal`] instead of panicking: upstream's
// `mi_assert` ends in `abort()` too, and a panic inside the allocator would
// otherwise unwind through its half-updated state into a consumer built with
// `panic = "unwind"`.

/// `assert!`, aborting rather than panicking without `std`.
macro_rules! ra_assert {
    ($c:expr $(,)?) => {
        ra_assert!($c, "assertion failed: {}", stringify!($c))
    };
    ($c:expr, $($arg:tt)+) => {{
        #[cfg(feature = "std")]
        {
            assert!($c, $($arg)+);
        }
        #[cfg(not(feature = "std"))]
        {
            if !$c {
                $crate::fatal(file!(), line!(), format_args!($($arg)+));
            }
        }
    }};
}

/// `assert_eq!`, aborting rather than panicking without `std`.
#[allow(unused_macros)] // only debug_checks and no_std builds use it
macro_rules! ra_assert_eq {
    ($a:expr, $b:expr $(,)?) => {
        ra_assert_eq!($a, $b, "{} == {}", stringify!($a), stringify!($b))
    };
    ($a:expr, $b:expr, $($arg:tt)+) => {{
        #[cfg(feature = "std")]
        {
            assert_eq!($a, $b, $($arg)+);
        }
        #[cfg(not(feature = "std"))]
        {
            match (&$a, &$b) {
                (l, r) => {
                    if !(*l == *r) {
                        $crate::fatal(
                            file!(),
                            line!(),
                            format_args!("{} (left: {:?}, right: {:?})", format_args!($($arg)+), l, r),
                        );
                    }
                }
            }
        }
    }};
}

/// `assert_ne!`, aborting rather than panicking without `std`.
#[allow(unused_macros)] // only no_std builds use it
macro_rules! ra_assert_ne {
    ($a:expr, $b:expr $(,)?) => {
        ra_assert_ne!($a, $b, "{} != {}", stringify!($a), stringify!($b))
    };
    ($a:expr, $b:expr, $($arg:tt)+) => {{
        #[cfg(feature = "std")]
        {
            assert_ne!($a, $b, $($arg)+);
        }
        #[cfg(not(feature = "std"))]
        {
            match (&$a, &$b) {
                (l, r) => {
                    if *l == *r {
                        $crate::fatal(
                            file!(),
                            line!(),
                            format_args!("{} (both: {:?})", format_args!($($arg)+), l),
                        );
                    }
                }
            }
        }
    }};
}

/// `debug_assert!`: [`ra_assert!`] in builds with debug assertions.
macro_rules! ra_debug_assert {
    ($($t:tt)+) => {{
        #[cfg(feature = "std")]
        {
            debug_assert!($($t)+);
        }
        #[cfg(not(feature = "std"))]
        {
            if cfg!(debug_assertions) {
                ra_assert!($($t)+);
            }
        }
    }};
}

/// `debug_assert_eq!`: [`ra_assert_eq!`] in builds with debug assertions.
macro_rules! ra_debug_assert_eq {
    ($($t:tt)+) => {{
        #[cfg(feature = "std")]
        {
            debug_assert_eq!($($t)+);
        }
        #[cfg(not(feature = "std"))]
        {
            if cfg!(debug_assertions) {
                ra_assert_eq!($($t)+);
            }
        }
    }};
}

/// `debug_assert_ne!`: [`ra_assert_ne!`] in builds with debug assertions.
macro_rules! ra_debug_assert_ne {
    ($($t:tt)+) => {{
        #[cfg(feature = "std")]
        {
            debug_assert_ne!($($t)+);
        }
        #[cfg(not(feature = "std"))]
        {
            if cfg!(debug_assertions) {
                ra_assert_ne!($($t)+);
            }
        }
    }};
}

/// A failed internal check without `std`: one line to stderr (or the output
/// hook), then [`abort`]. Formats into a stack buffer; never allocates and
/// never unwinds.
#[cfg(not(feature = "std"))]
#[cold]
#[inline(never)]
pub(crate) fn fatal(file: &str, line: u32, msg: core::fmt::Arguments<'_>) -> ! {
    struct Buf {
        b: [u8; 512],
        n: usize,
    }
    impl core::fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let room = self.b.len() - self.n;
            let mut k = s.len().min(room);
            while !s.is_char_boundary(k) {
                k -= 1;
            }
            self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
            self.n += k;
            Ok(())
        }
    }
    let mut b = Buf { b: [0; 512], n: 0 };
    let _ = core::fmt::write(
        &mut b,
        format_args!("rusty_alloc: internal check failed at {file}:{line}: {msg}\n"),
    );
    options::out_fmt(
        core::str::from_utf8(&b.b[..b.n]).unwrap_or("rusty_alloc: internal check failed\n"),
    );
    abort()
}

/// Abort if dropped: armed around each `GlobalAlloc` call without `std`, so
/// that a panic raised anywhere inside the allocator (a bounds check, an
/// overflow check in a debug build, a hook) can never unwind out of it into a
/// consumer built with `panic = "unwind"`. The normal return `forget`s it.
/// With `panic = "abort"` there are no unwind edges, so it compiles to
/// nothing.
#[cfg(not(feature = "std"))]
pub(crate) struct NoUnwind;

#[cfg(not(feature = "std"))]
impl Drop for NoUnwind {
    #[cold]
    fn drop(&mut self) {
        abort()
    }
}

/// The single-thread arm of [`ra_thread_local!`]: a `static` with a `.with()`.
#[cfg(any(
    all(not(feature = "std"), any(not(unix), ra_single_threaded)),
    all(
        target_arch = "wasm32",
        target_os = "unknown",
        not(target_feature = "atomics")
    )
))]
pub(crate) struct SingleThreadCell<T>(T);

#[cfg(any(
    all(not(feature = "std"), any(not(unix), ra_single_threaded)),
    all(
        target_arch = "wasm32",
        target_os = "unknown",
        not(target_feature = "atomics")
    )
))]
// SAFETY: only ever constructed by `ra_thread_local!`, and only on a build
// that is single-threaded by declaration: a `no_std` build that opted in with
// `--cfg ra_single_threaded` (required without an OS, a choice on unix), or
// `wasm32-unknown-unknown` without the atomics proposal, where `prim/wasm.rs`
// has assumed one thread since it was written. The same standing assumption
// as `prim::fixed` (constant thread id, TLS destructors that never fire, a
// spin lock that never contends). With one thread there is no other
// referent, so shared access cannot race. A build on a target that grows
// threads must revisit this type FIRST, which is what the
// `target_feature = "atomics"` half of the condition above is there to catch.
unsafe impl<T> Sync for SingleThreadCell<T> {}

#[cfg(any(
    all(not(feature = "std"), any(not(unix), ra_single_threaded)),
    all(
        target_arch = "wasm32",
        target_os = "unknown",
        not(target_feature = "atomics")
    )
))]
impl<T> SingleThreadCell<T> {
    pub(crate) const fn new(v: T) -> Self {
        Self(v)
    }
    /// Mirrors `LocalKey::with`, which is the only accessor the crate uses.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&self.0)
    }
}

/// `true` exactly when this build has ONE thread for the life of the program,
/// so that `prim::thread_id()` is a compile-time constant.
///
/// That is two targets: the bare-metal `prim::fixed` backend, which the crate
/// refuses to build without `--cfg ra_single_threaded`, and
/// `wasm32-unknown-unknown` without the atomics proposal, where
/// `prim/wasm.rs` has returned one id since it was written. It is **not**
/// `ra_single_threaded` alone: on a hosted target that cfg only unlocks the
/// fixed backend's unit tests, the OS prim still hands out real thread ids,
/// and the suite spawns threads.
///
/// What it buys: the cross-thread machinery — abandoning a segment when a
/// thread ends, adopting one back, the delayed-free list a remote free lands
/// on — is code that CANNOT execute here, and `ra_single_threaded` used to
/// prune none of it. The linker kept `adopt_segment` (1,154 B) and
/// `drain_delayed` (995 B) in an ESP32-S3 firmware that had asserted a single
/// context. Each consumer of this constant folds one branch so that code
/// becomes provably unreachable and the linker drops it; where a hosted build
/// would have compared thread ids, it still does
/// (`docs/plans/finished/firmware-code-size.md`, lever 1).
///
/// A `const`, not a `cfg`, so every site reads as `if ONE_THREAD` and a host
/// build compiles both arms — the pruned code is type-checked and unit-tested
/// everywhere, and only linked where it can run.
pub(crate) const ONE_THREAD: bool = cfg!(any(
    all(
        ra_single_threaded,
        not(miri),
        not(windows),
        not(unix),
        not(target_arch = "wasm32")
    ),
    all(
        target_arch = "wasm32",
        target_os = "unknown",
        not(target_feature = "atomics")
    )
));

/// `true` where `prim::protect` can actually protect a page: the OS backends
/// and the miri mock.
///
/// Guarded objects are a huge segment whose trailing page is `PROT_NONE`, so
/// an overflow faults on the first byte past the object. `prim::fixed` and
/// `prim::wasm` have no MMU and return `Err` from `protect`; there the
/// sampler used to run anyway and hand out a dedicated segment with an
/// UNPROTECTED trailing page — the whole cost of a guarded object and none of
/// the protection — while `try_guarded` (1,641 B) and the ChaCha block it
/// samples with (725 B) stayed in an ESP32-S3 image with `secure` off. The
/// runtime gate (`guarded_rate`) could not remove them: it is a field, and a
/// linker cannot prove a field is zero. Every consumer folds on this constant
/// instead (`docs/plans/finished/firmware-code-size.md`, lever 3).
pub(crate) const GUARD_PAGES: bool = cfg!(any(unix, windows, miri));

/// Whether anything draws from a heap's CSPRNG: `secure` free-list keys, or
/// guarded sampling. A build with neither never seeds it.
pub(crate) const RNG_USED: bool = GUARD_PAGES || cfg!(feature = "secure");

/// `true` where the prim is `prim::fixed`: one region, handed over once, with
/// no OS behind it. The arena layer folds on this constant — there is nothing
/// to reserve from, and a range managed from outside would carve its chunks
/// on absolute segment boundaries, which are not this target's strides
/// ([`REGION_STRIDES`]).
pub(crate) const FIXED_REGION: bool = cfg!(all(
    not(miri),
    not(windows),
    not(unix),
    not(target_arch = "wasm32")
));

/// `true` where segments are carved at `SEGMENT_SIZE` strides FROM THE
/// REGION'S BASE rather than from address zero: [`FIXED_REGION`], unless
/// `--cfg ra_aligned_region` asks for the hosted mask instead.
///
/// A hosted allocator recovers a block's segment by masking the pointer,
/// which is why its segments — and any region holding them — must be
/// `SEGMENT_SIZE`-aligned. On a fixed RAM map that alignment is paid as the
/// gap the linker leaves before the aligned static: 24,148 bytes on the
/// ESP32-S3 firmware that measured it, up to `SEGMENT_SIZE - 1` in general,
/// and charged to no section (`docs/plans/finished/region-alignment-dissolve.md`).
/// The backend already holds the region's base, so `segment_of` masks the
/// OFFSET from it instead, every alignment the backend serves is measured
/// from that base, and a region needs only `MAX_ALIGN_SIZE` alignment. wasm
/// dissolved the same constraint with a slice table for the same reason —
/// its scarce resource is space — and the hosted arms keep the mask, byte
/// for byte.
///
/// The price is on `segment_of`, and it is recorded there: the free path
/// grows from 36 to 39 instructions on the ESP32-S3 — a load of the base
/// and two subtractions where the mask was a literal and an `and` — which
/// the board prices at 9–17 ns per alloc/free pair (1.5–3 %) on its
/// small-object benches. A firmware that would rather have those than the
/// RAM sets `--cfg ra_aligned_region`: the mask is back,
/// `prim::fixed::Region` is segment-aligned again, and so is the gap.
pub(crate) const REGION_STRIDES: bool = FIXED_REGION && !cfg!(ra_aligned_region);

/// `true` where memory is ONE region the linker handed over AND there is one
/// thread to serve from it: [`FIXED_REGION`] under `--cfg ra_single_threaded`,
/// i.e. the first arm of [`ONE_THREAD`].
///
/// A hosted allocator manages many OS ranges, and four of its structures
/// exist only for that: **arenas** (reserved OS ranges carved into segment
/// chunks), the **segment map** (which of the address space's ranges are
/// ours), a **runtime option table** (read from the environment, settable at
/// run time), and a **RAM-resident heap sentinel** (a template every new
/// thread's heap is copied from). On a chip there is no OS to reserve from,
/// exactly one range whose bounds the backend already holds, no environment
/// and no tuner, and one heap for the life of the program. Each of the four
/// folds on this constant to what a single region needs — nothing, a bounds
/// check, the compiled-in defaults, a copy from flash — and the linker drops
/// the rest (`docs/plans/finished/firmware-what-is-left.md` §3 and §7).
///
/// What a firmware loses by it, stated rather than hidden: `options::set` is
/// a no-op there, and — on [`FIXED_REGION`], which this implies —
/// `arena::reserve_*` and `manage_os_memory_ex` return `Err`. Neither had a
/// working meaning on a chip before — an arena carved from the one region
/// only added an indirection to the same bytes, and an option set at run
/// time on a target with no environment was already the exception rather
/// than the rule.
pub(crate) const ONE_REGION: bool = FIXED_REGION && cfg!(ra_single_threaded);

pub mod alloc;
pub mod arena;
pub mod bins;
#[cfg(feature = "debug_checks")]
pub mod debug;
pub mod global;
pub mod heap;
pub mod init;
/// Thread-locals as pthread keys: the multi-threaded `no_std` profile on unix.
#[cfg(all(not(feature = "std"), unix, not(ra_single_threaded)))]
mod key_local;
pub mod options;
pub mod os;
pub mod page;
pub mod prim;
/// Kani proof harnesses (H-30). `cfg(kani)`-only: absent from every shipped
/// build, so it costs the crate nothing.
#[cfg(kani)]
mod proofs;
pub mod random;
pub mod segment;
pub mod segment_map;
// Wired into the segment paths only on wasm (F2, docs/plans/segment-tax.md);
// native builds compile it for its unit tests, so its items are "unused"
// there by design.
#[cfg_attr(not(all(target_arch = "wasm32", not(miri))), allow(dead_code))]
pub(crate) mod slice_pool;
pub mod stats;
pub mod types;

pub use bins::good_size;
pub use global::RustyAlloc;

/// Rebuild a pointer at `addr` keeping `p`'s provenance. Used wherever an
/// address round-trips through an integer (atomic words, encoded links) — the
/// thrice-learned law: provenance and reachability follow POINTERS.
#[inline]
pub fn ptr_with_addr<T>(p: *mut T, addr: usize) -> *mut T {
    p.with_addr(addr)
}

/// Our own semantic version, from the crate manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The mimalloc version we are API- and ABI-compatible with, in mimalloc's
/// encoding (major·10⁴ + minor·10² + patch): v2.4.5. `mi_version()` reports this.
pub const MI_COMPAT_VERSION: i32 = 20405;

/// mimalloc-encoded compat version, as reported by the C ABI `mi_version()`.
#[inline]
pub const fn version() -> i32 {
    MI_COMPAT_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_v2_4_5_compat() {
        assert_eq!(version(), 20405);
    }
}
