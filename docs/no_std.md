# no_std, multi-threaded

Since 2.3.2, ps-rusty_alloc runs as the `#[global_allocator]` of a `#![no_std]`
binary with any number of threads on unix (macOS and Linux, glibc or musl),
and the binary links no Rust `std`. No `--cfg` is needed. It builds with
`panic = "abort"` and with `panic = "unwind"`.

## Use

```toml
[dependencies]
ps-rusty_alloc = { version = "2.3.2", default-features = false }

# Or with the debug layer (docs/debugging.md):
# ps-rusty_alloc = { version = "2.3.2", default-features = false, features = ["debug_checks"] }
```

The library is `rusty_alloc` under either name:

```rust
#![no_std]

extern crate alloc;

#[global_allocator]
static GLOBAL: rusty_alloc::RustyAlloc = rusty_alloc::RustyAlloc;
```

There is nothing to initialise and nothing to call at thread exit.

What it needs from the platform: threads that are pthreads (`pthread_create`, or
anything built on it), and the C library the binary links anyway
(libSystem on macOS, libc on Linux). The calls it makes are the ones upstream
mimalloc makes: `mmap`, `munmap`, `madvise`, `mprotect`, `sysconf`,
`clock_gettime`, `getenv`, `getentropy`, `write`, `abort`, `pthread_self`,
`pthread_key_create`, `pthread_key_delete`, `pthread_setspecific` and, off
Apple, `pthread_getspecific`. They come from the `libc` crate with
`default-features = false`, which is declarations only.

## How the threaded parts work without std

| Piece | With `std` | Without `std`, on unix |
|---|---|---|
| Thread-locals (heap pointer, backing heap, subprocess tag, re-entrancy guards) | `std::thread_local!` | `KeyLocal` (`src/key_local.rs`): one pthread key per variable |
| Heap pointer on x86-64 Linux | initial-exec ELF TLS slot (`global_asm!`) | the same slot |
| Thread id | the thread pointer register | the same register |
| Thread exit | pthread key destructor abandons the heap | the same destructor |
| 64-bit option atomics | `AtomicI64` / `AtomicU64` | the same; a target without them does not build |
| Heap CSPRNG seed | `/dev/urandom` | `getentropy` |
| `RUSTY_ALLOC_*` / `MIMALLOC_*` options | read from the environment | the same |
| Diagnostics with no output hook | stderr | `write(2)` to fd 2 |
| Abort | `std::process::abort` | `libc::abort` |

`KeyLocal` stores the word in the key's slot, XOR its initial value, so a
thread that has never set it reads the initial value (the empty-heap sentinel
for the heap pointer) without a first-touch branch, and nothing is allocated
or freed per thread. A key is created on the first `set` anywhere and
published with one compare-exchange; a thread that loses the race deletes its
own key, so nothing waits. On Apple targets a read skips the call and loads
`tsd[key]` through the thread pointer (`tpidrro_el0` on arm64, `gs` on x86-64),
which is what libpthread's own `pthread_getspecific` does and what mimalloc's
`mi_prim_tls_slot` reads; builds with debug assertions compare every such read
with the call. The crate creates at most eight keys.

Everything else, the lock-free cross-thread free protocol, segment
abandonment and reclaim, arenas, the segment map, is the code the `std` build
runs. The one lock on a shared list (abandoned segments) is the same
compare-and-swap lock with or without `std`.

## panic = "unwind"

- The crate needs no `eh_personality` and no `std` panic machinery. Built with
  `panic = "unwind"`, the proof binary links no symbol from `std` or its panic
  runtime (below); the personality routine is the consumer's.
- Internal checks never panic without `std`. Debug assertions, the
  `debug_checks` free checks and segment validation print one line and call
  `libc::abort`, as upstream's `mi_assert` does. Running out of pthread keys
  aborts too.
- Every `RustyAlloc` method runs under an abort-on-unwind guard. A panic raised
  inside the allocator anyway (a compiler-inserted bounds or overflow check, or
  a registered output hook, error hook or `debug::set_handler` handler that
  panics) reaches your panic handler and then aborts at the allocator boundary;
  it never unwinds through half-updated allocator state into your frames. With
  `panic = "abort"` the guard has no unwind edge and compiles to nothing.
- A panic in your code between an allocation and its free is fine: each
  allocator call has completed (or aborted) before control returns to you, so
  unwinding frees whatever your destructors free, through the same paths.
- The guard is on `RustyAlloc`. The raw API (`rusty_alloc::alloc::malloc` and
  friends) has no guard; called directly from code that may unwind through it,
  it relies on the abort-on-check behaviour above.

## Single-threaded builds

`--cfg ra_single_threaded` stays as an explicit opt-in. On unix it turns the
thread-locals into plain statics: a shorter fast path, sound only if exactly
one thread ever touches the allocator. On a target with no OS (`prim::fixed`)
it is still required, because the constant thread id, the uncontended spin
lock and the split 64-bit atomics there are sound only with one thread. A
`no_std` build on Windows also still needs it, or the `std` feature.

## Proof

`bench/nostd-mt` is a `#![no_std]` `#![no_main]` binary with `RustyAlloc` as its
global allocator. Each run spawns 16 pthreads per round for 8 rounds (128
threads), which churn 2,560,000 blocks between 8 bytes and about 4 MiB, some
grown through `realloc`. Each block carries a pattern checked word for word
when it is freed. 365,919 blocks go to the next thread and are freed while
their owner is still running (cross-thread frees); 2,048 are left behind when
a thread exits and freed by the next round (frees into an abandoned or
reclaimed heap). The summary is compared byte for byte with
`bench/fixtures/nostd_mt.expected`.

`bun nostd.ts` in `bench/` builds it four ways and runs each 50 times:

| Build | Runs matching the fixture | ms per run (M4 Max) |
|---|---:|---:|
| release, `panic = "abort"` | 50/50 | 450 |
| release with debug assertions and overflow checks | 50/50 | 525 |
| release with `debug_checks` | 50/50 | 709 |
| release, `panic = "unwind"` (nightly, for the `eh_personality` lang item) | 50/50 | 457 |

Each binary passes `bench/nostd-nm.ts`, which runs `nm` over every symbol and
fails on anything from `std` (`std::`, `_ZN3std`, a v0 `3std` crate segment,
`__rust_std`) or its panic runtime (`panic_unwind`, `__rust_start_panic`). The
std benchmark binary, checked the same way as a control, fails with 410 such
symbols. The `debug_checks` build also runs `nostd-mt doublefree`, which frees a
block twice on a spawned thread: it prints
`rusty_alloc: error: double free of block ...` to stderr and dies with
`SIGABRT`.

The `panic = "unwind"` build defines a stub `eh_personality`, which needs
nightly: stable Rust cannot define the lang item. The
binary never unwinds (its panic handler aborts), so the stub is never called.
A real consumer supplies its own personality and unwinder.

## Cost

The `std` build is unchanged: the benchmark binary's `__text`, `__const` and
`__cstring` sections are byte-identical to 2.3.1's, and the only data that
differs is two line numbers in panic locations. Instruction counts (minimum
of 7 interleaved runs) are within noise: tasks 4.670 G vs 4.677 G, small
1.286 G vs 1.286 G, realistic 0.967 G vs 0.967 G.

Without `std`, reaching the heap costs a key-variable load and a branch
before the thread-local read. On Apple targets the read itself is one
register read and one load; on x86-64 Linux the heap pointer is the same
initial-exec slot as with `std`; elsewhere (aarch64 Linux, the BSDs) it is a
`pthread_getspecific` call.

## Limitations

- The runtime proof ran on macOS (aarch64). Linux x86-64 (glibc) and aarch64
  (musl) were type-checked and linted, not run; `ci.yml` (manual) builds and
  runs `nostd-mt` on its Linux runner.
- Threads must be pthreads. A thread made with a raw `clone` has no TSD and no
  exit destructor.
- `stats::process_info` reads zeros without `std` (no `/proc` reader), and
  `options::print` and `arena::arenas_print` stay `std`-only because they
  format into owned strings.
- Keys are never deleted: at most eight per process, for the life of the
  process.
