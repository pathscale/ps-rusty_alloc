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

### Dependency boundary

The no_std implementation supports the threaded allocator without enabling its optional std feature.

### TLS implementation

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
