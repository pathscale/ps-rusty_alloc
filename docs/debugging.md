# Debugging and visibility

## Already in upstream 2.2.6

- Double free: detected and aborted in every build, on the owner and the
  cross-thread path (`tests/double_free.rs`).
- Foreign pointer on `free`: detected under `debug_assertions` or the
  `debug_checks` feature (`src/alloc.rs`, `tests/foreign_free.rs`).
- `debug_checks`: full invariant validation (list walks, span tiling, page canaries).
- `secure`: encrypted free-list links with a same-segment bound on every decoded link.
- `blockmap`: per-page block-liveness map; catches a forged link that lands on a live block.
- `linkcheck`: extra free-list link checks in `src/page.rs`.
- Guarded objects: options `guarded_sample_rate` and `guarded_sample_seed`,
  `Heap::guarded_set_sample_rate`, `Heap::guarded_set_size_bound`.
- `Heap::visit_blocks`: walks every live area of a heap and optionally every
  allocated block; the base for a leak report.
- `stats`: counters in debug builds (`stats::print_process`, `stats::merged`,
  `stats::process_info`); compiled out of release.
- `arena::arenas_print` and `init::ABANDONED_COUNT`.
- `profile`: declared in `Cargo.toml`; nothing in the 2.2.6 sources is gated on it.

## Added in this fork

The library API is [Debug mode](#debug-mode-debug_checks) below, and
[`RustyAlloc`](../src/global.rs), the `GlobalAlloc` it hangs off. The bench
harness has these hooks in `bench/src/main.rs`, read from the environment and
off unless set:

- `BENCH_WAVE_RSS=1` (commit `a7a850c`), `workers` workload only. After each
  wave it prints to stderr `wave=<n> maxrss_mb=<peak RSS so far, getrusage>`;
  in the `rusty_alloc` build it adds `abandoned_segments=<init::ABANDONED_COUNT>`
  and the `arena::arenas_print` line. This is what showed RSS climbing per wave
  with zero abandoned segments.

  ```sh
  BENCH_WAVE_RSS=1 bench/bin/rusty_alloc workers 16
  ```

- `BENCH_PROFILE_SLEEP_MS=<ms>` (commit `143c0bb`), any workload. Sleeps
  before the timed work so a sampler can attach.

  ```sh
  BENCH_PROFILE_SLEEP_MS=300 bench/bin/rusty_alloc xthread 1 & sample $! 5 -f out.txt
  ```

- `BENCH_SEG_PROBE=1`, `rusty_alloc` build, any workload. At the end of the
  run (and on the last `realistic` iteration, before its maps drop) it dumps
  every heap's segments: high-water slice, free spans, live pages by kind
  (small `s<used>/<reserved>`, medium `m<slices>:<used>/<reserved>`, large
  `L<slices>`, free `F<slices>`), each prefixed by its resident KiB from
  `mincore`, plus resident totals for free, large, small and medium spans.
  `BENCH_SEG_PROBE_HW=1` prints the high-water slice and peak RSS after every
  `realistic` iteration. This is what showed the `realistic` fragmentation.

  ```sh
  BENCH_SEG_PROBE=1 bench/bin/rusty_alloc realistic 1
  ```

- `hugepark` workload with `BENCH_WAVE_RSS=1`: prints the parked-chunk
  counter against the number of chunks actually parked
  ([resident-budget.md](resident-budget.md)).

Library side: `arena::parked_resident()` returns that pair. The resident
budget's state is kept in two arena bitmaps (`parked`, `decommitted`); see
[resident-budget.md](resident-budget.md).


## Debug mode (`debug_checks`)

It works the same in a `no_std` multi-threaded build on unix: reports go to
fd 2 through `write(2)` when no output hook is registered, and the default
handler ends in `libc::abort` ([no_std.md](no_std.md)).

One allocator for both modes. `debug_checks` (upstream's feature, extended
here rather than a new name) switches [`RustyAlloc`](../src/global.rs) to a
checked implementation in [`src/debug.rs`](../src/debug.rs); without it that
module does not exist and the fast path is unchanged (see Cost below). The
feature also keeps upstream's own invariant checks in the core.

```toml
[features]
debug = ["rusty_alloc/debug_checks"]
```

### What is checked

Every block from `RustyAlloc` carries a 32-byte header (requested size,
alignment, allocation number, state, and a checksum keyed by the block
address) and an 8-byte canary after it.

| finding | when | `ViolationKind` |
|---|---|---|
| pointer outside every segment we own (another allocator's block, an FFI mismatch) | `dealloc`, `realloc` | `ForeignPointer` |
| our block, but from the raw `alloc::malloc` / `mi_malloc` API (C side of an FFI boundary) | `dealloc`, `realloc` | `NotFromGlobalAlloc` |
| pointer into the middle of a block | `dealloc`, `realloc` | `InteriorPointer` |
| block already freed (still in quarantine; after that the core's own double-free abort) | `dealloc`, `realloc` | `DoubleFree` |
| `Layout` size or alignment differs from the allocation's | `dealloc`, `realloc` | `SizeMismatch`, `AlignMismatch` |
| canary after the block overwritten | `dealloc`, `realloc` | `BufferOverflow` |
| header checksum fails (underflow or wild write) | `dealloc`, quarantine eviction | `CorruptHeader` |
| freed block's poison changed (write after free) | quarantine eviction, `flush_quarantine` | `UseAfterFree` |
| block returned without the requested alignment (allocator bug) | `alloc` | `Misaligned` |

Fills, mimalloc's values: fresh blocks `0xD0` (`UNINIT_BYTE`, not for
`alloc_zeroed`), freed blocks `0xDF` (`FREED_BYTE`), canary `0xDE`
(`CANARY_BYTE`). `realloc` always moves, so a stale pointer to the old block
is caught as a write after free.

Freed blocks go into a per-thread FIFO quarantine and are released, after
their poison and canary are checked, once the quarantine holds more than its
budget. Blocks larger than the budget skip it. A thread's quarantine is
emptied, and checked, when the thread exits. No timers and no sweeps: every
check runs on a free, an eviction or an explicit call.

### API (`rusty_alloc::debug`)

- `set_handler(Option<Handler>) -> Option<Handler>`, `Handler = fn(&Violation)`.
  Default (`None`): `default_handler`, which prints one line,
  `rusty_alloc: error: double free of block 0x... (size 40, align 8)`,
  through the output hook (`options::register_output`, else stderr) and
  aborts. A handler that returns makes the allocator continue: a free it cannot
  do safely (foreign, raw-API, interior, corrupt header, double free) is
  skipped and the block leaks; a free of a known block (layout mismatch,
  overflow, write after free) completes. `Violation` is `Copy` and
  `Display`; `print_violation` prints one.
- `leak_report(&mut dyn FnMut(&Leak)) -> LeakSummary`: every live block of
  the calling thread's heap and of segments abandoned by exited threads, built
  on `Heap::visit_blocks` (`mi_heap_visit_blocks`). `Leak` has the pointer,
  size, alignment and allocation number. `alloc_seq()` returns the calling
  thread's allocation number, a mark: blocks with `seq` above it came later.
  `print_leaks(max)` prints a summary and the first `max`.
- `stats() -> DebugStats`: per size class (the bin the performance build
  would use) allocations, frees, live bytes, peak bytes and rounding waste;
  totals; realloc patterns (grows, shrinks, small grows of at most
  max(16 B, 1/8), ping-pongs that undo the previous realloc); huge allocations
  above `LARGE_OBJ_SIZE_MAX`, their frees and same-size repeats (map, unmap,
  map again); chunk churn (claims from arenas, fresh OS reserves, chunks
  parked under the resident budget, chunks purged past it).
- `fragmentation_report() -> Fragmentation`: process RSS and peak, live
  bytes and waste, and for the calling thread's heap: pages, committed bytes,
  bytes in use, pages under a quarter used and the free bytes they hold,
  quarantine bytes; parked chunks process-wide.
- `print_stats()`, `print_report()` (leaks, then stats), in the spirit of
  `mi_stats_print`. With `show_stats` on (`RUSTY_ALLOC_SHOW_STATS=1` or
  `MIMALLOC_SHOW_STATS=1`) `print_report` runs at process exit.
- `set_quarantine_limit(bytes)`, `quarantine_limit()`, `flush_quarantine()`.
- `UNINIT_BYTE`, `FREED_BYTE`, `CANARY_BYTE`, `QUARANTINE_DEFAULT`.

Counters live in each thread's heap box as plain cells, not atomics. A
report merges them on demand under the heap registry lock (live threads read
as a racy snapshot, as upstream's `stats::merged` does); an exiting thread
folds its counters into a retired total at teardown. Byte counts are signed:
a cross-thread free lowers the freeing thread's count and only the merged sum
is exact. Merged peaks are the largest per-thread peak.

### Defaults (all changeable)

| what | default | change with |
|---|---|---|
| on a violation | print one line and abort | `set_handler` |
| quarantine budget | 1 MiB per thread | `set_quarantine_limit`, `RUSTY_ALLOC_DEBUG_QUARANTINE_KIB` |
| report at exit | off | `show_stats` option |
| sampled guard pages | off | options below |

### Sampled guard pages (GWP-ASan style)

Upstream already has it, in every build: guarded objects get their own
segment with a `PROT_NONE` page right after them, so an overflow faults on
the first byte past the object. Off unless `guarded_max` is set; then one
allocation in `guarded_sample_rate` (default 1000) with a size in
`[guarded_min, guarded_max]` is guarded, `guarded_precise=1` puts the end of
the object against the guard. Cheap enough for production at a sparse rate,
and it composes with debug mode (the fault comes after the canary).

```sh
RUSTY_ALLOC_GUARDED_MAX=1048576 RUSTY_ALLOC_GUARDED_SAMPLE_RATE=1 RUSTY_ALLOC_GUARDED_PRECISE=1 ./app
```

### Proof

No unit tests: `bench/src/bin/debug_demo.rs` triggers every finding above,
the leak report, the stats (exact deltas around a fixed workload, an exited
thread's counters), the report at exit, a guarded overflow faulting, and the
default handler aborting (in a child process). `bun fixtures.ts` in `bench/`
compares its output byte for byte with `bench/fixtures/debug_demo.expected`.

### Cost

Performance build (feature off): the bench binary's `__TEXT,__text`,
`__TEXT,__const`, `__TEXT,__cstring` and `__DATA,__data` are byte-identical
with and without this work (`RustyAlloc` on master as the base). Instructions
retired, min of 7 interleaved runs, binaries named to equal length:

| workload | before | after |
|---|---:|---:|
| tasks:1 | 4.667 G | 4.667 G |
| small:1 | 1.285 G | 1.285 G |
| realistic:1 | 0.966 G | 0.966 G |

Debug build (`bench/bin/debug`) against the performance build, min of 5:

| workload | instructions | wall | max RSS |
|---|---:|---:|---:|
| tasks:1 | 3.73x | 3.51x | 1.69x |
| small:1 | 23.7x | 25.0x | 1.94x |
| realistic:1 | 4.19x | 3.65x | 1.30x |

`small:1` is tiny blocks in a tight loop, where junk fill, poisoning and the
poison check on every block dominate; that is the price of catching a write
after free. Upstream's own `debug_checks` invariant walks are included.

### Survey: what others do, what we took

- **AddressSanitizer / LeakSanitizer.** Compiler instrumentation checks every
  access against shadow memory; redzones around blocks; freed memory held in a
  quarantine (256 MB by default on 64-bit); at exit LSan scans stacks,
  registers, globals and the heap for pointers and reports unreachable blocks
  with their allocation stacks. Taken: quarantine with delayed reuse. Not
  taken: shadow memory and access checks (needs the compiler; use ASan itself
  for that), the reachability scan (stack and register scanning is platform
  code and conservative).
- **Valgrind memcheck.** Binary translation, definedness bits per byte, leak
  classes by reachability; typically 10 to 50 times slower. Not taken, same reasons.
- **GWP-ASan** (Chrome, Android). Samples a small fraction of allocations onto
  pages with guard pages, so overflows and uses after free fault, at a cost low
  enough for production. Already upstream as guarded objects (mimalloc's
  `MI_GUARDED`); documented and demonstrated above rather than rebuilt.
- **Scudo** (Android). Every chunk has a header with a checksum keyed by a
  per-process cookie and the chunk address, covering state, size and how it
  was allocated; detects double free, corrupted headers, dealloc-type mismatch
  and delete-size mismatch; optional quarantine. Taken: the keyed header
  checksum, and its mismatch checks as `NotFromGlobalAlloc`, `SizeMismatch`
  and `AlignMismatch`.
- **hardened_malloc** (GrapheneOS). Canaries checked on free, zero on free
  with a check on reuse, randomized slots, guard slabs, delayed reuse. Taken:
  the canary and the poison check on reuse (as a check on eviction). Not
  taken: randomization and guard slabs, which are hardening, not debugging
  (upstream's `secure` covers free-list encoding).
- **PartitionAlloc** (Chromium). Cookies around blocks in debug builds,
  free-list pointers stored transformed and shadowed, BackupRefPtr
  (MiraclePtr) quarantines freed memory that a `raw_ptr<T>` still points to.
  Taken: the cookie idea, as the canary. Not taken: BackupRefPtr needs a smart
  pointer type in the client.
- **snmalloc.** A checked build validates frees (start of an object, owned
  memory) and protects free lists. Taken: start-of-object and ownership checks
  (`InteriorPointer`, `ForeignPointer`).
- **tcmalloc.** A sampling heap profiler (one sample per ~2 MiB allocated,
  with a stack) cheap enough for production, peak heap profiles, and stats
  that break memory down into in use, cached and fragmented. Taken: the
  fragmentation breakdown. Not taken: stacks (below).
- **Electric Fence, DUMA, Windows PageHeap.** Every allocation on its own
  page with a guard page; instant faults, large memory cost. Covered by
  guarded objects at sample rate 1, so no separate mode.
- **heaptrack, bytehound, dhat-rs.** Record a stack per allocation (an
  interposed `malloc`, or a `#[global_allocator]` wrapper using std's
  backtrace) for total, peak and leaked bytes per call site. Not taken:
  capturing a stack inside the allocator needs an unwinder that does not
  allocate, or a frame-pointer walk that needs more inline asm; allocation
  numbers stand in for call sites, and these tools work alongside this
  allocator when stacks are needed.
- **mimalloc.** `MI_DEBUG` levels of internal checks, `MI_PADDING` canaries
  checked on free ("buffer overflow in heap block"), the `0xD0`/`0xDF`/`0xDE`
  fills, `mi_register_error`, abort on corruption, `mi_stats_print`,
  `mi_heap_visit_blocks`, `show_stats` at exit. Taken: all of these shapes,
  wording and fill values.
- **jemalloc.** `opt.junk` fills, `opt.zero`, sampled profiling with
  `opt.prof_leak` at exit, `malloc_stats_print` with per-bin tables. Taken:
  per-bin tables and a leak summary at exit.

### Not done

- Call sites for leaks and hotspots (see above).
- Leaks in heaps of other live threads: call `leak_report` on each thread.
- Over-aligned blocks (align > 16) that the core placed at an offset inside
  its block are not listed by `leak_report`, and an interior pointer into one
  is reported without the block's size.
- The raw `alloc::malloc` / `free` API is not checked; only `RustyAlloc`.

## Decided

- Inline asm stays: on aarch64 macOS the thread id is read with
  `asm!("mrs {}, tpidrro_el0")` (`src/init.rs`), and the crate keeps its
  x86-64 Linux, Windows and aarch64 Linux TLS and owner-check asm. Debug mode
  adds none.

## Open

- `RESIDENT_FREE_BUDGET`: 8 (current) or 2 (lower RSS, slower).
