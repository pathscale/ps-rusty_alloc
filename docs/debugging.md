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

Every block from `RustyAlloc` and from the raw API carries a 64-byte header
(links into the live-block registry, allocation number, requested size and
alignment, the call sites and threads of its allocation and free, state, and
a checksum keyed by the block address that covers all of it) and an 8-byte
canary after it.

| finding | when | `ViolationKind` |
|---|---|---|
| pointer outside every segment we own (another allocator's block, an FFI mismatch) | any free or realloc | `ForeignPointer` |
| our block, but from the raw `alloc::malloc` / `mi_malloc` API (C side of an FFI boundary) | `dealloc`, `realloc` | `NotFromGlobalAlloc` |
| pointer into the middle of a block | any free or realloc | `InteriorPointer` |
| block already freed (still in quarantine; after that the core's own double-free abort) | any free or realloc | `DoubleFree` |
| `Layout` size or alignment differs from the allocation's | `dealloc`, `realloc` | `SizeMismatch`, `AlignMismatch` |
| canary after the block overwritten | any free or realloc | `BufferOverflow` |
| header checksum fails (underflow or wild write) | any free, quarantine eviction, registry walk | `CorruptHeader` |
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

### The raw API

`rusty_alloc::alloc::*` (`malloc`, `zalloc`, `calloc`, the aligned and
`_at` variants, `realloc` and its forms, `expand`, `free`, `usable_size`
and the `heap_*` family) goes through the same layer: same header, fills,
canary, quarantine, registry and call sites, and every free gets the checks
in the table above that need no `Layout`. `usable_size` is the requested
size, as under ASan, so a write past it is an overflow.

A raw block is marked as such. Freeing it through `RustyAlloc` is
`NotFromGlobalAlloc` (the Scudo dealloc-type mismatch); a raw `free` of a
`RustyAlloc` block is allowed, as Scudo allows it by default, since C code
freeing a buffer Rust handed it is common and correct. A pointer at the start
of a core block with no debug header (from `Heap::malloc` directly) is left
to the core.

### Call sites

Each allocation and each free records its call stack: a frame-pointer walk
(the fast unwinder of ASan and heaptrack) on aarch64 and x86-64, macOS, iOS,
Linux and Android, bounded by the thread's stack, so a frame without a frame
pointer ends the walk instead of faulting. Nothing is allocated and nothing
needs `std`. Each distinct stack is stored once in a stack depot, as ASan's
`StackDepot`: entries carved from 1 MiB chunks of OS pages (never from the
allocator being debugged), found through a lock-free hash table, named by a
32-bit `StackId` in the block header, never freed. Up to 16 frames by
default.

**Build the program with frame pointers**, or stacks stop at the first frame
built without one:

```sh
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --features debug
```

aarch64 macOS always keeps them; x86-64 and Linux need the flag (the standard
library comes prebuilt, so its frames may still end a walk; use
`-Z build-std` for those too).

A report prints the stack where the misuse was found and, as ASan does, where
the block was freed and where it was allocated:

```text
rusty_alloc: error: double free of block 0x1280500b0 (size 40, align 8)
rusty_alloc:   found by thread T1 here:
rusty_alloc:     #0 0x000000010002151c (/path/to/app+0x551c)
rusty_alloc:     #1 0x0000000100024a80 (/path/to/app+0x8a80)
rusty_alloc:   freed by thread T1 here:
rusty_alloc:     #0 0x0000000100028f8c (/path/to/app+0xcf8c)
rusty_alloc:   previously allocated by thread T1 here:
rusty_alloc:     #0 0x0000000100021368 (/path/to/app+0x5368)
```

Leak reports group blocks by allocation stack, as LeakSanitizer does
(`leak of 9600 bytes in 3 blocks allocated from:` and the frames). Threads are
numbered T1, T2, ... in the order they first need a number.

### Symbolizing

The allocator cannot symbolize without `std`, so a frame is a return
address with its image and the offset from the image's load address
(`dladdr`), the form `atos -l` and `addr2line` take. `tools/symbolize.ts`
rewrites a saved report with function names, and file and line when the
binary has debug info:

```sh
./app 2> report.txt
bun tools/symbolize.ts report.txt
```

```text
rusty_alloc:     #0 0x000000010002151c in app::release (/path/to/app+0x551c)
```

It uses `atos` on macOS and `addr2line` (binutils or `llvm-addr2line`) on
Linux, looks up the byte before each return address so the line is the call's
own, marks inlined frames, and demangles Rust v0 names. A stripped binary
keeps its raw lines.

### Leaks on every thread

Every live debug block is on a registry: 256 doubly linked lists sharded by
address, threaded through the block headers, each list under its own spin
lock, as Windows PageHeap keeps its busy list and Valgrind its table of live
blocks. A free unlinks the block before it is poisoned, so `leak_report`
walks only live, mapped headers: it never reads freed or unmapped memory,
never stops another thread, and sees blocks of every thread, running or
exited. The links are under the header checksum; a list that meets a damaged
header reports `CorruptHeader` and restarts empty, and the blocks it lost
are counted as `unlisted` in the summary rather than followed.

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
- `leak_report(&mut dyn FnMut(&Leak)) -> LeakSummary`: every live debug
  block of every thread, live or exited, from the registry. `Leak` has the
  pointer, size, alignment, allocation number, allocating thread and
  allocation stack. The visitor runs under a registry lock and must not
  allocate or free (that is reported). `alloc_seq()` returns the calling
  thread's allocation number, a mark: blocks with `seq` above it came later.
  `print_leaks(max)` prints a summary and the first `max` call sites.
- `Violation` carries the finding thread and stack, and for a known block
  the allocating and freeing threads and stacks (`thread`, `stack`,
  `alloc_thread`, `alloc_stack`, `free_thread`, `free_stack`).
- `capture() -> StackId` records the caller's stack for your own events;
  `thread_number()` is the calling thread's T number.
- `debug::stack`: `StackId`, `frames(id)` (the return addresses),
  `print_stack(id)`, `image_of(addr)` (`dladdr`), `set_stack_depth` /
  `stack_depth`, `depot_usage()`, `SUPPORTED`, `MAX_FRAMES`, and the
  building blocks `thread_stack_bounds`, `walk`, `capture_in` and `intern`.
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
| frames per stack | 16 (0 turns capture off) | `stack::set_stack_depth`, `RUSTY_ALLOC_DEBUG_STACK_DEPTH` |
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
through `RustyAlloc` and through the raw API, the leak report, the stats
(exact deltas around a fixed workload, an exited thread's counters), the
report at exit, a guarded overflow faulting, and the default handler aborting
(in a child process). It checks call sites (allocated, freed, found) for a
double free, a use after free, an overflow and a raw double free, a leak with
its call site on a spawned thread that is still running, and leaks on three
live threads at once. `bun fixtures.ts` in `bench/` builds it with frame
pointers forced, symbolizes every stack with `tools/symbolize.ts`, keeps the
first program frame, and compares the output byte for byte with
`bench/fixtures/debug_demo.expected`, which holds function names and no
addresses or paths. `bun nostd.ts` runs the `no_std` multi-threaded binary
with `debug_checks` 50 times.

### Cost

Performance build (feature off): the whole bench binary is byte-identical
with and without call sites, the registry and the raw API checks (2.3.2 as
the base, both built from the same path; same SHA-1). Instructions retired,
min of 7 interleaved runs, binaries named to equal length:

| workload | 2.3.2 | 2.3.3 |
|---|---:|---:|
| tasks:1 | 4.668 G | 4.667 G |
| small:1 | 1.286 G | 1.286 G |
| realistic:1 | 0.967 G | 0.967 G |

Debug build (`bench/bin/debug`) against the performance build, min of 5:

| workload | instructions | wall | max RSS | 2.3.2 instructions |
|---|---:|---:|---:|---:|
| tasks:1 | 7.98x | 6.87x | 1.99x | 3.74x |
| small:1 | 48.8x | 38.0x | 2.19x | 23.7x |
| realistic:1 | 8.39x | 6.68x | 1.38x | 4.19x |

About two fifths of the increase is the registry and the larger header (a
lock and the neighbouring headers rewritten on each allocation and free) and
the rest is stack capture.
With `RUSTY_ALLOC_DEBUG_STACK_DEPTH=0` the debug build is 1.44x, 1.42x and
1.41x the instructions of 2.3.2's on the three workloads. ASan and heaptrack
also capture a stack on every allocation. `small:1` is tiny blocks in a
tight loop, where junk fill, poisoning, the poison check and the stack on
every block dominate. Upstream's own `debug_checks` invariant walks are
included.

### Survey: what others do, what we took

- **AddressSanitizer / LeakSanitizer.** Compiler instrumentation checks every
  access against shadow memory; redzones around blocks; freed memory held in a
  quarantine (256 MB by default on 64-bit); at exit LSan scans stacks,
  registers, globals and the heap for pointers and reports unreachable blocks
  with their allocation stacks. Taken: quarantine with delayed reuse, the
  frame-pointer fast unwinder, the stack depot, and the report shape (where
  found, freed and allocated; leaks grouped by stack; offline symbolization
  of image+offset frames). Not taken: shadow memory and access checks (needs the compiler; use ASan itself
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
  fragmentation breakdown. Not taken: sampling (debug mode records every
  stack, which is what a debugging build is for).
- **Electric Fence, DUMA, Windows PageHeap.** Every allocation on its own
  page with a guard page; instant faults, large memory cost. Covered by
  guarded objects at sample rate 1, so no separate mode. Taken from PageHeap:
  its busy list of live blocks, as the registry that lists leaks on every
  thread.
- **heaptrack, bytehound, dhat-rs.** Record a stack per allocation (an
  interposed `malloc`, or a `#[global_allocator]` wrapper using std's
  backtrace) for total, peak and leaked bytes per call site. Taken: a stack
  per allocation, through a frame-pointer walk that allocates nothing, and the
  requirement to build with `-C force-frame-pointers=yes`. Not taken: a
  separate recorder process and the per-site totals over time (use these
  tools alongside for that).
- **mimalloc.** `MI_DEBUG` levels of internal checks, `MI_PADDING` canaries
  checked on free ("buffer overflow in heap block"), the `0xD0`/`0xDF`/`0xDE`
  fills, `mi_register_error`, abort on corruption, `mi_stats_print`,
  `mi_heap_visit_blocks`, `show_stats` at exit. Taken: all of these shapes,
  wording and fill values.
- **jemalloc.** `opt.junk` fills, `opt.zero`, sampled profiling with
  `opt.prof_leak` at exit, `malloc_stats_print` with per-bin tables. Taken:
  per-bin tables and a leak summary at exit.

### Not done

- Stacks on Windows and on targets other than aarch64 and x86-64 (no walker:
  reports say `<no stack: ...>`).
- Symbolizing inside the process: frames are printed raw, by design, and
  `tools/symbolize.ts` names them afterwards.
- An interior pointer into an over-aligned block (align > 16) that the core
  placed at an offset inside its block is reported without the block's size.

## Decided

- Inline asm stays: on aarch64 macOS the thread id is read with
  `asm!("mrs {}, tpidrro_el0")` (`src/init.rs`), and the crate keeps its
  x86-64 Linux, Windows and aarch64 Linux TLS and owner-check asm. Debug mode
  adds one instruction of it, the frame-pointer read (`mov {}, x29` /
  `mov {}, rbp`) that starts a stack walk.

## Open

- `RESIDENT_FREE_BUDGET`: 8 (current) or 2 (lower RSS, slower).
