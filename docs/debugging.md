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

No new library API. Two harness hooks in `bench/src/main.rs`, both read
from the environment and off unless set:

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

## Planned, not implemented

One allocator for both modes: checks behind a feature that is off by
default, compiled out of the performance build, with release instruction
counts required to match the build without the feature exactly.

Memory safety and FFI:

- Leak report at exit or on demand, built on `visit_blocks`, with call sites.
- FFI mismatches: free of a pointer this allocator never returned, wrong size
  or alignment on dealloc, double free (the last two partly exist upstream).
- Use-after-free: poison on free plus a bounded quarantine.
- Overflow: canaries around blocks.

Performance and fragmentation:

- Per-size-class stats.
- Rounding waste, and mostly-empty pages held: resident bytes against live bytes.
- Realloc thrash.
- Repeated large alloc and free of the same size.
- Hotspots by call site.

## Open questions

- On a failed check: abort or log.
- Quarantine size.
- Reuse upstream's `debug_checks` name or add a new feature.
- Inline asm: on aarch64 macOS the thread id is read with
  `asm!("mrs {}, tpidrro_el0")` (`src/init.rs`). The crate also has `asm!` and
  `global_asm!` for x86-64 Linux, Windows and aarch64 Linux TLS and owner checks.
  Keep, or replace with a non-asm thread id.
- `RESIDENT_FREE_BUDGET`: 8 (current) or 2 (lower RSS, slower).
