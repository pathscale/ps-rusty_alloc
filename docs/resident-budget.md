# Resident free budget

## Symptom

`workers:16` (8 waves of 16 threads, each building and dropping about 24 MB of
maps and strings, then exiting) had peak RSS 1.21-1.24x mimalloc. With the
`BENCH_WAVE_RSS` probe, RSS rose every wave, 515 MB to 641 MB, while mimalloc
stayed flat. Abandoned segments were zero and only one chunk was live between
waves.

## Cause

A Normal segment that empties goes back to its arena with every page its tenant
touched still resident; arena memory is handed out as-is. The next thread gets a
chunk and touches a slightly different subset of it. The resident set of a
process that churns threads becomes the union of every layout any tenant ever
used.

## Fix

`src/segment.rs` and `src/arena.rs`, commits `a95c129` (mechanism, budget 2), `d68fe90` (budget 8) and the arena-state fix on `perf-coalescing`.

- `RESIDENT_FREE_BUDGET = 8`: freed chunks allowed to stay resident, process wide.
- `arena::PARKED_RESIDENT`: atomic count of parked chunks.
- `park_or_purge` runs in `segment_free` before the chunk goes back to its
  arena. Under budget, the chunk is returned as `ChunkState::Parked` and
  counted. Over budget, the range its tenant carved (header slices excluded, up
  to `next_free_slice`) is purged with `os::purge` right there; if the purge
  decommitted, the chunk is returned as `ChunkState::Decommitted`.
- The state lives in the arena, not in the chunk: two bitmaps next to `used`
  and `dirty`, `parked` and `decommitted`, written by `arena::chunk_free_state`
  before it releases the `used` bit. Every claim path (`chunk_alloc` for a
  Normal segment, `chunk_alloc_n` for a huge block, for runs inside one bitmap word
  and across words) calls `settle_claimed` on the chunks it just took:
  a parked bit is cleared and uncounted, a decommitted bit is cleared and the
  chunk recommitted. A chunk is settled exactly once, by whoever takes it.

Reactive, no timer and no sweep: the free path checks the backlog itself.

## Numbers

Apple M4 Max, min of 7 interleaved rounds. `ra_base` is the build before the fix,
`ra_r1` budget 2, `ra_r1k8` budget 8.

| workload | build | wall vs mimalloc | max RSS vs mimalloc |
|---|---|---:|---:|
| workers:16 | ra_base | 0.92 | 1.24 |
| workers:16 | ra_r1 (2) | 1.10 | 0.92 |
| workers:16 | ra_r1k8 (8) | 1.03 | 1.01 |
| workers:8 | ra_base | 0.95 | 0.89 |
| workers:8 | ra_r1k8 (8) | 1.03 | 0.88 |
| workers:4 | ra_base | 0.97 | 0.77 |
| workers:4 | ra_r1k8 (8) | 0.96 | 0.77 |

Budget 8 costs 12% wall against the unfixed build on `workers:16` (205.5 vs
183.1 ms), still 1.03x mimalloc. Budget 2 gives 0.92-0.95x mimalloc RSS at
+10-14% wall. Other workloads stayed within noise (`r1` run, see
[benchmarks.md](benchmarks.md)).

## Fixed: huge blocks over parked chunks

Until the arena kept the state, it was a byte in the chunk's own `Segment`
header (`ps_free_state`), read only by `segment_alloc`. The huge path
(`arena::chunk_alloc_n`) never read it, so:

- a parked chunk taken by a huge block was never uncounted, and the budget
  eroded: the counter stayed at the budget with fewer (or no) chunks actually
  parked, so every later segment free purged;
- a decommitted chunk taken by a huge block was not recommitted by this code
  (moot on macOS and Linux, where `os::decommit` reports no recommit needed,
  but wrong on Windows);
- a chunk in the middle of a huge block had its header bytes overwritten by
  the block's payload; a later Normal tenant could read a stale "parked" byte
  and decrement a counter that was already 0, wrapping it to `usize::MAX`, so
  every free from then on purged.

The fix moved the state into the arena bitmaps described above, so it can be
neither skipped nor overwritten.

Probe: the `hugepark` workload. Each round, `t` threads build about 4 MB and
exit (their chunks go back to the arena), then the main thread takes three
80 MB huge blocks, which claim runs of those freed chunks, and writes 0x01
over the first 4 KiB of every chunk inside them. `BENCH_WAVE_RSS=1` prints
`arena::parked_resident()`, the counter and the number of chunks whose parked
bit is set, after each phase.

```sh
BENCH_WAVE_RSS=1 bench/bin/rusty_alloc hugepark 16
```

`hugepark:16`, before the fix (counter read through a local shim, no bitmap
existed) and after:

| phase | before: counter | after: counter | after: chunks parked |
|---|---:|---:|---:|
| round 0, threads exited | 8 | 8 | 8 |
| round 0, huge blocks live | 8 | 3 | 3 |
| rounds 1-5, threads exited | 8 | 8 | 8 |
| rounds 1-5, huge blocks live | 8 | 2 | 2 |

Before the fix the counter claimed 8 parked chunks while the huge blocks held
most of them, so the next frees purged instead of parking (max RSS, min of 7
interleaved rounds, 49.6 MB before against 53.9 MB after: the fix parks the
chunks the budget allows). After it,
the counter equals the number of parked chunks at every phase. The wrap to
`usize::MAX` did not show up in this probe because the budget refills the
counter before it reaches 0; it cannot happen after the fix, since no state is
read from chunk memory any more.

Cost, 7 interleaved rounds, min (`park_base` = the build before, `park_fix`
= after; ratios against mimalloc). Source: `bench/results/park-summary-*.md`
and, for 15 rounds of `workers:16` alone, `bench/results/parkw-summary-*.md`.

| workload | park_base wall / instr / RSS | park_fix wall / instr / RSS |
|---|---|---|
| hugepark:16 | 0.37 / 0.57 / 0.29 | 0.39 / 0.57 / 0.32 |
| workers:16 (15 rounds) | 209.2 ms / 28.705 G / 475.7 MB | 209.1 ms / 28.591 G / 466.1 MB |
| workers:8 | 1.03 / 0.97 / 0.85 | 1.01 / 0.98 / 0.88 |
| realistic:8 | 0.82 / 0.90 / 0.58 | 0.81 / 0.90 / 0.56 |
| tasks:1 | 0.92 / 0.91 / 0.95 | 0.93 / 0.91 / 0.94 |
| small:1 | 0.87 / 0.64 / 0.89 | 0.86 / 0.64 / 0.88 |
| large:1 | 0.72 / 0.36 / 0.72 | 0.71 / 0.36 / 0.72 |

Within noise everywhere; the claim path adds two bitmap loads.
