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

`src/segment.rs`, commits `a95c129` (mechanism, budget 2) and `d68fe90` (budget 8).

- `RESIDENT_FREE_BUDGET = 8`: freed chunks allowed to stay resident, process wide.
- `FREE_RESIDENT`: atomic count of parked chunks.
- `park_or_purge` runs in `segment_free` before `arena::chunk_free`. Under budget,
  the chunk is marked `FREE_STATE_RESIDENT` and counted. Over budget, the range its
  tenant carved (header slices excluded, up to `next_free_slice`) is purged with
  `os::purge` right there; if the purge decommitted, the chunk is marked
  `FREE_STATE_PURGED_RECOMMIT`.
- `segment_alloc` reads `ps_free_state` (a new `Segment` header byte; the header
  slice is never purged) before rewriting the header: a resident chunk is
  uncounted, a purged one is recommitted.

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

## Known gap

A chunk parked by `park_or_purge` can be taken by the Huge path
(`arena::chunk_alloc_n`), which does not read `ps_free_state`. Then a resident
chunk is never uncounted, and a purged-with-recommit chunk is not recommitted
by this code. Open; see [debugging.md](debugging.md#open-questions).
