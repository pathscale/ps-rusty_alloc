# bench

Standalone crate (its own `[workspace]`, `publish = false`), excluded from the
library package. The only place the C mimalloc appears; it is the baseline, not
a dependency of the library.

One binary per allocator, chosen by cargo feature: `system`, `mimalloc`,
`rusty_alloc` (this fork, through `src/ra_shim.rs`), `smalloc`,
`baby_mimalloc`, `rlsf`, `dlmalloc`.

Needs bun and macOS (`/usr/bin/time -l`).

```sh
cd bench
bun build.ts                        # all allocators into bin/
bun build.ts mimalloc rusty_alloc   # a subset
bun run.ts <rounds> <allocs> <workload:threads,...> [tag]
```

Examples, the runs behind `results/`:

```sh
bun run.ts 5 system,mimalloc,rusty_alloc,smalloc,baby_mimalloc,rlsf,dlmalloc \
  tasks:1,tasksbig:1,small:1,realistic:1,large:1,phases:1 st
bun run.ts 5 system,mimalloc,rusty_alloc,smalloc \
  tasks:4,small:4,small:16,xthread:1,xthread:4,realistic:8,large:4,workers:4,workers:16 mt
bun run.ts 5 mimalloc,rusty_alloc,rusty_alloc+RUSTY_ALLOC_PURGE_DELAY=10,rusty_alloc+RUSTY_ALLOC_PURGE_DELAY=0,system,smalloc \
  workers:16,workers:8,tasks:1 knobs
```

`<allocs>` are names in `bin/`; `name+VAR=value` runs that binary with an
environment variable set. To compare two builds of the fork, copy each
`bin/rusty_alloc` to its own name (the `ra_base`, `ra_r1`, `ra_r1k8` columns in
`results/` were made that way from commits `a7a850c`, `a95c129` and `d68fe90`).

Output: `results/<tag>-raw-<time>.jsonl` (one line per process) and
`results/<tag>-summary-<time>.md` (min per metric, ratio against mimalloc).

Hooks: `BENCH_WAVE_RSS=1` and `BENCH_PROFILE_SLEEP_MS`, see
[docs/debugging.md](../docs/debugging.md#added-in-this-fork).
