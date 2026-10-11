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

## Debug mode

Feature `debug` builds this fork with its debug layer on (`debug_checks`):
`bun build.ts debug` makes `bin/debug` for overhead runs against `bin/rusty_alloc`,
and the `debug_demo` program triggers every check once.

```sh
bun fixtures.ts          # build and run debug_demo, compare with fixtures/debug_demo.expected
bun fixtures.ts --regen  # rewrite the expected output after an intended change
```

The output is one `key: value` line per check and holds no addresses; a
mismatch lists each missing, extra or changed key. See
[docs/debugging.md](../docs/debugging.md).

## no_std, multi-threaded

`nostd-mt/` is a standalone `#![no_std]` `#![no_main]` binary with this fork as
its global allocator, 128 pthreads over 8 rounds, cross-thread frees and frees
after the owner thread has exited. `nostd.ts` builds it four ways
(`panic = "abort"`, debug assertions, `debug_checks`, `panic = "unwind"` on
nightly), runs each 50 times against `fixtures/nostd_mt.expected`, checks each
binary with `nostd-nm.ts` for std symbols, and checks that the `debug_checks`
build stops a double free on a spawned thread.

```sh
bun nostd.ts              # all four builds, 50 runs each
bun nostd.ts --runs 200   # more runs
bun nostd.ts --regen      # rewrite the expected output after an intended change
bun nostd-nm.ts <binary>  # the std-symbol check alone
```

See [docs/no_std.md](../docs/no_std.md).
