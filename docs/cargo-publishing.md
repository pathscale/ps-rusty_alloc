# Cargo publishing

The manually dispatched `Publish crate` workflow runs only from `master` and
publishes the version declared in `Cargo.toml` with
`cargo publish --registry crates-io`. Before dispatch, review the package
contents and run the affected local checks on the exact commit on `master`,
including:

```sh
cargo build --release
cargo test --release
RUSTFLAGS="--cfg loom" cargo test --test loom_xthread --release
cargo check --no-default-features
cargo check --no-default-features --features debug_checks
RUSTFLAGS="--cfg ra_single_threaded" cargo check --no-default-features
cargo publish --dry-run
```

The no-default-feature checks cover the Unix `no_std` configuration and its
`debug_checks` variant; the `ra_single_threaded` check covers the explicit
single-thread opt-in. The Loom model must be run separately with its `loom`
cfg.
