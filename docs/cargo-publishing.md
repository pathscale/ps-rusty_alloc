# Cargo publishing

`Publish` publishes the version declared in `Cargo.toml` when manually
dispatched from `master`. Before dispatch, review the package contents and run
the affected local checks on the exact commit, including:

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
cfg. Record the full checked commit SHA, then dispatch `Publish` from `master`
with that SHA and attest that the local checks passed. The workflow checks out
the dispatch SHA; the helper refuses a mismatched SHA, a dirty or untracked
checkout, or a manifest that does not explicitly allow `crates-io`.

The helper reads the package name and version from Cargo's manifest metadata.
It treats only an HTTP 404 as an unpublished version; an existing version is
a no-op and all request errors or other HTTP responses fail closed. The token
is supplied only through the workflow environment.
