//! The fork's own `GlobalAlloc` (`rusty_alloc::RustyAlloc`, `src/global.rs`), so
//! the bench measures the exact path a Rust user of this crate gets.

pub use rusty_alloc::RustyAlloc;
