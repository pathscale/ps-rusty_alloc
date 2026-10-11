//! Proves each debug-mode check of `rusty_alloc` (`debug_checks` feature) by
//! triggering it. Prints one `key: value` line per finding to stdout; the
//! output is compared byte for byte with `fixtures/debug_demo.expected` by
//! `bun fixtures.ts`. Addresses never appear in the output: a call stack is
//! printed as `{image+offset@address;...}`, which fixtures.ts symbolizes and
//! reduces to the first function outside the allocator and the runtime.
//!
//! Usage: debug_demo            all cases, log-and-continue handler
//!        debug_demo abort      one double free under the default handler

use rusty_alloc::RustyAlloc;
use rusty_alloc::alloc as raw;
use rusty_alloc::debug::stack::{self, StackId};
use rusty_alloc::debug::{self, Violation};
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::hint::black_box;
use std::io::Write;
use std::sync::{Arc, Barrier, mpsc};

#[global_allocator]
static A: RustyAlloc = RustyAlloc;

thread_local! {
    static LAST: Cell<Option<Violation>> = const { Cell::new(None) };
}

/// Log and continue: remember the violation for the case to print.
fn record(v: &Violation) {
    LAST.with(|c| c.set(Some(*v)));
}

fn take() -> String {
    match LAST.with(Cell::take) {
        None => "none".into(),
        Some(v) => format!(
            "{} size={} align={} block_size={} block_align={} offset={}",
            v.kind.name(),
            v.size,
            v.align,
            v.block_size,
            v.block_align,
            v.offset
        ),
    }
}

fn lay(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

/// Replace every `0x<hex>` with `0xADDR`.
fn scrub(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '0' && it.peek() == Some(&'x') {
            it.next();
            while it.peek().is_some_and(char::is_ascii_hexdigit) {
                it.next();
            }
            out.push_str("0xADDR");
        } else {
            out.push(c);
        }
    }
    out
}

fn case(out: &mut Vec<String>, key: &str, f: impl FnOnce()) {
    f();
    out.push(format!("{key}: {}", take()));
}

/// A stack as `{image+offset@address;...}` (`{}` when none was captured).
fn frames(id: StackId) -> String {
    let parts: Vec<String> = stack::frames(id)
        .iter()
        .map(|&a| match stack::image_of(a) {
            Some((name, base)) => format!("{name}+{:#x}@{a:#x}", a - base),
            None => format!("?@{a:#x}"),
        })
        .collect();
    format!("{{{}}}", parts.join(";"))
}

/// A case whose report must name its call sites: where the block was
/// allocated, where it was freed, and where the misuse was found, all on
/// this thread.
fn sites(out: &mut Vec<String>, key: &str, f: impl FnOnce()) {
    f();
    let me = debug::thread_number();
    let line = match LAST.with(Cell::take) {
        None => "none".into(),
        Some(v) => format!(
            "{} alloc={} free={} found={} same_thread={}",
            v.kind.name(),
            frames(v.alloc_stack),
            frames(v.free_stack),
            frames(v.stack),
            v.thread == me
                && v.alloc_thread == me
                && (v.free_stack.is_none() || v.free_thread == me)
        ),
    };
    out.push(format!("{key}: {line}"));
}

// Call sites. Each is a function of its own (never inlined, never a tail
// call, never identical to another) so it shows up as one frame by name.

#[inline(never)]
fn site_alloc(l: Layout) -> *mut u8 {
    // SAFETY (demo): a valid layout.
    black_box(unsafe { A.alloc(l) })
}

#[inline(never)]
fn site_free(p: *mut u8, l: Layout) {
    // SAFETY (demo): misuse here is deliberate and caught.
    unsafe { A.dealloc(black_box(p), l) };
    black_box(0x11u32);
}

#[inline(never)]
fn site_free_again(p: *mut u8, l: Layout) {
    // SAFETY (demo): misuse here is deliberate and caught.
    unsafe { A.dealloc(black_box(p), l) };
    black_box(0x22u32);
}

#[inline(never)]
fn site_flush() {
    debug::flush_quarantine();
    black_box(0x33u32);
}

#[inline(never)]
fn raw_site_alloc(n: usize) -> *mut u8 {
    black_box(raw::malloc(n))
}

#[inline(never)]
fn raw_site_free(p: *mut u8) {
    // SAFETY (demo): misuse here is deliberate and caught.
    unsafe { raw::free(black_box(p)) };
    black_box(0x44u32);
}

#[inline(never)]
fn raw_site_free_again(p: *mut u8) {
    // SAFETY (demo): misuse here is deliberate and caught.
    unsafe { raw::free(black_box(p)) };
    black_box(0x55u32);
}

#[inline(never)]
fn leak_in_thread(n: usize) -> *mut u8 {
    black_box(0x77u32);
    // SAFETY (demo): a valid layout.
    black_box(unsafe { A.alloc(lay(n, 8)) })
}

#[inline(never)]
fn leak_in_worker(n: usize) -> *mut u8 {
    black_box(0x66u32);
    // SAFETY (demo): a valid layout.
    black_box(unsafe { A.alloc(lay(n, 8)) })
}

/// The default handler report with each run of frame lines folded into one
/// `{...}` stack and every other address scrubbed.
fn fold_frames(s: &str) -> String {
    let mut out = String::new();
    let mut run: Vec<String> = Vec::new();
    let flush = |out: &mut String, run: &mut Vec<String>| {
        if !run.is_empty() {
            out.push_str(&format!("rusty_alloc:     {{{}}}\n", run.join(";")));
            run.clear();
        }
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("rusty_alloc:     #") {
            // "N 0xADDR (image+0xOFF)" or "N 0xADDR".
            let mut it = rest.split(' ');
            let _n = it.next();
            let addr = it.next().unwrap_or("?");
            let img = it.collect::<Vec<_>>().join(" ");
            let img = img.trim_start_matches('(').trim_end_matches(')');
            run.push(if img.is_empty() {
                format!("?@{addr}")
            } else {
                format!("{img}@{addr}")
            });
            continue;
        }
        flush(&mut out, &mut run);
        out.push_str(&scrub(line));
        out.push('\n');
    }
    flush(&mut out, &mut run);
    out
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("abort") {
        // A deliberate double free, caught before the core.
        let p = site_alloc(lay(40, 8));
        site_free(p, lay(40, 8));
        site_free_again(p, lay(40, 8));
        println!("not reached");
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("guarded") {
        // Run with the sampled guard-page options on: an overflow past the
        // canary faults on the guard page at once.
        let l = lay(1000, 8);
        // SAFETY (demo): a deliberate overflow into the guard page.
        unsafe {
            let p = A.alloc(l);
            for i in 0..8192 {
                p.add(1000 + i).write_volatile(0x41);
            }
            A.dealloc(p, l);
        }
        println!("not reached");
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("atexit") {
        let v = vec![1u8; 77];
        std::mem::forget(v);
        return;
    }
    debug::set_handler(Some(record));
    let mut out = Vec::new();

    // SAFETY (whole block): every misuse below is deliberate and is caught by
    // the debug layer before it reaches the core allocator.
    unsafe {
        let p = A.alloc(lay(32, 8));
        let fill = std::slice::from_raw_parts(p, 32)
            .iter()
            .all(|&b| b == debug::UNINIT_BYTE);
        out.push(format!("uninit_fill: {fill}"));
        A.dealloc(p, lay(32, 8));
        let p = A.alloc_zeroed(lay(32, 8));
        let zero = std::slice::from_raw_parts(p, 32).iter().all(|&b| b == 0);
        out.push(format!("zeroed: {zero}"));
        A.dealloc(p, lay(32, 8));
        let p = A.alloc(lay(100, 64));
        out.push(format!("overaligned: {}", p.addr().is_multiple_of(64)));
        A.dealloc(p, lay(100, 64));
        out.push(format!("clean_frees: {}", take()));

        case(&mut out, "buffer_overflow", || {
            let p = A.alloc(lay(24, 8));
            p.add(24).write(0x41);
            A.dealloc(p, lay(24, 8));
        });
        case(&mut out, "double_free", || {
            let p = A.alloc(lay(40, 8));
            A.dealloc(p, lay(40, 8));
            A.dealloc(p, lay(40, 8));
        });
        case(&mut out, "size_mismatch", || {
            let p = A.alloc(lay(64, 8));
            A.dealloc(p, lay(48, 8));
        });
        case(&mut out, "align_mismatch", || {
            let p = A.alloc(lay(64, 8));
            A.dealloc(p, lay(64, 16));
        });
        case(&mut out, "foreign_pointer", || {
            let p = libc::malloc(32).cast::<u8>();
            A.dealloc(p, lay(32, 8));
            libc::free(p.cast());
        });
        case(&mut out, "not_from_global_alloc", || {
            let p = rusty_alloc::alloc::malloc(32);
            A.dealloc(p, lay(32, 8));
            rusty_alloc::alloc::free(p);
        });
        case(&mut out, "interior_pointer", || {
            let p = A.alloc(lay(64, 8));
            A.dealloc(p.add(16), lay(48, 8));
            A.dealloc(p, lay(64, 8));
        });
        case(&mut out, "corrupt_header", || {
            let p = A.alloc(lay(64, 8));
            p.sub(8).write(0);
            A.dealloc(p, lay(64, 8));
        });
        case(&mut out, "use_after_free", || {
            let p = A.alloc(lay(48, 8));
            A.dealloc(p, lay(48, 8));
            p.add(8).write(1);
            debug::flush_quarantine();
        });
        case(&mut out, "realloc_stale_write", || {
            let p = A.alloc(lay(16, 8));
            let q = A.realloc(p, lay(16, 8), 64);
            p.write(7);
            A.dealloc(q, lay(64, 8));
            debug::flush_quarantine();
        });

        // Call sites in violation reports.
        sites(&mut out, "sites_double_free", || {
            let p = site_alloc(lay(40, 8));
            site_free(p, lay(40, 8));
            site_free_again(p, lay(40, 8));
        });
        sites(&mut out, "sites_use_after_free", || {
            let p = site_alloc(lay(48, 8));
            site_free(p, lay(48, 8));
            p.add(8).write(1);
            site_flush();
        });
        sites(&mut out, "sites_buffer_overflow", || {
            let p = site_alloc(lay(24, 8));
            p.add(24).write(0x41);
            site_free(p, lay(24, 8));
        });

        // The raw API (rusty_alloc::alloc) gets the same checks.
        case(&mut out, "raw_clean", || {
            let p = raw::malloc(32);
            let q = raw::zalloc(32);
            let r = raw::malloc_aligned(100, 64);
            let ok = std::slice::from_raw_parts(p, 32)
                .iter()
                .all(|&b| b == debug::UNINIT_BYTE)
                && std::slice::from_raw_parts(q, 32).iter().all(|&b| b == 0)
                && r.addr().is_multiple_of(64);
            assert!(ok, "raw fills or alignment");
            let s = raw::realloc(p, 64);
            raw::free(s);
            raw::free(q);
            raw::free(r);
        });
        out.push(format!("raw_usable_size: {}", {
            let p = raw::malloc(13);
            let n = raw::usable_size(p);
            raw::free(p);
            n
        }));
        case(&mut out, "raw_double_free", || {
            let p = raw::malloc(40);
            raw::free(p);
            raw::free(p);
        });
        case(&mut out, "raw_foreign_pointer", || {
            let p = libc::malloc(32).cast::<u8>();
            raw::free(p);
            libc::free(p.cast());
        });
        case(&mut out, "raw_interior_pointer", || {
            let p = raw::malloc(64);
            raw::free(p.add(16));
            raw::free(p);
        });
        case(&mut out, "raw_buffer_overflow", || {
            let p = raw::malloc(24);
            p.add(24).write(0x41);
            raw::free(p);
        });
        case(&mut out, "raw_use_after_free", || {
            let p = raw::malloc(48);
            raw::free(p);
            p.add(8).write(1);
            debug::flush_quarantine();
        });
        case(&mut out, "raw_realloc_stale_write", || {
            let p = raw::malloc(16);
            let q = raw::realloc(p, 64);
            p.write(7);
            raw::free(q);
            debug::flush_quarantine();
        });
        // Allowed both ways round would hide a real mixup, so only one way
        // is: a raw free of a GlobalAlloc block is fine (as in Scudo), a
        // GlobalAlloc dealloc of a raw block is not_from_global_alloc (above).
        case(&mut out, "raw_free_of_global_alloc", || {
            let p = A.alloc(lay(32, 8));
            raw::free(p);
        });
        sites(&mut out, "sites_raw_double_free", || {
            let p = raw_site_alloc(40);
            raw_site_free(p);
            raw_site_free_again(p);
        });
    }

    // Statistics: deltas around a fixed workload with no printing inside.
    let s0 = debug::stats();
    let mut ptrs = [std::ptr::null_mut::<u8>(); 1000];
    // SAFETY (demo): every block is freed with the layout it was allocated with.
    unsafe {
        for p in &mut ptrs {
            *p = A.alloc(lay(40, 8));
        }
        for p in &ptrs[..500] {
            A.dealloc(*p, lay(40, 8));
        }
        let mut p = A.alloc(lay(64, 8));
        let mut old = 64;
        for n in [72, 80, 88] {
            p = A.realloc(p, lay(old, 8), n);
            old = n;
        }
        A.dealloc(p, lay(old, 8));
        let mut q = A.alloc(lay(200, 8));
        q = A.realloc(q, lay(200, 8), 400);
        q = A.realloc(q, lay(400, 8), 200);
        q = A.realloc(q, lay(200, 8), 400);
        A.dealloc(q, lay(400, 8));
        for _ in 0..2 {
            let h = A.alloc(lay(40 << 20, 8));
            A.dealloc(h, lay(40 << 20, 8));
        }
    }
    let s1 = debug::stats();
    let f = debug::fragmentation_report();
    // SAFETY (demo): the other half of the blocks above.
    unsafe {
        for p in &ptrs[500..] {
            A.dealloc(*p, lay(40, 8));
        }
    }
    let (b0, b1) = {
        let i = rusty_alloc::bins::bin(40);
        (s0.bins[i], s1.bins[i])
    };
    out.push(format!(
        "stats_bin_40: block_size={} allocs={} frees={} live_bytes={} waste_bytes={}",
        b1.block_size,
        b1.allocs - b0.allocs,
        b1.frees - b0.frees,
        b1.live_bytes - b0.live_bytes,
        b1.waste_bytes - b0.waste_bytes
    ));
    out.push(format!(
        "stats_realloc: reallocs={} grows={} shrinks={} small_grows={} ping_pongs={}",
        s1.reallocs - s0.reallocs,
        s1.realloc_grows - s0.realloc_grows,
        s1.realloc_shrinks - s0.realloc_shrinks,
        s1.realloc_small_grows - s0.realloc_small_grows,
        s1.realloc_ping_pongs - s0.realloc_ping_pongs
    ));
    out.push(format!(
        "stats_huge: allocs={} frees={} same_size_repeats={}",
        s1.huge_allocs - s0.huge_allocs,
        s1.huge_frees - s0.huge_frees,
        s1.huge_repeats - s0.huge_repeats
    ));
    out.push(format!(
        "stats_chunks_counted: {}",
        s1.arena_claims + s1.os_reserves > s0.arena_claims + s0.os_reserves
    ));
    out.push(format!(
        "fragmentation_consistent: {}",
        f.pages > 0 && f.used_bytes <= f.page_bytes && f.live_bytes >= 20_000 && f.rss > 0
    ));

    // A thread's counters survive its exit (folded in at teardown).
    let t0 = debug::stats();
    std::thread::spawn(|| {
        // SAFETY (demo): allocated and freed with one layout.
        unsafe {
            for _ in 0..10 {
                let p = A.alloc(lay(4000, 8));
                A.dealloc(p, lay(4000, 8));
            }
        }
    })
    .join()
    .unwrap();
    let t1 = debug::stats();
    let i = rusty_alloc::bins::bin(4000);
    out.push(format!(
        "stats_exited_thread: allocs={} frees={}",
        t1.bins[i].allocs - t0.bins[i].allocs,
        t1.bins[i].frees - t0.bins[i].frees
    ));

    // Leaks: three blocks allocated after a mark and never freed.
    let mark = debug::alloc_seq();
    // SAFETY (demo): valid layouts.
    let kept = [10usize, 200, 5000].map(|n| unsafe { A.alloc(lay(n, 8)) });
    let mut found = [0usize; 8];
    let mut n = 0;
    let sum = debug::leak_report(&mut |l| {
        if l.seq > mark && n < found.len() {
            found[n] = l.size;
            n += 1;
        }
    });
    found[..n].sort_unstable();
    out.push(format!("leaks_after_mark: {:?}", &found[..n]));
    out.push(format!(
        "leak_summary_counts_them: {}",
        sum.blocks >= 3 && sum.bytes >= 5210
    ));
    for (p, s) in kept.iter().zip([10usize, 200, 5000]) {
        // SAFETY (demo): allocated above with this layout.
        unsafe { A.dealloc(*p, lay(s, 8)) };
    }

    // A leak on a spawned thread that is still running, with its call site.
    let me = debug::thread_number();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let t = std::thread::spawn(move || {
        let p = leak_in_thread(321);
        ready_tx.send((p.addr(), debug::thread_number())).unwrap();
        go_rx.recv().unwrap();
        // SAFETY (demo): allocated above with this layout.
        unsafe { A.dealloc(p, lay(321, 8)) };
    });
    let (addr, tno) = ready_rx.recv().unwrap();
    // The visitor must not allocate: keep the stack id, format it after.
    let mut seen = None;
    debug::leak_report(&mut |l| {
        if l.ptr == addr {
            seen = Some((l.size, l.thread, l.stack));
        }
    });
    out.push(format!(
        "leak_live_thread: {}",
        seen.map_or("not found".into(), |(size, thread, site)| format!(
            "size={size} other_thread={} site={site}",
            thread == tno && thread != me,
            site = frames(site)
        ))
    ));
    go_tx.send(()).unwrap();
    t.join().unwrap();

    // Leaks on several live threads at once.
    let sizes = [1111usize, 2222, 3333];
    let gate = Arc::new(Barrier::new(sizes.len() + 1));
    let workers: Vec<_> = sizes
        .iter()
        .map(|&n| {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let p = leak_in_worker(n);
                gate.wait(); // allocated
                gate.wait(); // reported
                // SAFETY (demo): allocated above with this layout.
                unsafe { A.dealloc(p, lay(n, 8)) };
            })
        })
        .collect();
    gate.wait();
    let mut hits = [(0usize, 0u32, StackId::NONE); 8];
    let mut n = 0;
    debug::leak_report(&mut |l| {
        if sizes.contains(&l.size) && l.thread != me && n < hits.len() {
            hits[n] = (l.size, l.thread, l.stack);
            n += 1;
        }
    });
    gate.wait();
    for w in workers {
        w.join().unwrap();
    }
    let mut found: Vec<(usize, u32, String)> =
        hits[..n].iter().map(|h| (h.0, h.1, frames(h.2))).collect();
    found.sort();
    let mut threads: Vec<u32> = found.iter().map(|f| f.1).collect();
    threads.sort_unstable();
    threads.dedup();
    out.push(format!(
        "leaks_live_threads: sizes={:?} threads={} sites={}",
        found.iter().map(|f| f.0).collect::<Vec<_>>(),
        threads.len(),
        found
            .iter()
            .map(|f| f.2.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    ));

    // At exit with show_stats on: the report is printed.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("atexit")
        .env("RUSTY_ALLOC_SHOW_STATS", "1")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&child.stderr);
    out.push(format!(
        "at_exit_report: {}",
        err.lines()
            .any(|l| l.starts_with("rusty_alloc: leaks: ") && l.ends_with(" bytes still allocated"))
            && err
                .lines()
                .any(|l| l.starts_with("rusty_alloc: stats: threads "))
            && err
                .lines()
                .any(|l| l.starts_with("rusty_alloc: memory: rss "))
    ));

    // Sampled guard pages (upstream's guarded objects, GWP-ASan style), here
    // sampling every allocation: an overflow faults instead of corrupting.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("guarded")
        .env("RUSTY_ALLOC_GUARDED_SAMPLE_RATE", "1")
        .env("RUSTY_ALLOC_GUARDED_MAX", "1048576")
        .env("RUSTY_ALLOC_GUARDED_PRECISE", "1")
        .output()
        .unwrap();
    {
        use std::os::unix::process::ExitStatusExt;
        let sig = child.status.signal();
        out.push(format!(
            "guarded_overflow_faults: {}",
            child.stdout.is_empty() && matches!(sig, Some(libc::SIGSEGV | libc::SIGBUS))
        ));
    }

    // The default handler: report and abort, in a child process.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("abort")
        .output()
        .unwrap();
    out.push(format!(
        "default_handler_stdout: {:?}",
        String::from_utf8_lossy(&child.stdout)
    ));
    out.push(format!(
        "default_handler_stderr: {:?}",
        fold_frames(&String::from_utf8_lossy(&child.stderr))
    ));
    {
        use std::os::unix::process::ExitStatusExt;
        out.push(format!(
            "default_handler_signal: {:?}",
            child.status.signal()
        ));
    }

    let mut so = std::io::stdout().lock();
    for l in out {
        writeln!(so, "{l}").unwrap();
    }
}
