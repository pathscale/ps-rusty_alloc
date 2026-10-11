//! Allocator benchmark harness. One binary per allocator (cargo feature).
//! Usage: malloc-bench <workload> <threads>
//! Prints: alloc=<name> wl=<wl> t=<threads> ms=<wall ms> ns_op=<wall ns per alloc+free pair> chk=<checksum>

#[cfg(feature = "rusty_alloc")]
mod ra_shim;

use std::alloc::{Layout, alloc, dealloc};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::mpsc;
use std::thread;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static A: mimalloc::MiMalloc = mimalloc::MiMalloc; // C reference baseline only
#[cfg(feature = "rusty_alloc")]
#[global_allocator]
static A: ra_shim::RustyAlloc = ra_shim::RustyAlloc;
#[cfg(feature = "smalloc")]
#[global_allocator]
static A: smmalloc::Smalloc = smmalloc::Smalloc::new();
#[cfg(feature = "baby_mimalloc")]
#[global_allocator]
static A: baby_mimalloc::MimallocMmapMutex = baby_mimalloc::new_mimalloc_mmap_mutex();
#[cfg(feature = "rlsf")]
#[global_allocator]
static A: rlsf::GlobalTlsf = rlsf::GlobalTlsf::new();
#[cfg(feature = "dlmalloc")]
#[global_allocator]
static A: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

const NAME: &str = if cfg!(feature = "mimalloc") {
    "mimalloc"
} else if cfg!(feature = "rusty_alloc") {
    "rusty_alloc"
} else if cfg!(feature = "smalloc") {
    "smalloc"
} else if cfg!(feature = "baby_mimalloc") {
    "baby_mimalloc"
} else if cfg!(feature = "rlsf") {
    "rlsf"
} else if cfg!(feature = "dlmalloc") {
    "dlmalloc"
} else {
    "system"
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Ring of live blocks; each op frees a random slot and refills it with a random size.
/// One op = one alloc+free pair.
fn churn(ops: u64, slots: usize, lo: usize, hi: usize, seed: u64, touch_all_pages: bool) -> u64 {
    let mut rng = Rng(seed | 1);
    let mut ring: Vec<(*mut u8, usize)> = vec![(std::ptr::null_mut(), 0); slots];
    let span = (hi - lo + 1) as u64;
    let mut chk = 0u64;
    for i in 0..ops {
        let r = rng.next();
        let idx = (r % slots as u64) as usize;
        let (p, sz) = ring[idx];
        if !p.is_null() {
            unsafe {
                chk = chk.wrapping_add(*p as u64);
                dealloc(p, Layout::from_size_align_unchecked(sz, 8));
            }
        }
        let sz = lo + ((r >> 32) % span) as usize;
        let p = unsafe { alloc(Layout::from_size_align_unchecked(sz, 8)) };
        if p.is_null() {
            eprintln!("alloc failed size={sz}");
            std::process::exit(2);
        }
        unsafe {
            *p = i as u8;
            *p.add(sz - 1) = i as u8;
            if touch_all_pages {
                let mut o = 4096;
                while o < sz {
                    *p.add(o) = i as u8;
                    o += 4096;
                }
            }
        }
        ring[idx] = (p, sz);
    }
    for (p, sz) in ring {
        if !p.is_null() {
            unsafe { dealloc(p, Layout::from_size_align_unchecked(sz, 8)) };
        }
    }
    black_box(chk)
}

fn par<F: Fn(u64) -> u64 + Sync>(threads: usize, f: F) -> u64 {
    if threads == 1 {
        return f(0);
    }
    thread::scope(|s| {
        let f = &f;
        let hs: Vec<_> = (0..threads).map(|t| s.spawn(move || f(t as u64))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).fold(0, u64::wrapping_add)
    })
}

/// Producer/consumer pairs: producers allocate batches of 16..256B blocks,
/// consumers on other threads free them. Every free is cross-thread.
fn xthread(pairs: usize, per_pair: u64) -> u64 {
    const BATCH: usize = 256;
    let mut hs = Vec::new();
    for t in 0..pairs {
        let (tx, rx) = mpsc::sync_channel::<Vec<usize>>(64);
        hs.push(thread::spawn(move || {
            let mut rng = Rng(0x9E3779B97F4A7C15 ^ t as u64);
            let mut left = per_pair;
            while left > 0 {
                let n = (BATCH as u64).min(left) as usize;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let sz = 16 + (rng.next() % 240) as usize;
                    let p = unsafe { alloc(Layout::from_size_align_unchecked(sz, 8)) };
                    unsafe { *p = sz as u8 };
                    v.push(p as usize);
                }
                left -= n as u64;
                tx.send(v).unwrap();
            }
            0u64
        }));
        hs.push(thread::spawn(move || {
            let mut chk = 0u64;
            for v in rx {
                for p in v {
                    let p = p as *mut u8;
                    unsafe {
                        let sz = *p as usize;
                        chk = chk.wrapping_add(sz as u64);
                        dealloc(p, Layout::from_size_align_unchecked(sz, 8));
                    }
                }
            }
            chk
        }));
    }
    hs.into_iter().map(|h| h.join().unwrap()).fold(0, u64::wrapping_add)
}

/// Build and drop String/Vec/HashMap structures, like a parser or indexer would.
fn realistic(iters: u64, seed: u64) -> u64 {
    let mut chk = 0u64;
    let mut rng = Rng(seed ^ 0xA5A5_5A5A_1234_5678);
    for it in 0..iters {
        let n = 4000;
        let mut m: HashMap<String, Vec<u32>> = HashMap::new();
        let mut names: Vec<String> = Vec::new();
        for i in 0..n {
            let k = format!("key-{}-{}", it, rng.next() % 100_000 + i);
            let len = (rng.next() % 48) as u32;
            let v: Vec<u32> = (0..len).collect();
            names.push(k.clone());
            m.insert(k, v);
        }
        for s in names.iter_mut().step_by(3) {
            s.push_str("-suffix-that-forces-a-realloc");
        }
        chk = chk.wrapping_add(m.len() as u64 + names.iter().map(|s| s.len() as u64).sum::<u64>());
        drop(m);
        drop(names);
    }
    black_box(chk)
}

/// Async-runtime-shaped single-thread churn: boxed futures of 32..512B live in a
/// 4096-slot ring and are polled+dropped in random (non-LIFO) order. Each task owns
/// an Arc<[u8]> input (clone/drop churn) and returns an owned output built by
/// iterator chains collected into Vec<u8> and String. Inputs are periodically
/// replaced by freshly collected Arc<[u8]>.
type Task = Pin<Box<dyn Future<Output = usize>>>;

fn work(input: &[u8], salt: u64) -> usize {
    let v: Vec<u8> = input.iter().map(|b| b.wrapping_add(salt as u8)).filter(|b| (*b & 1) == 0).collect();
    let s: String = v.iter().take(24).map(|b| char::from(b"abcdefghijklmnop"[(*b & 15) as usize])).collect();
    v.len() + s.len()
}

fn mk_task(r: u64, input: Arc<[u8]>) -> Task {
    let k = r >> 40;
    match r % 5 {
        0 => {
            let pad = [k; 1];
            Box::pin(async move { work(&input, pad[0]) })
        }
        1 => {
            let pad = [k; 6];
            Box::pin(async move { work(&input, pad[5]) })
        }
        2 => {
            let pad = [k; 14];
            Box::pin(async move { work(&input, pad[13]) })
        }
        3 => {
            let pad = [k; 30];
            Box::pin(async move { work(&input, pad[29]) })
        }
        _ => {
            let pad = [k; 60];
            Box::pin(async move { work(&input, pad[59]) })
        }
    }
}

fn tasks(ops: u64, seed: u64, slots: usize) -> u64 {
    let mut rng = Rng(seed ^ 0x51ED_2701_DEAD_BEEF);
    let mut pool: Vec<Arc<[u8]>> = (0..256u64).map(|i| (0..16 + i).map(|x| x as u8).collect()).collect();
    let mut ring: Vec<Option<Task>> = (0..slots).map(|_| None).collect();
    let mut cx = Context::from_waker(Waker::noop());
    let mut chk = 0u64;
    for i in 0..ops {
        let r = rng.next();
        let idx = (r % slots as u64) as usize;
        if let Some(mut f) = ring[idx].take() {
            if let Poll::Ready(n) = f.as_mut().poll(&mut cx) {
                chk = chk.wrapping_add(n as u64);
            }
        }
        let input = pool[((r >> 16) % 256) as usize].clone();
        ring[idx] = Some(mk_task(r, input));
        if (r >> 8) % 16 == 0 {
            let j = ((r >> 24) % 256) as usize;
            let len = 16 + (r >> 32) % 240;
            pool[j] = (0..len).map(|x| (x ^ i) as u8).collect();
        }
    }
    drop(ring);
    black_box(chk)
}

fn phases(seed: u64) -> u64 {
    let mut rng = Rng(seed ^ 0x7777_1234_ABCD_0001);
    let sizes = [24usize, 48, 96, 200, 400, 1000, 3000, 9000];
    let mut keep: Vec<Vec<u8>> = Vec::new();
    let mut chk = 0u64;
    for &sz in sizes.iter() {
        let n = (64 << 20) / sz;
        let mut v: Vec<Option<Vec<u8>>> = (0..n).map(|i| Some(vec![i as u8; sz])).collect();
        for slot in v.iter_mut() {
            if rng.next() % 10 != 0 {
                *slot = None;
            }
        }
        for b in v.into_iter().flatten() {
            chk = chk.wrapping_add(b[0] as u64);
            keep.push(b);
        }
    }
    chk.wrapping_add(keep.len() as u64)
}

/// Peak RSS so far (getrusage; bytes on macOS).
fn maxrss_mb() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    ru.ru_maxrss as f64 / 1048576.0
}

fn workers(t: usize) -> u64 {
    let mut chk = 0u64;
    for wave in 0..8u64 {
        let hs: Vec<_> = (0..t as u64)
            .map(|id| {
                thread::spawn(move || {
                    let mut m: HashMap<u64, String> = HashMap::new();
                    let mut v: Vec<Vec<u64>> = Vec::new();
                    let mut rng = Rng(wave * 1000 + id + 1);
                    for i in 0..120_000u64 {
                        m.insert(i, format!("worker-{}-{}-{}", wave, id, rng.next()));
                        v.push((0..(rng.next() % 24)).collect());
                    }
                    let c = m.len() as u64 + v.len() as u64;
                    drop(m);
                    drop(v);
                    c
                })
            })
            .collect();
        for h in hs {
            chk = chk.wrapping_add(h.join().unwrap());
        }
        // main thread keeps a little state between waves, like a coordinator
        chk = chk.wrapping_add(realistic(1, wave));
        if std::env::var_os("BENCH_WAVE_RSS").is_some() {
            eprintln!("wave={} maxrss_mb={:.1}", wave, maxrss_mb());
            #[cfg(feature = "rusty_alloc")]
            {
                let ab = rusty_alloc::init::ABANDONED_COUNT.load(std::sync::atomic::Ordering::Relaxed);
                let mut line = String::new();
                rusty_alloc::arena::arenas_print(&mut |s: &str| line.push_str(s.trim()));
                eprintln!("  abandoned_segments={} {}", ab, line);
            }
        }
    }
    chk
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let wl = a.get(1).map(String::as_str).unwrap_or("small");
    let t: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    // BENCH_PROFILE_SLEEP_MS: pause before work so a sampler can attach.
    if let Some(ms) = std::env::var("BENCH_PROFILE_SLEEP_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
        thread::sleep(std::time::Duration::from_millis(ms));
    }
    let start = Instant::now();
    // second value = ops per thread, for ns_op normalisation
    let (chk, ops): (u64, u64) = match wl {
        // (a)/(b) small mixed 16..255B, 1024 live per thread
        "small" => {
            let ops = 20_000_000;
            (par(t, move |id| churn(ops, 1024, 16, 255, 0x1234 + id * 7919, false)), ops)
        }
        // (c) cross-thread free, t = producer/consumer pairs
        "xthread" => {
            let ops = 10_000_000;
            (xthread(t, ops), ops)
        }
        // (d) String/Vec/HashMap build+drop; ops = iterations
        "realistic" => {
            let it = 150;
            (par(t, move |id| realistic(it, id)), it)
        }
        // (f) async-runtime shape: boxed futures, Arc churn, iterator collects
        "tasks" => {
            let ops = 2_000_000;
            (par(t, move |id| tasks(ops, id, 4096)), ops)
        }
        // (f2) same with 256K live tasks (~100MB working set)
        "tasksbig" => {
            let ops = 2_000_000;
            (par(t, move |id| tasks(ops, id, 262_144)), ops)
        }
        // (g) size-class phases: 8 phases x 64MB of one size; 90% freed randomly, 10% survive
        "phases" => (par(t, move |id| phases(id)), 8),
        // (h) worker waves: 8 waves of t threads, each builds ~24MB of maps/strings, drops, exits
        "workers" => (workers(t), 8),
        // (e) 4KB..1MB, 32 live per thread, touch every page
        "large" => {
            let ops = 200_000;
            (par(t, move |id| churn(ops, 32, 4096, 1 << 20, 0xBEEF + id, true)), ops)
        }
        _ => {
            eprintln!("unknown workload {wl}");
            std::process::exit(1);
        }
    };
    let ns = start.elapsed().as_nanos() as f64;
    println!(
        "alloc={} wl={} t={} ms={:.2} ns_op={:.2} chk={}",
        NAME,
        wl,
        t,
        ns / 1e6,
        ns / ops as f64,
        chk
    );
}
