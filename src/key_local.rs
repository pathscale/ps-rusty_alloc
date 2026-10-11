//! Thread-locals for a multi-threaded `no_std` build on unix: one pthread key
//! per variable.
//!
//! `std::thread_local!` is not available without `std`, and the native
//! `#[thread_local]` attribute is nightly-only. What every hosted unix has is
//! POSIX thread-specific data, which is what upstream mimalloc falls back to
//! wherever it cannot use `__thread` (`MI_TLS_PTHREAD`), and what this crate
//! already uses for its thread-exit hook (`init::done_slot`).
//!
//! Each [`KeyLocal`] holds one pointer-sized word per thread, stored directly in
//! the key's slot: no per-thread block, no allocation, nothing to free at
//! thread exit. The key is created on the first `set` and published with one
//! compare-exchange; a thread that loses the race deletes its own key. Nobody
//! waits for anybody. A `get` before any thread has set the variable needs no
//! key at all: the answer is the initial value.
//!
//! A fresh thread reads NULL from every key, so the stored word is the value
//! XOR the initial value: NULL decodes to the initial value without a "was it
//! set" flag, and a variable whose initial value is a sentinel pointer (the
//! empty heap) needs no first-touch branch. Pointers go through `map_addr`, so
//! a stored pointer keeps its provenance.
//!
//! On Apple targets a read skips the call: `pthread_getspecific(key)` is
//! `tsd[key]`, where `tsd` is the thread pointer (`tpidrro_el0` with its low
//! three CPU-number bits masked on arm64, `gs` on x86-64). That is the inline
//! `_pthread_getspecific_direct` libpthread itself is built on, and what
//! mimalloc's `mi_prim_tls_slot` reads. Debug builds check it against the
//! call on every read.

use core::cell::Cell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// A value that fits a TSD slot: encoded against the initial value so a NULL
/// slot means "never set on this thread".
pub trait KeyWord: Copy {
    /// The slot contents for `self`; NULL exactly when `self == init`.
    fn encode(self, init: Self) -> *mut c_void;
    /// Inverse of [`KeyWord::encode`].
    fn decode(raw: *mut c_void, init: Self) -> Self;
}

impl KeyWord for bool {
    #[inline(always)]
    fn encode(self, init: Self) -> *mut c_void {
        ptr::without_provenance_mut(usize::from(self ^ init))
    }
    #[inline(always)]
    fn decode(raw: *mut c_void, init: Self) -> Self {
        init ^ (raw.addr() != 0)
    }
}

impl KeyWord for usize {
    #[inline(always)]
    fn encode(self, init: Self) -> *mut c_void {
        ptr::without_provenance_mut(self ^ init)
    }
    #[inline(always)]
    fn decode(raw: *mut c_void, init: Self) -> Self {
        raw.addr() ^ init
    }
}

impl<T> KeyWord for *mut T {
    #[inline(always)]
    fn encode(self, init: Self) -> *mut c_void {
        self.cast::<c_void>().map_addr(|a| a ^ init.addr())
    }
    #[inline(always)]
    fn decode(raw: *mut c_void, init: Self) -> Self {
        if raw.is_null() {
            init
        } else {
            raw.cast::<T>().map_addr(|a| a ^ init.addr())
        }
    }
}

/// One thread-local word in a pthread key. The `no_std` arm of
/// `ra_thread_local!`; see the module docs.
pub struct KeyLocal<T> {
    /// `pthread_key_t + 1`; 0 until the first `set` anywhere.
    key: AtomicUsize,
    init: T,
}

// SAFETY: `init` is written once, at compile time, and only ever copied out;
// every per-thread value lives in that thread's own TSD slot, which no other
// thread can reach through this type. `key` is an atomic.
unsafe impl<T> Sync for KeyLocal<T> {}

impl<T: KeyWord> KeyLocal<T> {
    /// A variable whose value on every thread starts as `init`.
    pub const fn new(init: Cell<T>) -> Self {
        Self {
            key: AtomicUsize::new(0),
            init: init.into_inner(),
        }
    }

    /// Mirrors `LocalKey::with`, the only accessor the crate uses; the
    /// closure gets this variable, whose `get` and `set` act on the calling
    /// thread's value.
    #[inline(always)]
    pub fn with<R>(&'static self, f: impl FnOnce(&Self) -> R) -> R {
        f(self)
    }

    /// The calling thread's value.
    #[inline(always)]
    pub fn get(&self) -> T {
        let k = self.key.load(Ordering::Acquire);
        if k == 0 {
            // No thread has ever set it, so every thread holds `init`.
            return self.init;
        }
        T::decode(slot_get((k - 1) as libc::pthread_key_t), self.init)
    }

    /// Set the calling thread's value.
    #[inline(always)]
    pub fn set(&self, v: T) {
        let k = self.key.load(Ordering::Acquire);
        let key = if k == 0 {
            self.create()
        } else {
            (k - 1) as libc::pthread_key_t
        };
        // SAFETY: `key` came from a successful `pthread_key_create` and is
        // never deleted once published. A failure (ENOMEM for a key past the
        // first block on glibc) leaves the old value, which is never a value
        // this crate cannot handle: every variable here is a cache or a
        // guard that falls back to its initial value.
        unsafe {
            libc::pthread_setspecific(key, v.encode(self.init));
        }
    }

    /// Create the key and publish it, or adopt the one another thread
    /// published first. Lock-free: the loser deletes its own key.
    #[cold]
    #[inline(never)]
    fn create(&self) -> libc::pthread_key_t {
        let mut key: libc::pthread_key_t = 0;
        // SAFETY: out-param is a live local; no destructor, the slot holds a
        // plain word.
        if unsafe { libc::pthread_key_create(&raw mut key, None) } != 0 {
            // Out of keys. Thread-locals are not optional for an allocator,
            // and there is no caller to return an error to.
            crate::abort();
        }
        match self
            .key
            .compare_exchange(0, key as usize + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => key,
            Err(won) => {
                // SAFETY: our own key, never published, never set.
                unsafe { libc::pthread_key_delete(key) };
                (won - 1) as libc::pthread_key_t
            }
        }
    }
}

/// `pthread_getspecific(key)`, inline on Apple targets.
#[inline(always)]
fn slot_get(key: libc::pthread_key_t) -> *mut c_void {
    #[cfg(all(target_vendor = "apple", target_arch = "aarch64", not(miri)))]
    {
        let tp: usize;
        // SAFETY: read-only system-register read; see `init::thread_id` for
        // why it is `tpidrro_el0` on Darwin and why the low 3 bits go.
        unsafe {
            core::arch::asm!("mrs {}, tpidrro_el0", out(reg) tp,
                             options(nomem, nostack, preserves_flags));
        }
        let tsd = ptr::with_exposed_provenance::<*mut c_void>(tp & !0b111);
        // SAFETY: `tsd` is this thread's TSD array, which holds a slot for
        // every valid key; `key` is a valid key.
        let v = unsafe { tsd.add(key as usize).read() };
        // SAFETY: as `set`.
        debug_assert!(v == unsafe { libc::pthread_getspecific(key) });
        v
    }
    #[cfg(all(target_vendor = "apple", target_arch = "x86_64", not(miri)))]
    {
        let v: *mut c_void;
        // SAFETY: `gs` addresses this thread's TSD array on x86-64 Darwin;
        // slot `key` exists for every valid key. A read.
        unsafe {
            core::arch::asm!("mov {v}, qword ptr gs:[{k}*8]", k = in(reg) key as usize,
                             v = out(reg) v, options(nostack, preserves_flags, readonly));
        }
        // SAFETY: as `set`.
        debug_assert!(v == unsafe { libc::pthread_getspecific(key) });
        v
    }
    #[cfg(not(all(
        target_vendor = "apple",
        any(target_arch = "aarch64", target_arch = "x86_64"),
        not(miri)
    )))]
    // SAFETY: `key` is a valid key; `pthread_getspecific` has no other
    // precondition.
    unsafe {
        libc::pthread_getspecific(key)
    }
}
