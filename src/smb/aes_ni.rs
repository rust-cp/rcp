//! AES-128 encryption on the AES-NI instructions, for SMB message signing.
//!
//! Exists because of a measurement, not a preference. Signing 1 MiB with the table-driven
//! `Aes128` in `sign.rs` took 12.785 ms -- about 78 MB/s -- and on a session that requires
//! signing that is a ceiling on every byte written, well below what a 10 GbE link carries.
//! AES-CMAC is CBC-chained, so blocks cannot be computed in parallel; the speed comes from
//! doing each block in a handful of `aesenc` instructions and keeping the running state in
//! a register for the whole message instead of round-tripping it through memory.
//!
//! The round keys are the SAME bytes `Aes128::new` already expands: FIPS-197's key schedule,
//! in the byte order `aesenc` consumes directly. So there is one key schedule, one source of
//! truth, and the only thing that differs between the two paths is how a round is computed
//! -- which is exactly what the differential arm in `sign.rs` compares.
//!
//! Selection mirrors `sha256.rs`: detected once, cached, overridable with `RCP_NO_AES_NI`.
//! A fast path that is silently never taken passes every correctness test there is, so
//! test builds also COUNT entries into the hardware cipher, and the arm in `sign.rs` asks
//! whether a real `sign` call entered it. Asking `backend()` instead checks the selection
//! and not the call site: a call site hardwired to the portable cipher would leave
//! `backend()` reporting hardware and every arm green.

use std::sync::atomic::{AtomicU8, Ordering};

/// 0 = undecided, 1 = portable, 2 = hardware.
static BACKEND: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Portable,
    HardwareAesNi,
}

pub fn backend() -> Backend {
    match BACKEND.load(Ordering::Relaxed) {
        1 => Backend::Portable,
        2 => Backend::HardwareAesNi,
        _ => {
            let b = if hardware_available() {
                Backend::HardwareAesNi
            } else {
                Backend::Portable
            };
            BACKEND.store(
                if b == Backend::Portable { 1 } else { 2 },
                Ordering::Relaxed,
            );
            b
        }
    }
}

/// Whether this CPU can run the hardware path at all, independent of the override. Arms use
/// it to decide whether they can demand the hardware path, rather than skipping silently.
#[cfg(target_arch = "x86_64")]
pub fn cpu_has_aes_ni() -> bool {
    std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn cpu_has_aes_ni() -> bool {
    false
}

fn hardware_available() -> bool {
    select(
        std::env::var_os("RCP_NO_AES_NI").is_some(),
        cpu_has_aes_ni(),
    ) == Backend::HardwareAesNi
}

/// The decision itself, with its two inputs passed in rather than read.
///
/// Split out because the decision could not otherwise be tested: `backend()` is cached for
/// the life of the process, so an arm cannot set `RCP_NO_AES_NI` and observe the override
/// after anything has signed -- and setting it would change every other arm in the run.
/// A pure function of the two facts can be checked on all four combinations.
pub(crate) fn select(overridden: bool, cpu: bool) -> Backend {
    if cpu && !overridden {
        Backend::HardwareAesNi
    } else {
        Backend::Portable
    }
}

/// How many times THIS THREAD has entered the hardware cipher. Test builds only.
///
/// Asserting what `backend()` reports proves nothing about the call site: forcing
/// `aes_cmac` onto the portable cipher leaves `backend()` saying hardware and every arm
/// green. Counting entries here observes the path that actually ran. Thread-local, so arms
/// running in parallel cannot add to each other's count.
#[cfg(test)]
pub(crate) fn hardware_entries() -> usize {
    HARDWARE_ENTRIES.with(|c| c.get())
}

#[cfg(test)]
thread_local! {
    static HARDWARE_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Refuses to run the hardware cipher on a CPU without it.
///
/// A REAL assert, not a `debug_assert`. These functions are safe to call, so the check is
/// the only thing standing between a caller that skipped `cpu_has_aes_ni()` and an
/// illegal-instruction fault -- which kills the process with no message naming the cause.
/// In a release build a `debug_assert` is no check at all, so the safe signature would be a
/// promise the code did not keep. The cost is one load of a flag the standard library
/// caches after its first detection.
#[cfg(target_arch = "x86_64")]
fn require_hardware() {
    assert!(
        cpu_has_aes_ni(),
        "the AES-NI cipher was entered on a CPU without AES-NI"
    );
    #[cfg(test)]
    HARDWARE_ENTRIES.with(|c| c.set(c.get() + 1));
}

/// Encrypts one block in place. Panics on a CPU without AES-NI rather than faulting.
#[cfg(target_arch = "x86_64")]
pub fn encrypt_block(round_keys: &[[u8; 16]; 11], block: &mut [u8; 16]) {
    require_hardware();
    // SAFETY: `require_hardware` has just established the target features, and every load
    // and store is unaligned and within a 16-byte array.
    unsafe { encrypt_block_ni(round_keys, block) }
}

/// Absorbs whole 16-byte blocks into a CBC-MAC state: for each block, `x ^= block` then
/// encrypt `x`. `data.len()` must be a multiple of 16: a trailing partial block would be
/// silently dropped by the kernel, so it is refused instead. Panics on a CPU without AES-NI
/// rather than faulting.
#[cfg(target_arch = "x86_64")]
pub fn cbc_absorb(round_keys: &[[u8; 16]; 11], x: &mut [u8; 16], data: &[u8]) {
    require_hardware();
    assert_eq!(data.len() % 16, 0, "cbc_absorb takes whole blocks only");
    // SAFETY: as above; `chunks_exact(16)` guarantees every load reads 16 in-bounds bytes.
    unsafe { cbc_absorb_ni(round_keys, x, data) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn load_keys(round_keys: &[[u8; 16]; 11]) -> [std::arch::x86_64::__m128i; 11] {
    // SAFETY: callers run under the same aes,sse2 target features, established by the
    // safe entry points. Each rk is an initialized 16-byte array, and loadu needs no
    // stronger alignment; the zipped iteration never exceeds the eleven key slots.
    unsafe {
        use std::arch::x86_64::*;
        let mut k = [_mm_setzero_si128(); 11];
        for (slot, rk) in k.iter_mut().zip(round_keys.iter()) {
            *slot = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        }
        k
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn rounds(
    k: &[std::arch::x86_64::__m128i; 11],
    s: std::arch::x86_64::__m128i,
) -> std::arch::x86_64::__m128i {
    // SAFETY contract: both callers have aes,sse2 enabled after require_hardware. The
    // fixed eleven-key array covers k[0], k[1..10] and k[10]; operations use registers
    // only, with no pointer accesses or alignment requirements.
    use std::arch::x86_64::*;
    // AddRoundKey, nine full rounds, and a last round without MixColumns -- the same shape
    // as `Aes128::encrypt_block`, which is why the two can be compared byte for byte.
    let mut s = _mm_xor_si128(s, k[0]);
    for rk in &k[1..10] {
        s = _mm_aesenc_si128(s, *rk);
    }
    _mm_aesenclast_si128(s, k[10])
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_block_ni(round_keys: &[[u8; 16]; 11], block: &mut [u8; 16]) {
    // SAFETY: encrypt_block checked aes,sse2 before calling. load_keys and rounds share
    // those features. block is exactly sixteen initialized, exclusively borrowed bytes;
    // the unaligned load/store each touch only that array and retain no pointers.
    unsafe {
        use std::arch::x86_64::*;
        let k = load_keys(round_keys);
        let s = rounds(&k, _mm_loadu_si128(block.as_ptr() as *const __m128i));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
unsafe fn cbc_absorb_ni(round_keys: &[[u8; 16]; 11], x: &mut [u8; 16], data: &[u8]) {
    // SAFETY: cbc_absorb checked aes,sse2 and the whole-block length. x is a mutable
    // 16-byte array and chunks_exact yields only in-bounds 16-byte data blocks. All loads
    // and the final store are unaligned; load_keys/rounds have identical target features.
    unsafe {
        use std::arch::x86_64::*;
        let k = load_keys(round_keys);
        // The state stays in a register for the whole message; that, not the instruction count
        // of one block, is most of the difference from the table-driven path.
        let mut s = _mm_loadu_si128(x.as_ptr() as *const __m128i);
        for block in data.chunks_exact(16) {
            s = _mm_xor_si128(s, _mm_loadu_si128(block.as_ptr() as *const __m128i));
            s = rounds(&k, s);
        }
        _mm_storeu_si128(x.as_mut_ptr() as *mut __m128i, s);
    }
}
