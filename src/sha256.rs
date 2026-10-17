//! SHA-256 (FIPS 180-4), implemented here so the binary builds with no crates.io access.
//!
//! Two compression functions: a portable one, and one on the x86 SHA extensions (`sha_ni`),
//! chosen once at runtime. On a CPU with the extensions the hardware path runs about five
//! times faster than the portable one, which is what keeps content hashing off the critical
//! path of a copy. Both are checked against the standard vectors, and against each other,
//! in the tests below.

use std::sync::atomic::{AtomicU8, Ordering};

pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 0 = undecided, 1 = portable, 2 = hardware.
static BACKEND: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Portable,
    HardwareShaNi,
}

pub fn backend() -> Backend {
    match BACKEND.load(Ordering::Relaxed) {
        1 => Backend::Portable,
        2 => Backend::HardwareShaNi,
        _ => {
            let b = if hardware_available() {
                Backend::HardwareShaNi
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

#[cfg(target_arch = "x86_64")]
fn hardware_available() -> bool {
    std::env::var_os("RCP_NO_SHA_NI").is_none()
        && std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse4.1")
        && std::arch::is_x86_feature_detected!("ssse3")
}

#[cfg(not(target_arch = "x86_64"))]
fn hardware_available() -> bool {
    false
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: INITIAL,
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length += data.len() as u64;
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                compress_blocks(&mut self.state, &block);
                self.buffered = 0;
            }
        }
        let whole = data.len() - data.len() % 64;
        if whole > 0 {
            compress_blocks(&mut self.state, &data[..whole]);
            data = &data[whole..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0]);
        }
        self.update(&bit_length.to_be_bytes());
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn hex(self) -> String {
        to_hex(&self.finalize())
    }
}

/// `data.len()` is a multiple of 64.
fn compress_blocks(state: &mut [u32; 8], data: &[u8]) {
    debug_assert_eq!(data.len() % 64, 0);
    #[cfg(target_arch = "x86_64")]
    if backend() == Backend::HardwareShaNi {
        // SAFETY: hardware_available detected SHA, SSSE3 and SSE4.1 before caching this
        // backend; SSE2 is guaranteed by x86-64. state is eight initialized u32s, and
        // callers supply whole 64-byte
        // blocks, so the intrinsic loads/stores stay within the borrowed allocations.
        unsafe { shani::compress(state, data) };
        return;
    }
    for block in data.chunks_exact(64) {
        compress_portable(state, block.try_into().expect("64-byte block"));
    }
}

fn compress_portable(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("4 bytes"));
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(target_arch = "x86_64")]
mod shani {
    //! The Intel SHA extensions path: four rounds per `sha256rnds2`, message schedule by
    //! `sha256msg1`/`sha256msg2`. State is held in the ABEF/CDGH lane order the instructions
    //! want and shuffled back on the way out.
    use super::K;
    use std::arch::x86_64::*;

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    // SAFETY contract: the caller must establish all four target features and supply
    // complete SHA-256 blocks. Only compress_blocks calls this private-module function.
    pub unsafe fn compress(state: &mut [u32; 8], data: &[u8]) {
        // SAFETY: the feature precondition is established by compress_blocks. Two 16-byte
        // unaligned accesses cover exactly state[0..8]; each chunks_exact(64) block permits
        // four 16-byte loads. rounds4 indexes K at 4*i for i=0..15, so its final load covers
        // K[60..64]. Mutable state and immutable input cannot alias through safe borrows.
        unsafe {
            let mask = _mm_set_epi64x(
                0x0c0d_0e0f_0809_0a0bu64 as i64,
                0x0405_0607_0001_0203u64 as i64,
            );
            let dcba = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            let efgh = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);
            let cdab = _mm_shuffle_epi32(dcba, 0xb1);
            let efgh = _mm_shuffle_epi32(efgh, 0x1b);
            let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
            let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);

            macro_rules! rounds4 {
                ($abef:ident, $cdgh:ident, $w:expr, $i:expr) => {{
                    let k = _mm_loadu_si128(K.as_ptr().add(4 * $i) as *const __m128i);
                    let t1 = _mm_add_epi32($w, k);
                    $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
                    let t2 = _mm_shuffle_epi32(t1, 0x0e);
                    $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
                }};
            }
            macro_rules! schedule {
                ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
                    let t1 = _mm_sha256msg1_epu32($v0, $v1);
                    let t2 = _mm_alignr_epi8($v3, $v2, 4);
                    let t3 = _mm_add_epi32(t1, t2);
                    _mm_sha256msg2_epu32(t3, $v3)
                }};
            }
            macro_rules! schedule_rounds4 {
                ($abef:ident, $cdgh:ident, $w0:ident, $w1:ident, $w2:ident, $w3:ident, $w4:ident, $i:expr) => {{
                    $w4 = schedule!($w0, $w1, $w2, $w3);
                    rounds4!($abef, $cdgh, $w4, $i);
                }};
            }

            for block in data.chunks_exact(64) {
                let abef_save = abef;
                let cdgh_save = cdgh;
                let p = block.as_ptr() as *const __m128i;
                let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(p), mask);
                let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(1)), mask);
                let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(2)), mask);
                let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(3)), mask);
                let mut w4;

                rounds4!(abef, cdgh, w0, 0);
                rounds4!(abef, cdgh, w1, 1);
                rounds4!(abef, cdgh, w2, 2);
                rounds4!(abef, cdgh, w3, 3);
                schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
                schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
                schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
                schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
                schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
                schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
                schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
                schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
                schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
                schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
                schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
                schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);

                abef = _mm_add_epi32(abef, abef_save);
                cdgh = _mm_add_epi32(cdgh, cdgh_save);
            }

            let feba = _mm_shuffle_epi32(abef, 0x1b);
            let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
            let dcba = _mm_blend_epi16(feba, dchg, 0xf0);
            let hgef = _mm_alignr_epi8(dchg, feba, 8);
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, dcba);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, hgef);
        }
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn digest_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.hex()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn portable_hex(data: &[u8]) -> String {
        let mut state = INITIAL;
        let mut padded = data.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
        for block in padded.chunks_exact(64) {
            compress_portable(&mut state, block.try_into().unwrap());
        }
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        to_hex(&out)
    }

    #[test]
    fn sha256_matches_the_fips_180_vectors_including_a_million_a() {
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut h = Sha256::new();
        for _ in 0..1_000_000 {
            h.update(b"a");
        }
        assert_eq!(
            h.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn selected_backend_agrees_with_the_portable_one_on_every_length() {
        // The portable function is the reference; whichever backend `digest_hex` picked must
        // match it on lengths that cross every block boundary, in one call and byte by byte.
        eprintln!("backend: {:?}", backend());
        let mut data = Vec::new();
        for i in 0..700u32 {
            data.push((i.wrapping_mul(2654435761) >> 13) as u8);
            let one_shot = digest_hex(&data);
            assert_eq!(one_shot, portable_hex(&data), "length {}", data.len());
            if i % 97 == 0 {
                let mut h = Sha256::new();
                for b in &data {
                    h.update(std::slice::from_ref(b));
                }
                assert_eq!(h.hex(), one_shot, "incremental at length {}", data.len());
            }
        }
    }
}
