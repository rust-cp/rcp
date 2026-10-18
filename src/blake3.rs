//! BLAKE3, from the official `blake3` crate (the reference implementation by the BLAKE3
//! authors). The fast digest for copy verification, beside SHA-256 which stays the default
//! because FIPS names it.
//!
//! The crate builds its SIMD kernels (SSE2, SSE4.1, AVX2, AVX-512 on x86-64, NEON on
//! AArch64) and picks one at run time. Its Rayon multithreading is not enabled: one core
//! of the AVX-512 kernel already outruns the storage rcp copies between, and a copy is
//! already parallel over files.

#[cfg(test)]
const CHUNK_LEN: usize = 1024;

pub struct Blake3 {
    inner: blake3::Hasher,
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    pub fn new() -> Blake3 {
        Blake3 {
            inner: blake3::Hasher::new(),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.inner.finalize().as_bytes()
    }

    pub fn hex(&self) -> String {
        crate::sha256::to_hex(&self.finalize())
    }
}

pub fn digest_hex(data: &[u8]) -> String {
    let mut h = Blake3::new();
    h.update(data);
    h.hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official test-vector input: byte i is i mod 251.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn blake3_matches_the_official_vectors_either_side_of_a_chunk_boundary() {
        assert_eq!(
            digest_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            digest_hex(&pattern(1)),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
        assert_eq!(
            digest_hex(&pattern(1024)),
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        );
        assert_eq!(
            digest_hex(&pattern(1025)),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );
        assert_eq!(
            digest_hex(&pattern(2048)),
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"
        );
        assert_eq!(
            digest_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn incremental_equals_one_shot_at_every_kind_of_split() {
        let data = pattern(7 * CHUNK_LEN + 300);
        let whole = digest_hex(&data);
        for split in [
            1,
            63,
            64,
            65,
            1023,
            1024,
            1025,
            2048,
            4096,
            4097,
            data.len() - 1,
        ] {
            let mut h = Blake3::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.hex(), whole, "split at {split}");
        }
        let mut h = Blake3::new();
        for b in data.chunks(7) {
            h.update(b);
        }
        assert_eq!(h.hex(), whole, "seven bytes at a time");
    }

    #[test]
    fn large_updates_equal_chunk_at_a_time_updates() {
        // a large update takes the crate's wide SIMD path over many chunks at once; the
        // digest must not depend on it, including at a length that leaves a partial last
        // chunk
        for len in [128 * CHUNK_LEN + 1, 512 * CHUNK_LEN + 777, 1_000_000] {
            let data = pattern(len);
            let mut serial = Blake3::new();
            for b in data.chunks(CHUNK_LEN) {
                serial.update(b);
            }
            assert_eq!(digest_hex(&data), serial.hex(), "len {len}");
        }
    }

    #[test]
    fn control_a_changed_byte_changes_the_digest() {
        let mut data = pattern(3000);
        let a = digest_hex(&data);
        data[2999] ^= 1;
        assert_ne!(digest_hex(&data), a);
    }
}
