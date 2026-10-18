//! SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), from the RustCrypto `sha2` and `hmac`
//! crates.
//!
//! `sha2` selects its compression function at run time: the x86 SHA extensions (SHA-NI) or
//! the ARMv8 SHA-2 instructions where the CPU has them, a portable implementation
//! otherwise. That is what keeps content hashing off the critical path of a copy. The thin
//! wrapper here keeps the streaming interface the rest of the crate uses, and the tests
//! below pin it to the FIPS 180 and RFC 4231 vectors.
//!
//! `RCP_NO_SHA_NI` used to force the portable path of rcp's own implementation. It is still
//! accepted and is now a no-op: the crate's selection cannot be overridden at run time.

pub struct Sha256 {
    inner: sha2::Sha256,
}

/// What the CPU offers `sha2`, for `rcp version`. Detection only: the crate chooses for
/// itself, so this reports what it will find rather than steering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Portable,
    HardwareShaNi,
    HardwareArmSha2,
}

pub fn backend() -> Backend {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse4.1")
        && std::arch::is_x86_feature_detected!("ssse3")
    {
        return Backend::HardwareShaNi;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        return Backend::HardwareArmSha2;
    }
    Backend::Portable
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            inner: <sha2::Sha256 as sha2::Digest>::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.inner, data);
    }

    pub fn finalize(self) -> [u8; 32] {
        sha2::Digest::finalize(self.inner).into()
    }

    pub fn hex(self) -> String {
        to_hex(&self.finalize())
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
    use hmac::{KeyInit, Mac};
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn hmac_sha256_matches_rfc_4231_including_the_long_key_case() {
        // RFC 4231 test cases 1 and 6: a short key, and a key longer than the block size,
        // which HMAC hashes first.
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            to_hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn incremental_updates_equal_the_one_shot_digest_on_every_length() {
        // Lengths that cross every block boundary, fed in one call and byte by byte: the
        // streaming wrapper must agree with the one-shot digest everywhere.
        let mut data = Vec::new();
        for i in 0..700u32 {
            data.push((i.wrapping_mul(2654435761) >> 13) as u8);
            let one_shot = digest_hex(&data);
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
