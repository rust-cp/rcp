//! The digest adapters behind the `Digests` port; the driving adapter picks one and puts
//! it in the `Runtime`.
//!
//! Four, and they answer different questions:
//!
//! - **SHA-256**, the default, and the one a published spec names. Cryptographic.
//! - **BLAKE3** (`-blake3`), several times faster per core and parallel over chunks.
//!   Cryptographic, and not on the FIPS list.
//! - **XXH3-64** (`-xxh3`) and **XXH3-128** (`-xxh128`), for INTERCHANGE: they are what
//!   rsync's `--checksum-choice` and rclone's hashes speak, so a number rcp prints can be
//!   compared with a number another tool printed. **Neither is cryptographic** -- a
//!   chosen collision is cheap -- so they belong on a verify between two trees one
//!   operator controls, and nowhere that an adversary picks the bytes.

use std::sync::Arc;

use crate::blake3::Blake3;
use crate::ports::{Digest, Digests};
use crate::sha256::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha256,
    Blake3,
    Xxh3,
    Xxh128,
}

impl Algorithm {
    /// The name a report column or a `version` line uses.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Blake3 => "blake3",
            Algorithm::Xxh3 => "xxh3",
            Algorithm::Xxh128 => "xxh128",
        }
    }
    /// The algorithm a name on the wire or in a report means, if any.
    pub fn by_name(name: &str) -> Option<Algorithm> {
        match name {
            "sha256" => Some(Algorithm::Sha256),
            "blake3" => Some(Algorithm::Blake3),
            "xxh3" => Some(Algorithm::Xxh3),
            "xxh128" => Some(Algorithm::Xxh128),
            _ => None,
        }
    }
    /// The port adapter for this algorithm.
    pub fn digests(self) -> Arc<dyn Digests> {
        match self {
            Algorithm::Sha256 => Arc::new(Sha256Digests),
            Algorithm::Blake3 => Arc::new(Blake3Digests),
            Algorithm::Xxh3 => Arc::new(Xxh3Digests { wide: false }),
            Algorithm::Xxh128 => Arc::new(Xxh3Digests { wide: true }),
        }
    }
}

pub struct Sha256Digests;

impl Digests for Sha256Digests {
    fn name(&self) -> &'static str {
        "sha256"
    }
    fn start(&self) -> Box<dyn Digest> {
        Box::new(Sha256::new())
    }
}

impl Digest for Sha256 {
    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data)
    }
    fn finish(self: Box<Self>) -> String {
        (*self).hex()
    }
}

pub struct Blake3Digests;

impl Digests for Blake3Digests {
    fn name(&self) -> &'static str {
        "blake3"
    }
    fn start(&self) -> Box<dyn Digest> {
        Box::new(Blake3::new())
    }
}

impl Digest for Blake3 {
    fn update(&mut self, data: &[u8]) {
        Blake3::update(self, data)
    }
    fn finish(self: Box<Self>) -> String {
        self.hex()
    }
}

pub struct Xxh3Digests {
    wide: bool,
}

impl Digests for Xxh3Digests {
    fn name(&self) -> &'static str {
        if self.wide {
            "xxh128"
        } else {
            "xxh3"
        }
    }
    fn start(&self) -> Box<dyn Digest> {
        Box::new(crate::xxh3::Xxh3::new(self.wide))
    }
}

impl Digest for crate::xxh3::Xxh3 {
    fn update(&mut self, data: &[u8]) {
        crate::xxh3::Xxh3::update(self, data)
    }
    fn finish(self: Box<Self>) -> String {
        self.hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_adapters_stream_and_name_themselves() {
        for (alg, expect) in [
            (
                Algorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Blake3,
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
        ] {
            let d = alg.digests();
            assert_eq!(d.name(), alg.name());
            let mut h = d.start();
            h.update(b"ab");
            h.update(b"c");
            assert_eq!(h.finish(), expect);
        }
    }
}
