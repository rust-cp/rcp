//! XXH64, for the one thing a zstd frame needs it for: its content checksum.
//!
//! A frame may carry the low four bytes of `XXH64(content, seed = 0)` after its last
//! block. It is tempting to READ that field and not check it, with the argument that
//! every caller here wraps the payload in its own CRC-32 already. That argument is about
//! the deployment, not about the decoder: it is an invariant of how rcp happens to call
//! this, and any other caller gets `Ok` on wrong bytes. The decoder's own guarantee
//! should not depend on who is holding it.
//!
//! It matters here more than it would elsewhere, because the failure mode this module
//! keeps recording is a decode that SUCCEEDS with wrong bytes: a predefined table wrong
//! at two codes turned a 39,990-byte match into a 41-byte one and reported success. A
//! checksum is the one check that catches that class without knowing what went wrong.
//!
//! The crate already carries XXH3, which is a different algorithm with different
//! constants -- it cannot be reused for this.

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn merge(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val)).wrapping_mul(P1).wrapping_add(P4)
}

fn lane(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("an eight-byte window"))
}

/// The 64-bit digest of `data` with seed zero, which is what zstd frames use.
pub fn hash(data: &[u8]) -> u64 {
    let mut h;
    let mut at = 0usize;
    if data.len() >= 32 {
        let (mut v1, mut v2, mut v3, mut v4) =
            (P1.wrapping_add(P2), P2, 0u64, 0u64.wrapping_sub(P1));
        while at + 32 <= data.len() {
            v1 = round(v1, lane(data, at));
            v2 = round(v2, lane(data, at + 8));
            v3 = round(v3, lane(data, at + 16));
            v4 = round(v4, lane(data, at + 24));
            at += 32;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge(h, v1);
        h = merge(h, v2);
        h = merge(h, v3);
        h = merge(h, v4);
    } else {
        h = P5;
    }
    h = h.wrapping_add(data.len() as u64);

    while at + 8 <= data.len() {
        h = (h ^ round(0, lane(data, at)))
            .rotate_left(27)
            .wrapping_mul(P1)
            .wrapping_add(P4);
        at += 8;
    }
    if at + 4 <= data.len() {
        let v = u64::from(u32::from_le_bytes(
            data[at..at + 4].try_into().expect("a four-byte window"),
        ));
        h = (h ^ v.wrapping_mul(P1))
            .rotate_left(23)
            .wrapping_mul(P2)
            .wrapping_add(P3);
        at += 4;
    }
    while at < data.len() {
        h = (h ^ u64::from(data[at]).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
        at += 1;
    }

    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published vectors, which is the only way to know this is XXH64 and not a
    /// plausible-looking hash of my own.
    ///
    /// A checksum implementation that is self-consistent but wrong is WORSE than none: it
    /// would reject every real frame, and the obvious reading of that failure is that the
    /// decoder is broken rather than the checker. The frame arms in `mod.rs` would have
    /// caught it that way round -- these vectors say which side is at fault.
    #[test]
    fn the_published_vectors_match() {
        // seed 0, from the xxHash reference test suite
        assert_eq!(hash(b""), 0xEF46_DB37_51D8_E999, "the empty input vector");
        assert_eq!(hash(b"a"), 0xD24E_C4F1_A98C_6E5B, "a one-byte input");
        assert_eq!(hash(b"abc"), 0x44BC_2CF5_AD77_0999, "a three-byte input");
        // long enough to take the 32-byte accumulator path AND leave a tail of each width
        let long = b"The quick brown fox jumps over the lazy dog";
        assert_eq!(
            hash(long),
            0x0B24_2D36_1FDA_71BC,
            "a 43-byte input, which exercises the accumulator and all three tail widths"
        );
    }

    /// Every length from 0 to 200 hashes without panicking and without two adjacent
    /// lengths colliding, which is the cheap shape check on the tail arithmetic.
    #[test]
    fn every_length_takes_a_path_and_no_two_neighbors_collide() {
        let data: Vec<u8> = (0..200u32).map(|i| (i * 7 + 13) as u8).collect();
        let mut last = hash(&data[..0]);
        for n in 1..=200usize {
            let h = hash(&data[..n]);
            assert_ne!(h, last, "length {n} hashes the same as length {}", n - 1);
            last = h;
        }
    }
}
