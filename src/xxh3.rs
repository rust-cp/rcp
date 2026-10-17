//! XXH3, 64 and 128 bits (Yann Collet, xxHash 0.8), in safe Rust with nothing outside
//! `std`.
//!
//! Why this is here at all: it is the hash the field's tools already speak. rsync 3.2
//! added `xxh3` and `xxh128` to `--checksum-choice` and 3.5 still ships them; rclone's
//! backends and its hasher overlay carry them; `xxhsum` writes them. SHA-256 stays rcp's
//! default because a published spec names it and BLAKE3 stays the fast verification
//! option -- this one is for INTERCHANGE, where the number has to match what another tool
//! computed, so being bit-exact with the reference is the whole requirement.
//!
//! **It is not a cryptographic hash and must never be used as one.** XXH3 is a
//! non-cryptographic hash with no collision resistance against an adversary: a chosen
//! pair is cheap. `verify` between two trees under one operator's control is what it is
//! for; a digest that has to survive somebody wanting it to collide is SHA-256's job.
//!
//! The algorithm has four shapes by length -- 1-3, 4-8, 9-16, 17-128 and 129-240 bytes
//! are each handled in the open, and anything longer runs the accumulator loop over
//! 1024-byte blocks with a scramble between them. That is the reference's structure, not
//! an optimization of it: the output is defined by those branches, so they cannot be
//! merged.
//!
//! Verified against `libxxhash.so.0.8.2` on this machine rather than against hand-copied
//! vectors -- `scripts/xxh3-vectors.py` calls the reference through ctypes and writes the
//! table `tests/xxh3.rs` checks, over every length boundary the branches have and a
//! sample either side of each. A hash that agrees with a table somebody typed in is a
//! hash that agrees with the typing.

/// The reference's 192-byte secret (`XXH3_kSecret`). Derived from nothing; it is a
/// constant of the algorithm, and a different one gives a different hash.
const SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad,
    0x1c, //
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

const PRIME32_1: u64 = 0x9E37_79B1;
const PRIME32_2: u64 = 0x85EB_CA77;
const PRIME32_3: u64 = 0xC2B2_AE3D;
const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// Bytes accumulated per stripe, and stripes per block. The block is 1024 bytes: 16
/// stripes of 64, with the secret advancing 8 bytes per stripe.
const STRIPE: usize = 64;
const ACC_N: usize = 8;
const STRIPES_PER_BLOCK: usize = (SECRET.len() - STRIPE) / 8;
const MIDSIZE_MAX: usize = 240;
/// `XXH3_SECRET_SIZE_MIN`: the smallest secret the algorithm accepts, 136 bytes. It is
/// NOT the default secret's length, and the 129-240 branches index their last piece from
/// it -- reading `SECRET.len()` there instead gave the right answer for every input up to
/// 128 bytes and the wrong one from 129 on, which is exactly what the reference caught.
const SECRET_SIZE_MIN: usize = 136;

const INIT_ACC: [u64; ACC_N] = [
    PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
];

fn u32le(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as u64
}

fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

/// The full 128-bit product, which is where XXH3 gets its mixing.
fn mul128(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    (p as u64, (p >> 64) as u64)
}

fn mul128_fold64(a: u64, b: u64) -> u64 {
    let (lo, hi) = mul128(a, b);
    lo ^ hi
}

fn xorshift64(v: u64, shift: u32) -> u64 {
    v ^ (v >> shift)
}

fn avalanche(mut h: u64) -> u64 {
    h = xorshift64(h, 37);
    h = h.wrapping_mul(0x165667919E3779F9);
    xorshift64(h, 32)
}

fn avalanche64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^ (h >> 32)
}

fn rrmxmx(mut h: u64, len: u64) -> u64 {
    h ^= h.rotate_left(49) ^ h.rotate_left(24);
    h = h.wrapping_mul(0x9FB21C651E98DF25);
    h ^= (h >> 35).wrapping_add(len);
    h = h.wrapping_mul(0x9FB21C651E98DF25);
    xorshift64(h, 28)
}

// --- the short branches, each defined separately by the reference ------------------

fn len_1to3_64(data: &[u8], secret: &[u8], seed: u64) -> u64 {
    let c1 = data[0] as u32;
    let c2 = data[data.len() >> 1] as u32;
    let c3 = data[data.len() - 1] as u32;
    let combined = ((c1 << 16) | (c2 << 24) | c3 | ((data.len() as u32) << 8)) as u64;
    let flip = (u32le(secret, 0) ^ u32le(secret, 4)).wrapping_add(seed);
    avalanche64(combined ^ flip)
}

fn len_4to8_64(data: &[u8], secret: &[u8], mut seed: u64) -> u64 {
    seed ^= ((seed as u32).swap_bytes() as u64) << 32;
    let input1 = u32le(data, 0);
    let input2 = u32le(data, data.len() - 4);
    let flip = (u64le(secret, 8) ^ u64le(secret, 16)).wrapping_sub(seed);
    let input64 = input2.wrapping_add(input1 << 32);
    rrmxmx(input64 ^ flip, data.len() as u64)
}

fn len_9to16_64(data: &[u8], secret: &[u8], seed: u64) -> u64 {
    let flip1 = (u64le(secret, 24) ^ u64le(secret, 32)).wrapping_add(seed);
    let flip2 = (u64le(secret, 40) ^ u64le(secret, 48)).wrapping_sub(seed);
    let input_lo = u64le(data, 0) ^ flip1;
    let input_hi = u64le(data, data.len() - 8) ^ flip2;
    let acc = (data.len() as u64)
        .wrapping_add(input_lo.swap_bytes())
        .wrapping_add(input_hi)
        .wrapping_add(mul128_fold64(input_lo, input_hi));
    avalanche(acc)
}

fn len_0to16_64(data: &[u8], seed: u64) -> u64 {
    match data.len() {
        9..=16 => len_9to16_64(data, &SECRET, seed),
        4..=8 => len_4to8_64(data, &SECRET, seed),
        1..=3 => len_1to3_64(data, &SECRET, seed),
        _ => avalanche64(seed ^ u64le(&SECRET, 56) ^ u64le(&SECRET, 64)),
    }
}

fn mix16(data: &[u8], at: usize, secret: &[u8], sec_at: usize, seed: u64) -> u64 {
    let lo = u64le(data, at);
    let hi = u64le(data, at + 8);
    mul128_fold64(
        lo ^ u64le(secret, sec_at).wrapping_add(seed),
        hi ^ u64le(secret, sec_at + 8).wrapping_sub(seed),
    )
}

fn len_17to128_64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    // pairs from the outside in: 4 pairs at 128, 3 at 96, 2 at 64, 1 at 32
    let mut i = (len - 1) / 32;
    loop {
        acc = acc.wrapping_add(mix16(data, 16 * i, &SECRET, 32 * i, seed));
        acc = acc.wrapping_add(mix16(data, len - 16 * (i + 1), &SECRET, 32 * i + 16, seed));
        if i == 0 {
            break;
        }
        i -= 1;
    }
    avalanche(acc)
}

fn len_129to240_64(data: &[u8], seed: u64) -> u64 {
    const START_OFFSET: usize = 3;
    const LAST_OFFSET: usize = 17;
    let len = data.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    for i in 0..8 {
        acc = acc.wrapping_add(mix16(data, 16 * i, &SECRET, 16 * i, seed));
    }
    acc = avalanche(acc);
    for i in 8..(len / 16) {
        acc = acc.wrapping_add(mix16(
            data,
            16 * i,
            &SECRET,
            16 * (i - 8) + START_OFFSET,
            seed,
        ));
    }
    acc = acc.wrapping_add(mix16(
        data,
        len - 16,
        &SECRET,
        SECRET_SIZE_MIN - LAST_OFFSET,
        seed,
    ));
    avalanche(acc)
}

// --- the long path: accumulate, scramble, merge ------------------------------------

fn accumulate_512(acc: &mut [u64; ACC_N], data: &[u8], at: usize, secret: &[u8], sec_at: usize) {
    for i in 0..ACC_N {
        let data_val = u64le(data, at + 8 * i);
        let data_key = data_val ^ u64le(secret, sec_at + 8 * i);
        acc[i ^ 1] = acc[i ^ 1].wrapping_add(data_val);
        acc[i] = acc[i].wrapping_add((data_key & 0xFFFF_FFFF).wrapping_mul(data_key >> 32));
    }
}

fn scramble(acc: &mut [u64; ACC_N], secret: &[u8], sec_at: usize) {
    for i in 0..ACC_N {
        acc[i] = xorshift64(acc[i], 47);
        acc[i] ^= u64le(secret, sec_at + 8 * i);
        acc[i] = acc[i].wrapping_mul(PRIME32_1);
    }
}

fn hash_long_acc(acc: &mut [u64; ACC_N], data: &[u8]) {
    let block = STRIPES_PER_BLOCK * STRIPE;
    let blocks = (data.len() - 1) / block;
    for b in 0..blocks {
        for s in 0..STRIPES_PER_BLOCK {
            accumulate_512(acc, data, b * block + s * STRIPE, &SECRET, s * 8);
        }
        scramble(acc, &SECRET, SECRET.len() - STRIPE);
    }
    // the last, partial block: whole stripes, then one final stripe aligned to the end
    let done = blocks * block;
    let stripes = (data.len() - 1 - done) / STRIPE;
    for s in 0..stripes {
        accumulate_512(acc, data, done + s * STRIPE, &SECRET, s * 8);
    }
    accumulate_512(
        acc,
        data,
        data.len() - STRIPE,
        &SECRET,
        SECRET.len() - STRIPE - 7,
    );
}

fn merge_accs(acc: &[u64; ACC_N], secret: &[u8], sec_at: usize, start: u64) -> u64 {
    let mut result = start;
    for i in 0..4 {
        result = result.wrapping_add(mul128_fold64(
            acc[2 * i] ^ u64le(secret, sec_at + 16 * i),
            acc[2 * i + 1] ^ u64le(secret, sec_at + 16 * i + 8),
        ));
    }
    avalanche(result)
}

fn hash_long_64(data: &[u8]) -> u64 {
    let mut acc = INIT_ACC;
    hash_long_acc(&mut acc, data);
    merge_accs(
        &acc,
        &SECRET,
        11,
        (data.len() as u64).wrapping_mul(PRIME64_1),
    )
}

/// XXH3 over a whole slice, 64 bits, with the default secret and no seed.
pub fn hash64(data: &[u8]) -> u64 {
    match data.len() {
        0..=16 => len_0to16_64(data, 0),
        17..=128 => len_17to128_64(data, 0),
        129..=MIDSIZE_MAX => len_129to240_64(data, 0),
        _ => hash_long_64(data),
    }
}

// --- 128 bits ----------------------------------------------------------------------

/// A 128-bit digest, low half first as the reference orders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U128 {
    pub low: u64,
    pub high: u64,
}

impl U128 {
    /// Big-endian hex, high half first -- the order `xxhsum --tag` and rsync print.
    pub fn hex(&self) -> String {
        format!("{:016x}{:016x}", self.high, self.low)
    }
}

fn len_1to3_128(data: &[u8], seed: u64) -> U128 {
    let c1 = data[0] as u32;
    let c2 = data[data.len() >> 1] as u32;
    let c3 = data[data.len() - 1] as u32;
    let combinedl = ((c1 << 16) | (c2 << 24) | c3 | ((data.len() as u32) << 8)) as u64;
    let combinedh = (combinedl as u32).swap_bytes().rotate_left(13) as u64;
    let flipl = (u32le(&SECRET, 0) ^ u32le(&SECRET, 4)).wrapping_add(seed);
    let fliph = (u32le(&SECRET, 8) ^ u32le(&SECRET, 12)).wrapping_sub(seed);
    U128 {
        low: avalanche64(combinedl ^ flipl),
        high: avalanche64(combinedh ^ fliph),
    }
}

fn len_4to8_128(data: &[u8], mut seed: u64) -> U128 {
    seed ^= ((seed as u32).swap_bytes() as u64) << 32;
    let lo = u32le(data, 0);
    let hi = u32le(data, data.len() - 4);
    let input64 = lo.wrapping_add(hi << 32);
    let flip = (u64le(&SECRET, 16) ^ u64le(&SECRET, 24)).wrapping_add(seed);
    let keyed = input64 ^ flip;
    let (mut low, mut high) = mul128(keyed, PRIME64_1.wrapping_add((data.len() as u64) << 2));
    high = high.wrapping_add(low << 1);
    low ^= high >> 3;
    low = xorshift64(low, 35);
    low = low.wrapping_mul(0x9FB21C651E98DF25);
    low = xorshift64(low, 28);
    U128 {
        low,
        high: avalanche(high),
    }
}

fn len_9to16_128(data: &[u8], seed: u64) -> U128 {
    let flipl = (u64le(&SECRET, 32) ^ u64le(&SECRET, 40)).wrapping_sub(seed);
    let fliph = (u64le(&SECRET, 48) ^ u64le(&SECRET, 56)).wrapping_add(seed);
    let input_lo = u64le(data, 0);
    let mut input_hi = u64le(data, data.len() - 8);
    let (mut low, mut high) = mul128(input_lo ^ input_hi ^ flipl, PRIME64_1);
    low = low.wrapping_add(((data.len() as u64) - 1) << 54);
    input_hi ^= fliph;
    high = high
        .wrapping_add(input_hi)
        .wrapping_add((input_hi as u32 as u64).wrapping_mul(PRIME32_2.wrapping_sub(1)));
    low ^= high.swap_bytes();
    let (l2, h2) = mul128(low, PRIME64_2);
    U128 {
        low: avalanche(l2),
        high: avalanche(h2.wrapping_add(high.wrapping_mul(PRIME64_2))),
    }
}

fn len_0to16_128(data: &[u8], seed: u64) -> U128 {
    match data.len() {
        9..=16 => len_9to16_128(data, seed),
        4..=8 => len_4to8_128(data, seed),
        1..=3 => len_1to3_128(data, seed),
        _ => U128 {
            low: avalanche64(seed ^ u64le(&SECRET, 64) ^ u64le(&SECRET, 72)),
            high: avalanche64(seed ^ u64le(&SECRET, 80) ^ u64le(&SECRET, 88)),
        },
    }
}

fn len_17to128_128(data: &[u8], seed: u64) -> U128 {
    let len = data.len();
    let mut lo = (len as u64).wrapping_mul(PRIME64_1);
    let mut hi = 0u64;
    let mut i = (len - 1) / 32;
    loop {
        let (a, b) = mix32(lo, hi, data, 16 * i, data, len - 16 * (i + 1), 32 * i, seed);
        lo = a;
        hi = b;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    finish128(lo, hi, len)
}

/// The 128-bit mixer: one accumulator pair takes two 16-byte pieces and 32 secret bytes.
#[allow(clippy::too_many_arguments)]
fn mix32(
    mut lo: u64,
    mut hi: u64,
    a: &[u8],
    a_at: usize,
    b: &[u8],
    b_at: usize,
    sec_at: usize,
    seed: u64,
) -> (u64, u64) {
    lo = lo.wrapping_add(mix16(a, a_at, &SECRET, sec_at, seed));
    lo ^= u64le(b, b_at).wrapping_add(u64le(b, b_at + 8));
    hi = hi.wrapping_add(mix16(b, b_at, &SECRET, sec_at + 16, seed));
    hi ^= u64le(a, a_at).wrapping_add(u64le(a, a_at + 8));
    (lo, hi)
}

fn finish128(lo: u64, hi: u64, len: usize) -> U128 {
    let low = avalanche(lo.wrapping_add(hi));
    let high = 0u64.wrapping_sub(avalanche(
        lo.wrapping_mul(PRIME64_1)
            .wrapping_add(hi.wrapping_mul(PRIME64_4))
            .wrapping_add(((len as u64).wrapping_sub(0)).wrapping_mul(PRIME64_2)),
    ));
    U128 { low, high }
}

fn len_129to240_128(data: &[u8], seed: u64) -> U128 {
    const START_OFFSET: usize = 3;
    const LAST_OFFSET: usize = 17;
    let len = data.len();
    let mut lo = (len as u64).wrapping_mul(PRIME64_1);
    let mut hi = 0u64;
    for i in 0..4 {
        let (a, b) = mix32(lo, hi, data, 32 * i, data, 32 * i + 16, 32 * i, seed);
        lo = a;
        hi = b;
    }
    lo = avalanche(lo);
    hi = avalanche(hi);
    for i in 4..(len / 32) {
        let (a, b) = mix32(
            lo,
            hi,
            data,
            32 * i,
            data,
            32 * i + 16,
            START_OFFSET + 32 * (i - 4),
            seed,
        );
        lo = a;
        hi = b;
    }
    // the last 32 bytes, aligned to the end, with the secret read backwards and the two
    // halves swapped -- the reference passes the pieces in the other order here
    let (a, b) = mix32(
        lo,
        hi,
        data,
        len - 16,
        data,
        len - 32,
        SECRET_SIZE_MIN - LAST_OFFSET - 16,
        0u64.wrapping_sub(seed),
    );
    lo = a;
    hi = b;
    finish128(lo, hi, len)
}

fn hash_long_128(data: &[u8]) -> U128 {
    let mut acc = INIT_ACC;
    hash_long_acc(&mut acc, data);
    let low = merge_accs(
        &acc,
        &SECRET,
        11,
        (data.len() as u64).wrapping_mul(PRIME64_1),
    );
    let high = merge_accs(
        &acc,
        &SECRET,
        SECRET.len() - ACC_N * 8 - 11,
        !((data.len() as u64).wrapping_mul(PRIME64_2)),
    );
    U128 { low, high }
}

/// XXH3 over a whole slice, 128 bits, with the default secret and no seed.
pub fn hash128(data: &[u8]) -> U128 {
    match data.len() {
        0..=16 => len_0to16_128(data, 0),
        17..=128 => len_17to128_128(data, 0),
        129..=MIDSIZE_MAX => len_129to240_128(data, 0),
        _ => hash_long_128(data),
    }
}

/// A streaming digest: rcp reads a file in blocks, so it cannot hand the whole thing to
/// `hash64`. XXH3's long path is a block cipher shape, but its SHORT paths are defined
/// over the whole input -- so a stream under 241 bytes has to be held and hashed at the
/// end, and only past that does the accumulator carry state.
pub struct Xxh3 {
    acc: [u64; ACC_N],
    /// Input held back: everything, while the total is still short enough for a short
    /// path; afterwards only the tail that has not filled a stripe.
    buf: Vec<u8>,
    total: u64,
    /// Stripes consumed in the current block, so a scramble lands in the right place.
    stripe: usize,
    /// The last full stripe seen, kept because the final one is read from the END of the
    /// input and may already have been consumed.
    last: [u8; STRIPE],
    started: bool,
    wide: bool,
}

impl Xxh3 {
    pub fn new(wide: bool) -> Xxh3 {
        Xxh3 {
            acc: INIT_ACC,
            buf: Vec::new(),
            total: 0,
            stripe: 0,
            last: [0; STRIPE],
            started: false,
            wide,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        if !self.started {
            self.buf.extend_from_slice(data);
            if self.buf.len() <= MIDSIZE_MAX {
                return;
            }
            // past the short paths: the held bytes become the start of the long path
            self.started = true;
            let held = std::mem::take(&mut self.buf);
            self.absorb(&held);
            return;
        }
        self.absorb(data);
    }

    /// Feeds bytes, ALWAYS keeping between 1 and `STRIPE` of them in hand.
    ///
    /// That invariant is the whole of the streaming difficulty. The reference's long path
    /// reads its final stripe from the END of the input, overlapping whatever came before
    /// -- so a stripe that happens to end exactly where the input does must not also be
    /// accumulated on the way past. Feeding every full stripe eagerly did that, and for an
    /// input whose length is a multiple of 64 the last one was applied TWICE: 256 bytes
    /// fed one at a time disagreed with the reference while 255 and 257 agreed, which is
    /// the signature of an off-by-one-stripe rather than of a broken accumulator.
    fn absorb(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if !self.buf.is_empty() {
            let want = STRIPE.saturating_sub(self.buf.len());
            let take = want.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if data.is_empty() {
                return; // hold it: this may be the stripe the end lands on
            }
            let held = std::mem::take(&mut self.buf);
            self.stripe_in(&held);
        }
        let keep = ((data.len() - 1) % STRIPE) + 1;
        let whole = data.len() - keep;
        let mut at = 0;
        while at < whole {
            self.stripe_in(&data[at..at + STRIPE]);
            at += STRIPE;
        }
        self.buf.extend_from_slice(&data[whole..]);
    }

    fn stripe_in(&mut self, s: &[u8]) {
        accumulate_512(&mut self.acc, s, 0, &SECRET, self.stripe * 8);
        self.last.copy_from_slice(s);
        self.stripe += 1;
        if self.stripe == STRIPES_PER_BLOCK {
            scramble(&mut self.acc, &SECRET, SECRET.len() - STRIPE);
            self.stripe = 0;
        }
    }

    /// The 64-bit digest of everything fed so far.
    pub fn finish64(&self) -> u64 {
        match self.whole() {
            Some(all) => hash64(all),
            None => merge_accs(
                &self.closed(),
                &SECRET,
                11,
                self.total.wrapping_mul(PRIME64_1),
            ),
        }
    }

    /// The 128-bit digest of everything fed so far.
    pub fn finish128(&self) -> U128 {
        match self.whole() {
            Some(all) => hash128(all),
            None => {
                let acc = self.closed();
                U128 {
                    low: merge_accs(&acc, &SECRET, 11, self.total.wrapping_mul(PRIME64_1)),
                    high: merge_accs(
                        &acc,
                        &SECRET,
                        SECRET.len() - ACC_N * 8 - 11,
                        !(self.total.wrapping_mul(PRIME64_2)),
                    ),
                }
            }
        }
    }

    /// The whole input, when it is short enough that a short path defines the answer.
    fn whole(&self) -> Option<&[u8]> {
        (!self.started).then_some(&self.buf[..])
    }

    /// The accumulator with the final stripe applied. The reference's last stripe is read
    /// from the END of the input, which overlaps whatever came before it -- so a stream
    /// has to reconstruct it from the tail it kept plus the last full stripe it saw.
    fn closed(&self) -> [u64; ACC_N] {
        let mut acc = self.acc;
        let mut tail = [0u8; STRIPE];
        let n = self.buf.len();
        if n == 0 {
            tail.copy_from_slice(&self.last);
        } else {
            tail[..STRIPE - n].copy_from_slice(&self.last[n..]);
            tail[STRIPE - n..].copy_from_slice(&self.buf);
        }
        accumulate_512(&mut acc, &tail, 0, &SECRET, SECRET.len() - STRIPE - 7);
        acc
    }

    /// The digest as the hex a report or another tool would carry.
    pub fn hex(&self) -> String {
        if self.wide {
            self.finish128().hex()
        } else {
            format!("{:016x}", self.finish64())
        }
    }
}
