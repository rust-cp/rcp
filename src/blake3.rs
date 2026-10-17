//! BLAKE3 (the 2020 specification by O'Connor, Aumasson, Neves and Wilcox-O'Hearn),
//! implemented here so the binary keeps building with no crates.io access. The fast digest
//! for copy verification, beside SHA-256 which stays the default because FIPS names it.
//!
//! The Merkle-tree construction is what makes it fast on a copy tool's workloads: 1 KiB
//! chunks are independent, so a large `update` compresses its whole chunks on several
//! threads and merges their chaining values in order afterwards, and the result is the same
//! digest the serial hasher produces (the tests check that at many split points).

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Whole chunks in one `update` from which the chunk compressions are spread over threads.
const PARALLEL_CHUNKS: usize = 128;

#[inline(always)]
fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

#[inline(always)]
fn round(s: &mut [u32; 16], m: &[u32; 16]) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut p = [0u32; 16];
    for i in 0..16 {
        p[i] = m[MSG_PERMUTATION[i]];
    }
    *m = p;
}

fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    round(&mut s, &m);
    for _ in 0..6 {
        permute(&mut m);
        round(&mut s, &m);
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn words_of(block: &[u8]) -> [u32; 16] {
    debug_assert!(block.len() <= BLOCK_LEN);
    let mut w = [0u32; 16];
    let mut padded = [0u8; BLOCK_LEN];
    padded[..block.len()].copy_from_slice(block);
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_le_bytes(padded[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    w
}

fn first_8(s: &[u32; 16]) -> [u32; 8] {
    s[..8].try_into().expect("8 words")
}

/// The inputs to one final compression, kept so the same node can yield either a chaining
/// value (as a child) or the root hash (as the root).
struct Output {
    cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8(&compress(
            &self.cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }
    fn root_hash(&self) -> [u8; OUT_LEN] {
        let s = compress(&self.cv, &self.block, 0, self.block_len, self.flags | ROOT);
        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes());
        }
        out
    }
}

/// One chunk under construction: up to 16 blocks of 64 bytes.
struct ChunkState {
    cv: [u32; 8],
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: usize,
}

impl ChunkState {
    fn new(counter: u64) -> ChunkState {
        ChunkState {
            cv: IV,
            counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }
    fn len(&self) -> usize {
        self.blocks_compressed * BLOCK_LEN + self.block_len
    }
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let words = words_of(&self.block);
                self.cv = first_8(&compress(
                    &self.cv,
                    &words,
                    self.counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }
    fn output(&self) -> Output {
        Output {
            cv: self.cv,
            block: words_of(&self.block[..self.block_len]),
            counter: self.counter,
            block_len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

/// The chaining value of one complete chunk that is not the root.
fn chunk_cv(chunk: &[u8], counter: u64) -> [u32; 8] {
    debug_assert_eq!(chunk.len(), CHUNK_LEN);
    let mut cv = IV;
    for (i, block) in chunk.chunks(BLOCK_LEN).enumerate() {
        let mut flags = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == CHUNK_LEN / BLOCK_LEN - 1 {
            flags |= CHUNK_END;
        }
        cv = first_8(&compress(
            &cv,
            &words_of(block),
            counter,
            BLOCK_LEN as u32,
            flags,
        ));
    }
    cv
}

/// The chaining values of `data`'s whole chunks (`data.len()` a multiple of 1 KiB), spread
/// over threads when there are enough of them to be worth it.
fn chunk_cvs(data: &[u8], first_counter: u64) -> Vec<[u32; 8]> {
    let chunks = data.len() / CHUNK_LEN;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8);
    if chunks < PARALLEL_CHUNKS || threads < 2 {
        return data
            .chunks(CHUNK_LEN)
            .enumerate()
            .map(|(i, c)| chunk_cv(c, first_counter + i as u64))
            .collect();
    }
    let per = chunks.div_ceil(threads);
    let mut out = vec![[0u32; 8]; chunks];
    std::thread::scope(|scope| {
        for (t, slot) in out.chunks_mut(per).enumerate() {
            let start = t * per;
            let slice = &data[start * CHUNK_LEN..(start + slot.len()) * CHUNK_LEN];
            scope.spawn(move || {
                for (i, c) in slice.chunks(CHUNK_LEN).enumerate() {
                    slot[i] = chunk_cv(c, first_counter + (start + i) as u64);
                }
            });
        }
    });
    out
}

fn parent_output(left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(left);
    block[8..].copy_from_slice(right);
    Output {
        cv: IV,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT,
    }
}

/// A streaming BLAKE3 hasher (32-byte output, unkeyed).
pub struct Blake3 {
    chunk: ChunkState,
    /// Subtree chaining values awaiting a sibling, deepest last.
    stack: Vec<[u32; 8]>,
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    pub fn new() -> Blake3 {
        Blake3 {
            chunk: ChunkState::new(0),
            stack: Vec::new(),
        }
    }

    /// Merges a completed chunk's (or subtree's) chaining value into the stack: after
    /// `total` chunks, every trailing zero bit of `total` is a completed pair to merge.
    fn push_cv(&mut self, mut cv: [u32; 8], total: u64) {
        let mut t = total;
        while t & 1 == 0 {
            let left = self
                .stack
                .pop()
                .expect("a left sibling for every completed pair");
            cv = parent_output(&left, &cv).chaining_value();
            t >>= 1;
        }
        self.stack.push(cv);
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let counter = self.chunk.counter;
                self.push_cv(cv, counter + 1);
                self.chunk = ChunkState::new(counter + 1);
            }
            // whole chunks that are certainly not the last one go the fast way; at least
            // one byte is always kept back for the chunk state, since the final chunk of
            // the message is the root when it is alone and must not be finalized early
            if self.chunk.len() == 0 && input.len() > CHUNK_LEN {
                let whole = (input.len() - 1) / CHUNK_LEN;
                let first = self.chunk.counter;
                let cvs = chunk_cvs(&input[..whole * CHUNK_LEN], first);
                for (i, cv) in cvs.into_iter().enumerate() {
                    self.push_cv(cv, first + i as u64 + 1);
                }
                self.chunk = ChunkState::new(first + whole as u64);
                input = &input[whole * CHUNK_LEN..];
                continue;
            }
            let want = CHUNK_LEN - self.chunk.len();
            let take = want.min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize(&self) -> [u8; OUT_LEN] {
        let mut output = self.chunk.output();
        for cv in self.stack.iter().rev() {
            output = parent_output(cv, &output.chaining_value());
        }
        output.root_hash()
    }

    pub fn hex(&self) -> String {
        crate::sha256::to_hex(&self.finalize())
    }
}

/// One-shot digest as hex.
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
    fn threaded_chunks_equal_the_serial_hasher() {
        // above PARALLEL_CHUNKS whole chunks the update spreads over threads; the digest
        // must not depend on it, including at a length that leaves a partial last chunk
        for len in [
            PARALLEL_CHUNKS * CHUNK_LEN + 1,
            4 * PARALLEL_CHUNKS * CHUNK_LEN + 777,
            1_000_000,
        ] {
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
