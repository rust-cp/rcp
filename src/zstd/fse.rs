//! FSE -- the tANS entropy coder zstd uses for its sequence symbols.
//!
//! This is the piece everything above it rests on, and it is the reason the roadmap row
//! said zstd was weeks rather than a wire flag. Three things have to be right together or
//! nothing decodes: the normalized count table, the serialized description of that table
//! that crosses the wire, and a bitstream that is written forwards and read BACKWARDS.
//!
//! ## The bitstream runs backwards, and that is not an implementation detail
//!
//! A tANS encoder emits symbols in reverse and the decoder recovers them in order. The
//! stream therefore has to be read from its end, which zstd marks with a **sentinel**: the
//! highest set bit of the last non-zero byte is not data, it is the mark saying where the
//! written bits stopped. A stream whose last byte is zero is malformed, and a decoder that
//! forgets the sentinel reads padding as a symbol and produces plausible garbage rather
//! than an error -- the same failure shape this crate already records for a flipped bit
//! inside a compressed body.
//!
//! The reader here is written positionally rather than as zstd's sliding container: it
//! keeps a bit index and walks it down. That is slower per bit and much easier to argue is
//! correct, which is the right trade for a first correct implementation. The container
//! form is a later optimization with a round-trip already in place to hold it honest.
//!
//! ## What is proved here, and what is not
//!
//! These arms prove the coder agrees with ITSELF -- encode/decode round trips over
//! adversarial distributions, and a table description that survives write/read. They do
//! NOT prove agreement with the reference, because an FSE table alone is not something
//! `zstd` can be handed: it only appears inside a compressed block. That interop lands in
//! stage 3, and until it does this module carries the weaker claim on purpose.

use std::io;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zstd/fse: {what}"))
}

/// zstd's accuracy-log bounds for a sequence table.
pub const MIN_TABLE_LOG: u32 = 5;
pub const MAX_TABLE_LOG: u32 = 9;

/// Index of the highest set bit. `v` must not be zero.
fn high_bit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// Bits appended in order, packed least-significant-first into little-endian bytes.
pub struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    /// How many bits of `acc` are live.
    live: u32,
    /// Total bits appended, which the sentinel is placed just past.
    pub written: u32,
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BitWriter {
    pub fn new() -> BitWriter {
        BitWriter {
            out: Vec::new(),
            acc: 0,
            live: 0,
            written: 0,
        }
    }

    /// `nb` low bits of `value`. `nb` is at most 32 here; the caller's fields never exceed
    /// a table log plus a symbol code.
    pub fn add(&mut self, value: u32, nb: u32) {
        debug_assert!(nb <= 32);
        if nb == 0 {
            return;
        }
        let masked = u64::from(value) & ((1u64 << nb) - 1);
        self.acc |= masked << self.live;
        self.live += nb;
        self.written += nb;
        while self.live >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.live -= 8;
        }
    }

    /// Pads to a byte with zeros and returns the bytes, with NO sentinel.
    ///
    /// A table description is an ordinary forward header, not a tANS payload: its end is
    /// found by the reader running out of probability to distribute, so a sentinel would
    /// be a bit of data the reader never asked for. Using `finish` here writes one extra
    /// bit, which spills into an extra byte whenever the description ends on a byte
    /// boundary -- and in a real block the BITSTREAM starts at the next byte, so that
    /// extra byte moves the stream and everything after it decodes plausible garbage.
    pub fn finish_padded(mut self) -> Vec<u8> {
        if self.live > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }

    /// Appends the sentinel and pads to a byte, returning the finished stream.
    ///
    /// The sentinel is a single 1 bit immediately after the data. It is what lets the
    /// decoder find where the data ended without being told a length, which matters
    /// because the length in BITS is not otherwise recoverable from a byte count.
    pub fn finish(mut self) -> Vec<u8> {
        self.add(1, 1);
        if self.live > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// Reads a `BitWriter` stream from its end, which is the order a tANS decoder needs.
pub struct BitReader<'a> {
    data: &'a [u8],
    /// The next bit to be consumed is the one just BELOW this index.
    pos: u32,
}

impl<'a> BitReader<'a> {
    /// Locates the sentinel and positions just before it.
    /// The sentinel is in the LAST byte, and a last byte of zero is corrupt.
    ///
    /// This used to scan backwards for the last NON-ZERO byte, which is a different rule
    /// and a wrong one. The reference refuses a stream whose final byte is zero outright
    /// (`if (lastByte == 0) return ERROR`), because the sentinel is written into that byte
    /// by construction. Skipping over it instead starts the reader eight or more bits
    /// early and decodes the whole stream from the wrong place -- which does not fail, it
    /// produces plausible symbols, the failure shape this module exists to refuse.
    ///
    /// Nothing this crate writes is affected: `BitWriter::finish` appends the sentinel
    /// bit before padding, so its final byte always has a bit set.
    pub fn new(data: &'a [u8]) -> io::Result<BitReader<'a>> {
        let &last_byte = data
            .last()
            .ok_or_else(|| bad("an empty bitstream carries no sentinel"))?;
        if last_byte == 0 {
            return Err(bad(
                "the bitstream's last byte is zero, so the sentinel it must carry is missing",
            ));
        }
        let bit = high_bit(u32::from(last_byte));
        Ok(BitReader {
            data,
            pos: ((data.len() - 1) as u32) * 8 + bit,
        })
    }

    /// How many data bits remain unread.
    pub fn remaining(&self) -> u32 {
        self.pos
    }

    /// The next `nb` bits WITHOUT consuming them, zero-padded when the stream is short.
    ///
    /// Huffman needs this and FSE does not, and the difference is the point: an FSE
    /// decoder knows how many bits its next field takes before it reads them, because the
    /// state says so. A Huffman decoder does not -- the code's length is what it is trying
    /// to find out -- so it peeks a fixed table-log window, looks the symbol up, and then
    /// skips only the bits that symbol actually used.
    ///
    /// The zero padding at the end of the stream is deliberate and matches the reference:
    /// the final symbols legitimately peek past the start, and their codes are still
    /// uniquely determined by the bits that ARE there.
    pub fn peek(&self, nb: u32) -> u32 {
        if nb == 0 {
            return 0;
        }
        let have = self.pos.min(nb);
        let start = self.pos - have;
        let byte = (start / 8) as usize;
        let off = start % 8;
        let mut v: u64 = 0;
        for i in 0..5usize {
            if let Some(&b) = self.data.get(byte + i) {
                v |= u64::from(b) << (8 * i);
            }
        }
        let got = ((v >> off) & ((1u64 << have) - 1)) as u32;
        got << (nb - have)
    }

    /// Drops `nb` bits, saturating at the start of the stream.
    pub fn skip(&mut self, nb: u32) {
        self.pos = self.pos.saturating_sub(nb);
    }

    /// The `nb` bits most recently written among those not yet read.
    pub fn read(&mut self, nb: u32) -> io::Result<u32> {
        if nb == 0 {
            return Ok(0);
        }
        if nb > self.pos {
            return Err(bad("the bitstream ran out before a field was complete"));
        }
        self.pos -= nb;
        let byte = (self.pos / 8) as usize;
        let off = self.pos % 8;
        let mut v: u64 = 0;
        // at most 5 bytes span a 32-bit field at any offset
        for i in 0..5usize {
            if let Some(&b) = self.data.get(byte + i) {
                v |= u64::from(b) << (8 * i);
            }
        }
        Ok(((v >> off) & ((1u64 << nb) - 1)) as u32)
    }
}

/// Normalized counts: each entry is a share of `1 << table_log`, or **-1** for a symbol
/// that occurs but is rarer than one slot.
///
/// The -1 is not a sentinel for "absent" -- 0 means absent. It means "present, below the
/// resolution of this table", and such symbols are placed at the end of the state table
/// where they cost the most bits. Conflating the two loses symbols.
pub fn normalize(counts: &[u32], total: u32, table_log: u32) -> io::Result<Vec<i16>> {
    if total == 0 {
        return Err(bad("cannot normalize an empty distribution"));
    }
    if !(MIN_TABLE_LOG..=MAX_TABLE_LOG).contains(&table_log) {
        return Err(bad("table log out of range"));
    }
    let table_size = 1u32 << table_log;
    let low = total >> table_log;
    let mut norm = vec![0i16; counts.len()];
    let mut used = 0u32;
    let mut biggest = 0usize;
    let mut biggest_n = 0i16;

    for (s, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        if c <= low {
            // present but below one slot's worth
            norm[s] = -1;
            used += 1;
            continue;
        }
        // proportional share, never rounded down to nothing
        let share = ((u64::from(c) * u64::from(table_size)) / u64::from(total)).max(1) as i16;
        norm[s] = share;
        used += share as u32;
        if share > biggest_n {
            biggest_n = share;
            biggest = s;
        }
    }

    if used == 0 {
        return Err(bad("no symbol survived normalization"));
    }
    // The rounding above does not land on the table size, so the largest share absorbs the
    // difference -- it is the one that can give or take slots with the least relative harm.
    // Taking from a small share could drive it to zero, which would DELETE a symbol that
    // occurs, and a table that cannot represent an input symbol is not a rounding error.
    let mut delta = table_size as i64 - used as i64;
    if delta != 0 {
        let adjusted = biggest_n as i64 + delta;
        if adjusted < 1 {
            // the largest cannot absorb it alone; spread the remainder over the positive
            // shares, largest first, without taking any below one
            norm[biggest] = 1;
            delta = table_size as i64 - (used as i64 - biggest_n as i64 + 1);
            let mut order: Vec<usize> = (0..counts.len()).filter(|&s| norm[s] > 0).collect();
            order.sort_by_key(|&s| std::cmp::Reverse(norm[s]));
            for s in order {
                if delta == 0 {
                    break;
                }
                if delta > 0 {
                    let take = delta.min(i64::from(i16::MAX) - i64::from(norm[s]));
                    norm[s] += take as i16;
                    delta -= take;
                } else {
                    let give = (-delta).min(i64::from(norm[s]) - 1);
                    norm[s] -= give as i16;
                    delta += give;
                }
            }
            if delta != 0 {
                // The usual cause is not a rounding failure: it is an alphabet wider than
                // the table. 200 distinct symbols cannot be given a slot each in a 32-state
                // table, and no redistribution fixes that -- the caller has to raise the
                // accuracy log. Saying so beats "could not be balanced", which sends the
                // reader looking for an arithmetic bug that is not there.
                let distinct = counts.iter().filter(|&&c| c > 0).count();
                if distinct > table_size as usize {
                    return Err(bad(
                        "more distinct symbols than states: raise the accuracy log",
                    ));
                }
                return Err(bad("normalization could not be balanced"));
            }
        } else {
            norm[biggest] = adjusted as i16;
        }
    }

    let sum: i64 = norm
        .iter()
        .map(|&n| if n < 0 { 1i64 } else { i64::from(n) })
        .sum();
    if sum != i64::from(table_size) {
        return Err(bad("normalized counts do not sum to the table size"));
    }
    Ok(norm)
}

/// Serializes a normalized table the way zstd's block header carries it.
///
/// The format is the fiddliest part of FSE and the reason is worth stating: the field
/// width SHRINKS as probability is distributed, because once most of the table is spoken
/// for a remaining share cannot be large. So the writer and the reader have to track the
/// same running `remaining` and `threshold` and narrow in lockstep. A reader that
/// recomputes the width differently by one bit does not fail -- it silently reads the
/// following symbol's bits, which is the field-shift class of bug this crate already
/// records in its own HELLO reply.
pub fn write_ncount(norm: &[i16], table_log: u32) -> io::Result<Vec<u8>> {
    let table_size = 1i32 << table_log;
    let max_symbol = norm
        .iter()
        .rposition(|&n| n != 0)
        .ok_or_else(|| bad("an empty table has no description"))?;
    let mut w = BitWriter::new();
    w.add(table_log - MIN_TABLE_LOG, 4);

    let mut remaining = table_size + 1;
    let mut threshold = table_size;
    let mut nb_bits = table_log + 1;
    let mut symbol = 0usize;
    let mut previous_zero = false;

    while remaining > 1 && symbol <= max_symbol {
        if previous_zero {
            // a run of absent symbols, sent as repeat flags rather than one field each
            let start = symbol;
            let mut run = symbol;
            while run <= max_symbol && norm[run] == 0 {
                run += 1;
            }
            let mut at = start;
            while run >= at + 24 {
                at += 24;
                w.add(0xFFFF, 16);
            }
            while run >= at + 3 {
                at += 3;
                w.add(3, 2);
            }
            w.add((run - at) as u32, 2);
            // no `previous_zero = false` here: the count-writing code below sets it from
            // the value it actually wrote before the next iteration reads it, and the
            // compiler pointed out the assignment was dead. Leaving a redundant one in
            // would suggest the flag is live across this boundary, which it is not.
            symbol = run;
            if symbol > max_symbol {
                break;
            }
        }
        let count = i32::from(norm[symbol]);
        symbol += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        let mut value = count + 1;
        if value >= threshold {
            value += max;
        }
        // small values ride in one fewer bit, which is what makes the width adaptive
        let bits = if value < max { nb_bits - 1 } else { nb_bits };
        w.add(value as u32, bits);
        previous_zero = value == 1;
        if remaining < 1 {
            return Err(bad(
                "the table description over-distributed its probability",
            ));
        }
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    Ok(w.finish_padded())
}

/// The mirror of `write_ncount`.
///
/// Returns the counts, the accuracy log, and how many BYTES were consumed -- the last
/// because in a real block the description is followed immediately by the bitstream, and a
/// reader that guessed the boundary would start decoding inside the table.
pub fn read_ncount(data: &[u8]) -> io::Result<(Vec<i16>, u32, usize)> {
    let (norm, table_log, at, _) = read_ncount_live(data)?;
    Ok((norm, table_log, at))
}

/// The same read, plus the number of bits of the final byte the description did NOT use.
///
/// That count is the description's BIT alignment: zero means it ended exactly on a byte
/// boundary, anything else means it ended mid-byte and the partial byte is already inside
/// `at`. The distinction is the whole substance of the off-by-one recorded at the end of
/// this function, and without it the regression arm cannot tell whether it sampled both
/// shapes -- a fix conditional on alignment would pass an arm that only ever saw one.
fn read_ncount_live(data: &[u8]) -> io::Result<(Vec<i16>, u32, usize, u32)> {
    // The description is written LSB-first and read FORWARDS, unlike the tANS payload --
    // it is an ordinary header, not a tANS stream, and reading it backwards is a mistake
    // that produces a table rather than an error.
    let mut at = 0usize;
    let mut live = 0u32;
    let mut acc: u64 = 0;
    let take = |nb: u32, at: &mut usize, live: &mut u32, acc: &mut u64| -> io::Result<u32> {
        while *live < nb {
            let b = *data
                .get(*at)
                .ok_or_else(|| bad("the table description ends early"))?;
            *acc |= u64::from(b) << *live;
            *at += 1;
            *live += 8;
        }
        let v = (*acc & ((1u64 << nb) - 1)) as u32;
        *acc >>= nb;
        *live -= nb;
        Ok(v)
    };

    let table_log = take(4, &mut at, &mut live, &mut acc)? + MIN_TABLE_LOG;
    if !(MIN_TABLE_LOG..=MAX_TABLE_LOG).contains(&table_log) {
        return Err(bad(
            "the table description declares an accuracy log out of range",
        ));
    }
    let table_size = 1i32 << table_log;
    let mut remaining = table_size + 1;
    let mut threshold = table_size;
    let mut nb_bits = table_log + 1;
    let mut norm: Vec<i16> = Vec::new();
    let mut previous_zero = false;

    while remaining > 1 {
        if previous_zero {
            let mut run = 0usize;
            loop {
                let flag = take(2, &mut at, &mut live, &mut acc)?;
                run += flag as usize;
                if flag != 3 {
                    break;
                }
            }
            norm.resize(norm.len() + run, 0);
            previous_zero = false;
            continue;
        }
        let max = (2 * threshold - 1) - remaining;
        // read the narrow form first, then widen only if the value says so
        let narrow = take(nb_bits - 1, &mut at, &mut live, &mut acc)? as i32;
        let value = if narrow < max {
            narrow
        } else {
            let extra = take(1, &mut at, &mut live, &mut acc)? as i32;
            let wide = narrow + (extra << (nb_bits - 1));
            if wide >= threshold {
                wide - max
            } else {
                wide
            }
        };
        let count = value - 1;
        remaining -= count.abs();
        norm.push(count as i16);
        previous_zero = count == 0;
        if remaining < 1 {
            return Err(bad(
                "the table description over-distributed its probability",
            ));
        }
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    // `at` is already the byte count, and adding one for a partial trailing byte -- which
    // this did until it was measured -- DOUBLE-counts it: the reader pulled that byte into
    // the accumulator to finish the last field, so it is inside `at` already. The extra
    // byte does not corrupt the counts, which is why every round-trip arm stayed green; it
    // shifts the BITSTREAM that follows the description in a real block, and a bitstream
    // read one byte late still decodes plausible symbols and then runs out early.
    Ok((norm, table_log, at, live))
}

/// What the interleaved decoder has been ASKED to read, for arms that need to prove the
/// hard case was reached rather than assume it.
///
/// There is a plausible argument that the termination rule here ("more bits requested than
/// the stream held") might diverge from the reference's 64-bit-container overflow on a
/// bitstream SHORTER THAN 8 BYTES, where the reference's backward init has already counted
/// missing bytes as consumed. The evidence on the other side is reference frames agreeing
/// in both directions -- which is only evidence if those frames actually contain a short
/// interleaved bitstream, and nothing established that they did.
///
/// This codec's own encoder cannot supply one: it writes DIRECT weight tables only, so
/// `decode_interleaved` runs exclusively on frames the reference wrote. That makes the
/// coverage question unanswerable by construction and answerable only by counting.
///
/// Thread-local rather than global because the test harness runs each arm on its own
/// thread, and a shared counter would let one arm's coverage stand in for another's.
#[cfg(test)]
pub(crate) mod seen {
    use std::cell::Cell;
    thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static SHORTEST: Cell<usize> = const { Cell::new(usize::MAX) };
    }
    pub(crate) fn note(len: usize) {
        CALLS.with(|c| c.set(c.get() + 1));
        SHORTEST.with(|c| c.set(c.get().min(len)));
    }
    /// Start an arm's count from zero.
    ///
    /// Without this the instrument can RUBBER-STAMP A HOLE, which is the failure it was
    /// added to prevent. The direction that matters is this: a spawned thread
    /// would make `calls > 0` fail spuriously, which is merely annoying, but a test
    /// harness that REUSES a thread lets one arm inherit an earlier arm's count and pass
    /// without ever entering the decoder. Resetting at the top of the assertion's own arm
    /// closes that regardless of how the harness schedules threads.
    pub(crate) fn reset() {
        CALLS.with(|c| c.set(0));
        SHORTEST.with(|c| c.set(usize::MAX));
    }
    thread_local! {
        /// The DECODER BRANCHES this codec's own encoder can never produce, counted the same
        /// way and for the same reason: which of them does no reference frame in the sweep
        /// reach? That is the question that found the interleaved decoder at ZERO across 117
        /// frames, so it is answered by counting rather than by reasoning.
        static BRANCH: Cell<[usize; 8]> = const { Cell::new([0; 8]) };
    }
    /// 0 = treeless literals, 1 = single-stream Huffman, 2 = RLE sequence table,
    /// 3 = repeat-mode sequence table, 4 = raw literals, 5 = RLE literals,
    /// 6 = an RLE block, 7 = a raw block.
    ///
    /// **The last four were added by asking the same question one layer out.** The first
    /// four are branches inside a COMPRESSED block; these are the block and literals-section
    /// KINDS, which is a different axis and had never been counted at all. Three of the
    /// original four were at zero when first measured, so the axis nobody had looked at was
    /// worth looking at.
    pub(crate) fn branch(i: usize) {
        BRANCH.with(|c| {
            let mut v = c.get();
            v[i] += 1;
            c.set(v);
        });
    }
    pub(crate) fn branches() -> [usize; 8] {
        BRANCH.with(Cell::get)
    }
    pub(crate) fn reset_branches() {
        BRANCH.with(|c| c.set([0; 8]));
    }
    pub(crate) fn calls() -> usize {
        CALLS.with(Cell::get)
    }
    /// `usize::MAX` means the interleaved decoder was never entered on this thread.
    pub(crate) fn shortest() -> usize {
        SHORTEST.with(Cell::get)
    }
}

/// How the state table is walked while symbols are spread across it.
fn step_for(table_size: u32) -> u32 {
    (table_size >> 1) + (table_size >> 3) + 3
}

/// Places each symbol across the state table in the order both sides must agree on.
fn spread(norm: &[i16], table_log: u32) -> io::Result<Vec<u8>> {
    let table_size = 1u32 << table_log;
    let mask = table_size - 1;
    let step = step_for(table_size);
    let mut symbols = vec![0u8; table_size as usize];
    let mut high = table_size - 1;

    // the below-one-slot symbols take the highest states, where codes are longest
    for (s, &n) in norm.iter().enumerate() {
        if n == -1 {
            symbols[high as usize] = s as u8;
            high = high
                .checked_sub(1)
                .ok_or_else(|| bad("more low-probability symbols than states"))?;
        }
    }
    let mut position = 0u32;
    for (s, &n) in norm.iter().enumerate() {
        for _ in 0..n.max(0) {
            symbols[position as usize] = s as u8;
            position = (position + step) & mask;
            while position > high {
                position = (position + step) & mask;
            }
        }
    }
    if position != 0 {
        return Err(bad(
            "the spread did not return to its start; the counts do not fill the table",
        ));
    }
    Ok(symbols)
}

/// The encoder's side of one table.
pub struct CTable {
    table_log: u32,
    /// State transitions, indexed by cumulative position.
    next: Vec<u16>,
    /// Per symbol: how many bits to emit, and where its states begin.
    delta_bits: Vec<i32>,
    delta_find: Vec<i32>,
}

impl CTable {
    pub fn new(norm: &[i16], table_log: u32) -> io::Result<CTable> {
        let table_size = 1u32 << table_log;
        let symbols = spread(norm, table_log)?;
        let mut cumul = vec![0u32; norm.len() + 1];
        for s in 0..norm.len() {
            cumul[s + 1] = cumul[s]
                + if norm[s] == -1 {
                    1
                } else {
                    norm[s].max(0) as u32
                };
        }
        let mut cursor = cumul.clone();
        let mut next = vec![0u16; table_size as usize];
        for u in 0..table_size {
            let s = symbols[u as usize] as usize;
            next[cursor[s] as usize] = (table_size + u) as u16;
            cursor[s] += 1;
        }

        let mut delta_bits = vec![0i32; norm.len()];
        let mut delta_find = vec![0i32; norm.len()];
        let mut total = 0i32;
        for (s, &n) in norm.iter().enumerate() {
            match n {
                0 => delta_bits[s] = (((table_log + 1) as i32) << 16) - (1 << table_log),
                -1 | 1 => {
                    delta_bits[s] = ((table_log as i32) << 16) - (1 << table_log);
                    delta_find[s] = total - 1;
                    total += 1;
                }
                n => {
                    let n = i32::from(n);
                    let max_bits = table_log as i32 - high_bit((n - 1) as u32) as i32;
                    let min_state = n << max_bits;
                    delta_bits[s] = (max_bits << 16) - min_state;
                    delta_find[s] = total - n;
                    total += n;
                }
            }
        }
        Ok(CTable {
            table_log,
            next,
            delta_bits,
            delta_find,
        })
    }

    /// The state a stream starts in for `symbol`, emitting no bits.
    ///
    /// Public because a zstd block drives THREE of these in a fixed interleaving that
    /// `encode` cannot express; the order is the protocol and lives in `block.rs`.
    pub fn init_state_pub(&self, symbol: u8) -> u32 {
        self.init_state(symbol)
    }

    /// One symbol, advancing `state`. Public for the same reason as `init_state_pub`.
    pub fn encode_pub(&self, state: &mut u32, symbol: u8, w: &mut BitWriter) {
        self.encode(state, symbol, w);
    }

    fn init_state(&self, symbol: u8) -> u32 {
        let s = symbol as usize;
        let nb = ((self.delta_bits[s] + (1 << 15)) >> 16) as u32;
        let v = ((nb as i32) << 16) - self.delta_bits[s];
        self.next[((v >> nb) + self.delta_find[s]) as usize] as u32
    }

    fn encode(&self, state: &mut u32, symbol: u8, w: &mut BitWriter) {
        let s = symbol as usize;
        let nb = ((*state as i32 + self.delta_bits[s]) >> 16) as u32;
        w.add(*state, nb);
        *state = self.next[(((*state >> nb) as i32) + self.delta_find[s]) as usize] as u32;
    }
}

/// Encodes `input` with `table`, producing a stream `decode` reads back.
///
/// Symbols go in REVERSE and the state is flushed last, so that the decoder -- which reads
/// the stream backwards -- meets the state first and then recovers symbols in order. That
/// inversion is the whole trick of tANS and there is no way to test it partially: get it
/// wrong and nothing round-trips, which is at least a loud failure.
pub fn encode(input: &[u8], table: &CTable) -> io::Result<Vec<u8>> {
    if input.is_empty() {
        return Err(bad("nothing to encode"));
    }
    let mut w = BitWriter::new();
    let mut state = table.init_state(input[input.len() - 1]);
    for &sym in input[..input.len() - 1].iter().rev() {
        table.encode(&mut state, sym, &mut w);
    }
    w.add(state, table.table_log);
    Ok(w.finish())
}

/// The decoder's side of one table.
///
/// `Clone` because a zstd block may say its sequence table is a REPEAT of the previous
/// block's, so a frame has to keep the last one alive across block boundaries.
#[derive(Clone)]
pub struct DTable {
    table_log: u32,
    symbol: Vec<u8>,
    nb_bits: Vec<u8>,
    new_state: Vec<u16>,
}

impl DTable {
    /// The symbol a state decodes to, and the two numbers needed to leave it.
    ///
    /// Public for the same reason as `CTable::init_state_pub`: a zstd block drives three
    /// of these in a fixed interleaving that `decode` cannot express.
    pub fn at(&self, state: usize) -> Option<(u8, u32, usize)> {
        Some((
            *self.symbol.get(state)?,
            u32::from(self.nb_bits[state]),
            self.new_state[state] as usize,
        ))
    }

    pub fn log(&self) -> u32 {
        self.table_log
    }

    pub fn new(norm: &[i16], table_log: u32) -> io::Result<DTable> {
        let table_size = 1u32 << table_log;
        let symbols = spread(norm, table_log)?;
        let mut next: Vec<i32> = norm
            .iter()
            .map(|&n| if n == -1 { 1 } else { i32::from(n.max(0)) })
            .collect();
        let mut nb_bits = vec![0u8; table_size as usize];
        let mut new_state = vec![0u16; table_size as usize];
        for u in 0..table_size as usize {
            let s = symbols[u] as usize;
            let n = next[s];
            next[s] += 1;
            let bits = table_log - high_bit(n as u32);
            nb_bits[u] = bits as u8;
            new_state[u] = (((n as u32) << bits) - table_size) as u16;
        }
        Ok(DTable {
            table_log,
            symbol: symbols,
            nb_bits,
            new_state,
        })
    }
}

/// Decodes exactly `count` symbols.
///
/// The count is required rather than inferred: an FSE stream does not say how many symbols
/// it holds, and in a real block that number comes from the sequences header. Guessing it
/// from the remaining bits would read padding as data.
pub fn decode(data: &[u8], count: usize, table: &DTable) -> io::Result<Vec<u8>> {
    let mut r = BitReader::new(data)?;
    let mut state = r.read(table.table_log)? as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        if state >= table.symbol.len() {
            return Err(bad("the decoder reached a state outside its table"));
        }
        out.push(table.symbol[state]);
        // NO READ AFTER THE LAST SYMBOL, and getting this wrong is the first thing that
        // breaks. The encoder emits `n - 1` symbol codes for `n` symbols -- the first
        // symbol it processes only SETS the state and writes nothing, and that state is
        // flushed at the end. So a decoder that reads once per symbol asks for one field
        // that was never written and dies with "the bitstream ran out", which reads like a
        // truncated stream rather than an off-by-one in the loop. Measured: that is
        // exactly how this failed first.
        if i + 1 < count {
            let bits = u32::from(table.nb_bits[state]);
            let base = table.new_state[state] as usize;
            state = base + r.read(bits)? as usize;
        }
    }
    Ok(out)
}

/// Decodes an FSE stream that uses TWO interleaved states and does not say how many
/// symbols it holds.
///
/// This is the shape zstd's generic `FSE_decompress` writes, and it is what carries a
/// Huffman weight table. Two differences from `decode`, both of which matter:
///
/// - **Two states, alternating.** The encoder ran two independent state machines over
///   alternate symbols, so the decoder must too. Reading a two-state stream with one state
///   produces symbols, just not the right ones.
/// - **The end is found, not told.** `max` is a ceiling that stops a corrupt stream
///   spinning, NOT the expected length -- passing the length you want would truncate a
///   real table or read padding as a weight.
///
/// **"Stop when the bits run out" is wrong here, and it is wrong by exactly one symbol.**
/// Measured against a reference frame: that rule produced 115 weights whose probabilities
/// summed to 1015 of 1024, leaving 9 -- not a power of two, so no Huffman code completes.
/// The shortfall is a whole symbol, which is why it reads as a corrupt table rather than
/// an off-by-one.
///
/// The real rule is the reference's, and it is not the obvious one. `FSE_decompress`
/// decodes a symbol, asks its reader to reload, and treats **overflow** as the end -- at
/// which point it decodes ONE more symbol from the other state, because both states are
/// still holding one when the bits stop. Overflow there means "more than 64 bits have been
/// consumed from the container", and once that container is anchored at the start of the
/// buffer it is the same statement as "more bits were requested than the stream held". So
/// this positional reader does not need to grow zstd's sliding container to agree with it:
/// it records whether any request exceeded what remained, which is that predicate said
/// another way.
///
/// The boundary is STRICT. A request for exactly the remaining bits is not overflow, and a
/// reader that treats it as one drops the final pair.
///
/// **That equivalence is easy to doubt, and a derivation settles it.** The doubtful case
/// is a bitstream SHORTER THAN 8 BYTES: the reference's backward init counts the missing
/// bytes of a short buffer as already consumed, so a container judged with `> 64` and a
/// positional reader judged with `> remaining()` need not stop at the same symbol.
///
/// They do. For a buffer of length `L < 8` whose last byte has its highest set bit at
/// position `h`, the reference starts at
///
/// ```text
/// bitsConsumed = (8 - h) + (8 - L) * 8
/// ```
///
/// so the number of bits it may take before `bitsConsumed > 64` is exactly `(L - 1) * 8 + h`
/// -- which is the payload an absolute cursor sees when it starts on the end-mark bit and
/// reads only below it. The zero bytes a short container is padded with are PRE-CHARGED as
/// consumed by that init, so they are not a second budget to spend. Exact exhaustion is
/// `bitsConsumed == 64`, which the reference treats as completed rather than overflow, and
/// the `take` below is strict in the same direction. An attempt to construct a disagreeing
/// (length, last byte, width sequence) triple from this failed.
///
/// So the rule stands, and what actually needed fixing was the evidence offered for it.
///
/// The first thing counting showed was that the evidence deserved distrust, even if the
/// rule did not: the 117-frame boundary sweep entered this function **zero times**. This
/// codec writes direct weight tables only, so nothing it produces reaches here, and the
/// reference had chosen the direct form for every corpus in the sweep. The agreement being
/// cited as evidence was agreement about a function that never ran.
///
/// A skewed wide-alphabet family now forces the FSE branch, and the sweep enters here 36
/// times. Separately, a search over alphabets 12..256, inputs 24..16384 bytes and levels
/// 1, 5, 9 and 19 -- **525 calls** -- found the shortest weight bitstream zstd 1.5.5 emits
/// at this call site to be **10 bytes**. Not one fell below 8.
///
/// So: the disputed case is not merely uncovered, it did not occur once in 525 attempts to
/// provoke it from the reference. That is evidence it is hard to reach here, NOT proof it
/// is unreachable -- another producer, another version, or the sequences bitstream (a
/// different loop) could still get there. What is now true is that the claim has a scope,
/// and the function it is about is actually exercised against the reference.
pub fn decode_interleaved(data: &[u8], table: &DTable, max: usize) -> io::Result<Vec<u8>> {
    #[cfg(test)]
    seen::note(data.len());
    let mut r = BitReader::new(data)?;
    let mut s1 = r.read(table.table_log)? as usize;
    let mut s2 = r.read(table.table_log)? as usize;
    let size = 1usize << table.table_log;
    let mut out: Vec<u8> = Vec::new();
    let mut over = false;

    // Past the start of the buffer every bit reads as zero, which is exactly what the
    // reference's container hands out once it can no longer refill. `over` is set when the
    // request was larger than what remained -- the reload overflow, expressed positionally.
    fn take(r: &mut BitReader<'_>, nb: u32, over: &mut bool) -> u32 {
        if nb > r.remaining() {
            *over = true;
        }
        let v = r.peek(nb);
        r.skip(nb);
        v
    }

    loop {
        let (sym, bits, next) = table.at(s1).ok_or_else(|| bad("a state left its table"))?;
        out.push(sym);
        if out.len() > max {
            return Err(bad(
                "the interleaved stream decoded past the end of its alphabet",
            ));
        }
        s1 = next + take(&mut r, bits, &mut over) as usize;
        if s1 >= size {
            return Err(bad("a state left its table"));
        }
        if over {
            out.push(table.at(s2).ok_or_else(|| bad("a state left its table"))?.0);
            break;
        }
        let (sym, bits, next) = table.at(s2).ok_or_else(|| bad("a state left its table"))?;
        out.push(sym);
        if out.len() > max {
            return Err(bad(
                "the interleaved stream decoded past the end of its alphabet",
            ));
        }
        s2 = next + take(&mut r, bits, &mut over) as usize;
        if s2 >= size {
            return Err(bad("a state left its table"));
        }
        if over {
            out.push(table.at(s1).ok_or_else(|| bad("a state left its table"))?.0);
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts_of(data: &[u8]) -> (Vec<u32>, u32) {
        let top = data.iter().copied().max().unwrap_or(0) as usize;
        let mut c = vec![0u32; top + 1];
        for &b in data {
            c[b as usize] += 1;
        }
        (c, data.len() as u32)
    }

    fn round_trip(data: &[u8], table_log: u32) -> io::Result<Vec<u8>> {
        let (counts, total) = counts_of(data);
        let norm = normalize(&counts, total, table_log)?;
        let ct = CTable::new(&norm, table_log)?;
        let stream = encode(data, &ct)?;
        let dt = DTable::new(&norm, table_log)?;
        decode(&stream, data.len(), &dt)
    }

    /// The bit writer and the backward reader are inverses, field by field.
    ///
    /// This is separate from the coder arms because a bit-layer defect shows up there as
    /// "nothing round-trips", which says nothing about WHICH layer is wrong.
    #[test]
    fn the_backward_reader_returns_the_fields_the_writer_appended_in_reverse() {
        let fields: Vec<(u32, u32)> = vec![
            (1, 1),
            (0, 1),
            (5, 3),
            (255, 8),
            (0, 5),
            (12345, 17),
            (1, 32),
        ];
        let mut w = BitWriter::new();
        for &(v, n) in &fields {
            w.add(v, n);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes).expect("a finished stream has a sentinel");
        for &(v, n) in fields.iter().rev() {
            assert_eq!(
                r.read(n).expect("field"),
                v,
                "a {n}-bit field did not come back"
            );
        }
        assert_eq!(
            r.remaining(),
            0,
            "the reader did not land exactly on the start"
        );

        // THE CONTROL: without the sentinel the reader cannot know where data stopped, so
        // a stream of zero bytes is refused rather than read as a run of zero symbols.
        assert!(BitReader::new(&[0u8, 0, 0]).is_err());
        // and a reader asked for more than it holds says so
        let mut r = BitReader::new(&bytes).expect("sentinel");
        assert!(r.read(200).is_err());
    }

    /// A table description survives being written and read, including the width narrowing.
    #[test]
    fn a_table_description_round_trips_with_its_widths() {
        for data in [
            vec![0u8; 400],
            (0..=255u8).cycle().take(4000).collect::<Vec<u8>>(),
            b"the quick brown fox jumps over the lazy dog".repeat(30),
            // one dominant symbol plus a long tail, which is what forces both the -1 case
            // and the zero-run flags
            {
                let mut v = vec![7u8; 5000];
                for s in 0..=60u8 {
                    v.push(s * 4);
                }
                v
            },
        ] {
            for table_log in [MIN_TABLE_LOG, 7, MAX_TABLE_LOG] {
                let (counts, total) = counts_of(&data);
                // an alphabet wider than the table is a refusal by name, not a defect: it
                // is the caller's accuracy log that is wrong, and the arm below proves the
                // refusal is specific rather than a catch-all
                let norm = match normalize(&counts, total, table_log) {
                    Ok(n) => n,
                    Err(e) => {
                        assert!(
                            e.to_string().contains("more distinct symbols than states"),
                            "log {table_log}: unexpected refusal {e}"
                        );
                        continue;
                    }
                };
                let wire = write_ncount(&norm, table_log).expect("write");
                let (back, log_back, _used) = read_ncount(&wire).expect("read");
                assert_eq!(log_back, table_log, "the accuracy log did not survive");
                // trailing zeros are not carried, so compare the meaningful prefix
                let keep = norm.iter().rposition(|&n| n != 0).map_or(0, |i| i + 1);
                assert_eq!(
                    &back[..keep.min(back.len())],
                    &norm[..keep],
                    "counts differ at log {table_log} for a {}-byte corpus",
                    data.len()
                );
            }
        }
    }

    /// Where does the description END? In a real block the bitstream starts at that byte.
    ///
    /// This arm exists because the answer was WRONG and nothing caught it. `read_ncount`
    /// added one to its byte count "for a partial trailing byte", which the reader had
    /// already pulled into its accumulator -- so every description reported one byte too
    /// many. The counts were perfect, so every round-trip arm above stayed green; what
    /// broke was the Huffman weight bitstream that follows a description in a real block.
    /// Read one byte late it still decoded 115 plausible weights and then ran out, leaving
    /// probabilities summing to 1015 of 1024 -- a corrupt-looking table, two symbols short,
    /// with nothing pointing at the header.
    ///
    /// So the property is not "the counts survive" but "the reader agrees with the writer
    /// about where to stop", and the way to state that is to put known bytes after the
    /// description and require them back.
    #[test]
    fn the_description_reports_the_byte_where_the_stream_after_it_begins() {
        let tail: &[u8] = b"\xa5THE-BITSTREAM-STARTS-HERE\x5a";
        let mut checked = 0;
        // The two SHAPES a description can end in. A reader that is wrong only for one of
        // them -- "add a byte when the last one is full" -- passes an arm that happens to
        // sample only the other, and nothing in the sweep below guarantees both appear.
        // So count them and refuse to conclude anything until each has been seen.
        let (mut ended_mid_byte, mut ended_on_boundary) = (0, 0);
        let mut corpora: Vec<Vec<u8>> = vec![
            vec![0u8; 400],
            b"the quick brown fox jumps over the lazy dog".repeat(30),
            (0..=255u8).cycle().take(4000).collect::<Vec<u8>>(),
            {
                let mut v = vec![7u8; 5000];
                for s in 0..=60u8 {
                    v.push(s * 4);
                }
                v
            },
        ];
        // Those four were the whole sweep until the alignment count was added, and the
        // count is why they are no longer enough: all twelve of the descriptions they
        // produce end MID-BYTE, none on a boundary. So the shape a "add one when the last
        // byte is full" reader gets wrong was never once sampled -- the arm looked
        // thorough and covered half the space.
        //
        // A description's bit length falls out of its distribution and accuracy log and
        // cannot be dialed in directly, so vary the alphabet width instead and let both
        // shapes turn up. The assertion below is what makes that a measurement rather
        // than a hope.
        for distinct in 2u32..=48 {
            let mut v = vec![9u8; 600];
            for s in 0..distinct {
                let run = (distinct - s) as usize + 1;
                v.extend(std::iter::repeat_n((s * 5 + 1) as u8, run));
            }
            corpora.push(v);
        }
        for data in corpora {
            for table_log in [MIN_TABLE_LOG, 6, 7, MAX_TABLE_LOG] {
                let (counts, total) = counts_of(&data);
                let Ok(norm) = normalize(&counts, total, table_log) else {
                    continue;
                };
                let wire = write_ncount(&norm, table_log).expect("write");
                let mut block = wire.clone();
                block.extend_from_slice(tail);
                let (_, _, used, live) = read_ncount_live(&block).expect("read");
                assert_eq!(
                    used,
                    wire.len(),
                    "log {table_log}: the description is {} bytes but the reader stopped at {used}",
                    wire.len()
                );
                assert_eq!(
                    &block[used..],
                    tail,
                    "log {table_log}: the bytes after the description were not handed back intact"
                );
                if live == 0 {
                    ended_on_boundary += 1
                } else {
                    ended_mid_byte += 1
                }
                checked += 1;
            }
        }
        assert!(
            checked >= 8,
            "only {checked} descriptions were measured, which is not a sample"
        );
        assert!(
            ended_mid_byte > 0 && ended_on_boundary > 0,
            "the sweep measured {ended_mid_byte} descriptions ending mid-byte and \
             {ended_on_boundary} ending on a byte boundary. Both shapes must appear or this \
             arm cannot see a reader that is wrong for only one of them -- widen the corpora \
             or the accuracy logs until it does"
        );

        // THE CONTROL. Replant the defect -- one extra byte of boundary -- and require the
        // check to fire. Without this the arm would pass on a reader that always returned
        // the right answer for the wrong reason, and it would also have passed before the
        // fix if `used` happened to land on a byte boundary for every case above.
        let (counts, total) = counts_of(b"the quick brown fox jumps over the lazy dog");
        let norm = normalize(&counts, total, 6).expect("normalize");
        let wire = write_ncount(&norm, 6).expect("write");
        let mut block = wire.clone();
        block.extend_from_slice(tail);
        let (_, _, used) = read_ncount(&block).expect("read");
        let planted = used + 1;
        assert_ne!(&block[planted..], tail, "the control did not fire: a boundary one byte late is indistinguishable from the right one here, so this arm proves nothing");
    }

    /// Encode then decode returns the input, across distributions chosen to break it.
    #[test]
    fn the_coder_round_trips_across_awkward_distributions() {
        let mut cases: Vec<Vec<u8>> = vec![
            vec![3u8; 1],
            vec![3u8; 2],
            vec![0u8, 1, 0, 1, 0, 1],
            b"the quick brown fox jumps over the lazy dog".repeat(50),
        ];
        // a heavy skew plus rare symbols: the rare ones normalize to -1 and land in the
        // states with the longest codes, which is the case a naive table gets wrong
        let mut skew = vec![9u8; 6000];
        for s in 1..=40u8 {
            skew.push(s);
        }
        cases.push(skew);
        // near-uniform over a wide alphabet, which stresses the spread rather than the tail
        cases.push((0..=200u8).cycle().take(6000).collect());

        for data in cases {
            for table_log in [MIN_TABLE_LOG, 6, 8, MAX_TABLE_LOG] {
                let got = round_trip(&data, table_log);
                match got {
                    Ok(back) => assert_eq!(
                        back,
                        data,
                        "log {table_log}, {} bytes: the coder changed the symbols",
                        data.len()
                    ),
                    // a table too small for the alphabet is a refusal by name, not a panic
                    Err(e) => assert!(
                        e.to_string().contains("states")
                            || e.to_string().contains("balanced")
                            || e.to_string().contains("fill the table"),
                        "log {table_log}: unexpected failure {e}"
                    ),
                }
            }
        }
    }

    /// THE CONTROL for the coder arms: a stream decoded against the WRONG table must not
    /// return the input.
    ///
    /// Without this, `round_trip` would pass against a coder that ignored its table and
    /// echoed the input -- and an entropy coder that ignores its table is exactly the
    /// shape a first implementation accidentally takes.
    #[test]
    fn decoding_against_a_different_table_does_not_return_the_input() {
        let data = b"aaaaaaaaaabbbbbccccdde".repeat(40);
        let (counts, total) = counts_of(&data);
        let norm = normalize(&counts, total, 7).expect("normalize");
        let ct = CTable::new(&norm, 7).expect("ctable");
        let stream = encode(&data, &ct).expect("encode");

        // the right table returns the input
        let dt = DTable::new(&norm, 7).expect("dtable");
        assert_eq!(decode(&stream, data.len(), &dt).expect("decode"), data);

        // a table built from a DIFFERENT distribution must not
        let other: Vec<u8> = b"zzzzzyyyyxxxwwv".repeat(40).to_vec();
        let (oc, ot) = counts_of(&other);
        let onorm = normalize(&oc, ot, 7).expect("normalize");
        let odt = DTable::new(&onorm, 7).expect("dtable");
        // EITHER OUTCOME IS EVIDENCE, and the reasoning is worth writing down because the
        // first instinct is that the error branch makes this vacuous. It does not. The
        // hypothesis under test is "the coder ignores its table and just echoes bytes" --
        // and such a coder would SUCCEED with both tables and return the input both times.
        // The assertion above already pins that the right table succeeds and returns the
        // input. So a wrong table that either fails or returns something else rules the
        // hypothesis out; only "succeeds and returns the input" would support it.
        //
        // Measured here: the wrong table FAILS, because differing per-state bit widths
        // make the decoder consume the stream at a different rate and run off the end.
        // That is the table being consulted, loudly.
        match decode(&stream, data.len(), &odt) {
            Ok(back) => assert_ne!(
                back, data,
                "the wrong table returned the input; the coder is not using its table"
            ),
            Err(e) => assert!(
                e.to_string().contains("ran out") || e.to_string().contains("outside its table"),
                "the wrong table failed for an unrelated reason: {e}"
            ),
        }

        // And the transformation is real rather than a copy: an entropy coder that
        // returned its input would pass every round-trip arm in this file.
        assert_ne!(stream, data, "the encoder emitted its input unchanged");
        assert!(
            stream.len() < data.len(),
            "encoding {} bytes produced {} -- no coding happened",
            data.len(),
            stream.len()
        );
    }

    /// Normalized counts always sum to the table size and never delete a symbol that
    /// occurs. A table that cannot represent an input symbol is not a rounding error.
    #[test]
    fn normalization_fills_the_table_and_keeps_every_symbol_that_occurs() {
        let corpora: Vec<Vec<u8>> = vec![
            vec![1u8; 1000],
            (0..=255u8).cycle().take(10_000).collect(),
            {
                let mut v = vec![0u8; 20_000];
                v.extend((1..=30u8).collect::<Vec<u8>>());
                v
            },
        ];
        for data in corpora {
            for table_log in MIN_TABLE_LOG..=MAX_TABLE_LOG {
                let (counts, total) = counts_of(&data);
                let Ok(norm) = normalize(&counts, total, table_log) else {
                    continue;
                };
                let sum: i64 = norm
                    .iter()
                    .map(|&n| if n < 0 { 1 } else { i64::from(n) })
                    .sum();
                assert_eq!(
                    sum,
                    1i64 << table_log,
                    "log {table_log}: the table is not full"
                );
                for (s, &c) in counts.iter().enumerate() {
                    if c > 0 {
                        assert_ne!(
                            norm[s], 0,
                            "log {table_log}: symbol {s} occurs {c} times and was normalized away"
                        );
                    }
                }
            }
        }
    }
}
