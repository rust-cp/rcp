//! Huffman-coded literals, which is what the reference reaches for on text.
//!
//! Stage 3 shipped raw literals, so a block's literals crossed at their own size while the
//! sequences were entropy-coded. This is the other half of the ratio, and it is also what
//! unlocks READING a reference frame made from compressible input -- that arm currently
//! records a refusal by name, and this is what turns it into a decode.
//!
//! ## Weights, not lengths, and the last one is inferred
//!
//! zstd does not serialize code lengths. It serializes WEIGHTS, where a symbol's code
//! length is `max_bits + 1 - weight` and weight 0 means absent. The weight of the LAST
//! symbol is never written: it is deduced from the others, because a complete Huffman code
//! leaves exactly one possibility. That deduction is only correct for a COMPLETE tree, so
//! an encoder that emitted a non-canonical or incomplete code would produce a header the
//! decoder misreads rather than rejects.
//!
//! ## Four streams, because one cannot hold a block's literals
//!
//! The single-stream literals header carries a 10-bit size, so it caps at 1023 bytes --
//! far under a 128 KiB block. So the format's 4-stream mode is not an optimization here,
//! it is the only shape that fits: the literals are split into four parts, each coded
//! independently, with a 6-byte jump table giving the first three compressed sizes. Both
//! sides compute the split the same way or the streams desynchronise silently.
//!
//! ## What is NOT implemented, and is refused rather than guessed
//!
//! The weight table uses the **direct** 4-bit representation, which tops out at 128
//! explicit weights. A literal alphabet whose highest byte exceeds that cannot be
//! described this way, and rather than guess, `encode` returns `None` and the caller falls
//! back to raw literals. FSE-coded weights are the format's answer and are not here yet.

use super::fse::{BitReader, BitWriter};
use std::io;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zstd/huff: {what}"))
}

/// zstd's ceiling for a literals Huffman code.
const MAX_BITS: u32 = 11;

/// The highest symbol index the direct weight representation can describe.
const MAX_DIRECT_SYMBOL: usize = 128;

fn high_bit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// A built code: bits per symbol, the value to emit, and the table log.
pub struct Table {
    pub bits: Vec<u8>,
    pub code: Vec<u16>,
    pub max_bits: u32,
    /// The highest symbol index with a code, which sets the header's symbol count.
    pub last: usize,
}

/// Builds a canonical code over `data`'s byte frequencies, or `None` when the alphabet
/// cannot be described by the direct weight representation.
pub fn build(data: &[u8]) -> Option<Table> {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let last = (0..256).rposition(|s| freq[s] > 0)?;
    if last > MAX_DIRECT_SYMBOL {
        return None;
    }
    let distinct = freq.iter().filter(|&&f| f > 0).count();
    if distinct < 2 {
        // a one-symbol alphabet has no code to speak of; zstd spells that an RLE literals
        // block, which is a different section type and not this one's business
        return None;
    }
    let bits = crate::deflate::code_lengths(&freq[..=last], MAX_BITS);
    let max_bits = u32::from(*bits.iter().max()?);
    if max_bits == 0 || max_bits > MAX_BITS {
        return None;
    }

    // Canonical values, assigned from the LONGEST code down and in symbol order within a
    // length -- which is the order the reference's own table builder assumes. Assigning
    // from the shortest up instead produces a code that is self-consistent and that the
    // reference decodes to the wrong symbols.
    let mut per_rank = vec![0u16; (max_bits + 2) as usize];
    for &b in &bits {
        if b > 0 {
            per_rank[b as usize] += 1;
        }
    }
    let mut val_per_rank = vec![0u16; (max_bits + 2) as usize];
    let mut min = 0u16;
    for n in (1..=max_bits as usize).rev() {
        val_per_rank[n] = min;
        min += per_rank[n];
        min >>= 1;
    }
    let mut code = vec![0u16; bits.len()];
    for (s, &b) in bits.iter().enumerate() {
        if b > 0 {
            code[s] = val_per_rank[b as usize];
            val_per_rank[b as usize] += 1;
        }
    }
    Some(Table {
        bits,
        code,
        max_bits,
        last,
    })
}

/// Serializes the tree as a direct 4-bit weight table.
fn weights(t: &Table) -> io::Result<Vec<u8>> {
    // weight = max_bits + 1 - length, and 0 for an absent symbol. The LAST symbol's weight
    // is deliberately not written; see the module note.
    let mut w = Vec::with_capacity(t.last);
    for s in 0..t.last {
        let b = u32::from(*t.bits.get(s).unwrap_or(&0));
        w.push(if b == 0 {
            0u8
        } else {
            (t.max_bits + 1 - b) as u8
        });
    }
    if t.last == 0 || t.last > MAX_DIRECT_SYMBOL {
        return Err(bad(
            "the alphabet does not fit the direct weight representation",
        ));
    }
    let mut out = Vec::with_capacity(1 + w.len().div_ceil(2));
    out.push((127 + t.last) as u8);
    for pair in w.chunks(2) {
        // the FIRST of a pair takes the HIGH nibble, which is the opposite of the
        // little-endian instinct and is how the format reads them back
        let hi = pair[0] << 4;
        let lo = pair.get(1).copied().unwrap_or(0);
        out.push(hi | lo);
    }
    Ok(out)
}

/// Reads a direct weight table, returning bits-per-symbol and the table log.
fn read_weights(data: &[u8]) -> io::Result<(Vec<u8>, u32, usize)> {
    let &header = data
        .first()
        .ok_or_else(|| bad("the tree description is empty"))?;
    if header < 128 {
        // FSE-CODED WEIGHTS, which is what the reference writes on anything but a tiny
        // alphabet. The header byte is the SIZE of the description plus its bitstream, so
        // the boundary between the tree and the streams after it is explicit rather than
        // inferred -- which is the one thing that makes this decodable at all.
        let size = header as usize;
        if data.len() < 1 + size {
            return Err(bad("the FSE-coded weight table is truncated"));
        }
        let body = &data[1..1 + size];
        let (norm, table_log, used) = super::fse::read_ncount(body)?;
        let dt = super::fse::DTable::new(&norm, table_log)?;
        // 255 is the alphabet ceiling, NOT an expected length: the stream says nothing
        // about how many weights it holds and the decoder's own termination finds that.
        let w = super::fse::decode_interleaved(&body[used..], &dt, 255)?;
        let (bits, max_bits) = finish_weights(&w)?;
        return Ok((bits, max_bits, 1 + size));
    }
    let count = header as usize - 127;
    let bytes = count.div_ceil(2);
    if data.len() < 1 + bytes {
        return Err(bad("the weight table is truncated"));
    }
    let mut w = Vec::with_capacity(count + 1);
    for i in 0..count {
        let byte = data[1 + i / 2];
        w.push(if i % 2 == 0 { byte >> 4 } else { byte & 0x0F });
    }
    let (bits, max_bits) = finish_weights(&w)?;
    Ok((bits, max_bits, 1 + bytes))
}

/// Turns a weight list into code lengths, deducing the weight the stream left out.
///
/// The omission is not a saving, it is the format's completeness check made load-bearing:
/// a complete code satisfies `sum 2^(w-1) + 2^(last-1) == 2^max_bits`, so the final weight
/// is whatever makes the sum a power of two -- and if nothing does, the table is corrupt
/// and says so here rather than producing a code that decodes plausible garbage.
///
/// Both tree encodings share this, which is the reason it is a function: the direct and
/// FSE-coded branches differ only in how the weights arrive.
fn finish_weights(w: &[u8]) -> io::Result<(Vec<u8>, u32)> {
    // A weight is a small integer. Shifting by `x - 1` before checking it panics when
    // a crafted table names 33 or more, in debug and in release (the release shift
    // wraps, then the rank table is indexed off the end).
    if w.len() >= 256 || w.iter().any(|&x| u32::from(x) > MAX_BITS) {
        return Err(bad("a Huffman weight exceeds the alphabet or depth limit"));
    }
    let total: u32 = w
        .iter()
        .map(|&x| if x > 0 { 1u32 << (x - 1) } else { 0 })
        .sum();
    if total == 0 {
        return Err(bad("every weight is zero"));
    }
    let max_bits = high_bit(total) + 1;
    if max_bits > MAX_BITS {
        return Err(bad("the described code is deeper than zstd allows"));
    }
    let rest = (1u32 << max_bits) - total;
    if rest == 0 || !rest.is_power_of_two() {
        return Err(bad("the weights do not complete a Huffman code"));
    }
    let last = (high_bit(rest) + 1) as u8;
    let bits = w
        .iter()
        .chain(std::iter::once(&last))
        .map(|&x| {
            if x == 0 {
                0u8
            } else {
                (max_bits + 1 - u32::from(x)) as u8
            }
        })
        .collect();
    Ok((bits, max_bits))
}

/// How a block's literals are split across the four streams. Both sides must agree.
fn split(total: usize) -> [usize; 4] {
    let per = total.div_ceil(4);
    let a = per.min(total);
    let b = per.min(total - a);
    let c = per.min(total - a - b);
    [a, b, c, total - a - b - c]
}

/// Codes one stream: symbols in REVERSE, so the backwards reader recovers them in order.
fn encode_stream(part: &[u8], t: &Table) -> Vec<u8> {
    let mut w = BitWriter::new();
    for &sym in part.iter().rev() {
        w.add(
            u32::from(t.code[sym as usize]),
            u32::from(t.bits[sym as usize]),
        );
    }
    w.finish()
}

/// The complete literals section content: tree description, jump table, four streams.
///
/// Returns `None` when Huffman cannot describe this alphabet or would not pay, so the
/// caller can emit raw literals instead. That is a routine outcome, not a failure.
pub fn encode(literals: &[u8]) -> Option<(Vec<u8>, Table)> {
    if literals.len() < 64 {
        return None;
    }
    let t = build(literals)?;
    let desc = weights(&t).ok()?;
    let parts = split(literals.len());
    let mut at = 0usize;
    let mut streams = Vec::with_capacity(4);
    for n in parts {
        streams.push(encode_stream(&literals[at..at + n], &t));
        at += n;
    }
    if streams.iter().take(3).any(|s| s.len() > u16::MAX as usize) {
        return None;
    }
    let mut out = desc;
    for s in streams.iter().take(3) {
        out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    }
    for s in &streams {
        out.extend_from_slice(s);
    }
    if out.len() >= literals.len() {
        return None;
    }
    Some((out, t))
}

/// Decodes a 4-stream Huffman literals section of `regenerated` bytes.
pub fn decode(content: &[u8], regenerated: usize, four_streams: bool) -> io::Result<Vec<u8>> {
    let (tree, used) = read_tree(content)?;
    tree.streams(&content[used..], regenerated, four_streams)
}

/// A built Huffman decode table, separated from the bytes it was read from.
///
/// It is a separate type because a **treeless** literals block sends no tree at all: it
/// uses the one from an earlier block in the same frame. So the table has to outlive the
/// block that described it, and a decoder that rebuilds per block simply cannot read those
/// blocks -- measured, `zstd -1` on structured log lines emits them.
#[derive(Clone)]
pub struct Tree {
    sym: Vec<u8>,
    len: Vec<u8>,
    max_bits: u32,
}

/// Reads a tree description and returns it with the number of bytes it occupied.
pub fn read_tree(content: &[u8]) -> io::Result<(Tree, usize)> {
    let (bits, max_bits, used) = read_weights(content)?;
    // A lookup indexed by the next `max_bits` bits: every code that starts with those bits
    // maps to the same symbol, so one peek resolves a symbol of any length.
    let size = 1usize << max_bits;
    let mut sym = vec![0u8; size];
    let mut len = vec![0u8; size];
    let mut per_rank = vec![0u32; (max_bits + 2) as usize];
    for &b in &bits {
        if b > 0 {
            per_rank[b as usize] += 1;
        }
    }
    let mut val_per_rank = vec![0u32; (max_bits + 2) as usize];
    let mut min = 0u32;
    for n in (1..=max_bits as usize).rev() {
        val_per_rank[n] = min;
        min += per_rank[n];
        min >>= 1;
    }
    for (s, &b) in bits.iter().enumerate() {
        if b == 0 {
            continue;
        }
        let code = val_per_rank[b as usize];
        val_per_rank[b as usize] += 1;
        let span = 1usize << (max_bits - u32::from(b));
        let start = (code as usize) << (max_bits - u32::from(b));
        if start + span > size {
            return Err(bad("a code runs outside the decode table"));
        }
        for i in 0..span {
            sym[start + i] = s as u8;
            len[start + i] = b;
        }
    }

    Ok((Tree { sym, len, max_bits }, used))
}

impl Tree {
    /// Decodes the stream section that follows a tree description.
    pub fn streams(
        &self,
        rest: &[u8],
        regenerated: usize,
        four_streams: bool,
    ) -> io::Result<Vec<u8>> {
        let (sym, len, max_bits) = (&self.sym, &self.len, self.max_bits);
        // ONE stream or FOUR, and the header's Size_Format is what says which. The four-stream
        // form exists so a decoder can run the streams in parallel and is what the reference
        // writes for a block-sized literals section; the single-stream form is what it writes
        // when the section is small enough that three extra bitstream tails cost more than the
        // parallelism is worth. Refusing the single-stream form means refusing ordinary prose:
        // measured, `zstd -1` on English text picks it and this decoder called that a boundary.
        let (bounds, parts): ([(usize, usize); 4], [usize; 4]) = if four_streams {
            if rest.len() < 6 {
                return Err(bad("the jump table is missing"));
            }
            let s1 = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            let s2 = u16::from_le_bytes([rest[2], rest[3]]) as usize;
            let s3 = u16::from_le_bytes([rest[4], rest[5]]) as usize;
            let body_len = rest.len() - 6;
            if s1 + s2 + s3 > body_len {
                return Err(bad(
                    "the jump table describes more bytes than the section holds",
                ));
            }
            (
                [
                    (0, s1),
                    (s1, s2),
                    (s1 + s2, s3),
                    (s1 + s2 + s3, body_len - s1 - s2 - s3),
                ],
                split(regenerated),
            )
        } else {
            (
                [(0, rest.len()), (0, 0), (0, 0), (0, 0)],
                [regenerated, 0, 0, 0],
            )
        };
        let body = if four_streams { &rest[6..] } else { rest };

        let mut out = Vec::with_capacity(regenerated);
        for (i, &(start, n)) in bounds.iter().enumerate() {
            if parts[i] == 0 {
                continue;
            }
            if n == 0 {
                return Err(bad("a stream is empty but its share of the output is not"));
            }
            let mut r = BitReader::new(&body[start..start + n])?;
            for _ in 0..parts[i] {
                let v = r.peek(max_bits) as usize;
                let nb = u32::from(len[v]);
                if nb == 0 {
                    return Err(bad("the stream contains a code the tree does not define"));
                }
                if nb > r.remaining() {
                    return Err(bad(
                        "a literals bitstream ran out before its symbols were complete",
                    ));
                }
                out.push(sym[v]);
                r.skip(nb);
            }
        }
        if out.len() != regenerated {
            return Err(bad(
                "the streams decoded to a different length than the header declared",
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..4000u32 {
            v.extend_from_slice(format!("request {i} completed in {} ms\n", i % 250).as_bytes());
        }
        v
    }

    /// A literals section round trips through this encoder and decoder.
    #[test]
    fn literals_round_trip_through_four_streams() {
        for data in [
            text(),
            b"aaaaabbbbcccdde".repeat(50),
            (0..=120u8).cycle().take(5000).collect::<Vec<u8>>(),
        ] {
            let (content, _t) = encode(&data).expect("this alphabet is describable");
            let back = decode(&content, data.len(), true).expect("decodes");
            assert_eq!(
                back,
                data,
                "a {}-byte literals section did not survive",
                data.len()
            );
        }
    }

    /// It actually compresses, which every round-trip arm above would pass without.
    #[test]
    fn the_literals_section_is_smaller_than_the_literals() {
        let data = text();
        let (content, t) = encode(&data).expect("encodes");
        eprintln!(
            "literals {} -> section {} ({} bits max, last symbol {})",
            data.len(),
            content.len(),
            t.max_bits,
            t.last
        );
        assert!(
            content.len() * 10 < data.len() * 9,
            "the section is {} bytes from {}; that is not coding",
            content.len(),
            data.len()
        );
    }

    /// The alphabet limit is a refusal, not a silent mis-encode.
    ///
    /// The control is the pair: the same data confined to low bytes IS encodable, so the
    /// arm is measuring the limit rather than a decoder that refuses everything.
    #[test]
    fn an_alphabet_outside_the_direct_representation_is_declined() {
        let wide: Vec<u8> = (0..=255u8).cycle().take(4000).collect();
        assert!(
            encode(&wide).is_none(),
            "a full-byte alphabet cannot use the direct weight table and must decline"
        );
        let narrow: Vec<u8> = (0..=120u8).cycle().take(4000).collect();
        assert!(
            encode(&narrow).is_some(),
            "control: a narrow alphabet must still encode"
        );
    }

    /// Weights survive serialization, including the inferred last one.
    #[test]
    fn the_weight_table_round_trips_and_infers_the_last_symbol() {
        let data = text();
        let t = build(&data).expect("builds");
        let wire = weights(&t).expect("serializes");
        let (bits, max_bits, used) = read_weights(&wire).expect("reads");
        assert_eq!(
            used,
            wire.len(),
            "the reader consumed a different number of bytes than were written"
        );
        assert_eq!(max_bits, t.max_bits, "the table log did not survive");
        for s in 0..=t.last {
            assert_eq!(
                bits[s], t.bits[s],
                "symbol {s}: {} bits became {}",
                t.bits[s], bits[s]
            );
        }
        // and the LAST symbol is the one that was never written, so this is the inference
        // being checked rather than a copy
        assert!(
            t.bits[t.last] > 0,
            "the fixture's last symbol must be present for the inference to mean anything"
        );
    }
}
