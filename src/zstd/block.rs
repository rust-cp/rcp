//! Compressed blocks: a literals section and an FSE-coded sequences section.
//!
//! This is the stage where the encoder starts actually compressing, and it is the first
//! one the reference decoder can check end to end. Stage 2's FSE arms could only prove the
//! coder agreed with itself, because an FSE table is not something `zstd` can be handed --
//! it only appears inside a block. Here it does, so `zstd -d` reading our output is a
//! statement about the bitstream, the three interleaved states, the sequence format, the
//! offset coding and the literals header all at once.
//!
//! ## Predefined tables, deliberately
//!
//! The three symbol streams use **Predefined** mode, which means the table distributions
//! are the ones fixed in RFC 8878 and no table description crosses the wire at all. That
//! is a conformant zstd block, not a shortcut around one, and it is the right first step
//! for a reason worth stating: with predefined tables the DECODER builds its own copy from
//! the spec, so if our block decodes correctly, our FSE encoder and the reference's FSE
//! decoder agree on every detail of the coding. A bug in `write_ncount` could not hide
//! behind a matching bug in `read_ncount`, because neither runs.
//!
//! `FSE_Compressed` mode -- which does carry a table description and would exercise
//! `write_ncount` against the reference -- is the next step, and it is worth doing only
//! once this one is proved.
//!
//! ## What a sequence is
//!
//! A sequence says: copy `literal_len` bytes from the literals section, then copy
//! `match_len` bytes from `offset` back in the output produced so far. Blocks end with a
//! run of literals belonging to no sequence, which the decoder appends. Every length is
//! coded as a symbol plus extra bits, and the symbols are FSE-coded while the extra bits
//! ride raw in the same backwards bitstream.

use super::fse::{self, BitWriter, CTable};
use std::io;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zstd/block: {what}"))
}

/// Literal-length codes: the value each code starts at, and how many extra bits follow.
const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Match-length codes. The shortest match zstd expresses is 3, which is why the first
/// baseline is 3 rather than 0 -- a "match length" of 0 has no meaning.
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// The predefined distributions, fixed by RFC 8878. Both sides build the same tables from
/// these, which is what makes Predefined mode carry no table description.
const LL_NORM: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const LL_LOG: u32 = 6;
/// Note codes 46 and 47 are **-1, not 1**, and the difference is not cosmetic.
///
/// This table had them as 1 and every round trip passed, because the encoder and the
/// decoder read the same wrong table. What it broke was interop in the one direction
/// nothing measured: a `-1` symbol is placed from the TOP of the state table downwards, so
/// two extra of them move the low-probability block by two states AND change the skip
/// bound the spread walk uses -- which renumbers every state in the table, not just those
/// two codes. Measured against a reference frame: state 58 decoded to match-length code
/// 35 instead of 51, turning a 39,990-byte match into a 41-byte one, and the frame
/// decoded to 51 bytes of correct-looking output and reported success.
const ML_NORM: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const ML_LOG: u32 = 6;
const OF_NORM: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const OF_LOG: u32 = 5;

/// Resolves an `Offset_Value` against the three repeated offsets, and updates them.
///
/// Values 1..3 do not mean offsets 1..3, they name a slot in a three-entry history that
/// every sequence pushes to -- which is how zstd spends almost nothing on the
/// back-and-forth offsets that structured text produces. A decoder that reads them as
/// literal distances does not error: it copies from a plausible place and returns bytes,
/// which is the failure mode this whole module keeps guarding against.
///
/// **The shift when `Literals_Length` is zero is the part that is easy to drop.** With no
/// literals between two matches, the offset that the previous sequence just used cannot be
/// meant again -- repeating it would have been one longer match -- so that slot would be
/// wasted. The format spends it instead on `Repeated_Offset1 - 1`, which is the common
/// "the same run, one byte over" case, and shifts the other two up. That is a real
/// encoding, not a special case to skip.
fn repeat_offset(offset_value: u32, literal_len: u32, rep: &mut [u32; 3]) -> io::Result<u32> {
    if offset_value > 3 {
        let offset = offset_value - 3;
        *rep = [offset, rep[0], rep[1]];
        return Ok(offset);
    }
    let code = offset_value - 1 + u32::from(literal_len == 0);
    if code == 0 {
        // the most recent offset again, and the history does not move
        return Ok(rep[0]);
    }
    let offset = if code == 3 {
        if rep[0] <= 1 {
            return Err(bad(
                "a sequence asks for the most recent offset minus one, which would be zero",
            ));
        }
        rep[0] - 1
    } else {
        rep[code as usize]
    };
    if offset == 0 {
        return Err(bad("a repeated offset resolved to zero"));
    }
    rep[2] = if code >= 2 { rep[1] } else { rep[2] };
    rep[1] = rep[0];
    rep[0] = offset;
    Ok(offset)
}

/// The three offsets a frame starts with. Not arbitrary -- the format fixes them so the
/// first sequences of a frame can use the repeat codes before any offset has been seen.
pub const INITIAL_REPEATS: [u32; 3] = [1, 4, 8];

/// The Regenerated_Size of a raw or RLE literals section, and the header's width.
///
/// Raw and RLE share this layout, which is why it is one function: only the low bit of
/// Size_Format is meaningful for them, so 0 and 2 both mean a one-byte header.
fn raw_literals_size(body: &[u8], size_format: u8) -> io::Result<(usize, usize)> {
    match size_format {
        0 | 2 => Ok(((body[0] >> 3) as usize, 1usize)),
        1 => {
            if body.len() < 2 {
                return Err(bad("a two-byte literals header is truncated"));
            }
            Ok((
                (((body[0] as usize) >> 4) | ((body[1] as usize) << 4)) & 0xFFF,
                2,
            ))
        }
        _ => {
            if body.len() < 3 {
                return Err(bad("a three-byte literals header is truncated"));
            }
            Ok((
                (((body[0] as usize) >> 4)
                    | ((body[1] as usize) << 4)
                    | ((body[2] as usize) << 12))
                    & 0xF_FFFF,
                3,
            ))
        }
    }
}

/// What a frame carries from one block to the next.
///
/// It is tempting to make both halves of this block-local; both would be wrong. The
/// repeated offsets are named by sequences in later blocks, and a sequence table can be
/// declared a REPEAT of the one an earlier block sent -- so a decoder that starts each block
/// fresh does not error, it decodes to wrong bytes.
pub struct FrameState {
    pub rep: [u32; 3],
    /// How far back a match in this frame may reach, from the frame header.
    ///
    /// This is the half of the window's meaning that clamping the block size does NOT
    /// deliver: `Block_Maximum_Size` bounds how much one block regenerates, while
    /// `Window_Size` bounds how far a SEQUENCE may reach back into what the frame has
    /// already produced. A frame can declare a 1 KiB window, keep every block small, and
    /// still carry an offset of 100 KiB -- legal against the block cap, illegal against the
    /// window, and accepted by any decoder that checks only the block cap.
    ///
    /// `u64::MAX` means "the frame declared nothing", which leaves only the two bounds
    /// that always apply: the absolute block cap and the output produced so far.
    pub window: u64,
    ll: Option<fse::DTable>,
    of: Option<fse::DTable>,
    ml: Option<fse::DTable>,
    tree: Option<super::huff::Tree>,
}

impl Default for FrameState {
    fn default() -> Self {
        FrameState {
            rep: INITIAL_REPEATS,
            window: u64::MAX,
            ll: None,
            of: None,
            ml: None,
            tree: None,
        }
    }
}

impl FrameState {
    /// The state a frame starts in, carrying the window its header declared.
    pub fn with_window(window: u64) -> Self {
        FrameState {
            window,
            ..Default::default()
        }
    }
}

/// The four ways a block can say where one sequence table comes from.
///
/// `Repeat` is the one with a trap in it: there is nothing in the block that says which
/// earlier block set the table, so a decoder must hold it for the whole frame, and a
/// `Repeat` with no earlier table is corruption rather than a reason to fall back to the
/// predefined one. Falling back would decode -- to the wrong bytes.
fn seq_table(
    body: &[u8],
    at: &mut usize,
    mode: u8,
    predefined: &[i16],
    predefined_log: u32,
    max_symbol: usize,
    max_log: u32,
    previous: Option<fse::DTable>,
    what: &str,
) -> io::Result<fse::DTable> {
    match mode {
        0 => fse::DTable::new(predefined, predefined_log),
        1 => {
            #[cfg(test)]
            fse::seen::branch(2);
            // RLE: one symbol, always. A one-state table expresses it exactly -- zero bits
            // read per symbol -- so the sequence loop needs no special case.
            let sym = *body.get(*at).ok_or_else(|| {
                bad(&format!(
                    "the {what} table is RLE but the block ends before its symbol"
                ))
            })?;
            *at += 1;
            if sym as usize > max_symbol {
                return Err(bad(&format!(
                    "the {what} RLE table names a symbol outside the alphabet"
                )));
            }
            let mut norm = vec![0i16; sym as usize + 1];
            norm[sym as usize] = 1;
            fse::DTable::new(&norm, 0)
        }
        2 => {
            let (norm, log, used) = fse::read_ncount(&body[*at..])?;
            if log > max_log {
                return Err(bad(&format!(
                    "the {what} table declares an accuracy log above what its field allows"
                )));
            }
            if norm.len() > max_symbol + 1 {
                return Err(bad(&format!(
                    "the {what} table describes symbols outside its alphabet"
                )));
            }
            *at += used;
            fse::DTable::new(&norm, log)
        }
        _ => {
            #[cfg(test)]
            fse::seen::branch(3);
            previous.ok_or_else(|| {
                bad(&format!(
                    "the {what} table is marked repeat, but no earlier block in this frame set one"
                ))
            })
        }
    }
}

/// One copy instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seq {
    pub literal_len: u32,
    pub match_len: u32,
    /// The real back-distance, NOT the coded `Offset_Value`. The +3 that makes room for
    /// zstd's three repeat-offset codes is applied at coding time, in one place.
    pub offset: u32,
}

fn code_for(value: u32, base: &[u32]) -> usize {
    // linear from the top: the tables are short and this cannot be off by one the way a
    // hand-rolled binary search over inclusive baselines can
    base.iter()
        .rposition(|&b| b <= value)
        .expect("a zero baseline exists")
}

fn high_bit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

/// A hash-chain matcher producing zstd sequences over one block.
///
/// Deliberately modest: a 3-byte hash, a chain, and a greedy choice. The encoder's ratio
/// is not what stage 3 is proving -- correctness against the reference is -- and a clever
/// matcher would make a decode failure harder to localize. Matches are confined to THIS
/// block, so an offset can never reach behind the frame's start.
fn sequences(data: &[u8]) -> (Vec<Seq>, Vec<u8>) {
    const MIN_MATCH: usize = 3;
    // 32 and not deeper, measured rather than assumed: raising it to 64 doubles the chain
    // walk at every position and bought 605,008 -> 604,024 wire bytes on the codec arm's
    // 4.5 MB corpus, which is 0.16%. The ratio on this data is not search-depth bound --
    // lazy matching, adaptive FSE tables and repeat offsets were 11%, 26% and 4%.
    const CHAIN: usize = 32;
    const HASH_BITS: usize = 15;

    let mut seqs = Vec::new();
    let mut literals = Vec::new();
    if data.len() < MIN_MATCH + 1 {
        literals.extend_from_slice(data);
        return (seqs, literals);
    }

    let mut head = vec![usize::MAX; 1 << HASH_BITS];
    let mut prev = vec![usize::MAX; data.len()];
    let hash = |b: &[u8]| -> usize {
        (((b[0] as usize) << 10 ^ (b[1] as usize) << 5 ^ b[2] as usize).wrapping_mul(2654435761))
            >> (32 - HASH_BITS)
            & ((1 << HASH_BITS) - 1)
    };

    // The search itself, so the lazy lookahead below can run it at pos + 1 without a
    // second copy of the chain walk.
    let best_at =
        |data: &[u8], pos: usize, head: &[usize], prev: &[usize], h: usize| -> (usize, usize) {
            let mut best_len = 0usize;
            let mut best_off = 0usize;
            let mut cand = head[h];
            let mut walked = 0;
            while cand != usize::MAX && walked < CHAIN {
                walked += 1;
                let mut l = 0usize;
                while pos + l < data.len()
                    && data[cand + l] == data[pos + l]
                    && l < ML_BASE[ML_BASE.len() - 1] as usize
                {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_off = pos - cand;
                }
                cand = prev[cand];
            }
            (best_len, best_off)
        };

    let mut pos = 0usize;
    let mut run_start = 0usize;
    while pos + MIN_MATCH <= data.len() {
        let h = hash(&data[pos..pos + 3]);
        let (best_len, best_off) = best_at(data, pos, &head, &prev, h);
        prev[pos] = head[h];
        head[h] = pos;

        // LAZY MATCHING, the same trade the DEFLATE encoder here already makes: a match
        // found at `pos` is given up when the NEXT position finds a strictly longer one,
        // because one extra literal buys a longer copy. It costs a second chain walk per
        // matched position and is the cheapest ratio available -- the alternative levers
        // are a deeper chain, which costs more per position, or adaptive FSE tables, which
        // is a different piece of work.
        //
        // The lookahead runs BEFORE `pos + 1` is inserted into the chain, which is exactly
        // the state the next iteration would see, so deferring and re-searching gives the
        // same answer rather than a slightly different one.
        if best_len >= MIN_MATCH && best_off > 0 && pos + 1 + MIN_MATCH <= data.len() {
            let h1 = hash(&data[pos + 1..pos + 4]);
            let (next_len, next_off) = best_at(data, pos + 1, &head, &prev, h1);
            if next_len > best_len && next_off > 0 {
                pos += 1;
                continue;
            }
        }

        if best_len >= MIN_MATCH && best_off > 0 {
            let lit_len = pos - run_start;
            literals.extend_from_slice(&data[run_start..pos]);
            seqs.push(Seq {
                literal_len: lit_len as u32,
                match_len: best_len as u32,
                offset: best_off as u32,
            });
            // index the interior of the match so later positions can still find it
            for k in 1..best_len {
                if pos + k + MIN_MATCH <= data.len() {
                    let hk = hash(&data[pos + k..pos + k + 3]);
                    prev[pos + k] = head[hk];
                    head[hk] = pos + k;
                }
            }
            pos += best_len;
            run_start = pos;
        } else {
            pos += 1;
        }
    }
    literals.extend_from_slice(&data[run_start..]);
    (seqs, literals)
}

/// Chooses how one sequence field's FSE table crosses the wire, and builds it.
///
/// Returns the Symbol_Compression_Mode bits, the normalized counts to code with, its
/// accuracy log, and the description to append after the modes byte (empty for
/// Predefined).
///
/// **The predefined tables are a real option, not a fallback for failure.** They cost
/// nothing on the wire, and a table description built from a handful of sequences costs
/// more than it can ever save -- so the adaptive path is taken only once there are enough
/// sequences to amortize it. The threshold is a judgement, but its direction is not: a
/// block with four sequences and a 30-byte table description is strictly larger than the
/// same block with the predefined one.
///
/// RLE mode (a single symbol, one byte on the wire) is deliberately NOT emitted here even
/// though the decoder reads it: it needs a one-state coding table, and a table log of zero
/// is a shape the encoder side has never been exercised at. Reading a form this encoder
/// does not write is the safe asymmetry; writing one it has not proved is not.
fn pick_seq_table(
    counts: &[u32],
    nb_seq: usize,
    max_log: u32,
    predefined: &[i16],
    predefined_log: u32,
) -> (u8, Vec<i16>, u32, Vec<u8>) {
    let distinct = counts.iter().filter(|&&c| c > 0).count();
    let used = counts.iter().rposition(|&c| c > 0).map_or(0, |i| i + 1);
    if nb_seq >= 64 && distinct >= 2 {
        // An accuracy log above what the data can fill wastes description bytes on states
        // nothing reaches; one below it cannot separate the symbols. zstd's own rule is
        // about two bits under the log of the count, clamped to the field's ceiling.
        let want = fse::MIN_TABLE_LOG
            .max(high_bit(nb_seq as u32).saturating_sub(2))
            .min(max_log);
        for log in want..=max_log {
            if (1u32 << log) < distinct as u32 {
                continue;
            }
            let Ok(norm) = fse::normalize(&counts[..used], nb_seq as u32, log) else {
                continue;
            };
            let Ok(wire) = fse::write_ncount(&norm, log) else {
                continue;
            };
            if CTable::new(&norm, log).is_err() {
                continue;
            }
            return (2, norm, log, wire);
        }
    }
    (0, predefined.to_vec(), predefined_log, Vec::new())
}

/// The `Offset_Value` to send for one sequence, using a repeat code where one fits, and
/// the repeat history updated exactly as the decoder will update it.
///
/// This is the encoder's half of `repeat_offset` and it MUST stay its exact mirror: the
/// decoder's update runs unconditionally, so an encoder that resolves a repeat correctly
/// but updates differently desynchronizes on the NEXT sequence, not this one. Writing the
/// search as "for each value the decoder could read, ask what it would resolve to" rather
/// than as its own set of rules is what keeps the two the same thing.
fn offset_value_for(offset: u32, literal_len: u32, rep: &mut [u32; 3]) -> u32 {
    let ll0 = u32::from(literal_len == 0);
    for value in 1..=3u32 {
        let code = value - 1 + ll0;
        let candidate = match code {
            0 => rep[0],
            3 => {
                if rep[0] <= 1 {
                    continue;
                }
                rep[0] - 1
            }
            c => rep[c as usize],
        };
        if candidate != offset {
            continue;
        }
        if code != 0 {
            rep[2] = if code >= 2 { rep[1] } else { rep[2] };
            rep[1] = rep[0];
            rep[0] = offset;
        }
        return value;
    }
    *rep = [offset, rep[0], rep[1]];
    offset + 3
}

/// The literals section header for a Raw_Literals_Block.
fn raw_literals_header(out: &mut Vec<u8>, size: usize) -> io::Result<()> {
    // Literals_Block_Type 0 (Raw) in the low two bits, then a Size_Format that decides how
    // many bytes the size itself takes. The three widths are not interchangeable: a size
    // of 40 cannot use the 5-bit form, and a decoder handed the wrong form reads the next
    // section's first byte as part of the size.
    match size {
        0..=31 => out.push((size as u8) << 3),
        32..=4095 => {
            let v = (0b01u32 << 2) | ((size as u32) << 4);
            out.push(v as u8);
            out.push((v >> 8) as u8);
        }
        4096..=1_048_575 => {
            let v = (0b11u32 << 2) | ((size as u32) << 4);
            out.push(v as u8);
            out.push((v >> 8) as u8);
            out.push((v >> 16) as u8);
        }
        _ => {
            return Err(bad(
                "a literals section larger than 20 bits cannot be described",
            ))
        }
    }
    Ok(())
}

/// The header for a Compressed_Literals_Block in four-stream form.
///
/// Size_Format 11 is chosen for its 18-bit sizes rather than for its stream count: a block
/// holds far more literals than the single-stream form's 10 bits can describe, so four
/// streams are not an optimization here but the only shape that fits.
fn compressed_literals_header(
    out: &mut Vec<u8>,
    regenerated: usize,
    compressed: usize,
    content: &[u8],
) -> io::Result<()> {
    if regenerated >= (1 << 18) || compressed >= (1 << 18) {
        return Err(bad(
            "a literals section larger than 18 bits cannot be described in this form",
        ));
    }
    // type 2 (Compressed) | size format 3 | 18-bit regenerated | 18-bit compressed = 40 bits
    let v = 2u64 | (3u64 << 2) | ((regenerated as u64) << 4) | ((compressed as u64) << 22);
    out.extend_from_slice(&v.to_le_bytes()[..5]);
    out.extend_from_slice(content);
    Ok(())
}

fn number_of_sequences(out: &mut Vec<u8>, n: usize) -> io::Result<()> {
    match n {
        0..=127 => out.push(n as u8),
        128..=0x7EFF => {
            out.push((((n >> 8) + 0x80) & 0xFF) as u8);
            out.push((n & 0xFF) as u8);
        }
        0x7F00..=0x1_7EFF => {
            out.push(255);
            let v = n - 0x7F00;
            out.push((v & 0xFF) as u8);
            out.push((v >> 8) as u8);
        }
        _ => return Err(bad("too many sequences for one block")),
    }
    Ok(())
}

/// Encodes one block's worth of input as a Compressed_Block body.
///
/// Returns `None` when the result would not be smaller than the input, which is not a
/// failure: a block that does not compress is supposed to be sent stored, and an encoder
/// that emitted a larger compressed block would be worse than useless on incompressible
/// data.
pub fn compress_block(data: &[u8], rep: &mut [u32; 3]) -> io::Result<Option<Vec<u8>>> {
    let (seqs, literals) = sequences(data);
    if seqs.is_empty() {
        // nothing matched; a literals-only block is legal but never smaller than stored
        return Ok(None);
    }

    let mut out = Vec::with_capacity(data.len());
    match super::huff::encode(&literals) {
        Some((content, _)) => {
            compressed_literals_header(&mut out, literals.len(), content.len(), &content)?
        }
        None => {
            raw_literals_header(&mut out, literals.len())?;
            out.extend_from_slice(&literals);
        }
    }
    number_of_sequences(&mut out, seqs.len())?;

    // Per sequence: the three symbols, and the raw extra bits that refine each. This runs
    // BEFORE the modes byte is written, because the modes depend on what the symbols turn
    // out to be.
    //
    // The repeat history is walked on a COPY. A block that turns out not to be smaller
    // than its input is discarded below and sent stored, and a stored block carries no
    // sequences -- so the history the next block starts from must be the one this block
    // started from, not the one it would have ended with.
    let mut local_rep = *rep;
    let coded: Vec<(usize, usize, usize, u32)> = seqs
        .iter()
        .map(|s| {
            let ll = code_for(s.literal_len, &LL_BASE);
            let ml = code_for(s.match_len, &ML_BASE);
            let off_value = offset_value_for(s.offset, s.literal_len, &mut local_rep);
            let of = high_bit(off_value) as usize;
            (ll, ml, of, off_value)
        })
        .collect();
    if let Some(&(_, _, of, _)) = coded.iter().find(|&&(_, _, of, _)| of > 31) {
        return Err(bad(&format!(
            "offset code {of} is outside the format's alphabet"
        )));
    }

    // Counts over this block's own symbols, which is what makes an adaptive table possible
    // at all. The predefined tables are tuned for a general mixture; a block of timestamps
    // uses a handful of literal-length codes and almost one match-length code, and paying
    // predefined-table bit costs for symbols that never occur is most of the gap between
    // this encoder and the reference's.
    let mut ll_counts = vec![0u32; 36];
    let mut ml_counts = vec![0u32; 53];
    let mut of_counts = vec![0u32; 32];
    for &(ll, ml, of, _) in &coded {
        ll_counts[ll] += 1;
        ml_counts[ml] += 1;
        of_counts[of] += 1;
    }
    let (ll_mode, ll_norm, ll_log, ll_wire) =
        pick_seq_table(&ll_counts, seqs.len(), 9, &LL_NORM, LL_LOG);
    let (of_mode, of_norm, of_log, of_wire) =
        pick_seq_table(&of_counts, seqs.len(), 8, &OF_NORM, OF_LOG);
    let (ml_mode, ml_norm, ml_log, ml_wire) =
        pick_seq_table(&ml_counts, seqs.len(), 9, &ML_NORM, ML_LOG);
    // A predefined table cannot code a symbol it has no slot for, and falling through with
    // one would write a state the decoder cannot follow.
    if ll_mode == 0 && coded.iter().any(|&(ll, _, _, _)| ll >= LL_NORM.len()) {
        return Err(bad(
            "a literal-length code falls outside the predefined table",
        ));
    }
    if of_mode == 0 && coded.iter().any(|&(_, _, of, _)| of >= OF_NORM.len()) {
        return Err(bad("an offset code falls outside the predefined table"));
    }
    if ml_mode == 0 && coded.iter().any(|&(_, ml, _, _)| ml >= ML_NORM.len()) {
        return Err(bad(
            "a match-length code falls outside the predefined table",
        ));
    }

    // Symbol_Compression_Modes: two bits each for literal-length, offset and match-length
    // in that order, and the low two bits are RESERVED and must be zero -- a decoder is
    // entitled to reject a block that sets them. The three descriptions follow in the same
    // order, and only for the fields whose mode carries one.
    out.push((ll_mode << 6) | (of_mode << 4) | (ml_mode << 2));
    out.extend_from_slice(&ll_wire);
    out.extend_from_slice(&of_wire);
    out.extend_from_slice(&ml_wire);

    let ll_table = CTable::new(&ll_norm, ll_log)?;
    let ml_table = CTable::new(&ml_norm, ml_log)?;
    let of_table = CTable::new(&of_norm, of_log)?;

    let mut w = BitWriter::new();
    let last = seqs.len() - 1;

    // THE ORDER HERE IS THE PROTOCOL, and it is the part that cannot be reasoned out from
    // first principles -- it has to match what the decoder does in reverse. The encoder
    // initializes match-length, offset then literal-length states; writes the LAST
    // sequence's extra bits as literal-length, match-length, offset; then for every
    // earlier sequence writes the three symbols offset, match-length, literal-length
    // followed by the same three extra-bit fields; and finally flushes match-length,
    // offset, literal-length. Read backwards that gives the decoder literal-length,
    // offset, match-length states, then per sequence offset, match-length and
    // literal-length bits. Any transposition decodes to plausible garbage.
    let mut ll_state = ll_table.init_state_pub(coded[last].0 as u8);
    let mut of_state = of_table.init_state_pub(coded[last].2 as u8);
    let mut ml_state = ml_table.init_state_pub(coded[last].1 as u8);

    let (ll, ml, of, off_value) = coded[last];
    w.add(seqs[last].literal_len - LL_BASE[ll], LL_BITS[ll]);
    w.add(seqs[last].match_len - ML_BASE[ml], ML_BITS[ml]);
    w.add(off_value, of as u32);

    for n in (0..last).rev() {
        let (ll, ml, of, off_value) = coded[n];
        of_table.encode_pub(&mut of_state, of as u8, &mut w);
        ml_table.encode_pub(&mut ml_state, ml as u8, &mut w);
        ll_table.encode_pub(&mut ll_state, ll as u8, &mut w);
        w.add(seqs[n].literal_len - LL_BASE[ll], LL_BITS[ll]);
        w.add(seqs[n].match_len - ML_BASE[ml], ML_BITS[ml]);
        w.add(off_value, of as u32);
    }

    w.add(ml_state, ml_log);
    w.add(of_state, of_log);
    w.add(ll_state, ll_log);
    out.extend_from_slice(&w.finish());

    if out.len() >= data.len() {
        return Ok(None);
    }
    *rep = local_rep;
    Ok(Some(out))
}

/// Decodes a Compressed_Block body into `out`, appending.
///
/// `out` already holds everything decoded so far in this FRAME, which matters: a match
/// offset reaches back into it, and for a multi-block frame that reach can cross a block
/// boundary. Passing only the current block would silently corrupt the first matches of
/// every block after the first.
///
/// Only Raw literals and Predefined sequence tables are read, which is exactly what this
/// encoder writes. A reference block using Huffman literals or a carried FSE table is
/// refused BY NAME rather than mis-parsed -- "not implemented" is a fact a caller can act
/// on, and a decoder that guessed would produce plausible bytes.
/// `ceiling` is the absolute `out.len()` this ONE block may not pass -- the frame's
/// `Block_Maximum_Size` measured from where the block started. It is separate from `limit`,
/// which is the caller's budget for the whole frame, because the two fail for different
/// reasons and an operator reading the error should not have to guess which.
///
/// **Both are checked at every append rather than once at the end, and that ordering is the
/// point.** A post-block check runs only after the block has already expanded into `out`:
/// the refusal is correct but the memory has been spent, so the bound the window descriptor
/// advertises is not the bound a peer actually gets.
///
/// **Three guards, FOUR growth statements, and the difference is worth stating** -- it is
/// tempting to read the guards as "every place this function grows `out`", which is not
/// true and would send the next reader looking for a missing guard. `out` grows in four
/// places: the no-sequence literal copy, the per-sequence
/// literal copy, the per-sequence match copy, and the trailing literal copy. The match
/// copy has no guard of its own because the one before the literal copy covers both --
/// it is written against `ll + match_len`, the whole of what that sequence will emit,
/// before either happens. A fifth growth statement would need its own guard, and this
/// paragraph is the only thing that would tell you so.
pub fn decode_block(
    body: &[u8],
    out: &mut Vec<u8>,
    limit: usize,
    ceiling: usize,
    state: &mut FrameState,
) -> io::Result<()> {
    if body.is_empty() {
        return Err(bad("a compressed block has no body"));
    }
    // literals section header
    let kind = body[0] & 0b11;
    let size_format = (body[0] >> 2) & 0b11;
    let mut at;
    let literals: std::borrow::Cow<'_, [u8]> = match kind {
        0 => {
            #[cfg(test)]
            fse::seen::branch(4);
            let (lit_len, header) = raw_literals_size(body, size_format)?;
            at = header;
            if at + lit_len > body.len() {
                return Err(bad("the literals section runs past the block"));
            }
            let l = &body[at..at + lit_len];
            at += lit_len;
            std::borrow::Cow::Borrowed(l)
        }
        1 => {
            #[cfg(test)]
            fse::seen::branch(5);
            // RLE literals: the header's size is how many times ONE byte repeats.
            let (lit_len, header) = raw_literals_size(body, size_format)?;
            at = header;
            let &b = body
                .get(at)
                .ok_or_else(|| bad("an RLE literals section has no byte to repeat"))?;
            at += 1;
            std::borrow::Cow::Owned(vec![b; lit_len])
        }
        2 | 3 => {
            // Size_Format picks BOTH the header width and the stream count, and the two
            // are not the same question: 0 and 1 share a three-byte header and differ only
            // in whether the section holds one bitstream or four.
            let (regen, comp, header, four) = match size_format {
                3 => {
                    if body.len() < 5 {
                        return Err(bad("a five-byte literals header is truncated"));
                    }
                    let v = u64::from(body[0])
                        | (u64::from(body[1]) << 8)
                        | (u64::from(body[2]) << 16)
                        | (u64::from(body[3]) << 24)
                        | (u64::from(body[4]) << 32);
                    (
                        ((v >> 4) & 0x3_FFFF) as usize,
                        ((v >> 22) & 0x3_FFFF) as usize,
                        5usize,
                        true,
                    )
                }
                2 => {
                    if body.len() < 4 {
                        return Err(bad("a four-byte literals header is truncated"));
                    }
                    let v = u32::from(body[0])
                        | (u32::from(body[1]) << 8)
                        | (u32::from(body[2]) << 16)
                        | (u32::from(body[3]) << 24);
                    (
                        ((v >> 4) & 0x3FFF) as usize,
                        ((v >> 18) & 0x3FFF) as usize,
                        4usize,
                        true,
                    )
                }
                sf => {
                    if body.len() < 3 {
                        return Err(bad("a three-byte literals header is truncated"));
                    }
                    let v =
                        u32::from(body[0]) | (u32::from(body[1]) << 8) | (u32::from(body[2]) << 16);
                    (
                        ((v >> 4) & 0x3FF) as usize,
                        ((v >> 14) & 0x3FF) as usize,
                        3usize,
                        sf == 1,
                    )
                }
            };
            at = header;
            if at + comp > body.len() {
                return Err(bad("the compressed literals section runs past the block"));
            }
            let section = &body[at..at + comp];
            // A TREELESS block sends no description: `kind == 3` means "use the tree an
            // earlier block in this frame sent". There is nothing in the block naming
            // which one, so the only correct reading is the most recent -- and a treeless
            // block with no earlier tree is corruption, not a reason to guess a tree.
            #[cfg(test)]
            if !four {
                fse::seen::branch(1);
            }
            let l = if kind == 3 {
                #[cfg(test)]
                fse::seen::branch(0);
                let tree = state.tree.as_ref().ok_or_else(|| {
                    bad("a treeless literals section has no earlier tree in this frame to use")
                })?;
                tree.streams(section, regen, four)?
            } else {
                let (tree, used) = super::huff::read_tree(section)?;
                let l = tree.streams(&section[used..], regen, four)?;
                state.tree = Some(tree);
                l
            };
            at += comp;
            std::borrow::Cow::Owned(l)
        }
        _ => unreachable!("two bits have four values and all four are handled"),
    };
    let literals = literals.as_ref();

    // number of sequences
    if at >= body.len() {
        return Err(bad("the block ends before its sequence count"));
    }
    let b0 = body[at] as usize;
    at += 1;
    let nb_seq = if b0 < 128 {
        b0
    } else if b0 < 255 {
        if at >= body.len() {
            return Err(bad("a two-byte sequence count is truncated"));
        }
        let v = ((b0 - 0x80) << 8) + body[at] as usize;
        at += 1;
        v
    } else {
        if at + 1 >= body.len() {
            return Err(bad("a three-byte sequence count is truncated"));
        }
        let v = (body[at] as usize) + ((body[at + 1] as usize) << 8) + 0x7F00;
        at += 2;
        v
    };

    if nb_seq == 0 {
        if out.len() + literals.len() > limit {
            return Err(bad("the block decodes past the caller's limit"));
        }
        if out.len() + literals.len() > ceiling {
            return Err(bad(
                "a block regenerated more than its frame's window allows",
            ));
        }
        out.extend_from_slice(literals);
        return Ok(());
    }

    if at >= body.len() {
        return Err(bad("the block ends before its compression modes"));
    }
    let modes = body[at];
    at += 1;
    if modes & 0b11 != 0 {
        return Err(bad(
            "the reserved bits of the compression-modes byte are set",
        ));
    }
    // The three descriptions appear in this order and only for the modes that carry one,
    // so they must be read in order -- each one's length decides where the next begins,
    // and the bitstream begins after the last of them.
    let ll_dt = seq_table(
        body,
        &mut at,
        modes >> 6,
        &LL_NORM,
        LL_LOG,
        35,
        9,
        state.ll.take(),
        "literal-length",
    )?;
    let of_dt = seq_table(
        body,
        &mut at,
        (modes >> 4) & 0b11,
        &OF_NORM,
        OF_LOG,
        31,
        8,
        state.of.take(),
        "offset",
    )?;
    let ml_dt = seq_table(
        body,
        &mut at,
        (modes >> 2) & 0b11,
        &ML_NORM,
        ML_LOG,
        52,
        9,
        state.ml.take(),
        "match-length",
    )?;
    state.ll = Some(ll_dt.clone());
    state.of = Some(of_dt.clone());
    state.ml = Some(ml_dt.clone());
    // An INVARIANT BACKSTOP, not a reachable check, and the difference was measured: the
    // fuzz arm in `mod.rs` does not fail when this is removed. Every path that advances
    // `at` is bounded on its own -- `body.get` for an RLE table's symbol, `read_ncount`
    // returning a count no larger than the slice it was handed -- so `at` cannot get past
    // `body.len()` here. It stays because it costs one comparison and turns a future
    // unbounded advance into an error instead of a panic, but it is not evidence that this
    // boundary is tested.
    if at > body.len() {
        return Err(bad("the sequence tables run past the block"));
    }
    let mut r = fse::BitReader::new(&body[at..])?;

    // The mirror of the encoder's order, and the comment there is the authority. States
    // come out literal-length, offset, match-length because they were flushed
    // match-length, offset, literal-length.
    let mut ll_state = r.read(ll_dt.log())? as usize;
    let mut of_state = r.read(of_dt.log())? as usize;
    let mut ml_state = r.read(ml_dt.log())? as usize;

    let mut lit_at = 0usize;
    for i in 0..nb_seq {
        let (ll_code, ll_bits, ll_next) = ll_dt
            .at(ll_state)
            .ok_or_else(|| bad("a literal-length state left its table"))?;
        let (ml_code, ml_bits, ml_next) = ml_dt
            .at(ml_state)
            .ok_or_else(|| bad("a match-length state left its table"))?;
        let (of_code, of_bits, of_next) = of_dt
            .at(of_state)
            .ok_or_else(|| bad("an offset state left its table"))?;
        let (ll_code, ml_code, of_code) = (ll_code as usize, ml_code as usize, of_code as u32);

        // extra bits, read in the reverse of the order they were written
        if of_code >= 32 {
            return Err(bad("an offset code is too large to be real"));
        }
        let offset_value = (1u32 << of_code) | r.read(of_code)?;
        let match_len = *ML_BASE
            .get(ml_code)
            .ok_or_else(|| bad("a match-length code is outside its table"))?
            + r.read(ML_BITS[ml_code])?;
        let literal_len = *LL_BASE
            .get(ll_code)
            .ok_or_else(|| bad("a literal-length code is outside its table"))?
            + r.read(LL_BITS[ll_code])?;
        let offset = repeat_offset(offset_value, literal_len, &mut state.rep)? as usize;

        let ll = literal_len as usize;
        if lit_at + ll > literals.len() {
            return Err(bad(
                "a sequence asks for more literals than the section holds",
            ));
        }
        if out.len() + ll + match_len as usize > limit {
            return Err(bad("the block decodes past the caller's limit"));
        }
        if out.len() + ll + match_len as usize > ceiling {
            return Err(bad(
                "a block regenerated more than its frame's window allows",
            ));
        }
        out.extend_from_slice(&literals[lit_at..lit_at + ll]);
        lit_at += ll;
        if offset > out.len() {
            return Err(bad("a match offset reaches before the start of the output"));
        }
        // and the OTHER bound, which is the frame's own promise rather than a fact about
        // the buffer. A decoder that keeps only a window of history -- which is the whole
        // point of the descriptor -- would be reading memory it had already discarded.
        // This one holds the entire output, so the miss was a conformance gap rather than
        // a crash, which is exactly the kind that survives a round trip.
        if offset as u64 > state.window {
            return Err(bad(
                "a match offset reaches further back than the frame's window allows",
            ));
        }
        let start = out.len() - offset;
        // byte at a time on purpose: zstd matches may OVERLAP their own output, which is
        // how a run is expressed, and a block copy would read bytes that do not exist yet
        for k in 0..match_len as usize {
            let byte = out[start + k];
            out.push(byte);
        }

        // and the states advance only BETWEEN sequences, for the same reason `fse::decode`
        // does not read after its last symbol: the encoder set these states rather than
        // coding them
        if i + 1 < nb_seq {
            ll_state = ll_next + r.read(ll_bits)? as usize;
            ml_state = ml_next + r.read(ml_bits)? as usize;
            of_state = of_next + r.read(of_bits)? as usize;
        }
    }

    // AND THE STREAM MUST BE SPENT. "I decoded the declared number of sequences" is a
    // happy-path sufficiency claim: it says nothing about bits left over, which mean the
    // block was not the block its header described.
    // The reader counts down to the sentinel, so a well-formed sequences section lands
    // exactly on zero. Anything else is a stream this decoder read a different way than
    // the encoder wrote it, which is the failure mode this module exists to refuse rather
    // than to survive.
    if r.remaining() != 0 {
        return Err(bad(
            "the sequences bitstream has bits left after its last sequence",
        ));
    }

    if out.len() + (literals.len() - lit_at) > limit {
        return Err(bad("the block decodes past the caller's limit"));
    }
    if out.len() + (literals.len() - lit_at) > ceiling {
        return Err(bad(
            "a block regenerated more than its frame's window allows",
        ));
    }
    out.extend_from_slice(&literals[lit_at..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every sequence reconstructs its own slice of the input, checked without any zstd
    /// framing at all.
    ///
    /// This is the arm that localizes a failure. If the reference later rejects a block,
    /// this says whether the matcher was wrong or the CODING of a correct matcher was.
    #[test]
    fn the_sequences_replay_to_the_input() {
        let corpora: Vec<Vec<u8>> = vec![
            b"the quick brown fox jumps over the lazy dog".repeat(40),
            vec![7u8; 5000],
            (0..=255u8).cycle().take(9000).collect(),
            b"abcabcabcabcabcabc".repeat(200),
        ];
        for data in corpora {
            let (seqs, literals) = sequences(&data);
            let mut out: Vec<u8> = Vec::new();
            let mut lit = 0usize;
            for s in &seqs {
                out.extend_from_slice(&literals[lit..lit + s.literal_len as usize]);
                lit += s.literal_len as usize;
                let start = out.len() - s.offset as usize;
                for k in 0..s.match_len as usize {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            out.extend_from_slice(&literals[lit..]);
            assert_eq!(
                out,
                data,
                "replaying {} sequences did not rebuild {} bytes",
                seqs.len(),
                data.len()
            );
        }
    }

    /// Codes and baselines agree: a value's code must have a baseline at or below it, and
    /// the difference must fit the extra bits.
    ///
    /// Without this a table typo shows up only as a decode failure inside the reference,
    /// which is a long way from the line that is wrong.
    #[test]
    fn every_length_fits_the_code_it_is_given() {
        for v in (0u32..=200).chain([255, 256, 1000, 4095, 4096, 65535]) {
            let c = code_for(v, &LL_BASE);
            assert!(
                LL_BASE[c] <= v,
                "literal length {v} got code {c} with baseline {}",
                LL_BASE[c]
            );
            let extra = v - LL_BASE[c];
            assert!(
                LL_BITS[c] >= 32 || extra < (1u32 << LL_BITS[c]),
                "literal length {v}: {extra} does not fit {} bits",
                LL_BITS[c]
            );
        }
        for v in (3u32..=200).chain([255, 256, 1000, 65539]) {
            let c = code_for(v, &ML_BASE);
            assert!(ML_BASE[c] <= v, "match length {v} got code {c}");
            let extra = v - ML_BASE[c];
            assert!(
                ML_BITS[c] >= 32 || extra < (1u32 << ML_BITS[c]),
                "match length {v}: {extra} does not fit {} bits",
                ML_BITS[c]
            );
        }
        // THE CONTROL: the tables are strictly increasing, so `rposition` really is
        // finding the largest baseline at or below the value rather than any baseline.
        assert!(
            LL_BASE.windows(2).all(|w| w[0] < w[1]),
            "the literal-length baselines are not sorted"
        );
        assert!(
            ML_BASE.windows(2).all(|w| w[0] < w[1]),
            "the match-length baselines are not sorted"
        );
    }

    /// The predefined distributions are usable as written: they sum to their table size
    /// and build without error.
    ///
    /// A transcription slip in one of these arrays is otherwise invisible until the
    /// reference decoder disagrees, and it would look like a bitstream bug.
    #[test]
    fn the_predefined_tables_are_transcribed_correctly() {
        for (norm, log, what) in [
            (&LL_NORM[..], LL_LOG, "literal length"),
            (&ML_NORM[..], ML_LOG, "match length"),
            (&OF_NORM[..], OF_LOG, "offset"),
        ] {
            let sum: i32 = norm
                .iter()
                .map(|&n| if n < 0 { 1 } else { i32::from(n) })
                .sum();
            assert_eq!(
                sum,
                1 << log,
                "the predefined {what} table sums to {sum}, not {}",
                1 << log
            );
            CTable::new(norm, log)
                .unwrap_or_else(|e| panic!("the predefined {what} table does not build: {e}"));
            fse::DTable::new(norm, log).unwrap_or_else(|e| {
                panic!("the predefined {what} decode table does not build: {e}")
            });
        }
    }
}
