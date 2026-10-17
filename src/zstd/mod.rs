//! Zstandard, written here rather than linked, because this crate ships no dependencies.
//!
//! **Read `docs/src/design-notes.md` before touching this.** A thin thing called zstd would be a
//! label rather than a capability, which is why DEFLATE sits in this crate under its own
//! name rather than this one. This module has to earn the name, and the standard it has
//! to meet is not "it round-trips":
//!
//! > **Our output decodes with the reference `zstd`, and the reference's output decodes
//! > with ours.** An implementation that only agrees with itself is a private format
//! > wearing a public name.
//!
//! Both directions are asserted in `tests`, against `/usr/bin/zstd` when it is present,
//! and the arms that need it say so rather than passing quietly when it is absent --
//! presence is not capability, and neither is absence a pass.
//!
//! The format is RFC 8878. The parts that matter here:
//!
//! | layer | what it is |
//! | --- | --- |
//! | frame | magic, a header describing the window and content size, blocks, optional checksum |
//! | block | 3-byte header: last-flag, type (raw / RLE / compressed), size |
//! | compressed block | a literals section and a sequences section |
//! | literals | raw, RLE, or Huffman-coded with zstd's own weight format |
//! | sequences | (literal length, match length, offset) triples, FSE-coded, read BACKWARDS |

use std::io;

pub mod block;
pub mod fse;
pub mod huff;
pub mod xxh64;

/// `zstd`'s frame magic, little-endian on the wire.
pub const MAGIC: u32 = 0xFD2F_B528;

/// The largest block the format allows. A frame is a run of blocks each no bigger than
/// this, so a payload of any size crosses as several rather than one that cannot.
pub const MAX_BLOCK: usize = 128 << 10;

/// Block types, in the two bits of the block header that name them.
const BLOCK_RAW: u8 = 0;
const BLOCK_RLE: u8 = 1;
const BLOCK_COMPRESSED: u8 = 2;

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("zstd: {what}"))
}

/// Writes the frame header for `len` bytes of content.
///
/// `Single_Segment_flag` is set, which is the choice worth explaining: it tells the
/// decoder the whole frame decodes into one buffer of the size given, so no
/// `Window_Descriptor` byte is needed and no windowed streaming is implied. That suits
/// this crate, whose payloads are bounded (a wire frame is at most 16 MiB and a tar
/// member is chunked), and it is what lets the header stay four to eleven bytes. A
/// producer of unbounded streams would have to clear the flag and declare a window
/// instead.
fn frame_header(out: &mut Vec<u8>, len: u64) {
    out.extend_from_slice(&MAGIC.to_le_bytes());
    // The content-size field's width is chosen by the size itself, and the 2-byte form
    // carries a 256 BIAS -- a quirk of the format, not of this code: field value 0 in the
    // 2-byte form means 256, so sizes 0..=255 must use the 1-byte form and 256..=65791 the
    // 2-byte one. Getting that wrong produces a frame the reference decoder rejects.
    let (fcs_flag, width) = match len {
        0..=255 => (0u8, 1usize),
        256..=65_791 => (1, 2),
        65_792..=0xFFFF_FFFF => (2, 4),
        _ => (3, 8),
    };
    // bits 7-6 content-size flag, bit 5 single segment, bit 2 CHECKSUM, bits 1-0
    // dictionary id (none). Bits 4 and 3 are unused and reserved and must be zero.
    //
    // The checksum bit is SET, because verification on the READ side alone protects
    // frames other producers wrote and leaves this codec's own frames -- the common case
    // on the wire -- silent. The transport's CRC-32 does not close that either; it covers
    // the compressed bytes surviving the socket, not this decoder reading them the way the
    // reference would. So the encoder says what it decoded from, four bytes per frame,
    // and `zstd -d` checks it too.
    out.push((fcs_flag << 6) | (1 << 5) | (1 << 2));
    let v = if width == 2 { len - 256 } else { len };
    out.extend_from_slice(&v.to_le_bytes()[..width]);
}

/// Reads a frame header, returning the declared content size (when it carries one) and
/// how many bytes the header took.
fn read_frame_header(data: &[u8]) -> io::Result<(Option<u64>, usize, bool, usize, u64)> {
    if data.len() < 5 {
        return Err(bad("a frame is shorter than its own header"));
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(bad("not a zstd frame: the magic number does not match"));
    }
    let d = data[4];
    let fcs_flag = d >> 6;
    let single = d & (1 << 5) != 0;
    let checksum = d & (1 << 2) != 0;
    let dict_flag = d & 0b11;
    if d & (1 << 3) != 0 {
        return Err(bad("the reserved bit in the frame header is set"));
    }
    let mut at = 5;
    // THE WINDOW IS DECODED, not read past. It is tempting to argue it need not be: "a
    // window smaller than the content only limits how far back a match may reach, which a
    // correct encoder already respects". That is true of a
    // correct encoder and irrelevant to a decoder, which is handed bytes by whoever sent
    // them. `Block_Maximum_Size` is min(Window_Size, 128 KiB) -- per block, both
    // compressed and regenerated -- so a frame declaring a 1 KiB window and a 128 KiB
    // block is illegal, and reading past the descriptor accepted it. The window
    // descriptor exists to promise a reader how much memory the frame needs; honoring the
    // absolute cap alone keeps the promise the format makes to nobody in particular while
    // breaking the one this frame made.
    let mut window = u64::MAX;
    if !single {
        if data.len() <= at {
            return Err(bad("the frame header ends before its window descriptor"));
        }
        let w = data[at];
        let exponent = u64::from(w >> 3);
        let mantissa = u64::from(w & 7);
        // windowLog is 10 + Exponent, and the mantissa adds eighths of that base
        let base = 1u64 << (10 + exponent);
        window = base + (base / 8) * mantissa;
        at += 1;
    }
    // A FRAME THAT NAMES A DICTIONARY IS REFUSED, because this decoder has none and
    // cannot get one. Measuring the field and stepping over it reads as tolerance and is
    // the same defect class as ignoring trailing frames: the blocks after it decode, the
    // checksum over them matches, and the answer is wrong.
    //
    // Measured against the reference rather than argued. Take a frame `zstd -19` wrote,
    // set Dictionary_ID_flag and splice in an ID, change nothing else:
    //
    //     $ zstd -d -c dictframe.zst
    //     dictframe.zst : Decoding error (36) : Dictionary mismatch
    //
    // rc=1, zero bytes out. Skipping the field makes a decoder return 1024 bytes on the
    // input the reference refuses outright -- laxness, and of the worst kind, because a
    // frame ACTUALLY written against a dictionary has its tables and its match window
    // primed by content we do not hold, so the bytes would be wrong rather than merely
    // unauthorized.
    //
    // Be exact about the limit of this check. It catches a frame that DECLARES an ID.
    // The format also permits a dictionary with the ID omitted (`Dictionary_ID_flag` 0),
    // and nothing in the header distinguishes that from an ordinary frame -- the
    // reference cannot tell either, and decodes it to garbage that its checksum then
    // catches. That case is undetectable here and is not claimed.
    let dict_width = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    if dict_width != 0 {
        return Err(bad(
            "the frame names a dictionary, which this decoder does not carry",
        ));
    }
    at += dict_width;
    let fcs_width = match (fcs_flag, single) {
        (0, true) => 1,
        (0, false) => 0,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    if data.len() < at + fcs_width {
        return Err(bad("the frame header ends before its content size"));
    }
    let size = if fcs_width == 0 {
        None
    } else {
        let mut v = 0u64;
        for (i, &b) in data[at..at + fcs_width].iter().enumerate() {
            v |= u64::from(b) << (8 * i);
        }
        // the 2-byte form's 256 bias, the mirror of the one in `frame_header`
        Some(if fcs_width == 2 { v + 256 } else { v })
    };
    at += fcs_width;
    // A single-segment frame declares no window because the content size IS the window:
    // the whole frame is one segment held at once. Where neither is given, nothing bounds
    // it but the absolute cap.
    if single {
        // The `unwrap_or` here is UNREACHABLE, and saying so is the point: it is easy to read
        // the fallback as a policy decision about single-segment frames that declare no
        // content size. There are none. The format makes Frame_Content_Size mandatory when
        // Single_Segment_flag is set -- the field-width table above reads `(0, true) => 1`
        // for exactly that reason, so `size` is always `Some` on this branch. If that ever
        // stops being true the fallback degrades to the absolute cap rather than inventing
        // a window, which is the safe direction, but it is a backstop and not a rule.
        window = size.unwrap_or(u64::MAX);
    }
    // A DECLARED WINDOW OVER 128 MiB IS REFUSED, matching what `zstd -d` does with no
    // flags. This was laxness, found by asking what the reference refuses that we do not
    // rather than the other way round -- the direction that keeps producing findings.
    //
    // Measured, both frame shapes, because the cap's scope was the part worth checking:
    //
    //   windowed, `zstd --ultra -22 --long=31`  ->  Window size larger than maximum :
    //                                               2147483648 > 134217728
    //   single-segment, declared 134,217,727    ->  read, 134,217,727 bytes out
    //   single-segment, declared 134,217,728    ->  read, 134,217,728 bytes out
    //   single-segment, declared 200,000,000    ->  Frame requires too much memory
    //
    // So the rule is `> 1<<27`, not `>=`, and it applies to single-segment frames too --
    // where the window IS the declared content size, which is why the check sits after
    // that assignment rather than inside the windowed branch.
    //
    // WHAT THIS COSTS, stated rather than hidden: the reference's cap is a DEFAULT, and
    // `zstd -d --long=31` or `--memory=2048MB` lifts it. A peer configured that way reads
    // frames this now refuses. That is the trade, and it is made this way round because
    // the peer running `zstd -d` with no flags is the common case and the one interop is
    // judged against.
    //
    // It costs this codec's own output nothing: the wire layer caps a frame at
    // `remote::proto::MAX_FRAME`, 16 MiB, and a single-segment frame's window is its
    // content size, so our frames declare at most 16 MiB.
    const MAX_WINDOW: u64 = 1 << 27;
    if window > MAX_WINDOW {
        return Err(bad(
            "the frame declares a window larger than any decoder will hold",
        ));
    }
    let block_max = window.min(MAX_BLOCK as u64) as usize;
    Ok((size, at, checksum, block_max, window))
}

/// One block header: the last-block flag, the type, and the size.
fn block_header(out: &mut Vec<u8>, last: bool, kind: u8, size: usize) {
    let v = (u32::from(last) | (u32::from(kind) << 1) | ((size as u32) << 3)).to_le_bytes();
    out.extend_from_slice(&v[..3]);
}

/// Compresses `data` into a complete zstd frame.
///
/// **Today this emits stored blocks only**, which is valid zstd and compresses nothing.
/// It is here so the frame layer and the interop harness can be built and tested before
/// the entropy coders land, NOT as something to wire up as a codec: shipping this under
/// the name `zstd` is precisely the label `docs/src/design-notes.md` refused. The RLE block type is
/// used where a block is one repeated byte, which costs one byte instead of the run and
/// is the only compression this stage honestly performs.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 64 + 32);
    frame_header(&mut out, data.len() as u64);
    if data.is_empty() {
        // a frame still needs one block, and an empty raw block is how a zero-length
        // content is spelled. The checksum is not optional on this path just because
        // there is nothing to hash: the header already says a checksum follows, so
        // omitting it would truncate the frame.
        block_header(&mut out, true, BLOCK_RAW, 0);
        out.extend_from_slice(&(xxh64::hash(data) as u32).to_le_bytes());
        return out;
    }
    let mut at = 0;
    // The repeat history spans the FRAME. The encoder has to carry it for the same reason
    // the decoder does, and it has to carry it in lockstep: a block sent stored leaves the
    // history untouched, which is why `compress_block` only commits its copy on success.
    let mut rep = block::INITIAL_REPEATS;
    while at < data.len() {
        let n = (data.len() - at).min(MAX_BLOCK);
        let chunk = &data[at..at + n];
        let last = at + n == data.len();
        if n > 1 && chunk.iter().all(|&b| b == chunk[0]) {
            // RLE: the size field is the RUN LENGTH and the body is the single byte
            block_header(&mut out, last, BLOCK_RLE, n);
            out.push(chunk[0]);
        } else if let Some(body) = block::compress_block(chunk, &mut rep).ok().flatten() {
            // A compressed block, but only when it is actually smaller. `compress_block`
            // returns None rather than a larger body, so incompressible input falls
            // through to stored below instead of growing -- which is the behavior the
            // frame-level arms already pin for noise.
            block_header(&mut out, last, BLOCK_COMPRESSED, body.len());
            out.extend_from_slice(&body);
        } else {
            block_header(&mut out, last, BLOCK_RAW, n);
            out.extend_from_slice(chunk);
        }
        at += n;
    }
    out.extend_from_slice(&(xxh64::hash(data) as u32).to_le_bytes());
    out
}

/// Decompresses one zstd frame, refusing to produce more than `limit` bytes.
///
/// The limit is not decoration: a block header's size field is 21 bits and a frame may
/// carry any number of blocks, so a hostile frame of a few bytes can declare an unbounded
/// output. Every caller here already knows how much it expects.
pub fn decompress(data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut from = 0usize;
    // EVERY FRAME IN THE INPUT, not just the first.
    //
    // Decoding one frame and returning, ignoring whatever follows, is a silent defect, and
    // measurement confirms it exactly: handed two concatenated frames, the reference
    // returns 700 bytes and a one-frame decoder returns 320 -- the first frame's content,
    // with NO error. Concatenating frames is legal zstd (it is what `cat a.zst b.zst`
    // produces and what `zstd -d` expects), so that is a correct-looking decode of the
    // wrong bytes, which is the failure class this module exists to catch.
    //
    // The wire layer hands this one frame at a time, so the loop runs once there and
    // nothing about that path changes. What changes is every other caller.
    loop {
        from = decompress_one_frame(data, from, limit, &mut out)?;
        if from >= data.len() {
            break;
        }
    }
    Ok(out)
}

/// One frame, appended to `out`, returning where it ended.
fn decompress_one_frame(
    data: &[u8],
    start: usize,
    limit: usize,
    out: &mut Vec<u8>,
) -> io::Result<usize> {
    let data = &data[start..];

    // A SKIPPABLE FRAME IS SKIPPED, which is the whole of what the format asks of a
    // decoder that does not care what is in one. Magic `0x184D2A5_` -- the low nibble is
    // free for the writer to use -- then a four-byte little-endian size, then that many
    // bytes of anything.
    //
    // This arrived with the multi-frame loop and is the price of it: while only the first
    // frame was ever read, a trailing skippable frame was invisible, so nothing needed to
    // know about them. Once every frame is read, one of them stops the decode -- measured,
    // `zstd -d` returned 168 bytes on `data frame + skippable frame` and this returned an
    // error. Refusing a construct the reference reads is an interop defect even when the
    // refusal is loud, so it is closed rather than enumerated.
    if data.len() >= 8 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let n = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
            let end = 8usize
                .checked_add(n)
                .ok_or_else(|| bad("a skippable frame declares a size that overflows"))?;
            if end > data.len() {
                return Err(bad(
                    "a skippable frame declares more bytes than the input holds",
                ));
            }
            return Ok(start + end);
        }
    }

    let (declared, mut at, has_checksum, block_max, window) = read_frame_header(data)?;
    if let Some(n) = declared {
        if n > limit as u64 {
            return Err(bad(
                "the frame declares more content than the caller allows",
            ));
        }
    }
    let frame_start = out.len();
    // THE REMAINING BUDGET, not this frame's declared size, because of an amplification:
    // `reserve(n)` asks for capacity `len + n`, so with many frames each
    // declaring close to `limit`, every frame asks for `out.len() + limit` and the buffer
    // is reallocated toward roughly twice the cap it is allowed to reach. Bounded, so not
    // a memory-safety hole, but it is an attacker choosing our allocation pattern for
    // free. Clamping to what is actually still allowed makes the reservation a hint
    // again, and the arithmetic cannot underflow because `out.len()` never passes `limit`.
    let room = limit.saturating_sub(out.len());
    out.reserve(declared.unwrap_or(0).min(room as u64) as usize);
    // The repeated offsets and the sequence tables live for the whole FRAME, not the
    // block: a sequence in block three can name an offset last used in block one, and a
    // block can declare its table a repeat of an earlier one. Resetting either per block
    // decodes to wrong bytes without erroring.
    let mut frame = block::FrameState::with_window(window);
    loop {
        if at + 3 > data.len() {
            return Err(bad("the frame ends in the middle of a block header"));
        }
        let h =
            u32::from(data[at]) | (u32::from(data[at + 1]) << 8) | (u32::from(data[at + 2]) << 16);
        at += 3;
        let last = h & 1 != 0;
        let kind = ((h >> 1) & 0b11) as u8;
        let size = (h >> 3) as usize;
        // THE BLOCK SIZE FIELD IS 21 BITS AND THE FORMAT'S CAP IS 17, so the field is not
        // taken at its word. Otherwise a 4-byte RLE block could claim 2,097,151 bytes --
        // SIXTEEN TIMES what a block may regenerate -- and only the caller's `limit` would
        // refuse it.
        //
        // That is not merely a conformance gap, though it is one: it is what the wire
        // layer's expansion bound is DERIVED from. `max_expansion` is 32768 because an RLE
        // block costs four bytes and regenerates at most 131072, and that arithmetic is
        // only true if this cap is enforced. Without it the real worst case is 524,287 per
        // byte, and the bound would hold only because `limit` is itself set from the number
        // the bound gates -- protection in a circle. The cap makes the derivation sound.
        //
        // And the cap is the MINIMUM of the window and 128 KiB, not 128 KiB alone.
        // Enforcing only the absolute number accepts a frame that
        // promises a 1 KiB window and then hands over a 128 KiB block, which is the one
        // promise the window descriptor is in the header to make.
        if size > block_max {
            return Err(bad(
                "a block declares more content than its frame's window allows",
            ));
        }
        match kind {
            BLOCK_RAW => {
                #[cfg(test)]
                fse::seen::branch(7);
                if at + size > data.len() {
                    return Err(bad("a stored block runs past the end of the frame"));
                }
                if out.len() + size > limit {
                    return Err(bad("the frame decodes to more than the caller allows"));
                }
                out.extend_from_slice(&data[at..at + size]);
                at += size;
            }
            BLOCK_RLE => {
                #[cfg(test)]
                fse::seen::branch(6);
                if at >= data.len() {
                    return Err(bad("an RLE block has no byte to repeat"));
                }
                if out.len() + size > limit {
                    return Err(bad("the frame decodes to more than the caller allows"));
                }
                out.resize(out.len() + size, data[at]);
                at += 1;
            }
            BLOCK_COMPRESSED => {
                if at + size > data.len() {
                    return Err(bad("a compressed block runs past the end of the frame"));
                }
                // `size` here is the COMPRESSED payload length, which is a different
                // number from the one the block cap is about, so the cap above is narrower
                // than it looks. For a raw or RLE block the size field IS the
                // regenerated length, so checking it above is the whole check. For a
                // compressed block it bounds the INPUT, and the output is whatever the
                // sequences produce: a few hundred bytes of payload can regenerate far
                // more than `block_max` and every check so far would have waved it past.
                //
                // That also matters to the transport's expansion bound, which is derived
                // from "a block regenerates at most 128 KiB". Bounding the payload does
                // not establish that; bounding the output does.
                //
                // AND IT IS BOUNDED WHERE IT IS PRODUCED, not after the fact. A check below
                // the call alone refuses the frame but only once the block has already
                // expanded into `out` -- correct as a verdict, useless as a memory bound,
                // which is the whole point of the window descriptor. `decode_block` carries
                // the ceiling and checks it at every append. The post-call check stays as a
                // backstop and is expected to be unreachable; if it ever fires, an append
                // site was added without one.
                //
                // SO IT IS A BACKSTOP, NOT A CONTROL, and no arm exercises it. It cannot be
                // tested, not from outside. Reaching it needs a `decode_block` that appends past a
                // ceiling it was handed, which is a defect in a function this crate owns,
                // not an input any peer can send. Testing it would mean substituting a
                // deliberately broken `decode_block`, which measures the substitute. It
                // earns its two lines by failing loudly on a future edit rather than by
                // being covered today, and claiming otherwise would be the kind of
                // decorative control this suite keeps deleting.
                let before = out.len();
                let ceiling = before.saturating_add(block_max);
                block::decode_block(&data[at..at + size], out, limit, ceiling, &mut frame)?;
                if out.len() - before > block_max {
                    return Err(bad(
                        "a compressed block regenerated more than its frame's window allows",
                    ));
                }
                at += size;
            }
            _ => return Err(bad("a block declares the reserved type")),
        }
        if last {
            break;
        }
    }
    if let Some(n) = declared {
        // THIS frame's output, measured from where it started -- with several frames in
        // one input, `out.len()` is the running total and would compare the wrong number
        if (out.len() - frame_start) as u64 != n {
            return Err(bad(
                "the frame decoded to a different length than it declared",
            ));
        }
    }
    // The content checksum, VERIFIED rather than skipped.
    //
    // It is tempting to read past it on the grounds that every caller here wraps the
    // payload in its own CRC-32 anyway. That is a fact about rcp's wire, not a property of
    // this function: any other caller would get `Ok` on wrong bytes. It earns its cost
    // here more than it would in most decoders, because the failure this module keeps
    // recording is a decode that SUCCEEDS and is wrong -- a predefined table wrong at two
    // codes turned a 39,990-byte match into a 41-byte one and reported success. Four bytes
    // catch that class without knowing what broke.
    if has_checksum {
        if at + 4 > data.len() {
            return Err(bad(
                "the frame declares a content checksum but ends before it",
            ));
        }
        let want = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        // over THIS frame's output, not the whole buffer -- with several frames in one
        // input each carries its own checksum over its own content
        let got = xxh64::hash(&out[frame_start..]) as u32;
        if got != want {
            return Err(bad(
                "the frame's content checksum does not match what it decoded to",
            ));
        }
        at += 4;
    }
    Ok(start + at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// Runs the REFERENCE `zstd` over stdin, or returns None when it is not installed.
    ///
    /// Returning an Option rather than skipping inside each arm is deliberate: the caller
    /// decides what an absent reference means, and every caller here reports the skip
    /// instead of passing silently. A missing tool is "not measured", never "fine".
    fn reference(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
        let mut c = Command::new("zstd")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        c.stdin.take().expect("piped").write_all(input).ok()?;
        let out = c.wait_with_output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(out.stdout)
    }

    /// The reference compressing a FILE rather than a pipe, which is a different frame.
    ///
    /// `reference` above pipes, and a piped `zstd` does not know how many bytes are coming,
    /// so it clears `Single_Segment_flag` and writes a window descriptor. Handed a file it
    /// knows the size, sets the flag, and the window becomes the content size. Measured:
    ///
    ///     10 bytes     -> descriptor 0x24  (single, 1-byte content size)
    ///     1,000 bytes  -> descriptor 0x64  (single, 2-byte -- the one with the 256 bias)
    ///     300,000      -> descriptor 0xa4  (single, 4-byte)
    ///
    /// EVERY reference frame in every other arm is 0x04 or 0x00, because every other arm
    /// pipes. So the reference's single-segment output had never once reached this decoder,
    /// and "the sweep agrees with the reference" was saying nothing about it.
    fn reference_file(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join(format!("rcp-zstd-ss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(format!("in-{}", input.len()));
        std::fs::write(&path, input).ok()?;
        let out = Command::new("zstd")
            .args(args)
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let _ = std::fs::remove_file(&path);
        if !out.status.success() {
            return None;
        }
        Some(out.stdout)
    }

    fn have_reference() -> bool {
        reference(&["--version"], b"").is_some()
            || Command::new("zstd").arg("--version").output().is_ok()
    }

    fn corpus() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..20_000u32 {
            v.extend_from_slice(
                format!(
                    "2026-09-24T03:{:02}:{:02}Z host{} request {i}\n",
                    i % 60,
                    (i / 7) % 60,
                    i % 13
                )
                .as_bytes(),
            );
        }
        v
    }

    /// Which block types the encoder actually emits, and at what ratio.
    ///
    /// This exists because the interop arm below could pass while every block fell back
    /// to stored -- the reference would read it perfectly and prove nothing about the
    /// compressed path. Presence is not capability, and "the reference accepted it" is
    /// not "the reference accepted a compressed block".
    #[test]
    fn the_encoder_really_emits_compressed_blocks() {
        let text = corpus();
        let f = compress(&text);
        let mut at = read_frame_header(&f).expect("header").1;
        let mut kinds = [0usize; 4];
        loop {
            let h = u32::from(f[at]) | (u32::from(f[at + 1]) << 8) | (u32::from(f[at + 2]) << 16);
            at += 3;
            let last = h & 1 != 0;
            let kind = ((h >> 1) & 0b11) as usize;
            let size = (h >> 3) as usize;
            kinds[kind] += 1;
            at += if kind == 1 { 1 } else { size };
            if last {
                break;
            }
        }
        eprintln!(
            "block types raw={} rle={} compressed={} :: {} bytes from {}",
            kinds[0],
            kinds[1],
            kinds[2],
            f.len(),
            text.len()
        );
        assert!(
            kinds[2] > 0,
            "no block was compressed; the interop arm would be measuring the stored path only"
        );

        // AND THE LITERALS ARE HUFFMAN-CODED, not raw. Same reasoning one level down: a
        // compressed block whose literals are stored is still a compressed block, so the
        // count above would not notice Huffman silently never being chosen.
        let first = read_frame_header(&f).expect("header").1;
        let body_at = first + 3;
        let lit_type = f[body_at] & 0b11;
        eprintln!("first block's literals section type = {lit_type} (0 raw, 1 rle, 2 huffman)");
        assert_eq!(
            lit_type, 2,
            "the literals are not Huffman-coded; the Huffman path is not being exercised"
        );

        // EVERY block, not just the first, and the literals SHARE -- because the share is
        // what explains the gain. Huffman literals moved this frame from 172,745 to
        // 171,209 bytes, under one percent, and that looks like a broken feature until you
        // see that the literals are ~1% of the frame: the matcher covers so much of the
        // input that almost nothing is left uncoded. The literals section compresses 1.84x
        // in isolation (see huff's own arm); there is simply very little of it here.
        let mut at2 = first;
        let mut huff = 0;
        let mut litbytes = 0usize;
        loop {
            let h =
                u32::from(f[at2]) | (u32::from(f[at2 + 1]) << 8) | (u32::from(f[at2 + 2]) << 16);
            at2 += 3;
            let last_b = h & 1 != 0;
            let kind = ((h >> 1) & 0b11) as usize;
            let size = (h >> 3) as usize;
            if kind == 2 && f[at2] & 0b11 == 2 {
                huff += 1;
                let v = u64::from(f[at2])
                    | (u64::from(f[at2 + 1]) << 8)
                    | (u64::from(f[at2 + 2]) << 16)
                    | (u64::from(f[at2 + 3]) << 24)
                    | (u64::from(f[at2 + 4]) << 32);
                litbytes += ((v >> 22) & 0x3_FFFF) as usize;
            }
            at2 += if kind == 1 { 1 } else { size };
            if last_b {
                break;
            }
        }
        assert_eq!(
            huff, kinds[2],
            "only {huff} of {} compressed blocks used Huffman literals",
            kinds[2]
        );
        eprintln!("all {huff} compressed blocks use Huffman literals; their sections total {litbytes} bytes of a {}-byte frame", f.len());
        assert!(
            f.len() < text.len() * 9 / 10,
            "the frame is {} bytes from {}; that is not compression",
            f.len(),
            text.len()
        );
    }

    #[test]
    fn a_frame_round_trips_through_this_decoder() {
        for data in [Vec::new(), b"x".to_vec(), vec![7u8; 300_000], corpus()] {
            let f = compress(&data);
            let back = decompress(&f, data.len().max(1) * 2 + 64).expect("decodes");
            assert_eq!(back, data, "round trip changed {} bytes", data.len());
        }
    }

    /// THE ARM THAT MAKES THIS ZSTD RATHER THAN A PRIVATE FORMAT: the reference decoder
    /// reads what this encoder writes.
    ///
    /// Without it every other arm here would pass against a format that merely agrees
    /// with itself, which is the failure this whole module is written to avoid.
    #[test]
    fn the_reference_zstd_decodes_what_this_encoder_writes() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        for data in [b"x".to_vec(), vec![7u8; 300_000], corpus()] {
            let f = compress(&data);
            let back =
                reference(&["-d", "-c"], &f).expect("the reference decoder must read our frame");
            assert_eq!(
                back,
                data,
                "the reference decoded our {}-byte frame to something else",
                data.len()
            );
        }
    }

    /// A match may not reach further back than the frame's own window says it can.
    ///
    /// Clamping the BLOCK size to the window does not deliver this: a frame can declare a
    /// 1 KiB window, keep every block far under the cap, and still carry a sequence whose
    /// offset reaches 100 KiB back. Legal against the block cap, illegal against the
    /// window, and easy to accept if the two meanings are not kept separate.
    ///
    /// Built by SHRINKING a real reference frame's window descriptor rather than by hand:
    /// the frame's matches are whatever `zstd -19` chose, so the arm is about the decoder's
    /// bound rather than about a fixture somebody wrote to pass. The control is the same
    /// frame unpatched, which must still decode -- without it this would pass on a decoder
    /// that rejects every frame with a window descriptor.
    #[test]
    fn a_match_may_not_reach_past_the_window_the_frame_declared() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        // streamed from stdin, so the reference writes no content size and the frame
        // carries a real Window_Descriptor byte at index 5
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(4000);
        let f = reference(&["-19", "-c"], &text).expect("the reference must compress");
        let (_, _, _, _, window) = read_frame_header(&f).expect("header");
        assert!(
            window < u64::MAX,
            "this frame declares no window, so it cannot test a window bound -- the \
             reference wrote a single-segment frame and the arm needs a streamed one"
        );
        assert_eq!(
            decompress(&f, text.len() + 4096).expect("the unpatched frame must decode"),
            text
        );

        // now shrink the window to the smallest the format can spell: exponent 0,
        // mantissa 0, which is 1 KiB.
        let mut narrow = f.clone();
        narrow[5] = 0x00;
        let (_, _, _, _, small) = read_frame_header(&narrow).expect("patched header");
        assert_eq!(
            small, 1024,
            "the patched descriptor should spell a 1 KiB window, not {small}"
        );
        let e = decompress(&narrow, text.len() + 4096)
            .expect_err("a block regenerating past the declared window must be refused");

        // THE MESSAGE IS ASSERTED EXACTLY, and the reason is a defect this arm had.
        //
        // It used to assert `contains("window allows")`, which BOTH window refusals
        // satisfy. When the regeneration bound moved inside the block decoder, this frame
        // started tripping regeneration instead of the offset check -- and the arm kept
        // passing while its name became false. An arm that survives a change in what it
        // measures is the exact failure this module keeps finding elsewhere; it is only
        // embarrassing to find it here because the guard was written by the same hand.
        //
        // So each refusal is now pinned to its own wording, and the offset case lives in
        // its own arm below with a corpus that actually reaches it.
        assert!(
            e.to_string().contains("a block regenerated more than"),
            "expected the per-append regeneration bound, got: {e}"
        );
        eprintln!("a {}-byte reference frame decodes, and its first block is refused mid-append once the window is narrowed to 1 KiB", f.len());
    }

    /// The OFFSET bound, on a corpus that reaches it -- which the arm above no longer does.
    ///
    /// A match offset may not reach further back than the window, even when it lands inside
    /// output the decoder still holds. That is a conformance rule rather than a safety one
    /// here (this decoder keeps the whole output), which is why it survived so long: nothing
    /// crashes, the bytes are simply accepted when a window-respecting decoder would refuse.
    ///
    /// The corpus is built for it: a unique 5 KB prefix, 140 KB of filler, then the prefix
    /// again. The final copy is a match reaching back about 145,000 bytes. Narrowed to a
    /// 128 KiB window, that match is out of range while every block still regenerates at
    /// most 128 KiB -- so the offset check is the one that must fire, and the regeneration
    /// check must NOT. Measured at three widths: refused at 128 KiB, decodes at 256 KiB and
    /// 512 KiB, which is the control that the refusal is the window and not the frame.
    #[test]
    fn a_match_offset_may_not_reach_past_the_window_even_when_the_bytes_are_still_held() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        let mut st = 0xDEAD_BEEF_1234_5678u64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let head: Vec<u8> = (0..5_000).map(|_| (rnd() % 251) as u8).collect();
        let filler: Vec<u8> = (0..140_000).map(|_| (rnd() % 251) as u8).collect();
        let mut text = head.clone();
        text.extend_from_slice(&filler);
        text.extend_from_slice(&head);

        let f = reference(&["-19", "-c"], &text).expect("the reference must compress");
        assert_eq!(
            decompress(&f, text.len() + 4096).expect("the unpatched frame must decode"),
            text
        );

        // 0x38 is exponent 7, mantissa 0: base 1 << 17, exactly 128 KiB
        let mut narrow = f.clone();
        narrow[5] = 0x38;
        let (_, _, _, _, win) = read_frame_header(&narrow).expect("patched header");
        assert_eq!(
            win, 131_072,
            "0x38 should spell a 128 KiB window, not {win}"
        );
        let e = decompress(&narrow, text.len() + 4096)
            .expect_err("a match reaching past the declared window must be refused");
        assert!(
            e.to_string()
                .contains("a match offset reaches further back"),
            "expected the offset bound and not the regeneration bound, got: {e}"
        );

        // THE CONTROL: widen the window and the same frame decodes. Without it the refusal
        // above could be any property of this corpus rather than the window doing work.
        for (w, expect) in [(0x40u8, 262_144u64), (0x48, 524_288)] {
            let mut wide = f.clone();
            wide[5] = w;
            let (_, _, _, _, got) = read_frame_header(&wide).expect("header");
            assert_eq!(got, expect, "descriptor {w:#04x} should spell {expect}");
            assert_eq!(
                decompress(&wide, text.len() + 4096).expect("a wide enough window decodes"),
                text
            );
        }
        eprintln!(
            "a long-range match is refused at a 128 KiB window and accepted at 256 KiB and 512 KiB"
        );
    }

    /// The encoder writes a content checksum, and the REFERENCE agrees with the value.
    ///
    /// Two separate claims, and the second is the one worth the process spawn. Verifying
    /// a checksum on the read side protects frames somebody else wrote; with the flag off
    /// in the encoder, this codec's own frames -- what actually crosses the rcp wire --
    /// would carry no such protection at all. That is the kind of gap a round-trip arm
    /// cannot see, because both sides agreeing to omit a check still round-trips perfectly.
    ///
    /// It also pins XXH64 far harder than the four published vectors do. `zstd -d`
    /// recomputes the hash with its own implementation, so every payload here is another
    /// length at which ours must agree -- and a corrupted frame must be REFUSED by the
    /// reference, which is what proves the bytes we wrote are a checksum rather than four
    /// bytes the reference happens to ignore.
    #[test]
    fn every_frame_this_encoder_writes_carries_a_checksum_the_reference_agrees_with() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        let mut refused = 0;
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"x".to_vec(),
            b"the quick brown fox jumps over the lazy dog".repeat(40),
            vec![7u8; 300_000],
            corpus(),
        ];
        for data in &cases {
            let f = compress(data);
            assert!(
                read_frame_header(&f).expect("our own header must parse").2,
                "a {}-byte frame went out with the checksum flag clear",
                data.len()
            );
            // the reference reads it, which means the reference CHECKED it
            let back = reference(&["-d", "-c"], &f)
                .expect("the reference must read our checksummed frame");
            assert_eq!(
                &back,
                data,
                "the reference decoded our {}-byte frame to something else",
                data.len()
            );

            // and the control: break one content byte and require BOTH decoders to say so.
            // Without this the arm would pass on an encoder that wrote four zero bytes.
            if f.len() > 12 {
                let mut bad_frame = f.clone();
                let last = bad_frame.len() - 5; // just before the 4 checksum bytes
                bad_frame[last] ^= 0xFF;
                if reference(&["-d", "-c"], &bad_frame).is_none() {
                    refused += 1;
                }
            }
        }
        assert!(
            refused >= 2,
            "the reference refused only {refused} tampered frames; if it accepts them our \
             four checksum bytes are not the checksum it computes, and this arm proves nothing"
        );
        eprintln!(
            "{} frames from this encoder carried a checksum the reference verified; {refused} tampered frames refused by the reference",
            cases.len()
        );
    }

    /// And the other direction, which is a different claim: this decoder reads what the
    /// reference writes. Only stored and RLE blocks are decodable today, so the input is
    /// asked for at `--fast` with compression off (`-0` is still entropy-coded, `--format`
    /// does not help) -- and when the reference declines to emit stored blocks the arm
    /// says the shape it got rather than passing.
    #[test]
    fn this_decoder_reads_a_reference_frame_of_stored_blocks() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        // incompressible input is what makes the reference choose stored blocks; a
        // compressible one would come back entropy-coded and is covered once the
        // compressed-block path lands
        let mut noise = Vec::with_capacity(200_000);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        while noise.len() < 200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.push((x >> 24) as u8);
        }
        let f = reference(&["-1", "-c"], &noise).expect("the reference must compress");
        match decompress(&f, 400_000) {
            Ok(back) => assert_eq!(
                back, noise,
                "we decoded a reference frame to the wrong bytes"
            ),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("compressed blocks are not decoded yet"),
                    "a reference frame of stored blocks must decode; this failed for another reason: {s}"
                );
                eprintln!("NOT MEASURED: the reference chose compressed blocks for this input; the stored-block direction is untested here");
            }
        }
    }

    /// Corpora chosen to move the Huffman tree description around, not to be realistic.
    ///
    /// The weight table is the piece whose boundary was wrong, and the defect that hid it
    /// was a byte count that is only wrong when the description does NOT end on a byte
    /// boundary. One corpus cannot distinguish "the reader is right" from "this sample
    /// happens to land where the bug is invisible", so these vary the alphabet width and
    /// the skew, which is what moves the description's length in bits.
    fn corpora() -> Vec<(&'static str, Vec<u8>)> {
        let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
        v.push(("timestamps", corpus()));
        // a narrow alphabet: few symbols, so few weights and a short description
        v.push(("two symbols", b"abababbaab".repeat(4000)));
        // the full byte range, so the description carries 255 weights and long zero runs
        v.push(("every byte", (0..=255u8).cycle().take(120_000).collect()));
        // English-ish prose, the distribution zstd's defaults were tuned on
        v.push((
            "prose",
            b"the quick brown fox jumps over the lazy dog while the dog sleeps on. ".repeat(1500),
        ));
        // heavy skew with a sparse tail: one dominant literal, rare high bytes
        v.push(("skewed", {
            let mut d = vec![b'x'; 60_000];
            for i in 0..600u32 {
                d.extend_from_slice(&[200 + (i % 50) as u8, b'x', b'x']);
            }
            d
        }));
        v
    }

    /// Every reference frame in `corpora()` decodes to exactly the bytes that made it.
    ///
    /// This arm used to record a BOUNDARY -- the piece not yet implemented -- and it was
    /// written to be flipped to this the moment the last one landed. Each corpus at each
    /// level exercises a different combination: raw / RLE / Huffman / treeless literals,
    /// one bitstream or four, direct or FSE-coded weights, predefined / RLE / FSE /
    /// repeated sequence tables, and the three repeat-offset codes.
    ///
    /// **The corpora are the point, not the count.** The defects this found were each
    /// invisible to the others: a corpus of timestamps exercises FSE-coded weights and
    /// nothing else caught the table-description boundary; a two-symbol corpus is the only
    /// one whose single enormous match exposed a wrong predefined match-length
    /// distribution; ordinary prose is what picks the single-stream literals form. One
    /// corpus would have passed and proved a fraction of this.
    #[test]
    fn every_reference_frame_decodes_to_the_bytes_that_made_it() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; interop was NOT measured");
            return;
        }
        let mut measured = 0;
        let mut checksummed = 0;
        for (name, text) in corpora() {
            for level in ["-1", "-3", "-9"] {
                let f = reference(&[level, "-c"], &text).expect("the reference must compress");
                let back = decompress(&f, text.len() * 2 + 1024).unwrap_or_else(|e| {
                    panic!("{name} {level}: a reference frame did not decode: {e}")
                });
                assert_eq!(
                    back.len(),
                    text.len(),
                    "{name} {level}: decoded {} bytes from a {}-byte input",
                    back.len(),
                    text.len()
                );
                assert!(back == text, "{name} {level}: decoded the right LENGTH but the wrong bytes, which is the failure a length check alone would miss");
                // PRESENCE IS NOT CAPABILITY: the content checksum is only verified when
                // the frame carries one, so an arm that never sees one would pass with
                // the whole XXH64 path dead. `zstd -c` sets the flag by default, and this
                // requires it rather than hoping.
                assert!(read_frame_header(&f).expect("header").2, "{name} {level}: the reference frame carries no checksum, so this arm proves nothing about verifying one");
                checksummed += 1;
                // and the check must be able to FAIL: flipping the trailing digest has to
                // be refused, or "verified" means nothing
                let mut tampered = f.clone();
                let n = tampered.len();
                tampered[n - 1] ^= 0x01;
                let e = decompress(&tampered, text.len() * 2 + 1024)
                    .expect_err("a frame with a corrupted checksum must be refused");
                assert!(
                    e.to_string().contains("checksum"),
                    "{name} {level}: a corrupted checksum was refused for the wrong reason: {e}"
                );
                measured += 1;
            }
        }
        assert_eq!(
            measured, 15,
            "the corpus set changed; {measured} frames were read"
        );
        assert_eq!(
            checksummed, 15,
            "only {checksummed} of the frames carried a content checksum"
        );
        eprintln!("{measured} reference frames decoded byte-for-byte; all {checksummed} content checksums verified, and each is refused when tampered with");
    }

    /// Arbitrary bytes and corrupted frames must ERROR, never panic and never over-produce.
    ///
    /// This decoder is fed by a network socket, so every table log, symbol count, sequence
    /// count, literal size and match offset in it is attacker-chosen. Reading the code and
    /// finding the bounds checks is not evidence that they are all there -- the four
    /// defects this module already records were each invisible to a reading. So this runs
    /// the thing: a deterministic generator mutates real frames a byte at a time and also
    /// produces pure noise, and the only accepted outcomes are an error or an output
    /// within the caller's limit.
    ///
    /// A panic here is a denial of service on anything that decompresses untrusted input,
    /// which is what this is for.
    ///
    /// **Two controls, and they did NOT agree, which is the useful part.** Replanting a
    /// removed `offset > out.len()` check in the match copy makes this arm fail with
    /// `attempt to subtract with overflow` -- so the generator genuinely reaches the
    /// sequence decode path and the arm is not vacuous. Replanting a removed
    /// `at > body.len()` check before the sequence bitstream does NOT make it fail, and
    /// the reason is that the check is unreachable rather than untested: every path that
    /// advances `at` past the literals section is itself bounded (`body.get` for an RLE
    /// table symbol, and `read_ncount` returning a count no larger than the slice it was
    /// handed), so `at` cannot exceed `body.len()`. That guard is documented as the
    /// invariant backstop it is, instead of being counted as a defense this arm covers.
    #[test]
    fn corrupted_and_random_input_errors_rather_than_panicking() {
        let limit = 1 << 20;
        let mut errored = 0usize;
        let mut decoded = 0usize;

        for (_kind, input) in hostile_inputs() {
            match decompress(&input, limit) {
                Ok(out) => {
                    assert!(
                        out.len() <= limit,
                        "a corrupted frame decoded past the limit"
                    );
                    decoded += 1;
                }
                Err(_) => errored += 1,
            }
        }

        // The arm would be vacuous if everything were refused at the magic, so both
        // outcomes are required to have happened.
        assert!(
            errored > 1000,
            "only {errored} inputs were refused; the generator is not reaching the decoder"
        );
        eprintln!("fuzz: {errored} refused, {decoded} decoded within the limit, 0 panics");
    }

    /// WHICH REFUSAL PATHS THE HOSTILE CORPUS ACTUALLY REACHES, counted rather than assumed.
    ///
    /// This module's most expensive recurring mistake is a check nobody ever runs: the
    /// interleaved FSE decoder sat at ZERO entries across 117 reference frames while its
    /// termination rule was being argued over. The same suspicion applies to
    /// `remaining() != 0` -- 283 frames passing shows the check does not FALSE-reject valid
    /// padding, and says nothing about whether it ever fires.
    ///
    /// Measured, and it does: 6 of the 4,707 hostile inputs are refused for leftover bits.
    /// So the arm is not "reason about the bit reader", it is "name the conformance checks
    /// whose vacuity would be invisible, and require the corpus to reach every one".
    ///
    /// The counts are deliberately not asserted -- they move with the seed and pinning them
    /// would make this brittle without making it stronger. What is asserted is presence,
    /// which is the property that was missing.
    ///
    /// One check is knowingly absent from this list and it is worth saying why: `a match
    /// offset reaches further back than the frame's window allows` is NOT reached by this
    /// corpus, because mutating a frame rarely produces a long-range match that is still
    /// otherwise decodable. It has its own arm with a corpus built to reach it.
    #[test]
    fn the_hostile_corpus_reaches_every_conformance_check_that_matters() {
        use std::collections::BTreeMap;
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (_kind, input) in hostile_inputs() {
            if let Err(e) = decompress(&input, 1 << 20) {
                *seen.entry(e.to_string()).or_default() += 1;
            }
        }

        // Each of these is a refusal this decoder would otherwise only be ARGUED to make.
        const MUST_BE_REACHED: &[&str] = &[
            "the sequences bitstream has bits left after its last sequence",
            "the reserved bits of the compression-modes byte are set",
            "a match offset reaches before the start of the output",
            "a block regenerated more than its frame's window allows",
            "the frame's content checksum does not match",
            "a block declares more content than its frame's window allows",
            "the frame decoded to a different length than it declared",
            "a sequence asks for more literals than the section holds",
        ];
        for want in MUST_BE_REACHED {
            let hits: usize = seen
                .iter()
                .filter(|(m, _)| m.contains(want))
                .map(|(_, n)| n)
                .sum();
            assert!(
                hits > 0,
                "no hostile input was refused by `{want}`, so that check is untested by this \
                 corpus and its behavior is an argument rather than a measurement"
            );
        }
        eprintln!(
            "hostile corpus reaches {} distinct refusal paths, all {} named ones among them",
            seen.len(),
            MUST_BE_REACHED.len()
        );
    }

    /// The two shapes that used to be decoded WRONG, kept as a regression guard.
    ///
    /// This arm began life planting a laxness case -- a valid frame plus trailing bytes,
    /// which this decoder accepted and `zstd -d` refused -- to show the differential's
    /// laxness counter could move. Following that behavior one step further found the real
    /// defect behind it: if trailing bytes were ignored, then so was a whole trailing
    /// FRAME, and concatenated frames are legal zstd.
    ///
    /// Measured before the fix: two frames in, the reference returned 700 bytes and this
    /// returned 320 -- the first frame only, with no error. A correct-looking decode of the
    /// wrong bytes, which is the failure this module exists to catch, sitting in the public
    /// decode path the whole time.
    ///
    /// Both are now fixed, in opposite directions, and this arm pins both: every frame is
    /// decoded, and bytes that are not a frame are a refusal rather than a shrug. After the
    /// fix there is no input known to be accepted here and refused by the reference, so the
    /// differential's `we_are_laxer == 0` no longer has a planted case -- and saying that
    /// is more honest than manufacturing one.
    #[test]
    fn concatenated_frames_are_all_decoded_and_trailing_junk_is_refused() {
        let a = b"first frame content, distinctive".repeat(10);
        let b = b"SECOND FRAME CONTENT, ALSO DISTINCTIVE".repeat(10);

        // 1. BOTH frames, not just the first.
        let mut both = compress(&a);
        both.extend_from_slice(&compress(&b));
        let mut want = a.clone();
        want.extend_from_slice(&b);
        let got = decompress(&both, 1 << 20).expect("two frames in one buffer must decode");
        assert_eq!(
            got, want,
            "a second frame was dropped. This decoded to {} bytes where the two frames hold {} --              the exact shape of the defect this arm was written for",
            got.len(), want.len()
        );

        // 2. Trailing bytes that are NOT a frame are a refusal, not a silent stop.
        let mut junk = compress(&a);
        junk.extend_from_slice(b"trailing garbage that is not a frame");
        decompress(&junk, 1 << 20)
            .expect_err("bytes after the last frame must be refused, not ignored");

        // 3. SKIPPABLE frames, in every position, and the arithmetic settled by measurement.
        //
        //    This is the interop gap the multi-frame loop opened and had to close: before
        //    it, everything after frame one was invisible, so a skippable frame could not
        //    be noticed either way.
        //
        //    IT IS TEMPTING TO THINK THIS ADVANCE IS OFF BY EIGHT -- that `Frame_Size`
        //    counts the whole skippable frame including its own 8-byte header, so a
        //    decoder should step `n` rather than `8 + n`. It is a specific, falsifiable
        //    claim and it is WRONG, which is worth recording as carefully as a defect
        //    would be. RFC 8878 3.1.2 defines the field as "the size, in bytes, of the
        //    following `User_Data` (without including the magic number nor the size
        //    field)", and the reference agrees: with the field at 11 and NINETEEN bytes on
        //    the wire, `zstd -d` lands on the next data frame in all five arrangements
        //    below. Under the other reading it would land eight bytes early every time and
        //    none of them could pass.
        //
        //    So the five shapes are here because that claim names them, not because they
        //    all fail the same way: first, middle, last, two adjacent, and a zero-length
        //    payload, which is the case where the two readings differ by the most.
        let one_skip = |size: u32, body: &[u8]| {
            let mut v = 0x184D_2A50u32.to_le_bytes().to_vec();
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(body);
            v
        };
        let s11 = one_skip(11, b"hello world");
        let s0 = one_skip(0, b"");
        let arrangements: Vec<(&str, Vec<u8>)> = vec![
            (
                "between",
                [compress(&a), s11.clone(), compress(&b)].concat(),
            ),
            ("first", [s11.clone(), compress(&a), compress(&b)].concat()),
            ("last", [compress(&a), compress(&b), s11.clone()].concat()),
            (
                "adjacent",
                [compress(&a), s11.clone(), s11.clone(), compress(&b)].concat(),
            ),
            ("empty payload", [compress(&a), s0, compress(&b)].concat()),
        ];
        for (where_, buf) in &arrangements {
            assert_eq!(
                decompress(buf, 1 << 20).unwrap_or_else(|e| panic!("skippable {where_}: {e}")),
                want,
                "skippable {where_}: a skippable frame must be stepped over by 8 + Frame_Size"
            );
        }
        // and one that lies about its length is refused rather than read past
        let mut bad_skip = compress(&a);
        bad_skip.extend_from_slice(&0x184D_2A5Fu32.to_le_bytes()); // the low nibble is free
        bad_skip.extend_from_slice(&9_000u32.to_le_bytes());
        bad_skip.extend_from_slice(b"short");
        decompress(&bad_skip, 1 << 20)
            .expect_err("a skippable frame longer than the input must be refused");

        // THE REFERENCE, on every legal shape -- this decoder agreeing with itself about
        // multi-frame input is exactly the kind of agreement that hid the original defect,
        // and it is also the only thing that can settle the off-by-eight question above.
        if have_reference() {
            assert_eq!(
                reference(&["-d", "-c"], &both).expect("the reference reads two frames"),
                want
            );
            assert!(
                reference(&["-d", "-c"], &junk).is_none(),
                "the reference must also refuse trailing junk"
            );
            for (where_, buf) in &arrangements {
                assert_eq!(
                    reference(&["-d", "-c"], buf).unwrap_or_else(|| panic!("the reference must read skippable {where_}")),
                    want,
                    "skippable {where_}: the reference disagrees, so the 8 + Frame_Size reading is wrong after all"
                );
            }
            // Printed only here: the claim is agreement WITH THE REFERENCE, and it used to be
            // printed after the `else` too -- announcing a comparison that had not been made.
            eprintln!("multi-frame: two frames, a skippable frame between them, and trailing junk all behave as the reference does");
        } else {
            eprintln!("SKIP: /usr/bin/zstd is not installed; the reference half was NOT measured");
        }
    }

    /// The reference's SINGLE-SEGMENT frames decode, and until this arm none had ever been
    /// handed to this decoder.
    ///
    /// THE COVERAGE HOLE WAS IN THE HARNESS, NOT THE CORPUS, which is why no amount of
    /// adding inputs would have found it. `reference()` pipes, and a piped `zstd` cannot
    /// know how many bytes are coming, so it clears `Single_Segment_flag` every time.
    /// Every reference frame in every other arm -- all four hundred of them -- is
    /// descriptor 0x04 or 0x00. Handed a FILE the reference knows the size and sets the
    /// flag, at all three content-size widths.
    ///
    /// This also CORRECTS a claim made one commit earlier, which said the reference never
    /// emits single-segment frames at all. That was measured across levels and sizes and
    /// was still wrong, because every measurement went through a pipe -- the same
    /// one-input-path generalization this file keeps cataloging. The window cap that
    /// claim was justifying is unaffected: the 200,000,000-byte refusal was measured
    /// directly and stands. Only the reasoning about who else emits the shape was wrong.
    #[test]
    fn the_reference_single_segment_frames_decode_at_every_content_size_width() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; this was NOT measured");
            return;
        }
        // Sizes chosen to land in each Frame_Content_Size width: 1-byte (0..=255),
        // 2-byte (256..=65791, the form carrying the 256 bias), and 4-byte above that.
        let mut widths = [0usize; 3];
        let mut frames = 0usize;
        for n in [0usize, 1, 10, 255, 256, 1_000, 65_791, 65_792, 300_000] {
            let data: Vec<u8> = b"the quick brown fox jumps over the lazy dog. "
                .iter()
                .copied()
                .cycle()
                .take(n)
                .collect();
            for level in ["-3", "-19"] {
                let Some(f) = reference_file(&[level], &data) else {
                    panic!("the reference could not compress {n} bytes from a file");
                };
                let d = f[4];
                if d & (1 << 5) == 0 {
                    // Not every size makes the reference choose single-segment; skip
                    // those rather than assert, and let the counters below decide whether
                    // enough of the shape was reached to mean anything.
                    continue;
                }
                let got = decompress(&f, n + 4096)
                    .unwrap_or_else(|e| panic!("{n} bytes, {level}, descriptor {d:#04x}: {e}"));
                assert!(
                    got == data,
                    "{n} bytes, {level}: a reference single-segment frame decoded to {} wrong bytes",
                    got.len()
                );
                widths[(d >> 6).min(2) as usize] += 1;
                frames += 1;
            }
        }
        // WITHOUT THIS the arm passes on an empty loop, which is exactly the shape of the
        // hole it was written for.
        assert!(
            frames >= 8,
            "only {frames} single-segment reference frames were decoded, which is not coverage"
        );
        for (i, what) in ["1-byte", "2-byte", "4-byte"].iter().enumerate() {
            assert!(
                widths[i] > 0,
                "no reference single-segment frame used the {what} content-size field, so that \
                 width is still untested against the reference"
            );
        }
        eprintln!(
            "reference single-segment frames decoded: {frames} total, {} at 1-byte, {} at 2-byte, {} at 4-byte",
            widths[0], widths[1], widths[2]
        );
    }

    /// The declared window is capped where the reference caps it, and the BOUNDARY is
    /// asserted rather than the direction.
    ///
    /// This was laxness: a frame declaring a 2 GiB window decoded here and `zstd -d`
    /// answered `Window size larger than maximum : 2147483648 > 134217728`. It was found
    /// by inverting the usual question -- not "what do we refuse that the reference
    /// reads", which the differential already covers, but "what does the REFERENCE refuse
    /// that we read", which nothing was asking.
    ///
    /// Both sides of `1<<27` are checked because an off-by-one here is silent: too strict
    /// and we refuse frames every reference reads, too lax and the cap does nothing.
    #[test]
    fn a_window_larger_than_the_reference_will_hold_is_refused_at_the_same_boundary() {
        const MAXW: usize = 1 << 27;
        // Single-segment frames of RLE blocks: four bytes of wire per 128 KiB of content,
        // so a 200 MB declaration costs 6 KB to build and nothing to refuse.
        let rle_frame = |total: usize| {
            let mut f = MAGIC.to_le_bytes().to_vec();
            f.push((2 << 6) | (1 << 5)); // 4-byte content size, single segment, no checksum
            f.extend_from_slice(&(total as u32).to_le_bytes());
            let mut left = total;
            while left > 0 {
                let n = left.min(MAX_BLOCK);
                left -= n;
                let last = u32::from(left == 0);
                let h = ((n as u32) << 3) | (1 << 1) | last;
                f.extend_from_slice(&h.to_le_bytes()[..3]);
                f.push(b'q');
            }
            f
        };

        // AT the cap: accepted. The limit is raised past it so that `limit` is not what
        // refuses, which would make the arm pass for the wrong reason.
        let at_cap = rle_frame(MAXW);
        let got = decompress(&at_cap, MAXW + 4096)
            .expect("a frame declaring exactly the cap must decode");
        assert_eq!(
            got.len(),
            MAXW,
            "the at-cap frame decoded to the wrong length"
        );

        // ABOVE the cap: refused, by the window rule and not by anything downstream.
        let over = rle_frame(200_000_000);
        let e = decompress(&over, 300_000_000)
            .expect_err("a frame over the window cap must be refused");
        assert!(
            e.to_string().contains("declares a window larger"),
            "the refusal must name the window, not a downstream symptom: {e}"
        );

        if have_reference() {
            assert_eq!(
                reference(&["-d", "-c"], &at_cap)
                    .expect("the reference reads a frame at the cap")
                    .len(),
                MAXW,
                "the reference stops reading at the cap, so the cap is in the wrong place"
            );
            assert!(
                reference(&["-d", "-c"], &over).is_none(),
                "the reference reads a 200 MB window, so this refusal is a divergence, not a match"
            );
        } else {
            eprintln!("SKIP: /usr/bin/zstd is not installed; the reference half was NOT measured");
        }
        eprintln!("window cap: {MAXW} accepted and 200,000,000 refused, on both sides");
    }

    /// A frame naming a dictionary is refused, and the REFERENCE is what settles that.
    ///
    /// The header field was read and stepped over, so the blocks after it decoded, the
    /// checksum over them matched, and this returned bytes on an input `zstd -d` will not
    /// touch. Same shape as the multi-frame defect one round earlier: a correct-looking
    /// decode of something the ecosystem treats as undecodable.
    ///
    /// Three arms and a control, because a check that refuses everything passes every
    /// refusal arm while making the decoder useless.
    #[test]
    fn a_frame_that_names_a_dictionary_is_refused_and_the_reference_refuses_it_too() {
        let data = b"2026-09-24T03:00:00Z host1 request 7\n".repeat(200);
        let base = compress(&data);

        // CONTROL: the same frame with no dictionary flag is read by both.
        assert_eq!(
            decompress(&base, 1 << 20).expect("the unmodified frame must decode"),
            data
        );

        let mut widths_checked = 0usize;
        for (flag, width) in [(1u8, 1usize), (2, 2), (3, 4)] {
            let d = base[4];
            let hdr_rest = if d & (1 << 5) == 0 { 6 } else { 5 };
            let mut v = base[..4].to_vec();
            v.push((d & 0xFC) | flag);
            v.extend_from_slice(&base[5..hdr_rest]);
            v.extend(std::iter::repeat_n(0x42, width));
            v.extend_from_slice(&base[hdr_rest..]);

            let e = decompress(&v, 1 << 20)
                .expect_err("a frame naming a dictionary must be refused, not decoded without one");
            assert!(
                e.to_string().contains("names a dictionary"),
                "the refusal must be about the dictionary, not a downstream symptom: {e}"
            );

            // The reference, on the same bytes. Without this the arm only says this
            // decoder is strict, which is not the claim -- the claim is that it agrees.
            if have_reference() {
                assert!(
                    reference(&["-d", "-c"], &v).is_none(),
                    "the reference must refuse a {width}-byte dictionary ID it does not hold; if it \
                     reads one, this refusal is a divergence and belongs in DELIBERATELY_STRICTER"
                );
            }
            widths_checked += 1;
        }
        assert_eq!(
            widths_checked, 3,
            "all three Dictionary_ID widths must be exercised"
        );

        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; the reference half was NOT measured");
        }
        eprintln!(
            "dictionary: 3 ID widths refused here and by the reference; 1 control frame decoded"
        );
    }

    /// The hostile corpus, in one place so the two arms that read it cannot drift apart.
    ///
    /// Three shapes, because they reach different checks: a flipped byte finds a bad VALUE,
    /// a truncation finds a missing LENGTH check, and noise behind a valid magic gets past
    /// the first four bytes so the header parser runs at all.
    fn hostile_inputs() -> Vec<(&'static str, Vec<u8>)> {
        // xorshift rather than a dependency, and seeded so a failure is reproducible
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut out = Vec::new();

        for seed in [
            b"".as_slice(),
            b"a",
            b"abcabcabcabc",
            b"the quick brown fox jumps over the lazy dog",
        ] {
            let data: Vec<u8> = seed
                .iter()
                .cycle()
                .take(if seed.is_empty() { 0 } else { 3000 })
                .copied()
                .collect();
            let frame = compress(&data);
            for at in 0..frame.len().min(400) {
                for bit in [0x01u8, 0x80, 0xFF] {
                    let mut bad = frame.clone();
                    bad[at] ^= bit;
                    out.push(("flip", bad));
                }
            }

            // THE SAME FRAME WITH ITS CHECKSUM REMOVED, and the reason is a measurement.
            // Once this encoder started writing a content checksum, every corrupted frame
            // above began failing verification instead of decoding: the accept count over
            // this corpus went from 129 to ZERO. That is the checksum doing exactly its
            // job, and it also blinded the differential arm, which can only compare inputs
            // somebody accepts. A peer may send an unchecksummed frame -- `zstd --no-check`
            // does -- so mutating one is both realistic and the only way to keep measuring
            // what this decoder does with damage it cannot detect cheaply.
            //
            // Be exact about what this is. It is a valid no-checksum frame from THIS
            // encoder, made by clearing the flag and dropping the trailer, and the
            // reference reads it. It is NOT a sample of what `zstd --no-check` emits for
            // the same input: a different encoder makes different block and header choices.
            // It widens the differential's reach, which is what it is for; it does not
            // model a peer's output distribution and is not evidence about one.
            let mut nock = frame.clone();
            nock[4] &= !(1 << 2); // clear Content_Checksum_flag
            nock.truncate(nock.len() - 4);
            for at in 0..nock.len().min(400) {
                for bit in [0x01u8, 0x80, 0xFF] {
                    let mut bad = nock.clone();
                    bad[at] ^= bit;
                    out.push(("flip-nocheck", bad));
                }
            }
        }

        let frame = compress(&b"2026-09-24T03:00:00Z host1 request 7\n".repeat(200));
        for keep in 0..frame.len().min(600) {
            out.push(("truncation", frame[..keep].to_vec()));
        }

        // FRAMES THAT NAME A DICTIONARY, spliced rather than flipped -- and the
        // distinction is why the corpus above missed this for twenty rounds.
        //
        // Byte 4 is inside the flip window, so `flip` DOES set Dictionary_ID_flag
        // sometimes. It just never produces a dictionary frame: setting the flag without
        // inserting the ID shifts every later field by one to four bytes, so the content
        // size is read from the wrong offset and the blocks are misaligned. Both decoders
        // then refuse, for reasons that have nothing to do with dictionaries, and the
        // input lands in `checked_refusals` looking like coverage.
        //
        // A well-formed dictionary frame has to be BUILT: set the flag and splice an ID of
        // the matching width, leaving everything after it aligned. All three widths, since
        // the width comes from the flag value.
        for (flag, width) in [(1u8, 1usize), (2, 2), (3, 4)] {
            let d = frame[4];
            let mut v = frame[..4].to_vec();
            v.push((d & 0xFC) | flag);
            // the window descriptor, when the frame carries one, sits before the ID
            let hdr_rest = if d & (1 << 5) == 0 { 6 } else { 5 };
            v.extend_from_slice(&frame[5..hdr_rest]);
            v.extend(std::iter::repeat_n(0x42, width));
            v.extend_from_slice(&frame[hdr_rest..]);
            out.push(("dict-id", v));
        }

        for _ in 0..4000 {
            let n = (next() % 200) as usize + 4;
            let mut v = MAGIC.to_le_bytes().to_vec();
            while v.len() < n {
                v.extend_from_slice(&next().to_le_bytes());
            }
            v.truncate(n);
            out.push(("noise", v));
        }
        out
    }

    /// Not panicking is not the same as being RIGHT, and the arm above only measures the
    /// first. If the inputs this decoder ACCEPTS are never compared to anything, a
    /// confidently wrong decode of a corrupted frame counts as a success.
    ///
    /// So every accepted input is put to the reference, and the outcomes are sorted into
    /// three piles rather than two, because they mean different things:
    ///
    /// - **both accept, bytes differ** -- the worst class there is. Two decoders reading
    ///   one byte sequence into two answers is a silent wrong decode on the wire, and it
    ///   is a hard failure here.
    /// - **the reference accepts, we refuse** -- an interop defect in the safe direction,
    ///   but still a defect: a peer would send it and we would drop the transfer. Also a
    ///   hard failure.
    /// - **we accept, the reference refuses** -- laxness, not corruption. Measured here:
    ///   zero cases.
    /// - **we refuse, the reference accepts** -- an interop defect in the safe direction,
    ///   but still a defect: a peer would send it and we would drop the transfer. A hard
    ///   failure UNLESS the refusal is one of the enumerated strictness rules below.
    ///
    /// **The enumerated list is the load-bearing part.** "We are stricter than the
    /// reference" is exactly the sentence that would let a real interop bug through, so it
    /// is not available as a blanket excuse: each permitted refusal must name a rule the
    /// format states and this decoder enforces, and anything else fails. The list was
    /// derived by census rather than guessed -- over 4,559 hostile inputs the only refusal
    /// the reference disagrees with is the reserved field of `Symbol_Compression_Modes`,
    /// which RFC 8878 says must be all zeroes and which libzstd 1.5.5 ignores. That is a case
    /// of the reference being permissive about a MUST, and following it would mean accepting
    /// frames the format declares invalid. libzstd 1.5.7 enforces the rule too, so against a
    /// newer reference the two agree and the list is simply not needed.
    #[test]
    fn what_this_decoder_accepts_from_a_hostile_input_matches_the_reference() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; this was NOT measured");
            return;
        }
        /// Refusals the reference does not share, each with the rule that justifies it.
        /// Adding a line here is a claim about the format and should be read as one.
        const DELIBERATELY_STRICTER: &[&str] = &[
            // RFC 8878 3.1.1.3.2.1.1: the low two bits of Symbol_Compression_Modes are
            // Reserved and "must be all zeroes". libzstd 1.5.5 masks them off and
            // proceeds; 1.5.7 refuses them as this decoder does. Measured through the same
            // API on the 20 corpus frames that reach this check: 1.5.5 accepts 4, 1.5.7
            // accepts none.
            "the reserved bits of the compression-modes byte are set",
        ];

        let limit = 1 << 20;
        let (mut agreed, mut we_are_laxer, mut checked_refusals, mut stricter, mut reached) =
            (0usize, 0usize, 0usize, 0usize, 0usize);

        for (kind, input) in hostile_inputs() {
            match decompress(&input, limit) {
                Ok(ours) => {
                    match reference(&["-d", "-c"], &input) {
                        Some(theirs) => {
                            assert!(
                            theirs == ours,
                            "{kind}: this decoder and the reference read one {}-byte input into \
                             two different answers ({} vs {} bytes). That is a silent wrong \
                             decode, which is the failure this whole module is written against",
                            input.len(), ours.len(), theirs.len()
                        );
                            agreed += 1;
                        }
                        None => we_are_laxer += 1,
                    }
                }
                Err(e) => {
                    checked_refusals += 1;
                    let msg = e.to_string();
                    if DELIBERATELY_STRICTER.iter().any(|r| msg.contains(r)) {
                        reached += 1;
                    }
                    if let Some(theirs) = reference(&["-d", "-c"], &input) {
                        assert!(
                            DELIBERATELY_STRICTER.iter().any(|r| msg.contains(r)),
                            "{kind}: the reference read a {}-byte input into {} bytes and this \
                             decoder refused it with `{msg}` -- a peer could send this and we \
                             would drop it. If that refusal is right, add the rule that makes \
                             it right to DELIBERATELY_STRICTER; do not widen the check",
                            input.len(),
                            theirs.len()
                        );
                        stricter += 1;
                    }
                }
            }
        }

        // Without these the arm would pass if every input were refused by both, which
        // proves nothing about agreement.
        assert!(
            agreed > 50,
            "only {agreed} inputs were accepted, so there was almost nothing to compare"
        );
        assert!(
            checked_refusals > 1000,
            "only {checked_refusals} refusals were put to the reference"
        );

        // LAXNESS IS A HARD FAILURE TOO, not merely a count. For a wire codec, accepting a
        // frame the de-facto reference rejects is at least as bad as refusing one it
        // accepts, because it means delivering bytes the rest of the ecosystem treats as
        // invalid. Measured at zero over this corpus, so pinning it costs nothing today and
        // catches the regression that would otherwise sit quietly beside a healthy `agreed`
        // count.
        assert_eq!(
            we_are_laxer, 0,
            "{we_are_laxer} inputs were accepted by this decoder and refused by the reference. \
             That is not automatically wrong, but it is not allowed to appear silently -- \
             decide what the case is and record it here"
        );

        // AND THE WHITELISTED CHECK HAS TO BE REACHED, or the list is dead code that proves
        // nothing. If the mutations stop touching the compression-modes byte, no refusal
        // carries the listed text and the escape hatch goes untested while the arm keeps
        // passing. This also catches the brittle part of keying on error text: rename the
        // message without updating the list and this assertion fails rather than the arm
        // quietly widening.
        //
        // It asks that the check be REACHED, not that the reference DISAGREE. Requiring
        // disagreement would be a claim about libzstd's version rather than about this
        // decoder: a newer libzstd refuses reserved bits too, so every one of those frames
        // is refused by both, `stricter` is 0, and the arm would fail on agreement.
        // Reproduced with a `zstd` stand-in backed by libzstd 1.5.7, calibrated first
        // against 1.5.5, where it passes as the real CLI does. `stricter` is still
        // reported, and any refusal the reference does not share must still be on the
        // list above.
        assert!(
            reached > 0,
            "no refusal carried a DELIBERATELY_STRICTER text, so its one entry is untested. \
             Either the corpus stopped reaching that check or the error text was renamed out \
             from under the list"
        );
        eprintln!(
            "differential: {agreed} accepted and byte-identical to the reference, {we_are_laxer} \
             accepted only by us, {reached} refused on an enumerated rule ({stricter} of them \
             refused only by us), {checked_refusals} refusals put to the reference"
        );
    }

    /// What is the MOST a zstd frame can expand, per byte of frame?
    ///
    /// The wire layer refuses a payload claiming more than `body.len() * 32768 + 64`
    /// before it allocates, and 32768 can look like "LZ77-window folklore, not
    /// spec-native" -- possibly wrong in either direction. It is neither folklore nor
    /// a window size: an RLE block is the cheapest way the format has of producing output,
    /// at a 3-byte block header plus one repeated byte, and a block regenerates at most
    /// 128 KiB. 131072 / 4 is 32768, and nothing else is cheaper -- a compressed block
    /// has to spend a literals header and at least one sequence to express a long copy.
    ///
    /// So this builds the frame the argument describes, by hand, and measures the actual
    /// ratio. A derivation that nobody ran is the kind of claim this crate keeps finding
    /// to be wrong; the number is either under the bound or the bound moves.
    #[test]
    fn the_worst_expansion_a_frame_can_reach_stays_under_the_wire_bound() {
        // the bound the wire layer applies, kept here as a literal so a change to either
        // one breaks this arm rather than silently diverging
        let bound = 32768usize;

        let mut worst = 0f64;
        for blocks in [1usize, 4, 64, 512] {
            let mut frame = MAGIC.to_le_bytes().to_vec();
            frame.push(0); // no content size, no checksum, not single-segment
            frame.push(0x40); // window descriptor
            for i in 0..blocks {
                block_header(&mut frame, i + 1 == blocks, BLOCK_RLE, MAX_BLOCK);
                frame.push(b'x');
            }
            let out = decompress(&frame, blocks * MAX_BLOCK + 1).expect("an RLE frame must decode");
            assert_eq!(
                out.len(),
                blocks * MAX_BLOCK,
                "an RLE block did not regenerate its declared run"
            );
            let ratio = out.len() as f64 / frame.len() as f64;
            worst = worst.max(ratio);
            assert!(
                out.len() <= frame.len() * bound + 64,
                "{blocks} RLE blocks expanded {} bytes to {}, past the wire bound of {} -- the bound is too tight and would refuse a legal frame",
                frame.len(),
                out.len(),
                frame.len() * bound + 64
            );
        }

        // 512 IS A SAMPLE, NOT A MAXIMUM, and the four measured points cannot say what
        // happens past them. A frame may carry any number of blocks, and the ratio RISES
        // with the count as the 6-byte frame header amortizes away -- so if the bound held
        // only for the sampled counts, the arm would be reassuring about exactly the wrong
        // end of the range.
        //
        // It is bounded for every N instead, algebraically: N RLE blocks cost `6 + 4N`
        // bytes and regenerate `MAX_BLOCK * N`, so the wire layer's allowance of
        // `(6 + 4N) * 32768 + 64` exceeds it by `6 * 32768 + 64` for every N, because
        // `4 * 32768` is exactly `MAX_BLOCK`. The margin is a constant, not a function of
        // N, and the asymptotic ratio approaches 32768 from below without reaching it.
        for n in [1u64, 512, 4096, 1_000_000, u32::MAX as u64] {
            let frame_len = 6 + 4 * n;
            let regenerated = MAX_BLOCK as u64 * n;
            let allowed = frame_len * 32768 + 64;
            assert!(
                regenerated < allowed,
                "{n} RLE blocks would regenerate {regenerated} against an allowance of {allowed}"
            );
            assert_eq!(
                allowed - regenerated,
                6 * 32768 + 64,
                "the margin should be constant in N"
            );
        }

        // THE PER-BLOCK CEILING DOES NOT MOVE THIS BOUND, which is worth stating because
        // it was added in the same breath as the checks that do. It applies to compressed
        // blocks, inside `decode_block`. An RLE block never enters that function: its size
        // field IS its regenerated length, so the frame loop's `size > block_max` refusal
        // is the whole check, and the cheapest expansion the format allows is unchanged.
        // A narrower window makes each block regenerate LESS for the same header cost, so
        // the worst case is at a window of 128 KiB or more -- which is what `0x40` above
        // declares.

        // AND AN OVER-LARGE BLOCK IS REFUSED BY ITS SIZE, not merely by the caller's
        // limit. Without this the arm above would pass on a decoder that accepts a block
        // claiming 16x the format's cap, because a generous `limit` never notices.
        let mut over = MAGIC.to_le_bytes().to_vec();
        over.push(0);
        over.push(0x40);
        block_header(&mut over, true, BLOCK_RLE, MAX_BLOCK + 1);
        over.push(b'x');
        let e = decompress(&over, usize::MAX / 2)
            .expect_err("a block past the format's cap must be refused");
        assert!(
            e.to_string().contains("window allows"),
            "an over-large block was refused for the wrong reason: {e}"
        );
        // the control: one byte smaller is legal and must still decode
        let mut ok = MAGIC.to_le_bytes().to_vec();
        ok.push(0);
        ok.push(0x40);
        block_header(&mut ok, true, BLOCK_RLE, MAX_BLOCK);
        ok.push(b'x');
        assert_eq!(
            decompress(&ok, usize::MAX / 2)
                .expect("a block AT the cap is legal")
                .len(),
            MAX_BLOCK,
            "the cap is off by one"
        );

        // AND THE OTHER SIDE OF THE MINIMUM, which the two arms above cannot see because
        // both declare a window larger than 128 KiB. `Block_Maximum_Size` is
        // min(Window_Size, 128 KiB), so a frame promising a small window may not then
        // hand over a block bigger than it -- even though that block is far under the
        // absolute cap. A decoder that reads the window descriptor and throws it away
        // accepts this shape.
        //
        // Window descriptor 0 is exponent 0, mantissa 0: a 1 KiB window, the smallest the
        // format can spell.
        let mut narrow = MAGIC.to_le_bytes().to_vec();
        narrow.push(0);
        narrow.push(0x00);
        block_header(&mut narrow, true, BLOCK_RLE, 1025);
        narrow.push(b'x');
        let e = decompress(&narrow, usize::MAX / 2)
            .expect_err("a block larger than the frame's own declared window must be refused");
        assert!(
            e.to_string().contains("window allows"),
            "an over-window block was refused for the wrong reason: {e}"
        );
        // and its control, one byte under the window, which must decode
        let mut fits = MAGIC.to_le_bytes().to_vec();
        fits.push(0);
        fits.push(0x00);
        block_header(&mut fits, true, BLOCK_RLE, 1024);
        fits.push(b'x');
        assert_eq!(
            decompress(&fits, usize::MAX / 2)
                .expect("a block that fits the window is legal")
                .len(),
            1024,
            "the window bound is off by one"
        );

        eprintln!("worst measured frame expansion: {worst:.1}x against a bound of {bound}x; a block one byte past the cap is refused by name");
        // and the bound is TIGHT rather than arbitrary: the measurement must get close to
        // it, or the number is larger than the format can justify and is over-permissive
        assert!(worst > bound as f64 * 0.9, "the worst frame reached only {worst:.1}x of a {bound}x bound, so the bound is looser than the format needs");
    }

    /// A frame that MIXES block types keeps its cross-block state straight.
    ///
    /// The frame encoder emits an RLE block for an all-one-byte chunk WITHOUT going
    /// through `compress_block`, so that path never touches the repeat-offset history --
    /// which is correct, because a block with no sequences must leave it alone. Whether
    /// that is actually what happens needs an arm that mixes the two: every corpus above
    /// produces one kind of block or the other.
    ///
    /// So this forces the interleaving. A sequence in the compressed block AFTER an RLE
    /// block can name an offset last used BEFORE it, and the treeless literals path reuses
    /// a Huffman tree across the same gap. Getting either wrong does not error -- it
    /// decodes to the wrong bytes, which is why both directions are checked against the
    /// reference rather than against ourselves.
    #[test]
    fn a_frame_that_alternates_block_types_keeps_its_cross_block_state() {
        let mut data = Vec::new();
        for round in 0..3u32 {
            // an all-one-byte run longer than a block, so at least one WHOLE block is RLE
            data.extend(std::iter::repeat_n(b'a' + round as u8, MAX_BLOCK + 4096));
            // then something with real matches, whose sequences carry offsets
            for i in 0..4000u32 {
                data.extend_from_slice(
                    format!(
                        "2026-09-24T03:{:02}:{:02}Z host{} request {i}\n",
                        i % 60,
                        (i / 7) % 60,
                        i % 13
                    )
                    .as_bytes(),
                );
            }
        }

        let frame = compress(&data);

        // the arm is vacuous unless BOTH kinds are actually present
        let (_, mut at, _, _, _) = read_frame_header(&frame).expect("header");
        let (mut rle, mut compressed, mut raw) = (0, 0, 0);
        loop {
            let h = u32::from(frame[at])
                | (u32::from(frame[at + 1]) << 8)
                | (u32::from(frame[at + 2]) << 16);
            at += 3;
            let last = h & 1 != 0;
            let size = (h >> 3) as usize;
            match ((h >> 1) & 0b11) as u8 {
                BLOCK_RAW => {
                    raw += 1;
                    at += size;
                }
                BLOCK_RLE => {
                    rle += 1;
                    at += 1;
                }
                _ => {
                    compressed += 1;
                    at += size;
                }
            }
            if last {
                break;
            }
        }
        assert!(
            rle > 0,
            "no RLE block was emitted, so this arm does not test the mixed path"
        );
        assert!(
            compressed > 0,
            "no compressed block was emitted, so there are no sequences to desynchronize"
        );
        eprintln!(
            "mixed frame: {rle} RLE, {compressed} compressed, {raw} raw blocks over {} bytes",
            data.len()
        );

        // our own decoder
        assert!(
            decompress(&frame, data.len() * 2).expect("this decoder must read its own mixed frame")
                == data,
            "our decoder got the wrong bytes back from a mixed frame"
        );

        // and the reference, which is the direction that catches a state convention we
        // merely agree with ourselves about
        if have_reference() {
            let back =
                reference(&["-d", "-c"], &frame).expect("the reference must decode a mixed frame");
            assert!(
                back == data,
                "the reference decoded our mixed frame to the wrong bytes"
            );
        } else {
            eprintln!(
                "SKIP: /usr/bin/zstd is not installed; the reference half of this was NOT measured"
            );
        }
    }

    /// Differential against the reference on the SIZES that change which path runs.
    ///
    /// The 15-frame arm -- five ordinary corpora at three levels -- is one compressor on
    /// typical files, and several paths this decoder parses simply do not appear in it.
    /// The cheap answer is not more prose but more BOUNDARIES -- the lengths at which the
    /// format changes shape:
    ///
    /// - 0 and 1 byte, where a frame has almost no room for anything
    /// - 1023 / 1024 / 1025, the single-stream to four-stream literals split
    /// - `MAX_BLOCK` minus one, exactly, and plus one: the block boundary
    /// - a long single-byte run, which forces RLE and the longest match-length codes
    /// - incompressible noise, where every block must fall back to stored
    ///
    /// Each runs in BOTH directions -- the reference decodes what we write, and we decode
    /// what the reference writes -- because a round trip between two halves that share a
    /// convention cannot see a wrong convention, which is how three of this module's four
    /// defects survived.
    #[test]
    fn the_sizes_where_the_format_changes_shape_agree_with_the_reference() {
        // from zero, so this arm cannot inherit another arm's coverage and pass
        fse::seen::reset();
        fse::seen::reset_branches();
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; this was NOT measured");
            return;
        }
        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        for n in [
            0usize,
            1,
            2,
            7,
            8,
            63,
            64,
            1023,
            1024,
            1025,
            MAX_BLOCK - 1,
            MAX_BLOCK,
            MAX_BLOCK + 1,
        ] {
            cases.push((
                format!("text {n}"),
                b"the quick brown fox jumps over the lazy dog. "
                    .iter()
                    .copied()
                    .cycle()
                    .take(n)
                    .collect(),
            ));
            cases.push((format!("run {n}"), vec![b'q'; n]));
            // deterministic noise: nothing here compresses, so every block goes stored
            let mut st = 0x1234_5678_9ABC_DEF0u64;
            cases.push((
                format!("noise {n}"),
                (0..n)
                    .map(|_| {
                        st ^= st << 13;
                        st ^= st >> 7;
                        st ^= st << 17;
                        st as u8
                    })
                    .collect(),
            ));
        }

        // A SKEWED WIDE ALPHABET, and it is here because of what its absence measured.
        // Before this family the sweep entered the interleaved FSE decoder -- the one that
        // reads FSE-coded Huffman weights -- exactly ZERO times across all 117 frames, so
        // the function that once held an off-by-one, and whose termination rule is the
        // subtlest in the codec, had no interop coverage whatsoever. Text has too small an
        // alphabet and noise does not compress, so the reference chose the DIRECT weight
        // form every time and the FSE branch was never taken.
        //
        // What reaches it is data that compresses while still using most of the byte range.
        let mut st = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for distinct in [40usize, 100, 200, 256] {
            for n in [512usize, 8_192, 120_000] {
                let mut v = Vec::with_capacity(n);
                while v.len() < n {
                    let r = (rnd() % 1000) as usize;
                    // half the draws land on four symbols, which is what makes it
                    // compressible; the rest spread over the alphabet, which is what makes
                    // the weight table big enough for the reference to FSE-code it
                    let idx = if r < 500 { r % 4 } else { r % distinct };
                    v.push((idx * 251 % 256) as u8);
                }
                cases.push((format!("skewed {distinct} over {n}"), v));
            }
        }

        // THE THREE DECODER BRANCHES NO REFERENCE FRAME REACHED, and the measurement that
        // found them. Which of the paths this encoder cannot produce are also unexercised
        // by the reference? That is the same question that once found the
        // interleaved FSE decoder at ZERO across 117 frames. Counted over the 268-frame
        // sweep as it then stood:
        //
        //   treeless literals 0 | single-stream Huffman 0 | RLE seq table 4 | repeat-mode 0
        //
        // Three of the four decoder paths that read attacker-supplied bytes had never run.
        // "283 frames agree" said nothing whatever about them.
        //
        // Two families fix it, and which one reaches which was measured rather than
        // guessed. A LARGE skewed corpus spans several compressed blocks in one frame, so
        // the reference starts reusing the previous block's Huffman tree (treeless) and its
        // previous sequence tables (repeat-mode). SMALL skewed corpora put the whole
        // literals section under 1 KiB, which is the only size the single-stream form can
        // describe -- the four-stream header cannot express a section that small.
        cases.push(("skewed 400k, several blocks per frame".into(), {
            let mut v = Vec::with_capacity(400_000);
            while v.len() < 400_000 {
                let r = (rnd() % 1000) as usize;
                v.push(((if r < 500 { r % 4 } else { r % 200 }) * 251 % 256) as u8);
            }
            v
        }));
        for n in [80usize, 200] {
            cases.push((format!("skewed {n}, one short literals stream"), {
                let mut v = Vec::with_capacity(n);
                while v.len() < n {
                    let r = (rnd() % 1000) as usize;
                    v.push(((if r < 500 { r % 4 } else { r % 60 }) * 251 % 256) as u8);
                }
                v
            }));
        }

        // A NARROW LITERAL ALPHABET, a shape worth singling out: a block that is one
        // repeated byte plus matches. The format will not accept a Huffman
        // tree with fewer than two non-zero weights, and this encoder always reaches for
        // a four-stream compressed literals section when it attempts compression at all,
        // so "the literals here are basically one byte" is the case where those two facts
        // could collide. Pure runs never get there (they leave as whole-block RLE) and
        // text and noise have wide alphabets, so nothing already in the sweep tests it.
        for n in [64usize, 1_000, 5_000, 200_000] {
            for gap in [3usize, 97, 1_000] {
                let mut v = vec![b'a'; n];
                let mut i = gap;
                while i < n {
                    v[i] = b'b';
                    i += gap;
                }
                cases.push((format!("two symbols, b every {gap} of {n}"), v));
            }
            // and the extreme: a single foreign byte in an otherwise uniform block, so the
            // block is not RLE-able but very nearly is
            let mut v = vec![b'q'; n];
            v[n / 2] = b'Z';
            cases.push((format!("one foreign byte in {n}"), v));
        }

        let mut both = 0;
        for (name, data) in &cases {
            // OUT: the reference reads what this encoder wrote
            let ours = compress(data);
            let back = reference(&["-d", "-c"], &ours)
                .unwrap_or_else(|| panic!("{name}: the reference could not read our frame"));
            assert!(
                &back == data,
                "{name}: the reference decoded our {}-byte frame to {} wrong bytes",
                ours.len(),
                back.len()
            );

            // IN: this decoder reads what the reference wrote, with and WITHOUT a checksum
            // FOUR combinations, not three. "Levels -3 and -19, with and without a
            // checksum" is a 2x2, and three per corpus (201 frames over 67 corpora) misses
            // a cell: -19 with the checksum off. The grid carries all four so the sentence
            // stays true.
            for extra in [
                &["-3", "-c"][..],
                &["-3", "-c", "--no-check"][..],
                &["-19", "-c"][..],
                &["-19", "-c", "--no-check"][..],
            ] {
                let theirs = reference(extra, data)
                    .unwrap_or_else(|| panic!("{name}: the reference could not compress"));
                let got = decompress(&theirs, data.len() + 1024).unwrap_or_else(|e| {
                    panic!("{name} {extra:?}: we could not read a reference frame: {e}")
                });
                assert!(
                    &got == data,
                    "{name} {extra:?}: we decoded a reference frame to the wrong bytes"
                );
                both += 1;
            }
        }
        eprintln!(
            "{} boundary corpora agreed in both directions across {both} reference frames",
            cases.len()
        );
        assert!(
            both >= 100,
            "only {both} reference frames were read, which is not a sweep"
        );

        // What the sweep actually reached inside the interleaved FSE decoder. The
        // termination rule could plausibly diverge from the reference on a bitstream
        // shorter than 8 bytes, and the whole answer to that is whether these frames
        // contain one -- this codec's encoder writes direct weight tables only, so it
        // cannot supply the case itself. Counting turns "the frames agree, so the rule is
        // fine" from an assumption into a statement with a scope.
        let (calls, shortest) = (fse::seen::calls(), fse::seen::shortest());
        assert!(
            calls > 0,
            "the sweep never entered the interleaved decoder, so it says nothing about the \
             termination rule. That was the measured state before the skewed family above \
             was added -- if it returns, the corpora stopped producing FSE-coded weights"
        );
        // THE EIGHT BRANCHES THIS ENCODER CANNOT PRODUCE, each required to have run. Three
        // of the first four were at zero when first counted, and nothing in the suite would
        // ever have said so -- the frames agreed, and agreement on paths nobody takes is not
        // evidence.
        //
        // **The last four were added by asking the same question one axis out, and the
        // answer was different.** The first four are branches INSIDE a compressed block;
        // 4-7 are the block and literals-section KINDS, which nothing had ever counted.
        // Measured on this sweep the first time they were:
        //
        //     raw literals 140 | RLE literals 2 | RLE block 4 | raw block 102
        //
        // All four already covered, so this found no hole -- which is the result, and worth
        // the twenty minutes precisely because the same question one axis in had found
        // three. They stay asserted so a corpus that stops producing one of these shapes
        // says so instead of quietly narrowing.
        //
        // WHAT A NON-ZERO COUNT BUYS, stated precisely, because "presence only" would
        // concede that these counters show reachability and nothing else. That concession
        // is too large. The counters are read HERE, at the
        // end of the sweep whose body is `assert!(&got == data)` on every one of its
        // reference frames -- so a count above zero says the branch ran on at least one
        // frame this decoder then reproduced BYTE FOR BYTE against the reference. That is
        // a correctness observation about the branch, not merely that control passed
        // through it.
        //
        // What it still does not buy: coverage of the branch's own edge cases. "Treeless
        // literals ran four times and all four frames matched" is not "every treeless
        // path is right". The counts also move with the reference's own choices, so
        // pinning them to exact numbers would make this brittle without making it
        // stronger, and `> 0` is deliberately all that is asserted.
        let br = fse::seen::branches();
        for (i, what) in [
            "treeless literals",
            "single-stream Huffman",
            "an RLE sequence table",
            "a repeat-mode sequence table",
            "a raw literals section",
            "an RLE literals section",
            "an RLE block",
            "a raw block",
        ]
        .iter()
        .enumerate()
        {
            assert!(
                br[i] > 0,
                "no frame in this sweep made the decoder read {what}, so that branch is \
                 untested and the frames agreeing says nothing about it. Three of the first \
                 four were at zero when this assertion was written; the last four never \
                 were, and are held here so a narrowing corpus says so"
            );
        }
        eprintln!(
            "decoder branches this encoder cannot write: treeless {}, single-stream {}, RLE table {}, repeat table {}, raw literals {}, RLE literals {}, RLE block {}, raw block {}",
            br[0], br[1], br[2], br[3], br[4], br[5], br[6], br[7]
        );
        eprintln!(
            "interleaved FSE bitstreams read while sweeping: {calls}, shortest {shortest} bytes{}",
            if shortest < 8 {
                " -- the short-buffer case IS covered"
            } else {
                " -- none below 8 bytes; see the note on what that does and does not settle"
            }
        );
    }

    /// A single-segment frame ALWAYS carries its content size, and the window is that size.
    ///
    /// The line that invites the question is `if single { window = size.unwrap_or(u64::MAX) }`,
    /// and the question is the right one: if the size parser can return `None` for a
    /// single-segment frame, that fallback is not dead code, it is a hole that drops the
    /// window bound entirely and leaves only the absolute 128 KiB cap.
    ///
    /// The subtlety is that `Frame_Content_Size_flag == 0` means two different things. With
    /// the single-segment bit CLEAR it means the field is absent. With it SET the field is
    /// mandatory and the flag instead selects a ONE-byte width. Read as "0 means absent"
    /// in both cases -- the obvious reading -- the parser would not consume that byte, the
    /// first block header would be read starting one byte early, and the frame would
    /// desynchronize.
    ///
    /// So this asserts the property directly rather than reasoning about the branch: for
    /// every content-size flag, a single-segment frame yields `Some`, and the window it
    /// produces equals the declared size. The `unwrap_or` is then provably unreachable and
    /// stays only as an invariant backstop.
    ///
    /// The frame is hand-built rather than borrowed from the reference, and the obvious
    /// reason is wrong twice over. It is tempting to say `zstd` "only emits single-segment
    /// frames for small inputs and never at the widths above 1". Measured: from a PIPE it
    /// never emits them at any size, and from a FILE it emits them at all three widths --
    /// 10 bytes gives descriptor 0x24, 1,000 gives 0x64, 300,000 gives 0xa4. Both halves
    /// of that sentence are assumptions about a program that is sitting right there.
    ///
    /// The real reason to hand-build is the 8-BYTE width, which the reference does not
    /// reach without an input this suite has no business creating, and control over the
    /// declared size independent of the payload. The reference's own single-segment frames
    /// are exercised separately, in
    /// `the_reference_single_segment_frames_decode_at_every_content_size_width`.
    /// Here the reference is used the other way round: it must accept the frame, which is
    /// what makes this a test of the format rather than of my own reading of it.
    #[test]
    fn a_single_segment_frame_always_declares_its_size_and_that_size_is_the_window() {
        // (flag, width, payload length) -- the four legal single-segment encodings, each
        // carrying a size its field can actually hold. The 1-byte form tops out at 255,
        // and the 2-byte form is stored MINUS 256 so it cannot express anything smaller
        // than that; a single length for all four underflows, which is how the first draft
        // of this arm failed.
        for (flag, width, len) in [
            (0u8, 1usize, 200usize),
            (1, 2, 1000),
            (2, 4, 1000),
            (3, 8, 1000),
        ] {
            let payload: Vec<u8> = b"single-segment frames put the whole thing in one block. "
                .iter()
                .copied()
                .cycle()
                .take(len)
                .collect();
            let stored = if width == 2 {
                payload.len() as u64 - 256
            } else {
                payload.len() as u64
            };

            let mut frame = MAGIC.to_le_bytes().to_vec();
            frame.push((flag << 6) | (1 << 5)); // single-segment set, no checksum, no dict
            frame.extend_from_slice(&stored.to_le_bytes()[..width]);
            // One RAW block, last. The layout is Last_Block in bit 0, Block_Type in bits
            // 1-2, Block_Size in bits 3 and up -- so `| 1` sets the LAST flag and leaves
            // the type at 0, which is Raw. It is easy to misread `| 1` as selecting type 1
            // (RLE) and call this arm mislabeled; the bit that decides is not that one. It
            // is pinned rather than argued, twice over: the assertion
            // below reads the type field back, and the reference decodes these frames to
            // the multi-byte `payload` -- which an RLE block, being one byte repeated,
            // could not produce.
            let header = ((payload.len() as u32) << 3) | 1;
            assert_eq!(
                (header >> 1) & 0b11,
                0,
                "block type must be Raw (0), not RLE (1)"
            );
            assert_eq!(header & 1, 1, "last-block flag must be set");
            frame.extend_from_slice(&header.to_le_bytes()[..3]);
            frame.extend_from_slice(&payload);

            // The header parser must have CONSUMED the size field ...
            let (size, header_len, _checksum, block_max, window) = read_frame_header(&frame)
                .unwrap_or_else(|e| panic!("flag {flag}: header refused: {e}"));
            assert_eq!(
                size,
                Some(payload.len() as u64),
                "flag {flag}: the content size was not read"
            );
            assert_eq!(
                header_len,
                5 + width,
                "flag {flag}: the parser consumed {header_len} bytes, not {}",
                5 + width
            );
            // ... and the window must be that size, which is the bound the fallback would lose
            assert_eq!(
                window,
                payload.len() as u64,
                "flag {flag}: a single-segment window is its content size"
            );
            assert_eq!(
                block_max,
                payload.len(),
                "flag {flag}: block_max must follow the window, not the absolute cap"
            );

            // and the frame must decode, which is what proves the byte count above is not
            // merely self-consistent with a wrong parser
            assert_eq!(
                decompress(&frame, 4096).unwrap_or_else(|e| panic!("flag {flag}: {e}")),
                payload,
                "flag {flag}"
            );

            // THE CONTROL the reference supplies: if my hand-built frame were malformed,
            // every assertion above could pass against a decoder that shares my mistake.
            if have_reference() {
                let back = reference(&["-d", "-c"], &frame).unwrap_or_else(|| {
                    panic!("flag {flag}: the reference refused a frame this decoder accepted")
                });
                assert_eq!(
                    back, payload,
                    "flag {flag}: the reference read it differently"
                );
            }
        }

        // THE 128 KiB CAP, which every case above leaves untested. All four payloads are
        // smaller than `MAX_BLOCK`, so `min(window, 128 KiB)` is just
        // `window` and the arm would pass on a `block_max = window` assignment with the cap
        // deleted. One frame above the cap settles it.
        {
            let big = 200_000u64; // > MAX_BLOCK, so the cap must bite
            let mut frame = MAGIC.to_le_bytes().to_vec();
            frame.push((2 << 6) | (1 << 5)); // single-segment, 4-byte content size
            frame.extend_from_slice(&(big as u32).to_le_bytes());
            let (size, header_len, _c, block_max, window) =
                read_frame_header(&frame).expect("header");
            assert_eq!(size, Some(big));
            assert_eq!(header_len, 9);
            assert_eq!(
                window, big,
                "a single-segment window is its content size, uncapped"
            );
            assert_eq!(
                block_max, MAX_BLOCK,
                "block_max must be min(window, 128 KiB); with a {big}-byte window it is the CAP \
                 that decides, and this is the only case here where the two differ"
            );
        }

        // THE OTHER HALF: with single-segment CLEAR, flag 0 really does mean absent, and
        // the byte after the descriptor is the window descriptor instead. Without this the
        // arm above would also pass on a parser that consumed a size byte unconditionally.
        let mut frame = MAGIC.to_le_bytes().to_vec();
        frame.push(0); // no single-segment, flag 0 => no content size
        frame.push(0); // window descriptor: exponent 0, mantissa 0 => 1 KiB
        let payload = b"no content size here".to_vec();
        let header = ((payload.len() as u32) << 3) | 1;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(&payload);
        let (size, header_len, _c, block_max, window) = read_frame_header(&frame).expect("header");
        assert_eq!(
            size, None,
            "flag 0 without single-segment means the size really is absent"
        );
        assert_eq!(
            header_len, 6,
            "descriptor plus window descriptor, and no size field"
        );
        assert_eq!(window, 1024, "exponent 0, mantissa 0 is a 1 KiB window");
        assert_eq!(block_max, 1024);
        assert_eq!(decompress(&frame, 4096).expect("decodes"), payload);

        if have_reference() {
            assert_eq!(
                reference(&["-d", "-c"], &frame).expect("the reference must read it"),
                payload
            );
        } else {
            eprintln!("SKIP: /usr/bin/zstd is not installed; the reference half was NOT measured");
        }
    }

    /// THE COVERAGE COUNTER ITSELF, run as an experiment rather than trusted.
    ///
    /// The arm above rests on `fse::seen::calls() > 0` meaning "this sweep entered the
    /// interleaved decoder". That instrument deserves as much suspicion as the code it
    /// measures: an instrument that cannot fail proves nothing, and this one is asked to
    /// prove a NEGATIVE went away.
    ///
    /// The experiment: run the assertion twice on one thread, the first entering the
    /// decoder and the second not, with a reset between, and see whether the second still
    /// passes. That is what this does, and it is the control the house rule asks for: if
    /// the counter were stuck on, or inherited, or incremented by something other than the
    /// interleaved decoder, the `== 0` half would fail.
    ///
    /// Replacing the thread-local with a process-global `AtomicUsize` would be WORSE here
    /// rather than better. The test harness
    /// runs arms concurrently on several threads; a global counter would be incremented by
    /// whatever else happens to be decoding at the same moment, and a `reset()` in one arm
    /// would zero another arm's evidence mid-flight. Thread-local is right BECAUSE this
    /// decoder never spawns -- every `decode_interleaved` for a given `decompress` runs on
    /// the caller's thread.
    ///
    /// **That has one sharp edge.** If decoding ever moved to
    /// worker threads, the `== 0` half would pass VACUOUSLY -- the parent would see zero
    /// because the work happened elsewhere, not because the path was avoided, and that is
    /// a quiet failure rather than a loud one. It is harmless here only because the `> 0`
    /// half runs FIRST, on the same thread, and would fail before the vacuous pass could be
    /// reached. So the ordering is load-bearing: do not reorder these two halves, and do
    /// not drop the `> 0` half as redundant with the sweep's.
    #[test]
    fn the_coverage_counter_can_report_zero_and_therefore_means_something() {
        if !have_reference() {
            eprintln!("SKIP: /usr/bin/zstd is not installed; this was NOT measured");
            return;
        }

        // A corpus the reference FSE-codes the Huffman weights for -- compressible, but
        // over a wide alphabet. Same recipe as the sweep's skewed family.
        let mut st = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut wide = Vec::with_capacity(60_000);
        while wide.len() < 60_000 {
            let r = (rnd() % 1000) as usize;
            let idx = if r < 500 { r % 4 } else { r % 200 };
            wide.push((idx * 251 % 256) as u8);
        }

        // ARM: a reference frame that does reach the interleaved decoder.
        fse::seen::reset();
        let theirs = reference(&["-19", "-c"], &wide).expect("the reference must compress");
        assert_eq!(
            decompress(&theirs, wide.len() + 1024).expect("a reference frame must decode"),
            wide
        );
        let entered = fse::seen::calls();
        assert!(
            entered > 0,
            "the corpus no longer produces FSE-coded weights, so this control has no subject"
        );
        // `shortest` moving off its sentinel is a second, independent witness that the
        // decoder really ran here rather than the counter being nudged from somewhere else.
        assert_ne!(
            fse::seen::shortest(),
            usize::MAX,
            "calls moved but shortest did not, so the two disagree about whether the decoder ran"
        );

        // CONTROL, on the SAME thread, immediately after: reset, then decode something
        // that cannot reach it. This encoder writes direct weight tables only -- that is a
        // documented property of the encoder, and here it is the lever that produces a
        // guaranteed zero.
        fse::seen::reset();
        let ours = compress(&wide);

        // AND THE ZERO HAS TO MEAN THE RIGHT THING. `calls() == 0` is also what you get
        // from a raw or RLE block, or from any decode that returns before reaching the
        // literals at all. Without this the control would pass on a
        // frame that never had a Huffman table to code, which proves nothing about weight
        // tables. So the frame is required to actually carry a COMPRESSED block.
        let (_, hdr_len, _, _, _) = read_frame_header(&ours).expect("our own header");
        let bh = u32::from_le_bytes([ours[hdr_len], ours[hdr_len + 1], ours[hdr_len + 2], 0]);
        assert_eq!(
            (bh >> 1) & 0b11,
            2,
            "this control needs a COMPRESSED first block; a raw or RLE one would give the \
             same zero for a reason that has nothing to do with weight tables"
        );

        assert_eq!(
            decompress(&ours, wide.len() + 1024).expect("our own frame must decode"),
            wide
        );
        assert_eq!(
            fse::seen::calls(),
            0,
            "the counter reported {} entries into the interleaved decoder while decoding a \
             frame from an encoder that never FSE-codes its weight table. Either the counter \
             is inherited rather than reset, or it is being incremented by something that is \
             not that decoder -- in both cases the sweep's `calls > 0` is worthless",
            fse::seen::calls()
        );
        assert_eq!(
            fse::seen::shortest(),
            usize::MAX,
            "shortest survived a reset, so it inherits too"
        );

        eprintln!("coverage counter: {entered} entries on a reference frame, 0 on one of ours, across one thread");
    }

    /// The limit is enforced before the bytes are produced, not after.
    #[test]
    fn a_frame_cannot_decode_past_the_callers_limit() {
        let f = compress(&vec![3u8; 100_000]);
        let e = decompress(&f, 1000).expect_err("a frame larger than the limit must be refused");
        assert!(e.to_string().contains("allows"), "{e}");
        // THE CONTROL: the same frame inside a limit that admits it decodes fine, so the
        // refusal above is the limit doing work rather than the frame being unreadable.
        assert_eq!(
            decompress(&f, 100_000)
                .expect("decodes inside the limit")
                .len(),
            100_000
        );
    }

    /// A frame whose declared content size disagrees with what its blocks produce is a
    /// refusal. A decoder that ignored the declaration would hand back a short buffer.
    #[test]
    fn a_lying_content_size_is_refused() {
        let mut f = compress(b"hello world");
        // the header is magic(4) + descriptor(1) + 1-byte size for this length
        let size_at = 5;
        assert_eq!(
            f[size_at], 11,
            "the fixture assumes a 1-byte content size field"
        );
        f[size_at] = 12;
        let e =
            decompress(&f, 100).expect_err("a content size that does not match must be refused");
        assert!(e.to_string().contains("different length"), "{e}");
    }

    #[test]
    fn a_frame_that_is_not_a_frame_is_refused_by_name() {
        let e = decompress(b"not a zstd frame at all", 100).expect_err("must refuse");
        assert!(e.to_string().contains("magic"), "{e}");
        let e = decompress(b"ab", 100).expect_err("must refuse");
        assert!(e.to_string().contains("shorter"), "{e}");
    }
}
