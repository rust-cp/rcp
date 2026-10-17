//! DEFLATE (RFC 1951) and the gzip container (RFC 1952), decode side, in the standard
//! library alone -- so `tar://` can read a `.tar.gz` that `gzip`, `pigz` and `tar` wrote
//! without this crate growing a dependency.
//!
//! The decoder is the half that is worth having first and on its own. Reading a `.tar.gz`
//! is the common case (an OCI layer, a release tarball, anything a colleague sent), it is
//! the half that can be tested against artifacts this machine's own `gzip` produced, and
//! it is a hard requirement for the parallel-decode work that follows -- a pigz `-i`
//! stream is a sequence of independently-decodable members, which cannot be exploited
//! before a single member can be decoded at all.
//!
//! The Huffman decoder is the counts-and-symbols walk from Mark Adler's `puff.c` rather
//! than a lookup table. It is the slower of the two and the one whose correctness can be
//! read off the page: a canonical code is defined by how many codes share each length and
//! what order the symbols are in, and that is exactly what the two arrays hold. A table
//! decoder is a later optimization with the same observable behavior, and this file's
//! tests are what would keep it honest.
//!
//! What this does NOT do, deliberately, and each is a separate piece of work:
//! - encode. Writing DEFLATE is a different problem (match finding, block splitting) and
//!   the ordered parallel pipeline it feeds is its own item.
//! - zlib's container (RFC 1950). Two extra header bytes and Adler-32 instead of CRC-32;
//!   trivial to add once something needs it, and nothing here does.
//! - a streaming interface. `inflate` takes a whole member and returns a whole member,
//!   because the tar reader already holds a member in hand. A streaming decoder is not a
//!   refactor of this one -- it needs the bit reader to suspend -- so it is not pretended.

use std::io;

/// The longest Huffman code DEFLATE allows.
const MAXBITS: usize = 15;
/// Literal/length alphabet: 0..=255 literals, 256 end-of-block, 257..=285 lengths.
const MAXLCODES: usize = 286;
/// Distance alphabet.
const MAXDCODES: usize = 30;

/// `lengths[i]` is the bit length of symbol `i`; zero means the symbol is not used.
///
/// `count[n]` is how many symbols have length `n`, and `symbol` lists the symbols in
/// canonical order. Together those two are the whole of a canonical Huffman code.
struct Huffman {
    count: [u16; MAXBITS + 1],
    symbol: Vec<u16>,
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("deflate: {what}"))
}

impl Huffman {
    /// Builds the decoding tables from a list of code lengths.
    ///
    /// Refuses both an over-subscribed code (more codes than the length allows, which no
    /// valid stream contains and which would otherwise decode into whatever memory the
    /// symbol array happens to hold) and an incomplete one -- with ONE exception, which
    /// RFC 1951 requires: a distance code with a single symbol is legal, because a block
    /// may contain exactly one distance. An encoder that emits no distances at all leaves
    /// the whole alphabet unused, which is also legal and is handled above.
    ///
    /// **THE SECOND HALF IS THE ONE THAT IS EASY TO LEAVE OUT.** `puff.c` has both arms of
    /// the Kraft walk; a walk that tests only `left < 0`, with no `left > 0` arm, reads like
    /// a port of it and accepts every incomplete code. A comment describing the check is
    /// not the check, which is the whole argument for running a check rather than reading
    /// one.
    ///
    /// The consequence is not memory safety -- the symbol lookup stays inside the filled
    /// prefix either way -- it is DIFFERENTIAL PARSING, which for a copy tool is worse. A
    /// hand-built `.tar.gz` whose literal code is unambiguous but does not fill Kraft's
    /// inequality measures:
    ///
    /// | reader | verdict |
    /// | --- | --- |
    /// | `tar -tzf` | `invalid compressed data--format violated` |
    /// | `gunzip -c` | `invalid compressed data--format violated` |
    /// | python `gzip` | `Error -3 ... invalid literal/lengths set` |
    /// | a decoder without the `left > 0` arm | **accepted, 10240 bytes, a readable tar with a payload in it** |
    ///
    /// So an archive that a scanner, a CI gate or an operator running `gunzip -t` sees as
    /// corrupt and empty is one such a decoder extracts and writes to the destination.
    /// A mover must not see content its own ecosystem's verification cannot.
    fn new(lengths: &[u8]) -> io::Result<Huffman> {
        let mut count = [0u16; MAXBITS + 1];
        for &l in lengths {
            if l as usize > MAXBITS {
                return Err(bad("a code length above 15"));
            }
            count[l as usize] += 1;
        }
        if count[0] as usize == lengths.len() {
            // every symbol unused: a legal, and empty, code
            return Ok(Huffman {
                count,
                symbol: Vec::new(),
            });
        }
        // Kraft's inequality, walked one length at a time. `left` is how many codes of the
        // current length are still available; going negative means over-subscribed.
        let mut left: i32 = 1;
        for len in 1..=MAXBITS {
            left <<= 1;
            left -= i32::from(count[len]);
            if left < 0 {
                return Err(bad("an over-subscribed Huffman code"));
            }
        }
        // and the other half of Kraft, which is what `puff.c` calls "incomplete but not
        // simple". `left > 0` means the code does not fill its space, so some bit patterns
        // decode to nothing -- a stream every other DEFLATE reader refuses. The exemption
        // is RFC 1951's: ONE code of length 1 is a legal distance alphabet for a block
        // with a single distance, and leaves exactly `1 << (MAXBITS - 1)` unused.
        if left > 0 && !(count[1] == 1 && left == 1 << (MAXBITS - 1)) {
            return Err(bad("an incomplete Huffman code"));
        }
        let mut offs = [0u16; MAXBITS + 2];
        for len in 1..=MAXBITS {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huffman { count, symbol })
    }
}

/// A least-significant-bit-first bit reader over a byte slice, which is the order DEFLATE
/// packs Huffman codes and extra bits in.
struct Bits<'a> {
    data: &'a [u8],
    /// Index of the next byte to pull into `val`.
    at: usize,
    /// Bits not yet consumed, right-aligned.
    val: u32,
    /// How many of `val`'s low bits are valid.
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            at: 0,
            val: 0,
            cnt: 0,
        }
    }

    /// `need` bits, LSB first. `need` is never more than 13 in DEFLATE.
    fn take(&mut self, need: u32) -> io::Result<u32> {
        while self.cnt < need {
            let Some(&b) = self.data.get(self.at) else {
                return Err(bad("the stream ends in the middle of a block"));
            };
            self.at += 1;
            self.val |= u32::from(b) << self.cnt;
            self.cnt += 8;
        }
        let out = self.val & ((1u32 << need) - 1);
        self.val >>= need;
        self.cnt -= need;
        Ok(out)
    }

    /// Drops the remainder of the current byte, which a stored block is aligned to.
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.val >>= drop;
        self.cnt -= drop;
    }

    /// One Huffman symbol.
    ///
    /// Walks the code one bit at a time, tracking the first code of the current length and
    /// where its symbols start. A canonical code makes that comparison enough: if the code
    /// read so far minus the first code of this length is inside this length's count, the
    /// symbol is at that offset.
    fn symbol(&mut self, h: &Huffman) -> io::Result<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAXBITS {
            code |= self.take(1)? as i32;
            let count = i32::from(h.count[len]);
            if code - first < count {
                let i = (index + (code - first)) as usize;
                return h
                    .symbol
                    .get(i)
                    .copied()
                    .ok_or_else(|| bad("a Huffman code with no symbol"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(bad("a Huffman code longer than 15 bits"))
    }
}

/// Length code 257..=285: the base length and how many extra bits follow.
const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Distance code 0..=29.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order the code-length code's own lengths arrive in, which is not 0..18.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Literal/length codes in the FIXED code: 288, not the 286 a dynamic block may declare.
///
/// The two are different numbers for a reason and conflating them was a real defect here.
/// HLIT in a dynamic block ranges over 257..=286, because 286 and 287 encode nothing. The
/// fixed code of RFC 1951 3.2.6 nevertheless assigns both a length of 8, and it has to:
/// without them the code sums to 254/256 and is INCOMPLETE, so two of every 256 eight-bit
/// patterns decode to no symbol at all.
///
/// Building the fixed table at 286 was invisible until `Huffman::new` started checking
/// Kraft's inequality, and then `gzip -9` of an empty file -- a single fixed block holding
/// nothing but end-of-block -- stopped decoding. That is the measurement: the tree was
/// malformed the whole time and nothing said so, because an incomplete code only misbehaves
/// on the patterns it fails to cover.
const FIXLCODES: usize = 288;

/// The fixed code of RFC 1951 3.2.6, built once per block that uses it.
fn fixed() -> io::Result<(Huffman, Huffman)> {
    let mut lit = [0u8; FIXLCODES];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    // Every distance is five bits, including the two codes (30, 31) that no valid stream
    // uses -- the RFC defines the code over all 32 so that it is complete.
    let dist = [5u8; 32];
    Ok((Huffman::new(&lit)?, Huffman::new(&dist)?))
}

/// The dynamic code of RFC 1951 3.2.7: a code-length code, which then encodes the
/// literal/length and distance code lengths.
fn dynamic(b: &mut Bits<'_>) -> io::Result<(Huffman, Huffman)> {
    let nlen = b.take(5)? as usize + 257;
    let ndist = b.take(5)? as usize + 1;
    let ncode = b.take(4)? as usize + 4;
    if nlen > MAXLCODES || ndist > MAXDCODES {
        return Err(bad("too many length or distance codes"));
    }
    let mut clens = [0u8; 19];
    for &slot in CLEN_ORDER.iter().take(ncode) {
        clens[slot] = b.take(3)? as u8;
    }
    let clen = Huffman::new(&clens)?;

    let mut lengths = vec![0u8; nlen + ndist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = b.symbol(&clen)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            // 16 repeats the PREVIOUS length 3..=6 times, so it cannot be the first symbol
            16 => {
                let Some(&prev) = i.checked_sub(1).and_then(|p| lengths.get(p)) else {
                    return Err(bad(
                        "a repeat of the previous length with no previous length",
                    ));
                };
                let n = 3 + b.take(2)? as usize;
                if i + n > lengths.len() {
                    return Err(bad("a repeat that runs past the end of the lengths"));
                }
                lengths[i..i + n].fill(prev);
                i += n;
            }
            // 17 and 18 repeat a ZERO, so they have no such precondition
            17 | 18 => {
                let n = if sym == 17 {
                    3 + b.take(3)? as usize
                } else {
                    11 + b.take(7)? as usize
                };
                if i + n > lengths.len() {
                    return Err(bad("a run of zero lengths that runs past the end"));
                }
                lengths[i..i + n].fill(0);
                i += n;
            }
            _ => return Err(bad("a code-length symbol above 18")),
        }
    }
    if lengths[256] == 0 {
        return Err(bad("a block with no end-of-block code"));
    }
    Ok((
        Huffman::new(&lengths[..nlen])?,
        Huffman::new(&lengths[nlen..])?,
    ))
}

/// One Huffman-coded block, literals and matches, appended to `out`.
fn block(
    b: &mut Bits<'_>,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
    limit: usize,
) -> io::Result<()> {
    loop {
        let sym = b.symbol(lit)?;
        match sym {
            0..=255 => {
                if out.len() >= limit {
                    return Err(bad("the decoded stream is larger than the limit"));
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let i = sym as usize - 257;
                let len = LEN_BASE[i] as usize + b.take(u32::from(LEN_EXTRA[i]))? as usize;
                let dsym = b.symbol(dist)? as usize;
                if dsym >= DIST_BASE.len() {
                    // codes 30 and 31 exist in the fixed code and are invalid in a stream
                    return Err(bad("a distance code that no valid stream uses"));
                }
                let d = DIST_BASE[dsym] as usize + b.take(u32::from(DIST_EXTRA[dsym]))? as usize;
                if d > out.len() {
                    return Err(bad("a match that reaches before the start of the output"));
                }
                if out.len() + len > limit {
                    return Err(bad("the decoded stream is larger than the limit"));
                }
                // Byte at a time, and NOT `extend_from_within`: a match may overlap its own
                // output (`d` of 1 with a length of 100 is a run of one byte), which is how
                // DEFLATE encodes runs and which a bulk copy would get wrong.
                let start = out.len() - d;
                for k in 0..len {
                    out.push(out[start + k]);
                }
            }
            _ => return Err(bad("a literal/length symbol above 285")),
        }
    }
}

/// The default ceiling on a decoded member: 4 GiB.
///
/// A compressed stream can expand by roughly 1032:1, so a few megabytes of input can ask
/// for terabytes of memory -- the "zip bomb" shape. The caller that knows the expected
/// size should pass it; this is what a caller that does not know gets.
///
/// **No caller in this crate passes it, and that is deliberate rather than an oversight to
/// be re-found.** The one production consumer of this module is
/// `tar::client`, which knows what it is decoding and passes its own `MAX_EXPANDED`. This
/// constant exists for a caller that does NOT know -- a library user, or a future command
/// that decompresses something a user named -- and deleting it would mean the next such
/// caller invents a number instead of taking one with this reasoning attached.
pub const DEFAULT_LIMIT: usize = 4 << 30;

/// Decodes a raw DEFLATE stream.
///
/// `limit` bounds the OUTPUT, not the input, because that is the direction that grows.
pub fn inflate(data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let mut b = Bits::new(data);
    let mut out = Vec::new();
    loop {
        let last = b.take(1)? == 1;
        match b.take(2)? {
            // stored: byte-aligned, a length and its one's complement, then raw bytes
            0 => {
                b.align();
                if b.at + 4 > b.data.len() {
                    return Err(bad("a stored block with no length"));
                }
                let len = u16::from_le_bytes([b.data[b.at], b.data[b.at + 1]]) as usize;
                let nlen = u16::from_le_bytes([b.data[b.at + 2], b.data[b.at + 3]]) as usize;
                if len != !nlen & 0xffff {
                    return Err(bad("a stored block whose length and complement disagree"));
                }
                b.at += 4;
                if b.at + len > b.data.len() {
                    return Err(bad("a stored block that runs past the end of the stream"));
                }
                if out.len() + len > limit {
                    return Err(bad("the decoded stream is larger than the limit"));
                }
                out.extend_from_slice(&b.data[b.at..b.at + len]);
                b.at += len;
                // the bit buffer held only the alignment padding, which align() dropped
                b.val = 0;
                b.cnt = 0;
            }
            1 => {
                let (lit, dist) = fixed()?;
                block(&mut b, &lit, &dist, &mut out, limit)?;
            }
            2 => {
                let (lit, dist) = dynamic(&mut b)?;
                block(&mut b, &lit, &dist, &mut out, limit)?;
            }
            _ => return Err(bad("a reserved block type")),
        }
        if last {
            return Ok(out);
        }
    }
}

/// CRC-32 as gzip uses it: the reflected polynomial, table-free.
///
/// Table-free because the table is 1 KiB of state to justify and this runs once per
/// member over bytes that were just decompressed -- the decompression dominates. If a
/// profile ever says otherwise, a table is a local change with the same output.
/// The CRC-32 table, built at compile time from the same polynomial the bit-at-a-time
/// loop used. A table is eight times less work per byte, which is the difference between
/// a checksum that can ride on a data path and one that cannot: `Squeeze` now checksums
/// every compressed payload, and at eight shifts a byte that would have put a ceiling of
/// a few hundred megabytes a second on a compressed stream.
const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xedb8_8320 & mask);
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

const CRC_TABLE: [u32; 256] = crc_table();

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc = CRC_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// What a gzip member's header said about the file it holds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GzipHeader {
    /// The original name, if the writer stored one. `gzip` stores it; `tar -z` does not.
    pub name: Option<String>,
    /// Modification time as gzip records it: seconds since the epoch, zero for none.
    pub mtime: u32,
}

/// Decodes ONE gzip member and returns its bytes, its header, and how many input bytes it
/// consumed -- so a caller can walk a multi-member stream, which is what `pigz` writes and
/// what `cat a.gz b.gz` produces.
///
/// The CRC-32 and the length in the trailer are both checked. They are the only thing that
/// distinguishes a correct decode from a plausible one, so they are not optional and there
/// is no flag to skip them.
pub fn gunzip_member(data: &[u8], limit: usize) -> io::Result<(Vec<u8>, GzipHeader, usize)> {
    if data.len() < 18 {
        return Err(bad("a gzip member shorter than its own header and trailer"));
    }
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err(bad("not a gzip member (no 1f 8b magic)"));
    }
    if data[2] != 8 {
        return Err(bad("a gzip member that is not deflate-compressed"));
    }
    let flg = data[3];
    if flg & 0xe0 != 0 {
        return Err(bad("a gzip member with reserved flag bits set"));
    }
    let mtime = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut at = 10;
    // FEXTRA
    if flg & 0x04 != 0 {
        if at + 2 > data.len() {
            return Err(bad("a truncated extra field"));
        }
        let xlen = u16::from_le_bytes([data[at], data[at + 1]]) as usize;
        at += 2 + xlen;
        if at > data.len() {
            return Err(bad("an extra field that runs past the end"));
        }
    }
    // FNAME and FCOMMENT are NUL-terminated
    let zstring = |at: &mut usize| -> io::Result<Vec<u8>> {
        let start = *at;
        while *at < data.len() && data[*at] != 0 {
            *at += 1;
        }
        if *at >= data.len() {
            return Err(bad("a header string with no terminator"));
        }
        let s = data[start..*at].to_vec();
        *at += 1;
        Ok(s)
    };
    let mut name = None;
    if flg & 0x08 != 0 {
        // Lossy on purpose: gzip says ISO-8859-1 and real files carry anything. A name
        // that does not decode must not fail a member whose BYTES are fine.
        name = Some(String::from_utf8_lossy(&zstring(&mut at)?).into_owned());
    }
    if flg & 0x10 != 0 {
        zstring(&mut at)?;
    }
    if flg & 0x02 != 0 {
        at += 2; // header CRC16, not checked: the whole-member CRC32 below covers more
        if at > data.len() {
            return Err(bad("a truncated header CRC"));
        }
    }
    if at + 8 > data.len() {
        return Err(bad("a gzip member with no room for its trailer"));
    }
    // The deflate stream runs to 8 bytes before the end of what we were given. A caller
    // walking a multi-member stream does not know where the member ends until it is
    // decoded, so `inflate` is told the rest and reports back how much it used.
    let body = &data[at..];
    let mut b = Bits::new(body);
    let out = inflate_from(&mut b, limit)?;
    // round up to the next byte boundary: the trailer is byte-aligned
    let used = b.at;
    let trailer_at = at + used;
    if trailer_at + 8 > data.len() {
        return Err(bad(
            "a gzip member whose trailer is past the end of the stream",
        ));
    }
    let want_crc = u32::from_le_bytes([
        data[trailer_at],
        data[trailer_at + 1],
        data[trailer_at + 2],
        data[trailer_at + 3],
    ]);
    let want_len = u32::from_le_bytes([
        data[trailer_at + 4],
        data[trailer_at + 5],
        data[trailer_at + 6],
        data[trailer_at + 7],
    ]);
    let got = crc32(&out);
    if got != want_crc {
        return Err(bad(&format!(
            "the member's CRC-32 is {got:08x} and its trailer says {want_crc:08x}"
        )));
    }
    // ISIZE is the length modulo 2^32, which is what the format stores; comparing the
    // truncated value is the check the format supports, not a weaker version of one.
    if (out.len() as u32) != want_len {
        return Err(bad(&format!(
            "the member holds {} bytes and its trailer says {want_len}",
            out.len()
        )));
    }
    Ok((out, GzipHeader { name, mtime }, trailer_at + 8))
}

/// `inflate`, but over a bit reader the caller keeps, so it can see where the stream
/// stopped. That position is what lets a gzip member be found inside a longer buffer.
fn inflate_from(b: &mut Bits<'_>, limit: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let last = b.take(1)? == 1;
        match b.take(2)? {
            0 => {
                b.align();
                if b.at + 4 > b.data.len() {
                    return Err(bad("a stored block with no length"));
                }
                let len = u16::from_le_bytes([b.data[b.at], b.data[b.at + 1]]) as usize;
                let nlen = u16::from_le_bytes([b.data[b.at + 2], b.data[b.at + 3]]) as usize;
                if len != !nlen & 0xffff {
                    return Err(bad("a stored block whose length and complement disagree"));
                }
                b.at += 4;
                if b.at + len > b.data.len() {
                    return Err(bad("a stored block that runs past the end of the stream"));
                }
                if out.len() + len > limit {
                    return Err(bad("the decoded stream is larger than the limit"));
                }
                out.extend_from_slice(&b.data[b.at..b.at + len]);
                b.at += len;
                b.val = 0;
                b.cnt = 0;
            }
            1 => {
                let (lit, dist) = fixed()?;
                block(b, &lit, &dist, &mut out, limit)?;
            }
            2 => {
                let (lit, dist) = dynamic(b)?;
                block(b, &lit, &dist, &mut out, limit)?;
            }
            _ => return Err(bad("a reserved block type")),
        }
        if last {
            // The trailer is byte-aligned, so whole bytes still sitting in the bit buffer
            // have not been consumed and must be given back.
            b.at -= (b.cnt / 8) as usize;
            return Ok(out);
        }
    }
}

/// Every member of a gzip stream, concatenated.
///
/// `cat a.gz b.gz > both.gz` is a legal gzip file holding both, and `pigz -i` writes one
/// member per block for exactly this reason. Stopping at the first member would silently
/// return a PREFIX of the data -- the quiet-truncation shape -- so the whole stream is
/// walked and trailing bytes that are not a member are an error rather than an end.
pub fn gunzip(data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    // An EMPTY input is not an empty archive. The loop below never runs on one, so this
    // returned `Ok(vec![])` -- the same answer as a real gzip member holding nothing, and
    // indistinguishable from it. `tar://` reads that as "an archive with no members",
    // which is the exact silent-empty-copy shape the gzip decode was added to stop: a
    // truncated download, a zero-length file, a read that returned nothing all became a
    // successful copy of no files.
    if data.is_empty() {
        return Err(bad("an empty input is not a gzip stream"));
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        // A gzip stream may be padded with zero bytes, which `gzip` itself ignores.
        // Trailing zero padding is legal only after a real member. An all-zero
        // buffer has no member; treating it as padding returned an empty payload.
        if at > 0 && data[at..].iter().all(|&b| b == 0) {
            break;
        }
        let (bytes, _, used) = gunzip_member(&data[at..], limit.saturating_sub(out.len()))?;
        out.extend_from_slice(&bytes);
        if used == 0 {
            return Err(bad("a gzip member that consumed no input"));
        }
        at += used;
    }
    Ok(out)
}

/// How many candidates the parallel decode speculatively inflated, and how many of those
/// the chain then used.
///
/// Counted rather than inferred, because the whole design falls back to the serial path on
/// anything surprising -- so an arm asserting "the output is identical at 8 workers" passes
/// perfectly while the parallel path is never entered at all. That is the shape of a test
/// that measures nothing, and this is what tells them apart.
#[cfg(test)]
pub(crate) mod speculated {
    use std::cell::Cell;
    thread_local! {
        static TRIED: Cell<u64> = const { Cell::new(0) };
        static USED: Cell<u64> = const { Cell::new(0) };
    }
    pub fn reset() {
        TRIED.with(|c| c.set(0));
        USED.with(|c| c.set(0));
    }
    pub fn note_tried(n: u64) {
        TRIED.with(|c| c.set(c.get() + n));
    }
    pub fn note_used() {
        USED.with(|c| c.set(c.get() + 1));
    }
    /// `(candidates inflated, of those the chain used)`
    pub fn count() -> (u64, u64) {
        (TRIED.with(Cell::get), USED.with(Cell::get))
    }
}

#[cfg(test)]
fn note_tried(n: u64) {
    speculated::note_tried(n);
}
#[cfg(not(test))]
#[inline(always)]
fn note_tried(_n: u64) {}

#[cfg(test)]
fn note_used() {
    speculated::note_used();
}
#[cfg(not(test))]
#[inline(always)]
fn note_used() {}

/// The same, on `workers` threads. `0` or `1` is exactly `gunzip`.
///
/// **A gzip member does not say how long it is.** Its compressed length is only known once
/// it has been inflated, so the boundaries of a multi-member stream form a chain that
/// looks irreducibly serial: to know where member 2 starts you must finish member 1.
///
/// What breaks the chain is that member starts are FINDABLE, if not decidable. Every one
/// begins `1f 8b`, so a scan gives candidates; a candidate that is not a member is one
/// whose bytes merely happen to look like a header. Measured on an 18.6 MB archive of
/// 83 MB of log text written by this crate:
///
/// ```text
/// magic occurrences  367
/// survive the header check (CM == 8, no reserved flag bits)   22
/// real members                                                21
/// ```
///
/// So the cheap filter removes 94% of the noise and leaves ONE false survivor. That ratio
/// is what makes speculation affordable: the pool inflates every surviving candidate, and
/// the waste is the one that is not a member.
///
/// **The chain, not the speculation, decides the output.** Results are collected by offset;
/// then the member list is walked exactly as `gunzip` walks it -- start at 0, take that
/// member's consumed length, look for a result at the offset it lands on, inflate on
/// demand if there is none -- and only members ON that chain are concatenated. A false
/// candidate can therefore never enter the output, whatever it decoded to: it is simply an
/// offset the chain never visits. Speculation can waste work. It cannot change the answer.
///
/// Anything unexpected -- a chain step that fails, a stream that does not end where the
/// data does -- falls back to the serial path for the remainder rather than guessing.
pub fn gunzip_with(data: &[u8], limit: usize, workers: usize) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(bad("an empty input is not a gzip stream"));
    }
    // The gate is the CANDIDATE COUNT, not a size.
    //
    // It was `data.len() < 2 * GZIP_BLOCK` first, and that is wrong in the way that is
    // hardest to see: `data` is the COMPRESSED stream, so five 4 MiB members of ordinary
    // text -- which compress to well under 8 MiB together -- fell under the threshold and
    // went serial. Every equality assertion still passed, at every worker count, because
    // the serial path is what they were comparing against. The counter beside them is what
    // said so.
    //
    // `SCAN_FLOOR` is only there so a tiny file does not pay for a scan it cannot use; the
    // scan itself is one linear pass and the real question is whether there is more than
    // one member to share out.
    const SCAN_FLOOR: usize = 128 << 10;
    if workers <= 1 || data.len() < SCAN_FLOOR {
        return gunzip(data, limit);
    }

    // 1. candidates: the magic, then the header checks that cost nothing
    let mut candidates: Vec<usize> = Vec::new();
    let mut at = 0usize;
    while at + 18 <= data.len() {
        if data[at] == 0x1f && data[at + 1] == 0x8b && data[at + 2] == 8 && data[at + 3] & 0xe0 == 0
        {
            candidates.push(at);
        }
        at += 1;
    }
    // offset 0 must be one, or this is not a gzip stream at all and `gunzip` says so
    // better; and one candidate is one member, which has nothing to share out
    if candidates.first() != Some(&0) || candidates.len() < 2 {
        return gunzip(data, limit);
    }

    // 2. inflate every candidate, in parallel, speculatively
    note_tried(candidates.len() as u64);
    let decoded = inflate_candidates(data, &candidates, limit, workers);

    // 3. walk the chain; ONLY this decides what the output is
    let mut decoded = decoded;
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        if at > 0 && data[at..].iter().all(|&b| b == 0) {
            break;
        }
        let room = limit.saturating_sub(out.len());
        // `remove` rather than `get`: a member is on the chain once, and taking ownership
        // here is what stops the walk memcpying every member's output a second time.
        let (bytes, used) = match decoded.remove(&at) {
            Some(Ok((bytes, used))) if out.len() + bytes.len() <= limit => {
                note_used();
                (bytes, used)
            }
            // no speculative answer, one that overran the limit, or one that failed:
            // do it here, and let the error be the serial path's error
            _ => {
                let (bytes, _, used) = gunzip_member(&data[at..], room)?;
                (bytes, used)
            }
        };
        if used == 0 {
            return Err(bad("a gzip member that consumed no input"));
        }
        out.extend_from_slice(&bytes);
        at += used;
    }
    Ok(out)
}

/// Inflates each candidate offset on `workers` threads, keeping whatever came back.
///
/// Failures are KEPT rather than dropped, so the chain walk can tell "this candidate was
/// tried and is not a member" from "this offset was never a candidate" -- the two want
/// different handling and collapsing them re-inflates real members for no reason.
type Decoded = std::collections::BTreeMap<usize, io::Result<(Vec<u8>, usize)>>;

fn inflate_candidates(data: &[u8], candidates: &[usize], limit: usize, workers: usize) -> Decoded {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    // Peak memory is the sum of every candidate that DECODED, not just the ones the chain
    // keeps -- a false candidate's output sits in the map until this returns. Measured on
    // a real archive that costs nothing: 107 MiB peak serial against 108 MiB at 4 and 8
    // workers, because the chain walk takes ownership of each member as it goes, so the
    // map shrinks exactly as the output grows.
    //
    // A hostile archive is the question that number does not answer, and the honest answer
    // is that it is HARD to exploit rather than impossible: a hidden member has to survive
    // being embedded, which needs its containing block to be STORED, and anything
    // compressible enough to expand usefully tips that block towards being compressed
    // instead. Measured -- of 27 planted copies each of an 8 MiB-expanding member, a
    // 256 KiB member and a 1 MiB member, **none survived intact**; stored blocks also
    // carry a header every 64 KiB, which cuts any longer decoy in two.
    //
    // "Hard for an adversary" is not a bound, so here is one: speculation stops once the
    // decoded total passes `limit`, which is the ceiling this function was already given.
    // Whatever is missing, the chain inflates on demand, so correctness does not depend on
    // where the cap falls.
    let spent = Arc::new(AtomicU64::new(0));
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<(usize, io::Result<(Vec<u8>, usize)>)>();
    let mut out: Decoded = Decoded::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers.min(candidates.len()))
            .map(|_| {
                let (next, tx, spent) = (Arc::clone(&next), tx.clone(), Arc::clone(&spent));
                scope.spawn(move || loop {
                    if spent.load(Ordering::Relaxed) >= limit as u64 {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&off) = candidates.get(i) else { break };
                    let r = gunzip_member(&data[off..], limit).map(|(b, _, used)| (b, used));
                    if let Ok((b, _)) = &r {
                        spent.fetch_add(b.len() as u64, Ordering::Relaxed);
                    }
                    if tx.send((off, r)).is_err() {
                        break;
                    }
                })
            })
            .collect();
        drop(tx);
        // collected on THIS thread while the workers run, so a large archive does not
        // hold every member in a channel queue on top of the map
        for (off, r) in rx {
            out.insert(off, r);
        }
        for h in handles {
            let _ = h.join();
        }
    });
    out
}

/// Whether a buffer starts with the gzip magic, for a reader deciding how to open a file.
pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// ---------------------------------------------------------------------------
// ENCODE
// ---------------------------------------------------------------------------
//
// Writing DEFLATE, so `tar://` can produce a `.tar.gz` that `gzip`, `pigz` and `tar`
// accept rather than a plain tar under a `.gz` name.
//
// **That is what it did.** `TarTree::open` decompressed on read and, on create, simply
// wrote an uncompressed tar to whatever path it was given -- so `rcp copy /tree
// tar://out.tar.gz` produced a file whose name says gzip and whose content is not, and
// every consumer downstream of it (`tar -xzf`, an OCI tool, a colleague) got an error
// naming the wrong thing. The comment there said writing one "needs a DEFLATE encoder,
// which this crate does not have", which was true and is the reason this exists.
//
// FIXED Huffman blocks (RFC 1951 3.2.6), not dynamic. A fixed block uses the code every
// decoder already has built in, so there is no code table to emit and nothing to get
// wrong in the emitting; it costs a few percent of ratio against a dynamic block and
// buys a decoder-agnostic output whose correctness is checkable against the system
// `gzip` rather than argued. Dynamic blocks are a later, separate optimization with the
// same observable behavior, and the arms below are what would keep that honest.

/// The LZ77 window RFC 1951 allows, and the furthest back a match may reach.
const WINDOW: usize = 32 << 10;
/// `WINDOW - 1`: the ring index for `prev`, valid because `WINDOW` is a power of two.
const MASK: usize = WINDOW - 1;
/// The shortest and longest match the length codes can express.
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// How many earlier positions with the same 3-byte hash to try before taking the best so
/// far. Bounded because the chain is as long as the data is repetitive, and an unbounded
/// walk is quadratic on exactly the input compression is for.
/// 32, a measured compromise rather than a round number.
///
/// Swept with THIS encoder over the 400 KB narrow-alphabet corpus in the tests:
///
/// | chain | output | ratio |
/// | --- | --- | --- |
/// | 4 | 208,704 | 0.522 |
/// | 8 | 197,085 | 0.493 |
/// | 16 | 187,929 | 0.470 |
/// | 32 | 179,942 | 0.450 |
///
/// **"On ordinary input this knob does nothing" stood here and was measured on a corpus
/// that could not have shown otherwise.** The claim rested on an "English text" figure of
/// 3,669 bytes from 440,000 -- a ratio of 0.008, which should have been the tell. That
/// input was a 44-byte pangram repeated ten thousand times: after the first sentence every
/// position matches at distance 44, so chain depth cannot matter BY CONSTRUCTION. It was
/// not English, it was a loop.
///
/// Re-swept over 1,029,896 bytes of this crate's own source and prose, the knob moves:
///
/// | chain | output | ratio |
/// | --- | --- | --- |
/// | 4 | 415,367 | 0.4033 |
/// | 32 | 377,398 | 0.3664 |
/// | 128 | 372,694 | 0.3619 |
///
/// So 4 -> 32 is worth 9.2% on ordinary text and 32 -> 128 is worth a further 1.2% for
/// four times the work. The knee is real on both corpora even though the old reasoning
/// for it was not; this is a copy tool before it is a compressor, so it sits there.
/// Chain depth is the part that is nearly exhausted -- see
/// `the_match_chain_reaches_past_the_most_recent_candidate` for what is NOT: a stronger
/// SEARCH is worth about 11% beyond this, and the code table far more.
const MAX_CHAIN: usize = 32;

/// Take a match at least this long without spending a lookahead search on it.
///
/// Lazy matching searches EVERY position rather than every match, so on input that is
/// mostly matched it is several times the chain work of a greedy pass. This bounds that:
/// past 32 bytes the lookahead can only help by finding something longer still, which is
/// both rare and worth a fraction of a bit against the extra search per byte.
///
/// zlib spells the same idea `max_lazy_match` and makes it a per-level knob, which is what
/// `Level` below now does here too; this constant is the level-6 value and the default.
const MAX_LAZY: usize = 32;

/// How hard the match search works: the two knobs the sweeps above measured, as a pair.
///
/// **The level never crosses the wire, and that is a property of DEFLATE rather than a
/// simplification.** A deflate stream is self-describing -- the code tables and the
/// distances are in it -- so the decoder neither knows nor needs to know how hard the
/// encoder looked. Each side therefore uses its OWN level for what it sends, and there is
/// nothing to negotiate. Contrast the CODEC, which must be agreed because it decides how
/// the bytes are read at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Level {
    /// Positions with the same 3-byte hash to try before taking the best so far.
    pub chain: usize,
    /// Take a match at least this long without spending a lookahead search on it; 0 turns
    /// lazy matching off entirely, which is what makes the low levels fast.
    pub lazy: usize,
}

impl Level {
    /// Level 6, and deliberately the exact `MAX_CHAIN` / `MAX_LAZY` pair that shipped
    /// before this knob existed -- so a run without `-compress.level` produces byte-for-byte
    /// what it always did.
    pub const DEFAULT: Level = Level {
        chain: MAX_CHAIN,
        lazy: MAX_LAZY,
    };

    /// 1 (fastest) through 9 (smallest), zlib's scale and roughly zlib's shape: the low
    /// levels are greedy with a short chain, the middle adds lazy matching, the high levels
    /// lengthen the chain and lazy-match nearly always. Out of range clamps rather than
    /// failing, because the parser has already refused anything that is not a number here.
    pub fn of(n: u8) -> Level {
        match n.clamp(1, 9) {
            1 => Level { chain: 4, lazy: 0 },
            2 => Level { chain: 8, lazy: 0 },
            3 => Level { chain: 16, lazy: 0 },
            4 => Level { chain: 16, lazy: 8 },
            5 => Level {
                chain: 24,
                lazy: 16,
            },
            6 => Level::DEFAULT,
            7 => Level {
                chain: 64,
                lazy: 64,
            },
            8 => Level {
                chain: 128,
                lazy: 128,
            },
            _ => Level {
                chain: 256,
                lazy: MAX_MATCH,
            },
        }
    }
}
/// Literals and matches per block. A block boundary costs a few bits and lets the encoder
/// keep a bounded amount of state, which is what makes the parallel pipeline above this
/// possible later.
const BLOCK_SYMBOLS: usize = 16 << 10;

/// A least-significant-bit-first bit writer, the order DEFLATE packs in.
struct BitWriter {
    out: Vec<u8>,
    val: u32,
    cnt: u32,
}

impl BitWriter {
    fn new() -> BitWriter {
        BitWriter {
            out: Vec::new(),
            val: 0,
            cnt: 0,
        }
    }

    /// `n` bits of `v`, low bits first. Extra bits (lengths, distances) go out this way.
    fn bits(&mut self, v: u32, n: u32) {
        self.val |= (v & ((1u32 << n) - 1)) << self.cnt;
        self.cnt += n;
        while self.cnt >= 8 {
            self.out.push((self.val & 0xff) as u8);
            self.val >>= 8;
            self.cnt -= 8;
        }
    }

    /// A HUFFMAN code, which is packed starting from its MOST significant bit even though
    /// the stream itself is LSB-first. Getting this backwards produces a stream that
    /// decodes to garbage rather than to an error, so it is its own function.
    fn code(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.bits((v >> i) & 1, 1);
        }
    }

    fn align(&mut self) {
        if self.cnt > 0 {
            self.out.push((self.val & 0xff) as u8);
            self.val = 0;
            self.cnt = 0;
        }
    }

    /// Bytes straight into the stream, after aligning to a byte. A stored block's payload
    /// is not Huffman-coded and not bit-packed, so it goes out this way.
    fn raw(&mut self, bytes: &[u8]) {
        self.align();
        self.out.extend_from_slice(bytes);
    }

    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}

/// The fixed literal/length code: `(code, bits)` for a symbol, per RFC 1951 3.2.6.
fn fixed_lit(sym: u16) -> (u32, u32) {
    match sym {
        0..=143 => (0x30 + sym as u32, 8),
        144..=255 => (0x190 + (sym as u32 - 144), 9),
        256..=279 => (sym as u32 - 256, 7),
        _ => (0xc0 + (sym as u32 - 280), 8),
    }
}

/// The length code for `len`, and the extra bits that follow it.
fn length_code(len: usize) -> (u16, u32, u32) {
    let mut i = LEN_BASE.len() - 1;
    while i > 0 && (len as u16) < LEN_BASE[i] {
        i -= 1;
    }
    (
        257 + i as u16,
        len as u32 - LEN_BASE[i] as u32,
        u32::from(LEN_EXTRA[i]),
    )
}

/// The distance code for `dist`, and the extra bits that follow it.
fn distance_code(dist: usize) -> (u32, u32, u32) {
    // A DEFLATE distance is 1..=32768; zero is not a legal distance and would mean a
    // match against the position being encoded. Found by replanting a matcher defect --
    // `chain_link` before `chain_search`, which makes every position its own candidate --
    // and watching this line panic on `0 - DIST_BASE[0]`. In DEBUG that panic is the
    // failure; in RELEASE the subtraction wraps to `u32::MAX` and the extra bits become
    // garbage, so a corrupt stream would go out with nothing said. The assertion is here
    // rather than at the call site because this is where the domain is.
    debug_assert!(
        (1..=32768).contains(&dist),
        "distance {dist} is outside 1..=32768"
    );
    let mut i = DIST_BASE.len() - 1;
    while i > 0 && (dist as u16) < DIST_BASE[i] {
        i -= 1;
    }
    (
        i as u32,
        dist as u32 - DIST_BASE[i] as u32,
        u32::from(DIST_EXTRA[i]),
    )
}

/// One emitted symbol: a literal byte, or a match back `dist` for `len`.
#[derive(Clone, Copy)]
enum Sym {
    Lit(u8),
    Match { len: u16, dist: u16 },
}

fn hash3(b: &[u8]) -> usize {
    // a cheap 3-byte hash; collisions cost a chain walk, never correctness, because every
    // candidate is compared byte for byte before it is used
    ((b[0] as usize) << 10 ^ (b[1] as usize) << 5 ^ b[2] as usize) & (WINDOW - 1)
}

/// Greedy-with-lazy LZ77 over `data` at a chosen effort, producing the symbol stream a
/// block holds.
fn lz77_at(data: &[u8], level: Level) -> Vec<Sym> {
    let mut out = Vec::with_capacity(data.len() / 2 + 8);
    // `head[h]` is the most recent position with hash `h`; `prev` links each position to
    // the one before it in the same bucket.
    //
    // **`prev` IS A WINDOW-SIZED RING, NOT ONE SLOT PER INPUT BYTE**, which is how zlib
    // has always done it and is worth 128x here. The obvious
    // `vec![usize::MAX; data.len()]` is eight bytes per byte of input, so **32 MiB of
    // chain for a 4 MiB gzip member**, which contradicts the `GZIP_BLOCK` doc comment's
    // promise that the peak is one block plus its output.
    //
    // The ring is correct because the walk never looks further back than `WINDOW`: the
    // live range is `[i - WINDOW, i)`, exactly `WINDOW` positions, and `WINDOW` is a
    // power of two, so `p & MASK` is injective over that range. An entry it overwrites
    // is one the `floor` check would have rejected anyway.
    let mut head = vec![usize::MAX; WINDOW];
    let mut prev = vec![usize::MAX; WINDOW];

    // LAZY MATCHING (zlib calls this `deflate_slow`). A greedy matcher commits to the
    // match it finds at `i`. This one holds it, looks at `i + 1`, and if the match THERE
    // is strictly longer it spends `i` as a literal and takes the later, longer one --
    // one literal bought for more covered bytes.
    //
    // `>` and not `>=` matters: an equal-length match one position later is never better
    // and usually sits at a greater distance, which costs extra bits.
    //
    // The cost is that every position is searched rather than every match, so the chain
    // walk runs on each byte. `MAX_LAZY` bounds that: a match at least this long is taken
    // on the spot, because the lookahead can only improve on it by finding something
    // longer still, and past a certain length that is both rare and worth little.
    let mut pending: Option<(usize, usize, usize)> = None; // (position, len, dist)
    let mut i = 0;
    while i < data.len() {
        let (len, dist) = chain_search(data, &head, &prev, i, level.chain);
        chain_link(data, &mut head, &mut prev, i);

        match pending {
            // the later match is strictly better: give up `p` to a literal and hold this one
            Some((p, plen, _)) if len > plen => {
                out.push(Sym::Lit(data[p]));
                pending = Some((i, len, dist));
                i += 1;
            }
            // the held match wins: emit it and resume after it
            Some((p, plen, pdist)) => {
                out.push(Sym::Match {
                    len: plen as u16,
                    dist: pdist as u16,
                });
                // every position inside the match still enters the chain, so a later
                // match can start in the middle of this one. `p` and `i` (which is
                // `p + 1`) are already linked; `plen >= MIN_MATCH` so `end > i`.
                let end = p + plen;
                let mut k = i + 1;
                while k < end {
                    chain_link(data, &mut head, &mut prev, k);
                    k += 1;
                }
                i = end;
                pending = None;
            }
            // `level.lazy == 0` takes every match on the spot, which is a greedy pass: the
            // lookahead never runs, and that is what the low levels buy their speed with.
            None if len >= MIN_MATCH && (level.lazy == 0 || len >= level.lazy) => {
                // long enough that the lookahead is not worth a search per byte
                out.push(Sym::Match {
                    len: len as u16,
                    dist: dist as u16,
                });
                for k in 1..len {
                    chain_link(data, &mut head, &mut prev, i + k);
                }
                i += len;
            }
            None if len >= MIN_MATCH => {
                pending = Some((i, len, dist));
                i += 1;
            }
            None => {
                out.push(Sym::Lit(data[i]));
                i += 1;
            }
        }
    }
    // Unreachable in fact, kept so a future change cannot silently drop the tail: a held
    // match has `plen >= MIN_MATCH`, so its position is at least `MIN_MATCH` from the end
    // and the loop always runs again to resolve it.
    if let Some((_, plen, pdist)) = pending {
        out.push(Sym::Match {
            len: plen as u16,
            dist: pdist as u16,
        });
    }
    out
}

/// The longest match for `pos` reachable along its hash bucket, as `(len, dist)`.
///
/// Does NOT touch the chain. Searching and linking were one step while the chain was
/// broken in two ways at once -- `prev[i]` left unset on the match path, and set to `i`
/// itself on the literal path, a self-loop -- and separating them is what makes the
/// ordering checkable: search reads the bucket as it stood BEFORE `pos` joined it, then
/// `chain_link` adds `pos`. Doing it the other way round makes every position its own
/// best candidate at distance 0.
///
/// Neither half of that defect produced a wrong stream -- every candidate is compared
/// byte for byte -- which is why the round-trip and system-gzip arms were green
/// throughout. It cost RATIO. Measured by replanting both halves and running the real
/// encoder, at `MAX_CHAIN` 32 and fixed-Huffman blocks:
///
/// | corpus | broken | fixed | the defect cost |
/// | --- | --- | --- | --- |
/// | 400 KB, 4 symbols | 214,608 (0.5365) | 179,942 (0.4499) | +19.2% |
/// | 1,029,896 B of source and prose | 429,985 (0.4175) | 377,398 (0.3664) | +13.9% |
///
/// **It is tempting to say a text fixture could not find this one, and it is false.** That
/// belief comes from a 44-byte pangram repeated ten thousand times, called English text.
/// On real text the defect costs 14%, which any ratio bound catches. The narrow alphabet
/// is a SHARPER discriminator, not the only one -- so the reason to keep that fixture is
/// sensitivity, and the lesson is that a suite with no arm bounding the ratio at all
/// cannot see a ratio defect.
fn chain_search(
    data: &[u8],
    head: &[usize],
    prev: &[usize],
    pos: usize,
    chain: usize,
) -> (usize, usize) {
    if pos + MIN_MATCH > data.len() {
        return (0, 0);
    }
    let mut best_len = 0usize;
    let mut best_dist = 0usize;
    let h = hash3(&data[pos..]);
    let mut cand = head[h];
    let floor = pos.saturating_sub(WINDOW);
    let mut tries = 0;
    while cand != usize::MAX && cand >= floor && tries < chain {
        tries += 1;
        // compare forward from the candidate; a hash hit is a guess, the bytes decide
        let max = (data.len() - pos).min(MAX_MATCH);
        let mut l = 0;
        while l < max && data[cand + l] == data[pos + l] {
            l += 1;
        }
        if l > best_len {
            best_len = l;
            best_dist = pos - cand;
            if l == max {
                break;
            }
        }
        cand = prev[cand & MASK];
    }
    (best_len, best_dist)
}

/// Adds `pos` to its hash bucket, linking the previous head behind it.
///
/// A position too close to the end to hash is simply not added, which costs nothing: no
/// match can start there anyway.
fn chain_link(data: &[u8], head: &mut [usize], prev: &mut [usize], pos: usize) {
    if pos + MIN_MATCH <= data.len() {
        let h = hash3(&data[pos..]);
        prev[pos & MASK] = head[h];
        head[h] = pos;
    }
}

/// The most input one stored block can hold: `LEN` is 16 bits (RFC 1951 3.2.4).
const STORED_MAX: usize = 65535;

/// What a chunk of symbols costs as a fixed-Huffman block, in bits, end-of-block included.
fn fixed_bits(chunk: &[Sym]) -> usize {
    let mut bits = fixed_lit(256).1 as usize;
    for s in chunk {
        match *s {
            Sym::Lit(byte) => bits += fixed_lit(u16::from(byte)).1 as usize,
            Sym::Match { len, dist } => {
                let (sym, _, ebits) = length_code(len as usize);
                let (_, dbits) = (0, distance_code(dist as usize).2);
                bits += fixed_lit(sym).1 as usize + ebits as usize + 5 + dbits as usize;
            }
        }
    }
    bits
}

/// What the same span costs stored, in bits. Counts a whole byte of padding per sub-block
/// so the comparison never talks itself into stored on a rounding error.
fn stored_bits(span: usize) -> usize {
    let blocks = span.div_ceil(STORED_MAX).max(1);
    blocks * (3 + 7 + 32) + span * 8
}

/// Writes `data` as one or more stored blocks; `last` marks the final one BFINAL.
fn write_stored(w: &mut BitWriter, data: &[u8], last: bool) {
    let mut rest = data;
    loop {
        let n = rest.len().min(STORED_MAX);
        let final_here = last && n == rest.len();
        w.bits(u32::from(final_here), 1);
        w.bits(0, 2); // BTYPE 00
                      // LEN and NLEN are byte-aligned and little-endian, and NLEN is LEN's one's
                      // complement -- a decoder that checks it (ours does) rejects the block otherwise
        w.raw(&(n as u16).to_le_bytes());
        w.out.extend_from_slice(&(!(n as u16)).to_le_bytes());
        w.out.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
        if rest.is_empty() {
            return;
        }
    }
}

/// The longest code a literal/length or distance symbol may have (RFC 1951 3.2.7).
const MAX_CODE_BITS: u32 = 15;
/// The longest code the code-length alphabet may have (RFC 1951 3.2.7).
const MAX_CLEN_BITS: u32 = 7;

/// Optimal code lengths for `freq`, with no code longer than `limit` bits.
///
/// **Package-merge (Larmore-Hirschberg), not "halve the frequencies and retry".** The
/// retry fallback is what several encoders reach for when a plain Huffman tree overruns
/// the limit, and it is not optimal -- it perturbs the distribution until the tree happens
/// to fit. Package-merge is optimal *subject to* the limit, which is the actual problem
/// DEFLATE poses, and the limit is not hypothetical: a plain tree's depth grows like
/// log_phi of the symbol count, so a 16,384-symbol block with a Fibonacci-ish histogram
/// reaches about 20 bits and would be unencodable.
///
/// The coin-collector reading: symbol `i` offers a coin of value `freq[i]` in each of
/// `limit` denominations (2^-1 .. 2^-limit), and a code assigning `i` a length of `k` is a
/// purchase of that symbol's coins in the `k` largest denominations. The cheapest way to
/// buy a total denomination of `n - 1` is the optimal length-limited code, and the first
/// `2n - 2` coins of the final merged list are that purchase.
///
/// `limit` must satisfy `2^limit >= n`, which 15 does for 286 symbols and 7 does for 19.
///
/// `pub(crate)` because zstd's Huffman literals need exactly this -- a length-limited
/// canonical code -- and a second implementation would be a second thing to get wrong.
/// The two formats differ in how they SERIALIZE the lengths, not in how the lengths are
/// chosen, so the sharing stops at this function.
pub(crate) fn code_lengths(freq: &[u32], limit: u32) -> Vec<u8> {
    let mut lengths = vec![0u8; freq.len()];
    let mut used: Vec<usize> = (0..freq.len()).filter(|&i| freq[i] > 0).collect();
    // A code over ONE symbol is degenerate -- it has no bits to distinguish anything, and
    // `next_code` below would hand it the empty string. Callers force a second symbol
    // before getting here; this is the backstop, not the policy.
    if used.len() < 2 {
        for &i in &used {
            lengths[i] = 1;
        }
        return lengths;
    }
    used.sort_by_key(|&i| (freq[i], i));
    let base: Vec<u64> = used.iter().map(|&i| u64::from(freq[i])).collect();

    // Build each level's list, carrying only a weight and whether the item is a BASE coin
    // or a package.
    //
    // **WHAT IS DELIBERATELY NOT CARRIED IS WHICH SYMBOLS A PACKAGE CONTAINS, AND THE
    // OBVIOUS WAY TO CARRY IT -- A BITMASK -- IS WRONG.** A package can contain the same
    // symbol MORE THAN ONCE: its own base coin at this level, plus a package from the
    // level below that already holds it. A bitmask records presence, not multiplicity, so
    // every such symbol is counted once instead of twice and comes out with a code shorter
    // than it has paid for. The result is an OVER-SUBSCRIBED code -- Kraft sum above 1 --
    // which `inflate` refuses and `gzip` refuses with it.
    //
    // A test that checks ONE histogram (Fibonacci) does not trigger it. A fuzz over
    // 300,000 random histograms finds it in milliseconds; that fuzz is
    // `code_lengths_are_complete_over_many_histograms_not_just_one`.
    let mut levels: Vec<Vec<(u64, bool)>> = Vec::with_capacity(limit as usize);
    let mut level: Vec<(u64, bool)> = Vec::new();
    for _ in 0..limit {
        // package: pair the previous level up, dropping a lone odd coin -- it cannot be
        // paid for at this denomination
        let packed: Vec<(u64, bool)> = level
            .chunks_exact(2)
            .map(|p| (p[0].0 + p[1].0, false))
            .collect();
        // merge: both inputs are ascending, so one pass keeps the level sorted
        let mut merged = Vec::with_capacity(base.len() + packed.len());
        let (mut a, mut b) = (0, 0);
        while a < base.len() || b < packed.len() {
            let take_base = b >= packed.len() || (a < base.len() && base[a] <= packed[b].0);
            if take_base {
                merged.push((base[a], true));
                a += 1;
            } else {
                merged.push(packed[b]);
                b += 1;
            }
        }
        level.clone_from(&merged);
        levels.push(merged);
    }

    // Walk back down instead of tracking membership. `2n - 2` coins are bought at the top
    // level, each costing denomination 1/2, for a total of n - 1 -- which is what a code
    // over n symbols costs. Every PACKAGE among them was made from two coins one level
    // below, so that level contributes `2 * packages`. The base coins bought at a level
    // are always its cheapest, and the base list is in the same sorted order at every
    // level, so "b base coins here" means exactly `used[..b]` -- one bit each.
    let mut take = 2 * used.len() - 2;
    for list in levels.iter().rev() {
        let take_here = take.min(list.len());
        let packages = list[..take_here]
            .iter()
            .filter(|(_, is_base)| !*is_base)
            .count();
        for &i in used.iter().take(take_here - packages) {
            lengths[i] += 1;
        }
        take = 2 * packages;
    }
    lengths
}

/// Canonical codes for a set of lengths, per RFC 1951 3.2.2: shorter codes precede longer
/// ones, and within a length the symbols ascend. Written MSB-first by `BitWriter::code`.
fn canonical_codes(lengths: &[u8], max_bits: u32) -> Vec<u32> {
    let mut count = vec![0u32; max_bits as usize + 1];
    for &l in lengths {
        if l > 0 {
            count[l as usize] += 1;
        }
    }
    let mut next = vec![0u32; max_bits as usize + 2];
    let mut code = 0u32;
    for bits in 1..=max_bits as usize {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    let mut codes = vec![0u32; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l > 0 {
            codes[sym] = next[l as usize];
            next[l as usize] += 1;
        }
    }
    codes
}

/// One emitted code-length symbol: the symbol itself plus its extra bits.
type ClenItem = (u8, u32, u32);

/// Run-length encodes the concatenated literal and distance code lengths into the
/// code-length alphabet (RFC 1951 3.2.7): 16 repeats the PREVIOUS length 3-6 times, 17
/// runs 3-10 zeros and 18 runs 11-138.
///
/// The two length arrays are one sequence here, deliberately: a 16 may repeat the last
/// literal length as the first distance length, which the format allows and which saves
/// real bits when both tails are the same value.
fn rle_code_lengths(all: &[u8]) -> Vec<ClenItem> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let v = all[i];
        let mut run = 1;
        while i + run < all.len() && all[i + run] == v {
            run += 1;
        }
        i += run;
        if v == 0 {
            while run >= 11 {
                let n = run.min(138);
                out.push((18u8, (n - 11) as u32, 7));
                run -= n;
            }
            while run >= 3 {
                let n = run.min(10);
                out.push((17u8, (n - 3) as u32, 3));
                run -= n;
            }
            for _ in 0..run {
                out.push((0u8, 0, 0));
            }
        } else {
            // the first one is literal; only the repeats after it can use 16
            out.push((v, 0, 0));
            run -= 1;
            while run >= 3 {
                let n = run.min(6);
                out.push((16u8, (n - 3) as u32, 2));
                run -= n;
            }
            for _ in 0..run {
                out.push((v, 0, 0));
            }
        }
    }
    out
}

/// Everything a dynamic block needs, plus what it costs, so the caller can compare it with
/// stored and fixed before committing a single bit.
struct Dynamic {
    lit_len: Vec<u8>,
    lit_code: Vec<u32>,
    dist_len: Vec<u8>,
    dist_code: Vec<u32>,
    hlit: usize,
    hdist: usize,
    hclen: usize,
    clen_len: Vec<u8>,
    clen_code: Vec<u32>,
    rle: Vec<ClenItem>,
    bits: usize,
}

/// Builds the dynamic code for `chunk`, or `None` if the chunk is empty.
fn build_dynamic(chunk: &[Sym]) -> Option<Dynamic> {
    if chunk.is_empty() {
        return None;
    }
    // 286 literal/length symbols are meaningful; 286 and 287 encode nothing and a dynamic
    // block must not declare them, which is why this is 286 and `fixed_lit` covers 288.
    let mut lit_freq = vec![0u32; 286];
    let mut dist_freq = vec![0u32; DIST_BASE.len()];
    lit_freq[256] = 1; // exactly one end-of-block
    for s in chunk {
        match *s {
            Sym::Lit(byte) => lit_freq[byte as usize] += 1,
            Sym::Match { len, dist } => {
                lit_freq[length_code(len as usize).0 as usize] += 1;
                dist_freq[distance_code(dist as usize).0 as usize] += 1;
            }
        }
    }
    // FORCE TWO CODES IN EACH TREE. A block with no matches has an empty distance tree,
    // and a one-symbol tree is incomplete -- decoders disagree about those, and the bits
    // this costs are two header entries. zlib does the same thing for the same reason.
    force_two(&mut lit_freq);
    force_two(&mut dist_freq);

    let lit_len = code_lengths(&lit_freq, MAX_CODE_BITS);
    let dist_len = code_lengths(&dist_freq, MAX_CODE_BITS);
    let lit_code = canonical_codes(&lit_len, MAX_CODE_BITS);
    let dist_code = canonical_codes(&dist_len, MAX_CODE_BITS);

    // HLIT counts 257..=286 and HDIST 1..=30: trailing zero lengths are not sent
    let hlit = lit_len
        .iter()
        .rposition(|&l| l > 0)
        .map_or(257, |p| (p + 1).max(257));
    let hdist = dist_len
        .iter()
        .rposition(|&l| l > 0)
        .map_or(1, |p| (p + 1).max(1));

    let mut all = lit_len[..hlit].to_vec();
    all.extend_from_slice(&dist_len[..hdist]);
    let rle = rle_code_lengths(&all);

    let mut clen_freq = vec![0u32; CLEN_ORDER.len()];
    for &(sym, _, _) in &rle {
        clen_freq[sym as usize] += 1;
    }
    force_two(&mut clen_freq);
    let clen_len = code_lengths(&clen_freq, MAX_CLEN_BITS);
    let clen_code = canonical_codes(&clen_len, MAX_CLEN_BITS);

    // HCLEN drops trailing zeros IN THE PERMUTED ORDER, never below 4
    let hclen = CLEN_ORDER
        .iter()
        .rposition(|&i| clen_len[i] > 0)
        .map_or(4, |p| (p + 1).max(4));

    let mut bits = 3 + 5 + 5 + 4 + 3 * hclen;
    for &(sym, _, ebits) in &rle {
        bits += clen_len[sym as usize] as usize + ebits as usize;
    }
    bits += lit_len[256] as usize; // end-of-block
    for s in chunk {
        match *s {
            Sym::Lit(byte) => bits += lit_len[byte as usize] as usize,
            Sym::Match { len, dist } => {
                let (lsym, _, lextra) = length_code(len as usize);
                let (dsym, _, dextra) = distance_code(dist as usize);
                bits += lit_len[lsym as usize] as usize + lextra as usize;
                bits += dist_len[dsym as usize] as usize + dextra as usize;
            }
        }
    }
    Some(Dynamic {
        lit_len,
        lit_code,
        dist_len,
        dist_code,
        hlit,
        hdist,
        hclen,
        clen_len,
        clen_code,
        rle,
        bits,
    })
}

/// Gives a histogram at least two nonzero entries, so its Huffman code is complete.
fn force_two(freq: &mut [u32]) {
    let mut used = freq.iter().filter(|&&f| f > 0).count();
    let mut i = 0;
    while used < 2 && i < freq.len() {
        if freq[i] == 0 {
            freq[i] = 1;
            used += 1;
        }
        i += 1;
    }
}

/// Writes `chunk` as a dynamic-Huffman block (BTYPE 10).
fn write_dynamic(w: &mut BitWriter, d: &Dynamic, chunk: &[Sym], last: bool) {
    w.bits(u32::from(last), 1);
    w.bits(2, 2); // BTYPE 10
    w.bits((d.hlit - 257) as u32, 5);
    w.bits((d.hdist - 1) as u32, 5);
    w.bits((d.hclen - 4) as u32, 4);
    for &i in CLEN_ORDER.iter().take(d.hclen) {
        w.bits(u32::from(d.clen_len[i]), 3);
    }
    for &(sym, extra, ebits) in &d.rle {
        w.code(
            d.clen_code[sym as usize],
            u32::from(d.clen_len[sym as usize]),
        );
        if ebits > 0 {
            w.bits(extra, ebits);
        }
    }
    for s in chunk {
        match *s {
            Sym::Lit(byte) => w.code(
                d.lit_code[byte as usize],
                u32::from(d.lit_len[byte as usize]),
            ),
            Sym::Match { len, dist } => {
                let (lsym, lextra, lbits) = length_code(len as usize);
                w.code(
                    d.lit_code[lsym as usize],
                    u32::from(d.lit_len[lsym as usize]),
                );
                if lbits > 0 {
                    w.bits(lextra, lbits);
                }
                let (dsym, dextra, dbits) = distance_code(dist as usize);
                w.code(
                    d.dist_code[dsym as usize],
                    u32::from(d.dist_len[dsym as usize]),
                );
                if dbits > 0 {
                    w.bits(dextra, dbits);
                }
            }
        }
    }
    w.code(d.lit_code[256], u32::from(d.lit_len[256]));
}

/// Compresses `data` as a raw DEFLATE stream, choosing stored or fixed-Huffman per block.
///
/// The inverse of `inflate`, and the arms check exactly that plus the thing a round trip
/// cannot: that the system `gzip` accepts what this writes.
///
/// **Stored blocks are not an optimization, they are the floor.** With fixed Huffman
/// alone a literal costs 8 or 9 bits, so uniformly random bytes come out at 8.4375 bits
/// each -- measured at **+5.44%** on 200 KB of noise, an archive of already-compressed
/// files (an OCI layout, a tree of JPEGs) coming back LARGER from a `.tar.gz` than from a
/// `.tar`. The operator asked for compression and got expansion. A stored block costs
/// five bytes per 64 KiB, so the worst case is now about +0.01%.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    deflate_at(data, Level::DEFAULT)
}

/// The same, at a chosen search effort. Only the ENCODER changes: the stream a level 1 run
/// writes and the stream a level 9 run writes are both ordinary DEFLATE, and the same
/// `inflate` reads either.
pub fn deflate_at(data: &[u8], level: Level) -> Vec<u8> {
    let syms = lz77_at(data, level);
    let mut w = BitWriter::new();
    if syms.is_empty() {
        w.bits(1, 1); // BFINAL
        w.bits(1, 2); // fixed
        let (c, n) = fixed_lit(256);
        w.code(c, n);
        return w.finish();
    }
    let chunks: Vec<&[Sym]> = syms.chunks(BLOCK_SYMBOLS).collect();
    let mut at = 0usize;
    for (b, chunk) in chunks.iter().enumerate() {
        let span: usize = chunk
            .iter()
            .map(|s| match *s {
                Sym::Lit(_) => 1,
                Sym::Match { len, .. } => len as usize,
            })
            .sum();
        let last = b + 1 == chunks.len();
        // THREE WAYS TO WRITE THE SAME BLOCK, AND THE CHEAPEST ONE WINS ON A COUNT, NOT A
        // HEURISTIC. Each candidate reports the exact bits it would emit, including its
        // own header, so the choice cannot be wrong about its own cost.
        let stored = stored_bits(span);
        let fixed = fixed_bits(chunk);
        let dynamic = build_dynamic(chunk);
        let dyn_bits = dynamic.as_ref().map_or(usize::MAX, |d| d.bits);
        if stored < fixed && stored <= dyn_bits {
            write_stored(&mut w, &data[at..at + span], last);
            at += span;
            continue;
        }
        if dyn_bits < fixed {
            write_dynamic(
                &mut w,
                dynamic
                    .as_ref()
                    .expect("dyn_bits finite means it was built"),
                chunk,
                last,
            );
            at += span;
            continue;
        }
        at += span;
        w.bits(u32::from(last), 1);
        w.bits(1, 2);
        for s in chunk.iter() {
            match *s {
                Sym::Lit(byte) => {
                    let (c, n) = fixed_lit(u16::from(byte));
                    w.code(c, n);
                }
                Sym::Match { len, dist } => {
                    let (sym, extra, ebits) = length_code(len as usize);
                    let (c, n) = fixed_lit(sym);
                    w.code(c, n);
                    if ebits > 0 {
                        w.bits(extra, ebits);
                    }
                    let (dc, dextra, dbits) = distance_code(dist as usize);
                    // a distance code is five bits of the fixed code, MSB first
                    w.code(dc, 5);
                    if dbits > 0 {
                        w.bits(dextra, dbits);
                    }
                }
            }
        }
        let (c, n) = fixed_lit(256);
        w.code(c, n);
    }
    w.finish()
}

/// Wraps `data` in a gzip member (RFC 1952): header, DEFLATE, CRC-32 and the length.
///
/// `name` is stored when given, as `gzip` does and `tar -z` does not. `mtime` is seconds
/// since the epoch, zero for "not recorded", which is what the format says.
pub fn gzip(data: &[u8], name: Option<&str>, mtime: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 32);
    out.extend_from_slice(&[0x1f, 0x8b, 8]);
    out.push(if name.is_some() { 0x08 } else { 0 }); // FNAME
    out.extend_from_slice(&mtime.to_le_bytes());
    out.push(0); // no extra-compression hint
    out.push(3); // Unix
    if let Some(n) = name {
        // NUL-terminated and NUL-free: a name carrying one would truncate the field and
        // the rest would be read as deflate data
        out.extend_from_slice(n.replace('\0', "_").as_bytes());
        out.push(0);
    }
    out.extend_from_slice(&deflate(data));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// How much input one member of a streamed gzip holds: 4 MiB.
///
/// This is the memory bound, not a tuning knob for ratio. A member is compressed from a
/// buffer, so the peak is one block plus its output; the whole stream never exists at
/// once. Large enough that starting each block with an empty window costs almost nothing
/// (measured at well under a percent on text), small enough to be unremarkable RSS.
pub const GZIP_BLOCK: usize = 4 << 20;

/// The chunking `GzipWriter::rsyncable` cuts members on.
///
/// `max` is `GZIP_BLOCK`, so a rsyncable stream never holds more than a fixed-cut one
/// does and the `Write` impl's buffer bound is unchanged. `min` at a quarter of the
/// average keeps a pathological input from producing a run of tiny members, each of which
/// would pay for its own Huffman tables.
fn rsync_params() -> crate::cdc::Params {
    crate::cdc::Params {
        min: RSYNC_AVG / 4,
        avg: RSYNC_AVG,
        max: GZIP_BLOCK as u32,
    }
}

/// A megabyte, not pigz's ~4 KiB: see `GzipWriter::rsyncable` for why the unit being a
/// gzip MEMBER rather than a deflate block moves this by two orders of magnitude.
const RSYNC_AVG: u32 = 1 << 20;

/// Writes a gzip stream incrementally, as a run of independent members.
///
/// `gzip` above compresses a whole slice, so using it for an archive would mean holding
/// the archive in memory -- which is the wrong shape for `rcp copy /tree tar://out.tar.gz`
/// over a tree of any size. Concatenated members are a legal gzip file (RFC 1952 section
/// 2.2), `gzip` and `tar` both read one, and it is what `pigz -i` writes, so the stream
/// stays standard while the memory stays bounded.
///
/// The cost is stated rather than hidden: each member starts with an empty match window,
/// so a run repeating across a block boundary is not matched. With `GZIP_BLOCK` at 4 MiB
/// that is a fraction of a percent, and the same property is what lets a reader decode
/// members in parallel.
/// An ordered pool that compresses members off the writing thread.
///
/// The members are ALREADY independent -- that is what makes this possible without
/// changing the format, and it is why the 4 MiB framing was worth keeping even though it
/// costs a fraction of a percent in ratio. `pigz` reaches parallelism the same way.
///
/// **Memory is bounded and the bound is stated.** At most `workers` jobs are in flight,
/// each holding one `GZIP_BLOCK` of input, and at most `workers` finished members wait in
/// `ready` for their turn to be written. So the peak is about `workers * (GZIP_BLOCK +
/// its compressed size)` on top of the writer's own block -- roughly 4 MiB per worker.
/// Dispatching without that cap would let a fast producer queue the whole archive, which
/// is the failure the serial writer was shaped to avoid in the first place.
///
/// Order is restored on the writing side rather than by making workers wait: results
/// arrive in whatever order they finish, land in `ready` by sequence number, and are
/// written out as the run becomes contiguous.
/// What turns one member's input into its bytes on the wire: `gzip` for a `.tar.gz`,
/// `zstd_member` for a `.tar.zst`. A plain function pointer, so a worker thread can hold
/// one without any lifetime or boxing, and so the pool is the same pool for both.
type Encode = fn(&[u8], Option<&str>, u32) -> Vec<u8>;

/// One zstd frame per member. The name and mtime are gzip header fields with no place in
/// a zstd frame, so they are dropped here rather than smuggled into a skippable frame
/// that no reader would look for.
fn zstd_member(data: &[u8], _name: Option<&str>, _mtime: u32) -> Vec<u8> {
    crate::zstd::compress(data)
}

struct Pool {
    jobs: std::sync::mpsc::Sender<(usize, Vec<u8>, Option<String>, u32)>,
    /// `None` for a member whose compression panicked; see the worker loop.
    done: std::sync::mpsc::Receiver<(usize, Option<Vec<u8>>)>,
    handles: Vec<std::thread::JoinHandle<()>>,
    workers: usize,
    in_flight: usize,
    next_seq: usize,
    next_write: usize,
    ready: std::collections::BTreeMap<usize, Vec<u8>>,
}

impl Pool {
    fn new(workers: usize, encode: Encode) -> Pool {
        use std::sync::{mpsc, Arc, Mutex};
        let (jobs, job_rx) = mpsc::channel::<(usize, Vec<u8>, Option<String>, u32)>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (done_tx, done) = mpsc::channel::<(usize, Option<Vec<u8>>)>();
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let job_rx = Arc::clone(&job_rx);
            let done_tx = done_tx.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    // The guard is a temporary of THIS statement, so the lock is released
                    // as soon as a job is taken and the compression below runs outside it.
                    // Holding it across `gzip` would serialize the pool completely while
                    // looking exactly like this.
                    let job = job_rx.lock().map(|g| g.recv());
                    let Ok(Ok((seq, data, name, mtime))) = job else {
                        break;
                    };
                    // A PANICKING WORKER MUST NOT HANG THE WRITER. Without this, a job
                    // that panics never produces a result, the other workers keep their
                    // senders alive so the channel never disconnects, and `drain_one`
                    // waits forever for a member that is not coming. `deflate` has a
                    // `debug_assert` that can fire, so this is not hypothetical in a
                    // debug build. The failure is reported as an error instead.
                    let member = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        encode(&data, name.as_deref(), mtime)
                    }));
                    if done_tx.send((seq, member.ok())).is_err() {
                        break;
                    }
                }
            }));
        }
        // the pool's own copy goes away, so the workers' senders are the only ones left
        // and `done` disconnects exactly when every worker has exited
        drop(done_tx);
        Pool {
            jobs,
            done,
            handles,
            workers,
            in_flight: 0,
            next_seq: 0,
            next_write: 0,
            ready: std::collections::BTreeMap::new(),
        }
    }

    /// Takes one finished member, and writes out everything that is now contiguous.
    fn drain_one<W: io::Write>(&mut self, out: &mut W) -> io::Result<()> {
        let (seq, member) = self.done.recv().map_err(|_| {
            io::Error::other("a compression worker died before returning its member")
        })?;
        self.in_flight -= 1;
        let member =
            member.ok_or_else(|| io::Error::other("compressing an archive member panicked"))?;
        self.ready.insert(seq, member);
        while let Some(member) = self.ready.remove(&self.next_write) {
            out.write_all(&member)?;
            self.next_write += 1;
        }
        Ok(())
    }

    fn submit<W: io::Write>(
        &mut self,
        out: &mut W,
        data: Vec<u8>,
        name: Option<String>,
        mtime: u32,
    ) -> io::Result<()> {
        while self.in_flight >= self.workers {
            self.drain_one(out)?;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.in_flight += 1;
        self.jobs
            .send((seq, data, name, mtime))
            .map_err(|_| io::Error::other("the compression pool has shut down"))
    }

    /// Drains every outstanding member in order and stops the workers.
    fn finish<W: io::Write>(mut self, out: &mut W) -> io::Result<()> {
        while self.in_flight > 0 {
            self.drain_one(out)?;
        }
        drop(self.jobs);
        for h in self.handles.drain(..) {
            // A worker that panicked has already surfaced as a dead channel above; this
            // only reaps the threads.
            let _ = h.join();
        }
        debug_assert!(
            self.ready.is_empty(),
            "members left unwritten after the pool drained"
        );
        Ok(())
    }
}

/// Named for the format it was written for, and it now writes two: `zstd` builds one
/// whose members are zstd frames instead of gzip members. Everything else -- the bounded
/// block, the ordered pool, the content-defined cuts, what a dropped writer leaves -- is
/// the same for both, because both formats define a file as its members concatenated.
pub struct GzipWriter<W: io::Write> {
    inner: W,
    encode: Encode,
    buf: Vec<u8>,
    name: Option<String>,
    mtime: u32,
    /// Set once the first member is written, so the name is stored once rather than on
    /// every member.
    started: bool,
    /// Set by `finish`, so a second call does nothing.
    ///
    /// There is NO `Drop` guard, so a reader must not assume the tail is flushed on an
    /// early return. It is not: see `Out::finish` in `tar/client.rs` for what a dropped writer leaves on
    /// disk and why finishing it in `Drop` would be the wrong direction.
    done: bool,
    /// `None` compresses on the writing thread, which is the default and what every
    /// existing caller gets. `Some` moves it to a pool; the BYTES ARE THE SAME either
    /// way, because a member is a pure function of its input and the pool only changes
    /// which thread computes it and when it is written.
    pool: Option<Pool>,
    /// `Some` cuts members where the CONTENT says to rather than every `GZIP_BLOCK`
    /// bytes (`pigz --rsyncable`). See `rsyncable`.
    cut: Option<crate::cdc::Chunker>,
}

impl<W: io::Write> GzipWriter<W> {
    pub fn new(inner: W, name: Option<&str>, mtime: u32) -> GzipWriter<W> {
        GzipWriter::with_workers(inner, name, mtime, 1)
    }

    /// Compresses members on `workers` threads; 0 or 1 keeps everything on this one.
    ///
    /// Worth doing because deflate is the expensive half: on a 4 MiB member the LZ77 pass
    /// and the two Huffman passes dominate, while writing the result is a memcpy. It is
    /// opt-in rather than automatic because a library type that spawns threads off the
    /// machine's core count takes a decision that belongs to the run's `-parallel`.
    pub fn with_workers(inner: W, name: Option<&str>, mtime: u32, workers: usize) -> GzipWriter<W> {
        GzipWriter::build(inner, name, mtime, workers, gzip)
    }

    /// A `.zst` stream: one zstd frame per `GZIP_BLOCK` of input (or per content-defined
    /// chunk, with `rsyncable`), on `workers` threads.
    ///
    /// Concatenated frames are one zstd file by definition (RFC 8878, section 3.1), which
    /// is what `zstd -d`, `tar --zstd` and this crate's own decoder read. Each frame is
    /// single-segment with its size declared, so a reader holds at most one block of
    /// window. Independent frames cost ratio for the same reason gzip members do: each
    /// starts with an empty match history.
    pub fn zstd(inner: W, workers: usize, rsyncable: bool) -> GzipWriter<W> {
        let mut w = GzipWriter::build(inner, None, 0, workers, zstd_member);
        if rsyncable {
            w.cut = Some(crate::cdc::Chunker::new(rsync_params()));
        }
        w
    }

    fn build(
        inner: W,
        name: Option<&str>,
        mtime: u32,
        workers: usize,
        encode: Encode,
    ) -> GzipWriter<W> {
        GzipWriter {
            inner,
            encode,
            buf: Vec::with_capacity(GZIP_BLOCK),
            name: name.map(str::to_owned),
            mtime,
            started: false,
            done: false,
            pool: (workers > 1).then(|| Pool::new(workers, encode)),
            cut: None,
        }
    }

    /// Cuts each member where the CONTENT says to, instead of every `GZIP_BLOCK` bytes.
    /// `pigz --rsyncable`, reached through this crate's own Gear chunker.
    ///
    /// # The problem this solves, and why a fixed cut cannot
    ///
    /// Members are already independent, which is what gives parallel decode. But their
    /// BOUNDARIES are at fixed input offsets, so inserting one byte near the front shifts
    /// every later boundary by one and every later member compresses differently. The
    /// archive is then entirely new from the edit onward, and a delta transfer of the
    /// compressed file has nothing to match.
    ///
    /// Content-defined boundaries resynchronize: after an edit the chunker re-finds the
    /// same cut points within about one chunk, so every member past that point is
    /// BYTE-IDENTICAL to the one before the edit.
    ///
    /// # The parameters, and why they are not pigz's
    ///
    /// pigz cuts at roughly a 4 KiB average. Its unit is a deflate block inside ONE
    /// stream, so a cut costs a flush. Here the unit is a gzip MEMBER -- 18 bytes of
    /// frame plus a fresh Huffman table and an empty match window -- so a 4 KiB member
    /// would be mostly overhead. `RSYNC_AVG` is a megabyte for that reason, with the
    /// measured cost recorded beside it.
    ///
    /// # What it costs, measured rather than estimated
    ///
    /// Smaller members compress worse: each one restarts the match window and pays for
    /// its own code tables. The numbers are in the arm
    /// `rsyncable_costs_ratio_and_the_cost_is_bounded`, which fails if the penalty grows
    /// past what is recorded there.
    pub fn rsyncable(inner: W, name: Option<&str>, mtime: u32, workers: usize) -> GzipWriter<W> {
        let mut w = GzipWriter::with_workers(inner, name, mtime, workers);
        w.cut = Some(crate::cdc::Chunker::new(rsync_params()));
        w
    }

    fn flush_member(&mut self) -> io::Result<()> {
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(GZIP_BLOCK));
        let recycle = self.emit_member(data)?;
        if let Some(mut b) = recycle {
            b.clear();
            self.buf = b;
        }
        Ok(())
    }

    /// Compresses and writes one member. Returns the input buffer when it can be reused
    /// -- the serial path can, the pool moves it to a worker and cannot.
    fn emit_member(&mut self, data: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        // The name goes on the FIRST member only, and `started` decides that here rather
        // than in the pool so the answer does not depend on completion order.
        let name = if self.started {
            None
        } else {
            self.name.clone()
        };
        self.started = true;
        match self.pool.take() {
            // taken out and put back, because `submit` needs both the pool and the
            // writer and they are fields of the same struct
            Some(mut pool) => {
                let r = pool.submit(&mut self.inner, data, name, self.mtime);
                self.pool = Some(pool);
                r.map(|()| None)
            }
            None => {
                let member = (self.encode)(&data, name.as_deref(), self.mtime);
                self.inner.write_all(&member).map(|()| Some(data))
            }
        }
    }

    /// Writes the last member and the caller's stream is a complete gzip file.
    ///
    /// An empty input still writes one empty member: a zero-byte file is not a gzip
    /// stream, and `gzip -d` refuses it rather than reporting nothing.
    pub fn finish(mut self) -> io::Result<W> {
        if !self.done {
            self.done = true;
            if !self.buf.is_empty() || !self.started {
                self.flush_member()?;
            }
            if let Some(pool) = self.pool.take() {
                pool.finish(&mut self.inner)?;
            }
            self.inner.flush()?;
        }
        Ok(self.inner)
    }
}

impl<W: io::Write> io::Write for GzipWriter<W> {
    /// Takes at most what is left of the current block, so the buffer is bounded by
    /// `GZIP_BLOCK` and NOT by how much a caller hands over at once.
    ///
    /// The first version did `buf.extend_from_slice(data)` and split afterwards, which
    /// made the peak `max(GZIP_BLOCK, caller's slice)`. Every write in this crate happens
    /// to be at most the transfer layer's 1 MiB block, so the bound held -- but it held
    /// as a property of the CALLERS, re-established by auditing them, and a `Write` impl
    /// is public surface that anything may hand a whole file to. Bounding it here makes
    /// it a property of the type.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = GZIP_BLOCK - self.buf.len();
        let n = data.len().min(room);
        let taken = &data[..n];
        self.buf.extend_from_slice(taken);
        let Some(mut chunker) = self.cut.take() else {
            if self.buf.len() == GZIP_BLOCK {
                self.flush_member()?;
            }
            return Ok(n);
        };
        // Rsyncable: the chunker sees exactly the bytes that go into `buf`, and `buf`
        // always starts on a chunk boundary, so each chunk it completes IS one member --
        // no separate boundary arithmetic, and nothing to get out of step.
        //
        // The chunker's `max` is `GZIP_BLOCK`, so it cuts no later than the `room`
        // computation above allows. That is what keeps the buffer bound a property of
        // this type rather than of the caller's slice sizes.
        let mut chunks = Vec::new();
        chunker.push(taken, &mut chunks);
        let mut result = Ok(());
        for c in &chunks {
            let rest = self.buf.split_off(c.len as usize);
            let member = std::mem::replace(&mut self.buf, rest);
            if let Err(e) = self.emit_member(member) {
                result = Err(e);
                break;
            }
        }
        // Put it back even on the error path: a half-fed chunker left behind would
        // resynchronize somewhere else entirely if the caller retried.
        self.cut = Some(chunker);
        result?;
        Ok(n)
    }

    /// Flushes what has reached the inner writer, NOT the pending block.
    ///
    /// Cutting a member early on every `flush` would make one per write for a caller that
    /// flushes often, and the members carry 18 bytes of frame each. `finish` is what ends
    /// the stream.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Incompressible bytes, from a seed so a failure is reproducible.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Input whose 3-byte prefixes collide, which is the only shape that can measure the
    /// match chain. `ACGT` over 400 KB, with long pieces replanted far apart.
    fn narrow_alphabet() -> Vec<u8> {
        let mut x: u64 = 12345;
        let mut d = Vec::with_capacity(400_000);
        while d.len() < 400_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            d.push(b"ACGT"[(x >> 33) as usize & 3]);
        }
        for k in 0..20 {
            let piece: Vec<u8> = d[k * 1000..k * 1000 + 400].to_vec();
            d[200_000 + k * 1500..200_000 + k * 1500 + 400].copy_from_slice(&piece);
        }
        d
    }

    /// The encoder finds long-range matches, not just the most recent candidate.
    ///
    /// This arm exists because every other arm here was GREEN while the hash chain was
    /// broken in two ways at once -- `prev[i]` left unset on the match path, and set to
    /// `i` itself on the literal path, a self-loop. Neither produced an invalid stream,
    /// so a round trip could not see them and neither could the system `gzip`. What they
    /// cost was ratio, and only on colliding input: on English text the whole sweep from
    /// a 4-deep chain to a 128-deep one moves 0.078 to 0.077.
    ///
    /// Measured on the corpus below, 400 KB:
    ///
    /// | | output | ratio |
    /// | --- | --- | --- |
    /// | broken chain | 227,601 | 0.569 |
    /// | fixed, `MAX_CHAIN` 32 | 179,942 | 0.450 |
    /// | system `gzip -6` | 117,337 | 0.293 |
    /// | system `gzip -9` | 115,419 | 0.289 |
    ///
    /// **The gap to `gzip` is MOSTLY the coder and PARTLY the matcher, and saying "not
    /// the chain" was a confounded reading.** `gzip -6` changes the search and the code
    /// table together -- lazy matching, a far longer chain, AND dynamic blocks -- so
    /// comparing against it cannot attribute the difference to either. zlib's `Z_FIXED`
    /// strategy separates them, because it forces fixed-Huffman blocks while leaving the
    /// search at whatever the level asks for. On the same 400 KB corpus:
    ///
    /// | | output | ratio |
    /// | --- | --- | --- |
    /// | `Z_FIXED` level 1 -- weak search, fixed coder | 213,079 | 0.533 |
    /// | this encoder, fixed blocks only | 179,942 | 0.450 |
    /// | `Z_FIXED` level 9 -- strong search, fixed coder | 160,932 | 0.402 |
    /// | **this encoder now** -- dynamic coder | 120,430 | **0.301** |
    /// | default level 9 -- strong search, dynamic coder | 115,367 | 0.288 |
    ///
    /// Read the middle rows first. **zlib's STRONGEST matcher, restricted to fixed
    /// blocks, reached only 0.402** -- nowhere near 0.288 -- so the code table was doing
    /// most of the work and no chain depth substituted for it. That was a measurement of
    /// one strong matcher, NOT a proof of a floor: an optimal parser (zopfli, libdeflate)
    /// emitting only fixed blocks could go below 0.402, and calling it "the floor for any
    /// fixed-Huffman encoder" was a bound claimed from a single data point. Dynamic
    /// blocks have since taken this encoder to 0.301, past that 0.402, leaving 2.6%
    /// against `gzip -6` -- and that residue is the matcher: greedy, no lazy matching.
    ///
    /// **ADDING DYNAMIC BLOCKS MADE THIS ARM INERT, AND IT STAYED GREEN WHILE IT WAS.**
    /// The bar was `ratio < 0.53`, chosen so the replanted defect (0.537) fails it. Under
    /// dynamic blocks the SAME defect compresses to 0.3338 -- comfortably passing. The
    /// arm still ran, still named the chain, and could no longer see the thing it exists
    /// for. Nothing announced that; it was found by asking what the DEFECT would now
    /// measure rather than what the fix does.
    ///
    /// So the primary assertion is no longer the ratio. It is the LZ77 symbol count,
    /// which is upstream of every code table and cannot be flattered by one. Measured on
    /// this corpus, all three with dynamic blocks in place:
    ///
    /// | | symbols | ratio |
    /// | --- | --- | --- |
    /// | shipped | 73,851 | 0.3011 |
    /// | `MAX_CHAIN` 4 | 100,218 | 0.3221 |
    /// | the chain defect replanted | 104,079 | 0.3338 |
    ///
    /// Note what is NOT usable: match *coverage* is 0.9999 of the input in all three.
    /// The defect does not stop matches being found, it makes them SHORTER, so an arm
    /// bounding coverage would have been inert from the day it was written.
    #[test]
    fn the_match_chain_reaches_past_the_most_recent_candidate() {
        let data = narrow_alphabet();

        // THE PRIMARY ASSERTION IS THE MEAN MATCH LENGTH, and choosing it took three
        // rejected candidates -- each rejected by measurement, not by taste.
        //
        // What is wanted is a number that rises when the matcher improves, whatever the
        // coder does. Measured on this corpus:
        //
        // | | symbols | coverage | fixed-Huffman bits | ratio | mean match |
        // | --- | --- | --- | --- | --- | --- |
        // | the chain defect | 104,079 | 0.9999 | -- | 0.3338 | 3.84 |
        // | `MAX_CHAIN` 4 | 100,218 | 0.9999 | -- | 0.3221 | 3.99 |
        // | greedy, full chain | 73,851 | 0.9999 | 1,439,514 | 0.3011 | 5.42 |
        // | **shipped** (lazy) | 85,091 | 0.9483 | 1,440,252 | **0.3003** | **5.89** |
        //
        // - **Symbol count** was the primary assertion for exactly one commit. Lazy
        //   matching RAISES it, from 73,851 to 85,091, because spending literals is the
        //   mechanism and not a side effect. A bar that rewards fewer symbols punishes
        //   the improvement.
        // - **Coverage** is 0.9999 under both greedy and the defect, so it never
        //   discriminated, and lazy matching lowers it to 0.9483 on purpose.
        // - **Cost under the FIXED code** looked like the principled answer -- an
        //   unchanging reference coder, immune to the dynamic one. It says greedy is
        //   BETTER (1,439,514 against 1,440,252). That is not an error in the
        //   measurement: lazy matching wins here *because* its extra literals are cheap
        //   under a code fitted to the block, which is precisely what a fixed reference
        //   cannot see. **There is no coder-independent number that captures what lazy
        //   matching buys, because what it buys is coder-dependent by construction.**
        //
        // Mean match length is left. It rises with chain quality AND with the lookahead,
        // and 4.5 sits 13% above `MAX_CHAIN` 4 and 24% below shipped.
        let syms = lz77_at(&data, Level::DEFAULT);
        let covered: usize = syms
            .iter()
            .map(|s| match *s {
                Sym::Lit(_) => 0,
                Sym::Match { len, .. } => len as usize,
            })
            .sum();
        let matches = syms
            .iter()
            .filter(|s| matches!(s, Sym::Match { .. }))
            .count();
        let mean = covered as f64 / matches as f64;
        assert!(
            mean > 4.5,
            "matches average {mean:.2} bytes ({covered} bytes over {matches} matches); the chain is not reaching past head[h]"
        );

        let out = deflate(&data);
        let ratio = out.len() as f64 / data.len() as f64;
        // THE END-TO-END BAR, which measures the whole encoder and is kept for that
        // reason rather than in spite of it:
        //
        //   0.3372  chain depth 1
        //   0.3338  the chain defect, replanted
        //   0.3221  `MAX_CHAIN` 4
        //   0.3003  shipped
        //
        // 0.32 fails all three cripples and passes shipped with 6%. It also fails
        // `MAX_CHAIN` 4, deliberately: there is no bar between 0.3221 and 0.3338 with
        // usable margin, and a test reporting that a chain of 4 costs 7% on colliding
        // input is the right answer to a deliberate change, not a false alarm.
        assert!(
            ratio < 0.32,
            "colliding input compressed to {ratio:.4} ({} bytes)",
            out.len()
        );

        // THE CONTROL, and it is not decoration: a smaller output is only good if it is
        // still the same bytes. A chain bug that produced a wrong distance would make
        // this smaller AND wrong.
        let back = inflate(&out, DEFAULT_LIMIT).expect("the encoder's own output must decode");
        assert!(back == data, "the bytes changed");

        // and text stays where it was, so a chain tuned for the pathological case has
        // not cost the ordinary one
        let text = "the quick brown fox jumps over the lazy dog\n"
            .repeat(10_000)
            .into_bytes();
        let packed = deflate(&text);
        assert!(
            packed.len() < text.len() / 50,
            "text compressed to {} bytes from {}",
            packed.len(),
            text.len()
        );
    }

    /// The level knob, and the guarantee that matters most is the one about level 6.
    ///
    /// A knob whose DEFAULT changes the output is a silent regression for every caller who
    /// never asked for it, so `Level::DEFAULT` is the exact `MAX_CHAIN` / `MAX_LAZY` pair
    /// that shipped before, and this asserts the two encoders agree BYTE FOR BYTE rather
    /// than merely round-tripping.
    #[test]
    fn the_level_knob_trades_ratio_for_work_and_leaves_the_default_alone() {
        let data = narrow_alphabet();
        // the load-bearing one: no caller who omits `-compress.level` sees a different byte
        assert_eq!(
            deflate_at(&data, Level::of(6)),
            deflate(&data),
            "level 6 is not the shipped default"
        );

        let mut sizes = Vec::new();
        for n in 1..=9u8 {
            let out = deflate_at(&data, Level::of(n));
            // every level is ordinary DEFLATE and the one decoder reads all of them
            assert_eq!(
                inflate(&out, data.len()).expect("inflates"),
                data,
                "level {n} did not round-trip"
            );
            eprintln!(
                "level {n}: {} bytes, ratio {:.4}",
                out.len(),
                out.len() as f64 / data.len() as f64
            );
            sizes.push(out.len());
        }

        // THE ARM: more work buys ratio. Asserted end-to-end rather than pairwise, because
        // the levels are not required to be strictly monotone -- a longer chain can pick a
        // different match that codes a hair worse -- but 1 -> 9 must pay.
        assert!(
            sizes[8] < sizes[0],
            "level 9 ({}) is not smaller than level 1 ({})",
            sizes[8],
            sizes[0]
        );
        // and the gap is worth having rather than noise
        assert!(
            sizes[8] * 100 < sizes[0] * 97,
            "level 9 ({}) saves under 3% over level 1 ({})",
            sizes[8],
            sizes[0]
        );

        // the control: the knob is not simply ignored at the ends. Level 1 is greedy with a
        // 4-deep chain and MUST be worse than the default, or `Level::of` is returning the
        // same thing for every input and the sweep above proves nothing.
        assert!(
            sizes[0] > sizes[5],
            "level 1 ({}) is not worse than level 6 ({}); the knob may be inert",
            sizes[0],
            sizes[5]
        );
    }

    /// A plain Huffman tree over `freq`, with no length limit -- the CONTROL for
    /// `code_lengths`. Without it, "no code exceeds 15 bits" would also pass on a
    /// histogram whose unlimited tree never reached 15, proving nothing about the limit.
    fn unlimited_huffman_depth(freq: &[u32]) -> u32 {
        let mut heap: Vec<(u64, u32)> = freq
            .iter()
            .filter(|&&f| f > 0)
            .map(|&f| (u64::from(f), 1u32))
            .collect();
        if heap.len() < 2 {
            return heap.len() as u32;
        }
        let mut depth = 0;
        while heap.len() > 1 {
            heap.sort_by_key(|&(w, d)| (w, d));
            let (w0, d0) = heap.remove(0);
            let (w1, d1) = heap.remove(0);
            let d = d0.max(d1) + 1;
            depth = depth.max(d);
            heap.push((w0 + w1, d));
        }
        depth - 1
    }

    #[test]
    fn code_lengths_are_complete_and_stay_inside_the_limit() {
        // Fibonacci frequencies are the worst case for tree DEPTH: each symbol pairs with
        // the accumulated weight of every smaller one, so the tree is a caterpillar.
        let mut fib = vec![0u32; 30];
        fib[0] = 1;
        fib[1] = 1;
        for i in 2..30 {
            fib[i] = fib[i - 1] + fib[i - 2];
        }
        // THE CONTROL: an unlimited tree on this histogram really does overrun 15, so the
        // limit below is doing work rather than being satisfied by accident.
        let unlimited = unlimited_huffman_depth(&fib);
        assert!(
            unlimited > MAX_CODE_BITS,
            "control: unlimited depth {unlimited} must exceed {MAX_CODE_BITS}"
        );

        for limit in [MAX_CLEN_BITS, MAX_CODE_BITS] {
            let freq: Vec<u32> = fib[..(1 << limit).min(fib.len())].to_vec();
            let lengths = code_lengths(&freq, limit);
            let mut kraft = 0u64;
            for (i, &l) in lengths.iter().enumerate() {
                if freq[i] > 0 {
                    assert!(
                        l > 0 && u32::from(l) <= limit,
                        "symbol {i} got {l} bits, limit {limit}"
                    );
                    kraft += 1u64 << (limit - u32::from(l));
                } else {
                    assert_eq!(l, 0, "an unused symbol must get no code");
                }
            }
            // A COMPLETE code sums to exactly 1. Under summing leaves bit patterns that
            // decode to nothing; over summing is not a prefix code at all.
            assert_eq!(
                kraft,
                1u64 << limit,
                "limit {limit}: Kraft sum must be exactly 1"
            );
        }
    }

    #[test]
    fn code_lengths_are_complete_over_many_histograms_not_just_one() {
        // THE ARM THAT WOULD HAVE CAUGHT THE REAL DEFECT, and the one above would not.
        //
        // `code_lengths_are_complete_and_stay_inside_the_limit` checks a Fibonacci
        // histogram, because that is the worst case for tree DEPTH. It passed while the
        // function was returning OVER-SUBSCRIBED codes for ordinary skewed histograms --
        // the first version tracked a package's members in a bitmask, which cannot
        // record a symbol appearing in a package twice, so deep symbols were counted
        // once and given codes shorter than they had paid for.
        //
        // A depth worst case is not a correctness worst case. One histogram is one
        // histogram. This sweeps many, deterministically, and the smallest failure the
        // original fuzz found is pinned below so the arm still means something if the
        // sweep is ever changed.
        let complete = |freq: &[u32], limit: u32| -> bool {
            let l = code_lengths(freq, limit);
            let kraft: u64 = l
                .iter()
                .filter(|&&v| v > 0)
                .map(|&v| 1u64 << (limit - u32::from(v)))
                .sum();
            kraft == 1u64 << limit && l.iter().all(|&v| u32::from(v) <= limit)
        };

        // the exact histogram the bitmask version got wrong: Kraft came to 130, not 128
        let pinned = [
            16u32, 54, 227, 7, 6, 135, 3, 250, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(
            complete(&pinned, MAX_CLEN_BITS),
            "the pinned counterexample must produce a complete code"
        );

        let mut x: u64 = 1;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        // the code-length alphabet, which is where the defect actually reached the wire
        for _ in 0..20_000 {
            let n = 2 + (rnd() % 18) as usize;
            let freq: Vec<u32> = (0..CLEN_ORDER.len())
                .map(|i| if i < n { 1 + (rnd() % 5000) as u32 } else { 0 })
                .collect();
            assert!(
                complete(&freq, MAX_CLEN_BITS),
                "incomplete clen code for {freq:?}"
            );
        }
        // and the literal/length alphabet, including spreads that force the 15-bit limit
        for t in 0..300 {
            let n = 2 + (rnd() % 284) as usize;
            let freq: Vec<u32> = (0..286)
                .map(|i| {
                    if i >= n {
                        0
                    } else if t % 4 == 0 {
                        // a doubling spread is what drives a plain tree past 15 bits
                        1u32.wrapping_shl((i % 30) as u32).max(1)
                    } else {
                        1 + (rnd() % 100_000) as u32
                    }
                })
                .collect();
            assert!(
                complete(&freq, MAX_CODE_BITS),
                "incomplete literal code at n={n}, t={t}"
            );
        }
    }

    #[test]
    fn package_merge_beats_the_obvious_alternative_on_cost() {
        // The alternative this rejects: halve the frequencies until a plain tree fits.
        // Both produce a legal code, so only the COST distinguishes them.
        let mut fib = vec![0u32; 20];
        fib[0] = 1;
        fib[1] = 1;
        for i in 2..20 {
            fib[i] = fib[i - 1] + fib[i - 2];
        }
        let cost = |lengths: &[u8]| -> u64 {
            lengths
                .iter()
                .zip(&fib)
                .map(|(&l, &f)| u64::from(l) * u64::from(f))
                .sum()
        };
        let ours = code_lengths(&fib, MAX_CODE_BITS);

        // the retry fallback, implemented here only to be measured against
        let mut scaled = fib.clone();
        let fallback = loop {
            let lengths = code_lengths(&scaled, 30);
            if lengths.iter().all(|&l| u32::from(l) <= MAX_CODE_BITS) {
                // charge the ORIGINAL frequencies: the scaling is a means, not the data
                break lengths;
            }
            for f in &mut scaled {
                if *f > 0 {
                    *f = (*f / 2).max(1);
                }
            }
        };
        assert!(fallback.iter().all(|&l| u32::from(l) <= MAX_CODE_BITS));
        assert!(
            cost(&ours) <= cost(&fallback),
            "package-merge {} must not cost more than the retry fallback {}",
            cost(&ours),
            cost(&fallback)
        );
    }

    #[test]
    fn canonical_codes_are_a_prefix_code_in_the_order_the_rfc_requires() {
        let lengths = [3u8, 3, 3, 3, 3, 2, 4, 4];
        let codes = canonical_codes(&lengths, MAX_CODE_BITS);
        // no code is a prefix of another
        for a in 0..lengths.len() {
            for b in 0..lengths.len() {
                if a == b || lengths[a] == 0 || lengths[b] == 0 {
                    continue;
                }
                let (la, lb) = (u32::from(lengths[a]), u32::from(lengths[b]));
                if la <= lb {
                    assert_ne!(
                        codes[b] >> (lb - la),
                        codes[a],
                        "code {a} is a prefix of code {b}"
                    );
                }
            }
        }
        // RFC 1951 3.2.2: shorter codes come first, and equal lengths ascend by symbol
        assert_eq!(codes[5], 0, "the only 2-bit code sorts first");
        assert!(
            codes[0] < codes[1] && codes[1] < codes[2],
            "equal lengths ascend by symbol"
        );
    }

    #[test]
    fn the_code_length_run_coder_reproduces_what_it_was_given() {
        // every shape the alphabet has a symbol for: a long zero run (18), a short one
        // (17), a repeat (16), and singletons that can use none of them
        let mut all = vec![0u8; 140];
        all.extend_from_slice(&[7, 7, 7, 7, 7, 7, 7]);
        all.extend_from_slice(&[0, 0, 0, 0]);
        all.extend_from_slice(&[9, 1, 9]);
        all.extend_from_slice(&[3; 6]);
        let rle = rle_code_lengths(&all);

        // decode it the way a decoder would, which is the only check that matters
        let mut back: Vec<u8> = Vec::new();
        for &(sym, extra, ebits) in &rle {
            match sym {
                16 => {
                    let prev = *back.last().expect("16 repeats a previous length");
                    assert!(ebits == 2);
                    assert!(extra <= 3);
                    for _ in 0..extra + 3 {
                        back.push(prev);
                    }
                }
                17 => {
                    assert!(ebits == 3);
                    assert!(extra <= 7);
                    back.extend(std::iter::repeat_n(0, extra as usize + 3));
                }
                18 => {
                    assert!(ebits == 7);
                    assert!(extra <= 127);
                    back.extend(std::iter::repeat_n(0, extra as usize + 11));
                }
                v => {
                    assert_eq!(ebits, 0, "a literal length has no extra bits");
                    back.push(v);
                }
            }
        }
        assert_eq!(back, all, "the run coder must be lossless");
        // and it has to be worth doing: 140 zeros cannot cost 140 symbols
        assert!(
            rle.len() < all.len() / 2,
            "no compression happened: {} symbols for {}",
            rle.len(),
            all.len()
        );
    }

    #[test]
    fn a_dynamic_block_is_actually_chosen_and_the_stream_still_decodes() {
        // WITHOUT THIS ARM THE WHOLE FEATURE COULD BE DELETED AND EVERY OTHER TEST WOULD
        // STILL PASS. The fixed path stays correct, the round trips stay green, the
        // ratio bars have headroom; the only thing that changes is a number nobody
        // asserts on. So this reads the BTYPE off the wire.
        let btype = |out: &[u8]| (out[0] >> 1) & 3;
        let data = narrow_alphabet();
        let out = deflate(&data);
        assert_eq!(
            btype(&out),
            2,
            "the first block should be dynamic (BTYPE 10) on this corpus"
        );

        // it has to be chosen for the right reason: because it is SMALLER. Recompute
        // what the same symbols would have cost fixed, from the same functions the
        // encoder decides with.
        let syms = lz77_at(&data, Level::DEFAULT);
        let chunk = &syms[..syms.len().min(BLOCK_SYMBOLS)];
        let dynamic = build_dynamic(chunk).expect("a non-empty chunk builds a code");
        assert!(
            dynamic.bits < fixed_bits(chunk),
            "dynamic claimed {} bits against fixed {}; it should not have been chosen",
            dynamic.bits,
            fixed_bits(chunk)
        );

        // THE CONTROL: the bits the block actually occupies must match what `build_dynamic`
        // counted, or the block-choosing comparison is deciding on a number that has
        // nothing to do with the output. Encode one block alone and measure it.
        let mut w = BitWriter::new();
        write_dynamic(&mut w, &dynamic, chunk, true);
        let one = w.finish();
        assert_eq!(
            one.len(),
            dynamic.bits.div_ceil(8),
            "the block cost {} bits but was counted at {}",
            one.len() * 8,
            dynamic.bits
        );

        // and it still says the same thing it did before
        let back = inflate(&out, DEFAULT_LIMIT).expect("a dynamic block must decode");
        assert!(back == data, "the bytes changed");

        // THE OTHER CONTROL: noise must NOT pick dynamic. A code fitted to a flat
        // histogram is 286 lengths of header buying nothing, and stored wins.
        let noisy = noise(200_000, 99);
        assert_eq!(
            btype(&deflate(&noisy)),
            0,
            "uniform noise should go out stored, not dynamic"
        );
    }

    /// Splits a gzip stream into its members.
    ///
    /// Uses the SHIPPED decoder's own `gunzip_member`, which already returns how many
    /// bytes the member consumed. Searching for the boundary by decoding every prefix is
    /// quadratic, and on a 12 MiB fixture it does not finish.
    /// A test that reimplements the thing under test gets both the cost and the bugs.
    fn members(stream: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < stream.len() {
            let (_, _, used) =
                gunzip_member(&stream[at..], DEFAULT_LIMIT).expect("every member must decode");
            assert!(
                used > 0,
                "a member consumed nothing; the split would not terminate"
            );
            out.push(stream[at..at + used].to_vec());
            at += used;
        }
        out
    }

    fn write_all_pieces<W: io::Write>(w: &mut W, data: &[u8], piece: usize) {
        for p in data.chunks(piece) {
            let mut rest = p;
            while !rest.is_empty() {
                let n = w.write(rest).expect("writing to a Vec cannot fail");
                rest = &rest[n..];
            }
        }
    }

    /// THE WHOLE POINT of `rsyncable`: insert a byte near the FRONT of an archive and
    /// almost every member past it must be BYTE-IDENTICAL to the one before the edit.
    ///
    /// With fixed 4 MiB cuts every later boundary shifts by one byte and every later
    /// member compresses differently, which is the control below.
    #[test]
    fn an_edit_near_the_front_leaves_the_later_members_untouched() {
        let base = noise(GZIP_BLOCK * 3, 4242);
        let mut edited = base.clone();
        edited.splice(1000..1000, *b"AN INSERTED RUN OF BYTES");

        let run = |data: &[u8], rsync: bool| {
            let mut w = if rsync {
                GzipWriter::rsyncable(Vec::new(), None, 0, 1)
            } else {
                GzipWriter::with_workers(Vec::new(), None, 0, 1)
            };
            write_all_pieces(&mut w, data, 250_000);
            w.finish().expect("finishing cannot fail")
        };

        let shared = |a: &[u8], b: &[u8]| -> (usize, usize) {
            let (ma, mb) = (members(a), members(b));
            let set: std::collections::HashSet<&Vec<u8>> = ma.iter().collect();
            (mb.iter().filter(|m| set.contains(m)).count(), mb.len())
        };

        let (rs_same, rs_total) = shared(&run(&base, true), &run(&edited, true));
        let (fx_same, fx_total) = shared(&run(&base, false), &run(&edited, false));
        // MEASURED on this fixture: rsyncable 11 of 12 members survive, fixed cuts 0 of 4.

        // The fixture has to be several members long or "most members survive" is a
        // statement about one member.
        assert!(
            rs_total >= 6,
            "rsyncable produced {rs_total} members; the fixture is too small"
        );

        // CONTROL FIRST, because it is what makes the number above mean anything: with
        // fixed cuts, the edit destroys the whole tail.
        assert!(
            fx_same <= 1,
            "fixed cuts shared {fx_same} of {fx_total} members after a 24-byte insert -- \
             if this is high the input is too compressible to measure anything"
        );

        // And the claim. Not "all": the members AROUND the edit legitimately change, and
        // the chunker needs a chunk to resynchronize. Everything after that is identical.
        let kept = rs_same as f64 / rs_total as f64;
        assert!(
            rs_same >= rs_total - 2,
            "rsyncable kept only {rs_same} of {rs_total} members ({kept:.0}%); an edit should \
             cost about one chunk, not the tail"
        );

        // and both streams still decode to what went in
        assert_eq!(
            gunzip(&run(&edited, true), DEFAULT_LIMIT).expect("must decode"),
            edited
        );
    }

    /// The limit means the same thing on both paths, met or exceeded.
    ///
    /// It has to be asserted rather than assumed, because the parallel path uses `limit`
    /// for a SECOND purpose the serial one does not have: it is also the cap on how much
    /// speculation may decode before it stops. A cap that was allowed to change the answer
    /// would make the output depend on the worker count, which is the one thing this
    /// design promises it cannot.
    ///
    /// So: exactly enough room decodes on both paths; one byte less is refused on both.
    #[test]
    fn the_limit_means_the_same_on_the_parallel_path_as_on_the_serial_one() {
        let words: [&[u8]; 4] = [b"deployment ", b"controller ", b"harvester ", b"cluster "];
        let mut data = Vec::new();
        let mut x = 31u64;
        while data.len() < GZIP_BLOCK * 3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(words[(x >> 32) as usize % words.len()]);
        }
        let stream = {
            let mut w = GzipWriter::with_workers(Vec::new(), None, 0, 1);
            write_all_pieces(&mut w, &data, 250_000);
            w.finish().expect("finishing cannot fail")
        };
        let n = data.len();

        // exactly enough: both paths produce the file
        assert_eq!(gunzip(&stream, n).expect("serial, exact limit"), data);
        assert_eq!(
            gunzip_with(&stream, n, 4).expect("parallel, exact limit"),
            data
        );

        // one byte short: both refuse, and neither returns a truncated file, which is the
        // failure a cap on speculation could have introduced
        assert!(
            gunzip(&stream, n - 1).is_err(),
            "the serial path accepted a limit below the output"
        );
        assert!(
            gunzip_with(&stream, n - 1, 4).is_err(),
            "the parallel path accepted a limit the serial path refused"
        );

        // and a limit that stops speculation early still gets the whole file, because the
        // chain inflates on demand whatever the pool did not reach
        speculated::reset();
        let capped = gunzip_with(&stream, n, 4).expect("decodes");
        assert_eq!(capped, data);
        let (tried, used) = speculated::count();
        assert!(
            tried > 0 && used > 0,
            "the parallel path was not entered: tried {tried}, used {used}"
        );
    }

    /// A COMPLETE, VALID gzip member hidden inside another member's compressed bytes.
    ///
    /// **This arm exists because a decoy of plausible headers is not the control it looks
    /// like.** Planting headers that look plausible to the cheap filter passes two replants
    /// it should fail: one that makes the chain trust every candidate, and one that removes
    /// the header filter entirely. The reason is that such decoys are random bytes behind a
    /// valid-looking header, so `gunzip_member` rejects them at the CRC -- they never become
    /// `Ok` results, and any reassembly of the `Ok` results in offset order happens to be
    /// right. The header filter and the CRC do the work; the chain is never tested.
    ///
    /// So here the decoy is a REAL gzip member, byte-for-byte, sitting inside the stored
    /// block of a larger one. It has correct magic, a correct deflate stream, a correct
    /// CRC-32 and a correct ISIZE. Every check short of the chain accepts it. The chain is
    /// the only thing that keeps `DECOY CONTENT` out of the output, because the chain
    /// never visits that offset.
    #[test]
    fn a_valid_gzip_member_hidden_inside_another_is_refused_by_the_chain_alone() {
        let decoy_content = b"DECOY CONTENT THAT MUST NEVER APPEAR IN THE OUTPUT".repeat(4);
        let decoy = {
            let mut w = GzipWriter::with_workers(Vec::new(), None, 0, 1);
            write_all_pieces(&mut w, &decoy_content, 1 << 20);
            w.finish().expect("finishing cannot fail")
        };
        assert_eq!(
            gunzip(&decoy, DEFAULT_LIMIT).unwrap(),
            decoy_content,
            "the decoy has to be a real member on its own"
        );

        // incompressible carrier, so the decoy's bytes reach the stream literally
        let mut data = Vec::new();
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut planted = 0;
        while data.len() < GZIP_BLOCK * 3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(&x.to_le_bytes());
            if data.len() % (900 << 10) < 8 {
                data.extend_from_slice(&decoy);
                planted += 1;
            }
        }
        assert!(planted >= 3, "only {planted} decoys planted");
        let stream = {
            let mut w = GzipWriter::with_workers(Vec::new(), None, 0, 1);
            write_all_pieces(&mut w, &data, 250_000);
            w.finish().expect("finishing cannot fail")
        };

        // THE PRECONDITION: the hidden members are intact in the stream and decode on
        // their own. Without this the arm is about something else entirely.
        let mut whole_decoys = 0;
        let mut at = 0;
        while at + decoy.len() <= stream.len() {
            if stream[at..at + decoy.len()] == decoy[..] {
                whole_decoys += 1;
                assert_eq!(
                    gunzip_member(&stream[at..], DEFAULT_LIMIT).unwrap().0,
                    decoy_content,
                    "a planted member should decode where it sits"
                );
            }
            at += 1;
        }
        assert!(whole_decoys >= 3, "only {whole_decoys} intact decoys survived compression; the carrier was not incompressible enough");

        speculated::reset();
        let got = gunzip_with(&stream, DEFAULT_LIMIT, 4).expect("decodes");
        // Compared by length and digest, NOT by `assert_eq!` on the vectors: the first
        // version of this line printed two 12 MB byte arrays on failure -- 55 MB of
        // output for one assertion, which is not a failure message anybody reads.
        let differs = got.len() != data.len() || got != data;
        assert!(
            !differs,
            "the output is not the input: {} bytes out for {} in, first difference at {:?}",
            got.len(),
            data.len(),
            got.iter().zip(&data).position(|(a, b)| a != b)
        );
        assert!(
            !got.windows(5).any(|w| w == b"DECOY") || data.windows(5).any(|w| w == b"DECOY"),
            "decoy content reached the output"
        );
        let (tried, used) = speculated::count();
        assert!(tried > used, "the hidden members should have been tried and left off the chain: tried {tried}, used {used}");
        assert_eq!(
            got,
            gunzip(&stream, DEFAULT_LIMIT).unwrap(),
            "the parallel and serial paths disagree"
        );
    }

    /// A multi-member gzip stream, inflated on several threads.
    ///
    /// The property is byte-equality with the serial path at every worker count. What
    /// makes that property worth asserting is the counter beside it: `gunzip_with` falls
    /// back to `gunzip` on anything it does not like, so an equality arm on its own passes
    /// beautifully while the parallel path is never entered. `speculated::count()` is what
    /// distinguishes "identical because it works" from "identical because it never ran".
    #[test]
    fn a_multi_member_stream_inflates_on_several_threads_and_the_chain_decides() {
        let words: [&[u8]; 6] = [
            b"deployment ",
            b"controller ",
            b"harvester ",
            b"cluster ",
            b"manifest ",
            b"the ",
        ];
        let mut data = Vec::with_capacity(GZIP_BLOCK * 5);
        let mut x = 7u64;
        while data.len() < GZIP_BLOCK * 5 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(words[(x >> 32) as usize % words.len()]);
        }
        let stream = {
            let mut w = GzipWriter::with_workers(Vec::new(), None, 0, 1);
            write_all_pieces(&mut w, &data, 250_000);
            w.finish().expect("finishing cannot fail")
        };
        let serial = gunzip(&stream, DEFAULT_LIMIT).expect("the serial path decodes");
        assert_eq!(serial, data);

        let mut entered = 0;
        for workers in [1usize, 2, 4, 8] {
            speculated::reset();
            let got =
                gunzip_with(&stream, DEFAULT_LIMIT, workers).expect("the parallel path decodes");
            assert_eq!(got, serial, "workers={workers} produced different bytes");
            let (tried, used) = speculated::count();
            if workers == 1 {
                // one worker is defined to BE the serial path, so nothing is speculated --
                // the control on the counter itself, which would otherwise be free to
                // count on every run and prove nothing
                assert_eq!((tried, used), (0, 0), "one worker must not speculate");
                continue;
            }
            assert!(
                tried > 0,
                "workers={workers}: the parallel path was never entered"
            );
            assert!(used > 1, "workers={workers}: the chain used {used} speculative results, so the stream had no members to share out");
            assert!(
                tried >= used,
                "workers={workers}: used {used} of {tried} tried, which is impossible"
            );
            entered += 1;
        }
        assert_eq!(
            entered, 3,
            "only {entered} of the 3 multi-worker counts entered the parallel path"
        );
    }

    /// A member whose COMPRESSED BYTES contain plausible gzip headers.
    ///
    /// This is the failure the design has to survive, and it is not hypothetical: on an
    /// 18.6 MB archive of this crate's own output the magic `1f 8b` occurs 367 times for
    /// 21 real members, and one of those false hits survives the header check as well. A
    /// scanner that trusted its candidates would splice garbage into the output.
    ///
    /// **The decoys have to be planted in INCOMPRESSIBLE data, and the first attempt was
    /// not.** It surrounded each decoy with a run of `0xAA` and repeated the pattern, which
    /// made the whole region compressible -- so deflate emitted it as matches and the
    /// `1f 8b 08 00` bytes never appeared in the stream at all. Measured: 200 occurrences
    /// of `1f 8b`, 4 surviving the header check, and those 4 were the real members. The arm
    /// passed and tested nothing, which the `tried == used` assertion is what caught.
    ///
    /// Pure random data stores rather than compresses, so the bytes pass through literally.
    /// Measured on this fixture: **222 occurrences of `1f 8b`, 21 surviving the header
    /// check, for 3 real members** -- eighteen plausible decoys.
    ///
    /// **What this arm proves, exactly.** It proves the HEADER FILTER and the CRC keep
    /// garbage out. It does NOT prove the chain does, and saying it did would be wrong:
    /// these decoys are random bytes behind a valid-looking header, so `gunzip_member`
    /// rejects them at the CRC and they never become results at all. Replanted both ways
    /// -- a chain that trusts every candidate, and no header filter -- this arm stays
    /// GREEN. `a_valid_gzip_member_hidden_inside_another_is_refused_by_the_chain_alone`
    /// is the one that tests the chain, and it was written because this one did not.
    #[test]
    fn gzip_headers_hiding_inside_compressed_bytes_cannot_enter_the_output() {
        let mut data = Vec::new();
        let mut x = 0x2545F491_4F6CDD1Du64;
        while data.len() < GZIP_BLOCK * 3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(&x.to_le_bytes());
            // magic, method 8, no reserved flag bits: everything the cheap filter checks
            if data.len() % (700 << 10) < 8 {
                data.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3]);
            }
        }
        let stream = {
            let mut w = GzipWriter::with_workers(Vec::new(), None, 0, 1);
            write_all_pieces(&mut w, &data, 250_000);
            w.finish().expect("finishing cannot fail")
        };

        // the decoys really are IN the compressed stream and really do survive the filter,
        // or this arm is a no-op dressed as a control
        let mut survivors = 0;
        let mut at = 0;
        while at + 18 <= stream.len() {
            if stream[at] == 0x1f
                && stream[at + 1] == 0x8b
                && stream[at + 2] == 8
                && stream[at + 3] & 0xe0 == 0
            {
                survivors += 1;
            }
            at += 1;
        }
        assert!(survivors > 6, "only {survivors} candidates survive the header check; the decoys were compressed away and this arm would test nothing");

        speculated::reset();
        let got = gunzip_with(&stream, DEFAULT_LIMIT, 4).expect("decodes");
        assert_eq!(got, data, "a false candidate reached the output");
        let (tried, used) = speculated::count();
        assert!(
            tried > used,
            "the decoys should have been tried and discarded: tried {tried}, used {used}"
        );
        assert_eq!(
            got,
            gunzip(&stream, DEFAULT_LIMIT).unwrap(),
            "the parallel and serial paths disagree"
        );
    }

    /// Smaller members compress worse: each restarts the match window and carries its own
    /// code tables. The penalty is recorded here so it cannot grow unnoticed.
    #[test]
    fn rsyncable_costs_ratio_and_the_cost_is_bounded() {
        // Compressible input, because on incompressible noise both modes store blocks and
        // the comparison would measure nothing.
        let words: [&[u8]; 6] = [
            b"deployment ",
            b"controller ",
            b"harvester ",
            b"cluster ",
            b"manifest ",
            b"the ",
        ];
        let mut data = Vec::with_capacity(GZIP_BLOCK * 3);
        let mut x = 99u64;
        while data.len() < GZIP_BLOCK * 3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.extend_from_slice(words[(x >> 32) as usize % words.len()]);
        }

        let run = |rsync: bool| {
            let mut w = if rsync {
                GzipWriter::rsyncable(Vec::new(), None, 0, 1)
            } else {
                GzipWriter::with_workers(Vec::new(), None, 0, 1)
            };
            write_all_pieces(&mut w, &data, 250_000);
            w.finish().expect("finishing cannot fail")
        };
        let (fixed, rsync) = (run(false), run(true));
        // MEASURED on this fixture: 1_018_028 bytes in 3 members with fixed cuts against
        // 1_022_801 in 34 with content-defined ones -- ELEVEN times as many members for
        // 0.47% more output. The member count is high because Gear on low-entropy text
        // cuts more often than the 1 MiB target; on the noise fixture in the arm above it
        // lands on 12 members for 12 MiB, which is the target exactly.
        let penalty = rsync.len() as f64 / fixed.len() as f64;
        assert!(
            penalty < 1.05,
            "rsyncable cost {:.1}% more than fixed cuts ({} vs {} bytes); the recorded cost \
             is under 5%, so either the chunking got finer or the encoder regressed",
            (penalty - 1.0) * 100.0,
            rsync.len(),
            fixed.len()
        );
        // CONTROL: a penalty of exactly 1.0 would mean the two modes produced the same
        // stream, i.e. `rsyncable` did nothing. It must actually cut differently.
        assert_ne!(
            rsync, fixed,
            "rsyncable produced the same bytes as fixed cuts -- it is inert"
        );
        assert_eq!(gunzip(&rsync, DEFAULT_LIMIT).expect("must decode"), data);
    }

    /// Members are still independent, so a rsyncable stream decodes in parallel and is a
    /// legal gzip file -- the two properties the fixed-cut stream already had, which a
    /// content-defined cut must not lose.
    #[test]
    fn a_rsyncable_stream_is_still_concatenated_independent_members() {
        let data = noise(GZIP_BLOCK * 2 + 12345, 7);
        let mut w = GzipWriter::rsyncable(Vec::new(), Some("t.tar"), 0, 1);
        write_all_pieces(&mut w, &data, 100_000);
        let stream = w.finish().expect("finishing cannot fail");

        let ms = members(&stream);
        assert!(ms.len() >= 3, "expected several members, got {}", ms.len());
        // each one decodes ON ITS OWN -- that is what "independent" means and what a
        // parallel decoder relies on
        let mut rejoined = Vec::new();
        for m in &ms {
            rejoined
                .extend_from_slice(&gunzip(m, DEFAULT_LIMIT).expect("each member decodes alone"));
        }
        assert_eq!(rejoined, data, "the members must rejoin into the input");
        assert_eq!(
            gunzip(&stream, DEFAULT_LIMIT).expect("the whole stream decodes"),
            data
        );
        // the name is on the first member only, same as the fixed-cut writer
        assert!(
            ms[0].windows(5).any(|w| w == b"t.tar"),
            "the first member must carry the name"
        );
        assert!(
            !ms[1..].iter().any(|m| m.windows(5).any(|w| w == b"t.tar")),
            "only the first"
        );
    }

    #[test]
    fn a_parallel_gzip_stream_is_byte_identical_to_the_serial_one() {
        use std::io::Write as _;
        // THE WHOLE CLAIM. Members are independent and a member is a pure function of its
        // input, so moving the work to a pool must not change one byte -- not the ratio,
        // not the framing, not which member carries the name. Anything else would mean
        // the output depends on scheduling, which is the bug this arm exists to refuse.
        //
        // The input is deliberately several members long and NOT a multiple of
        // GZIP_BLOCK, so the last member is a short one and the ordering has something
        // to get wrong.
        let data = {
            let mut d = noise(GZIP_BLOCK * 3 + 7777, 2026);
            // half compressible, so members differ in size and finish at different times
            // -- a pool that returned them in completion order would be caught here
            for (i, b) in d.iter_mut().enumerate().take(GZIP_BLOCK * 2) {
                if i % 3 == 0 {
                    *b = b'A';
                }
            }
            d
        };
        let run = |workers: usize| -> Vec<u8> {
            let mut w = GzipWriter::with_workers(Vec::new(), Some("t.tar"), 0, workers);
            // handed over in odd-sized pieces, so block boundaries fall mid-write
            for piece in data.chunks(333_333) {
                let mut rest = piece;
                while !rest.is_empty() {
                    let n = w.write(rest).expect("writing to a Vec cannot fail");
                    rest = &rest[n..];
                }
            }
            w.finish().expect("finishing cannot fail")
        };
        let serial = run(1);
        for workers in [2, 3, 8] {
            assert_eq!(
                run(workers),
                serial,
                "{workers} workers produced different bytes"
            );
        }

        // and it is a gzip stream that says the same thing
        assert_eq!(
            gunzip(&serial, DEFAULT_LIMIT).expect("the stream must decode"),
            data
        );

        // THE CONTROL: the fixture has to actually span several members, or "identical"
        // would be a statement about one member and the ordering would never be
        // exercised. Count the gzip magic pairs at member boundaries by decoding.
        let members = serial.windows(3).filter(|w| w == b"\x1f\x8b\x08").count();
        assert!(
            members >= 4,
            "the fixture produced {members} members; it must span several"
        );

        // and the pool must be what is under test: one worker is the serial path by
        // construction, so a `with_workers` that ignored its argument would pass every
        // assertion above. Two workers on input this size cannot finish in submission
        // order by luck alone -- but rather than assert on timing, assert the pool was
        // built at all.
        let pooled = GzipWriter::with_workers(Vec::new(), None, 0, 4);
        assert!(pooled.pool.is_some(), "with_workers(4) must build a pool");
        let plain = GzipWriter::with_workers(Vec::new(), None, 0, 1);
        assert!(
            plain.pool.is_none(),
            "with_workers(1) must stay on this thread"
        );
        drop(pooled.finish());
        drop(plain.finish());
    }

    /// Incompressible input does not come out BIGGER than it went in.
    ///
    /// With fixed-Huffman blocks alone it did, and by a margin that matters: a literal
    /// costs 8 bits for byte values under 144 and 9 above, so uniformly random bytes
    /// average 8.4375 bits each. Measured on 200 KB of noise before stored blocks
    /// existed: **200,000 -> 210,873, +5.44%**.
    ///
    /// That is not a corner case for this crate. `rcp copy /tree tar://out.tar.gz` over
    /// an OCI layout, a photo library, or anything already compressed is exactly this
    /// input, and the operator asked for compression and got expansion under a name that
    /// promises the opposite. `gzip` has never had the problem, because a stored block
    /// costs five bytes per 64 KiB and it falls back to one.
    ///
    /// The bound here is +1%, not +0.01%: the block decision is per `BLOCK_SYMBOLS`
    /// chunk, so a chunk that is *just* compressible enough still goes out fixed, and
    /// pinning the arm to the theoretical floor would make it fail on a change to
    /// `BLOCK_SYMBOLS` that is not a defect.
    #[test]
    fn incompressible_input_is_not_inflated() {
        let mut noise = Vec::with_capacity(200_000);
        let mut x: u64 = 0xdead_beef;
        while noise.len() < 200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.extend_from_slice(&x.to_le_bytes());
        }
        let out = deflate(&noise);
        let overhead = out.len() as f64 / noise.len() as f64 - 1.0;
        assert!(
            overhead < 0.01,
            "noise grew {:+.2}% ({} bytes from {}); the stored-block fallback is not firing",
            overhead * 100.0,
            out.len(),
            noise.len()
        );

        // THE CONTROL. A "stored block" that dropped or reordered bytes would be
        // smaller or the same size and completely wrong, and the assertion above cannot
        // tell the difference.
        let back = inflate(&out, DEFAULT_LIMIT).expect("stored blocks must decode");
        assert!(back == noise, "the bytes changed");

        // THE SECOND CONTROL: choosing stored must not have become unconditional. Text
        // has to still compress hard, or the encoder has quietly turned into `cat`.
        let text = "the quick brown fox jumps over the lazy dog\n"
            .repeat(10_000)
            .into_bytes();
        let packed = deflate(&text);
        assert!(packed.len() < text.len() / 50, "text compressed to {} bytes from {}; stored blocks are being chosen when they should not be", packed.len(), text.len());

        // A span longer than one stored block (65535) must be split into several, with
        // BFINAL on the last alone -- a stream with two final blocks stops early and a
        // stream with none runs off the end.
        let mut big = Vec::with_capacity(300_000);
        let mut y: u64 = 0x1234_5678;
        while big.len() < 300_000 {
            y ^= y << 13;
            y ^= y >> 7;
            y ^= y << 17;
            big.extend_from_slice(&y.to_le_bytes());
        }
        let out = deflate(&big);
        assert!(
            inflate(&out, DEFAULT_LIMIT).unwrap() == big,
            "a span over 65535 bytes did not survive being split across stored blocks"
        );
    }

    /// Everything this encoder writes, its own decoder reads back byte for byte.
    ///
    /// The round trip is necessary and not sufficient -- an encoder and decoder that share
    /// a misunderstanding agree with each other perfectly. The arm after this one is the
    /// one that settles it, against the system `gzip`.
    #[test]
    fn what_the_encoder_writes_the_decoder_reads_back() {
        let text = "the quick brown fox jumps over the lazy dog. "
            .repeat(400)
            .into_bytes();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![7]),
            ("two bytes", vec![7, 7]),
            ("a run", vec![0xab; 100_000]),
            ("text", text.clone()),
            ("noise", noise(200_000, 12345)),
            // every byte value, so the 9-bit half of the fixed literal code is exercised
            ("all 256", (0..=255u8).cycle().take(70_000).collect()),
            // a match at the maximum length and one at the maximum distance
            ("long match", {
                let mut v = vec![1u8; MAX_MATCH + 10];
                v.extend_from_slice(&vec![1u8; MAX_MATCH + 10]);
                v
            }),
            ("far match", {
                let mut v = noise(WINDOW - 8, 99);
                let head: Vec<u8> = v[..64].to_vec();
                v.extend_from_slice(&head);
                v
            }),
        ];
        for (what, data) in cases {
            let packed = deflate(&data);
            let back = inflate(&packed, DEFAULT_LIMIT).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(
                back.len(),
                data.len(),
                "{what}: {} bytes back from {}",
                back.len(),
                data.len()
            );
            assert!(back == data, "{what}: the bytes differ");
            let wrapped = gzip(&data, Some("x.bin"), 0);
            let back =
                gunzip(&wrapped, DEFAULT_LIMIT).unwrap_or_else(|e| panic!("{what} gzip: {e}"));
            assert!(back == data, "{what}: the gzip round trip differs");
        }

        // the control: it must actually COMPRESS the compressible cases, or the arm above
        // would pass on an encoder that emitted every byte as a literal
        let runs = vec![0xabu8; 100_000];
        assert!(
            deflate(&runs).len() < 1000,
            "a 100k run compressed to {} bytes",
            deflate(&runs).len()
        );
        assert!(
            deflate(&text).len() < text.len() / 4,
            "text compressed to {} of {}",
            deflate(&text).len(),
            text.len()
        );
    }

    /// The fixed code must be COMPLETE, and an empty fixed block must decode.
    ///
    /// Hermetic, unlike the `gzip` interop arm, which skips where `gzip` is absent -- and
    /// this is exactly the defect that arm found: `fixed()` built the literal/length table
    /// over `MAXLCODES` (286, the dynamic-block limit) instead of `FIXLCODES` (288), so it
    /// summed to 254/256 and two of every 256 eight-bit patterns decoded to no symbol.
    /// `03 00` is what `gzip -9` writes for an empty file: BFINAL=1, BTYPE=01, then the
    /// seven zero bits of end-of-block.
    #[test]
    fn the_fixed_code_is_complete_and_an_empty_fixed_block_decodes() {
        let (lit, dist) = fixed().expect("the fixed code must build");
        // completeness, read off the tables rather than inferred: the counts must satisfy
        // Kraft with nothing left over, for BOTH trees
        for (name, h, total) in [("literal/length", &lit, FIXLCODES), ("distance", &dist, 32)] {
            let used: usize = h.count[1..].iter().map(|&c| c as usize).sum();
            assert_eq!(
                used + h.count[0] as usize,
                total,
                "{name}: {used} coded of {total}"
            );
            let mut left: i64 = 1;
            for len in 1..=MAXBITS {
                left = left * 2 - i64::from(h.count[len]);
            }
            assert_eq!(
                left, 0,
                "{name} code leaves {left} of its space unreachable"
            );
        }

        assert_eq!(
            inflate(&[0x03, 0x00], DEFAULT_LIMIT).expect("an empty fixed block"),
            Vec::<u8>::new()
        );

        // The control: the 286-length table is the old wiring, and it must NOT be complete.
        // Without this the arm would pass against code that never had the defect.
        let mut short = [0u8; MAXLCODES];
        for (i, l) in short.iter_mut().enumerate() {
            *l = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let e = match Huffman::new(&short) {
            Ok(_) => panic!("a 286-symbol fixed table must not build: it is incomplete"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("incomplete"), "{e}");
    }

    /// CRC-32 against the value every implementation agrees on.
    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(
            crc32(b"123456789"),
            0xcbf4_3926,
            "the CRC-32 check value is wrong"
        );
        assert_eq!(crc32(b""), 0, "an empty input must hash to zero");
        // the control: a one-bit change must change it
        assert_ne!(crc32(b"123456789"), crc32(b"123456788"));
    }

    /// A stored (uncompressed) block, hand-built, so the block framing is exercised
    /// without depending on any encoder at all.
    #[test]
    fn a_stored_block_round_trips() {
        let payload = b"the quick brown fox";
        let mut s = vec![0x01]; // BFINAL=1, BTYPE=00, then padding to the byte
        s.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        s.extend_from_slice(payload);
        assert_eq!(inflate(&s, DEFAULT_LIMIT).unwrap(), payload);

        // the control: corrupt the complement and it must be refused, not decoded
        let mut bad = s.clone();
        bad[3] ^= 0xff;
        let e = inflate(&bad, DEFAULT_LIMIT).unwrap_err().to_string();
        assert!(e.contains("complement disagree"), "{e}");
    }

    /// The limit is on the OUTPUT, which is the direction that grows.
    #[test]
    fn a_stream_larger_than_the_limit_is_refused_rather_than_allocated() {
        let payload = vec![b'x'; 1000];
        let mut s = vec![0x01];
        s.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        s.extend_from_slice(&payload);
        let e = inflate(&s, 999).unwrap_err().to_string();
        assert!(e.contains("larger than the limit"), "{e}");
        // the control: one byte more room and the same stream decodes
        assert_eq!(inflate(&s, 1000).unwrap().len(), 1000);
    }

    /// A truncated stream is an error and never a short read.
    #[test]
    fn a_truncated_stream_is_refused() {
        let mut s = vec![0x01];
        s.extend_from_slice(&100u16.to_le_bytes());
        s.extend_from_slice(&(!100u16).to_le_bytes());
        s.extend_from_slice(b"only a few bytes");
        let e = inflate(&s, DEFAULT_LIMIT).unwrap_err().to_string();
        assert!(e.contains("runs past the end"), "{e}");
    }

    /// An over-subscribed code is refused when the tables are built, not decoded into
    /// whatever the symbol array happens to hold.
    #[test]
    fn an_over_subscribed_huffman_code_is_refused() {
        // three symbols of length 1: only two codes of that length exist
        let e = match Huffman::new(&[1, 1, 1]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("three symbols of length 1 is over-subscribed and was accepted"),
        };
        assert!(e.contains("over-subscribed"), "{e}");
        // the controls: two of length 1 is complete, and all-zero is the legal empty code
        assert!(Huffman::new(&[1, 1]).is_ok());
        assert!(Huffman::new(&[0, 0, 0]).is_ok());
        let e = match Huffman::new(&[16]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a code length of 16 was accepted"),
        };
        assert!(e.contains("above 15"), "{e}");
    }

    /// A gzip header with a reserved flag bit, and one that is not gzip at all.
    #[test]
    fn a_member_that_is_not_gzip_is_refused_by_name() {
        assert!(gunzip(&[0u8; 20], DEFAULT_LIMIT).is_err());
        let mut not_gz = vec![0x1f, 0x8b, 8, 0];
        not_gz.extend_from_slice(&[0u8; 20]);
        assert!(gunzip(&not_gz, DEFAULT_LIMIT).is_err());
        let mut wrong_method = vec![0x1f, 0x8b, 9, 0];
        wrong_method.extend_from_slice(&[0u8; 20]);
        let e = gunzip(&wrong_method, DEFAULT_LIMIT)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not deflate-compressed"), "{e}");
        assert!(!is_gzip(b"PK\x03\x04"));
        assert!(is_gzip(&[0x1f, 0x8b, 8]));
    }
}

#[cfg(test)]
mod against_real_gzip {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    /// Decodes what THIS MACHINE's `gzip` and `tar` wrote, and compares against the
    /// original bytes.
    ///
    /// A decoder tested only against its own encoder is tested against its own
    /// misunderstandings. These vectors come from the reference implementation, at
    /// several levels and input shapes so that each block type is exercised:
    /// incompressible input makes `gzip` emit STORED blocks, `-1` on text emits FIXED
    /// Huffman, `-9` emits DYNAMIC.
    ///
    /// The fixtures are BUILT HERE rather than read from a path, because a fixture
    /// directory that exists only on the machine that made it turns this arm into a
    /// silent skip everywhere else -- the failure mode this project has already been
    /// caught by twice. If `gzip` cannot run, the arm says so and says what was missed;
    /// that is a gap in coverage, not a pass.
    fn gz(dir: &Path, args: &[&str], input: &Path, out: &Path) -> bool {
        let Ok(f) = std::fs::File::create(out) else {
            return false;
        };
        Command::new("gzip")
            .current_dir(dir)
            .args(args)
            .arg("-c")
            .arg(input)
            .stdout(f)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn it_decodes_what_the_system_gzip_wrote() {
        let dir = std::env::temp_dir().join(format!("rcp-gz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Incompressible, so the encoder falls back to stored blocks. Deterministic
        // rather than /dev/urandom: a failing run must be reproducible.
        let mut random = Vec::with_capacity(200_000);
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        while random.len() < 200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            random.extend_from_slice(&x.to_le_bytes());
        }
        let text = "the quick brown fox jumps over the lazy dog\n"
            .repeat(5000)
            .into_bytes();
        for (name, bytes) in [
            ("random.bin", &random),
            ("text.txt", &text),
            ("empty.bin", &Vec::new()),
            ("one.bin", &b"a".to_vec()),
        ] {
            std::fs::write(dir.join(name), bytes).unwrap();
        }

        if !gz(
            &dir,
            &["-9", "-k"],
            &dir.join("random.bin"),
            &dir.join("random.gz"),
        ) {
            eprintln!("SKIP: `gzip` did not run here, so the decoder was NOT checked against the reference implementation -- only against the hand-built vectors in the sibling arms");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        assert!(gz(
            &dir,
            &["-1", "-k"],
            &dir.join("text.txt"),
            &dir.join("text1.gz")
        ));
        assert!(gz(
            &dir,
            &["-9", "-k"],
            &dir.join("text.txt"),
            &dir.join("text9.gz")
        ));
        assert!(gz(
            &dir,
            &["-9"],
            &dir.join("empty.bin"),
            &dir.join("empty.gz")
        ));
        assert!(gz(&dir, &["-9"], &dir.join("one.bin"), &dir.join("one.gz")));

        for (gzf, raw) in [
            ("random.gz", "random.bin"),
            ("text1.gz", "text.txt"),
            ("text9.gz", "text.txt"),
            ("empty.gz", "empty.bin"),
            ("one.gz", "one.bin"),
        ] {
            let comp = std::fs::read(dir.join(gzf)).unwrap();
            let want = std::fs::read(dir.join(raw)).unwrap();
            let got = gunzip(&comp, DEFAULT_LIMIT).unwrap_or_else(|e| panic!("{gzf}: {e}"));
            assert_eq!(
                got.len(),
                want.len(),
                "{gzf}: decoded {} bytes, the original is {}",
                got.len(),
                want.len()
            );
            assert!(got == want, "{gzf}: the bytes differ from the original");
        }

        // Two members concatenated is a legal gzip file holding both, and is what
        // `pigz -i` writes. Stopping at the first would return a PREFIX of the data.
        let mut multi = std::fs::read(dir.join("text1.gz")).unwrap();
        multi.extend_from_slice(&std::fs::read(dir.join("text9.gz")).unwrap());
        let got = gunzip(&multi, DEFAULT_LIMIT).unwrap();
        assert_eq!(
            got.len(),
            text.len() * 2,
            "a two-member stream decoded to one member's worth"
        );
        assert!(
            got == [text.clone(), text.clone()].concat(),
            "the members did not decode to the same content twice"
        );

        // A real .tar.gz, if tar is here: the result must BE a tar, which its own magic says.
        std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
        std::fs::write(dir.join("tree/text.txt"), &text).unwrap();
        std::fs::write(dir.join("tree/sub/one.bin"), b"a").unwrap();
        if Command::new("tar")
            .current_dir(&dir)
            .args(["czf", "tree.tar.gz", "tree"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            let tgz = gunzip(
                &std::fs::read(dir.join("tree.tar.gz")).unwrap(),
                DEFAULT_LIMIT,
            )
            .unwrap();
            assert!(
                tgz.len() >= 512 && &tgz[257..262] == b"ustar",
                "the decoded .tar.gz is not a tar stream"
            );
            assert_eq!(
                tgz.len() % 512,
                0,
                "a tar stream is a whole number of 512-byte records"
            );
        }

        // `gzip -k` stores the original name; the header reader must give it back, and the
        // member must account for exactly its own file with nothing left over.
        let nine = std::fs::read(dir.join("text9.gz")).unwrap();
        let (_, h, used) = gunzip_member(&nine, DEFAULT_LIMIT).unwrap();
        assert_eq!(
            h.name.as_deref(),
            Some("text.txt"),
            "the stored name was not read back"
        );
        assert_eq!(
            used,
            nine.len(),
            "the member did not account for its whole file"
        );

        // THE CONTROL, and the reason the CRC check is not optional: flipping one bit of
        // the compressed body must FAIL rather than return different bytes. Without this
        // every arm above would still pass against a decoder that quietly produced
        // garbage on damaged input.
        let mut corrupt = nine.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0x01;
        match gunzip(&corrupt, DEFAULT_LIMIT) {
            Err(_) => {}
            Ok(bytes) => panic!(
                "a corrupted member decoded to {} bytes instead of failing",
                bytes.len()
            ),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The system `gzip` and `tar` read what THIS encoder wrote.
    ///
    /// The round trip in `what_the_encoder_writes_the_decoder_reads_back` is necessary
    /// and not sufficient: an encoder and a decoder that share a misunderstanding agree
    /// with each other perfectly. This is the arm that settles it, because the reference
    /// implementation has no share in our misunderstandings.
    ///
    /// The point of the encoder is `rcp copy /tree tar://out.tar.gz`, so the `tar` case
    /// is not decoration -- it is the thing being shipped. Before this encoder existed
    /// that command wrote a PLAIN TAR under a `.gz` name, which every reader rejects.
    #[test]
    fn the_system_gzip_reads_what_this_encoder_wrote() {
        let dir = std::env::temp_dir().join(format!("rcp-gzenc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let text = "the quick brown fox jumps over the lazy dog\n"
            .repeat(5000)
            .into_bytes();
        let mut random = Vec::with_capacity(200_000);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        while random.len() < 200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            random.extend_from_slice(&x.to_le_bytes());
        }

        // `gzip -d -c` on our bytes, back through a pipe. A decoder that accepted
        // anything would make this arm vacuous, so the control at the end plants a
        // one-bit fault and requires the same command to REFUSE it.
        let decode = |bytes: &[u8], name: &str| -> Option<Vec<u8>> {
            let p = dir.join(name);
            std::fs::write(&p, bytes).ok()?;
            let out = Command::new("gzip")
                .arg("-d")
                .arg("-c")
                .arg(&p)
                .output()
                .ok()?;
            if out.status.success() {
                Some(out.stdout)
            } else {
                None
            }
        };

        // Does gzip run at all? A missing binary is a GAP in coverage, said out loud,
        // never a pass -- this project has been caught by a silent skip twice.
        if decode(&gzip(b"probe", None, 0), "probe.gz").as_deref() != Some(&b"probe"[..]) {
            eprintln!("SKIP: `gzip` did not run here, so the ENCODER was NOT checked against the reference implementation -- only against rcp's own decoder, which shares its assumptions");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // A match at EXACTLY the maximum window distance, 32768. `noise(WINDOW)` then
        // a copy of its first bytes puts the candidate at `i - WINDOW`, the oldest
        // position the matcher will still accept.
        let far = {
            let mut v = Vec::with_capacity(WINDOW + 64);
            let mut x: u64 = 7;
            while v.len() < WINDOW {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push((x >> 24) as u8);
            }
            let head: Vec<u8> = v[..64].to_vec();
            v.extend_from_slice(&head);
            v
        };

        for (what, data) in [
            ("empty", Vec::new()),
            ("one byte", vec![b'a']),
            ("text", text.clone()),
            ("incompressible", random.clone()),
            // a run this long forces LENGTH 258, which has two encodings in RFC 1951 --
            // code 285 with no extra bits, and code 284 with five. rcp's own decoder
            // accepts both, so only a foreign decoder can say which one went out.
            ("a long run", vec![0x5au8; 300_000]),
            ("a match at the window's edge", far),
            (
                "every byte value",
                (0..=255u8).cycle().take(70_000).collect::<Vec<u8>>(),
            ),
        ] {
            let ours = gzip(&data, Some("payload.bin"), 0);
            let got = decode(&ours, "ours.gz").unwrap_or_else(|| {
                panic!(
                    "{what}: the system gzip refused {} bytes this encoder wrote",
                    ours.len()
                )
            });
            assert_eq!(
                got.len(),
                data.len(),
                "{what}: gzip decoded {} bytes, the original is {}",
                got.len(),
                data.len()
            );
            assert!(
                got == data,
                "{what}: the system gzip decoded different bytes"
            );
        }

        // The shipped use: a tar stream wrapped by this encoder must unpack with `tar`,
        // which validates the gzip member AND the tar records inside it.
        let mut tarball = Vec::new();
        {
            let mut hdr = [0u8; 512];
            let name = b"hello.txt";
            hdr[..name.len()].copy_from_slice(name);
            hdr[100..108].copy_from_slice(b"0000644\0");
            hdr[108..116].copy_from_slice(b"0000000\0");
            hdr[116..124].copy_from_slice(b"0000000\0");
            hdr[124..136].copy_from_slice(b"00000000013\0"); // the size field is OCTAL: 013 is 11 bytes
            hdr[136..148].copy_from_slice(b"00000000000\0");
            hdr[148..156].copy_from_slice(b"        "); // checksum field blank while summing
            hdr[156] = b'0';
            hdr[257..263].copy_from_slice(b"ustar\0");
            hdr[263..265].copy_from_slice(b"00");
            let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
            let oct = format!("{sum:06o}\0 ");
            hdr[148..156].copy_from_slice(oct.as_bytes());
            tarball.extend_from_slice(&hdr);
            let mut body = [0u8; 512];
            body[..11].copy_from_slice(b"hello there");
            tarball.extend_from_slice(&body);
            tarball.extend_from_slice(&[0u8; 1024]); // the two zero records that end a tar
        }
        std::fs::write(dir.join("t.tar.gz"), gzip(&tarball, Some("t.tar"), 0)).unwrap();
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let unpacked = Command::new("tar")
            .current_dir(&dir)
            .args(["xzf", "t.tar.gz", "-C", "out"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if unpacked {
            let back = std::fs::read(dir.join("out/hello.txt")).unwrap();
            assert!(
                back == b"hello there",
                "tar unpacked {back:?} from a .tar.gz this encoder wrote"
            );
        } else {
            eprintln!("NOTE: `tar` did not unpack the archive; `gzip` above still validated the member, so the wrapper is checked and the tar pairing is not");
        }

        // The stored name must survive a real reader, not only ours. `gzip -dN` is the
        // command that READS it: it writes the decompressed file under the name in the
        // header rather than the one derived from the path.
        //
        // `gzip -l -v` is NOT that command, and using it here cost a red run. Its
        // "uncompressed_name" column is derived from the FILE PATH -- a reference gzip
        // file copied to `renamed.gz` reports `renamed` too, so the column would have
        // agreed with us whether or not we stored anything at all.
        let stored = dir.join("stored");
        std::fs::create_dir_all(&stored).unwrap();
        std::fs::write(
            stored.join("wrong-name.gz"),
            gzip(&text, Some("text.txt"), 1_700_000_000),
        )
        .unwrap();
        if Command::new("gzip")
            .current_dir(&stored)
            .args(["-d", "-N", "wrong-name.gz"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            assert!(
                stored.join("text.txt").exists(),
                "gzip -dN did not find the name this encoder stored; it wrote {:?}",
                std::fs::read_dir(&stored)
                    .unwrap()
                    .filter_map(|e| e.ok().map(|e| e.file_name()))
                    .collect::<Vec<_>>()
            );
            assert!(
                std::fs::read(stored.join("text.txt")).unwrap() == text,
                "the file gzip -dN wrote holds different bytes"
            );
        } else {
            eprintln!("NOTE: `gzip -dN` did not run, so the stored FNAME was not checked against a real reader");
        }

        // THE CONTROL. Everything above would also pass against a `gzip` that accepted
        // any bytes at all. Flip one bit in the body and the same command must FAIL --
        // which is also what proves our CRC32 and length trailer are the real ones.
        let mut corrupt = gzip(&text, None, 0);
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0x01;
        assert!(decode(&corrupt, "corrupt.gz").is_none(), "the system gzip accepted a corrupted member, so it was not validating any of the arms above");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
