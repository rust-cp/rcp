//! The wire format between an `ssh://` client and `rcp serve`: length-prefixed frames of
//! XDR-style fields (the same codec the NFS client uses), one request and one response per
//! sequence number, answered in order so a client can keep several READs or WRITEs in
//! flight on one stream. Every operation mirrors one method of the `Tree` port, plus a
//! streaming SEGMENTS for `Tree::read`, so holes cross the wire as lengths, not zeros.

use std::borrow::Cow;
use std::io::{self, Read, Write};

use crate::catalog::Kind;
use crate::filter::Filter;
use crate::ports::{Basis, ChunkSig, Item, MetaOptions, Refusals, Removed, DIGEST_LEN};
use crate::xdr::{Decoder, Encoder};

/// 2 adds the weak fingerprint to every chunk signature. The server refuses a version it
/// does not speak, so a mixed pair fails by name rather than mis-parsing a frame -- which
/// is why the field is added unconditionally rather than behind a negotiated flag.
pub const VERSION: u32 = 5;
/// The HELLO for a codec other than LZ4. Version 5 stays exactly what it was -- raw or LZ4,
/// one bool -- so every peer that speaks it still does. A codec that needs more than a bool
/// asks with version 6 and names itself with a u32 tag, and a serve that does not speak 6
/// refuses the version before it reads a path, which names the gap instead of leaving a
/// stream the far side cannot read. v6 began as zstd alone (tag 2, no level); DEFLATE
/// joined it with tag 3 and a trailing level word, read only for that tag, so a v6 HELLO
/// from a zstd-only peer is still read correctly here.
pub const CODEC_VERSION: u32 = 6;

pub const OP_HELLO: u32 = 0;
pub const OP_LIST: u32 = 1;
pub const OP_STAT: u32 = 2;
pub const OP_OPEN_READ: u32 = 3;
pub const OP_READ: u32 = 4;
pub const OP_CLOSE: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_RESERVE: u32 = 7;
pub const OP_WRITE: u32 = 8;
pub const OP_HOLE: u32 = 9;
pub const OP_FINISH: u32 = 10;
pub const OP_MKDIR: u32 = 11;
pub const OP_SYMLINK: u32 = 12;
pub const OP_HARDLINK: u32 = 13;
pub const OP_REMOVE: u32 = 14;
pub const OP_RENAME: u32 = 15;
pub const OP_SETMETA: u32 = 16;
pub const OP_XATTRS: u32 = 17;
pub const OP_SETXATTRS: u32 = 18;
pub const OP_RESTORE_ATIME: u32 = 19;
pub const OP_SYNC: u32 = 20;
pub const OP_SEGMENTS: u32 = 21;
/// Delta transfer: the far side signs a file, or matches one against signatures sent in
/// batches, or rebuilds one as a patch against the file it has.
pub const OP_SIGNATURES: u32 = 22;
pub const OP_DELTA_BEGIN: u32 = 23;
pub const OP_DELTA_SIGS: u32 = 24;
pub const OP_DELTA_RUN: u32 = 25;
pub const OP_CREATE_PATCH: u32 = 26;
pub const OP_COPY_BASIS: u32 = 27;
pub const OP_EXPECT: u32 = 28;
/// A channel after the first joins the tree the first one opened. Same body and same reply
/// as HELLO; what differs is what the far side asserts. HELLO checks the endpoint is there
/// (a tag to read, a directory to serve) because a missing one is the user's mistake; a
/// join is not the place to discover that, since the first channel already did, and what
/// the run has done since then -- deleted the last tag, not yet published the first --
/// can make the same check false for a tree that is fine. A serve from before this op
/// answers it `Unsupported`, and the client then sends HELLO on the same channel.
pub const OP_ATTACH: u32 = 29;

/// SIGNATURES answers: batches of signatures, then the end.
pub const SIG_BATCH: u32 = 0;
pub const SIG_END: u32 = 1;
/// DELTA_RUN answers: patch steps, then the end carrying the whole file's digest.
pub const PATCH_LITERAL: u32 = 0;
pub const PATCH_COPY: u32 = 1;
pub const PATCH_HOLE: u32 = 2;
pub const PATCH_END: u32 = 3;

/// SEGMENTS answers: a data frame, a hole frame, then the end.
pub const SEG_DATA: u32 = 0;
pub const SEG_HOLE: u32 = 1;
pub const SEG_END: u32 = 2;

/// LIST answers: batches of items, batches of error strings, then the end, so a listing
/// of any size crosses in frames under the limit instead of one frame that cannot.
pub const LIST_ITEMS: u32 = 0;
pub const LIST_ERRORS: u32 = 1;
pub const LIST_END: u32 = 2;
/// Items per LIST batch; at the port's item size that is well under a megabyte a frame.
pub const LIST_BATCH: usize = 2048;

/// The largest frame either side accepts (a READ or WRITE payload plus its header).
pub const MAX_FRAME: usize = 16 << 20;

/// A data payload (READ reply, WRITE request, SEG_DATA, PATCH_LITERAL) carries a flag
/// saying how its bytes are encoded, so each one can be sent raw when compressing it
/// would not pay.
///
/// **The numbers are the wire's, and zstd holds 2 because an earlier release used it.**
/// Giving 2 to any other codec would make the same payload read as a different codec by a
/// peer from that release, so DEFLATE takes 3.
pub const PAYLOAD_RAW: u32 = 0;
pub const PAYLOAD_LZ4: u32 = 1;
pub const PAYLOAD_ZSTD: u32 = 2;
pub const PAYLOAD_DEFLATE: u32 = 3;

/// Which compressor a stream uses, agreed in HELLO: LZ4 under version 5, DEFLATE or zstd
/// under version 6 (see `CODEC_VERSION`).
///
/// zstd is this crate's own codec (`crate::zstd`) in every build. With `--features system-zstd`
/// the same frames are made and read by the system libzstd instead (`crate::zstd_system`).
/// The two interoperate: this encoder writes one single-segment frame that declares
/// its size, which is what the libzstd path requires, and this decoder was verified
/// against frames the reference library produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Codec {
    /// Fast, low ratio. The default, and what `-compress` alone selects.
    #[default]
    Lz4,
    /// Slower, higher ratio on text. `-compress.codec deflate`.
    Deflate,
    /// Real zstd frames on the wire. `-compress.codec zstd`.
    ///
    /// The encoder emits Huffman-coded literals and FSE-coded sequences, so what crosses
    /// is an ordinary zstd frame that `zstd -d` reads; the decoder reads the whole format
    /// back, verified against frames the reference produced at three levels over five
    /// corpora. No level knob -- see `compress` -- and no dictionary support.
    ///
    /// **It shipped 59% behind this crate's own DEFLATE, and the fix was the search rather
    /// than the format.** Measured on the contract arm's 4.5 MB of log-shaped text, wire
    /// bytes: plain ~4,537,400, lz4 ~1,118,400, **zstd ~605,000**, deflate ~602,600 --
    /// a coin flip between the two slow codecs. Getting there was lazy matching
    /// (960,872 -> 856,164), FSE sequence tables built from each block's own symbol counts
    /// (-> 630,260) and repeat offsets (-> 605,008); a deeper match chain was tried and
    /// reverted at 0.16%. What zstd buys over DEFLATE is that the FRAMES are zstd -- a
    /// peer, a pipe or an archive that already speaks it needs nothing from us.
    Zstd,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Lz4 => "lz4",
            Codec::Deflate => "deflate",
            Codec::Zstd => "zstd",
        }
    }
    pub fn by_name(name: &str) -> Option<Codec> {
        match name {
            "lz4" => Some(Codec::Lz4),
            "deflate" => Some(Codec::Deflate),
            "zstd" => Some(Codec::Zstd),
            _ => None,
        }
    }
    /// The number that crosses the wire in HELLO and as a payload flag.
    pub fn flag(self) -> u32 {
        match self {
            Codec::Lz4 => PAYLOAD_LZ4,
            Codec::Deflate => PAYLOAD_DEFLATE,
            Codec::Zstd => PAYLOAD_ZSTD,
        }
    }
    pub fn from_flag(flag: u32) -> Option<Codec> {
        match flag {
            PAYLOAD_LZ4 => Some(Codec::Lz4),
            PAYLOAD_DEFLATE => Some(Codec::Deflate),
            PAYLOAD_ZSTD => Some(Codec::Zstd),
            _ => None,
        }
    }
    /// `level` is 1..=9 in zlib's sense and **only DEFLATE reads it**. LZ4 here is the
    /// single-pass block format with no level knob at all.
    ///
    /// The command line REFUSES that combination rather than ignoring it. It is tempting to
    /// argue that refusing would trap anyone who had not also typed
    /// `-compress.codec deflate`; but the real trap is the SUCCESS -- exit 0, no warning, no
    /// reply field echoing the level actually used, and a caller who reasonably believes the
    /// number did something. This function still takes the level unconditionally because the
    /// WIRE has to tolerate what a peer sends; the refusal belongs at the option, where
    /// someone is present to answer.
    fn compress(self, data: &[u8], level: u8) -> Vec<u8> {
        match self {
            Codec::Lz4 => crate::lz4::compress(data),
            Codec::Deflate => crate::deflate::deflate_at(data, crate::deflate::Level::of(level)),
            // No level yet: this encoder has one match search, so a level would be a knob
            // that changes nothing. Saying so is the point -- a silently ignored level is
            // exactly the trap the DEFLATE knob's own refusal exists to avoid.
            Codec::Zstd => zstd_compress(data),
        }
    }
    /// The most output one compressed byte can legitimately expand to, used to refuse a
    /// dishonest `raw_len` BEFORE anything is allocated.
    ///
    /// LZ4: a sequence's literal-length and match-length bytes extend by 255 apiece, so
    /// 255 per input byte bounds it. DEFLATE: the cheapest match is a length code and a
    /// distance code at one bit each under a dynamic tree, and a length code reaches 258
    /// bytes -- 258 bytes from 2 bits is 1032 per input byte, which is zlib's own
    /// worst-case figure.
    fn max_expansion(self) -> usize {
        match self {
            Codec::Lz4 => 255,
            Codec::Deflate => 1032,
            // An RLE block is three header bytes plus one byte, and it regenerates up to
            // 128 KiB: 131072 output bytes from 4 input bytes is 32768 per byte. That is
            // the format's real worst case, not a guess -- a compressed block's sequences
            // are bounded far below it, and `zstd::tests` builds that frame and measures
            // 32,672x against this 32,768x.
            //
            // **The derivation depends on the decoder ENFORCING the 128 KiB cap.** The
            // block size field is 21 bits, so without that check a four-byte RLE block
            // could claim 2,097,151 -- sixteen times the cap -- and only the caller's limit
            // would refuse it, a limit itself set from the number this bound gates.
            // `zstd::decompress` rejects an over-large block by size.
            Codec::Zstd => 32768,
        }
    }
}

/// zstd through the system library when the build asked for it, else this crate's own.
/// A libzstd failure falls back to the crate's encoder rather than failing the payload: the
/// frames are the same format, and the far side reads either.
fn zstd_compress(data: &[u8]) -> Vec<u8> {
    #[cfg(feature = "system-zstd")]
    if let Ok(c) = crate::zstd_system::compress(data) {
        return c;
    }
    crate::zstd::compress(data)
}

/// The decoding half of `zstd_compress`.
fn zstd_decompress(body: &[u8], raw_len: usize) -> io::Result<Vec<u8>> {
    #[cfg(feature = "system-zstd")]
    return crate::zstd_system::decompress(body, raw_len);
    #[cfg(not(feature = "system-zstd"))]
    crate::zstd::decompress(body, raw_len)
}

/// Compression on one stream, agreed in HELLO and applied payload by payload. A block is
/// probed first: its first 64 KiB are compressed, and if they do not shrink below nine
/// tenths the whole block goes raw without the rest being tried. After eight unprofitable
/// blocks in a row the next sixty-four go raw with no probe at all, then one is probed
/// again; if that one is unprofitable too the pause repeats at once. So a stream of
/// already-compressed data settles at one 64 KiB probe per sixty-five blocks.
#[derive(Debug, Default)]
pub struct Squeeze {
    pub on: bool,
    /// Which compressor this stream uses. Only meaningful while `on`.
    pub codec: Codec,
    /// How hard the compressor works, 1..=9, DEFLATE only. See `Codec::compress`.
    ///
    /// **This never crosses the wire as a stream property, and that is the difference
    /// between it and the codec.** A DEFLATE stream is self-describing -- the decoder
    /// reads the block headers and the code tables out of the stream itself -- so the two
    /// sides do not have to agree on a level the way they have to agree on a codec. It is
    /// carried in HELLO only as a REQUEST, so that a `-compress.level` on the command
    /// line reaches the far side's encoder too, and a serve that does not read the field
    /// simply compresses at its own default and is still understood.
    pub level: u8,
    unprofitable: u32,
    skip: u32,
    /// After a pause: the next block decides alone whether the pause repeats.
    probing: bool,
    /// Blocks compressed and sent compressed, and blocks sent raw, for the record.
    pub packed: u64,
    pub raw: u64,
    /// How many times the compressor ran, whole blocks and probes alike.
    pub attempts: u64,
}

/// The prefix a block is probed with before the rest is compressed.
const PROBE: usize = 64 << 10;

/// The level a stream uses when nothing asked for one. Matches `deflate::Level::DEFAULT`,
/// so an unconfigured run emits the same bytes it emitted before the knob existed.
pub const DEFAULT_LEVEL: u8 = 6;

fn shrinks(compressed: usize, raw: usize) -> bool {
    compressed * 10 < raw * 9
}

impl Squeeze {
    /// A stream that compresses (`on`) or one that sends everything raw.
    pub fn new(on: bool) -> Squeeze {
        Squeeze {
            on,
            level: DEFAULT_LEVEL,
            ..Default::default()
        }
    }

    /// The same, with a codec both sides agreed on in HELLO and the level asked for.
    pub fn with_codec(on: bool, codec: Codec, level: u8) -> Squeeze {
        Squeeze {
            on,
            codec,
            level,
            ..Default::default()
        }
    }

    /// Appends `data` as a payload: flag, raw length, bytes.
    pub fn pack(&mut self, e: &mut Encoder, data: &[u8]) {
        if self.on && data.len() >= 64 {
            if self.skip > 0 {
                self.skip -= 1;
                if self.skip == 0 {
                    self.probing = true;
                }
            } else if let Some(c) = self.try_compress(data) {
                self.unprofitable = 0;
                self.probing = false;
                self.packed += 1;
                // The CRC is over the ORIGINAL bytes, so it checks the round trip rather
                // than the transfer: a flipped bit anywhere -- in the compressed body on
                // the wire, or in a decompressor that mis-decodes one -- fails it.
                e.u32(self.codec.flag())
                    .u32(data.len() as u32)
                    .u32(crate::deflate::crc32(data))
                    .opaque(&c);
                return;
            } else {
                self.unprofitable += 1;
                if self.probing || self.unprofitable >= 8 {
                    self.unprofitable = 0;
                    self.probing = false;
                    self.skip = 64;
                }
            }
        }
        self.raw += 1;
        e.u32(PAYLOAD_RAW).u32(data.len() as u32).opaque(data);
    }

    /// The compressed block when compressing pays, judged on a prefix first.
    fn try_compress(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.attempts += 1;
        if data.len() > 2 * PROBE
            && !shrinks(self.codec.compress(&data[..PROBE], self.level).len(), PROBE)
        {
            return None;
        }
        let c = self.codec.compress(data, self.level);
        shrinks(c.len(), data.len()).then_some(c)
    }
}

/// Reads a payload written by `Squeeze::pack`, decompressing when it was compressed.
pub fn unpack<'a>(d: &mut Decoder<'a>) -> io::Result<Cow<'a, [u8]>> {
    let flag = d.u32()?;
    let raw_len = d.u32()? as usize;
    // the checksum sits between the length and the body, so it has to be read BEFORE the
    // opaque and only for the flag that carries one
    let want = if flag != PAYLOAD_RAW {
        Some(d.u32()?)
    } else {
        None
    };
    let body = d.opaque()?;
    match flag {
        PAYLOAD_RAW => {
            if body.len() != raw_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("raw payload of {} bytes claims {raw_len}", body.len()),
                ));
            }
            Ok(Cow::Borrowed(body))
        }
        PAYLOAD_LZ4 | PAYLOAD_DEFLATE | PAYLOAD_ZSTD => {
            let codec = Codec::from_flag(flag).expect("matched above");
            let want = want.expect("read above for this flag");
            if raw_len > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed payload claims {raw_len} bytes, over the {MAX_FRAME} limit"
                    ),
                ));
            }
            // a compressed body cannot legitimately expand past its codec's worst case,
            // so a claim beyond that is refused before the output is allocated
            // `saturating_mul`, and it is not defensive noise: `MAX_FRAME` is 16 MiB and
            // DEFLATE's bound is 1032, so the product is about 17 GiB. That fits a 64-bit
            // `usize` and does NOT fit a 32-bit one, where a debug build would panic on a
            // perfectly honest large payload and a release build would wrap to 128 MiB.
            // Neither is a security hole -- `raw_len` is already capped at `MAX_FRAME`
            // above, so the wrapped bound still admits every legal claim -- but a crash on
            // a 32-bit target is a real defect, and only doing the arithmetic shows it.
            if raw_len
                > body
                    .len()
                    .saturating_mul(codec.max_expansion())
                    .saturating_add(64)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed payload of {} bytes claims {raw_len}",
                        body.len()
                    ),
                ));
            }
            // CHECKED. The LZ4 block format carries no integrity of its own, and a flipped
            // bit inside a compressed body does not usually make the decode FAIL -- it
            // relocates a match, so the decoder emits `raw_len` perfectly plausible bytes
            // that are not the ones that were sent. Measured: 41% of single-bit flips
            // decode to wrong bytes with no error anywhere. Nothing downstream would catch
            // it either: a copy records the SOURCE's digest in the catalog and never
            // re-reads the destination, so the catalog would assert a digest the file does
            // not have. Only compressed payloads pay for this -- a raw one is byte-for-byte
            // and rides the transport's own integrity -- and `-compress` is already a
            // CPU-for-bandwidth trade the caller asked for.
            let out = match codec {
                Codec::Lz4 => crate::lz4::decompress(body, raw_len).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("compressed payload: {e}"),
                    )
                })?,
                // `inflate` takes the limit it may produce, so a stream that decodes to
                // more than the sender claimed is refused by the decoder rather than by a
                // length check afterwards
                Codec::Deflate => crate::deflate::inflate(body, raw_len).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("compressed payload: {e}"),
                    )
                })?,
                // same contract as `inflate`: the limit is enforced inside the decoder, so
                // a frame that expands past what the sender claimed never gets allocated
                Codec::Zstd => zstd_decompress(body, raw_len).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("compressed payload: {e}"),
                    )
                })?,
            };
            if out.len() != raw_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "compressed payload decoded to {} bytes, not the {raw_len} it claimed",
                        out.len()
                    ),
                ));
            }
            let got = crate::deflate::crc32(&out);
            if got != want {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("compressed payload of {raw_len} bytes checksums {got:#010x}, not the {want:#010x} the sender computed")));
            }
            Ok(Cow::Owned(out))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload flag {other}"),
        )),
    }
}

/// Writes one frame: the body's length, then the body. A body over the limit is refused
/// here rather than truncated into a length the reader would reject.
pub fn write_frame(w: &mut dyn Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame of {} bytes exceeds the {MAX_FRAME} limit",
                body.len()
            ),
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)
}

/// Reads one frame's body; `None` at a clean end of stream.
pub fn read_frame(r: &mut dyn Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the stream ended inside a frame header",
            ));
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME} limit"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

fn kind_code(k: Kind) -> u32 {
    match k {
        Kind::File => 0,
        Kind::Dir => 1,
        Kind::Symlink => 2,
    }
}

fn kind_of(code: u32) -> io::Result<Kind> {
    match code {
        0 => Ok(Kind::File),
        1 => Ok(Kind::Dir),
        2 => Ok(Kind::Symlink),
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kind code {n}"),
        )),
    }
}

fn i128_of(d: &mut Decoder<'_>) -> io::Result<i128> {
    Ok(i128::from_be_bytes(
        d.fixed(16)?.try_into().expect("16 bytes"),
    ))
}

pub fn encode_item(e: &mut Encoder, i: &Item) {
    e.string(&i.rel)
        .u32(kind_code(i.kind))
        .u64(i.size)
        .fixed(&i.mtime_ns.to_be_bytes())
        .fixed(&i.atime_ns.to_be_bytes())
        .u32(i.mode)
        .u32(i.uid)
        .u32(i.gid)
        .u64(i.dev)
        .u64(i.ino)
        .u64(i.nlink)
        .u64(i.blocks);
    match &i.link_target {
        Some(t) => {
            e.bool(true).string(&t.to_string_lossy());
        }
        None => {
            e.bool(false);
        }
    }
}

pub fn decode_item(d: &mut Decoder<'_>) -> io::Result<Item> {
    let rel = d.string()?;
    let kind = kind_of(d.u32()?)?;
    let size = d.u64()?;
    let mtime_ns = i128_of(d)?;
    let atime_ns = i128_of(d)?;
    let (mode, uid, gid) = (d.u32()?, d.u32()?, d.u32()?);
    let (dev, ino, nlink, blocks) = (d.u64()?, d.u64()?, d.u64()?, d.u64()?);
    let link_target = if d.bool()? {
        Some(std::path::PathBuf::from(d.string()?))
    } else {
        None
    };
    Ok(Item {
        rel,
        kind,
        size,
        mtime_ns,
        atime_ns,
        mode,
        uid,
        gid,
        dev,
        ino,
        nlink,
        blocks,
        link_target,
    })
}

fn opt_u64(e: &mut Encoder, v: Option<u64>) {
    match v {
        Some(n) => {
            e.bool(true).u64(n);
        }
        None => {
            e.bool(false);
        }
    }
}

fn opt_u64_of(d: &mut Decoder<'_>) -> io::Result<Option<u64>> {
    Ok(if d.bool()? { Some(d.u64()?) } else { None })
}

fn opt_i128(e: &mut Encoder, v: Option<i128>) {
    match v {
        Some(n) => {
            e.bool(true).fixed(&n.to_be_bytes());
        }
        None => {
            e.bool(false);
        }
    }
}

fn opt_i128_of(d: &mut Decoder<'_>) -> io::Result<Option<i128>> {
    Ok(if d.bool()? { Some(i128_of(d)?) } else { None })
}

fn strings(e: &mut Encoder, v: &[String]) {
    e.u32(v.len() as u32);
    for s in v {
        e.string(s);
    }
}

fn strings_of(d: &mut Decoder<'_>) -> io::Result<Vec<String>> {
    let n = d.u32()?;
    (0..n).map(|_| d.string()).collect()
}

pub fn encode_filter(e: &mut Encoder, f: &Filter) {
    strings(e, &f.include);
    strings(e, &f.exclude);
    opt_u64(e, f.min_size);
    opt_u64(e, f.max_size);
    opt_i128(e, f.newer_than_ns);
    opt_i128(e, f.older_than_ns);
    match &f.kinds {
        Some(ks) => {
            e.bool(true).u32(ks.len() as u32);
            for k in ks {
                e.u32(kind_code(*k));
            }
        }
        None => {
            e.bool(false);
        }
    }
    opt_u64(e, f.uid.map(u64::from));
    opt_u64(e, f.gid.map(u64::from));
    opt_u64(e, f.fileid);
}

pub fn decode_filter(d: &mut Decoder<'_>) -> io::Result<Filter> {
    let include = strings_of(d)?;
    let exclude = strings_of(d)?;
    let min_size = opt_u64_of(d)?;
    let max_size = opt_u64_of(d)?;
    let newer_than_ns = opt_i128_of(d)?;
    let older_than_ns = opt_i128_of(d)?;
    let kinds = if d.bool()? {
        let n = d.u32()?;
        Some(
            (0..n)
                .map(|_| d.u32().and_then(kind_of))
                .collect::<io::Result<Vec<_>>>()?,
        )
    } else {
        None
    };
    let uid = opt_u64_of(d)?.map(|v| v as u32);
    let gid = opt_u64_of(d)?.map(|v| v as u32);
    let fileid = opt_u64_of(d)?;
    Ok(Filter {
        include,
        exclude,
        min_size,
        max_size,
        newer_than_ns,
        older_than_ns,
        kinds,
        uid,
        gid,
        fileid,
    })
}

pub fn encode_params(e: &mut Encoder, p: crate::cdc::Params) {
    e.u32(p.min).u32(p.avg).u32(p.max);
}

pub fn decode_params(d: &mut Decoder<'_>) -> io::Result<crate::cdc::Params> {
    // Checked HERE, at the one place a chunking crosses the wire, rather than in each of
    // the three opcodes that carry one. See `Params::validate` for what an unchecked
    // chunking buys the peer that sends it.
    let p = crate::cdc::Params {
        min: d.u32()?,
        avg: d.u32()?,
        max: d.u32()?,
    };
    p.validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(p)
}

pub fn encode_sigs(e: &mut Encoder, sigs: &[ChunkSig]) {
    e.u32(sigs.len() as u32);
    for s in sigs {
        e.u64(s.offset).u32(s.len).u64(s.weak).fixed(&s.digest);
    }
}

pub fn decode_sigs(d: &mut Decoder<'_>, into: &mut Vec<ChunkSig>) -> io::Result<()> {
    for _ in 0..d.u32()? {
        into.push(ChunkSig {
            offset: d.u64()?,
            len: d.u32()?,
            weak: d.u64()?,
            digest: d.fixed(DIGEST_LEN)?.try_into().expect("32 bytes"),
        });
    }
    Ok(())
}

pub fn encode_basis(e: &mut Encoder, b: &Basis) {
    e.u64(b.size).fixed(&b.mtime_ns.to_be_bytes()).u64(b.ino);
}

pub fn decode_basis(d: &mut Decoder<'_>) -> io::Result<Basis> {
    Ok(Basis {
        size: d.u64()?,
        mtime_ns: i128_of(d)?,
        ino: d.u64()?,
    })
}

pub fn encode_meta(e: &mut Encoder, m: MetaOptions) {
    e.bool(m.mode).bool(m.times).bool(m.owner).bool(m.atime);
}

pub fn decode_meta(d: &mut Decoder<'_>) -> io::Result<MetaOptions> {
    Ok(MetaOptions {
        mode: d.bool()?,
        times: d.bool()?,
        owner: d.bool()?,
        atime: d.bool()?,
    })
}

/// A `Removed` on the wire. Without it the server drops the value and the client writes
/// `Gone` for any success, so a far end that KEPT something -- a registry behind an
/// `rcp serve` refusing a blob delete -- is counted removed and recorded gone in the
/// catalog. Reading the two ends side by side shows it; it is why VERSION 3 exists.
/// A tag word rather than the bool it was under VERSION 3: `Deferred` is a third shape and
/// a bool has two. `VERSION` moved to 4 with it.
pub fn encode_removed(e: &mut Encoder, r: &Removed) {
    match r {
        Removed::Gone => {
            e.u32(0);
        }
        Removed::Deferred(why) => {
            e.u32(1).string(why);
        }
        Removed::Kept(why) => {
            e.u32(2).string(why);
        }
    }
}

pub fn decode_removed(d: &mut Decoder<'_>) -> io::Result<Removed> {
    match d.u32()? {
        0 => Ok(Removed::Gone),
        1 => Ok(Removed::Deferred(d.string()?)),
        2 => Ok(Removed::Kept(d.string()?)),
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("removed: unknown tag {t}"),
        )),
    }
}

pub fn encode_refusals(e: &mut Encoder, r: &Refusals) {
    e.bool(r.owner);
    strings(e, &r.xattrs);
}

pub fn decode_refusals(d: &mut Decoder<'_>) -> io::Result<Refusals> {
    Ok(Refusals {
        owner: d.bool()?,
        xattrs: strings_of(d)?,
    })
}

pub fn encode_xattrs(e: &mut Encoder, xs: &[(String, Vec<u8>)]) {
    e.u32(xs.len() as u32);
    for (k, v) in xs {
        e.string(k).opaque(v);
    }
}

pub fn decode_xattrs(d: &mut Decoder<'_>) -> io::Result<Vec<(String, Vec<u8>)>> {
    let n = d.u32()?;
    (0..n)
        .map(|_| Ok((d.string()?, d.opaque()?.to_vec())))
        .collect()
}

/// An error crosses the wire as its kind (by number) and its text.
pub fn kind_code_of(k: io::ErrorKind) -> u32 {
    match k {
        io::ErrorKind::NotFound => 1,
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::AlreadyExists => 3,
        io::ErrorKind::InvalidInput => 4,
        io::ErrorKind::InvalidData => 5,
        io::ErrorKind::Unsupported => 6,
        io::ErrorKind::NotADirectory => 7,
        io::ErrorKind::IsADirectory => 8,
        io::ErrorKind::DirectoryNotEmpty => 9,
        io::ErrorKind::StorageFull => 10,
        io::ErrorKind::ReadOnlyFilesystem => 11,
        io::ErrorKind::QuotaExceeded => 12,
        io::ErrorKind::CrossesDevices => 13,
        io::ErrorKind::ResourceBusy => 14,
        io::ErrorKind::TooManyLinks => 15,
        io::ErrorKind::InvalidFilename => 16,
        io::ErrorKind::TimedOut => 17,
        io::ErrorKind::Interrupted => 18,
        io::ErrorKind::WouldBlock => 19,
        io::ErrorKind::FileTooLarge => 20,
        _ => 0,
    }
}

pub fn error_kind_of(code: u32) -> io::ErrorKind {
    match code {
        1 => io::ErrorKind::NotFound,
        2 => io::ErrorKind::PermissionDenied,
        3 => io::ErrorKind::AlreadyExists,
        4 => io::ErrorKind::InvalidInput,
        5 => io::ErrorKind::InvalidData,
        6 => io::ErrorKind::Unsupported,
        7 => io::ErrorKind::NotADirectory,
        8 => io::ErrorKind::IsADirectory,
        9 => io::ErrorKind::DirectoryNotEmpty,
        10 => io::ErrorKind::StorageFull,
        11 => io::ErrorKind::ReadOnlyFilesystem,
        12 => io::ErrorKind::QuotaExceeded,
        13 => io::ErrorKind::CrossesDevices,
        14 => io::ErrorKind::ResourceBusy,
        15 => io::ErrorKind::TooManyLinks,
        16 => io::ErrorKind::InvalidFilename,
        17 => io::ErrorKind::TimedOut,
        18 => io::ErrorKind::Interrupted,
        19 => io::ErrorKind::WouldBlock,
        20 => io::ErrorKind::FileTooLarge,
        _ => io::ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire numbers are a contract with every build already deployed, so they are
    /// pinned here rather than left to whoever edits the constants next. zstd is 2 because
    /// an earlier release used 2; putting any other codec there would make two builds read
    /// the same payload as different codecs.
    #[test]
    fn the_wire_numbers_are_the_ones_deployed_builds_speak() {
        assert_eq!(
            (PAYLOAD_RAW, PAYLOAD_LZ4, PAYLOAD_ZSTD, PAYLOAD_DEFLATE),
            (0, 1, 2, 3)
        );
        assert_eq!((VERSION, CODEC_VERSION), (5, 6));
    }

    #[test]
    fn items_filters_and_frames_round_trip() {
        let item = Item {
            rel: "a/b".into(),
            kind: Kind::Symlink,
            size: 7,
            mtime_ns: -5,
            atime_ns: 1 << 70,
            mode: 0o644,
            uid: 1,
            gid: 2,
            dev: 3,
            ino: 4,
            nlink: 5,
            blocks: 6,
            link_target: Some("../x".into()),
        };
        let mut e = Encoder::new();
        encode_item(&mut e, &item);
        let bytes = e.into_bytes();
        assert_eq!(decode_item(&mut Decoder::new(&bytes)).unwrap(), item);
        let f = Filter {
            include: vec!["*.txt".into()],
            exclude: vec![],
            min_size: Some(1),
            max_size: None,
            newer_than_ns: Some(-9),
            older_than_ns: None,
            kinds: Some(vec![Kind::File, Kind::Dir]),
            uid: Some(7),
            gid: None,
            fileid: Some(9),
        };
        let mut e = Encoder::new();
        encode_filter(&mut e, &f);
        let bytes = e.into_bytes();
        assert_eq!(
            format!("{:?}", decode_filter(&mut Decoder::new(&bytes)).unwrap()),
            format!("{f:?}")
        );
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"hello");
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"");
        assert!(read_frame(&mut r).unwrap().is_none());
        // controls: a truncated frame is an error, not an end, and a body over the limit
        // is refused by the writer, not truncated into a length the reader would reject
        let mut r = &buf[..3];
        assert!(read_frame(&mut r).is_err());
        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, &vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(sink.is_empty());
        // every kind in the table round-trips, and one outside it lands on Other
        for k in [
            io::ErrorKind::NotFound,
            io::ErrorKind::StorageFull,
            io::ErrorKind::ReadOnlyFilesystem,
            io::ErrorKind::QuotaExceeded,
            io::ErrorKind::FileTooLarge,
        ] {
            assert_eq!(error_kind_of(kind_code_of(k)), k);
        }
        assert_eq!(
            error_kind_of(kind_code_of(io::ErrorKind::Deadlock)),
            io::ErrorKind::Other
        );
        // delta fields round-trip too
        let sigs = vec![
            ChunkSig {
                offset: 0,
                len: 5,
                weak: 0xdead_beef,
                digest: [7; DIGEST_LEN],
            },
            ChunkSig {
                offset: 5,
                len: 9000,
                weak: 0,
                digest: [0; DIGEST_LEN],
            },
        ];
        let basis = Basis {
            size: 7,
            mtime_ns: -3,
            ino: 99,
        };
        let mut e = Encoder::new();
        encode_params(
            &mut e,
            crate::cdc::Params {
                min: 1024,
                avg: 4096,
                max: 32768,
            },
        );
        encode_sigs(&mut e, &sigs);
        encode_basis(&mut e, &basis);
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes);
        assert_eq!(
            decode_params(&mut d).unwrap(),
            crate::cdc::Params {
                min: 1024,
                avg: 4096,
                max: 32768
            }
        );
        let mut got = Vec::new();
        decode_sigs(&mut d, &mut got).unwrap();
        assert_eq!(got, sigs);
        assert_eq!(decode_basis(&mut d).unwrap(), basis);

        // The control for that round trip: a chunking the wire must NOT accept. `max: 0`
        // cuts after every byte, so the peer that sends it asks the other end to sign a
        // file into one chunk per byte -- about 56 bytes of signature per byte of data.
        // Refusing it at decode covers all three opcodes that carry a chunking.
        let mut e = Encoder::new();
        encode_params(
            &mut e,
            crate::cdc::Params {
                min: 0,
                avg: 0,
                max: 0,
            },
        );
        let bytes = e.into_bytes();
        let err =
            decode_params(&mut Decoder::new(&bytes)).expect_err("a zero chunking must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[test]
    fn payloads_compress_when_it_pays_go_raw_when_it_does_not_and_stop_trying_for_a_while() {
        let text: Vec<u8> = "all work and no play makes a dull transfer tool; "
            .repeat(4000)
            .into_bytes();
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let noise: Vec<u8> = (0..100_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let mut s = Squeeze::new(true);
        let mut e = Encoder::new();
        s.pack(&mut e, &text);
        let bytes = e.into_bytes();
        assert!(
            bytes.len() < text.len() / 10,
            "text shrinks: {} of {}",
            bytes.len(),
            text.len()
        );
        let mut d = Decoder::new(&bytes);
        assert_eq!(unpack(&mut d).unwrap().as_ref(), &text[..]);
        assert_eq!((s.packed, s.raw), (1, 0));
        // noise goes raw, and after eight unprofitable blocks the attempts stop
        for _ in 0..8 {
            let mut e = Encoder::new();
            s.pack(&mut e, &noise);
            let bytes = e.into_bytes();
            assert_eq!(&bytes[..4], &PAYLOAD_RAW.to_be_bytes());
            assert_eq!(
                unpack(&mut Decoder::new(&bytes)).unwrap().as_ref(),
                &noise[..]
            );
        }
        assert_eq!((s.packed, s.raw, s.skip), (1, 8, 64));
        // during the pause even text goes raw untried, then the next block is probed: noise
        // again, and the pause repeats at once (one attempt, not eight)
        let attempts = s.attempts;
        let mut e = Encoder::new();
        s.pack(&mut e, &text);
        assert_eq!(&e.into_bytes()[..4], &PAYLOAD_RAW.to_be_bytes());
        for _ in 0..63 {
            let mut e = Encoder::new();
            s.pack(&mut e, &noise);
        }
        assert_eq!((s.skip, s.attempts), (0, attempts));
        let mut e = Encoder::new();
        s.pack(&mut e, &noise);
        assert_eq!(
            (s.skip, s.attempts),
            (64, attempts + 1),
            "one probe, then the pause again"
        );
        for _ in 0..64 {
            let mut e = Encoder::new();
            s.pack(&mut e, &noise);
        }
        // and a probe that pays ends the pause: text compresses again
        let mut e = Encoder::new();
        s.pack(&mut e, &text);
        assert_eq!(&e.into_bytes()[..4], &PAYLOAD_LZ4.to_be_bytes());
        // A large block of noise costs one prefix probe, not a pass over the whole block.
        //
        // Measure the probe against what a raw send costs ANYWAY, not against zero. When a
        // block is rejected, `pack` still writes it out with `e.opaque(data)` -- a copy of
        // the whole megabyte -- so timing `pack` and comparing it to `compress` alone puts
        // that copy on the probe's side of the ledger and nothing on the other. That was
        // what the first version of this arm did, and on this machine it made the ratio
        // ~3.4 against a threshold of 4: a failure that said nothing about the probe.
        // What the claim is actually about is the compression work, so subtract the copy
        // by measuring a Squeeze that does only the copy.
        //
        // And take the MINIMUM of several samples rather than one. This is a wall-clock
        // measurement inside a parallel test runner, so a single sample carries whatever
        // the other tests were doing to the CPU at that instant: the same arm that reads
        // ~180us alone read 773us against a 2.89ms whole-block run when the rest of the
        // suite was running, and failed by a hair. A minimum is a lower bound on the true
        // cost, it is taken the same way on both sides, and contention can only push a
        // sample up -- so noise makes this arm harder to pass, never easier.
        let big: Vec<u8> = noise.iter().cycle().take(1 << 20).copied().collect();
        let fastest = |f: &mut dyn FnMut()| {
            (0..7)
                .map(|_| {
                    let t = std::time::Instant::now();
                    f();
                    t.elapsed()
                })
                .min()
                .unwrap()
        };
        let mut raws = 0;
        let copy_time = fastest(&mut || {
            let mut off = Squeeze::default();
            let mut e = Encoder::new();
            off.pack(&mut e, &big);
            raws += off.raw;
        });
        assert_eq!(
            raws, 7,
            "the control path must have taken the raw branch every time"
        );
        let probe_time = fastest(&mut || {
            let mut fresh = Squeeze::new(true);
            let mut e = Encoder::new();
            fresh.pack(&mut e, &big);
        });
        let whole_time = fastest(&mut || {
            let _ = crate::lz4::compress(&big);
        });
        let probe_work = probe_time.saturating_sub(copy_time);
        assert!(probe_work * 4 < whole_time, "probe {probe_time:?} - copy {copy_time:?} = {probe_work:?} vs whole block {whole_time:?}");
        // controls: a stream that did not agree to compress sends raw and counts it; a
        // payload claiming more than a frame is refused before any allocation; a raw
        // payload whose length lies is refused; a corrupt block is refused
        let mut off = Squeeze::default();
        let mut e = Encoder::new();
        off.pack(&mut e, &text);
        assert_eq!(
            (&e.into_bytes()[..4], off.raw),
            (&PAYLOAD_RAW.to_be_bytes()[..], 1)
        );
        let mut e = Encoder::new();
        e.u32(PAYLOAD_LZ4).u32((MAX_FRAME + 1) as u32).opaque(b"xx");
        let bytes = e.into_bytes();
        assert!(unpack(&mut Decoder::new(&bytes)).is_err());
        let mut e = Encoder::new();
        e.u32(PAYLOAD_RAW).u32(5).opaque(b"xx");
        let bytes = e.into_bytes();
        assert!(unpack(&mut Decoder::new(&bytes)).is_err());
        let mut e = Encoder::new();
        e.u32(PAYLOAD_LZ4).u32(100).opaque(&[0xff, 0x00, 0x00]);
        let bytes = e.into_bytes();
        assert!(unpack(&mut Decoder::new(&bytes)).is_err());
        // a tiny body claiming a frame's worth of output is refused before the allocation
        let mut e = Encoder::new();
        e.u32(PAYLOAD_LZ4)
            .u32(MAX_FRAME as u32)
            .u32(0)
            .opaque(&[0x10, 0x00]);
        let bytes = e.into_bytes();
        assert!(unpack(&mut Decoder::new(&bytes))
            .unwrap_err()
            .to_string()
            .contains("claims"));

        // A COMPRESSED PAYLOAD IS CHECKSUMMED, and a single flipped bit in its body is
        // refused rather than decoded into plausible wrong bytes. The LZ4 block format
        // carries no integrity: a flip usually relocates a match instead of failing the
        // decode, so the decoder emits `raw_len` bytes that are simply not the ones that
        // were sent, and a copy records the SOURCE's digest in the catalog without ever
        // re-reading the destination.
        let payload: Vec<u8> = (0..4096u32).map(|i| (i / 7) as u8).collect();
        let mut s = Squeeze::new(true);
        let mut e = Encoder::new();
        s.pack(&mut e, &payload);
        let good = e.into_bytes();
        assert_eq!(s.packed, 1, "the fixture must actually compress");
        assert_eq!(
            unpack(&mut Decoder::new(&good)).unwrap().as_ref(),
            &payload[..],
            "the clean round trip"
        );

        // flip one bit in the compressed body (past flag, raw_len, crc and the opaque
        // length) and require a refusal rather than wrong bytes
        let mut caught = 0;
        let mut decoded_wrong = 0;
        for bit in 0..64usize {
            let mut bad = good.clone();
            let at = 16 + bit / 8;
            if at >= bad.len() {
                break;
            }
            bad[at] ^= 1 << (bit % 8);
            match unpack(&mut Decoder::new(&bad)) {
                Err(_) => caught += 1,
                Ok(out) if out.as_ref() == &payload[..] => {}
                Ok(_) => decoded_wrong += 1,
            }
        }
        assert!(
            caught > 0,
            "no flip was caught at all: the fixture is not exercising the body"
        );
        assert_eq!(
            decoded_wrong, 0,
            "{decoded_wrong} flips decoded to WRONG bytes with no error"
        );
    }

    /// `Removed` crosses the wire whole. Before this the server dropped it and the client
    /// wrote `Gone` on any success, so a far end that KEPT something would be counted
    /// removed and recorded gone. When this was written no adapter behind `rcp serve`
    /// could answer `Kept` -- a serve opened only a local directory -- so this round trip
    /// stood in for an end-to-end arm. A serve can open any endpoint now (`-via`), and the
    /// end-to-end arm exists: `a_relay_opens_the_endpoint_on_the_hop_and_a_kept_crosses_
    /// the_wire` in the contract suite, a registry behind the hop refusing its blob deletes
    /// and `3 deferred` arriving here. This one is what it rests on.
    #[test]
    fn a_removed_survives_the_wire_in_all_three_shapes() {
        for r in [
            Removed::Gone,
            Removed::Deferred("the registry collects it".into()),
            Removed::Kept("the server has it locked".into()),
        ] {
            let mut e = Encoder::new();
            encode_removed(&mut e, &r);
            let bytes = e.into_bytes();
            assert_eq!(decode_removed(&mut Decoder::new(&bytes)).unwrap(), r);
        }
        // the control: the two shapes do not decode to each other, so the arm above is
        // not passing because everything decodes to the same value
        let mut e = Encoder::new();
        encode_removed(&mut e, &Removed::Gone);
        assert_ne!(
            decode_removed(&mut Decoder::new(&e.into_bytes())).unwrap(),
            Removed::Kept(String::new())
        );
        // and a deferred is not a kept with the same reason: the tag carries the difference
        let mut e = Encoder::new();
        encode_removed(&mut e, &Removed::Deferred("x".into()));
        assert_ne!(
            decode_removed(&mut Decoder::new(&e.into_bytes())).unwrap(),
            Removed::Kept("x".into())
        );
        let mut e = Encoder::new();
        e.u32(7).string("x");
        assert!(
            decode_removed(&mut Decoder::new(&e.into_bytes())).is_err(),
            "an unknown tag decoded"
        );
    }
}
