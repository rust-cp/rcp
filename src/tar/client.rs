//! `TarTree`: the `Tree` port over a tar archive.
//!
//! Reading scans the archive once (a header block, a seek past the data, the next header)
//! and keeps the offsets, so opening a member is a seek rather than a scan. Writing
//! appends members to one file under a lock, since a tar is a stream and two members
//! cannot be written at once.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use super::Settings;
use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree, ZEROS,
};

pub const BLOCK: usize = 512;
/// A pax or GNU long header's payload; a path longer than this is not a path.
const MAX_EXTENDED: u64 = 1 << 20;

// ---------------------------------------------------------------------------------------------
// header fields
// ---------------------------------------------------------------------------------------------

/// A numeric header field: octal with a terminator, or GNU's base 256 when the high bit of
/// the first byte is set (which is how a size over 8 GiB is carried). A negative time uses
/// [`signed_number`]: the same marker with the 0x40 bit set is two's complement, and reading
/// it as unsigned turns a pre-epoch mtime into a huge positive or into zero when it overflows.
fn number(field: &[u8]) -> io::Result<u64> {
    let v = signed_number(field)?;
    u64::try_from(v).map_err(|_| bad("a base-256 header field does not fit in 64 bits"))
}

/// GNU base-256, signed. The marker byte's high bit is set. When its 0x40 bit is also set
/// the remaining bytes are a negative magnitude (`n - 256^(len-1)`); otherwise they are a
/// positive magnitude, with the marker's low 7 bits as its top.
fn signed_number(field: &[u8]) -> io::Result<i128> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: i128 = 0;
        for b in &field[1..] {
            v = v
                .checked_shl(8)
                .ok_or_else(|| bad("a base-256 header field does not fit in 128 bits"))?
                | i128::from(*b);
        }
        if field[0] & 0x40 != 0 {
            let bits = ((field.len() - 1) * 8) as u32;
            let base = 1i128
                .checked_shl(bits)
                .ok_or_else(|| bad("a base-256 header field does not fit in 128 bits"))?;
            v = v
                .checked_sub(base)
                .ok_or_else(|| bad("a base-256 header field does not fit in 128 bits"))?;
        } else {
            let top = i128::from(field[0] & 0x7f);
            let bits = ((field.len() - 1) * 8) as u32;
            v |= top
                .checked_shl(bits)
                .ok_or_else(|| bad("a base-256 header field does not fit in 128 bits"))?;
        }
        return Ok(v);
    }
    let text: String = field
        .iter()
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    let n = i128::from_str_radix(text, 8)
        .map_err(|_| bad(&format!("{text:?} is not an octal header field")))?;
    Ok(n)
}

/// Writes a number as the octal ustar wants, or base 256 when it will not fit -- which is
/// what GNU and bsdtar both read, and what a size over 8 GiB needs.
fn put_number(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let octal = format!("{value:o}");
    if octal.len() <= width {
        let pad = width - octal.len();
        field[..pad].fill(b'0');
        field[pad..width].copy_from_slice(octal.as_bytes());
        field[width] = 0;
        return;
    }
    field.fill(0);
    let mut v = value;
    for slot in field.iter_mut().rev() {
        *slot = (v & 0xff) as u8;
        v >>= 8;
    }
    field[0] |= 0x80;
}

fn put_str(field: &mut [u8], text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(field.len());
    field[..n].copy_from_slice(&bytes[..n]);
    field[n..].fill(0);
}

fn string(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

fn checksum(block: &[u8; BLOCK]) -> u32 {
    let mut sum: u32 = 0;
    for (i, b) in block.iter().enumerate() {
        // the checksum field itself counts as spaces
        sum += if (148..156).contains(&i) {
            b' ' as u32
        } else {
            *b as u32
        };
    }
    sum
}

fn blocks_for(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

// ---------------------------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------------------------

/// One member of the archive: where its data starts and what the header said.
#[derive(Debug, Clone)]
struct Member {
    item: Item,
    offset: u64,
    /// For a hard link, the member it points at (tar's `linkname` on typeflag `1`).
    link_to: Option<String>,
    /// Present when the member is stored sparse: which logical ranges are really in the
    /// archive. Absent means the ordinary layout, where logical offset equals archive
    /// offset from `offset`.
    sparse: Option<Sparse>,
}

/// Where a sparse member's bytes actually are.
///
/// `map` is the list of `(logical offset, length)` data extents, sorted and
/// non-overlapping; everything between them is a hole. `at` is the archive offset of the
/// FIRST extent's first byte -- for pax 1.0 that is past the decimal map text that opens
/// the member's data, which is why it is carried rather than derived from `Member::offset`.
///
/// The extents are laid out back to back in the archive in map order, so the archive
/// offset of logical position p inside extent i is `at + (bytes of extents 0..i) +
/// (p - offset_i)`.
#[derive(Debug, Clone, Default)]
struct Sparse {
    map: Vec<(u64, u64)>,
    at: u64,
}

impl Sparse {
    /// Total bytes actually stored, which is what the member's data blocks hold after the
    /// map text.
    fn stored(&self) -> u64 {
        self.map.iter().map(|(_, len)| *len).sum()
    }

    /// Checks a map against the size it claims to describe, and says which way it is wrong.
    ///
    /// Every one of these is a real shape a hostile or broken archive can carry, and the
    /// reason they are refused rather than clamped is that a clamped map still produces a
    /// file -- just the wrong one, silently. Overlap is included because two extents
    /// claiming the same logical byte makes the file's content depend on read order.
    fn validate(&self, realsize: u64, name: &str) -> io::Result<()> {
        let mut end = 0u64;
        for (i, (off, len)) in self.map.iter().enumerate() {
            if *len == 0 {
                continue;
            }
            if *off < end {
                return Err(bad(&format!("{name}: sparse extent {i} starts at {off}, inside or before the one that ended at {end}")));
            }
            let Some(stop) = off.checked_add(*len) else {
                return Err(bad(&format!(
                    "{name}: sparse extent {i} at {off} for {len} bytes overflows"
                )));
            };
            if stop > realsize {
                return Err(bad(&format!("{name}: sparse extent {i} ends at {stop}, past the declared size of {realsize}")));
            }
            end = stop;
        }
        Ok(())
    }
}

/// What a scan of the archive found, by path.
#[derive(Debug, Default)]
struct Index {
    members: BTreeMap<String, Member>,
    errors: Vec<String>,
}

/// The pax records of an extended header, IN ORDER and WITH REPEATS: `LEN KEY=VALUE\n`,
/// LEN counting itself.
///
/// The order and the repeats matter for exactly one thing, and it is the reason this exists
/// beside `pax`: GNU sparse format 0.0 encodes its extent map as alternating
/// `GNU.sparse.offset` and `GNU.sparse.numbytes` records, one pair per extent. Collapsed
/// into a map, a hundred extents become one -- the LAST one -- and the file that comes out
/// is a different file, with nothing reporting it.
fn pax_list(payload: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let Some(space) = rest.iter().position(|b| *b == b' ') else {
            break;
        };
        let Ok(len) = String::from_utf8_lossy(&rest[..space]).parse::<usize>() else {
            break;
        };
        if len < space + 2 || len > rest.len() {
            break;
        }
        let record = &rest[space + 1..len - 1];
        if let Some(eq) = record.iter().position(|b| *b == b'=') {
            out.push((
                String::from_utf8_lossy(&record[..eq]).into_owned(),
                String::from_utf8_lossy(&record[eq + 1..]).into_owned(),
            ));
        }
        rest = &rest[len..];
    }
    out
}

/// The pax key/value pairs of an extended header, last value winning -- which is right for
/// every key except the sparse 0.0 pair, and those are read from `pax_list` instead.
fn pax(payload: &[u8]) -> BTreeMap<String, String> {
    pax_list(payload).into_iter().collect()
}

/// The sparse map of a GNU 0.1 header: `GNU.sparse.map` is `off,len,off,len,...`.
fn sparse_map_0_1(text: &str, name: &str) -> io::Result<Vec<(u64, u64)>> {
    let mut nums = Vec::new();
    for field in text.split(',') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        nums.push(field.parse::<u64>().map_err(|_| {
            bad(&format!(
                "{name}: GNU.sparse.map has {field:?} where a number belongs"
            ))
        })?);
    }
    if nums.len() % 2 != 0 {
        return Err(bad(&format!("{name}: GNU.sparse.map has {} numbers, which is not a whole number of offset/length pairs", nums.len())));
    }
    if nums.len() / 2 > MAX_SPARSE_EXTENTS {
        return Err(bad(&format!(
            "{name}: a sparse map of {} extents is not a map",
            nums.len() / 2
        )));
    }
    Ok(nums.chunks(2).map(|p| (p[0], p[1])).collect())
}

/// The sparse map of a GNU 0.0 header: alternating `GNU.sparse.offset` and
/// `GNU.sparse.numbytes` records, in the order they appear.
///
/// Refused rather than repaired when they do not alternate, because the pairing is the
/// only thing that says which length belongs to which offset; a reader that guessed would
/// produce a plausible file from a damaged one.
fn sparse_map_0_0(records: &[(String, String)], name: &str) -> io::Result<Vec<(u64, u64)>> {
    let mut map = Vec::new();
    let mut pending: Option<u64> = None;
    for (key, value) in records {
        let which = match key.as_str() {
            "GNU.sparse.offset" => true,
            "GNU.sparse.numbytes" => false,
            _ => continue,
        };
        let n: u64 = value.parse().map_err(|_| {
            bad(&format!(
                "{name}: {key} reads {value:?}, which is not a number"
            ))
        })?;
        match (which, pending.take()) {
            (true, None) => pending = Some(n),
            (false, Some(off)) => map.push((off, n)),
            (true, Some(_)) => {
                return Err(bad(&format!(
                    "{name}: two GNU.sparse.offset records with no numbytes between them"
                )))
            }
            (false, None) => {
                return Err(bad(&format!(
                    "{name}: a GNU.sparse.numbytes record with no offset before it"
                )))
            }
        }
        if map.len() > MAX_SPARSE_EXTENTS {
            return Err(bad(&format!(
                "{name}: a sparse map of more than {MAX_SPARSE_EXTENTS} extents is not a map"
            )));
        }
    }
    if pending.is_some() {
        return Err(bad(&format!(
            "{name}: a GNU.sparse.offset record with no numbytes after it"
        )));
    }
    Ok(map)
}

/// The sparse map of an old-GNU `S` member: four `(offset, numbytes)` octal pairs in the
/// header itself, `isextended` at 482, `realsize` at 483, and 21 more pairs per extension
/// block for as long as each block's own `isextended` at 504 says there is another.
///
/// This is the form `tar --sparse` writes BY DEFAULT, so it is the one most likely to
/// arrive; the pax forms need a flag.
fn sparse_old_gnu(header: &[u8; BLOCK]) -> io::Result<(Vec<(u64, u64)>, u64, bool)> {
    let mut map = Vec::new();
    let mut at = 386;
    for _ in 0..4 {
        let off = number(&header[at..at + 12])?;
        let len = number(&header[at + 12..at + 24])?;
        if off != 0 || len != 0 {
            map.push((off, len));
        }
        at += 24;
    }
    let extended = header[482] != 0;
    let realsize = number(&header[483..495])?;
    Ok((map, realsize, extended))
}

/// One extension block of an old-GNU `S` member: 21 pairs then `isextended`.
fn sparse_old_gnu_extension(block: &[u8; BLOCK]) -> io::Result<(Vec<(u64, u64)>, bool)> {
    let mut map = Vec::new();
    let mut at = 0;
    for _ in 0..21 {
        let off = number(&block[at..at + 12])?;
        let len = number(&block[at + 12..at + 24])?;
        if off != 0 || len != 0 {
            map.push((off, len));
        }
        at += 24;
    }
    Ok((map, block[504] != 0))
}

/// One pax record: `LEN KEY=VALUE\n`, where LEN counts itself -- which is circular, so the
/// length is grown until it describes the record it is part of.
fn pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    while len.to_string().len() + body.len() != len {
        len += 1;
    }
    format!("{len}{body}")
}

/// The largest sparse map this reader will read, in extents.
///
/// A map is attacker-controlled length-prefixed data, so it needs a bound or a crafted
/// archive allocates as much as it likes before a single byte is checked. 4M extents is far
/// past any real file (ext4's own extent tree is shallower than this) and costs 64 MB of
/// `Vec` if one ever arrives, which is survivable; the entry after it is refused.
const MAX_SPARSE_EXTENTS: usize = 4 << 20;

/// Reads a pax 1.0 sparse map: decimal ASCII, newline-separated, at the front of the
/// member's own data -- `count`, then `offset` and `numbytes` per extent.
///
/// Returns the map and how many BYTES of the member it consumed, because the caller needs
/// that to find the first real data byte, and because the count is not derivable from the
/// map (the map text is padded to a 512 boundary and the padding is part of the member).
fn sparse_map_1_0(data: &[u8], name: &str) -> io::Result<(Vec<(u64, u64)>, usize)> {
    let mut at = 0usize;
    let next = |at: &mut usize| -> io::Result<u64> {
        let start = *at;
        let end = data[start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|p| start + p)
            .ok_or_else(|| {
                bad(&format!(
                    "{name}: a sparse map that never ends; no newline after byte {start}"
                ))
            })?;
        let text = std::str::from_utf8(&data[start..end]).map_err(|_| {
            bad(&format!(
                "{name}: a sparse map field at byte {start} is not text"
            ))
        })?;
        let value: u64 = text.trim().parse().map_err(|_| {
            bad(&format!(
                "{name}: a sparse map field at byte {start} reads {text:?}, which is not a number"
            ))
        })?;
        *at = end + 1;
        Ok(value)
    };
    let count = next(&mut at)? as usize;
    if count > MAX_SPARSE_EXTENTS {
        return Err(bad(&format!(
            "{name}: a sparse map of {count} extents is not a map"
        )));
    }
    let mut map = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let off = next(&mut at)?;
        let len = next(&mut at)?;
        map.push((off, len));
    }
    Ok((map, at))
}

/// A pax time (`1700000000.123456789`, or `-0.5`) in nanoseconds. The sign is taken from
/// the text: `"-0".parse()` is `0`, which used to keep a negative fraction positive.
fn pax_time(text: &str) -> Option<i128> {
    let text = text.trim();
    let neg = text.starts_with('-');
    let text = text.trim_start_matches(['+', '-']);
    let (secs, frac) = match text.split_once('.') {
        Some((s, f)) => (s, f),
        None => (text, ""),
    };
    let secs: i128 = secs.parse().ok()?;
    let mut nanos: i128 = 0;
    let digits = frac.chars().take(9).collect::<Vec<_>>();
    if digits.iter().any(|c| !c.is_ascii_digit()) {
        return None;
    }
    for (i, c) in digits.iter().enumerate() {
        nanos = nanos * 10 + c.to_digit(10)? as i128;
        if i + 1 == digits.len() {
            nanos *= 10i128.pow(8 - i as u32);
        }
    }
    let mag = secs * 1_000_000_000 + nanos;
    Some(if neg { -mag } else { mag })
}

/// Pax `mtime` text when ustar cannot carry the time: a fraction, or anything before the epoch.
fn format_pax_mtime(ns: i128) -> Option<String> {
    if ns >= 0 && ns % 1_000_000_000 == 0 {
        return None;
    }
    let neg = ns < 0;
    let mag = ns.unsigned_abs();
    let secs = mag / 1_000_000_000;
    let frac = mag % 1_000_000_000;
    let body = if frac == 0 {
        format!("{secs}")
    } else {
        format!("{secs}.{frac:09}")
    };
    Some(if neg { format!("-{body}") } else { body })
}

fn kind_of_typeflag(t: u8) -> Option<Kind> {
    match t {
        // 'S' is old-GNU sparse: a file, whose bytes are laid out by the map in its header
        b'0' | b'\0' | b'7' | b'S' => Some(Kind::File),
        b'1' => Some(Kind::File), // a hard link: a file with another name
        b'2' => Some(Kind::Symlink),
        b'5' => Some(Kind::Dir),
        _ => None,
    }
}

/// Reads the whole archive's headers, following pax and GNU long-name entries.
fn scan(path: &Path) -> io::Result<Index> {
    let mut f = io::BufReader::with_capacity(64 << 10, File::open(path)?);
    let mut index = Index::default();
    let mut offset: u64 = 0;
    let mut extended: BTreeMap<String, String> = BTreeMap::new();
    let mut extended_list: Vec<(String, String)> = Vec::new();
    // A global pax header (`g`) applies to every following member until a later one
    // replaces a key. It is not cleared with the per-file records.
    let mut global: BTreeMap<String, String> = BTreeMap::new();
    let mut long_name: Option<String> = None;
    let mut long_link: Option<String> = None;
    let mut zero_blocks = 0;
    // an inode of our own per member, so hard links inside the archive are recognized the
    // way they are on a filesystem; which members share one is settled below, when every
    // member is known and a link that names a member scanned later can still find it
    let mut next_ino: u64 = 1;
    loop {
        let mut block = [0u8; BLOCK];
        match f.read_exact(&mut block) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        offset += BLOCK as u64;
        if block.iter().all(|b| *b == 0) {
            zero_blocks += 1;
            if zero_blocks >= 2 {
                break;
            }
            continue;
        }
        zero_blocks = 0;
        let want = number(&block[148..156])?;
        if checksum(&block) != want as u32 {
            return Err(bad(&format!(
                "{}: a header at byte {} does not checksum; this is not a tar archive",
                path.display(),
                offset - BLOCK as u64
            )));
        }
        let typeflag = block[156];
        let size = number(&block[124..136])?;
        // pax and GNU long headers carry a payload and describe the NEXT member
        if matches!(typeflag, b'x' | b'X' | b'L' | b'K' | b'g') {
            if size > MAX_EXTENDED {
                return Err(bad(&format!(
                    "an extended header of {size} bytes is not a header"
                )));
            }
            let mut payload = vec![0u8; size as usize];
            f.read_exact(&mut payload)?;
            let pad = blocks_for(size) - size;
            io::copy(&mut f.by_ref().take(pad), &mut io::sink())?;
            offset += blocks_for(size);
            match typeflag {
                b'x' | b'X' => {
                    // the ordered list too, for sparse 0.0's repeated offset/numbytes pairs
                    extended_list.extend(pax_list(&payload));
                    extended.extend(pax(&payload));
                }
                b'g' => {
                    global.extend(pax(&payload));
                }
                b'L' => long_name = Some(string(&payload)),
                _ => long_link = Some(string(&payload)),
            }
            continue;
        }
        // Global records fill anything this member did not set. A per-file record wins.
        for (k, v) in &global {
            extended.entry(k.clone()).or_insert_with(|| v.clone());
        }
        // A sparse member arrives here as an ORDINARY `0` member whose pax records say it
        // is not one. Three things have to be undone before anything else reads the header:
        // the name is a decoy (`./GNUSparseFile.NNN/real-name`), the size is the stored
        // size rather than the file's, and the first bytes of the data are the map, not the
        // file. GNU.sparse.name and .realsize carry the truth and are read FIRST, so every
        // line below sees the real member.
        let sparse_major = extended
            .remove("GNU.sparse.major")
            .and_then(|v| v.parse::<u64>().ok());
        let sparse_minor = extended
            .remove("GNU.sparse.minor")
            .and_then(|v| v.parse::<u64>().ok());
        let sparse_name = extended.remove("GNU.sparse.name");
        // `realsize` is 1.0's key; 0.0 and 0.1 spell the same thing `GNU.sparse.size`
        let sparse_realsize = extended
            .remove("GNU.sparse.realsize")
            .or_else(|| extended.remove("GNU.sparse.size"))
            .and_then(|v| v.parse::<u64>().ok());
        let sparse_map_text = extended.remove("GNU.sparse.map");
        let is_sparse_1_0 = sparse_major == Some(1) && sparse_minor == Some(0);

        // FOUR ENCODINGS OF ONE IDEA, and three of them have no `GNU.sparse.major` at all
        // -- that key arrived with 1.0. So a guard that only checked the major silently
        // let 0.0 and 0.1 through as ORDINARY members: the extents were read as the whole
        // file, the copy reported PASSED, and the file on the other side was a different
        // file. That is the worst shape a defect can take here and it is why this
        // recognizes every form rather than refusing the ones it does not know.
        //
        //   1.0      major=1 minor=0, map in the member's own data (handled below)
        //   0.1      GNU.sparse.map = "off,len,off,len,..." in the pax header
        //   0.0      alternating GNU.sparse.offset / GNU.sparse.numbytes records
        //   old-GNU  typeflag 'S', four pairs in the header, more in extension blocks
        let pax_sparse_0_x: Option<io::Result<Vec<(u64, u64)>>> = if is_sparse_1_0 {
            None
        } else if let Some(text) = &sparse_map_text {
            Some(sparse_map_0_1(
                text,
                &sparse_name.clone().unwrap_or_default(),
            ))
        } else if extended_list
            .iter()
            .any(|(k, _)| k == "GNU.sparse.offset" || k == "GNU.sparse.numbytes")
        {
            Some(sparse_map_0_0(
                &extended_list,
                &sparse_name.clone().unwrap_or_default(),
            ))
        } else {
            None
        };

        let name = sparse_name
            .clone()
            .or_else(|| long_name.take())
            .or_else(|| extended.remove("path"))
            .unwrap_or_else(|| {
                let prefix = string(&block[345..500]);
                let name = string(&block[0..100]);
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            });
        let link = long_link
            .take()
            .or_else(|| extended.remove("linkpath"))
            .unwrap_or_else(|| string(&block[157..257]));
        let size = extended
            .remove("size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(size);
        let mtime = extended
            .remove("mtime")
            .and_then(|t| pax_time(&t))
            .unwrap_or_else(|| signed_number(&block[136..148]).unwrap_or(0) * 1_000_000_000);
        let atime = extended
            .remove("atime")
            .and_then(|t| pax_time(&t))
            .unwrap_or(mtime);
        let uid = extended
            .remove("uid")
            .and_then(|v| v.parse().ok())
            .unwrap_or(number(&block[108..116]).unwrap_or(0) as u32);
        let gid = extended
            .remove("gid")
            .and_then(|v| v.parse().ok())
            .unwrap_or(number(&block[116..124]).unwrap_or(0) as u32);
        let mode = number(&block[100..108]).unwrap_or(0o644) as u32 & 0o7777;
        extended.clear();
        extended_list.clear();

        let data_at = offset;
        offset += blocks_for(size);
        // A sparse member's map is at the front of its own data, so unlike every other
        // member this one is READ rather than skipped. Only the map text is read -- bounded
        // by MAX_EXTENDED, the same bound an extended header gets, since it is the same
        // kind of attacker-controlled preamble -- and the extents themselves are skipped
        // like any other data.
        let mut old_gnu_realsize: Option<u64> = None;
        let mut sparse: Option<Sparse> = None;
        let is_file = kind_of_typeflag(typeflag) == Some(Kind::File) && typeflag != b'1';
        if is_sparse_1_0 && is_file {
            let head = size.min(MAX_EXTENDED) as usize;
            let mut buf = vec![0u8; head];
            f.read_exact(&mut buf)?;
            let (map, used) = sparse_map_1_0(&buf, &name)?;
            // the map text is NUL-padded to a block, and the data starts after that padding
            let map_blocks = blocks_for(used as u64);
            if map_blocks > size {
                return Err(bad(&format!(
                    "{name}: a sparse map of {used} bytes does not fit the {size}-byte member"
                )));
            }
            sparse = Some(Sparse {
                map,
                at: data_at + map_blocks,
            });
            io::copy(
                &mut f.by_ref().take(blocks_for(size) - head as u64),
                &mut io::sink(),
            )?;
        } else if let Some(map) = pax_sparse_0_x.filter(|_| is_file) {
            // 0.0 and 0.1 keep the map in the HEADER, so the member's data is nothing but
            // the extents and the first byte of data is the first byte of the member.
            sparse = Some(Sparse {
                map: map?,
                at: data_at,
            });
            io::copy(&mut f.by_ref().take(blocks_for(size)), &mut io::sink())?;
        } else if typeflag == b'S' {
            // Old-GNU. The map is in the header, continued in as many extension blocks as
            // its `isextended` flags chain -- and those blocks sit BETWEEN the header and
            // the data, so the data offset moves with them.
            let (mut map, realsize, mut more) = sparse_old_gnu(&block)?;
            let mut extra_blocks = 0u64;
            while more {
                let mut ext = [0u8; BLOCK];
                f.read_exact(&mut ext)?;
                extra_blocks += 1;
                if extra_blocks as usize * 21 > MAX_SPARSE_EXTENTS {
                    return Err(bad(&format!(
                        "{name}: an old-GNU sparse map that never ends"
                    )));
                }
                let (more_map, again) = sparse_old_gnu_extension(&ext)?;
                map.extend(more_map);
                more = again;
            }
            let data_at = data_at + extra_blocks * BLOCK as u64;
            offset += extra_blocks * BLOCK as u64;
            old_gnu_realsize = Some(realsize);
            sparse = Some(Sparse { map, at: data_at });
            io::copy(&mut f.by_ref().take(blocks_for(size)), &mut io::sink())?;
        } else {
            io::copy(&mut f.by_ref().take(blocks_for(size)), &mut io::sink())?;
        }

        let Some(kind) = kind_of_typeflag(typeflag) else {
            index.errors.push(format!(
                "{name}: a member of type {:?} is not a file, directory or symlink",
                typeflag as char
            ));
            continue;
        };
        let Some(rel) = rel_name(&name) else {
            index.errors.push(format!(
                "{name}: a member that climbs out of the archive with `..` is refused"
            ));
            continue;
        };
        next_ino += 1;
        let (dev, ino, nlink) = (1, next_ino, 1);
        let size = if kind == Kind::File && typeflag != b'1' {
            size
        } else {
            0
        };
        // A sparse member's header size is what the archive STORES; the file's size is
        // GNU.sparse.realsize. Everything downstream -- listing, verify, the reader's own
        // bound -- wants the file's, and the stored size is only ever needed to walk the
        // archive, which is already done by here.
        let (size, blocks) = match (&sparse, sparse_realsize.or(old_gnu_realsize)) {
            (Some(s), Some(real)) => {
                s.validate(real, &name)?;
                (real, blocks_for(s.stored()) / 512)
            }
            (Some(_), None) => return Err(bad(&format!("{name}: a sparse member with no GNU.sparse.realsize does not say how long the file is"))),
            _ => (size, blocks_for(size) / 512),
        };
        let item = Item {
            rel: rel.clone(),
            kind,
            size,
            mtime_ns: mtime,
            atime_ns: atime,
            mode,
            uid,
            gid,
            dev,
            ino,
            nlink,
            blocks,
            link_target: if kind == Kind::Symlink {
                Some(PathBuf::from(&link))
            } else {
                None
            },
        };
        index.members.insert(
            rel,
            Member {
                item,
                offset: data_at,
                link_to: if typeflag == b'1' {
                    rel_name(&link)
                } else {
                    None
                },
                sparse,
            },
        );
    }
    // A `1` member is a second name for another member's inode, and tar allows it to name
    // one that appears later. Both ends get the same device and inode and an nlink of 2,
    // which is what makes `verify` see one file rather than two, and the link takes the
    // size it points at -- its own header says zero, since its bytes are over there.
    let links: Vec<(String, String)> = index
        .members
        .iter()
        .filter_map(|(rel, m)| m.link_to.clone().map(|t| (rel.clone(), t)))
        .collect();
    for (rel, target) in links {
        let Some(t) = index.members.get(&target) else {
            index.errors.push(format!(
                "{rel}: links to {target}, which this archive does not have"
            ));
            continue;
        };
        let (dev, ino, size) = (t.item.dev, t.item.ino, t.item.size);
        if let Some(m) = index.members.get_mut(&target) {
            m.item.nlink = 2;
        }
        if let Some(m) = index.members.get_mut(&rel) {
            m.item.dev = dev;
            m.item.ino = ino;
            m.item.size = size;
            m.item.nlink = 2;
            m.item.blocks = blocks_for(size) / 512;
        }
    }
    Ok(index)
}

/// `./a/b/`, `a/b` and `/a/b` all name `a/b`, and `.` or `./` names the archive's own root.
/// `None` is a member that climbs out of the archive with `..`, which is refused rather
/// than normalized, since that is the tar extraction attack. The empty string and `None`
/// are deliberately different answers: one is the root, the other is an escape.
fn normalize(name: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

/// A member name as a path relative to the archive root: the root itself is `.`.
fn rel_name(name: &str) -> Option<String> {
    match normalize(name) {
        Some(r) if r.is_empty() => Some(".".to_string()),
        other => other,
    }
}

// ---------------------------------------------------------------------------------------------
// the tree
// ---------------------------------------------------------------------------------------------

/// The archive, shared by the tree and every sink it makes: one stream, one lock.
pub struct Shared {
    path: PathBuf,
    display: PathBuf,
    /// The subpath inside the archive this endpoint roots at, `""` for the whole archive.
    sub: String,
    settings: Settings,
    /// The scan, taken once and shared; `None` until the first read.
    index: Mutex<Option<Arc<Index>>>,
    /// The append stream, for a destination.
    out: Mutex<Option<Writer>>,
    /// Whether this endpoint was opened to be written.
    create: bool,
    /// The decompressed copy of a `.tar.gz` or `.tar.zst`, deleted when this tree is
    /// dropped.
    ///
    /// The rest of this adapter reads the archive by SEEKING to a member's offset, and
    /// neither a gzip nor a zstd stream has offsets to seek to. Decompressing once to a temp file keeps that
    /// whole design, and the file is what every later read seeks in.
    ///
    /// **It does NOT yet cost disk rather than memory, whatever the design suggests.**
    /// `expand_if_needed` reads the whole archive into a `Vec` and expands it into another
    /// one before writing the file, so the peak is input + output in RAM and `MAX_EXPANDED`
    /// is an RSS ceiling, not a disk one. Streaming the decode is a separate piece of work
    /// -- neither decoder here suspends mid-stream -- and until one does the honest
    /// statement is the one here rather than the design it is aiming at.
    _expanded: Option<TempFile>,
}

/// A path that is removed when it goes out of scope.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The ceiling on a decompressed archive: 64 GiB.
///
/// A gzip stream can expand about 1032:1, so a few megabytes of input can ask for
/// terabytes. This is large enough for any real archive and small enough that a hostile
/// one fails with a message rather than exhausting the machine.
///
/// **Read this as a MEMORY ceiling, not a disk one**, because the decode is not streaming:
/// the expanded archive exists as a `Vec` before it reaches the temp file. 64 GiB of RSS
/// is not a limit any machine here can reach, so in practice the OOM killer is the real
/// bound and this constant only catches the absurd cases. Lowering it would be arbitrary;
/// making the decode stream is the fix, and that is its own item.
const MAX_EXPANDED: usize = 64 << 30;

/// Where a decompressed archive is written: `RCP_TMPDIR` if set, else the system temp
/// directory.
///
/// `RCP_TMPDIR` appeared in a comment here and was never read, so the escape hatch the
/// comment promised -- "point RCP_TMPDIR if the default is too small" -- did not exist. An
/// expanded OCI layer is routinely gigabytes and `/tmp` is routinely a small tmpfs, so
/// this is the difference between a copy that runs and one that fills a ramdisk.
fn tmp_root() -> PathBuf {
    match std::env::var_os("RCP_TMPDIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => std::env::temp_dir(),
    }
}

/// What the first bytes of an archive say wraps it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wrap {
    Plain,
    Gzip,
    Zstd,
}

impl Wrap {
    /// Decides from the MAGIC, not the name. A zstd file may also begin with a skippable
    /// frame (`0x184D2A5?`): `pzstd` writes one ahead of every data frame to record its
    /// size, so sniffing only the data-frame magic would hand a `pzstd` archive to the
    /// tar scan as-is. Measured with the skippable arm removed: the scan refuses it with
    /// "a header at byte 0 does not checksum; this is not a tar archive" -- loud, which
    /// is better than the gzip case below once was, and still a readable archive refused.
    fn sniff(head: &[u8]) -> Wrap {
        if crate::deflate::is_gzip(head) {
            return Wrap::Gzip;
        }
        if head.len() >= 4 {
            let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
            if magic == crate::zstd::MAGIC || magic & 0xFFFF_FFF0 == 0x184D_2A50 {
                return Wrap::Zstd;
            }
        }
        Wrap::Plain
    }
}

/// If `archive` is gzip or zstd, decompresses it into a temp file and returns its path.
///
/// Measured before this existed: `rcp copy tar://a.tar.gz /dest` exited 0, reported
/// `0 files`, and wrote nothing -- because a gzip member's first 512 bytes are not a tar
/// header, the scan found no members, and an archive with no members is not an error. A
/// silent empty copy is the worst shape a data mover has, so the decode is not optional
/// and a gzip archive that cannot be decoded is a failure with the reason in it.
///
/// zstd arrived later and did not share that failure: by then the scan checked the first
/// header's checksum, so a `.tar.zst` was refused as "not a tar archive" rather than read
/// as empty. Refused is still not read, which is what the zstd arm here fixes.
fn expand_if_needed(archive: &Path, settings: &Settings) -> io::Result<Option<TempFile>> {
    let mut head = Vec::with_capacity(4);
    {
        // `take(4).read_to_end`, not one `read`: a single read may return fewer bytes
        // than are there, and a short head would sniff as plain.
        let f = File::open(archive).map_err(|e| ctx(e, archive))?;
        f.take(4)
            .read_to_end(&mut head)
            .map_err(|e| ctx(e, archive))?;
    }
    let wrap = Wrap::sniff(&head);
    if wrap == Wrap::Plain {
        return Ok(None);
    }
    let raw = std::fs::read(archive).map_err(|e| ctx(e, archive))?;
    let out = match wrap {
        // The same `workers` that compresses members on the way out decompresses them on
        // the way in; the members are independent in both directions.
        Wrap::Gzip => crate::deflate::gunzip_with(&raw, MAX_EXPANDED, settings.workers),
        // Every frame, in order, into one buffer. zstd frames are as independent as gzip
        // members, but this decoder has no parallel entry point yet, so it is serial.
        Wrap::Zstd => crate::zstd::decompress(&raw, MAX_EXPANDED),
        Wrap::Plain => unreachable!("returned above"),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", archive.display())))?;
    // Beside the archive would need write permission there; `tmp_root` is the temp
    // directory, which `RCP_TMPDIR` can move.
    let path = tmp_root().join(format!(
        "rcp-tar-{}-{}.tar",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // The handle is registered for cleanup BEFORE anything can fail, because `TempFile`
    // was constructed after the `?` below and a write that ran out of space, or a signal
    // between the write and the return, left the partial archive in `/tmp` forever.
    let temp = TempFile(path.clone());
    // `create_new` and `mode`, not `fs::write`. `fs::write` opens with `O_CREAT|O_TRUNC`
    // and the process umask, so in a world-writable `/tmp` it followed a symlink planted
    // at the predictable name and truncated whatever it pointed at, and left the expanded
    // archive -- which is the CONTENT of whatever the caller is copying -- readable by
    // every user on the host. `create_new` makes a planted name an error instead.
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| ctx(e, &path))?;
        f.write_all(&out).map_err(|e| ctx(e, &path))?;
    }
    crate::debug!(
        settings.log,
        "tar {}: {wrap:?}, {} bytes expanded to {} at {}",
        archive.display(),
        raw.len(),
        out.len(),
        path.display()
    );
    Ok(Some(temp))
}

/// What the archive's NAME says it is wrapped in, for a `create`.
///
/// On READ the magic bytes decide (`expand_if_needed`), because a name is a claim and the
/// first two bytes are the fact. On CREATE there are no bytes yet, so the name is all
/// there is -- and it is binding. Until this existed, `rcp copy /tree tar://out.tar.gz`
/// wrote a PLAIN TAR under a `.gz` name, which `tar xzf` and `gzip -d` both reject: a
/// silent wrong output, the worst shape of defect this crate can produce.
/// The name to store in the gzip `FNAME` field, which is what `gzip -dN` writes back.
///
/// THIS HAS TO AGREE WITH `wrapper_for_create`, AND FOR A WHILE IT DID NOT. That function
/// lowercases before matching, so `Foo.Tgz` and `Foo.Gz` are accepted as gzip; this one
/// stripped only the four literal spellings `.gz`, `.GZ`, `.tgz`, `.TGZ`, so those two
/// fell through to the default and stored `Foo.Tgz.tar` and `Foo.Gz.tar` -- a name the
/// caller never wrote, on a stream that decompresses correctly, so nothing round-trips
/// red. The suffix is matched case-insensitively here too and the stem keeps its ORIGINAL
/// spelling: `out.TAR.GZ` stores `out.TAR`, not `out.tar`.
///
/// The old form also used `trim_end_matches`, which strips EVERY trailing occurrence
/// rather than one, so `a.tgz.tgz` stored `a.tar` and silently lost a suffix.
///
/// `None` means store no name at all, which is a legal header (RFC 1952: the flag is
/// simply clear) and says nothing false. Two cases reach it: a name that is not UTF-8,
/// where a lossy conversion would have `gzip -dN` write back a file nobody asked for, and
/// a name that is exactly `.gz`, whose stem is empty -- a set `FNAME` flag with a lone NUL
/// behind it.
fn gzip_stem(archive: &Path) -> Option<String> {
    let name = archive.file_name().and_then(|n| n.to_str())?;
    let lower = name.to_ascii_lowercase();
    // ASCII lowercasing never changes a byte's length, and leaves non-ASCII bytes alone,
    // so an index taken from `lower` is a char boundary in `name`.
    let stem = if let Some(cut) = lower.strip_suffix(".gz") {
        name[..cut.len()].to_owned()
    } else if let Some(cut) = lower.strip_suffix(".tgz") {
        format!("{}.tar", &name[..cut.len()])
    } else {
        format!("{name}.tar")
    };
    (!stem.is_empty()).then_some(stem)
}

fn wrapper_for_create(archive: &Path) -> io::Result<Wrap> {
    // MATCHED ON RAW BYTES, NOT ON `to_str()`, AND THAT IS THE WHOLE POINT.
    //
    // The first version did `file_name().and_then(|n| n.to_str()).unwrap_or_default()`,
    // which turns a name that is not valid UTF-8 into the EMPTY STRING. A destination
    // whose last component is `b"bad\xff\xfename.tar.gz"` therefore matched no suffix:
    // not compressed, and not refused either. It got a plain tar under a `.gz` name --
    // the exact defect this function exists to prevent, revived by a lossy conversion.
    // A path on Unix is bytes; asking whether it ends in `.gz` is a question about
    // bytes, and `to_str()` answers a different one.
    use std::os::unix::ffi::OsStrExt;
    let raw: Vec<u8> = archive
        .file_name()
        .map(|n| n.as_bytes().to_ascii_lowercase())
        .unwrap_or_default();
    let ends = |suffix: &str| raw.ends_with(suffix.as_bytes());
    // The same reasoning refuses the wrappers this crate does NOT write. Accepting them
    // silently would reintroduce exactly the defect above under a different suffix.
    for (suffix, what) in [
        (".bz2", "bzip2"),
        (".tbz", "bzip2"),
        (".tbz2", "bzip2"),
        (".xz", "xz"),
        (".txz", "xz"),
        (".lzma", "lzma"),
        (".lz", "lzip"),
        (".z", "compress"),
    ] {
        if ends(suffix) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: this name says {what}, which rcp does not write; name it `.tar`, `.tar.gz` or `.tar.zst`", archive.display()),
            ));
        }
    }
    // `.zst` and `.tzst` are the two suffixes GNU tar's `-a` maps to zstd.
    Ok(if ends(".gz") || ends(".tgz") {
        Wrap::Gzip
    } else if ends(".zst") || ends(".tzst") {
        Wrap::Zstd
    } else {
        Wrap::Plain
    })
}

/// Where an archive's bytes go: straight to the file, or through the member encoder,
/// which writes gzip members or zstd frames.
///
/// The encoder writes independent members of `GZIP_BLOCK` each rather than compressing
/// the archive as one slice, so the peak memory is one block and not the whole tree.
enum Out {
    Plain(File),
    Packed(Box<crate::deflate::GzipWriter<File>>),
    /// Held for the instant `finish` consumes the encoder, and after the archive is done.
    Spent,
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Out::Plain(f) => f.write(data),
            Out::Packed(g) => g.write(data),
            Out::Spent => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "this archive is already finished",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Out::Plain(f) => f.flush(),
            Out::Packed(g) => g.flush(),
            Out::Spent => Ok(()),
        }
    }
}

impl Out {
    /// Ends the stream and puts it on the disk.
    ///
    /// For the gzip case this is what writes the final member; without it the file stops
    /// mid-stream and every reader reports it truncated. `sync_all` is on the FILE, so it
    /// has to happen after the encoder has handed the file back -- flushing the encoder
    /// alone would fsync nothing.
    ///
    /// **What a run that dies before `sync` leaves behind, stated exactly, because two
    /// earlier drafts of this comment were wrong in OPPOSITE directions.**
    ///
    /// The first said a gzip failure is like a truncated tar. The second over-corrected
    /// to "nothing at all". Neither is right, and the true answer is the uncomfortable
    /// one:
    ///
    /// - Under `GZIP_BLOCK` of tar was written: the file may still be length 0, because
    ///   no member has been flushed. Nothing to salvage, and a retry is not blocked.
    /// - Past the first member: the flushed members are COMPLETE, each with its own CRC
    ///   and length. What is on disk is **legal concatenated gzip** of a truncated tar.
    ///   `gzip -t` PASSES it. `tar tzf` lists some members and then errors.
    ///
    /// That second case is worse than the defect this whole path exists to fix, in one
    /// specific way: the plain-tar-under-a-`.gz`-name failed `gzip -d` on the first byte,
    /// where this passes an integrity check and is wrong further in. `sync_publishes` is
    /// true for `create` and the run reports its failure, so nothing claims success --
    /// but an operator who reaches for `gzip -t` to decide whether the file survived
    /// will be told yes.
    ///
    /// There is deliberately no `Drop` finishing the stream: a `Drop` cannot report the
    /// write error it would hit on exactly this path, and finishing it would turn a
    /// truncated archive into a *well-formed* truncated archive, which is the direction
    /// away from loud. The leftover also trips `open`'s "this archive already has
    /// something in it" refusal, so a retry needs the file removed first -- annoying,
    /// and the right trade against silently overwriting.
    fn finish(&mut self) -> io::Result<()> {
        match std::mem::replace(self, Out::Spent) {
            Out::Plain(mut f) => {
                f.flush()?;
                f.sync_all()?;
            }
            Out::Packed(g) => {
                let f = g.finish()?;
                f.sync_all()?;
            }
            Out::Spent => {}
        }
        Ok(())
    }
}

/// A tar archive as a tree. The state is behind an `Arc` because a sink outlives the call
/// that made it and writes through the same stream.
pub struct TarTree(Arc<Shared>);

impl std::ops::Deref for TarTree {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.0
    }
}

struct Writer {
    file: Out,
    /// Members written so far, so a hard link can name one and a second copy of the same
    /// inode becomes a link rather than the bytes again.
    by_inode: BTreeMap<(u64, u64), String>,
    /// What each written member's header said, so a hard link to one can carry the same
    /// mode and times rather than a default.
    by_name: BTreeMap<String, Item>,
    /// Directories and symlinks whose header waits for `set_metadata` to say what its mode
    /// and times are. `mkdir` and `symlink` are told the path and nothing else, so writing
    /// then would put a default in the archive and there is no second pass over a stream.
    pending: BTreeMap<String, Pending>,
    /// Set once the end-of-archive marker is written, so `sync` is idempotent.
    closed: bool,
}

#[derive(Clone)]
enum Pending {
    Dir,
    Symlink(String),
}

impl TarTree {
    /// `tar://ARCHIVE[!/SUBPATH]`. The archive is a local path; `create` makes an empty one
    /// (truncating what is there), since a tar cannot be edited in place.
    pub fn open(
        archive: &Path,
        sub: &str,
        create: bool,
        settings: &Settings,
    ) -> io::Result<TarTree> {
        let sub = normalize(sub).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tar://{}!/{sub}: a subpath may not climb out of the archive with `..`",
                    archive.display()
                ),
            )
        })?;
        let display = PathBuf::from(if sub.is_empty() {
            format!("tar://{}", archive.display())
        } else {
            format!("tar://{}!/{sub}", archive.display())
        });
        // A gzip or zstd archive is decompressed on the way in and compressed on the way out. The
        // two directions decide differently on purpose: reading sniffs the magic bytes,
        // creating reads the name, because a file that does not exist yet has no bytes to
        // sniff. See `wrapper_for_create`.
        let expanded = if create {
            None
        } else {
            expand_if_needed(archive, settings)?
        };
        let tree = Shared {
            path: expanded
                .as_ref()
                .map_or_else(|| archive.to_path_buf(), |t| t.0.clone()),
            display,
            sub,
            settings: settings.clone(),
            index: Mutex::new(None),
            out: Mutex::new(None),
            create,
            _expanded: expanded,
        };
        if create {
            if !tree.sub.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{}: a subpath names what to read out of an archive, not where to write into one", tree.display.display())));
            }
            // An archive is written once from start to finish, so opening one to write
            // TRUNCATES it -- and a truncated destination lists as empty, which means the
            // plan cannot show the loss and `-requireconfirm` cannot catch it either. An
            // archive that is already there is refused by name instead.
            if std::fs::metadata(archive).is_ok_and(|m| m.len() > 0) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{}: this archive already has something in it, and writing one rewrites it from the start; remove it or name another path", archive.display()),
                ));
            }
            // before the file is made, so a name rcp cannot write leaves nothing behind
            let wrap = wrapper_for_create(archive)?;
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(archive)
                .map_err(|e| ctx(e, archive))?;
            // The stored name is the archive's own, minus the `.gz`, which is what `gzip
            // -dN` and `tar` write it back as. The mtime is left at 0 rather than the
            // clock, so the gzip HEADER does not differ between two runs over the same
            // tree.
            //
            // That is all it buys; it does not make the whole archive reproducible: the
            // tar members carry their own mtimes, uids and modes from the source, and the
            // walk order decides their sequence. A reproducible `.tar.gz` needs all of those pinned, which is a
            // different piece of work; this only removes the clock this code would
            // otherwise have added by itself.
            let file = if wrap == Wrap::Zstd {
                Out::Packed(Box::new(crate::deflate::GzipWriter::zstd(
                    file,
                    settings.workers,
                    settings.rsyncable,
                )))
            } else if wrap == Wrap::Gzip {
                // A name that is not UTF-8 stores NO name rather than a lossy one. The
                // gzip FNAME field is NUL-terminated bytes, so a mangled name would be
                // written back by `gzip -dN` as a file the caller never asked for. An
                // absent FNAME is a legal header (RFC 1952: the flag is simply clear)
                // and says nothing false.
                let stem = gzip_stem(archive);
                Out::Packed(Box::new(if settings.rsyncable {
                    crate::deflate::GzipWriter::rsyncable(
                        file,
                        stem.as_deref(),
                        0,
                        settings.workers,
                    )
                } else {
                    crate::deflate::GzipWriter::with_workers(
                        file,
                        stem.as_deref(),
                        0,
                        settings.workers,
                    )
                }))
            } else {
                Out::Plain(file)
            };
            *tree.out.lock().unwrap() = Some(Writer {
                file,
                by_inode: BTreeMap::new(),
                by_name: BTreeMap::new(),
                pending: BTreeMap::new(),
                closed: false,
            });
        } else {
            // fail now, with the archive's name, rather than at the first read
            File::open(archive).map_err(|e| ctx(e, archive))?;
        }
        Ok(TarTree(Arc::new(tree)))
    }
}

impl Shared {
    fn ctx_index(&self) -> io::Result<Arc<Index>> {
        let mut slot = self.index.lock().unwrap();
        if slot.is_none() {
            let index = scan(&self.path)?;
            crate::debug!(
                self.settings.log,
                "tar {}: {} members",
                self.path.display(),
                index.members.len()
            );
            *slot = Some(Arc::new(index));
        }
        Ok(slot.as_ref().unwrap().clone())
    }

    /// The member's name for a path relative to this endpoint's root.
    fn member_name(&self, rel: &str) -> String {
        match (self.sub.is_empty(), rel) {
            // `.` is how tar names an archive's own root, and it is a member like any
            // other: without it the root's mode and times are nobody's
            (true, ".") => ".".to_string(),
            (true, _) => rel.to_string(),
            (false, ".") => self.sub.clone(),
            (false, _) => format!("{}/{rel}", self.sub),
        }
    }

    /// The path relative to this endpoint's root for a member name, or `None` when the
    /// member is outside it.
    fn rel_of(&self, name: &str) -> Option<String> {
        if self.sub.is_empty() {
            return Some(name.to_string());
        }
        if name == self.sub {
            return Some(".".to_string());
        }
        name.strip_prefix(&format!("{}/", self.sub))
            .map(str::to_string)
    }

    fn member(&self, rel: &str) -> io::Result<Option<Member>> {
        let index = self.ctx_index()?;
        Ok(index.members.get(&self.member_name(rel)).cloned())
    }

    fn writer<T>(&self, f: impl FnOnce(&mut Writer) -> io::Result<T>) -> io::Result<T> {
        let mut out = self.out.lock().unwrap();
        let w = out.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}: this archive was opened to read",
                    self.display.display()
                ),
            )
        })?;
        if w.closed {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}: the archive has been finished; nothing more can be added",
                    self.display.display()
                ),
            ));
        }
        f(w)
    }

    /// One member header, with the pax extended header in front of it when ustar cannot
    /// carry a field.
    fn write_header(
        &self,
        w: &mut Writer,
        name: &str,
        item: &Item,
        typeflag: u8,
        link: &str,
        size: u64,
    ) -> io::Result<()> {
        let mut records = String::new();
        let mut record = |key: &str, value: &str| records.push_str(&pax_record(key, value));
        let (mut ustar_name, mut prefix) = split_name(name);
        if ustar_name.is_empty() {
            record("path", name);
            // something has to be in the field for older readers
            ustar_name = name
                .rsplit('/')
                .next()
                .unwrap_or("member")
                .chars()
                .take(100)
                .collect();
            prefix = String::new();
        }
        if link.len() > 100 {
            record("linkpath", link);
        }
        if size >= 1 << 33 {
            record("size", &size.to_string());
        }
        if let Some(text) = format_pax_mtime(item.mtime_ns) {
            record("mtime", &text);
        }
        if item.uid > 0o7777777 {
            record("uid", &item.uid.to_string());
        }
        if item.gid > 0o7777777 {
            record("gid", &item.gid.to_string());
        }
        if !records.is_empty() {
            let mut header = [0u8; BLOCK];
            let pax_name = format!("PaxHeaders/{}", name.rsplit('/').next().unwrap_or("member"));
            put_str(&mut header[0..100], &pax_name);
            put_number(&mut header[100..108], 0o644);
            put_number(&mut header[108..116], 0);
            put_number(&mut header[116..124], 0);
            put_number(&mut header[124..136], records.len() as u64);
            put_number(
                &mut header[136..148],
                (item.mtime_ns / 1_000_000_000).max(0) as u64,
            );
            header[156] = b'x';
            put_str(&mut header[257..263], "ustar");
            header[263..265].copy_from_slice(b"00");
            seal(&mut header);
            w.file.write_all(&header)?;
            w.file.write_all(records.as_bytes())?;
            let pad = blocks_for(records.len() as u64) as usize - records.len();
            w.file.write_all(&vec![0u8; pad])?;
        }

        let mut header = [0u8; BLOCK];
        put_str(&mut header[0..100], &ustar_name);
        put_number(&mut header[100..108], (item.mode & 0o7777) as u64);
        put_number(&mut header[108..116], item.uid as u64);
        put_number(&mut header[116..124], item.gid as u64);
        put_number(&mut header[124..136], size);
        put_number(
            &mut header[136..148],
            (item.mtime_ns / 1_000_000_000).max(0) as u64,
        );
        header[156] = typeflag;
        put_str(
            &mut header[157..257],
            &link.chars().take(100).collect::<String>(),
        );
        put_str(&mut header[257..263], "ustar");
        header[263..265].copy_from_slice(b"00");
        if let Some(names) = &self.settings.names {
            put_str(&mut header[265..297], &names.user(item.uid));
            put_str(&mut header[297..329], &names.group(item.gid));
        }
        put_str(&mut header[345..500], &prefix);
        seal(&mut header);
        w.file.write_all(&header)
    }
}

/// The checksum field, written last, as every tar writer does.
fn seal(header: &mut [u8; BLOCK]) {
    let sum = checksum(header);
    let text = format!("{sum:06o}\0 ");
    header[148..148 + text.len()].copy_from_slice(text.as_bytes());
}

/// ustar's name is 100 bytes with a 155-byte prefix, split at a `/`. Returns empty when the
/// name will not split, which is what makes a pax `path` record necessary.
fn split_name(name: &str) -> (String, String) {
    if name.len() <= 100 {
        return (name.to_string(), String::new());
    }
    // the longest prefix that leaves a name of 100 bytes or less
    let mut best: Option<usize> = None;
    for (i, _) in name.match_indices('/') {
        if i <= 155 && name.len() - i - 1 <= 100 {
            best = Some(i);
        }
    }
    match best {
        Some(i) => (name[i + 1..].to_string(), name[..i].to_string()),
        None => (String::new(), String::new()),
    }
}

/// What a header carries when the copy never told us: a tar entry still needs a mode.
fn default_item(rel: &str, kind: Kind, mode: u32) -> Item {
    Item {
        rel: rel.to_string(),
        kind,
        size: 0,
        mtime_ns: 0,
        atime_ns: 0,
        mode,
        uid: 0,
        gid: 0,
        dev: 1,
        ino: 0,
        nlink: 1,
        blocks: 0,
        link_target: None,
    }
}

fn ctx(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

pub struct TarReader {
    file: File,
    start: u64,
    size: u64,
    pos: u64,
    /// For a sparse member, the layout its bytes really have. `start` is then unused for
    /// positioning -- `Sparse::at` is where the extents begin -- and every read has to be
    /// placed by the map.
    sparse: Option<Sparse>,
}

impl TarReader {
    /// Where logical position `pos` is in the archive, and how many bytes of the same kind
    /// run from there.
    ///
    /// `Some(offset)` is data at that archive offset; `None` is a hole. The length is
    /// clamped to the end of the extent or of the hole, so a caller that loops on it walks
    /// the member one uniform run at a time.
    fn locate(&self, sparse: &Sparse, pos: u64) -> (Option<u64>, u64) {
        let mut stored = 0u64;
        for (off, len) in &sparse.map {
            if pos < *off {
                // in the hole that ends where this extent starts
                return (None, off - pos);
            }
            if pos < off + len {
                return (Some(sparse.at + stored + (pos - off)), off + len - pos);
            }
            stored += len;
        }
        // past the last extent: the trailing hole, out to the end of the file
        (None, self.size.saturating_sub(pos))
    }
}

impl Read for TarReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.size.saturating_sub(self.pos);
        if left == 0 {
            return Ok(0);
        }
        let want = buf.len().min(left as usize);
        let Some(sparse) = self.sparse.clone() else {
            let n = self.file.read(&mut buf[..want])?;
            self.pos += n as u64;
            return Ok(n);
        };
        // One run per call: a read never straddles the boundary between stored bytes and a
        // hole, so the file handle only ever has to be where the map says. Returning short
        // is what `Read` allows and what keeps this loop-free.
        let (at, run) = self.locate(&sparse, self.pos);
        let want = want.min(run as usize);
        match at {
            Some(offset) => {
                self.file.seek(SeekFrom::Start(offset))?;
                let n = self.file.read(&mut buf[..want])?;
                self.pos += n as u64;
                Ok(n)
            }
            None => {
                buf[..want].fill(0);
                self.pos += want as u64;
                Ok(want)
            }
        }
    }
}

impl Seek for TarReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let want = match from {
            SeekFrom::Start(n) => n,
            SeekFrom::End(d) => (self.size as i64 + d).max(0) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d).max(0) as u64,
        };
        let want = want.min(self.size);
        // A sparse member places the handle per read, so seeking it here would be a lie
        // the next read overwrites anyway; the logical position is the whole state.
        if self.sparse.is_none() {
            self.file.seek(SeekFrom::Start(self.start + want))?;
        }
        self.pos = want;
        Ok(want)
    }
}

/// One member being appended. The header goes down at `reserve`, because tar declares the
/// size before the bytes, and `finish` pads to the block.
pub struct TarSink {
    tree: Arc<Shared>,
    item: Item,
    written: u64,
    declared: u64,
    started: bool,
    /// A hard link to a member already written: no bytes, a `1` header at `finish`.
    link_to: Option<String>,
    /// How this member is being laid down. See `Layout`.
    layout: Layout,
}

/// The largest run of data a member can take before this sink stops waiting to see whether
/// a hole arrives and commits to the ordinary layout.
///
/// A member's header has to be written before its bytes, and a sparse header depends on the
/// WHOLE map, which is only known once the last byte has been seen. So the choice cannot be
/// made up front and cannot be deferred to the end either -- deferring would mean buffering
/// every dense file in the tree. The compromise: hold the first few MB, and decide.
///
/// A file with holes almost always has one early (that is what makes it sparse: an
/// allocation pattern, not a coincidence at the tail). A file whose first 8 MiB are solid
/// is taken to be dense, and if a hole shows up later it is written as the zeros it stands
/// for, exactly as before this existed -- correct, just larger. That is stated here rather
/// than discovered, because it is a real limit and not a bug.
const SPARSE_DECIDE: u64 = 8 << 20;

/// How a member's bytes are being written.
enum Layout {
    /// Nothing decided yet: bytes are held in `head` until a hole appears (sparse) or the
    /// held run passes `SPARSE_DECIDE` (ordinary).
    Undecided { head: Vec<u8> },
    /// The ordinary layout: header already written, bytes stream straight through.
    Plain,
    /// Sparse: extents recorded, their bytes spilled to a temp file, header written at
    /// `finish` once the map is complete.
    Sparse(SparseSpill),
}

/// The non-hole bytes of a sparse member, on their way to the archive.
///
/// They go to a temp file rather than memory because "sparse" bounds the HOLES, not the
/// data: a 1 TiB file that is half holes still has 512 GiB of bytes. The spill is the
/// stored size, which is exactly what the archive will hold.
struct SparseSpill {
    file: File,
    path: PathBuf,
    /// `(logical offset, length)` per extent, in order.
    map: Vec<(u64, u64)>,
    /// Logical position the next byte lands at.
    pos: u64,
}

impl Drop for SparseSpill {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl SparseSpill {
    fn new(rel: &str) -> io::Result<SparseSpill> {
        let dir = tmp_root();
        std::fs::create_dir_all(&dir)?;
        let stem: String = rel
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(40)
            .collect();
        for n in 0..16 {
            let path = dir.join(format!(
                "sparse-{stem}-{}-{:?}-{n}",
                std::process::id(),
                std::thread::current().id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(SparseSpill {
                        file,
                        path,
                        map: Vec::new(),
                        pos: 0,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(bad(
            "could not create a private spill file for a sparse member",
        ))
    }

    /// Appends data at the current logical position, extending the last extent when it is
    /// contiguous rather than starting a new one -- the map is the file's shape, not a log
    /// of the calls that built it.
    fn data(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        match self.map.last_mut() {
            Some((off, len)) if *off + *len == self.pos => *len += bytes.len() as u64,
            _ => self.map.push((self.pos, bytes.len() as u64)),
        }
        self.file.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    fn hole(&mut self, len: u64) {
        self.pos += len;
    }

    fn stored(&self) -> u64 {
        self.map.iter().map(|(_, len)| *len).sum()
    }
}

impl TarSink {
    /// Stops waiting and writes the member the ordinary way: the header, then everything
    /// held so far. Called when the held run passes `SPARSE_DECIDE` with no hole in it, and
    /// at `finish` for a member that never had one.
    ///
    /// The bytes that come out are the same bytes, in the same order, as before this sink
    /// learned to wait -- only emitted a moment later. That equality is asserted by an arm,
    /// because "the dense path is unchanged" is the claim the sparse work rests on.
    fn go_plain(&mut self) -> io::Result<()> {
        let head = match std::mem::replace(&mut self.layout, Layout::Plain) {
            Layout::Undecided { head } => head,
            other => {
                self.layout = other;
                return Ok(());
            }
        };
        let (item, name) = (self.item.clone(), self.tree.member_name(&self.item.rel));
        let (tree, declared) = (self.tree.clone(), self.declared);
        tree.writer(|w| {
            tree.write_header(w, &name, &item, b'0', "", declared)?;
            w.file.write_all(&head)
        })
    }

    /// Writes a member in GNU pax 1.0 sparse form: an extended header naming the real file
    /// and its real size, then a member whose data is the map followed by the extents.
    ///
    /// The shape is GNU tar's, read off `tar --sparse --format=posix` rather than off a
    /// specification, because the specification is the implementation here -- pax reserves
    /// the `GNU.` namespace and says nothing about what is in it. What GNU tar 1.35 writes:
    ///
    ///   x header at `./PaxHeaders/<base>`  GNU.sparse.major=1, .minor=0,
    ///                                      .name=<real name>, .realsize=<apparent size>
    ///   0 header at `./GNUSparseFile.N/<base>`  size = map text + extents, block-padded
    ///   data: "<count>\n" then "<off>\n<len>\n" per extent, NUL-padded to 512, then the
    ///         extents back to back
    ///
    /// The decoy name matters: a reader that does not know this extension extracts a file
    /// of the stored size under `GNUSparseFile.N/`, which is visibly not the original
    /// rather than a silently wrong version of it.
    fn write_sparse_member(&mut self, spill: SparseSpill, item: &Item) -> io::Result<Refusals> {
        let tree = self.tree.clone();
        let name = tree.member_name(&item.rel);
        let base = name.rsplit('/').next().unwrap_or("member").to_string();

        // GNU tar closes the map with a zero-length extent at the file's end, and this
        // matches it. The reader here does not need it -- realsize already says where the
        // file stops -- but writing what the reference writes is the cheaper side of an
        // interop question nobody wants to re-answer.
        let mut extents = spill.map.clone();
        extents.push((item.size, 0));
        let mut map_text = format!("{}\n", extents.len());
        for (off, len) in &extents {
            map_text.push_str(&format!("{off}\n{len}\n"));
        }
        let map_pad = (blocks_for(map_text.len() as u64) - map_text.len() as u64) as usize;
        let stored = spill.stored();
        let member_size = blocks_for(map_text.len() as u64) + stored;

        // EXACTLY ONE pax header, and that is the whole of this paragraph's reason to
        // exist. Building the member header with `write_header` is the trap: it emits its
        // OWN pax header whenever a field will not fit ustar -- a sub-second mtime, or a
        // decoy name past 100 bytes. Two `x` headers in a row is not two sets of records:
        // GNU tar resets its pending records at each one, so the SECOND silently erases
        // GNU.sparse.*, and tar extracts a 4672-byte file called
        // `GNUSparseFile.2452/hole.bin` -- the decoy, taken literally. It reports no error,
        // which is what makes it worth this comment: rcp's own reader merges the two and is
        // perfectly happy, so only the reference catches it.
        let decoy = format!("./GNUSparseFile.{}/{base}", std::process::id());
        let (decoy_ustar, decoy_prefix) = split_name(&decoy);
        let mut records = String::new();
        records.push_str(&pax_record("GNU.sparse.major", "1"));
        records.push_str(&pax_record("GNU.sparse.minor", "0"));
        records.push_str(&pax_record("GNU.sparse.name", &name));
        records.push_str(&pax_record("GNU.sparse.realsize", &item.size.to_string()));
        if let Some(text) = format_pax_mtime(item.mtime_ns) {
            records.push_str(&pax_record("mtime", &text));
        }
        if decoy_ustar.is_empty() {
            records.push_str(&pax_record("path", &decoy));
        }
        if item.uid > 0o7777777 {
            records.push_str(&pax_record("uid", &item.uid.to_string()));
        }
        if item.gid > 0o7777777 {
            records.push_str(&pax_record("gid", &item.gid.to_string()));
        }

        let mut spill_file = spill.file.try_clone()?;
        spill_file.seek(SeekFrom::Start(0))?;

        tree.writer(|w| {
            let mut header = [0u8; BLOCK];
            put_str(&mut header[0..100], &format!("./PaxHeaders/{base}"));
            put_number(&mut header[100..108], 0o644);
            put_number(&mut header[108..116], 0);
            put_number(&mut header[116..124], 0);
            put_number(&mut header[124..136], records.len() as u64);
            put_number(
                &mut header[136..148],
                (item.mtime_ns / 1_000_000_000).max(0) as u64,
            );
            header[156] = b'x';
            put_str(&mut header[257..263], "ustar");
            header[263..265].copy_from_slice(b"00");
            seal(&mut header);
            w.file.write_all(&header)?;
            w.file.write_all(records.as_bytes())?;
            let pad = blocks_for(records.len() as u64) as usize - records.len();
            w.file.write_all(&vec![0u8; pad])?;

            // the member itself, under the decoy name, sized as what it stores -- written
            // here rather than through `write_header`, so no second pax header can appear
            let mut header = [0u8; BLOCK];
            let ustar = if decoy_ustar.is_empty() {
                base.chars().take(100).collect::<String>()
            } else {
                decoy_ustar.clone()
            };
            put_str(&mut header[0..100], &ustar);
            put_number(&mut header[100..108], (item.mode & 0o7777) as u64);
            put_number(&mut header[108..116], item.uid as u64);
            put_number(&mut header[116..124], item.gid as u64);
            put_number(&mut header[124..136], member_size);
            put_number(
                &mut header[136..148],
                (item.mtime_ns / 1_000_000_000).max(0) as u64,
            );
            header[156] = b'0';
            put_str(&mut header[257..263], "ustar");
            header[263..265].copy_from_slice(b"00");
            if let Some(names) = &tree.settings.names {
                put_str(&mut header[265..297], &names.user(item.uid));
                put_str(&mut header[297..329], &names.group(item.gid));
            }
            put_str(&mut header[345..500], &decoy_prefix);
            seal(&mut header);
            w.file.write_all(&header)?;
            w.file.write_all(map_text.as_bytes())?;
            if map_pad > 0 {
                w.file.write_all(&vec![0u8; map_pad])?;
            }
            let moved = io::copy(&mut spill_file, &mut w.file)?;
            if moved != stored {
                return Err(bad(&format!(
                    "{}: {moved} bytes came back from the spill for {stored} recorded",
                    item.rel
                )));
            }
            let pad = (blocks_for(stored) - stored) as usize;
            if pad > 0 {
                w.file.write_all(&vec![0u8; pad])?;
            }
            if item.nlink > 1 {
                w.by_inode
                    .entry((item.dev, item.ino))
                    .or_insert_with(|| name.clone());
            }
            w.by_name.insert(name.clone(), item.clone());
            Ok(())
        })?;
        Ok(Refusals::default())
    }

    /// Commits to the sparse layout, moving anything already held into the spill.
    fn go_sparse(&mut self) -> io::Result<&mut SparseSpill> {
        if let Layout::Undecided { head } = std::mem::replace(&mut self.layout, Layout::Plain) {
            let mut spill = SparseSpill::new(&self.item.rel)?;
            spill.data(&head)?;
            self.layout = Layout::Sparse(spill);
        }
        match &mut self.layout {
            Layout::Sparse(s) => Ok(s),
            _ => Err(io::Error::other(format!(
                "{}: a hole arrived after the member was already being written flat",
                self.item.rel
            ))),
        }
    }
}

impl Sink for TarSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        if self.started {
            return Ok(());
        }
        self.declared = len;
        // The header is NOT written here any more. It used to be, and it cannot be: a
        // sparse member's header depends on the map, which is not known until the last
        // byte. `reserve` still records the declared size, which is the part callers rely
        // on, and `go_plain` writes the header the moment the layout is settled.
        self.started = true;
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.link_to.is_some() {
            return Ok(());
        }
        if !self.started {
            self.reserve(self.item.size)?;
        }
        if self.written + data.len() as u64 > self.declared {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: more bytes than the {} declared (the source changed during the copy)",
                    self.item.rel, self.declared
                ),
            ));
        }
        match &mut self.layout {
            Layout::Sparse(s) => s.data(data)?,
            Layout::Plain => {
                let tree = self.tree.clone();
                tree.writer(|w| w.file.write_all(data))?;
            }
            Layout::Undecided { head } => {
                head.extend_from_slice(data);
                if head.len() as u64 >= SPARSE_DECIDE {
                    self.go_plain()?;
                }
            }
        }
        self.written += data.len() as u64;
        Ok(())
    }

    fn hole(&mut self, len: u64) -> io::Result<()> {
        if self.link_to.is_some() {
            return Ok(());
        }
        if !self.started {
            self.reserve(self.item.size)?;
        }
        if self.written + len > self.declared {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: more bytes than the {} declared (the source changed during the copy)",
                    self.item.rel, self.declared
                ),
            ));
        }
        if matches!(self.layout, Layout::Plain) {
            // Already committed: the member is being written flat, so the hole becomes the
            // zeros it stands for. Correct, and larger -- see SPARSE_DECIDE.
            let mut left = len;
            while left > 0 {
                let n = left.min(ZEROS.len() as u64) as usize;
                let tree = self.tree.clone();
                tree.writer(|w| w.file.write_all(&ZEROS[..n]))?;
                left -= n as u64;
            }
            self.written += len;
            return Ok(());
        }
        self.go_sparse()?.hole(len);
        self.written += len;
        Ok(())
    }

    fn finish(
        &mut self,
        item: &Item,
        _xattrs: &[(String, Vec<u8>)],
        _opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        let tree = self.tree.clone();
        let name = tree.member_name(&item.rel);
        if let Some(target) = self.link_to.clone() {
            tree.writer(|w| tree.write_header(w, &name, item, b'1', &target, 0))?;
            return Ok(Refusals::default());
        }
        if !self.started {
            self.reserve(0)?;
        }
        if self.written != self.declared {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: {} bytes arrived for {} declared (the source changed during the copy)",
                    item.rel, self.written, self.declared
                ),
            ));
        }
        // A member that never saw a hole settles here, at the last possible moment.
        if matches!(self.layout, Layout::Undecided { .. }) {
            self.go_plain()?;
        }
        if let Layout::Sparse(spill) = std::mem::replace(&mut self.layout, Layout::Plain) {
            return self.write_sparse_member(spill, item);
        }
        let pad = (blocks_for(self.written) - self.written) as usize;
        tree.writer(|w| {
            if pad > 0 {
                w.file.write_all(&vec![0u8; pad])?;
            }
            // the first name for an inode is what a later copy of it links to
            if item.nlink > 1 {
                w.by_inode
                    .entry((item.dev, item.ino))
                    .or_insert_with(|| name.clone());
            }
            w.by_name.insert(name.clone(), item.clone());
            Ok(())
        })?;
        Ok(Refusals::default())
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Tree for TarTree {
    type Reader = TarReader;
    type Sink = TarSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        _parallel: usize,
    ) -> io::Result<Listing> {
        if self.create {
            // a fresh archive is empty, and scanning what we are writing would read our
            // own half-written header
            return Ok(Listing::default());
        }
        let index = self.ctx_index()?;
        let now = filter::now_ns();
        let mut items = Vec::new();
        let mut seen_root = false;
        for (name, m) in &index.members {
            let Some(rel) = self.rel_of(name) else {
                continue;
            };
            if rel == "." {
                seen_root = true;
                let mut root = m.item.clone();
                root.rel = ".".into();
                items.push(root);
                continue;
            }
            if max_depth.is_some_and(|d| rel.matches('/').count() + 1 > d) {
                continue;
            }
            if !filter.allows(&rel, m.item.kind == Kind::Dir) {
                continue;
            }
            let keep = match m.item.kind {
                Kind::Dir => true,
                Kind::File => {
                    filter.allows_file(m.item.size, m.item.mtime_ns, now)
                        && filter.allows_owner_kind(m.item.kind, m.item.uid, m.item.gid, m.item.ino)
                }
                Kind::Symlink => {
                    filter.allows_owner_kind(m.item.kind, m.item.uid, m.item.gid, m.item.ino)
                }
            };
            if keep {
                let mut item = m.item.clone();
                item.rel = rel;
                items.push(item);
            }
        }
        if !seen_root {
            // an archive need not carry an entry for its own root; the tree still has one
            items.push(Item {
                rel: ".".into(),
                kind: Kind::Dir,
                size: 0,
                mtime_ns: 0,
                atime_ns: 0,
                mode: 0o755,
                uid: 0,
                gid: 0,
                dev: 1,
                ino: 0,
                nlink: 1,
                blocks: 0,
                link_target: None,
            });
        }
        items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        Ok(Listing {
            items,
            errors: index.errors.clone(),
        })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        if self.create {
            return Ok(None);
        }
        Ok(self.member(rel)?.map(|m| {
            let mut item = m.item;
            item.rel = rel.to_string();
            item
        }))
    }

    fn open(&self, rel: &str) -> io::Result<TarReader> {
        let m = self.member(rel)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no such member", self.member_name(rel)),
            )
        })?;
        // a hard link's bytes are the member it points at -- including its sparse layout,
        // since the link has no data of its own
        let (offset, size, sparse) = match &m.link_to {
            Some(target) => {
                let index = self.ctx_index()?;
                let t = index.members.get(target).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{rel}: links to {target}, which this archive does not have"),
                    )
                })?;
                (t.offset, t.item.size, t.sparse.clone())
            }
            None => (m.offset, m.item.size, m.sparse.clone()),
        };
        let mut file = File::open(&self.path).map_err(|e| ctx(e, &self.path))?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(TarReader {
            file,
            start: offset,
            size,
            pos: 0,
            sparse,
        })
    }

    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut r = self.open(rel)?;
        // A SPARSE member knows exactly where its holes are, so it says so rather than
        // guessing: the run lengths come from the map, and a hole is reported whole instead
        // of in buffer-sized pieces. This is also the only path that can report a hole
        // LONGER than the buffer, which is what keeps a 64 MiB hole from costing 64 MiB of
        // reads on the way out.
        if let Some(sparse) = r.sparse.clone() {
            let mut pos = 0u64;
            while pos < r.size {
                let (at, run) = r.locate(&sparse, pos);
                if at.is_none() {
                    sink(Segment::Hole(run))?;
                    pos += run;
                    continue;
                }
                let mut left = run;
                while left > 0 {
                    r.seek(SeekFrom::Start(pos))?;
                    let want = buf.len().min(left as usize);
                    let n = r.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(bad(&format!(
                            "{rel}: the archive ends inside a sparse extent at byte {pos}"
                        )));
                    }
                    sink(Segment::Data(&buf[..n]))?;
                    pos += n as u64;
                    left -= n as u64;
                }
            }
            return Ok(());
        }
        // An ORDINARY member has no holes recorded, so runs of zeros are reported as holes
        // and a sparse destination can still stay sparse, exactly as the sftp and s3
        // adapters do. That is a guess, and a correct one: zeros are what a hole reads as.
        loop {
            let n = r.read(buf)?;
            if n == 0 {
                return Ok(());
            }
            if is_all_zero(&buf[..n]) {
                sink(Segment::Hole(n as u64))?;
            } else {
                sink(Segment::Data(&buf[..n]))?;
            }
        }
    }

    fn create_file(&self, item: &Item) -> io::Result<TarSink> {
        // a second name for an inode already written is a hard link, not the bytes again
        let link_to = if item.nlink > 1 {
            let out = self.out.lock().unwrap();
            out.as_ref()
                .and_then(|w| w.by_inode.get(&(item.dev, item.ino)).cloned())
        } else {
            None
        };
        Ok(TarSink {
            tree: self.0.clone(),
            item: item.clone(),
            written: 0,
            declared: item.size,
            started: false,
            link_to,
            layout: Layout::Undecided { head: Vec::new() },
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut TarSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        // recorded, not written: `set_metadata` is where the mode and times arrive, and a
        // stream has no second pass to correct a header with
        self.writer(|w| {
            w.pending.insert(rel.to_string(), Pending::Dir);
            Ok(())
        })
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        let target = target.to_string_lossy().into_owned();
        self.writer(|w| {
            w.pending.insert(rel.to_string(), Pending::Symlink(target));
            Ok(())
        })
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let (name, target) = (self.member_name(rel), self.member_name(existing));
        self.writer(|w| {
            // the link carries the mode and times of the member it points at, which is
            // what the inode has
            let item = w
                .by_name
                .get(&target)
                .cloned()
                .unwrap_or_else(|| default_item(rel, Kind::File, 0o644));
            self.write_header(w, &name, &item, b'1', &target, 0)
        })
    }

    // this adapter does not read the PAX records that would carry xattrs
    fn keeps_xattrs(&self) -> bool {
        false
    }

    fn remove(&self, _rel: &str, _kind: Kind) -> io::Result<Removed> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a tar archive is a stream: nothing can be removed from one",
        ))
    }

    fn rewrites_metadata_in_place(&self) -> bool {
        // A tar stream is written once through. `set_metadata` below writes a directory's
        // or a symlink's header because that is the first moment the item is known, and
        // falls through for a regular member whose header already went out -- so a `chmod`
        // over an existing archive changed nothing and reported the count anyway.
        false
    }

    fn set_metadata(&self, rel: &str, item: &Item, _opts: MetaOptions) -> io::Result<Refusals> {
        // a file's header carried its metadata when it was written; a directory's or a
        // symlink's is written here, which is the first moment the item is known
        let name = self.member_name(rel);
        self.writer(|w| {
            match w.pending.remove(rel) {
                Some(Pending::Dir) => {
                    self.write_header(w, &format!("{name}/"), item, b'5', "", 0)?
                }
                Some(Pending::Symlink(target)) => {
                    self.write_header(w, &name, item, b'2', &target, 0)?
                }
                // the root is never made by `mkdir` -- it is the tree -- but it is a member
                // like any other, and without it nothing carries the root's own mode
                None if item.kind == Kind::Dir && !w.by_name.contains_key(&name) => {
                    self.write_header(w, &format!("{name}/"), item, b'5', "", 0)?;
                    w.by_name.insert(name.clone(), item.clone());
                }
                None => {}
            }
            Ok(Refusals::default())
        })
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        // pax can carry SCHILY.xattr.*; this build does not write them, and says so
        Ok(attrs.iter().map(|(k, _)| k.clone()).collect())
    }

    fn restore_atime(&self, _item: &Item) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        let mut out = self.out.lock().unwrap();
        let Some(w) = out.as_mut() else { return Ok(()) };
        if w.closed {
            return Ok(());
        }
        // anything recorded and never given metadata (a directory the copy made but never
        // reached) still belongs in the archive, with what is known of it
        let pending: Vec<(String, Pending)> = w
            .pending
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (rel, what) in pending {
            let name = self.member_name(&rel);
            match what {
                Pending::Dir => self.write_header(
                    w,
                    &format!("{name}/"),
                    &default_item(&rel, Kind::Dir, 0o755),
                    b'5',
                    "",
                    0,
                )?,
                Pending::Symlink(target) => self.write_header(
                    w,
                    &name,
                    &default_item(&rel, Kind::Symlink, 0o777),
                    b'2',
                    &target,
                    0,
                )?,
            }
        }
        w.pending.clear();
        // two zero blocks end an archive; without them tar reads a truncated file
        w.file.write_all(&[0u8; BLOCK * 2])?;
        w.file.finish()?;
        w.closed = true;
        crate::debug!(
            self.settings.log,
            "tar {}: archive finished",
            self.path.display()
        );
        Ok(())
    }

    fn writes_in_one_stream(&self) -> bool {
        self.create
    }

    fn sync_publishes(&self) -> bool {
        // until the end-of-archive marker is written the file is not a tar, so a
        // destination that has not synced has not received the copy
        self.create
    }

    fn native_copy(
        &self,
        _dst: &Self,
        _files: &[&Item],
        _next: &AtomicUsize,
        _workers: usize,
        _opts: &FileOptions,
        _done: &mut dyn FnMut(usize, io::Result<FileOutcome>),
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no native engine into a tar archive",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_name_agrees_with_the_name_that_made_it_a_gzip() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let stem = |n: &str| gzip_stem(Path::new(n));
        // the ordinary spellings, and the stem keeps the caller's own casing
        assert_eq!(stem("out.tar.gz").as_deref(), Some("out.tar"));
        assert_eq!(stem("out.TAR.GZ").as_deref(), Some("out.TAR"));
        assert_eq!(stem("out.tgz").as_deref(), Some("out.tar"));
        assert_eq!(stem("out.TGZ").as_deref(), Some("out.tar"));
        // the two that were accepted as gzip and then stored a name nobody wrote
        assert_eq!(stem("Foo.Tgz").as_deref(), Some("Foo.tar"));
        assert_eq!(stem("Foo.Gz").as_deref(), Some("Foo"));
        // ONE suffix, not every trailing one
        assert_eq!(stem("a.tgz.tgz").as_deref(), Some("a.tgz.tar"));
        // and the two cases that store no name at all
        assert_eq!(stem(".gz"), None);
        assert_eq!(
            gzip_stem(Path::new(OsStr::from_bytes(b"bad\xff\xfe.tar.gz"))),
            None
        );

        // THE CONTROL: every name this function is asked about must be one
        // `wrapper_for_create` accepts, and the old logic is replanted to prove these
        // arms can fail. Without it, a `gzip_stem` that returned the input unchanged
        // would pass nothing above and still look like a test.
        let old = |n: &str| {
            n.strip_suffix(".gz")
                .or_else(|| n.strip_suffix(".GZ"))
                .map_or_else(
                    || {
                        format!(
                            "{}.tar",
                            n.trim_end_matches(".tgz").trim_end_matches(".TGZ")
                        )
                    },
                    str::to_owned,
                )
        };
        for n in [
            "out.tar.gz",
            "out.TAR.GZ",
            "out.tgz",
            "out.TGZ",
            "Foo.Tgz",
            "Foo.Gz",
            "a.tgz.tgz",
        ] {
            assert_eq!(
                wrapper_for_create(Path::new(n)).unwrap(),
                Wrap::Gzip,
                "{n} must be accepted as gzip"
            );
        }
        // the three the old logic got wrong, still wrong, so the arms above are not inert
        for (n, was) in [
            ("Foo.Tgz", "Foo.Tgz.tar"),
            ("Foo.Gz", "Foo.Gz.tar"),
            ("a.tgz.tgz", "a.tar"),
        ] {
            assert_eq!(old(n), was, "{n}: the defect must still reproduce");
            assert_ne!(Some(old(n)), stem(n), "{n}: the fix must change the answer");
        }
        // and the spellings the old logic already handled must NOT have moved
        for n in ["out.tar.gz", "out.TAR.GZ", "out.tgz", "out.TGZ"] {
            assert_eq!(
                Some(old(n)),
                stem(n),
                "{n}: this spelling was already correct"
            );
        }
    }

    #[test]
    fn zstd_is_known_by_its_magic_on_read_and_its_name_on_create() {
        // read: the data-frame magic, a skippable frame (pzstd leads with one), gzip,
        // and the negatives -- a plain tar header and a head too short to judge
        assert_eq!(Wrap::sniff(&crate::zstd::compress(b"x")[..4]), Wrap::Zstd);
        assert_eq!(Wrap::sniff(&[0x50, 0x2a, 0x4d, 0x18]), Wrap::Zstd);
        assert_eq!(Wrap::sniff(&[0x5f, 0x2a, 0x4d, 0x18]), Wrap::Zstd);
        assert_eq!(Wrap::sniff(&[0x1f, 0x8b, 0, 0]), Wrap::Gzip);
        assert_eq!(Wrap::sniff(b"./me"), Wrap::Plain);
        assert_eq!(Wrap::sniff(&[0x28, 0xb5, 0x2f]), Wrap::Plain);
        // create: both GNU tar suffixes, any case, and the refusals that remain
        for n in ["a.tar.zst", "a.TZST", "a.tzst", "a.Tar.Zst"] {
            assert_eq!(wrapper_for_create(Path::new(n)).unwrap(), Wrap::Zstd, "{n}");
        }
        assert_eq!(wrapper_for_create(Path::new("a.tar")).unwrap(), Wrap::Plain);
        for n in ["a.tar.xz", "a.tar.bz2", "a.tar.lz"] {
            let e = wrapper_for_create(Path::new(n)).unwrap_err().to_string();
            assert!(
                e.contains(".tar.zst"),
                "{n}: the refusal should name the suffixes rcp does write: {e}"
            );
        }
    }

    #[test]
    fn a_zstd_member_writer_emits_frames_the_decoder_reads_whole() {
        use std::io::Write;
        // three and a half blocks, so the stream is four frames; serial and pooled must
        // write the SAME bytes, since the pool only moves where a frame is computed
        let data: Vec<u8> = (0..(crate::deflate::GZIP_BLOCK * 7 / 2))
            .map(|i| (i % 251) as u8 ^ (i / 4096) as u8)
            .collect();
        let write = |workers| {
            let mut w = crate::deflate::GzipWriter::zstd(Vec::new(), workers, false);
            for c in data.chunks(1 << 20) {
                w.write_all(c).unwrap();
            }
            w.finish().unwrap()
        };
        let serial = write(1);
        assert_eq!(serial, write(4), "the pool changed the bytes");
        assert_eq!(crate::zstd::decompress(&serial, data.len()).unwrap(), data);
        // an empty archive is still one frame, not a zero-byte file `zstd -d` refuses
        let empty = crate::deflate::GzipWriter::zstd(Vec::new(), 1, false)
            .finish()
            .unwrap();
        assert_eq!(&empty[..4], &crate::zstd::MAGIC.to_le_bytes());
        assert!(crate::zstd::decompress(&empty, 0).unwrap().is_empty());
    }

    #[test]
    fn numbers_read_octal_and_base_256_and_write_back_the_same() {
        assert_eq!(number(b"0000644\0").unwrap(), 0o644);
        assert_eq!(number(b"00000000000 ").unwrap(), 0);
        assert_eq!(number(b"        ").unwrap(), 0);
        let mut field = [0u8; 12];
        put_number(&mut field, 1234);
        assert_eq!(number(&field).unwrap(), 1234);
        // over 8 GiB will not fit in 11 octal digits, so it goes out in base 256
        let big = 12 << 30;
        put_number(&mut field, big);
        assert!(field[0] & 0x80 != 0, "a size this large must use base 256");
        assert_eq!(number(&field).unwrap(), big);
        // and the largest octal that does fit stays octal, which older readers need
        put_number(&mut field, 0o77777777777);
        assert_eq!(field[0], b'7');
        assert_eq!(number(&field).unwrap(), 0o77777777777);
        // twelve 0xff bytes are the GNU encoding of -1, not a huge positive and not an overflow
        assert_eq!(signed_number(&[0xff; 12]).unwrap(), -1);
        assert_eq!(pax_time("-0.5"), Some(-500_000_000));
        assert_eq!(pax_time("-1.5"), Some(-1_500_000_000));
        assert_eq!(
            format_pax_mtime(-500_000_000).as_deref(),
            Some("-0.500000000")
        );
    }

    #[test]
    fn a_name_splits_into_prefix_and_name_only_where_ustar_allows() {
        assert_eq!(split_name("a/b"), ("a/b".to_string(), String::new()));
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(80));
        assert_eq!(split_name(&long), ("f".repeat(80), "d".repeat(120)));
        // no `/` in reach: it cannot be split, which is what makes a pax record necessary
        assert_eq!(split_name(&"x".repeat(200)), (String::new(), String::new()));
        // a component longer than 100 after the split point cannot be carried either
        let deep = format!("{}/{}", "d".repeat(10), "f".repeat(150));
        assert_eq!(split_name(&deep), (String::new(), String::new()));
    }

    #[test]
    fn pax_records_parse_and_a_time_keeps_its_nanoseconds() {
        // the length counts itself, so these are 30 and 12 bytes exactly
        let text = b"30 mtime=1700000000.123456789\n12 path=a/b\n";
        assert_eq!(text.len(), 42);
        let map = pax(text);
        assert_eq!(map.get("path").map(String::as_str), Some("a/b"));
        assert_eq!(
            pax_time(map.get("mtime").unwrap()),
            Some(1_700_000_000_123_456_789)
        );
        assert_eq!(pax_time("5"), Some(5_000_000_000));
        assert_eq!(pax_time("5.5"), Some(5_500_000_000));

        // and what the writer produces is what the reader reads, including the length that
        // has to grow to describe itself -- a record whose length crosses a digit boundary
        for value in ["a/b", &"p".repeat(90), &"q".repeat(9000)] {
            let written = pax_record("path", value);
            assert_eq!(
                written.len(),
                written.split(' ').next().unwrap().parse::<usize>().unwrap(),
                "the length must count itself: {written:.20}"
            );
            assert_eq!(
                pax(written.as_bytes()).get("path").map(String::as_str),
                Some(value)
            );
        }
    }

    /// The pax 1.0 map is decimal ASCII at the front of the member's own data, which means
    /// it is attacker-controlled and length-prefixed by a number that is also attacker
    /// controlled. Every shape below produces a FILE if it is trusted -- just the wrong
    /// one -- so each is refused by name rather than clamped.
    #[test]
    fn a_sparse_map_is_read_and_every_way_it_can_lie_is_refused() {
        // the shape GNU tar writes, including its terminating zero-length extent
        let good = b"3\n0\n4096\n67108864\n64\n67108928\n0\n";
        let (map, used) = sparse_map_1_0(good, "ok").expect("a well-formed map reads");
        assert_eq!(map, vec![(0, 4096), (67108864, 64), (67108928, 0)]);
        assert_eq!(
            used,
            good.len(),
            "the consumed count has to reach the end of the map text"
        );

        // THE CONTROL on the parser: a map with one extent reads as one extent, so the
        // three-extent result above is not the parser inventing structure.
        let (one, _) = sparse_map_1_0(b"1\n0\n10\n", "ok").unwrap();
        assert_eq!(one, vec![(0, 10)]);

        // a count that promises more than the text carries
        let e = sparse_map_1_0(b"9\n0\n10\n", "short")
            .unwrap_err()
            .to_string();
        assert!(e.contains("never ends"), "{e}");
        // a field that is not a number
        let e = sparse_map_1_0(b"1\n0\nzz\n", "text")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a number"), "{e}");
        // a count no file could have, which is the allocation this bound exists for
        let e = sparse_map_1_0(b"99999999999\n", "huge")
            .unwrap_err()
            .to_string();
        assert!(e.contains("is not a map"), "{e}");

        // and the map's own arithmetic, checked against the size it claims to describe
        let past = Sparse {
            map: vec![(0, 10), (900, 200)],
            at: 0,
        };
        let e = past.validate(1000, "past").unwrap_err().to_string();
        assert!(e.contains("past the declared size"), "{e}");

        let overlap = Sparse {
            map: vec![(0, 100), (50, 10)],
            at: 0,
        };
        let e = overlap.validate(1000, "overlap").unwrap_err().to_string();
        assert!(e.contains("inside or before"), "{e}");

        let over = Sparse {
            map: vec![(u64::MAX - 1, 5)],
            at: 0,
        };
        let e = over.validate(u64::MAX, "overflow").unwrap_err().to_string();
        assert!(e.contains("overflows"), "{e}");

        // THE CONTROL on the validator: the map the writer actually produces passes, so
        // the refusals above are about these shapes and not about validate() refusing
        // everything -- which would pass all four assertions while making the reader
        // useless.
        let fine = Sparse {
            map: vec![(0, 64), (67108800, 64), (67108864, 0)],
            at: 0,
        };
        fine.validate(67108864, "fine")
            .expect("the shape the writer emits has to validate");
    }

    #[test]
    fn a_member_that_climbs_out_of_the_archive_is_refused() {
        assert_eq!(normalize("./a/b/").as_deref(), Some("a/b"));
        assert_eq!(normalize("/a/b").as_deref(), Some("a/b"));
        assert_eq!(normalize("a//b").as_deref(), Some("a/b"));
        assert_eq!(normalize("../etc/passwd"), None);
        assert_eq!(normalize("a/../../etc/passwd"), None);
        // the root and an escape are different answers, which is the whole point of the
        // Option: `./` is a member every archive has and `..` is an attack
        assert_eq!(normalize("./").as_deref(), Some(""));
        assert_eq!(rel_name("./").as_deref(), Some("."));
        assert_eq!(rel_name("../x"), None);
    }
}
