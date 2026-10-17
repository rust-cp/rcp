//! A minimal zip writer (stored entries, no compression) so `logdump ID` can produce the
//! `ID.zip` `logdump` writes, without a compression crate. Logs are small; what
//! matters is that any unzip opens it.

use std::io::{self, Write};

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// Writes stored ZIP32 entries with UTF-8 names into a caller-owned output stream.
/// Call [`Self::finish`] to write the directory and flush the completed archive.
///
/// ```
/// use rcp::zipfile::ZipWriter;
/// let mut archive = ZipWriter::new(Vec::new());
/// archive.add("logs/café.txt", b"ready\n")?;
/// let bytes = archive.finish()?;
/// assert_eq!(&bytes[..4], &0x0403_4b50u32.to_le_bytes());
/// assert_eq!(&bytes[bytes.len() - 22..bytes.len() - 18], &0x0605_4b50u32.to_le_bytes());
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    central: Vec<u8>,
    /// Counted in a `u32` and narrowed at `finish`, NOT a `u16` that wraps.
    ///
    /// The end-of-central-directory record holds the count in 16 bits, so a zip32 archive
    /// cannot describe more than 65,535 entries. Counting in the field's own width made
    /// the 65,536th entry wrap to zero -- in release, silently, producing an archive whose
    /// directory says it is empty while the entries are all still in the file. Counting
    /// wider and refusing at `finish` turns that into a message.
    entries: u32,
}

/// The largest offset, length or count a zip32 header can hold. Past any of these the
/// archive needs the zip64 records, which this writer does not emit.
const ZIP32_MAX: u64 = u32::MAX as u64;
const ZIP32_MAX_ENTRIES: u32 = u16::MAX as u32;

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        ZipWriter {
            out,
            offset: 0,
            central: Vec::new(),
            entries: 0,
        }
    }

    /// Appends one entry. Names are recorded as supplied, without extraction-path checks.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when an entry size, starting offset or name
    /// exceeds its ZIP32 field, or propagates an output write error. A write error may
    /// leave partial bytes in the output; discard that archive rather than retrying it.
    pub fn add(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        if data.len() as u64 > ZIP32_MAX || self.offset > ZIP32_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry too large for a zip32 archive",
            ));
        }
        if name.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry name too long for a zip header",
            ));
        }
        let crc = crc32(data);
        let name_bytes = name.as_bytes();
        let (date, time) = dos_datetime();
        let mut local = Vec::with_capacity(30 + name_bytes.len());
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&10u16.to_le_bytes()); // version needed
        local.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        local.extend_from_slice(&0u16.to_le_bytes()); // stored
        local.extend_from_slice(&time.to_le_bytes());
        local.extend_from_slice(&date.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_bytes);
        self.out.write_all(&local)?;
        self.out.write_all(data)?;

        self.central
            .extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        self.central.extend_from_slice(&20u16.to_le_bytes()); // made by
        self.central.extend_from_slice(&10u16.to_le_bytes());
        self.central.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        self.central.extend_from_slice(&0u16.to_le_bytes());
        self.central.extend_from_slice(&time.to_le_bytes());
        self.central.extend_from_slice(&date.to_le_bytes());
        self.central.extend_from_slice(&crc.to_le_bytes());
        self.central
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.central
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.central
            .extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.central.extend_from_slice(&0u16.to_le_bytes()); // extra
        self.central.extend_from_slice(&0u16.to_le_bytes()); // comment
        self.central.extend_from_slice(&0u16.to_le_bytes()); // disk
        self.central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        self.central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        self.central
            .extend_from_slice(&(self.offset as u32).to_le_bytes());
        self.central.extend_from_slice(name_bytes);

        self.offset += (local.len() + data.len()) as u64;
        self.entries += 1;
        Ok(())
    }

    /// Writes the central directory and returns the flushed output.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when the archive offset, directory length
    /// or entry count exceeds ZIP32 limits, or propagates a directory write/flush error.
    pub fn finish(mut self) -> io::Result<W> {
        // CHECKED, not cast. `add` refuses an offset past `ZIP32_MAX` BEFORE it writes, so
        // the offset can still cross the limit while writing the last entry -- and
        // `self.offset as u32` then silently wrote a WRAPPED central-directory offset.
        // Every unzip seeks to that number, so the archive opens as corrupt or, worse,
        // as a different archive: the count and the entries are all still there and the
        // one pointer that finds them is wrong. The directory's own length has the same
        // shape, and the entry count is bounded by what its 16-bit field can hold.
        if self.offset > ZIP32_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the archive is {} bytes, past the {ZIP32_MAX} a zip32 central-directory offset can hold", self.offset)));
        }
        if self.central.len() as u64 > ZIP32_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the central directory is larger than a zip32 archive can describe",
            ));
        }
        if self.entries > ZIP32_MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} entries, past the {ZIP32_MAX_ENTRIES} a zip32 archive can describe",
                    self.entries
                ),
            ));
        }
        let central_offset = self.offset as u32;
        let entries = self.entries as u16;
        self.out.write_all(&self.central)?;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&entries.to_le_bytes());
        end.extend_from_slice(&entries.to_le_bytes());
        end.extend_from_slice(&(self.central.len() as u32).to_le_bytes());
        end.extend_from_slice(&central_offset.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.out.write_all(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// Today's date and time in the MS-DOS format zip headers use (local time is not available
/// without a time-zone database, so this is UTC; the archive's own timestamps do not matter).
fn dos_datetime() -> (u16, u16) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    let tod = secs % 86_400;
    let date = (((y - 1980).max(0) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time =
        ((tod / 3600) as u16) << 11 | (((tod % 3600) / 60) as u16) << 5 | ((tod % 60) / 2) as u16;
    (date, time)
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zip32 archive that cannot describe itself is REFUSED, not written wrong.
    ///
    /// Three header fields are too narrow to hold every value this writer can reach: the
    /// central-directory offset and length are 32 bits, the entry count is 16. Each was
    /// written with a plain cast, so the failure was an archive that looked fine and was
    /// not -- the count wrapping to zero, or the one pointer that finds the entries being
    /// a wrapped number every unzip seeks to.
    ///
    /// The entry-count arm is the one that can be run for real here; the other two need
    /// four gibibytes. It drives `add` past 65,535 entries with empty payloads.
    #[test]
    fn an_archive_too_large_to_describe_is_refused() {
        let mut z = ZipWriter::new(Vec::new());
        for i in 0..=ZIP32_MAX_ENTRIES {
            z.add(&format!("f{i}"), b"")
                .expect("entries up to the limit are fine");
        }
        assert_eq!(
            z.entries,
            ZIP32_MAX_ENTRIES + 1,
            "the count must not have wrapped: it is a u32 now"
        );
        let e = match z.finish() {
            Ok(_) => panic!("65,536 entries must be refused: the count field holds 16 bits"),
            Err(e) => e,
        };
        assert!(e.to_string().contains("65535"), "{e}");

        // The control, and it is what keeps this from being a writer that refuses
        // everything: exactly the limit is accepted, and the archive it produces says so.
        let mut z = ZipWriter::new(Vec::new());
        for i in 0..ZIP32_MAX_ENTRIES {
            z.add(&format!("f{i}"), b"").unwrap();
        }
        let bytes = z.finish().expect("the limit itself is a valid archive");
        let end = &bytes[bytes.len() - 22..];
        assert_eq!(
            &end[..4],
            &0x0605_4b50u32.to_le_bytes(),
            "the end-of-central-directory record"
        );
        assert_eq!(
            u16::from_le_bytes([end[10], end[11]]),
            u16::MAX,
            "the count in the record"
        );
    }

    #[test]
    fn crc32_matches_the_reference_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn unicode_names_are_marked_utf8_in_both_headers() {
        let name = "logs/café-😀.txt";
        let mut z = ZipWriter::new(Vec::new());
        z.add(name, b"log").unwrap();
        let bytes = z.finish().unwrap();
        let end = &bytes[bytes.len() - 22..];
        let central = u32::from_le_bytes(end[16..20].try_into().unwrap()) as usize;
        assert_eq!(&bytes[central..central + 4], &0x0201_4b50u32.to_le_bytes());
        assert_eq!(
            u16::from_le_bytes(bytes[6..8].try_into().unwrap()) & 0x0800,
            0x0800
        );
        assert_eq!(
            u16::from_le_bytes(bytes[central + 8..central + 10].try_into().unwrap()) & 0x0800,
            0x0800
        );
        assert_eq!(&bytes[30..30 + name.len()], name.as_bytes());
        assert_eq!(
            &bytes[central + 46..central + 46 + name.len()],
            name.as_bytes()
        );
    }

    #[test]
    fn archive_has_the_expected_structure() {
        let mut z = ZipWriter::new(Vec::new());
        z.add("a.txt", b"hello").unwrap();
        z.add("dir/b.log", b"world\n").unwrap();
        let bytes = z.finish().unwrap();
        assert_eq!(
            &bytes[..4],
            &0x0403_4b50u32.to_le_bytes(),
            "local header first"
        );
        assert_eq!(
            &bytes[bytes.len() - 22..bytes.len() - 18],
            &0x0605_4b50u32.to_le_bytes(),
            "end record last"
        );
        assert_eq!(
            u16::from_le_bytes([bytes[bytes.len() - 12], bytes[bytes.len() - 11]]),
            2,
            "two entries"
        );
        assert!(bytes.windows(5).any(|w| w == b"hello"));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }
}
