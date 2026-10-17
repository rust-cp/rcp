//! The copy catalog: one directory per copy ID holding a tab-separated index of every entry
//! completed so far. `resume` skips what the index already lists, `sync` compares the index
//! against a fresh scan of the source. Written one line per completed entry and flushed, so
//! a copy killed part-way leaves a truthful index rather than an empty one.
//!
//! The catalog root also holds `jobs.log`, one line per command run, which `logdump` prints.

#[cfg(windows)]
use crate::windows::PrivateOptions as OpenOptions;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HEADER: &str = "#rcp-catalog 1";

/// Whether a first line is this catalog's banner. Builds before the banner was renamed wrote
/// a different word before `-catalog 1`; accepting it keeps `resume` working on a catalog an
/// older build left behind, while anything else is still "not an rcp catalog".
fn is_banner(line: &str) -> bool {
    line == HEADER
        || (line.starts_with('#') && line.ends_with("-catalog 1") && line.len() == HEADER.len())
}

/// Opens a file of the catalog's own with `O_NOFOLLOW`: a symlink where `index.tsv` or
/// `jobs.log` should be is refused by the kernel rather than followed.
///
/// `not_a_link` checks the id's DIRECTORY, which leaves two gaps: a real directory whose
/// `index.tsv` is a link to a file elsewhere, and a `jobs.log` link at the root -- both
/// written through, since `OpenOptions::open` follows. The same flag
/// the uring engine opens destinations with, for the same reason: a name this run chose
/// is not a file this run made. `ELOOP` is the kernel's word for the refusal and its
/// message ("too many levels of symbolic links") describes a different problem, so it is
/// renamed here.
///
/// `O_NOFOLLOW` covers the LAST component only: `root/<id>` is a directory that
/// `not_a_link` checks with one syscall and this opens with another, and a link put there
/// between the two is followed by the kernel as an intermediate component. So the
/// directory is opened first, itself with `O_DIRECTORY | O_NOFOLLOW`, and the file is
/// opened THROUGH that descriptor by way of `/proc/self/fd/N/name` -- the path the kernel
/// resolves against the directory already held open, whatever `root/<id>` names by then.
/// The same thing `openat(2)` does, without a libc binding in a crate that has none. Where
/// `/proc` is not mounted the open falls back to the path with `O_NOFOLLOW` on its final
/// component, which guards that component and not the directory above it.
/// Creates a catalog directory, and every parent this call makes, readable by its owner
/// alone.
///
/// `create_dir_all` uses the process umask, so on the usual 022 a catalog landed at 0755
/// and anyone on the host could list which paths a run copied and read the digests. An
/// existing directory is left as it is: a mode the operator chose is theirs, and silently
/// tightening a directory someone else shares is its own surprise.
#[cfg(unix)]
fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(windows)]
fn private_dir(dir: &Path) -> io::Result<()> {
    crate::windows::Root::private_dir(dir).map(|_| ())
}

#[cfg(windows)]
fn open_nofollow(path: &Path, opts: &OpenOptions) -> io::Result<File> {
    opts.open(path)
}

#[cfg(unix)]
fn open_nofollow(path: &Path, opts: &OpenOptions) -> io::Result<File> {
    use crate::platform::{O_DIRECTORY, O_NOFOLLOW};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let link = |p: &Path| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is a symlink, and a catalog file must be the catalog's own",
                p.display()
            ),
        )
    };
    let mut opts = opts.clone();
    opts.custom_flags(O_NOFOLLOW);
    // A catalog file is this user's own. It records every source and destination path a
    // run touched -- which is an audit trail and a map of the filesystem -- and it was
    // created at the process umask, so 0644 on a default umask: world-readable. The
    // credential redaction elsewhere hides the secret in an argv; it does nothing about
    // the paths. `mode` applies only where a file is being created, so this is inert on
    // the read and append opens.
    opts.mode(0o600);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return opts.open(path);
    };
    let held = match OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(dir)
    {
        Ok(d) => d,
        // ELOOP, or ENOTDIR: measured, the kernel answers a symlink opened with both
        // flags as "not a directory", so the name is asked whether it is a link
        Err(e)
            if e.raw_os_error() == Some(40)
                || (e.raw_os_error() == Some(20)
                    && fs::symlink_metadata(dir)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false)) =>
        {
            return Err(link(dir))
        }
        Err(e) => return Err(e),
    };
    let through = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd())).join(name);
    let attempt = if Path::new("/proc/self/fd").exists() {
        opts.open(&through)
    } else {
        opts.open(path)
    };
    match attempt {
        Err(e) if e.raw_os_error() == Some(40) => Err(link(path)),
        other => other,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Path relative to the copy root, `.` for the root itself.
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i128,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Hex digest of the file content, in whatever algorithm the run used; empty for
    /// directories, symlinks and unhashed copies. WHICH algorithm is a property of the
    /// catalog, not of the entry -- see `Catalog::digest`, which exists because this
    /// column silently held a mixture until a measurement found one.
    pub sha256: String,
    /// The source's inode number when the entry was copied, so `sync` can tell a renamed or
    /// moved file from a new one. Zero in catalogs written before this column existed.
    pub ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::File => "f",
            Kind::Dir => "d",
            Kind::Symlink => "l",
        }
    }
    fn parse(tag: &str) -> Option<Kind> {
        match tag {
            "f" => Some(Kind::File),
            "d" => Some(Kind::Dir),
            "l" => Some(Kind::Symlink),
            _ => None,
        }
    }
}

/// Where completed entries go. The catalog is one implementation; `NoCatalog` is what
/// `-noId` and `isync` use, so the copy loop never asks whether it has a catalog.
pub trait Recorder: Send {
    fn record(&mut self, e: &Entry) -> io::Result<()>;
    fn record_gone(&mut self, path: &str) -> io::Result<()>;
}

pub struct NoCatalog;

impl Recorder for NoCatalog {
    fn record(&mut self, _: &Entry) -> io::Result<()> {
        Ok(())
    }
    fn record_gone(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
}

pub struct Catalog {
    pub id: String,
    pub dir: PathBuf,
    pub source: PathBuf,
    pub destination: PathBuf,
    /// The digest algorithm every entry's hex is in, by name (`sha256`, `blake3`, `xxh3`,
    /// `xxh128`). `None` for a catalog written before this was recorded, where the
    /// algorithm is genuinely unknown rather than assumed.
    pub digest: Option<String>,
    index: File,
}

/// `\r` IS IN THIS LIST, and must stay there. The reader below takes lines with
/// `BufReader::lines()`, which strips a trailing `\r` as part of CRLF handling -- so without
/// the escape a path ending in a carriage return is written whole and read back SHORTER,
/// silently naming a different directory. Both halves were measured: `resume` wrote a
/// finished copy into a decoy destination reporting PASSED, and `sync` resolved the
/// SOURCE to an unrelated empty directory, read the absence as "the source dropped them",
/// and removed all five destination files -- also PASSED.
///
/// The everyday route is not a hostile filename: it is a path that came off a CRLF line,
/// which is what `while read p; do ... done < list.txt` produces from a Windows file.
pub(crate) fn escape(s: &str) -> String {
    let mut out = s
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    // A path that is itself a header keyword, or that starts with `#`, is read back as a
    // header or a comment and then never removed by sync. `\.` is not produced by the
    // replacements above (a real backslash becomes `\\`), so it is a safe quote.
    if out.starts_with('#') || matches!(out.as_str(), "source" | "destination" | "digest" | "gone")
    {
        out.insert_str(0, "\\.");
    }
    out
}

pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('.') => {}
                Some(other) => {
                    out.push('\\');
                    out.push(other)
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A catalog as `indexlist` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub id: String,
    pub source: String,
    pub destination: String,
    /// `None` when the index could not be read -- a torn or truncated catalog. Not `0`,
    /// which is what a perfectly good empty catalog has.
    pub entries: Option<usize>,
}

/// Names the catalog root already uses for something that is not a catalog.
///
/// `<root>/jobs` holds one record per detached job and `<root>/jobs.log` is the audit log,
/// and a copy ID becomes a directory named `<root>/<id>` -- so `copy -newid jobs` put a
/// catalog where the job records live, and `indexdelete -id jobs` then deleted every job
/// record including the running ones. The sibling is worse in a quieter way:
/// `copy -newid jobs.log` turns the append-only audit log into a directory, which every
/// later `JobLog::append` fails to open, so the log simply stops without a word.
///
/// Refused by NAME rather than by noticing the collision later, because by the time a
/// write fails the damage is done.
pub const RESERVED_IDS: &[&str] = &["jobs", "jobs.log"];

impl Catalog {
    /// Validates a copy ID: it becomes a directory name.
    pub fn valid_id(id: &str) -> bool {
        #[cfg(windows)]
        if crate::windows::validate_name(id).is_err()
            || RESERVED_IDS
                .iter()
                .any(|r| crate::windows::same_name(r, id))
        {
            return false;
        }
        !id.is_empty()
            && id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && !id.starts_with('.')
            && !RESERVED_IDS.contains(&id)
    }

    fn check_id(id: &str) -> io::Result<()> {
        if Self::valid_id(id) {
            Ok(())
        } else {
            let why = if RESERVED_IDS.contains(&id) {
                format!("copy ID {id:?} is a name the catalog root already uses")
            } else {
                format!("copy ID {id:?} is not a valid name")
            };
            Err(io::Error::new(io::ErrorKind::InvalidInput, why))
        }
    }

    /// `copy -newid`: a fresh catalog. An existing ID is refused, which is the guard against
    /// two copies sharing one resume record.
    /// An id that names a symlink in the root is refused. Ids are already names rather
    /// than paths; this is the other half of that: `root/<id>` was joined and opened, so a
    /// link planted there pointed every write of this catalog somewhere else. Planting one
    /// needs write access to the root, which a copy has whenever the catalog sits inside
    /// an allowed tree -- a narrow case, and exactly the kind a rail exists to close.
    fn not_a_link(dir: &Path, id: &str) -> io::Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("copy ID {id}: {} is a symlink, and a catalog entry must be a directory of the catalog's own", dir.display()))),
            _ => Ok(()),
        }
    }

    pub fn create(
        root: &Path,
        id: &str,
        source: &Path,
        destination: &Path,
        digest: &str,
    ) -> io::Result<Catalog> {
        Self::check_id(id)?;
        let dir = root.join(id);
        Self::not_a_link(&dir, id)?;
        if dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("copy ID {id} already exists in catalog {}; use resume -id {id} or choose a new ID", root.display()),
            ));
        }
        private_dir(&dir)?;
        let mut index = open_nofollow(
            &dir.join("index.tsv"),
            OpenOptions::new().create_new(true).append(true),
        )?;
        writeln!(index, "{HEADER}")?;
        writeln!(index, "source\t{}", escape(&source.to_string_lossy()))?;
        writeln!(
            index,
            "destination\t{}",
            escape(&destination.to_string_lossy())
        )?;
        // The digest column holds hex and says nothing about what produced it. With one
        // algorithm that was fine; with four it is a mixture waiting to happen, and it
        // happened: `copy -newid m -blake3` then `sync -id m` left a.txt holding a BLAKE3
        // digest and b.txt a SHA-256 one, in the same column, with nothing to tell them
        // apart. `scan -edupe` groups by that column and `sync`'s move detection carries
        // it forward, so the mixture is not inert.
        writeln!(index, "digest\t{digest}")?;
        index.flush()?;
        Ok(Catalog {
            id: id.to_string(),
            dir,
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            digest: Some(digest.to_string()),
            index,
        })
    }

    /// `resume -id` / `sync -id`: reopen an existing catalog and read its endpoints.
    pub fn open(root: &Path, id: &str) -> io::Result<Catalog> {
        Self::check_id(id)?;
        let dir = root.join(id);
        Self::not_a_link(&dir, id)?;
        let path = dir.join("index.tsv");
        let (source, destination, digest) = Self::header(&path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("copy ID {id} has no catalog at {}: {e}", path.display()),
            )
        })?;
        let index = open_nofollow(&path, OpenOptions::new().append(true))?;
        Ok(Catalog {
            id: id.to_string(),
            dir,
            source,
            destination,
            digest,
            index,
        })
    }

    /// The catalog's endpoints and digest algorithm.
    ///
    /// Reads header lines until the first entry rather than a fixed count. It took the
    /// first two lines after the banner, which is a shape that breaks the moment a third
    /// header line exists -- and adding `digest` is exactly that moment.
    fn header(path: &Path) -> io::Result<(PathBuf, PathBuf, Option<String>)> {
        let reader = BufReader::new(open_nofollow(path, OpenOptions::new().read(true))?);
        let mut lines = reader.lines();
        match lines.next() {
            Some(Ok(h)) if is_banner(&h) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not an rcp catalog",
                ))
            }
        }
        let mut source = None;
        let mut destination = None;
        let mut digest = None;
        for line in lines {
            let line = line?;
            if let Some(v) = line.strip_prefix("source\t") {
                source = Some(PathBuf::from(unescape(v)));
            } else if let Some(v) = line.strip_prefix("destination\t") {
                destination = Some(PathBuf::from(unescape(v)));
            } else if let Some(v) = line.strip_prefix("digest\t") {
                digest = Some(v.to_string());
            } else if !line.is_empty() && !line.starts_with('#') {
                break; // the first entry: the header is over
            }
        }
        match (source, destination) {
            (Some(s), Some(d)) => Ok((s, d, digest)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "catalog lacks its endpoints",
            )),
        }
    }

    /// The raw bytes of an id's index, for `logdump`'s zip. Refuses a symlink in place of
    /// the index: `fs::read` followed one, and a link at `root/<id>/index.tsv` put any
    /// readable file on the machine into a zip named after the id.
    pub fn index_bytes(root: &Path, id: &str) -> io::Result<Vec<u8>> {
        Self::check_id(id)?;
        let dir = root.join(id);
        Self::not_a_link(&dir, id)?;
        let mut f = open_nofollow(&dir.join("index.tsv"), OpenOptions::new().read(true))?;
        let mut out = Vec::new();
        io::Read::read_to_end(&mut f, &mut out)?;
        Ok(out)
    }

    /// Everything the index lists, last record per path winning.
    pub fn entries(&self) -> io::Result<BTreeMap<String, Entry>> {
        Self::read_entries(&self.dir.join("index.tsv"))
    }

    fn read_entries(path: &Path) -> io::Result<BTreeMap<String, Entry>> {
        let reader = BufReader::new(open_nofollow(path, OpenOptions::new().read(true))?);
        let mut map = BTreeMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#')
                || line.starts_with("source\t")
                || line.starts_with("destination\t")
                || line.starts_with("digest\t")
                || line.is_empty()
            {
                continue;
            }
            if let Some(rest) = line.strip_prefix("gone\t") {
                map.remove(&unescape(rest));
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            // eight columns until the inode column was added; both shapes are read
            if f.len() != 8 && f.len() != 9 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("malformed catalog line: {line:?}"),
                ));
            }
            let bad = |what: &str| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad {what} in {line:?}"),
                )
            };
            let entry = Entry {
                path: unescape(f[0]),
                kind: Kind::parse(f[1]).ok_or_else(|| bad("kind"))?,
                size: f[2].parse().map_err(|_| bad("size"))?,
                mtime_ns: f[3].parse().map_err(|_| bad("mtime"))?,
                mode: f[4].parse().map_err(|_| bad("mode"))?,
                uid: f[5].parse().map_err(|_| bad("uid"))?,
                gid: f[6].parse().map_err(|_| bad("gid"))?,
                sha256: f[7].to_string(),
                ino: f
                    .get(8)
                    .map(|v| v.parse().map_err(|_| bad("inode")))
                    .transpose()?
                    .unwrap_or(0),
            };
            map.insert(entry.path.clone(), entry);
        }
        Ok(map)
    }

    /// Every catalog under `root`, sorted by ID.
    pub fn list(root: &Path) -> io::Result<Vec<Info>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in rd {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            let index = entry.path().join("index.tsv");
            if !Self::valid_id(&id) || !index.is_file() {
                continue;
            }
            let (source, destination, _) = match Self::header(&index) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let entries = // NOT `unwrap_or(0)`. A catalog whose index is torn read as `0 entries` with
                // STATUS: PASSED -- so the one command an operator runs to survey catalogs
                // after a crash said "nothing here, all fine", and an EMPTY catalog and a
                // DESTROYED one were indistinguishable in its output. `None` is printed as
                // "unreadable" by the caller.
                Self::read_entries(&index).map(|m| m.len()).ok();

            out.push(Info {
                id,
                source: source.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                entries,
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// IDs under `root` matching any of the globs (`indexdelete -match`).
    pub fn ids_matching(root: &Path, patterns: &[String]) -> io::Result<Vec<String>> {
        Ok(Self::list(root)?
            .into_iter()
            .map(|i| i.id)
            .filter(|id| patterns.iter().any(|p| crate::filter::matches(p, id)))
            .collect())
    }

    /// `indexdelete -id`: removes one catalog. An unknown ID is an error, not a no-op.
    pub fn delete(root: &Path, id: &str) -> io::Result<()> {
        Self::check_id(id)?;
        #[cfg(windows)]
        {
            let held = crate::windows::Root::open(root, false)?;
            held.open_file(&format!("{id}/index.tsv"), crate::windows::READ, false)?;
            held.remove_tree(id)
        }
        #[cfg(unix)]
        let dir = root.join(id);
        #[cfg(unix)]
        if !dir.join("index.tsv").is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("copy ID {id} has no catalog under {}", root.display()),
            ));
        }
        #[cfg(unix)]
        {
            fs::remove_dir_all(&dir)
        }
    }
}

impl Recorder for Catalog {
    /// Appends one completed entry and flushes it, so an interrupted copy keeps its record.
    fn record(&mut self, e: &Entry) -> io::Result<()> {
        // ONE `write_all`, NOT `writeln!`. `Write::write_fmt` on a bare `File` issues a
        // separate `write(2)` per format fragment -- strace counts ~18 for one entry, every
        // field and every tab its own syscall. Two consequences,
        // both measured: a copy killed mid-line (which `rcp job cancel` does, SIGTERM then
        // SIGKILL) left a torn line in 4 of 40 runs, and `read_entries` refuses the whole
        // catalog on the first malformed line -- so the interrupted copy could not resume
        // at all, which is the one thing the catalog exists to prevent. And two concurrent
        // writers interleaved into 44 malformed lines out of 907, because `O_APPEND` makes
        // each FRAGMENT atomic, not each line.
        //
        // The module header promises "flushed, so a copy killed part-way leaves a truthful
        // index"; with one write per fragment that is not true at line granularity. A
        // single `write_all` of an `O_APPEND` file under `PIPE_BUF` is.
        let line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            escape(&e.path),
            e.kind.tag(),
            e.size,
            e.mtime_ns,
            e.mode,
            e.uid,
            e.gid,
            e.sha256,
            e.ino
        );
        self.index.write_all(line.as_bytes())?;
        self.index.flush()
    }

    /// `sync` removed a destination entry: the index forgets it.
    fn record_gone(&mut self, path: &str) -> io::Result<()> {
        // same reason as `record` above: one write, not one per fragment
        self.index
            .write_all(format!("gone\t{}\n", escape(path)).as_bytes())?;
        self.index.flush()
    }
}

/// One line per command in `<root>/jobs.log`: when, what, on which endpoints, how it ended.
pub struct JobLog;

pub struct JobRecord<'a> {
    pub command: &'a str,
    pub id: &'a str,
    pub source: &'a str,
    pub destination: &'a str,
    pub status: &'a str,
    pub seconds: f64,
    pub summary: &'a str,
}

impl JobLog {
    pub fn append(root: &Path, r: &JobRecord<'_>) -> io::Result<()> {
        private_dir(root)?;
        let mut f = open_nofollow(
            &root.join("jobs.log"),
            OpenOptions::new().create(true).append(true),
        )?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // one write, for the reason `Recorder::record` gives: 90 concurrent scans against
        // one `jobs.log` otherwise produce interleaved, unparseable lines
        let line = format!(
            "{now}\t{}\t{}\t{}\t{}\t{}\t{:.3}\t{}\n",
            escape(r.command),
            escape(r.id),
            escape(r.source),
            escape(r.destination),
            r.status,
            r.seconds,
            escape(r.summary)
        );
        f.write_all(line.as_bytes())
    }

    /// Every line, oldest first; `id` filters to one copy ID.
    pub fn read(root: &Path, id: Option<&str>) -> io::Result<Vec<String>> {
        let path = root.join("jobs.log");
        let reader = match open_nofollow(&path, OpenOptions::new().read(true)) {
            Ok(f) => BufReader::new(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if let Some(id) = id {
                if line.split('\t').nth(2) != Some(&escape(id)) {
                    continue;
                }
            }
            out.push(line);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_escaped_field_unescapes_to_itself_through_tabs_newlines_and_backslashes() {
        for s in [
            "plain",
            "with\ttab",
            "with\nnewline",
            "back\\slash",
            "\\t literal",
        ] {
            assert_eq!(unescape(&escape(s)), s);
        }
    }

    #[test]
    fn ids_are_directory_names() {
        assert!(Catalog::valid_id("smoke-restore"));
        assert!(Catalog::valid_id("vm.backup_2026"));
        assert!(!Catalog::valid_id(""));
        assert!(!Catalog::valid_id("../escape"));
        assert!(!Catalog::valid_id("a/b"));
        assert!(!Catalog::valid_id(".hidden"));
        // The catalog root's own names are not available as ids. `copy -newid jobs` put a
        // catalog where the job records live, and `indexdelete -id jobs` then deleted every
        // one of them, running jobs included; `copy -newid jobs.log` turned the append-only
        // audit log into a directory, after which every `JobLog::append` failed to open it
        // and the log stopped with nothing said.
        for taken in RESERVED_IDS {
            assert!(
                !Catalog::valid_id(taken),
                "{taken} must not be usable as a copy ID"
            );
        }
        // the control: a name that merely starts the same way is fine
        assert!(Catalog::valid_id("jobs-nightly"));
        assert!(Catalog::valid_id("jobs.log.old"));
    }

    #[test]
    fn list_delete_and_job_log() {
        let root = std::env::temp_dir().join(format!("rcp-catalog-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert!(
            Catalog::list(&root).unwrap().is_empty(),
            "a missing root lists nothing"
        );
        let mut c =
            Catalog::create(&root, "one", Path::new("/src"), Path::new("/dst"), "sha256").unwrap();
        assert_eq!(c.digest.as_deref(), Some("sha256"));
        c.record(&Entry {
            path: "a".into(),
            kind: Kind::File,
            size: 1,
            mtime_ns: 2,
            mode: 3,
            uid: 4,
            gid: 5,
            sha256: "x".into(),
            ino: 0,
        })
        .unwrap();
        c.record_gone("a").unwrap();
        c.record(&Entry {
            path: "b".into(),
            kind: Kind::Dir,
            size: 0,
            mtime_ns: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            sha256: String::new(),
            ino: 0,
        })
        .unwrap();
        let infos = Catalog::list(&root).unwrap();
        assert_eq!(
            infos,
            vec![Info {
                id: "one".into(),
                source: "/src".into(),
                destination: "/dst".into(),
                entries: Some(1)
            }]
        );
        // the header is read by content rather than by counting lines, because it took the
        // first TWO lines after the banner and a third header line is exactly what adding
        // `digest` is. Reopening must still find both endpoints AND the algorithm.
        let reopened = Catalog::open(&root, "one").unwrap();
        assert_eq!(
            (reopened.source.as_path(), reopened.destination.as_path()),
            (Path::new("/src"), Path::new("/dst"))
        );
        assert_eq!(reopened.digest.as_deref(), Some("sha256"));
        drop(reopened);
        // and a catalog written before the algorithm was recorded reads as unknown rather
        // than as the default, because a -blake3 catalog from then looks the same
        let older = fs::read_to_string(root.join("one/index.tsv")).unwrap();
        fs::write(
            root.join("one/index.tsv"),
            older
                .lines()
                .filter(|l| !l.starts_with("digest\t"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        let old = Catalog::open(&root, "one").unwrap();
        assert_eq!(old.digest, None);
        assert_eq!(
            (old.source.as_path(), old.destination.as_path()),
            (Path::new("/src"), Path::new("/dst"))
        );
        assert_eq!(
            Catalog::list(&root).unwrap().len(),
            1,
            "a catalog with no digest line still lists"
        );
        JobLog::append(
            &root,
            &JobRecord {
                command: "copy",
                id: "one",
                source: "/src",
                destination: "/dst",
                status: "PASSED",
                seconds: 1.5,
                summary: "ok",
            },
        )
        .unwrap();
        JobLog::append(
            &root,
            &JobRecord {
                command: "verify",
                id: "-",
                source: "/src",
                destination: "/dst",
                status: "FAILED",
                seconds: 0.5,
                summary: "3 differences",
            },
        )
        .unwrap();
        assert_eq!(JobLog::read(&root, None).unwrap().len(), 2);
        assert_eq!(JobLog::read(&root, Some("one")).unwrap().len(), 1);
        assert_eq!(JobLog::read(&root, Some("nope")).unwrap().len(), 0);
        drop(c);
        drop(old);
        Catalog::delete(&root, "one").unwrap();
        assert!(
            Catalog::delete(&root, "one").is_err(),
            "deleting twice is an error"
        );
        assert!(Catalog::list(&root).unwrap().is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    /// `root/<id>` was joined and opened, and a symlink there was followed: an id that is a
    /// link to `/elsewhere` made `open` append to `/elsewhere/index.tsv` and `create` write
    /// through it. Ids are already names rather than paths; this is the other half, that
    /// the name must be a directory of the catalog's own and not a pointer out of it.
    #[test]
    #[cfg(unix)]
    fn a_catalog_id_that_is_a_symlink_is_refused_not_followed() {
        let scratch = std::env::temp_dir().join(format!("rcp-catalog-link-{}", std::process::id()));
        let root = scratch.join("catalog");
        let elsewhere = scratch.join("elsewhere");
        fs::create_dir_all(&root).unwrap();
        // a real catalog elsewhere (`create` makes the directory), and an id in the root
        // that points at it
        Catalog::create(
            &scratch,
            "elsewhere",
            Path::new("/src"),
            Path::new("/dst"),
            "sha256",
        )
        .unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("linked")).unwrap();
        let before = fs::read_to_string(elsewhere.join("index.tsv")).unwrap();
        let e = Catalog::open(&root, "linked")
            .err()
            .expect("a symlinked id was opened");
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(
            fs::read_to_string(elsewhere.join("index.tsv")).unwrap(),
            before,
            "the refusal still wrote through the link"
        );
        let e = Catalog::create(&root, "linked", Path::new("/a"), Path::new("/b"), "sha256")
            .err()
            .expect("a symlinked id was created through");
        assert!(e.to_string().contains("symlink"), "{e}");
        // the control: an ordinary id in the same root opens and creates
        Catalog::create(&root, "plain", Path::new("/a"), Path::new("/b"), "sha256").unwrap();
        Catalog::open(&root, "plain").unwrap();
        let _ = fs::remove_dir_all(&scratch);
    }

    /// The window between `not_a_link` and the open: with the check bypassed, a symlinked
    /// id directory must STILL not be opened through, because the directory is held open
    /// with `O_NOFOLLOW` and the file is reached through that descriptor.
    #[test]
    #[cfg(unix)]
    fn a_catalog_file_under_a_symlinked_directory_is_refused_without_the_directory_check() {
        let scratch =
            std::env::temp_dir().join(format!("rcp-catalog-dirlink-{}", std::process::id()));
        let real = scratch.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("index.tsv"), "x\n").unwrap();
        std::os::unix::fs::symlink(&real, scratch.join("linked")).unwrap();
        // `open_nofollow` directly, which is what `not_a_link` guards in front of
        let e = open_nofollow(
            &scratch.join("linked/index.tsv"),
            OpenOptions::new().append(true),
        )
        .unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(fs::read_to_string(real.join("index.tsv")).unwrap(), "x\n");
        // the control: the real directory opens through the same function
        open_nofollow(&real.join("index.tsv"), OpenOptions::new().append(true)).unwrap();
        let _ = fs::remove_dir_all(&scratch);
    }

    /// A catalog an older build wrote still opens after the banner was renamed, and a line
    /// that is not a catalog banner at all is still refused.
    ///
    /// The control matters as much as the acceptance: a banner check loosened to accept the
    /// old spelling must not become a check that accepts anything starting with `#`.
    #[test]
    fn a_catalog_under_the_previous_banner_still_opens_and_nothing_else_does() {
        let scratch =
            std::env::temp_dir().join(format!("rcp-catalog-banner-{}", std::process::id()));
        let root = scratch.join("catalog");
        let put = |id: &str, banner: &str| {
            fs::create_dir_all(root.join(id)).unwrap();
            fs::write(
                root.join(id).join("index.tsv"),
                format!("{banner}\nsource\t/s\ndestination\t/d\ndigest\tsha256\n"),
            )
            .unwrap();
        };
        put("current", HEADER);
        assert!(
            Catalog::open(&root, "current").is_ok(),
            "a catalog under the current banner must open"
        );
        // the shape older builds wrote: another word of the same length before `-catalog 1`
        put("older", &format!("#{}-catalog 1", "old"));
        assert!(
            Catalog::open(&root, "older").is_ok(),
            "a catalog an older build wrote must still open, or resume breaks"
        );
        for bad in [
            "#rcp-catalog 2",
            "rcp-catalog 1",
            "#rcp-catalog 1 ",
            "#a-catalog 1",
            "# comment",
            "",
        ] {
            put("bad", bad);
            let e = Catalog::open(&root, "bad")
                .err()
                .unwrap_or_else(|| panic!("{bad:?} was accepted as a catalog banner"));
            assert!(e.to_string().contains("not an rcp catalog"), "{bad:?}: {e}");
        }
        fs::remove_dir_all(&scratch).ok();
    }

    /// The directory check leaves the FILES: a real `root/<id>/` whose `index.tsv` is a
    /// link, and a `jobs.log` link at the root, were both written through. Every open of
    /// a catalog file refuses a link now, reads included, since `logdump` zips the index.
    #[test]
    #[cfg(unix)]
    fn a_catalog_file_that_is_a_symlink_is_refused_not_written_through() {
        let scratch =
            std::env::temp_dir().join(format!("rcp-catalog-filelink-{}", std::process::id()));
        let root = scratch.join("catalog");
        let target = scratch.join("target.tsv");
        fs::create_dir_all(root.join("linked")).unwrap();
        // a plausible index elsewhere, so the header reads if the link is followed
        fs::write(
            &target,
            format!("{HEADER}\nsource\t/s\ndestination\t/d\ndigest\tsha256\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, root.join("linked/index.tsv")).unwrap();
        let before = fs::read_to_string(&target).unwrap();
        let e = Catalog::open(&root, "linked")
            .err()
            .expect("an index that is a symlink was opened");
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(fs::read_to_string(&target).unwrap(), before);
        assert!(
            Catalog::index_bytes(&root, "linked").is_err(),
            "logdump's read followed the link"
        );
        assert!(
            Catalog::list(&root).unwrap().is_empty(),
            "a linked index was listed"
        );
        // `create` with a link already sitting where the index goes
        fs::create_dir_all(root.join("fresh")).unwrap();
        std::os::unix::fs::symlink(&target, root.join("fresh/index.tsv")).unwrap();
        assert!(
            Catalog::create(&root, "fresh", Path::new("/a"), Path::new("/b"), "sha256").is_err()
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            before,
            "create wrote through the link"
        );
        // the job log
        let log_target = scratch.join("log-target");
        fs::write(&log_target, "").unwrap();
        std::os::unix::fs::symlink(&log_target, root.join("jobs.log")).unwrap();
        let e = JobLog::append(
            &root,
            &JobRecord {
                command: "copy",
                id: "x",
                source: "/s",
                destination: "/d",
                status: "PASSED",
                seconds: 0.0,
                summary: "",
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(
            fs::metadata(&log_target).unwrap().len(),
            0,
            "the job line went through the link"
        );
        assert!(JobLog::read(&root, None).is_err());
        // the control: with the links gone, the same calls succeed
        fs::remove_file(root.join("jobs.log")).unwrap();
        fs::remove_file(root.join("fresh/index.tsv")).unwrap();
        fs::remove_dir(root.join("fresh")).unwrap();
        Catalog::create(&root, "fresh", Path::new("/a"), Path::new("/b"), "sha256").unwrap();
        Catalog::open(&root, "fresh").unwrap();
        assert!(!Catalog::index_bytes(&root, "fresh").unwrap().is_empty());
        JobLog::append(
            &root,
            &JobRecord {
                command: "copy",
                id: "x",
                source: "/s",
                destination: "/d",
                status: "PASSED",
                seconds: 0.0,
                summary: "",
            },
        )
        .unwrap();
        assert_eq!(JobLog::read(&root, None).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&scratch);
    }
}
