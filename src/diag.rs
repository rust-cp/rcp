//! The `diag` family: maintenance and troubleshooting commands, documented like the rest,
//! because an I/O generator, an index rebuild and a branch finder are
//! useful to whoever runs the migration, not only to whoever supports it.
//!
//! - `nio`: a read/write I/O generator against a path (local, NFS or S3), reporting rates.
//! - `find`: directories whose files match a pattern (`-branch-match`) or top-level branches
//!   whose files all match (`-top-match`).
//! - `indexdiag` / `rebuild`: check an index's ancestry against its destination, rebuild it
//!   from what the destination holds.
//! - `dump`: what rcp processes are running on this host and how big they are.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::catalog::{Catalog, Entry, Kind};
use crate::filter::{self, Filter};
use crate::human_bytes;
use crate::ports::Removed;
use crate::scan::{self, Scan};
use crate::tree::{Item, Tree};

// ---------------------------------------------------------------------------------------------
// nio
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NioOptions {
    pub seconds: f64,
    /// Percentage of operations that are reads (100: read only, 0: write only).
    pub read_pct: u32,
    /// Percentage of operations at a random offset (100: random, 0: sequential).
    pub random_pct: u32,
    pub block_size: usize,
    /// Worker files, each driven by `pending` threads.
    pub parallel: usize,
    pub pending: usize,
    /// Size of each worker file.
    pub file_size: u64,
    /// Write random bytes rather than zeros.
    pub random_data: bool,
}

#[derive(Debug, Default)]
pub struct NioReport {
    pub read_ops: u64,
    pub read_bytes: u64,
    pub write_ops: u64,
    pub write_bytes: u64,
    pub seconds: f64,
    pub files: usize,
    pub threads: usize,
    pub failures: Vec<String>,
    /// Scratch files the store will remove itself, later, rather than on request.
    pub warnings: Vec<String>,
}

impl NioReport {
    pub fn render(&self) -> String {
        let per = |b: u64| {
            if self.seconds > 0.0 {
                human_bytes((b as f64 / self.seconds) as u64)
            } else {
                "0 B".into()
            }
        };
        let ops = |n: u64| {
            if self.seconds > 0.0 {
                (n as f64 / self.seconds) as u64
            } else {
                0
            }
        };
        format!(
            "nio: {} files x {} threads, {:.1} s\n  read  {} ops ({} ops/s), {} ({}/s)\n  write {} ops ({} ops/s), {} ({}/s)",
            self.files,
            self.threads,
            self.seconds,
            self.read_ops,
            ops(self.read_ops),
            human_bytes(self.read_bytes),
            per(self.read_bytes),
            self.write_ops,
            ops(self.write_ops),
            human_bytes(self.write_bytes),
            per(self.write_bytes)
        )
    }
}

/// A small xorshift generator: offsets and data need to be unpredictable, not secure.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Runs the generator against `root`: a local directory gets positional reads and writes on
/// worker files it creates; a remote tree gets its worker files written through the port and
/// then read through the port (writes to a remote tree are whole-file rewrites, because the
/// port has no positional write). The worker files are removed afterwards.
pub fn nio<T: Tree>(t: &T, local_root: Option<&Path>, opts: &NioOptions) -> io::Result<NioReport> {
    let files = opts.parallel.max(1);
    let threads = opts.pending.max(1);
    let names: Vec<String> = (0..files)
        .map(|i| format!(".rcp-nio-{}-{i}", std::process::id()))
        .collect();
    let block = opts.block_size.max(4096);
    let size = opts.file_size.max(block as u64);
    let mut report = NioReport {
        files,
        threads: files * threads,
        ..Default::default()
    };
    // lay the worker files out
    let mut seed = Rng::new(std::process::id() as u64 ^ 0x9e37_79b9_7f4a_7c15);
    let mut pattern = vec![0u8; block];
    if opts.random_data {
        seed.fill(&mut pattern);
    }
    for name in &names {
        let item = Item {
            rel: name.clone(),
            kind: Kind::File,
            size,
            mtime_ns: filter::now_ns(),
            atime_ns: filter::now_ns(),
            mode: 0o600,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: size,
            link_target: None,
        };
        let mut sink = t.create_file(&item)?;
        crate::tree::Sink::reserve(&mut sink, size)?;
        let mut left = size;
        while left > 0 {
            let n = left.min(block as u64) as usize;
            crate::tree::Sink::write(&mut sink, &pattern[..n])?;
            left -= n as u64;
        }
        let meta = crate::tree::MetaOptions {
            mode: false,
            times: false,
            owner: false,
            atime: false,
        };
        crate::tree::Sink::finish(&mut sink, &item, &[], meta, false)?;
    }
    let deadline = Instant::now() + Duration::from_secs_f64(opts.seconds.max(0.1));
    let t0 = Instant::now();
    let stop = AtomicBool::new(false);
    let (ro, rb, wo, wb) = (
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    );
    let failures: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for (fi, name) in names.iter().enumerate() {
            for ti in 0..threads {
                let (ro, rb, wo, wb, stop, failures) = (&ro, &rb, &wo, &wb, &stop, &failures);
                let pattern = &pattern;
                scope.spawn(move || {
                    let mut rng =
                        Rng::new(((fi * 1024 + ti + 7) as u64).wrapping_mul(0x2545_f491_4f6c_dd1d));
                    let mut buf = vec![0u8; block];
                    let blocks = size / block as u64;
                    let mut next_seq = (ti as u64 * blocks / threads as u64) % blocks;
                    let local = local_root.map(|r| r.join(name));
                    let mut reader = if local.is_none() {
                        match t.open(name) {
                            Ok(r) => Some(r),
                            Err(e) => {
                                failures.lock().unwrap().push(format!("{name}: {e}"));
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    let file = local
                        .as_ref()
                        .and_then(|p| fs::OpenOptions::new().read(true).write(true).open(p).ok());
                    let result: io::Result<()> = (|| {
                        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                            let random = (rng.next() % 100) < opts.random_pct as u64;
                            let read = (rng.next() % 100) < opts.read_pct as u64;
                            let block_no = if random {
                                rng.next() % blocks
                            } else {
                                (next_seq + 1) % blocks
                            };
                            next_seq = block_no;
                            let off = block_no * block as u64;
                            if read {
                                match (&file, &mut reader) {
                                    (Some(f), _) => {
                                        f.read_exact_at(&mut buf, off)?;
                                    }
                                    (None, Some(r)) => {
                                        r.seek(SeekFrom::Start(off))?;
                                        r.read_exact(&mut buf)?;
                                    }
                                    _ => unreachable!(),
                                }
                                ro.fetch_add(1, Ordering::Relaxed);
                                rb.fetch_add(block as u64, Ordering::Relaxed);
                            } else {
                                match &file {
                                    Some(f) => {
                                        if opts.random_data {
                                            rng.fill(&mut buf);
                                        }
                                        f.write_all_at(&buf, off)?;
                                        wo.fetch_add(1, Ordering::Relaxed);
                                        wb.fetch_add(block as u64, Ordering::Relaxed);
                                    }
                                    None => {
                                        // no positional write on the port: rewrite the whole file
                                        let item = Item {
                                            rel: name.clone(),
                                            kind: Kind::File,
                                            size,
                                            mtime_ns: filter::now_ns(),
                                            atime_ns: filter::now_ns(),
                                            mode: 0o600,
                                            uid: 0,
                                            gid: 0,
                                            dev: 0,
                                            ino: 0,
                                            nlink: 1,
                                            blocks: size,
                                            link_target: None,
                                        };
                                        let mut sink = t.create_file(&item)?;
                                        crate::tree::Sink::reserve(&mut sink, size)?;
                                        let mut left = size;
                                        while left > 0 && Instant::now() < deadline {
                                            let n = left.min(block as u64) as usize;
                                            crate::tree::Sink::write(&mut sink, &pattern[..n])?;
                                            wo.fetch_add(1, Ordering::Relaxed);
                                            wb.fetch_add(n as u64, Ordering::Relaxed);
                                            left -= n as u64;
                                        }
                                        if left > 0 {
                                            // out of time mid-file: pad so the object is whole
                                            while left > 0 {
                                                let n = left.min(block as u64) as usize;
                                                crate::tree::Sink::write(&mut sink, &pattern[..n])?;
                                                left -= n as u64;
                                            }
                                        }
                                        let meta = crate::tree::MetaOptions {
                                            mode: false,
                                            times: false,
                                            owner: false,
                                            atime: false,
                                        };
                                        crate::tree::Sink::finish(
                                            &mut sink,
                                            &item,
                                            &[],
                                            meta,
                                            false,
                                        )?;
                                        reader = Some(t.open(name)?);
                                    }
                                }
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = result {
                        failures.lock().unwrap().push(format!("{name}: {e}"));
                        stop.store(true, Ordering::Relaxed);
                    }
                });
            }
        }
    });
    report.seconds = t0.elapsed().as_secs_f64();
    report.read_ops = ro.into_inner();
    report.read_bytes = rb.into_inner();
    report.write_ops = wo.into_inner();
    report.write_bytes = wb.into_inner();
    report.failures = failures.into_inner().unwrap();
    // The cleanup reads all three answers. Reading only `Err` means a store that answers
    // `Kept` leaves its scratch files behind and the report says nothing. Every `remove`
    // call site needs the same three-way match; grep for them when adding a variant.
    for name in &names {
        match t.remove(name, Kind::File) {
            Ok(Removed::Gone) => {}
            Ok(Removed::Deferred(why)) => report.warnings.push(format!("cleanup {name}: {why}")),
            Ok(Removed::Kept(why)) => report
                .failures
                .push(format!("cleanup {name}: the store kept it, {why}")),
            Err(e) => report.failures.push(format!("cleanup {name}: {e}")),
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// find
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindMode {
    /// Every directory holding at least one matching file.
    Branch,
    /// Every top-level directory (and the root's own files) whose files all match.
    Top,
}

#[derive(Debug, Default)]
pub struct FindReport {
    /// The directories found (as listed, or synthesized for the root), with their matching
    /// and total file counts.
    pub branches: Vec<(Item, usize, usize)>,
    pub errors: Vec<String>,
}

/// Which files match: the glob, plus the size, age, kind and owner predicates of `filter`.
fn file_matches(i: &Item, pattern: &str, filter: &Filter, now: i128) -> bool {
    filter::matches(pattern, &i.rel)
        && filter.allows_file(i.size, i.mtime_ns, now)
        && filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino)
}

pub fn find<T: Tree>(
    t: &T,
    mode: FindMode,
    pattern: &str,
    filter: &Filter,
    parallel: usize,
) -> io::Result<FindReport> {
    let listing = t.list(
        &Filter {
            include: Vec::new(),
            ..filter.clone()
        },
        None,
        parallel,
    )?;
    let now = filter::now_ns();
    let mut report = FindReport {
        errors: listing.errors.clone(),
        ..Default::default()
    };
    // per directory: (matching, total) over the files directly in it (branch) or below it (top)
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for i in listing.items.iter().filter(|i| i.kind == Kind::File) {
        let hit = file_matches(i, pattern, filter, now);
        let dir = i
            .rel
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| ".".into());
        let key = match mode {
            FindMode::Branch => dir,
            FindMode::Top => i
                .rel
                .split_once('/')
                .map(|(top, _)| top.to_string())
                .unwrap_or_else(|| ".".into()),
        };
        let c = counts.entry(key).or_insert((0, 0));
        c.1 += 1;
        if hit {
            c.0 += 1;
        }
    }
    let dirs: BTreeMap<&str, &Item> = listing
        .items
        .iter()
        .filter(|i| i.kind == Kind::Dir)
        .map(|i| (i.rel.as_str(), i))
        .collect();
    for (dir, (matching, total)) in counts {
        let keep = match mode {
            FindMode::Branch => matching > 0,
            FindMode::Top => total > 0 && matching == total,
        };
        if keep {
            let item = dirs
                .get(dir.as_str())
                .map(|i| (*i).clone())
                .unwrap_or_else(|| Item {
                    rel: dir.clone(),
                    kind: Kind::Dir,
                    size: 0,
                    mtime_ns: 0,
                    atime_ns: 0,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    dev: 0,
                    ino: 0,
                    nlink: 1,
                    blocks: 0,
                    link_target: None,
                });
            report.branches.push((item, matching, total));
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// index diagnosis and rebuild
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct IndexReport {
    pub entries: usize,
    /// Entries whose parent directory the index does not list.
    pub orphans: Vec<String>,
    /// Entries the destination no longer holds.
    pub missing: Vec<String>,
    /// Destination entries the index does not list.
    pub unlisted: Vec<String>,
}

/// Checks an index against a listing of its destination.
pub fn diagnose(entries: &BTreeMap<String, Entry>, destination: &[Item]) -> IndexReport {
    let mut r = IndexReport {
        entries: entries.len(),
        ..Default::default()
    };
    for path in entries.keys() {
        if path == "." {
            continue;
        }
        let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or(".");
        if !entries.contains_key(parent) {
            r.orphans.push(path.clone());
        }
    }
    let present: BTreeSet<&str> = destination.iter().map(|i| i.rel.as_str()).collect();
    for path in entries.keys() {
        if !present.contains(path.as_str()) {
            r.missing.push(path.clone());
        }
    }
    for i in destination {
        if !entries.contains_key(&i.rel) {
            r.unlisted.push(i.rel.clone());
        }
    }
    r
}

/// Rebuilds an index from the destination: every entry the destination holds, hashed, with
/// the ancestry complete by construction. Written as `<id>.rebuilt`, or over `<id>` with
/// `replace`.
pub fn rebuild<T: Tree>(
    root: &Path,
    id: &str,
    destination: &T,
    source_text: &str,
    destination_text: &str,
    parallel: usize,
    replace: bool,
    runtime: &crate::ports::Runtime,
) -> io::Result<(String, usize)> {
    let scan = scan::scan(
        destination,
        &scan::ScanOptions {
            parallel,
            filter: Filter::default(),
            max_depth: None,
            cache: None,
            hash: true,
            dedupe: false,
            block_size: 1 << 20,
            names: false,
            runtime: runtime.clone(),
        },
    )?;
    let entries = scan::to_entries(&scan);
    let new_id = if replace {
        id.to_string()
    } else {
        format!("{id}.rebuilt")
    };
    if replace {
        Catalog::delete(root, id)?;
    } else if Catalog::open(root, &new_id).is_ok() {
        Catalog::delete(root, &new_id)?;
    }
    // the rebuild hashed with THIS run's algorithm, so that is what the new catalog holds
    let mut c = Catalog::create(
        root,
        &new_id,
        Path::new(source_text),
        Path::new(destination_text),
        runtime.digests.name(),
    )?;
    for e in &entries {
        crate::catalog::Recorder::record(&mut c, e)?;
    }
    Ok((new_id, entries.len()))
}

// ---------------------------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub command: String,
    pub rss_kib: u64,
    pub threads: u64,
    pub fds: usize,
}

/// Every running rcp process visible in `/proc`, this one excluded.
pub fn processes() -> Vec<Process> {
    let me = std::process::id();
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(cmd) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = cmd
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).to_string())
            .collect();
        let is_rcp = argv
            .first()
            .is_some_and(|a| a == "rcp" || a.ends_with("/rcp"));
        if !is_rcp {
            continue;
        }
        let status = fs::read_to_string(entry.path().join("status")).unwrap_or_default();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let fds = fs::read_dir(entry.path().join("fd"))
            .map(|d| d.count())
            .unwrap_or(0);
        out.push(Process {
            pid,
            command: argv.join(" "),
            rss_kib: field("VmRSS:"),
            threads: field("Threads:"),
            fds,
        });
    }
    out.sort_by_key(|p| p.pid);
    out
}

/// Streams a file's bytes to `out` (`diag -cat`).
pub fn cat<T: Tree>(t: &T, rel: &str, out: &mut dyn Write) -> io::Result<u64> {
    let mut r = t.open(rel)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        out.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// `YYYY-MM-DD_HH:MM:SS[+nanoseconds]` (taken as UTC) or seconds since the epoch, to nanoseconds.
pub fn parse_timestamp(text: &str) -> Result<i128, String> {
    if let Ok(secs) = text.parse::<i64>() {
        return Ok(secs as i128 * 1_000_000_000);
    }
    let (main, nanos) = match text.split_once('+') {
        Some((m, n)) => (
            m,
            n.parse::<i128>()
                .map_err(|_| format!("{text:?}: nanoseconds after '+' must be a number"))?,
        ),
        None => (text, 0),
    };
    let (date, time) = main
        .split_once('_')
        .or_else(|| main.split_once('T'))
        .ok_or_else(|| {
            format!("{text:?}: use YYYY-MM-DD_HH:MM:SS[+nanoseconds] or epoch seconds")
        })?;
    let mut d = date.split('-');
    let bad = || format!("{text:?}: use YYYY-MM-DD_HH:MM:SS[+nanoseconds] or epoch seconds");
    let (y, m, day): (i64, u32, u32) = (
        d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
        d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
        d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
    );
    let mut t = time.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
        t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
        t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
    );
    if !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hh)
        || !(0..60).contains(&mm)
        || !(0..61).contains(&ss)
        || !(0..1_000_000_000).contains(&nanos)
    {
        return Err(bad());
    }
    let secs = crate::time::days_from_civil(y, m, day) * 86_400 + hh * 3600 + mm * 60 + ss;
    Ok(secs as i128 * 1_000_000_000 + nanos)
}

/// `from,to` lines (names or numbers resolved by the caller) into a map.
pub fn parse_map(
    text: &str,
    resolve: &dyn Fn(&str) -> Option<u32>,
) -> Result<BTreeMap<u32, u32>, String> {
    let mut map = BTreeMap::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The errors name the LINE NUMBER and what was expected, never the bytes read.
        // They used to quote the line, and `-umap` did not go through the rails, so a
        // railed `diag change -umap /etc/shadow` printed a password hash in its own error
        // message -- an unbounded one-line read of any file, dressed as a parse failure.
        // The rail is fixed at the call site; this is the other half, and it holds for an
        // ALLOWED file too, since a mapping table is not the run's to put in a log.
        let (from, to) = line.split_once(',').ok_or_else(|| {
            format!(
                "line {}: not from,to ({} characters, no comma)",
                n + 1,
                line.chars().count()
            )
        })?;
        let f = resolve(from.trim()).ok_or_else(|| {
            format!(
                "line {}: the first field is not a number or a known name",
                n + 1
            )
        })?;
        let t = resolve(to.trim()).ok_or_else(|| {
            format!(
                "line {}: the second field is not a number or a known name",
                n + 1
            )
        })?;
        map.insert(f, t);
    }
    if map.is_empty() {
        return Err("the table has no from,to lines".into());
    }
    Ok(map)
}

/// The statistics report over the files a find matched, for `-l`-style detail.
pub fn as_scan(items: Vec<Item>, runtime: &crate::ports::Runtime) -> Scan {
    Scan {
        listing: crate::ports::Listing {
            items,
            errors: Vec::new(),
        },
        hashes: BTreeMap::new(),
        seconds: 0.0,
        names: Some(runtime.names.clone()),
        hash_name: runtime.digests.name(),
        hashed: 0,
        cache_hits: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(rel: &str, kind: Kind, size: u64) -> Item {
        Item {
            rel: rel.into(),
            kind,
            size,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    #[test]
    fn timestamps_and_maps_parse() {
        assert_eq!(
            parse_timestamp("2015-09-19_23:00:12").unwrap(),
            1_442_703_612 * 1_000_000_000
        );
        assert_eq!(
            parse_timestamp("2015-09-19_23:00:12+500").unwrap(),
            1_442_703_612 * 1_000_000_000 + 500
        );
        assert_eq!(
            parse_timestamp("1600000000").unwrap(),
            1_600_000_000_000_000_000
        );
        assert!(parse_timestamp("2015-13-01_00:00:00").is_err());
        assert!(parse_timestamp("yesterday").is_err());
        let m = parse_map("# comment\n1000,2000\n1001, 2001\n", &|s| s.parse().ok()).unwrap();
        assert_eq!(m, [(1000, 2000), (1001, 2001)].into_iter().collect());
        assert!(parse_map("1000\n", &|s| s.parse().ok()).is_err());
        assert!(parse_map("", &|s| s.parse().ok()).is_err());
    }

    #[test]
    fn diagnosis_finds_orphans_missing_and_unlisted() {
        let entries: BTreeMap<String, Entry> = [".", "a", "a/x", "b/y"]
            .iter()
            .map(|p| {
                (
                    p.to_string(),
                    Entry {
                        path: p.to_string(),
                        kind: if p.contains('/') {
                            Kind::File
                        } else {
                            Kind::Dir
                        },
                        size: 0,
                        mtime_ns: 0,
                        mode: 0,
                        uid: 0,
                        gid: 0,
                        sha256: String::new(),
                        ino: 0,
                    },
                )
            })
            .collect();
        let dest = vec![
            item(".", Kind::Dir, 0),
            item("a", Kind::Dir, 0),
            item("a/x", Kind::File, 1),
            item("c", Kind::Dir, 0),
        ];
        let r = diagnose(&entries, &dest);
        assert_eq!(r.orphans, vec!["b/y"]);
        assert_eq!(r.missing, vec!["b/y"]);
        assert_eq!(r.unlisted, vec!["c"]);
    }

    #[test]
    fn rng_is_deterministic_and_nonzero() {
        let mut a = Rng::new(5);
        let mut b = Rng::new(5);
        assert_eq!(a.next(), b.next());
        assert_ne!(a.next(), 0);
    }
}
