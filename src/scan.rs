//! `scan`: a listing plus its reports (`-stats`, `-du`, `-l`, `-csv`,
//! `-html`, `-fmt`, `-edupe`), computed from one walk or from a saved index. Hashing, when
//! asked for, runs in parallel and hashes holes as zeros, so the digest matches `sha256sum`
//! on the same file.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::catalog::{Entry, Kind};
use crate::filter::Filter;
use crate::human_bytes;
use crate::ports::{hash_zeros, Item, Listing, Names, Runtime, Segment, Tree};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub parallel: usize,
    pub filter: Filter,
    pub max_depth: Option<usize>,
    /// Hash every file (`-sha256`, also accepted as `-md5`; `-blake3` for
    /// the faster digest).
    pub hash: bool,
    /// Hash only files whose size another file shares, to find exact duplicates (`-edupe`).
    pub dedupe: bool,
    pub block_size: usize,
    /// Show user and group names in listings (`-nonames` turns it off).
    pub names: bool,
    /// `-hashcache`: reuse the digest remembered for a file whose size, mtime and inode all
    /// still agree, instead of reading it again. Off unless asked for -- see
    /// `crate::hashcache` for why a digest cache must not be the default.
    pub cache: Option<std::sync::Arc<Mutex<crate::hashcache::HashCache>>>,
    pub runtime: Runtime,
}

pub struct Scan {
    pub listing: Listing,
    pub hashes: BTreeMap<String, String>,
    pub seconds: f64,
    /// The names port when listings show user and group names; `None` shows numbers.
    pub names: Option<std::sync::Arc<dyn Names>>,
    /// The digest column's name (`sha256`, `blake3`).
    pub hash_name: &'static str,
    /// How many files this run actually read to hash, and how many digests came from the
    /// cache instead. Counted rather than timed: "the second run was faster" is a claim a
    /// warm page cache also satisfies, so the arms assert on these two numbers.
    pub hashed: usize,
    pub cache_hits: usize,
}

pub fn scan<T: Tree>(t: &T, opts: &ScanOptions) -> io::Result<Scan> {
    let t0 = Instant::now();
    let parallel = opts.parallel.max(1);
    let mut listing = t.list(&opts.filter, opts.max_depth, parallel)?;
    // The walk keeps every directory so it can descend; a report about `-type f` or
    // `-uid 0` must not list directories that fail the same test.
    if opts.filter.kinds.is_some()
        || opts.filter.uid.is_some()
        || opts.filter.gid.is_some()
        || opts.filter.fileid.is_some()
    {
        listing
            .items
            .retain(|i| opts.filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino));
    }
    let mut hashes = BTreeMap::new();
    let mut cache_hits = 0usize;
    let mut hashed = 0usize;
    if opts.hash || opts.dedupe {
        let mut size_count: BTreeMap<u64, usize> = BTreeMap::new();
        for i in listing.items.iter().filter(|i| i.kind == Kind::File) {
            *size_count.entry(i.size).or_default() += 1;
        }
        let mut targets: Vec<&Item> = listing
            .items
            .iter()
            .filter(|i| i.kind == Kind::File && (opts.hash || size_count[&i.size] > 1))
            .collect();
        // Answered from the cache BEFORE the workers are handed a list, rather than inside
        // the loop: a file whose digest is remembered never becomes a unit of work at all,
        // so `targets.len()` after this is exactly the number of files this run will read.
        // That number is what the arms assert on.
        if let Some(cache) = &opts.cache {
            let mut c = cache.lock().unwrap();
            targets.retain(|i| match c.lookup(&i.rel, i.size, i.mtime_ns, i.ino) {
                Some(d) => {
                    hashes.insert(i.rel.clone(), d);
                    cache_hits += 1;
                    false
                }
                None => true,
            });
        }
        let hashed_now: Vec<(String, u64, i128, u64)> = targets
            .iter()
            .map(|i| (i.rel.clone(), i.size, i.mtime_ns, i.ino))
            .collect();
        let next = AtomicUsize::new(0);
        let out: Mutex<Vec<(usize, io::Result<String>)>> =
            Mutex::new(Vec::with_capacity(targets.len()));
        std::thread::scope(|scope| {
            for _ in 0..parallel.min(targets.len().max(1)) {
                scope.spawn(|| {
                    let mut buf = vec![0u8; opts.block_size.max(4096)];
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= targets.len() {
                            break;
                        }
                        let mut h = opts.runtime.hasher();
                        let r = t
                            .read(&targets[i].rel, &mut buf, &mut |seg| {
                                match seg {
                                    Segment::Data(d) => {
                                        opts.runtime.throttle.take(d.len() as u64);
                                        h.update(d)
                                    }
                                    Segment::Hole(n) => hash_zeros(&mut *h, n),
                                }
                                Ok(())
                            })
                            .map(|_| h.finish());
                        out.lock().unwrap().push((i, r));
                    }
                });
            }
        });
        let mut fresh: Vec<(usize, String)> = Vec::new();
        for (i, r) in out.into_inner().unwrap() {
            match r {
                Ok(h) => {
                    hashes.insert(targets[i].rel.clone(), h.clone());
                    fresh.push((i, h));
                }
                Err(e) => eprintln!("WARN: hash {}: {e}", targets[i].rel),
            }
        }
        // The facts are read from the listing taken before the hashing, NOT re-stated
        // afterwards. A file rewritten while this run was reading it would otherwise be
        // cached under its NEW size and mtime carrying the digest of a read that straddled
        // the change -- a stale entry that no later comparison could detect, written by the
        // very run that was supposed to notice.
        if let Some(cache) = &opts.cache {
            let mut c = cache.lock().unwrap();
            for (i, h) in fresh {
                let (rel, size, mtime_ns, ino) = &hashed_now[i];
                c.insert(rel, *size, *mtime_ns, *ino, &h);
            }
        }
        hashed = targets.len();
    }
    Ok(Scan {
        listing,
        hashes,
        seconds: t0.elapsed().as_secs_f64(),
        names: if opts.names {
            Some(opts.runtime.names.clone())
        } else {
            None
        },
        hash_name: opts.runtime.digests.name(),
        hashed,
        cache_hits,
    })
}

/// A scan rebuilt from a saved index (`scan -id`): the same reports without touching the
/// tree. Inode numbers and link targets are not in the index, so hard links and symlink
/// targets do not show.
pub fn from_entries(
    entries: &BTreeMap<String, Entry>,
    names: Option<std::sync::Arc<dyn Names>>,
    hash_name: &'static str,
) -> Scan {
    let mut items: Vec<Item> = entries
        .values()
        .map(|e| Item {
            rel: e.path.clone(),
            kind: e.kind,
            size: e.size,
            mtime_ns: e.mtime_ns,
            atime_ns: e.mtime_ns,
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            dev: 0,
            ino: e.ino,
            nlink: 1,
            blocks: e.size,
            link_target: None,
        })
        .collect();
    items.sort_by(|a, b| a.rel.cmp(&b.rel));
    let hashes = entries
        .values()
        .filter(|e| !e.sha256.is_empty())
        .map(|e| (e.path.clone(), e.sha256.clone()))
        .collect();
    Scan {
        listing: Listing {
            items,
            errors: Vec::new(),
        },
        hashes,
        seconds: 0.0,
        names,
        hash_name,
        hashed: 0,
        cache_hits: 0,
    }
}

/// The scan as catalog entries (`scan -newid`), digests included when they were computed.
pub fn to_entries(scan: &Scan) -> Vec<Entry> {
    scan.listing
        .items
        .iter()
        .map(|i| Entry {
            path: i.rel.clone(),
            kind: i.kind,
            size: i.size,
            mtime_ns: i.mtime_ns,
            mode: i.mode,
            uid: i.uid,
            gid: i.gid,
            sha256: scan.hashes.get(&i.rel).cloned().unwrap_or_default(),
            ino: i.ino,
        })
        .collect()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub directories: usize,
    pub files: usize,
    pub symlinks: usize,
    pub bytes: u64,
    pub allocated: u64,
    pub largest: Option<(String, u64)>,
}

pub fn summary(scan: &Scan) -> Summary {
    let mut s = Summary::default();
    for item in &scan.listing.items {
        match item.kind {
            Kind::Dir => s.directories += 1,
            Kind::Symlink => s.symlinks += 1,
            Kind::File => {
                s.files += 1;
                s.bytes += item.size;
                s.allocated += item.blocks;
                if s.largest.as_ref().is_none_or(|(_, n)| item.size > *n) {
                    s.largest = Some((item.rel.clone(), item.size));
                }
            }
        }
    }
    s
}

pub const SIZE_BUCKETS: [(&str, u64); 8] = [
    ("< 1 KiB", 1 << 10),
    ("< 8 KiB", 8 << 10),
    ("< 64 KiB", 64 << 10),
    ("< 1 MiB", 1 << 20),
    ("< 10 MiB", 10 << 20),
    ("< 100 MiB", 100 << 20),
    ("< 1 GiB", 1 << 30),
    (">= 1 GiB", u64::MAX),
];

/// Counts and bytes per size bucket.
pub fn size_bins(items: &[Item]) -> Vec<(String, usize, u64)> {
    let mut rows: Vec<(String, usize, u64)> = SIZE_BUCKETS
        .iter()
        .map(|(l, _)| (l.to_string(), 0, 0))
        .collect();
    for f in items.iter().filter(|i| i.kind == Kind::File) {
        let b = SIZE_BUCKETS
            .iter()
            .position(|(_, limit)| f.size < *limit)
            .unwrap_or(SIZE_BUCKETS.len() - 1);
        rows[b].1 += 1;
        rows[b].2 += f.size;
    }
    rows
}

/// Counts and bytes per depth.
pub fn depth_bins(items: &[Item]) -> Vec<(String, usize, u64)> {
    let mut by_depth: BTreeMap<usize, (usize, u64)> = BTreeMap::new();
    for i in items {
        let e = by_depth.entry(i.depth()).or_default();
        e.0 += 1;
        e.1 += i.size;
    }
    by_depth
        .into_iter()
        .map(|(d, (c, b))| (format!("depth {d}"), c, b))
        .collect()
}

fn table(out: &mut String, title: &str, rows: &[(String, usize, u64)]) {
    let _ = writeln!(out, "== {title} ==");
    let _ = writeln!(out, "{:<28} {:>10} {:>12}", "", "count", "bytes");
    for (label, count, bytes) in rows {
        let _ = writeln!(
            out,
            "{:<28} {:>10} {:>12}",
            label,
            count,
            human_bytes(*bytes)
        );
    }
    out.push('\n');
}

/// The `-stats` report: histograms by size, extension, depth and age, and the largest files
/// and directories.
pub fn stats_report(scan: &Scan) -> String {
    let items = &scan.listing.items;
    let files: Vec<&Item> = items.iter().filter(|i| i.kind == Kind::File).collect();
    let s = summary(scan);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} directories, {} files, {} symlinks, {} ({} allocated), largest {}\n",
        s.directories,
        s.files,
        s.symlinks,
        human_bytes(s.bytes),
        human_bytes(s.allocated),
        s.largest
            .as_ref()
            .map(|(p, n)| format!("{p} ({})", human_bytes(*n)))
            .unwrap_or_else(|| "-".into())
    );
    table(&mut out, "Files by size", &size_bins(items));

    let mut by_ext: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for f in &files {
        let name = f.name();
        let ext = match name.rfind('.') {
            Some(i) if i > 0 => name[i..].to_ascii_lowercase(),
            _ => "(none)".to_string(),
        };
        let e = by_ext.entry(ext).or_default();
        e.0 += 1;
        e.1 += f.size;
    }
    let mut ext_rows: Vec<(String, usize, u64)> =
        by_ext.into_iter().map(|(k, (c, b))| (k, c, b)).collect();
    ext_rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ext_rows.truncate(10);
    table(&mut out, "Top file extensions", &ext_rows);
    table(&mut out, "Entries by depth", &depth_bins(items));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    const AGE_BUCKETS: [(&str, i128); 6] = [
        ("< 1 day", 86_400),
        ("< 1 week", 7 * 86_400),
        ("< 1 month", 30 * 86_400),
        ("< 1 year", 365 * 86_400),
        ("< 5 years", 5 * 365 * 86_400),
        (">= 5 years", i128::MAX),
    ];
    let mut age_rows: Vec<(String, usize, u64)> = AGE_BUCKETS
        .iter()
        .map(|(l, _)| (l.to_string(), 0, 0))
        .collect();
    for f in &files {
        let age_s = (now - f.mtime_ns) / 1_000_000_000;
        let b = AGE_BUCKETS
            .iter()
            .position(|(_, limit)| age_s < *limit)
            .unwrap_or(AGE_BUCKETS.len() - 1);
        age_rows[b].1 += 1;
        age_rows[b].2 += f.size;
    }
    table(&mut out, "Files by modification age", &age_rows);

    let mut by_owner: BTreeMap<u32, (usize, u64)> = BTreeMap::new();
    for f in &files {
        let e = by_owner.entry(f.uid).or_default();
        e.0 += 1;
        e.1 += f.size;
    }
    let mut owner_rows: Vec<(String, usize, u64)> = by_owner
        .into_iter()
        .map(|(u, (c, b))| {
            (
                match &scan.names {
                    Some(n) => n.user(u),
                    None => u.to_string(),
                },
                c,
                b,
            )
        })
        .collect();
    owner_rows.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    owner_rows.truncate(10);
    table(&mut out, "Files by owner", &owner_rows);

    let mut largest: Vec<&Item> = files.clone();
    largest.sort_by(|a, b| b.size.cmp(&a.size).then(a.rel.cmp(&b.rel)));
    let _ = writeln!(out, "== Largest files ==");
    for f in largest.iter().take(10) {
        let _ = writeln!(out, "{:>12}  {}", human_bytes(f.size), f.rel);
    }
    out.push('\n');

    let usage = directory_usage(items);
    let mut dirs: Vec<(&String, &(u64, usize))> = usage.iter().collect();
    dirs.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
    let _ = writeln!(out, "== Largest directories (recursive) ==");
    for (rel, (bytes, count)) in dirs.iter().take(10) {
        let _ = writeln!(
            out,
            "{:>12}  {:>8} files  {}",
            human_bytes(*bytes),
            count,
            rel
        );
    }
    let sparse: u64 = files.iter().map(|f| f.size.saturating_sub(f.blocks)).sum();
    if sparse > 0 {
        let _ = writeln!(
            out,
            "\nsparse: {} of logical size is holes",
            human_bytes(sparse)
        );
    }
    out
}

/// Recursive bytes and file count per directory.
fn directory_usage(items: &[Item]) -> BTreeMap<String, (u64, usize)> {
    let mut usage: BTreeMap<String, (u64, usize)> = BTreeMap::new();
    for i in items.iter().filter(|i| i.kind == Kind::Dir) {
        usage.insert(i.rel.clone(), (0, 0));
    }
    for f in items.iter().filter(|i| i.kind == Kind::File) {
        let mut dir = f
            .rel
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| ".".into());
        loop {
            if let Some(e) = usage.get_mut(&dir) {
                e.0 += f.size;
                e.1 += 1;
            }
            if dir == "." {
                break;
            }
            dir = dir
                .rsplit_once('/')
                .map(|(d, _)| d.to_string())
                .unwrap_or_else(|| ".".into());
        }
    }
    usage
}

/// `-du`: one line per directory, deepest last, like `du`.
pub fn du_report(scan: &Scan, kib: bool) -> String {
    let usage = directory_usage(&scan.listing.items);
    let mut out = String::new();
    let mut rows: Vec<(&String, &(u64, usize))> = usage.iter().collect();
    rows.sort_by(|a, b| b.0.cmp(a.0)); // children before parents, root last
    for (rel, (bytes, _)) in rows {
        if kib {
            let _ = writeln!(out, "{}\t{}", bytes.div_ceil(1024), rel);
        } else {
            let _ = writeln!(out, "{bytes}\t{rel}");
        }
    }
    out
}

fn kind_char(k: Kind) -> char {
    match k {
        Kind::File => '-',
        Kind::Dir => 'd',
        Kind::Symlink => 'l',
    }
}

pub fn mode_string(kind: Kind, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(kind_char(kind));
    for (shift, sbit, sch) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        let x = bits & 1 != 0;
        s.push(match (mode & sbit != 0, x) {
            (true, true) => sch,
            (true, false) => sch.to_ascii_uppercase(),
            (false, true) => 'x',
            (false, false) => '-',
        });
    }
    s
}

/// Owner and group as a listing shows them.
pub fn owner_strings(uid: u32, gid: u32, names: Option<&dyn Names>) -> (String, String) {
    match names {
        Some(n) => (n.user(uid), n.group(gid)),
        None => (uid.to_string(), gid.to_string()),
    }
}

/// One long-listing line for an item: mode, owner, group, size, mtime (seconds), path.
pub fn long_line(i: &Item, names: Option<&dyn Names>, hash: Option<&str>) -> String {
    let (u, g) = owner_strings(i.uid, i.gid, names);
    let target = i
        .link_target
        .as_ref()
        .map(|t| format!(" -> {}", t.display()))
        .unwrap_or_default();
    let hash = hash.map(|h| format!("  {h}")).unwrap_or_default();
    format!(
        "{} {:>8} {:>8} {:>12} {:>12} {}{}{}",
        mode_string(i.kind, i.mode),
        u,
        g,
        i.size,
        i.mtime_ns.div_euclid(1_000_000_000),
        i.rel,
        target,
        hash
    )
}

/// `-l`: a long listing; plain: one path per line.
pub fn listing_report(scan: &Scan, long: bool) -> String {
    let mut out = String::new();
    for i in &scan.listing.items {
        if long {
            let _ = writeln!(
                out,
                "{}",
                long_line(
                    i,
                    scan.names.as_deref(),
                    scan.hashes.get(&i.rel).map(String::as_str)
                )
            );
        } else {
            let _ = writeln!(out, "{}", i.rel);
        }
    }
    out
}

/// `-fmt`: one line per entry from a template with `{path}`, `{name}`, `{kind}`, `{size}`,
/// `{size_h}`, `{mtime}` (seconds), `{mtime_ns}`, `{mode}` (octal), `{mode_s}`, `{uid}`,
/// `{gid}`, `{user}`, `{group}`, `{nlink}`, `{depth}`, `{target}`, `{sha256}` (also `{hash}`:
/// the digest in force, BLAKE3 under `-blake3`).
pub fn format_report(scan: &Scan, template: &str) -> String {
    let mut out = String::new();
    for i in &scan.listing.items {
        let (u, g) = owner_strings(i.uid, i.gid, scan.names.as_deref());
        let line = template
            .replace("{path}", &i.rel)
            .replace("{name}", i.name())
            .replace("{kind}", i.kind.tag())
            .replace("{size_h}", &human_bytes(i.size))
            .replace("{size}", &i.size.to_string())
            .replace("{mtime_ns}", &i.mtime_ns.to_string())
            .replace("{mtime}", &i.mtime_ns.div_euclid(1_000_000_000).to_string())
            .replace("{mode_s}", &mode_string(i.kind, i.mode))
            .replace("{mode}", &format!("{:04o}", i.mode))
            .replace("{uid}", &i.uid.to_string())
            .replace("{gid}", &i.gid.to_string())
            .replace("{user}", &u)
            .replace("{group}", &g)
            .replace("{nlink}", &i.nlink.to_string())
            .replace("{depth}", &i.depth().to_string())
            .replace(
                "{target}",
                &i.link_target
                    .as_ref()
                    .map(|t| t.display().to_string())
                    .unwrap_or_default(),
            )
            .replace(
                "{sha256}",
                scan.hashes.get(&i.rel).map(String::as_str).unwrap_or(""),
            )
            .replace(
                "{hash}",
                scan.hashes.get(&i.rel).map(String::as_str).unwrap_or(""),
            );
        let _ = writeln!(out, "{line}");
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// `-csv`: `kind,mode,uid,gid,user,group,size,mtime_ns,nlink,path,link_target,sha256`; the last
/// column is named for the digest in force (`blake3` under `-blake3`).
pub fn csv_report(scan: &Scan) -> String {
    let mut out = format!(
        "kind,mode,uid,gid,user,group,size,mtime_ns,nlink,path,link_target,{}\n",
        scan.hash_name
    );
    for i in &scan.listing.items {
        let (u, g) = owner_strings(i.uid, i.gid, scan.names.as_deref());
        let _ = writeln!(
            out,
            "{},{:04o},{},{},{},{},{},{},{},{},{},{}",
            i.kind.tag(),
            i.mode,
            i.uid,
            i.gid,
            csv_field(&u),
            csv_field(&g),
            i.size,
            i.mtime_ns,
            i.nlink,
            csv_field(&i.rel),
            csv_field(
                &i.link_target
                    .as_ref()
                    .map(|t| t.display().to_string())
                    .unwrap_or_default()
            ),
            scan.hashes.get(&i.rel).map(String::as_str).unwrap_or("")
        );
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// `-html`: a self-contained page with the summary, the statistics and the usage table.
pub fn html_report(scan: &Scan, root: &str) -> String {
    let s = summary(scan);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>rcp scan of {}</title>",
        html_escape(root)
    );
    let _ = writeln!(out, "<style>body{{font-family:sans-serif;margin:2em}}pre{{background:#f4f4f4;padding:1em;overflow:auto}}</style></head><body>");
    let _ = writeln!(out, "<h1>rcp scan of {}</h1>", html_escape(root));
    let _ = writeln!(
        out,
        "<p>{} directories, {} files, {} symlinks, {} ({} allocated), scanned in {:.2} s</p>",
        s.directories,
        s.files,
        s.symlinks,
        human_bytes(s.bytes),
        human_bytes(s.allocated),
        scan.seconds
    );
    let _ = writeln!(
        out,
        "<h2>Statistics</h2>\n<pre>{}</pre>",
        html_escape(&stats_report(scan))
    );
    let _ = writeln!(
        out,
        "<h2>Directory usage</h2>\n<pre>{}</pre>",
        html_escape(&du_report(scan, false))
    );
    if !scan.listing.errors.is_empty() {
        let _ = writeln!(
            out,
            "<h2>Unreadable</h2>\n<pre>{}</pre>",
            html_escape(&scan.listing.errors.join("\n"))
        );
    }
    out.push_str("</body></html>\n");
    out
}

/// `-edupe`: groups of files with identical content, and the bytes a dedupe would reclaim.
pub fn dedupe_report(scan: &Scan) -> String {
    let mut groups: BTreeMap<&str, Vec<&Item>> = BTreeMap::new();
    for i in scan.listing.items.iter().filter(|i| i.kind == Kind::File) {
        if let Some(h) = scan.hashes.get(&i.rel) {
            groups.entry(h.as_str()).or_default().push(i);
        }
    }
    let mut dup: Vec<(&str, &Vec<&Item>)> = groups
        .iter()
        .filter(|(_, g)| g.len() > 1)
        .map(|(h, g)| (*h, g))
        .collect();
    dup.sort_by(|a, b| {
        (b.1[0].size * (b.1.len() as u64 - 1)).cmp(&(a.1[0].size * (a.1.len() as u64 - 1)))
    });
    let mut out = String::new();
    let mut reclaim = 0u64;
    let mut dup_files = 0usize;
    for (hash, g) in &dup {
        let extra = g[0].size * (g.len() as u64 - 1);
        reclaim += extra;
        dup_files += g.len() - 1;
        let _ = writeln!(
            out,
            "{} x{} ({} each, {} reclaimable) {}",
            &hash[..16],
            g.len(),
            human_bytes(g[0].size),
            human_bytes(extra),
            g.iter()
                .map(|i| i.rel.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let _ = writeln!(
        out,
        "dedupe: {} duplicate groups, {} redundant files, {} reclaimable",
        dup.len(),
        dup_files,
        human_bytes(reclaim)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_strings_render_like_ls_including_setuid_and_sticky_bits() {
        assert_eq!(mode_string(Kind::File, 0o644), "-rw-r--r--");
        assert_eq!(mode_string(Kind::Dir, 0o755), "drwxr-xr-x");
        assert_eq!(mode_string(Kind::File, 0o4755), "-rwsr-xr-x");
        assert_eq!(mode_string(Kind::File, 0o4644), "-rwSr--r--");
        assert_eq!(mode_string(Kind::Dir, 0o1777), "drwxrwxrwt");
    }

    #[test]
    fn a_csv_field_is_quoted_only_when_it_holds_a_comma_or_a_quote() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn entries_round_trip_through_a_saved_scan() {
        let entries: BTreeMap<String, Entry> = [
            Entry {
                path: ".".into(),
                kind: Kind::Dir,
                size: 0,
                mtime_ns: 1,
                mode: 0o755,
                uid: 0,
                gid: 0,
                sha256: String::new(),
                ino: 0,
            },
            Entry {
                path: "a.txt".into(),
                kind: Kind::File,
                size: 5,
                mtime_ns: 2_000_000_000,
                mode: 0o644,
                uid: 0,
                gid: 0,
                sha256: "abc".into(),
                ino: 7,
            },
        ]
        .into_iter()
        .map(|e| (e.path.clone(), e))
        .collect();
        let s = from_entries(&entries, None, "sha256");
        assert_eq!(summary(&s).files, 1);
        assert_eq!(to_entries(&s).len(), 2);
        assert_eq!(to_entries(&s)[1].sha256, "abc");
        assert_eq!(
            format_report(&s, "{kind} {size} {mtime} {path}")
                .lines()
                .nth(1),
            Some("f 5 2 a.txt")
        );
    }

    fn fixture(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rcp-scan-cache-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tree")).unwrap();
        std::fs::create_dir_all(d.join("state")).unwrap();
        for (n, body) in [("a.txt", "alpha"), ("b.txt", "bravo"), ("c.txt", "charlie")] {
            std::fs::write(d.join("tree").join(n), body).unwrap();
        }
        d
    }

    fn opts(cache: Option<std::sync::Arc<Mutex<crate::hashcache::HashCache>>>) -> ScanOptions {
        ScanOptions {
            parallel: 2,
            filter: Filter::default(),
            max_depth: None,
            hash: true,
            dedupe: false,
            block_size: 4096,
            names: false,
            cache,
            runtime: Runtime::plain(),
        }
    }

    /// The claim `-hashcache` makes: the second scan of an unchanged tree reads no file
    /// bytes at all, and answers with the same digests.
    ///
    /// Asserted on `hashed`, the number of files the run handed to its workers, NOT on
    /// elapsed time -- a second run is faster anyway once the page cache is warm, so a
    /// timing arm would pass with the cache doing nothing.
    #[test]
    fn a_second_scan_of_an_unchanged_tree_reads_nothing() {
        let d = fixture("hit");
        let tree = crate::tree::LocalTree::new(&d.join("tree"));
        let root = d.join("tree").display().to_string();

        let c1 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let first = scan(&tree, &opts(Some(c1.clone()))).unwrap();
        assert_eq!(first.hashed, 3, "a cold cache reads every file");
        assert_eq!(first.cache_hits, 0);
        c1.lock().unwrap().save(true).unwrap();

        let c2 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let second = scan(&tree, &opts(Some(c2))).unwrap();
        assert_eq!(second.hashed, 0, "a warm cache reads none");
        assert_eq!(second.cache_hits, 3);
        assert_eq!(
            second.hashes, first.hashes,
            "and answers with the same digests"
        );

        // CONTROL. The same second scan with no cache reads all three again -- so the zero
        // above is the cache working and not a scan that stopped finding files.
        let bare = scan(&tree, &opts(None)).unwrap();
        assert_eq!(bare.hashed, 3);
        assert_eq!(bare.cache_hits, 0);
        assert_eq!(bare.hashes, first.hashes);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The failure mode that matters: a changed file served from the cache. A rewrite gives
    /// the file a new mtime, so the cached digest must be refused and the new content must
    /// be what the scan reports.
    #[test]
    fn a_changed_file_is_reread_and_its_new_digest_reported() {
        let d = fixture("change");
        let tree = crate::tree::LocalTree::new(&d.join("tree"));
        let root = d.join("tree").display().to_string();

        let c1 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let first = scan(&tree, &opts(Some(c1.clone()))).unwrap();
        c1.lock().unwrap().save(true).unwrap();
        let was = first.hashes["b.txt"].clone();

        std::fs::write(d.join("tree").join("b.txt"), "BRAVO!").unwrap();
        let c2 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let second = scan(&tree, &opts(Some(c2.clone()))).unwrap();
        assert_eq!(second.hashed, 1, "only the changed file is read again");
        assert_eq!(second.cache_hits, 2);
        assert_ne!(
            second.hashes["b.txt"], was,
            "the reported digest is of the content on disk"
        );
        assert_eq!(
            second.hashes["a.txt"], first.hashes["a.txt"],
            "the unchanged ones are unchanged"
        );

        // and the new digest replaces the old one, so a third scan is a hit on all three
        c2.lock().unwrap().save(true).unwrap();
        let c3 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let third = scan(&tree, &opts(Some(c3))).unwrap();
        assert_eq!(third.hashed, 0);
        assert_eq!(
            third.hashes["b.txt"], second.hashes["b.txt"],
            "and it is the NEW digest that was cached"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Two algorithms over one tree are two caches. Without this, `scan -blake3` followed by
    /// `scan -sha256` would serve BLAKE3 digests under a SHA-256 heading -- the mixture the
    /// catalog's digest column already shipped once.
    #[test]
    fn a_scan_in_a_second_algorithm_does_not_reuse_the_first_algorithms_digests() {
        let d = fixture("algo");
        let tree = crate::tree::LocalTree::new(&d.join("tree"));
        let root = d.join("tree").display().to_string();

        let mut b3 = opts(None);
        b3.runtime = Runtime {
            digests: crate::hash::Algorithm::Blake3.digests(),
            ..Runtime::plain()
        };
        let c1 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "blake3",
        )));
        b3.cache = Some(c1.clone());
        let blake = scan(&tree, &b3).unwrap();
        c1.lock().unwrap().save(true).unwrap();

        let c2 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let sha = scan(&tree, &opts(Some(c2))).unwrap();
        assert_eq!(
            sha.hashed, 3,
            "a SHA-256 scan reads the files even though BLAKE3 digests exist"
        );
        assert_eq!(sha.cache_hits, 0);
        assert_ne!(sha.hashes["a.txt"], blake.hashes["a.txt"]);

        // control: the BLAKE3 scan repeated IS a hit, so the miss above is the algorithm
        // boundary rather than a cache that never saved anything
        let c3 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "blake3",
        )));
        b3.cache = Some(c3);
        assert_eq!(scan(&tree, &b3).unwrap().hashed, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A file replaced by the rename-into-place that `cp -p`, `rsync --times` and most
    /// editors perform: new content, and size and mtime restored to the old values. Size and
    /// mtime alone -- rclone's check, and everything this cache has on a store with no real
    /// inode -- say nothing changed. The inode says otherwise, and on a local tree that is
    /// what makes the difference.
    #[test]
    #[cfg(unix)]
    fn a_file_replaced_with_its_old_size_and_mtime_is_caught_by_the_inode() {
        use std::os::unix::fs::MetadataExt;
        let d = fixture("rename");
        let tree = crate::tree::LocalTree::new(&d.join("tree"));
        let root = d.join("tree").display().to_string();
        let target = d.join("tree").join("a.txt");

        let c1 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let first = scan(&tree, &opts(Some(c1.clone()))).unwrap();
        c1.lock().unwrap().save(true).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        let (mtime, mtime_ns, old_ino) = (before.mtime(), before.mtime_nsec(), before.ino());

        // same length, different bytes, written to a sibling and renamed over the top
        let tmp = d.join("tree").join(".a.new");
        std::fs::write(&tmp, "ALPHA").unwrap();
        std::fs::rename(&tmp, &target).unwrap();
        set_mtime(&target, mtime, mtime_ns);
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(after.len(), before.len(), "the size is restored");
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (mtime, mtime_ns),
            "the mtime is restored"
        );
        if after.ino() == old_ino {
            // A filesystem that hands the rename the same inode number back cannot be told
            // apart this way. Skipping is honest and passing would not be -- but a SILENT
            // skip that reports green is the failure this crate keeps writing rules about,
            // so it says so and the arm's own comment tells a reader to look for this line.
            eprintln!("SKIPPED a_file_replaced_with_its_old_size_and_mtime_is_caught_by_the_inode: {} reused inode {old_ino}", d.display());
            let _ = std::fs::remove_dir_all(&d);
            return;
        }

        let c2 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let second = scan(&tree, &opts(Some(c2))).unwrap();
        assert_eq!(second.hashed, 1, "the replaced file is read again");
        assert_ne!(
            second.hashes["a.txt"], first.hashes["a.txt"],
            "and the digest is of the new content"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **The limit, pinned so nobody can claim it away.** A writer that opens the file,
    /// overwrites bytes without changing its length, and restores the modification time
    /// leaves size, mtime and inode all identical, and `-hashcache` then reports the digest
    /// of content that is no longer on disk. That is true of every mtime-keyed cache --
    /// rclone's `hasher` overlay included -- and it is why the flag is opt-in rather than
    /// the default: `scan -sha256` is often run to catch exactly this.
    ///
    /// This arm asserts the WRONG answer on purpose. If someone later makes the cache
    /// content-aware, it fails, and the right response is to rewrite it rather than to
    /// discover the change by reading the docs.
    #[test]
    #[cfg(unix)]
    fn an_in_place_rewrite_that_restores_the_mtime_is_served_stale() {
        use std::os::unix::fs::MetadataExt;
        let d = fixture("stale");
        let tree = crate::tree::LocalTree::new(&d.join("tree"));
        let root = d.join("tree").display().to_string();
        let target = d.join("tree").join("a.txt");

        let c1 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let first = scan(&tree, &opts(Some(c1.clone()))).unwrap();
        c1.lock().unwrap().save(true).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        let (mtime, mtime_ns) = (before.mtime(), before.mtime_nsec());

        // written THROUGH the same inode -- no rename, same length
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&target)
                .unwrap();
            f.write_all(b"ALPHA").unwrap();
        }
        set_mtime(&target, mtime, mtime_ns);
        let after = std::fs::metadata(&target).unwrap();
        assert_eq!(
            (after.len(), after.mtime(), after.mtime_nsec(), after.ino()),
            (before.len(), mtime, mtime_ns, before.ino()),
            "all three fields restored"
        );

        let c2 = std::sync::Arc::new(Mutex::new(crate::hashcache::HashCache::open(
            &d.join("state"),
            &root,
            "sha256",
        )));
        let second = scan(&tree, &opts(Some(c2))).unwrap();
        assert_eq!(
            second.hashed, 0,
            "nothing looked changed, so nothing was read"
        );
        assert_eq!(
            second.hashes["a.txt"], first.hashes["a.txt"],
            "and the digest reported is STALE -- this is the documented limit"
        );

        // The remedy, and the control that shows it works: without the cache the same tree
        // reports the real digest. So `-hashcache` is the thing that made the answer wrong,
        // not the scanner.
        let truth = scan(&tree, &opts(None)).unwrap();
        assert_ne!(
            truth.hashes["a.txt"], first.hashes["a.txt"],
            "a scan without -hashcache still sees the tampering"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Restores a modification time, the way a tool that preserves times does. The same
    /// `File::set_times` the local tree's own `set_metadata` uses.
    #[cfg(unix)]
    fn set_mtime(path: &std::path::Path, secs: i64, nanos: i64) {
        let t = UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos as u32);
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
            .unwrap();
    }
}
