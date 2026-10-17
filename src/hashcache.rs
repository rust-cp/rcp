//! A digest cache, so a second `scan -sha256` over an unchanged tree does not read every
//! byte again. After rclone's `hasher` overlay: remember what a file hashed to alongside
//! the cheap facts that say whether it is still the same file, and reuse the digest when
//! all of them agree.
//!
//! # What "still the same file" means here, and what it cannot mean
//!
//! Three fields have to agree: **size**, **mtime** to the nanosecond, and **inode**.
//! rclone's overlay uses size and modification time alone, because most of its backends
//! have no inode to offer; a local tree does, and the inode is what separates a file that
//! was rewritten in place from one that was replaced by a rename -- the second changes its
//! inode even when the writer restores size and mtime afterwards, which `cp -p`, `rsync
//! --times`, `tar -x` and every editor that writes a temp file and renames it all do.
//!
//! **It is still not a content check, and a cache hit is not a hash.** A writer that opens
//! the file, overwrites bytes without changing its length, and then restores the old mtime
//! leaves all three fields identical and this cache returns the digest of content that is
//! no longer there. That is inherent to every mtime-keyed cache, rclone's included, and the
//! reason the cache is **off unless asked for** (`-hashcache`) rather than on by default:
//! the whole point of `scan -sha256` is often to catch exactly that kind of tampering, and
//! a tool that silently answered from a cache would report the content it was asked to
//! check rather than the content on disk.
//!
//! `scan -newid` carries whatever digests the run produced into the catalog's digest
//! column, cache hits included, so a saved index inherits exactly the property above. That
//! is not a second hazard: no decision reads that column. `sync` skips on size, mtime and
//! what the destination shows, and the only place a stored digest travels is a detected
//! MOVE, where the file is the same inode with the same size and mtime and the digest was
//! not going to differ. Checked rather than assumed -- `plan.rs` is where it is decided.
//!
//! # One file per (root, algorithm)
//!
//! The catalog's digest column held a mixture of algorithms until a measurement found one,
//! and the fix there was to record which algorithm the catalog uses. The same trap is
//! sharper here, because a cache is consulted rather than printed: a BLAKE3 digest served
//! to a SHA-256 scan is a wrong answer that looks like a right one. So the algorithm is in
//! the file's name AND in its header, and a header that disagrees discards the file rather
//! than merging it.
//!
//! The root is in the header for the same reason one level up: entries are keyed by the
//! path *relative* to the scanned root, so two roots sharing a cache would answer each
//! other's questions. The file name carries a digest of the root only to keep the names
//! apart; the header is what decides.
//!
//! The root is the endpoint as `Endpoint::display` renders it, which carries a USER for
//! `ssh://` and `sftp://` and no password for anything -- the DAV and HTTPS renderings drop
//! userinfo outright. So the worst that lands in this file is a username, beside a list of
//! every path under the root, which is the same exposure the catalog's own index has and is
//! why both are 0600 in a 0700 directory. It also means `/data` and `/data/` are two
//! caches: a miss, never a wrong answer.
//!
//! # A cache never fails a scan
//!
//! Unreadable, truncated, from a future version, malformed on line 4000 -- every one of
//! those is "no cached digests", not an error. The cost of a miss is a re-read; the cost of
//! refusing to scan is the whole command. A malformed line is skipped rather than
//! half-parsed, because a half-parsed line is how a wrong digest would get in.
//!
//! Two scans of one root at the same time are last-writer-wins, and that is deliberate
//! rather than unconsidered: the write goes to a temporary sibling and is renamed, so a
//! reader sees one whole file or the other and never a half of each. The loser's new
//! entries are lost and have to be recomputed next time, which costs a read. What cannot
//! happen is a wrong digest, which is the only outcome worth locking for.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::catalog::{escape, unescape};

const HEADER: &str = "#rcp-hashcache 1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cached {
    size: u64,
    mtime_ns: i128,
    ino: u64,
    digest: String,
}

pub struct HashCache {
    path: PathBuf,
    algo: String,
    root: String,
    entries: BTreeMap<String, Cached>,
    /// Paths this run asked about, so a full unfiltered scan can drop what is gone.
    seen: BTreeSet<String>,
    hits: usize,
    misses: usize,
}

/// A digest of the root string, for the file name alone. FNV-1a rather than the crate's own
/// hashers because it has to be the same number in every process -- `RandomState` is seeded
/// per run, which would give one root a new cache file every time.
fn name_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl std::fmt::Debug for HashCache {
    /// Counts, never contents. The entries are a list of every path under the root and what
    /// its bytes hash to -- the same map of somebody's filesystem the catalog opens 0600 to
    /// keep off a shared host, and `-debug` prints this struct.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashCache")
            .field("algo", &self.algo)
            .field("entries", &self.entries.len())
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .finish()
    }
}

impl HashCache {
    /// The cache for one root and one algorithm, loaded if it is there and usable.
    ///
    /// `dir` is the catalog root: the cache is state about a tree this user has scanned,
    /// which is what that directory already holds, and it inherits its 0700.
    pub fn open(dir: &Path, root: &str, algo: &str) -> HashCache {
        let path = dir
            .join("hashes")
            .join(format!("{algo}-{:016x}.tsv", name_hash(root)));
        let entries = Self::load(&path, root, algo).unwrap_or_default();
        HashCache {
            path,
            algo: algo.to_string(),
            root: root.to_string(),
            entries,
            seen: BTreeSet::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// `None` for anything that is not a cache of this root in this algorithm. Never an
    /// error: see the module header.
    fn load(path: &Path, root: &str, algo: &str) -> Option<BTreeMap<String, Cached>> {
        #[cfg(unix)]
        let file = std::fs::File::open(path).ok()?;
        #[cfg(windows)]
        let file = crate::windows::PrivateOptions::new()
            .read(true)
            .open(path)
            .ok()?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        match lines.next() {
            Some(Ok(h)) if h == HEADER => {}
            _ => return None,
        }
        let mut entries = BTreeMap::new();
        let (mut algo_ok, mut root_ok) = (false, false);
        for line in lines {
            let Ok(line) = line else { return None };
            if let Some(v) = line.strip_prefix("algo\t") {
                // A mismatch is not a reason to keep reading: every entry below it is in the
                // wrong algorithm, and serving one is the defect this file is shaped around.
                if v != algo {
                    return None;
                }
                algo_ok = true;
                continue;
            }
            if let Some(v) = line.strip_prefix("root\t") {
                if unescape(v) != root {
                    return None;
                }
                root_ok = true;
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 5 {
                continue; // skipped, not half-parsed
            }
            let (Ok(size), Ok(mtime_ns), Ok(ino)) = (f[1].parse(), f[2].parse(), f[3].parse())
            else {
                continue;
            };
            if f[4].is_empty() {
                continue;
            }
            entries.insert(
                unescape(f[0]),
                Cached {
                    size,
                    mtime_ns,
                    ino,
                    digest: f[4].to_string(),
                },
            );
        }
        // A cache with no header lines at all is a file that happens to start with our
        // banner. Both have to be there and both have to agree.
        (algo_ok && root_ok).then_some(entries)
    }

    /// A store that reports no modification time leaves the cache nothing to detect a change
    /// with, and the three-field check silently collapses to size alone.
    ///
    /// This is not hypothetical and it is not only about mtime. Every adapter here that has
    /// no real inode synthesizes one as `fnv64(path)` -- s3, dav, https, oci, and hdfs when
    /// the namenode withholds `fileId`. That is deliberately STABLE across runs, which is
    /// right for `sync`'s move detection and worthless here: a field that is a function of
    /// the key the entry is already filed under cannot disagree with itself, so on those
    /// stores the check is size and mtime, exactly rclone's. `oci://` goes one step further
    /// and reports `mtime_ns: 0` for everything, at which point it is size alone -- and
    /// "same length" is not a reason to believe two blobs are the same blob.
    ///
    /// So a zero mtime is refused rather than served. A local file really stamped at the
    /// epoch is refused with it; the cost of that is one re-read.
    fn usable(mtime_ns: i128) -> bool {
        mtime_ns != 0
    }

    /// The remembered digest for a file whose size, mtime and inode all still agree.
    pub fn lookup(&mut self, rel: &str, size: u64, mtime_ns: i128, ino: u64) -> Option<String> {
        self.seen.insert(rel.to_string());
        if !Self::usable(mtime_ns) {
            self.misses += 1;
            return None;
        }
        match self.entries.get(rel) {
            Some(c) if c.size == size && c.mtime_ns == mtime_ns && c.ino == ino => {
                self.hits += 1;
                Some(c.digest.clone())
            }
            _ => {
                self.misses += 1;
                None
            }
        }
    }

    /// Records a digest this run computed. An empty digest is not recorded -- that is what a
    /// failed read leaves behind, and caching it would make one unreadable moment permanent.
    pub fn insert(&mut self, rel: &str, size: u64, mtime_ns: i128, ino: u64, digest: &str) {
        // An entry `lookup` can never serve is pure growth: written every run, read never.
        if digest.is_empty() || !Self::usable(mtime_ns) {
            return;
        }
        self.seen.insert(rel.to_string());
        self.entries.insert(
            rel.to_string(),
            Cached {
                size,
                mtime_ns,
                ino,
                digest: digest.to_string(),
            },
        );
    }

    /// Hits and misses this run, for the line `scan` prints and for the arms that prove the
    /// cache was consulted rather than assumed to have been.
    pub fn stats(&self) -> (usize, usize) {
        (self.hits, self.misses)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes the cache back.
    ///
    /// `complete` says the run walked the whole root with no filter and no depth limit, in
    /// which case a path the run never asked about is a path that is gone and is dropped.
    /// A FILTERED run must pass `false`: `-type f` or `-maxdepth 1` means most of the tree
    /// was never looked at, and pruning on that would throw away the cache for everything
    /// outside the filter -- the second run pays for the first run's narrowness.
    ///
    /// Written to a temporary sibling and renamed, so a run killed here leaves the previous
    /// cache rather than a truncated one. 0600 for the same reason the catalog is: the
    /// contents are a map of a filesystem.
    pub fn save(&mut self, complete: bool) -> io::Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        if complete {
            self.entries.retain(|p, _| self.seen.contains(p));
        }
        let Some(dir) = self.path.parent() else {
            return Ok(());
        };
        #[cfg(unix)]
        if !dir.is_dir() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        #[cfg(windows)]
        let held = crate::windows::Root::private_dir(dir)?;
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        #[cfg(unix)]
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        #[cfg(windows)]
        let mut out = crate::windows::PrivateOptions::new()
            .write(true)
            .delete_access(true)
            .create_new(true)
            .open(&tmp)?;
        let mut buf = String::with_capacity(64 * self.entries.len() + 128);
        buf.push_str(HEADER);
        buf.push('\n');
        buf.push_str(&format!("algo\t{}\n", self.algo));
        buf.push_str(&format!("root\t{}\n", escape(&self.root)));
        for (p, c) in &self.entries {
            buf.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                escape(p),
                c.size,
                c.mtime_ns,
                c.ino,
                c.digest
            ));
        }
        out.write_all(buf.as_bytes())?;
        out.flush()?;
        #[cfg(windows)]
        {
            out.sync_all()?;
            let name = self
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| io::Error::other("cache has no Unicode filename"))?;
            let result = held.rename_file(&out, name).and_then(|_| held.flush());
            drop(out);
            if result.is_err() {
                if let Some(name) = tmp.file_name().and_then(|n| n.to_str()) {
                    let _ = held.delete(name, false);
                }
            }
            result
        }
        #[cfg(unix)]
        drop(out);
        #[cfg(unix)]
        match std::fs::rename(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rcp-hashcache-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_digest_survives_the_round_trip_and_is_served_back() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "sha256");
        assert_eq!(c.lookup("a.txt", 10, 7, 99), None, "nothing is cached yet");
        c.insert("a.txt", 10, 7, 99, "abcd");
        c.save(true).unwrap();

        let mut again = HashCache::open(&d, "/data", "sha256");
        assert_eq!(again.lookup("a.txt", 10, 7, 99), Some("abcd".to_string()));
        assert_eq!(again.stats(), (1, 0));
    }

    /// The control for the arm above: the same three fields, one of them moved, must MISS.
    /// Without this an `entries.get(rel)` that ignored size, mtime and inode entirely would
    /// pass the round-trip arm and serve a stale digest for every changed file.
    #[test]
    fn a_file_that_changed_in_any_of_the_three_fields_misses() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "sha256");
        c.insert("a.txt", 10, 7, 99, "abcd");
        c.save(false).unwrap();

        for (size, mtime, ino, what) in [
            (11u64, 7i128, 99u64, "size"),
            (10, 8, 99, "mtime"),
            (10, 7, 100, "inode"),
        ] {
            let mut again = HashCache::open(&d, "/data", "sha256");
            assert_eq!(
                again.lookup("a.txt", size, mtime, ino),
                None,
                "a changed {what} must not be a hit"
            );
            assert_eq!(again.stats(), (0, 1));
        }
        // and the unchanged triple still hits, so the arm above is not passing because the
        // cache is simply empty
        let mut same = HashCache::open(&d, "/data", "sha256");
        assert_eq!(same.lookup("a.txt", 10, 7, 99), Some("abcd".to_string()));
    }

    #[test]
    fn a_cache_written_in_one_algorithm_is_not_served_to_another() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "blake3");
        c.insert("a.txt", 10, 7, 99, "b3digest");
        c.save(true).unwrap();

        let mut wrong = HashCache::open(&d, "/data", "sha256");
        assert_eq!(
            wrong.lookup("a.txt", 10, 7, 99),
            None,
            "a BLAKE3 digest must never answer a SHA-256 scan"
        );
        // the right algorithm still gets it
        let mut right = HashCache::open(&d, "/data", "blake3");
        assert_eq!(
            right.lookup("a.txt", 10, 7, 99),
            Some("b3digest".to_string())
        );
    }

    /// Two roots must not answer each other. The file name is a digest of the root, so this
    /// would ordinarily be two files -- the arm forces the collision by handing the SECOND
    /// root the FIRST root's file, which is what a name collision would look like.
    #[test]
    fn a_cache_of_one_root_is_not_served_to_another() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data/one", "sha256");
        c.insert("a.txt", 10, 7, 99, "abcd");
        c.save(true).unwrap();
        let written = d
            .join("hashes")
            .join(format!("sha256-{:016x}.tsv", name_hash("/data/one")));
        let collided = d
            .join("hashes")
            .join(format!("sha256-{:016x}.tsv", name_hash("/data/two")));
        std::fs::copy(&written, &collided).unwrap();

        let mut other = HashCache::open(&d, "/data/two", "sha256");
        assert_eq!(
            other.lookup("a.txt", 10, 7, 99),
            None,
            "a cache naming another root must be discarded"
        );
        assert!(other.is_empty());
    }

    #[test]
    fn a_damaged_cache_is_a_miss_and_not_an_error() {
        let d = dir();
        let path = d
            .join("hashes")
            .join(format!("sha256-{:016x}.tsv", name_hash("/data")));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for body in [
            "".to_string(),
            "garbage".to_string(),
            format!("{HEADER}\n"),               // no header lines
            format!("{HEADER}\nalgo\tsha256\n"), // no root
            format!("{HEADER}\nalgo\tsha256\nroot\t/data\na.txt\tten\t7\t99\tabcd\n"), // unparsable size
            format!("{HEADER}\nalgo\tsha256\nroot\t/data\na.txt\t10\t7\t99\n"),        // short line
            format!("{HEADER}\nalgo\tsha256\nroot\t/data\na.txt\t10\t7\t99\t\n"), // empty digest
        ] {
            std::fs::write(&path, &body).unwrap();
            let mut c = HashCache::open(&d, "/data", "sha256");
            assert_eq!(
                c.lookup("a.txt", 10, 7, 99),
                None,
                "damaged cache {body:?} must not answer"
            );
        }
        // control: the same file, well formed, does answer -- so the arm above is measuring
        // the damage rather than a path that never reads anything
        std::fs::write(
            &path,
            format!("{HEADER}\nalgo\tsha256\nroot\t/data\na.txt\t10\t7\t99\tabcd\n"),
        )
        .unwrap();
        let mut c = HashCache::open(&d, "/data", "sha256");
        assert_eq!(c.lookup("a.txt", 10, 7, 99), Some("abcd".to_string()));
    }

    #[test]
    fn a_complete_run_drops_what_is_gone_and_a_filtered_one_keeps_it() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "sha256");
        c.insert("a.txt", 1, 1, 1, "aa");
        c.insert("b.txt", 2, 2, 2, "bb");
        c.save(false).unwrap();

        // a filtered run that only looked at a.txt must not evict b.txt
        let mut filtered = HashCache::open(&d, "/data", "sha256");
        assert_eq!(filtered.lookup("a.txt", 1, 1, 1), Some("aa".to_string()));
        filtered.save(false).unwrap();
        let mut after = HashCache::open(&d, "/data", "sha256");
        assert_eq!(
            after.lookup("b.txt", 2, 2, 2),
            Some("bb".to_string()),
            "a filtered run must keep what it did not look at"
        );

        // a complete run that only saw a.txt means b.txt is gone
        let mut complete = HashCache::open(&d, "/data", "sha256");
        assert_eq!(complete.lookup("a.txt", 1, 1, 1), Some("aa".to_string()));
        complete.save(true).unwrap();
        let mut pruned = HashCache::open(&d, "/data", "sha256");
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned.lookup("b.txt", 2, 2, 2), None);
    }

    #[test]
    fn a_path_with_a_tab_or_a_newline_survives_the_round_trip() {
        let d = dir();
        let nasty = "dir/a\tb\nc\\d.txt";
        let mut c = HashCache::open(&d, "/data", "sha256");
        c.insert(nasty, 10, 7, 99, "abcd");
        c.save(true).unwrap();
        let mut again = HashCache::open(&d, "/data", "sha256");
        assert_eq!(again.len(), 1, "one entry, not two halves of a split line");
        assert_eq!(again.lookup(nasty, 10, 7, 99), Some("abcd".to_string()));
    }

    #[test]
    fn a_failed_read_is_not_cached() {
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "sha256");
        c.insert("a.txt", 10, 7, 99, "");
        assert!(
            c.is_empty(),
            "an empty digest is what a failed read leaves; caching it makes the failure permanent"
        );
    }

    /// A store with no modification time (`oci://` reports zero for every blob) leaves size
    /// as the only field that could disagree, and two blobs of the same length are not the
    /// same blob. Refused on the way in and on the way out, so neither an old cache nor a
    /// new one can serve one.
    #[test]
    fn a_tree_that_reports_no_modification_time_gets_no_hits() {
        let d = dir();
        let mut c = HashCache::open(&d, "oci://reg/app", "sha256");
        c.insert("blob/a", 10, 0, 7, "abcd");
        assert!(
            c.is_empty(),
            "an entry that could only ever be matched on size is not stored"
        );

        // and even if one were there -- from a version of this file without the guard --
        // it is not served
        let path = d
            .join("hashes")
            .join(format!("sha256-{:016x}.tsv", name_hash("oci://reg/app")));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("{HEADER}\nalgo\tsha256\nroot\toci://reg/app\nblob/a\t10\t0\t7\tabcd\n"),
        )
        .unwrap();
        let mut old = HashCache::open(&d, "oci://reg/app", "sha256");
        assert_eq!(old.len(), 1, "the entry is in the file");
        assert_eq!(
            old.lookup("blob/a", 10, 0, 7),
            None,
            "and is still not served"
        );

        // control: the same entry with a real mtime is served, so the arm is measuring the
        // zero rather than a lookup that never matches anything
        std::fs::write(
            &path,
            format!("{HEADER}\nalgo\tsha256\nroot\toci://reg/app\nblob/a\t10\t5\t7\tabcd\n"),
        )
        .unwrap();
        let mut ok = HashCache::open(&d, "oci://reg/app", "sha256");
        assert_eq!(ok.lookup("blob/a", 10, 5, 7), Some("abcd".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn the_cache_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let mut c = HashCache::open(&d, "/data", "sha256");
        c.insert("a.txt", 10, 7, 99, "abcd");
        c.save(true).unwrap();
        let path = d
            .join("hashes")
            .join(format!("sha256-{:016x}.tsv", name_hash("/data")));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the cache lists every path under the root");
    }
}
