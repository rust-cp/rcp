//! `S3Tree`: the `Tree` port over a bucket. Keys under the endpoint's prefix are the tree;
//! `dir/` zero-byte objects are directories (synthesized when only their children exist);
//! POSIX metadata rides in user metadata the way s3fs writes it (`mtime`, `mode`, `uid`,
//! `gid`), and a symlink is an object whose body is its target and whose mode says so.
//!
//! Uploads stream: the executor declares the size up front (`reserve`), so a file at most
//! `SINGLE_PUT_MAX` long goes out as one `PUT` with a known `Content-Length`, and a larger
//! one as a multipart upload whose parts are opened as the bytes arrive. Nothing is buffered
//! beyond the HTTP client's own window, whatever the object size.

use crate::ports::KernelFileDescriptor as RawFd;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::config::{self, Resolved};
use super::sigv4::{self, EMPTY_SHA256, UNSIGNED_PAYLOAD};
use super::xml;
use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::net::http::{percent_encode, Connection, Response};
use crate::time;
use crate::tree::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree, ZEROS,
};

/// Objects up to this size go as one `PUT`; above it, multipart with parts of at least this.
pub const SINGLE_PUT_MAX: u64 = 64 << 20;
const MAX_PARTS: u64 = 10_000;
const LIST_PAGE: usize = 1000;
const ATTEMPTS: usize = 4;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// Connections to one endpoint plus what every request needs to be signed.
pub struct Pool {
    resolved: Resolved,
    idle: Mutex<Vec<Connection>>,
    log: Arc<dyn crate::ports::Log>,
}

impl Pool {
    fn take(&self) -> io::Result<Connection> {
        if let Some(c) = self.idle.lock().unwrap().pop() {
            return Ok(c);
        }
        Connection::connect(&self.resolved.target)
    }

    fn give(&self, c: Connection) {
        if c.idle() {
            self.idle.lock().unwrap().push(c);
        }
    }

    /// The request path for a key: `/bucket/key` path-style, `/key` virtual-hosted.
    fn path(&self, key: &str) -> String {
        let enc = percent_encode(key, true);
        if self.resolved.path_style {
            format!("/{}/{enc}", self.resolved.bucket)
        } else {
            format!("/{enc}")
        }
    }

    /// The signed request line target and headers.
    fn prepare(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        mut headers: Vec<(String, String)>,
        payload_hash: &str,
    ) -> (String, Vec<(String, String)>) {
        let path = self.path(key);
        headers.push(("host".into(), self.resolved.target.host_header()));
        if let Some(creds) = &self.resolved.creds {
            sigv4::sign(
                creds,
                &self.resolved.region,
                &time::amz_date(time::now_secs()),
                method,
                &path,
                query,
                &mut headers,
                payload_hash,
            );
        }
        let target = if query.is_empty() {
            path
        } else {
            format!("{path}?{}", sigv4::canonical_query(query))
        };
        (target, headers)
    }

    /// A buffered request, retried on transport failure and on the service's transient
    /// statuses. The response is returned whatever its status; `check` classifies it.
    fn request(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> io::Result<Response> {
        let hash = if body.is_empty() {
            EMPTY_SHA256.to_string()
        } else {
            sigv4::sha256_hex(body)
        };
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(200 << attempt));
            }
            let (target, hs) = self.prepare(method, key, query, headers.clone(), &hash);
            let mut conn = match self.take() {
                Ok(c) => c,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            let outcome = conn.request(method, &target, &hs, body);
            match &outcome {
                Ok(r) => crate::debug!(
                    self.log,
                    "s3 {method} {key} (attempt {}): {}",
                    attempt + 1,
                    r.status
                ),
                Err(e) => {
                    crate::debug!(self.log, "s3 {method} {key} (attempt {}): {e}", attempt + 1)
                }
            }
            match outcome {
                Ok(r)
                    if r.status == 429
                        || r.status == 500
                        || r.status == 502
                        || r.status == 503
                        || r.status == 504 =>
                {
                    self.give(conn);
                    last = Some(error_of(&r, key));
                }
                Ok(r) => {
                    self.give(conn);
                    return Ok(r);
                }
                Err(e) => last = Some(e), // the connection is dropped; a fresh one next time
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no attempt made")))
    }

    fn head(&self, key: &str) -> io::Result<Option<Response>> {
        let r = self.request("HEAD", key, &[], Vec::new(), &[])?;
        match r.status {
            404 => Ok(None),
            _ => check(r, key).map(Some),
        }
    }
}

pub(crate) fn kind_of_status(status: u16) -> io::ErrorKind {
    match status {
        404 => io::ErrorKind::NotFound,
        401 | 403 => io::ErrorKind::PermissionDenied,
        400 | 411 | 412 | 416 => io::ErrorKind::InvalidInput,
        409 => io::ErrorKind::AlreadyExists,
        501 => io::ErrorKind::Unsupported,
        // A throttled or overloaded service is the one failure in this list worth
        // retrying, and without this arm it arrives as the same `io` as a missing bucket.
        // Every sibling adapter needs the same mapping, and fixing one does not fix the
        // others: the arm that measures it starts a REGISTRY stand-in, so reverting the OCI
        // map turns it red while S3 and HDFS stay green either way.
        429 | 502 | 503 | 504 => io::ErrorKind::ResourceBusy,
        _ => io::ErrorKind::Other,
    }
}

fn error_of(r: &Response, what: &str) -> io::Error {
    let text = String::from_utf8_lossy(&r.body);
    let detail = match (xml::value(&text, "Code"), xml::value(&text, "Message")) {
        (Some(c), Some(m)) => format!("{c}: {m}"),
        (Some(c), None) => c,
        _ => format!("HTTP {}", r.status),
    };
    io::Error::new(kind_of_status(r.status), format!("{what}: {detail}"))
}

fn check(r: Response, what: &str) -> io::Result<Response> {
    if r.ok() {
        Ok(r)
    } else {
        Err(error_of(&r, what))
    }
}

/// What rcp stores beside an object.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Meta {
    mtime_ns: Option<i128>,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// Every user metadata pair, for a metadata-replacing copy to carry forward.
    all: BTreeMap<String, String>,
}

impl Meta {
    fn from_headers(headers: &[(String, String)]) -> Meta {
        let mut m = Meta::default();
        for (k, v) in headers {
            let k = k.to_ascii_lowercase();
            if let Some(name) = k.strip_prefix("x-amz-meta-") {
                m.all.insert(name.to_string(), v.clone());
            }
        }
        m.mtime_ns = m.all.get("mtime").and_then(|v| parse_mtime(v));
        m.mode = m.all.get("mode").and_then(|v| v.parse().ok());
        m.uid = m.all.get("uid").and_then(|v| v.parse().ok());
        m.gid = m.all.get("gid").and_then(|v| v.parse().ok());
        m
    }

    fn headers(&self) -> Vec<(String, String)> {
        self.all
            .iter()
            .map(|(k, v)| (format!("x-amz-meta-{k}"), v.clone()))
            .collect()
    }

    fn set(
        &mut self,
        mtime_ns: Option<i128>,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) {
        if let Some(t) = mtime_ns {
            self.mtime_ns = Some(t);
            self.all.insert("mtime".into(), format_mtime(t));
        }
        if let Some(m) = mode {
            self.mode = Some(m);
            self.all.insert("mode".into(), m.to_string());
        }
        if let Some(u) = uid {
            self.uid = Some(u);
            self.all.insert("uid".into(), u.to_string());
        }
        if let Some(g) = gid {
            self.gid = Some(g);
            self.all.insert("gid".into(), g.to_string());
        }
    }
}

/// `seconds.nanoseconds`, which s3fs and rclone both read as a decimal number of seconds.
fn format_mtime(ns: i128) -> String {
    let neg = ns < 0;
    let abs = ns.unsigned_abs();
    let secs = abs / 1_000_000_000;
    let frac = abs % 1_000_000_000;
    if neg {
        format!("-{secs}.{frac:09}")
    } else {
        format!("{secs}.{frac:09}")
    }
}

fn parse_mtime(text: &str) -> Option<i128> {
    let neg = text.starts_with('-');
    let text = text.strip_prefix('-').unwrap_or(text);
    let (secs, frac) = match text.split_once('.') {
        Some((s, f)) => (s, f),
        None => (text, ""),
    };
    let secs: i128 = secs.parse().ok()?;
    let mut nanos: i128 = 0;
    let mut scale: i128 = 100_000_000;
    for c in frac.chars().take(9) {
        nanos += c.to_digit(10)? as i128 * scale;
        scale /= 10;
    }
    let mag = secs.unsigned_abs() * 1_000_000_000 + nanos as u128;
    let mag = i128::try_from(mag).ok()?;
    Some(if neg { -mag } else { mag })
}

fn full_mode(kind: Kind, mode: u32) -> u32 {
    let bits = match kind {
        Kind::File => S_IFREG,
        Kind::Dir => S_IFDIR,
        Kind::Symlink => S_IFLNK,
    };
    bits | (mode & 0o7777)
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// One object as a listing reports it.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key: String,
    pub size: u64,
    pub mtime_ns: i128,
}

pub struct S3Tree {
    pool: Arc<Pool>,
    /// `""` at the bucket root, otherwise `a/b/`.
    prefix: String,
    display: PathBuf,
}

impl S3Tree {
    /// Opens `bucket` at `sub` (the path after the bucket) and confirms it is reachable with
    /// one listing request, so a wrong endpoint, credential or bucket fails here.
    pub fn connect(
        bucket: &str,
        sub: &Path,
        _create: bool,
        options: &config::S3Options,
        log: Arc<dyn crate::ports::Log>,
    ) -> io::Result<S3Tree> {
        let resolved = config::resolve(bucket, options)?;
        let pool = Arc::new(Pool {
            resolved,
            idle: Mutex::new(Vec::new()),
            log,
        });
        let mut prefix = sub
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        if !prefix.is_empty() {
            prefix.push('/');
        }
        let display = PathBuf::from(format!("s3://{bucket}/{prefix}"));
        let t = S3Tree {
            pool,
            prefix,
            display,
        };
        t.list_page(&t.prefix, None, 1)
            .map_err(|e| io::Error::new(e.kind(), format!("s3://{bucket}: {e}")))?;
        Ok(t)
    }

    fn key(&self, rel: &str) -> String {
        if rel == "." {
            self.prefix.trim_end_matches('/').to_string()
        } else {
            format!("{}{rel}", self.prefix)
        }
    }

    fn dir_key(&self, rel: &str) -> String {
        if rel == "." {
            self.prefix.clone()
        } else {
            format!("{}{rel}/", self.prefix)
        }
    }

    /// One page of `ListObjectsV2`.
    fn list_page(
        &self,
        prefix: &str,
        token: Option<&str>,
        max: usize,
    ) -> io::Result<(Vec<KeyInfo>, Option<String>)> {
        let mut q = vec![
            ("list-type".to_string(), "2".to_string()),
            ("max-keys".to_string(), max.to_string()),
        ];
        if !prefix.is_empty() {
            q.push(("prefix".into(), prefix.to_string()));
        }
        if let Some(t) = token {
            q.push(("continuation-token".into(), t.to_string()));
        }
        let r = check(self.pool.request("GET", "", &q, Vec::new(), &[])?, "list")?;
        let text = String::from_utf8_lossy(&r.body);
        let mut out = Vec::new();
        for c in xml::blocks(&text, "Contents") {
            let Some(key) = xml::value(c, "Key") else {
                continue;
            };
            let size = xml::value(c, "Size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mtime_ns = xml::value(c, "LastModified")
                .and_then(|s| time::parse_rfc3339(&s))
                .unwrap_or(0);
            out.push(KeyInfo {
                key,
                size,
                mtime_ns,
            });
        }
        let next = if xml::value(&text, "IsTruncated").as_deref() == Some("true") {
            match xml::value(&text, "NextContinuationToken").filter(|t| !t.is_empty()) {
                Some(t) => Some(t),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "S3 listing is truncated and carries no continuation token, so it is not a complete listing",
                    ))
                }
            }
        } else {
            None
        };
        Ok((out, next))
    }

    fn list_all(&self, prefix: &str) -> io::Result<Vec<KeyInfo>> {
        let mut all = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let (mut page, next) = self.list_page(prefix, token.as_deref(), LIST_PAGE)?;
            all.append(&mut page);
            match next {
                Some(t) => token = Some(t),
                None => return Ok(all),
            }
        }
    }

    /// Reads an object's metadata; `kind` is what the key's shape says it is, and the mode
    /// can turn a file into a symlink.
    fn item_from_head(
        &self,
        rel: &str,
        kind: Kind,
        r: &Response,
        link_target: Option<PathBuf>,
    ) -> Item {
        let meta = Meta::from_headers(&r.headers);
        let size = if kind == Kind::File {
            r.header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        } else {
            0
        };
        let mtime_ns = meta
            .mtime_ns
            .or_else(|| {
                r.header("last-modified")
                    .and_then(time::parse_http_date)
                    .map(|s| s as i128 * 1_000_000_000)
            })
            .unwrap_or(0);
        let mode = meta.mode.map(|m| m & 0o7777).unwrap_or(match kind {
            Kind::Dir => 0o755,
            Kind::Symlink => 0o777,
            Kind::File => 0o644,
        });
        Item {
            rel: rel.to_string(),
            kind,
            size,
            mtime_ns,
            atime_ns: mtime_ns,
            mode,
            uid: meta.uid.unwrap_or(0),
            gid: meta.gid.unwrap_or(0),
            dev: 0,
            ino: fnv64(&self.key(rel)),
            nlink: 1,
            blocks: size,
            link_target,
        }
    }

    fn get_body(&self, key: &str) -> io::Result<Vec<u8>> {
        check(self.pool.request("GET", key, &[], Vec::new(), &[])?, key).map(|r| r.body)
    }

    /// HEAD one entry and build its item, following the symlink convention.
    fn describe(&self, rel: &str, kind: Kind) -> io::Result<Option<Item>> {
        let key = if kind == Kind::Dir {
            self.dir_key(rel)
        } else {
            self.key(rel)
        };
        let Some(r) = self.pool.head(&key)? else {
            return Ok(None);
        };
        let meta = Meta::from_headers(&r.headers);
        if kind == Kind::File && meta.mode.is_some_and(|m| m & S_IFMT == S_IFLNK) {
            let target = String::from_utf8_lossy(&self.get_body(&key)?).to_string();
            return Ok(Some(self.item_from_head(
                rel,
                Kind::Symlink,
                &r,
                Some(PathBuf::from(target)),
            )));
        }
        Ok(Some(self.item_from_head(rel, kind, &r, None)))
    }

    fn synthesized_dir(&self, rel: &str) -> Item {
        Item {
            rel: rel.to_string(),
            kind: Kind::Dir,
            size: 0,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: fnv64(&self.dir_key(rel)),
            nlink: 1,
            blocks: 0,
            link_target: None,
        }
    }

    fn put(&self, key: &str, meta: &Meta, body: &[u8]) -> io::Result<()> {
        let mut headers = meta.headers();
        headers.push(("content-type".into(), "application/octet-stream".into()));
        check(self.pool.request("PUT", key, &[], headers, body)?, key).map(|_| ())
    }

    /// A server-side copy of `from` onto `to`, with `meta` replacing the metadata when given.
    fn copy_object(&self, from: &str, to: &str, meta: Option<&Meta>) -> io::Result<()> {
        let mut headers = vec![(
            "x-amz-copy-source".to_string(),
            format!(
                "/{}/{}",
                self.pool.resolved.bucket,
                percent_encode(from, true)
            ),
        )];
        match meta {
            Some(m) => {
                headers.push(("x-amz-metadata-directive".into(), "REPLACE".into()));
                headers.push(("content-type".into(), "application/octet-stream".into()));
                headers.extend(m.headers());
            }
            None => headers.push(("x-amz-metadata-directive".into(), "COPY".into())),
        }
        let r = check(self.pool.request("PUT", to, &[], headers, &[])?, to)?;
        // a copy can fail after a 200 status: the error then comes in the body
        let text = String::from_utf8_lossy(&r.body);
        if text.contains("<Error>") {
            return Err(io::Error::other(format!(
                "{to}: {}",
                xml::value(&text, "Message").unwrap_or_else(|| "copy failed".into())
            )));
        }
        Ok(())
    }
}

fn now_ns() -> i128 {
    filter::now_ns()
}

fn parents_of(rel: &str) -> impl Iterator<Item = &str> {
    rel.match_indices('/').map(move |(i, _)| &rel[..i])
}

impl Tree for S3Tree {
    type Reader = S3Reader;
    type Sink = S3Sink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        let keys = self.list_all(&self.prefix)?;
        let mut errors = Vec::new();
        // rel -> (kind, has an object of its own)
        let mut entries: BTreeMap<String, (Kind, bool)> = BTreeMap::new();
        let mut root_marker = false;
        for k in &keys {
            let rel = &k.key[self.prefix.len()..];
            if rel.is_empty() {
                root_marker = true;
                continue;
            }
            let (rel, kind) = match rel.strip_suffix('/') {
                Some(d) => (d, Kind::Dir),
                None => (rel, Kind::File),
            };
            if rel.is_empty()
                || rel
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                errors.push(format!("{}: key is not a path, skipped", k.key));
                continue;
            }
            if let Some((prev, _)) = entries.get(rel) {
                if *prev != kind {
                    errors.push(format!(
                        "{rel}: the bucket has both an object and a prefix of that name, so neither is copied"
                    ));
                    entries.remove(rel);
                    continue;
                }
            }
            entries.insert(rel.to_string(), (kind, true));
            for p in parents_of(rel) {
                entries.entry(p.to_string()).or_insert((Kind::Dir, false));
            }
        }
        // ancestors excluded by the filter take their subtrees with them
        let mut allowed: BTreeMap<String, bool> = BTreeMap::new();
        let names: Vec<(String, Kind, bool)> = entries
            .iter()
            .map(|(r, (k, o))| (r.clone(), *k, *o))
            .collect();
        let mut wanted: Vec<(String, Kind, bool)> = Vec::new();
        for (rel, kind, owned) in names {
            let depth = rel.matches('/').count() + 1;
            let parent_ok = rel
                .rsplit_once('/')
                .is_none_or(|(p, _)| allowed.get(p).copied().unwrap_or(false));
            let ok = parent_ok
                && filter.allows(&rel, kind == Kind::Dir)
                && max_depth.is_none_or(|d| depth <= d);
            allowed.insert(rel.clone(), ok);
            if ok {
                wanted.push((rel, kind, owned));
            }
        }
        // describe every owned entry in parallel; synthesized directories need no request
        let items: Mutex<Vec<Item>> = Mutex::new(Vec::with_capacity(wanted.len() + 1));
        let errs: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let next = AtomicUsize::new(0);
        let workers = parallel.clamp(1, 32).min(wanted.len().max(1));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((rel, kind, owned)) = wanted.get(i) else {
                        break;
                    };
                    let item = if *owned {
                        match self.describe(rel, *kind) {
                            Ok(Some(it)) => it,
                            Ok(None) => continue, // gone between the listing and now
                            Err(e) => {
                                errs.lock().unwrap().push(format!("{rel}: {e}"));
                                continue;
                            }
                        }
                    } else {
                        self.synthesized_dir(rel)
                    };
                    items.lock().unwrap().push(item);
                });
            }
        });
        let mut items = items.into_inner().unwrap();
        errors.append(&mut errs.into_inner().unwrap());
        let now = now_ns();
        items.retain(|i| match i.kind {
            Kind::Dir => true,
            Kind::File => {
                filter.allows_file(i.size, i.mtime_ns, now)
                    && filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino)
            }
            Kind::Symlink => filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino),
        });
        let root = if root_marker && !self.prefix.is_empty() {
            self.describe(".", Kind::Dir)?
                .unwrap_or_else(|| self.synthesized_dir("."))
        } else {
            self.synthesized_dir(".")
        };
        items.push(root);
        items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        errors.sort();
        Ok(Listing { items, errors })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        if rel == "." {
            if self.prefix.is_empty() {
                return Ok(Some(self.synthesized_dir(".")));
            }
            return Ok(Some(
                self.describe(".", Kind::Dir)?
                    .unwrap_or_else(|| self.synthesized_dir(".")),
            ));
        }
        if let Some(i) = self.describe(rel, Kind::File)? {
            return Ok(Some(i));
        }
        if let Some(i) = self.describe(rel, Kind::Dir)? {
            return Ok(Some(i));
        }
        let (children, _) = self.list_page(&self.dir_key(rel), None, 1)?;
        Ok(if children.is_empty() {
            None
        } else {
            Some(self.synthesized_dir(rel))
        })
    }

    fn open(&self, rel: &str) -> io::Result<S3Reader> {
        let key = self.key(rel);
        let size = self
            .pool
            .head(&key)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{rel}: no such object"))
            })?
            .header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(S3Reader {
            pool: self.pool.clone(),
            key,
            size,
            pos: 0,
            conn: None,
        })
    }

    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut r = self.open(rel)?;
        loop {
            let mut filled = 0;
            while filled < buf.len() {
                let n = r.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                return Ok(());
            }
            let chunk = &buf[..filled];
            if is_all_zero(chunk) {
                sink(Segment::Hole(filled as u64))?;
            } else {
                sink(Segment::Data(chunk))?;
            }
            if filled < buf.len() {
                return Ok(());
            }
        }
    }

    fn create_file(&self, item: &Item) -> io::Result<S3Sink> {
        let mut meta = Meta::default();
        meta.set(
            Some(item.mtime_ns),
            Some(full_mode(Kind::File, item.mode)),
            Some(item.uid),
            Some(item.gid),
        );
        Ok(S3Sink {
            pool: self.pool.clone(),
            key: self.key(&item.rel),
            meta,
            expected: None,
            pos: 0,
            state: State::Idle,
            finished: false,
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut S3Sink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        if rel == "." && self.prefix.is_empty() {
            return Ok(());
        }
        let key = self.dir_key(rel);
        if self.pool.head(&key)?.is_some() {
            return Ok(());
        }
        let mut meta = Meta::default();
        meta.set(
            Some(now_ns()),
            Some(full_mode(Kind::Dir, 0o755)),
            None,
            None,
        );
        self.put(&key, &meta, &[])
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        let mut meta = Meta::default();
        meta.set(
            Some(now_ns()),
            Some(full_mode(Kind::Symlink, 0o777)),
            None,
            None,
        );
        self.put(&self.key(rel), &meta, target.to_string_lossy().as_bytes())
    }

    fn hard_link(&self, _existing: &str, _rel: &str) -> io::Result<()> {
        // A bucket has no links, and "the nearest thing" is not the same thing. The
        // server-side copy this used to make returns `Ok(())`, so the run reported `N
        // linked` against a store where each name is a separate billable object -- and
        // `verify` then reported `DIFF hardlink` for that group on every later run,
        // because fabricated inodes cannot match. `describe` says `hard_links: false` for
        // s3 already; this makes the adapter agree with it. See the HDFS one for the
        // measurement. `copy_tree` turns `Unsupported` into a plain copy.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "an object store has no hard links",
        ))
    }

    // an object store has no extended attributes; modes and owners DO ride in user metadata, so only this one is false
    fn keeps_xattrs(&self) -> bool {
        false
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        if rel == "." && self.prefix.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the bucket itself is not removed; remove its contents",
            ));
        }
        let key = if kind == Kind::Dir {
            self.dir_key(rel)
        } else {
            self.key(rel)
        };
        let r = self.pool.request("DELETE", &key, &[], Vec::new(), &[])?;
        match r.status {
            404 => Ok(Removed::Gone),
            // a 403 to a DELETE is the bucket policy refusing, not a broken transfer; a
            // 401 is a credential this run cannot fix by rerunning, and `kind_of_status`
            // calls both `PermissionDenied` so the kind could not tell them apart.
            status => match check(r, rel) {
                Ok(_) => Ok(Removed::Gone),
                Err(e) => crate::net::http::delete_refused(status, rel, e),
            },
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        // no rename in the API: a server-side copy (no data moves) then a delete
        let (a, b) = (self.key(from), self.key(to));
        self.copy_object(&a, &b, None)?;
        let r = self.pool.request("DELETE", &a, &[], Vec::new(), &[])?;
        match r.status {
            404 => Ok(()),
            _ => check(r, from).map(|_| ()),
        }
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let key = if item.kind == Kind::Dir {
            self.dir_key(rel)
        } else {
            self.key(rel)
        };
        if key.is_empty() {
            return Ok(Refusals::default()); // the bucket root has no object to carry metadata
        }
        let Some(head) = self.pool.head(&key)? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{rel}: no such object"),
            ));
        };
        let current = Meta::from_headers(&head.headers);
        let mut wanted = current.clone();
        let mode = if opts.mode {
            Some(full_mode(item.kind, item.mode))
        } else {
            None
        };
        let (uid, gid) = if opts.owner {
            (Some(item.uid), Some(item.gid))
        } else {
            (None, None)
        };
        wanted.set(
            if opts.times {
                Some(item.mtime_ns)
            } else {
                None
            },
            mode,
            uid,
            gid,
        );
        if wanted == current {
            return Ok(Refusals::default());
        }
        let size: u64 = head
            .header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if size > 5 << 30 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("{rel}: metadata of an object over 5 GiB cannot be rewritten in place (the service's single-copy limit)")));
        }
        self.copy_object(&key, &key, Some(&wanted))
            .map(|_| Refusals::default())
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|(n, _)| n.clone()).collect())
    }

    fn restore_atime(&self, _item: &Item) -> io::Result<()> {
        Ok(()) // reading an object touches nothing
    }

    fn sync(&self) -> io::Result<()> {
        Ok(()) // every upload was acknowledged when it finished
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
            "no server-side batch copy",
        ))
    }
}

/// A streaming `GET`, reissued with a `Range` after a seek.
pub struct S3Reader {
    pool: Arc<Pool>,
    key: String,
    size: u64,
    pos: u64,
    conn: Option<Connection>,
}

impl S3Reader {
    fn start(&mut self) -> io::Result<()> {
        let mut headers = Vec::new();
        if self.pos > 0 {
            headers.push(("range".to_string(), format!("bytes={}-", self.pos)));
        }
        let (target, hs) = self
            .pool
            .prepare("GET", &self.key, &[], headers, EMPTY_SHA256);
        let mut conn = self.pool.take()?;
        conn.send_head("GET", &target, &hs, 0)?;
        let r = conn.read_head(false)?;
        if !r.ok() {
            let mut r = r;
            r.body = conn.drain().unwrap_or_default();
            self.pool.give(conn);
            return Err(error_of(&r, &self.key));
        }
        // The registry and WebDAV readers both refuse a ranged read the server answered
        // from zero -- a 200 to a Range, or a 206 whose Content-Range starts elsewhere --
        // and this one must too. Reading any 2xx after a seek as bytes from `pos` means an
        // S3-compatible service that ignores Range (a proxy in front of one does) has the
        // head of the object written at its tail. The same two checks, before a byte is
        // placed.
        if self.pos > 0 {
            if r.status != 206 {
                let _ = conn.drain();
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: asked for bytes from {} and the service answered {} with the whole object; it does not honor Range", self.key, self.pos, r.status)));
            }
            match r
                .header("content-range")
                .and_then(crate::net::http::content_range_start)
            {
                Some(start) if start == self.pos => {}
                Some(start) => {
                    let _ = conn.drain();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: asked for bytes from {} and the service's 206 starts at {start}; its Range handling cannot be trusted", self.key, self.pos)));
                }
                None => {
                    let _ = conn.drain();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: the service answered 206 without a readable Content-Range, so where its bytes start is unknown", self.key)));
                }
            }
        }
        self.conn = Some(conn);
        Ok(())
    }
}

impl Read for S3Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        if self.conn.is_none() {
            self.start()?;
        }
        let conn = self.conn.as_mut().unwrap();
        let n = conn.read_body(buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: object ended at {} of {} bytes",
                    self.key, self.pos, self.size
                ),
            ));
        }
        self.pos += n as u64;
        if self.pos >= self.size {
            let mut done = self.conn.take().unwrap();
            let _ = done.drain(); // nothing should be left; if it is, the connection is not reused
            self.pool.give(done);
        }
        Ok(n)
    }
}

impl Seek for S3Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        let target = target as u64;
        if target != self.pos {
            self.conn = None; // the body in flight is abandoned with its connection
            self.pos = target;
        }
        Ok(self.pos)
    }
}

enum State {
    Idle,
    /// No size was declared: the bytes are kept and sent as one signed `PUT` at the end.
    Buffering(Vec<u8>),
    /// One streaming `PUT` of a declared size.
    Single(Connection),
    Multi {
        upload_id: String,
        part_size: u64,
        etags: Vec<(u32, String)>,
        part_no: u32,
        current: Option<(Connection, u64, u64)>,
    },
}

/// A streaming upload; `reserve` picks the shape, `finish` completes it.
pub struct S3Sink {
    pool: Arc<Pool>,
    key: String,
    meta: Meta,
    expected: Option<u64>,
    pos: u64,
    state: State,
    finished: bool,
}

impl S3Sink {
    fn put_headers(&self) -> Vec<(String, String)> {
        let mut h = self.meta.headers();
        h.push(("content-type".into(), "application/octet-stream".into()));
        h
    }

    fn start_single(&mut self, len: u64) -> io::Result<()> {
        let (target, hs) =
            self.pool
                .prepare("PUT", &self.key, &[], self.put_headers(), UNSIGNED_PAYLOAD);
        let mut conn = self.pool.take()?;
        conn.send_head("PUT", &target, &hs, len)?;
        self.state = State::Single(conn);
        Ok(())
    }

    fn start_multi(&mut self, len: u64) -> io::Result<()> {
        let q = vec![("uploads".to_string(), String::new())];
        let r = check(
            self.pool
                .request("POST", &self.key, &q, self.put_headers(), &[])?,
            &self.key,
        )?;
        let text = String::from_utf8_lossy(&r.body);
        let upload_id = xml::value(&text, "UploadId").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no UploadId in the multipart initiation", self.key),
            )
        })?;
        let part_size =
            (len.div_ceil(MAX_PARTS).max(SINGLE_PUT_MAX) + (1 << 20) - 1) & !((1 << 20) - 1);
        self.state = State::Multi {
            upload_id,
            part_size,
            etags: Vec::new(),
            part_no: 0,
            current: None,
        };
        Ok(())
    }

    fn finish_part(
        pool: &Pool,
        key: &str,
        mut conn: Connection,
        part_no: u32,
    ) -> io::Result<String> {
        let mut r = conn.read_head(false)?;
        r.body = conn.drain()?;
        pool.give(conn);
        let r = check(r, key)?;
        r.header("etag").map(|e| e.to_string()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{key}: part {part_no} came back without an ETag"),
            )
        })
    }

    fn write_multi(&mut self, mut data: &[u8]) -> io::Result<()> {
        let expected = self.expected.unwrap_or(0);
        while !data.is_empty() {
            let State::Multi {
                upload_id,
                part_size,
                etags,
                part_no,
                current,
            } = &mut self.state
            else {
                unreachable!()
            };
            if current.is_none() {
                if self.pos >= expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: more bytes than the {expected} declared", self.key),
                    ));
                }
                *part_no += 1;
                let len = (*part_size).min(expected - self.pos);
                let q = vec![
                    ("partNumber".to_string(), part_no.to_string()),
                    ("uploadId".to_string(), upload_id.clone()),
                ];
                let (target, hs) =
                    self.pool
                        .prepare("PUT", &self.key, &q, Vec::new(), UNSIGNED_PAYLOAD);
                let mut conn = self.pool.take()?;
                conn.send_head("PUT", &target, &hs, len)?;
                *current = Some((conn, 0, len));
            }
            let (conn, written, len) = current.as_mut().unwrap();
            let take = ((*len - *written) as usize).min(data.len());
            conn.write_body(&data[..take])?;
            *written += take as u64;
            self.pos += take as u64;
            data = &data[take..];
            if written == len {
                let (conn, _, _) = current.take().unwrap();
                let etag = Self::finish_part(&self.pool, &self.key, conn, *part_no)?;
                etags.push((*part_no, etag));
            }
        }
        Ok(())
    }

    fn abort(&mut self) {
        if let State::Multi { upload_id, .. } = &self.state {
            let q = vec![("uploadId".to_string(), upload_id.clone())];
            let _ = self.pool.request("DELETE", &self.key, &q, Vec::new(), &[]);
        }
        self.state = State::Idle;
    }
}

impl Sink for S3Sink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        self.expected = Some(len);
        if len == 0 {
            self.state = State::Buffering(Vec::new());
        } else if len <= SINGLE_PUT_MAX {
            self.start_single(len)?;
        } else {
            self.start_multi(len)?;
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.state {
            State::Idle => {
                self.state = State::Buffering(data.to_vec());
                self.pos += data.len() as u64;
                Ok(())
            }
            State::Buffering(buf) => {
                buf.extend_from_slice(data);
                self.pos += data.len() as u64;
                Ok(())
            }
            State::Single(conn) => {
                let expected = self.expected.unwrap_or(0);
                if self.pos + data.len() as u64 > expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: more bytes than the {expected} declared", self.key),
                    ));
                }
                conn.write_body(data)?;
                self.pos += data.len() as u64;
                Ok(())
            }
            State::Multi { .. } => self.write_multi(data),
        }
    }

    fn hole(&mut self, mut len: u64) -> io::Result<()> {
        while len > 0 {
            let n = len.min(ZEROS.len() as u64) as usize;
            self.write(&ZEROS[..n])?;
            len -= n as u64;
        }
        Ok(())
    }

    fn finish(
        &mut self,
        _item: &Item,
        xattrs: &[(String, Vec<u8>)],
        _opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        if let Some(expected) = self.expected {
            if self.pos != expected {
                self.abort();
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: {} bytes arrived for {expected} declared (the source changed during the copy)", self.key, self.pos)));
            }
        }
        let state = std::mem::replace(&mut self.state, State::Idle);
        match state {
            State::Idle => self
                .pool
                .request("PUT", &self.key, &[], self.put_headers(), &[])
                .and_then(|r| check(r, &self.key))
                .map(|_| ())?,
            State::Buffering(buf) => check(
                self.pool
                    .request("PUT", &self.key, &[], self.put_headers(), &buf)?,
                &self.key,
            )
            .map(|_| ())?,
            State::Single(mut conn) => {
                let mut r = conn.read_head(false)?;
                r.body = conn.drain()?;
                self.pool.give(conn);
                check(r, &self.key)?;
            }
            State::Multi {
                upload_id,
                etags,
                current,
                ..
            } => {
                if let Some((_abandoned, written, len)) = current {
                    self.state = State::Multi {
                        upload_id,
                        part_size: 0,
                        etags: Vec::new(),
                        part_no: 0,
                        current: None,
                    };
                    self.abort();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: last part incomplete ({written} of {len} bytes)",
                            self.key
                        ),
                    ));
                }
                let mut body = String::from("<CompleteMultipartUpload>");
                for (n, etag) in &etags {
                    body.push_str(&format!(
                        "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                        xml::escape(etag)
                    ));
                }
                body.push_str("</CompleteMultipartUpload>");
                let q = vec![("uploadId".to_string(), upload_id.clone())];
                let posted = self.pool.request(
                    "POST",
                    &self.key,
                    &q,
                    vec![("content-type".into(), "application/xml".into())],
                    body.as_bytes(),
                );
                let r = match posted.and_then(|r| check(r, &self.key)) {
                    Ok(r) => r,
                    Err(e) => {
                        self.state = State::Multi {
                            upload_id,
                            part_size: 0,
                            etags,
                            part_no: 0,
                            current: None,
                        };
                        self.abort();
                        return Err(e);
                    }
                };
                let text = String::from_utf8_lossy(&r.body);
                if text.contains("<Error>") {
                    self.state = State::Multi {
                        upload_id,
                        part_size: 0,
                        etags,
                        part_no: 0,
                        current: None,
                    };
                    self.abort();
                    return Err(io::Error::other(format!(
                        "{}: {}",
                        self.key,
                        xml::value(&text, "Message")
                            .unwrap_or_else(|| "multipart completion failed".into())
                    )));
                }
            }
        }
        self.finished = true;
        Ok(Refusals {
            owner: false,
            xattrs: xattrs.iter().map(|(n, _)| n.clone()).collect(),
        })
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Drop for S3Sink {
    fn drop(&mut self) {
        if !self.finished {
            self.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_round_trips_through_headers() {
        let mut m = Meta::default();
        m.set(
            Some(1_600_000_000_123_456_789),
            Some(full_mode(Kind::File, 0o644)),
            Some(1000),
            Some(1000),
        );
        let headers = m.headers();
        assert!(headers.contains(&(
            "x-amz-meta-mtime".to_string(),
            "1600000000.123456789".to_string()
        )));
        assert!(headers.contains(&("x-amz-meta-mode".to_string(), "33188".to_string())));
        let back = Meta::from_headers(
            &headers
                .iter()
                .map(|(k, v)| (k.to_ascii_uppercase(), v.clone()))
                .collect::<Vec<_>>(),
        );
        assert_eq!(back, m);
        assert_eq!(parse_mtime("1600000000"), Some(1_600_000_000_000_000_000));
        assert_eq!(parse_mtime("1600000000.5"), Some(1_600_000_000_500_000_000));
        assert_eq!(parse_mtime("x"), None);
    }

    #[test]
    fn part_sizes_stay_within_the_service_limits() {
        for len in [SINGLE_PUT_MAX + 1, 1 << 40, 5 << 40] {
            let part =
                (len.div_ceil(MAX_PARTS).max(SINGLE_PUT_MAX) + (1 << 20) - 1) & !((1 << 20) - 1);
            assert!(part >= SINGLE_PUT_MAX);
            assert!(
                len.div_ceil(part) <= MAX_PARTS,
                "{len}: {} parts",
                len.div_ceil(part)
            );
            assert_eq!(part % (1 << 20), 0);
        }
    }

    #[test]
    fn parents_are_every_prefix() {
        assert_eq!(parents_of("a/b/c").collect::<Vec<_>>(), vec!["a", "a/b"]);
        assert_eq!(parents_of("x").count(), 0);
    }
}
