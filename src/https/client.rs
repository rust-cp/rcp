//! `HttpsTree`: the `Tree` port over a plain web server, read-only.

use crate::ports::KernelFileDescriptor as RawFd;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex};

use super::index::{self, Entry};
use super::Settings;
use crate::base64;
use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::net::http::{
    content_range_start, content_range_total, percent_decode, percent_encode, split_url,
};
use crate::net::http::{Connection, Scheme};
use crate::net::origin::{remote_error, Pool};
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree,
};
use crate::time::parse_http_date_ns;

/// Which listing shape answered for this tree, decided once at `connect` and then trusted.
///
/// Decided once because it is a property of the SERVER, not of a directory, and re-sniffing
/// per directory would cost a request for `rcp-index.json` at every level of the walk
/// against a server that has none -- the common case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// a published `rcp-index.json` at the root, describing the whole tree
    Index,
    /// nginx `autoindex_format json`, per directory
    Json,
    /// an Apache-style HTML page, per directory, with a `HEAD` per file for size and date
    Html,
}

pub struct HttpsTree {
    pool: Arc<Pool>,
    /// the decoded path of the root on the server, with no trailing slash
    root: String,
    display: PathBuf,
    shape: Shape,
    /// the whole published index, read once, when `shape` is `Index`
    index: Option<Vec<u8>>,
}

fn content_length(r: &crate::net::http::Response) -> Option<u64> {
    r.header("content-length")
        .and_then(|v| v.trim().parse().ok())
}

fn readonly(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what}: an http:// or https:// endpoint is a source only -- a plain web server has no agreed way to create, remove or rename anything (dav:// is the protocol that does)"),
    )
}

impl HttpsTree {
    /// Opens `url` as a tree. `create` is refused rather than ignored: a caller asking for
    /// a destination has asked for something this adapter cannot be.
    pub fn connect(
        url: &str,
        create: bool,
        settings: &Settings,
        log: Arc<dyn crate::ports::Log>,
    ) -> io::Result<HttpsTree> {
        if create {
            return Err(readonly(url));
        }
        let (scheme, host, port, path) = split_url(url)?;
        let origin = Pool::key(scheme, &host, port);
        let auth = settings
            .user
            .clone()
            .or_else(|| {
                match (
                    std::env::var("RCP_HTTP_USER"),
                    std::env::var("RCP_HTTP_PASSWORD"),
                ) {
                    (Ok(u), Ok(p)) if !u.is_empty() => Some(format!("{u}:{p}")),
                    (Ok(u), _) if u.contains(':') => Some(u),
                    _ => None,
                }
            })
            .map(|c| format!("Basic {}", base64::encode(c.as_bytes())));
        let pool = Arc::new(Pool {
            log,
            origin: origin.clone(),
            auth,
            targets: Mutex::new(BTreeMap::new()),
            idle: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "rustls")]
            tls: if scheme == Scheme::Https {
                Some(crate::net::tls::config(
                    settings.noverify,
                    crate::net::tls::HTTP_NOVERIFY,
                )?)
            } else {
                None
            },
        });
        let root = percent_decode(&path).trim_end_matches('/').to_string();
        let display = PathBuf::from(format!(
            "{}{}",
            origin,
            if root.is_empty() { "/" } else { &root }
        ));
        let mut t = HttpsTree {
            pool,
            root,
            display,
            shape: Shape::Html,
            index: None,
        };

        // The published index first, because it is the only shape carrying a mode, a real
        // mtime and a digest -- and because one request answers for the whole tree, where
        // the autoindex shapes cost a request per directory.
        let name = settings
            .index
            .clone()
            .unwrap_or_else(|| "rcp-index.json".to_string());
        if !name.is_empty() {
            let r = t.pool.request(
                "GET",
                &format!("{}/{}", t.target(".", false), percent_encode(&name, false)),
                &[],
                &[],
            )?;
            if r.ok() {
                // parsed here rather than at first use so a corrupt index fails the OPEN,
                // where the operator is still looking, and not halfway through a walk
                index::parse_rcp_index(&r.body, "")?;
                t.shape = Shape::Index;
                t.index = Some(r.body);
                return Ok(t);
            }
        }

        // Otherwise ask the collection itself and read what comes back. `Accept` asks
        // nginx for its JSON form; a server that does not know it answers HTML and the
        // sniffer sorts them out, so this is one request either way.
        let r = t.pool.request(
            "GET",
            &t.target(".", true),
            &[("accept", "application/json")],
            &[],
        )?;
        if !r.ok() {
            return Err(remote_error(&r, &t.display.display().to_string()));
        }
        t.shape = if index::looks_like_json(&r.body) {
            Shape::Json
        } else {
            Shape::Html
        };
        Ok(t)
    }

    /// Which listing shape this endpoint answered with, for a report and for the arms.
    pub fn shape(&self) -> Shape {
        self.shape
    }

    fn abs(&self, rel: &str) -> String {
        if rel == "." {
            if self.root.is_empty() {
                "/".to_string()
            } else {
                self.root.clone()
            }
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    fn target(&self, rel: &str, dir: bool) -> String {
        let p = percent_encode(&self.abs(rel), true);
        if dir && !p.ends_with('/') {
            format!("{p}/")
        } else {
            p
        }
    }

    fn item_of(&self, rel: String, e: &Entry) -> Item {
        let size = if e.kind == Kind::Dir { 0 } else { e.size };
        Item {
            ino: fnv64(&rel),
            rel,
            kind: e.kind,
            size,
            mtime_ns: e.mtime_ns,
            atime_ns: e.mtime_ns,
            mode: e.mode,
            uid: 0,
            gid: 0,
            dev: 0,
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    /// `HEAD` for the one thing an HTML autoindex cannot say: how big a file is and when
    /// it changed. Costed only for `Shape::Html`, and only for files.
    ///
    /// Apache strips `Content-Length: 0` from a `HEAD` (it has since the change that
    /// stopped a zero length being invented for one). A missing length is therefore what
    /// an empty file looks like there, and also what a server looks like when it never
    /// says how long the file is. Those are not the same, so a missing length is checked
    /// with `Range: bytes=0-0` rather than recorded as zero.
    fn head(&self, rel: &str) -> io::Result<(u64, i128)> {
        let r = self
            .pool
            .request("HEAD", &self.target(rel, false), &[], &[])?;
        if !r.ok() {
            return Err(remote_error(&r, rel));
        }
        let mtime = r
            .header("last-modified")
            .and_then(parse_http_date_ns)
            .unwrap_or(0);
        let size = match content_length(&r) {
            Some(n) => n,
            None => self.size_when_head_omits_length(rel)?,
        };
        Ok((size, mtime))
    }

    /// The length, when `HEAD` did not name one.
    ///
    /// An empty file on Apache answers `416` with `Content-Range: bytes */0`. A file that
    /// has bytes answers `206` with the total. A server that ignores `Range` and answers
    /// `200` is believed only when that response itself names the length. Anything else
    /// stays unknown: recording it as zero is how a short copy used to be reported done.
    fn size_when_head_omits_length(&self, rel: &str) -> io::Result<u64> {
        let r = self.pool.request(
            "GET",
            &self.target(rel, false),
            &[("range", "bytes=0-0")],
            &[],
        )?;
        let total = r.header("content-range").and_then(content_range_total);
        let known = match r.status {
            206 | 416 => total,
            200 => total.or_else(|| content_length(&r)),
            _ => None,
        };
        known.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{rel}: HEAD has no Content-Length, and a one-byte range did not name the file's size"
                ),
            )
        })
    }

    fn list_dir(&self, rel: &str) -> io::Result<Vec<Item>> {
        let entries = match self.shape {
            Shape::Index => {
                let body = self.index.as_deref().unwrap_or_default();
                let under = if rel == "." {
                    String::new()
                } else {
                    rel.to_string()
                };
                index::parse_rcp_index(body, &under)?
            }
            Shape::Json | Shape::Html => {
                let r = self.pool.request(
                    "GET",
                    &self.target(rel, true),
                    &[("accept", "application/json")],
                    &[],
                )?;
                if !r.ok() {
                    return Err(remote_error(&r, rel));
                }
                if index::looks_like_json(&r.body) {
                    index::parse_nginx_json(&r.body)?
                } else {
                    index::parse_html(&r.body, &self.abs(rel))?
                }
            }
        };
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let child = if rel == "." {
                e.name.clone()
            } else {
                format!("{rel}/{}", e.name)
            };
            let mut item = self.item_of(child.clone(), &e);
            // an HTML page says nothing but the name and whether it ends in a slash
            if self.shape == Shape::Html && item.kind == Kind::File {
                let (size, mtime) = self.head(&child)?;
                item.size = size;
                item.blocks = size;
                item.mtime_ns = mtime;
                item.atime_ns = mtime;
            }
            out.push(item);
        }
        Ok(out)
    }

    fn handle(&self) -> HttpsHandle {
        HttpsHandle {
            pool: self.pool.clone(),
            root: self.root.clone(),
        }
    }
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl Tree for HttpsTree {
    type Reader = HttpsReader;
    type Sink = NoSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        struct Queue {
            dirs: Vec<(String, usize)>,
            in_flight: usize,
        }
        let root = Item {
            ino: fnv64("."),
            rel: ".".into(),
            kind: Kind::Dir,
            size: 0,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            dev: 0,
            nlink: 1,
            blocks: 0,
            link_target: None,
        };
        let queue = Mutex::new(Queue {
            dirs: vec![(".".to_string(), 0)],
            in_flight: 0,
        });
        let wake = Condvar::new();
        let collected: Mutex<Listing> = Mutex::new(Listing {
            items: vec![root],
            errors: Vec::new(),
        });
        let now = filter::now_ns();
        std::thread::scope(|scope| {
            for _ in 0..parallel.clamp(1, 32) {
                scope.spawn(|| {
                    let mut items: Vec<Item> = Vec::new();
                    let mut errors: Vec<String> = Vec::new();
                    loop {
                        let (rel, depth) = {
                            let mut q = queue.lock().unwrap();
                            loop {
                                if let Some(d) = q.dirs.pop() {
                                    q.in_flight += 1;
                                    break d;
                                }
                                if q.in_flight == 0 {
                                    drop(q);
                                    let mut c = collected.lock().unwrap();
                                    c.items.append(&mut items);
                                    c.errors.append(&mut errors);
                                    return;
                                }
                                q = wake.wait(q).unwrap();
                            }
                        };
                        let mut subdirs = Vec::new();
                        match self.list_dir(&rel) {
                            Ok(entries) => {
                                for item in entries {
                                    let is_dir = item.kind == Kind::Dir;
                                    if !filter.allows(&item.rel, is_dir) {
                                        continue;
                                    }
                                    if item.kind == Kind::File
                                        && !filter.allows_file(item.size, item.mtime_ns, now)
                                    {
                                        continue;
                                    }
                                    if is_dir && max_depth.is_none_or(|d| depth + 1 < d) {
                                        subdirs.push((item.rel.clone(), depth + 1));
                                    }
                                    items.push(item);
                                }
                            }
                            Err(e) => errors.push(format!("{rel}: {e}")),
                        }
                        let mut q = queue.lock().unwrap();
                        q.dirs.append(&mut subdirs);
                        q.in_flight -= 1;
                        drop(q);
                        wake.notify_all();
                    }
                });
            }
        });
        let mut listing = collected.into_inner().unwrap();
        // THE ROOT'S TIME IS DERIVED, NOT INVENTED. It was hardcoded `mtime_ns: 0` while
        // `keeps_times()` answers TRUE for an index-shaped tree, so the root was the one
        // entry in the listing carrying a placeholder where every other time was real --
        // and the copy WRITES it, so a tree fetched from an index-shaped server came out
        // with its top directory dated 1970-01-01. Measured in the contract suite:
        // `SystemTime { tv_sec: 0, tv_nsec: 0 }`.
        //
        // (`verify` did NOT report a difference on it, which is worth writing down because
        // that was the first guess: both sides read the same zero, because the copy had
        // just written it. The symptom is the date on disk, not a verify diff.)
        //
        // HTTP has no directory time to publish -- an index lists files -- so the newest
        // file in the tree is the closest real answer, and it is the same answer a local
        // directory gives after the copy that wrote it.
        //
        // Only where times are real at all: on an autoindex `keeps_times()` is false, the
        // comparison is skipped either way, and a derived value would be noise.
        if self.keeps_times() {
            if let Some(newest) = listing
                .items
                .iter()
                .filter(|i| i.rel != ".")
                .map(|i| i.mtime_ns)
                .max()
            {
                if let Some(root) = listing.items.iter_mut().find(|i| i.rel == ".") {
                    root.mtime_ns = newest;
                }
            }
        }
        listing.items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        listing.errors.sort();
        Ok(listing)
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        if rel == "." {
            return Ok(Some(self.item_of(
                ".".into(),
                &Entry {
                    name: ".".into(),
                    kind: Kind::Dir,
                    size: 0,
                    mtime_ns: 0,
                    mode: 0o755,
                    digest: None,
                },
            )));
        }
        // An index answers without a request. Otherwise a HEAD is the only stat HTTP has,
        // and a 404 there is a missing file rather than a failure.
        if self.shape == Shape::Index {
            let (parent, name) = match rel.rsplit_once('/') {
                Some((p, n)) => (p.to_string(), n.to_string()),
                None => (".".to_string(), rel.to_string()),
            };
            let under = if parent == "." { String::new() } else { parent };
            let found = index::parse_rcp_index(self.index.as_deref().unwrap_or_default(), &under)?
                .into_iter()
                .find(|e| e.name == name);
            return Ok(found.map(|e| self.item_of(rel.to_string(), &e)));
        }
        match self.head(rel) {
            Ok((size, mtime)) => Ok(Some(self.item_of(
                rel.to_string(),
                &Entry {
                    name: rel.into(),
                    kind: Kind::File,
                    size,
                    mtime_ns: mtime,
                    mode: 0o644,
                    digest: None,
                },
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn open(&self, rel: &str) -> io::Result<HttpsReader> {
        let size = self
            .stat(rel)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{rel}: no such file")))?
            .size;
        Ok(HttpsReader {
            tree: self.handle(),
            rel: rel.to_string(),
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
            if is_all_zero(&buf[..filled]) {
                sink(Segment::Hole(filled as u64))?;
            } else {
                sink(Segment::Data(&buf[..filled]))?;
            }
            if filled < buf.len() {
                return Ok(());
            }
        }
    }

    fn create_file(&self, item: &Item) -> io::Result<NoSink> {
        Err(readonly(&item.rel))
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut NoSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        Err(readonly(rel))
    }

    fn symlink(&self, rel: &str, _target: &Path) -> io::Result<()> {
        Err(readonly(rel))
    }

    fn hard_link(&self, _existing: &str, rel: &str) -> io::Result<()> {
        Err(readonly(rel))
    }

    fn remove(&self, rel: &str, _kind: Kind) -> io::Result<Removed> {
        Err(readonly(rel))
    }

    fn rename(&self, from: &str, _to: &str) -> io::Result<()> {
        Err(readonly(from))
    }

    fn set_metadata(&self, rel: &str, _item: &Item, _opts: MetaOptions) -> io::Result<Refusals> {
        Err(readonly(rel))
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, rel: &str, _attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Err(readonly(rel))
    }

    fn restore_atime(&self, _item: &Item) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    fn keeps_times(&self) -> bool {
        // Only a published index carries the source's own mtime. An autoindex date is
        // when the SERVER last wrote the file, exactly as WebDAV's `getlastmodified` is,
        // so the planner matches on size there and `verify` skips the comparison.
        self.shape == Shape::Index
    }

    // an http listing carries no mode, owner or xattr: the adapter synthesizes 0644/0755 and uid 0
    fn keeps_modes(&self) -> bool {
        false
    }
    fn keeps_owner(&self) -> bool {
        false
    }
    fn keeps_xattrs(&self) -> bool {
        false
    }
    fn rewrites_metadata_in_place(&self) -> bool {
        false
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
        Err(readonly("native copy"))
    }
}

#[derive(Clone)]
struct HttpsHandle {
    pool: Arc<Pool>,
    root: String,
}

impl HttpsHandle {
    fn target(&self, rel: &str) -> String {
        let abs = if rel == "." {
            if self.root.is_empty() {
                "/".to_string()
            } else {
                self.root.clone()
            }
        } else {
            format!("{}/{rel}", self.root)
        };
        percent_encode(&abs, true)
    }
}

/// A streaming `GET`, reissued with a `Range` after a seek -- the same two checks the
/// registry, WebDAV and S3 readers make, because a server free to ignore a `Range` answers
/// 200 with the whole file and every byte from `pos` on would really be a byte from zero.
pub struct HttpsReader {
    tree: HttpsHandle,
    rel: String,
    size: u64,
    pos: u64,
    conn: Option<(Scheme, String, u16, Connection)>,
}

impl HttpsReader {
    fn start(&mut self) -> io::Result<()> {
        let (scheme, host, port, _) = split_url(&format!("{}/", self.tree.pool.origin))?;
        let mut conn = self.tree.pool.take(scheme, &host, port)?;
        let range = format!("bytes={}-", self.pos);
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if self.pos > 0 {
            extra.push(("range", &range));
        }
        conn.send_head(
            "GET",
            &self.tree.target(&self.rel),
            &self.tree.pool.headers(&extra),
            0,
        )?;
        let r = conn.read_head(false)?;
        if self.pos > 0 && r.status == 200 {
            let _ = conn.drain();
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: asked for bytes from {} and the server answered 200 with the whole file; it does not honor Range", self.rel, self.pos)));
        }
        if self.pos > 0 && r.status == 206 {
            match r.header("content-range").and_then(content_range_start) {
                Some(s) if s == self.pos => {}
                Some(s) => {
                    let _ = conn.drain();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: asked for bytes from {} and the server's 206 starts at {s}; its Range handling cannot be trusted", self.rel, self.pos)));
                }
                None => {
                    let _ = conn.drain();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: the server answered 206 without a readable Content-Range, so where its bytes start is unknown", self.rel)));
                }
            }
        }
        if !r.ok() {
            let mut r = r;
            r.body = conn.drain().unwrap_or_default();
            return Err(remote_error(&r, &self.rel));
        }
        self.conn = Some((scheme, host, port, conn));
        Ok(())
    }
}

impl Read for HttpsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        if self.conn.is_none() {
            self.start()?;
        }
        let (_, _, _, conn) = self.conn.as_mut().unwrap();
        let n = conn.read_body(buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: file ended at {} of {} bytes",
                    self.rel, self.pos, self.size
                ),
            ));
        }
        self.pos += n as u64;
        if self.pos >= self.size {
            let (scheme, host, port, mut done) = self.conn.take().unwrap();
            let _ = done.drain();
            self.tree.pool.give(scheme, &host, port, done);
        }
        Ok(n)
    }
}

impl Seek for HttpsReader {
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
        if target as u64 != self.pos {
            self.conn = None;
            self.pos = target as u64;
        }
        Ok(self.pos)
    }
}

/// The sink of a read-only tree. It exists because `Tree` names a `Sink` type, and every
/// one of its methods refuses: `create_file` never returns one, so none is ever built.
pub struct NoSink;

impl Sink for NoSink {
    fn reserve(&mut self, _len: u64) -> io::Result<()> {
        Err(readonly("write"))
    }

    fn write(&mut self, _data: &[u8]) -> io::Result<()> {
        Err(readonly("write"))
    }

    fn hole(&mut self, _len: u64) -> io::Result<()> {
        Err(readonly("write"))
    }

    fn finish(
        &mut self,
        _item: &Item,
        _xattrs: &[(String, Vec<u8>)],
        _opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        Err(readonly("write"))
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;
    use crate::https::testserver::{Quirks, Server, Shape};
    use crate::ports::Tree;

    fn stand_in(shape: Shape, quirks: Quirks) -> (PathBuf, Server) {
        let root = std::env::temp_dir().join(format!(
            "rcp-http-unit-{}-{}",
            std::process::id(),
            fnv64(&format!("{shape:?}{:?}", std::time::Instant::now()))
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("big.bin"),
            (0u8..=255).cycle().take(5000).collect::<Vec<u8>>(),
        )
        .unwrap();
        let server = Server::start_with(&root, shape, quirks).unwrap();
        (root, server)
    }

    fn tree(server: &Server, shape: Shape) -> HttpsTree {
        let mut s = Settings::default();
        if shape != Shape::Index {
            // force the autoindex readers rather than looking for an index that is not there
            s.index = Some(String::new());
        }
        HttpsTree::connect(&server.url("/"), false, &s, Arc::new(crate::ports::Silent)).unwrap()
    }

    /// The `Range` path, exercised the only way it can be: by seeking the reader.
    ///
    /// Worth stating plainly, because it is a limit of the SUITE and not of the code: no
    /// command drives a seek on a SOURCE reader. `diag nio` is the one core caller of
    /// `Seek`, and it lays out its own files with `create_file`, so it needs a writable
    /// tree and a read-only endpoint can never be its subject. The registry and WebDAV
    /// readers are measured the same way for the same reason.
    #[test]
    fn a_seek_reissues_the_get_with_a_range_and_the_bytes_come_from_the_offset() {
        let (root, server) = stand_in(Shape::Json, Quirks::default());
        let t = tree(&server, Shape::Json);
        let mut r = t.open("big.bin").unwrap();
        let mut head = [0u8; 16];
        r.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 0, "the file does not start where the fixture says");

        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut at = [0u8; 8];
        r.read_exact(&mut at).unwrap();
        let want: Vec<u8> = (1000u32..1008).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            &at[..],
            &want[..],
            "the bytes after a seek are not the bytes at that offset"
        );
        assert!(
            server.ranges.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "no Range request was made, so the seek re-read from zero"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A server that answers 206 from zero mis-assembles a resumed read exactly as one
    /// that ignores the header does: the status says partial and the bytes are the whole
    /// file. Refused before a byte is placed, as the registry, WebDAV and S3 readers do.
    #[test]
    fn a_206_from_the_wrong_offset_is_refused_before_a_byte_is_placed() {
        let (root, server) = stand_in(
            Shape::Json,
            Quirks {
                lies_range: true,
                ..Quirks::default()
            },
        );
        let t = tree(&server, Shape::Json);
        let mut r = t.open("big.bin").unwrap();
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut buf = [0u8; 8];
        let e = r.read_exact(&mut buf).unwrap_err();
        assert!(
            e.to_string().contains("206 starts at 0"),
            "the refusal does not say what the server did: {e}"
        );
        let _ = std::fs::remove_dir_all(root);

        // the control: the honest server serves the same seek
        let (root, server) = stand_in(Shape::Json, Quirks::default());
        let t = tree(&server, Shape::Json);
        let mut r = t.open("big.bin").unwrap();
        r.seek(SeekFrom::Start(1000)).unwrap();
        r.read_exact(&mut buf)
            .expect("the honest server serves the range");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A server free to ignore `Range` answers 200 with the whole file, so every byte
    /// from `pos` on would really be a byte from zero.
    #[test]
    fn a_200_to_a_ranged_read_is_refused_rather_than_written_at_the_offset() {
        let (root, server) = stand_in(
            Shape::Json,
            Quirks {
                ignore_range: true,
                ..Quirks::default()
            },
        );
        let t = tree(&server, Shape::Json);
        let mut r = t.open("big.bin").unwrap();
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut buf = [0u8; 8];
        let e = r.read_exact(&mut buf).unwrap_err();
        assert!(
            e.to_string().contains("does not honor Range"),
            "the refusal does not name the cause: {e}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Apache omits `Content-Length` on `HEAD` of a zero-byte file. The listing still
    /// records that file as empty, and a file that has bytes still reports its real size.
    #[test]
    fn an_html_listing_keeps_an_empty_file_when_head_omits_a_zero_content_length() {
        let (root, server) = stand_in(
            Shape::Html,
            Quirks {
                apache_zero_head: true,
                ..Quirks::default()
            },
        );
        std::fs::write(root.join("empty"), b"").unwrap();
        let t = tree(&server, Shape::Html);
        let listing = t.list(&Filter::default(), None, 2).unwrap();
        assert!(
            listing.errors.is_empty(),
            "an empty file failed the listing: {:?}",
            listing.errors
        );
        let empty = listing
            .items
            .iter()
            .find(|i| i.rel == "empty")
            .expect("the empty file was dropped");
        assert_eq!(empty.size, 0, "the empty file was given a size");
        let big = listing
            .items
            .iter()
            .find(|i| i.rel == "big.bin")
            .expect("the sized file was dropped");
        assert_eq!(big.size, 5000, "a file that has bytes lost its length");
        let mut got = Vec::new();
        t.open("empty").unwrap().read_to_end(&mut got).unwrap();
        assert!(got.is_empty(), "the empty file copied as bytes");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A missing length that the range probe also will not name is a failure. Recording
    /// it as zero is the short copy this check exists to stop.
    #[test]
    fn a_length_nobody_will_name_is_an_error_and_not_an_empty_file() {
        let (root, server) = stand_in(
            Shape::Html,
            Quirks {
                hides_length: true,
                ..Quirks::default()
            },
        );
        let t = tree(&server, Shape::Html);
        let listing = t.list(&Filter::default(), None, 1).unwrap();
        assert!(
            listing
                .errors
                .iter()
                .any(|e| e.contains("did not name the file's size")),
            "the unknown length was not refused: {:?}",
            listing.errors
        );
        assert!(
            listing.items.iter().all(|i| i.rel != "big.bin"),
            "a file of unknown size was listed"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `keeps_times` is a property of the LISTING, not of the transport: only a published
    /// index carries the source's own mtime.
    #[test]
    fn only_a_published_index_claims_to_keep_times() {
        for (shape, want) in [
            (Shape::Index, true),
            (Shape::Json, false),
            (Shape::Html, false),
        ] {
            let (root, server) = stand_in(shape, Quirks::default());
            let t = tree(&server, shape);
            assert_eq!(
                t.keeps_times(),
                want,
                "{shape:?} answered the wrong thing for keeps_times"
            );
            // and it is the LISTING that decides, so the tree recognized the shape served
            assert_eq!(
                t.shape() == super::Shape::Index,
                want,
                "{shape:?} was not recognized as the shape it serves"
            );
            let _ = std::fs::remove_dir_all(root);
        }
    }
}
