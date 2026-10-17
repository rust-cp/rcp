//! `DavTree`: the `Tree` port over WebDAV. One HTTP request per operation, with `PROPFIND`
//! doing the walking and `GET`/`PUT` the bytes.
//!
//! Three things about the protocol shape the adapter, and each is a decision rather than a
//! transcription of the RFC:
//!
//! - **`PROPFIND Depth: 1` lists one collection**, and returns the collection ITSELF as the
//!   first `response`. That self-entry has to be dropped or the walk never terminates --
//!   the directory would contain itself. It is matched by comparing decoded paths, not by
//!   position, because a server is free to order the responses however it likes and at
//!   least one does.
//! - **`href` is a URL, not a name.** It may be absolute or rooted, and it is
//!   percent-encoded. Every comparison here happens after decoding, and the child's name is
//!   what remains after the parent's path -- not the last path segment, which gets a
//!   directory's own trailing slash wrong.
//! - **`PUT` needs a `Content-Length` it cannot always know.** The `Sink` buffers until
//!   `reserve` tells it the size, exactly as the HDFS one does, so a copy with a known size
//!   streams and a patch without one is held.
//!
//! There is deliberately no `Depth: infinity` walk even though the protocol offers one:
//! servers commonly refuse it (Apache's `DavDepthInfinity` is off by default), the reply is
//! unbounded in memory, and the per-directory walk parallelises across the same pool.

use crate::ports::KernelFileDescriptor as RawFd;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex};

use super::xml::{Event, Reader};
use super::Settings;
use crate::base64;
use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::net::http::{
    self, content_range_start, percent_decode, percent_encode, Connection, Scheme,
};
use crate::net::origin::{remote_error, Pool};
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree, ZEROS,
};
use crate::time::parse_http_date_ns;

/// `scheme`, host, port and the path of a `dav://` / `davs://` / `http://` / `https://` URL,
/// read by the shared [`http::split_url`] once the WebDAV scheme is written as the HTTP one
/// it stands for.
pub fn split_url(url: &str) -> io::Result<(Scheme, String, u16, String)> {
    if let Some(r) = url.strip_prefix("davs://") {
        http::split_url(&format!("https://{r}"))
    } else if let Some(r) = url.strip_prefix("dav://") {
        http::split_url(&format!("http://{r}"))
    } else if url.starts_with("http://") || url.starts_with("https://") {
        http::split_url(url)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url:?}: not a dav://, davs://, http:// or https:// URL"),
        ))
    }
}

/// The same URL written in its cleartext scheme, for `-dav.insecure`; `None` when it is
/// already cleartext and there is nothing to rewrite.
///
/// The rewrite happens BEFORE the split so the default port comes from the scheme the run
/// actually speaks. Applied after the split, as it was, `davs://host/p -dav.insecure` kept
/// the https default of 443 and then sent cleartext to it, and the pool's origin -- which
/// is also the `Destination` of every MOVE and COPY -- read `http://host:443`.
///
/// By prefix rather than by `replacen`, because a path may itself contain `https://` and
/// replacing the first occurrence anywhere would rewrite the path instead of the scheme.
///
/// What this does NOT fix, and cannot: behind a TLS terminator the server knows itself as
/// `https://host` while this run legitimately speaks `http://host`, and RFC 4918 wants the
/// `Destination` in the server's terms. Nothing here can know the external URI, so a
/// server that checks it will refuse the MOVE. That needs an option naming the public
/// origin, not a guess.
fn plain(url: &str) -> Option<String> {
    url.strip_prefix("davs://")
        .map(|r| format!("dav://{r}"))
        .or_else(|| url.strip_prefix("https://").map(|r| format!("http://{r}")))
}

/// One `<response>` of a multistatus, reduced to what a `Tree` needs.
struct Entry {
    /// the decoded path of the `href`, with no trailing slash
    path: String,
    dir: bool,
    size: u64,
    mtime_ns: i128,
}

/// Parses a `207 Multistatus` into entries. A `response` whose `propstat` says anything
/// but 2xx is skipped rather than failed on: a server may report one property it cannot
/// produce for one entry, and losing the whole listing over that would be worse.
///
/// `base` is the decoded path the request was made to. An href is usually absolute or
/// rooted, and RFC 4918 lets it be relative; a relative one is resolved against `base`.
///
/// The statuses are read PER PROPSTAT. One flag for the whole response is the obvious
/// shape, and on a conformant server it fails: a second propstat answering 403 or 424 for
/// a property this did not ask for (a quota, a lock token) clears the flag and the entry
/// vanishes from the listing. So each propstat's properties are held until its status is
/// read and applied only when that status is 2xx; the entry is kept when at least one
/// propstat was, or when a response-level status was. Properties under a refused propstat
/// are never applied, which a single flag also gets wrong in the other direction.
fn parse_multistatus(body: &str, base: &str) -> io::Result<Vec<Entry>> {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    let mut cur: Option<Entry> = None;
    // the properties of the propstat being read, applied at its end if its status allows.
    // Each is an Option because a tuple with defaults would let a second 2xx propstat
    // carrying only `getlastmodified` REPLACE the size the first one gave, with 0 -- two
    // blocks that did not conflict, merged by overwriting.
    let mut pending: Option<(Option<bool>, Option<u64>, Option<i128>)> = None;
    let mut keep = false;
    let mut has_href = false;
    let mut in_propstat = false;
    // What an earlier 2xx propstat of THIS response said `resourcetype` was, so a later
    // one that says the opposite can be caught rather than merged.
    let mut said_dir: Option<bool> = None;
    // Whether any 2xx propstat of THIS response gave a length this reader could parse.
    // `Entry.size` defaults to 0 and cannot distinguish "the server said zero" from "the
    // server said nothing", and those are different facts about a file.
    let mut had_size = false;
    while let Some(e) = r.next()? {
        match e {
            Event::Start {
                name: "response", ..
            } => {
                cur = Some(Entry {
                    path: String::new(),
                    dir: false,
                    size: 0,
                    mtime_ns: 0,
                });
                keep = false;
                has_href = false;
                in_propstat = false;
                pending = None;
                said_dir = None;
                had_size = false;
            }
            Event::Start {
                name: "propstat",
                empty: false,
            } => {
                in_propstat = true;
                pending = Some((None, None, None));
            }
            Event::End { name: "propstat" } => {
                in_propstat = false;
                pending = None;
            }
            Event::Start {
                name: "href",
                empty: false,
            } => {
                let href = r.text("href")?;
                has_href = true;
                if let Some(c) = cur.as_mut() {
                    // an href may be a full URL, a rooted path or a relative reference;
                    // either way only the path part is a position in the tree
                    let rel: String;
                    let path = match href
                        .find("://")
                        .and_then(|i| href[i + 3..].find('/').map(|j| i + 3 + j))
                    {
                        Some(i) => &href[i..],
                        None if href.starts_with('/') => href.as_str(),
                        None => {
                            // relative: `img.jpg` under the request path. `base` is
                            // already decoded, so it is encoded back before the common
                            // decode below rather than decoded twice. Dot segments are
                            // resolved as RFC 3986 says: `../peer` is a SIBLING of the
                            // request path, not a child called `peer` -- which is what
                            // trimming a leading `./` and nothing else made of it.
                            rel = remove_dot_segments(&format!(
                                "{}/{}",
                                percent_encode(base.trim_end_matches('/'), true),
                                href
                            ));
                            rel.as_str()
                        }
                    };
                    // A `?query` or `#fragment` is not part of the path. A literal `?` in
                    // a name arrives as `%3F`, so cutting BEFORE decoding loses nothing a
                    // conformant server sent; a server appending `?x=1` to every href
                    // (some do, behind a proxy) named files that did not exist.
                    let path = path.split(['?', '#']).next().unwrap_or("");
                    c.path = percent_decode(path).trim_end_matches('/').to_string();
                }
            }
            Event::Start {
                name: "resourcetype",
                empty,
            } => {
                let is_dir = if empty {
                    false
                } else {
                    r.child_names("resourcetype")?.contains(&"collection")
                };
                if let Some(p) = pending.as_mut() {
                    p.0 = Some(is_dir);
                }
            }
            Event::Start {
                name: "getcontentlength",
                empty: false,
            } => {
                let t = r.text("getcontentlength")?;
                if let Some(p) = pending.as_mut() {
                    // Not `unwrap_or(0)`: a length of zero is not a missing property --
                    // it is a positive assertion that the file is empty, which every later
                    // stage believes. `open()` takes the size verbatim, the reader returns
                    // EOF before the first byte, and `DavSink::finish` compares 0 written
                    // against 0 expected and agrees. Measured: with `unwrap_or(0)`, a file
                    // the server really serves 370 bytes of scanned as `0 bytes` with
                    // STATUS: PASSED.
                    //
                    // So an unreadable length is NO length, exactly as
                    // `getlastmodified` below treats a date it cannot read, and the
                    // response end refuses a file that never got one.
                    if let Ok(n) = t.trim().parse() {
                        p.1 = Some(n);
                    }
                }
            }
            Event::Start {
                name: "getlastmodified",
                empty: false,
            } => {
                let t = r.text("getlastmodified")?;
                if let Some(p) = pending.as_mut() {
                    // a date this cannot read is no date, and stays whatever an earlier
                    // propstat said rather than becoming the epoch
                    if let Some(ns) = parse_http_date_ns(t.trim()) {
                        p.2 = Some(ns);
                    }
                }
            }
            Event::Start {
                name: "status",
                empty: false,
            } => {
                let t = r.text("status")?;
                // `HTTP/1.1 200 OK`. Inside a propstat, a 404 is the server listing a
                // property it does not have, which is normal and keeps the entry. A
                // status directly under the RESPONSE is about the resource itself (RFC
                // 4918 lets a server answer that way instead of with a propstat), and
                // there a 404 is a missing resource. Applying the carve-out to every
                // status alike would list it as a file of size 0.
                let code = t
                    .split_whitespace()
                    .nth(1)
                    .and_then(|c| c.parse::<u16>().ok());
                match (in_propstat, code) {
                    (true, Some(code)) if (200..300).contains(&code) => {
                        if let (Some(c), Some((dir, size, mtime))) = (cur.as_mut(), pending.take())
                        {
                            if let Some(d) = dir {
                                // A propstat that OMITS a property cannot clobber one that
                                // carries it (see `pending`). This is the other case: two
                                // 2xx propstats both CARRY `resourcetype` and disagree. A
                                // flat write lets whichever arrives last win, and a
                                // `<D:collection/>` followed by an empty `<D:resourcetype/>`
                                // turns a collection into a file.
                                //
                                // Letting collection win is tempting, on the argument that its
                                // failure is "wrong but plainly so". It is not. Read as a
                                // collection, a FILE is PROPFINDed, answers with only itself, that
                                // self-entry is dropped, and the copy writes an empty directory and
                                // EXITS 0 -- the file's bytes are simply gone, and nothing in the
                                // run says so. That is not plainer than the other direction; it is
                                // the same silent loss wearing a different shape, and it is the
                                // shape that loses DATA.
                                //
                                // Neither answer is truthful, because a server that
                                // contradicts itself about one entry is telling us it does
                                // not know what that entry is. So the entry is refused by
                                // name, which is what this crate does everywhere else with
                                // something it cannot represent, and the run fails loudly
                                // instead of guessing. Dropping just the entry was the
                                // other candidate and is no better: a `copy` would omit a
                                // file and still exit 0.
                                match said_dir {
                                    Some(prev) if prev != d => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("{}: the server's PROPFIND says this is a collection in one propstat and not in another, so what it is cannot be known from its answer", c.path),
                                        ))
                                    }
                                    _ => said_dir = Some(d),
                                }
                                c.dir = d;
                            }
                            if let Some(n) = size {
                                c.size = n;
                                had_size = true;
                            }
                            if let Some(m) = mtime {
                                c.mtime_ns = m;
                            }
                        }
                        keep = true;
                    }
                    // a refused propstat: its properties are dropped, the entry is not
                    (true, _) => pending = None,
                    (false, Some(code)) if (200..300).contains(&code) => keep = true,
                    // a response-level status that is not 2xx is about the resource:
                    // 404 here is a missing resource, not a missing property
                    (false, _) => {
                        keep = false;
                        cur = None;
                    }
                }
            }
            Event::End { name: "response" } => {
                if let Some(c) = cur.take() {
                    // An entry is kept when it HAS an href, not when the href is
                    // non-empty: the server's root decodes to `""`, and the test that
                    // dropped empty paths made `dav://host/` -- a share served at the
                    // root -- unopenable. Found by the first unit arm to open one.
                    if keep && has_href {
                        // A FILE with no readable length is refused by name, for the same
                        // reason the contradictory `resourcetype` above is: the server has
                        // not told us what this entry is, and every candidate default is a
                        // claim it did not make. Zero is the worst of them -- it reads as
                        // "empty file" all the way down, so the copy writes nothing, the
                        // sink's own size check compares 0 against 0 and agrees, and
                        // `verify` compares the same wrong number against itself.
                        //
                        // Directories are exempt: a collection has no content length and
                        // conformant servers omit it.
                        if !c.dir && !had_size {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("{}: the server's PROPFIND gave this file no readable getcontentlength, so its length is unknown; treating that as zero would copy an empty file and report success", c.path),
                            ));
                        }
                        out.push(c);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// RFC 3986 section 5.2.4 over a rooted path: `.` segments are dropped, `..` removes the
/// segment before it, and a `..` at the root stays at the root. A trailing `/` from a
/// trailing `.` or `..` is kept, since a collection's href ends in one.
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            "." => {}
            ".." => {
                out.pop();
            }
            s if s.is_empty() && i != 0 && i != last => {} // `a//b`: an empty segment
            s => out.push(s),
        }
    }
    let mut joined = out.join("/");
    if !joined.starts_with('/') {
        joined.insert(0, '/');
    }
    if matches!(segments.last(), Some(&".") | Some(&"..")) && !joined.ends_with('/') {
        joined.push('/');
    }
    joined
}

/// How many `<status>` lines of a multistatus are not 2xx. A 207 to a DELETE lists the
/// members the server could not remove, each with its own status.
///
/// Fallible, and the reason is what an infallible version does: stopping at a parse error
/// and returning the count so far, a 207 whose body was cut off before its first
/// `<status>` counts as zero failures, and zero failures is `Gone`. A body this
/// cannot read is an answer this cannot act on; it is an error, not a removal.
fn failed_members(body: &str) -> io::Result<(usize, Vec<u16>)> {
    let mut r = Reader::new(body);
    let mut failed = 0;
    let mut worst: Vec<u16> = Vec::new();
    let mut statuses = 0;
    while let Some(e) = r.next()? {
        if let Event::Start {
            name: "status",
            empty: false,
        } = e
        {
            statuses += 1;
            let t = r.text("status")?;
            match t
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
            {
                // 404 and 410 on a member of a DELETE mean it was not there to remove,
                // which is the end state asked for. Counting them as failures reported a
                // collection as `Kept` when part of it was already gone.
                Some(404) | Some(410) => {}
                Some(code) if !(200..300).contains(&code) => {
                    failed += 1;
                    worst.push(code);
                }
                Some(_) => {}
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("a multistatus member has a status this cannot read: {t:?}"),
                    ))
                }
            }
        }
    }
    if statuses == 0 {
        // a 207 is a list of statuses; one with none is not saying what happened
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the server answered 207 with no member statuses",
        ));
    }
    Ok((failed, worst))
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

pub struct DavTree {
    pool: Arc<Pool>,
    /// the decoded path of the root on the server, with no trailing slash
    root: String,
    display: PathBuf,
}

/// Whether a redirect's `Location` is `target` with a slash appended, written as a
/// path or as an absolute URI on this origin. Anything else -- another host, another
/// path, a scheme change -- is not this and stays refused.
fn only_adds_slash(origin: &str, location: &str, target: &str) -> bool {
    // Absolute, it is read with the same splitter as the endpoint URL, so a default
    // port the server left out (`http://host/p/`) still names this origin.
    let path = if location.starts_with("http://") || location.starts_with("https://") {
        match http::split_url(location) {
            Ok((scheme, host, port, path))
                if Pool::key(scheme, &host.to_ascii_lowercase(), port)
                    == origin.to_ascii_lowercase() =>
            {
                path
            }
            _ => return false,
        }
    } else {
        location.to_string()
    };
    // Compared decoded, because a server may escape a name differently from the way
    // this adapter did and still mean the same resource.
    percent_decode(&path) == format!("{}/", percent_decode(target))
}

impl DavTree {
    /// Opens `url` as a collection; with `create` a missing root is `MKCOL`ed.
    pub fn connect(
        url: &str,
        create: bool,
        settings: &Settings,
        log: Arc<dyn crate::ports::Log>,
    ) -> io::Result<DavTree> {
        // `-dav.insecure` used to be applied AFTER the split, which left the port behind:
        // the https default 443 was taken from the URL as written and then spoken to in
        // cleartext, so `davs://host/p -dav.insecure` dialed the TLS port with plain HTTP
        // and the origin read `http://host:443`. Rewriting the scheme FIRST makes the
        // default port come from the scheme the run actually speaks, and an explicit
        // `:port` still wins because it is in the authority either way.
        //
        // Done by prefix, not by `replacen`: a path may contain `https://` (an endpoint
        // named after a URL), and replacing the first occurrence anywhere would rewrite
        // the path instead of the scheme.
        let insecure_url;
        let url = match settings.insecure.then(|| plain(url)).flatten() {
            Some(rewritten) => {
                insecure_url = rewritten;
                insecure_url.as_str()
            }
            None => url,
        };
        let (scheme, host, port, path) = split_url(url)?;
        let scheme = if settings.insecure {
            Scheme::Http
        } else {
            scheme
        };
        let origin = Pool::key(scheme, &host, port);
        let auth = settings
            .user
            .clone()
            .or_else(|| {
                match (
                    std::env::var("RCP_DAV_USER"),
                    std::env::var("RCP_DAV_PASSWORD"),
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
                Some(crate::net::tls::config(settings.noverify)?)
            } else {
                None
            },
        });
        let root = percent_decode(&path).trim_end_matches('/').to_string();
        let display = PathBuf::from(format!(
            "{}{}",
            origin
                .replacen("http://", "dav://", 1)
                .replacen("https://", "davs://", 1),
            if root.is_empty() { "/" } else { &root }
        ));
        let t = DavTree {
            pool,
            root,
            display,
        };
        match t.propfind_one(".")? {
            Some(e) if e.dir => {}
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: not a collection", t.display.display()),
                ))
            }
            None if create => {
                t.mkcol(".")?;
            }
            // Not refused here when it is not to be created: a dry run opens its destination
            // this way, and a destination that does not exist yet is an empty one to plan
            // against -- refused, `-dryrun` into a new directory on this transport would fail
            // at open while the same run into a local one planned it. A SOURCE that
            // is not there still fails: its listing answers `NotFound`, which ends the run.
            None => {}
        }
        Ok(t)
    }

    /// The decoded server path of `rel`.
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

    /// The request target for `rel`: the encoded path, with a trailing slash for a
    /// collection because several servers answer 301 to the slashless form and this
    /// adapter refuses redirects.
    fn target(&self, rel: &str, dir: bool) -> String {
        let p = percent_encode(&self.abs(rel), true);
        if dir && !p.ends_with('/') {
            format!("{p}/")
        } else {
            p
        }
    }

    /// The `Destination` of a `MOVE` or `COPY`: an absolute URI. RFC 4918 allows a rooted
    /// path too, but RFC 2518 did not and servers of that vintage answer 400 to one,
    /// while every server accepts the absolute form -- so it is the only form sent.
    fn destination(&self, rel: &str) -> String {
        format!("{}{}", self.pool.origin, self.target(rel, false))
    }

    fn item_of(&self, rel: String, e: &Entry) -> Item {
        let size = if e.dir { 0 } else { e.size };
        Item {
            ino: fnv64(&e.path),
            rel,
            kind: if e.dir { Kind::Dir } else { Kind::File },
            size,
            mtime_ns: e.mtime_ns,
            atime_ns: e.mtime_ns,
            // A server keeps no mode. These are what a fresh file and directory get
            // locally, so a copy OUT of WebDAV lands with ordinary permissions rather
            // than with zero, and `-nomods` is the way to ask for something else.
            mode: if e.dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            dev: 0,
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    fn propfind(&self, rel: &str, depth: &str, dir: bool) -> io::Result<Vec<Entry>> {
        const BODY: &[u8] = br#"<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop></D:propfind>"#;
        let ask = |dir: bool| {
            self.pool.request(
                "PROPFIND",
                &self.target(rel, dir),
                &[
                    ("depth", depth),
                    ("content-type", "application/xml; charset=utf-8"),
                ],
                BODY,
            )
        };
        let mut r = ask(dir)?;
        // Asked without the slash, a collection on Apache's mod_dav (and nginx, and IIS)
        // answers 301 to the same path WITH one, and the adapter refuses redirects -- so
        // `dav://host/dav/t` failed at open with "HTTP 301" against a real server while
        // every stand-in answered 207. Only that one redirect is taken: it names the
        // same resource, so following it moves nothing to another host or path.
        if !dir
            && matches!(r.status, 301 | 302 | 307 | 308)
            && r.header("location")
                .is_some_and(|l| only_adds_slash(&self.pool.origin, l, &self.target(rel, false)))
        {
            crate::debug!(
                self.pool.log,
                "dav PROPFIND {rel}: {} to the collection form",
                r.status
            );
            r = ask(true)?;
        }
        crate::debug!(
            self.pool.log,
            "dav PROPFIND {rel} depth={depth}: {}",
            r.status
        );
        if r.status == 404 {
            return Ok(Vec::new());
        }
        if r.status != 207 {
            return Err(remote_error(&r, rel));
        }
        parse_multistatus(&String::from_utf8_lossy(&r.body), &self.abs(rel))
    }

    /// `PROPFIND Depth: 0`, the nearest thing WebDAV has to a `stat`.
    fn propfind_one(&self, rel: &str) -> io::Result<Option<Entry>> {
        // Asked WITHOUT the trailing slash, because that form answers for a file and a
        // collection alike; the slash form is only needed once the kind is known.
        match self.propfind(rel, "0", false) {
            Ok(v) => Ok(v.into_iter().next()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn mkcol(&self, rel: &str) -> io::Result<()> {
        let r = self
            .pool
            .request("MKCOL", &self.target(rel, true), &[], &[])?;
        match r.status {
            // 405 here is "it is already a collection", which is the state asked for
            200..=299 | 405 => Ok(()),
            _ => Err(remote_error(&r, rel)),
        }
    }

    /// One collection's children, as items with full relative paths.
    fn list_dir(&self, rel: &str) -> io::Result<Vec<Item>> {
        let parent = self.abs(rel).trim_end_matches('/').to_string();
        let mut out = Vec::new();
        let mut elsewhere: Option<String> = None;
        for e in self.propfind(rel, "1", true)? {
            // The collection itself comes back first in its own listing. Dropping it by
            // PATH rather than by position is what makes this terminate on a server that
            // orders the responses differently -- and one does.
            if e.path == parent {
                continue;
            }
            let Some(name) = e.path.strip_prefix(&format!("{parent}/")) else {
                crate::debug!(
                    self.pool.log,
                    "dav {rel}: ignoring {:?}, which is not under {parent:?}",
                    e.path
                );
                elsewhere.get_or_insert_with(|| e.path.clone());
                continue;
            };
            if name.is_empty() || name.contains('/') {
                continue; // a server that returned deeper entries than Depth: 1 asked for
            }
            // `%2e%2e` decodes to `..`, and a child called `..` is the parent: a listing
            // that carried one walked up out of the root and never terminated. Neither
            // `.` nor `..` can be a child of anything, so both are ignored by name.
            if name == "." || name == ".." {
                crate::debug!(
                    self.pool.log,
                    "dav {rel}: ignoring a child called {name:?}, which cannot be one"
                );
                continue;
            }
            let child = if rel == "." {
                name.to_string()
            } else {
                format!("{rel}/{name}")
            };
            out.push(self.item_of(child, &e));
        }
        // A server answering under a DIFFERENT prefix than the one asked -- Nextcloud
        // has been seen answering `/files/user/...` for a request under
        // `/remote.php/dav/files/user/...` behind some proxies -- produced an empty
        // listing and a debug line, which reads as "the collection is empty". When
        // nothing at all was under the requested path and something was elsewhere,
        // that is the server's answer and it is an error with the prefix in it.
        if out.is_empty() {
            if let Some(other) = elsewhere {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{rel}: the server lists this collection under {other:?}, not under {parent:?}; name the path the server uses")));
            }
        }
        Ok(out)
    }

    fn handle(&self) -> DavHandle {
        DavHandle {
            pool: self.pool.clone(),
            root: self.root.clone(),
        }
    }
}

fn now_ns() -> i128 {
    filter::now_ns()
}

impl Tree for DavTree {
    type Reader = DavReader;
    type Sink = DavSink;

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
        let root = match self.propfind_one(".")? {
            Some(e) => self.item_of(".".into(), &e),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{}: no such collection", self.display.display()),
                ))
            }
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
        let now = now_ns();
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
                                    if !is_dir
                                        && !filter.allows_owner_kind(
                                            item.kind, item.uid, item.gid, item.ino,
                                        )
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
        listing.items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        listing.errors.sort();
        Ok(listing)
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        Ok(self
            .propfind_one(rel)?
            .map(|e| self.item_of(rel.to_string(), &e)))
    }

    fn open(&self, rel: &str) -> io::Result<DavReader> {
        let size = self
            .propfind_one(rel)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{rel}: no such file")))?
            .size;
        Ok(DavReader {
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

    fn create_file(&self, item: &Item) -> io::Result<DavSink> {
        Ok(DavSink {
            tree: self.handle(),
            rel: item.rel.clone(),
            expected: None,
            pos: 0,
            state: SinkState::Idle,
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut DavSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        if rel == "." {
            return Ok(());
        }
        self.mkcol(rel)
    }

    fn symlink(&self, rel: &str, _target: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{rel}: WebDAV has no symlinks"),
        ))
    }

    fn hard_link(&self, _existing: &str, _rel: &str) -> io::Result<()> {
        // WebDAV has no links. The server-side COPY this used to issue does save the
        // bytes on the wire -- that part of the old comment was true -- but it returns
        // `Ok(())`, so the run reported `N linked` for two independent resources, and
        // `verify` then reported `DIFF hardlink` for that group forever. `describe` says
        // `hard_links: false` for dav already. See the HDFS one for the measurement;
        // `copy_tree` turns `Unsupported` into a plain copy, which is what the second
        // name actually is.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WebDAV has no hard links",
        ))
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        // A COLLECTION DELETE IS RECURSIVE -- RFC 4918 9.6.1 has it act as `Depth: infinity`
        // and allows no other depth -- where every other adapter's directory removal is an
        // rmdir that refuses a non-empty directory. The planner removes children first, so
        // the collection is empty by the time an unscoped run reaches it; what can still be
        // inside is what the run did NOT look at: a name excluded by a filter, one below
        // `-depth`, one a sync's catalog never recorded. `isync -depth 1` to a collection
        // holding `d/hidden` would delete `hidden` with `d`. So the collection is listed
        // first and a non-empty one is refused the way rmdir refuses it.
        //
        // WHAT THIS DOES NOT CLOSE, and it is tempting to call it the ordinary sync race, which it
        // is not: a name that appears between this listing and the DELETE is deleted WITH the
        // collection, where rmdir would refuse and leave it. WebDAV has no non-recursive delete to
        // send instead. The window is one round trip, and only on a collection the source no longer
        // has.
        if kind == Kind::Dir {
            let inside = self.list_dir(rel)?;
            if !inside.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::DirectoryNotEmpty,
                    format!("{rel}: the collection still holds {} entr{} this run did not remove, and a collection DELETE would remove them with it", inside.len(), if inside.len() == 1 { "y" } else { "ies" }),
                ));
            }
        }
        let r = self
            .pool
            .request("DELETE", &self.target(rel, kind == Kind::Dir), &[], &[])?;
        match r.status {
            // A collection DELETE may answer 207 with a status per member, and `200..=299`
            // would swallow it: a member the server could not remove would be counted gone
            // with the rest. The statuses are read.
            // The member statuses decide, and 401 among them is NOT `Kept`.
            //
            // This arm is matched BEFORE the `_` arm below, so a 207 never reaches
            // `delete_refused` -- and were `failed_members` to return only a COUNT, a member
            // answering 401 would be indistinguishable from one answering 423 and become
            // "the server kept 1 member; run sync again". That is the exact defect the
            // 401/403 split exists to close, reopened one layer in. Only reading the two
            // functions side by side shows it; the contract arm for the non-207 path cannot,
            // because it never sends a multistatus body.
            207 => match failed_members(&String::from_utf8_lossy(&r.body)) {
                Ok((0, _)) => Ok(Removed::Gone),
                Ok((n, codes)) if codes.iter().any(|c| *c == 401 || *c == 407) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{rel}: the store did not accept this run's credentials for {n} member{} of this collection; every removal will answer the same until they are fixed, so rerunning changes nothing", if n == 1 { "" } else { "s" }),
                )),
                Ok((n, _)) => Ok(Removed::Kept(format!("the server removed part of it and kept {n} member{}", if n == 1 { "" } else { "s" }))),
                Err(e) => Err(io::Error::new(e.kind(), format!("{rel}: the 207 to its DELETE could not be read, so what was removed is unknown: {e}"))),
            },
            200..=299 | 404 | 410 => Ok(Removed::Gone),
            // 423 is a lock somebody else holds: the server answered, and the entry stays.
            // Neither a fault in this run nor a removal, which is exactly what `Kept` is.
            423 => Ok(Removed::Kept("the server has it locked".into())),
            // and a 403 is the same kind of answer as the 423 above -- the server replied
            // and refused -- so it does not belong in the failure bucket, here or in any
            // other adapter.
            //
            // A 401 is NOT, and keying on the error kind would sweep it in: `kind_of_status`
            // calls 401, 403 and 423 all `PermissionDenied`, so the kind cannot tell them
            // apart. `delete_refused` decides from the status. See it for why the two
            // remedies differ.
            _ => http::delete_refused(r.status, rel, remote_error(&r, rel)),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let r = self.pool.request(
            "MOVE",
            &self.target(from, false),
            &[("destination", &self.destination(to)), ("overwrite", "T")],
            &[],
        )?;
        if r.ok() {
            Ok(())
        } else {
            Err(remote_error(&r, to))
        }
    }

    fn set_metadata(&self, _rel: &str, _item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        // A server keeps `getlastmodified` as a record of when IT was written, and the
        // live properties are read-only in the protocol. So this refuses rather than
        // issuing a PROPPATCH that a server would accept and ignore.
        //
        // `Refusals` can only say `owner` and `xattrs`, so the mode and the times go
        // unreported here -- and that is covered at the command level instead:
        // `rewrites_metadata_in_place` is false, so `chmod` and `chown` refuse by name
        // before a request is made. A copy's `-nomods` is the way to stop asking.
        Ok(Refusals {
            owner: opts.owner,
            xattrs: Vec::new(),
        })
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|(n, _)| n.clone()).collect())
    }

    fn restore_atime(&self, _item: &Item) -> io::Result<()> {
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    fn keeps_times(&self) -> bool {
        // `getlastmodified` is when the SERVER wrote it, and it is read-only
        false
    }

    // a WebDAV collection carries no mode, owner or xattr: the adapter synthesizes 0644/0755 and uid 0
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
        // The same answer as a registry and a tar stream, for a different reason: the
        // properties this crate would change are live and read-only, so `chmod` and
        // `chown` refuse up front instead of reporting entries they did not change.
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
        // COPY is server-side but only WITHIN one server, and `native_copy` is called with
        // two trees that may be different ones. Refused rather than silently wrong.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no server-side batch copy between two WebDAV endpoints",
        ))
    }
}

/// What a reader or sink needs from the tree, without borrowing it.
#[derive(Clone)]
struct DavHandle {
    pool: Arc<Pool>,
    root: String,
}

impl DavHandle {
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

/// A streaming `GET`, reissued with a `Range` after a seek.
pub struct DavReader {
    tree: DavHandle,
    rel: String,
    size: u64,
    pos: u64,
    conn: Option<(Scheme, String, u16, Connection)>,
}

impl DavReader {
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
        // A server free to ignore a `Range` answers 200 with the whole file, and every
        // byte from `pos` on would then really be a byte from zero -- the head of the file
        // written at its tail. The registry client learned this the expensive way; it is
        // refused here before a byte is placed rather than after.
        if self.pos > 0 && r.status == 200 {
            let _ = conn.drain();
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: asked for bytes from {} and the server answered 200 with the whole file; it does not honor Range", self.rel, self.pos)));
        }
        // And a 206 is only half an answer: the OTHER half is `Content-Range`, which says
        // where the bytes it carries start. A server answering 206 from zero -- such
        // servers exist, and the stand-in models one -- would be accepted by the status
        // alone and its bytes placed at `pos`. The header is required and read.
        if self.pos > 0 && r.status == 206 {
            // the registry client's reader: unit case-insensitive, `bytes */N` refused
            let start = r.header("content-range").and_then(content_range_start);
            match start {
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

impl Read for DavReader {
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

impl Seek for DavReader {
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

enum SinkState {
    Idle,
    Buffering(Vec<u8>),
    Streaming(Scheme, String, u16, Connection),
}

/// A `PUT`. Streams when `reserve` gave it a length, buffers when it did not, because a
/// `PUT` needs a `Content-Length` before the first byte and chunked upload is optional in
/// the protocol and refused by enough servers not to be worth relying on.
pub struct DavSink {
    tree: DavHandle,
    rel: String,
    expected: Option<u64>,
    pos: u64,
    state: SinkState,
}

impl DavSink {
    fn start(&mut self, len: u64) -> io::Result<()> {
        let (scheme, host, port, _) = split_url(&format!("{}/", self.tree.pool.origin))?;
        let mut conn = self.tree.pool.take(scheme, &host, port)?;
        conn.send_head(
            "PUT",
            &self.tree.target(&self.rel),
            &self
                .tree
                .pool
                .headers(&[("content-type", "application/octet-stream")]),
            len,
        )?;
        self.state = SinkState::Streaming(scheme, host, port, conn);
        Ok(())
    }

    fn finish_put(&mut self) -> io::Result<()> {
        let SinkState::Streaming(scheme, host, port, mut conn) =
            std::mem::replace(&mut self.state, SinkState::Idle)
        else {
            return Err(io::Error::other("no PUT in flight"));
        };
        let mut r = conn.read_head(false)?;
        r.body = conn.drain()?;
        self.tree.pool.give(scheme, &host, port, conn);
        if r.ok() {
            Ok(())
        } else {
            Err(remote_error(&r, &self.rel))
        }
    }
}

impl Sink for DavSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        self.expected = Some(len);
        self.start(len)
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.state {
            SinkState::Idle => self.state = SinkState::Buffering(data.to_vec()),
            SinkState::Buffering(b) => b.extend_from_slice(data),
            SinkState::Streaming(_, _, _, conn) => {
                if let Some(expected) = self.expected {
                    if self.pos + data.len() as u64 > expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{}: more bytes than the {expected} declared", self.rel),
                        ));
                    }
                }
                conn.write_body(data)?;
            }
        }
        self.pos += data.len() as u64;
        Ok(())
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
        opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        if let Some(expected) = self.expected {
            if self.pos != expected {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: {} bytes arrived for {expected} declared (the source changed during the copy)", self.rel, self.pos)));
            }
        }
        match std::mem::replace(&mut self.state, SinkState::Idle) {
            SinkState::Idle => {
                self.start(0)?;
                self.finish_put()?;
            }
            SinkState::Buffering(buf) => {
                self.start(buf.len() as u64)?;
                if let SinkState::Streaming(_, _, _, conn) = &mut self.state {
                    conn.write_body(&buf)?;
                }
                self.finish_put()?;
            }
            s @ SinkState::Streaming(..) => {
                self.state = s;
                self.finish_put()?;
            }
        }
        // Refused rather than attempted: the properties are live and read-only, and a
        // PROPPATCH a server accepts and ignores would be the silent success this crate
        // keeps hunting.
        Ok(Refusals {
            owner: opts.owner,
            xattrs: xattrs.iter().map(|(n, _)| n.clone()).collect(),
        })
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_is_split_the_same_way_the_other_http_adapters_split_one() {
        let ok = |u: &str| {
            let (s, h, p, path) = split_url(u).unwrap_or_else(|e| panic!("{u}: {e}"));
            (s == Scheme::Https, h, p, path)
        };
        assert_eq!(
            ok("dav://host/a/b"),
            (false, "host".into(), 80, "/a/b".into())
        );
        assert_eq!(ok("davs://host/a"), (true, "host".into(), 443, "/a".into()));
        assert_eq!(
            ok("dav://host:8080/a"),
            (false, "host".into(), 8080, "/a".into())
        );
        // `http://` and `https://` are accepted too, because a server's own Destination
        // header and a user's copy-paste both use them
        assert_eq!(
            ok("https://host/a"),
            (true, "host".into(), 443, "/a".into())
        );
        // the authority is what follows the last `@`, as everywhere else
        assert_eq!(
            ok("dav://user:pw@host:8080/a"),
            (false, "host".into(), 8080, "/a".into())
        );
        assert_eq!(
            ok("davs://[::1]:8443/a"),
            (true, "[::1]".into(), 8443, "/a".into())
        );
        assert_eq!(
            ok("dav://[::1]/a"),
            (false, "[::1]".into(), 80, "/a".into())
        );
        for bad in [
            "ftp://host/a",
            "dav://[::1/a",
            "dav://@/a",
            "dav://[]/a",
            "dav://::1/a",
            "dav://[::1]x/a",
        ] {
            assert!(split_url(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn a_path_survives_encoding_and_decoding_including_the_characters_that_need_it() {
        for s in [
            "/a/b",
            "/a b/c",
            "/a+b",
            "/%zz",
            "/naïve/ünïcode",
            "/a?b#c",
            "/100%",
        ] {
            assert_eq!(percent_decode(&percent_encode(s, true)), s, "{s}");
        }
        // a space is `%20` and not `+`: `+` is form encoding and a server reads it as a
        // literal plus in a path, so a file named `a+b` and one named `a b` would collide
        assert_eq!(percent_encode("/a b", true), "/a%20b");
        assert_eq!(percent_encode("/a+b", true), "/a%2Bb");
        // the control: an already-safe path is unchanged, so the encoder is not simply
        // escaping everything
        assert_eq!(percent_encode("/a/b-c_d.e~f", true), "/a/b-c_d.e~f");
        // and a broken escape is left visible rather than dropped
        assert_eq!(percent_decode("/a%zzb"), "/a%zzb");
        assert_eq!(percent_decode("/a%"), "/a%");
    }

    #[test]
    fn a_multistatus_is_read_into_entries_and_the_collection_drops_its_own_self_entry() {
        let body = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/dir/</D:href><D:propstat><D:prop>
    <D:resourcetype><D:collection/></D:resourcetype></D:prop>
    <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
  <D:response><D:href>/dav/dir/a%20file.txt</D:href><D:propstat><D:prop>
    <D:resourcetype/><D:getcontentlength>12</D:getcontentlength>
    <D:getlastmodified>Tue, 15 Nov 1994 12:45:26 GMT</D:getlastmodified></D:prop>
    <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir").unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].path.as_str(), e[0].dir), ("/dav/dir", true));
        assert_eq!(
            (e[1].path.as_str(), e[1].dir, e[1].size),
            ("/dav/dir/a file.txt", false, 12)
        );
        assert_eq!(e[1].mtime_ns, 784_903_526_000_000_000);
        // an absolute href carries a scheme and authority the path must be taken out of
        let abs = body.replace("<D:href>/dav/", "<D:href>https://host:8443/dav/");
        let e = parse_multistatus(&abs, "/dav/dir").unwrap();
        assert_eq!(e[1].path, "/dav/dir/a file.txt");
    }

    #[test]
    fn a_response_the_server_could_not_produce_is_skipped_and_a_404_propstat_is_not_one() {
        // A 403 on the whole response: skip it rather than lose the listing.
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/a</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop>
    <D:status>HTTP/1.1 403 Forbidden</D:status></D:propstat></D:response>
  <D:response><D:href>/b</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop>
    <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir").unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].path, "/b");
        // The control, and the reason the 404 case is carved out: a server routinely
        // answers a SECOND propstat with 404 listing the properties it does not have, and
        // reading that as "skip this entry" loses every file on such a server.
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/b</D:href>
    <D:propstat><D:prop><D:resourcetype/><D:getcontentlength>5</D:getcontentlength></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status></D:propstat>
    <D:propstat><D:prop><D:getcontentlanguage/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir").unwrap();
        assert_eq!(
            e.len(),
            1,
            "a 404 propstat dropped an entry the server DID describe"
        );
        assert_eq!(e[0].size, 5);
    }

    /// A share served at the server's root has an empty path, and is an entry.
    #[test]
    fn a_collection_at_the_server_root_is_an_entry_with_an_empty_path() {
        let body = r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir").unwrap();
        assert_eq!(e.len(), 1, "the root was dropped");
        assert!(e[0].dir);
        assert!(e[0].path.is_empty());
        // the control: a response with no href at all is still dropped
        let e = parse_multistatus(&body.replace("<D:href>/</D:href>", ""), "/").unwrap();
        assert!(e.is_empty());
    }

    /// A status directly under the response is about the resource, and a 404 there is a
    /// missing resource; only a 404 INSIDE a propstat is a missing property.
    #[test]
    fn a_response_level_404_is_a_missing_resource_and_not_a_missing_property() {
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/missing</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>
  <D:response><D:href>/dav/here</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
    <D:propstat><D:prop><D:foo/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav").unwrap();
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            ["/dav/here"],
            "a resource the server said was missing is listed"
        );
    }

    /// A second propstat refusing a property this did not ask for keeps the entry, and
    /// the properties under the refused propstat are not applied.
    #[test]
    fn a_refused_propstat_neither_drops_the_entry_nor_supplies_its_properties() {
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/f</D:href>
    <D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
    <D:propstat><D:prop><D:quota-used-bytes/></D:prop><D:status>HTTP/1.1 403 Forbidden</D:status></D:propstat>
    <D:propstat><D:prop><D:getcontentlength>999</D:getcontentlength></D:prop><D:status>HTTP/1.1 424 Failed Dependency</D:status></D:propstat>
  </D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav").unwrap();
        assert_eq!(e.len(), 1, "a 403 propstat dropped the entry");
        assert_eq!(
            e[0].size, 7,
            "a property under a refused propstat was applied"
        );
        // the control: an entry whose ONLY propstat is refused is still skipped
        let only = r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/g</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 403 Forbidden</D:status></D:propstat></D:response></D:multistatus>"#;
        assert!(parse_multistatus(only, "/dav").unwrap().is_empty());
    }

    /// A listing the server gives under another prefix is an error naming that prefix,
    /// not an empty collection.
    #[test]
    fn a_listing_under_another_prefix_is_an_error_and_not_an_empty_collection() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            href_prefix: Some("/elsewhere"),
            ..Quirks::default()
        });
        let t = tree(&s, "/in");
        let l = t.list(&Filter::default(), None, 1).unwrap();
        assert_eq!(
            l.items.len(),
            1,
            "children under another prefix were listed as this collection's"
        );
        assert_eq!(l.errors.len(), 1, "{:?}", l.errors);
        assert!(
            l.errors[0].contains("/elsewhere/in")
                && l.errors[0].contains("name the path the server uses"),
            "{}",
            l.errors[0]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Two 2xx propstats that do not conflict are merged: one carrying the size and one
    /// the date give an entry with both. A tuple of defaults per propstat gave size 0.
    #[test]
    fn two_successful_propstats_merge_rather_than_overwrite() {
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/f</D:href>
    <D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
    <D:propstat><D:prop><D:getlastmodified>Tue, 15 Nov 1994 12:45:26 GMT</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
  </D:response>
  <D:response><D:href>/dav/d/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
    <D:propstat><D:prop><D:getlastmodified>Tue, 15 Nov 1994 12:45:26 GMT</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
  </D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav").unwrap();
        assert_eq!(
            (e[0].size, e[0].mtime_ns),
            (7, 784_903_526_000_000_000),
            "the second propstat overwrote the first"
        );
        assert!(
            e[1].dir,
            "a later propstat without resourcetype turned the collection into a file"
        );
        // and a date the reader cannot parse leaves an earlier date standing rather
        // than replacing it with the epoch
        let e = parse_multistatus(&body.replace("<D:getlastmodified>Tue, 15 Nov 1994 12:45:26 GMT</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n  </D:response>\n  <D:response><D:href>/dav/d/</D:href>", "<D:getlastmodified>Tue, 15 Nov 1994 12:45:26 GMT</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat><D:propstat><D:prop><D:getlastmodified>junk</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n  </D:response>\n  <D:response><D:href>/dav/d/</D:href>"), "/dav").unwrap();
        assert_eq!(e[0].mtime_ns, 784_903_526_000_000_000);
    }

    /// The case the merge arm above does NOT cover: both propstats are 2xx and both CARRY
    /// `resourcetype`, disagreeing. An unconditional write lets whichever comes last win,
    /// and a collection becomes a file.
    ///
    /// NEITHER answer is taken. A server that contradicts itself about one entry is
    /// telling us it does not know what that entry is, and both guesses lose data: a
    /// collection read as a file is GET, and what a server renders for one -- an HTML
    /// index -- is written into a file under that name; a FILE read as a collection is
    /// PROPFINDed, answers with only itself, that self-entry is dropped, and the copy
    /// writes an empty directory and EXITS 0 with the bytes gone.
    ///
    /// **Keep this arm's name and the reasoning above in step with its body.** A name such
    /// as `..._resolve_to_the_collection` over a body that requires an `Err` still
    /// compiles, and that is exactly how an overstated claim outlives the code it was
    /// about.
    ///
    /// Blast radius, stated precisely because it is easy to overstate: the `Err` ends THIS PROPFIND
    /// body, which WebDAV issues per directory at Depth 1. `list` records it in `Listing.errors`
    /// and the walk continues into siblings, so one contradictory entry costs that directory's
    /// children and fails the run -- it does not stop the tree.
    #[test]
    fn two_propstats_that_disagree_on_resourcetype_are_refused_rather_than_guessed() {
        let both = |first: &str, second: &str| {
            let body = format!(
                r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/x</D:href>
                <D:propstat><D:prop>{first}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
                <D:propstat><D:prop>{second}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
                </D:response></D:multistatus>"#
            );
            parse_multistatus(&body, "/dav")
        };
        let coll = "<D:resourcetype><D:collection/></D:resourcetype>";
        // the length is here so the `file, file` control below reaches the resourcetype
        // question rather than tripping the separate refusal of a file with no readable
        // `getcontentlength` -- two different defects, and this arm is about the first
        let file = "<D:resourcetype/><D:getcontentlength>7</D:getcontentlength>";
        // Refused, in both orders. It is tempting to let the collection win and call the
        // resulting empty directory "wrong but plainly so"; it is a copy that exits 0 having
        // lost the file's bytes, which is not plain at all. A server contradicting itself
        // about one entry cannot tell us what that entry is, so neither guess is taken.
        for (a, b) in [(coll, file), (file, coll)] {
            let msg = match both(a, b) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("a server that contradicts itself about resourcetype was believed"),
            };
            assert!(
                msg.contains("collection in one propstat and not in another"),
                "{msg}"
            );
            assert!(
                msg.contains("/dav/x"),
                "the refusal does not name the entry: {msg}"
            );
        }
        // the controls: agreement still reads as what both blocks say, so the refusal has
        // not simply taken over every response with two propstats
        assert!(both(coll, coll).unwrap()[0].dir);
        assert!(
            !both(file, file).unwrap()[0].dir,
            "two propstats that agree it is a file must still say file"
        );
    }

    /// Dot segments in a relative href resolve as RFC 3986 says.
    #[test]
    fn a_relative_href_with_dot_segments_resolves_against_the_request_path() {
        assert_eq!(remove_dot_segments("/dav/dir/sub/../peer"), "/dav/dir/peer");
        assert_eq!(remove_dot_segments("/dav/dir/./a/../b"), "/dav/dir/b");
        assert_eq!(remove_dot_segments("/dav/dir/sub/.."), "/dav/dir/");
        assert_eq!(remove_dot_segments("/../x"), "/x");
        assert_eq!(remove_dot_segments("/a//b"), "/a/b");
        // the control: a path with no dot segments is unchanged
        assert_eq!(remove_dot_segments("/dav/dir/a.txt"), "/dav/dir/a.txt");
        let body = r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>../peer</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir/sub").unwrap();
        assert_eq!(e[0].path, "/dav/dir/peer");
    }

    /// A relative href is resolved against the request path; RFC 4918 allows one.
    #[test]
    fn a_relative_href_is_resolved_against_the_request_path() {
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>./</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
  <D:response><D:href>a%20file.txt</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
  <D:response><D:href>sub/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/my dir").unwrap();
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            ["/dav/my dir", "/dav/my dir/a file.txt", "/dav/my dir/sub"]
        );
        // the control: a rooted href is not resolved against anything
        let e = parse_multistatus(
            &body.replace("<D:href>sub/</D:href>", "<D:href>/other/sub/</D:href>"),
            "/dav/my dir",
        )
        .unwrap();
        assert_eq!(e[2].path, "/other/sub");
    }

    /// A `?query` or `#fragment` on an href is not part of the path; a literal `?` in a
    /// name arrives as `%3F` and survives.
    #[test]
    fn a_query_or_fragment_on_an_href_is_not_part_of_the_path() {
        let body = r#"<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/a.txt?x=1</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
  <D:response><D:href>/dav/b.txt#frag</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
  <D:response><D:href>/dav/c%3Fd.txt</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>7</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let e = parse_multistatus(body, "/dav/dir").unwrap();
        let paths: Vec<&str> = e.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["/dav/a.txt", "/dav/b.txt", "/dav/c?d.txt"]);
    }

    /// A 207 this cannot read is an error, not zero failures. The first version stopped
    /// at the parse error and returned the count so far, and zero is `Gone`.
    #[test]
    fn a_207_that_cannot_be_read_is_an_error_and_not_a_removal() {
        let cut =
            r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/x</D:href><D:status>HTTP/1.1 4"#;
        assert!(
            failed_members(cut).is_err(),
            "a truncated 207 counted as zero failures"
        );
        assert!(
            failed_members(r#"<D:multistatus xmlns:D="DAV:"></D:multistatus>"#).is_err(),
            "a 207 with no statuses counted as zero failures"
        );
        assert!(failed_members(r#"<D:multistatus xmlns:D="DAV:"><D:response><D:status>garbage</D:status></D:response></D:multistatus>"#).is_err());
        // the control: a readable 207 counts, both ways
        let ok = r#"<D:multistatus xmlns:D="DAV:"><D:response><D:href>/x</D:href><D:status>HTTP/1.1 423 Locked</D:status></D:response><D:response><D:href>/y</D:href><D:status>HTTP/1.1 200 OK</D:status></D:response></D:multistatus>"#;
        assert_eq!(failed_members(ok).unwrap(), (1, vec![423]));
        assert_eq!(
            failed_members(&ok.replace("423 Locked", "204 No Content")).unwrap(),
            (0, vec![])
        );
        // A member 401 must come back as a STATUS and not just a count, because the
        // caller sorts a credential failure from a refusal and a count cannot: as a count,
        // a 401 member is reported as "the server kept 1 member; run sync again" -- the
        // 401/403 defect reopened one layer in.
        assert_eq!(
            failed_members(&ok.replace("423 Locked", "401 Unauthorized")).unwrap(),
            (1, vec![401])
        );
        // and 404 on a member of a DELETE is the end state asked for, not a failure
        assert_eq!(
            failed_members(&ok.replace("423 Locked", "404 Not Found")).unwrap(),
            (0, vec![])
        );
    }

    /// A zone id is the second half of the IPv6 story; the brackets are the first.
    /// RFC 6874 writes it `%25eth0` in a URI because `%` must be escaped there; the
    /// resolver wants `%eth0`. Strip only the brackets and the literal goes to the name
    /// lookup exactly as a bracketed `[::1]` would.
    #[test]
    fn a_zone_id_is_decoded_for_the_resolver_and_dropped_for_the_certificate() {
        // THE ARM: the resolver form
        assert_eq!(&*crate::unbracketed("[fe80::1%25eth0]"), "fe80::1%eth0");
        assert_eq!(&*crate::unbracketed("fe80::1%25eth0"), "fe80::1%eth0");
        // measured out of tree, and it needs no IPv6 stack because it is a parse:
        //   fe80::1%25lo -> ERR failed to lookup address information
        //   fe80::1%lo   -> OK  [fe80::1%1]:80
        #[cfg(unix)]
        assert!(
            std::net::ToSocketAddrs::to_socket_addrs(&(
                &*crate::unbracketed("[fe80::1%25lo]"),
                80u16
            ))
            .is_ok(),
            "the decoded zone does not resolve"
        );
        // THE CONTROL: an address with no zone is untouched, and so is a name
        assert_eq!(&*crate::unbracketed("[::1]"), "::1");
        assert_eq!(&*crate::unbracketed("host.example"), "host.example");
        // and a literal `%25` that is NOT a zone is left alone by the same rule, because
        // the only thing `%25` can mean in an authority is an escaped `%`
        assert_eq!(&*crate::unbracketed("[::1]"), "::1");

        // the certificate cannot carry a zone: it is which interface to leave by, not who
        // the peer is, so no certificate names one and rustls refuses the whole string
        assert_eq!(crate::unzoned("fe80::1%eth0"), "fe80::1");
        assert_eq!(
            crate::unzoned("::1"),
            "::1",
            "control: an address without a zone is unchanged"
        );
        assert_eq!(crate::unzoned("host.example"), "host.example");
    }

    /// `NO_PROXY` naming an IPv6 address must exempt it. A port strip that splits every
    /// entry on its last colon turns `::1` into `::` and `[::1]` into `[::`, and neither
    /// matches the host; traffic then goes through the proxy the operator just excluded.
    #[test]
    fn no_proxy_exempts_an_ipv6_address_in_either_spelling() {
        let matches = http::no_proxy_matches_for_test;
        // THE ARM: both spellings of the entry, against the host as it is actually stored
        assert!(
            matches("::1", "[::1]"),
            "NO_PROXY=::1 did not exempt the host it names"
        );
        assert!(
            matches("[::1]", "[::1]"),
            "NO_PROXY=[::1] did not exempt the host it names"
        );
        assert!(
            matches("fe80::1,[::1]", "[::1]"),
            "a list did not exempt its second entry"
        );
        // THE CONTROLS: a name still works, a port is still stripped from a name, and an
        // address that is NOT the host is still not exempt
        assert!(matches("example.com", "example.com"));
        assert!(
            matches("example.com:8080", "example.com"),
            "a port on a named entry is still stripped"
        );
        assert!(
            matches(".example.com", "a.example.com"),
            "a suffix entry still matches a subdomain"
        );
        assert!(!matches("::2", "[::1]"), "a different address was exempted");
        assert!(!matches("example.org", "example.com"));
    }

    /// Arms that check only a PARSER can all pass while `dav://[::1]:8443/a` cannot open,
    /// because the host goes on from the parser to the RESOLVER, which must not see the
    /// brackets. This arm checks the resolver.
    ///
    /// This box has no IPv6 stack (`bind [::1]` is `EAFNOSUPPORT`), so the arm cannot be an
    /// end-to-end socket test and does not pretend to be one. What it measures is the thing
    /// that goes wrong: with the brackets on, `[::1]` is not an address, so it goes
    /// to the name resolver and comes back "failed to lookup address information". Whatever
    /// happens after a correct parse -- refused, unreachable, no IPv6 at all -- is not that.
    #[test]
    fn an_ipv6_literal_reaches_the_resolver_as_an_address_and_not_as_a_name() {
        let lookup_failed = |e: &io::Error| {
            let s = e.to_string();
            s.contains("failed to lookup address information")
                || s.contains("Name or service not known")
                || e.raw_os_error() == Some(11001)
                || s.contains("No such host is known")
        };
        let open = |u: &str| {
            DavTree::connect(
                u,
                false,
                &Settings::default(),
                Arc::new(crate::ports::Silent),
            )
            .err()
            .expect("nothing is listening, so this must fail")
        };

        // THE ARM: port 1 has nothing on it, so this fails either way -- but it must fail
        // as an address, never as a name.
        let e = open("dav://[::1]:1/x");
        assert!(
            !lookup_failed(&e),
            "the bracketed literal went to the resolver as a name: {e}"
        );

        // THE CONTROL: a genuine name that resolves nowhere DOES come back that way, so
        // the arm above is reading a real distinction and not a message that never appears.
        let e = open("dav://no-such-host.invalid:1/x");
        assert!(
            lookup_failed(&e),
            "a name that resolves nowhere should say so: {e}"
        );
    }

    /// `-dav.insecure` is applied before the split, so the default port follows the scheme
    /// the run speaks. Applied after, `davs://host/p` kept 443 and spoke cleartext to it.
    #[test]
    fn dav_insecure_takes_the_cleartext_default_port_and_leaves_an_explicit_one_alone() {
        let port = |u: &str| {
            split_url(&plain(u).unwrap_or_else(|| u.to_string()))
                .unwrap()
                .2
        };
        assert_eq!(
            port("davs://host/p"),
            80,
            "no port written: the http default, not 443"
        );
        assert_eq!(port("https://host/p"), 80);
        assert_eq!(
            port("davs://host:8443/p"),
            8443,
            "an explicit port is the operator's and survives"
        );
        // the control: without the rewrite the same URL is 443
        assert_eq!(split_url("davs://host/p").unwrap().2, 443);
        // and a path that merely CONTAINS a scheme is not a scheme
        assert_eq!(
            plain("dav://host/https://x"),
            None,
            "no prefix to rewrite, so nothing is rewritten"
        );
        assert_eq!(
            plain("davs://host/https://x").as_deref(),
            Some("dav://host/https://x"),
            "the prefix is rewritten and the path is not"
        );
    }

    fn stand_in(
        quirks: super::super::testserver::Quirks,
    ) -> (PathBuf, super::super::testserver::Server) {
        let root = std::env::temp_dir().join(format!(
            "rcp-dav-unit-{}-{}",
            std::process::id(),
            fnv64(&format!("{:?}", std::time::Instant::now()))
        ));
        std::fs::create_dir_all(root.join("in/sub")).unwrap();
        std::fs::write(root.join("in/a.txt"), b"a".repeat(5000)).unwrap();
        std::fs::write(root.join("in/b.txt"), b"bb").unwrap();
        let server = super::super::testserver::Server::start_with(&root, quirks).unwrap();
        (root, server)
    }

    fn tree(server: &super::super::testserver::Server, path: &str) -> DavTree {
        DavTree::connect(
            &server.url(path),
            false,
            &Settings::default(),
            Arc::new(crate::ports::Silent),
        )
        .unwrap()
    }

    fn names(t: &DavTree) -> Vec<String> {
        let l = t.list(&Filter::default(), None, 2).unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        l.items.iter().map(|i| i.rel.clone()).collect()
    }

    /// A child called `..` cannot be one. A listing that carries `%2e%2e/` is walked
    /// without it, and terminates.
    #[test]
    fn a_child_called_dot_dot_is_ignored_rather_than_walked() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            dotdot_child: true,
            ..Quirks::default()
        });
        assert_eq!(names(&tree(&s, "/in")), [".", "a.txt", "b.txt", "sub"]);
        // the control: the honest stand-in lists the same, so the arm is about the
        // ignored entry and not about the listing being empty
        let honest = super::super::testserver::Server::start(&root).unwrap();
        assert_eq!(names(&tree(&honest, "/in")), [".", "a.txt", "b.txt", "sub"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Apache's mod_dav answers a `PROPFIND` of a collection named without its slash
    /// with 301 to the slash form, and the stand-in now does the same by default. The
    /// adapter follows that one redirect -- the endpoint URL is written without a slash,
    /// so every open goes through it -- and no other.
    #[test]
    fn a_collection_redirect_that_only_adds_the_slash_is_followed_and_no_other() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks::default());
        let t = tree(&s, "/in");
        assert_eq!(names(&t), [".", "a.txt", "b.txt", "sub"]);
        // a child collection is asked for without its slash too, since `stat` cannot know
        // the kind before it asks
        assert_eq!(t.stat("sub").unwrap().map(|i| i.kind), Some(Kind::Dir));
        assert_eq!(t.stat("a.txt").unwrap().map(|i| i.size), Some(5000));
        let away = super::super::testserver::Server::start_with(
            &root,
            Quirks {
                collection_redirect_to: Some("/elsewhere/"),
                ..Quirks::default()
            },
        )
        .unwrap();
        let refused = DavTree::connect(
            &away.url("/in"),
            false,
            &Settings::default(),
            Arc::new(crate::ports::Silent),
        )
        .err()
        .expect("a redirect to another path is refused");
        assert!(refused.to_string().contains("HTTP 301"), "{refused}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_a_location_naming_the_same_resource_with_a_slash_counts() {
        let origin = "http://h:80";
        for (location, want) in [
            ("/d/t/", true),
            ("http://h:80/d/t/", true),
            // the default port left out, as Apache writes it on port 80
            ("http://h/d/t/", true),
            ("http://H/d/t/", true),
            // escaped differently from the request, same resource
            ("/d/%74/", true),
            ("/d/t", false),
            ("/d/t//", false),
            ("/d/t/x/", false),
            ("/elsewhere/", false),
            ("http://other/d/t/", false),
            ("http://h:8080/d/t/", false),
            ("https://h/d/t/", false),
        ] {
            assert_eq!(
                only_adds_slash(origin, location, "/d/t"),
                want,
                "{location}"
            );
        }
    }

    /// A 206 whose bytes start at zero is refused before a byte is placed.
    #[test]
    fn a_206_from_the_wrong_offset_is_refused_before_a_byte_is_placed() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            lies_range: true,
            ..Quirks::default()
        });
        let t = tree(&s, "/in");
        let mut r = t.open("a.txt").unwrap();
        r.seek(SeekFrom::Start(100)).unwrap();
        let mut buf = [0u8; 16];
        let e = r.read(&mut buf).unwrap_err();
        assert!(e.to_string().contains("206 starts at 0"), "{e}");
        assert_eq!(
            s.ranges.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the Range was not asked for"
        );
        // the control: the honest stand-in answers the range asked, and the read is the
        // bytes from there
        let honest = super::super::testserver::Server::start(&root).unwrap();
        let t = tree(&honest, "/in");
        let mut r = t.open("a.txt").unwrap();
        r.seek(SeekFrom::Start(4990)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 10);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A 207 the reader cannot finish is an error, end to end: the collection is still
    /// there and `remove` says it does not know what happened.
    #[test]
    fn a_garbled_207_to_a_delete_is_an_error_and_the_collection_stays() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            garbled_207: true,
            ..Quirks::default()
        });
        let t = tree(&s, "/");
        // A collection that still holds something is refused before any DELETE is sent,
        // because that DELETE would remove the member with it.
        let e = t.remove("in", Kind::Dir).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::DirectoryNotEmpty, "{e}");
        assert!(root.join("in/a.txt").exists());
        // Emptied, as the planner leaves it, the DELETE is sent and its 207 is the answer.
        std::fs::remove_dir_all(root.join("in")).unwrap();
        std::fs::create_dir(root.join("in")).unwrap();
        let e = t.remove("in", Kind::Dir).unwrap_err();
        assert!(e.to_string().contains("could not be read"), "{e}");
        assert!(root.join("in").exists());
        // the control: a readable partial 207 is `Kept`, with the count
        let partial = super::super::testserver::Server::start_with(
            &root,
            Quirks {
                partial_delete: true,
                ..Quirks::default()
            },
        )
        .unwrap();
        let t = tree(&partial, "/");
        assert!(
            matches!(t.remove("in", Kind::Dir).unwrap(), Removed::Kept(why) if why.contains("1 member"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Elements in another namespace do not reach the listing, however they are named.
    #[test]
    fn a_listing_reads_only_the_dav_namespace_whatever_the_prefix() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            foreign_ns: true,
            ..Quirks::default()
        });
        // the prefix is `a:`, a decoy `href` and a decoy 500 `status` follow every real
        // one: read by prefix-stripping, every entry is `/decoy` and skipped
        assert_eq!(names(&tree(&s, "/in")), [".", "a.txt", "b.txt", "sub"]);
        let item = tree(&s, "/in").stat("a.txt").unwrap().unwrap();
        assert_eq!(item.size, 5000);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `Destination` is an absolute URI, which every server accepts and RFC 2518 ones
    /// require.
    #[test]
    fn a_move_names_its_destination_as_an_absolute_uri() {
        use super::super::testserver::Quirks;
        let (root, s) = stand_in(Quirks {
            absolute_destination: true,
            ..Quirks::default()
        });
        let t = tree(&s, "/in");
        t.rename("b.txt", "c.txt").unwrap();
        assert!(root.join("in/c.txt").exists());
        assert!(!root.join("in/b.txt").exists());
        // and the sibling: WebDAV has COPY, which is a second copy of the bytes and not a
        // second name for one file, so `hard_link` is `Unsupported` and the transfer layer
        // copies instead. Reporting COPY as a hard link would have told a caller that two
        // paths shared storage when they never did.
        let e = t
            .hard_link("c.txt", "d.txt")
            .expect_err("WebDAV cannot hard link");
        assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}");
        assert!(
            !root.join("in/d.txt").exists(),
            "a refused link must leave nothing behind"
        );
        // the control: the strict stand-in refuses a rooted Destination, so the arm
        // above is measuring the form and not the server's leniency
        let r = t
            .pool
            .request(
                "MOVE",
                &t.target("c.txt", false),
                &[("destination", &t.target("e.txt", false))],
                &[],
            )
            .unwrap();
        assert_eq!(r.status, 400);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `dav://` URL reads as the `http://` URL it stands for, on the whole table the
    /// shared parser is held to, and `davs://` as `https://`.
    #[test]
    fn a_dav_url_reads_as_the_http_url_it_stands_for() {
        for (url, want) in http::AUTHORITIES {
            let Some(rest) = url.strip_prefix("http://") else {
                continue;
            };
            let got = split_url(&format!("dav://{rest}"))
                .ok()
                .map(|(_, h, p, path)| (h, p, path));
            let want = want.map(|(h, p, path)| (h.to_string(), p, path.to_string()));
            assert_eq!(got, want, "dav://{rest}");
        }
        assert_eq!(split_url("davs://host/p").unwrap().2, 443);
        assert!(split_url("ftp://host/p").is_err());
    }
}
