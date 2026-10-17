//! A stand-in WebDAV service backed by a local directory: `PROPFIND`, `GET` (with `Range`),
//! `PUT`, `MKCOL`, `DELETE`, `MOVE` and `COPY`, which is the whole set this adapter uses.
//!
//! Two things it does on purpose that a naive stand-in would not, because both are shapes a
//! real server has and an adapter can get wrong against a tidier one:
//!
//! - It answers `PROPFIND Depth: 1` with the collection's **own entry first**, as every
//!   real server does. An adapter that drops the self-entry by position rather than by
//!   path passes against a server that omits it and loops forever against one that does
//!   not. `--selflast` moves it to the end, so the arm can prove the adapter is not just
//!   skipping the first response.
//! - It emits a **second `propstat` with 404** listing a property it does not have, which
//!   is normal and which an adapter reading "any non-2xx propstat means skip" would treat
//!   as a missing file.
//!
//! It is deliberately not a complete WebDAV server: no locking, no `PROPPATCH`, no dead
//! properties. Those are the parts the adapter refuses by name, so a stand-in that
//! implemented them would be testing something nothing calls.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct Server {
    pub port: u16,
    /// The number of `Range` requests served, for an arm that needs to prove a resume
    /// happened rather than that the bytes were right.
    pub ranges: Arc<AtomicU64>,
}

/// How the stand-in should misbehave, for the arms that need a server to be awkward.
#[derive(Clone, Copy, Default)]
pub struct Quirks {
    /// Put the collection's own entry LAST in its listing instead of first.
    pub self_last: bool,
    /// Answer `GET` with 200 and the whole file even when a `Range` was asked for.
    pub ignore_range: bool,
    /// Require `Authorization: Basic <creds>` on every request.
    pub require: Option<&'static str>,
    /// Answer `DELETE` with 423 Locked.
    pub locked: bool,
    /// Answer `DELETE` with 403 Forbidden -- a server that allows writes and not deletes.
    /// The same KIND of answer as the 423 above (the server replied and refused), so it
    /// belongs with the 423 and not in the failure bucket; without this arm nothing shows it.
    pub forbid_delete: bool,
    /// Answer `DELETE` with 401 Unauthorized -- a credential the server will not accept,
    /// or one that expired after the listing. This is NOT the 403 above, and a change that
    /// teaches WebDAV to call a 403 `Kept` can easily sweep the 401 in with it: `Kept` prints
    /// "run `sync` again once the entry can go", and no number of reruns fixes a password.
    pub unauthorized_delete: bool,
    /// Answer a collection `DELETE` with 207: one member 423, the rest removed. What RFC
    /// 4918 says a server does when it can remove some of a collection and not all.
    pub partial_delete: bool,
    /// Answer a collection `DELETE` with a 207 whose body stops mid-element, before any
    /// member status, and remove nothing. A reader that counts the statuses it managed
    /// to parse counts zero and calls that a clean removal.
    pub garbled_207: bool,
    /// List a child called `%2e%2e/` in every collection. Decoded, that is `..`, and a
    /// walker that queues it walks up out of the root.
    pub dotdot_child: bool,
    /// Answer a ranged `GET` with 206 and a `Content-Range` from zero, body from zero.
    /// The status says partial; the bytes are the whole file.
    pub lies_range: bool,
    /// Bind `DAV:` to the prefix `a:` and put a decoy `href` and `status` in ANOTHER
    /// namespace after the real ones in every response. A reader that strips prefixes
    /// reads the decoys.
    pub foreign_ns: bool,
    /// Answer 400 to a `MOVE` or `COPY` whose `Destination` is not an absolute URI, as an
    /// RFC 2518 server does.
    pub absolute_destination: bool,
    /// Prefix every CHILD href in a listing with this, so the children are listed under
    /// a path other than the one asked -- what a server behind a rewriting proxy does.
    pub href_prefix: Option<&'static str>,
    /// Answer `PROPFIND` of any path ENDING in this with 500, so one subdirectory of an
    /// otherwise healthy tree cannot be listed. The cause does not matter to the property
    /// under test -- a server fault, a contradictory `resourcetype`, a permission -- only
    /// that the source listing comes back incomplete while the rest of the walk succeeds.
    /// A failure at the ROOT is the easy case and is already safe: nothing lists, so
    /// nothing is planned.
    pub fail_propfind_under: Option<&'static str>,
    /// How a FILE's `getcontentlength` is reported. A length is the one property whose
    /// absence used to be indistinguishable from a value: it defaulted to zero, which
    /// reads as "empty file" through the copy, the sink's own size check and `verify`.
    pub content_length: ContentLength,
    /// Where the redirect for a collection asked without its slash points, instead of the
    /// same path with the slash. A redirect to any other resource is one the adapter must
    /// still refuse.
    pub collection_redirect_to: Option<&'static str>,
}

/// What the stand-in puts in `<D:getcontentlength>` for a file.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum ContentLength {
    /// The file's real length, as a conformant server sends.
    #[default]
    Real,
    /// The property is not emitted at all -- what a server behind a transforming proxy,
    /// or one serving a dynamically generated resource, does.
    Omitted,
    /// A value that is not an integer. Not a hypothetical shape: the point is that the
    /// reader must not turn text it cannot parse into a number it can.
    Unparseable,
}

impl Server {
    pub fn start(root: &Path) -> io::Result<Server> {
        Server::start_with(root, Quirks::default())
    }

    pub fn start_with(root: &Path, quirks: Quirks) -> io::Result<Server> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let root = Arc::new(fs::canonicalize(root)?);
        let ranges = Arc::new(AtomicU64::new(0));
        let counter = ranges.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let root = root.clone();
                let counter = counter.clone();
                std::thread::spawn(move || serve(stream, root, quirks, counter));
            }
        });
        Ok(Server { port, ranges })
    }

    pub fn url(&self, path: &str) -> String {
        format!("dav://127.0.0.1:{}{path}", self.port)
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<Request>> {
    // read until the blank line that ends the head
    loop {
        if let Some(i) = find(buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).into_owned();
            let mut lines = head.lines();
            let start = lines.next().unwrap_or("");
            let mut parts = start.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| {
                    l.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let mut body = buf[i + 4..].to_vec();
            buf.clear();
            while body.len() < len {
                let mut chunk = [0u8; 65536];
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    return Ok(None);
                }
                body.extend_from_slice(&chunk[..n]);
            }
            buf.extend_from_slice(&body[len..]);
            body.truncate(len);
            if method.is_empty() {
                return Ok(None);
            }
            return Ok(Some(Request {
                method,
                target,
                headers,
                body,
            }));
        }
        let mut chunk = [0u8; 65536];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The path under `root` that a request target names, refusing anything that climbs out.
fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let path = decode(target.split('?').next().unwrap_or(""));
    let mut out = root.to_path_buf();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => out.push(s),
        }
    }
    Some(out)
}

fn http_date(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // civil-from-days, matching the client's reader
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let dow = (days + 4).rem_euclid(7) as usize;
    let names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        names[dow],
        d,
        months[(m - 1) as usize],
        y,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// One `<D:response>`. The second `propstat` with 404 is not decoration: it is what a real
/// server emits for a property it does not carry, and reading it as a refusal loses files.
fn response_xml(href: &str, meta: &fs::Metadata, quirks: Quirks) -> String {
    let rt = if meta.is_dir() { "<D:collection/>" } else { "" };
    let len = match (meta.is_dir(), quirks.content_length) {
        (true, _) => String::new(),
        (false, ContentLength::Real) => {
            format!("<D:getcontentlength>{}</D:getcontentlength>", meta.len())
        }
        (false, ContentLength::Omitted) => String::new(),
        (false, ContentLength::Unparseable) => {
            "<D:getcontentlength>3.7e2</D:getcontentlength>".to_string()
        }
    };
    let modified = meta.modified().map(http_date).unwrap_or_default();
    let (decoy_href, decoy_status) = if quirks.foreign_ns {
        (
            r#"<X:href xmlns:X="urn:decoy">/decoy</X:href>"#,
            r#"<X:status xmlns:X="urn:decoy">HTTP/1.1 500 Decoy</X:status>"#,
        )
    } else {
        ("", "")
    };
    let xml = format!(
        "<D:response><D:href>{}</D:href>{decoy_href}<D:propstat><D:prop><D:resourcetype>{rt}</D:resourcetype>{len}<D:getlastmodified>{modified}</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status>{decoy_status}</D:propstat><D:propstat><D:prop><D:getcontentlanguage/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>",
        xml_escape(&encode(href))
    );
    if quirks.foreign_ns {
        xml.replace("<D:", "<a:").replace("</D:", "</a:")
    } else {
        xml
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    fn xml(status: u16, body: String) -> Reply {
        Reply {
            status,
            headers: vec![(
                "Content-Type".into(),
                "application/xml; charset=utf-8".into(),
            )],
            body: body.into_bytes(),
        }
    }
}

fn text_of(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        423 => "Locked",
        _ => "Error",
    }
}

fn serve(mut stream: TcpStream, root: Arc<PathBuf>, quirks: Quirks, ranges: Arc<AtomicU64>) {
    let mut buf = Vec::new();
    loop {
        let req = match read_request(&mut stream, &mut buf) {
            Ok(Some(r)) => r,
            _ => return,
        };
        let reply = handle(&req, &root, quirks, &ranges);
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
            reply.status,
            text_of(reply.status),
            reply.body.len()
        );
        for (k, v) in &reply.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(&reply.body).is_err() {
            return;
        }
    }
}

fn handle(req: &Request, root: &Path, quirks: Quirks, ranges: &AtomicU64) -> Reply {
    if let Some(want) = quirks.require {
        let given = req.header("authorization").unwrap_or("");
        let expected = format!("Basic {}", crate::base64::encode(want.as_bytes()));
        if given != expected {
            let mut r = Reply::new(401);
            r.headers
                .push(("WWW-Authenticate".into(), "Basic realm=\"stand-in\"".into()));
            return r;
        }
    }
    let Some(path) = resolve(root, &req.target) else {
        return Reply::new(403);
    };
    let target_path = decode(req.target.split('?').next().unwrap_or(""));
    match req.method.as_str() {
        "PROPFIND" => {
            if let Some(tail) = quirks.fail_propfind_under {
                if target_path.trim_end_matches('/').ends_with(tail) {
                    return Reply::new(500);
                }
            }
            let Ok(meta) = fs::symlink_metadata(&path) else {
                return Reply::new(404);
            };
            // A collection asked for without its trailing slash is redirected to the slash
            // form, as Apache's mod_dav does, with an absolute `Location` on this origin.
            // Every stand-in before this answered 207, and the adapter failed with
            // "HTTP 301" at open against the first real server it met.
            if meta.is_dir() && !req.target.split('?').next().unwrap_or("").ends_with('/') {
                let mut r = Reply::new(301);
                let path = quirks
                    .collection_redirect_to
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{}/", req.target));
                r.headers.push((
                    "Location".into(),
                    format!("http://{}{path}", req.header("host").unwrap_or("")),
                ));
                return r;
            }
            let mut responses = vec![response_xml(&target_path, &meta, quirks)];
            if meta.is_dir() && req.header("depth").unwrap_or("infinity") != "0" {
                let base = target_path.trim_end_matches('/').to_string();
                let mut entries: Vec<_> = fs::read_dir(&path)
                    .map(|d| d.flatten().collect())
                    .unwrap_or_default();
                entries.sort_by_key(|e| e.file_name());
                for e in entries {
                    let Ok(m) = e.metadata() else { continue };
                    let name = e.file_name().to_string_lossy().into_owned();
                    let href = format!(
                        "{}{base}/{name}{}",
                        quirks.href_prefix.unwrap_or(""),
                        if m.is_dir() { "/" } else { "" }
                    );
                    responses.push(response_xml(&href, &m, quirks));
                }
                if quirks.dotdot_child {
                    // `encode` would turn the dots into themselves; the point is the
                    // ESCAPED form, which decodes to `..` only after the client's decode
                    let xml = response_xml("/PLACEHOLDER/", &meta, quirks)
                        .replace("/PLACEHOLDER/", &format!("{base}/%2e%2e/"));
                    responses.push(xml);
                }
                if quirks.self_last {
                    let own = responses.remove(0);
                    responses.push(own);
                }
            }
            if quirks.foreign_ns {
                Reply::xml(
                    207,
                    format!(
                        r#"<?xml version="1.0" encoding="utf-8"?><a:multistatus xmlns:a="DAV:">{}</a:multistatus>"#,
                        responses.concat()
                    ),
                )
            } else {
                Reply::xml(
                    207,
                    format!(
                        r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">{}</D:multistatus>"#,
                        responses.concat()
                    ),
                )
            }
        }
        "GET" | "HEAD" => {
            let Ok(data) = fs::read(&path) else {
                return Reply::new(404);
            };
            let range = req
                .header("range")
                .and_then(|r| r.strip_prefix("bytes="))
                .and_then(|r| r.split('-').next())
                .and_then(|s| s.parse::<usize>().ok());
            match range {
                Some(_) if quirks.lies_range => {
                    ranges.fetch_add(1, Ordering::SeqCst);
                    let mut r = Reply::new(206);
                    r.headers.push((
                        "Content-Range".into(),
                        format!("bytes 0-{}/{}", data.len().saturating_sub(1), data.len()),
                    ));
                    r.body = if req.method == "HEAD" {
                        Vec::new()
                    } else {
                        data
                    };
                    r
                }
                Some(from) if !quirks.ignore_range => {
                    ranges.fetch_add(1, Ordering::SeqCst);
                    let from = from.min(data.len());
                    let mut r = Reply::new(206);
                    r.headers.push((
                        "Content-Range".into(),
                        format!(
                            "bytes {}-{}/{}",
                            from,
                            data.len().saturating_sub(1),
                            data.len()
                        ),
                    ));
                    r.body = if req.method == "HEAD" {
                        Vec::new()
                    } else {
                        data[from..].to_vec()
                    };
                    r
                }
                Some(_) => {
                    ranges.fetch_add(1, Ordering::SeqCst);
                    Reply {
                        status: 200,
                        headers: Vec::new(),
                        body: if req.method == "HEAD" {
                            Vec::new()
                        } else {
                            data
                        },
                    }
                }
                None => Reply {
                    status: 200,
                    headers: Vec::new(),
                    body: if req.method == "HEAD" {
                        Vec::new()
                    } else {
                        data
                    },
                },
            }
        }
        "PUT" => {
            if path.parent().is_none_or(|p| !p.is_dir()) {
                return Reply::new(409); // no parent collection, which is the spec's answer
            }
            let existed = path.exists();
            match fs::write(&path, &req.body) {
                Ok(()) => Reply::new(if existed { 204 } else { 201 }),
                Err(_) => Reply::new(403),
            }
        }
        "MKCOL" => {
            if path.exists() {
                return Reply::new(405);
            }
            if path.parent().is_none_or(|p| !p.is_dir()) {
                return Reply::new(409);
            }
            match fs::create_dir(&path) {
                Ok(()) => Reply::new(201),
                Err(_) => Reply::new(403),
            }
        }
        "DELETE" => {
            if quirks.locked {
                return Reply::new(423);
            }
            if quirks.forbid_delete {
                return Reply::new(403);
            }
            if quirks.unauthorized_delete {
                return Reply::new(401);
            }
            if quirks.garbled_207 && path.is_dir() {
                return Reply::xml(207, r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/in/a.txt</D:href><D:status>HTTP/1.1 4"#.to_string());
            }
            if quirks.partial_delete && path.is_dir() {
                // remove the files, keep the directory and report one member locked
                let kept = format!("{}/locked", target_path.trim_end_matches('/'));
                if let Ok(rd) = fs::read_dir(&path) {
                    for e in rd.flatten() {
                        if e.path().is_file() {
                            let _ = fs::remove_file(e.path());
                        }
                    }
                }
                return Reply::xml(
                    207,
                    format!(
                        r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{}</D:href><D:status>HTTP/1.1 423 Locked</D:status></D:response></D:multistatus>"#,
                        xml_escape(&encode(&kept))
                    ),
                );
            }
            let Ok(meta) = fs::symlink_metadata(&path) else {
                return Reply::new(404);
            };
            let r = if meta.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            match r {
                Ok(()) => Reply::new(204),
                Err(_) => Reply::new(403),
            }
        }
        "MOVE" | "COPY" => {
            let Some(dest) = req.header("destination") else {
                return Reply::new(400);
            };
            if quirks.absolute_destination && !dest.contains("://") {
                return Reply::new(400);
            }
            // a Destination may be a full URL or a rooted path
            let dest_path = match dest
                .find("://")
                .and_then(|i| dest[i + 3..].find('/').map(|j| i + 3 + j))
            {
                Some(i) => &dest[i..],
                None => dest,
            };
            let Some(to) = resolve(root, dest_path) else {
                return Reply::new(403);
            };
            if !path.exists() {
                return Reply::new(404);
            }
            let existed = to.exists();
            let r = if req.method == "MOVE" {
                fs::rename(&path, &to)
            } else if path.is_dir() {
                fs::create_dir_all(&to)
            } else {
                fs::copy(&path, &to).map(|_| ())
            };
            match r {
                Ok(()) => Reply::new(if existed { 204 } else { 201 }),
                Err(_) => Reply::new(403),
            }
        }
        "OPTIONS" => {
            let mut r = Reply::new(200);
            r.headers.push(("DAV".into(), "1".into()));
            r.headers.push((
                "Allow".into(),
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY".into(),
            ));
            r
        }
        _ => Reply::new(405),
    }
}
