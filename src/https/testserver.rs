//! A stand-in web server backed by a local directory, serving a directory three ways.
//!
//! One server rather than three, because the property worth measuring is that the SAME
//! tree copies identically whichever listing convention its operator happens to serve --
//! and three separate fixtures could drift apart and hide exactly that.
//!
//! It is deliberately awkward in the ways a real autoindex is: the HTML shape emits the
//! sort-order links, the "Parent Directory" link and Apache's doubled icon-plus-text link
//! for every entry, because those are what a naive reader turns into files.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Which listing convention this server speaks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// publish `rcp-index.json` at the root, as `rcp scan -json` writes it
    Index,
    /// nginx `autoindex_format json`
    Json,
    /// Apache-style HTML, controls and all
    Html,
}

#[derive(Clone, Copy, Default)]
pub struct Quirks {
    /// Answer a ranged `GET` with 206 and a `Content-Range` from zero, body from zero.
    pub lies_range: bool,
    /// Answer every ranged `GET` with 200 and the whole file.
    pub ignore_range: bool,
    /// Publish an `rcp-index.json` whose sizes disagree with the files, so a copy that
    /// trusted the index without reading the bytes would report success on short files.
    pub stale_index: bool,
    /// `HEAD` of a zero-length file omits `Content-Length`, and `Range: bytes=0-0` on it
    /// answers `416` with `Content-Range: bytes */0`. That is what Apache httpd does.
    pub apache_zero_head: bool,
    /// `HEAD` omits `Content-Length`, and a ranged `GET` answers `200` with an empty
    /// chunked body and no `Content-Range`. The length is then unknowable.
    pub hides_length: bool,
}

pub struct Server {
    pub port: u16,
    /// `Range` requests served, for an arm that must show a resume happened.
    pub ranges: Arc<AtomicU64>,
}

impl Server {
    pub fn start(root: &Path, shape: Shape) -> io::Result<Server> {
        Server::start_with(root, shape, Quirks::default())
    }

    pub fn start_with(root: &Path, shape: Shape, quirks: Quirks) -> io::Result<Server> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let root = Arc::new(fs::canonicalize(root)?);
        let ranges = Arc::new(AtomicU64::new(0));
        let counter = ranges.clone();
        std::thread::spawn(move || {
            for c in listener.incoming() {
                let Ok(stream) = c else { continue };
                let root = root.clone();
                let counter = counter.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &root, shape, quirks, &counter);
                });
            }
        });
        Ok(Server { port, ranges })
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

fn serve(
    mut stream: TcpStream,
    root: &Path,
    shape: Shape,
    quirks: Quirks,
    ranges: &AtomicU64,
) -> io::Result<()> {
    loop {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte)? {
                0 => return Ok(()),
                _ => head.push(byte[0]),
            }
        }
        let text = String::from_utf8_lossy(&head).to_string();
        let mut lines = text.lines();
        let Some(request) = lines.next() else {
            return Ok(());
        };
        let mut parts = request.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("/").to_string();
        let range = lines
            .find(|l| l.to_ascii_lowercase().starts_with("range:"))
            .map(|l| l[6..].trim().to_string());

        let path = target.split(['?', '#']).next().unwrap_or("/");
        let decoded = crate::net::http::percent_decode(path);
        let rel = decoded.trim_start_matches('/');
        let full = root.join(rel);

        // the published index, synthesized from the tree on demand
        if rel == "rcp-index.json" || rel.ends_with("/rcp-index.json") {
            if shape != Shape::Index {
                write_head(&mut stream, 404, "text/plain", 0, None)?;
                continue;
            }
            let body = rcp_index(root, quirks.stale_index);
            write_head(&mut stream, 200, "application/json", body.len(), None)?;
            if method != "HEAD" {
                stream.write_all(&body)?;
            }
            continue;
        }

        let meta = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => {
                write_head(&mut stream, 404, "text/plain", 0, None)?;
                continue;
            }
        };

        if meta.is_dir() {
            let body = match shape {
                // an Index server still answers a collection: the walk never asks, but a
                // client that does must not get a 404 for a directory that exists
                Shape::Index | Shape::Json => json_listing(&full),
                Shape::Html => html_listing(&full, &decoded),
            };
            let ctype = if matches!(shape, Shape::Html) {
                "text/html"
            } else {
                "application/json"
            };
            write_head(&mut stream, 200, ctype, body.len(), None)?;
            if method != "HEAD" {
                stream.write_all(&body)?;
            }
            continue;
        }

        let data = fs::read(&full).unwrap_or_default();
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last_modified = imf(modified);

        // Apache omits Content-Length on HEAD exactly when the file is empty, and a
        // one-byte range of that file is unsatisfiable.
        if quirks.apache_zero_head && data.is_empty() && !quirks.hides_length {
            if method == "HEAD" {
                write_head_bare(
                    &mut stream,
                    200,
                    "OK",
                    "text/plain",
                    None,
                    Some(&last_modified),
                )?;
                continue;
            }
            if range.is_some() {
                write_head_bare(
                    &mut stream,
                    416,
                    "Range Not Satisfiable",
                    "text/plain",
                    Some("bytes */0"),
                    None,
                )?;
                continue;
            }
        }
        if quirks.hides_length {
            if method == "HEAD" {
                write_head_bare(
                    &mut stream,
                    200,
                    "OK",
                    "application/octet-stream",
                    None,
                    Some(&last_modified),
                )?;
                continue;
            }
            if range.is_some() {
                ranges.fetch_add(1, Ordering::Relaxed);
                stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                )?;
                continue;
            }
        }

        let start = range
            .as_deref()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split('-').next())
            .and_then(|s| s.trim().parse::<usize>().ok());
        match start {
            Some(s) if !quirks.ignore_range => {
                ranges.fetch_add(1, Ordering::Relaxed);
                let (from, cr) = if quirks.lies_range {
                    (
                        0,
                        format!("bytes 0-{}/{}", data.len().saturating_sub(1), data.len()),
                    )
                } else {
                    (
                        s,
                        format!(
                            "bytes {}-{}/{}",
                            s,
                            data.len().saturating_sub(1),
                            data.len()
                        ),
                    )
                };
                let slice = data.get(from..).unwrap_or_default();
                write_head_full(
                    &mut stream,
                    206,
                    "application/octet-stream",
                    slice.len(),
                    Some(&cr),
                    Some(&last_modified),
                )?;
                if method != "HEAD" {
                    stream.write_all(slice)?;
                }
            }
            _ => {
                if start.is_some() {
                    ranges.fetch_add(1, Ordering::Relaxed);
                }
                write_head_full(
                    &mut stream,
                    200,
                    "application/octet-stream",
                    data.len(),
                    None,
                    Some(&last_modified),
                )?;
                if method != "HEAD" {
                    stream.write_all(&data)?;
                }
            }
        }
    }
}

fn write_head(
    s: &mut TcpStream,
    status: u16,
    ctype: &str,
    len: usize,
    cr: Option<&str>,
) -> io::Result<()> {
    write_head_full(s, status, ctype, len, cr, None)
}

fn write_head_full(
    s: &mut TcpStream,
    status: u16,
    ctype: &str,
    len: usize,
    cr: Option<&str>,
    modified: Option<&str>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        206 => "Partial Content",
        404 => "Not Found",
        _ => "Unknown",
    };
    let mut h = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\nAccept-Ranges: bytes\r\n");
    if let Some(cr) = cr {
        h.push_str(&format!("Content-Range: {cr}\r\n"));
    }
    if let Some(m) = modified {
        h.push_str(&format!("Last-Modified: {m}\r\n"));
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())
}

/// A response with no body. `content_range` set means this is a `416`: the length of the
/// empty body is sent so the client can finish it. A `200` without one is a `HEAD` that
/// deliberately omits `Content-Length`.
fn write_head_bare(
    s: &mut TcpStream,
    status: u16,
    reason: &str,
    ctype: &str,
    content_range: Option<&str>,
    modified: Option<&str>,
) -> io::Result<()> {
    let mut h =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nAccept-Ranges: bytes\r\n");
    if status != 200 || content_range.is_some() {
        h.push_str("Content-Length: 0\r\n");
    }
    if let Some(cr) = content_range {
        h.push_str(&format!("Content-Range: {cr}\r\n"));
    }
    if let Some(m) = modified {
        h.push_str(&format!("Last-Modified: {m}\r\n"));
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())
}

/// The whole tree as `rcp scan -json` writes it: one `entry` object per line, then `done`.
fn rcp_index(root: &Path, stale: bool) -> Vec<u8> {
    let mut out = String::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        for p in names {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name == "rcp-index.json" {
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(m) = fs::symlink_metadata(&p) else {
                continue;
            };
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i128)
                .unwrap_or(0);
            if m.is_dir() {
                out.push_str(&format!("{{\"event\":\"entry\",\"path\":\"{rel}\",\"kind\":\"d\",\"size\":0,\"mtime_ns\":{mtime},\"mode\":493}}\n"));
                stack.push((p, rel));
            } else {
                // the stale quirk: a size the bytes do not agree with
                let size = if stale { m.len() + 100 } else { m.len() };
                out.push_str(&format!("{{\"event\":\"entry\",\"path\":\"{rel}\",\"kind\":\"f\",\"size\":{size},\"mtime_ns\":{mtime},\"mode\":420}}\n"));
            }
        }
    }
    out.push_str("{\"event\":\"done\",\"status\":\"passed\",\"command\":\"scan\"}\n");
    out.into_bytes()
}

/// nginx `autoindex_format json`.
fn json_listing(dir: &Path) -> Vec<u8> {
    let mut rows: Vec<String> = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return b"[]".to_vec();
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        let secs = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if m.is_dir() {
            rows.push(format!(
                "{{\"name\":\"{name}\",\"type\":\"directory\",\"mtime\":\"{}\"}}",
                imf(secs)
            ));
        } else {
            rows.push(format!(
                "{{\"name\":\"{name}\",\"type\":\"file\",\"mtime\":\"{}\",\"size\":{}}}",
                imf(secs),
                m.len()
            ));
        }
    }
    format!("[{}]", rows.join(",")).into_bytes()
}

/// Apache `mod_autoindex`, with every control a real one emits.
fn html_listing(dir: &Path, request_path: &str) -> Vec<u8> {
    let mut body = format!("<html><head><title>Index of {request_path}</title></head><body>\n<h1>Index of {request_path}</h1>\n<table>\n");
    // the sort controls, which are links and are not entries
    body.push_str(" <tr><th><a href=\"?C=N;O=D\">Name</a></th><th><a href=\"?C=M;O=A\">Last modified</a></th><th><a href=\"?C=S;O=A\">Size</a></th></tr>\n");
    // the parent link, which is the one that makes a naive walker climb out
    body.push_str(" <tr><td><a href=\"/icons/back.gif\"><img src=\"/icons/back.gif\"></a></td><td><a href=\"../\">Parent Directory</a></td></tr>\n");
    let Ok(rd) = fs::read_dir(dir) else {
        return body.into_bytes();
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        let href = crate::net::http::percent_encode(&name, false);
        let slash = if m.is_dir() { "/" } else { "" };
        // Apache emits the icon link and the text link for the same entry: a reader that
        // takes both lists every file twice
        body.push_str(&format!(
            " <tr><td><a href=\"{href}{slash}\"><img src=\"/icons/f.gif\"></a></td><td><a href=\"{href}{slash}\">{name}{slash}</a></td></tr>\n"
        ));
    }
    body.push_str("</table></body></html>\n");
    body.into_bytes()
}

/// An IMF-fixdate, which is the only date format the readers accept.
fn imf(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil-from-days, the same algorithm the date reader uses in reverse
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
    let names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        names[days.rem_euclid(7) as usize],
        d,
        months[(m - 1) as usize],
        y,
        h,
        mi,
        s
    )
}
