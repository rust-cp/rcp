//! Reading a directory listing out of an ordinary web server.
//!
//! HTTP has no directory listing. What it has is three conventions, and this module reads
//! all three because a source you do not control will be serving whichever one its
//! operator's server happens to emit:
//!
//! - **`rcp-index.json`**, which this crate can publish itself (`rcp scan -json`). It is
//!   the only one of the three that carries a mode, a real mtime and a digest, so it is
//!   tried first and it is the only shape for which `keeps_times` is true.
//! - **nginx's `autoindex_format json`**: a top-level array of
//!   `{name, type: file|directory|other, mtime, size}`. Sizes and dates come with the
//!   listing, so no per-file `HEAD` is needed.
//! - **Apache `mod_autoindex` and everything shaped like it** (Caddy, lighttpd, Python's
//!   `http.server`): an HTML page of `<a href>` links. This carries nothing but names, so
//!   size and mtime cost a `HEAD` per file, exactly as rclone's http backend does.
//!
//! **The HTML reader is where the judgement is**, because an autoindex page is full of
//! links that are not entries and treating one as a file is how a copy acquires a file
//! called `?C=N;O=D`. Four kinds are dropped, each for its own reason:
//!
//! - a link carrying a **query or a fragment** is a control, not a name: `?C=M;O=A` is the
//!   sort order and `#foo` is a position on the page. A real file whose name contains `?`
//!   arrives percent-encoded as `%3F`, so cutting on the literal loses nothing.
//! - a link that **leaves this directory** -- absolute to another authority, or rooted
//!   somewhere else, or `../` -- is navigation. Apache's "Parent Directory" is exactly
//!   this and it is the link that makes a naive walker climb out of the tree.
//! - a link **equal to the directory itself** is the self-link, the same trap WebDAV's
//!   `PROPFIND Depth: 1` sets with its own entry: followed, the directory contains itself
//!   and the walk does not terminate.
//! - a **duplicate** name, because Apache emits the icon link and the text link for the
//!   same entry and a reader that takes both reports every file twice.
//!
//! A trailing `/` means a collection. That is the only signal HTML gives, and it is the
//! one every one of these servers emits.

use std::collections::BTreeSet;
use std::io;

use crate::catalog::Kind;
use crate::json::{self, Json};

/// One entry of a listing, before it becomes an `Item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i128,
    pub mode: u32,
    /// only `rcp-index.json` carries one; it lets `verify` check content without asking
    /// the far side to hash a second time
    pub digest: Option<String>,
}

impl Entry {
    fn dir(name: String) -> Entry {
        Entry {
            name,
            kind: Kind::Dir,
            size: 0,
            mtime_ns: 0,
            mode: 0o755,
            digest: None,
        }
    }

    fn file(name: String, size: u64) -> Entry {
        Entry {
            name,
            kind: Kind::File,
            size,
            mtime_ns: 0,
            mode: 0o644,
            digest: None,
        }
    }
}

/// Which listing shape a body is, decided by looking at it rather than by asking the
/// server: `Content-Type` on an autoindex page is `text/html` either way, and nginx's JSON
/// array and an HTML document are told apart by their first non-space byte.
pub(crate) fn looks_like_json(body: &[u8]) -> bool {
    body.iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'[' || *b == b'{')
}

/// `rcp-index.json`: the `entry` events of `rcp scan -json`, one per line or as an array.
///
/// Read as **newline-delimited JSON first**, because that is what `rcp scan -json`
/// actually emits -- a stream of objects, not a document -- and a publisher who simply
/// redirects the scan into a file gets a working index with no post-processing. An array
/// is accepted too, for a publisher who wrapped it.
pub(crate) fn parse_rcp_index(body: &[u8], under: &str) -> io::Result<Vec<Entry>> {
    let bad =
        |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("rcp-index.json: {why}"));
    let mut rows: Vec<Json> = Vec::new();
    let text = std::str::from_utf8(body).map_err(|e| bad(e.to_string()))?;
    if looks_like_json(body) && text.trim_start().starts_with('[') {
        match json::parse(body).map_err(bad)? {
            Json::Array(a) => rows = a,
            _ => return Err(bad("the document is not an array of entries".into())),
        }
    } else {
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let v =
                json::parse(line.as_bytes()).map_err(|e| bad(format!("line {}: {e}", n + 1)))?;
            rows.push(v);
        }
    }

    let mut out = Vec::new();
    for v in rows {
        // `rcp scan -json` emits `done` and `warning` objects beside the entries, and an
        // index is the entries. Anything without a path is not one.
        if v.get("event")
            .and_then(Json::as_str)
            .is_some_and(|e| e != "entry")
        {
            continue;
        }
        let Some(path) = v.get("path").and_then(Json::as_str) else {
            continue;
        };
        // An index is supplied by the remote server. A parent component is navigation,
        // never a child: carrying it into Item.rel would let a copy escape its destination.
        if path.split('/').any(|component| component == "..") || path.contains('\0') {
            return Err(bad(format!("unsafe entry path {path:?}")));
        }
        // The index describes a whole tree; this call wants one directory of it. `under`
        // is that directory relative to the index root, and a path outside it is another
        // directory's business -- NOT an error, because one index serves every level.
        let Some(rest) = strip_under(path, under) else {
            continue;
        };
        // and only the immediate children: `a/b/c` is not a child of `a`
        if rest.contains('/') || rest == "." || rest == ".." {
            continue;
        }
        let kind = match v.get("kind").and_then(Json::as_str) {
            Some("d") => Kind::Dir,
            Some("l") => Kind::Symlink,
            _ => Kind::File,
        };
        out.push(Entry {
            name: rest.to_string(),
            kind,
            size: v.get("size").and_then(Json::as_u64).unwrap_or(0),
            mtime_ns: v
                .get("mtime_ns")
                .and_then(Json::as_i64)
                .map(i128::from)
                .unwrap_or(0),
            mode: v
                .get("mode")
                .and_then(Json::as_u64)
                .map(|m| m as u32)
                .unwrap_or(if kind == Kind::Dir { 0o755 } else { 0o644 }),
            digest: v
                .get("digest")
                .and_then(Json::as_str)
                .filter(|d| !d.is_empty())
                .map(str::to_string),
        });
    }
    Ok(out)
}

/// `a/b/c` under `a` is `b/c`; under `` it is itself; under `x` it is nothing.
fn strip_under<'a>(path: &'a str, under: &str) -> Option<&'a str> {
    let path = path.trim_start_matches("./").trim_start_matches('/');
    let under = under.trim_matches('/');
    if under.is_empty() {
        return (!path.is_empty()).then_some(path);
    }
    let rest = path.strip_prefix(under)?.strip_prefix('/')?;
    (!rest.is_empty()).then_some(rest)
}

/// nginx `autoindex_format json`: `[{"name":"a","type":"file","mtime":"...","size":12}]`.
pub(crate) fn parse_nginx_json(body: &[u8]) -> io::Result<Vec<Entry>> {
    let bad =
        |why: String| io::Error::new(io::ErrorKind::InvalidData, format!("the JSON index: {why}"));
    let Json::Array(rows) = json::parse(body).map_err(bad)? else {
        return Err(bad("the document is not an array".into()));
    };
    let mut out = Vec::new();
    for v in rows {
        let Some(name) = v.get("name").and_then(Json::as_str) else {
            continue;
        };
        // nginx does not escape `/` in a name and nothing here should invent one: a name
        // with a separator in it is not a child of this directory
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            continue;
        }
        let mut e = match v.get("type").and_then(Json::as_str) {
            Some("directory") => Entry::dir(name.to_string()),
            // `other` is a socket, a fifo or a device: nginx says so, and none of them is
            // something to copy. Dropped rather than guessed at as a file.
            Some("other") => continue,
            _ => Entry::file(
                name.to_string(),
                v.get("size").and_then(Json::as_u64).unwrap_or(0),
            ),
        };
        if let Some(ns) = v
            .get("mtime")
            .and_then(Json::as_str)
            .and_then(crate::time::parse_http_date_ns)
        {
            e.mtime_ns = ns;
        }
        out.push(e);
    }
    Ok(out)
}

/// An Apache-style HTML autoindex: every `<a href>` that names a child of this directory.
///
/// `dir` is the request path, decoded, with no trailing slash -- what a self-link and a
/// parent link are compared against.
pub(crate) fn parse_html(body: &[u8], dir: &str) -> io::Result<Vec<Entry>> {
    let text = String::from_utf8_lossy(body);
    let mut out: Vec<Entry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let dir = dir.trim_end_matches('/');
    for href in hrefs(&text) {
        // a query or a fragment makes it a control on the page, not a name
        if href.contains('?') || href.contains('#') || href.is_empty() {
            continue;
        }
        let trailing = href.ends_with('/');
        // An absolute URL is kept only when it is under this same directory; anything
        // else is a link off the page. The authority is not compared here because the
        // pool refuses another authority anyway -- what matters is that it is not a child.
        let path = match href
            .find("://")
            .and_then(|i| href[i + 3..].find('/').map(|j| i + 3 + j))
        {
            Some(i) => &href[i..],
            None => href,
        };
        let decoded = crate::net::http::percent_decode(path);
        let name = if decoded.starts_with('/') {
            // rooted: a child of this directory or nothing
            let Some(rest) = decoded.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) else {
                continue;
            };
            rest.trim_end_matches('/').to_string()
        } else {
            decoded.trim_end_matches('/').to_string()
        };
        // `..` is the parent link every one of these servers emits, and the empty name is
        // the self-link; both are the trap that makes a walk climb or loop
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.starts_with("../")
        {
            continue;
        }
        // Apache emits the icon link and the text link for the same entry
        if !seen.insert(name.clone()) {
            continue;
        }
        out.push(if trailing {
            Entry::dir(name)
        } else {
            Entry::file(name, 0)
        });
    }
    Ok(out)
}

/// Every `href="..."` in the document, in order. A deliberately small reader: an autoindex
/// page is generated HTML and this needs the attribute, not a document model.
fn hrefs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(at) = text[i..].find("href").map(|j| i + j) {
        let mut k = at + 4;
        while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || bytes[k] != b'=' {
            i = at + 4;
            continue;
        }
        k += 1;
        while k < bytes.len() && (bytes[k] as char).is_ascii_whitespace() {
            k += 1;
        }
        let quote = if k < bytes.len() && (bytes[k] == b'"' || bytes[k] == b'\'') {
            bytes[k]
        } else {
            0
        };
        if quote != 0 {
            k += 1;
            match text[k..].find(quote as char) {
                Some(end) => {
                    out.push(&text[k..k + end]);
                    i = k + end + 1;
                }
                None => break,
            }
        } else {
            let end = text[k..]
                .find([' ', '>', '\t', '\n'])
                .map(|j| k + j)
                .unwrap_or(bytes.len());
            out.push(&text[k..end]);
            i = end;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apache_autoindex_page_yields_its_entries_and_none_of_its_controls() {
        // the shape Apache mod_autoindex emits, sort links and parent link included
        let page = r##"<html><head><title>Index of /pub</title></head><body>
<h1>Index of /pub</h1>
<table>
 <tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
 <tr><td><a href="/icons/back.gif"><img src="/icons/back.gif"></a></td><td><a href="/">Parent Directory</a></td></tr>
 <tr><td><a href="/icons/folder.gif"></a></td><td><a href="sub/">sub/</a></td></tr>
 <tr><td><a href="a.txt">a.txt</a></td></tr>
 <tr><td><a href="a.txt">a.txt</a></td></tr>
 <tr><td><a href="with%20space.bin">with space.bin</a></td></tr>
 <tr><td><a href="../escape.txt">up</a></td></tr>
 <tr><td><a href="https://elsewhere.example/other.txt">off site</a></td></tr>
 <tr><td><a href="#top">top</a></td></tr>
</table></body></html>"##;
        let e = parse_html(page.as_bytes(), "/pub").unwrap();
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["sub", "a.txt", "with space.bin"],
            "the listing took a control for an entry, or lost an entry"
        );
        assert_eq!(
            e[0].kind,
            Kind::Dir,
            "a trailing slash is the only signal HTML gives for a collection"
        );
        assert_eq!(e[1].kind, Kind::File);
        // the controls, spelled out: each of these is dropped for its own reason and a
        // reader that dropped everything would pass the assertion above too
        assert!(
            !names.contains(&"escape.txt"),
            "a ../ link climbed out of the directory"
        );
        assert!(
            !names.contains(&"other.txt"),
            "a link to another site became a file"
        );
        assert!(
            !names.iter().any(|n| n.contains("C=")),
            "a sort control became a file"
        );
        assert!(
            !names.contains(&"back.gif"),
            "an icon under /icons became a child of /pub"
        );
    }

    #[test]
    fn an_absolute_href_under_the_same_directory_is_still_a_child() {
        let page = r#"<a href="http://h/pub/a.txt">a</a><a href="http://h/other/b.txt">b</a>"#;
        let e = parse_html(page.as_bytes(), "/pub");
        let names: Vec<String> = e.unwrap().into_iter().map(|x| x.name).collect();
        assert_eq!(
            names,
            vec!["a.txt"],
            "an absolute link under this directory is a child; one elsewhere is not"
        );
    }

    #[test]
    fn nginx_json_carries_kind_size_and_date_without_a_head_per_file() {
        let body = br#"[
          {"name":"sub","type":"directory","mtime":"Tue, 15 Nov 1994 12:45:26 GMT"},
          {"name":"a.txt","type":"file","mtime":"Tue, 15 Nov 1994 12:45:26 GMT","size":12},
          {"name":"dev0","type":"other"},
          {"name":"bad/name","type":"file","size":1}
        ]"#;
        let e = parse_nginx_json(body).unwrap();
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["sub", "a.txt"],
            "a device or a name with a separator became an entry"
        );
        assert_eq!(
            (e[1].size, e[1].mtime_ns),
            (12, 784_903_526_000_000_000),
            "the listing's own size and date were not used"
        );
        assert_eq!(e[0].kind, Kind::Dir);
    }

    #[test]
    fn an_rcp_index_is_read_as_the_scan_emits_it_and_only_one_directory_at_a_time() {
        // exactly what `rcp scan -json` writes: one object per line, `done` included
        let body = br#"{"event":"entry","path":"a.txt","kind":"f","size":3,"mtime_ns":784903526000000000,"mode":420,"digest":"abc"}
{"event":"entry","path":"sub","kind":"d","size":0,"mtime_ns":0,"mode":493}
{"event":"entry","path":"sub/b.txt","kind":"f","size":5,"mtime_ns":0,"mode":420}
{"event":"done","status":"passed","command":"scan"}
"#;
        let top = parse_rcp_index(body, "").unwrap();
        let names: Vec<&str> = top.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["a.txt", "sub"],
            "the root listing took a grandchild, or the done event"
        );
        assert_eq!(
            top[0].digest.as_deref(),
            Some("abc"),
            "the digest the index carries was dropped"
        );
        assert_eq!(top[0].mode, 0o644, "the mode the index carries was dropped");
        assert_eq!(top[0].mtime_ns, 784_903_526_000_000_000);

        // the same document serves the subdirectory, which is the point of one index
        let sub = parse_rcp_index(body, "sub").unwrap();
        assert_eq!(
            sub.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["b.txt"]
        );
        // the control: a directory the index does not describe lists empty, not everything
        assert!(parse_rcp_index(body, "nowhere").unwrap().is_empty());
    }

    #[test]
    fn an_rcp_index_as_an_array_reads_the_same_as_the_stream() {
        let stream = br#"{"event":"entry","path":"a.txt","kind":"f","size":3}"#;
        let array = br#"[{"event":"entry","path":"a.txt","kind":"f","size":3}]"#;
        assert_eq!(
            parse_rcp_index(stream, "").unwrap(),
            parse_rcp_index(array, "").unwrap()
        );
    }

    #[test]
    fn an_rcp_index_refuses_paths_that_escape_the_tree() {
        for path in [
            "..",
            "../victim",
            "sub/..",
            "sub/../victim",
            "/../victim",
            "./../victim",
            "bad\0name",
        ] {
            let row = format!(
                "{{\"event\":\"entry\",\"path\":{},\"kind\":\"d\"}}",
                json::quote(path)
            );
            for under in ["", "sub"] {
                assert!(
                    parse_rcp_index(row.as_bytes(), under).is_err(),
                    "accepted {path:?} under {under:?}"
                );
                assert!(parse_rcp_index(format!("[{row}]").as_bytes(), under).is_err());
            }
        }
        assert!(parse_rcp_index(br#"{"path":"\u002e\u002e/victim","kind":"f"}"#, "").is_err());
        let safe = br#"[{"path":".","kind":"d"},{"path":"./safe.txt","kind":"f"},{"path":"sub/..hidden","kind":"f"}]"#;
        assert_eq!(
            parse_rcp_index(safe, "")
                .unwrap()
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            vec!["safe.txt"]
        );
        assert_eq!(parse_rcp_index(safe, "sub").unwrap()[0].name, "..hidden");
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error_naming_the_index_rather_than_an_empty_listing() {
        let e = parse_rcp_index(b"<html>not an index</html>", "").unwrap_err();
        assert!(
            e.to_string().contains("rcp-index.json"),
            "the error does not name what could not be read: {e}"
        );
        // the control: the shape sniffer does not call an HTML page JSON in the first place
        assert!(!looks_like_json(b"<html>"));
        assert!(looks_like_json(b"  [ {} ]"));
    }
}
