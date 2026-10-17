//! An HTTP/1.1 client with exactly what S3 needs: keep-alive connections, `Content-Length`
//! and chunked response bodies, bodies streamed in both directions (a multi-gigabyte object
//! never sits in memory), an HTTP proxy (`CONNECT` for TLS, absolute URIs for plain HTTP)
//! honoring the usual `*_PROXY` variables, and TLS behind the `tls` feature.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::base64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// `user:password`, sent as `Proxy-Authorization: Basic`.
    pub auth: Option<String>,
    /// The URL was `https://`. CONNECT and the proxy credential would go out in cleartext,
    /// because this client does not speak TLS to the proxy. Such a URL is refused.
    pub tls: bool,
}

/// Where connections go: the origin, and the proxy in front of it if the environment names one.
#[derive(Clone)]
pub struct Target {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub proxy: Option<Proxy>,
    #[cfg(feature = "rustls")]
    pub tls: Option<std::sync::Arc<rustls::ClientConfig>>,
}

impl Target {
    /// `host:port` for the Host header (the port is dropped when it is the scheme's default).
    pub fn host_header(&self) -> String {
        let default = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Parses `http://[user:pass@]host[:port]` (a bare `host:port` is taken as http).
/// An `https://` URL is parsed so the caller can refuse it: this client would send
/// `CONNECT` and `Proxy-Authorization` on a cleartext TCP connection to that host.
pub fn parse_proxy(url: &str) -> Option<Proxy> {
    let tls = url.trim().starts_with("https://");
    // The default port follows the scheme the URL names. An https URL is still refused
    // before a byte is sent; the port is recorded so the refusal names the right place.
    let default = if tls { 443 } else { 80 };
    let rest = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url.trim());
    let rest = rest.trim_end_matches('/');
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a.to_string()), h),
        None => (None, rest),
    };
    // The same bracket-aware reading as every other authority in the crate. Without it
    // `http://[::1]:3128` splits on the last colon of the ADDRESS, so an IPv6 proxy is
    // reached under a host that is not one.
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        if h.is_empty() || h.contains('[') {
            return None;
        }
        let p = match after.strip_prefix(':') {
            Some(p) if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) => return None,
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default,
            None => return None,
        };
        (format!("[{h}]"), p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p))
                if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') =>
            {
                (h.to_string(), p.parse().ok()?)
            }
            _ => (hostport.to_string(), default),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(Proxy {
        host,
        port,
        auth,
        tls,
    })
}

/// Refuses a proxy URL that would carry `CONNECT` and `Proxy-Authorization` in cleartext.
pub fn refuse_cleartext_proxy(proxy: &Proxy) -> io::Result<()> {
    if proxy.tls {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "proxy {}: an https:// proxy is refused because CONNECT and Proxy-Authorization would be sent before any TLS handshake; use an http:// proxy URL",
                proxy.host
            ),
        ))
    } else {
        Ok(())
    }
}

/// Whether `NO_PROXY` exempts `host`. `host` arrives as it is carried everywhere else --
/// an IPv6 literal still in its brackets.
///
/// The port strip is NOT a plain `rsplit_once(':')` on any entry, which is right for
/// `example.com:8080` and destroys an address: `NO_PROXY=::1` becomes the entry `::` and
/// `NO_PROXY=[::1]` becomes `[::`, so neither matches the stored `[::1]` and IPv6 traffic
/// goes through the proxy the operator has just exempted.
///
/// Both spellings are accepted because both are written in the wild, and the comparison is
/// made on the bare address so it does not matter which side wore the brackets.
fn no_proxy_matches(no_proxy: &str, host: &str) -> bool {
    let bare_host = crate::unbracketed(host).to_ascii_lowercase();
    for entry in no_proxy.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return true;
        }
        // a port is stripped only when what follows the colon is a port: a bracketed
        // literal has none to strip, and an unbracketed address is all colons
        let entry = match entry.rsplit_once(':') {
            Some((h, p))
                if !entry.starts_with('[')
                    && !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit())
                    && !h.contains(':') =>
            {
                h
            }
            Some((h, p))
                if entry.starts_with('[')
                    && h.ends_with(']')
                    && !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                h
            }
            _ => entry,
        };
        let entry = crate::unbracketed(entry.trim_start_matches('.')).to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if bare_host == entry || bare_host.ends_with(&format!(".{entry}")) {
            return true;
        }
    }
    false
}

/// The `NO_PROXY` matcher, for the arms in `dav::client` that keep the six authority
/// readers honest with one another.
#[doc(hidden)]
pub fn no_proxy_matches_for_test(no_proxy: &str, host: &str) -> bool {
    no_proxy_matches(no_proxy, host)
}

/// A `DELETE` the store answered and refused, sorted by WHY it refused -- which is the
/// difference between two remedies, and which only the status carries.
///
/// Keying `Removed::or_refused` on `io::ErrorKind::PermissionDenied` alone is not enough.
/// All four `kind_of_status` tables here map **401 and 403 to that one kind** (WebDAV adds
/// 423), so every one of them would become `Kept`, and `Kept` prints *"run `sync` again once the
/// entry can go"*. For a 403 or a 423 that is exactly right: the store answered, this entry
/// is protected or locked, somebody unlocks it, a later run gets it.
///
/// For a **401 it is wrong and cannot come right**. The run is not authenticated at all:
/// every remaining removal in the same run answers the same way, the operator has to fix a
/// credential rather than rerun, and a rerun with the same credential reproduces it
/// exactly. Telling them to rerun is advice that cannot work no matter how often it is
/// followed -- which is the same defect `or_refused` was built to fix, one status further
/// in. A **407** is that sentence about the proxy instead of the store.
///
/// So the decision is made HERE, from the status, and not inferred downstream from a kind
/// that has already thrown the difference away.
#[cfg(any(feature = "s3", feature = "dav", feature = "hdfs", feature = "oci"))]
pub(crate) fn delete_refused(
    status: u16,
    rel: &str,
    e: io::Error,
) -> io::Result<crate::ports::Removed> {
    match status {
        401 => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{rel}: the store did not accept this run's credentials (401); every removal will answer the same until they are fixed, so rerunning changes nothing: {e}"))),
        407 => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{rel}: the proxy did not accept this run's credentials (407); every removal will answer the same until they are fixed, so rerunning changes nothing: {e}"))),
        403 | 423 => Ok(crate::ports::Removed::Kept(format!("the store refused: {e}"))),
        // Anything else keeps the old rule: a kind that is not `PermissionDenied` is a
        // fault in this run and stays one. No status in the four tables maps to that kind
        // beyond the three above, so this arm is the non-refusals.
        _ => crate::ports::Removed::or_refused(e),
    }
}

/// The proxy the environment wants for `host` over `scheme`, if any.
pub fn proxy_from_env(scheme: Scheme, host: &str) -> Option<Proxy> {
    let var = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| std::env::var(n).ok())
            .filter(|v| !v.is_empty())
    };
    if let Some(np) = var(&["NO_PROXY", "no_proxy"]) {
        if no_proxy_matches(&np, host) {
            return None;
        }
    }
    let url = match scheme {
        Scheme::Https => var(&["HTTPS_PROXY", "https_proxy"]),
        Scheme::Http => var(&["HTTP_PROXY", "http_proxy"]),
    }?;
    parse_proxy(&url)
}

pub enum Stream {
    Tcp(TcpStream),
    #[cfg(feature = "rustls")]
    Tls(Box<super::tls::TlsStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(buf),
            #[cfg(feature = "rustls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(buf),
            #[cfg(feature = "rustls")]
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.flush(),
            #[cfg(feature = "rustls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

enum Body {
    None,
    Length(u64),
    Chunked { in_chunk: u64, done: bool },
    UntilClose,
}

#[derive(Debug, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

const TIMEOUT: Duration = Duration::from_secs(120);

pub struct Connection {
    stream: Stream,
    rbuf: Vec<u8>,
    rpos: usize,
    body: Body,
    /// Whether the connection may carry another request once the current body is consumed.
    pub reusable: bool,
    absolute_uris: bool,
    proxy_auth: Option<String>,
    origin: String,
    host_header: String,
}

/// One of the crate's two resolver call sites, and the one every HTTP adapter shares --
/// S3, the registry, WebHDFS, WebDAV and the proxy dial below all arrive here.
///
/// `unbracketed` is the whole IPv6 story: the host is carried WITH its brackets because
/// that is what a URL and a `Host:` header need, and `to_socket_addrs` is the one place
/// that must see the address instead of the literal.
fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let host = crate::unbracketed(host);
    let addrs = (host.as_ref(), port)
        .to_socket_addrs()
        .map_err(|e| io::Error::new(e.kind(), format!("{host}: {e}")))?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host}: no addresses"));
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(20)) {
            Ok(s) => {
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(TIMEOUT))?;
                s.set_write_timeout(Some(TIMEOUT))?;
                return Ok(s);
            }
            Err(e) => last = io::Error::new(e.kind(), format!("{host}:{port}: {e}")),
        }
    }
    Err(last)
}

impl Connection {
    pub fn connect(t: &Target) -> io::Result<Connection> {
        let host_header = t.host_header();
        let origin = format!(
            "{}://{}",
            if t.scheme == Scheme::Https {
                "https"
            } else {
                "http"
            },
            host_header
        );
        let (tcp, absolute_uris, proxy_auth) = match &t.proxy {
            None => (connect_tcp(&t.host, t.port)?, false, None),
            Some(p) => {
                refuse_cleartext_proxy(p)?;
                let auth = p.auth.as_ref().map(|a| base64::encode(a.as_bytes()));
                let mut tcp = connect_tcp(&p.host, p.port)
                    .map_err(|e| io::Error::new(e.kind(), format!("proxy {e}")))?;
                if t.scheme == Scheme::Https {
                    let mut req = format!(
                        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
                        t.host, t.port, t.host, t.port
                    );
                    if let Some(a) = &auth {
                        req.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
                    }
                    req.push_str("\r\n");
                    tcp.write_all(req.as_bytes())?;
                    let mut probe = Connection {
                        stream: Stream::Tcp(tcp),
                        rbuf: Vec::new(),
                        rpos: 0,
                        body: Body::None,
                        reusable: true,
                        absolute_uris: false,
                        proxy_auth: None,
                        origin: String::new(),
                        host_header: String::new(),
                    };
                    let r = probe.read_head(true)?;
                    if r.status != 200 {
                        return Err(io::Error::other(format!(
                            "proxy {}:{} refused CONNECT to {}:{}: HTTP {}",
                            p.host, p.port, t.host, t.port, r.status
                        )));
                    }
                    #[allow(
                        clippy::infallible_destructuring_match,
                        reason = "irrefutable only in a build without TLS"
                    )]
                    let tcp = match probe.stream {
                        Stream::Tcp(tcp) => tcp,
                        #[cfg(feature = "rustls")]
                        Stream::Tls(_) => unreachable!("the CONNECT probe is plain TCP"),
                    };
                    (tcp, false, None)
                } else {
                    (tcp, true, auth)
                }
            }
        };
        let stream = match t.scheme {
            Scheme::Http => Stream::Tcp(tcp),
            #[cfg(feature = "rustls")]
            Scheme::Https => {
                let cfg = t.tls.as_ref().ok_or_else(|| io::Error::other("no TLS configuration"))?;
                Stream::Tls(Box::new(super::tls::connect(cfg, &t.host, tcp)?))
            }
            #[cfg(not(feature = "rustls"))]
            Scheme::Https => return Err(io::Error::new(io::ErrorKind::Unsupported, "https endpoints need an rcp built with the rustls feature (cargo build --features rustls); -s3.insecure selects http")),
        };
        Ok(Connection {
            stream,
            rbuf: Vec::with_capacity(64 * 1024),
            rpos: 0,
            body: Body::None,
            reusable: true,
            absolute_uris,
            proxy_auth,
            origin,
            host_header,
        })
    }

    /// Writes the request line and headers; `Host`, `Content-Length` and keep-alive are added
    /// here. The caller then writes exactly `content_length` bytes with `write_body`.
    pub fn send_head(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        content_length: u64,
    ) -> io::Result<()> {
        if !matches!(self.body, Body::None) {
            return Err(io::Error::other("previous response body not consumed"));
        }
        let mut head = String::with_capacity(512);
        let target = if self.absolute_uris {
            format!("{}{target}", self.origin)
        } else {
            target.to_string()
        };
        head.push_str(&format!("{method} {target} HTTP/1.1\r\n"));
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            head.push_str(&format!("Host: {}\r\n", self.host_header));
        }
        for (k, v) in headers {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        if let Some(a) = &self.proxy_auth {
            head.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
        }
        if content_length > 0 || matches!(method, "PUT" | "POST") {
            head.push_str(&format!("Content-Length: {content_length}\r\n"));
        }
        head.push_str("Connection: keep-alive\r\n\r\n");
        self.stream.write_all(head.as_bytes())
    }

    pub fn write_body(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    /// A whole request with a body in memory, and the whole response.
    pub fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> io::Result<Response> {
        self.send_head(method, target, headers, body.len() as u64)?;
        if !body.is_empty() {
            self.write_body(body)?;
        }
        self.stream.flush()?;
        let mut r = self.read_head(method == "HEAD")?;
        r.body = self.drain()?;
        Ok(r)
    }

    fn fill(&mut self) -> io::Result<usize> {
        if self.rpos > 0 && self.rpos == self.rbuf.len() {
            self.rbuf.clear();
            self.rpos = 0;
        }
        let mut tmp = [0u8; 32 * 1024];
        let n = self.stream.read(&mut tmp)?;
        self.rbuf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(i) = self.rbuf[self.rpos..].iter().position(|&b| b == b'\n') {
                let line = &self.rbuf[self.rpos..self.rpos + i];
                let line = String::from_utf8_lossy(line)
                    .trim_end_matches('\r')
                    .to_string();
                self.rpos += i + 1;
                return Ok(line);
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before the response arrived",
                ));
            }
        }
    }

    /// Reads the status line and headers and arms the body reader. `head_only` for HEAD.
    pub fn read_head(&mut self, head_only: bool) -> io::Result<Response> {
        self.stream.flush()?;
        let status_line = loop {
            let l = self.read_line()?;
            if !l.is_empty() {
                break l;
            }
        };
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad status line {status_line:?}"),
            )
        })?;
        let mut headers = Vec::new();
        loop {
            let l = self.read_line()?;
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        if status == 100 {
            return self.read_head(head_only);
        }
        let r = Response {
            status,
            headers,
            body: Vec::new(),
        };
        let close = r
            .header("connection")
            .map_or(version == "HTTP/1.0", |v| v.eq_ignore_ascii_case("close"));
        self.reusable = !close;
        self.body = if head_only || status == 204 || status == 304 || (100..200).contains(&status) {
            Body::None
        } else if r
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            Body::Chunked {
                in_chunk: 0,
                done: false,
            }
        } else if let Some(n) = r
            .header("content-length")
            .and_then(|v| v.parse::<u64>().ok())
        {
            if n == 0 {
                Body::None
            } else {
                Body::Length(n)
            }
        } else {
            self.reusable = false;
            Body::UntilClose
        };
        Ok(r)
    }

    fn take_buffered(&mut self, buf: &mut [u8], max: usize) -> usize {
        let avail = &self.rbuf[self.rpos..];
        let n = avail.len().min(buf.len()).min(max);
        buf[..n].copy_from_slice(&avail[..n]);
        self.rpos += n;
        n
    }

    /// Reads body bytes; `Ok(0)` once the body is complete, after which the connection is
    /// ready for the next request (when the server allowed it).
    pub fn read_body(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.body {
                Body::None => return Ok(0),
                Body::Length(remaining) => {
                    if self.rpos == self.rbuf.len() && self.fill()? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!("connection closed with {remaining} body bytes outstanding"),
                        ));
                    }
                    let n = self.take_buffered(buf, remaining.min(usize::MAX as u64) as usize);
                    let left = remaining - n as u64;
                    self.body = if left == 0 {
                        Body::None
                    } else {
                        Body::Length(left)
                    };
                    return Ok(n);
                }
                Body::UntilClose => {
                    if self.rpos == self.rbuf.len() && self.fill()? == 0 {
                        self.body = Body::None;
                        return Ok(0);
                    }
                    return Ok(self.take_buffered(buf, usize::MAX));
                }
                Body::Chunked { in_chunk, done } => {
                    if done {
                        self.body = Body::None;
                        return Ok(0);
                    }
                    if in_chunk == 0 {
                        let line = self.read_line()?;
                        let size_text = line.split(';').next().unwrap_or("").trim();
                        let size = u64::from_str_radix(size_text, 16).map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("bad chunk size {line:?}"),
                            )
                        })?;
                        if size == 0 {
                            // trailers, then the blank line
                            while !self.read_line()?.is_empty() {}
                            self.body = Body::None;
                            return Ok(0);
                        }
                        self.body = Body::Chunked {
                            in_chunk: size,
                            done: false,
                        };
                        continue;
                    }
                    if self.rpos == self.rbuf.len() && self.fill()? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed inside a chunk",
                        ));
                    }
                    let n = self.take_buffered(buf, in_chunk.min(usize::MAX as u64) as usize);
                    let left = in_chunk - n as u64;
                    if left == 0 {
                        let crlf = self.read_line()?; // the CRLF after the chunk
                        if !crlf.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "chunk not followed by CRLF",
                            ));
                        }
                    }
                    self.body = Body::Chunked {
                        in_chunk: left,
                        done: false,
                    };
                    return Ok(n);
                }
            }
        }
    }

    /// The rest of the current body, in memory.
    pub fn drain(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = self.read_body(&mut buf)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    /// Whether the last response has been fully read, so another request may follow.
    pub fn idle(&self) -> bool {
        matches!(self.body, Body::None) && self.reusable
    }
}

/// `scheme`, host, port and the path-with-query of an `http://` or `https://` URL.
///
/// The one reading every HTTP adapter shares, and the one `Away` checks a hand-off against.
/// The authority is what follows the LAST `@`, so userinfo in a redirect is stripped and
/// `http://allowed:80@real:80/` resolves to `real:80` and is checked as such. A bracketed
/// IPv6 literal keeps its colons, and the port is only what follows the bracket.
pub fn split_url(url: &str) -> io::Result<(Scheme, String, u16, String)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url:?}: not an http:// or https:// URL"),
        ));
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let hostport = match hostport.rsplit_once('@') {
        Some((_, after)) => after,
        None => hostport,
    };
    let default = if scheme == Scheme::Https { 443 } else { 80 };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{url:?}: unterminated IPv6 literal"),
            )
        })?;
        if h.contains('[') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{url:?}: malformed IPv6 literal"),
            ));
        }
        let p = match after.strip_prefix(':') {
            // digits, and only digits: `"+80".parse::<u16>()` is `Ok(80)`, so a parse
            // alone accepts `[::1]:+80`
            Some(p) if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{url:?}: bad port"),
                ))
            }
            Some(p) => p.parse::<u16>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{url:?}: bad port"))
            })?,
            None if after.is_empty() => default,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{url:?}: trailing text after the IPv6 literal"),
                ))
            }
        };
        (format!("[{h}]"), p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("{url:?}: bad port"))
                })?,
            ),
            _ => (hostport.to_string(), default),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url:?}: no host"),
        ));
    }
    if host.contains(':') && !host.starts_with('[') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url:?}: an IPv6 address must be written in brackets"),
        ));
    }
    // A bracket anywhere in an unbracketed host is not a host: `x]y` was accepted here
    // and by the WebHDFS parser while the registry's refused it -- the one disagreement
    // the table arm found on its first run, and the reason the table exists.
    if !host.starts_with('[') && host.contains(['[', ']']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{url:?}: a bracket in the host that is not an IPv6 literal"),
        ));
    }
    Ok((scheme, host, port, path.to_string()))
}

/// The first byte a `Content-Range: bytes FIRST-LAST/TOTAL` names, if it names one.
///
/// A 206 says "here is a range" and only this header says which. A server that answers 206
/// while sending from zero mis-assembles a resumed read exactly as a 200 does, so the
/// header is read rather than the status trusted. `bytes */N` (a range the server refused)
/// names no first byte and is therefore not the one that was asked for.
pub fn content_range_start(value: &str) -> Option<u64> {
    // The unit is case-insensitive (RFC 9110), and requiring lowercase `bytes` made a
    // server answering `Bytes 500-999/1000` -- which is legal -- look like one with no
    // usable `Content-Range`, so a resume that would have worked was refused.
    let value = value.trim();
    let rest = value
        .get(..5)
        .filter(|u| u.eq_ignore_ascii_case("bytes"))
        .map(|_| &value[5..])?
        .trim_start();
    rest.split(['-', '/']).next()?.trim().parse().ok()
}

/// The total a `Content-Range: bytes FIRST-LAST/TOTAL` or `bytes */TOTAL` names.
///
/// `*/N` is what a `416` uses to say how long the representation is when the asked-for
/// range does not exist, which is how an empty file answers `Range: bytes=0-0`. `*` as
/// the total means the server does not know, so it is not a size.
pub fn content_range_total(value: &str) -> Option<u64> {
    let value = value.trim();
    let rest = value
        .get(..5)
        .filter(|u| u.eq_ignore_ascii_case("bytes"))
        .map(|_| &value[5..])?
        .trim_start();
    let total = rest.split('/').nth(1)?.trim();
    if total == "*" || total.is_empty() {
        return None;
    }
    total.parse().ok()
}

/// Percent-encodes per RFC 3986: unreserved bytes pass and everything else is `%XX` in
/// upper case, which is also the form SigV4 signs. `/` passes only when `keep_slash` is
/// true, so a whole path can go through in one call while a query value cannot.
pub fn percent_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decodes a percent-encoded path. Invalid escapes are left as they are rather than
/// dropped: a mangled name that is visible beats a silently different one.
pub fn percent_decode(s: &str) -> String {
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

/// URLs and how [`split_url`] reads them: host, port and path, or `None` for a refusal.
/// Every HTTP adapter reads a URL through `split_url` and `Away` checks a hand-off against
/// its answer, so an adapter that rewrites its own scheme first (`dav://`) is held to this
/// same table.
#[cfg(test)]
pub(crate) const AUTHORITIES: &[(&str, Option<(&str, u16, &str)>)] = &[
    ("http://host/a", Some(("host", 80, "/a"))),
    ("https://host/a", Some(("host", 443, "/a"))),
    ("http://host:8080/a/b", Some(("host", 8080, "/a/b"))),
    ("http://host", Some(("host", 80, "/"))),
    ("http://host//a", Some(("host", 80, "//a"))),
    ("http://user:pw@host:81/a", Some(("host", 81, "/a"))),
    ("http://a@b@host/a", Some(("host", 80, "/a"))),
    ("http://[::1]/a", Some(("[::1]", 80, "/a"))),
    ("http://[::1]:5000/a", Some(("[::1]", 5000, "/a"))),
    (
        "http://[::ffff:1.2.3.4]:81/a",
        Some(("[::ffff:1.2.3.4]", 81, "/a")),
    ),
    (
        "http://[fe80::1%25eth0]/a",
        Some(("[fe80::1%25eth0]", 80, "/a")),
    ),
    ("http://[FE80::ABCD]/a", Some(("[FE80::ABCD]", 80, "/a"))),
    ("http://host:0/a", Some(("host", 0, "/a"))),
    ("http://host:65536/a", None),
    ("http://host:abc/a", None),
    ("http://host:/a", None),
    ("http://[::1/a", None),
    ("http://[::1]x/a", None),
    ("http://junk[::1]:5000/a", None),
    ("http://[]/a", None),
    ("http://::1/a", None),
    ("http://x]y/a", None),
    ("http://host]:80/a", None),
    ("http://x[y]/a", None),
    ("http://[::1]:+80/a", None),
    ("http://host:+80/a", None),
    ("http://[::1]]/a", None),
    ("http://[[::1]/a", None),
    ("http:///a", None),
    ("http://@/a", None),
    ("ftp://host/a", None),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve(responses: Vec<&'static [u8]>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            for r in responses {
                // read one request head
                let mut got = Vec::new();
                let mut b = [0u8; 1];
                while !got.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).unwrap() == 0 {
                        return;
                    }
                    got.push(b[0]);
                }
                s.write_all(r).unwrap();
            }
        });
        port
    }

    fn target(port: u16) -> Target {
        Target {
            scheme: Scheme::Http,
            host: "127.0.0.1".into(),
            port,
            proxy: None,
            #[cfg(feature = "rustls")]
            tls: None,
        }
    }

    #[test]
    fn keep_alive_with_length_then_chunked_bodies() {
        let port = serve(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: 1\r\n\r\nhello",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4;ext=1\r\ndefg\r\n0\r\nX-Trailer: t\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ]);
        let mut c = Connection::connect(&target(port)).unwrap();
        let r = c.request("GET", "/a", &[], b"").unwrap();
        assert_eq!(
            (r.status, r.header("x-a"), r.body.as_slice()),
            (200, Some("1"), &b"hello"[..])
        );
        assert!(c.idle());
        let r = c.request("GET", "/b", &[], b"").unwrap();
        assert_eq!(r.body, b"abcdefg");
        assert!(c.idle());
        let r = c.request("DELETE", "/c", &[], b"").unwrap();
        assert_eq!(r.status, 204);
        assert!(!c.reusable);
    }

    #[test]
    fn a_body_can_be_streamed_in_small_reads() {
        let port = serve(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
        ]);
        let mut c = Connection::connect(&target(port)).unwrap();
        c.send_head("GET", "/x", &[], 0).unwrap();
        let r = c.read_head(false).unwrap();
        assert_eq!(r.status, 200);
        let mut got = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = c.read_body(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"0123456789");
        assert!(c.idle());
    }

    #[test]
    fn proxy_rules_from_the_environment_shape() {
        assert_eq!(
            parse_proxy("http://u:p@proxy.example:3128"),
            Some(Proxy {
                host: "proxy.example".into(),
                port: 3128,
                auth: Some("u:p".into()),
                tls: false,
            })
        );
        assert_eq!(
            parse_proxy("proxy.example"),
            Some(Proxy {
                host: "proxy.example".into(),
                port: 80,
                auth: None,
                tls: false,
            })
        );
        assert!(no_proxy_matches(
            "localhost,.internal.example, 10.0.0.1:443",
            "s3.internal.example"
        ));
        assert!(no_proxy_matches("*", "anything"));
        assert!(!no_proxy_matches("internal.example", "notinternal.example"));
        assert!(no_proxy_matches("10.0.0.1:443", "10.0.0.1"));
    }

    /// The table every HTTP adapter's reading of a URL is held to. `x]y` and `host?x=1` are
    /// the rows most likely to go wrong.
    #[test]
    fn split_url_reads_a_table_of_authorities() {
        for (url, want) in AUTHORITIES {
            let got = split_url(url).ok().map(|(_, h, p, path)| (h, p, path));
            let want = want.map(|(h, p, path)| (h.to_string(), p, path.to_string()));
            assert_eq!(got, want, "{url}");
        }
        // `host?x=1` has no path, and the query is read as part of the host -- a URL nothing
        // here produces and a name that resolves nowhere. Pinned rather than fixed, so a
        // change to it is a decision and not an accident.
        assert_eq!(
            split_url("http://host?x=1")
                .ok()
                .map(|(_, h, p, path)| (h, p, path)),
            Some(("host?x=1".to_string(), 80, "/".to_string()))
        );
    }

    /// The proxy parser, reached only through the environment, reads an authority the way
    /// `split_url` does.
    #[test]
    fn the_proxy_parser_reads_ipv6_and_default_ports() {
        // and the proxy parser, reached only through the environment
        let proxy = |u: &str| parse_proxy(u).map(|p| (p.host, p.port));
        assert_eq!(
            proxy("http://[::1]:3128"),
            Some(("[::1]".to_string(), 3128)),
            "an IPv6 proxy keeps its address"
        );
        assert_eq!(proxy("http://[::1]"), Some(("[::1]".to_string(), 80)));
        assert_eq!(
            proxy("http://host:3128"),
            Some(("host".to_string(), 3128)),
            "control: a named proxy is unchanged"
        );
        assert_eq!(proxy("http://[::1"), None);
        // the default port follows the SCHEME, as it does in every other reader. Taking 80
        // for both would dial an https proxy on 80.
        assert_eq!(
            proxy("https://proxy.example"),
            Some(("proxy.example".to_string(), 443)),
            "an https proxy defaulted to the http port"
        );
        assert_eq!(proxy("https://[::1]"), Some(("[::1]".to_string(), 443)));
        assert_eq!(
            proxy("http://proxy.example"),
            Some(("proxy.example".to_string(), 80)),
            "control: the http default is unchanged"
        );
        assert_eq!(
            proxy("https://proxy.example:3128"),
            Some(("proxy.example".to_string(), 3128)),
            "control: an explicit port still wins"
        );
        let https = parse_proxy("https://user:secret@proxy.example").unwrap();
        assert!(https.tls);
        assert!(refuse_cleartext_proxy(&https).is_err());
        assert!(refuse_cleartext_proxy(&parse_proxy("http://proxy.example").unwrap()).is_ok());
    }

    #[test]
    fn a_content_range_total_is_the_length_including_an_unsatisfiable_range() {
        assert_eq!(content_range_total("bytes 0-0/12"), Some(12));
        assert_eq!(content_range_total("bytes */0"), Some(0));
        assert_eq!(content_range_total("Bytes 500-999/1000"), Some(1000));
        assert_eq!(content_range_total("bytes 0-0/*"), None);
        assert_eq!(content_range_total("bytes 0-0"), None);
    }
}
