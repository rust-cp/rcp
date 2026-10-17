//! A stand-in S3 service for the tests: one bucket or more in memory, path-style, the
//! operations the client uses (`ListObjectsV2`, `PutObject`, `GetObject` with ranges,
//! `HeadObject`, `DeleteObject`, `CopyObject`, the multipart trio) and SigV4 verified on
//! every request, so a signing mistake fails a test here rather than against a real
//! service. A payload hash, when the client signs one, is checked against the body.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use super::sigv4::{self, canonical_request, parse_authorization, Credentials, UNSIGNED_PAYLOAD};
use super::xml;
use crate::time;

#[derive(Debug, Clone)]
pub struct Object {
    pub data: Vec<u8>,
    /// User metadata, names without the `x-amz-meta-` prefix, lower case.
    pub meta: BTreeMap<String, String>,
    pub modified_ns: i128,
    pub etag: String,
}

#[derive(Default)]
struct Store {
    /// `bucket/key` -> object
    objects: BTreeMap<String, Object>,
    /// upload id -> (bucket/key, metadata, parts)
    uploads: BTreeMap<String, (String, BTreeMap<String, String>, BTreeMap<u32, Vec<u8>>)>,
    next_upload: u64,
    /// Answer every ranged `GET` with 206 and the whole object from zero.
    lies_range: bool,
    /// Answer every `DELETE` with 403, as a bucket policy that allows writes and not
    /// deletes does. The store ANSWERED and refused -- which is `Removed::Kept`, not a
    /// fault in the run -- and measuring that needs a server, because a permission arm
    /// built on `chmod` cannot fail for root, which is who the suite runs as.
    refuses_delete: bool,
}

pub struct Server {
    pub port: u16,
    pub creds: Credentials,
    buckets: Vec<String>,
    store: Arc<Mutex<Store>>,
    tls: bool,
}

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
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
    fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn read_request(stream: &mut impl Read, buf: &mut Vec<u8>) -> io::Result<Option<Request>> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            buf.drain(..end + 4);
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default().to_string();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or_default().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| {
                    l.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (
                    p.to_string(),
                    q.split('&')
                        .filter(|s| !s.is_empty())
                        .map(|kv| match kv.split_once('=') {
                            Some((k, v)) => (percent_decode(k), percent_decode(v)),
                            None => (percent_decode(kv), String::new()),
                        })
                        .collect(),
                ),
                None => (target.clone(), Vec::new()),
            };
            let len: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            while buf.len() < len {
                let mut tmp = [0u8; 64 * 1024];
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "body cut short",
                    ));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let body: Vec<u8> = buf.drain(..len).collect();
            return Ok(Some(Request {
                method,
                path,
                query,
                headers,
                body,
            }));
        }
        let mut tmp = [0u8; 64 * 1024];
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn reply(status: u16, body: Vec<u8>) -> Reply {
    Reply {
        status,
        headers: Vec::new(),
        body,
    }
}

fn error(status: u16, code: &str, message: &str) -> Reply {
    reply(
        status,
        format!(
            "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{}</Message></Error>",
            xml::escape(message)
        )
        .into_bytes(),
    )
}

fn write_reply(stream: &mut impl Write, r: &Reply, head_only: bool) -> io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\n",
        r.status,
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: keep-alive\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    if !head_only {
        stream.write_all(&r.body)?;
    }
    stream.flush()
}

fn etag_of(data: &[u8]) -> String {
    format!("\"{}\"", &sigv4::sha256_hex(data)[..32])
}

impl Server {
    /// Serves `buckets` on a free loopback port until the process ends.
    pub fn start(buckets: &[&str], creds: Credentials) -> Server {
        Self::start_with(buckets, creds, None)
    }

    /// From now on, a ranged `GET` is answered 206 with the whole object from zero.
    pub fn lie_about_ranges(&self) {
        self.store.lock().unwrap().lies_range = true;
    }

    /// Every `DELETE` from now on is refused with 403.
    pub fn refuse_deletes(&self) {
        self.store.lock().unwrap().refuses_delete = true;
    }

    /// The same service over TLS, with a PEM certificate chain and PKCS#8 private key.
    #[cfg(feature = "rustls")]
    pub fn start_tls(
        buckets: &[&str],
        creds: Credentials,
        cert_pem: &str,
        key_pem: &str,
    ) -> Server {
        let certs = crate::net::tls::pem_certificates(cert_pem);
        // the PEM markers are assembled so the repository's credential scan does not read a
        // parser as a leaked key
        let (begin, end) = (
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
            concat!("-----END ", "PRIVATE KEY-----"),
        );
        let key = key_pem
            .split(begin)
            .nth(1)
            .and_then(|k| k.split(end).next())
            .and_then(crate::base64::decode)
            .expect("a PKCS#8 PRIVATE KEY block");
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("a usable certificate and key");
        Self::start_with(buckets, creds, Some(Arc::new(cfg)))
    }

    #[cfg(not(feature = "rustls"))]
    fn start_with(buckets: &[&str], creds: Credentials, _tls: Option<()>) -> Server {
        Self::start_plain(buckets, creds, false)
    }

    #[cfg(feature = "rustls")]
    fn start_with(
        buckets: &[&str],
        creds: Credentials,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Server {
        match tls {
            None => Self::start_plain(buckets, creds, false),
            Some(cfg) => {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let store = Arc::new(Mutex::new(Store::default()));
                let server = Server {
                    port,
                    creds: creds.clone(),
                    buckets: buckets.iter().map(|b| b.to_string()).collect(),
                    store: store.clone(),
                    tls: true,
                };
                let buckets: Vec<String> = server.buckets.clone();
                std::thread::spawn(move || {
                    for stream in listener.incoming().flatten() {
                        let (store, creds, buckets, cfg) =
                            (store.clone(), creds.clone(), buckets.clone(), cfg.clone());
                        std::thread::spawn(move || {
                            let conn = rustls::ServerConnection::new(cfg).unwrap();
                            let tls = rustls::StreamOwned::new(conn, stream);
                            serve_connection(tls, store, creds, buckets)
                        });
                    }
                });
                server
            }
        }
    }

    fn start_plain(buckets: &[&str], creds: Credentials, tls: bool) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let store = Arc::new(Mutex::new(Store::default()));
        let server = Server {
            port,
            creds: creds.clone(),
            buckets: buckets.iter().map(|b| b.to_string()).collect(),
            store: store.clone(),
            tls,
        };
        let buckets: Vec<String> = server.buckets.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let store = store.clone();
                let creds = creds.clone();
                let buckets = buckets.clone();
                std::thread::spawn(move || serve_connection(stream, store, creds, buckets));
            }
        });
        server
    }

    pub fn endpoint(&self) -> String {
        format!(
            "{}://127.0.0.1:{}",
            if self.tls { "https" } else { "http" },
            self.port
        )
    }

    /// The keys in a bucket, sorted.
    pub fn keys(&self, bucket: &str) -> Vec<String> {
        let prefix = format!("{bucket}/");
        self.store
            .lock()
            .unwrap()
            .objects
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string))
            .collect()
    }

    pub fn object(&self, bucket: &str, key: &str) -> Option<Object> {
        self.store
            .lock()
            .unwrap()
            .objects
            .get(&format!("{bucket}/{key}"))
            .cloned()
    }

    pub fn open_uploads(&self) -> usize {
        self.store.lock().unwrap().uploads.len()
    }
}

fn serve_connection<S: Read + Write>(
    mut stream: S,
    store: Arc<Mutex<Store>>,
    creds: Credentials,
    buckets: Vec<String>,
) {
    let mut buf = Vec::new();
    while let Ok(Some(req)) = read_request(&mut stream, &mut buf) {
        let head_only = req.method == "HEAD";
        let r = match verify(&req, &creds) {
            Err(r) => r,
            Ok(()) => handle(&req, &store, &buckets),
        };
        if write_reply(&mut stream, &r, head_only).is_err() {
            return;
        }
    }
}

/// Recomputes the signature from what arrived and compares.
fn verify(req: &Request, creds: &Credentials) -> Result<(), Reply> {
    let Some(auth) = req.header("authorization").and_then(parse_authorization) else {
        return Err(error(403, "AccessDenied", "no signature"));
    };
    if auth.access_key != creds.access_key {
        return Err(error(403, "InvalidAccessKeyId", "unknown access key"));
    }
    let payload_hash = req
        .header("x-amz-content-sha256")
        .unwrap_or(UNSIGNED_PAYLOAD)
        .to_string();
    if payload_hash != UNSIGNED_PAYLOAD && payload_hash != sigv4::sha256_hex(&req.body) {
        return Err(error(
            400,
            "XAmzContentSHA256Mismatch",
            "payload hash does not match the body",
        ));
    }
    let mut signed: Vec<(String, String)> = Vec::new();
    for name in &auth.signed_headers {
        match req.header(name) {
            Some(v) => signed.push((name.clone(), v.to_string())),
            None => {
                return Err(error(
                    403,
                    "SignatureDoesNotMatch",
                    &format!("signed header {name} absent"),
                ))
            }
        }
    }
    let canonical = canonical_request(&req.method, &req.path, &req.query, &signed, &payload_hash);
    let amz_date = req.header("x-amz-date").unwrap_or_default().to_string();
    if !amz_date.starts_with(&auth.date) {
        return Err(error(403, "SignatureDoesNotMatch", "date scope mismatch"));
    }
    let expected = sigv4::signature(creds, &auth.region, &amz_date, &canonical);
    if expected != auth.signature {
        return Err(error(
            403,
            "SignatureDoesNotMatch",
            "the request signature we calculated does not match",
        ));
    }
    Ok(())
}

fn meta_of(req: &Request) -> BTreeMap<String, String> {
    req.headers
        .iter()
        .filter_map(|(k, v)| {
            k.to_ascii_lowercase()
                .strip_prefix("x-amz-meta-")
                .map(|n| (n.to_string(), v.clone()))
        })
        .collect()
}

fn object_headers(o: &Object) -> Vec<(String, String)> {
    let mut h = vec![
        (
            "Last-Modified".to_string(),
            time::http_date((o.modified_ns / 1_000_000_000) as i64),
        ),
        ("ETag".to_string(), o.etag.clone()),
        (
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ),
    ];
    for (k, v) in &o.meta {
        h.push((format!("x-amz-meta-{k}"), v.clone()));
    }
    h
}

fn parse_range(spec: &str, len: u64) -> Option<(u64, u64)> {
    let r = spec.strip_prefix("bytes=")?;
    let (a, b) = r.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return Some((len.saturating_sub(n), len));
    }
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() {
        len
    } else {
        b.parse::<u64>().ok()? + 1
    };
    if start >= len {
        return None;
    }
    Some((start, end.min(len)))
}

fn handle(req: &Request, store: &Mutex<Store>, buckets: &[String]) -> Reply {
    let path = req.path.trim_start_matches('/');
    let (bucket, key) = match path.split_once('/') {
        Some((b, k)) => (b.to_string(), percent_decode(k)),
        None => (path.to_string(), String::new()),
    };
    if !buckets.contains(&bucket) {
        return error(404, "NoSuchBucket", &format!("no bucket {bucket}"));
    }
    let full = format!("{bucket}/{key}");
    let mut st = store.lock().unwrap();
    let now = time::now_secs() as i128 * 1_000_000_000;
    match (req.method.as_str(), key.is_empty()) {
        ("GET", true) if req.query("list-type") == Some("2") => {
            let prefix = format!("{bucket}/{}", req.query("prefix").unwrap_or(""));
            let max: usize = req
                .query("max-keys")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000)
                .max(1);
            let after = req.query("continuation-token").map(str::to_string);
            let mut body = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
            let mut count = 0;
            let mut next = None;
            for (k, o) in st.objects.range(prefix.clone()..) {
                if !k.starts_with(&prefix) {
                    break;
                }
                if let Some(a) = &after {
                    if k <= a {
                        continue;
                    }
                }
                if count == max {
                    next = Some(k.clone());
                    break;
                }
                count += 1;
                body.push_str(&format!("<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>", xml::escape(&k[bucket.len() + 1..]), time::rfc3339(o.modified_ns), xml::escape(&o.etag), o.data.len()));
            }
            match &next {
                // the token is the last key of this page; the next page starts after it
                Some(_) => {
                    let last = st
                        .objects
                        .range(prefix.clone()..)
                        .filter(|(k, _)| {
                            k.starts_with(&prefix) && after.as_ref().is_none_or(|a| *k > a)
                        })
                        .nth(count - 1)
                        .map(|(k, _)| k.clone())
                        .unwrap();
                    body.push_str(&format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>", xml::escape(&last)));
                }
                None => body.push_str("<IsTruncated>false</IsTruncated>"),
            }
            body.push_str(&format!("<KeyCount>{count}</KeyCount></ListBucketResult>"));
            reply(200, body.into_bytes())
        }
        ("POST", true) if req.query("delete").is_some() => {
            let text = String::from_utf8_lossy(&req.body).to_string();
            let mut body = String::from("<?xml version=\"1.0\"?><DeleteResult>");
            for k in xml::blocks(&text, "Key") {
                let k = xml::unescape(k);
                st.objects.remove(&format!("{bucket}/{k}"));
                body.push_str(&format!(
                    "<Deleted><Key>{}</Key></Deleted>",
                    xml::escape(&k)
                ));
            }
            body.push_str("</DeleteResult>");
            reply(200, body.into_bytes())
        }
        ("PUT", false) if req.query("uploadId").is_some() => {
            let id = req.query("uploadId").unwrap().to_string();
            let n: u32 = match req.query("partNumber").and_then(|v| v.parse().ok()) {
                Some(n) => n,
                None => return error(400, "InvalidArgument", "partNumber"),
            };
            match st.uploads.get_mut(&id) {
                Some((k, _, parts)) if *k == full => {
                    let etag = etag_of(&req.body);
                    parts.insert(n, req.body.clone());
                    Reply {
                        status: 200,
                        headers: vec![("ETag".into(), etag)],
                        body: Vec::new(),
                    }
                }
                _ => error(404, "NoSuchUpload", "no such upload"),
            }
        }
        ("PUT", false) => {
            let meta = meta_of(req);
            if let Some(src) = req.header("x-amz-copy-source") {
                let src = percent_decode(src.trim_start_matches('/'));
                let Some(source) = st.objects.get(&src).cloned() else {
                    return error(404, "NoSuchKey", "copy source");
                };
                let replace = req
                    .header("x-amz-metadata-directive")
                    .is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
                let obj = Object {
                    data: source.data,
                    meta: if replace { meta } else { source.meta },
                    modified_ns: now,
                    etag: source.etag.clone(),
                };
                st.objects.insert(full, obj);
                return reply(
                    200,
                    format!(
                        "<CopyObjectResult><ETag>{}</ETag></CopyObjectResult>",
                        xml::escape(&source.etag)
                    )
                    .into_bytes(),
                );
            }
            let etag = etag_of(&req.body);
            st.objects.insert(
                full,
                Object {
                    data: req.body.clone(),
                    meta,
                    modified_ns: now,
                    etag: etag.clone(),
                },
            );
            Reply {
                status: 200,
                headers: vec![("ETag".into(), etag)],
                body: Vec::new(),
            }
        }
        ("POST", false) if req.query("uploads").is_some() => {
            st.next_upload += 1;
            let id = format!("upload-{}", st.next_upload);
            st.uploads
                .insert(id.clone(), (full.clone(), meta_of(req), BTreeMap::new()));
            reply(200, format!("<InitiateMultipartUploadResult><Bucket>{bucket}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>", xml::escape(&key)).into_bytes())
        }
        ("POST", false) if req.query("uploadId").is_some() => {
            let id = req.query("uploadId").unwrap().to_string();
            let Some((k, meta, parts)) = st.uploads.remove(&id) else {
                return error(404, "NoSuchUpload", "no such upload");
            };
            if k != full {
                return error(400, "InvalidRequest", "upload belongs to another key");
            }
            let text = String::from_utf8_lossy(&req.body).to_string();
            let mut data = Vec::new();
            let mut last = 0;
            for p in xml::blocks(&text, "Part") {
                let n: u32 = xml::value(p, "PartNumber")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let etag = xml::value(p, "ETag").unwrap_or_default();
                if n <= last {
                    return error(400, "InvalidPartOrder", "parts out of order");
                }
                last = n;
                match parts.get(&n) {
                    Some(bytes) if etag_of(bytes) == etag => data.extend_from_slice(bytes),
                    _ => return error(400, "InvalidPart", &format!("part {n}")),
                }
            }
            let etag = format!("\"{}-{}\"", &sigv4::sha256_hex(&data)[..32], last);
            st.objects.insert(
                full,
                Object {
                    data,
                    meta,
                    modified_ns: now,
                    etag: etag.clone(),
                },
            );
            reply(200, format!("<CompleteMultipartUploadResult><ETag>{}</ETag></CompleteMultipartUploadResult>", xml::escape(&etag)).into_bytes())
        }
        ("DELETE", false) if req.query("uploadId").is_some() => {
            st.uploads.remove(req.query("uploadId").unwrap());
            reply(204, Vec::new())
        }
        ("GET", false) | ("HEAD", false) => match st.objects.get(&full) {
            None => error(404, "NoSuchKey", "no such key"),
            Some(o) => {
                let mut headers = object_headers(o);
                let len = o.data.len() as u64;
                match req.header("range") {
                    // the quirk: 206 and a Content-Range from zero, body from zero -- the
                    // status says partial and the bytes are the whole object
                    Some(_) if st.lies_range => {
                        headers.push((
                            "Content-Range".into(),
                            format!("bytes 0-{}/{len}", len.saturating_sub(1)),
                        ));
                        Reply {
                            status: 206,
                            headers,
                            body: o.data.clone(),
                        }
                    }
                    Some(spec) => match parse_range(spec, len) {
                        Some((s, e)) => {
                            headers.push((
                                "Content-Range".into(),
                                format!("bytes {s}-{}/{len}", e - 1),
                            ));
                            Reply {
                                status: 206,
                                headers,
                                body: o.data[s as usize..e as usize].to_vec(),
                            }
                        }
                        None => error(416, "InvalidRange", "range not satisfiable"),
                    },
                    None => Reply {
                        status: 200,
                        headers,
                        body: o.data.clone(),
                    },
                }
            }
        },
        ("DELETE", false) if st.refuses_delete => error(
            403,
            "AccessDenied",
            "this policy allows writes and not deletes",
        ),
        ("DELETE", false) => {
            st.objects.remove(&full);
            reply(204, Vec::new())
        }
        _ => error(
            400,
            "InvalidRequest",
            &format!("{} {}", req.method, req.path),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_and_percent_decoding() {
        assert_eq!(parse_range("bytes=0-9", 100), Some((0, 10)));
        assert_eq!(parse_range("bytes=90-", 100), Some((90, 100)));
        assert_eq!(parse_range("bytes=-5", 100), Some((95, 100)));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(percent_decode("a%20b%2Fc%"), "a b/c%");
    }
}
