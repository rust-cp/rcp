//! `OciTree`: the `Tree` port over one repository of a registry, seen as an OCI image
//! layout. Reads resolve the tags (or the one tag the endpoint names) to manifests, walk
//! indexes to their children, and present every reachable blob under `blobs/sha256/`;
//! `index.json` and `oci-layout` are synthesized. Writes upload blobs through the chunked
//! upload protocol (`POST`, `PATCH`, `PUT`), skip the ones the registry already holds, stage
//! manifests as they arrive and push them, children first, when the copy finishes.
//!
//! Authentication is the registry's own: a `Bearer` challenge is answered by fetching a token
//! from the realm it names (with basic credentials when there are any), a `Basic` challenge
//! by sending them. Credentials come from `-oci.user`, `RCP_OCI_USER` / `RCP_OCI_PASSWORD`,
//! then the container tools' files (`REGISTRY_AUTH_FILE`, `~/.docker/config.json`,
//! `$XDG_RUNTIME_DIR/containers/auth.json`).

use crate::ports::KernelFileDescriptor as RawFd;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::Settings;
use crate::base64;
use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::json::{self, Json};
use crate::net::http::{
    content_range_start, proxy_from_env, split_url, Connection, Response, Scheme, Target,
};
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, Log, MetaOptions, Refusals, Removed,
    Segment, Sink, Tree, ZEROS,
};
use crate::sha256::{self, Sha256};

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
const MEDIA_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MEDIA_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const REF_NAME: &str = "org.opencontainers.image.ref.name";
const LAYOUT: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";
/// A file up to this size is held until `finish` can tell a manifest from a layer.
const SNIFF_MAX: u64 = 8 << 20;
const MAX_MANIFEST: usize = 16 << 20;
const ATTEMPTS: usize = 4;
const TAG_PAGE: usize = 1000;
const BLOB_PREFIX: &str = "blobs/sha256/";

pub(crate) fn kind_of_status(status: u16) -> io::ErrorKind {
    match status {
        404 => io::ErrorKind::NotFound,
        401 | 403 => io::ErrorKind::PermissionDenied,
        400 | 411 | 412 | 416 => io::ErrorKind::InvalidInput,
        409 => io::ErrorKind::AlreadyExists,
        405 | 501 => io::ErrorKind::Unsupported,
        // A throttled or overloaded registry is the one failure in this list worth
        // retrying, and it used to arrive as the same `io` as everything else -- which is
        // exactly the signal an agent needs to tell a wait from a dead end.
        429 | 502 | 503 | 504 => io::ErrorKind::ResourceBusy,
        _ => io::ErrorKind::Other,
    }
}

/// The registry's own error text when the body carries one, else the status.
fn error_of(r: &Response, what: &str) -> io::Error {
    let detail = json::parse(&r.body).ok().and_then(|j| {
        let errs = j.get("errors")?.as_array()?;
        let parts: Vec<String> = errs
            .iter()
            .filter_map(|e| {
                let code = e.get("code")?.as_str()?.to_string();
                match e
                    .get("message")
                    .and_then(Json::as_str)
                    .filter(|m| !m.is_empty())
                {
                    Some(m) => Some(format!("{code}: {m}")),
                    None => Some(code),
                }
            })
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    });
    io::Error::new(
        kind_of_status(r.status),
        format!(
            "{what}: {}",
            detail.unwrap_or_else(|| format!("HTTP {}", r.status))
        ),
    )
}

fn check(r: Response, what: &str) -> io::Result<Response> {
    if r.ok() {
        Ok(r)
    } else {
        Err(error_of(&r, what))
    }
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `sha256:<hex>` to `<hex>`; any other algorithm is refused, since the layout names blobs
/// by it and nothing here could verify another one.
fn hex_of(digest: &str) -> io::Result<String> {
    match digest.strip_prefix("sha256:") {
        Some(h) if is_hex64(h) => Ok(h.to_string()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("digest {digest:?} is not sha256:<64 hex digits>"),
        )),
    }
}

fn target(scheme: Scheme, host: &str, port: u16, noverify: bool) -> io::Result<Target> {
    #[cfg(not(feature = "rustls"))]
    let _ = noverify;
    Ok(Target {
        scheme,
        host: host.to_string(),
        port,
        proxy: proxy_from_env(scheme, host),
        #[cfg(feature = "rustls")]
        tls: if scheme == Scheme::Https {
            Some(crate::net::tls::config(
                noverify,
                crate::net::tls::OCI_NOVERIFY,
            )?)
        } else {
            None
        },
    })
}

/// The path part of a `Location` header, which may be absolute.
fn location_path(loc: &str) -> String {
    match loc.find("://") {
        Some(i) => {
            let rest = &loc[i + 3..];
            rest.find('/')
                .map(|j| rest[j..].to_string())
                .unwrap_or_else(|| "/".to_string())
        }
        None => loc.to_string(),
    }
}

/// Where an upload session lives: the path, and a target of its own when the registry
/// handed the upload to another host.
///
/// It may. `POST /v2/<repo>/blobs/uploads/` answers with a `Location`, and the spec puts no
/// constraint on where it points; ECR and GAR return a signed URL on their storage host.
/// Reading only the path sends the body to the original registry under a path that means
/// nothing there. An away target
/// gets NO `Authorization` header: the signature in the URL is the credential, and this
/// registry's token is not for that host to see.
#[derive(Clone)]
struct UploadAt {
    path: String,
    away: Option<Target>,
}

fn with_query(path: &str, key: &str, value: &str) -> String {
    if path.contains('?') {
        format!("{path}&{key}={value}")
    } else {
        format!("{path}?{key}={value}")
    }
}

/// `key="value", key=value, ...` from an authentication challenge.
fn challenge_params(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = text.trim();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { break };
        let key = rest[..eq].trim().to_ascii_lowercase();
        rest = &rest[eq + 1..];
        let value;
        if let Some(r) = rest.strip_prefix('"') {
            let end = r.find('"').unwrap_or(r.len());
            value = r[..end].to_string();
            rest = &r[end.min(r.len())..];
            rest = rest.strip_prefix('"').unwrap_or(rest);
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            value = rest[..end].trim().to_string();
            rest = &rest[end..];
        }
        rest = rest
            .trim_start()
            .strip_prefix(',')
            .unwrap_or(rest)
            .trim_start();
        out.insert(key, value);
    }
    out
}

/// Docker Hub's registry is not at the name people type.
fn canonical_host(host: &str) -> &str {
    match host {
        "docker.io" | "index.docker.io" | "registry.hub.docker.com" => "registry-1.docker.io",
        h => h,
    }
}

/// `user:password` for `host` (with its port when one was given) from the container
/// tools' credential files.
fn stored_credentials(host: &str, port: Option<u16>) -> Option<String> {
    let env = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(f) = env("REGISTRY_AUTH_FILE") {
        files.push(PathBuf::from(f));
    }
    if let Some(d) = env("XDG_RUNTIME_DIR") {
        files.push(PathBuf::from(d).join("containers/auth.json"));
    }
    if let Some(d) = env("DOCKER_CONFIG") {
        files.push(PathBuf::from(d).join("config.json"));
    }
    if let Some(h) = env("HOME") {
        files.push(PathBuf::from(h).join(".docker/config.json"));
    }
    let mut wanted = vec![host.to_string()];
    if let Some(p) = port {
        wanted.insert(0, format!("{host}:{p}"));
    }
    if host == "registry-1.docker.io" {
        wanted.extend(["index.docker.io", "docker.io"].map(str::to_string));
    }
    for file in files {
        let Ok(text) = std::fs::read(&file) else {
            continue;
        };
        let Ok(doc) = json::parse(&text) else {
            continue;
        };
        let Some(Json::Object(auths)) = doc.get("auths") else {
            continue;
        };
        for (key, entry) in auths {
            let name = key
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let name = name.split('/').next().unwrap_or(name);
            if !wanted.iter().any(|w| w == name) {
                continue;
            }
            if let Some(auth) = entry.get("auth").and_then(Json::as_str) {
                if let Some(raw) = base64::decode(auth.trim()) {
                    if let Ok(s) = String::from_utf8(raw) {
                        if s.contains(':') {
                            return Some(s);
                        }
                    }
                }
            }
            if let (Some(u), Some(p)) = (
                entry.get("username").and_then(Json::as_str),
                entry.get("password").and_then(Json::as_str),
            ) {
                return Some(format!("{u}:{p}"));
            }
        }
    }
    None
}

enum Auth {
    None,
    Basic,
    Bearer(String),
}

/// Connections to one registry, the repository's scope, and whatever the registry asked
/// for to let requests through.
struct Pool {
    target: Target,
    repo: String,
    noverify: bool,
    creds: Option<String>,
    push: bool,
    /// Where an upload `Location` may hand the bytes on to; see `oci::Away`.
    away: crate::oci::Away,
    auth: Mutex<Auth>,
    idle: Mutex<Vec<Connection>>,
    log: Arc<dyn Log>,
}

impl Pool {
    fn take(&self) -> io::Result<Connection> {
        if let Some(c) = self.idle.lock().unwrap().pop() {
            return Ok(c);
        }
        Connection::connect(&self.target)
    }

    fn give(&self, c: Connection) {
        if c.idle() {
            self.idle.lock().unwrap().push(c);
        }
    }

    fn path(&self, tail: &str) -> String {
        format!("/v2/{}/{tail}", self.repo)
    }

    /// Reads a `Location` into an upload endpoint, opening a target of its own when it
    /// names another host. `base` is the session this `Location` came from, because a
    /// relative one is relative to the host that sent it -- an away host that answers the
    /// `PATCH` with a bare path means a path on itself, not back on the registry.
    fn upload_at(&self, base: Option<&UploadAt>, loc: &str) -> io::Result<UploadAt> {
        if !loc.contains("://") {
            return Ok(UploadAt {
                path: loc.to_string(),
                away: base.and_then(|b| b.away.clone()),
            });
        }
        let (scheme, host, port, path) = split_url(loc)?;
        if scheme == self.target.scheme && host == self.target.host && port == self.target.port {
            return Ok(UploadAt { path, away: None });
        }
        self.may_go_to(
            scheme,
            &host,
            port,
            "handed the upload to",
            "send blobs there",
        )?;
        crate::debug!(self.log, "oci upload handed to {host}:{port}");
        Ok(UploadAt {
            path,
            away: Some(target(scheme, &host, port, self.noverify)?),
        })
    }

    /// Whether this run may be sent to a host the REGISTRY named, rather than the operator.
    ///
    /// Two places in the protocol let the far end pick where our traffic goes: the upload
    /// `Location` and the bearer `realm`. The realm is the sharper one, because fetching a
    /// token sends the basic credentials -- so a registry answering
    /// `WWW-Authenticate: Bearer realm="http://elsewhere/token"` is handed the run's
    /// username and password. Measured before this check existed: a run railed to
    /// `-allow oci://HOST/app` sent `Basic b3BlcmF0b3I6c3VwZXJzZWNyZXQ=` to a listener on
    /// another port, which is the credential itself in the clear.
    ///
    /// Both are legitimate in the protocol -- Docker Hub's realm is `auth.docker.io` and
    /// ECR's uploads go to S3 -- so an unrailed run follows them: naming the registry is
    /// already the statement of trust. A railed one follows them only to an authority its
    /// own roots name, because `-allow` is the operator saying where this run may go.
    fn may_go_to(
        &self,
        scheme: Scheme,
        host: &str,
        port: u16,
        did: &str,
        to: &str,
    ) -> io::Result<()> {
        let name = if scheme == Scheme::Http {
            "http"
        } else {
            "https"
        };
        self.away.check(name, host, port).map_err(|refused| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} {did} {refused} to {to}", self.target.host),
            )
        })
    }

    /// The request headers with the current authorization added.
    fn headers(&self, mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
        match &*self.auth.lock().unwrap() {
            Auth::None => {}
            Auth::Basic => {
                if let Some(c) = &self.creds {
                    headers.push((
                        "authorization".into(),
                        format!("Basic {}", base64::encode(c.as_bytes())),
                    ));
                }
            }
            Auth::Bearer(t) => headers.push(("authorization".into(), format!("Bearer {t}"))),
        }
        headers
    }

    /// Answers a 401: fetches a token from the realm, or arms basic credentials. `Ok(true)`
    /// means the request is worth repeating.
    fn challenge(&self, r: &Response) -> io::Result<bool> {
        let Some(www) = r.header("www-authenticate") else {
            return Ok(false);
        };
        let (kind, params) = match www.split_once(' ') {
            Some((k, p)) => (k.to_ascii_lowercase(), challenge_params(p)),
            None => (www.to_ascii_lowercase(), BTreeMap::new()),
        };
        let hint = "credentials: -oci.user USER:PASSWORD, RCP_OCI_USER with RCP_OCI_PASSWORD, or a login in ~/.docker/config.json";
        match kind.as_str() {
            "bearer" => {
                let realm = params.get("realm").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bearer challenge names no realm",
                    )
                })?;
                let scope = params.get("scope").cloned().unwrap_or_else(|| {
                    format!(
                        "repository:{}:{}",
                        self.repo,
                        if self.push { "pull,push" } else { "pull" }
                    )
                });
                let (scheme, host, port, path) = split_url(realm)?;
                // The registry chose this host and we are about to send it the credentials.
                self.may_go_to(
                    scheme,
                    &host,
                    port,
                    "asked for a token from",
                    "get tokens there",
                )?;
                let mut q = format!("scope={}", scope.replace(',', "%2C"));
                if let Some(s) = params.get("service") {
                    q.push_str(&format!("&service={s}"));
                }
                let full = if path.contains('?') {
                    format!("{path}&{q}")
                } else {
                    format!("{path}?{q}")
                };
                let t = target(scheme, &host, port, self.noverify)?;
                let mut conn = Connection::connect(&t)?;
                let mut hs = vec![("host".to_string(), t.host_header())];
                if let Some(c) = &self.creds {
                    hs.push((
                        "authorization".into(),
                        format!("Basic {}", base64::encode(c.as_bytes())),
                    ));
                }
                let resp = conn.request("GET", &full, &hs, &[])?;
                if resp.status == 401 || resp.status == 403 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "{} refused a token for {scope}{}; {hint}",
                            host,
                            if self.creds.is_some() {
                                " with the credentials given"
                            } else {
                                " without credentials"
                            }
                        ),
                    ));
                }
                let resp = check(resp, "token")?;
                let doc = json::parse(&resp.body).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("token reply: {e}"))
                })?;
                let token = doc
                    .get("token")
                    .or_else(|| doc.get("access_token"))
                    .and_then(Json::as_str)
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "token reply carries no token")
                    })?;
                crate::debug!(self.log, "oci token for {scope} from {host}");
                *self.auth.lock().unwrap() = Auth::Bearer(token.to_string());
                Ok(true)
            }
            "basic" => {
                if self.creds.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("{} wants basic authentication; {hint}", self.target.host),
                    ));
                }
                if matches!(*self.auth.lock().unwrap(), Auth::Basic) {
                    return Ok(false);
                }
                *self.auth.lock().unwrap() = Auth::Basic;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// A buffered request with authorization, retried on transport failure and transient
    /// statuses, and repeated once after answering a challenge. Returned whatever its
    /// status; `check` classifies.
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> io::Result<Response> {
        let mut last = None;
        let mut challenged = false;
        let mut attempt = 0;
        while attempt < ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(200 << attempt));
            }
            let mut conn = match self.take() {
                Ok(c) => c,
                Err(e) => {
                    last = Some(e);
                    attempt += 1;
                    continue;
                }
            };
            let hs = self.headers(headers.clone());
            let outcome = conn.request(method, path, &hs, body);
            match &outcome {
                Ok(r) => crate::debug!(self.log, "oci {method} {path}: {}", r.status),
                Err(e) => crate::debug!(self.log, "oci {method} {path}: {e}"),
            }
            match outcome {
                Ok(r) if r.status == 401 && !challenged => {
                    self.give(conn);
                    challenged = true;
                    if self.challenge(&r)? {
                        continue;
                    }
                    return Ok(r);
                }
                Ok(r) if matches!(r.status, 429 | 500 | 502 | 503 | 504) => {
                    self.give(conn);
                    last = Some(error_of(&r, path));
                    attempt += 1;
                }
                Ok(r) => {
                    self.give(conn);
                    return Ok(r);
                }
                Err(e) => {
                    last = Some(e);
                    attempt += 1;
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no attempt made")))
    }

    /// A streaming GET's request and response head, retried on a transport failure as
    /// `request` retries a buffered one.
    ///
    /// The streaming path had no retry at all: a GET whose connection died before its
    /// status line failed the blob. That is the ordinary fate of a pooled keep-alive
    /// connection the server closed while it sat idle, and under load it happened here --
    /// a mid-blob resume reissued its GET on such a connection and the copy failed with
    /// "connection closed before the response arrived" instead of resuming. Nothing of the
    /// body has been read at this point, so asking again costs nothing.
    fn get_head(
        &self,
        path: &str,
        headers: &[(String, String)],
    ) -> io::Result<(Connection, Response)> {
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(200 << attempt));
            }
            let mut conn = match self.take() {
                Ok(c) => c,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            match conn
                .send_head("GET", path, headers, 0)
                .and_then(|()| conn.read_head(false))
            {
                Ok(r) => return Ok((conn, r)),
                Err(e) => {
                    crate::debug!(
                        self.log,
                        "oci GET {path}: {e}; asking again on another connection"
                    );
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no attempt made")))
    }

    fn head(&self, path: &str, headers: Vec<(String, String)>) -> io::Result<Option<Response>> {
        let r = self.request("HEAD", path, headers, &[])?;
        match r.status {
            404 => Ok(None),
            _ => check(r, path).map(Some),
        }
    }

    fn blob_present(&self, hex: &str) -> io::Result<bool> {
        Ok(self
            .head(&self.path(&format!("blobs/sha256:{hex}")), Vec::new())?
            .is_some())
    }
}

/// A blob the tree reaches: its size, and its bytes when it is a manifest.
struct Blob {
    size: u64,
    content: Option<Arc<Vec<u8>>>,
    /// A manifest an index names that the registry no longer holds. See `model`.
    missing: bool,
}

/// The repository resolved into a layout.
struct Model {
    blobs: BTreeMap<String, Blob>,
    index: Arc<Vec<u8>>,
    layout: Arc<Vec<u8>>,
    /// Tags the listing named whose manifest was gone when it was read. A listing error,
    /// not an absence: see `model`.
    vanished: Vec<String>,
}

fn media_of(body: &Json, content_type: Option<&str>) -> String {
    if let Some(m) = body.get("mediaType").and_then(Json::as_str) {
        return m.to_string();
    }
    if let Some(ct) = content_type {
        let ct = ct.split(';').next().unwrap_or(ct).trim();
        if ct.contains("manifest") || ct.contains("index") {
            return ct.to_string();
        }
    }
    if body.get("manifests").is_some() {
        MEDIA_INDEX.to_string()
    } else {
        MEDIA_MANIFEST.to_string()
    }
}

/// Whether bytes are an image manifest or index rather than a config or a layer.
fn is_manifest(data: &[u8]) -> bool {
    let trimmed = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &data[i..])
        .unwrap_or(data);
    if !trimmed.starts_with(b"{") {
        return false;
    }
    match json::parse(data) {
        Ok(doc) => {
            doc.get("schemaVersion").is_some()
                && (doc.get("layers").is_some()
                    || doc.get("manifests").is_some()
                    || doc.get("config").is_some())
        }
        Err(_) => false,
    }
}

/// The digests of the manifests an index names.
fn children_of(doc: &Json) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    if let Some(list) = doc.get("manifests").and_then(Json::as_array) {
        for m in list {
            let d = m.get("digest").and_then(Json::as_str).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "index entry without a digest")
            })?;
            out.push(hex_of(d)?);
        }
    }
    Ok(out)
}

/// The size each index entry declares for the manifest it names.
fn declared_sizes(doc: &Json) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let Some(list) = doc.get("manifests").and_then(Json::as_array) else {
        return out;
    };
    for m in list {
        if let (Some(hex), Some(size)) = (
            m.get("digest")
                .and_then(Json::as_str)
                .and_then(|d| hex_of(d).ok()),
            m.get("size").and_then(Json::as_u64),
        ) {
            out.insert(hex, size);
        }
    }
    out
}

/// What a manifest refers to besides other manifests: `(hex, size, media type)`.
fn layers_of(doc: &Json) -> io::Result<Vec<(String, Option<u64>, String)>> {
    let mut out = Vec::new();
    let mut take = |d: &Json| -> io::Result<()> {
        let digest = d.get("digest").and_then(Json::as_str).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "descriptor without a digest")
        })?;
        out.push((
            hex_of(digest)?,
            d.get("size").and_then(Json::as_u64),
            d.get("mediaType")
                .and_then(Json::as_str)
                .unwrap_or("application/octet-stream")
                .to_string(),
        ));
        Ok(())
    };
    if let Some(c) = doc.get("config") {
        take(c)?;
    }
    if let Some(list) = doc.get("layers").and_then(Json::as_array) {
        for l in list {
            take(l)?;
        }
    }
    if doc.get("fsLayers").is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a schema 1 manifest; only schema 2 (OCI and Docker) images are handled",
        ));
    }
    Ok(out)
}

fn item_of(rel: &str, kind: Kind, size: u64) -> Item {
    Item {
        rel: rel.to_string(),
        kind,
        size,
        mtime_ns: 0,
        atime_ns: 0,
        mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
        uid: 0,
        gid: 0,
        dev: 0,
        ino: fnv64(rel),
        nlink: 1,
        blocks: size,
        link_target: None,
    }
}

/// Manifests and tags received during a copy, pushed at the end.
#[derive(Default)]
struct Staging {
    manifests: BTreeMap<String, (String, Vec<u8>)>,
    tags: BTreeMap<String, Vec<String>>,
    /// Whether this run wrote `oci-layout`, which is the source SAYING it is a layout.
    /// A layout owes an index; see `publish`.
    saw_layout: bool,
}

pub struct OciTree {
    pool: Arc<Pool>,
    tag: Option<String>,
    display: PathBuf,
    model: Mutex<Option<Arc<Model>>>,
    staging: Arc<Mutex<Staging>>,
}

impl OciTree {
    /// Opens `repo` on `host` (`tag` narrows the tree to one image) and confirms the
    /// registry answers; a source must exist, a destination need not.
    pub fn connect(
        host: &str,
        port: Option<u16>,
        repo: &str,
        tag: Option<&str>,
        create: bool,
        settings: &Settings,
    ) -> io::Result<OciTree> {
        Self::open(host, port, repo, tag, create, true, settings)
    }

    /// The same repository for a channel that joins one already opened: the registry must
    /// still answer, but whether the tag or the repository exists is not asked again. The
    /// first open asked, and the run's own work can change the answer since -- a delete
    /// removes the last tag, and a push has not published its first.
    pub fn attach(
        host: &str,
        port: Option<u16>,
        repo: &str,
        tag: Option<&str>,
        create: bool,
        settings: &Settings,
    ) -> io::Result<OciTree> {
        Self::open(host, port, repo, tag, create, false, settings)
    }

    fn open(
        host: &str,
        port: Option<u16>,
        repo: &str,
        tag: Option<&str>,
        create: bool,
        assert_exists: bool,
        settings: &Settings,
    ) -> io::Result<OciTree> {
        let host = canonical_host(host);
        let repo = if host == "registry-1.docker.io" && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo.to_string()
        };
        let scheme = if settings.insecure {
            Scheme::Http
        } else {
            Scheme::Https
        };
        let creds = settings
            .user
            .clone()
            .or_else(|| stored_credentials(host, port));
        let port = port.unwrap_or(if scheme == Scheme::Https { 443 } else { 80 });
        let t = target(scheme, host, port, settings.noverify)?;
        let display = PathBuf::from(format!(
            "oci://{}{}/{repo}{}",
            host,
            if port == if scheme == Scheme::Https { 443 } else { 80 } {
                String::new()
            } else {
                format!(":{port}")
            },
            tag.map(|t| format!(":{t}")).unwrap_or_default()
        ));
        let pool = Arc::new(Pool {
            target: t,
            repo: repo.clone(),
            noverify: settings.noverify,
            creds,
            push: create,
            away: settings.away.clone(),
            auth: Mutex::new(Auth::None),
            idle: Mutex::new(Vec::new()),
            log: settings.log.clone(),
        });
        let ping = pool.request("GET", "/v2/", Vec::new(), &[])?;
        if ping.status == 401 {
            return Err(error_of(&ping, "the registry refused the credentials"));
        }
        if !ping.ok() && ping.status != 404 {
            return Err(error_of(&ping, "the registry's /v2/ endpoint"));
        }
        let tree = OciTree {
            pool,
            tag: tag.map(str::to_string),
            display,
            model: Mutex::new(None),
            staging: Arc::new(Mutex::new(Staging::default())),
        };
        if !create && assert_exists {
            match tag {
                Some(t) => {
                    let path = tree.pool.path(&format!("manifests/{t}"));
                    if tree
                        .pool
                        .head(&path, vec![("accept".into(), ACCEPT.into())])?
                        .is_none()
                    {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "no such tag"));
                    }
                }
                None => {
                    let r = tree.pool.request(
                        "GET",
                        &format!("{}?n=1", tree.pool.path("tags/list")),
                        Vec::new(),
                        &[],
                    )?;
                    if r.status == 404 {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "no such repository",
                        ));
                    }
                    let r = check(r, "tags")?;
                    let doc = json::parse(&r.body).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("tags listing: {e}"))
                    })?;
                    if doc
                        .get("tags")
                        .and_then(Json::as_array)
                        .is_none_or(|t| t.is_empty())
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "the repository has no tags",
                        ));
                    }
                }
            }
        }
        Ok(tree)
    }

    /// Every tag of the repository, following the listing's `Link` pages.
    fn list_tags(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        let mut next = Some(format!("{}?n={TAG_PAGE}", self.pool.path("tags/list")));
        while let Some(path) = next.take() {
            let r = self.pool.request("GET", &path, Vec::new(), &[])?;
            if r.status == 404 {
                return Ok(out);
            }
            let r = check(r, "tags")?;
            let link = r
                .header("link")
                .filter(|l| l.contains("rel=\"next\""))
                .and_then(|l| l.split(';').next())
                .map(|u| {
                    u.trim()
                        .trim_start_matches('<')
                        .trim_end_matches('>')
                        .to_string()
                });
            let doc = json::parse(&r.body).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("tags listing: {e}"))
            })?;
            let page: Vec<String> = doc
                .get("tags")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let got = page.len();
            out.extend(page);
            if let Some(l) = link {
                next = Some(location_path(&l));
            } else if got == TAG_PAGE {
                // no Link header: page by the last tag, which the API also allows
                next = out.last().map(|last| {
                    format!("{}?n={TAG_PAGE}&last={last}", self.pool.path("tags/list"))
                });
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// One manifest by tag or digest: `(hex, media type, bytes)`, the digest checked
    /// against the bytes.
    fn fetch_manifest(&self, reference: &str) -> io::Result<(String, String, Vec<u8>)> {
        let path = self.pool.path(&format!("manifests/{reference}"));
        let r = check(
            self.pool
                .request("GET", &path, vec![("accept".into(), ACCEPT.into())], &[])?,
            &format!("manifest {reference}"),
        )?;
        if r.body.len() > MAX_MANIFEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "manifest {reference}: {} bytes is not a manifest",
                    r.body.len()
                ),
            ));
        }
        let hex = sha256::digest_hex(&r.body);
        if let Some(claimed) = r.header("docker-content-digest") {
            let claimed = hex_of(claimed)?;
            if claimed != hex {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("manifest {reference}: the registry says sha256:{claimed} but the bytes are sha256:{hex}")));
            }
        }
        if let Some(want) = reference.strip_prefix("sha256:") {
            if want != hex {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("manifest {reference} came back as sha256:{hex}"),
                ));
            }
        }
        let doc = json::parse(&r.body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("manifest {reference}: {e}"),
            )
        })?;
        let media = media_of(&doc, r.header("content-type"));
        Ok((hex, media, r.body))
    }

    /// Resolves the repository (or its one tag) into the layout, once.
    fn model(&self) -> io::Result<Arc<Model>> {
        // HELD FOR THE BUILD, not just the check. Two callers that both find no model build
        // two, and a parallel `delete` is exactly two callers: one builds its model after the
        // other has deleted the index manifest and its tag, reads an empty image, and sends
        // the child manifest a BLOB delete -- which the registry refuses with 405, so the
        // manifest stays while the run reports it deferred to garbage collection. A relay arm
        // showed it failing 1 run in 3 under load. One build, before any removal.
        let mut slot = self.model.lock().unwrap();
        if let Some(m) = &*slot {
            return Ok(m.clone());
        }
        let tags = match &self.tag {
            Some(t) => vec![t.clone()],
            None => self.list_tags()?,
        };
        let mut blobs: BTreeMap<String, Blob> = BTreeMap::new();
        let mut index_entries: Vec<(String, String, u64, String)> = Vec::new(); // tag, hex, size, media
                                                                                // level by level: the tags, then the children the indexes name, and so on
        let mut level: Vec<(String, Option<String>)> =
            tags.into_iter().map(|t| (t.clone(), Some(t))).collect();
        // what each index entry says its manifest weighs, for one the registry no longer holds
        let mut declared: BTreeMap<String, u64> = BTreeMap::new();
        let mut vanished: Vec<String> = Vec::new();
        while !level.is_empty() {
            type Fetched = (
                String,
                Option<String>,
                io::Result<(String, String, Vec<u8>)>,
            );
            let results: Vec<Fetched> = {
                let next = AtomicUsize::new(0);
                let out: Mutex<Vec<Fetched>> = Mutex::new(Vec::new());
                let workers = level.len().clamp(1, 8);
                std::thread::scope(|scope| {
                    for _ in 0..workers {
                        scope.spawn(|| loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some((reference, tag)) = level.get(i) else {
                                break;
                            };
                            let r = self.fetch_manifest(reference);
                            out.lock()
                                .unwrap()
                                .push((reference.clone(), tag.clone(), r));
                        });
                    }
                });
                out.into_inner().unwrap()
            };
            let mut next_level: Vec<(String, Option<String>)> = Vec::new();
            for (reference, tag, r) in results {
                // A 404 here is the repository changing under the read, and it is not a
                // failure of the read. Two ways it happens, both measured:
                // - an index names a manifest the registry no longer holds. An interrupted
                //   delete leaves exactly that (the child went, the index had not yet), and
                //   so does a delete running on another tree -- a relay gives each of its
                //   connections one -- while this one is still being read. Failing the whole
                //   read on it means the rerun that should finish the delete cannot even list
                //   the image; the relay arm failed on the release runner with MANIFEST_UNKNOWN
                //   that way. It is listed at the size its index declares, marked
                //   missing: a delete then finds it gone, and a copy fails on that one file
                //   saying why, rather than on the whole image or not at all.
                // - a tag the listing named was deleted before its manifest was read. With
                //   no tag asked for it is left out of the image, and it is REPORTED, as a
                //   listing error: a registry that is still replicating answers the same 404
                //   for a tag it will serve a minute later, and a copy that left it out and
                //   exited 0 would have lost an image nobody was told about. A listing error
                //   fails the run, and a sync or mirror plans no removals
                //   from a listing that has one.
                let (hex, media, body) = match r {
                    Err(e) if e.kind() == io::ErrorKind::NotFound && tag.is_none() => {
                        let hex = reference.trim_start_matches("sha256:").to_string();
                        crate::debug!(
                            self.pool.log,
                            "oci manifest {reference} is named by an index but not in the registry"
                        );
                        let size = declared.get(&hex).copied().unwrap_or(0);
                        blobs.entry(hex).or_insert(Blob {
                            size,
                            content: None,
                            missing: true,
                        });
                        continue;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound && self.tag.is_none() => {
                        vanished.push(format!("tag {reference}: the registry listed it, but its manifest was not there when it was read ({e})"));
                        continue;
                    }
                    r => r?,
                };
                let doc = json::parse(&body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if let Some(t) = tag {
                    index_entries.push((t, hex.clone(), body.len() as u64, media.clone()));
                }
                if blobs.contains_key(&hex) {
                    continue;
                }
                declared.extend(declared_sizes(&doc));
                for (child_hex, size, child_media) in layers_of(&doc)? {
                    let size = match size {
                        Some(s) => s,
                        None => {
                            let r = self.pool.head(&self.pool.path(&format!("blobs/sha256:{child_hex}")), Vec::new())?.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("blob sha256:{child_hex} named by a manifest is not in the registry")))?;
                            r.header("content-length")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(0)
                        }
                    };
                    crate::debug!(
                        self.pool.log,
                        "oci blob sha256:{child_hex} {size} bytes ({child_media})"
                    );
                    blobs.entry(child_hex).or_insert(Blob {
                        size,
                        content: None,
                        missing: false,
                    });
                }
                for child in children_of(&doc)? {
                    if !blobs.contains_key(&child)
                        && !next_level
                            .iter()
                            .any(|(r, _)| r == &format!("sha256:{child}"))
                    {
                        next_level.push((format!("sha256:{child}"), None));
                    }
                }
                crate::debug!(
                    self.pool.log,
                    "oci manifest sha256:{hex} {} bytes ({media})",
                    body.len()
                );
                blobs.insert(
                    hex,
                    Blob {
                        size: body.len() as u64,
                        content: Some(Arc::new(body)),
                        missing: false,
                    },
                );
            }
            level = next_level;
        }
        index_entries.sort();
        // the exact bytes skopeo's oci: transport writes for the same image, so a layout
        // copied through a registry and back compares equal
        let mut index = String::from("{\"schemaVersion\":2,\"manifests\":[");
        for (i, (tag, hex, size, media)) in index_entries.iter().enumerate() {
            if i > 0 {
                index.push(',');
            }
            index.push_str(&format!("{{\"mediaType\":{},\"digest\":\"sha256:{hex}\",\"size\":{size},\"annotations\":{{\"{REF_NAME}\":{}}}}}", json::quote(media), json::quote(tag)));
        }
        index.push_str("]}");
        let model = Arc::new(Model {
            blobs,
            index: Arc::new(index.into_bytes()),
            layout: Arc::new(LAYOUT.to_vec()),
            vanished,
        });
        *slot = Some(model.clone());
        Ok(model)
    }

    fn forget(&self) {
        *self.model.lock().unwrap() = None;
    }

    fn items(&self, model: &Model) -> Vec<Item> {
        let mut items = vec![
            item_of(".", Kind::Dir, 0),
            item_of("blobs", Kind::Dir, 0),
            item_of("blobs/sha256", Kind::Dir, 0),
        ];
        for (hex, b) in &model.blobs {
            items.push(item_of(&format!("{BLOB_PREFIX}{hex}"), Kind::File, b.size));
        }
        items.push(item_of("index.json", Kind::File, model.index.len() as u64));
        items.push(item_of("oci-layout", Kind::File, model.layout.len() as u64));
        items
    }

    /// Pushes a manifest and everything it depends on, tagging it as `index.json` said.
    fn push_manifest(
        &self,
        hex: &str,
        staged: &mut BTreeMap<String, (String, Vec<u8>)>,
        tags: &BTreeMap<String, Vec<String>>,
        pushed: &mut BTreeSet<String>,
    ) -> io::Result<()> {
        if pushed.contains(hex) {
            return Ok(());
        }
        let wanted: &[String] = tags.get(hex).map(Vec::as_slice).unwrap_or(&[]);
        let by_digest = self.pool.path(&format!("manifests/sha256:{hex}"));
        let accept = vec![("accept".to_string(), ACCEPT.to_string())];
        let (media, body, present) = match staged.remove(hex) {
            Some((media, body)) => (media, body, false),
            None => {
                // not received in this copy: already a manifest here, or here as a blob only
                if let Some(r) = self.pool.head(&by_digest, accept.clone())? {
                    if wanted.is_empty() {
                        pushed.insert(hex.to_string());
                        return Ok(());
                    }
                    let _ = r;
                    let r = check(
                        self.pool.request("GET", &by_digest, accept.clone(), &[])?,
                        &by_digest,
                    )?;
                    let doc = json::parse(&r.body)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    (media_of(&doc, r.header("content-type")), r.body, true)
                } else {
                    let path = self.pool.path(&format!("blobs/sha256:{hex}"));
                    let r = self.pool.request("GET", &path, Vec::new(), &[])?;
                    if r.status == 404 {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "manifest sha256:{hex} is neither in this copy nor in the registry"
                            ),
                        ));
                    }
                    let r = check(r, &path)?;
                    let doc = json::parse(&r.body)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    (media_of(&doc, None), r.body, false)
                }
            }
        };
        let doc = json::parse(&body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("manifest sha256:{hex}: {e}"),
            )
        })?;
        for child in children_of(&doc)? {
            self.push_manifest(&child, staged, tags, pushed)?;
        }
        let headers = vec![("content-type".to_string(), media.clone())];
        if wanted.is_empty() {
            if !present {
                check(
                    self.pool.request("PUT", &by_digest, headers, &body)?,
                    &format!("push manifest sha256:{hex}"),
                )?;
                crate::debug!(self.pool.log, "oci pushed sha256:{hex} ({media})");
            }
        } else {
            for tag in wanted {
                let by_tag = self.pool.path(&format!("manifests/{tag}"));
                let current = self
                    .pool
                    .head(&by_tag, accept.clone())?
                    .and_then(|r| r.header("docker-content-digest").map(str::to_string));
                if current.as_deref() == Some(&format!("sha256:{hex}")) {
                    continue;
                }
                check(
                    self.pool.request("PUT", &by_tag, headers.clone(), &body)?,
                    &format!("push manifest {tag}"),
                )?;
                crate::debug!(self.pool.log, "oci pushed {tag} -> sha256:{hex} ({media})");
            }
        }
        pushed.insert(hex.to_string());
        Ok(())
    }

    /// Everything staged during the copy, in dependency order.
    /// Every staged digest `index.json`'s roots reach, following the children of the
    /// staged manifests themselves. A digest that is not staged is not walked: it is
    /// already in the registry, or it is a layer.
    fn reachable(
        &self,
        roots: &[String],
        staged: &BTreeMap<String, (String, Vec<u8>)>,
    ) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut queue: Vec<String> = roots.to_vec();
        while let Some(hex) = queue.pop() {
            if !seen.insert(hex.clone()) {
                continue;
            }
            if let Some((_, body)) = staged.get(&hex) {
                if let Ok(doc) = json::parse(body) {
                    queue.extend(children_of(&doc).unwrap_or_default());
                }
            }
        }
        seen
    }

    fn publish(&self) -> io::Result<()> {
        let (mut staged, tags, saw_layout) = {
            let mut st = self.staging.lock().unwrap();
            (
                std::mem::take(&mut st.manifests),
                std::mem::take(&mut st.tags),
                std::mem::take(&mut st.saw_layout),
            )
        };
        // A copy into a registry repository is a copy of an IMAGE, and an image needs a
        // tag pushed. `oci-layout` is the source SAYING it is an OCI layout, and a layout
        // owes an `index.json` -- so a run that wrote one and never got an index naming
        // anything has produced no image, whatever it uploaded.
        //
        // Two cases reach this from opposite ends. Measured without this check, both: a
        // full layout with its index removed uploaded 3 blobs, pushed 0 manifests and said
        // PASSED; a layout holding one plain blob and no index uploaded 1, pushed 0 and
        // said PASSED. Asking whether anything had been STAGED guards only the first, and
        // is a question about what happened to sniff as a manifest rather than about what
        // the source was.
        //
        // The condition is deliberately about the layout marker and not about "uploaded
        // something and pushed no tag", which would fail a legitimate resume: there the
        // destination already shows `index.json` and `oci-layout`, so both are skipped and
        // `saw_layout` is false while a missing blob still goes up. Copying loose blobs
        // with a filter that excluded the marker stays allowed for the same reason -- the
        // run never claimed to be moving a layout.
        if saw_layout && tags.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: the source is an OCI layout whose index.json names nothing, so this copy would create no image ({} manifest(s) held back rather than stored as blobs nothing references)",
                    self.pool.repo,
                    staged.len()
                ),
            ));
        }
        if staged.is_empty() && tags.is_empty() {
            return Ok(());
        }
        // `index.json` names the roots and everything else is reached from them, so what
        // it does not reach was never a manifest however much it looked like one. Those
        // go up as blobs, and FIRST: a manifest that references one would be refused for
        // a blob the registry does not have yet.
        let roots: Vec<String> = tags.keys().cloned().collect();
        // With NO roots at all, that rule sends EVERY manifest up as an unreferenced blob
        // and pushes no tag: the repository ends up holding bytes no client can name, and
        // unguarded, the run says PASSED. Measured on a layout with its `index.json`
        // removed: 3 blobs uploaded, 0 manifests pushed, status PASSED. A
        // copy into a registry repository is a copy of an IMAGE, and this one produced
        // none, so it fails -- and fails here, before the blobs go up, so a refusal costs
        // nothing. `index.json` is required of an OCI layout; a source without one is
        // malformed, which is what the message says.
        let reachable = self.reachable(&roots, &staged);
        for (hex, (_, body)) in staged.iter() {
            if !reachable.contains(hex) {
                crate::debug!(
                    self.pool.log,
                    "oci sha256:{hex} reads as a manifest but nothing reaches it; stored as a blob"
                );
                if !self.pool.blob_present(hex)? {
                    OciSink::upload_whole(&self.pool, hex, body)?;
                }
            }
        }
        staged.retain(|hex, _| reachable.contains(hex));
        let mut pushed = BTreeSet::new();
        for hex in roots {
            self.push_manifest(&hex, &mut staged, &tags, &mut pushed)?;
        }
        self.forget();
        Ok(())
    }
}

fn blob_hex(rel: &str) -> Option<&str> {
    rel.strip_prefix(BLOB_PREFIX).filter(|h| is_hex64(h))
}

impl Tree for OciTree {
    type Reader = OciReader;
    type Sink = OciSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        _parallel: usize,
    ) -> io::Result<Listing> {
        let model = self.model()?;
        let now = filter::now_ns();
        let mut items = Vec::new();
        for it in self.items(&model) {
            if it.rel != "." && max_depth.is_some_and(|d| it.depth() > d) {
                continue;
            }
            if it.rel != "." && !filter.allows(&it.rel, it.kind == Kind::Dir) {
                continue;
            }
            if it.kind == Kind::File
                && !(filter.allows_file(it.size, it.mtime_ns, now)
                    && filter.allows_owner_kind(it.kind, it.uid, it.gid, it.ino))
            {
                continue;
            }
            items.push(it);
        }
        items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        Ok(Listing {
            items,
            errors: model.vanished.clone(),
        })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        let model = self.model()?;
        Ok(self.items(&model).into_iter().find(|i| i.rel == rel))
    }

    fn open(&self, rel: &str) -> io::Result<OciReader> {
        let model = self.model()?;
        let (source, size) = match rel {
            "index.json" => (Source::Bytes(model.index.clone()), model.index.len() as u64),
            "oci-layout" => (
                Source::Bytes(model.layout.clone()),
                model.layout.len() as u64,
            ),
            _ => {
                let hex = blob_hex(rel).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("{rel}: not in the image"))
                })?;
                let blob = model.blobs.get(hex).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("{rel}: not in the image"))
                })?;
                if blob.missing {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "{rel}: an index names this manifest but the registry does not hold it"
                        ),
                    ));
                }
                match &blob.content {
                    Some(c) => (Source::Bytes(c.clone()), blob.size),
                    None => (
                        Source::Blob {
                            hex: hex.to_string(),
                            conn: None,
                            hasher: None,
                        },
                        blob.size,
                    ),
                }
            }
        };
        Ok(OciReader {
            pool: self.pool.clone(),
            source,
            pos: 0,
            size,
            resumed_at: None,
            stalls_left: STALLS,
            cuts: 0,
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

    fn create_file(&self, item: &Item) -> io::Result<OciSink> {
        let what = match item.rel.as_str() {
            "oci-layout" => What::Ignored,
            "index.json" => What::Index(Vec::new()),
            rel => {
                let hex = blob_hex(rel).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{rel}: a registry takes only blobs/sha256/<digest>, index.json and oci-layout")))?;
                if self.pool.blob_present(hex)? {
                    crate::debug!(self.pool.log, "oci sha256:{hex} is already in the registry");
                    What::Present
                } else if item.size <= SNIFF_MAX {
                    What::Buffer {
                        hex: hex.to_string(),
                        buf: Vec::with_capacity(item.size as usize),
                    }
                } else {
                    What::Stream {
                        hex: hex.to_string(),
                        conn: None,
                        at: UploadAt {
                            path: String::new(),
                            away: None,
                        },
                        written: 0,
                        size: item.size,
                    }
                }
            }
        };
        Ok(OciSink {
            pool: self.pool.clone(),
            staging: self.staging.clone(),
            rel: item.rel.clone(),
            what,
            size: item.size,
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut OciSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        match rel {
            "." | "blobs" | "blobs/sha256" => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{rel}: a registry has no directory but blobs/sha256"),
            )),
        }
    }

    fn symlink(&self, rel: &str, _target: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{rel}: a registry holds no symlinks"),
        ))
    }

    fn hard_link(&self, _existing: &str, _rel: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a registry holds no hard links; the blob is uploaded, or already there",
        ))
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        // Neither of these is an object the registry holds: `index.json` and `oci-layout`
        // are views this adapter renders over the tag list, and a registry has no
        // directory but `blobs/sha256`. Removing the manifests IS what removes them, so
        // the end state the caller asked for holds and `Gone` is the honest answer.
        if kind == Kind::Dir || rel == "index.json" || rel == "oci-layout" {
            return Ok(Removed::Gone);
        }
        let hex = blob_hex(rel).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{rel}: not in the image"))
        })?;
        // What the model says the digest is -- and when the model does not know it at all, it
        // is not a blob this tree listed but one it cannot place: a model read after part of
        // the image was already deleted (another tree on the far side of a relay, each with
        // its own) lacks the manifests that the deletion left untagged. Ask the registry, with
        // a HEAD rather than a DELETE: a DELETE is not a type probe, because a 405 there says
        // the METHOD is refused, not what the digest is.
        let manifest = match self.model()?.blobs.get(hex) {
            Some(b) => b.content.is_some() || b.missing,
            None => self
                .pool
                .head(
                    &self.pool.path(&format!("manifests/sha256:{hex}")),
                    vec![("accept".into(), ACCEPT.into())],
                )?
                .is_some(),
        };
        if manifest {
            let path = self.pool.path(&format!("manifests/sha256:{hex}"));
            let r = self.pool.request("DELETE", &path, Vec::new(), &[])?;
            match r.status {
                404 => Ok(Removed::Gone),
                405 => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("{rel}: this registry does not delete manifests"),
                )),
                // a 403 is the registry refusing, not a fault in this run -- but a 401 is
                // a credential this run cannot fix by rerunning, and keying on the error
                // KIND could not tell the two apart because `kind_of_status` calls both
                // `PermissionDenied`. Decided from the status; see `delete_refused`.
                status => match check(r, rel) {
                    Ok(_) => Ok(Removed::Gone),
                    Err(e) => crate::net::http::delete_refused(status, rel, e),
                },
            }
        } else {
            let path = self.pool.path(&format!("blobs/sha256:{hex}"));
            let r = self.pool.request("DELETE", &path, Vec::new(), &[])?;
            match r.status {
                // 404 is gone; 405 is NOT. Docker Hub, ECR and Artifact Registry all
                // answer 405 here -- blobs belong to the registry's garbage collector --
                // and this returned `Ok(())` for both, so the run counted three blobs
                // removed that the registry still holds. A debug line said so, which the
                // summary did not read and the operator did not see.
                404 => Ok(Removed::Gone),
                // Deferred, not kept: the registry WILL remove it, on its collector's
                // schedule, and there is nothing for the operator to do -- which is the
                // difference between this and a lock somebody else holds.
                405 => Ok(Removed::Deferred("the registry does not delete blobs on request; this one is left to its garbage collection, which the registry's operator runs".into())),
                // a 403 is the registry refusing, which is Kept and not a failure; a 401
                // is a credential, which is a failure of the run. See `delete_refused`.
                status => match check(r, rel) {
                    Ok(_) => Ok(Removed::Gone),
                    Err(e) => crate::net::http::delete_refused(status, rel, e),
                },
            }
        }
    }

    fn rename(&self, from: &str, _to: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{from}: blobs are named by their content and cannot be renamed"),
        ))
    }

    fn set_metadata(&self, _rel: &str, _item: &Item, _opts: MetaOptions) -> io::Result<Refusals> {
        Ok(Refusals::default()) // a registry keeps no modes, times or owners
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

    /// The end of a copy: the manifests go up now that their blobs are there.
    fn sync(&self) -> io::Result<()> {
        self.publish()
    }
    /// The blobs are uploaded as they are copied; the manifests that make them an image are
    /// pushed here, so a registry is not a destination that has received the copy until this
    /// has run.
    fn keeps_times(&self) -> bool {
        // A registry stores blobs by digest and no times at all, so every item this
        // adapter lists is built with `mtime_ns: 0`. The trait default is `true`, and
        // without this override the planner and `verify` both believe a registry carries
        // the source's times -- so a correct, complete copy to one is reported by `verify`
        // as an mtime difference on EVERY file, and a later `sync` compares
        // `same_mtime(source, 0)` and recopies.
        //
        // The contract suite must not ASSERT that behavior (`assert_failed(verify, "DIFF
        // mtime")`): an arm pinning a defect in place is worse than no arm, because it makes
        // the defect look intended.
        //
        // Tar is genuinely the other way and is NOT grouped here: it writes the source
        // mtime into each header, so the default `true` is the honest answer there.
        false
    }

    // a registry carries no mode, owner or xattr: the adapter synthesizes 0644/0755 and uid 0
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
        false // a registry keeps no modes, owners or times at all; see `set_metadata`
    }

    fn sync_publishes(&self) -> bool {
        true
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

#[expect(
    clippy::large_enum_variant,
    reason = "one per open file; boxing buys nothing"
)]
enum Source {
    Bytes(Arc<Vec<u8>>),
    /// A streaming `GET`, reissued with a `Range` after a seek; a read from the start is
    /// digested and checked against the name at the end.
    Blob {
        hex: String,
        conn: Option<Connection>,
        hasher: Option<Sha256>,
    },
}

pub struct OciReader {
    pool: Arc<Pool>,
    source: Source,
    pos: u64,
    size: u64,
    /// The offset a mid-stream resume was last attempted at, so one that makes no progress
    /// is not attempted twice. A blob may be resumed any number of times as long as each
    /// one moves; the first that does not is the last.
    resumed_at: Option<u64>,
    /// How many non-delivering reconnections in a row this blob may still have (see
    /// `STALLS`). On the reader, not in a local: a count was tried inside `read` first,
    /// where it reset on every call, capped resumes per call rather than per blob, and
    /// watched 977 of them sail past a limit of 64.
    stalls_left: u32,
    /// Every cut so far, for the refusal to say how many there were.
    cuts: u32,
}

/// The bound on reconnections that are NOT delivering: after this many in a row that each
/// carried fewer than `STALL_BYTES`, the blob is called undeliverable. A reconnection that
/// delivers a kilobyte or more resets the count.
///
/// Why not a budget of resumes derived from the blob's size, such as `(size / 1024)`
/// clamped to `[64, 4096]`? The ceiling looks defensible -- "4096 resumes over a 4 GiB
/// layer is one drop per mebibyte" -- but above 4 MiB the budget is frozen, so the SAME
/// link the suite already models as "many resumes finish", 2 KiB delivered per cut, needs
/// 5120 resumes for a 10 MiB layer and is refused while every one of them is delivering.
/// Reproduced with that formula: `the registry cut the stream 4097 times over 10485760
/// bytes ... it is not delivering this blob`. A 10 MiB fixture shows it; no
/// multi-gigabyte one is needed.
///
/// The rule such a formula reaches for is "a link that cannot carry a kilobyte between drops is not
/// a link." That is a statement about progress per reconnection, not about how many reconnections a
/// blob of a given size may have, so it is measured as that. It is size-independent by
/// construction, and the dribbling server the ceiling was for -- 64 bytes per cut -- is refused
/// after sixty-four of them whatever size it declares. What it does not bound is a server that
/// delivers exactly a kilobyte per connection forever against a size of `u64::MAX`; that server can
/// equally hold one connection open and trickle forever, and no per-blob bound here would change
/// that. It is one reconnection per kilobyte, which is the rate the linear region of the
/// size-derived formula allows.
///
/// The reset admits a pattern -- a kilobyte, then a byte, then a kilobyte -- and it is fair to ask
/// whether that is worse than a size cap. It is bounded, and the bound is worth writing down: a run
/// that is never refused delivers at least `STALL_BYTES` in every `STALLS` reconnections, so a blob
/// of `size` bytes costs at most `STALLS * (size / STALL_BYTES + 1)` reconnections before it is
/// either complete or refused -- the `+ 1` is the final partial kilobyte, which a 100-byte blob
/// tolerating 63 one-byte cuts demonstrates. For 10 MiB that is 655,424, against a 4,096 cap --
/// more, and every one of them buys progress, since a reconnection that moves the offset by nothing
/// is refused outright. A server that wants to cost this client a TLS handshake per kilobyte can do
/// it either way.
const STALLS: u32 = 64;
const STALL_BYTES: u64 = 1024;

impl OciReader {
    fn start(&mut self) -> io::Result<()> {
        let Source::Blob { hex, conn, hasher } = &mut self.source else {
            return Ok(());
        };
        let path = self.pool.path(&format!("blobs/sha256:{hex}"));
        let mut headers = Vec::new();
        if self.pos > 0 {
            headers.push(("range".to_string(), format!("bytes={}-", self.pos)));
        }
        // the first request may need a challenge answered; a buffered HEAD settles that
        // before the streaming GET, which cannot be repeated once its body is flowing
        if matches!(*self.pool.auth.lock().unwrap(), Auth::None) {
            self.pool.head(&path, Vec::new())?;
        }
        crate::debug!(
            self.pool.log,
            "oci GET blob sha256:{hex} from byte {}",
            self.pos
        );
        // A token has a lifetime -- Docker Hub's is about five minutes -- and a copy of a
        // large image outlives it. A 401 here is that expiry, not a refusal: answer the
        // challenge and ask again. Once is enough; a second means the credentials really
        // are wrong. Nothing has been read from the body at this point, so reissuing the
        // GET is free, which is why the challenge is answered here and never mid-stream.
        let mut c = None;
        for attempt in 0..2 {
            let hs = self.pool.headers(headers.clone());
            let (mut conn, r) = self.pool.get_head(&path, &hs)?;
            if r.ok() {
                // A `Range` is a request, not a guarantee. A server free to ignore it
                // answers 200 with the WHOLE blob, and then every byte from `pos` on is
                // really a byte from zero: the destination is filled with the blob's head
                // written at its tail. The digest catches that for a resume, because the
                // hasher rides across and ends up fed the wrong bytes -- measured against
                // a stand-in that cuts and ignores `Range`, the copy fails, blaming the
                // blob. But `Seek` clears the hasher, so on that path there is no digest
                // left to catch anything and the mis-assembly would be silent.
                //
                // So require what was asked for: a ranged request is answered 206, or it
                // is refused here, before a byte is placed at the wrong offset. The
                // message names the server's behavior rather than the blob's bytes.
                //
                // And 206 alone is not enough. It says "here is a range" without saying
                // WHICH, and a server that answers 206 while sending from zero puts the
                // blob's head at its tail just as surely as a 200 does. So read the
                // `Content-Range` it is required to carry and require it to start where
                // the read stopped. The 200 half and this half are the same mistake,
                // which is trusting a reply's shape instead of its content.
                if self.pos > 0 {
                    let wrong = if r.status != 206 {
                        Some(format!(
                            "answered {} with the whole blob; it does not honor Range",
                            r.status
                        ))
                    } else {
                        match r.header("content-range").and_then(content_range_start) {
                            Some(at) if at == self.pos => None,
                            Some(at) => Some(format!("answered 206 starting at {at}")),
                            None => Some("answered 206 with no usable Content-Range".to_string()),
                        }
                    };
                    if let Some(what) = wrong {
                        let mut r = r;
                        r.body = conn.drain().unwrap_or_default();
                        self.pool.give(conn);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("sha256:{hex}: asked for bytes from {} and the registry {what}, so this read cannot be continued", self.pos),
                        ));
                    }
                }
                c = Some(conn);
                break;
            }
            let mut r = r;
            r.body = conn.drain().unwrap_or_default();
            self.pool.give(conn);
            if r.status == 401 && attempt == 0 && self.pool.challenge(&r)? {
                crate::debug!(
                    self.pool.log,
                    "oci blob sha256:{hex}: the token expired mid-copy, renewed"
                );
                continue;
            }
            return Err(error_of(&r, &path));
        }
        let c = c.expect("the loop returns on failure");
        // A fresh read hashes from the start. A reissued one keeps whatever hasher it had:
        // for a mid-stream resume that is the hasher holding bytes 0..pos, and the `Range`
        // request delivers pos.. , so nothing is skipped and the digest still guards the
        // whole blob. `Seek` is the case where bytes ARE skipped, and it clears the hasher
        // itself before changing `pos`, so there is nothing to carry.
        *hasher = if self.pos == 0 {
            Some(Sha256::new())
        } else {
            hasher.take()
        };
        *conn = Some(c);
        Ok(())
    }
}

impl Read for OciReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        match &mut self.source {
            Source::Bytes(b) => {
                let n = ((self.size - self.pos) as usize).min(buf.len());
                buf[..n].copy_from_slice(&b[self.pos as usize..self.pos as usize + n]);
                self.pos += n as u64;
                Ok(n)
            }
            Source::Blob { .. } => {
                // A token expires MID-BODY on a large blob and the registry simply stops
                // sending: the 200 and its headers are long gone, so there is no 401 to
                // read, only a dead stream. This is the half the before-the-body retry
                // does not reach. It is reachable, and cheaply, because `start` already
                // asks with `Range: bytes=pos-`: drop the connection and reissue, and the
                // reissued GET meets the 401 where it CAN be answered. The hasher rides
                // across, since a Range resume skips nothing and the digest check is the
                // only thing making a partial read safe.
                //
                // A LOOP, not recursion (`return self.read(buf)` after reopening).
                // Recursion invites a stack overflow: `resumed_at` stops a resume repeating
                // at an offset that moved nothing, so progress bounds the NUMBER of resumes
                // and not the DEPTH, because a server that sends a byte and dies makes
                // progress every time.
                //
                // The crash did not reproduce, and that is worth recording rather than
                // quietly claiming a fix. Against a stand-in that hangs up every 64 bytes
                // of a 4 MB layer -- 62,502 reconnections, so 62,502 frames -- a RECURSIVE
                // version completed, in 51 s. The frames are small and the stack absorbed
                // them.
                //
                // It is a loop anyway, because the depth is chosen by the far end and
                // nothing here bounds it; 62,502 survived on this machine, which says
                // nothing about a smaller stack or a larger blob. Iterating costs a few
                // lines and removes the question instead of leaving it to be re-asked.
                //
                // Two things bound the NUMBER of resumes. Progress: `resumed_at` refuses a
                // second attempt at an offset that did not move. And a budget on the
                // reader -- progress alone is not a bound, because a server that sends one
                // byte and hangs up moves the offset every time, so the only limit would be
                // the size the server itself declared.
                //
                // The count lives on the reader, not in a local here: a local resets on
                // every call to `read`, so it caps resumes per CALL rather than per blob
                // and sails past a limit of 64. It counts reconnections that did not
                // deliver rather than reconnections -- see `STALLS` for why.
                loop {
                    if matches!(&self.source, Source::Blob { conn: None, .. }) {
                        self.start()?;
                    }
                    let pos = self.pos;
                    let Source::Blob { hex, conn, hasher } = &mut self.source else {
                        unreachable!("the source does not change kind")
                    };
                    let c = conn.as_mut().expect("start opened it");
                    let read = match c.read_body(buf) {
                        Ok(0) if pos < self.size => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the registry stopped sending",
                        )),
                        other => other,
                    };
                    let n = match read {
                        Ok(n) => n,
                        Err(e) => {
                            if self.resumed_at == Some(pos) || hasher.is_none() {
                                return Err(e);
                            }
                            self.cuts += 1;
                            // progress since the last reissue is what the bound is about
                            let delivered = pos.saturating_sub(self.resumed_at.unwrap_or(0));
                            if delivered >= STALL_BYTES {
                                self.stalls_left = STALLS;
                            } else {
                                // decremented THEN tested: tested-then-decremented
                                // refused on the 65th stall while saying "the last 64"
                                self.stalls_left -= 1;
                                if self.stalls_left == 0 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        format!("sha256:{hex}: the registry cut the stream {} times over {} bytes, and the last {STALLS} reconnections each delivered under {STALL_BYTES} bytes; it is not delivering this blob", self.cuts, self.size),
                                    ));
                                }
                            }
                            crate::debug!(self.pool.log, "oci blob sha256:{hex}: the stream died at {pos} of {} bytes ({e}); reissuing from there", self.size);
                            *conn = None;
                            self.resumed_at = Some(pos);
                            continue;
                        }
                    };
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "sha256:{hex}: the blob ended at {pos} of {} bytes",
                                self.size
                            ),
                        ));
                    }
                    if let Some(h) = hasher {
                        h.update(&buf[..n]);
                    }
                    self.pos = pos + n as u64;
                    if self.pos >= self.size {
                        let mut done = conn.take().expect("still open");
                        let _ = done.drain();
                        self.pool.give(done);
                        if let Some(h) = hasher.take() {
                            let got = h.hex();
                            if &got != hex {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("sha256:{hex}: the registry served bytes with digest sha256:{got}")));
                            }
                        }
                    }
                    return Ok(n);
                }
            }
        }
    }
}

impl Seek for OciReader {
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
            if let Source::Blob { conn, hasher, .. } = &mut self.source {
                *conn = None;
                *hasher = None;
            }
            self.pos = target;
            // A seek is a new stream, so the stall accounting starts over with it.
            // Otherwise `pos - resumed_at` after a seek BEHIND the last resume point is an
            // underflow -- a panic in a debug build and a wrapped "delivered" count in a
            // release one, which resets the budget as if a great deal had arrived.
            self.resumed_at = None;
            self.stalls_left = STALLS;
        }
        Ok(self.pos)
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "one per open file; boxing buys nothing"
)]
enum What {
    /// The registry has this blob: the bytes are not wanted.
    Present,
    /// `oci-layout`: nothing to store.
    Ignored,
    /// `index.json`: read for its tags.
    Index(Vec<u8>),
    /// Held until `finish` decides between a manifest (staged) and a blob (uploaded).
    Buffer { hex: String, buf: Vec<u8> },
    /// One chunked upload streaming as the bytes arrive.
    Stream {
        hex: String,
        conn: Option<Connection>,
        at: UploadAt,
        written: u64,
        size: u64,
    },
}

pub struct OciSink {
    pool: Arc<Pool>,
    staging: Arc<Mutex<Staging>>,
    rel: String,
    what: What,
    size: u64,
}

impl OciSink {
    /// Whether the destination already holds this content, and how long it is; the
    /// generic engine skips the source read then.
    pub fn present_len(&self) -> Option<u64> {
        match self.what {
            What::Present | What::Ignored => Some(self.size),
            _ => None,
        }
    }

    /// Opens an upload session: `POST` for the location, then a `PATCH` whose body is the
    /// blob, declared at `size`.
    fn start_upload(pool: &Pool, size: u64) -> io::Result<(Connection, UploadAt)> {
        let r = check(
            pool.request("POST", &pool.path("blobs/uploads/"), Vec::new(), &[])?,
            "start upload",
        )?;
        let at = pool.upload_at(
            None,
            r.header("location").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upload started without a Location",
                )
            })?,
        )?;
        let ct = vec![(
            "content-type".to_string(),
            "application/octet-stream".to_string(),
        )];
        let hs = if at.away.is_some() {
            ct
        } else {
            pool.headers(ct)
        };
        let mut conn = match &at.away {
            Some(t) => Connection::connect(t)?,
            None => pool.take()?,
        };
        conn.send_head("PATCH", &at.path, &hs, size)?;
        Ok((conn, at))
    }

    /// Reads the `PATCH` reply and commits the upload under its digest, at wherever that
    /// reply says the session now lives -- which may be a third place again.
    fn commit_upload(
        pool: &Pool,
        mut conn: Connection,
        at: &UploadAt,
        hex: &str,
    ) -> io::Result<()> {
        let mut r = conn.read_head(false)?;
        r.body = conn.drain()?;
        if at.away.is_none() {
            pool.give(conn);
        }
        let r = check(r, &format!("upload sha256:{hex}"))?;
        let at = match r.header("location") {
            Some(l) => pool.upload_at(Some(at), l)?,
            None => at.clone(),
        };
        let put = with_query(&at.path, "digest", &format!("sha256:{hex}"));
        match &at.away {
            None => check(
                pool.request("PUT", &put, Vec::new(), &[])?,
                &format!("commit sha256:{hex}"),
            )
            .map(|_| ()),
            Some(t) => {
                let mut c = Connection::connect(t)?;
                c.send_head("PUT", &put, &[], 0)?;
                let mut r = c.read_head(false)?;
                r.body = c.drain()?;
                check(r, &format!("commit sha256:{hex}")).map(|_| ())
            }
        }
    }

    fn upload_whole(pool: &Pool, hex: &str, data: &[u8]) -> io::Result<()> {
        let (mut conn, at) = Self::start_upload(pool, data.len() as u64)?;
        conn.write_body(data)?;
        Self::commit_upload(pool, conn, &at, hex)
    }
}

impl Sink for OciSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        if let What::Stream { conn, at, size, .. } = &mut self.what {
            *size = len;
            let (c, a) = Self::start_upload(&self.pool, len)?;
            *conn = Some(c);
            *at = a;
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.what {
            What::Present | What::Ignored => Ok(()),
            What::Index(buf) => {
                if buf.len() + data.len() > MAX_MANIFEST {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "index.json: not an index (too large)",
                    ));
                }
                buf.extend_from_slice(data);
                Ok(())
            }
            What::Buffer { buf, .. } => {
                buf.extend_from_slice(data);
                Ok(())
            }
            What::Stream {
                conn,
                written,
                size,
                ..
            } => {
                if conn.is_none() {
                    let (c, a) = Self::start_upload(&self.pool, *size)?;
                    *conn = Some(c);
                    if let What::Stream { at, .. } = &mut self.what {
                        *at = a;
                    }
                    return self.write(data);
                }
                if *written + data.len() as u64 > *size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: more bytes than the {size} declared", self.rel),
                    ));
                }
                conn.as_mut().unwrap().write_body(data)?;
                *written += data.len() as u64;
                Ok(())
            }
        }
    }

    fn hole(&mut self, mut len: u64) -> io::Result<()> {
        if matches!(self.what, What::Present | What::Ignored) {
            return Ok(());
        }
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
        let refusals = Refusals {
            owner: false,
            xattrs: xattrs.iter().map(|(n, _)| n.clone()).collect(),
        };
        match std::mem::replace(&mut self.what, What::Ignored) {
            What::Present => {}
            What::Ignored => {
                // `oci-layout` carries nothing to store, and it carries one fact: the
                // source calls itself an OCI image layout. `publish` needs that, because a
                // layout owes an `index.json` and a source that skipped one produces no
                // image however many blobs it sent.
                if self.rel == "oci-layout" {
                    self.staging.lock().unwrap().saw_layout = true;
                }
            }
            What::Index(buf) => {
                let doc = json::parse(&buf).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("index.json: {e}"))
                })?;
                let mut st = self.staging.lock().unwrap();
                for m in doc.get("manifests").and_then(Json::as_array).unwrap_or(&[]) {
                    let hex = hex_of(m.get("digest").and_then(Json::as_str).unwrap_or(""))?;
                    let tags = st.tags.entry(hex).or_default();
                    if let Some(t) = m
                        .get("annotations")
                        .and_then(|a| a.get(REF_NAME))
                        .and_then(Json::as_str)
                    {
                        if !tags.iter().any(|x| x == t) {
                            tags.push(t.to_string());
                        }
                    }
                }
            }
            What::Buffer { hex, buf } => {
                let got = sha256::digest_hex(&buf);
                if got != hex {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: the content's digest is sha256:{got}, not its name",
                            self.rel
                        ),
                    ));
                }
                // Sniffing JSON is a guess, and `publish` is where it is settled: what
                // `index.json` reaches is pushed as a manifest, and what it does not is
                // uploaded as the blob it evidently was. Deciding it here instead meant a
                // layer that happens to be JSON with the manifest keys was staged INSTEAD
                // of uploaded, and its parent then failed with MANIFEST_BLOB_UNKNOWN -- a
                // broken image, for a guess.
                if is_manifest(&buf) {
                    let doc = json::parse(&buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    let media = media_of(&doc, None);
                    crate::debug!(self.pool.log, "oci staged manifest sha256:{hex} ({media})");
                    self.staging
                        .lock()
                        .unwrap()
                        .manifests
                        .insert(hex, (media, buf));
                } else {
                    Self::upload_whole(&self.pool, &hex, &buf)?;
                }
            }
            What::Stream {
                hex,
                conn,
                at,
                written,
                size,
            } => {
                let Some(conn) = conn else {
                    // reserve was never called and nothing was written: an empty blob
                    Self::upload_whole(&self.pool, &hex, &[])?;
                    return Ok(refusals);
                };
                if written != size {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: {written} bytes arrived for {size} declared (the source changed during the copy)", self.rel)));
                }
                Self::commit_upload(&self.pool, conn, &at, &hex)?;
            }
        }
        Ok(refusals)
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

#[cfg(test)]
mod tests {
    /// A seek starts the stall accounting over. It did not: `resumed_at` survived a
    /// seek, so a cut after a seek BEHIND it computed `pos - resumed_at` on a `pos`
    /// smaller than `resumed_at` -- a panic in a debug build, and in a release build a
    /// wrapped count that read as a great deal delivered and reset the budget.
    #[test]
    fn a_seek_starts_the_stall_accounting_over() {
        use super::*;
        let pool = Arc::new(Pool {
            target: target(Scheme::Http, "127.0.0.1", 1, false).unwrap(),
            repo: "r".into(),
            noverify: false,
            creds: None,
            push: false,
            away: crate::oci::Away::Anywhere,
            auth: Mutex::new(Auth::None),
            idle: Mutex::new(Vec::new()),
            log: Arc::new(crate::ports::Silent),
        });
        let mut r = OciReader {
            pool,
            source: Source::Blob {
                hex: "0".repeat(64),
                conn: None,
                hasher: None,
            },
            pos: 900,
            size: 4096,
            resumed_at: Some(800),
            stalls_left: 3,
            cuts: 5,
        };
        r.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!((r.resumed_at, r.stalls_left, r.pos), (None, STALLS, 100));
        // the control: a seek to the current position is a no-op and keeps the state,
        // which is what the client's read-ahead window sends
        r.resumed_at = Some(50);
        r.stalls_left = 2;
        r.stream_position().unwrap();
        assert_eq!((r.resumed_at, r.stalls_left), (Some(50), 2));
    }

    use super::*;

    #[test]
    fn challenge_parameters_and_locations_parse() {
        let p = challenge_params(
            r#"realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push""#,
        );
        assert_eq!(
            p.get("realm").map(String::as_str),
            Some("https://auth.example/token")
        );
        assert_eq!(
            p.get("service").map(String::as_str),
            Some("registry.example")
        );
        assert_eq!(
            p.get("scope").map(String::as_str),
            Some("repository:a/b:pull,push")
        );
        let p = challenge_params("realm=\"x\", charset=UTF-8");
        assert_eq!(p.get("charset").map(String::as_str), Some("UTF-8"));
        assert_eq!(
            location_path("http://h:5000/v2/r/blobs/uploads/abc?_state=1"),
            "/v2/r/blobs/uploads/abc?_state=1"
        );
        assert_eq!(
            location_path("/v2/r/blobs/uploads/abc"),
            "/v2/r/blobs/uploads/abc"
        );
        assert_eq!(
            with_query("/a?b=1", "digest", "sha256:x"),
            "/a?b=1&digest=sha256:x"
        );
        assert_eq!(with_query("/a", "digest", "sha256:x"), "/a?digest=sha256:x");
        assert_eq!(
            split_url("https://auth.example/token?x=1").unwrap(),
            (
                Scheme::Https,
                "auth.example".into(),
                443,
                "/token?x=1".into()
            )
        );
        // a 206's Content-Range says WHERE the body starts, and the unit is
        // case-insensitive (RFC 9110). Requiring lowercase made a legal `Bytes 500-...`
        // read as no usable header at all, refusing a resume that would have worked.
        assert_eq!(content_range_start("bytes 500-999/1000"), Some(500));
        assert_eq!(content_range_start("Bytes 500-999/1000"), Some(500));
        assert_eq!(content_range_start("  BYTES  0-9/10 "), Some(0));
        // a range the server refused names no first byte, so it is not the one asked for
        assert_eq!(content_range_start("bytes */1000"), None);
        assert_eq!(content_range_start("items 1-2/3"), None);
        assert_eq!(
            split_url("http://h:5000").unwrap(),
            (Scheme::Http, "h".into(), 5000, "/".into())
        );
        assert!(split_url("ftp://h/").is_err());

        // A bracketed IPv6 literal carries colons of its own, so the port is what follows
        // the closing bracket. A guard of `the host part contains no colon` declines to
        // split ANY bracketed host: `[::1]:5000` comes out as the host `[::1]:5000` on port
        // 80, and the authority built from it -- `http://[::1]:5000:80` -- can never match
        // `-allow http://[::1]:5000`. That false denial fails closed, so a refused hand-off
        // rather than an admitted one, which is why it is easy to miss without this arm.
        assert_eq!(
            split_url("http://[::1]:5000/v2/").unwrap(),
            (Scheme::Http, "[::1]".into(), 5000, "/v2/".into())
        );
        assert_eq!(
            split_url("https://[fe80::1%25eth0]:8443/t").unwrap(),
            (Scheme::Https, "[fe80::1%25eth0]".into(), 8443, "/t".into())
        );
        // and with no port the scheme's default still applies, rather than the last hex
        // group being read as one
        assert_eq!(
            split_url("https://[::1]/v2/").unwrap(),
            (Scheme::Https, "[::1]".into(), 443, "/v2/".into())
        );
        assert_eq!(
            split_url("http://[2001:db8::5]/").unwrap(),
            (Scheme::Http, "[2001:db8::5]".into(), 80, "/".into())
        );

        // Userinfo is not part of the host. `user@host:5000` became the host `user@host`,
        // which matches no rail and resolves to nothing -- and it carries a credential a
        // registry put in a URL, which is never where this client takes one from.
        assert_eq!(
            split_url("https://user:pass@auth.example:8443/token").unwrap(),
            (Scheme::Https, "auth.example".into(), 8443, "/token".into())
        );
        assert_eq!(
            split_url("http://someone@[::1]:5000/v2/").unwrap(),
            (Scheme::Http, "[::1]".into(), 5000, "/v2/".into())
        );

        // the control on all of that: the ordinary forms must not have moved
        assert_eq!(
            split_url("https://reg.example/v2/").unwrap(),
            (Scheme::Https, "reg.example".into(), 443, "/v2/".into())
        );
        assert_eq!(
            split_url("http://reg.example:80/v2/").unwrap(),
            (Scheme::Http, "reg.example".into(), 80, "/v2/".into())
        );
        assert!(split_url("http:///nohost").is_err());
    }

    #[test]
    fn manifests_are_told_from_configs_and_layers() {
        assert!(is_manifest(br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:a","size":1},"layers":[]}"#));
        assert!(is_manifest(br#"{"schemaVersion":2,"manifests":[]}"#));
        // an image config has a "config" object too, but no schemaVersion
        assert!(!is_manifest(
            br#"{"architecture":"amd64","config":{"Env":[]},"rootfs":{"type":"layers"}}"#
        ));
        assert!(!is_manifest(b"\x1f\x8b\x08 not json"));
        assert!(!is_manifest(b"{ broken"));
        let doc = json::parse(br#"{"schemaVersion":2,"config":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000001","size":7},"layers":[{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000002","size":9,"mediaType":"x"}]}"#).unwrap();
        let l = layers_of(&doc).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].1, Some(9));
        assert!(hex_of("md5:abc").is_err());
        assert!(hex_of("sha256:ABCD").is_err());
        assert_eq!(canonical_host("docker.io"), "registry-1.docker.io");
        assert_eq!(canonical_host("ghcr.io"), "ghcr.io");
    }

    #[test]
    fn credentials_are_read_from_the_container_tools_file() {
        let dir = std::env::temp_dir().join(format!("rcp-oci-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("auth.json");
        std::fs::write(&file, format!(r#"{{"auths":{{"https://index.docker.io/v1/":{{"auth":"{}"}},"registry.example:5000":{{"username":"u","password":"p"}}}}}}"#, base64::encode(b"hub:secret"))).unwrap();
        std::env::set_var("REGISTRY_AUTH_FILE", &file);
        assert_eq!(
            stored_credentials("registry-1.docker.io", None).as_deref(),
            Some("hub:secret")
        );
        assert_eq!(
            stored_credentials("registry.example", Some(5000)).as_deref(),
            Some("u:p")
        );
        assert_eq!(stored_credentials("registry.example", None), None);
        assert_eq!(stored_credentials("other.example", None), None);
        std::env::remove_var("REGISTRY_AUTH_FILE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The registry's reading of a URL was once the loosest: `[::1]x` came out as host
    /// `[::1]x` on the default port, an authority that fails in DNS later rather than here.
    /// Malformed is refused now, by the shared `net::http::split_url`.
    #[test]
    fn text_after_an_ipv6_bracket_is_refused_not_kept_as_the_host() {
        for bad in [
            "http://[::1]x/v2/",
            "http://[::1]:abc/v2/",
            "http://[::1/v2/",
            "http://::1/v2/",
            "http://[]/v2/",
            "http://junk[::1]:5000/v2/",
            "http://junk[::1]/v2/",
        ] {
            assert!(split_url(bad).is_err(), "{bad} was accepted");
        }
        // the control: the well-formed bracket forms still parse, so the refusal is about
        // the trailing text and not about brackets
        let (_, h, p, _) = split_url("http://[::1]:5000/v2/").unwrap();
        assert_eq!((h.as_str(), p), ("[::1]", 5000));
        let (_, h, p, _) = split_url("https://[::1]/v2/").unwrap();
        assert_eq!((h.as_str(), p), ("[::1]", 443));
    }
}
