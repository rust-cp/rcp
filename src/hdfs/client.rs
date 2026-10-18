//! `HdfsTree`: the `Tree` port over WebHDFS. Every operation is one namenode request, and
//! reads and writes follow the 307 redirect to a datanode; the redirect target is opened as
//! its own HTTP connection, pooled by host. Ownership is by name in HDFS, so uid and gid
//! are resolved through the local passwd and group files in both directions; a name this
//! host does not know becomes 0 on listing and is set by name on the way in when the source
//! owner has a name here.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex};

use crate::catalog::Kind;
use crate::filter::{self, Filter};
use crate::json::{self, Json};
use crate::names;
use crate::net::http::{
    percent_encode, proxy_from_env, split_url, Connection, Response, Scheme, Target,
};
use crate::tree::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree, ZEROS,
};

/// The namenode for `hdfs:///path` from the environment: `HDFS_NAMENODE` or `RCP_HDFS_NAMENODE`.
pub fn hdfs_namenode_env() -> Option<String> {
    env("HDFS_NAMENODE").or_else(|| env("RCP_HDFS_NAMENODE"))
}

/// The pseudo-authentication user for WebHDFS: `RCP_HDFS_USER`, `HADOOP_USER_NAME`, else the
/// calling user's name.
pub fn hdfs_user() -> String {
    env("RCP_HDFS_USER")
        .or_else(|| env("HADOOP_USER_NAME"))
        .unwrap_or_else(|| {
            let uid = std::fs::metadata("/proc/self")
                .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
                .unwrap_or(0);
            names::user(uid)
        })
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

const ATTEMPTS: usize = 3;

/// Connections to any host the cluster redirects to, pooled by `scheme://host:port`.
pub struct Pool {
    log: Arc<dyn crate::ports::Log>,
    /// Where a `Location` may hand this run on, and the namenode's own authority, which
    /// the operator named by writing the endpoint and which is therefore always reachable.
    away: crate::ports::Away,
    origin: String,
    targets: Mutex<BTreeMap<String, Target>>,
    idle: Mutex<BTreeMap<String, Vec<Connection>>>,
    /// The `hadoop.auth` cookie a Kerberos-secured namenode hands back after a SPNEGO
    /// negotiation, scoped to its exact issuing origin so redirects cannot carry it to
    /// another host, port, or a downgraded HTTP connection.
    cookies: Mutex<BTreeMap<String, String>>,
    #[cfg(feature = "rustls")]
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl Pool {
    fn cookie_for(&self, scheme: Scheme, host: &str, port: u16) -> Option<String> {
        self.cookies
            .lock()
            .unwrap()
            .get(&Self::key(scheme, &host.to_ascii_lowercase(), port))
            .cloned()
    }

    fn remember_cookie(&self, scheme: Scheme, host: &str, port: u16, cookie: String) {
        self.cookies
            .lock()
            .unwrap()
            .insert(Self::key(scheme, &host.to_ascii_lowercase(), port), cookie);
    }
    fn key(scheme: Scheme, host: &str, port: u16) -> String {
        format!(
            "{}://{host}:{port}",
            if scheme == Scheme::Https {
                "https"
            } else {
                "http"
            }
        )
    }

    fn target(&self, scheme: Scheme, host: &str, port: u16) -> io::Result<Target> {
        let key = Self::key(scheme, host, port);
        let mut t = self.targets.lock().unwrap();
        if let Some(t) = t.get(&key) {
            return Ok(t.clone());
        }
        #[cfg(not(feature = "rustls"))]
        if scheme == Scheme::Https {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "https WebHDFS needs an rcp built with the rustls feature",
            ));
        }
        let target = Target {
            scheme,
            host: host.to_string(),
            port,
            proxy: proxy_from_env(scheme, host),
            #[cfg(feature = "rustls")]
            tls: self.tls.clone(),
        };
        t.insert(key, target.clone());
        Ok(target)
    }

    /// Whether this run may be sent to a host the NAMENODE named rather than the operator.
    ///
    /// WebHDFS is two steps by design: the namenode answers a data operation with a 307
    /// naming a datanode, and the client opens a second connection there. On a CREATE that
    /// second connection carries the file body, so the namenode chooses where this run's
    /// bytes go -- and its redirect can carry a delegation token in the query string, so it
    /// also chooses who sees that.
    ///
    /// The same shape as the OCI upload `Location`, and it needs the same check here: a
    /// policy that lives inside the registry adapter is consulted only by registries.
    /// `-allow` bounds the endpoints the operator named, and the namenode's own authority
    /// is one of them by construction.
    fn may_go_to(&self, scheme: Scheme, host: &str, port: u16) -> io::Result<()> {
        let name = if scheme == Scheme::Https {
            "https"
        } else {
            "http"
        };
        // Through the SAME comparison `Away` uses, not `==`. A namenode spelled `NN:9870`
        // by the operator and `nn:9870` in its own redirect missed `origin` as bytes, fell
        // through to the rail, and -- where the only root was `hdfs:///path`, which names
        // no authority at all -- was refused. A false denial of the host the endpoint
        // named, and two comparisons of the same thing disagreeing is how it happened.
        if crate::ports::Away::Only([self.origin.clone()].into())
            .check(name, host, port)
            .is_ok()
        {
            return Ok(());
        }
        self.away.check(name, host, port).map_err(|refused| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the namenode at {} redirected to {refused} to read and write there",
                    self.origin
                ),
            )
        })
    }

    fn take(&self, scheme: Scheme, host: &str, port: u16) -> io::Result<Connection> {
        // in `take` rather than at the two redirect sites: every connection this adapter
        // opens goes through here, including a pooled one, so the rail cannot be reached
        // around by a third data path added later
        self.may_go_to(scheme, host, port)?;
        let key = Self::key(scheme, host, port);
        if let Some(c) = self
            .idle
            .lock()
            .unwrap()
            .get_mut(&key)
            .and_then(|v| v.pop())
        {
            return Ok(c);
        }
        Connection::connect(&self.target(scheme, host, port)?)
    }

    fn give(&self, scheme: Scheme, host: &str, port: u16, c: Connection) {
        if c.idle() {
            self.idle
                .lock()
                .unwrap()
                .entry(Self::key(scheme, host, port))
                .or_default()
                .push(c);
        }
    }

    /// A buffered request to a URL, retried on transport failure.
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> io::Result<Response> {
        let (scheme, host, port, target) = split_url(url)?;
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            }
            let mut conn = match self.take(scheme, &host, port) {
                Ok(c) => c,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            let mut hs: Vec<(String, String)> = headers.to_vec();
            if let Some(c) = self.cookie_for(scheme, &host, port) {
                hs.push(("Cookie".into(), c));
            }
            match conn.request(method, &target, &hs, body) {
                Ok(r) if r.status == 401 && wants_negotiate(&r) => {
                    // a Kerberos-secured namenode: answer the challenge with a SPNEGO token
                    // for HTTP@host on the same connection, then keep the cookie it issues
                    let token = match spnego_token(&host) {
                        Ok(t) => t,
                        Err(e) => {
                            return Err(io::Error::new(
                                e.kind(),
                                format!("{host}: the namenode wants Kerberos (Negotiate) and {e}"),
                            ))
                        }
                    };
                    hs.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                    hs.push((
                        "Authorization".into(),
                        format!("Negotiate {}", crate::base64::encode(&token)),
                    ));
                    match conn.request(method, &target, &hs, body) {
                        Ok(r2) => {
                            if let Some(c) = auth_cookie(&r2) {
                                crate::debug!(
                                    self.log,
                                    "hdfs {host}: Kerberos negotiated, hadoop.auth cookie kept"
                                );
                                self.remember_cookie(scheme, &host, port, c);
                            }
                            if r2.status == 401 {
                                return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{host}: the namenode rejected the Kerberos negotiation (HTTP 401)")));
                            }
                            self.give(scheme, &host, port, conn);
                            return Ok(r2);
                        }
                        Err(e) => last = Some(e),
                    }
                }
                Ok(r) => {
                    if let Some(c) = auth_cookie(&r) {
                        self.remember_cookie(scheme, &host, port, c);
                    }
                    self.give(scheme, &host, port, conn);
                    return Ok(r);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no attempt made")))
    }
}

fn wants_negotiate(r: &Response) -> bool {
    r.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("www-authenticate")
            && v.trim().to_ascii_lowercase().starts_with("negotiate")
    })
}

/// One SPNEGO token toward `HTTP@host` from the ticket cache, as `curl --negotiate` and
/// the Hadoop clients send it.
fn spnego_token(host: &str) -> io::Result<Vec<u8>> {
    let mut ctx = crate::gss::Context::initiator(
        &format!("HTTP@{host}"),
        crate::gss::Mech::Spnego,
        crate::gss::GSS_C_MUTUAL_FLAG,
    )?;
    let step = ctx.init_step(None)?;
    Ok(step.token)
}

/// The `hadoop.auth` cookie of a reply, as `name=value` for a Cookie header.
fn auth_cookie(r: &Response) -> Option<String> {
    r.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
        .find(|c| c.starts_with("hadoop.auth="))
}

/// The error a namenode wraps in JSON, as an `io::Error` of the matching kind.
/// What a status means, as a table an automated caller can branch on. Named so the shared
/// arm in `ports` can compare it with the other adapters' -- see `status_tests`.
pub(crate) fn kind_of_status(status: u16) -> io::ErrorKind {
    match status {
        404 => io::ErrorKind::NotFound,
        401 | 403 => io::ErrorKind::PermissionDenied,
        400 => io::ErrorKind::InvalidInput,
        // A throttled or overloaded service is the one failure in this list worth
        // retrying, and without this arm it arrives as the same `io` as a missing bucket.
        // Every sibling adapter needs the same mapping, and fixing one does not fix the
        // others: the arm that measures it starts a REGISTRY stand-in, so reverting the OCI
        // map turns it red while S3 and HDFS stay green either way.
        429 | 502 | 503 | 504 => io::ErrorKind::ResourceBusy,
        _ => io::ErrorKind::Other,
    }
}

fn remote_error(r: &Response, what: &str) -> io::Error {
    let kind = kind_of_status(r.status);
    let detail = json::parse(&r.body).ok().and_then(|j| {
        let e = j.get("RemoteException")?;
        Some(format!(
            "{}: {}",
            e.get("exception")
                .and_then(Json::as_str)
                .unwrap_or("RemoteException"),
            e.get("message").and_then(Json::as_str).unwrap_or("")
        ))
    });
    let detail = detail.unwrap_or_else(|| format!("HTTP {}", r.status));
    let kind = if detail.starts_with("FileNotFoundException") {
        io::ErrorKind::NotFound
    } else if detail.starts_with("FileAlreadyExistsException") {
        io::ErrorKind::AlreadyExists
    } else if detail.starts_with("AccessControlException") {
        io::ErrorKind::PermissionDenied
    } else if detail.starts_with("UnsupportedOperationException") {
        io::ErrorKind::Unsupported
    } else if detail.contains("is non empty") {
        io::ErrorKind::DirectoryNotEmpty
    } else {
        kind
    };
    io::Error::new(kind, format!("{what}: {detail}"))
}

pub struct HdfsTree {
    pool: Arc<Pool>,
    /// `http://namenode:port/webhdfs/v1`
    base: String,
    /// The absolute path in HDFS of the root, without a trailing slash (`""` for `/`).
    root: String,
    user: String,
    display: PathBuf,
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// How every HDFS endpoint of a run is reached: the namenode for `hdfs:///path`, the
/// pseudo-authentication user, certificate checking, and where debug lines go.
#[derive(Clone)]
pub struct Settings {
    pub namenode: Option<String>,
    pub user: String,
    pub noverify: bool,
    /// Where a namenode's `Location` may send this run's bytes; set from the rails.
    pub away: crate::ports::Away,
    pub log: Arc<dyn crate::ports::Log>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("namenode", &self.namenode)
            .field("user", &self.user)
            .field("noverify", &self.noverify)
            .finish()
    }
}

impl Settings {
    /// The environment's defaults: `HDFS_NAMENODE`, `HADOOP_USER_NAME`, `RCP_HDFS_*`.
    pub fn from_env(log: Arc<dyn crate::ports::Log>) -> Settings {
        Settings {
            namenode: hdfs_namenode_env(),
            user: hdfs_user(),
            noverify: false,
            away: crate::ports::Away::Anywhere,
            log,
        }
    }
}

/// The namenode from the endpoint or the settings.
pub fn namenode(from_endpoint: &str, settings: &Settings) -> io::Result<String> {
    let text = if from_endpoint.is_empty() {
        settings.namenode.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hdfs:///path needs the namenode: -hdfs.namenode HOST:PORT, HDFS_NAMENODE or hdfs://host:port/path"))?
    } else {
        from_endpoint.to_string()
    };
    // `split_url` below STRIPS userinfo, because its other job is reading a `Location` a
    // datanode handed back -- where `user@host` is the server's spelling of a host and
    // dropping it is right. This value is the opposite: an operator typed it, into
    // `-hdfs.namenode`, `HDFS_NAMENODE` or `RCP_HDFS_NAMENODE`. Stripping it there means
    // the credential is discarded, the run goes out unauthenticated, and the operator
    // believes they authenticated -- the worst of the three outcomes, and the one
    // `s3::config::parse_endpoint` refuses by name for exactly this reason.
    //
    // The same string is already refused in the ENDPOINT spelling (`hdfs://user@nn/x`),
    // so accepting it here gave one intent two answers. Refused before any message can
    // quote it, and without repeating it.
    let authority = text
        .split("://")
        .last()
        .unwrap_or(&text)
        .split('/')
        .next()
        .unwrap_or("");
    if authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the namenode carries a user or password in its authority, which WebHDFS does not take there and this run would silently discard. Use -hdfs.user USER, or Kerberos with -hdfs.sec, and write the namenode as host:port",
        ));
    }
    let url = if text.contains("://") {
        text
    } else {
        format!("http://{text}")
    };
    let (scheme, host, port, _) = split_url(&url)?;
    Ok(format!(
        "{}://{host}:{port}",
        if scheme == Scheme::Https {
            "https"
        } else {
            "http"
        }
    ))
}

impl HdfsTree {
    /// Opens `path` on the namenode; the root must exist (or is created with `create`).
    pub fn connect(
        namenode_text: &str,
        path: &Path,
        create: bool,
        settings: &Settings,
    ) -> io::Result<HdfsTree> {
        let origin = namenode(namenode_text, settings)?;
        let user = settings.user.clone();
        let pool = Arc::new(Pool {
            log: settings.log.clone(),
            away: settings.away.clone(),
            origin: origin.clone(),
            targets: Mutex::new(BTreeMap::new()),
            idle: Mutex::new(BTreeMap::new()),
            cookies: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "rustls")]
            tls: if origin.starts_with("https://") {
                Some(crate::net::tls::config(
                    settings.noverify,
                    crate::net::tls::HDFS_NOVERIFY,
                )?)
            } else {
                None
            },
        });
        let root = path.to_string_lossy().trim_end_matches('/').to_string();
        let display = PathBuf::from(format!(
            "{}{}",
            origin
                .replacen("http://", "hdfs://", 1)
                .replacen("https://", "hdfs://", 1),
            if root.is_empty() { "/" } else { &root }
        ));
        let t = HdfsTree {
            pool,
            base: format!("{origin}/webhdfs/v1"),
            root,
            user,
            display,
        };
        match t.status("")? {
            Some(st) if st.kind == Kind::Dir => {}
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: not a directory", t.display.display()),
                ))
            }
            // Not refused here when it is not to be created: a dry run opens its destination
            // this way, and a destination that does not exist yet is an empty one to plan
            // against -- refused, `-dryrun` into a new directory on this transport would fail
            // at open while the same run into a local one plans it. A SOURCE that
            // is not there still fails: its listing answers `NotFound`, which ends the run.
            None => {
                if create && !t.op_bool("PUT", "", "MKDIRS", &[("permission", "755")])? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: MKDIRS was refused", t.display.display()),
                    ));
                }
            }
        }
        Ok(t)
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

    fn url(&self, rel: &str, op: &str, params: &[(&str, &str)]) -> String {
        let mut u = format!(
            "{}{}?op={op}&user.name={}",
            self.base,
            percent_encode(&self.abs(rel), true),
            percent_encode(&self.user, false)
        );
        for (k, v) in params {
            u.push('&');
            u.push_str(k);
            u.push('=');
            u.push_str(&percent_encode(v, false));
        }
        u
    }

    fn call(
        &self,
        method: &str,
        rel: &str,
        op: &str,
        params: &[(&str, &str)],
    ) -> io::Result<Response> {
        let r = self
            .pool
            .request(method, &self.url(rel, op, params), &[], &[])?;
        crate::debug!(self.pool.log, "hdfs {method} {op} {rel}: {}", r.status);
        if r.ok() {
            Ok(r)
        } else {
            Err(remote_error(&r, rel))
        }
    }

    fn op_bool(
        &self,
        method: &str,
        rel: &str,
        op: &str,
        params: &[(&str, &str)],
    ) -> io::Result<bool> {
        let r = self.call(method, rel, op, params)?;
        json::parse(&r.body)
            .ok()
            .and_then(|j| j.get("boolean").and_then(Json::as_bool))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{rel}: {op} response has no boolean"),
                )
            })
    }

    fn item_of(&self, rel: String, st: &Json) -> Option<Item> {
        let kind = match st.get("type").and_then(Json::as_str)? {
            "FILE" => Kind::File,
            "DIRECTORY" => Kind::Dir,
            "SYMLINK" => Kind::Symlink,
            _ => return None,
        };
        let ms = |k: &str| st.get(k).and_then(Json::as_i64).unwrap_or(0) as i128 * 1_000_000;
        let mode = st
            .get("permission")
            .and_then(Json::as_str)
            .and_then(|p| u32::from_str_radix(p, 8).ok())
            .unwrap_or(0o644);
        let owner = st.get("owner").and_then(Json::as_str).unwrap_or("");
        let group = st.get("group").and_then(Json::as_str).unwrap_or("");
        let size = if kind == Kind::File {
            st.get("length").and_then(Json::as_u64).unwrap_or(0)
        } else {
            0
        };
        Some(Item {
            ino: st
                .get("fileId")
                .and_then(Json::as_u64)
                .unwrap_or_else(|| fnv64(&self.abs(&rel))),
            rel,
            kind,
            size,
            mtime_ns: ms("modificationTime"),
            atime_ns: ms("accessTime"),
            mode: mode & 0o7777,
            uid: names::uid_of(owner).unwrap_or(0),
            gid: names::gid_of(group).unwrap_or(0),
            dev: 0,
            nlink: 1,
            blocks: size,
            link_target: st.get("symlink").and_then(Json::as_str).map(PathBuf::from),
        })
    }

    /// GETFILESTATUS, `None` when nothing is there.
    fn status(&self, rel: &str) -> io::Result<Option<Item>> {
        let r = self
            .pool
            .request("GET", &self.url(rel, "GETFILESTATUS", &[]), &[], &[])?;
        if r.status == 404 {
            return Ok(None);
        }
        if !r.ok() {
            let e = remote_error(&r, rel);
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let j = json::parse(&r.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{rel}: {e}")))?;
        let st = j.get("FileStatus").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{rel}: no FileStatus"))
        })?;
        Ok(self.item_of(rel.to_string(), st))
    }

    /// LISTSTATUS of one directory: its entries as items with full relative paths.
    fn list_dir(&self, rel: &str) -> io::Result<Vec<Item>> {
        let r = self.call("GET", rel, "LISTSTATUS", &[])?;
        let j = json::parse(&r.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{rel}: {e}")))?;
        let list = j
            .get("FileStatuses")
            .and_then(|f| f.get("FileStatus"))
            .and_then(Json::as_array)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{rel}: no FileStatuses"),
                )
            })?;
        let mut out = Vec::new();
        for st in list {
            let name = st.get("pathSuffix").and_then(Json::as_str).unwrap_or("");
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                continue;
            }
            let child = if rel == "." {
                name.to_string()
            } else {
                format!("{rel}/{name}")
            };
            if let Some(i) = self.item_of(child, st) {
                out.push(i);
            }
        }
        Ok(out)
    }
}

fn now_ns() -> i128 {
    filter::now_ns()
}

impl Tree for HdfsTree {
    type Reader = HdfsReader;
    type Sink = HdfsSink;

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
        // a root that is not there is `NotFound` -- giving it a made-up directory item that
        // then fails to list reads as an unreadable destination
        let Some(root) = self.status(".")? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no such path", self.display.display()),
            ));
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
        self.status(rel)
    }

    fn open(&self, rel: &str) -> io::Result<HdfsReader> {
        let size = self
            .status(rel)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{rel}: no such file")))?
            .size;
        Ok(HdfsReader {
            tree: HdfsHandle {
                pool: self.pool.clone(),
                base: self.base.clone(),
                root: self.root.clone(),
                user: self.user.clone(),
            },
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

    fn create_file(&self, item: &Item) -> io::Result<HdfsSink> {
        let perm = format!("{:o}", item.mode & 0o777);
        Ok(HdfsSink {
            tree: HdfsHandle {
                pool: self.pool.clone(),
                base: self.base.clone(),
                root: self.root.clone(),
                user: self.user.clone(),
            },
            rel: item.rel.clone(),
            permission: perm,
            expected: None,
            pos: 0,
            state: SinkState::Idle,
            finished: false,
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut HdfsSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        if rel == "." {
            return Ok(());
        }
        if !self.op_bool("PUT", rel, "MKDIRS", &[("permission", "755")])? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{rel}: MKDIRS was refused"),
            ));
        }
        Ok(())
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        if let Some(existing) = self.status(rel)? {
            if existing.kind == Kind::Symlink && existing.link_target.as_deref() == Some(target) {
                return Ok(());
            }
            self.remove(rel, existing.kind)?.cleared(rel)?;
        }
        self.call(
            "PUT",
            rel,
            "CREATESYMLINK",
            &[
                ("destination", &target.to_string_lossy()),
                ("createParent", "false"),
            ],
        )
        .map(|_| ())
    }

    fn hard_link(&self, _existing: &str, _rel: &str) -> io::Result<()> {
        // HDFS HAS NO HARD LINKS, AND SAYING SO IS THE WHOLE JOB. It is tempting to emulate
        // one: READ the first file back through this process, WRITE it again under the
        // second name, and return `Ok(())` -- but then the run counts a link it has not
        // made. Measured on a 4 MiB file with one link: `copy` reported `1 files (4194304
        // bytes), 1 linked` while the namenode saw 8 MiB created and 4 MiB read, three
        // times the traffic the summary claimed and twice the storage (before replication).
        // `verify` then reported `DIFF hardlink` forever, because two objects cannot share
        // an inode; rerunning paid the whole cost again and converged no closer. And
        // `rcp describe` said `hard_links: false` for this very scheme in the same breath.
        //
        // `Unsupported` is the answer `copy_tree` already knows what to do with: it falls
        // back to a plain copy, which moves 8 MiB instead of 12, REPORTS 8 MiB, and leaves
        // a tree `verify` accepts. Cheaper and true, which is not the usual trade.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HDFS has no hard links",
        ))
    }

    // WebHDFS has no extended attributes this adapter reads, so an empty list is "cannot say"
    fn keeps_xattrs(&self) -> bool {
        false
    }

    fn remove(&self, rel: &str, _kind: Kind) -> io::Result<Removed> {
        if rel == "." && self.root.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the filesystem root itself is not removed; remove its contents",
            ));
        }
        // The request is made here rather than through `op_bool` because the STATUS is the
        // thing that decides, and `op_bool` -> `call` turns it into an `io::Error` whose
        // kind calls 401 and 403 the same. See `net::http::delete_refused`.
        let r = self.pool.request(
            "DELETE",
            &self.url(rel, "DELETE", &[("recursive", "false")]),
            &[],
            &[],
        )?;
        crate::debug!(self.pool.log, "hdfs DELETE DELETE {rel}: {}", r.status);
        if r.ok() {
            // WebHDFS answers `{"boolean":false}` when it did not delete. That is the
            // namenode saying the entry stays -- a refusal inside a successful response,
            // which is where this whole distinction started.
            let deleted = json::parse(&r.body)
                .ok()
                .and_then(|j| j.get("boolean").and_then(Json::as_bool))
                .unwrap_or(true);
            return Ok(if deleted {
                Removed::Gone
            } else {
                Removed::Kept("the namenode did not delete it".into())
            });
        }
        let e = remote_error(&r, rel);
        // THE STATUS DECIDES, AND IT HAS TO BE ASKED FIRST. `remote_error` takes the kind
        // from the exception name in the JSON body, which is the namenode's word about the
        // PATH -- not about whether this run was allowed to ask. So a 401 whose body
        // carries a `FileNotFoundException` came through here as `NotFound`, and the
        // short-circuit below turned it into `Removed::Gone`: a credential failure recorded
        // in the catalog as a completed removal, which a later `sync` then believes.
        //
        // 404 and 410 are the only statuses that mean the entry is not there. Everything
        // else goes to `delete_refused`, which sorts by status: 401/407 are errors no rerun
        // fixes, 403/423 are the store refusing and the entry is `Kept`.
        if matches!(r.status, 404 | 410) {
            return Ok(Removed::Gone);
        }
        crate::net::http::delete_refused(r.status, rel, e)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        // RENAME refuses to replace an existing destination: clear it first
        if let Some(existing) = self.status(to)? {
            self.remove(to, existing.kind)?.cleared(to)?;
        }
        let dest = self.abs(to);
        match self.op_bool("PUT", from, "RENAME", &[("destination", &dest)]) {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other(format!(
                "{from} -> {to}: the namenode refused the rename"
            ))),
            Err(e) => Err(e),
        }
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let mut refusals = Refusals::default();
        if opts.owner {
            let owner = names::user(item.uid);
            let group = names::group(item.gid);
            match self.call(
                "PUT",
                rel,
                "SETOWNER",
                &[("owner", &owner), ("group", &group)],
            ) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                Err(e) => return Err(e),
            }
        }
        if item.kind != Kind::Symlink {
            if opts.mode {
                self.call(
                    "PUT",
                    rel,
                    "SETPERMISSION",
                    &[("permission", &format!("{:o}", item.mode & 0o777))],
                )?;
            }
            if opts.times {
                let m = (item.mtime_ns / 1_000_000).to_string();
                let a = ((if opts.atime {
                    item.atime_ns
                } else {
                    item.mtime_ns
                }) / 1_000_000)
                    .to_string();
                self.call(
                    "PUT",
                    rel,
                    "SETTIMES",
                    &[("modificationtime", &m), ("accesstime", &a)],
                )?;
            }
        }
        Ok(refusals)
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|(n, _)| n.clone()).collect())
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        self.call(
            "PUT",
            &item.rel,
            "SETTIMES",
            &[("accesstime", &(item.atime_ns / 1_000_000).to_string())],
        )
        .map(|_| ())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
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

/// What a reader or sink needs from the tree, without borrowing it.
#[derive(Clone)]
struct HdfsHandle {
    pool: Arc<Pool>,
    base: String,
    root: String,
    user: String,
}

impl HdfsHandle {
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
    fn url(&self, rel: &str, op: &str, params: &[(&str, &str)]) -> String {
        let mut u = format!(
            "{}{}?op={op}&user.name={}",
            self.base,
            percent_encode(&self.abs(rel), true),
            percent_encode(&self.user, false)
        );
        for (k, v) in params {
            u.push('&');
            u.push_str(k);
            u.push('=');
            u.push_str(&percent_encode(v, false));
        }
        u
    }
    /// The datanode URL a data operation redirects to.
    fn redirect(
        &self,
        method: &str,
        rel: &str,
        op: &str,
        params: &[(&str, &str)],
    ) -> io::Result<String> {
        // through the pool's request path, so a Kerberos-secured namenode is negotiated
        // with and its cookie carried, the same as for every other namenode call
        let r = self
            .pool
            .request(method, &self.url(rel, op, params), &[], &[])?;
        match r.status {
            307 | 302 | 303 => r.header("location").map(str::to_string).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{rel}: redirect without a Location"),
                )
            }),
            _ => Err(remote_error(&r, rel)),
        }
    }
}

/// A streaming OPEN, reissued with an offset after a seek.
pub struct HdfsReader {
    tree: HdfsHandle,
    rel: String,
    size: u64,
    pos: u64,
    conn: Option<(Scheme, String, u16, Connection)>,
}

impl HdfsReader {
    fn start(&mut self) -> io::Result<()> {
        let off = self.pos.to_string();
        let url = self
            .tree
            .redirect("GET", &self.rel, "OPEN", &[("offset", &off)])?;
        let (scheme, host, port, target) = split_url(&url)?;
        let mut conn = self.tree.pool.take(scheme, &host, port)?;
        conn.send_head("GET", &target, &[], 0)?;
        let r = conn.read_head(false)?;
        if !r.ok() {
            let mut r = r;
            r.body = conn.drain().unwrap_or_default();
            return Err(remote_error(&r, &self.rel));
        }
        self.conn = Some((scheme, host, port, conn));
        Ok(())
    }
}

impl Read for HdfsReader {
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

impl Seek for HdfsReader {
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

/// A two-step CREATE: the namenode's redirect, then one streaming PUT to the datanode.
pub struct HdfsSink {
    tree: HdfsHandle,
    rel: String,
    permission: String,
    expected: Option<u64>,
    pos: u64,
    state: SinkState,
    finished: bool,
}

impl HdfsSink {
    fn start(&mut self, len: u64) -> io::Result<()> {
        let url = self.tree.redirect(
            "PUT",
            &self.rel,
            "CREATE",
            &[("overwrite", "true"), ("permission", &self.permission)],
        )?;
        let (scheme, host, port, target) = split_url(&url)?;
        let mut conn = self.tree.pool.take(scheme, &host, port)?;
        conn.send_head(
            "PUT",
            &target,
            &[(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            len,
        )?;
        self.state = SinkState::Streaming(scheme, host, port, conn);
        Ok(())
    }
}

impl Sink for HdfsSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        self.expected = Some(len);
        self.start(len)
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.state {
            SinkState::Idle => {
                self.state = SinkState::Buffering(data.to_vec());
            }
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
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        if let Some(expected) = self.expected {
            if self.pos != expected {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: {} bytes arrived for {expected} declared (the source changed during the copy)", self.rel, self.pos)));
            }
        }
        let state = std::mem::replace(&mut self.state, SinkState::Idle);
        match state {
            SinkState::Idle => {
                self.start(0)?;
                let SinkState::Streaming(scheme, host, port, mut conn) =
                    std::mem::replace(&mut self.state, SinkState::Idle)
                else {
                    unreachable!()
                };
                let mut r = conn.read_head(false)?;
                r.body = conn.drain()?;
                self.tree.pool.give(scheme, &host, port, conn);
                if !r.ok() {
                    return Err(remote_error(&r, &self.rel));
                }
            }
            SinkState::Buffering(buf) => {
                self.start(buf.len() as u64)?;
                let SinkState::Streaming(scheme, host, port, mut conn) =
                    std::mem::replace(&mut self.state, SinkState::Idle)
                else {
                    unreachable!()
                };
                conn.write_body(&buf)?;
                let mut r = conn.read_head(false)?;
                r.body = conn.drain()?;
                self.tree.pool.give(scheme, &host, port, conn);
                if !r.ok() {
                    return Err(remote_error(&r, &self.rel));
                }
            }
            SinkState::Streaming(scheme, host, port, mut conn) => {
                let mut r = conn.read_head(false)?;
                r.body = conn.drain()?;
                self.tree.pool.give(scheme, &host, port, conn);
                if !r.ok() {
                    return Err(remote_error(&r, &self.rel));
                }
            }
        }
        self.finished = true;
        // metadata after the bytes: the namenode sets what CREATE could not
        let tree = HdfsTree {
            pool: self.tree.pool.clone(),
            base: self.tree.base.clone(),
            root: self.tree.root.clone(),
            user: self.tree.user.clone(),
            display: PathBuf::new(),
        };
        let mut refusals = tree.set_metadata(
            &self.rel,
            item,
            MetaOptions {
                mode: false,
                ..opts
            },
        )?;
        refusals.xattrs = xattrs.iter().map(|(n, _)| n.clone()).collect();
        Ok(refusals)
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_cookies_stay_on_the_issuing_origin() {
        use std::io::{BufRead, Write};
        for case in ["same", "port", "host", "downgrade"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let peer = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = io::BufReader::new(stream.try_clone().unwrap());
                let mut received = Vec::new();
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    received.push(line);
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
                received
            });
            let key = Pool::key(Scheme::Http, "127.0.0.1", port);
            let pool = Pool {
                log: Arc::new(crate::ports::Silent),
                away: crate::ports::Away::Anywhere,
                origin: key.clone(),
                targets: Mutex::new(
                    [(
                        key,
                        Target {
                            scheme: Scheme::Http,
                            host: "127.0.0.1".into(),
                            port,
                            proxy: None,
                            #[cfg(feature = "rustls")]
                            tls: None,
                        },
                    )]
                    .into(),
                ),
                idle: Mutex::new(BTreeMap::new()),
                cookies: Mutex::new(BTreeMap::new()),
                #[cfg(feature = "rustls")]
                tls: None,
            };
            let scheme = if case == "downgrade" {
                Scheme::Https
            } else {
                Scheme::Http
            };
            let host = if case == "host" {
                "other.example"
            } else {
                "127.0.0.1"
            };
            let issuer_port = if case == "port" {
                port.wrapping_add(1)
            } else {
                port
            };
            pool.remember_cookie(scheme, host, issuer_port, "hadoop.auth=test-ticket".into());
            assert_eq!(
                pool.cookie_for(scheme, host, issuer_port).as_deref(),
                Some("hadoop.auth=test-ticket")
            );
            let response = pool.request("GET", &format!("http://127.0.0.1:{port}/data"), &[], &[]);
            let received = peer.join().unwrap();
            assert_eq!(response.unwrap().status, 200);
            let cookie = received
                .iter()
                .any(|line| line.starts_with("Cookie: hadoop.auth=test-ticket"));
            assert_eq!(
                cookie,
                case == "same",
                "cookie confidentiality failed for {case}"
            );
        }
    }

    #[test]
    fn urls_split_and_paths_encode() {
        assert_eq!(
            split_url("http://nn:9870/webhdfs/v1/a?op=X").unwrap(),
            (Scheme::Http, "nn".into(), 9870, "/webhdfs/v1/a?op=X".into())
        );
        assert_eq!(split_url("https://nn/").unwrap().2, 443);
        assert!(split_url("ftp://x").is_err());
        let h = HdfsHandle {
            pool: Arc::new(Pool {
                log: Arc::new(crate::ports::Silent),
                away: crate::ports::Away::Anywhere,
                origin: "http://nn:9870".into(),
                targets: Mutex::new(BTreeMap::new()),
                idle: Mutex::new(BTreeMap::new()),
                cookies: Mutex::new(BTreeMap::new()),
                #[cfg(feature = "rustls")]
                tls: None,
            }),
            base: "http://nn:9870/webhdfs/v1".into(),
            root: "/data/in".into(),
            user: "jon".into(),
        };
        assert_eq!(
            h.url("dir/a b", "OPEN", &[("offset", "5")]),
            "http://nn:9870/webhdfs/v1/data/in/dir/a%20b?op=OPEN&user.name=jon&offset=5"
        );
        assert_eq!(h.abs("."), "/data/in");
        let root = HdfsHandle {
            root: String::new(),
            ..h
        };
        assert_eq!(root.abs("."), "/");
        assert_eq!(root.abs("x"), "/x");
    }

    /// The authority of a namenode redirect is what follows the last `@`, because it feeds
    /// the same `Away` check as every other adapter and a disagreement is a rail that means
    /// two things. WebHDFS once took `user@host` whole as the host. These are the forms that
    /// broke, plus the ones the fix could plausibly break instead.
    #[test]
    fn the_authority_is_what_follows_the_last_at_and_the_brackets_are_not_the_port() {
        let ok = |u: &str| -> (String, u16, String) {
            let (_, h, p, path) = split_url(u).unwrap_or_else(|e| panic!("{u}: {e}"));
            (h, p, path)
        };
        assert_eq!(ok("http://host/p"), ("host".into(), 80, "/p".into()));
        assert_eq!(ok("https://host/p"), ("host".into(), 443, "/p".into()));
        assert_eq!(ok("http://host:9864/p"), ("host".into(), 9864, "/p".into()));
        // userinfo, which is where this started
        assert_eq!(
            ok("http://hdfs@host:9864/p"),
            ("host".into(), 9864, "/p".into())
        );
        assert_eq!(ok("http://@host/p"), ("host".into(), 80, "/p".into()));
        // the LAST `@` wins: a userinfo that itself contains one must not shorten the host
        assert_eq!(ok("http://a@b@host:1/p"), ("host".into(), 1, "/p".into()));
        // and a userinfo spelled as an authority must not BE the authority -- the control
        // for the strip, in the form a spoofer would write it
        assert_eq!(
            ok("http://allowed:80@real:9864/p"),
            ("real".into(), 9864, "/p".into())
        );
        // an `@` after the authority belongs to the path and is not userinfo at all
        assert_eq!(ok("http://host/p@q"), ("host".into(), 80, "/p@q".into()));
        // bracketed IPv6, with and without a port; the colons inside are not the port
        assert_eq!(ok("http://[::1]/p"), ("[::1]".into(), 80, "/p".into()));
        assert_eq!(
            ok("http://[::1]:9864/p"),
            ("[::1]".into(), 9864, "/p".into())
        );
        assert_eq!(
            ok("https://[2001:db8::1]/p"),
            ("[2001:db8::1]".into(), 443, "/p".into())
        );
        assert_eq!(
            ok("http://user@[::1]:9864/p"),
            ("[::1]".into(), 9864, "/p".into())
        );
        // and the malformed ones are refused rather than guessed at
        for bad in [
            "http://[::1/p",
            "http://[::1]x/p",
            "http://host@/p",
            "http://[]:80/p",
            "ftp://host/p",
            "http://::1/p",
            "http://::1:9864/p",
        ] {
            assert!(split_url(bad).is_err(), "{bad} was accepted");
        }
    }
}
