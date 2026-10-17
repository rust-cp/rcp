//! A stand-in WebHDFS service backed by a local directory: the namenode operations the
//! client uses, and a datanode on the same port that the namenode redirects to, the way a
//! real cluster does (with `&datanode=1` marking the second hop). Symlinks are refused with
//! the `UnsupportedOperationException` a Hadoop namenode returns, since HDFS symlinks are
//! disabled in every current release; ownership is by name and the caller's `user.name`
//! is trusted, which is exactly pseudo authentication.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::gss;
use crate::json;
use crate::names;

pub struct Server {
    pub port: u16,
}

/// The Kerberos side of a secured stand-in: the keytab credential, the `hadoop.auth`
/// cookies issued after a SPNEGO negotiation, and the delegation tokens put into datanode
/// redirects, which is how a real secured cluster lets the datanode hop skip Kerberos.
struct Krb {
    cred: gss::AcceptorCred,
    cookies: Mutex<HashSet<String>>,
    delegations: Mutex<HashSet<String>>,
    counter: AtomicU64,
}

impl Krb {
    fn delegation(&self) -> String {
        let t = format!("dt-{}", self.counter.fetch_add(1, Ordering::Relaxed));
        self.delegations.lock().unwrap().insert(t.clone());
        t
    }
}

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
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
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<Request>> {
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
                    percent_decode(p),
                    q.split('&')
                        .filter(|s| !s.is_empty())
                        .map(|kv| match kv.split_once('=') {
                            Some((k, v)) => (percent_decode(k), percent_decode(v)),
                            None => (percent_decode(kv), String::new()),
                        })
                        .collect(),
                ),
                None => (percent_decode(&target), Vec::new()),
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

fn json_reply(status: u16, body: String) -> Reply {
    Reply {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.into_bytes(),
    }
}

fn exception(status: u16, class: &str, message: &str) -> Reply {
    json_reply(
        status,
        format!(
            "{{\"RemoteException\":{{\"exception\":{},\"javaClassName\":{},\"message\":{}}}}}",
            json::quote(class),
            json::quote(&format!("org.apache.hadoop.{class}")),
            json::quote(message)
        ),
    )
}

fn io_exception(e: &io::Error, path: &str) -> Reply {
    match e.kind() {
        io::ErrorKind::NotFound => exception(
            404,
            "FileNotFoundException",
            &format!("File does not exist: {path}"),
        ),
        io::ErrorKind::PermissionDenied => exception(
            403,
            "AccessControlException",
            &format!("Permission denied: {path}"),
        ),
        io::ErrorKind::AlreadyExists => exception(
            403,
            "FileAlreadyExistsException",
            &format!("{path} already exists"),
        ),
        io::ErrorKind::DirectoryNotEmpty => exception(
            403,
            "PathIsNotEmptyDirectoryException",
            &format!("`{path} is non empty': Directory is not empty"),
        ),
        _ => exception(500, "IOException", &e.to_string()),
    }
}

fn status_json(path: &Path, name: &str) -> io::Result<String> {
    let m = fs::symlink_metadata(path)?;
    let kind = if m.file_type().is_symlink() {
        "SYMLINK"
    } else if m.is_dir() {
        "DIRECTORY"
    } else {
        "FILE"
    };
    let symlink = if kind == "SYMLINK" {
        format!(
            ",\"symlink\":{}",
            json::quote(&fs::read_link(path)?.to_string_lossy())
        )
    } else {
        String::new()
    };
    Ok(format!(
        "{{\"accessTime\":{},\"blockSize\":134217728,\"childrenNum\":0,\"fileId\":{},\"group\":{},\"length\":{},\"modificationTime\":{},\"owner\":{},\"pathSuffix\":{},\"permission\":\"{:o}\",\"replication\":3,\"type\":\"{kind}\"{symlink}}}",
        m.atime() * 1000 + m.atime_nsec() / 1_000_000,
        m.ino(),
        json::quote(&names::group(m.gid())),
        if kind == "FILE" { m.len() } else { 0 },
        m.mtime() * 1000 + m.mtime_nsec() / 1_000_000,
        json::quote(&names::user(m.uid())),
        json::quote(name),
        m.permissions().mode() & 0o777
    ))
}

fn write_reply(stream: &mut TcpStream, r: &Reply) -> io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        201 => "Created",
        307 => "Temporary Redirect",
        401 => "Unauthorized",
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
    stream.write_all(&r.body)?;
    stream.flush()
}

impl Server {
    /// Serves `root` as the HDFS root (`/` maps to it) on a free loopback port.
    pub fn start(root: &Path) -> io::Result<Server> {
        Server::start_with(root, None, None, "")
    }

    /// A namenode whose data-operation redirects name a DIFFERENT host, which is what a
    /// hostile or compromised namenode does with the two-step WebHDFS protocol: the
    /// second connection is where a CREATE sends the file body. `away` is dialed only if
    /// this run follows the redirect, so a listener there is the observation.
    pub fn start_redirecting_to(root: &Path, away: u16) -> io::Result<Server> {
        Server::start_with(root, None, Some(away), "")
    }

    /// A namenode whose redirects carry `userinfo@` in the authority. That is a legal URL
    /// and a real one -- a proxying or federated namenode can emit it -- and it is also
    /// the browser-familiar spoofing shape, where the part before the `@` is the host a
    /// reader's eye stops at. Both readings need the same answer: the authority is what
    /// follows the `@`, and nothing before it.
    pub fn start_redirecting_as(
        root: &Path,
        away: Option<u16>,
        userinfo: &'static str,
    ) -> io::Result<Server> {
        Server::start_with(root, None, away, userinfo)
    }

    /// A namenode that requires Kerberos: SPNEGO against the keytab's `HTTP/127.0.0.1`,
    /// then a `hadoop.auth` cookie, and delegation tokens on the datanode redirects.
    pub fn start_kerberized(root: &Path) -> io::Result<Server> {
        let krb = Krb {
            cred: gss::AcceptorCred::acquire()?,
            cookies: Mutex::new(HashSet::new()),
            delegations: Mutex::new(HashSet::new()),
            counter: AtomicU64::new(1),
        };
        Server::start_with(root, Some(Arc::new(krb)), None, "")
    }

    fn start_with(
        root: &Path,
        krb: Option<Arc<Krb>>,
        datanode: Option<u16>,
        userinfo: &'static str,
    ) -> io::Result<Server> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        // the port the redirects NAME, which is this one unless a caller asked for a
        // namenode that hands the data hop somewhere else
        let datanode = datanode.unwrap_or(port);
        let root = Arc::new(fs::canonicalize(root)?);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let root = root.clone();
                let krb = krb.clone();
                std::thread::spawn(move || serve(stream, root, datanode, userinfo, krb));
            }
        });
        Ok(Server { port })
    }

    pub fn endpoint(&self) -> String {
        format!("hdfs://127.0.0.1:{}", self.port)
    }
}

fn serve(
    mut stream: TcpStream,
    root: Arc<PathBuf>,
    port: u16,
    userinfo: &'static str,
    krb: Option<Arc<Krb>>,
) {
    stream.set_nodelay(true).ok();
    let mut buf = Vec::new();
    while let Ok(Some(req)) = read_request(&mut stream, &mut buf) {
        let r = handle(&req, &root, port, userinfo, krb.as_deref());
        if write_reply(&mut stream, &r).is_err() {
            return;
        }
    }
}

fn negotiate_challenge() -> Reply {
    let mut r = exception(401, "AuthenticationException", "Authentication required");
    r.headers
        .push(("WWW-Authenticate".into(), "Negotiate".into()));
    r
}

/// Authentication first (pseudo, or Kerberos when the stand-in is secured), then the
/// operation; headers the negotiation produced ride on whatever the operation answers.
fn handle(req: &Request, root: &Path, port: u16, userinfo: &str, krb: Option<&Krb>) -> Reply {
    let datanode = req.query("datanode").is_some();
    let mut extra: Vec<(String, String)> = Vec::new();
    match krb {
        Some(k) if datanode => {
            if !req
                .query("delegation")
                .is_some_and(|d| k.delegations.lock().unwrap().contains(d))
            {
                return exception(
                    401,
                    "AuthenticationException",
                    "delegation token required on the datanode",
                );
            }
        }
        Some(k) => {
            let cookie_ok = req.header("cookie").is_some_and(|c| {
                c.split(';').any(|p| {
                    p.trim()
                        .strip_prefix("hadoop.auth=")
                        .is_some_and(|v| k.cookies.lock().unwrap().contains(v))
                })
            });
            if !cookie_ok {
                let token = req
                    .header("authorization")
                    .and_then(|a| a.strip_prefix("Negotiate "))
                    .and_then(|b| crate::base64::decode(b.trim()));
                let Some(token) = token else {
                    return negotiate_challenge();
                };
                let mut ctx = match gss::Context::acceptor() {
                    Ok(c) => c,
                    Err(_) => return negotiate_challenge(),
                };
                match ctx.accept_step(&k.cred, &token) {
                    Ok(step) if step.complete => {
                        let peer = ctx.peer.clone().unwrap_or_default();
                        let value = format!(
                            "u={}&p={peer}&t=kerberos&e=0&s={}",
                            peer.split('@').next().unwrap_or(""),
                            k.counter.fetch_add(1, Ordering::Relaxed)
                        );
                        k.cookies.lock().unwrap().insert(value.clone());
                        extra.push((
                            "Set-Cookie".into(),
                            format!("hadoop.auth={value}; Path=/; HttpOnly"),
                        ));
                        if !step.token.is_empty() {
                            extra.push((
                                "WWW-Authenticate".into(),
                                format!("Negotiate {}", crate::base64::encode(&step.token)),
                            ));
                        }
                    }
                    _ => return negotiate_challenge(),
                }
            }
        }
        None => {
            if req.query("user.name").is_none() {
                return exception(401, "AuthenticationException", "user.name required");
            }
        }
    }
    let mut r = dispatch(req, root, port, userinfo, krb);
    r.headers.extend(extra);
    r
}

fn dispatch(req: &Request, root: &Path, port: u16, userinfo: &str, krb: Option<&Krb>) -> Reply {
    let Some(hdfs_path) = req.path.strip_prefix("/webhdfs/v1") else {
        return exception(404, "IOException", "not a WebHDFS path");
    };
    let hdfs_path = if hdfs_path.is_empty() { "/" } else { hdfs_path };
    if hdfs_path.split('/').any(|c| c == "..") {
        return exception(400, "IllegalArgumentException", "..");
    }
    let local = root.join(hdfs_path.trim_start_matches('/'));
    let Some(op) = req.query("op").map(str::to_uppercase) else {
        return exception(400, "IllegalArgumentException", "no op");
    };
    // a secured namenode puts a delegation token on every redirect to a datanode
    let delegation = krb
        .map(|k| format!("&delegation={}", k.delegation()))
        .unwrap_or_default();
    let datanode = req.query("datanode").is_some();
    match (req.method.as_str(), op.as_str()) {
        ("GET", "GETFILESTATUS") => match status_json(&local, "") {
            Ok(s) => json_reply(200, format!("{{\"FileStatus\":{s}}}")),
            Err(e) => io_exception(&e, hdfs_path),
        },
        ("GET", "LISTSTATUS") => {
            let entries = match fs::read_dir(&local) {
                Ok(d) => d,
                Err(e) => return io_exception(&e, hdfs_path),
            };
            let mut items = Vec::new();
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Ok(s) = status_json(&e.path(), &n) {
                    items.push(s);
                }
            }
            items.sort();
            json_reply(
                200,
                format!(
                    "{{\"FileStatuses\":{{\"FileStatus\":[{}]}}}}",
                    items.join(",")
                ),
            )
        }
        ("GET", "OPEN") if !datanode => {
            if !local.is_file() {
                return exception(
                    404,
                    "FileNotFoundException",
                    &format!("File does not exist: {hdfs_path}"),
                );
            }
            let offset = req.query("offset").unwrap_or("0");
            Reply { status: 307, headers: vec![("Location".into(), format!("http://{userinfo}127.0.0.1:{port}/webhdfs/v1{hdfs_path}?op=OPEN&user.name={}&datanode=1&offset={offset}{delegation}", req.query("user.name").unwrap_or("")))], body: Vec::new() }
        }
        ("GET", "OPEN") => {
            let offset: u64 = req
                .query("offset")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            match fs::read(&local) {
                Ok(data) => {
                    let start = (offset as usize).min(data.len());
                    let end = req
                        .query("length")
                        .and_then(|v| v.parse::<usize>().ok())
                        .map_or(data.len(), |l| (start + l).min(data.len()));
                    Reply {
                        status: 200,
                        headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                        body: data[start..end].to_vec(),
                    }
                }
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "CREATE") if !datanode => {
            if local.is_dir() {
                return exception(
                    403,
                    "FileAlreadyExistsException",
                    &format!("{hdfs_path} is a directory"),
                );
            }
            if !local.parent().is_some_and(|p| p.is_dir()) {
                return exception(
                    404,
                    "FileNotFoundException",
                    &format!("Parent directory doesn't exist: {hdfs_path}"),
                );
            }
            let perm = req.query("permission").unwrap_or("644");
            Reply { status: 307, headers: vec![("Location".into(), format!("http://{userinfo}127.0.0.1:{port}/webhdfs/v1{hdfs_path}?op=CREATE&user.name={}&datanode=1&permission={perm}&overwrite={}{delegation}", req.query("user.name").unwrap_or(""), req.query("overwrite").unwrap_or("false")))], body: Vec::new() }
        }
        ("PUT", "CREATE") => {
            if local.exists() && req.query("overwrite") != Some("true") {
                return exception(
                    403,
                    "FileAlreadyExistsException",
                    &format!("{hdfs_path} already exists"),
                );
            }
            let perm = req
                .query("permission")
                .and_then(|p| u32::from_str_radix(p, 8).ok())
                .unwrap_or(0o644);
            match fs::write(&local, &req.body)
                .and_then(|_| fs::set_permissions(&local, fs::Permissions::from_mode(perm)))
            {
                Ok(()) => Reply {
                    status: 201,
                    headers: vec![(
                        "Location".into(),
                        format!("webhdfs://127.0.0.1:{port}{hdfs_path}"),
                    )],
                    body: Vec::new(),
                },
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "MKDIRS") => {
            let perm = req
                .query("permission")
                .and_then(|p| u32::from_str_radix(p, 8).ok())
                .unwrap_or(0o755);
            match fs::create_dir_all(&local)
                .and_then(|_| fs::set_permissions(&local, fs::Permissions::from_mode(perm)))
            {
                Ok(()) => json_reply(200, "{\"boolean\":true}".into()),
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("DELETE", "DELETE") => {
            let recursive = req.query("recursive") == Some("true");
            let r = match fs::symlink_metadata(&local) {
                Ok(m) if m.is_dir() && recursive => fs::remove_dir_all(&local),
                Ok(m) if m.is_dir() => fs::remove_dir(&local),
                Ok(_) => fs::remove_file(&local),
                Err(_) => return json_reply(200, "{\"boolean\":false}".into()),
            };
            match r {
                Ok(()) => json_reply(200, "{\"boolean\":true}".into()),
                Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => exception(
                    403,
                    "PathIsNotEmptyDirectoryException",
                    &format!("`{hdfs_path} is non empty': Directory is not empty"),
                ),
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "RENAME") => {
            let Some(dest) = req.query("destination") else {
                return exception(400, "IllegalArgumentException", "destination");
            };
            let to = root.join(dest.trim_start_matches('/'));
            if to.exists() {
                return json_reply(200, "{\"boolean\":false}".into());
            }
            match fs::rename(&local, &to) {
                Ok(()) => json_reply(200, "{\"boolean\":true}".into()),
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "SETPERMISSION") => {
            let perm = req
                .query("permission")
                .and_then(|p| u32::from_str_radix(p, 8).ok())
                .unwrap_or(0o644);
            match fs::set_permissions(&local, fs::Permissions::from_mode(perm)) {
                Ok(()) => Reply {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "SETOWNER") => {
            let uid = req.query("owner").and_then(names::uid_of);
            let gid = req.query("group").and_then(names::gid_of);
            match std::os::unix::fs::lchown(&local, uid, gid) {
                Ok(()) => Reply {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "SETTIMES") => {
            let m = req
                .query("modificationtime")
                .and_then(|v| v.parse::<i64>().ok());
            let a = req.query("accesstime").and_then(|v| v.parse::<i64>().ok());
            let cur = match fs::metadata(&local) {
                Ok(c) => c,
                Err(e) => return io_exception(&e, hdfs_path),
            };
            let to_time = |ms: i64| {
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64)
            };
            let mtime = m.map(to_time).unwrap_or_else(|| cur.modified().unwrap());
            let atime = a.map(to_time).unwrap_or_else(|| cur.accessed().unwrap());
            match fs::File::open(&local).and_then(|f| {
                f.set_times(fs::FileTimes::new().set_modified(mtime).set_accessed(atime))
            }) {
                Ok(()) => Reply {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                Err(e) => io_exception(&e, hdfs_path),
            }
        }
        ("PUT", "CREATESYMLINK") => exception(
            400,
            "UnsupportedOperationException",
            "Symlinks not supported",
        ),
        _ => exception(
            400,
            "IllegalArgumentException",
            &format!(
                "Invalid value for webhdfs parameter \"op\": {} {}",
                req.method, op
            ),
        ),
    }
}
