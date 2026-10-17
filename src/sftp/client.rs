//! `SftpTree`: the `Tree` port over SFTP version 3, reached through `ssh -s sftp` (or the
//! command `RCP_SSH` names), so any host with OpenSSH is an endpoint whether or not rcp
//! is installed there. One subsystem session per pooled channel; reads and writes are
//! pipelined by request id within a window, 256 KiB apiece (the most OpenSSH's server
//! takes in one packet). What SFTP v3 cannot say: inode numbers (so hard links are not
//! detected on an sftp source and not made on an sftp destination: the core copies the
//! file instead), nanosecond times (whole seconds), holes (zero runs are detected on read
//! and skipped on write), extended attributes (none).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use super::proto::*;
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, Log, MetaOptions, Refusals, Removed,
    Segment, Sink, Tree,
};

const READ_WINDOW: usize = 8;
const WRITE_WINDOW: usize = 16;

/// One SFTP session over one ssh subsystem channel.
struct Session {
    child: Option<Child>,
    input: Box<dyn Read + Send>,
    output: Box<dyn Write + Send>,
    next_id: u32,
    /// Replies that arrived while another id was awaited.
    parked: HashMap<u32, (u8, Vec<u8>)>,
    extensions: BTreeMap<String, String>,
    /// The READ and WRITE lengths this server accepts; see `Session::io_limits`.
    max_read: u32,
    max_write: u32,
}

fn status_error(body: &[u8], what: &str) -> io::Error {
    let mut d = Dec::new(body);
    let code = d.u32().unwrap_or(FX_FAILURE);
    let text = d.string().unwrap_or_default();
    io::Error::new(
        kind_of(code),
        if text.is_empty() {
            format!("{what}: sftp status {code}")
        } else {
            format!("{what}: {text}")
        },
    )
}

/// How `sftp://` endpoints are reached: the ssh command that starts the subsystem
/// (`RCP_SSH` overrides it, as for `ssh://`), and where debug lines go.
#[derive(Clone)]
pub struct Settings {
    pub ssh: String,
    pub log: Arc<dyn Log>,
}

impl Settings {
    /// `RCP_SSH`, or `ssh`.
    pub fn from_env(log: Arc<dyn Log>) -> Settings {
        Settings {
            ssh: std::env::var("RCP_SSH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "ssh".into()),
            log,
        }
    }
}

impl Session {
    fn open(
        settings: &Settings,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> io::Result<Session> {
        let mut c = Command::new(&settings.ssh);
        c.arg("-o").arg("BatchMode=yes");
        if let Some(p) = port {
            c.arg("-p").arg(p.to_string());
        }
        let target = match user {
            Some(u) => format!("{u}@{host}"),
            None => host.to_string(),
        };
        c.arg(target).arg("-s").arg("sftp");
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = c.spawn().map_err(|e| {
            io::Error::new(e.kind(), format!("{}: cannot start ssh: {e}", settings.ssh))
        })?;
        let input = Box::new(BufReader::with_capacity(
            1 << 20,
            child.stdout.take().expect("piped"),
        ));
        let output = Box::new(BufWriter::with_capacity(
            1 << 20,
            child.stdin.take().expect("piped"),
        ));
        let mut s = Session {
            child: Some(child),
            input,
            output,
            next_id: 1,
            parked: HashMap::new(),
            extensions: BTreeMap::new(),
            max_read: DEFAULT_IO,
            max_write: DEFAULT_IO,
        };
        let mut e = Enc::new();
        e.u32(3);
        write_packet(&mut s.output, INIT, &e.into_bytes())?;
        s.output.flush()?;
        let (t, body) = s.next_packet()?;
        if t != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the sftp subsystem answered INIT with packet type {t}"),
            ));
        }
        let mut d = Dec::new(&body);
        let version = d.u32()?;
        if version < 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("sftp version {version}; rcp needs 3"),
            ));
        }
        while !d.rest().is_empty() {
            let name = d.string()?;
            let data = d.string()?;
            s.extensions.insert(name, data);
        }
        (s.max_read, s.max_write) = s.io_limits()?;
        Ok(s)
    }

    /// The READ and WRITE lengths to use: what the server advertises through
    /// `limits@openssh.com`, capped at `IO_CEILING`, or `DEFAULT_IO` when it advertises
    /// nothing. A length of zero in the reply means the server sets no limit.
    fn io_limits(&mut self) -> io::Result<(u32, u32)> {
        if !self.has("limits@openssh.com") {
            return Ok((DEFAULT_IO, DEFAULT_IO));
        }
        let mut e = Enc::new();
        e.string("limits@openssh.com");
        match self.call(EXTENDED, &e.into_bytes())? {
            (EXTENDED_REPLY, body) => {
                let mut d = Dec::new(&body);
                let _max_packet = d.u64()?;
                let read = d.u64()?;
                let write = d.u64()?;
                let usable = |n: u64| match n {
                    0 => IO_CEILING,
                    n => n.min(IO_CEILING as u64) as u32,
                };
                Ok((usable(read), usable(write)))
            }
            (STATUS, body) => Err(status_error(&body, "sftp limits@openssh.com")),
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sftp limits@openssh.com: packet type {other} where a reply was expected"),
            )),
        }
    }

    fn next_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        match read_packet(&mut self.input)? {
            Some(p) => Ok(p),
            None => {
                let status = self
                    .child
                    .as_mut()
                    .and_then(|c| c.try_wait().ok().flatten());
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    match status {
                        Some(s) => format!("the sftp subsystem ended ({s})"),
                        None => "the sftp subsystem closed the stream".to_string(),
                    },
                ))
            }
        }
    }

    /// Sends one request; the id to receive by.
    fn send(&mut self, t: u8, args: &[u8]) -> io::Result<u32> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut body = Vec::with_capacity(args.len() + 4);
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(args);
        write_packet(&mut self.output, t, &body)?;
        self.output.flush()?;
        Ok(id)
    }

    /// The reply to `id`: its type and the body after the id.
    fn recv(&mut self, id: u32) -> io::Result<(u8, Vec<u8>)> {
        if let Some(r) = self.parked.remove(&id) {
            return Ok(r);
        }
        loop {
            let (t, body) = self.next_packet()?;
            if body.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sftp reply without an id",
                ));
            }
            let got = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
            let rest = body[4..].to_vec();
            if got == id {
                return Ok((t, rest));
            }
            if self.parked.len() > 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the sftp server answers requests nobody made",
                ));
            }
            self.parked.insert(got, (t, rest));
        }
    }

    fn call(&mut self, t: u8, args: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let id = self.send(t, args)?;
        self.recv(id)
    }

    /// A request whose only good answer is STATUS OK.
    fn ok(&mut self, t: u8, args: &[u8], what: &str) -> io::Result<()> {
        match self.call(t, args)? {
            (STATUS, body) => {
                let code = Dec::new(&body).u32()?;
                if code == FX_OK {
                    Ok(())
                } else {
                    Err(status_error(&body, what))
                }
            }
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: sftp packet type {other} where a status was expected"),
            )),
        }
    }

    fn handle(&mut self, t: u8, args: &[u8], what: &str) -> io::Result<Vec<u8>> {
        match self.call(t, args)? {
            (HANDLE, body) => Ok(Dec::new(&body).bytes()?.to_vec()),
            (STATUS, body) => Err(status_error(&body, what)),
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: sftp packet type {other} where a handle was expected"),
            )),
        }
    }

    fn attrs(&mut self, t: u8, args: &[u8], what: &str) -> io::Result<Attrs> {
        match self.call(t, args)? {
            (ATTRS, body) => Attrs::decode(&mut Dec::new(&body)),
            (STATUS, body) => Err(status_error(&body, what)),
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: sftp packet type {other} where attributes were expected"),
            )),
        }
    }

    /// The single name a READLINK or REALPATH answers with.
    fn name(&mut self, t: u8, args: &[u8], what: &str) -> io::Result<String> {
        match self.call(t, args)? {
            (NAME, body) => {
                let mut d = Dec::new(&body);
                if d.u32()? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{what}: empty name reply"),
                    ));
                }
                d.string()
            }
            (STATUS, body) => Err(status_error(&body, what)),
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: sftp packet type {other} where a name was expected"),
            )),
        }
    }

    fn close(&mut self, handle: &[u8]) -> io::Result<()> {
        let mut e = Enc::new();
        e.bytes(handle);
        self.ok(CLOSE, &e.into_bytes(), "close")
    }

    fn has(&self, extension: &str) -> bool {
        self.extensions.contains_key(extension)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Pool {
    settings: Settings,
    user: Option<String>,
    host: String,
    port: Option<u16>,
    idle: Mutex<Vec<Session>>,
}

impl Pool {
    fn take(&self) -> io::Result<Session> {
        if let Some(s) = self.idle.lock().unwrap().pop() {
            return Ok(s);
        }
        Session::open(&self.settings, self.user.as_deref(), &self.host, self.port)
    }
    fn give(&self, s: Session) {
        if s.parked.is_empty() {
            self.idle.lock().unwrap().push(s);
        }
    }
    fn with<R>(&self, f: impl FnOnce(&mut Session) -> io::Result<R>) -> io::Result<R> {
        let mut s = self.take()?;
        let r = f(&mut s);
        self.give(s);
        r
    }
}

pub struct SftpTree {
    pool: Arc<Pool>,
    root: String,
    display: PathBuf,
}

fn secs(ns: i128) -> u32 {
    (ns / 1_000_000_000).clamp(0, u32::MAX as i128) as u32
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// What `path` is, for a server whose LSTAT left out the permissions that would say (SFTP v3
/// allows that). Only READLINK is evidence: it answers only for a link and does not follow
/// one, and a link is then replaced. Nothing else here is. It is tempting to take "OPENDIR
/// opens it and REALPATH resolves it to its own path" for a directory, but OPENDIR follows a
/// link, and draft-02's REALPATH need only normalize the spelling -- pkg/sftp and SFTPGo do
/// exactly that -- so a link to a directory would pass, and the subtree would be written
/// through it. These are the servers that omit permissions in the first place. So a name
/// READLINK does not answer for is unknown: its mkdir fails and the subtree is fenced. On such
/// a server a directory already at the destination fails the copy loudly, which is the cost.
fn probe_kind(s: &mut Session, path: &str) -> Option<Kind> {
    let mut e = Enc::new();
    e.string(path);
    s.name(READLINK, &e.into_bytes(), path)
        .ok()
        .map(|_| Kind::Symlink)
}

/// Which port kind a mode's type bits describe, if one this tool carries.
fn kind_of_mode(mode: u32) -> Option<Kind> {
    match mode & 0o170000 {
        0o040000 => Some(Kind::Dir),
        0o120000 => Some(Kind::Symlink),
        0o100000 => Some(Kind::File),
        _ => None,
    }
}

impl SftpTree {
    /// Reaches `path` on `host` through one session, creating the directory when `create`
    /// says so.
    pub fn connect(
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        path: &Path,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SftpTree> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: sftp:// paths are absolute on the remote host",
                    path.display()
                ),
            ));
        }
        let root = path.to_string_lossy().trim_end_matches('/').to_string();
        let root = if root.is_empty() {
            "/".to_string()
        } else {
            root
        };
        let mut s = Session::open(settings, user, host, port)?;
        let mut e = Enc::new();
        e.string(&root);
        match s.attrs(LSTAT, &e.into_bytes(), &root) {
            Ok(a) => {
                if kind_of_mode(a.permissions.unwrap_or(0)) != Some(Kind::Dir) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        format!("{root}: not a directory"),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                let mut m = Enc::new();
                m.string(&root);
                Attrs {
                    permissions: Some(0o755),
                    ..Default::default()
                }
                .encode(&mut m);
                s.ok(MKDIR, &m.into_bytes(), &root)?;
            }
            // Not refused here when it is not to be created: a dry run opens its destination
            // this way, and a destination that does not exist yet is an empty one to plan
            // against -- refused, `-dryrun` into a new directory on this transport would fail
            // at open while the same run into a local one planned it. A SOURCE that
            // is not there still fails: its listing answers `NotFound`, which ends the run.
            Err(e) if e.kind() == io::ErrorKind::NotFound && !create => {}
            Err(e) => return Err(e),
        }
        let display = PathBuf::from(format!(
            "sftp://{}{host}{}{root}",
            user.map(|u| format!("{u}@")).unwrap_or_default(),
            port.map(|p| format!(":{p}")).unwrap_or_default()
        ));
        crate::debug!(
            settings.log,
            "sftp {}: subsystem through {} ({} extensions; reads of {} and writes of {} bytes)",
            display.display(),
            settings.ssh,
            s.extensions.len(),
            s.max_read,
            s.max_write
        );
        let pool = Arc::new(Pool {
            settings: settings.clone(),
            user: user.map(str::to_string),
            host: host.to_string(),
            port,
            idle: Mutex::new(vec![s]),
        });
        Ok(SftpTree {
            pool,
            root,
            display,
        })
    }

    fn abs(&self, rel: &str) -> String {
        if rel == "." {
            self.root.clone()
        } else if self.root == "/" {
            format!("/{rel}")
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    fn item_from(&self, rel: &str, a: &Attrs, link_target: Option<PathBuf>) -> Option<Item> {
        let mode = a.permissions.unwrap_or(0);
        let kind = kind_of_mode(mode)?;
        let (uid, gid) = a.uid_gid.unwrap_or((0, 0));
        let (atime, mtime) = a.times.unwrap_or((0, 0));
        let size = if kind == Kind::File {
            a.size.unwrap_or(0)
        } else {
            0
        };
        Some(Item {
            rel: rel.to_string(),
            kind,
            size,
            mtime_ns: mtime as i128 * 1_000_000_000,
            atime_ns: atime as i128 * 1_000_000_000,
            mode: mode & 0o7777,
            uid,
            gid,
            dev: 0,
            ino: fnv64(&self.abs(rel)),
            nlink: 1,
            blocks: size,
            link_target,
        })
    }

    fn lstat_item(&self, s: &mut Session, rel: &str) -> io::Result<Option<Item>> {
        let path = self.abs(rel);
        let mut e = Enc::new();
        e.string(&path);
        let a = match s.attrs(LSTAT, &e.into_bytes(), &path) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let link_target = if kind_of_mode(a.permissions.unwrap_or(0)) == Some(Kind::Symlink) {
            let mut e = Enc::new();
            e.string(&path);
            Some(PathBuf::from(s.name(READLINK, &e.into_bytes(), &path)?))
        } else {
            None
        };
        Ok(self.item_from(rel, &a, link_target))
    }

    /// Every entry of one directory, by name, with its attributes.
    fn readdir(&self, s: &mut Session, rel: &str) -> io::Result<Vec<(String, Attrs)>> {
        let path = self.abs(rel);
        let mut e = Enc::new();
        e.string(&path);
        let handle = s.handle(OPENDIR, &e.into_bytes(), &path)?;
        let mut out = Vec::new();
        let result = (|| loop {
            let mut e = Enc::new();
            e.bytes(&handle);
            match s.call(READDIR, &e.into_bytes())? {
                (NAME, body) => {
                    let mut d = Dec::new(&body);
                    for _ in 0..d.u32()? {
                        let name = d.string()?;
                        let _longname = d.string()?;
                        let a = Attrs::decode(&mut d)?;
                        if name != "." && name != ".." && !name.contains('/') {
                            out.push((name, a));
                        }
                    }
                }
                (STATUS, body) => {
                    let code = Dec::new(&body).u32()?;
                    if code == FX_EOF {
                        return Ok(());
                    }
                    return Err(status_error(&body, &path));
                }
                (other, _) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{path}: sftp packet type {other} in a directory listing"),
                    ))
                }
            }
        })();
        let closed = s.close(&handle);
        result?;
        closed?;
        Ok(out)
    }

    fn setstat(&self, s: &mut Session, rel: &str, attrs: &Attrs) -> io::Result<()> {
        let path = self.abs(rel);
        let mut e = Enc::new();
        e.string(&path);
        attrs.encode(&mut e);
        s.ok(SETSTAT, &e.into_bytes(), &path)
    }

    fn remove_any(&self, s: &mut Session, rel: &str) -> io::Result<()> {
        let path = self.abs(rel);
        let mut e = Enc::new();
        e.string(&path);
        let a = match s.attrs(LSTAT, &e.into_bytes(), &path) {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut e = Enc::new();
        e.string(&path);
        let t = if kind_of_mode(a.permissions.unwrap_or(0)) == Some(Kind::Dir) {
            RMDIR
        } else {
            REMOVE
        };
        s.ok(t, &e.into_bytes(), &path)
    }
}

pub struct SftpReader {
    pool: Arc<Pool>,
    sess: Option<Session>,
    handle: Vec<u8>,
    pos: u64,
    size: u64,
    window: VecDeque<(u32, u64, u32)>,
    ahead: u64,
    leftover: Vec<u8>,
    taken: usize,
}

impl SftpReader {
    fn fill(&mut self) -> io::Result<()> {
        let s = self.sess.as_mut().expect("open reader has a session");
        while self.window.len() < READ_WINDOW && self.ahead < self.size {
            let len = (self.size - self.ahead).min(s.max_read as u64) as u32;
            let mut e = Enc::new();
            e.bytes(&self.handle).u64(self.ahead).u32(len);
            let id = s.send(READ, &e.into_bytes())?;
            self.window.push_back((id, self.ahead, len));
            self.ahead += len as u64;
        }
        Ok(())
    }

    fn drain_window(&mut self) {
        if let Some(s) = self.sess.as_mut() {
            while let Some((id, _, _)) = self.window.pop_front() {
                let _ = s.recv(id);
            }
        }
    }

    fn discard(&mut self) {
        self.drain_window();
        self.leftover.clear();
        self.taken = 0;
    }

    /// The next block from the window: the bytes, or none at the end of the file.
    fn next_block(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.pos >= self.size {
            return Ok(None);
        }
        self.fill()?;
        let Some((id, offset, want)) = self.window.pop_front() else {
            return Ok(None);
        };
        debug_assert_eq!(offset, self.pos);
        let s = self.sess.as_mut().expect("open reader has a session");
        let reply = match s.recv(id) {
            Ok(r) => r,
            Err(e) => {
                // The request was already popped. Later window entries sit past `ahead`
                // and must not be consumed as this offset's bytes.
                self.drain_window();
                self.ahead = self.pos;
                return Err(e);
            }
        };
        match reply {
            (DATA, body) => {
                let data = Dec::new(&body).bytes()?.to_vec();
                if data.is_empty() {
                    self.size = self.pos;
                    self.discard();
                    return Ok(None);
                }
                self.pos += data.len() as u64;
                // A short DATA reply is legal. `fill` already queued the next read at
                // `offset + want`, so those bytes would be appended here and the gap
                // never requested. Drop that window and ask again from where the
                // consumer actually is.
                if (data.len() as u32) < want {
                    self.drain_window();
                    self.ahead = self.pos;
                }
                self.fill()?;
                Ok(Some(data))
            }
            (STATUS, body) => {
                let code = Dec::new(&body).u32()?;
                if code == FX_EOF {
                    self.size = self.pos;
                    self.discard();
                    Ok(None)
                } else {
                    Err(status_error(&body, "read"))
                }
            }
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sftp packet type {other} where data was expected"),
            )),
        }
    }
}

impl Drop for SftpReader {
    fn drop(&mut self) {
        self.discard();
        if let Some(mut s) = self.sess.take() {
            let _ = s.close(&self.handle);
            self.pool.give(s);
        }
    }
}

impl Read for SftpReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.taken < self.leftover.len() {
            let n = (self.leftover.len() - self.taken).min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[self.taken..self.taken + n]);
            self.taken += n;
            return Ok(n);
        }
        // `pos` counts bytes fetched; what the consumer has taken lags by the leftover
        let Some(data) = self.next_block()? else {
            return Ok(0);
        };
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        if n < data.len() {
            self.leftover = data;
            self.taken = n;
        } else {
            self.leftover.clear();
            self.taken = 0;
        }
        Ok(n)
    }
}

impl Seek for SftpReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let consumed = self.pos - (self.leftover.len() - self.taken) as u64;
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => consumed as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        let new = new as u64;
        if new != consumed {
            self.discard();
            self.pos = new;
            self.ahead = new;
        }
        Ok(new)
    }
}

pub struct SftpSink {
    pool: Arc<Pool>,
    sess: Option<Session>,
    handle: Vec<u8>,
    path: String,
    pos: u64,
    pending: VecDeque<u32>,
    closed: bool,
}

impl SftpSink {
    fn reap_one(&mut self) -> io::Result<()> {
        let Some(id) = self.pending.pop_front() else {
            return Ok(());
        };
        let s = self.sess.as_mut().expect("open sink has a session");
        match s.recv(id)? {
            (STATUS, body) => {
                if Dec::new(&body).u32()? == FX_OK {
                    Ok(())
                } else {
                    Err(status_error(&body, &self.path))
                }
            }
            (other, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: sftp packet type {other} where a status was expected",
                    self.path
                ),
            )),
        }
    }
    fn drain(&mut self) -> io::Result<()> {
        let mut first = None;
        while !self.pending.is_empty() {
            if let Err(e) = self.reap_one() {
                first.get_or_insert(e);
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn fsetstat(&mut self, attrs: &Attrs) -> io::Result<()> {
        let mut e = Enc::new();
        e.bytes(&self.handle);
        attrs.encode(&mut e);
        let s = self.sess.as_mut().expect("open sink has a session");
        s.ok(FSETSTAT, &e.into_bytes(), &self.path)
    }
}

impl Drop for SftpSink {
    fn drop(&mut self) {
        let _ = self.drain();
        if let Some(mut s) = self.sess.take() {
            if !self.closed {
                let _ = s.close(&self.handle);
            }
            self.pool.give(s);
        }
    }
}

impl Sink for SftpSink {
    fn reserve(&mut self, _len: u64) -> io::Result<()> {
        Ok(())
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let max = self
            .sess
            .as_ref()
            .expect("open sink has a session")
            .max_write;
        for chunk in data.chunks(max as usize) {
            if self.pending.len() >= WRITE_WINDOW {
                self.reap_one()?;
            }
            let mut e = Enc::new();
            e.bytes(&self.handle).u64(self.pos).bytes(chunk);
            let s = self.sess.as_mut().expect("open sink has a session");
            let id = s.send(WRITE, &e.into_bytes())?;
            self.pending.push_back(id);
            self.pos += chunk.len() as u64;
        }
        Ok(())
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        // nothing is written; the final size is set at finish, so a trailing hole counts
        self.pos += len;
        Ok(())
    }
    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals> {
        self.drain()?;
        let mut refusals = Refusals {
            owner: false,
            xattrs: xattrs.iter().map(|(k, _)| k.clone()).collect(),
        };
        self.fsetstat(&Attrs {
            size: Some(self.pos),
            ..Default::default()
        })?;
        if opts.owner {
            match self.fsetstat(&Attrs {
                uid_gid: Some((item.uid, item.gid)),
                ..Default::default()
            }) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                Err(e) => return Err(e),
            }
        }
        let mut a = Attrs::default();
        if opts.mode {
            a.permissions = Some(item.mode & 0o7777);
        }
        if opts.times {
            a.times = Some((
                secs(if opts.atime {
                    item.atime_ns
                } else {
                    item.mtime_ns
                }),
                secs(item.mtime_ns),
            ));
        }
        if a != Attrs::default() {
            self.fsetstat(&a)?;
        }
        if fsync {
            let s = self.sess.as_mut().expect("open sink has a session");
            if s.has("fsync@openssh.com") {
                let mut e = Enc::new();
                e.string("fsync@openssh.com").bytes(&self.handle);
                s.ok(EXTENDED, &e.into_bytes(), &self.path)?;
            }
        }
        let s = self.sess.as_mut().expect("open sink has a session");
        s.close(&self.handle)?;
        self.closed = true;
        Ok(refusals)
    }
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Tree for SftpTree {
    type Reader = SftpReader;
    type Sink = SftpSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        _parallel: usize,
    ) -> io::Result<Listing> {
        let now = crate::filter::now_ns();
        self.pool.with(|s| {
            // a root that is not there is `NotFound`: a source that ends the run, a dry run's
            // destination that is empty. Never an empty, error-free listing.
            let Some(root) = self.lstat_item(s, ".")? else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{}: No such file or directory", self.root().display()),
                ));
            };
            let mut items = vec![root];
            let mut errors = Vec::new();
            let mut dirs: Vec<(String, usize)> = vec![(".".to_string(), 0)];
            while let Some((dir, depth)) = dirs.pop() {
                let entries = match self.readdir(s, &dir) {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(format!("{}: {e}", self.abs(&dir)));
                        continue;
                    }
                };
                for (name, a) in entries {
                    let rel = if dir == "." {
                        name.clone()
                    } else {
                        format!("{dir}/{name}")
                    };
                    // An entry whose type the server did not report is not dropped in silence:
                    // unreported, it would copy as nothing and pass. A type this tool does not
                    // carry -- a fifo, a socket, a device -- is left out.
                    let Some(kind) = kind_of_mode(a.permissions.unwrap_or(0)) else {
                        // no permissions at all, or permissions without type bits
                        if a.permissions.is_none_or(|m| m & 0o170000 == 0) {
                            errors.push(format!(
                                "{}: the server did not report its type, so it is not copied",
                                self.abs(&rel)
                            ));
                        }
                        continue;
                    };
                    if !filter.allows(&rel, kind == Kind::Dir)
                        || max_depth.is_some_and(|d| depth + 1 > d)
                    {
                        continue;
                    }
                    let link_target = if kind == Kind::Symlink {
                        let path = self.abs(&rel);
                        let mut e = Enc::new();
                        e.string(&path);
                        match s.name(READLINK, &e.into_bytes(), &path) {
                            Ok(t) => Some(PathBuf::from(t)),
                            Err(e) => {
                                errors.push(format!("{path}: {e}"));
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    let Some(item) = self.item_from(&rel, &a, link_target) else {
                        continue;
                    };
                    let keep = match kind {
                        Kind::Dir => true,
                        Kind::File => {
                            filter.allows_file(item.size, item.mtime_ns, now)
                                && filter.allows_owner_kind(kind, item.uid, item.gid, item.ino)
                        }
                        Kind::Symlink => {
                            filter.allows_owner_kind(kind, item.uid, item.gid, item.ino)
                        }
                    };
                    if kind == Kind::Dir {
                        dirs.push((rel.clone(), depth + 1));
                    }
                    if keep {
                        items.push(item);
                    }
                }
            }
            items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
            errors.sort();
            Ok(Listing { items, errors })
        })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        self.pool.with(|s| self.lstat_item(s, rel))
    }

    fn open(&self, rel: &str) -> io::Result<SftpReader> {
        let path = self.abs(rel);
        let mut s = self.pool.take()?;
        let opened = (|| {
            let mut e = Enc::new();
            e.string(&path).u32(PFLAG_READ);
            Attrs::default().encode(&mut e);
            let handle = s.handle(OPEN, &e.into_bytes(), &path)?;
            let mut e = Enc::new();
            e.bytes(&handle);
            let size = match s.attrs(FSTAT, &e.into_bytes(), &path) {
                Ok(a) => a.size.unwrap_or(0),
                Err(e) => {
                    let _ = s.close(&handle);
                    return Err(e);
                }
            };
            Ok((handle, size))
        })();
        match opened {
            Ok((handle, size)) => Ok(SftpReader {
                pool: self.pool.clone(),
                sess: Some(s),
                handle,
                pos: 0,
                size,
                window: VecDeque::new(),
                ahead: 0,
                leftover: Vec::new(),
                taken: 0,
            }),
            Err(e) => {
                self.pool.give(s);
                Err(e)
            }
        }
    }

    fn read(
        &self,
        rel: &str,
        _buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        // blocks of zeros are holes: SFTP cannot say where the data is, so this is what
        // keeps a sparse file sparse across it
        let mut r = self.open(rel)?;
        while let Some(block) = r.next_block()? {
            if is_all_zero(&block) {
                sink(Segment::Hole(block.len() as u64))?;
            } else {
                sink(Segment::Data(&block))?;
            }
        }
        Ok(())
    }

    fn create_file(&self, item: &Item) -> io::Result<SftpSink> {
        let path = self.abs(&item.rel);
        let mut s = self.pool.take()?;
        // DO NOT OPEN THROUGH A SYMLINK THAT HOLDS THE NAME. OPEN with CREAT|TRUNC follows one, on
        // the server, so a copy of file `a` onto a destination symlink `a` would truncate and
        // rewrite whatever the link pointed at -- outside the destination -- and leave the link in
        // place (measured). CREAT|EXCL does not follow, so a new file costs one round trip. When
        // the name is taken, LSTAT says by what: a regular file is overwritten; anything else -- a
        // symlink, or a kind the server's LSTAT does not identify -- is removed and the file
        // created exclusively. This settles what holds the name when the run looks. SFTP v3 has no
        // open that refuses to follow, so a link planted between the LSTAT and the TRUNC open by a
        // concurrent writer is still followed.
        let open = |s: &mut Session, flags: u32| {
            let mut e = Enc::new();
            e.string(&path).u32(flags);
            Attrs {
                permissions: Some(item.mode & 0o7777 | 0o200),
                ..Default::default()
            }
            .encode(&mut e);
            s.handle(OPEN, &e.into_bytes(), &path)
        };
        let opened = match open(&mut s, PFLAG_WRITE | PFLAG_CREAT | PFLAG_EXCL) {
            Ok(h) => Ok(h),
            Err(first) => {
                let mut e = Enc::new();
                e.string(&path);
                match s.attrs(LSTAT, &e.into_bytes(), &path) {
                    Ok(a) if kind_of_mode(a.permissions.unwrap_or(0)) == Some(Kind::File) => {
                        open(&mut s, PFLAG_WRITE | PFLAG_CREAT | PFLAG_TRUNC)
                    }
                    Ok(_) => {
                        let mut r = Enc::new();
                        r.string(&path);
                        s.ok(REMOVE, &r.into_bytes(), &path)
                            .and_then(|()| open(&mut s, PFLAG_WRITE | PFLAG_CREAT | PFLAG_EXCL))
                    }
                    // LSTAT could not say what is there, so nothing is removed on a guess: the
                    // exclusive open's own error stands
                    Err(_) => Err(first),
                }
            }
        };
        match opened {
            Ok(handle) => Ok(SftpSink {
                pool: self.pool.clone(),
                sess: Some(s),
                handle,
                path,
                pos: 0,
                pending: VecDeque::new(),
                closed: false,
            }),
            Err(e) => {
                self.pool.give(s);
                Err(e)
            }
        }
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut SftpSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        let path = self.abs(rel);
        self.pool.with(|s| {
            let mut e = Enc::new();
            e.string(&path);
            Attrs {
                permissions: Some(0o755),
                ..Default::default()
            }
            .encode(&mut e);
            match s.ok(MKDIR, &e.into_bytes(), &path) {
                Ok(()) => Ok(()),
                Err(err) => {
                    // a directory already there is what was wanted
                    let mut e = Enc::new();
                    e.string(&path);
                    let kind = match s.attrs(LSTAT, &e.into_bytes(), &path) {
                        Ok(a) if a.permissions.is_none() => probe_kind(s, &path),
                        Ok(a) => kind_of_mode(a.permissions.unwrap_or(0)),
                        Err(_) => None,
                    };
                    match kind {
                        Some(Kind::Dir) => Ok(()),
                        // A SYMLINK WHERE A DIRECTORY BELONGS IS REPLACED, as the local tree
                        // replaces one. Refused and left in place, the MKDIR fails but the
                        // files under it are still created -- and the server resolves the
                        // path, so it opens them THROUGH the link: a `copy` over sftp wrote
                        // `a/x` into whatever `a` pointed at, outside the destination
                        // (measured).
                        Some(Kind::Symlink) => {
                            let mut r = Enc::new();
                            r.string(&path);
                            s.ok(REMOVE, &r.into_bytes(), &path)?;
                            let mut m = Enc::new();
                            m.string(&path);
                            Attrs {
                                permissions: Some(0o755),
                                ..Default::default()
                            }
                            .encode(&mut m);
                            s.ok(MKDIR, &m.into_bytes(), &path)
                        }
                        _ => Err(err),
                    }
                }
            }
        })
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        let path = self.abs(rel);
        self.pool.with(|s| {
            // SYMLINK refuses an existing name (a sync recreating a link hits this)
            self.remove_any(s, rel)?;
            let mut e = Enc::new();
            // OpenSSH's order: the target first, then the link
            e.string(&target.to_string_lossy()).string(&path);
            s.ok(SYMLINK, &e.into_bytes(), &path)
        })
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let (from, to) = (self.abs(existing), self.abs(rel));
        self.pool.with(|s| {
            if !s.has("hardlink@openssh.com") {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("{to}: this sftp server has no hard links"),
                ));
            }
            let mut e = Enc::new();
            e.string("hardlink@openssh.com").string(&from).string(&to);
            s.ok(EXTENDED, &e.into_bytes(), &to)
        })
    }

    // SFTP v3 has no extended attributes at all
    fn keeps_xattrs(&self) -> bool {
        false
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        let path = self.abs(rel);
        // `pool.with` is split here, deliberately. It takes a session and then runs the
        // closure, and BOTH can fail with `PermissionDenied`: the server answering
        // SSH_FX_PERMISSION_DENIED, and `Command::spawn` never starting the subsystem at
        // all (an `RCP_SSH` that is not executable, a noexec mount, an SELinux denial).
        // Folded together, the second came out as `Removed::Kept`, whose printed remedy is
        // to rerun once the entry can go -- advice about a server that refused, for a case
        // where no packet was ever sent. Taking the session first keeps them apart.
        let mut s = self.pool.take().map_err(|e| io::Error::new(e.kind(), format!("{rel}: the sftp subsystem could not be started, so nothing was asked of the server: {e}")))?;
        let r = {
            let mut e = Enc::new();
            e.string(&path);
            s.ok(
                if kind == Kind::Dir { RMDIR } else { REMOVE },
                &e.into_bytes(),
                &path,
            )
        };
        self.pool.give(s);
        match r {
            Ok(()) => Ok(Removed::Gone),
            // the end state holds, as the local and NFSv3 adapters already said; this one
            // reported a failure for a name that had vanished between the listing and now
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removed::Gone),
            // SSH_FX_PERMISSION_DENIED is the server refusing, the same as a WebDAV 423 --
            // BUT ONLY WHEN THE SERVER ANSWERED. `pool.with` also fails before any packet
            // is sent: `Command::spawn` on an `RCP_SSH` that is not executable, a noexec
            // mount, an SELinux denial, all `PermissionDenied`. Reported as `Kept`, those
            // print "run sync again once the entry can go", which is advice for a server
            // that refused -- and here nothing was asked. `Session::spawned` says which
            // side the error came from, so the two stop being the same answer.
            Err(e) => Removed::or_refused(e),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (self.abs(from), self.abs(to));
        self.pool.with(|s| {
            if s.has("posix-rename@openssh.com") {
                let mut e = Enc::new();
                e.string("posix-rename@openssh.com").string(&a).string(&b);
                return s.ok(EXTENDED, &e.into_bytes(), &b);
            }
            // plain RENAME refuses an existing target; clear it first
            self.remove_any(s, to)?;
            let mut e = Enc::new();
            e.string(&a).string(&b);
            s.ok(RENAME, &e.into_bytes(), &b)
        })
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let mut refusals = Refusals::default();
        if item.kind == Kind::Symlink {
            // SETSTAT follows the link; nothing here reaches the link itself
            refusals.owner = opts.owner;
            return Ok(refusals);
        }
        self.pool.with(|s| {
            if opts.owner {
                match self.setstat(
                    s,
                    rel,
                    &Attrs {
                        uid_gid: Some((item.uid, item.gid)),
                        ..Default::default()
                    },
                ) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                    Err(e) => return Err(e),
                }
            }
            let mut a = Attrs::default();
            if opts.mode {
                a.permissions = Some(item.mode & 0o7777);
            }
            if opts.times {
                a.times = Some((
                    secs(if opts.atime {
                        item.atime_ns
                    } else {
                        item.mtime_ns
                    }),
                    secs(item.mtime_ns),
                ));
            }
            if a != Attrs::default() {
                self.setstat(s, rel, &a)?;
            }
            Ok(refusals)
        })
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|(k, _)| k.clone()).collect())
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        self.pool.with(|s| {
            self.setstat(
                s,
                &item.rel,
                &Attrs {
                    times: Some((secs(item.atime_ns), secs(item.mtime_ns))),
                    ..Default::default()
                },
            )
        })
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
            "no native engine over sftp",
        ))
    }
}
