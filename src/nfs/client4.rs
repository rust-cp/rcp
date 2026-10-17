//! `Nfs4Tree`: the `Tree` port over NFSv4.0 (RFC 7530) as the data protocol, selected with
//! `-nfs.vers 4`. Everything is a COMPOUND: the root is walked from PUTROOTFH (no MOUNT
//! protocol), a client id is established once with SETCLIENTID and confirmed, every file
//! read or written is OPENed under an open-owner of its own and CLOSEd afterwards, READs
//! and WRITEs carry that open's stateid, and attributes travel as `fattr4` with owners as
//! strings (numeric when the server speaks that way, `name@domain` otherwise). The lease
//! is renewed when the tree has been idle. Pipelining is as on v3: a reader keeps READs in
//! flight ahead of the consumer and a sink keeps UNSTABLE WRITEs in flight, committed once.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::client::Pool;
use super::rpc::{self, Connection, Credentials, NFS_PROG};
use super::v4::*;
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::names;
use crate::tree::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree,
};

const READ_WINDOW: usize = 8;
const WRITE_WINDOW: usize = 16;
/// The uid a name this host does not know maps to (nobody).
const UNKNOWN_ID: u32 = 65534;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn split(rel: &str) -> (String, String) {
    match rel.rsplit_once('/') {
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => (".".to_string(), rel.to_string()),
    }
}

fn kind_of(ftype: u32) -> Option<Kind> {
    match ftype {
        NF4REG => Some(Kind::File),
        NF4DIR => Some(Kind::Dir),
        NF4LNK => Some(Kind::Symlink),
        _ => None,
    }
}

/// What every operation shares: the pool, the client id, the lease, and the owner naming.
/// How long to wait between retries of a COMPOUND the server answered `DELAY` or `GRACE`,
/// and how many times. Short enough that a file coming back from slow storage is not held
/// up by the client, bounded so a server stuck in its grace period fails by name instead of
/// hanging the copy.
const RETRY_WAITS: &[std::time::Duration] = &[
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(400),
    std::time::Duration::from_millis(1600),
    std::time::Duration::from_millis(3000),
];

struct Shared {
    pool: Arc<Pool>,
    clientid: AtomicU64,
    verifier: [u8; 8],
    client_name: Vec<u8>,
    lease: u32,
    last_call: AtomicU64,
    /// Whether the server takes numeric owner strings (flipped off on NFS4ERR_BADOWNER).
    numeric_owners: AtomicBool,
    domain: Mutex<Option<String>>,
    owner_seq: AtomicU64,
    settings: super::Settings,
}

impl Shared {
    /// Runs one COMPOUND, renewing the lease first when the tree has been idle for half
    /// of it, and re-establishing the client id when the server says it expired.
    fn compound(&self, c: Compound) -> io::Result<(u32, Vec<OpResult>)> {
        let idle = now_secs().saturating_sub(self.last_call.load(Ordering::Relaxed));
        if idle > (self.lease as u64 / 2).max(1) {
            let mut r = Compound::new();
            r.renew(self.clientid.load(Ordering::Relaxed));
            match call(&self.pool, r) {
                Ok((NFS4_OK, _)) => {}
                Ok((NFS4ERR_EXPIRED | NFS4ERR_STALE_CLIENTID, _)) => self.setclientid()?,
                Ok((s, _)) => return Err(status_error(s, "RENEW")),
                Err(e) => return Err(e),
            }
        }
        // RETRIED, because two NFSv4 statuses mean "ask again shortly" and nothing asked
        // again. `NFS4ERR_DELAY` is what a server sends while it brings a file back from
        // slow storage, and `NFS4ERR_GRACE` is the window after a server restart during
        // which it accepts no new state -- both are normal, both are transient, and both
        // failed the whole copy of that file. An operator saw a failure where the correct
        // behavior is to wait a moment.
        //
        // Bounded and backed off: a server that answers DELAY forever is a server that is
        // not going to serve this file, and a tight retry loop makes that worse for
        // everyone else on it. After `RETRY_WAITS` the status is returned and reported the
        // way it always was.
        let mut r = call(&self.pool, c.clone())?;
        for wait in RETRY_WAITS {
            if !matches!(r.0, NFS4ERR_DELAY | NFS4ERR_GRACE) {
                break;
            }
            crate::debug!(
                self.settings.log,
                "nfs4: status {} -- waiting {}ms and asking again",
                r.0,
                wait.as_millis()
            );
            std::thread::sleep(*wait);
            r = call(&self.pool, c.clone())?;
        }
        self.last_call.store(now_secs(), Ordering::Relaxed);
        Ok(r)
    }

    /// SETCLIENTID and its confirmation: one client id for the tree, however many
    /// connections carry it.
    fn setclientid(&self) -> io::Result<()> {
        let mut c = Compound::new();
        c.setclientid(&self.verifier, &self.client_name);
        let (status, ops) = call(&self.pool, c)?;
        if status != NFS4_OK {
            return Err(status_error(status, "SETCLIENTID"));
        }
        let r = ops
            .last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SETCLIENTID: no result"))?;
        let mut c = Compound::new();
        c.setclientid_confirm(r.clientid, &r.verifier);
        let (status, _) = call(&self.pool, c)?;
        if status != NFS4_OK {
            return Err(status_error(status, "SETCLIENTID_CONFIRM"));
        }
        self.clientid.store(r.clientid, Ordering::Relaxed);
        self.last_call.store(now_secs(), Ordering::Relaxed);
        Ok(())
    }

    fn next_owner(&self) -> Vec<u8> {
        format!(
            "rcp-{}-{}",
            std::process::id(),
            self.owner_seq.fetch_add(1, Ordering::Relaxed)
        )
        .into_bytes()
    }

    /// A uid or gid from the server's owner string: a number, or `name@domain` looked up
    /// in this host's passwd and group files.
    fn id_of(&self, text: &str, user: bool) -> u32 {
        if let Ok(n) = text.parse::<u32>() {
            return n;
        }
        let (name, domain) = text
            .split_once('@')
            .map(|(n, d)| (n, Some(d)))
            .unwrap_or((text, None));
        if let Some(d) = domain {
            let mut cur = self.domain.lock().unwrap();
            if cur.is_none() {
                *cur = Some(d.to_string());
            }
        }
        let looked = if user {
            names::uid_of(name)
        } else {
            names::gid_of(name)
        };
        looked.unwrap_or(UNKNOWN_ID)
    }

    /// The owner string for `id`: numeric while the server accepts that, `name@domain`
    /// otherwise (the domain from `RCP_NFS4_DOMAIN`, else what the server itself uses).
    fn owner_string(&self, id: u32, user: bool) -> String {
        if self.numeric_owners.load(Ordering::Relaxed) {
            return id.to_string();
        }
        let name = if user {
            names::user(id)
        } else {
            names::group(id)
        };
        let domain = std::env::var("RCP_NFS4_DOMAIN")
            .ok()
            .filter(|d| !d.is_empty())
            .or_else(|| self.domain.lock().unwrap().clone())
            .unwrap_or_else(|| "localdomain".into());
        format!("{name}@{domain}")
    }

    fn item_from(&self, rel: String, a: &Attrs, link_target: Option<PathBuf>) -> Option<Item> {
        let kind = kind_of(a.ftype?)?;
        Some(Item {
            rel,
            kind,
            size: if kind == Kind::File {
                a.size.unwrap_or(0)
            } else {
                0
            },
            mtime_ns: a.time_modify.map(|t| t.ns()).unwrap_or(0),
            atime_ns: a.time_access.map(|t| t.ns()).unwrap_or(0),
            mode: a.mode.unwrap_or(0) & 0o7777,
            uid: a.owner.as_deref().map(|o| self.id_of(o, true)).unwrap_or(0),
            gid: a
                .owner_group
                .as_deref()
                .map(|g| self.id_of(g, false))
                .unwrap_or(0),
            dev: a.fsid.map(|(major, _)| major).unwrap_or(0),
            ino: a.fileid.unwrap_or(0),
            nlink: a.numlinks.unwrap_or(1) as u64,
            blocks: a.space_used.unwrap_or(0),
            link_target,
        })
    }
}

pub struct Nfs4Tree {
    shared: Arc<Shared>,
    root_fh: Vec<u8>,
    /// The directory holding the root and the root's name there, when the root is a path
    /// inside the export; `None` at the export root.
    root_parent: Option<(Vec<u8>, String)>,
    /// The root does not exist and was not to be created (a dry run's new destination, or
    /// a missing source). `root_fh` is then an ANCESTOR; see the v3 tree's field of the
    /// same name for why nothing may treat it as the root.
    missing: bool,
    display: PathBuf,
    rtmax: u32,
    wtmax: u32,
    handles: Mutex<BTreeMap<String, Vec<u8>>>,
    acl4: bool,
}

struct WalkQueue {
    dirs: Vec<(String, Vec<u8>, usize)>,
    in_flight: usize,
}

fn status_of(status: u32, ops: &[OpResult], what: &str) -> io::Result<()> {
    if status == NFS4_OK {
        return Ok(());
    }
    // the failing operation is the last one answered; name it when it helps
    let op = ops.last().map(|o| o.op);
    let label = match op {
        Some(OP_LOOKUP) => format!("{what}: LOOKUP"),
        Some(OP_OPEN) => format!("{what}: OPEN"),
        Some(OP_CREATE) => format!("{what}: CREATE"),
        Some(OP_REMOVE) => format!("{what}: REMOVE"),
        Some(OP_RENAME) => format!("{what}: RENAME"),
        Some(OP_LINK) => format!("{what}: LINK"),
        Some(OP_SETATTR) => format!("{what}: SETATTR"),
        Some(OP_READ) => format!("{what}: READ"),
        Some(OP_WRITE) => format!("{what}: WRITE"),
        Some(OP_READDIR) => format!("{what}: READDIR"),
        _ => what.to_string(),
    };
    Err(status_error(status, &label))
}

impl Nfs4Tree {
    /// Reaches `export` on `host` over NFSv4 (the root walked from PUTROOTFH, no mount
    /// protocol), establishes a client id, and resolves `sub` inside it, creating missing
    /// components when `create` is set. The port comes from the portmapper unless
    /// `RCP_NFS_PORT` says otherwise.
    pub fn connect(
        host: &str,
        export: &str,
        sub: &Path,
        create: bool,
        settings: &super::Settings,
    ) -> io::Result<Nfs4Tree> {
        let creds = Credentials::current();
        let hosts: Vec<String> = host
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
        let env_port = std::env::var("RCP_NFS_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok());
        let nfs_port = match env_port {
            Some(p) => p,
            None => hosts
                .iter()
                .find_map(|h| rpc::getport(h, NFS_PROG, NFS4_VERS).ok())
                .unwrap_or(2049),
        };
        let sec = settings.sec;
        let pool = Arc::new(Pool::new(
            hosts.clone(),
            nfs_port,
            creds.clone(),
            sec,
            NFS_PROG,
            NFS4_VERS,
        ));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let shared = Arc::new(Shared {
            pool,
            clientid: AtomicU64::new(0),
            verifier: (now as u64).to_be_bytes(),
            client_name: format!("rcp/{}/{}/{now}", creds.machine, std::process::id()).into_bytes(),
            lease: 90,
            last_call: AtomicU64::new(now_secs()),
            numeric_owners: AtomicBool::new(true),
            domain: Mutex::new(None),
            owner_seq: AtomicU64::new(1),
            settings: settings.clone(),
        });
        // the export in the server's v4 namespace, then its lease and transfer sizes
        let mut c = Compound::new();
        c.putrootfh();
        for comp in export.split('/').filter(|s| !s.is_empty() && *s != ".") {
            c.lookup(comp);
        }
        c.getfh().getattr(&bitmap_of(&[
            FATTR4_LEASE_TIME,
            FATTR4_MAXREAD,
            FATTR4_MAXWRITE,
        ]));
        let (status, ops) = call(&shared.pool, c).map_err(|e| {
            let text = e.to_string();
            if text.contains("program version mismatch") || text.contains("program unavailable") {
                io::Error::new(io::ErrorKind::Unsupported, format!("{host}:{export}: the server does not speak NFSv4 ({text}); use -nfs.vers 3"))
            } else {
                io::Error::new(e.kind(), format!("{host}:{export}: NFSv4: {e}"))
            }
        })?;
        status_of(
            status,
            &ops,
            &format!("{host}:{export}: NFSv4 walk to the export"),
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{e}; is it exported for NFSv4?")))?;
        let export_fh = ops.iter().find_map(|o| o.fh.clone()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "NFSv4: no handle in the reply")
        })?;
        let info = ops
            .iter()
            .find_map(|o| o.decoded.clone())
            .unwrap_or_default();
        let lease = info.lease_time.unwrap_or(90).max(10);
        let rtmax = info.maxread.unwrap_or(65_536).clamp(4096, 1 << 20) as u32;
        let wtmax = info.maxwrite.unwrap_or(65_536).clamp(4096, 1 << 20) as u32;
        let shared = Arc::new(Shared {
            lease,
            ..Arc::try_unwrap(shared).ok().expect("unshared")
        });
        shared
            .setclientid()
            .map_err(|e| io::Error::new(e.kind(), format!("{host}:{export}: {e}")))?;
        let mut root_fh = export_fh;
        let mut root_parent = None;
        let mut missing = false;
        for comp in sub.components() {
            if missing {
                break;
            }
            if let std::path::Component::Normal(name) = comp {
                let name = name.to_string_lossy();
                let mut c = Compound::new();
                c.putfh(&root_fh).lookup(&name).getfh();
                let (status, ops) = call(&shared.pool, c)?;
                let looked = if status == NFS4_OK {
                    ops.last().and_then(|o| o.fh.clone())
                } else {
                    None
                };
                root_parent = Some((root_fh.clone(), name.to_string()));
                root_fh = match looked {
                    Some(fh) => fh,
                    None if status == NFS4ERR_NOENT && create => {
                        let attrs = Attrs {
                            mode: Some(0o700),
                            ..Default::default()
                        };
                        let mut c = Compound::new();
                        c.putfh(&root_fh).create_dir(&name, &attrs).getfh();
                        let (status, ops) = call(&shared.pool, c)?;
                        status_of(status, &ops, &format!("{host}:{export}:{}", sub.display()))?;
                        ops.last().and_then(|o| o.fh.clone()).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "CREATE: no handle in the reply",
                            )
                        })?
                    }
                    // not to be created: a dry run's destination plans as empty, and the
                    // walk stops rather than resolving later names against the ancestor
                    None if status == NFS4ERR_NOENT => {
                        missing = true;
                        root_fh.clone()
                    }
                    None => {
                        return status_of(
                            status,
                            &ops,
                            &format!("{host}:{export}:{}", sub.display()),
                        )
                        .map(|_| unreachable!())
                    }
                };
            }
        }
        let display = if sub == Path::new("/") {
            format!("{host}:{export}")
        } else {
            format!("{host}:{export}:{}", sub.display())
        };
        crate::debug!(settings.log, "nfs4 {display}: nfs port {nfs_port}, sec {}, lease {lease}, rtmax {rtmax}, wtmax {wtmax}, clientid {:#x}", sec.name(), shared.clientid.load(Ordering::Relaxed));
        Ok(Nfs4Tree {
            shared,
            root_fh,
            root_parent,
            missing,
            display: PathBuf::from(display),
            rtmax,
            wtmax,
            handles: Mutex::new(BTreeMap::new()),
            acl4: settings.acl4,
        })
    }

    fn compound(&self, c: Compound) -> io::Result<(u32, Vec<OpResult>)> {
        self.shared.compound(c)
    }

    /// The handle for `rel`, resolved component by component and cached.
    fn fh_of(&self, rel: &str) -> io::Result<Vec<u8>> {
        if self.missing {
            // the same words the server's own NOENT carries, so a missing root reads the
            // same whether the walk or a later call found it
            let at = if rel == "." {
                self.display.clone()
            } else {
                self.display.join(rel)
            };
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no such file or directory", at.display()),
            ));
        }
        if rel == "." {
            return Ok(self.root_fh.clone());
        }
        if let Some(fh) = self.handles.lock().unwrap().get(rel) {
            return Ok(fh.clone());
        }
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let mut c = Compound::new();
        c.putfh(&dir).lookup(&name).getfh();
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, rel)?;
        let fh = ops.last().and_then(|o| o.fh.clone()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{rel}: no handle in the reply"),
            )
        })?;
        self.handles
            .lock()
            .unwrap()
            .insert(rel.to_string(), fh.clone());
        Ok(fh)
    }

    fn remember(&self, rel: &str, fh: Vec<u8>) {
        self.handles.lock().unwrap().insert(rel.to_string(), fh);
    }

    /// Runs `op` with the handle for `rel`; on a STALE or EXPIRED handle, drops the cached
    /// entry and runs it once more against a freshly resolved one.
    ///
    /// `fh_of` caches, and nothing ever invalidated an entry. A handle goes stale when the
    /// server restarts, the export is re-shared, or the file is replaced -- all ordinary
    /// events during a long copy -- and every later operation on that path then failed
    /// against a handle the server no longer honors, forever, because the cache kept
    /// handing back the same dead value.
    ///
    /// ONE retry: a second staleness on a freshly resolved handle is a server doing
    /// something a retry cannot fix, and looping on it turns a failure into a hang.
    fn retrying<T>(&self, rel: &str, mut op: impl FnMut(&[u8]) -> io::Result<T>) -> io::Result<T> {
        let fh = self.fh_of(rel)?;
        match op(&fh) {
            Err(e) if e.kind() == io::ErrorKind::StaleNetworkFileHandle => {
                crate::debug!(
                    self.shared.settings.log,
                    "nfs4 {rel}: the handle went stale -- looking the name up again"
                );
                self.forget(rel);
                let fresh = self.fh_of(rel)?;
                op(&fresh)
            }
            other => other,
        }
    }

    fn forget(&self, rel: &str) {
        let mut h = self.handles.lock().unwrap();
        let prefix = format!("{rel}/");
        h.retain(|k, _| k != rel && !k.starts_with(&prefix));
    }

    fn getattr(&self, fh: &[u8], what: &str) -> io::Result<Attrs> {
        let mut c = Compound::new();
        c.putfh(fh).getattr(&item_attr_bits());
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, what)?;
        ops.last().and_then(|o| o.decoded.clone()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: no attributes in the reply"),
            )
        })
    }

    fn readlink(&self, fh: &[u8], what: &str) -> io::Result<PathBuf> {
        let mut c = Compound::new();
        c.putfh(fh).readlink();
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, what)?;
        let text = ops.last().and_then(|o| o.data.clone()).unwrap_or_default();
        Ok(PathBuf::from(String::from_utf8_lossy(&text).into_owned()))
    }

    /// SETATTR with the anonymous stateid; `what` names the entry in errors.
    fn setattr(&self, fh: &[u8], attrs: &Attrs, what: &str) -> io::Result<()> {
        let mut c = Compound::new();
        c.putfh(fh).setattr(&Stateid::ANONYMOUS, attrs);
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, what)
    }

    /// Ownership as a SETATTR of its own, so a refusal (not root) does not take the mode
    /// and times with it; a server that wants names gets them on the retry.
    fn set_owner(
        &self,
        fh: &[u8],
        stateid: &Stateid,
        uid: u32,
        gid: u32,
        what: &str,
    ) -> io::Result<bool> {
        for _ in 0..2 {
            let attrs = Attrs {
                owner: Some(self.shared.owner_string(uid, true)),
                owner_group: Some(self.shared.owner_string(gid, false)),
                ..Default::default()
            };
            let mut c = Compound::new();
            c.putfh(fh).setattr(stateid, &attrs);
            let (status, ops) = self.compound(c)?;
            match status {
                NFS4_OK => return Ok(false),
                NFS4ERR_PERM | NFS4ERR_ACCESS => return Ok(true),
                NFS4ERR_BADOWNER if self.shared.numeric_owners.swap(false, Ordering::Relaxed) => {
                    continue
                }
                _ => return status_of(status, &ops, what).map(|_| false),
            }
        }
        Ok(true)
    }

    /// One directory's entries with their attributes and handles, following cookies.
    fn readdir(&self, conn: &mut Connection, dir: &[u8]) -> io::Result<Vec<DirEntry4>> {
        let mut out = Vec::new();
        let mut cookie = 0u64;
        let mut verf = [0u8; 8];
        loop {
            let dircount = self.shared.settings.dircount;
            let mut c = Compound::new();
            c.putfh(dir).readdir(
                cookie,
                &verf,
                dircount,
                dircount.saturating_mul(4).clamp(1 << 20, 8 << 20),
                &item_attr_bits(),
            );
            let reply = conn.call(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes())?;
            let (status, ops) = decode_compound(&reply)?;
            status_of(status, &ops, "directory")?;
            let r = ops
                .last()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "READDIR: no result"))?;
            verf = r.cookieverf;
            if let Some(last) = r.entries.last() {
                cookie = last.cookie;
            }
            let n = r.entries.len();
            out.extend(
                r.entries
                    .iter()
                    .filter(|e| e.name != "." && e.name != "..")
                    .cloned(),
            );
            if r.eof {
                self.shared.last_call.store(now_secs(), Ordering::Relaxed);
                return Ok(out);
            }
            // see the v3 reader: a page with no entries and no eof is an incomplete
            // listing, and returning it as a complete one let `sync` read the missing
            // entries as deletions. Measured there; the same shape, so the same refusal.
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the server answered a READDIR continuation with no entries and did not say the directory had ended, so this listing is incomplete",
                ));
            }
        }
    }

    /// OPEN on `dir`/`name` under a fresh open-owner: the stateid, the file's handle, and
    /// the owner's next sequence number, with a delegation returned at once and the open
    /// confirmed when the server asks. An expired client id is re-established once.
    fn open(
        &self,
        dir: &[u8],
        name: &str,
        access: u32,
        create: Option<&Attrs>,
        what: &str,
    ) -> io::Result<Open> {
        for attempt in 0..2 {
            let owner = self.shared.next_owner();
            let mut c = Compound::new();
            c.putfh(dir)
                .open(
                    0,
                    access,
                    self.shared.clientid.load(Ordering::Relaxed),
                    &owner,
                    name,
                    create,
                )
                .getfh();
            let (status, ops) = self.compound(c)?;
            if attempt == 0 && matches!(status, NFS4ERR_EXPIRED | NFS4ERR_STALE_CLIENTID) {
                self.shared.setclientid()?;
                continue;
            }
            status_of(status, &ops, what)?;
            let opened = ops.iter().find(|o| o.op == OP_OPEN).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{what}: no OPEN result"),
                )
            })?;
            let fh = ops.last().and_then(|o| o.fh.clone()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{what}: no handle after OPEN"),
                )
            })?;
            let mut stateid = opened.stateid.unwrap_or_default();
            let mut seqid = 1;
            if let Some(d) = opened.delegation {
                let mut c = Compound::new();
                c.putfh(&fh).delegreturn(&d);
                let _ = self.compound(c);
            }
            if opened.rflags & OPEN4_RESULT_CONFIRM != 0 {
                let mut c = Compound::new();
                c.putfh(&fh).open_confirm(&stateid, seqid);
                let (status, ops) = self.compound(c)?;
                status_of(status, &ops, &format!("{what}: OPEN_CONFIRM"))?;
                stateid = ops.last().and_then(|o| o.stateid).unwrap_or(stateid);
                seqid += 1;
            }
            return Ok(Open { fh, stateid, seqid });
        }
        unreachable!("the loop returns or errors")
    }
}

/// An open file: its handle, stateid, and the owner's sequence number for CLOSE.
struct Open {
    fh: Vec<u8>,
    stateid: Stateid,
    seqid: u32,
}

fn close(conn: &mut Connection, open: &Open) -> io::Result<()> {
    let mut c = Compound::new();
    c.putfh(&open.fh).close(open.seqid, &open.stateid);
    let (status, ops) =
        decode_compound(&conn.call(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes())?)?;
    status_of(status, &ops, "CLOSE")
}

pub struct Nfs4Reader {
    shared: Arc<Shared>,
    conn: Option<Connection>,
    open: Open,
    pos: u64,
    size: u64,
    rtmax: u32,
}

impl Drop for Nfs4Reader {
    fn drop(&mut self) {
        if let Some(mut c) = self.conn.take() {
            let _ = close(&mut c, &self.open);
            self.shared.pool.give(c);
        }
    }
}

impl Read for Nfs4Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(self.rtmax as usize)
            .min((self.size - self.pos) as usize) as u32;
        let conn = self.conn.as_mut().expect("open reader has a connection");
        let mut c = Compound::new();
        c.putfh(&self.open.fh)
            .read(&self.open.stateid, self.pos, want);
        let (status, ops) = decode_compound(&conn.call(
            NFS_PROG,
            NFS4_VERS,
            NFSPROC4_COMPOUND,
            &c.into_bytes(),
        )?)?;
        status_of(status, &ops, "READ")?;
        let data = ops.last().and_then(|o| o.data.clone()).unwrap_or_default();
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "read: {} bytes arrived for {} declared (the source changed during the copy)",
                    self.pos, self.size
                ),
            ));
        }
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Nfs4Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

pub struct Nfs4Sink {
    tree_shared: Arc<Shared>,
    conn: Option<Connection>,
    open: Option<Open>,
    rel: String,
    pos: u64,
    wtmax: u32,
    /// (xid, expected count) of UNSTABLE writes in flight.
    pending: VecDeque<(u32, u32)>,
    wrote_any: bool,
    /// Verifier from the first WRITE. A later WRITE or COMMIT with a different one means
    /// the server restarted and the unstable data is gone.
    write_verf: Option<[u8; 8]>,
    acl4: bool,
    numeric_owners: bool,
}

impl Nfs4Sink {
    fn reap_one(&mut self) -> io::Result<()> {
        let Some((xid, expect)) = self.pending.pop_front() else {
            return Ok(());
        };
        let conn = self.conn.as_mut().expect("open sink has a connection");
        let (status, ops) = decode_compound(&conn.recv(xid)?)?;
        status_of(status, &ops, &self.rel)?;
        let last = ops.last();
        let count = last.map(|o| o.count).unwrap_or(0);
        if count != expect {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("{}: short WRITE ({count} of {expect} bytes)", self.rel),
            ));
        }
        let verf = last.map(|o| o.verifier).unwrap_or_default();
        if let Some(prev) = self.write_verf {
            if prev != verf {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: NFS write verifier changed; the server may have restarted and dropped unstable data",
                        self.rel
                    ),
                ));
            }
        } else {
            self.write_verf = Some(verf);
        }
        Ok(())
    }
    fn drain(&mut self) -> io::Result<()> {
        while !self.pending.is_empty() {
            self.reap_one()?;
        }
        Ok(())
    }
    fn compound_here(&mut self, c: Compound, what: &str) -> io::Result<Vec<OpResult>> {
        let conn = self.conn.as_mut().expect("open sink has a connection");
        let (status, ops) = decode_compound(&conn.call(
            NFS_PROG,
            NFS4_VERS,
            NFSPROC4_COMPOUND,
            &c.into_bytes(),
        )?)?;
        status_of(status, &ops, what)?;
        Ok(ops)
    }
}

impl Drop for Nfs4Sink {
    fn drop(&mut self) {
        let _ = self.drain();
        if let Some(mut c) = self.conn.take() {
            if let Some(open) = &self.open {
                let _ = close(&mut c, open);
            }
            self.tree_shared.pool.give(c);
        }
    }
}

impl Sink for Nfs4Sink {
    fn reserve(&mut self, _len: u64) -> io::Result<()> {
        Ok(()) // the final SETATTR sets the length; unwritten ranges are holes on the server
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let open = self.open.as_ref().expect("open sink");
        let (fh, stateid) = (open.fh.clone(), open.stateid);
        for chunk in data.chunks(self.wtmax as usize) {
            if self.pending.len() >= WRITE_WINDOW {
                self.reap_one()?;
            }
            let mut c = Compound::new();
            c.putfh(&fh).write(&stateid, self.pos, UNSTABLE4, chunk);
            let conn = self.conn.as_mut().expect("open sink has a connection");
            let xid = conn.send(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes())?;
            self.pending.push_back((xid, chunk.len() as u32));
            self.pos += chunk.len() as u64;
            self.wrote_any = true;
        }
        Ok(())
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.pos += len;
        Ok(())
    }
    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        _fsync: bool,
    ) -> io::Result<Refusals> {
        self.drain()?;
        let rel = self.rel.clone();
        let (fh, stateid) = {
            let o = self.open.as_ref().expect("open sink");
            (o.fh.clone(), o.stateid)
        };
        if self.wrote_any {
            let mut c = Compound::new();
            c.putfh(&fh).commit(0, 0);
            let ops = self.compound_here(c, &format!("{rel}: COMMIT"))?;
            let verf = ops.last().map(|o| o.verifier).unwrap_or_default();
            if let Some(prev) = self.write_verf {
                if prev != verf {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{rel}: NFS commit verifier does not match the writes; the server may have restarted"
                        ),
                    ));
                }
            }
        }
        let mut refusals = Refusals::default();
        // size first (a truncate, under the open's stateid), then ownership, then the ACL,
        // then mode and times: chown clears setuid, and an ACL rewrites the group bits
        let mut c = Compound::new();
        c.putfh(&fh).setattr(
            &stateid,
            &Attrs {
                size: Some(self.pos),
                ..Default::default()
            },
        );
        self.compound_here(c, &format!("{rel}: SETATTR size"))?;
        if opts.owner {
            let owner_attrs = |numeric: bool| {
                let name = |id: u32, user: bool| {
                    if numeric {
                        id.to_string()
                    } else {
                        let domain = std::env::var("RCP_NFS4_DOMAIN")
                            .ok()
                            .filter(|d| !d.is_empty())
                            .or_else(|| self.tree_shared.domain.lock().unwrap().clone())
                            .unwrap_or_else(|| "localdomain".into());
                        format!(
                            "{}@{domain}",
                            if user {
                                names::user(id)
                            } else {
                                names::group(id)
                            }
                        )
                    }
                };
                Attrs {
                    owner: Some(name(item.uid, true)),
                    owner_group: Some(name(item.gid, false)),
                    ..Default::default()
                }
            };
            let mut numeric = self.numeric_owners;
            loop {
                let mut c = Compound::new();
                c.putfh(&fh).setattr(&stateid, &owner_attrs(numeric));
                let conn = self.conn.as_mut().expect("open sink has a connection");
                let (status, ops) = decode_compound(&conn.call(
                    NFS_PROG,
                    NFS4_VERS,
                    NFSPROC4_COMPOUND,
                    &c.into_bytes(),
                )?)?;
                match status {
                    NFS4_OK => break,
                    NFS4ERR_PERM | NFS4ERR_ACCESS => {
                        refusals.owner = true;
                        break;
                    }
                    NFS4ERR_BADOWNER if numeric => {
                        numeric = false;
                        self.tree_shared
                            .numeric_owners
                            .store(false, Ordering::Relaxed);
                    }
                    _ => status_of(status, &ops, &format!("{rel}: SETATTR owner"))?,
                }
            }
        }
        for (name, value) in xattrs {
            if name == ACL_NAME && self.acl4 {
                let mut c = Compound::new();
                c.putfh(&fh).setattr(
                    &stateid,
                    &Attrs {
                        acl: Some(value.clone()),
                        ..Default::default()
                    },
                );
                let conn = self.conn.as_mut().expect("open sink has a connection");
                let (status, ops) = decode_compound(&conn.call(
                    NFS_PROG,
                    NFS4_VERS,
                    NFSPROC4_COMPOUND,
                    &c.into_bytes(),
                )?)?;
                match status {
                    NFS4_OK => {}
                    NFS4ERR_PERM | NFS4ERR_ACCESS | NFS4ERR_ATTRNOTSUPP | NFS4ERR_NOTSUPP => {
                        refusals.xattrs.push(name.clone())
                    }
                    _ => status_of(status, &ops, &format!("{rel}: SETATTR acl"))?,
                }
            } else {
                refusals.xattrs.push(name.clone());
            }
        }
        let mut rest = Attrs::default();
        if opts.mode {
            rest.mode = Some(item.mode);
        }
        if opts.times {
            rest.time_modify_set = Some(Some(Time4::from_ns(item.mtime_ns)));
            rest.time_access_set = Some(Some(Time4::from_ns(if opts.atime {
                item.atime_ns
            } else {
                item.mtime_ns
            })));
        }
        if rest != Attrs::default() {
            let mut c = Compound::new();
            c.putfh(&fh).setattr(&stateid, &rest);
            self.compound_here(c, &format!("{rel}: SETATTR"))?;
        }
        if let Some(open) = self.open.take() {
            let conn = self.conn.as_mut().expect("open sink has a connection");
            close(conn, &open).map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        }
        Ok(refusals)
    }
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Tree for Nfs4Tree {
    type Reader = Nfs4Reader;
    type Sink = Nfs4Sink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        // a missing root is `NotFound`: a source that ends the run, a dry run's
        // destination that plans as empty
        let root_fh = self.fh_of(".")?;
        let root_attr = self.getattr(&root_fh, &self.display.display().to_string())?;
        let Some(root_item) = self.shared.item_from(".".to_string(), &root_attr, None) else {
            return Ok(Listing::unseen_root(self.root()));
        };
        if root_item.kind != Kind::Dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", self.display.display()),
            ));
        }
        let queue = Mutex::new(WalkQueue {
            dirs: vec![(".".to_string(), root_fh, 0)],
            in_flight: 0,
        });
        let wake = Condvar::new();
        let collected: Mutex<Listing> = Mutex::new(Listing {
            items: vec![root_item],
            errors: Vec::new(),
        });
        let now = crate::filter::now_ns();
        std::thread::scope(|scope| {
            for _ in 0..parallel.clamp(1, 32) {
                scope.spawn(|| {
                    let mut conn = match self.shared.pool.take() {
                        Ok(c) => c,
                        Err(e) => {
                            collected.lock().unwrap().errors.push(format!("{}: {e}", self.display.display()));
                            return;
                        }
                    };
                    let mut items: Vec<Item> = Vec::new();
                    let mut errors: Vec<String> = Vec::new();
                    loop {
                        let (rel, fh, depth) = {
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
                                    self.shared.pool.give(conn);
                                    return;
                                }
                                q = wake.wait(q).unwrap();
                            }
                        };
                        let mut subdirs = Vec::new();
                        match self.readdir(&mut conn, &fh) {
                            Ok(entries) => {
                                for e in entries {
                                    let child = if rel == "." { e.name.clone() } else { format!("{rel}/{}", e.name) };
                                    if let Some(err) = e.attrs.rdattr_error.filter(|s| *s != NFS4_OK) {
                                        errors.push(format!("{child}: {}", status_error(err, "attributes")));
                                        continue;
                                    }
                                    let Some(efh) = e.attrs.filehandle.clone() else {
                                        errors.push(format!("{child}: the server returned no file handle in READDIR"));
                                        continue;
                                    };
                                    let link_target = if e.attrs.ftype == Some(NF4LNK) {
                                        let mut c = Compound::new();
                                        c.putfh(&efh).readlink();
                                        match conn.call(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes()).and_then(|r| decode_compound(&r)) {
                                            Ok((NFS4_OK, ops)) => Some(PathBuf::from(String::from_utf8_lossy(&ops.last().and_then(|o| o.data.clone()).unwrap_or_default()).into_owned())),
                                            Ok((s, _)) => {
                                                errors.push(format!("{child}: {}", status_error(s, "READLINK")));
                                                continue;
                                            }
                                            Err(err) => {
                                                errors.push(format!("{child}: {err}"));
                                                continue;
                                            }
                                        }
                                    } else {
                                        None
                                    };
                                    let Some(item) = self.shared.item_from(child.clone(), &e.attrs, link_target) else {
                                        eprintln!("WARN: skipping special file {child}");
                                        continue;
                                    };
                                    let is_dir = item.kind == Kind::Dir;
                                    if !filter.allows(&item.rel, is_dir) {
                                        continue;
                                    }
                                    if item.kind == Kind::File && !filter.allows_file(item.size, item.mtime_ns, now) {
                                        continue;
                                    }
                                    if !is_dir && !filter.allows_owner_kind(item.kind, item.uid, item.gid, item.ino) {
                                        continue;
                                    }
                                    self.remember(&child, efh.clone());
                                    if is_dir && max_depth.is_none_or(|d| depth + 1 < d) {
                                        subdirs.push((child, efh, depth + 1));
                                    }
                                    items.push(item);
                                }
                            }
                            Err(e) => errors.push(format!("{rel}: {e}")),
                        }
                        let mut q = queue.lock().unwrap();
                        q.dirs.extend(subdirs);
                        q.in_flight -= 1;
                        wake.notify_all();
                    }
                });
            }
        });
        let mut listing = collected.into_inner().unwrap();
        listing.items.sort_by(|a, b| a.rel.cmp(&b.rel));
        listing.errors.sort();
        Ok(listing)
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        // through `retrying`, so a cached handle that went stale is looked up again rather
        // than reported as a failure for the rest of the run
        let got = self.retrying(rel, |fh| self.getattr(fh, rel).map(|a| (fh.to_vec(), a)));
        let (fh, attrs) = match got {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.forget(rel);
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let target = if attrs.ftype == Some(NF4LNK) {
            Some(self.readlink(&fh, rel)?)
        } else {
            None
        };
        Ok(self.shared.item_from(rel.to_string(), &attrs, target))
    }

    fn open(&self, rel: &str) -> io::Result<Nfs4Reader> {
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let open = self.open(&dir, &name, OPEN4_SHARE_ACCESS_READ, None, rel)?;
        let size = self.getattr(&open.fh, rel)?.size.unwrap_or(0);
        Ok(Nfs4Reader {
            shared: self.shared.clone(),
            conn: Some(self.shared.pool.take()?),
            open,
            pos: 0,
            size,
            rtmax: self.rtmax,
        })
    }

    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let open = self.open(&dir, &name, OPEN4_SHARE_ACCESS_READ, None, rel)?;
        let size = self.getattr(&open.fh, rel)?.size.unwrap_or(0);
        let chunk = (self.rtmax as usize).min(buf.len().max(4096)) as u32;
        let mut conn = self.shared.pool.take()?;
        let result = (|| {
            let mut pending: VecDeque<(u32, u64, u32)> = VecDeque::new();
            let mut next_off = 0u64;
            let mut pos = 0u64;
            while pos < size {
                while pending.len() < READ_WINDOW && next_off < size {
                    let want = chunk.min((size - next_off) as u32);
                    let mut c = Compound::new();
                    c.putfh(&open.fh).read(&open.stateid, next_off, want);
                    let xid = conn.send(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes())?;
                    pending.push_back((xid, next_off, want));
                    next_off += want as u64;
                }
                let Some((xid, off, want)) = pending.pop_front() else {
                    break;
                };
                let (status, ops) = decode_compound(&conn.recv(xid)?)?;
                status_of(status, &ops, rel)?;
                let (data, eof) = ops
                    .last()
                    .map(|o| (o.data.clone().unwrap_or_default(), o.eof))
                    .unwrap_or_default();
                if data.is_empty() || off != pos {
                    while let Some((xid, _, _)) = pending.pop_front() {
                        let _ = conn.recv(xid);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{rel}: {pos} bytes arrived for {size} declared (the source changed during the copy)"
                        ),
                    ));
                }
                if is_all_zero(&data) {
                    sink(Segment::Hole(data.len() as u64))?;
                } else {
                    sink(Segment::Data(&data))?;
                }
                pos += data.len() as u64;
                if eof {
                    if pos < size {
                        while let Some((xid, _, _)) = pending.pop_front() {
                            let _ = conn.recv(xid);
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{rel}: {pos} bytes arrived for {size} declared (the source changed during the copy)"
                            ),
                        ));
                    }
                    break;
                }
                // A short READ is legal and desynchronizes the pipeline: the next
                // request was already issued at `off + want`.
                if (data.len() as u32) < want {
                    while let Some((xid, _, _)) = pending.pop_front() {
                        let _ = conn.recv(xid);
                    }
                    next_off = pos;
                }
            }
            while let Some((xid, _, _)) = pending.pop_front() {
                let _ = conn.recv(xid);
            }
            Ok(())
        })();
        let closed = close(&mut conn, &open);
        self.shared.pool.give(conn);
        result.and(closed)
    }

    fn create_file(&self, item: &Item) -> io::Result<Nfs4Sink> {
        let rel = item.rel.as_str();
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let attrs = Attrs {
            mode: Some(0o600),
            size: Some(0),
            ..Default::default()
        };
        // A SYMLINK AT THE NAME IS REPLACED. OPEN never follows one -- it answers
        // NFS4ERR_SYMLINK (RFC 7530 16.16) -- so nothing is written through it, but left
        // alone the copy fails on every run and the link stays. What holds the name is asked
        // only after a refusal, so a plain create costs no extra round trip. A symlink or other
        // special file is removed by name, as the local tree, SFTP and v3 replace one; a
        // directory stays and the refusal stands. (v4.0: RFC 7530 answers SYMLINK for special
        // files too. 4.1 answers WRONG_TYPE, which this client does not speak.)
        let open = match self.open(&dir, &name, OPEN4_SHARE_ACCESS_WRITE, Some(&attrs), rel) {
            Ok(o) => o,
            // only on THAT refusal: any other -- GRACE, DELAY, a denied ADD_FILE -- says nothing
            // about what holds the name, and removing a link the retry then cannot replace
            // loses it
            Err(refused) if status_in(&refused) == Some(NFS4ERR_SYMLINK) => match self.stat(rel) {
                Ok(Some(i)) if i.kind != Kind::File && i.kind != Kind::Dir => {
                    self.forget(rel);
                    self.remove(rel, i.kind)?.cleared(rel)?;
                    self.open(&dir, &name, OPEN4_SHARE_ACCESS_WRITE, Some(&attrs), rel)?
                }
                _ => return Err(refused),
            },
            Err(e) => return Err(e),
        };
        self.remember(rel, open.fh.clone());
        Ok(Nfs4Sink {
            tree_shared: self.shared.clone(),
            conn: Some(self.shared.pool.take()?),
            open: Some(open),
            rel: rel.to_string(),
            pos: 0,
            wtmax: self.wtmax,
            pending: VecDeque::new(),
            wrote_any: false,
            write_verf: None,
            acl4: self.acl4,
            numeric_owners: self.shared.numeric_owners.load(Ordering::Relaxed),
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut Nfs4Sink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        if rel == "." {
            return Ok(());
        }
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let attrs = Attrs {
            mode: Some(0o700),
            ..Default::default()
        };
        let mut c = Compound::new();
        c.putfh(&dir).create_dir(&name, &attrs).getfh();
        let (status, ops) = self.compound(c)?;
        match status {
            NFS4_OK => {
                if let Some(fh) = ops.last().and_then(|o| o.fh.clone()) {
                    self.remember(rel, fh);
                }
                Ok(())
            }
            NFS4ERR_EXIST => match self.stat(rel)? {
                Some(i) if i.kind == Kind::Dir => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{rel}: exists and is not a directory"),
                )),
            },
            _ => status_of(status, &ops, rel),
        }
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        if let Some(existing) = self.stat(rel)? {
            if existing.kind == Kind::Symlink && existing.link_target.as_deref() == Some(target) {
                return Ok(());
            }
            self.remove(rel, existing.kind)?.cleared(rel)?;
        }
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let attrs = Attrs {
            mode: Some(0o777),
            ..Default::default()
        };
        let mut c = Compound::new();
        c.putfh(&dir)
            .create_symlink(&name, &target.to_string_lossy(), &attrs)
            .getfh();
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, rel)?;
        if let Some(fh) = ops.last().and_then(|o| o.fh.clone()) {
            self.remember(rel, fh);
        }
        Ok(())
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let file = self.fh_of(existing)?;
        let want = self.getattr(&file, existing)?.fileid;
        if let Some(cur) = self.stat(rel)? {
            if Some(cur.ino) == want {
                return Ok(());
            }
            self.remove(rel, cur.kind)?.cleared(rel)?;
        }
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let mut c = Compound::new();
        c.putfh(&file).savefh().putfh(&dir).link(&name);
        let (status, ops) = self.compound(c)?;
        status_of(status, &ops, rel)?;
        self.remember(rel, file);
        Ok(())
    }

    fn remove(&self, rel: &str, _kind: Kind) -> io::Result<Removed> {
        let (dir, name) = if rel == "." {
            if self.missing {
                return Ok(Removed::Gone);
            }
            match &self.root_parent {
                Some((fh, name)) => (fh.clone(), name.clone()),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "the export root itself cannot be removed; remove its contents",
                    ))
                }
            }
        } else {
            let (parent, name) = split(rel);
            // a parent that is already gone is the end state asked for, as v3 answers
            let dir = match self.fh_of(&parent) {
                Ok(d) => d,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removed::Gone),
                Err(e) => return Err(e),
            };
            (dir, name)
        };
        let mut c = Compound::new();
        c.putfh(&dir).remove(&name);
        let (status, ops) = self.compound(c)?;
        self.forget(rel);
        match status {
            NFS4_OK | NFS4ERR_NOENT => Ok(Removed::Gone),
            // NFS4ERR_ACCES / NFS4ERR_PERM: the server answered and refused THIS OBJECT.
            // An RPC-level rejection of the CALL never reaches here -- `self.compound(c)?`
            // returns it first -- so `or_refused` only ever sees a COMPOUND status. Same
            // reasoning as the v3 client; the arm that measured it is in the contract
            // suite.
            _ => match status_of(status, &ops, rel) {
                Ok(()) => Ok(Removed::Gone),
                Err(e) => Removed::or_refused(e),
            },
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (fparent, fname) = split(from);
        let (tparent, tname) = split(to);
        let fdir = self.fh_of(&fparent)?;
        let tdir = self.fh_of(&tparent)?;
        let mut c = Compound::new();
        c.putfh(&fdir).savefh().putfh(&tdir).rename(&fname, &tname);
        let (status, ops) = self.compound(c)?;
        self.forget(from);
        self.forget(to);
        status_of(status, &ops, &format!("{from} -> {to}"))
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let fh = self.fh_of(rel)?;
        let mut refusals = Refusals::default();
        if opts.owner {
            refusals.owner = self.set_owner(&fh, &Stateid::ANONYMOUS, item.uid, item.gid, rel)?;
        }
        if item.kind != Kind::Symlink {
            let mut rest = Attrs::default();
            if opts.mode {
                rest.mode = Some(item.mode);
            }
            if opts.times {
                rest.time_modify_set = Some(Some(Time4::from_ns(item.mtime_ns)));
                rest.time_access_set = Some(Some(Time4::from_ns(if opts.atime {
                    item.atime_ns
                } else {
                    item.mtime_ns
                })));
            }
            if rest != Attrs::default() {
                self.setattr(&fh, &rest, rel)?;
            }
        }
        Ok(refusals)
    }

    /// NFSv4 has no extended attributes in this version, and POSIX ACLs live in the v3-side
    /// NFSACL program; with `-acl4` the NFSv4 ACL is the one attribute carried.
    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        if !self.acl4 {
            return Ok(Vec::new());
        }
        let Some(item) = self.stat(rel)? else {
            return Ok(Vec::new());
        };
        if item.kind == Kind::Symlink {
            return Ok(Vec::new());
        }
        let fh = self.fh_of(rel)?;
        let mut c = Compound::new();
        c.putfh(&fh).getattr_acl();
        let (status, ops) = self.compound(c)?;
        match status {
            NFS4_OK => Ok(ops
                .last()
                .and_then(|o| o.attrs.clone())
                .map(|a| vec![(ACL_NAME.to_string(), a)])
                .unwrap_or_default()),
            NFS4ERR_ATTRNOTSUPP | NFS4ERR_NOTSUPP => Ok(Vec::new()),
            _ => status_of(status, &ops, &format!("{rel}: GETATTR acl")).map(|_| Vec::new()),
        }
    }

    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        let mut refused = Vec::new();
        for (name, value) in attrs {
            if name != ACL_NAME || !self.acl4 {
                refused.push(name.clone());
                continue;
            }
            let fh = self.fh_of(rel)?;
            let mut c = Compound::new();
            c.putfh(&fh).setattr_acl(value);
            let (status, ops) = self.compound(c)?;
            match status {
                NFS4_OK => {}
                NFS4ERR_PERM | NFS4ERR_ACCESS | NFS4ERR_ATTRNOTSUPP | NFS4ERR_NOTSUPP => {
                    refused.push(name.clone())
                }
                _ => status_of(status, &ops, &format!("{rel}: SETATTR acl"))?,
            }
        }
        Ok(refused)
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        let fh = self.fh_of(&item.rel)?;
        self.setattr(
            &fh,
            &Attrs {
                time_access_set: Some(Some(Time4::from_ns(item.atime_ns))),
                ..Default::default()
            },
            &item.rel,
        )
    }

    fn sync(&self) -> io::Result<()> {
        Ok(()) // every file was committed when it finished
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
            "no server-side copy in NFSv4.0",
        ))
    }
}
