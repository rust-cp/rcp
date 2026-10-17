//! `NfsTree`: the `Tree` port over the NFSv3 client. A pool of TCP connections is shared by
//! the worker threads; every reader and sink borrows one while it is open. Reads and writes
//! are pipelined: a reader keeps several READs in flight ahead of the consumer and a sink
//! keeps a window of UNSTABLE WRITEs in flight, committed once at the end, which is where
//! a userspace client beats a kernel mount on a filer.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use super::acl;
use super::proto::*;

/// How long to wait between retries of a request the server answered `NFS3ERR_JUKEBOX`,
/// and how many times. Bounded so a file that never comes back fails by name rather than
/// hanging the copy.
const RETRY_WAITS: &[std::time::Duration] = &[
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(400),
    std::time::Duration::from_millis(1600),
    std::time::Duration::from_millis(3000),
];
use super::rpc::{self, Connection, Credentials, Security, MOUNT_PROG, NFS_PROG};
use super::v4::{self, V4};
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::tree::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree,
};

const READ_WINDOW: usize = 8;
const WRITE_WINDOW: usize = 16;

/// Connections to one server, handed out to whoever needs one and returned afterwards.
pub struct Pool {
    /// The server's addresses (`ip1,ip2:/export`): connections rotate across them and a
    /// refused address is skipped, so several interfaces of one filer share the load.
    hosts: Vec<String>,
    next_host: AtomicUsize,
    port: u16,
    creds: Credentials,
    /// The security every connection is opened with, and the program whose NULL
    /// procedure carries the Kerberos context establishment.
    sec: Security,
    prog: u32,
    vers: u32,
    idle: Mutex<Vec<Connection>>,
}

impl Pool {
    pub(super) fn new(
        hosts: Vec<String>,
        port: u16,
        creds: Credentials,
        sec: Security,
        prog: u32,
        vers: u32,
    ) -> Pool {
        Pool {
            hosts,
            next_host: AtomicUsize::new(0),
            port,
            creds,
            sec,
            prog,
            vers,
            idle: Mutex::new(Vec::new()),
        }
    }
    pub(super) fn take(&self) -> io::Result<Connection> {
        if let Some(c) = self.idle.lock().unwrap().pop() {
            return Ok(c);
        }
        let start = self.next_host.fetch_add(1, Ordering::Relaxed);
        let mut last = None;
        for i in 0..self.hosts.len() {
            let host = &self.hosts[(start + i) % self.hosts.len()];
            match Connection::connect_secure(
                (host.as_str(), self.port),
                self.creds.clone(),
                self.sec,
                host,
                self.prog,
                self.vers,
            ) {
                Ok(c) => return Ok(c),
                Err(e) => {
                    last = Some(io::Error::new(
                        e.kind(),
                        format!("{host}:{}: {e}", self.port),
                    ))
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no server address")))
    }
    pub(super) fn give(&self, c: Connection) {
        if c.inflight == 0 {
            self.idle.lock().unwrap().push(c);
        }
    }
    /// Runs `f` with a pooled connection.
    pub(super) fn with<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut c = self.take()?;
        let r = f(&mut c);
        self.give(c);
        r
    }
}

pub struct NfsTree {
    pool: Arc<Pool>,
    root_fh: Fh,
    /// The directory holding the root and the root's name there, when the root is a path
    /// inside the export (`delete -removetopdir` needs it); `None` at the export root.
    root_parent: Option<(Fh, String)>,
    /// Set when the root does not exist and was not to be created: a dry run's
    /// destination that is still to be made, or a source that is not there. `root_fh` is
    /// then the deepest ANCESTOR that resolved, and nothing may use it as the root --
    /// `fh_of(".")` answers `NotFound`, so a listing reads as a missing root and every
    /// other call fails or reports `Gone` rather than acting on the wrong directory.
    missing: bool,
    display: PathBuf,
    rtmax: u32,
    wtmax: u32,
    handles: Mutex<BTreeMap<String, Fh>>,
    /// Connections for the NFSACL program: the NFS pool itself when the server has it on
    /// the NFS port (Linux and ONTAP do), a pool of its own when the portmapper puts it
    /// elsewhere, `None` when the server does not serve it, in which case ACLs are
    /// reported as refused attributes.
    acl: Option<Arc<Pool>>,
    settings: super::Settings,
    /// The NFSv4 sidecar for `-acl4`: NFSv4 ACLs as `system.nfs4_acl`.
    v4: Option<Arc<V4>>,
}

/// Which ACLs GETACL is asked for: a directory has a default ACL too.
fn acl_mask(kind: Kind) -> u32 {
    match kind {
        Kind::Dir => acl::NFS_ACL | acl::NFS_ACLCNT | acl::NFS_DFACL | acl::NFS_DFACLCNT,
        _ => acl::NFS_ACL | acl::NFS_ACLCNT,
    }
}

/// The ACLs of `fh` as the attributes the local side would list: the access ACL only when
/// it says more than the mode, the default ACL when there is one.
fn get_acls(pool: &Pool, fh: &Fh, kind: Kind) -> io::Result<Vec<(String, Vec<u8>)>> {
    let reply = pool.with(|c| {
        c.call(
            acl::NFSACL_PROG,
            acl::NFSACL_VERS,
            acl::ACLPROC_GETACL,
            &acl::args_getacl(fh, acl_mask(kind)),
        )
    })?;
    let (access, default) = acl::res_getacl(&reply)?;
    let mut out = Vec::new();
    if acl::is_extended(&access) {
        out.push((acl::ACCESS_NAME.to_string(), acl::to_xattr(&access)));
    }
    if kind == Kind::Dir && !default.is_empty() {
        out.push((acl::DEFAULT_NAME.to_string(), acl::to_xattr(&default)));
    }
    Ok(out)
}

/// Sets the ACL attributes among `attrs` on `fh` (`rel` on the v4 side): the POSIX ones
/// with one SETACL, the NFSv4 one with a SETATTR through the `-acl4` sidecar. Every other
/// name, and an ACL name the server has no program or version for, comes back as refused.
fn set_acls(
    pool: Option<&Pool>,
    v4: Option<&V4>,
    fh: &Fh,
    rel: &str,
    attrs: &[(String, Vec<u8>)],
) -> io::Result<Vec<String>> {
    let mut refused: Vec<String> = attrs
        .iter()
        .filter(|(n, _)| !acl::is_acl_name(n) && n != v4::ACL_NAME)
        .map(|(n, _)| n.clone())
        .collect();
    if let Some((_, bytes)) = attrs.iter().find(|(n, _)| n == v4::ACL_NAME) {
        match v4 {
            None => refused.push(v4::ACL_NAME.to_string()),
            Some(v4) => match v4.set_acl(rel, bytes) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                    ) =>
                {
                    refused.push(v4::ACL_NAME.to_string())
                }
                Err(e) => return Err(io::Error::new(e.kind(), format!("NFSv4 {e}"))),
            },
        }
    }
    let acl_names: Vec<&str> = attrs
        .iter()
        .filter(|(n, _)| acl::is_acl_name(n))
        .map(|(n, _)| n.as_str())
        .collect();
    if acl_names.is_empty() {
        return Ok(refused);
    }
    let Some(pool) = pool else {
        refused.extend(acl_names.iter().map(|n| n.to_string()));
        return Ok(refused);
    };
    let mut mask = 0;
    let mut access = Vec::new();
    let mut default = Vec::new();
    for (name, value) in attrs {
        if name == acl::ACCESS_NAME {
            access = acl::from_xattr(value)?;
            mask |= acl::NFS_ACL;
        } else if name == acl::DEFAULT_NAME {
            default = acl::from_xattr(value)?;
            mask |= acl::NFS_DFACL;
        }
    }
    let args = acl::args_setacl(fh, mask, &access, &default)?;
    match pool
        .with(|c| {
            c.call(
                acl::NFSACL_PROG,
                acl::NFSACL_VERS,
                acl::ACLPROC_SETACL,
                &args,
            )
        })
        .and_then(|r| acl::res_setacl(&r))
    {
        Ok(()) => {}
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) =>
        {
            refused.extend(acl_names.iter().map(|n| n.to_string()))
        }
        Err(e) => return Err(io::Error::new(e.kind(), format!("SETACL: {e}"))),
    }
    Ok(refused)
}

fn kind_of(ftype: u32) -> Option<Kind> {
    match ftype {
        NF3REG => Some(Kind::File),
        NF3DIR => Some(Kind::Dir),
        NF3LNK => Some(Kind::Symlink),
        _ => None,
    }
}

fn item_from(rel: String, a: &Fattr3, link_target: Option<PathBuf>) -> Option<Item> {
    let kind = kind_of(a.ftype)?;
    Some(Item {
        rel,
        kind,
        size: if kind == Kind::File { a.size } else { 0 },
        mtime_ns: a.mtime.ns(),
        atime_ns: a.atime.ns(),
        mode: a.mode & 0o7777,
        uid: a.uid,
        gid: a.gid,
        dev: a.fsid,
        ino: a.fileid,
        nlink: a.nlink as u64,
        blocks: a.used,
        link_target,
    })
}

fn split(rel: &str) -> (String, String) {
    match rel.rsplit_once('/') {
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => (".".to_string(), rel.to_string()),
    }
}

impl NfsTree {
    /// Mounts `export` on `host` (over the wire: the MOUNT protocol, no root needed) and
    /// resolves `sub` inside it, creating missing components when `create` is set (a copy
    /// destination). Ports come from the portmapper unless `RCP_NFS_PORT` and
    /// `RCP_MOUNT_PORT` say otherwise, which is how the stand-in server is reached.
    pub fn connect(
        host: &str,
        export: &str,
        sub: &Path,
        create: bool,
        settings: &super::Settings,
    ) -> io::Result<NfsTree> {
        let creds = Credentials::current();
        let log = settings.log.clone();
        let env_port = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u16>().ok());
        let hosts: Vec<String> = host
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .collect();
        // the mount goes through whichever address answers first; the pool then rotates
        let mut chosen = None;
        let mut last = io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host}: no server address"),
        );
        for h in &hosts {
            let attempt = (|| -> io::Result<(Connection, u16, u16)> {
                let mount_port = match env_port("RCP_MOUNT_PORT") {
                    Some(p) => p,
                    None => rpc::getport(h, MOUNT_PROG, MOUNT_VERS)
                        .map_err(|e| io::Error::new(e.kind(), format!("{h}: mountd: {e}")))?,
                };
                let nfs_port = match env_port("RCP_NFS_PORT") {
                    Some(p) => p,
                    None => rpc::getport(h, NFS_PROG, NFS_VERS).unwrap_or(2049),
                };
                // mountd with the same security as the export; a mountd that will not
                // take Kerberos (its exports may be AUTH_SYS for MNT alone) gets AUTH_SYS
                let sec = settings.sec;
                let m = match Connection::connect_secure(
                    (h.as_str(), mount_port),
                    creds.clone(),
                    sec,
                    h,
                    MOUNT_PROG,
                    MOUNT_VERS,
                ) {
                    Ok(m) => m,
                    Err(e)
                        if sec != Security::Sys && e.kind() != io::ErrorKind::PermissionDenied =>
                    {
                        crate::debug!(
                            log,
                            "nfs {h}: mountd did not take {} ({e}); trying AUTH_SYS for the mount",
                            sec.name()
                        );
                        Connection::connect((h.as_str(), mount_port), creds.clone()).map_err(
                            |e| io::Error::new(e.kind(), format!("{h}:{mount_port} (mountd): {e}")),
                        )?
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("{h}:{mount_port} (mountd): {e}"),
                        ))
                    }
                };
                Ok((m, mount_port, nfs_port))
            })();
            match attempt {
                Ok(v) => {
                    chosen = Some(v);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let Some((mut m, mount_port, nfs_port)) = chosen else {
            return Err(last);
        };
        let export_fh =
            res_mnt(&m.call(MOUNT_PROG, MOUNT_VERS, MOUNTPROC_MNT, &args_mnt(export))?)
                .map_err(|e| io::Error::new(e.kind(), format!("{host}:{export}: {e}")))?;
        let sec = settings.sec;
        let pool = Arc::new(Pool::new(
            hosts.clone(),
            nfs_port,
            creds.clone(),
            sec,
            NFS_PROG,
            NFS_VERS,
        ));
        let (rtmax, wtmax) = pool
            .with(|c| {
                res_fsinfo(&c.call(NFS_PROG, NFS_VERS, NFSPROC_FSINFO, &args_fh(&export_fh))?)
            })
            .unwrap_or((65_536, 65_536));
        // NFSACL: `RCP_NFSACL_PORT`, else the NFS port when a NULL call is accepted there,
        // else wherever the portmapper says; a server without it gets no ACL calls at all
        let acl_pool = match env_port("RCP_NFSACL_PORT") {
            Some(p) if p == nfs_port => Some(pool.clone()),
            Some(p) => Some(Arc::new(Pool::new(
                hosts.clone(),
                p,
                creds.clone(),
                sec,
                acl::NFSACL_PROG,
                acl::NFSACL_VERS,
            ))),
            None => {
                if pool
                    .with(|c| c.call(acl::NFSACL_PROG, acl::NFSACL_VERS, acl::ACLPROC_NULL, &[]))
                    .is_ok()
                {
                    Some(pool.clone())
                } else {
                    hosts
                        .iter()
                        .find_map(|h| rpc::getport(h, acl::NFSACL_PROG, acl::NFSACL_VERS).ok())
                        .map(|p| {
                            if p == nfs_port {
                                pool.clone()
                            } else {
                                Arc::new(Pool::new(
                                    hosts.clone(),
                                    p,
                                    creds.clone(),
                                    sec,
                                    acl::NFSACL_PROG,
                                    acl::NFSACL_VERS,
                                ))
                            }
                        })
                }
            }
        };
        // -acl4: the v4 sidecar, walked to the export before anything is created below it;
        // a server without v4 is refused up front rather than dropping what was asked for
        let v4 = if settings.acl4 {
            Some(Arc::new(V4::connect(pool.clone(), export, sub).map_err(
                |e| io::Error::new(e.kind(), format!("-acl4: {host}:{export}: {e}")),
            )?))
        } else {
            None
        };
        let mut root_fh = export_fh;
        let mut root_parent = None;
        let mut missing = false;
        for comp in sub.components() {
            if missing {
                break;
            }
            if let std::path::Component::Normal(name) = comp {
                let name = name.to_string_lossy();
                let looked_up = pool.with(|c| {
                    res_lookup(&c.call(
                        NFS_PROG,
                        NFS_VERS,
                        NFSPROC_LOOKUP,
                        &args_diropargs(&root_fh, &name),
                    )?)
                    .map(|(fh, _)| fh)
                });
                root_parent = Some((root_fh.clone(), name.to_string()));
                root_fh = match looked_up {
                    Ok(fh) => fh,
                    Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                        let attrs = Sattr3 {
                            mode: Some(0o700),
                            ..Default::default()
                        };
                        let made = pool.with(|c| {
                            res_create(
                                &c.call(
                                    NFS_PROG,
                                    NFS_VERS,
                                    NFSPROC_MKDIR,
                                    &args_mkdir(&root_fh, &name, &attrs),
                                )?,
                                "MKDIR",
                            )
                        });
                        match made {
                            Ok((Some(fh), _)) => fh,
                            Ok((None, _)) => pool.with(|c| {
                                res_lookup(&c.call(
                                    NFS_PROG,
                                    NFS_VERS,
                                    NFSPROC_LOOKUP,
                                    &args_diropargs(&root_fh, &name),
                                )?)
                                .map(|(fh, _)| fh)
                            })?,
                            Err(e) => {
                                return Err(io::Error::new(
                                    e.kind(),
                                    format!("{host}:{export}:{}: {e}", sub.display()),
                                ))
                            }
                        }
                    }
                    // Not refused when it is not to be created, which is how a dry run
                    // opens its destination: a directory that does not exist yet is an
                    // empty one to plan against, as it is on every other transport. The
                    // walk STOPS here -- a later component cannot exist below a missing
                    // one, and continuing would resolve names against the ancestor.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        missing = true;
                        root_fh.clone()
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("{host}:{export}:{}: {e}", sub.display()),
                        ))
                    }
                };
            }
        }
        let display = if sub == Path::new("/") {
            format!("{host}:{export}")
        } else {
            format!("{host}:{export}:{}", sub.display())
        };
        crate::debug!(
            log,
            "nfs {display}: mount port {mount_port}, nfs port {nfs_port}, sec {}, rtmax {rtmax}, wtmax {wtmax}, dircount {}, nfsacl {}, v4 {}",
            sec.name(),
            settings.dircount,
            acl_pool.as_ref().map(|p| format!("port {}", p.port)).unwrap_or_else(|| "none".into()),
            if v4.is_some() { "on" } else { "off" }
        );
        Ok(NfsTree {
            pool,
            root_fh,
            root_parent,
            missing,
            display: PathBuf::from(display),
            rtmax: rtmax.clamp(4096, 1 << 20),
            wtmax: wtmax.clamp(4096, 1 << 20),
            handles: Mutex::new(BTreeMap::new()),
            acl: acl_pool,
            v4,
            settings: settings.clone(),
        })
    }

    fn call(&self, proc_: u32, args: &[u8]) -> io::Result<Vec<u8>> {
        // RETRIED on `NFS3ERR_JUKEBOX`, which nothing retried. The status means the server
        // is fetching the file from slow storage and the client should ask again shortly;
        // it is the one v3 status that is transient by definition, and it failed the copy
        // of that file. Every v3 procedure answers with its status in the first four bytes
        // of the body, so one place covers all of them.
        let mut reply = self
            .pool
            .with(|c| c.call(NFS_PROG, NFS_VERS, proc_, args))?;
        for wait in RETRY_WAITS {
            let status = reply
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            if status != Some(NFS3ERR_JUKEBOX) {
                break;
            }
            crate::debug!(
                self.settings.log,
                "nfs: the server is retrieving the file -- waiting {}ms and asking again",
                wait.as_millis()
            );
            std::thread::sleep(*wait);
            reply = self
                .pool
                .with(|c| c.call(NFS_PROG, NFS_VERS, proc_, args))?;
        }
        Ok(reply)
    }

    /// The handle for `rel`, resolved component by component and cached.
    fn fh_of(&self, rel: &str) -> io::Result<Fh> {
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
        let (fh, _) = res_lookup(&self.call(NFSPROC_LOOKUP, &args_diropargs(&dir, &name))?)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", rel)))?;
        self.handles
            .lock()
            .unwrap()
            .insert(rel.to_string(), fh.clone());
        Ok(fh)
    }

    fn remember(&self, rel: &str, fh: Fh) {
        self.handles.lock().unwrap().insert(rel.to_string(), fh);
    }

    /// Runs `op` with the handle for `rel`; on a STALE handle, drops the cached entry and
    /// runs it once more against a freshly resolved one.
    ///
    /// `fh_of` caches and nothing ever invalidated an entry. A handle goes stale when the
    /// server restarts, the export is re-shared, or the file is replaced -- ordinary events
    /// during a long copy -- and every later operation on that path then failed against a
    /// handle the server no longer honors, forever, because the cache kept handing back the
    /// same dead value. ONE retry: a second staleness on a fresh handle is not something a
    /// retry can fix, and looping on it turns a failure into a hang.
    fn retrying<T>(&self, rel: &str, mut op: impl FnMut(&Fh) -> io::Result<T>) -> io::Result<T> {
        let fh = self.fh_of(rel)?;
        match op(&fh) {
            Err(e) if e.kind() == io::ErrorKind::StaleNetworkFileHandle => {
                crate::debug!(
                    self.settings.log,
                    "nfs {rel}: the handle went stale -- looking the name up again"
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
        if let Some(v4) = &self.v4 {
            v4.forget(rel);
        }
    }

    fn getattr(&self, fh: &Fh) -> io::Result<Fattr3> {
        res_getattr(&self.call(NFSPROC_GETATTR, &args_fh(fh))?)
    }

    fn readlink(&self, fh: &Fh) -> io::Result<PathBuf> {
        res_readlink(&self.call(NFSPROC_READLINK, &args_fh(fh))?).map(PathBuf::from)
    }

    fn setattr(&self, fh: &Fh, attrs: &Sattr3, what: &str) -> io::Result<()> {
        res_setattr(&self.call(NFSPROC_SETATTR, &args_setattr(fh, attrs))?)
            .map_err(|e| io::Error::new(e.kind(), format!("{what}: {e}")))
    }

    /// One directory's entries with their handles, following READDIRPLUS cookies.
    fn readdir(&self, conn: &mut Connection, dir: &Fh) -> io::Result<Vec<DirEntry>> {
        let mut out = Vec::new();
        let (mut cookie, mut verf) = (0u64, 0u64);
        loop {
            let dircount = self.settings.dircount;
            let reply = conn.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_READDIRPLUS,
                &args_readdirplus(
                    dir,
                    cookie,
                    verf,
                    dircount,
                    dircount.saturating_mul(4).clamp(1 << 20, 8 << 20),
                ),
            )?;
            let (entries, eof, v) = res_readdirplus(&reply)?;
            verf = v;
            if let Some(last) = entries.last() {
                cookie = last.cookie;
            }
            let n = entries.len();
            out.extend(
                entries
                    .into_iter()
                    .filter(|e| e.name != "." && e.name != ".."),
            );
            if eof {
                return Ok(out);
            }
            // A PAGE WITH NO ENTRIES AND NO EOF IS NOT THE END OF THE DIRECTORY. Returning
            // `Ok(out)` on `n == 0` -- a clean, complete listing as far as every caller can
            // tell -- lets a server that answers a continuation with zero entries truncate
            // the listing SILENTLY. Measured against a stand-in patched to do exactly that:
            // `sync: 0 files, 3 skipped, 5 removed ... STATUS: PASSED`, five destination
            // files destroyed, exit 0.
            //
            // `copy_tree` has a guard for this shape -- it plans no removals when the
            // source listing reported an error -- and it cannot fire, because a zero-entry
            // page produces no error to report. An incomplete listing has to SAY it is
            // incomplete, or every guard downstream is reasoning about a lie.
            //
            // RFC 1813 says a server that cannot return even one entry answers
            // NFS3ERR_TOOSMALL, which this client already turns into an error. So this
            // needs a non-conforming or degraded server -- and the point is that there was
            // no defense, and the failure mode was deletion rather than a short read.
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the server answered a READDIRPLUS continuation with no entries and did not say the directory had ended, so this listing is incomplete",
                ));
            }
        }
    }
}

struct WalkQueue {
    dirs: Vec<(String, Fh, usize)>,
    in_flight: usize,
}

pub struct NfsReader {
    pool: Arc<Pool>,
    conn: Option<Connection>,
    fh: Fh,
    pos: u64,
    size: u64,
    rtmax: u32,
}

impl Drop for NfsReader {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take() {
            self.pool.give(c);
        }
    }
}

impl Read for NfsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(self.rtmax as usize)
            .min((self.size - self.pos) as usize) as u32;
        let conn = self.conn.as_mut().expect("open reader has a connection");
        let (data, _eof) = res_read(&conn.call(
            NFS_PROG,
            NFS_VERS,
            NFSPROC_READ,
            &args_read(&self.fh, self.pos, want),
        )?)?;
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

impl Seek for NfsReader {
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

pub struct NfsSink {
    pool: Arc<Pool>,
    conn: Option<Connection>,
    fh: Fh,
    pos: u64,
    wtmax: u32,
    /// (xid, expected count) of UNSTABLE writes in flight.
    pending: VecDeque<(u32, u32)>,
    wrote_any: bool,
    /// Verifier from the first WRITE. A later WRITE or COMMIT with a different one means
    /// the server restarted and the unstable data is gone.
    write_verf: Option<u64>,
    acl: Option<Arc<Pool>>,
    v4: Option<Arc<V4>>,
}

impl NfsSink {
    fn reap_one(&mut self) -> io::Result<()> {
        let Some((xid, expected)) = self.pending.pop_front() else {
            return Ok(());
        };
        let conn = self.conn.as_mut().expect("open sink has a connection");
        let (count, _committed, verf) = res_write(&conn.recv(xid)?)?;
        if count != expected {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short NFS write: {count} of {expected} bytes"),
            ));
        }
        if let Some(prev) = self.write_verf {
            if prev != verf {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NFS write verifier changed; the server may have restarted and dropped unstable data",
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
}

impl Drop for NfsSink {
    fn drop(&mut self) {
        let _ = self.drain();
        if let Some(c) = self.conn.take() {
            self.pool.give(c);
        }
    }
}

impl Sink for NfsSink {
    fn reserve(&mut self, _len: u64) -> io::Result<()> {
        Ok(()) // the final SETATTR sets the length; unwritten ranges are holes on the server
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(self.wtmax as usize) {
            if self.pending.len() >= WRITE_WINDOW {
                self.reap_one()?;
            }
            let conn = self.conn.as_mut().expect("open sink has a connection");
            let xid = conn.send(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_WRITE,
                &args_write(&self.fh, self.pos, UNSTABLE, chunk),
            )?;
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
        let conn = self.conn.as_mut().expect("open sink has a connection");
        if self.wrote_any {
            let verf = res_commit(&conn.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_COMMIT,
                &args_commit(&self.fh, 0, 0),
            )?)?;
            if let Some(prev) = self.write_verf {
                if prev != verf {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NFS commit verifier does not match the writes; the server may have restarted",
                    ));
                }
            }
        }
        let mut refusals = Refusals::default();
        // size first (a truncate), then ownership, then the ACL, then mode and times: chown
        // clears setuid, and an ACL rewrites the group bits so the mode must land after it
        let size = Sattr3 {
            size: Some(self.pos),
            ..Default::default()
        };
        res_setattr(&conn.call(
            NFS_PROG,
            NFS_VERS,
            NFSPROC_SETATTR,
            &args_setattr(&self.fh, &size),
        )?)?;
        if opts.owner {
            let own = Sattr3 {
                uid: Some(item.uid),
                gid: Some(item.gid),
                ..Default::default()
            };
            match res_setattr(&conn.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_SETATTR,
                &args_setattr(&self.fh, &own),
            )?) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                Err(e) => return Err(e),
            }
        }
        if !xattrs.is_empty() {
            refusals.xattrs = set_acls(
                self.acl.as_deref(),
                self.v4.as_deref(),
                &self.fh,
                &item.rel,
                xattrs,
            )?;
        }
        let mut rest = Sattr3::default();
        if opts.mode {
            rest.mode = Some(item.mode);
        }
        if opts.times {
            rest.mtime = SetTime::Client(Time3::from_ns(item.mtime_ns));
            rest.atime = SetTime::Client(Time3::from_ns(if opts.atime {
                item.atime_ns
            } else {
                item.mtime_ns
            }));
        }
        if rest != Sattr3::default() {
            res_setattr(&conn.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_SETATTR,
                &args_setattr(&self.fh, &rest),
            )?)?;
        }
        Ok(refusals)
    }
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Tree for NfsTree {
    type Reader = NfsReader;
    type Sink = NfsSink;

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
        let root_attr = self.getattr(&root_fh)?;
        let Some(root_item) = item_from(".".to_string(), &root_attr, None) else {
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
                    let mut conn = match self.pool.take() {
                        Ok(c) => c,
                        Err(e) => {
                            collected
                                .lock()
                                .unwrap()
                                .errors
                                .push(format!("{}: {e}", self.display.display()));
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
                                    self.pool.give(conn);
                                    return;
                                }
                                q = wake.wait(q).unwrap();
                            }
                        };
                        let mut subdirs = Vec::new();
                        match self.readdir(&mut conn, &fh) {
                            Ok(entries) => {
                                for e in entries {
                                    let child = if rel == "." {
                                        e.name.clone()
                                    } else {
                                        format!("{rel}/{}", e.name)
                                    };
                                    let (attrs, efh) = match (e.attrs, e.fh) {
                                        (Some(a), Some(f)) => (a, f),
                                        (a, f) => {
                                            // a server that omits them gets asked
                                            let f = match f {
                                                Some(f) => f,
                                                None => match conn
                                                    .call(
                                                        NFS_PROG,
                                                        NFS_VERS,
                                                        NFSPROC_LOOKUP,
                                                        &args_diropargs(&fh, &e.name),
                                                    )
                                                    .and_then(|r| res_lookup(&r))
                                                {
                                                    Ok((f, _)) => f,
                                                    Err(err) => {
                                                        errors.push(format!("{child}: {err}"));
                                                        continue;
                                                    }
                                                },
                                            };
                                            let a = match a {
                                                Some(a) => a,
                                                None => match conn
                                                    .call(
                                                        NFS_PROG,
                                                        NFS_VERS,
                                                        NFSPROC_GETATTR,
                                                        &args_fh(&f),
                                                    )
                                                    .and_then(|r| res_getattr(&r))
                                                {
                                                    Ok(a) => a,
                                                    Err(err) => {
                                                        errors.push(format!("{child}: {err}"));
                                                        continue;
                                                    }
                                                },
                                            };
                                            (a, f)
                                        }
                                    };
                                    let link_target = if attrs.ftype == NF3LNK {
                                        match conn
                                            .call(
                                                NFS_PROG,
                                                NFS_VERS,
                                                NFSPROC_READLINK,
                                                &args_fh(&efh),
                                            )
                                            .and_then(|r| res_readlink(&r))
                                        {
                                            Ok(t) => Some(PathBuf::from(t)),
                                            Err(err) => {
                                                errors.push(format!("{child}: {err}"));
                                                continue;
                                            }
                                        }
                                    } else {
                                        None
                                    };
                                    let Some(item) = item_from(child.clone(), &attrs, link_target)
                                    else {
                                        eprintln!("WARN: skipping special file {child}");
                                        continue;
                                    };
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
        // through `retrying`, so a cached handle that went stale is looked up again rather
        // than reported as a failure for the rest of the run
        let got = self.retrying(rel, |fh| self.getattr(fh).map(|a| (fh.clone(), a)));
        let (fh, attrs) = match got {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.forget(rel);
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let target = if attrs.ftype == NF3LNK {
            Some(self.readlink(&fh)?)
        } else {
            None
        };
        Ok(item_from(rel.to_string(), &attrs, target))
    }

    fn open(&self, rel: &str) -> io::Result<NfsReader> {
        let fh = self.fh_of(rel)?;
        let size = self.getattr(&fh)?.size;
        Ok(NfsReader {
            pool: self.pool.clone(),
            conn: Some(self.pool.take()?),
            fh,
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
        let fh = self.fh_of(rel)?;
        let size = self.getattr(&fh)?.size;
        let chunk = (self.rtmax as usize).min(buf.len().max(4096)) as u32;
        let mut conn = self.pool.take()?;
        let result = (|| {
            let mut pending: VecDeque<(u32, u64, u32)> = VecDeque::new();
            let mut next_off = 0u64;
            let mut pos = 0u64;
            while pos < size {
                while pending.len() < READ_WINDOW && next_off < size {
                    let want = chunk.min((size - next_off) as u32);
                    let xid = conn.send(
                        NFS_PROG,
                        NFS_VERS,
                        NFSPROC_READ,
                        &args_read(&fh, next_off, want),
                    )?;
                    pending.push_back((xid, next_off, want));
                    next_off += want as u64;
                }
                let Some((xid, off, want)) = pending.pop_front() else {
                    break;
                };
                let (data, eof) = res_read(&conn.recv(xid)?)?;
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
            // drain anything still in flight so the connection goes back clean
            while let Some((xid, _, _)) = pending.pop_front() {
                let _ = conn.recv(xid);
            }
            Ok(())
        })();
        self.pool.give(conn);
        result
    }

    fn create_file(&self, item: &Item) -> io::Result<NfsSink> {
        let rel = item.rel.as_str();
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        let attrs = Sattr3 {
            mode: Some(0o600),
            size: Some(0),
            ..Default::default()
        };
        let create = |how| {
            res_create(
                &self.call(NFSPROC_CREATE, &args_create(&dir, &name, how, &attrs))?,
                "CREATE",
            )
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
        };
        // A server that REFUSES the create over a non-regular name (RFC 1813 leaves it to the
        // server; Linux hands the object back instead, below) is asked what holds it. Only
        // EXIST leads there: it is the answer about the name. INVAL is any bad argument, and
        // a symlink found beside it did not cause it -- removed on that evidence, it would be
        // lost when the retry failed the same way. A lookup that cannot answer leaves the
        // refusal standing. `AlreadyExists` is
        // EXIST alone: `proto::status_error` gives that kind to no other status, and the
        // transport never produces it. A fifo, socket or device refused this way stays, and
        // the copy fails: `stat` answers nothing for a kind this tool does not carry, so there
        // is no evidence of what holds the name. (Linux takes the path below instead, where
        // the reply's own type is the evidence, and replaces those too.)
        let (mut fh, post) = match create(UNCHECKED) {
            Ok(r) => r,
            Err(refused) if refused.kind() == io::ErrorKind::AlreadyExists => {
                match self.stat(rel) {
                    Ok(Some(i)) if i.kind == Kind::Symlink => {
                        self.forget(rel);
                        self.remove(rel, i.kind)?.cleared(rel)?;
                        create(GUARDED)?
                    }
                    _ => return Err(refused),
                }
            }
            Err(e) => return Err(e),
        };
        // WHAT THE NAME HOLDS IS READ FROM THE REPLY. An UNCHECKED CREATE of a name that is not a
        // regular file does not fail on Linux nfsd: it hands back that object, unchanged, with
        // its own handle and attributes. The server does not follow a symlink there, but WRITEs
        // that follow fail on the link's handle, on every run, and the link stays. A symlink
        // or other special file is therefore removed by name -- REMOVE does not
        // follow either -- and the file created GUARDED, as the local tree and SFTP replace
        // one. A directory stays, and the copy fails loudly, as it does elsewhere.
        let ftype = match post {
            Some(a) => Some(a.ftype),
            None => self.stat(rel)?.map(|i| match i.kind {
                Kind::File => NF3REG,
                Kind::Dir => NF3DIR,
                _ => NF3LNK,
            }),
        };
        match ftype {
            Some(NF3REG) => {}
            // created, and then the name reads as absent or as nothing this tool knows: the
            // handle is not known to be the file at the name, so nothing is written to it
            None => {
                return Err(io::Error::other(format!(
                    "{rel}: CREATE answered, but what holds the name could not be read back"
                )))
            }
            Some(NF3DIR) => {
                return Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    format!("{rel}: a directory holds the name"),
                ))
            }
            Some(t) => {
                self.forget(rel);
                self.remove(rel, kind_of(t).unwrap_or(Kind::Symlink))?
                    .cleared(rel)?;
                fh = create(GUARDED)?.0;
            }
        }
        let fh = match fh {
            Some(fh) => fh,
            None => {
                self.forget(rel);
                self.fh_of(rel)?
            }
        };
        self.remember(rel, fh.clone());
        Ok(NfsSink {
            pool: self.pool.clone(),
            conn: Some(self.pool.take()?),
            fh,
            pos: 0,
            wtmax: self.wtmax,
            pending: VecDeque::new(),
            wrote_any: false,
            write_verf: None,
            acl: self.acl.clone(),
            v4: self.v4.clone(),
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut NfsSink,
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
        let attrs = Sattr3 {
            mode: Some(0o700),
            ..Default::default()
        };
        match res_create(
            &self.call(NFSPROC_MKDIR, &args_mkdir(&dir, &name, &attrs))?,
            "MKDIR",
        ) {
            Ok((Some(fh), _)) => {
                self.remember(rel, fh);
                Ok(())
            }
            Ok((None, _)) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match self.stat(rel)? {
                Some(i) if i.kind == Kind::Dir => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{rel}: exists and is not a directory"),
                )),
            },
            Err(e) => Err(io::Error::new(e.kind(), format!("{rel}: {e}"))),
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
        let (fh, _) = res_create(
            &self.call(
                NFSPROC_SYMLINK,
                &args_symlink(&dir, &name, &Sattr3::default(), &target.to_string_lossy()),
            )?,
            "SYMLINK",
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        if let Some(fh) = fh {
            self.remember(rel, fh);
        }
        Ok(())
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let file = self.fh_of(existing)?;
        let want = self.getattr(&file)?.fileid;
        if let Some(cur) = self.stat(rel)? {
            if cur.ino == want {
                return Ok(());
            }
            self.remove(rel, cur.kind)?.cleared(rel)?;
        }
        let (parent, name) = split(rel);
        let dir = self.fh_of(&parent)?;
        res_wcc_only(
            &self.call(NFSPROC_LINK, &args_link(&file, &dir, &name))?,
            "LINK",
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        self.remember(rel, file);
        Ok(())
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
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
            let dir = match self.fh_of(&parent) {
                Ok(d) => d,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removed::Gone),
                Err(e) => return Err(e),
            };
            (dir, name)
        };
        let (proc_, what) = if kind == Kind::Dir {
            (NFSPROC_RMDIR, "RMDIR")
        } else {
            (NFSPROC_REMOVE, "REMOVE")
        };
        self.forget(rel);
        match res_wcc_only(&self.call(proc_, &args_diropargs(&dir, &name))?, what) {
            Ok(()) => Ok(Removed::Gone),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removed::Gone),
            // NFS3ERR_ACCES is the server refusing THIS OBJECT, which is `Kept` rather than
            // a failure.
            //
            // An RPC-level rejection of the CALL -- `AUTH_BADCRED`, `AUTH_TOOWEAK`, an
            // expired Kerberos context -- is the same `io::ErrorKind::PermissionDenied`
            // and a different remedy, and it does NOT reach this match: `self.call(..)?`
            // above returns it first. So `or_refused` only ever sees an NFS status, which
            // is what it is for. A guard was added here on the assumption that it did
            // reach this arm, and the arm written to prove it showed the opposite, so the
            // guard was dead code and is gone. `an_nfs_call_refused_by_rpc_is_a_failure_
            // and_not_a_kept_entry` keeps it that way.
            Err(e) => Removed::or_refused(io::Error::new(e.kind(), format!("{rel}: {e}"))),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (from_parent, from_name) = split(from);
        let (to_parent, to_name) = split(to);
        let fdir = self.fh_of(&from_parent)?;
        let tdir = self.fh_of(&to_parent)?;
        let fh = self.fh_of(from).ok();
        res_wcc_only(
            &self.call(
                NFSPROC_RENAME,
                &args_rename(&fdir, &from_name, &tdir, &to_name),
            )?,
            "RENAME",
        )
        .map_err(|e| io::Error::new(e.kind(), format!("{from} -> {to}: {e}")))?;
        self.forget(from);
        if let Some(fh) = fh {
            self.remember(to, fh);
        }
        Ok(())
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let fh = self.fh_of(rel)?;
        let mut refusals = Refusals::default();
        if opts.owner {
            let own = Sattr3 {
                uid: Some(item.uid),
                gid: Some(item.gid),
                ..Default::default()
            };
            match self.setattr(&fh, &own, rel) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                Err(e) => return Err(e),
            }
        }
        if item.kind != Kind::Symlink {
            let mut rest = Sattr3::default();
            if opts.mode {
                rest.mode = Some(item.mode);
            }
            if opts.times {
                rest.mtime = SetTime::Client(Time3::from_ns(item.mtime_ns));
                rest.atime = SetTime::Client(Time3::from_ns(if opts.atime {
                    item.atime_ns
                } else {
                    item.mtime_ns
                }));
            }
            if rest != Sattr3::default() {
                self.setattr(&fh, &rest, rel)?;
            }
        }
        Ok(refusals)
    }

    /// NFSv3 has no extended attributes on the wire; the POSIX ACLs travel through the
    /// NFSACL program when the server has it, and nothing else does.
    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        if self.acl.is_none() && self.v4.is_none() {
            return Ok(Vec::new());
        }
        let Some(item) = self.stat(rel)? else {
            return Ok(Vec::new());
        };
        if item.kind == Kind::Symlink {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if let Some(pool) = &self.acl {
            let fh = self.fh_of(rel)?;
            out = get_acls(pool, &fh, item.kind)
                .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        }
        if let Some(v4) = &self.v4 {
            if let Some(bytes) = v4
                .get_acl(rel)
                .map_err(|e| io::Error::new(e.kind(), format!("{rel}: NFSv4 {e}")))?
            {
                out.push((v4::ACL_NAME.to_string(), bytes));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        if attrs.is_empty() {
            return Ok(Vec::new());
        }
        let fh = self.fh_of(rel)?;
        set_acls(self.acl.as_deref(), self.v4.as_deref(), &fh, rel, attrs)
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        let fh = self.fh_of(&item.rel)?;
        self.setattr(
            &fh,
            &Sattr3 {
                atime: SetTime::Client(Time3::from_ns(item.atime_ns)),
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
            "no server-side copy in NFSv3",
        ))
    }
}
