//! A small NFSv3 and MOUNT server backed by a local directory, serving both programs on one
//! TCP port, so the client can be exercised end to end in the contract suite without root
//! or a kernel `nfsd`. It is a test fixture: no locking, no export table, no security, and
//! file handles are the server's own inode numbers. It is honest about the wire format,
//! which is the part worth testing here; behavior against a real filer is a separate check.

use std::collections::BTreeMap;
use std::fs::{self, File, FileTimes};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{
    lchown, symlink, FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};

use crate::tree::libc_o_nofollow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::acl;
use super::proto::*;
use super::rpc::{self, MOUNT_PROG, NFS_PROG, PORTMAP_PROG};
use super::v4;
use crate::gss;
use crate::xdr::{Decoder, Encoder};

/// Where the stand-in keeps an NFSv4 ACL on its backing directory: ext4 has no handler for
/// `system.nfs4_acl` (that name exists only on a kernel NFS mount), so a user attribute
/// stands in for it.
pub const NFS4_ACL_BACKING_NAME: &str = "user.rcp.nfs4_acl";

struct State {
    root: PathBuf,
    /// Answer `NFS3ERR_JUKEBOX` to this many NFS calls, decrementing, then behave normally.
    ///
    /// A real server sends this while it brings a file back from slow storage. It is the
    /// only transient v3 status, nothing in the client retried it, and so a copy of a file
    /// on tape failed. The counter reproduces exactly that: the first N calls say "ask
    /// again", the rest succeed.
    jukebox: usize,
    /// Answer `NFS3ERR_STALE` to this many GETATTRs, decrementing, then behave normally.
    ///
    /// A handle goes stale when the server restarts or the export is re-shared. The
    /// client caches handles and never invalidated one, so every later operation on that
    /// path failed against a dead handle forever. The counter reproduces one such event:
    /// the cached handle is refused, a fresh LOOKUP works.
    stale_getattrs: usize,
    /// Whether the NFSACL program is served; a server without it is the control for the
    /// ACL arm (attributes reported as refused, never silently dropped).
    acl: bool,
    /// An export that accepts Kerberos only: AUTH_SYS calls are rejected as too weak.
    require_gss: bool,
    /// Reject only REMOVE and RMDIR at the RPC level, with AUTH_TOOWEAK, while every other
    /// call succeeds. A server does this when the export's security changed under a live
    /// mount, or when a Kerberos ticket expired mid-run.
    ///
    /// It is a narrow quirk on purpose: `require_gss` rejects EVERY call, so the mount
    /// never lands and a `delete` cannot reach the removal it is supposed to measure.
    reject_removes: bool,
    /// Refuse an UNCHECKED CREATE of a name that holds something other than a regular file
    /// with EXIST, instead of handing that object back as Linux nfsd does. RFC 1813 leaves
    /// this to the server, and a client that handles only Linux's answer leaves the link in
    /// place on the others.
    refuse_special_creates: Option<io::ErrorKind>,
    /// Handle (the backing inode number) to the first path seen for it, so hard links share
    /// a fileid the way they do on a real server. The mapping is refreshed when the known
    /// path no longer carries that inode: the test process creates and removes many
    /// directories and the filesystem reuses inode numbers, so a handle recorded for a
    /// directory another test has since deleted must not shadow the one that inherited its
    /// number (measured: every operation under a fresh root failing with NFS3ERR 2).
    by_id: BTreeMap<u64, PathBuf>,
    v4: V4State,
}

impl State {
    fn id_for(&mut self, path: &Path) -> io::Result<u64> {
        let id = fs::symlink_metadata(path)?.ino();
        let stale = match self.by_id.get(&id) {
            None => true,
            Some(known) => {
                known != path
                    && fs::symlink_metadata(known)
                        .map(|m| m.ino() != id)
                        .unwrap_or(true)
            }
        };
        if stale {
            self.by_id.insert(id, path.to_path_buf());
        }
        Ok(id)
    }
    fn path_of(&self, fh: &[u8]) -> Option<PathBuf> {
        if fh.len() != 8 {
            return None;
        }
        self.by_id
            .get(&u64::from_be_bytes(fh.try_into().expect("8 bytes")))
            .cloned()
    }
}

pub struct Server {
    pub port: u16,
    stop: Arc<Mutex<bool>>,
    state: Arc<Mutex<State>>,
}

impl Server {
    /// Serves `root` as the only export (any export path is accepted) on a free port, with
    /// the NFSACL program beside NFS and MOUNT.
    pub fn start(root: &Path) -> io::Result<Server> {
        Server::start_with_acl(root, true)
    }

    /// As `start`, with the NFSACL program served or not.
    pub fn start_with_acl(root: &Path, acl: bool) -> io::Result<Server> {
        Server::start_with(root, acl, false)
    }

    /// An export that requires Kerberos (RPCSEC_GSS with the keytab's `nfs/127.0.0.1`).
    pub fn start_kerberized(root: &Path) -> io::Result<Server> {
        Server::start_with(root, true, true)
    }

    /// An export that answers `NFS3ERR_JUKEBOX` to the first `calls` NFS requests and
    /// `NFS3ERR_STALE` to the first `getattrs` GETATTRs, then serves normally.
    ///
    /// Both are transient conditions a real server produces and neither had a client-side
    /// answer: JUKEBOX failed the copy of a file on slow storage, and a stale handle
    /// poisoned its cache entry for the rest of the run.
    pub fn start_flaky(root: &Path, calls: usize, getattrs: usize) -> io::Result<Server> {
        let s = Server::start_full(root, true, false, false)?;
        {
            let mut st = s.state.lock().unwrap();
            st.jukebox = calls;
            st.stale_getattrs = getattrs;
        }
        Ok(s)
    }

    /// An export that refuses an UNCHECKED CREATE over a symlink or special file with `status`
    /// (`AlreadyExists` for EXIST, `InvalidInput` for INVAL).
    pub fn start_refusing_special_creates(
        root: &Path,
        status: io::ErrorKind,
    ) -> io::Result<Server> {
        let s = Server::start_full(root, true, false, false)?;
        s.state.lock().unwrap().refuse_special_creates = Some(status);
        Ok(s)
    }

    /// An export whose REMOVE and RMDIR are refused by RPC itself, everything else served.
    pub fn start_rejecting_removes(root: &Path) -> io::Result<Server> {
        Server::start_full(root, true, false, true)
    }

    fn start_with(root: &Path, acl: bool, require_gss: bool) -> io::Result<Server> {
        Server::start_full(root, acl, require_gss, false)
    }

    fn start_full(
        root: &Path,
        acl: bool,
        require_gss: bool,
        reject_removes: bool,
    ) -> io::Result<Server> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let state = Arc::new(Mutex::new(State {
            root: fs::canonicalize(root)?,
            acl,
            require_gss,
            reject_removes,
            refuse_special_creates: None,
            jukebox: 0,
            stale_getattrs: 0,
            by_id: BTreeMap::new(),
            v4: V4State::default(),
        }));
        let root_id = {
            let mut s = state.lock().unwrap();
            let r = s.root.clone();
            s.id_for(&r)?
        };
        let stop = Arc::new(Mutex::new(false));
        let stop2 = stop.clone();
        let state_for_faults = state.clone();
        std::thread::spawn(move || loop {
            if *stop2.lock().unwrap() {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = state.clone();
                    std::thread::spawn(move || serve(stream, state, root_id, port));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return,
            }
        });
        Ok(Server {
            port,
            stop,
            state: state_for_faults,
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

fn read_record(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 4];
        s.read_exact(&mut h)?;
        let v = u32::from_be_bytes(h);
        let len = (v & 0x7fff_ffff) as usize;
        // the same cap as the client's `read_record`, and for the same reason: the stand-in
        // is reachable from the suite and a fragment header alone commits resident memory
        if out.len().saturating_add(len) > rpc::MAX_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPC record over the limit",
            ));
        }
        let start = out.len();
        out.resize(start + len, 0);
        s.read_exact(&mut out[start..])?;
        if v & 0x8000_0000 != 0 {
            return Ok(out);
        }
    }
}

fn reply(s: &mut TcpStream, xid: u32, accept: u32, body: &[u8]) -> io::Result<()> {
    reply_with_verf(s, xid, (rpc::AUTH_NONE, &[]), accept, body)
}

fn reply_with_verf(
    s: &mut TcpStream,
    xid: u32,
    verf: (u32, &[u8]),
    accept: u32,
    body: &[u8],
) -> io::Result<()> {
    let mut e = Encoder::new();
    e.u32(xid)
        .u32(1)
        .u32(0)
        .u32(verf.0)
        .opaque(verf.1)
        .u32(accept);
    let mut out = e.into_bytes();
    out.extend_from_slice(body);
    s.write_all(&(0x8000_0000u32 | out.len() as u32).to_be_bytes())?;
    s.write_all(&out)
}

/// A rejected call: `MSG_DENIED`, `AUTH_ERROR`, with the auth status.
fn reject(s: &mut TcpStream, xid: u32, auth_stat: u32) -> io::Result<()> {
    let mut e = Encoder::new();
    e.u32(xid).u32(1).u32(1).u32(1).u32(auth_stat);
    let out = e.into_bytes();
    s.write_all(&(0x8000_0000u32 | out.len() as u32).to_be_bytes())?;
    s.write_all(&out)
}

/// The RPCSEC_GSS context of one connection, once established.
struct GssSession {
    ctx: gss::Context,
    service: u32,
}

const GSS_HANDLE: &[u8] = b"rcp-standin-context";
const GSS_WINDOW: u32 = 128;

fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>, root_id: u64, port: u16) {
    stream.set_nodelay(true).ok();
    let mut session: Option<GssSession> = None;
    let mut pending: Option<gss::Context> = None;
    let mut acceptor: Option<gss::AcceptorCred> = None;
    loop {
        let record = match read_record(&mut stream) {
            Ok(r) => r,
            Err(_) => return,
        };
        let call = match parse_call(&record) {
            Ok(v) => v,
            Err(_) => return,
        };
        let (with_acl, require_gss, reject_removes) = {
            let s = state.lock().unwrap();
            (s.acl, s.require_gss, s.reject_removes)
        };
        // RPCSEC_GSS: control calls establish the context, data calls are checked and
        // unwrapped here and wrapped again on the way out
        let mut args: Vec<u8> = call.args.to_vec();
        let mut gss_seq: Option<u32> = None;
        if call.cred_flavor == rpc::RPCSEC_GSS {
            let mut d = Decoder::new(call.cred);
            let parsed = (|| -> io::Result<(u32, u32, u32, u32, Vec<u8>)> {
                Ok((d.u32()?, d.u32()?, d.u32()?, d.u32()?, d.opaque()?.to_vec()))
            })();
            let Ok((vers, gss_proc, seq, service, handle)) = parsed else {
                let _ = reject(&mut stream, call.xid, 1);
                continue;
            };
            if vers != rpc::RPCSEC_GSS_VERS {
                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                continue;
            }
            match gss_proc {
                rpc::GSS_PROC_INIT | rpc::GSS_PROC_CONTINUE_INIT => {
                    let token = Decoder::new(&args)
                        .opaque()
                        .map(|t| t.to_vec())
                        .unwrap_or_default();
                    if acceptor.is_none() {
                        match gss::AcceptorCred::acquire() {
                            Ok(c) => acceptor = Some(c),
                            Err(_) => {
                                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                                continue;
                            }
                        }
                    }
                    let mut ctx = match pending.take() {
                        Some(c) => c,
                        None => match gss::Context::acceptor() {
                            Ok(c) => c,
                            Err(_) => {
                                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                                continue;
                            }
                        },
                    };
                    let (major, out_token) =
                        match ctx.accept_step(acceptor.as_ref().expect("acquired"), &token) {
                            Ok(step) => (if step.complete { 0 } else { 1 }, step.token),
                            Err(_) => {
                                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                                continue;
                            }
                        };
                    let mut res = Encoder::new();
                    res.opaque(GSS_HANDLE)
                        .u32(major)
                        .u32(0)
                        .u32(GSS_WINDOW)
                        .opaque(&out_token);
                    let r = if major == 0 {
                        let mut w = Encoder::new();
                        w.u32(GSS_WINDOW);
                        let mic = ctx.mic(&w.into_bytes()).unwrap_or_default();
                        session = Some(GssSession { ctx, service });
                        reply_with_verf(
                            &mut stream,
                            call.xid,
                            (rpc::RPCSEC_GSS, &mic),
                            0,
                            &res.into_bytes(),
                        )
                    } else {
                        pending = Some(ctx);
                        reply(&mut stream, call.xid, 0, &res.into_bytes())
                    };
                    if r.is_err() {
                        return;
                    }
                    continue;
                }
                rpc::GSS_PROC_DESTROY => {
                    session = None;
                    let _ = reply(&mut stream, call.xid, 0, &[]);
                    continue;
                }
                _ => {}
            }
            // a data call: the context must exist, the header MIC and the body must check out
            let Some(s) = session.as_ref() else {
                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CTXPROBLEM);
                continue;
            };
            if handle != GSS_HANDLE
                || call.verf_flavor != rpc::RPCSEC_GSS
                || s.ctx
                    .verify_mic(&record[..call.cred_end], call.verf)
                    .is_err()
            {
                let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                continue;
            }
            let unwrapped = (|| -> io::Result<Vec<u8>> {
                match service {
                    rpc::GSS_SVC_INTEGRITY => {
                        let mut d = Decoder::new(&args);
                        let data = d.opaque()?.to_vec();
                        let mic = d.opaque()?;
                        s.ctx.verify_mic(&data, mic)?;
                        Ok(data)
                    }
                    rpc::GSS_SVC_PRIVACY => {
                        let mut d = Decoder::new(&args);
                        s.ctx.unwrap(d.opaque()?, true)
                    }
                    _ => {
                        let mut e = Encoder::new();
                        e.u32(seq);
                        let mut v = e.into_bytes();
                        v.extend_from_slice(&args);
                        Ok(v)
                    }
                }
            })();
            match unwrapped {
                Ok(data)
                    if data.len() >= 4
                        && u32::from_be_bytes(data[..4].try_into().expect("4 bytes")) == seq =>
                {
                    args = data[4..].to_vec()
                }
                _ => {
                    let _ = reject(&mut stream, call.xid, rpc::RPCSEC_GSS_CREDPROBLEM);
                    continue;
                }
            }
            gss_seq = Some(seq);
        } else if require_gss && call.prog != PORTMAP_PROG {
            // an export that wants Kerberos: AUTH_SYS is too weak
            let _ = reject(&mut stream, call.xid, 5);
            continue;
        } else if reject_removes
            && call.prog == NFS_PROG
            && matches!(call.proc_, NFSPROC_REMOVE | NFSPROC_RMDIR)
        {
            // RPC refuses the CALL, which is NOT the server refusing one object: the
            // remedy is the credential, and every later removal answers the same way. A
            // client that reads this as `Kept` tells the operator to rerun.
            let _ = reject(&mut stream, call.xid, 5);
            continue;
        }
        let (xid, prog, vers, proc_) = (call.xid, call.prog, call.vers, call.proc_);
        let result = match (prog, vers) {
            (MOUNT_PROG, MOUNT_VERS) => mount_proc(proc_, &args, root_id),
            (NFS_PROG, NFS_VERS) => nfs_proc(proc_, &args, &state),
            (NFS_PROG, v4::NFS4_VERS) if with_acl => nfs4_proc(proc_, &args, &state),
            (PORTMAP_PROG, 2) => portmap_proc(proc_, &args, port, with_acl),
            (acl::NFSACL_PROG, acl::NFSACL_VERS) if with_acl => acl_proc(proc_, &args, &state),
            (acl::NFSACL_PROG, _) if with_acl => Err(2),
            (MOUNT_PROG, _) | (NFS_PROG, _) | (PORTMAP_PROG, _) => Err(2), // version mismatch
            _ => Err(1),                                                   // program unavailable
        };
        let r = match (result, gss_seq, session.as_ref()) {
            (Ok(body), Some(seq), Some(s)) => {
                // the reply verifier is a MIC over the call's sequence number; the body is
                // wrapped the way the call was
                let mut w = Encoder::new();
                w.u32(seq);
                let verf = s.ctx.mic(&w.into_bytes()).unwrap_or_default();
                let mut data = Encoder::new();
                data.u32(seq);
                let mut data = data.into_bytes();
                data.extend_from_slice(&body);
                let out = match s.service {
                    rpc::GSS_SVC_INTEGRITY => {
                        let mic = s.ctx.mic(&data).unwrap_or_default();
                        let mut e = Encoder::new();
                        e.opaque(&data).opaque(&mic);
                        e.into_bytes()
                    }
                    rpc::GSS_SVC_PRIVACY => {
                        let mut e = Encoder::new();
                        e.opaque(&s.ctx.wrap(&data, true).unwrap_or_default());
                        e.into_bytes()
                    }
                    _ => body,
                };
                reply_with_verf(&mut stream, xid, (rpc::RPCSEC_GSS, &verf), 0, &out)
            }
            (Ok(body), _, _) => reply(&mut stream, xid, 0, &body),
            (Err(accept), _, _) => reply(&mut stream, xid, accept, &[]),
        };
        if r.is_err() {
            return;
        }
    }
}

/// One RPC call as received: the header fields, the credential and verifier, and where
/// the credential ends (the RPCSEC_GSS header MIC covers everything before that).
struct Call<'a> {
    xid: u32,
    prog: u32,
    vers: u32,
    proc_: u32,
    cred_flavor: u32,
    cred: &'a [u8],
    cred_end: usize,
    verf_flavor: u32,
    verf: &'a [u8],
    args: &'a [u8],
}

fn parse_call(record: &[u8]) -> io::Result<Call<'_>> {
    let mut d = Decoder::new(record);
    let xid = d.u32()?;
    if d.u32()? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a call"));
    }
    let _rpcvers = d.u32()?;
    let prog = d.u32()?;
    let vers = d.u32()?;
    let proc_ = d.u32()?;
    let cred_flavor = d.u32()?;
    let cred = d.opaque()?;
    let cred_end = record.len() - d.remaining();
    let verf_flavor = d.u32()?;
    let verf = d.opaque()?;
    let args = &record[record.len() - d.remaining()..];
    Ok(Call {
        xid,
        prog,
        vers,
        proc_,
        cred_flavor,
        cred,
        cred_end,
        verf_flavor,
        verf,
        args,
    })
}

/// The portmapper the stand-in plays for itself: GETPORT and DUMP both point at this port.
fn portmap_proc(proc_: u32, args: &[u8], port: u16, with_acl: bool) -> Result<Vec<u8>, u32> {
    let mut e = Encoder::new();
    let mut programs = vec![
        (PORTMAP_PROG, 2),
        (MOUNT_PROG, MOUNT_VERS),
        (NFS_PROG, NFS_VERS),
    ];
    if with_acl {
        programs.push((acl::NFSACL_PROG, acl::NFSACL_VERS));
        programs.push((NFS_PROG, v4::NFS4_VERS));
    }
    match proc_ {
        0 => {}
        3 => {
            let mut d = Decoder::new(args);
            let prog = d.u32().map_err(|_| 4u32)?;
            let vers = d.u32().map_err(|_| 4u32)?;
            let known = programs.contains(&(prog, vers));
            e.u32(if known { port as u32 } else { 0 });
        }
        4 => {
            for (prog, vers) in programs {
                e.u32(1).u32(prog).u32(vers).u32(6).u32(port as u32);
            }
            e.u32(0);
        }
        _ => return Err(3),
    }
    Ok(e.into_bytes())
}

/// Client ids and open state for the NFSv4 stand-in: enough of RFC 7530's state model to
/// refuse what a client that skipped a step would send (an OPEN under an unconfirmed
/// client id, a READ under a stateid no OPEN produced), which is what makes the arms that
/// run the data path over v4 evidence rather than a smoke test.
#[derive(Default)]
struct V4State {
    next_clientid: u64,
    /// Client id to its confirmation verifier and whether SETCLIENTID_CONFIRM arrived.
    clients: BTreeMap<u64, ([u8; 8], bool)>,
    next_stateid: u64,
    /// A stateid's `other` field to the open file and the stateid's current seqid.
    opens: BTreeMap<[u8; 12], (PathBuf, u32)>,
}

const V4_LEASE: u32 = 90;

/// Every attribute the stand-in serves for a backing object, before the request's bitmap
/// narrows it. Owners are numeric strings, which is the form a server without an id
/// mapper answers with.
fn attrs4_of(path: &Path, id: u64, fh: &[u8], want: &[u32]) -> io::Result<v4::Attrs> {
    let m = fs::symlink_metadata(path)?;
    let ft = m.file_type();
    let ftype = if ft.is_dir() {
        v4::NF4DIR
    } else if ft.is_file() {
        v4::NF4REG
    } else if ft.is_symlink() {
        v4::NF4LNK
    } else if ft.is_socket() {
        v4::NF4SOCK
    } else if ft.is_fifo() {
        v4::NF4FIFO
    } else if ft.is_block_device() {
        v4::NF4BLK
    } else {
        v4::NF4CHR
    };
    let wants_acl = want.first().is_some_and(|w| w & (1 << v4::FATTR4_ACL) != 0);
    let acl = if wants_acl {
        Some(nfs4_acl_of(path)?)
    } else {
        None
    };
    let all = v4::Attrs {
        supported: Some(v4::bitmap_of(&[
            v4::FATTR4_SUPPORTED_ATTRS,
            v4::FATTR4_TYPE,
            v4::FATTR4_CHANGE,
            v4::FATTR4_SIZE,
            v4::FATTR4_FSID,
            v4::FATTR4_LEASE_TIME,
            v4::FATTR4_RDATTR_ERROR,
            v4::FATTR4_ACL,
            v4::FATTR4_FILEHANDLE,
            v4::FATTR4_FILEID,
            v4::FATTR4_MAXREAD,
            v4::FATTR4_MAXWRITE,
            v4::FATTR4_MODE,
            v4::FATTR4_NUMLINKS,
            v4::FATTR4_OWNER,
            v4::FATTR4_OWNER_GROUP,
            v4::FATTR4_RAWDEV,
            v4::FATTR4_SPACE_USED,
            v4::FATTR4_TIME_ACCESS,
            v4::FATTR4_TIME_ACCESS_SET,
            v4::FATTR4_TIME_METADATA,
            v4::FATTR4_TIME_MODIFY,
            v4::FATTR4_TIME_MODIFY_SET,
        ])),
        ftype: Some(ftype),
        change: Some((m.ctime() as u64) << 32 | (m.ctime_nsec() as u64 & 0xffff_ffff)),
        size: Some(m.len()),
        fsid: Some((1, 0)),
        lease_time: Some(V4_LEASE),
        rdattr_error: Some(v4::NFS4_OK),
        acl,
        filehandle: Some(fh.to_vec()),
        fileid: Some(id),
        maxread: Some(256 << 10),
        maxwrite: Some(256 << 10),
        mode: Some(m.mode() & 0o7777),
        numlinks: Some(m.nlink() as u32),
        owner: Some(m.uid().to_string()),
        owner_group: Some(m.gid().to_string()),
        rawdev: Some((0, 0)),
        space_used: Some(m.blocks() * 512),
        time_access: Some(v4::Time4 {
            seconds: m.atime(),
            nseconds: m.atime_nsec() as u32,
        }),
        time_access_set: None,
        time_metadata: Some(v4::Time4 {
            seconds: m.ctime(),
            nseconds: m.ctime_nsec() as u32,
        }),
        time_modify: Some(v4::Time4 {
            seconds: m.mtime(),
            nseconds: m.mtime_nsec() as u32,
        }),
        time_modify_set: None,
    };
    Ok(all.restricted_to(want))
}

/// A uid or gid from an owner string the way a server with an id mapper reads it: a
/// number as is, `name@domain` through this host's passwd and group files.
fn id4_of(text: &str, user: bool) -> Result<u32, u32> {
    if let Ok(n) = text.parse::<u32>() {
        return Ok(n);
    }
    let name = text.split_once('@').map(|(n, _)| n).unwrap_or(text);
    let looked = if user {
        crate::names::uid_of(name)
    } else {
        crate::names::gid_of(name)
    };
    looked.ok_or(v4::NFS4ERR_BADOWNER)
}

/// Applies a SETATTR's attributes to the backing object; the bitmap of what was set.
fn apply_sattr4(path: &Path, a: &v4::Attrs) -> Result<Vec<u32>, u32> {
    let err = |e: io::Error| nfs_status(&e);
    let mut set = Vec::new();
    let is_link = fs::symlink_metadata(path)
        .map_err(err)?
        .file_type()
        .is_symlink();
    if a.owner.is_some() || a.owner_group.is_some() {
        let uid = a.owner.as_deref().map(|o| id4_of(o, true)).transpose()?;
        let gid = a
            .owner_group
            .as_deref()
            .map(|g| id4_of(g, false))
            .transpose()?;
        lchown(path, uid, gid).map_err(err)?;
        if uid.is_some() {
            set.push(v4::FATTR4_OWNER);
        }
        if gid.is_some() {
            set.push(v4::FATTR4_OWNER_GROUP);
        }
    }
    if let Some(acl) = &a.acl {
        v4::decode_aces(acl).map_err(|_| v4::NFS4ERR_BADXDR)?;
        crate::xattr::set(path, NFS4_ACL_BACKING_NAME, acl).map_err(err)?;
        set.push(v4::FATTR4_ACL);
    }
    if is_link {
        return Ok(set);
    }
    if let Some(size) = a.size {
        File::options()
            .write(true)
            .open(path)
            .map_err(err)?
            .set_len(size)
            .map_err(err)?;
        set.push(v4::FATTR4_SIZE);
    }
    if let Some(mode) = a.mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(err)?;
        set.push(v4::FATTR4_MODE);
    }
    if a.time_access_set.is_some() || a.time_modify_set.is_some() {
        let m = fs::metadata(path).map_err(err)?;
        let cur_a = UNIX_EPOCH + Duration::new(m.atime() as u64, m.atime_nsec() as u32);
        let cur_m = UNIX_EPOCH + Duration::new(m.mtime() as u64, m.mtime_nsec() as u32);
        let pick = |t: &Option<v4::SetTime4>, cur: SystemTime| match t {
            None => cur,
            Some(None) => SystemTime::now(),
            Some(Some(t)) => UNIX_EPOCH + Duration::new(t.seconds.max(0) as u64, t.nseconds),
        };
        let times = FileTimes::new()
            .set_accessed(pick(&a.time_access_set, cur_a))
            .set_modified(pick(&a.time_modify_set, cur_m));
        File::options()
            .read(true)
            .open(path)
            .map_err(err)?
            .set_times(times)
            .map_err(err)?;
        if a.time_access_set.is_some() {
            set.push(v4::FATTR4_TIME_ACCESS_SET);
        }
        if a.time_modify_set.is_some() {
            set.push(v4::FATTR4_TIME_MODIFY_SET);
        }
    }
    Ok(set)
}

fn change_info(e: &mut Encoder, dir: &Path) {
    let c = fs::symlink_metadata(dir)
        .map(|m| (m.ctime() as u64) << 32 | (m.ctime_nsec() as u64 & 0xffff_ffff))
        .unwrap_or(0);
    e.bool(true).u64(c).u64(c.wrapping_add(1));
}

/// NFSv4.0 COMPOUND: the data protocol a `-nfs.vers 4` client speaks and the stateless
/// operations the `-acl4` sidecar sends. The current handle walks the backing directory
/// (a pseudo root above the export, whose only name is `export`), attributes come from
/// the backing object with numeric owners, and the ACL attribute is its
/// `user.rcp.nfs4_acl` (or one derived from its mode). Client ids and open stateids are
/// real: an OPEN needs a confirmed client id, every OPEN asks to be confirmed, and READ,
/// WRITE and CLOSE need a stateid an OPEN produced. Processing stops at the first failing
/// operation, as the protocol says.
fn nfs4_proc(proc_: u32, args: &[u8], state: &Arc<Mutex<State>>) -> Result<Vec<u8>, u32> {
    let garbage = |_: io::Error| 4u32;
    if proc_ == 0 {
        return Ok(Vec::new());
    }
    if proc_ != v4::NFSPROC4_COMPOUND {
        return Err(3);
    }
    let mut d = Decoder::new(args);
    let tag = d.opaque().map_err(garbage)?.to_vec();
    let minor = d.u32().map_err(garbage)?;
    let count = d.u32().map_err(garbage)?;
    let mut results = Encoder::new();
    let mut done = 0u32;
    let mut status = v4::NFS4_OK;
    if minor != 0 {
        status = v4::NFS4ERR_MINOR_VERS_MISMATCH; // no operation is processed
    }
    let mut current: Option<PathBuf> = None;
    let mut saved: Option<PathBuf> = None;
    let mut at_pseudo_root = false;
    let root = state.lock().unwrap().root.clone();
    let fh_of = |p: &Path| -> Result<Vec<u8>, u32> {
        state
            .lock()
            .unwrap()
            .id_for(p)
            .map(|id| id.to_be_bytes().to_vec())
            .map_err(|_| v4::NFS4ERR_STALE)
    };
    // the stateid a READ, WRITE or CLOSE names must be one an OPEN produced, and it must
    // name the current handle's file (the same inode: a hard link reaches its file under
    // whichever name the handle was first seen by)
    let open_path = |sid: &v4::Stateid, current: &Option<PathBuf>| -> Result<PathBuf, u32> {
        let p = state
            .lock()
            .unwrap()
            .v4
            .opens
            .get(&sid.other)
            .map(|(p, _)| p.clone())
            .ok_or(v4::NFS4ERR_BAD_STATEID)?;
        let same = match current {
            Some(c) => {
                fs::symlink_metadata(c).ok().map(|m| m.ino())
                    == fs::symlink_metadata(&p).ok().map(|m| m.ino())
            }
            None => false,
        };
        if !same {
            return Err(v4::NFS4ERR_BAD_STATEID);
        }
        Ok(p)
    };
    for _ in 0..count {
        if status != v4::NFS4_OK {
            break;
        }
        let op = d.u32().map_err(garbage)?;
        let outcome: Result<Vec<u8>, u32> = (|| {
            let mut r = Encoder::new();
            match op {
                v4::OP_PUTROOTFH => {
                    current = None;
                    at_pseudo_root = true;
                }
                v4::OP_LOOKUP if at_pseudo_root => {
                    let name = d.string().map_err(garbage)?;
                    if name != "export" {
                        return Err(v4::NFS4ERR_NOENT);
                    }
                    current = Some(root.clone());
                    at_pseudo_root = false;
                }
                v4::OP_PUTFH => {
                    let fh = d.opaque().map_err(garbage)?;
                    current = Some(state.lock().unwrap().path_of(fh).ok_or(v4::NFS4ERR_STALE)?);
                    at_pseudo_root = false;
                }
                v4::OP_GETFH => {
                    let p = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    r.opaque(&fh_of(p)?);
                }
                v4::OP_SAVEFH => {
                    saved = Some(current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?);
                }
                v4::OP_RESTOREFH => {
                    current = Some(saved.clone().ok_or(10030u32)?); // NFS4ERR_RESTOREFH
                }
                v4::OP_LOOKUP => {
                    let name = d.string().map_err(garbage)?;
                    let dir = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    if !fs::symlink_metadata(dir)
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                    {
                        return Err(v4::NFS4ERR_NOTDIR);
                    }
                    let p = dir.join(&name);
                    fs::symlink_metadata(&p).map_err(|e| nfs_status(&e))?;
                    current = Some(p);
                }
                v4::OP_LOOKUPP => {
                    let p = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    if *p == root {
                        return Err(v4::NFS4ERR_NOENT);
                    }
                    current = p.parent().map(Path::to_path_buf);
                }
                v4::OP_GETATTR => {
                    let want = v4::decode_bitmap(&mut d).map_err(garbage)?;
                    let p = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let fh = fh_of(p)?;
                    let id = u64::from_be_bytes(fh[..8].try_into().expect("8 bytes"));
                    let attrs = attrs4_of(p, id, &fh, &want).map_err(|e| nfs_status(&e))?;
                    attrs.encode(&mut r);
                }
                v4::OP_SETATTR => {
                    let sid = v4::Stateid::decode(&mut d).map_err(garbage)?;
                    let attrs = v4::Attrs::decode(&mut d).map_err(|_| v4::NFS4ERR_BADXDR)?;
                    let p = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    // a size change is a write and needs an open's stateid; anything else
                    // takes the anonymous one
                    if attrs.size.is_some() && sid != v4::Stateid::ANONYMOUS {
                        open_path(&sid, &current)?;
                    }
                    let unsupported = attrs.ftype.is_some()
                        || attrs.change.is_some()
                        || attrs.fileid.is_some()
                        || attrs.numlinks.is_some()
                        || attrs.time_modify.is_some();
                    if unsupported {
                        return Err(v4::NFS4ERR_ATTRNOTSUPP);
                    }
                    let set = apply_sattr4(&p, &attrs)?;
                    v4::encode_bitmap(&mut r, &v4::bitmap_of(&set));
                }
                v4::OP_ACCESS => {
                    let mask = d.u32().map_err(garbage)?;
                    current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    r.u32(mask).u32(mask);
                }
                v4::OP_READLINK => {
                    let p = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let t = fs::read_link(p).map_err(|e| nfs_status(&e))?;
                    r.string(&t.to_string_lossy());
                }
                v4::OP_READDIR => {
                    let cookie = d.u64().map_err(garbage)?;
                    d.fixed(8).map_err(garbage)?;
                    let _dircount = d.u32().map_err(garbage)?;
                    let maxcount = d.u32().map_err(garbage)?;
                    let want = v4::decode_bitmap(&mut d).map_err(garbage)?;
                    let dir = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let mut names: Vec<String> = fs::read_dir(dir)
                        .map_err(|e| nfs_status(&e))?
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    // cookies 1 and 2 are reserved; entry i carries cookie i + 3
                    let start = cookie.saturating_sub(2) as usize;
                    r.fixed(&[0u8; 8]);
                    let mut used = 0usize;
                    let mut eof = true;
                    for (i, name) in names.iter().enumerate().skip(start) {
                        let p = dir.join(name);
                        let mut entry = Encoder::new();
                        entry.bool(true).u64(i as u64 + 3).string(name);
                        match fh_of(&p).and_then(|fh| {
                            let id = u64::from_be_bytes(fh[..8].try_into().expect("8 bytes"));
                            attrs4_of(&p, id, &fh, &want).map_err(|e| nfs_status(&e))
                        }) {
                            Ok(a) => a.encode(&mut entry),
                            Err(st) => v4::Attrs {
                                rdattr_error: Some(st),
                                ..Default::default()
                            }
                            .restricted_to(&want)
                            .encode(&mut entry),
                        }
                        let bytes = entry.into_bytes();
                        if used + bytes.len() + 8 > maxcount as usize && used > 0 {
                            eof = false;
                            break;
                        }
                        used += bytes.len();
                        r.fixed(&bytes);
                    }
                    r.bool(false).bool(eof);
                }
                v4::OP_CREATE => {
                    let ftype = d.u32().map_err(garbage)?;
                    let target = if ftype == v4::NF4LNK {
                        Some(d.string().map_err(garbage)?)
                    } else {
                        None
                    };
                    let name = d.string().map_err(garbage)?;
                    let attrs = v4::Attrs::decode(&mut d).map_err(|_| v4::NFS4ERR_BADXDR)?;
                    let dir = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let p = dir.join(&name);
                    match ftype {
                        v4::NF4DIR => fs::create_dir(&p).map_err(|e| nfs_status(&e))?,
                        v4::NF4LNK => {
                            symlink(target.unwrap_or_default(), &p).map_err(|e| nfs_status(&e))?
                        }
                        _ => return Err(v4::NFS4ERR_NOTSUPP),
                    }
                    let set = apply_sattr4(
                        &p,
                        &v4::Attrs {
                            mode: attrs.mode,
                            ..Default::default()
                        },
                    )?;
                    change_info(&mut r, &dir);
                    v4::encode_bitmap(&mut r, &v4::bitmap_of(&set));
                    current = Some(p);
                }
                v4::OP_REMOVE => {
                    let name = d.string().map_err(garbage)?;
                    let dir = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let p = dir.join(&name);
                    let m = fs::symlink_metadata(&p).map_err(|e| nfs_status(&e))?;
                    if m.is_dir() {
                        fs::remove_dir(&p)
                    } else {
                        fs::remove_file(&p)
                    }
                    .map_err(|e| nfs_status(&e))?;
                    change_info(&mut r, &dir);
                }
                v4::OP_RENAME => {
                    let old = d.string().map_err(garbage)?;
                    let new = d.string().map_err(garbage)?;
                    let from = saved.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let to = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    fs::rename(from.join(&old), to.join(&new)).map_err(|e| nfs_status(&e))?;
                    change_info(&mut r, &from);
                    change_info(&mut r, &to);
                }
                v4::OP_LINK => {
                    let name = d.string().map_err(garbage)?;
                    let file = saved.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let dir = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    fs::hard_link(&file, dir.join(&name)).map_err(|e| nfs_status(&e))?;
                    change_info(&mut r, &dir);
                }
                v4::OP_SETCLIENTID => {
                    let verifier: [u8; 8] =
                        d.fixed(8).map_err(garbage)?.try_into().expect("8 bytes");
                    d.opaque().map_err(garbage)?; // id
                    d.u32().map_err(garbage)?; // callback program
                    d.string().map_err(garbage)?;
                    d.string().map_err(garbage)?;
                    d.u32().map_err(garbage)?; // callback ident
                    let mut s = state.lock().unwrap();
                    s.v4.next_clientid += 1;
                    let id = 0x5243_5000_0000_0000 | s.v4.next_clientid;
                    let confirm = verifier.iter().rev().copied().collect::<Vec<u8>>();
                    s.v4.clients
                        .insert(id, (confirm.clone().try_into().expect("8 bytes"), false));
                    r.u64(id).fixed(&confirm);
                }
                v4::OP_SETCLIENTID_CONFIRM => {
                    let id = d.u64().map_err(garbage)?;
                    let verifier = d.fixed(8).map_err(garbage)?;
                    let mut s = state.lock().unwrap();
                    match s.v4.clients.get_mut(&id) {
                        Some((v, confirmed)) if v[..] == *verifier => *confirmed = true,
                        _ => return Err(v4::NFS4ERR_STALE_CLIENTID),
                    }
                }
                v4::OP_RENEW => {
                    let id = d.u64().map_err(garbage)?;
                    if !state
                        .lock()
                        .unwrap()
                        .v4
                        .clients
                        .get(&id)
                        .is_some_and(|(_, c)| *c)
                    {
                        return Err(v4::NFS4ERR_STALE_CLIENTID);
                    }
                }
                v4::OP_OPEN => {
                    d.u32().map_err(garbage)?; // seqid
                    let access = d.u32().map_err(garbage)?;
                    d.u32().map_err(garbage)?; // deny
                    let clientid = d.u64().map_err(garbage)?;
                    d.opaque().map_err(garbage)?; // owner
                    let create = match d.u32().map_err(garbage)? {
                        v4::OPEN4_NOCREATE => None,
                        _ => {
                            let how = d.u32().map_err(garbage)?;
                            if how == v4::EXCLUSIVE4 {
                                d.fixed(8).map_err(garbage)?;
                                Some((how, v4::Attrs::default()))
                            } else {
                                Some((
                                    how,
                                    v4::Attrs::decode(&mut d).map_err(|_| v4::NFS4ERR_BADXDR)?,
                                ))
                            }
                        }
                    };
                    let claim = d.u32().map_err(garbage)?;
                    if claim != v4::CLAIM_NULL {
                        return Err(v4::NFS4ERR_NOTSUPP);
                    }
                    let name = d.string().map_err(garbage)?;
                    if !state
                        .lock()
                        .unwrap()
                        .v4
                        .clients
                        .get(&clientid)
                        .is_some_and(|(_, c)| *c)
                    {
                        return Err(v4::NFS4ERR_STALE_CLIENTID);
                    }
                    let dir = current.clone().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    let p = dir.join(&name);
                    let mut set = Vec::new();
                    // OPEN never follows a symlink at the name: ISDIR for a directory, SYMLINK
                    // for anything else that is not a regular file (RFC 7530 16.16). This
                    // stand-in used to open through one.
                    if let Ok(m) = fs::symlink_metadata(&p) {
                        if m.is_dir() {
                            return Err(v4::NFS4ERR_ISDIR);
                        }
                        if !m.is_file() {
                            return Err(
                                if matches!(
                                    create.as_ref().map(|c| c.0),
                                    Some(v4::GUARDED4 | v4::EXCLUSIVE4)
                                ) {
                                    v4::NFS4ERR_EXIST
                                } else {
                                    v4::NFS4ERR_SYMLINK
                                },
                            );
                        }
                    }
                    match &create {
                        None => {
                            let m = fs::symlink_metadata(&p).map_err(|e| nfs_status(&e))?;
                            if m.is_dir() {
                                return Err(v4::NFS4ERR_ISDIR);
                            }
                            if access & v4::OPEN4_SHARE_ACCESS_WRITE != 0 {
                                File::options()
                                    .write(true)
                                    .open(&p)
                                    .map_err(|e| nfs_status(&e))?;
                            }
                        }
                        Some((how, attrs)) => {
                            let existed = fs::symlink_metadata(&p).is_ok();
                            if existed && *how == v4::GUARDED4 {
                                return Err(v4::NFS4ERR_EXIST);
                            }
                            File::options()
                                .write(true)
                                .create(true)
                                .truncate(false)
                                .open(&p)
                                .map_err(|e| nfs_status(&e))?;
                            let mut wanted = attrs.clone();
                            if existed {
                                wanted.mode = None; // UNCHECKED on an existing file keeps its mode
                            }
                            set = apply_sattr4(&p, &wanted)?;
                        }
                    }
                    let (sid, rflags) = {
                        let mut s = state.lock().unwrap();
                        s.v4.next_stateid += 1;
                        let mut other = [0u8; 12];
                        other[..8].copy_from_slice(&s.v4.next_stateid.to_be_bytes());
                        other[8..].copy_from_slice(b"open");
                        s.v4.opens.insert(other, (p.clone(), 1));
                        (v4::Stateid { seqid: 1, other }, v4::OPEN4_RESULT_CONFIRM)
                    };
                    sid.encode(&mut r);
                    change_info(&mut r, &dir);
                    r.u32(rflags);
                    v4::encode_bitmap(&mut r, &v4::bitmap_of(&set));
                    r.u32(v4::OPEN_DELEGATE_NONE);
                    current = Some(p);
                }
                v4::OP_OPEN_CONFIRM => {
                    let sid = v4::Stateid::decode(&mut d).map_err(garbage)?;
                    d.u32().map_err(garbage)?; // seqid
                    let mut s = state.lock().unwrap();
                    let (_, seq) =
                        s.v4.opens
                            .get_mut(&sid.other)
                            .ok_or(v4::NFS4ERR_BAD_STATEID)?;
                    *seq += 1;
                    v4::Stateid {
                        seqid: *seq,
                        other: sid.other,
                    }
                    .encode(&mut r);
                }
                v4::OP_CLOSE => {
                    d.u32().map_err(garbage)?; // seqid
                    let sid = v4::Stateid::decode(&mut d).map_err(garbage)?;
                    let mut s = state.lock().unwrap();
                    let (_, seq) =
                        s.v4.opens
                            .remove(&sid.other)
                            .ok_or(v4::NFS4ERR_BAD_STATEID)?;
                    v4::Stateid {
                        seqid: seq + 1,
                        other: sid.other,
                    }
                    .encode(&mut r);
                }
                v4::OP_DELEGRETURN => {
                    v4::Stateid::decode(&mut d).map_err(garbage)?;
                }
                v4::OP_READ => {
                    let sid = v4::Stateid::decode(&mut d).map_err(garbage)?;
                    let offset = d.u64().map_err(garbage)?;
                    let count = d.u32().map_err(garbage)?;
                    let p = open_path(&sid, &current)?;
                    let f = File::open(&p).map_err(|e| nfs_status(&e))?;
                    let len = f.metadata().map_err(|e| nfs_status(&e))?.len();
                    let mut buf = vec![0u8; count.min(1 << 20) as usize];
                    let mut got = 0usize;
                    while got < buf.len() {
                        let n = f
                            .read_at(&mut buf[got..], offset + got as u64)
                            .map_err(|e| nfs_status(&e))?;
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                    buf.truncate(got);
                    r.bool(offset + got as u64 >= len).opaque(&buf);
                }
                v4::OP_WRITE => {
                    let sid = v4::Stateid::decode(&mut d).map_err(garbage)?;
                    let offset = d.u64().map_err(garbage)?;
                    let stable = d.u32().map_err(garbage)?;
                    let data = d.opaque().map_err(garbage)?;
                    let p = open_path(&sid, &current)?;
                    let f = File::options()
                        .write(true)
                        .open(&p)
                        .map_err(|e| nfs_status(&e))?;
                    f.write_all_at(data, offset).map_err(|e| nfs_status(&e))?;
                    if stable != v4::UNSTABLE4 {
                        f.sync_data().map_err(|e| nfs_status(&e))?;
                    }
                    r.u32(data.len() as u32).u32(stable).fixed(b"rcpstand");
                }
                v4::OP_COMMIT => {
                    d.u64().map_err(garbage)?;
                    d.u32().map_err(garbage)?;
                    let p = current.as_ref().ok_or(v4::NFS4ERR_NOFILEHANDLE)?;
                    File::open(p)
                        .and_then(|f| f.sync_data())
                        .map_err(|e| nfs_status(&e))?;
                    r.fixed(b"rcpstand");
                }
                _ => return Err(v4::NFS4ERR_OP_ILLEGAL),
            }
            Ok(r.into_bytes())
        })();
        let st = match outcome {
            Ok(body) => {
                results.u32(op).u32(v4::NFS4_OK).fixed(&body);
                v4::NFS4_OK
            }
            Err(st) => {
                results.u32(op).u32(st);
                if op == v4::OP_SETATTR {
                    results.u32(0); // the attrsset bitmap travels with a failure too
                }
                st
            }
        };
        done += 1;
        status = st;
    }
    let mut e = Encoder::new();
    e.u32(status).opaque(&tag).u32(done);
    let mut body = e.into_bytes();
    body.extend_from_slice(&results.into_bytes());
    Ok(body)
}

/// The NFSv4 ACL of a backing object: its stored attribute, else its mode as three entries.
fn nfs4_acl_of(path: &Path) -> io::Result<Vec<u8>> {
    match crate::xattr::get(path, NFS4_ACL_BACKING_NAME) {
        Ok(bytes) => Ok(bytes),
        Err(err) if matches!(err.raw_os_error(), Some(61) | Some(95)) => {
            let m = fs::symlink_metadata(path)?;
            Ok(v4::aces_from_mode(m.mode() & 0o777, m.is_dir()))
        }
        Err(err) => Err(err),
    }
}

/// The three entries the mode bits amount to, which is what a server answers for a file
/// with no extended ACL.
fn acl_from_mode(mode: u32) -> Vec<acl::Entry> {
    vec![
        acl::Entry {
            tag: acl::ACL_USER_OBJ,
            perm: ((mode >> 6) & 7) as u16,
            id: u32::MAX,
        },
        acl::Entry {
            tag: acl::ACL_GROUP_OBJ,
            perm: ((mode >> 3) & 7) as u16,
            id: u32::MAX,
        },
        acl::Entry {
            tag: acl::ACL_OTHER,
            perm: (mode & 7) as u16,
            id: u32::MAX,
        },
    ]
}

/// NFSACL v3: GETACL and SETACL against the backing directory's own POSIX ACLs, which are
/// its `system.posix_acl_*` attributes.
fn acl_proc(proc_: u32, args: &[u8], state: &Arc<Mutex<State>>) -> Result<Vec<u8>, u32> {
    let garbage = |_: io::Error| 4u32;
    let mut e = Encoder::new();
    let read_acl = |path: &Path, name: &str| -> io::Result<Vec<acl::Entry>> {
        match crate::xattr::get(path, name) {
            Ok(bytes) => acl::from_xattr(&bytes),
            Err(err) if err.raw_os_error() == Some(61) || err.raw_os_error() == Some(95) => {
                Ok(Vec::new())
            } // ENODATA, ENOTSUP
            Err(err) => Err(err),
        }
    };
    match proc_ {
        acl::ACLPROC_NULL => {}
        acl::ACLPROC_GETACL => {
            let mut d = Decoder::new(args);
            let fh = d.opaque().map_err(garbage)?;
            let mask = d.u32().map_err(garbage)?;
            let Some(path) = state.lock().unwrap().path_of(fh) else {
                e.u32(NFS3ERR_STALE).bool(false);
                return Ok(e.into_bytes());
            };
            let outcome = (|| -> io::Result<Vec<u8>> {
                let meta = fs::symlink_metadata(&path)?;
                let mut access = read_acl(&path, acl::ACCESS_NAME)?;
                if access.is_empty() {
                    access = acl_from_mode(meta.mode());
                }
                let default = if meta.is_dir() {
                    read_acl(&path, acl::DEFAULT_NAME)?
                } else {
                    Vec::new()
                };
                acl::encode_getacl_reply(mask, &access, &default)
            })();
            match outcome {
                Ok(body) => return Ok(body),
                Err(err) => {
                    e.u32(nfs_status(&err)).bool(false);
                }
            }
        }
        acl::ACLPROC_SETACL => {
            let (fh, mask, access, default) = acl::decode_setacl_args(args).map_err(garbage)?;
            let Some(path) = state.lock().unwrap().path_of(&fh) else {
                e.u32(NFS3ERR_STALE).bool(false);
                return Ok(e.into_bytes());
            };
            let outcome = (|| -> io::Result<()> {
                if mask & acl::NFS_ACL != 0 && !access.is_empty() {
                    crate::xattr::set(&path, acl::ACCESS_NAME, &acl::to_xattr(&access))?;
                }
                if mask & acl::NFS_DFACL != 0 && !default.is_empty() {
                    crate::xattr::set(&path, acl::DEFAULT_NAME, &acl::to_xattr(&default))?;
                }
                Ok(())
            })();
            match outcome {
                Ok(()) => e.u32(NFS3_OK).bool(false),
                Err(err) => e.u32(nfs_status(&err)).bool(false),
            };
        }
        _ => return Err(3),
    }
    Ok(e.into_bytes())
}

fn mount_proc(proc_: u32, args: &[u8], root_id: u64) -> Result<Vec<u8>, u32> {
    let mut e = Encoder::new();
    match proc_ {
        MOUNTPROC_NULL => {}
        MOUNTPROC_MNT => {
            let mut d = Decoder::new(args);
            let _path = d.string().map_err(|_| 4u32)?; // every path maps to the single export
            e.u32(0).opaque(&root_id.to_be_bytes()).u32(1).u32(1); // status, fh, auth flavors [AUTH_SYS]
        }
        MOUNTPROC_UMNT => {}
        MOUNTPROC_EXPORT => {
            e.bool(true)
                .string("/export")
                .bool(true)
                .string("127.0.0.0/8")
                .bool(false)
                .bool(false);
        }
        _ => return Err(3),
    }
    Ok(e.into_bytes())
}

fn now3() -> Time3 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Time3 {
        seconds: d.as_secs() as u32,
        nseconds: d.subsec_nanos(),
    }
}

fn attrs_of(path: &Path, id: u64) -> io::Result<Fattr3> {
    let m = fs::symlink_metadata(path)?;
    let ft = m.file_type();
    let ftype = if ft.is_dir() {
        NF3DIR
    } else if ft.is_file() {
        NF3REG
    } else if ft.is_symlink() {
        NF3LNK
    } else if ft.is_socket() {
        NF3SOCK
    } else if ft.is_fifo() {
        NF3FIFO
    } else if ft.is_block_device() {
        NF3BLK
    } else {
        NF3CHR
    };
    Ok(Fattr3 {
        ftype,
        mode: m.mode() & 0o7777,
        nlink: m.nlink() as u32,
        uid: m.uid(),
        gid: m.gid(),
        size: m.len(),
        used: m.blocks() * 512,
        rdev: (0, 0),
        fsid: 1,
        fileid: id,
        atime: Time3 {
            seconds: m.atime() as u32,
            nseconds: m.atime_nsec() as u32,
        },
        mtime: Time3 {
            seconds: m.mtime() as u32,
            nseconds: m.mtime_nsec() as u32,
        },
        ctime: Time3 {
            seconds: m.ctime() as u32,
            nseconds: m.ctime_nsec() as u32,
        },
    })
}

fn nfs_status(e: &io::Error) -> u32 {
    match e.kind() {
        io::ErrorKind::NotFound => NFS3ERR_NOENT,
        io::ErrorKind::PermissionDenied => NFS3ERR_ACCES,
        io::ErrorKind::AlreadyExists => NFS3ERR_EXIST,
        io::ErrorKind::NotADirectory => NFS3ERR_NOTDIR,
        io::ErrorKind::IsADirectory => NFS3ERR_ISDIR,
        io::ErrorKind::DirectoryNotEmpty => NFS3ERR_NOTEMPTY,
        io::ErrorKind::StorageFull => NFS3ERR_NOSPC,
        io::ErrorKind::InvalidInput => NFS3ERR_INVAL,
        _ => match e.raw_os_error() {
            Some(1) => 1,
            Some(39) => NFS3ERR_NOTEMPTY,
            _ => NFS3ERR_IO,
        },
    }
}

fn apply_sattr(path: &Path, s: &Sattr3) -> io::Result<()> {
    let is_link = fs::symlink_metadata(path)?.file_type().is_symlink();
    if s.uid.is_some() || s.gid.is_some() {
        lchown(path, s.uid, s.gid)?;
    }
    if is_link {
        return Ok(());
    }
    if let Some(size) = s.size {
        File::options().write(true).open(path)?.set_len(size)?;
    }
    if let Some(mode) = s.mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    if s.atime != SetTime::DontChange || s.mtime != SetTime::DontChange {
        let m = fs::metadata(path)?;
        let cur_a = UNIX_EPOCH + Duration::new(m.atime() as u64, m.atime_nsec() as u32);
        let cur_m = UNIX_EPOCH + Duration::new(m.mtime() as u64, m.mtime_nsec() as u32);
        let pick = |t: SetTime, cur: SystemTime| match t {
            SetTime::DontChange => cur,
            SetTime::ServerTime => SystemTime::now(),
            SetTime::Client(t) => UNIX_EPOCH + Duration::new(t.seconds as u64, t.nseconds),
        };
        File::options().read(true).open(path)?.set_times(
            FileTimes::new()
                .set_accessed(pick(s.atime, cur_a))
                .set_modified(pick(s.mtime, cur_m)),
        )?;
    }
    Ok(())
}

fn nfs_proc(proc_: u32, args: &[u8], state: &Arc<Mutex<State>>) -> Result<Vec<u8>, u32> {
    let mut d = Decoder::new(args);
    let mut e = Encoder::new();
    let garbage = |_: io::Error| 4u32;
    macro_rules! fail {
        ($e:expr, $status:expr) => {{
            $e.u32($status);
            return Ok($e.into_bytes());
        }};
    }
    // resolve a handle to a path, answering NFS3ERR_STALE when unknown
    macro_rules! path_of {
        ($fh:expr) => {
            match state.lock().unwrap().path_of($fh) {
                Some(p) => p,
                None => fail!(e, NFS3ERR_STALE),
            }
        };
    }
    // The two injected faults, decrementing so a bounded retry can get past them. Before
    // the NULL arm so a JUKEBOX reply is what EVERY procedure sees, which is how a real
    // server behaves while it is fetching from slow storage.
    {
        let mut st = state.lock().unwrap();
        if proc_ != NFSPROC_NULL && st.jukebox > 0 {
            st.jukebox -= 1;
            drop(st);
            fail!(e, NFS3ERR_JUKEBOX);
        }
    }
    match proc_ {
        NFSPROC_NULL => {}
        NFSPROC_GETATTR => {
            let fh = d.opaque().map_err(garbage)?;
            let path = path_of!(fh);
            // Only a NON-ROOT handle is made stale, and the check sits after the path is
            // resolved so it can tell them apart. The root's handle is fetched during
            // connect, before any cache exists, so faulting it would test the mount rather
            // than the thing this knob is for: a handle `fh_of` CACHED and never
            // invalidated, which is what a server restart or an export re-share produces.
            {
                let mut st = state.lock().unwrap();
                if st.stale_getattrs > 0 && path != st.root {
                    st.stale_getattrs -= 1;
                    drop(st);
                    fail!(e, NFS3ERR_STALE);
                }
            }
            let id = match state.lock().unwrap().id_for(&path) {
                Ok(i) => i,
                Err(err) => fail!(e, nfs_status(&err)),
            };
            match attrs_of(&path, id) {
                Ok(a) => {
                    e.u32(NFS3_OK);
                    a.encode(&mut e);
                }
                Err(err) => fail!(e, nfs_status(&err)),
            }
        }
        NFSPROC_SETATTR => {
            let fh = d.opaque().map_err(garbage)?;
            let s = Sattr3::decode(&mut d).map_err(garbage)?;
            let path = path_of!(fh);
            match apply_sattr(&path, &s) {
                Ok(()) => {
                    e.u32(NFS3_OK);
                    let id = match state.lock().unwrap().id_for(&path) {
                        Ok(i) => i,
                        Err(err) => fail!(e, nfs_status(&err)),
                    };
                    encode_wcc(&mut e, attrs_of(&path, id).ok().as_ref());
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_LOOKUP => {
            let fh = d.opaque().map_err(garbage)?;
            let name = d.string().map_err(garbage)?;
            let dir = path_of!(fh);
            let path = dir.join(&name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let id = match state.lock().unwrap().id_for(&path) {
                        Ok(i) => i,
                        Err(err) => fail!(e, nfs_status(&err)),
                    };
                    e.u32(NFS3_OK).opaque(&id.to_be_bytes());
                    encode_post_op_attr(&mut e, attrs_of(&path, id).ok().as_ref());
                    encode_post_op_attr(&mut e, None);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_post_op_attr(&mut e, None);
                }
            }
        }
        NFSPROC_ACCESS => {
            let fh = d.opaque().map_err(garbage)?;
            let mask = d.u32().map_err(garbage)?;
            let _ = path_of!(fh);
            e.u32(NFS3_OK);
            encode_post_op_attr(&mut e, None);
            e.u32(mask);
        }
        NFSPROC_READLINK => {
            let fh = d.opaque().map_err(garbage)?;
            let path = path_of!(fh);
            match fs::read_link(&path) {
                Ok(t) => {
                    e.u32(NFS3_OK);
                    encode_post_op_attr(&mut e, None);
                    e.string(&t.to_string_lossy());
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_post_op_attr(&mut e, None);
                }
            }
        }
        NFSPROC_READ => {
            let fh = d.opaque().map_err(garbage)?;
            let offset = d.u64().map_err(garbage)?;
            let count = d.u32().map_err(garbage)?;
            let path = path_of!(fh);
            let result = File::open(&path).and_then(|f| {
                let size = f.metadata()?.len();
                let mut buf = vec![0u8; count.min(1 << 20) as usize];
                let mut got = 0;
                while got < buf.len() {
                    let n = f.read_at(&mut buf[got..], offset + got as u64)?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
                buf.truncate(got);
                Ok((buf, offset + got as u64 >= size))
            });
            match result {
                Ok((data, eof)) => {
                    e.u32(NFS3_OK);
                    encode_post_op_attr(&mut e, None);
                    e.u32(data.len() as u32).bool(eof).opaque(&data);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_post_op_attr(&mut e, None);
                }
            }
        }
        NFSPROC_WRITE => {
            let fh = d.opaque().map_err(garbage)?;
            let offset = d.u64().map_err(garbage)?;
            let _count = d.u32().map_err(garbage)?;
            let _stable = d.u32().map_err(garbage)?;
            let data = d.opaque().map_err(garbage)?;
            let path = path_of!(fh);
            // a handle that is not a regular file is refused, as nfsd's S_IFREG check refuses it
            // (NFS3ERR_INVAL), rather than opened through
            match File::options()
                .write(true)
                .custom_flags(libc_o_nofollow())
                .open(&path)
                .map_err(|e| {
                    if e.raw_os_error() == Some(40) {
                        io::Error::from(io::ErrorKind::InvalidInput)
                    } else {
                        e
                    }
                })
                .and_then(|f| f.write_all_at(data, offset))
            {
                Ok(()) => {
                    e.u32(NFS3_OK);
                    encode_wcc(&mut e, None);
                    e.u32(data.len() as u32)
                        .u32(FILE_SYNC)
                        .u64(0x5243_5020_7465_7374);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_CREATE | NFSPROC_MKDIR | NFSPROC_SYMLINK => {
            let fh = d.opaque().map_err(garbage)?;
            let name = d.string().map_err(garbage)?;
            let how = if proc_ == NFSPROC_CREATE {
                d.u32().map_err(garbage)?
            } else {
                0
            };
            let s = Sattr3::decode(&mut d).map_err(garbage)?;
            let target = if proc_ == NFSPROC_SYMLINK {
                Some(d.string().map_err(garbage)?)
            } else {
                None
            };
            let dir = path_of!(fh);
            let path = dir.join(&name);
            // CREATE as Linux nfsd answers it (`nfsd3_create_file`): a name that exists is
            // EXIST for GUARDED and EXCLUSIVE; for UNCHECKED, a regular file is truncated and
            // anything else is handed back as it is, with its own handle and attributes. The
            // server never follows a symlink at the name -- this stand-in used to, with
            // `File::create`, which let a client that does not look at the reply pass here and
            // fail against a real server.
            let existing = fs::symlink_metadata(&path).ok();
            let strict = state.lock().unwrap().refuse_special_creates;
            let result = match proc_ {
                NFSPROC_CREATE => match existing {
                    Some(_) if how != 0 => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                    Some(m) if !m.is_file() && strict.is_some() => {
                        Err(io::Error::from(strict.expect("checked")))
                    }
                    Some(m) if !m.is_file() => Ok(()),
                    _ => File::options()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .custom_flags(libc_o_nofollow())
                        .open(&path)
                        .map(|_| ())
                        .and_then(|_| apply_sattr(&path, &s)),
                },
                NFSPROC_MKDIR => fs::create_dir(&path).and_then(|_| apply_sattr(&path, &s)),
                _ => symlink(target.unwrap_or_default(), &path),
            };
            match result {
                Ok(()) => {
                    let id = match state.lock().unwrap().id_for(&path) {
                        Ok(i) => i,
                        Err(err) => fail!(e, nfs_status(&err)),
                    };
                    e.u32(NFS3_OK).bool(true).opaque(&id.to_be_bytes());
                    encode_post_op_attr(&mut e, attrs_of(&path, id).ok().as_ref());
                    encode_wcc(&mut e, None);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_REMOVE | NFSPROC_RMDIR => {
            let fh = d.opaque().map_err(garbage)?;
            let name = d.string().map_err(garbage)?;
            let dir = path_of!(fh);
            let path = dir.join(&name);
            let result = if proc_ == NFSPROC_RMDIR {
                fs::remove_dir(&path)
            } else {
                fs::remove_file(&path)
            };
            match result {
                Ok(()) => {
                    e.u32(NFS3_OK);
                    encode_wcc(&mut e, None);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_RENAME => {
            let from_dir = d.opaque().map_err(garbage)?;
            let from_name = d.string().map_err(garbage)?;
            let to_dir = d.opaque().map_err(garbage)?;
            let to_name = d.string().map_err(garbage)?;
            let from = path_of!(from_dir).join(&from_name);
            let to = path_of!(to_dir).join(&to_name);
            match fs::rename(&from, &to) {
                Ok(()) => {
                    // the handle map follows the inode, which rename keeps
                    let _ = state.lock().unwrap().id_for(&to);
                    e.u32(NFS3_OK);
                    encode_wcc(&mut e, None);
                    encode_wcc(&mut e, None);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_wcc(&mut e, None);
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_LINK => {
            let fh = d.opaque().map_err(garbage)?;
            let dfh = d.opaque().map_err(garbage)?;
            let name = d.string().map_err(garbage)?;
            let file = path_of!(fh);
            let dir = path_of!(dfh);
            match fs::hard_link(&file, dir.join(&name)) {
                Ok(()) => {
                    e.u32(NFS3_OK);
                    encode_post_op_attr(&mut e, None);
                    encode_wcc(&mut e, None);
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_post_op_attr(&mut e, None);
                    encode_wcc(&mut e, None);
                }
            }
        }
        NFSPROC_READDIRPLUS => {
            let fh = d.opaque().map_err(garbage)?;
            let cookie = d.u64().map_err(garbage)?;
            let _verf = d.u64().map_err(garbage)?;
            let _dircount = d.u32().map_err(garbage)?;
            let _maxcount = d.u32().map_err(garbage)?;
            let dir = path_of!(fh);
            let mut names: Vec<String> = vec![".".into(), "..".into()];
            match fs::read_dir(&dir) {
                Ok(rd) => {
                    for entry in rd.flatten() {
                        names.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
                Err(err) => {
                    e.u32(nfs_status(&err));
                    encode_post_op_attr(&mut e, None);
                    return Ok(e.into_bytes());
                }
            }
            names[2..].sort();
            e.u32(NFS3_OK);
            encode_post_op_attr(&mut e, None);
            e.u64(1); // cookieverf
                      // small pages, so the client's cookie continuation is exercised on every tree
            const PAGE: usize = 5;
            let start = cookie as usize;
            let end = (start + PAGE).min(names.len());
            for (i, name) in names.iter().enumerate().take(end).skip(start) {
                let path = if name == "." {
                    dir.clone()
                } else if name == ".." {
                    dir.parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| dir.clone())
                } else {
                    dir.join(name)
                };
                let id = match state.lock().unwrap().id_for(&path) {
                    Ok(i) => i,
                    Err(err) => fail!(e, nfs_status(&err)),
                };
                e.bool(true).u64(id).string(name).u64(i as u64 + 1);
                encode_post_op_attr(&mut e, attrs_of(&path, id).ok().as_ref());
                e.bool(true).opaque(&id.to_be_bytes());
            }
            e.bool(false).bool(end >= names.len());
        }
        NFSPROC_FSSTAT => {
            let fh = d.opaque().map_err(garbage)?;
            let _ = path_of!(fh);
            e.u32(NFS3_OK);
            encode_post_op_attr(&mut e, None);
            // tbytes fbytes abytes tfiles ffiles afiles invarsec: a fixture-sized filesystem
            e.u64(1 << 40)
                .u64(1 << 39)
                .u64(1 << 39)
                .u64(1_000_000)
                .u64(900_000)
                .u64(900_000)
                .u32(0);
        }
        NFSPROC_FSINFO => {
            let fh = d.opaque().map_err(garbage)?;
            let _ = path_of!(fh);
            e.u32(NFS3_OK);
            encode_post_op_attr(&mut e, None);
            // rtmax rtpref rtmult wtmax wtpref wtmult dtpref maxfilesize time_delta properties
            e.u32(1 << 20)
                .u32(1 << 20)
                .u32(4096)
                .u32(1 << 20)
                .u32(1 << 20)
                .u32(4096)
                .u32(64 << 10)
                .u64(u64::MAX)
                .u32(0)
                .u32(1)
                .u32(0x1b);
        }
        NFSPROC_COMMIT => {
            let fh = d.opaque().map_err(garbage)?;
            let path = path_of!(fh);
            let _ = File::open(&path).and_then(|f| f.sync_all());
            e.u32(NFS3_OK);
            encode_wcc(&mut e, None);
            e.u64(0x5243_5020_7465_7374);
        }
        _ => return Err(3),
    }
    let _ = now3;
    Ok(e.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::rpc::{Connection, Credentials};

    #[test]
    fn mounts_and_answers_lookup_and_read() {
        let dir = std::env::temp_dir().join(format!("rcp-nfsd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/hello.txt"), b"hello over nfs").unwrap();
        let server = Server::start(&dir).unwrap();
        let mut c =
            Connection::connect(("127.0.0.1", server.port), Credentials::current()).unwrap();
        let root = res_mnt(
            &c.call(MOUNT_PROG, MOUNT_VERS, MOUNTPROC_MNT, &args_mnt("/export"))
                .unwrap(),
        )
        .unwrap();
        let (sub, attrs) = res_lookup(
            &c.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_LOOKUP,
                &args_diropargs(&root, "sub"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(attrs.unwrap().ftype, NF3DIR);
        let (file, _) = res_lookup(
            &c.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_LOOKUP,
                &args_diropargs(&sub, "hello.txt"),
            )
            .unwrap(),
        )
        .unwrap();
        let (data, eof) = res_read(
            &c.call(NFS_PROG, NFS_VERS, NFSPROC_READ, &args_read(&file, 6, 100))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data, b"over nfs");
        assert!(eof);
        let err = res_lookup(
            &c.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_LOOKUP,
                &args_diropargs(&sub, "missing"),
            )
            .unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let (entries, eof, _) = res_readdirplus(
            &c.call(
                NFS_PROG,
                NFS_VERS,
                NFSPROC_READDIRPLUS,
                &args_readdirplus(&root, 0, 0, 1024, 4096),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(entries.iter().any(|e| e.name == "sub"));
        assert!(eof);
        let _ = fs::remove_dir_all(&dir);
    }
}
