//! SUN RPC version 2 (RFC 5531) over TCP with record marking, AUTH_SYS credentials, and
//! pipelining: a connection can have many calls outstanding, and replies are matched to
//! calls by transaction ID. That is what lets one connection keep a filer busy.
//!
//! With Kerberos (`-nfs.sec krb5`, `krb5i`, `krb5p`) the credential is RPCSEC_GSS
//! (RFC 2203): a security context is established on each connection with the server's
//! `nfs@host` principal, every call's header carries a MIC in its verifier, and with
//! `krb5i` the body is checksummed, with `krb5p` encrypted; every reply's verifier is a MIC
//! over the call's sequence number and is checked. The context is per connection, so the
//! pipelining above is untouched.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::gss;
use crate::xdr::{Decoder, Encoder};

pub const PORTMAP_PROG: u32 = 100_000;
pub const NFS_PROG: u32 = 100_003;
pub const MOUNT_PROG: u32 = 100_005;

/// The largest RPC record this client will hold. A record is one whole RPC message, so
/// the ceiling has to clear the biggest READ or WRITE the mount negotiates (typically 1
/// MiB, and this client asks for no more) with room for the headers and a generous
/// server. Anything past it is a server claiming more than any NFS exchange needs.
pub(crate) const MAX_RECORD: usize = 64 << 20;

/// The prefix every RPC-level rejection of a CALL carries, and the only thing that tells
/// one apart from an NFS status refusing one OBJECT. Both arrive as `PermissionDenied`.
pub(crate) const REJECTED: &str = "RPC call rejected";

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const REPLY_ACCEPTED: u32 = 0;
const ACCEPT_SUCCESS: u32 = 0;
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
pub const RPCSEC_GSS: u32 = 6;

/// RPCSEC_GSS control and data procedures (the `gss_proc` field of the credential).
pub const RPCSEC_GSS_VERS: u32 = 1;
pub const GSS_PROC_DATA: u32 = 0;
pub const GSS_PROC_INIT: u32 = 1;
pub const GSS_PROC_CONTINUE_INIT: u32 = 2;
pub const GSS_PROC_DESTROY: u32 = 3;
/// The three services: authentication only, integrity (MIC on the body), privacy
/// (encrypted body).
pub const GSS_SVC_NONE: u32 = 1;
pub const GSS_SVC_INTEGRITY: u32 = 2;
pub const GSS_SVC_PRIVACY: u32 = 3;
/// Auth-status codes a server rejects with when the context is bad.
pub const RPCSEC_GSS_CREDPROBLEM: u32 = 13;
pub const RPCSEC_GSS_CTXPROBLEM: u32 = 14;

/// The security an NFS endpoint is reached with: the `sec=` of a mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Security {
    #[default]
    Sys,
    Krb5,
    Krb5i,
    Krb5p,
}

impl Security {
    pub fn parse(s: &str) -> Option<Security> {
        match s.to_ascii_lowercase().as_str() {
            "sys" | "unix" | "auth_sys" => Some(Security::Sys),
            "krb5" => Some(Security::Krb5),
            "krb5i" => Some(Security::Krb5i),
            "krb5p" => Some(Security::Krb5p),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Security::Sys => "sys",
            Security::Krb5 => "krb5",
            Security::Krb5i => "krb5i",
            Security::Krb5p => "krb5p",
        }
    }
    fn service(self) -> u32 {
        match self {
            Security::Sys | Security::Krb5 => GSS_SVC_NONE,
            Security::Krb5i => GSS_SVC_INTEGRITY,
            Security::Krb5p => GSS_SVC_PRIVACY,
        }
    }
}

/// What a connection signs with: nothing beyond AUTH_SYS, or an established GSS context.
enum Auth {
    Sys,
    Gss {
        ctx: gss::Context,
        handle: Vec<u8>,
        service: u32,
        seq: u32,
        /// The sequence number sent with each call still in flight, by XID: the reply's
        /// verifier is a MIC over it.
        seqs: BTreeMap<u32, u32>,
    },
}

/// The RPC verifier of a reply, and the body after the accept status.
struct Reply {
    xid: u32,
    verf_flavor: u32,
    verf: Vec<u8>,
    body: io::Result<Vec<u8>>,
}

/// Who the server sees: AUTH_SYS carries uid, gid, machine name and groups in the clear.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    pub machine: String,
    pub groups: Vec<u32>,
}

impl Credentials {
    pub fn current() -> Credentials {
        let uid = std::fs::metadata("/proc/self")
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
            .unwrap_or(0);
        let gid = std::fs::metadata("/proc/self")
            .map(|m| std::os::unix::fs::MetadataExt::gid(&m))
            .unwrap_or(0);
        let machine = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "rcp".into());
        Credentials {
            uid,
            gid,
            machine,
            groups: vec![gid],
        }
    }

    fn encode(&self, e: &mut Encoder) {
        let mut body = Encoder::new();
        body.u32(0); // stamp
        body.string(&self.machine);
        body.u32(self.uid).u32(self.gid);
        body.u32(self.groups.len().min(16) as u32);
        for g in self.groups.iter().take(16) {
            body.u32(*g);
        }
        e.u32(AUTH_SYS).opaque(&body.into_bytes());
        e.u32(AUTH_NONE).u32(0); // verifier
    }
}

/// One TCP connection, with calls in flight tracked by XID.
pub struct Connection {
    stream: TcpStream,
    next_xid: u32,
    creds: Credentials,
    auth: Auth,
    /// Replies that arrived while waiting for a different XID.
    parked: BTreeMap<u32, Vec<u8>>,
    pub inflight: usize,
}

/// A failure the server reported rather than a transport failure.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub xid: u32,
    pub what: String,
}

impl Connection {
    /// `addr` is `(host, port)` everywhere it is called. The host is unbracketed here --
    /// the crate's SECOND resolver call site, and an easy one to assume is covered by the
    /// strip in `net::http::connect_tcp` when it is not.
    ///
    /// `Endpoint::nfs` strips brackets at PARSE time, which covers `nfs://[::1]/export`,
    /// and does not cover every socket: `rcp show '[::1]'` hands the token straight to
    /// `rpc::dump`, and `nfs://[::1]:2049/export` does not end in `]` so the parse-time
    /// strip is a no-op on it. Stripping at the dial covers all of them, and is where the
    /// HTTP client does it.
    pub fn connect(addr: (&str, u16), creds: Credentials) -> io::Result<Connection> {
        let host = crate::unbracketed(addr.0);
        let addrs: Vec<_> = (host.as_ref(), addr.1).to_socket_addrs()?.collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for a in addrs {
            match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
                    let seed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos())
                        .unwrap_or(1);
                    return Ok(Connection {
                        stream,
                        next_xid: seed | 1,
                        creds,
                        auth: Auth::Sys,
                        parked: BTreeMap::new(),
                        inflight: 0,
                    });
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// A connection with the given security: AUTH_SYS as `connect`, or a Kerberos
    /// context established with `nfs@host` through the NULL procedure of `prog`/`vers`.
    pub fn connect_secure(
        addr: (&str, u16),
        creds: Credentials,
        sec: Security,
        host: &str,
        prog: u32,
        vers: u32,
    ) -> io::Result<Connection> {
        let mut c = Connection::connect(addr, creds)?;
        if sec != Security::Sys {
            c.establish_gss(host, sec, prog, vers)?;
        }
        Ok(c)
    }

    /// Whether the connection carries a Kerberos context.
    pub fn is_secure(&self) -> bool {
        matches!(self.auth, Auth::Gss { .. })
    }

    fn write_record(&mut self, msg: &[u8]) -> io::Result<()> {
        // record marking: last-fragment bit plus length
        let header = (0x8000_0000u32 | msg.len() as u32).to_be_bytes();
        self.stream.write_all(&header)?;
        self.stream.write_all(msg)
    }

    /// RPCSEC_GSS context establishment (RFC 2203, section 5.2): INIT, then CONTINUE_INIT
    /// while either side has more to say, over the NULL procedure. A Kerberos exchange with
    /// mutual authentication is one round trip.
    fn establish_gss(&mut self, host: &str, sec: Security, prog: u32, vers: u32) -> io::Result<()> {
        let service = sec.service();
        let mut flags = gss::GSS_C_MUTUAL_FLAG | gss::GSS_C_INTEG_FLAG;
        if service == GSS_SVC_PRIVACY {
            flags |= gss::GSS_C_CONF_FLAG;
        }
        let target = format!("nfs@{host}");
        let mut ctx = gss::Context::initiator(&target, gss::Mech::Krb5, flags)?;
        let mut handle: Vec<u8> = Vec::new();
        let mut input: Option<Vec<u8>> = None;
        let mut proc_ = GSS_PROC_INIT;
        let mut window_verf: Option<(u32, Vec<u8>)> = None;
        loop {
            let step = ctx
                .init_step(input.as_deref())
                .map_err(|e| io::Error::new(e.kind(), format!("Kerberos for {target}: {e}")))?;
            if step.token.is_empty() {
                break;
            }
            let xid = self.next_xid;
            self.next_xid = self.next_xid.wrapping_add(2);
            let mut e = Encoder::new();
            e.u32(xid).u32(MSG_CALL).u32(2).u32(prog).u32(vers).u32(0);
            let mut cred = Encoder::new();
            cred.u32(RPCSEC_GSS_VERS)
                .u32(proc_)
                .u32(0)
                .u32(service)
                .opaque(&handle);
            e.u32(RPCSEC_GSS).opaque(&cred.into_bytes());
            e.u32(AUTH_NONE).u32(0);
            e.opaque(&step.token);
            let msg = e.into_bytes();
            self.write_record(&msg)?;
            let record = self.read_record()?;
            let reply = Self::parse_reply(&record)?;
            if reply.xid != xid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RPCSEC_GSS: the server answered a different call",
                ));
            }
            let body = reply.body.map_err(|e| {
                io::Error::new(e.kind(), format!("RPCSEC_GSS context with {target}: {e}"))
            })?;
            let mut d = Decoder::new(&body);
            let new_handle = d.opaque()?.to_vec();
            let major = d.u32()?;
            let minor = d.u32()?;
            let window = d.u32()?;
            let token = d.opaque()?.to_vec();
            if major != 0 && major != 1 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("RPCSEC_GSS: the server refused the Kerberos context for {target} (GSS major {major:#x}, minor {minor})")));
            }
            handle = new_handle;
            if reply.verf_flavor == RPCSEC_GSS {
                window_verf = Some((window, reply.verf));
            }
            if step.complete && major == 0 {
                break;
            }
            input = Some(token);
            proc_ = GSS_PROC_CONTINUE_INIT;
            if major == 0 && input.as_ref().is_some_and(|t| t.is_empty()) {
                // the server is done and sent nothing more: our context must be complete
                if !ctx.established {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RPCSEC_GSS: the server finished before the Kerberos context did",
                    ));
                }
                break;
            }
        }
        if !ctx.established {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("RPCSEC_GSS: the Kerberos context with {target} was not established"),
            ));
        }
        // the server's verifier on the final control reply is a MIC over its window
        if let Some((window, verf)) = window_verf {
            let mut w = Encoder::new();
            w.u32(window);
            ctx.verify_mic(&w.into_bytes(), &verf).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("RPCSEC_GSS: the server's context verifier did not check out: {e}"),
                )
            })?;
        }
        self.auth = Auth::Gss {
            ctx,
            handle,
            service,
            seq: 0,
            seqs: BTreeMap::new(),
        };
        Ok(())
    }

    /// Sends a call and returns its XID without waiting.
    pub fn send(&mut self, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> io::Result<u32> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(2);
        let mut e = Encoder::new();
        e.u32(xid)
            .u32(MSG_CALL)
            .u32(2)
            .u32(prog)
            .u32(vers)
            .u32(proc_);
        let msg = match &mut self.auth {
            Auth::Sys => {
                self.creds.encode(&mut e);
                let mut msg = e.into_bytes();
                msg.extend_from_slice(args);
                msg
            }
            Auth::Gss {
                ctx,
                handle,
                service,
                seq,
                seqs,
            } => {
                *seq += 1;
                let s = *seq;
                seqs.insert(xid, s);
                let mut cred = Encoder::new();
                cred.u32(RPCSEC_GSS_VERS)
                    .u32(GSS_PROC_DATA)
                    .u32(s)
                    .u32(*service)
                    .opaque(handle);
                e.u32(RPCSEC_GSS).opaque(&cred.into_bytes());
                // the verifier: a MIC over the header so far (xid through the credential)
                let mic = ctx.mic(&e.buf)?;
                e.u32(RPCSEC_GSS).opaque(&mic);
                let mut msg = e.into_bytes();
                match *service {
                    GSS_SVC_INTEGRITY => {
                        let mut body = Encoder::new();
                        body.u32(s);
                        let mut body = body.into_bytes();
                        body.extend_from_slice(args);
                        let mic = ctx.mic(&body)?;
                        let mut b = Encoder::new();
                        b.opaque(&body).opaque(&mic);
                        msg.extend_from_slice(&b.into_bytes());
                    }
                    GSS_SVC_PRIVACY => {
                        let mut body = Encoder::new();
                        body.u32(s);
                        let mut body = body.into_bytes();
                        body.extend_from_slice(args);
                        let wrapped = ctx.wrap(&body, true)?;
                        let mut b = Encoder::new();
                        b.opaque(&wrapped);
                        msg.extend_from_slice(&b.into_bytes());
                    }
                    _ => msg.extend_from_slice(args),
                }
                msg
            }
        };
        self.write_record(&msg)?;
        self.inflight += 1;
        Ok(xid)
    }

    /// Checks a reply's verifier and unwraps its body under the connection's context.
    fn finish_reply(&mut self, reply: Reply) -> (u32, io::Result<Vec<u8>>) {
        let Auth::Gss {
            ctx, service, seqs, ..
        } = &mut self.auth
        else {
            return (reply.xid, reply.body);
        };
        let seq = seqs.remove(&reply.xid);
        let body = match reply.body {
            Err(e) => Err(e),
            Ok(body) => (|| {
                let Some(seq) = seq else { return Ok(body) }; // a control reply
                if reply.verf_flavor != RPCSEC_GSS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RPCSEC_GSS: the reply carries no GSS verifier",
                    ));
                }
                let mut w = Encoder::new();
                w.u32(seq);
                ctx.verify_mic(&w.into_bytes(), &reply.verf).map_err(|e| {
                    io::Error::new(e.kind(), format!("RPCSEC_GSS: reply verifier: {e}"))
                })?;
                match *service {
                    GSS_SVC_INTEGRITY => {
                        let mut d = Decoder::new(&body);
                        let data = d.opaque()?.to_vec();
                        let mic = d.opaque()?;
                        ctx.verify_mic(&data, mic).map_err(|e| {
                            io::Error::new(
                                e.kind(),
                                format!("RPCSEC_GSS: reply body checksum: {e}"),
                            )
                        })?;
                        Self::strip_seq(data, seq)
                    }
                    GSS_SVC_PRIVACY => {
                        let mut d = Decoder::new(&body);
                        let wrapped = d.opaque()?;
                        let data = ctx.unwrap(wrapped, true).map_err(|e| {
                            io::Error::new(e.kind(), format!("RPCSEC_GSS: reply body: {e}"))
                        })?;
                        Self::strip_seq(data, seq)
                    }
                    _ => Ok(body),
                }
            })(),
        };
        (reply.xid, body)
    }

    fn strip_seq(data: Vec<u8>, seq: u32) -> io::Result<Vec<u8>> {
        let mut d = Decoder::new(&data);
        if d.u32()? != seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPCSEC_GSS: the reply body carries another call's sequence number",
            ));
        }
        Ok(data[4..].to_vec())
    }

    /// Reads one record (all fragments) from the stream.
    fn read_record(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut h = [0u8; 4];
            self.stream.read_exact(&mut h)?;
            let v = u32::from_be_bytes(h);
            let len = (v & 0x7fff_ffff) as usize;
            // BOUNDED. `out.resize(start + len, 0)` both allocates AND zero-fills before a
            // single payload byte arrives, so unbounded, the fragment header alone commits
            // resident memory. Measured without the bound: a 4-byte header claiming
            // 0x7fffffff against a server that then sent NOTHING took VmRSS from 3,288 kB
            // to 2,098,904 kB -- two gigabytes resident, bought with four bytes -- and a
            // fragment chain with no terminator added 768 MiB more. `Pool::take` opens a
            // connection per worker with no cap, so it is per connection.
            //
            // This crate's other two framed protocols do the same, in the same place in the
            // same shaped function: `remote::proto` caps at `MAX_FRAME` (16 MiB) and
            // `sftp::proto` at `MAX_PACKET` (1 MiB).
            // A record is a whole RPC message including a READ's data, so the ceiling is
            // the largest transfer size this client ever negotiates plus headroom.
            if len > MAX_RECORD || out.len().saturating_add(len) > MAX_RECORD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the server's RPC record claims {} bytes, over the {MAX_RECORD} limit",
                        out.len().saturating_add(len)
                    ),
                ));
            }
            let start = out.len();
            out.resize(start + len, 0);
            self.stream.read_exact(&mut out[start..])?;
            if v & 0x8000_0000 != 0 {
                return Ok(out);
            }
        }
    }

    /// Waits for the reply to `xid`, parking other replies that arrive first. Returns the
    /// reply body after the RPC header, or the server's rejection as an error.
    pub fn recv(&mut self, xid: u32) -> io::Result<Vec<u8>> {
        loop {
            if let Some(body) = self.parked.remove(&xid) {
                self.inflight -= 1;
                return Ok(body);
            }
            let record = self.read_record()?;
            let reply = Self::parse_reply(&record)?;
            let (got, body) = self.finish_reply(reply);
            if got == xid {
                self.inflight -= 1;
                return body;
            }
            match body {
                Ok(b) => {
                    self.parked.insert(got, b);
                }
                Err(e) => {
                    // a rejection for another xid: park it as an error marker
                    self.parked.insert(got, format!("\0RPCERR{e}").into_bytes());
                }
            }
        }
    }

    /// Waits for whichever reply arrives next.
    pub fn recv_any(&mut self) -> io::Result<(u32, io::Result<Vec<u8>>)> {
        if let Some((&xid, _)) = self.parked.iter().next() {
            let body = self.parked.remove(&xid).expect("present");
            self.inflight -= 1;
            return Ok((xid, Self::unpark(body)));
        }
        let record = self.read_record()?;
        let reply = Self::parse_reply(&record)?;
        let (xid, body) = self.finish_reply(reply);
        self.inflight -= 1;
        Ok((xid, body))
    }

    fn unpark(body: Vec<u8>) -> io::Result<Vec<u8>> {
        if body.starts_with(b"\0RPCERR") {
            Err(io::Error::other(
                String::from_utf8_lossy(&body[7..]).into_owned(),
            ))
        } else {
            Ok(body)
        }
    }

    fn parse_reply(record: &[u8]) -> io::Result<Reply> {
        let mut d = Decoder::new(record);
        let xid = d.u32()?;
        if d.u32()? != MSG_REPLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPC message is not a reply",
            ));
        }
        let status = d.u32()?;
        if status != REPLY_ACCEPTED {
            let why = d.u32().unwrap_or(0);
            let text = if why == 1 {
                let stat = d.u32().unwrap_or(0);
                match stat {
                    1 => "RPC call rejected: bad credential (AUTH_BADCRED); check the security the export requires (-nfs.sec)".to_string(),
                    2 => "RPC call rejected: the credential was rejected (AUTH_REJECTEDCRED)".to_string(),
                    5 => "RPC call rejected: this security flavor is too weak for the export (AUTH_TOOWEAK); the export wants Kerberos (-nfs.sec krb5, krb5i or krb5p)".to_string(),
                    RPCSEC_GSS_CREDPROBLEM => "RPC call rejected: the Kerberos credential was not accepted (RPCSEC_GSS_CREDPROBLEM)".to_string(),
                    RPCSEC_GSS_CTXPROBLEM => "RPC call rejected: the Kerberos context is no longer valid (RPCSEC_GSS_CTXPROBLEM); the ticket may have expired".to_string(),
                    n => format!("RPC call rejected: authentication error {n}; check AUTH_SYS credentials and the export's root squash"),
                }
            } else {
                format!("RPC call rejected (reason {why})")
            };
            // Every branch above starts with `REJECTED`, and that prefix is load-bearing:
            // it is how a caller tells an RPC-level refusal of the CALL from an NFS status
            // refusing one OBJECT. Both are `PermissionDenied`, and `Removed::or_refused`
            // maps that kind to `Kept`, whose remedy is "run `sync` again" -- which cannot
            // fix a credential. See `nfs::rejected_the_call`.
            debug_assert!(
                text.starts_with(REJECTED),
                "an RPC rejection that {REJECTED:?} does not match: {text}"
            );
            return Ok(Reply {
                xid,
                verf_flavor: AUTH_NONE,
                verf: Vec::new(),
                body: Err(io::Error::new(io::ErrorKind::PermissionDenied, text)),
            });
        }
        let verf_flavor = d.u32()?;
        let verf = d.opaque()?.to_vec();
        let accept = d.u32()?;
        if accept != ACCEPT_SUCCESS {
            let what = match accept {
                1 => "program unavailable on this server".to_string(),
                2 => "program version mismatch".to_string(),
                3 => "procedure unavailable".to_string(),
                4 => "garbage arguments".to_string(),
                5 => "server system error".to_string(),
                n => format!("accept status {n}"),
            };
            return Ok(Reply {
                xid,
                verf_flavor,
                verf,
                body: Err(io::Error::other(format!("RPC: {what}"))),
            });
        }
        Ok(Reply {
            xid,
            verf_flavor,
            verf,
            body: Ok(record[record.len() - d.remaining()..].to_vec()),
        })
    }

    /// A call that waits for its own reply.
    pub fn call(&mut self, prog: u32, vers: u32, proc_: u32, args: &[u8]) -> io::Result<Vec<u8>> {
        let xid = self.send(prog, vers, proc_, args)?;
        self.recv(xid)
    }
}

/// The portmapper's port: 111, unless `RCP_PORTMAP_PORT` says otherwise (the stand-in server).
pub fn portmap_port() -> u16 {
    std::env::var("RCP_PORTMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(111)
}

/// One registration with the portmapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub prog: u32,
    pub vers: u32,
    /// 6 for TCP, 17 for UDP.
    pub prot: u32,
    pub port: u32,
}

/// PORTMAP v2 DUMP: every program registered on `host`.
pub fn dump(host: &str) -> io::Result<Vec<Mapping>> {
    let mut c = Connection::connect((host, portmap_port()), Credentials::current())?;
    let reply = c.call(PORTMAP_PROG, 2, 4, &[])?;
    let mut d = Decoder::new(&reply);
    let mut out = Vec::new();
    while d.u32()? != 0 {
        out.push(Mapping {
            prog: d.u32()?,
            vers: d.u32()?,
            prot: d.u32()?,
            port: d.u32()?,
        });
    }
    Ok(out)
}

/// PORTMAP v2 GETPORT: where a program listens on `host`.
pub fn getport(host: &str, prog: u32, vers: u32) -> io::Result<u16> {
    let mut c = Connection::connect((host, portmap_port()), Credentials::current())?;
    let mut e = Encoder::new();
    e.u32(prog).u32(vers).u32(6).u32(0); // IPPROTO_TCP
    let reply = c.call(PORTMAP_PROG, 2, 3, &e.into_bytes())?;
    let port = Decoder::new(&reply).u32()?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host}: program {prog} version {vers} is not registered with the portmapper"),
        ));
    }
    Ok(port as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A server that answers calls out of order, to prove replies are matched by XID.
    fn reversing_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut pending: Vec<(u32, Vec<u8>)> = Vec::new();
            loop {
                let mut h = [0u8; 4];
                if s.read_exact(&mut h).is_err() {
                    return;
                }
                let len = (u32::from_be_bytes(h) & 0x7fff_ffff) as usize;
                let mut msg = vec![0u8; len];
                s.read_exact(&mut msg).unwrap();
                let mut d = Decoder::new(&msg);
                let xid = d.u32().unwrap();
                // skip: msg type, rpcvers, prog, vers, proc, cred, verf
                for _ in 0..5 {
                    d.u32().unwrap();
                }
                d.u32().unwrap();
                d.opaque().unwrap();
                d.u32().unwrap();
                d.opaque().unwrap();
                let arg = d.u32().unwrap();
                pending.push((xid, arg.to_be_bytes().to_vec()));
                if pending.len() == 3 {
                    for (xid, body) in pending.drain(..).rev() {
                        let mut e = Encoder::new();
                        e.u32(xid)
                            .u32(MSG_REPLY)
                            .u32(REPLY_ACCEPTED)
                            .u32(AUTH_NONE)
                            .opaque(&[])
                            .u32(ACCEPT_SUCCESS);
                        let mut out = e.into_bytes();
                        out.extend_from_slice(&body);
                        s.write_all(&(0x8000_0000u32 | out.len() as u32).to_be_bytes())
                            .unwrap();
                        s.write_all(&out).unwrap();
                    }
                }
            }
        });
        port
    }

    #[test]
    fn replies_are_matched_by_xid_even_out_of_order() {
        let port = reversing_server();
        let mut c = Connection::connect(("127.0.0.1", port), Credentials::current()).unwrap();
        let xids: Vec<u32> = (1..=3)
            .map(|i| {
                c.send(NFS_PROG, 3, 0, &Encoder::new().u32(i * 10).buf)
                    .unwrap()
            })
            .collect();
        assert_eq!(c.inflight, 3);
        // ask for them in sending order although the server answers reversed
        for (i, xid) in xids.iter().enumerate() {
            let body = c.recv(*xid).unwrap();
            assert_eq!(Decoder::new(&body).u32().unwrap(), (i as u32 + 1) * 10);
        }
        assert_eq!(c.inflight, 0);
    }
}
