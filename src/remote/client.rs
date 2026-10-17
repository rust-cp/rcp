//! `SshTree`: the `Tree` port over an `rcp serve` reached through ssh (or any command
//! `RCP_SSH` names, which is how the contract suite reaches a serve without a daemon).
//! One ssh session per pooled channel, as many channels as the run has workers; each
//! channel is a sequential request stream. A copy reads through SEGMENTS, which the server
//! streams without waiting, and writes through a window of pipelined WRITEs; the `Read`
//! path (verify, and any caller of `open`) is one request per block and pays a round trip
//! each, which is the known cost until it gets a read-ahead. Holes travel as lengths in
//! both directions, so a sparse file stays sparse over the wire.

use std::collections::VecDeque;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use super::proto::Codec;
use super::proto::*;
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::ports::{
    Basis, ChunkSig, Digests, FileOptions, FileOutcome, Item, Listing, Log, MetaOptions, Patch,
    Refusals, Removed, Runtime, Segment, Sink, Tree,
};
use crate::xdr::{Decoder, Encoder};

const WRITE_WINDOW: usize = 16;
/// READs kept in flight ahead of a sequential reader.
const READ_WINDOW: usize = 8;
const BLOCK: u32 = 1 << 20;

/// How `ssh://` endpoints are reached: the ssh command (`RCP_SSH` overrides it), the rcp
/// on the far side (`-rcp.remote`, default `rcp`), and where debug lines go.
#[derive(Clone)]
pub struct Settings {
    pub ssh: String,
    pub remote_rcp: String,
    /// Ask the far side to compress the data payloads (`-compress`).
    pub compress: bool,
    /// Which compressor to ask for (`-compress.codec`). The far side answers with the one
    /// it will actually use.
    pub codec: Codec,
    /// How hard to compress, 1..=9 (`-compress.level`), DEFLATE only. Unlike the codec
    /// this needs no agreement -- a DEFLATE stream is self-describing -- so it is sent as
    /// a request and never answered.
    pub level: u8,
    /// Certificates and keys for `rcps://`. Empty unless the run named some.
    pub tls: super::TlsFiles,
    pub log: Arc<dyn Log>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("ssh", &self.ssh)
            .field("remote_rcp", &self.remote_rcp)
            .finish()
    }
}

impl Settings {
    pub fn from_env(log: Arc<dyn Log>) -> Settings {
        let path = |var: &str| {
            std::env::var(var)
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        };
        // The same four names `rcp mcp` relays, read here so a serve or a child gets them
        // without the option. An option on the command line overrides this; see `main`.
        let tls = super::TlsFiles {
            ca: path("RCP_TLS_CA"),
            cert: path("RCP_TLS_CERT"),
            key: path("RCP_TLS_KEY"),
            client_ca: path("RCP_TLS_CLIENTCA"),
        };
        Settings {
            ssh: std::env::var("RCP_SSH")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "ssh".into()),
            remote_rcp: std::env::var("RCP_REMOTE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "rcp".into()),
            compress: false,
            codec: Codec::default(),
            level: DEFAULT_LEVEL,
            tls,
            log,
        }
    }
}

/// One request stream to one `rcp serve`.
struct Channel {
    /// None for a channel over in-memory streams, which is how the reply rules are tested.
    child: Option<Child>,
    input: Box<dyn Read + Send>,
    output: Box<dyn Write + Send>,
    next_seq: u32,
    /// Sequence numbers sent and not yet received, in order.
    inflight: VecDeque<u32>,
    /// Payload compression on this stream, once HELLO agreed to it.
    squeeze: Squeeze,
}

fn remote_error(status: u32, text: String) -> io::Error {
    io::Error::new(error_kind_of(status - 1), text)
}

/// How a channel reaches its `rcp serve`.
///
/// `ssh://` spawns OpenSSH, which authenticates the peer and starts the far side as that
/// user before a frame moves. `rcp://` opens a socket to a listener that has already been
/// started, which authenticates NOBODY -- see `server::check_listen` for the rules that
/// makes acceptable.
#[derive(Clone, Debug)]
pub enum Dial {
    Ssh {
        user: Option<String>,
        host: String,
        port: Option<u16>,
    },
    /// `host` is kept beside `addr` because they are not the same question: `addr` is what
    /// `connect` dials (brackets and all), and `host` is the name a certificate has to
    /// carry. For plaintext only the first matters; for `rcps://` both do.
    Tcp {
        host: String,
        addr: String,
        secure: bool,
    },
}

impl Dial {
    /// The one place `host` and `port` become an address to dial, so the IPv6 bracket rule
    /// is applied once rather than at each caller.
    pub fn tcp(host: &str, port: u16, secure: bool) -> Dial {
        Dial::Tcp {
            host: host.to_string(),
            addr: crate::host_port_for_dial(host, port),
            secure,
        }
    }

    /// How this endpoint prints in reports and errors.
    fn scheme(&self) -> String {
        match self {
            Dial::Ssh { user, host, port } => format!(
                "ssh://{}{host}{}",
                user.as_ref().map(|u| format!("{u}@")).unwrap_or_default(),
                port.map(|p| format!(":{p}")).unwrap_or_default()
            ),
            Dial::Tcp { addr, secure, .. } => {
                format!("{}://{addr}", if *secure { "rcps" } else { "rcp" })
            }
        }
    }
}

impl Channel {
    fn dial(settings: &Settings, d: &Dial) -> io::Result<Channel> {
        match d {
            Dial::Ssh { user, host, port } => Channel::open(settings, user.as_deref(), host, *port),
            Dial::Tcp { host, addr, secure } => match secure {
                false => Channel::open_tcp(addr),
                true => Channel::open_tls(settings, host, addr),
            },
        }
    }

    /// A channel straight to a listening `rcp serve`. No child process: the socket is the
    /// channel, cloned so the reads and the writes are independent handles.
    fn open_tcp(addr: &str) -> io::Result<Channel> {
        let stream = std::net::TcpStream::connect(addr)
            .map_err(|e| io::Error::new(e.kind(), format!("rcp://{addr}: {e}")))?;
        // Nagle batches small writes waiting for an ack, which is exactly wrong for a
        // request/reply protocol: every call would pay up to 40 ms before its frame left.
        let _ = stream.set_nodelay(true);
        let reader = stream.try_clone()?;
        let input = Box::new(BufReader::with_capacity(1 << 20, reader));
        let output = Box::new(BufWriter::with_capacity(1 << 20, stream));
        Ok(Channel {
            child: None,
            input,
            output,
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        })
    }

    /// The same channel inside TLS. One stream serves both directions -- a TLS connection
    /// is one piece of state and does not split the way a socket does -- so the reader and
    /// the writer share it; `tls::Shared` says why that cannot deadlock here.
    ///
    /// The configuration is built per channel rather than cached on the pool, and that was
    /// measured rather than waved through: one build is **1.6 ms** and eight (the channels
    /// a `-parallel 8` run opens) are **13 ms**, once, at startup. The S3 client caches its
    /// config on the target because it opens a connection per request; a channel here lives
    /// for the whole run. Caching would add shared mutable state to `Settings` to save an
    /// eighth of the time the first `ls` takes.
    #[cfg(feature = "rustls")]
    fn open_tls(settings: &Settings, host: &str, addr: &str) -> io::Result<Channel> {
        let cfg = super::tls::client_config(&settings.tls)?;
        let stream = super::tls::connect(&cfg, host, addr)?;
        let shared = super::tls::Shared::new(stream);
        let input = Box::new(BufReader::with_capacity(1 << 20, shared.clone()));
        let output = Box::new(BufWriter::with_capacity(1 << 20, shared));
        Ok(Channel {
            child: None,
            input,
            output,
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        })
    }

    #[cfg(not(feature = "rustls"))]
    fn open_tls(_settings: &Settings, _host: &str, addr: &str) -> io::Result<Channel> {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("rcps://{addr}: this rcp was built without the rustls feature (cargo build --features rustls); rcp:// is the plaintext scheme, loopback only")))
    }

    fn open(
        settings: &Settings,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> io::Result<Channel> {
        let mut c = Command::new(&settings.ssh);
        c.arg("-o").arg("BatchMode=yes");
        if let Some(p) = port {
            c.arg("-p").arg(p.to_string());
        }
        let target = match user {
            Some(u) => format!("{u}@{host}"),
            None => host.to_string(),
        };
        c.arg(target).arg(format!("{} serve", settings.remote_rcp));
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
        Ok(Channel {
            child: Some(child),
            input,
            output,
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        })
    }

    /// Names the tree to serve and asks for compression when the settings want it; the
    /// far side's rcp version comes back, and whether it compresses (a serve from before
    /// compression answers with no flag, which is a no).
    fn hello(
        &mut self,
        target: &str,
        create: bool,
        compress: bool,
        codec: Codec,
        level: u8,
    ) -> io::Result<Greeting> {
        self.greet(OP_HELLO, target, create, compress, codec, level)
    }

    /// HELLO or ATTACH: the same body and the same reply, and a different promise about
    /// what the far side checks (see `OP_ATTACH`).
    fn greet(
        &mut self,
        op: u32,
        target: &str,
        create: bool,
        compress: bool,
        codec: Codec,
        level: u8,
    ) -> io::Result<Greeting> {
        let mut e = Encoder::new();
        // Raw and LZ4 ask with version 5, exactly as every peer since compression has; any
        // other codec asks with version 6 and names itself (see `CODEC_VERSION`). A serve
        // that does not speak 6 refuses it by version, before it reads a path, so asking
        // for zstd or DEFLATE from an older serve fails with a reason instead of a stream
        // it cannot read.
        let named = compress && codec != Codec::Lz4;
        if named {
            e.u32(CODEC_VERSION)
                .string(target)
                .bool(create)
                .u32(codec.flag());
            // DEFLATE's level rides last, and only for DEFLATE: the original zstd-only v6
            // HELLO ends at the tag, and a serve reads the level only when the tag asks for it
            if codec == Codec::Deflate {
                e.u32(u32::from(level));
            }
        } else {
            e.u32(VERSION).string(target).bool(create).bool(compress);
        }
        let reply = self.call(op, &e.into_bytes()).map_err(|err| {
            if named {
                io::Error::new(err.kind(), format!("-compress.codec {} needs a far rcp that speaks protocol {CODEC_VERSION}: {err}", codec.name()))
            } else {
                err
            }
        })?;
        let mut d = Decoder::new(&reply);
        let version = d.string().unwrap_or_default();
        // ONE word, then four tree answers, and it is REQUIRED: four bools follow it, so a
        // tolerant read of a missing word would consume `keeps_times` in its place -- the
        // defect once recorded here, where a short-circuited flag left every later answer
        // one field late and every ssh sync recopied nothing. Under v5 the word is RAW (0)
        // or LZ4 (1), which is also how XDR encodes the bool an older serve sends; under
        // v6 it must be the tag asked for, or the two sides would disagree about how to
        // read a payload.
        let answer = d.u32()?;
        self.squeeze = if named {
            if answer != codec.flag() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "the far rcp answered codec {answer} to a request for {} ({})",
                        codec.name(),
                        codec.flag()
                    ),
                ));
            }
            Squeeze::with_codec(true, codec, level)
        } else {
            Squeeze::with_codec(compress && answer == PAYLOAD_LZ4, Codec::Lz4, level)
        };
        // what the far tree answers to the two questions a planner asks; a serve that
        // speaks this VERSION always sends them, so a missing pair is a garbled reply
        let keeps_times = d.bool()?;
        let rewrites_metadata = d.bool()?;
        let writes_in_one_stream = d.bool()?;
        let sync_publishes = d.bool()?;
        Ok(Greeting {
            version,
            keeps_times,
            rewrites_metadata,
            writes_in_one_stream,
            sync_publishes,
        })
    }

    /// Sends one request; its sequence number, to receive by.
    fn send(&mut self, op: u32, args: &[u8]) -> io::Result<u32> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let mut e = Encoder::new();
        e.u32(seq).u32(op);
        let mut body = e.into_bytes();
        body.extend_from_slice(args);
        write_frame(&mut self.output, &body)?;
        self.output.flush()?;
        self.inflight.push_back(seq);
        Ok(seq)
    }

    /// The reply to `seq`. The server answers in order, so every frame must carry the
    /// oldest sequence number still in flight; an earlier request whose reply nobody
    /// waited for is discarded here whatever its outcome, because the sender of a
    /// pipelined request that gave up on it (a sink dropped after an error) has already
    /// reported. A frame out of that order means the stream is broken.
    fn recv(&mut self, seq: u32) -> io::Result<Vec<u8>> {
        if !self.inflight.contains(&seq) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("request {seq} is not in flight"),
            ));
        }
        loop {
            let frame = self.next_frame()?;
            let mut d = Decoder::new(&frame);
            let got = d.u32()?;
            let status = d.u32()?;
            match self.inflight.front() {
                Some(&oldest) if oldest == got => {
                    self.inflight.pop_front();
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("reply {got} arrived while waiting for {seq}"),
                    ))
                }
            }
            if got != seq {
                continue;
            }
            if status != 0 {
                return Err(remote_error(status, d.string().unwrap_or_default()));
            }
            return Ok(frame[8..].to_vec());
        }
    }

    fn next_frame(&mut self) -> io::Result<Vec<u8>> {
        match read_frame(&mut self.input)? {
            Some(f) => Ok(f),
            None => {
                let status = self
                    .child
                    .as_mut()
                    .and_then(|c| c.try_wait().ok().flatten());
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    match status {
                        Some(s) => {
                            format!("rcp serve ended ({s}); is rcp installed on the remote host?")
                        }
                        None => "rcp serve closed the stream".to_string(),
                    },
                ))
            }
        }
    }

    fn call(&mut self, op: u32, args: &[u8]) -> io::Result<Vec<u8>> {
        let seq = self.send(op, args)?;
        self.recv(seq)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct Pool {
    settings: Settings,
    dial: Dial,
    /// What every HELLO on this pool names: an absolute path on the host, or -- for a
    /// relay -- the endpoint the host opens on our behalf.
    target: String,
    /// Whether the first channel opened the target to be created, which a joining channel
    /// repeats: a registry takes it as push rights, and without them a later channel could
    /// not upload into the repository the first one is building.
    create: bool,
    /// Whether the far side knows ATTACH; cleared by the first serve that answers it
    /// `Unsupported`, so a pool of old serves pays that round trip once, not per channel.
    joins: AtomicBool,
    idle: Mutex<Vec<Channel>>,
}

impl Pool {
    fn take(&self) -> io::Result<Channel> {
        if let Some(c) = self.idle.lock().unwrap().pop() {
            return Ok(c);
        }
        let mut c = Channel::dial(&self.settings, &self.dial)?;
        self.join(&mut c)?;
        Ok(c)
    }

    /// Greets a freshly dialed channel as one joining this pool's tree: ATTACH, or HELLO to
    /// a serve that predates it.
    fn join(&self, c: &mut Channel) -> io::Result<()> {
        let (compress, codec, level) = (
            self.settings.compress,
            self.settings.codec,
            self.settings.level,
        );
        if self.joins.load(Ordering::Relaxed) {
            match c.greet(OP_ATTACH, &self.target, self.create, compress, codec, level) {
                Ok(_) => return Ok(()),
                // A serve from before ATTACH refuses the op by number and keeps the channel,
                // having read nothing of the body; it gets the HELLO every later channel sent
                // before, on the same channel. The number is matched, not just the kind: an
                // ATTACH a new serve refuses as Unsupported (a codec it lacks) is an answer,
                // and HELLO would only be refused the same way.
                Err(e)
                    if e.kind() == io::ErrorKind::Unsupported
                        && e.to_string().contains(&format!("operation {OP_ATTACH}")) =>
                {
                    self.joins.store(false, Ordering::Relaxed)
                }
                Err(e) => return Err(e),
            }
        }
        c.hello(&self.target, false, compress, codec, level)?;
        Ok(())
    }
    fn give(&self, c: Channel) {
        if c.inflight.is_empty() {
            self.idle.lock().unwrap().push(c);
        }
    }
    fn with<R>(&self, f: impl FnOnce(&mut Channel) -> io::Result<R>) -> io::Result<R> {
        let mut c = self.take()?;
        let r = f(&mut c);
        self.give(c);
        r
    }
}

/// What the far side said in its HELLO reply.
struct Greeting {
    version: String,
    keeps_times: bool,
    rewrites_metadata: bool,
    writes_in_one_stream: bool,
    sync_publishes: bool,
}

pub struct SshTree {
    pool: Arc<Pool>,
    display: PathBuf,
    /// The far tree's own answers, carried here because the planner asks THIS tree.
    keeps_times: bool,
    rewrites_metadata: bool,
    writes_in_one_stream: bool,
    sync_publishes: bool,
}

impl SshTree {
    /// Reaches `path` on `host` through one channel, creating the directory when `create`
    /// says so; a host without rcp, or a path that is not there, fails here.
    pub fn connect(
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        path: &Path,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let hop = format!(
            "ssh://{}{host}{}",
            user.map(|u| format!("{u}@")).unwrap_or_default(),
            port.map(|p| format!(":{p}")).unwrap_or_default()
        );
        Self::connect_to(
            user,
            host,
            port,
            &path.to_string_lossy(),
            PathBuf::from(format!("{hop}{}", path.display())),
            create,
            settings,
        )
    }

    /// A relay: the `rcp serve` on `host` opens `target` -- any endpoint this binary can
    /// open, with the HOST's environment -- and this side speaks to it exactly as it would
    /// to a directory there. `display` is how the endpoint prints in reports.
    pub fn connect_via(
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        target: &str,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let hop = format!(
            "ssh://{}{host}{}",
            user.map(|u| format!("{u}@")).unwrap_or_default(),
            port.map(|p| format!(":{p}")).unwrap_or_default()
        );
        Self::connect_to(
            user,
            host,
            port,
            target,
            PathBuf::from(format!("{target} via {hop}")),
            create,
            settings,
        )
    }

    /// Reaches `path` on a LISTENING serve at `addr`, with no ssh in the picture. The
    /// same protocol, the same session, one socket instead of a child process.
    pub fn connect_tcp(
        host: &str,
        port: u16,
        secure: bool,
        path: &Path,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let dial = Dial::tcp(host, port, secure);
        let display = PathBuf::from(format!("{}{}", dial.scheme(), path.display()));
        Self::connect_dial(dial, &path.to_string_lossy(), display, create, settings)
    }

    /// A relay through a listening serve: it opens `target` with ITS environment, exactly
    /// as the ssh relay does.
    pub fn connect_tcp_via(
        host: &str,
        port: u16,
        secure: bool,
        target: &str,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let dial = Dial::tcp(host, port, secure);
        let display = PathBuf::from(format!("{target} via {}", dial.scheme()));
        Self::connect_dial(dial, target, display, create, settings)
    }

    fn connect_to(
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        target: &str,
        display: PathBuf,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let dial = Dial::Ssh {
            user: user.map(str::to_string),
            host: host.to_string(),
            port,
        };
        Self::connect_dial(dial, target, display, create, settings)
    }

    fn connect_dial(
        dial: Dial,
        target: &str,
        display: PathBuf,
        create: bool,
        settings: &Settings,
    ) -> io::Result<SshTree> {
        let mut c = Channel::dial(settings, &dial)?;
        // the server names the target in its own errors, and the caller names the endpoint
        let greeting = c
            .hello(
                target,
                create,
                settings.compress,
                settings.codec,
                settings.level,
            )
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", display.display())))?;
        let through = match &dial {
            Dial::Ssh { .. } => settings.ssh.clone(),
            Dial::Tcp { addr, .. } => addr.clone(),
        };
        crate::debug!(
            settings.log,
            "{}: rcp {} serving through {}{}",
            dial.scheme(),
            greeting.version,
            through,
            if c.squeeze.on {
                ", compressing"
            } else if settings.compress {
                ", the far side does not compress"
            } else {
                ""
            }
        );
        let pool = Arc::new(Pool {
            settings: settings.clone(),
            dial,
            target: target.to_string(),
            create,
            joins: AtomicBool::new(true),
            idle: Mutex::new(vec![c]),
        });
        Ok(SshTree {
            pool,
            display,
            keeps_times: greeting.keeps_times,
            rewrites_metadata: greeting.rewrites_metadata,
            writes_in_one_stream: greeting.writes_in_one_stream,
            sync_publishes: greeting.sync_publishes,
        })
    }

    fn call(&self, op: u32, args: &[u8]) -> io::Result<Vec<u8>> {
        self.pool.with(|c| c.call(op, args))
    }

    fn simple(&self, op: u32, args: &[u8]) -> io::Result<()> {
        self.call(op, args).map(|_| ())
    }
}

/// A sequential reader over a remote file that keeps READs in flight ahead of its
/// consumer, so a round trip is paid once per window rather than once per block; a seek
/// discards the window and starts it again at the new position.
pub struct SshReader {
    pool: Arc<Pool>,
    chan: Option<Channel>,
    handle: u32,
    /// The next byte the consumer gets.
    pos: u64,
    size: u64,
    block: u32,
    /// READs in flight, oldest first: (sequence, offset, length).
    window: VecDeque<(u32, u64, u32)>,
    /// Where the next READ to issue starts.
    ahead: u64,
    /// The tail of the last reply the consumer has not taken yet.
    leftover: Vec<u8>,
    taken: usize,
}

impl SshReader {
    fn new(pool: Arc<Pool>, chan: Channel, handle: u32, size: u64, block: u32) -> SshReader {
        SshReader {
            pool,
            chan: Some(chan),
            handle,
            pos: 0,
            size,
            block,
            window: VecDeque::new(),
            ahead: 0,
            leftover: Vec::new(),
            taken: 0,
        }
    }

    /// Issues READs until the window is full or the file is covered.
    fn fill(&mut self) -> io::Result<()> {
        let chan = self.chan.as_mut().expect("open reader has a channel");
        while self.window.len() < READ_WINDOW && self.ahead < self.size {
            let len = (self.size - self.ahead).min(self.block as u64) as u32;
            let mut e = Encoder::new();
            e.u32(self.handle).u64(self.ahead).u32(len);
            let seq = chan.send(OP_READ, &e.into_bytes())?;
            self.window.push_back((seq, self.ahead, len));
            self.ahead += len as u64;
        }
        Ok(())
    }

    /// Collects every reply in flight and drops it: after a seek, and before the channel
    /// goes back to the pool.
    fn discard(&mut self) {
        if let Some(chan) = self.chan.as_mut() {
            while let Some((seq, _, _)) = self.window.pop_front() {
                let _ = chan.recv(seq);
            }
        }
        self.leftover.clear();
        self.taken = 0;
    }

    /// Drops every reply in flight WITHOUT touching the bytes the consumer has not taken
    /// yet. `discard` clears those too, which is right after a seek and wrong after a
    /// short read, where they are the reply just received.
    fn discard_keeping_leftover(&mut self) {
        if let Some(chan) = self.chan.as_mut() {
            while let Some((seq, _, _)) = self.window.pop_front() {
                let _ = chan.recv(seq);
            }
        }
    }

    /// Puts the reader back where the consumer thinks it is, and returns the error that
    /// got it there.
    ///
    /// `read` pops the window entry BEFORE it receives the reply, so an error between the
    /// two leaves the window short one block with `ahead` already past it. That matters
    /// because an error is not necessarily the end: `read_to_end` retries on
    /// `Interrupted`, and the retry would pop the NEXT entry -- one block further into the
    /// file -- and hand back its bytes as if they were the missing block's. Measured on a
    /// 100-byte file with a 16-byte block: `read_to_end` returned `Ok(84)`, a short read
    /// reported as a complete one, with no error anywhere for the caller to see.
    ///
    /// So resync: drop everything in flight and rewind `ahead` to the consumer's position,
    /// which makes the retry re-issue the READ that failed at the offset it belongs to.
    fn resync(&mut self, e: io::Error) -> io::Error {
        self.discard();
        self.ahead = self.pos;
        e
    }
}

impl Drop for SshReader {
    fn drop(&mut self) {
        self.discard();
        if let Some(mut c) = self.chan.take() {
            let mut e = Encoder::new();
            e.u32(self.handle);
            let _ = c.call(OP_CLOSE, &e.into_bytes());
            self.pool.give(c);
        }
    }
}

impl Read for SshReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.taken < self.leftover.len() {
            let n = (self.leftover.len() - self.taken).min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[self.taken..self.taken + n]);
            self.taken += n;
            self.pos += n as u64;
            return Ok(n);
        }
        if self.pos >= self.size {
            return Ok(0);
        }
        self.fill()?;
        let Some((seq, offset, want)) = self.window.pop_front() else {
            return Ok(0);
        };
        debug_assert_eq!(offset, self.pos, "the window is sequential");
        let chan = self.chan.as_mut().expect("open reader has a channel");
        let reply = match chan.recv(seq) {
            Ok(r) => r,
            Err(e) => return Err(self.resync(e)),
        };
        let mut d = Decoder::new(&reply);
        let data = match unpack(&mut d) {
            Ok(d) => d,
            Err(e) => return Err(self.resync(e)),
        };
        if data.is_empty() {
            // the file ended early: nothing further in flight can have data either
            self.size = self.pos;
            self.discard();
            return Ok(0);
        }
        // A SHORT REPLY DESYNCHRONIZES THE WINDOW, and nothing else notices.
        //
        // `fill` issues READs at `ahead` and advances `ahead` by the length it ASKED for.
        // If a reply comes back shorter than that -- which the server's own `got < len`
        // says, a flag it has always sent and which is easy to leave undecoded -- then the
        // next window entry's offset is past where the consumer actually is, and the bytes
        // between are never requested. The file is reassembled with a gap in it, no error
        // anywhere, and `debug_assert_eq!(offset, self.pos)` above catches it only in a
        // debug build. So the window is dropped and `ahead` rewound to where the consumer
        // really is, which makes the next `fill` ask for the missing bytes.
        let short = data.len() < want as usize;
        let eof = d.bool().unwrap_or(short);
        let taken_all = data.len();
        let n = taken_all.min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        if n < taken_all {
            self.leftover.clear();
            self.leftover.extend_from_slice(&data[n..]);
            self.taken = 0;
        }
        if short {
            let resume = offset + taken_all as u64;
            self.discard_keeping_leftover();
            self.ahead = resume;
            if eof && resume < self.size {
                // the server says the file ends here, so the stat this run planned from is
                // stale; reading past it would spin on empty replies
                self.size = resume;
            }
        }
        // keep the window full behind this reply
        self.fill()?;
        Ok(n)
    }
}

impl Seek for SshReader {
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
        let new = new as u64;
        if new != self.pos {
            self.discard();
            self.pos = new;
            self.ahead = new;
        }
        Ok(self.pos)
    }
}

pub struct SshSink {
    pool: Arc<Pool>,
    chan: Option<Channel>,
    handle: u32,
    rel: String,
    pending: VecDeque<u32>,
    nocache: bool,
}

impl SshSink {
    fn reap_one(&mut self) -> io::Result<()> {
        let Some(seq) = self.pending.pop_front() else {
            return Ok(());
        };
        let chan = self.chan.as_mut().expect("open sink has a channel");
        chan.recv(seq)
            .map(|_| ())
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.rel)))
    }
    /// Collects every outstanding reply, so the channel is clean and reusable afterwards,
    /// and reports the first failure among them.
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
}

impl Drop for SshSink {
    fn drop(&mut self) {
        let _ = self.drain();
        if let Some(mut c) = self.chan.take() {
            let mut e = Encoder::new();
            e.u32(self.handle);
            let _ = c.call(OP_CLOSE, &e.into_bytes());
            self.pool.give(c);
        }
    }
}

impl Sink for SshSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        let mut e = Encoder::new();
        e.u32(self.handle).u64(len);
        let chan = self.chan.as_mut().expect("open sink has a channel");
        chan.call(OP_RESERVE, &e.into_bytes()).map(|_| ())
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(BLOCK as usize) {
            if self.pending.len() >= WRITE_WINDOW {
                self.reap_one()?;
            }
            let mut e = Encoder::new();
            e.u32(self.handle);
            let chan = self.chan.as_mut().expect("open sink has a channel");
            chan.squeeze.pack(&mut e, chunk);
            let seq = chan.send(OP_WRITE, &e.into_bytes())?;
            self.pending.push_back(seq);
        }
        Ok(())
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        if self.pending.len() >= WRITE_WINDOW {
            self.reap_one()?;
        }
        let mut e = Encoder::new();
        e.u32(self.handle).u64(len);
        let chan = self.chan.as_mut().expect("open sink has a channel");
        let seq = chan.send(OP_HOLE, &e.into_bytes())?;
        self.pending.push_back(seq);
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
        let mut e = Encoder::new();
        e.u32(self.handle);
        encode_item(&mut e, item);
        encode_xattrs(&mut e, xattrs);
        encode_meta(&mut e, opts);
        e.bool(fsync).bool(self.nocache);
        let chan = self.chan.as_mut().expect("open sink has a channel");
        let reply = chan
            .call(OP_FINISH, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.rel)))?;
        decode_refusals(&mut Decoder::new(&reply))
    }
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
    fn copy_basis(&mut self, offset: u64, len: u64) -> io::Result<()> {
        // pipelined like a write: the serve reads the basis, the client sends two numbers
        if self.pending.len() >= WRITE_WINDOW {
            self.reap_one()?;
        }
        let mut e = Encoder::new();
        e.u32(self.handle).u64(offset).u64(len);
        let chan = self.chan.as_mut().expect("open sink has a channel");
        let seq = chan.send(OP_COPY_BASIS, &e.into_bytes())?;
        self.pending.push_back(seq);
        Ok(())
    }
    fn expect(&mut self, digest: &str) -> io::Result<()> {
        // a call on this channel must not overtake the pipelined steps still in flight
        self.drain()?;
        let mut e = Encoder::new();
        e.u32(self.handle).string(digest);
        let chan = self.chan.as_mut().expect("open sink has a channel");
        chan.call(OP_EXPECT, &e.into_bytes())
            .map(|_| ())
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.rel)))
    }
}

fn kind_code(k: Kind) -> u32 {
    match k {
        Kind::File => 0,
        Kind::Dir => 1,
        Kind::Symlink => 2,
    }
}

impl Tree for SshTree {
    type Reader = SshReader;
    type Sink = SshSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn keeps_times(&self) -> bool {
        self.keeps_times
    }

    fn rewrites_metadata_in_place(&self) -> bool {
        self.rewrites_metadata
    }

    fn writes_in_one_stream(&self) -> bool {
        // A far tree that publishes in `sync` stages what it is sent in the serve that
        // received it, and every channel is its own serve: files written through a second
        // channel sit in a staging area the `sync` never reaches. Measured through a relay
        // into a registry at -parallel 8, the push reported success and the tag did not
        // exist. The same reason `-nodes` refuses such a destination; here the writes go
        // through one channel instead, which the engine gets by writing one at a time.
        self.writes_in_one_stream || self.sync_publishes
    }

    fn sync_publishes(&self) -> bool {
        self.sync_publishes
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        let mut e = Encoder::new();
        encode_filter(&mut e, filter);
        e.u32(max_depth.map(|d| d as u32).unwrap_or(u32::MAX))
            .u32(parallel as u32);
        // batches stream under one sequence number until LIST_END, like SEGMENTS
        let args = e.into_bytes();
        self.pool.with(|chan| {
            let seq = chan.send(OP_LIST, &args)?;
            let mut items = Vec::new();
            let mut errors = Vec::new();
            loop {
                let frame = chan.next_frame()?;
                let mut d = Decoder::new(&frame);
                let got = d.u32()?;
                let status = d.u32()?;
                if got != seq {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("reply {got} arrived while listing under {seq}"),
                    ));
                }
                if status != 0 {
                    chan.inflight.pop_front();
                    return Err(remote_error(status, d.string().unwrap_or_default()));
                }
                match d.u32()? {
                    LIST_ITEMS => {
                        for _ in 0..d.u32()? {
                            items.push(decode_item(&mut d)?);
                        }
                    }
                    LIST_ERRORS => {
                        for _ in 0..d.u32()? {
                            errors.push(d.string()?);
                        }
                    }
                    LIST_END => {
                        chan.inflight.pop_front();
                        return Ok(Listing { items, errors });
                    }
                    tag => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("listing tag {tag}"),
                        ))
                    }
                }
            }
        })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        let mut e = Encoder::new();
        e.string(rel);
        let reply = self.call(OP_STAT, &e.into_bytes())?;
        let mut d = Decoder::new(&reply);
        if d.bool()? {
            Ok(Some(decode_item(&mut d)?))
        } else {
            Ok(None)
        }
    }

    fn open(&self, rel: &str) -> io::Result<SshReader> {
        let mut chan = self.pool.take()?;
        let mut e = Encoder::new();
        e.string(rel);
        let reply = match chan.call(OP_OPEN_READ, &e.into_bytes()) {
            Ok(r) => r,
            Err(e) => {
                self.pool.give(chan);
                return Err(io::Error::new(e.kind(), format!("{rel}: {e}")));
            }
        };
        let mut d = Decoder::new(&reply);
        let handle = d.u32()?;
        let size = d.u64()?;
        Ok(SshReader::new(self.pool.clone(), chan, handle, size, BLOCK))
    }

    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        // the server streams segments under one sequence number until SEG_END
        let mut chan = self.pool.take()?;
        let result = (|| {
            let mut e = Encoder::new();
            e.string(rel)
                .u32(buf.len().clamp(4096, MAX_FRAME - 64) as u32);
            let seq = chan.send(OP_SEGMENTS, &e.into_bytes())?;
            loop {
                let frame = chan.next_frame()?;
                let mut d = Decoder::new(&frame);
                let got = d.u32()?;
                let status = d.u32()?;
                if got != seq {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("reply {got} arrived while streaming {seq}"),
                    ));
                }
                if status != 0 {
                    chan.inflight.pop_front();
                    return Err(remote_error(status, d.string().unwrap_or_default()));
                }
                match d.u32()? {
                    SEG_DATA => sink(Segment::Data(&unpack(&mut d)?))?,
                    SEG_HOLE => sink(Segment::Hole(d.u64()?))?,
                    SEG_END => {
                        chan.inflight.pop_front();
                        return Ok(());
                    }
                    // anything else means the stream is not what it claims; the channel
                    // is not returned to the pool with frames still unread behind this one
                    tag => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("segment tag {tag}"),
                        ))
                    }
                }
            }
        })();
        self.pool.give(chan);
        result.map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn create_file(&self, item: &Item) -> io::Result<SshSink> {
        let mut chan = self.pool.take()?;
        let mut e = Encoder::new();
        encode_item(&mut e, item);
        let reply = match chan.call(OP_CREATE, &e.into_bytes()) {
            Ok(r) => r,
            Err(e) => {
                self.pool.give(chan);
                return Err(io::Error::new(e.kind(), format!("{}: {e}", item.rel)));
            }
        };
        let handle = Decoder::new(&reply).u32()?;
        Ok(SshSink {
            pool: self.pool.clone(),
            chan: Some(chan),
            handle,
            rel: item.rel.clone(),
            pending: VecDeque::new(),
            nocache: false,
        })
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut SshSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn signatures(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        digests: &dyn Digests,
    ) -> io::Result<Vec<ChunkSig>> {
        // the far side signs its own file and streams the signatures in batches
        let mut e = Encoder::new();
        e.string(rel);
        encode_params(&mut e, params);
        e.string(digests.name());
        let args = e.into_bytes();
        self.pool
            .with(|chan| {
                let seq = chan.send(OP_SIGNATURES, &args)?;
                let mut sigs = Vec::new();
                loop {
                    let frame = chan.next_frame()?;
                    let mut d = Decoder::new(&frame);
                    let got = d.u32()?;
                    let status = d.u32()?;
                    if got != seq {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("reply {got} arrived while signing under {seq}"),
                        ));
                    }
                    if status != 0 {
                        chan.inflight.pop_front();
                        return Err(remote_error(status, d.string().unwrap_or_default()));
                    }
                    match d.u32()? {
                        SIG_BATCH => decode_sigs(&mut d, &mut sigs)?,
                        SIG_END => {
                            chan.inflight.pop_front();
                            return Ok(sigs);
                        }
                        tag => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("signature tag {tag}"),
                            ))
                        }
                    }
                }
            })
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn delta(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        sigs: &[ChunkSig],
        runtime: &Runtime,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<String> {
        // the far side holds the bytes, so the signatures go there and only the patch
        // comes back
        let mut e = Encoder::new();
        e.string(rel);
        encode_params(&mut e, params);
        e.string(runtime.digests.name());
        let begin = e.into_bytes();
        self.pool
            .with(|chan| {
                let reply = chan.call(OP_DELTA_BEGIN, &begin)?;
                let h = Decoder::new(&reply).u32()?;
                for batch in sigs.chunks(LIST_BATCH) {
                    let mut e = Encoder::new();
                    e.u32(h);
                    encode_sigs(&mut e, batch);
                    chan.call(OP_DELTA_SIGS, &e.into_bytes())?;
                }
                let mut e = Encoder::new();
                e.u32(h);
                let seq = chan.send(OP_DELTA_RUN, &e.into_bytes())?;
                loop {
                    let frame = chan.next_frame()?;
                    let mut d = Decoder::new(&frame);
                    let got = d.u32()?;
                    let status = d.u32()?;
                    if got != seq {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("reply {got} arrived while patching under {seq}"),
                        ));
                    }
                    if status != 0 {
                        chan.inflight.pop_front();
                        return Err(remote_error(status, d.string().unwrap_or_default()));
                    }
                    match d.u32()? {
                        PATCH_LITERAL => {
                            let b = unpack(&mut d)?;
                            runtime.throttle.take(b.len() as u64);
                            emit(Patch::Literal(&b))?;
                        }
                        PATCH_COPY => emit(Patch::Copy {
                            offset: d.u64()?,
                            len: d.u64()?,
                        })?,
                        PATCH_HOLE => emit(Patch::Hole(d.u64()?))?,
                        PATCH_END => {
                            chan.inflight.pop_front();
                            return d.string();
                        }
                        tag => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("patch tag {tag}"),
                            ))
                        }
                    }
                }
            })
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn create_patch(
        &self,
        item: &Item,
        basis: &Basis,
        digests: &dyn Digests,
    ) -> io::Result<SshSink> {
        let mut chan = self.pool.take()?;
        let mut e = Encoder::new();
        encode_item(&mut e, item);
        encode_basis(&mut e, basis);
        e.string(digests.name());
        let reply = match chan.call(OP_CREATE_PATCH, &e.into_bytes()) {
            Ok(r) => r,
            Err(e) => {
                self.pool.give(chan);
                return Err(io::Error::new(e.kind(), format!("{}: {e}", item.rel)));
            }
        };
        let handle = Decoder::new(&reply).u32()?;
        Ok(SshSink {
            pool: self.pool.clone(),
            chan: Some(chan),
            handle,
            rel: item.rel.clone(),
            pending: VecDeque::new(),
            nocache: false,
        })
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        let mut e = Encoder::new();
        e.string(rel);
        self.simple(OP_MKDIR, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        let mut e = Encoder::new();
        e.string(rel).string(&target.to_string_lossy());
        self.simple(OP_SYMLINK, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let mut e = Encoder::new();
        e.string(existing).string(rel);
        self.simple(OP_HARDLINK, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        let mut e = Encoder::new();
        e.string(rel).u32(kind_code(kind));
        let reply = self
            .call(OP_REMOVE, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        decode_removed(&mut Decoder::new(&reply))
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let mut e = Encoder::new();
        e.string(from).string(to);
        self.simple(OP_RENAME, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{from} -> {to}: {e}")))
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let mut e = Encoder::new();
        e.string(rel);
        encode_item(&mut e, item);
        encode_meta(&mut e, opts);
        let reply = self
            .call(OP_SETMETA, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        decode_refusals(&mut Decoder::new(&reply))
    }

    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut e = Encoder::new();
        e.string(rel);
        let reply = self
            .call(OP_XATTRS, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        decode_xattrs(&mut Decoder::new(&reply))
    }

    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        let mut e = Encoder::new();
        e.string(rel);
        encode_xattrs(&mut e, attrs);
        let reply = self
            .call(OP_SETXATTRS, &e.into_bytes())
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
        let mut d = Decoder::new(&reply);
        let n = d.u32()?;
        (0..n).map(|_| d.string()).collect()
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        let mut e = Encoder::new();
        encode_item(&mut e, item);
        self.simple(OP_RESTORE_ATIME, &e.into_bytes())
    }

    fn sync(&self) -> io::Result<()> {
        self.simple(OP_SYNC, &[])
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
            "no native engine over ssh",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(seq: u32, status: u32, body: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u32(seq).u32(status);
        let mut bytes = e.into_bytes();
        if status == 0 {
            bytes.extend_from_slice(body);
        } else {
            let mut t = Encoder::new();
            t.string(std::str::from_utf8(body).unwrap());
            bytes.extend_from_slice(&t.into_bytes());
        }
        let mut frame = Vec::new();
        write_frame(&mut frame, &bytes).unwrap();
        frame
    }

    fn channel(replies: &[Vec<u8>]) -> Channel {
        Channel {
            child: None,
            input: Box::new(io::Cursor::new(replies.concat())),
            output: Box::new(io::sink()),
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        }
    }

    /// A pool that opened `/t` with `create`, for the join arms.
    fn joining_pool(create: bool) -> Pool {
        Pool {
            settings: Settings {
                ssh: "none".into(),
                remote_rcp: "rcp".into(),
                compress: false,
                codec: Codec::default(),
                level: DEFAULT_LEVEL,
                tls: crate::remote::TlsFiles::default(),
                log: Arc::new(crate::ports::Silent),
            },
            dial: Dial::Ssh {
                user: None,
                host: "x".into(),
                port: None,
            },
            target: "/t".into(),
            create,
            joins: AtomicBool::new(true),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// The greeting a serve sends back: its version, raw payloads, four tree answers.
    fn greeting() -> Vec<u8> {
        let mut e = Encoder::new();
        e.string("0.1.0").u32(PAYLOAD_RAW);
        for _ in 0..4 {
            e.bool(false);
        }
        e.into_bytes()
    }

    /// What a channel sent, as (op, target, create) per frame.
    fn greetings_sent(wire: &[u8]) -> Vec<(u32, String, bool)> {
        let mut r = io::Cursor::new(wire);
        let mut out = Vec::new();
        while let Some(frame) = read_frame(&mut r).unwrap() {
            let mut d = Decoder::new(&frame);
            let _seq = d.u32().unwrap();
            let op = d.u32().unwrap();
            let _version = d.u32().unwrap();
            out.push((op, d.string().unwrap(), d.bool().unwrap()));
        }
        out
    }

    #[derive(Clone)]
    struct Wire(Arc<Mutex<Vec<u8>>>);
    impl Write for Wire {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_later_channel_joins_with_the_first_channels_create_and_sends_no_hello() {
        let pool = joining_pool(true);
        let mut c = channel(&[reply(1, 0, &greeting())]);
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        c.output = Box::new(wire.clone());
        pool.join(&mut c).unwrap();
        assert_eq!(
            greetings_sent(&wire.0.lock().unwrap()),
            vec![(OP_ATTACH, "/t".to_string(), true)],
            "one ATTACH carrying the first open's create, and no HELLO after it"
        );
        assert!(pool.joins.load(Ordering::Relaxed));
    }

    #[test]
    fn a_serve_from_before_attach_gets_the_old_hello_once_per_pool() {
        let pool = joining_pool(true);
        // what a serve that predates the op answers, from its catch-all arm
        let refused = reply(
            1,
            1 + kind_code_of(io::ErrorKind::Unsupported),
            format!("operation {OP_ATTACH}").as_bytes(),
        );
        let mut c = channel(&[refused, reply(2, 0, &greeting())]);
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        c.output = Box::new(wire.clone());
        pool.join(&mut c).unwrap();
        assert_eq!(
            greetings_sent(&wire.0.lock().unwrap()),
            vec![
                (OP_ATTACH, "/t".to_string(), true),
                // the HELLO every later channel sent before ATTACH: never create
                (OP_HELLO, "/t".to_string(), false),
            ]
        );
        // and the next channel goes straight to HELLO
        assert!(!pool.joins.load(Ordering::Relaxed));
        let mut c = channel(&[reply(1, 0, &greeting())]);
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        c.output = Box::new(wire.clone());
        pool.join(&mut c).unwrap();
        assert_eq!(
            greetings_sent(&wire.0.lock().unwrap()),
            vec![(OP_HELLO, "/t".to_string(), false)]
        );
    }

    #[test]
    fn a_join_a_new_serve_refuses_for_another_reason_is_that_refusal() {
        // Unsupported, but not the op: falling back would only be refused again, and the
        // pool would stop joining for every later channel on a serve that can
        let pool = joining_pool(false);
        let refused = reply(
            1,
            1 + kind_code_of(io::ErrorKind::Unsupported),
            b"protocol version 6 names codec 9",
        );
        let mut c = channel(&[refused]);
        let wire = Wire(Arc::new(Mutex::new(Vec::new())));
        c.output = Box::new(wire.clone());
        let err = pool.join(&mut c).unwrap_err();
        assert!(err.to_string().contains("codec 9"), "{err}");
        assert_eq!(greetings_sent(&wire.0.lock().unwrap()).len(), 1);
        assert!(pool.joins.load(Ordering::Relaxed));
    }

    #[test]
    fn a_reply_nobody_waited_for_is_discarded_and_a_reply_out_of_order_is_an_error() {
        // three pipelined requests; the first fails and its sender gave up on it
        let mut c = channel(&[
            reply(
                1,
                1 + kind_code_of(io::ErrorKind::StorageFull),
                b"disk full",
            ),
            reply(2, 0, b"ok"),
            reply(3, 0, b""),
        ]);
        assert_eq!(
            (
                c.send(7, &[]).unwrap(),
                c.send(7, &[]).unwrap(),
                c.send(7, &[]).unwrap()
            ),
            (1, 2, 3)
        );
        assert_eq!(c.recv(2).unwrap(), b"ok");
        assert_eq!(c.inflight, VecDeque::from([3]));
        assert!(c.recv(3).unwrap().is_empty());
        assert!(c.inflight.is_empty());
        // controls: a request never sent is refused before any frame is read, a failure
        // that IS waited for comes back with its kind and text, and a frame that skips
        // the oldest request in flight breaks the stream
        assert_eq!(c.recv(9).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let mut c = channel(&[reply(
            1,
            1 + kind_code_of(io::ErrorKind::PermissionDenied),
            b"denied",
        )]);
        c.send(7, &[]).unwrap();
        let e = c.recv(1).unwrap_err();
        assert_eq!(
            (e.kind(), e.to_string()),
            (io::ErrorKind::PermissionDenied, "denied".to_string())
        );
        let mut c = channel(&[reply(2, 0, b""), reply(1, 0, b"")]);
        c.send(7, &[]).unwrap();
        c.send(7, &[]).unwrap();
        assert_eq!(c.recv(1).unwrap_err().kind(), io::ErrorKind::InvalidData);
        // and a stream that ends is a closed serve, not a hang
        let mut c = channel(&[]);
        c.send(7, &[]).unwrap();
        assert_eq!(
            c.recv(1).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// A writer that counts the frames written through it (a frame is two writes).
    struct Counting(Arc<AtomicUsize>);

    impl Write for Counting {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A reply shorter than the READ asked for must not leave a GAP in the file.
    ///
    /// `fill` advances `ahead` by the length it requested, so a short reply put every
    /// later window entry one gap ahead of where the consumer actually was -- and the
    /// bytes in between were never asked for again. The file came back with a hole in it
    /// and `read_to_end` returned `Ok(n)`, a corrupt read reported as a complete one. The
    /// server has always sent a `got < len` flag on every READ reply; this client decoded
    /// the payload and stopped, so the one signal that named the condition was discarded.
    #[test]
    fn a_short_reply_does_not_leave_a_gap_in_the_file() {
        let block = 16u32;
        let size = 100u64;
        let byte = |i: u64| i as u8;
        // seq 1: a full block at 0. seq 2: EIGHT bytes where sixteen were asked for, and
        // NOT end of file. seqs 3..=7: the rest of the first window, which the resync
        // drops unread. seq 8 on: the re-issued reads, starting at 24 where the short
        // reply really ended rather than at 32 where `ahead` had been advanced to.
        let mut replies = Vec::new();
        let mut push = |seq: u32, off: u64, len: u64, eof: bool| {
            let data: Vec<u8> = (off..off + len).map(byte).collect();
            let mut e = Encoder::new();
            Squeeze::default().pack(&mut e, &data);
            e.bool(eof);
            replies.push(reply(seq, 0, &e.into_bytes()));
        };
        push(1, 0, 16, false);
        push(2, 16, 8, false);
        for (n, off) in (3u32..=7).zip([32u64, 48, 64, 80, 96]) {
            push(n, off, (size - off).min(16), off + 16 >= size);
        }
        let mut seq = 8u32;
        let mut off = 24u64;
        while off < size {
            let len = (size - off).min(16);
            push(seq, off, len, off + len >= size);
            seq += 1;
            off += len;
        }
        replies.push(reply(seq, 0, b"")); // CLOSE

        let chan = Channel {
            child: None,
            input: Box::new(io::Cursor::new(replies.concat())),
            output: Box::new(io::sink()),
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        };
        let pool = Arc::new(Pool {
            settings: Settings {
                ssh: "none".into(),
                remote_rcp: "rcp".into(),
                compress: false,
                codec: Codec::default(),
                level: DEFAULT_LEVEL,
                tls: crate::remote::TlsFiles::default(),
                log: Arc::new(crate::ports::Silent),
            },
            dial: Dial::Ssh {
                user: None,
                host: "x".into(),
                port: None,
            },
            target: "/".into(),
            create: false,
            joins: AtomicBool::new(true),
            idle: Mutex::new(Vec::new()),
        });
        let mut r = SshReader::new(pool, chan, 1, size, block);
        let mut got = Vec::new();
        Read::read_to_end(&mut r, &mut got).unwrap();
        let want: Vec<u8> = (0..size).map(byte).collect();
        assert_eq!(
            got.len(),
            want.len(),
            "read {} bytes of a {size}-byte file",
            got.len()
        );
        assert_eq!(
            got, want,
            "the bytes differ: a gap was left where the short reply ended"
        );
        // the control, and it is what makes the arm about the GAP rather than the count:
        // the byte at the seam is the one the old wiring skipped
        assert_eq!(got[24], byte(24), "the byte after the short reply is wrong");
    }

    #[test]
    fn a_reader_keeps_a_window_of_reads_in_flight_and_returns_bytes_in_order() {
        // a 100-byte file read in 16-byte blocks: 7 blocks; every reply scripted in order
        let block = 16u32;
        let size = 100u64;
        let mut replies = Vec::new();
        let mut seq = 1u32;
        let mut off = 0u64;
        while off < size {
            let len = (size - off).min(block as u64) as usize;
            let data: Vec<u8> = (off..off + len as u64).map(|i| i as u8).collect();
            let mut e = Encoder::new();
            Squeeze::default().pack(&mut e, &data);
            e.bool(off + len as u64 >= size);
            replies.push(reply(seq, 0, &e.into_bytes()));
            seq += 1;
            off += len as u64;
        }
        replies.push(reply(seq, 0, b"")); // CLOSE
        let sent = Arc::new(AtomicUsize::new(0));
        let chan = Channel {
            child: None,
            input: Box::new(io::Cursor::new(replies.concat())),
            output: Box::new(Counting(sent.clone())),
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        };
        let pool = Arc::new(Pool {
            settings: Settings {
                ssh: "none".into(),
                remote_rcp: "rcp".into(),
                compress: false,
                codec: Codec::default(),
                level: DEFAULT_LEVEL,
                tls: crate::remote::TlsFiles::default(),
                log: Arc::new(crate::ports::Silent),
            },
            dial: Dial::Ssh {
                user: None,
                host: "x".into(),
                port: None,
            },
            target: "/".into(),
            create: false,
            joins: AtomicBool::new(true),
            idle: Mutex::new(Vec::new()),
        });
        let mut r = SshReader::new(pool, chan, 1, size, block);
        let mut got = Vec::new();
        let mut buf = [0u8; 10];
        let n = r.read(&mut buf).unwrap();
        got.extend_from_slice(&buf[..n]);
        // the first read put the whole file's worth of READs (7, under the window of 8)
        // on the wire before consuming one reply
        assert_eq!(
            sent.load(Ordering::Relaxed) / 2,
            7,
            "requests in flight after the first read"
        );
        assert_eq!(n, 10);
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            got,
            (0..100u64).map(|i| i as u8).collect::<Vec<_>>(),
            "bytes arrive in order across replies and partial takes"
        );
        assert_eq!(r.pos, 100);
        // control: a reader over a serve that answers nothing reports the broken stream
        let chan = Channel {
            child: None,
            input: Box::new(io::Cursor::new(Vec::new())),
            output: Box::new(io::sink()),
            next_seq: 1,
            inflight: VecDeque::new(),
            squeeze: Squeeze::default(),
        };
        let pool = Arc::new(Pool {
            settings: Settings {
                ssh: "none".into(),
                remote_rcp: "rcp".into(),
                compress: false,
                codec: Codec::default(),
                level: DEFAULT_LEVEL,
                tls: crate::remote::TlsFiles::default(),
                log: Arc::new(crate::ports::Silent),
            },
            dial: Dial::Ssh {
                user: None,
                host: "x".into(),
                port: None,
            },
            target: "/".into(),
            create: false,
            joins: AtomicBool::new(true),
            idle: Mutex::new(Vec::new()),
        });
        let mut r = SshReader::new(pool, chan, 1, 50, block);
        assert_eq!(
            r.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// A v5 serve from before codec tags answers with a BOOL where this side reads a u32
    /// word; XDR encodes them the same, so all four tree answers after it stay aligned
    /// whichever way it answered.
    #[test]
    fn a_v5_reply_keeps_every_tree_answer_aligned() {
        for requested in [false, true] {
            for accepted in [false, true] {
                let mut e = Encoder::new();
                e.string("pre-codec")
                    .bool(accepted)
                    .bool(false)
                    .bool(true)
                    .bool(false)
                    .bool(true);
                let mut c = channel(&[reply(1, 0, &e.into_bytes())]);
                let g = c
                    .hello("/old", false, requested, Codec::Lz4, DEFAULT_LEVEL)
                    .unwrap();
                assert_eq!(
                    (
                        g.keeps_times,
                        g.rewrites_metadata,
                        g.writes_in_one_stream,
                        g.sync_publishes
                    ),
                    (false, true, false, true)
                );
                assert_eq!(c.squeeze.on, requested && accepted);
            }
        }
    }

    /// A named codec asks with version 6 and nothing else crosses first, so an older serve
    /// refuses it by version -- and the error says so -- before it reads a path. The serve
    /// must then answer with the tag asked for; any other answer is refused rather than
    /// followed. Unconditional, because zstd is in every build.
    #[test]
    fn a_named_codec_asks_with_v6_and_needs_its_own_tag_back() {
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for (codec, level_word) in [(Codec::Zstd, None), (Codec::Deflate, Some(9u32))] {
            let mut c = channel(&[reply(
                1,
                1 + kind_code_of(io::ErrorKind::Unsupported),
                b"protocol version 6; this rcp serve speaks 5",
            )]);
            let sent = Arc::new(Mutex::new(Vec::new()));
            c.output = Box::new(Capture(sent.clone()));
            let err = c.hello("/old", true, true, codec, 9).err().unwrap();
            let sent = sent.lock().unwrap();
            let mut wire = io::Cursor::new(sent.as_slice());
            let frame = read_frame(&mut wire).unwrap().unwrap();
            let mut d = Decoder::new(&frame);
            assert_eq!(d.u32().unwrap(), 1); // sequence
            assert_eq!(d.u32().unwrap(), OP_HELLO);
            assert_eq!(d.u32().unwrap(), CODEC_VERSION);
            assert_eq!(d.string().unwrap(), "/old");
            assert!(d.bool().unwrap());
            assert_eq!(d.u32().unwrap(), codec.flag());
            assert_eq!(
                level_word.map(|_| d.u32().unwrap()),
                level_word,
                "only DEFLATE carries a level"
            );
            assert!(d.u32().is_err(), "nothing follows");
            assert_eq!(wire.position() as usize, sent.len(), "only HELLO crossed");
            assert!(
                err.to_string()
                    .contains("needs a far rcp that speaks protocol 6")
                    && err.to_string().contains("speaks 5"),
                "{err}"
            );
            assert!(!c.squeeze.on);
        }
        for tag in [PAYLOAD_RAW, PAYLOAD_LZ4, PAYLOAD_ZSTD, PAYLOAD_DEFLATE, 99] {
            let mut e = Encoder::new();
            e.string("peer")
                .u32(tag)
                .bool(true)
                .bool(false)
                .bool(true)
                .bool(false);
            let mut c = channel(&[reply(1, 0, &e.into_bytes())]);
            let got = c.hello("/peer", false, true, Codec::Zstd, DEFAULT_LEVEL);
            assert_eq!(got.is_ok(), tag == PAYLOAD_ZSTD, "tag {tag}");
            assert_eq!(c.squeeze.on, tag == PAYLOAD_ZSTD);
        }
    }
}
