//! The ports of the hexagon: every interface the core (`plan`, `transfer`, `scan`,
//! `catalog`, `filter`) talks through, and nothing else. The core imports this module and
//! its sibling core modules only; adapters implement these traits and the driving adapter
//! (the CLI in `main.rs`) assembles a `Runtime` and the trees and hands them in. A test in
//! `tests/hexagon.rs` reads the source and fails the build of the idea if a core module
//! reaches past its ports.
//!
//! - [`Tree`] and [`Sink`]: a storage location (local directory, NFS export, bucket, HDFS
//!   path, remote rcp) as the core sees it.
//! - [`Digests`] and [`Digest`]: the content hash of the run (SHA-256, BLAKE3).
//! - [`Throttle`]: the byte rate the run may read at.
//! - [`Log`]: where debug lines go.
//! - [`Names`]: user and group names for ids.
//! - [`Batches`]: a fleet that copies file batches on the core's behalf (`-nodes`).

use std::fmt;
use std::io::{self, Read, Seek};
#[cfg(unix)]
pub type KernelFileDescriptor = std::os::fd::RawFd;
/// Windows handles cannot be passed to Unix kernel-copy engines.
#[cfg(windows)]
pub enum KernelFileDescriptor {}
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use KernelFileDescriptor as RawFd;

use crate::catalog::Kind;
use crate::filter::Filter;

/// One entry of a listed tree, relative to its root (`.` is the root itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub rel: String,
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i128,
    pub atime_ns: i128,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Device and inode: two items with the same pair and `nlink > 1` are one hard-linked file.
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    /// Allocated bytes, for `scan -du` and the sparse ratio.
    pub blocks: u64,
    pub link_target: Option<PathBuf>,
}

impl Item {
    pub fn depth(&self) -> usize {
        if self.rel == "." {
            0
        } else {
            self.rel.matches('/').count() + 1
        }
    }
    pub fn name(&self) -> &str {
        self.rel.rsplit('/').next().unwrap_or(&self.rel)
    }
}

/// A listing plus the directories that could not be read. An unreadable directory is
/// reported, not fatal: the rest of the tree still gets copied.
#[derive(Debug, Default)]
pub struct Listing {
    pub items: Vec<Item>,
    pub errors: Vec<String>,
}

impl Listing {
    /// The listing of a root that is not there, or not a file or directory, when it is
    /// listed -- which must NOT read as an empty tree. `Listing::default()` is no items and
    /// no errors, the exact shape of a complete listing of an empty source, so a mirror would
    /// plan every destination entry as gone and a sync every catalog entry. Connecting
    /// checks the root first, so what reaches here is a root that vanished
    /// between the connect and the list; the error makes the listing incomplete, and an
    /// incomplete source listing plans no removals.
    pub fn unseen_root(root: &Path) -> Listing {
        Listing {
            items: Vec::new(),
            errors: vec![format!(
                "{}: the root is not there to list, so the listing is not complete",
                root.display()
            )],
        }
    }
}

/// A run of file content: bytes, or a hole of the given length.
pub enum Segment<'a> {
    Data(&'a [u8]),
    Hole(u64),
}

/// Which parts of an item's metadata to apply.
#[derive(Debug, Clone, Copy)]
pub struct MetaOptions {
    pub mode: bool,
    pub times: bool,
    pub owner: bool,
    /// Restore the access time from the item rather than setting it to the modification time.
    pub atime: bool,
}

impl Default for MetaOptions {
    fn default() -> Self {
        MetaOptions {
            mode: true,
            times: true,
            owner: true,
            atime: false,
        }
    }
}

/// What a `remove` did, because "the call did not fail" is not "the object is gone".
///
/// Two answers, error or `Ok(())`, are not enough: every caller reads the second as a
/// removal. A registry answers **405** to a blob `DELETE` -- Docker Hub, ECR and Artifact
/// Registry all do, because blobs belong to its garbage collector rather than to its
/// clients -- and that is neither a failure the run should stop for nor a removal the run
/// may count. The reason rides along so the summary can say which store kept what, in that
/// store's own terms.
///
/// `Gone` means the END STATE holds, not that a request was issued. A registry's
/// `index.json`, `oci-layout` and directories are views this crate renders, and removing
/// the manifests is what removes them, so they are `Gone` without a `DELETE` of their
/// own.
///
/// `Kept` and `Deferred` are separate answers because a caller reading only the exit code
/// must conclude different things from them. A registry that answers 405 to a
/// blob `DELETE` will remove the blob ITSELF, on its garbage collector's schedule; the
/// operator has nothing left to do. A WebDAV server answering 423, or a namenode answering
/// `false`, has REFUSED: the entry is still there and will stay there until somebody
/// does something. A `delete` that ends with entries refused has not done what it was
/// asked, and its exit code says so; one that ends with entries deferred has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    /// the entry is no longer there
    Gone,
    /// the store answered without an error and will remove it itself, later
    Deferred(String),
    /// the store answered without an error, and refused
    Kept(String),
}

impl Removed {
    /// For a remove made on the way to something else -- clearing a name before a rename
    /// or a symlink -- where `Kept` is not a third outcome but a reason the next step
    /// cannot happen. A bare `self.remove(..)?`, `Kept` being `Ok`, goes on to rename over
    /// an entry the store has just said it is keeping; grep for the `?` to find such call
    /// sites. `Deferred` is not cleared either: the name is still taken until the store
    /// gets around to it.
    pub fn cleared(self, what: &str) -> io::Result<()> {
        match self {
            Removed::Gone => Ok(()),
            Removed::Deferred(why) => Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("{what}: not cleared yet, {why}"),
            )),
            Removed::Kept(why) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{what}: not cleared, {why}"),
            )),
        }
    }

    /// A store's refusal, told apart from a fault in this run -- a fourth outcome `remove`
    /// has that the three variants alone do not capture.
    ///
    /// Only WebDAV (a 423, or a 207 with a refused member) and HDFS (a namenode's `false`)
    /// produce `Kept` directly, because those two answer a refusal INSIDE a successful
    /// response. A local `EACCES`, an `NFS3ERR_ACCES`, an SFTP permission denial and an S3
    /// `403` are the same event -- the store answered and said no -- and without this each
    /// of them would be an `Err`.
    ///
    /// The exit code is right either way (`ok()` is false for failures and for kept
    /// alike). What differs is the REMEDY printed beside it: a failure says to use
    /// `resume`, and `resume` never plans removals, so for a refusal that advice cannot work
    /// no matter how often it is followed. A refusal says to run `sync` again once the entry can go.
    ///
    /// Only `PermissionDenied` crosses over. A timeout, a malformed answer or a broken
    /// connection is a fault in the run and stays one.
    pub fn or_refused(e: io::Error) -> io::Result<Removed> {
        if e.kind() == io::ErrorKind::PermissionDenied {
            return Ok(Removed::Kept(format!("the store refused: {e}")));
        }
        Err(e)
    }
}

/// What applying metadata could not do, as opposed to what failed: a non-root copy cannot
/// give a file away, and a destination filesystem may refuse `trusted.*` attributes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Refusals {
    pub owner: bool,
    pub xattrs: Vec<String>,
}

impl Refusals {
    pub fn is_empty(&self) -> bool {
        !self.owner && self.xattrs.is_empty()
    }
}

/// One entry a run could not complete: what was attempted, where, and a stable code an
/// automated caller can branch on without reading the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The operation: `copy`, `link`, `symlink`, `mkdir`, `remove`, `directory`, `list`,
    /// `finishing`.
    pub op: &'static str,
    /// The entry, relative to the tree root; the tree itself for `list` and `finishing`.
    pub path: String,
    /// One of the codes in `code_of`, plus `owner` for an ownership refusal made an error
    /// by `-chown`.
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(op: &'static str, path: impl Into<String>, e: &io::Error) -> Failure {
        Failure {
            op,
            path: path.into(),
            code: code_of(e),
            message: e.to_string(),
        }
    }
    /// A failure that is not an `io::Error`: the caller names the code.
    pub fn of(
        op: &'static str,
        path: impl Into<String>,
        code: &'static str,
        message: impl Into<String>,
    ) -> Failure {
        Failure {
            op,
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path, self.message)
    }
}

/// The stable code for an error kind. The set is closed on purpose: an automated caller
/// branches on these, so a kind that is not listed becomes `io` rather than a new name.
pub fn code_of(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::NotFound => "notfound",
        io::ErrorKind::PermissionDenied => "permission",
        io::ErrorKind::AlreadyExists => "exists",
        io::ErrorKind::Unsupported => "unsupported",
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => "invalid",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::Interrupted => "interrupted",
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof => "disconnected",
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown => "unreachable",
        io::ErrorKind::StorageFull => "nospace",
        io::ErrorKind::QuotaExceeded => "quota",
        io::ErrorKind::ResourceBusy => "busy",
        io::ErrorKind::WouldBlock => "wouldblock",
        _ => "io",
    }
}

/// A streaming content hash.
pub trait Digest: Send {
    fn update(&mut self, data: &[u8]);
    /// The hex digest; consumes the hasher.
    fn finish(self: Box<Self>) -> String;
}

/// The digest algorithm of a run: names itself and starts hashers.
pub trait Digests: Send + Sync {
    fn name(&self) -> &'static str;
    fn start(&self) -> Box<dyn Digest>;
}

/// The rate every source byte is read at; `take` blocks as long as the limit says.
pub trait Throttle: Send + Sync {
    fn take(&self, bytes: u64);
    /// Whether `take` can block at all. An engine that multiplexes many files on one
    /// thread asks, because it blocks its whole event loop, not one file, when it pays.
    fn limits(&self) -> bool {
        true
    }
}

/// Where a run may be sent by a host it is already talking to.
///
/// Several protocols let the far end pick where the next connection goes: an OCI upload
/// `Location`, an OCI bearer `realm`, a WebHDFS `Location` naming the datanode that will
/// receive the file body. Each of those is a host chosen by the remote rather than by the
/// operator, and each is a place this run's bytes -- or its credentials -- end up.
///
/// They are all legitimate in their protocols. Docker Hub's realm is `auth.docker.io`,
/// ECR's uploads go to S3, and a WebHDFS cluster is datanodes by design, so an unrailed
/// run follows them: naming the cluster is already the statement of trust. A railed one
/// follows them only to an authority its own `-allow` roots name, because `-allow` is the
/// operator saying where this run may go.
///
/// The policy lives here, next to the rails, rather than inside one adapter. It was
/// `oci::Away` and only OCI consulted it, which is exactly how the same hole stayed open
/// in `hdfs://` after it was closed for registries -- two adapters, one rule, and only one
/// of them enforcing it. One definition and one `check` is the structural answer.
#[derive(Clone, Debug)]
pub enum Away {
    /// Follow it. The remote is trusted, which is what an unrailed run has already said by
    /// naming it.
    Anywhere,
    /// Follow it only to one of these `scheme://host:port` authorities. The endpoint's own
    /// authority is the operator's choice and is admitted by its caller before this is
    /// consulted.
    Only(Arc<[String]>),
}

impl Away {
    /// `Ok(())` if this run may be handed to `scheme://host:port`, or the tail of a refusal
    /// naming what was refused and the `-allow` that would admit it.
    ///
    /// The advice names the PORT when it is not the scheme's default. It did not at first,
    /// and advice that does not work costs a round of trying it: for an away host on
    /// `https://reg.local:8443` it said `add -allow https://reg.local`, which derives :443
    /// and refuses the same hand-off again.
    pub fn check(&self, scheme: &str, host: &str, port: u16) -> Result<(), String> {
        let Away::Only(allowed) = self else {
            return Ok(());
        };
        let authority = format!("{scheme}://{host}:{port}");
        if allowed.iter().any(|a| same_authority(a, &authority)) {
            return Ok(());
        }
        let advice = if port == if scheme == "http" { 80 } else { 443 } {
            format!("{scheme}://{host}")
        } else {
            authority.clone()
        };
        Err(format!(
            "{authority}, which this run's rails do not name; add -allow {advice}"
        ))
    }
}

/// Whether two `scheme://host:port` strings name the same place.
///
/// Not `==`, whose failure is a FALSE DENIAL, not a bypass. DNS names are case-insensitive
/// and a trailing dot is the same name rooted, so under `==` `-allow https://Reg.Example`
/// and a `Location` on `https://reg.example` are two different authorities and the
/// hand-off is refused. Neither of those can let an unnamed
/// host through -- the comparison is still exact after normalizing -- so this is about the
/// rail not refusing work it was meant to admit.
///
/// The scheme is compared the same way, because a URL's scheme is case-insensitive too.
/// The port is already a number on both sides by the time it gets here. Bracketed IPv6
/// literals normalize on case as well, which is what makes `[::1]` and `[::1]` agree
/// whichever of the two hex spellings each side used; rcp does not canonicalize IPv6
/// address FORMS (`[::1]` against `[0:0:0:0:0:0:0:1]`), and that residue is a false denial
/// of the same kind rather than a hole.
fn same_authority(a: &str, b: &str) -> bool {
    let strip = |s: &str| -> String {
        let s = s.to_ascii_lowercase();
        match s.rsplit_once(':') {
            // "host." and "host" are the same name; the dot is the root label written out
            Some((host, port)) => format!("{}:{port}", host.trim_end_matches('.')),
            None => s,
        }
    };
    strip(a) == strip(b)
}

/// Where the run's debug lines go. `enabled` is checked first so the arguments are not
/// formatted when nobody is listening.
pub trait Log: Send + Sync {
    fn enabled(&self) -> bool;
    fn line(&self, args: fmt::Arguments<'_>);
}

/// User and group names for ids, and back.
pub trait Names: Send + Sync {
    fn user(&self, uid: u32) -> String;
    fn group(&self, gid: u32) -> String;
    fn uid_of(&self, name: &str) -> Option<u32>;
    fn gid_of(&self, name: &str) -> Option<u32>;
}

/// The cross-cutting ports a run needs, assembled once by the driving adapter.
#[derive(Clone)]
pub struct Runtime {
    pub digests: Arc<dyn Digests>,
    /// The digester for delta CHUNK signatures, fixed at a `DIGEST_LEN`-wide strong hash
    /// whatever `-hash` says. Separate from `digests` because the two answer to different
    /// audiences: `digests` produces the digest a user reads and compares against another
    /// tool, `chunk_digests` produces a 32-byte value that never leaves the pair of rcps
    /// and whose width the wire format fixes.
    pub chunk_digests: Arc<dyn Digests>,
    pub throttle: Arc<dyn Throttle>,
    pub log: Arc<dyn Log>,
    pub names: Arc<dyn Names>,
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("digests", &self.digests.name())
            .field("log", &self.log.enabled())
            .finish()
    }
}

impl Runtime {
    pub fn hasher(&self) -> Box<dyn Digest> {
        self.digests.start()
    }
}

pub struct Unlimited;

impl Throttle for Unlimited {
    fn take(&self, _bytes: u64) {}
    fn limits(&self) -> bool {
        false
    }
}

pub struct Silent;

impl Log for Silent {
    fn enabled(&self) -> bool {
        false
    }
    fn line(&self, _args: fmt::Arguments<'_>) {}
}

pub struct NumericNames;

impl Names for NumericNames {
    fn user(&self, uid: u32) -> String {
        uid.to_string()
    }
    fn group(&self, gid: u32) -> String {
        gid.to_string()
    }
    fn uid_of(&self, name: &str) -> Option<u32> {
        name.parse().ok()
    }
    fn gid_of(&self, name: &str) -> Option<u32> {
        name.parse().ok()
    }
}

/// One `DEBUG` line through a [`Log`], formatted only when the log is enabled.
#[macro_export]
macro_rules! debug {
    ($log:expr, $($arg:tt)*) => {{
        let log: &dyn $crate::ports::Log = &*$log;
        if log.enabled() {
            log.line(format_args!($($arg)*));
        }
    }};
}

/// How one file is copied: what to hash, what to restore, what to flush, and the runtime
/// whose digest and throttle the copy goes through.
#[derive(Debug, Clone)]
pub struct FileOptions {
    pub block_size: usize,
    pub hash: bool,
    pub meta: MetaOptions,
    pub xattrs: bool,
    pub fsync: bool,
    pub nocache: bool,
    pub preserve_atime: bool,
    /// Rewrite a file the destination already has as a patch against it (`-delta`).
    pub delta: bool,
    /// Separately tuned read and write concurrency (`-parallel auto`). `None` -- which is
    /// what a fixed `-parallel N` leaves -- means the stream path takes no permits at all
    /// and runs exactly the code it ran before the stages existed.
    pub stages: Option<Arc<crate::stage::Stages>>,
    pub runtime: Runtime,
}

/// What copying one file produced.
#[derive(Debug)]
pub struct FileOutcome {
    pub bytes: u64,
    /// The hex digest of the content under the run's algorithm, when one was asked for.
    pub sha256: Option<String>,
    pub refusals: Refusals,
    /// For a file sent as a patch: the bytes that crossed as literals.
    pub literal: Option<u64>,
}

/// One content-defined chunk of a destination file: where it is, how long, and its digest
/// under the run's algorithm. The digest is inline, not a heap object, because a large
/// file has a million of these on both ends at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSig {
    pub offset: u64,
    pub len: u32,
    /// The chunk's Gear fingerprint, which the chunker computed on the way past and which
    /// therefore costs nothing to carry. It is the first tier of the match: a source chunk
    /// whose weak hash is in no signature cannot match any of them, so its strong digest
    /// need never be computed. Eight more bytes per signature -- 0.1% of the file at an
    /// 8 KiB average chunk -- to skip up to 82% of the source's hashing. See `delta`.
    pub weak: u64,
    pub digest: [u8; DIGEST_LEN],
}

/// Every digest the runtime can name is 256 bits.
pub const DIGEST_LEN: usize = 32;

/// The identity of the destination file a patch is computed against, so a file that
/// changed between signing and patching is refused rather than patched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Basis {
    pub size: u64,
    pub mtime_ns: i128,
    pub ino: u64,
}

/// One step of a patch: bytes the destination lacks, a range it already has, or a hole.
#[derive(Debug)]
pub enum Patch<'a> {
    Literal(&'a [u8]),
    Copy { offset: u64, len: u64 },
    Hole(u64),
}

/// A file being written: segments in, then `finish` with the item whose metadata it takes.
pub trait Sink {
    /// Declares the final length up front so the filesystem can lay the file out; unwritten
    /// ranges stay holes.
    fn reserve(&mut self, len: u64) -> io::Result<()>;
    fn write(&mut self, data: &[u8]) -> io::Result<()>;
    fn hole(&mut self, len: u64) -> io::Result<()>;
    /// Truncates to the exact length, applies attributes then metadata, optionally fsyncs.
    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals>;
    /// The descriptor, for engines that copy in the kernel; `None` for a remote sink.
    fn raw_fd(&self) -> Option<RawFd>;
    /// Drops what was written from the page cache (`-nocache`); nothing to do remotely.
    fn drop_cache(&self) {}
    /// On a sink from `create_patch`: appends `len` bytes of the basis from `offset`.
    fn copy_basis(&mut self, _offset: u64, _len: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a patch sink",
        ))
    }
    /// On a sink from `create_patch`: the digest the rebuilt file must have; `finish`
    /// refuses the file otherwise.
    ///
    /// The default FAILS, like `copy_basis` above and unlike what it used to do. It
    /// returned `Ok(())` -- fails open -- which is the wrong default for the one call that
    /// decides whether a file rebuilt from a patch is allowed to replace the file it was
    /// built against. Today nothing reaches it: `patch_one` calls `create_patch` first and
    /// every sink that does not override THAT refuses, so a sink cannot be a patch sink
    /// without overriding both. But the pairing was accidental rather than enforced, and an
    /// adapter that grows `create_patch` and forgets `expect` would have silently accepted
    /// every patched file without checking a digest, with nothing in the output to say so.
    /// Failing closed makes that a compile-time-shaped mistake: the sink does not work
    /// until the check is written.
    fn expect(&mut self, _digest: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a patch sink",
        ))
    }
}

pub trait Tree: Sync {
    type Reader: Read + Seek;
    type Sink: Sink;

    fn root(&self) -> &Path;
    /// Every entry in sorted order, parents before children, honoring the filter and depth
    /// limit (`None` for unlimited), listed by `parallel` threads.
    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing>;
    /// The item at `rel`, or `None` when nothing is there.
    fn stat(&self, rel: &str) -> io::Result<Option<Item>>;
    /// Refuse path aliases that would make two distinct planner names address the
    /// same destination entry. Case-sensitive adapters need no additional check.
    fn validate_paths(&self, _source: &[Item], _destination: &[Item]) -> io::Result<()> {
        Ok(())
    }
    /// A plain reader over a file's bytes (holes read as zeros).
    fn open(&self, rel: &str) -> io::Result<Self::Reader>;
    /// Streams a file's content as segments through `sink`, using `buf` as the read buffer.
    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()>;
    /// Opens the destination file for `item`; the item is the whole source entry because an
    /// object store takes the metadata with the bytes rather than after them.
    fn create_file(&self, item: &Item) -> io::Result<Self::Sink>;
    /// Signs the file at `rel` for delta transfer: its chunks under `params`, digested by
    /// `digests`. The default reads the file through `read`; an adapter whose far side can
    /// sign for itself overrides it.
    fn signatures(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        digests: &dyn Digests,
    ) -> io::Result<Vec<ChunkSig>> {
        let mut signer = crate::delta::Signer::new(params, digests);
        let mut buf = vec![0u8; 1 << 20];
        self.read(rel, &mut buf, &mut |seg| match seg {
            Segment::Data(d) => signer.feed(d),
            Segment::Hole(n) => signer.feed_zeros(n),
        })?;
        signer.finish()
    }
    /// Matches the file at `rel` against a destination's signatures and streams the patch
    /// through `emit`; returns the digest of the whole file. The default reads the file
    /// through `read` and matches here; an adapter whose far side holds the bytes overrides
    /// it so only the patch crosses.
    fn delta(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        sigs: &[ChunkSig],
        runtime: &Runtime,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<String> {
        let mut matcher =
            crate::delta::Matcher::new(params, sigs, &*runtime.chunk_digests, &*runtime.digests);
        let mut buf = vec![0u8; 1 << 20];
        self.read(rel, &mut buf, &mut |seg| match seg {
            Segment::Data(d) => {
                runtime.throttle.take(d.len() as u64);
                matcher.feed(d, emit)
            }
            Segment::Hole(n) => matcher.hole(n, emit),
        })?;
        matcher.finish(emit)
    }
    /// Opens a sink that rebuilds `item` as a patch against the file already at its path,
    /// whose identity must still be `basis`. The rebuilt file replaces the old one only
    /// when `finish` succeeds; `Err(Unsupported)` means "copy the file whole instead".
    fn create_patch(
        &self,
        _item: &Item,
        _basis: &Basis,
        _digests: &dyn Digests,
    ) -> io::Result<Self::Sink> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no patching on this adapter",
        ))
    }
    /// Moves a file's bytes without the copy loop reading them: into `sink` without passing
    /// through user space when the adapter and the sink share a kernel, at the rate
    /// `opts.runtime.throttle` allows, or not at all when the destination is content
    /// addressed and already holds them. `Ok(None)` means "not possible here, use `read`",
    /// and an adapter that cannot produce a digest must answer that when `opts.hash` asks
    /// for one, since the copy loop has no other chance to compute it.
    fn kernel_copy(
        &self,
        rel: &str,
        sink: &mut Self::Sink,
        opts: &FileOptions,
    ) -> io::Result<Option<u64>>;
    fn mkdir(&self, rel: &str) -> io::Result<()>;
    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()>;
    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()>;
    /// Removes an entry, and says whether it is actually gone -- see `Removed`, which
    /// exists because "the call did not fail" and "the object is no longer there" are
    /// different claims and this port could only make the first one.
    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed>;
    /// Moves an entry to a new path, replacing what is there; `Err(Unsupported)` when the
    /// adapter has no rename and the caller should copy instead.
    fn rename(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no rename on this adapter",
        ))
    }
    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals>;
    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>>;
    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>>;
    /// Restores a source file's access time after reading it (`-preserve-atime`).
    fn restore_atime(&self, item: &Item) -> io::Result<()>;
    /// Flushes everything written to this tree to stable storage (one call per job, not per file).
    fn sync(&self) -> io::Result<()>;
    /// Whether this tree is one stream, so its files must be written one at a time.
    ///
    /// A tar archive is: a member's header declares a size and its bytes follow, so two
    /// members cannot be in flight at once. Measured before this was here, a copy into one
    /// with the default worker count produced an archive GNU tar read as far as the first
    /// interleaved member and then reported "Skipping to next header" for the rest. The
    /// core copies files one at a time into such a tree, whatever `-parallel` says.
    fn writes_in_one_stream(&self) -> bool {
        false
    }

    /// Whether `sync` *publishes* the copy rather than only making it durable.
    ///
    /// A registry holds the blobs long before it shows an image: the manifests that name
    /// them are pushed in `sync`, so until that succeeds nothing can be pulled. Same for a
    /// tar destination, which is not an archive until the end-of-archive marker is there.
    ///
    /// What this decides is ONE thing the core cannot decide for itself: whether a path
    /// that never calls `sync` may use this destination at all. The `-nodes` fleet and
    /// `copybatch` are separate processes holding their own staging, and only the
    /// coordinator syncs, so for a publishing destination they would report a success with
    /// nothing at the far end -- measured at 3 blobs uploaded, 0 manifests pushed.
    ///
    /// It does NOT decide what a failing `sync` means. It did for one round, and that was
    /// a regression: a failure was taken as fatal for a registry and a warning for a
    /// filesystem, on the reasoning that a filesystem already has every file in place. It
    /// does not -- a write that returned has not reached the disk, and `syncfs` answering
    /// EIO is the kernel saying the dirty pages were dropped. A `sync` that fails is a
    /// failed copy either way.
    fn sync_publishes(&self) -> bool {
        false
    }
    /// Whether a file written here comes back with the mtime it was given.
    ///
    /// Every transport before WebDAV could say yes: a filesystem sets it, S3 keeps it in
    /// user metadata, HDFS has SETTIMES, a registry has no times at all and is never asked.
    /// A WebDAV server records when IT wrote the file and the property is read-only, so
    /// the planner's "does the destination still hold this" check -- size AND mtime --
    /// read every file on such a destination as changed and `sync` copied the whole tree
    /// again. Measured: two files crossed for one edit. When this is false the planner
    /// matches on size alone, which is rsync's `--size-only` and the honest best a store
    /// like that allows; the CATALOG still carries the source mtime, so a changed source
    /// is still noticed. What is lost is detection of a destination edited in place to
    /// the same length, and that is stated rather than hidden.
    fn keeps_times(&self) -> bool {
        true
    }
    /// Whether the mode on an `Item` from this tree is the entry's own, or invented.
    ///
    /// The sibling of `keeps_times` for modes, and the argument is the same one. WebDAV, a
    /// registry and an http listing carry no mode, so their adapters SYNTHESIZE `0o644` for
    /// files and `0o755` for directories -- and without this gate `verify` compares that
    /// against the source's real mode. Measured against an http tree of three files:
    ///
    /// ```text
    /// DIFF mode deploy.sh:  source 0755, destination 0644
    /// DIFF mode secret.env: source 0600, destination 0644
    /// ```
    ///
    /// `readme.txt`, which really is 0644, was silent. So the check fires on exactly the
    /// files where a mode carries meaning -- the executable and the secret -- and stays
    /// quiet on the ones where it does not. That is worse than not checking: it is noise
    /// that looks like signal, on the entries an operator would act on.
    ///
    /// NOT the same question as `rewrites_metadata_in_place`, and tar is the case that
    /// keeps them apart: a tar header STORES the mode (so this is true) and cannot be
    /// rewritten afterwards (so that is false).
    fn keeps_modes(&self) -> bool {
        true
    }
    /// Whether the uid and gid on an `Item` from this tree are the entry's own.
    ///
    /// Separate from `keeps_modes` because the sets differ: S3 carries uid and gid in user
    /// metadata and sftp carries them on the wire, while neither carries an ACL. The same
    /// synthesis applies -- dav, oci and http report `uid: 0, gid: 0` -- and an ungated
    /// comparison has the same flaw. It is silent in a suite that runs as root only
    /// because the source's owner happens to match the invented one.
    fn keeps_owner(&self) -> bool {
        true
    }
    /// Whether an empty `xattrs()` from this tree means "none" or "cannot say".
    ///
    /// Seven adapters return `Ok(Vec::new())` unconditionally. Against a source that has
    /// xattrs that is a `DIFF xattr` per file for a fact the copy already WARNED about and
    /// passed on; against a source that has none it is two empty lists agreeing, which
    /// reads as a check that ran. ACLs ride here too -- `xattr.rs` says so in its first
    /// lines -- so this is the flag that decides whether "0 differences" means the ACLs
    /// matched or were never read.
    fn keeps_xattrs(&self) -> bool {
        true
    }
    /// Whether `chmod` and `chown` against this destination can change anything.
    ///
    /// Not "does it store metadata", which is why this is not called `keeps_metadata`. Tar
    /// is the case that makes the distinction: it DOES store modes, in each
    /// member's header, and still cannot rewrite one after the fact, because a tar stream
    /// is written once through. Its `set_metadata` falls through to `None => {}` for a
    /// regular member that is already written, returns `Ok`, and `apply_tree` counts it as
    /// changed. A registry is the other shape -- it keeps nothing at all -- and both end
    /// up here, because the question `run_apply` asks is the same one.
    ///
    /// During a COPY these destinations are right to accept metadata: an image has no
    /// modes and a tar header is written with the member. It is only as the whole of a
    /// `chmod` that applying nothing and reporting entries changed is a silent success.
    fn rewrites_metadata_in_place(&self) -> bool {
        true
    }
    /// The adapter's own batch engine for same-adapter copies (io_uring on the local one).
    /// Claims files from `next`, reports each through `done`. `Err(Unsupported)` before any
    /// claim means "use the generic engine"; the default is exactly that.
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
            "no native engine for this adapter",
        ))
    }
}

/// A fleet that copies file batches for the core (`-nodes`): given the files, it reports
/// each outcome through `done` and returns when every batch is accounted for.
pub trait Batches: Send + Sync + fmt::Debug {
    fn copy(
        &self,
        files: &[&Item],
        done: &mut (dyn FnMut(usize, io::Result<FileOutcome>) + Send),
    ) -> io::Result<()>;
}

/// The items of a listing by relative path.
pub fn index(items: &[Item]) -> std::collections::BTreeMap<&str, &Item> {
    items.iter().map(|i| (i.rel.as_str(), i)).collect()
}

/// One megabyte of zeros in .bss: what a hole hashes as, and what zero detection compares to.
pub static ZEROS: [u8; 1 << 20] = [0; 1 << 20];

pub fn is_all_zero(chunk: &[u8]) -> bool {
    chunk.chunks(ZEROS.len()).all(|c| c == &ZEROS[..c.len()])
}

/// Feeds `n` zero bytes to a digest, the way a hole hashes.
pub fn hash_zeros(h: &mut dyn Digest, mut n: u64) {
    while n > 0 {
        let take = n.min(ZEROS.len() as u64) as usize;
        h.update(&ZEROS[..take]);
        n -= take as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Away` is the rail a registry's `Location`, a bearer `realm` and a namenode's
    /// redirect are all measured against, so its comparison is worth measuring directly:
    /// a contract arm reaches it only through whatever spellings a stand-in happens to
    /// emit, and every stand-in here writes `http://127.0.0.1:<highport>`.
    #[test]
    fn an_authority_matches_the_same_place_written_differently() {
        let only = |list: &[&str]| {
            Away::Only(
                list.iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .into(),
            )
        };

        // the plain case, and the refusal it is the other half of
        let rail = only(&["https://reg.example:443"]);
        assert!(rail.check("https", "reg.example", 443).is_ok());
        let refused = rail.check("https", "elsewhere.example", 443).unwrap_err();
        assert!(
            refused.contains("elsewhere.example")
                && refused.contains("-allow https://elsewhere.example"),
            "{refused}"
        );

        // case and a trailing dot are the same NAME, and comparing them as bytes made the
        // rail refuse a hand-off it was written to admit. False denial, never a bypass.
        assert!(only(&["https://Reg.Example:443"])
            .check("https", "reg.example", 443)
            .is_ok());
        assert!(only(&["https://reg.example:443"])
            .check("https", "REG.EXAMPLE", 443)
            .is_ok());
        assert!(only(&["https://reg.example.:443"])
            .check("https", "reg.example", 443)
            .is_ok());
        assert!(only(&["HTTPS://reg.example:443"])
            .check("https", "reg.example", 443)
            .is_ok());
        assert!(only(&["https://[::1]:5000"])
            .check("https", "[::1]", 5000)
            .is_ok());

        // and the control on all of that: normalizing must not make different places the
        // same one. A check that lowercased its way into matching anything would pass
        // every line above.
        assert!(
            only(&["https://reg.example:443"])
                .check("https", "reg.example", 5000)
                .is_err(),
            "a different port matched"
        );
        assert!(
            only(&["https://reg.example:443"])
                .check("http", "reg.example", 443)
                .is_err(),
            "a different scheme matched"
        );
        assert!(
            only(&["https://reg.example:443"])
                .check("https", "evil-reg.example", 443)
                .is_err(),
            "a suffix matched"
        );
        assert!(
            only(&["https://reg.example:443"])
                .check("https", "reg.example.evil", 443)
                .is_err(),
            "a longer name matched"
        );
        assert!(
            only(&[]).check("https", "reg.example", 443).is_err(),
            "an empty list admitted a host"
        );

        // no rails, no list: an unrailed run follows what it is told, because naming the
        // remote is already the statement of trust
        assert!(Away::Anywhere
            .check("http", "anything.example", 12345)
            .is_ok());

        // the advice names the port only when it is not the scheme's default, because
        // `-allow https://reg.local` derives :443 and would refuse :8443 again
        assert!(only(&[])
            .check("https", "reg.local", 8443)
            .unwrap_err()
            .contains("-allow https://reg.local:8443"));
        assert!(only(&[])
            .check("http", "reg.local", 80)
            .unwrap_err()
            .contains("-allow http://reg.local"));
    }
}

/// One statement about what an HTTP status means, so three adapters cannot drift apart.
///
/// They did. 429 became `ResourceBusy` in the registry client and stayed `Other` -- which
/// reaches an agent as the undifferentiated `io` -- in S3 and WebHDFS, for a round. The arm
/// that measured it starts a REGISTRY stand-in, so reverting the registry's map turned it
/// red while the other two were green either way, which is the sibling-adapter blind spot
/// this project keeps paying for.
///
/// This is deliberately a TEST rather than a shared function: each adapter's table has
/// entries the others do not (S3's 409 is `AlreadyExists`, WebHDFS answers exceptions by
/// name), and collapsing them would lose that. What has to agree is the handful of codes
/// an automated caller branches on, and a test says so without flattening the rest.
#[cfg(test)]
mod status_tests {
    use std::io::ErrorKind;

    /// The HTTP adapters built into this run. Each is held to the shared codes on its own,
    /// so a build with one of them still checks that one.
    // each push is behind its own feature, so a build may make any number of them
    #[allow(unused_mut, clippy::vec_init_then_push)]
    fn adapters() -> Vec<(&'static str, fn(u16) -> ErrorKind)> {
        let mut out: Vec<(&'static str, fn(u16) -> ErrorKind)> = Vec::new();
        #[cfg(feature = "oci")]
        out.push(("oci", crate::oci::client_kind_of_status));
        #[cfg(feature = "s3")]
        out.push(("s3", crate::s3::client_kind_of_status));
        #[cfg(feature = "hdfs")]
        out.push(("hdfs", crate::hdfs::client_kind_of_status));
        out
    }

    #[test]
    fn a_throttled_service_says_busy_whichever_adapter_is_speaking() {
        for (name, kind_of) in adapters() {
            for status in [429u16, 502, 503, 504] {
                assert_eq!(kind_of(status), ErrorKind::ResourceBusy, "{name} {status}");
            }
            // the control, and it is what keeps this from passing on an adapter that called
            // everything retryable: a status with no entry still falls back, and the codes the
            // three DO share still mean what they meant
            for status in [418u16, 500, 507] {
                assert_eq!(kind_of(status), ErrorKind::Other, "{name} {status}");
            }
            for (status, want) in [
                (404u16, ErrorKind::NotFound),
                (401, ErrorKind::PermissionDenied),
                (403, ErrorKind::PermissionDenied),
            ] {
                assert_eq!(kind_of(status), want, "{name} {status}");
            }
        }
    }
}
