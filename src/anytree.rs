//! `AnyTree`: one static type over every adapter, so a command can copy from a local path
//! to an NFS export or a bucket (or the reverse) through the same generic executor. An enum
//! rather than a trait object because the `Tree` port has associated types, and because the
//! dispatch cost is one match per call against I/O that costs microseconds to milliseconds.

use crate::ports::KernelFileDescriptor as RawFd;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::AtomicUsize;

use crate::catalog::Kind;
#[cfg(feature = "dav")]
use crate::dav::client::{DavReader, DavSink, DavTree};
use crate::filter::Filter;
#[cfg(all(feature = "hdfs", unix))]
use crate::hdfs::client::{HdfsReader, HdfsSink, HdfsTree};
#[cfg(feature = "https")]
use crate::https::client::{HttpsReader, HttpsTree, NoSink};
#[cfg(all(feature = "nfs", unix))]
use crate::nfs::client::{NfsReader, NfsSink, NfsTree};
#[cfg(all(feature = "nfs", unix))]
use crate::nfs::client4::{Nfs4Reader, Nfs4Sink, Nfs4Tree};
#[cfg(feature = "oci")]
use crate::oci::client::{OciReader, OciSink, OciTree};
use crate::ports::{Basis, ChunkSig, Digests, Log, Patch, Runtime};
#[cfg(all(feature = "remote", unix))]
use crate::remote::client::{SshReader, SshSink, SshTree};
#[cfg(feature = "s3")]
use crate::s3::client::{S3Reader, S3Sink, S3Tree};
#[cfg(all(feature = "sftp", unix))]
use crate::sftp::client::{SftpReader, SftpSink, SftpTree};
#[cfg(feature = "smb")]
use crate::smb::client::{SmbReader, SmbSink, SmbTree};
#[cfg(all(feature = "tar", unix))]
use crate::tar::client::{TarReader, TarSink, TarTree};
use crate::tree::{
    FileOptions, FileOutcome, Item, Listing, LocalSink, LocalTree, MetaOptions, Refusals, Removed,
    Segment, Sink, Tree,
};
use crate::{Endpoint, Remote};
use std::sync::Arc;

/// How each kind of remote endpoint is reached in this run: the driven adapters' settings,
/// assembled by the driving adapter beside the `Runtime`.
#[derive(Clone)]
pub struct Transports {
    #[cfg(all(feature = "nfs", unix))]
    pub nfs: crate::nfs::Settings,
    #[cfg(feature = "s3")]
    pub s3: crate::s3::config::S3Options,
    #[cfg(all(feature = "hdfs", unix))]
    pub hdfs: crate::hdfs::client::Settings,
    #[cfg(all(feature = "remote", unix))]
    pub ssh: crate::remote::Settings,
    #[cfg(feature = "oci")]
    pub oci: crate::oci::Settings,
    #[cfg(all(feature = "sftp", unix))]
    pub sftp: crate::sftp::client::Settings,
    #[cfg(all(feature = "tar", unix))]
    pub tar: crate::tar::Settings,
    #[cfg(feature = "dav")]
    pub dav: crate::dav::Settings,
    #[cfg(feature = "smb")]
    pub smb: crate::smb::Settings,
    #[cfg(feature = "https")]
    pub https: crate::https::Settings,
    /// `-via ssh://[user@]host[:port]`: every endpoint that is not local is opened by the
    /// `rcp serve` on that host and spoken to over ssh, so a run here reaches what only
    /// the hop can see -- a registry behind a bastion, a second serve on a private
    /// network. The hop opens the endpoint with ITS environment.
    pub via: Option<Endpoint>,
    pub log: Arc<dyn Log>,
}

impl std::fmt::Debug for Transports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Transports");
        #[cfg(all(feature = "nfs", unix))]
        d.field("nfs", &self.nfs);
        #[cfg(feature = "s3")]
        d.field("s3", &self.s3);
        #[cfg(all(feature = "hdfs", unix))]
        d.field("hdfs", &self.hdfs);
        #[cfg(all(feature = "remote", unix))]
        d.field("ssh", &self.ssh);
        #[cfg(all(feature = "sftp", unix))]
        d.field("sftp.ssh", &self.sftp.ssh);
        #[cfg(feature = "oci")]
        d.field("oci", &self.oci);
        #[cfg(all(feature = "tar", unix))]
        d.field("tar", &self.tar);
        #[cfg(feature = "dav")]
        d.field("dav.user", &self.dav.user.is_some());
        #[cfg(feature = "smb")]
        d.field("smb.user", &self.smb.user.is_some());
        d.finish()
    }
}

impl Transports {
    /// The environment's defaults for every transport.
    pub fn from_env(log: Arc<dyn Log>) -> Transports {
        Transports {
            #[cfg(all(feature = "nfs", unix))]
            nfs: crate::nfs::Settings::from_env(log.clone()),
            #[cfg(feature = "s3")]
            s3: crate::s3::config::S3Options::from_env(),
            #[cfg(all(feature = "hdfs", unix))]
            hdfs: crate::hdfs::client::Settings::from_env(log.clone()),
            #[cfg(all(feature = "remote", unix))]
            ssh: crate::remote::Settings::from_env(log.clone()),
            #[cfg(feature = "oci")]
            oci: crate::oci::Settings::from_env(log.clone()),
            #[cfg(all(feature = "sftp", unix))]
            sftp: crate::sftp::client::Settings::from_env(log.clone()),
            #[cfg(all(feature = "tar", unix))]
            tar: crate::tar::Settings {
                names: None,
                log: log.clone(),
                workers: 1,
                rsyncable: false,
            },
            #[cfg(feature = "dav")]
            dav: crate::dav::Settings::default(),
            #[cfg(feature = "smb")]
            smb: crate::smb::Settings::default(),
            #[cfg(feature = "https")]
            https: crate::https::Settings::default(),
            via: None,
            log,
        }
    }
}

// The size spread between variants depends on which endpoints the build has: in the default
// build the adapters are close to one another, and in a build with one of them beside the
// local tree they are not. Trees, readers and sinks are one per open endpoint or file, so the
// bytes are not multiplied by anything that matters. The same holds for all three enums.
#[allow(clippy::large_enum_variant)]
pub enum AnyTree {
    Local(LocalTree),
    #[cfg(all(feature = "nfs", unix))]
    Nfs(NfsTree),
    #[cfg(all(feature = "nfs", unix))]
    Nfs4(Nfs4Tree),
    #[cfg(feature = "s3")]
    S3(S3Tree),
    #[cfg(all(feature = "hdfs", unix))]
    Hdfs(HdfsTree),
    #[cfg(all(feature = "remote", unix))]
    Ssh(SshTree),
    #[cfg(all(feature = "sftp", unix))]
    Sftp(SftpTree),
    #[cfg(feature = "smb")]
    Smb(SmbTree),
    #[cfg(feature = "oci")]
    Oci(OciTree),
    #[cfg(all(feature = "tar", unix))]
    Tar(TarTree),
    #[cfg(feature = "dav")]
    Dav(DavTree),
    #[cfg(feature = "https")]
    Https(HttpsTree),
}

#[allow(clippy::large_enum_variant)] // see `AnyTree`
pub enum AnyReader {
    Local(std::fs::File),
    #[cfg(all(feature = "nfs", unix))]
    Nfs(NfsReader),
    #[cfg(all(feature = "nfs", unix))]
    Nfs4(Nfs4Reader),
    #[cfg(feature = "s3")]
    S3(S3Reader),
    #[cfg(all(feature = "hdfs", unix))]
    Hdfs(HdfsReader),
    #[cfg(all(feature = "remote", unix))]
    Ssh(SshReader),
    #[cfg(all(feature = "sftp", unix))]
    Sftp(SftpReader),
    #[cfg(feature = "smb")]
    Smb(SmbReader),
    #[cfg(feature = "oci")]
    Oci(OciReader),
    #[cfg(all(feature = "tar", unix))]
    Tar(TarReader),
    #[cfg(feature = "dav")]
    Dav(DavReader),
    #[cfg(feature = "https")]
    Https(HttpsReader),
}

#[allow(clippy::large_enum_variant)] // see `AnyTree`
pub enum AnySink {
    Local(LocalSink),
    #[cfg(all(feature = "nfs", unix))]
    Nfs(NfsSink),
    #[cfg(all(feature = "nfs", unix))]
    Nfs4(Nfs4Sink),
    #[cfg(feature = "s3")]
    S3(S3Sink),
    #[cfg(all(feature = "hdfs", unix))]
    Hdfs(HdfsSink),
    #[cfg(all(feature = "remote", unix))]
    Ssh(SshSink),
    #[cfg(all(feature = "sftp", unix))]
    Sftp(SftpSink),
    #[cfg(feature = "smb")]
    Smb(SmbSink),
    #[cfg(feature = "oci")]
    Oci(OciSink),
    #[cfg(all(feature = "tar", unix))]
    Tar(TarSink),
    #[cfg(feature = "dav")]
    Dav(DavSink),
    /// An `https://` tree is read-only, so this variant is never constructed:
    /// `create_file` refuses before one could be.
    #[cfg(feature = "https")]
    Https(NoSink),
}

impl AnyTree {
    /// The tree for a channel that joins one another channel opened (see
    /// `remote::proto::OP_ATTACH`). A registry is the one adapter whose open asserts
    /// something the run itself makes false -- a tag a delete removes, a repository a push
    /// has not published yet -- so it has a join of its own that keeps the push rights of
    /// the first open and skips the assertion. Every other endpoint opens as a later
    /// channel always has: for reading, never creating, so a second channel cannot make a
    /// directory or start a second archive.
    pub fn attach(ep: &Endpoint, create: bool, tr: &Transports) -> io::Result<AnyTree> {
        #[cfg(feature = "oci")]
        if let (Remote::Oci { host, port, tag }, None) = (&ep.remote, &tr.via) {
            return Ok(AnyTree::Oci(OciTree::attach(
                host,
                *port,
                ep.path.to_string_lossy().trim_start_matches('/'),
                tag.as_deref(),
                create,
                &tr.oci,
            )?));
        }
        let _ = create;
        Self::open(ep, false, tr)
    }

    /// Opens the adapter an endpoint names; a remote endpoint is reached here, so a bad host,
    /// export, bucket or credential fails before anything is planned. With `create`, a
    /// missing path inside an export is made, as a copy destination expects.
    pub fn open(ep: &Endpoint, create: bool, tr: &Transports) -> io::Result<AnyTree> {
        let transport = match &ep.remote {
            Remote::Local => "local",
            #[cfg(all(feature = "nfs", unix))]
            Remote::Nfs { .. } if tr.nfs.vers == 4 => "nfs v4",
            Remote::Nfs { .. } => "nfs",
            Remote::S3 { .. } => "s3",
            Remote::Hdfs { .. } => "hdfs",
            Remote::Ssh { .. } => "ssh",
            Remote::Rcp { secure, .. } => {
                if *secure {
                    "rcps"
                } else {
                    "rcp"
                }
            }
            Remote::Sftp { .. } => "sftp",
            Remote::Smb { .. } => "smb",
            Remote::Oci { .. } => "oci",
            Remote::Tar { .. } => "tar",
            Remote::Dav { secure, .. } => {
                if *secure {
                    "davs"
                } else {
                    "dav"
                }
            }
            Remote::Https { secure, .. } => {
                if *secure {
                    "https"
                } else {
                    "http"
                }
            }
        };
        crate::debug!(
            tr.log,
            "open {} ({transport}{})",
            ep.display(),
            if create { ", create" } else { "" }
        );
        #[cfg(not(all(feature = "remote", unix)))]
        if tr.via.is_some() && !matches!(ep.remote, Remote::Local) {
            return Err(not_built(
                "-via relays through `rcp serve`, and this",
                "remote",
            ));
        }
        #[cfg(all(feature = "remote", unix))]
        if let Some(hop) = &tr.via {
            if !matches!(ep.remote, Remote::Local) {
                crate::debug!(tr.log, "open {} via {}", ep.display(), hop.display());
                let tree = match &hop.remote {
                    Remote::Ssh { user, host, port } => SshTree::connect_via(
                        user.as_deref(),
                        host,
                        *port,
                        &ep.display(),
                        create,
                        &tr.ssh,
                    )?,
                    // the same relay over a socket: the hop still opens the endpoint with
                    // ITS environment and its own rails, which is the whole point of -via
                    Remote::Rcp { host, port, secure } => SshTree::connect_tcp_via(
                        host,
                        *port,
                        *secure,
                        &ep.display(),
                        create,
                        &tr.ssh,
                    )?,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{}: -via names an ssh:// or rcp:// serve", hop.display()),
                        ))
                    }
                };
                return Ok(AnyTree::Ssh(tree));
            }
        }
        match &ep.remote {
            Remote::Local => Ok(AnyTree::Local(LocalTree::new(&ep.path))),
            #[cfg(all(feature = "nfs", unix))]
            Remote::Nfs { host, export } if tr.nfs.vers == 4 => Ok(AnyTree::Nfs4(
                Nfs4Tree::connect(host, export, &ep.path, create, &tr.nfs)?,
            )),
            #[cfg(all(feature = "nfs", unix))]
            Remote::Nfs { host, export } => Ok(AnyTree::Nfs(NfsTree::connect(
                host, export, &ep.path, create, &tr.nfs,
            )?)),
            #[cfg(feature = "s3")]
            Remote::S3 { bucket } => Ok(AnyTree::S3(S3Tree::connect(
                bucket,
                &ep.path,
                create,
                &tr.s3,
                tr.log.clone(),
            )?)),
            #[cfg(all(feature = "hdfs", unix))]
            Remote::Hdfs { namenode } => Ok(AnyTree::Hdfs(HdfsTree::connect(
                namenode, &ep.path, create, &tr.hdfs,
            )?)),
            #[cfg(all(feature = "remote", unix))]
            Remote::Ssh { user, host, port } => Ok(AnyTree::Ssh(SshTree::connect(
                user.as_deref(),
                host,
                *port,
                &ep.path,
                create,
                &tr.ssh,
            )?)),
            // the same adapter and the same protocol; only the channel differs
            #[cfg(all(feature = "remote", unix))]
            Remote::Rcp { host, port, secure } => Ok(AnyTree::Ssh(SshTree::connect_tcp(
                host, *port, *secure, &ep.path, create, &tr.ssh,
            )?)),
            #[cfg(all(feature = "sftp", unix))]
            Remote::Sftp { user, host, port } => Ok(AnyTree::Sftp(SftpTree::connect(
                user.as_deref(),
                host,
                *port,
                &ep.path,
                create,
                &tr.sftp,
            )?)),
            #[cfg(feature = "smb")]
            Remote::Smb {
                user,
                host,
                port,
                share,
            } => Ok(AnyTree::Smb(SmbTree::connect(
                user.as_deref(),
                host,
                *port,
                share,
                &ep.path,
                create,
                &tr.smb,
                &*tr.log,
            )?)),
            #[cfg(feature = "oci")]
            Remote::Oci { host, port, tag } => Ok(AnyTree::Oci(OciTree::connect(
                host,
                *port,
                ep.path.to_string_lossy().trim_start_matches('/'),
                tag.as_deref(),
                create,
                &tr.oci,
            )?)),
            #[cfg(all(feature = "tar", unix))]
            Remote::Tar { sub } => Ok(AnyTree::Tar(TarTree::open(&ep.path, sub, create, &tr.tar)?)),
            #[cfg(feature = "dav")]
            Remote::Dav { .. } => Ok(AnyTree::Dav(DavTree::connect(
                &ep.display(),
                create,
                &tr.dav,
                tr.log.clone(),
            )?)),
            #[cfg(feature = "https")]
            Remote::Https { .. } => Ok(AnyTree::Https(HttpsTree::connect(
                &ep.display(),
                create,
                &tr.https,
                tr.log.clone(),
            )?)),
            // Every scheme parses whatever the build, so a URL for an endpoint left out of
            // this binary is recognized and refused by name instead of being misread as a
            // local path.
            #[allow(unreachable_patterns)]
            other => Err(not_built("this", other.feature())),
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, AnyTree::Local(_))
    }
}

/// The refusal for an endpoint whose Cargo feature was left out of this build.
fn not_built(what: &str, feature: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} rcp was built without the `{feature}` feature; rebuild with `--features {feature}`"),
    )
}

macro_rules! delegate {
    ($self:ident, $t:ident => $body:expr) => {
        match $self {
            AnyTree::Local($t) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs($t) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs4($t) => $body,
            #[cfg(feature = "s3")]
            AnyTree::S3($t) => $body,
            #[cfg(all(feature = "hdfs", unix))]
            AnyTree::Hdfs($t) => $body,
            #[cfg(all(feature = "remote", unix))]
            AnyTree::Ssh($t) => $body,
            #[cfg(all(feature = "sftp", unix))]
            AnyTree::Sftp($t) => $body,
            #[cfg(feature = "smb")]
            AnyTree::Smb($t) => $body,
            #[cfg(feature = "oci")]
            AnyTree::Oci($t) => $body,
            #[cfg(feature = "dav")]
            AnyTree::Dav($t) => $body,
            #[cfg(feature = "https")]
            AnyTree::Https($t) => $body,
            #[cfg(all(feature = "tar", unix))]
            AnyTree::Tar($t) => $body,
        }
    };
}

macro_rules! delegate_reader {
    ($self:ident, $r:ident => $body:expr) => {
        match $self {
            AnyReader::Local($r) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnyReader::Nfs($r) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnyReader::Nfs4($r) => $body,
            #[cfg(feature = "s3")]
            AnyReader::S3($r) => $body,
            #[cfg(all(feature = "hdfs", unix))]
            AnyReader::Hdfs($r) => $body,
            #[cfg(all(feature = "remote", unix))]
            AnyReader::Ssh($r) => $body,
            #[cfg(all(feature = "sftp", unix))]
            AnyReader::Sftp($r) => $body,
            #[cfg(feature = "smb")]
            AnyReader::Smb($r) => $body,
            #[cfg(feature = "oci")]
            AnyReader::Oci($r) => $body,
            #[cfg(feature = "dav")]
            AnyReader::Dav($r) => $body,
            #[cfg(feature = "https")]
            AnyReader::Https($r) => $body,
            #[cfg(all(feature = "tar", unix))]
            AnyReader::Tar($r) => $body,
        }
    };
}

macro_rules! delegate_sink {
    ($self:ident, $s:ident => $body:expr) => {
        match $self {
            AnySink::Local($s) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnySink::Nfs($s) => $body,
            #[cfg(all(feature = "nfs", unix))]
            AnySink::Nfs4($s) => $body,
            #[cfg(feature = "s3")]
            AnySink::S3($s) => $body,
            #[cfg(all(feature = "hdfs", unix))]
            AnySink::Hdfs($s) => $body,
            #[cfg(all(feature = "remote", unix))]
            AnySink::Ssh($s) => $body,
            #[cfg(all(feature = "sftp", unix))]
            AnySink::Sftp($s) => $body,
            #[cfg(feature = "smb")]
            AnySink::Smb($s) => $body,
            #[cfg(feature = "oci")]
            AnySink::Oci($s) => $body,
            #[cfg(feature = "dav")]
            AnySink::Dav($s) => $body,
            #[cfg(feature = "https")]
            AnySink::Https($s) => $body,
            #[cfg(all(feature = "tar", unix))]
            AnySink::Tar($s) => $body,
        }
    };
}

impl Read for AnyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        delegate_reader!(self, r => r.read(buf))
    }
}

impl Seek for AnyReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        delegate_reader!(self, r => r.seek(pos))
    }
}

impl Sink for AnySink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        delegate_sink!(self, s => s.reserve(len))
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        delegate_sink!(self, s => s.write(data))
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        delegate_sink!(self, s => s.hole(len))
    }
    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals> {
        delegate_sink!(self, s => s.finish(item, xattrs, opts, fsync))
    }
    fn raw_fd(&self) -> Option<RawFd> {
        delegate_sink!(self, s => s.raw_fd())
    }
    fn drop_cache(&self) {
        delegate_sink!(self, s => s.drop_cache())
    }
    fn copy_basis(&mut self, offset: u64, len: u64) -> io::Result<()> {
        delegate_sink!(self, s => s.copy_basis(offset, len))
    }
    fn expect(&mut self, digest: &str) -> io::Result<()> {
        delegate_sink!(self, s => s.expect(digest))
    }
}

impl Tree for AnyTree {
    fn validate_paths(&self, source: &[Item], destination: &[Item]) -> io::Result<()> {
        match self {
            Self::Local(t) => t.validate_paths(source, destination),
            #[allow(unreachable_patterns)]
            _ => Ok(()),
        }
    }
    type Reader = AnyReader;
    type Sink = AnySink;

    fn root(&self) -> &Path {
        delegate!(self, t => t.root())
    }
    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        delegate!(self, t => t.list(filter, max_depth, parallel))
    }
    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        delegate!(self, t => t.stat(rel))
    }
    fn open(&self, rel: &str) -> io::Result<AnyReader> {
        match self {
            AnyTree::Local(t) => t.open(rel).map(AnyReader::Local),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs(t) => t.open(rel).map(AnyReader::Nfs),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs4(t) => t.open(rel).map(AnyReader::Nfs4),
            #[cfg(feature = "s3")]
            AnyTree::S3(t) => t.open(rel).map(AnyReader::S3),
            #[cfg(all(feature = "hdfs", unix))]
            AnyTree::Hdfs(t) => t.open(rel).map(AnyReader::Hdfs),
            #[cfg(all(feature = "remote", unix))]
            AnyTree::Ssh(t) => t.open(rel).map(AnyReader::Ssh),
            #[cfg(all(feature = "sftp", unix))]
            AnyTree::Sftp(t) => t.open(rel).map(AnyReader::Sftp),
            #[cfg(feature = "smb")]
            AnyTree::Smb(t) => t.open(rel).map(AnyReader::Smb),
            #[cfg(feature = "oci")]
            AnyTree::Oci(t) => t.open(rel).map(AnyReader::Oci),
            #[cfg(feature = "dav")]
            AnyTree::Dav(t) => t.open(rel).map(AnyReader::Dav),
            #[cfg(feature = "https")]
            AnyTree::Https(t) => t.open(rel).map(AnyReader::Https),
            #[cfg(all(feature = "tar", unix))]
            AnyTree::Tar(t) => t.open(rel).map(AnyReader::Tar),
        }
    }
    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        delegate!(self, t => t.read(rel, buf, sink))
    }
    fn create_file(&self, item: &Item) -> io::Result<AnySink> {
        match self {
            AnyTree::Local(t) => t.create_file(item).map(AnySink::Local),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs(t) => t.create_file(item).map(AnySink::Nfs),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs4(t) => t.create_file(item).map(AnySink::Nfs4),
            #[cfg(feature = "s3")]
            AnyTree::S3(t) => t.create_file(item).map(AnySink::S3),
            #[cfg(all(feature = "hdfs", unix))]
            AnyTree::Hdfs(t) => t.create_file(item).map(AnySink::Hdfs),
            #[cfg(all(feature = "remote", unix))]
            AnyTree::Ssh(t) => t.create_file(item).map(AnySink::Ssh),
            #[cfg(all(feature = "sftp", unix))]
            AnyTree::Sftp(t) => t.create_file(item).map(AnySink::Sftp),
            #[cfg(feature = "smb")]
            AnyTree::Smb(t) => t.create_file(item).map(AnySink::Smb),
            #[cfg(feature = "oci")]
            AnyTree::Oci(t) => t.create_file(item).map(AnySink::Oci),
            #[cfg(all(feature = "tar", unix))]
            AnyTree::Tar(t) => t.create_file(item).map(AnySink::Tar),
            #[cfg(feature = "dav")]
            AnyTree::Dav(t) => t.create_file(item).map(AnySink::Dav),
            #[cfg(feature = "https")]
            AnyTree::Https(t) => t.create_file(item).map(AnySink::Https),
        }
    }
    fn kernel_copy(
        &self,
        rel: &str,
        sink: &mut AnySink,
        opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        match (self, sink) {
            (AnyTree::Local(t), AnySink::Local(s)) => t.kernel_copy(rel, s, opts),
            // a content-addressed destination that already holds the file: nothing to read
            #[cfg(feature = "oci")]
            (_, AnySink::Oci(s)) => Ok(s.present_len()),
            // unreachable only in a build with no endpoint beside the local one
            #[allow(unreachable_patterns)]
            _ => Ok(None),
        }
    }
    fn signatures(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        digests: &dyn Digests,
    ) -> io::Result<Vec<ChunkSig>> {
        delegate!(self, t => t.signatures(rel, params, digests))
    }
    fn delta(
        &self,
        rel: &str,
        params: crate::cdc::Params,
        sigs: &[ChunkSig],
        runtime: &Runtime,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<String> {
        delegate!(self, t => t.delta(rel, params, sigs, runtime, emit))
    }
    fn create_patch(
        &self,
        item: &Item,
        basis: &Basis,
        digests: &dyn Digests,
    ) -> io::Result<AnySink> {
        match self {
            AnyTree::Local(t) => t.create_patch(item, basis, digests).map(AnySink::Local),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs(t) => t.create_patch(item, basis, digests).map(AnySink::Nfs),
            #[cfg(all(feature = "nfs", unix))]
            AnyTree::Nfs4(t) => t.create_patch(item, basis, digests).map(AnySink::Nfs4),
            #[cfg(feature = "s3")]
            AnyTree::S3(t) => t.create_patch(item, basis, digests).map(AnySink::S3),
            #[cfg(all(feature = "hdfs", unix))]
            AnyTree::Hdfs(t) => t.create_patch(item, basis, digests).map(AnySink::Hdfs),
            #[cfg(all(feature = "remote", unix))]
            AnyTree::Ssh(t) => t.create_patch(item, basis, digests).map(AnySink::Ssh),
            #[cfg(all(feature = "sftp", unix))]
            AnyTree::Sftp(t) => t.create_patch(item, basis, digests).map(AnySink::Sftp),
            #[cfg(feature = "smb")]
            AnyTree::Smb(t) => t.create_patch(item, basis, digests).map(AnySink::Smb),
            #[cfg(feature = "oci")]
            AnyTree::Oci(t) => t.create_patch(item, basis, digests).map(AnySink::Oci),
            #[cfg(all(feature = "tar", unix))]
            AnyTree::Tar(t) => t.create_patch(item, basis, digests).map(AnySink::Tar),
            #[cfg(feature = "dav")]
            AnyTree::Dav(t) => t.create_patch(item, basis, digests).map(AnySink::Dav),
            #[cfg(feature = "https")]
            AnyTree::Https(t) => t.create_patch(item, basis, digests).map(AnySink::Https),
        }
    }
    fn mkdir(&self, rel: &str) -> io::Result<()> {
        delegate!(self, t => t.mkdir(rel))
    }
    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        delegate!(self, t => t.symlink(rel, target))
    }
    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        delegate!(self, t => t.hard_link(existing, rel))
    }
    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        delegate!(self, t => t.remove(rel, kind))
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        delegate!(self, t => t.rename(from, to))
    }
    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        delegate!(self, t => t.set_metadata(rel, item, opts))
    }
    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        delegate!(self, t => t.xattrs(rel))
    }
    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        delegate!(self, t => t.set_xattrs(rel, attrs))
    }
    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        delegate!(self, t => t.restore_atime(item))
    }
    fn sync(&self) -> io::Result<()> {
        delegate!(self, t => t.sync())
    }
    fn keeps_times(&self) -> bool {
        delegate!(self, t => t.keeps_times())
    }
    // THE THREE BELOW WERE MISSING, AND THAT MADE SIXTEEN OVERRIDES DEAD CODE. `keeps_times`
    // was delegated here; its three siblings were not, so `AnyTree` answered the trait's
    // default `true` for every adapter -- and every command goes through `AnyTree`. So
    // `keeps_modes` and `keeps_owner` on dav, http, oci and smb, and `keeps_xattrs` on
    // those plus s3, sftp, hdfs and tar, had never once been read.
    //
    // Measured on the smb adapter the moment it was written: `verify` against a share
    // reported
    //
    //     DIFF mode message.txt: source 0640, destination 0644
    //     DIFF mode script.sh:   source 0755, destination 0644
    //     verify: 7 entries compared, 4 differences, 0 WARNINGS
    //
    // which is exactly the output `keeps_modes`'s own doc comment in `ports.rs` quotes as
    // the thing it was added to stop -- against an invented 0644, with no warning, on a
    // copy that was correct and complete. The predicate was right; nothing asked it.
    fn keeps_modes(&self) -> bool {
        delegate!(self, t => t.keeps_modes())
    }
    fn keeps_owner(&self) -> bool {
        delegate!(self, t => t.keeps_owner())
    }
    fn keeps_xattrs(&self) -> bool {
        delegate!(self, t => t.keeps_xattrs())
    }
    fn rewrites_metadata_in_place(&self) -> bool {
        delegate!(self, t => t.rewrites_metadata_in_place())
    }
    fn sync_publishes(&self) -> bool {
        delegate!(self, t => t.sync_publishes())
    }
    fn writes_in_one_stream(&self) -> bool {
        delegate!(self, t => t.writes_in_one_stream())
    }
    fn native_copy(
        &self,
        dst: &Self,
        files: &[&Item],
        next: &AtomicUsize,
        workers: usize,
        opts: &FileOptions,
        done: &mut dyn FnMut(usize, io::Result<FileOutcome>),
    ) -> io::Result<()> {
        match (self, dst) {
            (AnyTree::Local(s), AnyTree::Local(d)) => {
                s.native_copy(d, files, next, workers, opts, done)
            }
            #[allow(unreachable_patterns)]
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no native engine across adapters",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Is `feature` compiled into this build? `cfg!` needs a literal, hence the table.
    fn built(feature: &str) -> bool {
        match feature {
            "nfs" => cfg!(feature = "nfs"),
            "s3" => cfg!(feature = "s3"),
            "smb" => cfg!(feature = "smb"),
            "sftp" => cfg!(feature = "sftp"),
            "remote" => cfg!(feature = "remote"),
            "dav" => cfg!(feature = "dav"),
            "hdfs" => cfg!(feature = "hdfs"),
            "https" => cfg!(feature = "https"),
            "oci" => cfg!(feature = "oci"),
            "tar" => cfg!(feature = "tar"),
            other => panic!("no feature {other:?}"),
        }
    }

    /// A URL for an endpoint left out of the build is refused by name, with the feature that
    /// adds it, and not read as a local path. Only a reduced build can show the refusal, so
    /// CI's `features` job runs these tests with no endpoint at all; in the default build the
    /// arm still holds the table to `Remote::feature`, and the count at the end shows which of
    /// the two it measured.
    #[test]
    fn an_endpoint_left_out_of_the_build_is_refused_by_name() {
        let tr = Transports::from_env(Arc::new(crate::ports::Silent));
        let table = [
            ("nfs://filer/export/p", "nfs"),
            ("s3://bucket/p", "s3"),
            ("smb://host/share/p", "smb"),
            ("sftp://host/p", "sftp"),
            ("ssh://host/p", "remote"),
            ("rcp://host:9/p", "remote"),
            ("dav://host/p", "dav"),
            ("hdfs://namenode:9870/p", "hdfs"),
            ("https://host/p", "https"),
            ("oci://host/repo", "oci"),
            ("tar:///nonexistent/a.tar", "tar"),
        ];
        let mut refused = 0;
        for (url, feature) in table {
            let ep = Endpoint::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(ep.remote.feature(), feature, "{url}");
            if built(feature) {
                continue;
            }
            let Err(e) = AnyTree::open(&ep, false, &tr) else {
                panic!("{url} opened in a build without `{feature}`");
            };
            assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{url}: {e}");
            let text = e.to_string();
            // the caller prefixes the endpoint, so the message names only what is missing
            assert!(
                text.starts_with("this rcp was built without")
                    && text.contains(&format!("`{feature}`")),
                "{url}: {text}"
            );
            refused += 1;
        }
        let left_out = table.iter().filter(|(_, f)| !built(f)).count();
        assert_eq!(refused, left_out);
        // `-via` is the one route to a remote endpoint that is not a URL of its own
        if !built("remote") {
            let tr = Transports {
                via: Some(Endpoint::parse("ssh://hop/").unwrap()),
                ..Transports::from_env(Arc::new(crate::ports::Silent))
            };
            let ep = Endpoint::parse("s3://bucket/p").unwrap();
            let Err(e) = AnyTree::open(&ep, false, &tr) else {
                panic!("-via opened without `remote`");
            };
            assert!(e.to_string().contains("`remote`"), "{e}");
        }
    }
    /// Every capability predicate on `Tree` must be DELEGATED by `AnyTree`, checked against
    /// this file's own source rather than against behavior.
    ///
    /// This is the arm that would have found the `keeps_modes` / `keeps_owner` /
    /// `keeps_xattrs` gap the day it was written, instead of one adapter later. The way that
    /// bug worked is the reason a behavioral test could not: `AnyTree` answers the trait's
    /// DEFAULT for anything it does not override, and a default is a silent success. Nothing
    /// fails to compile, nothing warns, and a test written against the resulting output --
    /// which is what the WebDAV arm was -- goes green and LOCKS THE BUG IN.
    ///
    /// The remedy fits in one line: assert that the wrapper's answer comes from the
    /// adapter, for every predicate, by construction. Reading the source is how that is
    /// done without one instance of every adapter and a live server apiece.
    ///
    /// Adding a predicate to `Tree` and not to `AnyTree` now fails HERE, with the name.
    #[test]
    fn every_capability_predicate_is_delegated_rather_than_left_to_its_default() {
        let ports = include_str!("ports.rs");
        // Everything in this file EXCEPT this test module, and that is not tidiness: the
        // haystack otherwise contains this arm's own assertions, so the control below --
        // which requires a predicate nobody wrote to read as NOT delegated -- found its own
        // search string and failed. A test that anchors on its own text measures the
        // ordering of two literals inside itself, which this repo has paid for before.
        let anytree = include_str!("anytree.rs");
        let anytree = &anytree[..anytree.find("#[cfg(test)]").unwrap_or(anytree.len())];
        // ONLY the `Tree` trait's body. Reading the whole file picked up `Log::enabled`,
        // which has the same shape and is not a tree capability -- an arm that fails on
        // something it was never about gets edited until it passes, and what it is edited
        // into is usually weaker. Brace depth from the trait's own opening brace, because
        // a "stop at a line that is just }" rule breaks on the first nested block.
        let start = ports
            .find("pub trait Tree")
            .expect("the port is named `Tree`");
        let open = start + ports[start..].find('{').expect("the trait has a body");
        let mut depth = 0i32;
        let mut end = open;
        for (i, ch) in ports[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(
            end > open,
            "the trait body did not close, so this arm is reading nothing"
        );
        let ports = &ports[open..end];
        // the predicates are the `fn <name>(&self) -> bool` methods of the port: no
        // arguments, a bool, and a default body. That shape is exactly "a wrapper can
        // silently keep the default", which is the class this checks.
        let mut found = Vec::new();
        for line in ports.lines().map(str::trim) {
            if let Some(rest) = line.strip_prefix("fn ") {
                if let Some(name) = rest.split('(').next() {
                    if rest.contains("(&self) -> bool") {
                        found.push(name.to_string());
                    }
                }
            }
        }
        assert!(
            found.len() >= 6,
            "only {} predicates found in the port, so this arm is not reading what it thinks: {found:?}",
            found.len()
        );
        let missing: Vec<&String> = found
            .iter()
            .filter(|n| !anytree.contains(&format!("delegate!(self, t => t.{n}()")))
            .collect();
        assert!(
            missing.is_empty(),
            "AnyTree does not delegate these, so it answers the trait's default for EVERY adapter and every override of them is dead code: {missing:?}"
        );
        // THE CONTROL: the check can fail. A predicate that does not exist must not be
        // reported as delegated -- if it were, the comparison above would pass for a port
        // method nobody wrote, and therefore proves nothing about the ones who did.
        assert!(!anytree.contains("delegate!(self, t => t.keeps_nothing_at_all()"));
    }
}
