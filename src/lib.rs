//! rcp (Rust copy): a general-purpose data mover for local paths, NFS exports and S3
//! buckets, distributed under Apache-2.0, with no bundled interpreter or telemetry.
//!
//! # Stability
//!
//! The supported interface is the `rcp` command. This library is public so the binary,
//! the in-tree tests and the fuzz targets can share it, and so a caller can start from
//! [`ports::Runtime::plain`]. The library API is unstable before 1.0: modules, types and
//! behavior may change in any release. Items that exist only for tests are `doc(hidden)`
//! and are not part of that surface.
//!
//! The crates.io package name is `rust-cp` (`rcp` was already published by someone else).
//! The library target name is still `rcp`, so dependents write `use rcp::...`.
//!
//! The default build's only third-party crates are audited open-source cryptography (the
//! RustCrypto `sha2`, `hmac`, `md4`, `md-5`, `aes` and `cmac` crates, and the official
//! `blake3`). Enable `rustls` for TLS and
//! `system-zstd` to use the system compression library. Endpoint modules are controlled
//! by their corresponding Cargo features; parsing an [`Endpoint`] does not open it or
//! check that its transport was enabled. GNU/Linux release binaries dynamically link
//! system GNU libc, and Kerberos requires the host's GSSAPI library and ticket cache.
//!
//! The crate is a hexagon, and `tests/hexagon.rs` reads the source to keep it one.
//!
//! - **Ports** ([`ports`]): [`ports::Tree`] and [`ports::Sink`] for a storage location; `Digests` for the content
//!   hash; `Throttle` for the read rate; `Log` for debug lines; `Names` for ids; `Batches`
//!   for a worker fleet. `Runtime` bundles the cross-cutting ones.
//! - **Core** (`plan`, `transfer`, `scan`, `catalog`, `filter`): pure logic from listings to
//!   actions and the use cases that run them, written against the ports only, with no
//!   process-wide state.
//! - **Driven adapters**: `tree::LocalTree` (with `uring` as its fast engine and `xattr`),
//!   `nfs::NfsTree` and `nfs::Nfs4Tree`, `s3::client::S3Tree`, `hdfs::client::HdfsTree`;
//!   `hash` (SHA-256, BLAKE3), `throttle`, `log`, `names`, `cluster` (the ssh fleet).
//!   Each takes its settings at construction; `anytree` is the static dispatch over the trees
//!   and `Transports` the settings of every remote kind.
//! - **Driving adapter**: the CLI in `main.rs`, which parses options, assembles a `Runtime`
//!   and `Transports`, opens the trees and calls the use cases. [`ports::Runtime::plain`] is
//!   the assembly a library caller starts from.
//!
//! Unsafe code supports filesystem and network syscalls, GSSAPI loading, process
//! lifecycle control, and CPU-specific hashing and encryption. Its safety depends on
//! checked buffer extents, ownership, runtime CPU-feature detection, and syscall-specific
//! contracts documented at those sites; these boundaries also have regression tests.
//!
//! Endpoints are paths (`file:///...` or `/...`), NFS exports (`host:/export[:/sub]`,
//! `nfs://host/export`), buckets (`s3://bucket/prefix`) or HDFS paths
//! (`hdfs://namenode:port/path`, over WebHDFS).

#[macro_use]
pub mod ports;
#[cfg(all(
    windows,
    any(
        feature = "nfs",
        feature = "hdfs",
        feature = "remote",
        feature = "sftp",
        feature = "tar",
        feature = "system-zstd"
    )
))]
compile_error!("These protocol/platform features are not supported on Windows yet. Build with --no-default-features, optionally enabling s3,smb,dav,https,oci,rustls. No security or authentication fallback is enabled.");
pub mod anytree;
pub mod base64;
pub mod blake3;
pub mod catalog;
pub mod cdc;
pub mod cluster;
#[cfg(feature = "dav")]
pub mod dav;
pub mod deflate;
pub mod delta;
pub mod describe;
#[cfg(unix)]
pub mod diag;
pub mod filter;
#[cfg(unix)]
pub mod gss;
pub mod hash;
pub mod hashcache;
#[cfg(all(feature = "hdfs", unix))]
pub mod hdfs;
#[cfg(feature = "https")]
pub mod https;
#[cfg(unix)]
pub mod jobs;
pub mod json;
pub mod log;
pub mod lz4;
#[cfg(unix)]
pub mod mcp;
pub mod mounts;
pub mod names;
pub mod net;
#[cfg(all(feature = "nfs", unix))]
pub mod nfs;
#[cfg(feature = "oci")]
pub mod oci;
pub mod plan;
pub mod platform;
#[cfg(all(feature = "remote", unix))]
pub mod remote;
pub mod runtime;
#[cfg(feature = "s3")]
pub mod s3;
pub mod scan;
#[cfg(all(feature = "sftp", unix))]
pub mod sftp;
pub mod sha256;
#[cfg(feature = "smb")]
pub mod smb;
pub mod stage;
#[cfg(all(feature = "tar", unix))]
pub mod tar;
pub mod throttle;
pub mod time;
pub mod transfer;
#[cfg_attr(windows, path = "tree_windows.rs")]
pub mod tree;
#[cfg(unix)]
pub mod uring;
#[cfg(windows)]
pub mod windows;
#[cfg(unix)]
pub mod xattr;
pub mod xdr;
pub mod xxh3;
pub mod zipfile;
pub mod zstd;
/// System libzstd as an alternative backend for the zstd codec, behind `--features system-zstd`.
#[cfg(feature = "system-zstd")]
pub mod zstd_system;

use std::fmt;
use std::path::{Path, PathBuf};

/// How an endpoint is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    Local,
    /// `host:/export[/sub]` and `nfs://host/export[/sub]`.
    Nfs {
        host: String,
        export: String,
    },
    /// `s3://bucket/prefix`.
    S3 {
        bucket: String,
    },
    /// `hdfs://namenode:port/path` (`namenode` empty for `hdfs:///path`, resolved from the
    /// environment when the tree is opened).
    Hdfs {
        namenode: String,
    },
    /// `ssh://[user@]host[:port]/path`: an `rcp serve` on the host, through ssh.
    Ssh {
        user: Option<String>,
        host: String,
        port: Option<u16>,
    },
    /// `rcp://host:port/path`: the same `rcp serve`, reached by a socket instead of ssh.
    /// No user and no default port -- see the parser for why both are deliberate.
    /// `secure` is `rcps://`: the same frames inside TLS, which is the only way a serve may
    /// bind anything but loopback.
    Rcp {
        host: String,
        port: u16,
        secure: bool,
    },
    /// A directory on a host reached through OpenSSH's sftp subsystem: no rcp needed there.
    Sftp {
        user: Option<String>,
        host: String,
        port: Option<u16>,
    },
    /// `smb://[user@]host[:port]/share[/path]`: a Windows, Samba or NAS share over SMB2.
    /// The share is its own field because it is not a directory — it is what `TREE_CONNECT`
    /// takes — and the path is what lives inside it.
    Smb {
        user: Option<String>,
        host: String,
        port: Option<u16>,
        share: String,
    },
    /// `oci://host[:port]/repository[:tag]`: a container registry repository as an image
    /// layout; the path is the repository.
    Oci {
        host: String,
        port: Option<u16>,
        tag: Option<String>,
    },
    /// `tar://ARCHIVE[!/SUBPATH]`: a tar archive as a tree. The path is the archive.
    Tar {
        sub: String,
    },
    /// `dav://host[:port]/path` and `davs://...`: a WebDAV collection. `secure` is the
    /// `davs://` form, kept on the endpoint rather than derived from the port, because a
    /// server on a nonstandard port is still the one the operator wrote.
    Dav {
        host: String,
        port: Option<u16>,
        secure: bool,
    },
    /// `https://host[:port]/path` and `http://...`: an ordinary web server, read-only. Its
    /// listing comes from a convention rather than the protocol -- see `https::index`.
    Https {
        host: String,
        port: Option<u16>,
        secure: bool,
    },
}

/// A write to stdout failed because the reader went away (`rcp scan X | head`): end the run
/// quietly with 141, the status a SIGPIPE death gives, which is what a pipeline expects. Any
/// other error returns, for the caller to report.
///
/// SIGPIPE stays ignored for the whole run, so this is the only place a closed pipe ends it. A
/// pipe to a child -- the `ssh` under an sftp:// or ssh:// endpoint -- that closes mid-write is
/// an ordinary `BrokenPipe` error, reported like any other failed write.
pub fn exit_if_reader_left(e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(141);
    }
}

impl Remote {
    /// The scheme a URL for this endpoint is written with.
    pub fn scheme(&self) -> &'static str {
        match self {
            Remote::Local => "local",
            Remote::Nfs { .. } => "nfs://",
            Remote::S3 { .. } => "s3://",
            Remote::Hdfs { .. } => "hdfs://",
            Remote::Ssh { .. } => "ssh://",
            Remote::Rcp { secure: true, .. } => "rcps://",
            Remote::Rcp { .. } => "rcp://",
            Remote::Sftp { .. } => "sftp://",
            Remote::Smb { .. } => "smb://",
            Remote::Oci { .. } => "oci://",
            Remote::Tar { .. } => "tar://",
            Remote::Dav { secure: true, .. } => "davs://",
            Remote::Dav { .. } => "dav://",
            Remote::Https { secure: true, .. } => "https://",
            Remote::Https { .. } => "http://",
        }
    }

    /// The Cargo feature that builds this endpoint's adapter in. Every scheme parses in
    /// every build; only opening one needs its feature.
    pub fn feature(&self) -> &'static str {
        match self {
            Remote::Local => "",
            Remote::Nfs { .. } => "nfs",
            Remote::S3 { .. } => "s3",
            Remote::Hdfs { .. } => "hdfs",
            Remote::Ssh { .. } | Remote::Rcp { .. } => "remote",
            Remote::Sftp { .. } => "sftp",
            Remote::Smb { .. } => "smb",
            Remote::Oci { .. } => "oci",
            Remote::Tar { .. } => "tar",
            Remote::Dav { .. } => "dav",
            Remote::Https { .. } => "https",
        }
    }
}

/// A source or destination as the CLI accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The local path; for NFS the path inside the export and for S3 the prefix (`/` at the
    /// export or bucket root).
    pub path: PathBuf,
    pub remote: Remote,
}

#[derive(Debug)]
pub struct EndpointError(pub String);

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EndpointError {}

/// `host[:port]` of a URL authority, keeping the brackets on an IPv6 literal so the host
/// can be printed back into a URL and read by the transport's own parser.
///
/// One implementation, not one per scheme. A per-scheme copy that splits on the LAST colon
/// with a guard that the host has no colon of its own never matches `[::1]:8443`, so the
/// whole authority becomes the host and the brackets are then trimmed off it:
/// `dav://[::1]:8443/a` displays as `dav://::1]:8443/a` and the WebDAV client, which reads
/// bracketed literals correctly, refuses its own endpoint. Only the chain from
/// `Endpoint::parse` through `display()` to `split_url` shows it; unit arms that call
/// `split_url` directly never see it.
/// A host as it goes back into a URL: an IPv6 address gets its brackets, so the display
/// of an `ssh://` endpoint parses again as the same endpoint.
/// `host:port` as `TcpStream::connect` wants it, which for IPv6 means the brackets go back
/// ON: `::1:9000` is ambiguous and parses as neither, where `[::1]:9000` is exact. The
/// endpoint strips them (ssh takes a bare `::1` with `-p`), so a socket caller has to put
/// them back rather than assume the stored host is dialable as written.
pub fn host_port_for_dial(host: &str, port: u16) -> String {
    format!("{}:{port}", bracketed(host))
}

fn bracketed(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// The reverse, for the one consumer that must NOT have the brackets: the resolver.
///
/// Every parser reads `[::1]:8443` correctly, and round-tripping `parse` -> `display()` ->
/// the transport's own parser proves it -- yet without this strip `dav://[::1]:8443/a`
/// cannot open, because round-tripping a parser is not opening a socket. The host reaches
/// `(host, port).to_socket_addrs()` still bracketed, and `[::1]` is not an address -- it
/// is a name, so it goes to the resolver and fails `Name or service not known`.
///
/// The brackets are RIGHT everywhere else: `Host: [::1]:8443` and `CONNECT [::1]:443`
/// both need them, and RFC 3986 requires them in a URL. So this is a strip at the point
/// of use rather than a different host field.
/// The zone is the second half of the story, and stripping brackets alone misses it. A
/// link-local address carries one -- `fe80::1%eth0` -- and RFC 6874 says a URI writes it
/// `%25eth0`, because `%` must be escaped there. Strip only the brackets and the resolver
/// gets `fe80::1%25eth0`, which is not an address either, so it goes to the name lookup
/// exactly as `[::1]` did. Measured, and it needs no IPv6 stack to measure:
///
/// ```text
/// fe80::1%25lo -> ERR failed to lookup address information
/// fe80::1%lo   -> OK  [fe80::1%1]:80
/// ```
pub(crate) fn unbracketed(host: &str) -> std::borrow::Cow<'_, str> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.find("%25") {
        Some(i) => std::borrow::Cow::Owned(format!("{}%{}", &bare[..i], &bare[i + 3..])),
        None => std::borrow::Cow::Borrowed(bare),
    }
}

/// The address without its zone, for the one consumer that cannot carry one: a TLS
/// `ServerName`. A zone is a LOCAL routing detail -- which interface to leave by -- and is
/// no part of the peer's identity, so no certificate can name it and rustls refuses the
/// whole string rather than ignoring the tail.
///
/// Only the TLS builds have such a consumer, so a build without the feature would report
/// this dead if its own test did not keep it alive; the `allow` says that deliberately
/// rather than letting a real dead function hide behind a cfg.
#[cfg_attr(not(feature = "rustls"), allow(dead_code))]
pub(crate) fn unzoned(host: &str) -> &str {
    host.split_once('%').map_or(host, |(a, _)| a)
}

/// `scheme://user:password@host/path` with the password replaced by `***`, for the places
/// that must print an endpoint they have not parsed yet.
///
/// The parse-time refusals are the real control -- an endpoint carrying a password is
/// refused, by `no_password_in` for ssh and sftp and by name for dav, http and s3. But some
/// sites print the endpoint BEFORE anything parses it, and a refusal downstream does not
/// unwrite a log line upstream. `main`'s `-loglevel DEBUG` echo of the positionals is the
/// one that matters: it fires before dispatch, so with `DEBUG` set it wrote the very
/// credential the refusal exists to keep out of the log.
///
/// The user is KEPT. It is not the secret, and a log line that cannot say which account a
/// run used is worth less. Only what follows the first colon goes.
pub fn redact_userinfo(text: &str) -> std::borrow::Cow<'_, str> {
    let Some(after) = text.find("://").map(|i| i + 3) else {
        return std::borrow::Cow::Borrowed(text);
    };
    // the authority ends at the first `/` after the scheme, and the `@` must be inside it:
    // `s3://bucket/a@b` has no userinfo, and neither does a local path that happens to
    // contain the sequence
    let end = text[after..].find('/').map_or(text.len(), |i| after + i);
    let Some(at) = text[after..end].rfind('@').map(|i| after + i) else {
        return std::borrow::Cow::Borrowed(text);
    };
    let Some(colon) = text[after..at].find(':').map(|i| after + i) else {
        return std::borrow::Cow::Borrowed(text);
    };
    std::borrow::Cow::Owned(format!("{}***{}", &text[..=colon], &text[at..]))
}

/// Refuse `user:password@host` in an ssh or sftp authority, and do it WITHOUT repeating the
/// endpoint back. Both transports run `ssh` as a child process, which takes a key or an
/// agent and has no password argument, so a password here can never be used -- but it can
/// very much be RECORDED: every other refusal in those two arms interpolates `{text:?}`,
/// and the endpoint itself reaches `jobs.log`, `index.tsv` (both 0644 under the catalog),
/// the `-json` `done.source`, the `-html` title and the child's `ps` line. So the refusal
/// has to come first and has to be silent about the value. `rest` is everything after the
/// scheme; the authority is read without the path split, because that split's own refusal
/// is one of the messages that would quote it.
fn no_password_in(rest: &str, scheme: &str) -> Result<(), EndpointError> {
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some((user, _)) = authority.rsplit_once('@') {
        if user.contains(':') {
            return Err(EndpointError(format!(
                "{scheme} endpoint carries a password in the authority. rcp runs ssh, which takes a key or an agent and has no password argument, so the password could only be recorded -- in the job log and the catalog index, both world-readable -- never used. Write {scheme}://user@host/path and let ssh find the key"
            )));
        }
    }
    Ok(())
}

fn host_port(authority: &str) -> Result<(&str, Option<u16>), String> {
    let port_of = |p: &str| -> Result<u16, String> {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("port {p:?} is not a number"));
        }
        p.parse::<u16>()
            .map_err(|_| format!("port {p:?} is not a number"))
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err("unterminated IPv6 literal".into());
        };
        if inner.is_empty() || inner.contains('[') {
            return Err("malformed IPv6 literal".into());
        }
        let host = &authority[..inner.len() + 2];
        return match after.strip_prefix(':') {
            Some(p) => Ok((host, Some(port_of(p)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err("trailing text after the IPv6 literal".into()),
        };
    }
    if authority.contains(['[', ']']) {
        return Err("a bracket in the host that is not an IPv6 literal".into());
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h, Some(port_of(p)?))),
        Some(_) => Err("an IPv6 address must be written in brackets".into()),
        None => Ok((authority, None)),
    }
}

impl Endpoint {
    pub fn local(path: impl Into<PathBuf>) -> Endpoint {
        Endpoint {
            path: path.into(),
            remote: Remote::Local,
        }
    }

    /// `file:///path` and `/path` are the same local endpoint. `host:/export[/sub]`,
    /// `host:/export:/sub` and `nfs://host/export[/sub]` are NFS endpoints reached with the
    /// built-in NFSv3 client; the export is the whole path the server exports, so a
    /// subdirectory of an export is written `host:/export:/sub` when the split is not obvious.
    /// `host` may be a comma-separated list of the server's addresses (`ip1,ip2:/export`),
    /// which connections rotate across.
    /// `s3://bucket[/prefix]` is a bucket reached with the built-in S3 client.
    /// Parsing performs no filesystem or network access.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] for unsupported endpoint syntax, malformed authorities
    /// or ports, and forbidden URL credentials. Transport availability is checked later.
    ///
    /// # Examples
    ///
    /// ```
    /// use rcp::{Endpoint, Remote};
    /// use std::path::Path;
    /// let endpoint = Endpoint::parse("file:///data/source")?;
    /// assert_eq!(endpoint.remote, Remote::Local);
    /// assert_eq!(endpoint.path, Path::new("/data/source"));
    /// assert!(Endpoint::parse("file://relative").is_err());
    /// # Ok::<(), rcp::EndpointError>(())
    /// ```
    pub fn parse(text: &str) -> Result<Endpoint, EndpointError> {
        #[cfg(windows)]
        if Path::new(text).is_absolute() {
            return Ok(Endpoint::local(text));
        }
        if let Some(rest) = text.strip_prefix("file://") {
            if !rest.starts_with('/') {
                return Err(EndpointError(format!(
                    "endpoint {text:?} is not an absolute file:// path; use file:///absolute/path"
                )));
            }
            #[cfg(windows)]
            let rest = if rest.as_bytes().get(2) == Some(&b':') {
                &rest[1..]
            } else {
                rest
            };
            return Ok(Endpoint::local(rest));
        }
        if text.starts_with('/') {
            return Ok(Endpoint::local(text));
        }
        if let Some(rest) = text.strip_prefix("ssh://") {
            // FIRST, before the path split below, because that split's own refusal quotes
            // `{text:?}` -- and so does every other refusal in this arm. A password in the
            // authority would be printed by whichever one fired, and from there into
            // `jobs.log`, `index.tsv`, the `-json` `done.source` and the `-html` title,
            // files this tool writes at 0644 and keeps. Same placement reasoning as
            // `s3::config::parse_endpoint`. ssh has no password argument anyway: the
            // transport runs `ssh` as a child, which reads a key or an agent, so a
            // password here could only be recorded, never used.
            no_password_in(rest, "ssh")?;
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => {
                    return Err(EndpointError(format!(
                    "ssh endpoint {text:?} needs an absolute path: ssh://[user@]host[:port]/path"
                )))
                }
            };
            let (user, hostport) = match authority.rsplit_once('@') {
                Some((u, h)) => (Some(u.to_string()), h),
                None => (None, authority),
            };
            // the same bracket-aware reader as `oci://` and `dav://`, and the brackets
            // come OFF here: the host is handed to ssh as an argument, and `::1` is what
            // ssh takes, with the port as `-p`. `[::1]:2222` was stored whole as the host
            // with no port, so the transport dialed a name that resolves nowhere.
            let (host, port) = host_port(hostport)
                .map_err(|why| EndpointError(format!("ssh endpoint {text:?}: {why}")))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() || user.as_deref() == Some("") {
                return Err(EndpointError(format!(
                    "ssh endpoint {text:?} names no host: ssh://[user@]host[:port]/path"
                )));
            }
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "ssh endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                path.to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Ssh {
                    user,
                    host: host.to_string(),
                    port,
                },
            });
        }
        // `rcps` first: `rcp` is its prefix, so testing the shorter one first would read
        // every `rcps://` endpoint as an `rcp://` one whose host began with `s`
        if let Some((rest, secure)) = text
            .strip_prefix("rcps://")
            .map(|r| (r, true))
            .or_else(|| text.strip_prefix("rcp://").map(|r| (r, false)))
        {
            let scheme = if secure { "rcps" } else { "rcp" };
            // No user, ever. `ssh://` carries one because ssh authenticates it; an rcp
            // endpoint reaches a listener whose peer authentication is TLS or nothing, so a
            // user here would be a name the protocol carries and no one checks -- an
            // identity in appearance only, which is worse than none.
            no_password_in(rest, scheme)?;
            if rest.contains('@') {
                return Err(EndpointError(format!(
                    "{scheme} endpoint {text:?} names a user: an rcp endpoint has no password or account of its own. The peer identity is the client certificate (-tls.cert), or a tunnel that authenticates for it"
                )));
            }
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => {
                    return Err(EndpointError(format!(
                    "{scheme} endpoint {text:?} needs an absolute path: {scheme}://host:port/path"
                )))
                }
            };
            let (host, port) = host_port(authority)
                .map_err(|why| EndpointError(format!("{scheme} endpoint {text:?}: {why}")))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() {
                return Err(EndpointError(format!(
                    "{scheme} endpoint {text:?} names no host: {scheme}://host:port/path"
                )));
            }
            // A port is REQUIRED, unlike ssh's 22. There is no registered port for this and
            // inventing a default would mean a typo silently dialing some other service.
            let Some(port) = port else {
                return Err(EndpointError(format!("{scheme} endpoint {text:?} names no port: {scheme}://host:port/path, the port `rcp serve -listen` was given")));
            };
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "{scheme} endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                path.to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Rcp {
                    host: host.to_string(),
                    port,
                    secure,
                },
            });
        }
        if let Some(rest) = text.strip_prefix("sftp://") {
            // see the ssh arm: first, because every refusal below quotes `{text:?}`
            no_password_in(rest, "sftp")?;
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => {
                    return Err(EndpointError(format!(
                    "sftp endpoint {text:?} needs an absolute path: sftp://[user@]host[:port]/path"
                )))
                }
            };
            let (user, hostport) = match authority.rsplit_once('@') {
                Some((u, h)) => (Some(u.to_string()), h),
                None => (None, authority),
            };
            // the same bracket-aware reader as `oci://` and `dav://`, and the brackets
            // come OFF here: the host is handed to ssh as an argument, and `::1` is what
            // ssh takes, with the port as `-p`. `[::1]:2222` was stored whole as the host
            // with no port, so the transport dialed a name that resolves nowhere.
            let (host, port) = host_port(hostport)
                .map_err(|why| EndpointError(format!("sftp endpoint {text:?}: {why}")))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() || user.as_deref() == Some("") {
                return Err(EndpointError(format!(
                    "sftp endpoint {text:?} names no host: sftp://[user@]host[:port]/path"
                )));
            }
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "sftp endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                path.to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Sftp {
                    user,
                    host: host.to_string(),
                    port,
                },
            });
        }
        if let Some(rest) = text.strip_prefix("smb://") {
            let authority_end = rest.find('/').unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            // The dav rule, and the dav reason: a refusal that quotes the URL back writes
            // the password into the job log, on the one path that exists to keep it out.
            // So this message does not repeat `{text}`.
            if authority
                .rsplit_once('@')
                .is_some_and(|(u, _)| u.contains(':'))
            {
                return Err(EndpointError(
                    "an smb endpoint carries a password; it does not go in the URL (and is not repeated here). Use -smb.user [DOMAIN\\]USER:PASSWORD or RCP_SMB_USER with RCP_SMB_PASSWORD".to_string(),
                ));
            }
            let (user, hostport) = match authority.rsplit_once('@') {
                Some((u, h)) => (Some(u.to_string()), h),
                None => (None, authority),
            };
            let (host, port) = host_port(hostport)
                .map_err(|why| EndpointError(format!("smb endpoint {text:?}: {why}")))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if host.is_empty() || user.as_deref() == Some("") {
                return Err(EndpointError(format!(
                    "smb endpoint {text:?} names no host: smb://[user@]host[:port]/share[/path]"
                )));
            }
            // The first path component is the SHARE, which TREE_CONNECT takes; everything
            // after it is a path inside that share. A URL with no share names nothing that
            // can be connected, so it is refused rather than defaulting to one.
            let after = &rest[authority_end..];
            let mut parts = after.trim_start_matches('/').splitn(2, '/');
            let share = parts.next().unwrap_or("");
            if share.is_empty() {
                return Err(EndpointError(format!(
                    "smb endpoint {text:?} names no share: smb://[user@]host[:port]/share[/path]"
                )));
            }
            // A backslash would make the TREE_CONNECT path `\\host\a\b`, which names a DFS
            // referral rather than the share the operator wrote. `C$` and `ADMIN$` are
            // ordinary share names and are deliberately NOT refused.
            if share.contains('\\') {
                return Err(EndpointError(format!(
                    "smb endpoint {text:?}: {share:?} is not a share name"
                )));
            }
            let path = parts.next().unwrap_or("");
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "smb endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = format!("/{}", path.trim_end_matches('/'));
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Smb {
                    user,
                    host: host.to_string(),
                    port,
                    share: share.to_string(),
                },
            });
        }
        if let Some(rest) = text.strip_prefix("tar://") {
            // `!/` separates the archive from a path inside it, the way jar and zip URLs
            // do, because a tar member's name may contain anything a path may
            let (archive, sub) = match rest.split_once("!/") {
                Some((a, s)) => (a, s),
                None => (rest, ""),
            };
            if archive.is_empty() {
                return Err(EndpointError(format!(
                    "tar endpoint {text:?} names no archive: tar://ARCHIVE[!/SUBPATH]"
                )));
            }
            if archive.contains("://") {
                return Err(EndpointError(format!(
                    "tar endpoint {text:?}: the archive is a local path, not another endpoint"
                )));
            }
            return Ok(Endpoint {
                path: PathBuf::from(archive),
                remote: Remote::Tar {
                    sub: sub.trim_end_matches('/').to_string(),
                },
            });
        }
        if let Some(rest) = text.strip_prefix("oci://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i + 1..]),
                None => {
                    return Err(EndpointError(format!(
                    "oci endpoint {text:?} names no repository: oci://host[:port]/repository[:tag]"
                )))
                }
            };
            let (host, port) = host_port(authority)
                .map_err(|why| EndpointError(format!("oci endpoint {text:?}: {why}")))?;
            if host.is_empty() || host.contains('@') {
                return Err(EndpointError(format!(
                    "oci endpoint {text:?} names no host: oci://host[:port]/repository[:tag]"
                )));
            }
            if path.contains('@') {
                return Err(EndpointError(format!("oci endpoint {text:?}: name a tag, not a digest (rcp copies every tag of a repository, or one tag)")));
            }
            let (repo, tag) = match path.rsplit_once(':') {
                Some((r, t)) => (r, Some(t)),
                None => (path.trim_end_matches('/'), None),
            };
            if repo.is_empty()
                || repo.split('/').any(|c| {
                    c.is_empty()
                        || !c.bytes().all(|b| {
                            b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || b == b'.'
                                || b == b'_'
                                || b == b'-'
                        })
                })
            {
                return Err(EndpointError(format!("oci endpoint {text:?}: a repository is lowercase path components of letters, digits, '.', '_' and '-'")));
            }
            if let Some(t) = tag {
                let ok = !t.is_empty()
                    && t.len() <= 128
                    && t.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
                    && !t.starts_with('.')
                    && !t.starts_with('-');
                if !ok {
                    return Err(EndpointError(format!(
                        "oci endpoint {text:?}: tag {t:?} is not a valid tag"
                    )));
                }
            }
            return Ok(Endpoint {
                path: PathBuf::from(format!("/{repo}")),
                remote: Remote::Oci {
                    host: host.to_string(),
                    port,
                    tag: tag.map(str::to_string),
                },
            });
        }
        for (prefix, secure) in [("davs://", true), ("dav://", false)] {
            let Some(rest) = text.strip_prefix(prefix) else {
                continue;
            };
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            // Credentials belong in `-dav.user` or the environment, not in a URL that ends
            // up in the job log, in a report and in `ps`. Refused by name rather than
            // quietly stripped, which would leave an operator thinking they were sent.
            if authority.contains('@') {
                // and the refusal must not QUOTE the URL back, which every other message
                // in this arm does. The reason for the rule is that the endpoint reaches
                // the job log, a report and `ps` -- so a refusal that prints
                // `dav://user:hunter2@host/path` writes the password into the job log
                // itself, on the one path that exists to keep it out. Measured:
                // `rcp copy -noId /tmp 'dav://user:hunter2@host/path'` printed `hunter2`.
                return Err(EndpointError("a WebDAV endpoint carries a user and password; they do not go in the URL (and are not repeated here). Use -dav.user USER:PASSWORD or RCP_DAV_USER".to_string()));
            }
            let (host, port) = host_port(authority)
                .map_err(|why| EndpointError(format!("WebDAV endpoint {text:?}: {why}")))?;
            if host.is_empty() {
                return Err(EndpointError(format!(
                    "WebDAV endpoint {text:?} names no host: {prefix}host[:port]/path"
                )));
            }
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "WebDAV endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                "/".to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Dav {
                    host: host.to_string(),
                    port,
                    secure,
                },
            });
        }
        for (prefix, secure) in [("https://", true), ("http://", false)] {
            let Some(rest) = text.strip_prefix(prefix) else {
                continue;
            };
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            // the same refusal as WebDAV's, for the same reason: a credential in a URL
            // ends up in the job log, in a report and in `ps`
            if authority.contains('@') {
                // same refusal, same reason, and the same rule about not repeating it
                return Err(EndpointError("an http endpoint carries a user and password; they do not go in the URL (and are not repeated here). Use -http.user USER:PASSWORD or RCP_HTTP_USER".to_string()));
            }
            let (host, port) = host_port(authority)
                .map_err(|why| EndpointError(format!("http endpoint {text:?}: {why}")))?;
            if host.is_empty() {
                return Err(EndpointError(format!(
                    "http endpoint {text:?} names no host: {prefix}host[:port]/path"
                )));
            }
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "http endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                "/".to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Https {
                    host: host.to_string(),
                    port,
                    secure,
                },
            });
        }
        if let Some(rest) = text.strip_prefix("hdfs://") {
            let (namenode, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            if namenode.contains('/') || namenode.contains('@') {
                return Err(EndpointError(format!(
                    "HDFS endpoint {text:?}: use hdfs://namenode:port/path or hdfs:///path"
                )));
            }
            // the same reader as every other authority, so `hdfs://::1/x` is refused here
            // rather than accepted and then refused by the WebHDFS client, and
            // `hdfs://[::1]:9870/x` is read as the literal it is
            if !namenode.is_empty() {
                host_port(namenode)
                    .map_err(|why| EndpointError(format!("HDFS endpoint {text:?}: {why}")))?;
            }
            let path = if path.is_empty() { "/" } else { path };
            if path.split('/').any(|c| c == "." || c == "..") {
                return Err(EndpointError(format!(
                    "HDFS endpoint {text:?}: the path is not a plain path"
                )));
            }
            let clean = if path.len() > 1 {
                path.trim_end_matches('/').to_string()
            } else {
                path.to_string()
            };
            return Ok(Endpoint {
                path: PathBuf::from(clean),
                remote: Remote::Hdfs {
                    namenode: namenode.to_string(),
                },
            });
        }
        if let Some(rest) = text.strip_prefix("s3://") {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if bucket.is_empty() {
                return Err(EndpointError(format!(
                    "S3 endpoint {text:?} names no bucket; use s3://bucket/prefix"
                )));
            }
            if bucket.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.')) {
                return Err(EndpointError(format!(
                    "S3 endpoint {text:?}: bucket names use letters, digits, '-' and '.'"
                )));
            }
            let prefix = prefix.trim_matches('/');
            if prefix.split('/').any(|c| c == "." || c == "..") || prefix.contains("//") {
                return Err(EndpointError(format!(
                    "S3 endpoint {text:?}: the prefix is not a plain path"
                )));
            }
            return Ok(Endpoint {
                path: PathBuf::from(format!("/{prefix}")),
                remote: Remote::S3 {
                    bucket: bucket.to_string(),
                },
            });
        }
        if let Some(rest) = text.strip_prefix("nfs://") {
            let (host, path) = rest.split_once('/').ok_or_else(|| {
                EndpointError(format!("NFS endpoint {text:?} needs nfs://host/export"))
            })?;
            return Self::nfs(text, host, &format!("/{path}"));
        }
        if let Some((host, rest)) = text.split_once(":/") {
            if !host.is_empty() && !host.contains('/') {
                return Self::nfs(text, host, &format!("/{rest}"));
            }
        }
        Err(EndpointError(format!("endpoint {text:?} is none of file:///absolute/path, an absolute path, host:/export, nfs://, s3://, hdfs://, ssh://, rcp://, rcps://, sftp://, smb://, oci://, dav://, http:// or tar://")))
    }

    fn nfs(text: &str, host: &str, path: &str) -> Result<Endpoint, EndpointError> {
        if host.is_empty() || host.split(',').any(|h| h.trim().is_empty()) {
            return Err(EndpointError(format!(
                "NFS endpoint {text:?} has no host (or an empty one in its address list)"
            )));
        }
        // The two NFS spellings disagreed on IPv6 and only one of them worked. `::1:/export`
        // stores `::1` and dials it; `nfs://[::1]/export` stored `[::1]`, which the resolver
        // reads as a name. NFS has no URL to print the host back into -- its display form is
        // `host:/export`, where brackets mean nothing -- so the address is what is kept, and
        // the two spellings become the same endpoint. Done per element: an address list may
        // be `nfs://[::1],[::2]/export`.
        let host: String = host
            .split(',')
            .map(|h| unbracketed(h.trim()))
            .collect::<Vec<_>>()
            .join(",");
        let host = host.as_str();
        // `host:/export:/sub` separates the export from the path below it explicitly
        let (export, sub) = match path.split_once(":/") {
            Some((e, s)) => (e.to_string(), format!("/{s}")),
            None => (path.to_string(), "/".to_string()),
        };
        let export = if export.len() > 1 {
            export.trim_end_matches('/').to_string()
        } else {
            export
        };
        Ok(Endpoint {
            path: PathBuf::from(sub),
            remote: Remote::Nfs {
                host: host.to_string(),
                export,
            },
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn is_local(&self) -> bool {
        self.remote == Remote::Local
    }

    pub fn is_nfs(&self) -> bool {
        matches!(self.remote, Remote::Nfs { .. })
    }

    pub fn is_s3(&self) -> bool {
        matches!(self.remote, Remote::S3 { .. })
    }

    pub fn is_hdfs(&self) -> bool {
        matches!(self.remote, Remote::Hdfs { .. })
    }

    pub fn is_ssh(&self) -> bool {
        matches!(self.remote, Remote::Ssh { .. })
    }

    /// Whether this endpoint is an `rcp serve` of either kind, which is what `-via` needs:
    /// a relay is a serve that opens endpoints on this run's behalf, and reaching it by
    /// socket rather than by ssh changes nothing about what it then does.
    pub fn is_serve(&self) -> bool {
        matches!(self.remote, Remote::Ssh { .. } | Remote::Rcp { .. })
    }

    pub fn is_sftp(&self) -> bool {
        matches!(self.remote, Remote::Sftp { .. })
    }

    pub fn is_smb(&self) -> bool {
        matches!(self.remote, Remote::Smb { .. })
    }

    pub fn is_oci(&self) -> bool {
        matches!(self.remote, Remote::Oci { .. })
    }

    pub fn is_dav(&self) -> bool {
        matches!(self.remote, Remote::Dav { .. })
    }

    pub fn is_https(&self) -> bool {
        matches!(self.remote, Remote::Https { .. })
    }

    /// The same endpoint at `name` below this one.
    pub fn join(&self, name: &str) -> Endpoint {
        #[cfg(windows)]
        if !matches!(self.remote, Remote::Local) {
            return Endpoint {
                path: PathBuf::from(format!(
                    "{}/{}",
                    self.path.to_string_lossy().trim_end_matches('/'),
                    name
                )),
                remote: self.remote.clone(),
            };
        }
        Endpoint {
            path: self.path.join(name),
            remote: self.remote.clone(),
        }
    }

    /// The same endpoint at the parent of this one (a local `/` stays `/`).
    pub fn parent(&self) -> Endpoint {
        #[cfg(windows)]
        if !matches!(self.remote, Remote::Local) {
            let path = self.path.to_string_lossy();
            let parent = path
                .rsplit_once('/')
                .map(|(p, _)| if p.is_empty() { "/" } else { p })
                .unwrap_or(&path);
            return Endpoint {
                path: PathBuf::from(parent),
                remote: self.remote.clone(),
            };
        }
        Endpoint {
            path: self
                .path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.path.clone()),
            remote: self.remote.clone(),
        }
    }

    /// How the endpoint prints in reports and the job log.
    pub fn display(&self) -> String {
        match &self.remote {
            Remote::Nfs { host, export } => {
                if self.path == Path::new("/") {
                    format!("{host}:{export}")
                } else {
                    format!("{host}:{export}:{}", self.path.display())
                }
            }
            Remote::S3 { bucket } => {
                let prefix = self.path.to_string_lossy();
                let prefix = prefix.trim_start_matches('/');
                if prefix.is_empty() {
                    format!("s3://{bucket}")
                } else {
                    format!("s3://{bucket}/{prefix}")
                }
            }
            Remote::Hdfs { namenode } => format!("hdfs://{namenode}{}", self.path.display()),
            Remote::Ssh { user, host, port } => format!(
                "ssh://{}{}{}{}",
                user.as_ref().map(|u| format!("{u}@")).unwrap_or_default(),
                bracketed(host),
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                self.path.display()
            ),
            Remote::Rcp { host, port, secure } => format!(
                "{}://{}:{port}{}",
                if *secure { "rcps" } else { "rcp" },
                bracketed(host),
                self.path.display()
            ),
            Remote::Sftp { user, host, port } => format!(
                "sftp://{}{}{}{}",
                user.as_ref().map(|u| format!("{u}@")).unwrap_or_default(),
                bracketed(host),
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                self.path.display()
            ),
            Remote::Smb {
                user,
                host,
                port,
                share,
            } => {
                let inside = self
                    .path
                    .to_string_lossy()
                    .trim_end_matches('/')
                    .to_string();
                format!(
                    "smb://{}{}{}/{share}{inside}",
                    user.as_ref().map(|u| format!("{u}@")).unwrap_or_default(),
                    bracketed(host),
                    port.map(|p| format!(":{p}")).unwrap_or_default()
                )
            }
            Remote::Oci { host, port, tag } => format!(
                "oci://{host}{}{}{}",
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                self.path.display(),
                tag.as_ref().map(|t| format!(":{t}")).unwrap_or_default()
            ),
            Remote::Dav { host, port, secure } => format!(
                "{}://{host}{}{}",
                if *secure { "davs" } else { "dav" },
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                self.path.display()
            ),
            Remote::Https { host, port, secure } => format!(
                "{}://{host}{}{}",
                if *secure { "https" } else { "http" },
                port.map(|p| format!(":{p}")).unwrap_or_default(),
                self.path.display()
            ),
            Remote::Tar { sub } => {
                if sub.is_empty() {
                    format!("tar://{}", self.path.display())
                } else {
                    format!("tar://{}!/{sub}", self.path.display())
                }
            }
            Remote::Local => self.path.display().to_string(),
        }
    }
}

/// `check_distinct` for endpoints of any kind: local ones by canonical path, remote ones by
/// server (or bucket) and path; endpoints of different kinds never collide here (the same
/// export mounted locally is not detectable without asking the server).
pub fn check_distinct_endpoints(source: &Endpoint, destination: &Endpoint) -> Result<(), String> {
    if source.remote == Remote::Local && destination.remote == Remote::Local {
        return check_distinct(&source.path, &destination.path);
    }
    if source.remote != destination.remote {
        return Ok(());
    }
    let (s, d) = (&source.path, &destination.path);
    let what = if source.is_s3() {
        "bucket path"
    } else if source.is_hdfs() {
        "HDFS path"
    } else if source.is_ssh() {
        "remote path"
    } else if source.is_oci() {
        "repository"
    } else {
        "export path"
    };
    if s == d {
        return Err(format!(
            "source and destination are the same {what}: {}",
            source.display()
        ));
    }
    if d.starts_with(s) {
        return Err(format!(
            "destination {} is inside source {}",
            destination.display(),
            source.display()
        ));
    }
    if s.starts_with(d) {
        return Err(format!(
            "source {} is inside destination {}",
            source.display(),
            destination.display()
        ));
    }
    Ok(())
}

/// Canonicalize `path`, following symlinks even when the target does not exist yet, and
/// appending whatever has not been created. A destination that has not been created yet
/// can still sit inside the source, and a dangling link is not a path that stays where
/// it is spelled.
fn resolve_uncreated(path: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(path) {
        return p;
    }
    #[cfg(unix)]
    {
        walk_links(path)
    }
    #[cfg(not(unix))]
    {
        let mut missing = Vec::new();
        let mut cur = path.to_path_buf();
        loop {
            let name = cur.file_name().map(|n| n.to_os_string());
            if !cur.pop() {
                return path.to_path_buf();
            }
            if let Some(n) = name {
                missing.push(n);
            }
            if let Ok(real) = std::fs::canonicalize(&cur) {
                let mut full = real;
                for n in missing.iter().rev() {
                    full.push(n);
                }
                return full;
            }
            if cur.as_os_str().is_empty() {
                return path.to_path_buf();
            }
        }
    }
}

/// The same walk the command-line rail uses: every existing symlink is followed, including
/// one whose target does not exist, and the missing suffix is appended as spelled.
#[cfg(unix)]
fn walk_links(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut left: Vec<std::ffi::OsString> = abs
        .components()
        .rev()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name.to_os_string()),
            std::path::Component::ParentDir => Some(std::ffi::OsString::from("..")),
            _ => None,
        })
        .collect();
    let mut out = PathBuf::from("/");
    let mut hops = 0;
    while let Some(name) = left.pop() {
        if name == ".." {
            out.pop();
            continue;
        }
        out.push(&name);
        match out.canonicalize() {
            Ok(real) => out = real,
            Err(_) => {
                if let Ok(target) = std::fs::read_link(&out) {
                    hops += 1;
                    if hops > 40 {
                        return out;
                    }
                    out.pop();
                    let target = if target.is_absolute() {
                        out = PathBuf::from("/");
                        target
                    } else {
                        target
                    };
                    for c in target.components().rev() {
                        match c {
                            std::path::Component::Normal(n) => left.push(n.to_os_string()),
                            std::path::Component::ParentDir => {
                                left.push(std::ffi::OsString::from(".."))
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    out
}

/// Refuses the two layouts a copy cannot survive: identical endpoints, and one nested inside
/// the other (the walk would feed on its own output).
pub fn check_distinct(source: &Path, destination: &Path) -> Result<(), String> {
    let src =
        std::fs::canonicalize(source).map_err(|e| format!("source {}: {e}", source.display()))?;
    let dst = resolve_uncreated(destination);
    if src == dst {
        return Err(format!(
            "source and destination are the same directory: {}",
            src.display()
        ));
    }
    if dst.starts_with(&src) {
        return Err(format!(
            "destination {} is inside source {}",
            dst.display(),
            src.display()
        ));
    }
    if src.starts_with(&dst) {
        return Err(format!(
            "source {} is inside destination {}",
            src.display(),
            dst.display()
        ));
    }
    Ok(())
}

/// Whether standard error is a terminal (progress lines default to on when it is).
pub fn stderr_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Human-readable byte counts for reports: `1.5 GiB`, `312 KiB`, `40 B`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Endpoint::parse` reads URLs too, and disagreed with the transports' reader on a
    /// VALID literal: it displayed `dav://[::1]:8443/a` as `dav://::1]:8443/a`, which the
    /// WebDAV client then refused. The chain that matters is parse, display, and the
    /// transport's own reader agreeing.
    #[test]
    fn an_ipv6_endpoint_survives_parse_and_display_into_the_transport_parser() {
        for (text, host, port) in [
            ("dav://[::1]:8443/a", "[::1]", Some(8443)),
            ("davs://[fe80::1%25eth0]/a", "[fe80::1%25eth0]", None),
            ("dav://host:8080/a", "host", Some(8080)),
            ("dav://host/a", "host", None),
        ] {
            let ep = Endpoint::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(ep.display(), text);
            let Remote::Dav {
                host: h, port: p, ..
            } = &ep.remote
            else {
                panic!("{text}: not dav")
            };
            assert_eq!((h.as_str(), *p), (host, port), "{text}");
            #[cfg(feature = "dav")]
            dav::split_url(&ep.display()).unwrap_or_else(|e| {
                panic!(
                    "the WebDAV client refused its own endpoint {}: {e}",
                    ep.display()
                )
            });
        }
        let ep = Endpoint::parse("oci://[::1]:5000/app").unwrap();
        assert_eq!(ep.display(), "oci://[::1]:5000/app");
        // ssh and sftp: the host is what ssh takes as an argument (no brackets), the
        // port is separate, and the display brackets the host again
        for (text, host, port) in [
            ("ssh://[::1]:2222/x", "::1", Some(2222)),
            ("ssh://alice@[fe80::1%25eth0]/x", "fe80::1%25eth0", None),
            ("sftp://[::1]:22/x", "::1", Some(22)),
            ("ssh://host:22/x", "host", Some(22)),
        ] {
            let ep = Endpoint::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(ep.display(), text);
            let (h, p) = match &ep.remote {
                Remote::Ssh { host, port, .. } | Remote::Sftp { host, port, .. } => {
                    (host.as_str(), *port)
                }
                _ => panic!("{text}: not ssh"),
            };
            assert_eq!((h, p), (host, port), "{text}");
        }
        for bad in [
            "ssh://[::1/x",
            "ssh://::1/x",
            "sftp://[::1]:+22/x",
            "ssh://[::1]x/x",
            "hdfs://::1/x",
            "hdfs://[::1/x",
            "hdfs://nn:abc/x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad} was accepted");
        }
        // A password in an ssh or sftp authority is refused, and the refusal does not
        // repeat it. Both halves matter: accepting it would write the password into the
        // job log and the catalog index while ssh never used it, and refusing it with
        // `{text:?}` would write it into the same files from the refusal instead.
        // The path-less spellings are here because the "needs an absolute path" refusal
        // fires FIRST in source order and quotes the endpoint -- the reason the guard
        // runs before the path split rather than beside the `@`.
        for bad in [
            "ssh://alice:NOTAREALPW@host/x",
            "sftp://alice:NOTAREALPW@host/x",
            "ssh://alice:NOTAREALPW@host",
            "sftp://alice:NOTAREALPW@host",
            "ssh://alice:NOTAREALPW@[::1]:2222/x",
            "ssh://a@b:NOTAREALPW@host/x",
        ] {
            let e = Endpoint::parse(bad).unwrap_err().to_string();
            assert!(
                e.contains("password in the authority"),
                "{bad} was not refused for the password: {e}"
            );
            assert!(
                !e.contains("NOTAREALPW"),
                "the refusal of {bad} repeated the password: {e}"
            );
        }
        // the controls: a userless and a passwordless authority still parse, and an IPv6
        // host -- which is full of colons -- is not mistaken for a password
        for good in [
            "ssh://alice@host/x",
            "sftp://alice@host/x",
            "ssh://host/x",
            "ssh://alice@[::1]:2222/x",
            "ssh://[::1]:2222/x",
        ] {
            Endpoint::parse(good).unwrap_or_else(|e| panic!("{good} was refused: {e}"));
        }
    }

    /// The backstop for the sites that print an endpoint before anything parses it. The
    /// user survives -- it is not the secret and a log that cannot say which account ran is
    /// worth less -- and everything after the first colon does not.
    #[test]
    fn redacting_an_endpoint_takes_the_password_and_keeps_everything_else() {
        for (text, want) in [
            (
                "dav://operator:s3cret@host/coll",
                "dav://operator:***@host/coll",
            ),
            (
                "ssh://alice:hunter2@host:22/tmp/x",
                "ssh://alice:***@host:22/tmp/x",
            ),
            ("https://u:p@host/a/b?q=1", "https://u:***@host/a/b?q=1"),
            // no path after the authority: the redaction still has to find its end
            ("dav://operator:s3cret@host", "dav://operator:***@host"),
            // `a@b` is the user, `pw` the password, per the rsplit the parsers use
            ("ssh://a@b:pw@host/x", "ssh://a@b:***@host/x"),
        ] {
            assert_eq!(redact_userinfo(text), want, "{text}");
        }
        // The controls, and each is a different way of having no password to take. The
        // fourth is the one that makes the "inside the authority" rule load-bearing: an
        // `@` and a `:` in the PATH are not userinfo, and a redaction that read them as
        // such would corrupt an object key.
        for same in [
            "ssh://alice@host/x",          // a user, no password
            "dav://host:8443/coll",        // a port, no user at all
            "/local/path:with@both",       // no scheme
            "s3://bucket/mail:archive@v2", // `:` and `@` in the key, after the authority
            "oci://[::1]:5000/app",        // an IPv6 host is full of colons
        ] {
            assert_eq!(
                redact_userinfo(same),
                same,
                "{same} was rewritten and carries no password"
            );
        }
        // hdfs keeps its authority as text and the WebHDFS client reads it; parse and
        // client must agree, which `hdfs://::1/x` -- accepted here, refused there -- broke
        let ep = Endpoint::parse("hdfs://[::1]:9870/x").unwrap();
        assert_eq!(ep.display(), "hdfs://[::1]:9870/x");
        net::http::split_url("http://[::1]:9870/").unwrap();
        for bad in [
            "dav://[::1/a",
            "dav://[::1]x/a",
            "dav://::1/a",
            "dav://[]/a",
            "dav://x]y/a",
            "dav://[::1]:+80/a",
            "dav://host:abc/a",
            "oci://[::1/app",
            "oci://::1/app",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn endpoints_parse_local_nfs_and_s3_forms_and_refuse_malformed_ones() {
        assert_eq!(Endpoint::parse("/a/b").unwrap(), Endpoint::local("/a/b"));
        assert_eq!(Endpoint::parse("file:///a").unwrap(), Endpoint::local("/a"));
        let n = Endpoint::parse("filer:/vol/data:/sub").unwrap();
        assert_eq!(
            n.remote,
            Remote::Nfs {
                host: "filer".into(),
                export: "/vol/data".into()
            }
        );
        assert_eq!(
            (n.path.as_path(), n.display()),
            (Path::new("/sub"), "filer:/vol/data:/sub".to_string())
        );
        let s = Endpoint::parse("s3://bucket/a/b/").unwrap();
        assert_eq!(
            s.remote,
            Remote::S3 {
                bucket: "bucket".into()
            }
        );
        assert_eq!(
            (s.path.as_path(), s.display()),
            (Path::new("/a/b"), "s3://bucket/a/b".to_string())
        );
        assert_eq!(
            Endpoint::parse("s3://bucket").unwrap().display(),
            "s3://bucket"
        );
        assert_eq!(s.join("c").display(), "s3://bucket/a/b/c");
        assert_eq!(s.parent().display(), "s3://bucket/a");
        assert!(Endpoint::parse("s3://").is_err());
        assert!(Endpoint::parse("s3://b/../x").is_err());
        assert!(Endpoint::parse("s3://b_ad/x").is_err());
        let h = Endpoint::parse("hdfs://nn:9870/data/in/").unwrap();
        assert_eq!(
            (h.remote.clone(), h.path.as_path(), h.display()),
            (
                Remote::Hdfs {
                    namenode: "nn:9870".into()
                },
                Path::new("/data/in"),
                "hdfs://nn:9870/data/in".to_string()
            )
        );
        assert_eq!(
            Endpoint::parse("hdfs:///x").unwrap().remote,
            Remote::Hdfs {
                namenode: String::new()
            }
        );
        assert_eq!(
            Endpoint::parse("hdfs://nn").unwrap().path.as_path(),
            Path::new("/")
        );
        assert!(Endpoint::parse("hdfs://nn/../x").is_err());
        assert!(check_distinct_endpoints(
            &Endpoint::parse("s3://b/a").unwrap(),
            &Endpoint::parse("s3://b/a/c").unwrap()
        )
        .is_err());
        assert!(check_distinct_endpoints(
            &Endpoint::parse("s3://b/a").unwrap(),
            &Endpoint::parse("s3://c/a").unwrap()
        )
        .is_ok());
        assert!(check_distinct_endpoints(
            &Endpoint::parse("s3://b/a").unwrap(),
            &Endpoint::parse("filer:/a").unwrap()
        )
        .is_ok());
    }
}
