//! `rcp serve`: the far end of an `ssh://` endpoint. Reads request frames on stdin, answers
//! on stdout, and serves one local tree (the path the client names in HELLO) through the
//! `Tree` port, so everything the local adapter can do is what the remote can do. One
//! process per connection; the client opens as many as it has workers.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use super::proto::*;
use crate::anytree::{AnyReader, AnySink, AnyTree, Transports};
use crate::ports::{ChunkSig, Digests, Patch, Runtime, Segment, Sink, Tree};
use crate::tree::LocalTree;
use crate::xdr::{Decoder, Encoder};
use std::sync::Arc;

struct Session {
    /// Any adapter, not only the local one: a serve is a RELAY when the client's HELLO
    /// names an endpoint rather than a path, and it opens that endpoint on the client's
    /// behalf with its own environment -- its credentials, its transport settings, its
    /// `RCP_ALLOWED_ROOTS`. That is what lets an `rcp` reach a registry, a bucket or a
    /// second `rcp serve` that only this host can see.
    tree: Option<AnyTree>,
    readers: BTreeMap<u32, AnyReader>,
    sinks: BTreeMap<u32, AnySink>,
    /// A sink that failed a write, hole or reserve keeps the failure here, so the pipelined
    /// requests behind the failed one are refused rather than applied to a broken file.
    failed: BTreeMap<u32, String>,
    /// Delta matches being set up: the file, its chunking, and the signatures so far.
    deltas: BTreeMap<u32, DeltaSetup>,
    /// Roots this session may open, beyond whatever `RCP_ALLOWED_ROOTS` says. A `-listen`
    /// run fills this from its own `-allow`; a stdio serve leaves it empty and is bounded
    /// by the environment alone, as it always was.
    roots: Vec<String>,
    /// Payload compression, agreed in HELLO.
    squeeze: Squeeze,
    next_handle: u32,
    runtime: Runtime,
}

/// The most signatures one delta setup holds: about 350 MiB of them.
const MAX_SIGNATURES: usize = 8 << 20;
/// The most delta setups a session holds at once; a client abandoning them is refused
/// more, and CLOSE on the handle drops one.
const MAX_DELTA_SETUPS: usize = 64;

struct DeltaSetup {
    rel: String,
    params: crate::cdc::Params,
    digests: Arc<dyn Digests>,
    sigs: Vec<ChunkSig>,
}

/// The digest a client named, as the adapter behind the port.
fn digests_named(name: &str) -> io::Result<Arc<dyn Digests>> {
    crate::hash::Algorithm::by_name(name)
        .map(|a| a.digests())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("digest {name:?} is not one this rcp serve has"),
            )
        })
}

fn garbage(e: io::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("request: {e}"))
}

/// The hop operator's rail. `RCP_ALLOWED_ROOTS` in the serve's environment -- set from
/// `~/.ssh/rc`, an `authorized_keys` `environment=`, or the wrapper that launches it --
/// bounds what a client may ask this serve to open, endpoints included, the same way it
/// bounds a railed command line. Unset means what a serve always meant: whatever the ssh
/// user may reach.
fn served_allowed(text: &str, extra: &[String]) -> io::Result<()> {
    // `extra` is what a `-listen` run was told on its command line. It is passed in rather
    // than read here because the two sources were NOT the same source, and the gap was a
    // hole: `check_listen` counted `-allow` as railing the listener while this function
    // read only the environment, so `serve -listen 127.0.0.1:P -allow /srv` started
    // happily and then served a write to /tmp/elsewhere. Found by running the copy the
    // rail was supposed to refuse, which is the only way that gap shows.
    let env = std::env::var("RCP_ALLOWED_ROOTS").unwrap_or_default();
    if env.is_empty() && extra.is_empty() {
        return Ok(());
    }
    let v = if extra.is_empty() {
        env
    } else if env.is_empty() {
        extra.join(",")
    } else {
        format!("{env},{}", extra.join(","))
    };
    let clean = |r: &str| -> Option<String> {
        let r = r.trim();
        match r.trim_end_matches('/') {
            "" if r.starts_with('/') => Some("/".to_string()),
            "" => None,
            t => Some(t.to_string()),
        }
    };
    let roots: Vec<String> = v.split(',').filter_map(clean).collect();
    if roots.is_empty() {
        return Ok(());
    }
    let under = |text: &str, root: &str| -> bool {
        if root == "/" {
            return text.starts_with('/');
        }
        text == root
            || text
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    // A remote endpoint cannot be canonicalized here. Climbing text is refused rather
    // than accepted because its spelling happened to start with an allowed prefix.
    if text.contains("://") {
        if text.contains("/../") || text.ends_with("/..") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{text}: a path with `..` in it cannot be checked against this serve's allowed roots"
                ),
            ));
        }
        let text = text.trim_end_matches('/');
        return if roots.iter().any(|r| under(text, r)) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{text}: not under this serve's allowed roots ({})",
                    roots.join(", ")
                ),
            ))
        };
    }
    // A local path is compared after symlinks and `..` are resolved. `/srv/../etc` and
    // `/srv/link` (link → /etc) both spell as though they sit under `/srv`.
    let local = resolved_local(Path::new(text));
    let shown = local.display().to_string();
    let ok = roots.iter().any(|r| {
        if r.contains("://") {
            return false;
        }
        let root = r.trim().strip_prefix("file://").unwrap_or(r.trim());
        under(
            &shown,
            &resolved_local(Path::new(root)).display().to_string(),
        )
    });
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{shown}: not under this serve's allowed roots ({})",
                roots.join(", ")
            ),
        ))
    }
}

/// The path a local endpoint really names: every symlink followed and every `..` applied,
/// as far as the path exists, with what does not exist yet appended. Same walk the
/// command-line rail uses; a serve that only compared the spelling admitted `/srv/../etc`.
fn resolved_local(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut left: Vec<OsString> = abs
        .components()
        .rev()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name.to_os_string()),
            std::path::Component::ParentDir => Some(OsString::from("..")),
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
                            std::path::Component::ParentDir => left.push(OsString::from("..")),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    out
}

fn path_under(text: &str, root: &str) -> bool {
    if root == "/" {
        return text.starts_with('/');
    }
    text == root
        || text
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Refuses a path that would leave the served tree: absolute, or with a `..` component.
fn check_rel(rel: &str) -> io::Result<()> {
    if rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{rel}: outside the served tree"),
        ));
    }
    Ok(())
}

impl Session {
    fn tree(&self) -> io::Result<&AnyTree> {
        self.tree
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no HELLO yet"))
    }

    fn handle(&mut self) -> u32 {
        self.next_handle += 1;
        self.next_handle
    }

    /// A relative path from the client: inside the served tree, or refused. The client rcp
    /// never sends one that is not, so this is a guard for what else may speak the protocol.
    fn rel(&self, d: &mut Decoder<'_>) -> io::Result<String> {
        let rel = d.string().map_err(garbage)?;
        check_rel(&rel)?;
        self.anchor(&rel)?;
        Ok(rel)
    }

    fn item(&self, d: &mut Decoder<'_>) -> io::Result<crate::ports::Item> {
        let item = decode_item(d).map_err(garbage)?;
        check_rel(&item.rel)?;
        self.anchor(&item.rel)?;
        Ok(item)
    }

    /// A relative path whose parent chain, once symlinks are followed, still sits in the
    /// served tree. The final component may be a symlink this session is about to read as
    /// a link; an intermediate symlink to somewhere else is how `sub/file` leaves the tree.
    fn anchor(&self, rel: &str) -> io::Result<()> {
        let Some(AnyTree::Local(tree)) = &self.tree else {
            return Ok(());
        };
        // The root itself has a parent outside the tree. Operating on `.` is the tree.
        if rel.is_empty() || rel == "." {
            return Ok(());
        }
        let root = resolved_local(tree.root());
        let full = tree.full(rel);
        let parent = full.parent().unwrap_or(tree.root());
        let parent = resolved_local(parent);
        if path_under(&parent.display().to_string(), &root.display().to_string()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{rel}: outside the served tree"),
            ))
        }
    }

    /// An open or create follows the final component. A symlink planted at that name, or
    /// at a parent, must not resolve outside the tree.
    fn followed_stays(&self, rel: &str) -> io::Result<()> {
        let Some(AnyTree::Local(tree)) = &self.tree else {
            return Ok(());
        };
        let root = resolved_local(tree.root());
        let full = resolved_local(&tree.full(rel));
        if path_under(&full.display().to_string(), &root.display().to_string()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{rel}: outside the served tree"),
            ))
        }
    }

    /// One request; the reply body (after the status), or the error to report.
    fn dispatch(
        &mut self,
        op: u32,
        d: &mut Decoder<'_>,
        out: &mut dyn Write,
        seq: u32,
    ) -> io::Result<Vec<u8>> {
        let mut e = Encoder::new();
        match op {
            OP_HELLO | OP_ATTACH => {
                // a later channel joining the tree the first one opened: nothing is created
                // and nothing is asserted about the endpoint (see `OP_ATTACH`)
                let attach = op == OP_ATTACH;
                let version = d.u32().map_err(garbage)?;
                // Version 5 is raw or LZ4 and one bool; version 6 names a codec with a tag
                // (see `CODEC_VERSION`). Anything else is refused at the first field,
                // before a path is read or a tree opened.
                if version != VERSION && version != CODEC_VERSION {
                    return Err(io::Error::new(io::ErrorKind::Unsupported, format!("protocol version {version}; this rcp serve speaks {VERSION} and {CODEC_VERSION}")));
                }
                let target = d.string().map_err(garbage)?;
                let create = d.bool().map_err(garbage)?;
                // REQUIRED, and this reverses an older reading. "These are trailing fields,
                // so a peer that predates them runs off the end and a default is harmless"
                // fails this repo's own rule: `version` is checked for EQUALITY above, so a
                // peer that predates a field has already been refused by version, and the
                // only way a tolerant read can fire is a TRUNCATED frame. A truncated read
                // is not evidence of absence. Within a version every peer sends every field.
                let (compress, codec, level) = if version == VERSION {
                    (d.bool().map_err(garbage)?, Codec::Lz4, DEFAULT_LEVEL)
                } else {
                    // v6: the codec is REQUIRED and must be one this serve speaks. An unknown
                    // tag is refused rather than answered with LZ4: a v6 client asked for a
                    // named codec explicitly, and a quiet downgrade would hand it a stream it
                    // did not ask for. (LZ4 itself never travels as v6; it is version 5.)
                    let tag = d.u32().map_err(garbage)?;
                    let codec = match Codec::from_flag(tag) {
                        Some(c) if c != Codec::Lz4 => c,
                        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, format!("protocol version {CODEC_VERSION} names codec {tag}; this rcp serve speaks zstd ({PAYLOAD_ZSTD}) and deflate ({PAYLOAD_DEFLATE}) there"))),
                    };
                    // DEFLATE carries a level; zstd does not (the original zstd-only v6 HELLO
                    // ends at the tag, and still parses here). The level is DEFLATE's LAST
                    // field, and an out-of-range one falls back to the DEFAULT, not to nine:
                    // `clamp(1, 9)` would send 10, 255 and 1000 to the most expensive setting
                    // this side offers, answering the one input a caller cannot have meant
                    // with maximum effort. The peer choosing how hard THIS side works is accepted: it is
                    // bounded by `MAX_FRAME` a payload, and whoever asks is already let in
                    // (loopback, or mutual TLS).
                    let level = if codec == Codec::Deflate {
                        let asked = d.u32().map_err(garbage)?;
                        if (1..=9).contains(&asked) {
                            asked as u8
                        } else {
                            DEFAULT_LEVEL
                        }
                    } else {
                        DEFAULT_LEVEL
                    };
                    (true, codec, level)
                };
                // The string is an ENDPOINT. A bare absolute path is the local one, which
                // is every HELLO before relays existed; anything with a scheme is opened
                // through the same adapters this binary has when it is the client.
                let ep = crate::Endpoint::parse(&target)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                served_allowed(&ep.display(), &self.roots)?;
                if ep.is_local() {
                    let path = ep.path.clone();
                    if !path.is_absolute() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "{}: ssh:// paths are absolute on the remote host",
                                path.display()
                            ),
                        ));
                    }
                    match std::fs::metadata(&path) {
                        _ if attach => {}
                        Ok(m) if m.is_dir() => {}
                        Ok(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::NotADirectory,
                                format!("{}: not a directory", path.display()),
                            ))
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                            std::fs::create_dir_all(&path)?
                        }
                        Err(e) => {
                            return Err(io::Error::new(
                                e.kind(),
                                format!("{}: {e}", path.display()),
                            ))
                        }
                    }
                    self.tree = Some(AnyTree::Local(LocalTree::new(&path)));
                } else {
                    // this host's environment, on purpose: a relay's credentials and
                    // transport settings are the hop operator's, not the caller's
                    let transports = Transports::from_env(self.runtime.log.clone());
                    let tree = if attach {
                        AnyTree::attach(&ep, create, &transports)
                    } else {
                        AnyTree::open(&ep, create, &transports)
                    };
                    self.tree =
                        Some(tree.map_err(|e| {
                            io::Error::new(e.kind(), format!("{}: {e}", ep.display()))
                        })?);
                }
                self.squeeze = Squeeze::with_codec(compress, codec, level);
                // The level the serve ACTUALLY used, logged as a discriminator. A pull
                // measurement alone cannot settle it: two different byte totals out of a
                // serve are consistent with the level having reached its encoder AND with
                // the serve having been configured that way itself, and the numbers alone
                // cannot separate them. This line can. The contract arm reads it back, so
                // the claim rests on the serve's own report rather than on the arrangement
                // of the test.
                crate::debug!(
                    self.runtime.log,
                    "serve: hello compress={compress} codec={} level={level}",
                    codec.name()
                );
                // The questions the planner and the metadata commands ask a tree, answered
                // for the tree the hop actually opened. Without them the client's `SshTree`
                // answers the defaults -- true, true -- for a WebDAV tree behind a relay,
                // and `sync` through the hop recopies every file as if `keeps_times` did
                // not exist. All FOUR, read from the trait: a tar behind the hop needs one
                // writer at a time, and a registry behind it publishes on `sync` -- neither
                // is the local default.
                let tree = self.tree()?;
                // ONE word for the codec, then the four tree answers. Under v5 it is the tag of
                // what this side will send -- RAW (0) or LZ4 (1) -- which is also exactly how
                // XDR encodes the bool a v5 client from before tags reads there. Under v6 it
                // is the codec's tag, which the client requires to match what it asked for.
                let answer = if version == VERSION {
                    if compress {
                        PAYLOAD_LZ4
                    } else {
                        PAYLOAD_RAW
                    }
                } else {
                    codec.flag()
                };
                e.string(env!("CARGO_PKG_VERSION"))
                    .u32(answer)
                    .bool(tree.keeps_times())
                    .bool(tree.rewrites_metadata_in_place())
                    .bool(tree.writes_in_one_stream())
                    .bool(tree.sync_publishes());
            }
            OP_LIST => {
                let filter = decode_filter(d).map_err(garbage)?;
                let depth = d.u32().map_err(garbage)?;
                let parallel = d.u32().map_err(garbage)?;
                let listing = self.tree()?.list(
                    &filter,
                    if depth == u32::MAX {
                        None
                    } else {
                        Some(depth as usize)
                    },
                    parallel.clamp(1, 32) as usize,
                )?;
                // batches under this sequence number, then LIST_END as the reply
                for batch in listing.items.chunks(LIST_BATCH) {
                    let mut f = Encoder::new();
                    f.u32(seq).u32(0).u32(LIST_ITEMS).u32(batch.len() as u32);
                    for i in batch {
                        encode_item(&mut f, i);
                    }
                    write_frame(out, &f.into_bytes())?;
                }
                for batch in listing.errors.chunks(LIST_BATCH) {
                    let mut f = Encoder::new();
                    f.u32(seq).u32(0).u32(LIST_ERRORS).u32(batch.len() as u32);
                    for err in batch {
                        f.string(err);
                    }
                    write_frame(out, &f.into_bytes())?;
                }
                e.u32(LIST_END);
            }
            OP_STAT => {
                let rel = self.rel(d)?;
                match self.tree()?.stat(&rel)? {
                    Some(i) => {
                        e.bool(true);
                        encode_item(&mut e, &i);
                    }
                    None => {
                        e.bool(false);
                    }
                }
            }
            OP_OPEN_READ => {
                let rel = self.rel(d)?;
                self.followed_stays(&rel)?;
                // the size from the tree rather than from the reader: a reader over any
                // adapter is `Read + Seek`, and only the local one is a file with metadata
                let size = self
                    .tree()?
                    .stat(&rel)?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, format!("{rel}: no such file"))
                    })?
                    .size;
                let f = self.tree()?.open(&rel)?;
                let h = self.handle();
                self.readers.insert(h, f);
                e.u32(h).u64(size);
            }
            OP_READ => {
                let h = d.u32().map_err(garbage)?;
                let offset = d.u64().map_err(garbage)?;
                let len = d.u32().map_err(garbage)?.min((MAX_FRAME - 64) as u32) as usize;
                let f = self.readers.get_mut(&h).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("read handle {h}"))
                })?;
                // Seek then read, not `read_at`: this was a positional read on a local
                // file, and a reader over any adapter is `Read + Seek`. Every reader here
                // treats a seek to its current position as a no-op, so the sequential
                // case -- which is what the client's read-ahead window sends -- costs
                // nothing, and a real seek is what a real seek should cost.
                io::Seek::seek(f, io::SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; len];
                let mut got = 0;
                while got < len {
                    let n = io::Read::read(f, &mut buf[got..])?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
                buf.truncate(got);
                self.squeeze.pack(&mut e, &buf);
                e.bool(got < len);
            }
            OP_CLOSE => {
                let h = d.u32().map_err(garbage)?;
                self.readers.remove(&h);
                self.sinks.remove(&h);
                self.failed.remove(&h);
                self.deltas.remove(&h);
            }
            OP_SEGMENTS => {
                // a stream of frames under this sequence number, ending with SEG_END
                let rel = self.rel(d)?;
                // `read` follows the last component. A symlink there must still land in the tree.
                self.followed_stays(&rel)?;
                let block = d
                    .u32()
                    .map_err(garbage)?
                    .clamp(4096, (MAX_FRAME - 64) as u32) as usize;
                let mut buf = vec![0u8; block];
                let mut squeeze = std::mem::take(&mut self.squeeze);
                let result = self.tree().and_then(|tree| {
                    tree.read(&rel, &mut buf, &mut |seg| {
                        let mut f = Encoder::new();
                        f.u32(seq).u32(0);
                        match seg {
                            Segment::Data(data) => {
                                f.u32(SEG_DATA);
                                squeeze.pack(&mut f, data);
                            }
                            Segment::Hole(n) => {
                                f.u32(SEG_HOLE).u64(n);
                            }
                        }
                        write_frame(out, &f.into_bytes())
                    })
                });
                self.squeeze = squeeze;
                result?;
                e.u32(SEG_END);
            }
            OP_CREATE => {
                let item = self.item(d)?;
                self.followed_stays(&item.rel)?;
                let sink = self.tree()?.create_file(&item)?;
                let h = self.handle();
                self.sinks.insert(h, sink);
                e.u32(h);
            }
            OP_RESERVE => {
                let h = d.u32().map_err(garbage)?;
                let len = d.u64().map_err(garbage)?;
                self.fallible(h, |sink| sink.reserve(len))?;
            }
            OP_WRITE => {
                let h = d.u32().map_err(garbage)?;
                let data = unpack(d).map_err(garbage)?;
                self.fallible(h, |sink| sink.write(&data))?;
            }
            OP_HOLE => {
                let h = d.u32().map_err(garbage)?;
                let len = d.u64().map_err(garbage)?;
                self.fallible(h, |sink| sink.hole(len))?;
            }
            OP_FINISH => {
                let h = d.u32().map_err(garbage)?;
                let item = self.item(d)?;
                let xattrs = decode_xattrs(d).map_err(garbage)?;
                let meta = decode_meta(d).map_err(garbage)?;
                let fsync = d.bool().map_err(garbage)?;
                let nocache = d.bool().map_err(garbage)?;
                let refusals = {
                    if let Some(why) = self.failed.get(&h) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{}: not finished, an earlier write failed: {why}", item.rel),
                        ));
                    }
                    let sink = self.sink(h)?;
                    let r = sink.finish(&item, &xattrs, meta, fsync)?;
                    if nocache {
                        sink.drop_cache();
                    }
                    r
                };
                self.sinks.remove(&h);
                self.failed.remove(&h);
                encode_refusals(&mut e, &refusals);
            }
            OP_MKDIR => {
                let rel = self.rel(d)?;
                self.tree()?.mkdir(&rel)?;
            }
            OP_SYMLINK => {
                let rel = self.rel(d)?;
                let target = d.string().map_err(garbage)?;
                self.tree()?.symlink(&rel, Path::new(&target))?;
            }
            OP_HARDLINK => {
                let existing = d.string().map_err(garbage)?;
                check_rel(&existing)?;
                self.anchor(&existing)?;
                self.followed_stays(&existing)?;
                let rel = self.rel(d)?;
                self.tree()?.hard_link(&existing, &rel)?;
            }
            OP_REMOVE => {
                let rel = self.rel(d)?;
                let kind = match d.u32().map_err(garbage)? {
                    0 => crate::catalog::Kind::File,
                    1 => crate::catalog::Kind::Dir,
                    _ => crate::catalog::Kind::Symlink,
                };
                let r = self.tree()?.remove(&rel, kind)?;
                encode_removed(&mut e, &r);
            }
            OP_RENAME => {
                let from = self.rel(d)?;
                let to = self.rel(d)?;
                self.tree()?.rename(&from, &to)?;
            }
            OP_SETMETA => {
                let rel = self.rel(d)?;
                let item = self.item(d)?;
                // A symlink is lchown'd and not opened. A file's mode and times follow the name.
                if item.kind != crate::catalog::Kind::Symlink {
                    self.followed_stays(&rel)?;
                }
                let meta = decode_meta(d).map_err(garbage)?;
                let r = self.tree()?.set_metadata(&rel, &item, meta)?;
                encode_refusals(&mut e, &r);
            }
            OP_XATTRS => {
                let rel = self.rel(d)?;
                let xs = self.tree()?.xattrs(&rel)?;
                encode_xattrs(&mut e, &xs);
            }
            OP_SETXATTRS => {
                let rel = self.rel(d)?;
                let xs = decode_xattrs(d).map_err(garbage)?;
                let refused = self.tree()?.set_xattrs(&rel, &xs)?;
                e.u32(refused.len() as u32);
                for r in &refused {
                    e.string(r);
                }
            }
            OP_RESTORE_ATIME => {
                let item = self.item(d)?;
                self.followed_stays(&item.rel)?;
                self.tree()?.restore_atime(&item)?;
            }
            OP_SYNC => {
                self.tree()?.sync()?;
            }
            OP_SIGNATURES => {
                let rel = self.rel(d)?;
                self.followed_stays(&rel)?;
                let params = decode_params(d).map_err(garbage)?;
                let digests = digests_named(&d.string().map_err(garbage)?)?;
                let sigs = self.tree()?.signatures(&rel, params, &*digests)?;
                for batch in sigs.chunks(LIST_BATCH) {
                    let mut f = Encoder::new();
                    f.u32(seq).u32(0).u32(SIG_BATCH);
                    encode_sigs(&mut f, batch);
                    write_frame(out, &f.into_bytes())?;
                }
                e.u32(SIG_END);
            }
            OP_DELTA_BEGIN => {
                let rel = self.rel(d)?;
                self.followed_stays(&rel)?;
                let params = decode_params(d).map_err(garbage)?;
                let digests = digests_named(&d.string().map_err(garbage)?)?;
                self.tree()?;
                if self.deltas.len() >= MAX_DELTA_SETUPS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "{MAX_DELTA_SETUPS} delta setups already open; run or close one first"
                        ),
                    ));
                }
                let h = self.handle();
                self.deltas.insert(
                    h,
                    DeltaSetup {
                        rel,
                        params,
                        digests,
                        sigs: Vec::new(),
                    },
                );
                e.u32(h);
            }
            OP_DELTA_SIGS => {
                let h = d.u32().map_err(garbage)?;
                let setup = self.deltas.get_mut(&h).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("delta handle {h}"))
                })?;
                decode_sigs(d, &mut setup.sigs).map_err(garbage)?;
                // a million signatures is a terabyte at the largest chunk; eight times that is
                // not a file, it is a client filling this process
                if setup.sigs.len() > MAX_SIGNATURES {
                    self.deltas.remove(&h);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("more than {MAX_SIGNATURES} signatures for one file"),
                    ));
                }
            }
            OP_DELTA_RUN => {
                let h = d.u32().map_err(garbage)?;
                let setup = self.deltas.remove(&h).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("delta handle {h}"))
                })?;
                let runtime = Runtime {
                    digests: setup.digests.clone(),
                    chunk_digests: self.runtime.chunk_digests.clone(),
                    throttle: self.runtime.throttle.clone(),
                    log: self.runtime.log.clone(),
                    names: self.runtime.names.clone(),
                };
                let mut squeeze = std::mem::take(&mut self.squeeze);
                let result = self.tree().and_then(|tree| {
                    tree.delta(&setup.rel, setup.params, &setup.sigs, &runtime, &mut |p| {
                        let mut f = Encoder::new();
                        f.u32(seq).u32(0);
                        match p {
                            Patch::Literal(b) => {
                                f.u32(PATCH_LITERAL);
                                squeeze.pack(&mut f, b);
                            }
                            Patch::Copy { offset, len } => {
                                f.u32(PATCH_COPY).u64(offset).u64(len);
                            }
                            Patch::Hole(n) => {
                                f.u32(PATCH_HOLE).u64(n);
                            }
                        }
                        write_frame(out, &f.into_bytes())
                    })
                });
                self.squeeze = squeeze;
                let digest = result?;
                e.u32(PATCH_END).string(&digest);
            }
            OP_CREATE_PATCH => {
                let item = self.item(d)?;
                self.followed_stays(&item.rel)?;
                let basis = decode_basis(d).map_err(garbage)?;
                let digests = digests_named(&d.string().map_err(garbage)?)?;
                let sink = self.tree()?.create_patch(&item, &basis, &*digests)?;
                let h = self.handle();
                self.sinks.insert(h, sink);
                e.u32(h);
            }
            OP_COPY_BASIS => {
                let h = d.u32().map_err(garbage)?;
                let offset = d.u64().map_err(garbage)?;
                let len = d.u64().map_err(garbage)?;
                self.fallible(h, |sink| sink.copy_basis(offset, len))?;
            }
            OP_EXPECT => {
                let h = d.u32().map_err(garbage)?;
                let digest = d.string().map_err(garbage)?;
                self.fallible(h, |sink| sink.expect(&digest))?;
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("operation {other}"),
                ))
            }
        }
        let _ = &self.runtime;
        Ok(e.into_bytes())
    }

    fn sink(&mut self, h: u32) -> io::Result<&mut AnySink> {
        self.sinks
            .get_mut(&h)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("write handle {h}")))
    }

    /// A data operation on a sink: refused once one has failed, and remembered when it fails.
    fn fallible(
        &mut self,
        h: u32,
        op: impl FnOnce(&mut AnySink) -> io::Result<()>,
    ) -> io::Result<()> {
        if let Some(why) = self.failed.get(&h) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("write handle {h}: an earlier write failed: {why}"),
            ));
        }
        match op(self.sink(h)?) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.failed.insert(h, e.to_string());
                Err(e)
            }
        }
    }
}

/// Serves stdin and stdout until the client closes the stream. Errors in a request are
/// reported to the client; only a broken stream ends the loop with an error.
pub fn serve(runtime: Runtime) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_on(runtime, &[], stdin.lock(), stdout.lock())
}

/// The same session over any pair of streams.
///
/// `serve` is this over stdio, which is what an `ssh://` endpoint gets: OpenSSH has already
/// authenticated the peer and started this process as that user. `listen` is this over a
/// socket, where NOTHING has authenticated anyone -- see the rules there.
pub fn serve_on(
    runtime: Runtime,
    roots: &[String],
    read: impl io::Read,
    write: impl Write,
) -> io::Result<()> {
    let mut input = BufReader::with_capacity(1 << 20, read);
    let mut output = BufWriter::with_capacity(1 << 20, write);
    let mut session = Session {
        tree: None,
        readers: BTreeMap::new(),
        sinks: BTreeMap::new(),
        failed: BTreeMap::new(),
        deltas: BTreeMap::new(),
        roots: roots.to_vec(),
        squeeze: Squeeze::default(),
        next_handle: 0,
        runtime,
    };
    while let Some(body) = read_frame(&mut input)? {
        let mut d = Decoder::new(&body);
        let (seq, op) = match (d.u32(), d.u32()) {
            (Ok(s), Ok(o)) => (s, o),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a frame without a header",
                ))
            }
        };
        let mut reply = Encoder::new();
        reply.u32(seq);
        match session.dispatch(op, &mut d, &mut output, seq) {
            Ok(payload) => {
                reply.u32(0);
                let mut bytes = reply.into_bytes();
                bytes.extend_from_slice(&payload);
                write_frame(&mut output, &bytes)?;
            }
            Err(err) => {
                reply
                    .u32(1 + kind_code_of(err.kind()))
                    .string(&err.to_string());
                write_frame(&mut output, &reply.into_bytes())?;
            }
        }
        output.flush()?;
    }
    Ok(())
}

/// Why a `-listen` address was refused. Separate from the bind so it can be tested without
/// opening a socket, and so the reason is one string in one place rather than three.
///
/// **The rule, and why it is this rule.** Over `ssh://`, OpenSSH authenticates the peer and
/// starts `rcp serve` as that user before a single frame is read; the protocol inherits an
/// identity it never has to establish. A bare socket inherits nothing. So a listener that
/// served the protocol as-is on a routable address would be an unauthenticated remote file
/// service -- read and write, anywhere the serving user can reach -- and that is not a
/// feature anyone asked for.
///
/// Two conditions, both required, and neither is a default that can be drifted into:
///
/// - **Roots, always.** `-allow` or `RCP_ALLOWED_ROOTS` must name what may be served. Not
///   because it authenticates anything -- it does not -- but because it bounds what an
///   authenticated *or* unauthenticated peer can reach, and a bound blast radius is worth
///   having under every other control that might fail.
/// - **Loopback, unless the peer is authenticated.** A plaintext listener on `127.0.0.1` is
///   reachable only by something already on the host, which is the case this exists for:
///   `-nodes` and `-via` across a tunnel somebody else authenticated. Anything routable
///   needs MUTUAL TLS: `-tls.clientca` naming the authority that must have signed the
///   peer's certificate.
///
/// **A server certificate alone does not count, and that is the subtle part.** `-tls.cert`
/// and `-tls.key` prove to the CLIENT who the serve is and keep a passive observer out of
/// the stream. They establish nothing whatever about who connected. A serve with a
/// certificate and no client verifier, bound to a routable address, is still an
/// unauthenticated remote filesystem -- now wearing a padlock, which is worse than the
/// plain one because it reads as solved. So `check_listen` asks for `is_mutual`, not for
/// "has TLS", and a serve that offers TLS without requiring a client certificate is
/// refused on a routable address exactly as a plaintext one is.
///
/// **And what mutual TLS buys is AUTHENTICATION, not AUTHORIZATION -- say the second part
/// out loud.** The gap between those two words is the most significant limit on this
/// transport, even though it is not a defect in the code: `-tls.clientca` makes the peer
/// prove it holds a certificate this authority signed. It does not ask WHICH certificate. There is no subject or SAN allowlist here,
/// so every holder of a leaf from that CA is the same caller as far as this serve is
/// concerned, and a CA that signs a fleet has signed a front door for the whole fleet.
///
/// The consequence for an operator is concrete rather than theoretical: **name a CA that
/// exists for this purpose**, not the organization-wide one that also signs laptops and
/// service meshes. The `-allow` roots are what bounds the damage if that advice is
/// ignored, which is why they are required even under mutual TLS and not merely
/// recommended. A per-peer allowlist would close it properly and is not implemented; it
/// is recorded as open rather than implied by the word "authenticated".
#[derive(Debug, PartialEq, Eq)]
pub enum ListenRefusal {
    NoRoots,
    NotLoopback(String),
    /// TLS was asked for by half: a certificate without its key, or the other way round.
    HalfIdentity,
    /// `-tls.clientca` without anything to present: mutual TLS is mutual.
    NoServerIdentity,
    /// `-tls.*` on a binary built without the feature, so nothing would negotiate TLS.
    ///
    /// **This refusal completes the partition; it does not close a hole.** The build
    /// without the feature refuses anyway -- `tls_config` returns an error, and it runs
    /// before `TcpListener::bind`, so no socket is ever created. But `check_listen` is the
    /// documented, arm-covered place where a listener is decided, and without this variant
    /// it answers Ok for a state that can never be served. `is_mutual()` returning true on
    /// a binary that cannot do mutual TLS is the specific lie: the gate that lifts the
    /// loopback rule would be satisfied by an option the build cannot honor. Without the
    /// variant, `serve -listen 0.0.0.0:0 -allow /tmp` with a full
    /// `-tls.cert`/`-tls.key`/`-tls.clientca` set exits 1 from `tls_config` with no
    /// listener bound.
    NoTlsFeature,
}

impl std::fmt::Display for ListenRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenRefusal::NoRoots => write!(
                f,
                "serve -listen needs -allow ROOT (or RCP_ALLOWED_ROOTS): a listener serves whatever the protocol asks for, so what it may reach has to be named"
            ),
            ListenRefusal::NotLoopback(a) => write!(
                f,
                "serve -listen {a}: only a loopback address may be served without mutual TLS, because nothing else authenticates the peer. Bind 127.0.0.1 and reach it through a tunnel, or give -tls.cert, -tls.key and -tls.clientca -- a server certificate on its own encrypts the stream without identifying who connected, so it does not lift this"
            ),
            ListenRefusal::HalfIdentity => write!(f, "serve -listen: -tls.cert and -tls.key go together: name both, or neither"),
            ListenRefusal::NoServerIdentity => write!(f, "serve -listen: -tls.clientca asks the peer for a certificate, so this side needs one too: give -tls.cert and -tls.key"),
            ListenRefusal::NoTlsFeature => write!(
                f,
                "serve -listen with -tls.* needs an rcp built with the rustls feature (cargo build --features rustls): without it nothing would negotiate TLS, so the options cannot lift the loopback rule"
            ),
        }
    }
}

/// Decides whether `addr` may be served, given whether any root was railed.
///
/// Pure, so the arms can cover every shape -- IPv4 and IPv6 loopback, a routable address, a
/// wildcard bind -- without a socket. A wildcard (`0.0.0.0`, `::`) is NOT loopback: it
/// includes every interface the host has, which is the exact thing being refused.
pub fn check_listen(
    addr: std::net::SocketAddr,
    railed: bool,
    tls: &super::TlsFiles,
) -> Result<(), ListenRefusal> {
    if !railed {
        return Err(ListenRefusal::NoRoots);
    }
    // BEFORE anything reads `is_mutual`, because on a binary without the feature that
    // question has no honest answer: the files are named and nothing will ever present or
    // verify them. Refusing here keeps the loopback rule's precondition true by
    // construction rather than by a later error from a different function.
    if !cfg!(feature = "rustls") && tls.any() {
        return Err(ListenRefusal::NoTlsFeature);
    }
    if tls.cert.is_some() != tls.key.is_some() {
        return Err(ListenRefusal::HalfIdentity);
    }
    if tls.is_mutual() && !tls.has_identity() {
        return Err(ListenRefusal::NoServerIdentity);
    }
    if !addr.ip().is_loopback() && !tls.is_mutual() {
        return Err(ListenRefusal::NotLoopback(addr.to_string()));
    }
    Ok(())
}

#[cfg(feature = "rustls")]
type ServerTls = Option<Arc<rustls::ServerConfig>>;
#[cfg(not(feature = "rustls"))]
type ServerTls = Option<std::convert::Infallible>;

#[cfg(feature = "rustls")]
fn tls_config(files: &super::TlsFiles) -> io::Result<ServerTls> {
    if !files.has_identity() {
        return Ok(None);
    }
    super::tls::server_config(files).map(Some)
}

/// Without the feature the options are REFUSED, not ignored. A serve asked for mutual TLS
/// and given none would look identical from the outside to one that got it.
#[cfg(not(feature = "rustls"))]
fn tls_config(files: &super::TlsFiles) -> io::Result<ServerTls> {
    if files.any() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "serve -listen with -tls.* needs an rcp built with the rustls feature (cargo build --features rustls)"));
    }
    Ok(None)
}

#[cfg(feature = "rustls")]
fn accept_tls(
    cfg: &Arc<rustls::ServerConfig>,
    stream: std::net::TcpStream,
    roots: &[String],
    runtime: &Runtime,
) -> io::Result<io::Result<()>> {
    let shared = super::tls::Shared::new(super::tls::accept(cfg, stream)?);
    Ok(serve_on(runtime.clone(), roots, shared.clone(), shared))
}

#[cfg(not(feature = "rustls"))]
fn accept_tls(
    cfg: &std::convert::Infallible,
    _s: std::net::TcpStream,
    _r: &[String],
    _rt: &Runtime,
) -> io::Result<io::Result<()>> {
    match *cfg {}
}

/// Serves the protocol on `addr` until the process is stopped, one thread per connection.
///
/// `railed` is whether this run has any allowed root; see `check_listen` for why both it
/// and the loopback rule are required. `ready` is called once with the bound address, which
/// is how a caller that asked for port 0 learns the port it got.
pub fn listen(
    runtime: Runtime,
    addr: std::net::SocketAddr,
    roots: &[String],
    tls: &super::TlsFiles,
    ready: impl FnOnce(std::net::SocketAddr),
) -> io::Result<()> {
    check_listen(addr, !roots.is_empty(), tls)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
    // Built once, before the bind, so a certificate that cannot be read fails the command
    // rather than every connection to a listener that already announced itself.
    let server_tls = tls_config(tls)?;
    let listener = std::net::TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    crate::debug!(runtime.log, "serve: listening on {bound}");
    ready(bound);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            // one peer that vanished mid-handshake is not a reason to stop serving
            Err(e) => {
                crate::debug!(
                    runtime.log,
                    "serve: a connection failed before it began: {e}"
                );
                continue;
            }
        };
        let runtime = runtime.clone();
        let roots = roots.to_vec();
        #[allow(
            clippy::clone_on_copy,
            reason = "`ServerTls` is `Copy` only in a build without TLS"
        )]
        let server_tls = server_tls.clone();
        std::thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into());
            let outcome = match server_tls {
                None => {
                    // Two handles on one socket: the session reads and writes independently,
                    // and a `TcpStream` is only `Read` on `&self` for one direction at a time.
                    match stream.try_clone() {
                        Ok(reader) => serve_on(runtime.clone(), &roots, reader, stream),
                        Err(e) => {
                            crate::debug!(
                                runtime.log,
                                "serve: {peer}: cannot split the socket: {e}"
                            );
                            return;
                        }
                    }
                }
                Some(cfg) => match accept_tls(&cfg, stream, &roots, &runtime) {
                    Ok(r) => r,
                    Err(e) => {
                        // Where a peer with no certificate, or one from the wrong authority,
                        // is turned away. Named here rather than inside a frame, because the
                        // session never starts.
                        crate::debug!(runtime.log, "serve: {peer} refused: {e}");
                        return;
                    }
                },
            };
            match outcome {
                Ok(()) => crate::debug!(runtime.log, "serve: {peer} closed"),
                Err(e) => crate::debug!(runtime.log, "serve: {peer}: {e}"),
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape of address the rule has to decide, without opening a socket.
    ///
    /// The wildcard cases are the ones worth having: `0.0.0.0` and `::` are not loopback --
    /// they are EVERY interface, which is precisely what the rule refuses -- and a check
    /// written as "is it not a routable unicast address" rather than "is it loopback" would
    /// wave them through.
    #[test]
    fn only_a_railed_loopback_address_may_be_served() {
        use std::net::SocketAddr;
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let plain = super::super::TlsFiles::default();

        assert_eq!(check_listen(a("127.0.0.1:9000"), true, &plain), Ok(()));
        assert_eq!(check_listen(a("[::1]:9000"), true, &plain), Ok(()));
        // the whole 127/8 block is loopback, not just .0.0.1
        assert_eq!(check_listen(a("127.9.9.9:9000"), true, &plain), Ok(()));

        // no roots: refused wherever it binds, loopback included
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), false, &plain),
            Err(ListenRefusal::NoRoots)
        );
        assert_eq!(
            check_listen(a("10.0.0.5:9000"), false, &plain),
            Err(ListenRefusal::NoRoots)
        );

        // railed but reachable: refused, and the message names the address
        for spec in [
            "0.0.0.0:9000",
            "[::]:9000",
            "10.0.0.5:9000",
            "192.168.1.2:22",
        ] {
            let got = check_listen(a(spec), true, &plain);
            assert_eq!(
                got,
                Err(ListenRefusal::NotLoopback(spec.to_string())),
                "{spec} was not refused"
            );
            assert!(
                got.unwrap_err().to_string().contains("mutual TLS"),
                "{spec}: the refusal should say what would make it acceptable"
            );
        }
    }

    fn tls_files(cert: bool, key: bool, client_ca: bool) -> super::super::TlsFiles {
        super::super::TlsFiles {
            ca: None,
            cert: cert.then(|| PathBuf::from("cert.pem")),
            key: key.then(|| PathBuf::from("key.pem")),
            client_ca: client_ca.then(|| PathBuf::from("ca.pem")),
        }
    }

    /// The rule that a server certificate does NOT lift the loopback restriction, stated as
    /// an arm because it is the one an implementer is most likely to "fix".
    ///
    /// The control is the pair: the SAME routable address is refused with a server identity
    /// and accepted once a client authority is named. Without the second half the arm would
    /// pass against a `check_listen` that refuses every routable address unconditionally --
    /// which is the old behavior, and would make the whole feature untestably absent.
    ///
    /// **It runs only with the feature, and the `#[cfg]` is load-bearing rather than
    /// convenient.** Without `tls` compiled in, `-tls.*` is refused outright (see the arm
    /// below), so "mutual TLS lifts the restriction" is not a statement the default build
    /// can make at all -- there is no mutual TLS in it. Asserting it anyway would be
    /// asserting a policy about a capability the binary does not have.
    #[test]
    #[cfg(feature = "rustls")]
    fn a_server_certificate_does_not_lift_loopback_but_a_client_authority_does() {
        use std::net::SocketAddr;
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let files = tls_files;

        let routable = a("10.0.0.5:9000");
        // encryption without peer authentication: still refused, and for the same reason
        let got = check_listen(routable, true, &files(true, true, false));
        assert_eq!(got, Err(ListenRefusal::NotLoopback(routable.to_string())));
        assert!(
            got.unwrap_err()
                .to_string()
                .contains("encrypts the stream without identifying who connected"),
            "the refusal has to say why a certificate was not enough"
        );
        // the control: the same address, the same certificate, plus a client authority
        assert_eq!(
            check_listen(routable, true, &files(true, true, true)),
            Ok(()),
            "mutual TLS is what lifts it"
        );
        // and a wildcard bind is no different: it is every interface, not a special case
        assert_eq!(
            check_listen(a("0.0.0.0:9000"), true, &files(true, true, true)),
            Ok(())
        );

        // the two half-configurations, which are typos rather than choices
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), true, &files(true, false, false)),
            Err(ListenRefusal::HalfIdentity)
        );
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), true, &files(false, true, false)),
            Err(ListenRefusal::HalfIdentity)
        );
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), true, &files(false, false, true)),
            Err(ListenRefusal::NoServerIdentity),
            "asking the peer for a certificate while offering none cannot handshake"
        );

        // roots still come first: mutual TLS does not excuse an unbounded serve
        assert_eq!(
            check_listen(routable, false, &files(true, true, true)),
            Err(ListenRefusal::NoRoots)
        );
    }

    /// Without the feature, `-tls.*` is refused BY `check_listen`, not later by whoever
    /// tries to build a config.
    ///
    /// It is worth stating what this covers and what it does not. It is **not** a hole:
    /// `tls_config` refuses too, and it runs before `TcpListener::bind`, so no socket is
    /// ever created -- a default build with a full cert/key/clientca set exits 1 with
    /// nothing listening. The point is narrower and still worth covering: `check_listen` is
    /// the documented place a listener is decided and the only one these arms cover, and it
    /// must not answer `Ok` for a configuration that can never be served. Worse, it would
    /// reach that `Ok` through `is_mutual()`, so the gate that lifts the loopback rule would
    /// be satisfied by options the build cannot honor.
    ///
    /// The control is the third assertion: with NO tls options the same routable address
    /// gets `NotLoopback`, so this arm is not simply "the default build refuses
    /// everything".
    #[test]
    #[cfg(not(feature = "rustls"))]
    fn without_the_feature_the_tls_options_are_refused_by_the_listen_check_itself() {
        use std::net::SocketAddr;
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let routable = a("10.0.0.5:9000");

        // the full, otherwise-valid mutual set: refused, and not for being non-loopback
        let got = check_listen(routable, true, &tls_files(true, true, true));
        assert_eq!(got, Err(ListenRefusal::NoTlsFeature));
        assert!(
            got.unwrap_err().to_string().contains("--features rustls"),
            "the refusal has to name the build that would honor it"
        );
        // even on loopback, where the options change nothing, naming them is still a
        // request the binary cannot honor and saying so beats ignoring it
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), true, &tls_files(true, true, false)),
            Err(ListenRefusal::NoTlsFeature)
        );

        // THE CONTROL: with no tls options at all the old rules still decide, so this arm
        // is about the options and not about the build refusing everything
        let plain = super::super::TlsFiles::default();
        assert_eq!(
            check_listen(routable, true, &plain),
            Err(ListenRefusal::NotLoopback(routable.to_string()))
        );
        assert_eq!(check_listen(a("127.0.0.1:9000"), true, &plain), Ok(()));
        // and roots still come first
        assert_eq!(
            check_listen(a("127.0.0.1:9000"), false, &tls_files(true, true, true)),
            Err(ListenRefusal::NoRoots)
        );
    }

    fn session() -> Session {
        Session {
            tree: None,
            readers: BTreeMap::new(),
            sinks: BTreeMap::new(),
            failed: BTreeMap::new(),
            deltas: BTreeMap::new(),
            roots: Vec::new(),
            squeeze: Squeeze::default(),
            next_handle: 0,
            runtime: Runtime::plain(),
        }
    }

    /// A COMPLETE version-5 HELLO, which is the only kind a version-5 peer sends.
    ///
    /// This used to stop after `create`, and it passed because the serve defaulted the
    /// fields that follow. Removing that tolerance broke this helper and three arms
    /// that use it -- which is the finding working, not collateral damage: the only thing
    /// relying on a short HELLO was a fixture simulating a peer the VERSION check already
    /// refuses.
    fn hello(s: &mut Session, dir: &Path) {
        let mut out = Vec::new();
        let mut h = Encoder::new();
        h.u32(VERSION)
            .string(&dir.to_string_lossy())
            .bool(false)
            .bool(false);
        let bytes = h.into_bytes();
        s.dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut out, 1)
            .unwrap();
    }

    #[test]
    fn a_join_opens_a_tree_hello_would_refuse_and_never_creates_it() {
        // the tree the first channel opened is gone -- `delete -removetopdir` removes it
        // last -- and a channel that joins now must still come up, so the remaining work
        // fails or succeeds item by item instead of at the door
        let dir = std::env::temp_dir().join(format!("rcp-serve-join-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let greet = |create: bool| {
            let mut h = Encoder::new();
            h.u32(VERSION)
                .string(&dir.to_string_lossy())
                .bool(create)
                .bool(false);
            h.into_bytes()
        };
        let mut s = session();
        let err = s
            .dispatch(
                OP_HELLO,
                &mut Decoder::new(&greet(false)),
                &mut Vec::new(),
                1,
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "the control: {err}");

        let mut s = session();
        s.dispatch(
            OP_ATTACH,
            &mut Decoder::new(&greet(true)),
            &mut Vec::new(),
            1,
        )
        .expect("a join does not assert the tree");
        assert!(
            !dir.exists(),
            "a join created the directory: only the first open may, or a second channel \
             could recreate what the run just removed"
        );
    }

    #[test]
    fn a_sink_that_failed_once_refuses_every_later_write_and_its_finish() {
        let dir = std::env::temp_dir().join(format!("rcp-serve-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = session();
        hello(&mut s, &dir);
        let mut out = Vec::new();
        let item = crate::ports::Item {
            rel: "f".into(),
            kind: crate::catalog::Kind::File,
            size: 4,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: 0,
            link_target: None,
        };
        let mut e = Encoder::new();
        encode_item(&mut e, &item);
        let bytes = e.into_bytes();
        let reply = s
            .dispatch(OP_CREATE, &mut Decoder::new(&bytes), &mut out, 2)
            .unwrap();
        let h = Decoder::new(&reply).u32().unwrap();
        // a reserve no filesystem grants fails, and from then on the handle is poisoned
        let mut e = Encoder::new();
        e.u32(h).u64(u64::MAX);
        let bytes = e.into_bytes();
        let first = s
            .dispatch(OP_RESERVE, &mut Decoder::new(&bytes), &mut out, 3)
            .unwrap_err();
        assert!(
            !first.to_string().contains("an earlier write failed"),
            "the first failure is the filesystem's own: {first}"
        );
        let mut e = Encoder::new();
        e.u32(h);
        Squeeze::default().pack(&mut e, b"data");
        let bytes = e.into_bytes();
        let later = s
            .dispatch(OP_WRITE, &mut Decoder::new(&bytes), &mut out, 4)
            .unwrap_err();
        assert!(
            later.to_string().contains("an earlier write failed"),
            "{later}"
        );
        let mut e = Encoder::new();
        e.u32(h);
        encode_item(&mut e, &item);
        encode_xattrs(&mut e, &[]);
        encode_meta(&mut e, crate::ports::MetaOptions::default());
        e.bool(false).bool(false);
        let bytes = e.into_bytes();
        let fin = s
            .dispatch(OP_FINISH, &mut Decoder::new(&bytes), &mut out, 5)
            .unwrap_err();
        assert!(fin.to_string().contains("not finished"), "{fin}");
        assert_eq!(
            std::fs::read(dir.join("f")).unwrap_or_default(),
            b"",
            "no data reached the file"
        );
        // control: a fresh handle on the same session writes and finishes
        let mut e = Encoder::new();
        encode_item(&mut e, &item);
        let bytes = e.into_bytes();
        let reply = s
            .dispatch(OP_CREATE, &mut Decoder::new(&bytes), &mut out, 6)
            .unwrap();
        let h2 = Decoder::new(&reply).u32().unwrap();
        let mut e = Encoder::new();
        e.u32(h2);
        Squeeze::default().pack(&mut e, b"data");
        let bytes = e.into_bytes();
        s.dispatch(OP_WRITE, &mut Decoder::new(&bytes), &mut out, 7)
            .unwrap();
        let mut e = Encoder::new();
        e.u32(h2);
        encode_item(&mut e, &item);
        encode_xattrs(&mut e, &[]);
        encode_meta(&mut e, crate::ports::MetaOptions::default());
        e.bool(false).bool(false);
        let bytes = e.into_bytes();
        s.dispatch(OP_FINISH, &mut Decoder::new(&bytes), &mut out, 8)
            .unwrap();
        assert_eq!(std::fs::read(dir.join("f")).unwrap(), b"data");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A HELLO that ends early is REFUSED, not defaulted.
    ///
    /// It is tempting to accept a HELLO stopping after `create` on the reasoning that a
    /// client from before compression sends nothing more. Such a client cannot reach this
    /// code: `VERSION` is checked for EQUALITY, so a peer that predates any of these fields
    /// is refused by version before the fields are read. Within a version every peer sends
    /// all of them, so the only thing that can produce a short frame is TRUNCATION -- and
    /// treating that as "an old peer with modest tastes" is the same mistake as treating a
    /// truncated read as evidence of absence.
    ///
    /// So the property is: short is an error. Each prefix is tried, because an
    /// arm that only truncates in one place would pass against a serve that happened to
    /// check just that field.
    #[test]
    fn a_hello_that_ends_early_is_refused_rather_than_defaulted() {
        let dir = std::env::temp_dir().join(format!("rcp-serve-hello-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.to_string_lossy().to_string();

        // every prefix short of a full frame, in both versions: v5 without its compress
        // bool; v6 without its tag; v6 DEFLATE without its level
        let short: [(u32, Vec<u32>); 3] = [
            (VERSION, vec![]),
            (CODEC_VERSION, vec![]),
            (CODEC_VERSION, vec![PAYLOAD_DEFLATE]),
        ];
        for (i, (version, rest)) in short.iter().enumerate() {
            let mut s = session();
            let mut h = Encoder::new();
            h.u32(*version).string(&target).bool(false);
            for w in rest {
                h.u32(*w);
            }
            let bytes = h.into_bytes();
            let e = s
                .dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut Vec::new(), 1)
                .expect_err("a short HELLO must be refused");
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "prefix {i}: {e}");
            assert!(
                !s.squeeze.on,
                "prefix {i} left compression on after a refused HELLO"
            );
        }

        // THE CONTROLS, and they are the half that matters: each complete frame is
        // accepted, answered with the codec word its version defines, and turns
        // compression on. Without them this arm would pass against a serve that refused
        // every HELLO ever sent.
        let answer = |s: &mut Session, h: Encoder| {
            let bytes = h.into_bytes();
            let reply = s
                .dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut Vec::new(), 2)
                .expect("a complete HELLO is accepted");
            let mut d = Decoder::new(&reply);
            assert_eq!(d.string().unwrap(), env!("CARGO_PKG_VERSION"));
            d.u32().unwrap()
        };
        // v5, LZ4: the word is 1, which is also the bool `true` a pre-tag client reads
        let mut s = session();
        let mut h = Encoder::new();
        h.u32(VERSION).string(&target).bool(false).bool(true);
        assert_eq!(answer(&mut s, h), PAYLOAD_LZ4);
        assert!(s.squeeze.on && s.squeeze.codec == Codec::Lz4);
        // v6, DEFLATE at 9: the tag comes back, and the level reached the encoder
        let mut s = session();
        let mut h = Encoder::new();
        h.u32(CODEC_VERSION)
            .string(&target)
            .bool(false)
            .u32(PAYLOAD_DEFLATE)
            .u32(9);
        assert_eq!(answer(&mut s, h), PAYLOAD_DEFLATE);
        assert!(s.squeeze.on && s.squeeze.codec == Codec::Deflate);
        assert_eq!(
            s.squeeze.level, 9,
            "the level in the frame is the level the serve took"
        );
        // v6, zstd, as a zstd-only peer sends it: the frame ends at the tag, and no level
        // is read
        let mut s = session();
        let mut h = Encoder::new();
        h.u32(CODEC_VERSION)
            .string(&target)
            .bool(false)
            .u32(PAYLOAD_ZSTD);
        assert_eq!(answer(&mut s, h), PAYLOAD_ZSTD);
        assert!(s.squeeze.on && s.squeeze.codec == Codec::Zstd);

        // and a level a peer should never have sent falls back to the DEFAULT rather than
        // to the most expensive setting -- `clamp(1, 9)` would send 1000 to 9
        for silly in [0u32, 10, 255, 1000, u32::MAX] {
            let mut s = session();
            let mut h = Encoder::new();
            h.u32(CODEC_VERSION)
                .string(&target)
                .bool(false)
                .u32(PAYLOAD_DEFLATE)
                .u32(silly);
            let bytes = h.into_bytes();
            s.dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut Vec::new(), 3)
                .expect("an out-of-range level is not a protocol error");
            assert_eq!(
                s.squeeze.level, DEFAULT_LEVEL,
                "level {silly} was not answered with the default"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// v6 names a codec, and a name this serve does not answer with v6 -- LZ4, which is
    /// version 5's, or one it has never heard of -- is refused BEFORE a tree is opened, so
    /// nothing is created for a session that cannot proceed. A version
    /// past this serve's is refused at the first field, before any path is read.
    #[test]
    fn a_v6_hello_names_a_codec_this_serve_speaks_or_is_refused_before_a_tree_opens() {
        let dir = std::env::temp_dir().join(format!("rcp-zstd-hello-{}", std::process::id()));
        for tag in [PAYLOAD_RAW, PAYLOAD_LZ4, 99] {
            let mut s = session();
            let mut h = Encoder::new();
            h.u32(CODEC_VERSION)
                .string(&dir.to_string_lossy())
                .bool(true)
                .u32(tag);
            let err = s
                .dispatch(
                    OP_HELLO,
                    &mut Decoder::new(&h.into_bytes()),
                    &mut Vec::new(),
                    1,
                )
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported, "tag {tag}: {err}");
            assert!(!dir.exists(), "tag {tag} created the directory");
            assert!(!s.squeeze.on);
        }
        // control: the same frame naming zstd opens (and creates) the tree
        let mut s = session();
        let mut h = Encoder::new();
        h.u32(CODEC_VERSION)
            .string(&dir.to_string_lossy())
            .bool(true)
            .u32(PAYLOAD_ZSTD);
        s.dispatch(
            OP_HELLO,
            &mut Decoder::new(&h.into_bytes()),
            &mut Vec::new(),
            1,
        )
        .unwrap();
        assert!(dir.is_dir() && s.squeeze.on);
        std::fs::remove_dir_all(&dir).unwrap();
        let err = session()
            .dispatch(
                OP_HELLO,
                &mut Decoder::new(&7u32.to_be_bytes()),
                &mut Vec::new(),
                1,
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn a_path_outside_the_served_tree_is_refused_before_anything_is_touched() {
        let dir = std::env::temp_dir().join(format!("rcp-serve-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("inner")).unwrap();
        let mut s = session();
        let mut out = Vec::new();
        let mut hello = Encoder::new();
        hello
            .u32(VERSION)
            .string(&dir.join("inner").to_string_lossy())
            .bool(false)
            .bool(false);
        let bytes = hello.into_bytes();
        s.dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut out, 1)
            .unwrap();
        for (op, rel) in [
            (OP_OPEN_READ, "../escape"),
            (OP_MKDIR, "a/../../escape"),
            (OP_STAT, "/etc/hostname"),
            (OP_REMOVE, ".."),
        ] {
            let mut e = Encoder::new();
            e.string(rel).u32(0);
            let bytes = e.into_bytes();
            let err = s
                .dispatch(op, &mut Decoder::new(&bytes), &mut out, 2)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{rel}: {err}");
            assert!(err.to_string().contains("outside the served tree"), "{err}");
        }
        assert!(!dir.join("escape").exists());
        // control: a path inside the tree reaches the filesystem, and is judged there
        let mut e = Encoder::new();
        e.string("a/..b/missing");
        let bytes = e.into_bytes();
        assert_eq!(
            s.dispatch(OP_OPEN_READ, &mut Decoder::new(&bytes), &mut out, 3)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let mut e = Encoder::new();
        e.string("made");
        let bytes = e.into_bytes();
        s.dispatch(OP_MKDIR, &mut Decoder::new(&bytes), &mut out, 4)
            .unwrap();
        assert!(dir.join("inner/made").is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_listing_crosses_in_batches_and_ends_with_the_reply() {
        let dir = std::env::temp_dir().join(format!("rcp-serve-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let n = LIST_BATCH * 2 + 5;
        for i in 0..n {
            std::fs::write(dir.join(format!("f{i}")), b"x").unwrap();
        }
        let mut s = session();
        let mut out = Vec::new();
        let mut hello = Encoder::new();
        hello
            .u32(VERSION)
            .string(&dir.to_string_lossy())
            .bool(false)
            .bool(false);
        let bytes = hello.into_bytes();
        s.dispatch(OP_HELLO, &mut Decoder::new(&bytes), &mut out, 1)
            .unwrap();
        let mut e = Encoder::new();
        encode_filter(&mut e, &crate::filter::Filter::default());
        e.u32(u32::MAX).u32(4);
        let bytes = e.into_bytes();
        let reply = s
            .dispatch(OP_LIST, &mut Decoder::new(&bytes), &mut out, 2)
            .unwrap();
        assert_eq!(Decoder::new(&reply).u32().unwrap(), LIST_END);
        // three item batches (2048, 2048, 5 + the root) went out ahead of the reply
        let mut r = &out[..];
        let mut batches = Vec::new();
        while let Some(frame) = read_frame(&mut r).unwrap() {
            let mut d = Decoder::new(&frame);
            assert_eq!(
                (d.u32().unwrap(), d.u32().unwrap(), d.u32().unwrap()),
                (2, 0, LIST_ITEMS)
            );
            batches.push(d.u32().unwrap() as usize);
        }
        assert_eq!(batches.iter().sum::<usize>(), n + 1);
        assert_eq!(batches.len(), 3, "{batches:?}");
        assert!(batches.iter().all(|&b| b <= LIST_BATCH));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
