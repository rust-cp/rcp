//! NFS version 3 (RFC 1813) and MOUNT version 3: the structures and the argument/result
//! encodings for the procedures a copy needs. Both directions are here because the
//! stand-in server in `testserver.rs` speaks the same wire format back.

use std::io;

use crate::xdr::{Decoder, Encoder};

pub const NFS_VERS: u32 = 3;
pub const MOUNT_VERS: u32 = 3;

// NFSv3 procedures
pub const NFSPROC_NULL: u32 = 0;
pub const NFSPROC_GETATTR: u32 = 1;
pub const NFSPROC_SETATTR: u32 = 2;
pub const NFSPROC_LOOKUP: u32 = 3;
pub const NFSPROC_ACCESS: u32 = 4;
pub const NFSPROC_READLINK: u32 = 5;
pub const NFSPROC_READ: u32 = 6;
pub const NFSPROC_WRITE: u32 = 7;
pub const NFSPROC_CREATE: u32 = 8;
pub const NFSPROC_MKDIR: u32 = 9;
pub const NFSPROC_SYMLINK: u32 = 10;
pub const NFSPROC_REMOVE: u32 = 12;
pub const NFSPROC_RMDIR: u32 = 13;
pub const NFSPROC_RENAME: u32 = 14;
pub const NFSPROC_LINK: u32 = 15;
pub const NFSPROC_READDIRPLUS: u32 = 17;
pub const NFSPROC_FSSTAT: u32 = 18;
pub const NFSPROC_FSINFO: u32 = 19;
pub const NFSPROC_COMMIT: u32 = 21;

// MOUNT procedures
pub const MOUNTPROC_NULL: u32 = 0;
pub const MOUNTPROC_MNT: u32 = 1;
pub const MOUNTPROC_UMNT: u32 = 3;
pub const MOUNTPROC_EXPORT: u32 = 5;

pub const NFS3_OK: u32 = 0;
pub const NFS3ERR_NOENT: u32 = 2;
pub const NFS3ERR_IO: u32 = 5;
pub const NFS3ERR_ACCES: u32 = 13;
pub const NFS3ERR_EXIST: u32 = 17;
pub const NFS3ERR_NOTDIR: u32 = 20;
pub const NFS3ERR_ISDIR: u32 = 21;
pub const NFS3ERR_INVAL: u32 = 22;
pub const NFS3ERR_NOSPC: u32 = 28;
pub const NFS3ERR_NOTEMPTY: u32 = 66;
pub const NFS3ERR_ROFS: u32 = 30;
pub const NFS3ERR_STALE: u32 = 70;
/// The user's quota is exhausted, which is NOT the same as the filesystem being full --
/// an operator who reads "no space left on device" checks free space, finds plenty, and
/// looks in the wrong place. `StorageFull` is the closest kind std has; the message is what
/// distinguishes them.
pub const NFS3ERR_DQUOT: u32 = 69;
/// "Try again later": the server is bringing the file back from slow storage. It is a
/// retryable condition and the only NFS status that is, so it must not read as a failure.
pub const NFS3ERR_JUKEBOX: u32 = 10008;
pub const NFS3ERR_NOTSUPP: u32 = 10004;
pub const NFS3ERR_SERVERFAULT: u32 = 10006;

pub const NF3REG: u32 = 1;
pub const NF3DIR: u32 = 2;
pub const NF3BLK: u32 = 3;
pub const NF3CHR: u32 = 4;
pub const NF3LNK: u32 = 5;
pub const NF3SOCK: u32 = 6;
pub const NF3FIFO: u32 = 7;

pub const UNSTABLE: u32 = 0;
pub const FILE_SYNC: u32 = 2;

pub fn status_error(status: u32, what: &str) -> io::Error {
    let (kind, text) = match status {
        NFS3ERR_NOENT => (io::ErrorKind::NotFound, "no such file or directory"),
        NFS3ERR_IO => (io::ErrorKind::Other, "I/O error"),
        NFS3ERR_ACCES => (io::ErrorKind::PermissionDenied, "permission denied"),
        NFS3ERR_EXIST => (io::ErrorKind::AlreadyExists, "already exists"),
        NFS3ERR_NOTDIR => (io::ErrorKind::NotADirectory, "not a directory"),
        NFS3ERR_ISDIR => (io::ErrorKind::IsADirectory, "is a directory"),
        NFS3ERR_INVAL => (io::ErrorKind::InvalidInput, "invalid argument"),
        NFS3ERR_NOSPC => (io::ErrorKind::StorageFull, "no space left on device"),
        NFS3ERR_NOTEMPTY => (io::ErrorKind::DirectoryNotEmpty, "directory not empty"),
        // without this arm a read-only export falls to the catch-all and reports as a
        // generic "NFS error" -- with no sign that the whole destination is read-only and
        // every later entry will fail the same way
        NFS3ERR_ROFS => (io::ErrorKind::ReadOnlyFilesystem, "the export is read-only"),
        // NOT `NotFound`. A stale handle says the HANDLE is no longer valid -- after a
        // server restart, an export re-share, or the file being replaced -- and says nothing
        // about whether the name still holds a file. Mapped to `NotFound` it would reach
        // `Removed::Gone` through the removal path, which records "gone" in the catalog for
        // an entry that may be sitting there untouched; a later `sync` then believes the
        // catalog and never removes it. `StaleNetworkFileHandle`
        // is exactly this condition and no other, so nothing downstream can confuse it
        // with absence.
        NFS3ERR_STALE => (io::ErrorKind::StaleNetworkFileHandle, "stale file handle"),
        NFS3ERR_NOTSUPP => (
            io::ErrorKind::Unsupported,
            "operation not supported by the server",
        ),
        // Not left to the catch-all "NFS error": both name a specific condition an operator
        // would act on differently: a quota is raised by an admin,
        // a JUKEBOX wait is raised by waiting.
        NFS3ERR_DQUOT => (
            io::ErrorKind::StorageFull,
            "the user's disk quota is exhausted (the filesystem may have space)",
        ),
        NFS3ERR_JUKEBOX => (
            io::ErrorKind::WouldBlock,
            "the server is retrieving the file from slow storage; retryable",
        ),
        1 => (io::ErrorKind::PermissionDenied, "not owner"),
        _ => (io::ErrorKind::Other, "NFS error"),
    };
    io::Error::new(kind, format!("{what}: {text} (NFS3ERR {status})"))
}

/// A file handle: opaque to the client, up to 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fh(pub Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Time3 {
    pub seconds: u32,
    pub nseconds: u32,
}

impl Time3 {
    pub fn ns(&self) -> i128 {
        self.seconds as i128 * 1_000_000_000 + self.nseconds as i128
    }
    pub fn from_ns(ns: i128) -> Time3 {
        let s = ns.div_euclid(1_000_000_000);
        Time3 {
            seconds: s.clamp(0, u32::MAX as i128) as u32,
            nseconds: ns.rem_euclid(1_000_000_000) as u32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fattr3 {
    pub ftype: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev: (u32, u32),
    pub fsid: u64,
    pub fileid: u64,
    pub atime: Time3,
    pub mtime: Time3,
    pub ctime: Time3,
}

impl Fattr3 {
    pub fn decode(d: &mut Decoder<'_>) -> io::Result<Fattr3> {
        Ok(Fattr3 {
            ftype: d.u32()?,
            mode: d.u32()?,
            nlink: d.u32()?,
            uid: d.u32()?,
            gid: d.u32()?,
            size: d.u64()?,
            used: d.u64()?,
            rdev: (d.u32()?, d.u32()?),
            fsid: d.u64()?,
            fileid: d.u64()?,
            atime: Time3 {
                seconds: d.u32()?,
                nseconds: d.u32()?,
            },
            mtime: Time3 {
                seconds: d.u32()?,
                nseconds: d.u32()?,
            },
            ctime: Time3 {
                seconds: d.u32()?,
                nseconds: d.u32()?,
            },
        })
    }
    pub fn encode(&self, e: &mut Encoder) {
        e.u32(self.ftype)
            .u32(self.mode)
            .u32(self.nlink)
            .u32(self.uid)
            .u32(self.gid)
            .u64(self.size)
            .u64(self.used)
            .u32(self.rdev.0)
            .u32(self.rdev.1)
            .u64(self.fsid)
            .u64(self.fileid);
        for t in [self.atime, self.mtime, self.ctime] {
            e.u32(t.seconds).u32(t.nseconds);
        }
    }
}

/// `post_op_attr`: attributes the server chose to include.
pub fn decode_post_op_attr(d: &mut Decoder<'_>) -> io::Result<Option<Fattr3>> {
    if d.bool()? {
        Ok(Some(Fattr3::decode(d)?))
    } else {
        Ok(None)
    }
}

pub fn encode_post_op_attr(e: &mut Encoder, a: Option<&Fattr3>) {
    match a {
        Some(a) => {
            e.bool(true);
            a.encode(e);
        }
        None => {
            e.bool(false);
        }
    }
}

/// `wcc_data`: pre-op (size, mtime, ctime) and post-op attributes; skipped by the client.
pub fn decode_wcc(d: &mut Decoder<'_>) -> io::Result<Option<Fattr3>> {
    if d.bool()? {
        d.u64()?;
        d.skip(16)?;
    }
    decode_post_op_attr(d)
}

pub fn encode_wcc(e: &mut Encoder, after: Option<&Fattr3>) {
    e.bool(false);
    encode_post_op_attr(e, after);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    DontChange,
    ServerTime,
    Client(Time3),
}

/// `sattr3`: the attributes SETATTR, CREATE and MKDIR may set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sattr3 {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: SetTime,
    pub mtime: SetTime,
}

impl Default for Sattr3 {
    fn default() -> Self {
        Sattr3 {
            mode: None,
            uid: None,
            gid: None,
            size: None,
            atime: SetTime::DontChange,
            mtime: SetTime::DontChange,
        }
    }
}

impl Sattr3 {
    pub fn encode(&self, e: &mut Encoder) {
        for v in [self.mode, self.uid, self.gid] {
            match v {
                Some(x) => e.bool(true).u32(x),
                None => e.bool(false),
            };
        }
        match self.size {
            Some(s) => e.bool(true).u64(s),
            None => e.bool(false),
        };
        for t in [self.atime, self.mtime] {
            match t {
                SetTime::DontChange => e.u32(0),
                SetTime::ServerTime => e.u32(1),
                SetTime::Client(t) => e.u32(2).u32(t.seconds).u32(t.nseconds),
            };
        }
    }
    pub fn decode(d: &mut Decoder<'_>) -> io::Result<Sattr3> {
        let mode = if d.bool()? { Some(d.u32()?) } else { None };
        let uid = if d.bool()? { Some(d.u32()?) } else { None };
        let gid = if d.bool()? { Some(d.u32()?) } else { None };
        let size = if d.bool()? { Some(d.u64()?) } else { None };
        let time = |d: &mut Decoder<'_>| -> io::Result<SetTime> {
            Ok(match d.u32()? {
                0 => SetTime::DontChange,
                1 => SetTime::ServerTime,
                _ => SetTime::Client(Time3 {
                    seconds: d.u32()?,
                    nseconds: d.u32()?,
                }),
            })
        };
        let atime = time(d)?;
        let mtime = time(d)?;
        Ok(Sattr3 {
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// argument encoders (client side)
// ---------------------------------------------------------------------------------------------

pub fn args_fh(fh: &Fh) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0);
    e.into_bytes()
}

pub fn args_diropargs(dir: &Fh, name: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&dir.0).string(name);
    e.into_bytes()
}

pub fn args_setattr(fh: &Fh, attrs: &Sattr3) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0);
    attrs.encode(&mut e);
    e.bool(false); // no guard
    e.into_bytes()
}

pub fn args_read(fh: &Fh, offset: u64, count: u32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0).u64(offset).u32(count);
    e.into_bytes()
}

pub fn args_write(fh: &Fh, offset: u64, stable: u32, data: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0)
        .u64(offset)
        .u32(data.len() as u32)
        .u32(stable)
        .opaque(data);
    e.into_bytes()
}

/// CREATE with mode UNCHECKED.
/// `createhow3`: UNCHECKED creates or truncates, GUARDED refuses a name that exists.
pub const UNCHECKED: u32 = 0;
pub const GUARDED: u32 = 1;

pub fn args_create(dir: &Fh, name: &str, how: u32, attrs: &Sattr3) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&dir.0).string(name).u32(how);
    attrs.encode(&mut e);
    e.into_bytes()
}

pub fn args_mkdir(dir: &Fh, name: &str, attrs: &Sattr3) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&dir.0).string(name);
    attrs.encode(&mut e);
    e.into_bytes()
}

pub fn args_symlink(dir: &Fh, name: &str, attrs: &Sattr3, target: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&dir.0).string(name);
    attrs.encode(&mut e);
    e.string(target);
    e.into_bytes()
}

pub fn args_rename(from_dir: &Fh, from_name: &str, to_dir: &Fh, to_name: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&from_dir.0)
        .string(from_name)
        .opaque(&to_dir.0)
        .string(to_name);
    e.into_bytes()
}

pub fn args_link(file: &Fh, dir: &Fh, name: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&file.0).opaque(&dir.0).string(name);
    e.into_bytes()
}

pub fn args_readdirplus(dir: &Fh, cookie: u64, verf: u64, dircount: u32, maxcount: u32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&dir.0)
        .u64(cookie)
        .u64(verf)
        .u32(dircount)
        .u32(maxcount);
    e.into_bytes()
}

pub fn args_commit(fh: &Fh, offset: u64, count: u32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0).u64(offset).u32(count);
    e.into_bytes()
}

pub fn args_mnt(path: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(path);
    e.into_bytes()
}

// ---------------------------------------------------------------------------------------------
// result decoders (client side)
// ---------------------------------------------------------------------------------------------

fn status(d: &mut Decoder<'_>, what: &str) -> io::Result<()> {
    let s = d.u32()?;
    if s == NFS3_OK {
        Ok(())
    } else {
        Err(status_error(s, what))
    }
}

pub fn res_getattr(reply: &[u8]) -> io::Result<Fattr3> {
    let mut d = Decoder::new(reply);
    status(&mut d, "GETATTR")?;
    Fattr3::decode(&mut d)
}

pub fn res_setattr(reply: &[u8]) -> io::Result<()> {
    let mut d = Decoder::new(reply);
    status(&mut d, "SETATTR")
}

pub fn res_lookup(reply: &[u8]) -> io::Result<(Fh, Option<Fattr3>)> {
    let mut d = Decoder::new(reply);
    status(&mut d, "LOOKUP")?;
    let fh = Fh(d.opaque()?.to_vec());
    let attrs = decode_post_op_attr(&mut d)?;
    Ok((fh, attrs))
}

pub fn res_readlink(reply: &[u8]) -> io::Result<String> {
    let mut d = Decoder::new(reply);
    status(&mut d, "READLINK")?;
    decode_post_op_attr(&mut d)?;
    d.string()
}

/// `(data, eof)`.
pub fn res_read(reply: &[u8]) -> io::Result<(Vec<u8>, bool)> {
    let mut d = Decoder::new(reply);
    status(&mut d, "READ")?;
    decode_post_op_attr(&mut d)?;
    let _count = d.u32()?;
    let eof = d.bool()?;
    let data = d.opaque()?.to_vec();
    Ok((data, eof))
}

/// `(count, committed, verifier)`.
pub fn res_write(reply: &[u8]) -> io::Result<(u32, u32, u64)> {
    let mut d = Decoder::new(reply);
    status(&mut d, "WRITE")?;
    decode_wcc(&mut d)?;
    let count = d.u32()?;
    let committed = d.u32()?;
    let verf = d.u64()?;
    Ok((count, committed, verf))
}

/// CREATE, MKDIR and SYMLINK share a result shape: optional handle, optional attributes.
pub fn res_create(reply: &[u8], what: &str) -> io::Result<(Option<Fh>, Option<Fattr3>)> {
    let mut d = Decoder::new(reply);
    status(&mut d, what)?;
    let fh = if d.bool()? {
        Some(Fh(d.opaque()?.to_vec()))
    } else {
        None
    };
    let attrs = decode_post_op_attr(&mut d)?;
    Ok((fh, attrs))
}

pub fn res_wcc_only(reply: &[u8], what: &str) -> io::Result<()> {
    let mut d = Decoder::new(reply);
    status(&mut d, what)
}

pub fn res_commit(reply: &[u8]) -> io::Result<u64> {
    let mut d = Decoder::new(reply);
    status(&mut d, "COMMIT")?;
    decode_wcc(&mut d)?;
    d.u64()
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attrs: Option<Fattr3>,
    pub fh: Option<Fh>,
}

/// `(entries, eof, cookieverf)`.
pub fn res_readdirplus(reply: &[u8]) -> io::Result<(Vec<DirEntry>, bool, u64)> {
    let mut d = Decoder::new(reply);
    status(&mut d, "READDIRPLUS")?;
    decode_post_op_attr(&mut d)?;
    let verf = d.u64()?;
    let mut out = Vec::new();
    while d.bool()? {
        let fileid = d.u64()?;
        let name = d.string()?;
        let cookie = d.u64()?;
        let attrs = decode_post_op_attr(&mut d)?;
        let fh = if d.bool()? {
            Some(Fh(d.opaque()?.to_vec()))
        } else {
            None
        };
        out.push(DirEntry {
            fileid,
            name,
            cookie,
            attrs,
            fh,
        });
    }
    let eof = d.bool()?;
    Ok((out, eof, verf))
}

/// FSINFO: `(rtmax, wtmax)`, the server's preferred maximum read and write sizes.
pub fn res_fsinfo(reply: &[u8]) -> io::Result<(u32, u32)> {
    let mut d = Decoder::new(reply);
    status(&mut d, "FSINFO")?;
    decode_post_op_attr(&mut d)?;
    let rtmax = d.u32()?;
    let _rtpref = d.u32()?;
    let _rtmult = d.u32()?;
    let wtmax = d.u32()?;
    Ok((rtmax, wtmax))
}

pub fn res_mnt(reply: &[u8]) -> io::Result<Fh> {
    let mut d = Decoder::new(reply);
    let s = d.u32()?;
    if s != 0 {
        return Err(status_error(s, "MOUNT"));
    }
    Ok(Fh(d.opaque()?.to_vec()))
}

/// One line of a server's export list: the path and the clients allowed (empty: everyone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub path: String,
    pub groups: Vec<String>,
}

/// MOUNTPROC_EXPORT: the linked list of exports and their group lists.
pub fn res_exports(reply: &[u8]) -> io::Result<Vec<Export>> {
    let mut d = Decoder::new(reply);
    let mut out = Vec::new();
    while d.bool()? {
        let path = d.string()?;
        let mut groups = Vec::new();
        while d.bool()? {
            groups.push(d.string()?);
        }
        out.push(Export { path, groups });
    }
    Ok(out)
}

pub fn args_exports() -> Vec<u8> {
    Vec::new()
}

/// FSSTAT: total and free bytes, total and free files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
}

pub fn res_fsstat(reply: &[u8]) -> io::Result<FsStat> {
    let mut d = Decoder::new(reply);
    status(&mut d, "FSSTAT")?;
    decode_post_op_attr(&mut d)?;
    Ok(FsStat {
        total_bytes: d.u64()?,
        free_bytes: d.u64()?,
        avail_bytes: d.u64()?,
        total_files: d.u64()?,
        free_files: d.u64()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_and_sattr_round_trip() {
        let a = Fattr3 {
            ftype: NF3REG,
            mode: 0o644,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            size: 12345,
            used: 16384,
            rdev: (0, 0),
            fsid: 7,
            fileid: 99,
            atime: Time3 {
                seconds: 1,
                nseconds: 2,
            },
            mtime: Time3 {
                seconds: 3,
                nseconds: 4,
            },
            ctime: Time3 {
                seconds: 5,
                nseconds: 6,
            },
        };
        let mut e = Encoder::new();
        a.encode(&mut e);
        assert_eq!(Fattr3::decode(&mut Decoder::new(&e.buf)).unwrap(), a);
        let s = Sattr3 {
            mode: Some(0o600),
            uid: None,
            gid: Some(5),
            size: Some(0),
            atime: SetTime::ServerTime,
            mtime: SetTime::Client(Time3 {
                seconds: 9,
                nseconds: 8,
            }),
        };
        let mut e = Encoder::new();
        s.encode(&mut e);
        assert_eq!(Sattr3::decode(&mut Decoder::new(&e.buf)).unwrap(), s);
        assert_eq!(
            Time3::from_ns(1_600_000_000_123_456_789).ns(),
            1_600_000_000_123_456_789
        );
    }

    #[test]
    fn errors_map_to_kinds() {
        assert_eq!(
            status_error(NFS3ERR_NOENT, "LOOKUP").kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            status_error(NFS3ERR_ACCES, "WRITE").kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(status_error(NFS3ERR_NOTEMPTY, "RMDIR")
            .to_string()
            .contains("RMDIR"));
    }
}
