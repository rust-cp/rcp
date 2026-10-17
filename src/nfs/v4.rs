//! NFSv4.0 on the wire (RFC 7530): the COMPOUND procedure, its operations, the attribute
//! bitmap and the `fattr4` codec, plus two users of it. `V4` is the stateless sidecar that
//! `-acl4` runs beside the v3 data path (LOOKUP, GETATTR and SETATTR of the ACL attribute
//! need no client id, open or lease). `client4::Nfs4Tree` is the full data client, built on
//! the same `Compound` builder and result decoder, with SETCLIENTID, opens and stateids.
//! The stand-in server in `testserver` shares the attribute codec, so both ends of the
//! contract suite speak the one encoding. The kernel's `system.nfs4_acl` attribute on a
//! v4 mount is the ACL attribute's own XDR, so nothing is translated for it.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use super::client::Pool;
use super::rpc::NFS_PROG;
use crate::xdr::{Decoder, Encoder};

pub const NFS4_VERS: u32 = 4;
pub const NFSPROC4_COMPOUND: u32 = 1;

pub const OP_ACCESS: u32 = 3;
pub const OP_CLOSE: u32 = 4;
pub const OP_COMMIT: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_DELEGRETURN: u32 = 8;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LINK: u32 = 11;
pub const OP_LOOKUP: u32 = 15;
pub const OP_LOOKUPP: u32 = 16;
pub const OP_OPEN: u32 = 18;
pub const OP_OPEN_CONFIRM: u32 = 20;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30;
pub const OP_RESTOREFH: u32 = 31;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35;
pub const OP_SETCLIENTID_CONFIRM: u32 = 36;
pub const OP_WRITE: u32 = 38;

/// Attribute numbers (bit positions in the bitmap).
pub const FATTR4_SUPPORTED_ATTRS: u32 = 0;
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_CHANGE: u32 = 3;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_FSID: u32 = 8;
pub const FATTR4_LEASE_TIME: u32 = 10;
pub const FATTR4_RDATTR_ERROR: u32 = 11;
pub const FATTR4_ACL: u32 = 12;
pub const FATTR4_FILEHANDLE: u32 = 19;
pub const FATTR4_FILEID: u32 = 20;
pub const FATTR4_MAXREAD: u32 = 30;
pub const FATTR4_MAXWRITE: u32 = 31;
pub const FATTR4_MODE: u32 = 33;
pub const FATTR4_NUMLINKS: u32 = 35;
pub const FATTR4_OWNER: u32 = 36;
pub const FATTR4_OWNER_GROUP: u32 = 37;
pub const FATTR4_RAWDEV: u32 = 41;
pub const FATTR4_SPACE_USED: u32 = 45;
pub const FATTR4_TIME_ACCESS: u32 = 47;
pub const FATTR4_TIME_ACCESS_SET: u32 = 48;
pub const FATTR4_TIME_METADATA: u32 = 52;
pub const FATTR4_TIME_MODIFY: u32 = 53;
pub const FATTR4_TIME_MODIFY_SET: u32 = 54;

pub const NF4REG: u32 = 1;
pub const NF4DIR: u32 = 2;
pub const NF4BLK: u32 = 3;
pub const NF4CHR: u32 = 4;
pub const NF4LNK: u32 = 5;
pub const NF4SOCK: u32 = 6;
pub const NF4FIFO: u32 = 7;

pub const NFS4_OK: u32 = 0;
pub const NFS4ERR_PERM: u32 = 1;
pub const NFS4ERR_NOENT: u32 = 2;
pub const NFS4ERR_IO: u32 = 5;
pub const NFS4ERR_ACCESS: u32 = 13;
pub const NFS4ERR_EXIST: u32 = 17;
pub const NFS4ERR_NOTDIR: u32 = 20;
pub const NFS4ERR_ISDIR: u32 = 21;
pub const NFS4ERR_INVAL: u32 = 22;
pub const NFS4ERR_NOSPC: u32 = 28;
pub const NFS4ERR_ROFS: u32 = 30;
pub const NFS4ERR_NOTEMPTY: u32 = 66;
pub const NFS4ERR_STALE: u32 = 70;
/// The user's quota, not the filesystem's space. Reported as "no space left on device" an
/// operator checks free space, finds plenty, and looks in the wrong place.
pub const NFS4ERR_DQUOT: u32 = 69;
/// The file handle was valid and has aged out -- a volatile handle the server no longer
/// honors. Distinct from `STALE`, and it is the one an `fh_of` cache must react to by
/// dropping its entry and looking the name up again.
pub const NFS4ERR_FHEXPIRED: u32 = 10014;
/// The security flavor this export requires is not the one being offered. It names the
/// remedy -- `-nfs.sec` -- which a bare `permission denied` does not.
pub const NFS4ERR_WRONGSEC: u32 = 10016;
/// The readdir cookie is no longer valid, usually because the directory changed under the
/// walk. A listing that swallows it is a listing that silently drops entries.
pub const NFS4ERR_BAD_COOKIE: u32 = 10003;
pub const NFS4ERR_NOTSUPP: u32 = 10004;
pub const NFS4ERR_DELAY: u32 = 10008;
pub const NFS4ERR_EXPIRED: u32 = 10011;
pub const NFS4ERR_GRACE: u32 = 10013;
pub const NFS4ERR_NOFILEHANDLE: u32 = 10020;
/// OPEN named something other than a regular file or a directory -- a symlink, which OPEN
/// never follows (RFC 7530 16.16).
pub const NFS4ERR_SYMLINK: u32 = 10029;

pub const NFS4ERR_MINOR_VERS_MISMATCH: u32 = 10021;
pub const NFS4ERR_STALE_CLIENTID: u32 = 10022;
pub const NFS4ERR_STALE_STATEID: u32 = 10023;
pub const NFS4ERR_OLD_STATEID: u32 = 10024;
pub const NFS4ERR_BAD_STATEID: u32 = 10025;
pub const NFS4ERR_BAD_SEQID: u32 = 10026;
pub const NFS4ERR_ATTRNOTSUPP: u32 = 10032;
pub const NFS4ERR_BADXDR: u32 = 10036;
pub const NFS4ERR_BADOWNER: u32 = 10039;
pub const NFS4ERR_OP_ILLEGAL: u32 = 10044;

/// The attribute name the kernel gives an NFSv4 ACL on a v4 mount.
pub const ACL_NAME: &str = "system.nfs4_acl";

/// An NFSv4 status as an error, keeping the number. Several statuses share an `ErrorKind`, and
/// a caller that must act on ONE of them reads the number, not the text: matching the text lets
/// a file whose name contains it pass for that refusal.
#[derive(Debug)]
pub struct StatusError {
    pub status: u32,
    message: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StatusError {}

/// The NFSv4 status an error carries, if `status_error` made it.
pub fn status_in(e: &io::Error) -> Option<u32> {
    e.get_ref()?.downcast_ref::<StatusError>().map(|s| s.status)
}

pub fn status_error(status: u32, what: &str) -> io::Error {
    let (kind, text) = match status {
        NFS4ERR_PERM => (io::ErrorKind::PermissionDenied, "not owner"),
        NFS4ERR_NOENT => (io::ErrorKind::NotFound, "no such file or directory"),
        NFS4ERR_IO => (io::ErrorKind::Other, "I/O error"),
        NFS4ERR_ACCESS => (io::ErrorKind::PermissionDenied, "permission denied"),
        NFS4ERR_EXIST => (io::ErrorKind::AlreadyExists, "already exists"),
        NFS4ERR_NOTDIR => (io::ErrorKind::NotADirectory, "not a directory"),
        NFS4ERR_ISDIR => (io::ErrorKind::IsADirectory, "is a directory"),
        NFS4ERR_SYMLINK => (
            io::ErrorKind::InvalidInput,
            "is a symlink, which OPEN does not follow",
        ),
        NFS4ERR_INVAL => (io::ErrorKind::InvalidInput, "invalid argument"),
        NFS4ERR_NOSPC => (io::ErrorKind::StorageFull, "no space left on device"),
        NFS4ERR_NOTEMPTY => (io::ErrorKind::DirectoryNotEmpty, "directory not empty"),
        // see `proto::status_error`: a stale handle is not an absent name, and mapped to
        // `NotFound` it would reach `Removed::Gone` and write "gone" into the catalog for an
        // entry that may still be there
        NFS4ERR_STALE => (io::ErrorKind::StaleNetworkFileHandle, "stale file handle"),
        // a read-only export refusing a write. Left to the catch-all it would report as a
        // generic "NFS error" with no indication that the whole destination is read-only
        // and every later entry will fail the same way
        NFS4ERR_ROFS => (io::ErrorKind::ReadOnlyFilesystem, "the export is read-only"),
        NFS4ERR_NOTSUPP | NFS4ERR_ATTRNOTSUPP => {
            (io::ErrorKind::Unsupported, "not supported by the server")
        }
        NFS4ERR_DELAY => (
            io::ErrorKind::WouldBlock,
            "the server asks for a retry later",
        ),
        NFS4ERR_GRACE => (
            io::ErrorKind::WouldBlock,
            "the server is in its grace period after a restart",
        ),
        NFS4ERR_EXPIRED | NFS4ERR_STALE_CLIENTID => {
            (io::ErrorKind::TimedOut, "the client's lease expired")
        }
        NFS4ERR_STALE_STATEID | NFS4ERR_OLD_STATEID | NFS4ERR_BAD_STATEID => (
            io::ErrorKind::Other,
            "the server does not recognize the open state",
        ),
        NFS4ERR_BAD_SEQID => (io::ErrorKind::Other, "open-owner sequence mismatch"),
        NFS4ERR_MINOR_VERS_MISMATCH => (io::ErrorKind::Unsupported, "minor version not served"),
        NFS4ERR_BADOWNER => (
            io::ErrorKind::InvalidInput,
            "owner or group name not accepted",
        ),
        NFS4ERR_NOFILEHANDLE => (io::ErrorKind::InvalidInput, "no current file handle"),
        // Four more kept out of the catch-all "NFS error". Each names a different remedy -- raise a quota, look the handle up again, pass `-nfs.sec`,
        // restart the listing -- and "NFS error" names none of them.
        NFS4ERR_DQUOT => (
            io::ErrorKind::StorageFull,
            "the user's disk quota is exhausted (the filesystem may have space)",
        ),
        NFS4ERR_FHEXPIRED => (
            io::ErrorKind::StaleNetworkFileHandle,
            "the file handle expired; look the name up again",
        ),
        NFS4ERR_WRONGSEC => (
            io::ErrorKind::PermissionDenied,
            "the export requires a different security flavor; see -nfs.sec",
        ),
        NFS4ERR_BAD_COOKIE => (
            io::ErrorKind::InvalidData,
            "the readdir cookie is no longer valid; the directory changed under the listing",
        ),
        _ => (io::ErrorKind::Other, "NFS error"),
    };
    io::Error::new(
        kind,
        StatusError {
            status,
            message: format!("{what}: {text} (NFS4ERR {status})"),
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Time4 {
    pub seconds: i64,
    pub nseconds: u32,
}

impl Time4 {
    pub fn ns(&self) -> i128 {
        self.seconds as i128 * 1_000_000_000 + self.nseconds as i128
    }
    pub fn from_ns(ns: i128) -> Time4 {
        Time4 {
            seconds: ns.div_euclid(1_000_000_000) as i64,
            nseconds: ns.rem_euclid(1_000_000_000) as u32,
        }
    }
    fn encode(&self, e: &mut Encoder) {
        e.u64(self.seconds as u64).u32(self.nseconds);
    }
    fn decode(d: &mut Decoder<'_>) -> io::Result<Time4> {
        Ok(Time4 {
            seconds: d.u64()? as i64,
            nseconds: d.u32()?,
        })
    }
}

/// A stateid: the anonymous one (all zeros) for attribute operations, the server's for an
/// open file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stateid {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl Stateid {
    pub const ANONYMOUS: Stateid = Stateid {
        seqid: 0,
        other: [0; 12],
    };
    pub fn encode(&self, e: &mut Encoder) {
        e.u32(self.seqid).fixed(&self.other);
    }
    pub fn decode(d: &mut Decoder<'_>) -> io::Result<Stateid> {
        let seqid = d.u32()?;
        let other = d.fixed(12)?;
        Ok(Stateid {
            seqid,
            other: other.try_into().expect("12 bytes"),
        })
    }
}

/// A `settime4`: the server's clock, or the client's value.
pub type SetTime4 = Option<Time4>;

/// The attributes rcp reads and writes, decoded from or encoded into a `fattr4`. A field
/// that is `None` is absent from the bitmap.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attrs {
    pub supported: Option<Vec<u32>>,
    pub ftype: Option<u32>,
    pub change: Option<u64>,
    pub size: Option<u64>,
    pub fsid: Option<(u64, u64)>,
    pub lease_time: Option<u32>,
    pub rdattr_error: Option<u32>,
    pub acl: Option<Vec<u8>>,
    pub filehandle: Option<Vec<u8>>,
    pub fileid: Option<u64>,
    pub maxread: Option<u64>,
    pub maxwrite: Option<u64>,
    pub mode: Option<u32>,
    pub numlinks: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub rawdev: Option<(u32, u32)>,
    pub space_used: Option<u64>,
    pub time_access: Option<Time4>,
    pub time_access_set: Option<SetTime4>,
    pub time_metadata: Option<Time4>,
    pub time_modify: Option<Time4>,
    pub time_modify_set: Option<SetTime4>,
}

/// A bitmap4 from attribute numbers.
pub fn bitmap_of(bits: &[u32]) -> Vec<u32> {
    let mut words = Vec::new();
    for b in bits {
        let w = (*b / 32) as usize;
        if words.len() <= w {
            words.resize(w + 1, 0);
        }
        words[w] |= 1 << (b % 32);
    }
    words
}

fn bit_set(words: &[u32], bit: u32) -> bool {
    words
        .get((bit / 32) as usize)
        .is_some_and(|w| w & (1 << (bit % 32)) != 0)
}

pub fn encode_bitmap(e: &mut Encoder, words: &[u32]) {
    e.u32(words.len() as u32);
    for w in words {
        e.u32(*w);
    }
}

pub fn decode_bitmap(d: &mut Decoder<'_>) -> io::Result<Vec<u32>> {
    let n = d.u32()?;
    if n > 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bitmap too long",
        ));
    }
    (0..n).map(|_| d.u32()).collect()
}

fn encode_settime(e: &mut Encoder, t: &SetTime4) {
    match t {
        None => {
            e.u32(0);
        }
        Some(t) => {
            e.u32(1);
            t.encode(e);
        }
    }
}

fn decode_settime(d: &mut Decoder<'_>) -> io::Result<SetTime4> {
    match d.u32()? {
        0 => Ok(None),
        1 => Ok(Some(Time4::decode(d)?)),
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("settime4 discriminant {n}"),
        )),
    }
}

impl Attrs {
    /// The bitmap of the fields present, in ascending order.
    pub fn bitmap(&self) -> Vec<u32> {
        let mut bits = Vec::new();
        let mut add = |present: bool, bit: u32| {
            if present {
                bits.push(bit);
            }
        };
        add(self.supported.is_some(), FATTR4_SUPPORTED_ATTRS);
        add(self.ftype.is_some(), FATTR4_TYPE);
        add(self.change.is_some(), FATTR4_CHANGE);
        add(self.size.is_some(), FATTR4_SIZE);
        add(self.fsid.is_some(), FATTR4_FSID);
        add(self.lease_time.is_some(), FATTR4_LEASE_TIME);
        add(self.rdattr_error.is_some(), FATTR4_RDATTR_ERROR);
        add(self.acl.is_some(), FATTR4_ACL);
        add(self.filehandle.is_some(), FATTR4_FILEHANDLE);
        add(self.fileid.is_some(), FATTR4_FILEID);
        add(self.maxread.is_some(), FATTR4_MAXREAD);
        add(self.maxwrite.is_some(), FATTR4_MAXWRITE);
        add(self.mode.is_some(), FATTR4_MODE);
        add(self.numlinks.is_some(), FATTR4_NUMLINKS);
        add(self.owner.is_some(), FATTR4_OWNER);
        add(self.owner_group.is_some(), FATTR4_OWNER_GROUP);
        add(self.rawdev.is_some(), FATTR4_RAWDEV);
        add(self.space_used.is_some(), FATTR4_SPACE_USED);
        add(self.time_access.is_some(), FATTR4_TIME_ACCESS);
        add(self.time_access_set.is_some(), FATTR4_TIME_ACCESS_SET);
        add(self.time_metadata.is_some(), FATTR4_TIME_METADATA);
        add(self.time_modify.is_some(), FATTR4_TIME_MODIFY);
        add(self.time_modify_set.is_some(), FATTR4_TIME_MODIFY_SET);
        bitmap_of(&bits)
    }

    /// Only the fields `want` names, for a reply to a request bitmap.
    pub fn restricted_to(&self, want: &[u32]) -> Attrs {
        let mut a = self.clone();
        macro_rules! keep {
            ($f:ident, $bit:expr) => {
                if !bit_set(want, $bit) {
                    a.$f = None;
                }
            };
        }
        keep!(supported, FATTR4_SUPPORTED_ATTRS);
        keep!(ftype, FATTR4_TYPE);
        keep!(change, FATTR4_CHANGE);
        keep!(size, FATTR4_SIZE);
        keep!(fsid, FATTR4_FSID);
        keep!(lease_time, FATTR4_LEASE_TIME);
        keep!(rdattr_error, FATTR4_RDATTR_ERROR);
        keep!(acl, FATTR4_ACL);
        keep!(filehandle, FATTR4_FILEHANDLE);
        keep!(fileid, FATTR4_FILEID);
        keep!(maxread, FATTR4_MAXREAD);
        keep!(maxwrite, FATTR4_MAXWRITE);
        keep!(mode, FATTR4_MODE);
        keep!(numlinks, FATTR4_NUMLINKS);
        keep!(owner, FATTR4_OWNER);
        keep!(owner_group, FATTR4_OWNER_GROUP);
        keep!(rawdev, FATTR4_RAWDEV);
        keep!(space_used, FATTR4_SPACE_USED);
        keep!(time_access, FATTR4_TIME_ACCESS);
        keep!(time_access_set, FATTR4_TIME_ACCESS_SET);
        keep!(time_metadata, FATTR4_TIME_METADATA);
        keep!(time_modify, FATTR4_TIME_MODIFY);
        keep!(time_modify_set, FATTR4_TIME_MODIFY_SET);
        a
    }

    /// A whole `fattr4`: bitmap, then the values in attribute order.
    pub fn encode(&self, e: &mut Encoder) {
        let bits = self.bitmap();
        encode_bitmap(e, &bits);
        let mut v = Encoder::new();
        if let Some(s) = &self.supported {
            encode_bitmap(&mut v, s);
        }
        if let Some(t) = self.ftype {
            v.u32(t);
        }
        if let Some(c) = self.change {
            v.u64(c);
        }
        if let Some(s) = self.size {
            v.u64(s);
        }
        if let Some((a, b)) = self.fsid {
            v.u64(a).u64(b);
        }
        if let Some(l) = self.lease_time {
            v.u32(l);
        }
        if let Some(r) = self.rdattr_error {
            v.u32(r);
        }
        if let Some(a) = &self.acl {
            v.fixed(a);
        }
        if let Some(f) = &self.filehandle {
            v.opaque(f);
        }
        if let Some(i) = self.fileid {
            v.u64(i);
        }
        if let Some(m) = self.maxread {
            v.u64(m);
        }
        if let Some(m) = self.maxwrite {
            v.u64(m);
        }
        if let Some(m) = self.mode {
            v.u32(m);
        }
        if let Some(n) = self.numlinks {
            v.u32(n);
        }
        if let Some(o) = &self.owner {
            v.string(o);
        }
        if let Some(g) = &self.owner_group {
            v.string(g);
        }
        if let Some((a, b)) = self.rawdev {
            v.u32(a).u32(b);
        }
        if let Some(s) = self.space_used {
            v.u64(s);
        }
        if let Some(t) = &self.time_access {
            t.encode(&mut v);
        }
        if let Some(t) = &self.time_access_set {
            encode_settime(&mut v, t);
        }
        if let Some(t) = &self.time_metadata {
            t.encode(&mut v);
        }
        if let Some(t) = &self.time_modify {
            t.encode(&mut v);
        }
        if let Some(t) = &self.time_modify_set {
            encode_settime(&mut v, t);
        }
        e.opaque(&v.into_bytes());
    }

    /// Decodes a `fattr4` whose bitmap has already been read.
    pub fn decode_values(bits: &[u32], vals: &[u8]) -> io::Result<Attrs> {
        let mut d = Decoder::new(vals);
        let mut a = Attrs::default();
        for word in 0..bits.len() {
            for i in 0..32 {
                if bits[word] & (1 << i) == 0 {
                    continue;
                }
                let bit = word as u32 * 32 + i;
                match bit {
                    FATTR4_SUPPORTED_ATTRS => a.supported = Some(decode_bitmap(&mut d)?),
                    FATTR4_TYPE => a.ftype = Some(d.u32()?),
                    FATTR4_CHANGE => a.change = Some(d.u64()?),
                    FATTR4_SIZE => a.size = Some(d.u64()?),
                    FATTR4_FSID => a.fsid = Some((d.u64()?, d.u64()?)),
                    FATTR4_LEASE_TIME => a.lease_time = Some(d.u32()?),
                    FATTR4_RDATTR_ERROR => a.rdattr_error = Some(d.u32()?),
                    FATTR4_ACL => {
                        // the ACL is the rest of the values only when it is the last
                        // attribute asked for; decode its own length instead
                        let start = vals.len() - d.remaining();
                        let n = d.u32()?;
                        for _ in 0..n {
                            d.u32()?;
                            d.u32()?;
                            d.u32()?;
                            d.opaque()?;
                        }
                        let end = vals.len() - d.remaining();
                        a.acl = Some(vals[start..end].to_vec());
                    }
                    FATTR4_FILEHANDLE => a.filehandle = Some(d.opaque()?.to_vec()),
                    FATTR4_FILEID => a.fileid = Some(d.u64()?),
                    FATTR4_MAXREAD => a.maxread = Some(d.u64()?),
                    FATTR4_MAXWRITE => a.maxwrite = Some(d.u64()?),
                    FATTR4_MODE => a.mode = Some(d.u32()?),
                    FATTR4_NUMLINKS => a.numlinks = Some(d.u32()?),
                    FATTR4_OWNER => a.owner = Some(d.string()?),
                    FATTR4_OWNER_GROUP => a.owner_group = Some(d.string()?),
                    FATTR4_RAWDEV => a.rawdev = Some((d.u32()?, d.u32()?)),
                    FATTR4_SPACE_USED => a.space_used = Some(d.u64()?),
                    FATTR4_TIME_ACCESS => a.time_access = Some(Time4::decode(&mut d)?),
                    FATTR4_TIME_ACCESS_SET => a.time_access_set = Some(decode_settime(&mut d)?),
                    FATTR4_TIME_METADATA => a.time_metadata = Some(Time4::decode(&mut d)?),
                    FATTR4_TIME_MODIFY => a.time_modify = Some(Time4::decode(&mut d)?),
                    FATTR4_TIME_MODIFY_SET => a.time_modify_set = Some(decode_settime(&mut d)?),
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("attribute {other} in a fattr4 cannot be decoded here"),
                        ))
                    }
                }
            }
        }
        Ok(a)
    }

    pub fn decode(d: &mut Decoder<'_>) -> io::Result<Attrs> {
        let bits = decode_bitmap(d)?;
        let vals = d.opaque()?;
        Attrs::decode_values(&bits, vals)
    }
}

/// The attributes a listing or a stat asks for: everything an `Item` is made of, the
/// handle, and the per-entry error attribute so a bad entry does not fail a READDIR.
pub fn item_attr_bits() -> Vec<u32> {
    bitmap_of(&[
        FATTR4_TYPE,
        FATTR4_SIZE,
        FATTR4_FSID,
        FATTR4_RDATTR_ERROR,
        FATTR4_FILEHANDLE,
        FATTR4_FILEID,
        FATTR4_MODE,
        FATTR4_NUMLINKS,
        FATTR4_OWNER,
        FATTR4_OWNER_GROUP,
        FATTR4_RAWDEV,
        FATTR4_SPACE_USED,
        FATTR4_TIME_ACCESS,
        FATTR4_TIME_MODIFY,
    ])
}

/// Share access and deny for OPEN.
pub const OPEN4_SHARE_ACCESS_READ: u32 = 1;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 2;
pub const OPEN4_NOCREATE: u32 = 0;
pub const OPEN4_CREATE: u32 = 1;
pub const UNCHECKED4: u32 = 0;
pub const GUARDED4: u32 = 1;
pub const EXCLUSIVE4: u32 = 2;
pub const CLAIM_NULL: u32 = 0;
pub const OPEN4_RESULT_CONFIRM: u32 = 2;
pub const OPEN_DELEGATE_NONE: u32 = 0;
pub const OPEN_DELEGATE_READ: u32 = 1;
pub const OPEN_DELEGATE_WRITE: u32 = 2;
pub const UNSTABLE4: u32 = 0;
pub const FILE_SYNC4: u32 = 2;

/// One COMPOUND under construction: an empty tag, minor version 0, then the operations.
///
/// `Clone` so a caller can send the SAME compound again: `NFS4ERR_DELAY` and
/// `NFS4ERR_GRACE` mean "ask again shortly", and a retry has to be the identical request.
#[derive(Clone)]
pub struct Compound {
    e: Encoder,
    count: u32,
    count_at: usize,
}

impl Default for Compound {
    fn default() -> Self {
        Self::new()
    }
}

impl Compound {
    pub fn new() -> Compound {
        let mut e = Encoder::new();
        e.opaque(&[]).u32(0);
        let count_at = e.buf.len();
        e.u32(0);
        Compound {
            e,
            count: 0,
            count_at,
        }
    }
    fn op(&mut self, op: u32) -> &mut Encoder {
        self.count += 1;
        self.e.u32(op);
        &mut self.e
    }
    pub fn putrootfh(&mut self) -> &mut Self {
        self.op(OP_PUTROOTFH);
        self
    }
    pub fn putfh(&mut self, fh: &[u8]) -> &mut Self {
        self.op(OP_PUTFH).opaque(fh);
        self
    }
    pub fn getfh(&mut self) -> &mut Self {
        self.op(OP_GETFH);
        self
    }
    pub fn savefh(&mut self) -> &mut Self {
        self.op(OP_SAVEFH);
        self
    }
    pub fn restorefh(&mut self) -> &mut Self {
        self.op(OP_RESTOREFH);
        self
    }
    pub fn lookup(&mut self, name: &str) -> &mut Self {
        self.op(OP_LOOKUP).string(name);
        self
    }
    pub fn lookupp(&mut self) -> &mut Self {
        self.op(OP_LOOKUPP);
        self
    }
    pub fn getattr(&mut self, bits: &[u32]) -> &mut Self {
        let e = self.op(OP_GETATTR);
        encode_bitmap(e, bits);
        self
    }
    /// GETATTR asking for the ACL alone.
    pub fn getattr_acl(&mut self) -> &mut Self {
        self.getattr(&bitmap_of(&[FATTR4_ACL]))
    }
    pub fn setattr(&mut self, stateid: &Stateid, attrs: &Attrs) -> &mut Self {
        let e = self.op(OP_SETATTR);
        stateid.encode(e);
        attrs.encode(e);
        self
    }
    /// SETATTR of the ACL alone, with the anonymous stateid (all zeros), which is what a
    /// non-size attribute takes.
    pub fn setattr_acl(&mut self, acl: &[u8]) -> &mut Self {
        let attrs = Attrs {
            acl: Some(acl.to_vec()),
            ..Default::default()
        };
        self.setattr(&Stateid::ANONYMOUS, &attrs)
    }
    pub fn access(&mut self, mask: u32) -> &mut Self {
        self.op(OP_ACCESS).u32(mask);
        self
    }
    pub fn readlink(&mut self) -> &mut Self {
        self.op(OP_READLINK);
        self
    }
    pub fn readdir(
        &mut self,
        cookie: u64,
        verf: &[u8; 8],
        dircount: u32,
        maxcount: u32,
        bits: &[u32],
    ) -> &mut Self {
        let e = self.op(OP_READDIR);
        e.u64(cookie).fixed(verf).u32(dircount).u32(maxcount);
        encode_bitmap(e, bits);
        self
    }
    pub fn create_dir(&mut self, name: &str, attrs: &Attrs) -> &mut Self {
        let e = self.op(OP_CREATE);
        e.u32(NF4DIR).string(name);
        attrs.encode(e);
        self
    }
    pub fn create_symlink(&mut self, name: &str, target: &str, attrs: &Attrs) -> &mut Self {
        let e = self.op(OP_CREATE);
        e.u32(NF4LNK).string(target).string(name);
        attrs.encode(e);
        self
    }
    pub fn remove(&mut self, name: &str) -> &mut Self {
        self.op(OP_REMOVE).string(name);
        self
    }
    /// RENAME from the saved handle's directory to the current one.
    pub fn rename(&mut self, old: &str, new: &str) -> &mut Self {
        self.op(OP_RENAME).string(old).string(new);
        self
    }
    /// LINK the saved handle's file into the current directory.
    pub fn link(&mut self, name: &str) -> &mut Self {
        self.op(OP_LINK).string(name);
        self
    }
    /// OPEN with CLAIM_NULL in the current directory; `create` carries the mode of a new file.
    pub fn open(
        &mut self,
        seqid: u32,
        access: u32,
        clientid: u64,
        owner: &[u8],
        name: &str,
        create: Option<&Attrs>,
    ) -> &mut Self {
        let e = self.op(OP_OPEN);
        e.u32(seqid).u32(access).u32(0).u64(clientid).opaque(owner);
        match create {
            Some(attrs) => {
                e.u32(OPEN4_CREATE).u32(UNCHECKED4);
                attrs.encode(e);
            }
            None => {
                e.u32(OPEN4_NOCREATE);
            }
        }
        e.u32(CLAIM_NULL).string(name);
        self
    }
    pub fn open_confirm(&mut self, stateid: &Stateid, seqid: u32) -> &mut Self {
        let e = self.op(OP_OPEN_CONFIRM);
        stateid.encode(e);
        e.u32(seqid);
        self
    }
    pub fn close(&mut self, seqid: u32, stateid: &Stateid) -> &mut Self {
        let e = self.op(OP_CLOSE);
        e.u32(seqid);
        stateid.encode(e);
        self
    }
    pub fn delegreturn(&mut self, stateid: &Stateid) -> &mut Self {
        let e = self.op(OP_DELEGRETURN);
        stateid.encode(e);
        self
    }
    pub fn read(&mut self, stateid: &Stateid, offset: u64, count: u32) -> &mut Self {
        let e = self.op(OP_READ);
        stateid.encode(e);
        e.u64(offset).u32(count);
        self
    }
    pub fn write(&mut self, stateid: &Stateid, offset: u64, stable: u32, data: &[u8]) -> &mut Self {
        let e = self.op(OP_WRITE);
        stateid.encode(e);
        e.u64(offset).u32(stable).opaque(data);
        self
    }
    pub fn commit(&mut self, offset: u64, count: u32) -> &mut Self {
        self.op(OP_COMMIT).u64(offset).u32(count);
        self
    }
    pub fn renew(&mut self, clientid: u64) -> &mut Self {
        self.op(OP_RENEW).u64(clientid);
        self
    }
    /// SETCLIENTID with a callback the server cannot reach, so no delegations are offered.
    pub fn setclientid(&mut self, verifier: &[u8; 8], id: &[u8]) -> &mut Self {
        let e = self.op(OP_SETCLIENTID);
        e.fixed(verifier)
            .opaque(id)
            .u32(0x4000_0000)
            .string("tcp")
            .string("0.0.0.0.0.0")
            .u32(0);
        self
    }
    pub fn setclientid_confirm(&mut self, clientid: u64, verifier: &[u8; 8]) -> &mut Self {
        self.op(OP_SETCLIENTID_CONFIRM)
            .u64(clientid)
            .fixed(verifier);
        self
    }
    pub fn into_bytes(mut self) -> Vec<u8> {
        let n = self.count.to_be_bytes();
        self.e.buf[self.count_at..self.count_at + 4].copy_from_slice(&n);
        self.e.into_bytes()
    }
}

/// One directory entry from READDIR.
#[derive(Debug, Clone, PartialEq)]
pub struct DirEntry4 {
    pub cookie: u64,
    pub name: String,
    pub attrs: Attrs,
}

/// One operation's result out of a COMPOUND reply.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OpResult {
    pub op: u32,
    pub status: u32,
    /// GETFH's handle.
    pub fh: Option<Vec<u8>>,
    /// GETATTR's attribute values when the ACL bit came back set (the raw ACL).
    pub attrs: Option<Vec<u8>>,
    /// GETATTR's decoded attributes.
    pub decoded: Option<Attrs>,
    /// OPEN, OPEN_CONFIRM and CLOSE: the resulting stateid.
    pub stateid: Option<Stateid>,
    /// OPEN: the result flags and a delegation to return, if one was pressed on us.
    pub rflags: u32,
    pub delegation: Option<Stateid>,
    /// READ and READLINK: the bytes; READ: whether the end was reached.
    pub data: Option<Vec<u8>>,
    pub eof: bool,
    /// WRITE: the count and stability; WRITE and COMMIT: the verifier.
    pub count: u32,
    pub committed: u32,
    pub verifier: [u8; 8],
    /// READDIR: the entries, the cookie verifier, and whether the end was reached.
    pub entries: Vec<DirEntry4>,
    pub cookieverf: [u8; 8],
    /// SETCLIENTID: the client id and its confirmation verifier.
    pub clientid: u64,
}

fn decode_change_info(d: &mut Decoder<'_>) -> io::Result<()> {
    d.bool()?;
    d.u64()?;
    d.u64()?;
    Ok(())
}

fn decode_ace(d: &mut Decoder<'_>) -> io::Result<()> {
    d.u32()?;
    d.u32()?;
    d.u32()?;
    d.opaque()?;
    Ok(())
}

/// The overall status and every operation's result; the server stops at the first
/// failing operation, so the list may be shorter than what was sent.
pub fn decode_compound(reply: &[u8]) -> io::Result<(u32, Vec<OpResult>)> {
    let mut d = Decoder::new(reply);
    let status = d.u32()?;
    d.opaque()?; // tag
    let n = d.u32()?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let op = d.u32()?;
        let st = d.u32()?;
        let mut r = OpResult {
            op,
            status: st,
            ..Default::default()
        };
        if st == NFS4_OK {
            match op {
                OP_GETFH => r.fh = Some(d.opaque()?.to_vec()),
                OP_GETATTR => {
                    let bits = decode_bitmap(&mut d)?;
                    let vals = d.opaque()?;
                    if bits.first().is_some_and(|w| w & (1 << FATTR4_ACL) != 0)
                        && bits.iter().enumerate().all(|(i, w)| {
                            if i == 0 {
                                w & !(1 << FATTR4_ACL) == 0
                            } else {
                                *w == 0
                            }
                        })
                    {
                        r.attrs = Some(vals.to_vec());
                    }
                    r.decoded = Some(Attrs::decode_values(&bits, vals)?);
                }
                OP_SETATTR => {
                    decode_bitmap(&mut d)?;
                }
                OP_OPEN => {
                    r.stateid = Some(Stateid::decode(&mut d)?);
                    decode_change_info(&mut d)?;
                    r.rflags = d.u32()?;
                    decode_bitmap(&mut d)?;
                    match d.u32()? {
                        OPEN_DELEGATE_NONE => {}
                        OPEN_DELEGATE_READ => {
                            r.delegation = Some(Stateid::decode(&mut d)?);
                            d.bool()?;
                            decode_ace(&mut d)?;
                        }
                        OPEN_DELEGATE_WRITE => {
                            r.delegation = Some(Stateid::decode(&mut d)?);
                            d.bool()?;
                            match d.u32()? {
                                1 => {
                                    d.u64()?;
                                }
                                _ => {
                                    d.u32()?;
                                    d.u32()?;
                                }
                            }
                            decode_ace(&mut d)?;
                        }
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("delegation type {other}"),
                            ))
                        }
                    }
                }
                OP_OPEN_CONFIRM | OP_CLOSE => r.stateid = Some(Stateid::decode(&mut d)?),
                OP_READ => {
                    r.eof = d.bool()?;
                    r.data = Some(d.opaque()?.to_vec());
                }
                OP_READLINK => r.data = Some(d.opaque()?.to_vec()),
                OP_WRITE => {
                    r.count = d.u32()?;
                    r.committed = d.u32()?;
                    r.verifier = d.fixed(8)?.try_into().expect("8 bytes");
                }
                OP_COMMIT => r.verifier = d.fixed(8)?.try_into().expect("8 bytes"),
                OP_READDIR => {
                    r.cookieverf = d.fixed(8)?.try_into().expect("8 bytes");
                    while d.bool()? {
                        let cookie = d.u64()?;
                        let name = d.string()?;
                        let attrs = Attrs::decode(&mut d)?;
                        r.entries.push(DirEntry4 {
                            cookie,
                            name,
                            attrs,
                        });
                    }
                    r.eof = d.bool()?;
                }
                OP_CREATE => {
                    decode_change_info(&mut d)?;
                    decode_bitmap(&mut d)?;
                }
                OP_REMOVE | OP_LINK => decode_change_info(&mut d)?,
                OP_RENAME => {
                    decode_change_info(&mut d)?;
                    decode_change_info(&mut d)?;
                }
                OP_ACCESS => {
                    d.u32()?;
                    d.u32()?;
                }
                OP_SETCLIENTID => {
                    r.clientid = d.u64()?;
                    r.verifier = d.fixed(8)?.try_into().expect("8 bytes");
                }
                _ => {}
            }
        } else {
            match op {
                OP_SETATTR => {
                    decode_bitmap(&mut d)?; // attrsset, present whatever the status
                }
                OP_SETCLIENTID if st == 10017 => {
                    // NFS4ERR_CLID_INUSE carries the other client's address
                    d.string()?;
                    d.string()?;
                }
                _ => {}
            }
        }
        out.push(r);
    }
    Ok((status, out))
}

/// An ACL as the attribute carries it: a count, then `(type, flag, access mask, who)` per
/// entry. This is also the layout of the kernel's `system.nfs4_acl`.
pub fn encode_aces(aces: &[(u32, u32, u32, &str)]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u32(aces.len() as u32);
    for (t, f, m, who) in aces {
        e.u32(*t).u32(*f).u32(*m).string(who);
    }
    e.into_bytes()
}

pub fn decode_aces(bytes: &[u8]) -> io::Result<Vec<(u32, u32, u32, String)>> {
    let mut d = Decoder::new(bytes);
    let n = d.u32()?;
    if n > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACL with too many entries",
        ));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        out.push((d.u32()?, d.u32()?, d.u32()?, d.string()?));
    }
    if d.remaining() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing bytes after the ACL",
        ));
    }
    Ok(out)
}

/// Access mask bits used when a stand-in server derives an ACL from mode bits.
pub const ACE4_READ_DATA: u32 = 0x1;
pub const ACE4_WRITE_DATA: u32 = 0x2;
pub const ACE4_APPEND_DATA: u32 = 0x4;
pub const ACE4_READ_NAMED_ATTRS: u32 = 0x8;
pub const ACE4_WRITE_NAMED_ATTRS: u32 = 0x10;
pub const ACE4_EXECUTE: u32 = 0x20;
pub const ACE4_DELETE_CHILD: u32 = 0x40;
pub const ACE4_READ_ATTRIBUTES: u32 = 0x80;
pub const ACE4_WRITE_ATTRIBUTES: u32 = 0x100;
pub const ACE4_READ_ACL: u32 = 0x20000;
pub const ACE4_WRITE_ACL: u32 = 0x40000;
pub const ACE4_WRITE_OWNER: u32 = 0x80000;
pub const ACE4_SYNCHRONIZE: u32 = 0x100000;

/// The ACL a server answers for an object with none of its own: the mode bits as three
/// ALLOW entries for OWNER@, GROUP@ and EVERYONE@.
pub fn aces_from_mode(mode: u32, dir: bool) -> Vec<u8> {
    let of = |bits: u32, owner: bool| {
        let mut m = ACE4_READ_ATTRIBUTES | ACE4_READ_ACL | ACE4_SYNCHRONIZE;
        if bits & 4 != 0 {
            m |= ACE4_READ_DATA | ACE4_READ_NAMED_ATTRS;
        }
        if bits & 2 != 0 {
            m |=
                ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_WRITE_NAMED_ATTRS | ACE4_WRITE_ATTRIBUTES;
            if dir {
                m |= ACE4_DELETE_CHILD;
            }
        }
        if bits & 1 != 0 {
            m |= ACE4_EXECUTE;
        }
        if owner {
            m |= ACE4_WRITE_ACL | ACE4_WRITE_OWNER | ACE4_WRITE_ATTRIBUTES;
        }
        m
    };
    encode_aces(&[
        (0, 0, of((mode >> 6) & 7, true), "OWNER@"),
        (0, 0x40, of((mode >> 3) & 7, false), "GROUP@"),
        (0, 0, of(mode & 7, false), "EVERYONE@"),
    ])
}

/// The v4 side of one export for `-acl4`: the pool it shares with the v3 client (a server
/// serves both versions on one port) and the v4 handles of the directories seen so far.
pub struct V4 {
    pool: Arc<Pool>,
    /// The path inside the export the tree is rooted at, walked lazily: it may not exist
    /// yet when the v3 side is about to create it.
    sub: Vec<String>,
    dirs: Mutex<BTreeMap<String, Vec<u8>>>,
}

/// The cache key of the export's own handle (no relative path is empty).
const EXPORT_KEY: &str = "";

pub(super) fn call(pool: &Pool, c: Compound) -> io::Result<(u32, Vec<OpResult>)> {
    let reply =
        pool.with(|conn| conn.call(NFS_PROG, NFS4_VERS, NFSPROC4_COMPOUND, &c.into_bytes()))?;
    decode_compound(&reply)
}

fn split(rel: &str) -> (String, String) {
    match rel.rsplit_once('/') {
        Some((parent, name)) => (parent.to_string(), name.to_string()),
        None => (".".to_string(), rel.to_string()),
    }
}

impl V4 {
    /// Walks from the server's root to `export` over v4 and keeps that handle; `sub` is
    /// walked on first use. An error names what the server lacks: no v4 at all, or no such
    /// export in its v4 namespace.
    pub fn connect(pool: Arc<Pool>, export: &str, sub: &std::path::Path) -> io::Result<V4> {
        let mut c = Compound::new();
        c.putrootfh();
        for comp in export.split('/').filter(|s| !s.is_empty() && *s != ".") {
            c.lookup(comp);
        }
        c.getfh();
        let (status, ops) =
            call(&pool, c).map_err(|e| io::Error::new(e.kind(), format!("NFSv4: {e}")))?;
        if status != NFS4_OK {
            return Err(status_error(status, "NFSv4 walk to the export"));
        }
        let fh = ops.last().and_then(|o| o.fh.clone()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "NFSv4: no handle in the COMPOUND reply",
            )
        })?;
        let sub = sub
            .components()
            .filter_map(|c| {
                if let std::path::Component::Normal(n) = c {
                    Some(n.to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .collect();
        let dirs = Mutex::new(BTreeMap::from([(EXPORT_KEY.to_string(), fh)]));
        Ok(V4 { pool, sub, dirs })
    }

    fn walk(&self, from: &[u8], names: &[String], what: &str) -> io::Result<Vec<u8>> {
        let mut c = Compound::new();
        c.putfh(from);
        for n in names {
            c.lookup(n);
        }
        c.getfh();
        let (status, ops) = call(&self.pool, c)?;
        if status != NFS4_OK {
            return Err(status_error(status, &format!("{what}: LOOKUP")));
        }
        ops.last().and_then(|o| o.fh.clone()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: no handle in the COMPOUND reply"),
            )
        })
    }

    fn dir_fh(&self, rel: &str) -> io::Result<Vec<u8>> {
        if let Some(fh) = self.dirs.lock().unwrap().get(rel) {
            return Ok(fh.clone());
        }
        let fh = if rel == "." {
            let export = self
                .dirs
                .lock()
                .unwrap()
                .get(EXPORT_KEY)
                .cloned()
                .expect("the export handle is cached at connect");
            self.walk(&export, &self.sub, &self.sub.join("/"))?
        } else {
            let (parent, name) = split(rel);
            let pfh = self.dir_fh(&parent)?;
            self.walk(&pfh, std::slice::from_ref(&name), rel)?
        };
        self.dirs
            .lock()
            .unwrap()
            .insert(rel.to_string(), fh.clone());
        Ok(fh)
    }

    /// Forgets cached handles under `rel` (a removed or replaced directory).
    pub fn forget(&self, rel: &str) {
        let mut d = self.dirs.lock().unwrap();
        let prefix = format!("{rel}/");
        d.retain(|k, _| k == EXPORT_KEY || (k != rel && !k.starts_with(&prefix)));
    }

    fn target(&self, rel: &str, c: &mut Compound) -> io::Result<()> {
        if rel == "." {
            c.putfh(&self.dir_fh(".")?);
        } else {
            let (parent, name) = split(rel);
            c.putfh(&self.dir_fh(&parent)?).lookup(&name);
        }
        Ok(())
    }

    /// The ACL attribute of `rel`, `None` when the server does not carry ACLs there.
    pub fn get_acl(&self, rel: &str) -> io::Result<Option<Vec<u8>>> {
        let mut c = Compound::new();
        self.target(rel, &mut c)?;
        c.getattr_acl();
        let (status, ops) = call(&self.pool, c)?;
        match status {
            NFS4_OK => Ok(ops.last().and_then(|o| o.attrs.clone())),
            NFS4ERR_ATTRNOTSUPP | NFS4ERR_NOTSUPP => Ok(None),
            s => Err(status_error(s, &format!("{rel}: GETATTR acl"))),
        }
    }

    pub fn set_acl(&self, rel: &str, acl: &[u8]) -> io::Result<()> {
        let mut c = Compound::new();
        self.target(rel, &mut c)?;
        c.setattr_acl(acl);
        let (status, _) = call(&self.pool, c)?;
        if status != NFS4_OK {
            return Err(status_error(status, &format!("{rel}: SETATTR acl")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_known_by_its_status_not_its_text() {
        // the status survives as a number, with the message unchanged
        let e = status_error(NFS4ERR_SYMLINK, "a/b: OPEN");
        assert_eq!(status_in(&e), Some(NFS4ERR_SYMLINK));
        assert!(e.to_string().contains("is a symlink"), "{e}");
        // a name that spells the refusal is not the refusal
        let e = status_error(
            NFS4ERR_GRACE,
            "is a symlink, which OPEN does not follow: OPEN",
        );
        assert_eq!(status_in(&e), Some(NFS4ERR_GRACE));
        // an error nothing here made carries no status at all
        assert_eq!(
            status_in(&io::Error::new(
                io::ErrorKind::InvalidInput,
                "is a symlink, which OPEN does not follow"
            )),
            None
        );
    }

    #[test]
    fn compounds_encode_with_their_count_and_decode_per_operation() {
        let mut c = Compound::new();
        c.putrootfh().lookup("export").getfh().getattr_acl();
        let bytes = c.into_bytes();
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.opaque().unwrap(), b"");
        assert_eq!(d.u32().unwrap(), 0); // minor version
        assert_eq!(d.u32().unwrap(), 4); // four operations
        assert_eq!(d.u32().unwrap(), OP_PUTROOTFH);
        assert_eq!(d.u32().unwrap(), OP_LOOKUP);
        assert_eq!(d.string().unwrap(), "export");
        assert_eq!(d.u32().unwrap(), OP_GETFH);
        assert_eq!(d.u32().unwrap(), OP_GETATTR);
        assert_eq!(d.u32().unwrap(), 1);
        assert_eq!(d.u32().unwrap(), 1 << FATTR4_ACL);
        assert_eq!(d.remaining(), 0);

        // a reply: PUTROOTFH ok, LOOKUP ok, GETFH ok with a handle, GETATTR ok with an ACL
        let acl = encode_aces(&[(0, 0, 0x1601ff, "OWNER@")]);
        let mut e = Encoder::new();
        e.u32(NFS4_OK).opaque(&[]).u32(4);
        e.u32(OP_PUTROOTFH).u32(NFS4_OK);
        e.u32(OP_LOOKUP).u32(NFS4_OK);
        e.u32(OP_GETFH).u32(NFS4_OK).opaque(&[9, 9, 9, 9]);
        e.u32(OP_GETATTR)
            .u32(NFS4_OK)
            .u32(1)
            .u32(1 << FATTR4_ACL)
            .opaque(&acl);
        let (status, ops) = decode_compound(&e.into_bytes()).unwrap();
        assert_eq!(status, NFS4_OK);
        assert_eq!(ops[2].fh.as_deref(), Some(&[9u8, 9, 9, 9][..]));
        assert_eq!(ops[3].attrs.as_deref(), Some(&acl[..]));
        assert_eq!(
            ops[3].decoded.as_ref().unwrap().acl.as_deref(),
            Some(&acl[..])
        );
        // a GETATTR whose bitmap omits the ACL carries no attribute, and a failed
        // SETATTR still carries its attrsset bitmap
        let mut e = Encoder::new();
        e.u32(NFS4ERR_ATTRNOTSUPP).opaque(&[]).u32(2);
        e.u32(OP_GETATTR).u32(NFS4_OK).u32(1).u32(0).opaque(&[]);
        e.u32(OP_SETATTR).u32(NFS4ERR_ATTRNOTSUPP).u32(0);
        let (status, ops) = decode_compound(&e.into_bytes()).unwrap();
        assert_eq!(status, NFS4ERR_ATTRNOTSUPP);
        assert_eq!(ops[0].attrs, None);
        assert_eq!(ops[1].status, NFS4ERR_ATTRNOTSUPP);
        assert_eq!(
            status_error(NFS4ERR_ATTRNOTSUPP, "x").kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn attributes_round_trip_in_bitmap_order() {
        let a = Attrs {
            ftype: Some(NF4REG),
            size: Some(300_000),
            fsid: Some((7, 0)),
            filehandle: Some(vec![1, 2, 3]),
            fileid: Some(4242),
            mode: Some(0o640),
            numlinks: Some(2),
            owner: Some("1000".into()),
            owner_group: Some("staff@example.net".into()),
            rawdev: Some((0, 0)),
            space_used: Some(4096),
            time_access: Some(Time4 {
                seconds: 1_600_000_000,
                nseconds: 5,
            }),
            time_modify: Some(Time4 {
                seconds: 1_600_000_001,
                nseconds: 6,
            }),
            acl: Some(encode_aces(&[
                (0, 0, 0x1601ff, "OWNER@"),
                (1, 0, 2, "EVERYONE@"),
            ])),
            time_modify_set: Some(Some(Time4 {
                seconds: 1,
                nseconds: 2,
            })),
            time_access_set: Some(None),
            ..Default::default()
        };
        let mut e = Encoder::new();
        a.encode(&mut e);
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes);
        let back = Attrs::decode(&mut d).unwrap();
        assert_eq!(back, a);
        assert_eq!(d.remaining(), 0);
        // the bitmap names exactly the present fields, and restriction drops the rest
        assert_eq!(
            a.bitmap(),
            bitmap_of(&[
                FATTR4_TYPE,
                FATTR4_SIZE,
                FATTR4_FSID,
                FATTR4_ACL,
                FATTR4_FILEHANDLE,
                FATTR4_FILEID,
                FATTR4_MODE,
                FATTR4_NUMLINKS,
                FATTR4_OWNER,
                FATTR4_OWNER_GROUP,
                FATTR4_RAWDEV,
                FATTR4_SPACE_USED,
                FATTR4_TIME_ACCESS,
                FATTR4_TIME_ACCESS_SET,
                FATTR4_TIME_MODIFY,
                FATTR4_TIME_MODIFY_SET
            ])
        );
        let only = a.restricted_to(&bitmap_of(&[FATTR4_SIZE, FATTR4_OWNER]));
        assert_eq!(
            only,
            Attrs {
                size: Some(300_000),
                owner: Some("1000".into()),
                ..Default::default()
            }
        );
        assert_eq!(
            Time4::from_ns(1_600_000_000_000_000_005).ns(),
            1_600_000_000_000_000_005
        );
        assert_eq!(Time4::from_ns(-1).seconds, -1);
    }

    #[test]
    fn open_and_readdir_replies_decode() {
        let mut e = Encoder::new();
        e.u32(NFS4_OK).opaque(&[]).u32(3);
        // OPEN: stateid, change_info, rflags CONFIRM, attrset, a read delegation
        e.u32(OP_OPEN)
            .u32(NFS4_OK)
            .u32(1)
            .fixed(&[7u8; 12])
            .bool(true)
            .u64(1)
            .u64(2)
            .u32(OPEN4_RESULT_CONFIRM)
            .u32(0);
        e.u32(OPEN_DELEGATE_READ)
            .u32(9)
            .fixed(&[8u8; 12])
            .bool(false)
            .u32(0)
            .u32(0)
            .u32(0)
            .string("OWNER@");
        // READDIR: verifier, two entries, eof
        e.u32(OP_READDIR).u32(NFS4_OK).fixed(&[1u8; 8]);
        for (cookie, name) in [(3u64, "a"), (4, "b")] {
            e.bool(true).u64(cookie).string(name);
            Attrs {
                fileid: Some(cookie * 10),
                ..Default::default()
            }
            .encode(&mut e);
        }
        e.bool(false).bool(true);
        // WRITE: count, committed, verifier
        e.u32(OP_WRITE)
            .u32(NFS4_OK)
            .u32(512)
            .u32(FILE_SYNC4)
            .fixed(&[2u8; 8]);
        let (status, ops) = decode_compound(&e.into_bytes()).unwrap();
        assert_eq!(status, NFS4_OK);
        assert_eq!(
            ops[0].stateid,
            Some(Stateid {
                seqid: 1,
                other: [7; 12]
            })
        );
        assert_eq!(ops[0].rflags, OPEN4_RESULT_CONFIRM);
        assert_eq!(
            ops[0].delegation,
            Some(Stateid {
                seqid: 9,
                other: [8; 12]
            })
        );
        assert_eq!(ops[1].entries.len(), 2);
        assert_eq!(ops[1].entries[1].name, "b");
        assert_eq!(ops[1].entries[1].attrs.fileid, Some(40));
        assert!(ops[1].eof);
        assert_eq!(ops[2].count, 512);
        assert_eq!(ops[2].verifier, [2; 8]);
    }

    #[test]
    fn aces_round_trip_and_a_mode_becomes_three_entries() {
        let aces = vec![
            (0, 0, 0x1601ff, "OWNER@"),
            (1, 0x40, 0x120089, "GROUP@"),
            (0, 0, 0x1200a9, "alice@example.net"),
        ];
        let bytes = encode_aces(&aces);
        let back = decode_aces(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[2], (0, 0, 0x1200a9, "alice@example.net".to_string()));
        assert!(decode_aces(&bytes[..bytes.len() - 1]).is_err());
        let from_mode = decode_aces(&aces_from_mode(0o640, false)).unwrap();
        assert_eq!(
            from_mode.iter().map(|a| a.3.as_str()).collect::<Vec<_>>(),
            vec!["OWNER@", "GROUP@", "EVERYONE@"]
        );
        assert!(from_mode[0].2 & ACE4_WRITE_DATA != 0);
        assert!(from_mode[1].2 & ACE4_WRITE_DATA == 0);
        assert!(from_mode[2].2 & ACE4_READ_DATA == 0);
        assert!(decode_aces(&aces_from_mode(0o750, true)).unwrap()[0].2 & ACE4_DELETE_CHILD != 0);
    }
}
