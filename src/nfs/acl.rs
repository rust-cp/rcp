//! The NFSACL sideband program (100227, version 3): `GETACL` and `SETACL` carry POSIX ACLs
//! beside NFSv3, which has no attribute of its own for them. Linux `nfsd` and ONTAP both
//! serve it, on the NFS port. On the local side an ACL is the `system.posix_acl_access` or
//! `system.posix_acl_default` extended attribute in the kernel's little-endian layout, so
//! this module is where the two encodings meet, and it follows the kernel's own conventions
//! for the corners: a three-entry ACL goes on the wire padded to four with a `MASK` entry
//! equal to the group entry (some servers refuse three), and a four-entry ACL whose mask
//! equals its group entry comes back as three, which is how `fs/nfs_common/nfsacl.c` treats
//! it in both directions.

use std::io;

use super::proto::{decode_post_op_attr, status_error, Fh, NFS3_OK};
use crate::xdr::{Decoder, Encoder};

pub const NFSACL_PROG: u32 = 100_227;
pub const NFSACL_VERS: u32 = 3;
pub const ACLPROC_NULL: u32 = 0;
pub const ACLPROC_GETACL: u32 = 1;
pub const ACLPROC_SETACL: u32 = 2;

/// The `mask` bits of GETACL and SETACL: which of the two ACLs the call is about.
pub const NFS_ACL: u32 = 0x0001;
pub const NFS_ACLCNT: u32 = 0x0002;
pub const NFS_DFACL: u32 = 0x0004;
pub const NFS_DFACLCNT: u32 = 0x0008;
/// ORed into the tag of every entry of a default ACL on the wire.
const NFS_ACL_DEFAULT: u32 = 0x1000;
pub const NFS_ACL_MAX_ENTRIES: u32 = 1024;

pub const ACL_USER_OBJ: u16 = 0x01;
pub const ACL_USER: u16 = 0x02;
pub const ACL_GROUP_OBJ: u16 = 0x04;
pub const ACL_GROUP: u16 = 0x08;
pub const ACL_MASK: u16 = 0x10;
pub const ACL_OTHER: u16 = 0x20;
const UNDEFINED_ID: u32 = u32::MAX;
const XATTR_VERSION: u32 = 2;

pub const ACCESS_NAME: &str = "system.posix_acl_access";
pub const DEFAULT_NAME: &str = "system.posix_acl_default";

/// Whether `name` is one of the two attributes this protocol carries.
pub fn is_acl_name(name: &str) -> bool {
    name == ACCESS_NAME || name == DEFAULT_NAME
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub tag: u16,
    pub perm: u16,
    /// A uid or gid for `ACL_USER` and `ACL_GROUP`; `u32::MAX` (undefined) otherwise.
    pub id: u32,
}

/// The kernel's xattr layout: a version word, then `(tag u16, perm u16, id u32)` per entry,
/// all little-endian.
pub fn from_xattr(bytes: &[u8]) -> io::Result<Vec<Entry>> {
    let bad = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("posix ACL attribute: {what}"),
        )
    };
    if bytes.len() < 4 || !(bytes.len() - 4).is_multiple_of(8) {
        return Err(bad("wrong length"));
    }
    if u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")) != XATTR_VERSION {
        return Err(bad("unknown version"));
    }
    let mut out = Vec::with_capacity((bytes.len() - 4) / 8);
    for chunk in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
        let perm = u16::from_le_bytes([chunk[2], chunk[3]]);
        let id = u32::from_le_bytes(chunk[4..8].try_into().expect("4 bytes"));
        if !matches!(
            tag,
            ACL_USER_OBJ | ACL_USER | ACL_GROUP_OBJ | ACL_GROUP | ACL_MASK | ACL_OTHER
        ) {
            return Err(bad("unknown entry tag"));
        }
        out.push(Entry {
            tag,
            perm: perm & 7,
            id: if matches!(tag, ACL_USER | ACL_GROUP) {
                id
            } else {
                UNDEFINED_ID
            },
        });
    }
    Ok(out)
}

pub fn to_xattr(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * 8);
    out.extend_from_slice(&XATTR_VERSION.to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        out.extend_from_slice(&e.id.to_le_bytes());
    }
    out
}

/// The order the kernel keeps entries in: by tag (`USER_OBJ`, `USER`, `GROUP_OBJ`, `GROUP`,
/// `MASK`, `OTHER`), named entries by id.
fn canonical(mut entries: Vec<Entry>) -> Vec<Entry> {
    entries.sort_by_key(|e| (e.tag, e.id));
    entries
}

/// Whether an access ACL says more than the mode bits do, which is when the kernel stores
/// it as an attribute at all: a `MASK` or a named user or group.
pub fn is_extended(entries: &[Entry]) -> bool {
    entries
        .iter()
        .any(|e| matches!(e.tag, ACL_USER | ACL_GROUP | ACL_MASK))
}

fn encode_acl(
    e: &mut Encoder,
    entries: &[Entry],
    with_entries: bool,
    default: bool,
) -> io::Result<()> {
    let count = if entries.is_empty() {
        0
    } else {
        entries.len().max(4)
    };
    if count > NFS_ACL_MAX_ENTRIES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ACL has {count} entries; the protocol carries at most {NFS_ACL_MAX_ENTRIES}"),
        ));
    }
    e.u32(count as u32);
    if !with_entries || entries.is_empty() {
        e.u32(0);
        return Ok(());
    }
    let padded: Vec<Entry> = if entries.len() == 3 {
        // the kernel's own padding: a MASK equal to the group entry, in canonical order
        let find = |tag| entries.iter().find(|x| x.tag == tag).copied();
        match (find(ACL_USER_OBJ), find(ACL_GROUP_OBJ), find(ACL_OTHER)) {
            (Some(u), Some(g), Some(o)) => vec![
                u,
                g,
                Entry {
                    tag: ACL_MASK,
                    perm: g.perm,
                    id: UNDEFINED_ID,
                },
                o,
            ],
            _ => entries.to_vec(),
        }
    } else {
        entries.to_vec()
    };
    e.u32(padded.len() as u32);
    let flag = if default { NFS_ACL_DEFAULT } else { 0 };
    for x in &padded {
        e.u32(x.tag as u32 | flag);
        e.u32(if matches!(x.tag, ACL_USER | ACL_GROUP) {
            x.id
        } else {
            0
        });
        e.u32(x.perm as u32 & 7);
    }
    Ok(())
}

fn decode_acl(d: &mut Decoder<'_>) -> io::Result<Vec<Entry>> {
    let _count = d.u32()?;
    let len = d.u32()?;
    if len > NFS_ACL_MAX_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ACL with {len} entries on the wire"),
        ));
    }
    let mut entries = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let tag = (d.u32()? & !NFS_ACL_DEFAULT) as u16;
        let id = d.u32()?;
        let perm = (d.u32()? & 7) as u16;
        if !matches!(
            tag,
            ACL_USER_OBJ | ACL_USER | ACL_GROUP_OBJ | ACL_GROUP | ACL_MASK | ACL_OTHER
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACL entry with tag {tag:#x} on the wire"),
            ));
        }
        entries.push(Entry {
            tag,
            perm,
            id: if matches!(tag, ACL_USER | ACL_GROUP) {
                id
            } else {
                UNDEFINED_ID
            },
        });
    }
    let mut entries = canonical(entries);
    // the kernel's own stripping of the padding it adds
    if entries.len() == 4 {
        let group = entries
            .iter()
            .find(|x| x.tag == ACL_GROUP_OBJ)
            .map(|x| x.perm);
        if let Some(i) = entries.iter().position(|x| x.tag == ACL_MASK) {
            if Some(entries[i].perm) == group {
                entries.remove(i);
            }
        }
    }
    Ok(entries)
}

pub fn args_getacl(fh: &Fh, mask: u32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.opaque(&fh.0).u32(mask);
    e.into_bytes()
}

/// The access and default ACLs a GETACL reply carries (either may be empty).
pub fn res_getacl(reply: &[u8]) -> io::Result<(Vec<Entry>, Vec<Entry>)> {
    let mut d = Decoder::new(reply);
    let status = d.u32()?;
    if status != NFS3_OK {
        return Err(status_error(status, "GETACL"));
    }
    decode_post_op_attr(&mut d)?;
    let _mask = d.u32()?;
    let access = decode_acl(&mut d)?;
    let default = decode_acl(&mut d)?;
    Ok((access, default))
}

/// SETACL: `mask` names which of the two ACLs to set; the other is sent empty and ignored.
pub fn args_setacl(fh: &Fh, mask: u32, access: &[Entry], default: &[Entry]) -> io::Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.opaque(&fh.0).u32(mask);
    encode_acl(&mut e, access, mask & NFS_ACL != 0, false)?;
    encode_acl(&mut e, default, mask & NFS_DFACL != 0, true)?;
    Ok(e.into_bytes())
}

pub fn res_setacl(reply: &[u8]) -> io::Result<()> {
    let mut d = Decoder::new(reply);
    let status = d.u32()?;
    if status != NFS3_OK {
        return Err(status_error(status, "SETACL"));
    }
    Ok(())
}

/// Server side of GETACL: the reply body for `access` and `default` (with the attributes
/// omitted), used by the stand-in server.
pub fn encode_getacl_reply(mask: u32, access: &[Entry], default: &[Entry]) -> io::Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.u32(NFS3_OK).bool(false).u32(mask);
    encode_acl(&mut e, access, mask & NFS_ACL != 0, false)?;
    encode_acl(&mut e, default, mask & NFS_DFACL != 0, true)?;
    Ok(e.into_bytes())
}

/// Server side of SETACL: the handle, the mask and the two ACLs as sent.
pub fn decode_setacl_args(args: &[u8]) -> io::Result<(Vec<u8>, u32, Vec<Entry>, Vec<Entry>)> {
    let mut d = Decoder::new(args);
    let fh = d.opaque()?.to_vec();
    let mask = d.u32()?;
    let access = decode_acl(&mut d)?;
    let default = decode_acl(&mut d)?;
    Ok((fh, mask, access, default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended() -> Vec<Entry> {
        vec![
            Entry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_USER,
                perm: 4,
                id: 1000,
            },
            Entry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_MASK,
                perm: 4,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_OTHER,
                perm: 0,
                id: UNDEFINED_ID,
            },
        ]
    }

    #[test]
    fn xattr_bytes_round_trip_and_reject_garbage() {
        let acl = extended();
        let bytes = to_xattr(&acl);
        assert_eq!(bytes.len(), 4 + 5 * 8);
        assert_eq!(&bytes[..4], &[2, 0, 0, 0]);
        assert_eq!(from_xattr(&bytes).unwrap(), acl);
        assert!(from_xattr(&bytes[..11]).is_err());
        assert!(from_xattr(&[1, 0, 0, 0]).is_err());
        assert!(is_extended(&acl));
        assert!(!is_extended(&[acl[0], acl[2], acl[4]]));
    }

    #[test]
    fn wire_round_trip_keeps_an_extended_acl_and_the_kernel_padding_cancels() {
        let fh = Fh(vec![7; 8]);
        let default = vec![
            Entry {
                tag: ACL_USER_OBJ,
                perm: 7,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_GROUP_OBJ,
                perm: 5,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_OTHER,
                perm: 5,
                id: UNDEFINED_ID,
            },
        ];
        let args = args_setacl(&fh, NFS_ACL | NFS_DFACL, &extended(), &default).unwrap();
        let (got_fh, mask, access, dflt) = decode_setacl_args(&args).unwrap();
        assert_eq!(got_fh, vec![7; 8]);
        assert_eq!(mask, NFS_ACL | NFS_DFACL);
        assert_eq!(access, extended());
        // three entries went out as four (the count word says so) and came back as three
        let mut d = Decoder::new(&args);
        d.opaque().unwrap();
        d.u32().unwrap();
        let access_count = d.u32().unwrap();
        assert_eq!(access_count, 5);
        assert_eq!(dflt, default);
        // a reply carries the same shapes back, and the default tags carry the flag on the wire
        let reply = encode_getacl_reply(
            NFS_ACL | NFS_ACLCNT | NFS_DFACL | NFS_DFACLCNT,
            &extended(),
            &default,
        )
        .unwrap();
        assert!(reply
            .windows(4)
            .any(|w| w == (ACL_USER_OBJ as u32 | NFS_ACL_DEFAULT).to_be_bytes()));
        assert_eq!(res_getacl(&reply).unwrap(), (extended(), default.clone()));
        // a mask-only request leaves the arrays empty but the counts present
        let reply = encode_getacl_reply(NFS_ACLCNT, &extended(), &default).unwrap();
        assert_eq!(res_getacl(&reply).unwrap(), (Vec::new(), Vec::new()));
        // a failure status is an error naming the procedure
        let mut e = Encoder::new();
        e.u32(13).bool(false);
        let err = res_getacl(&e.into_bytes()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("GETACL"));
    }

    #[test]
    fn entries_come_back_in_the_kernels_order() {
        let fh = Fh(vec![1]);
        let scrambled = vec![
            Entry {
                tag: ACL_OTHER,
                perm: 0,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_GROUP,
                perm: 4,
                id: 2000,
            },
            Entry {
                tag: ACL_USER_OBJ,
                perm: 6,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_MASK,
                perm: 6,
                id: UNDEFINED_ID,
            },
            Entry {
                tag: ACL_GROUP,
                perm: 2,
                id: 1000,
            },
            Entry {
                tag: ACL_GROUP_OBJ,
                perm: 4,
                id: UNDEFINED_ID,
            },
        ];
        let args = args_setacl(&fh, NFS_ACL, &scrambled, &[]).unwrap();
        let (_, _, access, dflt) = decode_setacl_args(&args).unwrap();
        assert_eq!(
            access.iter().map(|e| (e.tag, e.id)).collect::<Vec<_>>(),
            vec![
                (ACL_USER_OBJ, UNDEFINED_ID),
                (ACL_GROUP_OBJ, UNDEFINED_ID),
                (ACL_GROUP, 1000),
                (ACL_GROUP, 2000),
                (ACL_MASK, UNDEFINED_ID),
                (ACL_OTHER, UNDEFINED_ID)
            ]
        );
        assert!(dflt.is_empty());
    }
}
