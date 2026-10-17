//! SFTP version 3 on the wire (draft-ietf-secsh-filexfer-02, the dialect every
//! OpenSSH `sftp-server` speaks): packets of `u32 length, u8 type, u32 id, fields`, with
//! strings as `u32 length, bytes` (unpadded, unlike XDR) and attributes as a flag word
//! followed by the fields the flags name.

use std::io::{self, Read, Write};

pub const INIT: u8 = 1;
pub const VERSION: u8 = 2;
pub const OPEN: u8 = 3;
pub const CLOSE: u8 = 4;
pub const READ: u8 = 5;
pub const WRITE: u8 = 6;
pub const LSTAT: u8 = 7;
pub const FSTAT: u8 = 8;
pub const SETSTAT: u8 = 9;
pub const FSETSTAT: u8 = 10;
pub const OPENDIR: u8 = 11;
pub const READDIR: u8 = 12;
pub const REMOVE: u8 = 13;
pub const MKDIR: u8 = 14;
pub const RMDIR: u8 = 15;
pub const REALPATH: u8 = 16;
pub const STAT: u8 = 17;
pub const RENAME: u8 = 18;
pub const READLINK: u8 = 19;
pub const SYMLINK: u8 = 20;
pub const STATUS: u8 = 101;
pub const HANDLE: u8 = 102;
pub const DATA: u8 = 103;
pub const NAME: u8 = 104;
pub const ATTRS: u8 = 105;
pub const EXTENDED: u8 = 200;
pub const EXTENDED_REPLY: u8 = 201;

pub const FX_OK: u32 = 0;
pub const FX_EOF: u32 = 1;
pub const FX_NO_SUCH_FILE: u32 = 2;
pub const FX_PERMISSION_DENIED: u32 = 3;
pub const FX_FAILURE: u32 = 4;
pub const FX_BAD_MESSAGE: u32 = 5;
pub const FX_NO_CONNECTION: u32 = 6;
pub const FX_CONNECTION_LOST: u32 = 7;
pub const FX_OP_UNSUPPORTED: u32 = 8;

pub const PFLAG_READ: u32 = 1;
pub const PFLAG_WRITE: u32 = 2;
pub const PFLAG_CREAT: u32 = 8;
pub const PFLAG_TRUNC: u32 = 16;
/// SSH_FXF_EXCL: with CREAT, fail if the name exists -- and, as O_EXCL, without following a
/// symlink that holds the name.
pub const PFLAG_EXCL: u32 = 32;

pub const ATTR_SIZE: u32 = 1;
pub const ATTR_UIDGID: u32 = 2;
pub const ATTR_PERMISSIONS: u32 = 4;
pub const ATTR_ACMODTIME: u32 = 8;
pub const ATTR_EXTENDED: u32 = 0x8000_0000;

/// The READ or WRITE length used when the server does not say what it accepts: the 32 KiB
/// every version 3 server must take, which is also what OpenSSH's own client uses then.
pub const DEFAULT_IO: u32 = 32 << 10;
/// The most asked for in one READ or WRITE, whatever a server advertises, so a reply always
/// fits under `MAX_PACKET`.
///
/// This was the length used for every request, on the belief that it was the largest read or
/// write OpenSSH's server accepts. It is not: OpenSSH's 256 KiB limit is on the whole
/// MESSAGE, header included, so a 256 KiB WRITE is a few dozen bytes over it and the server
/// drops the connection. Every file of 256 KiB or more failed against a real OpenSSH, measured
/// against OpenSSH 10.3: 262,100 bytes crossed and 262,144 did not. The server says what it
/// takes through `limits@openssh.com` (256 KiB less 1024), and that is what is used now.
pub const IO_CEILING: u32 = 256 << 10;
/// The largest packet this side accepts.
pub const MAX_PACKET: usize = 1 << 20;

/// What a STATUS code means as an `io::ErrorKind`.
pub fn kind_of(code: u32) -> io::ErrorKind {
    match code {
        FX_NO_SUCH_FILE => io::ErrorKind::NotFound,
        FX_PERMISSION_DENIED => io::ErrorKind::PermissionDenied,
        FX_OP_UNSUPPORTED => io::ErrorKind::Unsupported,
        FX_NO_CONNECTION | FX_CONNECTION_LOST => io::ErrorKind::ConnectionAborted,
        FX_BAD_MESSAGE => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::Other,
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    pub times: Option<(u32, u32)>,
}

impl Attrs {
    pub fn encode(&self, e: &mut Enc) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if self.times.is_some() {
            flags |= ATTR_ACMODTIME;
        }
        e.u32(flags);
        if let Some(s) = self.size {
            e.u64(s);
        }
        if let Some((u, g)) = self.uid_gid {
            e.u32(u).u32(g);
        }
        if let Some(p) = self.permissions {
            e.u32(p);
        }
        if let Some((a, m)) = self.times {
            e.u32(a).u32(m);
        }
    }

    pub fn decode(d: &mut Dec<'_>) -> io::Result<Attrs> {
        let flags = d.u32()?;
        let mut a = Attrs::default();
        if flags & ATTR_SIZE != 0 {
            a.size = Some(d.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            a.uid_gid = Some((d.u32()?, d.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            a.permissions = Some(d.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            a.times = Some((d.u32()?, d.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            for _ in 0..d.u32()? {
                d.bytes()?;
                d.bytes()?;
            }
        }
        Ok(a)
    }
}

#[derive(Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Enc {
        Enc(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
        self
    }
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Dec<'a> {
        Dec { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sftp packet ends early",
            ));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    pub fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn string(&mut self) -> io::Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

/// Writes one packet: length, type, then the body (which starts with the id for every
/// type but INIT).
pub fn write_packet(w: &mut dyn Write, t: u8, body: &[u8]) -> io::Result<()> {
    w.write_all(&((body.len() + 1) as u32).to_be_bytes())?;
    w.write_all(&[t])?;
    w.write_all(body)
}

/// Reads one packet: its type and body; `None` at a clean end of stream.
pub fn read_packet(r: &mut dyn Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the sftp stream ended inside a packet header",
            ));
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sftp packet of {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let t = body[0];
    body.remove(0);
    Ok(Some((t, body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_and_packets_round_trip() {
        let a = Attrs {
            size: Some(7),
            uid_gid: Some((1, 2)),
            permissions: Some(0o100644),
            times: Some((3, 4)),
        };
        let mut e = Enc::new();
        a.encode(&mut e);
        // an extended pair after the known fields is skipped, not an error
        e.0[0..4].copy_from_slice(
            &(ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME | ATTR_EXTENDED)
                .to_be_bytes(),
        );
        e.u32(1).string("x@y").string("z");
        let bytes = e.into_bytes();
        assert_eq!(Attrs::decode(&mut Dec::new(&bytes)).unwrap(), a);
        let mut buf = Vec::new();
        let mut body = Enc::new();
        body.u32(9).string("hello");
        write_packet(&mut buf, STATUS, &body.into_bytes()).unwrap();
        let mut r = &buf[..];
        let (t, body) = read_packet(&mut r).unwrap().unwrap();
        assert_eq!(t, STATUS);
        let mut d = Dec::new(&body);
        assert_eq!(
            (d.u32().unwrap(), d.string().unwrap()),
            (9, "hello".to_string())
        );
        assert!(read_packet(&mut r).unwrap().is_none());
        // controls: a truncated packet and an empty one are errors, a short field too
        let mut r = &buf[..6];
        assert!(read_packet(&mut r).is_err());
        let zero = 0u32.to_be_bytes();
        let mut r = &zero[..];
        assert!(read_packet(&mut r).is_err());
        assert!(Dec::new(&[0, 0]).u32().is_err());
        assert_eq!(kind_of(FX_NO_SUCH_FILE), io::ErrorKind::NotFound);
        assert_eq!(kind_of(FX_OP_UNSUPPORTED), io::ErrorKind::Unsupported);
    }
}
