//! XDR (RFC 4506): the wire encoding under SUN RPC and NFS. Everything is big-endian and
//! padded to four bytes; that is the whole standard.

use std::io;

#[derive(Default, Clone)]
pub struct Encoder {
    pub buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            buf: Vec::with_capacity(256),
        }
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.u32(v as u32)
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u32(v as u32)
    }
    /// Variable-length opaque: length, bytes, padding.
    pub fn opaque(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self.pad();
        self
    }
    /// Fixed-length opaque: bytes, padding, no length.
    pub fn fixed(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self.pad();
        self
    }
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.opaque(s.as_bytes())
    }
    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated XDR data")
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        let b = self.data.get(self.pos..self.pos + 4).ok_or_else(short)?;
        self.pos += 4;
        Ok(u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }
    pub fn i32(&mut self) -> io::Result<i32> {
        self.u32().map(|v| v as i32)
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        let b = self.data.get(self.pos..self.pos + 8).ok_or_else(short)?;
        self.pos += 8;
        Ok(u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }
    pub fn bool(&mut self) -> io::Result<bool> {
        Ok(self.u32()? != 0)
    }
    pub fn opaque(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.fixed(n)
    }
    pub fn fixed(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let pad = (4 - n % 4) % 4;
        let padded = n.checked_add(pad).ok_or_else(short)?;
        let end = self.pos.checked_add(padded).ok_or_else(short)?;
        if end > self.data.len() {
            return Err(short());
        }
        let b = &self.data[self.pos..self.pos + n];
        self.pos = end;
        Ok(b)
    }
    pub fn string(&mut self) -> io::Result<String> {
        Ok(String::from_utf8_lossy(self.opaque()?).into_owned())
    }
    pub fn skip(&mut self, n: usize) -> io::Result<()> {
        self.fixed(n).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_padding() {
        let mut e = Encoder::new();
        e.u32(7)
            .u64(1 << 40)
            .bool(true)
            .opaque(b"abcde")
            .string("hi")
            .fixed(&[1, 2, 3]);
        let bytes = e.into_bytes();
        assert_eq!(bytes.len() % 4, 0);
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.u32().unwrap(), 7);
        assert_eq!(d.u64().unwrap(), 1 << 40);
        assert!(d.bool().unwrap());
        assert_eq!(d.opaque().unwrap(), b"abcde");
        assert_eq!(d.string().unwrap(), "hi");
        assert_eq!(d.fixed(3).unwrap(), &[1, 2, 3]);
        assert_eq!(d.remaining(), 0);
        assert!(
            d.u32().is_err(),
            "reading past the end is an error, not a panic"
        );
    }
}
