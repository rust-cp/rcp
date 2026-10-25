//! The S3 adapter: `s3://bucket/prefix` endpoints reached with a small HTTP/1.1 client and
//! AWS Signature Version 4, in the standard library only. Objects map onto the tree port:
//! keys are paths, `dir/` marker objects are directories, symlinks are objects whose body is
//! the target, and POSIX metadata (`mtime`, `mode`, `uid`, `gid`) travels as user metadata in
//! the s3fs convention so a tree round-trips through a bucket and comes back with its times.
//!
//! TLS is behind the `rustls` cargo feature (rustls); the default build speaks plain HTTP, which
//! is what an on-premises MinIO or a local gateway offers, and refuses `https://` endpoints
//! with a message naming the feature.

pub mod client;
pub mod config;
pub mod sigv4;
/// In-process S3 stand-in used by the integration tests.
#[doc(hidden)]
pub mod testserver;
pub mod xml;

#[cfg(test)]
pub(crate) fn client_kind_of_status(status: u16) -> std::io::ErrorKind {
    client::kind_of_status(status)
}
