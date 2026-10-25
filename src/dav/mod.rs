//! `dav://` and `davs://`: WebDAV endpoints (RFC 4918), the protocol behind Nextcloud,
//! ownCloud, SharePoint, Apache `mod_dav` and every "map a network drive over HTTPS" box.
//!
//! It is a filesystem drawn on HTTP, which is why it fits this crate's `Tree` port almost
//! exactly and why the two places it does NOT fit are worth naming up front:
//!
//! - **There is no `stat`.** `PROPFIND` with `Depth: 0` is the nearest thing, and it costs
//!   a request and an XML parse. The adapter uses it, but a listing already carries every
//!   property a `stat` would ask for, so the scan path never pays for one.
//! - **There are no owners, modes or hard links.** A server keeps `getlastmodified` and
//!   nothing else this crate would set, so `set_metadata` refuses the rest by name rather
//!   than pretending -- the same shape as the registry and tar adapters.
//!
//! Symlinks are absent too, and that is a real limit rather than an oversight: the protocol
//! has no representation for one.

pub mod client;
/// In-process WebDAV stand-in used by the integration tests.
#[doc(hidden)]
pub mod testserver;
pub mod xml;

pub use client::{split_url, DavTree};

/// Where a `dav://` endpoint points and how to reach it.
#[derive(Clone, Default)]
pub struct Settings {
    /// `-dav.user USER:PASSWORD`, or `RCP_DAV_USER` with `RCP_DAV_PASSWORD`.
    pub user: Option<String>,
    /// `-dav.insecure`: speak plain HTTP to a `davs://` endpoint. A `Transport`
    /// capability, so no MCP call can set it.
    pub insecure: bool,
    /// `-dav.noverify`: do not verify the server's certificate. Also `Transport`.
    pub noverify: bool,
}
