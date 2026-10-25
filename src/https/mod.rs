//! `https://` and `http://`: an ordinary web server as a read-only tree.
//!
//! The other transports here speak a protocol that has a directory listing. HTTP does not,
//! and that single fact shapes the whole adapter:
//!
//! - **It is read-only, by name.** `create_file`, `mkdir`, `remove`, `rename` and
//!   `set_metadata` refuse and say why, rather than issuing a `PUT` that some servers
//!   accept. A plain web server has no agreed way to create anything, and the one protocol
//!   that does have it is `dav://`, which is already here. Naming the refusal beats a copy
//!   that half works against one server and not another.
//! - **The listing comes from a convention, not the protocol.** Three are read --
//!   `rcp-index.json`, nginx's JSON autoindex, an Apache-style HTML page -- in that order,
//!   because they carry decreasing amounts of truth. See `index.rs`, where the choosing is
//!   done and where the traps are.
//! - **`keeps_times` is true only for `rcp-index.json`**, the one shape that carries a real
//!   mtime. For the other two the planner matches on size, exactly as it does for WebDAV,
//!   and `verify` skips the mtime comparison and says so.
//!
//! Why this exists when `curl` and `wget -r` do: neither resumes a whole tree from a
//! catalog, neither verifies against a digest the publisher stated, and `wget -r` walks an
//! autoindex page by following links, which is the trap `index.rs` is mostly about.
//!
//! The transport underneath is the same pooled HTTP connection every other adapter here
//! uses, so `Range`, proxies, TLS and the refusal to follow a redirect to another authority
//! are not reimplemented.

pub mod client;
pub mod index;
/// In-process HTTP stand-in used by the integration tests.
#[doc(hidden)]
pub mod testserver;

pub use client::HttpsTree;

/// Where an `https://` endpoint points and how to reach it.
#[derive(Clone, Default)]
pub struct Settings {
    /// `-http.user USER:PASSWORD`, or `RCP_HTTP_USER` with `RCP_HTTP_PASSWORD`.
    pub user: Option<String>,
    /// `-http.noverify`: do not verify the server's certificate. A `Transport`
    /// capability, so no MCP call can set it.
    pub noverify: bool,
    /// `-http.index NAME`: the published index to look for (default `rcp-index.json`).
    /// Naming it empty turns the index off and forces the autoindex readers, which is how
    /// an operator tests what a consumer without the index will see.
    pub index: Option<String>,
}
