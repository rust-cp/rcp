//! A userspace NFS client, so `host:/export` endpoints need no mount and no root, and so a
//! copy can keep many requests in flight per connection instead of what one kernel mount
//! allows. Version 3 by default and NFSv4.0 with `-nfs.vers 4`; AUTH_SYS or Kerberos
//! (`-nfs.sec`); the limits are in the README.
//!
//! `xdr` and `rpc` are the transport, `proto` the NFSv3 and MOUNT wire formats, `v4` the
//! NFSv4 COMPOUND codec, `client` and `client4` the `Tree` adapters over each version, `acl`
//! the NFSACL sideband, and `testserver` a small in-process server backed by a directory
//! (all of those programs), which is how the contract suite exercises the clients without
//! privileges.

pub mod acl;
pub mod client;
pub mod client4;
pub mod proto;
pub mod rpc;
pub mod show;
pub mod testserver;
pub mod v4;

pub use client::NfsTree;
pub use client4::Nfs4Tree;

use std::fmt;
use std::sync::Arc;

use crate::ports::Log;

/// How every NFS endpoint of a run is reached: `-acl4`, `-nfs.sec`, `-nfs.vers`,
/// `-dircount`, and where its debug lines go. Built by the driving adapter and handed to
/// each tree at `connect`; nothing here is process-wide.
#[derive(Clone)]
pub struct Settings {
    /// Carry NFSv4 ACLs (`system.nfs4_acl`) through the v4 sidecar; an export whose server
    /// has no v4 is refused.
    pub acl4: bool,
    /// The security every connection is opened with.
    pub sec: rpc::Security,
    /// 3 (the default) or 4: the protocol the data moves over.
    pub vers: u32,
    /// The READDIRPLUS (v3) or READDIR (v4) request size.
    pub dircount: u32,
    pub log: Arc<dyn Log>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("acl4", &self.acl4)
            .field("sec", &self.sec.name())
            .field("vers", &self.vers)
            .field("dircount", &self.dircount)
            .finish()
    }
}

impl Settings {
    /// The environment's defaults: `RCP_NFS_SEC`, `RCP_NFS_VERS`, `RCP_NFS_ACL4`, AUTH_SYS, v3, 64 KiB.
    pub fn from_env(log: Arc<dyn Log>) -> Settings {
        Settings {
            // read from the environment like the other two, so the MCP server can relay
            // the operator's choice to a child the way it relays the security flavor
            acl4: std::env::var("RCP_NFS_ACL4").is_ok_and(|v| !v.is_empty()),
            sec: std::env::var("RCP_NFS_SEC")
                .ok()
                .and_then(|v| rpc::Security::parse(&v))
                .unwrap_or_default(),
            vers: std::env::var("RCP_NFS_VERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|v| *v == 3 || *v == 4)
                .unwrap_or(3),
            dircount: 64 << 10,
            log,
        }
    }
}
