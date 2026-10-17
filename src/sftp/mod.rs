//! `sftp://` endpoints: SFTP version 3 through OpenSSH's subsystem, for hosts that have
//! ssh but no rcp.

pub mod client;
pub mod proto;

pub use client::SftpTree;
