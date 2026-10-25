//! SMB2 endpoints: `smb://[user[:pass]@]host[:port]/share[/path]`.
//!
//! Scope is stated up front because SMB is large and most of it is not a file copy:
//! SMB **2**, dialects 0x0202 through 0x0300, NTLMv2 authentication, and the operations
//! the `Tree` trait needs. No SMB1 (it is deprecated and its security model is not worth
//! reviving), no DFS, no Kerberos, no oplocks or leases, no change notification.
//!
//! **Message signing IS implemented** -- see `sign` -- and it is worth saying why, because
//! it is easy to read the dialect list as though signing were a cost of 0x0311. It is not.
//! Signing has been in SMB2 since 0x0202, and the SERVER decides whether to require it:
//! Windows 11 24H2 and Windows Server 2025 do by default, as does a Samba configured
//! `server signing = mandatory`, which is usual for a domain member. Against such a server
//! there is no dialect to fall back to, so a module that only read the bit and refused by
//! name would be excluded from most current deployments. `negotiate` reads that bit and
//! arms a key instead of producing an error.
//!
//! What the stand-in these arms run against can measure is still nothing about signing --
//! it does not require it. The measurement is a real Samba with `server signing =
//! mandatory`, at each of the three dialects, and it is recorded in the README rather than
//! here because it cannot be re-run from a unit arm. No Windows server was contacted.

pub mod client;
pub mod conn;
pub mod ntlm;
pub mod proto;
#[cfg(test)]
pub(crate) mod scripted;
pub mod sign;
/// In-process SMB stand-in used by the integration tests.
#[doc(hidden)]
pub mod testserver;

pub use client::{Settings, SmbTree};
