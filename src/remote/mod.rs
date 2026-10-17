//! rcp's own remote transport: `ssh://[user@]host[:port]/path` endpoints served by `rcp
//! serve` on the far side. The ssh connection is OpenSSH's (its keys, agent, jump hosts
//! and multiplexing apply unchanged); inside it, `proto` is a small framed protocol that
//! mirrors the `Tree` port, `server` answers it over the local adapter, and `client` is
//! the `SshTree` adapter. This is the channel the delta and compression work rides on: a
//! protocol rcp controls at both ends.
//!
//! The same protocol also runs over a plain socket -- `rcp serve -listen ADDR`, dialed as
//! `rcp://host:port/path` or `rcps://host:port/path`. What changes there is not the frames
//! but who is on the other end of them: see `server::check_listen` and `tls`.

pub mod client;
pub mod proto;
pub mod server;
#[cfg(feature = "rustls")]
pub mod tls;

use std::path::PathBuf;

pub use client::{Settings, SshTree};

/// Where the certificates and keys for this run come from.
///
/// Carried unconditionally -- in `Settings`, and by `serve -listen` -- so the option
/// parsing needs no `cfg`. Read only by the `tls` module, which is gated; a build without
/// the feature refuses these options by name rather than accepting and ignoring them, since
/// "I asked for mutual TLS and got none" is the one outcome that must not be silent.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TlsFiles {
    /// `-tls.ca`: the authority a CLIENT checks the server's certificate against. Unset
    /// falls back to the system bundle, the same one `https://` uses.
    pub ca: Option<PathBuf>,
    /// `-tls.cert` / `-tls.key`: this side's own identity. On a serve it is what the
    /// listener presents; on a client it is what it presents when the serve asks.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// `-tls.clientca`: the authority a SERVE requires the peer's certificate to come from.
    /// Its presence is what turns mutual TLS on, and the only thing that lifts loopback.
    pub client_ca: Option<PathBuf>,
}

impl TlsFiles {
    /// Whether this serve authenticates the PEER. `check_listen` asks exactly this, and the
    /// answer is deliberately not "does it have a certificate": a serve's own certificate
    /// proves who the serve is to whoever connects, and says nothing about who connected.
    pub fn is_mutual(&self) -> bool {
        self.client_ca.is_some()
    }
    /// Whether this side has an identity to present at all.
    pub fn has_identity(&self) -> bool {
        self.cert.is_some() || self.key.is_some()
    }
    /// Whether any of these options was named, which is how a build without the `tls`
    /// feature knows to refuse rather than ignore.
    pub fn any(&self) -> bool {
        self.ca.is_some() || self.has_identity() || self.is_mutual()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutual_is_exactly_a_client_ca() {
        let f = TlsFiles::default();
        assert!(!f.is_mutual(), "nothing named: not mutual");
        assert!(!f.has_identity());
        assert!(!f.any());
        let server_only = TlsFiles {
            cert: Some("c".into()),
            key: Some("k".into()),
            ..TlsFiles::default()
        };
        assert!(server_only.has_identity());
        assert!(server_only.any());
        assert!(
            !server_only.is_mutual(),
            "control: a certificate of its own does not authenticate the PEER"
        );
        let mutual = TlsFiles {
            client_ca: Some("ca".into()),
            ..server_only.clone()
        };
        assert!(mutual.is_mutual());
    }
}
