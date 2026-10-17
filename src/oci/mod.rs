//! `oci://` endpoints: a repository on a container registry (the OCI Distribution API)
//! presented as an OCI image layout, so a copy between two registries mirrors an image the
//! way skopeo and crane do, a copy from a registry to a directory writes a layout skopeo's
//! `oci:` transport reads, and a copy from a layout to a registry pushes it.
//!
//! The tree is `oci-layout`, `index.json` and `blobs/sha256/<hex>` for every blob an
//! image reaches: manifests, indexes, configs and layers. Content-addressed names make
//! deduplication free: a blob the destination already holds is not read from the source.
//! Manifests are staged as they arrive and pushed, children before parents, when the copy
//! finishes, because a registry refuses a manifest whose blobs it does not have yet.

pub mod client;

use std::sync::Arc;

use crate::ports::Log;

pub use client::OciTree;

/// Where a registry may send this run.
///
/// A registry names other hosts in two places, and both are the far end choosing where our
/// traffic goes:
///
/// - the upload `Location`. `POST /v2/.../blobs/uploads/` answers with one, and for ECR,
///   GAR and anything else fronting object storage it names a DIFFERENT host, which is
///   where the blob's bytes then go. Two hops, never a loop: `start_upload` reads one and
///   `commit_upload` at most one more.
/// - the bearer `realm`. A 401 carries `WWW-Authenticate: Bearer realm="..."`, the client
///   fetches a token from it, and it sends the BASIC CREDENTIALS to get one. Docker Hub's
///   realm really is another host (`auth.docker.io` for `registry-1.docker.io`), so this
///   is the protocol working as designed -- and it means a registry that answers with
///   `realm="http://elsewhere/token"` is handed the run's username and password.
///
/// Measured, before this existed: a run railed to `-allow oci://HOST/app` sent
/// `Basic b3BlcmF0b3I6c3VwZXJzZWNyZXQ=` to a listener on another port. That is the
/// credential itself, not the payload, which makes it the more serious of the two.
///
/// Following either is the feature. `-allow` bounds the endpoints the OPERATOR named, so a
/// railed run follows them only to a host its own roots name.
///
/// The policy itself is [`crate::ports::Away`], shared with the other adapters whose
/// protocols hand a run on -- `hdfs://` had the same hole open for as long as this type
/// lived here and only registries consulted it. Re-exported under the old name because
/// `oci::Away` is what the driving adapter and the tests say.
pub use crate::ports::Away;

/// How registries are reached in this run: the `-oci.*` options.
#[derive(Clone)]
pub struct Settings {
    /// Plain HTTP instead of HTTPS.
    pub insecure: bool,
    /// Skip certificate verification.
    pub noverify: bool,
    /// `user:password` for every registry of the run, ahead of the credential files.
    pub user: Option<String>,
    /// Where an upload `Location` may send the bytes; set from the rails.
    pub away: Away,
    pub log: Arc<dyn Log>,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("insecure", &self.insecure)
            .field("noverify", &self.noverify)
            .field("user", &self.user.as_ref().map(|_| "…"))
            .finish()
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Settings {
    /// The environment's defaults: `RCP_OCI_INSECURE`, `RCP_OCI_NOVERIFY`, `RCP_OCI_USER`
    /// with `RCP_OCI_PASSWORD`.
    pub fn from_env(log: Arc<dyn Log>) -> Settings {
        let user = match (env("RCP_OCI_USER"), env("RCP_OCI_PASSWORD")) {
            (Some(u), Some(p)) => Some(format!("{u}:{p}")),
            (Some(u), None) if u.contains(':') => Some(u),
            _ => None,
        };
        Settings {
            insecure: env("RCP_OCI_INSECURE").is_some(),
            noverify: env("RCP_OCI_NOVERIFY").is_some(),
            user,
            away: Away::Anywhere,
            log,
        }
    }
}

#[cfg(test)]
pub(crate) fn client_kind_of_status(status: u16) -> std::io::ErrorKind {
    client::kind_of_status(status)
}
