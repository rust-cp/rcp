//! The default assembly of the ports: what a run has when the driving adapter installs
//! nothing. SHA-256, no rate limit, no log, and system names. Library callers and tests
//! start here; the CLI replaces the pieces its options name.

use std::sync::Arc;

use crate::ports::{Runtime, Silent, Unlimited};

impl Runtime {
    pub fn plain() -> Runtime {
        Runtime {
            digests: crate::hash::Algorithm::Sha256.digests(),
            chunk_digests: crate::hash::Algorithm::Sha256.digests(),
            throttle: Arc::new(Unlimited),
            log: Arc::new(Silent),
            names: Arc::new(crate::names::SystemNames),
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Runtime::plain()
    }
}
