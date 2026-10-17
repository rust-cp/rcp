//! A connection pool bound to one origin, and the status table the adapters that use it
//! share. For endpoints that talk to exactly the host the operator named.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use super::http::{proxy_from_env, split_url, Connection, Response, Scheme, Target};

/// Attempts per request before a transport failure is reported.
const ATTEMPTS: usize = 3;

/// What a status means, as the same table the other HTTP adapters publish. `423 Locked` is
/// WebDAV's own and maps to `PermissionDenied`: somebody else holds the resource, which is
/// a refusal rather than a fault in this run.
pub fn kind_of_status(status: u16) -> io::ErrorKind {
    match status {
        404 | 410 => io::ErrorKind::NotFound,
        401 | 403 | 423 => io::ErrorKind::PermissionDenied,
        400 | 405 | 409 => io::ErrorKind::InvalidInput,
        412 => io::ErrorKind::AlreadyExists,
        429 | 502 | 503 | 504 => io::ErrorKind::ResourceBusy,
        507 => io::ErrorKind::StorageFull,
        _ => io::ErrorKind::Other,
    }
}

pub fn remote_error(r: &Response, what: &str) -> io::Error {
    // A WebDAV error body is XML and usually says less than the status, so the status is
    // the message and the body only joins it when it is short enough to be a sentence.
    let body = String::from_utf8_lossy(&r.body);
    let detail = body.trim();
    let detail = if detail.is_empty() || detail.len() > 200 {
        String::new()
    } else {
        format!(": {}", detail.replace('\n', " "))
    };
    io::Error::new(
        kind_of_status(r.status),
        format!("{what}: HTTP {}{detail}", r.status),
    )
}

/// Connections to one origin, pooled. One authority only: the WebDAV and HTTPS adapters
/// have no hand-off shaped like a registry `Location` or a namenode redirect, so there is
/// no `Away` policy here -- a redirect to another host is refused rather than followed.
pub struct Pool {
    // read by WebDAV's MOVE and COPY; an HTTPS source only carries it
    #[cfg_attr(not(feature = "dav"), allow(dead_code))]
    pub(crate) log: Arc<dyn crate::ports::Log>,
    pub(crate) origin: String,
    pub(crate) auth: Option<String>,
    pub(crate) targets: Mutex<BTreeMap<String, Target>>,
    pub(crate) idle: Mutex<BTreeMap<String, Vec<Connection>>>,
    #[cfg(feature = "rustls")]
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
}

impl Pool {
    pub(crate) fn key(scheme: Scheme, host: &str, port: u16) -> String {
        format!(
            "{}://{host}:{port}",
            if scheme == Scheme::Https {
                "https"
            } else {
                "http"
            }
        )
    }

    pub(crate) fn take(&self, scheme: Scheme, host: &str, port: u16) -> io::Result<Connection> {
        let key = Self::key(scheme, host, port);
        // The whole of this adapter's away policy, and it is a refusal rather than a list:
        // every request goes to the authority the operator wrote. A server answering 3xx
        // toward somewhere else does not get followed, so there is no second host to rail.
        if key != self.origin {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("the server at {} tried to hand this run to {key}, which is not the endpoint you named", self.origin)));
        }
        if let Some(c) = self.idle.lock().unwrap().get_mut(&key).and_then(Vec::pop) {
            return Ok(c);
        }
        let target = {
            let mut t = self.targets.lock().unwrap();
            match t.get(&key) {
                Some(t) => t.clone(),
                None => {
                    #[cfg(not(feature = "rustls"))]
                    if scheme == Scheme::Https {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "TLS (davs://, https://) needs an rcp built with the rustls feature",
                        ));
                    }
                    let target = Target {
                        scheme,
                        host: host.to_string(),
                        port,
                        proxy: proxy_from_env(scheme, host),
                        #[cfg(feature = "rustls")]
                        tls: self.tls.clone(),
                    };
                    t.insert(key, target.clone());
                    target
                }
            }
        };
        Connection::connect(&target)
    }

    pub(crate) fn give(&self, scheme: Scheme, host: &str, port: u16, c: Connection) {
        if c.idle() {
            self.idle
                .lock()
                .unwrap()
                .entry(Self::key(scheme, host, port))
                .or_default()
                .push(c);
        }
    }

    pub(crate) fn headers(&self, extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut hs: Vec<(String, String)> = extra
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if let Some(a) = &self.auth {
            hs.push(("Authorization".into(), a.clone()));
        }
        hs
    }

    /// A buffered request to a path on the endpoint's own authority, retried on transport
    /// failure. `409 Conflict` is NOT retried: it means a parent collection is missing and
    /// asking again cannot change that.
    pub(crate) fn request(
        &self,
        method: &str,
        target: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<Response> {
        let (scheme, host, port, _) = split_url(&format!("{}{target}", self.origin))?;
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            }
            let mut conn = match self.take(scheme, &host, port) {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            match conn.request(method, target, &self.headers(extra), body) {
                Ok(r) => {
                    self.give(scheme, &host, port, conn);
                    return Ok(r);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no attempt made")))
    }
}
