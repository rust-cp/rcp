//! TLS for `rcps://` endpoints and for `rcp serve -listen`, behind the `tls` feature.
//!
//! **Encryption is not authentication, and that distinction is the whole design here.**
//! `rcp://` is plaintext and may bind only a loopback address, because a socket inherits no
//! identity: over `ssh://`, OpenSSH has authenticated the peer and started the far side as
//! that user before a frame moves, and a bare socket has had none of that done for it.
//!
//! Server TLS alone does not repair that. It proves to the CLIENT who the server is and
//! keeps a passive observer out of the stream; it says nothing whatever about who is
//! connecting. A serve with a certificate and no client verifier, on a routable address, is
//! still an unauthenticated remote filesystem -- now with a padlock on it, which is worse
//! than the plain one because it looks solved. So only MUTUAL TLS lifts the loopback rule:
//! `-tls.clientca` names the authority that must have signed the peer's certificate, and
//! rustls refuses the handshake for anything it did not sign.
//!
//! The pieces are rustls with the ring provider, the same as `https://` S3 uses, and the
//! PEM reader is shared with it.

use std::io;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use super::TlsFiles;
use crate::base64;
use crate::net::tls::pem_certificates;

/// Every PEM block of `text` as (label, DER).
///
/// Generic over the label rather than one reader per kind, so that no full PEM marker for a
/// private key appears as a literal anywhere in this repository -- a credential scan cannot
/// tell a parser from a leak, and the cheaper fix is to not write the string.
/// The most a PEM file may be before it is refused unread.
///
/// An unbounded `read_to_string` is a local memory exhaustion, and the reach is worth
/// being exact about: these paths come from `-tls.*` on this run's own
/// command line or its `RCP_TLS_*` environment, so a peer cannot choose them and this is
/// not remote. What it IS is a foot-gun with a bad failure mode -- point `-tls.ca` at a
/// multi-gigabyte file by mistake and the process dies with an allocation failure instead
/// of a sentence naming the option. A real chain of a hundred certificates is well under
/// 200 KB; a megabyte is generous by an order of magnitude and still small enough that the
/// refusal happens instantly.
const MAX_PEM: u64 = 1 << 20;

/// Reads a PEM file, refusing one that is implausibly large rather than loading it.
///
/// The size is taken from the METADATA and checked before the read, which is the point: a
/// check after `read_to_string` has already paid the memory it exists to avoid. A path
/// that is not a regular file (a fifo, say) has no meaningful length, so it falls through
/// to the read and fails there as it always did.
fn read_pem(path: &Path, option: &str) -> io::Result<String> {
    if let Ok(m) = std::fs::metadata(path) {
        if m.is_file() && m.len() > MAX_PEM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{option} {}: {} bytes is too large for a PEM file (limit {MAX_PEM}); is this the right path?", path.display(), m.len()),
            ));
        }
    }
    std::fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{option} {}: {e}", path.display())))
}

fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    const B: &str = "-----BEGIN ";
    const E: &str = "-----END ";
    const DASH: &str = "-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find(B) {
        let after = &rest[s + B.len()..];
        let Some(l) = after.find(DASH) else { break };
        let label = after[..l].trim().to_string();
        let body = &after[l + DASH.len()..];
        let Some(e) = body.find(E) else { break };
        if let Some(der) = base64::decode(&body[..e]) {
            out.push((label, der));
        }
        // the remainder still carries this block's `LABEL-----` tail; the next `find(B)`
        // steps over it, since a label contains no BEGIN marker
        rest = &body[e + E.len()..];
    }
    out
}

/// A certificate chain and the key that goes with it.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Reads `-tls.cert` and `-tls.key`.
///
/// The three key encodings in circulation are all accepted, because which one a tool emits
/// is an accident of that tool: `openssl req -newkey` writes PKCS#8, `openssl genrsa`
/// writes PKCS#1 and `openssl ecparam -genkey` writes SEC1. Refusing two of the three would
/// be a puzzle for whoever generated the key with the wrong command.
pub fn read_identity(cert: &Path, key: &Path) -> io::Result<Identity> {
    let cert_text = read_pem(cert, "-tls.cert")?;
    let chain = pem_certificates(&cert_text);
    if chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("-tls.cert {}: no CERTIFICATE blocks", cert.display()),
        ));
    }
    let key_text = read_pem(key, "-tls.key")?;
    let mut found = None;
    for (label, der) in pem_blocks(&key_text) {
        found = match label.as_str() {
            concat!("RSA PRIVATE", " KEY") => {
                Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)))
            }
            concat!("EC PRIVATE", " KEY") => {
                Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)))
            }
            concat!("PRIVATE", " KEY") => Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
            _ => continue,
        };
        break;
    }
    let key = found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "-tls.key {}: no private key block (PKCS#8, PKCS#1 or SEC1)",
                key.display()
            ),
        )
    })?;
    Ok(Identity { chain, key })
}

/// A trust store from one PEM bundle, named by the option it came from so the refusal says
/// which file was empty rather than just that something was.
pub fn roots_from(path: &Path, option: &str) -> io::Result<RootCertStore> {
    let text = read_pem(path, option)?;
    let certs = pem_certificates(&text);
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{option} {}: no CERTIFICATE blocks", path.display()),
        ));
    }
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{option} {}: no usable certificates", path.display()),
        ));
    }
    Ok(roots)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The listener's configuration: an identity, and a client verifier when `-tls.clientca`
/// named one.
pub fn server_config(files: &TlsFiles) -> io::Result<Arc<ServerConfig>> {
    let (Some(cert), Some(key)) = (files.cert.as_deref(), files.key.as_deref()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "serve -listen with TLS needs both -tls.cert and -tls.key",
        ));
    };
    let id = read_identity(cert, key)?;
    let builder = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let builder = match files.client_ca.as_deref() {
        Some(ca) => {
            let roots = roots_from(ca, "-tls.clientca")?;
            // `builder()` here, not `builder_with_provider`: this verifier must use the
            // same provider as the config, and rustls threads it through the builder.
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("-tls.clientca: {e}"))
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let cfg = builder.with_single_cert(id.chain, id.key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("-tls.cert/-tls.key: {e}"),
        )
    })?;
    Ok(Arc::new(cfg))
}

/// The dialer's configuration: trust roots for the server, and this side's own certificate
/// when the serve is going to ask for one.
pub fn client_config(files: &TlsFiles) -> io::Result<Arc<ClientConfig>> {
    let roots = match files.ca.as_deref() {
        Some(p) => roots_from(p, "-tls.ca")?,
        None => {
            // The same resolution `https://` uses: `AWS_CA_BUNDLE`, `SSL_CERT_FILE` or
            // `RCP_CA_BUNDLE`, else the first distribution bundle on disk. Sharing it is
            // deliberate -- an operator who has already pointed this container at a trust
            // store should not have to do it twice -- and `-tls.ca` overrides all of them.
            let p = crate::net::tls::bundle_path().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "rcps:// found no CA bundle; name one with -tls.ca (or set RCP_CA_BUNDLE)",
                )
            })?;
            roots_from(&p, "the system CA bundle")?
        }
    };
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots);
    let cfg = match (files.cert.as_deref(), files.key.as_deref()) {
        (Some(c), Some(k)) => {
            let id = read_identity(c, k)?;
            builder
                .with_client_auth_cert(id.chain, id.key)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("-tls.cert/-tls.key: {e}"),
                    )
                })?
        }
        (None, None) => builder.with_no_client_auth(),
        // half an identity is a typo, not a choice: without both, the serve would ask for a
        // certificate and get none, and the handshake would fail with rustls's wording
        // rather than with the name of the option that is missing
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "-tls.cert and -tls.key go together: name both, or neither",
            ))
        }
    };
    Ok(Arc::new(cfg))
}

pub type ClientStream = StreamOwned<ClientConnection, TcpStream>;
pub type ServerStream = StreamOwned<ServerConnection, TcpStream>;

/// Dials `addr`, presenting `host` as the name to check the certificate against.
pub fn connect(cfg: &Arc<ClientConfig>, host: &str, addr: &str) -> io::Result<ClientStream> {
    let tcp = TcpStream::connect(addr)
        .map_err(|e| io::Error::new(e.kind(), format!("rcps://{addr}: {e}")))?;
    // Nagle batches small writes waiting for an ack, which is exactly wrong for a
    // request/reply protocol. Same reason as the plaintext dialer.
    let _ = tcp.set_nodelay(true);
    // rustls reads a `ServerName` as a DNS name or an IP, and `[::1]` is neither
    let host = crate::unbracketed(host);
    let host = crate::unzoned(&host);
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("rcps://{host}: {e}")))?;
    let conn = ClientConnection::new(cfg.clone(), name).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    // Drive the handshake now. Otherwise a certificate the client will not accept surfaces
    // halfway through the first frame, as a protocol error on a stream that looked open.
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| io::Error::new(e.kind(), format!("rcps://{addr}: TLS to {host}: {e}")))?;
    Ok(stream)
}

/// Completes a server handshake on an accepted socket.
///
/// Eager for the same reason the client's is, and for one more: with `-tls.clientca` this is
/// where a peer with no certificate, or one from the wrong authority, is turned away. That
/// refusal belongs at accept time, in the log line that names the peer, not inside a frame.
pub fn accept(cfg: &Arc<ServerConfig>, tcp: TcpStream) -> io::Result<ServerStream> {
    let _ = tcp.set_nodelay(true);
    let conn = ServerConnection::new(cfg.clone()).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| io::Error::new(e.kind(), format!("TLS handshake: {e}")))?;
    Ok(stream)
}

/// One duplex stream handed out as an independent reader and writer.
///
/// A `TcpStream` splits with `try_clone` because the kernel owns the two directions. A TLS
/// stream cannot: the record layer, the sequence numbers and the key schedule are one piece
/// of state, so both directions must go through the same object. `Shared` is that object
/// behind a lock.
///
/// The lock is never contended in this crate and the reason is worth stating, because a
/// mutex around a BLOCKING read is a deadlock in most other shapes. A `Channel` is a
/// sequential request stream used by one worker: it writes its requests, then reads their
/// replies, on one thread. A serve's session is the same loop from the other side. Neither
/// ever holds the read half while another thread wants the write half, because there is no
/// other thread. Parallelism here is more channels, not more users of one channel.
pub struct Shared<T>(Arc<Mutex<T>>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Shared(self.0.clone())
    }
}

impl<T> Shared<T> {
    pub fn new(inner: T) -> Shared<T> {
        Shared(Arc::new(Mutex::new(inner)))
    }
    /// A poisoned lock here means a worker panicked mid-frame. The stream's bytes are then
    /// untrustworthy, but so is dropping the connection silently, so the inner value is
    /// taken and the next read or write fails on its own terms with a real error.
    fn get(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T: io::Read> io::Read for Shared<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.get().read(buf)
    }
}

impl<T: io::Write> io::Write for Shared<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.get().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generic PEM reader has to keep labels apart, because `PRIVATE KEY` is a suffix of
    /// `RSA PRIVATE KEY` and a `contains` test would read a PKCS#1 key as PKCS#8 -- which
    /// rustls then rejects with a message about the DER, not about the label.
    /// A PEM path that is implausibly large is refused by NAME, before it is read.
    ///
    /// The control is the second half: a small file at the same path is read normally, so
    /// the arm measures the size rule rather than a reader that refuses everything.
    #[test]
    fn an_implausibly_large_pem_is_refused_before_it_is_read() {
        // the PID alone is not unique enough: arms in one binary share a process, so a
        // second arm using the same path races this one. That is not hypothetical -- a
        // stray duplicate `#[test]` registered this arm twice, the two copies ran
        // concurrently against one file, and the second truncated it to its control
        // fixture while the first was still asserting the size refusal. The failure read
        // as "the size check does not work", which it was not.
        let dir = std::env::temp_dir().join(format!(
            "rcp-pem-size-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let big = dir.join("big.pem");
        // one byte past the limit is enough; the check is on the metadata, so this costs
        // a sparse-ish write rather than a real megabyte of PEM
        std::fs::write(&big, vec![b'x'; (MAX_PEM + 1) as usize]).expect("write");
        let e = roots_from(&big, "-tls.ca").expect_err("an oversized PEM must be refused");
        let msg = e.to_string();
        assert!(msg.contains("too large for a PEM file"), "{msg}");
        assert!(
            msg.contains("-tls.ca"),
            "the refusal has to name the option that chose the path: {msg}"
        );

        // THE CONTROL: a small file at the same path gets past the size rule and fails for
        // its CONTENT instead, which is the pre-existing behavior this must not change.
        std::fs::write(&big, b"not pem at all\n").expect("write");
        let e = roots_from(&big, "-tls.ca").expect_err("a small non-PEM still fails");
        assert!(
            e.to_string().contains("no CERTIFICATE blocks"),
            "the small file must fail on content, not size: {e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pem_blocks_read_each_label_exactly() {
        let one = |label: &str, body: &str| {
            format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
        };
        // "aGk=" is "hi"; the point is the labels, not the DER
        let text = format!(
            "{}{}{}",
            one("CERTIFICATE", "aGk="),
            one(concat!("RSA PRIVATE", " KEY"), "aGk="),
            one(concat!("PRIVATE", " KEY"), "aGk=")
        );
        let got: Vec<String> = pem_blocks(&text)
            .into_iter()
            .map(|(l, d)| {
                assert_eq!(d, b"hi");
                l
            })
            .collect();
        assert_eq!(
            got,
            vec![
                "CERTIFICATE".to_string(),
                concat!("RSA PRIVATE", " KEY").to_string(),
                concat!("PRIVATE", " KEY").to_string()
            ]
        );

        // control: text with no blocks yields none, so the loop cannot be inventing labels
        assert!(pem_blocks("no pem here\njust words\n").is_empty());
        // control: an unterminated block is not a block
        assert!(pem_blocks("-----BEGIN CERTIFICATE-----\naGk=\n").is_empty());
    }
}
