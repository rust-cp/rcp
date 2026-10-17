//! TLS for `https://` endpoints, behind the `tls` feature: rustls with the ring provider,
//! trust roots read from the file the environment names (`AWS_CA_BUNDLE`, the boto name, or
//! `SSL_CERT_FILE`) or from the distribution's bundle, and `-s3.noverify`, which is
//! printed as the warning it deserves.

use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::base64;

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

const BUNDLES: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The PEM bundle to trust: the environment's choice, else the first distribution bundle found.
pub fn bundle_path() -> Option<PathBuf> {
    for var in ["AWS_CA_BUNDLE", "SSL_CERT_FILE", "RCP_CA_BUNDLE"] {
        if let Ok(p) = std::env::var(var) {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    BUNDLES
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
}

/// Every `CERTIFICATE` block of a PEM file as DER.
pub fn pem_certificates(text: &str) -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(s) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[s + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(e) = body.find("-----END CERTIFICATE-----") else {
            break;
        };
        if let Some(der) = base64::decode(&body[..e]) {
            out.push(CertificateDer::from(der));
        }
        rest = &body[e + "-----END CERTIFICATE-----".len()..];
    }
    out
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client configuration: the trust roots, or none at all when `noverify`.
pub fn config(noverify: bool) -> io::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let cfg = if noverify {
        eprintln!("WARN: -s3.noverify: the server's certificate is not checked; the connection is private only against a passive observer");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let path = bundle_path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no CA bundle found; set AWS_CA_BUNDLE to a PEM file (or -s3.noverify to skip verification)"))?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        let certs = pem_certificates(&text);
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no CERTIFICATE blocks", path.display()),
            ));
        }
        let mut roots = RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no usable certificates", path.display()),
            ));
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

pub fn connect(cfg: &Arc<ClientConfig>, host: &str, tcp: TcpStream) -> io::Result<TlsStream> {
    // The third consumer that must see the address rather than the URL literal: rustls
    // reads a `ServerName` as either a DNS name or an IP, and `[::1]` is neither, so an
    // https endpoint on an IPv6 literal failed at the handshake even once it dialed.
    // Unbracketed it parses as an IP, and rustls correctly sends no SNI for one.
    let host = crate::unbracketed(host);
    let host = crate::unzoned(&host);
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{host}: {e}")))?;
    let conn = ClientConnection::new(cfg.clone(), name).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    // drive the handshake now so a certificate failure surfaces as a connect error
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| io::Error::new(e.kind(), format!("TLS to {host}: {e}")))?;
    Ok(stream)
}
