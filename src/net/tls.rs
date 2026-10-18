//! TLS for `https://` endpoints, behind the `tls` feature: rustls with the ring provider,
//! trust roots read from the file the environment names (`AWS_CA_BUNDLE`, the boto name, or
//! `SSL_CERT_FILE`) or from the distribution's bundle, and each endpoint's `-*.noverify`,
//! which is printed as the warning it deserves, naming the option that turned it on.

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

/// The option that turns certificate verification off, per endpoint kind. HDFS has no
/// option of its own and follows `-s3.noverify`; OCI follows either of its two.
pub const S3_NOVERIFY: &str = "-s3.noverify";
pub const HDFS_NOVERIFY: &str = "-s3.noverify";
pub const DAV_NOVERIFY: &str = "-dav.noverify";
pub const HTTP_NOVERIFY: &str = "-http.noverify";
pub const OCI_NOVERIFY: &str = "-oci.noverify (or -s3.noverify)";

/// What a run with verification off prints, naming the option that turned it off.
pub fn noverify_warning(flag: &str) -> String {
    format!("WARN: {flag}: the server's certificate is not checked; the connection is private only against a passive observer")
}

fn no_bundle_message(flag: &str) -> String {
    format!("no CA bundle found; set AWS_CA_BUNDLE to a PEM file (or {flag} to skip verification)")
}

/// A client configuration: the trust roots, or none at all when `noverify`. `flag` is the
/// option that controls verification for the calling endpoint, one of the constants above.
pub fn config(noverify: bool, flag: &str) -> io::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let cfg = if noverify {
        eprintln!("{}", noverify_warning(flag));
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let path = bundle_path()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, no_bundle_message(flag)))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_noverify_warning_names_each_endpoints_own_option() {
        for (flag, option) in [
            (S3_NOVERIFY, "-s3.noverify"),
            (HDFS_NOVERIFY, "-s3.noverify"),
            (DAV_NOVERIFY, "-dav.noverify"),
            (HTTP_NOVERIFY, "-http.noverify"),
            (OCI_NOVERIFY, "-oci.noverify"),
        ] {
            let warning = noverify_warning(flag);
            assert!(warning.starts_with(&format!("WARN: {option}")), "{warning}");
            assert!(no_bundle_message(flag).contains(option));
        }
        // the control: a warning for WebDAV does not send the reader to the S3 option
        assert!(!noverify_warning(DAV_NOVERIFY).contains("-s3."));
        assert!(!noverify_warning(HTTP_NOVERIFY).contains("-s3."));
    }

    #[test]
    fn every_named_option_is_a_real_option() {
        for flag in [
            S3_NOVERIFY,
            HDFS_NOVERIFY,
            DAV_NOVERIFY,
            HTTP_NOVERIFY,
            OCI_NOVERIFY,
        ] {
            for word in flag.split([' ', '(', ')']) {
                if let Some(name) = word.strip_prefix('-') {
                    assert!(
                        crate::describe::capability_of(name).is_some(),
                        "{name} is not an rcp option"
                    );
                }
            }
        }
    }
}
