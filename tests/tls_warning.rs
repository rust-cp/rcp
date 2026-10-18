//! The warning printed when certificate verification is turned off names the option that
//! turned it off, for each TLS endpoint. Nothing listens on the target port, so each run
//! fails to connect after it has built its TLS configuration and printed the warning.
#![cfg(feature = "rustls")]

use std::net::TcpListener;
use std::process::Command;

/// A loopback port that nothing is listening on.
fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn stderr_of(args: &[&str]) -> String {
    let catalog = std::env::temp_dir().join(format!("rcp-tls-warning-{}", std::process::id()));
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .arg("-catalog")
        .arg(&catalog)
        .args(args)
        .env_remove("RCP_S3_NOVERIFY")
        .env_remove("RCP_OCI_NOVERIFY")
        .output()
        .expect("rcp runs");
    let _ = std::fs::remove_dir_all(&catalog);
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn each_endpoint_names_its_own_noverify_option() {
    let port = closed_port();
    let cases = [
        (
            "-dav.noverify",
            format!("davs://127.0.0.1:{port}/data"),
            "WARN: -dav.noverify",
        ),
        (
            "-http.noverify",
            format!("https://127.0.0.1:{port}/data/"),
            "WARN: -http.noverify",
        ),
        (
            "-oci.noverify",
            format!("oci://127.0.0.1:{port}/repo:tag"),
            "WARN: -oci.noverify",
        ),
    ];
    for (option, url, want) in cases {
        let err = stderr_of(&["scan", "-q", option, &url]);
        assert!(err.contains(want), "{option} {url}: {err}");
        // the control: before this was fixed, every endpoint named the S3 option
        assert!(!err.contains("-s3.noverify:"), "{option} {url}: {err}");
    }
}
