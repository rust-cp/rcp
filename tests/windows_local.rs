#![cfg(windows)]
use rcp::catalog::{Catalog, NoCatalog};
use rcp::filter::Filter;
use rcp::plan::Mode;
use rcp::transfer::{copy_tree, verify_tree, CopyOptions, Ownership, VerifyOptions};
use rcp::tree::{LocalTree, Sink, Tree};

fn cli(f: &Fixture, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args(args)
        .arg("-catalog")
        .arg(f.0.join("cli-catalog"))
        .output()
        .unwrap()
}
fn passed(out: std::process::Output) -> String {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
#[test]
fn terminating_a_foreground_copy_keeps_the_old_file_and_catalog_resumes() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), vec![7; 2 * 1024 * 1024]).unwrap();
    fs::create_dir_all(f.0.join("dst")).unwrap();
    fs::write(f.0.join("dst/a"), b"old destination").unwrap();
    let src = f.0.join("src").display().to_string();
    let dst = f.0.join("dst").display().to_string();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args([
            "copy", "-newid", "cancel", "-bwlimit", "4k", "-bs", "4k", "-noown", "-noxattr",
            "-nolinks", &src, &dst,
        ])
        .arg("-catalog")
        .arg(f.0.join("cli-catalog"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    loop {
        let staged = fs::read_dir(f.0.join("dst")).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rcp-stage-")
        });
        if staged {
            break;
        }
        if child.try_wait().unwrap().is_some() || start.elapsed().as_secs() >= 8 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("copy did not reach its staged write");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    assert_eq!(fs::read(f.0.join("dst/a")).unwrap(), b"old destination");
    passed(cli(
        &f,
        &["resume", "-id", "cancel", "-noown", "-noxattr", "-nolinks"],
    ));
    assert_eq!(
        fs::read(f.0.join("dst/a")).unwrap(),
        vec![7; 2 * 1024 * 1024]
    );
}
#[test]
#[cfg(feature = "dav")]
fn native_cli_reads_webdav_and_verifies_its_copy() {
    let f = Fixture::new();
    fs::write(f.0.join("src/sub/a"), b"WebDAV payload").unwrap();
    let server = rcp::dav::testserver::Server::start(&f.0.join("src")).unwrap();
    let source = format!("dav://127.0.0.1:{}/", server.port);
    let dest = f.0.join("dst").display().to_string();
    passed(cli(
        &f,
        &[
            "copy", "-noId", "-noown", "-noxattr", "-nolinks", &source, &dest,
        ],
    ));
    assert_eq!(fs::read(f.0.join("dst/sub/a")).unwrap(), b"WebDAV payload");
    passed(cli(&f, &["verify", &source, &dest]));
}
#[test]
#[cfg(feature = "https")]
fn native_cli_reads_http_index() {
    let f = Fixture::new();
    fs::write(f.0.join("src/sub/a"), b"HTTP payload").unwrap();
    let server = rcp::https::testserver::Server::start(
        &f.0.join("src"),
        rcp::https::testserver::Shape::Index,
    )
    .unwrap();
    let source = format!("http://127.0.0.1:{}/", server.port);
    let dest = f.0.join("dst").display().to_string();
    passed(cli(
        &f,
        &[
            "copy", "-noId", "-noown", "-noxattr", "-nolinks", &source, &dest,
        ],
    ));
    assert_eq!(fs::read(f.0.join("dst/sub/a")).unwrap(), b"HTTP payload");
    passed(cli(&f, &["verify", &source, &dest]));
}
#[test]
#[cfg(all(feature = "s3", feature = "rustls"))]
fn native_tls_uses_an_explicit_bundle_and_refuses_a_missing_one() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), b"TLS payload").unwrap();
    let openssl = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).is_file())
    .expect("Git OpenSSL is required for the native TLS fixture");
    let certificate = f.0.join("certificate.pem");
    let key = f.0.join("key.pem");
    let generated = std::process::Command::new(openssl)
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .arg("-out")
        .arg(&certificate)
        .arg("-keyout")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "TLS fixture certificate generation failed"
    );
    let server = rcp::s3::testserver::Server::start_tls(
        &["testbucket"],
        rcp::s3::sigv4::Credentials {
            access_key: "test-key".into(),
            secret_key: "test-secret".into(),
            session_token: None,
        },
        &fs::read_to_string(&certificate).unwrap(),
        &fs::read_to_string(&key).unwrap(),
    );
    let source = f.0.join("src").display().to_string();
    let run = |bundle: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args([
                "copy",
                "-noId",
                "-noown",
                "-noxattr",
                "-nolinks",
                &source,
                "s3://testbucket/prefix",
                "-s3.endpoint",
                &server.endpoint(),
            ])
            .arg("-catalog")
            .arg(f.0.join("cli-catalog"))
            .env("AWS_ACCESS_KEY_ID", "test-key")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env("AWS_REGION", "us-east-1")
            .env_remove("AWS_SESSION_TOKEN")
            .env("AWS_CA_BUNDLE", bundle)
            .env("SSL_CERT_FILE", bundle)
            .env("RCP_CA_BUNDLE", bundle)
            .output()
            .unwrap()
    };
    assert!(!run(&f.0.join("absent.pem")).status.success());
    assert!(server.keys("testbucket").is_empty());
    passed(run(&certificate));
    assert_eq!(
        server.object("testbucket", "prefix/a").unwrap().data,
        b"TLS payload"
    );
}
#[test]
#[cfg(feature = "s3")]
fn native_cli_s3_round_trip_checks_signatures() {
    let f = Fixture::new();
    fs::write(f.0.join("src/sub/a"), b"S3 payload").unwrap();
    let server = rcp::s3::testserver::Server::start(
        &["testbucket"],
        rcp::s3::sigv4::Credentials {
            access_key: "test-key".into(),
            secret_key: "test-secret".into(),
            session_token: None,
        },
    );
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args(args)
            .args(["-s3.endpoint", &server.endpoint()])
            .arg("-catalog")
            .arg(f.0.join("cli-catalog"))
            .env("AWS_ACCESS_KEY_ID", "test-key")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env("AWS_REGION", "us-east-1")
            .env_remove("AWS_SESSION_TOKEN")
            .output()
            .unwrap()
    };
    let source = f.0.join("src").display().to_string();
    let dest = f.0.join("dst").display().to_string();
    let bucket = "s3://testbucket/prefix";
    passed(run(&[
        "copy", "-noId", "-noown", "-noxattr", "-nolinks", &source, bucket,
    ]));
    assert_eq!(
        server.object("testbucket", "prefix/sub/a").unwrap().data,
        b"S3 payload"
    );
    passed(run(&[
        "copy", "-noId", "-noown", "-noxattr", "-nolinks", bucket, &dest,
    ]));
    passed(cli(&f, &["verify", &source, &dest]));
}
#[test]
fn native_cli_copy_verify_sync_delete_and_platform_description() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), b"before").unwrap();
    let src = f.0.join("src").display().to_string();
    let dst = f.0.join("dst").display().to_string();
    passed(cli(
        &f,
        &[
            "copy", "-newid", "native", "-noown", "-noxattr", "-nolinks", &src, &dst,
        ],
    ));
    passed(cli(&f, &["verify", &src, &dst]));
    fs::write(f.0.join("src/a"), b"after, changed").unwrap();
    passed(cli(
        &f,
        &["sync", "-id", "native", "-noown", "-noxattr", "-nolinks"],
    ));
    assert_eq!(fs::read(f.0.join("dst/a")).unwrap(), b"after, changed");
    passed(cli(&f, &["scan", "-sha256", "-hashcache", &src]));
    passed(cli(&f, &["scan", "-sha256", "-hashcache", &src]));
    let denied = cli(&f, &["delete", "-force", "-readonly", &dst]);
    assert!(!denied.status.success());
    assert!(f.0.join("dst/a").exists());
    let denied = cli(&f, &["delete", "-force", "-requireconfirm", &dst]);
    assert!(!denied.status.success());
    assert!(f.0.join("dst/a").exists());
    passed(cli(&f, &["delete", "-force", &dst]));
    assert!(!f.0.join("dst/a").exists());
    let description = passed(cli(&f, &["describe"]));
    let parsed = rcp::json::parse(description.as_bytes()).unwrap();
    assert!(format!("{parsed:?}").contains("100 nanoseconds"));
    assert!(!description.contains("\"name\": \"mcp\""));
    assert!(!cli(&f, &["mcp"]).status.success());
    assert!(!cli(&f, &["job", "list"]).status.success());
    let version = passed(cli(&f, &["version"]));
    let transports = version
        .lines()
        .find(|line| line.starts_with("transports:"))
        .unwrap();
    for supported in ["local", "s3", "smb", "dav", "http"] {
        assert!(transports.contains(supported), "{transports}");
    }
    for unsupported in ["tar", "ssh", "rcp (", "rcps", "sftp", "nfs", "hdfs", "oci"] {
        assert!(!transports.contains(unsupported), "{transports}");
    }
}
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rcp-win-local-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(p.join("src/sub")).unwrap();
        Self(p)
    }
    fn src(&self) -> LocalTree {
        LocalTree::new(&self.0.join("src"))
    }
    fn dst(&self) -> LocalTree {
        LocalTree::new(&self.0.join("dst"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn options() -> CopyOptions {
    CopyOptions {
        hard_links: false,
        ownership: Ownership::Skip,
        xattrs: false,
        fsync: true,
        ..CopyOptions::default()
    }
}
#[test]
fn copy_verify_mirror_delete_and_unicode() {
    let f = Fixture::new();
    fs::write(f.0.join("src/sub/caf\u{e9}.txt"), b"first").unwrap();
    fs::write(f.0.join("src/zeros"), vec![0; 90_001]).unwrap();
    let src = f.src();
    let dst = f.dst();
    let result = copy_tree(&src, &dst, Mode::Fresh, None, &mut NoCatalog, &options()).unwrap();
    assert!(result.ok(), "{result:?}");
    assert_eq!(result.copied_files, 2);
    assert!(dst.stat("zeros").unwrap().unwrap().blocks < 90_001);
    let verified = verify_tree(&src, &dst, &VerifyOptions::default()).unwrap();
    assert!(verified.passed(), "{verified:?}");
    assert!(verified.skipped.contains(&"mode"));
    fs::write(f.0.join("src/sub/caf\u{e9}.txt"), b"changed data").unwrap();
    fs::remove_file(f.0.join("src/zeros")).unwrap();
    fs::write(f.0.join("dst/extra"), b"obsolete").unwrap();
    let result = copy_tree(&src, &dst, Mode::Mirror, None, &mut NoCatalog, &options()).unwrap();
    assert!(result.ok(), "{result:?}");
    assert_eq!(result.removed, 2);
    assert_eq!(
        fs::read(f.0.join("dst/sub/caf\u{e9}.txt")).unwrap(),
        b"changed data"
    );
    assert!(verify_tree(&src, &dst, &VerifyOptions::default())
        .unwrap()
        .passed());
}
#[test]
fn native_hard_links_preserve_identity_and_copy_grouping() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), b"same inode").unwrap();
    fs::hard_link(f.0.join("src/a"), f.0.join("src/b")).unwrap();
    let src = f.src();
    let dst = f.dst();
    let mut opts = options();
    opts.hard_links = true;
    let report = copy_tree(&src, &dst, Mode::Fresh, None, &mut NoCatalog, &opts).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.linked, 1);
    let a = dst.stat("a").unwrap().unwrap();
    let b = dst.stat("b").unwrap().unwrap();
    assert_eq!(a.ino, b.ino);
    assert_eq!(a.nlink, 2);
    assert!(verify_tree(&src, &dst, &VerifyOptions::default())
        .unwrap()
        .passed());
}
#[test]
fn case_only_mirror_difference_is_refused_without_removing_data() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), b"source").unwrap();
    let src = f.src();
    let dst = f.dst();
    dst.mkdir(".").unwrap();
    fs::write(f.0.join("dst/A"), b"destination").unwrap();
    let error = copy_tree(&src, &dst, Mode::Mirror, None, &mut NoCatalog, &options()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(fs::read(f.0.join("dst/A")).unwrap(), b"destination");
}
#[test]
fn catalog_resume_sync_and_atomic_abort() {
    let f = Fixture::new();
    fs::write(f.0.join("src/a"), b"original").unwrap();
    let src = f.src();
    let dst = f.dst();
    let catalog_root = f.0.join("catalog");
    let mut catalog =
        Catalog::create(&catalog_root, "copy1", src.root(), dst.root(), "sha256").unwrap();
    assert!(
        copy_tree(&src, &dst, Mode::Fresh, None, &mut catalog, &options())
            .unwrap()
            .ok()
    );
    drop(catalog);
    let mut catalog = Catalog::open(&catalog_root, "copy1").unwrap();
    let entries = catalog.entries().unwrap();
    let result = copy_tree(
        &src,
        &dst,
        Mode::Resume,
        Some(&entries),
        &mut catalog,
        &options(),
    )
    .unwrap();
    assert!(result.ok(), "{result:?}");
    assert_eq!(result.copied_files, 0);
    let item = src.stat("a").unwrap().unwrap();
    {
        let mut staged = dst.create_file(&item).unwrap();
        staged.write(b"unfinished").unwrap();
    }
    assert_eq!(fs::read(f.0.join("dst/a")).unwrap(), b"original");
    assert!(!fs::read_dir(f.0.join("dst")).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".rcp-stage-")));
    fs::remove_file(f.0.join("src/a")).unwrap();
    let result = copy_tree(
        &src,
        &dst,
        Mode::Sync,
        Some(&entries),
        &mut catalog,
        &options(),
    )
    .unwrap();
    assert!(result.ok(), "{result:?}");
    assert_eq!(result.removed, 1);
}
#[test]
fn junction_source_is_incomplete_and_cannot_authorize_mirror_deletion() {
    let f = Fixture::new();
    fs::create_dir_all(f.0.join("outside")).unwrap();
    fs::write(f.0.join("outside/secret"), b"outside").unwrap();
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(f.0.join("src").join("junction"))
        .arg(f.0.join("outside"))
        .status()
        .unwrap();
    assert!(status.success());
    let src = f.src();
    let dst = f.dst();
    dst.mkdir(".").unwrap();
    fs::write(f.0.join("dst/keep"), b"must survive").unwrap();
    let listing = src.list(&Filter::default(), None, 2).unwrap();
    assert!(!listing.errors.is_empty());
    assert!(!listing.items.iter().any(|i| i.rel.contains("secret")));
    let report = copy_tree(&src, &dst, Mode::Mirror, None, &mut NoCatalog, &options()).unwrap();
    assert_eq!(report.removed, 0);
    assert!(f.0.join("dst/keep").exists());
    drop(src);
    drop(dst);
    fs::remove_dir(f.0.join("src/junction")).unwrap();
}
