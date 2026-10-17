//! A throwaway MIT Kerberos realm for the contract suite: `krb5kdc` on a free port under a
//! temporary directory, a user with a ticket, and a keytab holding `nfs/127.0.0.1` and
//! `HTTP/127.0.0.1`, so the client and the stand-in servers can be exercised against a
//! real KDC rather than against each other. One realm per test process, started on first
//! use; the KDC dies with the process (PR_SET_PDEATHSIG). Absent tools skip the arms.

#![allow(dead_code)]

use std::ffi::c_int;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const REALM: &str = "RCP.TEST";
pub const USER: &str = "rcpuser";
pub const PASSWORD: &str = "rcp-user-password";

pub struct Kdc {
    pub dir: PathBuf,
    pub port: u16,
    pub keytab: PathBuf,
    pub ccache: PathBuf,
    pub krb5_conf: PathBuf,
    _kdc: Child,
}

extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
}
const PR_SET_PDEATHSIG: c_int = 1;
const SIGKILL: c_int = 9;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> Option<Kdc> {
    for tool in ["krb5kdc", "kdb5_util", "kadmin.local", "kinit"] {
        if !have(tool) {
            // a skipped arm prints only to captured stderr and then reports ok, so where the
            // tools are meant to be present (CI sets this), their absence is a failure
            if std::env::var_os("RCP_REQUIRE_KDC").is_some_and(|v| !v.is_empty() && v != "0") {
                panic!("KDC harness: {tool} is not installed and RCP_REQUIRE_KDC is set");
            }
            eprintln!("KDC harness: {tool} is not installed; Kerberos arms are skipped");
            return None;
        }
    }
    let dir = std::env::temp_dir().join(format!("rcp-kdc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let krb5_conf = dir.join("krb5.conf");
    let kdc_conf = dir.join("kdc.conf");
    let keytab = dir.join("keytab");
    let ccache = dir.join("ccache");
    fs::write(
        &krb5_conf,
        format!(
            "[libdefaults]\n    default_realm = {REALM}\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    rdns = false\n    dns_canonicalize_hostname = false\n    default_ccache_name = FILE:{cc}\n[realms]\n    {REALM} = {{\n        kdc = 127.0.0.1:{port}\n    }}\n",
            cc = ccache.display()
        ),
    )
    .unwrap();
    fs::write(
        &kdc_conf,
        format!(
            "[kdcdefaults]\n    kdc_ports = {port}\n    kdc_tcp_ports = {port}\n[realms]\n    {REALM} = {{\n        database_name = {d}/principal\n        key_stash_file = {d}/stash\n        acl_file = {d}/kadm5.acl\n        max_life = 10h\n        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n    }}\n[logging]\n    kdc = FILE:{d}/kdc.log\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let env = |c: &mut Command| {
        c.env("KRB5_CONFIG", &krb5_conf)
            .env("KRB5_KDC_PROFILE", &kdc_conf)
            .env("KRB5CCNAME", format!("FILE:{}", ccache.display()))
            .env("KRB5_KTNAME", format!("FILE:{}", keytab.display()));
    };
    let run = |args: &[&str]| {
        let mut c = Command::new(args[0]);
        c.args(&args[1..]);
        env(&mut c);
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "{} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["kdb5_util", "-P", "master-password", "create", "-s"]);
    run(&[
        "kadmin.local",
        "-q",
        &format!("addprinc -pw {PASSWORD} {USER}"),
    ]);
    run(&["kadmin.local", "-q", "addprinc -randkey nfs/127.0.0.1"]);
    run(&["kadmin.local", "-q", "addprinc -randkey HTTP/127.0.0.1"]);
    run(&[
        "kadmin.local",
        "-q",
        &format!("ktadd -k {} nfs/127.0.0.1 HTTP/127.0.0.1", keytab.display()),
    ]);
    let mut kdc = Command::new("krb5kdc");
    kdc.args(["-n", "-P"])
        .arg(dir.join("kdc.pid"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    env(&mut kdc);
    // SAFETY: prctl in the child before exec, so the KDC cannot outlive the test process.
    unsafe {
        use std::os::unix::process::CommandExt;
        kdc.pre_exec(|| {
            prctl(PR_SET_PDEATHSIG, SIGKILL as std::ffi::c_ulong);
            Ok(())
        });
    }
    // PR_SET_PDEATHSIG fires when the spawning THREAD exits, not the process (Linux
    // semantics), so the KDC is spawned from a thread that parks for the life of the
    // process. Spawned from a test thread, the KDC died when that test finished, and every
    // Kerberos arm after it failed with "Cannot contact any KDC" while each passed alone.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(kdc.spawn()).unwrap();
        loop {
            std::thread::park();
        }
    });
    let child = rx.recv().unwrap().unwrap();
    // a ticket for the user, once the KDC answers
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut c = Command::new("kinit");
        c.arg(USER)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        env(&mut c);
        let mut child = c.spawn().unwrap();
        // a kinit that found no KDC listening yet exits before it reads the password, so
        // the write may land on a closed pipe: that is the "not ready" case the loop
        // retries, not a failure (measured: one broken pipe in ~10 suite runs)
        let _ = child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{PASSWORD}\n").as_bytes());
        let out = child.wait_with_output().unwrap();
        if out.status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "kinit never succeeded: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // the process's own Kerberos environment, for in-process acceptors and child rcps
    std::env::set_var("KRB5_CONFIG", &krb5_conf);
    std::env::set_var("KRB5CCNAME", format!("FILE:{}", ccache.display()));
    std::env::set_var("KRB5_KTNAME", format!("FILE:{}", keytab.display()));
    Some(Kdc {
        dir,
        port,
        keytab,
        ccache,
        krb5_conf,
        _kdc: child,
    })
}

static KDC: OnceLock<Option<Kdc>> = OnceLock::new();
/// The realm, started on first use; `None` when the Kerberos tools are not installed.
pub fn kdc() -> Option<&'static Kdc> {
    KDC.get_or_init(start).as_ref()
}
