//! Starting and stopping the stand-in SMB2 server the arms run against.
//!
//! Compiled into the library rather than behind `cfg(test)`, the same as the WebDAV
//! stand-in and for the same reason: an INTEGRATION test is a separate crate, and
//! `cfg(test)` on a library module does not reach it, so a contract arm could not start a
//! server at all.
//!
//! The shipped binary still cannot serve anything: `start` runs `python3` against a script
//! under `CARGO_MANIFEST_DIR`, which is a path in the source tree, and returns `None` when
//! it -- or impacket -- is absent. A copy tool that can be made to serve is a different
//! program, and this is not one.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

pub struct Server {
    child: Child,
    pub port: u16,
    /// Kept for its `Drop`, which removes the share directory.
    _dir: tempdir::Dir,
    pub share: std::path::PathBuf,
}

impl Server {
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A directory that removes itself, so a failed arm does not leave a share behind.
pub mod tempdir {
    use std::path::PathBuf;
    pub struct Dir(pub PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Picks a free port by binding one and letting it go.
///
/// There is a race between the release and the server's bind, and it is accepted rather
/// than hidden: the alternative is parsing a port out of the server's own output, and
/// impacket's SimpleSMBServer exposes no accessor for its socket. A collision shows up as
/// a refused connection in the arm, not as a wrong answer.
fn free_port() -> Option<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let p = l.local_addr().ok()?.port();
    drop(l);
    Some(p)
}

/// Starts the server, or returns `None` when python3 or impacket is missing.
pub fn start() -> Option<Server> {
    let ok = Command::new("python3")
        .args(["-c", "import impacket.smbserver"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return None;
    }
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/smb_server.py");
    if !script.exists() {
        return None;
    }
    let port = free_port()?;
    let share = std::env::temp_dir().join(format!("rcp-smb-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&share).ok()?;
    let dir = tempdir::Dir(share.clone());

    let mut child = Command::new("python3")
        .arg(&script)
        .arg(&share)
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Wait for READY, then for the port to actually accept -- the server prints its
    // intention before `start()` binds, so the line alone is not enough. Waiting on the
    // socket rather than on a sleep is what keeps this from being a machine-speed race.
    let mut out = BufReader::new(child.stdout.take()?);
    let mut line = String::new();
    let _ = out.read_line(&mut line);
    if !line.starts_with("READY") {
        let _ = child.kill();
        return None;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().ok()?,
            std::time::Duration::from_millis(200),
        )
        .is_ok()
        {
            return Some(Server {
                child,
                port,
                _dir: dir,
                share,
            });
        }
        std::thread::yield_now();
    }
    let _ = child.kill();
    None
}
