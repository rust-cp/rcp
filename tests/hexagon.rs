//! The hexagon, enforced: the core modules reach the outside world through `ports` only.
//! A source scan, because a dependency rule that lives in a doc comment is a rule the next
//! change forgets. Each arm names the file and the offending line.

use std::fs;
use std::path::Path;

/// The core: pure logic from listings to actions, and the use cases that run it.
const CORE: &[&str] = &[
    "src/plan.rs",
    "src/transfer.rs",
    "src/scan.rs",
    "src/catalog.rs",
    "src/filter.rs",
    "src/ports.rs",
    "src/cdc.rs",
    "src/delta.rs",
];

/// Adapter modules the core must not name.
const ADAPTERS: &[&str] = &[
    "tree", "nfs", "s3", "hdfs", "uring", "sha256", "blake3", "gss", "hash", "throttle", "log",
    "names", "cluster", "xattr", "mounts", "zipfile", "anytree", "runtime", "remote", "lz4",
    "sftp", "oci", "describe", "mcp", "jobs", "tar", "smb", "dav", "https", "net",
];

/// The endpoint adapters. Each builds on the core and the shared plumbing (`net`, `xdr`,
/// `json`, `time`, the digests) and never on another endpoint, so any one of them can be
/// left out of a build.
const ENDPOINTS: &[&str] = &[
    "nfs", "s3", "smb", "sftp", "remote", "dav", "hdfs", "https", "oci", "tar",
];

fn source(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of a file outside its `#[cfg(test)]` module, numbered from 1.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        out.push((n + 1, line));
    }
    out
}

#[test]
fn the_core_names_no_adapter_module() {
    let mut offenses = Vec::new();
    for file in CORE {
        let text = source(file);
        for (n, line) in production_lines(&text) {
            for a in ADAPTERS {
                for pattern in [
                    format!("crate::{a}::"),
                    format!("use crate::{a};"),
                    format!("crate::{a}::{{"),
                ] {
                    if line.contains(&pattern) {
                        offenses.push(format!("{file}:{n}: {}", line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        offenses.is_empty(),
        "core modules reaching past their ports:\n{}",
        offenses.join("\n")
    );
}

/// Every `.rs` file under `src/<module>/`, relative to the crate root.
fn module_files(module: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut dirs = vec![root.join("src").join(module)];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    out.sort();
    out
}

/// The lines of `text` that name endpoint module `other`.
fn names_module<'a>(text: &'a str, other: &str) -> Vec<(usize, &'a str)> {
    let patterns = [
        format!("crate::{other}::"),
        format!("use crate::{other};"),
        format!("rcp::{other}::"),
    ];
    text.lines()
        .enumerate()
        .filter(|(_, l)| patterns.iter().any(|p| l.contains(p.as_str())))
        .map(|(n, l)| (n + 1, l))
        .collect()
}

#[test]
fn no_endpoint_names_another_endpoint() {
    // test modules too: a test that reaches into another endpoint breaks the build that
    // leaves that endpoint out just as surely as production code does
    let mut offenses = Vec::new();
    for endpoint in ENDPOINTS {
        let files = module_files(endpoint);
        assert!(!files.is_empty(), "src/{endpoint}/ has no source");
        for file in files {
            let text = source(&file);
            for other in ENDPOINTS.iter().filter(|o| *o != endpoint) {
                for (n, line) in names_module(&text, other) {
                    offenses.push(format!("{file}:{n}: {}", line.trim()));
                }
            }
        }
    }
    assert!(
        offenses.is_empty(),
        "endpoint modules reaching into another endpoint:\n{}",
        offenses.join("\n")
    );
}

#[test]
fn the_core_keeps_no_process_wide_state() {
    let mut offenses = Vec::new();
    for file in CORE {
        let text = source(file);
        for (n, line) in production_lines(&text) {
            let t = line.trim_start();
            // a static is process-wide state; ZEROS is the one allowed, a constant table
            if (t.starts_with("static ") || t.starts_with("pub static ")) && !t.contains("ZEROS") {
                offenses.push(format!("{file}:{n}: {}", line.trim()));
            }
            if t.contains("OnceLock") || t.contains("thread_local!") {
                offenses.push(format!("{file}:{n}: {}", line.trim()));
            }
        }
    }
    assert!(
        offenses.is_empty(),
        "process-wide state in the core:\n{}",
        offenses.join("\n")
    );
}

#[test]
fn every_port_has_a_null_adapter_a_library_caller_can_start_from() {
    // the runtime with nothing installed is the seam a library caller starts from, and it
    // must not depend on the CLI: SHA-256, unlimited, silent, system names
    let rt = rcp::ports::Runtime::plain();
    assert_eq!(rt.digests.name(), "sha256");
    assert!(!rt.log.enabled());
    let mut h = rt.hasher();
    h.update(b"abc");
    assert_eq!(
        h.finish(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let t = std::time::Instant::now();
    rt.throttle.take(1 << 40);
    assert!(
        t.elapsed().as_millis() < 100,
        "the null throttle never waits"
    );
}

#[test]
fn control_the_scan_sees_an_adapter_reference_when_one_is_planted() {
    // the rule test above passes on an empty crate too; this arm plants an offense in a copy
    // of a core file and checks the same scan reports it, so a green run means the scan
    // looked
    // planted at the top: the scan stops at the file's own test module
    let text = format!(
        "fn planted() {{ let _ = crate::nfs::Settings::from_env; }}\n{}",
        source("src/plan.rs")
    );
    let hits: Vec<_> = production_lines(&text)
        .into_iter()
        .filter(|(_, l)| l.contains("crate::nfs::"))
        .collect();
    assert_eq!(hits.len(), 1, "the planted line is found once");
    let text = format!(
        "static PLANTED: std::sync::OnceLock<u8> = std::sync::OnceLock::new();\n{}",
        source("src/plan.rs")
    );
    let hits: Vec<_> = production_lines(&text)
        .into_iter()
        .filter(|(_, l)| l.contains("OnceLock"))
        .collect();
    assert_eq!(hits.len(), 1);
    let text = format!(
        "use crate::remote::Settings;\n{}",
        source("src/sftp/client.rs")
    );
    assert_eq!(names_module(&text, "remote").len(), 1);
    assert!(module_files("sftp")
        .iter()
        .any(|f| f.ends_with("client.rs")));
}
