//! `-nodes`: a copy or scan spread over a fleet of hosts. The
//! coordinator (this process) lists and plans as usual, then hands the file batches to
//! worker processes on the named nodes over `ssh` and collects one result line per file;
//! directories, links, symlinks, metadata and the catalog stay with the coordinator. A node
//! needs `rcp` on its `PATH` and the same endpoints reachable: an NFS export or a bucket is
//! naturally shared, a local path must be the same mount on every node.
//!
//! The protocol is plain text so `-copybatch PROG` can replace the worker with anything:
//! the worker gets `SOURCE DESTINATION` as its last two arguments and NUL-separated paths
//! relative to the source on stdin, and prints one line per path on stdout:
//!
//! ```text
//! ok<TAB>PATH<TAB>BYTES<TAB>SHA256-or-empty<TAB>OWNER-REFUSED(0|1)<TAB>XATTRS-REFUSED(count)
//! fail<TAB>PATH<TAB>MESSAGE
//! ```
//!
//! `localhost` as a node name runs the worker on this host without ssh; `RCP_SSH` names the
//! ssh program (the tests point it at a stub).

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::catalog::Kind;
use crate::tree::{FileOptions, FileOutcome, Item, Refusals, Tree};

#[cfg(unix)]
extern "C" {
    fn signal(signum: std::os::raw::c_int, handler: usize) -> usize;
}

/// A worker that dies (or never starts) closes its stdin while the batch is still being
/// written; with SIGPIPE at its default that would kill the coordinator instead of failing
/// the batch. The signal is ignored for the duration of the fleet run and restored after.
#[cfg(unix)]
struct SigpipeGuard(usize);

#[cfg(windows)]
struct SigpipeGuard;

#[cfg(windows)]
impl SigpipeGuard {
    fn ignore() -> Self {
        Self
    }
}

#[cfg(unix)]
impl SigpipeGuard {
    fn ignore() -> SigpipeGuard {
        // SAFETY: installing SIG_IGN (1) for SIGPIPE (13); the previous disposition is kept.
        SigpipeGuard(unsafe { signal(13, 1) })
    }
}

#[cfg(unix)]
impl Drop for SigpipeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring the disposition that was in force before.
        unsafe { signal(13, self.0) };
    }
}

/// Where the batches go and how the worker is invoked.
#[derive(Clone)]
pub struct Fleet {
    pub nodes: Vec<String>,
    /// A program replacing `rcp copybatch` on every node, with its own arguments.
    pub copybatch: Option<String>,
    /// The options to forward to the worker (block size, hashing, ownership, ...).
    /// Credentials are NOT here -- see `env`.
    pub forward: Vec<String>,
    /// Credentials, as environment variables for the worker process. A command line is
    /// readable by every user on the machine that runs it, for as long as it runs; a
    /// process's own environment is not. `launcher` applies these to a local worker and
    /// `fleet()` refuses an ssh one, because ssh has no way to carry an environment that
    /// does not end up on the remote command line anyway.
    pub env: Vec<(String, String)>,
    pub source: String,
    pub destination: String,
    pub log: std::sync::Arc<dyn crate::ports::Log>,
}

impl std::fmt::Debug for Fleet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fleet")
            .field("nodes", &self.nodes)
            .field("copybatch", &self.copybatch)
            .field("forward", &self.forward)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .finish()
    }
}

impl crate::ports::Batches for Fleet {
    fn copy(
        &self,
        files: &[&Item],
        done: &mut (dyn FnMut(usize, io::Result<FileOutcome>) + Send),
    ) -> io::Result<()> {
        copy_batches(self, files, done)
    }
}

/// One result line to the coordinator on stdout. A coordinator that has gone away ends the
/// worker quietly, as `crate::exit_if_reader_left` describes.
fn line(args: std::fmt::Arguments<'_>) {
    let mut o = io::stdout().lock();
    if let Err(e) = writeln!(o, "{args}") {
        crate::exit_if_reader_left(&e);
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other)
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The command that starts a worker on `node`: the program itself for `localhost`, otherwise
/// `ssh` (or `RCP_SSH`) to the node.
pub fn launcher(
    node: &str,
    worker: &[String],
    env: &[(String, String)],
    log: &dyn crate::ports::Log,
) -> Command {
    crate::debug!(log, "node {node}: {}", worker.join(" "));
    if node == "localhost" || node == "local" {
        let mut c = Command::new(&worker[0]);
        c.args(&worker[1..]);
        // a local worker takes its credentials through its own environment, which no
        // other process can read; `fleet()` refuses to build a remote one that needs any
        c.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        c
    } else {
        let ssh = std::env::var("RCP_SSH")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "ssh".into());
        let mut c = Command::new(ssh);
        c.args(["-o", "BatchMode=yes", node]);
        // ssh passes one string to the remote shell: quote every word
        let line = worker
            .iter()
            .map(|w| format!("'{}'", w.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        c.arg(line);
        c
    }
}

/// The worker's argument vector for a copy batch.
fn copy_worker(fleet: &Fleet) -> Vec<String> {
    match &fleet.copybatch {
        Some(prog) => {
            let mut v: Vec<String> = prog.split_whitespace().map(str::to_string).collect();
            v.push(fleet.source.clone());
            v.push(fleet.destination.clone());
            v
        }
        None => {
            let mut v = vec!["rcp".to_string(), "copybatch".to_string()];
            v.extend(fleet.forward.iter().cloned());
            v.push(fleet.source.clone());
            v.push(fleet.destination.clone());
            v
        }
    }
}

/// Splits indexes into `n` batches balanced by size: largest first, each to the lightest.
pub fn partition(files: &[&Item], n: usize) -> Vec<Vec<usize>> {
    let n = n.max(1);
    let mut order: Vec<usize> = (0..files.len()).collect();
    order.sort_by(|a, b| files[*b].size.cmp(&files[*a].size).then(a.cmp(b)));
    let mut batches: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut load = vec![0u64; n];
    for i in order {
        let lightest = (0..n).min_by_key(|k| (load[*k], *k)).unwrap();
        batches[lightest].push(i);
        load[lightest] += files[i].size.max(1);
    }
    batches
}

/// Runs the file batches on the fleet, reporting each file through `done` as its line
/// arrives. A node that fails to start or dies reports every file it was given as failed.
pub fn copy_batches(
    fleet: &Fleet,
    files: &[&Item],
    done: &mut (dyn FnMut(usize, io::Result<FileOutcome>) + Send),
) -> io::Result<()> {
    let batches = partition(files, fleet.nodes.len());
    let worker = copy_worker(fleet);
    let done = Mutex::new(done);
    let _sigpipe = SigpipeGuard::ignore();
    std::thread::scope(|scope| {
        for (node, batch) in fleet.nodes.iter().zip(batches) {
            if batch.is_empty() {
                continue;
            }
            let (worker, done) = (&worker, &done);
            scope.spawn(move || {
                let by_rel: BTreeMap<&str, usize> =
                    batch.iter().map(|i| (files[*i].rel.as_str(), *i)).collect();
                let mut reported: Vec<bool> = vec![false; files.len()];
                let outcome = (|| -> io::Result<()> {
                    let mut child = launcher(node, worker, &fleet.env, &*fleet.log)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .map_err(|e| {
                            io::Error::new(
                                e.kind(),
                                format!("node {node}: cannot start worker: {e}"),
                            )
                        })?;
                    let mut stdin = child.stdin.take().expect("piped");
                    let input: Vec<u8> = batch
                        .iter()
                        .flat_map(|i| {
                            files[*i]
                                .rel
                                .as_bytes()
                                .iter()
                                .copied()
                                .chain(std::iter::once(0u8))
                        })
                        .collect();
                    let writer = std::thread::spawn(move || {
                        let _ = stdin.write_all(&input);
                    });
                    let stdout = child.stdout.take().expect("piped");
                    for line in BufReader::new(stdout).lines() {
                        let line = line?;
                        let f: Vec<&str> = line.split('\t').collect();
                        let (rel, result) = match f.as_slice() {
                            ["ok", rel, bytes, sha, owner, xattrs, ..] => (
                                unescape(rel),
                                Ok(FileOutcome {
                                    bytes: bytes.parse().unwrap_or(0),
                                    sha256: if sha.is_empty() {
                                        None
                                    } else {
                                        Some(sha.to_string())
                                    },
                                    refusals: Refusals {
                                        owner: *owner == "1",
                                        xattrs: (0..xattrs.parse::<usize>().unwrap_or(0))
                                            .map(|_| "attribute".to_string())
                                            .collect(),
                                    },
                                    literal: None,
                                }),
                            ),
                            ["fail", rel, rest @ ..] => (
                                unescape(rel),
                                Err(io::Error::other(format!(
                                    "node {node}: {}",
                                    rest.join("\t")
                                ))),
                            ),
                            _ => {
                                eprintln!("WARN: node {node}: unrecognized worker line {line:?}");
                                continue;
                            }
                        };
                        match by_rel.get(rel.as_str()) {
                            Some(&i) if !reported[i] => {
                                reported[i] = true;
                                (done.lock().unwrap())(i, result);
                            }
                            _ => eprintln!(
                                "WARN: node {node}: result for a path it was not given: {rel}"
                            ),
                        }
                    }
                    let _ = writer.join();
                    let status = child.wait()?;
                    if !status.success() {
                        return Err(io::Error::other(format!(
                            "node {node}: worker exited with {status}"
                        )));
                    }
                    Ok(())
                })();
                let err = outcome
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| format!("node {node}: no result line"));
                for i in &batch {
                    if !reported[*i] {
                        (done.lock().unwrap())(*i, Err(io::Error::other(err.clone())));
                    }
                }
            });
        }
    });
    Ok(())
}

/// The worker side of a copy: paths on stdin, one result line per path on stdout.
pub fn serve_copybatch<T: Tree>(
    src: &T,
    dst: &T,
    fopts: &FileOptions,
    parallel: usize,
) -> io::Result<usize> {
    // A batch copies files and nothing else; it never calls `sync`, so a destination that
    // publishes there would take the bytes and show nothing. The coordinator refuses the
    // same pair; this is the refusal for someone running `copybatch` by hand.
    if dst.sync_publishes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: a batch cannot publish to this destination, because only a whole copy calls sync", dst.root().display()),
        ));
    }
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let rels: Vec<String> = input
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .map(|r| String::from_utf8_lossy(r).to_string())
        .collect();
    let items: Vec<Item> = rels
        .iter()
        .filter_map(|rel| match src.stat(rel) {
            Ok(Some(i)) if i.kind == Kind::File => Some(i),
            Ok(_) => {
                line(format_args!(
                    "fail\t{}\tnot a regular file on the source",
                    escape(rel)
                ));
                None
            }
            Err(e) => {
                line(format_args!("fail\t{}\t{e}", escape(rel)));
                None
            }
        })
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out = io::stdout();
    let failures = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..parallel.max(1).min(items.len().max(1)) {
            scope.spawn(|| {
                let mut buf = vec![0u8; fopts.block_size];
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let item = &items[i];
                    let line = match crate::transfer::copy_one(src, dst, item, fopts, &mut buf) {
                        Ok(o) => format!(
                            "ok\t{}\t{}\t{}\t{}\t{}",
                            escape(&item.rel),
                            o.bytes,
                            o.sha256.unwrap_or_default(),
                            if o.refusals.owner { 1 } else { 0 },
                            o.refusals.xattrs.len()
                        ),
                        Err(e) => {
                            failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            format!(
                                "fail\t{}\t{}",
                                escape(&item.rel),
                                e.to_string().replace('\n', " ")
                            )
                        }
                    };
                    let mut o = out.lock();
                    if let Err(e) = writeln!(o, "{line}") {
                        crate::exit_if_reader_left(&e);
                    }
                    let _ = o.flush();
                }
            });
        }
    });
    Ok(failures.into_inner())
}

// ---------------------------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------------------------

/// One listing entry as a worker prints it: catalog-style escaping, one line per entry.
pub fn item_line(i: &Item, sha256: Option<&str>) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        escape(&i.rel),
        i.kind.tag(),
        i.size,
        i.mtime_ns,
        i.atime_ns,
        i.mode,
        i.uid,
        i.gid,
        i.dev,
        i.ino,
        i.nlink,
        i.blocks,
        i.link_target
            .as_ref()
            .map(|p| escape(&p.to_string_lossy()))
            .unwrap_or_default(),
        sha256.unwrap_or_default()
    )
}

pub fn parse_item_line(line: &str) -> Option<(Item, Option<String>)> {
    let f: Vec<&str> = line.split('\t').collect();
    if f.len() != 14 {
        return None;
    }
    let kind = match f[1] {
        "f" => Kind::File,
        "d" => Kind::Dir,
        "l" => Kind::Symlink,
        _ => return None,
    };
    let item = Item {
        rel: unescape(f[0]),
        kind,
        size: f[2].parse().ok()?,
        mtime_ns: f[3].parse().ok()?,
        atime_ns: f[4].parse().ok()?,
        mode: f[5].parse().ok()?,
        uid: f[6].parse().ok()?,
        gid: f[7].parse().ok()?,
        dev: f[8].parse().ok()?,
        ino: f[9].parse().ok()?,
        nlink: f[10].parse().ok()?,
        blocks: f[11].parse().ok()?,
        link_target: if f[12].is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(unescape(f[12])))
        },
    };
    Some((
        item,
        if f[13].is_empty() {
            None
        } else {
            Some(f[13].to_string())
        },
    ))
}

/// Runs `rcp scanbatch` on the fleet, each node listing the subtrees it is given, and
/// merges the entries. `forward` carries the scan options (filters, hashing).
pub fn scan_batches(
    nodes: &[String],
    forward: &[String],
    source: &str,
    subtrees: &[String],
    log: &dyn crate::ports::Log,
) -> io::Result<(Vec<Item>, BTreeMap<String, String>, Vec<String>)> {
    let mut worker = vec!["rcp".to_string(), "scanbatch".to_string()];
    worker.extend(forward.iter().cloned());
    worker.push(source.to_string());
    let batches: Vec<Vec<&String>> = (0..nodes.len().max(1))
        .map(|k| {
            subtrees
                .iter()
                .skip(k)
                .step_by(nodes.len().max(1))
                .collect()
        })
        .collect();
    let _sigpipe = SigpipeGuard::ignore();
    let collected: Mutex<(Vec<Item>, BTreeMap<String, String>, Vec<String>)> =
        Mutex::new((Vec::new(), BTreeMap::new(), Vec::new()));
    std::thread::scope(|scope| {
        for (node, batch) in nodes.iter().zip(batches) {
            if batch.is_empty() {
                continue;
            }
            let (worker, collected) = (&worker, &collected);
            scope.spawn(move || {
                let outcome = (|| -> io::Result<()> {
                    let mut child = launcher(node, worker, &[], log)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .map_err(|e| {
                            io::Error::new(
                                e.kind(),
                                format!("node {node}: cannot start worker: {e}"),
                            )
                        })?;
                    let mut stdin = child.stdin.take().expect("piped");
                    let input: Vec<u8> = batch
                        .iter()
                        .flat_map(|r| r.as_bytes().iter().copied().chain(std::iter::once(0u8)))
                        .collect();
                    let writer = std::thread::spawn(move || {
                        let _ = stdin.write_all(&input);
                    });
                    let stdout = child.stdout.take().expect("piped");
                    for line in BufReader::new(stdout).lines() {
                        let line = line?;
                        if let Some(msg) = line.strip_prefix("error\t") {
                            collected
                                .lock()
                                .unwrap()
                                .2
                                .push(format!("node {node}: {}", unescape(msg)));
                            continue;
                        }
                        match parse_item_line(&line) {
                            Some((item, sha)) => {
                                let mut c = collected.lock().unwrap();
                                if let Some(s) = sha {
                                    c.1.insert(item.rel.clone(), s);
                                }
                                c.0.push(item);
                            }
                            None => {
                                eprintln!("WARN: node {node}: unrecognized listing line {line:?}")
                            }
                        }
                    }
                    let _ = writer.join();
                    let status = child.wait()?;
                    if !status.success() {
                        return Err(io::Error::other(format!(
                            "node {node}: worker exited with {status}"
                        )));
                    }
                    Ok(())
                })();
                if let Err(e) = outcome {
                    collected.lock().unwrap().2.push(e.to_string());
                }
            });
        }
    });
    Ok(collected.into_inner().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(rel: &str, size: u64) -> Item {
        Item {
            rel: rel.into(),
            kind: Kind::File,
            size,
            mtime_ns: 1,
            atime_ns: 2,
            mode: 0o644,
            uid: 3,
            gid: 4,
            dev: 5,
            ino: 6,
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    #[test]
    fn partition_balances_by_size_largest_first() {
        let items = [
            file("a", 100),
            file("b", 60),
            file("c", 50),
            file("d", 10),
            file("e", 1),
        ];
        let refs: Vec<&Item> = items.iter().collect();
        let b = partition(&refs, 2);
        let load = |batch: &Vec<usize>| batch.iter().map(|i| items[*i].size).sum::<u64>();
        assert_eq!((load(&b[0]), load(&b[1])), (111, 110));
        assert_eq!(b[0], vec![0, 3, 4]);
        assert_eq!(partition(&refs, 1)[0].len(), 5);
    }

    #[test]
    fn item_lines_round_trip_with_escaping() {
        let mut i = file("dir with\ttab/na\\me", 7);
        i.link_target = Some("../x\ny".into());
        let line = item_line(&i, Some("abc"));
        let (back, sha) = parse_item_line(&line).unwrap();
        assert_eq!((back, sha.as_deref()), (i, Some("abc")));
        assert!(parse_item_line("garbage").is_none());
    }

    #[test]
    fn launcher_quotes_for_the_remote_shell() {
        let c = launcher(
            "w0",
            &["rcp".into(), "copybatch".into(), "it's".into()],
            &[],
            &crate::ports::Silent,
        );
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec!["-o", "BatchMode=yes", "w0", "'rcp' 'copybatch' 'it'\\''s'"]
        );
        let local = launcher(
            "localhost",
            &["rcp".into(), "copybatch".into()],
            &[],
            &crate::ports::Silent,
        );
        assert_eq!(local.get_program().to_string_lossy(), "rcp");
    }
}
