//! The command contract, exercised through the real binary.
//! Every arm that shows a check passing has a control that shows the same check failing when
//! the defect it guards against is planted; a verify that always says PASSED would pass the
//! happy-path arms on its own.
//!
//! **What "control" means here**, because it is easy to mistake a control that "still passes
//! with the defect replanted" for the defect itself. It is the ARM that must go red when the
//! fix is removed. The control's job is the opposite one: to show the measurement is not
//! vacuous -- that the listener would have been dialed, that the guard admits what it is
//! supposed to admit, that a refusal is about the thing under test and not about a command
//! that never works. A control that also detected the regression would be a second primary
//! assertion, which is fine but is not what the word is doing.
//!
//! So a control is usually the positive half of a pair: `-readonly logdump ID` is refused
//! AND bare `logdump` still reads; a railed run refuses an unnamed away host AND an
//! unrailed one reaches it; `chmod` on a registry is refused AND `chmod` on a directory
//! still works. Without the second half a guard that refused everything would pass every
//! refusal arm while making the command useless -- which is the failure this file is
//! actually protecting against, and it has caught it.
//!
//! An ineffective control is ineffective for a different reason: it measures something the
//! defect does not touch at all. A 429 arm whose control ran a registry with no failing
//! status would prove only that a normal copy works; a permitted-realm control that checked
//! only that a socket opened would not show that the credential arrived. That is the test
//! to apply -- does the control exercise the mechanism -- not whether it independently fails.
//!
//! The contract is the default build's: arms for every endpoint sit side by side and share
//! stand-ins, so the file needs every endpoint feature and is left out of a build without
//! one. That a reduced build compiles is checked by CI's `features` job.
#![cfg(all(
    feature = "nfs",
    feature = "s3",
    feature = "smb",
    feature = "sftp",
    feature = "remote",
    feature = "dav",
    feature = "hdfs",
    feature = "https",
    feature = "oci",
    feature = "tar"
))]

mod support;

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rcp-test-{}-{}-{}", std::process::id(), n, name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.path(rel).display().to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rcp(catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn assert_passed(o: &Output) -> String {
    let out = stdout(o);
    assert!(
        o.status.success(),
        "expected exit 0, got {:?}\n{out}",
        o.status.code()
    );
    assert!(
        out.lines().last() == Some("STATUS: PASSED"),
        "last line must be STATUS: PASSED\n{out}"
    );
    assert!(!out.contains("ERROR:"), "no ERROR lines on success\n{out}");
    out
}

fn assert_failed(o: &Output, needle: &str) -> String {
    let out = stdout(o);
    assert_eq!(o.status.code(), Some(1), "expected exit 1\n{out}");
    assert!(
        out.lines().last() == Some("STATUS: FAILED"),
        "last line must be STATUS: FAILED\n{out}"
    );
    assert!(out.contains("ERROR:"), "an ERROR line is required\n{out}");
    assert!(out.contains(needle), "expected {needle:?} in\n{out}");
    out
}

fn write(path: &Path, content: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn set_times(path: &Path, mtime_secs: u64, atime_secs: u64) {
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_times(
        fs::FileTimes::new()
            .set_modified(UNIX_EPOCH + Duration::from_secs(mtime_secs))
            .set_accessed(UNIX_EPOCH + Duration::from_secs(atime_secs)),
    )
    .unwrap();
}

fn set_mtime(path: &Path, secs: u64) {
    set_times(path, secs, secs)
}

fn fixture(s: &Scratch) -> PathBuf {
    let src = s.path("source");
    write(&src.join("message.txt"), b"hello from the source\n", 0o640);
    write(
        &src.join("nested/deeper/data.bin"),
        &(0u8..=255).cycle().take(300_000).collect::<Vec<u8>>(),
        0o600,
    );
    write(&src.join("script.sh"), b"#!/bin/sh\necho hi\n", 0o755);
    write(&src.join("empty"), b"", 0o644);
    symlink("message.txt", src.join("link-to-message")).unwrap();
    symlink("/nowhere/at/all", src.join("dangling")).unwrap();
    fs::set_permissions(src.join("nested"), fs::Permissions::from_mode(0o750)).unwrap();
    set_mtime(&src.join("message.txt"), 1_600_000_000);
    set_mtime(&src.join("nested/deeper/data.bin"), 1_650_000_123);
    src
}

fn sha256_of(path: &Path) -> String {
    rcp::sha256::digest_hex(&fs::read(path).unwrap())
}

fn euid() -> u32 {
    fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
}

fn uring_available() -> bool {
    stdout(&rcp(Path::new("/tmp"), &["version"])).contains("io_uring: available")
}

#[test]
fn copy_then_verify_preserves_content_modes_links_and_times() {
    let s = Scratch::new("copy");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    let out = rcp(
        &cat,
        &[
            "copy",
            "-parallel",
            "3",
            "-newid",
            "smoke",
            &format!("file://{}", src.display()),
            &format!("file://{}", dst.display()),
        ],
    );
    let text = assert_passed(&out);
    assert!(text.contains("copy: 4 files"), "{text}");
    if uring_available() {
        assert!(
            text.contains("engine io_uring"),
            "the io_uring engine is used when the kernel has it\n{text}"
        );
    }

    for rel in [
        "message.txt",
        "nested/deeper/data.bin",
        "script.sh",
        "empty",
    ] {
        assert_eq!(
            sha256_of(&src.join(rel)),
            sha256_of(&dst.join(rel)),
            "{rel} content"
        );
        let a = fs::metadata(src.join(rel)).unwrap();
        let b = fs::metadata(dst.join(rel)).unwrap();
        assert_eq!(a.mode() & 0o7777, b.mode() & 0o7777, "{rel} mode");
        assert_eq!(
            (a.mtime(), a.mtime_nsec()),
            (b.mtime(), b.mtime_nsec()),
            "{rel} mtime"
        );
    }
    assert_eq!(
        fs::metadata(dst.join("nested")).unwrap().mode() & 0o7777,
        0o750
    );
    assert_eq!(
        fs::read_link(dst.join("link-to-message")).unwrap(),
        PathBuf::from("message.txt")
    );
    assert_eq!(
        fs::read_link(dst.join("dangling")).unwrap(),
        PathBuf::from("/nowhere/at/all")
    );

    let out = rcp(
        &cat,
        &[
            "verify",
            &format!("file://{}", src.display()),
            &format!("file://{}", dst.display()),
        ],
    );
    let text = assert_passed(&out);
    assert!(text.contains("0 differences"), "{text}");

    // the catalog lists every entry with the content hash of what was copied
    let index = fs::read_to_string(cat.join("smoke/index.tsv")).unwrap();
    assert!(index.contains("message.txt\tf\t22\t"), "{index}");
    assert!(
        index.contains(&sha256_of(&src.join("message.txt"))),
        "{index}"
    );
}

#[test]
fn every_engine_produces_the_same_tree() {
    let s = Scratch::new("engines");
    let src = fixture(&s);
    let cat = s.path("catalog");
    for (engine, extra) in [
        ("threads", vec![]),
        ("uring", vec![]),
        ("threads", vec!["-nohash"]),
        ("uring", vec!["-nohash"]),
    ] {
        let dst = s.path(&format!("dst-{engine}-{}", extra.len()));
        let mut args = vec![
            "copy",
            "-newid",
            &*Box::leak(format!("e-{engine}-{}", extra.len()).into_boxed_str()),
            "-engine",
            engine,
        ];
        args.extend(extra.iter().copied());
        args.push(src.to_str().unwrap());
        args.push(dst.to_str().unwrap());
        let text = assert_passed(&rcp(&cat, &args));
        if engine == "uring" && !uring_available() {
            assert!(
                text.contains("WARN: io_uring engine requested but unavailable"),
                "{text}"
            );
        }
        assert_passed(&rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ));
        let index =
            fs::read_to_string(cat.join(format!("e-{engine}-{}/index.tsv", extra.len()))).unwrap();
        let hashed = index
            .lines()
            .any(|l| l.contains(&sha256_of(&src.join("message.txt"))));
        assert_eq!(
            hashed,
            extra.is_empty(),
            "-nohash leaves the catalog without digests\n{index}"
        );
    }
}

/// Under `-bwlimit` the io_uring engine used to open every file its share allowed (up to
/// 16 per worker) and pay the throttle for all of them, sleeping on the ring's only thread,
/// before it reaped a single completion. Files then landed late and all together, and a
/// detached job's catalog stayed empty for most of the run, which failed
/// `a_job_outlives_the_call...` in CI with 0 entries after 20 s.
///
/// Asserted as a count, not a time: when the first file is reported done, how many
/// destination files has the engine already created? The engine creates a file when it
/// starts it, so that count is the number it had in flight. It used to be every file in
/// the tree (20 here); one per worker is the bound, and 2x the worker count allows for a
/// worker that started its next file before the report was read.
#[test]
fn a_rate_limited_uring_copy_finishes_files_as_it_goes() {
    use std::io::BufRead;
    if !uring_available() {
        eprintln!("io_uring is unavailable here; the engine this test is about cannot run");
        return;
    }
    let s = Scratch::new("uring-bw");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    for i in 0..20 {
        write(
            &src.join(format!("f{i}.bin")),
            &noise(100_000, i as u64 + 1),
            0o644,
        );
    }
    let dst = s.path("dst");
    let workers = 2;
    let mut child = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args([
            "-catalog",
            s.path("catalog").to_str().unwrap(),
            "copy",
            "-json",
            "-engine",
            "uring",
            "-parallel",
            &workers.to_string(),
            "-bwlimit",
            "300k",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let files_in = |dir: &Path| {
        fs::read_dir(dir)
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .count()
            })
            .unwrap_or(0)
    };
    let mut started = None;
    let mut seen = Vec::new();
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if line.contains("\"event\":\"entry\"") && line.contains("\"kind\":\"f\"") {
            started = Some(files_in(&dst));
            break;
        }
        seen.push(line);
    }
    let _ = child.kill();
    let _ = child.wait();
    let started =
        started.unwrap_or_else(|| panic!("no file was reported done:\n{}", seen.join("\n")));
    assert!(
        started <= 2 * workers,
        "when the first file was reported done the engine had already started {started} of 20; \
         it is paying the throttle for files it is not finishing (bound {})",
        2 * workers
    );
}

#[test]
fn verify_reports_each_kind_of_difference_and_passes_when_clean() {
    let s = Scratch::new("verify");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "v",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // control: untouched destination passes
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));

    // plant one defect of each kind verify must catch
    fs::write(dst.join("message.txt"), b"hello from the sOurce\n").unwrap(); // same size, different bytes
    fs::set_permissions(dst.join("script.sh"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(dst.join("extra.txt"), b"not in the source").unwrap();
    fs::remove_file(dst.join("empty")).unwrap();
    fs::remove_file(dst.join("link-to-message")).unwrap();
    symlink("script.sh", dst.join("link-to-message")).unwrap();
    let text = assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "destination differs from source",
    );
    for needle in [
        "DIFF content message.txt: first difference at byte 16",
        "DIFF mode script.sh: source 0755, destination 0644",
        "DIFF extra extra.txt",
        "DIFF missing empty",
        "DIFF link link-to-message",
        "DIFF mtime message.txt",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    // the rewrite and the added file bumped two mtimes as well: 5 planted + 2 mtime
    assert!(text.contains("7 differences"), "{text}");
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-nomods",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "5 differences",
    );
    assert!(
        !text.contains("DIFF mtime"),
        "-nomods hides modification times\n{text}"
    );
    // -nodata hides the content difference and nothing else
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-nomods",
                "-nodata",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "4 differences",
    );
    assert!(!text.contains("DIFF content"), "{text}");
    // -v lists every compared entry with a verdict
    let text = assert_failed(
        &rcp(
            &cat,
            &["verify", "-v", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFFERENT f message.txt",
    );
    assert!(text.contains("same f nested/deeper/data.bin"), "{text}");
}

/// The three kinds the arm above does not plant, and `size` is the one that matters.
///
/// Neutering `if s.size != d.size` in `verify_tree` left the whole suite green except for
/// one arm that caught it incidentally, through its JSON. That is not coverage: the
/// content comparison cannot serve as a backstop, because the file list is pre-filtered on
/// `d.size == i.size` before any byte is read -- a size-mismatched file is never queued,
/// so `content.get(rel)` misses and the entry falls through in silence. A destination
/// truncated to one byte per file therefore verified as `0 differences, STATUS: PASSED`.
///
/// `type` and `unreadable` ride along because they are the other two `DIFF` kinds with no
/// arm, and all three are one fixture apart.
#[test]
fn verify_reports_a_size_a_type_and_an_unreadable_difference() {
    let s = Scratch::new("verify-size");
    let src = s.path("source");
    let dst = s.path("destination");
    for d in [&src, &dst] {
        fs::create_dir_all(d).unwrap();
    }
    // three files, three ways for the destination to be wrong about them
    write(
        &src.join("truncated.txt"),
        b"the source holds rather more than one byte\n",
        0o644,
    );
    write(&src.join("wrongkind.txt"), b"a file at the source\n", 0o644);
    write(&src.join("gone.txt"), b"readable at the source\n", 0o644);

    write(&dst.join("truncated.txt"), b"t", 0o644);
    fs::create_dir(dst.join("wrongkind.txt")).unwrap();
    write(&dst.join("gone.txt"), b"readable at the source\n", 0o000);

    let cat = s.path("catalog");
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-noattrs",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "destination differs from source",
    );
    // the length comes from the fixture rather than a literal, so the arm cannot drift
    // into asserting a number nobody maintains
    let n = fs::metadata(src.join("truncated.txt")).unwrap().len();
    assert!(
        text.contains(&format!(
            "DIFF size truncated.txt: source {n} bytes, destination 1 bytes"
        )),
        "no size difference reported:\n{text}"
    );
    assert!(
        text.contains("DIFF type wrongkind.txt"),
        "no type difference reported:\n{text}"
    );

    // THE CONTROL: the same three files, correct. Without it the arm would pass against a
    // verify that reported every entry as different.
    let good = s.path("good");
    fs::create_dir_all(&good).unwrap();
    for (n, b) in [
        (
            "truncated.txt",
            &b"the source holds rather more than one byte\n"[..],
        ),
        ("wrongkind.txt", b"a file at the source\n"),
        ("gone.txt", b"readable at the source\n"),
    ] {
        write(&good.join(n), b, 0o644);
    }
    assert_passed(&rcp(
        &s.path("cat2"),
        &[
            "verify",
            "-noattrs",
            src.to_str().unwrap(),
            good.to_str().unwrap(),
        ],
    ));

    // `unreadable` needs a destination the run genuinely cannot read, and root can read a
    // 0o000 file, so the suite has to say what it measured rather than skip in silence.
    if euid() == 0 {
        eprintln!("SKIP the unreadable arm: running as root, which reads a 0o000 file");
    } else {
        let text = assert_failed(
            &rcp(
                &s.path("cat3"),
                &[
                    "verify",
                    "-noattrs",
                    src.to_str().unwrap(),
                    dst.to_str().unwrap(),
                ],
            ),
            "DIFF unreadable gone.txt",
        );
        assert!(text.contains("gone.txt"), "{text}");
    }
}

#[test]
fn mtime_window_tolerates_rounding_but_not_drift() {
    let s = Scratch::new("window");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "w",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    set_mtime(&dst.join("message.txt"), 1_600_000_001); // one second off
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF mtime message.txt",
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-mtimewindow",
            "2",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // control: the window is a window, not a switch
    set_mtime(&dst.join("message.txt"), 1_600_000_010);
    assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-mtimewindow",
                "2",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "DIFF mtime message.txt",
    );
}

#[test]
fn sparse_input_stays_sparse_on_every_engine() {
    let s = Scratch::new("sparse");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();
    let image = src.join("disk.qcow2");
    {
        let f = fs::File::create(&image).unwrap();
        f.set_len(64 << 20).unwrap(); // 64 MiB hole
        use std::os::unix::fs::FileExt;
        f.write_all_at(b"header", 0).unwrap();
        f.write_all_at(b"tail data", (64 << 20) - 16).unwrap();
        f.write_all_at(&[7u8; 4096], 20 << 20).unwrap();
    }
    let cat = s.path("catalog");
    for (i, extra) in [
        vec!["-engine", "threads"],
        vec!["-engine", "uring"],
        vec!["-engine", "threads", "-nohash"],
    ]
    .iter()
    .enumerate()
    {
        let dst = s.path(&format!("destination{i}"));
        let id = format!("sparse{i}");
        let mut args = vec!["copy", "-newid", &id];
        args.extend(extra.iter().copied());
        args.push(src.to_str().unwrap());
        args.push(dst.to_str().unwrap());
        assert_passed(&rcp(&cat, &args));
        let copied = fs::metadata(dst.join("disk.qcow2")).unwrap();
        assert_eq!(copied.len(), 64 << 20);
        assert!(
            copied.blocks() * 512 < 8 << 20,
            "{extra:?}: destination should be sparse, uses {} bytes",
            copied.blocks() * 512
        );
        assert_eq!(sha256_of(&image), sha256_of(&dst.join("disk.qcow2")));
        assert_passed(&rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ));
    }
    // scan -stats reports the holes
    let text = assert_passed(&rcp(&cat, &["scan", "-stats", src.to_str().unwrap()]));
    assert!(text.contains("sparse:"), "{text}");
}

#[test]
fn resume_finishes_an_interrupted_copy_and_new_ids_are_unique() {
    let s = Scratch::new("resume");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "job",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // the same ID again is refused: two copies must not share a resume record
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "job",
                src.to_str().unwrap(),
                s.path("elsewhere").to_str().unwrap(),
            ],
        ),
        "already exists",
    );

    // simulate an interruption: destination lost a file and a directory, the index still lists them
    fs::remove_file(dst.join("nested/deeper/data.bin")).unwrap();
    fs::remove_dir(dst.join("nested/deeper")).unwrap();
    fs::remove_file(dst.join("script.sh")).unwrap();
    let text = assert_passed(&rcp(&cat, &["resume", "-id", "job"]));
    assert!(
        text.contains("resume: 2 files"),
        "only the missing files are copied\n{text}"
    );
    assert!(text.contains("2 skipped"), "{text}");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));

    // control: an unknown ID is an error, not a silent fresh copy
    assert_failed(&rcp(&cat, &["resume", "-id", "nope"]), "has no catalog");
}

#[test]
fn sync_copies_changes_and_removes_what_the_source_dropped() {
    let s = Scratch::new("sync");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "mirror",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));

    write(
        &src.join("message.txt"),
        b"changed after the first copy\n",
        0o640,
    );
    set_mtime(&src.join("message.txt"), 1_700_000_000);
    write(&src.join("nested/new.txt"), b"added later", 0o644);
    fs::remove_file(src.join("script.sh")).unwrap();
    fs::remove_file(src.join("dangling")).unwrap();
    fs::remove_dir_all(src.join("nested/deeper")).unwrap();

    // control: before sync, verify sees the drift
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF",
    );
    let text = assert_passed(&rcp(&cat, &["sync", "-id", "mirror"]));
    assert!(text.contains("sync: 2 files"), "changed + added\n{text}");
    assert!(
        text.contains("4 removed"),
        "script.sh, dangling, deeper/data.bin, deeper\n{text}"
    );
    assert!(!dst.join("script.sh").exists());
    assert!(!dst.join("nested/deeper").exists());
    assert_eq!(
        fs::read(dst.join("message.txt")).unwrap(),
        b"changed after the first copy\n"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // a second sync is a no-op
    let again = stdout(&rcp(&cat, &["sync", "-id", "mirror"]));
    assert!(
        again.contains("sync: 0 files") && again.contains("0 removed"),
        "{again}"
    );
}

#[test]
fn isync_mirrors_without_a_catalog() {
    let s = Scratch::new("isync");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(
        &cat,
        &["isync", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    assert!(text.contains("isync: 4 files"), "{text}");
    assert!(!text.contains("catalog:"), "isync keeps no catalog\n{text}");
    assert!(stdout(&rcp(&cat, &["indexlist"])).contains("0 catalogs"));

    write(&src.join("message.txt"), b"changed\n", 0o640);
    set_mtime(&src.join("message.txt"), 1_700_000_000);
    write(&src.join("brand/new.txt"), b"new", 0o644);
    fs::remove_file(src.join("script.sh")).unwrap();
    fs::write(dst.join("stray.tmp"), b"only in the destination").unwrap();
    let text = assert_passed(&rcp(
        &cat,
        &["isync", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    assert!(text.contains("isync: 2 files"), "changed + new\n{text}");
    assert!(
        text.contains("2 removed"),
        "script.sh and stray.tmp\n{text}"
    );
    assert!(text.contains("2 skipped"), "data.bin and empty\n{text}");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    let again = assert_passed(&rcp(
        &cat,
        &["isync", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    assert!(
        again.contains("isync: 0 files") && again.contains("0 removed"),
        "{again}"
    );
}

#[test]
fn filters_select_what_is_copied_and_verified() {
    let s = Scratch::new("filters");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("excluded");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "f1",
            "-exclude",
            "*.bin",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(!dst.join("nested/deeper/data.bin").exists(), "excluded");
    assert!(dst.join("nested/deeper").is_dir());
    assert!(dst.join("message.txt").exists());
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-exclude",
            "*.bin",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // control: the same verify without the filter sees the gap
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF missing nested/deeper/data.bin",
    );

    let dst = s.path("matched");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "f2",
            "-match",
            "*.txt",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("copy: 1 files"), "{text}");
    assert!(dst.join("message.txt").exists());
    assert!(!dst.join("script.sh").exists());
    assert!(!dst.join("empty").exists());
    assert!(
        dst.join("nested/deeper").is_dir(),
        "directories pass an include filter"
    );

    let dst = s.path("deep");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "f3",
            "-depth",
            "1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        dst.join("nested").is_dir() && !dst.join("nested/deeper").exists(),
        "-depth 1 stops below the first level"
    );

    // control: a fresh copy with no filter carries everything
    let dst = s.path("all");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "f4",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(dst.join("nested/deeper/data.bin").exists());
}

/// **A name this run did not look at is not a name the source no longer has.** A filter or a
/// depth cap leaves no error behind, so the source listing reads as complete -- and it is
/// complete for what was asked, because the destination is listed through the same filter and
/// cap. Excluded and too-deep destination entries are never candidates for removal; this pins
/// it.
#[test]
fn a_filter_or_depth_cap_on_sync_does_not_remove_what_it_did_not_look_at() {
    let s = Scratch::new("scoped-sync");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("dst");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "base",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let (deep, excluded) = (dst.join("nested/deeper/stray.txt"), dst.join("stray.bin"));
    let (src, dst) = (src.to_str().unwrap(), dst.to_str().unwrap());

    // A FILE THE SOURCE STILL HAS, now outside an attribute filter. `message.txt` is truncated
    // on the source, so `-minsize 1` leaves it out of the copy. If it also left it out of the
    // source listing altogether, its destination copy (still non-empty, still passing) would
    // be planned as a removal: deleted while the source still had the path. Not copied, and
    // not removed.
    let msg = Path::new(src).join("message.txt");
    let before = fs::read(&msg).unwrap();
    fs::write(&msg, b"").unwrap();
    let text = assert_passed(&rcp(&cat, &["isync", "-minsize", "1", src, dst]));
    assert_eq!(
        fs::read(Path::new(dst).join("message.txt")).unwrap(),
        before,
        "a path the source still has was removed or overwritten:\n{text}"
    );
    fs::write(&msg, &before).unwrap();

    // one stray at a time: each is extraneous to the OTHER run, which would rightly remove it
    fs::write(&deep, b"not on the source").unwrap();
    assert_passed(&rcp(&cat, &["isync", "-depth", "1", src, dst]));
    assert!(deep.exists(), "a name below the depth cap was removed");
    fs::remove_file(&deep).unwrap();
    fs::write(&excluded, b"not on the source").unwrap();
    assert_passed(&rcp(&cat, &["isync", "-exclude", "*.bin", src, dst]));
    assert!(excluded.exists(), "an excluded name was removed");
    // and an attribute filter: every fixture file is under 1 MiB, so the source lists none of
    // them -- which is "not this run's", not "gone". The destination is listed through the
    // path patterns only (the confirm rail needs to see every file a copy would replace), so
    // this is the arm that says the removal view still applies the size test.
    let text = assert_passed(&rcp(&cat, &["isync", "-minsize", "1m", src, dst]));
    assert!(
        Path::new(dst).join("message.txt").exists() && text.contains("0 removed"),
        "a file outside -minsize was removed:\n{text}"
    );
    fs::write(&deep, b"not on the source").unwrap();

    // control: unscoped, both are extraneous and go
    let text = assert_passed(&rcp(&cat, &["isync", src, dst]));
    assert!(text.contains("2 removed"), "{text}");
    assert!(!excluded.exists() && !deep.exists());
}

/// **An entry of the wrong kind is replaced, not failed on forever.** A mirror whose destination
/// had a file where the source has a directory failed with "File exists", then "Not a
/// directory" for everything under it, and advised running again -- which failed the same way
/// every time. And a SYMLINK where the source has a directory is worse than a
/// failure: left in place, the copy of the files under it opens through the link and writes
/// wherever it points. Now the entry in the way goes first, in both directions.
#[test]
fn a_mirror_replaces_an_entry_of_the_wrong_kind() {
    let s = Scratch::new("kinds");
    let (src, dst, outside) = (s.path("src"), s.path("dst"), s.path("outside"));
    fs::create_dir_all(src.join("was-file")).unwrap();
    write(&src.join("was-file/x"), b"x\n", 0o644);
    fs::create_dir_all(src.join("was-link")).unwrap();
    write(&src.join("was-link/y"), b"y\n", 0o644);
    write(&src.join("was-dir"), b"now a file\n", 0o644);
    fs::create_dir_all(dst.join("was-dir")).unwrap();
    write(&dst.join("was-dir/old"), b"old\n", 0o644);
    write(
        &dst.join("was-file"),
        b"a file where a directory belongs\n",
        0o644,
    );
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, dst.join("was-link")).unwrap();
    let cat = s.path("catalog");
    let (src_s, dst_s) = (src.to_str().unwrap(), dst.to_str().unwrap());

    let dry = assert_passed(&rcp(&cat, &["isync", "-dryrun", src_s, dst_s]));
    assert!(
        dry.contains("# was-file") && dry.contains("# was-link") && dry.contains("# was-dir"),
        "the plan did not show what is in the way:\n{dry}"
    );
    let text = assert_passed(&rcp(&cat, &["isync", src_s, dst_s]));
    assert_eq!(fs::read(dst.join("was-file/x")).unwrap(), b"x\n", "{text}");
    assert!(
        !fs::symlink_metadata(dst.join("was-link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the symlink is still there\n{text}"
    );
    assert_eq!(fs::read(dst.join("was-link/y")).unwrap(), b"y\n");
    assert!(
        !outside.join("y").exists(),
        "the copy wrote through the destination's symlink\n{text}"
    );
    assert_eq!(fs::read(dst.join("was-dir")).unwrap(), b"now a file\n");
    assert_passed(&rcp(&cat, &["verify", src_s, dst_s]));
    // and it converges: a second run has nothing to do
    let again = assert_passed(&rcp(&cat, &["isync", src_s, dst_s]));
    assert!(
        again.contains("0 files") && again.contains("0 removed"),
        "{again}"
    );

    // An obstacle the FILTER would leave out is still in the way: an empty destination file
    // under `-minsize 1`, where the source has a directory. Judged against the filtered view
    // of the destination it is invisible, and the mkdir fails.
    fs::create_dir_all(src.join("hidden-obstacle")).unwrap();
    write(&src.join("hidden-obstacle/z"), b"z\n", 0o644);
    write(&dst.join("hidden-obstacle"), b"", 0o644);
    let text = assert_passed(&rcp(&cat, &["isync", "-minsize", "1", src_s, dst_s]));
    assert_eq!(
        fs::read(dst.join("hidden-obstacle/z")).unwrap(),
        b"z\n",
        "{text}"
    );
}

/// **An incomplete source listing replaces nothing either.** A wrong-kind replacement is a
/// removal, and a run whose source listing failed says "no removals were planned" -- the
/// replacement must not run anyway, after that sentence. It stays a loud conflict instead.
#[test]
fn an_incomplete_source_listing_replaces_nothing() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("incomplete-kind");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in/sub")).unwrap();
    write(&root.join("in/sub/unseen.txt"), b"u\n", 0o644);
    fs::create_dir_all(root.join("in/d")).unwrap();
    write(&root.join("in/d/x"), b"x\n", 0o644);
    let server = Server::start_with(
        &root,
        Quirks {
            fail_propfind_under: Some("/sub"),
            ..Quirks::default()
        },
    )
    .unwrap();
    let dst = s.path("dst");
    fs::create_dir_all(&dst).unwrap();
    write(
        &dst.join("d"),
        b"a file where the source has a directory\n",
        0o644,
    );
    let cat = s.path("catalog");
    let text = assert_failed(
        &rcp_dav(&cat, &["isync", &server.url("/in"), dst.to_str().unwrap()]),
        "no removals were planned",
    );
    assert_eq!(
        fs::read(dst.join("d")).unwrap(),
        b"a file where the source has a directory\n",
        "a run that planned no removals replaced an entry:\n{text}"
    );
}

/// **A directory the source dropped keeps what a scoped run did not look at.** The case
/// above is a stray inside a directory the source still has; this one is a directory the
/// source no longer has at all, so it IS planned for removal -- and it still holds a name the
/// run excluded, or one below `-depth`. On a local tree the rmdir refuses and that refusal was
/// a failure of the run; on WebDAV a collection DELETE is recursive and took the hidden name
/// with it. Now the directory stays, the run passes, and the name survives, on both.
#[test]
fn a_dropped_directory_keeps_what_a_scoped_run_did_not_look_at() {
    let s = Scratch::new("scoped-rmdir");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    let server = rcp::dav::testserver::Server::start(&root).unwrap();
    let local = s.path("dst");
    let sides: [(&str, String, PathBuf); 2] = [
        ("local", local.display().to_string(), local.clone()),
        ("dav", server.url("/in"), root.join("in")),
    ];
    let src = src.to_str().unwrap();
    for (label, url, disk) in &sides {
        assert_passed(&rcp_dav(&cat, &["copy", "-noId", "-type", "f", src, url]));
        let (deep, excluded) = (disk.join("gone/deep.txt"), disk.join("gone2/x.bin"));
        fs::create_dir_all(deep.parent().unwrap()).unwrap();
        fs::write(&deep, b"below the cap").unwrap();
        let text = assert_passed(&rcp_dav(
            &cat,
            &["isync", "-type", "f", "-depth", "1", src, url],
        ));
        assert!(
            deep.exists(),
            "{label}: removing a dropped directory took a name below -depth with it\n{text}"
        );
        // and it says so: the plan showed the removal, so keeping it is not silent
        assert!(
            text.contains("WARN: gone: left in place"),
            "{label}: the kept directory left no trace\n{text}"
        );
        fs::remove_dir_all(deep.parent().unwrap()).unwrap();

        fs::create_dir_all(excluded.parent().unwrap()).unwrap();
        fs::write(&excluded, b"excluded").unwrap();
        let text = assert_passed(&rcp_dav(
            &cat,
            &["isync", "-type", "f", "-exclude", "*.bin", src, url],
        ));
        assert!(
            excluded.exists(),
            "{label}: removing a dropped directory took an excluded name with it\n{text}"
        );

        // control: unscoped, the directory and what is in it are extraneous and go
        assert_passed(&rcp_dav(&cat, &["isync", "-type", "f", src, url]));
        assert!(
            !excluded.exists() && !disk.join("gone2").exists(),
            "{label}: the unscoped run left the dropped directory"
        );
    }
}

#[test]
fn hard_links_are_preserved_unless_asked_otherwise() {
    let s = Scratch::new("links");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let cat = s.path("catalog");
    let dst = s.path("linked");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "h1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("1 linked") && text.contains("copy: 4 files"),
        "{text}"
    );
    let a = fs::metadata(dst.join("message.txt")).unwrap();
    let b = fs::metadata(dst.join("nested/also-message.txt")).unwrap();
    assert_eq!(
        (a.dev(), a.ino()),
        (b.dev(), b.ino()),
        "one inode in the destination"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));

    let dst = s.path("unlinked");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "h2",
            "-nolinks",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("0 linked") && text.contains("copy: 5 files"),
        "{text}"
    );
    let a = fs::metadata(dst.join("message.txt")).unwrap();
    let b = fs::metadata(dst.join("nested/also-message.txt")).unwrap();
    assert_ne!(a.ino(), b.ino(), "two files");
    // verify knows the difference between a link and a copy, unless told not to care
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF hardlink",
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nolinks",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
}

#[test]
fn extended_attributes_travel_with_the_file() {
    let s = Scratch::new("xattr");
    let src = fixture(&s);
    if rcp::xattr::set(&src.join("message.txt"), "user.rcp.label", b"green").is_err() {
        eprintln!(
            "skipping xattr arm: user attributes unsupported on {}",
            src.display()
        );
        return;
    }
    rcp::xattr::set(&src.join("nested"), "user.rcp.dir", b"yes").unwrap();
    let cat = s.path("catalog");
    let dst = s.path("with");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "x1",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        rcp::xattr::get(&dst.join("message.txt"), "user.rcp.label").unwrap(),
        b"green"
    );
    assert_eq!(
        rcp::xattr::get(&dst.join("nested"), "user.rcp.dir").unwrap(),
        b"yes"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // control: a changed attribute is a difference, and -noxattr hides it
    rcp::xattr::set(&dst.join("message.txt"), "user.rcp.label", b"red").unwrap();
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF xattr message.txt",
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-noxattr",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));

    let dst = s.path("without");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "x2",
            "-noxattr",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        rcp::xattr::list(&dst.join("message.txt"))
            .unwrap()
            .is_empty(),
        "-noxattr copies none"
    );
}

#[test]
fn preserve_atime_keeps_the_source_untouched_and_carries_it_over() {
    let s = Scratch::new("atime");
    let src = fixture(&s);
    set_times(&src.join("message.txt"), 1_600_000_000, 1_500_000_000);
    let cat = s.path("catalog");
    let dst = s.path("kept");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "a1",
            "-preserve-atime",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(src.join("message.txt")).unwrap().atime(),
        1_500_000_000,
        "source atime untouched"
    );
    assert_eq!(
        fs::metadata(dst.join("message.txt")).unwrap().atime(),
        1_500_000_000,
        "destination carries the source atime"
    );
    // control: without the flag the destination's atime is its mtime
    let dst = s.path("plain");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "a2",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(dst.join("message.txt")).unwrap().atime(),
        1_600_000_000
    );
}

#[test]
fn endpoints_are_validated_before_any_write() {
    let s = Scratch::new("endpoints");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    // an NFS endpoint whose host runs no portmapper fails at mount time, before any write
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "a",
                "127.0.0.1:/backup",
                dst.to_str().unwrap(),
            ],
        ),
        "mountd",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "b",
                src.to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "same directory",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "c",
                src.to_str().unwrap(),
                src.join("nested").to_str().unwrap(),
            ],
        ),
        "inside source",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "../escape",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "not a valid name",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-parallel",
                "0",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "at least 1",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-bs",
                "12",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "-bs must be",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-engine",
                "magic",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "-engine",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-chown",
                "-noown",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "contradict",
    );
    assert!(!dst.exists(), "nothing was written by a refused command");
    assert!(!cat.join("a").exists());
    assert!(!cat.join("b").exists());
    // control: the same shape with a valid destination is accepted
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "d",
            "-bs",
            "64k",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
}

#[test]
fn ownership_is_preserved_when_running_as_root() {
    // Only root can set uid and gid, so this arm is a measurement as root and a skip elsewhere.
    if euid() != 0 {
        eprintln!("skipping ownership arm: not root");
        return;
    }
    let s = Scratch::new("owner");
    let src = fixture(&s);
    std::os::unix::fs::chown(src.join("message.txt"), Some(65534), Some(65534)).unwrap();
    std::os::unix::fs::lchown(src.join("link-to-message"), Some(65534), Some(65534)).unwrap();
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "o",
            "-chown",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let m = fs::metadata(dst.join("message.txt")).unwrap();
    assert_eq!((m.uid(), m.gid()), (65534, 65534));
    let l = fs::symlink_metadata(dst.join("link-to-message")).unwrap();
    assert_eq!((l.uid(), l.gid()), (65534, 65534));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // control: a changed owner is a difference, and -noown hides it
    std::os::unix::fs::chown(dst.join("message.txt"), Some(0), Some(0)).unwrap();
    assert_failed(
        &rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ),
        "DIFF owner message.txt",
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-noown",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // chown over a tree
    assert_passed(&rcp(&cat, &["chown", "65534:65534", dst.to_str().unwrap()]));
    assert_eq!(fs::metadata(dst.join("script.sh")).unwrap().uid(), 65534);
    assert_passed(&rcp(
        &cat,
        &["chown", "0", "-match", "*.sh", dst.to_str().unwrap()],
    ));
    assert_eq!(fs::metadata(dst.join("script.sh")).unwrap().uid(), 0);
    assert_eq!(
        fs::metadata(dst.join("empty")).unwrap().uid(),
        65534,
        "unmatched entries keep their owner"
    );
}

#[test]
fn ownership_refusal_is_a_warning_by_default_and_an_error_with_chown() {
    if euid() == 0 {
        eprintln!("skipping non-root ownership arm: root can give files away");
        return;
    }
    let s = Scratch::new("owner-nonroot");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    // a non-root chown to a foreign uid is refused: over a tree, it is an error per entry
    assert_failed(
        &rcp(&cat, &["chown", "0:0", src.to_str().unwrap()]),
        "not permitted",
    );
    // to one's own uid it is a no-op that succeeds
    let me = euid();
    assert_passed(&rcp(
        &cat,
        &["chown", &me.to_string(), src.to_str().unwrap()],
    ));
    // copying one's own files preserves ownership without any warning
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "n1",
            "-chown",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(!text.contains("WARN"), "{text}");
}

#[test]
fn chmod_applies_a_mode_across_a_tree_with_filters() {
    let s = Scratch::new("chmod");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(
        &cat,
        &["chmod", "0600", "-match", "*.txt", src.to_str().unwrap()],
    ));
    assert!(text.contains("chmod: 1 entries changed"), "{text}");
    assert_eq!(
        fs::metadata(src.join("message.txt")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(src.join("script.sh")).unwrap().mode() & 0o7777,
        0o755,
        "unmatched entries keep their mode"
    );
    assert_passed(&rcp(&cat, &["chmod", "0700", src.to_str().unwrap()]));
    assert_eq!(
        fs::metadata(src.join("script.sh")).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(src.join("nested")).unwrap().mode() & 0o7777,
        0o700,
        "directories included"
    );
    assert_failed(
        &rcp(&cat, &["chmod", "rwx", src.to_str().unwrap()]),
        "octal mode",
    );
    assert_failed(
        &rcp(
            &cat,
            &["chown", "alice-no-such-user", src.to_str().unwrap()],
        ),
        "not a number or a known user",
    );
}

#[test]
fn delete_counts_first_and_removes_only_with_force() {
    let s = Scratch::new("delete");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(&cat, &["delete", src.to_str().unwrap()]));
    assert!(
        text.contains("dry run") && text.contains("4 files"),
        "{text}"
    );
    assert!(
        src.join("message.txt").exists(),
        "nothing removed without -force"
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "delete",
            "-force",
            "-exclude",
            "*.bin",
            src.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("3 files"), "{text}");
    assert!(
        src.join("nested/deeper/data.bin").exists(),
        "excluded file survives"
    );
    assert!(!src.join("message.txt").exists());
    assert!(!src.join("dangling").exists());
    assert_passed(&rcp(&cat, &["delete", "-force", src.to_str().unwrap()]));
    assert!(
        src.is_dir() && fs::read_dir(&src).unwrap().next().is_none(),
        "the top directory stays without -removetopdir"
    );
    assert_passed(&rcp(
        &cat,
        &["delete", "-force", "-removetopdir", src.to_str().unwrap()],
    ));
    assert!(!src.exists());
    assert_failed(
        &rcp(&cat, &["delete", "-force", "/"]),
        "refusing to delete /",
    );
}

#[test]
fn blake3_is_the_digest_when_asked_and_sha256_otherwise() {
    let s = Scratch::new("blake3");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let b3 = |rel: &str| rcp::blake3::digest_hex(&fs::read(src.join(rel)).unwrap());
    // scan: the CSV column is named for the digest and carries BLAKE3
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-csv", "-blake3", src.to_str().unwrap()],
    ));
    assert!(text.lines().next().unwrap().ends_with(",blake3"), "{text}");
    assert!(
        text.contains(&format!("message.txt,,{}", b3("message.txt"))),
        "{text}"
    );
    assert!(
        text.contains(&format!("data.bin,,{}", b3("nested/deeper/data.bin"))),
        "the 300 KB file crosses chunk boundaries\n{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-blake3",
            "-fmt",
            "{path} {hash}",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains(&format!("message.txt {}", b3("message.txt"))),
        "{text}"
    );
    // copy: the catalog records the BLAKE3 digest of what was written
    let dst = s.path("dst");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-blake3",
            "-newid",
            "b3",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let index = fs::read_to_string(cat.join("b3/index.tsv")).unwrap();
    assert!(
        index
            .lines()
            .any(|l| l.starts_with("message.txt\tf\t") && l.contains(&b3("message.txt"))),
        "{index}"
    );
    assert!(
        !index.contains(&sha256_of(&src.join("message.txt"))),
        "no SHA-256 when BLAKE3 was asked for\n{index}"
    );
    // control: without the option the digest is SHA-256 and the column says so
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-csv", "-sha256", src.to_str().unwrap()],
    ));
    assert!(text.lines().next().unwrap().ends_with(",sha256"), "{text}");
    assert!(
        text.contains(&format!(
            "message.txt,,{}",
            sha256_of(&src.join("message.txt"))
        )),
        "{text}"
    );
    assert!(stdout(&rcp(&cat, &["version"])).contains("blake3: the blake3 crate"));

    // A catalog's digest column holds hex and one algorithm's worth of meaning, and the
    // column is named `sha256` because for a long time that is all it could be. With four
    // algorithms it is a mixture waiting to happen, and it happened -- measured before
    // this record existed:
    //
    //     copy -newid m -blake3 src dst     ->  a.txt e0e63aa4... (BLAKE3)
    //     sync -id m                        ->  b.txt 7f8b1dfc... (SHA-256)
    //
    // in the same column of the same file, with nothing to tell them apart, and the
    // SHA-256 of a.txt (2c8b08da...) nowhere in it. That mixture is not inert: `scan
    // -edupe` groups files by this column, so two byte-identical files hashed under
    // different algorithms are never grouped, and `sync`'s move detection carries an
    // entry's digest forward to the file it moved to.
    //
    // The catalog records what wrote it, and a later run under a different algorithm is
    // refused by name rather than silently rehashing a tree or silently mixing.
    let head = fs::read_to_string(cat.join("b3/index.tsv")).unwrap();
    assert!(
        head.lines().any(|l| l == "digest\tblake3"),
        "the catalog does not say what wrote it:\n{head}"
    );
    let mixable = s.path("mixable");
    fs::create_dir_all(&mixable).unwrap();
    write(&mixable.join("a.txt"), b"one\n", 0o644);
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "mixed",
            "-blake3",
            mixable.to_str().unwrap(),
            s.path("mixed-dst").to_str().unwrap(),
        ],
    ));
    write(&mixable.join("b.txt"), b"two\n", 0o644);
    let out = rcp(&cat, &["sync", "-id", "mixed"]);
    assert_failed(&out, "was written with blake3 and this run uses sha256");
    assert!(
        stdout(&out).contains("-blake3"),
        "the refusal must name the flag that would work:\n{}",
        stdout(&out)
    );
    // the control, and it is what keeps this from being a guard that refuses everything:
    // the SAME command with the matching flag works, and the column stays one algorithm
    assert_passed(&rcp(&cat, &["sync", "-id", "mixed", "-blake3"]));
    let index = fs::read_to_string(cat.join("mixed/index.tsv")).unwrap();
    for name in ["a.txt", "b.txt"] {
        let want = rcp::blake3::digest_hex(&fs::read(mixable.join(name)).unwrap());
        assert!(
            index.contains(&want),
            "{name} is not in the catalog's own algorithm:\n{index}"
        );
        assert!(
            !index.contains(&sha256_of(&mixable.join(name))),
            "{name} went in as SHA-256 under a BLAKE3 catalog:\n{index}"
        );
    }
    // and a catalog written before the record says so rather than being assumed: the line
    // is absent, the run still works, and it warns -- because a catalog made with -blake3
    // before this existed looks exactly like one made without it
    let older = fs::read_to_string(cat.join("mixed/index.tsv"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("digest\t"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(cat.join("mixed/index.tsv"), format!("{older}\n")).unwrap();
    let out = rcp(&cat, &["sync", "-id", "mixed"]);
    let text = assert_passed(&out);
    assert!(
        text.contains("predates the digest-algorithm record"),
        "an unrecorded algorithm must be said, not assumed:\n{text}"
    );
}

#[test]
fn bwlimit_caps_the_read_rate_on_every_engine() {
    let s = Scratch::new("bwlimit");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();
    // 16 MiB of non-zero bytes (zeros would be holes, which cost no reads)
    let data: Vec<u8> = (0..16u32 << 20).map(|i| (i % 251) as u8 + 1).collect();
    fs::write(src.join("big.bin"), &data).unwrap();
    let cat = s.path("catalog");
    for engine in ["threads", "uring"] {
        let dst = s.path(&format!("dst-{engine}"));
        let start = Instant::now();
        assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-engine",
                engine,
                "-bwlimit",
                "4m",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ));
        let limited = start.elapsed();
        assert!(
            limited >= Duration::from_millis(3500),
            "{engine}: 16 MiB at 4 MiB/s must take about 4 s, took {limited:?}"
        );
        assert_eq!(fs::read(dst.join("big.bin")).unwrap(), data, "{engine}");
        // control: the same copy without the limit is faster than the limited one. Four
        // seconds of headroom, because a loaded machine once stretched a free 16 MiB copy
        // past the two seconds an 8 MiB/s limit allowed and failed a true control
        let free = s.path(&format!("free-{engine}"));
        let start = Instant::now();
        assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-engine",
                engine,
                src.to_str().unwrap(),
                free.to_str().unwrap(),
            ],
        ));
        assert!(
            start.elapsed() < limited,
            "{engine}: unlimited took {:?}, limited {limited:?}",
            start.elapsed()
        );
    }
    // verify reads both sides through the same bucket: 32 MiB at 16 MiB/s
    let start = Instant::now();
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-bwlimit",
            "16m",
            src.to_str().unwrap(),
            s.path("dst-threads").to_str().unwrap(),
        ],
    ));
    assert!(
        start.elapsed() >= Duration::from_millis(1700),
        "verify took {:?}",
        start.elapsed()
    );
    // scan -sha256 reads through it too, and a rate with /s is the same rate
    let start = Instant::now();
    assert_passed(&rcp(
        &cat,
        &["scan", "-sha256", "-bwlimit", "8m/s", src.to_str().unwrap()],
    ));
    assert!(
        start.elapsed() >= Duration::from_millis(1700),
        "scan took {:?}",
        start.elapsed()
    );
    // controls: nonsense and a rate below the floor are refused before anything runs
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-bwlimit",
                "fast",
                src.to_str().unwrap(),
                s.path("x").to_str().unwrap(),
            ],
        ),
        "not a size",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-bwlimit",
                "1k",
                src.to_str().unwrap(),
                s.path("x").to_str().unwrap(),
            ],
        ),
        "at least 4k",
    );
    assert!(!s.path("x").exists());
}

#[test]
fn parallel_auto_tunes_the_worker_count_within_its_ceiling() {
    let s = Scratch::new("auto-parallel");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();
    let block: Vec<u8> = (0..128u32 << 10).map(|i| (i % 253) as u8 + 1).collect();
    for i in 0..400 {
        fs::write(src.join(format!("f{i:03}.bin")), &block).unwrap();
    }
    let cat = s.path("catalog");
    let dst = s.path("dst");
    // 50 MiB at 8 MiB/s is about 6 s. 30 MiB measures only two judged windows, because a
    // window the end of the copy cuts short gets no verdict, and the third knob's turn would
    // ride on that partial window. The margin is the point rather than the arithmetic. At
    // 16 MiB/s this is "three or four windows" for three knobs -- one window of slack -- and on
    // a loaded machine it delivers exactly TWO, moving `workers` then `readers` and ending
    // before `writers` ever gets a turn. The arm then fails for a reason that has nothing to
    // do with the tuner. A bound that needs every window to arrive is not a bound.
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-engine",
            "threads",
            "-parallel",
            "auto:6",
            "-bwlimit",
            "8m",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    let text = assert_passed(&out);
    assert!(text.contains("copy: 400 files"), "{text}");
    let err = String::from_utf8_lossy(&out.stderr);
    // `tune: <knob> <was> -> <now> <decision>, <rate>`
    let moves: Vec<(&str, usize)> = err
        .lines()
        .filter_map(|l| l.split("tune: ").nth(1))
        .filter_map(|l| {
            let mut f = l.split(' ');
            let name = f.next()?;
            let _was = f.next()?;
            let _arrow = f.next()?;
            Some((name, f.next()?.parse().ok()?))
        })
        .collect();
    assert!(moves.len() >= 2, "the tuner reports every window:\n{err}");
    assert!(
        moves.iter().all(|(_, c)| (1..=6).contains(c)),
        "every knob stays within 1..=6: {moves:?}"
    );
    assert!(err.contains("keeping") || err.contains("undoing"), "{err}");
    // Three knobs, not one. `-parallel auto` tunes the workers in flight AND how many of
    // them may be inside a read or a write; a build that reported only `workers` would be
    // the single-knob tuner wearing the new log format.
    for knob in ["workers", "readers", "writers"] {
        assert!(
            moves.iter().any(|(n, _)| *n == knob),
            "no window moved `{knob}`; the tuner is not three-dimensional:\n{err}"
        );
    }
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // controls: a fixed count is never tuned, and a bad ceiling is refused
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-parallel",
            "3",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            s.path("fixed").to_str().unwrap(),
        ],
    );
    assert_passed(&out);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("tune: "));
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-parallel",
                "auto:0",
                src.to_str().unwrap(),
                s.path("x").to_str().unwrap(),
            ],
        ),
        "at least 1",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-parallel",
                "automatic",
                src.to_str().unwrap(),
                s.path("x").to_str().unwrap(),
            ],
        ),
        "auto:N",
    );
}

#[test]
fn scan_reports_counts_listings_stats_and_duplicates() {
    let s = Scratch::new("scan");
    let src = fixture(&s);
    write(
        &src.join("nested/copy-of-message.txt"),
        b"hello from the source\n",
        0o640,
    );
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(&cat, &["scan", src.to_str().unwrap()]));
    assert!(text.contains("5 files, 2 symlinks"), "{text}");
    let text = assert_passed(&rcp(&cat, &["scan", "-l", src.to_str().unwrap()]));
    assert!(
        text.contains("-rwxr-xr-x") && text.contains("link-to-message -> message.txt"),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-csv", "-sha256", src.to_str().unwrap()],
    ));
    assert!(
        text.lines()
            .next()
            .unwrap()
            .starts_with("kind,mode,uid,gid,user,group,size,mtime_ns,nlink,path"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "message.txt,,{}",
            sha256_of(&src.join("message.txt"))
        )),
        "{text}"
    );
    let text = assert_passed(&rcp(&cat, &["scan", "-stats", src.to_str().unwrap()]));
    for needle in [
        "== Files by size ==",
        "== Top file extensions ==",
        ".txt",
        "== Largest files ==",
        "== Largest directories (recursive) ==",
        "== Files by modification age ==",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    let text = assert_passed(&rcp(&cat, &["scan", "-du", src.to_str().unwrap()]));
    assert!(text.contains("300000\tnested/deeper"), "{text}");
    let text = assert_passed(&rcp(&cat, &["scan", "-edupe", src.to_str().unwrap()]));
    assert!(
        text.contains("1 duplicate groups, 1 redundant files, 22 B reclaimable"),
        "{text}"
    );
    assert!(
        text.contains("message.txt nested/copy-of-message.txt"),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-depth", "1", "-q", src.to_str().unwrap()],
    ));
    assert!(
        text.contains("3 files, 2 symlinks"),
        "-depth 1 stops at the first level\n{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-fmt",
            "{kind} {size} {path}",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("f 22 message.txt") && text.contains("l 0 link-to-message"),
        "{text}"
    );
    assert_failed(&rcp(&cat, &["frobnicate"]), "unknown command");
    assert!(stdout(&rcp(&cat, &["license"]))
        .contains("requires no activation; licensed under Apache-2.0"));
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_PORTMAP_PORT", "1")
        .arg("-catalog")
        .arg(&cat)
        .args(["show", "127.0.0.1"])
        .output()
        .unwrap();
    assert_failed(&out, "portmapper");
}

#[test]
fn estimate_projects_from_a_measured_sample() {
    let s = Scratch::new("estimate");
    let src = fixture(&s);
    let text = assert_passed(&rcp(
        &s.path("catalog"),
        &["estimate", "-sample", "100000", src.to_str().unwrap()],
    ));
    assert!(
        text.contains("read sample: 1 files, 293.0 KiB"),
        "the largest file is sampled whole\n{text}"
    );
    assert!(
        text.contains("estimate: data") && text.contains("rough total"),
        "{text}"
    );
}

#[test]
fn catalogs_are_listed_deleted_and_logged() {
    let s = Scratch::new("index");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "keep",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            s.path("other").to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    let text = assert_passed(&rcp(&cat, &["indexlist"]));
    assert!(
        text.contains("keep\t9 entries") && text.contains("1 catalogs"),
        "4 files, 2 links, 3 directories; -noId leaves no catalog\n{text}"
    );
    let text = assert_passed(&rcp(&cat, &["logdump"]));
    assert!(
        text.lines().filter(|l| l.contains("\tcopy\t")).count() == 2
            && text.contains("\tverify\t-\t"),
        "{text}"
    );
    assert!(text.contains("logdump: 3 jobs"), "{text}");
    // `logdump -id` also writes keep.zip: run it from a scratch directory, not the crate
    let cwd = s.path("cwd");
    fs::create_dir_all(&cwd).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .current_dir(&cwd)
        .args(["-catalog", cat.to_str().unwrap(), "logdump", "-id", "keep"])
        .output()
        .unwrap();
    let text = assert_passed(&out);
    assert!(
        text.contains("logdump: 1 jobs") && cwd.join("keep.zip").is_file(),
        "{text}"
    );
    assert_passed(&rcp(&cat, &["indexdelete", "-id", "keep"]));
    assert_failed(
        &rcp(&cat, &["indexdelete", "-id", "keep"]),
        "has no catalog",
    );
    assert_failed(&rcp(&cat, &["resume", "-id", "keep"]), "has no catalog");
    assert!(stdout(&rcp(&cat, &["indexlist"])).contains("0 catalogs"));
}

#[test]
fn a_failed_entry_is_reported_and_the_rest_still_copies() {
    if euid() == 0 {
        eprintln!("skipping unreadable-file arm: root reads everything");
        return;
    }
    let s = Scratch::new("partial");
    let src = fixture(&s);
    fs::set_permissions(src.join("script.sh"), fs::Permissions::from_mode(0o000)).unwrap();
    let dst = s.path("destination");
    let cat = s.path("catalog");
    for engine in ["threads", "uring"] {
        let dst = dst.join(engine);
        let out = rcp(
            &cat,
            &[
                "copy",
                "-newid",
                engine,
                "-engine",
                engine,
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        );
        let text = assert_failed(&out, "copy script.sh");
        assert!(text.contains("copy: 3 files"), "{text}");
        assert_eq!(
            fs::read(dst.join("message.txt")).unwrap(),
            fs::read(src.join("message.txt")).unwrap()
        );
    }
}

#[test]
fn size_and_age_predicates_select_files() {
    let s = Scratch::new("predicates");
    let src = fixture(&s);
    let cat = s.path("catalog");
    // sizes: message.txt 22, script.sh 18, empty 0, data.bin 300000
    let text = assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-q",
            "-minsize",
            "20",
            "-maxsize",
            "1k",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("1 files"),
        "only message.txt is between 20 B and 1 KiB\n{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-q", "-maxsize", "0", src.to_str().unwrap()],
    ));
    assert!(text.contains("1 files"), "only the empty file\n{text}");
    // ages: message.txt and data.bin were set to 2020 and 2022; the rest are new
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-q", "-newer", "1d", src.to_str().unwrap()],
    ));
    assert!(
        text.contains("2 files"),
        "script.sh and empty were written just now\n{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-q", "-older", "1w", src.to_str().unwrap()],
    ));
    assert!(text.contains("2 files"), "message.txt and data.bin\n{text}");
    // the same predicates drive a copy
    let dst = s.path("recent");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-newer",
            "1d",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("copy: 2 files"), "{text}");
    assert!(dst.join("script.sh").exists());
    assert!(!dst.join("message.txt").exists());
    assert_failed(
        &rcp(&cat, &["scan", "-minsize", "huge", src.to_str().unwrap()]),
        "not a size",
    );
    assert_failed(
        &rcp(&cat, &["scan", "-newer", "-3d", src.to_str().unwrap()]),
        "cannot be negative",
    );
    // control: no predicate, every file
    let text = assert_passed(&rcp(&cat, &["scan", "-q", src.to_str().unwrap()]));
    assert!(text.contains("4 files"), "{text}");
}

#[test]
fn dry_run_plans_and_writes_nothing() {
    let s = Scratch::new("dryrun");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-dryrun",
            "-newid",
            "dry",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("copy (dry run, nothing written): 4 files (300040 bytes), 0 skipped, 3 directories, 2 symlinks, 0 removed, 0 linked"), "{text}");
    assert!(!dst.exists(), "nothing written");
    assert!(!cat.join("dry").exists(), "no catalog for a dry run");
    // a dry-run isync shows removals it would make
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    fs::write(dst.join("stray"), b"x").unwrap();
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "isync",
            "-dryrun",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("0 files") && text.contains("2 removed") && text.contains("3 skipped"),
        "stray and the dropped empty file would go\n{text}"
    );
    assert!(
        dst.join("stray").exists() && dst.join("empty").exists(),
        "the dry run removed nothing"
    );
}

#[test]
fn verify_csv_and_scan_html_and_show() {
    let s = Scratch::new("formats");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    fs::remove_file(dst.join("empty")).unwrap();
    fs::write(dst.join("a,b"), b"comma").unwrap();
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-nomods",
                "-csv",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "2 differences",
    );
    assert!(
        text.contains("kind,path,detail\n")
            && text.contains("missing,empty,\n")
            && text.contains("extra,\"a,b\",\n"),
        "{text}"
    );
    assert!(
        !text.contains("DIFF "),
        "csv replaces the DIFF lines\n{text}"
    );
    let text = assert_passed(&rcp(&cat, &["scan", "-html", src.to_str().unwrap()]));
    assert!(
        text.starts_with("<!DOCTYPE html>")
            && text.contains("== Files by size ==")
            && text.contains("</html>"),
        "{text}"
    );
    let text = assert_passed(&rcp(&cat, &["show", "-all"]));
    assert!(
        text.lines().any(|l| l.starts_with("/ ")),
        "the root filesystem is listed\n{text}"
    );
    let text = assert_passed(&rcp(&cat, &["show"]));
    assert!(
        text.contains("network types; -all for every mount"),
        "{text}"
    );
}

#[test]
fn progress_lines_go_to_stderr_only_when_asked() {
    let s = Scratch::new("progress");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-progress",
            src.to_str().unwrap(),
            s.path("a").to_str().unwrap(),
        ],
    );
    assert_passed(&out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("progress: 4/4 files"), "{err}");
    assert!(
        !stdout(&out).contains("progress:"),
        "stdout stays parseable"
    );
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-noprogress",
            src.to_str().unwrap(),
            s.path("b").to_str().unwrap(),
        ],
    );
    assert_passed(&out);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("progress:"));
}

#[test]
fn sync_dry_run_lists_changes_and_checks_the_target() {
    let s = Scratch::new("sync-dry");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "m",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    write(&src.join("message.txt"), b"changed\n", 0o640);
    set_mtime(&src.join("message.txt"), 1_700_000_000);
    write(&src.join("brand/new.txt"), b"new", 0o644);
    fs::remove_file(src.join("script.sh")).unwrap();
    let text = assert_passed(&rcp(&cat, &["sync", "dry-run", "-id", "m"]));
    for needle in [
        "* message.txt",
        "+d brand",
        "+ brand/new.txt",
        "# script.sh",
        "sync dry-run (dry run, nothing written): 2 files",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    assert!(
        dst.join("script.sh").exists() && !dst.join("brand").exists(),
        "nothing changed"
    );
    let quiet = assert_passed(&rcp(&cat, &["sync", "dry-run", "-id", "m", "-q"]));
    assert!(
        !quiet.contains("* message.txt"),
        "-q keeps the listing out\n{quiet}"
    );
    // -target: the destination still matches the index
    assert_passed(&rcp(&cat, &["sync", "dry-run", "-id", "m", "-target"]));
    fs::write(dst.join("empty"), b"no longer empty").unwrap();
    let text = assert_failed(
        &rcp(&cat, &["sync", "dry-run", "-id", "m", "-target"]),
        "index entries no longer match",
    );
    assert!(
        text.contains("? empty: destination changed since the copy"),
        "{text}"
    );
    // -snap: sync from another path standing in for the source
    let snap = s.path("snapshot");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            snap.to_str().unwrap(),
        ],
    ));
    let text = assert_passed(&rcp(
        &cat,
        &["sync", "-id", "m", "-snap", snap.to_str().unwrap()],
    ));
    assert!(
        text.contains(&format!("source {}", snap.display())),
        "{text}"
    );
    assert_eq!(fs::read(dst.join("message.txt")).unwrap(), b"changed\n");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
}

#[test]
fn isync_estimate_reports_the_pending_work() {
    let s = Scratch::new("isync-est");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    write(&src.join("more.bin"), &[1u8; 50_000], 0o644);
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "isync",
            "estimate",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("isync estimate: 1 files (48.8 KiB) to copy, 1 to remove, 3 unchanged"),
        "{text}"
    );
    assert!(text.contains("estimate: about"), "{text}");
    assert!(!dst.join("more.bin").exists(), "an estimate copies nothing");
}

#[test]
fn verify_long_listing_stats_mode_and_nanosecond_tolerance() {
    let s = Scratch::new("verify-forms");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // -stats compares tree statistics, not entries: a same-size content change is invisible
    fs::write(dst.join("message.txt"), b"hello from the sOurce\n").unwrap();
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-stats",
            "-nomods",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let text = assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-stats",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("statistics compared")
            && text.contains("files ")
            && text.contains("directories"),
        "{text}"
    );
    fs::write(dst.join("extra.txt"), b"one more file").unwrap();
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-stats",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "DIFF stats files: source 4, destination 5",
    );
    assert!(text.contains("* files "), "{text}");
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-stats",
                "-csv",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "destination differs from source",
    );
    assert!(
        text.contains("statistic,source,destination,same")
            && text.contains("files,4,5,false")
            && text.contains("directories,3,3,true"),
        "{text}"
    );
    fs::remove_file(dst.join("extra.txt")).unwrap();
    // -l: the differing entry in two lines with stars on the differing fields
    fs::set_permissions(dst.join("script.sh"), fs::Permissions::from_mode(0o600)).unwrap();
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-l",
                "-nomods",
                "-nodata",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "DIFF mode script.sh",
    );
    assert!(
        text.contains("*-rwxr-xr-x") && text.contains("*-rw-------"),
        "{text}"
    );
    assert!(text.contains(" script.sh"), "{text}");
    // a destination whose nanoseconds were dropped is tolerated by default, not with a window
    let secs = fs::metadata(src.join("message.txt")).unwrap().mtime() as u64;
    set_mtime(&dst.join("message.txt"), secs); // whole seconds: ns = 0 (source ns = 0 too here)
    set_times(&src.join("message.txt"), secs, secs);
    let f = fs::File::options()
        .write(true)
        .open(src.join("message.txt"))
        .unwrap();
    f.set_times(
        fs::FileTimes::new()
            .set_modified(UNIX_EPOCH + Duration::from_nanos(secs * 1_000_000_000 + 123_456)),
    )
    .unwrap();
    // control: with data, attributes and times all off, nothing is left to differ
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nodata",
            "-noattrs",
            "-nomods",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-nodata",
                "-noown",
                "-noxattr",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "DIFF mode script.sh",
    );
    assert!(
        text.contains("destination nanoseconds of 0") && !text.contains("DIFF mtime message.txt"),
        "tolerated with a warning\n{text}"
    );
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "verify",
                "-nodata",
                "-mtimewindow",
                "0",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "DIFF mtime message.txt",
    );
    assert!(
        !text.contains("nanoseconds of 0"),
        "an explicit window is strict\n{text}"
    );
}

#[test]
fn scan_saves_and_reads_indexes_formats_and_names() {
    let s = Scratch::new("scan-index");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-newid", "inv", "-sha256", src.to_str().unwrap()],
    ));
    assert!(text.contains("scan index"), "{text}");
    fs::remove_file(src.join("message.txt")).unwrap();
    // the saved index still lists the file that is gone, with its digest
    let text = assert_passed(&rcp(&cat, &["scan", "-id", "inv", "-l"]));
    assert!(
        text.contains("message.txt") && text.contains("saved index inv"),
        "{text}"
    );
    assert!(
        text.contains("2544db72068edd85"),
        "digest recorded in the index\n{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-id", "inv", "-fmt", "{kind}|{size}|{user}|{path}"],
    ));
    assert!(
        text.contains("f|22|root|message.txt")
            || text.contains("f|22|") && text.contains("|message.txt"),
        "{text}"
    );
    let text = assert_passed(&rcp(&cat, &["scan", "-id", "inv", "-stats"]));
    assert!(text.contains("== Files by owner =="), "{text}");
    // names on by default in -l, numbers with -nonames
    let with = assert_passed(&rcp(&cat, &["scan", "-l", src.to_str().unwrap()]));
    let without = assert_passed(&rcp(
        &cat,
        &["scan", "-l", "-nonames", src.to_str().unwrap()],
    ));
    let me = euid();
    let my_name = rcp::names::user(me);
    assert!(without.contains(&format!(" {me:>8} ")), "{without}");
    if my_name != me.to_string() {
        assert!(with.contains(&my_name), "{with}");
    }
    // bare path is scan; -type/-uid filters
    let text = assert_passed(&rcp(&cat, &["-q", src.to_str().unwrap()]));
    assert!(
        text.contains("3 files, 2 symlinks"),
        "bare path scans\n{text}"
    );
    let text = assert_passed(&rcp(&cat, &["scan", "-type", "l", src.to_str().unwrap()]));
    assert!(
        text.contains("0 directories, 0 files, 2 symlinks"),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-type", "f,d", "-q", src.to_str().unwrap()],
    ));
    assert!(
        text.contains("3 directories, 3 files, 0 symlinks"),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-uid", &me.to_string(), "-q", src.to_str().unwrap()],
    ));
    assert!(text.contains("3 files"), "{text}");
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-uid", "4000000000", "-q", src.to_str().unwrap()],
    ));
    assert!(text.contains("0 files"), "{text}");
    assert_failed(
        &rcp(&cat, &["scan", "-type", "x", src.to_str().unwrap()]),
        "use f, d or l",
    );
    assert_failed(
        &rcp(
            &cat,
            &["scan", "-uid", "nobody-like-this", src.to_str().unwrap()],
        ),
        "not a number or a known user",
    );
}

#[test]
fn chown_and_chmod_take_their_flag_forms() {
    let s = Scratch::new("apply-flags");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let me = euid();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "chmod",
            "-mode",
            "0600",
            "-match",
            "*.txt",
            "-v",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("changed message.txt") && text.contains("chmod: 1 entries changed"),
        "{text}"
    );
    assert_eq!(
        fs::metadata(src.join("message.txt")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_passed(&rcp(
        &cat,
        &[
            "chmod",
            "-reference",
            src.join("script.sh").to_str().unwrap(),
            "-match",
            "empty",
            src.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(src.join("empty")).unwrap().mode() & 0o7777,
        0o755,
        "-reference copies the mode of script.sh"
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "chown",
            "-user",
            &me.to_string(),
            "-v",
            src.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("changed message.txt"), "{text}");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "chown",
            "-user",
            &me.to_string(),
            "-user-from",
            "4000000000",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("chown: 0 entries changed"),
        "-user-from selects nothing owned by that uid\n{text}"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "chown",
            "-reference",
            src.join("script.sh").to_str().unwrap(),
            src.to_str().unwrap(),
        ],
    ));
    assert_failed(
        &rcp(
            &cat,
            &["chown", "-user", "no-such-user-here", src.to_str().unwrap()],
        ),
        "not a number or a known user",
    );
    assert_failed(&rcp(&cat, &["chown", src.to_str().unwrap()]), "chown needs");
    assert_failed(&rcp(&cat, &["chmod", src.to_str().unwrap()]), "chmod needs");
}

#[test]
fn estimate_from_an_index_at_a_link_speed_and_with_a_live_copy() {
    let s = Scratch::new("estimate-forms");
    let src = fixture(&s);
    let cat = s.path("catalog");
    assert_passed(&rcp(&cat, &["scan", "-newid", "sc", src.to_str().unwrap()]));
    let text = assert_passed(&rcp(&cat, &["estimate", "-id", "sc", "-gbit", "10"]));
    assert!(
        text.contains("index sc: 3 directories, 4 files, 2 symlinks, 293.0 KiB"),
        "{text}"
    );
    assert!(text.contains("best case 0.0 s at 10 Gbit/s"), "{text}");
    let target = s.path("target");
    fs::create_dir_all(&target).unwrap();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "estimate",
            "-target",
            target.to_str().unwrap(),
            "-t",
            "2s",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("live test copy: 3 files, 293.0 KiB"),
        "the empty file carries no bytes to time\n{text}"
    );
    assert!(
        fs::read_dir(&target).unwrap().next().is_none(),
        "the scratch directory is removed"
    );
    assert_failed(
        &rcp(&cat, &["estimate", "-gbit", "0", src.to_str().unwrap()]),
        "-gbit",
    );
    assert_failed(
        &rcp(&cat, &["estimate", "-t", "soon", src.to_str().unwrap()]),
        "-t",
    );
}

#[test]
fn indexdelete_by_pattern_and_logdump_zip() {
    let s = Scratch::new("index-forms");
    let src = fixture(&s);
    let cat = s.path("catalog");
    for id in ["job-a", "job-b", "other"] {
        assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-newid",
                id,
                src.to_str().unwrap(),
                s.path(id).to_str().unwrap(),
            ],
        ));
    }
    let text = assert_passed(&rcp(&cat, &["indexdelete", "-match", "job-*"]));
    assert!(
        text.contains("removed catalog job-a")
            && text.contains("removed catalog job-b")
            && !text.contains("other"),
        "{text}"
    );
    assert!(stdout(&rcp(&cat, &["indexlist"])).contains("1 catalogs"));
    assert_failed(
        &rcp(&cat, &["indexdelete", "-match", "nothing-*"]),
        "no catalog matches",
    );
    assert_failed(&rcp(&cat, &["indexdelete"]), "needs -id ID or -match GLOB");
    // logdump ID writes ID.zip in the working directory
    let cwd = s.path("cwd");
    fs::create_dir_all(&cwd).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .current_dir(&cwd)
        .args(["-catalog", cat.to_str().unwrap(), "logdump", "other"])
        .output()
        .unwrap();
    let text = assert_passed(&out);
    assert!(
        text.contains("wrote other.zip") && text.contains("logdump: 1 jobs"),
        "{text}"
    );
    let zip = fs::read(cwd.join("other.zip")).unwrap();
    assert_eq!(&zip[..4], &[0x50, 0x4b, 0x03, 0x04], "a zip local header");
    assert!(
        zip.windows(15).any(|w| w == b"other/index.tsv"),
        "the catalog index is inside"
    );
    assert!(
        zip.windows(14).any(|w| w == b"other/jobs.log"),
        "the job lines are inside"
    );

    // That zip is a WRITE, and the rails were not seeing it. `logdump` is the one command
    // whose answer depends on its arguments rather than its name -- with no ID it prints
    // and writes nothing -- so `describe`'s per-name `writes: false` let the ID form
    // straight through. Measured before the fix: `-readonly logdump other` reported
    // PASSED with other.zip on disk, and `-allow` never saw the working directory at all
    // because the working directory is not an endpoint the command was given.
    let logdump = |dir: &Path, args: &[&str]| {
        let mut a = vec!["-catalog", cat.to_str().unwrap()];
        a.extend_from_slice(args);
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .current_dir(dir)
            .args(&a)
            .output()
            .unwrap()
    };
    let fresh = s.path("cwd2");
    fs::create_dir_all(&fresh).unwrap();
    assert_failed(
        &logdump(&fresh, &["-readonly", "logdump", "other"]),
        "read-only",
    );
    assert!(
        !fresh.join("other.zip").exists(),
        "a read-only run wrote the zip anyway"
    );
    // and the control on that refusal: without an ID there is no write, so a read-only
    // run must still be able to read the log. A guard that refused both would pass the
    // line above while breaking the command's whole read-only use.
    let listed = assert_passed(&logdump(&fresh, &["-readonly", "logdump"]));
    assert!(
        listed.contains(" jobs from ") && listed.contains("other"),
        "a read-only logdump with no ID must still read the log:\n{listed}"
    );
    assert!(
        !fresh.join("other.zip").exists(),
        "logdump with no ID wrote a zip"
    );

    let out = logdump(
        &fresh,
        &[
            "-allow",
            s.path("nowhere-near").to_str().unwrap(),
            "logdump",
            "other",
        ],
    );
    assert_failed(&out, "outside the roots");
    assert!(
        !fresh.join("other.zip").exists(),
        "a railed run wrote outside its roots"
    );
    // named the directory it is standing in, it works: the rail is a list, not a ban
    assert_passed(&logdump(
        &fresh,
        &["-allow", fresh.to_str().unwrap(), "logdump", "other"],
    ));
    assert!(fresh.join("other.zip").is_file());

    // The name is chosen by the ID, so the file may already be a symlink somebody else
    // put there. `File::create` followed it and wrote zip bytes through to the target;
    // `O_NOFOLLOW` makes the kernel refuse, which closes the window a stat-first check
    // would leave open.
    let bait = s.path("bait.txt");
    write(&bait, b"not zip bytes\n", 0o644);
    let planted = s.path("cwd3");
    fs::create_dir_all(&planted).unwrap();
    symlink(&bait, planted.join("other.zip")).unwrap();
    assert_failed(&logdump(&planted, &["logdump", "other"]), "is a symlink");
    assert_eq!(
        fs::read(&bait).unwrap(),
        b"not zip bytes\n",
        "the symlink's target was written through"
    );
}

#[test]
fn network_only_features_are_refused_with_a_reason() {
    let s = Scratch::new("refusals");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let dst = s.path("destination");
    // the S3 options are accepted; on a run with no s3:// endpoint they have no effect
    assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-q",
            "-s3.insecure",
            "-s3.endpoint",
            "http://s3.example",
            src.to_str().unwrap(),
        ],
    ));
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env_remove("HDFS_NAMENODE")
        .env_remove("RCP_HDFS_NAMENODE")
        .arg("-catalog")
        .arg(&cat)
        .args(["copy", "hdfs:///demo/src", dst.to_str().unwrap()])
        .output()
        .unwrap();
    assert_failed(&out, "needs the namenode");
    assert!(!dst.exists());
    let text = stdout(&rcp(&cat, &["help", "filters"]));
    assert!(
        text.contains("FILTERS") && text.contains("-minsize 100m"),
        "{text}"
    );
    let text = stdout(&rcp(&cat, &["help", "-match"]));
    assert!(text.contains("FILTERS"), "{text}");
    assert_passed(&rcp(&cat, &["license"]));
    assert_passed(&rcp(&cat, &["activate"]));
}

/// rcp pointed at the in-process stand-in NFS server instead of the portmapper.
fn rcp_nfs(catalog: &Path, port: u16, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_NFS_PORT", port.to_string())
        .env("RCP_MOUNT_PORT", port.to_string())
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

#[test]
fn nfs_endpoints_copy_verify_sync_and_scan_over_the_wire() {
    let s = Scratch::new("nfs");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let nfs_a = "127.0.0.1:/export:/a";

    // local -> NFS, with a catalog that remembers the NFS endpoint
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-newid", "to-nfs", src.to_str().unwrap(), nfs_a],
    ));
    assert!(
        text.contains("copy: 4 files")
            && text.contains("1 linked")
            && text.contains("engine threads"),
        "{text}"
    );
    // the bytes and metadata landed on the server's backing directory
    let backing = export.join("a");
    assert_eq!(
        fs::read(backing.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::metadata(backing.join("script.sh")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(backing.join("message.txt")).unwrap().mtime(),
        1_600_000_000
    );
    assert_eq!(
        fs::read_link(backing.join("dangling")).unwrap(),
        PathBuf::from("/nowhere/at/all")
    );
    let a = fs::metadata(backing.join("message.txt")).unwrap();
    let b = fs::metadata(backing.join("nested/also-message.txt")).unwrap();
    assert_eq!(a.ino(), b.ino(), "hard link recreated through LINK");
    // verify in both directions: local against NFS, NFS against local
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), nfs_a],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", nfs_a, src.to_str().unwrap()],
    ));
    // control: tamper with the backing store, the NFS side shows the difference
    fs::write(backing.join("message.txt"), b"hello from the sOurce\n").unwrap();
    assert_failed(
        &rcp_nfs(
            &cat,
            server.port,
            &["verify", "-nomods", src.to_str().unwrap(), nfs_a],
        ),
        "DIFF content message.txt",
    );
    // sync through the catalog repairs it and removes what the source dropped
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&rcp_nfs(&cat, server.port, &["sync", "-id", "to-nfs"]));
    assert!(
        text.contains("sync: 1 files") && text.contains("1 removed"),
        "{text}"
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), nfs_a],
    ));

    // NFS -> NFS inside the same export, then NFS -> local
    let nfs_b = "127.0.0.1:/export:/b";
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-noId", nfs_a, nfs_b],
    ));
    assert_passed(&rcp_nfs(&cat, server.port, &["verify", nfs_a, nfs_b]));
    let back = s.path("back");
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-noId", nfs_b, back.to_str().unwrap()],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));

    // scan and the reports work on an export
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["scan", "-l", "-stats", "127.0.0.1:/export"],
    ));
    assert!(
        text.contains("a/message.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    // chmod and delete over the wire
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["chmod", "0600", "-match", "*.sh", nfs_b],
    ));
    assert_eq!(
        fs::metadata(export.join("b/script.sh")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["delete", "-force", "-removetopdir", nfs_b],
    ));
    assert!(!export.join("b").exists());
    // A symlink holding a file's name on the export is replaced by the file, as the local tree
    // and SFTP replace one. Not written through, and not left to fail the copy on every run.
    let (over, precious) = (export.join("over"), s.path("precious.txt"));
    fs::create_dir_all(&over).unwrap();
    fs::write(&precious, b"not yours\n").unwrap();
    symlink(&precious, over.join("message.txt")).unwrap();
    let out = rcp_nfs(
        &cat,
        server.port,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/over",
        ],
    );
    assert_eq!(
        fs::read(&precious).unwrap(),
        b"not yours\n",
        "the copy wrote through the export's symlink:\n{}",
        stdout(&out)
    );
    assert_passed(&out);
    assert!(
        fs::symlink_metadata(over.join("message.txt"))
            .unwrap()
            .is_file(),
        "the link was not replaced by the file"
    );
    assert_eq!(
        fs::read(over.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    // The same against a server that REFUSES the create over the link instead of handing the
    // link back, as RFC 1813 allows: the refusal is answered by a lookup, and the link is
    // replaced the same way.
    let strict_export = s.path("strict-export");
    fs::create_dir_all(strict_export.join("over")).unwrap();
    symlink(&precious, strict_export.join("over/message.txt")).unwrap();
    let strict = rcp::nfs::testserver::Server::start_refusing_special_creates(
        &strict_export,
        std::io::ErrorKind::AlreadyExists,
    )
    .unwrap();
    let out = rcp_nfs(
        &cat,
        strict.port,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/over",
        ],
    );
    assert_eq!(
        fs::read(&precious).unwrap(),
        b"not yours\n",
        "the copy wrote through the export's symlink:\n{}",
        stdout(&out)
    );
    assert_passed(&out);
    assert!(
        fs::symlink_metadata(strict_export.join("over/message.txt"))
            .unwrap()
            .is_file(),
        "the refused create left the link"
    );
    // INVAL is not about the name: any bad argument earns it. A link found beside it did not
    // cause it, so it stays, and the copy fails loudly.
    let inval_export = s.path("inval-export");
    fs::create_dir_all(inval_export.join("over")).unwrap();
    symlink(&precious, inval_export.join("over/message.txt")).unwrap();
    let inval = rcp::nfs::testserver::Server::start_refusing_special_creates(
        &inval_export,
        std::io::ErrorKind::InvalidInput,
    )
    .unwrap();
    assert_failed(
        &rcp_nfs(
            &cat,
            inval.port,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                "127.0.0.1:/export:/over",
            ],
        ),
        "invalid argument",
    );
    assert!(
        fs::symlink_metadata(inval_export.join("over/message.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "a link was removed on an INVAL that was not about it"
    );
    assert_eq!(fs::read(&precious).unwrap(), b"not yours\n");
    // A dry run into a directory that is not there yet, two levels deep, plans against an
    // empty one and creates nothing, over both protocol versions. It failed at open, because
    // the mount resolves the root component by component and refused the first missing one.
    for vers in ["3", "4"] {
        let dry = assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &[
                "isync",
                "-dryrun",
                "-nfs.vers",
                vers,
                "-type",
                "f",
                src.to_str().unwrap(),
                "127.0.0.1:/export:/fresh/deeper",
            ],
        ));
        assert!(
            dry.contains("+ message.txt"),
            "v{vers}: the dry run did not plan the copy:\n{dry}"
        );
        assert!(
            !export.join("fresh").exists(),
            "v{vers}: a dry run created the destination\n{dry}"
        );
        // a missing SOURCE is still an error, not an empty tree
        assert_failed(
            &rcp_nfs(
                &cat,
                server.port,
                &["scan", "-nfs.vers", vers, "127.0.0.1:/export:/fresh/deeper"],
            ),
            "no such file",
        );
    }
    // bad endpoints fail before any write
    assert_failed(
        &rcp_nfs(
            &cat,
            server.port,
            &[
                "copy",
                "-noId",
                "127.0.0.1:/export:/missing",
                back.to_str().unwrap(),
            ],
        ),
        "no such file",
    );
    assert_failed(
        &rcp_nfs(&cat, server.port, &["copy", "-noId", nfs_a, nfs_a]),
        "same export path",
    );
    assert_failed(
        &rcp_nfs(
            &cat,
            server.port,
            &["copy", "-noId", "127.0.0.1:/export", nfs_a],
        ),
        "inside source",
    );
}

#[test]
fn nfs_endpoints_carry_posix_acls_through_the_nfsacl_program() {
    use rcp::nfs::acl::{self, Entry};
    let s = Scratch::new("nfs-acl");
    let src = s.path("source");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("f"), b"acl bytes\n").unwrap();
    fs::write(src.join("d/inner"), b"inner\n").unwrap();
    // an extended access ACL (a named user and a mask) and a three-entry default ACL
    let access = acl::to_xattr(&[
        Entry {
            tag: acl::ACL_USER_OBJ,
            perm: 6,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_USER,
            perm: 4,
            id: 12345,
        },
        Entry {
            tag: acl::ACL_GROUP_OBJ,
            perm: 4,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_MASK,
            perm: 4,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_OTHER,
            perm: 0,
            id: u32::MAX,
        },
    ]);
    // The directory gets an access ACL of its own, with execute. It was given the FILE's
    // (owner `rw-`), which leaves a directory nobody but root can enter: the release
    // workflow's first non-root run failed to list `d/inner` with "Permission denied".
    // Root ignores the missing bit, which is why this passed locally.
    let dir_access = acl::to_xattr(&[
        Entry {
            tag: acl::ACL_USER_OBJ,
            perm: 7,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_USER,
            perm: 5,
            id: 12345,
        },
        Entry {
            tag: acl::ACL_GROUP_OBJ,
            perm: 5,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_MASK,
            perm: 5,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_OTHER,
            perm: 0,
            id: u32::MAX,
        },
    ]);
    let default = acl::to_xattr(&[
        Entry {
            tag: acl::ACL_USER_OBJ,
            perm: 7,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_GROUP_OBJ,
            perm: 5,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_OTHER,
            perm: 5,
            id: u32::MAX,
        },
    ]);
    if rcp::xattr::set(&src.join("f"), acl::ACCESS_NAME, &access).is_err() {
        eprintln!(
            "skipping NFSACL arm: POSIX ACLs unsupported on {}",
            src.display()
        );
        return;
    }
    rcp::xattr::set(&src.join("d"), acl::ACCESS_NAME, &dir_access).unwrap();
    rcp::xattr::set(&src.join("d"), acl::DEFAULT_NAME, &default).unwrap();
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let nfs_a = "127.0.0.1:/export:/a";

    // local -> NFS: the ACLs land on the server's backing directory, nothing is refused
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-newid", "acl-to-nfs", src.to_str().unwrap(), nfs_a],
    ));
    assert!(!text.contains("refused"), "{text}");
    let backing = export.join("a");
    assert_eq!(
        rcp::xattr::get(&backing.join("f"), acl::ACCESS_NAME).unwrap(),
        access
    );
    assert_eq!(
        rcp::xattr::get(&backing.join("d"), acl::ACCESS_NAME).unwrap(),
        dir_access
    );
    assert_eq!(
        rcp::xattr::get(&backing.join("d"), acl::DEFAULT_NAME).unwrap(),
        default
    );
    // the mode survived the ACL (the ACL's mask is what the group bits show)
    assert_eq!(
        fs::metadata(backing.join("f")).unwrap().mode() & 0o777,
        0o640
    );
    // verify reads them back over the wire in both directions
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), nfs_a],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", nfs_a, src.to_str().unwrap()],
    ));
    // control: a changed ACL on the server is a difference, seen through GETACL (the mask
    // is left alone, since the kernel derives the group mode bits from it)
    let changed = acl::to_xattr(&[
        Entry {
            tag: acl::ACL_USER_OBJ,
            perm: 6,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_USER,
            perm: 6,
            id: 12345,
        },
        Entry {
            tag: acl::ACL_GROUP_OBJ,
            perm: 4,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_MASK,
            perm: 4,
            id: u32::MAX,
        },
        Entry {
            tag: acl::ACL_OTHER,
            perm: 0,
            id: u32::MAX,
        },
    ]);
    rcp::xattr::set(&backing.join("f"), acl::ACCESS_NAME, &changed).unwrap();
    assert_failed(
        &rcp_nfs(&cat, server.port, &["verify", src.to_str().unwrap(), nfs_a]),
        "DIFF xattr f",
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", "-noxattr", src.to_str().unwrap(), nfs_a],
    ));
    // sync plans on size and time, as it does locally, so an attribute drift alone is not
    // recopied; a changed file is, and its ACL goes with it through SETACL
    let text = assert_passed(&rcp_nfs(&cat, server.port, &["sync", "-id", "acl-to-nfs"]));
    assert!(text.contains("sync: 0 files"), "{text}");
    fs::write(src.join("f"), b"acl bytes, second version\n").unwrap();
    let text = assert_passed(&rcp_nfs(&cat, server.port, &["sync", "-id", "acl-to-nfs"]));
    assert!(text.contains("sync: 1 files"), "{text}");
    assert_eq!(
        rcp::xattr::get(&backing.join("f"), acl::ACCESS_NAME).unwrap(),
        access
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), nfs_a],
    ));
    // NFS -> local brings them back byte for byte
    let back = s.path("back");
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-noId", nfs_a, back.to_str().unwrap()],
    ));
    assert_eq!(
        rcp::xattr::get(&back.join("f"), acl::ACCESS_NAME).unwrap(),
        access
    );
    assert_eq!(
        rcp::xattr::get(&back.join("d"), acl::DEFAULT_NAME).unwrap(),
        default
    );
    // a file with no extended ACL lists no attribute over the wire, as it would locally
    assert!(rcp::xattr::list(&back.join("d/inner")).unwrap().is_empty());
    // show lists the program among the server's RPC services
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_PORTMAP_PORT", server.port.to_string())
        .arg("-catalog")
        .arg(&cat)
        .args(["show", "127.0.0.1"])
        .output()
        .unwrap();
    let text = assert_passed(&out);
    assert!(text.contains("nfs_acl"), "{text}");

    // control: a server without the NFSACL program refuses the attributes out loud
    let export2 = s.path("export2");
    fs::create_dir_all(&export2).unwrap();
    let plain = rcp::nfs::testserver::Server::start_with_acl(&export2, false).unwrap();
    let text = assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/p",
        ],
    ));
    assert!(text.contains("3 extended attributes refused"), "{text}");
    assert!(rcp::xattr::list(&export2.join("p/f")).unwrap().is_empty());
    assert_failed(
        &rcp_nfs(
            &cat,
            plain.port,
            &["verify", src.to_str().unwrap(), "127.0.0.1:/export:/p"],
        ),
        "DIFF xattr f",
    );
    assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &[
            "verify",
            "-noxattr",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/p",
        ],
    ));
}

#[test]
fn acl4_carries_nfsv4_acls_between_exports_over_the_v4_sidecar() {
    use rcp::nfs::testserver::NFS4_ACL_BACKING_NAME as BACKING;
    use rcp::nfs::v4;
    let s = Scratch::new("nfs-acl4");
    let export = s.path("export");
    fs::create_dir_all(export.join("a/d")).unwrap();
    fs::write(export.join("a/f"), b"v4 acl bytes\n").unwrap();
    fs::write(export.join("a/d/g"), b"inner\n").unwrap();
    let acl = v4::encode_aces(&[
        (0, 0, 0x1601bf, "OWNER@"),
        (0, 0x40, 0x120089, "GROUP@"),
        (0, 0, 0x1200a9, "alice@example.net"),
        (1, 0, 0x2, "EVERYONE@"),
    ]);
    if rcp::xattr::set(&export.join("a/f"), BACKING, &acl).is_err() {
        eprintln!(
            "skipping -acl4 arm: user attributes unsupported on {}",
            export.display()
        );
        return;
    }
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let (nfs_a, nfs_b, nfs_c) = (
        "127.0.0.1:/export:/a",
        "127.0.0.1:/export:/b",
        "127.0.0.1:/export:/c",
    );

    // export -> export with -acl4: the ACL is read with GETATTR and written with SETATTR
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-acl4", "-newid", "acl4", nfs_a, nfs_b],
    ));
    assert!(!text.contains("refused"), "{text}");
    assert_eq!(rcp::xattr::get(&export.join("b/f"), BACKING).unwrap(), acl);
    // a file with no ACL of its own has the mode-derived one, which travels too
    assert_eq!(
        rcp::xattr::get(&export.join("b/d/g"), BACKING).unwrap(),
        v4::aces_from_mode(0o644, false)
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", "-acl4", nfs_a, nfs_b],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", "-acl4", nfs_b, nfs_a],
    ));
    // control: a changed ACL is a difference under -acl4 and invisible without it
    let other = v4::encode_aces(&[
        (0, 0, 0x1601bf, "OWNER@"),
        (0, 0x40, 0x120089, "GROUP@"),
        (0, 0, 0x120089, "EVERYONE@"),
    ]);
    rcp::xattr::set(&export.join("b/f"), BACKING, &other).unwrap();
    assert_failed(
        &rcp_nfs(&cat, server.port, &["verify", "-acl4", nfs_a, nfs_b]),
        "DIFF xattr f",
    );
    assert_passed(&rcp_nfs(&cat, server.port, &["verify", nfs_a, nfs_b]));
    // control: without -acl4 nothing is asked for and nothing is refused
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-noId", nfs_a, nfs_c],
    ));
    assert!(!text.contains("refused"), "{text}");
    assert!(rcp::xattr::get(&export.join("c/f"), BACKING).is_err());
    // the sidecar's handles follow a replaced directory: remove b/d on the server, sync recreates it
    fs::remove_dir_all(export.join("b/d")).unwrap();
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["sync", "-acl4", "-id", "acl4"],
    ));
    assert!(text.contains("sync: 1 files"), "{text}");
    assert_eq!(
        rcp::xattr::get(&export.join("b/d/g"), BACKING).unwrap(),
        v4::aces_from_mode(0o644, false)
    );
    // control: -acl4 against a server without v4 is refused before anything is planned
    let export2 = s.path("export2");
    fs::create_dir_all(export2.join("a")).unwrap();
    fs::write(export2.join("a/f"), b"no v4 here\n").unwrap();
    let plain = rcp::nfs::testserver::Server::start_with_acl(&export2, false).unwrap();
    assert_failed(
        &rcp_nfs(
            &cat,
            plain.port,
            &["copy", "-acl4", "-noId", nfs_a, "127.0.0.1:/export:/p"],
        ),
        "-acl4",
    );
    assert!(!export2.join("p").exists());
    // and without the option the same server serves the same copy
    assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &["copy", "-noId", nfs_a, "127.0.0.1:/export:/p"],
    ));
    assert_eq!(fs::read(export2.join("p/f")).unwrap(), b"no v4 here\n");
}

#[test]
fn loglevel_debug_writes_events_to_stderr_and_dircount_reaches_readdirplus() {
    let s = Scratch::new("loglevel");
    let src = fixture(&s);
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_NFS_PORT", server.port.to_string())
            .env("RCP_MOUNT_PORT", server.port.to_string())
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .expect("rcp runs")
    };
    // DEBUG: the endpoints, the server's ports and programs, and the dircount in force
    let out = run(&[
        "copy",
        "-noId",
        "-loglevel",
        "debug",
        "-dircount",
        "8k",
        src.to_str().unwrap(),
        "127.0.0.1:/export:/a",
    ]);
    assert_passed(&out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DEBUG copy "), "{err}");
    assert!(
        err.contains("DEBUG open 127.0.0.1:/export:/a (nfs, create)"),
        "{err}"
    );
    assert!(
        err.contains("dircount 8192") && err.contains("nfsacl port") && err.contains("v4 off"),
        "{err}"
    );
    assert!(
        !stdout(&out).contains("DEBUG"),
        "the report on stdout carries no debug lines"
    );
    // INFO, the default, writes nothing
    let out = run(&[
        "verify",
        "-loglevel",
        "INFO",
        src.to_str().unwrap(),
        "127.0.0.1:/export:/a",
    ]);
    assert_passed(&out);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("DEBUG"));
    let out = run(&["verify", src.to_str().unwrap(), "127.0.0.1:/export:/a"]);
    assert_passed(&out);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("DEBUG"));
    // controls: an unknown level and an unreasonable dircount are refused
    assert_failed(
        &run(&["scan", "-loglevel", "TRACE", src.to_str().unwrap()]),
        "use INFO or DEBUG",
    );
    assert_failed(
        &run(&["scan", "-dircount", "17", "127.0.0.1:/export"]),
        "-dircount must be between",
    );
    assert_failed(
        &run(&["scan", "-dircount", "lots", "127.0.0.1:/export"]),
        "-dircount",
    );
    // S3 requests are logged with their status too
    let s3 = rcp::s3::testserver::Server::start(&["dbg"], s3_creds());
    let out = rcp_s3(
        &cat,
        &s3,
        &s3_creds().secret_key,
        &[
            "copy",
            "-noId",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            "s3://dbg/in",
        ],
    );
    assert_passed(&out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("DEBUG s3 PUT ") && err.contains(": 200"),
        "{err}"
    );
}

#[test]
fn kerberos_contexts_establish_through_the_kdc_and_protect_messages() {
    use rcp::gss::*;
    let Some(_kdc) = support::kdc() else { return };
    match available() {
        Ok(()) => {}
        Err(e) => panic!("the GSSAPI library must load where the KDC tools are installed: {e}"),
    }
    let cred = AcceptorCred::acquire().unwrap();
    // krb5 with mutual authentication: two initiator steps, one acceptor step
    let mut init = Context::initiator(
        "nfs@127.0.0.1",
        Mech::Krb5,
        GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG,
    )
    .unwrap();
    let mut acc = Context::acceptor().unwrap();
    let s1 = init.init_step(None).unwrap();
    assert!(!s1.complete);
    assert!(!s1.token.is_empty());
    let a1 = acc.accept_step(&cred, &s1.token).unwrap();
    assert!(
        a1.complete && !a1.token.is_empty(),
        "mutual authentication returns a token"
    );
    assert_eq!(acc.peer.as_deref(), Some("rcpuser@RCP.TEST"));
    let s2 = init.init_step(Some(&a1.token)).unwrap();
    assert!(s2.complete);
    assert!(s2.token.is_empty());
    // integrity: a MIC verifies the bytes it was made over and nothing else
    let mic = init.mic(b"rpc header").unwrap();
    acc.verify_mic(b"rpc header", &mic).unwrap();
    assert!(acc.verify_mic(b"rpc header!", &mic).is_err());
    // privacy: the wrapped bytes do not carry the text, and unwrap returns it
    let wrapped = init.wrap(b"the secret body", true).unwrap();
    assert!(!wrapped.windows(15).any(|w| w == b"the secret body"));
    assert_eq!(acc.unwrap(&wrapped, true).unwrap(), b"the secret body");
    // both directions
    let back = acc.wrap(b"reply", true).unwrap();
    assert_eq!(init.unwrap(&back, true).unwrap(), b"reply");
    // And the control on the new `conf` argument: under krb5p the receiver demands that
    // the token it was handed was actually SEALED. An integrity-only token carries the
    // plaintext in the clear, so accepting one where privacy was negotiated is a silent
    // downgrade -- the body is readable on the wire and nothing says so.
    let integrity_only = init.wrap(b"the secret body", false).unwrap();
    assert!(
        integrity_only.windows(15).any(|w| w == b"the secret body"),
        "an unsealed token carries its plaintext"
    );
    assert!(
        acc.unwrap(&integrity_only, true).is_err(),
        "krb5p must refuse an integrity-only token"
    );
    // a FRESH token for the control: a GSS context tracks sequence numbers, so replaying
    // the one just refused measures replay detection instead of the conf check
    let integrity_again = init.wrap(b"the secret body", false).unwrap();
    assert_eq!(
        acc.unwrap(&integrity_again, false).unwrap(),
        b"the secret body",
        "and krb5i must still accept one"
    );
    // SPNEGO toward the HTTP service, as a WebHDFS namenode negotiates
    let mut si = Context::initiator("HTTP@127.0.0.1", Mech::Spnego, GSS_C_MUTUAL_FLAG).unwrap();
    let mut sa = Context::acceptor().unwrap();
    let t1 = si.init_step(None).unwrap();
    let r1 = sa.accept_step(&cred, &t1.token).unwrap();
    assert_eq!(sa.peer.as_deref(), Some("rcpuser@RCP.TEST"));
    if !t1.complete {
        let t2 = si.init_step(Some(&r1.token)).unwrap();
        assert!(t2.complete, "SPNEGO completes on the second step");
    }
    // control: a service the KDC does not know is refused at the first step
    let mut bad =
        Context::initiator("nfs@unknown.rcp.test", Mech::Krb5, GSS_C_MUTUAL_FLAG).unwrap();
    let err = bad.init_step(None).unwrap_err();
    assert!(err.to_string().contains("GSS major"), "{err}");
}

#[test]
fn nfs_endpoints_over_kerberos_with_authentication_integrity_and_privacy() {
    let Some(_kdc) = support::kdc() else { return };
    let s = Scratch::new("nfs-krb5");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start_kerberized(&export).unwrap();
    let cat = s.path("catalog");
    for sec in ["krb5", "krb5i", "krb5p"] {
        let dest = format!("127.0.0.1:/export:/{sec}");
        let text = assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &[
                "copy",
                "-noId",
                "-nfs.sec",
                sec,
                "-loglevel",
                "DEBUG",
                "-parallel",
                "3",
                src.to_str().unwrap(),
                &dest,
            ],
        ));
        assert!(
            text.contains("copy: 4 files") && text.contains("1 linked"),
            "{sec}: {text}"
        );
        assert_eq!(
            fs::read(export.join(sec).join("message.txt")).unwrap(),
            b"hello from the source\n",
            "{sec}"
        );
        assert_eq!(
            fs::read(export.join(sec).join("nested/deeper/data.bin"))
                .unwrap()
                .len(),
            300_000,
            "{sec}"
        );
        assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &["verify", "-nfs.sec", sec, src.to_str().unwrap(), &dest],
        ));
        assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &["verify", "-nfs.sec", sec, &dest, src.to_str().unwrap()],
        ));
        // the NFSACL and NFSv4 sidecars ride the same Kerberos context
        assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &["scan", "-acl4", "-nfs.sec", sec, &dest],
        ));
        let text = assert_passed(&rcp_nfs(
            &cat,
            server.port,
            &["scan", "-l", "-nfs.sec", sec, &dest],
        ));
        assert!(text.contains("message.txt"), "{text}");
    }
    // NFSv4 as the data protocol rides the same RPCSEC_GSS context
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "copy",
            "-noId",
            "-nfs.sec",
            "krb5i",
            "-nfs.vers",
            "4",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/v4",
        ],
    ));
    assert!(
        text.contains("copy: 4 files") && text.contains("1 linked"),
        "{text}"
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "verify",
            "-nfs.sec",
            "krb5p",
            "-nfs.vers",
            "4",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/v4",
        ],
    ));
    // privacy hides the file bytes on the wire: capture what the server received in the
    // clear by reading the backing store is trivially the plaintext, so instead check the
    // DEBUG line names the security and the context was established once per connection
    let out = rcp_nfs(
        &cat,
        server.port,
        &[
            "scan",
            "-nfs.sec",
            "krb5p",
            "-loglevel",
            "DEBUG",
            "127.0.0.1:/export:/krb5p",
        ],
    );
    assert_passed(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("sec krb5p"));
    // controls: AUTH_SYS is refused as too weak by an export that wants Kerberos; a
    // Kerberos request without a ticket fails before anything is planned; an unknown
    // flavor is a usage error
    assert_failed(
        &rcp_nfs(
            &cat,
            server.port,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                "127.0.0.1:/export:/sys",
            ],
        ),
        "too weak",
    );
    assert!(!export.join("sys").exists());
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_NFS_PORT", server.port.to_string())
        .env("RCP_MOUNT_PORT", server.port.to_string())
        .env("KRB5CCNAME", "FILE:/nonexistent/no-ticket-cache")
        .arg("-catalog")
        .arg(&cat)
        .args([
            "copy",
            "-noId",
            "-nfs.sec",
            "krb5",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/noticket",
        ])
        .output()
        .unwrap();
    let text = assert_failed(&out, "GSS major");
    assert!(text.contains("nfs@127.0.0.1"), "{text}");
    assert!(!export.join("noticket").exists());
    assert_failed(
        &rcp_nfs(
            &cat,
            server.port,
            &["scan", "-nfs.sec", "ntlm", "127.0.0.1:/export"],
        ),
        "use sys, krb5, krb5i or krb5p",
    );
    // RCP_NFS_SEC in the environment is the same as the option
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_NFS_PORT", server.port.to_string())
        .env("RCP_MOUNT_PORT", server.port.to_string())
        .env("RCP_NFS_SEC", "krb5i")
        .arg("-catalog")
        .arg(&cat)
        .args(["scan", "127.0.0.1:/export:/krb5i"])
        .output()
        .unwrap();
    assert_passed(&out);
    // a plain export still takes AUTH_SYS, and takes Kerberos too when asked
    let plain_root = s.path("plain");
    fs::create_dir_all(&plain_root).unwrap();
    let plain = rcp::nfs::testserver::Server::start(&plain_root).unwrap();
    assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/a",
        ],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &[
            "verify",
            "-nfs.sec",
            "krb5",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/a",
        ],
    ));
}

#[test]
fn hdfs_endpoints_over_kerberos_negotiate_once_and_keep_the_cookie() {
    let Some(_kdc) = support::kdc() else { return };
    let s = Scratch::new("hdfs-krb5");
    let src = fixture(&s);
    fs::remove_file(src.join("dangling")).ok();
    let root = s.path("hdfs-root");
    fs::create_dir_all(&root).unwrap();
    let server = rcp::hdfs::testserver::Server::start_kerberized(&root).unwrap();
    let cat = s.path("catalog");
    let out = rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            "hdfs:///in",
        ],
    );
    let text = assert_passed(&out);
    assert!(text.contains("copy: 4 files"), "{text}");
    assert_eq!(
        fs::read(root.join("in/message.txt")).unwrap(),
        b"hello from the source\n"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Kerberos negotiated, hadoop.auth cookie kept"),
        "{err}"
    );
    // one negotiation per process: the cookie carries every later request
    assert_eq!(err.matches("Kerberos negotiated").count(), 1, "{err}");
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["verify", "-type", "f", src.to_str().unwrap(), "hdfs:///in"],
    ));
    // control: no ticket, no access, and the error says what was wanted
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("HDFS_NAMENODE", format!("127.0.0.1:{}", server.port))
        .env("NO_PROXY", "*")
        .env("KRB5CCNAME", "FILE:/nonexistent/no-ticket-cache")
        .arg("-catalog")
        .arg(&cat)
        .args(["scan", "hdfs:///in"])
        .output()
        .unwrap();
    assert_failed(&out, "wants Kerberos (Negotiate)");
}

#[test]
fn nfs_sparse_files_and_large_pipelined_writes_survive_the_wire() {
    let s = Scratch::new("nfs-sparse");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("disk.img")).unwrap();
        f.set_len(48 << 20).unwrap();
        f.write_all_at(b"start", 0).unwrap();
        f.write_all_at(&[9u8; 3 << 20], 16 << 20).unwrap(); // 3 MiB: several WRITEs in flight
        f.write_all_at(b"end", (48 << 20) - 3).unwrap();
    }
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "copy",
            "-noId",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            "127.0.0.1:/export",
        ],
    ));
    let copied = fs::metadata(export.join("disk.img")).unwrap();
    assert_eq!(copied.len(), 48 << 20);
    assert!(
        copied.blocks() * 512 < 6 << 20,
        "holes are not written over NFS either, uses {}",
        copied.blocks() * 512
    );
    assert_eq!(
        sha256_of(&src.join("disk.img")),
        sha256_of(&export.join("disk.img"))
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["verify", src.to_str().unwrap(), "127.0.0.1:/export"],
    ));
    // the same over NFSv4: holes stay holes and the pipelined WRITEs land in order
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "copy",
            "-nfs.vers",
            "4",
            "-noId",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/v4",
        ],
    ));
    let copied = fs::metadata(export.join("v4/disk.img")).unwrap();
    assert_eq!(copied.len(), 48 << 20);
    assert!(
        copied.blocks() * 512 < 6 << 20,
        "holes are not written over NFSv4 either, uses {}",
        copied.blocks() * 512
    );
    assert_eq!(
        sha256_of(&src.join("disk.img")),
        sha256_of(&export.join("v4/disk.img"))
    );
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "verify",
            "-nfs.vers",
            "4",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/v4",
        ],
    ));
}

#[test]
fn nfs_vers_4_moves_the_data_over_compound_with_open_state() {
    use rcp::nfs::testserver::NFS4_ACL_BACKING_NAME as BACKING;
    use rcp::nfs::v4;
    let s = Scratch::new("nfs-v4");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let (nfs_a, nfs_b) = ("127.0.0.1:/export:/a", "127.0.0.1:/export:/b");
    let v4 = |args: &[&str]| {
        let mut v = vec![args[0], "-nfs.vers", "4"];
        v.extend_from_slice(&args[1..]);
        rcp_nfs(&cat, server.port, &v)
    };

    // local -> export over v4: no MOUNT, a client id, an OPEN and CLOSE per file
    let out = v4(&[
        "copy",
        "-newid",
        "v4",
        "-loglevel",
        "DEBUG",
        "-parallel",
        "3",
        src.to_str().unwrap(),
        nfs_a,
    ]);
    let text = assert_passed(&out);
    assert!(
        text.contains("copy: 4 files") && text.contains("1 linked"),
        "{text}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("open 127.0.0.1:/export:/a (nfs v4, create)") && err.contains("clientid 0x"),
        "{err}"
    );
    assert!(
        !err.contains("mount port"),
        "no MOUNT protocol under v4: {err}"
    );
    let backing = export.join("a");
    assert_eq!(
        fs::read(backing.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::read(backing.join("nested/deeper/data.bin"))
            .unwrap()
            .len(),
        300_000
    );
    assert_eq!(
        fs::metadata(backing.join("script.sh")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(backing.join("message.txt")).unwrap().mtime(),
        1_600_000_000
    );
    assert_eq!(
        fs::read_link(backing.join("dangling")).unwrap(),
        PathBuf::from("/nowhere/at/all")
    );
    assert_eq!(
        fs::metadata(backing.join("message.txt")).unwrap().ino(),
        fs::metadata(backing.join("nested/also-message.txt"))
            .unwrap()
            .ino(),
        "hard link through LINK"
    );
    // verify both ways, and a tampered byte on the server is a difference
    assert_passed(&v4(&["verify", src.to_str().unwrap(), nfs_a]));
    assert_passed(&v4(&["verify", nfs_a, src.to_str().unwrap()]));
    fs::write(backing.join("message.txt"), b"hello from the sOurce\n").unwrap();
    assert_failed(
        &v4(&["verify", "-nomods", src.to_str().unwrap(), nfs_a]),
        "DIFF content message.txt",
    );
    // sync repairs it and removes what the source dropped
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&v4(&["sync", "-id", "v4"]));
    assert!(
        text.contains("sync: 1 files") && text.contains("1 removed"),
        "{text}"
    );
    assert_passed(&v4(&["verify", src.to_str().unwrap(), nfs_a]));
    // export -> export and back to local, scan, chmod, delete
    assert_passed(&v4(&["copy", "-noId", nfs_a, nfs_b]));
    assert_passed(&v4(&["verify", nfs_a, nfs_b]));
    let back = s.path("back");
    assert_passed(&v4(&["copy", "-noId", nfs_b, back.to_str().unwrap()]));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));
    let text = assert_passed(&v4(&["scan", "-l", "-stats", "127.0.0.1:/export"]));
    assert!(
        text.contains("a/message.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    assert_passed(&v4(&["chmod", "0600", "-match", "*.sh", nfs_b]));
    assert_eq!(
        fs::metadata(export.join("b/script.sh")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_passed(&v4(&["delete", "-force", "-removetopdir", nfs_b]));
    assert!(!export.join("b").exists());
    // a symlink holding a file's name is replaced, not opened through (OPEN on one answers
    // NFS4ERR_SYMLINK, RFC 7530 16.16) and not left to fail every run
    let (over, precious) = (export.join("over"), s.path("precious.txt"));
    fs::create_dir_all(&over).unwrap();
    fs::write(&precious, b"not yours\n").unwrap();
    symlink(&precious, over.join("message.txt")).unwrap();
    let out = v4(&[
        "copy",
        "-noId",
        src.to_str().unwrap(),
        "127.0.0.1:/export:/over",
    ]);
    assert_eq!(
        fs::read(&precious).unwrap(),
        b"not yours\n",
        "the copy wrote through the export's symlink:\n{}",
        stdout(&out)
    );
    assert_passed(&out);
    assert!(
        fs::symlink_metadata(over.join("message.txt"))
            .unwrap()
            .is_file(),
        "the link was not replaced by the file"
    );
    assert_eq!(
        fs::read(over.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    // -acl4 rides the data protocol: the ACL is one more attribute of the same OPEN
    let acl = v4::encode_aces(&[
        (0, 0, 0x1601bf, "OWNER@"),
        (0, 0x40, 0x120089, "GROUP@"),
        (0, 0, 0x1200a9, "alice@example.net"),
        (1, 0, 0x2, "EVERYONE@"),
    ]);
    if rcp::xattr::set(&backing.join("message.txt"), BACKING, &acl).is_ok() {
        assert_passed(&v4(&[
            "copy",
            "-acl4",
            "-noId",
            nfs_a,
            "127.0.0.1:/export:/c",
        ]));
        assert_eq!(
            rcp::xattr::get(&export.join("c/message.txt"), BACKING).unwrap(),
            acl
        );
        assert_passed(&v4(&["verify", "-acl4", nfs_a, "127.0.0.1:/export:/c"]));
    }
    // the same request through the environment
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_NFS_PORT", server.port.to_string())
        .env("RCP_NFS_VERS", "4")
        .arg("-catalog")
        .arg(&cat)
        .args(["scan", nfs_a])
        .output()
        .unwrap();
    assert_passed(&out);
    // controls: a server without v4 is refused before anything is planned, and there is
    // no version 5
    let export2 = s.path("export2");
    fs::create_dir_all(&export2).unwrap();
    let plain = rcp::nfs::testserver::Server::start_with_acl(&export2, false).unwrap();
    let text = assert_failed(
        &rcp_nfs(
            &cat,
            plain.port,
            &[
                "copy",
                "-nfs.vers",
                "4",
                "-noId",
                src.to_str().unwrap(),
                "127.0.0.1:/export:/p",
            ],
        ),
        "does not speak NFSv4",
    );
    assert!(text.contains("use -nfs.vers 3"), "{text}");
    assert!(!export2.join("p").exists());
    assert_passed(&rcp_nfs(
        &cat,
        plain.port,
        &[
            "copy",
            "-nfs.vers",
            "3",
            "-noId",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/p",
        ],
    ));
    assert_failed(
        &rcp_nfs(&cat, server.port, &["scan", "-nfs.vers", "5", nfs_a]),
        "use 3 or 4",
    );
}

/// A stand-in for ssh: records its arguments and runs `rcp serve` here, so the whole
/// remote transport is exercised with no daemon and no keys.
fn serve_stub(s: &Scratch) -> (PathBuf, PathBuf) {
    let stub = s.path("stub-ssh");
    let log = s.path("ssh-args.log");
    fs::write(
        &stub,
        format!(
            "#!/bin/sh\necho \"$@\" >> {}\nexec {} serve\n",
            log.display(),
            env!("CARGO_BIN_EXE_rcp")
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    (stub, log)
}

/// Pseudo-random bytes that do not compress and do not repeat, cheaply.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    // spread the seeds: `seed | 1` alone made 8 and 9 the same stream, and the delta arm
    // then deduplicated one edit against the other, which was correct and not the test
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The literal byte count the summary reports for a delta run.
fn delta_literal(text: &str) -> u64 {
    let after = text
        .split("delta: 1 files, ")
        .nth(1)
        .unwrap_or_else(|| panic!("no delta in\n{text}"));
    after.split(' ').next().unwrap().parse().unwrap()
}

#[test]
fn delta_sends_only_the_changed_chunks_in_every_direction() {
    let s = Scratch::new("delta");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    let mut data = noise(32 << 20, 7);
    fs::write(src.join("big.bin"), &data).unwrap();
    fs::write(src.join("small.txt"), b"too small for a patch").unwrap();
    let (stub, _log) = serve_stub(&s);
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("ssh://filer{}/dst", remote.display());
    let edit = |data: &mut Vec<u8>, at: usize, seed: u64| {
        let patch = noise(1 << 20, seed);
        data[at..at + patch.len()].copy_from_slice(&patch);
        fs::write(src.join("big.bin"), &*data).unwrap();
    };

    // control: a file the destination lacks moves in full, delta or not
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", src.to_str().unwrap(), &dst],
    ));
    assert!(!text.contains("delta:"), "{text}");

    // local -> ssh: 1 MiB changed at 10 MiB moves as about 1 MiB of literals
    edit(&mut data, 10 << 20, 8);
    let out = rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            "-delta",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    let text = assert_passed(&out);
    let literal = delta_literal(&text);
    // the edit plus at most one chunk of slop at each end (64 KiB is the largest chunk
    // for a 32 MiB file)
    assert!(
        (1 << 20..(1 << 20) + (128 << 10)).contains(&literal),
        "{literal} literal bytes for a 1 MiB edit\n{text}"
    );
    let debug = String::from_utf8_lossy(&out.stderr);
    assert!(
        debug.contains("DEBUG delta big.bin:") && debug.contains("signatures"),
        "{debug}"
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));

    // ssh -> local: the far side matches, only the patch comes back
    let back = s.path("back");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", &dst, back.to_str().unwrap()],
    ));
    edit(&mut data, 20 << 20, 9);
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", src.to_str().unwrap(), &dst],
    ));
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", &dst, back.to_str().unwrap()],
    ));
    let literal = delta_literal(&text);
    assert!((1 << 20..2 << 20).contains(&literal), "{literal}\n{text}");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));

    // ssh -> ssh, and local -> local through the same port defaults
    let dst2 = format!("ssh://filer{}/dst2", remote.display());
    assert_passed(&rcp_over_ssh(&cat, &stub, &["copy", "-noId", &dst, &dst2]));
    let local2 = s.path("local2");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            local2.to_str().unwrap(),
        ],
    ));
    edit(&mut data, 25 << 20, 10);
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", src.to_str().unwrap(), &dst],
    ));
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", &dst, &dst2],
    ));
    assert!(delta_literal(&text) < 2 << 20, "{text}");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-delta",
            src.to_str().unwrap(),
            local2.to_str().unwrap(),
        ],
    ));
    assert!(delta_literal(&text) < 2 << 20, "{text}");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst2],
    ));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), local2.to_str().unwrap()],
    ));

    // a shorter source: the destination ends where the source does
    data.truncate(20 << 20);
    fs::write(src.join("big.bin"), &data).unwrap();
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", src.to_str().unwrap(), &dst],
    ));
    assert!(text.contains("delta: 1 files"), "{text}");
    assert_eq!(
        fs::metadata(remote.join("dst/big.bin")).unwrap().len(),
        20 << 20
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));

    // a hard-linked destination: the patch replaces the name, the other link keeps its bytes
    fs::hard_link(remote.join("dst/big.bin"), remote.join("dst/other.bin")).unwrap();
    let before = fs::read(remote.join("dst/other.bin")).unwrap();
    edit(&mut data, 1 << 20, 11);
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-delta", src.to_str().unwrap(), &dst],
    ));
    assert_eq!(
        fs::read(remote.join("dst/other.bin")).unwrap(),
        before,
        "the other link is untouched"
    );
    assert_eq!(fs::read(remote.join("dst/big.bin")).unwrap(), data);
    assert_eq!(fs::metadata(remote.join("dst/big.bin")).unwrap().nlink(), 1);
    // and nothing is left beside the files
    let names: Vec<String> = fs::read_dir(remote.join("dst"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.contains("rcp-patch")), "{names:?}");
}

/// A stand-in transport that records the bytes crossing each way: (stub, to the serve,
/// from the serve).
fn counting_stub(s: &Scratch) -> (PathBuf, PathBuf, PathBuf) {
    let stub = s.path("ssh-count");
    let wire_in = s.path("wire-in");
    let wire_out = s.path("wire-out");
    write(
        &stub,
        format!(
            "#!/bin/sh\ntee -a {} | {} serve | tee -a {}\n",
            wire_in.display(),
            env!("CARGO_BIN_EXE_rcp"),
            wire_out.display()
        )
        .as_bytes(),
        0o755,
    );
    (stub, wire_in, wire_out)
}

/// The same stand-in, with the SERVE made verbose.
///
/// `-loglevel DEBUG` on the client says nothing about the far side: the serve is a
/// separate process started by this script with its own default level, so its `debug!`
/// lines are suppressed unless the script asks for them. That is exactly why the flag
/// belongs here and not in the client's argument list -- an arm that wants the serve's own
/// report has to make the serve willing to give one.
fn counting_stub_verbose(s: &Scratch) -> (PathBuf, PathBuf, PathBuf) {
    let stub = s.path("ssh-count-v");
    let wire_in = s.path("wire-in");
    let wire_out = s.path("wire-out");
    write(
        &stub,
        format!(
            "#!/bin/sh\ntee -a {} | {} serve -loglevel DEBUG | tee -a {}\n",
            wire_in.display(),
            env!("CARGO_BIN_EXE_rcp"),
            wire_out.display()
        )
        .as_bytes(),
        0o755,
    );
    (stub, wire_in, wire_out)
}

fn wire_bytes(p: &Path) -> u64 {
    fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn compress_shrinks_text_on_the_wire_and_passes_noise_through() {
    let s = Scratch::new("compress");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    let text: Vec<u8> =
        b"the quick brown fox jumps over the lazy dog, again and again\n".repeat(150_000);
    fs::write(src.join("text.txt"), &text).unwrap();
    let noise = noise(8 << 20, 21);
    fs::write(src.join("noise.bin"), &noise).unwrap();
    let (stub, wire_in, wire_out) = counting_stub(&s);
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("ssh://filer{}/dst", remote.display());

    // local -> ssh: the noise crosses at its own size, the text at a fraction of it
    let out = rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            "-compress",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    assert_passed(&out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(", compressing"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (to, from) = (wire_bytes(&wire_in), wire_bytes(&wire_out));
    assert!(
        to > 8 << 20 && to < (8 << 20) + (512 << 10),
        "{to} bytes to the serve for 8 MiB of noise and {} of text",
        text.len()
    );
    assert!(from < 64 << 10, "{from} bytes back");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));

    // control: without -compress everything crosses whole
    fs::remove_file(&wire_in).unwrap();
    fs::remove_file(&wire_out).unwrap();
    let dst2 = format!("ssh://filer{}/dst2", remote.display());
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", src.to_str().unwrap(), &dst2],
    ));
    let plain = wire_bytes(&wire_in);
    assert!(
        plain > (8 << 20) + text.len() as u64,
        "{plain} bytes without compression"
    );

    // ssh -> local: the serve compresses what it sends
    fs::remove_file(&wire_in).unwrap();
    fs::remove_file(&wire_out).unwrap();
    let back = s.path("back");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", "-compress", &dst, back.to_str().unwrap()],
    ));
    let (to, from) = (wire_bytes(&wire_in), wire_bytes(&wire_out));
    assert!(
        from > 8 << 20 && from < (8 << 20) + (512 << 10),
        "{from} bytes from the serve"
    );
    assert!(to < 64 << 10, "{to} bytes to it");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));

    // and a delta over a compressed stream: literals shrink too when they are text
    let mut edited = text.clone();
    edited[1 << 20..(1 << 20) + 200_000].copy_from_slice(
        &b"a different line of text that repeats itself for a while\n".repeat(4000)[..200_000],
    );
    fs::write(src.join("text.txt"), &edited).unwrap();
    fs::remove_file(&wire_in).unwrap();
    fs::remove_file(&wire_out).unwrap();
    let out_text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            "-compress",
            "-delta",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    // both files are patched (no catalog, so nothing is known to be unchanged): the noise
    // as copies of itself, the text as its edited chunks
    assert!(out_text.contains("delta: 2 files"), "{out_text}");
    assert!(
        wire_bytes(&wire_in) < 512 << 10,
        "{} bytes for a 200 KB text edit sent as a compressed patch",
        wire_bytes(&wire_in)
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));
}

#[test]
fn delta_keeps_a_sparse_file_sparse_and_sends_none_of_an_unchanged_one() {
    let s = Scratch::new("delta-sparse");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("sparse.img")).unwrap();
        f.set_len(16 << 20).unwrap();
        f.write_all_at(&noise(4096, 31), 0).unwrap();
        f.write_all_at(&noise(4096, 32), (16 << 20) - 4096).unwrap();
    }
    let cat = s.path("catalog");
    let dst = s.path("dst");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-delta",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("delta: 1 files, 0 literal bytes"), "{text}");
    let blocks = fs::metadata(dst.join("sparse.img")).unwrap().blocks() * 512;
    assert!(
        blocks < 1 << 20,
        "the patched file is still sparse: {blocks} bytes allocated"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // control: a change inside the data moves only that chunk
    {
        use std::os::unix::fs::FileExt;
        let f = fs::OpenOptions::new()
            .write(true)
            .open(src.join("sparse.img"))
            .unwrap();
        f.write_all_at(&noise(4096, 33), 0).unwrap();
    }
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-delta",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let literal = delta_literal(&text);
    assert!(literal > 0 && literal <= 128 << 10, "{literal}\n{text}");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
}

/// A stand-in transport that adds `ms` of latency each way (a python relay in front of
/// the serve), so round trips can be counted in wall time.
fn latency_stub(s: &Scratch, ms: u32) -> PathBuf {
    let relay = s.path("relay.py");
    write(&relay, RELAY_PY.as_bytes(), 0o755);
    let stub = s.path("ssh-slow");
    write(
        &stub,
        format!(
            "#!/bin/sh\nexec python3 {} {} {} \"$@\"\n",
            relay.display(),
            ms as f64 / 1000.0,
            env!("CARGO_BIN_EXE_rcp")
        )
        .as_bytes(),
        0o755,
    );
    stub
}

const RELAY_PY: &str = r#"#!/usr/bin/env python3
"""A stand-in transport that adds latency: every frame in either direction is delivered
`delay` seconds after it was read, in order, so frames sent back to back arrive back to
back after one delay (latency, not a per-frame stall). Usage: relay.py DELAY RCP [ssh args]."""
import collections, struct, subprocess, sys, threading, time

delay = float(sys.argv[1])
rcp = sys.argv[2]
serve = subprocess.Popen([rcp, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)


def frames(reader):
    while True:
        hdr = reader.read(4)
        if len(hdr) < 4:
            return
        (n,) = struct.unpack(">I", hdr)
        body = reader.read(n)
        yield hdr + body


def relay(reader, writer):
    queue = collections.deque()
    cv = threading.Condition()
    done = [False]

    def pump():
        for frame in frames(reader):
            with cv:
                queue.append((time.monotonic() + delay, frame))
                cv.notify()
        with cv:
            done[0] = True
            cv.notify()

    threading.Thread(target=pump, daemon=True).start()
    while True:
        with cv:
            while not queue and not done[0]:
                cv.wait()
            if not queue:
                break
            due, frame = queue.popleft()
        now = time.monotonic()
        if due > now:
            time.sleep(due - now)
        try:
            writer.write(frame)
            writer.flush()
        except BrokenPipeError:
            break
    try:
        writer.close()
    except Exception:
        pass


up = threading.Thread(target=relay, args=(sys.stdin.buffer, serve.stdin), daemon=True)
up.start()
relay(serve.stdout, sys.stdout.buffer)
serve.wait()
"#;

#[test]
fn ssh_reads_run_ahead_of_the_consumer_so_a_verify_pays_few_round_trips() {
    assert!(
        Command::new("python3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
        "python3 is needed for the latency stand-in"
    );
    let s = Scratch::new("readahead");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("big.bin"), noise(16 << 20, 41)).unwrap();
    let (fast, _log) = serve_stub(&s);
    let slow = latency_stub(&s, 50);
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("ssh://filer{}/dst", remote.display());
    assert_passed(&rcp_over_ssh(
        &cat,
        &fast,
        &["copy", "-noId", src.to_str().unwrap(), &dst],
    ));
    // control: the stand-in really adds latency; a scan is a couple of round trips
    let t = Instant::now();
    assert_passed(&rcp_over_ssh(&cat, &slow, &["scan", &dst]));
    let scan = t.elapsed();
    assert!(
        scan >= Duration::from_millis(150),
        "a scan through 50 ms each way took {scan:?}"
    );
    // sixteen 1 MiB reads one round trip each would be sixteen scans' worth; with the
    // window they are two
    let t = Instant::now();
    assert_passed(&rcp_over_ssh(
        &cat,
        &slow,
        &["verify", "-parallel", "1", src.to_str().unwrap(), &dst],
    ));
    let verify = t.elapsed();
    assert!(
        verify < scan * 6,
        "verify of 16 MiB took {verify:?} against a scan of {scan:?}: reads are not running ahead"
    );
}

/// A stand-in transport that runs the sftp stand-in server for `-s sftp` and the serve
/// for anything else, logging its arguments like `serve_stub`.
fn any_stub(s: &Scratch) -> (PathBuf, PathBuf) {
    let stub = s.path("ssh-any");
    let log = s.path("ssh-any.log");
    let sftp = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/sftp_stub.py");
    write(&stub, format!("#!/bin/sh\necho \"$@\" >> {}\ncase \" $* \" in\n  *\" -s sftp \"*) exec python3 {} \"$@\" ;;\n  *) exec {} serve ;;\nesac\n", log.display(), sftp.display(), env!("CARGO_BIN_EXE_rcp")).as_bytes(), 0o755);
    (stub, log)
}

/// Reads and writes are sized by what the server says it takes, and every file crosses at the
/// sizes OpenSSH's sftp-server enforces.
///
/// Every file of 256 KiB or more failed against a real OpenSSH. The client sent 256 KiB of
/// WRITE data per message, OpenSSH's limit is 256 KiB for the WHOLE message, and the server
/// ended the session; the stand-in was paramiko, which takes 16 MB, so the suite never saw it.
/// The stand-in now enforces OpenSSH's limit (the control below shows it does) and offers
/// `limits@openssh.com` the way OpenSSH does, or not at all with `RCP_SFTP_STUB_NO_LIMITS=1`,
/// the way a server before OpenSSH 8.7 does.
#[test]
fn sftp_reads_and_writes_fit_what_the_server_says_it_takes() {
    if !Command::new("python3")
        .args(["-c", "import paramiko"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 with paramiko is needed for the sftp stand-in server");
        return;
    }
    let s = Scratch::new("sftp-limits");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    // one byte either side of the 256 KiB message limit, and a file that fills the write window
    for (name, len, seed) in [
        ("under", (256 << 10) - 1, 61),
        ("at", 256 << 10, 62),
        ("over", (256 << 10) + 1, 63),
        ("window", 5 << 20, 64),
    ] {
        fs::write(src.join(name), noise(len, seed)).unwrap();
    }
    let (stub, _log) = any_stub(&s);
    let cat = s.path("catalog");

    // control: the stand-in ends the session on a message over OpenSSH's limit, exactly as
    // OpenSSH does, so the arms below are measured against the limit and not against paramiko
    let stand_in = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/sftp_stub.py");
    let mut child = Command::new("python3")
        .arg(&stand_in)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        // INIT, version 3
        stdin.write_all(&[0, 0, 0, 5, 1, 0, 0, 0, 3]).unwrap();
        // a message one byte over the limit; only its length is ever read
        stdin
            .write_all(&((256u32 << 10) + 1).to_be_bytes())
            .unwrap();
    }
    let status = child.wait_with_output().unwrap().status;
    assert_eq!(
        status.code(),
        Some(11),
        "the stand-in took a message over 256 KiB"
    );

    for (limits, reads, writes) in [(true, 261120, 261120), (false, 32768, 32768)] {
        let remote = s.path(if limits { "limits" } else { "no-limits" });
        fs::create_dir_all(&remote).unwrap();
        let dst = format!("sftp://alice@filer{}/dst", remote.display());
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_rcp"))
                .env("RCP_SSH", &stub)
                .env("RCP_SFTP_STUB_NO_LIMITS", if limits { "0" } else { "1" })
                .arg("-catalog")
                .arg(&cat)
                .args(args)
                .output()
                .expect("rcp runs")
        };
        let out = run(&[
            "copy",
            "-noId",
            "-loglevel",
            "DEBUG",
            src.to_str().unwrap(),
            &dst,
        ]);
        let text = assert_passed(&out);
        assert!(text.contains("copy: 4 files"), "{text}");
        let debug = String::from_utf8_lossy(&out.stderr);
        assert!(
            debug.contains(&format!("reads of {reads} and writes of {writes} bytes")),
            "limits advertised: {limits}\n{debug}"
        );
        // the bytes on the server, read without rcp
        for name in ["under", "at", "over", "window"] {
            assert_eq!(
                fs::read(remote.join("dst").join(name)).unwrap(),
                fs::read(src.join(name)).unwrap(),
                "{name}, limits advertised: {limits}"
            );
        }
        // and back, through READs of the same sizes
        let back = s.path(if limits {
            "back-limits"
        } else {
            "back-no-limits"
        });
        assert_passed(&run(&["copy", "-noId", &dst, back.to_str().unwrap()]));
        for name in ["under", "at", "over", "window"] {
            assert_eq!(
                fs::read(back.join(name)).unwrap(),
                fs::read(src.join(name)).unwrap(),
                "{name} read back, limits advertised: {limits}"
            );
        }
    }
}

/// A transport that dies mid-file is a failure the run reports, not a signal that ends it.
///
/// SIGPIPE used to be reset to its default so that `rcp ... | head` ended quietly, and that
/// also killed the run the moment it wrote to an `ssh` child that had gone: exit 141, no error,
/// no STATUS line, and a file left half written under its final name. That is how the sftp
/// size defect first showed itself against a real OpenSSH. The stand-in here ends the session
/// after its first megabyte, the way a server that drops the connection mid-file does.
#[test]
fn a_transport_that_dies_mid_file_is_reported_rather_than_fatal() {
    if !Command::new("python3")
        .args(["-c", "import paramiko"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 with paramiko is needed for the sftp stand-in server");
        return;
    }
    let s = Scratch::new("sftp-dies");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("big.bin"), noise(8 << 20, 71)).unwrap();
    let (stub, _log) = any_stub(&s);
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("sftp://alice@filer{}/dst", remote.display());
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env("RCP_SFTP_STUB_DIE_AFTER", "1000000")
        .arg("-catalog")
        .arg(s.path("catalog"))
        .args(["copy", "-noId", src.to_str().unwrap(), &dst])
        .output()
        .expect("rcp runs");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        out.status.signal(),
        None,
        "the run was killed by a signal: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = assert_failed(&out, "big.bin");
    assert!(text.contains("STATUS: FAILED"), "{text}");
}

#[test]
fn sftp_endpoints_reach_a_host_that_has_only_openssh() {
    // the stand-in server is paramiko over stdio; without paramiko there is no server to
    // test against, and saying so beats a green run that tested nothing
    if !Command::new("python3")
        .args(["-c", "import paramiko"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 with paramiko is needed for the sftp stand-in server");
        return;
    }
    let s = Scratch::new("sftp");
    let src = s.path("src");
    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("big.bin"), noise(3 << 20, 51)).unwrap();
    write(&src.join("nested/msg.txt"), b"hello over sftp\n", 0o640);
    fs::hard_link(src.join("nested/msg.txt"), src.join("nested/also.txt")).unwrap();
    symlink("msg.txt", src.join("nested/link")).unwrap();
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("sparse.img")).unwrap();
        f.set_len(8 << 20).unwrap();
        f.write_all_at(b"head", 0).unwrap();
        f.write_all_at(b"tail", (8 << 20) - 4).unwrap();
    }
    let (stub, log) = any_stub(&s);
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("sftp://alice@filer:2222{}/dst", remote.display());

    // local -> sftp: files, modes, the symlink and a sparse file arrive; the hard link is
    // a second file, which is what the protocol allows
    let out = rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-newid",
            "sftp",
            "-loglevel",
            "DEBUG",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    let text = assert_passed(&out);
    assert!(
        text.contains("copy: 4 files") && text.contains("1 symlinks"),
        "{text}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("subsystem through"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("-p 2222") && seen.contains("alice@filer") && seen.contains("-s sftp"),
        "{seen}"
    );
    assert_eq!(
        fs::read(remote.join("dst/nested/also.txt")).unwrap(),
        b"hello over sftp\n"
    );
    assert_eq!(
        fs::metadata(remote.join("dst/nested/msg.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        fs::read_link(remote.join("dst/nested/link")).unwrap(),
        PathBuf::from("msg.txt")
    );
    let blocks = fs::metadata(remote.join("dst/sparse.img"))
        .unwrap()
        .blocks()
        * 512;
    assert!(
        blocks < 1 << 20,
        "sparse file over sftp occupies {blocks} bytes"
    );
    // a mirror into a directory that is not there yet is an EMPTY destination, not an
    // unreadable one: neither a failure nor, under the rail, an overwrite it cannot rule out
    // (destination listing errors are reported; this is the control)
    // A symlink in the destination where the source has a directory is replaced, not written
    // through: the server resolves the path, so otherwise the files under it land wherever
    // the link points (measured: `x` appeared outside the destination).
    let (linked, outside) = (remote.join("linked"), s.path("outside"));
    fs::create_dir_all(&linked).unwrap();
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, linked.join("nested")).unwrap();
    let out = rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            &format!("sftp://alice@filer:2222{}", linked.display()),
        ],
    );
    // the safety half first: whatever else happened, nothing lands outside the destination --
    // with the link replaced, or, where it could not be, with everything beneath the failed
    // mkdir refused
    assert!(
        fs::read_dir(&outside).unwrap().next().is_none(),
        "the copy wrote through the destination's symlink:\n{}",
        stdout(&out)
    );
    let text = assert_passed(&out);
    assert!(
        fs::symlink_metadata(linked.join("nested"))
            .unwrap()
            .is_dir(),
        "{text}"
    );
    assert_eq!(
        fs::read(linked.join("nested/msg.txt")).unwrap(),
        b"hello over sftp\n"
    );

    // And a FILE copied onto a destination symlink of the same name: OPEN with CREAT|TRUNC
    // follows the link on the server, so without care this truncates and rewrites the link's
    // target outside the destination and leaves the link where it was (measured).
    let (over, precious) = (remote.join("over"), s.path("precious.txt"));
    fs::create_dir_all(&over).unwrap();
    fs::write(&precious, b"not yours\n").unwrap();
    symlink(&precious, over.join("big.bin")).unwrap();
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            &format!("sftp://alice@filer:2222{}", over.display()),
        ],
    ));
    assert_eq!(
        fs::read(&precious).unwrap(),
        b"not yours\n",
        "the copy wrote through the destination's symlink:\n{text}"
    );
    assert!(
        fs::symlink_metadata(over.join("big.bin"))
            .unwrap()
            .is_file(),
        "the link was not replaced by the file"
    );
    assert_eq!(
        fs::read(over.join("big.bin")).unwrap(),
        fs::read(src.join("big.bin")).unwrap()
    );

    // A sync that MOVES a file under a directory the destination holds as a symlink whose
    // attributes carry no permissions, which SFTP v3 allows. The listing says it
    // could not type the entry; READLINK tells the mkdir it is a link, which is replaced; and
    // were it not, the move is refused rather than renamed through the link.
    let (msrc, mdst, elsewhere) = (s.path("msrc"), remote.join("moved"), s.path("elsewhere"));
    fs::create_dir_all(msrc.join("old")).unwrap();
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(msrc.join("old/f.txt"), b"moving\n").unwrap();
    let murl = format!("sftp://alice@filer:2222{}", mdst.display());
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-newid", "sftp-move", msrc.to_str().unwrap(), &murl],
    ));
    fs::create_dir_all(msrc.join("a")).unwrap();
    fs::rename(msrc.join("old/f.txt"), msrc.join("a/f.txt")).unwrap();
    symlink(&elsewhere, mdst.join("a")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env("RCP_STUB_BARE_LINKS", "1")
        .arg("-catalog")
        .arg(&cat)
        .args(["sync", "-id", "sftp-move"])
        .output()
        .unwrap();
    let said = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(
        fs::read_dir(&elsewhere).unwrap().next().is_none(),
        "the move renamed through the destination's symlink:\n{said}"
    );
    assert!(
        said.contains("did not report its type"),
        "an untyped entry was dropped in silence:\n{said}"
    );
    assert!(
        fs::symlink_metadata(mdst.join("a")).unwrap().is_dir(),
        "the link was not replaced:\n{said}"
    );
    assert_eq!(
        fs::read(mdst.join("a/f.txt")).unwrap(),
        b"moving\n",
        "{said}"
    );
    // The same server without READLINK either, and with a REALPATH that only normalizes the
    // spelling, as draft-02 allows. OPENDIR follows the link and REALPATH
    // does not resolve it, so neither is evidence of a directory: the name is unknown, the
    // mkdir fails, and nothing beneath it is moved -- nor is the directory's mode, applied at
    // the end of the run, set through the link onto what it points at.
    let elsewhere2 = s.path("elsewhere2");
    fs::create_dir_all(&elsewhere2).unwrap();
    fs::set_permissions(&elsewhere2, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(msrc.join("b")).unwrap();
    fs::set_permissions(msrc.join("b"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(msrc.join("a/f.txt"), msrc.join("b/f.txt")).unwrap();
    symlink(&elsewhere2, mdst.join("b")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env("RCP_STUB_BARE_LINKS", "1")
        .env("RCP_STUB_NO_READLINK", "1")
        .env("RCP_STUB_LEXICAL_REALPATH", "1")
        .arg("-catalog")
        .arg(&cat)
        .args(["sync", "-id", "sftp-move"])
        .output()
        .unwrap();
    let said = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(
        fs::read_dir(&elsewhere2).unwrap().next().is_none(),
        "the move renamed through a link OPENDIR followed:\n{said}"
    );
    assert_eq!(
        fs::metadata(&elsewhere2).unwrap().permissions().mode() & 0o777,
        0o700,
        "the directory's mode was set through the link:\n{said}"
    );
    assert!(
        !out.status.success() && said.contains("could not be made"),
        "{said}"
    );
    assert!(
        fs::symlink_metadata(mdst.join("b"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "{said}"
    );

    let fresh = format!("sftp://alice@filer:2222{}/fresh", remote.display());
    let dry = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["isync", "-dryrun", src.to_str().unwrap(), &fresh],
    ));
    assert!(
        !remote.join("fresh").exists(),
        "a dry run created the destination\n{dry}"
    );
    assert_failed(
        &rcp_over_ssh(
            &cat,
            &stub,
            &[
                "scan",
                &format!("sftp://alice@filer:2222{}/nowhere", remote.display()),
            ],
        ),
        "No such file",
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["isync", "-requireconfirm", src.to_str().unwrap(), &fresh],
    ));
    assert_eq!(
        fs::read(remote.join("fresh/nested/msg.txt")).unwrap(),
        b"hello over sftp\n"
    );
    // verify: content and modes agree; the hard link is reported as the one difference,
    // and -nolinks accepts the rest
    assert_failed(
        &rcp_over_ssh(&cat, &stub, &["verify", src.to_str().unwrap(), &dst]),
        "DIFF hardlink",
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", "-nolinks", src.to_str().unwrap(), &dst],
    ));
    // sync after a change, scan, sftp -> local, delete
    fs::write(src.join("nested/msg.txt"), b"changed\n").unwrap();
    let text = assert_passed(&rcp_over_ssh(&cat, &stub, &["sync", "-id", "sftp"]));
    assert!(
        text.contains("sync: 2 files") || text.contains("sync: 1 files"),
        "{text}"
    );
    assert_eq!(
        fs::read(remote.join("dst/nested/msg.txt")).unwrap(),
        b"changed\n"
    );
    let text = assert_passed(&rcp_over_ssh(&cat, &stub, &["scan", "-l", "-stats", &dst]));
    assert!(
        text.contains("nested/msg.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    let back = s.path("back");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", &dst, back.to_str().unwrap()],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nolinks",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["delete", "-force", "-removetopdir", &dst],
    ));
    assert!(!remote.join("dst").exists());
    // controls: a missing remote path without create, a relative path, a transport that
    // cannot start
    assert_failed(
        &rcp_over_ssh(
            &cat,
            &stub,
            &["scan", &format!("sftp://filer{}/missing", remote.display())],
        ),
        "No such file",
    );
    assert_failed(
        &rcp_over_ssh(&cat, &stub, &["scan", "sftp://filer"]),
        "absolute path",
    );
    assert_failed(
        &rcp_over_ssh(&cat, Path::new("/nonexistent/ssh"), &["scan", &dst]),
        "cannot start ssh",
    );
}

fn rcp_over_ssh(catalog: &Path, stub: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", stub)
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

#[test]
fn ssh_endpoints_reach_an_rcp_serve_through_the_transport_command() {
    let s = Scratch::new("ssh");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("sparse.img")).unwrap();
        f.set_len(8 << 20).unwrap();
        f.write_all_at(b"head", 0).unwrap();
        f.write_all_at(b"tail", (8 << 20) - 4).unwrap();
    }
    let (stub, log) = serve_stub(&s);
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("ssh://alice@filer:2222{}/dst", remote.display());

    // local -> ssh: the stub saw ssh's arguments, the serve did the writing
    let out = rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-newid",
            "ssh",
            "-loglevel",
            "DEBUG",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    let text = assert_passed(&out);
    assert!(
        text.contains("copy: 5 files") && text.contains("1 linked"),
        "{text}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&format!("open {dst} (ssh, create)")), "{err}");
    assert!(err.contains("serving through"), "{err}");
    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("-o BatchMode=yes")
            && seen.contains("-p 2222")
            && seen.contains("alice@filer")
            && seen.contains("rcp serve"),
        "{seen}"
    );
    let backing = remote.join("dst");
    assert_eq!(
        fs::read(backing.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::read(backing.join("nested/deeper/data.bin"))
            .unwrap()
            .len(),
        300_000
    );
    assert_eq!(
        fs::metadata(backing.join("script.sh")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(backing.join("message.txt")).unwrap().mtime(),
        1_600_000_000
    );
    assert_eq!(
        fs::read_link(backing.join("dangling")).unwrap(),
        PathBuf::from("/nowhere/at/all")
    );
    assert_eq!(
        fs::metadata(backing.join("message.txt")).unwrap().ino(),
        fs::metadata(backing.join("nested/also-message.txt"))
            .unwrap()
            .ino(),
        "hard link recreated remotely"
    );
    let sparse = fs::metadata(backing.join("sparse.img")).unwrap();
    assert_eq!(sparse.len(), 8 << 20);
    assert!(
        sparse.blocks() * 512 < 1 << 20,
        "holes crossed the wire as lengths, uses {}",
        sparse.blocks() * 512
    );
    assert_eq!(
        sha256_of(&src.join("sparse.img")),
        sha256_of(&backing.join("sparse.img"))
    );
    // verify both ways, a tampered byte shows, sync repairs and removes
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", &dst, src.to_str().unwrap()],
    ));
    fs::write(backing.join("message.txt"), b"hello from the sOurce\n").unwrap();
    assert_failed(
        &rcp_over_ssh(
            &cat,
            &stub,
            &["verify", "-nomods", src.to_str().unwrap(), &dst],
        ),
        "DIFF content message.txt",
    );
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&rcp_over_ssh(&cat, &stub, &["sync", "-id", "ssh"]));
    assert!(
        text.contains("sync: 1 files") && text.contains("1 removed"),
        "{text}"
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["verify", src.to_str().unwrap(), &dst],
    ));
    // ssh -> ssh, ssh -> local, scan, chmod, delete
    let dst2 = format!("ssh://filer{}/dst2", remote.display());
    assert_passed(&rcp_over_ssh(&cat, &stub, &["copy", "-noId", &dst, &dst2]));
    assert_passed(&rcp_over_ssh(&cat, &stub, &["verify", &dst, &dst2]));
    let back = s.path("back");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["copy", "-noId", &dst2, back.to_str().unwrap()],
    ));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));
    // a sparse file read through the serve arrives as data and holes, so it lands sparse
    let blocks = fs::metadata(back.join("sparse.img")).unwrap().blocks() * 512;
    assert!(
        blocks < 1 << 20,
        "sparse file copied back from ssh occupies {blocks} bytes"
    );
    let text = assert_passed(&rcp_over_ssh(&cat, &stub, &["scan", "-l", "-stats", &dst2]));
    assert!(
        text.contains("message.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["chmod", "0600", "-match", "*.sh", &dst2],
    ));
    assert_eq!(
        fs::metadata(remote.join("dst2/script.sh")).unwrap().mode() & 0o7777,
        0o600
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["delete", "-force", "-removetopdir", &dst2],
    ));
    assert!(!remote.join("dst2").exists());
    // -rcp.remote names the far side's rcp, and a plain host takes no user or port
    fs::write(&log, "").unwrap();
    // a listing larger than one batch crosses in several frames and arrives whole
    let many = remote.join("many");
    fs::create_dir_all(&many).unwrap();
    for i in 0..5000 {
        fs::write(many.join(format!("f{i}")), b"x").unwrap();
    }
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["scan", &format!("ssh://filer{}", many.display())],
    ));
    assert!(text.contains("5000 files"), "{text}");
    let plain = format!("ssh://filer{}/dst", remote.display());
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &["scan", "-rcp.remote", "/opt/bin/rcp", &plain],
    ));
    let seen = fs::read_to_string(&log).unwrap();
    assert!(
        seen.contains("filer /opt/bin/rcp serve") && !seen.contains("-p "),
        "{seen}"
    );
    // controls: a missing remote path without create, a relative path, a transport that
    // cannot start, and the same remote path twice
    assert_failed(
        &rcp_over_ssh(
            &cat,
            &stub,
            &["scan", &format!("ssh://filer{}/missing", remote.display())],
        ),
        "No such file",
    );
    assert_failed(
        &rcp_over_ssh(&cat, &stub, &["scan", "ssh://filer"]),
        "absolute path",
    );
    assert_failed(
        &rcp_over_ssh(&cat, Path::new("/nonexistent/ssh"), &["scan", &dst]),
        "cannot start ssh",
    );
    assert_failed(
        &rcp_over_ssh(&cat, &stub, &["copy", "-noId", &dst, &dst]),
        "same remote path",
    );
}

#[test]
fn version_states_the_engines_and_sha256_vectors_hold() {
    let text = stdout(&rcp(Path::new("/tmp"), &["version"]));
    assert!(
        text.contains("io_uring:") && text.contains("sha256:"),
        "{text}"
    );
    assert_eq!(
        rcp::sha256::digest_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now > 1_600_000_000);
    let _ = Scratch::new("version").s("unused");
}

fn s3_creds() -> rcp::s3::sigv4::Credentials {
    rcp::s3::sigv4::Credentials {
        access_key: "AKIATESTACCESSKEY".into(),
        secret_key: "test-secret-key-for-the-stand-in".into(),
        session_token: None,
    }
}

fn rcp_s3(
    catalog: &Path,
    server: &rcp::s3::testserver::Server,
    secret: &str,
    args: &[&str],
) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("AWS_ACCESS_KEY_ID", &server.creds.access_key)
        .env("AWS_SECRET_ACCESS_KEY", secret)
        .env("NO_PROXY", "*")
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_ENDPOINT_URL")
        .env_remove("AWS_SESSION_TOKEN")
        .arg("-catalog")
        .arg(catalog)
        .arg("-s3.endpoint")
        .arg(server.endpoint())
        .args(args)
        .output()
        .expect("rcp runs")
}

#[test]
fn s3_endpoints_copy_verify_sync_and_scan_over_the_wire() {
    let s = Scratch::new("s3");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let server = rcp::s3::testserver::Server::start(&["bkt"], s3_creds());
    let secret = server.creds.secret_key.clone();
    let cat = s.path("catalog");
    let a = "s3://bkt/a";

    // local -> bucket, with a catalog that remembers the bucket endpoint
    let text = assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["copy", "-newid", "to-s3", src.to_str().unwrap(), a],
    ));
    // 5 files and 0 linked, NOT 4 and 1: a bucket has no hard links. It used to report the
    // second name as `linked` while writing a second full object, so the summary claimed
    // two keys shared storage in a store where that is not a thing anyone can do.
    // `hard_link` is `Unsupported` now and the transfer layer copies -- which is what was
    // happening on the wire all along; the change is that the count says so.
    assert!(
        text.contains("copy: 5 files") && text.contains("0 linked"),
        "{text}"
    );
    assert_eq!(
        server
            .object("bkt", "a/nested/also-message.txt")
            .expect("the second name was written in full")
            .data,
        b"hello from the source\n"
    );
    // the bytes and the metadata landed as objects and user metadata
    let msg = server.object("bkt", "a/message.txt").expect("object");
    assert_eq!(msg.data, b"hello from the source\n");
    assert_eq!(
        msg.meta.get("mode").map(String::as_str),
        Some("33184"),
        "0o100640 in decimal, the s3fs convention"
    );
    assert_eq!(
        msg.meta.get("mtime").map(String::as_str),
        Some("1600000000.000000000")
    );
    assert_eq!(
        msg.meta.get("uid").map(String::as_str),
        Some(euid().to_string().as_str())
    );
    let link = server.object("bkt", "a/dangling").expect("symlink object");
    assert_eq!(
        (
            link.data.as_slice(),
            link.meta.get("mode").map(String::as_str)
        ),
        (&b"/nowhere/at/all"[..], Some("41471"))
    );
    let keys = server.keys("bkt");
    assert!(
        keys.contains(&"a/".to_string()) && keys.contains(&"a/nested/deeper/".to_string()),
        "directory markers: {keys:?}"
    );
    assert_eq!(
        server
            .object("bkt", "a/nested/")
            .unwrap()
            .meta
            .get("mode")
            .map(String::as_str),
        Some("16872"),
        "0o40750 on the marker"
    );
    assert_eq!(
        server
            .object("bkt", "a/nested/also-message.txt")
            .unwrap()
            .data,
        b"hello from the source\n",
        "the hard link became a server-side copy"
    );
    // verify in both directions; the bucket has no hard links, which verify says
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["verify", "-nolinks", src.to_str().unwrap(), a],
    ));
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["verify", a, src.to_str().unwrap()],
    ));
    assert_failed(
        &rcp_s3(
            &cat,
            &server,
            &secret,
            &["verify", src.to_str().unwrap(), a],
        ),
        "DIFF hardlink",
    );
    // control: change the source, the bucket side shows the difference
    fs::write(src.join("message.txt"), b"hello from the sOurce\n").unwrap();
    assert_failed(
        &rcp_s3(
            &cat,
            &server,
            &secret,
            &["verify", "-nolinks", "-nomods", src.to_str().unwrap(), a],
        ),
        "DIFF content message.txt",
    );
    // sync through the catalog repairs it and removes what the source dropped
    fs::remove_file(src.join("empty")).unwrap();
    let text = assert_passed(&rcp_s3(&cat, &server, &secret, &["sync", "-id", "to-s3"]));
    assert!(text.contains("1 removed"), "{text}");
    assert!(server.object("bkt", "a/empty").is_none());
    assert_eq!(
        server.object("bkt", "a/message.txt").unwrap().data,
        b"hello from the sOurce\n"
    );
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["verify", "-nolinks", src.to_str().unwrap(), a],
    ));

    // bucket -> bucket, then bucket -> local
    let b = "s3://bkt/b";
    assert_passed(&rcp_s3(&cat, &server, &secret, &["copy", "-noId", a, b]));
    assert_passed(&rcp_s3(&cat, &server, &secret, &["verify", a, b]));
    let back = s.path("back");
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["copy", "-noId", b, back.to_str().unwrap()],
    ));
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &[
            "verify",
            "-nolinks",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(back.join("nested/deeper/data.bin"))
            .unwrap()
            .mtime(),
        1_650_000_123,
        "mtime survived the round trip"
    );
    assert_eq!(
        fs::metadata(back.join("script.sh")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::read_link(back.join("dangling")).unwrap(),
        PathBuf::from("/nowhere/at/all")
    );

    // scan and reports on the bucket; chmod and delete over the wire
    let text = assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["scan", "-l", "-stats", "s3://bkt"],
    ));
    assert!(
        text.contains("a/message.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["chmod", "0600", "-match", "*.sh", b],
    ));
    assert_eq!(
        server
            .object("bkt", "b/script.sh")
            .unwrap()
            .meta
            .get("mode")
            .map(String::as_str),
        Some("33152"),
        "0o100600"
    );
    assert_eq!(
        server.object("bkt", "b/script.sh").unwrap().data,
        b"#!/bin/sh\necho hi\n",
        "a metadata rewrite keeps the bytes"
    );
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["delete", "-force", "-removetopdir", b],
    ));
    assert!(
        server.keys("bkt").iter().all(|k| !k.starts_with("b/")),
        "{:?}",
        server.keys("bkt")
    );
    // bad credentials, buckets and layouts fail before any write
    assert_failed(
        &rcp_s3(&cat, &server, "wrong-secret", &["scan", "s3://bkt"]),
        "SignatureDoesNotMatch",
    );
    assert_failed(
        &rcp_s3(&cat, &server, &secret, &["scan", "s3://nope"]),
        "NoSuchBucket",
    );
    assert_failed(
        &rcp_s3(&cat, &server, &secret, &["copy", "-noId", a, a]),
        "same bucket path",
    );
    assert_failed(
        &rcp_s3(&cat, &server, &secret, &["copy", "-noId", "s3://bkt", a]),
        "inside source",
    );
    if !cfg!(feature = "rustls") {
        let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args(["scan", "-s3.endpoint", "https://127.0.0.1:1", "s3://bkt"])
            .env("AWS_ACCESS_KEY_ID", "a")
            .env("AWS_SECRET_ACCESS_KEY", "b")
            .output()
            .unwrap();
        assert_failed(&out, "tls feature");
    }
}

#[test]
fn s3_multipart_uploads_and_sparse_objects_round_trip() {
    let s = Scratch::new("s3-large");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();
    // 70 MiB: over the single-PUT limit, with a 20 MiB hole in the middle
    let big = src.join("big.bin");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = fs::File::create(&big).unwrap();
        let block: Vec<u8> = (0u8..=255).cycle().take(1 << 20).collect();
        for _ in 0..25 {
            f.write_all(&block).unwrap();
        }
        f.seek(SeekFrom::Start(45 << 20)).unwrap();
        for _ in 0..25 {
            f.write_all(&block).unwrap();
        }
    }
    write(&src.join("small.txt"), b"small\n", 0o644);
    let server = rcp::s3::testserver::Server::start(&["big"], s3_creds());
    let secret = server.creds.secret_key.clone();
    let cat = s.path("catalog");
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &[
            "copy",
            "-noId",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            "s3://big/up",
        ],
    ));
    let obj = server.object("big", "up/big.bin").expect("uploaded");
    assert_eq!(obj.data.len(), 70 << 20);
    assert!(
        obj.etag.ends_with("-2\""),
        "two parts of 64 MiB and 6 MiB: {}",
        obj.etag
    );
    assert_eq!(server.open_uploads(), 0, "no multipart upload left open");
    assert_eq!(
        &obj.data[25 << 20..(25 << 20) + 16],
        &[0u8; 16],
        "the hole is zeros in the bucket"
    );
    assert_eq!(rcp::sha256::digest_hex(&obj.data), sha256_of(&big));
    let back = s.path("back");
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["copy", "-noId", "s3://big/up", back.to_str().unwrap()],
    ));
    assert_eq!(sha256_of(&back.join("big.bin")), sha256_of(&big));
    assert!(
        fs::metadata(back.join("big.bin")).unwrap().blocks() * 512 < 60 << 20,
        "the zeros came back as a hole"
    );
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["verify", src.to_str().unwrap(), "s3://big/up"],
    ));
}

/// A certificate authority: a self-signed CA:TRUE certificate and its key.
#[cfg(feature = "rustls")]
fn authority(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let (crt, key) = (
        dir.join(format!("{name}.crt")),
        dir.join(format!("{name}.key")),
    );
    let out = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            &format!("/CN={name}"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&crt)
        .output()
        .expect("openssl is installed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (crt, key)
}

/// A leaf certificate signed by `ca`, with the extensions in `ext`.
///
/// `extendedKeyUsage` matters more here than it looks: rustls's client verifier requires
/// `clientAuth` on a peer certificate and its server side requires `serverAuth`, so a leaf
/// that carries the wrong one is refused with a message about the EKU rather than about the
/// chain -- which reads like a signing problem and is not one.
#[cfg(feature = "rustls")]
fn signed_by(dir: &Path, ca: &(PathBuf, PathBuf), name: &str, ext: &str) -> (PathBuf, PathBuf) {
    let (crt, key, csr, cfg) = (
        dir.join(format!("{name}.crt")),
        dir.join(format!("{name}.key")),
        dir.join(format!("{name}.csr")),
        dir.join(format!("{name}.ext")),
    );
    fs::write(&cfg, ext).unwrap();
    let out = Command::new("openssl")
        .args([
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            &format!("/CN={name}"),
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&csr)
        .output()
        .expect("openssl is installed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new("openssl")
        .args(["x509", "-req", "-days", "2", "-CAcreateserial"])
        .arg("-in")
        .arg(&csr)
        .arg("-CA")
        .arg(&ca.0)
        .arg("-CAkey")
        .arg(&ca.1)
        .arg("-extfile")
        .arg(&cfg)
        .arg("-out")
        .arg(&crt)
        .output()
        .expect("openssl is installed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (crt, key)
}

/// A self-signed certificate for 127.0.0.1 and its key, made with the openssl CLI.
#[cfg(feature = "rustls")]
fn self_signed(dir: &Path, name: &str) -> (String, String) {
    let cert = dir.join(format!("{name}.crt"));
    let key = dir.join(format!("{name}.key"));
    let out = Command::new("openssl")
        // an end-entity certificate that is its own trust anchor: `req -x509` defaults to
        // CA:TRUE, which a verifier rightly refuses as a leaf
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            &format!("/CN={name}"),
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl is installed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        fs::read_to_string(cert).unwrap(),
        fs::read_to_string(key).unwrap(),
    )
}

#[cfg(feature = "rustls")]
#[test]
fn s3_over_tls_verifies_the_certificate_against_the_named_bundle() {
    let s = Scratch::new("s3-tls");
    let src = fixture(&s);
    let (cert, key) = self_signed(&s.0, "stand-in");
    let (other_cert, _) = self_signed(&s.0, "someone-else");
    fs::write(s.path("trusted.pem"), &cert).unwrap();
    fs::write(s.path("untrusted.pem"), &other_cert).unwrap();
    let server = rcp::s3::testserver::Server::start_tls(&["tls"], s3_creds(), &cert, &key);
    let secret = server.creds.secret_key.clone();
    let cat = s.path("catalog");
    let run = |bundle: &str, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("AWS_ACCESS_KEY_ID", &server.creds.access_key)
            .env("AWS_SECRET_ACCESS_KEY", &secret)
            .env("AWS_CA_BUNDLE", s.path(bundle))
            .env("NO_PROXY", "*")
            .arg("-catalog")
            .arg(&cat)
            .arg("-s3.endpoint")
            .arg(server.endpoint())
            .args(args)
            .output()
            .expect("rcp runs")
    };
    // trusted: a copy over TLS, verified back
    assert_passed(&run(
        "trusted.pem",
        &[
            "copy",
            "-noId",
            "-nolinks",
            src.to_str().unwrap(),
            "s3://tls/data",
        ],
    ));
    assert_eq!(
        server.object("tls", "data/message.txt").unwrap().data,
        b"hello from the source\n"
    );
    assert_passed(&run(
        "trusted.pem",
        &["verify", "-nolinks", src.to_str().unwrap(), "s3://tls/data"],
    ));
    // control: a bundle that does not contain the server's certificate is refused
    assert_failed(
        &run("untrusted.pem", &["scan", "-q", "s3://tls/data"]),
        "TLS",
    );
    // -s3.noverify accepts it and says so on stderr
    let out = run(
        "untrusted.pem",
        &["scan", "-q", "-s3.noverify", "s3://tls/data"],
    );
    assert_passed(&out);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("WARN: -s3.noverify"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn show_asks_a_server_for_its_services_and_exports() {
    let s = Scratch::new("show");
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_PORTMAP_PORT", server.port.to_string())
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .unwrap()
    };
    let text = assert_passed(&run(&["show", "127.0.0.1"]));
    assert!(
        text.contains("host: 127.0.0.1")
            && text.contains("mountd")
            && text.contains("nfs")
            && text.contains("/export")
            && text.contains("127.0.0.0/8"),
        "{text}"
    );
    assert!(!text.contains("export details"), "-v only: {text}");
    let text = assert_passed(&run(&["show", "-v", "127.0.0.1"]));
    assert!(
        text.contains("export details")
            && text.contains("rtmax 1.0 MiB")
            && text.contains("total 1.0 TiB")
            && text.contains("free 512.0 GiB"),
        "{text}"
    );
    // control: a host with no portmapper is an error, and the run fails
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_PORTMAP_PORT", "1")
        .arg("-catalog")
        .arg(&cat)
        .args(["show", "127.0.0.1"])
        .output()
        .unwrap();
    assert_failed(&out, "portmapper");
    // the mounts listing is unchanged when no host is named
    let text = assert_passed(&run(&["show", "-all"]));
    assert!(text.contains("mount point"), "{text}");

    // `show` takes a HOST, and its error quotes the token back. So a URL typed here went
    // to the resolver and came back inside a message:
    //
    //   ERROR: show dav://user:hunter2@host/path: dav://user:hunter2@host/path: portmapper: ...
    //
    // which puts the password in the run's output and in whatever log caught it -- the
    // thing the endpoint refusals in `lib.rs` exist to prevent, reached through a command
    // that never parses an endpoint at all. Measured before the fix.
    for token in [
        "dav://user:hunter2@host/path",
        "https://user:hunter2@host/p",
        "user:hunter2@nfshost",
    ] {
        let out = run(&["show", token]);
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(
            !out.status.success(),
            "a token that is not a host was accepted: {token}\n{text}"
        );
        assert!(
            !text.contains("hunter2"),
            "the refusal repeated the password it was refusing: {token}\n{text}"
        );
        assert!(
            text.contains("takes an NFS host"),
            "the refusal does not say what show wants: {token}\n{text}"
        );
    }
    // the control: a plain host still reaches the resolver and is answered, so the guard
    // has not simply turned `show HOST` off
    let text = assert_passed(&run(&["show", "127.0.0.1"]));
    assert!(
        text.contains("host: 127.0.0.1") && text.contains("/export"),
        "{text}"
    );
}

#[test]
fn nfs_endpoints_rotate_across_server_addresses_and_skip_a_dead_one() {
    let s = Scratch::new("nfs-multi");
    let src = fixture(&s);
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let cat = s.path("catalog");
    // 127.0.0.2 has nothing listening: the mount and every connection fall through to 127.0.0.1
    let target = "127.0.0.2,127.0.0.1:/export:/a";
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "copy",
            "-noId",
            "-parallel",
            "3",
            src.to_str().unwrap(),
            target,
        ],
    ));
    assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "verify",
            src.to_str().unwrap(),
            "127.0.0.1,127.0.0.2:/export:/a",
        ],
    ));
    assert_eq!(
        fs::read(export.join("a/message.txt")).unwrap(),
        b"hello from the source\n"
    );
    // control: only dead addresses fail with the last address named
    assert_failed(
        &rcp_nfs(&cat, server.port, &["scan", "127.0.0.2,127.0.0.3:/export"]),
        "127.0.0.3",
    );
    assert_failed(
        &rcp_nfs(&cat, server.port, &["scan", ",127.0.0.1:/export"]),
        "empty one",
    );
}

#[test]
fn fileid_filter_and_help_info() {
    let s = Scratch::new("fileid");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let ino = fs::metadata(src.join("message.txt")).unwrap().ino();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-l",
            "-fileid",
            &ino.to_string(),
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("message.txt") && !text.contains("script.sh"),
        "{text}"
    );
    assert_failed(
        &rcp(&cat, &["scan", "-fileid", "x", src.to_str().unwrap()]),
        "not an inode number",
    );
    let text = stdout(&rcp(&cat, &["help", "info"]));
    assert!(
        text.contains("RCP INFO") && text.contains("PARALLELISM"),
        "{text}"
    );
    let text = stdout(&rcp(&cat, &["help", "filters"]));
    assert!(text.contains("-fileid 671907"), "{text}");
}

#[test]
fn sync_moves_renamed_files_on_the_destination_instead_of_recopying() {
    let s = Scratch::new("moves");
    let src = fixture(&s);
    let dst = s.path("destination");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "mv",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let before = fs::metadata(dst.join("nested/deeper/data.bin"))
        .unwrap()
        .ino();
    // a rename in place and a move into a new directory
    fs::rename(src.join("message.txt"), src.join("renamed.txt")).unwrap();
    fs::create_dir_all(src.join("moved")).unwrap();
    fs::rename(
        src.join("nested/deeper/data.bin"),
        src.join("moved/data.bin"),
    )
    .unwrap();
    fs::remove_dir(src.join("nested/deeper")).unwrap();
    let text = assert_passed(&rcp(&cat, &["sync", "dry-run", "-id", "mv"]));
    assert!(
        text.contains("> renamed.txt <- message.txt")
            && text.contains("> moved/data.bin <- nested/deeper/data.bin"),
        "{text}"
    );
    assert!(
        !text.contains("# message.txt") && !text.contains("+ renamed.txt"),
        "a move is neither a removal nor a new file: {text}"
    );
    let text = assert_passed(&rcp(&cat, &["sync", "dry-run", "-stats", "-id", "mv"]));
    assert!(
        text.contains("== Files by size ==") && text.contains("2 moved"),
        "{text}"
    );
    let text = assert_passed(&rcp(&cat, &["sync", "-id", "mv"]));
    assert!(
        text.contains("0 files (0 bytes)")
            && text.contains("2 moved")
            && text.contains("1 removed"),
        "{text}"
    );
    assert_eq!(
        fs::metadata(dst.join("moved/data.bin")).unwrap().ino(),
        before,
        "renamed, not recopied: same inode on the destination"
    );
    assert!(!dst.join("message.txt").exists());
    assert!(!dst.join("nested/deeper").exists());
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // the catalog followed: a second sync is a no-op and a resume has nothing to do
    let text = assert_passed(&rcp(&cat, &["sync", "-id", "mv"]));
    assert!(
        text.contains("0 files (0 bytes)")
            && text.contains("0 moved")
            && text.contains("0 removed"),
        "{text}"
    );
    // control: a file with the same name but new content is copied, not moved
    fs::write(src.join("renamed.txt"), b"changed\n").unwrap();
    let text = assert_passed(&rcp(&cat, &["sync", "-id", "mv"]));
    assert!(
        text.contains("1 files") && text.contains("0 moved"),
        "{text}"
    );
}

#[test]
fn moves_work_over_nfs_and_become_server_side_copies_on_s3() {
    let s = Scratch::new("moves-remote");
    let src = fixture(&s);
    let cat = s.path("catalog");
    // NFS: RENAME on the wire keeps the inode
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let nfs = rcp::nfs::testserver::Server::start(&export).unwrap();
    assert_passed(&rcp_nfs(
        &cat,
        nfs.port,
        &[
            "copy",
            "-newid",
            "nfs-mv",
            src.to_str().unwrap(),
            "127.0.0.1:/export:/t",
        ],
    ));
    let before = fs::metadata(export.join("t/nested/deeper/data.bin"))
        .unwrap()
        .ino();
    fs::rename(
        src.join("nested/deeper/data.bin"),
        src.join("data-moved.bin"),
    )
    .unwrap();
    let text = assert_passed(&rcp_nfs(&cat, nfs.port, &["sync", "-id", "nfs-mv"]));
    assert!(
        text.contains("1 moved") && text.contains("0 files (0 bytes)"),
        "{text}"
    );
    assert_eq!(
        fs::metadata(export.join("t/data-moved.bin")).unwrap().ino(),
        before
    );
    assert_passed(&rcp_nfs(
        &cat,
        nfs.port,
        &["verify", src.to_str().unwrap(), "127.0.0.1:/export:/t"],
    ));
    // S3: copy then delete, so the object's ETag (its content) is unchanged and no bytes moved
    let s3 = rcp::s3::testserver::Server::start(&["mv"], s3_creds());
    let secret = s3.creds.secret_key.clone();
    assert_passed(&rcp_s3(
        &cat,
        &s3,
        &secret,
        &[
            "copy",
            "-newid",
            "s3-mv",
            "-nolinks",
            src.to_str().unwrap(),
            "s3://mv/t",
        ],
    ));
    let etag = s3.object("mv", "t/data-moved.bin").unwrap().etag;
    fs::rename(src.join("data-moved.bin"), src.join("data-back.bin")).unwrap();
    let text = assert_passed(&rcp_s3(&cat, &s3, &secret, &["sync", "-id", "s3-mv"]));
    assert!(
        text.contains("1 moved") && text.contains("0 files (0 bytes)"),
        "{text}"
    );
    assert_eq!(s3.object("mv", "t/data-back.bin").unwrap().etag, etag);
    assert!(s3.object("mv", "t/data-moved.bin").is_none());
    assert_passed(&rcp_s3(
        &cat,
        &s3,
        &secret,
        &["verify", "-nolinks", src.to_str().unwrap(), "s3://mv/t"],
    ));
}

#[test]
fn diag_file_utilities_find_change_and_index_diagnosis() {
    let s = Scratch::new("diag");
    let src = fixture(&s);
    let cat = s.path("catalog");
    // file utilities: -cat streams bytes with no STATUS line, the rest report one
    let out = rcp(
        &cat,
        &["diag", "-cat", src.join("message.txt").to_str().unwrap()],
    );
    assert_eq!(
        (out.status.code(), out.stdout.as_slice()),
        (Some(0), &b"hello from the source\n"[..])
    );
    assert_passed(&rcp(
        &cat,
        &["diag", "-mkdir", src.join("made").to_str().unwrap()],
    ));
    assert!(src.join("made").is_dir());
    assert_passed(&rcp(
        &cat,
        &["diag", "-rmdir", src.join("made").to_str().unwrap()],
    ));
    assert!(!src.join("made").exists());
    assert_failed(
        &rcp(
            &cat,
            &["diag", "-rmdir", src.join("nested").to_str().unwrap()],
        ),
        "nested",
    );
    fs::create_dir_all(src.join("gone/deep")).unwrap();
    write(&src.join("gone/deep/x"), b"x", 0o644);
    assert_passed(&rcp(
        &cat,
        &["diag", "-rmrf", src.join("gone").to_str().unwrap()],
    ));
    assert!(!src.join("gone").exists());
    assert_failed(&rcp(&cat, &["diag"]), "needs one of");
    // find
    let text = assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "find",
            "-branch-match",
            "*.txt",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains(".  (1 of 3 files match)") && text.contains("diag find: 1 directories"),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &["diag", "find", "-top-match", "*.bin", src.to_str().unwrap()],
    ));
    assert!(
        text.contains("nested  (1 of 1 files match)") && !text.contains("\n.  "),
        "{text}"
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "find",
            "-q",
            "-branch-match",
            "*",
            "-minsize",
            "100k",
            src.to_str().unwrap(),
        ],
    ));
    assert!(text.trim().starts_with("diag find: 1 "), "{text}");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "find",
            "-fmt",
            "{path}",
            "-branch-match",
            "*",
            src.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("nested/deeper\n"), "{text}");
    // change: times, an owner map that maps the caller to itself, a direct -u
    assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "change",
            "-mtime",
            "2015-09-19_23:00:12+500",
            "-match",
            "*.sh",
            src.to_str().unwrap(),
        ],
    ));
    let m = fs::metadata(src.join("script.sh")).unwrap();
    assert_eq!((m.mtime(), m.mtime_nsec()), (1_442_703_612, 500));
    assert_eq!(
        fs::metadata(src.join("message.txt")).unwrap().mtime(),
        1_600_000_000,
        "-match limited the change"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "change",
            "-atime",
            "1600000000",
            "-depth",
            "1",
            src.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(src.join("empty")).unwrap().atime(),
        1_600_000_000
    );
    let me = euid();
    fs::write(s.path("umap.csv"), format!("# me to me\n{me},{me}\n")).unwrap();
    let text = assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "change",
            "-umap",
            s.path("umap.csv").to_str().unwrap(),
            "-v",
            src.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("changed message.txt") && text.contains("entries changed"),
        "{text}"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "change",
            "-u",
            &me.to_string(),
            "-type",
            "f",
            src.to_str().unwrap(),
        ],
    ));
    assert_failed(
        &rcp(
            &cat,
            &[
                "diag",
                "change",
                "-mtime",
                "yesterday",
                src.to_str().unwrap(),
            ],
        ),
        "YYYY-MM-DD",
    );
    assert_failed(
        &rcp(&cat, &["diag", "change", src.to_str().unwrap()]),
        "needs -u/-g",
    );
    // index diagnosis and rebuild
    let dst = s.path("dst");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "idx",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    let text = assert_passed(&rcp(&cat, &["diag", "indexdiag", "-id", "idx"]));
    assert!(text.contains("0 orphans, 0 missing, 0 unlisted"), "{text}");
    fs::remove_file(dst.join("empty")).unwrap();
    write(&dst.join("extra"), b"e", 0o644);
    assert_failed(
        &rcp(&cat, &["diag", "indexdiag", "-id", "idx"]),
        "missing empty",
    );
    let text = assert_passed(&rcp(&cat, &["diag", "indexdiag", "-id", "idx", "-rebuild"]));
    assert!(text.contains("index idx.rebuilt rebuilt"), "{text}");
    let text = assert_passed(&rcp(&cat, &["indexlist"]));
    assert!(text.contains("idx.rebuilt\t"), "{text}");
    assert_passed(&rcp(&cat, &["diag", "indexdiag", "-id", "idx.rebuilt"]));
    let text = assert_passed(&rcp(&cat, &["diag", "rebuild", "-id", "idx"]));
    assert!(text.contains("replaced the original"), "{text}");
    assert_passed(&rcp(&cat, &["diag", "indexdiag", "-id", "idx"]));
    assert_passed(&rcp(&cat, &["diag", "-rmid", "idx.rebuilt"]));
    assert_failed(&rcp(&cat, &["diag", "-rmid", "idx.rebuilt"]), "idx.rebuilt");
    let text = assert_passed(&rcp(&cat, &["diag", "dump"]));
    assert!(text.contains("diag dump:"), "{text}");
}

#[test]
fn diag_nio_generates_io_locally_and_over_the_wire() {
    let s = Scratch::new("nio");
    let target = s.path("target");
    fs::create_dir_all(&target).unwrap();
    let cat = s.path("catalog");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "nio",
            "-t",
            "1",
            "-parallel",
            "2",
            "-npend",
            "2",
            "-size",
            "1m",
            "-bs",
            "64k",
            "-random",
            "-read%",
            "50",
            target.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("nio: 2 files x 4 threads"), "{text}");
    let ops = |line: &str| {
        line.split_whitespace()
            .nth(1)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let read_ops = text
        .lines()
        .find(|l| l.trim_start().starts_with("read "))
        .map(ops)
        .unwrap_or(0);
    let write_ops = text
        .lines()
        .find(|l| l.trim_start().starts_with("write "))
        .map(ops)
        .unwrap_or(0);
    assert!(read_ops > 0 && write_ops > 0, "{text}");
    assert!(
        fs::read_dir(&target).unwrap().count() == 0,
        "worker files removed"
    );
    // over NFS: reads through the port, writes as whole-file rewrites
    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "diag",
            "nio",
            "-t",
            "1",
            "-parallel",
            "1",
            "-npend",
            "2",
            "-size",
            "256k",
            "-bs",
            "64k",
            "-sequential",
            "-read",
            "127.0.0.1:/export",
        ],
    ));
    assert!(
        text.lines()
            .find(|l| l.trim_start().starts_with("read "))
            .map(ops)
            .unwrap_or(0)
            > 0,
        "{text}"
    );
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &[
            "diag",
            "nio",
            "-t",
            "1",
            "-parallel",
            "1",
            "-npend",
            "1",
            "-size",
            "256k",
            "-bs",
            "64k",
            "-write",
            "-wrdata",
            "127.0.0.1:/export",
        ],
    ));
    assert!(
        text.lines()
            .find(|l| l.trim_start().starts_with("write "))
            .map(ops)
            .unwrap_or(0)
            > 0,
        "{text}"
    );
    assert!(
        fs::read_dir(&export).unwrap().count() == 0,
        "worker files removed from the export"
    );
    assert_failed(
        &rcp(
            &cat,
            &["diag", "nio", "-read%", "150", target.to_str().unwrap()],
        ),
        "percentage",
    );
}

/// A stand-in for ssh: drops the `-o BatchMode=yes HOST` prefix and runs the command line
/// locally, with the freshly built rcp first on PATH.
fn ssh_stub(s: &Scratch) -> PathBuf {
    let stub = s.path("ssh-stub.sh");
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_rcp"))
        .parent()
        .unwrap()
        .display()
        .to_string();
    write(&stub, format!("#!/bin/sh\n# args: -o BatchMode=yes HOST 'command line'\nshift 3\nexport PATH=\"{bin_dir}:$PATH\"\neval \"exec $1\"\n").as_bytes(), 0o755);
    stub
}

fn rcp_fleet(catalog: &Path, stub: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", stub)
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

#[test]
fn nodes_spread_the_files_over_workers_and_the_coordinator_keeps_the_catalog() {
    let s = Scratch::new("nodes");
    let src = fixture(&s);
    fs::hard_link(src.join("message.txt"), src.join("nested/also-message.txt")).unwrap();
    let dst = s.path("dst");
    let cat = s.path("catalog");
    let stub = ssh_stub(&s);
    let text = assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &[
            "copy",
            "-newid",
            "fleet",
            "-nodes",
            "w0,w1",
            "-bs",
            "256k",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        text.contains("copy: 4 files")
            && text.contains("1 linked")
            && text.contains("engine nodes"),
        "{text}"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    assert_eq!(
        fs::metadata(dst.join("script.sh")).unwrap().mode() & 0o7777,
        0o755,
        "workers apply metadata"
    );
    // the catalog is the coordinator's: it has digests and drives resume and sync
    let index = fs::read_to_string(cat.join("fleet/index.tsv")).unwrap();
    assert!(
        index.lines().any(|l| l.starts_with("message.txt\tf\t")
            && l.contains(&sha256_of(&src.join("message.txt")))),
        "{index}"
    );
    let text = assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &["resume", "-id", "fleet", "-nodes", "w0"],
    ));
    assert!(
        text.contains("0 files (0 bytes)") && text.contains("5 skipped"),
        "four files and the link: {text}"
    );
    fs::write(src.join("message.txt"), b"changed by the source\n").unwrap();
    let text = assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &["sync", "-id", "fleet", "-nodes", "w0,w1"],
    ));
    assert!(
        text.contains("1 files") && text.contains("engine nodes"),
        "{text}"
    );
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
    ));
    // scan over the fleet lists what a local scan lists
    let local = assert_passed(&rcp(
        &cat,
        &["scan", "-csv", "-sha256", src.to_str().unwrap()],
    ));
    let fleet = assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &[
            "scan",
            "-csv",
            "-sha256",
            "-nodes",
            "w0,w1",
            src.to_str().unwrap(),
        ],
    ));
    let rows = |t: &str| {
        t.lines()
            .filter(|l| {
                l.len() > 2
                    && matches!(l.as_bytes()[0], b'f' | b'd' | b'l')
                    && l.as_bytes()[1] == b','
            })
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>()
    };
    assert_eq!(
        rows(&local),
        rows(&fleet),
        "local:\n{local}\nfleet:\n{fleet}"
    );
    // controls: a fleet nobody can reach fails every file and the run; an empty list is refused
    let text = assert_failed(
        &rcp_fleet(
            &cat,
            Path::new("/bin/false"),
            &[
                "copy",
                "-noId",
                "-nodes",
                "w9",
                src.to_str().unwrap(),
                s.path("dst2").to_str().unwrap(),
            ],
        ),
        "node w9",
    );
    assert!(
        text.contains("4 entries failed") || text.contains("entries failed"),
        "{text}"
    );
    assert_failed(
        &rcp_fleet(
            &cat,
            &stub,
            &[
                "copy",
                "-noId",
                "-nodes",
                ",",
                src.to_str().unwrap(),
                s.path("dst3").to_str().unwrap(),
            ],
        ),
        "comma-separated",
    );
}

#[test]
fn copybatch_runs_a_user_program_with_the_line_protocol() {
    let s = Scratch::new("copybatch");
    let src = fixture(&s);
    let dst = s.path("dst");
    let cat = s.path("catalog");
    // a worker in shell: copies with cp, reports one line per path, refuses one path on purpose
    let prog = s.path("worker.sh");
    write(
        &prog,
        b"#!/bin/sh\nsrc=$1; dst=$2\ntr '\\0' '\\n' | while IFS= read -r p; do\n  if [ \"$p\" = script.sh ]; then printf 'fail\\t%s\\tnot today\\n' \"$p\"; continue; fi\n  mkdir -p \"$dst/$(dirname \"$p\")\" && cp \"$src/$p\" \"$dst/$p\" && printf 'ok\\t%s\\t%s\\t\\t0\\t0\\n' \"$p\" \"$(wc -c < \"$src/$p\")\"\ndone\n",
        0o755,
    );
    let text = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-copybatch",
                prog.to_str().unwrap(),
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "script.sh: node localhost: not today",
    );
    assert!(
        text.contains("3 files") && text.contains("engine nodes"),
        "{text}"
    );
    assert_eq!(
        fs::read(dst.join("nested/deeper/data.bin")).unwrap().len(),
        300_000
    );
    assert!(!dst.join("script.sh").exists());
    // with the refusal removed the same program passes, and verify agrees on the bytes
    fs::write(
        &prog,
        fs::read_to_string(&prog)
            .unwrap()
            .replace("= script.sh", "= never"),
    )
    .unwrap();
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-copybatch",
            prog.to_str().unwrap(),
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nodata",
            "-noattrs",
            "-nolinks",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-noattrs",
            "-nolinks",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
}

fn rcp_hdfs(catalog: &Path, server: &rcp::hdfs::testserver::Server, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("HDFS_NAMENODE", format!("127.0.0.1:{}", server.port))
        .env("NO_PROXY", "*")
        .env("HADOOP_USER_NAME", "tester")
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

/// A namenode picks where the bytes go. A railed run does not have to let it pick freely.
///
/// WebHDFS is two steps: the namenode answers OPEN and CREATE with a 307 naming a
/// datanode, and the client opens a second connection there. On a CREATE that second
/// connection carries the file body, and the redirect's query string can carry a
/// delegation token -- so a namenode that names a host of its choosing is choosing where
/// this run's data and credentials land. Exactly the OCI upload-`Location` shape, which
/// was closed for registries while this stayed open, because the policy lived inside the
/// registry adapter. It now lives in `ports`.
///
/// The observation is a second listener that the run reaches only if it follows the
/// redirect. Counting its connections is the measurement, and the
/// control is the same copy unrailed, which must reach it.
#[test]
fn a_namenode_redirect_may_not_send_a_railed_run_to_an_unnamed_host() {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let s = Scratch::new("hdfs-away");
    let root = s.path("hdfs-root");
    fs::create_dir_all(root.join("in")).unwrap();
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(
        &src.join("payload.bin"),
        b"the bytes a hostile namenode would like\n",
        0o644,
    );

    // the "datanode" the namenode will name: it answers nothing useful, it only counts
    let away = TcpListener::bind("127.0.0.1:0").unwrap();
    let away_port = away.local_addr().unwrap().port();
    let dialed = Arc::new(AtomicUsize::new(0));
    let counter = dialed.clone();
    std::thread::spawn(move || {
        for stream in away.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let server = rcp::hdfs::testserver::Server::start_redirecting_to(&root, away_port).unwrap();
    let cat = s.path("catalog");
    let namenode = format!("hdfs://127.0.0.1:{}", server.port);

    // railed to the namenode and nowhere else: the hand-off is refused, by name, before
    // the connection is made
    let out = rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            "-allow",
            &namenode,
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
            &format!("{namenode}/in"),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    // the connection count first, because it is the only one of the three that an
    // incidental failure cannot satisfy: with the gate removed the copy still FAILS --
    // the stand-in datanode drops the connection -- so a bare "it did not succeed" would
    // pass either way. What separates the two worlds is whether the socket was opened.
    assert_eq!(
        dialed.load(Ordering::SeqCst),
        0,
        "the away listener was dialed by a railed run:\n{text}"
    );
    assert!(
        text.contains("redirected to") && text.contains(&format!("127.0.0.1:{away_port}")),
        "the refusal does not name where it was being sent:\n{text}"
    );
    assert!(
        !out.status.success(),
        "a railed run followed the redirect:\n{text}"
    );

    // the rail still admits the namenode itself, which is not on the -allow list as an
    // http authority but is the endpoint the operator wrote: a scan reaches it and works
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["scan", "-allow", &namenode, &format!("{namenode}/in")],
    ));
    assert_eq!(
        dialed.load(Ordering::SeqCst),
        0,
        "a namenode-only operation reached the away host"
    );

    // The control, and it is what makes the arm a measurement rather than an assertion
    // that HDFS is broken: an UNRAILED run follows the redirect, because naming the
    // cluster is already the statement of trust and a real cluster IS datanodes. Remove
    // the gate and the first arm passes this one too; keep the gate and only this one
    // reaches the listener.
    let out = rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            src.to_str().unwrap(),
            &format!("{namenode}/in"),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        dialed.load(Ordering::SeqCst) > 0,
        "an unrailed run did not follow the redirect, so the arm above proves nothing:\n{text}"
    );

    // and one named away host is allowed through, so the rail is a list rather than a ban
    let out = rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            "-allow",
            &namenode,
            "-allow",
            &format!("http://127.0.0.1:{away_port}"),
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
            &format!("{namenode}/in"),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !text.contains("redirected to"),
        "a named away host was still refused:\n{text}"
    );
}

/// The authority of a URL is what follows the `@`, and the two adapters that follow a
/// remote's choice of host did not agree about it: the registry client stripped userinfo
/// and the WebHDFS one did not, so `http://hdfs@127.0.0.1:9864/` parsed with a host of
/// `hdfs@127.0.0.1` -- a name that matches no rail and resolves nowhere. The asymmetry is
/// visible only when the two parsers are read side by side.
///
/// Both halves matter and they pull opposite ways, which is why this is one arm with two
/// servers rather than two arms. Strip too little and a legal redirect is refused; strip
/// too much -- taking the part BEFORE the `@` as the host, the way a hurried reader does
/// -- and `-allow` is satisfied by a name the connection never goes to. The second server
/// is the control: it puts the allowed authority in the userinfo and the real one after
/// it, and the run must still be refused.
#[test]
fn the_authority_of_a_redirect_is_what_follows_the_at_sign() {
    let s = Scratch::new("hdfs-userinfo");
    let root = s.path("hdfs-root");
    fs::create_dir_all(root.join("in")).unwrap();
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(
        &src.join("payload.bin"),
        b"a redirect with a user in it\n",
        0o644,
    );
    let cat = s.path("catalog");

    // a namenode that redirects to ITSELF, named with userinfo. The operator railed the
    // namenode, the redirect goes to the same authority, so this must be allowed and the
    // copy must land.
    let server = rcp::hdfs::testserver::Server::start_redirecting_as(&root, None, "hdfs@").unwrap();
    let namenode = format!("hdfs://127.0.0.1:{}", server.port);
    let out = rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            "-allow",
            &namenode,
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
            &format!("{namenode}/in"),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        out.status.success(),
        "a redirect to the railed authority, written with userinfo, was refused:\n{text}"
    );
    assert_eq!(
        fs::read(root.join("in/payload.bin")).unwrap(),
        b"a redirect with a user in it\n"
    );

    // The control. This namenode's redirect reads `http://127.0.0.2:9999@127.0.0.1:AWAY/`
    // -- the allowed authority sitting in the userinfo, the real one after the `@`, and
    // AWAY is a listener the rail does not name. A parser that stopped at the `@` would
    // read `127.0.0.2:9999`, find it on the list and dial AWAY anyway. Counting AWAY's
    // connections is what separates the two worlds, exactly as in the sibling arm: with
    // the userinfo mishandled either way the copy fails, so a bare failure proves nothing.
    let away = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let away_port = away.local_addr().unwrap().port();
    let dialed = Arc::new(AtomicUsize::new(0));
    let counter = dialed.clone();
    std::thread::spawn(move || {
        for stream in away.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let decoy = rcp::hdfs::testserver::Server::start_redirecting_as(
        &root,
        Some(away_port),
        "127.0.0.2:9999@",
    )
    .unwrap();
    let decoy_node = format!("hdfs://127.0.0.1:{}", decoy.port);
    let out = rcp_hdfs(
        &cat,
        &decoy,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            "-allow",
            "http://127.0.0.2:9999",
            "-allow",
            &decoy_node,
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
            &format!("{decoy_node}/in"),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert_eq!(
        dialed.load(Ordering::SeqCst),
        0,
        "userinfo naming an allowed host let a railed run dial an unnamed one:\n{text}"
    );
    assert!(
        !out.status.success(),
        "userinfo naming an allowed host let a redirect through:\n{text}"
    );
    assert!(
        text.contains("redirected to") && text.contains(&format!("127.0.0.1:{away_port}")),
        "the refusal does not name where it was really being sent:\n{text}"
    );
}

#[test]
fn hdfs_endpoints_copy_verify_sync_scan_and_delete_over_webhdfs() {
    let s = Scratch::new("hdfs");
    let src = fixture(&s);
    let root = s.path("hdfs-root");
    fs::create_dir_all(&root).unwrap();
    let server = rcp::hdfs::testserver::Server::start(&root).unwrap();
    let cat = s.path("catalog");
    let explicit = format!("{}/in", server.endpoint());
    // local -> HDFS with an explicit namenode; symlinks are refused by the namenode, so
    // regular files only, and times are kept to the millisecond
    let text = assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "copy",
            "-newid",
            "to-hdfs",
            "-type",
            "f",
            src.to_str().unwrap(),
            &explicit,
        ],
    ));
    assert!(
        text.contains("copy: 4 files") && text.contains("3 directories"),
        "{text}"
    );
    assert_eq!(
        fs::read(root.join("in/message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::metadata(root.join("in/script.sh")).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(root.join("in/message.txt")).unwrap().mtime(),
        1_600_000_000
    );
    assert_eq!(
        fs::metadata(root.join("in/nested")).unwrap().mode() & 0o777,
        0o750
    );
    // the symlinks are reported as failures, not silently dropped
    let text = assert_failed(
        &rcp_hdfs(
            &cat,
            &server,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                &format!("{}/with-links", server.endpoint()),
            ],
        ),
        "symlink dangling",
    );
    assert!(text.contains("UnsupportedOperationException"), "{text}");
    // hdfs:///path takes the namenode from the environment; verify both ways with a window for the milliseconds
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "verify",
            "-type",
            "f",
            "-mtimewindow",
            "1",
            src.to_str().unwrap(),
            "hdfs:///in",
        ],
    ));
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "verify",
            "-type",
            "f",
            "-mtimewindow",
            "1",
            "hdfs:///in",
            src.to_str().unwrap(),
        ],
    ));
    // control: the bytes are compared
    fs::write(root.join("in/message.txt"), b"hello from the sOurce\n").unwrap();
    assert_failed(
        &rcp_hdfs(
            &cat,
            &server,
            &[
                "verify",
                "-type",
                "f",
                "-nomods",
                src.to_str().unwrap(),
                "hdfs:///in",
            ],
        ),
        "DIFF content message.txt",
    );
    // sync repairs it, removes what the source dropped and renames what the source renamed
    fs::remove_file(src.join("empty")).unwrap();
    fs::rename(
        src.join("nested/deeper/data.bin"),
        src.join("nested/data-moved.bin"),
    )
    .unwrap();
    let text = assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["sync", "-id", "to-hdfs", "-type", "f"],
    ));
    assert!(
        text.contains("1 files") && text.contains("1 moved") && text.contains("1 removed"),
        "{text}"
    );
    assert!(root.join("in/nested/data-moved.bin").is_file());
    assert!(!root.join("in/nested/deeper/data.bin").exists());
    assert!(!root.join("in/empty").exists());
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "verify",
            "-type",
            "f",
            "-mtimewindow",
            "1",
            src.to_str().unwrap(),
            "hdfs:///in",
        ],
    ));
    // HDFS -> local, scan, chmod and delete over the wire
    let back = s.path("back");
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["copy", "-noId", "hdfs:///in", back.to_str().unwrap()],
    ));
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "verify",
            "-type",
            "f",
            "-mtimewindow",
            "1",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    let text = assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["scan", "-l", "-stats", "hdfs:///"],
    ));
    assert!(
        text.contains("in/message.txt") && text.contains("== Files by size =="),
        "{text}"
    );
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["chmod", "0600", "-match", "*.sh", "hdfs:///in"],
    ));
    assert_eq!(
        fs::metadata(root.join("in/script.sh")).unwrap().mode() & 0o777,
        0o600
    );
    assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &["delete", "-force", "-removetopdir", "hdfs:///in"],
    ));
    assert!(!root.join("in").exists());
    assert_failed(
        &rcp_hdfs(&cat, &server, &["scan", "hdfs:///missing"]),
        "no such path",
    );
    // a dry run into a directory that is not there yet plans against an empty one, and
    // creates nothing, rather than failing at open
    let dry = assert_passed(&rcp_hdfs(
        &cat,
        &server,
        &[
            "isync",
            "-dryrun",
            "-type",
            "f",
            src.to_str().unwrap(),
            "hdfs:///fresh",
        ],
    ));
    assert!(
        dry.contains("+ message.txt") && !root.join("fresh").exists(),
        "{dry}"
    );
    assert_failed(
        &rcp_hdfs(
            &cat,
            &server,
            &["copy", "-noId", "hdfs:///a", "hdfs:///a/b"],
        ),
        "inside source",
    );
}

/// A stand-in registry (tests/support/registry_stub.py) on a free port; dies with the test.
struct Registry {
    child: std::process::Child,
    port: u16,
}

impl Registry {
    fn start(args: &[&str]) -> Registry {
        use std::io::BufRead;
        let stub = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/registry_stub.py");
        let mut child = Command::new("python3")
            .arg(&stub)
            .arg("0")
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("python3 runs the registry stand-in");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line
            .trim()
            .strip_prefix("ready ")
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("registry stand-in did not report a port: {line:?}"));
        Registry { child, port }
    }
    fn url(&self, repo: &str) -> String {
        format!("oci://127.0.0.1:{}/{repo}", self.port)
    }
    /// `GET /_stub/<what>`: a control the stand-in offers, for a state a copy cannot make.
    fn control(&self, what: &str) {
        use std::io::{Read, Write};
        let mut c = std::net::TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        write!(c, "GET /_stub/{what} HTTP/1.0\r\nHost: stub\r\n\r\n").unwrap();
        let mut text = String::new();
        c.read_to_string(&mut text).unwrap();
        assert!(text.contains(" 200 "), "{text}");
    }

    /// `GET /_stub/stats`: the upload counters, as the stand-in's JSON.
    fn stats(&self) -> String {
        use std::io::{Read, Write};
        let mut c = std::net::TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.write_all(b"GET /_stub/stats HTTP/1.0\r\nHost: stub\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        c.read_to_string(&mut text).unwrap();
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }
    fn stat(&self, key: &str) -> u64 {
        let s = self.stats();
        s.split(&format!("\"{key}\": "))
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no {key} in {s}"))
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An OCI image layout with two tags: `v1` is a manifest, `latest` an index of that
/// manifest (amd64) and a second one (arm64); a config and two layers, one shared.
/// `rcp delete` over a registry prints a count, and that count claimed things that had not
/// happened. Three of them, all reaching the operator as "N removed":
///
/// - A blob `DELETE` answered **405**. Docker Hub, ECR and Artifact Registry all answer
///   that: blobs belong to the registry's garbage collector, not to its clients. The
///   adapter logged a debug line saying so and returned `Ok(())`, which `transfer` counts.
/// - The pseudo-entries a registry does not have -- `index.json`, `oci-layout`, and every
///   directory -- returned `Ok(())` without a request being made at all.
/// - And the two were indistinguishable from a real removal, because `Sink::remove` had
///   exactly two answers: error, or removed.
///
/// That is a missing state in the port, not a wording problem. The measurement is the
/// registry's own refusal counter against the number rcp printed; the control is the
/// manifest, which the same run really does remove, so an arm that merely counted nothing
/// would fail too.
#[test]
fn a_registry_that_keeps_a_blob_is_not_a_blob_removed() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-delete");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);
    let app = reg.url("app");

    let text = assert_passed(&rcp(
        &cat,
        &["delete", "-force", "-removetopdir", "-oci.insecure", &app],
    ));
    let refused = reg.stat("blob_delete_refused");
    assert!(
        refused > 0,
        "the stand-in never refused a blob delete, so this arm measures nothing: {}",
        reg.stats()
    );
    // the two counts rcp printed, parsed out of its own summary line
    let summary = text
        .lines()
        .find(|l| l.starts_with("delete: "))
        .unwrap_or_else(|| panic!("no delete summary:\n{text}"));
    let count = |word: &str| -> usize {
        let toks: Vec<&str> = summary.split_whitespace().collect();
        toks.iter()
            .position(|t| t.trim_end_matches([',', ';']) == word)
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| toks[i].parse().ok())
            .unwrap_or_else(|| panic!("the summary has no {word} count:\n{summary}"))
    };
    let (files, deferred) = (count("files"), count("deferred"));
    // Eight entries were enumerated: six blobs (three of them manifests) plus the two
    // views, `index.json` and `oci-layout`. Three of the six the registry refuses. So the
    // sum is fixed at eight and the SPLIT is the claim: every refusal must land on the
    // deferred side, and the previous code put all eight on the removed side. Deferred
    // and not kept: the registry's collector removes blobs, so the run still passes --
    // `assert_passed` above is part of this arm.
    assert_eq!(deferred, refused as usize, "the registry refused {refused} blob deletes and rcp reported {deferred} deferred:\n{text}\n{}", reg.stats());
    assert_eq!(files + deferred, 8, "the entry count changed; this arm is about the split, so the total has to be pinned:\n{text}");
    assert!(
        text.contains("garbage collection") && text.contains("DEFERRED:"),
        "a deferred entry must say who will remove it and why:\n{text}"
    );
    assert!(
        !text.contains("kept"),
        "a registry's garbage collection is deferral, not refusal:\n{text}"
    );

    // The control: the manifest IS removed, by the same run, and the registry proves it by
    // no longer serving the image. Without this the arm would pass on a delete that did
    // nothing at all, which is the opposite defect and just as wrong.
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &app,
            s.path("back").to_str().unwrap(),
        ],
    );
    assert!(
        !out.status.success(),
        "the image is still served after delete, so nothing was removed:\n{}",
        stdout(&out)
    );
}

fn oci_layout(dir: &Path) -> std::collections::BTreeMap<&'static str, String> {
    let blobs = dir.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let put = |data: &[u8]| -> (String, usize) {
        let h = rcp::sha256::digest_hex(data);
        fs::write(blobs.join(&h), data).unwrap();
        (h, data.len())
    };
    let (cfg, cfg_n) = put(br#"{"architecture":"amd64","os":"linux","config":{"Env":["A=1"]},"rootfs":{"type":"layers","diff_ids":[]}}"#);
    let (l1, l1_n) = put(&noise(300 << 10, 7));
    let (l2, l2_n) = put(&noise((1 << 20) + 17, 8));
    let layer = "application/vnd.oci.image.layer.v1.tar+gzip";
    let manifest = "application/vnd.oci.image.manifest.v1+json";
    let index = "application/vnd.oci.image.index.v1+json";
    let config = format!(
        r#"{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg}","size":{cfg_n}}}"#
    );
    let (m1, m1_n) = put(format!(r#"{{"schemaVersion":2,"mediaType":"{manifest}","config":{config},"layers":[{{"mediaType":"{layer}","digest":"sha256:{l1}","size":{l1_n}}}]}}"#).as_bytes());
    let (m2, m2_n) = put(format!(r#"{{"schemaVersion":2,"mediaType":"{manifest}","config":{config},"layers":[{{"mediaType":"{layer}","digest":"sha256:{l1}","size":{l1_n}}},{{"mediaType":"{layer}","digest":"sha256:{l2}","size":{l2_n}}}]}}"#).as_bytes());
    let (idx, idx_n) = put(format!(r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":[{{"mediaType":"{manifest}","digest":"sha256:{m1}","size":{m1_n},"platform":{{"architecture":"amd64","os":"linux"}}}},{{"mediaType":"{manifest}","digest":"sha256:{m2}","size":{m2_n},"platform":{{"architecture":"arm64","os":"linux"}}}}]}}"#).as_bytes());
    fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    fs::write(dir.join("index.json"), format!(r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{index}","digest":"sha256:{idx}","size":{idx_n},"annotations":{{"org.opencontainers.image.ref.name":"latest"}}}},{{"mediaType":"{manifest}","digest":"sha256:{m1}","size":{m1_n},"annotations":{{"org.opencontainers.image.ref.name":"v1"}}}}]}}"#)).unwrap();
    [
        ("config", cfg),
        ("layer1", l1),
        ("layer2", l2),
        ("m1", m1),
        ("m2", m2),
        ("index", idx),
    ]
    .into_iter()
    .collect()
}

#[test]
fn oci_endpoints_mirror_images_between_registries_and_layouts() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci");
    let layout = s.path("layout");
    let digests = oci_layout(&layout);
    let cat = s.path("catalog");
    // three registries: one seeded with the image (open), one behind the token dance, one
    // behind basic credentials
    let source = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);
    let hub = Registry::start(&["--token"]);
    let private = Registry::start(&["--user", "mirror:s3cret"]);
    let app = source.url("app");

    // registry -> registry: every blob and manifest crosses once, in dependency order
    let out = rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "mirror",
            "-loglevel",
            "DEBUG",
            "-oci.insecure",
            &app,
            &hub.url("mirror"),
        ],
    );
    let text = assert_passed(&out);
    assert!(text.contains("copy: 8 files"), "{text}");
    let debug = String::from_utf8_lossy(&out.stderr);
    assert!(
        debug.contains("oci token for")
            && debug.contains("pushed latest ->")
            && debug.contains("pushed v1 ->"),
        "{debug}"
    );
    assert_eq!(
        (hub.stat("blob_uploads"), hub.stat("manifest_pushes")),
        (3, 3),
        "{}",
        hub.stats()
    );
    assert_passed(&rcp(
        &cat,
        &["verify", "-oci.insecure", &app, &hub.url("mirror")],
    ));
    // a second mirror on the same registry moves no blob and reads none from the source
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-loglevel",
            "DEBUG",
            "-oci.insecure",
            &app,
            &hub.url("mirror2"),
        ],
    );
    assert_passed(&out);
    let debug = String::from_utf8_lossy(&out.stderr);
    assert!(
        !debug.contains("GET blob"),
        "a present blob was read from the source:\n{debug}"
    );
    assert_eq!(
        (hub.stat("blob_uploads"), hub.stat("manifest_pushes")),
        (3, 6),
        "{}",
        hub.stats()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-oci.insecure",
            &hub.url("mirror"),
            &hub.url("mirror2"),
        ],
    ));

    // registry -> directory: a layout whose blobs are named by their content, and whose
    // index.json is what skopeo writes
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &app,
            back.to_str().unwrap(),
        ],
    ));
    for hex in digests.values() {
        let p = back.join("blobs/sha256").join(hex);
        assert!(p.exists(), "{} missing", p.display());
        assert_eq!(&sha256_of(&p), hex);
    }
    assert_eq!(
        fs::read(back.join("index.json")).unwrap(),
        fs::read(layout.join("index.json")).unwrap()
    );
    assert_eq!(
        fs::read(back.join("oci-layout")).unwrap(),
        fs::read(layout.join("oci-layout")).unwrap()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            layout.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));

    // directory -> registry with basic credentials.
    //
    // DO NOT MAKE THIS ARM ASSERT THE DEFECT. It is tempting to read "the registry keeps no
    // times, so a verify sees them differ" and require `assert_failed(verify, "DIFF mtime")`
    // -- but that pins in place the exact contradiction `keeps_times` exists to prevent,
    // which is worse than having no arm, because it makes the defect look intended. A
    // registry stores no times at all, and an `OciTree` that kept the trait's default `true`
    // would report a correct and complete copy as an mtime difference on every file.
    let fromdisk = private.url("fromdisk");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            layout.to_str().unwrap(),
            &fromdisk,
        ],
    ));
    assert_eq!(
        (
            private.stat("blob_uploads"),
            private.stat("manifest_pushes")
        ),
        (3, 3),
        "{}",
        private.stats()
    );
    let text = assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            layout.to_str().unwrap(),
            &fromdisk,
        ],
    ));
    assert!(
        !text.contains("DIFF mtime"),
        "verify compared mtimes against a registry that stores none:\n{text}"
    );
    assert!(
        text.contains("modification times were not compared"),
        "the skipped comparison is not reported:\n{text}"
    );
    // the control: `-nomods` asked for no mtime comparison and still passes, so the arm
    // above is not passing because verify stopped comparing anything
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            layout.to_str().unwrap(),
            &fromdisk,
        ],
    ));
    // one tag: only what it reaches
    let one = private.url("one");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            &format!("{app}:v1"),
            &one,
        ],
    ));
    assert!(text.contains("copy: 5 files"), "{text}");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-l",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            &one,
        ],
    ));
    assert!(
        text.contains(&digests["m1"])
            && text.contains(&digests["layer1"])
            && !text.contains(&digests["layer2"])
            && !text.contains(&digests["index"]),
        "{text}"
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-oci.insecure",
                "-oci.user",
                "mirror:s3cret",
                &format!("{one}:latest"),
            ],
        ),
        "no such tag",
    );
    // A registry keeps no modes, owners or times -- the `-nomods` lines above are that
    // fact already -- so `chmod` and `chown` against one have nothing to change. Walking the
    // whole image, accepting every change, keeping none of it and reporting the count would
    // be a silent success that produces nothing, which is the pattern this codebase refuses
    // everywhere else. So they refuse by name, as the README says, rather than letting
    // `set_metadata` quietly return Ok.
    assert_failed(
        &rcp(
            &cat,
            &[
                "chmod",
                "-oci.insecure",
                "-oci.user",
                "mirror:s3cret",
                "-mode",
                "755",
                &fromdisk,
            ],
        ),
        "cannot change modes, owners or times once written",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "chown",
                "-oci.insecure",
                "-oci.user",
                "mirror:s3cret",
                "-user",
                "root",
                &fromdisk,
            ],
        ),
        "cannot change modes, owners or times once written",
    );
    // the control: a directory DOES keep them, so the same two commands still work --
    // a refusal keyed on the wrong thing would pass the two lines above and break every
    // ordinary chmod
    assert_passed(&rcp(
        &cat,
        &[
            "chmod",
            "-mode",
            "755",
            "-type",
            "f",
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::metadata(back.join("oci-layout"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    // delete removes the tags; the blobs stay for the registry's own collection
    assert_passed(&rcp(
        &cat,
        &[
            "delete",
            "-force",
            "-oci.insecure",
            "-oci.user",
            "mirror:s3cret",
            &one,
        ],
    ));
    assert_failed(
        &rcp(
            &cat,
            &["scan", "-oci.insecure", "-oci.user", "mirror:s3cret", &one],
        ),
        "no tags",
    );
    // controls: wrong credentials, a missing repository and tag, and endpoints that do
    // not parse
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-oci.insecure",
                "-oci.user",
                "mirror:wrong",
                &fromdisk,
            ],
        ),
        "refused the credentials",
    );
    assert_failed(
        &rcp(&cat, &["scan", "-oci.insecure", &source.url("nosuch")]),
        "no such repository",
    );
    assert_failed(
        &rcp(&cat, &["scan", "-oci.insecure", &format!("{app}:nosuch")]),
        "no such tag",
    );
    assert_failed(
        &rcp(&cat, &["scan", "-oci.insecure", "oci://127.0.0.1"]),
        "names no repository",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-oci.insecure",
                &format!("{app}@sha256:{}", digests["m1"]),
            ],
        ),
        "name a tag",
    );
    assert_failed(
        &rcp(
            &cat,
            &["scan", "-oci.insecure", "-oci.user", "nocolon", &app],
        ),
        "USER:PASSWORD",
    );
}

/// Every line of a `-json` run, parsed. The parser is deliberately small and strict: a
/// line that is not one flat JSON object of string, number and boolean fields fails here,
/// which is the property the arm is about.
fn events(out: &Output) -> Vec<std::collections::BTreeMap<String, String>> {
    let text = stdout(out);
    let mut all = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let body = line
            .strip_prefix('{')
            .and_then(|l| l.strip_suffix('}'))
            .unwrap_or_else(|| panic!("not a JSON object: {line}"));
        let mut fields = std::collections::BTreeMap::new();
        let (mut rest, mut key) = (body, String::new());
        while !rest.is_empty() {
            let after_quote = rest
                .strip_prefix('"')
                .unwrap_or_else(|| panic!("field does not start with a quote: {rest} in {line}"));
            let end = after_quote
                .find('"')
                .unwrap_or_else(|| panic!("unterminated key in {line}"));
            key.clear();
            key.push_str(&after_quote[..end]);
            rest = after_quote[end + 1..]
                .strip_prefix(':')
                .unwrap_or_else(|| panic!("no colon after {key} in {line}"));
            let value = if let Some(r) = rest.strip_prefix('"') {
                // a quoted value ends at the first unescaped quote; the escapes are the
                // writer's own, and a reader that stopped at the first backslash-quote
                // would read half a message and call it a field
                let mut out = String::new();
                let mut chars = r.char_indices();
                let end = loop {
                    let Some((i, c)) = chars.next() else {
                        panic!("unterminated value in {line}")
                    };
                    match c {
                        '"' => break i,
                        '\\' => match chars.next() {
                            Some((_, 'n')) => out.push('\n'),
                            Some((_, 't')) => out.push('\t'),
                            Some((_, 'r')) => out.push('\r'),
                            Some((_, c)) => out.push(c),
                            None => panic!("value ends in a backslash in {line}"),
                        },
                        c => out.push(c),
                    }
                };
                rest = &r[end + 1..];
                out
            } else if let Some(r) = rest.strip_prefix('[') {
                // An array of strings, which `done.skipped` is. This reader took only
                // scalars, so the first array field made a LEGAL JSON line fail the
                // machine-readability arm -- the checker was the narrow thing, not the
                // output. Kept deliberately simple: these arrays hold quoted strings and
                // commas, no nesting, and anything else should fail here rather than be
                // waved through.
                let Some(end) = r.find(']') else {
                    panic!("unterminated array in {line}")
                };
                let inner = &r[..end];
                assert!(
                    !inner.contains('['),
                    "a nested array is beyond this reader: {line}"
                );
                for item in inner.split(',').filter(|s| !s.trim().is_empty()) {
                    let t = item.trim();
                    assert!(
                        t.starts_with('"') && t.ends_with('"') && t.len() >= 2,
                        "array item {t:?} in field {key} is not a quoted string in {line}"
                    );
                }
                rest = &r[end + 1..];
                format!("[{inner}]")
            } else {
                let end = rest.find(',').unwrap_or(rest.len());
                let v = rest[..end].to_string();
                assert!(
                    v == "true" || v == "false" || v.parse::<f64>().is_ok(),
                    "field {key} is neither a string, a number nor a boolean: {v:?} in {line}"
                );
                rest = &rest[end..];
                v
            };
            fields.insert(key.clone(), value);
            rest = rest.strip_prefix(',').unwrap_or(rest);
        }
        all.push(fields);
    }
    all
}

fn of<'a>(e: &'a std::collections::BTreeMap<String, String>, key: &str) -> &'a str {
    e.get(key)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("no {key} in {e:?}"))
}

#[test]
fn json_events_carry_the_run_and_stdout_stays_machine_readable() {
    let s = Scratch::new("json");
    let src = fixture(&s);
    symlink("message.txt", src.join("link")).unwrap();
    let cat = s.path("catalog");
    let dst = s.path("dst");

    // a copy: an event per entry, then one done carrying the same numbers the text run
    // prints, and nothing on stdout that is not an event
    let out = rcp(
        &cat,
        &[
            "copy",
            "-json",
            "-newid",
            "j",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stdout(&out));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains("STATUS: PASSED") && text.contains("copy: "),
        "the human lines belong on stderr:\n{text}"
    );
    assert!(
        !stdout(&out).contains("STATUS"),
        "stdout must carry events only:\n{}",
        stdout(&out)
    );
    let ev = events(&out);
    let done = ev.last().expect("a done event");
    assert_eq!(of(done, "event"), "done");
    assert_eq!(
        (of(done, "status"), of(done, "command")),
        ("passed", "copy")
    );
    let entries: Vec<_> = ev.iter().filter(|e| of(e, "event") == "entry").collect();
    assert_eq!(
        entries
            .iter()
            .filter(|e| of(e, "kind") == "f")
            .count()
            .to_string(),
        of(done, "files")
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| of(e, "kind") == "l")
            .count()
            .to_string(),
        of(done, "symlinks")
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| of(e, "kind") == "d")
            .count()
            .to_string(),
        of(done, "directories")
    );
    // every file carries the digest the run computed, and it is the file's
    let one = entries
        .iter()
        .find(|e| of(e, "path") == "message.txt")
        .expect("message.txt");
    assert_eq!(of(one, "digest"), sha256_of(&src.join("message.txt")));
    // the same run without -json reports the same numbers in its text summary
    let plain = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            s.path("dst2").to_str().unwrap(),
        ],
    ));
    assert!(
        plain.contains(&format!(
            "copy: {} files ({} bytes)",
            of(done, "files"),
            of(done, "bytes")
        )),
        "text summary disagrees with the events:\n{plain}\n{done:?}"
    );

    // verify: one event per difference, and a done that says failed
    write(&dst.join("message.txt"), b"changed", 0o644);
    let out = rcp(
        &cat,
        &[
            "verify",
            "-json",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let ev = events(&out);
    assert!(
        ev.iter().any(|e| of(e, "event") == "difference"
            && of(e, "kind") == "size"
            && of(e, "path") == "message.txt"),
        "{ev:?}"
    );
    assert_eq!(of(ev.last().unwrap(), "status"), "failed");

    // an endpoint that is not there: an error event with the kind's own code, not "usage"
    let out = rcp(&cat, &["scan", "-json", &s.s("nothing-here")]);
    assert_eq!(out.status.code(), Some(1));
    let ev = events(&out);
    let err = ev
        .iter()
        .find(|e| of(e, "event") == "error")
        .expect("an error event");
    assert_eq!(of(err, "code"), "notfound", "{ev:?}");
    assert_eq!(of(ev.last().unwrap(), "status"), "failed");
    // a mistyped option is a usage failure, which is a different code
    let out = rcp(
        &cat,
        &["scan", "-json", "-parallel", "green", src.to_str().unwrap()],
    );
    assert_eq!(
        of(
            events(&out)
                .iter()
                .find(|e| of(e, "event") == "error")
                .expect("an error"),
            "code"
        ),
        "usage"
    );

    // scan emits entries only when a listing was asked for
    let out = rcp(&cat, &["scan", "-json", src.to_str().unwrap()]);
    let ev = events(&out);
    assert!(
        ev.iter().all(|e| of(e, "event") == "done"),
        "a bare scan is the summary alone: {ev:?}"
    );
    let out = rcp(&cat, &["scan", "-json", "-l", src.to_str().unwrap()]);
    let ev = events(&out);
    assert_eq!(
        ev.iter()
            .filter(|e| of(e, "event") == "entry")
            .count()
            .to_string(),
        format!(
            "{}",
            ev.iter().filter(|e| of(e, "event") == "entry").count()
        )
    );
    assert!(
        ev.iter().filter(|e| of(e, "event") == "entry").count() > 3,
        "{ev:?}"
    );

    // the control: without -json stdout is the human report and parses as no event at all
    let out = rcp(&cat, &["scan", src.to_str().unwrap()]);
    assert!(
        !stdout(&out).contains("\"event\""),
        "a run without -json emits no events:\n{}",
        stdout(&out)
    );
}

/// **The rail sees every file a copy would replace, not only the ones inside the filter.**
/// The destination was listed through the whole filter, so an existing `a.txt` smaller than
/// `-minsize` was missing from the plan's view of it, the source `a.txt` (which passes) was
/// planned as new, and `-requireconfirm` let the overwrite through unconfirmed.
#[test]
fn the_confirm_rail_sees_an_overwrite_the_filter_would_hide() {
    let s = Scratch::new("rail-filter");
    let (src, dst) = (s.path("src"), s.path("dst"));
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("a.txt"), &[b'x'; 4096], 0o644);
    write(&dst.join("a.txt"), b"small, and somebody's\n", 0o644);
    let cat = s.path("catalog");
    let (src, dst_s) = (src.to_str().unwrap(), dst.to_str().unwrap());
    let dry = assert_passed(&rcp(
        &cat,
        &["copy", "-noId", "-dryrun", "-minsize", "1k", src, dst_s],
    ));
    assert!(
        dry.contains("* a.txt"),
        "the plan showed the overwrite of a file outside the filter as a new file:\n{dry}"
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-requireconfirm",
                "-minsize",
                "1k",
                src,
                dst_s,
            ],
        ),
        "would overwrite",
    );
    assert_eq!(
        fs::read(dst.join("a.txt")).unwrap(),
        b"small, and somebody's\n",
        "the refused run overwrote it anyway"
    );
    // the control: confirmed with the digest the dry run printed, it proceeds
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-requireconfirm",
            "-minsize",
            "1k",
            "-confirm",
            &plan_of(&dry),
            src,
            dst_s,
        ],
    ));
    assert_eq!(fs::read(dst.join("a.txt")).unwrap().len(), 4096);
}

/// **A destination the listing could not fully read is said so, and the rail counts it.** A
/// destination directory whose listing failed read as an empty one: the error was dropped, a
/// mirror reported success over a tree it had not seen, and a copy that would overwrite files
/// inside that directory was not "destructive" to `-requireconfirm`.
#[test]
fn a_destination_the_listing_could_not_read_is_reported_and_railed() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dst-unseen");
    let src = s.path("src");
    fs::create_dir_all(src.join("hidden")).unwrap();
    write(&src.join("hidden/f.txt"), b"new\n", 0o644);
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in/hidden")).unwrap();
    write(
        &root.join("in/hidden/f.txt"),
        b"old, and somebody's\n",
        0o644,
    );
    let cat = s.path("catalog");
    let server = Server::start_with(
        &root,
        Quirks {
            fail_propfind_under: Some("/hidden"),
            ..Quirks::default()
        },
    )
    .unwrap();
    let (src_s, dst) = (src.to_str().unwrap(), server.url("/in"));

    let dry = stdout(&rcp_dav(&cat, &["copy", "-noId", "-dryrun", src_s, &dst]));
    assert!(
        dry.lines().any(|l| l.starts_with("? ")),
        "the plan did not say part of the destination was unseen:\n{dry}"
    );
    assert_failed(
        &rcp_dav(&cat, &["copy", "-noId", "-requireconfirm", src_s, &dst]),
        "would overwrite",
    );
    assert_eq!(
        fs::read(root.join("in/hidden/f.txt")).unwrap(),
        b"old, and somebody's\n",
        "the refused run overwrote it anyway"
    );
    // a mirror over it is not a success: it has not seen the whole destination
    assert_failed(&rcp_dav(&cat, &["isync", src_s, &dst]), "hidden");

    // the control: the same destination, readable, passes -- so the unreadable part is what failed
    let honest = Server::start(&root).unwrap();
    assert_passed(&rcp_dav(&cat, &["isync", src_s, &honest.url("/in")]));
    // and a destination that is not there yet is empty, not unreadable -- in a dry run too,
    // which opens it without creating it rather than failing at open
    let dry = assert_passed(&rcp_dav(
        &cat,
        &["isync", "-dryrun", src_s, &honest.url("/new")],
    ));
    assert!(
        dry.contains("+ hidden/f.txt") && !root.join("new").exists(),
        "{dry}"
    );
    assert_passed(&rcp_dav(
        &cat,
        &["isync", "-requireconfirm", src_s, &honest.url("/new")],
    ));
    assert_failed(
        &rcp_dav(&cat, &["scan", &honest.url("/nowhere")]),
        "no such",
    );
}

/// The `plan:` line a dry run (or a counting delete) prints.
fn plan_of(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("plan: "))
        .unwrap_or_else(|| panic!("no plan digest in\n{text}"))
        .to_string()
}

#[test]
fn the_rails_bound_a_run_that_a_program_drives() {
    let s = Scratch::new("rails");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"one\n", 0o644);
    write(&src.join("b.txt"), b"two\n", 0o644);
    let cat = s.path("catalog");
    let dst = s.path("dst");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));

    // -confirm: a dry run names the plan, and only that name lets the run proceed
    let dry = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-dryrun",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert!(
        dry.contains("* a.txt") && dry.contains("* b.txt"),
        "a fresh copy over an existing tree overwrites, and the plan must say so:\n{dry}"
    );
    let digest = plan_of(&dry);
    // armed and unconfirmed: refused, and the refusal does not hand over the digest
    let refused = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-requireconfirm",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "would overwrite",
    );
    assert!(
        !refused.contains(&digest),
        "the refusal must not carry the digest, or the plan need never be read:\n{refused}"
    );
    // the wrong digest is refused too, so the check is not "any -confirm will do"
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-requireconfirm",
                "-confirm",
                "0000000000000000",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "would overwrite",
    );
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-requireconfirm",
            "-confirm",
            &digest,
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    // a tree that changed since the plan was read invalidates the digest
    write(&src.join("c.txt"), b"three\n", 0o644);
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-requireconfirm",
                "-confirm",
                &digest,
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ),
        "would overwrite",
    );
    // the control: unarmed, the same run proceeds, so the rail is what refused above
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));

    // delete: the counting run names the plan, the removing run needs it
    let counted = assert_passed(&rcp(&cat, &["delete", dst.to_str().unwrap()]));
    let digest = plan_of(&counted);
    assert_failed(
        &rcp(
            &cat,
            &["delete", "-force", "-requireconfirm", dst.to_str().unwrap()],
        ),
        "would remove entries",
    );
    assert!(
        dst.join("a.txt").exists(),
        "a refused delete removes nothing"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "delete",
            "-force",
            "-requireconfirm",
            "-confirm",
            &digest,
            dst.to_str().unwrap(),
        ],
    ));
    assert!(!dst.join("a.txt").exists());

    // -readonly refuses every command that writes and allows every command that does not
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-readonly",
                src.to_str().unwrap(),
                s.path("dst2").to_str().unwrap(),
            ],
        ),
        "read-only",
    );
    assert!(!s.path("dst2").exists(), "a read-only run creates nothing");
    assert_failed(
        &rcp(
            &cat,
            &["delete", "-force", "-readonly", src.to_str().unwrap()],
        ),
        "read-only",
    );
    assert_passed(&rcp(&cat, &["scan", "-readonly", src.to_str().unwrap()]));
    // Three commands write because of an ARGUMENT rather than because of their name, and
    // `describe::COMMANDS` says `writes: false` for all three -- true of the bare command
    // and false of the form with the argument. Each was measured under `-readonly` without
    // the guard: `estimate -target` reported PASSED having copied a live sample into the
    // target and removed it again, and `scan -newid` reported PASSED with the catalog
    // created.
    let target = s.path("estimate-target");
    fs::create_dir_all(&target).unwrap();
    assert_failed(
        &rcp(
            &cat,
            &[
                "estimate",
                "-readonly",
                "-target",
                target.to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "read-only",
    );
    assert_eq!(
        fs::read_dir(&target).unwrap().count(),
        0,
        "a read-only estimate wrote into the target"
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-readonly",
                "-newid",
                "ro-scan",
                src.to_str().unwrap(),
            ],
        ),
        "read-only",
    );
    assert!(
        !cat.join("ro-scan").exists(),
        "a read-only scan created a catalog"
    );
    // and the control on all three, which is what stops this being a guard that refuses
    // the command outright: the bare form still reads, and the argument form still works
    // when the run is not read-only
    assert_passed(&rcp(&cat, &["scan", "-readonly", src.to_str().unwrap()]));
    assert_passed(&rcp(&cat, &["estimate", src.to_str().unwrap()]));
    assert_passed(&rcp(
        &cat,
        &["scan", "-newid", "rw-scan", src.to_str().unwrap()],
    ));
    assert!(cat.join("rw-scan").exists());

    // which commands write is describe's own table, so the two cannot disagree
    for c in rcp::describe::COMMANDS.iter().filter(|c| c.writes) {
        let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args(["-catalog", cat.to_str().unwrap(), c.name, "-readonly"])
            .output()
            .expect("rcp runs");
        assert!(
            stdout(&out).contains("read-only"),
            "{} writes but -readonly let it start:\n{}",
            c.name,
            stdout(&out)
        );
    }

    // -allow: a path outside the roots is refused, and the boundary is a path boundary
    let pad = s.path("srcpad");
    fs::create_dir_all(&pad).unwrap();
    write(&pad.join("p.txt"), b"pad\n", 0o644);
    assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
        ],
    ));
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                src.to_str().unwrap(),
                pad.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-allow",
                src.to_str().unwrap(),
                src.to_str().unwrap(),
                s.path("elsewhere").to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert!(!s.path("elsewhere").exists());
    // the environment arms it too, and a scheme root never admits a local path
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_ALLOWED_ROOTS", src.to_str().unwrap())
        .args([
            "-catalog",
            cat.to_str().unwrap(),
            "scan",
            pad.to_str().unwrap(),
        ])
        .output()
        .expect("rcp runs");
    assert_failed(&out, "outside the roots");
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_ALLOWED_ROOTS", "oci://registry.example")
        .args([
            "-catalog",
            cat.to_str().unwrap(),
            "scan",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("rcp runs");
    assert_failed(&out, "outside the roots");

    // and the property that matters most: a refused endpoint costs no connection. The
    // stand-in transport writes a line per invocation, and must write none.
    let (stub, log) = serve_stub(&s);
    let remote = format!("ssh://filer{}/x", s.path("remote").display());
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env("RCP_ALLOWED_ROOTS", src.to_str().unwrap())
        .args(["-catalog", cat.to_str().unwrap(), "scan", &remote])
        .output()
        .expect("rcp runs");
    assert_failed(&out, "outside the roots");
    assert!(
        !log.exists() || fs::read_to_string(&log).unwrap().is_empty(),
        "the transport was started for an endpoint the rails refuse:\n{}",
        fs::read_to_string(&log).unwrap_or_default()
    );
    // the control: with that root allowed, the same endpoint does start the transport
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env(
            "RCP_ALLOWED_ROOTS",
            format!("ssh://filer{}", s.path("remote").display()),
        )
        .args(["-catalog", cat.to_str().unwrap(), "scan", &remote])
        .output()
        .expect("rcp runs");
    let _ = out;
    assert!(
        log.exists() && !fs::read_to_string(&log).unwrap().is_empty(),
        "the allowed endpoint must reach the transport, else the check above proves nothing"
    );

    // A rail on the spelling of a path is not a rail on the path. Both of these copied
    // the secret before the endpoint was resolved the way the kernel resolves it.
    let secret = s.path("secret");
    fs::create_dir_all(&secret).unwrap();
    write(&secret.join("s.txt"), b"classified\n", 0o600);
    let out = s.path("out");
    let inside = format!(
        "{}/..{}",
        src.display(),
        secret
            .strip_prefix(s.path(""))
            .map(|r| format!("/{}", r.display()))
            .unwrap_or_default()
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-allow",
                src.to_str().unwrap(),
                "-allow",
                out.to_str().unwrap(),
                &inside,
                out.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    symlink(&secret, src.join("link")).unwrap();
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-allow",
                src.to_str().unwrap(),
                "-allow",
                out.to_str().unwrap(),
                src.join("link").to_str().unwrap(),
                out.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert!(
        !out.join("s.txt").exists(),
        "the secret escaped a rail that was supposed to hold it"
    );
    // the control: the same roots still admit the tree itself, symlink and all, and a copy
    // recreates that link rather than following it
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-allow",
            src.to_str().unwrap(),
            "-allow",
            out.to_str().unwrap(),
            src.to_str().unwrap(),
            out.to_str().unwrap(),
        ],
    ));
    assert!(text.contains("1 symlinks"), "{text}");
    // the link is recreated, not followed: what landed is a symlink, and no file was read
    // through it (it still resolves, because a faithful copy keeps the target it had)
    assert!(out
        .join("link")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!text.contains("s.txt"));

    // A path that does not exist yet is where a resolver can fail OPEN: one that gives up
    // when `canonicalize` does is wrong, because `canonicalize` fails for a DANGLING symlink
    // as well as for a missing path. `-allow ROOT` then admits `ROOT/out` with `out` a link
    // to anywhere, and a create follows a link.
    let away = s.path("away");
    fs::create_dir_all(&away).unwrap();
    symlink(away.join("gone"), src.join("dangling")).unwrap();
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-allow",
                src.to_str().unwrap(),
                "-allow",
                out.to_str().unwrap(),
                src.to_str().unwrap(),
                src.join("dangling/under").to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert!(
        !away.join("gone").exists(),
        "the copy followed a dangling link out of the roots"
    );
    // a path that does not exist and is not a link is still admitted under its root, or a
    // fresh destination could never be written
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-allow",
            src.to_str().unwrap(),
            "-allow",
            out.to_str().unwrap(),
            src.to_str().unwrap(),
            out.join("new/deeper").to_str().unwrap(),
        ],
    ));

    // `/` is a root that admits every local path -- and it used to admit nothing, because
    // trimming the trailing slash left an empty string that was then dropped, leaving a
    // run with no roots at all, which is a rail that is not there
    assert_passed(&rcp(&cat, &["scan", "-allow", "/", src.to_str().unwrap()]));
    assert_failed(
        &rcp(&cat, &["scan", "-allow", "/", "s3://bucket/x"]),
        "outside the roots",
    );

    // a remote path cannot be resolved from here, so one that climbs is refused rather
    // than compared as text
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                "nfs://filer/export",
                "nfs://filer/export/../secret",
            ],
        ),
        "cannot be checked",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                "oci://reg/repo",
                "oci://reg/repo/../other",
            ],
        ),
        "cannot be checked",
    );
    // the schemes that refuse a climbing path when they parse it still do
    assert_failed(
        &rcp(&cat, &["scan", "sftp://filer/export/../secret"]),
        "not a plain path",
    );
    assert_failed(
        &rcp(&cat, &["scan", "s3://bucket/p/../q"]),
        "not a plain path",
    );

    // an option whose value names a program to run is refused on a railed run, whichever
    // rail it is, because no rail can bound what that program does
    for rail in [
        vec!["-allow", src.to_str().unwrap()],
        vec!["-readonly"],
        vec!["-requireconfirm"],
    ] {
        let mut a = vec!["scan"];
        a.extend(rail.iter().copied());
        a.extend_from_slice(&["-copybatch", "touch /dev/null", src.to_str().unwrap()]);
        assert_failed(&rcp(&cat, &a), "no rail can bound");
    }
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                src.to_str().unwrap(),
                "-nodes",
                "elsewhere",
                src.to_str().unwrap(),
            ],
        ),
        "no rail can bound",
    );
    // the control: unrailed, the same option is the documented feature it always was
    assert_passed(&rcp(
        &cat,
        &["scan", "-nodes", "localhost", src.to_str().unwrap()],
    ));

    // `-allow` bounds the TEXT of an endpoint. An option that changes which SERVICE that
    // text is resolved against walks straight through it, and that was measured rather
    // than reasoned: `scan -allow s3://corp/bucket -s3.endpoint http://127.0.0.1:PORT
    // s3://corp/bucket` sent `GET /corp/?list-type=2&prefix=bucket/` to a listener no
    // rail had named. Same shape for -hdfs.namenode, and -s3.profile / -oci.user choose
    // whose credentials go with it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port to stand in for the other service");
    let port = listener.local_addr().unwrap().port();
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    let watcher = std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(s); // a reset is enough; what is measured is that we were dialed
                }
                Err(_) => break,
            }
        }
    });
    let elsewhere = format!("http://127.0.0.1:{port}");
    for rail in [
        vec!["-allow", "s3://corp/bucket"],
        vec!["-readonly"],
        vec!["-requireconfirm"],
    ] {
        let mut a = vec!["scan"];
        a.extend(rail.iter().copied());
        a.extend_from_slice(&["-s3.endpoint", &elsewhere, "s3://corp/bucket"]);
        assert_failed(&rcp(&cat, &a), "no rail can bound");
    }
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                "s3://corp/bucket",
                "-s3.profile",
                "other",
                "s3://corp/bucket",
            ],
        ),
        "no rail can bound",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                "oci://reg/repo",
                "-oci.user",
                "someone:secret",
                "oci://reg/repo",
            ],
        ),
        "no rail can bound",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "scan",
                "-allow",
                "hdfs:///d",
                "-hdfs.namenode",
                "127.0.0.1:1",
                "hdfs:///d",
            ],
        ),
        "no rail can bound",
    );
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "a railed run reached the service the rails never named"
    );
    // And the limit of that, pinned rather than left to the prose: the rails bound the
    // COMMAND LINE and not the environment a run inherits. It is easy to overstate that
    // claim -- `RCP_S3_ENDPOINT` redirects the same traffic, and so do AWS's own
    // variables, which rcp reads because AWS's own tools do. The
    // split is deliberate (a caller writes the call, a server owns the environment) and
    // it is a documented boundary, so it gets an arm: this run IS redirected, and a
    // change that started refusing it would be a change to what the rails claim.
    let before = reached.load(Ordering::SeqCst);
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_S3_ENDPOINT", &elsewhere)
        .args([
            "-catalog",
            cat.to_str().unwrap(),
            "scan",
            "-allow",
            "s3://corp/bucket",
            "s3://corp/bucket",
        ])
        .output()
        .expect("rcp runs");
    let _ = out;
    assert!(
        reached.load(Ordering::SeqCst) > before,
        "the environment is documented as reaching the service, and this run did not"
    );
    // the control: the identical command without a rail DOES dial it, so the assertion
    // above is about the refusal and not about an endpoint that never connects anyway
    let _ = rcp(
        &cat,
        &["scan", "-s3.endpoint", &elsewhere, "s3://corp/bucket"],
    );
    assert!(
        reached.load(Ordering::SeqCst) > 0,
        "the unrailed run must reach the stand-in, else the count above proves nothing"
    );
    // A command line MAY turn TLS off; a call into somebody else's rails may not. The
    // four switches were `Setting`, which is the class a call is allowed to set, so an
    // MCP caller answering a railed server could send `options: ["-oci.noverify"]` and
    // stop certificate verification for a host the operator named. They are `Transport`
    // now: `why_not` refuses them from a call, `why_not_railed` does not refuse them from
    // a command line, because `-allow` bounds WHERE a run goes and these bound how well
    // the connection to there is authenticated -- a different question, and the
    // operator's to answer. The call side is measured in the MCP arm; this is the half
    // that must keep WORKING, and without it a stricter classification would look right
    // here while breaking every operator who writes `-oci.insecure` beside a rail.
    for sw in [
        "-oci.insecure",
        "-oci.noverify",
        "-s3.insecure",
        "-s3.noverify",
    ] {
        assert_passed(&rcp(
            &cat,
            &[
                "scan",
                "-allow",
                src.to_str().unwrap(),
                "-readonly",
                sw,
                src.to_str().unwrap(),
            ],
        ));
    }

    // and the two capabilities a command line DOES own stay owned: -allow is the
    // operator's, and a second path is put through -allow like any endpoint
    assert_passed(&rcp(
        &cat,
        &[
            "scan",
            "-allow",
            src.to_str().unwrap(),
            "-readonly",
            src.to_str().unwrap(),
        ],
    ));
    assert_failed(
        &rcp(
            &cat,
            &[
                "chmod",
                "-allow",
                src.to_str().unwrap(),
                "-reference",
                pad.join("p.txt").to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    // `-match *.txt`, so the reference's 0644 lands on files only. Applied to the whole
    // tree it also sets `src` itself to 0644, and a directory without its search bit
    // cannot be entered by anyone but root: the release workflow's first non-root run
    // failed every file under it with "Permission denied", and every later step here
    // writes into `src`. Root ignores the missing bit, which is why this passed locally.
    assert_passed(&rcp(
        &cat,
        &[
            "chmod",
            "-allow",
            src.to_str().unwrap(),
            "-match",
            "*.txt",
            "-reference",
            src.join("b.txt").to_str().unwrap(),
            src.to_str().unwrap(),
        ],
    ));

    // `-umap` and `-gmap` name a file too, so they are not plain settings. Classified as
    // one, `diag change` opened them with a bare `read_to_string`, with no rail in the way,
    // and the parse error QUOTED THE OFFENDING LINE. So a railed `-umap /etc/shadow`
    // printed a password hash in its own error message -- an unbounded one-line read of
    // any file on the host, dressed as a parse failure.
    let shadowish = pad.join("shadowish");
    write(
        &shadowish,
        b"root:$6$NOTAREALHASH:20000:0:99999:7:::\n",
        0o600,
    );
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "diag",
                "change",
                "-umap",
                shadowish.to_str().unwrap(),
                "-allow",
                src.to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert!(
        !out.contains("NOTAREALHASH"),
        "the rail refused the file and printed it anyway:\n{out}"
    );
    // and the second half, which holds with no rails at all: a malformed map the run IS
    // allowed to read still must not have its bytes echoed into an error
    write(
        &src.join("bad.csv"),
        b"root:$6$NOTAREALHASH:20000:0:99999:7:::\n",
        0o600,
    );
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "diag",
                "change",
                "-umap",
                src.join("bad.csv").to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "not from,to",
    );
    assert!(
        !out.contains("NOTAREALHASH"),
        "a parse error carried the file's contents:\n{out}"
    );
    // the control: a map inside the roots is read and used, so the refusal is the rail
    // A valid map must be usable without root: changing an ordinary user's ownership
    // would test chown privileges instead of whether the rail admits this map.
    let uid = fs::metadata(&src).unwrap().uid();
    let mapped_uid = if uid == 0 { 2000 } else { uid };
    write(
        &src.join("ok.csv"),
        format!("{uid},{mapped_uid}\n").as_bytes(),
        0o644,
    );
    assert_passed(&rcp(
        &cat,
        &[
            "diag",
            "change",
            "-umap",
            src.join("ok.csv").to_str().unwrap(),
            "-allow",
            src.to_str().unwrap(),
            src.to_str().unwrap(),
        ],
    ));

    // The READ side of the symlink rule. The write side is closed with `O_NOFOLLOW`;
    // `diag -cat` opens the PARENT through the rails and then reads a name inside it, so a
    // link at the last component moved the read anywhere. Measured: `diag -cat ROOT/link
    // -allow ROOT` printed `/etc/hostname`. The whole path goes through `allowed` now, which
    // resolves the final component the way the kernel does. `-reference` had the same shape.
    write(&pad.join("secret.txt"), b"classified\n", 0o600);
    symlink(pad.join("secret.txt"), src.join("peek")).unwrap();
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "diag",
                "-cat",
                src.join("peek").to_str().unwrap(),
                "-allow",
                src.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    assert!(
        !out.contains("classified"),
        "the rail refused and read it anyway:\n{out}"
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "chmod",
                "-allow",
                src.to_str().unwrap(),
                "-reference",
                src.join("peek").to_str().unwrap(),
                src.to_str().unwrap(),
            ],
        ),
        "outside the roots",
    );
    // the control: a real file at the same place is read, so the refusal is the link.
    // `diag -cat` prints no STATUS line on purpose -- the bytes are the output -- so this
    // reads the bytes rather than using `assert_passed`.
    write(&src.join("plain.txt"), b"ordinary\n", 0o644);
    let out = rcp(
        &cat,
        &[
            "diag",
            "-cat",
            src.join("plain.txt").to_str().unwrap(),
            "-allow",
            src.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ordinary"),
        "{}",
        stdout(&out)
    );
    drop(watcher); // the listener dies with the test's process
}

/// Drives `rcp mcp` over pipes: one request per line in, one reply per line out. Returns
/// the replies as text, in order.
fn mcp(server_args: &[&str], requests: &[String]) -> Vec<String> {
    let mut argv = vec!["mcp"];
    argv.extend_from_slice(server_args);
    mcp_argv(&argv, requests)
}

/// The same, but the caller writes the WHOLE argument list including where `mcp` sits.
/// Every arm above passes the server's options after the command word, and the parser
/// accepts them before it too -- which is a second, untested command line, and it was
/// the one where `-allow` went missing entirely.
fn mcp_argv(argv: &[&str], requests: &[String]) -> Vec<String> {
    use std::io::Write;
    // The arms make claims about which scheme a call tries, and a CA bundle named by the
    // environment is read before any connection is made; one the test user cannot read
    // turns "tries https" into a permission error. The server's calls use rcp's own trust
    // resolution, not whatever the invoking shell exported.
    let mut child = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env_remove("AWS_CA_BUNDLE")
        .env_remove("SSL_CERT_FILE")
        .env_remove("RCP_CA_BUNDLE")
        .args(argv)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("rcp mcp starts");
    let mut input = child.stdin.take().unwrap();
    for r in requests {
        writeln!(input, "{r}").unwrap();
    }
    drop(input); // the server serves until the input ends
    let out = child.wait_with_output().expect("rcp mcp ends");
    assert!(
        out.status.success(),
        "rcp mcp exited {:?}",
        out.status.code()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The `text` of a tool result, and whether the call reported failure.
fn result_text(reply: &str) -> (String, bool) {
    let at = reply
        .find("\"text\": \"")
        .unwrap_or_else(|| panic!("no text in {reply}"));
    let rest = &reply[at + 9..];
    let mut text = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next().expect("unterminated text") {
            '"' => break,
            '\\' => match chars.next().expect("value ends in a backslash") {
                'n' => text.push('\n'),
                't' => text.push('\t'),
                'r' => text.push('\r'),
                'u' => {
                    let hex: String = (0..4)
                        .map(|_| chars.next().expect("short escape"))
                        .collect();
                    text.push(
                        char::from_u32(u32::from_str_radix(&hex, 16).expect("hex"))
                            .expect("a character"),
                    );
                }
                c => text.push(c),
            },
            c => text.push(c),
        }
    }
    (text, reply.contains("\"isError\": true"))
}

fn call(id: u32, tool: &str, args: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{args}}}}}")
}

#[test]
fn the_mcp_server_speaks_the_protocol_and_keeps_the_rails() {
    let s = Scratch::new("mcp");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"one\n", 0o644);
    write(&src.join("b.txt"), b"two\n", 0o644);
    let dst = s.s("dst");

    // the handshake, the tool list, and a notification that takes no reply
    let replies = mcp(
        &[],
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.to_string(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":"three","method":"ping"}"#.to_string(),
        ],
    );
    assert_eq!(
        replies.len(),
        3,
        "a notification must take no reply:\n{replies:#?}"
    );
    assert!(
        replies[0].contains("\"protocolVersion\"") && replies[0].contains("\"serverInfo\""),
        "{}",
        replies[0]
    );
    assert!(
        replies[0].contains("\"id\": 1"),
        "a number id goes back a number: {}",
        replies[0]
    );
    assert!(
        replies[2].contains("\"id\": \"three\""),
        "a string id goes back a string: {}",
        replies[2]
    );
    for name in rcp::mcp::tool_names() {
        assert!(
            replies[1].contains(&format!("\"name\": \"{name}\"")),
            "tools/list omits {name}"
        );
    }
    // every tool's schema is a JSON object with its own properties
    assert!(replies[1].matches("\"inputSchema\"").count() == rcp::mcp::tool_names().len());

    // a copy into empty space just runs; nothing to overwrite, nothing to confirm
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_copy",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{dst}\"}}",
                src.display()
            ),
        )],
    );
    let (text, failed) = result_text(&replies[0]);
    assert!(
        !failed,
        "a copy into empty space must not need a plan: {text}"
    );
    assert!(
        text.contains("\"status\":\"passed\"") && text.contains("\"files\":2"),
        "{text}"
    );
    assert_eq!(fs::read(s.path("dst/a.txt")).unwrap(), b"one\n");

    // the same copy again would overwrite, so it is refused, and the refusal names the
    // tool to call rather than a command-line option
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_copy",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{dst}\"}}",
                src.display()
            ),
        )],
    );
    let (text, failed) = result_text(&replies[0]);
    assert!(failed && text.contains("rcp_plan"), "{text}");

    // plan, then confirm with what it returned
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_plan",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{dst}\"}}",
                src.display()
            ),
        )],
    );
    let (text, failed) = result_text(&replies[0]);
    assert!(!failed, "{text}");
    let digest = text
        .lines()
        .find_map(|l| {
            l.split("\"plan\":\"")
                .nth(1)
                .map(|r| r.split('"').next().unwrap().to_string())
        })
        .expect("a plan digest");
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_copy",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{dst}\",\"confirm\":\"{digest}\"}}",
                src.display()
            ),
        )],
    );
    let (text, failed) = result_text(&replies[0]);
    assert!(
        !failed,
        "the digest the plan returned must be accepted: {text}"
    );
    // the control: a digest that is not that one is refused
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_copy",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{dst}\",\"confirm\":\"0000000000000000\"}}",
                src.display()
            ),
        )],
    );
    assert!(result_text(&replies[0]).1, "a wrong digest must be refused");

    // delete needs the digest rcp_count returns
    let replies = mcp(
        &[],
        &[call(1, "rcp_delete", &format!("{{\"target\":\"{dst}\"}}"))],
    );
    let (text, failed) = result_text(&replies[0]);
    assert!(failed && text.contains("rcp_count"), "{text}");
    assert!(
        s.path("dst/a.txt").exists(),
        "a refused delete removes nothing"
    );
    let replies = mcp(
        &[],
        &[call(1, "rcp_count", &format!("{{\"target\":\"{dst}\"}}"))],
    );
    let (text, _) = result_text(&replies[0]);
    let digest = text
        .split("\"plan\":\"")
        .nth(1)
        .map(|r| r.split('"').next().unwrap().to_string())
        .expect("a plan digest");
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_delete",
            &format!("{{\"target\":\"{dst}\",\"confirm\":\"{digest}\"}}"),
        )],
    );
    assert!(
        !result_text(&replies[0]).1,
        "{}",
        result_text(&replies[0]).0
    );
    assert!(!s.path("dst/a.txt").exists());

    // the server's own rails reach every call: started on one root, it cannot leave it
    let replies = mcp(
        &["-allow", src.to_str().unwrap()],
        &[
            call(
                1,
                "rcp_scan",
                &format!("{{\"source\":\"{}\"}}", src.display()),
            ),
            call(
                2,
                "rcp_scan",
                &format!("{{\"source\":\"{}\"}}", s.s("elsewhere")),
            ),
        ],
    );
    assert!(
        !result_text(&replies[0]).1,
        "the allowed root must work: {}",
        result_text(&replies[0]).0
    );
    assert!(
        result_text(&replies[1]).1 && result_text(&replies[1]).0.contains("outside the roots"),
        "{}",
        result_text(&replies[1]).0
    );
    // and read-only reaches them too: the server starts (it writes nothing itself) and
    // every call it makes is refused, which is the useful shape
    let replies = mcp(
        &["-readonly"],
        &[call(
            1,
            "rcp_copy",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{}\"}}",
                src.display(),
                s.s("ro-dst")
            ),
        )],
    );
    assert!(
        result_text(&replies[0]).1 && result_text(&replies[0]).0.contains("read-only"),
        "{}",
        result_text(&replies[0]).0
    );
    assert!(!s.path("ro-dst").exists());

    // The server's CREDENTIALS and transport configuration reach every call too, and two
    // rules meet there in direct conflict: `rails` always adds `-requireconfirm`, a railed
    // run refuses a credential on its command line, and a relay that puts the server's
    // credential on the command line makes the child of `rcp mcp -oci.user U:P` refuse the
    // server's own credential.
    //
    // The relay's unit test reads `rails()` output and never runs a child, so it cannot see
    // that. This arm runs one, against a registry that demands the credential.
    if Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let layout = s.path("mcp-layout");
        oci_layout(&layout);
        let reg = Registry::start(&[
            "--user",
            "operator:supersecret",
            "--seed",
            "app",
            layout.to_str().unwrap(),
        ]);
        let replies = mcp(
            &["-oci.insecure", "-oci.user", "operator:supersecret"],
            &[call(
                1,
                "rcp_scan",
                &format!("{{\"source\":\"{}\"}}", reg.url("app")),
            )],
        );
        let (text, failed) = result_text(&replies[0]);
        assert!(
            !failed,
            "the server's own credential was refused by its child:\n{text}"
        );
        // the control: the same call with the WRONG credential must be refused by the
        // REGISTRY, not by the rails, or this arm would pass on a server that sends none
        let replies = mcp(
            &["-oci.insecure", "-oci.user", "operator:wrong"],
            &[call(
                1,
                "rcp_scan",
                &format!("{{\"source\":\"{}\"}}", reg.url("app")),
            )],
        );
        let (text, failed) = result_text(&replies[0]);
        assert!(
            failed && text.contains("refused the credentials"),
            "a wrong credential must fail at the registry:\n{text}"
        );
        // and `-oci.insecure` is a plain setting, which was relayed NOWHERE before this:
        // a plain-HTTP registry was unreachable through the server whatever it was
        // started with. Without it the call above could not have reached this stub at all.
        let replies = mcp(
            &["-oci.user", "operator:supersecret"],
            &[call(
                1,
                "rcp_scan",
                &format!("{{\"source\":\"{}\"}}", reg.url("app")),
            )],
        );
        let (text, failed) = result_text(&replies[0]);
        // Case-insensitively, because the two builds say it differently and the arm is
        // about neither spelling. Without the `tls` feature the refusal reads "built
        // without the rustls feature"; with it, rustls speaks TLS at a plain-HTTP stub and
        // reports "TLS to 127.0.0.1: received corrupt message". Both prove the call tried
        // https rather than falling back to cleartext, which is the whole claim.
        //
        // A lowercase-only match passes ONLY in a build with `tls` off, so it measures the
        // absence of a feature; running the suite with `--all-features` shows that.
        assert!(
            failed && text.to_lowercase().contains("tls"),
            "without -oci.insecure the call must try https:\n{text}"
        );
    }

    // options are checked against the parser's tables, so a call cannot invent one or
    // smuggle an endpoint through them
    let replies = mcp(
        &[],
        &[
            call(
                1,
                "rcp_scan",
                &format!("{{\"source\":\"{}\",\"options\":[\"-l\"]}}", src.display()),
            ),
            call(
                2,
                "rcp_scan",
                &format!(
                    "{{\"source\":\"{}\",\"options\":[\"-frobnicate\"]}}",
                    src.display()
                ),
            ),
            call(
                3,
                "rcp_scan",
                &format!(
                    "{{\"source\":\"{}\",\"options\":[\"/etc/shadow\"]}}",
                    src.display()
                ),
            ),
            call(
                4,
                "rcp_scan",
                &format!(
                    "{{\"source\":\"{}\",\"options\":[\"-readonly\"]}}",
                    src.display()
                ),
            ),
        ],
    );
    assert!(
        !result_text(&replies[0]).1 && result_text(&replies[0]).0.contains("\"event\":\"entry\""),
        "-l must list: {}",
        result_text(&replies[0]).0
    );
    assert!(result_text(&replies[1]).1);
    assert!(result_text(&replies[1]).0.contains("rcp_describe"));
    assert!(result_text(&replies[2]).1);
    assert!(result_text(&replies[2])
        .0
        .contains("endpoints go in their own fields"));
    assert!(result_text(&replies[3]).1);
    assert!(result_text(&replies[3]).0.contains("set by the server"));

    // A known name is not a safe option. This call, with two -allow roots in force,
    // created /tmp/rcp-pwn-probe before the value was looked at: -copybatch names a
    // program and the server relayed it. Every option whose value is a capability -- a
    // program, a host, a service, a credential -- is refused whatever it is set to.
    let pwn = s.path("pwned");
    let replies = mcp(
        &["-allow", src.to_str().unwrap(), "-allow", &dst],
        &[
            call(1, "rcp_copy", &format!("{{\"source\":\"{}\",\"destination\":\"{dst}\",\"options\":[\"-copybatch\",\"touch {}\"]}}", src.display(), pwn.display())),
            call(2, "rcp_scan", &format!("{{\"source\":\"{}\",\"options\":[\"-nodes\",\"localhost\"]}}", src.display())),
            call(3, "rcp_scan", &format!("{{\"source\":\"{}\",\"options\":[\"-oci.user\",\"someone:secret\"]}}", src.display())),
            call(4, "rcp_scan", &format!("{{\"source\":\"{}\",\"options\":[\"-s3.endpoint\",\"http://elsewhere.invalid\"]}}", src.display())),
            call(5, "rcp_scan", &format!("{{\"source\":\"{}\",\"options\":[\"-reference\",\"/etc/shadow\"]}}", src.display())),
            // the control: an ordinary setting on the same server still runs
            call(6, "rcp_scan", &format!("{{\"source\":\"{}\",\"options\":[\"-parallel\",\"2\"]}}", src.display())),
        ],
    );
    for i in 0..5 {
        let (text, is_error) = result_text(&replies[i]);
        assert!(
            is_error && text.contains("not from a call"),
            "reply {i} let a capability through: {text}"
        );
    }
    assert!(!pwn.exists(), "the program named by an option ran");
    assert!(
        !result_text(&replies[5]).1,
        "{}",
        result_text(&replies[5]).0
    );

    // Every destructive tool takes the digest of the dry run of its OWN command. Until
    // rcp_isync_plan existed, rcp_isync was told to use rcp_plan, which plans a copy: the
    // two printed different digests (20d6219d81bec157 against 296677cd670b40fc on the
    // same pair of trees), so the call could not be satisfied at all.
    for (name, plan, command, plan_command) in rcp::mcp::plan_pairs() {
        let plan = plan
            .unwrap_or_else(|| panic!("{name} needs a digest and names no tool that prints one"));
        assert!(
            plan_command.contains(&"-dryrun") || plan_command.first() == Some(&"delete"),
            "{plan} does not plan: {plan_command:?}"
        );
        let same: Vec<&str> = plan_command
            .iter()
            .copied()
            .filter(|a| *a != "-dryrun")
            .collect();
        let mine: Vec<&str> = command.iter().copied().filter(|a| *a != "-force").collect();
        assert_eq!(
            same, mine,
            "{name} takes the digest of {plan}, which runs a different command"
        );
    }
    // and end to end: the plan tool's digest is accepted by the tool it belongs to
    let m = s.path("mirror-src");
    let md = s.path("mirror-dst");
    fs::create_dir_all(&m).unwrap();
    fs::create_dir_all(&md).unwrap();
    write(&m.join("keep.txt"), b"keep\n", 0o644);
    write(&md.join("gone.txt"), b"gone\n", 0o644);
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_isync_plan",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{}\"}}",
                m.display(),
                md.display()
            ),
        )],
    );
    let text = result_text(&replies[0]).0;
    let digest: String = text
        .split("\"plan\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or_else(|| panic!("no plan digest in {text}"))
        .to_string();
    let replies = mcp(
        &[],
        &[call(
            1,
            "rcp_isync",
            &format!(
                "{{\"source\":\"{}\",\"destination\":\"{}\",\"confirm\":\"{digest}\"}}",
                m.display(),
                md.display()
            ),
        )],
    );
    assert!(
        !result_text(&replies[0]).1,
        "the plan tool's own digest was refused: {}",
        result_text(&replies[0]).0
    );
    assert!(!md.join("gone.txt").exists());
    assert!(md.join("keep.txt").exists());

    // malformed calls are protocol errors rather than tool failures, which is the
    // difference between "this call makes no sense" and "the tool ran and refused"
    let replies = mcp(
        &[],
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":2,"method":"no/such/method"}"#.to_string(),
            "not json at all".to_string(),
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rcp_verify","arguments":{"source":"/x"}}}"#.to_string(),
        ],
    );
    assert!(
        replies[0].contains("\"error\"") && replies[0].contains("-32602"),
        "{}",
        replies[0]
    );
    assert!(
        replies[1].contains("\"error\"") && replies[1].contains("-32601"),
        "{}",
        replies[1]
    );
    assert!(replies[2].contains("-32700"), "{}", replies[2]);
    assert!(
        result_text(&replies[3]).1 && result_text(&replies[3]).0.contains("needs destination"),
        "{}",
        result_text(&replies[3]).0
    );

    // A rail is a rail wherever the operator wrote it. Every arm above starts the server
    // as `rcp mcp -allow ...`, and the parser equally accepts `rcp -allow ... mcp` --
    // which is the shape a host's config file naturally produces when options come from
    // one list and the subcommand from another. The server was handed
    // `env::args().skip(2)` on the assumption that `mcp` was argv[1], so the second shape
    // passed it `["/safe", "mcp"]`: `-allow` was not dropped by a policy decision, it was
    // never seen. Measured before the fix: this exact call returned `"status":"passed"`
    // over a tree outside the root.
    let outside = s.path("outside");
    fs::create_dir_all(&outside).unwrap();
    write(&outside.join("secret.txt"), b"not yours\n", 0o644);
    let safe = s.path("safe");
    fs::create_dir_all(&safe).unwrap();
    write(&safe.join("mine.txt"), b"mine\n", 0o644);
    let scan_outside = call(
        1,
        "rcp_scan",
        &format!("{{\"source\":\"{}\"}}", outside.display()),
    );
    let scan_safe = call(
        1,
        "rcp_scan",
        &format!("{{\"source\":\"{}\"}}", safe.display()),
    );

    for argv in [
        vec!["mcp", "-allow", safe.to_str().unwrap()], // options after the command
        vec!["-allow", safe.to_str().unwrap(), "mcp"], // and before it
        vec!["-allow", safe.to_str().unwrap(), "-json", "mcp"], // and with another option between
    ] {
        let (text, failed) = result_text(&mcp_argv(&argv, std::slice::from_ref(&scan_outside))[0]);
        assert!(
            failed && text.contains("outside the roots"),
            "the rail did not survive {argv:?}: {text}"
        );
        // and the control on the refusal: the rail must still permit what it names, or
        // an arm that refuses everything would pass this while making the server useless
        let (text, failed) = result_text(&mcp_argv(&argv, std::slice::from_ref(&scan_safe))[0]);
        assert!(
            !failed && text.contains("\"files\":1"),
            "the rail refused its own root under {argv:?}: {text}"
        );
    }
}

#[test]
fn a_job_outlives_the_call_that_started_it_and_leaves_a_resumable_catalog() {
    let s = Scratch::new("job");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    // enough files, slowly enough, that the job is still running when it is measured
    for i in 0..40 {
        write(
            &src.join(format!("f{i}.bin")),
            &noise(200_000, i as u64 + 1),
            0o644,
        );
    }
    let cat = s.path("catalog");
    let dst = s.s("dst");
    let index = cat.join("j/index.tsv");

    let out = rcp(
        &cat,
        &[
            "job",
            "start",
            "copy",
            "-newid",
            "j",
            "-bwlimit",
            "300k",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    let text = assert_passed(&out);
    let id = text
        .split_whitespace()
        .find(|w| w.starts_with("job-"))
        .expect("an id")
        .to_string();
    // the options after `start` belong to the job, not to `job` itself
    assert!(
        text.contains("-bwlimit 300k"),
        "the job did not keep its options:\n{text}"
    );

    // the catalog fills while the job runs, which is what makes a cancel resumable. It
    // used to be written in one pass after every file had landed: a copy killed part way
    // left no file entries at all and resuming it copied everything again.
    let entries = |path: &Path| {
        fs::read_to_string(path)
            .map(|t| t.lines().filter(|l| l.split('\t').count() > 3).count())
            .unwrap_or(0)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while entries(&index) < 4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let during = entries(&index);
    // what the job itself said, so a failure here can be told apart: a copy that never
    // started, one that is running slowly, and one writing entries the catalog did not get
    let said = |ext: &str| {
        fs::read_to_string(cat.join(format!("jobs/{id}.{ext}")))
            .unwrap_or_else(|e| format!("({e})"))
    };
    assert!(during >= 4, "the catalog had {during} entries after 20 s; it is not being written as files land\nevents:\n{}\nmessages:\n{}", said("ndjson"), said("log"));
    let status = assert_passed(&rcp(&cat, &["job", "status", &id]));
    assert!(
        status.contains("running"),
        "the job should still be running while it is measured:\n{status}"
    );
    // and so does the event log, flushed per entry, so a caller can watch it
    let events = fs::read_to_string(cat.join(format!("jobs/{id}.ndjson"))).unwrap();
    assert!(
        events.matches("\"event\":\"entry\"").count() >= 4,
        "the events are not reaching the log while the job runs:\n{events}"
    );
    // reading it twice from the offset it returns hands over nothing twice
    let first = assert_passed(&rcp(&cat, &["job", "log", &id]));
    let at = first
        .lines()
        .find_map(|l| {
            l.strip_prefix("job log: ")
                .and_then(|r| r.split(' ').next())
        })
        .expect("an offset")
        .to_string();
    let again = assert_passed(&rcp(&cat, &["job", "log", "-n", &at, &id]));
    assert!(
        !again.contains("\"event\":\"entry\""),
        "the same events were handed over twice:\n{again}"
    );

    // cancel stops it and says how to finish it
    let text = assert_passed(&rcp(&cat, &["job", "cancel", &id]));
    assert!(
        text.contains("canceled") && text.contains("rcp resume -id j"),
        "{text}"
    );
    let after = entries(&index);
    assert!(
        after >= during,
        "the catalog lost entries when the job was canceled: {during} then {after}"
    );
    assert!(
        after < 40,
        "the job finished before it could be canceled; the measurement below would prove nothing"
    );

    // resume finishes it, skipping exactly what the catalog recorded
    let text = assert_passed(&rcp(&cat, &["resume", "-id", "j"]));
    let skipped: usize = text
        .split(" skipped")
        .next()
        .and_then(|l| l.rsplit(", ").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    assert_eq!(
        skipped, after,
        "resume skipped {skipped} of the {after} the catalog recorded:\n{text}"
    );
    assert_passed(&rcp(&cat, &["verify", src.to_str().unwrap(), &dst]));

    // status now reads the run's own last event rather than the job file, which still
    // says running because nothing updates it when the child exits
    let text = assert_passed(&rcp(&cat, &["job", "status", &id]));
    assert!(text.contains("canceled"), "{text}");
    // and the remedy it offers has to be one that works. For a COPY, `resume` is right:
    // it walks what the catalog did not record and copies it. That is the control for the
    // sync case below, which had the same line and could not act on it.
    assert!(
        text.contains("rcp resume -id"),
        "a canceled copy was not pointed at resume:\n{text}"
    );

    // A canceled SYNC was told the same thing, and `resume` never plans REMOVALS -- so the
    // advice could not finish the job however often it was followed. Same defect as the
    // one `Removed::or_refused` fixed in the foreground summary, still here because this
    // arm read the job's state and not its command.
    let syncsrc = s.path("syncsrc");
    fs::create_dir_all(&syncsrc).unwrap();
    for i in 0..40 {
        write(
            &syncsrc.join(format!("g{i}.bin")),
            &noise(200_000, i as u64 + 100),
            0o644,
        );
    }
    let sdst = s.s("syncdst");
    // `sync` needs an EXISTING catalog id (`-id`, not `-newid`), so one copy lays it down
    // first and the sync then has real work: more files arrive in the source afterwards.
    assert_passed(&rcp(
        &cat,
        &["copy", "-newid", "k", syncsrc.to_str().unwrap(), &sdst],
    ));
    for i in 40..90 {
        write(
            &syncsrc.join(format!("g{i}.bin")),
            &noise(200_000, i as u64 + 100),
            0o644,
        );
    }
    let out = rcp(
        &cat,
        &[
            "job",
            "start",
            "sync",
            "-id",
            "k",
            "-bwlimit",
            "300k",
            syncsrc.to_str().unwrap(),
            &sdst,
        ],
    );
    let sid = assert_passed(&out)
        .split_whitespace()
        .find(|w| w.starts_with("job-"))
        .expect("an id")
        .to_string();
    let sindex = cat.join("k/index.tsv");
    let deadline = Instant::now() + Duration::from_secs(20);
    while entries(&sindex) < 45 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_passed(&rcp(&cat, &["job", "cancel", &sid]));
    let text = assert_passed(&rcp(&cat, &["job", "status", &sid]));
    assert!(
        text.contains("run the same `sync` again"),
        "a canceled sync was not told to rerun sync:\n{text}"
    );
    assert!(
        !text.contains("rcp resume -id"),
        "a canceled sync was pointed at resume, which never plans removals:\n{text}"
    );
    // list names it, forget removes it, and a job that is gone is an error to ask about
    assert!(assert_passed(&rcp(&cat, &["job", "list"])).contains(&id));
    assert_passed(&rcp(&cat, &["job", "forget", &id]));
    assert!(!assert_passed(&rcp(&cat, &["job", "list"])).contains(&id));
    assert_failed(&rcp(&cat, &["job", "status", &id]), &id);

    // the controls: a job needs a command, a command may not carry its own catalog, and
    // an unknown subcommand is refused by name
    assert_failed(&rcp(&cat, &["job", "start"]), "needs the command to run");
    assert_failed(
        &rcp(
            &cat,
            &["job", "start", "copy", "-catalog", "/tmp/x", "/a", "/b"],
        ),
        "goes before `job`",
    );
    assert_failed(
        &rcp(&cat, &["job", "frobnicate"]),
        "use start, list, status",
    );
}

/// A job id names a file under the catalog, so an id that is not a name is a path.
///
/// `Catalog` has refused these since it was written; `Jobs` interpolated the id into
/// `<catalog>/jobs/{id}.json` and never asked. `cancel` is the sharp end: it reads that
/// file, trusts the `pid` it finds, and sends SIGTERM then SIGKILL. Measured before the
/// fix -- a record planted one directory up, naming a `sleep 300` of this user's, and
/// `rcp job cancel ../victim` reported PASSED with the sleep dead.
///
/// `log` and `forget` are the same read and the same delete one path away; they are
/// checked here too because the fix is one guard and a guard is worth nothing if it is
/// only on the subcommand somebody remembered.
#[test]
fn a_job_id_is_a_name_and_never_a_path() {
    let s = Scratch::new("job-id");
    let cat = s.path("catalog");
    fs::create_dir_all(cat.join("jobs")).unwrap();

    // a live process of this user, standing in for whatever a planted record would name
    let mut victim = Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("sleep starts");
    let record = format!("{{\"id\": \"victim\", \"pid\": {}, \"started\": 1, \"state\": \"running\", \"catalog\": null, \"argv\": [\"sleep\"]}}\n", victim.id());
    write(&cat.join("victim.json"), record.as_bytes(), 0o644);
    write(&cat.join("victim.ndjson"), b"", 0o644);

    for id in [
        "../victim",
        "../../victim",
        "/tmp/victim",
        "..",
        ".",
        ".hidden",
        "has/slash",
        "",
    ] {
        for sub in ["status", "cancel", "log", "forget"] {
            let out = rcp(&cat, &["job", sub, id]);
            assert!(!out.status.success(), "job {sub} {id:?} was accepted");
        }
    }
    // the record is still there and so is the process: nothing was read, signaled or
    // deleted through a traversed path
    assert!(
        cat.join("victim.json").exists(),
        "a traversed id deleted a file outside the jobs directory"
    );
    assert!(
        victim
            .try_wait()
            .expect("the victim can be polled")
            .is_none(),
        "a traversed id killed another process"
    );
    let _ = victim.kill();
    let _ = victim.wait();

    // The control, and it is the point of the arm rather than decoration: a guard that
    // refuses every id passes every line above while making `rcp job` useless. A real id
    // still works, and the shape of a real one -- dots and dashes -- is exactly what the
    // traversal arms are built out of, so this is not a free pass.
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"a\n", 0o644);
    let dst = s.s("dst");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "job",
            "start",
            "copy",
            "-newid",
            "k",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    let id = text
        .split_whitespace()
        .find(|w| w.starts_with("job-"))
        .expect("an id")
        .to_string();
    assert!(
        id.contains('-') && id.contains("job-"),
        "the ids this guard has to admit look like {id:?}"
    );
    assert_passed(&rcp(&cat, &["job", "wait", "-t", "30s", &id]));
    assert_passed(&rcp(&cat, &["job", "status", &id]));
    assert_passed(&rcp(&cat, &["job", "log", &id]));
    assert_passed(&rcp(&cat, &["job", "forget", &id]));
}

/// A call the host gave up on must not leave a copy running. Killing the server used to
/// leave the child copying: the host believes the call was canceled and the writes carry
/// on with nobody watching. `rcp job` is how a run is meant to outlive its caller.
#[test]
fn a_killed_server_takes_its_child_with_it() {
    let s = Scratch::new("mcp-orphan");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    for i in 0..40 {
        write(
            &src.join(format!("f{i:03}.bin")),
            &noise(200 << 10, i as u64),
            0o644,
        );
    }
    let dst = s.s("dst");
    let call = call(
        1,
        "rcp_copy",
        &format!(
            "{{\"source\":\"{}\",\"destination\":\"{dst}\",\"options\":[\"-bwlimit\",\"100k\"]}}",
            src.display()
        ),
    );
    let mut server = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("rcp mcp starts");
    {
        use std::io::Write as _;
        // the call goes in and stdin STAYS OPEN, so the server is mid-call, not finishing
        writeln!(server.stdin.as_mut().unwrap(), "{call}").unwrap();
    }
    // wait for the child to exist, then kill the server out from under it
    let child = (0..100).find_map(|_| {
        std::thread::sleep(Duration::from_millis(50));
        Command::new("pgrep")
            .arg("-P")
            .arg(server.id().to_string())
            .output()
            .ok()
            .and_then(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .split_whitespace()
                    .next()
                    .and_then(|p| p.parse::<u32>().ok())
            })
    });
    server.kill().unwrap();
    server.wait().unwrap();
    let child = child.expect("the server spawned no child");
    let gone = (0..60).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        !Command::new("kill")
            .args(["-0", &child.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    if !gone {
        let _ = Command::new("kill")
            .args(["-9", &child.to_string()])
            .status();
    }
    assert!(
        gone,
        "the child outlived the server it was serving: pid {child} was still copying"
    );
}

/// A registry may hand an upload to another host, and two of the big ones do. The stand-in
/// does it on a second listener: the blobs have to arrive there, and this registry's
/// credential must not go with them.
#[test]
fn an_upload_follows_the_location_the_registry_gives_it() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-away");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--away", "--token"]);
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            layout.to_str().unwrap(),
            &reg.url("app"),
        ],
    ));
    assert_eq!(
        (reg.stat("blob_uploads"), reg.stat("manifest_pushes")),
        (3, 3),
        "{}",
        reg.stats()
    );
    assert!(
        reg.stat("away_uploads") >= 3,
        "the upload never reached the host the Location named: {}",
        reg.stats()
    );
    assert_eq!(
        reg.stat("away_authorized"),
        0,
        "the registry's token was sent to a third-party host: {}",
        reg.stats()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            "-oci.insecure",
            layout.to_str().unwrap(),
            &reg.url("app"),
        ],
    ));

    // Following that Location is the feature. WHERE it may point is the operator's call
    // once the run has rails: the registry chose the host, and `-allow` is the statement
    // of where this run's data may go. A railed run that names only the registry must
    // refuse the hand-off, and must refuse it without sending the blob.
    let reg2 = Registry::start(&["--away"]);
    let before = reg2.stat("away_uploads");
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                "-allow",
                layout.to_str().unwrap(),
                "-allow",
                &reg2.url("app"),
                layout.to_str().unwrap(),
                &reg2.url("app"),
            ],
        ),
        "rails do not name",
    );
    assert!(
        out.contains("add -allow"),
        "the refusal must say how to permit it:\n{out}"
    );
    assert_eq!(
        reg2.stat("away_uploads"),
        before,
        "a refused hand-off still sent the blob: {}",
        reg2.stats()
    );
    // the control: name the away host too and the identical copy goes through, so the
    // refusal above is the rail and not a registry that was never reachable
    let away = format!("http://127.0.0.1:{}", reg2.stat("away_port"));
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            "-allow",
            layout.to_str().unwrap(),
            "-allow",
            &reg2.url("app"),
            "-allow",
            &away,
            layout.to_str().unwrap(),
            &reg2.url("app"),
        ],
    ));
    assert!(
        reg2.stat("away_uploads") >= 3,
        "the permitted hand-off never happened: {}",
        reg2.stats()
    );
    // and an unrailed run follows it as it always did -- naming the registry is the trust
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            layout.to_str().unwrap(),
            &reg2.url("app2"),
        ],
    ));

    // How a root becomes an authority -- default ports, and an explicit 80 or 443 that an
    // earlier version rewrote to the other one -- is measured in `main.rs`'s own unit
    // test rather than here. An arm was written here first and it could not fail: the
    // stand-in binds its away listener on a random high port, so planting the defect back
    // left the arm green. An arm that cannot fail reads as coverage and is not.

    // The SHARPER half of the same class, and the one the blob-path fix did not reach: a
    // bearer `realm`. A 401 names where to get a token, the client goes there, and it
    // sends the BASIC CREDENTIALS to get one. Docker Hub's realm really is another host,
    // so this is the protocol working -- and it means a registry answering with a realm
    // of its choosing is handed the run's username and password. Measured before the
    // check existed: `Basic b3BlcmF0b3I6c3VwZXJzZWNyZXQ=` arrived at a listener on
    // another port, from a run railed to the registry alone.
    let thief =
        std::net::TcpListener::bind("127.0.0.1:0").expect("a port to stand in for a hostile realm");
    let thief_port = thief.local_addr().unwrap().port();
    let asked = Arc::new(AtomicUsize::new(0));
    // Counting connections is not the property. What makes a hostile realm worth a rail is
    // that fetching a token SENDS THE CREDENTIALS, so the stand-in reads the request and
    // records whether one arrived. A permitted-realm control that only asserted it had
    // been dialed would also be satisfied by a run that opened a socket and sent nothing.
    let with_creds = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    let creds = Arc::clone(&with_creds);
    std::thread::spawn(move || {
        for stream in thief.incoming() {
            match stream {
                Ok(mut s) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    use std::io::Read;
                    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 2048];
                    if let Ok(n) = s.read(&mut buf) {
                        let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                        if head.contains("authorization: basic") {
                            creds.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    drop(s);
                }
                Err(_) => break,
            }
        }
    });
    let reg4 = Registry::start(&[
        "--token",
        "--realm",
        &format!("http://127.0.0.1:{thief_port}/token"),
    ]);
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_OCI_USER", "operator")
        .env("RCP_OCI_PASSWORD", "supersecret")
        .args([
            "-catalog",
            cat.to_str().unwrap(),
            "copy",
            "-noId",
            "-oci.insecure",
            "-allow",
            layout.to_str().unwrap(),
            "-allow",
            &reg4.url("app"),
            layout.to_str().unwrap(),
            &reg4.url("app"),
        ])
        .output()
        .expect("rcp runs");
    let text = assert_failed(&out, "asked for a token from");
    assert!(text.contains("rails do not name"), "{text}");
    assert_eq!(
        asked.load(Ordering::SeqCst),
        0,
        "the credentials were carried to a host the rails never named"
    );
    assert_eq!(
        with_creds.load(Ordering::SeqCst),
        0,
        "a Basic credential reached the hostile realm"
    );
    // The control, and it is the whole arm: name that host and the run BOTH reaches it and
    // hands it the credentials. Without the second half the refusal above could be a
    // listener nothing would ever have dialed, or one that would have been dialed with
    // nothing in its hands -- and only the first of those makes a rail worth having.
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_OCI_USER", "operator")
        .env("RCP_OCI_PASSWORD", "supersecret")
        .args([
            "-catalog",
            cat.to_str().unwrap(),
            "copy",
            "-noId",
            "-oci.insecure",
            "-allow",
            layout.to_str().unwrap(),
            "-allow",
            &reg4.url("app"),
            "-allow",
            &format!("http://127.0.0.1:{thief_port}"),
            layout.to_str().unwrap(),
            &reg4.url("app"),
        ])
        .output()
        .expect("rcp runs");
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        asked.load(Ordering::SeqCst) > 0,
        "the permitted realm was never dialed, so the refusal above proves nothing"
    );
    assert!(
        with_creds.load(Ordering::SeqCst) > 0,
        "the permitted realm was dialed but got no credential, so the refusal above is not measuring what it claims:\n{text}"
    );
    // and the refusal it stops giving is the rail's, not some later failure standing in
    // for it: the token fetch goes through and the run dies at the stand-in instead
    assert!(
        !text.contains("rails do not name"),
        "the rail still refused a realm it was told to allow:\n{text}"
    );
}

/// A copy whose manifests never went up leaves blobs in the registry and no image, and a
/// resume has to finish the job. It is tempting to expect the catalog to defeat that by
/// recording the manifests as done; measured, it does not, because `Mode::Resume` skips
/// only what the catalog knows AND the destination already shows, and an unpublished
/// registry shows nothing. So this arm is the end-to-end property rather than a fix: a
/// failed publish is recoverable by re-running. (A `committed` flag on the file outcome is
/// not a useful second line of defense: `AnySink` has no delegation for it, so the default
/// always wins, and wiring it up would stop a SUCCESSFUL publish from cataloging its
/// manifests. What holds is the skip rule itself, which this arm measures.)
#[test]
fn a_resume_after_a_failed_publish_still_publishes() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-resume");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    // a registry that takes blobs and refuses every manifest: the blobs land, the image
    // does not, and the run fails
    let reg = Registry::start(&["--no-manifests"]);
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-newid",
                "half",
                "-oci.insecure",
                layout.to_str().unwrap(),
                &reg.url("app"),
            ],
        ),
        "finishing",
    );
    assert!(
        reg.stat("blob_uploads") >= 3 && reg.stat("manifest_pushes") == 0,
        "{}",
        reg.stats()
    );
    // the catalog kept the blobs and not the manifests, so the resume republishes
    reg.control("publish");
    let text = assert_passed(&rcp(&cat, &["resume", "-id", "half", "-oci.insecure"]));
    let _ = &text;
    assert_eq!(
        reg.stat("manifest_pushes"),
        3,
        "the resume published nothing: {}",
        reg.stats()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            "-oci.insecure",
            layout.to_str().unwrap(),
            &reg.url("app"),
        ],
    ));
}

/// A throttled registry is the one failure in the code set worth waiting on. It used to
/// arrive as `io`, the same code as everything the set has no name for, which is exactly
/// the distinction an agent needs to tell a wait from a dead end.
#[test]
fn a_registry_over_its_rate_limit_says_busy_rather_than_io() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-429");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--throttle", "--seed", "app", layout.to_str().unwrap()]);
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-json",
            "-oci.insecure",
            &reg.url("app"),
            s.path("dst").to_str().unwrap(),
        ],
    );
    let codes: Vec<String> = events(&out)
        .into_iter()
        .filter(|e| of(e, "event") == "error")
        .map(|e| of(&e, "code").to_string())
        .collect();
    assert!(
        codes.iter().any(|c| c == "busy"),
        "a 429 must be its own code, not the fallback: {codes:?}"
    );
    assert!(!codes.iter().any(|c| c == "io"), "{codes:?}");
    // "The same registry without the rate limit copies cleanly" is not a control here: it
    // runs a registry that returns no failing status at all, so reverting 429 to the
    // fallback leaves it green. It measures that a normal copy works, which nine other arms
    // already hold.
    //
    // The control a mapping table needs is a SECOND status, and the pair is what makes
    // either one mean something: 429 must come back `busy` and a status with no entry in
    // the table must still come back `io`. A change that mapped everything to `busy` to
    // pass the line above would fail this one, and a change that dropped the 429 entry
    // would fail that one.
    let reg = Registry::start(&[
        "--blobstatus",
        "418",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-json",
            "-oci.insecure",
            &reg.url("app"),
            s.path("dst-other").to_str().unwrap(),
        ],
    );
    let codes: Vec<String> = events(&out)
        .into_iter()
        .filter(|e| of(e, "event") == "error")
        .map(|e| of(&e, "code").to_string())
        .collect();
    assert!(
        codes.iter().any(|c| c == "io"),
        "a status the table does not name must fall back, or `busy` means nothing: {codes:?}"
    );
    assert!(
        !codes.iter().any(|c| c == "busy"),
        "a status the table does not name came back retryable: {codes:?}"
    );
    // and a status it DOES name, from the same mechanism, is still itself
    let reg = Registry::start(&[
        "--blobstatus",
        "503",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-json",
            "-oci.insecure",
            &reg.url("app"),
            s.path("dst-503").to_str().unwrap(),
        ],
    );
    let codes: Vec<String> = events(&out)
        .into_iter()
        .filter(|e| of(e, "event") == "error")
        .map(|e| of(&e, "code").to_string())
        .collect();
    assert!(
        codes.iter().any(|c| c == "busy"),
        "503 is an overloaded registry and is worth waiting on too: {codes:?}"
    );

    // and a sanity check, which is not the control: the stand-in itself works
    let reg = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg.url("app"),
            s.path("dst2").to_str().unwrap(),
        ],
    ));
}

/// A layer whose bytes happen to read like a manifest. The sniff cannot tell, so what
/// `index.json` reaches decides: this one is reached by nothing, and goes up as the blob
/// it is. Staging it instead -- which is what the sniff used to do on its own -- left its
/// parent unpushable and the image broken.
#[test]
fn a_layer_that_reads_like_a_manifest_is_still_stored_as_a_layer() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-sniff");
    let dir = s.path("layout");
    let blobs = dir.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let put = |data: &[u8]| -> (String, usize) {
        let h = rcp::sha256::digest_hex(data);
        fs::write(blobs.join(&h), data).unwrap();
        (h, data.len())
    };
    // a layer that is JSON carrying every key the sniff looks for
    let (trap, trap_n) = put(
        br#"{"schemaVersion":2,"config":{"note":"this is a layer"},"layers":[],"manifests":[]}"#,
    );
    let (cfg, cfg_n) =
        put(br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#);
    let manifest = "application/vnd.oci.image.manifest.v1+json";
    let layer = "application/vnd.oci.image.layer.v1.tar+gzip";
    let (m, m_n) = put(
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{manifest}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg}","size":{cfg_n}}},"layers":[{{"mediaType":"{layer}","digest":"sha256:{trap}","size":{trap_n}}}]}}"#
        )
        .as_bytes(),
    );
    fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    fs::write(
        dir.join("index.json"),
        format!(r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{manifest}","digest":"sha256:{m}","size":{m_n},"annotations":{{"org.opencontainers.image.ref.name":"latest"}}}}]}}"#),
    )
    .unwrap();

    let cat = s.path("catalog");
    let reg = Registry::start(&[]);
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            dir.to_str().unwrap(),
            &reg.url("app"),
        ],
    ));
    // two blobs (the config and the trap) and one manifest: the trap was not published as
    // a manifest, and it was not left out of the blob store either
    assert_eq!(
        (reg.stat("blob_uploads"), reg.stat("manifest_pushes")),
        (2, 1),
        "{}",
        reg.stats()
    );
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg.url("app"),
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read(back.join("blobs/sha256").join(&trap)).unwrap(),
        fs::read(blobs.join(&trap)).unwrap()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            dir.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));

    // The other end of that rule: with NO index.json there are no roots, so the rule sends
    // EVERY manifest up as an unreferenced blob and pushes no tag -- and, unguarded, the run
    // says PASSED. Measured on this layout with its index removed and no refusal: 3 blob
    // uploads, 0 manifest pushes, status PASSED, and a repository holding bytes no client
    // can name.
    fs::remove_file(dir.join("index.json")).unwrap();
    let reg2 = Registry::start(&[]);
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                dir.to_str().unwrap(),
                &reg2.url("app"),
            ],
        ),
        "index.json names nothing",
    );
    assert!(
        out.contains("create no image"),
        "the refusal must say what was not produced:\n{out}"
    );
    assert_eq!(reg2.stat("manifest_pushes"), 0, "{}", reg2.stats());
    // and it refuses BEFORE anything is staged goes up, so nothing unreferenced is left
    // behind. Exactly one blob lands: the config. The trap and the real manifest both
    // sniff as manifests and are therefore staged, and staged is what the refusal stops --
    // without that, all three go up as blobs and the run is called a success.
    assert_eq!(
        reg2.stat("blob_uploads"),
        1,
        "something that reads as a manifest went up as a blob anyway: {}",
        reg2.stats()
    );
    // the control: put the index back and the identical copy succeeds, so the refusal is
    // about the missing roots and not about this registry or this layout
    fs::write(
        dir.join("index.json"),
        format!(r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{manifest}","digest":"sha256:{m}","size":{m_n},"annotations":{{"org.opencontainers.image.ref.name":"latest"}}}}]}}"#),
    )
    .unwrap();
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            dir.to_str().unwrap(),
            &reg2.url("app"),
        ],
    ));
    assert_eq!(reg2.stat("manifest_pushes"), 1, "{}", reg2.stats());

    // The same defect from the other end: a layout holding blobs that sniff as NOTHING. A
    // guard that asks whether anything has been staged is asking about what happened to
    // look like a manifest rather than about what the source was, so this goes through --
    // 1 blob uploaded, 0 manifests, PASSED. `oci-layout` is the source calling itself a
    // layout, and a layout owes an index; that is the condition, and it covers both.
    let bare = s.path("bare");
    fs::create_dir_all(bare.join("blobs/sha256")).unwrap();
    let plain = b"just-some-layer-bytes-not-json-at-all";
    fs::write(
        bare.join("blobs/sha256")
            .join(rcp::sha256::digest_hex(plain)),
        plain,
    )
    .unwrap();
    fs::write(
        bare.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let reg3 = Registry::start(&[]);
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                bare.to_str().unwrap(),
                &reg3.url("bare"),
            ],
        ),
        "index.json names nothing",
    );
    assert_eq!(reg3.stat("manifest_pushes"), 0, "{}", reg3.stats());
    // Note what this does NOT claim. A plain blob streams straight up as the copy reaches
    // it -- only manifest-shaped bytes are held back -- so by the time `sync` refuses, one
    // blob has landed and cannot be unsent. The refusal is that no IMAGE is claimed, not
    // that the registry is untouched; unreferenced blobs are what a registry's garbage
    // collection is for. Held-back manifests are the part a refusal can still prevent,
    // and the previous arm measures that at 1 upload where an unguarded copy sends 3.
    assert_eq!(reg3.stat("blob_uploads"), 1, "{}", reg3.stats());
    // and the condition must NOT fire where no layout was claimed: the same blob, copied
    // without the marker, is a blob the caller asked for and it goes up
    fs::remove_file(bare.join("oci-layout")).unwrap();
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            bare.to_str().unwrap(),
            &reg3.url("bare"),
        ],
    ));
}

/// A registry token has a lifetime, and a copy of a real image outlives it. The stand-in
/// retires one every few requests; the copy has to carry on regardless, because the 401 is
/// an expiry and not a refusal.
#[test]
fn a_token_that_expires_mid_copy_is_renewed_rather_than_failing_the_file() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-expire");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let source = Registry::start(&[
        "--token",
        "--expire",
        "1",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let dest = Registry::start(&[]);
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &source.url("app"),
            &dest.url("app"),
        ],
    ));
    assert!(
        source.stat("tokens_issued") > 1,
        "no token was ever renewed, so nothing expired: {}",
        source.stats()
    );
    assert_eq!(
        (dest.stat("blob_uploads"), dest.stat("manifest_pushes")),
        (3, 3),
        "{}",
        dest.stats()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-oci.insecure",
            &source.url("app"),
            &dest.url("app"),
        ],
    ));
}

/// A blob GET whose connection dies before its status line is asked again, not failed.
///
/// That is what reusing a keep-alive connection the server closed while it sat idle looks
/// like, and the streaming GET was the one request path with no retry: the release
/// workflow's first `--features rustls` run lost `a_stream_that_dies_mid_blob_...` to it
/// under load, when a mid-blob resume reissued its GET on such a connection and the copy
/// failed with "connection closed before the response arrived". `--drophead 2` closes
/// every second blob GET unanswered, so the case is reached on every run rather than when
/// the machine is busy. The count is the control: it must have dropped some.
#[test]
fn a_blob_get_whose_connection_dies_before_the_response_is_asked_again() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-drophead");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--drophead", "2", "--seed", "app", layout.to_str().unwrap()]);
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg.url("app"),
            back.to_str().unwrap(),
        ],
    ));
    assert!(
        reg.stat("dropped") > 0,
        "the stand-in dropped no GET, so nothing was asked again: {}",
        reg.stats()
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            layout.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
}

/// The other half of that: the case the retry above does not reach. A token that expires
/// with the body already flowing leaves no 401 to answer: the 200 and its headers are spent,
/// and the registry simply stops sending. `--cut N` is that, exactly -- a real 200 with the
/// real `Content-Length`, N bytes, then the connection closed, once per blob.
#[test]
fn a_stream_that_dies_mid_blob_is_reissued_from_where_it_stopped() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-cut");
    let layout = s.path("layout");
    // a layer big enough to be cut in the middle rather than delivered before the cut
    let blobs = layout.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let put = |data: &[u8]| -> (String, usize) {
        let h = rcp::sha256::digest_hex(data);
        fs::write(blobs.join(&h), data).unwrap();
        (h, data.len())
    };
    let big: Vec<u8> = (0..400_000u32)
        .map(|i| (i.wrapping_mul(7).wrapping_add(3) % 251) as u8)
        .collect();
    let (lay, lay_n) = put(&big);
    let (cfg, cfg_n) =
        put(br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#);
    let mt = "application/vnd.oci.image.manifest.v1+json";
    let (m, m_n) = put(
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{mt}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg}","size":{cfg_n}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{lay}","size":{lay_n}}}]}}"#
        )
        .as_bytes(),
    );
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        layout.join("index.json"),
        format!(r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{mt}","digest":"sha256:{m}","size":{m_n},"annotations":{{"org.opencontainers.image.ref.name":"v1"}}}}]}}"#),
    )
    .unwrap();

    let cat = s.path("catalog");
    let reg = Registry::start(&["--cut", "10000", "--seed", "app", layout.to_str().unwrap()]);
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg.url("app"),
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        reg.stat("cuts"),
        1,
        "the stand-in never cut a stream, so nothing was recovered from: {}",
        reg.stats()
    );
    // the bytes are all there and they are the right ones. The digest check is what makes
    // a resumed read safe at all, and it survives the reissue because the hasher rides
    // across: a `Range` resume skips nothing, so what it has absorbed is still a prefix.
    assert_eq!(
        fs::read(back.join("blobs/sha256").join(&lay)).unwrap(),
        big,
        "the layer came back wrong after the cut"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            layout.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    // Two controls, and the first is what makes the arm a measurement at all: the
    // stand-in must have CUT the stream, or this passes on a blob delivered whole. It is
    // asserted above rather than here so a zero shows up before the bytes are compared.
    //
    // The second has to be executable. With the resume removed this same run dies with the
    // body outstanding, measured as `connection closed with 390000 body bytes
    // outstanding` -- but a hand-measurement in a comment is not a control, because nothing
    // runs it. The executable form is the `--norange` server below: it cuts the same way
    // and then refuses to honor the resume, and the run must fail. That is the same
    // property from the other side -- the reissue is load-bearing, so a server that will
    // not serve it cannot be recovered from -- and it runs.

    // A `Range` is a request, not a guarantee, and a server free to ignore it answers 200
    // with the whole blob -- so every byte from `pos` on is really a byte from zero, and
    // the destination gets the blob's head written at its tail. The digest catches that
    // here, because the hasher rides across and is fed the wrong bytes; it does NOT catch
    // it on the `Seek` path, which clears the hasher. So the honest place to refuse is
    // before a byte is placed at the wrong offset, and the message has to name the server
    // rather than the blob -- `the registry served bytes with digest sha256:91044a0e...`
    // reads as a corrupt blob, and that is not what happened.
    let reg2 = Registry::start(&[
        "--cut",
        "10000",
        "--norange",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                &reg2.url("app"),
                s.path("nr").to_str().unwrap(),
            ],
        ),
        "does not honor Range",
    );
    assert!(
        out.contains("asked for bytes from"),
        "the refusal must say what was asked and what came back:\n{out}"
    );
    assert!(
        !out.contains("served bytes with digest"),
        "a Range the server ignored is not a corrupt blob, and must not be reported as one:\n{out}"
    );

    // And 206 alone is not enough. The status says "here is a range" without saying WHICH,
    // so a server that answers 206 while sending from zero mis-assembles the read exactly
    // as a 200 does. The `Content-Range` is the only thing that says where the bytes
    // start, so it is read rather than the status trusted.
    let reg3 = Registry::start(&[
        "--cut",
        "10000",
        "--liesrange",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                &reg3.url("app"),
                s.path("lies").to_str().unwrap(),
            ],
        ),
        "answered 206 starting at 0",
    );
    assert!(
        !out.contains("served bytes with digest"),
        "a 206 that lied about its offset is not a corrupt blob:\n{out}"
    );

    // One cut is one resume, and an arm which cuts once cannot tell a resume LOOP from a
    // resume RECURSION -- reissuing by calling `read` again costs one stack frame per
    // reconnection, with the depth chosen by the far end. `--always` keeps cutting, so
    // finishing takes a resume per chunk.
    //
    // Said plainly, because the arm does not prove what it might appear to: a recursive
    // version completes this too. The depth is in the hundreds and the stack absorbs it;
    // on a bigger hand-measurement, 62,502 frames also completed. So this arm
    // holds that MANY resumes finish correctly, which is worth holding on its own, and the
    // loop is there because nothing bounds a depth the far end picks -- not because a
    // crash was reproduced.
    let reg4 = Registry::start(&[
        "--cut",
        "2048",
        "--always",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let many = s.path("many");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg4.url("app"),
            many.to_str().unwrap(),
        ],
    ));
    assert!(
        reg4.stat("cuts") > 100,
        "the stand-in cut once, which is the case already covered: {}",
        reg4.stats()
    );
    assert_eq!(
        fs::read(many.join("blobs/sha256").join(&lay)).unwrap(),
        big,
        "the layer came back wrong after many cuts"
    );

    // And the bound, which is the part progress alone does not give. `resumed_at` refuses
    // a second attempt at an offset that did not MOVE -- so a server sending one byte and
    // hanging up defeats it, because the offset moves every time and the only limit left
    // is the size the server itself declared. A budget derived from the blob is the
    // answer: the arm above needs ~195 resumes over 400 kB and passes inside 390, and this
    // one needs 6,250 and is refused by name.
    //
    // Without the budget this case SUCCEEDS, after six thousand reconnections. Refusing it
    // is the point rather than a casualty: a registry that hangs up every 64 bytes is not
    // delivering the blob.
    let reg5 = Registry::start(&[
        "--cut",
        "64",
        "--always",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                &reg5.url("app"),
                s.path("dribble").to_str().unwrap(),
            ],
        ),
        "is not delivering this blob",
    );
    assert!(
        out.contains("cut the stream"),
        "the refusal must name what the server did:\n{out}"
    );
    assert!(
        reg5.stat("cuts") < 1000,
        "the budget did not stop it: {}",
        reg5.stats()
    );
    assert_eq!(
        fs::read(many.join("blobs/sha256").join(&lay)).unwrap(),
        big,
        "the layer came back wrong after many resumes"
    );
}

/// A fleet cannot publish, and the refusal is the fix for a measured silent success: without
/// it this same copy exits 0 reporting 8 files while pushing 0 manifests, leaving a registry
/// with three blobs and no repository at all. Each worker is its own process, so whatever
/// it stages for `sync` dies with it and only the coordinator — which copied nothing —
/// calls `sync`.
#[test]
fn a_fleet_is_refused_by_a_destination_that_publishes_when_it_finishes() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("fleet-oci");
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let stub = ssh_stub(&s);
    let reg = Registry::start(&[]);
    let (src, app) = (layout.display().to_string(), reg.url("app"));

    assert_failed(
        &rcp_fleet(
            &cat,
            &stub,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                "-nodes",
                "w0,w1",
                &src,
                &app,
            ],
        ),
        "fleet cannot publish",
    );
    assert_eq!(
        (reg.stat("blob_uploads"), reg.stat("manifest_pushes")),
        (0, 0),
        "refused before anything moved: {}",
        reg.stats()
    );

    // control: the same copy without -nodes publishes, and the image is there
    assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &["copy", "-noId", "-oci.insecure", &src, &app],
    ));
    assert_eq!(
        (reg.stat("blob_uploads"), reg.stat("manifest_pushes")),
        (3, 3),
        "{}",
        reg.stats()
    );
    assert_passed(&rcp(&cat, &["scan", "-oci.insecure", &reg.url("app")]));

    // control: a fleet into a filesystem, whose sync only flushes, is not refused
    let dst = s.path("dst");
    assert_passed(&rcp_fleet(
        &cat,
        &stub,
        &["copy", "-noId", "-nodes", "w0", &src, dst.to_str().unwrap()],
    ));
    assert!(dst.join("index.json").exists());
}

/// A tar archive is a tree: written from one, read back, and -- the part that matters --
/// read by the tar everyone else has. Every claim here is checked both ways round.
#[test]
fn tar_endpoints_pack_a_tree_and_unpack_one_that_tar_itself_wrote() {
    let s = Scratch::new("tar");
    let src = fixture(&s);
    fs::create_dir_all(src.join("nested")).unwrap();
    write(&src.join("nested/deep.bin"), &noise(300 << 10, 3), 0o640);
    symlink("message.txt", src.join("link")).unwrap();
    fs::hard_link(src.join("message.txt"), src.join("hard.txt")).unwrap();
    let cat = s.path("catalog");
    let archive = s.path("out.tar");
    let tar_url = format!("tar://{}", archive.display());

    // pack, and rcp's own verify compares every byte and every piece of metadata across
    // the archive boundary: mode, times to the nanosecond, ownership, links
    let text = assert_passed(&rcp(
        &cat,
        &["copy", "-noId", src.to_str().unwrap(), &tar_url],
    ));
    assert!(
        text.contains("symlinks") && text.contains("1 linked"),
        "{text}"
    );
    let text = assert_passed(&rcp(&cat, &["verify", src.to_str().unwrap(), &tar_url]));
    assert!(text.contains("0 differences"), "{text}");

    // unpack to a directory and compare with the source, which is the round trip
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &["copy", "-noId", &tar_url, back.to_str().unwrap()],
    ));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), back.to_str().unwrap()],
    ));
    // the hard link survived as a link, not as a second copy
    assert_eq!(
        fs::metadata(back.join("hard.txt")).unwrap().ino(),
        fs::metadata(back.join("message.txt")).unwrap().ino()
    );
    assert!(back
        .join("link")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());

    // a subpath roots at one directory inside the archive
    let text = assert_passed(&rcp(&cat, &["scan", "-l", &format!("{tar_url}!/nested")]));
    assert!(
        text.contains("deep.bin") && !text.contains("message.txt"),
        "{text}"
    );

    // what a tar has no room for is refused by name rather than half-done
    assert_failed(&rcp(&cat, &["delete", "-force", &tar_url]), "stream");
    // and an archive that already has something in it is never silently rewritten: the
    // destination of a fresh archive lists as empty, so no plan could show the loss
    assert_failed(
        &rcp(&cat, &["copy", "-noId", src.to_str().unwrap(), &tar_url]),
        "already has something in it",
    );
    assert!(fs::metadata(&archive).unwrap().len() > 0);
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                &format!("tar://{}!/inside", s.path("other.tar").display()),
            ],
        ),
        "subpath names what to read",
    );

    let Some(tar) = std::env::var_os("PATH")
        .and_then(|_| Command::new("tar").arg("--version").output().ok())
        .filter(|o| o.status.success())
    else {
        eprintln!("SKIP: no tar(1) here, so the interoperability half of this arm did not run");
        return;
    };
    let gnu = String::from_utf8_lossy(&tar.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    // THE claim: the tar everyone else has reads what rcp wrote, and its extraction is
    // the source again
    let x = s.path("x");
    fs::create_dir_all(&x).unwrap();
    let out = Command::new("tar")
        .args(["xf", archive.to_str().unwrap(), "-C", x.to_str().unwrap()])
        .output()
        .expect("tar runs");
    assert!(
        out.status.success(),
        "{gnu} refused an archive rcp wrote:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).is_empty(),
        "{gnu} read it with complaints:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            src.to_str().unwrap(),
            x.to_str().unwrap(),
        ],
    ));

    // and the reverse: an archive tar(1) wrote, with names too long for ustar, reads here
    let deep = s.path("deep");
    let long = deep.join("d".repeat(120)).join("e".repeat(120));
    fs::create_dir_all(&long).unwrap();
    write(&long.join("f".repeat(120)), b"long\n", 0o644);
    write(&deep.join("short.txt"), b"short\n", 0o644);
    let theirs = s.path("theirs.tar");
    let out = Command::new("tar")
        .args([
            "cf",
            theirs.to_str().unwrap(),
            "-C",
            deep.to_str().unwrap(),
            ".",
        ])
        .output()
        .expect("tar runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mine = s.path("mine");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &format!("tar://{}", theirs.display()),
            mine.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            deep.to_str().unwrap(),
            mine.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read(
            mine.join("d".repeat(120))
                .join("e".repeat(120))
                .join("f".repeat(120))
        )
        .unwrap(),
        b"long\n"
    );

    // A tar stream is written once through, so `chmod` over an existing archive cannot
    // rewrite a member's header. `set_metadata` wrote one for a directory or a symlink --
    // the first moment those items are known -- and fell through for a regular member
    // already on the tape, returning Ok, so `apply_tree` counted it as changed. It is the
    // sibling of the registry case: the archive stores modes and still cannot change one
    // afterwards, which is a different question from whether it
    // stores them at all, and is why the predicate is named for the question it answers.
    let archive = s.path("packed.tar");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            deep.to_str().unwrap(),
            &format!("tar://{}", archive.display()),
        ],
    ));
    let before = fs::read(&archive).unwrap();
    assert_failed(
        &rcp(
            &cat,
            &[
                "chmod",
                "-mode",
                "755",
                &format!("tar://{}", archive.display()),
            ],
        ),
        "cannot change modes, owners or times once written",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "chown",
                "-user",
                "root",
                &format!("tar://{}", archive.display()),
            ],
        ),
        "cannot change modes, owners or times once written",
    );
    assert_eq!(
        fs::read(&archive).unwrap(),
        before,
        "a refused chmod still touched the archive"
    );
    // the control: a directory does rewrite in place, so the refusal is about the archive
    // and not about the command
    assert_passed(&rcp(
        &cat,
        &[
            "chmod",
            "-mode",
            "755",
            "-type",
            "f",
            mine.to_str().unwrap(),
        ],
    ));
}

/// A destination is not always a tree this run made. A symlink sitting where a file or a
/// directory belongs must not be FOLLOWED: the bytes would land wherever it points --
/// outside the destination entirely, past every rail -- and the copy would leave the link in
/// place instead of producing what the source has. Both engines, because they open the
/// destination themselves.
#[test]
fn a_copy_writes_into_its_destination_rather_than_through_a_link_in_it() {
    let s = Scratch::new("nofollow");
    let src = s.path("src");
    fs::create_dir_all(src.join("sub")).unwrap();
    write(&src.join("f.txt"), b"from the source\n", 0o644);
    write(&src.join("sub/g.txt"), b"in a directory\n", 0o644);
    let away = s.path("away");
    fs::create_dir_all(&away).unwrap();
    let cat = s.path("catalog");

    for engine in ["auto", "threads"] {
        let dst = s.path(&format!("dst-{engine}"));
        fs::create_dir_all(&dst).unwrap();
        write(&away.join("target"), b"not this\n", 0o644);
        symlink(away.join("target"), dst.join("f.txt")).unwrap();
        symlink(&away, dst.join("sub")).unwrap();

        assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-engine",
                engine,
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ));

        assert_eq!(
            fs::read(away.join("target")).unwrap(),
            b"not this\n",
            "{engine}: the copy wrote through a link, outside the destination"
        );
        assert!(
            !away.join("g.txt").exists(),
            "{engine}: the copy wrote through a linked directory"
        );
        // and the destination is what the source says it is, which is the other half
        assert!(
            dst.join("f.txt")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_file(),
            "{engine}: the link is still there"
        );
        assert_eq!(fs::read(dst.join("f.txt")).unwrap(), b"from the source\n");
        assert!(dst
            .join("sub")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_dir());
        assert_eq!(
            fs::read(dst.join("sub/g.txt")).unwrap(),
            b"in a directory\n"
        );
        assert_passed(&rcp(
            &cat,
            &["verify", src.to_str().unwrap(), dst.to_str().unwrap()],
        ));
    }

    // the controls: an ordinary overwrite still overwrites, and a symlink in the SOURCE is
    // still recreated as a symlink rather than followed
    let dst = s.path("dst-auto");
    write(&dst.join("f.txt"), b"older\n", 0o644);
    symlink("f.txt", src.join("link")).unwrap();
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    assert_eq!(fs::read(dst.join("f.txt")).unwrap(), b"from the source\n");
    assert!(dst
        .join("link")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
}

fn rcp_dav(catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("NO_PROXY", "*")
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

/// `dav://` end to end against a real WebDAV server: copy in, verify, sync, delete.
///
/// The stand-in is deliberately awkward in the two ways a real server is, because an
/// adapter that only meets a tidy one is an adapter that has not been tested:
///
/// - Its `PROPFIND Depth: 1` includes the collection's **own** entry, which every real
///   server does and which makes a walk that does not drop it recurse forever.
/// - Every entry carries a **second `propstat` answering 404** for a property the server
///   does not have. That is normal, and an adapter reading "a non-2xx propstat means skip
///   this entry" loses every file on such a server.
#[test]
fn dav_endpoints_copy_verify_sync_and_delete_over_webdav() {
    let s = Scratch::new("dav");
    let src = fixture(&s);
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    let server = rcp::dav::testserver::Server::start(&root).unwrap();
    let cat = s.path("catalog");
    let dst = server.url("/in");

    // in: the regular files, then read back and compared against the source. The
    // protocol has no symlinks, and the fixture's two are refused BY NAME rather than
    // dropped -- asserted further down, because a copy that quietly skipped them would
    // pass this half.
    let text = assert_passed(&rcp_dav(
        &cat,
        &[
            "copy",
            "-newid",
            "up",
            "-type",
            "f",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    assert!(
        text.contains("copy: 4 files") && text.contains("3 directories"),
        "{text}"
    );
    // `-noattrs`: a WebDAV server carries no modes or owners and its mtime is its own
    // write time, so the comparison this transport can honestly make is the bytes
    assert_passed(&rcp_dav(
        &cat,
        &[
            "verify",
            "-noattrs",
            "-type",
            "f",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    assert_eq!(
        fs::read(root.join("in/message.txt")).unwrap(),
        b"hello from the source\n"
    );
    // THIS BLOCK ASSERTED A DEFECT UNTIL THE `smb://` ADAPTER WAS WRITTEN, and the two
    // lines it replaces are worth stating rather than quietly deleting. They were
    //
    //     let text = assert_failed(&... ["verify", "-nomods", ...], "DIFF mode");
    //     let text = assert_failed(&... ["verify", ...], "DIFF mode");
    //
    // -- a verify against a WebDAV collection reporting four `DIFF mode` rows and failing.
    // `keeps_modes` and `keeps_owner` were added to the port to stop exactly that, and dav
    // overrides both to false. The overrides never ran: `AnyTree`, which every command goes
    // through, delegated `keeps_times` and not its three siblings, so it answered the
    // trait's default `true`. Sixteen overrides across eight adapters had never been read.
    // The arm here was written against what the tool did, so it FROZE the defect in place
    // and went green on it for as long as it existed.
    //
    // What a correct run looks like now: the whole verify PASSES -- the copy above really
    // is complete -- and each comparison it could not make says so, in prose and in
    // `skipped`. The mtime one was already right and is unchanged.
    let out = rcp_dav(
        &cat,
        &["verify", "-json", "-type", "f", src.to_str().unwrap(), &dst],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "verify against the collection failed:\n{text}"
    );
    assert!(
        !text.contains("DIFF mode"),
        "verify compared modes against a collection that has none:\n{text}"
    );
    assert!(
        !text.contains("DIFF mtime"),
        "verify compared mtimes against a server that keeps its own:\n{text}"
    );
    for what in [
        "modes were not compared",
        "owners were not compared",
        "modification times were not compared",
    ] {
        assert!(
            text.contains(what),
            "the skipped comparison {what:?} is not reported:\n{text}"
        );
    }
    // THE CONTROL, without which the three assertions above would also pass if `verify`
    // had simply stopped checking modes everywhere: against a LOCAL destination, which
    // does keep them, the same check on the same source still reports the difference and
    // still fails. The check was NARROWED by the transport, not switched off.
    let modes_control = s.path("keeps-modes");
    assert_passed(&rcp_dav(
        &cat,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            src.to_str().unwrap(),
            modes_control.to_str().unwrap(),
        ],
    ));
    fs::set_permissions(
        modes_control.join("script.sh"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let text = assert_failed(
        &rcp_dav(
            &cat,
            &[
                "verify",
                "-type",
                "f",
                src.to_str().unwrap(),
                modes_control.to_str().unwrap(),
            ],
        ),
        "DIFF mode",
    );
    assert!(
        text.contains("script.sh: source 0755"),
        "the mode difference is not reported against the file that has it:\n{text}"
    );
    // and said in a field an automated caller can branch on. The English warning is not
    // one: with `differences` counting only what WAS compared, a caller reading the JSON
    // concluded the mtimes matched when they had never been looked at. `-mtimewindow` is
    // passed here too, because on this destination it tunes a comparison that does not
    // happen -- a silent no-op until the warning named it.
    // (read straight off the Output: with `-json` the last line is the `done` event, not
    // the `STATUS:` line `assert_failed` requires)
    let out = rcp_dav(
        &cat,
        &[
            "verify",
            "-json",
            "-mtimewindow",
            "5",
            "-type",
            "f",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    let text = stdout(&out);
    // The run PASSES now, where it used to fail on the invented modes; `skipped` names all
    // four checks this transport cannot make rather than only the mtime one.
    assert!(
        out.status.success(),
        "verify against the collection failed:\n{text}"
    );
    for token in ["mode", "owner", "xattr", "mtime"] {
        assert!(
            text.contains(&format!("\"{token}\"")),
            "the skipped list does not name {token}:\n{text}"
        );
    }
    assert!(
        text.contains("-mtimewindow tunes that comparison"),
        "the window was accepted and silently unused:\n{text}"
    );
    // the control: against a destination that DOES keep times, the same field is present
    // and empty, so a caller can tell "nothing skipped" from "too old to say"
    let local = s.path("keeps-times");
    assert_passed(&rcp_dav(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            local.to_str().unwrap(),
        ],
    ));
    let out = rcp_dav(
        &cat,
        &[
            "verify",
            "-json",
            "-type",
            "f",
            src.to_str().unwrap(),
            local.to_str().unwrap(),
        ],
    );
    let text = stdout(&out);
    assert!(out.status.success(), "the control verify failed:\n{text}");
    assert!(
        text.contains(r#""skipped":[]"#),
        "a destination that keeps everything still reported a skip:\n{text}"
    );
    let text = assert_failed(
        &rcp_dav(
            &cat,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                &server.url("/with-links"),
            ],
        ),
        "WebDAV has no symlinks",
    );
    assert!(
        text.contains("symlink dangling"),
        "the refusal does not name the link:\n{text}"
    );

    // out: the same tree back to a local directory, and the bytes match
    let back = s.path("back");
    assert_passed(&rcp_dav(
        &cat,
        &["copy", "-noId", &dst, back.to_str().unwrap()],
    ));
    assert_passed(&rcp_dav(
        &cat,
        &[
            "verify",
            "-noattrs",
            "-type",
            "f",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read(back.join("nested/deeper/data.bin")).unwrap(),
        fs::read(src.join("nested/deeper/data.bin")).unwrap()
    );

    // a listing over the wire sees what the server holds, and does not see the collection
    // inside itself -- which is what an undropped self-entry looks like from here
    let text = assert_passed(&rcp_dav(&cat, &["scan", "-noId", &dst]));
    assert!(
        !text.contains("in/in"),
        "the collection is listed inside itself:\n{text}"
    );

    // sync: one changed file crosses, and the rest do not
    write(&src.join("message.txt"), b"changed on the source\n", 0o644);
    // Only one file crosses. This is the arm for `keeps_times`: a WebDAV server's mtime is
    // its own write time, and before the planner knew that, every file on the destination
    // read as changed and sync copied the whole tree for one edit -- measured as two files
    // crossing here rather than one, and it would have been four on a slower server.
    let text = assert_passed(&rcp_dav(&cat, &["sync", "-id", "up", "-type", "f"]));
    assert!(
        text.contains("sync: 1 files") && text.contains("3 skipped"),
        "sync did not move exactly the one changed file:\n{text}"
    );
    assert_eq!(
        fs::read(root.join("in/message.txt")).unwrap(),
        b"changed on the source\n"
    );
    // `-dryrun -target` checks the destination against the index, and it compared mtimes
    // without asking whether the destination keeps one -- so after a clean copy every
    // file read as "changed since the copy".
    let text = assert_passed(&rcp_dav(
        &cat,
        &["sync", "-id", "up", "-dryrun", "-target", "-type", "f"],
    ));
    assert!(
        !text.contains("changed since the copy"),
        "-target read a WebDAV mtime as a change:\n{text}"
    );

    // delete, and the server really no longer has it
    assert_passed(&rcp_dav(&cat, &["delete", "-force", "-removetopdir", &dst]));
    assert!(
        !root.join("in").exists(),
        "the collection is still there after delete"
    );
}

/// The two server shapes that separate a correct adapter from one that passed by luck.
#[test]
fn a_dav_walk_terminates_wherever_the_server_puts_the_collections_own_entry() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-self");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in/sub")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    write(&root.join("in/sub/b.txt"), b"b\n", 0o644);
    let cat = s.path("catalog");

    // A server that puts its own entry LAST. An adapter dropping the self-entry by
    // position rather than by path reads the collection as a child of itself here, and
    // the walk does not terminate. Its control is the same tree from the default server,
    // which puts the entry first: both must see exactly the same four entries.
    let mut seen = Vec::new();
    for quirks in [
        Quirks::default(),
        Quirks {
            self_last: true,
            ..Quirks::default()
        },
    ] {
        let server = Server::start_with(&root, quirks).unwrap();
        let out = rcp_dav(&cat, &["scan", "-noId", &server.url("/in")]);
        let text = assert_passed(&out);
        // `N directories, M files, ...`: both numbers, because an undropped self-entry
        // shows up as an extra directory, not as an extra file
        let summary = text
            .lines()
            .find(|l| l.contains(" directories, ") && l.contains(" files, "))
            .unwrap_or_else(|| panic!("no scan summary:\n{text}"));
        let toks: Vec<&str> = summary.split_whitespace().collect();
        let count = |word: &str| -> usize {
            toks.iter()
                .position(|t| t.trim_end_matches(',') == word)
                .and_then(|i| toks[i - 1].parse().ok())
                .unwrap()
        };
        seen.push((count("directories"), count("files")));
    }
    assert_eq!(seen[0], seen[1], "the walk saw a different tree depending on where the server put the collection's own entry");
    assert_eq!(
        seen[0],
        (2, 2),
        "the fixture is two directories and two files; anything else means the walk drifted"
    );
}

/// A server that ignores `Range` hands back the whole file, so every byte from `pos` on is
/// really a byte from zero -- the head of the file written at its tail. The registry client
/// learned this the expensive way; this arm is the WebDAV one, refusing before a byte is
/// placed rather than after.
#[test]
fn a_dav_server_that_ignores_range_is_refused_rather_than_mis_assembled() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-range");
    let root = s.path("dav-root");
    fs::create_dir_all(&root).unwrap();
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("big.bin"), &body).unwrap();
    let cat = s.path("catalog");

    // The control first, and it is what makes this a measurement: an honest server serves
    // a ranged read, the counter proves a Range was asked for, and the bytes come back
    // whole. Without it the arm below would pass against a client that never seeks.
    // `diag nio -sequential -read` writes a file and reads it back block by block, and
    // its first read is block 1, so a nonzero offset -- a `Range` -- is guaranteed rather
    // than probable.
    let nio = |url: &str| -> Output {
        rcp_dav(
            &cat,
            &[
                "diag",
                "nio",
                "-t",
                "1",
                "-parallel",
                "1",
                "-npend",
                "1",
                "-size",
                "256k",
                "-bs",
                "64k",
                "-sequential",
                "-read",
                url,
            ],
        )
    };
    let server = Server::start(&root).unwrap();
    assert_passed(&nio(&server.url("/")));
    assert!(
        server.ranges.load(Ordering::SeqCst) > 0,
        "no Range was asked for, so this arm measures nothing"
    );

    // and the dishonest one is refused, by name, saying what it asked for
    let liar = Server::start_with(
        &root,
        Quirks {
            ignore_range: true,
            ..Quirks::default()
        },
    )
    .unwrap();
    let out = nio(&liar.url("/"));
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a server that ignored Range was not refused:\n{text}"
    );
    assert!(
        text.contains("does not honor Range"),
        "the refusal does not say why:\n{text}"
    );
    assert!(
        liar.ranges.load(Ordering::SeqCst) > 0,
        "the liar was never asked for a Range"
    );
}

/// Credentials belong in an option or the environment, never in an endpoint that lands in
/// the job log, a report and `ps`. And a server that asks for them gets them.
#[test]
fn dav_credentials_come_from_the_option_and_never_from_the_url() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-auth");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    let cat = s.path("catalog");
    let server = Server::start_with(
        &root,
        Quirks {
            require: Some("operator:s3cret"),
            ..Quirks::default()
        },
    )
    .unwrap();
    let url = server.url("/in");

    // no credential: refused by the server, and the refusal reaches the operator
    let out = rcp_dav(&cat, &["scan", "-noId", &url]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success() && text.contains("401"),
        "an unauthenticated scan was not refused:\n{text}"
    );

    // with it, through the option
    assert_passed(&rcp_dav(
        &cat,
        &["scan", "-noId", "-dav.user", "operator:s3cret", &url],
    ));
    // and through the environment, which is how a railed MCP child gets it
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("NO_PROXY", "*")
        .env("RCP_DAV_USER", "operator")
        .env("RCP_DAV_PASSWORD", "s3cret")
        .arg("-catalog")
        .arg(&cat)
        .args(["scan", "-noId", &url])
        .output()
        .expect("rcp runs");
    assert_passed(&out);

    // A credential written into the URL is refused rather than quietly stripped: stripping
    // would leave an operator believing it had been sent.
    let with_creds = url.replace("dav://", "dav://operator:s3cret@");
    let out = rcp_dav(&cat, &["scan", "-noId", &with_creds]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        text.contains("-dav.user"),
        "a URL carrying credentials must be refused and say where they go:\n{text}"
    );
    // and the refusal must not REPEAT the credential. This arm passed for four rounds
    // while the message quoted the whole URL back, because it only asked whether
    // `-dav.user` was named. The rule's own stated reason is that the endpoint reaches the
    // job log, a report and `ps` -- so a refusal that prints it writes the password into
    // the job log on the one path that exists to keep it out.
    assert!(
        !text.contains("s3cret"),
        "the refusal repeated the password it was refusing:\n{text}"
    );
}

/// A length the reader cannot get is not a length of zero.
///
/// `getcontentlength` was read with `unwrap_or(0)`, and a missing property left
/// `Entry.size` at its default 0. Zero is not a missing value -- it is a positive claim
/// that the file is empty, and every later stage believes it: `open()` takes the size
/// verbatim, the reader returns EOF before the first byte, and `DavSink::finish` compares
/// 0 written against 0 expected and agrees. Measured before the fix: `scan` over a tree
/// whose files really hold bytes reported them as `0 bytes` and `STATUS: PASSED`.
///
/// Twelve lines below that `unwrap_or`, `getlastmodified` does the opposite and says why:
/// a date it cannot read is no date. This brings the length into line.
#[test]
fn a_file_whose_length_the_server_did_not_give_is_refused_rather_than_read_as_empty() {
    use rcp::dav::testserver::{ContentLength, Quirks, Server};
    let s = Scratch::new("dav-len");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    write(&root.join("in/real.txt"), &vec![b'x'; 370], 0o644);

    for (label, quirk) in [
        ("omitted", ContentLength::Omitted),
        ("unparseable", ContentLength::Unparseable),
    ] {
        let server = Server::start_with(
            &root,
            Quirks {
                content_length: quirk,
                ..Quirks::default()
            },
        )
        .unwrap();
        let url = server.url("/in");
        let cat = s.path(&format!("cat-{label}"));

        // scan is the cheapest place the old behavior showed: it counted the bytes
        let out = rcp_dav(&cat, &["scan", "-noId", &url]);
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(
            !out.status.success(),
            "{label}: a tree with an unknown file length scanned clean:\n{text}"
        );
        assert!(
            text.contains("no readable getcontentlength"),
            "{label}: the refusal does not say what is missing:\n{text}"
        );
        assert!(
            !text.contains("370 bytes"),
            "{label}: the stand-in leaked the real length into the listing:\n{text}"
        );

        // and the copy does not write an empty file and call it done
        let dst = s.path(&format!("out-{label}"));
        let out = rcp_dav(
            &s.path(&format!("cat2-{label}")),
            &["copy", "-noId", &url, dst.to_str().unwrap()],
        );
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(
            !out.status.success(),
            "{label}: the copy reported success:\n{text}"
        );
        assert_eq!(
            fs::metadata(dst.join("real.txt"))
                .map(|m| m.len())
                .unwrap_or(0),
            0,
            "{label}: bytes were written for a file of unknown length"
        );
    }

    // THE CONTROL: the same file, the same server, a real length. Without it the arm
    // would pass against a reader that refused every WebDAV file there is -- and the
    // control has to check the BYTES, because a copy that reported success while writing
    // nothing is the whole defect.
    let server = Server::start(&root).unwrap();
    let dst = s.path("out-ok");
    assert_passed(&rcp_dav(
        &s.path("cat-ok"),
        &["copy", "-noId", &server.url("/in"), dst.to_str().unwrap()],
    ));
    assert_eq!(
        fs::metadata(dst.join("real.txt")).unwrap().len(),
        370,
        "a conformant server's file did not copy whole"
    );
}

/// `rewrites_metadata_in_place` had one consumer, and `diag change` was not it.
///
/// Measured before the fix, against a WebDAV collection -- where `set_metadata` returns
/// `Ok` without issuing a request, because there is no request it could issue: `chmod`
/// was refused by name, and `diag change -mtime` on the SAME tree two commands later
/// reported `3 entries changed` and `STATUS: PASSED`. The guard now sits inside
/// `apply_tree_depth`, which is the gate both callers go through.
///
/// The arm runs both commands against one server so the contradiction is the thing
/// asserted, rather than two separate claims that happen to agree.
#[test]
fn diag_change_is_refused_wherever_chmod_is_refused() {
    let s = Scratch::new("dav-diagchange");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    let server = rcp::dav::testserver::Server::start(&root).unwrap();
    let url = server.url("/in");
    let cat = s.path("catalog");
    let needle = "cannot change modes, owners or times once written";

    assert_failed(&rcp_dav(&cat, &["chmod", "-mode", "755", &url]), needle);
    assert_failed(
        &rcp_dav(
            &cat,
            &["diag", "change", "-mtime", "2020-01-01T00:00:00", &url],
        ),
        needle,
    );

    // THE CONTROL: a local tree can rewrite metadata, so the same `diag change` really
    // does change it. Without this the guard could be "refuse every diag change" and the
    // two assertions above would still pass.
    let local = s.path("local");
    fs::create_dir_all(&local).unwrap();
    let f = local.join("a.txt");
    write(&f, b"a\n", 0o644);
    let before = fs::metadata(&f).unwrap().modified().unwrap();
    let out = rcp(
        &s.path("cat2"),
        &[
            "diag",
            "change",
            "-mtime",
            "2020-01-01T00:00:00",
            local.to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        out.status.success(),
        "diag change was refused on a tree that can do it:\n{text}"
    );
    assert!(
        !text.contains(needle),
        "the guard fired on a tree that rewrites metadata:\n{text}"
    );
    assert_ne!(
        fs::metadata(&f).unwrap().modified().unwrap(),
        before,
        "diag change reported success and changed no mtime:\n{text}"
    );
}

/// Every regular file under `dir`, at any depth. The arm below measures a DELETION, so it
/// counts what is on disk rather than reading the run's own summary back to itself.
fn count_files(dir: &Path) -> usize {
    let mut n = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                n += 1;
            }
        }
    }
    n
}

/// A credential reaches no file this run writes and no command line it hands out.
///
/// Two sites, one rule, and both had their own hand-kept list of "things that are not
/// secret" -- a deny-list, which fails open on whatever was added last:
///
/// - `rcp job` persisted the raw argv to `<catalog>/jobs/<id>.json`, printed it from five
///   subcommands, and put it on the detached child's `ps` line for the length of the copy.
/// - `forward_args` had no credential names in `LOCAL`, so `-nodes h1,h2` put
///   `-dav.user alice:PASSWORD` on the command line of every host in the fleet.
///
/// Both now ask `describe`'s own table, which already classifies these as
/// `Capability::Credential`, instead of remembering.
#[test]
fn a_credential_reaches_no_file_and_no_remote_command_line() {
    const PW: &str = "NOTAREALPW";
    let s = Scratch::new("cred-sinks");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"a\n", 0o644);
    let cat = s.path("catalog");

    // a detached job, which is the case that writes the argv to disk and keeps it
    let creds = format!("alice:{PW}");
    let out = rcp(
        &cat,
        &[
            "job",
            "start",
            "copy",
            "-noId",
            "-dav.user",
            &creds,
            src.to_str().unwrap(),
            s.path("dst").to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(out.status.success(), "the job did not start:\n{text}");
    assert!(
        !text.contains(PW),
        "starting the job printed the password:\n{text}"
    );
    assert!(text.contains("<redacted>"), "the job line does not show the option at all, so the arm cannot tell redaction from omission:\n{text}");

    // every file under the catalog, at any depth: jobs/<id>.json, jobs.log, index.tsv
    let mut hits = Vec::new();
    let mut stack = vec![cat.clone()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if String::from_utf8_lossy(&fs::read(&p).unwrap_or_default()).contains(PW) {
                hits.push(p);
            }
        }
    }
    assert!(hits.is_empty(), "the password was written into {hits:?}");

    // and `job list`, which reads that file back and prints it to whoever runs it
    let text = stdout(&rcp(&cat, &["job", "list"]));
    assert!(!text.contains(PW), "job list printed the password:\n{text}");

    // A fleet node reached over ssh: refused by name, because ssh carries a command line
    // and every way to put an environment on it ends up on that host's `ps` too.
    let out = rcp(
        &s.path("cat2"),
        &[
            "copy",
            "-noId",
            "-nodes",
            "filer",
            "-dav.user",
            &creds,
            src.to_str().unwrap(),
            s.path("dst2").to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a credential was forwarded to a remote node:\n{text}"
    );
    assert!(
        text.contains("cannot be forwarded to the remote node"),
        "the refusal does not say what is wrong:\n{text}"
    );
    assert!(
        text.contains("RCP_DAV_USER"),
        "the refusal does not name the channel that works:\n{text}"
    );
    assert!(
        !text.contains(PW),
        "the refusal repeated the password:\n{text}"
    );

    // THE CONTROLS. Without them the arm passes against a build that refuses every job and
    // every fleet, which would be a worse tool and a greener suite.
    let out = rcp(
        &s.path("cat3"),
        &[
            "job",
            "start",
            "copy",
            "-noId",
            src.to_str().unwrap(),
            s.path("dst3").to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "a job with no credential was refused:\n{}",
        stdout(&out)
    );
    let out = rcp(
        &s.path("cat4"),
        &[
            "copy",
            "-noId",
            "-nodes",
            "localhost",
            src.to_str().unwrap(),
            s.path("dst4").to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !text.contains("cannot be forwarded"),
        "a fleet with no credential was refused:\n{text}"
    );
}

/// A mirror reads absence as an instruction to delete, so it may only do that from a
/// listing it knows is complete.
///
/// Measured before the fix, against a source whose `sub/` could not be listed: `isync`
/// removed `sub/deep1.txt`, `sub/deep2.txt` and `sub/` itself from the destination -- three
/// files gone because of one directory nobody could read -- and the remedy it printed was
/// `resume`, which re-plans the copy and never plans removals, so nothing could undo it.
/// `scan` over the same source reported `2 files` for a four-file tree and `STATUS: PASSED`.
///
/// Both halves are here because they are the same mistake at two levels: a partial answer
/// presented as a whole one. The counts still print; the verdict says they are partial.
#[test]
fn an_incomplete_source_listing_removes_nothing_and_does_not_report_a_clean_scan() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-partial");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in/sub")).unwrap();
    write(&root.join("in/clean1.txt"), b"one\n", 0o644);
    write(&root.join("in/clean2.txt"), b"two\n", 0o644);
    write(&root.join("in/sub/deep1.txt"), b"three\n", 0o644);
    write(&root.join("in/sub/deep2.txt"), b"four\n", 0o644);

    // the destination already mirrors the source exactly, so every removal the planner
    // could propose is a file the source still holds
    let mirror = s.path("mirror");
    fs::create_dir_all(mirror.join("sub")).unwrap();
    for (p, b) in [
        ("clean1.txt", &b"one\n"[..]),
        ("clean2.txt", b"two\n"),
        ("sub/deep1.txt", b"three\n"),
        ("sub/deep2.txt", b"four\n"),
    ] {
        write(&mirror.join(p), b, 0o644);
    }
    let before = count_files(&mirror);
    assert_eq!(before, 4, "the fixture did not lay down what the arm needs");

    let broken = Server::start_with(
        &root,
        Quirks {
            fail_propfind_under: Some("/sub"),
            ..Quirks::default()
        },
    )
    .unwrap();
    let url = broken.url("/in");

    // scan: the counts print, and the verdict does not call them complete
    let out = rcp_dav(&s.path("cat-scan"), &["scan", "-noId", &url]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a scan that could not read a directory reported success:\n{text}"
    );
    assert!(
        text.contains("could not be read"),
        "the scan does not say why it is short:\n{text}"
    );
    assert!(
        text.contains("2 files"),
        "the partial counts were withheld as well as the verdict:\n{text}"
    );

    // isync: nothing is removed, and the run says that is why
    let out = rcp_dav(
        &s.path("cat-isync"),
        &["isync", "-noId", &url, mirror.to_str().unwrap()],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "an isync from an incomplete listing reported success:\n{text}"
    );
    assert!(
        text.contains("0 removed"),
        "the mirror was swept from a listing that had errors:\n{text}"
    );
    assert!(
        text.contains("no removals were planned"),
        "the run does not say it withheld the removals:\n{text}"
    );
    assert_eq!(
        count_files(&mirror),
        before,
        "an incomplete source listing deleted destination files"
    );

    // THE CONTROL, and it is the half that says the gate is about the ERRORS rather than
    // about `isync`: the same server without the quirk, and the same mirror with one extra
    // file, really does remove it. Without this the gate could be "never remove anything"
    // and every assertion above would still pass.
    let healthy = Server::start(&root).unwrap();
    write(&mirror.join("stale.txt"), b"not in the source\n", 0o644);
    let out = rcp_dav(
        &s.path("cat-control"),
        &[
            "isync",
            "-noId",
            &healthy.url("/in"),
            mirror.to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        text.contains("1 removed"),
        "a complete listing did not sweep the mirror:\n{text}"
    );
    assert!(
        !mirror.join("stale.txt").exists(),
        "the stale file survived a healthy isync:\n{text}"
    );
    assert_eq!(
        count_files(&mirror),
        before,
        "the control removed more than the stale file"
    );
}

/// The same rule one transport over, and here the endpoint really does reach the files.
///
/// `ssh://user:password@host/path` used to parse. rcp runs `ssh` as a child, which takes a
/// key or an agent and has no password argument, so the password was never *used* -- but it
/// was recorded, into `jobs.log` and `index.tsv` under the catalog (both 0644), the `-json`
/// `done.source`, the `-html` title and the child's `ps` line. The four parse-time refusals
/// in that arm each quoted `{text:?}`, so even a rejected endpoint wrote it down.
///
/// So the arm checks the sinks, not just the message: after the run, nothing anywhere under
/// the catalog may contain the password.
#[test]
fn an_ssh_endpoint_carrying_a_password_is_refused_and_the_password_reaches_no_sink() {
    let s = Scratch::new("ssh-pw");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"a\n", 0o644);

    // one literal, so a hit anywhere is unambiguous
    const PW: &str = "NOTAREALPW";

    for (scheme, ep) in [
        ("ssh", format!("ssh://alice:{PW}@198.51.100.7/tmp/x")),
        ("sftp", format!("sftp://alice:{PW}@198.51.100.7/tmp/x")),
        // no path: the "needs an absolute path" refusal fires first in source order and
        // quotes the endpoint, which is why the guard runs before the path split
        ("ssh", format!("ssh://alice:{PW}@198.51.100.7")),
    ] {
        let cat = s.path(&format!("catalog-{scheme}-{}", ep.len()));
        let out = rcp(&cat, &["copy", "-noId", src.to_str().unwrap(), &ep]);
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(!out.status.success(), "{ep} was accepted:\n{text}");
        assert!(
            text.contains("password in the authority"),
            "{ep} was refused for some other reason:\n{text}"
        );
        assert!(
            !text.contains(PW),
            "the refusal of {ep} repeated the password:\n{text}"
        );

        // and the catalog -- jobs.log, index.tsv, anything else the run laid down
        let mut hits = Vec::new();
        let mut stack = vec![cat.clone()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if String::from_utf8_lossy(&fs::read(&p).unwrap_or_default()).contains(PW) {
                    hits.push(p);
                }
            }
        }
        assert!(
            hits.is_empty(),
            "{ep}: the password was written into {hits:?}"
        );
    }

    // The control, and it is the half that says the guard is about passwords rather than
    // about `@`: the same endpoints without one get past this refusal entirely. They still
    // fail, because `RCP_SSH` points at a binary that exits non-zero without dialing -- the
    // failure is a different one, which is the point. (Dialing TEST-NET-2 for real works
    // too and costs a 20 s connect timeout per arm; the stub keeps the arm under a second.)
    for ep in [
        "ssh://alice@198.51.100.7/tmp/x",
        "sftp://alice@198.51.100.7/tmp/x",
    ] {
        let cat = s.path(&format!("control-{}", ep.len()));
        let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_SSH", "/bin/false")
            .arg("-catalog")
            .arg(&cat)
            .args(["scan", "-noId", ep])
            .output()
            .expect("rcp runs");
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(
            !out.status.success(),
            "{ep} reached a host that does not answer:\n{text}"
        );
        assert!(
            !text.contains("password in the authority"),
            "{ep} carries no password and was refused for one:\n{text}"
        );
    }
}

/// A WebDAV server keeps no modes, owners or times this crate can set, so `chmod` and
/// `chown` refuse by name instead of reporting entries they did not change. Same shape as
/// the registry and the tar stream, and it goes through the same predicate.
#[test]
fn a_dav_collection_cannot_be_chmodded_and_says_so() {
    let s = Scratch::new("dav-meta");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    let server = rcp::dav::testserver::Server::start(&root).unwrap();
    let cat = s.path("catalog");
    let url = server.url("/in");
    let before = fs::metadata(root.join("in/a.txt")).unwrap().permissions();

    assert_failed(
        &rcp_dav(&cat, &["chmod", "-mode", "755", &url]),
        "cannot change modes, owners or times once written",
    );
    assert_failed(
        &rcp_dav(&cat, &["chown", "-user", "root", &url]),
        "cannot change modes, owners or times once written",
    );
    assert_eq!(
        fs::metadata(root.join("in/a.txt")).unwrap().permissions(),
        before,
        "a refused chmod still changed something"
    );

    // the control: the refusal is about the transport, not about the command, so the same
    // chmod on a local directory still works
    let local = s.path("local");
    fs::create_dir_all(&local).unwrap();
    write(&local.join("a.txt"), b"a\n", 0o644);
    assert_passed(&rcp_dav(
        &cat,
        &[
            "chmod",
            "-mode",
            "755",
            "-type",
            "f",
            local.to_str().unwrap(),
        ],
    ));
}

/// `diag -rmdir` and `diag -rmrf` must not throw the third answer away: `|_|` on the result
/// of `remove` makes a store that KEPT the entry print "removed", and the two diag arms are
/// easy to miss when the port changes under them. A locked WebDAV collection is the case
/// that reaches it from the command line.
#[test]
fn diag_rmdir_and_rmrf_say_kept_when_the_store_kept_it() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-locked");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in/sub")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    let cat = s.path("catalog");
    let locked = Server::start_with(
        &root,
        Quirks {
            locked: true,
            ..Quirks::default()
        },
    )
    .unwrap();

    let out = rcp_dav(&cat, &["diag", "-rmdir", &locked.url("/in/sub")]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a kept collection was reported removed:\n{text}"
    );
    assert!(
        text.contains("not removed") && text.contains("locked"),
        "the refusal does not say the store kept it:\n{text}"
    );
    assert!(
        root.join("in/sub").exists(),
        "the stand-in removed a collection it said was locked"
    );

    let out = rcp_dav(&cat, &["diag", "-rmrf", &locked.url("/in")]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        text.contains("kept") && text.contains("KEPT:"),
        "rmrf did not report what the store kept:\n{text}"
    );
    assert!(
        !text.contains("1 files, 0 symlinks, 1 directories removed"),
        "rmrf counted kept entries as removed:\n{text}"
    );
    assert!(
        !out.status.success(),
        "-rmrf passed with entries the store refused still there:\n{text}"
    );
    // and with -json the kept entries are EVENTS, not only lines: a caller reading the
    // stream would otherwise see a clean removal that the text output contradicts
    let out = rcp_dav(&cat, &["diag", "-json", "-rmrf", &locked.url("/in")]);
    let text = stdout(&out);
    assert!(
        text.lines().any(|l| l.starts_with("{\"event\":\"kept\"")),
        "no kept event in the json stream:\n{text}"
    );

    // the control: the same two commands against an honest server remove, and say so
    let honest = Server::start(&root).unwrap();
    let text =
        String::from_utf8_lossy(&rcp_dav(&cat, &["diag", "-rmdir", &honest.url("/in/sub")]).stderr)
            .to_string();
    assert!(
        text.contains("removed") && !text.contains("not removed"),
        "{text}"
    );
    assert!(!root.join("in/sub").exists());
}

/// A resume budget that scales with blob size fails on arithmetic: frozen at 4096 above
/// 4 MiB, a 10 MiB layer over the SAME link the suite already models as "many resumes
/// finish" -- 2 KiB delivered per cut -- needs 5120 resumes and is refused while every
/// resume is delivering. That takes no multi-gigabyte fixture to reach. So the bound is on
/// resumes that do NOT deliver (under 1 KiB, sixty-four in a row), which is
/// size-independent; the dribbling server a size ceiling would be for is the control.
#[test]
fn a_link_that_keeps_delivering_is_never_refused_however_large_the_blob() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("oci-big-resume");
    let layout = s.path("layout");
    let blobs = layout.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let put = |data: &[u8]| -> (String, usize) {
        let h = rcp::sha256::digest_hex(data);
        fs::write(blobs.join(&h), data).unwrap();
        (h, data.len())
    };
    // 10 MiB: 5120 cuts at 2 KiB, comfortably past the old ceiling of 4096
    let big: Vec<u8> = (0..10u32 << 20)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 253) as u8)
        .collect();
    let (lay, lay_n) = put(&big);
    let (cfg, cfg_n) =
        put(br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#);
    let mt = "application/vnd.oci.image.manifest.v1+json";
    let (m, m_n) = put(format!(r#"{{"schemaVersion":2,"mediaType":"{mt}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{cfg}","size":{cfg_n}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{lay}","size":{lay_n}}}]}}"#).as_bytes());
    fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(layout.join("index.json"), format!(r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"{mt}","digest":"sha256:{m}","size":{m_n},"annotations":{{"org.opencontainers.image.ref.name":"v1"}}}}]}}"#)).unwrap();
    let cat = s.path("catalog");

    let reg = Registry::start(&[
        "--cut",
        "2048",
        "--always",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &reg.url("app"),
            back.to_str().unwrap(),
        ],
    ));
    assert!(reg.stat("cuts") > 4096, "the stand-in cut only {} times, so the old ceiling was never reached and this arm proves nothing", reg.stat("cuts"));
    assert_eq!(
        fs::read(back.join("blobs/sha256").join(&lay)).unwrap(),
        big,
        "the layer came back wrong across thousands of resumes"
    );

    // the control: a server that delivers 64 bytes per cut is still refused, so the bound
    // did not simply go away
    let dribble = Registry::start(&[
        "--cut",
        "64",
        "--always",
        "--seed",
        "app",
        layout.to_str().unwrap(),
    ]);
    let out = assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-oci.insecure",
                &dribble.url("app"),
                s.path("dribble").to_str().unwrap(),
            ],
        ),
        "is not delivering this blob",
    );
    assert!(out.contains("cut the stream"), "{out}");
}

/// RFC 4918 lets a collection DELETE answer 207 with a status per member. `200..=299`
/// swallowed it, so a collection the server only half removed was counted gone.
#[test]
fn a_dav_collection_the_server_only_half_removed_is_kept_not_gone() {
    use rcp::dav::testserver::{Quirks, Server};
    let s = Scratch::new("dav-207");
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    write(&root.join("in/a.txt"), b"a\n", 0o644);
    let cat = s.path("catalog");
    let partial = Server::start_with(
        &root,
        Quirks {
            partial_delete: true,
            ..Quirks::default()
        },
    )
    .unwrap();
    // FAILED, not passed: a member the server refused is still there, and a delete that
    // leaves what it was asked to remove has not done what it was asked. It is tempting to
    // say "kept is not a failure"; ask what a caller reading only the exit code concludes
    // -- see `Removed` in ports.rs.
    let text = assert_failed(
        &rcp_dav(
            &cat,
            &["delete", "-force", "-removetopdir", &partial.url("/in")],
        ),
        "refused by the store are still there",
    );
    assert!(
        text.contains("1 kept") && text.contains("KEPT:") && text.contains("kept 1 member"),
        "a 207 was counted as a removal:\n{text}"
    );
    assert!(
        root.join("in").exists(),
        "the stand-in removed what it reported keeping"
    );
    // A plain 403: the server replied and refused, which is the same KIND of answer as
    // the 423 above and must not land in the failure bucket. `or_refused` does that sorting,
    // and it has to be wired into every adapter that can hear it -- WebDAV, the adapter the
    // whole idea came from, as well as WebHDFS and the registry. The remedy printed is the
    // point: a failure says to use `resume`, and `resume` never plans removals.
    let forbidden = Server::start_with(
        &root,
        Quirks {
            forbid_delete: true,
            ..Quirks::default()
        },
    )
    .unwrap();
    let text = assert_failed(
        &rcp_dav(
            &cat,
            &["delete", "-force", "-removetopdir", &forbidden.url("/in")],
        ),
        "refused by the store are still there",
    );
    assert!(
        text.contains("KEPT:"),
        "a 403 to a DELETE was reported as a failure of the run:\n{text}"
    );
    assert!(
        !text.contains("use resume"),
        "a refusal pointed at resume, which never plans removals:\n{text}"
    );
    assert!(
        root.join("in").exists(),
        "the stand-in removed what it reported keeping"
    );

    // A 401 is NOT the 403 above, and teaching this adapter to call a 403 `Kept` easily
    // sweeps the 401 in with it, because `kind_of_status` calls both `PermissionDenied` and
    // `or_refused` keyed on exactly that kind. `Kept` prints "run `sync` again once the
    // entry can go"; no number of reruns fixes a credential the server will not accept, and
    // every later removal in the same run answers the same way. It is a failure of the run.
    let unauth = Server::start_with(
        &root,
        Quirks {
            unauthorized_delete: true,
            ..Quirks::default()
        },
    )
    .unwrap();
    let text = assert_failed(
        &rcp_dav(
            &cat,
            &["delete", "-force", "-removetopdir", &unauth.url("/in")],
        ),
        "credentials",
    );
    assert!(
        !text.contains("KEPT:"),
        "a 401 was reported as the store keeping the entry, whose remedy is to rerun:\n{text}"
    );
    assert!(
        root.join("in").exists(),
        "the stand-in removed what it refused"
    );

    // the control: the honest server answers 204 and the collection is gone
    let honest = Server::start(&root).unwrap();
    let text = assert_passed(&rcp_dav(
        &cat,
        &["delete", "-force", "-removetopdir", &honest.url("/in")],
    ));
    assert!(!text.contains("kept"), "{text}");
    assert!(!root.join("in").exists());
}

/// An S3-compatible service that answers a ranged GET with 206 and the whole object from
/// zero is refused before a byte is placed, as the registry and WebDAV readers do. An S3
/// reader that accepts any 2xx after a seek is the one HTTP transport where that claim
/// would not hold.
#[test]
fn an_s3_service_that_lies_about_ranges_is_refused_before_a_byte_is_placed() {
    let s = Scratch::new("s3-range");
    let server = rcp::s3::testserver::Server::start(&["rng"], s3_creds());
    let secret = server.creds.secret_key.clone();
    let cat = s.path("catalog");
    let nio = |url: &str| -> Output {
        rcp_s3(
            &cat,
            &server,
            &secret,
            &[
                "diag",
                "nio",
                "-t",
                "1",
                "-parallel",
                "1",
                "-npend",
                "1",
                "-size",
                "256k",
                "-bs",
                "64k",
                "-sequential",
                "-read",
                url,
            ],
        )
    };
    // the control first: the honest service serves the ranges and the read passes
    assert_passed(&nio("s3://rng/nio"));
    server.lie_about_ranges();
    let out = nio("s3://rng/nio");
    let text = stdout(&out);
    assert!(
        !out.status.success(),
        "a 206 from zero was read as bytes from the offset:\n{text}"
    );
    assert!(
        text.contains("206 starts at 0"),
        "the refusal does not say what the service did:\n{text}"
    );
}

/// `Removed` advertised three outcomes and `remove` had four: only WebDAV (423, a 207 with
/// a refused member) and HDFS (a namenode's `false`) ever answered `Kept`, because those
/// two report a refusal INSIDE a successful response. A bucket policy that allows writes
/// and not deletes answers 403, which is the same event -- the store answered and said no
/// -- and it became a failure in the run instead.
///
/// Both still fail the run, so this is not about the exit code. It is about the REMEDY
/// printed beside it: a failure says to use `resume`, and `resume` never plans removals,
/// so that advice could not work however many times it was followed.
///
/// Measured against a server rather than with `chmod`, deliberately: the suite runs as
/// root here, `unlink` inside a mode-500 directory SUCCEEDS, and a permission arm built
/// that way would pass without ever reaching the code it claims to test.
#[test]
fn a_store_that_refuses_a_delete_is_kept_and_not_a_failure_of_the_run() {
    let s = Scratch::new("s3-refuse");
    let server = rcp::s3::testserver::Server::start(&["keep"], s3_creds());
    let secret = server.creds.secret_key.clone();
    let cat = s.path("catalog");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("f.txt"), b"one\n", 0o644);
    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["copy", "-noId", src.to_str().unwrap(), "s3://keep/in"],
    ));

    // the control FIRST, so the arm below is not passing against a service that refuses
    // everything: this policy deletes, and the delete is clean and says nothing about kept
    let text = assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["delete", "-force", "-removetopdir", "s3://keep/in"],
    ));
    assert!(
        !text.contains("kept") && !text.contains("KEPT"),
        "a clean delete reported a refusal:\n{text}"
    );

    assert_passed(&rcp_s3(
        &cat,
        &server,
        &secret,
        &["copy", "-noId", src.to_str().unwrap(), "s3://keep/in2"],
    ));
    server.refuse_deletes();
    let text = assert_failed(
        &rcp_s3(
            &cat,
            &server,
            &secret,
            &["delete", "-force", "-removetopdir", "s3://keep/in2"],
        ),
        "refused by the store are still there",
    );
    assert!(
        text.contains("KEPT:"),
        "the 403 was reported as a failure rather than a refusal:\n{text}"
    );
    assert!(
        !text.contains("use resume"),
        "a refusal pointed at resume, which never plans removals:\n{text}"
    );
    // and the object really is still there, which is what `Kept` asserts about the world
    assert!(
        !server.keys("keep").is_empty(),
        "the service kept nothing but rcp reported it kept"
    );
}

/// `ssh://[::1]:2222/x`: the host ssh is handed is `::1` and the port is `-p 2222`. The
/// endpoint parser stored `[::1]:2222` whole as the host with no port, and the transport
/// dialed a name that resolves nowhere. Measured through the stub, which logs its argv.
#[test]
fn an_ipv6_ssh_endpoint_hands_ssh_the_bare_address_and_the_port() {
    let s = Scratch::new("ssh-v6");
    let (stub, log) = serve_stub(&s);
    let dir = s.path("served");
    fs::create_dir_all(&dir).unwrap();
    write(&dir.join("f"), b"x", 0o644);
    let cat = s.path("catalog");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "scan",
            "-noId",
            &format!("ssh://alice@[::1]:2222{}", dir.display()),
        ],
    ));
    let argv = fs::read_to_string(&log).unwrap();
    assert!(
        argv.contains("-p 2222"),
        "the port did not reach ssh: {argv}"
    );
    assert!(
        argv.contains("alice@::1 ") || argv.contains("alice@::1\n"),
        "the host ssh was given is not the bare address: {argv}"
    );
    assert!(!argv.contains("[::1]"), "the brackets reached ssh: {argv}");
}

/// Through a hop, `tar://` still takes its files one at a time. `writes_in_one_stream`
/// was not carried in HELLO, so `-parallel 4` into a tar behind the relay interleaved
/// four members and produced an archive tar could not read past the first.
#[test]
fn a_tar_behind_the_hop_is_still_written_one_file_at_a_time() {
    let s = Scratch::new("relay-tar");
    let (stub, _log) = serve_stub(&s);
    let cat = s.path("catalog");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    for i in 0..8 {
        write(
            &src.join(format!("f{i}.bin")),
            &noise(300_000 + i * 1000, i as u64),
            0o644,
        );
    }
    let archive = s.path("out.tar");
    let relayed = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_SSH", &stub)
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .expect("rcp runs")
    };
    let text = assert_passed(&relayed(&[
        "copy",
        "-noId",
        "-parallel",
        "4",
        "-via",
        "ssh://hop",
        src.to_str().unwrap(),
        &format!("tar://{}", archive.display()),
    ]));
    assert!(text.contains("copy: 8 files"), "{text}");
    // the archive reads back whole, through the same hop and directly
    let back = s.path("back");
    assert_passed(&relayed(&[
        "copy",
        "-noId",
        &format!("tar://{}", archive.display()),
        back.to_str().unwrap(),
    ]));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            "-noattrs",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    if Command::new("tar")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let out = Command::new("tar")
            .args(["-tf", archive.to_str().unwrap()])
            .output()
            .unwrap();
        let listed = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && listed.lines().filter(|l| l.ends_with(".bin")).count() == 8,
            "tar does not read the archive whole:\n{listed}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// `sync -dryrun -target` admits a destination mtime truncated to the second, as the
/// planner does; it compared nanoseconds exactly and reported as changed a file a resume
/// would then skip.
#[test]
fn dryrun_target_admits_the_same_mtime_truncation_the_planner_admits() {
    let s = Scratch::new("target-ns");
    let src = s.path("src");
    let dst = s.path("dst");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("a.txt"), b"aaaa", 0o644);
    // a source mtime with nanoseconds, and a destination that holds only the seconds
    let ts = |p: &Path, t: &str| {
        assert!(Command::new("touch")
            .args(["-d", t, p.to_str().unwrap()])
            .status()
            .unwrap()
            .success())
    };
    ts(&src.join("a.txt"), "2020-01-02 03:04:05.123456789");
    let cat = s.path("catalog");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-newid",
            "t",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    ));
    ts(&dst.join("a.txt"), "2020-01-02 03:04:05");
    let text = assert_passed(&rcp(&cat, &["sync", "-id", "t", "-dryrun", "-target"]));
    assert!(
        !text.contains("changed since the copy"),
        "-target reported a truncated mtime as a change:\n{text}"
    );
    // the control: a destination mtime that differs by a whole second IS reported
    ts(&dst.join("a.txt"), "2020-01-02 03:04:07");
    let out = rcp(&cat, &["sync", "-id", "t", "-dryrun", "-target"]);
    assert!(
        stdout(&out).contains("changed since the copy"),
        "a real mtime change was not reported:\n{}",
        stdout(&out)
    );
}

/// What the planner asks a tree -- does it keep times, can its metadata be rewritten --
/// has to be answered by the tree the HOP opened, not by the `SshTree` standing in for
/// it here. If `SshTree` answers the defaults, a `sync` through the hop to a WebDAV
/// collection recopies every file for one edit -- the `keeps_times` bug again, on the
/// relay path. HELLO carries both answers, so `SshTree` needs no override of its own.
#[test]
fn a_relay_carries_what_the_far_tree_answers_the_planner() {
    use rcp::dav::testserver::Server;
    let s = Scratch::new("relay-times");
    let (stub, _log) = serve_stub(&s);
    let src = fixture(&s);
    let root = s.path("dav-root");
    fs::create_dir_all(root.join("in")).unwrap();
    let server = Server::start(&root).unwrap();
    let cat = s.path("catalog");
    let dst = server.url("/in");
    let relayed = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_SSH", &stub)
            .env("NO_PROXY", "*")
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .expect("rcp runs")
    };

    let text = assert_passed(&relayed(&[
        "copy",
        "-newid",
        "up",
        "-type",
        "f",
        "-via",
        "ssh://hop",
        src.to_str().unwrap(),
        &dst,
    ]));
    assert!(text.contains("copy: 4 files"), "{text}");
    write(&src.join("message.txt"), b"changed on the source\n", 0o644);
    // the arm: exactly one file crosses through the hop, as it does direct
    let text = assert_passed(&relayed(&[
        "sync",
        "-id",
        "up",
        "-type",
        "f",
        "-via",
        "ssh://hop",
    ]));
    assert!(
        text.contains("sync: 1 files") && text.contains("3 skipped"),
        "a sync through the hop did not move exactly the one changed file:\n{text}"
    );
    // and a chmod through the hop is refused by name, as it is direct, rather than
    // accepted and silently not done
    assert_failed(
        &relayed(&["chmod", "-mode", "755", "-via", "ssh://hop", &dst]),
        "cannot change modes, owners or times once written",
    );
    // the control: the same chmod through the hop to a LOCAL directory is allowed, so the
    // refusal above is the far tree's answer and not the relay refusing chmod
    let local = s.path("local");
    fs::create_dir_all(&local).unwrap();
    write(&local.join("f"), b"x", 0o644);
    assert_passed(&relayed(&[
        "chmod",
        "-mode",
        "755",
        &format!("ssh://hop{}", local.display()),
    ]));
}

/// A channel that joins a relayed registry after the run removed its last tag.
#[test]
fn a_channel_that_joins_after_the_last_tag_went_still_opens() {
    // In CI a relayed delete failed now and then with "the repository has no tags": one
    // worker deleted the tagged manifests while another worker's channel was still coming
    // up, and that channel's serve re-ran the open's "is there an image here" check. It
    // never failed unloaded (40 of 40 passed), so the order is forced here instead of
    // hoped for: the tags go first, a reader then holds the only channel, and the next
    // request has to dial a second one into a repository with no tags.
    use rcp::anytree::{AnyTree, Transports};
    use rcp::ports::Tree;
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("relay-late-join");
    let log = s.path("ssh-args.log");
    let stub = s.path("stub-ssh");
    // the hop opens the registry with ITS environment, so the insecure flag is set there
    fs::write(
        &stub,
        format!(
            "#!/bin/sh\necho \"$@\" >> {}\nRCP_OCI_INSECURE=1 NO_PROXY='*' exec {} serve\n",
            log.display(),
            env!("CARGO_BIN_EXE_rcp"),
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    let layout = s.path("layout");
    let digests = oci_layout(&layout);
    let reg = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);

    let mut tr = Transports::from_env(Arc::new(rcp::ports::Silent));
    tr.ssh.ssh = stub.to_string_lossy().into_owned();
    tr.via = Some(rcp::Endpoint::parse("ssh://hop/").unwrap());
    let tree = AnyTree::open(&rcp::Endpoint::parse(&reg.url("app")).unwrap(), false, &tr)
        .expect("the first channel opens a registry that has its tags");
    let blob = |k: &str| format!("blobs/sha256/{}", digests[k]);
    // `latest` names the index and `v1` names m1: deleting both leaves no tag at all
    tree.remove(&blob("index"), rcp::catalog::Kind::File)
        .unwrap();
    tree.remove(&blob("m1"), rcp::catalog::Kind::File).unwrap();
    let held = tree
        .open(&blob("layer1"))
        .expect("a reader takes the only channel");
    // a second channel, dialed now, joins a repository with no tags
    let late = tree.remove(&blob("layer2"), rcp::catalog::Kind::File);
    drop(held);
    let dials = fs::read_to_string(&log).unwrap_or_default().lines().count();
    assert_eq!(dials, 2, "the arm needs exactly one late channel");
    assert!(
        late.is_ok(),
        "the late channel could not join: {:?}",
        late.err()
    );
}

/// A push through a hop into a repository that does not exist yet.
#[test]
fn a_relayed_push_into_a_new_repository_publishes_through_one_serve() {
    // Every worker past the first dials its own channel, and each channel is its own
    // `rcp serve` on the hop that opens the endpoint again. Two defects, both measured
    // here: the later opens went out as "must already exist", so the repository the first
    // channel was building was "no such tag" to the others; and once they could open it,
    // what they were sent stayed in their own staging, which `sync` on the first never
    // published -- a push that passed and a tag that did not exist.
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("relay-push");
    let (stub, log) = serve_stub(&s);
    let layout = s.path("layout");
    oci_layout(&layout);
    let reg = Registry::start(&[]);
    let fresh = reg.url("fresh");
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("RCP_SSH", &stub)
        .env("RCP_OCI_INSECURE", "1")
        .env("NO_PROXY", "*")
        .arg("-catalog")
        .arg(s.path("catalog"))
        .args(["copy", "-parallel", "8", "-via", "ssh://hop"])
        .arg(&layout)
        .arg(&fresh)
        .output()
        .expect("rcp runs");
    assert_passed(&out);
    // Passing is not the claim: the push once passed with every manifest left in the
    // staging of a serve that `sync` never reached. The claim is an image, read back
    // directly, with every blob the layout holds.
    let back = s.path("back");
    assert_passed(&rcp(
        &s.path("catalog-direct"),
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &fresh,
            back.to_str().unwrap(),
        ],
    ));
    let names = |d: &Path| -> std::collections::BTreeSet<String> {
        fs::read_dir(d.join("blobs/sha256"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(
        names(&layout),
        names(&back),
        "the image that went up is not the layout"
    );
    // and it went up through one serve, the one whose `sync` publishes it
    let dials = fs::read_to_string(&log).unwrap_or_default().lines().count();
    assert_eq!(
        dials, 1,
        "a registry behind the hop was written through {dials} serves"
    );
}

/// `-via ssh://hop`: the hop's `rcp serve` opens the endpoint and this side speaks to it as
/// it would to a directory there. The stub stands in for ssh and runs a serve locally, so
/// the "hop" is this machine -- which is enough to prove the shape, and it is the same
/// stub every ssh arm uses. The registry stand-in is what the hop reaches.
///
/// The second half needs a serve that can open a registry: a `Kept` from the far side
/// crossing the wire.
#[test]
fn a_relay_opens_the_endpoint_on_the_hop_and_a_kept_crosses_the_wire() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("relay");
    let (stub, _log) = serve_stub(&s);
    let layout = s.path("layout");
    oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);
    let app = reg.url("app");
    // The hop opens the registry with ITS environment, so the insecure flag is in the
    // environment the stub serve inherits, not on this command line.
    let relayed = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_SSH", &stub)
            .env("RCP_OCI_INSECURE", "1")
            .env("NO_PROXY", "*")
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .expect("rcp runs")
    };

    // the same bytes through the hop as direct
    let direct = s.path("direct");
    let via = s.path("via");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &app,
            direct.to_str().unwrap(),
        ],
    ));
    let out = relayed(&[
        "copy",
        "-noId",
        "-loglevel",
        "DEBUG",
        "-via",
        "ssh://hop",
        &app,
        via.to_str().unwrap(),
    ]);
    let text = assert_passed(&out);
    assert!(text.contains("copy: 8 files"), "{text}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("via ssh://hop"),
        "the debug line does not say the endpoint went through the hop"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-nomods",
            direct.to_str().unwrap(),
            via.to_str().unwrap(),
        ],
    ));

    // and a scan through the hop lists what a direct one lists
    let a = assert_passed(&rcp(&cat, &["scan", "-noId", "-oci.insecure", &app]));
    let b = assert_passed(&relayed(&["scan", "-noId", "-via", "ssh://hop", &app]));
    // the counts, not the whole line: it ends in the elapsed time, and under the full
    // suite's load a direct and a relayed scan took different times and this compared
    // them -- green alone, red in the full run, which is the shape a timing leak has
    let count = |t: &str| {
        t.lines()
            .find(|l| l.contains(" files, "))
            .and_then(|l| l.split(';').next())
            .map(str::to_string)
            .unwrap_or_default()
    };
    assert!(!count(&a).is_empty(), "no scan summary:\n{a}");
    assert_eq!(
        count(&a),
        count(&b),
        "a relayed scan differs from a direct one:\n{a}\n---\n{b}"
    );

    // A non-Gone answer crosses the wire: the registry defers its blob deletes on the
    // HOP, and the count arrives here as deferred rather than as removed -- the
    // end-to-end arm the proto round trip in `remote/proto.rs` was standing in for.
    let text = assert_passed(&relayed(&[
        "delete",
        "-force",
        "-removetopdir",
        "-via",
        "ssh://hop",
        &app,
    ]));
    assert!(
        text.contains("3 deferred") && text.contains("garbage collection"),
        "a Deferred on the far side did not arrive as deferred:\n{text}"
    );

    // the control: a hop that cannot reach the endpoint fails, and the failure names both
    // the hop and the endpoint rather than looking like a local error
    let out = relayed(&[
        "scan",
        "-noId",
        "-via",
        "ssh://hop",
        "oci://127.0.0.1:1/app",
    ]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "an unreachable endpoint behind the hop was scanned:\n{text}"
    );
    assert!(
        text.contains("via ssh://hop") && text.contains("127.0.0.1:1"),
        "the failure names neither the hop nor the endpoint:\n{text}"
    );
}

/// A source can name `a/f` without naming `a`: a tar archive may, and so may any listing built
/// from object keys. If nothing makes `a` on the destination, the write resolves it through
/// whatever stands there, and a symlink `a -> elsewhere` puts `f` elsewhere. And because a copy
/// replaces a file standing where the source has a directory, the same shape can REMOVE a file
/// outside the destination: `a/b` resolves to `elsewhere/b`, a file, which is taken to be in the
/// way. Both measured. So the parent is planned like a listed directory: its mkdir replaces the
/// link, and nothing is written through it.
#[test]
fn a_parent_the_source_only_implies_is_made_and_nothing_is_written_through_a_link_there() {
    if !Command::new("tar")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: tar(1) is needed to write an archive without its parent entries");
        return;
    }
    let s = Scratch::new("implied");
    let cat = s.path("catalog");
    let tree = s.path("tree");
    fs::create_dir_all(tree.join("a/b")).unwrap();
    write(&tree.join("a/f"), b"file\n", 0o644);
    write(&tree.join("a/b/g"), b"deeper\n", 0o644);
    // `--no-recursion` with the members named: tar(1) stores exactly those and no parent entry
    let archive = |name: &str, members: &[&str]| -> String {
        let path = s.path(name);
        let out = Command::new("tar")
            .arg("cf")
            .arg(&path)
            .arg("--no-recursion")
            .arg("-C")
            .arg(&tree)
            .args(members)
            .output()
            .expect("tar runs");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        format!("tar://{}", path.display())
    };
    // a file whose parent is never named, and a directory whose parent is never named
    for (name, members) in [
        ("file.tar", &["a/f"][..]),
        ("dir.tar", &["a/b", "a/b/g"][..]),
    ] {
        let url = archive(name, members);
        let outside = s.path(&format!("outside-{name}"));
        fs::create_dir_all(&outside).unwrap();
        // what the second archive's `a/b` resolves to through the link: a file it must not remove
        write(&outside.join("b"), b"precious\n", 0o644);
        let dst = s.path(&format!("dst-{name}"));
        fs::create_dir_all(&dst).unwrap();
        symlink(&outside, dst.join("a")).unwrap();

        let text = assert_passed(&rcp(&cat, &["copy", "-noId", &url, dst.to_str().unwrap()]));
        assert_eq!(
            fs::read(outside.join("b")).unwrap(),
            b"precious\n",
            "{name}: a file outside the destination was changed:\n{text}"
        );
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            1,
            "{name}: something was written outside the destination:\n{text}"
        );
        let a = fs::symlink_metadata(dst.join("a")).unwrap();
        assert!(
            a.is_dir(),
            "{name}: the link standing where the source implies a directory was not replaced"
        );
        // and it is not given metadata the source never had: the source has no entry for it,
        // so there is no time to restore, and stamping one would write 1970 on it
        assert!(
            a.modified().unwrap() > SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000),
            "{name}: the implied directory was stamped with a time the source never gave it"
        );
        for m in members {
            assert!(
                fs::symlink_metadata(dst.join(m)).is_ok(),
                "{name}: {m} did not land inside the destination:\n{text}"
            );
        }
        // and a sync from the same archive keeps the parent it implies rather than planning it
        // away as an entry the source does not have
        let plan = assert_passed(&rcp(
            &cat,
            &["isync", "-dryrun", "-l", &url, dst.to_str().unwrap()],
        ));
        // Measured before this change: `# a`, the directory planned as in the way and replaced
        // with its contents. `-` is the removal marker, `#` the replacement one; neither may
        // name the parent the source implies.
        assert!(
            !plan.lines().any(|l| matches!(l.trim_end(), "# a" | "- a")),
            "{name}: a sync plans the implied parent away:\n{plan}"
        );
        let text = assert_passed(&rcp(&cat, &["isync", &url, dst.to_str().unwrap()]));
        assert!(
            fs::symlink_metadata(dst.join("a"))
                .map(|m| m.is_dir())
                .unwrap_or(false),
            "{name}: a sync removed the parent the source implies:\n{text}"
        );
    }
}

/// A repository that changed under the read. On the release runner the relay arm above
/// failed its `delete` with `manifest sha256:...: MANIFEST_UNKNOWN`: a relay gives each of
/// its connections its own tree, and one read its image after another had deleted a child
/// manifest but not yet the index that names it. The same state is left behind by a delete
/// that is interrupted between the two -- and then the rerun that should finish the job
/// could not even list the image. The stand-in makes that state directly, rather than
/// hoping a race produces it: 48 runs of the relay arm under load never did.
#[test]
fn an_image_whose_index_names_a_manifest_already_deleted_still_lists_and_deletes() {
    if !Command::new("python3")
        .args(["-c", "import http.server"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the registry stand-in");
        return;
    }
    let s = Scratch::new("vanished");
    let layout = s.path("layout");
    let digests = oci_layout(&layout);
    let cat = s.path("catalog");
    let reg = Registry::start(&["--seed", "app", layout.to_str().unwrap()]);
    let app = reg.url("app");
    // m2 goes; the index tagged `latest` still names it
    reg.control(&format!("vanish/app/sha256:{}", digests["m2"]));

    // the image still lists, the missing manifest in it at the size its index declares
    let listed = assert_passed(&rcp(&cat, &["scan", "-noId", "-l", "-oci.insecure", &app]));
    assert!(
        listed.contains(&digests["m2"]),
        "the manifest the index names is not listed:\n{listed}"
    );

    // a copy fails on that one manifest, and says why, rather than passing without it
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-oci.insecure",
            &app,
            s.path("copy").to_str().unwrap(),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "an image missing a manifest copied cleanly:\n{text}"
    );
    assert!(
        text.contains(&digests["m2"]) && text.contains("does not hold it"),
        "the failure does not name the missing manifest:\n{text}"
    );

    // and a delete finishes the job: the manifest already gone counts as gone
    let text = assert_passed(&rcp(
        &cat,
        &["delete", "-force", "-removetopdir", "-oci.insecure", &app],
    ));
    // the config and the one layer still named are blobs, which the stand-in leaves to its
    // collector; the missing manifest is not a third, sent a blob delete it cannot take
    assert!(
        text.contains("2 deferred"),
        "the missing manifest was not deleted as a manifest:\n{text}"
    );
    // Now the listing names a tag deleted before its manifest could be read. It is left out
    // of the image and REPORTED, as a directory a listing could not read is: a registry
    // still replicating answers the same 404 for a tag it will serve a minute later, and a
    // copy that drops it and exits 0 has lost an image nobody was told about.
    reg.control("ghost/app/gone");
    let out = rcp(&cat, &["scan", "-noId", "-l", "-oci.insecure", &app]);
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a listed tag that could not be read was dropped without a word:\n{text}"
    );
    assert!(
        text.contains("tag gone") && text.contains("not there when it was read"),
        "the failure does not name the tag:\n{text}"
    );
    for m in ["index", "m1", "m2"] {
        assert!(
            !text.contains(&digests[m]),
            "manifest {m} is still listed after the delete:\n{text}"
        );
    }
}

/// Two hops: the first hop's serve opens `ssh://hop2/...` through its own transport, so a
/// chain of rcps carries the bytes. Both hops are the same stub here, which is the only
/// difference from a real chain and is stated.
#[test]
fn a_chain_of_two_hops_moves_the_same_bytes_as_one() {
    let s = Scratch::new("relay-chain");
    let (stub, _log) = serve_stub(&s);
    let src = fixture(&s);
    let one = s.path("one");
    let two = s.path("two");
    let cat = s.path("catalog");
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            &format!("ssh://hop2{}", one.display()),
        ],
    ));
    let text = assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            "-via",
            "ssh://hop1",
            src.to_str().unwrap(),
            &format!("ssh://hop2{}", two.display()),
        ],
    ));
    assert!(text.contains("copy: 4 files"), "{text}");
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), one.to_str().unwrap()],
    ));
    assert_passed(&rcp(
        &cat,
        &["verify", src.to_str().unwrap(), two.to_str().unwrap()],
    ));
    // The control: the hop's rail. `RCP_ALLOWED_ROOTS` in the SERVE's environment bounds
    // what a client may ask it to open. It is set inside the stub, on purpose: the first
    // draft set it in this process, which railed the CLIENT -- whose `-via` is `Runs` and
    // was refused before the hop was ever reached. Correct behavior, wrong control. The
    // hop's environment is the hop operator's, and this is what that looks like.
    let railed = s.path("stub-railed");
    write(
        &railed,
        format!(
            "#!/bin/sh\nexport RCP_ALLOWED_ROOTS=/nowhere\nexec {} serve\n",
            env!("CARGO_BIN_EXE_rcp")
        )
        .as_bytes(),
        0o755,
    );
    let out = rcp_over_ssh(
        &cat,
        &railed,
        &[
            "scan",
            "-noId",
            "-via",
            "ssh://hop1",
            &format!("ssh://hop2{}", two.display()),
        ],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a railed hop opened an endpoint outside its roots:\n{text}"
    );
    // "allowed roots", not "RCP_ALLOWED_ROOTS": a `-listen` serve takes them from `-allow`
    // too, so naming only the environment variable would be wrong for half its callers
    assert!(
        text.contains("allowed roots") && text.contains("/nowhere"),
        "the refusal does not name the hop's roots:\n{text}"
    );
    // and the same railed hop admits what IS under its roots, so the rail is a list
    let admits = s.path("stub-admits");
    write(
        &admits,
        format!(
            "#!/bin/sh\nexport RCP_ALLOWED_ROOTS={}\nexec {} serve\n",
            s.path("").display(),
            env!("CARGO_BIN_EXE_rcp")
        )
        .as_bytes(),
        0o755,
    );
    assert_passed(&rcp_over_ssh(
        &cat,
        &admits,
        &["scan", "-noId", &format!("ssh://hop2{}", two.display())],
    ));
}

/// A stand-in transport that cuts the wire after `after` bytes have crossed in either
/// direction, killing the serve, and leaves `marker` behind so an arm can tell a cut from
/// a run that happened to fail. No test-only code in the binary: the proxy sits where ssh
/// would, which is exactly where a real network dies.
fn cutting_stub(s: &Scratch, name: &str, after: u64) -> (PathBuf, PathBuf) {
    let cutter = s.path("cutter.py");
    if !cutter.exists() {
        write(
            &cutter,
            br#"#!/usr/bin/env python3
import os, subprocess, sys, threading
n, marker, rcp = int(sys.argv[1]), sys.argv[2], sys.argv[3]
p = subprocess.Popen([rcp, "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
lock = threading.Lock()
crossed = [0]
def cut():
    with open(marker, "w") as f:
        f.write(str(crossed[0]))
    p.kill()
    os._exit(0)
def pump(src, dst_write):
    while True:
        b = os.read(src, 65536)
        if not b:
            return
        with lock:
            room = n - crossed[0]
            if len(b) >= room:
                dst_write(b[:room])
                crossed[0] = n
                cut()
            crossed[0] += len(b)
        dst_write(b)
def to_serve(b):
    try:
        p.stdin.write(b); p.stdin.flush()
    except Exception:
        os._exit(0)
def to_client(b):
    try:
        os.write(1, b)
    except Exception:
        os._exit(0)
t = threading.Thread(target=pump, args=(0, to_serve), daemon=True)
t.start()
pump(p.stdout.fileno(), to_client)
p.wait()
"#,
            0o755,
        );
    }
    let stub = s.path(name);
    let marker = s.path(&format!("{name}.cut"));
    write(
        &stub,
        format!(
            "#!/bin/sh\nexec python3 {} {after} {} {}\n",
            cutter.display(),
            marker.display(),
            env!("CARGO_BIN_EXE_rcp")
        )
        .as_bytes(),
        0o755,
    );
    (stub, marker)
}

/// Fault injection: the wire to an `rcp serve` dies at a chosen point, and a resume from
/// the catalog completes the copy whatever phase the cut landed in.
///
/// The cut points are a sweep rather than three named phases, because naming a phase by
/// a byte offset would be a guess about the protocol's framing. What the sweep proves is
/// measured instead: the destination's file count at the moment of failure is 0 for at
/// least one cut (nothing had crossed -- the plan or the first open) and strictly between
/// 0 and all for at least one other (mid-transfer), and for EVERY cut the copy failed
/// rather than passed, the marker fired, `resume` passed and `verify` passed. The control
/// is a cut point past the whole transfer: no cut, no marker, the copy passes on its own.
#[test]
fn a_wire_that_dies_at_any_point_is_finished_by_a_resume() {
    if !Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP: python3 is needed for the cutting stand-in");
        return;
    }
    let s = Scratch::new("faults");
    let src = fixture(&s);
    // enough bytes that cuts land inside files rather than between them
    for i in 0..6u32 {
        let body: Vec<u8> = (0..400_000u32)
            .map(|j| ((j ^ i.wrapping_mul(2654435761)) % 251) as u8)
            .collect();
        write(&src.join(format!("blob{i}.bin")), &body, 0o644);
    }
    let cat = s.path("catalog");
    let run = |stub: &Path, args: &[&str]| -> Output {
        // a dead wire must fail, not hang: the whole run is bounded
        Command::new("timeout")
            .arg("120")
            .arg(env!("CARGO_BIN_EXE_rcp"))
            .env("RCP_SSH", stub)
            .arg("-catalog")
            .arg(&cat)
            .args(args)
            .output()
            .expect("rcp runs")
    };
    // COMPLETE files, not present ones: the serve creates a file at OPEN, so a cut 300
    // bytes into the run still leaves one file on disk, empty or partial. The first
    // version of this counted presence and read every cut as "one file crossed"; the
    // measurement that separates the phases is whether the bytes are all there.
    let complete_in = |dir: &Path| -> usize {
        let mut n = 0;
        let mut stack = vec![PathBuf::new()];
        while let Some(rel) = stack.pop() {
            for e in fs::read_dir(dir.join(&rel)).into_iter().flatten().flatten() {
                let m = e.metadata().unwrap();
                let sub = rel.join(e.file_name());
                if m.is_dir() {
                    stack.push(sub);
                } else if m.is_file()
                    && m.len() > 0
                    && fs::metadata(src.join(&sub)).is_ok_and(|sm| sm.len() == m.len())
                {
                    // non-empty too: the fixture's empty file is "complete" the moment the
                    // serve creates it at OPEN, which is not a byte having crossed
                    n += 1;
                }
            }
        }
        n
    };
    // the source measured the same way it will be measured on the destination
    let total_files = complete_in(&src);
    assert!(
        total_files >= 9,
        "the fixture has fewer non-empty files than expected: {total_files}"
    );

    let mut at_failure = Vec::new();
    for (i, after) in [120u64, 6_000, 120_000, 700_000, 1_500_000, 2_300_000]
        .into_iter()
        .enumerate()
    {
        let (stub, marker) = cutting_stub(&s, &format!("cut{i}"), after);
        let dst = s.path(&format!("dst{i}"));
        let id = format!("job{i}");
        let out = run(
            &stub,
            &[
                "copy",
                "-newid",
                &id,
                "-type",
                "f",
                "-parallel",
                "1",
                src.to_str().unwrap(),
                &format!("ssh://hop{}", dst.display()),
            ],
        );
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
        assert!(marker.exists(), "cut {i} at {after} bytes never fired, so this iteration measured a healthy wire:\n{text}");
        assert!(
            !out.status.success(),
            "cut {i} at {after} bytes: the copy PASSED over a wire that died:\n{text}"
        );
        at_failure.push(complete_in(&dst));
        // the resume finishes it, over a wire that now stays up
        let (ok_stub, _) = serve_stub(&s);
        let text = assert_passed(&run(&ok_stub, &["resume", "-id", &id]));
        assert!(text.contains("resume: "), "{text}");
        assert_passed(&rcp(
            &cat,
            &[
                "verify",
                "-nomods",
                "-type",
                "f",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        ));
        assert_eq!(
            complete_in(&dst),
            total_files,
            "cut {i}: the resume did not complete the tree"
        );
    }
    // the sweep really covered more than one phase
    assert!(
        at_failure.contains(&0),
        "no cut landed before the first file crossed; counts at failure were {at_failure:?}"
    );
    assert!(
        at_failure.iter().any(|n| *n > 0 && *n < total_files),
        "no cut landed mid-transfer; counts at failure were {at_failure:?}"
    );

    // the control: a cut point beyond the whole transfer is no cut at all
    let (stub, marker) = cutting_stub(&s, "nocut", u64::MAX / 2);
    let dst = s.path("dst-nocut");
    assert_passed(&run(
        &stub,
        &[
            "copy",
            "-newid",
            "whole",
            "-type",
            "f",
            src.to_str().unwrap(),
            &format!("ssh://hop{}", dst.display()),
        ],
    ));
    assert!(!marker.exists(), "the control cut fired, so the sweep above may have measured the proxy rather than the protocol");
    assert_eq!(complete_in(&dst), total_files);
}

fn rcp_http(catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("NO_PROXY", "*")
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

/// `https://` and `http://`: an ordinary web server as a read-only tree.
///
/// The property worth measuring is that the SAME tree arrives identically whichever
/// listing convention the operator's server happens to serve -- a published
/// `rcp-index.json`, nginx's JSON autoindex, or an Apache-style HTML page full of links
/// that are not files. So one fixture is served three ways and the three results are
/// compared against each other, not just against the source: a bug that dropped the same
/// file from all three would pass a per-shape assertion and fails this one.
#[test]
fn an_http_source_copies_the_same_tree_from_all_three_listing_conventions() {
    use rcp::https::testserver::{Server, Shape};
    let s = Scratch::new("http-shapes");
    let root = s.path("web");
    fs::create_dir_all(root.join("sub/deep")).unwrap();
    write(&root.join("a.txt"), b"alpha\n", 0o644);
    write(&root.join("with space.bin"), b"spaced\n", 0o644);
    write(&root.join("sub/b.txt"), b"bravo\n", 0o644);
    write(&root.join("sub/deep/c.txt"), b"charlie\n", 0o644);

    let mut results: Vec<(Shape, Vec<(String, u64, String)>)> = Vec::new();
    for shape in [Shape::Index, Shape::Json, Shape::Html] {
        let server = Server::start(&root, shape).unwrap();
        let cat = s.path(&format!("catalog-{shape:?}"));
        let dst = s.path(&format!("out-{shape:?}"));
        let text = assert_passed(&rcp_http(
            &cat,
            &["copy", "-noId", &server.url("/"), dst.to_str().unwrap()],
        ));
        assert!(text.contains("copy:"), "{text}");
        // every file, its length and its bytes -- the listing AND the transfer
        let mut got: Vec<(String, u64, String)> = Vec::new();
        let mut stack = vec![dst.clone()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().filter_map(Result::ok) {
                let p = e.path();
                let rel = p.strip_prefix(&dst).unwrap().to_string_lossy().to_string();
                if p.is_dir() {
                    stack.push(p);
                    got.push((rel, 0, String::from("<dir>")));
                } else {
                    let b = fs::read(&p).unwrap();
                    got.push((rel, b.len() as u64, String::from_utf8_lossy(&b).to_string()));
                }
            }
        }
        got.sort();
        results.push((shape, got));
    }

    let expected: Vec<(String, u64, String)> = {
        let mut v = vec![
            ("a.txt".into(), 6, "alpha\n".into()),
            ("with space.bin".into(), 7, "spaced\n".into()),
            ("sub".into(), 0, "<dir>".into()),
            ("sub/b.txt".into(), 6, "bravo\n".into()),
            ("sub/deep".into(), 0, "<dir>".into()),
            ("sub/deep/c.txt".into(), 8, "charlie\n".into()),
        ];
        v.sort();
        v
    };
    for (shape, got) in &results {
        assert_eq!(got, &expected, "{shape:?} did not deliver the fixture");
    }
    // and the three agree with EACH OTHER, which a shared omission would not satisfy
    assert_eq!(
        results[0].1, results[1].1,
        "the published index and the JSON autoindex disagree"
    );
    assert_eq!(
        results[1].1, results[2].1,
        "the JSON autoindex and the HTML autoindex disagree"
    );

    // Only the published index carries the source's own mtime, so only it says it keeps
    // times. The HTML page carries none at all; nginx's carries the server's.
    let server = Server::start(&root, Shape::Index).unwrap();
    let cat = s.path("cat-times");
    let out = s.path("out-times");
    assert_passed(&rcp_http(
        &cat,
        &["copy", "-noId", &server.url("/"), out.to_str().unwrap()],
    ));
    let src_mtime = fs::metadata(root.join("a.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let dst_mtime = fs::metadata(out.join("a.txt")).unwrap().modified().unwrap();
    assert_eq!(
        src_mtime, dst_mtime,
        "the published index carries an mtime and the copy did not keep it"
    );
}

/// The half of the adapter that is a refusal: a plain web server is a source and nothing
/// else, and every write names itself rather than failing somewhere inside a transfer.
#[test]
fn an_http_endpoint_refuses_to_be_a_destination_by_name() {
    use rcp::https::testserver::{Server, Shape};
    let s = Scratch::new("http-ro");
    let root = s.path("web");
    fs::create_dir_all(&root).unwrap();
    write(&root.join("a.txt"), b"alpha\n", 0o644);
    let server = Server::start(&root, Shape::Json).unwrap();
    let cat = s.path("catalog");
    let src = s.path("src");
    write(&src.join("new.txt"), b"new\n", 0o644);

    for (verb, args) in [
        ("copy", vec!["copy", "-noId", "SRC", "URL"]),
        ("mkdir", vec!["copy", "-noId", "-type", "f", "SRC", "URL"]),
        ("delete", vec!["delete", "-force", "URL"]),
    ] {
        let url = server.url("/");
        let filled: Vec<&str> = args
            .iter()
            .map(|a| match *a {
                "SRC" => src.to_str().unwrap(),
                "URL" => url.as_str(),
                other => other,
            })
            .collect();
        let out = rcp_http(&cat, &filled);
        let text = stdout(&out);
        assert!(
            !out.status.success(),
            "{verb} against a web server should refuse:\n{text}"
        );
        assert!(
            text.contains("source only") || text.contains("read"),
            "the refusal does not say why {verb} cannot work:\n{text}"
        );
    }
    // the control: the same endpoint as a SOURCE works, so the refusals above are about
    // writing and not about the endpoint being unreachable
    let back = s.path("back");
    assert_passed(&rcp_http(
        &cat,
        &["copy", "-noId", &server.url("/"), back.to_str().unwrap()],
    ));
    assert_eq!(fs::read(back.join("a.txt")).unwrap(), b"alpha\n");
}

/// NFS refuses in two ways with one `ErrorKind`, and only one of them is `Kept`.
///
/// `NFS3ERR_ACCES` is the server refusing THIS OBJECT: the file is protected, somebody
/// changes the mode, a later `sync` removes it. That is what `Kept` means, and its printed
/// remedy -- run `sync` again -- is the right one.
///
/// An RPC-level rejection is not: `AUTH_BADCRED`, `AUTH_TOOWEAK` and the two `RPCSEC_GSS`
/// problems refuse the CALL, every later removal answers the same way, and the fix is
/// `-nfs.sec` or a renewed ticket.
///
/// **This arm exists because I claimed that second case was broken and it was not.** The
/// reasoning was that both arrive as `PermissionDenied` and `remove` ends in
/// `Removed::or_refused`, so an expired ticket would be reported as `Kept`. It is not,
/// because `self.call(..)?` returns the rejection before the match is reached -- so
/// `or_refused` only ever sees an NFS status, which is exactly what it is for. The guard I
/// added was dead code and is gone; this arm is what showed that, and it stays as the
/// thing that would have caught the bug if it had been real.
///
/// The stand-in rejects ONLY `REMOVE` and `RMDIR`, because `require_gss` rejects every
/// call and then the mount never lands, so a `delete` cannot reach the removal this is
/// about.
#[test]
fn an_nfs_call_refused_by_rpc_is_a_failure_and_not_a_kept_entry() {
    let s = Scratch::new("nfs-rpc-reject");
    let export = s.path("export");
    fs::create_dir_all(export.join("a")).unwrap();
    write(&export.join("a/keep.txt"), b"bytes\n", 0o644);
    let cat = s.path("catalog");

    // the control FIRST, so the arm cannot pass against a stand-in that is simply broken:
    // an honest server removes the tree and says nothing about keeping anything
    let honest = rcp::nfs::testserver::Server::start(&export).unwrap();
    let text = assert_passed(&rcp_nfs(
        &cat,
        honest.port,
        &["delete", "-force", "-removetopdir", "127.0.0.1:/export:/a"],
    ));
    assert!(
        !text.contains("KEPT"),
        "the honest server reported a refusal:\n{text}"
    );
    assert!(
        !export.join("a").exists(),
        "the control did not actually remove the tree"
    );

    fs::create_dir_all(export.join("a")).unwrap();
    write(&export.join("a/keep.txt"), b"bytes\n", 0o644);
    let rejecting = rcp::nfs::testserver::Server::start_rejecting_removes(&export).unwrap();
    let text = assert_failed(
        &rcp_nfs(
            &cat,
            rejecting.port,
            &["delete", "-force", "-removetopdir", "127.0.0.1:/export:/a"],
        ),
        "RPC call rejected",
    );
    assert!(!text.contains("KEPT"), "an RPC rejection was reported as the store keeping the entry, whose remedy is to rerun:\n{text}");
    assert!(
        text.contains("AUTH_TOOWEAK") && text.contains("-nfs.sec"),
        "the failure does not name the credential as the thing to fix:\n{text}"
    );
    assert!(
        export.join("a/keep.txt").exists(),
        "the stand-in removed what it refused"
    );
}

/// A `.tar.gz` read through `tar://`, which SILENTLY COPIED NOTHING before there was a
/// decoder.
///
/// Measured, and the numbers are the point:
///
/// ```text
/// $ rcp copy -noId tar:///tmp/a.tar.gz /dest
/// copy: 0 files (0 bytes), 0 skipped, 1 directories, ...
/// STATUS: PASSED
/// ```
///
/// The archive held two files. A gzip member's first 512 bytes are not a tar header, so
/// the scan found no members, and an archive with no members is not an error -- the run
/// reported success and wrote nothing. That is the worst shape a data mover has: the
/// operator has no reason to look.
///
/// So the arm checks CONTENT and not just an exit code, and its controls are the two ways
/// the fix could be fake: the same tree as an UNCOMPRESSED tar must still round-trip (the
/// decode did not break the plain path), and a CORRUPTED gzip must FAIL rather than fall
/// back to reporting an empty archive.
#[test]
fn a_gzipped_tar_is_read_rather_than_silently_reported_empty() {
    let s = Scratch::new("targz");
    let src = fixture(&s);
    fs::create_dir_all(src.join("nested")).unwrap();
    // big enough that the encoder uses more than one block, and compressible so it is not
    // all stored blocks
    write(
        &src.join("nested/deep.bin"),
        &b"the quick brown fox jumps over the lazy dog\n".repeat(4000),
        0o640,
    );
    let cat = s.path("catalog");

    // The archive is made by the SYSTEM tar, so this measures interoperability rather
    // than a round trip through one implementation's own idea of the format.
    let plain = s.path("made.tar");
    let ok = Command::new("tar")
        .arg("-cf")
        .arg(&plain)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: `tar` did not run here, so the .tar.gz path was NOT checked against the reference implementation");
        return;
    }
    let gz = s.path("made.tar.gz");
    assert!(Command::new("sh")
        .arg("-c")
        .arg(format!("gzip -9 -c {} > {}", plain.display(), gz.display()))
        .status()
        .unwrap()
        .success());

    // the control FIRST: an uncompressed archive of the same tree round-trips, so a
    // failure below is about the gzip and not about this fixture
    let back_plain = s.path("back-plain");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &format!("tar://{}", plain.display()),
            back_plain.to_str().unwrap(),
        ],
    ));
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-noattrs",
            "-type",
            "f",
            src.to_str().unwrap(),
            back_plain.to_str().unwrap(),
        ],
    ));

    // and now the gzipped one, which must produce the SAME tree
    let back = s.path("back-gz");
    let text = assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &format!("tar://{}", gz.display()),
            back.to_str().unwrap(),
        ],
    ));
    assert!(
        !text.contains("copy: 0 files"),
        "a gzipped archive was read as empty and the run still passed:\n{text}"
    );
    assert_passed(&rcp(
        &cat,
        &[
            "verify",
            "-noattrs",
            "-type",
            "f",
            src.to_str().unwrap(),
            back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read(back.join("message.txt")).unwrap(),
        fs::read(src.join("message.txt")).unwrap()
    );
    assert_eq!(
        fs::read(back.join("nested/deep.bin")).unwrap(),
        fs::read(src.join("nested/deep.bin")).unwrap()
    );

    // a scan sees the members too, not only a copy
    let text = assert_passed(&rcp(
        &cat,
        &["scan", "-noId", &format!("tar://{}", gz.display())],
    ));
    assert!(
        !text.contains("0 files"),
        "a scan of a gzipped archive reported no files:\n{text}"
    );

    // THE SECOND CONTROL: corrupt the compressed body. The CRC must catch it and the run
    // must FAIL -- without this, a decoder that quietly returned nothing on damage would
    // put the original defect back and every assertion above would still pass.
    let mut bytes = fs::read(&gz).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let broken = s.path("broken.tar.gz");
    fs::write(&broken, &bytes).unwrap();
    let out = rcp(
        &cat,
        &["scan", "-noId", &format!("tar://{}", broken.display())],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a corrupted .tar.gz was accepted:\n{text}"
    );
    assert!(
        text.contains("deflate") || text.contains("CRC"),
        "the refusal does not say the archive failed to decompress:\n{text}"
    );
}

/// Writing a `.tar.gz` produces one, rather than a plain tar wearing the name.
///
/// The sibling arm above fixed the READ direction. The write direction stayed broken for
/// longer and was worse, because the output leaves this machine: `rcp copy /tree
/// tar://out.tar.gz` opened the file and wrote uncompressed tar records into it, so
///
/// ```text
/// $ tar tzf out.tar.gz
/// tar: This does not look like a tar archive
/// gzip: out.tar.gz: not in gzip format
/// ```
///
/// and rcp's own run said PASSED. The README named this as a known limitation, which was
/// honest and did not help: nothing that says `STATUS: PASSED` sends an operator to a
/// paragraph in a README, and the bad file is discovered wherever they shipped it to. A
/// documented wrong output is still a wrong output.
///
/// Every assertion here goes through the SYSTEM `tar` and `gzip`, because rcp reading
/// back what rcp wrote would pass just as happily on the broken version: its own reader
/// sniffs the magic and falls through to a plain tar. That is not a hypothetical -- it is
/// why this arm does not use `rcp copy tar://out.tar.gz back/` as its evidence.
#[test]
fn writing_a_dot_tar_dot_gz_writes_a_real_gzip_stream() {
    let s = Scratch::new("targzw");
    let src = fixture(&s);
    fs::create_dir_all(src.join("nested")).unwrap();
    // over the 4 MiB block, so the multi-member path is exercised rather than described
    write(
        &src.join("nested/deep.bin"),
        &b"the quick brown fox jumps over the lazy dog\n".repeat(200_000),
        0o640,
    );
    let cat = s.path("catalog");

    let probe = Command::new("gzip")
        .arg("--version")
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if !probe {
        eprintln!("SKIP: `gzip` did not run here, so what rcp WRITES was not checked against the reference implementation -- only against rcp's own reader, which shares its assumptions");
        return;
    }

    // the control FIRST: a `.tar` name still writes a plain tar, so a failure below is
    // about the gzip wrapper and not about the tar writer
    let plain = s.path("out.tar");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            &format!("tar://{}", plain.display()),
        ],
    ));
    assert!(
        Command::new("tar")
            .arg("-tf")
            .arg(&plain)
            .status()
            .unwrap()
            .success(),
        "a `.tar` name no longer produces a plain tar"
    );
    assert_ne!(
        &fs::read(&plain).unwrap()[..2],
        &[0x1f, 0x8b],
        "a `.tar` name was gzipped anyway"
    );

    // and the real case
    let gz = s.path("out.tar.gz");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            src.to_str().unwrap(),
            &format!("tar://{}", gz.display()),
        ],
    ));
    let head = fs::read(&gz).unwrap();
    assert_eq!(
        &head[..2],
        &[0x1f, 0x8b],
        "the file rcp wrote under a .tar.gz name does not start with the gzip magic"
    );

    // `tar tzf` validates the gzip member AND the tar records inside it. This is the
    // command the original defect failed.
    let listed = Command::new("tar").arg("-tzf").arg(&gz).output().unwrap();
    assert!(
        listed.status.success(),
        "the system tar could not read the .tar.gz rcp wrote: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let names = String::from_utf8_lossy(&listed.stdout).to_string();
    assert!(
        names.contains("message.txt"),
        "tar listed the archive without the file that is in it:\n{names}"
    );
    assert!(
        names.contains("deep.bin"),
        "tar listed the archive without the large member:\n{names}"
    );

    // unpack it for real and compare bytes, since a listing only reads headers
    let back = s.path("back");
    fs::create_dir_all(&back).unwrap();
    assert!(
        Command::new("tar")
            .arg("-xzf")
            .arg(&gz)
            .arg("-C")
            .arg(&back)
            .status()
            .unwrap()
            .success(),
        "the system tar could not unpack what rcp wrote"
    );
    assert_eq!(
        fs::read(back.join("message.txt")).unwrap(),
        fs::read(src.join("message.txt")).unwrap()
    );
    assert_eq!(
        fs::read(back.join("nested/deep.bin")).unwrap(),
        fs::read(src.join("nested/deep.bin")).unwrap(),
        "the member that spans a compression block came back different"
    );

    // It must actually be COMPRESSED. Without this the arm would pass on an encoder that
    // wrapped stored blocks in a gzip header -- valid, readable, and useless.
    assert!(
        head.len() < fs::metadata(&plain).unwrap().len() as usize / 4,
        "the .tar.gz is {} bytes against a .tar of {}, so it is barely compressed",
        head.len(),
        fs::metadata(&plain).unwrap().len()
    );

    // A name saying a wrapper rcp cannot write is refused by name rather than written as
    // a plain tar -- the same defect under a different suffix.
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                &format!("tar://{}", s.path("out.tar.bz2").display()),
            ],
        ),
        "which rcp does not write",
    );
    assert!(
        !s.path("out.tar.bz2").exists(),
        "a refused name still left a file behind"
    );
}

/// `.tar.zst` in both directions, checked against the SYSTEM `zstd` and `tar`.
///
/// Without zstd support a `.tar.zst` destination is refused by name, and a `.tar.zst`
/// SOURCE is scanned as a plain tar and refused as "not a tar archive" -- loud, unlike
/// the gzip case the sibling arm records, but a readable archive refused all the same.
///
/// The read side is fed by the reference encoder, including `pzstd`, whose output begins
/// with a SKIPPABLE frame rather than a data frame: a sniff that knew only the data-frame
/// magic takes that archive for a plain tar and refuses it (measured by removing the
/// skippable arm; this test then fails on the `pzstd` archive). The write side is read
/// back by the reference decoder and `tar`, never by rcp's own reader, which shares its
/// assumptions. The controls are a corrupted frame, which must fail, and the compression
/// ratio, which rules out stored blocks wearing the name.
#[test]
fn a_dot_tar_dot_zst_is_read_and_written_as_real_zstd() {
    let s = Scratch::new("tarzst");
    let src = fixture(&s);
    fs::create_dir_all(src.join("nested")).unwrap();
    // over the 4 MiB member size, so the archive is several frames and not one
    write(
        &src.join("nested/deep.bin"),
        &b"the quick brown fox jumps over the lazy dog\n".repeat(200_000),
        0o640,
    );
    let cat = s.path("catalog");
    let have = |tool: &str| {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    if !have("zstd") || !have("tar") {
        eprintln!("SKIP: `zstd` or `tar` did not run here, so .tar.zst was NOT checked against the reference implementation");
        return;
    }
    let plain = s.path("made.tar");
    assert!(Command::new("tar")
        .arg("-cf")
        .arg(&plain)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .unwrap()
        .success());

    // READ: the reference's own frames, then pzstd's skippable-frame layout
    let mut made = vec![("zstd", s.path("made.tar.zst"))];
    assert!(Command::new("zstd")
        .args(["-q", "-19", "-o"])
        .arg(&made[0].1)
        .arg(&plain)
        .status()
        .unwrap()
        .success());
    if have("pzstd") {
        let p = s.path("made-p.tar.zst");
        assert!(Command::new("pzstd")
            .args(["-q", "-p", "2", "-o"])
            .arg(&p)
            .arg(&plain)
            .status()
            .unwrap()
            .success());
        let head = fs::read(&p).unwrap();
        assert_eq!(u32::from_le_bytes(head[..4].try_into().unwrap()) & 0xFFFF_FFF0, 0x184D_2A50, "pzstd no longer leads with a skippable frame, so this arm tests nothing the plain one does not");
        made.push(("pzstd", p));
    } else {
        eprintln!("SKIP (part): `pzstd` did not run here, so an archive that leads with a skippable frame was NOT read");
    }
    for (who, archive) in &made {
        let back = s.path(&format!("back-{who}"));
        let text = assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-noId",
                &format!("tar://{}", archive.display()),
                back.to_str().unwrap(),
            ],
        ));
        assert!(
            !text.contains("copy: 0 files"),
            "{who}: a .tar.zst was read as empty and the run still passed:\n{text}"
        );
        assert_eq!(
            fs::read(back.join("nested/deep.bin")).unwrap(),
            fs::read(src.join("nested/deep.bin")).unwrap(),
            "{who}: the large member came back different"
        );
        assert_eq!(
            fs::read(back.join("message.txt")).unwrap(),
            fs::read(src.join("message.txt")).unwrap(),
            "{who}"
        );
    }

    // a damaged frame fails rather than falling back to an empty archive
    let mut bytes = fs::read(&made[0].1).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let broken = s.path("broken.tar.zst");
    fs::write(&broken, &bytes).unwrap();
    let out = rcp(
        &cat,
        &["scan", "-noId", &format!("tar://{}", broken.display())],
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &stdout(&out);
    assert!(
        !out.status.success(),
        "a corrupted .tar.zst was accepted:\n{text}"
    );
    assert!(
        text.contains("zstd"),
        "the refusal does not say the archive failed to decompress:\n{text}"
    );

    // WRITE: both suffixes, and the rsyncable cut on a pool of workers
    for (name, extra) in [
        ("out.tar.zst", &[][..]),
        ("out.tzst", &["-rsyncable", "-parallel", "4"][..]),
    ] {
        let zst = s.path(name);
        let mut args = vec!["copy", "-noId"];
        args.extend_from_slice(extra);
        let target = format!("tar://{}", zst.display());
        args.extend([src.to_str().unwrap(), target.as_str()]);
        assert_passed(&rcp(&cat, &args));
        let head = fs::read(&zst).unwrap();
        assert_eq!(
            &head[..4],
            &[0x28, 0xb5, 0x2f, 0xfd],
            "{name}: rcp did not write the zstd magic"
        );
        assert!(
            Command::new("zstd")
                .args(["-q", "-t"])
                .arg(&zst)
                .status()
                .unwrap()
                .success(),
            "{name}: the reference zstd rejects what rcp wrote"
        );
        let back = s.path(&format!("unpacked-{name}"));
        fs::create_dir_all(&back).unwrap();
        let out = Command::new("tar")
            .arg("--zstd")
            .arg("-xf")
            .arg(&zst)
            .arg("-C")
            .arg(&back)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{name}: the system tar could not unpack what rcp wrote: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read(back.join("nested/deep.bin")).unwrap(),
            fs::read(src.join("nested/deep.bin")).unwrap(),
            "{name}: the member spanning several frames came back different"
        );
        assert_eq!(
            fs::read(back.join("message.txt")).unwrap(),
            fs::read(src.join("message.txt")).unwrap(),
            "{name}"
        );
        assert!(
            head.len() < fs::metadata(&plain).unwrap().len() as usize / 4,
            "{name}: {} bytes against a .tar of {}, so it is barely compressed",
            head.len(),
            fs::metadata(&plain).unwrap().len()
        );
    }
}

/// A catalog is an audit trail: it names every source and destination path a run touched,
/// and its digests. Nothing that records that should be world-readable by default.
///
/// It was. `fs::create_dir_all` and a plain `OpenOptions::open` take the process umask, so
/// on the usual 022 a catalog landed 0755 with `index.tsv` at 0644, and a job record --
/// which additionally holds the whole argv of the running copy -- the same. Credential
/// redaction hides the secret in that argv and says nothing about who may read the rest.
///
/// Measured through the binary rather than the helper, because the umask is a property of
/// the process that creates the file, and only a real run has one.
#[test]
fn a_catalog_and_a_job_record_are_readable_by_their_owner_alone() {
    let s = Scratch::new("catalog-modes");
    let cat = s.path("cat");
    fs::create_dir_all(s.path("src")).unwrap();
    write(&s.path("src/a.txt"), b"hello", 0o644);
    assert_passed(&rcp(
        &cat,
        &["copy", "-newid", "j1", &s.s("src"), &s.s("dst")],
    ));

    let mode = |p: PathBuf| {
        fs::metadata(&p)
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        mode(cat.join("j1")),
        0o700,
        "the catalog directory is listable by anyone"
    );
    assert_eq!(
        mode(cat.join("j1/index.tsv")),
        0o600,
        "the index is readable by anyone"
    );
    assert_eq!(
        mode(cat.join("jobs.log")),
        0o600,
        "the job log is readable by anyone"
    );

    // The control, and the reason the arm is worth having: the COPY's own output must NOT
    // be tightened. rcp preserves the source's mode, and a fix that clamped everything to
    // 0600 would pass every assertion above while quietly breaking every copy.
    assert_eq!(
        mode(s.path("dst/a.txt")),
        0o644,
        "the copied file must keep the source's mode"
    );
}

/// `-acl4` and `-noxattr` are a contradiction, and a contradiction is refused by name.
///
/// NFSv4 ACLs ride in the extended-attribute channel (`system.nfs4_acl`), so asking for
/// them while turning that channel off carries none -- and the combination was ACCEPTED in
/// silence. The run reported the same counts and the same `STATUS: PASSED` as one that had
/// carried every ACL, which is the shape of failure that never gets noticed.
#[test]
fn acl4_with_the_attribute_channel_off_is_refused_rather_than_silently_carrying_nothing() {
    let s = Scratch::new("acl4-contradiction");
    fs::create_dir_all(s.path("src")).unwrap();
    write(&s.path("src/a.txt"), b"x", 0o644);
    let cat = s.path("cat");
    for off in ["-noxattr", "-noattrs"] {
        let out = assert_failed(
            &rcp(
                &cat,
                &["copy", "-noid", "-acl4", off, &s.s("src"), &s.s("dst")],
            ),
            "-acl4",
        );
        assert!(
            out.contains(off),
            "the message must name the option that collides: {out}"
        );
    }
    // The control, and it is what keeps this from being a blanket refusal: each option
    // alone is still accepted.
    assert_passed(&rcp(
        &cat,
        &["copy", "-noid", "-noxattr", &s.s("src"), &s.s("dst1")],
    ));
    assert_passed(&rcp(
        &cat,
        &["copy", "-noid", "-acl4", &s.s("src"), &s.s("dst2")],
    ));
}

/// `verify` must work with an http tree on the DESTINATION side, and say what it skipped.
///
/// No arm put one there. Every http arm used it as the source, so the ordering asymmetry
/// in `verify` -- which takes its two endpoints in the order written and made `keeps_times`
/// a question about the destination alone -- was invisible from this file.
///
/// The root directory is the other half, and the symptom is NOT the one first guessed. Its
/// `mtime_ns` was hardcoded `0` while an index-shaped tree answers `keeps_times()` TRUE,
/// and `verify` did not report a difference on it -- both sides read the same zero, because
/// the copy had just written it there. What it did do is date the copied tree's top
/// directory 1970-01-01, which is the assertion below.
#[test]
fn verify_works_with_an_http_tree_on_either_side() {
    use rcp::https::testserver::{Server, Shape};
    let s = Scratch::new("http-verify-dst");
    let root = s.path("web");
    fs::create_dir_all(root.join("sub")).unwrap();
    write(&root.join("a.txt"), b"alpha\n", 0o644);
    write(&root.join("sub/b.txt"), b"bravo\n", 0o644);

    // an index publishes the source's own mtimes, so times ARE comparable here -- which is
    // what makes the root's placeholder reachable
    let server = Server::start(&root, Shape::Index).unwrap();
    let cat = s.path("catalog");
    let dst = s.path("out");
    assert_passed(&rcp_http(
        &cat,
        &["copy", "-noId", &server.url("/"), dst.to_str().unwrap()],
    ));

    // http as the SOURCE, then as the DESTINATION: both must agree the trees match
    let a = assert_passed(&rcp_http(
        &cat,
        &["verify", &server.url("/"), dst.to_str().unwrap()],
    ));
    let b = assert_passed(&rcp_http(
        &cat,
        &["verify", dst.to_str().unwrap(), &server.url("/")],
    ));
    for text in [&a, &b] {
        assert!(
            !text.contains("DIFF mtime ."),
            "the root's time is a placeholder compared against a real one:\n{text}"
        );
    }

    // The observable half of the root's placeholder time: the COPY writes it to the
    // destination directory, so a tree copied from an index-shaped server came out dated
    // 1970. The root's time is derived from the newest file the index lists now, which is
    // a real time and the one a local directory would carry after the same copy.
    let root_mtime = fs::metadata(&dst).unwrap().modified().unwrap();
    let epoch_ish = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    assert!(
        root_mtime > epoch_ish,
        "the copied root is dated {root_mtime:?}, which is the epoch placeholder"
    );
    let newest = ["a.txt", "sub/b.txt"]
        .iter()
        .map(|r| fs::metadata(root.join(r)).unwrap().modified().unwrap())
        .max()
        .unwrap();
    assert_eq!(
        root_mtime, newest,
        "the root's time must be the newest file's, not an invention"
    );

    // and an autoindex, where times are NOT real: the comparison is skipped and said so,
    // whichever side the http tree is on. Without this the arm would pass on a build that
    // simply never compared times at all.
    let auto = Server::start(&root, Shape::Json).unwrap();
    let cat2 = s.path("catalog2");
    let dst2 = s.path("out2");
    assert_passed(&rcp_http(
        &cat2,
        &["copy", "-noId", &auto.url("/"), dst2.to_str().unwrap()],
    ));
    for args in [
        [&auto.url("/"), dst2.to_str().unwrap()],
        [dst2.to_str().unwrap(), &auto.url("/")],
    ] {
        let text = assert_passed(&rcp_http(&cat2, &["verify", args[0], args[1]]));
        assert!(
            text.contains("modification times were not compared"),
            "a skipped comparison must say so, in both orders:\n{text}"
        );
    }
}

/// Two transient NFS conditions that had no client-side answer, and now do.
///
/// `NFS3ERR_JUKEBOX` is what a server sends while it brings a file back from slow storage
/// -- the only v3 status that is transient by definition -- and nothing retried it, so a
/// copy of a file on tape simply failed. `NFS3ERR_STALE` on a CACHED handle is what a
/// server restart or an export re-share produces, and `fh_of` never invalidated an entry,
/// so the dead handle was handed back for the rest of the run and every later operation on
/// that path failed against it.
///
/// The server answers JUKEBOX to the first three calls and STALE to the first GETATTR.
/// Three is chosen against the client's budget: `RETRY_WAITS` gives each call four retries,
/// so three faults are absorbed within one call and the copy must simply succeed. The
/// control below exceeds that budget on purpose.
#[test]
fn a_jukebox_wait_and_a_stale_handle_are_both_survivable() {
    let s = Scratch::new("nfs-transient");
    let export = s.path("export");
    fs::create_dir_all(export.join("sub")).unwrap();
    write(&export.join("a.txt"), b"alpha\n", 0o644);
    write(&export.join("sub/b.txt"), b"bravo\n", 0o644);

    let server = rcp::nfs::testserver::Server::start_flaky(&export, 3, 1).unwrap();
    let cat = s.path("catalog");
    let src = "127.0.0.1:/export".to_string();
    let text = assert_passed(&rcp_nfs(
        &cat,
        server.port,
        &["copy", "-noId", &src, &s.s("out")],
    ));
    assert!(text.contains("copy: 2 files"), "{text}");
    assert_eq!(fs::read(s.path("out/a.txt")).unwrap(), b"alpha\n");
    assert_eq!(fs::read(s.path("out/sub/b.txt")).unwrap(), b"bravo\n");

    // The control, and it is what makes the arm about the RETRIES rather than about a
    // server that never faulted: the same faults with the retry budget exhausted must
    // still be visible as faults. A server that answers JUKEBOX to far more calls than the
    // client will wait for has to fail, by name.
    let stubborn = rcp::nfs::testserver::Server::start_flaky(&export, 10_000, 0).unwrap();
    let cat2 = s.path("catalog2");
    let out = assert_failed(
        &rcp_nfs(&cat2, stubborn.port, &["copy", "-noId", &src, &s.s("out2")]),
        "ERROR:",
    );
    assert!(
        out.contains("retriev") || out.contains("10008") || out.contains("NFS"),
        "the failure must name the condition:\n{out}"
    );
}

/// `rcp://`: the protocol over a socket instead of ssh.
///
/// The transport is the same `rcp serve` and the same frames; what changes is the channel
/// and, because a socket authenticates nobody where ssh authenticates everybody, the rules
/// about who may be served.
///
/// **The roots arm is here because it caught a real hole.** `check_listen` counted `-allow`
/// as railing the listener while the session's rail read only `RCP_ALLOWED_ROOTS` from the
/// environment -- two sources for one rail. Measured against a running listener started
/// with `-allow /tmp/scratch`: a copy to `/tmp/elsewhere` reported PASSED and the directory
/// was created. Nothing in the refusal arms or the happy path would have shown it; only
/// running the copy the rail was supposed to refuse does.
#[test]
fn rcp_endpoints_serve_the_protocol_over_a_socket_within_their_roots() {
    let s = Scratch::new("rcp-listen");
    let cat = s.path("catalog");
    let src = s.path("source");
    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("a.txt"), b"hello over a socket\n").unwrap();
    fs::write(src.join("big.bin"), noise(300_000, 19)).unwrap();
    fs::write(src.join("nested/d.txt"), b"deep\n").unwrap();

    // Both refusals, before anything is listening. They are what keeps this from being an
    // unauthenticated remote file service.
    assert_failed(
        &rcp(&cat, &["serve", "-listen", "127.0.0.1:0"]),
        "needs -allow",
    );
    let out = rcp(
        &cat,
        &[
            "serve",
            "-listen",
            "0.0.0.0:0",
            "-allow",
            &s.path("").to_string_lossy(),
        ],
    );
    assert_failed(&out, "only a loopback address");

    // and the endpoint's own refusals: no port to guess, and no user to pretend to check
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "rcp://127.0.0.1/x",
                &s.path("y").to_string_lossy(),
            ],
        ),
        "names no port",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "rcp://bob@127.0.0.1:9/x",
                &s.path("y").to_string_lossy(),
            ],
        ),
        "names a user",
    );

    let root = s.path("").to_string_lossy().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args(["serve", "-listen", "127.0.0.1:0", "-allow", &root])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("rcp serve -listen starts");

    // the bound port comes back on stderr, because -listen 0 asks the kernel to choose
    let mut line = String::new();
    {
        use std::io::BufRead;
        let mut err = std::io::BufReader::new(child.stderr.take().unwrap());
        err.read_line(&mut line)
            .expect("the listener announces its address");
    }
    let addr = line
        .trim()
        .rsplit(' ')
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        addr.starts_with("127.0.0.1:"),
        "the listener announced {line:?}"
    );

    let dst = format!("rcp://{addr}{}", s.path("dst").display());
    let out = rcp(&cat, &["copy", "-noId", &src.to_string_lossy(), &dst]);
    let text = assert_passed(&out);
    assert!(text.contains("copy: 3 files"), "{text}");
    assert_passed(&rcp(&cat, &["verify", &src.to_string_lossy(), &dst]));

    // back the other way: the socket is a tree at both ends
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &["copy", "-noId", &dst, &back.to_string_lossy()],
    ));
    assert_eq!(
        fs::read(back.join("big.bin")).unwrap(),
        fs::read(src.join("big.bin")).unwrap(),
        "the round trip changed the bytes"
    );

    // A SECOND listener, as a relay hop. `-via` took an ssh:// hop only, which left
    // `connect_tcp_via` reachable from no command line at all -- built, compiled, and dead.
    //
    // Two things this arm had to get right, and got wrong first:
    //  * The destination has to be REMOTE. `-via` routes the endpoints this process should
    //    not open itself, and a local path is not one, so a version that copied to a local
    //    path through the hop passed while the hop was never dialed.
    //  * A hop's rail bounds the endpoint TEXT, so a root of `/tmp/x` does not admit
    //    `rcp://host:port/tmp/x` -- the same rule the ssh relay arm spells `ssh://filer/..`.
    //    The hop therefore needs the first listener's port in its own `-allow`, which is
    //    why it is started second.
    let hop_roots = format!("rcp://{addr}{}", s.path("").display());
    let mut hop_child = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args([
            "serve",
            "-listen",
            "127.0.0.1:0",
            "-allow",
            &root,
            "-allow",
            &hop_roots,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the hop starts");
    let mut hop_line = String::new();
    {
        use std::io::BufRead;
        let mut err = std::io::BufReader::new(hop_child.stderr.take().unwrap());
        err.read_line(&mut hop_line)
            .expect("the hop announces its address");
    }
    let hop = format!(
        "rcp://{}",
        hop_line.trim().rsplit(' ').next().unwrap_or_default()
    );
    let chained = format!("rcp://{addr}{}", s.path("relayed").display());
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &src.to_string_lossy(),
            &chained,
            "-via",
            &hop,
        ],
    ));
    assert_eq!(
        fs::read(s.path("relayed").join("big.bin")).unwrap(),
        fs::read(src.join("big.bin")).unwrap(),
        "the relay changed the bytes"
    );
    // and the HOP's rails bind what it opens on our behalf: the same first listener, a path
    // its own root covers, but one the hop's `rcp://` root does not
    let outside_via = std::env::temp_dir().join(format!("rcp-via-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside_via);
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &src.to_string_lossy(),
            &format!("rcp://{addr}{}", outside_via.display()),
            "-via",
            &hop,
        ],
    );
    assert_failed(&out, "not under this serve's allowed roots");
    assert!(
        !outside_via.exists(),
        "the refused relay created {}",
        outside_via.display()
    );
    let _ = hop_child.kill();
    let _ = hop_child.wait();

    // THE ARM: a path outside the roots is refused, and nothing is created for it
    let outside = std::env::temp_dir().join(format!("rcp-listen-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside);
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &src.to_string_lossy(),
            &format!("rcp://{addr}{}", outside.display()),
        ],
    );
    assert_failed(&out, "not under this serve's allowed roots");
    assert!(
        !outside.exists(),
        "the refused copy created {}",
        outside.display()
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// `rcps://` end to end, and the rule that only MUTUAL TLS lifts the loopback restriction.
///
/// The bind is `0.0.0.0:0` on purpose. A wildcard is not a loopback address -- it is every
/// interface the host has -- so `check_listen` refuses it for a plaintext serve and for one
/// carrying only its own certificate. That refusal being lifted is the thing this measures,
/// and it is measured as a PAIR: the same address with the same server certificate, refused
/// without `-tls.clientca` and accepted with it. Without the first half the arm would pass
/// against a build that had simply stopped checking.
#[cfg(feature = "rustls")]
#[test]
fn rcps_endpoints_need_mutual_tls_before_they_leave_loopback() {
    let s = Scratch::new("rcps-mutual");
    let cat = s.path("catalog");
    let src = s.path("source");
    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("a.txt"), b"hello through TLS\n").unwrap();
    fs::write(src.join("big.bin"), noise(300_000, 23)).unwrap();
    fs::write(src.join("nested/d.txt"), b"deep\n").unwrap();
    let root = s.path("").to_string_lossy().to_string();

    let ca = authority(&s.0, "ca");
    let (server_crt, server_key) = signed_by(&s.0, &ca, "serve", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n");
    let (client_crt, client_key) = signed_by(&s.0, &ca, "client", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:client\n");
    // a second authority nothing here trusts, and a client it signed
    let other = authority(&s.0, "other-ca");
    let (stranger_crt, stranger_key) = signed_by(&s.0, &other, "stranger", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:stranger\n");
    let p = |x: &PathBuf| x.to_string_lossy().to_string();

    // HALF the pair: a wildcard bind WITH a server certificate, and no client authority.
    // Encryption without peer authentication does not lift the rule.
    let out = rcp(
        &cat,
        &[
            "serve",
            "-listen",
            "0.0.0.0:0",
            "-allow",
            &root,
            "-tls.cert",
            &p(&server_crt),
            "-tls.key",
            &p(&server_key),
        ],
    );
    let text = assert_failed(&out, "only a loopback address");
    assert!(
        text.contains("without identifying who connected"),
        "the refusal has to say why the certificate was not enough:\n{text}"
    );
    // and the two half-configurations
    assert_failed(
        &rcp(
            &cat,
            &[
                "serve",
                "-listen",
                "127.0.0.1:0",
                "-allow",
                &root,
                "-tls.cert",
                &p(&server_crt),
            ],
        ),
        "-tls.cert and -tls.key go together",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "serve",
                "-listen",
                "127.0.0.1:0",
                "-allow",
                &root,
                "-tls.clientca",
                &p(&ca.0),
            ],
        ),
        "this side needs one too",
    );

    // THE OTHER HALF: same address, same certificate, plus the client authority.
    let mut child = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args([
            "serve",
            "-listen",
            "0.0.0.0:0",
            "-allow",
            &root,
            "-tls.cert",
            &p(&server_crt),
            "-tls.key",
            &p(&server_key),
            "-tls.clientca",
            &p(&ca.0),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("rcp serve -listen starts");
    let mut line = String::new();
    {
        use std::io::BufRead;
        let mut err = std::io::BufReader::new(child.stderr.take().unwrap());
        err.read_line(&mut line)
            .expect("the listener announces its address");
    }
    let port = line
        .trim()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        port.parse::<u16>().is_ok(),
        "the listener announced {line:?}"
    );
    let dst = format!("rcps://127.0.0.1:{port}{}", s.path("dst").display());

    let with = |args: &[&str]| {
        let mut a: Vec<String> = vec!["-catalog".into(), p(&cat)];
        a.extend(args.iter().map(|x| x.to_string()));
        Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args(&a)
            .env("NO_PROXY", "*")
            .output()
            .expect("rcp runs")
    };
    let creds = [
        "-tls.ca",
        &p(&ca.0),
        "-tls.cert",
        &p(&client_crt),
        "-tls.key",
        &p(&client_key),
    ]
    .map(String::from);
    let copy: Vec<String> = [
        vec!["copy".into(), "-noId".into(), p(&src), dst.clone()],
        creds.to_vec(),
    ]
    .concat();
    let text = assert_passed(&with(&copy.iter().map(String::as_str).collect::<Vec<_>>()));
    assert!(text.contains("copy: 3 files"), "{text}");
    let verify: Vec<String> =
        [vec!["verify".into(), p(&src), dst.clone()], creds.to_vec()].concat();
    assert_passed(&with(
        &verify.iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    assert_eq!(
        fs::read(s.path("dst").join("big.bin")).unwrap(),
        fs::read(src.join("big.bin")).unwrap(),
        "TLS changed the bytes"
    );

    // The refusals, each asserted by ITS OWN reason rather than by a non-zero exit. The
    // difference is not pedantry: probing this by hand with a RELATIVE source path made all
    // four "fail" on `endpoint "src" is none of ...`, before a socket was opened, and every
    // one of them would have satisfied an `assert!(!success)`.
    let refused = |args: &[&str], why: &str, dir: &str| {
        let mut a: Vec<String> = vec![
            "-catalog".into(),
            p(&cat),
            "copy".into(),
            "-noId".into(),
            p(&src),
            format!("rcps://127.0.0.1:{port}{}", s.path(dir).display()),
        ];
        a.extend(args.iter().map(|x| x.to_string()));
        let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
            .args(&a)
            .env("NO_PROXY", "*")
            .output()
            .expect("rcp runs");
        let text = assert_failed(&out, why);
        // and it wrote nothing: a refused handshake must not leave a half-made tree
        assert!(
            !s.path(dir).exists(),
            "the refused copy created {}:\n{text}",
            s.path(dir).display()
        );
    };

    // no certificate at all: the serve asked for one, rustls says so by name
    refused(&["-tls.ca", &p(&ca.0)], "CertificateRequired", "no-cert");
    // a certificate from an authority the SERVE does not trust
    refused(
        &[
            "-tls.ca",
            &p(&ca.0),
            "-tls.cert",
            &p(&stranger_crt),
            "-tls.key",
            &p(&stranger_key),
        ],
        "UnknownCA",
        "wrong-ca",
    );
    // the mirror: a CLIENT that does not trust the serve walks away itself, and the message
    // comes from this side (UnknownIssuer) rather than as an alert from the far one
    refused(
        &[
            "-tls.ca",
            &p(&other.0),
            "-tls.cert",
            &p(&client_crt),
            "-tls.key",
            &p(&client_key),
        ],
        "UnknownIssuer",
        "untrusting",
    );

    // Plaintext against a TLS listener is not a quiet downgrade. It is refused by the frame
    // limit: the client sends its HELLO, the listener cannot parse a ClientHello out of it
    // and replies with an alert, and the client reads those bytes as a frame header. The
    // number is nonsense and the refusal is the point -- asserted here so that removing the
    // limit shows up as this arm rather than as an unbounded allocation.
    let plain = format!("rcp://127.0.0.1:{port}{}", s.path("plain").display());
    let out = with(&["copy", "-noId", &p(&src), &plain]);
    assert_failed(&out, "exceeds the 16777216 limit");
    assert!(!s.path("plain").exists());

    let _ = child.kill();
    let _ = child.wait();
}

/// The second codec, and the claim is a COMPARISON rather than a threshold: `deflate`
/// crosses fewer bytes than `lz4` on the same text, through the same counting stand-in.
///
/// It is deflate and not zstd on purpose. The roadmap row asked for zstd; a zstd codec is
/// FSE entropy coding, Huffman literals and a sequence format in both directions, in a
/// crate that depends on nothing but cryptography, and shipping something thin under that name would be
/// a label rather than a capability. What the row wanted -- a second codec, negotiated in
/// HELLO, trading CPU for ratio where LZ4 trades the other way -- is what this measures,
/// using the DEFLATE encoder the crate already has for `.tar.gz`.
#[test]
fn a_second_codec_is_negotiated_and_crosses_fewer_bytes_than_the_first() {
    let s = Scratch::new("codec");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    // text with real structure rather than one repeated line: LZ4 does very well on an
    // exact repeat, and a comparison that only measures that is not about the codecs
    let mut text = Vec::new();
    for i in 0..60_000u32 {
        text.extend_from_slice(
            format!(
                "2026-09-24T03:{:02}:{:02}Z host{} service[{}]: request {} completed in {} ms\n",
                i % 60,
                (i / 7) % 60,
                i % 13,
                1000 + i % 900,
                i,
                i % 250
            )
            .as_bytes(),
        );
    }
    fs::write(src.join("log.txt"), &text).unwrap();
    let cat = s.path("catalog");
    let remote = s.path("remote");
    fs::create_dir_all(&remote).unwrap();

    let measure = |tag: &str, args: &[&str]| -> u64 {
        let sub = Scratch::new(&format!("codec-{tag}"));
        let (stub, wire_in, _wire_out) = counting_stub(&sub);
        let dst = format!("ssh://filer{}/{tag}", remote.display());
        let mut a: Vec<&str> = vec!["copy", "-noId"];
        a.extend_from_slice(args);
        a.push(src.to_str().unwrap());
        a.push(&dst);
        assert_passed(&rcp_over_ssh(&cat, &stub, &a));
        // and the bytes arrived intact whichever codec carried them
        assert_passed(&rcp_over_ssh(
            &cat,
            &stub,
            &["verify", src.to_str().unwrap(), &dst],
        ));
        wire_bytes(&wire_in)
    };

    let plain = measure("plain", &[]);
    let lz4 = measure("lz4", &["-compress"]);
    let deflate = measure("deflate", &["-compress.codec", "deflate"]);
    let zstd = measure("zstd", &["-compress.codec", "zstd"]);
    eprintln!(
        "wire bytes: plain {plain}, lz4 {lz4}, deflate {deflate}, zstd {zstd}, source {}",
        text.len()
    );

    // each compresses, or the comparisons below are between failures
    assert!(lz4 < plain, "lz4 sent {lz4} of {plain} uncompressed");
    assert!(
        deflate < plain,
        "deflate sent {deflate} of {plain} uncompressed"
    );
    assert!(zstd < plain, "zstd sent {zstd} of {plain} uncompressed");
    // THE ARM
    assert!(
        deflate < lz4,
        "deflate sent {deflate} bytes and lz4 {lz4}; the second codec is not buying ratio"
    );
    assert!(
        zstd < lz4,
        "zstd sent {zstd} bytes and lz4 {lz4}; the third codec is not buying ratio"
    );

    // `-compress.codec` implies `-compress`: naming a codec and still sending everything
    // raw is the failure mode of requiring both, so it is asserted rather than assumed
    assert!(
        deflate < plain * 9 / 10,
        "deflate sent {deflate} of {plain}, which is what a run with compression OFF looks like"
    );
    assert!(
        zstd < plain * 9 / 10,
        "zstd sent {zstd} of {plain}, which is what a run with compression OFF looks like"
    );

    // an unknown codec is refused by name rather than silently falling back to lz4
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-compress.codec",
                "brotli",
                src.to_str().unwrap(),
                &s.path("x").to_string_lossy(),
            ],
        ),
        "lz4, deflate or zstd",
    );
    assert!(!s.path("x").exists());
}

/// `-compress.level` reaches the FAR side's encoder, which is the only claim worth
/// testing about it.
///
/// The direction is deliberate and it is the opposite of the codec arm above. That one
/// pushes, so the bytes it counts were compressed by the LOCAL process -- a level that
/// never left this machine would still pass it. This one PULLS: the source is behind the
/// stub, so every payload counted here was compressed by `rcp serve`, and the only way a
/// number typed on this command line can change them is by crossing HELLO and being read
/// on the other side. If the serve ignored the field, both runs would compress at the
/// same default and produce byte-identical wire totals.
///
/// Which is also why there is no separate control: an inert knob does not produce a
/// smaller number here, it produces the SAME number, so the assertion cannot be satisfied
/// by a level that goes nowhere.
#[test]
fn the_deflate_level_reaches_the_far_sides_encoder() {
    let s = Scratch::new("level");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    // the same log-shaped text as the codec arm: real structure, not one repeated line,
    // because chain depth has nothing to find in an exact repeat
    let mut text = Vec::new();
    for i in 0..60_000u32 {
        text.extend_from_slice(
            format!(
                "2026-09-24T03:{:02}:{:02}Z host{} service[{}]: request {} completed in {} ms\n",
                i % 60,
                (i / 7) % 60,
                i % 13,
                1000 + i % 900,
                i,
                i % 250
            )
            .as_bytes(),
        );
    }
    fs::write(src.join("log.txt"), &text).unwrap();
    let cat = s.path("catalog");

    let pull = |tag: &str, level: &str| -> u64 {
        let sub = Scratch::new(&format!("level-{tag}"));
        let (stub, _wire_in, wire_out) = counting_stub_verbose(&sub);
        let dst = sub.path("dst");
        let remote_src = format!("ssh://filer{}", src.display());
        let out = rcp_over_ssh(
            &cat,
            &stub,
            &[
                "copy",
                "-noId",
                "-compress.codec",
                "deflate",
                "-compress.level",
                level,
                &remote_src,
                dst.to_str().unwrap(),
            ],
        );
        assert_passed(&out);
        // THE SERVE'S OWN REPORT of the level it used, which is a stronger claim than the
        // byte totals below. Two different totals
        // out of a serve are consistent with the level having crossed HELLO and with the
        // serve having been configured that way itself; the numbers cannot separate those.
        // This line can, and the stub starts `rcp serve` with NO arguments, so the only
        // place the number can have come from is the frame.
        let log = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            log.contains(&format!("serve: hello compress=true codec=deflate level={level}")),
            "the serve did not report level {level}; its hello line is the discriminator, not the byte count:\n{log}"
        );
        // the bytes arrived intact at every level, which is the half a ratio cannot show
        assert_eq!(
            fs::read(dst.join("log.txt")).unwrap(),
            text,
            "level {level} did not deliver the file"
        );
        wire_bytes(&wire_out)
    };

    let one = pull("one", "1");
    let nine = pull("nine", "9");
    eprintln!(
        "wire bytes out of the serve: level 1 {one}, level 9 {nine}, source {}",
        text.len()
    );

    // THE ARM
    assert!(nine < one, "level 9 sent {nine} bytes and level 1 {one}; the level is not reaching the serve's encoder");

    // and the range is refused on the command line rather than clamped, so a typo is a
    // question rather than a silently different run
    for bad in ["0", "10", "six"] {
        assert_failed(
            &rcp(
                &cat,
                &[
                    "copy",
                    "-noId",
                    "-compress.level",
                    bad,
                    src.to_str().unwrap(),
                    &s.path("x").to_string_lossy(),
                ],
            ),
            "a number from 1 to 9",
        );
        assert!(
            !s.path("x").exists(),
            "-compress.level {bad} was refused but the run had already started"
        );
    }

    // A LEVEL ON A CODEC THAT HAS NONE IS ALSO REFUSED. The argument for accepting it is
    // that refusing would trap anyone who had not also typed `-compress.codec deflate`; but
    // the trap is the success, since that person is at a terminal able to answer, and an
    // accepting run exits 0 having done nothing with the number.
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-compress.level",
                "9",
                src.to_str().unwrap(),
                &s.path("y").to_string_lossy(),
            ],
        ),
        "only deflate has levels",
    );
    assert!(!s.path("y").exists());
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-compress.codec",
                "lz4",
                "-compress.level",
                "9",
                src.to_str().unwrap(),
                &s.path("y").to_string_lossy(),
            ],
        ),
        "only deflate has levels",
    );
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                "-compress.codec",
                "zstd",
                "-compress.level",
                "9",
                src.to_str().unwrap(),
                &s.path("w").to_string_lossy(),
            ],
        ),
        "only deflate has levels",
    );
    // THE CONTROL: the same level WITH deflate names is accepted and copies, so the arm
    // above is about the codec pairing and not about the level being refused outright.
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-compress.codec",
            "deflate",
            "-compress.level",
            "9",
            src.to_str().unwrap(),
            &s.path("z").to_string_lossy(),
        ],
    ));
    assert!(
        s.path("z").join("log.txt").exists(),
        "the accepted combination has to actually copy"
    );
}

/// A hole in a tar is written as a hole, not as the zeros it stands for.
///
/// The number this arm exists for, measured before any of it was written: a 64 MiB file
/// with 128 bytes of data in it, occupying 8 KiB on disk, packed to **67,113,472 bytes**
/// and took 4.77 s doing it. `tar -cf --sparse` wrote 10,240. That is 6554x, and it is the
/// gap this closes.
///
/// Every claim here is checked against the tar everyone else has, in BOTH directions,
/// because a sparse format agreed with nobody is just a private one.
#[test]
fn a_hole_crosses_a_tar_as_a_hole_and_the_reference_agrees_both_ways() {
    let s = Scratch::new("tarsparse");
    let cat = s.path("catalog");
    let src = s.path("source");
    fs::create_dir_all(&src).unwrap();

    // 64 MiB apparent, 128 bytes real: one extent at each end and a hole between
    let image = src.join("hole.bin");
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(&image).unwrap();
        f.set_len(64 << 20).unwrap();
        f.write_all_at(&[b'H'; 64], 0).unwrap();
        f.write_all_at(&[b'T'; 64], (64 << 20) - 64).unwrap();
    }
    let real_disk = fs::metadata(&image).unwrap().blocks() * 512;
    assert!(
        real_disk < 64 << 10,
        "the fixture itself has to be sparse, it uses {real_disk} bytes"
    );

    let archive = s.path("out.tar");
    let tar_url = format!("tar://{}", archive.display());
    assert_passed(&rcp(
        &cat,
        &["copy", "-noId", src.to_str().unwrap(), &tar_url],
    ));
    let packed = fs::metadata(&archive).unwrap().len();

    // THE MEASUREMENT. The old layout produced 67,113,472 bytes for this fixture; the
    // bound is two orders of magnitude under that rather than a tight fit, because the
    // exact size depends on how many pax records the member happens to need.
    assert!(
        packed < 64 << 10,
        "a 64 MiB hole packed to {packed} bytes; the whole point is that it should not"
    );

    // it is a REAL sparse member, not a small archive by luck
    let bytes = fs::read(&archive).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("GNU.sparse.major=1"),
        "the member is not marked sparse"
    );
    assert!(
        text.contains("GNU.sparse.realsize=67108864"),
        "the real size is not recorded"
    );

    // rcp reads its own back, and the hole survives as a hole rather than as zeros
    let back = s.path("back");
    assert_passed(&rcp(
        &cat,
        &["copy", "-noId", &tar_url, back.to_str().unwrap()],
    ));
    let got = fs::metadata(back.join("hole.bin")).unwrap();
    assert_eq!(got.len(), 64 << 20, "the round trip lost the file's length");
    assert!(
        got.blocks() * 512 < 64 << 10,
        "the round trip filled the hole in: {} bytes on disk",
        got.blocks() * 512
    );
    assert_eq!(sha256_of(&image), sha256_of(&back.join("hole.bin")));
    assert_passed(&rcp(&cat, &["verify", src.to_str().unwrap(), &tar_url]));

    // THE CONTROL, and the one that keeps this arm honest: a tree with NO holes must come
    // out the ordinary way. Without it, a writer that marked every member sparse -- or one
    // that lost data and wrote a short archive -- would pass every assertion above.
    let dense = s.path("dense");
    fs::create_dir_all(&dense).unwrap();
    write(&dense.join("solid.bin"), &noise(3 << 20, 11), 0o644);
    let plain = s.path("plain.tar");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            dense.to_str().unwrap(),
            &format!("tar://{}", plain.display()),
        ],
    ));
    let plain_bytes = fs::read(&plain).unwrap();
    assert!(
        !String::from_utf8_lossy(&plain_bytes).contains("GNU.sparse"),
        "a file with no holes acquired a sparse header"
    );
    assert!(
        plain_bytes.len() >= 3 << 20,
        "a 3 MiB dense file packed to {} bytes, which would mean data was dropped",
        plain_bytes.len()
    );

    // THE STATED LIMIT, asserted rather than hoped for. The header has to be written before
    // the bytes and a sparse header needs the whole map, so the sink holds only the first
    // SPARSE_DECIDE bytes while it waits to see a hole. A file that is solid for longer
    // than that is written flat even though it has a hole later -- correct, and larger.
    let late = s.path("late");
    fs::create_dir_all(&late).unwrap();
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(late.join("late.bin")).unwrap();
        f.set_len(12 << 20).unwrap();
        f.write_all_at(&noise(9 << 20, 5), 0).unwrap(); // solid past the 8 MiB decision point
    }
    let late_tar = s.path("late.tar");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            late.to_str().unwrap(),
            &format!("tar://{}", late_tar.display()),
        ],
    ));
    let late_len = fs::metadata(&late_tar).unwrap().len();
    assert!(late_len > 11 << 20, "the documented limit says a late hole is written flat, but the archive is only {late_len} bytes");
    let late_back = s.path("late_back");
    assert_passed(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            &format!("tar://{}", late_tar.display()),
            late_back.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        sha256_of(&late.join("late.bin")),
        sha256_of(&late_back.join("late.bin")),
        "the flat path has to still be correct"
    );

    let Some(tar) = Command::new("tar")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
    else {
        eprintln!(
            "SKIP: no tar(1) here, so the interoperability half of the sparse arm did not run"
        );
        return;
    };
    let gnu = String::from_utf8_lossy(&tar.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    // DIRECTION ONE: the reference reads what rcp wrote, and gets a sparse file back.
    // This is the half that caught the real defect -- rcp's own reader was happy with an
    // archive carrying two pax headers, and only tar(1) noticed the second had erased the
    // sparse records and extracted the decoy name literally.
    let x = s.path("x");
    fs::create_dir_all(&x).unwrap();
    let out = Command::new("tar")
        .args(["xf", archive.to_str().unwrap(), "-C", x.to_str().unwrap()])
        .output()
        .expect("tar runs");
    assert!(
        out.status.success(),
        "{gnu} refused a sparse archive rcp wrote:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let theirs = fs::metadata(x.join("hole.bin")).unwrap_or_else(|e| {
        panic!(
            "{gnu} did not produce hole.bin ({e}); it extracted: {:?}",
            walk(&x)
        )
    });
    assert_eq!(theirs.len(), 64 << 20, "{gnu} extracted the wrong length");
    assert!(
        theirs.blocks() * 512 < 64 << 10,
        "{gnu} extracted it solid: {} bytes on disk",
        theirs.blocks() * 512
    );
    assert_eq!(sha256_of(&image), sha256_of(&x.join("hole.bin")));

    // DIRECTION TWO: rcp reads what the reference wrote -- in ALL FOUR of the encodings
    // GNU tar can produce, not just the one rcp writes.
    //
    // THE REASON THIS IS A SWEEP AND NOT ONE CASE. Only `1.0` carries
    // `GNU.sparse.major`; that key arrived with it. A reader that gates on the major
    // therefore treats 0.0 and 0.1 as ORDINARY members, reads the extents as though they
    // were the whole file, and reports PASSED -- measured, before this was fixed: a
    // 4,160-byte file where a 67,108,928-byte one belongs, same on-disk block count, a
    // different digest, and nothing said a word. Silent, successful, wrong. The digest
    // assertion in this loop is what stands between that and a green run.
    let forms: &[(&str, &[&str])] = &[
        ("old-GNU (the default --sparse, typeflag S)", &["--sparse"]),
        (
            "pax 0.0 (repeated offset/numbytes records)",
            &["--sparse", "--format=posix", "--sparse-version=0.0"],
        ),
        (
            "pax 0.1 (GNU.sparse.map in the header)",
            &["--sparse", "--format=posix", "--sparse-version=0.1"],
        ),
        (
            "pax 1.0 (map in the member's data)",
            &["--sparse", "--format=posix", "--sparse-version=1.0"],
        ),
    ];
    let mut read_back = 0;
    for (label, flags) in forms {
        let ref_tar = s.path(&format!("ref{read_back}.tar"));
        let mut args: Vec<&str> = vec!["-cf", ref_tar.to_str().unwrap()];
        args.extend(flags.iter().copied());
        args.extend(["-C", src.to_str().unwrap(), "hole.bin"]);
        let out = Command::new("tar").args(&args).output().expect("tar runs");
        if !out.status.success() {
            eprintln!(
                "SKIP {label}: this {gnu} will not write it ({})",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            continue;
        }
        let from_ref = s.path(&format!("from_ref{read_back}"));
        assert_passed(&rcp(
            &cat,
            &[
                "copy",
                "-noId",
                &format!("tar://{}", ref_tar.display()),
                from_ref.to_str().unwrap(),
            ],
        ));
        let got = from_ref.join("hole.bin");
        let mine = fs::metadata(&got).unwrap_or_else(|e| {
            panic!(
                "{label}: no hole.bin came out ({e}); got {:?}",
                walk(&from_ref)
            )
        });
        assert_eq!(mine.len(), 64 << 20, "{label}: wrong length");
        assert!(
            mine.blocks() * 512 < 64 << 10,
            "{label}: the hole was filled in, {} bytes on disk",
            mine.blocks() * 512
        );
        assert_eq!(
            sha256_of(&image),
            sha256_of(&got),
            "{label}: read back as a DIFFERENT FILE"
        );
        read_back += 1;
    }
    // Not `> 0`: a sweep that quietly shrank to one case is the failure this counts
    // against. This tar writes all four.
    assert_eq!(
        read_back, 4,
        "only {read_back} of the 4 sparse encodings were exercised"
    );
}

/// Everything under a directory, for a failure message that says what IS there.
fn walk(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            out.push(p.strip_prefix(root).unwrap_or(&p).display().to_string());
            if p.is_dir() {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

fn rcp_smb(catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rcp"))
        .env("NO_PROXY", "*")
        .env("RCP_SMB_USER", "tester")
        .env("RCP_SMB_PASSWORD", "")
        .arg("-catalog")
        .arg(catalog)
        .args(args)
        .output()
        .expect("rcp runs")
}

/// `smb://` end to end against a real SMB2 server: copy in, verify, read back, scan, sync
/// and delete.
///
/// The stand-in is impacket's `SimpleSMBServer`. A missing impacket is a SKIP that says so
/// — not a pass, because a suite that reports green for a transport it never reached is
/// exactly the silent success this repo keeps refusing.
///
/// THREE THINGS THE STAND-IN DOES DIFFERENTLY FROM A REAL SERVER, said here rather than
/// left to be discovered as an unexplained pass:
///
/// - `SET_INFO FileBasicInformation` applies `LastWriteTime` as the ACCESS time and
///   `ChangeTime` as the MODIFICATION time, which is the reverse of MS-FSCC. The adapter
///   writes all three fields, so the value lands either way — and therefore the mtime
///   assertions below prove the ROUND TRIP, not which field a real server read it from.
/// - Deleting a directory through `FILE_DELETE_ON_CLOSE` is an `rmtree` there. The adapter
///   deliberately uses `FileDispositionInformation` instead, which this server DOES gate on
///   emptiness, so `remove` has the rmdir semantics the core expects.
/// - `FileIdBothDirectoryInformation` comes back with a zero file id, which is why the
///   adapter does not use that class and does not claim hard-link detection.
#[test]
fn smb_endpoints_copy_verify_scan_sync_and_delete_over_smb2() {
    let Some(mut server) = rcp::smb::testserver::start() else {
        eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
        return;
    };
    let s = Scratch::new("smb");
    let src = fixture(&s);
    let cat = s.path("catalog");
    let share = server.share.clone();
    fs::create_dir_all(share.join("in")).unwrap();
    let dst = format!("smb://127.0.0.1:{}/DATA/in", server.port);

    // in: the regular files. `-type f` because SMB2 carries no symlinks, and the fixture's
    // two are refused BY NAME rather than dropped -- asserted below, because a copy that
    // quietly skipped them would pass this half.
    let text = assert_passed(&rcp_smb(
        &cat,
        &[
            "copy",
            "-newid",
            "smbup",
            "-type",
            "f",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    assert!(
        text.contains("copy: 4 files") && text.contains("3 directories"),
        "{text}"
    );
    assert_eq!(
        fs::read(share.join("in/message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::read(share.join("in/nested/deeper/data.bin")).unwrap(),
        fs::read(src.join("nested/deeper/data.bin")).unwrap()
    );
    assert_eq!(
        fs::metadata(share.join("in/empty")).unwrap().len(),
        0,
        "a zero-length file did not survive the copy"
    );
    // A mirror into a directory that is not there yet is an EMPTY destination: not an
    // unreadable one the run failed to see, and not an overwrite the rail cannot rule out.
    // Destination listing errors are reported; this is the control that says a new
    // destination is not one of them.
    let fresh = format!("smb://127.0.0.1:{}/DATA/fresh", server.port);
    // a DRY run opens the destination without creating it, so here the root is really not
    // there -- and a plan against a destination that does not exist yet is a plan against an
    // empty one, not a failure at open ("no such file or directory").
    let dry = assert_passed(&rcp_smb(
        &cat,
        &[
            "isync",
            "-dryrun",
            "-type",
            "f",
            src.to_str().unwrap(),
            &fresh,
        ],
    ));
    assert!(
        dry.contains("+ message.txt") && !share.join("fresh").exists(),
        "{dry}"
    );
    // and a SOURCE that is not there still fails
    assert_failed(
        &rcp_smb(
            &cat,
            &[
                "scan",
                &format!("smb://127.0.0.1:{}/DATA/nowhere", server.port),
            ],
        ),
        "no such",
    );
    assert_passed(&rcp_smb(
        &cat,
        &[
            "isync",
            "-requireconfirm",
            "-type",
            "f",
            src.to_str().unwrap(),
            &fresh,
        ],
    ));
    assert_eq!(
        fs::read(share.join("fresh/message.txt")).unwrap(),
        b"hello from the source\n"
    );

    // The times DID cross, which is what `keeps_times: true` claims for this transport and
    // what separates it from the WebDAV one. Read off the filesystem the share is a view
    // of, so the assertion does not go through the same code it is checking.
    let mtime = fs::metadata(share.join("in/message.txt")).unwrap().mtime();
    assert_eq!(
        mtime, 1_600_000_000,
        "the source mtime did not reach the share"
    );

    // Bytes and times compare clean with EVERY check asked for. Modes and owners do not
    // exist on a share, so rather than compare an invented 0644 against a real 0755, the
    // adapter says the comparison did not happen -- in prose for an operator and in
    // `skipped` for a caller.
    let out = rcp_smb(
        &cat,
        &["verify", "-json", "-type", "f", src.to_str().unwrap(), &dst],
    );
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "verify against the share failed:\n{text}"
    );
    assert!(
        !text.contains("DIFF mode"),
        "verify compared modes against a share that has none:\n{text}"
    );
    for token in [r#""mode""#, r#""owner""#, r#""xattr""#] {
        assert!(
            text.contains(&format!("\"skipped\":[{token}")) || text.contains(&format!(",{token}")),
            "the skipped list does not name {token}:\n{text}"
        );
    }
    assert!(
        text.contains("modes were not compared"),
        "the skipped mode check is not said in prose:\n{text}"
    );

    // THE CONTROL, and it is the arm that matters, because the assertion above would also
    // pass if `verify` had simply stopped checking modes everywhere. Against a LOCAL
    // destination -- which does keep modes -- the same check on the same source reports the
    // difference and fails. So the check was NARROWED by the transport, not switched off.
    let control = s.path("keeps-modes");
    assert_passed(&rcp_smb(
        &cat,
        &[
            "copy",
            "-noId",
            "-type",
            "f",
            src.to_str().unwrap(),
            control.to_str().unwrap(),
        ],
    ));
    fs::set_permissions(control.join("script.sh"), fs::Permissions::from_mode(0o600)).unwrap();
    let text = assert_failed(
        &rcp_smb(
            &cat,
            &[
                "verify",
                "-type",
                "f",
                src.to_str().unwrap(),
                control.to_str().unwrap(),
            ],
        ),
        "DIFF mode",
    );
    assert!(
        text.contains("script.sh: source 0755"),
        "the mode difference is not reported against the file that has it:\n{text}"
    );

    // a symlink is refused by name rather than followed or silently skipped
    let text = assert_failed(
        &rcp_smb(&cat, &["copy", "-noId", src.to_str().unwrap(), &dst]),
        "symlink",
    );
    assert!(
        text.contains("no symlinks"),
        "the refusal does not say why:\n{text}"
    );

    // out: the same tree back to a local directory, through the read path
    let back = s.path("back");
    assert_passed(&rcp_smb(
        &cat,
        &["copy", "-noId", &dst, back.to_str().unwrap()],
    ));
    assert_eq!(
        fs::read(back.join("nested/deeper/data.bin")).unwrap(),
        fs::read(src.join("nested/deeper/data.bin")).unwrap()
    );
    assert_eq!(
        fs::read(back.join("message.txt")).unwrap(),
        b"hello from the source\n"
    );
    assert_eq!(
        fs::metadata(back.join("message.txt")).unwrap().mtime(),
        1_600_000_000,
        "the mtime did not come back off the share"
    );

    // A NANOSECOND SOURCE TIME, which is the case the fixture's whole seconds hide.
    //
    // SMB counts in 100-nanosecond FILETIME ticks. The fixture pins `1_600_000_000`, a
    // whole second, so nothing here had ever measured whether the client's SET_INFO
    // payload carries sub-second precision at all -- a client that truncated mtime to
    // seconds would have passed every arm in this file.
    let ticks = s.path("ticks");
    fs::create_dir_all(&ticks).unwrap();
    fs::write(ticks.join("odd.bin"), b"a nanosecond time\n").unwrap();
    let odd = UNIX_EPOCH + Duration::new(1_600_000_000, 123_456_789);
    fs::File::options()
        .write(true)
        .open(ticks.join("odd.bin"))
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(odd).set_accessed(odd))
        .unwrap();
    let tickdst = format!("smb://127.0.0.1:{}/DATA/ticks", server.port);
    assert_passed(&rcp_smb(
        &cat,
        &["copy", "-noId", ticks.to_str().unwrap(), &tickdst],
    ));
    // Read off the filesystem the share is a view of, because the stand-in's LISTING path
    // reports whole seconds -- impacket builds its FILETIMEs from `os.stat`'s integer
    // tuple, where the sub-second part is gone before any conversion. So `...789` arriving
    // as `...700` is visible on disk and not on the wire.
    assert_eq!(
        fs::metadata(share.join("ticks/odd.bin"))
            .unwrap()
            .mtime_nsec(),
        123_456_700,
        "the client sent a time that is not a 100 ns FILETIME tick"
    );
    assert_passed(&rcp_smb(
        &cat,
        &["verify", "-noId", ticks.to_str().unwrap(), &tickdst],
    ));

    // THE CONTROL, at the resolution this stand-in can carry: a different SECOND is still
    // a difference, so the arm above is not passing because times stopped being compared.
    //
    // The SUB-TICK control -- that `...800` against `...700` is a difference rather than a
    // blanket 100 ns window -- CANNOT be written here, for the read-path reason above, and
    // is not faked: it lives in `plan::tests::coarser_destination_times_match_only_when_
    // the_dropped_part_is_zero`, on the numbers a real Samba returned.
    let later = UNIX_EPOCH + Duration::new(1_600_000_077, 123_456_789);
    fs::File::options()
        .write(true)
        .open(ticks.join("odd.bin"))
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(later).set_accessed(later))
        .unwrap();
    let text = assert_failed(
        &rcp_smb(
            &cat,
            &["verify", "-noId", ticks.to_str().unwrap(), &tickdst],
        ),
        "DIFF mtime",
    );
    assert!(
        text.contains("odd.bin"),
        "the difference is not reported against the file that has it:\n{text}"
    );

    // a listing over the wire sees what the server holds, and nothing else
    let text = assert_passed(&rcp_smb(&cat, &["scan", "-noId", &dst]));
    assert!(
        text.contains("4 files"),
        "the scan did not see the four files:\n{text}"
    );
    assert!(
        !text.contains("in/in"),
        "the directory is listed inside itself:\n{text}"
    );

    // sync: one changed file crosses and the rest do not, which is the arm for
    // `keeps_times` -- a transport whose mtime did not survive reads every file as changed
    write(&src.join("message.txt"), b"changed on the source\n", 0o640);
    let text = assert_passed(&rcp_smb(&cat, &["sync", "-id", "smbup", "-type", "f"]));
    assert!(
        text.contains("sync: 1 files") && text.contains("3 skipped"),
        "sync did not move exactly the one changed file:\n{text}"
    );
    assert_eq!(
        fs::read(share.join("in/message.txt")).unwrap(),
        b"changed on the source\n"
    );

    // delete, and the server really no longer has it
    assert_passed(&rcp_smb(&cat, &["delete", "-force", "-removetopdir", &dst]));
    assert!(
        !share.join("in").exists(),
        "the directory is still there after delete"
    );

    server.stop();
}

/// The handshake retry, proved by a gate that kills connections before the server sees them.
///
/// The retry was measured against a real Samba -- 32 failures of 2048 without it, 1 with --
/// and that measurement cannot run in CI, because it needs a server that intermittently
/// wedges. So the BEHAVIOR is pinned here instead, with a stand-in for the failure rather
/// than a stand-in for the server: a listener in front of the real one that accepts the
/// first few connections and drops them without a byte.
///
/// That reaches the client exactly as the defect does -- the handshake dies at the
/// transport before TREE_CONNECT -- while being deterministic, which the defect is not.
#[test]
fn a_handshake_that_dies_at_the_transport_is_retried_on_a_fresh_connection() {
    let Some(mut server) = rcp::smb::testserver::start() else {
        eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
        return;
    };
    let s = Scratch::new("smb-retry");
    let cat = s.path("catalog");
    fs::create_dir_all(server.share.join("in")).unwrap();

    // `kill_first` connections are accepted and dropped; the rest are pumped to the server.
    let gate = |kill_first: usize, upstream: u16| -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut down) = stream else { return };
                if counter.fetch_add(1, Ordering::SeqCst) < kill_first {
                    // No FIN-after-data, no error status -- just gone. This is the shape
                    // the real failure has: the client is left with a dead socket partway
                    // through a handshake it has already started.
                    drop(down);
                    continue;
                }
                let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", upstream)) else {
                    return;
                };
                let (mut down2, mut up2) = (down.try_clone().unwrap(), up.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut down2, &mut up2);
                });
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut up, &mut down);
                });
            }
        });
        (port, seen)
    };

    // TWO failures, then a working server: the third connection carries the work.
    let (port, seen) = gate(2, server.port);
    let url = format!("smb://127.0.0.1:{port}/DATA/in");
    assert_passed(&rcp_smb(&cat, &["scan", "-noId", &url]));
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "the client did not dial again after the two dead connections"
    );

    // THE CONTROL, and it carries two claims the arm above cannot: that the retry is
    // BOUNDED, and that giving up says so by name rather than reporting whichever socket
    // error came last. Without it, a client that retried forever would pass the first half.
    let (port, seen) = gate(99, server.port);
    let url = format!("smb://127.0.0.1:{port}/DATA/in");
    let text = assert_failed(&rcp_smb(&cat, &["scan", "-noId", &url]), "handshake failed");
    assert!(
        text.contains("3 connections in a row"),
        "giving up does not name the attempts:\n{text}"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "the client made {} attempts, not 3",
        seen.load(Ordering::SeqCst)
    );

    // AND THE SHAPE THE DEFECT ACTUALLY HAS, which the gate above does NOT model.
    //
    // Dropping an accepted socket gives the client `UnexpectedEof` or `ConnectionReset`
    // in microseconds. The real wedge is SILENCE: the socket stays open, nothing comes
    // back, and the client is killed by its own deadline -- a different branch of
    // `worth_another_connection` and a different order of magnitude in time. So the arm
    // above cannot fail if `HANDSHAKE_TIMEOUT` were reverted to the data path's 60 s,
    // because nothing in it ever reaches a timeout.
    //
    // This one does. The gate completes the TCP handshake and then says nothing at all,
    // twice, so each attempt costs a full `HANDSHAKE_TIMEOUT` and the third succeeds.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let silent_port = silent.local_addr().unwrap().port();
    let upstream = server.port;
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let keep = held.clone();
    std::thread::spawn(move || {
        for stream in silent.incoming() {
            let Ok(down) = stream else { return };
            if counter.fetch_add(1, Ordering::SeqCst) < 2 {
                // HELD OPEN, not dropped: the client must time out rather than see an EOF.
                keep.lock().unwrap().push(down);
                continue;
            }
            let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", upstream)) else {
                return;
            };
            let (mut d2, mut u2) = (down.try_clone().unwrap(), up.try_clone().unwrap());
            let mut d3 = down;
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut d2, &mut u2);
            });
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut up, &mut d3);
            });
        }
    });
    let url = format!("smb://127.0.0.1:{silent_port}/DATA/in");
    let began = Instant::now();
    assert_passed(&rcp_smb(&cat, &["scan", "-noId", &url]));
    assert_eq!(
        seen.load(Ordering::SeqCst),
        3,
        "the client did not dial again after the two silent connections"
    );
    // AND IT REALLY TIMED OUT, twice, rather than the gate having failed some faster way:
    // two deadlines is the floor. This is also what pins the deadline to something short --
    // at the data path's 60 s the same arm would take over two minutes.
    assert!(
        began.elapsed() >= Duration::from_secs(20),
        "two silent attempts took {:?}; the client did not wait out its deadline",
        began.elapsed()
    );

    server.stop();
}

/// The handshake's short fuse does NOT stay lit for the session's own operations.
///
/// The retry needs a handshake deadline well under the data path's, or a wedged connection
/// costs a minute before anything can be tried again. The risk that creates is the
/// opposite one: leave the short fuse in place and a read that legitimately takes longer
/// than ten seconds -- a big file off a loaded filer, exactly what the 60 s is for -- gets
/// called dead. One line restores it, and nothing asserted that line ran.
///
/// So: a gate that counts the server's replies and stalls ONE of them, after the handshake
/// is over, for longer than the handshake deadline. With the deadline restored this is
/// slow and succeeds; without it, it fails.
///
/// Counted, not timed. The first draft stalled "half a second in" and the whole scan
/// finished in 23 ms, so the gate never fired -- caught only because the arm asserts the
/// stall HAPPENED. A trigger that never fires makes an arm agree with everything.
#[test]
fn the_short_handshake_deadline_does_not_outlive_the_handshake() {
    let Some(mut server) = rcp::smb::testserver::start() else {
        eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
        return;
    };
    let s = Scratch::new("smb-fuse");
    let cat = s.path("catalog");
    fs::create_dir_all(server.share.join("in")).unwrap();
    write(&server.share.join("in/a.txt"), b"content\n", 0o644);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().unwrap().port();
    let upstream = server.port;
    // Longer than HANDSHAKE_TIMEOUT (10 s), shorter than TIMEOUT (60 s). A stall between
    // the two is the only thing that can tell them apart from out here.
    let stall = Duration::from_secs(14);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut down) = stream else { return };
            let Ok(mut up) = std::net::TcpStream::connect(("127.0.0.1", upstream)) else {
                return;
            };
            let (mut down2, mut up2) = (down.try_clone().unwrap(), up.try_clone().unwrap());
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut down2, &mut up2);
            });
            std::thread::spawn(move || {
                let mut replies = 0usize;
                let mut stalled = false;
                let mut buf = [0u8; 8192];
                loop {
                    let n = match std::io::Read::read(&mut up, &mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    replies += 1;
                    // The handshake is four replies -- negotiate, two session setups, tree
                    // connect. Hold the sixth, which is inside the listing and safely past
                    // the point where the short deadline is supposed to have been retired.
                    if !stalled && replies >= 6 {
                        stalled = true;
                        std::thread::sleep(stall);
                    }
                    if std::io::Write::write_all(&mut down, &buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });

    let url = format!("smb://127.0.0.1:{port}/DATA/in");
    let began = Instant::now();
    let text = assert_passed(&rcp_smb(&cat, &["scan", "-noId", &url]));
    assert!(
        text.contains("1 files"),
        "the listing did not survive the stall:\n{text}"
    );
    // AND THE STALL REALLY HAPPENED, rather than this arm passing because the gate never
    // fired -- which would make it a second, slower copy of the plain scan arm.
    assert!(
        began.elapsed() >= stall,
        "the run finished in {:?}, so the gate never stalled anything",
        began.elapsed()
    );

    server.stop();
}

/// The credential does not go in the URL, and the refusal does not repeat it.
///
/// The WebDAV arm of this exists because a refusal that quoted the URL back wrote the
/// password into the job log, on the one path that exists to keep it out. Same shape, same
/// measurement, one scheme later.
#[test]
fn an_smb_url_with_a_password_is_refused_without_echoing_it() {
    let s = Scratch::new("smb-url");
    let cat = s.path("catalog");
    let text = stdout(&rcp_smb(&cat, &["scan", "smb://user:hunter2@host/DATA/x"]));
    assert!(
        !text.contains("hunter2"),
        "the password was echoed back:\n{text}"
    );
    assert!(
        text.contains("-smb.user"),
        "the refusal does not say where the credential goes:\n{text}"
    );
    // THE CONTROL: a URL with a user and no password is accepted, so the refusal is about
    // the password rather than about the '@'
    let ep = rcp::Endpoint::parse("smb://alice@host:4455/DATA/sub/dir")
        .expect("a user with no password parses");
    assert_eq!(ep.display(), "smb://alice@host:4455/DATA/sub/dir");
    assert!(ep.is_smb());
    // a share is required; a host alone names nothing TREE_CONNECT can take
    let e = rcp::Endpoint::parse("smb://host/").unwrap_err().to_string();
    assert!(e.contains("names no share"), "{e}");
}

/// The four paths the arm above never reaches, asked as "what did I NOT exercise?" rather
/// than "does the happy path work?".
///
/// Each one runs code the first arm leaves cold:
///
/// - **A sparse file** is the ONLY thing that reaches `FileEndOfFileInformation` in the
///   sink. Without it that call is written and never executed. It is also the branch most
///   likely to be wrong, because sending it unconditionally would corrupt the last byte of
///   every file on this stand-in (which implements it as "seek to length-1, write a zero").
/// - **An empty directory** is the case where this server does NOT strip `.` and `..` --
///   it only strips them when the entry count exceeds two. A client that trusted the
///   server to filter them reports two phantom children and a walk that recurses.
/// - **A non-ASCII name** is the only thing that exercises UTF-16LE both ways on a name
///   rather than on a path the test itself wrote in ASCII.
/// - **A non-empty directory removed** is the case the delete design was chosen for: the
///   adapter uses `FileDispositionInformation` rather than `FILE_DELETE_ON_CLOSE`
///   specifically so the emptiness check lands where the client can read it. Untested,
///   that reasoning is a comment rather than a behavior.
#[test]
fn smb_carries_a_hole_an_empty_directory_and_a_non_ascii_name_and_refuses_a_full_rmdir() {
    let Some(mut server) = rcp::smb::testserver::start() else {
        eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
        return;
    };
    let s = Scratch::new("smb-edges");
    let cat = s.path("catalog");
    let share = server.share.clone();
    let src = s.path("src");
    fs::create_dir_all(src.join("hollow")).unwrap();
    fs::create_dir_all(src.join("naïve dir")).unwrap();
    write(
        &src.join("naïve dir/résumé.txt"),
        "café\n".as_bytes(),
        0o644,
    );
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("sparse.img")).unwrap();
        f.set_len(8 << 20).unwrap();
        f.write_all_at(b"head", 0).unwrap();
        f.write_all_at(b"tail", (8 << 20) - 4).unwrap();
    }
    // a file that ends IN a hole, which is the case `FileEndOfFileInformation` exists for:
    // the bytes written stop short of the length, so nothing but that call can set it
    {
        use std::os::unix::fs::FileExt;
        let f = fs::File::create(src.join("tailhole.img")).unwrap();
        f.set_len(3 << 20).unwrap();
        f.write_all_at(b"only the head is data", 0).unwrap();
    }
    let dst = format!("smb://127.0.0.1:{}/DATA/in", server.port);
    let text = assert_passed(&rcp_smb(
        &cat,
        &[
            "copy",
            "-newid",
            "edges",
            "-type",
            "f",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    assert!(
        text.contains("copy: 3 files"),
        "the three files did not all cross:\n{text}"
    );

    // THE HOLE. Both files come back at their full LENGTH -- that is the assertion that
    // `FileEndOfFileInformation` ran, because the bytes written stop short of it.
    assert_eq!(
        fs::metadata(share.join("in/sparse.img")).unwrap().len(),
        8 << 20,
        "the sparse file did not reach its full length"
    );
    assert_eq!(
        fs::metadata(share.join("in/tailhole.img")).unwrap().len(),
        3 << 20,
        "a file ending in a hole did not reach its full length"
    );
    // and the bytes at both ends survived. The stand-in's end-of-file handler writes a zero
    // at length-1, so a file whose last byte is DATA is the one that would be corrupted by
    // sending the call unconditionally -- `sparse.img` ends in `tail`, so this is that check.
    let got = fs::read(share.join("in/sparse.img")).unwrap();
    assert_eq!(&got[..4], b"head", "the head of the sparse file is wrong");
    assert_eq!(&got[got.len() - 4..], b"tail", "the LAST BYTES of the sparse file were overwritten -- the length call fired when it should not have");
    assert!(
        got[4..got.len() - 4].iter().all(|&b| b == 0),
        "the hole came back as something other than zeros"
    );
    // the hole stayed a hole rather than crossing as megabytes of zeros
    let blocks = fs::metadata(share.join("in/sparse.img")).unwrap().blocks() * 512;
    assert!(
        blocks < 1 << 20,
        "the sparse file occupies {blocks} bytes on the share, so the hole crossed as data"
    );

    // THE EMPTY DIRECTORY. This server sends `.` and `..` unstripped when a directory has
    // nothing else in it, so a client that did not filter them itself reports two phantom
    // children here -- and, since `..` is a directory, walks upward forever.
    assert!(
        share.join("in/hollow").is_dir(),
        "the empty directory did not cross"
    );
    let text = assert_passed(&rcp_smb(&cat, &["scan", "-noId", &dst]));
    assert!(
        !text.contains("hollow/."),
        "`.` or `..` reached the listing:\n{text}"
    );
    // said as a count too, because a name-substring check would miss a phantom that
    // happened to print differently
    assert!(
        text.contains("3 files"),
        "the scan does not see exactly the three files:\n{text}"
    );

    // THE NON-ASCII NAME, through UTF-16LE in both directions
    assert_eq!(
        fs::read(share.join("in/naïve dir/résumé.txt")).unwrap(),
        "café\n".as_bytes()
    );
    let back = s.path("back");
    assert_passed(&rcp_smb(
        &cat,
        &["copy", "-noId", &dst, back.to_str().unwrap()],
    ));
    assert_eq!(
        fs::read(back.join("naïve dir/résumé.txt")).unwrap(),
        "café\n".as_bytes(),
        "the non-ASCII name did not survive the round trip"
    );
    assert_eq!(fs::read(back.join("sparse.img")).unwrap().len(), 8 << 20);

    // THE NON-EMPTY DIRECTORY. `delete` without -force only counts, so this uses the
    // adapter directly: removing a directory that still has a child must be REFUSED, which
    // is the whole reason the delete path uses FileDispositionInformation.
    let tr = rcp::anytree::Transports::from_env(Arc::new(rcp::ports::Silent));
    let ep = rcp::Endpoint::parse(&dst).expect("the endpoint parses");
    let tree = rcp::anytree::AnyTree::open(&ep, false, &tr).expect("opens the share");
    let e = rcp::ports::Tree::remove(&tree, "naïve dir", rcp::catalog::Kind::Dir);
    match e {
        Ok(r) => panic!("removing a non-empty directory reported {r:?} instead of refusing"),
        Err(err) => assert!(
            err.to_string().contains("not empty"),
            "the refusal does not say the directory is not empty, so the reason is lost: {err}"
        ),
    }
    // THE CONTROL: the same call on the directory that IS empty succeeds, so the refusal
    // above is about emptiness rather than about directories, or about this client being
    // unable to remove anything at all.
    let r = rcp::ports::Tree::remove(&tree, "hollow", rcp::catalog::Kind::Dir)
        .expect("an empty directory is removable");
    assert!(
        !share.join("in/hollow").exists(),
        "remove reported {r:?} and the directory is still there"
    );

    // RENAME, which `sync` calls when it detects a moved file and which nothing else here
    // reaches. The payload is a `FileRenameInformation` whose FileName is SHARE-relative
    // with RootDirectory 0 -- the detail most easily got wrong, because the CREATE path
    // next to it takes the same shape of name and a leading separator is accepted there by
    // some servers and not others. Wrong, this silently renames into the wrong directory
    // or fails; either way nothing else in the suite would notice.
    rcp::ports::Tree::rename(&tree, "sparse.img", "moved/elsewhere.img")
        .expect_err("a rename into a directory that does not exist must fail");
    rcp::ports::Tree::mkdir(&tree, "moved").expect("mkdir");
    rcp::ports::Tree::rename(&tree, "sparse.img", "moved/elsewhere.img").expect("rename");
    assert!(
        !share.join("in/sparse.img").exists(),
        "the old name is still there after a rename"
    );
    assert_eq!(
        fs::metadata(share.join("in/moved/elsewhere.img"))
            .unwrap()
            .len(),
        8 << 20,
        "the renamed file is not the one that was renamed"
    );
    // and the name landed where it was asked to, not one level up -- the failure a
    // share-relative-versus-tree-relative mistake produces, which a bare "the file exists
    // somewhere" check would miss
    assert!(
        !share.join("in/elsewhere.img").exists(),
        "the rename resolved its name against the wrong root"
    );

    server.stop();
}

/// zstd crosses both wire directions, smaller than LZ4 and raw on text, and incompressible
/// data crosses raw with bounded framing. zstd is in every build, so this always runs, and
/// it asks with the `-compress-codec` spelling, which is how that alias stays exercised.
#[test]
fn zstd_measures_both_wire_directions_against_lz4_and_raw() {
    let s = Scratch::new("zstd-wire");
    let src = s.path("src");
    fs::create_dir_all(&src).unwrap();
    let text = b"the quick brown fox jumps over the lazy dog, again and again\n".repeat(150_000);
    fs::write(src.join("text.txt"), &text).unwrap();
    let (stub, wire_in, wire_out) = counting_stub(&s);
    let cat = s.path("catalog");
    let mut sizes = Vec::new();
    for codec in ["raw", "lz4", "zstd"] {
        let remote = s.path(codec);
        fs::create_dir_all(&remote).unwrap();
        let dst = format!("ssh://filer{}/dst", remote.display());
        let _ = fs::remove_file(&wire_in);
        let _ = fs::remove_file(&wire_out);
        let mut args = vec!["copy", "-noId", "-parallel", "1"];
        if codec != "raw" {
            args.extend(["-compress-codec", codec]);
        }
        args.extend([src.to_str().unwrap(), &dst]);
        assert_passed(&rcp_over_ssh(&cat, &stub, &args));
        let sent = wire_bytes(&wire_in);
        assert!(sent > 0);
        assert_eq!(fs::read(remote.join("dst/text.txt")).unwrap(), text);
        sizes.push(sent);
        if codec == "zstd" {
            fs::remove_file(&wire_in).unwrap();
            fs::remove_file(&wire_out).unwrap();
            let back = s.path("back");
            assert_passed(&rcp_over_ssh(
                &cat,
                &stub,
                &[
                    "copy",
                    "-noId",
                    "-parallel",
                    "1",
                    "-compress-codec",
                    "zstd",
                    &dst,
                    back.to_str().unwrap(),
                ],
            ));
            let received = wire_bytes(&wire_out);
            assert!(
                received > 0 && received < text.len() as u64 / 100,
                "{received} bytes received"
            );
            assert_eq!(fs::read(back.join("text.txt")).unwrap(), text);
        }
    }
    assert!(sizes[2] < sizes[1] && sizes[1] < sizes[0] / 10, "{sizes:?}");

    // Incompressible data must actually cross raw, with bounded framing overhead.
    fs::remove_file(src.join("text.txt")).unwrap();
    let random = noise(2 << 20, 71);
    fs::write(src.join("noise.bin"), &random).unwrap();
    fs::remove_file(&wire_in).unwrap();
    fs::remove_file(&wire_out).unwrap();
    let remote = s.path("noise");
    fs::create_dir_all(&remote).unwrap();
    let dst = format!("ssh://filer{}/dst", remote.display());
    assert_passed(&rcp_over_ssh(
        &cat,
        &stub,
        &[
            "copy",
            "-noId",
            "-parallel",
            "1",
            "-compress-codec",
            "zstd",
            src.to_str().unwrap(),
            &dst,
        ],
    ));
    let sent = wire_bytes(&wire_in);
    assert!(
        sent > random.len() as u64 && sent < random.len() as u64 + 16384,
        "{sent}"
    );
    assert_eq!(fs::read(remote.join("dst/noise.bin")).unwrap(), random);

    // the two spellings of the option cannot name two codecs at once
    let out = rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-compress.codec",
            "lz4",
            "-compress-codec",
            "zstd",
            src.to_str().unwrap(),
            &dst,
        ],
    );
    assert_failed(&out, "name two codecs");
}

/// A file standing where the source has a directory is replaced by `copy` and `resume`, as
/// `isync` and `sync` replace it, on local and NFS alike.
///
/// Without this, only the mirror modes replace one. A copy into a destination with a file `d`
/// where the source has a directory `d` fails with "File exists" on local, "exists and is not
/// a directory" on NFS v3 and v4, refuses everything beneath it, and says to run again once
/// the cause is fixed -- measured on all three. One entry replaced is the same size
/// of act as the overwrite a copy already makes of a file.
///
/// The REVERSE stays refused, and is the control: a directory where the source has a file is a
/// subtree the source never had, and a copy that removed it would be making a mirror's
/// decision. The dry run is the other control -- it plans the replacement and makes none.
#[test]
fn copy_and_resume_replace_a_file_standing_where_the_source_has_a_directory() {
    let s = Scratch::new("in-the-way");
    let src = s.path("src");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("d/x"), b"x\n").unwrap();
    // the reverse: the source has a FILE `f`, the destinations a directory `f` with content
    fs::write(src.join("f"), b"f\n").unwrap();
    let cat = s.path("cat");
    let plant = |root: &Path| {
        fs::create_dir_all(root.join("f")).unwrap();
        fs::write(root.join("f/keep"), b"not the source's\n").unwrap();
        fs::write(root.join("d"), b"in the way\n").unwrap();
    };
    let landed = |root: &Path, how: &str| {
        assert!(
            fs::symlink_metadata(root.join("d")).unwrap().is_dir(),
            "{how}: the file in the way is still there"
        );
        assert_eq!(fs::read(root.join("d/x")).unwrap(), b"x\n", "{how}");
        assert_eq!(
            fs::read(root.join("f/keep")).unwrap(),
            b"not the source's\n",
            "{how}: a directory in the way of a file was removed by a copy"
        );
    };

    let local = s.path("local");
    plant(&local);
    // the dry run plans the replacement, and makes none
    let dry = stdout(&rcp(
        &cat,
        &[
            "copy",
            "-noId",
            "-dryrun",
            src.to_str().unwrap(),
            local.to_str().unwrap(),
        ],
    ));
    assert!(
        dry.lines().any(|l| l == "# d"),
        "the plan does not show the replacement:\n{dry}"
    );
    assert!(
        !dry.lines().any(|l| l == "# f"),
        "the plan removes a directory a copy must not:\n{dry}"
    );
    assert!(
        fs::symlink_metadata(local.join("d")).unwrap().is_file(),
        "a dry run replaced the file"
    );
    // the copy replaces it, and still refuses the reverse by name
    assert_failed(
        &rcp(
            &cat,
            &[
                "copy",
                "-noId",
                src.to_str().unwrap(),
                local.to_str().unwrap(),
            ],
        ),
        "copy f",
    );
    landed(&local, "local copy");

    let export = s.path("export");
    fs::create_dir_all(&export).unwrap();
    let server = rcp::nfs::testserver::Server::start(&export).unwrap();
    for v in ["3", "4"] {
        let root = export.join(format!("copy{v}"));
        plant(&root);
        let dst = format!("127.0.0.1:/export:/copy{v}");
        assert_failed(
            &rcp_nfs(
                &cat,
                server.port,
                &["copy", "-noId", "-nfs.vers", v, src.to_str().unwrap(), &dst],
            ),
            "",
        );
        landed(&root, &format!("NFS v{v} copy"));
        // resume lists its destination, so the replacement is PLANNED there rather than
        // found by the mkdir. The first copy fails on the reverse conflict, which leaves a
        // job to resume; then `d` is turned back into a file before the resume runs.
        let root = export.join(format!("resume{v}"));
        plant(&root);
        let dst = format!("127.0.0.1:/export:/resume{v}");
        let id = format!("r{v}");
        assert_failed(
            &rcp_nfs(
                &cat,
                server.port,
                &[
                    "copy",
                    "-newid",
                    &id,
                    "-nfs.vers",
                    v,
                    src.to_str().unwrap(),
                    &dst,
                ],
            ),
            "",
        );
        fs::remove_dir_all(root.join("d")).unwrap();
        fs::write(root.join("d"), b"in the way again\n").unwrap();
        let text = assert_failed(
            &rcp_nfs(&cat, server.port, &["resume", "-id", &id]),
            "copy f",
        );
        landed(&root, &format!("NFS v{v} resume:\n{text}"));
    }
}
