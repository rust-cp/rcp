//! The executors: copy (with resume, sync and mirror as plans), verify, delete, chown, chmod
//! and estimate, all written against the `Tree` port. Every entry-level failure is collected
//! and reported, never fatal: a backup that copies 9,999 of 10,000 files and says which one
//! failed beats one that stops at the first.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::catalog::{Entry, Kind, Recorder};
use crate::filter::Filter;
use crate::human_bytes;
use crate::plan::{plan, Mode};
use crate::ports::{
    hash_zeros, index, Basis, Batches, Failure, FileOptions, FileOutcome, Item, Listing, Log,
    MetaOptions, Names, Patch, Removed, Runtime, Segment, Sink, Tree,
};

/// Which file engine the copy uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// io_uring where the adapter and kernel allow it, threads otherwise.
    Auto,
    Threads,
    Uring,
}

/// What to do about ownership, which only root can fully preserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Try; a refusal is counted and reported as a warning.
    Preserve,
    /// A refusal fails the entry (`-chown`).
    Require,
    /// Never attempt it (`-noown`).
    Skip,
}

#[derive(Debug, Clone)]
pub struct CopyOptions {
    pub parallel: usize,
    /// `-parallel auto`: `parallel` is a ceiling and a tuner moves the active worker count.
    pub auto_parallel: bool,
    pub filter: Filter,
    pub max_depth: Option<usize>,
    /// Record the SHA-256 of every file in the catalog. Off, the kernel copies the bytes
    /// without them passing through user space.
    pub hash: bool,
    pub hard_links: bool,
    pub xattrs: bool,
    pub ownership: Ownership,
    pub preserve_atime: bool,
    pub fsync: bool,
    pub block_size: usize,
    pub nocache: bool,
    pub engine: Engine,
    /// Send a file the destination already has as a patch against it (`-delta`).
    pub delta: bool,
    /// Plan and report, write nothing.
    pub dry_run: bool,
    /// In a dry run, also check that the destination still matches the catalog (`-target`).
    pub dry_run_target: bool,
    /// In a dry run, report tree statistics over what would be transferred (`-stats`).
    pub dry_run_stats: bool,
    /// Print a progress line to stderr every few seconds and once at the end.
    pub progress: bool,
    /// Hand the file batches to worker processes on other hosts (`-nodes`, `-copybatch`).
    pub fleet: Option<std::sync::Arc<dyn Batches>>,
    /// The plan digest the caller says it has read (`-confirm`); checked whenever it is
    /// given, and required when `require_confirm` and the plan would remove or overwrite.
    pub confirm: Option<String>,
    /// Refuse a destructive run that carries no matching `confirm` (`-requireconfirm`,
    /// `RCP_REQUIRE_CONFIRM`), which is how a caller that is a program is bounded.
    pub require_confirm: bool,
    /// The run's digest, throttle, log and names.
    pub runtime: Runtime,
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            parallel: 2,
            auto_parallel: false,
            filter: Filter::default(),
            max_depth: None,
            hash: true,
            hard_links: true,
            xattrs: true,
            ownership: Ownership::Preserve,
            preserve_atime: false,
            fsync: false,
            block_size: 1 << 20,
            nocache: false,
            engine: Engine::Auto,
            delta: false,
            dry_run: false,
            dry_run_target: false,
            dry_run_stats: false,
            progress: false,
            fleet: None,
            confirm: None,
            require_confirm: false,
            runtime: Runtime::plain(),
        }
    }
}

impl CopyOptions {
    pub fn file_options(&self) -> FileOptions {
        FileOptions {
            block_size: self.block_size.max(4096),
            hash: self.hash,
            meta: MetaOptions {
                mode: true,
                times: true,
                owner: self.ownership != Ownership::Skip,
                atime: self.preserve_atime,
            },
            xattrs: self.xattrs,
            fsync: self.fsync,
            nocache: self.nocache,
            preserve_atime: self.preserve_atime,
            delta: self.delta,
            stages: None,
            runtime: self.runtime.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub struct CopyReport {
    pub copied_files: usize,
    pub copied_bytes: u64,
    pub linked: usize,
    pub skipped_files: usize,
    pub skipped_bytes: u64,
    pub directories: usize,
    pub symlinks: usize,
    pub removed: usize,
    /// Entries the destination will remove itself, later. See `DeleteReport::deferred`.
    pub deferred: Vec<String>,
    /// Entries the destination refused to remove -- it answered without an error and kept
    /// them. See `DeleteReport::kept`; the sync did not reach the state it was asked for.
    pub kept: Vec<String>,
    /// Files renamed or moved on the destination instead of copied again (sync).
    pub moved: usize,
    /// Files sent as a patch against the destination's copy, and the literal bytes those
    /// patches carried (`-delta`).
    pub delta_files: usize,
    pub delta_literal: u64,
    /// The short name of the plan this run made: what `-confirm` takes (see `plan_digest`).
    pub plan_digest: String,
    pub owner_refused: usize,
    pub xattr_refused: usize,
    pub failures: Vec<Failure>,
    pub warnings: Vec<String>,
    pub engine: &'static str,
    pub seconds: f64,
    pub dry_run: bool,
    /// Dry run: one line per planned action (`+` new, `*` changed, `=` link, `#` removed).
    pub planned: Vec<String>,
    /// Dry run with `-target`: catalog entries the destination no longer matches.
    pub target_mismatches: Vec<String>,
    /// Dry run with `-stats`: the statistics report over everything new or changed.
    pub planned_stats: Option<String>,
}

impl CopyReport {
    /// A refused removal is a failure of the run: `sync` was asked to make the destination
    /// match the source, and an entry the store refused to remove means it does not.
    pub fn ok(&self) -> bool {
        self.failures.is_empty() && self.kept.is_empty()
    }
}

/// AN ENTRY OF THE WRONG KIND IS IN THE WAY, not merely out of date. A mirror whose destination
/// had a file `a` where the source has a directory `a` failed with "File exists" and then "Not a
/// directory" for everything under it, and told the operator to run it again -- which fails the
/// same way forever. The other direction -- a directory where the source has a file -- failed
/// the same way. rsync replaces the entry.
///
/// A non-directory in the way of a directory goes BEFORE the directories are made. That includes
/// a symlink, and it has to: left in place, the copy of `a/x` would open through it and write
/// wherever it points. A directory in the way of a file or symlink joins the removals, which run
/// children first, so whatever the planner found gone inside it is cleared before it; anything
/// else left inside stops it as a non-empty directory.
///
/// Judged against EVERY destination entry at the path, not the attribute-filtered view: an
/// obstacle is in the way whatever its size or owner, and the filtered view hid an empty file
/// under `-minsize 1` standing where the source has a directory.
/// Whether `rel` lies under one of `blocked` -- directories whose mkdir failed. The root failing
/// blocks everything.
fn beneath(rel: &str, blocked: &[String]) -> bool {
    blocked.iter().any(|b| {
        b == "."
            || (rel.len() > b.len()
                && rel.starts_with(b.as_str())
                && rel.as_bytes()[b.len()] == b'/')
    })
}

fn not_beneath() -> io::Error {
    io::Error::other("not written: a directory above it could not be made, so what stands there is not the directory the plan made")
}

///
/// `copy` and `resume` take the first half only (`dirs_too` false): a file or symlink where the
/// source has a directory is ONE entry replaced, the same size of act as the overwrite `copy`
/// already makes of a file, and refusing it failed the run with "File exists" on every transport.
/// A directory where the source has a file is a subtree the source never had, and removing it
/// is a mirror's decision, not a copy's; that stays a loud failure.
/// The directories `items` needs but does not list: every parent of an entry that is not
/// itself an entry. See where `copy_tree` plans them.
fn implied_parents(items: &[Item]) -> Vec<Item> {
    let named: std::collections::BTreeSet<&str> = items.iter().map(|i| i.rel.as_str()).collect();
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for i in items {
        let mut rel = i.rel.as_str();
        while let Some((parent, _)) = rel.rsplit_once('/') {
            if parent.is_empty()
                || parent == "."
                || named.contains(parent)
                || !out.insert(parent.to_string())
            {
                break;
            }
            rel = parent;
        }
    }
    out.into_iter()
        .map(|rel| Item {
            rel,
            kind: Kind::Dir,
            size: 0,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: 0,
            link_target: None,
        })
        .collect()
}

fn in_the_way(
    p: &mut crate::plan::Plan<'_>,
    source: &[Item],
    dst_seen: &BTreeMap<&str, &Item>,
    dirs_too: bool,
) {
    for item in source {
        if let Some(d) = dst_seen.get(item.rel.as_str()) {
            if (item.kind == Kind::Dir) != (d.kind == Kind::Dir) {
                if d.kind == Kind::Dir {
                    if !dirs_too {
                        continue;
                    }
                    if !p.remove.iter().any(|(r, _)| r == &item.rel) {
                        p.remove.push((item.rel.clone(), Kind::Dir));
                    }
                } else {
                    p.clear.push((item.rel.clone(), d.kind));
                }
            }
        }
    }
    p.remove
        .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(b.0.cmp(&a.0)));
}

/// One line per planned action, in the order the run would take them: `+` a new file,
/// `*` one the destination already has, `+d` a directory, `+l` a symlink, `=` a hard
/// link, `>` a file the source moved, `#` an entry to remove, `?` a part of the destination
/// its listing could not read. Built for every run, not
/// just a dry one, because the plan digest and the dry-run report must describe the same
/// plan or the digest is worth nothing.
fn plan_lines(
    mode: Mode,
    p: &crate::plan::Plan<'_>,
    dst_index: &BTreeMap<&str, &Item>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(p.copy.len() + p.remove.len() + p.dirs.len());
    // what is in the way comes out first, as the executor takes it
    for (rel, _) in &p.clear {
        out.push(format!("# {rel}"));
    }
    for d in &p.dirs {
        if !dst_index.contains_key(d.rel.as_str()) && mode != Mode::Fresh {
            out.push(format!("+d {}", d.rel));
        }
    }
    for f in &p.copy {
        out.push(format!(
            "{} {}",
            if dst_index.contains_key(f.rel.as_str()) {
                "*"
            } else {
                "+"
            },
            f.rel
        ));
    }
    for (f, target) in &p.link {
        out.push(format!("= {} -> {target}", f.rel));
    }
    for (f, from, _) in &p.moves {
        out.push(format!("> {} <- {from}", f.rel));
    }
    for s in &p.symlinks {
        if dst_index
            .get(s.rel.as_str())
            .is_none_or(|d| d.kind != Kind::Symlink || d.link_target != s.link_target)
        {
            out.push(format!("+l {}", s.rel));
        }
    }
    for (rel, _) in &p.remove {
        out.push(format!("# {rel}"));
    }
    out
}

/// A short name for exactly what a run would do: the two endpoints and every planned
/// action, under the run's own digest. A change that alters the PLAN since it was printed
/// -- a file added, removed, or moved into or out of the overwrite set -- produces a
/// different name, which is the property `-confirm` rests on. A change the plan does not
/// show (new content under the same planned overwrite, anything outside the run's scope)
/// does not: the digest names the actions, not a snapshot of either tree.
pub fn plan_digest(
    runtime: &Runtime,
    source: &std::path::Path,
    destination: &std::path::Path,
    lines: &[String],
) -> String {
    let mut h = runtime.hasher();
    h.update(source.display().to_string().as_bytes());
    h.update(b"\n");
    h.update(destination.display().to_string().as_bytes());
    h.update(b"\n");
    for l in lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    h.finish().chars().take(16).collect()
}

/// One dimension the tuner can move: its current value, and the gradient state that says
/// which way to go next and how far.
///
/// `read` and `write` a `Gate`'s limit; `workers` the admitted worker count. They are the
/// same kind of thing to the search -- an integer with a throughput response -- which is
/// why one routine drives all three rather than three copies of the same loop.
struct Knob<'a> {
    name: &'static str,
    get: Box<dyn Fn() -> usize + Send + Sync + 'a>,
    set: Box<dyn Fn(usize) + Send + Sync + 'a>,
    ceiling: usize,
    direction: i64,
    step: usize,
    improving: u32,
}

impl<'a> Knob<'a> {
    fn new(
        name: &'static str,
        ceiling: usize,
        get: impl Fn() -> usize + Send + Sync + 'a,
        set: impl Fn(usize) + Send + Sync + 'a,
    ) -> Knob<'a> {
        Knob {
            name,
            get: Box::new(get),
            set: Box::new(set),
            ceiling: ceiling.max(1),
            direction: 1,
            step: 1,
            improving: 0,
        }
    }
}

/// The online tuner behind `-parallel auto`, after Marlin (Arifuzzaman and Arslan, ICS'23)
/// and FastBioDL (arXiv 2508.05511): every half second the throughput of the window is
/// compared with the previous one, the knob under test moves one step in the direction that
/// helped and reverses when it does not, the step growing while a direction keeps paying and
/// resetting on a reversal. Each knob is bounded to `1..=ceiling`, and the loop stops once
/// every file has been claimed.
///
/// **A move is kept only if it PAID, and paid twice.** Three rules, all three added on
/// 2026-09-24 after a knob that appears nowhere in the rate was measured walking across its
/// whole range, and all three anchored by `a_knob_with_nothing_to_gain_holds_still`:
///
/// - a window that is merely FLAT is undone, not kept -- keeping it is a ratchet, because a
///   knob with no effect reads flat in whichever direction it happens to point;
/// - the margin that separates "better" from "flat" is the larger of 3% and three times the
///   measured noise, where the noise is sampled for free from windows that re-read a
///   configuration the search has already read;
/// - an improvement is not acted on until a SECOND window at the same setting confirms
///   it, because the tail of the noise distribution is fatter than any multiple of its
///   spread;
/// - then the OLD setting is re-read for one window (A/B/A), because both windows came
///   after the move, and a step change in the machine's load between the baseline and the
///   probe reads as a gain in both. Added 2026-09-28, when a saturated four-core run walked
///   the knob-with-nothing-to-gain to its ceiling in 1 of 30 runs, keeping 6 of 77 probes;
/// - and the move, re-applied, must beat that re-read once more (A/B/A/B), because a load
///   PULSE covering exactly the probe and confirm windows passes A/B/A. A move
///   measured against a window that moved nothing is not kept at all.
///
/// **With more than one knob it is coordinate descent**: one dimension is moved per window,
/// round-robin, each carrying its own direction and step. That is the whole reason the
/// stages exist. A single worker count cannot express "read wider, write narrower", and a
/// sink whose throughput peaks at a low queue depth -- a contended device, a rate-limited
/// endpoint -- wants exactly that while the source wants the opposite.
///
/// **The move is evaluated one window LATER, against the knob that made it.** The
/// single-knob loop this grew out of compared a window to the previous one and applied the
/// verdict to the knob it was about to move, which is correct only when there is exactly
/// one knob. Generalized naively it credits knob B with knob A's effect and the search
/// walks a landscape it is not measuring -- worse than useless, because it still converges
/// and still logs decisions. So a move is remembered (`pending`, with the value it came
/// from), the NEXT window measures it, and a move that hurt is reversed and **undone**.
/// `the_tuner_attributes_a_rate_change_to_the_knob_that_caused_it` is the arm.
///
/// `window` is a parameter rather than a constant so a test can run the same search at a
/// speed a test can afford. Production passes `TUNE_WINDOW`.
/// Folds one noise sample into the running estimate, FAST UP AND SLOW DOWN.
///
/// A symmetric average is the wrong shape for a threshold that exists to keep the search
/// from acting on noise. When the machine gets busier the noise steps up at once, and an
/// estimate that needs four samples to notice spends those four samples deciding by coin
/// flip -- which is the entire failure being guarded against, arriving exactly when it is
/// most likely. Rising quickly costs only some search speed while the burst lasts; falling
/// slowly costs nothing at all once it is over.
fn blend(noise: f64, seen: f64, seen_count: u32) -> f64 {
    if seen_count == 0 {
        return seen;
    }
    let w = if seen > noise { 0.5 } else { 0.1 };
    (1.0 - w) * noise + w * seen
}

fn tune(
    knobs: &mut [Knob<'_>],
    window: Duration,
    progress: &Progress,
    next: &AtomicUsize,
    files: usize,
    finished: &AtomicBool,
    log: &dyn Log,
) {
    let poll = (window / 10).max(Duration::from_millis(1));
    let mut last_bytes = progress.bytes.load(Ordering::Relaxed);
    let mut last_rate = 0.0f64;
    let mut turn = 0usize;
    // What is in flight for the window about to be measured: which knob, what it was before
    // the move, which stage of judging it we are at, and the rate it is being judged
    // against. `Probe` is the moved configuration's first window, `Confirm` its second, and
    // `Undo` the window that runs after the move has been put back.
    #[derive(PartialEq)]
    enum Stage {
        Probe,
        Confirm,
        Undo,
        /// The move was better twice and has been put back to re-read the old setting:
        /// `now` is the value to restore if it really paid, `confirmed` the rate it showed.
        Recheck {
            now: usize,
            confirmed: f64,
        },
        /// The move has been re-applied after a recheck that found the old setting slower;
        /// this window must show the move ahead of that recheck AGAIN before it is kept
        /// (A/B/A/B). `baseline` in `pending` is the recheck's rate.
        Settle,
    }
    let mut pending: Option<(usize, usize, Stage, f64)> = None;
    // How far two measurements of the SAME configuration differ, as a fraction, averaged
    // over the undo windows -- see the verdict below for why those are free samples of it.
    let (mut noise, mut noise_seen) = (0.0f64, 0u32);
    // THE FIRST TWO WINDOWS MEASURE THE NOISE RATHER THAN GUESSING AT IT. Nothing is probed
    // in them, so they are two readings of one configuration and their difference is a
    // sample of exactly the quantity the margin below needs. The cost is two windows before
    // the search starts; the alternative is to decide the first few probes against a fixed
    // 3% that may be inside the noise, and those early probes are the ones that set the
    // direction everything after them follows.
    let mut warmup = 2u32;
    while !finished.load(Ordering::Relaxed) && next.load(Ordering::Relaxed) < files {
        let t = Instant::now();
        while t.elapsed() < window && !finished.load(Ordering::Relaxed) {
            std::thread::sleep(poll);
        }
        // A WINDOW THE COPY CUT SHORT GETS NO VERDICT. It measured a fraction of a window, often
        // the last burst of a draining queue, and a re-applied move judged on it could be kept
        // with nothing left to take it back. The restore below the loop puts
        // back whatever was still being judged.
        if finished.load(Ordering::Relaxed) {
            break;
        }
        let bytes = progress.bytes.load(Ordering::Relaxed);
        let rate = (bytes - last_bytes) as f64 / t.elapsed().as_secs_f64();
        last_bytes = bytes;

        // verdict on the probe that was in flight for the window just measured
        if let Some((j, was, stage, baseline)) = pending.take() {
            if stage == Stage::Settle {
                // THE FINAL B. The recheck showed the old setting slower than the confirm
                // window, but a load PULSE that covers exactly the probe and confirm windows
                // and ends before the recheck reads the same way (100 / 150 / 150 / 100
                // keeps a knob that does nothing). The move, re-applied, has to beat the
                // recheck once more -- in the window A/B/A already paid for.
                let margin = (3.0 * noise).clamp(0.03, 0.25);
                let k = &mut knobs[j];
                let now = (k.get)();
                if baseline > 0.0 && rate > baseline * (1.0 + margin) {
                    k.improving += 1;
                    if k.improving >= 2 {
                        k.step = (k.step * 2).min(4);
                    }
                    crate::debug!(log, "tune: {} {} -> {} better, rechecked and re-read, keeping, {:.1} MiB/s against {:.1} (margin {:.1}%)", k.name, was, now, rate / (1024.0 * 1024.0), baseline / (1024.0 * 1024.0), margin * 100.0);
                    last_rate = rate;
                } else {
                    k.direction = -k.direction;
                    k.step = 1;
                    k.improving = 0;
                    (k.set)(was);
                    crate::debug!(log, "tune: {} {} -> {} better, but not again when re-applied; undoing, {:.1} MiB/s (margin {:.1}%)", k.name, was, now, rate / (1024.0 * 1024.0), margin * 100.0);
                    last_rate = rate;
                    pending = Some((j, now, Stage::Undo, baseline));
                    continue;
                }
            } else if let Stage::Recheck { now, confirmed } = stage {
                // THE OLD SETTING, RE-READ. It ran in the window that produced `baseline`
                // too, so the two differ only by noise -- a free sample -- UNLESS the load on
                // the machine changed, which is exactly what this window is here to catch:
                // a move judged against a baseline taken before a step change in ambient
                // load reads "better" in its probe AND its confirm window, because both came
                // after the change. Measured under a saturated four-core run: a knob that
                // appears nowhere in the rate kept 6 of 77 probes and walked to its ceiling.
                // If the old setting is now as fast as the move was, the gain was the
                // machine's, not the knob's.
                let margin = (3.0 * noise).clamp(0.03, 0.25);
                let k = &mut knobs[j];
                // The old setting has to read AS IT DID, within the margin, and not merely
                // slower than the move. A re-read well below its baseline is the load moving
                // the other way, and taking it as "no step" would hand the final re-read an
                // easy bar to beat: 100 / 150 / 150 / 50 / 100 would keep a knob that does
                // nothing, because 100 beats 50. And 100 then 120 at one setting is a
                // partial step, not noise, so only a re-read inside the margin is sampled;
                // sampled unconditionally, a step the recheck had just caught goes into the
                // estimate and pushes the margin to its cap.
                let as_it_was =
                    baseline > 0.0 && rate > 0.0 && (rate / baseline - 1.0).abs() <= margin;
                // a re-read inside the margin is a noise sample whether or not the move then
                // beats it, so it is not dropped when the move does not
                if as_it_was {
                    noise = blend(noise, (rate / baseline - 1.0).abs(), noise_seen);
                    noise_seen += 1;
                }
                if as_it_was && confirmed > rate * (1.0 + margin) {
                    (k.set)(now);
                    crate::debug!(log, "tune: {} {} -> {} better, rechecked, re-applying, {:.1} MiB/s against {:.1} (margin {:.1}%)", k.name, was, now, confirmed / (1024.0 * 1024.0), rate / (1024.0 * 1024.0), margin * 100.0);
                    last_rate = rate;
                    // The bar for the final re-read is the HIGHER of the two readings of the
                    // old setting. The recheck may sit a whole margin under its baseline and
                    // still count as "read as it did", and judged against the recheck alone
                    // that margin is spent twice: 100 / 150 / 150 / 79 / 100 would keep a
                    // knob that does nothing, the final window only returning to where it
                    // began.
                    pending = Some((j, was, Stage::Settle, rate.max(baseline)));
                    continue;
                }
                k.direction = -k.direction;
                k.step = 1;
                k.improving = 0;
                if as_it_was {
                    crate::debug!(log, "tune: {} {} -> {} better, but {} re-read as fast as the move, so the load moved and not the knob; undoing, {:.1} MiB/s against {:.1} (margin {:.1}%)", k.name, was, now, was, rate / (1024.0 * 1024.0), confirmed / (1024.0 * 1024.0), margin * 100.0);
                } else {
                    crate::debug!(log, "tune: {} {} -> {} better, but {} did not re-read as it did, so the load moved and not the knob; undoing, {:.1} MiB/s against {:.1} (margin {:.1}%)", k.name, was, now, was, rate / (1024.0 * 1024.0), baseline / (1024.0 * 1024.0), margin * 100.0);
                }
                // the knob is back at `was`, which this window just measured: a fresh
                // baseline for the next probe, with nothing left to settle
                last_rate = rate;
            } else if stage == Stage::Undo {
                // An undo: its effect is known by construction, and judging it would count
                // the reversal as an improvement and grow the step for going backwards.
                //
                // IT IS ALSO A FREE SAMPLE OF THE MEASUREMENT NOISE, and that is the whole
                // reason the margin below can adapt. This window runs at the configuration
                // the probe was launched FROM, and so did the window that produced
                // `baseline` -- same knobs, two windows apart -- so their difference is
                // noise and nothing else. Every undo yields one, at no cost, from windows
                // the search was spending anyway.
                if baseline > 0.0 && rate > 0.0 {
                    noise = blend(noise, (rate / baseline - 1.0).abs(), noise_seen);
                    noise_seen += 1;
                }
                last_rate = rate;
            } else {
                // A VERDICT IS ONLY WORTH MAKING IF IT BEATS THE NOISE. The fixed 3% this
                // used alone is a guess about a quantity the loop can measure, and on this
                // repository's own test rig the guess is wrong: two windows of an unchanged
                // configuration differ by about 2%, so 3% is barely one standard deviation
                // of the DIFFERENCE between two of them. Measured before this margin
                // existed, on a landscape where one knob appears nowhere in the rate at all:
                // 19 of that knob's 80 probes came back "better" and were kept, and it
                // random-walked across its whole range on pure noise.
                //
                // So the margin is the larger of 3% and three times the observed noise,
                // which costs nothing when the link is steady and refuses to decide when it
                // is not. The estimate starts from the warm-up windows above, so it is in
                // force from the first probe rather than after the search has already
                // committed to a direction on a guess.
                if stage == Stage::Confirm && last_rate > 0.0 && rate > 0.0 {
                    // the confirm window re-reads the SAME configuration the probe window
                    // read, so the two differ only by noise -- another free sample
                    noise = blend(noise, (rate / last_rate - 1.0).abs(), noise_seen);
                    noise_seen += 1;
                }
                // ...and CAPPED, because a margin that grows without limit is a tuner that
                // stops tuning. On a machine noisy enough to push it past a quarter, the
                // moves being refused are large real gains, and the confirming window below
                // already makes a spurious one of those need two excursions in a row.
                let margin = if noise_seen > 0 {
                    (3.0 * noise).clamp(0.03, 0.25)
                } else {
                    0.03
                };
                let k = &mut knobs[j];
                let now = (k.get)();
                if baseline > 0.0 && rate > baseline * (1.0 + margin) {
                    if stage == Stage::Probe {
                        // ONE GOOD WINDOW IS NOT A RESULT. The margin above rules out the
                        // noise this rig can measure; a second window at the same setting,
                        // against the same baseline, rules out the excursion it cannot --
                        // scheduling hiccups make the tail of that distribution fatter than
                        // any fixed multiple of a standard deviation covers. Measured with
                        // the margin alone and no confirmation, on a knob that appears
                        // nowhere in the rate: 1, 3 and 6 kept moves across three runs, the
                        // last two of which walked the knob over all six of its values.
                        //
                        // It costs one window per improvement, and only per IMPROVEMENT --
                        // a probe that fails outright is undone as before.
                        crate::debug!(
                            log,
                            "tune: {} {} -> {} better, confirming, {:.1} MiB/s (margin {:.1}%)",
                            k.name,
                            was,
                            now,
                            rate / (1024.0 * 1024.0),
                            margin * 100.0
                        );
                        last_rate = rate;
                        pending = Some((j, was, Stage::Confirm, baseline));
                        continue;
                    }
                    // BETTER TWICE, AND STILL NOT A RESULT: both windows came after the move,
                    // so a step change in the machine's load between the baseline and the
                    // probe reads as a gain in both. Put the old setting back for one window
                    // and see whether it is as fast now (`Stage::Recheck`).
                    (k.set)(was);
                    crate::debug!(log, "tune: {} {} -> {} better twice, rechecking {}, {:.1} MiB/s (margin {:.1}%)", k.name, was, now, was, rate / (1024.0 * 1024.0), margin * 100.0);
                    last_rate = rate;
                    pending = Some((
                        j,
                        was,
                        Stage::Recheck {
                            now,
                            confirmed: rate,
                        },
                        baseline,
                    ));
                    continue;
                } else if baseline > 0.0 {
                    // A MOVE IS KEPT ONLY IF IT PAID. Worse and flat are both undone, and
                    // the flat half of that matters: keeping a flat move ("a flat window
                    // holds") is a RATCHET. A knob that changes nothing measures flat in
                    // whichever direction it is pointing, so it walks -- and
                    // `a_knob_with_nothing_to_gain_holds_still` caught the real thing doing
                    // it, a knob that appears nowhere in the rate stepping
                    // `1 -> 2 flat, keeping` then `2 -> 3 flat, keeping` and on across the
                    // range. In production that is `-parallel auto` opening readers and
                    // writers no measurement asked for, which on a contended device is not
                    // merely wasteful.
                    //
                    // It is also the best explanation for a failure that looked like bad
                    // attribution: under a parallel suite run,
                    // `the_tuner_attributes_a_rate_change_to_the_knob_that_caused_it` came
                    // back `4 readers (want 6) and 1 writers (want 1)` -- the write knob
                    // exactly right and the read knob stalled three steps short of a
                    // ceiling it should have climbed to. The path that run took was not
                    // traced, so this is the mechanism that fits rather than the mechanism
                    // that was watched; what WAS watched is the same knob-with-no-signal
                    // behavior on a landscape built to isolate it.
                    //
                    // WHAT IT COSTS, since it is a real trade: a landscape with a flat SHELF
                    // before a rise is now uncrossable, because the step only grows after an
                    // improvement, so a stalled knob probes one at a time and undoes each
                    // time. The trade is taken this way because a shelf is speculative and
                    // the drift was measured; and because refusing to spend concurrency that
                    // buys nothing is the behavior wanted from a tuner in the first place.
                    k.direction = -k.direction;
                    k.step = 1;
                    k.improving = 0;
                    (k.set)(was);
                    let verdict = if rate < baseline * (1.0 - margin) {
                        "worse"
                    } else {
                        "flat"
                    };
                    crate::debug!(
                        log,
                        "tune: {} {} -> {} {verdict}, undoing, {:.1} MiB/s (margin {:.1}%)",
                        k.name,
                        was,
                        now,
                        rate / (1024.0 * 1024.0),
                        margin * 100.0
                    );
                    // The undo IS a configuration change, so it gets its own window. Doing
                    // it and also probing the next knob would leave two knobs different
                    // between consecutive windows, and the next verdict would be about
                    // both -- which is precisely the attribution error this loop exists to
                    // avoid, reintroduced one level down. Measured: with the undo folded
                    // into the same window, the write knob in
                    // `the_tuner_attributes_a_rate_change_to_the_knob_that_caused_it`
                    // settles at 4 of a wanted 1, because each undo cancels the next
                    // knob's move in the arithmetic.
                    last_rate = rate;
                    pending = Some((j, now, Stage::Undo, baseline));
                    continue;
                } else {
                    // NO BASELINE: nothing moved in the window before the probe. A move with
                    // no measurement behind it is not kept. Keeping it ("the move stands")
                    // is tempting, but a zero-throughput window is not only the first one (a
                    // run of empty files, a server that has not sent a byte yet), so every
                    // probe would be kept and the knobs would walk their ranges on no
                    // evidence at all.
                    k.improving = 0;
                    (k.set)(was);
                    crate::debug!(
                        log,
                        "tune: {} {} -> {} unmeasured, undoing, {:.1} MiB/s",
                        k.name,
                        was,
                        now,
                        rate / (1024.0 * 1024.0)
                    );
                    last_rate = rate;
                    pending = Some((j, now, Stage::Undo, baseline));
                    continue;
                }
            }
        } else {
            if warmup > 0 {
                warmup -= 1;
                if last_rate > 0.0 && rate > 0.0 {
                    // two windows, one configuration: a noise sample by construction
                    noise = blend(noise, (rate / last_rate - 1.0).abs(), noise_seen);
                    noise_seen += 1;
                }
                last_rate = rate;
                continue;
            }
            last_rate = rate;
        }

        // and the next probe, on the next knob in turn
        let j = turn % knobs.len();
        turn += 1;
        let k = &mut knobs[j];
        let was = (k.get)();
        let mut moved = (was as i64 + k.direction * k.step as i64).clamp(1, k.ceiling as i64);
        if moved == was as i64 {
            // pinned at a bound: turn around so this window probes the other way instead
            // of spending it on a move that is not a move
            k.direction = -k.direction;
            k.step = 1;
            moved = (was as i64 + k.direction).clamp(1, k.ceiling as i64);
        }
        if moved != was as i64 {
            (k.set)(moved as usize);
            pending = Some((j, was, Stage::Probe, last_rate));
        }
    }
    // THE COPY ENDED WITH A VERDICT OWED. A probe, a confirm or a re-applied move still in
    // flight is a setting no window has judged, and the workers still finishing their files
    // run under it: without this, "no measurement, no move" would hold for every window but
    // the last. Put back the setting that was measured. A recheck has already done so, and
    // an undo's knob is already back.
    if let Some((j, was, stage, _)) = pending {
        if matches!(stage, Stage::Probe | Stage::Confirm | Stage::Settle) {
            (knobs[j].set)(was);
        }
    }
}

/// How long a window of the tuner's search is. Long enough that a window's throughput is a
/// measurement rather than a sample of one file's startup, short enough that a run of a few
/// seconds still gets several probes per knob.
const TUNE_WINDOW: Duration = Duration::from_millis(500);

/// Below this size a patch costs more round trips than the bytes are worth.
const DELTA_MIN: u64 = 64 << 10;

/// Copies one file through the port: as a patch when `-delta` asks and the destination has
/// a file to patch, else a kernel copy when no hash is wanted and the adapter can, else the
/// segment stream, hashed as it passes.
pub fn copy_one<T: Tree>(
    src: &T,
    dst: &T,
    item: &Item,
    opts: &FileOptions,
    buf: &mut [u8],
) -> io::Result<FileOutcome> {
    let xattrs = if opts.xattrs {
        src.xattrs(&item.rel)?
    } else {
        Vec::new()
    };
    if opts.delta && item.kind == Kind::File && item.size >= DELTA_MIN {
        if let Some(existing) = dst.stat(&item.rel)? {
            if existing.kind == Kind::File && existing.size >= DELTA_MIN {
                // a patch is an optimization: whatever stops it (an adapter without one, a
                // basis that changed, a temporary file that cannot be made, a digest that
                // did not check) the whole copy below is still correct, and a failure that
                // would stop that too reports there
                match patch_one(src, dst, item, &existing, opts, &xattrs) {
                    Ok(o) => return Ok(o),
                    Err(e) => {
                        crate::debug!(opts.runtime.log, "delta {}: {e}; copying whole", item.rel)
                    }
                }
            }
        }
    }
    // Open the source before the destination is created. `create_file` truncates an
    // existing file, so a source that is already gone would otherwise destroy the copy.
    if src.stat(&item.rel)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: no such file", item.rel),
        ));
    }
    let mut sink = dst.create_file(item)?;
    let mut sha256 = None;
    // an adapter that can move the bytes itself (or already has them) says so; one that
    // cannot digest them declines when a hash is wanted
    let in_kernel = src.kernel_copy(&item.rel, &mut sink, opts)?;
    if in_kernel.is_none() {
        sink.reserve(item.size)?;
        let mut hasher = opts.runtime.hasher();
        let hash = opts.hash;
        // The two-stage path (`-parallel auto`). The permit is taken around the whole
        // `read` and handed back for the duration of each write, so a thread is counted in
        // exactly one stage at a time and the two limits stay independent. Hashing and the
        // throttle sit on the read side because they are costs of producing the bytes, not
        // of placing them.
        //
        // `None` -- every fixed `-parallel N` -- takes no permits and runs the same code
        // this path ran before the stages existed. That is deliberate and asserted: the
        // decomposition is a tuner feature, and a run that asked for a fixed worker count
        // should not inherit a second gate it never asked for.
        let stages = opts.stages.as_deref();
        let mut held = stages.map(|s| s.read.enter());
        let streamed = src.read(&item.rel, buf, &mut |seg| match seg {
            Segment::Data(d) => {
                opts.runtime.throttle.take(d.len() as u64);
                if hash {
                    hasher.update(d);
                }
                match stages {
                    Some(s) => s.write_within_read(&mut held, || sink.write(d)),
                    None => sink.write(d),
                }
            }
            Segment::Hole(n) => {
                if hash {
                    hash_zeros(&mut *hasher, n);
                }
                match stages {
                    Some(s) => s.write_within_read(&mut held, || sink.hole(n)),
                    None => sink.hole(n),
                }
            }
        });
        // before `?`: a read that failed must still give the permit back, or one error
        // leaks a slot out of the read gate for the rest of the run
        drop(held);
        streamed?;
        if hash {
            sha256 = Some(hasher.finish());
        }
    }
    let refusals = sink.finish(item, &xattrs, opts.meta, opts.fsync)?;
    if opts.nocache {
        sink.drop_cache();
    }
    if opts.preserve_atime {
        if let Err(e) = src.restore_atime(item) {
            eprintln!("WARN: atime not restored on {}: {e}", item.rel);
        }
    }
    Ok(FileOutcome {
        bytes: item.size,
        sha256,
        refusals,
        literal: None,
    })
}

/// Sends `item` as a patch against `existing`: the destination signs its copy, the source
/// matches and streams the patch, the destination rebuilds beside the old file and checks
/// the digest before replacing it.
fn patch_one<T: Tree>(
    src: &T,
    dst: &T,
    item: &Item,
    existing: &Item,
    opts: &FileOptions,
    xattrs: &[(String, Vec<u8>)],
) -> io::Result<FileOutcome> {
    let params = crate::delta::params_for(existing.size.max(item.size));
    let basis = Basis {
        size: existing.size,
        mtime_ns: existing.mtime_ns,
        ino: existing.ino,
    };
    // sign first, then open the basis and check it is still what was stat'ed and signed:
    // a file replaced or rewritten in between fails the identity check here, one changed
    // after this open fails the digest check at finish
    let sigs = dst.signatures(&item.rel, params, &*opts.runtime.chunk_digests)?;
    // The patch is checked against the digest the source computed, which is the
    // algorithm `-hash` selected. Chunk signatures stay on `chunk_digests` (SHA-256);
    // hashing the rebuilt file with that instead makes every non-SHA-256 run reject
    // the patch and copy the file whole.
    let mut sink = dst.create_patch(item, &basis, &*opts.runtime.digests)?;
    let mut literal = 0u64;
    // Every patch instruction is bounded against what the two stats already say, here,
    // where both sizes are in hand -- not in each adapter that decodes a patch.
    //
    // The instructions carry `u64` lengths straight off the wire. `Patch::Hole(n)` was
    // handed to the sink unchecked, so one frame saying `u64::MAX` asks the destination to
    // produce 16 exbibytes: a sparse-file sink extends forever, and a sink without holes
    // hashes zeros for about 2600 years. `Patch::Copy` is the same shape and additionally
    // reads OUT of the basis, so an unbounded offset+len is a read past the file the peer
    // was allowed to see. Neither needs a heuristic ceiling: the source file's size and
    // the basis's size are exactly the right bounds and both are already known.
    let mut produced = 0u64;
    let mut grow = |n: u64| -> io::Result<()> {
        produced = produced
            .checked_add(n)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "patch length overflows"))?;
        if produced > item.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "patch rebuilds {} bytes for a {}-byte file",
                    produced, item.size
                ),
            ));
        }
        Ok(())
    };
    let digest = src.delta(&item.rel, params, &sigs, &opts.runtime, &mut |p| match p {
        Patch::Literal(b) => {
            grow(b.len() as u64)?;
            literal += b.len() as u64;
            sink.write(b)
        }
        Patch::Copy { offset, len } => {
            grow(len)?;
            let end = offset.checked_add(len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "patch copy range overflows")
            })?;
            if end > basis.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "patch copies {offset}..{end} from a {}-byte basis",
                        basis.size
                    ),
                ));
            }
            sink.copy_basis(offset, len)
        }
        Patch::Hole(n) => {
            grow(n)?;
            sink.hole(n)
        }
    })?;
    sink.expect(&digest)?;
    let refusals = sink.finish(item, xattrs, opts.meta, opts.fsync)?;
    if opts.nocache {
        sink.drop_cache();
    }
    if opts.preserve_atime {
        if let Err(e) = src.restore_atime(item) {
            eprintln!("WARN: atime not restored on {}: {e}", item.rel);
        }
    }
    crate::debug!(
        opts.runtime.log,
        "delta {}: {} of {} bytes as literals over {} signatures",
        item.rel,
        literal,
        item.size,
        sigs.len()
    );
    Ok(FileOutcome {
        bytes: item.size,
        sha256: if opts.hash { Some(digest) } else { None },
        refusals,
        literal: Some(literal),
    })
}

fn entry_of(item: &Item, sha256: String) -> Entry {
    Entry {
        path: item.rel.clone(),
        kind: item.kind,
        size: item.size,
        mtime_ns: item.mtime_ns,
        mode: item.mode,
        uid: item.uid,
        gid: item.gid,
        sha256,
        ino: item.ino,
    }
}

fn owner_refused(op: &'static str, item: &Item) -> Failure {
    Failure::of(
        op,
        &item.rel,
        "owner",
        format!(
            "ownership {}:{} not permitted (not root)",
            item.uid, item.gid
        ),
    )
}

/// Whether a path the source did not list was inside this run's walk. An excluded name,
/// a child of an excluded directory, or a name with more components than `-depth` was
/// never compared, so it is not a removal.
fn removal_in_scope(filter: &Filter, rel: &str, kind: Kind, max_depth: Option<usize>) -> bool {
    if let Some(max) = max_depth {
        if rel != "." && rel.split('/').count() > max {
            return false;
        }
    }
    let paths = filter.paths_only();
    if rel == "." {
        return true;
    }
    let mut acc = String::new();
    for (i, part) in rel.split('/').enumerate() {
        if i > 0 {
            acc.push('/');
        }
        acc.push_str(part);
        let last = acc.len() == rel.len();
        if !paths.allows(&acc, !last || kind == Kind::Dir) {
            return false;
        }
    }
    true
}

/// Live counters the workers bump and the progress line reads.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicUsize,
    pub bytes: AtomicU64,
    pub total_files: usize,
    pub total_bytes: u64,
}

impl Progress {
    fn line(&self, started: Instant) -> String {
        let (f, b) = (
            self.files.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        );
        let secs = started.elapsed().as_secs_f64();
        format!(
            "progress: {f}/{} files, {}/{} ({}/s), {secs:.1} s",
            self.total_files,
            human_bytes(b),
            human_bytes(self.total_bytes),
            human_bytes(if secs > 0.0 {
                (b as f64 / secs) as u64
            } else {
                0
            })
        )
    }
}

/// Copies `src` into `dst` per `mode`, recording each completed entry.
pub fn copy_tree<T: Tree>(
    src: &T,
    dst: &T,
    mode: Mode,
    known: Option<&BTreeMap<String, Entry>>,
    recorder: &mut dyn Recorder,
    opts: &CopyOptions,
) -> io::Result<CopyReport> {
    let t0 = Instant::now();
    let mut report = CopyReport {
        engine: "threads",
        dry_run: opts.dry_run,
        ..Default::default()
    };
    // a destination that is one stream takes its files one at a time, whatever was asked
    let parallel = if dst.writes_in_one_stream() {
        1
    } else {
        opts.parallel.max(1)
    };

    // THE SOURCE IS LISTED THROUGH THE PATH PATTERNS ONLY, like the destination below, and the
    // attribute predicates choose what is copied. A path pattern is a property of the PATH, so
    // both sides agree on it; a size, an age or an owner is a property of each FILE, so they
    // need not. Listed through the whole filter, a source file truncated to 0 bytes under
    // `-minsize 1` would vanish from the listing, and its 2 MB copy at the destination --
    // which still passes -- would be planned as a removal: the path deleted while the source
    // still has it. The same for `-newer`, `-older`, `-uid`, `-gid`. A file outside the
    // predicates is not copied and not removed, the way rsync's `--min-size` skips a
    // transfer rather than excluding a name.
    let mut listing = src.list(&opts.filter.paths_only(), opts.max_depth, parallel)?;
    let now = crate::filter::now_ns();
    let (in_scope, outside): (Vec<Item>, Vec<Item>) = std::mem::take(&mut listing.items)
        .into_iter()
        .partition(|i| opts.filter.admits(i, now));
    listing.items = in_scope;
    // A PARENT THE SOURCE NAMES ONLY BY IMPLICATION is planned as a directory like any other.
    // A tar archive may hold `a/f` with no entry for `a`, and so may any listing built from
    // object keys. Unplanned, nothing makes `a`, so the write resolves `a` through whatever
    // the destination holds there: measured, `a -> /elsewhere` put `f` in /elsewhere, and
    // since a COPY replaces a file in a directory's way, the same shape would remove a file
    // outside the destination. Planned, `a` gets the mkdir that replaces a link, the fence
    // when it cannot be made, and the in-the-way check a listed directory gets. It has no
    // metadata of its own to apply, and no catalog entry, since the source has no such
    // entry to compare against.
    let implied = implied_parents(&listing.items);
    let implied_rels: std::collections::BTreeSet<String> =
        implied.iter().map(|i| i.rel.clone()).collect();
    if !implied.is_empty() {
        listing.items.extend(implied);
        listing.items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
    }
    let still_there: std::collections::BTreeSet<&str> =
        outside.iter().map(|i| i.rel.as_str()).collect();
    report.failures.extend(
        listing
            .errors
            .iter()
            .map(|e| Failure::of("list", src.root().display().to_string(), "io", e.clone())),
    );
    // A fresh copy does not otherwise ask what is already at the destination, which is
    // what makes it fast. It has to when the plan is going to be shown or confirmed:
    // not looking is the same as not knowing, and a rail that cannot see an overwrite
    // does not guard against one. The condition is the same on both runs, so the digest
    // a dry run prints is the digest the real run computes.
    let need_plan = opts.dry_run || opts.require_confirm || opts.confirm.is_some();
    let dst_listing = match mode {
        Mode::Fresh if !need_plan => Listing::default(),
        // through the path patterns only; the attribute predicates are applied below, to
        // the view that decides skips and removals and not to the one that shows overwrites
        _ => match dst.list(&opts.filter.paths_only(), opts.max_depth, parallel) {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Listing::default(),
            Err(e) => return Err(e),
        },
    };
    // WHAT THE DESTINATION LISTING COULD NOT READ is reported, as the source's is. Dropped,
    // a destination directory that could not be listed would read as an empty one, so a
    // mirror would under-remove with nothing said and the confirm rail could not see the
    // overwrites inside it. It does not gate removals -- a removal is only ever planned from
    // a name that WAS listed -- but a run that could not see all of its destination has not
    // shown that the destination matches. A destination that is not there at all is empty,
    // not unreadable: a dry run opens it without creating it, and its `NotFound` is the
    // `Listing::default()` above. (It is tempting to assume the root is always created
    // first; it is not.)
    dst.validate_paths(&listing.items, &dst_listing.items)?;
    let dst_unseen: &[String] = &dst_listing.errors;
    report.failures.extend(
        dst_unseen
            .iter()
            .map(|e| Failure::of("list", dst.root().display().to_string(), "io", e.clone())),
    );
    // Every destination entry at a path the run covers: what a copy there would replace.
    let dst_seen = index(&dst_listing.items);
    // The same entries narrowed by the attribute predicates, as the source was: what the run
    // may skip or remove. A destination file outside `-size` is not this run's to remove.
    let dst_index: BTreeMap<&str, &Item> = dst_seen
        .iter()
        .filter(|(_, i)| opts.filter.admits(i, now))
        .map(|(k, i)| (*k, *i))
        .collect();
    // `listing.errors` is what makes absence mean "gone" rather than "unseen" -- see the
    // removal block in `plan`. It is read here rather than inside `plan` because `plan` is
    // core and takes facts, not a `Listing`.
    let source_complete = listing.errors.is_empty();
    let mut p = plan(
        mode,
        &listing.items,
        &dst_index,
        known,
        opts.hard_links,
        dst.keeps_times(),
        source_complete,
    );
    // a path the source still has, outside the predicates, is not a path it no longer has.
    // Neither is a path the listing never walked: an excluded name, a child of an excluded
    // directory, or a name below `-depth`. Both listings stop at the same filter and depth,
    // so a catalog entry there is unseen, not gone.
    p.remove.retain(|(rel, kind)| {
        !still_there.contains(rel.as_str())
            && removal_in_scope(&opts.filter, rel, *kind, opts.max_depth)
    });
    // Not from an incomplete source listing: the run then says no removals were planned, and
    // a replacement is a removal. The conflict stays a loud failure.
    if matches!(mode, Mode::Mirror | Mode::Sync) && source_complete {
        in_the_way(&mut p, &listing.items, &dst_seen, true);
    } else if matches!(mode, Mode::Fresh | Mode::Resume) {
        // `dst_seen` is empty for a copy that did not list its destination; the mkdir below
        // replaces what it finds in the way instead
        in_the_way(&mut p, &listing.items, &dst_seen, false);
    }
    if !source_complete && matches!(mode, Mode::Mirror | Mode::Sync) {
        report.failures.push(Failure::of(
            "list",
            src.root().display().to_string(),
            "io",
            "the source listing was incomplete, so no removals were planned: an entry this run could not see is not an entry the source no longer has. Fix the errors above and run again".to_string(),
        ));
    }
    report.skipped_files = p.skipped_files;
    report.skipped_bytes = p.skipped_bytes;

    let mut planned = Vec::new();
    if need_plan {
        planned = plan_lines(mode, &p, &dst_seen);
        // A destination the listing could not fully read may hold a file the plan shows as
        // new: say so in the plan, and count the run destructive, because an overwrite it
        // cannot see is not one it can rule out.
        planned.extend(dst_unseen.iter().map(|e| format!("? {e}")));
        report.plan_digest = plan_digest(&opts.runtime, src.root(), dst.root(), &planned);
        // a run that would remove or overwrite is refused unless the caller passes the
        // digest a dry run of the same command printed: the plan has to have been looked
        // at, and a change to the plan since then produces a different digest
        let destructive = !dst_unseen.is_empty()
            || !p.clear.is_empty()
            || !p.remove.is_empty()
            || !p.moves.is_empty()
            || p.copy.iter().any(|f| dst_seen.contains_key(f.rel.as_str()));
        if !opts.dry_run
            && (opts.confirm.is_some() || (opts.require_confirm && destructive))
            && opts.confirm.as_deref() != Some(report.plan_digest.as_str())
        {
            // deliberately without the digest: a refusal that carried it would let a
            // caller satisfy the check without ever reading the plan
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("this run would {}; re-run it with -dryrun to see the plan and the digest that goes with it, then pass that digest as -confirm", if !p.remove.is_empty() { "remove entries from the destination" } else { "overwrite entries on the destination" }),
            ));
        }
    }

    if opts.dry_run {
        report.engine = "dry-run";
        report.copied_files = p.copy.len();
        report.copied_bytes = p.copy.iter().map(|i| i.size).sum();
        report.linked = p.link.len();
        report.directories = p.dirs.len();
        report.symlinks = p.symlinks.len();
        report.removed = p.clear.len() + p.remove.len();
        report.moved = p.moves.len();
        report.planned = planned;
        if opts.dry_run_stats {
            let items: Vec<Item> = p
                .copy
                .iter()
                .chain(p.moves.iter().map(|(i, _, _)| i))
                .map(|i| (*i).clone())
                .collect();
            let scan = crate::scan::Scan {
                listing: Listing {
                    items,
                    errors: Vec::new(),
                },
                hashes: BTreeMap::new(),
                seconds: t0.elapsed().as_secs_f64(),
                names: Some(opts.runtime.names.clone()),
                hash_name: opts.runtime.digests.name(),
                hashed: 0,
                cache_hits: 0,
            };
            report.planned_stats = Some(crate::scan::stats_report(&scan));
        }
        if opts.dry_run_target {
            if let Some(k) = known {
                for e in k.values() {
                    match dst_seen.get(e.path.as_str()) {
                        None => report.target_mismatches.push(format!("? {}: missing on the destination", e.path)),
                        Some(d) if d.kind != e.kind => report.target_mismatches.push(format!("? {}: destination is a {:?}, index says {:?}", e.path, d.kind, e.kind)),
                        // the mtime half only where the destination keeps one; on a
                        // store that cannot, every file read as "changed since the copy"
                        // `same_mtime`, not equality: the planner admits a destination that
                        // truncated the nanoseconds, and this compared exactly, so a resume
                        // would skip a file `-target` had just reported as changed
                        Some(d) if e.kind == Kind::File && (d.size != e.size || (dst.keeps_times() && !crate::plan::same_mtime(e.mtime_ns, d.mtime_ns))) => {
                            report.target_mismatches.push(format!("? {}: destination changed since the copy (size {} vs {}, mtime {} vs {})", e.path, d.size, e.size, d.mtime_ns, e.mtime_ns))
                        }
                        _ => {}
                    }
                }
            }
        }
        report.seconds = t0.elapsed().as_secs_f64();
        return Ok(report);
    }

    // Directories, parents first (the listing is sorted, so a parent precedes its children).
    // They come before removals because a move needs its new parent to exist and its old
    // parent to still hold it.
    // What is in the way of a directory goes first: a file or symlink where the source has a
    // directory, which the mkdir below would fail on and the files under it would open through.
    for (rel, kind) in &p.clear {
        match dst.remove(rel, *kind) {
            Ok(Removed::Gone) => {
                report.removed += 1;
                recorder.record_gone(rel)?;
            }
            Ok(Removed::Deferred(why)) => report.deferred.push(format!("{rel}: {why}")),
            Ok(Removed::Kept(why)) => report.kept.push(format!("{rel}: {why}")),
            Err(e) => report.failures.push(Failure::new("remove", rel, &e)),
        }
    }
    // NOTHING IS WRITTEN UNDER A DIRECTORY THAT COULD NOT BE MADE. What stands at that path is
    // not the directory the plan made -- a file, a link the adapter did not recognize, a name
    // the server would not create -- and on a transport whose server resolves paths, writing
    // `a/x` under a symlink `a` it could not replace lands wherever `a` points: measured over
    // SFTP with a mkdir that did not replace a link, and still possible where a server's
    // LSTAT omits the permissions that identify one. The mkdir failure is reported;
    // everything beneath it is refused by name rather than attempted.
    let mut blocked: Vec<String> = Vec::new();
    for item in &p.dirs {
        if beneath(&item.rel, &blocked) {
            report
                .failures
                .push(Failure::new("mkdir", &item.rel, &not_beneath()));
            blocked.push(item.rel.clone());
            continue;
        }
        let made = match dst.mkdir(&item.rel) {
            // A COPY THAT DID NOT LIST ITS DESTINATION finds what is in the way here rather
            // than in the plan. The same replacement the plan would have made, for the same
            // reason: a file or symlink standing where the source has a directory is one entry
            // replaced. Asked of `stat`, which does not follow a link on any adapter, so a link
            // is replaced rather than taken for the directory it points at.
            Err(e) if mode == Mode::Fresh && !need_plan => match dst.stat(&item.rel) {
                Ok(Some(there)) if there.kind != Kind::Dir => {
                    match dst.remove(&item.rel, there.kind) {
                        Ok(Removed::Gone) => {
                            report.removed += 1;
                            recorder.record_gone(&item.rel)?;
                            dst.mkdir(&item.rel)
                        }
                        _ => Err(e),
                    }
                }
                _ => Err(e),
            },
            other => other,
        };
        match made {
            Ok(()) => report.directories += 1,
            Err(e) => {
                report.failures.push(Failure::new("mkdir", &item.rel, &e));
                blocked.push(item.rel.clone());
            }
        }
    }

    // Renames and moves: the bytes are already on the destination under the old name. An
    // adapter without rename, or a rename that fails, falls back to copying the file and
    // removing the old name, which is what a sync without this step would have done.
    let mut fallback_copies: Vec<&Item> = Vec::new();
    let mut fallback_removals: Vec<(String, Kind)> = Vec::new();
    for (item, from, sha) in &p.moves {
        // Nor is anything renamed into or out of one: the server resolves both names, so a
        // rename into `a/x` under an unreplaced link `a` lands wherever it points. Refused
        // rather than copied instead -- the copy would be refused too -- and the old name is
        // left where it is, since nothing took its place.
        if beneath(&item.rel, &blocked) || beneath(from, &blocked) {
            report.failures.push(Failure::of(
                "move",
                &item.rel,
                crate::ports::code_of(&not_beneath()),
                format!("from {from}: {}", not_beneath()),
            ));
            continue;
        }
        match dst.rename(from, &item.rel) {
            Ok(()) => {
                recorder.record_gone(from)?;
                match dst.set_metadata(&item.rel, item, opts.file_options().meta) {
                    Ok(r) if r.owner && opts.ownership == Ownership::Require => {
                        report.failures.push(owner_refused("move", item));
                        // The bytes are already at the new path. The catalog has to name it,
                        // or a later sync treats the file as something this run never wrote.
                        recorder.record(&entry_of(item, sha.clone()))?;
                    }
                    Ok(r) => {
                        if r.owner {
                            report.owner_refused += 1;
                        }
                        report.moved += 1;
                        recorder.record(&entry_of(item, sha.clone()))?;
                    }
                    Err(e) => {
                        report.failures.push(Failure::of(
                            "move",
                            &item.rel,
                            crate::ports::code_of(&e),
                            format!("moved {from} -> {}: metadata not applied: {e}", item.rel),
                        ));
                        recorder.record(&entry_of(item, sha.clone()))?;
                    }
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::Unsupported {
                    report
                        .warnings
                        .push(format!("move {from} -> {}: {e}; copying instead", item.rel));
                }
                fallback_copies.push(item);
                fallback_removals.push((from.clone(), Kind::File));
            }
        }
    }

    // Removals: what the source no longer has must not survive to be verified.
    for (rel, kind) in p.remove.iter().chain(fallback_removals.iter()) {
        // what stands above it is not the directory the listing saw
        if beneath(rel, &blocked) {
            report
                .failures
                .push(Failure::new("remove", rel, &not_beneath()));
            continue;
        }
        match dst.remove(rel, *kind) {
            Ok(Removed::Gone) => {
                report.removed += 1;
                recorder.record_gone(rel)?;
            }
            // The destination still holds it, so the catalog must NOT record it gone: a
            // later resume would skip an entry that is still there.
            Ok(Removed::Deferred(why)) => report.deferred.push(format!("{rel}: {why}")),
            Ok(Removed::Kept(why)) => report.kept.push(format!("{rel}: {why}")),
            // Not empty in a filtered or depth-capped run: the directory keeps what the run
            // did not look at, as `delete` already does. Both listings stop at the same
            // filter and depth, so a directory the source dropped can still hold an excluded
            // name or one below the cap, and neither is this run's to remove.
            //
            // Said, not silent: the plan showed `# {rel}`, and a run that then keeps it without a
            // word diverges from its own plan with no trace. A warning, not a failure and not
            // `kept` -- `kept` is the store refusing, and fails the run.
            Err(e)
                if *kind == Kind::Dir
                    && e.kind() == io::ErrorKind::DirectoryNotEmpty
                    && (!opts.filter.is_empty() || opts.max_depth.is_some()) =>
            {
                // what is known is that it is not empty in a scoped run, not what is in it: a
                // child the scope left out, or one written since the listing
                report.warnings.push(format!("{rel}: left in place; it is not empty, and this run's filter or -depth may have left entries in it"));
            }
            Err(e) => report.failures.push(Failure::new("remove", rel, &e)),
        }
    }

    // Files: every worker claims the next index; the native engine claims through the same
    // counter, so a worker that fell back to threads never duplicates work.
    let mut all_files: Vec<&Item> = p.copy.clone();
    all_files.extend(fallback_copies);
    all_files.retain(|f| {
        let clear = !beneath(&f.rel, &blocked);
        if !clear {
            report
                .failures
                .push(Failure::new("copy", &f.rel, &not_beneath()));
        }
        clear
    });
    let files = &all_files;
    let mut fopts = opts.file_options();
    // `-parallel auto` copies through two separately tuned stages; a fixed `-parallel N`
    // leaves `stages` as `None` and takes the path it always took.
    let stages = opts
        .auto_parallel
        .then(|| std::sync::Arc::new(crate::stage::Stages::new(parallel)));
    fopts.stages = stages.clone();
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, io::Result<FileOutcome>)>> =
        Mutex::new(Vec::with_capacity(files.len()));
    let uring_used = AtomicBool::new(false);
    let engine_warning: Mutex<Option<String>> = Mutex::new(None);
    // The catalog is what `resume` reads, so an entry has to be written when its file
    // lands, not when every file has. It used to be written in one pass after the whole
    // batch: a copy killed after 28 of 40 files left 3 entries, and resuming it copied
    // all 40 again. The lock is taken once per completed file, which is nothing beside
    // copying the file.
    let recorder = Mutex::new(recorder);
    let record_failed: Mutex<Option<io::Error>> = Mutex::new(None);
    let write_entry = |item: &Item, outcome: &io::Result<FileOutcome>| {
        let Ok(o) = outcome else { return };
        if o.refusals.owner && opts.ownership == Ownership::Require {
            return; // a refusal that is an error here is a failure, not an entry
        }
        let entry = entry_of(item, o.sha256.clone().unwrap_or_default());
        if let Err(e) = recorder.lock().unwrap().record(&entry) {
            let mut slot = record_failed.lock().unwrap();
            if slot.is_none() {
                *slot = Some(e);
            }
        }
    };
    let progress = Progress {
        total_files: files.len(),
        total_bytes: files.iter().map(|i| i.size).sum(),
        ..Default::default()
    };
    let finished = AtomicBool::new(false);
    // `-parallel auto`: the workers admitted to claim files; the tuner moves it
    let active = AtomicUsize::new(if opts.auto_parallel {
        parallel.min(2)
    } else {
        parallel
    });
    if let Some(fleet) = &opts.fleet {
        // A worker is a separate process with its own connection to the destination, and
        // whatever it stages for `sync` dies with it. For a destination that publishes in
        // `sync` that is not a slow copy, it is a copy that reports success with nothing at
        // the far end: measured against a registry, 3 blobs uploaded, 0 manifests pushed,
        // and the repository does not exist. Refuse the pair rather than emit that.
        if dst.sync_publishes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: a fleet cannot publish to this destination, because each worker stages its own and only this process calls sync; copy without -nodes", dst.root().display()),
            ));
        }
        // the fleet copies the files; this process keeps the plan, the metadata and the
        // catalog, and writes each entry as its worker reports the file, exactly as the
        // local engines do
        let mut done = |i: usize, r: io::Result<FileOutcome>| {
            if let Ok(o) = &r {
                progress.files.fetch_add(1, Ordering::Relaxed);
                progress.bytes.fetch_add(o.bytes, Ordering::Relaxed);
            }
            write_entry(files[i], &r);
            results.lock().unwrap().push((i, r));
        };
        fleet.copy(files, &mut done)?;
        report.engine = "nodes";
    } else {
        std::thread::scope(|scope| {
            // everything the threads share, by reference, so the per-worker closures can `move`
            // their index without moving the shared state
            let (active, progress, next, finished, results, uring_used, engine_warning, fopts) = (
                &active,
                &progress,
                &next,
                &finished,
                &results,
                &uring_used,
                &engine_warning,
                &fopts,
            );
            if opts.progress {
                scope.spawn(move || {
                    let mut last = Instant::now();
                    while !finished.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(100));
                        if last.elapsed() >= Duration::from_secs(5) {
                            eprintln!("{}", progress.line(t0));
                            last = Instant::now();
                        }
                    }
                });
            }
            if opts.auto_parallel {
                let log = &*opts.runtime.log;
                let stages = stages.clone();
                scope.spawn(move || {
                    // Three dimensions, probed round-robin. `workers` is how many files are in
                    // flight; `read` and `write` are how many of those threads may be inside
                    // each half of a copy. Without the stages the third and second knobs do
                    // not exist and this is the single-knob tuner it has always been.
                    let mut knobs = vec![Knob::new(
                        "workers",
                        parallel,
                        || active.load(Ordering::Relaxed),
                        |n| active.store(n, Ordering::Relaxed),
                    )];
                    if let Some(s) = &stages {
                        let (r, w) = (std::sync::Arc::clone(s), std::sync::Arc::clone(s));
                        knobs.push(Knob::new("readers", parallel, move || r.read.limit(), {
                            let s = std::sync::Arc::clone(s);
                            move |n| s.read.set_limit(n)
                        }));
                        knobs.push(Knob::new("writers", parallel, move || w.write.limit(), {
                            let s = std::sync::Arc::clone(s);
                            move |n| s.write.set_limit(n)
                        }));
                    }
                    tune(
                        &mut knobs,
                        TUNE_WINDOW,
                        progress,
                        next,
                        files.len(),
                        finished,
                        log,
                    );
                });
            }
            let mut workers = Vec::new();
            for k in 0..parallel.min(files.len().max(1)) {
                workers.push(scope.spawn(move || {
                // a worker above the admitted count waits at the gate; with the native
                // engine the gate is passed once, so the tuner can only add such workers
                let gate = || {
                    while k >= active.load(Ordering::Relaxed) && next.load(Ordering::Relaxed) < files.len() {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                };
                gate();
                // a patch goes through the port's sinks, which the native engine bypasses
                if opts.engine != Engine::Threads && !opts.delta {
                    let mut done = |i: usize, r: io::Result<FileOutcome>| {
                        if let Ok(o) = &r {
                            progress.files.fetch_add(1, Ordering::Relaxed);
                            progress.bytes.fetch_add(o.bytes, Ordering::Relaxed);
                        }
                        write_entry(files[i], &r);
                        results.lock().unwrap().push((i, r));
                    };
                    match src.native_copy(dst, files, next, parallel, fopts, &mut done) {
                        Ok(()) => {
                            uring_used.store(true, Ordering::Relaxed);
                            return;
                        }
                        Err(e) => {
                            if opts.engine == Engine::Uring {
                                engine_warning.lock().unwrap().get_or_insert_with(|| format!("io_uring engine requested but unavailable, using threads: {e}"));
                            }
                        }
                    }
                }
                let mut buf = vec![0u8; fopts.block_size];
                loop {
                    gate();
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let r = copy_one(src, dst, files[i], fopts, &mut buf);
                    if let Ok(o) = &r {
                        progress.files.fetch_add(1, Ordering::Relaxed);
                        progress.bytes.fetch_add(o.bytes, Ordering::Relaxed);
                    }
                    write_entry(files[i], &r);
                    results.lock().unwrap().push((i, r));
                }
            }));
            }
            // Join the workers explicitly, then release the ticker; the scope would otherwise
            // wait on a ticker that is waiting on the scope.
            for w in workers {
                let _ = w.join();
            }
            finished.store(true, Ordering::Relaxed);
        });
    }
    if opts.progress {
        eprintln!("{}", progress.line(t0));
    }
    if uring_used.load(Ordering::Relaxed) {
        report.engine = "io_uring";
    }
    if let Some(w) = engine_warning.into_inner().unwrap() {
        report.warnings.push(w);
    }
    let recorder = recorder.into_inner().unwrap();
    if let Some(e) = record_failed.into_inner().unwrap() {
        report.failures.push(Failure::new("catalog", "", &e));
    }
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    let mut hashes: BTreeMap<&str, String> = BTreeMap::new();
    for (i, outcome) in results {
        let item = files[i];
        match outcome {
            Ok(o) => {
                if o.refusals.owner {
                    if opts.ownership == Ownership::Require {
                        report.failures.push(Failure::of(
                            "copy",
                            &item.rel,
                            "owner",
                            format!(
                                "ownership {}:{} not permitted (not root)",
                                item.uid, item.gid
                            ),
                        ));
                        continue;
                    }
                    report.owner_refused += 1;
                }
                report.xattr_refused += o.refusals.xattrs.len();
                report.copied_files += 1;
                report.copied_bytes += o.bytes;
                if let Some(l) = o.literal {
                    report.delta_files += 1;
                    report.delta_literal += l;
                }
                // the entry went into the catalog as the file landed; what is left here
                // is the accounting and the digest a hard link to this file will carry
                hashes.insert(item.rel.as_str(), o.sha256.unwrap_or_default());
            }
            Err(e) => report.failures.push(Failure::new("copy", &item.rel, &e)),
        }
    }
    // A later hard link records the target's digest. A moved or skipped file was never
    // copied in this run, so its digest is the one the catalog already has, not the empty
    // string a missing map entry would write.
    for (item, _, sha) in &p.moves {
        if !sha.is_empty() {
            hashes
                .entry(item.rel.as_str())
                .or_insert_with(|| sha.clone());
        }
    }
    if let Some(k) = known {
        for (_, target) in &p.link {
            if hashes.contains_key(target.as_str()) {
                continue;
            }
            if let Some(e) = k.get(target) {
                if !e.sha256.is_empty() {
                    hashes.insert(target.as_str(), e.sha256.clone());
                }
            }
        }
    }

    // Hard links share the inode already placed, so they carry its data and metadata. A
    // destination with no hard links (sftp, an object store) gets the file again instead.
    let mut link_buf = vec![0u8; fopts.block_size];
    for (item, target) in &p.link {
        // the TARGET too: a link resolves it on the server, so one beneath an unreplaced link
        // would give the destination a name for an inode outside it
        if beneath(&item.rel, &blocked) || beneath(target, &blocked) {
            report
                .failures
                .push(Failure::new("link", &item.rel, &not_beneath()));
            continue;
        }
        match dst.hard_link(target, &item.rel) {
            Ok(()) => {
                report.linked += 1;
                recorder.record(&entry_of(
                    item,
                    hashes.get(target.as_str()).cloned().unwrap_or_default(),
                ))?;
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                match copy_one(src, dst, item, &fopts, &mut link_buf) {
                    Ok(o) if o.refusals.owner && opts.ownership == Ownership::Require => {
                        report.failures.push(owner_refused("copy", item));
                    }
                    Ok(o) => {
                        if o.refusals.owner {
                            report.owner_refused += 1;
                        }
                        report.copied_files += 1;
                        report.copied_bytes += o.bytes;
                        recorder.record(&entry_of(item, o.sha256.unwrap_or_default()))?;
                    }
                    Err(e) => report.failures.push(Failure::of(
                        "copy",
                        &item.rel,
                        crate::ports::code_of(&e),
                        format!("in place of a link to {target}: {e}"),
                    )),
                }
            }
            Err(e) => report.failures.push(Failure::of(
                "link",
                &item.rel,
                crate::ports::code_of(&e),
                format!("-> {target}: {e}"),
            )),
        }
    }

    // Symlinks: recreated as symlinks, never followed; only ownership applies to a link.
    let link_meta = MetaOptions {
        mode: false,
        times: false,
        owner: fopts.meta.owner,
        atime: false,
    };
    for item in &p.symlinks {
        if beneath(&item.rel, &blocked) {
            report
                .failures
                .push(Failure::new("symlink", &item.rel, &not_beneath()));
            continue;
        }
        let target = item.link_target.clone().unwrap_or_default();
        match dst
            .symlink(&item.rel, &target)
            .and_then(|_| dst.set_metadata(&item.rel, item, link_meta))
        {
            Ok(r) if r.owner && opts.ownership == Ownership::Require => {
                report.failures.push(owner_refused("symlink", item));
            }
            Ok(r) => {
                if r.owner {
                    report.owner_refused += 1;
                }
                report.symlinks += 1;
                recorder.record(&entry_of(item, String::new()))?;
            }
            Err(e) => report.failures.push(Failure::new("symlink", &item.rel, &e)),
        }
    }

    // Directories last, children before parents, so populating a directory does not bump
    // the mtime just restored and a read-only mode lands after its contents exist.
    for item in p.dirs.iter().rev() {
        // not a directory whose mkdir failed, nor anything under one: its failure is already
        // reported, and a SETSTAT follows a link on the server, so a mode or owner meant for
        // the directory lands on whatever the unreplaced link points at
        if blocked.iter().any(|b| b == &item.rel) || beneath(&item.rel, &blocked) {
            continue;
        }
        if implied_rels.contains(&item.rel) {
            continue;
        }
        let result = (|| {
            if opts.xattrs {
                let attrs = src.xattrs(&item.rel)?;
                report.xattr_refused += dst.set_xattrs(&item.rel, &attrs)?.len();
            }
            dst.set_metadata(&item.rel, item, fopts.meta)
        })();
        match result {
            Ok(r) if r.owner && opts.ownership == Ownership::Require => {
                report.failures.push(owner_refused("directory", item));
            }
            Ok(r) => {
                if r.owner {
                    report.owner_refused += 1;
                }
                recorder.record(&entry_of(item, String::new()))?;
            }
            Err(e) => report
                .failures
                .push(Failure::new("directory", &item.rel, &e)),
        }
    }

    // A destination that cannot finish has not received the copy, whatever the per-file
    // lines said. For a registry that is obvious: the manifests go up here, so a failure
    // means no image. For a filesystem it is less obvious and just as true. It is tempting
    // to demote the filesystem case to a warning on the reasoning that the files are
    // "already in place". They are not. A write that returned has not reached the disk,
    // and `syncfs` answering EIO or ENOSPC is precisely the kernel saying the dirty pages
    // were dropped. Reporting success on that is unrecoverable for whoever reads the
    // report; reporting a failure someone else caused costs a re-run.
    //
    // `sync_publishes` keeps the job it was added for -- refusing a fleet whose workers
    // each stage their own -- and is out of this decision, which needs no split.
    if let Err(e) = dst.sync() {
        report.failures.push(Failure::new(
            "finishing",
            dst.root().display().to_string(),
            &e,
        ));
        // And the standing advice on a failure -- "use resume" -- is not enough for THIS
        // one, which is worth saying rather than leaving to be discovered. Resume skips a
        // file the catalog knows and the destination shows at the right size and time. A
        // flush that failed can leave exactly that: the metadata written, the bytes not. So
        // the recovery is a comparison of content, which is what `verify` is.
        if !dst.sync_publishes() {
            report.warnings.push(format!("WARN the destination may hold files whose bytes never reached the disk; `rcp verify {} DESTINATION` compares content, where resume only compares size and time", dst.root().display()));
        }
    }
    if report.owner_refused > 0 {
        report.warnings.push(format!("ownership not preserved on {} entries (not root); -chown makes that an error, -noown silences it", report.owner_refused));
    }
    if report.xattr_refused > 0 {
        report.warnings.push(format!("{} extended attributes refused by the destination (trusted.* or security.* need privileges)", report.xattr_refused));
    }
    report.seconds = t0.elapsed().as_secs_f64();
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub parallel: usize,
    pub filter: Filter,
    pub max_depth: Option<usize>,
    pub data: bool,
    pub mode: bool,
    pub owner: bool,
    pub mtime: bool,
    /// `None`: exact, except that a destination whose nanoseconds are zero on a matching
    /// second is tolerated and counted (rsync and some filesystems drop them). `Some(w)`:
    /// a difference larger than `w` is a difference, nothing else is.
    pub mtime_window_ns: Option<i128>,
    pub runtime: Runtime,
    pub xattrs: bool,
    pub hard_links: bool,
    pub block_size: usize,
    pub verbose: bool,
    /// `-l`: two-line long listing per differing entry, differing fields starred.
    pub long: bool,
    /// `-stats`: compare tree statistics instead of entries.
    pub stats: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            parallel: 2,
            filter: Filter::default(),
            max_depth: None,
            data: true,
            mode: true,
            owner: true,
            mtime: true,
            mtime_window_ns: None,
            runtime: Runtime::plain(),
            xattrs: true,
            hard_links: true,
            block_size: 1 << 20,
            verbose: false,
            long: false,
            stats: false,
        }
    }
}

/// One difference found by `verify`. Displays as `DIFF <kind> <path>: <detail>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub kind: &'static str,
    pub path: String,
    pub detail: String,
}

impl fmt::Display for Diff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "DIFF {} {}", self.kind, self.path)
        } else {
            write!(f, "DIFF {} {}: {}", self.kind, self.path, self.detail)
        }
    }
}

impl Diff {
    /// `kind,path,detail` with CSV quoting.
    pub fn csv(&self) -> String {
        let q = |s: &str| {
            if s.contains([',', '"', '\n']) {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };
        format!("{},{},{}", self.kind, q(&self.path), q(&self.detail))
    }
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub compared: usize,
    pub bytes: u64,
    pub differences: Vec<Diff>,
    pub warnings: Vec<String>,
    /// One line per compared entry when `-v` is on.
    pub verbose: Vec<String>,
    /// Two lines per differing entry when `-l` is on.
    pub long_lines: Vec<String>,
    pub ns_zero_tolerated: usize,
    /// Checks the run was asked for and did not make, named so a caller can branch on them
    /// without reading prose. A skipped check is not a difference and not a failure, so it
    /// was visible ONLY as an English warning: an automated caller reading `differences: 0`
    /// concluded the mtimes matched, when they had not been looked at. Stable tokens, one
    /// per check (`mtime` is the only one today).
    pub skipped: Vec<&'static str>,
    pub seconds: f64,
}

impl VerifyReport {
    pub fn passed(&self) -> bool {
        self.differences.is_empty()
    }
}

/// The two-line long form for a differing entry: the source, then the destination values,
/// with a `*` on every field that differs.
///
/// `mtime_differs` is passed in rather than derived here: the caller has already decided
/// whether the times differ, taking `keeps_times` and `-mtimewindow` into account, and a
/// second opinion computed from a raw inequality contradicted the first.
fn long_pair(s: &Item, d: &Item, names: &dyn Names, mtime_differs: bool) -> [String; 2] {
    let star = |differs: bool, text: String| {
        if differs {
            format!("*{text}")
        } else {
            format!(" {text}")
        }
    };
    let (su, sg) = crate::scan::owner_strings(s.uid, s.gid, Some(names));
    let (du, dg) = crate::scan::owner_strings(d.uid, d.gid, Some(names));
    let mode_differs = s.kind != d.kind || s.mode != d.mode;
    let src = format!(
        "{} {:>9} {:>9} {:>13} {:>13} {}",
        star(mode_differs, crate::scan::mode_string(s.kind, s.mode)),
        star(s.uid != d.uid, su),
        star(s.gid != d.gid, sg),
        star(s.size != d.size, s.size.to_string()),
        star(
            mtime_differs,
            s.mtime_ns.div_euclid(1_000_000_000).to_string()
        ),
        s.rel
    );
    let dst = format!(
        "{} {:>9} {:>9} {:>13} {:>13}",
        star(mode_differs, crate::scan::mode_string(d.kind, d.mode)),
        star(s.uid != d.uid, du),
        star(s.gid != d.gid, dg),
        star(s.size != d.size, d.size.to_string()),
        star(
            mtime_differs,
            d.mtime_ns.div_euclid(1_000_000_000).to_string()
        )
    );
    [src, dst]
}

/// `verify -stats`: the two trees' statistics side by side; a mismatch is a difference.
fn compare_stats(report: &mut VerifyReport, sl: &[Item], dl: &[Item]) {
    let count = |items: &[Item], k: Kind| items.iter().filter(|i| i.kind == k).count();
    let bytes = |items: &[Item]| {
        items
            .iter()
            .filter(|i| i.kind == Kind::File)
            .map(|i| i.size)
            .sum::<u64>()
    };
    let mut rows: Vec<(String, u64, u64)> = vec![
        (
            "directories".into(),
            count(sl, Kind::Dir) as u64,
            count(dl, Kind::Dir) as u64,
        ),
        (
            "files".into(),
            count(sl, Kind::File) as u64,
            count(dl, Kind::File) as u64,
        ),
        (
            "symlinks".into(),
            count(sl, Kind::Symlink) as u64,
            count(dl, Kind::Symlink) as u64,
        ),
        ("bytes".into(), bytes(sl), bytes(dl)),
    ];
    for ((label, sc, sb), (_, dc, db)) in crate::scan::size_bins(sl)
        .into_iter()
        .zip(crate::scan::size_bins(dl))
    {
        rows.push((format!("files {label}"), sc as u64, dc as u64));
        rows.push((format!("bytes {label}"), sb, db));
    }
    let sd = crate::scan::depth_bins(sl);
    let dd = crate::scan::depth_bins(dl);
    for i in 0..sd.len().max(dd.len()) {
        let label = sd
            .get(i)
            .or(dd.get(i))
            .map(|r| r.0.clone())
            .unwrap_or_default();
        rows.push((
            format!("entries at {label}"),
            sd.get(i).map_or(0, |r| r.1 as u64),
            dd.get(i).map_or(0, |r| r.1 as u64),
        ));
    }
    for (label, a, b) in rows {
        report.compared += 1;
        let mark = if a == b { " " } else { "*" };
        report
            .verbose
            .push(format!("{mark} {label:<28} {a:>14} {b:>14}"));
        if a != b {
            report.differences.push(Diff {
                kind: "stats",
                path: label,
                detail: format!("source {a}, destination {b}"),
            });
        }
    }
}

fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(got)
}

/// Compares two files byte for byte, returning the offset of the first difference. Cheaper
/// than hashing both sides, and it stops at the first mismatch.
fn first_difference<A: Read, B: Read>(
    a: &mut A,
    b: &mut B,
    buf_a: &mut [u8],
    buf_b: &mut [u8],
    throttle: &dyn crate::ports::Throttle,
) -> io::Result<Option<u64>> {
    let mut pos = 0u64;
    loop {
        let na = fill(a, buf_a)?;
        let nb = fill(b, buf_b)?;
        throttle.take((na + nb) as u64);
        let n = na.min(nb);
        if buf_a[..n] != buf_b[..n] {
            let i = buf_a[..n]
                .iter()
                .zip(&buf_b[..n])
                .position(|(x, y)| x != y)
                .unwrap_or(0);
            return Ok(Some(pos + i as u64));
        }
        if na != nb {
            return Ok(Some(pos + n as u64));
        }
        if n == 0 {
            return Ok(None);
        }
        pos += n as u64;
    }
}

/// Compares every source entry with its destination counterpart. Destination entries the
/// source lacks are differences: a backup that carries extra data is not a copy of its source.
pub fn verify_tree<T: Tree>(src: &T, dst: &T, opts: &VerifyOptions) -> io::Result<VerifyReport> {
    let t0 = Instant::now();
    let parallel = opts.parallel.max(1);
    let mut report = VerifyReport::default();
    // `verify` consults `keeps_times` as the planner does, or the two commands contradict
    // each other on exactly the stores the flag exists for: a WebDAV destination stamps its
    // OWN modification time and a registry stores none at all (tar is NOT in this set -- it
    // writes the source mtime into each header), so the planner correctly holds a file
    // well-enough-copied on size while `verify` would report an mtime difference for EVERY
    // file of the copy it had just made. The comparison is not silently dropped -- a
    // skipped check that reports green is the failure mode this crate keeps writing rules
    // about -- it is skipped and said out loud, once.
    //
    // BOTH SIDES, because `verify` takes its two endpoints in the order written -- nothing
    // makes the store the second one. Measured with only `dst.keeps_times()` checked, the
    // same two trees one command apart: with the http tree as the DESTINATION, `1 warnings`
    // and `skipped: ["mtime"]`; with it as the SOURCE, four `DIFF mtime` lines, `0
    // warnings`, and `skipped` EMPTY. So an automated caller branching on `skipped` --
    // which is what that field is for -- would conclude the times had been compared and
    // disagreed. `rcp verify oci://reg/app /local/copy` is the same path.
    let times_comparable = src.keeps_times() && dst.keeps_times();
    let mtime_comparable = opts.mtime && times_comparable;
    // The same question for the three fields that had no predicate at all. BOTH sides
    // again: an invented mode is invented whichever end it comes from.
    let modes_comparable = src.keeps_modes() && dst.keeps_modes();
    let mode_comparable = opts.mode && modes_comparable;
    let owners_comparable = src.keeps_owner() && dst.keeps_owner();
    let owner_comparable = opts.owner && owners_comparable;
    let xattrs_both = src.keeps_xattrs() && dst.keeps_xattrs();
    let xattrs_comparable = opts.xattrs && xattrs_both;
    let sl = src.list(&opts.filter, opts.max_depth, parallel)?;
    let dl = dst.list(&opts.filter, opts.max_depth, parallel)?;
    report.warnings.extend(
        sl.errors
            .iter()
            .chain(dl.errors.iter())
            .map(|e| format!("WARN unreadable {e}")),
    );
    if opts.stats {
        report.verbose.push(format!(
            "  {:<28} {:>14} {:>14}",
            "statistic", "source", "destination"
        ));
        compare_stats(&mut report, &sl.items, &dl.items);
        report.bytes = sl
            .items
            .iter()
            .filter(|i| i.kind == Kind::File)
            .map(|i| i.size)
            .sum();
        report.seconds = t0.elapsed().as_secs_f64();
        return Ok(report);
    }
    let dmap = index(&dl.items);

    // Content, in parallel, for files that exist on both sides with the same size.
    let files: Vec<&Item> = sl
        .items
        .iter()
        .filter(|i| i.kind == Kind::File && opts.data)
        .filter(|i| {
            dmap.get(i.rel.as_str())
                .is_some_and(|d| d.kind == Kind::File && d.size == i.size)
        })
        .collect();
    let next = AtomicUsize::new(0);
    let content: Mutex<Vec<(usize, io::Result<Option<u64>>)>> =
        Mutex::new(Vec::with_capacity(files.len()));
    std::thread::scope(|scope| {
        for _ in 0..parallel.min(files.len().max(1)) {
            scope.spawn(|| {
                let bs = opts.block_size.max(4096);
                let mut a = vec![0u8; bs];
                let mut b = vec![0u8; bs];
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let rel = &files[i].rel;
                    let r = src.open(rel).and_then(|mut fa| {
                        dst.open(rel).and_then(|mut fb| {
                            first_difference(
                                &mut fa,
                                &mut fb,
                                &mut a,
                                &mut b,
                                &*opts.runtime.throttle,
                            )
                        })
                    });
                    content.lock().unwrap().push((i, r));
                }
            });
        }
    });
    let content: BTreeMap<&str, io::Result<Option<u64>>> = content
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|(i, r)| (files[i].rel.as_str(), r))
        .collect();

    let diff = |kind: &'static str, path: &str, detail: String| Diff {
        kind,
        path: path.to_string(),
        detail,
    };
    let mut inode_groups: BTreeMap<(u64, u64), Vec<&Item>> = BTreeMap::new();
    for s in &sl.items {
        report.compared += 1;
        let Some(d) = dmap.get(s.rel.as_str()) else {
            report
                .differences
                .push(diff("missing", &s.rel, String::new()));
            continue;
        };
        if s.kind != d.kind {
            report.differences.push(diff(
                "type",
                &s.rel,
                format!("source {:?}, destination {:?}", s.kind, d.kind),
            ));
            continue;
        }
        let before = report.differences.len();
        match s.kind {
            Kind::File => {
                report.bytes += s.size;
                if s.size != d.size {
                    report.differences.push(diff(
                        "size",
                        &s.rel,
                        format!("source {} bytes, destination {} bytes", s.size, d.size),
                    ));
                } else if opts.data {
                    match content.get(s.rel.as_str()) {
                        Some(Ok(Some(at))) => report.differences.push(diff(
                            "content",
                            &s.rel,
                            format!("first difference at byte {at}"),
                        )),
                        Some(Err(e)) => {
                            report
                                .differences
                                .push(diff("unreadable", &s.rel, e.to_string()))
                        }
                        _ => {}
                    }
                }
                if opts.hard_links && s.nlink > 1 {
                    inode_groups.entry((s.dev, s.ino)).or_default().push(s);
                }
            }
            Kind::Symlink => {
                if s.link_target != d.link_target {
                    let show = |p: &Option<std::path::PathBuf>| {
                        p.as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    };
                    report.differences.push(diff(
                        "link",
                        &s.rel,
                        format!(
                            "source -> {}, destination -> {}",
                            show(&s.link_target),
                            show(&d.link_target)
                        ),
                    ));
                }
            }
            Kind::Dir => {}
        }
        if mode_comparable && s.kind != Kind::Symlink && s.mode != d.mode {
            report.differences.push(diff(
                "mode",
                &s.rel,
                format!("source {:04o}, destination {:04o}", s.mode, d.mode),
            ));
        }
        if owner_comparable && (s.uid != d.uid || s.gid != d.gid) {
            report.differences.push(diff(
                "owner",
                &s.rel,
                format!(
                    "source {}:{}, destination {}:{}",
                    s.uid, s.gid, d.uid, d.gid
                ),
            ));
        }
        // Held rather than consumed on the spot, because `-l` prints a `*` beside every
        // field that differs and used to decide that for itself from a raw inequality --
        // so a WebDAV `verify -l` could say "modification times were not compared" and
        // star the mtime column in the same output, and a difference inside
        // `-mtimewindow` was starred after being ruled not a difference. One verdict now,
        // used by both.
        let mut mtime_differs = false;
        if mtime_comparable && s.kind != Kind::Symlink && s.mtime_ns != d.mtime_ns {
            mtime_differs = match opts.mtime_window_ns {
                Some(w) => (s.mtime_ns - d.mtime_ns).abs() > w,
                None => {
                    // a destination that keeps seconds or milliseconds and dropped the rest
                    if crate::plan::same_mtime(s.mtime_ns, d.mtime_ns) {
                        report.ns_zero_tolerated += 1;
                        false
                    } else {
                        true
                    }
                }
            };
            if mtime_differs {
                report.differences.push(diff(
                    "mtime",
                    &s.rel,
                    format!("source {}, destination {}", s.mtime_ns, d.mtime_ns),
                ));
            }
        }
        if xattrs_comparable {
            match (src.xattrs(&s.rel), dst.xattrs(&d.rel)) {
                (Ok(a), Ok(b)) if a != b => {
                    let names = |v: &[(String, Vec<u8>)]| {
                        v.iter()
                            .map(|(n, _)| n.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    report.differences.push(diff(
                        "xattr",
                        &s.rel,
                        format!("source [{}], destination [{}]", names(&a), names(&b)),
                    ));
                }
                (Err(e), _) | (_, Err(e)) => {
                    report.warnings.push(format!("WARN xattr {}: {e}", s.rel))
                }
                _ => {}
            }
        }
        if opts.verbose {
            let verdict = if report.differences.len() == before {
                "same"
            } else {
                "DIFFERENT"
            };
            report
                .verbose
                .push(format!("{verdict} {} {}", s.kind.tag(), s.rel));
        }
        if opts.long && report.differences.len() != before {
            report
                .long_lines
                .extend(long_pair(s, d, &*opts.runtime.names, mtime_differs));
        }
    }
    if report.ns_zero_tolerated > 0 {
        report.warnings.push(format!(
            "WARN: {} files have the same mtime seconds but destination nanoseconds of 0 (treated as equal; -mtimewindow 0 makes them differences)",
            report.ns_zero_tolerated
        ));
    }
    // Each skipped check names itself in `skipped` AND says so once in prose, because a
    // caller reads the first and an operator reads the second. Silence on either is the
    // failure this whole field exists to stop: `0 differences` over a comparison that
    // never ran reads exactly like `0 differences` over one that did.
    for (asked, source_has, dest_has, token, what) in [
        (
            opts.mode,
            src.keeps_modes(),
            dst.keeps_modes(),
            "mode",
            "modes",
        ),
        (
            opts.owner,
            src.keeps_owner(),
            dst.keeps_owner(),
            "owner",
            "owners",
        ),
        (
            opts.xattrs,
            src.keeps_xattrs(),
            dst.keeps_xattrs(),
            "xattr",
            "extended attributes and the ACLs that ride in them",
        ),
    ] {
        if asked && !(source_has && dest_has) {
            report.skipped.push(token);
            // name the end that is the reason; when neither carries them, the source is
            // named because that is where the operator's real values are
            let which = if !source_has {
                src.root().display()
            } else {
                dst.root().display()
            };
            report.warnings.push(format!(
                "WARN: {what} were not compared: {which} carries none, so the values in its listing are this adapter's own and every entry would differ (-noattrs stops asking)"
            ));
        }
    }
    if opts.mtime && !times_comparable {
        // `-mtimewindow` names the comparison that is not happening, so the warning says
        // so by name. Without this the operator passes a window, sees no mtime difference,
        // and reads that as the window working -- the flag is a silent no-op here, because
        // the comparison it tunes never runs at all.
        let window = if opts.mtime_window_ns.is_some() {
            " (-mtimewindow tunes that comparison, so it does nothing here)"
        } else {
            ""
        };
        report.skipped.push("mtime");
        // name the side that is the reason, because "which end cannot keep times" is the
        // first thing an operator asks and the message used to always say the destination
        let which = if !src.keeps_times() {
            src.root().display().to_string()
        } else {
            dst.root().display().to_string()
        };
        report.warnings.push(format!(
            "WARN: modification times were not compared: {which} keeps its own, so every file would differ (this is what the planner already skips on; -noattrs stops asking){window}"
        ));
    }
    for (_, group) in inode_groups.iter().filter(|(_, g)| g.len() > 1) {
        let dst_inodes: Vec<(u64, u64)> = group
            .iter()
            .filter_map(|s| dmap.get(s.rel.as_str()))
            .map(|d| (d.dev, d.ino))
            .collect();
        if dst_inodes.windows(2).any(|w| w[0] != w[1]) {
            let names = group
                .iter()
                .map(|s| s.rel.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            report.differences.push(diff(
                "hardlink",
                &names,
                "one inode in the source, separate files in the destination".into(),
            ));
        }
    }
    let src_paths: Vec<&str> = sl.items.iter().map(|i| i.rel.as_str()).collect();
    for d in &dl.items {
        if src_paths.binary_search(&d.rel.as_str()).is_err() {
            report
                .differences
                .push(diff("extra", &d.rel, String::new()));
        }
    }
    report.seconds = t0.elapsed().as_secs_f64();
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// delete, chown, chmod
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DeleteOptions {
    pub parallel: usize,
    pub filter: Filter,
    pub force: bool,
    pub remove_top: bool,
    /// The plan digest the caller says it has read (`-confirm`).
    pub confirm: Option<String>,
    /// Refuse to remove anything without a matching `confirm` (`-requireconfirm`).
    pub require_confirm: bool,
    pub runtime: Option<Runtime>,
}

#[derive(Debug, Default)]
pub struct DeleteReport {
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub bytes: u64,
    pub failures: Vec<String>,
    /// Entries the store will remove on its own schedule: a registry answering 405 to a
    /// blob `DELETE` because its garbage collector owns blobs. Not a failure -- the run
    /// did what it could and there is nothing left for the operator to do -- but not a
    /// removal either, so it is not counted as one.
    pub deferred: Vec<String>,
    /// Entries the store REFUSED to remove: a locked WebDAV resource, a namenode answering
    /// `false`. They are still there and will stay there, so a `delete` that ends with any
    /// of these has not done what it was asked and its exit code says so. Kept apart from
    /// `deferred` because a caller reading only the exit code must be able to tell them apart.
    pub kept: Vec<String>,
    /// Without `-force` nothing is removed; the counts say what would be.
    pub dry_run: bool,
    /// The short name of what this run would remove: what `-confirm` takes.
    pub plan_digest: String,
    pub seconds: f64,
}

/// Removes a tree. Without `force` it only counts. Files and symlinks go in parallel,
/// directories afterwards from the deepest up; the root itself only with `remove_top`.
pub fn delete_tree<T: Tree>(t: &T, opts: &DeleteOptions) -> io::Result<DeleteReport> {
    let t0 = Instant::now();
    let parallel = opts.parallel.max(1);
    let listing = t.list(&opts.filter, None, parallel)?;
    let mut report = DeleteReport {
        dry_run: !opts.force,
        ..Default::default()
    };
    report
        .failures
        .extend(listing.errors.iter().map(|e| format!("list {e}")));
    let leaves: Vec<&Item> = listing
        .items
        .iter()
        .filter(|i| i.kind != Kind::Dir)
        .collect();
    // With an include pattern, a directory is removed only when it matches the pattern itself.
    let dirs: Vec<&Item> = listing
        .items
        .iter()
        .filter(|i| i.kind == Kind::Dir && (i.rel != "." || opts.remove_top))
        .filter(|i| opts.filter.include.is_empty() || opts.filter.allows(&i.rel, false))
        .collect();
    // the same plan the count reports and the removal acts on, so the digest a counting
    // run prints is the digest the removing run computes
    if let Some(runtime) = &opts.runtime {
        let lines: Vec<String> = leaves
            .iter()
            .chain(dirs.iter())
            .map(|i| format!("# {}", i.rel))
            .collect();
        report.plan_digest = plan_digest(runtime, t.root(), std::path::Path::new(""), &lines);
    }
    if opts.force
        && (opts.confirm.is_some() || opts.require_confirm)
        && opts.confirm.as_deref() != Some(report.plan_digest.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "this run would remove entries; run it without -force to see what, and the digest that goes with it, then pass that digest as -confirm",
        ));
    }
    if !opts.force {
        for i in &leaves {
            match i.kind {
                Kind::File => {
                    report.files += 1;
                    report.bytes += i.size;
                }
                Kind::Symlink => report.symlinks += 1,
                Kind::Dir => {}
            }
        }
        report.directories = dirs.len();
        report.seconds = t0.elapsed().as_secs_f64();
        return Ok(report);
    }
    let next = AtomicUsize::new(0);
    let outcomes: Mutex<Vec<(usize, io::Result<Removed>)>> =
        Mutex::new(Vec::with_capacity(leaves.len()));
    std::thread::scope(|scope| {
        for _ in 0..parallel.min(leaves.len().max(1)) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= leaves.len() {
                    break;
                }
                let r = t.remove(&leaves[i].rel, leaves[i].kind);
                outcomes.lock().unwrap().push((i, r));
            });
        }
    });
    for (i, r) in outcomes.into_inner().unwrap() {
        match r {
            Ok(Removed::Gone) => match leaves[i].kind {
                Kind::File => {
                    report.files += 1;
                    report.bytes += leaves[i].size;
                }
                Kind::Symlink => report.symlinks += 1,
                Kind::Dir => {}
            },
            Ok(Removed::Deferred(why)) => report.deferred.push(format!("{}: {why}", leaves[i].rel)),
            Ok(Removed::Kept(why)) => report.kept.push(format!("{}: {why}", leaves[i].rel)),
            Err(e) => report
                .failures
                .push(format!("delete {}: {e}", leaves[i].rel)),
        }
    }
    for d in dirs.iter().rev() {
        match t.remove(&d.rel, Kind::Dir) {
            Ok(Removed::Gone) => report.directories += 1,
            Ok(Removed::Deferred(why)) => report.deferred.push(format!("{}: {why}", d.rel)),
            Ok(Removed::Kept(why)) => report.kept.push(format!("{}: {why}", d.rel)),
            // not empty with a filter in force: the directory keeps what the filter kept
            Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty && !opts.filter.is_empty() => {}
            Err(e) => report.failures.push(format!("rmdir {}: {e}", d.rel)),
        }
    }
    report.seconds = t0.elapsed().as_secs_f64();
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Set the owner and/or group; `from_*` restrict the change to entries currently owned so.
    Owner {
        uid: Option<u32>,
        gid: Option<u32>,
        from_uid: Option<u32>,
        from_gid: Option<u32>,
    },
    /// Map owners and groups through tables (`diag change -umap/-gmap`); entries whose owner
    /// is in neither table are left alone.
    OwnerMap {
        uid_map: BTreeMap<u32, u32>,
        gid_map: BTreeMap<u32, u32>,
    },
    Mode(u32),
    /// Set the access and/or modification time (`diag change -atime/-mtime`).
    Times {
        atime_ns: Option<i128>,
        mtime_ns: Option<i128>,
    },
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub changed: usize,
    pub failures: Vec<String>,
    /// Every entry changed, when asked for (`-v`).
    pub changed_paths: Vec<String>,
    pub seconds: f64,
}

/// `chown` / `chmod` over a tree, in parallel. A mode never applies to a symlink.
pub fn apply_tree<T: Tree>(
    t: &T,
    filter: &Filter,
    parallel: usize,
    change: Change,
    verbose: bool,
) -> io::Result<ApplyReport> {
    apply_tree_depth(t, filter, None, parallel, change, verbose)
}

/// `apply_tree` with a depth limit (`diag change -depth`).
pub fn apply_tree_depth<T: Tree>(
    t: &T,
    filter: &Filter,
    max_depth: Option<usize>,
    parallel: usize,
    change: Change,
    verbose: bool,
) -> io::Result<ApplyReport> {
    let t0 = Instant::now();
    // HERE rather than only in the caller, because `chmod`/`chown` was not the only
    // caller. `diag change` reaches this function directly, and measured against a WebDAV
    // collection -- where `set_metadata` returns `Ok` without issuing a request, since
    // there is nothing it could issue -- `diag change -mtime` reported `3 entries changed`
    // and `STATUS: PASSED` while `chmod` on the SAME tree was refused by name two commands
    // earlier. A guard with one consumer is a guard the next caller walks past, so it
    // belongs at the gate every caller goes through.
    if !t.rewrites_metadata_in_place() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            // no root in the text: both callers already name the endpoint when they print
            "this tree cannot change modes, owners or times once written, so there is nothing to change".to_string(),
        ));
    }
    let parallel = parallel.max(1);
    let listing = t.list(filter, max_depth, parallel)?;
    let mut report = ApplyReport::default();
    report
        .failures
        .extend(listing.errors.iter().map(|e| format!("list {e}")));
    // A directory passes an include filter during a walk so its children can match; here the
    // filter is about the entry itself, so directories are held to the same patterns.
    let items: Vec<&Item> = listing
        .items
        .iter()
        .filter(|i| {
            !(matches!(change, Change::Mode(_) | Change::Times { .. }) && i.kind == Kind::Symlink)
        })
        .filter(|i| {
            if i.rel == "." {
                filter.include.is_empty() && filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino)
            } else {
                filter.allows(&i.rel, false)
                    && filter.allows_owner_kind(i.kind, i.uid, i.gid, i.ino)
            }
        })
        .filter(|i| match &change {
            Change::Owner {
                from_uid, from_gid, ..
            } => from_uid.is_none_or(|u| u == i.uid) && from_gid.is_none_or(|g| g == i.gid),
            Change::OwnerMap { uid_map, gid_map } => {
                uid_map.contains_key(&i.uid) || gid_map.contains_key(&i.gid)
            }
            Change::Mode(_) | Change::Times { .. } => true,
        })
        .collect();
    let next = AtomicUsize::new(0);
    let outcomes: Mutex<Vec<(usize, io::Result<()>)>> = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|scope| {
        for _ in 0..parallel.min(items.len().max(1)) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let mut wanted = items[i].clone();
                let meta = match &change {
                    Change::Owner { uid, gid, .. } => {
                        wanted.uid = uid.unwrap_or(wanted.uid);
                        wanted.gid = gid.unwrap_or(wanted.gid);
                        MetaOptions {
                            mode: false,
                            times: false,
                            owner: true,
                            atime: false,
                        }
                    }
                    Change::OwnerMap { uid_map, gid_map } => {
                        wanted.uid = uid_map.get(&wanted.uid).copied().unwrap_or(wanted.uid);
                        wanted.gid = gid_map.get(&wanted.gid).copied().unwrap_or(wanted.gid);
                        MetaOptions {
                            mode: false,
                            times: false,
                            owner: true,
                            atime: false,
                        }
                    }
                    Change::Mode(m) => {
                        wanted.mode = *m;
                        MetaOptions {
                            mode: true,
                            times: false,
                            owner: false,
                            atime: false,
                        }
                    }
                    Change::Times { atime_ns, mtime_ns } => {
                        wanted.atime_ns = atime_ns.unwrap_or(wanted.atime_ns);
                        wanted.mtime_ns = mtime_ns.unwrap_or(wanted.mtime_ns);
                        MetaOptions {
                            mode: false,
                            times: true,
                            owner: false,
                            atime: true,
                        }
                    }
                };
                let r = t
                    .set_metadata(&wanted.rel, &wanted, meta)
                    .and_then(|refusals| {
                        if refusals.owner {
                            Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                format!(
                                    "ownership {}:{} not permitted (not root)",
                                    wanted.uid, wanted.gid
                                ),
                            ))
                        } else {
                            Ok(())
                        }
                    });
                outcomes.lock().unwrap().push((i, r));
            });
        }
    });
    let mut outcomes = outcomes.into_inner().unwrap();
    outcomes.sort_by_key(|(i, _)| *i);
    for (i, r) in outcomes {
        match r {
            Ok(()) => {
                report.changed += 1;
                if verbose {
                    report.changed_paths.push(items[i].rel.clone());
                }
            }
            Err(e) => report.failures.push(format!("{}: {e}", items[i].rel)),
        }
    }
    report.seconds = t0.elapsed().as_secs_f64();
    Ok(report)
}

// ---------------------------------------------------------------------------------------------
// estimate
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EstimateOptions {
    pub parallel: usize,
    pub filter: Filter,
    pub sample_bytes: u64,
    pub block_size: usize,
    /// Link speed for the best-case figure (`-gbit`).
    pub gbit: f64,
    /// Duration of the live test copy when a target tree is given (`-t`).
    pub live_seconds: f64,
    pub runtime: Runtime,
}

#[derive(Debug, Default)]
pub struct Estimate {
    pub directories: usize,
    pub files: usize,
    pub symlinks: usize,
    pub bytes: u64,
    pub scan_seconds: f64,
    pub sampled_files: usize,
    pub sampled_bytes: u64,
    pub sample_seconds: f64,
    pub read_bytes_per_s: f64,
    pub entries_per_s: f64,
    pub projected_data_seconds: f64,
    pub projected_metadata_seconds: f64,
    /// Best case at the given link speed: bytes over the wire, nothing else.
    pub gbit: f64,
    pub gbit_seconds: f64,
    /// Live test copy (`-target`): what was copied in the time allowed and the projection.
    pub live_files: usize,
    pub live_bytes: u64,
    pub live_seconds: f64,
    pub live_bytes_per_s: f64,
    pub projected_live_seconds: f64,
}

/// The parts of an estimate that need no I/O: totals and the link-speed floor. Used by
/// `estimate -id` on a saved scan.
pub fn estimate_static(
    directories: usize,
    files: usize,
    symlinks: usize,
    bytes: u64,
    gbit: f64,
) -> Estimate {
    Estimate {
        directories,
        files,
        symlinks,
        bytes,
        gbit,
        gbit_seconds: if gbit > 0.0 {
            bytes as f64 * 8.0 / (gbit * 1e9)
        } else {
            0.0
        },
        ..Default::default()
    }
}

/// Copies the largest files into `scratch` for up to `seconds`, measuring the rate. The
/// caller removes `scratch` afterwards.
pub fn live_copy<T: Tree>(
    src: &T,
    scratch: &T,
    files: &[&Item],
    parallel: usize,
    block_size: usize,
    seconds: f64,
    runtime: &Runtime,
) -> (usize, u64, f64) {
    let deadline = Instant::now() + Duration::from_secs_f64(seconds.max(0.1));
    let next = AtomicUsize::new(0);
    let done_files = AtomicUsize::new(0);
    let done_bytes = AtomicU64::new(0);
    let fopts = FileOptions {
        block_size: block_size.max(4096),
        hash: false,
        meta: MetaOptions {
            mode: false,
            times: false,
            owner: false,
            atime: false,
        },
        xattrs: false,
        fsync: false,
        nocache: true,
        preserve_atime: false,
        delta: false,
        stages: None,
        runtime: runtime.clone(),
    };
    let t0 = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..parallel.max(1).min(files.len().max(1)) {
            scope.spawn(|| {
                let mut buf = vec![0u8; fopts.block_size];
                while Instant::now() < deadline {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    // the scratch name is flat (`f0`, `f1`, ...): only the bytes matter here
                    let scratch_item = Item {
                        rel: format!("f{i}"),
                        ..files[i].clone()
                    };
                    let result = scratch.create_file(&scratch_item).and_then(|mut sink| {
                        sink.reserve(files[i].size)?;
                        src.read(&files[i].rel, &mut buf, &mut |seg| match seg {
                            Segment::Data(d) => sink.write(d),
                            Segment::Hole(n) => sink.hole(n),
                        })?;
                        sink.finish(&scratch_item, &[], fopts.meta, false)
                    });
                    if result.is_ok() {
                        done_files.fetch_add(1, Ordering::Relaxed);
                        done_bytes.fetch_add(files[i].size, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    (
        done_files.load(Ordering::Relaxed),
        done_bytes.load(Ordering::Relaxed),
        t0.elapsed().as_secs_f64(),
    )
}

/// Scans, then times reading a sample of the largest files with the requested parallelism,
/// and projects from the two rates. The projection is a floor for the data half (a copy also
/// writes) and a rough figure for the metadata half (a copy creates about four times the
/// metadata operations a scan performs); it is printed as such. With `live`, a scratch tree
/// under the intended target, the largest files are really copied there for `live_seconds`
/// and that rate projects the whole job.
pub fn estimate<T: Tree>(t: &T, live: Option<&T>, opts: &EstimateOptions) -> io::Result<Estimate> {
    let parallel = opts.parallel.max(1);
    let t0 = Instant::now();
    let listing = t.list(&opts.filter, None, parallel)?;
    let mut e = Estimate {
        scan_seconds: t0.elapsed().as_secs_f64(),
        ..Default::default()
    };
    for i in &listing.items {
        match i.kind {
            Kind::Dir => e.directories += 1,
            Kind::Symlink => e.symlinks += 1,
            Kind::File => {
                e.files += 1;
                e.bytes += i.size;
            }
        }
    }
    e.gbit = opts.gbit;
    e.gbit_seconds = if opts.gbit > 0.0 {
        e.bytes as f64 * 8.0 / (opts.gbit * 1e9)
    } else {
        0.0
    };
    e.entries_per_s = listing.items.len() as f64 / e.scan_seconds.max(1e-6);
    let mut by_size: Vec<&Item> = listing
        .items
        .iter()
        .filter(|i| i.kind == Kind::File && i.size > 0)
        .collect();
    by_size.sort_by_key(|a| std::cmp::Reverse(a.size));
    let mut sample: Vec<&Item> = Vec::new();
    let mut budget = opts.sample_bytes;
    for i in by_size {
        if budget == 0 {
            break;
        }
        sample.push(i);
        budget = budget.saturating_sub(i.size);
    }
    let next = AtomicUsize::new(0);
    let read = AtomicUsize::new(0);
    let t1 = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..parallel.min(sample.len().max(1)) {
            scope.spawn(|| {
                let mut buf = vec![0u8; opts.block_size.max(4096)];
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= sample.len() {
                        break;
                    }
                    let mut got = 0usize;
                    let _ = t.read(&sample[i].rel, &mut buf, &mut |seg| {
                        got += match seg {
                            Segment::Data(d) => d.len(),
                            Segment::Hole(n) => n as usize,
                        };
                        Ok(())
                    });
                    read.fetch_add(got, Ordering::Relaxed);
                }
            });
        }
    });
    e.sample_seconds = t1.elapsed().as_secs_f64();
    e.sampled_files = sample.len();
    e.sampled_bytes = read.load(Ordering::Relaxed) as u64;
    e.read_bytes_per_s = e.sampled_bytes as f64 / e.sample_seconds.max(1e-6);
    e.projected_data_seconds = if e.read_bytes_per_s > 0.0 {
        e.bytes as f64 / e.read_bytes_per_s
    } else {
        0.0
    };
    e.projected_metadata_seconds = listing.items.len() as f64 * 4.0 / e.entries_per_s.max(1e-6);
    if let Some(scratch) = live {
        let mut all: Vec<&Item> = listing
            .items
            .iter()
            .filter(|i| i.kind == Kind::File && i.size > 0)
            .collect();
        all.sort_by_key(|a| std::cmp::Reverse(a.size));
        let (f, b, s) = live_copy(
            t,
            scratch,
            &all,
            parallel,
            opts.block_size,
            opts.live_seconds,
            &opts.runtime,
        );
        e.live_files = f;
        e.live_bytes = b;
        e.live_seconds = s;
        e.live_bytes_per_s = b as f64 / s.max(1e-6);
        e.projected_live_seconds = if e.live_bytes_per_s > 0.0 {
            e.bytes as f64 / e.live_bytes_per_s
        } else {
            0.0
        };
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_excluded_or_deep_path_is_not_a_removal() {
        let mut excluded = Filter::default();
        excluded.exclude.push("skip".into());
        excluded.exclude.push("*.tmp".into());
        assert!(removal_in_scope(&excluded, "keep", Kind::File, None));
        assert!(!removal_in_scope(&excluded, "skip", Kind::Dir, None));
        assert!(!removal_in_scope(&excluded, "skip/child", Kind::File, None));
        assert!(!removal_in_scope(&excluded, "notes.tmp", Kind::File, None));
        let mut included = Filter::default();
        included.include.push("keep/*".into());
        assert!(removal_in_scope(&included, "keep", Kind::Dir, None));
        assert!(removal_in_scope(&included, "keep/a", Kind::File, None));
        assert!(!removal_in_scope(&included, "other", Kind::File, None));
        assert!(removal_in_scope(
            &Filter::default(),
            "a/b",
            Kind::File,
            Some(2)
        ));
        assert!(!removal_in_scope(
            &Filter::default(),
            "a/b/c",
            Kind::File,
            Some(2)
        ));
        assert!(removal_in_scope(
            &Filter::default(),
            ".",
            Kind::Dir,
            Some(1)
        ));
    }

    fn item(rel: &str, size: u64, mtime_ns: i128) -> Item {
        Item {
            rel: rel.into(),
            kind: Kind::File,
            size,
            mtime_ns,
            atime_ns: mtime_ns,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 1,
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    /// A log that keeps what it is told, so a failing tuner arm can show the decisions that
    /// got it where it ended up instead of only the destination.
    #[derive(Default)]
    struct Trace(Mutex<Vec<String>>);

    impl Log for Trace {
        fn enabled(&self) -> bool {
            true
        }
        fn line(&self, args: fmt::Arguments<'_>) {
            self.0.lock().unwrap().push(args.to_string());
        }
    }

    /// Where the tuner ended up, and what it is fair to conclude from that.
    struct Settled {
        readers: usize,
        writers: usize,
        /// The spread of the per-window rate measured with the knobs HELD STILL, as a
        /// percentage of its mean.
        ///
        /// **This is the rig's own noise floor, and it decides whose failure a failure is.**
        /// `tune` calls a window `worse` below -3% and `better` above +3%; if the rig varies
        /// by more than that with nothing moving, those verdicts are coin flips and the
        /// search is walking a landscape it cannot see. Every assertion below prints it, so
        /// the next person to read a failure is told whether to suspect the tuner or the
        /// machine it was measured on.
        noise_pct: f64,
        /// The mean of those same held-still windows, so a failure can say whether the rig
        /// was measuring the landscape it was given.
        mean_rate: f64,
        log: Vec<String>,
    }

    /// Runs the real `tune` against a stand-in whose throughput is a known function of the
    /// two stage limits, and returns where it settled.
    ///
    /// No files and no I/O: a thread advances `progress.bytes` at `rate(readers, writers)`,
    /// which is exactly what the tuner reads. That keeps the test about the SEARCH -- the
    /// only thing this change adds -- and out of the business of arranging a disk that is
    /// genuinely contended, which no test on a shared machine can do reproducibly.
    fn settle(
        ceiling: usize,
        rate: impl Fn(usize, usize) -> f64 + Send + Sync + 'static,
        windows: u32,
    ) -> Settled {
        settle_with_window(ceiling, rate, windows, Duration::from_millis(20))
    }

    fn settle_with_window(
        ceiling: usize,
        rate: impl Fn(usize, usize) -> f64 + Send + Sync + 'static,
        windows: u32,
        window: Duration,
    ) -> Settled {
        let stages = std::sync::Arc::new(crate::stage::Stages::new(ceiling));
        let progress = Progress::default();
        let finished = AtomicBool::new(false);
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            let (stages_w, progress_w, finished_w) =
                (std::sync::Arc::clone(&stages), &progress, &finished);
            s.spawn(move || {
                let tick = Duration::from_millis(1);
                // The fraction is CARRIED. A tick's share of a rate of 500 is 0.5 bytes,
                // and `0.5 as u64` is 0 -- so the first version of this harness fed the
                // tuner a flat zero for every configuration and every arm measured the
                // tuner's behavior on a dead stream. Found by the arms failing; it would
                // have been invisible had the landscape happened to favor the start.
                //
                // The rate is also scaled to real byte rates. A landscape written in tens
                // and hundreds would put a 20 ms window in single digits of bytes, where
                // the tuner's 3% thresholds are pure quantization noise; MiB/s puts the
                // windows where the comparison is about the landscape.
                const SCALE: f64 = (1u64 << 20) as f64;
                let mut carry = 0.0f64;
                let mut last = Instant::now();
                while !finished_w.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    // elapsed, not the nominal tick: sleep(1ms) is a floor, not a promise,
                    // and pretending otherwise makes the simulated rate depend on how
                    // loaded the machine is
                    let dt = last.elapsed().as_secs_f64();
                    last = Instant::now();
                    carry += rate(stages_w.read.limit(), stages_w.write.limit()) * SCALE * dt;
                    let whole = carry.floor();
                    carry -= whole;
                    progress_w.bytes.fetch_add(whole as u64, Ordering::Relaxed);
                }
            });
            let (r, w) = (
                std::sync::Arc::clone(&stages),
                std::sync::Arc::clone(&stages),
            );
            let mut knobs = vec![
                Knob::new("readers", ceiling, move || r.read.limit(), {
                    let s = std::sync::Arc::clone(&stages);
                    move |n| s.read.set_limit(n)
                }),
                Knob::new("writers", ceiling, move || w.write.limit(), {
                    let s = std::sync::Arc::clone(&stages);
                    move |n| s.write.set_limit(n)
                }),
            ];
            // THE RIG'S OWN NOISE FLOOR, measured before the search starts, with the knobs
            // held exactly where they are. Nothing about the landscape changes across these
            // windows, so every difference between them is the rig: the producer adds bytes
            // in per-tick lumps, and a window is however many lumps happened to land inside
            // it. Under load a tick dilates, fewer lumps land, and the spread grows.
            //
            // It is measured rather than assumed because `tune` decides on a 3% difference,
            // and a rig that varies by more than 3% with nothing moving is deciding the
            // search by coin flip. Reported in every assertion below so a failure names the
            // right suspect instead of sending the next reader into the tuner.
            let (noise_pct, mean_rate) = {
                let poll = (window / 10).max(Duration::from_millis(1));
                let mut rates = Vec::new();
                let mut last = progress.bytes.load(Ordering::Relaxed);
                for i in 0..9 {
                    let t = Instant::now();
                    while t.elapsed() < window {
                        std::thread::sleep(poll);
                    }
                    let now = progress.bytes.load(Ordering::Relaxed);
                    let seen = (now - last) as f64 / t.elapsed().as_secs_f64();
                    last = now;
                    // the first window is the producer thread starting up, not a measurement
                    if i > 0 {
                        rates.push(seen);
                    }
                }
                let mean = rates.iter().sum::<f64>() / rates.len() as f64;
                let var =
                    rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
                (
                    if mean > 0.0 {
                        100.0 * var.sqrt() / mean
                    } else {
                        f64::INFINITY
                    },
                    mean,
                )
            };
            let stop = &finished;
            s.spawn(move || {
                // THE BUDGET IS A COUNT OF WINDOWS, NOT A WALL-CLOCK DURATION, and the
                // difference is a test that fails under load while passing alone.
                //
                // This used to be `sleep(window * windows)`. That is a wall clock, and the
                // thing it is budgeting is not: `tune` spends a window as
                // `while t.elapsed() < window { sleep(poll) }`, and under CPU contention
                // each `sleep(poll)` overshoots, so a nominal 20 ms window takes longer and
                // FEWER of them fit in a fixed six seconds. The tuner then gets cut off
                // mid-climb. Measured: `the_tuner_attributes_a_rate_change_to_the_knob_that
                // _caused_it` failed at `4 readers (want 6)` during a full parallel suite
                // run, and passed in 6.00s when run alone on the same commit.
                //
                // A longer sleep would have papered over it at whatever load was current
                // and broken again on a busier machine. Waiting the SAME way the tuner
                // does makes both clocks dilate together, so the tuner gets its `windows`
                // windows whether the machine is idle or loaded.
                let poll = (window / 10).max(Duration::from_millis(1));
                for _ in 0..windows {
                    let t = Instant::now();
                    while t.elapsed() < window {
                        std::thread::sleep(poll);
                    }
                }
                stop.store(true, Ordering::Relaxed);
            });
            let trace = Trace::default();
            tune(&mut knobs, window, &progress, &next, 1, &finished, &trace);
            Settled {
                readers: (knobs[0].get)(),
                writers: (knobs[1].get)(),
                noise_pct,
                mean_rate,
                log: trace.0.into_inner().unwrap(),
            }
        })
    }

    /// The last few decisions, for a failure message. The whole log is hundreds of lines and
    /// the end is where the search stopped being able to improve.
    fn tail(log: &[String]) -> String {
        log.iter()
            .rev()
            .take(12)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    }

    /// The roadmap row for this feature, and the row's own wording needed correcting before
    /// it could be tested.
    ///
    /// **A merely SLOW sink wants MORE writers, not fewer.** If each write takes ten times
    /// a read and the writes are independent, saturating the pipe needs ten writers per
    /// reader; a tuner that answered "fewer" there would be wrong. The setting where fewer
    /// writers is right is a CONTENDED sink -- a device whose aggregate throughput peaks at
    /// a low queue depth and falls off past it, which is the ordinary behavior of a seeking
    /// disk, a rate-limited endpoint, or a server with a small request window. That is the
    /// case a single worker count cannot express, and it is the one modeled here: reads
    /// scale nearly linearly with concurrency, writes do not.
    #[test]
    fn a_contended_sink_settles_with_fewer_writers_than_readers() {
        // reads: nearly linear in R. writes: aggregate FALLS as W rises, peaking at W = 1.
        let s = settle(
            8,
            |rd, wr| {
                (rd as f64 * 20.0 / (1.0 + 0.02 * (rd - 1) as f64))
                    .min(150.0 / (1.0 + 2.0 * (wr - 1) as f64))
            },
            300,
        );
        let (r, w) = (s.readers, s.writers);
        assert!(w < r, "settled at {r} readers and {w} writers; the contended stage should have ended up the narrower one (rig noise {:.1}%)\n  {}", s.noise_pct, tail(&s.log));
        assert!(r >= 4, "readers settled at {r} of a ceiling of 8, so the search never climbed the uncontended stage (rig noise {:.1}%)\n  {}", s.noise_pct, tail(&s.log));

        // The control, and it is the half that makes the arm mean anything. Swap which
        // stage contends and the answer must swap with it. Without this, a tuner that
        // always drove the second knob down -- because of the probe order, an off-by-one,
        // or a knob whose setter did nothing -- would pass the assertion above while
        // measuring nothing at all.
        let s = settle(
            8,
            |rd, wr| {
                (150.0 / (1.0 + 2.0 * (rd - 1) as f64))
                    .min(wr as f64 * 20.0 / (1.0 + 0.02 * (wr - 1) as f64))
            },
            300,
        );
        let (r, w) = (s.readers, s.writers);
        assert!(r < w, "with the contention moved to the READ stage the tuner settled at {r} readers and {w} writers; it is not following the landscape, it is following the knob order (rig noise {:.1}%)\n  {}", s.noise_pct, tail(&s.log));
    }

    /// The generalization's own defect, caught by giving two knobs opposite landscapes.
    ///
    /// The single-knob loop measured a window, compared it with the previous one, and
    /// applied the verdict to the knob it was about to move -- sound when that is always
    /// the same knob. Carried over unchanged to three knobs it credits each knob with the
    /// PREVIOUS knob's effect. Replanted (evaluate `knobs[turn % n]` against the last
    /// window instead of the remembered `pending`) this arm fails: the two stages end up
    /// on the wrong sides, because each is being steered by the other's measurements.
    #[test]
    fn the_tuner_attributes_a_rate_change_to_the_knob_that_caused_it() {
        // A landscape where the two knobs want opposite extremes and nothing else does:
        // readers want the ceiling, writers want the floor, with no interaction term to
        // let a confused search stumble into the right answer.
        //
        // GEOMETRIC, so that every step is the same 50% whichever knob takes it and
        // wherever it is. The additive version this replaced (`rd * 50 + (7 - wr) * 50`)
        // has a per-step gain that SHRINKS as the search succeeds -- the last writer step
        // is worth 9% -- so near the answer the arm stopped testing attribution and started
        // testing whether the rig could resolve 9%. On a loaded machine it could not, and
        // the arm failed with the tuner behaving correctly. Relative gain is what a hill
        // climber compares, and here it is constant, so the arm asks the same question at
        // every point and on every machine.
        let s = settle(
            6,
            |rd, wr| 100.0 * 1.5f64.powi(rd as i32 - 1) * 1.5f64.powi(6 - wr as i32),
            300,
        );
        let (r, w) = (s.readers, s.writers);
        assert!(r >= 5 && w <= 2, "settled at {r} readers (want 6) and {w} writers (want 1): the search is not attributing rate changes to the knob that made the move (rig noise {:.1}%)\n  {}", s.noise_pct, tail(&s.log));
    }

    /// **A knob with nothing to gain must not move**, and until 2026-09-24 one moved across
    /// its entire range.
    ///
    /// The landscape here names only `rd`; `wr` appears nowhere in it, so no setting of the
    /// write knob is better or worse than any other and the correct behavior is to leave it
    /// alone. What the tuner did instead, measured on this exact landscape:
    ///
    /// ```text
    /// tune: writers 1 -> 2 flat, keeping, 304.4 MiB/s
    /// tune: writers 2 -> 3 flat, keeping, 305.9 MiB/s
    /// tune: writers 3 -> 4 worse,  undoing, 293.9 MiB/s
    /// tune: writers 3 -> 2 better, keeping, 304.2 MiB/s
    /// ```
    ///
    /// Two separate defects in four lines. `flat, keeping` is a RATCHET -- a knob that
    /// changes nothing reads flat in whichever direction it points, so it walks. And the
    /// `worse` and `better` verdicts are on 3.4% and 3.5% differences when two windows of
    /// an unchanged configuration already differ by about 2%, so they are coin flips
    /// dressed as measurements. 19 of the knob's 80 probes came back `better` and were kept.
    ///
    /// **The control is the landscape itself**: a knob absent from the rate cannot have a
    /// right place to be, so any movement at all is the defect, with no threshold to argue
    /// about. Three replants, three runs each, on the same machine as the five green runs
    /// of the fix:
    ///
    /// | replanted | arm fails | writer moves kept |
    /// | --- | --- | --- |
    /// | a flat window is kept (the behavior before this) | 3 of 3 | 94-99 of ~100 probes |
    /// | no confirming window before a keep | 3 of 3 | 2-8 of ~76 |
    /// | margin fixed at 3% instead of tracking the noise | **1 of 3** | up to 4 of 89 |
    ///
    /// **The third row is recorded because it is the weak one**, and a control that fires
    /// one time in three would be dishonest to present as a control. It is weak here for a
    /// reason that does not generalize: this rig's noise measures about 2%, so a fixed 3%
    /// is very nearly the right number by luck, and the confirming window covers the rest.
    /// The adaptive margin is kept for the machine where that luck runs out -- a busier
    /// runner, a longer window, a real link -- where 3% is inside the noise and every
    /// verdict is a coin flip. That is a claim about machines this arm has not run on, so
    /// it is stated as the reason for a choice and not as a measurement.
    /// **A step in the machine's load is not a knob's doing.** The landscape names only the
    /// read knob, and the whole rate steps between x1 and x1.5 every 200 ms -- ten windows at
    /// each level, a square wave of ambient load. A writer move probed just after a rising
    /// edge reads "better" in its probe AND its confirm window, both judged against a
    /// baseline taken before the edge; without the A/B/A recheck the tuner keeps it. The
    /// recheck re-reads the old setting two windows into the same plateau, sees it just as
    /// fast, and undoes the move. Found because `a_knob_with_nothing_to_gain_holds_still`
    /// failed 1 in 30 runs on a saturated four-core machine, keeping 6 of 77 probes; this
    /// makes that load profile deliberate instead of waiting for the scheduler to produce it.
    #[test]
    fn a_step_in_the_machines_load_is_not_credited_to_a_knob() {
        let start = Instant::now();
        let s = settle(
            6,
            move |rd, _wr| {
                rd as f64
                    * 50.0
                    * if (start.elapsed().as_millis() / 200).is_multiple_of(2) {
                        1.0
                    } else {
                        1.5
                    }
            },
            300,
        );
        let kept = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("keeping"))
            .count();
        let undone = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("the load moved"))
            .count();
        assert!(kept <= 1, "the write knob appears nowhere in the rate and kept {kept} moves under a stepping load ({undone} caught by the recheck)\n  {}", tail(&s.log));
    }

    /// **A load PULSE is not a knob's doing either.** Two windows at x1.5 every twelve: a
    /// writer move whose probe and confirm windows land in the pulse passes A/B/A -- the
    /// recheck, after the pulse, reads the old setting slower -- and A/B/A alone would keep
    /// it (100 / 150 / 150 / 100). The re-applied move must beat the recheck once more
    /// (A/B/A/B), and after the pulse it cannot.
    #[test]
    fn a_pulse_in_the_machines_load_is_not_credited_to_a_knob() {
        let start = Instant::now();
        let s = settle(
            6,
            move |rd, _wr| {
                rd as f64
                    * 50.0
                    * if start.elapsed().as_millis() % 240 < 40 {
                        1.5
                    } else {
                        1.0
                    }
            },
            300,
        );
        let kept = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("keeping"))
            .count();
        let caught = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("not again when re-applied"))
            .count();
        assert!(kept <= 1, "the write knob appears nowhere in the rate and kept {kept} moves under a pulsing load ({caught} caught by the final re-read)\n  {}", tail(&s.log));
    }

    /// **A dip after the pulse is not a step to credit either.** The load rises for the probe
    /// and confirm windows and then falls BELOW where it started for the recheck: the old
    /// setting reads slower than the move, and a recheck that took that as "no step" would
    /// leave the final re-read only the dip to beat. So the old setting has to re-read within
    /// the margin of its own baseline.
    #[test]
    fn a_pulse_then_a_dip_in_the_machines_load_is_not_credited_to_a_knob() {
        // The load is timed to the null knob's own moves, so every probe of it meets the same
        // adversary instead of whichever phase of a clock it happens to land on: from the
        // moment the write knob changes, 1.5x for the probe and confirm windows, 0.5x for the
        // recheck, then back to 1x. Moves made while that is playing out (the recheck and the
        // re-apply) do not restart it.
        let state = Mutex::new((usize::MAX, None::<Instant>));
        let s = settle(
            6,
            move |rd, wr| {
                let mut st = state.lock().unwrap();
                let quiet =
                    st.1.is_none_or(|t| t.elapsed() >= Duration::from_millis(100));
                if st.0 != usize::MAX && wr != st.0 && quiet {
                    st.1 = Some(Instant::now());
                }
                st.0 = wr;
                let since = st.1.map_or(u128::MAX, |t| t.elapsed().as_millis());
                rd as f64
                    * 50.0
                    * if since < 40 {
                        1.5
                    } else if since < 60 {
                        0.5
                    } else {
                        1.0
                    }
            },
            300,
        );
        let kept = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("keeping"))
            .count();
        assert!(kept <= 1, "the write knob appears nowhere in the rate and kept {kept} moves under a pulse followed by a dip\n  {}", tail(&s.log));
    }

    /// **A dip inside the margin is not a lower bar.** The same adversary timed to the null
    /// knob, but gentle: the recheck reads 10% low and the final re-read 5% high. On a margin
    /// between 10% and 16.7% -- this rig's runs 4% to 25% -- the recheck counts as "read as it
    /// did", and judged against the recheck alone the re-applied move beats it, keeping the
    /// knob for returning to about where it started. Judged against
    /// the higher of the baseline and the recheck it cannot be kept: "as it was" needs a
    /// margin of at least 10%, and beating the baseline then needs a gain over 10%, which
    /// 1.05x is not.
    #[test]
    fn a_dip_inside_the_margin_does_not_lower_the_bar() {
        // The adversary follows the tuner's MOVES of the write knob, not a clock, so each
        // level lands on its window however far a loaded machine stretches the windows (a
        // clock-timed first draft failed 1 run in 10 under a four-core load, every time on a
        // window that straddled two levels). A probe `was -> now` starts it at 1.5x; the
        // recheck putting `was` back drops it to 0.9x; the re-apply of `now` lifts it to
        // 1.05x; the undo that follows ends it at 1x. Any other move starts a new one.
        struct Adversary {
            last: usize,
            reader: usize,
            pulse: Option<(usize, usize)>,
            moves: u32,
        }
        let state = Mutex::new(Adversary {
            last: usize::MAX,
            reader: usize::MAX,
            pulse: None,
            moves: 0,
        });
        let s = settle_with_window(
            6,
            move |rd, wr| {
                let mut a = state.lock().unwrap();
                // A move of the OTHER knob ends the pulse. Left at 0.9x after a recheck that
                // was (rightly) undone without a move, the next write probe started from a
                // 0.9x baseline and finished on 1.05x: load that is higher whenever the knob
                // is at its new setting, which no A/B test can tell from the knob itself.
                // The adversary is ambient load around 1x, not a knob in disguise.
                if a.reader != usize::MAX && rd != a.reader {
                    a.pulse = None;
                }
                a.reader = rd;
                if a.last != usize::MAX && wr != a.last {
                    let (last, moves) = (a.last, a.moves);
                    a.moves = match a.pulse {
                        Some((was, _)) if moves == 0 && wr == was => 1,
                        Some((was, now)) if moves == 1 && wr == now && last == was => 2,
                        Some((was, _)) if moves == 2 && wr == was => 3,
                        _ => {
                            a.pulse = Some((last, wr));
                            0
                        }
                    };
                }
                a.last = wr;
                let level = match (a.pulse, a.moves) {
                    (Some(_), 0) => 1.5,
                    (Some(_), 1) => 0.9,
                    (Some(_), 2) => 1.05,
                    _ => 1.0,
                };
                rd as f64 * 50.0 * level
            },
            300,
            // On Windows 20 ms samples measured roughly 50% scheduler noise in
            // this adversary's 10% dip. Use a longer measurement interval; retain
            // the same landscape, budget and zero-kept-moves assertion.
            Duration::from_millis(if cfg!(windows) { 200 } else { 20 }),
        );
        let kept = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("keeping"))
            .count();
        let rechecked = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("rechecking"))
            .count();
        assert!(
            rechecked > 0,
            "no write probe reached the recheck, so this arm tested nothing\n  {}",
            tail(&s.log)
        );
        // zero, not "at most one": "as it was" needs a margin of at least 10%, and the final
        // re-read then has to beat the baseline by more than 5% it does not have
        assert_eq!(kept, 0, "the write knob appears nowhere in the rate and kept {kept} moves on a dip inside the margin\n  {}", tail(&s.log));
    }

    /// **No measurement, no move.** With nothing flowing -- a run of empty files, a server that
    /// has not sent a byte -- every window is zero, and a probe judged against a zero baseline
    /// and KEPT as "unmeasured" would let both knobs walk their ranges on no evidence. So such
    /// a move is undone.
    #[test]
    fn with_nothing_flowing_no_knob_moves() {
        let s = settle(6, |_rd, _wr| 0.0, 60);
        let kept = s.log.iter().filter(|l| l.contains("keeping")).count();
        assert_eq!(
            kept,
            0,
            "a move was kept with no throughput to judge it by\n  {}",
            tail(&s.log)
        );
    }

    /// **The last window is judged like the others.** The loop ends when the copy does, and
    /// it could end with a probe applied and no window to judge it, leaving the tail of the
    /// copy under a setting nothing measured. With nothing flowing every probe
    /// is undone, so the knobs have to end where they started, whichever window the budget
    /// runs out on.
    #[test]
    fn a_copy_that_ends_mid_probe_leaves_the_measured_setting() {
        let fresh = crate::stage::Stages::new(6);
        let start = (fresh.read.limit(), fresh.write.limit());
        for windows in 20..30 {
            let s = settle(6, |_rd, _wr| 0.0, windows);
            assert_eq!(
                (s.readers, s.writers),
                start,
                "after {windows} windows the knobs were left off the measured setting\n  {}",
                tail(&s.log)
            );
        }
    }

    #[test]
    fn a_knob_with_nothing_to_gain_holds_still() {
        let s = settle(6, |rd, _wr| rd as f64 * 50.0, 300);
        let kept = s
            .log
            .iter()
            .filter(|l| l.contains("writers") && l.contains("keeping"))
            .count();
        let probes = s.log.iter().filter(|l| l.contains("writers")).count();
        // EVERY VALUE THE WRITE KNOB WAS EVER SET TO, which is the measure that says
        // "traversed its range" rather than "happened to end somewhere". A final reading
        // alone would not: the budget can expire with a probe still in flight, so the last
        // value is legitimately one step off whatever the search settled on.
        let visited: std::collections::BTreeSet<&str> = s
            .log
            .iter()
            .filter(|l| l.contains("writers"))
            .flat_map(|l| {
                l.split_whitespace()
                    .skip(2)
                    .take(3)
                    .filter(|w| w.len() == 1 && w.chars().all(|c| c.is_ascii_digit()))
            })
            .collect();
        // Measured on the fix: 1 kept probe of 75 and three values touched, out of a
        // ceiling of 6. Measured on the defect: a kept move on nearly every probe, and all
        // six values.
        //
        // **The bound is on KEPT MOVES, and it was on values touched, which made this arm
        // fail about one run in six.** One kept move touches three values when it points at
        // the edge but FOUR when it points inward -- both neighbors of the start, then one
        // past the new position -- so `visited <= 3` rejected the single kept move the fix
        // is measured to make, whenever it happened to point inward: 5 of 30 runs, every
        // failure `keeping 1 of ~75` with values {1, 2, 3, 4}, and 2 of 10 on the commit
        // before. Values touched follow from kept moves and their direction, so they add no
        // signal of their own; kept moves are the measure.
        //
        // Re-measured, ten runs each, with every run's numbers printed (touched / kept):
        //
        // | build | kept moves | fails `kept <= 1` |
        // | --- | --- | --- |
        // | the fix | 0 in 10 runs; 1 in the 5 failures above; never 2 in 40 | 0 of 40 |
        // | a flat window is kept | 72-74, all six values | 10 of 10 |
        // | margin fixed at 3% | 0-8 | 7 of 10 |
        // | no confirming window | 0-3 | **3 of 10** |
        //
        // **The last row is weak and is recorded as weak.** On this landscape the margin does
        // most of the confirming window's work, so removing the window alone keeps two or
        // three moves in some runs and none in others; this arm is not what defends it. The
        // table in the doc comment above records 3 of 3 for that row under the old bound; it
        // was measured on a different run and is not reproduced here.
        assert!(
            visited.len() <= 4 && kept <= 1,
            "the write knob appears NOWHERE in the rate and still touched {} of 6 values ({visited:?}), keeping {kept} of {probes} probes, ending at {} (rig noise {:.1}%, mean {:.0} MiB/s)\n  {}",
            visited.len(),
            s.writers,
            s.noise_pct,
            s.mean_rate / (1024.0 * 1024.0),
            tail(&s.log)
        );
        // and the control's other half: the knob that IS in the rate must still have moved,
        // or "nothing moved" would pass the assertion above while measuring nothing
        assert!(s.readers >= 5, "the read knob settled at {} of a ceiling of 6, so the search stopped moving altogether and the assertion above proved nothing\n  {}", s.readers, tail(&s.log));
    }

    /// **The knobs move; do the gates ever open?** Those are different questions, and the
    /// contract arm only answers the first: it reads the tuner's log, which reports a knob
    /// moving whether or not anything passes through the gate it sets. A gate nobody enters
    /// is a setting with no effect, and it looks identical from the outside.
    ///
    /// So this runs a REAL `copy_one` against real local trees and reads the cumulative
    /// admission counters. It also pins the boundary, which is the half that would
    /// otherwise rot into a false assumption: a local copy with no digest wanted goes
    /// through `copy_file_range` in the kernel, which does both halves itself, so the
    /// stages are not entered AND MUST NOT BE. `-hash` is what declines the kernel path and
    /// puts the bytes on the streaming path the stages meter.
    #[test]
    fn a_staged_copy_takes_permits_and_a_kernel_copy_does_not() {
        let dir =
            std::env::temp_dir().join(format!("rcp-stage-{}-{}", std::process::id(), line!()));
        let (src_root, dst_root) = (dir.join("src"), dir.join("dst"));
        std::fs::create_dir_all(&src_root).unwrap();
        std::fs::create_dir_all(&dst_root).unwrap();
        let body: Vec<u8> = (0..(600u32 << 10)).map(|i| (i % 251) as u8).collect();
        std::fs::write(src_root.join("f.bin"), &body).unwrap();

        let src = crate::tree::LocalTree::new(&src_root);
        let dst = crate::tree::LocalTree::new(&dst_root);
        let listed = src.stat("f.bin").unwrap().expect("the fixture is there");

        let run = |hash: bool, name: &str| -> std::sync::Arc<crate::stage::Stages> {
            let stages = std::sync::Arc::new(crate::stage::Stages::new(4));
            let runtime = Runtime::default();
            let fopts = FileOptions {
                block_size: 64 << 10,
                hash,
                meta: MetaOptions {
                    mode: true,
                    times: true,
                    owner: false,
                    atime: false,
                },
                xattrs: false,
                fsync: false,
                nocache: false,
                preserve_atime: false,
                delta: false,
                stages: Some(std::sync::Arc::clone(&stages)),
                runtime,
            };
            let mut item = listed.clone();
            item.rel = name.to_string();
            let mut buf = vec![0u8; fopts.block_size];
            copy_one(&src2(&src_root, name, &body), &dst, &item, &fopts, &mut buf).unwrap();
            assert_eq!(
                std::fs::read(dst_root.join(name)).unwrap(),
                body,
                "the staged copy did not reproduce the bytes"
            );
            stages
        };

        // streaming path: a digest is wanted, so the kernel declines and every block goes
        // through the read gate and the write gate
        let staged = run(true, "hashed.bin");
        assert!(
            staged.read.entered() > 1,
            "the read gate was entered {} times on a 600 KiB file in 64 KiB blocks",
            staged.read.entered()
        );
        assert!(
            staged.write.entered() > 1,
            "the write gate was entered {} times",
            staged.write.entered()
        );

        // The control and the boundary: no digest, so `copy_file_range` moves the bytes and
        // there is nothing for the stages to meter. Zero on BOTH is correct, not a miss --
        // the read permit is taken inside the `in_kernel.is_none()` branch, so a file the
        // kernel handles never reaches either gate. (This assertion was written expecting
        // `(1, 0)`, on the assumption that the file's read permit was taken before the
        // kernel was offered the copy. It was not; the measurement corrected the guess,
        // which is the reason to assert the exact pair rather than `== 0` on one of them.)
        let kernel = run(false, "kernel.bin");
        #[cfg(windows)]
        assert!(
            kernel.read.entered() > 0 && kernel.write.entered() > 0,
            "the Windows fallback must meter both stages"
        );
        #[cfg(unix)]
        assert_eq!(
            (kernel.read.entered(), kernel.write.entered()),
            (0, 0),
            "the kernel path took {:?} permits; a copy the kernel performs end to end should reach neither gate",
            (kernel.read.entered(), kernel.write.entered())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A second tree rooted at the same place, so each arm reads its own name. `copy_one`
    /// takes `&T` for both ends, so source and destination must be the same type.
    fn src2(root: &std::path::Path, name: &str, body: &[u8]) -> crate::tree::LocalTree {
        std::fs::write(root.join(name), body).unwrap();
        crate::tree::LocalTree::new(root)
    }

    /// A fixed `-parallel N` must take no permits at all -- not "a wide gate", none. A gate
    /// wide enough not to bite is still a mutex and a condvar on every block of every file,
    /// and a user who asked for a fixed worker count did not ask for a tuner's machinery.
    #[test]
    fn a_fixed_parallel_count_leaves_the_stages_absent() {
        let runtime = Runtime::default();
        let mut opts = CopyOptions {
            runtime: runtime.clone(),
            ..Default::default()
        };
        opts.auto_parallel = false;
        assert!(
            opts.file_options().stages.is_none(),
            "a fixed -parallel built a FileOptions carrying stages"
        );
        // and the control: the flag is what decides it, so the other setting must differ
        opts.auto_parallel = true;
        assert!(
            opts.auto_parallel,
            "the option that selects the staged path is not readable"
        );
    }

    /// `verify -l` puts a `*` on every field that differs, and it used to decide that for
    /// the mtime itself, from a raw inequality. So a WebDAV run could print "modification
    /// times were not compared" and star the mtime column in the same output, and a
    /// difference inside `-mtimewindow` was starred after being ruled not a difference.
    /// The caller's verdict is passed in now; this is the arm that they agree.
    #[test]
    fn the_long_form_stars_the_mtime_only_when_the_comparison_said_it_differs() {
        let names = crate::names::SystemNames;
        // the two items differ in mtime RAW, which is the state a WebDAV destination is
        // always in, and in size, which is a real difference either way
        let s = item("f", 10, 1_000_000_000);
        let d = item("f", 20, 2_000_000_000);

        // The columns are mode, uid, gid, size, mtime -- each `*`-prefixed when it differs
        // -- so the mtime is the fifth. Checked by FIELD and not by substring: `*10` is
        // the size's star and a `contains("*1")` reads it as the mtime's.
        let mtime_field = |line: &str| line.split_whitespace().nth(4).unwrap_or("").to_string();

        // THE ARM: the comparison said the times do not differ, so the column is not starred
        let [src, dst] = long_pair(&s, &d, &names, false);
        assert_eq!(
            mtime_field(&src),
            "1",
            "the source mtime was starred after the comparison ruled it equal:\n{src}"
        );
        assert_eq!(
            mtime_field(&dst),
            "2",
            "the destination mtime was starred after the comparison ruled it equal:\n{dst}"
        );

        // THE CONTROL, two halves. The size DOES differ and must still be starred, so the
        // arm is not passing against a long form that stopped starring anything...
        assert!(
            src.contains("*10") && dst.contains("*20"),
            "the size difference lost its star:\n{src}\n{dst}"
        );
        // ...and when the comparison DOES say the times differ, the column is starred
        let [src, dst] = long_pair(&s, &d, &names, true);
        assert_eq!(
            mtime_field(&src),
            "*1",
            "a real mtime difference was not starred:\n{src}"
        );
        assert_eq!(
            mtime_field(&dst),
            "*2",
            "a real mtime difference was not starred:\n{dst}"
        );
    }
}
