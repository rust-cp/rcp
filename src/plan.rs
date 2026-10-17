//! The planner: pure logic from listings to actions. It never touches a filesystem, which is
//! what makes the resume, sync and hard-link rules testable in microseconds, and what keeps
//! the executor in `transfer.rs` a loop with no decisions in it.

use std::collections::{BTreeMap, BTreeSet};

use crate::catalog::{Entry, Kind};
use crate::ports::Item;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `copy`: everything is transferred.
    Fresh,
    /// `resume`: what the catalog lists and the destination still holds is skipped.
    Resume,
    /// `sync`: changed since the catalog is re-copied; what the source dropped is removed.
    Sync,
    /// `isync`: like sync, but the destination listing stands in for a catalog.
    Mirror,
}

#[derive(Debug, Default)]
pub struct Plan<'a> {
    /// Destination entries to remove, children before parents.
    pub remove: Vec<(String, Kind)>,
    /// Destination non-directories standing where the source has a directory, removed BEFORE
    /// the directories are made: a file (or a symlink) called `a` where the source has a
    /// directory `a`. Mirror and sync only; filled by `transfer::plan_run`, which has the
    /// unfiltered view of the destination this needs (see `in_the_way`).
    pub clear: Vec<(String, Kind)>,
    pub dirs: Vec<&'a Item>,
    /// Files whose content is transferred.
    pub copy: Vec<&'a Item>,
    /// Files created as hard links of an already-placed file: (item, rel of the file to link to).
    pub link: Vec<(&'a Item, String)>,
    pub symlinks: Vec<&'a Item>,
    /// Files the source renamed or moved since the catalog was written: (item at its new
    /// path, the old path, the digest recorded for it). Matched by inode, size and mtime
    /// against catalog entries the source no longer lists; sync only.
    pub moves: Vec<(&'a Item, String, String)>,
    pub skipped_files: usize,
    pub skipped_bytes: u64,
}

/// Whether a destination's modification time is the source's, allowing for a destination
/// that keeps coarser time: nanoseconds dropped (rsync, some filesystems) or milliseconds
/// (HDFS, object stores). A coarser time only counts when the dropped part is zero, so a
/// genuinely different time within the same second is still a difference.
pub fn same_mtime(source_ns: i128, destination_ns: i128) -> bool {
    if source_ns == destination_ns {
        return true;
    }
    // EITHER side may be the coarse one. `verify` takes its endpoints in the order written,
    // so checking only the destination makes an http, WebDAV or sftp SOURCE (whole
    // seconds) against a local destination (nanoseconds) report a difference for every
    // file of a correct copy. Measured: source `...579000000000` against destination
    // `...579366454338`, the same second, called a difference. Passing `-mtimewindow 1` in
    // both directions in the contract suite would route around it, which is a workaround
    // wearing a test's clothes.
    //
    // 100 ns is SMB, and only a REAL Samba behind an `smb://` endpoint shows why. NTFS and
    // `FileBasicInformation` both count in 100-nanosecond FILETIME ticks, so a local
    // source at `...827067` arrives as `...827000` and, without this unit, `verify` calls
    // every file of a correct copy a difference -- five of five, on a tree that `diff -r`
    // says is byte-identical. The suite cannot see it: its smb arm pins the source mtime
    // to `1_600_000_000`, a whole second, where the quantization rounds to nothing. Same
    // shape as the SMB CreditCharge defect -- the fixture was chosen where the coarse case
    // does not arise.
    //
    // **WHAT THIS COSTS, said plainly, because it is easy to call it narrower than it
    // is.** The guard is `either side is on a tick`, not `both are`, and it has to be: the
    // case it exists for is a nanosecond source against a tick-aligned destination. On an SMB destination that guard is therefore ALWAYS true -- every
    // FILETIME converted back is a multiple of 100 -- so against a share this accepts any
    // source within the same 100 ns bucket, up to 99 ns away. A destination that ROUNDED
    // rather than truncated would land in the next bucket and still compare unequal.
    //
    // That is the same shape as the whole-second unit above it, which can hide almost a
    // full second when one side lands on a second boundary, and it is a thousand times
    // narrower. It is not a claim that the comparison is exact.
    for unit in [1_000_000_000i128, 1_000_000, 100] {
        let (a, b) = (source_ns.div_euclid(unit), destination_ns.div_euclid(unit));
        if (destination_ns.rem_euclid(unit) == 0 || source_ns.rem_euclid(unit) == 0) && a == b {
            return true;
        }
    }
    false
}

/// Whether the destination already holds this item well enough to skip its transfer.
/// `times` is the destination's `keeps_times`: false means its mtimes are its own and a
/// file is held well enough when the size agrees.
fn matches(dst: Option<&Item>, item: &Item, times: bool) -> bool {
    match dst {
        Some(d) => match item.kind {
            Kind::File => {
                d.kind == Kind::File
                    && d.size == item.size
                    && (!times || same_mtime(item.mtime_ns, d.mtime_ns))
            }
            Kind::Dir => d.kind == Kind::Dir,
            Kind::Symlink => d.kind == Kind::Symlink && d.link_target == item.link_target,
        },
        None => false,
    }
}

/// `source`: the listing to transfer. `destination`: what is there now (empty for a fresh
/// target). `known`: the catalog for resume and sync. `hard_links`: whether files that share
/// an inode are recreated as links rather than copied twice. `source_complete`: whether the
/// source listing came back without errors -- see the removal block for why it decides
/// whether a mirror sweeps at all.
pub fn plan<'a>(
    mode: Mode,
    source: &'a [Item],
    destination: &BTreeMap<&str, &Item>,
    known: Option<&BTreeMap<String, Entry>>,
    hard_links: bool,
    times: bool,
    source_complete: bool,
) -> Plan<'a> {
    let mut p = Plan::default();
    let present: BTreeSet<&str> = source.iter().map(|i| i.rel.as_str()).collect();

    // Removals: for sync, catalog entries the source no longer has; for mirror, destination
    // entries the source no longer has. Children before parents so rmdir finds them empty.
    //
    // A MIRROR READS ABSENCE AS AN INSTRUCTION TO DELETE, so it may only do that from a
    // listing that is known complete. When the source listing reported an error, "the
    // source no longer has it" and "we could not see it" are the same observation, and
    // acting on the second destroys data the source still holds.
    //
    // Measured, on a WebDAV source whose server contradicted itself about ONE entry inside
    // `sub/`: that directory's listing failed, so `sub/deep1.txt` and `sub/deep2.txt` were
    // absent from `source`, and `isync` removed them from the mirror along with the
    // directory -- three entries deleted because of one entry nobody could read. The run
    // did exit non-zero, and the remedy it printed was `resume`, which re-plans the copy
    // and never plans removals, so nothing could undo it.
    //
    // Sync is NOT gated the same way, and the asymmetry is the point: sync removes what the
    // CATALOG says this run put there and the source no longer lists. A listing error means
    // the catalog entry is unconfirmed rather than contradicted -- still a reason not to
    // delete it, so the gate covers both -- but the mirror is the one that deletes files it
    // never wrote.
    let mut gone: Vec<(String, Kind)> = match (mode, known, source_complete) {
        (_, _, false) => Vec::new(),
        (Mode::Sync, Some(k), true) => k
            .iter()
            .filter(|(rel, _)| !present.contains(rel.as_str()))
            .map(|(rel, e)| (rel.clone(), e.kind))
            .collect(),
        (Mode::Mirror, _, true) => destination
            .iter()
            .filter(|(rel, _)| !present.contains(*rel))
            .map(|(rel, i)| (rel.to_string(), i.kind))
            .collect(),
        _ => Vec::new(),
    };
    gone.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(b.0.cmp(&a.0)));

    // Renames and moves: a catalog file the source no longer lists, whose inode, size and
    // mtime reappear under a new path, is one file that changed its name. Inode alone is
    // not enough (filesystems reuse numbers), and a catalog written before the inode column
    // records 0, which never matches.
    let mut gone_by_inode: BTreeMap<u64, Vec<&Entry>> = BTreeMap::new();
    if mode == Mode::Sync {
        if let Some(k) = known {
            for (rel, _) in &gone {
                if let Some(e) = k.get(rel) {
                    if e.kind == Kind::File && e.ino != 0 {
                        gone_by_inode.entry(e.ino).or_default().push(e);
                    }
                }
            }
        }
    }
    let mut claimed: BTreeSet<&str> = BTreeSet::new();

    // Files. The first file seen for a shared inode is copied; the rest link to it.
    let mut first_by_inode: BTreeMap<(u64, u64), &str> = BTreeMap::new();
    for item in source {
        match item.kind {
            Kind::Dir => p.dirs.push(item),
            // recreated idempotently in every mode: the adapter leaves a matching link alone
            Kind::Symlink => p.symlinks.push(item),
            Kind::File => {
                let dst = destination.get(item.rel.as_str()).copied();
                if mode == Mode::Sync && known.is_some_and(|k| !k.contains_key(&item.rel)) {
                    let old = gone_by_inode.get(&item.ino).and_then(|es| {
                        es.iter().find(|e| {
                            e.size == item.size
                                && e.mtime_ns == item.mtime_ns
                                && !claimed.contains(e.path.as_str())
                        })
                    });
                    if let Some(e) = old {
                        claimed.insert(e.path.as_str());
                        p.moves.push((item, e.path.clone(), e.sha256.clone()));
                        if hard_links && item.nlink > 1 {
                            first_by_inode
                                .entry((item.dev, item.ino))
                                .or_insert(item.rel.as_str());
                        }
                        continue;
                    }
                }
                let skip = match mode {
                    Mode::Fresh => false,
                    Mode::Resume => {
                        known.is_some_and(|k| k.contains_key(&item.rel))
                            && matches(dst, item, times)
                    }
                    Mode::Sync => match known.and_then(|k| k.get(&item.rel)) {
                        Some(e) => {
                            e.size == item.size
                                && e.mtime_ns == item.mtime_ns
                                && matches(dst, item, times)
                        }
                        None => false,
                    },
                    Mode::Mirror => matches(dst, item, times),
                };
                if skip {
                    p.skipped_files += 1;
                    p.skipped_bytes += item.size;
                    if hard_links && item.nlink > 1 {
                        first_by_inode
                            .entry((item.dev, item.ino))
                            .or_insert(item.rel.as_str());
                    }
                    continue;
                }
                if hard_links && item.nlink > 1 {
                    match first_by_inode.get(&(item.dev, item.ino)) {
                        Some(first) => {
                            p.link.push((item, first.to_string()));
                            continue;
                        }
                        None => {
                            first_by_inode.insert((item.dev, item.ino), item.rel.as_str());
                        }
                    }
                }
                p.copy.push(item);
            }
        }
    }
    gone.retain(|(rel, _)| !claimed.contains(rel.as_str()));
    p.remove = gone;
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(rel: &str, size: u64, mtime: i128, ino: u64, nlink: u64) -> Item {
        Item {
            rel: rel.into(),
            kind: Kind::File,
            size,
            mtime_ns: mtime,
            atime_ns: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 1,
            ino,
            nlink,
            blocks: size,
            link_target: None,
        }
    }
    fn dir(rel: &str) -> Item {
        Item {
            kind: Kind::Dir,
            ..file(rel, 0, 0, 0, 1)
        }
    }
    fn entry(i: &Item) -> Entry {
        Entry {
            path: i.rel.clone(),
            kind: i.kind,
            size: i.size,
            mtime_ns: i.mtime_ns,
            mode: i.mode,
            uid: i.uid,
            gid: i.gid,
            sha256: String::new(),
            ino: i.ino,
        }
    }

    #[test]
    fn fresh_copies_everything_and_links_shared_inodes() {
        let src = vec![
            dir("."),
            file("a", 10, 1, 100, 2),
            file("b", 10, 1, 100, 2),
            file("c", 5, 2, 101, 1),
        ];
        let p = plan(Mode::Fresh, &src, &BTreeMap::new(), None, true, true, true);
        assert_eq!(
            p.copy.iter().map(|i| i.rel.as_str()).collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert_eq!(
            p.link
                .iter()
                .map(|(i, t)| (i.rel.as_str(), t.as_str()))
                .collect::<Vec<_>>(),
            [("b", "a")]
        );
        // control: with hard links off, b is a second copy
        let p = plan(Mode::Fresh, &src, &BTreeMap::new(), None, false, true, true);
        assert_eq!(p.copy.len(), 3);
        assert!(p.link.is_empty());
    }

    #[test]
    fn resume_skips_only_what_the_catalog_lists_and_the_destination_holds() {
        let src = vec![
            dir("."),
            file("a", 10, 1, 1, 1),
            file("b", 10, 1, 2, 1),
            file("c", 10, 1, 3, 1),
        ];
        let dst_items = [
            file("a", 10, 1, 9, 1),
            file("b", 10, 1, 8, 1),
            file("c", 10, 7, 7, 1),
        ];
        let dst: BTreeMap<&str, &Item> = dst_items.iter().map(|i| (i.rel.as_str(), i)).collect();
        let known: BTreeMap<String, Entry> = [entry(&src[1]), entry(&src[3])]
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect();
        let p = plan(Mode::Resume, &src, &dst, Some(&known), true, true, true);
        // a: known and matching -> skipped; b: not known -> copied; c: known but mtime differs -> copied
        assert_eq!(
            p.copy.iter().map(|i| i.rel.as_str()).collect::<Vec<_>>(),
            ["b", "c"]
        );
        assert_eq!(p.skipped_files, 1);
        assert!(p.remove.is_empty(), "resume never removes");
    }

    #[test]
    fn sync_removes_what_the_source_dropped_children_first() {
        let src = vec![dir("."), file("keep", 1, 1, 1, 1)];
        let old = [
            dir("."),
            file("keep", 1, 1, 1, 1),
            dir("gone"),
            file("gone/x", 1, 1, 2, 1),
            file("gone/y", 1, 1, 3, 1),
        ];
        let known: BTreeMap<String, Entry> =
            old.iter().map(entry).map(|e| (e.path.clone(), e)).collect();
        let dst: BTreeMap<&str, &Item> = old.iter().map(|i| (i.rel.as_str(), i)).collect();
        let p = plan(Mode::Sync, &src, &dst, Some(&known), true, true, true);
        assert_eq!(
            p.remove.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
            ["gone/y", "gone/x", "gone"]
        );
        assert_eq!(p.skipped_files, 1);
        assert!(p.copy.is_empty());
    }

    #[test]
    fn sync_recognizes_a_renamed_file_by_inode_size_and_mtime() {
        // the catalog knew a/old.bin (inode 42); the source now has b/new.bin with the same
        // inode, size and mtime, and a/old.bin is gone
        let src = vec![
            dir("."),
            dir("b"),
            file("b/new.bin", 100, 5, 42, 1),
            file("other", 1, 1, 7, 1),
        ];
        let old = [
            dir("."),
            dir("a"),
            file("a/old.bin", 100, 5, 42, 1),
            file("other", 1, 1, 7, 1),
        ];
        let known: BTreeMap<String, Entry> = old
            .iter()
            .map(|i| Entry {
                sha256: if i.rel == "a/old.bin" {
                    "digest".into()
                } else {
                    String::new()
                },
                ..entry(i)
            })
            .map(|e| (e.path.clone(), e))
            .collect();
        let dst: BTreeMap<&str, &Item> = old.iter().map(|i| (i.rel.as_str(), i)).collect();
        let p = plan(Mode::Sync, &src, &dst, Some(&known), true, true, true);
        assert_eq!(
            p.moves
                .iter()
                .map(|(i, from, sha)| (i.rel.as_str(), from.as_str(), sha.as_str()))
                .collect::<Vec<_>>(),
            [("b/new.bin", "a/old.bin", "digest")]
        );
        assert!(p.copy.is_empty(), "the moved file is not copied again");
        assert_eq!(
            p.remove.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
            ["a"],
            "only the emptied directory is removed"
        );
        // control: a different mtime is a new file and a removal, not a move
        let src2 = vec![
            dir("."),
            dir("b"),
            file("b/new.bin", 100, 6, 42, 1),
            file("other", 1, 1, 7, 1),
        ];
        let p = plan(Mode::Sync, &src2, &dst, Some(&known), true, true, true);
        assert!(p.moves.is_empty());
        assert_eq!(p.copy.len(), 1);
        assert_eq!(
            p.remove.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
            ["a/old.bin", "a"]
        );
        // control: an inode of 0 (an older catalog) never matches
        let known0: BTreeMap<String, Entry> = known
            .iter()
            .map(|(k, e)| {
                (
                    k.clone(),
                    Entry {
                        ino: 0,
                        ..e.clone()
                    },
                )
            })
            .collect();
        let src0 = vec![dir("."), dir("b"), file("b/new.bin", 100, 5, 0, 1)];
        assert!(
            plan(Mode::Sync, &src0, &dst, Some(&known0), true, true, true)
                .moves
                .is_empty()
        );
    }

    #[test]
    fn coarser_destination_times_match_only_when_the_dropped_part_is_zero() {
        assert!(same_mtime(
            1_600_000_000_123_456_789,
            1_600_000_000_123_456_789
        ));
        assert!(
            same_mtime(1_600_000_000_123_456_789, 1_600_000_000_000_000_000),
            "seconds only"
        );
        assert!(
            same_mtime(1_600_000_000_123_456_789, 1_600_000_000_123_000_000),
            "milliseconds only"
        );
        assert!(
            !same_mtime(1_600_000_000_123_456_789, 1_600_000_000_124_000_000),
            "a different millisecond"
        );
        // a microsecond-truncated destination is a DIFFERENT 100 ns tick (...4567 vs
        // ...4560), so it is still a difference -- the 100 ns unit below does not swallow it
        assert!(
            !same_mtime(1_600_000_000_123_456_789, 1_600_000_000_123_456_000),
            "789 ns apart is not the same tick"
        );
        assert!(!same_mtime(
            1_600_000_001_000_000_000,
            1_600_000_000_000_000_000
        ));

        // 100 ns IS SMB, and these are the numbers a real Samba returned. Without this
        // unit, `verify` called five of five files a difference on a tree `diff -r` says is
        // byte-identical -- see the comment in `same_mtime`.
        assert!(
            same_mtime(1_790_292_449_658_827_067, 1_790_292_449_658_827_000),
            "an SMB FILETIME tick"
        );
        assert!(
            same_mtime(1_790_292_449_658_827_000, 1_790_292_449_658_827_067),
            "and with SMB as the source"
        );
        // THE CONTROL, and it is what keeps the tolerance from becoming a blanket 100 ns
        // window: the NEXT tick is a real difference, so a file written 100 ns later is
        // still reported. Tolerance applies only when one side sits exactly on a tick.
        assert!(
            !same_mtime(1_790_292_449_658_827_067, 1_790_292_449_658_827_100),
            "the next tick is a difference"
        );
        assert!(
            !same_mtime(1_790_292_449_658_827_167, 1_790_292_449_658_827_000),
            "167 ns apart crosses a tick"
        );
        // TWO CASES THE CONTRACT NEEDS AND A SINGLE TRUE-CASE ASSERTION WOULD MISS, and
        // they are the difference between an example and a contract:
        // neither side aligned, one nanosecond apart -- the predicate must not fire at all
        assert!(
            !same_mtime(1_790_292_449_658_827_067, 1_790_292_449_658_827_068),
            "two unaligned times must not be compared by bucket"
        );
        // and the case the guard DOES admit, stated rather than left implicit: with one
        // side on a tick, 99 ns is inside the bucket and is accepted
        assert!(
            same_mtime(1_790_292_449_658_827_099, 1_790_292_449_658_827_000),
            "one side aligned, 99 ns apart, is inside the tick this tolerates"
        );

        // AND THE FAR END OF THE UNIT ABOVE, which is what this tolerance really costs and
        // is easy to leave unstated. A whole-second SOURCE against a destination 900 ms
        // later is ACCEPTED. That is deliberate -- it is the case the `||` exists for, an
        // http/S3/tar source whose times are whole seconds against a local destination --
        // but it means `sync` can skip a file whose mtime
        // moved by most of a second when one side sits on a second boundary. The 100 ns
        // unit is a thousand times narrower than the hazard already here.
        assert!(
            same_mtime(1_600_000_000_000_000_000, 1_600_000_000_900_000_000),
            "a whole-second side tolerates the rest of its second, by design"
        );
        assert!(
            !same_mtime(1_600_000_000_100_000_000, 1_600_000_000_900_000_000),
            "with neither side on a boundary, 800 ms apart is a difference"
        );
        let src = vec![dir("."), file("a", 4, 1_600_000_000_123_456_789, 1, 1)];
        let old = [dir("."), file("a", 4, 1_600_000_000_123_000_000, 9, 1)];
        let dst: BTreeMap<&str, &Item> = old.iter().map(|i| (i.rel.as_str(), i)).collect();
        assert_eq!(
            plan(Mode::Mirror, &src, &dst, None, true, true, true).skipped_files,
            1,
            "a millisecond store holds the file"
        );
    }

    #[test]
    fn mirror_uses_the_destination_as_the_record() {
        let src = vec![
            dir("."),
            file("same", 4, 1, 1, 1),
            file("changed", 4, 2, 2, 1),
            file("new", 4, 1, 3, 1),
        ];
        let old = [
            dir("."),
            file("same", 4, 1, 1, 1),
            file("changed", 4, 1, 2, 1),
            file("extra", 4, 1, 4, 1),
        ];
        let dst: BTreeMap<&str, &Item> = old.iter().map(|i| (i.rel.as_str(), i)).collect();
        let p = plan(Mode::Mirror, &src, &dst, None, true, true, true);
        assert_eq!(
            p.copy.iter().map(|i| i.rel.as_str()).collect::<Vec<_>>(),
            ["changed", "new"]
        );
        assert_eq!(
            p.remove.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
            ["extra"]
        );
        assert_eq!(p.skipped_files, 1);
    }

    /// An incomplete source listing plans no removals, in either mode that has them.
    ///
    /// `extra` is absent from `source` in both runs below; the only difference is whether
    /// the listing that produced `source` came back clean. That is the whole rule: absence
    /// means "gone" only when the run could see everything, and otherwise means "unseen".
    /// The copies are unaffected -- what was seen is still worth transferring.
    #[test]
    fn an_incomplete_source_listing_plans_no_removals_but_still_copies() {
        let src = vec![dir("."), file("same", 4, 1, 1, 1), file("new", 4, 1, 3, 1)];
        let old = [
            dir("."),
            file("same", 4, 1, 1, 1),
            file("extra", 4, 1, 4, 1),
        ];
        let dst: BTreeMap<&str, &Item> = old.iter().map(|i| (i.rel.as_str(), i)).collect();
        let known: BTreeMap<String, Entry> =
            old.iter().map(|i| (i.rel.clone(), entry(i))).collect();

        for (mode, k) in [(Mode::Mirror, None), (Mode::Sync, Some(&known))] {
            // the control first: a complete listing really does propose the removal, so a
            // gate that simply never removed anything could not pass this pair
            let clean = plan(mode, &src, &dst, k, true, true, true);
            assert_eq!(
                clean
                    .remove
                    .iter()
                    .map(|(r, _)| r.as_str())
                    .collect::<Vec<_>>(),
                ["extra"],
                "{mode:?}: a complete listing did not propose the removal"
            );

            let partial = plan(mode, &src, &dst, k, true, true, false);
            assert!(
                partial.remove.is_empty(),
                "{mode:?}: an incomplete listing proposed {:?}",
                partial.remove
            );
            assert_eq!(
                partial
                    .copy
                    .iter()
                    .map(|i| i.rel.as_str())
                    .collect::<Vec<_>>(),
                clean
                    .copy
                    .iter()
                    .map(|i| i.rel.as_str())
                    .collect::<Vec<_>>(),
                "{mode:?}: the gate withheld copies as well as removals"
            );
        }
    }
}
