# Commands

| command | behavior |
| --- | --- |
| `copy` | Walks SOURCE and recreates it under DESTINATION: directories, regular files, symlinks (as symlinks, never followed), hard links (as hard links), extended attributes and ACLs. Preserves mode, owner, group and modification time. Runs of zero bytes and filesystem holes become holes, so a sparse disk image stays sparse. Every completed entry is appended to the catalog under the copy ID with the SHA-256 of the bytes read. |
| `resume` | Reopens the catalog for `-id` and copies only what the catalog does not list, or lists but the destination no longer matches (size and mtime). The endpoints come from the catalog, so an interrupted copy resumes with one argument. |
| `sync` | Re-scans SOURCE against the catalog: changed files (size or mtime) are copied again, new entries are added, and entries the source no longer has are removed from DESTINATION. A file the source renamed or moved (same inode, size and mtime under a new path) is renamed on the destination rather than copied again and removed: `rename` locally and over NFS, a server-side copy and delete on S3. A second `sync` with no changes reports 0 files, 0 removed, 0 moved. `-snap PATH` reads from another path standing in for the source, such as a snapshot directory. `sync dry-run` lists what would happen (`+` new, `*` changed, `=` link, `>` moved, `#` removed; `-q` for counts only), with `-stats` reports tree statistics over everything new or changed, and with `-target` also checks that the destination still matches the index. |
| `isync` | The same incremental mirror without a catalog: the destination listing is the record. Useful for a periodic mirror where nobody wants state on the side. `isync estimate` reports what the next run would move and a projected time. **A run whose source listing reported any error plans no removals at all**, and says so: an entry the run could not see is not an entry the source no longer has, and a mirror is the one mode that reads absence as an instruction to delete. `sync` is gated the same way. |
| `verify` | Compares every SOURCE entry with DESTINATION: type, size, content (byte for byte, stopping at the first difference), mode, owner, group, modification time, symlink target, extended attributes, and whether hard-linked files are still one inode. Destination entries the source lacks are differences too. One `DIFF <kind> <path>: ...` line per difference; `-l` adds the two-line long form with differing fields starred; `-stats` compares tree statistics (counts, size and depth bins) instead of entries, `-csv` as rows. A destination whose mtime nanoseconds are zero on a matching second is tolerated with one warning, as rsync and some filesystems drop them; `-mtimewindow` makes the comparison strict within a window. |
| `scan` | Lists a tree, and **fails when any directory could not be read** -- the counts still print, because a partial answer beats none, but they are short by an unknown amount and the verdict says so rather than reporting PASSED over a subtree nobody saw (`-json` carries the count as `done.unreadable`). `-l` long listing with user and group names (`-nonames` for numbers), `-csv` machine-readable rows, `-fmt TEMPLATE` with `{path}`, `{size}`, `{mtime}`, `{mode_s}`, `{user}`, `{sha256}` and friends, `-stats` histograms by size, extension, depth, age and owner plus the largest files and directories, `-html` a self-contained page, `-du` / `-duk` per-directory usage, `-sha256` digests, `-hashcache` to answer from a remembered digest when a file's size, nanosecond mtime and inode all still agree (128 files / 1.07 GiB, warm page cache: 0.22 s and 128 files read becomes 0.004 s and **zero** files read, same digests). It is opt-in on purpose and the reason is the one thing to know about it: a writer that overwrites bytes in place without changing the length and restores the mtime leaves nothing for the cache to notice, so a scan run to CATCH that must not use the flag -- which is why a plain `scan -sha256` still reads every byte. Two algorithms over one tree are two caches, a damaged cache is a miss rather than an error, and a filtered run never evicts what it did not look at. `verify`, `copy` and `sync` do not consult it: a `verify` answering from a record is not a verify, and a copy reads the bytes anyway. `-edupe` exact-duplicate groups and the bytes a dedupe would reclaim, `-depth N` to stop early, `-q` for the summary only. `-newid ID` saves the scan as an index; `scan -id ID` produces every report from the saved index without touching the tree. A bare `rcp PATH` is `scan PATH`. |
| `estimate` | Scans, times reading a sample of the largest files at the requested parallelism, and projects a copy time from the measured rates, with a best-case figure at `-gbit N` link speed. `-target DIR -t DURATION` runs a live test copy into a scratch directory under the target for that long, removes it, and projects from the measured write rate. `estimate -id SCANID` gives the static figures from a saved scan. Labeled as rough, because it is. |
| `delete` | Counts what would go and stops. With `-force` removes files and symlinks in parallel, then directories from the deepest up; the top directory only with `-removetopdir`. Refuses `/`. |
| `chown`, `chmod` | Apply an owner or an octal mode across a tree, in parallel, honoring the filters. `chown` takes `-user` and `-group` (names or numbers), `-user-from` / `-group-from` to touch only entries currently owned so, or `-reference PATH` to copy another entry's ownership; `chmod` takes `-mode` or `-reference`; `-v` lists every entry changed. A mode never applies to a symlink. |
| `show` | With a host: asks its portmapper which RPC programs it serves (nfs, mountd, nlockmgr, ...) and its MOUNT service which paths it exports to whom; `-v` also mounts each export and reports its transfer sizes and free space. Without one: lists this host's mounted filesystems from `/proc/self/mountinfo`, network types (NFS, CIFS, Ceph, sshfs and friends) by default, everything with `-all`. |
| `indexlist`, `indexdelete` | Show or remove catalogs; `indexdelete -match GLOB` removes every catalog whose ID matches. `jobs` and `jobs.log` are not available as copy IDs -- the catalog root already uses those names, and `copy -newid jobs` put a catalog where the job records live, after which `indexdelete -id jobs` deleted every one of them. **A catalog whose index cannot be read prints `unreadable` and fails the command** -- not `0 entries` under `STATUS: PASSED`, which is what an EMPTY catalog looks like and which made a torn one survey as healthy. |
| `logdump` | Prints `jobs.log`: one line per command run, with endpoints, outcome, duration and summary. With an ID it filters to that ID and writes `ID.zip` in the working directory holding those lines and the catalog's index. |
| `diag` | Maintenance and troubleshooting commands. `-cat`, `-mkdir`, `-rmdir` and `-rmrf PATH` are file utilities on any endpoint (a file on an export or in a bucket included); `-rmid ID` removes an index. `diag nio` is an I/O generator: `-read`/`-write`/`-read% N`, `-random`/`-sequential`/`-rand% N`, `-t SECS`, `-bs`, `-size` per worker file (default 64 MiB), `-parallel` worker files each driven by `-npend` threads, `-wrdata` for random bytes; positional I/O on a local path, reads through the port and whole-file rewrites on a remote one; it reports ops/s and bytes/s and removes its files. `diag find -branch-match GLOB` lists the directories holding a matching file and `-top-match GLOB` the top-level branches whose files all match, with the other filters as predicates and `-l`, `-q`, `-fmt`. `diag change` sets `-u`/`-g`, maps owners through `-umap`/`-gmap` CSV tables (`from,to` per line), or sets `-atime`/`-mtime` (`YYYY-MM-DD_HH:MM:SS[+nanoseconds]`, taken as UTC, or epoch seconds), honoring the filters and `-depth`. `diag indexdiag -id ID` checks an index's ancestry against its destination (orphans, missing, unlisted); `-rebuild` writes `ID.rebuilt` from what the destination holds, `-replace` (or `diag rebuild`) overwrites the original. `diag dump` lists the rcp processes on this host with their memory, threads and descriptors. |

## Options

`-parallel N` (default: the CPU count, between 2 and 8) sets the number of workers for every
command that has any.
`-match GLOB` and `-exclude GLOB` filter by path relative to the root: `*` within a
component, `**` across components, `?`, `[a-c]`, `[!x]`; a pattern without `/` also matches
the last component, so `-exclude '*.tmp'` means what people expect. Directories pass an
include pattern during a copy so their children can match; for `chmod`, `chown` and `delete`
the pattern applies to the entry itself. `-minsize SIZE`, `-maxsize SIZE`, `-newer AGE` and
`-older AGE` (`64k`, `2g`; `30m`, `7d`, `2w`) select files by size and modification age,
`-type f|d|l`, `-uid` and `-gid` (names or numbers) by kind and owner, `-fileid N` by inode
number; all apply to every command that walks a tree. `rcp help filters` has examples.

`-dryrun` on `copy`, `resume`, `sync` and `isync` plans, prints the counts (files, bytes,
removals, skips) and writes nothing, not even a catalog. A destination that does not exist
yet is planned against as an empty one and is not created. That holds on local, WebDAV,
HDFS, SFTP, SMB and NFS destinations. NFS resolves the path component by component; the
walk stops at the first missing one, and every call on that root then answers "no such
file or directory" rather than acting on the parent it did reach. `-progress` prints a line every five
seconds on stderr with files, bytes and rate, and once at the end; it is on by default when
stderr is a terminal and `-noprogress` turns it off. Stdout stays parseable either way.

Copy options: `-engine auto|uring|threads`, `-nohash` (no digest; the kernel copies the bytes
with `copy_file_range`, which is a reflink on XFS and Btrfs and a server-side copy on an
NFSv4.2 *mount* -- this is the kernel acting on an ordinary path, not rcp's own `nfs://`
client, which speaks v3 and v4.0 and offers no server-side copy at all), `-nolinks` (hard links become separate files), `-noxattr`, `-chown` (ownership
must be preserved, otherwise the entry fails), `-noown` (never touch ownership),
`-nodes HOSTS` and `-copybatch PROG` (cluster mode, above),
`-preserve-atime`, `-fsync` (per file; the default is one `syncfs` per job), `-nocache` (drop
copied data from the page cache so a large backup does not evict the working set), `-bs SIZE`
(block size, default 1m), `-depth N`.

Verify options: `-nodata`, `-noattrs` (no mode, owner, mtime or attributes), `-noown`,
`-nomods` (no mtime), `-mtimewindow SECONDS` (tolerance for servers that round), `-noxattr`,
`-nolinks`, `-v` (a verdict line per entry), `-csv` (differences as `kind,path,detail`).

`-bwlimit RATE` (`64m`, `1g`, `500k/s`) caps the bytes read from sources per second across
every worker and engine, one token bucket for the whole run, so a migration can share a
link. `-loglevel DEBUG` writes one line per event on stderr: each endpoint opened and its
transport, an NFS server's ports and programs, every S3 and HDFS request with its status,
every worker launched in cluster mode. `INFO`, the default, writes none, and any other level
is refused. `-dircount SIZE` (default `64k`) is the READDIRPLUS request size on an export
(on v4, the READDIR `dircount`). `-nfs.vers 3|4` and `-nfs.sec
sys|krb5|krb5i|krb5p` are described under NFS above. `-md5` checksums the files the way `-sha256` does; the digest
is SHA-256 unless `-blake3` selects BLAKE3 (pure Rust, tree-parallel over 1 KiB chunks,
several times faster per core; not a FIPS digest, which is why SHA-256 stays the default).
The `-csv` column and `{hash}` placeholder follow the digest in force. Accepted and without effect:
`-nonames` on commands without listings, `-preserve-atime` on commands that only read
(sources are opened with `O_NOATIME`), and `license` / `activate` (no activation is required).
`-s3.endpoint`, `-s3.profile`, `-s3.insecure` and `-s3.noverify` are described under S3.

Ownership is the one thing a non-root copy cannot fully preserve. By default a refused
`chown` is counted and reported once as a warning; `-chown` turns it into a per-entry error,
`-noown` stops rcp from trying. Extended attributes the destination refuses (`trusted.*` and
`security.*` without the capability) are reported the same way.
