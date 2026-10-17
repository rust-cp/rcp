# Local competitor campaign

This campaign compares the unchanged v0.1.0 release with installed rsync,
rclone, and GNU cp. It is a local-filesystem comparison, not a network throughput
or state-of-the-art claim. `campaign.py` records exact versions, release provenance,
commands, randomized execution order, raw trials, CPU, sampled process-tree RSS,
kernel filesystem accounting, and independently verified completion time.

The generated small, large, and mixed corpora contain deterministic repeated
random blocks. Fresh copies and changed syncs are separate; cp participates only
in fresh copies. Sync changes append to every tenth file, remove every twentieth
file at a different offset, and add replacement files. All runs require equal
regular-file paths, contents (SHA-256), sizes, modes, and modification times.
Ownership, ACLs, xattrs, links, sparse extents, directory metadata, and crash
recovery are outside this profile. RCP catalog and inline hashing are disabled;
rclone post-copy checksum verification is disabled. Independent SHA-256 checking
is included in completion time for every tool. Each run ends with an external
filesystem flush; RCP also performs its own internal job flush.

Five measured trials per tool/case follow one warmup, with deterministic shuffled
tool order. This is a warm-cache, shared WSL2 host experiment without cache
dropping or privileged tuning. RSS sampling can miss short-lived peaks. CPU and
filesystem accounting describe the transfer process; barrier costs are recorded
separately and verification contributes elapsed time. Results are descriptive;
no statistical significance or universal ranking is asserted.

## Recorded results

`results/local-20261001` contains 126 validated trials: 105 measured trials and
21 warmups. Median verified completion seconds (five measurements each):

| Workload | Case | RCP | rsync | rclone | cp |
|---|---|---:|---:|---:|---:|
| Small | Fresh | 0.543 | 0.589 | 1.450 | 0.465 |
| Small | Changed | 0.782 | 0.809 | 0.937 | — |
| Large | Fresh | 2.676 | 2.920 | 2.756 | 2.690 |
| Large | Changed | 0.731 | 0.801 | 1.066 | — |
| Mixed | Fresh | 1.103 | 1.110 | 1.326 | 1.102 |
| Mixed | Changed | 0.406 | 0.343 | 0.365 | — |

RCP does not win every case: mixed changed sync was slower than both competitors,
and cp was faster for small fresh copies. Large-copy transfer-only times are
misleading because RCP flushes internally while the other tools' flush cost lands
in the external barrier. Use verified completion for this comparison.
The mixed-sync median gap to rsync was 62.849 ms, but RCP's five-run range was
274.630–751.139 ms and rsync's was 270.515–389.810 ms. Five shared-host trials
do not establish a repeatable 63 ms implementation penalty or a confidence
interval. Nanosecond clock readings include process startup, initialization and
command execution; enumeration/stat/hash/planning/write need separate probes.
Small repeatable gains matter, but a candidate needs more paired repetitions and
absolute millisecond distributions before it is accepted.

Kernel `wait4` filesystem output counters returned zero on this WSL host for all
tools, despite confirmed writes. Preserve those raw values as unavailable physical
I/O accounting, not evidence of zero writes. Logical source and changed-payload
byte counts are recorded; device/network byte measurements remain outstanding.
The CLI version string also reports "no runtime dependencies", but this packaged
GNU binary requires glibc and uses system GSSAPI for Kerberos; artifact inspection
and runtime documentation establish the actual requirements.

## Optimization evidence ledger

Existing mechanisms are code observations, not claims of measured benefit.
Conditional and deferred items require backend capabilities and correctness tests
before implementation. This list covers major families, not every published idea.

| Family | Status | Evidence or next decision |
|---|---|---|
| End-to-end bottleneck diagnosis | Benchmark next | Campaign includes verified completion, transfer CPU/RSS and flush cost; remote phase timings remain needed. |
| Capability-aware strategy | Existing | Tree adapters expose supported operations; compare strategy against endpoint capabilities. |
| Metadata-rich enumeration | Existing; benchmark next | NFS READDIRPLUS and SMB create metadata; measure redundant stat RPCs. |
| Protocol windows and compounds | Benchmark next | Measure outstanding requests/bytes independently of file concurrency. |
| Session reuse | Existing; benchmark next | Transport/session adapters exist; measure connection/setup work per job. |
| Metadata/signature caching | Existing; conditional | Catalog/hash cache; mutation and stale-signature tests must govern reuse. |
| Incremental change indexes | Conditional | Backend change-token support needs capability-specific fallback. |
| Server-side copy/clone/range assembly | Conditional | NFS COPY/CLONE, SMB COPYCHUNK and S3 copy require semantics/error validation. |
| Compression/raw bypass/sparse handling | Existing | Stream codecs, raw bypass and sparse paths; measure CPU and bytes on representative entropy. |
| Congestion and fairness | Deferred | Bandwidth limit exists; remote contention measurements precede controller changes. |
| Crypto execution/TLS offload | Existing; conditional | Crypto/TLS paths exist; no security weakening to improve timing. |
| Retry/throttling | Partial; benchmark next | Byte throttling and bounded local open retries exist; a general backend retry/backoff policy is not established. Audit failures before adding one. |
| Resume/checkpoint cadence | Existing; benchmark next | Catalog/resume; quantify persistence overhead and interruption recovery. |
| Verified/durable completion | Existing; benchmark next | Verification and job flush; campaign uses common SHA-256 and flush boundary. |
| Multiresource admission/scheduling | Deferred | First measure CPU, memory, I/O and request pressure together. |
| Buffers/allocation/byte backpressure | Benchmark next | Account resident buffers and queues; rejected CDC experiment remains preserved. |
| SIMD/PGO/LTO | Existing; conditional | Release LTO enabled; runtime-dispatch/fallback correctness before further tuning. |
| Portable native I/O | Deferred | Linux ARM constant defects and Unix/Linux assumptions block support claims. |
| Filesystem snapshot replication | Conditional | Requires suitable filesystem and explicit snapshot consistency semantics. |
| NUMA/NIC locality | Deferred | Current WSL host cannot provide representative placement measurements. |
| RDMA/kernel bypass/accelerators | Deferred | Needs representative hardware and authorization for host changes. |
| Multipath/FEC/distribution | Deferred | Requires remote failure/congestion workloads and integrity-preserving reconstruction. |

The bounded CDC optimization was tried in a draft change and rejected because some workloads
regressed. No candidate patch is applied to production. ETags are not assumed to
be universal MD5 values; cached signatures and range resumes require appropriate
strong validators. Do not enable privileged tuning, public publication, or new
access grants as part of this campaign.

## Remaining packaging and portability findings

The v0.1.0 release is Linux x86-64 GNU with glibc 2.39 and system GSSAPI for
Kerberos. ARM, macOS, and native Windows have not been validated. Hardcoded
Linux x86 flag constants in tree, io_uring and catalog paths differ on ARM;
native portability needs implementation and native tests, not only compilation.

The `scripts/publish.sh` path once mislabeled supplied binaries as static x86-64
and invented compiler/source provenance. That was fixed separately; the fix does
not change the v0.1.0 binary measured here.

Debug events already use the `Log` port and `-loglevel DEBUG` stderr adapter
(`src/log.rs`); jobs retain IDs and logs (`src/jobs.rs`), and diagnostic operations
live in `src/diag.rs`. Structured timestamps, correlated operation/request IDs,
retry reasons, and phase timings remain candidates. Any implementation must redact
credentials, leave MCP stdout valid, and make remote export opt-in. No distributed
tracing or external telemetry support is claimed by this campaign.

## First phase profile and upstream comparison

The five-repeat mixed changed-sync profile in `results/mixed-flush-profile-20261001`
uses the same release and correctness checks, with `profile-flush.c` observing
actual `syncfs` calls through LD_PRELOAD. It calls the real function, preserves its
result and errno, and never suppresses the flush. Compile with the command in the
source header, then run the campaign with `--workloads mixed --cases changed
--repeats 5 --preload /absolute/path/profile-flush.so`. Static programs do not
interpose; external GNU sync barriers are still observed. This exploratory run
overlapped the tail of local Rust tests and is not a new performance ranking.

All 18 profiled trials passed (15 measured, three warmups). The mixed source had
809 files and 40,505,992 bytes after mutations. Only 1,020,552 bytes in 122 modified
or new files required copying; 41 paths were deleted. Mutation selection is by
sorted path, not random bytes, and the largest mixed file was unchanged.
RCP's median internal flush was 0.060882 s, versus median transfer elapsed time
0.122035 s. This attributes a substantial measured phase cost to durability.
The remaining time includes process startup, enumeration, planning, metadata and
copying; their separate costs are not yet measured. Removing the flush would
weaken completion semantics and is not an acceptable optimization.

The subsequent ten-repeat `mixed-metadata-profile-20261001` adds observational
libc metadata probes; all 33 trials passed (30 measured and three warmups).
Every measured RCP process made 1,689 `statx` calls and 1,784 `readdir64` calls.
Median cumulative boundary times were 2.962 ms and 0.867 ms respectively;
median internal flush was 67.506 ms and command elapsed time was 138.970 ms.
These probes do not measure Rust-side indexing, allocations, process startup,
io_uring syscalls or all file I/O. Static binaries bypass LD_PRELOAD, and forked
children can inherit counters: do not compare or sum their totals as equivalent
syscall coverage. Probe overhead also makes these diagnostic trials unsuitable
as new performance rankings.

Source audit found a single `dst.sync()` at the end of `copy_tree`; local `sync`
uses one `syncfs` on the destination filesystem. It is not a per-file default
flush, and it can include unrelated dirty data on that filesystem. The measured
profile has exactly one internal RCP flush per trial. Errors become failures,
with advice to verify content because resume's size/time check cannot establish
durability after writeback failure. No redundant production flush was identified
in this workload. The extra external barrier is part of the comparison protocol.

`analyze.py RESULTS_DIR` derives `phases.csv` from retained raw trials and checks
the arithmetic. It separates command, external flush and SHA-256 verification
in milliseconds for each comparator; command time includes any internal flush.
Medians of individual phases need not sum to median completion. The ten-repeat
RCP libc boundary details are preserved in `rcp-boundaries.csv`.

Exact comparator versions are rsync 3.2.7/protocol31, rclone 1.74.4 and GNU cp9.4.
The script now resolves executable paths under the measurement PATH and hashes
them before collecting versions and timing; profile versions match the original
campaign. Original evidence is retained unchanged.

| Comparator source | Observation tied to this campaign | Attribution limit |
|---|---|---|
| [rsync generator.c, commit 6b5ae825db985e9d1c98576651b50c8e490ddb97](https://github.com/RsyncProject/rsync/blob/6b5ae825db985e9d1c98576651b50c8e490ddb97/generator.c) | `quick_check_ok` compares size and mtime for ordinary files; `generate_files` supports incremental file lists. Our explicit `--whole-file` disables delta transfer. | Incremental traversal is a candidate to compare; it is not established as the cause of the observed gap. |
| [rsync receiver.c at the same commit](https://github.com/RsyncProject/rsync/blob/6b5ae825db985e9d1c98576651b50c8e490ddb97/receiver.c) | `receive_data` calls per-file fsync only when requested and verifies transfer checksums. We did not request `--fsync`; the common external barrier is necessary. | Inline transfer checksum work differs from the other tools, despite equal independently checked final contents. |
| [rclone operations.go, commit 5bc93a2a7ab0ebd0a11352bc4968eabeffb18027](https://github.com/rclone/rclone/blob/5bc93a2a7ab0ebd0a11352bc4968eabeffb18027/fs/operations/operations.go) | `equal` first rejects size differences, then can accept matching modification times. Appends change size; unchanged files keep exact times. | Hash-based handling of same-size/time-changed files is not exercised by this mutation pattern. |
| [rclone local.go at the same commit](https://github.com/rclone/rclone/blob/5bc93a2a7ab0ebd0a11352bc4968eabeffb18027/backend/local/local.go) | `Size` and `ModTime` return stored object metadata. The update path copies and closes output; metadata updates re-read it. | Metadata reuse is a source-derived hypothesis to test with counters, not proof of fewer syscalls in this run. |
| [rclone sync.go at the same commit](https://github.com/rclone/rclone/blob/5bc93a2a7ab0ebd0a11352bc4968eabeffb18027/fs/sync/sync.go) | `run` constructs a `march.March` over source and destination; checking and transfers have separate configured queues. Our checkers/transfers are each one. | Higher concurrency defaults cannot explain our results because those defaults were overridden. |
| [GNU coreutils copy.c, v9.4](https://github.com/coreutils/coreutils/blob/v9.4/src/copy.c) | `copy_reg` has clone, kernel-copy and buffered paths. Our `--reflink=never` disables clone, with external flush and verification. | cp is a fresh-copy comparator, not a changed-sync implementation. |

The rsync and coreutils sources are GPLv3-or-later; rclone is
[MIT licensed](https://github.com/rclone/rclone/blob/5bc93a2a7ab0ebd0a11352bc4968eabeffb18027/COPYING).
No external code was imported. Independently implemented ideas still need mutation,
metadata, deletion, interruption and durability regressions, followed by paired
baseline/candidate measurements. Current evidence does not justify a production
optimization or a claim that delta chunking caused the competitor difference.
