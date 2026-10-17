# Linux comparison, rcp 0.1.1

Local copies on this machine, ten verified runs each, cold and warm page cache.
Headline `rcp` is the default copy: SHA-256 (SHA-NI on this CPU), io_uring, a
catalog entry per finished file, and a final `syncfs`. `rcp-nohash` and
`rcp-kernel` (`-nohash -engine threads`) are labeled diagnostics, not the product.

0 of 480 trials failed an independent SHA-256 check. rcp, rsync, and cp also
matched mode and exact mtime. rclone is content only.

## Machine

KVM guest, not WSL. Ubuntu 24.04.5, kernel `6.12.94+`, 4 vCPU Intel Xeon
(family 6, model 207, SHA-NI, AVX-512), 16 GB RAM, no swap. The bench disk is
ext4 on `/dev/vdc` (`findmnt -T /var/tmp`).

`dd` of 1 GiB on that disk, after the campaign:

| op | command | result |
|---|---|---|
| write | `dd if=/dev/zero of=/var/tmp/ddtest bs=1M count=1024 conv=fdatasync` | 1.1 GB/s |
| cold read | `sync; echo 3 > /proc/sys/vm/drop_caches` then `dd if=/var/tmp/ddtest of=/dev/null bs=1M` | 1.5 GB/s |
| warm read | same `dd` again | 3.5 GB/s |

Versions: rcp 0.1.1 (`sha256` hardware, io_uring available), binary SHA-256
`8cf3d3819f1ecdf7b853f9c7e0896ec22ed7080c7fa07995a3bab1ae1bb68b8b`; rsync 3.2.7
protocol 31; rclone v1.60.1-DEV; GNU cp 9.4; rustc 1.99.0. Statistics match
hyperfine `--runs N` (min, max, mean, median, standard deviation) over verified
trials. The driver is `bench/campaign.py` because each trial is checksummed
outside the timer.

Guest `drop_caches` does not evict the hypervisor disk cache, so later cold
runs can be warmer than the first. Tool order inside each repetition is
shuffled (seed 7). Medians are what the tables use.

## What was timed

The tool command only. Before every timed command, cold runs `sync` and drop
the page cache; warm runs `sync` only. That sync matters: rcp ends a local
copy with `syncfs`, which flushes every dirty page on the filesystem. Without
it, a warm rcp trial pays for the previous tool's writeback and looks slower
than it is. `sync` leaves the page cache populated.

Commands:

- rcp fresh: `rcp -catalog DIR copy SRC DST` (directory contents, same layout as `rsync SRC/` and `cp -a SRC/. DST/`)
- rsync fresh: `rsync -a --whole-file SRC/ DST/`
- rsync delta: `rsync -a` (size and mtime, no `--delete`, no `--whole-file`)
- rclone: `rclone copy` / `rclone sync`
- cp fresh only: `cp -a --reflink=never SRC/. DST/`
- delta: `rcp sync -id job1` against a catalog written at the same paths
- resume: SIGTERM, then SIGKILL after 2 seconds, once 30% of source files are complete by size; rsync uses `--partial` then `--append`

Corpora, payload a tiled 64 KiB `os.urandom` block, seed 7:

| workload | shape |
|---|---|
| small | 80 directories × 100 files × 4 KiB (8,000 files) |
| large | 4 × 64 MiB (256 MiB) |
| mixed | 1,500 × 4 KiB + 24 × 512 KiB + 3 × 8 MiB |
| delta | the mixed tree, 128 bytes appended to every 10th file, 30 files added, nothing deleted |
| resume | 24 × 8 MiB |

## Medians (seconds)

Ten verified runs. Failed column is 0 on every row. The per-trial logs are
not committed; `bench/campaign.py` writes them under `--out` when the run
is reproduced.

### Cold

| workload | rcp | rcp-nohash | rcp-kernel | rsync | rclone | cp |
|---|---:|---:|---:|---:|---:|---:|
| small | **0.190** | 0.187 | 0.208 | 0.276 | 0.429 | 0.379 |
| large | 0.280 | 0.252 | 0.281 | 0.348 | 0.341 | **0.171** |
| mixed | 0.109 | 0.104 | **0.098** | 0.151 | 0.188 | 0.118 |
| delta | **0.073** |  |  | 0.098 | 0.118 |  |
| resume | 0.237 |  |  | **0.218** | 0.225 |  |

### Warm

| workload | rcp | rcp-nohash | rcp-kernel | rsync | rclone | cp |
|---|---:|---:|---:|---:|---:|---:|
| small | 0.172 | 0.172 | **0.157** | 0.237 | 0.297 | 0.188 |
| large | 0.238 | 0.226 | 0.216 | 0.301 | 0.281 | **0.137** |
| mixed | 0.091 | 0.081 | 0.064 | 0.125 | 0.136 | **0.061** |
| delta | **0.052** |  |  | 0.074 | 0.066 |  |
| resume | **0.140** |  |  | 0.191 | 0.165 |  |

Default rcp is faster than rsync and rclone on every workload except cold
resume. It is faster than cp on cold and warm small, cold mixed, and both
delta runs. It is slower than cp on large files (both caches) and on a warm
mixed tree, and slower than rsync on a cold resume.

## Where rcp loses

### Large files versus cp

Cold median 0.280 s versus cp 0.171 s (about 1.6×). Warm 0.238 s versus
0.137 s (about 1.7×). rcp still beats rsync (0.348 s cold, 0.301 s warm) and
rclone (0.341 s cold, 0.281 s warm).

A single cold run of the same 256 MiB tree, `TIMEFORMAT` and `strace -c`:

| tool | wall | user | sys | what the syscalls were |
|---|---:|---:|---:|---|
| `cp -a --reflink=never` | 0.169 s | 0.001 s | 0.148 s | 2048 `read` + 2048 `write`, no `copy_file_range` |
| rcp default | 0.239 s | 0.138 s | 0.200 s | `io_uring_enter` |
| `rcp -nohash -engine threads` | 0.268 s | 0.000 s | 0.183 s | `copy_file_range` |

The user time on the default run is SHA-256 of 256 MiB on one thread (SHA-NI).
`syncfs` in that strace was 0.17 ms, so the durability flush is not the gap on
this virtual disk. Turning the hash off does not catch cp: the campaign's
cold `rcp-nohash` median is 0.252 s, and `copy_file_range` on this virtio ext4
is slower than cp's 128 KiB `read`/`write`. io_uring with the hash on the ring
thread adds both costs on one thread, and four workers do not help a single
disk the way they help 8,000 small files.

A double-buffered copy that hashed the previous 128 KiB while the next was
read was implemented and measured against `/tmp/rcp-v02-baseline` and cp, five
cold interleaved runs, checksummed. It was slower than io_uring and was not
kept (`git checkout -- src docs` after the trials):

| attempt | rcp median | cp median | baseline io_uring median |
|---|---:|---:|---:|
| channel, one slot of queue | 0.347 s | 0.184 s | 0.285 s |
| rendezvous channel | 0.352 s | 0.160 s | 0.265 s |
| atomics, spinning | 0.378 s | 0.200 s | 0.287 s |
| atomics, `park`/`unpark` | 0.411 s | 0.199 s | 0.355 s |

`strace -c` of the channel attempt spent 0.316 s in 4,107 `futex` calls. The
park attempt's own `time` was wall 0.356 s, user 0.149 s, sys 0.184 s: the
digest sat beside the copy in the accounting and did not hide under it. A
standalone two-thread copy of one 64 MiB file did match cp (both 0.047 s) while
burning a core on a stand-in hash, so overlap is possible on this guest. The
same shape inside rcp did not beat the io_uring path, and checksums were the
reason to stop rather than keep tuning a regression.

Skipping `set_len` before the writes was tried earlier and did not beat the
old binary. It was reverted the same way. Sparse files stayed on the extent
path throughout; `sparse_input_stays_sparse_on_every_engine` was not weakened.

### Warm mixed tree versus cp

Cold mixed, rcp wins (0.109 s versus cp 0.118 s). Warm mixed, cp is 0.061 s
and rcp is 0.091 s. `rcp-kernel` (no hash, `copy_file_range`) is 0.064 s, next
to cp. The warm gap is the SHA-256, paid on data that is already in the page
cache. That is the default on purpose: the catalog records a digest.

### Cold resume versus rsync

Cold median 0.237 s versus rsync 0.218 s (about 8%). Warm resume goes the
other way: rcp 0.140 s, rsync 0.191 s. rcp catalogs a file when it finishes and
recopies a partial file. rsync `--append` continues the interrupted file.
Appending without a digest of the prefix that is already on disk would report
a checksum rcp had not computed. That change was not made.

## Tests

No product test failed, so there is no test-fix change.

| command | result |
|---|---|
| `cargo test --locked --all-targets` | 573 passed, 0 failed, 0 ignored |
| `cargo test --locked --doc` | 5 passed, 0 failed |
| `cargo test --locked --features rustls` | 0 failed (577 tests + 5 doctests) |
| `LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/13 scripts/fuzz.sh 10` | exit 0. json 13,739,687 runs, zstd 3,044,642, deflate 101,817, lz4 14,120,382, no crash |

The fuzz link needs that `LIBRARY_PATH`: rust-lld looks for `-lstdc++`, and the
unversioned library is only under the gcc directory. The seed corpus in
`fuzz/corpus/` is a few bytes; libFuzzer grew inputs from it.

## Not run

- k3s interop (`interop/k3s/tests.sh`). This guest's pid 1 is tini, not
  systemd, and `k3s`, `kubectl`, and `docker` are not installed. The script
  needs a cluster and `KUBECONFIG`.
- NFS. The client filesystems `nfs` and `nfs4` are present. `nfsd` is not in
  `/proc/filesystems`, so the kernel server cannot start.
- S3 and SFTP. MinIO is not installed (the current community URL returns
  HTTP 410), and sshd is installed but not running. A download or an apt
  install during the timed campaign would have dirtied the disk those trials
  were measuring. They were not added after the fact as a shorter, separate
  study.

## Reproduce

```bash
RCP_BIN=target/release/rcp python3 bench/campaign.py \
  --out bench/results/linux-20261014 \
  --work /var/tmp/rcp-bench-fair \
  --runs 10 --caches cold,warm --seed 7
```

The binary measured above is the release build of the sources these results
ship with, SHA-256 `8cf3d381…`. The raw logs from that run are not in the
tree.
