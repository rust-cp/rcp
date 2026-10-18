# Engines

The `copy` family has two file engines and picks one at runtime.

**io_uring** (default where the kernel allows it): each worker owns a ring and drives up to
16 files at once as small state machines: open both ends, read a window of chunks, write each
chunk as it lands, hash chunks in offset order, apply metadata, close. One thread keeps a
queue depth of dozens of operations, which is what an NFS server or an NVMe device needs to
show its throughput; a thread doing one blocking read then one blocking write cannot. The ring
is set up with raw syscalls and hand-mapped shared memory rather than through a crate.
Kernels older than 5.6, or hosts where `io_uring_setup` is disabled by policy (a common
hardening setting, and Docker's default seccomp profile), make the setup fail and the thread
engine takes over with no difference in the result.

**threads**: the portable engine. Per-worker buffers, `SEEK_DATA` / `SEEK_HOLE` extent maps so
holes cost nothing, `copy_file_range` per extent when no digest is wanted, `O_NOATIME` on
sources, `posix_fadvise(SEQUENTIAL)`, positional writes, metadata through the open descriptor
(`fchmod`, `futimens`, `fchown`, `fsetxattr`), and a single `syncfs` at the end of the job.

That final flush is a *durability* step. It is tempting to make a failing one a warning,
on the reasoning that the files are in place, named and readable, with only their writeback
to stable storage in doubt. **It is a failed copy, for every destination**, because that
reasoning is wrong: a `syncfs` that fails is the filesystem saying it could not write the data, which is not a
weaker claim than the files being visible. The same call on a registry is a *publishing*
step — the manifests go up there,
and until they do nothing can be pulled — so there a failure fails the run. One port
method carrying both meanings would apply one policy to both; the tree answers which kind
it is, and that same answer is what refuses a fleet against a
destination nobody would ever call `sync` on.

Both engines hash with SHA-256 on the x86 SHA extensions when the CPU has them (about five
times the portable rate), detected once at runtime; `rcp version` says which. The directory
walk is parallel too: a work queue of directories shared by the workers, because a
metadata-bound tree is limited by `lstat` latency, not bandwidth.
