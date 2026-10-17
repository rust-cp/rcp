# Design

A hexagon, all the way through. `ports.rs` holds every interface the core talks through:
`Tree` and `Sink` for a storage location (`list`, `read` as segments of data and holes,
`create_file`, `kernel_copy`, metadata, attributes), `Digests` for the content hash,
`Throttle` for the read rate, `Log` for debug lines, `Names` for user and group ids, and
`Batches` for a worker fleet; `Runtime` bundles the cross-cutting ones. The core (`plan.rs`,
`transfer.rs`, `scan.rs`, `catalog.rs`, `filter.rs`) is written against those ports only and
keeps no process-wide state: `plan.rs` turns listings into actions with no I/O, so the resume,
sync and hard-link rules are unit-tested in microseconds, and `transfer.rs` and `scan.rs` run
the use cases. The driven adapters are `LocalTree` (with `uring.rs` as its fast engine),
`NfsTree` and `Nfs4Tree`, `S3Tree`, `HdfsTree`, the two digests, the token bucket, the
stderr log, the system name tables and the ssh fleet, each taking its settings at
construction; `anytree.rs` is the static dispatch over the trees and `Transports` the
settings of every remote kind. The driving adapter is the CLI in `main.rs`: it parses the
options, assembles a `Runtime` and `Transports`, opens the trees and calls the use cases; a
library caller starts from `Runtime::plain()`. `tests/hexagon.rs` reads the source and fails
when a core module names an adapter or keeps a static, with a control that plants an offense
and checks the scan sees it. `unsafe` is the syscalls a copy needs -- `tree`, `uring`, `gss`, `xattr` -- plus seven libc
declarations in five other modules: `setsid` and `kill` (`jobs`), `signal` (`cluster` and
`main`), `prctl` and `getppid` (`mcp`), `isatty` (`lib`). **Hand-kept versions of this
sentence go wrong easily**: naming only the four modules, miscounting the declarations, or
attributing a `fork` to `cluster`, which this crate does not call anywhere. The list above
came from `grep -rn 'extern "C"' src/`, and so should the next one: a hand-kept inventory
of the code is the code's second copy, and the second copy is the one that rots. The protocol code (`nfs/`: XDR, SUN RPC, NFSv3; `s3/`: HTTP,
SigV4, the XML that the service speaks) is written against the standard library and tested
against in-process stand-in servers that speak the real wire formats.
