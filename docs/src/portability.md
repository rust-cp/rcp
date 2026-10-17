# Platform validation

This is a development support matrix, not a list of published binaries. Releases publish
the Linux x86-64 GNU build only; Linux ARM64 and Windows x86-64 are built from source.
Candidates are development builds, not release assets.

| Target | Current status | Remaining validation |
| --- | --- | --- |
| Linux x86-64 GNU | Existing supported release target; portability regression checks run on an x86-64 Linux container | Existing UBI 9/10 and minimum GLIBC 2.29 compatibility evidence applies to the existing release, not automatically to newly built candidates |
| Linux ARM64 GNU | Protected-open flags corrected; cross-check/link and native ordinary runtime qualification passed | Pinned older-libc candidate requires GLIBC 2.29 and passed native UBI9/GLIBC 2.34 smoke; full native protocol/KDC peers remain separate |
| Windows x86-64 MSVC | Native NTFS local adapter and executable implemented; optimized local/CLI and S3, WebDAV, HTTP and verified TLS tests passed | Real Windows SMB peers and unsupported protocol/process features remain separate qualifications |

## Architecture

Keep copy, verify, scan and sync against the existing `Tree` and `Sink` ports.
Platform filesystem, process and loader code belongs in driven adapters. `platform`
centralizes Linux open-flag ABI constants used by the local tree, catalog, CLI log
and io_uring adapters. AArch64 uses `O_NOFOLLOW = 1 << 15` and
`O_DIRECTORY = 1 << 14`, whereas x86-64 uses bits 17 and 16. These differences are
specified by the [Linux ARM64 UAPI header](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/fcntl.h).
The regression test checks kernel behavior, including that a rejected file-link
open leaves its target bytes intact.

`Sink::raw_fd` now returns a platform kernel-copy capability: a Unix descriptor on
Unix, and an uninhabited type on Windows. Windows sinks return `None`, selecting
the generic thread engine without interpreting a Windows handle as an integer fd.
The new `Tree::validate_paths` hook refuses case-only source/destination aliases
before planning can treat one Windows entry as both a copy and a removal.

## Native ARM64 qualification

A native run passed on GitHub's standard `ubuntu-24.04-arm` runner. The run and the
commits it tested predate this repository's current history, so they are not linked
here; rerun `portability.yml` to reproduce it. The script asserted `uname -m = aarch64` and native Rust host
`aarch64-unknown-linux-gnu` (Rust 1.87.0). This is native execution, not emulation.

Formatting and all-target/all-feature Clippy passed. The bounded
`s3,smb,dav,https,rustls` build passed 362 library tests and 2 CLI unit tests.
Default-feature architecture/reference suites passed 5 hexagon, 7 description,
1 documentation and 3 xxHash tests. All 13 exactly selected release/TLS CLI
contracts passed: copy/verify, every engine, sparse files, resume, sync, deletion,
hard links, xattrs, version/crypto vectors, MCP and job cancellation. Protected
file/directory symlink opens and SHA-256 backend/FIPS vectors passed natively.
The ordinary scope does not execute NFS, Kerberos or OCI realm contracts and
does not qualify all native protocol peers.

The initial Ubuntu release/TLS candidate is ELF64 AArch64. Its direct dependencies are
`libc.so.6`, `ld-linux-aarch64.so.1` and `libgcc_s.so.1`; GSSAPI stays dynamically
loaded. Its required symbol versions include **GLIBC_2.39**. It is an Ubuntu 24.04
development candidate, not proof of UBI 9/10 or GLIBC 2.29 compatibility. The
archive checksum at the stated commit is
`60043241711fbcab4cb4e46890d4d9b450519d527dcd16969ce535ffa21f5e32`.

Reproduce on a native AArch64 GNU/Linux host with Rust 1.87, procps, zstd and
libzstd development headers using `bash scripts/test-linux-arm64.sh`, or dispatch
`portability.yml` with `scope=ordinary-arm64`. Full ARM64 protocol/KDC qualification
and Windows qualification have independent manual scopes. No candidate is
uploaded or released by this recipe.

## Older-GLIBC ARM64 packaging

A native ABI run (which, like the run above, predates the current history) built the
unchanged application
with official Rust 1.90.0/Bullseye on the existing native ARM runner. The builder
uses GLIBC 2.31 and the candidate's **maximum required symbol version is GLIBC_2.29**.
The independent native runtime is UBI 9.8/GLIBC 2.34. Its exact-binary copy/verify,
isync, MCP ping, missing-input failure, deletion preview and forced deletion
smoke passed, and the host GSSAPI library loaded. This establishes ordinary
runtime compatibility on UBI9; it does not claim functional runtime testing on
GLIBC 2.29, all protocol/KDC peers, UBI10 or FIPS.

The ARM supplier manifests are pinned separately from the existing x86 manifests:

- Builder: `docker.io/library/rust@sha256:c90f06dc32cb5ba7716c1e65fc2c63b4a430580bd8b6a676e1028aed0ed53e5d`.
- Runtime: `registry.access.redhat.com/ubi9/ubi-minimal@sha256:a28d61d9531d13cb1c0a70d2e9f214aee029db73b614149122747905d973de74`.

The builder's default Linux protocol features plus rustls are compiled; the
shared build script keeps its x86 default and accepts `aarch64-unknown-linux-gnu`.
The gate validates ELF64 machine and interpreter, rejects GLIBC_PRIVATE and
requirements above 2.34, and retains the observed maximum. Six gate
tests passed, including newer/private ABI and wrong architecture/interpreter
refusals. Existing x86 Container CI also checks its real default-target binary.

Binary SHA256 for this run is
`081c468e7dcd5b7dacaf20cba9bc1cad00677abaf1f49c5f16532cdc4df1dc4b`.
Reproduce with manual `portability.yml` scope `arm64-abi`. The evidence
artifact retains the exact binary, Cargo lock/metadata and notices, supplier
configuration, RPM inventory, GLIBC gate output, toolchain and command results.
The final native package run passed the same build/runtime gates
and produced archive SHA256
`c0186acac7fb5459af7e1ae1cb95c35e32e1f2e1e619d0cc67c1cb7f9e754da8`.
Both independent builds produced the same binary SHA256 recorded above. The
downloaded archive was checked for exactly six regular files, licenses, ELF64
AArch64 identity and matching archived, downloaded and native-smoked binary
checksums. The candidate archive includes licenses, runtime requirements and checksums; it
is not published as a release. The UBI package lists name packages without versions,
so a superseded RPM no longer breaks the build; a new base image digest or package set
still needs renewed native qualification.

## Windows candidate scope

Build with Rust 1.87 and the existing MSVC/Windows SDK tools:

```powershell
cargo build --locked --release --no-default-features --features s3,smb,dav,https,rustls
./scripts/test-windows.ps1 -BuildCandidate
```

The default all-protocol feature set remains unchanged for Linux. On Windows,
NFS, HDFS, SFTP, remote rcp, tar and system-zstd produce an explicit compilation
error instead of bypassing their platform/authentication requirements. OCI can be
compiled separately; it is not included in the qualified Windows candidate recipe.

The NTFS adapter opens each component relative to a pinned directory handle with
reparse processing disabled, refuses traversal/device/stream names and junctions,
and enumerates by handle. Other filesystem identities and UNC local mounts are
not qualified. Files are staged exclusively, flushed and atomically renamed.
Foreground termination keeps the old destination and the catalog can resume.
This is not a transaction over the whole tree. Abrupt termination can leave an
abandoned stage file; ordinary aborted sinks remove their stage files. The attempted
NT delete-on-close toggle returned ERROR_NOT_SUPPORTED on this host, so it is not
part of the qualified adapter.

Sparse output and native hard links are supported. Times use NTFS 100 ns precision.
The adapter does not translate POSIX owners, modes, ACLs or xattrs to Windows
security descriptors: owner/xattr refusals and skipped verification checks remain
visible, and chmod/chown are refused. Catalog/cache creation uses a protected
owner-only DACL. Existing operator-selected ACLs are not rewritten.

Detached jobs, worker fleets, MCP, diagnostics and mount reports are explicitly
unsupported on Windows. They need separate process-tree lifecycle and platform
adapters; no numeric-PID killing, post-spawn cancellation race or no-op security
check is substituted. `-nocache` is refused. Delta and io_uring select the existing
whole-file/thread fallbacks, with capabilities and engine warnings visible.

SMB uses the Windows system cryptographic RNG; a failure refuses authentication.
No clock-derived nonce fallback exists. Large Windows sends are bounded in chunks
so the existing socket/absolute deadlines remain effective. Windows TLS uses an
explicit PEM bundle through `RCP_CA_BUNDLE`, `SSL_CERT_FILE` or `AWS_CA_BUNDLE`;
there is no Windows certificate-store integration or verification downgrade.

## Original audit and remaining semantics

The compiler audit used the default endpoint features; no endpoint was disabled to
make the result look successful. It found Unix-only imports in catalog, tree,
ports, anytree, diag, jobs, MCP, io_uring and protocol stand-in servers.
Linking additionally requires replacements for Linux filesystem syscalls,
`dlopen`/`dlsym`, POSIX signals/session creation and xattrs.

The original default-feature audit had 158 errors. The implemented subset addresses
filesystem primitives and local operations; the remaining full-port requirements are:

- Native qualifications for unsupported filesystem identities and UNC mounts,
  and explicit translations if POSIX or Windows ACL preservation is added.
- Pinned process identities and process-tree cancellation using Windows handles
  and job objects, retaining MCP output isolation and resumable catalogs. Do not
  substitute arbitrary numeric-PID termination for the Linux pidfd guarantee.
- Existing SHA-256 and AES x86 CPU dispatch already has software fallbacks for
  non-x86 targets; validate their vectors on native ARM64.
- An explicit Windows GSSAPI library/provider contract or a clear Unsupported
  refusal for Kerberos. Linux continues loading host GSSAPI dynamically. Windows
  SSPI is not ABI-compatible with that loader. Validate native zstd linking when
  the optional system-zstd feature is enabled.

Native Windows x86-64 qualification used Rust 1.87.0, MSVC 14.44 and Windows SDK
10.0.26100.0 on NTFS. Formatting and Clippy with warnings denied passed. The
optimized candidate subset passed 328 library tests, 2 CLI unit tests, 5
architecture tests and 10 Windows functional tests, including foreground
termination with catalog resume. Enabling rustls passed all 11 Windows functional
tests, including successful explicit-CA transfer and rejection of a missing CA
bundle. The recipe uses the same feature selection in
CI and creates candidates only after the selected tests pass.

## Reproducing checks

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features
cargo test --locked --test hexagon
cargo test --locked
rustup target add aarch64-unknown-linux-gnu
cargo check --locked --target aarch64-unknown-linux-gnu --all-targets
# On an x86-64 Debian host with gcc-aarch64-linux-gnu and libc6-dev-arm64-cross:
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --locked --target aarch64-unknown-linux-gnu
aarch64-linux-gnu-readelf -h target/aarch64-unknown-linux-gnu/debug/rcp
aarch64-linux-gnu-readelf -d target/aarch64-unknown-linux-gnu/debug/rcp
```

The all-target cross-check proves type checking. The separate cross-build completed
with Rust 1.98.1 and Debian 12's GCC cross-toolchain; ELF inspection reported ELF64
AArch64 and direct dependencies on `libgcc_s.so.1` and `libc.so.6`. Neither check
proves native runtime behavior or an older GLIBC baseline. Docker
ARM64 execution on the current x86-64 host failed with `Exec format error`; it
was not reported as native ARM64 validation.

Linux x86-64 validation passed formatting, all-target/all-feature clippy, 413 library
tests, 2 CLI unit tests, 5 architecture tests, and the chunker, description,
documentation, xxHash and doctest suites. The initial slim-container contract run
had 139 passes and two failures caused by missing `pgrep` and Python. With `procps`,
Python and the hash-pinned protocol peers installed, a normal container init for
child reaping and `RCP_REQUIRE_KDC=1`, all 141 contract tests passed, including real
Kerberos, signed SMB, SFTP, local copy/verify/sync/deletion and MCP child cleanup.
These results are native Linux x86-64 container tests, not ARM64 or Windows tests.

`.github/workflows/portability.yml` is manual and read-only. Its ARM64 job asserts
the native architecture, installs the same KDC and protocol peers as existing CI,
requires the KDC tests, tests default/TLS/minimal builds and produces a local
candidate tarball and checksum without uploading or releasing it. The default
and TLS suites include copy/verify, sync/deletion, MCP and job cancellation.
The Windows job runs the separate native NTFS qualification script and creates a
ZIP/checksum, retained as workflow evidence for seven days. It does not report the Unix
process/protocol contract suite as a Windows qualification.

GitHub provides `ubuntu-24.04-arm` as a standard runner for public repositories. The
project uses no self-hosted runners; do not add a paid runner or persistent host access
to complete validation. See the [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Candidate bundles

Run `scripts/test-windows.ps1 -BuildCandidate` on native Windows with Rust 1.87
and the existing MSVC toolchain, or dispatch `portability.yml` with
`scope=windows-local`. The candidate profile uses
`-C target-feature=+crt-static` throughout qualification and packaging, avoiding
a separately installed Visual C++ runtime prerequisite. PE import names are
recorded in the manifest, and packaging rejects dynamic MSVC runtime imports.
The Windows ZIP contains the executable, Apache-2.0 project license, dependency
notices, runtime limitations, this support matrix, source/feature/binary manifest
and checksums. It remains unsigned and requires the qualified Windows/NTFS profile.

The existing GNU x86-64 Container workflow now packages its exact ABI-gated and
native UBI9-smoked executable into a tarball with the same documentation,
manifest and checksums, plus its GLIBC gate evidence. Both bundles are retained
as workflow artifacts for seven days; neither is a release asset.
`python -m unittest discover -s scripts -p test_package_candidate.py` verifies
archive contents, deterministic serialization and refusal of incorrect target,
feature, source revision, license/notices and GLIBC evidence inputs.

A streaming experiment was rejected and closed unmerged; its measured regressions stay
out of the tree. Unsupported Windows protocols/process features, real
Windows SMB peer qualification and full native ARM64 protocol/KDC qualification
remain separate work.
