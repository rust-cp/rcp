# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Tags made by the manual `Release` run are signed keylessly with gitsign under the
  release workflow's identity on `main`, starting with this release. `docs/src/releases.md`
  shows how to verify one with `gitsign verify-tag`.

### Changed

- Cryptography comes from widely used open-source crates instead of rcp's own code: SHA-256
  and HMAC from RustCrypto `sha2` and `hmac`, NTLM's MD4 and MD5 from `md4` and `md-5`,
  SMB signing from `aes` and `cmac`, and BLAKE3 from the official `blake3` crate. The
  default build now compiles those crates and their support crates, and nothing else from
  crates.io. Digests and signatures are unchanged; BLAKE3 is about twice as fast per core.

### Deprecated

- `RCP_NO_SHA_NI` and `RCP_NO_AES_NI` are accepted and have no effect. The crates choose
  their hardware paths at run time and cannot be overridden.

### Fixed

- Skipping certificate verification no longer prints `WARN: -s3.noverify` for every
  endpoint. The warning, and the missing-CA-bundle hint, name the option that turned
  verification off: `-dav.noverify`, `-http.noverify`, `-oci.noverify` or `-s3.noverify`
  (HDFS follows `-s3.noverify`).

## [0.1.1] - 2026-10-17

### Changed

- The project lives at <https://github.com/rust-cp/rcp>; documentation is at
  <https://rust-cp.github.io/rcp/>.
- Container package lists name packages without versions, so a superseded
  distribution package no longer breaks the build. The base images stay digest pinned.

### Fixed

- The release binary now starts on RHEL 9 and other GNU libc 2.34 systems. v0.1.0's
  binary was built on Ubuntu 24.04 and required glibc 2.39. Releases are now built in a
  digest-pinned Debian Bullseye builder, the build fails if the binary needs a GNU libc
  newer than 2.34, and the binary is run on UBI 9 before it is published.
- On Linux ARM64, protected opens use that architecture's `O_NOFOLLOW` and `O_DIRECTORY`
  values, so they refuse symbolic links as they do on x86-64.
- `rcp version` no longer claims "no runtime dependencies". On Windows it lists the
  transports that build supports.

### Added

- A release archive carries `SBOM.spdx.json`, and the GitHub release publishes
  that SPDX document next to the archive and checksums.
- Releases are signed: each archive gets a keyless Sigstore bundle
  (`*.tar.gz.sigstore.json`), and the release carries SLSA build provenance
  (`rcp.intoto.jsonl`, `rcp.sigstore.json`).
- Releases publish the hardened container image to `ghcr.io/rust-cp/rcp`, signed with
  cosign, with an SPDX SBOM attestation and build provenance on the image digest.
- Windows x86-64 (MSVC): local NTFS paths, with private-file ACLs and directory
  durability, and the `s3://`, `smb://`, `dav://` and `https://` endpoints. Build from
  source; there is no Windows release asset yet, and SMB has not been tested against a
  real Windows server.
- Linux ARM64: ordinary operations tested on native ARM64 hardware. Build from source;
  NFS, Kerberos and OCI have not been run natively on ARM64.
- A hardened container image definition under `container/`, built in CI with an SBOM and
  a vulnerability gate.
- Registry publishing records the build target, commit, rustc version and source
  repository in the manifest annotations.

## [0.1.0] - 2026-09-30

First release.

### Fixed

- MCP replies preserve escaped request IDs and trim large Unicode event streams safely.
- JSON rejects malformed numbers, unescaped string controls, and excessive nesting.
- Background jobs use unique IDs, preserve existing logs, and recognize reused process IDs.
- A background job whose record cannot be written stops its new process group and reaps
  its child before returning the filesystem error.
- ZIP logs identify UTF-8 filenames for standard readers.
- MCP endpoint fields cannot inject command-line options.
- HTTP indexes reject parent traversal; WebHDFS authentication cookies stay on their issuing origin.
- Linux job cancellation pins process identity before signaling; older kernels refuse unsafe cancellation.
- Release tests require a real Kerberos KDC before creating a release tag.
- Release archives include dependency license notices and system glibc requirements.

### Added

- `copy`, `sync`, `verify`, `scan`, `delete`, `show`, `resume` and the `diag` family over local
  and mounted paths.
- Endpoints: `nfs://` (v3 and v4.0, with NFSACL and v4 ACLs), `s3://`, `smb://`, `sftp://`,
  `ssh://` and `rcp://` (native remote transport with delta sync and stream compression),
  `dav://`/`davs://`, `hdfs://`, `https://` sources, `oci://` registries and `tar://` archives
  (gzip, zstd, sparse members).
- One Cargo feature per endpoint, all on by default. A build that leaves one out refuses its
  URLs by name.
- Digests: SHA-256, BLAKE3, xxh3/xxh128, with a digest cache in the catalog.
- `-parallel auto` tuning, `-bwlimit`, resumable jobs and a plan-then-confirm safety model.
- Agent interface: `-json` event stream, `rcp describe`, and `rcp mcp` over stdio.

