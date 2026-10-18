# Roadmap

What rcp intends to do, and not do, over the next year (through the end of 2027). Plans can
change; the roadmap says where the project is heading so users and contributors can judge
whether it fits them. The detailed record of what has been built, and the test that decided
each item was done, is the roadmap table in the
[design notes](docs/src/design-notes.md#roadmap).

## Intends to do

- **Keep `main` releasable and ship from it.** Releases follow Semantic Versioning, with
  signed archives, SBOMs and build provenance, as set out in
  [docs/src/releases.md](docs/src/releases.md).
- **Harden the endpoints already shipped** (local, NFS v3 and v4.0, S3, SMB 2 and 3, SFTP,
  `ssh://`/`rcp://`, WebDAV, HDFS, HTTPS sources, OCI registries, tar): fix defects found by
  the contract, interop and fuzz suites, and extend those suites where a defect shows a gap.
- **Items not yet placed** in the design notes, which are candidates for this period:
  several streams per large file (today the `-parallel` unit is a file); concurrent ranged
  GETs and multipart PUTs on S3; and resuming a partly written object rather than only a
  partly copied tree.
- **Platforms**: the Windows x86-64 and Linux ARM64 builds are source-only today
  ([CHANGELOG.md](CHANGELOG.md), [docs/src/portability.md](docs/src/portability.md)); widening
  what is tested natively on them comes before publishing release assets for them.
- **Keep the documentation current** with each release: the command-line reference is
  generated from the code and checked by `tests/docs.rs`.

## Does not intend to do

- **Telemetry.** rcp sends nothing about itself to anyone
  ([docs/src/telemetry.md](docs/src/telemetry.md)), and that will not change.
- **QUIC.** rcp's remote transport runs inside ssh, which is where the high-RTT answer
  (HPN-SSH) lives.
- **NFSv4.1 sessions**, for now: they bring no data-path gain over 4.0 for a copy tool. NFS
  4.2's server-side COPY is the one worth having and needs 4.1 first, so it stays a later item.
- **An MD5 digest.** `-md5` is accepted for compatibility only and does not compute MD5.
- **Credentials in URLs.** Endpoints refuse them by name; credentials come from options, the
  environment or the credential files the protocol's own tools use.
