# rcp

rcp copies, verifies, resumes, and syncs trees. One binary talks to local disks and to
network storage, records every transfer in a catalog, and sends no telemetry.

A copy is content-defined: each file is hashed (SHA-256, using SHA-NI when the CPU has
it), the catalog keeps that record, and a later `sync` or `resume` moves only what the
record says is still missing. The default local engine uses `io_uring` on Linux. The
default build compiles no third-party crate.

## Endpoints

Every endpoint can be a source or a destination, except HTTP and HTTPS, which are
read-only.

| Endpoint | Written as |
| --- | --- |
| Local or mounted path | `/path`, `file:///path` |
| NFS v3 and v4.0, no mount | `host:/export[:/subdir]`, `nfs://host/export` |
| S3 | `s3://bucket/prefix` |
| SMB 2 and 3 | `smb://[user@]host/share/path` |
| SFTP | `sftp://[user@]host/path` |
| Another rcp, over ssh or directly | `ssh://host/path`, `rcp://host:port/path`, `rcps://host:port/path` |
| WebDAV | `dav://host/path`, `davs://host/path` |
| HDFS, via WebHDFS | `hdfs://namenode:port/path` |
| HTTP and HTTPS sources | `http://host/path`, `https://host/path` |
| OCI registries | `oci://registry/repository:tag` |
| tar archives, including gzip, zstd, and sparse members | `tar:///path/archive.tar.gz` |

TLS (`https://`, `davs://`, `rcps://`, and TLS S3) needs a build with `--features rustls`.

## Install

Download a release from the
[releases page](https://github.com/rust-cp/rcp/releases) and check it against the
published `SHA256SUMS`:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf rcp-v*-x86_64-unknown-linux-gnu.tar.gz
```

The release also publishes `*.tar.gz.spdx.json`, an SPDX bill of materials for the
runtime Cargo graph of that binary. The same document is packed inside the archive as
`SBOM.spdx.json`. Each archive is signed with Sigstore (`*.tar.gz.sigstore.json`), and the
release carries SLSA build provenance (`rcp.intoto.jsonl` and its Sigstore bundle
`rcp.sigstore.json`). The [releases guide](docs/src/releases.md) shows how to verify them.

The release binary runs on x86-64 GNU/Linux with glibc 2.34 or newer, which includes
RHEL 9. Each release is checked against that limit at build time and run on UBI 9
before it is published. The archive's `RUNTIME.txt` lists its required glibc symbol versions. Kerberos
also needs a system GSSAPI library and realm configuration. `THIRD_PARTY_LICENSES.txt`
includes the licenses of the bundled Rust dependencies.

### From source

Rust 1.87 or newer:

```sh
cargo build --release                    # compiles no third-party crate
cargo build --release --features rustls  # adds TLS
```

| Feature | Default | Adds |
| --- | --- | --- |
| `nfs`, `s3`, `smb`, `sftp`, `remote`, `dav`, `hdfs`, `https`, `oci`, `tar` | yes | One endpoint each. `remote` is `ssh://`, `rcp://`, and `rcp serve`. None pulls in a crate. |
| `rustls` | no | TLS through rustls. The only feature that pulls in crates. |
| `system-zstd` | no | The `ssh://` stream's zstd through the system libzstd instead of the built-in codec. Implies `remote`. |

CI enforces that the default build compiles no third-party crate. An offline host still
needs cached registry metadata for Cargo to resolve optional TLS dependencies; see the
[offline build instructions](docs/src/building.md). To leave endpoints out, name the ones
to keep:

```sh
cargo build --release --no-default-features --features nfs,s3
```

A URL for an endpoint that was left out is refused by name, with the feature that adds it.

## Examples

```sh
rcp copy /data /backup
rcp verify /data /backup
rcp copy -newid nightly /data nfs01.example:/export/data
rcp sync -id nightly
rcp copy /data s3://bucket/data
rcp copy /data smb://files.example/share/data
rcp copy /data sftp://files.example/data
rcp copy /data ssh://files.example/data
rcp copy /data dav://files.example/data
rcp copy https://files.example/pub/ /data
rcp copy oci://registry.example/app:1 /tmp/app
rcp copy /data tar:///tmp/data.tar.zst
rcp scan /data
```

`rcp help` lists every command and option. The
[command-line reference](docs/src/reference/cli.md) has the same tables. For automation,
`-json` emits a stable event stream, `rcp describe` publishes the command-line contract,
and `rcp mcp` serves rcp as an MCP tool, with `-allow`, `-readonly`, and plan confirmation
as safety rails.

## Benchmark

Local copies on one KVM guest, measured 2026-10-14. Ten runs each, seed 7, checksums
checked after every trial (0 failures in 480 trials). The guest is Ubuntu 24.04.5,
kernel 6.12.94+, 4 vCPU, 16 GB, ext4. Tools: rcp 0.1.1 default (SHA-256 catalog),
rsync 3.2.7, rclone 1.60.1, GNU cp 9.4. Cold runs drop the guest page cache before
each trial. Warm runs only `sync`. Dropping the guest cache does not drop the
hypervisor's cache.

Median seconds. Lower is faster. **Bold** is the fastest on that row.

### Cold

| workload | rcp | rsync | rclone | cp |
| --- | ---: | ---: | ---: | ---: |
| small (8,000 × 4 KiB) | **0.190** | 0.276 | 0.429 | 0.379 |
| large (4 × 64 MiB) | 0.280 | 0.348 | 0.341 | **0.171** |
| mixed | **0.109** | 0.151 | 0.188 | 0.118 |
| delta | **0.073** | 0.098 | 0.118 |  |
| resume | 0.237 | **0.218** | 0.225 |  |

### Warm

| workload | rcp | rsync | rclone | cp |
| --- | ---: | ---: | ---: | ---: |
| small | **0.172** | 0.237 | 0.297 | 0.188 |
| large | 0.238 | 0.301 | 0.281 | **0.137** |
| mixed | 0.091 | 0.125 | 0.136 | **0.061** |
| delta | **0.052** | 0.074 | 0.066 |  |
| resume | **0.140** | 0.191 | 0.165 |  |

cp wins large files, about 1.6× cold and 1.7× warm, and it wins warm mixed. rcp
loses cold resume to rsync by about 8%. On the other rows rcp is faster than both
rsync and rclone. Turning rcp's hash off does not hand large files to rcp: the
no-hash build's cold large median was 0.252 s, still behind cp at 0.171 s. cp is
copying bytes; rcp is also building the catalog it later resumes from.

Delta and resume are not a `cp` workload, so those cells are empty. S3, SFTP, and
NFS were not part of this run. The harness and the full table, including the
diagnostic builds, are in [`bench/RESULTS.md`](bench/RESULTS.md).

## Documentation

The user guide, one chapter per endpoint, the command-line reference, and the design
notes are in [`docs/`](docs/src/SUMMARY.md). To read them as a book, run
`mdbook serve docs`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md).
Changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
