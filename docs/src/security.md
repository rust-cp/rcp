# Security requirements and assurance case

This chapter states what users can and cannot expect from rcp in terms of security, and
argues why those expectations are met. Reporting a vulnerability, and how reports are
handled, is in the repository's `SECURITY.md`.

## What rcp is

A command-line program that copies, verifies, resumes, syncs and scans file trees between a
local filesystem and network storage (NFS, S3, SMB, SFTP, `ssh://` and `rcp://` peers,
WebDAV, HDFS, HTTPS sources, OCI registries) and tar archives. It runs with the privileges
of the user who starts it, keeps a catalog of what it transferred, and sends no telemetry
([Telemetry](telemetry.md)). `rcp serve` exposes a directory to another rcp, and `rcp mcp`
lets an agent drive rcp within operator-set limits ([Driving rcp from an agent](guide/agents.md)).

## Security requirements

What you can expect:

1. **Integrity of transferred data.** A copy hashes every file (SHA-256 by default, BLAKE3
   on request) and records it in the catalog; `verify` compares content, not just sizes and
   times, and a run that cannot confirm data arrived intact does not report success.
2. **Writes stay where they were sent.** rcp writes, removes or changes only what is under
   the destination it was given. Local opens that must not follow a symbolic link use
   `O_NOFOLLOW`/`O_DIRECTORY`, and names that would leave a tree (`.`, `..`, separators,
   absolute paths, device names on Windows) are refused.
3. **Credentials go only to the endpoint they belong to.** Credentials are never taken from
   a URL (an endpoint carrying one is refused), are redacted from logged and described
   command lines, and are relayed to helper processes through their environment, not their
   command line.
4. **Verified TLS by default.** With TLS (`--features rustls`), certificates are verified
   against the system bundle or the bundle the environment names, with TLS 1.2 or 1.3 only.
   Turning verification off takes an explicit `-*.noverify` option and prints a warning.
5. **Bounded behavior against hostile peers and inputs.** A server, peer or file cannot make
   rcp allocate or loop without bound: lengths and counts from the wire are checked before
   allocation, and parsers refuse malformed input by name.
6. **A network listener is not exposed by accident.** `rcp serve -listen` refuses to start
   without `-allow` roots, serves only paths inside them, and binds only loopback unless mutual
   TLS (`-tls.clientca`) is configured.
7. **An agent stays inside its rails.** `rcp mcp` will not start without `-allow`, and
   `-readonly` and plan confirmation limit what a caller can do.
8. **No telemetry.** rcp opens sockets only to the hosts listed in [Telemetry](telemetry.md).

What you cannot expect:

- Confidentiality or integrity **on the wire** for protocols that have none: plain NFS
  (`-nfs.sec sys`), SMB without signing, `http://`, `rcp://` without TLS, and S3, WebDAV or OCI
  over `http`. rcp uses these only when you name them; use `krb5i`/`krb5p`, `-smb.sign`,
  `https`, `davs`, `rcps` or ssh-based transports where the network is not trusted.
- Protection from a **malicious server you chose to trust**: it can serve wrong data, which
  `verify` against a trusted copy detects but cannot prevent.
- Protection from **other local users with your privileges**, or from root on the host.
- Protection of credentials you pass as **command-line options** from other local users who
  can read the process table. Use the environment or credential files instead.
- FIPS validation. rcp is not a FIPS-validated module.

## Threat model

Assets: the data being moved and the destination's existing contents; credentials for the
endpoints; the catalog; the host account rcp runs as.

Adversaries considered:

- A **network attacker** between rcp and an endpoint (reads or alters traffic).
- A **malicious or compromised server or peer** (NFS, S3, SMB, WebDAV, HDFS, OCI, HTTP, an
  `rcp serve`), which can send malformed or oversized responses, names that try to escape
  the tree, redirects to other hosts, or wrong data.
- A **malicious file or archive** as a source (a tar, a compressed stream, JSON).
- An **agent or automation** driving `rcp mcp` that tries to act outside its rails.
- A **remote client** of `rcp serve -listen`.

Out of scope: an attacker who already controls the account rcp runs as, the operating
system, or the build and release infrastructure beyond what signed releases and provenance
let users check.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Where it is enforced |
| --- | --- | --- | --- |
| Command line and environment | the operator | (none: the operator is trusted) | option parsing in `src/main.rs`; values are validated and an unknown option is refused |
| Network endpoints | rcp | every server and peer response | each adapter's parser (`src/nfs/`, `src/s3/`, `src/smb/`, `src/dav/`, `src/hdfs/`, `src/oci/`, `src/https/`, `src/remote/`) |
| Archives and streams | rcp | tar members, zstd/deflate/LZ4 frames, JSON | `src/tar/`, `src/zstd/`, `src/deflate.rs`, `src/lz4.rs`, `src/json.rs` (all fuzzed) |
| `rcp serve` | the served `-allow` roots | the connecting client | `src/remote/server.rs`; loopback-only without mutual TLS |
| `rcp mcp` | the operator's rails (`-allow`, `-readonly`) | the agent's requests | `src/mcp.rs`, `src/describe.rs` capability classes |
| Local filesystem | the destination tree | symbolic links and names inside it | `src/tree.rs`, `src/platform.rs`, `src/windows.rs` |

## Secure design principles applied

- **Fail-safe defaults.** TLS verifies by default; a listener binds loopback only; `rcp mcp`
  refuses to start without `-allow`; credentials in URLs are refused; an endpoint left out of
  a build is refused by name rather than guessed at.
- **Complete mediation.** Every path a client or agent names is checked against the allowed
  roots on each request, not once per session (`src/remote/server.rs`, `src/mcp.rs`).
- **Least privilege.** rcp needs no elevated privileges and asks for none; the catalog is
  created private to the user (mode 0600 files, private directories, `src/catalog.rs`); the container image has no shell or package manager
  (`container/README.md`).
- **Economy of mechanism.** One `Tree` interface for every endpoint and a core that does no
  I/O of its own ([Architecture](architecture.md)); `tests/hexagon.rs` fails if the core
  reaches an adapter directly. `unsafe` is confined to the system calls a copy needs.
- **Separation of privilege and open design.** Integrity is checked by content hash
  end to end, independently of the transport; all algorithms and protocols are public.
- **Least common mechanism.** Credentials are scoped to their endpoint kind and are not
  shared across endpoints or relayed on command lines.
- **Psychological acceptability.** Refusals name what was refused and why; unsafe options
  (`-*.noverify`, `-*.insecure`) must be named explicitly, and skipping certificate
  verification prints a warning.

## Common implementation weaknesses countered

| Weakness (CWE) | Countermeasure | Evidence |
| --- | --- | --- |
| Memory-safety errors (CWE-119, CWE-787, CWE-416) | Rust, with `unsafe` limited to system calls | [Architecture](architecture.md); CodeQL and Clippy in CI |
| Path traversal (CWE-22) and link following (CWE-59) | names with `.`, `..` or separators refused; `O_NOFOLLOW` protected opens | `src/lib.rs`, `src/platform.rs` tests, `src/windows.rs` (`traversal_stream_and_device_names_are_refused`), `src/https/index.rs` (`an_rcp_index_refuses_paths_that_escape_the_tree`) |
| Uncontrolled resource consumption (CWE-400, CWE-789) | lengths checked before allocation; caps on signatures, nesting and claimed sizes | `src/json.rs` (`excessive_nesting_is_rejected_without_overflowing_the_stack`), LZ4 size checks, fuzz targets in `fuzz/` |
| Improper input validation (CWE-20) | allowlist parsing of options, URLs and wire formats; malformed input refused by name | contract tests (`tests/contract.rs`), fuzzing (`.github/workflows/fuzz.yml`) |
| Improper certificate validation (CWE-295) | rustls with verification on by default | `src/net/tls.rs` |
| Cleartext credentials in logs or arguments (CWE-532, CWE-214) | credential redaction; environment relay to children | `src/describe.rs` (`redact_credentials`), `src/mcp.rs` |
| Exposure through a network listener (CWE-1327) | loopback-only unless mutual TLS; `-allow` roots required | `src/remote/server.rs`, [Remote hosts](endpoints/remote.md) |
| Integer overflow (CWE-190) | wire lengths bounds-checked before use; overflow is a panic, not wraparound, in test builds and in the fuzz targets (`overflow-checks = true` in `fuzz/Cargo.toml`) | unit tests, fuzzing |
| Vulnerable dependencies (CWE-1395) | small reviewed dependency set; `cargo deny` advisories, `cargo vet`, Dependabot alerts | `deny.toml`, `supply-chain/`, [External dependencies](dependencies.md) |
| Tampered releases (CWE-494) | Sigstore-signed archives and image, SLSA provenance, reproducible build check | [Releases](releases.md), `.github/workflows/assurance.yml` |

## Evidence that keeps the argument true

Every pull request runs formatting, Clippy with warnings denied, the test suite with real
peers, the interop suite against real servers, fuzzing, CodeQL, `cargo deny`, `cargo vet`,
zizmor, actionlint and gitleaks. The assurance workflow measures line coverage (at least 80%)
and checks that the release build reproduces bit for bit. A change that weakens one of the
requirements above is a vulnerability under `SECURITY.md`'s scope.
