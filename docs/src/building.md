# Building

See [platform validation](portability.md) for Linux ARM64 work and the Windows
portability blockers. A successful cross-check is not native runtime validation.

```sh
cargo build --release                    # the default build; see below for --offline
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release   # static binary
cargo test
cargo build --release --features rustls  # https:// S3 endpoints; adds rustls and ring
```

All commands run from the repository root. The default build compiles this crate, the
audited open-source cryptography crates it uses -- RustCrypto `sha2`, `hmac`, `md4`,
`md-5`, `aes` and `cmac`, and the official `blake3` -- and the small support crates those
need (`digest`, `cipher`, `hybrid-array`, `typenum`, `cpufeatures` and the like). CI holds
the default build to exactly that list with `cargo tree`, so a new dependency is a reviewed
change to the allow-list rather than an accident. `blake3` compiles its assembly and C
SIMD kernels with the `cc` crate at build time, so a C compiler must be on the host, as it
already is for the `rustls` build's `ring`.

An air-gapped host needs those crates before `--offline` works, and cargo resolves optional
dependencies too, so the lockfile's TLS entries need the registry index even when the
`rustls` feature is off. Either copy the registry from a connected host (run
`cargo fetch --locked` there and carry `~/.cargo/registry` across), or use a
`cargo vendor` directory. Then `cargo build --release --offline --locked` works as above.
The `rustls` build adds rustls and ring, the one thing the standard library does not have,
and is the one to ship where buckets live behind HTTPS.

## Hardware acceleration

`sha2`, `aes` and `blake3` pick their CPU paths at run time: SHA-NI and AES-NI on x86-64,
the ARMv8 SHA-2 and AES instructions on ARM64, and SSE4.1, AVX2 or AVX-512 (NEON on ARM64)
for BLAKE3, with portable code where the CPU has none of them. `rcp version` reports what
SHA-256 found. `RCP_NO_SHA_NI` and `RCP_NO_AES_NI`, which used to force rcp's own portable
code, are still accepted and have no effect: the crates' selection cannot be overridden at
run time.

## Choosing endpoints

Each endpoint is a Cargo feature, and all of them are on by default: `nfs`, `s3`, `smb`,
`sftp`, `remote` (`ssh://`, `rcp://` and `rcp serve`), `dav`, `hdfs`, `https`, `oci` and
`tar`. None adds a dependency, so turning one off only makes the binary smaller and its
attack surface narrower. A build names the ones it keeps:

```sh
cargo build --release --no-default-features --features nfs,s3
```

Every scheme still parses in such a build, so a URL for an endpoint that was left out is
refused by name rather than read as a local path:

```text
$ rcp copy /data smb://nas/share/data
ERROR: smb://nas/share/data: this rcp was built without the `smb` feature; rebuild with `--features smb`
```

`rcp serve` needs `remote` and `rcp show HOST` needs `nfs`. Options that only configure a
left-out endpoint, such as `-smb.sign` without `smb`, are accepted and have nothing to
configure. The contract suite in `tests/contract.rs` covers the default build; CI's
`features` job checks that the library and binary build with each feature alone, with none,
and with every pair.

The release build targets x86-64 GNU/Linux and dynamically links the host's GNU libc.
Its archive includes `RUNTIME.txt`, which records the build environment and required glibc
symbol versions, and `THIRD_PARTY_LICENSES.txt` for the Rust dependencies. Check those
requirements on the destination host; compatibility with older distributions is not
implied by the target name. Kerberos needs the system GSSAPI library and a valid ticket.
Safe job cancellation uses pidfds on Linux x86-64 and AArch64 and requires kernel support
for `pidfd_open` (Linux 5.3 or later); an unavailable or blocked syscall is reported as a
refusal.

The `+crt-static` commands above and below are custom builds for local interoperability
testing, not the release configuration. They need the target's static C runtime at build
time and cannot load the system GSSAPI library for Kerberos. Distributing a custom static
GNU build also requires handling its C runtime's license and source obligations; the Rust
dependency notice bundle does not cover that runtime.

## Against real servers

The contract suite talks to in-process stand-ins. `scripts/interop.sh` puts each network
endpoint in front of the server people actually run, one container each: VersityGW (S3),
the CNCF distribution registry (OCI), Apache httpd with `mod_autoindex` (HTTPS sources) and
`mod_dav` (WebDAV), OpenSSH (SFTP, and `ssh://` with this build's `rcp serve` on the far
side), Samba (SMB, plain and signed), NFS-Ganesha (NFSv3 and v4.0) and Apache Hadoop
(WebHDFS). For each it copies a fixture up, verifies it, copies it back, and diffs both the
round trip and the server's own copy against the fixture, so a defect that is symmetric in
rcp still shows up. The fixture is small and hostile: an empty file, sizes one byte either
side of the read and write boundaries, a 17 MB file, a 200-byte name, spaces, `%`, `#`,
`+` and non-ASCII names, and an empty directory. Needs Docker, and a static build for
`ssh://`:

```sh
RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --release --features rustls --target x86_64-unknown-linux-gnu
RCP=target/x86_64-unknown-linux-gnu/release/rcp scripts/interop.sh          # all of them
RCP=target/x86_64-unknown-linux-gnu/release/rcp scripts/interop.sh smb nfs  # some
```

`KEEP=1` leaves the containers and the work directory for a look afterwards. The `Interop`
workflow runs one job per endpoint on every pull request and weekly.

### Across hosts, on k3s

`-nodes`, `-via` and `rcps://` need more than one host, so `interop/k3s/` stands them up
as pods on a k3s cluster with an Ansible playbook, then `interop/k3s/tests.sh` runs four
scenarios from client pods:

- **fleet**: an S3-to-S3 copy spread with `-nodes` over three worker pods. Each worker
  must have run at least one batch, and the copy must verify and read back identical.
- **relay**: a copy, verify and read-back to `ssh://hop-b` with `-via ssh://hop-a`. A
  NetworkPolicy admits only hop pods to hop-b, and the client's own dial to hop-b is the
  control: it must fail, so a pass went through the hop.
- **mtls**: the same round trip over `rcps://` to a serve that requires a client
  certificate from the suite's CA. No certificate, a certificate from another CA, and a
  serve the client does not trust must each be refused, and the serve must still answer
  afterwards.
- **krb**: NFS-Ganesha exporting with RPCSEC_GSS only, against an MIT KDC in the same pod.
  A copy, verify and read-back under `krb5`, `krb5i` and `krb5p`, and `krb5p` over NFSv4.0,
  each compared against the server's disk. AUTH_SYS and a client without a ticket are the
  controls, and must be refused. The client runs a dynamically linked rcp, the only kind
  that can load the system GSSAPI library.

```sh
RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --release --features rustls --target x86_64-unknown-linux-gnu
cargo build --release --features rustls     # the dynamic build the Kerberos client runs
ansible-playbook interop/k3s/playbook.yml   # uses the cluster on $KUBECONFIG, else starts k3s
interop/k3s/tests.sh                        # or: tests.sh relay krb
ansible-playbook interop/k3s/playbook.yml -e state=absent   # delete the namespace
```

A cluster already answering on the kubeconfig is used as it is. Otherwise the playbook runs
`$K3S_BOOTSTRAP` if set, or downloads the pinned k3s release and checks it against the
release's own checksums. The fleet, relay and mTLS pods run the static binary from a
`hostPath` mount; the Kerberos client uses the separate dynamically linked build so it can
load GSSAPI. A rebuild needs a re-run of the playbook. The `Interop` workflow runs this as its
`k3s` job.
