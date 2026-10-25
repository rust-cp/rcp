# Minimal Linux runtime image

This image supports Linux x86-64 and Linux ARM64. A release tag is a multi-arch index of
those two platforms. Its scratch final stage contains the GNU libc
loader and required dynamic libraries, CA roots, GSSAPI libraries, an SSH client,
and license notices. It contains no shell, compiler, Python, or package manager.
It is neither a static executable nor a FIPS-validated distribution.

The container and future release workflows build with the digest-pinned official
Rust 1.90.0/Bullseye image (glibc 2.31), then reject binaries with versioned
GNU libc requirements above 2.34. They separately test the exact binary on a
digest-pinned UBI9 base, including dynamic GSSAPI loading. The scratch runtime
still uses Ubuntu's newer libc, which can run the older-baseline executable.
The UBI9 image in `compatibility-test.Dockerfile` is only a test environment.
Signed distribution repositories supply its test tools; their installed package
inventory and final image identity must accompany local evidence.

The v0.1.0 binary required GLIBC_2.39 and failed to start on UBI9/RHEL9's
glibc 2.34; releases from 0.1.1 on are built against the 2.34 baseline. A 2.28 target would
require a separate older build sysroot and broader runtime testing; it is not
claimed here. UBI9 tests do not substitute for testing a full Rocky/RHEL9 host,
nor do GSSAPI loading tests prove real Kerberos authentication.

Build from an explicitly identified binary and its third-party notices:

```sh
python3 scripts/build-container.py --binary /path/to/rcp \
  --notices /path/to/THIRD_PARTY_LICENSES.txt --image localhost/rcp:test \
  --version 0.1.0 --revision SOURCE_COMMIT
```

The builder never pushes a registry tag. The Ubuntu base is digest pinned and
Renovate proposes digest updates. `packages.lock` names the signed Ubuntu archive
packages, including transitive dependencies, without versions: the archive drops
superseded versions, so an exact pin stops building as soon as a security update
lands. Each build installs the current signed package, records the installed
versions in `/usr/share/rcp/runtime-packages.json`, and is smoke tested and scanned.
The UBI 9 compatibility locks (`compatibility-packages.lock` and
`compatibility-arm64-packages.lock`) follow the same rule for the same reason.

Run with explicit writable state and data mounts:

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount type=volume,source=rcp-state,target=/state \
  --mount type=bind,source=/data,target=/data localhost/rcp:test version
```

The image runs as UID/GID 10001. Bind mounts must permit that user to access them;
rootless engines additionally apply their user namespace mapping. Arbitrary owner
preservation requires privileges that this configuration deliberately lacks: use
appropriate mappings or `-noown`. An unavailable io_uring engine falls back to
threads; do not weaken seccomp to silence that diagnostic.

Mount credential files, ticket caches, SSH known_hosts, and realm configuration
with appropriate ownership and read-only permissions where possible. GSSAPI
loading does not prove authentication against a real realm. SSH helpers requiring
a shell, hardware-token middleware, and custom ProxyCommand programs are not
included. Detached jobs need a persistent foreground process or supervisor;
a one-shot container exits when its entrypoint exits.

Compile the test-only posture probe and run the smoke suite:

```sh
cc -Wall -Wextra -Werror container/hardening-probe.c -o /tmp/rcp-probe
python3 scripts/container-smoke.py --image localhost/rcp:test \
  --probe /tmp/rcp-probe --output /tmp/rcp-smoke-results
```

The suite checks actual UID, capability masks, no_new_privileges and seccomp,
read-only root filesystem, GSSAPI loading, SSH startup, absence of a shell,
copy and changed sync with removal, content/mode/mtime verification, MCP response
integrity, and deletion confirmation. It uses only uniquely named disposable
fixtures and retains command evidence. It does not test remote authentication,
every protocol, crash recovery, or all kernel configurations.

Export an OCI archive and produce Syft JSON plus SPDX JSON, then scan the Syft
SBOM with Grype. Retain the full vulnerability report and database identity,
including unfixed findings. A package SBOM alone is not complete coverage of
statically linked Rust dependencies; retain Cargo.lock and the source revision
alongside it. Image digests, SBOMs, and scan reports do not constitute signatures
or compliance certification. No registry publication is configured here.
