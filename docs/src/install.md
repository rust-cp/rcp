# Install, upgrade and uninstall

## Quick start

1. Install rcp (either way below).
2. Copy a tree, then check it:

   ```sh
   rcp copy /data /backup
   rcp verify /data /backup
   ```

3. Run it again later: `rcp sync` moves only what changed, using the catalog the first copy
   recorded. `rcp help` lists every command and option, and the
   [command-line reference](reference/cli.md) has the same tables.

## From a release archive

Each release on the [releases page](https://github.com/rust-cp/rcp/releases) carries an
x86-64 GNU/Linux archive, `SHA256SUMS`, an SPDX SBOM, a Sigstore signature and build
provenance ([Releases](releases.md) shows how to verify them). Install into a prefix, using
the usual `PREFIX` and `DESTDIR` conventions:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
PREFIX=${PREFIX:-$HOME/.local}
install -D -m 0755 rcp-vX.Y.Z-x86_64-unknown-linux-gnu/rcp "${DESTDIR}${PREFIX}/bin/rcp"
```

Uninstall by removing that file: `rm "${DESTDIR}${PREFIX}/bin/rcp"`. rcp installs nothing
else. Its catalog (`~/.local/state/rcp/catalog` unless `-catalog`, `RCP_CATALOG` or
`XDG_STATE_HOME` says otherwise; see [The catalog](guide/catalog.md)) is yours to keep or delete.

## Container image

The signed runtime image is public at `ghcr.io/rust-cp/rcp`, tagged with the version. It
runs as UID/GID 10001 with `/state` as its home and catalog, and has no shell or package
manager (`container/README.md` describes it). Pull it, verify it, and run it with the data
mounted:

```sh
docker pull ghcr.io/rust-cp/rcp:X.Y.Z
cosign verify ghcr.io/rust-cp/rcp:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/rust-cp/rcp/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --mount type=volume,source=rcp-state,target=/state \
  --mount type=bind,source=/data,target=/data,readonly \
  --mount type=bind,source=/backup,target=/backup \
  ghcr.io/rust-cp/rcp:X.Y.Z copy -noown /data /backup
```

`podman` takes the same arguments. The bind mounts must be readable (and `/backup`
writable) by UID 10001, or add `--user "$(id -u):$(id -g)"`. Uninstall with
`docker rmi ghcr.io/rust-cp/rcp:X.Y.Z` and `docker volume rm rcp-state`.

The bare binary is also published as an OCI artifact at `ghcr.io/rust-cp/rcp-binary`, for
hosts that pull through a registry: `oras pull ghcr.io/rust-cp/rcp-binary:X.Y.Z` fetches
`rcp` and `SHA256SUMS` ([Releases](releases.md)).

## With Cargo

From source, with Cargo's own install convention (`--root`, or `CARGO_INSTALL_ROOT`, picks
the location; the default is `~/.cargo`):

```sh
cargo install --locked --git https://github.com/rust-cp/rcp --tag vX.Y.Z            # default build
cargo install --locked --git https://github.com/rust-cp/rcp --tag vX.Y.Z --features rustls
cargo uninstall rcp
```

**TLS needs `--features rustls`.** A source build without it has no TLS: every TLS
endpoint (`https://`, `davs://`, `rcps://`, and S3, OCI or WebHDFS over https) is refused
with an error naming the feature, and only their plaintext forms work. The release archive, the container image and the registry binary are all built with
`rustls`; a source build that talks to anything over a network you do not control should be
too. `rcp version` lists what a build supports.

The release profile strips symbols. For a build that keeps debugging information, Cargo's
profile variables apply: `CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=true`.
`RUSTFLAGS` and Cargo's other standard variables are honored; the build adds no flags of its
own beyond `Cargo.toml`'s release profile.

## Upgrade

Install the new version over the old one, by either method above. Only the latest release
is supported (`SECURITY.md`). Read the release's section of `CHANGELOG.md` first: changes a
user must act on are listed there, and the project follows Semantic Versioning, so before
1.0 a minor version can carry a breaking change and says so in its notes.

## Development environment

Everything needed to change rcp and run its tests, on Debian or Ubuntu:

```sh
git clone https://github.com/rust-cp/rcp && cd rcp
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal -c clippy,rustfmt
sudo apt-get install -y --no-install-recommends zstd krb5-kdc krb5-admin-server krb5-user libgssapi-krb5-2
python3 -m pip install --user --require-hashes -r tests/support/requirements.txt
cargo test && cargo test --features rustls
```

These are the same steps CI runs (`.github/workflows/ci.yml`). `CONTRIBUTING.md` lists the
checks to run before pushing.
