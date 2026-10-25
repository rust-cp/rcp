# Releases and provenance

The `Release` workflow runs on a `vX.Y.Z` tag matching the crate version, including a
pre-release such as `v0.1.3-alpha.1`. It runs the contract tests, including mandatory
real-KDC Kerberos checks, then builds Linux x86-64 and Linux ARM64 GNU binaries with the
`rustls` feature for TLS support. Each binary dynamically links system GNU libc; Kerberos
also needs the host's GSSAPI library. There is no musl release archive.

The GitHub release contains both tarballs, one `SHA256SUMS`, and an SPDX bill of materials
for each archive (`rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.spdx.json` and
`rcp-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz.spdx.json`). Each archive includes the
binary, `LICENSE`, `README.md`, `RUNTIME.txt` with the required glibc symbol versions,
`THIRD_PARTY_LICENSES.txt` with dependency notices, and the same bill of materials as
`SBOM.spdx.json`. Download the assets from the
[releases page](https://github.com/rust-cp/rcp/releases), verify the checksums,
extract the archive that matches the machine, and check its runtime requirements before installing:

```sh
sha256sum --check SHA256SUMS
tar -xzf rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
cat rcp-vX.Y.Z-x86_64-unknown-linux-gnu/RUNTIME.txt
install -m 755 rcp-vX.Y.Z-x86_64-unknown-linux-gnu/rcp "$HOME/.local/bin/rcp"
```

Create `$HOME/.local/bin` first if needed and ensure it is on `PATH`.

`scripts/release.sh` (see the repository's `CONTRIBUTING.md`) prepares the version bump.
Running the workflow by hand on `main` with a version checks the release, creates the tag,
signs it, and publishes in one run.

When the repository secret `CARGO_REGISTRY_TOKEN` is set, that run also publishes the
crate to crates.io (`cargo publish --locked`). The package name is `rust-cp`. When the
secret is not set, the step says so and the rest of the release continues. The step runs
for a tag push and for the manual release run, which is what creates the tag.

## Signatures and provenance

Every release is signed keylessly through Sigstore from the release workflow's
GitHub identity:

- `rcp-vX.Y.Z-<target>.tar.gz.sigstore.json` is the cosign signature bundle for that
  archive. `<target>` is `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`.
- `rcp.intoto.jsonl` is the SLSA build provenance statement for the archive and its
  SBOM, and `rcp.sigstore.json` is the Sigstore bundle that signs it. The same
  attestation is stored with GitHub.

Use cosign v3 or later for every `cosign` command on this page. The release workflow signs
with cosign v3 and its newer Sigstore bundle format. cosign v2.6.1 still verifies the archive
bundle below, but cosign v2.x reports "no signatures found" for the images (see
[Container image and registry artifacts](#container-image-and-registry-artifacts)).

```sh
cosign verify-blob rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz \
  --bundle rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/rust-cp/rcp/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz --repo rust-cp/rcp
```

### Signed tags

Tags made by the release workflow (from 0.1.2 on) are signed keylessly with
[gitsign](https://github.com/sigstore/gitsign) under the workflow's identity on `main`. To
verify one, with `gitsign` installed:

```sh
git fetch --tags https://github.com/rust-cp/rcp
gitsign verify-tag vX.Y.Z \
  --certificate-identity https://github.com/rust-cp/rcp/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

GitHub's web interface shows these tags as unverified, because it does not check Sigstore
signatures; `gitsign verify-tag` is the check. `v0.1.1` predates this and is an unsigned
annotated tag; its release assets are signed as described above.

## Container image and registry artifacts

The workflow pushes the hardened runtime image (see `container/README.md`) to
`ghcr.io/rust-cp/rcp:X.Y.Z` as a multi-arch index (`linux/amd64` and `linux/arm64`).
Each platform image is also tagged `X.Y.Z-linux-amd64` or `X.Y.Z-linux-arm64`. The index
digest and both platform digests are signed with cosign. Each platform digest carries an
SPDX SBOM attestation, and those attestations are also attached to the index so verifying
the version tag still finds one. Each digest carries build provenance. Verifying them needs cosign v3
or later. The release workflow signs with cosign v3, which stores signatures and
attestations in the newer Sigstore bundle format, attached to the image as OCI referrers.
cosign v2.x looks only for the older signature tags and reports "no signatures found" for
every published image, 0.1.1 and 0.1.2 included.

```sh
cosign verify ghcr.io/rust-cp/rcp:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/rust-cp/rcp/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson ghcr.io/rust-cp/rcp:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/rust-cp/rcp/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/rust-cp/rcp:X.Y.Z --repo rust-cp/rcp
```

The bare x86-64 binary is pushed as an OCI artifact to `ghcr.io/rust-cp/rcp-binary:X.Y.Z`
and signed the same way. The same manifest is also tagged
`X.Y.Z-x86_64-unknown-linux-gnu`. The ARM64 binary is
`ghcr.io/rust-cp/rcp-binary:X.Y.Z-aarch64-unknown-linux-gnu`.
`scripts/publish.sh [REGISTRY/REPO] [TAG]` performs that push
with [oras](https://oras.land): one layer for the binary, one for `SHA256SUMS`, and
manifest annotations recording the repository, commit, dirty-tree flag, rustc version,
target, build time and binary SHA-256.

Both packages are public, so no login is needed to pull them.

```sh
oras pull ghcr.io/rust-cp/rcp-binary@sha256:<digest>
sha256sum --check SHA256SUMS
oras manifest fetch ghcr.io/rust-cp/rcp-binary@sha256:<digest> | jq .annotations
```
