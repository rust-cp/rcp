# Releases and provenance

The `Release` workflow runs on a `vX.Y.Z` tag matching the crate version. It runs the
contract tests, including mandatory real-KDC Kerberos checks, then builds an x86-64
GNU/Linux binary with the `rustls` feature for TLS support. The binary dynamically links
system GNU libc; Kerberos also needs the host's GSSAPI library.

The GitHub release contains the tarball, `SHA256SUMS`, and an SPDX bill of materials
named `rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.spdx.json`. The archive includes the
binary, `LICENSE`, `README.md`, `RUNTIME.txt` with the required glibc symbol versions,
`THIRD_PARTY_LICENSES.txt` with dependency notices, and the same bill of materials as
`SBOM.spdx.json`. Download the assets from the
[releases page](https://github.com/rust-cp/rcp/releases), verify the checksums,
extract the archive, and check its runtime requirements before installing:

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

## Signatures and provenance

Every release is signed keylessly through Sigstore from the release workflow's
GitHub identity:

- `rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sigstore.json` is the cosign signature
  bundle for the archive.
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
`ghcr.io/rust-cp/rcp:X.Y.Z`. The image digest is signed with cosign and carries an
SPDX SBOM attestation and a build provenance attestation. Verifying them needs cosign v3
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

The bare binary is also pushed as an OCI artifact to `ghcr.io/rust-cp/rcp-binary:X.Y.Z`
and signed the same way. `scripts/publish.sh [REGISTRY/REPO] [TAG]` performs that push
with [oras](https://oras.land): one layer for the binary, one for `SHA256SUMS`, and
manifest annotations recording the repository, commit, dirty-tree flag, rustc version,
target, build time and binary SHA-256.

Both packages are public, so no login is needed to pull them.

```sh
oras pull ghcr.io/rust-cp/rcp-binary@sha256:<digest>
sha256sum --check SHA256SUMS
oras manifest fetch ghcr.io/rust-cp/rcp-binary@sha256:<digest> | jq .annotations
```
