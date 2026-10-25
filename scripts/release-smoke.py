#!/usr/bin/env python3
"""Check the actual release archive before creating its tag or publishing it."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def checksums(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, filename = line.split()
        rows.append((digest, filename))
    return rows


def main():
    dist = Path(sys.argv[1]).resolve()
    tag = sys.argv[2]
    target = sys.argv[3] if len(sys.argv) > 3 else "x86_64-unknown-linux-gnu"
    name = f"rcp-{tag}-{target}"
    archive = dist / f"{name}.tar.gz"
    rows = checksums((dist / "SHA256SUMS").read_text())
    expected = [digest for digest, filename in rows if filename == archive.name]
    assert expected, archive.name
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected[0]
    sbom_name = f"{archive.name}.spdx.json"
    sbom_digest = [digest for digest, filename in rows if filename == sbom_name]
    assert sbom_digest, sbom_name
    assert hashlib.sha256((dist / sbom_name).read_bytes()).hexdigest() == sbom_digest[0]
    with tempfile.TemporaryDirectory(prefix="rcp-release-smoke-") as directory:
        root = Path(directory)
        with tarfile.open(archive) as bundle:
            # This is our generated archive; still reject paths outside the install root.
            for member in bundle.getmembers():
                assert not member.issym() and not member.islnk()
                assert (root / member.name).resolve().is_relative_to(root)
            bundle.extractall(root, filter="data")
        install = root / name
        for filename in ["rcp", "LICENSE", "README.md", "RUNTIME.txt", "THIRD_PARTY_LICENSES.txt", "SBOM.spdx.json"]:
            assert (install / filename).stat().st_size > 0, filename
        sbom = json.loads((install / "SBOM.spdx.json").read_text())
        assert sbom["spdxVersion"] == "SPDX-2.3"
        assert any(package["name"] == "rust-cp" for package in sbom["packages"])
        binary = install / "rcp"
        env = dict(os.environ, HOME=str(root), RCP_CATALOG=str(root / "catalog"))

        def run(*args, ok=True, input=None):
            result = subprocess.run([str(binary), *map(str, args)], env=env,
                                    input=input, text=True, capture_output=True, timeout=30)
            if ok:
                assert result.returncode == 0, (args, result.stdout, result.stderr)
            else:
                assert result.returncode != 0, args
            return result

        assert tag.removeprefix("v") in run("version").stdout
        source, destination = root / "source", root / "destination"
        source.mkdir()
        (source / "unicode-雪.txt").write_text("release smoke — verified\n")
        (source / "binary").write_bytes(bytes(range(256)) * 100)
        run("copy", source, destination)
        run("verify", source, destination)
        assert (destination / "binary").read_bytes() == (source / "binary").read_bytes()
        (source / "unicode-雪.txt").write_text("updated contents\n")
        run("isync", source, destination)
        run("verify", source, destination)
        run("copy", root / "missing", root / "bad", ok=False)
        identifier = 'quoted"id\\雪'
        reply = run("mcp", input=json.dumps({"jsonrpc": "2.0", "id": identifier,
                                             "method": "ping"}) + "\n")
        response = json.loads(reply.stdout)
        assert response["id"] == identifier and "result" in response
        run("delete", destination)
        assert (destination / "binary").is_file(), "delete without -force must only count"
        run("delete", "-force", destination)
        assert not any(destination.iterdir())
    print("Release archive: checksum, clean install, copy/integrity, incremental update, error, MCP and deletion smoke checks passed")


if __name__ == "__main__":
    main()
