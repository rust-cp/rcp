#!/usr/bin/env python3
"""Write an SPDX 2.3 bill of materials for rcp's normal (runtime) Cargo graph.

The release binary is built with `--features rustls`. Pass that feature set's
`cargo metadata --format-version 1` document on stdin, or point `--metadata` at
the file `scripts/build-gnu.sh` already writes.

    cargo metadata --locked --features rustls --format-version 1 | python3 scripts/spdx-sbom.py --output rcp.spdx.json
    python3 scripts/spdx-sbom.py --metadata cargo-metadata.json --output SBOM.spdx.json
    cargo metadata --locked --features rustls --format-version 1 | python3 scripts/spdx-sbom.py --check rcp.spdx.json
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
from urllib.parse import quote


def runtime_edges(metadata):
    """Normal dependency edges only. Build and dev edges are not in the binary."""
    resolve = metadata.get("resolve")
    if not resolve or not resolve.get("root"):
        raise ValueError("Cargo metadata must resolve one root package")
    root = resolve["root"]
    nodes = {node["id"]: node for node in resolve["nodes"]}
    edges = []
    seen = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if not any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                continue
            edges.append((package_id, dependency["pkg"]))
            pending.append(dependency["pkg"])
    packages = {package["id"]: package for package in metadata["packages"] if package["id"] in seen}
    if root not in packages:
        raise ValueError("resolved root is missing from the package list")
    return root, packages, edges


def spdx_id(index):
    return f"SPDXRef-Package-{index}"


def purl(package):
    name = quote(package["name"], safe="")
    version = quote(package["version"], safe="")
    return f"pkg:cargo/{name}@{version}"


def license_concluded(declared):
    if not declared or any(word in declared for word in (" OR ", " AND ", " WITH ", "/")):
        return "NOASSERTION"
    return declared


def lock_checksums(path):
    """Registry checksums live in Cargo.lock, not in `cargo metadata`."""
    if path is None or not path.is_file():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {
        (package["name"], package["version"]): package["checksum"]
        for package in data.get("package", [])
        if isinstance(package.get("checksum"), str)
    }


def package_record(package, spdxid, checksums):
    declared = package.get("license") or "NOASSERTION"
    record = {
        "SPDXID": spdxid,
        "name": package["name"],
        "versionInfo": package["version"],
        "downloadLocation": download_location(package),
        "filesAnalyzed": False,
        "licenseDeclared": declared,
        "licenseConcluded": license_concluded(declared),
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl(package),
            }
        ],
    }
    # Cargo.lock is the checksum that was fetched. Metadata often leaves it null.
    checksum = checksums.get((package["name"], package["version"])) or package.get("checksum")
    if isinstance(checksum, str) and len(checksum) == 64:
        record["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
    return record


def download_location(package):
    source = package.get("source") or ""
    if source.startswith("registry+"):
        name = quote(package["name"], safe="")
        version = quote(package["version"], safe="")
        return f"https://crates.io/crates/{name}/{version}"
    return package.get("repository") or "NOASSERTION"


def canonical(root, packages, edges, checksums):
    ordered = sorted(
        (package for package_id, package in packages.items() if package_id != root),
        key=lambda package: (package["name"], package["version"], package["id"]),
    )
    ids = {root: spdx_id(0)}
    for index, package in enumerate(ordered, start=1):
        ids[package["id"]] = spdx_id(index)
    records = [package_record(packages[root], ids[root], checksums)]
    records.extend(package_record(package, ids[package["id"]], checksums) for package in ordered)
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ids[root],
        }
    ]
    relationships.extend(
        {
            "spdxElementId": ids[parent],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": ids[child],
        }
        for parent, child in sorted(edges, key=lambda edge: (ids[edge[0]], ids[edge[1]]))
    )
    return records, relationships


def document(metadata, namespace, checksums=None):
    root, packages, edges = runtime_edges(metadata)
    records, relationships = canonical(root, packages, edges, checksums or {})
    version = packages[root]["version"]
    if namespace is None:
        fingerprint = hashlib.sha256(
            json.dumps({"packages": records, "relationships": relationships}, sort_keys=True).encode()
        ).hexdigest()[:16]
        namespace = f"https://github.com/rust-cp/rcp/spdx/{version}/{fingerprint}"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"rcp-{version}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": "2026-10-14T00:00:00Z",
            "creators": ["Tool: scripts/spdx-sbom.py"],
        },
        "packages": records,
        "relationships": relationships,
    }


def comparable(document_text):
    parsed = json.loads(document_text) if isinstance(document_text, str) else document_text
    return {
        "spdxVersion": parsed["spdxVersion"],
        "name": parsed["name"],
        "documentNamespace": parsed["documentNamespace"],
        "packages": parsed["packages"],
        "relationships": parsed["relationships"],
    }


def render(metadata, namespace, checksums=None):
    return json.dumps(document(metadata, namespace, checksums), indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, help="cargo metadata JSON file; default is stdin")
    parser.add_argument("--output", type=Path, help="write the SPDX document here")
    parser.add_argument("--check", type=Path, help="fail unless this file matches the metadata")
    parser.add_argument("--namespace", help="document namespace URI; default is derived from the graph")
    parser.add_argument("--lock", type=Path, default=Path("Cargo.lock"), help="Cargo.lock used for registry checksums")
    args = parser.parse_args()
    if bool(args.output) == bool(args.check):
        parser.error("pass exactly one of --output or --check")
    raw = args.metadata.read_text(encoding="utf-8") if args.metadata else sys.stdin.read()
    metadata = json.loads(raw)
    checksums = lock_checksums(args.lock)
    if args.check:
        expected = comparable(document(metadata, args.namespace, checksums))
        actual = comparable(args.check.read_text(encoding="utf-8"))
        if actual != expected:
            raise SystemExit(f"{args.check} does not match the Cargo metadata graph; regenerate it")
        return
    args.output.write_text(render(metadata, args.namespace, checksums), encoding="utf-8")


if __name__ == "__main__":
    main()
