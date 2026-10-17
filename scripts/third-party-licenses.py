#!/usr/bin/env python3
"""Bundle the license notices of the release binary's normal Cargo dependencies."""

import json
from pathlib import Path
import sys


def runtime_packages(metadata):
    """Follow normal dependency edges; build scripts are not distributed in the binary."""
    resolve = metadata.get("resolve")
    if not resolve or not resolve.get("root"):
        raise ValueError("Cargo metadata must resolve one root package")
    root = resolve["root"]
    nodes = {node["id"]: node for node in resolve["nodes"]}
    seen = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(
            dependency["pkg"]
            for dependency in nodes[package_id]["deps"]
            if any(kind["kind"] is None for kind in dependency["dep_kinds"])
        )
    return sorted(
        (package for package in metadata["packages"] if package["id"] in seen and package["id"] != root),
        key=lambda package: (package["name"], package["version"], package["id"]),
    )


def license_files(package):
    directory = Path(package["manifest_path"]).parent.resolve()
    paths = {
        path.resolve()
        for path in directory.rglob("*")
        if path.is_file()
        and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
    }
    if package.get("license_file"):
        declared = (directory / package["license_file"]).resolve()
        if not declared.is_file():
            raise ValueError(f"{package['name']}: declared license file is missing")
        paths.add(declared)
    for path in paths:
        if not path.is_relative_to(directory):
            raise ValueError(f"{package['name']}: license file leaves package directory")
    if not paths:
        raise ValueError(f"{package['name']} {package['version']}: no license notices found")
    return directory, sorted(paths, key=lambda path: path.relative_to(directory).as_posix())


def render_notices(metadata):
    parts = [
        "Third-party license notices\n",
        "These notices accompany the dependencies included in the rcp release binary.\n",
    ]
    for package in runtime_packages(metadata):
        parts.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\n")
        parts.append(f"Declared license: {package.get('license') or 'see notices below'}\n")
        directory, paths = license_files(package)
        for path in paths:
            parts.append(f"\n--- {path.relative_to(directory).as_posix()} ---\n")
            # Preserve notice text, including nested licenses referenced by ring's LICENSE.
            contents = path.read_text(encoding="utf-8")
            parts.append(contents)
            if not contents.endswith("\n"):
                parts.append("\n")
    return "".join(parts)


def main():
    sys.stdout.write(render_notices(json.load(sys.stdin)))


if __name__ == "__main__":
    main()
