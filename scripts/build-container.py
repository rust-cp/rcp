#!/usr/bin/env python3
"""Build a local runtime image from an explicit binary; never push a registry tag."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--notices", type=Path, required=True)
parser.add_argument("--image", required=True)
parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
parser.add_argument("--connection", help="An existing Podman connection; never changes its default")
parser.add_argument("--version", default="unknown")
parser.add_argument("--revision", default="unknown")
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
engine = [args.engine]
if args.connection:
    if args.engine != "podman":
        parser.error("--connection requires Podman")
    engine += ["--connection", args.connection]
with tempfile.TemporaryDirectory(prefix="rcp-image-build-") as temporary:
    context = Path(temporary)
    for name in ("Dockerfile", "runtime-rootfs.py", "packages.lock"):
        shutil.copy(repo/"container"/name, context/name)
    shutil.copy(args.binary, context/"rcp")
    shutil.copy(repo/"LICENSE", context/"LICENSE")
    shutil.copy(args.notices, context/"THIRD_PARTY_LICENSES.txt")
    subprocess.run([*engine, "build", "--platform", "linux/amd64", "--tag", args.image,
                    "--build-arg", f"RCP_VERSION={args.version}",
                    "--build-arg", f"RCP_SOURCE_REVISION={args.revision}",
                    "--build-arg", f"RCP_BINARY_SHA256={binary_hash}", str(context)], check=True)
print(f"Local image {args.image}; binary SHA-256 {binary_hash}; no registry push")
