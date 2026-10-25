"""Assemble only required ELF runtimes, trust roots, notices and private state paths.

The scratch final stage contains glibc and its loader: it is not a static binary.
No shell, compiler, package manager or Python interpreter is copied.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
root.mkdir(exist_ok=False)
copied = set()
packages = {"ca-certificates"}


def owner(path):
    for candidate in (path, path.resolve()):
        result = subprocess.run(["dpkg-query", "-S", str(candidate)], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                package = line.split(": ", 1)[0].split(", ", 1)[0]
                # usrmerge may emit diversion notices before the actual owner.
                if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?", package):
                    return package
    return None


def copy(path):
    path = Path(path)
    if str(path) in copied:
        return
    if not path.is_file():
        raise SystemExit(f"Missing runtime file: {path}")
    target = root / str(path).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Materialize the target under its loader-visible name; no dangling symlinks.
    shutil.copy2(path.resolve(), target)
    copied.add(str(path))
    package = owner(path)
    if package:
        packages.add(package)


def elf(path):
    copy(path)
    result = subprocess.run(["ldd", str(path)], capture_output=True, text=True)
    if result.returncode or "not found" in result.stdout:
        raise SystemExit(f"Unresolved runtime dependencies: {path}")
    for library in re.findall(r"(/[^\s]+)", result.stdout):
        copy(library)


def multiarch():
    machine = os.uname().machine
    if machine == "x86_64":
        return "x86_64-linux-gnu"
    if machine == "aarch64":
        return "aarch64-linux-gnu"
    raise SystemExit(f"unsupported runtime architecture: {machine}")


lib = Path("/usr/lib") / multiarch()
for binary in ("/usr/local/bin/rcp", "/usr/bin/ssh", str(lib / "libgssapi_krb5.so.2")):
    elf(binary)
# Runtime-loaded Kerberos plugins do not appear in the executable's DT_NEEDED.
for plugin in (lib / "krb5/plugins").rglob("*.so"):
    elf(plugin)
for path in ("/etc/os-release", "/etc/ssl/certs/ca-certificates.crt", "/usr/share/rcp/LICENSE",
             "/usr/share/rcp/THIRD_PARTY_LICENSES.txt"):
    copy(path)

for directory, mode, uid in (("etc", 0o755, 0), ("tmp", 0o1777, 0),
                             ("state", 0o700, 10001)):
    path = root / directory
    path.mkdir(exist_ok=True)
    path.chmod(mode)
    os.chown(path, uid, uid)
(root/"etc/passwd").write_text("root:x:0:0:root:/root:/usr/sbin/nologin\nrcp:x:10001:10001:rcp:/state:/usr/sbin/nologin\n")
(root/"etc/group").write_text("root:x:0:\nrcp:x:10001:\n")
(root/"etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files dns\n")
(root/"etc/krb5.conf").write_text("# Mount deployment-specific realm configuration here.\n")

inventory = []
for package in sorted(packages):
    info = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}", package], text=True)
    name, version, architecture = info.split("\t")
    inventory.append(dict(name=name, version=version, architecture=architecture))
    copyright_file = Path("/usr/share/doc") / name / "copyright"
    if not copyright_file.exists():
        raise SystemExit(f"Missing runtime package license: {name}")
    copy(copyright_file)

# Preserve upstream source identities as well as binary package names. Ubuntu
# advisories commonly refer to the source package (e.g. glibc, not libc6).
# These records identify packages supplying selected files, not complete installs.
status = root/"var/lib/dpkg/status"
status.parent.mkdir(parents=True)
status.write_text("\n\n".join(
    subprocess.check_output(["dpkg-query", "-s", p['name']], text=True).strip()
    for p in inventory)+"\n")
(root/"usr/share/rcp/runtime-packages.json").write_text(json.dumps(inventory, indent=2)+"\n")
(root/"usr/share/rcp/runtime-files.json").write_text(json.dumps(sorted(copied), indent=2)+"\n")
print(json.dumps(inventory, indent=2))
