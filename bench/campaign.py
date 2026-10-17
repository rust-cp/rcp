#!/usr/bin/env python3
"""Compare rcp with rsync, rclone, and cp on this machine.

The timed region is the tool command only. After every run an independent
SHA-256 walk checks the destination. A mismatch is a failed trial and is not
used as a speed result. Summaries follow hyperfine's --runs N statistics
(min, max, mean, median, standard deviation) over the verified trials.

Cold runs drop the page cache before the tool starts. Warm runs do one
untimed warmup per tool, then measure without dropping the cache. Every
timed command is preceded by a sync, including warm runs: rcp finishes a
local copy with syncfs, which flushes every dirty page on the filesystem.
Without that sync, a warm rcp trial would pay for the previous tool's
writeback. sync leaves the page cache populated, so a warm run stays warm.
Tool order inside each repetition is shuffled so one tool does not always
run last.

Guest drop_caches does not evict the hypervisor's disk cache. Later cold
runs can be warmer than the first. Medians over a shuffled order are what
the tables report.

Headline rcp is the default copy: SHA-256 catalog, io_uring when the kernel
allows it, and a final syncfs. rcp-nohash and rcp-kernel are extra local
modes so a gap can be attributed to hashing or to userspace copy. They are
not the product default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RCP = os.environ.get("RCP_BIN", str(ROOT / "target" / "release" / "rcp"))

# Corpus sizes. Large enough that process startup is not the whole measurement
# on this host, small enough that 10 cold and 10 warm runs finish.
SMALL_DIRS = 80
SMALL_PER_DIR = 100  # 8_000 files * 4 KiB
SMALL_SIZE = 4096
LARGE_COUNT = 4
LARGE_SIZE = 64 * 1024 * 1024  # 256 MiB total
MIXED_SMALL = 1500
MIXED_MEDIUM = 24  # 512 KiB
MIXED_LARGE = 3  # 8 MiB
RESUME_FILES = 24
RESUME_SIZE = 8 * 1024 * 1024  # 192 MiB
RESUME_FRACTION = 0.30


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, text=True, **kw)


def capture(cmd: list[str]) -> str:
    p = run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.strip()


def drop_caches() -> None:
    subprocess.run(
        ["sudo", "-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
        check=True,
    )


def settle(cache: str) -> None:
    """Make the timed command's durability its own.

    rcp ends a local copy with syncfs, which flushes every dirty page on the
    filesystem, not only the pages that copy wrote. Warm runs restore or
    delete a destination first; without a sync those pages would be flushed
    inside rcp's timer and not inside cp, rsync, or rclone. sync writes them
    back and leaves the page cache populated, so a warm run stays warm.
    """
    if cache == "cold":
        drop_caches()
    else:
        subprocess.run(["sudo", "-n", "sync"], check=True)


def rm_rf(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def write_file(path: Path, size: int, block: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        left = size
        while left >= len(block):
            reps = min(left // len(block), 64)
            f.write(block * reps)
            left -= len(block) * reps
        if left:
            f.write(block[:left])


def make_tree(root: Path, layout: list[tuple[str, int]], block: bytes) -> None:
    rm_rf(root)
    root.mkdir(parents=True)
    for rel, size in layout:
        write_file(root / rel, size, block)


def small_layout() -> list[tuple[str, int]]:
    out = []
    for d in range(SMALL_DIRS):
        for i in range(SMALL_PER_DIR):
            out.append((f"d{d:03d}/f{i:03d}.dat", SMALL_SIZE))
    return out


def large_layout() -> list[tuple[str, int]]:
    return [(f"blob{i}.bin", LARGE_SIZE) for i in range(LARGE_COUNT)]


def mixed_layout() -> list[tuple[str, int]]:
    out = []
    for i in range(MIXED_SMALL):
        out.append((f"small/s{i:04d}.dat", SMALL_SIZE))
    for i in range(MIXED_MEDIUM):
        out.append((f"medium/m{i:03d}.dat", 512 * 1024))
    for i in range(MIXED_LARGE):
        out.append((f"large/l{i}.bin", 8 * 1024 * 1024))
    return out


def resume_layout() -> list[tuple[str, int]]:
    return [(f"part/p{i:03d}.bin", RESUME_SIZE) for i in range(RESUME_FILES)]


def net_small_layout(n: int) -> list[tuple[str, int]]:
    return [(f"d{i // 50:02d}/f{i:04d}.dat", SMALL_SIZE) for i in range(n)]


def mutate_tree(src: Path) -> dict:
    """Append to every 10th file and add a directory of new files.

    Nothing is deleted, so rsync -a, rclone sync, and rcp sync all converge
    on the same tree without a delete flag.
    """
    files = sorted(p for p in src.rglob("*") if p.is_file())
    changed = []
    for i, p in enumerate(files):
        if i % 10 == 0:
            with p.open("ab") as f:
                f.write(b"\nchanged-by-campaign\n")
            changed.append(str(p.relative_to(src)))
    extra = src / "added"
    extra.mkdir(exist_ok=True)
    blob = os.urandom(1024)
    added = []
    for i in range(30):
        name = extra / f"new{i:02d}.dat"
        name.write_bytes(blob + i.to_bytes(2, "little"))
        added.append(str(name.relative_to(src)))
    return {"appended": changed, "added": added}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(root: Path) -> dict[str, tuple[str, int, int, int]]:
    """rel -> (sha256, size, mode, mtime_ns) for regular files."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            st = p.lstat()
            if not stat_is_reg(st.st_mode):
                continue
            rel = str(p.relative_to(root))
            out[rel] = (sha256_file(p), st.st_size, st.st_mode & 0o7777, st.st_mtime_ns)
    return out


def stat_is_reg(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)


def compare(src: Path, dst: Path, require_meta: bool) -> dict:
    a = manifest(src)
    b = manifest(dst)
    missing = sorted(set(a) - set(b))
    extra = sorted(set(b) - set(a))
    content_bad = []
    mode_bad = []
    mtime_bad = []
    for rel, (digest, size, mode, mtime) in a.items():
        if rel not in b:
            continue
        gd, gs, gm, gt = b[rel]
        if digest != gd or size != gs:
            content_bad.append(rel)
        if mode != gm:
            mode_bad.append(rel)
        if mtime != gt:
            mtime_bad.append(rel)
    ok = not missing and not extra and not content_bad
    if require_meta:
        ok = ok and not mode_bad and not mtime_bad
    return {
        "ok": ok,
        "files": len(a),
        "missing": len(missing),
        "extra": len(extra),
        "content_mismatch": len(content_bad),
        "mode_mismatch": len(mode_bad),
        "mtime_mismatch": len(mtime_bad),
        "sample": (missing + extra + content_bad + mode_bad + mtime_bad)[:5],
    }


def tree_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            if stat_is_reg(st.st_mode):
                total += st.st_size
    return total


def complete_files(src: Path, dst: Path) -> int:
    n = 0
    if not src.exists():
        return 0
    for dirpath, _, filenames in os.walk(src):
        for name in filenames:
            sp = Path(dirpath) / name
            rel = sp.relative_to(src)
            dp = dst / rel
            try:
                if sp.is_file() and dp.is_file() and sp.stat().st_size == dp.stat().st_size:
                    n += 1
            except FileNotFoundError:
                continue
    return n


class Tool:
    def __init__(self, name: str, require_meta: bool):
        self.name = name
        self.require_meta = require_meta

    def fresh(self, src: Path, dst: Path, cat: Path) -> list[str]:
        raise NotImplementedError

    def sync(self, src: Path, dst: Path, cat: Path, ident: str) -> list[str]:
        raise NotImplementedError

    def resume(self, src: Path, dst: Path, cat: Path, ident: str) -> list[str]:
        raise NotImplementedError

    def partial(self, src: Path, dst: Path, cat: Path, ident: str) -> list[str]:
        return self.fresh(src, dst, cat)


class Rcp(Tool):
    def __init__(self, name: str, extra: list[str] | None = None):
        super().__init__(name, require_meta=True)
        self.extra = extra or []

    def _base(self, cat: Path) -> list[str]:
        return [RCP, "-catalog", str(cat)]

    def fresh(self, src, dst, cat):
        return self._base(cat) + ["copy", *self.extra, str(src), str(dst)]

    def sync(self, src, dst, cat, ident):
        return self._base(cat) + ["sync", "-id", ident]

    def partial(self, src, dst, cat, ident):
        return self._base(cat) + ["copy", "-newid", ident, str(src), str(dst)]

    def resume(self, src, dst, cat, ident):
        return self._base(cat) + ["resume", "-id", ident]


class Rsync(Tool):
    def __init__(self, ssh: list[str] | None = None, dest_prefix: str = ""):
        super().__init__("rsync", require_meta=True)
        self.ssh = ssh
        self.dest_prefix = dest_prefix

    def _e(self) -> list[str]:
        if not self.ssh:
            return []
        return ["-e", " ".join(self.ssh)]

    def _dst(self, dst: Path) -> str:
        return f"{self.dest_prefix}{dst}/" if self.dest_prefix else str(dst) + "/"

    def fresh(self, src, dst, cat):
        # --whole-file matches local rsync's default and keeps a fresh copy
        # from spending time on a delta search. -a preserves mode and mtime.
        return ["rsync", "-a", "--whole-file", *self._e(), str(src) + "/", self._dst(dst)]

    def sync(self, src, dst, cat, ident):
        # No --whole-file: unchanged files are skipped by size and mtime.
        # No --delete: the mutation does not remove files.
        return ["rsync", "-a", *self._e(), str(src) + "/", self._dst(dst)]

    def partial(self, src, dst, cat, ident):
        return ["rsync", "-a", "--partial", "--whole-file", *self._e(), str(src) + "/", self._dst(dst)]

    def resume(self, src, dst, cat, ident):
        # --append continues a shorter partial file. The prefix is the bytes
        # already written; the campaign checks the final SHA-256.
        return [
            "rsync",
            "-a",
            "--partial",
            "--append",
            *self._e(),
            str(src) + "/",
            self._dst(dst),
        ]


class Rclone(Tool):
    def __init__(self, extra: list[str] | None = None, name: str = "rclone"):
        super().__init__(name, require_meta=False)
        self.extra = extra or []

    def fresh(self, src, dst, cat):
        return ["rclone", "copy", str(src), str(dst), *self.extra]

    def sync(self, src, dst, cat, ident):
        return ["rclone", "sync", str(src), str(dst), *self.extra]

    def resume(self, src, dst, cat, ident):
        return self.fresh(src, dst, cat)


class Cp(Tool):
    def __init__(self):
        super().__init__("cp", require_meta=True)

    def fresh(self, src, dst, cat):
        # --reflink=never forces a byte copy. Trailing /. copies the contents,
        # matching rcp and rsync src/.
        return ["cp", "-a", "--reflink=never", str(src) + "/.", str(dst) + "/"]


def timed(cmd: list[str], log: Path) -> tuple[float | None, int, str]:
    t0 = time.perf_counter()
    p = run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    dt = time.perf_counter() - t0
    text = p.stdout
    log.write_text(text)
    if p.returncode != 0:
        return None, p.returncode, text[-2000:]
    return dt, 0, text[-500:]


def stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def engine_of(text: str) -> str:
    for line in text.splitlines():
        if "engine " in line:
            # "engine io_uring," 
            part = line.split("engine ", 1)[1]
            return part.split(",", 1)[0].strip()
    return ""


def env_record() -> dict:
    def sh(cmd: str) -> str:
        return capture(["bash", "-lc", cmd])

    cpu = sh("lscpu | sed -n '1,25p'")
    return {
        "uname": sh("uname -a"),
        "os": sh("sed -n '1,6p' /etc/os-release"),
        "virt": sh("systemd-detect-virt || true"),
        "cpu": cpu,
        "nproc": os.cpu_count(),
        "meminfo": sh("grep -E 'MemTotal|MemAvailable|SwapTotal' /proc/meminfo"),
        "fs": sh("findmnt -T /var/tmp -o TARGET,FSTYPE,SOURCE,OPTIONS"),
        "rustc": sh("rustc --version"),
        "rcp": sh(f"{RCP} version"),
        "rcp_sha256": hashlib.sha256(Path(RCP).read_bytes()).hexdigest(),
        "rsync": sh("rsync --version | head -2"),
        "rclone": sh("rclone version | head -3"),
        "cp": sh("cp --version | head -1"),
        "hyperfine": sh("hyperfine --version"),
        "python": sys.version,
        "drop_caches": "cold: sudo sync; echo 3 > /proc/sys/vm/drop_caches. warm: sudo sync only, so syncfs does not flush another tool's dirty pages",
        "wsl": "microsoft" in sh("uname -a").lower(),
    }


def kill_at_fraction(cmd: list[str], src: Path, dst: Path, log: Path) -> dict:
    """Start cmd and SIGKILL it once `fraction` of source files are complete."""
    total = sum(1 for p in src.rglob("*") if p.is_file())
    need = max(1, int(total * RESUME_FRACTION))
    log_f = log.open("w")
    proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT, start_new_session=True)
    t0 = time.perf_counter()
    hit = False
    while time.perf_counter() - t0 < 120:
        if complete_files(src, dst) >= need:
            hit = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.01)
    elapsed = time.perf_counter() - t0
    if proc.poll() is None:
        # SIGTERM lets the tool finish its current syscall and, for rsync
        # --partial, rename the temp file. SIGKILL follows if it stays up.
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        killed = True
    else:
        killed = False
    log_f.close()
    return {
        "killed": killed and hit,
        "finished_early": not hit,
        "setup_s": elapsed,
        "complete_files": complete_files(src, dst),
        "dest_bytes": tree_bytes(dst),
        "source_files": total,
    }


def copy_tree(src: Path, dst: Path) -> None:
    rm_rf(dst)
    shutil.copytree(src, dst, symlinks=True)


def measure_case(
    tool: Tool,
    kind: str,
    src: Path,
    work: Path,
    runs: int,
    cache: str,
    rng: random.Random,
    logs: Path,
) -> list[dict]:
    """One tool, one workload, one cache mode. Returns trial dicts."""
    rows = []
    # Warmup fills the page cache. It is not a measured trial.
    if cache == "warm":
        _one(tool, kind, src, work, logs / f"{tool.name}-{kind}-warmup", warmup=True)
    for i in range(runs):
        row = _one(tool, kind, src, work, logs / f"{tool.name}-{kind}-{cache}-{i}")
        row.update({"tool": tool.name, "workload": kind, "cache": cache, "rep": i})
        rows.append(row)
        print(
            f"  {cache:4} {tool.name:12} {kind:8} rep {i}: "
            f"{row['seconds'] if row['seconds'] is not None else 'FAIL':} "
            f"verify={row['verify'].get('ok')} rc={row['rc']}",
            flush=True,
        )
    return rows


def _one(tool: Tool, kind: str, src: Path, work: Path, log: Path, warmup: bool = False) -> dict:
    dst = work / "dst"
    cat = work / "catalog"
    snap_dst = work / "snap-dst"
    snap_cat = work / "snap-catalog"
    log.parent.mkdir(parents=True, exist_ok=True)
    meta: dict = {}

    if kind == "delta":
        rm_rf(dst)
        shutil.copytree(snap_dst, dst, symlinks=True, copy_function=shutil.copy2)
        if tool.name.startswith("rcp"):
            rm_rf(cat)
            shutil.copytree(snap_cat, cat)
    elif kind == "resume":
        rm_rf(dst)
        rm_rf(cat)
        dst.mkdir(parents=True)
        cat.mkdir(parents=True)
        ident = "resume1"
        meta["partial"] = kill_at_fraction(
            tool.partial(src, dst, cat, ident), src, dst, log.with_suffix(".partial.log")
        )
        if not meta["partial"]["killed"]:
            return {
                "seconds": None,
                "rc": 0,
                "verify": {"ok": False, "sample": ["partial copy finished before the kill"]},
                "engine": "",
                "meta": meta,
                "warmup": warmup,
            }
    else:
        rm_rf(dst)
        rm_rf(cat)
        dst.mkdir(parents=True)
        cat.mkdir(parents=True)

    if not warmup and os.environ.get("BENCH_CACHE") == "cold":
        drop_caches()

    ident = "job1"
    if kind == "delta":
        cmd = tool.sync(src, dst, cat, ident)
    elif kind == "resume":
        cmd = tool.resume(src, dst, cat, ident)
    else:
        cmd = tool.fresh(src, dst, cat)
    seconds, rc, tail = timed(cmd, log.with_suffix(".log"))
    text = log.with_suffix(".log").read_text(errors="replace") if log.with_suffix(".log").exists() else ""
    verify = {"ok": False, "sample": ["command failed"]}
    if rc == 0:
        verify = compare(src, dst, tool.require_meta)
        if not verify["ok"]:
            seconds = None
    return {
        "seconds": seconds,
        "rc": rc,
        "verify": verify,
        "engine": engine_of(text),
        "cmd": cmd,
        "meta": meta,
        "tail": tail if rc != 0 or not verify.get("ok") else "",
        "warmup": warmup,
    }


def build_sources(work: Path, block: bytes, which: set[str]) -> dict[str, Path]:
    srcs = {}
    if "small" in which:
        print("building small corpus", flush=True)
        p = work / "src-small"
        make_tree(p, small_layout(), block)
        srcs["small"] = p
    if "large" in which:
        print("building large corpus", flush=True)
        p = work / "src-large"
        make_tree(p, large_layout(), block)
        srcs["large"] = p
    if "mixed" in which or "delta" in which:
        print("building mixed corpus", flush=True)
        base = work / "src-mixed-base"
        make_tree(base, mixed_layout(), block)
        srcs["mixed"] = base
        if "delta" in which:
            mutated = work / "src-mixed-mut"
            rm_rf(mutated)
            shutil.copytree(base, mutated, copy_function=shutil.copy2)
            info = mutate_tree(mutated)
            (work / "mutation.json").write_text(json.dumps(info, indent=2))
            srcs["delta"] = mutated
    if "resume" in which:
        print("building resume corpus", flush=True)
        p = work / "src-resume"
        make_tree(p, resume_layout(), block)
        srcs["resume"] = p
    return srcs


def prepare_delta(tools: list[Tool], work: Path, block: bytes) -> Path:
    """Copy the pristine tree, keep that dest, then mutate the source in place.

    rcp sync re-reads the source and destination paths stored in the catalog,
    so each trial restores the pristine dest at that same path and restores
    the catalog. The restore is not timed.
    """
    src = work / "src-delta"
    print("preparing delta source and per-tool snapshots", flush=True)
    make_tree(src, mixed_layout(), block)
    for tool in tools:
        if tool.name == "cp":
            continue
        slot = work / "snaps" / tool.name
        dst = slot / "dst"
        cat = slot / "catalog"
        rm_rf(slot)
        dst.mkdir(parents=True)
        cat.mkdir(parents=True)
        if isinstance(tool, Rcp):
            cmd = [RCP, "-catalog", str(cat), "copy", "-newid", "job1", str(src), str(dst)]
        else:
            cmd = tool.fresh(src, dst, cat)
        p = run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (slot / "setup.log").write_text(p.stdout)
        if p.returncode != 0:
            raise SystemExit(f"delta setup failed for {tool.name}:\n{p.stdout[-800:]}")
        check = compare(src, dst, tool.require_meta)
        if not check["ok"]:
            raise SystemExit(f"delta setup verify failed for {tool.name}: {check}")
        shutil.copytree(dst, slot / "dst.base", copy_function=shutil.copy2)
        if isinstance(tool, Rcp):
            shutil.copytree(cat, slot / "catalog.base")
    mutate_tree(src)
    return src


def trial_delta(tool: Tool, src: Path, work: Path, log: Path, cache: str) -> dict:
    slot = work / "snaps" / tool.name
    dst = slot / "dst"
    cat = slot / "catalog"
    rm_rf(dst)
    shutil.copytree(slot / "dst.base", dst, copy_function=shutil.copy2)
    if isinstance(tool, Rcp):
        rm_rf(cat)
        shutil.copytree(slot / "catalog.base", cat)
    settle(cache)
    cmd = tool.sync(src, dst, cat, "job1")
    seconds, rc, tail = timed(cmd, log)
    text = log.read_text(errors="replace") if log.exists() else ""
    verify = {"ok": False, "sample": ["command failed"]}
    if rc == 0:
        verify = compare(src, dst, tool.require_meta)
        if not verify["ok"]:
            seconds = None
    return {
        "seconds": seconds,
        "rc": rc,
        "verify": verify,
        "engine": engine_of(text),
        "cmd": cmd,
        "tail": tail if rc != 0 or not verify.get("ok") else "",
    }


def trial_fresh(tool: Tool, src: Path, work: Path, log: Path, cache: str) -> dict:
    dst = work / "dst" / tool.name
    cat = work / "catalog" / tool.name
    rm_rf(dst)
    rm_rf(cat)
    dst.mkdir(parents=True)
    cat.mkdir(parents=True)
    settle(cache)
    cmd = tool.fresh(src, dst, cat)
    seconds, rc, tail = timed(cmd, log)
    text = log.read_text(errors="replace") if log.exists() else ""
    verify = {"ok": False, "sample": ["command failed"]}
    if rc == 0:
        verify = compare(src, dst, tool.require_meta)
        if not verify["ok"]:
            seconds = None
    return {
        "seconds": seconds,
        "rc": rc,
        "verify": verify,
        "engine": engine_of(text),
        "cmd": cmd,
        "tail": tail if rc != 0 or not verify.get("ok") else "",
    }


def trial_resume(tool: Tool, src: Path, work: Path, log: Path, cache: str) -> dict:
    dst = work / "dst" / tool.name
    cat = work / "catalog" / tool.name
    rm_rf(dst)
    rm_rf(cat)
    dst.mkdir(parents=True)
    cat.mkdir(parents=True)
    partial = kill_at_fraction(tool.partial(src, dst, cat, "resume1"), src, dst, log.with_suffix(".partial.log"))
    if not partial["killed"]:
        return {
            "seconds": None,
            "rc": 0,
            "verify": {"ok": False, "sample": ["partial copy finished before the kill"]},
            "engine": "",
            "cmd": [],
            "meta": partial,
            "tail": "",
        }
    settle(cache)
    cmd = tool.resume(src, dst, cat, "resume1")
    seconds, rc, tail = timed(cmd, log)
    text = log.read_text(errors="replace") if log.exists() else ""
    verify = {"ok": False, "sample": ["command failed"]}
    if rc == 0:
        verify = compare(src, dst, tool.require_meta)
        if not verify["ok"]:
            seconds = None
    return {
        "seconds": seconds,
        "rc": rc,
        "verify": verify,
        "engine": engine_of(text),
        "cmd": cmd,
        "meta": partial,
        "tail": tail if rc != 0 or not verify.get("ok") else "",
    }


def campaign(args: argparse.Namespace) -> None:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)
    env = env_record()
    (out / "env.json").write_text(json.dumps(env, indent=2))
    print(env["rcp"].splitlines()[0], flush=True)
    print("wsl" if env["wsl"] else "not WSL", env["virt"], flush=True)

    block = os.urandom(64 * 1024)
    which = set(args.workloads.split(","))
    tools: list[Tool] = []
    wanted = set(args.tools.split(","))
    if "rcp" in wanted:
        tools.append(Rcp("rcp"))
    if "rcp-nohash" in wanted:
        tools.append(Rcp("rcp-nohash", ["-nohash"]))
    if "rcp-kernel" in wanted:
        tools.append(Rcp("rcp-kernel", ["-nohash", "-engine", "threads"]))
    if "rsync" in wanted:
        tools.append(Rsync())
    if "rclone" in wanted:
        tools.append(Rclone())
    if "cp" in wanted:
        tools.append(Cp())

    srcs = build_sources(work, block, which - {"delta"})
    if "delta" in which:
        srcs["delta"] = prepare_delta(
            [t for t in tools if t.name in ("rcp", "rsync", "rclone")], work, block
        )

    rng = random.Random(args.seed)
    trials: list[dict] = []
    caches = args.caches.split(",")
    for cache in caches:
        os.environ["BENCH_CACHE"] = cache
        for kind in args.workloads.split(","):
            active = []
            for t in tools:
                if kind in ("delta", "resume") and t.name in ("cp", "rcp-nohash", "rcp-kernel"):
                    continue
                if kind == "delta" and t.name != "rcp" and t.name.startswith("rcp"):
                    continue
                active.append(t)
            if cache == "warm":
                print(f"warmup {kind}", flush=True)
                for t in active:
                    row = dispatch(t, kind, srcs[kind], work, logs / f"warmup-{t.name}-{kind}.log", "warm")
                    if not row["verify"].get("ok"):
                        print(f"  WARMUP FAIL {t.name} {kind}: {row['verify']} {row.get('tail','')[:400]}", flush=True)
            for rep in range(args.runs):
                order = active[:]
                rng.shuffle(order)
                for t in order:
                    log = logs / f"{kind}-{cache}-{t.name}-{rep}.log"
                    row = dispatch(t, kind, srcs[kind], work, log, cache)
                    row.update({"tool": t.name, "workload": kind, "cache": cache, "rep": rep})
                    trials.append(row)
                    sec = row["seconds"]
                    shown = f"{sec:.4f}s" if isinstance(sec, float) else "FAIL"
                    print(
                        f"  {cache:4} {kind:8} {t.name:12} {rep}: {shown} "
                        f"ok={row['verify'].get('ok')} engine={row.get('engine','')}",
                        flush=True,
                    )
                    if not row["verify"].get("ok"):
                        print(f"    {row['verify']} {row.get('tail','')[:500]}", flush=True)

    (out / "trials.json").write_text(json.dumps(trials, indent=2))
    summary = summarize(trials)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    (out / "summary.md").write_text(render_md(summary, env))
    print(render_md(summary, env))


def dispatch(tool: Tool, kind: str, src: Path, work: Path, log: Path, cache: str) -> dict:
    log.parent.mkdir(parents=True, exist_ok=True)
    if kind == "delta":
        # Warmup must not permanently mutate the snapshot. trial_delta restores it.
        if cache == "warm" and log.name.startswith("warmup-"):
            # still restore inside trial_delta
            pass
        return trial_delta(tool, src, work, log, "warm" if cache == "warm" and log.name.startswith("warmup-") else cache)
    if kind == "resume":
        # A warmup resume still consumes a partial copy. Do it for real so the
        # source pages are hot, and do not record it.
        return trial_resume(tool, src, work, log, "warm" if log.name.startswith("warmup-") else cache)
    return trial_fresh(tool, src, work, log, "warm" if log.name.startswith("warmup-") else cache)


def summarize(trials: list[dict]) -> list[dict]:
    groups: dict[tuple, list] = {}
    for t in trials:
        if t.get("warmup"):
            continue
        groups.setdefault((t["workload"], t["cache"], t["tool"]), []).append(t)
    rows = []
    for (wl, cache, tool), items in sorted(groups.items()):
        good = [i["seconds"] for i in items if isinstance(i.get("seconds"), float)]
        failed = [i for i in items if not isinstance(i.get("seconds"), float)]
        row = {
            "workload": wl,
            "cache": cache,
            "tool": tool,
            "verified": len(good),
            "failed": len(failed),
            **{k: v for k, v in stats(good).items() if k != "n"},
        }
        if good:
            row["n"] = len(good)
        engines = sorted({i.get("engine") or "" for i in items if i.get("engine")})
        if engines:
            row["engine"] = ",".join(engines)
        if failed:
            row["failure"] = failed[0].get("verify")
        rows.append(row)
    return rows


def render_md(summary: list[dict], env: dict) -> str:
    lines = [
        "| workload | cache | tool | verified | failed | median s | min s | max s | mean s | stddev s | engine |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for r in summary:
        if r.get("verified", 0) == 0:
            lines.append(
                f"| {r['workload']} | {r['cache']} | {r['tool']} | 0 | {r['failed']} | — | — | — | — | — | {r.get('engine','')} |"
            )
            continue
        lines.append(
            "| {workload} | {cache} | {tool} | {verified} | {failed} | {median:.4f} | {min:.4f} | {max:.4f} | {mean:.4f} | {stddev:.4f} | {eng} |".format(
                eng=r.get("engine", ""), **{k: v for k, v in r.items() if k != "engine"}
            )
        )
    lines.append("")
    lines.append("rcp: " + env["rcp"].splitlines()[0])
    lines.append("kernel: " + env["uname"])
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    p.add_argument("--work", default="/var/tmp/rcp-bench-work")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--caches", default="cold,warm")
    p.add_argument("--workloads", default="small,large,mixed,delta,resume")
    p.add_argument("--tools", default="rcp,rcp-nohash,rcp-kernel,rsync,rclone,cp")
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    if not Path(RCP).is_file():
        sys.exit(f"no rcp binary at {RCP}")
    campaign(args)


if __name__ == "__main__":
    main()
