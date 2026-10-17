#!/usr/bin/env bash
# rcp's copy engines against each other on the same workloads, same host, same parallelism.
#
# Usage: bench/compare.sh WORKDIR [REPS] [PARALLEL]
#   RCP_BIN  path to rcp (default: target/release/rcp next to this script's crate)
#   TOOLS    space-separated subset of: rcp rcp-threads rcp-nohash (default: all)
#
# Tools:
#   rcp          default settings: io_uring engine where the kernel allows it, SHA-256 catalog
#   rcp-threads  -engine threads: one blocking read then one blocking write per worker
#   rcp-nohash   -nohash: copy_file_range per data extent, no digest in the catalog
#
# Each workload is copied REPS times by each engine, the order rotated each rep so cache warmth
# does not favor whoever runs last. Page cache is dropped before every run when
# /proc/sys/vm/drop_caches is writable; otherwise the runs are warm-cache and the report says
# so. Every copy is checked by `diff -r` -- NOT by rcp's own verify, which would be the tool
# grading itself -- so a fast copy that is wrong shows up as a failed check rather than a good
# number. A second table times `rcp verify` itself on one tree.
set -euo pipefail
WORK=${1:?usage: compare.sh WORKDIR [REPS] [PARALLEL]}
REPS=${2:-3}
PAR=${3:-4}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RCP_BIN=${RCP_BIN:-$HERE/../target/release/rcp}
TOOLS=${TOOLS:-"rcp rcp-threads rcp-nohash"}
[ -x "$RCP_BIN" ] || { echo "rcp binary not found at $RCP_BIN (bun run build:rcp)" >&2; exit 2; }
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd)
RESULTS="$WORK/results.csv"; : > "$RESULTS"
echo "tool,workload,rep,seconds,bytes,files,checked_by,engine" >> "$RESULTS"
VRESULTS="$WORK/results-verify.csv"; : > "$VRESULTS"
echo "tool,workload,rep,seconds,bytes,files,status" >> "$VRESULTS"

drop_caches() { sync; if [ -w /proc/sys/vm/drop_caches ]; then echo 3 > /proc/sys/vm/drop_caches 2>/dev/null && return 0; fi; return 1; }
if drop_caches; then CACHE="cold (page cache dropped before every run)"; else CACHE="WARM (drop_caches not writable here)"; fi
echo "cache policy: $CACHE"
echo "rcp: $("$RCP_BIN" version | tr '\n' ';')"

# ---- workloads -------------------------------------------------------------------------------
make_small() { # 20,000 x 4 KiB in 200 directories: metadata-bound
  local d=$1; [ -d "$d" ] && return; mkdir -p "$d"
  python3 - "$d" <<'PY'
import os, sys, random
root = sys.argv[1]; rnd = random.Random(7)
for i in range(200):
    sub = os.path.join(root, f"dir{i:03d}"); os.makedirs(sub, exist_ok=True)
    for j in range(100):
        with open(os.path.join(sub, f"f{j:03d}.dat"), "wb") as f: f.write(rnd.randbytes(4096))
PY
}
make_large() { # 2 x 512 MiB of incompressible data plus a 1 GiB image that is 95% holes: bandwidth-bound
  # Sized so that an engine which filled holes would still fit beside the source on a small
  # disk; the data-to-hole ratio is what the workload is about.
  local d=$1; [ -d "$d" ] && return; mkdir -p "$d"
  head -c $((512<<20)) /dev/urandom > "$d/blob1.bin"
  head -c $((512<<20)) /dev/urandom > "$d/blob2.bin"
  python3 - "$d/disk.img" <<'PY'
import os, sys, random
p = sys.argv[1]; size = 1 << 30; rnd = random.Random(11)
with open(p, "wb") as f:
    f.truncate(size)
    for _ in range(13):                      # 13 x 4 MiB of data scattered through 1 GiB
        f.seek(rnd.randrange(0, size - (4 << 20))); f.write(rnd.randbytes(4 << 20))
PY
}
bytes_of() { du -sb "$1" | cut -f1; }
files_of() { find "$1" -type f | wc -l; }

# ---- runners ---------------------------------------------------------------------------------
rcp_flags() { case "$1" in rcp-threads) echo "-engine threads";; rcp-nohash) echo "-nohash";; *) echo "";; esac; }
run_rcp_copy() { local tool=$1 src=$2 dst=$3 id=$4; "$RCP_BIN" -catalog "$WORK/rcp-catalog" copy -parallel "$PAR" $(rcp_flags "$tool") -newid "$id" "$src" "$dst" > "$WORK/log-$tool-$id.txt" 2>&1; }
run_rcp_verify() { "$RCP_BIN" -catalog "$WORK/rcp-catalog" verify -parallel "$PAR" "$1" "$2" > "$WORK/log-rcp-verify-$3.txt" 2>&1; }
# The independent check: content and tree shape by diff, which shares no code with rcp.
run_diff_check() { diff -r -q --no-dereference "$1" "$2" > "$WORK/log-diff-$3.txt" 2>&1; }

timed() { local t0 t1; t0=$(date +%s.%N); "$@"; local rc=$?; t1=$(date +%s.%N); echo "$(echo "$t1 - $t0" | bc) $rc"; }

RUN=$(date -u +%H%M%S)   # copy IDs must be unique per run: the catalog persists between runs
one() { # tool workload rep
  local tool=$1 wl=$2 rep=$3 src="$WORK/src-$wl" dst="$WORK/dst-$tool-$wl-$rep" id="$RUN-$wl-$rep-$tool"
  # Every engine gets an existing, empty destination, so the timed work is the same.
  rm -rf "$dst"; mkdir -p "$dst"; drop_caches || true
  local res rc secs verified=no engine=-
  res=$(timed run_rcp_copy "$tool" "$src" "$dst" "$id")
  secs=${res% *}; rc=${res#* }
  if [ "$rc" = 0 ]; then
    engine=$(grep -oE 'engine [a-z_]+' "$WORK/log-$tool-$id.txt" | head -1 | cut -d' ' -f2)
    run_diff_check "$src" "$dst" "$id" && verified=diff || verified=FAILED-diff
  else
    secs=NaN; verified="copy-rc-$rc"
  fi
  echo "$tool,$wl,$rep,$secs,$(bytes_of "$src"),$(files_of "$src"),$verified,$engine" >> "$RESULTS"
  printf '   %-12s %-6s rep %s: %8ss  verified=%s engine=%s\n' "$tool" "$wl" "$rep" "$secs" "$verified" "$engine"
  rm -rf "$dst"
}

verify_one() { # tool workload rep tree
  local tool=$1 wl=$2 rep=$3 tree=$4 src="$WORK/src-$wl" id="$RUN-v-$wl-$rep-$tool" res secs rc status
  drop_caches || true
  res=$(timed run_rcp_verify "$src" "$tree" "$id")
  secs=${res% *}; rc=${res#* }
  if [ "$rc" = 0 ]; then status=passed; else status="rc-$rc"; fi
  echo "$tool,$wl,$rep,$secs,$(bytes_of "$src"),$(files_of "$src"),$status" >> "$VRESULTS"
  printf '   verify %-4s %-6s rep %s: %8ss  %s\n' "$tool" "$wl" "$rep" "$secs" "$status"
}

echo "preparing workloads under $WORK"; make_small "$WORK/src-small"; make_large "$WORK/src-large"
echo "small: $(files_of "$WORK/src-small") files, $(bytes_of "$WORK/src-small") bytes; large: $(files_of "$WORK/src-large") files, $(bytes_of "$WORK/src-large") bytes (disk.img is sparse)"
rm -rf "$WORK/rcp-catalog"
read -r -a TOOL_LIST <<< "$TOOLS"
for wl in small large; do
  for rep in $(seq 1 "$REPS"); do
    n=${#TOOL_LIST[@]}
    for ((k = 0; k < n; k++)); do
      tool=${TOOL_LIST[$(( (k + rep - 1) % n ))]}   # rotate the order each rep
      one "$tool" "$wl" "$rep"
    done
  done
done

# ---- verify benchmark: one rcp copy per workload, then rcp verifies it REPS times ------------
for wl in small large; do
  tree="$WORK/dst-verify-$wl"; rm -rf "$tree"; mkdir -p "$tree"
  run_rcp_copy rcp "$WORK/src-$wl" "$tree" "$RUN-vtree-$wl" || { echo "verify-tree copy failed for $wl" >&2; continue; }
  for rep in $(seq 1 "$REPS"); do
    verify_one rcp "$wl" "$rep" "$tree"
  done
  rm -rf "$tree"
done

# ---- summary ---------------------------------------------------------------------------------
python3 - "$RESULTS" "$VRESULTS" "$CACHE" "$PAR" <<'PY'
import csv, sys, statistics as st
rows = list(csv.DictReader(open(sys.argv[1])))
vrows = list(csv.DictReader(open(sys.argv[2])))
print(f"\n## Copy (parallel {sys.argv[4]}, cache {sys.argv[3]})\n")
print("| workload | tool | engine | runs | median s | min s | MiB/s (median) | files/s (median) | checked |")
print("|---|---|---|---|---|---|---|---|---|")
for wl in ["small", "large"]:
    for tool in ["rcp", "rcp-threads", "rcp-nohash"]:
        rs = [r for r in rows if r["workload"] == wl and r["tool"] == tool and r["seconds"] != "NaN"]
        if not rs: continue
        secs = [float(r["seconds"]) for r in rs]; med = st.median(secs); b = int(rs[0]["bytes"]); n = int(rs[0]["files"])
        ver = ",".join(sorted(set(r["checked_by"] for r in rs))); eng = ",".join(sorted(set(r["engine"] for r in rs)))
        print(f"| {wl} | {tool} | {eng} | {len(rs)} | {med:.2f} | {min(secs):.2f} | {b/med/2**20:.1f} | {n/med:.0f} | {ver} |")
print(f"\n## Verify (parallel {sys.argv[4]}, same rcp-made tree, cache {sys.argv[3]})\n")
print("| workload | tool | runs | median s | min s | MiB/s (median) | status |")
print("|---|---|---|---|---|---|---|")
for wl in ["small", "large"]:
    for tool in ["rcp"]:
        rs = [r for r in vrows if r["workload"] == wl and r["tool"] == tool]
        if not rs: continue
        secs = [float(r["seconds"]) for r in rs]; med = st.median(secs); b = int(rs[0]["bytes"])
        print(f"| {wl} | {tool} | {len(rs)} | {med:.2f} | {min(secs):.2f} | {b/med/2**20:.1f} | {','.join(sorted(set(r['status'] for r in rs)))} |")
bad = [r for r in rows if r["seconds"] == "NaN" or r["checked_by"].startswith(("FAILED", "copy-rc"))]
bad += [r for r in vrows if r["status"] != "passed"]
print(f"\n{len(bad)} failed run(s)" if bad else "\nall runs copied and checked by diff")
for r in bad: print("  ", r)
PY
