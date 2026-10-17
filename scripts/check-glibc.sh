#!/usr/bin/env bash
# Fail closed on GNU/Linux ELF binaries requiring a newer libc than the deployment floor.
set -euo pipefail
export LC_ALL=C
binary=${1:?usage: check-glibc.sh BINARY [MAX_VERSION]}
maximum=${2:-2.34}
target=${3:-x86_64-unknown-linux-gnu}
case "$target" in
  x86_64-unknown-linux-gnu) interpreter=ld-linux-x86-64.so.2; machine='Advanced Micro Devices X86-64' ;;
  aarch64-unknown-linux-gnu) interpreter=ld-linux-aarch64.so.1; machine=AArch64 ;;
  *) echo 'unsupported GNU/Linux ABI target' >&2; exit 2 ;;
esac
[[ $maximum =~ ^[0-9]+\.[0-9]+$ ]] || { echo 'invalid GLIBC limit' >&2; exit 2; }
header=$(readelf --file-header --wide "$binary")
grep -q "Machine:.*$machine" <<< "$header" && grep -q 'Class:.*ELF64' <<< "$header" || {
  echo "expected ELF64 $target machine" >&2; exit 1;
}
program_headers=$(readelf --program-headers --wide "$binary")
grep -F 'Requesting program interpreter:' <<< "$program_headers" | grep -Fq "/$interpreter]" || {
  echo "expected dynamically linked $target GNU/Linux binary" >&2; exit 1;
}
requirements=$(readelf --version-info --wide "$binary")
if grep -q GLIBC_PRIVATE <<< "$requirements"; then
  echo 'private GNU libc ABI is forbidden' >&2; exit 1
fi
versions=$(grep -oE 'Name: GLIBC_[0-9]+(\.[0-9]+)+' <<< "$requirements" | sed 's/Name: GLIBC_//' | sort -Vu)
[[ -n $versions ]] || { echo 'no versioned GNU libc requirements found' >&2; exit 1; }
highest=$(tail -1 <<< "$versions")
printf 'Required GLIBC versions:\n%s\nMaximum required: %s; allowed: %s\n' "$versions" "$highest" "$maximum"
[[ $(printf '%s\n%s\n' "$highest" "$maximum" | sort -V | tail -1) == "$maximum" ]] || {
  echo "binary requires GLIBC_$highest, exceeding GLIBC_$maximum" >&2; exit 1;
}
