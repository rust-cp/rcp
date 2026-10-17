#!/usr/bin/env bash
# The multi-host scenarios, run from the client pod that playbook.yml stands up:
#
#   fleet   `-nodes` spreads an S3-to-S3 copy over three worker pods; every worker must
#           have run a batch, and the copy must verify and read back identical
#   relay   `-via ssh://hop-a` reaches hop-b, which a NetworkPolicy closes to everything but
#           a hop; the client's own dial to hop-b is the control and must fail
#   mtls    `rcps://` to a serve that requires a client certificate from the suite's CA;
#           no certificate, one from another CA, and an untrusted server must each fail
#   krb     NFS-Ganesha exporting with RPCSEC_GSS only, against an MIT KDC: copy, verify and
#           read back under krb5, krb5i and krb5p (and krb5p over v4.0), with AUTH_SYS and a
#           client without a ticket as the controls that must fail
#
#   interop/k3s/tests.sh [fleet relay mtls krb]
set -uo pipefail

NS=${NS:-rcp-interop}
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}
k() { kubectl -n "$NS" "$@"; }
# in a pod, through sh so the pod's own PATH and quoting apply
pod() { local pod=$1; shift; k exec "$pod" -- sh -c "$*"; }
TLS="-tls.ca /etc/rcp-tls/ca.crt -tls.cert /etc/rcp-tls/client.crt -tls.key /etc/rcp-tls/client.key"

# run LABEL POD CMD -- print the tail of what CMD printed, return its status
run() {
    local label=$1 pod=$2 out rc
    shift 2
    out=$(pod "$pod" "$*" 2>&1)
    rc=$?
    echo "$label: rc=$rc"
    printf '%s\n' "$out" | tail -3 | sed 's/^/    /'
    return $rc
}
# refused LABEL POD CMD -- CMD must fail; a success here is the defect
refused() {
    local label=$1 pod=$2 out rc
    shift 2
    out=$(pod "$pod" "$*" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "$label: ACCEPTED, and it must not be"
        printf '%s\n' "$out" | tail -3 | sed 's/^/    /'
        return 1
    fi
    echo "$label: refused (rc=$rc): $(printf '%s\n' "$out" | grep -m1 -E 'ERROR|error' | cut -c1-150)"
}
# same POD-A DIR-A POD-B DIR-B -- the two trees hold the same names and bytes
same() {
    local sums="find . -type f -exec sha256sum {} + | sort; find . -type d -empty | sort"
    if diff <(pod "$1" "cd '$2' && $sums") <(pod "$3" "cd '$4' && $sums") >/tmp/rcp-k3s-diff 2>&1; then
        echo "same: $1:$2 and $3:$4 hold the same $(pod "$1" "find '$2' -type f | wc -l") files"
    else
        echo "DIFFERENT: $1:$2 and $3:$4"
        head -20 /tmp/rcp-k3s-diff
        return 1
    fi
}

# The fixture, built in a client pod: sizes either side of the read and write
# boundaries, a 17 MB file, awkward names, an empty file and an empty directory.
fixture() { # fixture [POD]
    pod "${1:-client}" '
        set -e
        f=/data/fixture
        rm -rf "$f" && mkdir -p "$f/nested/deeper" "$f/with space" "$f/empty-dir"
        : >"$f/empty"
        echo "hello from rcp" >"$f/message.txt"
        head -c 65537 /dev/urandom >"$f/just past 64k.bin"
        head -c 262144 /dev/urandom >"$f/nested/exactly 256k.bin"
        head -c 262145 /dev/urandom >"$f/nested/256k+1.bin"
        head -c 4194305 /dev/urandom >"$f/nested/deeper/4m+1.bin"
        head -c 17000000 /dev/urandom >"$f/17m.bin"
        echo plus >"$f/with space/a+b.txt"
        echo pct >"$f/with space/100% done.txt"
        echo hash >"$f/with space/#hash.txt"
        echo unicode >"$f/nested/naïve café ☕.txt"
        echo long >"$f/nested/$(printf "l%.0s" $(seq 1 200))"
    '
}

fleet() {
    local nodes=node-0.node,node-1.node,node-2.node n ok=1
    pod client 'rm -rf /data/back-fleet /tmp/cat-fleet*'
    for n in 0 1 2; do pod "node-$n" 'rm -f /tmp/rcp-calls'; done
    run "fleet: seed the source" client rcp -catalog /tmp/cat-fleet-seed copy -noId /data/fixture s3://interop/src || return 1
    run "fleet: copy over $nodes" client rcp -catalog /tmp/cat-fleet copy -nodes $nodes s3://interop/src s3://interop/dst || return 1
    # the claim is a fleet copy, so every worker must have done some of it
    for n in 0 1 2; do
        local b
        b=$(pod "node-$n" 'grep -c " copybatch" /tmp/rcp-calls 2>/dev/null || echo 0')
        echo "fleet: node-$n ran $b batch(es)"
        [ "${b:-0}" -ge 1 ] || ok=0
    done
    [ $ok = 1 ] || { echo "fleet: a worker ran nothing, so this was not spread"; return 1; }
    run "fleet: verify" client rcp -catalog /tmp/cat-fleet-v verify -noattrs s3://interop/src s3://interop/dst || return 1
    run "fleet: read back" client rcp -catalog /tmp/cat-fleet-b copy -noId s3://interop/dst /data/back-fleet || return 1
    same client /data/fixture client /data/back-fleet
}

relay() {
    local via=-via\ ssh://hop-a
    pod client 'rm -rf /data/back-relay'
    for p in hop-a hop-b; do pod "$p" 'rm -f /tmp/rcp-calls; rm -rf /data/tree'; done
    # the control: the client itself cannot reach hop-b, so a pass below went through hop-a
    refused "relay: the client's own dial to hop-b" client rcp scan -noId ssh://hop-b/data || return 1
    run "relay: copy through hop-a" client rcp -catalog /tmp/cat-relay copy -noId -parallel 8 /data/fixture ssh://hop-b/data/tree $via || return 1
    run "relay: verify through hop-a" client rcp -catalog /tmp/cat-relay-v verify -noattrs /data/fixture ssh://hop-b/data/tree $via || return 1
    same client /data/fixture hop-b /data/tree || return 1
    run "relay: read back through hop-a" client rcp -catalog /tmp/cat-relay-b copy -noId ssh://hop-b/data/tree /data/back-relay $via || return 1
    same client /data/fixture client /data/back-relay || return 1
    # and the serves ran where the chain says: hop-a for the client, hop-b for hop-a
    echo "relay: serves on hop-a: $(pod hop-a 'grep -c " serve" /tmp/rcp-calls'), on hop-b: $(pod hop-b 'grep -c " serve" /tmp/rcp-calls')"
}

mtls() {
    local url=rcps://rcps:7712/data/tree
    pod client 'rm -rf /data/back-mtls'
    run "mtls: copy with a client certificate" client rcp -catalog /tmp/cat-mtls copy -noId /data/fixture $url $TLS || return 1
    run "mtls: verify" client rcp -catalog /tmp/cat-mtls-v verify -noattrs /data/fixture $url $TLS || return 1
    run "mtls: read back" client rcp -catalog /tmp/cat-mtls-b copy -noId $url /data/back-mtls $TLS || return 1
    same client /data/fixture client /data/back-mtls || return 1
    refused "mtls: no client certificate" client rcp scan -noId $url -tls.ca /etc/rcp-tls/ca.crt || return 1
    refused "mtls: a certificate from another CA" client rcp scan -noId $url \
        -tls.ca /etc/rcp-tls/ca.crt -tls.cert /etc/rcp-tls/rogue.crt -tls.key /etc/rcp-tls/rogue.key || return 1
    refused "mtls: a serve this client does not trust" client rcp scan -noId $url \
        -tls.ca /etc/rcp-tls/rogue-ca.crt -tls.cert /etc/rcp-tls/client.crt -tls.key /etc/rcp-tls/client.key || return 1
    # the refusals did not take the serve down
    run "mtls: still serving" client rcp scan -noId $url $TLS
}

krb() {
    local r=/opt/rcp-interop/rcp-dyn url=nfs://krb/export flavor
    fixture krbclient || { echo "krb: could not build the fixture in the Kerberos client"; return 1; }
    pod krbclient 'rm -rf /data/back-* /tmp/cat-krb*'
    # a fresh ticket each run: tickets from a realm the krb pod has since recreated hold keys
    # its new KDC never issued, and fail as "Decrypt integrity check failed"
    pod krbclient 'kdestroy -q 2>/dev/null; kinit rcpuser </etc/rcp-krb-secret/user >/dev/null' ||
        { echo "krb: kinit failed"; return 1; }
    # the controls: the export takes nothing but Kerberos, and Kerberos takes a ticket
    refused "krb: AUTH_SYS against an export that requires Kerberos" krbclient "$r scan -noId $url" || return 1
    refused "krb: krb5 without a ticket" krbclient "KRB5CCNAME=FILE:/nonexistent $r scan -noId $url -nfs.sec krb5" || return 1
    for flavor in krb5 krb5i krb5p; do
        run "krb: copy under $flavor" krbclient "$r -catalog /tmp/cat-krb-$flavor copy -noId /data/fixture $url/$flavor -nfs.sec $flavor" || return 1
        run "krb: verify under $flavor" krbclient "$r -catalog /tmp/cat-krb-$flavor-v verify -noattrs /data/fixture $url/$flavor -nfs.sec $flavor" || return 1
        same krbclient /data/fixture krb "/export/$flavor" || return 1
        run "krb: read back under $flavor" krbclient "$r -catalog /tmp/cat-krb-$flavor-b copy -noId $url/$flavor /data/back-$flavor -nfs.sec $flavor" || return 1
        same krbclient /data/fixture krbclient "/data/back-$flavor" || return 1
    done
    run "krb: copy under krb5p over v4.0" krbclient "$r -catalog /tmp/cat-krb-v4 copy -noId /data/fixture $url/krb5p-v4 -nfs.sec krb5p -nfs.vers 4" || return 1
    run "krb: verify under krb5p over v4.0" krbclient "$r -catalog /tmp/cat-krb-v4-v verify -noattrs /data/fixture $url/krb5p-v4 -nfs.sec krb5p -nfs.vers 4" || return 1
    same krbclient /data/fixture krb /export/krb5p-v4
}

wanted=("$@")
[ ${#wanted[@]} -eq 0 ] && wanted=(fleet relay mtls krb)
fixture || { echo "could not build the fixture in the client pod"; exit 1; }
declare -A result
for t in "${wanted[@]}"; do
    echo "== $t"
    if "$t"; then result[$t]=PASS; else result[$t]=FAIL; fi
done
echo "== summary"
rc=0
for t in "${wanted[@]}"; do
    echo "$t: ${result[$t]}"
    [ "${result[$t]}" = PASS ] || rc=1
done
exit $rc
