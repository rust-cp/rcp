#!/usr/bin/env bash
# Interop: run rcp against real servers, one container per protocol.
#
# The contract suite runs every endpoint against stand-ins written in this repository.
# A stand-in only behaves the way its author thought the protocol works, and twice that
# was not how the real server behaved: OpenSSH's sftp-server ended the session on a
# 256 KiB WRITE, and Apache answered a collection named without its slash with a 301.
# This script checks every endpoint it can against the software people actually run.
#
# Usage: scripts/interop.sh [ENDPOINT...]      (default: every endpoint)
#   RCP=path/to/rcp   the binary under test (default: target/release/rcp)
#   KEEP=1            leave the containers running afterward
#
# Each endpoint does the same round trip with the same fixture: copy the fixture to the
# server, verify it there, copy it back to a fresh local directory, and compare the result
# with the fixture byte for byte (diff -r). Where the server's own storage is visible, the
# files as the server stored them are compared too, so a pair of symmetric bugs in rcp
# cannot cancel out.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RCP=${RCP:-$ROOT/target/release/rcp}
RCP=$(realpath "$RCP")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rcp-interop.XXXXXX")
PREFIX=rcp-interop
ALL=(s3 oci https dav sftp ssh smb nfs hdfs)
RESULTS=()

log() { printf '\n== %s\n' "$*"; }
die() { printf 'interop: %s\n' "$*" >&2; exit 2; }

cleanup() {
    if [ "${KEEP:-0}" != 1 ]; then
        docker ps -aq --filter "name=^$PREFIX-" | xargs -r docker rm -f >/dev/null 2>&1
        rm -rf "$WORK"
    else
        echo "KEEP=1: containers and $WORK left in place"
    fi
}
trap cleanup EXIT

[ -x "$RCP" ] || die "no rcp binary at $RCP (cargo build --release --features rustls)"
command -v docker >/dev/null || die "docker is required"

# --- the fixture ---------------------------------------------------------------------------
# Names that have broken a protocol encoder before (space, +, %, #, a non-ASCII name, a
# 200-character name) and sizes either side of the boundaries that have broken a transport
# before (64 KiB, the 256 KiB SFTP message limit, 1 MiB blocks, and a multi-block file).
fixture() {
    local f=$WORK/fixture
    mkdir -p "$f/nested/deeper" "$f/with space" "$f/empty-dir"
    : >"$f/empty"
    printf 'hello\n' >"$f/message.txt"
    head -c 65537 /dev/urandom >"$f/just past 64k.bin"
    head -c 262144 /dev/urandom >"$f/nested/exactly 256k.bin"
    head -c 262145 /dev/urandom >"$f/nested/256k+1.bin"
    head -c $((4 * 1048576 + 1)) /dev/urandom >"$f/nested/deeper/4m+1.bin"
    head -c $((17 * 1048576)) /dev/urandom >"$f/17m.bin"
    printf 'plus\n' >"$f/with space/a+b.txt"
    printf 'percent\n' >"$f/with space/100% done.txt"
    printf 'hash\n' >"$f/with space/#hash.txt"
    printf 'non-ascii\n' >"$f/nested/naïve café ☕.txt"
    printf 'long\n' >"$f/nested/$(printf 'l%.0s' $(seq 1 200))"
    echo "$f"
}

# --- the round trip ------------------------------------------------------------------------
# roundtrip NAME URL [rcp options...]
# Copies the fixture to URL, verifies it there, copies it back and diffs the result.
roundtrip() {
    local name=$1 url=$2
    shift 2
    local back=$WORK/back-$name cat=$WORK/catalog-$name
    rm -rf "$back"
    local ok=1
    run "$name copy up" "$RCP" -catalog "$cat" copy "$@" "$FIXTURE" "$url" || ok=0
    [ $ok = 1 ] && { run "$name verify" "$RCP" -catalog "$cat" verify -noattrs "$@" "$FIXTURE" "$url" || ok=0; }
    [ $ok = 1 ] && { run "$name copy back" "$RCP" -catalog "$cat" copy "$@" "$url" "$back" || ok=0; }
    if [ $ok = 1 ]; then
        if diff -r "$FIXTURE" "$back" >"$WORK/diff-$name" 2>&1; then
            echo "diff -r: identical"
        else
            echo "diff -r: DIFFERENT"
            head -20 "$WORK/diff-$name"
            ok=0
        fi
    fi
    return $((1 - ok))
}

# run LABEL CMD... -- print the command's tail, return its status
run() {
    local label=$1
    shift
    local out rc
    out=$("$@" 2>&1)
    rc=$?
    printf '%s: rc=%s\n' "$label" "$rc"
    printf '%s\n' "$out" | tail -4 | sed 's/^/    /'
    return $rc
}

# server_dir NAME -- compare what the server stored on its own disk with the fixture
server_disk() { # server_disk NAME DIR [REFERENCE] -- the server's own storage against the fixture
    local name=$1 dir=$2 ref=${3:-$FIXTURE}
    if diff -r "$ref" "$dir" >"$WORK/disk-$name" 2>&1; then
        echo "server disk: identical to the ${3:+changed }fixture"
    else
        echo "server disk: DIFFERENT"
        head -20 "$WORK/disk-$name"
        return 1
    fi
}

# ready LABEL CMD... -- until CMD succeeds, up to 90 s.
#
# A TCP connect is NOT readiness here: docker's port proxy accepts on the host port the
# moment the container starts and resets the connection if the server behind it is not
# listening yet, which failed the first HTTP run with "Connection reset by peer". So every
# server is probed in its own protocol.
ready() {
    local label=$1 i
    shift
    for i in $(seq 1 180); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    echo "$label: not ready after 90 s"
    return 1
}
http_ok() { curl -fsS --noproxy '*' -o /dev/null "$1"; }

start() { # start NAME docker-run-args...
    local name=$PREFIX-$1
    shift
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" "$@" >/dev/null || return 1
}

# --- the endpoints -------------------------------------------------------------------------

# S3: versitygw serving a POSIX directory, so the objects are plain files on its disk.
ep_s3() {
    local data=$WORK/s3-data port=17070
    mkdir -p "$data/interop"
    start s3 -p 127.0.0.1:$port:7070 -v "$data:/data" \
        versity/versitygw:latest@sha256:30292fc2eeacc67a36993b01f7a7a5e3361a19cced0e80c1d71cfa2a4b0a2499 --access interop --secret interop-secret-key posix /data || return 1
    ready s3 curl -sS --noproxy '*' -o /dev/null "http://127.0.0.1:$port/" || return 1
    AWS_ACCESS_KEY_ID=interop AWS_SECRET_ACCESS_KEY=interop-secret-key AWS_REGION=us-east-1 \
        roundtrip s3 s3://interop/tree -s3.endpoint http://127.0.0.1:$port || return 1
    server_disk s3 "$data/interop/tree"
}

# OCI: the CNCF distribution registry. The fixture is a real image (alpine, as `docker save`
# writes it), not a file tree, and the proof is the other client: after rcp pushes the image,
# docker itself pulls it back from the registry and runs it.
ep_oci() {
    local port=15000 layout=$WORK/oci-layout back=$WORK/oci-back ref
    local fixture=alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
    ref=127.0.0.1:$port/interop/alpine:3
    start oci -p 127.0.0.1:$port:5000 registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 || return 1
    ready oci http_ok "http://127.0.0.1:$port/v2/" || return 1
    mkdir -p "$layout"
    docker pull -q "$fixture" >/dev/null || return 1
    # docker save needs a tag; set it from the verified digest rather than a cached tag.
    docker tag "$fixture" alpine:3 || return 1
    # with the containerd image store a plain save keeps the multi-arch index but only this
    # platform's blobs, a layout no registry can accept; -platform saves one complete image.
    # Docker before 28 has no -platform and its classic store saves one platform anyway.
    docker save --platform linux/amd64 -o "$WORK/alpine.tar" alpine:3 2>/dev/null ||
        docker save -o "$WORK/alpine.tar" alpine:3 || return 1
    tar -x -C "$layout" -f "$WORK/alpine.tar" || return 1
    # docker save writes an OCI layout plus its own legacy manifest.json and repositories;
    # rcp refuses to push files a registry cannot hold, so only the layout goes up
    rm -f "$layout/manifest.json" "$layout/repositories"
    local cat=$WORK/catalog-oci
    run "oci push" "$RCP" -catalog "$cat" copy -oci.insecure "$layout" "oci://$ref" || return 1
    # the independent client: docker pulls what rcp pushed, and it runs
    docker rmi -f "$ref" >/dev/null 2>&1
    run "docker pull" docker pull -q "$ref" || return 1
    run "docker run" docker run --rm "$ref" sh -c 'echo pushed by rcp, pulled by docker' || return 1
    docker rmi -f "$ref" >/dev/null 2>&1
    run "oci pull" "$RCP" -catalog "$cat" copy -oci.insecure "oci://$ref" "$back" || return 1
    # the tag names the same manifest it named in the source layout
    local want got
    want=$(tagged_manifest "$layout" 3) got=$(tagged_manifest "$back" 3)
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "tag 3: source $want, registry $got"; return 1; }
    echo "tag 3: $got in the layout, the registry and the pull"
    local bad=0 f
    for f in "$back"/blobs/sha256/*; do
        [ "$(sha256sum <"$f" | cut -d' ' -f1)" = "$(basename "$f")" ] || { echo "blob $f does not match its name"; bad=1; }
    done
    [ $bad = 0 ] && echo "blobs: $(ls "$back/blobs/sha256" | wc -l) pulled, every one matches its digest"
    # rcp's own layout is what the registry holds, exactly. (A docker-saved layout is not:
    # its index.json carries annotations and an untagged attestation manifest that a
    # registry's tags cannot express, so verifying it against the registry reports them.)
    run "oci verify" "$RCP" -catalog "$cat" verify -nomods -oci.insecure "$back" "oci://$ref" || return 1
    return $bad
}

# The digest of the manifest a layout's index.json tags NAME.
tagged_manifest() { # tagged_manifest LAYOUT NAME
    python3 -c 'import json,sys
for m in json.load(open(sys.argv[1]+"/index.json"))["manifests"]:
    if m.get("annotations",{}).get("org.opencontainers.image.ref.name")==sys.argv[2]: print(m["digest"])' "$1" "$2"
}

# The shared httpd config for the HTTP and WebDAV servers.
httpd_conf() { # httpd_conf FILE EXTRA-LINES
    local cid
    cid=$(docker create httpd:2.4@sha256:03f858efb82c25cb0f9962946615cdcdaf26927cb971722149b563197cfd0fdd) || return 1
    docker cp "$cid:/usr/local/apache2/conf/httpd.conf" "$1" >/dev/null && docker rm -f "$cid" >/dev/null
    printf '%s\n' "$2" >>"$1"
}

# HTTP sources: Apache serving the fixture with mod_autoindex. Read-only, so the round trip
# is one way: rcp reads the tree through Apache's listing and Range requests.
ep_https() {
    local port=18080 conf=$WORK/httpd-plain.conf back=$WORK/back-https cat=$WORK/catalog-https
    httpd_conf "$conf" 'IndexOptions FancyIndexing HTMLTable NameWidth=*' || return 1
    start https -p 127.0.0.1:$port:80 -v "$FIXTURE:/usr/local/apache2/htdocs:ro" \
        -v "$conf:/usr/local/apache2/conf/httpd.conf:ro" httpd:2.4@sha256:03f858efb82c25cb0f9962946615cdcdaf26927cb971722149b563197cfd0fdd || return 1
    ready https http_ok "http://127.0.0.1:$port/message.txt" || return 1
    rm -rf "$back"
    run "https copy" "$RCP" -catalog "$cat" copy -http.index '' "http://127.0.0.1:$port/" "$back" || return 1
    # directories carry no files over HTTP, so an empty one cannot be seen in a listing
    if diff -r -x empty-dir "$FIXTURE" "$back" >"$WORK/diff-https" 2>&1; then
        echo "diff -r: identical (empty directories are invisible over HTTP)"
    else
        echo "diff -r: DIFFERENT"
        head -20 "$WORK/diff-https"
        return 1
    fi
}

# WebDAV: Apache mod_dav + mod_dav_fs, the server the 301-on-a-collection defect came from.
ep_dav() {
    local port=18081 conf=$WORK/httpd-dav.conf data=$WORK/dav-data
    mkdir -p "$data/tree" "$WORK/dav-lock" && chmod 777 "$data" "$data/tree" "$WORK/dav-lock"
    httpd_conf "$conf" 'LoadModule dav_module modules/mod_dav.so
LoadModule dav_fs_module modules/mod_dav_fs.so
LoadModule dav_lock_module modules/mod_dav_lock.so
DavLockDB /var/lock/dav/lockdb
Alias /dav /dav-data
<Directory /dav-data>
    Dav On
    Options Indexes
    Require all granted
</Directory>' || return 1
    start dav -p 127.0.0.1:$port:80 -v "$data:/dav-data" -v "$WORK/dav-lock:/var/lock/dav" \
        -v "$conf:/usr/local/apache2/conf/httpd.conf:ro" httpd:2.4@sha256:03f858efb82c25cb0f9962946615cdcdaf26927cb971722149b563197cfd0fdd || return 1
    ready dav http_ok "http://127.0.0.1:$port/dav/" || return 1
    roundtrip dav "dav://127.0.0.1:$port/dav/tree" || return 1
    server_disk dav "$data/tree"
}

# SFTP: OpenSSH's own sftp-server, reached through the system ssh client.
ssh_server() { # ssh_server NAME PORT [DOCKER-ARGS...] -- an OpenSSH server that trusts a fresh key
    local name=$1 port=$2 key=$WORK/id_ed25519
    shift 2
    [ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -f "$key" || return 1
    start "$name" -p 127.0.0.1:$port:2222 -e PUID=0 -e PGID=0 -e USER_NAME=interop \
        -e PUBLIC_KEY="$(cat "$key.pub")" -v "$WORK/$name-data:/data" "$@" \
        ghcr.io/linuxserver/openssh-server:latest@sha256:946fa26105e0ec212fdf821b9ddc59aab65f2c2d07c02b25ff0f5001fc332ff0 || return 1
    ready "$name" ssh -p "$port" -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR interop@127.0.0.1 true || return 1
    cat >"$WORK/ssh_config-$name" <<EOF
Host interop-$name
    HostName 127.0.0.1
    Port $port
    User interop
    IdentityFile $key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
EOF
    printf '#!/bin/sh\nexec ssh -F %s "$@"\n' "$WORK/ssh_config-$name" >"$WORK/ssh-$name"
    chmod +x "$WORK/ssh-$name"
}

ep_sftp() {
    mkdir -p "$WORK/sftp-data/tree" && chmod 777 "$WORK/sftp-data" "$WORK/sftp-data/tree"
    ssh_server sftp 12222 || return 1
    RCP_SSH=$WORK/ssh-sftp roundtrip sftp "sftp://interop-sftp/data/tree" || return 1
    server_disk sftp "$WORK/sftp-data/tree"
}

# ssh:// runs `rcp serve` on the far side, so the server needs an rcp that runs there: the
# release's static binary (RCP_SERVE, or RCP itself when it is static), dropped into the same
# OpenSSH server. A dynamically linked glibc build cannot run on that image's musl base.
# Plain, then -compress and -delta: a second copy over a changed file sends it as a patch.
ep_ssh() {
    local serve=${RCP_SERVE:-$RCP} data=$WORK/ssh-data
    file -L "$serve" | grep -q 'static' || {
        echo "ssh: $serve is dynamically linked; set RCP_SERVE to a -C target-feature=+crt-static build"
        return 1
    }
    mkdir -p "$data" && chmod 777 "$data"
    ssh_server ssh 12223 -v "$serve:/usr/local/bin/rcp:ro" || return 1
    export RCP_SSH=$WORK/ssh-ssh
    roundtrip ssh "ssh://interop-ssh/data/tree" -rcp.remote /usr/local/bin/rcp || return 1
    server_disk ssh "$data/tree" || return 1
    roundtrip ssh-compress "ssh://interop-ssh/data/zstd" -rcp.remote /usr/local/bin/rcp \
        -compress.codec zstd || return 1
    server_disk ssh-compress "$data/zstd" || return 1
    # change the middle of the largest file, then send only what changed
    local src=$WORK/ssh-delta-src cat=$WORK/catalog-ssh-delta
    cp -a "$FIXTURE" "$src" && printf 'changed by the delta arm' |
        dd of="$src/17m.bin" bs=1 seek=8000000 conv=notrunc status=none || return 1
    run "ssh delta" "$RCP" -catalog "$cat" copy -rcp.remote /usr/local/bin/rcp -delta \
        "$src" "ssh://interop-ssh/data/tree" || return 1
    server_disk ssh-delta "$data/tree" "$src"
}

# Containers that install their server at start need the host's CA bundle when the host
# reaches the package mirror through an intercepting proxy (INTEROP_CA_BUNDLE, or the
# sandbox's own bundle when it exists).
ca_mount() {
    local ca=${INTEROP_CA_BUNDLE:-}
    [ -z "$ca" ] && [ -f /root/.ccr/ca-bundle.crt ] && ca=/root/.ccr/ca-bundle.crt
    [ -n "$ca" ] && printf -- '-v\n%s:/etc/ssl/certs/ca-certificates.crt:ro\n' "$ca"
}

# wait_log NAME PATTERN -- until the container logs PATTERN, up to 180 s
wait_log() {
    local i
    for i in $(seq 1 180); do
        docker logs "$PREFIX-$1" 2>&1 | grep -q "$2" && return 0
        docker ps -q --filter "name=^$PREFIX-$1\$" | grep -q . || {
            echo "$1: the container stopped: $(docker inspect -f 'exit {{.State.ExitCode}} {{.State.Error}}' "$PREFIX-$1" 2>&1)"
            docker logs --tail 60 "$PREFIX-$1" 2>&1
            return 1
        }
        sleep 1
    done
    echo "$1: no '$2' after 180 s"
    docker logs --tail 20 "$PREFIX-$1" 2>&1
    return 1
}

# SMB: Samba, installed from Alpine at container start. Run twice, the second time with
# -smb.sign, since the one signing defect found so far (a KDF one byte short of SP800-108)
# was invisible to a stand-in that shared the same mistake.
ep_smb() {
    local port=11445 data=$WORK/smb-data
    mkdir -p "$data/tree" && chmod 777 "$data" "$data/tree"
    local -a ca
    mapfile -t ca < <(ca_mount)
    start smb -p 127.0.0.1:$port:445 -v "$data:/share" "${ca[@]}" alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 sh -c '
        apk add --no-cache samba >/dev/null || exit 1
        adduser -D -H interop && printf "interop-pw\ninterop-pw\n" | smbpasswd -s -a interop
        cat >/etc/samba/smb.conf <<EOF
[global]
    server min protocol = SMB2_10
    map to guest = never
    force user = root
[interop]
    path = /share
    read only = no
    valid users = interop
EOF
        echo samba-ready
        exec smbd --foreground --no-process-group --debug-stdout' || return 1
    wait_log smb samba-ready || return 1
    export RCP_SMB_USER=interop RCP_SMB_PASSWORD=interop-pw
    ready smb "$RCP" scan -noId "smb://127.0.0.1:$port/interop" || return 1
    roundtrip smb "smb://127.0.0.1:$port/interop/tree" || return 1
    server_disk smb "$data/tree" || return 1
    roundtrip smb-signed "smb://127.0.0.1:$port/interop/signed" -smb.sign || return 1
    server_disk smb-signed "$data/signed"
}

# NFS: NFS-Ganesha, the userspace server (a container cannot run the kernel's nfsd without
# the host's module; CI runs the kernel server on the runner itself, see ep_nfs_kernel).
# v3 and v4.0 both, on fixed ports so no portmapper is needed.
ep_nfs() {
    # one destination per version, made before the server starts: an NFS URL mounts its
    # whole path, so the root must exist (unlike every other endpoint), and nothing may
    # change the export behind Ganesha's back once it runs -- its cache keeps handles to
    # what the host removed, and a later write lands in an unlinked inode
    local data=$WORK/nfs-data
    mkdir -p "$data/tree3" "$data/tree4" && chmod 777 "$data" "$data/tree3" "$data/tree4"
    local -a ca
    mapfile -t ca < <(ca_mount)
    start nfs --privileged -p 127.0.0.1:12049:2049 -p 127.0.0.1:12048:20048 \
        -v "$data:/export" "${ca[@]}" debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce sh -c '
        apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
            nfs-ganesha nfs-ganesha-vfs rpcbind >/dev/null || exit 1
        cat >/etc/ganesha/ganesha.conf <<EOF
NFS_CORE_PARAM { NFS_Port = 2049; MNT_Port = 20048; Enable_NLM = false; Enable_RQUOTA = false; Protocols = 3, 4;
    Enable_UDP = false; allow_set_io_flusher_fail = true; }
NFSV4 { Graceless = true; }
EXPORT {
    Export_Id = 1; Path = /export; Pseudo = /export;
    Access_Type = RW; Squash = No_Root_Squash; SecType = sys;
    Protocols = 3, 4; Transports = TCP;
    FSAL { Name = VFS; }
}
EOF
        mkdir -p /var/run/ganesha /var/lib/nfs/ganesha /run/rpcbind && rpcbind -w || exit 1
        echo ganesha-ready
        exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf' || return 1
    wait_log nfs ganesha-ready || return 1
    export RCP_NFS_PORT=12049 RCP_MOUNT_PORT=12048
    ready nfs "$RCP" scan -noId "nfs://127.0.0.1/export" || return 1
    roundtrip nfs3 "nfs://127.0.0.1/export/tree3" || return 1
    server_disk nfs3 "$data/tree3" || return 1
    roundtrip nfs4 "nfs://127.0.0.1/export/tree4" -nfs.vers 4 || return 1
    server_disk nfs4 "$data/tree4"
}

# HDFS: one Apache Hadoop node running a namenode and a datanode. WebHDFS writes follow the
# namenode's redirect to a datanode by the name it registered, so the node shares the host's
# network and registers as 127.0.0.1. Blocks are not files, so instead of reading the
# server's disk, Hadoop's own client reads back what rcp wrote.
ep_hdfs() {
    # the image sets neither HADOOP_HOME nor a writable conf or log dir for its user, and its
    # entrypoint wrapper edits the config from the environment; bypass it and use /tmp
    start hdfs --network host --entrypoint /bin/bash apache/hadoop:3.4.1@sha256:69ffa97339aff768c4e6120c3fb27aa04c121402b1c8158408a5fb5be586a30e -c '
        export HADOOP_CONF_DIR=/tmp/hadoop-conf HADOOP_LOG_DIR=/tmp/hadoop-logs
        cp -r /opt/hadoop/etc/hadoop $HADOOP_CONF_DIR && mkdir -p $HADOOP_LOG_DIR || exit 1
        conf=$HADOOP_CONF_DIR
        cat >$conf/core-site.xml <<EOF
<configuration>
<property><name>fs.defaultFS</name><value>hdfs://127.0.0.1:8020</value></property>
</configuration>
EOF
        cat >$conf/hdfs-site.xml <<EOF
<configuration>
<property><name>dfs.replication</name><value>1</value></property>
<property><name>dfs.permissions.enabled</name><value>false</value></property>
<property><name>dfs.datanode.hostname</name><value>127.0.0.1</value></property>
<property><name>dfs.namenode.datanode.registration.ip-hostname-check</name><value>false</value></property>
</configuration>
EOF
        hdfs namenode -format -force -nonInteractive >/tmp/format.log 2>&1 || { cat /tmp/format.log; exit 1; }
        hdfs --daemon start namenode && hdfs --daemon start datanode || exit 1
        hdfs dfsadmin -safemode wait || exit 1
        hdfs dfs -mkdir -p /interop || exit 1
        echo hdfs-ready
        exec tail -F $HADOOP_LOG_DIR/hadoop-*-datanode-*.log' || return 1
    wait_log hdfs hdfs-ready || return 1
    ready hdfs "$RCP" scan -noId "hdfs://127.0.0.1:9870/interop" || return 1
    roundtrip hdfs "hdfs://127.0.0.1:9870/interop/tree" || return 1
    local f bad=0
    for f in "nested/deeper/4m+1.bin" "17m.bin" "nested/naïve café ☕.txt" "with space/100% done.txt"; do
        docker exec -e HADOOP_CONF_DIR=/tmp/hadoop-conf "$PREFIX-hdfs" hdfs dfs -cat "/interop/tree/$f" 2>/dev/null | cmp -s - "$FIXTURE/$f" ||
            { echo "hadoop reads $f differently"; bad=1; }
    done
    [ $bad = 0 ] && echo "hadoop's own client reads back what rcp wrote"
    return $bad
}

# --- main ----------------------------------------------------------------------------------
FIXTURE=$(fixture)
echo "rcp: $("$RCP" version 2>&1 | head -1)"
echo "fixture: $(find "$FIXTURE" -type f | wc -l) files, $(du -sh "$FIXTURE" | cut -f1)"

wanted=("$@")
[ ${#wanted[@]} -eq 0 ] && wanted=("${ALL[@]}")
for ep in "${wanted[@]}"; do
    declare -F "ep_$ep" >/dev/null || { RESULTS+=("$ep: SKIP (no harness yet)"); continue; }
    log "$ep"
    if "ep_$ep"; then RESULTS+=("$ep: PASS"); else RESULTS+=("$ep: FAIL"); fi
done

log summary
printf '%s\n' "${RESULTS[@]}"
printf '%s\n' "${RESULTS[@]}" | grep -q ': FAIL' && exit 1
exit 0
