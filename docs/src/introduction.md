# rcp

A data mover for local paths, NFS exports, S3 buckets and HDFS, distributed under the
Apache-2.0 license. The default build uses audited open-source cryptography crates
(RustCrypto and the official BLAKE3) and otherwise only its own code; the release
binary includes TLS support and uses the host's GNU libc. There is no bundled interpreter
or telemetry.

Start with [building and runtime requirements](building.md) and
[release installation and verification](releases.md). The
[Rust API reference](api/rcp/index.html) is published beside this book at
<https://rust-cp.github.io/rcp/>.

```sh
rcp copy     [copy options] [-newid ID | -noId] SOURCE DESTINATION
rcp resume   [copy options] -id ID
rcp sync     [copy options] -id ID [-snap PATH]
rcp sync dry-run -id ID [-target] [-l | -q]               # what sync would do
rcp isync    [copy options] SOURCE DESTINATION            # incremental, no catalog
rcp isync estimate SOURCE DESTINATION | -id ID
rcp verify   [verify options] SOURCE DESTINATION
rcp scan     [scan options] [-newid ID] SOURCE            # or: rcp SOURCE
rcp scan     -id ID [scan options]                        # reports from a saved scan
rcp estimate [-sample BYTES] [-gbit N] [-target DIR -t DURATION] SOURCE
rcp estimate -id SCANID [-gbit N]
rcp delete   [-parallel N] [-force] [-removetopdir] PATH
rcp chown    [-v] (-user U [-group G] | -reference PATH | UID[:GID]) [-user-from U] PATH
rcp chmod    [-v] (-mode MODE | -reference PATH | MODE) PATH
rcp show     [-all] | HOST... [-v]                        # mounts, or a server's exports
rcp indexlist | indexdelete (-id ID | -match GLOB) | logdump [ID]
rcp diag     (-cat | -mkdir | -rmdir | -rmrf) PATH | -rmid ID     # file utilities
rcp diag     nio | find | change | indexdiag | rebuild | dump     # see below
rcp help [filters | info] | version
```

Endpoints are directories, written as `/path` or `file:///path`; NFS exports written as
`host:/export`, `host:/export:/subdir`, `nfs://host/export` or, through several of the
server's addresses at once, `ip1,ip2:/export`; buckets written as `s3://bucket/prefix`; or
HDFS paths written as `hdfs://namenode:port/path`. A mounted NFS or SMB export is a
directory like any other; an export named directly is reached with the built-in NFSv3
client, which needs no mount and no root and keeps many requests in flight per connection; a
bucket with the built-in S3 client; an HDFS path over WebHDFS; a WebDAV collection. Any endpoint can be the
source or the destination of any command, with the exceptions a transport's own model
forces: a registry stores blobs and manifests rather than a filesystem, so `oci://` takes
no symlink, no hard link and no `chmod` or `chown` destination, and it cannot be a
`-nodes` destination because only the coordinating process publishes; a `tar://` stream is
written once through and cannot be modified in place. Each of those refuses by name rather
than silently doing nothing.
