# Remote hosts through ssh, and without it

`ssh://[user@]host[:port]/path` is a directory on a host that has rcp installed. The
endpoint opens `ssh host rcp serve` and everything a local path can do happens there: the
listing, the reads and writes, hard links, symlinks, attributes, all through the same
`Tree` port the other adapters implement. The connection is OpenSSH's, so its keys, agent,
`ProxyJump`, `ControlMaster` and host-key policy apply unchanged; `RCP_SSH` names another
command in ssh's place (the contract suite uses a script that runs `rcp serve` in place),
and `-rcp.remote PATH` names the rcp on the far side when it is not on `PATH`. One ssh
session per worker: `-parallel 8` opens eight, which is cheap under `ControlMaster`.

`-compress` compresses the data payloads on the stream, and `-compress.codec` chooses how:
`lz4` (the default, fast), `deflate` or `zstd` -- the two slower ones land within half a
percent of each other and both send about 1.85x fewer bytes than lz4 on log-shaped text.
The codec is negotiated in HELLO, and the serve must answer with the one asked for. A serve
that cannot is refused rather than followed: two ends disagreeing about how to read a
payload is a corruption, and a quiet fallback would hand the caller a stream it did not ask
for (see **Wire compression codecs** above for the versions). Naming a codec implies
`-compress`.

**Pick `zstd` when the other end already speaks zstd**, which is what it buys: the frames
are ordinary zstd frames that `zstd -d` reads, and the decoder reads anything the reference
writes. It is a complete pure-Rust implementation -- Huffman-coded literals, FSE-coded
sequences built from each block's own statistics, repeat offsets, lazy matching. On ratio
it is a coin flip with `deflate` on this corpus, so there is no reason to switch for that
alone.

`-compress.level N` sets how hard deflate works, 1..9 as zlib means it, default 6. Unlike
the codec it needs no agreement -- a DEFLATE stream carries its own code tables, so the
decoder never has to know what the encoder was told -- so it rides in HELLO purely as a
request for effort and reaches the far side's encoder as well as this one. Level 6 is
byte-for-byte the encoder that shipped before the knob existed, which is asserted rather
than intended. Neither lz4 nor this zstd encoder has a level, so naming one without
`-compress.codec deflate` is REFUSED rather than quietly ignored -- a run that exits 0
having done nothing with the number is the failure, not the refusal.

Inside the session rcp speaks its own framed protocol, one request per sequence number,
answered in order. A copy streams a file's content as data and hole segments, so a sparse
file crosses the wire as its data plus lengths and lands sparse in either direction, and
a writer keeps sixteen writes in flight; a listing crosses in batches, so a tree of any
size fits the frame limit; and the `Read` path that `verify` takes keeps eight megabyte
reads in flight ahead of its consumer, so a round trip is paid once per window rather
than once per block (a seek discards the window). The protocol mirrors
the port rather than a shell: no quoting, no `tar`, no `cpio`, and an error on the far
side comes back as the same `io::Error` kind it was there.

The trust model is ssh's, and it is worth saying what that does and does not give. The
serve runs as the user ssh logged in as, on any absolute directory the client names, and
refuses a relative path that would step outside it (`..`, or an absolute path, is an
error before anything is touched). That is the same standing an interactive login has,
so it is no escalation; it is also no confinement, and a forced-command deployment that
wants one needs a wrapper that fixes the root, the way `rrsync` does for rsync. The
`-rcp.remote` string is passed to the remote login shell as rsync's `--rsync-path` is,
which is what lets it say `-rcp.remote "sudo rcp"`, and which means a path with spaces
or shell characters needs the quoting that shell expects. Numeric uid and gid cross as
numbers and mean whatever they mean on the far host, which is rsync's default too, and
the hard-link and catalog identity of a remote file is its device and inode there,
consistent within one tree and meaningless across two.

`rcp serve` is the far end. It takes no arguments, reads frames on stdin and answers on
stdout, and serves the directory the client names, creating it when the client is a
destination. It is what the delta and compression work rides on: a channel rcp controls at
both ends.

## Without ssh: rcp:// and rcps://

`rcp serve -listen ADDR` holds a socket and speaks the same frames over it;
`rcp://host:port/path` is the endpoint. No child process and no handshake per channel,
which is what `-nodes` and `-via` want across a tunnel something else already
authenticates. An rcp endpoint takes no user (there is nothing to check one against) and
no default port (there is no registered one, and inventing one means a typo dials some
other service).

**What the socket does not inherit is the point.** Over `ssh://`, OpenSSH has
authenticated the peer and started the far side as that user before a frame moves; a
socket inherits nothing. So `-listen` refuses to start without `-allow ROOT` (or
`RCP_ALLOWED_ROOTS`) naming what it may serve, and refuses any address that is not
loopback.

`rcps://host:port/path` is that socket inside TLS, in a build with `--features rustls`. The
serve presents `-tls.cert` with `-tls.key`; the client checks it against `-tls.ca` (the
system bundle by default) and presents its own certificate with the same two options.
**Only `-tls.clientca` lets a serve bind anything but loopback**, and that is deliberate:
a server certificate encrypts the stream and proves who the serve is, while establishing
nothing about who connected, so a serve with a certificate and no client verifier on a
routable address is still an unauthenticated remote filesystem. Naming the authority the
peer's certificate must come from is the thing that changes.

```
serve  $ rcp serve -listen 0.0.0.0:7712 -allow /srv/data \
           -tls.cert serve.crt -tls.key serve.key -tls.clientca ca.crt
client $ rcp copy /local rcps://filer:7712/srv/data \
           -tls.ca ca.crt -tls.cert client.crt -tls.key client.key
```

The four options are `Transport` capabilities: a railed command line may set them, an MCP
call may not, and `rcp mcp` relays the server's choice to every child through
`RCP_TLS_CA`, `RCP_TLS_CERT`, `RCP_TLS_KEY` and `RCP_TLS_CLIENTCA`.

## Relay: -via ssh://hop

`rcp copy -via ssh://bastion oci://registry.internal/app /local` opens the registry on
the bastion and copies from there. `-via` names an `rcp serve` that opens every remote
endpoint of the run on this side's behalf -- a registry, a bucket, a WebDAV server, a
second `rcp serve` -- and this side speaks to it exactly as it would to a directory on that
host. A chain is just an `ssh://` or `rcp://` endpoint behind a `-via`: the hop opens it through
its own transport. `-via` takes either kind of serve. Local endpoints stay local, which
also means a relay is only exercised when the endpoint behind it is remote.

Two things about the trust model are the whole design. **The hop opens the endpoint with
its own environment**: its credentials, its transport settings, its `RCP_OCI_INSECURE`,
because a relay's secrets are the hop operator's and a HELLO is not the place to carry
someone else's. And **the hop operator has a rail**: `RCP_ALLOWED_ROOTS` in the serve's
environment (an `authorized_keys` `environment=`, `~/.ssh/rc`, a wrapper) or `-allow` on a
`-listen` serve bounds what any client may ask that serve to open, endpoints included.
That rail bounds the endpoint TEXT, so a root of `/srv` admits `/srv/x` and does NOT admit
`rcp://filer:7712/srv/x` -- a hop that is to open remote endpoints needs them spelled in
its own roots. Unset, a serve opens what the ssh
user can reach, which is what it always could. `-via` itself is a `Runs` capability: a
call through `rcp mcp` cannot set it and a railed command line strips it.

The hop's HELLO reply also carries what the far tree answers the planner -- whether it
keeps times, whether its metadata can be rewritten in place -- because the `SshTree` on
this side is what the planner asks, and without them it would answer the defaults. Without
that override, `sync -via ssh://hop` to a WebDAV collection would recopy every file for one
edit, the same bug `keeps_times` fixes on the direct path, and `chmod` through the hop would
be accepted and silently not done. Both are test arms, with a local directory through the
same hop as the control.

**Every worker's channel is its own `rcp serve`, and each one opens the endpoint again.**
Only the first open asserts that the endpoint is there. The channels after it send ATTACH
instead of HELLO: the same body and reply, and no "is there an image here" check, because
the run's own work can make that answer false for a tree that is fine. A delete removes the
last tag before a slow channel comes up, and a push has not published its first tag yet.
Both used to fail on the late channels, as "the repository has no tags" and "no such
repository". A join keeps the first open's push rights and never creates anything, so a
second channel cannot recreate a directory the run removed or start a second archive. A
serve that predates ATTACH answers it `Unsupported`, and the pool falls back to the old
HELLO on the same channel once, then sends HELLO to that pool for the rest of the run.

**A registry behind a hop is written through one channel.** A registry publishes its
manifests at `sync`, and each serve stages what it received, so files written through a
second channel sat in a staging area the first channel's `sync` never reached. Measured
through a relay at `-parallel 8`, the push reported success and the tag did not exist. The
engine now writes such a tree one file at a time, the way it writes a tar archive, for the
same reason `-nodes` refuses a registry as its destination. Reads are not limited.
