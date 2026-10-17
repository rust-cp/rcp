# Container images: oci://

`oci://host[:port]/repository[:tag]` is a repository on a container registry (the OCI
Distribution API), presented as an OCI image layout: `oci-layout`, `index.json` and
`blobs/sha256/<digest>` for every blob the image reaches, manifests and indexes included.
Every tag of the repository is in the tree, or the one named. So `rcp copy` between two
registries mirrors an image the way `skopeo copy` and `crane copy` do; a copy from a
registry to a directory writes a layout skopeo's `oci:` transport reads (and byte for byte
what it would write, `index.json` included); a copy from a layout pushes it; `verify`
compares two registries or a layout against one (`-nomods`, since a registry keeps no
times, modes or owners); `scan` lists what an image is made of. Names are content, so a
blob the destination already holds is neither uploaded nor read from the source, and a
second mirror of the same image moves nothing but its manifests. A blob skipped that way
is recorded in the catalog with an empty digest column, as a kernel copy is: it was never
read, and the registry's own content-addressing is what proved it holds those exact bytes.
The skip is a `HEAD` on the destination repository and nothing more, so it is exactly as
good as the registry's promise that a digest names its bytes; rcp does not re-read to
check, and a registry that answers `HEAD` for content it does not have would leave the
manifest unpushable. (The stand-in keeps one blob store for every repository, which is why
the second-mirror measurement above moves no blob; a registry that links blobs per
repository would answer `HEAD` with a 404 there and take the upload.) Uploads stream through
the chunked upload protocol; manifests are staged as they arrive and pushed, children
before parents and tagged as `index.json` says, when the copy finishes, because a registry
refuses a manifest whose blobs it does not have yet. Nothing but the sniff can tell a
manifest from a layer that happens to be JSON, so what `index.json` reaches decides: what
it does not reach goes up as the blob it is. **A layout with no `index.json` reaches
nothing, and that used to be a silent success** — every manifest went up as a blob no
client can name, no tag was pushed, and the run said `PASSED`, measured at 3 blobs and 0
manifests. `oci-layout` is the source saying it is a layout, and a layout owes an index,
so a run that wrote one and got an index naming nothing now fails, saying the copy would
create no image.

Be exact about what that prevents, because an earlier sentence here was not: it stops the
**manifests**, which are held back until `sync`, and it cannot unsend a plain blob, which
streams up as the copy reaches it. On the measured layout that is 1 upload where the old
code sent 3. Unreferenced blobs are what a registry's garbage collection is for; an image
that does not exist is not. Downloads are digested as they pass
and a blob whose bytes do not match its name is refused. `docker.io` is Docker Hub
(`library/` is added for a bare name). Authentication is the registry's own: a `Bearer`
challenge is answered from the realm it names, a `Basic` one with the credentials;
those come from `-oci.user USER:PASSWORD`, `RCP_OCI_USER` with `RCP_OCI_PASSWORD`, or the
container tools' own files (`REGISTRY_AUTH_FILE`, `~/.docker/config.json`,
`$XDG_RUNTIME_DIR/containers/auth.json`). `-oci.insecure` uses plain HTTP, `-oci.noverify`
skips certificate checks; HTTPS needs a build with the `rustls` feature, as S3 does. What a
registry has no room for is refused in the open: a path that is not a blob, a symlink, a
rename. `delete` removes tags and manifests; blobs stay until the registry's own garbage
collection, which is the registry's job.

**A stream that dies mid-blob is reissued from where it stopped.** A token expires with
the body already flowing -- Docker Hub's lasts about five minutes and a large image
outlives it -- and there is no 401 left to answer: the 200 and its headers are spent, so
the registry just stops sending. The retry before the first byte cannot reach that. rcp
reissues the `GET` with `Range: bytes=N-` from the
byte it stopped at, which is where a 401 *can* be answered, and carries the running digest
across, because a range resume skips nothing and that digest is the only thing making a
partial read safe. Bounded by progress: a resume is attempted once at a
given offset, so one that moves no bytes is the last, and 64 consecutive reconnections
that each deliver under 1024 bytes stop a server that dribbles and hangs up. A
reconnection that delivers a kilobyte or more resets that count. And a `Range` is a request, not
a guarantee -- a server free to ignore it answers 200 with the whole blob, which would put
the blob's head at its tail -- so a ranged read that is not answered 206 is refused before
a byte lands at the wrong offset, naming the server rather than the blob. The digest would
catch it on this path, since the hasher rides across; it would not on the `Seek` path,
which carries no hasher, and the refusal covers both. The executable control for the reissue is a stand-in that cuts and then refuses to honor the `Range`: with the resume load-bearing, that run must fail, and does.

**An upload goes where the registry sends it.** `POST .../blobs/uploads/` answers with a
`Location`, and the spec puts no constraint on where it points — ECR and GAR hand the body
to a signed URL on their own storage host. rcp follows it, on a connection to that host,
and deliberately sends it **no** `Authorization`: the signature in the URL is the
credential, and this registry's token is not for a third party to see. A relative
`Location` from that host means a path on *that* host, not back on the registry. It is
tempting to read only the path; that sends the body to the original registry under a path
that means nothing there — and against a stand-in that serves both,
the copy *succeeded* while never touching the host it was sent to. The contract arm runs a
stand-in that hands uploads to a second listener, requires the blobs to arrive there, and
requires the credential not to.

**The bearer `realm` is the sharper half of the same thing.**
A `401` names a `realm` to fetch a token from, and fetching one *sends the basic
credentials* — so a registry answering `WWW-Authenticate: Bearer realm="http://elsewhere/token"`
is handed this run's username and password. Measured before the gate existed: a run railed
to `-allow oci://HOST/app` sent `Basic b3BlcmF0b3I6c3VwZXJzZWNyZXQ=` to a listener on
another port. Docker Hub's realm really is another host, so following it is the feature;
what bounds it is that a **railed** run follows an upload `Location` or a `realm` only to
an authority its own `-allow` roots name. `hdfs://` is the third protocol with this shape —
a namenode's 307 chooses the datanode that receives the file body — and it is gated by the
same rule, which now lives once in `ports` rather than inside the registry client.

**A `-nodes` fleet cannot have a registry as its destination, and says so.** Each worker is
its own process holding its own staged manifests, and only this process calls `sync`, so
the manifests were never pushed: measured, `copy -nodes` exited 0 reporting 8 files while
the registry took 3 blobs, 0 manifests, and had no such repository at all. A silent success
that produces nothing pullable is worse than a refusal, so the pair is refused — by the
coordinator and by `copybatch` on the worker side. Blob uploads are already eight in
flight within one process.
