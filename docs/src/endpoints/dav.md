# WebDAV: dav://

`rcp copy /data davs://cloud.example/remote.php/dav/files/me/backup` speaks WebDAV (RFC
4918), the protocol behind Nextcloud, ownCloud, SharePoint, Apache `mod_dav` and most "map a
network drive over HTTPS" appliances: `PROPFIND` with `Depth: 1` walks one collection at a
time (never `infinity`, which servers commonly refuse and which is unbounded in memory),
`GET` with `Range` reads, `PUT` writes, `MKCOL`, `DELETE` and `MOVE` for rename. **There
is no hard link**: `COPY` writes a second copy of the bytes, which is not a second name for
one file, so `hard_link` is refused as unsupported and the transfer layer copies -- the
same bytes that `COPY` would have written, with the summary now saying `copied` rather
than `linked`. The same is true of `s3://`, `oci://`, `hdfs://` and `sftp://`. `dav://` is plain HTTP and `davs://` needs the `rustls` build.
Credentials go in `-dav.user USER:PASSWORD` or `RCP_DAV_USER` with `RCP_DAV_PASSWORD`;
a URL carrying `user:password@` is refused by name rather than quietly stripped, because
the endpoint lands in the job log, in every report and in `ps`. **The refusal does not
repeat the URL**: quoting the endpoint back would put the password in the job log on the one
path that exists to keep it out. The same holds for the `http://` endpoint, for
`-s3.endpoint`, and for `rcp show`, which takes an NFS host and would otherwise hand a
mistyped URL to the resolver with the password inside the error. All four refuse without
repeating the token.

Three things the protocol cannot hold, each refused by name rather than dropped: symlinks
(there is no representation for one; `-type f` leaves them out), hard links, and any of the
modes, owners and times this crate would set. That last one has a consequence for `sync`
that is worth knowing: a server's `getlastmodified` is when *it* wrote the file, and the
property is read-only, so the destination cannot carry the source's mtime. The planner's
"does the destination still hold this file" check used to compare size AND mtime, and read
every file on a WebDAV destination as changed -- measured as two files crossing for one
edit before `keeps_times` existed. A destination that says it cannot keep times is now
matched on size, which is rsync's `--size-only` and the honest best such a store allows;
the catalog still carries the source mtime, so a changed source is still noticed. What that
cannot detect is a file edited in place on the server to the same length.

`verify` asks the same question, so the two commands do not contradict each other on
exactly the stores `keeps_times` exists for. The flag's other consumers are the relay's
HELLO, the `AnyTree` delegation, the planner and `sync -dryrun -target`; a `verify` that
ignored it would see a correct, complete copy to a WebDAV destination held done by the
planner and report an mtime difference on EVERY file. The comparison is skipped when the
destination keeps its own times, and **said out loud in a warning** rather than
dropped quietly -- a check that silently stops running is how a suite goes green without
measuring anything. The modes are still compared, so `verify` against a WebDAV destination
still reports what the server cannot hold; `-noattrs` is the comparison this transport can
make without any of that.

The XML reader is deliberately not a general one: it reads a `207 Multistatus` and nothing
else and refuses a `DOCTYPE` outright rather than defending against entity expansion --
each stated in `src/dav/xml.rs` with the reason it is safe to omit here. It DOES resolve
namespaces. It is tempting to strip prefixes and compare local names, on the reasoning that
every server binds `D:` to `DAV:`, but that reasoning is about servers while the reader is
fed by whatever answers on the port: an `href` in another namespace placed after the real
one would be read as the entry's path. Only `DAV:` elements are read, whatever their prefix, and a foreign element takes its subtree with it.

One consequence of the size-only match is worth its own sentence: `isync` -- `Mode::Mirror`,
no catalog -- to a WebDAV destination skips a source file edited in place to the same
length, because without a catalog there is no recorded source mtime to compare against and
the destination cannot hold one. `sync -id` sees the edit through the catalog; `isync` does
not. `verify -noattrs` after an `isync` is the check. S3 is the neighboring case: a bucket this
crate wrote carries the source mtime in object metadata and `keeps_times` is honestly true,
but a bucket written by another tool carries only the store's `Last-Modified`, and against
one of those `isync` recopies every file whose length matches and whose date does not. The contract suite runs the client against an
in-process stand-in (`src/dav/testserver.rs`) that is deliberately awkward in the two ways
real servers are: its listings include the collection's own entry, in either position, and
every entry carries a second `propstat` answering 404 for a property it lacks. An adapter
that only meets a tidy server is one that has not been tested.

That was measured the hard way. Against Apache 2.4 with `mod_dav`, every run failed at open
with `HTTP 301`, and the stand-in had never shown it. A collection named without its trailing
slash, as an endpoint URL is written, gets a 301 from Apache to the same path with the slash.
The adapter refuses redirects, and the stand-in answered 207 to both forms. Now the adapter
follows exactly that redirect, when `Location` names the same resource on the same origin
with a slash added, and refuses every other. The stand-in answers the way Apache does.
Against Apache 2.4 `httpd:2.4` (Debian), a tree of 10 files and 22 MB copies up and back
down, including names with spaces, `+`, `%`, non-ASCII characters and a 200-character name.
`verify` reports 0 differences, and `diff -r` against the server's disk is clean.
