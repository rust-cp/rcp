# Driving rcp from an agent

**`rcp job`** runs a command in a session of its own and reports on it afterwards, so a
caller need not hold a tool call open for a terabyte. `rcp job start copy -newid ID SOURCE
DESTINATION` returns a job id at once; `status`, `wait`, `log`, `cancel` and `forget` work
from that id from any process, including one started later. The command after `start` is
taken verbatim, so its options are its own rather than the `job` command's.

On Linux x86-64 and AArch64, `job cancel` uses a process handle (pidfd) so a recycled PID cannot receive the signal. It requires Linux 5.3 or later and permission to use `pidfd_open` and `pidfd_send_signal`; if those calls are unavailable, cancellation reports an error instead of signaling an unpinned PID.

Nothing there is a daemon. The job is the ordinary command with its events going to a file,
in its own session so a closing terminal or a dying agent host does not take it with it.
`rcp job log -n OFFSET` reads forward from where the last read stopped and never hands over
half a line, so polling it never sees a partial event.

A canceled job leaves its catalog and `rcp resume -id ID` finishes it. **That depends on
when catalog entries are written.** The catalog is what `resume` reads; with entries written
in one pass *after every file in the batch had landed*, a copy killed after 28 of 40 files
left no file entries at all, and resuming it copied all 40 again. Entries are written as
each file lands, so a
canceled job resumes from where it stopped. A contract arm measures exactly that: it
counts the entries while the job is still running, cancels, and requires `resume` to skip
that many.

`resume` is the remedy for a COPY, and only for a copy. It re-plans the copy against the
catalog and **never plans a removal**, so a failed `sync` or `isync` is finished by running
that verb again, and a run that kept no catalog at all (`-noid`, a dry run, a bare `isync`)
has nothing to resume. Each of the three names what will actually work, in the summary and in `rcp job show` alike. Advice that cannot
work costs an operator a run before they learn it was wrong.

**`rcp mcp`** serves JSON-RPC 2.0 on stdio, one message per line, so an agent host can
call rcp as a tool instead of assembling a command line and parsing prose: `initialize`,
`ping`, `tools/list` and `tools/call`, with the tools `rcp_plan`, `rcp_copy`,
`rcp_isync_plan`, `rcp_isync`, `rcp_verify`, `rcp_scan`, `rcp_count`, `rcp_delete`,
`rcp_show` and `rcp_describe`. Each returns the `-json` events of the run it made.

Every destructive tool has a plan tool beside it that runs the dry run of **its own**
command, and the pairing is not decoration: a copy's plan lists every source file, an
isync's lists only what differs and what it would remove, and the digest is a hash over
those lines. While `rcp_isync` was told to take `rcp_plan`'s digest, the two printed
different numbers for the same pair of trees (`20d6219d81bec157` against
`296677cd670b40fc`) and the call could not be satisfied at all. A test walks every
destructive tool, requires the command it plans with to be its own, and then runs the
pair end to end.

Every call runs rcp itself as a child. Running the command in the server's own process
would be shorter by a page and wrong: the command writes its events to stdout, which there
is the protocol channel. A child keeps the two apart, gives every call the same argument
parsing and the same rails a person gets, and means a copy that dies takes nothing with
it.

Two things follow from the child, and both were measured rather than assumed. **A killed
server takes its child with it**: without that, killing the server left the copy running,
so a host that had given up on the call was still being written to — the child asks the
kernel for a death signal when its parent goes, and a contract arm kills a server
mid-copy and requires the child to be gone. (`rcp job` is how a run is *meant* to outlive
its caller, and it puts itself in a session of its own so this never reaches it.) And **a
reply is bounded**: the child's events are held whole in memory to be returned as one
string, so a scan of a hundred million files would be a hundred million events in a single
reply. Past 4 MiB the middle is dropped, with a `warning` event saying how many went and
both ends — the beginning and the `done` — kept, since a tool call is the wrong shape for
a firehose and `rcp job` is the right one.

The rails are the point of the wiring rather than an afterthought. The server's rails reach
every call -- `-allow`, `-readonly` on the command line, and its `-oci.user`, `-s3.endpoint`,
`-s3.profile`, `-hdfs.namenode` and transport switches through the child's environment --
and `-requireconfirm` is added whether or not it was asked for, so a call that would remove or overwrite is refused until its `confirm` carries the
digest `rcp_plan` (or `rcp_count`) returned for the same endpoints and options. A copy into
empty space just runs, because whether a call is destructive is something only the plan
knows and the child computes it. A call's `options` are checked against this build's own
option tables, so a call cannot invent an option, smuggle an endpoint through them, set
the rails itself, or turn certificate verification off for a host the operator named.

Say what does NOT reach a call, because "whatever the server was started with" is not the
rule. `-nodes`, `-copybatch` and
`-rcp.remote` name a program to run or a host to run one on, and are relayed neither way:
no rail bounds what a program does, so a server started with one does not hand it to a
caller and a caller cannot ask for one. `-catalog` IS relayed, as `RCP_CATALOG`, so the
children share the directory the server was started with (see `relay_env`). `-nfs.sec`,
`-nfs.vers` and `-acl4` **are** carried, through `RCP_NFS_SEC`, `RCP_NFS_VERS` and
`RCP_NFS_ACL4`; the first two are `Transport` and a call may not name them at all, and
`-acl4` a call may add but cannot strip. A hand-written summary of a table the code already
publishes is easy to get wrong, and this one has been, more than once: run `rcp describe`
rather than trusting this sentence.

**Checking the option NAME is not enough.**
`-copybatch` takes a program to run per batch — a documented feature, and the right one
for a person at a terminal. Through the server it was arbitrary command execution: a
`rcp_copy` call carrying `-copybatch 'touch /tmp/rcp-pwn-probe'`, to a server started with
two `-allow` roots, created that file.

A list of the nine options whose value is a capability would be the same shape as the
bug: **a tenth would be exposed until somebody remembered a second table.** So every option now carries a classification in the
same table that carries its summary — `Setting`, `Runs`, `Path`, `Service`, `Credential`,
`Transport` or `Rail` — with **no default variant**, and `tests/describe.rs` fails the build when an
option the parser accepts has none. A call may set what is classified `Setting` and
nothing else; the rails read the same table for the options no rail can bound
(`-copybatch`, `-nodes`, `-rcp.remote`), which are refused on any railed run whether or
not a server is involved. `rcp describe` publishes `settable_by_a_call` per option, so an
agent reads the rule instead of learning it from a refusal. **No count is written here**,
deliberately: a count that once stood in this place said "100 of the 115 options are
settable, 15 are not" while the table had already grown to 117 options and 23 refusals. A
number copied out of a table is a second copy of the table. Ask the build:

```
rcp describe | grep -c 'settable_by_a_call.*false'
```

Three rails bound a run, all off by default, because a person at a terminal should not
have to ask twice. A caller that drives rcp on someone's behalf sets them and then cannot
exceed them, whatever it was told to do.

**`-allow ROOT`** (repeatable, or `RCP_ALLOWED_ROOTS`, comma-separated) is the set of
roots the run may touch. Every endpoint must be a root or lie under one, on a path
boundary, so `/data` does not admit `/database`; a local root never admits a remote
endpoint, or the reverse. The check happens *before anything is opened*, so a refused
endpoint costs no connection and learns nothing about the far side.

**A local endpoint is resolved the way the kernel resolves it before it is compared.** A
spelling check is not containment: with only a spelling check and `-allow /data` in force,
`/data/../secret` passed the rail and its files were copied, and
so did `/data/link` where `link` was a symlink to anywhere at all. Both were measured,
both are refused now, and the arms that cover them fail if the lexical check comes back.
Components are resolved from the root outwards, each existing one canonicalized before the
next is applied, because that is the order the kernel uses — `a/b/..` is not `a` when `b`
is a symlink. What does not exist yet is appended, so a destination that has never been
created is still checked. Symlinks *inside* a tree need none of this: a copy recreates
them and never follows one.

**A resolver like that fails open easily.** `canonicalize` fails for a path that does not
exist *and* for a symlink whose target does not, and taking the spelling in both cases
admits `ROOT/out` with `out` a dangling link to anywhere — a create follows a link. A
component that is a link is read and followed whether or not its target exists (40 hops,
then it stops, as the kernel does); only a path with no link left in it is taken as
spelled. Two more of the same kind: **`-allow /` is a root that admits every local path**,
where trimming its trailing slash naively leaves an empty string that is dropped, leaving a
run with *no* roots — a rail that is not there.
And a **remote** endpoint whose text climbs (`nfs://host/export/../secret`) is refused
rather than compared: only the far side can resolve it, so there is nothing honest to
compare. `sftp://` and `s3://` already refused one when they parsed it; this is the rest.

**A rail on the text of an endpoint is not a rail on the service it resolves to.** `rcp mcp`
refuses every option that is not a
plain setting; a railed *command line* refused only the two that name a program to run. So
this went through:

```
$ rcp scan -allow s3://corp/bucket -s3.endpoint http://127.0.0.1:8931 s3://corp/bucket
```

and a listener on loopback — a host no rail named — received
`GET /corp/?list-type=2&prefix=bucket/`, while the same run without `-s3.endpoint` goes to
AWS. `-hdfs.namenode` is the same shape, and `-s3.profile` and `-oci.user` choose whose
credentials ride along. A railed run now refuses all four on the command line.

What that does is **move** the capability to the environment, not remove it, and it is
worth saying exactly. `RCP_S3_ENDPOINT` redirects the same traffic, and so do AWS's own
`AWS_ENDPOINT_URL_S3`, `AWS_ENDPOINT_URL` and an `endpoint_url` in the named profile,
which rcp reads because AWS's own tools do. The rails bound the **command line** — the
part a caller writes and an operator reads — and not the environment a run inherits. Where
those are the same party this changes nothing. Where they are not, which is the case the
rails exist for, the caller writes the command line and the server owns the environment.

`-snap` and `-reference` stay, because they are opened through the same
`-allow` check as any endpoint; the rails themselves stay, because on a command line they
are the operator's own.

**The registry's upload hand-off is bounded by the same roots.** A registry answers the
upload `POST` with a `Location`, and for ECR, GAR and anything fronting object storage that
names a different host, which is where each blob's bytes then go. Following it is the
feature. But the *registry* picks that host, and `-allow` is the operator saying where this
run's data may go, so a railed run follows the hand-off only to an authority its own roots
name, and says which `-allow` would permit it. An unrailed run follows it as before:
naming the registry is already the statement of trust. Never a loop — the hand-off is read
at most twice, once when the upload opens and once when it commits.

What is still true and worth saying plainly: this is a check before the open, so it cannot
close a race against a symlink planted between the two, and it constrains *endpoints*
rather than every syscall a run makes. It is a rail, not a sandbox.

**A symlink inside the destination is the other half of that, and it is not a rail
question at all** — it was wrong for a copy with no rails on. A destination is not always
a tree this run made, and a link sitting where a file belongs was followed: measured, a
copy into a tree holding `f.txt -> /elsewhere/target` wrote the source's bytes into
`/elsewhere/target` and left the link in place, and a linked *directory* took a whole
subtree with it. Both halves are wrong — the write escapes and the copy does not produce
what the source has. Local destinations open with `O_NOFOLLOW` now (both engines, since
each opens its own), and a link found in the way is removed and replaced by the file or
directory the source has. A symlink in the *source* is still recreated as a symlink, and
an ordinary overwrite still overwrites; both are controls on the same test. The separator is a
comma rather than the colon a `PATH` uses, because every endpoint scheme has a colon in
it: splitting on colons turned `ssh://host/path` into the two roots `ssh` and
`//host/path`, which admitted nothing at all. A test control caught that.

**`-readonly`** (or `RCP_READONLY`) refuses every command that writes to an endpoint,
before it starts. Which commands write is the table `rcp describe` publishes, so the two
cannot disagree -- plus three whose write-ness depends on an ARGUMENT rather than their
name, which the table cannot express: `logdump ID` writes `ID.zip`, `scan -newid ID`
writes a catalog, and `estimate -target DIR` copies a live sample into `DIR` to time it.
All three reported PASSED under `-readonly` before they were listed; finding one such
command is the cue to look for its siblings.

The boundary this draws is the ENDPOINTS, stated exactly because the looser version was
false: a read-only run still appends to `jobs.log` under the catalog directory, and a run
railed with `-allow /only-here` still writes `<id>/index.tsv` under the catalog too. That
is rcp's own record of what ran, in a directory the operator named with `-catalog`, and
suppressing it would trade an audit trail for a slogan.

That is easy to read as a hole in `-allow` rather than a boundary, so the reason it is
safe is worth stating rather than leaving to be re-derived: **`catalog` is itself a `Rail`,
and a call through `rcp mcp` cannot set it.** A railed COMMAND LINE can -- `-allow /data
-catalog /elsewhere` is accepted, because `why_not_railed` admits `Rail`. That is not a
hole, and the distinction is the whole point: the rails bound what a *caller* may choose
through a command line the *operator* wrote. Whoever writes `-catalog` on the command line
is the operator, and the operator may put the catalog anywhere. The property that holds is
that nothing reaching rcp through a call can move it. `-allow` bounds where a caller may
send the DATA; it is not a sandbox around the process, and a rail that could be pointed
anywhere by the thing being railed would not be one.

**`-confirm DIGEST`** with **`-requireconfirm`** (or `RCP_REQUIRE_CONFIRM`) refuses a run
that would remove or overwrite anything unless the digest matches the one a dry run of the
same command printed on its `plan:` line (for `delete`, the counting run without
`-force`). The digest covers both endpoints and every planned action, so a change that
alters the plan since it was read no longer matches. It names the actions and is not a
snapshot of either tree: new content under the same planned overwrite, or a change
outside the run's scope, leaves the plan and its digest as they were. **The refusal deliberately does not
name the digest it wanted**: a refusal that handed it over would let a caller satisfy the
check without ever reading the plan, which is the only thing the check is for. A test
asserts the refusal does not contain it.

One consequence worth stating: a plain `copy` never asks what is already at the
destination, which is what makes it fast. When the plan is going to be shown or confirmed
it has to ask, because not looking is the same as not knowing, and a rail that cannot see
an overwrite does not guard against one. So a dry run of a copy onto an existing tree now
marks those files `*` rather than `+`, which is what it always should have said.

Two more things the rail sees. The destination is listed through the
path patterns (`-match`, `-exclude`) only, so a destination file that `-minsize`, an age
or an owner filter would leave out still shows as the overwrite it is. The attribute
filters are then applied to decide what the run may skip or remove, so such a file is
never removed. And a destination directory the listing could not read is reported as a
failure and shown on a `?` line, and it makes the run count as destructive: a rail cannot
rule out an overwrite it could not see.

A directory the source dropped is removed as an rmdir on every transport, including
WebDAV, whose collection `DELETE` is recursive by the RFC and is only sent once the
collection lists empty. One residual on WebDAV only: a name written into that collection in
the single round trip between its listing and the `DELETE` goes with it, where an rmdir
would refuse. The protocol has no non-recursive delete to send instead. In a filtered or
`-depth`-capped run, such a directory can still hold a name the run did not look at. It
stays, with that name inside it, and a `WARN` line says so; that is not a failure.

The attribute filters (`-minsize`, `-maxsize`, the ages, `-uid`, `-gid`, `-type`,
`-fileid`) are tested against each side's own entries. The source is listed through the
path patterns too: a file the source still has, outside the predicates, is neither copied
nor removed, the way rsync's `--min-size` skips a transfer rather than hiding a name.
Where a predicate describes the destination copy differently from its source, the two
never meet. That is `-uid` or `-gid` without ownership carried, an age where the store
keeps its own times, and `-fileid` always. Such files are recopied on every run and never
removed.

`isync` and `sync` replace an entry of the wrong kind: a file or symlink where the source
has a directory is removed before the directory is made, and a directory where the source
has a file joins the removals, children first. Both show on the plan as `#` lines.
`copy` and `resume` replace the first kind too, since one entry replaced is the same size of
act as a file overwritten. A copy that did not list its destination finds the entry when the
mkdir fails, looks at it without following a link, and replaces it then. A directory where
the source has a file stays a failure for them: removing it would remove a subtree the
source never had, which is a mirror's decision. The
symlink case matters beyond convergence: left in place, the copy would open through it and
write wherever it points. Any entry in the way counts, including one the filters would
otherwise leave out.

That holds wherever the client can see the link. A local `O_NOFOLLOW` open sees it, and so
does SFTP's LSTAT; where a server leaves the permissions out of LSTAT, READLINK tells a link
from a directory. NFS never follows one at the name: an UNCHECKED CREATE hands back the link
itself, and a v4 OPEN answers `NFS4ERR_SYMLINK`, so the reply is read and the link replaced.
SFTP v3 has no open that refuses to follow, so a link planted by a concurrent writer between
the look and the open is still followed. More generally, each replacement looks and then acts,
so an entry another writer puts at the name in between can be the one removed. A destination
that something else is changing during the run is outside what these checks settle. NFS
replaces a link whether the server hands it back from CREATE (Linux) or refuses the CREATE
with EXIST. INVAL is any bad argument, so a link found beside it is left alone. v4 replaces one
only on the `NFS4ERR_SYMLINK` status, never after another refusal. Where SFTP's LSTAT carries
no permissions, READLINK is the only evidence taken: a name it answers for is a link and is
replaced, and any other name is unknown. OPENDIR follows a link, and draft-02's REALPATH need
only normalize the spelling, so neither can tell a directory from a link to one. On such a
server an existing directory fails its mkdir, and the subtree beneath it is refused loudly. Nothing is made, moved, removed or linked beneath a
directory whose mkdir failed, since what stands at that path is not the directory the plan
made. An SMB2 server without the POSIX extensions resolves links itself: Samba with
`follow symlinks` presents a link as the file it points at, with that file's size and
times. To the client that name is a regular file, as indistinguishable from the target as a
hard link is, and an overwrite goes where the server sends it, as it does for any SMB client.
Where the link may point is the server's setting. Samba's `wide links`, off by default,
keeps it inside the share, which is not the same as inside the destination directory. A Windows server reports a link as a reparse point instead. The
listing names it as not copied, and the server refuses to open through it.

`rcp describe` prints what this build can do as one JSON object: every command with the
arguments it takes and whether it writes, every option with its kind and a one-line
summary, every endpoint scheme with a capability table (writable, sparse files, hard
links, symlinks, extended attributes, ACLs, rename, identity, delta transfer, and the
finest modification time it can carry), the `-json` events, the error codes and the exit
codes. So a caller does not have to be told out of band what this binary accepts, and does
not have to parse the usage text to find out.

**It cannot fall behind the binary**, and that is the point rather than a hope: the option
list is built from the very arrays the argument parser matches against, and `tests/describe.rs`
fails the build when an option has no summary, when a summary names an option the parser
no longer accepts, when a described command is not in the dispatch, or when `describe` and
`version` disagree about the transports. Each of those arms has a control.

The capability table is a statement about each protocol, not about a particular server: a
`false` means the protocol has no way to say it, so rcp refuses or approximates it in the
open. It is also the answer to "will this copy survive the trip": a tree with hard links
bound for `sftp://`, `s3://` or `oci://` arrives as separate files, and `describe` says so
before the copy rather than in its report.

`-json` turns the run into events: one JSON object per line on stdout and nothing else,
with every human line, `STATUS` included, moved to stderr. So a caller parses stdout whole
and still gets a readable log by watching stderr. The exit code does not change: 0 for
`STATUS: PASSED`, 1 for `STATUS: FAILED`.

| event | when | fields |
| --- | --- | --- |
| `entry` | a file, directory or symlink completed | `path`, `kind` (`f`, `d`, `l`), `size`, `mtime_ns`, `mode`, and `digest` when the run hashed it |
| `removed` | `sync` removed an entry the source dropped | `path` |
| `deferred` | the destination will remove the entry itself, later -- a registry that leaves blobs to its garbage collector | `path`, with why in the store's own terms |
| `kept` | the destination REFUSED to remove the entry and it is still there -- a locked WebDAV resource, a namenode answering `false`, a bucket policy or a filesystem answering "permission denied" | `path`, with why in the store's own terms |
| `difference` | `verify` found one | `kind`, `path`, `detail` |
| `warning` | something worth saying that did not fail | `message` |
| `error` | an entry or the run failed | `code`, `message`, plus `op` and `path` for an entry |
| `done` | the command ended | `status` (`passed` or `failed`), `command`, and that command's own counts, `deferred` and `kept` among them |

**`deferred` is not a failure; `kept` is.** It is tempting to give both one answer --
"kept is not a failure, and a run that kept everything still says `passed`" -- on the
reasoning that a registry `delete` which removed the manifests and left the blobs to garbage
collection has done the thing a registry delete means. That reasoning is right about the
registry and wrong about a locked WebDAV file, which is a different thing: the registry WILL
remove its blobs and there is nothing left to do, while the locked file is still there and
will stay there. Ask what a caller reading only the exit code concludes, and for the second
case one shared answer gives it "the wrong thing". So the two are split. A `delete` or
`sync` that ends with anything `kept` exits 1 and says which entries the store refused; one
that ends with entries `deferred` exits 0 and says which the store will finish. `diag
-rmdir` and `-rmrf` answer the same way.

**And `kept` covers every store.** It is easy to answer `kept` only for WebDAV and HDFS,
because those two report a refusal *inside* a successful response. A local `EACCES`, an
`NFS3ERR_ACCES`, an SFTP permission denial and an S3 `403` are the same event -- the store
answered and said no. Reporting any of them as a failure of the run gets the exit code right
and the REMEDY printed beside it wrong, since a failure says to use `resume` and `resume`
never plans removals, so the advice could not work however often it was followed.
`Removed::or_refused` maps a `PermissionDenied` to `kept`; anything else -- a timeout, a
broken connection, an answer that could not be read -- is still a failure, because it is
one.

**Every adapter calls it, not only the ones with a protocol-specific refusal.** The easy
mistake is to handle only that refusal: WebDAV's 423 and partial 207 while an ordinary
401/403 drops into failures, WebHDFS's namenode `false` but not a 403 over HTTP, the
registry's 405 but not a refusal. WebDAV, the adapter the whole idea came from, is as prone
to it as any. All eight call it, and the WebDAV arm has a `forbid_delete` stand-in that
measured red without it.

**Keying on `PermissionDenied` alone is too broad.** It cannot tell a **401** from a
**403**, because all four `kind_of_status` tables map both to that one kind. So a bad
password would become `kept`, whose printed remedy is "run `sync` again once the entry can
go" -- advice that cannot come right, since the run is not authenticated at all, every
remaining removal answers the same way, and a rerun with the same credential reproduces it
exactly. The same defect one status further in.

The four HTTP adapters decide from the **status**, in `net::http::delete_refused`, and not
from a kind that has already thrown the difference away: a 403 or a 423 is `kept`, and a 401
(or a 407, the same sentence about the proxy) is a failure that names the credential as what
to fix. The stand-in has an `unauthorized_delete` switch, and the arm was measured red
against the kind-based version, printing `KEPT: .: the store refused: .: HTTP 401`.

**Local, NFS, NFSv4 and SFTP still go through `or_refused`, and the reason is easy to get
wrong in both directions.**

It is tempting to say those protocols "have no 401". That is false: RPC rejects a call with
`AUTH_BADCRED`, `AUTH_REJECTEDCRED`, `AUTH_TOOWEAK` and two `RPCSEC_GSS` problems, and
`rpc.rs` maps all of them to `PermissionDenied`. From that it is equally tempting to
conclude NFS has the same defect as the kind-based HTTP adapters.

**That conclusion is also wrong, and the arm written to prove it is what shows so.** An RPC
rejection never reaches `or_refused`: `self.call(..)?` in the v3 client and
`self.compound(c)?` in the v4 one return it first, so the only errors that arrive at the
match are NFS statuses — which is exactly what `or_refused` is for. A `delete` against an
export that answers `AUTH_TOOWEAK` already fails, already names `-nfs.sec`, and reports
nothing as kept. A guard added on the strength of the second reading would be dead code.

The arm is `an_nfs_call_refused_by_rpc_is_a_failure_and_not_a_kept_entry`, with a stand-in
that rejects only `REMOVE` and `RMDIR` (rejecting every call means the mount never lands, so
the removal is never reached) and an honest server as its control. Without such an arm, two
readings of the code can disagree indefinitely.

The arm for this uses a stand-in S3 service with a `refuse_deletes` switch rather than a
`chmod`, and that is not a convenience: the suite runs as root, where `unlink` inside a
mode-500 directory SUCCEEDS, so a permission arm built that way would pass without ever
reaching the code it claims to measure.

An error's `code` is one of `notfound`, `permission`, `exists`, `unsupported`, `invalid`,
`timeout`, `interrupted`, `disconnected`, `unreachable`, `nospace`, `quota`, `busy`,
`wouldblock`, `io`, `owner` (ownership could not be preserved and `-chown` made that an
error) or `usage` (the arguments, an option, or an endpoint's shape). **The set is
closed**: an error kind with no name of its own reports `io` rather than inventing one, so
a caller can branch on the code and be sure a future release will not hand it a name it has
never seen.

`busy` exists because the cost of the fallback is concrete, and the measurement is the
whole argument: without it, a registry answering 429 because it is over its rate limit and a
repository that does not exist both arrive as `io`, and those call for opposite behavior —
one is worth waiting on and the other never will be. 429, 502, 503 and 504 from a registry
are `busy`, and a contract arm reads the code off a throttled stand-in. `quota` went in
beside it and **is not measured**: it is what the kernel's `EDQUOT` already maps to, so a
local write over a quota reports it rather than `io`, but nothing here has produced one.
Said plainly because the two are not the same kind of claim.

A closed set is a promise not to invent names *silently*, not a promise never to name
anything: `rcp describe` publishes the list, so a caller reads it rather than hard-coding
it, and an addition shows up there.

The `entry` events come from the same records the catalog keeps, so what an agent sees and
what `resume` and `sync` will later read are one list, not two. `scan` emits an `entry` per
item only when a listing was asked for (`-l`, `-csv`, `-html`, `-fmt`); a bare `scan`
emits its summary alone, since a scan of a large tree *is* the listing and an agent that
wanted it would have said so.
