# Delta transfer

`-delta` sends a file the destination already has as a patch against it instead of
whole. The destination cuts its copy into content-defined chunks (a Gear rolling hash
with FastCDC's normalized chunking, 8 KiB on average for a file up to 32 MiB and larger
for larger files) and signs each with the run's digest; the source cuts its own copy the
same way, sends the chunks the destination lacks as bytes and the rest as "copy this
range of what you have"; the destination rebuilds the file beside the old one, checks the
whole-file digest the source computed as it went, and only then renames it into place.
The destination is signed first and then opened and checked against the size, mtime and
inode the run stat'ed, so a file replaced or rewritten in between is refused; one that
changes after that fails the whole-file digest check at the end, and the old file is
kept either way. The rebuilt file grows under an unpredictable name created exclusively
beside the old one, an interrupted patch leaves nothing behind, and a destination that
is one name of a hard-linked inode gets a new inode while the other names keep theirs.
Whatever stops a patch, the file is then copied whole, so `-delta` never fails a copy
that would have succeeded without it. Files under 64 KiB and files the destination
lacks move whole.

Two things about the chunking are worth knowing because both were defects first. The cut
masks sit HIGH in the fingerprint word: Gear pushes an old byte's contribution toward the
high bits, so testing the LOW bits decided each cut from a 15-byte window, and two places
in a file whose last fifteen bytes agree then cut identically -- every record boundary in
a fixed-width-record file, every run of padding. And the chunk signatures always use a
32-byte strong digest whatever `-hash` says, because they are a wire detail between two
rcps rather than something a user reads; sharing the `-hash` choice made `-delta -xxh3`
transfer every file whole while printing output identical to a run with no `-delta` at
all. Both changed where chunks fall, so the `rcp serve` protocol version moved with them
and a mixed pair fails by name.

Over `ssh://` both halves run where the bytes are: an ssh destination signs itself and
applies the patch on its own host, an ssh source takes the signatures and matches on its
own host, so what crosses the wire is signatures one way and changed chunks the other.
Between two ssh endpoints the machine running rcp is the relay, so signatures and
literals each cross two links; the serves never talk to each other. On a local or NFS
endpoint the same code runs in process through the port's defaults. A sparse file is
chunked as zeros on both ends, so an unchanged one sends nothing and the zero chunks
travel as holes. The summary says what it saved: `delta: 3 files,
1085249 literal bytes`, and `-loglevel DEBUG` gives the per-file line.

Measured on a 32 MiB file with 1 MiB rewritten: about 1.07 MiB of literals over about
3,560 signatures, in every direction. The chunker is content-defined, so an insertion
shifts only the chunks around it; a fixed-block scheme would lose everything after the
edit.
