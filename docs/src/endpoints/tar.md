# Archives: tar://

`tar://ARCHIVE[!/SUBPATH]` is a tar archive as a tree. `rcp copy DIR tar://out.tar` packs;
`rcp copy tar://out.tar DIR` unpacks; `rcp scan tar://out.tar` says what is in one without
extracting it, and `!/sub` roots at a directory inside. Reading opens a member by seeking
to its offset, because the archive is scanned once and the offsets kept — so unpacking one
file out of a hundred gigabytes reads that file, not everything before it.

`-rsyncable` cuts the `.tar.gz` members where the CONTENT says to instead of every 4 MiB,
which is `pigz --rsyncable` reached through this crate's own Gear chunker. The members
were already independent — that is what gives parallel decode, and it is `pigz -i` — but
their boundaries were at fixed input offsets, so inserting one byte near the front shifted
every later boundary and rewrote the whole tail. Measured through the CLI on 12 MB of
log-like text with a 25-byte insertion at offset 3000: **fixed cuts keep 0 of 3 members,
`-rsyncable` keeps 25 of 27**. `gzip -t` and `tar tzf` accept both, because the format did
not change — only where the cuts fall. It costs about 0.5% of ratio, and an arm fails if
that grows past 5%.

The format written is POSIX ustar with pax extended headers where ustar has no room: a
path over 100 bytes that will not split at a `/`, a size over 8 GiB, a link target over
100 bytes, a time with nanoseconds, an id over 2097151. Reading also takes GNU's `L` and
`K` long-name members, which is what `tar cf` writes by default, and GNU's base-256
numbers. Hard links are members of type `1` and come back as one inode on the other side;
symlinks are type `2`.

**The interoperability claim is measured in both directions**, because an archive only
another rcp can read is not an archive: a contract arm packs a tree, has `tar xf` extract
it and compares, then has `tar cf` write one (with names too long for ustar) and reads it
back with rcp. Both comparisons are `rcp verify`, which checks the bytes and the metadata
rather than the listing.

**A `.tar.gz` is read too; without a decoder it SILENTLY COPIES NOTHING.** Measured
without one:

```
$ rcp copy -noId tar:///tmp/a.tar.gz /dest
copy: 0 files (0 bytes), 0 skipped, 1 directories, ...
STATUS: PASSED
```

The archive held two files. A gzip member's first 512 bytes are not a tar header, so the
scan found no members, and an archive with no members is not an error — the run reported
success and wrote nothing, which is the worst shape a data mover has because the operator
has no reason to look. `deflate.rs` is DEFLATE (RFC 1951) and the gzip container (RFC
1952) in the standard library alone, and the archive is decompressed once to a temp file
rather than into memory, so the seek-to-a-member's-offset design is kept. The decode
still holds the compressed input and the expanded archive in memory before that temp file
is written, and `MAX_EXPANDED` is that memory ceiling; a multi-gigabyte archive is not
streamed to disk yet. The CRC-32 and length in each member's
trailer are checked and there is no flag to skip them: they are the only thing separating
a correct decode from a plausible one. A multi-member stream — `cat a.gz b.gz`, or what
`pigz -i` writes — decodes as the whole thing rather than its first member.

**Writing one is supported too.** Falling back to a plain tar for a `tar://` destination
whose name ends in `.gz` would be a defect even if documented: the run would say `PASSED`
and leave a file that `tar xzf` and `gzip -d` both reject. A limitation written
down in a README does not reach the operator who is reading `STATUS: PASSED`.

The encoder is DEFLATE with a 32 KiB window and a bounded hash chain, in `deflate.rs`
beside the decoder. Three things about it are load-bearing:

- **Each block is written stored, fixed-Huffman or dynamic-Huffman, whichever counts
  fewest bits — an exact count of what each would emit, header included, not a
  heuristic.** The two outer choices are there for opposite reasons. Stored is the
  *floor*: with fixed Huffman alone a literal costs 8 or 9 bits, so uniformly random
  bytes come out at 8.4375 bits each, measured at **+5.44%** on 200 KB of noise —
  `rcp copy /tree tar://out.tar.gz` over an OCI layout or a photo library is exactly
  that input, and the `.tar.gz` came back *larger* than the `.tar` under a name that
  promises the opposite. A stored block costs five bytes per 64 KiB. Dynamic is the
  *ceiling*: a code fitted to the block's own histogram, with its lengths bounded at 15
  bits by package-merge rather than by perturbing the frequencies until a plain tree
  happens to fit. On the 400 KB 4-symbol corpus it takes the output from 179,942 to
  **120,430** (0.450 → **0.301**), and on 1,029,896 bytes of this crate's source and
  prose from 377,398 to **320,057** (0.366 → **0.311**).

- **The matcher is lazy, not greedy.** Having found a match it holds it, looks one byte
  further, and takes the later match instead if that one is strictly longer — buying a
  literal to cover more bytes. `>` and not `>=`: an equal-length match one position later
  is never better and usually sits at a greater distance. It costs a chain walk per byte
  rather than per match, bounded by taking any match of 32 bytes or more on the spot.
  Worth 2.7% on source and prose (320,057 → **311,493**) and 0.2% on the pathological
  4-symbol corpus — and **the symbol count goes UP** while doing it, from 73,851 to
  85,091, because spending literals is the mechanism rather than a side effect.

- **Members compress in parallel, and the bytes do not change.** Because members are
  independent and each is a pure function of its input, moving the work to a pool alters
  only which thread computes it — `-parallel` sets the worker count, an ordered queue
  restores submission order on the writing side, and at most one block per worker is in
  flight so memory stays bounded at roughly 4 MiB each. On 16 MB of source and prose
  across 4 cores: **1.27 s → 0.38 s at 4 workers (3.3×)**, output byte-identical at 1, 2,
  4 and 8 workers. Eight workers buy little here because that input is only four members.

- **The stream is a run of independent gzip members**, one per 4 MiB of input, which is
  what `pigz -i` writes and what RFC 1952 §2.2 allows. `deflate()` compresses a whole
  slice, so wrapping the archive in one member would mean holding the archive in memory —
  the wrong shape for a tree of any size. Each member starts with an empty match window,
  which costs a fraction of a percent at 4 MiB and is exactly the property that lets a
  reader decode members in parallel.
- **Reading sniffs the magic bytes; writing reads the name.** A file that does not exist
  yet has no bytes to sniff, so on create the name is binding — and a name saying a
  wrapper rcp does not write (`.bz2`, `.xz`, `.lz`, …) is refused before the file is
  made, rather than quietly given a plain tar. That is the same defect under a different
  suffix.

**`.tar.zst` is read and written the same way**, through the crate's own zstd codec (the
one `-compress.codec zstd` uses on the wire). A name ending in `.zst` or `.tzst` writes
one zstd frame per 4 MiB of input, which is the zstd equivalent of the gzip members above:
concatenated frames are one file by definition (RFC 8878 §3.1), `-parallel` compresses
them on a pool with byte-identical output, and `-rsyncable` cuts them where the content
says to. Reading sniffs the frame magic and also a leading skippable frame, which is how
`pzstd` begins every archive. A contract arm reads archives made by the reference `zstd
-19` and by `pzstd`, and has the reference `zstd -t` and `tar --zstd -xf` read what rcp
wrote.

**The ratio is gzip's, not zstd's, and the numbers say so.** On 3.3 MB of this crate's
source and docs: rcp's `.tar.zst` is 991,256 bytes, rcp's `.tar.gz` is 979,640, the
reference `zstd -3` is 922,291 and `zstd -19` is 705,977. The encoder has one greedy match
search and 4 MiB frames with no shared history; what `.tar.zst` buys today is the format,
for a consumer that wants zstd, and a decode that is not slower than gzip's. Before this,
a `.tar.zst` source was refused as "not a tar archive" and a `.tar.zst` destination was
refused by name.

The correctness claim is against the reference implementation, not a round trip:
`the_system_gzip_reads_what_this_encoder_wrote` puts rcp's output through the system
`gzip -d`, `gzip -dN` and `tar xzf`, and a contract arm packs a real tree to
`tar://out.tar.gz` and has `tar -xzf` unpack it. An encoder and a decoder that share a
misunderstanding agree with each other perfectly, so rcp reading back its own archive
would have proven nothing — it sniffs the magic and falls through to a plain tar. The
shapes deliberately include a run long enough to force **length 258** (which RFC 1951
lets you encode two ways, and rcp's own decoder accepts both) and a match at **exactly
the 32 KiB window edge** (distance 32768, the largest legal one), because those are the
cases where picking the wrong code still round-trips locally.

**How far it is from `gzip`, measured so the attribution is not guesswork.** Comparing
against `gzip -6` cannot say whether the difference is the matcher or the code table,
because `gzip` changes both at once. zlib's `Z_FIXED` separates them — on a 400 KB
4-symbol corpus, `Z_FIXED` level 1 is 0.533, `Z_FIXED` level 9 is 0.402, and the default
level 9 is 0.288. So **zlib's strongest matcher, restricted to fixed blocks, still only
reaches 0.402** — the code table was doing most of the work, which is why dynamic blocks
were the thing worth building and no chain depth substituted for them.

| | output on 400 KB | ratio |
| --- | --- | --- |
| rcp, greedy + fixed blocks (where this started) | 179,942 | 0.450 |
| `Z_FIXED` level 9 — strong search, fixed coder | 160,932 | 0.402 |
| rcp, + dynamic blocks | 120,430 | 0.301 |
| **rcp, + lazy matching** | **120,139** | **0.3003** |
| system `gzip -6` | 117,337 | 0.2933 |
| zlib default level 9 | 115,367 | 0.2885 |

Both halves of that are now done, and the second one barely moves this corpus while
mattering on real input — worth stating, because the 400 KB fixture is deliberately
pathological and is not the thing anyone compresses:

| | rcp | `gzip -6` | gap |
| --- | --- | --- | --- |
| 400 KB, 4-symbol alphabet | 120,139 (0.3003) | 117,337 (0.2933) | 2.4% |
| 1,029,896 B of source and prose | 311,493 (0.3025) | 308,452 (0.2994) | **1.0%** |

Note 0.402 was never a floor for fixed-Huffman encoders — it is one strong matcher's
result, and an optimal parser (zopfli, libdeflate) emitting fixed blocks could go lower.
The remaining gap is an optimal parse, which rcp does not attempt.

What a stream has no room for is refused in the open. There is no rename, no removal and
no editing in place: `delete` on an archive is refused rather than half-done. **An archive
that already has something in it is never rewritten** — writing one truncates from the
start, and a truncated destination lists as empty, so no plan could show the loss and
`-requireconfirm` could not catch it; the refusal is the only honest answer. A tar
destination is a single stream, so its files are written one at a time whatever
`-parallel` says: measured before that was enforced, a copy with the default worker count
produced an archive GNU tar read as far as the first interleaved member and then reported
"Skipping to next header" for the rest. And the archive is not a tar until the two zero
blocks at the end are written, which is `sync`'s job — so a tar destination is one of the
two whose `sync` publishes, beside a registry, and a fleet cannot write one.

Holes ARE carried, as **GNU pax 1.0 sparse members** — a `GNU.sparse.*` extended header
naming the real file and its real size, and a decimal extent map at the front of the
member's data. `tar --sparse --format=posix` writes the same shape, and reads this one: a
64 MiB file holding 128 real bytes packs to **9,216 bytes** rather than 67,113,472, and
`tar xf` extracts it sparse.

The limit is where the decision has to be made. A member's header precedes its bytes and a
sparse header needs the whole extent map, so the writer holds the first **8 MiB** waiting
to see a hole; a file solid for longer than that is written flat even if a hole comes
later — correct, and larger.

**Reading covers all four encodings GNU tar can write**, and it has to: only 1.0 carries
`GNU.sparse.major`, so a reader that gates on that key treats 0.0 and 0.1 as ordinary
members, reads the extents as the whole file, and reports success on a file that is not
the source.

| form | where the map lives | written by |
| --- | --- | --- |
| old-GNU | typeflag `S`, four pairs in the header plus extension blocks | `tar --sparse` (the default) |
| pax 0.0 | repeated `GNU.sparse.offset` / `GNU.sparse.numbytes` records | `--sparse-version=0.0` |
| pax 0.1 | `GNU.sparse.map`, comma-separated | `--sparse-version=0.1` |
| pax 1.0 | a decimal map at the front of the member's data | `--sparse-version=1.0`; what rcp writes |

Extended attributes are not written (pax can carry `SCHILY.xattr.*`; this build does not),
and a run that asks for them is told.
