# Compression on the ssh stream

`-compress` asks an `ssh://` far side for LZ4 on the data payloads (reads, writes,
streamed segments, delta literals; never metadata or holes, which are already small).
It is agreed in HELLO and applied one block at a time: each payload carries a flag saying
whether it is raw or compressed; a block is probed on its first 64 KiB and goes raw
without the rest being tried when the probe does not shrink below nine tenths; after
eight such blocks in a row the next sixty-four go raw with no probe, then one is probed
again, and if it does not pay the pause repeats at once. So text costs a compression pass
per block and shrinks, and a tree of already-compressed data settles at one 64 KiB probe
per sixty-five blocks and crosses at its own size. The
codec is the LZ4 block format in this crate, so there is nothing to install on either
side, and a serve from before this option answers the request with a no and the run
proceeds uncompressed. `-loglevel DEBUG` says which of the two happened.

`-compress.codec deflate` swaps in the DEFLATE encoder this crate already carries for
`.tar.gz`, and `-compress.level 1..9` chooses how hard it works on both sides. On 4.5 MB
of log-shaped text pulled through a counting stand-in, the serve sent 793,848 bytes at
level 1 and 599,604 at level 9.

`-compress.codec zstd` swaps in a zstd encoder and decoder written for this crate, again
with nothing to install: frames carry Huffman-coded literals and FSE-coded sequences and
are read by `zstd -d`, and the decoder reads raw, RLE, Huffman and treeless literals, one
bitstream or four, predefined / RLE / FSE-compressed / repeated sequence tables, and the
three repeat-offset codes. Interop is asserted in both directions against `/usr/bin/zstd`: five corpora at three
levels, plus a boundary sweep over the lengths where the format changes shape (0, 1, the
1 KiB single-stream/four-stream literals split, either side of the 128 KiB block edge;
text, single-byte runs, incompressible noise, skewed wide alphabets, and blocks whose
literals are nearly one byte) with and without a frame checksum, at levels -3 and -19 -- **280 reference
frames** in the sweep alone. The frame's XXH64 content
checksum is both **written and verified**: the reference recomputes it on every frame this
encoder produces, and refuses one whose content has been altered. The skewed corpora are
there for a measured reason -- without them the sweep never once entered the FSE-coded
Huffman-weight decoder, so the arms said nothing about it. **Three more branches were at
zero when somebody finally counted** -- treeless literals, single-stream Huffman and
repeat-mode sequence tables, all of which parse attacker-supplied bytes and none of which
any reference frame had ever reached. A large skewed corpus (several blocks in one frame,
so the reference starts reusing trees and tables) and two small ones (a literals section
under 1 KiB, the only size the single-stream form can describe) fix it, and the sweep now
fails if any of the four stops being exercised.

**Concatenated frames used to be silent data loss.** Given two frames in one buffer this
decoder returned the first and stopped, with no error, where `zstd -d` returns both --
measured at 320 bytes against 700. Every frame is decoded now, bytes that are not a frame
are a refusal rather than a shrug, and skippable frames are skipped in all five
arrangements the reference accepts them in (first, middle, last, two adjacent, and an
empty payload).

**A frame that names a dictionary is refused.** Stepping over the header's
`Dictionary_ID` is the tempting shortcut, and it is silent tolerance: the blocks after it
decode, the checksum over them matches, and the decoder returns bytes on an input `zstd -d`
will not touch -- measured, the reference answers `Decoding error (36) : Dictionary
mismatch` and zero bytes where the shortcut returned 1,024. Same class as the multi-frame
defect. A hostile corpus does not catch it on its own, because its bit flips *do* set the
dictionary flag but never insert the ID, which shifts every later field and makes both
decoders refuse for unrelated reasons; a well-formed dictionary frame has to be built, and
is, at all three ID widths. What is still not detectable here: a dictionary used with
its ID omitted, which the format permits and which no header distinguishes from an
ordinary frame -- the reference cannot tell either.

**A declared window over 128 MiB is refused, and that was laxness until it was measured
from the other direction.** Every check here had been asking what this decoder refuses
that `zstd -d` reads. Asking the inverse -- what does the REFERENCE refuse that we read --
found a frame from `zstd --ultra -22 --long=31` that decoded here and got
`Window size larger than maximum : 2147483648 > 134217728` there. The boundary is
measured on both sides: a hand-built single-segment frame declaring exactly `1<<27`
decodes in both, and one declaring 200,000,000 is refused by both. What it costs is said
rather than hidden: the reference's cap is a *default*, so `zstd -d --long=31` reads
frames this now refuses. That trade is made this way round because the peer running
`zstd -d` with no flags is the common case. It costs this codec's own output nothing --
a wire frame is at most 16 MiB.
Hostile input is checked against the reference too, not just for panics: over 4,710
corrupted, truncated and random inputs, **129 are accepted and byte-identical to the
reference, none are accepted only by us, and four are refused only by us** -- all four
because RFC 8878 reserves the low two bits of `Symbol_Compression_Modes` and libzstd
ignores them. A refusal the reference disagrees with fails that arm unless it names a rule
like that one. Accepting where the reference refuses fails it too, and that zero is a
measurement rather than a counter nobody has seen move: removing the dictionary refusal
moves it from 0 to 3, so the zero means the corpus contains inputs that would expose laxness
and none of them do. A planted case would not serve: a frame with trailing bytes that the
decoder read to the frame end looks like one, but that behavior is a defect, and fixing it
leaves such a counter with no subject at all. The same corpus is required to **reach** eight
named conformance refusals (it reaches 24 distinct ones in total); a check that stops
firing fails by name, which is how this codec keeps finding code that was argued about
rather than run.
Pushing the same 4.5 MB through the counting stand-in:
plain ~4,537,400 bytes, lz4 ~1,118,400, **zstd ~605,000**, deflate ~602,600. (The last
digits move by a few bytes between runs because the count includes the request paths, and
the scratch directory's name changes; the comparison is stable, the units digit is not.)

Getting there was encoder work rather than format work, and each step was measured on this
same arm: lazy matching 960,872 -> 856,164, FSE sequence tables built from the block's own
symbol counts 856,164 -> 630,260, repeat offsets 630,260 -> 605,008. A deeper match chain
was tried and reverted: 64 instead of 32 doubles the search and bought 0.16%.
