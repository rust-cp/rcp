# Design notes

This document traces rcp's design to what the literature and comparable tools actually
do, records what rcp implements and plans, and gives the reasoning, measurements and
rejected alternatives behind each design decision. The literature survey is dated
2026-09-21. Every survey entry names its source; where a claim could not be verified from
the source itself it says so.

## Literature survey

### Content-defined chunking and delta synchronization

- **FastCDC** (Xia et al., USENIX ATC 2016; extended in IEEE TPDS 2020) replaced Rabin
  fingerprinting with a Gear rolling hash, cut-point skipping below a minimum size, and
  "normalized chunking" to narrow the chunk-size distribution. About 10x the throughput of
  Rabin-based chunking at nearly the same deduplication ratio.
  [usenix.org/conference/atc16/technical-sessions/presentation/xia](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia)
- **A Thorough Investigation of Content-Defined Chunking Algorithms** (arXiv 2409.06066,
  v3 August 2026) compared the leading chunkers on throughput, deduplication ratio, average
  chunk size and variance. It recommends **Gear with normalized chunking** as the practical
  choice (window 32 bytes, bit threshold `log2(target - window)`, NC-1..NC-3), and finds
  that normalization reduces variance with only marginal loss of deduplication.
  [arxiv.org/abs/2409.06066](https://arxiv.org/abs/2409.06066)
- **VectorCDC** (arXiv 2508.05797, v2 January 2026) accelerates hashless chunkers with
  SIMD; 8-26x over previous vector-accelerated chunkers. Relevant as the ceiling, not as a
  requirement: Gear at ~600 MiB/s per core is about 4.8 Gbit/s, ahead of the 1 and 10
  Gbit paths rcp usually moves data over and behind a 25 or 100 Gbit one, where chunking
  would want either VectorCDC or a core per stream.
  [arxiv.org/abs/2508.05797](https://arxiv.org/abs/2508.05797)
- **Dsync** (Xiao et al.) and **NetSync** (IEEE TPDS 2022) redesign rsync's delta
  protocol around CDC: the weak hash **FastFp** is the sum of the Gear rolling hashes
  produced while chunking, so it costs nothing extra; strong hashes are computed only for
  weak-hash matches, and the protocol exploits locality. Both are several times faster
  than rsync's byte-sliding window at similar bandwidth savings.
  [lingfenghsiang.github.io/docs/DSync.pdf](https://lingfenghsiang.github.io/docs/DSync.pdf),
  [NetSync (TPDS'22)](https://www.thucloud.com/zhenhua/papers/TPDS'22%20NetSync.pdf)
- **SkySync** (USENIX FAST 2026) uses the Dsync workflow as its baseline and describes it
  step by step: client chunks and sends weak checksums with chunk metadata; the server
  chunks its copy, matches weak checksums, computes strong checksums for matches only and
  returns them; the client confirms with its own strong checksums.
  [usenix.org FAST'26 prepub](https://www.usenix.org/system/files/conf%C3%A9rence/fast26/fast26spring-prepub_zhang-zhihao.pdf)
- **Chunking attacks on backup services** (arXiv 2504.02095, April 2025) show that CDC
  parameters leak through chunk sizes when an attacker can observe them. For rcp the
  chunk boundaries never leave an authenticated ssh channel, and the Gear table is not a
  secret; noted so nobody later treats the chunker as a confidentiality mechanism.
  [arxiv.org/pdf/2504.02095](https://arxiv.org/pdf/2504.02095)

### Online tuning of parallelism

- **Marlin** ("Use Only What You Need: Judicious Parallelism for File Transfers in High
  Performance Networks", Arifuzzaman and Arslan, ACM ICS 2023) separates read, network and
  write parallelism and tunes each with online gradient descent, on the observation that one
  parallelism level for all three overburdens the ones that need less.
  [dl.acm.org/doi/10.1145/3577193.3593722](https://dl.acm.org/doi/10.1145/3577193.3593722)
- **FastBioDL** (arXiv 2508.05511, August 2025) frames a parallel downloader as online
  optimization: a utility function of throughput and stream count, gradient descent on the
  number of concurrent streams, up to 4x over static tools.
  [arxiv.org/abs/2508.05511](https://arxiv.org/abs/2508.05511)
- **AutoMDT** (arXiv 2508.05546, SC'25 workshops) and **Elastic Data Transfer Optimization
  with Hybrid Reinforcement Learning** (arXiv 2511.06159) continue the line; Globus's static
  concurrency loses to the online tuners in every table shown.
  [arxiv.org/abs/2508.05546](https://arxiv.org/abs/2508.05546),
  [arxiv.org/abs/2511.06159](https://arxiv.org/abs/2511.06159)

### Integrity hashing

- TeraCopy's authors recommend **xxHash3 or BLAKE3** for copy verification and MD5 or
  CRC32 only for interchange; BLAKE3 runs at 4-7 GB/s per core on recent x86-64, SHA-256
  with SHA-NI at 1.5-2.5 GB/s, portable SHA-256 at 300-500 MB/s.
  [codesector.com/how-to/choose-checksum-file-format](https://codesector.com/how-to/choose-checksum-file-format)
- FIPS 140-3 approves only SHA-2 and SHA-3; BLAKE3 is not on the list. So BLAKE3 is the
  fast option and SHA-256 stays the default where a published spec names it. That is a
  statement about the algorithm: rcp's SHA-256 is its own code, not a validated module,
  and a deployment that needs a validated module needs one from outside this crate.
  [devtoolspro.org SHA-256 alternatives 2026](https://devtoolspro.org/articles/sha256-alternatives-2026-guide/)

### What comparable tools ship

- **rsync 3.5.0** (August 2026) is a security release (33 fixes); its data path is
  unchanged since 3.2: xxh3/xxh128 checksums, zstd and lz4 compression, byte-sliding
  delta transfer. No copy_file_range, no CDC.
  [rsync NEWS](https://download.samba.org/pub/rsync/NEWS.md)
- **rclone 1.75.1** (September 2026): dozens of cloud backends, multi-thread transfers for
  capable backends, a hasher overlay caching checksums, an sftp host-key pinning flag.
  Go, no delta transfer.
  [rclone changelog](https://rclone.org/changelog/)
- **wcp** (io_uring file copy) measured 2.6 GB/s against cp at 1.2 GB/s and rsync at
  0.6 GB/s locally, at the cost of portability and memory.
  [github.com/wheybags/wcp](https://github.com/wheybags/wcp)
- **QUIC**: ESnet's guidance is that transfer tools have not adopted it, that the HTTP/3
  stacks they measured run 2-5x slower than HTTP/2 on 10G links because QUIC lives in user
  space, and that HPN-SSH is the practical answer on high-RTT paths. Two qualifications:
  those are measurements of particular implementations at one link speed, not a property
  of the protocol; and HPN-SSH is a patched OpenSSH at both ends, so it is an option a
  site can choose, not something rcp can assume. What rcp does about high-RTT paths on
  stock OpenSSH is open several sessions (one per worker) so the aggregate is not bound
  by one channel's window. The QUIC transfer tools on GitHub are small peer-to-peer
  projects (quic-send, quicfiletransfer).
  [fasterdata.es.net/data-transfer-tools/quic](https://fasterdata.es.net/data-transfer-tools/quic/)

## What rcp does

The base: io_uring on the local path, `copy_file_range` (a reflink where the filesystem
offers one), sparse files by extent and by zero detection, pipelined NFS v3 and v4.0 with
Kerberos, S3 and HDFS clients with no SDK, SHA-256 verification with SHA-NI, a catalog for
resume and sync, and `-nodes` scale-out over ssh. Measured against the literature, that base
lacked a fast non-FIPS hash, a delta protocol, an rcp-to-rcp transport that a delta protocol
can run on, rate limiting, and any online tuning of parallelism. The roadmap below closes
those gaps and adds endpoints and an agent interface.

## Roadmap

Each item names the test that decides it is done.

| item | what | done when |
| --- | --- | --- |
| BLAKE3 (done) | BLAKE3 through the official `blake3` crate; `-blake3` beside `-sha256` | official test vectors pass; incremental equals one-shot at every split; large updates equal chunk-at-a-time ones |
| `-bwlimit` (done) | one token bucket over every reader | a 32 MiB copy at 8 MiB/s takes at least 3.5 s; without the option it does not |
| `-parallel auto` (done) | online gradient tuner within `[1, N]` -- on the worker count, and with the three-way tuner below, on read and write concurrency too | the DEBUG trajectory stays within bounds and settles, and names all three knobs; fixed `-parallel` is untouched |
| `ssh://` (done) | `rcp serve` on stdio, an `SshTree` adapter over it | copy, verify, sync, scan, chmod, delete, sparse files and hard links through a stand-in transport command; `-rcp.remote`; a transport that cannot start is refused; a listing of any size crosses in batches; a path outside the served tree is refused |
| delta sync (done) | `-delta`: Gear NC chunking and a strong hash, matched where the bytes are, over `ssh://` and in process (design notes below) | a 32 MiB file with 1 MiB changed moves as about 1.07 MiB of literals in every direction (measured); a new file moves in full; a shrunk file and a hard-linked destination come out right; a basis that changed after signing and a rebuilt file with the wrong digest are refused; an abandoned patch leaves nothing behind |
| `-compress` (done) | LZ4 block format on the `ssh://` stream, a raw-or-compressed flag per payload, agreed in HELLO with a graceful no from an older serve; a 64 KiB prefix probe before a block is compressed whole | round-trips; text shrinks; random bytes are passed through unchanged; after eight unprofitable blocks the next sixty-four go raw unprobed and one probe then decides whether the pause repeats (unit arm, with the probe timed against a whole-block pass); a payload claiming more output than LZ4 can produce from its bytes is refused before allocation; wire bytes measured through a counting stand-in transport (contract arm) |
| ssh read-ahead (done) | eight READs in flight on the `Read` path that `verify` takes; a seek discards the window | a unit arm over the in-memory channel shows the window on the wire before the first reply is consumed and the bytes in order across partial takes; a contract arm through a stand-in that adds 50 ms of latency each way verifies 16 MiB well under the sequential bound, with the latency itself measured on a scan as the control |
| `sftp://` (done) | SFTP v3 through OpenSSH's subsystem; pipelined reads (8 x 256 KiB) and writes (16 deep); zero runs as holes; second times; hard links refused unless `hardlink@openssh.com` (the core copies the file instead); no xattrs | a contract arm through a stand-in sftp server (paramiko over stdio, itself validated with OpenSSH's `sftp -D`): copy with a hard link, a symlink and a sparse file, verify, scan, copy back, sync, delete; the refusals are visible |
| `smb://` (done) | SMB2 as a `Tree`: dialects 0x0202/0x0210/0x0300 (deliberately **not** 0x0311, which needs the preauth integrity hash this does not compute -- signing, which it does, is required by SERVERS rather than by that dialect), NTLMv2 built from MD4/MD5/HMAC-MD5 checked against RFC 1320, RFC 1321, RFC 2202 and MS-NLMP's worked example; CREATE/CLOSE/READ/WRITE/QUERY_DIRECTORY/SET_INFO; a stat is the CREATE response rather than a second QUERY_INFO; delete goes through `FileDispositionInformation` so an empty-directory check lands where a server makes it; `reserve` declares the final length with `FileEndOfFileInformation` before the first write, because an SMB2 write lands at an absolute offset and a server is not obliged to extend a file to meet one past its end; credentials from `-smb.user` or `RCP_SMB_USER`, never from the URL; **message signing** (HMAC-SHA256 on 0x0202/0x0210, AES-128-CMAC with the SP800-108 KDF on 0x0300), armed by the server's SecurityMode bit, with AES and CMAC checked against FIPS-197 and RFC 4493 and the whole path measured against a Samba running `server signing = mandatory`. A share carries no POSIX mode, owner, symlink, hard link or xattr and the adapter refuses or reports rather than inventing; times cross both ways | a contract arm against impacket's `SimpleSMBServer`: copy in, the mtime read off the filesystem the share is a view of, verify with every check asked (modes, owners and xattrs reported as not compared, with a local destination as the control that the same check still fires where both ends keep them), a symlink refused by name, copy back, scan, sync moving exactly the one changed file, delete. Unit arms: the NTLM vectors with a control that uppercasing the domain gives a DIFFERENT key, a truncated response naming its field, a directory page whose next-entry offset points inside its own record refused rather than looped, a reparse point reported as neither file nor directory. A missing impacket is a SKIP that says so, not a pass. A second arm covers what the first does not reach, and it found two defects: an 8 MiB sparse file arrived as **4096 bytes** because `reserve` was a no-op and the server answered `Count = Length` for a write past the end that it silently skipped; and `STATUS_NO_SUCH_FILE` (0xC000000F, distinct from `STATUS_OBJECT_NAME_NOT_FOUND`) was unmapped, so a copy did not create its destination directory. Both are replanted and the arms required to fire |
| `oci://` (done) | the OCI Distribution API as an image-layout tree: registry-to-registry mirroring, registry-to-directory, directory-to-registry, content-addressed dedup, multi-arch indexes, token and basic auth, manifests pushed children-first at the end | a stand-in registry (tests/support/registry_stub.py, in memory, with the token dance and basic credentials) counts uploads: a mirror moves 3 blobs and 3 manifests, a second mirror of the same image uploads no blob and reads none from the source; a layout written from a registry has every blob named by its content and the same `index.json` bytes as the one that seeded it; a layout pushed with basic credentials verifies back with `-nomods`, and without it the times differ (the control); one tag reaches only its own blobs; delete leaves the repository without tags; wrong credentials, a missing repository and tag, and malformed endpoints are refused by name |
| `dav://` (done) | WebDAV (RFC 4918): `PROPFIND Depth: 1` walks, `GET` with `Range`, `PUT`, `MKCOL`, `DELETE`, `MOVE`, `COPY`; basic auth from an option or the environment, never from the URL; a purpose-built multistatus reader that refuses a DOCTYPE and resolves namespaces (only `DAV:` elements are read, whatever the prefix); statuses read per propstat; relative hrefs resolved; `Destination` absolute; `keeps_times` false, so the planner matches on size, and `verify` skips the same comparison and says so; HELLO carries that through a relay | a stand-in server that puts the collection's own entry first OR last and answers a 404 propstat per entry: copy, verify, scan, sync (exactly one file for one edit, direct and through `-via`), delete; quirks for a 206 from zero, a garbled 207, a `..` child, a foreign-namespace decoy, an RFC 2518 `Destination`, a rewritten href prefix -- each refused or ignored by name; credentials in a URL are refused by name; `chmod` refuses, through a hop too |
| fault injection (done) | a byte-cutting proxy in ssh's position kills the serve after N bytes in either direction, with a marker so a cut is distinguishable from a run that merely failed; no test-only code in the binary | a sweep of six cut points over a copy to `ssh://`: every copy fails rather than passes, every marker fires, every `resume -id` completes and verifies; the count of complete non-empty files at failure is 0 for at least one cut and strictly between 0 and all for another, so the sweep covered more than one phase; a cut point past the whole transfer is the control -- no marker, the copy passes on its own |
| `tar://` (done) | pack any tree into a tar stream and unpack one; an OCI layout to `oci-archive` as a case; sparse extents per the `tar://` sparse row below | a round trip reproduces modes, times and links, and `tar xf` reads what rcp wrote while rcp reads what `tar cf` wrote |
| `https://` (done) | an ordinary web server as a READ-ONLY tree. No protocol listing exists, so three conventions are read in order of how much truth they carry: a published `rcp-index.json` (this crate's own `scan -json`, the only one with a mode, a real mtime and a digest, and one request for the whole tree), nginx `autoindex_format json`, an Apache-style HTML page (a `HEAD` per file for size and date, as rclone's http backend does). `keeps_times` is true only for the index. Writes refuse by name -- `dav://` is the protocol that has them | the SAME fixture served all three ways, and the three results compared against each other as well as against the source, so a shared omission cannot pass; an HTML page carrying Apache's sort links, parent link and doubled icon-plus-text link, none of which becomes a file; a copy refused as a destination with the source half working as its control; a seek reissuing the GET with a `Range`, and a 206 from zero and a 200 to a ranged read each refused before a byte is placed |
| relay (done) | `-via ssh://hop`: the serve's session holds any adapter, HELLO carries an endpoint rather than a path, the hop opens it with its own environment and honors `RCP_ALLOWED_ROOTS`; `-via` is a `Runs` capability | a copy through the hop moves the same bytes as a direct one and a relayed scan lists the same; a `Kept` from a registry behind the hop arrives as kept; a chain of two hops verifies against the source; an unreachable endpoint names the hop and the endpoint; a railed hop refuses what is outside its roots; a channel that joins after the run deleted the last tag still opens (ATTACH, forced order: the tags go, a reader holds the only channel, the next request dials), with HELLO to a serve that predates it; a push into a new repository through the hop is read back complete, written through one serve |
| delta weak hash (done) | the sum of the Gear hashes as a free weak fingerprint (Dsync, NetSync); strong digests only for weak matches; signatures streamed in batches | all three are implemented: `Chunk.weak` is the running Gear sum, so the fingerprint costs nothing beyond the chunking; `Matcher` indexes by it and computes a strong digest only for a weak hit; and signatures cross as `SIG_BATCH` frames of 2048 ended by `SIG_END`, bounded at 8M per setup. Arms: a crafted weak collision still yields a correct file; a source sharing nothing with the basis computes **zero** strong digests, with the control that an identical source computes one for every chunk. See "Weak hash and streamed signatures" below for why a wire-byte criterion could not measure the batching |
| SIMD chunking — **lane parallelism not adopted; a stable 1.45x from a two-stage scan** | lane-parallel Gear behind runtime detection was the plan. Four runs of the same binary put four independent streams at **0.99x, 1.02x, 1.17x and 1.26x** over one -- a spread that straddles 1.0, so on this machine the lane gain cannot be told apart from noise. What is stable across the same four runs is DECOUPLING the scan from the length rules: **1.45x, 1.45x, 1.47x, 1.51x**, from removing per-byte branches rather than from any parallelism | identical cut points AND identical weak hashes to the scalar chunker on random, log-line, text, zero-run, constant and short input at three parameter sets; the lane scan agrees candidate-for-candidate and sum-for-sum with the single-stream one, with a cold lane as the control. See below |
| three-way tuner (done) | read and write concurrency tuned separately from the worker count (Marlin), within `-parallel auto[:N]`. A worker holds a read permit while the source produces bytes and a write permit while the sink takes them, never both, so the two caps are independent without a channel, a second buffer copy or extra threads | a stand-in with a CONTENDED sink settles with fewer writers than readers (a merely slow sink wants MORE writers, see below); the mirror-image landscape as the control; fixed `-parallel` carries no stages at all |
| interchange (done) | `-xxh3` / `-xxh128` digests (rsync 3.5, rclone manifests), and `-compress` codecs negotiated in HELLO with LZ4 the default. `-compress.codec deflate`, and `-compress.codec zstd`, which writes real zstd frames and reads any the reference writes: FSE entropy coding, Huffman literals and a sequence format in both directions, in a crate whose only dependencies are cryptography | digests: vectors pass. Codecs, measured through the same counting stand-in on 4.5 MB of log-shaped text: **plain ~4,537,400 / lz4 ~1,118,400 / zstd ~605,000 / deflate ~602,600 bytes** -- so both slow codecs cross about 1.85x fewer bytes than lz4 and land within half a percent of each other. zstd's ratio comes from its SEARCH, not its format: lazy matching, FSE tables built from each block's own symbol counts, and repeat offsets, in that order of payoff (see below). Each is asserted to beat plain first, or the comparison would be between failures; a serve that ignores the requested codec is the replant, and it brings them within 8 bytes and fails the arm by name. `-compress.codec brotli` is refused rather than quietly falling back. Interop is checked against `/usr/bin/zstd` in BOTH directions -- the reference decodes what this encoder writes, and this decoder reads 15 reference frames (five corpora x three levels) byte-for-byte, plus a 280-frame boundary sweep whose skewed and narrow-alphabet corpora exist because without them the sweep never enters the FSE-coded Huffman-weight decoder. The level knob exists for deflate: `-compress.level 1..9`, proved to reach the far side's encoder by a PULL (level 1 sends 793,848 bytes out of the serve, level 9 599,604), with level 6 asserted byte-identical to the encoder without a level knob; on lz4 and zstd a level is REFUSED rather than ignored |
| digest cache — **done, for `scan` only** | per-file digests beside the catalog keyed by size, mtime, inode and algorithm (rclone's hasher overlay), behind `-hashcache`. `verify`, `copy` and `sync` deliberately do NOT consult it | 128 files / 1.07 GiB, warm page cache: 0.22 s and 128 files read becomes 0.004 s and **0** files read, same digests. The arms assert the FILE COUNT, not the clock, and one asserts the stale answer the mtime key cannot avoid |
| `rcp://` and `rcps://` (done) | `rcp serve -listen ADDR` speaks the same frames over a socket, and `rcp://host:port/path` is the endpoint. No ssh, no child process: the socket IS the channel. `rcps://` is that socket inside TLS, and **only MUTUAL TLS (`-tls.clientca`) lets a serve bind anything but loopback** -- a server certificate encrypts the stream without establishing who connected, which is not what the loopback rule was standing in for | a real tree copies to a listening serve and back with identical bytes and a clean `verify`, plaintext and over TLS; a path outside the roots is refused and creates nothing; the listener refusals (no roots, not loopback, half an identity, a client authority with nothing to present) and the endpoint refusals (no port to guess, no user to pretend to check); `check_listen` decided for loopback, wildcard and routable addresses in v4 and v6; a wildcard bind refused WITH a server certificate and accepted with a client authority, which is the pair; three TLS refusals each asserted by its own rustls reason (`CertificateRequired`, `UnknownCA`, `UnknownIssuer`) with nothing created; a two-listener `-via` chain, replanted against the ssh-only rule |
| block pipeline (pigz) — **done for the tar pack path** | N compressors over the 4 MiB gzip members the writer already emits, one ordered writer, at most one block per worker in flight. Dictionary priming and the ssh `-compress` path are **not** done: priming would make a member depend on its predecessor, which is exactly the independence this relies on, so it is a different design rather than an increment | measured 1.27 s -> 0.38 s at 4 workers on 4 cores over 16 MB, and the output is BYTE-IDENTICAL at 1, 2, 4 and 8 workers -- asserted, because a pipeline whose result depends on scheduling is the defect this is shaped to refuse |
| rsyncable blocks (pigz `--rsyncable`, `-i`) — **done**, as `-rsyncable` | gzip MEMBERS cut at the Gear chunker's boundaries. They were already independently decodable, so `-i` came free with the 4 MiB framing; what was missing is that the boundaries were at fixed INPUT offsets | measured end to end through `rcp copy DIR tar://out.tar.gz -rsyncable`, 12 MB of log-like text, a 25-byte insertion at offset 3000: **fixed cuts keep 0 of 3 members, content-defined cuts keep 25 of 27**. `gzip -t` and `tar tzf` accept both. Ratio cost 0.47% |
| `tar://` sparse (done) | holes carried as GNU pax 1.0 sparse members, written and read; reading covers ALL FOUR encodings GNU tar writes (old-GNU `S`, pax 0.0, 0.1, 1.0) | a 64 MiB file holding 128 bytes packs to **9,216 bytes** against **67,113,472** written flat; `tar xf` extracts it as one file of the right name, length and content, on disk **sparse**; rcp reads a member GNU tar wrote and the hole survives; a tree with no holes acquires no sparse header and does not shrink; the stated 8 MiB decision limit is asserted rather than hoped for; four map refusals and two controls; the four-encoding read sweep asserts its own count. See below |
| parallel gzip DECODE (done) | `gunzip_with(data, limit, workers)`: candidate member starts found by scanning for the magic, inflated speculatively on N threads, and the output decided by walking the member chain exactly as the serial path does | 83 MB of log text in an 18.6 MB archive: **0.748 s at 1 worker, 0.471 s at 2, 0.328 s at 4** (109 -> 256 MiB/s, 2.34x on 4 cores), byte-identical at 1/2/4/8 asserted; a counter proves the parallel path was ENTERED, which caught a gate that compared a threshold against the COMPRESSED size and sent every test serial; a complete valid gzip member hidden inside another is refused by the chain alone, and that arm was written because the obvious one passed two replants it should have failed. See below |
| gzip (done) | deflate and inflate in the crate's own code, gzip framing with CRC-32, multi-member streams both read and written. The encoder is LZ77 over a 32 KiB window with a bounded hash chain, choosing **stored, fixed-Huffman or dynamic-Huffman per block** on an exact bit count of each; dynamic code lengths are bounded at 15 bits by package-merge, which is optimal under the limit. A `tar://` destination named `.tar.gz` is compressed as a run of 4 MiB members, so peak memory is one block rather than the archive | the system `gzip -d`, `gzip -dN`, `gzip -t` and `tar xzf` read what rcp wrote, and rcp reads gzip's and pigz's; a corrupted CRC is refused in both directions; the code lengths satisfy Kraft exactly and never exceed the limit, with an unlimited tree as the control; incompressible input does not expand materially (stored blocks cost ~5 bytes per 64 KiB and an 18-byte member per 4 MiB, so a `.tar.gz` of already-compressed files is a hair LARGER than the `.tar`; the arm bounds it at +1%). Parallel decode of pigz's `-i` boundaries is the row above. Lazy matching: `Level::lazy` drives the match decision at `deflate.rs:895`, every level from 4 up sets it, and the arm at `deflate.rs:1894` carries a measured table comparing greedy against it |

### Agent interface

A copy tool an agent can drive needs, in this order: output it can parse, a description
it can discover, bounds it cannot argue past, and a way to let go of a long job.

| item | what | done when |
| --- | --- | --- |
| `-json` (done) | one JSON object per line on stdout: an entry per completed item with its digest, a difference per `verify` finding, a warning, an error with a stable code from a closed set, a done with that command's counts; every human line moves to stderr; the exit code is unchanged | a contract arm parses every stdout line with a strict reader (a field that is not a string, number or boolean fails it), counts the entries by kind and finds the same numbers in the done event and in the text run's summary; a missing endpoint reports `notfound` and a mistyped option `usage`, which is the control that the code is not a constant; a bare `scan` emits the summary alone and `-l` emits the entries; a run without `-json` emits no event at all |
| `rcp describe` (done) | commands, options, endpoint schemes with a capability table, the events, the error codes and the exit codes, as one JSON object; the option list is built from the parser's own tables | `tests/describe.rs`: an option with no summary, a summary for an option the parser dropped, a described command that is not in the dispatch, or a transports line that disagrees with `version`, each fails the build, and each arm has a control. The capability columns are checked for being informative rather than constant |
| safety rails (done) | `-allow ROOT` (repeatable, or `RCP_ALLOWED_ROOTS`), `-readonly`, and `-confirm DIGEST` with `-requireconfirm` for any run that would remove or overwrite, where the digest is what a dry run of the same command printed | the right digest proceeds and the wrong one is refused; a changed tree invalidates a digest that was right; the refusal does not contain the digest it wanted, so the plan must be read; `-readonly` refuses every command `describe` marks as writing; an endpoint outside the roots is refused with the stand-in transport's log still empty, and the control with that root allowed reaches it. The control on the environment variable found the separator defect |
| `rcp mcp` (done) | a JSON-RPC 2.0 stdio server in the crate's own code: initialize, ping, tools/list, tools/call over nine tools, each running rcp itself as a child with `-json` so the protocol channel stays clean and every call inherits the server's rails plus `-requireconfirm` | a contract arm drives it over pipes: the handshake, a notification that takes no reply, ids echoed in their own type, a copy into empty space that needs no plan, the same copy refused with the tool to call named, plan then confirm accepted and a wrong digest refused, delete refused until `rcp_count`'s digest, the server's `-allow` and `-readonly` reaching every call, an invented option and a smuggled endpoint and a self-set rail each refused, and malformed calls answered as JSON-RPC errors rather than tool failures |
| jobs (done) | `rcp job start\|list\|status\|wait\|cancel\|log\|forget` with a job file and the catalog, so a tool call returns and the agent polls | a throttled copy starts, shows running, cancels, resumes and verifies; an unknown id is a clean error |

## Delta sync

The `-delta` design, decision by decision:

- **Direction, and placement.** Destination signatures travel to the source; matching
  bytes are copied at the destination. That is Dsync's shape and the right one for a copy
  tool. The matching has to run **where the source bytes are**, as an operation on the
  source tree (`delta(rel, signatures) -> instructions`): the local adapter matches in
  process, the ssh adapter sends the signatures to its serve and gets the instruction
  stream back. Matching in the core would pull every source byte across the wire for an
  `ssh://` source and save nothing on the path that matters. Between two ssh endpoints the
  client is a relay, as the README says.
- **Two tiers.** A single strong hash per chunk on both sides looks cheaper than a second
  tier when BLAKE3 runs at several GB/s. Measured, it is not: an 8 KiB chunk is far too
  small for BLAKE3's tree parallelism, so the per-chunk pass ran at 266 MiB/s against
  1179 MiB/s for the whole file, and was **82%** of the source side's hashing (50% under
  SHA-256, 38% under xxh3). The Gear fingerprint the chunker already computes is free, so
  it filters and the strong digest decides, as Dsync describes; a source chunk whose
  fingerprint no signature carries never has its strong digest computed. The weak tier adds
  eight bytes per signature on the wire, 0.1% of the file. It is protocol `VERSION` 2,
  unconditionally, because the serve refuses a version it does not speak, by name.
- **Chunk size scales with file size**, the way rsync's block size does, so a terabyte
  file does not ship a gigabyte of signatures. The average chunk follows the square root
  of the file (rsync's rule) rather than a fixed divisor, so a terabyte file has a million
  chunks and a petabyte one 256 million rather than a billion.
- **Patch to a temporary file, then rename.** In-place patching corrupts when a chunk is
  read from an offset that an earlier instruction already overwrote, and it rewrites every
  other hard link of the destination inode. The temporary file is also what makes an
  interrupted patch leave the old file intact. It is created exclusively under an
  unpredictable name (a planted symlink or a peer on a shared export with the same pid gets
  a refusal, not a shared write), with mode 0600, and the directory is synced after the
  rename when `-fsync` asks.
- **Basis identity and a final digest.** The signatures name the basis (size, mtime,
  inode). The basis is signed, then opened and checked, so the identity check covers the
  signing window; the patch refuses a basis that changed after signing, and the
  reconstructed file's whole-file digest is checked against the source's before the rename.
- **Shorter source.** The instruction stream ends with the final length; a destination
  longer than the source is truncated by construction, never by omission.
- **Fallback.** A patch that cannot proceed for any reason falls back to a whole copy.
- **Holes.** Holes are chunked as zeros on both ends and the zero chunks go out as holes,
  so a sparse file matches itself.
- **Bounds.** A signature is 44 bytes inline (a million of them, the most a terabyte file
  produces at the largest chunk, is about 44 MiB per side plus the map). A serve refuses
  more than eight million signatures for one file and more than sixty-four setups per
  session.

### Weak hash and streamed signatures

- **The fingerprint is free.** `Chunk.weak` is the running sum of the Gear hashes the
  chunker computes anyway, which is exactly Dsync's FastFp. No second pass.
- **The strong digest is the second tier.** `Matcher` indexes signatures by `(weak)` and
  computes a per-chunk digest only when a fingerprint hits. The module header carries the
  measurement above that motivates it.
- **Signatures stream.** `SIG_BATCH` frames of `LIST_BATCH` = 2048 signatures under one
  sequence number, like listings, terminated by `SIG_END`, with `MAX_SIGNATURES` = 8M
  bounding one delta setup at about 350 MiB.

**A wire-byte criterion cannot measure the batching; the contract suite does.** "Signature
bytes on the wire drop about 8x" is a statement about the weak tier; a build that sent only
the first batch would satisfy it and silently lose every chunk past the 2048th. What holds
the line is `tests/contract.rs`: a 32 MiB fixture chunks at an 8 KiB average into ~4096
chunks, which is **two** batches, and the test asserts a 1 MiB edit moves between 1 MiB and
1 MiB + 128 KiB of literals. Drop the second batch and the literal count jumps by megabytes.
The multi-batch path is not merely executed there — it is load-bearing for an assertion.

**The index cannot stream, and that is not a gap.** `Tree::signatures` returns a `Vec` and
`Matcher::new` takes a slice, so the list is materialized on both sides. That is inherent:
a matcher is a lookup table, and you cannot index against signatures you have thrown away.
Transmission streams; the index does not, and the `MAX_SIGNATURES` cap is what bounds it.

### Not yet placed, and deliberately not planned

Not yet placed: several streams per large file (the `-parallel` unit is a file); concurrent
ranged GETs and multipart PUTs on S3; resuming a partly written object rather than only a
partly copied tree; and `ControlMaster`, which is ssh configuration rather than rcp's to add
but is what makes one session per worker cheap.

The Gear table here comes from a seeded splitmix64, not the table published with FastCDC,
so the paper's deduplication ratios are a guide, not a measurement of this chunker; the
protocol is closed at both ends, so nothing depends on the table being the published one.

Deliberately not planned: QUIC (see ESnet above; rcp's remote transport runs inside ssh,
which is where the field's high-RTT answer, HPN-SSH, lives), and NFSv4.1 sessions (no
data-path gain over 4.0 for a copy tool; 4.2's server-side COPY is the one worth having and
needs 4.1 first, so it stays a later item).

## Safety rails, the MCP server and the registry endpoint

Every issue below was reproduced before anything was changed, and each fix has a contract
arm with a control that fails when the fix is removed. Suspected defects that measurement
showed not to exist are recorded too, with the reason.

### Safety rails

| issue | what the measurement showed | resolution |
| --- | --- | --- |
| `-allow` constrained spelling, not paths | `-allow /data` admitted `/data/../secret` and copied it; a symlinked endpoint leaked too | endpoints are resolved as the kernel resolves them |
| `-allow` bounds an endpoint's text, not its service | `scan -allow s3://corp/bucket -s3.endpoint http://127.0.0.1:PORT` sent `GET /corp/?list-type=2&prefix=bucket/` to a listener no rail named | a railed command line refuses `Service` and `Credential` options; both have environment routes |
| the environment is not a safe route by construction either | `AWS_ENDPOINT_URL` and a profile's `endpoint_url` redirect too | documented as such, and the boundary has an arm of its own |
| `diag -cat` read through a symlink in an allowed root | `diag -cat ROOT/link -allow ROOT` printed `/etc/hostname` | the whole path goes through `allowed`, not just the parent |
| `-uid 0 -mode 4755` under `-allow` as a privilege escalation | **not a defect.** As an unprivileged user the chown is refused — `ownership 0:0 not permitted (not root)` — and the setuid bit that does land sits on a `nobody`-owned file, which grants nothing. As root there is nothing to escalate to | none |

Open: `-allow` is a check before the open, so it cannot close a TOCTOU race.

### MCP server

| issue | what the measurement showed | resolution |
| --- | --- | --- |
| a call's option VALUES were not validated | a call with `-copybatch 'touch /tmp/x'` created that file under two `-allow` roots | nine options are refused from a call; three are refused on any railed run |
| `rcp_plan`'s digest cannot satisfy `rcp_isync` | `20d6219d81bec157` against `296677cd670b40fc` on one pair of trees | `rcp_isync_plan`, and every destructive tool names its own plan tool |
| a refusal named a rail the server did not relay | a server started with `-oci.user someone:secret` refused the option in a call and ran the child without it | every non-`Setting` option the server was started with is relayed |
| relaying on the command line made the child refuse the server's own credential | see below | credentials and transport configuration are relayed through the child's environment; `Runs` is relayed neither way |
| `-oci.insecure` was relayed nowhere | found while measuring the credential relay | relayed |
| `PR_SET_PDEATHSIG` is thread-bound and could kill children early | true of `prctl`, but the server has no threads: one read-a-line, run-it, write-a-line loop, so the forking thread is the process | no defect; a comment says what adding a worker thread would break |
| dropping the middle of a long reply could slice JSON lines | `trim_events` already cuts on line boundaries and inserts a `warning` event | no defect |

**Relaying a credential on the command line cannot work.** `rails()` always injects
`-requireconfirm`, which makes the MCP child a railed run; a railed run refuses credentials
on its command line; so a server started as `rcp mcp -oci.user U:P` that relays `-oci.user`
on the child's command line refuses its own credential. A unit test that reads `rails()`
output and never runs a child cannot see this. Credentials and transport configuration are
relayed through the child's ENVIRONMENT, which is the split the rails already rest on, and
the contract suite starts a real server against a registry that demands a credential.

**The plan digest is reproducibility, not approval.** It proves the plan a run would carry
out is the plan that was printed, and nothing about who read it. It is not a substitute for
an approval that binds a person, a session and a time, and the README should not be read as
claiming one.

Open: the child's output is held whole in memory, so a run with millions of entries has no
back pressure and no progress until it ends.

### Registry credentials and hand-offs

**A registry names where the credentials go.** A 401 carries
`WWW-Authenticate: Bearer realm="..."`, the client fetches a token from it, and it sends
the BASIC CREDENTIALS to get one. Docker Hub's realm really is another host, so this is the
protocol working -- and it means a registry that answers with a realm of its choosing is
handed the run's username and password. Measured from a run railed to the registry alone:
`Basic b3BlcmF0b3I6c3VwZXJzZWNyZXQ=` arrived at a listener on another port. The upload
hand-off moves blob BYTES to another host; the realm moves the credential. Both go
through one policy.

| issue | what the measurement showed | resolution |
| --- | --- | --- |
| an upload `Location` on another host was not followed | the copy passed while never touching the host it was sent to | followed, on its own connection, with no `Authorization` |
| the upload hand-off had no destination policy | `upload_at` followed an absolute `Location` to any host, and `-allow` never saw it | a railed run follows it only to an authority its own roots name |
| the bearer realm was unbounded and carried the credential | `Basic ...` at a host no rail named | one `may_go_to` for both the realm and the upload hand-off |
| `RCP_OCI_INSECURE` was invisible to the away policy | the policy derived https where the wire was http | fixed |
| the hand-off refusal's advice omitted a non-default port | `add -allow https://h` derives :443 and refuses again | the advice names the port and works |
| railing a push to ECR or GAR needs the storage host named | true, and the operator cannot predict it | accepted: fail-closed is what a rail means, and the error names the host |
| a token that expires mid-copy failed the file | two blobs failed `UNAUTHORIZED` and the manifest push with them | a 401 on the streaming GET is answered once and the read reissued |
| the shared authorization could race between workers | the auth is behind a mutex; two 401s cost two token fetches, not a mixed header | no defect |
| unbounded redirects could hang a worker | `upload_at` has exactly two call sites, one when the upload opens and one when it commits, so the hand-off is structurally capped at two hops | no counter needed |

Open: a token that expires **mid-body** on a multi-gigabyte blob GET is not renewed (the
retry is before the first byte); and stripping `Authorization` on every away host is right
for signed URLs and wrong for a storage host under the same auth realm, and nothing here can
measure which a real registry wants.

### Registry publishing and reads

| issue | what the measurement showed | resolution |
| --- | --- | --- |
| `-nodes` never published to a registry | exit 0, "8 files", 3 blobs, 0 manifests, no such repository | the pair is refused, at the coordinator and at `copybatch` |
| the 8 MiB JSON sniff had a costly false positive | a layer that reads like a manifest was staged instead of uploaded, and its parent then failed `MANIFEST_BLOB_UNKNOWN` | `publish` settles it: what `index.json` reaches is a manifest, what it does not goes up as a blob |
| a publish with no `index.json` demoted every manifest to a blob | 3 blobs uploaded, 0 manifests pushed, `STATUS: PASSED`, and a repository holding bytes no client can name | refused at publish, naming the malformed layout; loose blobs have gone up by then, and the manifests a client could name have not |
| the no-index guard asked about staging, not about the source | a layout with one plain blob and no index: 1 upload, 0 manifests, PASSED | `oci-layout` is the claim, and a layout owes an index |
| a 206 alone does not say WHICH range | a 206 sending from zero mis-assembles as surely as a 200 | `Content-Range` is read and must start where the read stopped |
| `content_range_start` required a lowercase `bytes` | a legal `Bytes 500-...` read as no header | case-insensitive, with the `bytes */N` case |
| the resume recursion had no depth bound | the crash did not reproduce: 62,502 frames completed in 51 s | a loop anyway: the depth is the far end's to choose |
| a failing `sync` is a failed copy | a registry's `sync` failure is a failed publish; demoting a filesystem `syncfs` failure to a warning hides dropped writes | a `sync` that fails is a failed copy, registry or filesystem |
| the closed error-code set lost the retry signal | a registry over its rate limit and a missing repository both reported `io` | `busy` and `quota` added, and `describe` publishes them; only `busy` is measured |
| 502/503/504 mapped to `busy` conflates a crash with backpressure | true as taxonomy; all four are transient and retry is the right response to each | kept; the code set stays closed |
| `verify` of a registry source might skip the blob-name digest | **not a defect.** `verify` does not seek: it reads both sides through to EOF, which is exactly when the reader compares the digest to the name | none |
| the second-mirror measurement might overstate cross-repository dedup | the stand-in keeps one blob store for all repositories, so a registry that links blobs per repository would upload there | the measurement stands for what it measures; the README says which |

**A resume after a failed publish does not skip the manifests it owes.** `Mode::Resume`
skips a file only when the catalog knows it **and** the destination already shows it, and a
registry with no tags shows nothing, so the resume re-reads `index.json`, re-stages and
publishes. A contract arm holds that end to end. A `committed` flag to keep the catalog from
recording a staged manifest as done was tried and removed: `impl Sink for AnySink` had no
`committed` delegation, so the default always won, and a successful publish reported all 8
`entry` events and 11 catalog rows. Wiring it up would have introduced the failure it was
meant to prevent. The conjunctive skip is therefore what stands between a catalog record and
a skipped manifest, and any change that lets resume trust the catalog alone would remove it.

Two cases stay open with reasons rather than fixes. A source with **no** `oci-layout` whose
blobs sniff as manifests still publishes nothing and passes -- that is the same rule that
keeps a deliberate blob-only push working, and a source with no marker is not claiming to be
a layout. And a filesystem `sync` failure has no arm: making `syncfs` fail needs either a
fault-injection hook in production code or a stub `Tree` implementing 23 methods, neither
worth it to guard a three-line change. `Content-Range` is not yet sent on a `PATCH`, which
some registries require.

## Digest cache

**The catalog records which algorithm produced its digests.** Its digest column holds hex,
and hex says nothing about what produced it. With one algorithm that is invisible; with four
it becomes a mixture — measured:

```
$ rcp copy -newid m -blake3 src dst
$ rcp sync -id m                       # the default, sha256
a.txt e0e63aa4...   (BLAKE3)
b.txt 7f8b1dfc...   (SHA-256)
```

Same column, same file, nothing to tell them apart, both runs PASSED, and `scan -edupe`
groups files by that column. The catalog records its algorithm and refuses a continuation
under a different one, naming the flag that would work. That is a prerequisite for a cache
rather than a cache: there is no trusting a stored digest until you know what it is a digest
in.

**A `verify` that answers from a cache is not a verify.** It reports on what was read last
time, keyed on metadata the thing being checked also controls. The failure it would miss is
the one `verify` exists for: content changed while size and mtime were preserved, which is
a restore from a bad backup, a filesystem that lost a write, and a deliberate edit, all at
once.

So the shape is narrower than rclone's, because rclone's hasher overlay sits in front of a
REMOTE whose bytes cost money and time to re-read, and rcp's `verify` is usually reading
local disk on both sides:

- **`scan`** may use it. A listing is not a check, and re-reading a tree to print its
  digests is the case the cache is for.
- **`verify` may not**, on either side, unless the operator asks for it in those words —
  a `-trustcache` that says plainly it is comparing records rather than bytes. That flag
  does not exist.
- **`copy` and `sync` gain nothing**: they read the file in order to write it, so the
  digest is free.

What is built is exactly that: `scan -hashcache`, and nothing else. `verify`, `copy` and
`sync` do not consult it and no flag makes them.

The cache lives beside the catalogs, one file per `(root, algorithm)`, and is keyed on
size, nanosecond mtime and inode. Measured on 128 files / 1.07 GiB of random data, four
cores, SHA-256, with a **warm page cache** -- the condition least favorable to a cache,
since a cold tree would make the first column slower still:

| | wall clock (3 runs) | files read |
| --- | --- | --- |
| `scan -sha256` | 0.238 / 0.243 / 0.220 s | 128 |
| `scan -sha256 -hashcache` | 0.004 / 0.005 / 0.004 s | **0** |

The digests are identical to the uncached scan and to `sha256sum`, checked by diff. The
file is 14 KB for 128 entries, mode 0600.

**The number that carries the claim is the right-hand column, not the left.** "The second
run was faster" is satisfied by a warm page cache doing nothing at all, so `scan` counts
the files it hands to its workers and the arms assert on that count -- zero with the cache,
128 with it removed as the control.

Three decisions, each a defect avoided rather than a preference:

- **`ino` earns its place only on a local tree.** Every adapter without a real inode
  synthesizes one as `fnv64(path)` -- stable across runs by design, which is right for
  `sync`'s move detection and worthless as a change detector, since a function of the key
  cannot disagree with itself. There the check is size and mtime, exactly rclone's. And
  `oci://` reports `mtime_ns: 0` for every blob, which would collapse it to size alone, so
  **a zero mtime is refused a hit** and not stored.
- **A cache is never allowed to fail a scan.** Truncated, malformed, from another root,
  from another algorithm: every one of those is "no cached digests", and a malformed line
  is skipped rather than half-parsed.
- **Pruning is conditional on the run being complete.** A filtered or depth-limited scan
  never looked at most of the tree, so evicting what it did not see would make the next
  full scan pay for this narrow one.

The limit is written down in the module and **pinned by an arm that asserts the wrong
answer on purpose**: a writer that overwrites bytes in place without changing the length
and then restores the mtime leaves all three fields identical, and `-hashcache` then
reports a digest of content that is gone. Every mtime-keyed cache has this hole, rclone's
included. It is why the flag is opt-in: the same arm shows a scan *without* it still
catching the tampering, so the operator who needs that answer has it by default.

## Rsyncable gzip members

pigz has two related flags, and separating them is the whole insight. `pigz -i` writes
independently-decodable blocks; this crate writes independent gzip MEMBERS, because
concatenated members are a legal gzip file and that is what makes parallel decode possible.
So `-i` comes free with the 4 MiB framing.

`--rsyncable` is the other half. With members cut at FIXED INPUT OFFSETS, inserting one byte
near the front shifts every later boundary by one and every later member compresses
differently. The archive is entirely new from the edit onward, and a delta transfer of the
compressed file has nothing to match.

`-rsyncable` cuts members with the Gear chunker the crate already has for `-delta`. Measured
end to end through the CLI on 12 MB of log-like text, inserting 25 bytes at offset 3000:

| | members identical after the insert |
| --- | --- |
| fixed cuts | **0 of 3** |
| `-rsyncable` | **25 of 27** |

`gzip -t` and `tar tzf` accept both, which they must: the format does not change, only
where the cuts fall.

**The parameters are not pigz's, and the reason is the unit.** pigz cuts at roughly a
4 KiB average because its unit is a deflate block inside one stream, where a cut costs a
flush. Here the unit is a gzip member — 18 bytes of frame, a fresh Huffman table and an
empty match window — so a 4 KiB member would be mostly overhead. The average is a
megabyte, with `min = avg/4` and `max = GZIP_BLOCK`, which keeps the writer's buffer bound
exactly what it was.

**What it costs.** On compressible text: 1,018,028 bytes in 3 members with fixed cuts
against 1,022,801 in 34 with content-defined ones — eleven times as many members for
**0.47%** more output. An arm fails if that grows past 5%. The member count is high there
because Gear on low-entropy text cuts more often than the target; on incompressible noise
it lands on 12 members for 12 MiB, which is the target exactly. Both numbers are in the
arms rather than in this paragraph alone.

**Test helpers should use the shipped decoder.** A helper that splits a stream into
members by decoding every prefix to find each boundary is quadratic, and on a 12 MiB
fixture it does not finish. The shipped decoder's `gunzip_member` already returns how many
bytes it consumed. A test that reimplements the thing under test inherits both its cost and
its bugs.
## Three-way parallelism tuner

A single tuned number -- how many workers are admitted to claim files -- cannot say "read
wider, write narrower". Marlin's argument is that a transfer has stages with different cost
and different contention, so `-parallel auto` also tunes read and write concurrency, in
`src/stage.rs`.

**The decomposition is a pair of counted gates, not a pair of thread pools.** A worker still
owns one file end to end; it holds a READ permit while the source produces bytes and a WRITE
permit while the sink takes them, and never both. So the read limit caps threads inside a
read and the write limit caps threads inside a write, independently, with no channel between
stages, no second buffer copy and no extra threads. The cost is that a worker re-queues for
the read gate after each block, which is the mechanism rather than an overhead: it is what
makes a read limit of two mean two threads reading.

Never both at once is load-bearing, so it has the sharpest arm in the module. A narrow read
gate and a wide write gate: if the permit really is handed back, several threads write at
once though only one may read, and the write gate's peak occupancy exceeds one; if it were
held across the write, that peak is pinned at one however wide the gate. Replanted -- the
whole defect is moving one `take()` after one `enter()` -- it fails with *"the write gate
peaked at 1 with a read limit of 1"*.

**A contended sink, not a slow one, is the case for fewer writers.** A merely slow sink
wants MORE writers: if a write costs ten reads and the writes are independent, saturating
the pipe needs ten writers per reader. The case where fewer is right is a **contended**
sink -- a device whose aggregate throughput peaks at a low queue depth and falls off past
it, the ordinary behavior of a seeking disk or a rate-limited endpoint. That is the case a
single worker count cannot express, and the one the arm models. Its control is the mirror
image: move the contention to the read stage and the answer must swap, or the tuner is
following the knob order rather than the landscape.

**At most one knob changes per window.** A single-knob loop measures a window, compares it
with the previous one, and applies the verdict to the knob it is about to move -- correct
only when that is always the same knob. Carried to three knobs it credits each knob with the
previous one's effect. Remembering the move is not enough, because **an undo is also a
change**: on "worse", reversing *and* probing the next knob leaves two knobs different
between consecutive windows and the next verdict is about both. Measured: with the undo
folded into the same window, the write knob settles at **4** of a wanted **1**, because each
undo cancels the next knob's move in the arithmetic. The undo gets its own window and is not
itself judged.

**The test stand-in must carry fractional bytes.** A stand-in that advances
`progress.bytes` by `rate * tick` truncates: a tick's share of a rate of 500 is 0.5 bytes,
and `0.5 as u64` is **0**. Every configuration then feeds the tuner a flat zero, and every
arm measures the tuner's behavior on a dead stream. The stand-in carries the fraction, and
scales the landscape to real byte rates so a 20 ms window is not pure quantization noise.

**"The knobs move" and "the gates open" are different claims**, and only the second is worth
anything. The contract arm reads the tuner's log, which reports a knob moving whether or not
a single thread ever passes through the gate it sets. So `Gate` carries a cumulative
admission count and `a_staged_copy_takes_permits_and_a_kernel_copy_does_not` runs a real
`copy_one` against real local trees and reads it.

That arm also pins the boundary, which is wider than it first appears. A local copy with no
digest wanted goes through `copy_file_range`, so the kernel does both halves and the stages
are not entered: measured **(0, 0)** admissions, not `(1, 0)` -- the file's read permit is
taken inside the branch that runs only when the kernel declines the copy. `-hash` is what
declines it and puts the bytes on the metered path. So: the kernel-copy and `io_uring` paths
are untuned because there is nothing there to separate, and the delta path has its own
shape.

A fixed `-parallel N` carries no stages at all -- not a gate wide enough not to bite, none
-- because a wide gate is still a mutex and a condvar on every block of every file, and a
run that asked for a fixed worker count did not ask for a tuner's machinery.

## Tuner decision margin and noise

The attribution arm failed intermittently inside parallel suite runs -- `4 readers (want 6)
and 1 writers (want 1)` -- and passed 10 of 10 times alone. Its time budget was one cause (it
is a window count, not a wall clock); the decision threshold was a second, independent
one, and fixing the first does not fix the second.

**The rig's own noise is measurable.** With both knobs held still, two consecutive windows of
the stand-in differ by about **2%** -- and a fixed rule calling a window `better` above +3%
and `worse` below -3% sits at roughly one standard deviation of the difference between two
such windows, so a large share of its verdicts are coin flips. That is not a property of the
rig: it is a property of comparing two single samples against a fixed threshold, and a real
link is noisier than this stand-in, not quieter.

**The clean demonstration needs no threshold at all.** Give the tuner a landscape in which
one knob appears NOWHERE in the rate. No setting of it is better or worse than any other,
so any movement is wrong, and there is nothing to argue about. With the fixed threshold:

```text
tune: writers 1 -> 2 flat, keeping, 304.4 MiB/s
tune: writers 2 -> 3 flat, keeping, 305.9 MiB/s
tune: writers 3 -> 4 worse,  undoing, 293.9 MiB/s
tune: writers 3 -> 2 better, keeping, 304.2 MiB/s
```

Two defects in four lines. `flat, keeping` is a **ratchet** -- a knob that changes nothing
reads flat whichever way it points, so it walks -- and the `worse`/`better` verdicts are on
3.4% and 3.5% differences inside a 2% noise floor. Over one run the knob kept a move on
**19 of 80** probes and visited all six of its values.

Three rules, each with its own replant:

| rule | why | replant fails the arm |
| --- | --- | --- |
| a flat window is undone, not kept | a move is kept only if it paid | 3 of 3, keeping 94-99 of ~100 probes |
| the margin is `max(3%, 3 x measured noise)` | the threshold should track the thing it is separating from | 1 of 3 |
| an improvement needs a second window at the same setting before it is acted on | the tail is fatter than any multiple of the spread | 3 of 3, keeping 2-8 of ~76 |

**The noise estimate costs nothing.** Two of the windows the search already spends re-read
a configuration it has just read: the window after an undo runs at the setting the probe was
launched from, and the confirming window re-reads the probe's own setting. Each is two
readings of one configuration, so each difference is a noise sample by construction. No
extra windows, no calibration phase beyond the two windows at the very start, and no
constant to guess.

It rises fast and decays slowly, deliberately. When a machine gets busier the noise steps up
at once, and a symmetric average spends the next several windows deciding by coin flip --
which is the failure being guarded against, arriving exactly when it is most likely.

**A known weakness:** the margin's replant fires only one time in three on this machine,
because 2% noise makes a fixed 3% very nearly the right number by luck and the confirming
window covers the rest. The margin is kept for the machine where that luck runs out. That is
an argument about machines the arm has not run on, so it is stated as a reason and not as a
result.

**What it costs.** A kept improvement takes three windows instead of two, so the search is
about half as fast to climb; and a landscape with a flat SHELF before a rise is uncrossable,
because a stalled knob probes one step at a time and undoes each. Both are accepted for the
same reason: refusing to spend concurrency that no measurement asked for is the behavior
wanted from a tuner, and a shelf is a speculative shape while the drift was measured.

### Complexity arms count work instead of timing it

The same noise affects any arm that compares two wall-clock measurements.
`decoding_a_run_of_ampersands_is_linear_and_not_quadratic` tells a linear `decode` from a
quadratic one by timing both sizes, and failed under load with `8x the input cost 24.2x the
time`. Best-of-five runs does not help when the LARGE run is the one a loaded scheduler
preempts in every sample; a bound that needs a quiet machine is not a bound.

So the instrument changed rather than its statistic: `decode` counts the bytes it looks at,
in test builds only, and the arm compares COUNTS. Measured, and exactly, with no spread at
all: **279,922 -> 2,239,922, a ratio of 8.0**, against **200,030,000 -> 12,800,240,000, a
ratio of 64.0** when the quadratic scan is replanted. A complexity class is a property of
the work; timing is a proxy for the work that also measures the machine, and on a busy
machine the machine wins. What it gives up is stated in the arm: wall-clock is no longer
asserted, so a change that kept the scan linear while making each step expensive would pass.
## Gear chunker performance

The delta path chunks every byte on both ends, so the chunker's rate is a ceiling on what
`-delta` can do however fast the disk and the network are. Measured: **664 MiB/s,
1.44 ns/byte** on a 48 MiB buffer. Ten gigabit is 1192 MiB/s, so the chunker really is
below that line.

The plan was lane-parallel Gear behind a runtime AVX2 check. What the measurement showed:

| variant | run 1 | run 2 | run 3 |
| --- | ---: | ---: | ---: |
| `chunk`, the fused loop | 655 | 625 | 664 MiB/s |
| `scan` alone, one stream | 1138 | 888 | 911 |
| `scan`, four lanes | 1157 | 1041 | 1150 |
| `chunk_scanned` (scan + walk) | 963 | 945 | 965 |
| **lanes vs one stream** | 1.02x | 1.17x | 1.26x |
| **two-stage vs `chunk`** | 1.47x | 1.51x | 1.45x |

A fourth run on the same binary kept only its ratios: **0.99x** for the lanes and **1.45x**
for the two-stage. It is reported separately rather than folded into the table, because
per-variant numbers for that run were not recorded.

**The lane row straddles 1.0.** Four runs of the same binary on the same input, and one of
them is a slowdown. On a four-core shared VM that is not a result, it is the noise floor --
and it answers the question, because a SIMD kernel would have to clear that floor by a wide
margin to be worth an intrinsic, a feature check and a block of `unsafe`. The reasoning
behind the plan was that `fp = (fp << 1) + GEAR[b]` is a two-cycle dependency chain, so one
stream cannot use a wide core; the measurement says something else limits this loop first.
**The lane code is kept** -- it is correct, it is proven equivalent, and it is the baseline
any future SIMD attempt has to beat -- but nothing calls it on the hot path, and no claim is
made that it is faster.

**What pays is separating the two things the loop does.** The fused chunker tests the mask
*and* tracks a length against `min`, `avg` and `max`, every byte. `scan` tests only the
mask; `Cuts::chunks` then applies the length rules to one entry per candidate -- 4.6 per
chunk, about one per 2 KiB. Same output, **1.45x**, stable across every run.

That separation is only legal because of two facts, and both are asserted rather than
argued:

- **The scan does not need to know where the cuts are.** Bit `j` of the fingerprint depends
  on the last `j + 1` bytes; the masks sit at bit 32 and above; `min >= MIN_CHUNK` is 256.
  So the reset `Chunker` performs at each cut is always further back than any mask bit can
  see, and the candidate positions are a property of the buffer alone.
- **The weak hash survives the decoupling exactly.** This is the part that could have killed
  it. Each chunk's FastFp is the sum of fingerprints computed *from a reset*, which a
  continuous scan does not have. But the recurrence is linear mod 2^64, so running it from
  `s` instead of zero only adds `s * 2^(k+1)`; summing over a chunk and using that
  `2^64 = 0`, `weak = sum(b) - sum(a-1) + 2 * fp(a-1)`. Exact for any chunk of 62 bytes or
  more, which every legal `Params` guarantees. Without it, cut positions could be found in
  parallel and every chunk would still need a second pass for its hash -- the whole cost
  again. `the_two_stage_scan_reproduces_the_chunker_exactly` compares every field of every
  chunk across six inputs and three parameter sets, and its control drops the `2 * fp(a-1)`
  term and requires the match to break.

Three pitfalls the measurement exposed. A perfectly periodic buffer yields **zero**
candidates -- the fingerprint enters a cycle that never meets the mask -- so a
lane-equivalence arm on it compares two empty lists and proves nothing; the non-vacuity
check catches that. A constant buffer does the same, which is why every cut there is forced
by `max` and lands where no candidate was recorded, and why the scan keeps a state rung
every 4 KiB. And `chunk_scanned` deliberately does not emit the unfinished tail, so a rate
test counting 5328 chunks against the fused chunker's 5329 is an off-by-one in the test, not
a chunker defect.

**Not yet on the hot path, and the reason is specific.** `Chunker` is a streaming API and
the 1.45x comes from scanning a whole buffer at once, so wiring it in means buffering, which
changes when `Matcher` emits patches and needs the under-62-byte final chunk handled
separately. That is a change to the one piece of code both ends of every delta must agree on
byte for byte. The decomposition is proven and measured; the wiring is the next step.
## Socket transport (`rcp://`)

`ssh://` pays for a child process and an ssh handshake per channel. For `-nodes` and `-via`
across a tunnel somebody else already authenticated, that is all cost and no benefit, so
`rcp serve -listen ADDR` speaks the same frames over TCP and `rcp://host:port/path` is the
endpoint. `Channel` already abstracted over `Box<dyn Read/Write + Send>` with an
`Option<Child>`, so the client side is a second constructor rather than a second transport.

**What a socket does not inherit is the thing that matters.** Over `ssh://`, OpenSSH has
authenticated the peer and started `rcp serve` as that user before a frame is read; the
protocol inherits an identity it never establishes. A socket inherits nothing, so served
as-is on a routable address this would be an unauthenticated remote file service, read and
write. The listener therefore **refuses a non-loopback address** unless mutual TLS
authenticates the peer, and refuses to start at all without `-allow`. Refusing a capability
is a smaller error than quietly shipping an open one.

**The roots come from one place.** The listener requires roots and the session enforces
them, and those must be the same roots. With `check_listen` counting `-allow` while the
session's rail read only `RCP_ALLOWED_ROOTS` from the environment, `serve -listen
127.0.0.1:P -allow /srv` started happily, and a copy to `/tmp/elsewhere` reported
**PASSED** with the directory created. Every refusal arm passed while that was true, and so
did the happy path; the only thing that showed it was running the copy the rail was supposed
to refuse. The roots are passed in rather than read from two places, and the contract arm
replants the two-source version and requires it to fail.

Endpoint shape, and both parts are deliberate refusals rather than conveniences:

- **No user.** `rcp://bob@host:port/path` is refused. A username the protocol carries and
  nobody checks is an identity in appearance only, which is worse than none.
- **No default port.** `ssh://` may omit 22; `rcp://` may not omit its port. There is no
  registered port for this, and inventing one means a typo dials some other service.

## Remote transport encryption (`rcps://`)

`rcps://` is the `rcp://` socket inside TLS. The obvious design is "add TLS, drop the
loopback rule". It is wrong: encryption is not authentication, and the rule follows
authentication.

`-tls.cert` and `-tls.key` prove to the CLIENT who the serve is, and keep a passive observer
out of the stream. They establish **nothing** about who connected. A serve with a
certificate and no client verifier, bound to a routable address, is still an unauthenticated
remote filesystem -- now wearing a padlock, which is worse than the plain one because it
reads as solved. So `check_listen` asks `is_mutual()`, which is exactly "was `-tls.clientca`
named", and a TLS serve without one is refused on a routable address precisely as a
plaintext serve is. The contract arm measures that as a PAIR: the same wildcard bind with
the same server certificate, refused without the client authority and accepted with it.
Without the second half the arm would pass against a build that had stopped checking at all.

Two half-configurations are refused by name rather than resolved, because either resolution
is a guess: a certificate without its key (`-tls.cert` alone), and a client authority with
nothing to present (`-tls.clientca` alone, which asks the peer for a certificate while
offering none and cannot complete a handshake).

**The refusals are asserted by their own reasons.** Probing the refusal cases with a
RELATIVE source path makes every one of them "fail" on `endpoint "src" is none of ...` --
before a socket is opened -- and an `assert!(!success)` is satisfied by all four. What the
arm asserts is what rustls actually says, and the three TLS cases are different by
construction:

| case | who refuses, and how it reads |
| --- | --- |
| client has no certificate | the serve, as a TLS alert: `received fatal alert: CertificateRequired` |
| client's certificate is from another authority | the serve, as `received fatal alert: UnknownCA` |
| client does not trust the SERVE | the client itself: `invalid peer certificate: UnknownIssuer` |
| plaintext `rcp://` against a TLS listener | the frame limit: the alert bytes read as a frame header, `exceeds the 16777216 limit` |

That last one is not a graceful message and it is not meant to be; what matters is that a
plaintext client is not quietly served, and that the refusal is bounded rather than an
allocation. The arm pins the number so that removing the limit shows up here.

**One stream, two halves, and why the lock cannot deadlock.** A `TcpStream` splits with
`try_clone` because the kernel owns the two directions. A TLS connection cannot: the record
layer, the sequence numbers and the key schedule are one piece of state. So the reader and
the writer share one object behind a mutex. That is a deadlock in most shapes and is not one
here: a `Channel` is a sequential request stream used by ONE worker, which writes its
requests and then reads their replies on one thread, and a serve's session is the same loop
from the other side. Parallelism in this crate is more channels, never more users of one
channel.

**The `-tls.*` options are `Transport`, not `Credential`.** `Credential` is what they look
like, but a `Credential` is refused on any RAILED command line -- and `serve -listen` is
railed by construction, since it will not start without `-allow`. As `Credential` these
would be options that could never be used on the only command that needs them (the contract
arm reports `-tls.cert chooses or carries a credential, which no rail can bound`).
`Transport` is the class for "how well is the connection to a named endpoint
authenticated" and already holds `-oci.insecure` and `-nfs.sec`. It preserves the half that
matters -- a `Transport` is still refused from an MCP CALL, so a caller cannot name the
trust anchor a railed server checks against, and `relay_env` still carries the operator's
choice to every child. What it gives up is value redaction in logs, and these values are
file paths rather than keys.

**Every scheme the parser accepts is described.** `describe` and the `endpoint ... is none
of` refusal a user reads after a typo are both checked against the parser. A guard that
checks named adapters against their source files cannot see `rcp://`, which shares the ssh
adapter and has no file of its own. `every_scheme_the_parser_accepts_has_a_row` derives the
list from the parser's own `strip_prefix` literals and checks both surfaces. Replanted, it
names `["rcps", "rcp"]` for each.

**`-via rcp://` needs an arm that actually dials the hop.** `connect_tcp_via` is only
reachable once `-via` accepts more than `is_ssh()`. An arm that copies to a LOCAL path
through the hop passes without dialing it -- `-via` routes the endpoints this process
should not open itself, and a local path is not one. The arm therefore uses a second
listener, because a hop's rail bounds the endpoint TEXT: a root of `/tmp/x` does not admit
`rcp://host:port/tmp/x`, the same rule the ssh relay arm spells `ssh://filer/...`. So the
hop is started after the destination listener, with that listener's port in its own
`-allow`.

Not implemented: a serve that authenticates by anything other than a certificate -- no
token, no PSK, no unix-domain socket. None of those is needed while `rcp://` on loopback
plus a tunnel, or `rcps://` with a client authority, covers the two cases that exist.
## DEFLATE encoder

A `tar://` destination named `.tar.gz` must contain gzip. Writing a plain tar under a `.gz`
name and reporting `PASSED` is a defect, and a known-limitation note in the README does not
fix it: nothing that prints `STATUS: PASSED` sends an operator to a paragraph in a README,
and the file is discovered wherever it was shipped. That is why the crate has its own
DEFLATE encoder.

**The correctness claim is against the reference implementation, never a round trip.** An
encoder and a decoder that share a misunderstanding agree with each other perfectly, and
rcp's own reader is the worst possible judge here: it sniffs the gzip magic and falls
through to a plain tar, so it reads a mislabeled plain tar happily. The arms put rcp's
bytes through the system `gzip -d`, `gzip -dN` and `tar xzf`, and a contract arm packs a
real tree and has `tar -xzf` unpack it. Where `gzip` is absent the arm SKIPS and says what
was not checked; a silent skip is a pass that checked nothing.

### The hash chain, and why no arm saw its defect

The hash chain once broke in two ways at once — `prev[i]` left unset on the match path
(truncating each bucket) and set to `i` itself on the literal path (a self-loop a later walk
spins on). The stream stayed valid DEFLATE throughout, because every candidate is compared
byte for byte before it is used, so the defect could only ever cost ratio.

**Beware a fixture that cannot measure the thing.** A corpus made of a 44-byte pangram
repeated ten thousand times shows chain depth as irrelevant — a sweep from a 4-deep chain to
a 128-deep one moves the ratio only 0.078 to 0.077 — but after the first sentence every
position matches at distance 44, so chain depth cannot matter *by construction*. That is a
measurement of the fixture, not of text, and its 0.008 ratio is the tell.

Measured on 1,029,896 bytes of this crate's own source and prose, with both halves of the
defect replanted into the real encoder and a narrow corpus beside it as a control:

| corpus at `MAX_CHAIN` 32 | broken | fixed | what the defect cost |
| --- | --- | --- | --- |
| 400 KB, 4-symbol alphabet | 214,608 (0.5365) | 179,942 (0.4499) | **+19.2%** |
| 1,029,896 B source and prose | 429,985 (0.4175) | 377,398 (0.3664) | **+13.9%** |

The replant reproduces the defective encoder's recorded 214,608 to the byte, which is what makes
the prose row trustworthy. Against the system's own encoder on the narrow corpus,
`gzip -6` is 117,337 (0.293) and `gzip -9` is 115,419 (0.289).

So the narrow alphabet is a **sharper** discriminator, not the only one: a prose fixture
catches the defect at 14%. What let it through was simpler — **no arm bounded the ratio at
all**, on any corpus.

**A test that asserts "it compressed" cannot find this.** The arm that catches it
(`the_match_chain_reaches_past_the_most_recent_candidate`) asserts a ratio BOUND on the
colliding corpus, with the decode as its control — a smaller output is only good news if
it is still the same bytes.

### Separating the search from the code table

Comparing against `gzip -6` cannot attribute a gap to the coder or to the matcher, because
`gzip` changes the search and the code table together: lazy matching, a far longer chain,
*and* dynamic blocks. zlib's `Z_FIXED` strategy is the discriminator, because it forces
fixed-Huffman blocks while the level still sets the search effort. On the same corpus:

| | output | ratio |
| --- | --- | --- |
| `Z_FIXED` level 1 — weak search, fixed coder | 213,079 | 0.533 |
| **rcp, fixed coder, greedy** | 179,942 | **0.450** |
| `Z_FIXED` level 9 — **strong** search, fixed coder | 160,932 | 0.402 |
| **rcp, dynamic coder** | 120,430 | **0.301** |
| default level 9 — strong search, **dynamic** coder | 115,367 | 0.288 |

**zlib's strongest matcher, restricted to fixed blocks, still only reaches 0.402** — so the
code table does most of the work and no chain depth substitutes for it. rcp at 0.450 against
even that meant **the matcher was leaving about 11% on the table too**: greedy, with no lazy
matching. Both were real work.

**Both are done.** Dynamic blocks took the same corpus from 0.450 to 0.301 — past
`Z_FIXED` level 9's 0.402, as the table predicted, which is why they were built before the
matcher was touched. Lazy matching then took it to 0.3003.

That second number is nearly flat because **the 400 KB fixture is pathological by
construction and is not what lazy matching is for.** On a corpus of this crate's own source
and prose it is worth 2.7%, which is most of the remaining gap:

| | rcp | `gzip -6` | gap |
| --- | --- | --- | --- |
| 400 KB, 4-symbol alphabet | 120,139 (0.3003) | 117,337 (0.2933) | 2.4% |
| 1,029,896 B source and prose | 311,493 (0.3025) | 308,452 (0.2994) | **1.0%** |

What is left is an optimal parse (zopfli, libdeflate), which rcp does not attempt.

**0.402 is a measurement, not a floor.** It is one strong matcher's result, and an optimal
parser emitting only fixed blocks could beat it; calling it "the floor for any
fixed-Huffman encoder" would draw a mechanism from a single data point. `MAX_CHAIN` stays at
32 (the sweep's knee) because chain DEPTH is what is nearly exhausted.

### A bar calibrated downstream decays silently

`the_match_chain_reaches_past_the_most_recent_candidate` bounded the narrow corpus at
`< 0.53`, chosen so the replanted chain defect (0.537) fails it. With dynamic blocks the
defect compresses to **0.3338** — comfortably under the bar. The arm still passed, still
named the chain, and could no longer detect the thing it was written for.

Nothing failed to announce this; the arm simply kept being green. It shows up only when you
ask what the *defect* now measures, rather than what the fix measures, which is the question
a bar tightens against. The arm therefore does not measure the matcher through the coder:
it asserts on the LZ77 symbol stream — how much of the input matches cover — which no code
table can flatter, and keeps a ratio bound beside it as the end-to-end guard.

**The general form:** a bar calibrated against one configuration decays when anything
downstream of the thing it measures improves, and it decays *silently*, because improvement
moves the number the safe way. Any arm asserting on an end-to-end number is measuring every
stage between its subject and its assertion.

### Incompressible input is not inflated

With only fixed-Huffman blocks, a literal costs 8 bits under byte value 144 and 9 above, so
uniformly random input averages 8.4375 bits per byte — **+5.44% measured on 200 KB of
noise**. `rcp copy /tree tar://out.tar.gz` over an OCI layout or a photo library is exactly
that input, so a fixed-only encoder makes the `.tar.gz` *larger* than the `.tar`, under a
name that promises the opposite, while every arm stays green: the stream is valid, `gzip -d`
reads it, `tar xzf` unpacks it. Nothing there tests the direction of the size change.

Each block goes out stored, fixed or dynamic, whichever costs fewer bits — an exact count of
each candidate including its own header, so the choice cannot be wrong about what it is
choosing. Stored is what `gzip` has always fallen back to and costs five bytes per 64 KiB.
The arm (`incompressible_input_is_not_inflated`) bounds the overhead at +1% and carries two
controls, because "smaller" is not "correct": the noise must decode back byte for byte, and
text must still compress by 50x, or the encoder has quietly become `cat`.

### 4 MiB members

The stream is a run of independent 4 MiB gzip members rather than one member, which is
what `pigz -i` writes and what RFC 1952 §2.2 allows. `deflate()` takes a whole slice, so one
member would mean holding the archive in memory. It is also the shape the block pipeline,
`-rsyncable` and parallel decode need: each starts from a format that already has
independent blocks in it.
## Compression on the `ssh://` stream

`-compress` compresses each payload on the `ssh://` stream with a raw-or-compressed flag per
payload. LZ4 is the default; `-compress.codec deflate` and `-compress.codec zstd` are the
two slow codecs. Measured through the counting stand-in that sits in ssh's position, on
4.5 MB of log-shaped text (timestamps, hostnames, varying numbers -- not one repeated line,
which LZ4 handles unrepresentatively well):

| | wire bytes | vs raw |
| --- | ---: | ---: |
| no `-compress` | 4,537,408 | 1.00x |
| `-compress` (lz4) | 1,118,408 | 4.06x |
| `-compress.codec zstd` | 605,008 | 7.50x |
| `-compress.codec deflate` | 602,644 | **7.53x** |

**The two slow codecs are within half a percent, and zstd's ratio comes from its search,
not its container.** As first wired, the zstd encoder sent 960,872 bytes -- 59% behind this
crate's own DEFLATE. Each change below closed part of that gap without changing the format:

| change | wire bytes | |
| --- | ---: | --- |
| as first wired | 960,872 | greedy matching, predefined FSE tables, no repeat offsets |
| lazy matching | 856,164 | -11%; a match is given up when the next position finds a longer one |
| FSE tables from the block's own counts | 630,260 | **-26%**, the big one: predefined tables charge for symbols a block never uses |
| repeat offsets | 605,008 | -4%; structured text reuses one distance constantly |
| match chain 32 -> 64 | 604,024 | **reverted** -- 0.16% for twice the search |

So what zstd buys is **interchange**: the frames are ordinary zstd frames, so a peer, a
pipe or an archive that already speaks zstd needs nothing from us. It is not a ratio
sacrifice to use it.

The last digits of every figure here move by a few bytes between runs, because the count
includes request paths and the scratch directory's name changes. The comparisons are
stable; do not read the units digit as a constant.

**The negotiation is an ANSWER, not a request, and that asymmetry is the design.** The
client names a codec; the serve replies with the codec it will actually use. A serve that
does not know the name answers LZ4 and the client follows its answer rather than its own
request -- because two ends disagreeing about how to read a payload is a corruption, while
falling back is only a worse ratio. The caller asked for a smaller stream, not a different
outcome. `-compress.codec brotli` is refused rather than quietly falling back.

**Every codec field in HELLO is read as required.** Within a protocol version every peer
sends them (see the level section below for the full argument). The reply shows why a
tolerant read is dangerous as well as useless: FOUR bools follow the codec there, so a
tolerant read of an absent field would consume them instead -- the same shape as a defect
in `hello` where a short-circuited flag left every later answer one field late and `sync`
silently recopied nothing.

**Wire tags.** zstd is payload tag 2 and DEFLATE is tag 3, and both non-LZ4 codecs ask with
HELLO version 6, so a raw or LZ4 peer's handshake is unchanged. zstd holds tag 2 because an
earlier release used it; changing it would break interop.

**Each codec carries its own expansion bound**, used to refuse a dishonest `raw_len`
before anything is allocated: 255 bytes per input byte for LZ4 (a sequence's length bytes
extend by 255 apiece), 1032 for DEFLATE (a length code reaches 258 bytes and the cheapest
match is two one-bit codes under a dynamic tree -- zlib's own worst-case figure). The
multiplication saturates: `MAX_FRAME` (16 MiB) times 1032 is about 17 GiB, fine in a
64-bit `usize`, a panic in a 32-bit debug build and a wrap in a 32-bit release one. The
wrap is not a hole -- `raw_len` is capped at `MAX_FRAME` first, so even the wrapped bound
admits every legal claim -- but it is a crash on a 32-bit target. The CRC-32 over the
ORIGINAL bytes covers every codec, because a flipped bit in a compressed body usually
relocates a match rather than failing the decode, so the decoder emits plausible bytes
that are not the ones sent.

**The LZ4 prefix probe's timing arm compares like with like.** Before a block is
compressed whole, a 64 KiB prefix is probed; after eight unprofitable blocks the next
sixty-four go raw unprobed. A rejected block is still copied whole into the encoder, so the
arm prices that copy separately rather than charging it to the probe with nothing on the
other side of the ledger, and takes the minimum of seven samples. Its control lands at
1.658 ms against a 1.659 ms whole-block pass.

## zstd codec

`-compress.codec zstd` is an encoder that emits Huffman-coded literals and FSE-coded
sequences, and a decoder that reads the format back, in the crate's own code. That is FSE
entropy coding, Huffman literals and a sequence format in both directions, in a crate whose
only dependencies are cryptography; a thin encoder wearing the name would be a label
rather than a capability, which is why DEFLATE came first.

**The system library is an optional backend, not an alternative.** `--features system-zstd`
swaps the system libzstd in behind its stable one-shot C API. The crate's codec is in every
build. Frames cross between the two in both directions, and a unit arm asserts it on text,
a run and noise.

**The same codec writes `.tar.zst`.** A `.tar.zst` is written as one frame per 4 MiB,
through the pool and the content-defined cuts the `.tar.gz` writer already has, and read
by sniffing the frame magic or a leading skippable frame (`pzstd`'s layout). It always uses
the crate's codec, not the `system-zstd` backend, so an archive is the same bytes from every
build. The ratio is gzip's rather than zstd's: 991,256 bytes against `zstd -3`'s 922,291
on 3.3 MB of this crate's text. Closing that gap means a better match search, not a
different container.

### Interop is checked against the reference, not against itself

Both directions are checked against `/usr/bin/zstd` rather than against each other -- the
reference decodes what this encoder writes, and this decoder reads **15 reference frames**
(five corpora at three levels) byte-for-byte, plus **280 more** in a boundary sweep over
the lengths where the format changes shape, at two levels crossed with and without a frame
checksum.

Five ordinary corpora at three nearby levels is ONE compressor on typical files, and several
paths this decoder parses do not appear in it. The boundary sweep, the mixed-block-type
frame, the corrupted-input fuzz arm and the verified content checksum exist for that reason.
The claim is "agrees with the reference wherever we have looked, and we have looked at the
edges", which is weaker than "reads the whole format" and is what the evidence supports.

**The fuzz arm is differential.** Counting 0 panics over thousands of hostile inputs says
nothing about the ones that DECODE -- a confidently wrong answer passes as a success. Every
accepted input is also put to the reference, and over 4,710 corrupted, truncated and random
inputs the split is: **129 accepted and byte-identical to the reference, 0 accepted only by
us, 4 refused only by us**. Those four are one cause, and the reference is the permissive
one: RFC 8878 says the low two bits of `Symbol_Compression_Modes` are reserved and must be
zero, and libzstd masks them off. Refusals the reference disagrees with fail the arm unless
they name a rule like that one, so "we are stricter" cannot be used as a blanket excuse for
a real interop bug.

Two things that arm measured on the way:

- **The content checksum silently empties a naive fuzz corpus.** Once the encoder writes a
  checksum, every corrupted frame fails verification instead of decoding, and the accept
  count over the original inputs went from 129 to **zero**. That is the checksum working,
  and it also blinds the differential, which can only compare what somebody accepts -- so
  the corpus mutates unchecksummed frames too, which is what a peer running
  `zstd --no-check` would send anyway.
- **A length check would not catch the replant.** The control for this arm is a one-byte
  offset error in the match copy; it produces 3,000 bytes where the reference produces 3,000
  different bytes. Same length, different content, no error raised by either decoder on its
  own.

### Window bounds

The window bound is enforced at every append inside the block decoder, with a post-block
check kept as a backstop that should never fire. Checking only after a block has expanded
gives the right refusal after the memory has been spent.

Each window refusal is pinned to its own wording. Both refusals say `window allows`, so an
arm asserting only that substring keeps passing when the bound moves and the arm starts
exercising the other check. The offset case has its own corpus (a unique prefix, 140 KB of
filler, the prefix again: a match reaching back ~145,000 bytes, refused at a 128 KiB window
and accepted at 256 KiB).

**Declared-window cap.** `zstd --ultra -22 --long=31` writes a frame whose declared window
the reference refuses: `zstd -d` answers `Window size larger than maximum : 2147483648 >
134217728`. The cap is `> 1<<27`, it applies to single-segment frames too (where the
window IS the declared content size), and both sides of the boundary are asserted -- a
hand-built frame declaring exactly `1<<27` decodes in both, 200,000,000 is refused by
both. Building those by hand is cheap: RLE blocks cost four bytes per 128 KiB, so a
200 MB declaration is a 6 KB frame.

**Conformance checks run in both directions.** "What do we refuse that the reference reads"
(the differential's `stricter` pile, the `DELIBERATELY_STRICTER` list, the conformance
sweep) is half a suite. "What does the reference refuse that we read" is the other half,
and it is the question that found the window cap. Which half is missing is invisible from
inside a suite written in one direction.

### Coverage of the decoder's branches

The hostile corpus is required to **reach** eight named conformance refusals rather than
merely to produce errors. It reaches 24 distinct ones; the rarest of the named eight fires
6 times, which includes the leftover-bits check.

Three decoder paths the encoder cannot write -- treeless literals, single-stream Huffman and
repeat-mode sequence tables -- are exercised by two corpus families: one large skewed input,
so the reference spans several blocks per frame and starts reusing trees and tables, and two
small ones, whose literals sections fit the single-stream form. Without them those three
branches were reached zero times across 268 sweep frames (RLE sequence tables four times);
they parse attacker-supplied bytes, and agreement over the other frames said nothing about
them. The sweep fails by name if any branch stops being reached. The grid is 70 corpora /
280 frames, and the interleaved FSE decoder covers 68 entries.

The block type and the literals-section type are counted too:

    raw literals 140 | RLE literals 2 | RLE block 4 | raw block 102

All four are covered, and the counters stay asserted so a corpus that stops producing one of
these shapes says so rather than quietly narrowing. A replant that removes one `branch()`
call fails the sweep, so the assertions are live rather than decorative.

### Frame-level rules

**Every frame is decoded.** Concatenating frames is legal zstd, so ignoring bytes after the
first frame silently drops a whole trailing frame: with two frames in, the reference returns
700 bytes and a first-frame-only decoder returns 320, with no error -- a correct-looking
decode of the wrong bytes, in the function every caller uses. Bytes that are not a frame are
refused rather than shrugged at, and skippable frames are skipped.

**A frame naming a dictionary is refused**, at all three ID widths. Measuring
`Dictionary_ID` and stepping over it decodes the blocks after it and matches the checksum --
1,024 bytes returned where `zstd -d` answers `Decoding error (36) : Dictionary mismatch`.
The corpus has a family for this: the existing bit flips do set the dictionary flag, but
setting it without inserting the ID shifts every later field, so both decoders refuse for
reasons unrelated to dictionaries and the input lands in the refusal pile looking like
coverage. Replanting the defect moves `we_are_laxer` from 0 to 3.

**A skippable frame's `Frame_Size` counts `User_Data` alone.** RFC 8878 3.1.2 defines it
that way, so the advance is `8 + n`. Reading it as including the 8-byte header would be an
off-by-eight that desynchronizes everything after the first skippable frame; the reference
settles it: with the field at 11 and nineteen bytes on the wire, `zstd -d` lands on the next
data frame in all five arrangements, where the other reading would land eight bytes early in
every one. The five arrangements are in the arm, and the RFC sentence is quoted where the
advance is computed.

**Single-segment frames reach the decoder through a file-based path.** A piped `zstd` cannot
know the input length, so it clears `Single_Segment_flag` every time; handed a FILE it sets
the flag at all three content-size widths -- 10 bytes gives descriptor `0x24`, 1,000 gives
`0x64`, 300,000 gives `0xa4`. It is tempting to conclude from piped measurements that the
reference never emits single-segment frames; it does. Because `reference()` in the test
module pipes, every one of the ~400 reference frames in the other arms is descriptor `0x04`
or `0x00`, and no amount of adding corpora changes that: the shape is chosen by how the
reference is invoked, not by what it is fed. A file-based path and an arm requiring all
three widths cover it; 18 frames decode byte-for-byte.

### Decoder defects found by reference interop

Four of them, and each was invisible to the others -- which is the argument for the
five-corpus interop arm rather than one sample:

| defect | what it looked like | what found it |
| --- | --- | --- |
| `read_ncount` counted one byte too many, double-counting the partial trailing byte the reader had already pulled | every round trip green; the weight bitstream that follows read one byte late, decoded 115 plausible weights and stopped two short, summing 1015 of 1024 | a reference frame of timestamps |
| the predefined match-length distribution had codes 46 and 47 as `1` instead of `-1` | encoder and decoder shared the wrong table, so every round trip passed; against the reference, state 58 decoded to code 35 instead of 51, turning a 39,990-byte match into a 41-byte one -- and the frame **reported success** with 51 bytes of correct-looking output | a two-symbol corpus, whose single enormous match is the only place the difference shows |
| single-stream compressed literals were refused as unimplemented | ordinary English prose at `-1` does not decode | the prose corpus |
| RLE and treeless literals were refused | structured log lines at `-1` do not decode; a treeless block needs the tree an EARLIER block sent, so it is frame state | the timestamp corpus, again, after the other three were fixed |

The through-line is that three of the four produced **plausible output or a green suite**
rather than an error. A round trip between an encoder and a decoder that share a table
cannot see a wrong table. Only the reference can.

## DEFLATE compression level

`-compress.level N`, 1..9 in zlib's sense, default 6. It moves two numbers inside the
matcher -- how far down the hash chain a search walks, and how long a match has to be
before the lazy arm stops looking for a better one at the next byte -- which is the same
pair zlib spells `max_chain_length` and `max_lazy_match`.

| level | chain | lazy |
| ---: | ---: | ---: |
| 1 | 4 | greedy |
| 2 | 8 | greedy |
| 3 | 16 | greedy |
| 4 | 16 | 8 |
| 5 | 24 | 16 |
| **6** | **32** | **32** |
| 7 | 64 | 64 |
| 8 | 128 | 128 |
| 9 | 256 | 258 |

**Level 6 is asserted to be byte-for-byte the encoder without a level knob.** A default
that quietly changes output is a regression for every caller who never asked for one, so
`deflate_at(data, Level::of(6)) == deflate(data)` is the first assertion in the unit arm
rather than a comment.

Measured on the 400 KB colliding corpus the chain arms already use:

| level | output | ratio |
| ---: | ---: | ---: |
| 1 | 128,853 | 0.3221 |
| 3 | 122,739 | 0.3068 |
| 6 | 120,139 | 0.3003 |
| 9 | 116,666 | **0.2917** |

Level 9 is below `gzip -6`'s 117,337 on this corpus and within 1.1% of `gzip -9`'s
115,419 -- so the residual gap to zlib at the top of the range is about a percent.

Levels 3 and 4 are not strictly ordered (122,739 against 122,785): a deeper chain can
pick a different match that codes a hair worse. The arm therefore bounds 1 against 9 end to
end rather than asserting monotonicity it does not have.

**The level never crosses the wire as a stream property, and that is the whole difference
between it and the codec.** A DEFLATE stream is self-describing -- the decoder reads the
block headers and the code tables out of the stream itself -- so the two ends do not have
to agree on a level the way they must agree on a codec. It rides in HELLO only as a
REQUEST, so a number typed on one command line reaches the other side's encoder.

**The trailing HELLO fields are required, not tolerated.** `VERSION` is checked for
equality, so a peer predating `codec` or `level` is already refused by version; within a
version every peer sends both. The only way a tolerant `unwrap_or` read could fire is a
TRUNCATED frame, and a truncated frame must not read as an absent field. Such a tolerance
would support no honest peer and would silently turn a corrupt HELLO into a plausible
session.

**A bad value is refused at the terminal and defaulted from the wire, on purpose.** The
command line REFUSES 0, 10 or `six`. The serve answers an out-of-range level with the
DEFAULT. A typo at a terminal is a question the caller can still answer; a field in a frame
from a peer is not, and working at the default is a better answer there than dropping a
connection over a number that cannot affect whether the result decodes. Clamping to 1..9
was rejected: `clamp(1, 9)` sends 0 to 1 and sends 10, 255 and 1000 to **9**, answering
the one input a caller cannot have meant with the most expensive setting on offer. The safe
reading of a value a peer should never have sent is the one this side would have used had
the peer said nothing.

**The contract arm pulls rather than pushes.** A push counts bytes this process compressed,
so a level that never left the machine would still pass; pulling counts bytes `rcp serve`
compressed. Measured: **level 1 793,848 bytes out of the serve, level 9 599,604**. Two
different totals are consistent both with the level having crossed HELLO and with the serve
having been configured that way itself, and the numbers alone cannot separate those. So the
serve logs the level it actually used and the arm reads it back; the stand-in starts
`rcp serve` with no arguments, so the only place that number can have come from is the
frame. A serve patched to ignore the field sends the same number twice and fails the arm.

**LZ4 has no level** -- it is the single-pass block format -- so `-compress.level` without
`-compress.codec deflate` is **refused**. Accepting and ignoring it was considered and
rejected. The argument for it is that refusing makes the level a trap for anyone who has
not also typed the codec; but the trap is the SUCCESS: exit 0, no warning, no reply field
echoing the level actually used, and a caller who has every reason to think the number did
something. It would also contradict the rule beside it -- `-compress.level 10` is refused
because a typo at a terminal is a question the caller can still answer, and the person who
omitted the codec is at that same terminal. Two rules in one option cannot point opposite
ways.

## Skipped arms

The suite prints a line whenever an arm cannot run -- 37 such sites -- but `cargo test`
captures stdout for passing tests, so a skip that fires is invisible in a normal green run.
Measured with `--nocapture` across the lib and integration suites: **one**, `SKIP the
unreadable arm: running as root, which reads a 0o000 file`, which is a property of the
container and not of the code. Everything else -- every `zstd` and `gzip` reference half,
every `python3` stand-in -- ran. A default run cannot report this count; `--nocapture` can.
A skip is a check that did not happen, never a pass.

## Sparse tar members

Without sparse support, `tar://` writes a hole as the zeros it stands for. Measured on a
64 MiB file holding 128 real bytes and occupying 8 KiB on disk:

| | archive bytes | pack time |
| --- | ---: | ---: |
| rcp, hole written flat | 67,113,472 | 4.77 s (debug) |
| `tar -cf --sparse` | 10,240 | — |
| `tar -cf --sparse --format=posix` | 10,240 | — |
| **rcp, pax 1.0 sparse** | **9,216** | **0.30 s (release)** |

**Read the size column, not the time one.** On this machine the fixture lives on tmpfs,
where writing 64 MiB of zeros is nearly free: the release-build dense pack of the same
apparent bytes takes 0.42 s against the sparse path's 0.30 s, which is not a headline. The
67 MB that no longer exists is the result -- on a real disk, in an artifact store, or
across any of the network transports this crate has, that is the whole cost. The one time
figure worth quoting is `verify` through the archive: **0.05 s against a dense member,
0.02 s against the sparse one**, because the reader skips holes instead of comparing
zeros to zeros.

### The format is read off the reference

pax reserves the `GNU.` keyword namespace and says nothing about what goes in it, so the
specification here IS GNU tar. What 1.35 writes, verified by `od`:

```
x header at ./PaxHeaders/<base>     GNU.sparse.major=1  .minor=0
                                    .name=<real name>   .realsize=<apparent size>
0 header at ./GNUSparseFile.N/<base>   size = map text + extents, block-padded
data:  "<count>\n" then "<off>\n<len>\n" per extent, NUL-padded to 512, then the extents
```

Two details that are not obvious and are copied rather than reasoned about: the member name
is a **decoy**, so a reader that does not know the extension extracts something visibly
wrong rather than a silently truncated file; and GNU closes the map with a **zero-length
extent at the file's end**. The reader here does not need that terminator -- `realsize`
already says where the file stops -- but writing what the reference writes is the cheap
side of an interop question nobody wants to re-answer.

### One extended header per member, and why rcp's own tests could not see it

The member header must not go through `write_header`. That function emits its **own** pax
header whenever a field will not fit ustar -- a sub-second mtime, or a decoy name past 100
bytes -- so a sparse member written through it carries two `x` headers in a row.

That is not two sets of records. GNU tar **resets its pending records at each extended
header**, so the second one erases `GNU.sparse.*`, and `tar xf` produces:

```
GNUSparseFile.2452/hole.bin   4672 bytes
```

The decoy, taken literally, with no error reported. rcp's own reader accumulates pax
records across headers, so it merges the two and is perfectly happy: every rcp-side
assertion -- round trip, digest, `verify`, hole preservation -- passes. **Only the
reference catches it**, which is the argument for running the other implementation rather
than trusting a green suite of one's own. The member header is therefore written inline
with no pax fallback, and every record the member needs is folded into the single sparse
header.

The replant is faithful and fires exactly there: restoring the `write_header` call leaves
every rcp-side assertion green and fails at the tar-interop half with

```
tar (GNU tar) 1.35 did not produce hole.bin; it extracted:
["GNUSparseFile.3942", "GNUSparseFile.3942/hole.bin"]
```

### The 8 MiB decision window

A member's header must be written before its bytes, and a sparse header needs the **whole**
map, which is not known until the last byte. So the choice cannot be made up front, and
deferring it to the end would mean buffering every dense file in the tree. The sink holds
the first **8 MiB** while it waits to see a hole:

- a hole in that window -> sparse, and the non-hole bytes spill to a temp file (bounded by
  the stored size, which is exactly what the archive will hold, not by the apparent size)
- 8 MiB of solid bytes with no hole -> the ordinary layout, header written then, bytes
  streaming straight through as before
- a hole that arrives **after** that -> written as the zeros it stands for, correct and
  larger

A file that is sparse is sparse by allocation pattern, not by coincidence at the tail, so
the early window catches the real cases. The third bullet is asserted by an arm rather than
left as a hope: a 12 MiB file solid for its first 9 MiB packs to more than 11 MiB, and
still round-trips to the same digest.

### The arms, and what each control is for

Three refusable shapes in the map, four in the validator, and two controls that are the
point rather than decoration:

- **a tree with no holes must not acquire a sparse header and must not shrink.** Without
  it, a writer that marked every member sparse -- or one that simply lost data and wrote a
  short archive -- passes every assertion about the sparse fixture.
- **the map the writer emits must validate.** Four refusal assertions pass trivially
  against a `validate` that refuses everything, which would make the reader useless while
  the arm stayed green.

Replanted three ways, each firing on its own line: the old flat-hole path fails the archive
size; the two-pax-header defect fails the tar-interop half; a reader that ignores
`GNU.sparse.*` fails the round trip.

**A green suite can hide a test that stopped running.** Inserting the map unit test above
an existing one left the existing test's `#[test]` attribute attached to the new function
and stripped it from the old: two registrations of the new arm, zero of
`a_member_that_climbs_out_of_the_archive_is_refused`. The suite stayed green. It was found
by reading the test-name list rather than the pass count: confirm the count is plausible
before concluding anything from a green run. 407 tests, up from 405 by exactly the two arms
added.

### Reading all four GNU sparse encodings

A reader that handles only pax 1.0 and relies on a version guard to refuse the rest does
not work, because the older pax forms carry no version at all. Measured, against archives
GNU tar 1.35 wrote from the same fixture, with only a 1.0 reader in place:

| encoding | what rcp did | length | digest |
| --- | --- | ---: | --- |
| old-GNU (`S`) | refused by name | — | — |
| pax 0.0 | **STATUS: PASSED** | 4,160 | `73b5cfe1a2e7` |
| pax 0.1 | **STATUS: PASSED** | 4,160 | `73b5cfe1a2e7` |
| pax 1.0 | PASSED | 67,108,928 | `c4f1e48a7199` (the source) |

Silent, successful, and a different file. The mechanism is one key: **`GNU.sparse.major`
arrived with 1.0**, so 0.0 and 0.1 carry no major at all, and the guard that refused "a
sparse format this reader does not have" never fired for them. They fell through to the
ordinary path, which read the extents as the whole file.

All four are read, which is the only sound resolution -- "refuse what we do not know"
does not work when the thing you do not know looks exactly like something ordinary.

| form | where the map lives | who writes it |
| --- | --- | --- |
| old-GNU | typeflag `S`: four `(offset, numbytes)` octal pairs at header+386, `isextended` at 482, `realsize` at 483, then 21 pairs per extension block while the chain continues | `tar --sparse` **by default**, so the likeliest to arrive |
| pax 0.0 | alternating `GNU.sparse.offset` / `GNU.sparse.numbytes` records, one pair per extent | `--sparse-version=0.0` |
| pax 0.1 | `GNU.sparse.map` = `off,len,off,len,...` | `--sparse-version=0.1` |
| pax 1.0 | a decimal map at the front of the member's own data | `--sparse-version=1.0`, and what rcp writes |

0.0 forced a second pax reader: records have to be kept **in order and with repeats**,
since a hundred extents collapsed into a `BTreeMap` become one -- the last -- and the file
that comes out is again a different file with nothing reporting it. `pax_list` is that
reader and `pax` is built from it.

The arm is a **sweep over all four**, and it asserts the COUNT (`read_back == 4`) rather
than `> 0`, because a sweep that quietly shrank to the one case that works is the failure
this exists to catch. Three replants, each firing where it should: 0.0/0.1 falling through
fails with `pax 0.0 (repeated offset/numbytes records): wrong length`; `S` not being a file
kind fails the copy; collapsing the pax records into a map fails the copy.

Only 1.0 is WRITTEN, deliberately -- it is the portable form, GNU tar and bsdtar both read
it, and writing four encodings of one idea would be four times the surface for no reader
that gains anything.

### Edge cases

| input | apparent | blocks | rcp round trip | `tar xf` |
| --- | ---: | ---: | --- | --- |
| entirely a hole, 16 MiB | 16,777,216 | 0 | same, 0 blocks | same, 0 blocks |
| data only at the tail | 8,388,608 | 8 | same | same |
| data only at the head | 8,388,608 | 8 | same | same |
| zero length | 0 | 0 | same | same |
| sparse + a hard link to it | 33,554,496 | 16 | same inode, 2 links, 16 blocks | 2 links, 16 blocks |

All four files pack to **18,432 bytes** together; gzipped, **523 bytes**. Sparse composes
with `.tar.gz` and with parallel decode, and `tar -xzf` reads the result with the hole
intact. None of these cases failed. The all-hole case was the one expected to break -- its
extent map is nothing but the terminator -- and it does not.

## Parallel gzip decode

A gzip member does not say how long it is. Its compressed length is known only once it has
been inflated, so the boundaries of a multi-member stream look irreducibly serial: to find
member 2 you must finish member 1.

What breaks the chain is that member starts are **findable**, if not decidable. Measured on
an 18.6 MB archive holding 83 MB of log text, written by this crate:

| | count |
| --- | ---: |
| occurrences of the magic `1f 8b` | 367 |
| surviving the header check (`CM == 8`, no reserved flag bits) | 22 |
| real members | 21 |

The cheap filter removes **94%** of the noise and leaves **one** false survivor. That ratio
is the whole feasibility argument: speculate on every survivor, and the waste is one
member in twenty-one.

**The chain, not the speculation, decides the output.** Results are collected by offset;
then the member list is walked exactly as the serial `gunzip` walks it — start at 0, take
that member's consumed length, look for a result at the offset it lands on, inflate on
demand if there is none — and only members ON that walk are concatenated. A false candidate
is simply an offset the walk never visits. Speculation can waste work; it cannot change the
answer.

Measured, release, four cores:

| workers | time | throughput | |
| ---: | ---: | ---: | --- |
| 1 | 0.748 s | 109 MiB/s | the serial path by definition |
| 2 | 0.471 s | 178 MiB/s | 1.59x |
| 4 | **0.328 s** | **256 MiB/s** | **2.34x** |
| 8 | 0.345 s | 243 MiB/s | past the core count, as expected |

End to end through `rcp copy tar://a.tar.gz DIR` the unpack goes ~1.93 s to ~0.87 s, but
that figure is **not** clean attribution — `-parallel 4` also parallelizes the file writing.
The isolated decode numbers above are the ones that mean something.

### A counter proves the parallel path runs

`gunzip_with` falls back to the serial path on anything it does not like, so an arm
asserting "the output is identical at 8 workers" passes while the parallel path is **never
entered**. A `#[cfg(test)]` counter reports `(candidates inflated, of those used by the
chain)`, and the arm asserts both.

The counter caught a defect on its first run. The gate was `data.len() < 2 * GZIP_BLOCK` —
and `data` is the **compressed** stream, so five 4 MiB members of ordinary text, which
compress to well under 8 MiB together, fell under the threshold and went serial. Every
equality assertion passed at every worker count, because the serial path is what they
compared against. The gate is the candidate count.

### Adversarial arms, and which property each one proves

The obvious adversarial arm plants plausible gzip headers inside a member's compressed
bytes — magic, method 8, no reserved flag bits — and checks the output is unharmed. The
fixture needs care: surrounding each decoy with a run of `0xAA` makes the region
compressible, so deflate emits matches and the bytes never reach the stream. Measured: 200
occurrences of `1f 8b`, 4 surviving the filter, and those 4 were the real members. Pure
random data stores rather than compresses, and then the fixture works: **222 occurrences,
21 surviving, 3 real members**.

**That arm proves less than it looks like.** Replanted two ways — a chain that trusts every
candidate, and no header filter at all — **it stays green both times**. Its decoys are
random bytes behind a valid-looking header, so `gunzip_member` rejects them at the **CRC**.
They never become results, and reassembling the successful results in offset order happens
to be right. The header filter and the CRC do the work; the chain is never tested.

So a second arm plants a **complete, valid gzip member** inside another member's stored
block: correct magic, correct deflate stream, correct CRC-32, correct ISIZE. Every check
short of the chain accepts it. The chain is the only thing keeping `DECOY CONTENT` out of
the output, and the replant that makes the chain trust its candidates fails by name.

The weaker arm is kept, with its doc comment saying exactly what it does and does not
prove, because "these decoys are rejected by the CRC" is a real property worth holding —
it is not the one the arm's name suggests.

To keep a failure readable, the arm compares the two 12 MB vectors by length and content and
reports the first differing index; `assert_eq!` on them prints **55 MB** on failure.

### Memory

Peak memory is the sum of every candidate that DECODED, not just the ones the chain keeps:
a false candidate's output sits in the map until the call returns. The expectation was
roughly 2x. Measured with `VmHWM` on the 83 MB archive:

| workers | peak RSS |
| ---: | ---: |
| 1 | 107 MiB |
| 4 | 108 MiB |
| 8 | 108 MiB |

Unchanged — and the reason is the `remove` that was added for SPEED. The chain walk takes
ownership of each member as it goes, so the map shrinks exactly as the output grows and
the peak is about one copy rather than two. Reverting that optimization would cost memory
as well as time.

### The hostile case, and why it is hard rather than impossible

A hidden member amplifies memory only if it both SURVIVES being embedded and EXPANDS. Those
requirements fight, and the measurement says so:

| planted decoy | compressed | copies planted | survived intact |
| --- | ---: | ---: | ---: |
| a member holding 8 MiB of zeros (≈1000x expansion) | 8,196 B | 27 | **0** |
| a member holding 256 KiB of random bytes (1x) | 262,242 B | 27 | **0** |
| a member holding 1 MiB of random bytes (1x) | 1,048,914 B | 7 | **0** |

To survive, a decoy's bytes must reach the stream literally, which needs its containing
block to be **stored** — and anything compressible enough to expand usefully tips that
block toward being compressed instead. Stored blocks also carry a header every 64 KiB,
which cuts any longer decoy in two. The decoys that DO survive elsewhere in these arms are
tens of bytes, precisely because they are too small to tip anything.

**"Hard for an adversary" is not a bound**, so there is one: speculation stops once the
decoded total passes `limit`, the ceiling the function was already given. Correctness does
not depend on where the cap falls, because the chain inflates on demand whatever the pool
did not reach — and that is asserted rather than assumed, by an arm requiring the limit to
mean the same thing on both paths, met and exceeded. Replanted by making the chain give up
instead of inflating on demand: it fails with *"the parallel path accepted a limit the
serial path refused"*, which is the silent truncation the arm exists to catch.
