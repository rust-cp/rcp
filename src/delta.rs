//! Delta transfer in the core: the destination signs its copy of a file (content-defined
//! chunks, a strong digest each), the source matches its own chunks against those
//! signatures and emits a patch (bytes the destination lacks, ranges it already has, holes),
//! and the destination applies the patch to a fresh file beside the old one. The shape is
//! Dsync's (Xiao et al.), two tiers: the chunker's Gear fingerprint filters, and the strong
//! digest decides.
//!
//! **This module said the opposite until it was measured**, and the sentence it said it in
//! named the very case where it is most wrong: "at BLAKE3 or SHA-NI speeds a strong digest
//! per chunk on both ends costs less than a weak tier saves." The source side digests every
//! byte TWICE -- once for the whole-file digest the destination checks its rebuild against,
//! and once per chunk to look the chunk up. Over 64 MiB, min of five runs:
//!
//! | algorithm | whole file | per 8 KiB chunk | the per-chunk pass is |
//! | --- | --- | --- | --- |
//! | sha256 | 225 MiB/s | 221 MiB/s | 50% of the hashing |
//! | blake3 | 1179 MiB/s | 266 MiB/s | **82%** |
//! | xxh3 | 568 MiB/s | 915 MiB/s | 38% |
//!
//! BLAKE3 is the worst case, not the best one, because an 8 KiB chunk is far too small for
//! its tree parallelism while the whole-file pass uses all of it. So the tier costs eight
//! bytes per signature -- 0.1% of the file at an 8 KiB average -- and skips the per-chunk
//! digest for every chunk whose fingerprint no signature carries, which on a file with
//! nothing in common is all of them.
//!
//! Everything here is pure: bytes in, signatures or patch steps out. Where the bytes come
//! from is the adapters' business, and every adapter gets these for free through the
//! `Tree` defaults; the ssh adapter runs the same code on the far side instead.

use std::collections::HashMap;
use std::io;

use crate::cdc::{Chunk, Chunker, Params};
use crate::ports::{is_all_zero, ChunkSig, Digest, Digests, Patch, DIGEST_LEN, ZEROS};

/// The chunking a file of `size` bytes gets: the average chunk grows with the square root
/// of the file, the way rsync's block size does, so the signature list and the granularity
/// of an edit grow together: 8 KiB up to 64 MiB, 32 KiB at 1 GiB, 1 MiB at 1 TiB, 4 MiB
/// from 16 TiB on.
pub fn params_for(size: u64) -> Params {
    let avg = size.isqrt().next_power_of_two().clamp(8 << 10, 4 << 20) as u32;
    Params {
        min: avg / 4,
        avg,
        max: avg * 8,
    }
}

/// Decodes the hex a `Digest` finishes with into its 32 bytes; anything else is refused
/// rather than folded into a digest that would alias others.
pub fn digest_bytes(hex: &str) -> io::Result<[u8; DIGEST_LEN]> {
    let b = hex.as_bytes();
    if b.len() != 2 * DIGEST_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "digest of {} hex characters, not {}",
                b.len(),
                2 * DIGEST_LEN
            ),
        ));
    }
    let mut out = [0u8; DIGEST_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&b[2 * i..2 * i + 2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "digest is not hex"))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("digest is not hex: {pair:?}"),
            )
        })?;
    }
    Ok(out)
}

/// Splits a byte stream into chunks that may straddle the pieces fed in: `piece(bytes,
/// done)` receives the bytes belonging to the chunk in progress, and `done` says the chunk
/// ends with them.
struct Splitter {
    chunker: Chunker,
    pending: Vec<Chunk>,
    /// Bytes of the chunk in progress already handed out.
    in_progress: usize,
}

impl Splitter {
    fn new(params: Params) -> Splitter {
        Splitter {
            chunker: Chunker::new(params),
            pending: Vec::new(),
            in_progress: 0,
        }
    }

    /// `piece(bytes, end)`: `end` is `Some(weak)` when those bytes finish a chunk, carrying
    /// the Gear fingerprint the chunker already computed for it, and `None` when more of
    /// the chunk is still to come. The weak hash is what makes the first tier free -- it is
    /// a by-product of finding the cut point, not a second pass.
    fn feed(
        &mut self,
        data: &[u8],
        piece: &mut dyn FnMut(&[u8], Option<u64>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.pending.clear();
        self.chunker.push(data, &mut self.pending);
        let mut cursor = 0usize;
        for c in &self.pending {
            let take = c.len as usize - self.in_progress;
            piece(&data[cursor..cursor + take], Some(c.weak))?;
            cursor += take;
            self.in_progress = 0;
        }
        if cursor < data.len() {
            piece(&data[cursor..], None)?;
            self.in_progress += data.len() - cursor;
        }
        Ok(())
    }

    /// Ends the chunk in progress, if any bytes are pending.
    fn finish(
        &mut self,
        piece: &mut dyn FnMut(&[u8], Option<u64>) -> io::Result<()>,
    ) -> io::Result<()> {
        match self.chunker.finish() {
            Some(c) => {
                self.in_progress = 0;
                piece(&[], Some(c.weak))?;
            }
            // the chunker and this count see the same bytes, so nothing pending here either
            None => debug_assert_eq!(self.in_progress, 0),
        }
        Ok(())
    }
}

/// One chunk being digested: the hasher, and how long it is so far.
struct Open {
    hasher: Box<dyn Digest>,
    len: u64,
}

fn digest_piece(open: &mut Option<Open>, digests: &dyn Digests, bytes: &[u8]) -> u64 {
    let o = open.get_or_insert_with(|| Open {
        hasher: digests.start(),
        len: 0,
    });
    o.hasher.update(bytes);
    o.len += bytes.len() as u64;
    o.len
}

fn close(open: &mut Option<Open>) -> io::Result<(u64, [u8; DIGEST_LEN])> {
    let o = open.take().expect("a chunk was open");
    Ok((o.len, digest_bytes(&o.hasher.finish())?))
}

/// Signs a destination file: feed its bytes (and holes), collect chunk signatures.
pub struct Signer<'a> {
    splitter: Splitter,
    digests: &'a dyn Digests,
    open: Option<Open>,
    next_offset: u64,
    sigs: Vec<ChunkSig>,
}

impl<'a> Signer<'a> {
    pub fn new(params: Params, digests: &'a dyn Digests) -> Signer<'a> {
        Signer {
            splitter: Splitter::new(params),
            digests,
            open: None,
            next_offset: 0,
            sigs: Vec::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> io::Result<()> {
        let (digests, open, next, sigs) = (
            self.digests,
            &mut self.open,
            &mut self.next_offset,
            &mut self.sigs,
        );
        self.splitter.feed(data, &mut |bytes, end| {
            digest_piece(open, digests, bytes);
            if let Some(weak) = end {
                let (len, digest) = close(open)?;
                sigs.push(ChunkSig {
                    offset: *next,
                    len: len as u32,
                    weak,
                    digest,
                });
                *next += len;
            }
            Ok(())
        })
    }

    /// A hole is a run of zeros to the chunker, in pieces the zero page can supply.
    pub fn feed_zeros(&mut self, mut n: u64) -> io::Result<()> {
        while n > 0 {
            let take = n.min(ZEROS.len() as u64) as usize;
            self.feed(&ZEROS[..take])?;
            n -= take as u64;
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<Vec<ChunkSig>> {
        let (open, next, sigs) = (&mut self.open, &mut self.next_offset, &mut self.sigs);
        self.splitter.finish(&mut |_, end| {
            let (len, digest) = close(open)?;
            sigs.push(ChunkSig {
                offset: *next,
                len: len as u32,
                weak: end.expect("finish ends a chunk"),
                digest,
            });
            *next += len;
            Ok(())
        })?;
        Ok(self.sigs)
    }
}

/// Matches a source file against a destination's signatures and emits the patch: a chunk
/// the destination has becomes a copy of its range there, a chunk of zeros becomes a hole,
/// any other becomes its literal bytes. A hole in the source is fed through the chunker as
/// zeros, exactly as the signer feeds the destination's holes, so both ends cut a sparse
/// file at the same points; the zero chunks then go out as holes, so the destination stays
/// sparse. The whole file is digested as it passes, so the destination can check what it
/// rebuilt.
pub struct Matcher<'a> {
    splitter: Splitter,
    /// The digester for CHUNK signatures, which is NOT the one `-hash` selects.
    ///
    /// A chunk signature is a wire detail between two rcps: it is compared only against
    /// signatures the peer just produced, never published, and the frame it travels in is
    /// `DIGEST_LEN` bytes wide. Handing it the user's `-hash` choice made `-delta -xxh3`
    /// fail `digest_bytes` on EVERY chunk -- an 8-byte digest into a 32-byte field -- and
    /// the error was swallowed into a `debug!`, so the run transferred every file whole
    /// and printed output byte-identical to a run without `-delta`. The caller passes the
    /// runtime's fixed strong digester here and its `-hash` choice to `whole`.
    chunks: &'a dyn Digests,
    /// Signatures by WEAK hash. A source chunk whose fingerprint is absent here cannot
    /// match any signature, so its strong digest is never computed -- the whole point of
    /// the tier. Collisions are expected and cheap: the list is walked and each candidate
    /// checked against the strong digest, which is what makes the weak hash a filter
    /// rather than a decision.
    known: HashMap<u64, Vec<(u32, [u8; DIGEST_LEN], u64)>>,
    whole: Box<dyn Digest>,
    chunk: Vec<u8>,
    /// Bytes the patch carried as literals, for the report.
    pub literal: u64,
    /// Chunks whose strong digest had to be computed, and chunks seen. Not a statistic for
    /// its own sake: the claim this tier makes is "the strong digest is skipped for a chunk
    /// that cannot match", and these two numbers are how a test measures it rather than
    /// believing it.
    pub strong_computed: u64,
    pub chunks_seen: u64,
}

impl<'a> Matcher<'a> {
    pub fn new(
        params: Params,
        sigs: &[ChunkSig],
        chunks: &'a dyn Digests,
        whole: &dyn Digests,
    ) -> Matcher<'a> {
        let mut known: HashMap<u64, Vec<(u32, [u8; DIGEST_LEN], u64)>> =
            HashMap::with_capacity(sigs.len());
        // Deduplicated through a SET, not by scanning the bucket. A scan would be
        // `at.iter().any(..)` per insert, so building the index is quadratic IN ONE WEAK
        // BUCKET -- and a bucket's contents are chosen by the peer that sends the
        // signatures. The weak hash is a Gear fingerprint, which is cheap to collide on
        // purpose, so an attacker-shaped signature list puts everything in one bucket:
        // with the scan, 200k signatures measured 35 seconds to index, and at the
        // server's own `MAX_SIGNATURES` ceiling of 8Mi that extrapolates to about 17
        // hours before a single byte is compared. The set makes it linear.
        //
        // The bucket can still be long, and the per-chunk walk over it is still O(bucket);
        // that walk is the tier doing its job and is bounded by the signature ceiling. The
        // quadratic term is the one that had no bound at all.
        let mut seen: std::collections::HashSet<(u64, u32, [u8; DIGEST_LEN])> =
            std::collections::HashSet::with_capacity(sigs.len());
        for s in sigs {
            if seen.insert((s.weak, s.len, s.digest)) {
                known
                    .entry(s.weak)
                    .or_default()
                    .push((s.len, s.digest, s.offset));
            }
        }
        Matcher {
            splitter: Splitter::new(params),
            chunks,
            known,
            whole: whole.start(),
            chunk: Vec::with_capacity(params.max as usize),
            literal: 0,
            strong_computed: 0,
            chunks_seen: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        digests: &dyn Digests,
        known: &HashMap<u64, Vec<(u32, [u8; DIGEST_LEN], u64)>>,
        chunk: &mut Vec<u8>,
        literal: &mut u64,
        strong_computed: &mut u64,
        chunks_seen: &mut u64,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
        bytes: &[u8],
        end: Option<u64>,
    ) -> io::Result<()> {
        chunk.extend_from_slice(bytes);
        let Some(weak) = end else { return Ok(()) };
        *chunks_seen += 1;
        let len = chunk.len() as u64;
        if is_all_zero(chunk) {
            emit(Patch::Hole(len))?;
            chunk.clear();
            return Ok(());
        }
        // The first tier. The chunk is buffered here anyway -- a literal needs its bytes --
        // so the strong digest is computed from the buffer ON DEMAND rather than fed
        // incrementally, which is what lets it be skipped at all.
        let candidates = known
            .get(&weak)
            .map(|v| {
                v.iter()
                    .filter(|(l, _, _)| *l as u64 == len)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut copied = None;
        if !candidates.is_empty() {
            *strong_computed += 1;
            let mut h = digests.start();
            h.update(chunk);
            let digest = digest_bytes(&h.finish())?;
            copied = candidates
                .iter()
                .find(|(_, d, _)| d == &digest)
                .map(|(_, _, offset)| *offset);
        }
        match copied {
            Some(offset) => emit(Patch::Copy { offset, len })?,
            None => {
                *literal += len;
                emit(Patch::Literal(chunk))?;
            }
        }
        chunk.clear();
        Ok(())
    }

    /// Feeds source bytes; `emit` receives every patch step completed inside them.
    pub fn feed(
        &mut self,
        data: &[u8],
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.whole.update(data);
        let (digests, known, chunk, literal) =
            (self.chunks, &self.known, &mut self.chunk, &mut self.literal);
        let (sc, cs) = (&mut self.strong_computed, &mut self.chunks_seen);
        self.splitter.feed(data, &mut |bytes, end| {
            Self::step(digests, known, chunk, literal, sc, cs, emit, bytes, end)
        })
    }

    /// A hole in the source: zeros to the chunker, in pieces the zero page can supply, so
    /// the cut points match the signer's; the chunks of zeros go out as holes.
    pub fn hole(
        &mut self,
        mut n: u64,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        while n > 0 {
            let take = n.min(ZEROS.len() as u64) as usize;
            self.feed(&ZEROS[..take], emit)?;
            n -= take as u64;
        }
        Ok(())
    }

    /// The last chunk, then the digest of the whole source.
    pub fn finish(
        mut self,
        emit: &mut dyn FnMut(Patch<'_>) -> io::Result<()>,
    ) -> io::Result<String> {
        let (digests, known, chunk, literal) =
            (self.chunks, &self.known, &mut self.chunk, &mut self.literal);
        let (sc, cs) = (&mut self.strong_computed, &mut self.chunks_seen);
        self.splitter.finish(&mut |bytes, end| {
            Self::step(digests, known, chunk, literal, sc, cs, emit, bytes, end)
        })?;
        Ok(self.whole.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn digests() -> Arc<dyn Digests> {
        crate::hash::Algorithm::Sha256.digests()
    }

    /// The weak tier's whole claim, counted rather than timed: a chunk whose fingerprint
    /// no signature carries never has its strong digest computed.
    ///
    /// Counting beats timing here. The saving is one hashing pass over the non-matching
    /// bytes, and a timing arm on a shared machine measures the machine; the number of
    /// strong digests computed is exactly the quantity the claim is about and does not
    /// move between runs.
    #[test]
    fn a_chunk_that_cannot_match_never_gets_a_strong_digest() {
        let params = Params {
            min: 2048,
            avg: 8192,
            max: 65536,
        };
        let basis = noise(1 << 20, 7);
        let sigs = sign(&basis, params, 100_003);
        assert!(
            sigs.len() > 50,
            "too few chunks for the ratio below to mean anything: {}",
            sigs.len()
        );

        // a source with nothing in common: every chunk is a literal, and the strong digest
        // is the work the tier exists to skip
        let fresh = noise(1 << 20, 99);
        let d = digests();
        let mut nothing = |_: Patch<'_>| -> io::Result<()> { Ok(()) };
        // `finish` consumes the matcher, so the counters are read before it: the last chunk
        // is one of many and the ratio is what the claim is about
        let mut m = Matcher::new(params, &sigs, &*d, &*d);
        for piece in fresh.chunks(100_003) {
            m.feed(piece, &mut nothing).unwrap();
        }
        assert!(m.chunks_seen > 50, "{} chunks", m.chunks_seen);
        assert_eq!(
            m.strong_computed, 0,
            "{} of {} chunks were strongly digested although none could match",
            m.strong_computed, m.chunks_seen
        );

        // The control, and it is the half that makes the arm mean anything: the SAME basis
        // against a source that does match must still compute strong digests, and must
        // still produce a correct patch. A tier that never computed one would pass the
        // line above while matching nothing ever again.
        let mut m = Matcher::new(params, &sigs, &*d, &*d);
        for piece in basis.chunks(100_003) {
            m.feed(piece, &mut nothing).unwrap();
        }
        assert!(m.strong_computed > 50, "an identical source computed {} strong digests; the tier is filtering out real matches", m.strong_computed);
        assert_eq!(
            m.strong_computed, m.chunks_seen,
            "every chunk of an identical source has a weak hit, so every one is checked"
        );

        // and end to end, which is the property no counter can stand in for: an identical
        // source is all copies and no literals, and a fresh one is all literals
        let (rebuilt, copied, lit, _) = patch(&basis, &basis, &sigs, params, 100_003, None);
        assert_eq!(rebuilt, basis);
        assert_eq!(
            (copied, lit),
            (basis.len() as u64, 0),
            "an identical source should copy everything"
        );
        let (rebuilt, copied, _, _) = patch(&basis, &fresh, &sigs, params, 100_003, None);
        assert_eq!(rebuilt, fresh);
        assert_eq!(
            copied, 0,
            "a source with nothing in common should copy nothing"
        );
    }

    /// A weak collision must not become a wrong copy. The fingerprint filters; the strong
    /// digest decides, and a signature list with a planted collision proves the second half
    /// is still doing the work.
    #[test]
    fn a_weak_collision_is_caught_by_the_strong_digest() {
        let params = Params {
            min: 2048,
            avg: 8192,
            max: 65536,
        };
        let basis = noise(1 << 19, 11);
        let source = noise(1 << 19, 12);
        let mut sigs = sign(&basis, params, 100_003);
        assert!(sigs.len() > 20, "{}", sigs.len());

        // every signature claims the weak hash of the source's FIRST chunk, so the filter
        // lets everything through and only the strong digest can refuse it
        let first_weak = {
            let mut probe = Vec::new();
            Chunker::new(params).push(&source, &mut probe);
            probe.first().expect("a chunk").weak
        };
        for s in sigs.iter_mut() {
            s.weak = first_weak;
        }
        // The filter is weak hash AND length, so this arm could pass without the strong
        // digest ever running: if every signature had the planted weak but its own length,
        // the length filter could reject them all and the assertion below would hold with
        // nothing checked. So the first signature
        // is given the source chunk's LENGTH as well, which makes the strong digest the
        // only thing left that can refuse it -- and its running is asserted, not assumed.
        let first_len = {
            let mut probe = Vec::new();
            Chunker::new(params).push(&source, &mut probe);
            probe.first().expect("a chunk").len
        };
        sigs[0].len = first_len;
        let (rebuilt, copied, _, _, strong) =
            patch_counting(&basis, &source, &sigs, params, 100_003);
        assert!(strong > 0, "the strong digest never ran, so the collision was refused by the length filter and this arm proves nothing about it");
        assert_eq!(rebuilt, source, "a weak collision produced the wrong bytes");
        assert_eq!(copied, 0, "a weak collision was taken as a match");

        // the control: with the real weak hashes, the same basis against itself still
        // copies -- so the line above is the strong digest refusing, not the matcher
        // refusing everything
        let sigs = sign(&basis, params, 100_003);
        let (rebuilt, copied, _, _) = patch(&basis, &basis, &sigs, params, 100_003, None);
        assert_eq!(rebuilt, basis);
        assert_eq!(copied, basis.len() as u64);
    }

    /// `-delta` with a digest narrower than `DIGEST_LEN` must still produce a patch.
    ///
    /// It did not. `Matcher` used ONE digester for both the chunk signatures and the
    /// whole-file digest, so `-hash xxh3` fed an 8-byte digest into `digest_bytes`, which
    /// refuses anything but 64 hex characters. Every chunk raised `InvalidData`, the error
    /// was swallowed into a `debug!` in `copy_one`, and the summary line is suppressed when
    /// `delta_files == 0` -- so `rcp copy -delta -xxh3` transferred every file whole and
    /// printed output byte-identical to a run with no `-delta` at all. Silent, and exactly
    /// the shape of failure that never gets reported.
    ///
    /// The control is the third assertion: the whole-file digest must actually be the
    /// narrow one asked for. A fix that quietly forced sha256 everywhere would pass the
    /// first two and break the `-hash` contract.
    #[test]
    fn a_narrow_whole_file_digest_does_not_disable_the_delta() {
        let params = Params {
            min: 512,
            avg: 2048,
            max: 8192,
        };
        let basis = noise(1 << 18, 11);
        let sigs = sign(&basis, params, 4096);
        assert!(sigs.len() > 20, "too few chunks: {}", sigs.len());

        let chunks = digests();
        let whole = crate::hash::Algorithm::Xxh3.digests();
        assert_eq!(
            whole.start().finish().len(),
            16,
            "xxh3 is 8 bytes, 16 hex characters"
        );

        let mut m = Matcher::new(params, &sigs, &*chunks, &*whole);
        let mut copied = 0u64;
        let mut literal = 0u64;
        for piece in basis.chunks(4096) {
            m.feed(piece, &mut |p: Patch<'_>| {
                match p {
                    Patch::Copy { len, .. } => copied += len,
                    Patch::Literal(b) => literal += b.len() as u64,
                    Patch::Hole(n) => literal += n,
                }
                Ok(())
            })
            .unwrap();
        }
        let digest = m
            .finish(&mut |p: Patch<'_>| {
                match p {
                    Patch::Copy { len, .. } => copied += len,
                    Patch::Literal(b) => literal += b.len() as u64,
                    Patch::Hole(n) => literal += n,
                }
                Ok(())
            })
            .expect("a narrow whole-file digest must not fail the match");
        assert!(
            copied > 0,
            "an identical source copied nothing: the delta is a no-op"
        );
        assert_eq!(
            literal, 0,
            "an identical source sent {literal} literal bytes"
        );
        assert_eq!(
            digest.len(),
            16,
            "the whole-file digest must still be the one -hash asked for, not sha256"
        );

        // The measurement of red, in the same arm: the OLD wiring is exactly this call with
        // the narrow digester in BOTH slots, and it must fail. Without this line the arm
        // would pass just as happily against code that never had the defect.
        let mut old = Matcher::new(params, &sigs, &*whole, &*whole);
        let mut fed = Ok(());
        for piece in basis.chunks(4096) {
            fed = old.feed(piece, &mut |_: Patch<'_>| Ok(()));
            if fed.is_err() {
                break;
            }
        }
        let old = fed.and_then(|()| old.finish(&mut |_: Patch<'_>| Ok(())));
        assert!(old.is_err(), "one digester for both roles produced {old:?}; the defect this arm covers is gone from the test, not from the code");
    }

    /// Building the signature index is LINEAR in the number of signatures, even when the
    /// peer puts every one of them in the same weak bucket.
    ///
    /// A dedup that scans the bucket on each insert is quadratic. The weak hash is a Gear
    /// fingerprint and the signature list comes from the far side, so one bucket holding
    /// everything is a list a peer can simply choose to send. Measured with the scan at
    /// 200k signatures: 35 seconds, and `MAX_SIGNATURES` (8Mi) extrapolates to about 17
    /// hours before the first byte is compared.
    ///
    /// **A RATIO OF TWO TIMINGS IS THE WRONG SHAPE FOR THIS TEST.** It is tempting to argue
    /// that a ratio beats a wall clock because "a timing assertion on a shared runner is a
    /// flake generator" -- true of a TIGHT wall clock, and a ratio test is typically tighter
    /// still: one sample per size, bound 20 against a linear prediction of 8, is 2.5x of
    /// margin and no repeats at all. A sibling ratio test in `dav/xml.rs` with three times
    /// that margin AND a minimum over five runs still failed twice on a loaded machine. Never
    /// having been seen to fail is not the same as robust.
    ///
    /// So the shape is: **one size, chosen so the two complexity classes are three orders
    /// of magnitude apart, and an absolute bound in the middle of that gap.**
    /// Measured on this machine, in the debug profile the suite actually runs:
    ///
    /// | | 500,000 signatures, one bucket |
    /// | --- | --- |
    /// | shipped (set) | **0.69 s** |
    /// | quadratic (replanted) | **~22 minutes** -- 13.29 s at a TENTH of the size, and it grows as the square |
    ///
    /// The bound is 20 s: twenty-nine times the linear measurement, and the replant passes
    /// it at about an eighth of this arm's size. A wall clock is a flake generator when the
    /// margin is small; no scheduler turns 0.69 s into 20 s.
    ///
    /// Counting the work instead, as `dav/xml.rs` does, was considered and does not
    /// fit: there is no single place every bucket scan must pass through, so a counter
    /// would only catch a scan that had been helpfully instrumented to be caught.
    #[test]
    fn one_weak_bucket_holding_everything_indexes_in_linear_time() {
        let params = Params {
            min: 512,
            avg: 2048,
            max: 8192,
        };
        // every signature in ONE bucket (`weak: 0`) with a DISTINCT digest, so the dedup
        // can never short-circuit
        let adversarial = |n: usize| -> Vec<ChunkSig> {
            (0..n)
                .map(|i| {
                    let mut digest = [0u8; DIGEST_LEN];
                    digest[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    ChunkSig {
                        offset: i as u64 * 1024,
                        len: 1024,
                        weak: 0,
                        digest,
                    }
                })
                .collect()
        };
        let d = digests();
        const N: usize = 500_000;
        let sigs = adversarial(N);
        let t = std::time::Instant::now();
        let m = Matcher::new(params, &sigs, &*d, &*d);
        let took = t.elapsed().as_secs_f64();
        // reading the index back keeps the matcher alive past the measurement AND is the
        // first control: an index that dropped its entries would be fast and useless
        assert_eq!(
            m.known.values().map(Vec::len).sum::<usize>(),
            N,
            "the index dropped entries instead of holding them"
        );
        assert_eq!(m.known.len(), 1, "the arm is not exercising one bucket");
        assert!(took < 20.0, "indexing {N} signatures in one weak bucket took {took:.2}s; linear is about 0.1s here and the quadratic this guards against is minutes");

        // The control: the same list must still MATCH. An index that dropped the entries
        // would be linear and useless, and would pass the line above.
        let sigs = adversarial(64);
        let m = Matcher::new(params, &sigs, &*d, &*d);
        assert_eq!(m.known.len(), 1, "the arm is not exercising one bucket");
        assert_eq!(
            m.known[&0].len(),
            64,
            "the index dropped entries instead of holding them"
        );
    }

    fn sign(data: &[u8], params: Params, feed: usize) -> Vec<ChunkSig> {
        let d = digests();
        let mut s = Signer::new(params, &*d);
        for piece in data.chunks(feed) {
            s.feed(piece).unwrap();
        }
        s.finish().unwrap()
    }

    /// Runs the matcher over `source` in pieces and applies the patch to `basis` the way a
    /// sink would: the rebuilt bytes, the copied byte count, the literal count, the digest.
    fn patch(
        basis: &[u8],
        source: &[u8],
        sigs: &[ChunkSig],
        params: Params,
        feed: usize,
        hole_at: Option<(usize, u64)>,
    ) -> (Vec<u8>, u64, u64, String) {
        let (out, copied, literal, digest, _) =
            patch_inner(basis, source, sigs, params, feed, hole_at);
        (out, copied, literal, digest)
    }

    /// `patch`, also returning how many strong digests the matcher computed.
    fn patch_counting(
        basis: &[u8],
        source: &[u8],
        sigs: &[ChunkSig],
        params: Params,
        feed: usize,
    ) -> (Vec<u8>, u64, u64, String, u64) {
        patch_inner(basis, source, sigs, params, feed, None)
    }

    fn patch_inner(
        basis: &[u8],
        source: &[u8],
        sigs: &[ChunkSig],
        params: Params,
        feed: usize,
        hole_at: Option<(usize, u64)>,
    ) -> (Vec<u8>, u64, u64, String, u64) {
        let d = digests();
        let mut m = Matcher::new(params, sigs, &*d, &*d);
        let mut out = Vec::new();
        let mut copied = 0u64;
        let mut emit = |p: Patch<'_>| -> io::Result<()> {
            match p {
                Patch::Literal(b) => out.extend_from_slice(b),
                Patch::Copy { offset, len } => {
                    copied += len;
                    out.extend_from_slice(&basis[offset as usize..(offset + len) as usize]);
                }
                Patch::Hole(n) => out.extend(std::iter::repeat_n(0u8, n as usize)),
            }
            Ok(())
        };
        let mut fed = 0usize;
        for piece in source.chunks(feed) {
            if let Some((at, n)) = hole_at {
                if fed == at {
                    m.hole(n, &mut emit).unwrap();
                }
            }
            m.feed(piece, &mut emit).unwrap();
            fed += piece.len();
        }
        let literal = m.literal;
        let strong = m.strong_computed;
        let digest = m.finish(&mut emit).unwrap();
        (out, copied, literal, digest, strong)
    }

    fn whole(data: &[u8]) -> String {
        let mut h = digests().start();
        h.update(data);
        h.finish()
    }

    #[test]
    fn a_changed_region_travels_as_literals_and_the_rest_as_copies() {
        let params = params_for(4 << 20);
        let basis = noise(4 << 20, 1);
        let mut source = basis.clone();
        let edit = noise(256 << 10, 2);
        source[1 << 20..(1 << 20) + edit.len()].copy_from_slice(&edit);
        let sigs = sign(&basis, params, 100_003);
        assert_eq!(
            sigs.iter().map(|s| s.len as u64).sum::<u64>(),
            basis.len() as u64
        );
        assert_eq!(
            sign(&basis, params, 1 << 20),
            sigs,
            "signatures do not depend on how the bytes were fed"
        );
        let (out, copied, literal, digest) = patch(&basis, &source, &sigs, params, 65_537, None);
        assert_eq!(out, source, "the patch rebuilds the source");
        assert_eq!(
            digest,
            whole(&source),
            "the matcher digests the whole source"
        );
        assert_eq!(copied + literal, source.len() as u64);
        assert!(
            literal >= edit.len() as u64 && literal < 2 * edit.len() as u64,
            "{literal} literal bytes for a {} byte edit",
            edit.len()
        );
        // controls: a source with nothing in common is all literals, and so is a new file
        // (no signatures at all); both still rebuild exactly
        let other = noise(4 << 20, 9);
        let (out, copied, _, _) = patch(&basis, &other, &sigs, params, 4096, None);
        assert_eq!((out, copied), (other, 0));
        let (out, copied, _, _) = patch(&basis, &source, &[], params, 1 << 20, None);
        assert_eq!((out, copied), (source, 0));
    }

    #[test]
    fn holes_and_a_shorter_source_come_out_exact_and_parameters_scale() {
        let params = params_for(1 << 20);
        let basis = noise(1 << 20, 3);
        let sigs = sign(&basis, params, 1 << 20);
        // the source: the first half of the basis, a hole, then a new tail
        let mut source = basis[..512 << 10].to_vec();
        let tail = noise(10_000, 4);
        source.extend_from_slice(&tail);
        let (out, copied, _, digest) = patch(
            &basis,
            &source,
            &sigs,
            params,
            512 << 10,
            Some((512 << 10, 100_000)),
        );
        let mut expect = basis[..512 << 10].to_vec();
        expect.extend(std::iter::repeat_n(0u8, 100_000));
        expect.extend_from_slice(&tail);
        assert_eq!(out, expect);
        assert_eq!(digest, whole(&expect));
        assert!(copied > 400 << 10, "the unchanged half is copied: {copied}");
        // a sparse file identical on both sides moves nothing: the signer and the matcher
        // cut the zeros the same way, and the zero chunks go out as holes
        let head = noise(1000, 5);
        let tail = noise(1000, 6);
        let d2 = digests();
        let mut s = Signer::new(params, &*d2);
        s.feed(&head).unwrap();
        s.feed_zeros(4 << 20).unwrap();
        s.feed(&tail).unwrap();
        let sigs = s.finish().unwrap();
        let mut m = Matcher::new(params, &sigs, &*d2, &*d2);
        let mut holes = 0u64;
        let mut copied = 0u64;
        let mut literal_bytes = 0u64;
        let mut emit = |p: Patch<'_>| -> io::Result<()> {
            match p {
                Patch::Literal(b) => literal_bytes += b.len() as u64,
                Patch::Copy { len, .. } => copied += len,
                Patch::Hole(n) => holes += n,
            }
            Ok(())
        };
        m.feed(&head, &mut emit).unwrap();
        m.hole(4 << 20, &mut emit).unwrap();
        m.feed(&tail, &mut emit).unwrap();
        m.finish(&mut emit).unwrap();
        assert_eq!(
            literal_bytes, 0,
            "an unchanged sparse file sends no literals"
        );
        assert!(
            holes > (4 << 20) - (2 * params.max as u64),
            "the zeros travel as holes: {holes}"
        );
        assert_eq!(holes + copied, 2000 + (4 << 20));
        // and a hole signed on the destination side chunks as zeros
        let d = digests();
        let mut s = Signer::new(params, &*d);
        s.feed(&basis[..1000]).unwrap();
        s.feed_zeros(3 << 20).unwrap();
        let sigs = s.finish().unwrap();
        assert_eq!(
            sigs.iter().map(|s| s.len as u64).sum::<u64>(),
            1000 + (3 << 20)
        );
        assert_eq!(params_for(32 << 20).avg, 8 << 10);
        assert_eq!(params_for(1 << 30).avg, 32 << 10);
        assert_eq!(params_for(1 << 40).avg, 1 << 20);
        assert_eq!(params_for(1 << 50).avg, 4 << 20);
        assert_eq!(params_for(10).avg, 8 << 10);
        let hex = format!("{}{}", "00ff10", "a".repeat(58));
        assert_eq!(&digest_bytes(&hex).unwrap()[..3], &[0, 255, 16]);
        // controls: a short digest and a non-hex one are refused, not aliased to zeros
        assert!(digest_bytes("00ff10").is_err());
        assert!(digest_bytes(&"zz".repeat(32)).is_err());
    }
}
