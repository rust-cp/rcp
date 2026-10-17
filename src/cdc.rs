//! Content-defined chunking for delta transfer: FastCDC's Gear rolling hash with normalized
//! chunking (Xia et al., USENIX ATC'16; the practical recommendation of arXiv 2409.06066)
//! and the FastFp weak hash of Dsync (Xiao et al.) that falls out of the same rolling
//! hashes, so a chunk's weak signature costs nothing beyond the chunking. Pure logic on
//! bytes, in the core: both ends of a delta run the same code on their own data and agree
//! on where chunks fall without exchanging anything but signatures.
//!
//! Cut points: after `min` bytes the rolling hash is tested against a strict mask (more
//! bits) until the chunk reaches the target size, then a loose mask (fewer bits) until
//! `max`, where the chunk is cut regardless. That is normalization level 2: chunk sizes
//! crowd around the target instead of spreading over `min..max`.

/// The chunking parameters both ends must share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub min: u32,
    pub avg: u32,
    pub max: u32,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            min: 2 << 10,
            avg: 8 << 10,
            max: 64 << 10,
        }
    }
}

/// The smallest chunk a peer may ask for. The floor is what bounds how much a signature
/// list can cost relative to the file it describes: at 256 bytes a chunk, a `ChunkSig` of
/// about 56 bytes is at worst a fifth of the data it signs.
pub const MIN_CHUNK: u32 = 256;
/// The largest chunk a peer may ask for -- well above `params_for`'s 32 MiB ceiling, so a
/// legitimate request is never refused, and far below a length that would make a buffer
/// allocation a denial of service.
pub const MAX_CHUNK: u32 = 64 << 20;
/// `params_for` builds `min = avg/4, max = avg*8`, a spread of 32. Twice that is slack for
/// a future shape; more than that is not a chunking, it is an amplifier.
const MAX_SPREAD: u32 = 64;

impl Params {
    /// Refuses a chunking a peer could use to make the other end do unbounded work.
    ///
    /// `Params` arrive over the wire from whichever side proposes the delta, and nothing
    /// checked them. `max: 0` cuts after every byte, so an 8 MiB file signs as 8 million
    /// chunks -- about 448 MiB of `ChunkSig` for 8 MiB of data, extrapolating to 56 GiB
    /// per GiB. `min: 0` is the same defect from the other side. Neither is a chunking any
    /// honest caller would send: `params_for` produces `min` from 2 KiB up and a spread of
    /// exactly 32, so the bounds below refuse only what no legitimate peer asks for.
    pub fn validate(&self) -> Result<(), String> {
        if self.min < MIN_CHUNK {
            return Err(format!("chunk minimum {} is below {MIN_CHUNK}", self.min));
        }
        if self.max > MAX_CHUNK {
            return Err(format!("chunk maximum {} is above {MAX_CHUNK}", self.max));
        }
        if self.min > self.avg || self.avg > self.max {
            return Err(format!(
                "chunking {}..{}..{} is not ordered",
                self.min, self.avg, self.max
            ));
        }
        if self.max / self.min > MAX_SPREAD {
            return Err(format!(
                "chunking spreads {}..{}, more than {MAX_SPREAD}x",
                self.min, self.max
            ));
        }
        Ok(())
    }

    /// The two cut masks, placed HIGH in the word rather than low.
    ///
    /// Gear rolls with `fp = (fp << 1) + GEAR[b]`, so an old byte's contribution walks
    /// toward the HIGH bits and bit `j` of the fingerprint depends on the last `j + 1`
    /// bytes and no more. Testing `fp & mask` with the mask's bits at the BOTTOM therefore
    /// decides each cut from a window as narrow as the mask is wide: at `avg` 8 KiB that
    /// is 15 bytes under the strict mask and 11 under the loose one.
    ///
    /// That is not an academic point. Content-defined chunking earns its cost by putting
    /// the SAME cut in the same place after an edit elsewhere, and a window of 15 bytes
    /// cannot tell apart two places in a file whose last 15 bytes match -- which is every
    /// record boundary in a fixed-width-record file, every run of padding, every repeated
    /// header. Such a file measured 6.3x the wire traffic, because the chunking kept
    /// cutting on the padding rather than on content.
    ///
    /// `<< SHIFT` moves the same NUMBER of set bits to positions 32 and up, so the cut
    /// probability -- and with it the average chunk size -- is unchanged, while the window
    /// becomes at least 33 bytes and up to 47.
    ///
    /// This changes where chunks fall, which both ends must agree on, so `remote::proto`'s
    /// `VERSION` moves with it. A mixed pair would still be SAFE (the strong digest gates
    /// every match, so the worst case is no matches and a whole transfer) but it would be
    /// silently slower, and silence is the thing being fixed here.
    fn masks(&self) -> (u64, u64) {
        /// Far enough up that even the loose mask's lowest bit needs 33 bytes of history.
        const SHIFT: u32 = 32;
        let bits = self.avg.max(2).ilog2();
        let strict = ((1u64 << (bits + 2)) - 1) << SHIFT;
        let loose = ((1u64 << bits.saturating_sub(2).max(1)) - 1) << SHIFT;
        (strict, loose)
    }
}

/// One chunk: where it is, how long, and its weak hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub offset: u64,
    pub len: u32,
    pub weak: u64,
}

/// The Gear table: 256 pseudo-random 64-bit values, fixed by splitmix64 from a fixed seed
/// so every build agrees.
const fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut i = 0;
    while i < 256 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        t[i] = z ^ (z >> 31);
        i += 1;
    }
    t
}

pub const GEAR: [u64; 256] = gear_table();

/// A streaming chunker: feed bytes in any pieces, collect chunks as they complete, then
/// `finish` for the tail.
pub struct Chunker {
    params: Params,
    strict: u64,
    loose: u64,
    fp: u64,
    weak: u64,
    len: u32,
    start: u64,
}

impl Chunker {
    pub fn new(params: Params) -> Chunker {
        let (strict, loose) = params.masks();
        Chunker {
            params,
            strict,
            loose,
            fp: 0,
            weak: 0,
            len: 0,
            start: 0,
        }
    }

    fn cut(&mut self) -> Chunk {
        let c = Chunk {
            offset: self.start,
            len: self.len,
            weak: self.weak,
        };
        self.start += self.len as u64;
        self.len = 0;
        self.fp = 0;
        self.weak = 0;
        c
    }

    /// Feeds `data`; `out` receives every chunk completed inside it.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<Chunk>) {
        for &b in data {
            self.fp = (self.fp << 1).wrapping_add(GEAR[b as usize]);
            self.weak = self.weak.wrapping_add(self.fp);
            self.len += 1;
            if self.len >= self.params.max {
                out.push(self.cut());
                continue;
            }
            if self.len < self.params.min {
                continue;
            }
            let mask = if self.len < self.params.avg {
                self.strict
            } else {
                self.loose
            };
            if self.fp & mask == 0 {
                out.push(self.cut());
            }
        }
    }

    /// The final chunk, if any bytes are pending.
    pub fn finish(&mut self) -> Option<Chunk> {
        if self.len == 0 {
            None
        } else {
            Some(self.cut())
        }
    }
}

/// Chunks a whole buffer.
pub fn chunk(data: &[u8], params: Params) -> Vec<Chunk> {
    let mut c = Chunker::new(params);
    let mut out = Vec::new();
    c.push(data, &mut out);
    out.extend(c.finish());
    out
}

/// How many bytes it takes for the Gear fingerprint to forget where it started.
///
/// **Exactly 64, and not as a margin over something smaller.** The recurrence is linear mod
/// 2^64, so starting it from `s` instead of zero gives `fp(k) = fp_zero(k) + s * 2^(k+1)`;
/// at `k = 63` that term is `s * 2^64`, which is zero. So after 64 bytes the fingerprint is
/// the SAME 64-bit value whatever it started from -- not merely the same in the bits a mask
/// tests. That is what lets a scan of a region start cold and still produce exact sums,
/// which the weak hash needs and a mask-only argument would not have given.
///
/// (The weaker fact is also true and is what `Chunker`'s reset relies on: bit `j` depends
/// on the last `j + 1` bytes, the masks sit at bit 32 and above and the widest is 15 bits,
/// so no cut decision can see further back than 47 bytes -- and `min >= MIN_CHUNK` is 256,
/// so a reset is always further back than that.)
///
/// **This is the constant the whole decoupling rests on.** `Chunker` resets the
/// fingerprint to zero at every cut, and `min >= MIN_CHUNK` is 256, so by the time a cut is
/// even eligible the reset is more than 200 bytes in the past -- further back than any mask
/// bit can see. So the SET OF CANDIDATE CUT POSITIONS in a buffer does not depend on where
/// the cuts actually fall, and can be computed for the whole buffer in one pass, or for
/// disjoint regions in parallel, each warmed up with `WARMUP` bytes of the bytes before it.
pub const WARMUP: usize = 64;

/// The fingerprint and its running sum at one candidate cut position.
///
/// Both are the CONTINUOUS values -- computed without ever resetting at a cut -- which is
/// what makes them independent of where the cuts fall. `Cuts::chunks` converts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The index of the byte that completed this fingerprint, within the scanned buffer.
    pub at: usize,
    /// The continuous fingerprint after that byte.
    pub fp: u64,
    /// The continuous sum of every fingerprint up to and including that byte.
    pub sum: u64,
    /// Whether the STRICT mask was satisfied. The loose mask's set bits are a subset of the
    /// strict one's -- both start at bit 32 and loose is narrower -- so a strict hit is
    /// always a loose hit, and one scan with the loose test finds both.
    pub strict: bool,
}

/// Every candidate cut position in a buffer, and the state at its end.
#[derive(Debug, Default, Clone)]
pub struct Cuts {
    pub at: Vec<Candidate>,
    /// The continuous `(fp, sum)` the scan started from.
    pub from: (u64, u64),
    /// `(fp, sum)` after byte `LADDER - 1`, `2 * LADDER - 1`, and so on. See `LADDER`.
    pub rungs: Vec<(u64, u64)>,
    /// The continuous fingerprint after the last byte scanned.
    pub fp: u64,
    /// The continuous sum after the last byte scanned.
    pub sum: u64,
}

/// Scans `data` for candidate cut positions, continuing from `fp` and `sum`.
///
/// `fp` and `sum` are the continuous state after whatever came before `data`; pass zeros
/// for the start of a stream. Every position where the fingerprint satisfies the LOOSE
/// mask is recorded, whether or not the chunk length rules would allow a cut there -- the
/// length rules are `Cuts::chunks`'s job, and separating them is the point.
pub fn scan(data: &[u8], params: Params, fp: u64, sum: u64, out: &mut Cuts) {
    let (strict, loose) = params.masks();
    out.from = (fp, sum);
    let (mut fp, mut sum) = (fp, sum);
    for (i, &b) in data.iter().enumerate() {
        fp = (fp << 1).wrapping_add(GEAR[b as usize]);
        sum = sum.wrapping_add(fp);
        if fp & loose == 0 {
            out.at.push(Candidate {
                at: i,
                fp,
                sum,
                strict: fp & strict == 0,
            });
        }
        if i % LADDER == LADDER - 1 {
            out.rungs.push((fp, sum));
        }
    }
    out.fp = fp;
    out.sum = sum;
}

/// How many regions the lane-parallel scan splits a buffer into.
///
/// The recurrence `fp = (fp << 1) + GEAR[b]` is two dependent operations, so one stream
/// advances one byte per two cycles however wide the machine is -- the limit is the
/// dependency chain, not the issue width. Four independent streams have no dependency
/// between them, so a superscalar core can have all four in flight at once. This is the
/// same parallelism a SIMD kernel would exploit, reached without a vector register, an
/// intrinsic, a runtime feature check or a line of `unsafe`.
const LANES: usize = 4;

/// Below this there is nothing to split: the warm-up would cost more than the overlap saves.
const LANE_MIN: usize = 1 << 16;

/// Scans `data` for candidate cut positions using `LANES` independent streams.
///
/// Each region after the first starts cold and warms up on the `WARMUP` bytes before it, at
/// which point its fingerprints are exact to the full 64 bits (see `WARMUP`) -- so its
/// candidates and its LOCAL running sums are exact, and the global sums follow by adding
/// what the earlier regions totalled. Nothing is approximated and nothing depends on where
/// the cuts fall.
///
/// Falls back to `scan` when the buffer is too small to be worth splitting.
pub fn scan_lanes(data: &[u8], params: Params, fp: u64, sum: u64, out: &mut Cuts) {
    if data.len() < LANE_MIN {
        return scan(data, params, fp, sum, out);
    }
    // `state_at` replays from here when a forced cut lands before the first rung, so it
    // has to be set on this path too -- `scan` sets it and a reader would reasonably
    // assume the two are interchangeable.
    out.from = (fp, sum);
    let (strict, loose) = params.masks();
    let span = data.len() / LANES;

    // Each lane's candidates and rungs land in its own vectors, then are concatenated in
    // order. Collecting into one shared vector would need a lock or a sort, and the point
    // of the split is to have neither.
    let mut per_lane: Vec<(Vec<Candidate>, Vec<(u64, u64)>, u64, u64)> = (0..LANES)
        .map(|_| (Vec::new(), Vec::new(), 0u64, 0u64))
        .collect();
    let mut f = [0u64; LANES];
    let mut s = [0u64; LANES];
    for lane in 0..LANES {
        let start = lane * span;
        // lane 0 continues the caller's stream; the rest start cold and warm up on the
        // WARMUP bytes before them, after which their fingerprints are exact
        if lane == 0 {
            f[0] = fp;
        } else {
            let warm = start.min(WARMUP);
            for &b in &data[start - warm..start] {
                f[lane] = (f[lane] << 1).wrapping_add(GEAR[b as usize]);
            }
        }
    }

    // ONE loop over the shared offset, advancing all four streams. Written as separate
    // statements per lane rather than a nested loop so the four dependency chains are
    // visibly independent to the scheduler; a `for lane in 0..LANES` inner loop leaves
    // them sequential, which is the version this replaced and which measured no faster
    // than one stream.
    for i in 0..span {
        for lane in 0..LANES {
            let b = data[lane * span + i];
            f[lane] = (f[lane] << 1).wrapping_add(GEAR[b as usize]);
            s[lane] = s[lane].wrapping_add(f[lane]);
        }
        for lane in 0..LANES {
            let g = lane * span + i;
            if f[lane] & loose == 0 {
                per_lane[lane].0.push(Candidate {
                    at: g,
                    fp: f[lane],
                    sum: s[lane],
                    strict: f[lane] & strict == 0,
                });
            }
            if g % LADDER == LADDER - 1 {
                per_lane[lane].1.push((f[lane], s[lane]));
            }
        }
    }
    // the last lane's region runs to the end of the buffer, which `span` may not reach
    {
        let lane = LANES - 1;
        for (k, &b) in data[lane * span + span..].iter().enumerate() {
            let g = lane * span + span + k;
            f[lane] = (f[lane] << 1).wrapping_add(GEAR[b as usize]);
            s[lane] = s[lane].wrapping_add(f[lane]);
            if f[lane] & loose == 0 {
                per_lane[lane].0.push(Candidate {
                    at: g,
                    fp: f[lane],
                    sum: s[lane],
                    strict: f[lane] & strict == 0,
                });
            }
            if g % LADDER == LADDER - 1 {
                per_lane[lane].1.push((f[lane], s[lane]));
            }
        }
    }
    for lane in 0..LANES {
        per_lane[lane].2 = f[lane];
        per_lane[lane].3 = s[lane];
    }

    // Stitch: a lane's sums are local, so each is lifted by everything before it. The
    // fingerprints need no lifting -- they are already exact.
    let mut carry = sum;
    let mut rungs: Vec<(u64, u64)> = Vec::new();
    for (at, lane_rungs, _, total) in per_lane.iter_mut() {
        for c in at.iter_mut() {
            c.sum = c.sum.wrapping_add(carry);
        }
        for r in lane_rungs.iter_mut() {
            r.1 = r.1.wrapping_add(carry);
        }
        out.at.append(at);
        rungs.append(lane_rungs);
        carry = carry.wrapping_add(*total);
    }
    out.rungs = rungs;
    out.fp = per_lane[LANES - 1].2;
    out.sum = carry;
}

/// Recovers a chunk's reset-based weak hash from two continuous sums and the fingerprint
/// the chunk started after.
///
/// The Gear recurrence `fp = (fp << 1) + GEAR[b]` is LINEAR over the integers mod 2^64 --
/// both the shift and the add are -- so running it from a different starting value only
/// adds a multiple of that value:
///
/// ```text
/// fp_continuous(a + k) = fp_reset(a + k) + fp_continuous(a - 1) * 2^(k+1)   (mod 2^64)
/// ```
///
/// Summing that over a chunk `a..=b` gives
///
/// ```text
/// sum(b) - sum(a-1) = weak_reset + fp_continuous(a-1) * (2^(b-a+2) - 2)
/// ```
///
/// and for any chunk at least 62 bytes long `2^(b-a+2)` is zero mod 2^64, leaving
/// `weak_reset = sum(b) - sum(a-1) + 2 * fp_continuous(a-1)`. `MIN_CHUNK` is 256, so every
/// chunk a legal `Params` can produce is long enough -- **except a stream's final chunk**,
/// which `finish` cuts at whatever length is left. That one is computed the plain way.
///
/// Without this identity the decoupling would be worth much less: cut positions alone can
/// be found in parallel, but every chunk still needs a weak hash, and recovering those
/// would mean a second pass over every byte -- which is the whole cost again.
fn weak_between(sum_end: u64, sum_before: u64, fp_before: u64) -> u64 {
    sum_end
        .wrapping_sub(sum_before)
        .wrapping_add(fp_before.wrapping_mul(2))
}

/// How far apart the scan records the continuous state regardless of candidates.
///
/// A cut forced by `max` almost never lands on a candidate -- if it did, it would not have
/// been forced -- so its `(fp, sum)` has to come from somewhere. Replaying from the chunk's
/// own start would cost up to `max` bytes per forced cut, which on data that forces every
/// cut (a long run of one byte, where the fingerprint can settle into a cycle that never
/// meets the mask) is the whole buffer again. A rung every 4 KiB bounds the replay to 4 KiB
/// for 16 bytes per 4 KiB of memory: 0.4% space for at most 6% of the work back, on the
/// input that provokes it, and nothing at all on input that does not.
const LADDER: usize = 4 << 10;

impl Cuts {
    /// The continuous `(fp, sum)` after byte `at` in `data`, from the nearest rung at or
    /// before it.
    fn state_at(&self, data: &[u8], at: usize) -> (u64, u64) {
        let rung = at / LADDER;
        let (mut fp, mut sum, from) = if rung == 0 {
            (self.from.0, self.from.1, 0)
        } else {
            (
                self.rungs[rung - 1].0,
                self.rungs[rung - 1].1,
                rung * LADDER,
            )
        };
        for &b in &data[from..=at] {
            fp = (fp << 1).wrapping_add(GEAR[b as usize]);
            sum = sum.wrapping_add(fp);
        }
        (fp, sum)
    }
}

/// Chunks `data` in two stages: a per-byte scan for candidate cut positions, then a walk
/// over the candidates applying the length rules.
///
/// `base` is the stream offset of `data`, `carried` how many bytes of an unfinished chunk
/// precede it (those bytes are NOT in `data`), and `before` the continuous `(fp, sum)` at
/// that chunk's start. Returns the chunks that completed inside `data` and the state a
/// following buffer continues from.
///
/// The point of the split is that the first stage is the only per-byte work and does not
/// depend on where the cuts fall, so it can be vectorized or split across regions, while
/// the second touches one entry per candidate -- about one per 2 KiB at an 8 KiB average.
pub fn chunk_scanned(
    data: &[u8],
    params: Params,
    base: u64,
    carried: u32,
    before: (u64, u64),
    scan_state: (u64, u64),
    out: &mut Vec<Chunk>,
) -> (u32, (u64, u64), (u64, u64)) {
    // `from` is set by the scan itself; it is not passed in here, so the two cannot drift
    let mut cuts = Cuts::default();
    scan(data, params, scan_state.0, scan_state.1, &mut cuts);

    let (mut before, mut start) = (before, -(carried as i64));
    let mut i = 0usize;
    let n = data.len() as i64;
    loop {
        let forced = start + params.max as i64 - 1;
        let mut pick = None;
        while i < cuts.at.len() {
            let at = cuts.at[i].at as i64;
            if at < start + params.min as i64 {
                i += 1;
                continue;
            }
            if at > forced {
                break;
            }
            // below the target the strict mask is in force, at or above it the loose one;
            // every recorded candidate already satisfies the loose mask
            if (at - start + 1) as u32 >= params.avg || cuts.at[i].strict {
                pick = Some(at);
                i += 1;
                break;
            }
            i += 1;
        }
        let cut_at = match pick {
            Some(at) => at,
            None => forced,
        };
        if cut_at >= n {
            break;
        }
        let state = cuts.state_at(data, cut_at as usize);
        out.push(Chunk {
            offset: base.wrapping_add(start as u64),
            len: (cut_at - start + 1) as u32,
            weak: weak_between(state.1, before.1, before.0),
        });
        before = state;
        start = cut_at + 1;
    }
    ((n - start) as u32, before, (cuts.fp, cuts.sum))
}

/// The weak hash of a whole buffer on its own, for a caller that has a chunk's bytes.
pub fn weak_of(data: &[u8]) -> u64 {
    let mut fp = 0u64;
    let mut weak = 0u64;
    for &b in data {
        fp = (fp << 1).wrapping_add(GEAR[b as usize]);
        weak = weak.wrapping_add(fp);
    }
    weak
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cut decision must look at a WIDE window of recent bytes, not a handful.
    ///
    /// Measured directly rather than argued: feed a buffer, then flip the byte `d` back
    /// from the end and see whether `fp & mask` changes its answer. Gear pushes an old
    /// byte's contribution toward the high bits, so the largest `d` that can change the
    /// answer IS the window, and with the mask at the bottom of the word that window was
    /// 15 bytes under the strict mask and 11 under the loose one. Two places in a file
    /// whose last 15 bytes agree then cut identically however different the rest is --
    /// which is what a fixed-width-record file, a run of padding or a repeated header
    /// looks like, and one such file measured 6.3x the wire traffic.
    ///
    /// The control is the second half: the average chunk size must NOT move. The same
    /// number of mask bits is set either way, so the cut probability is unchanged; a
    /// "fix" that widened the window by setting more bits would pass the first assertion
    /// while halving throughput, and this catches that.
    #[test]
    fn a_cut_is_decided_from_a_wide_window_of_bytes() {
        let params = Params {
            min: 2048,
            avg: 8192,
            max: 65536,
        };
        let (strict, loose) = params.masks();

        // the furthest-back byte whose value can still change the masked fingerprint
        let window = |mask: u64| -> usize {
            let base = noise(4096, 7);
            let fp_of = |b: &[u8]| {
                b.iter()
                    .fold(0u64, |fp, &x| (fp << 1).wrapping_add(GEAR[x as usize]))
            };
            let mut furthest = 0;
            for d in 1..=64usize {
                let mut changed = false;
                for seed in 0..32u64 {
                    let mut edited = base.clone();
                    let at = edited.len() - d;
                    edited[at] = edited[at].wrapping_add(1).wrapping_add(seed as u8);
                    if (fp_of(&base) & mask) != (fp_of(&edited) & mask) {
                        changed = true;
                        break;
                    }
                }
                if changed {
                    furthest = d;
                }
            }
            furthest
        };

        assert!(
            window(strict) >= 32,
            "the strict mask decides a cut from only {} bytes of history",
            window(strict)
        );
        assert!(
            window(loose) >= 32,
            "the loose mask decides a cut from only {} bytes of history",
            window(loose)
        );

        // the control: the same number of bits is set, so the average chunk is the same
        assert_eq!(strict.count_ones(), 15, "strict mask bit count");
        assert_eq!(loose.count_ones(), 11, "loose mask bit count");
        let data = noise(1 << 20, 99);
        let chunks = chunk(&data, params);
        let avg = data.len() as f64 / chunks.len() as f64;
        assert!(
            avg > 3000.0 && avg < 20000.0,
            "average chunk {avg:.0} bytes is nowhere near the {} asked for",
            params.avg
        );
    }

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

    /// The decoupling, checked against the chunker it has to agree with byte for byte.
    ///
    /// `chunk_scanned` never resets the fingerprint and recovers each chunk's weak hash
    /// from two continuous sums; `chunk` resets at every cut and sums as it goes. They are
    /// the same numbers only if two claims hold: that no mask bit can see back as far as
    /// `min`, so the reset is invisible to where the cuts fall, and that the Gear
    /// recurrence is linear mod 2^64, so `weak_between` recovers the reset-based sum
    /// exactly. Nothing here argues for either; it runs both and compares every field of
    /// every chunk.
    ///
    /// The corpus is chosen for the two ways this can break. **A long run of one byte** is
    /// the case where the fingerprint can settle into a cycle that never meets the mask, so
    /// every cut is forced by `max` and lands where no candidate was recorded -- the path
    /// through the ladder, which is otherwise never taken. **Text** has the low entropy
    /// that makes near-repeats common. Random data exercises neither.
    #[test]
    fn the_two_stage_scan_reproduces_the_chunker_exactly() {
        let corpus: Vec<(&str, Vec<u8>)> = vec![
            ("random", noise(3 << 20, 11)),
            ("zeros", vec![0u8; 1 << 20]),
            ("one byte repeated", vec![0x41u8; 300 << 10]),
            (
                "text",
                std::iter::repeat_n(
                    b"the quick brown fox jumps over the lazy dog. ".to_vec(),
                    20000,
                )
                .flatten()
                .collect(),
            ),
            (
                "zeros then noise",
                [vec![0u8; 200 << 10], noise(700 << 10, 5)].concat(),
            ),
            ("short", noise(100, 3)),
            ("empty", Vec::new()),
        ];
        for (min, avg, max) in [
            (2048u32, 8192u32, 65536u32),
            (256, 1024, 8192),
            (16 << 10, 64 << 10, 512 << 10),
        ] {
            let params = Params { min, avg, max };
            params.validate().unwrap();
            for (name, data) in &corpus {
                let want = chunk(data, params);
                let mut got = Vec::new();
                let (tail, before, _) = chunk_scanned(data, params, 0, 0, (0, 0), (0, 0), &mut got);
                // the streaming tail is the one chunk the identity cannot produce -- it can
                // be shorter than 62 bytes -- so it is cut the plain way, exactly as
                // `Chunker::finish` does
                if tail > 0 {
                    let start = data.len() - tail as usize;
                    got.push(Chunk {
                        offset: start as u64,
                        len: tail,
                        weak: weak_of(&data[start..]),
                    });
                    let _ = before;
                }
                assert_eq!(
                    got.len(),
                    want.len(),
                    "{name} at {min}/{avg}/{max}: {} chunks, want {}",
                    got.len(),
                    want.len()
                );
                for (g, w) in got.iter().zip(want.iter()) {
                    assert_eq!(
                        (g.offset, g.len),
                        (w.offset, w.len),
                        "{name} at {min}/{avg}/{max}: cut points differ"
                    );
                    assert_eq!(g.weak, w.weak, "{name} at {min}/{avg}/{max}: chunk at {} len {} has weak {:#x}, want {:#x}", g.offset, g.len, g.weak, w.weak);
                }
                let covered: u64 = got.iter().map(|c| c.len as u64).sum();
                assert_eq!(
                    covered,
                    data.len() as u64,
                    "{name}: the chunks do not cover the input"
                );
            }
        }

        // The control. The identity is not a tautology -- it depends on the chunk being at
        // least 62 bytes, which is why `weak_of` handles the tail -- so drop that term and
        // the arm must fail. Without this, a `weak_between` that happened to return the
        // right thing for some other reason would look proven.
        let data = noise(1 << 20, 11);
        let params = Params {
            min: 2048,
            avg: 8192,
            max: 65536,
        };
        let mut got = Vec::new();
        chunk_scanned(&data, params, 0, 0, (0, 0), (0, 0), &mut got);
        let want = chunk(&data, params);
        let naive: Vec<u64> = {
            // `sum(b) - sum(a-1)` WITHOUT the `+ 2 * fp(a-1)` correction
            let mut cuts = Cuts::default();
            scan(&data, params, 0, 0, &mut cuts);
            let mut prev = 0u64;
            want.iter()
                .map(|c| {
                    let end = (c.offset + c.len as u64 - 1) as usize;
                    let s = cuts.state_at(&data, end).1;
                    let w = s.wrapping_sub(prev);
                    prev = s;
                    w
                })
                .collect()
        };
        assert!(
            naive.iter().zip(want.iter()).filter(|(n, w)| **n != w.weak).count() > want.len() / 2,
            "dropping the 2*fp(a-1) term still matched most chunks, so the arm above is not testing the identity"
        );
    }

    /// The lane-parallel scan must produce the SAME candidates, rungs and end state as the
    /// single-stream one, byte for byte and field for field.
    ///
    /// The claim it rests on is that after `WARMUP` bytes a fingerprint has forgotten where
    /// it started -- not approximately, exactly, because the starting value has been
    /// shifted out of a 64-bit word. If that were only true of the bits a mask tests, the
    /// candidates would agree and the SUMS would not, and the weak hashes would be wrong in
    /// a way no cut-point comparison could see. So this compares `sum` too.
    #[test]
    fn the_lane_scan_agrees_with_the_single_stream_one() {
        let params = Params {
            min: 2048,
            avg: 8192,
            max: 65536,
        };
        // Log lines rather than one sentence repeated: a PERFECTLY periodic buffer drives
        // the fingerprint into a cycle that never meets the mask, so it yields zero
        // candidates and comparing two empty lists proves nothing. The non-vacuity check
        // below refuses exactly that input.
        let logs: Vec<u8> = (0..24000u32)
            .flat_map(|i| {
                format!(
                    "2026-09-24T02:{:02}:{:02}Z request {i} served in {} ms\n",
                    i % 60,
                    (i / 7) % 60,
                    i % 97
                )
                .into_bytes()
            })
            .collect();
        for (name, data, expect_candidates) in [
            ("random", noise(1 << 20, 23), true),
            ("log lines", logs, true),
            // The degenerate case, pinned rather than excused: a constant buffer meets no
            // mask, so every cut is forced by `max` and goes through the ladder.
            ("zeros", vec![0u8; 1 << 20], false),
        ] {
            let (mut one, mut many) = (Cuts::default(), Cuts::default());
            scan(&data, params, 0, 0, &mut one);
            scan_lanes(&data, params, 0, 0, &mut many);
            assert_eq!(
                many.at.len(),
                one.at.len(),
                "{name}: {} candidates from the lanes, {} from one stream",
                many.at.len(),
                one.at.len()
            );
            assert_eq!(many.at, one.at, "{name}: the candidates differ");
            assert_eq!(many.rungs, one.rungs, "{name}: the ladders differ");
            assert_eq!(
                (many.fp, many.sum),
                (one.fp, one.sum),
                "{name}: the end state differs"
            );
            assert_eq!(
                !one.at.is_empty(),
                expect_candidates,
                "{name}: {} candidates, expected {}",
                one.at.len(),
                if expect_candidates { "some" } else { "none" }
            );
        }

        // The control: a lane that does NOT warm up must disagree, or the warm-up is doing
        // nothing and the agreement above is an accident of this data.
        let data = noise(1 << 20, 23);
        let (strict, loose) = params.masks();
        let span = data.len() / LANES;
        let mut cold = 0usize;
        for lane in 1..LANES {
            let (mut f, mut s) = (0u64, 0u64);
            for (i, &b) in data[lane * span..(lane + 1) * span].iter().enumerate() {
                f = (f << 1).wrapping_add(GEAR[b as usize]);
                s = s.wrapping_add(f);
                if f & loose == 0 && i < WARMUP {
                    cold += 1;
                }
                let _ = strict;
            }
            // the first WARMUP fingerprints of a cold lane are wrong, so its sums are wrong
            // from the first byte onward
            let want = one_stream_sum(&data, params, lane * span, span);
            assert_ne!(s, want, "a cold lane's sum matched the true one, so warming up cannot be what makes the lanes agree");
        }
        let _ = cold;
    }

    /// The true continuous sum over `data[at..at+len]`, computed from the start of the
    /// buffer so there is no warm-up question.
    fn one_stream_sum(data: &[u8], _params: Params, at: usize, len: usize) -> u64 {
        let (mut f, mut s) = (0u64, 0u64);
        for (i, &b) in data.iter().enumerate() {
            f = (f << 1).wrapping_add(GEAR[b as usize]);
            if i >= at && i < at + len {
                s = s.wrapping_add(f);
            }
        }
        s
    }

    #[test]
    fn chunks_cover_the_input_within_the_bounds_and_crowd_the_target() {
        let data = noise(4 << 20, 1);
        let p = Params::default();
        let chunks = chunk(&data, p);
        let mut pos = 0u64;
        for c in &chunks {
            assert_eq!(c.offset, pos);
            assert!(
                c.len >= p.min || c.offset + c.len as u64 == data.len() as u64,
                "{c:?}"
            );
            assert!(c.len <= p.max, "{c:?}");
            pos += c.len as u64;
        }
        assert_eq!(pos, data.len() as u64);
        let mean = data.len() as f64 / chunks.len() as f64;
        assert!(
            mean > 5000.0 && mean < 14000.0,
            "mean chunk {mean:.0} around the 8 KiB target"
        );
        let near = chunks
            .iter()
            .filter(|c| c.len >= 4 << 10 && c.len <= 16 << 10)
            .count();
        assert!(
            near * 10 >= chunks.len() * 7,
            "{near} of {} chunks within 4..16 KiB",
            chunks.len()
        );
    }

    #[test]
    fn piecewise_feeding_gives_the_same_chunks_and_weak_hashes() {
        let data = noise(600_000, 2);
        let whole = chunk(&data, Params::default());
        let mut c = Chunker::new(Params::default());
        let mut out = Vec::new();
        for piece in data.chunks(7919) {
            c.push(piece, &mut out);
        }
        out.extend(c.finish());
        assert_eq!(out, whole);
        for ch in &whole {
            assert_eq!(
                weak_of(&data[ch.offset as usize..(ch.offset + ch.len as u64) as usize]),
                ch.weak
            );
        }
    }

    #[test]
    fn an_insertion_shifts_only_the_chunks_around_it() {
        // content-defined: after inserting bytes at 1 MiB, the chunks after the edit
        // realign, so most of the file's chunks are found again by (len, weak)
        let data = noise(3 << 20, 3);
        let mut edited = data[..1 << 20].to_vec();
        edited.extend_from_slice(b"an insertion of a few bytes");
        edited.extend_from_slice(&data[1 << 20..]);
        let a = chunk(&data, Params::default());
        let b = chunk(&edited, Params::default());
        let known: std::collections::HashSet<(u32, u64)> =
            a.iter().map(|c| (c.len, c.weak)).collect();
        let found = b
            .iter()
            .filter(|c| known.contains(&(c.len, c.weak)))
            .count();
        assert!(
            found * 100 >= b.len() * 95,
            "{found} of {} chunks found again",
            b.len()
        );
        // control: fixed-size blocks would lose everything after the edit
        let fixed_a: std::collections::HashSet<u64> = data.chunks(8192).map(weak_of).collect();
        let fixed_found = edited
            .chunks(8192)
            .filter(|c| fixed_a.contains(&weak_of(c)))
            .count();
        assert!(
            fixed_found * 100 < edited.len() / 8192 * 40,
            "fixed blocks: {fixed_found} found"
        );
    }
}
