//! What the chunker costs, measured rather than assumed.
//!
//! The delta path chunks every byte it reads on both ends, so this rate is a ceiling on
//! what `-delta` can do however fast the disk and the network are. The roadmap entry that
//! prompted these numbers is about a 10 Gbit path, which is 1192 MiB/s.
//!
//! **This prints; it does not gate.** A throughput assertion on a shared, virtualized
//! machine fails for reasons that have nothing to do with the code, and a test that is red
//! for a reason nobody can act on gets ignored, which is worse than not having it. The
//! correctness of every variant here is asserted in `src/cdc.rs`; this answers "is it
//! faster", and the answer is a number a person reads.
//!
//! Run it with `cargo test --release --test chunker_rate -- --nocapture`.

use std::time::Instant;

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

fn rate(label: &str, bytes: usize, secs: f64) -> f64 {
    let mib = (bytes as f64) / (1024.0 * 1024.0) / secs;
    eprintln!(
        "{label:<28} {mib:>8.0} MiB/s   {:>5.2} ns/byte",
        secs * 1e9 / bytes as f64
    );
    mib
}

#[test]
fn how_fast_the_chunker_runs() {
    let n = 48usize << 20;
    let data = noise(n, 0x2545F491);
    let params = rcp::cdc::Params {
        min: 2 << 10,
        avg: 8 << 10,
        max: 64 << 10,
    };

    // warm the page cache and the branch predictors; a first run measures neither variant
    let _ = rcp::cdc::chunk(&data[..1 << 20], params);

    let t = Instant::now();
    let want = rcp::cdc::chunk(&data, params);
    let one = rate("chunk (one stream)", n, t.elapsed().as_secs_f64());

    let t = Instant::now();
    let mut cuts = rcp::cdc::Cuts::default();
    rcp::cdc::scan(&data, params, 0, 0, &mut cuts);
    let scan_one = rate("scan (one stream)", n, t.elapsed().as_secs_f64());

    let t = Instant::now();
    let mut lanes = rcp::cdc::Cuts::default();
    rcp::cdc::scan_lanes(&data, params, 0, 0, &mut lanes);
    let scan_lanes = rate("scan (4 lanes)", n, t.elapsed().as_secs_f64());

    let t = Instant::now();
    let mut got = Vec::new();
    // the third return is the TAIL: bytes of an unfinished chunk, which `chunk_scanned`
    // deliberately does not emit because a stream may continue. `chunk` has no such
    // caller and cuts it. Comparing the two without accounting for it is an off-by-one,
    // and this assertion had it -- 5328 against 5329 -- which read as a defect in the
    // chunker and was one in the test.
    let (tail, _, _) = rcp::cdc::chunk_scanned(&data, params, 0, 0, (0, 0), (0, 0), &mut got);
    let two_stage = rate("chunk_scanned (one stream)", n, t.elapsed().as_secs_f64());

    eprintln!();
    eprintln!(
        "10 Gbit is 1192 MiB/s. lanes vs one stream: {:.2}x. two-stage vs chunk: {:.2}x.",
        scan_lanes / scan_one,
        two_stage / one
    );
    eprintln!(
        "{} chunks, {} candidates ({:.1} candidates per chunk)",
        want.len(),
        cuts.at.len(),
        cuts.at.len() as f64 / want.len() as f64
    );

    // Not a speed assertion -- a sanity one. If a variant produced a wildly different chunk
    // count the numbers above would be comparing different work, and the equivalence arms
    // in src/cdc.rs would have caught it, so this is belt and braces.
    assert!(!want.is_empty());
    assert!(!got.is_empty());
    assert_eq!(
        got.len() + usize::from(tail > 0),
        want.len(),
        "the two-stage chunker produced a different number of chunks (tail {tail})"
    );
}
