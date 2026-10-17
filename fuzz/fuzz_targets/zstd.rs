#![no_main]

use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = rcp::zstd::decompress(data, LIMIT);
    let sample = &data[..data.len().min(64 * 1024)];
    let frame = rcp::zstd::compress(sample);
    let decoded = rcp::zstd::decompress(&frame, sample.len().saturating_add(64))
        .expect("a frame this crate wrote");
    assert_eq!(decoded, sample);
});
