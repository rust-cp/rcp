#![no_main]

use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = rcp::deflate::inflate(data, LIMIT);
    let _ = rcp::deflate::gunzip(data, LIMIT);
    let sample = &data[..data.len().min(32 * 1024)];
    let member = rcp::deflate::gzip(sample, None, 0);
    let decoded = rcp::deflate::gunzip(&member, sample.len().saturating_add(64))
        .expect("a gzip member this crate wrote");
    assert_eq!(decoded, sample);
});
