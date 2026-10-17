#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let claimed = match data.split_first() {
        Some((head, _)) => (*head as usize) << 8,
        None => 0,
    };
    let _ = rcp::lz4::decompress(data, claimed.min(1 << 16));
    let sample = &data[..data.len().min(32 * 1024)];
    let block = rcp::lz4::compress(sample);
    let decoded = rcp::lz4::decompress(&block, sample.len()).expect("a block this crate wrote");
    assert_eq!(decoded, sample);
});
