#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rcp::json::parse(data);
    let Some(text) = std::str::from_utf8(data).ok() else {
        return;
    };
    let sample = &text[..text.len().min(64 * 1024)];
    let encoded = rcp::json::quote(sample);
    let parsed = rcp::json::parse(encoded.as_bytes()).expect("a quoted string is JSON");
    assert_eq!(parsed.as_str(), Some(sample));
});
