//! Optional system libzstd, using only its stable one-shot C API. No registry,
//! vendored C sources, build script, subprocess, or default-build linkage.
//!
//! The zstd CODEC is in every build (`crate::zstd`, pure Rust). This is an alternative
//! backend for it, chosen with `--features system-zstd`: the same frames, made and read by the
//! system library. Frames cross between the two builds in both directions, because the
//! crate's encoder writes the one single-segment, size-declaring frame `decompress` here
//! requires, and the crate's decoder reads what `ZSTD_compress` writes.
use std::ffi::{c_int, c_void};
use std::io;

#[link(name = "zstd")]
extern "C" {
    fn ZSTD_compressBound(src_size: usize) -> usize;
    fn ZSTD_compress(
        dst: *mut c_void,
        capacity: usize,
        src: *const c_void,
        size: usize,
        level: c_int,
    ) -> usize;
    fn ZSTD_decompress(dst: *mut c_void, capacity: usize, src: *const c_void, size: usize)
        -> usize;
    fn ZSTD_isError(code: usize) -> u32;
    fn ZSTD_findFrameCompressedSize(src: *const c_void, size: usize) -> usize;
    fn ZSTD_getFrameContentSize(src: *const c_void, size: usize) -> u64;
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    // SAFETY: all pointers refer to live, non-overlapping slices of the supplied
    // sizes. The stable API writes at most capacity and returns a size or error.
    unsafe {
        let capacity = ZSTD_compressBound(data.len());
        if ZSTD_isError(capacity) != 0 {
            return Err(invalid("zstd compression bound"));
        }
        let mut out = vec![0; capacity];
        let n = ZSTD_compress(
            out.as_mut_ptr().cast(),
            out.len(),
            data.as_ptr().cast(),
            data.len(),
            3,
        );
        if ZSTD_isError(n) != 0 || n > out.len() {
            return Err(invalid("zstd compression failed"));
        }
        out.truncate(n);
        Ok(out)
    }
}

pub fn decompress(data: &[u8], raw_len: usize) -> io::Result<Vec<u8>> {
    if raw_len > crate::remote::proto::MAX_FRAME {
        return Err(invalid("zstd payload exceeds frame limit"));
    }
    // Require exactly one ordinary frame with the advertised size, before allocating
    // output. No concatenated/skippable frames, unknown content size, or trailing junk.
    if !data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(invalid("invalid zstd frame magic"));
    }
    // SAFETY: the input slice is live for both inspection calls; decompression gets
    // a separate, bounded output slice. libzstd checks malformed input internally.
    unsafe {
        let frame_len = ZSTD_findFrameCompressedSize(data.as_ptr().cast(), data.len());
        if ZSTD_isError(frame_len) != 0 || frame_len != data.len() {
            return Err(invalid("invalid zstd frame length"));
        }
        if ZSTD_getFrameContentSize(data.as_ptr().cast(), data.len()) != raw_len as u64 {
            return Err(invalid(
                "zstd frame content size differs from payload length",
            ));
        }
        let mut out = vec![0; raw_len];
        let n = ZSTD_decompress(
            out.as_mut_ptr().cast(),
            out.len(),
            data.as_ptr().cast(),
            data.len(),
        );
        if ZSTD_isError(n) != 0 || n != raw_len {
            return Err(invalid("zstd decompression failed"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_frame_exact_size_no_trailing_or_concatenated_data() {
        let bytes = compress(&vec![42; 4096]).unwrap();
        assert_eq!(decompress(&bytes, 4096).unwrap(), vec![42; 4096]);
        assert!(decompress(&bytes, 4095).is_err());
        assert!(decompress(&bytes, usize::MAX).is_err());
        assert!(decompress(&bytes[..bytes.len() - 1], 4096).is_err());
        assert!(decompress(&[bytes.clone(), bytes.clone()].concat(), 4096).is_err());
        assert!(decompress(&[bytes, vec![0]].concat(), 4096).is_err());
    }

    /// The two backends read each other's frames: the crate's encoder writes the one
    /// single-segment, size-declaring frame `decompress` here demands, and the crate's
    /// decoder reads what `ZSTD_compress` writes. A build with this feature and one
    /// without it meet on the same stream, so this is the property interop rests on.
    #[test]
    fn frames_cross_between_the_system_library_and_the_crates_own_codec() {
        let mut text = Vec::new();
        for i in 0..20_000u32 {
            text.extend_from_slice(
                format!("line {i} of a log that repeats itself {}\n", i % 17).as_bytes(),
            );
        }
        for data in [
            text.clone(),
            vec![7u8; 100_000],
            (0..50_000u32)
                .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                .collect(),
        ] {
            let ours = crate::zstd::compress(&data);
            assert_eq!(
                decompress(&ours, data.len()).expect("libzstd reads the crate's frame"),
                data
            );
            let theirs = compress(&data).unwrap();
            assert_eq!(
                crate::zstd::decompress(&theirs, data.len())
                    .expect("the crate reads libzstd's frame"),
                data
            );
        }
    }
}
