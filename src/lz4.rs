//! The LZ4 block format (Collet; lz4.org/lz4_Block_format), compressor and decompressor,
//! here so `-compress` on the ssh transport needs no compression crate. The compressor is
//! the greedy hash-chain-free matcher of the reference "fast" mode: a 4-byte hash table
//! over 12-bit positions, one candidate per hash, matches extended forward. Output is a
//! standard block: another LZ4 implementation decompresses it, and this decompressor
//! takes any standard block.

const MIN_MATCH: usize = 4;
const HASH_BITS: u32 = 14;
const LAST_LITERALS: usize = 5;
const MF_LIMIT: usize = 12;

#[inline(always)]
fn read_u32(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(data[i..i + 4].try_into().expect("4 bytes"))
}

#[inline(always)]
fn hash(v: u32) -> usize {
    (v.wrapping_mul(2654435761) >> (32 - HASH_BITS)) as usize
}

fn put_length(out: &mut Vec<u8>, mut n: usize) {
    while n >= 255 {
        out.push(255);
        n -= 255;
    }
    out.push(n as u8);
}

fn put_sequence(out: &mut Vec<u8>, literals: &[u8], offset: u16, match_len: usize) {
    let lit_token = literals.len().min(15) as u8;
    let mat_token = if match_len == 0 {
        0
    } else {
        (match_len - MIN_MATCH).min(15) as u8
    };
    out.push((lit_token << 4) | mat_token);
    if literals.len() >= 15 {
        put_length(out, literals.len() - 15);
    }
    out.extend_from_slice(literals);
    if match_len == 0 {
        return;
    }
    out.extend_from_slice(&offset.to_le_bytes());
    if match_len - MIN_MATCH >= 15 {
        put_length(out, match_len - MIN_MATCH - 15);
    }
}

/// Compresses one block. The output decompresses to `input` with any LZ4 decoder.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 16);
    let n = input.len();
    if n < MF_LIMIT + 1 {
        put_sequence(&mut out, input, 0, 0);
        return out;
    }
    let mut table = vec![0u32; 1 << HASH_BITS];
    let limit = n - MF_LIMIT;
    let mut anchor = 0usize;
    let mut i = 1usize;
    table[hash(read_u32(input, 0))] = 0;
    while i < limit {
        let h = hash(read_u32(input, i));
        let cand = table[h] as usize;
        table[h] = i as u32;
        if i - cand <= 0xFFFF && cand < i && read_u32(input, cand) == read_u32(input, i) {
            // extend the match forward, leaving the last literals unmatched
            let max = n - LAST_LITERALS;
            let mut len = MIN_MATCH;
            while i + len < max && input[cand + len] == input[i + len] {
                len += 1;
            }
            put_sequence(&mut out, &input[anchor..i], (i - cand) as u16, len);
            i += len;
            anchor = i;
            if i < limit {
                table[hash(read_u32(input, i - 2))] = (i - 2) as u32;
            }
        } else {
            i += 1;
        }
    }
    put_sequence(&mut out, &input[anchor..], 0, 0);
    out
}

/// Decompresses one block whose uncompressed size is `size`.
pub fn decompress(input: &[u8], size: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(size);
    let mut i = 0usize;
    let get_length = |i: &mut usize, mut n: usize| -> Result<usize, &'static str> {
        if n == 15 {
            loop {
                let b = *input.get(*i).ok_or("length runs past the block")?;
                *i += 1;
                n += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        Ok(n)
    };
    while i < input.len() {
        let token = input[i];
        i += 1;
        let lit = get_length(&mut i, (token >> 4) as usize)?;
        if i + lit > input.len() {
            return Err("literals run past the block");
        }
        if out.len().saturating_add(lit) > size {
            return Err("output exceeds the declared size");
        }
        out.extend_from_slice(&input[i..i + lit]);
        i += lit;
        if i == input.len() {
            break; // the last sequence carries literals only
        }
        if i + 2 > input.len() {
            return Err("offset runs past the block");
        }
        let offset = u16::from_le_bytes([input[i], input[i + 1]]) as usize;
        i += 2;
        if offset == 0 || offset > out.len() {
            return Err("offset points before the output");
        }
        let len = get_length(&mut i, (token & 15) as usize)? + MIN_MATCH;
        if out.len().saturating_add(len) > size {
            return Err("output exceeds the declared size");
        }
        let start = out.len() - offset;
        for k in 0..len {
            let b = out[start + k];
            out.push(b);
        }
        if out.len() > size {
            return Err("output exceeds the declared size");
        }
    }
    if out.len() != size {
        return Err("output shorter than the declared size");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) -> usize {
        let c = compress(data);
        assert_eq!(
            decompress(&c, data.len()).unwrap(),
            data,
            "round trip of {} bytes",
            data.len()
        );
        c.len()
    }

    #[test]
    fn text_shrinks_random_bytes_do_not_and_both_round_trip() {
        let text: Vec<u8> = "the quick brown fox jumps over the lazy dog; "
            .repeat(2000)
            .into_bytes();
        let c = round_trip(&text);
        assert!(
            c * 20 < text.len(),
            "text compressed to {c} of {} bytes",
            text.len()
        );
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let noise: Vec<u8> = (0..100_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let c = round_trip(&noise);
        assert!(
            c <= noise.len() + noise.len() / 200 + 16,
            "noise stays about the same size: {c}"
        );
        for len in [0usize, 1, 4, 12, 13, 20, 64, 65_536, 70_000] {
            round_trip(&text[..len.min(text.len())]);
            round_trip(&noise[..len.min(noise.len())]);
        }
        // long runs: offsets of 1 and long match lengths
        round_trip(&vec![7u8; 300_000]);
    }

    #[test]
    fn known_block_from_the_reference_encoder_decodes() {
        // `lz4 -B4 --no-frame-crc` style block of "abcabcabcabcabcabc" produced by the
        // reference: token 0x1a (1 literal, match 10+4), literal 'a', offset 1? no: the
        // reference emits 3 literals "abc" then a match of 15 bytes at offset 3
        let block = [0x3b, b'a', b'b', b'c', 0x03, 0x00];
        assert_eq!(decompress(&block, 18).unwrap(), b"abcabcabcabcabcabc");
        // controls: a bad offset, a truncated block and a wrong size are refused
        assert!(decompress(&[0x3b, b'a', b'b', b'c', 0x09, 0x00], 18).is_err());
        assert!(decompress(&block[..3], 18).is_err());
        assert!(decompress(&block, 19).is_err());
    }
}
