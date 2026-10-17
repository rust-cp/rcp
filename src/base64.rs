//! Base64 (RFC 4648, standard alphabet): proxy credentials go out encoded, PEM certificates
//! come in encoded.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let v = (chunk[0] as u32) << 16
            | if n > 1 { (chunk[1] as u32) << 8 } else { 0 }
            | if n > 2 { chunk[2] as u32 } else { 0 };
        out.push(ALPHABET[(v >> 18) as usize & 63] as char);
        out.push(ALPHABET[(v >> 12) as usize & 63] as char);
        out.push(if n > 1 {
            ALPHABET[(v >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if n > 2 {
            ALPHABET[v as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decodes, ignoring whitespace; `None` on any other byte outside the alphabet.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut padded = false;
    for b in text.bytes() {
        if padded {
            match b {
                b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
                _ => return None,
            }
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padded = true;
                continue;
            }
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // One leftover character is not a quantum. Padding may leave 0, 2 or 4 bits.
    if bits == 6 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_rfc_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(decode("Zm9v\nYmFy").unwrap(), b"foobar");
        assert!(decode("Zm9v*").is_none());
    }
}
