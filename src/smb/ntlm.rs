//! MD4, MD5, HMAC-MD5 and NTLMv2, which SMB2 session setup needs and nothing else here
//! does.
//!
//! **These are here because NTLM requires them, not because they are worth having.** MD4
//! and MD5 are both broken as hash functions and neither is offered as an rcp digest --
//! `-md5` does not exist and will not. They appear only inside the NTLM key schedule,
//! where the protocol specifies them and no choice is available, and they are named
//! `ntlm::md4` rather than `hash::md4` so that stays visible at every call site.
//!
//! Every function below is checked against the vectors in its own defining document --
//! RFC 1320 for MD4, RFC 1321 for MD5, RFC 2202 for HMAC-MD5, and MS-NLMP's worked example
//! for NTLMv2 -- because a hash that is subtly wrong produces a login failure fifteen
//! layers away, and the protocol gives back `STATUS_LOGON_FAILURE` either way.

/// MD4 (RFC 1320).
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());

    for block in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, w) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        // round 1: F = (b & c) | (!b & d)
        for i in 0..16 {
            let (k, s) = (i, [3u32, 7, 11, 19][i % 4]);
            let f = (b & c) | (!b & d);
            let t = a.wrapping_add(f).wrapping_add(x[k]).rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = t;
        }
        // round 2: G = (b & c) | (b & d) | (c & d), constant 0x5a827999
        for i in 0..16 {
            let k = (i % 4) * 4 + i / 4;
            let s = [3u32, 5, 9, 13][i % 4];
            let g = (b & c) | (b & d) | (c & d);
            let t = a
                .wrapping_add(g)
                .wrapping_add(x[k])
                .wrapping_add(0x5a82_7999)
                .rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = t;
        }
        // round 3: H = b ^ c ^ d, constant 0x6ed9eba1
        const ORDER3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for i in 0..16 {
            let s = [3u32, 9, 11, 15][i % 4];
            let h = b ^ c ^ d;
            let t = a
                .wrapping_add(h)
                .wrapping_add(x[ORDER3[i]])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(s);
            a = d;
            d = c;
            c = b;
            b = t;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

const MD5_K: [u32; 64] = {
    // K[i] = floor(abs(sin(i+1)) * 2^32), written out because it cannot be computed in a
    // const context without floating point
    [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ]
};

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// MD5 (RFC 1321).
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());

    for block in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let t = a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(t.rotate_left(MD5_S[i]));
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// HMAC-MD5 (RFC 2104), the only MAC NTLMv2 uses.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..16].copy_from_slice(&md5(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    let mut outer = Vec::with_capacity(80);
    for b in k.iter() {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(data);
    outer.extend_from_slice(&md5(&inner));
    md5(&outer)
}

/// UTF-16LE, which every string on the NTLM and SMB2 wire is.
pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// NTOWFv2: `HMAC-MD5(MD4(UTF16LE(password)), UTF16LE(uppercase(user) + domain))`.
///
/// Note the asymmetry, which is a classic place to get this wrong: the USER is uppercased
/// and the DOMAIN is not.
pub fn ntowf_v2(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt = md4(&utf16le(password));
    let mut ident = utf16le(&user.to_uppercase());
    ident.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt, &ident)
}

/// The NTLMv2 response: a 16-byte HMAC over the server challenge and the blob, followed by
/// the blob itself. Returns `(nt_response, session_base_key)`.
pub fn ntlmv2_response(
    ntowf: &[u8; 16],
    server_challenge: &[u8; 8],
    blob: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let mut input = Vec::with_capacity(8 + blob.len());
    input.extend_from_slice(server_challenge);
    input.extend_from_slice(blob);
    let proof = hmac_md5(ntowf, &input);
    let key = hmac_md5(ntowf, &proof);
    let mut out = Vec::with_capacity(16 + blob.len());
    out.extend_from_slice(&proof);
    out.extend_from_slice(blob);
    (out, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 1320, appendix A.5 -- the suite the document itself publishes.
    #[test]
    fn md4_matches_rfc_1320() {
        for (input, want) in [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ] {
            assert_eq!(hex(&md4(input.as_bytes())), want, "md4({input:?})");
        }
    }

    /// RFC 1321, appendix A.5.
    #[test]
    fn md5_matches_rfc_1321() {
        for (input, want) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(hex(&md5(input.as_bytes())), want, "md5({input:?})");
        }
    }

    /// RFC 2202, section 2 -- including case 6, whose key is LONGER than the block and so
    /// takes the branch that hashes the key first. Without that case the `key.len() > 64`
    /// arm is never executed and could be anything at all.
    #[test]
    fn hmac_md5_matches_rfc_2202_including_the_long_key_case() {
        assert_eq!(
            hex(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex(&hmac_md5(&[0xaa; 16], &[0xdd; 50])),
            "56be34521d144c88dbb8c733f0e8b3f6"
        );
        assert_eq!(
            hex(&hmac_md5(&[0x0c; 16], b"Test With Truncation")),
            "56461ef2342edc00f9bab995690efd4c"
        );
        // case 6: an 80-byte key, longer than MD5's 64-byte block
        assert_eq!(
            hex(&hmac_md5(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
        assert_eq!(
            hex(&hmac_md5(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
            )),
            "6f630fad67cda0ee1fb1f562db3aa53e"
        );
    }

    /// MS-NLMP section 4.2.4.1.1: the worked example the specification publishes, with
    /// User "User", Domain "Domain", Password "Password".
    ///
    /// This is the one that catches the uppercase asymmetry -- the user is uppercased and
    /// the domain is not -- which produces a plausible-looking key either way and a login
    /// failure fifteen layers later.
    #[test]
    fn ntowf_v2_matches_the_ms_nlmp_worked_example() {
        assert_eq!(
            hex(&md4(&utf16le("Password"))),
            "a4f49c406510bdcab6824ee7c30fd852",
            "NTOWFv1 of the example password"
        );
        assert_eq!(
            hex(&ntowf_v2("User", "Domain", "Password")),
            "0c868a403bfd7a93a3001ef22ef02e3f"
        );
        // THE CONTROL on the asymmetry: lowercasing the domain instead must NOT match, or
        // the assertion above would pass for a function that uppercased both.
        let mut ident = utf16le("USER");
        ident.extend_from_slice(&utf16le("DOMAIN"));
        let both_upper = hmac_md5(&md4(&utf16le("Password")), &ident);
        assert_ne!(
            hex(&both_upper),
            "0c868a403bfd7a93a3001ef22ef02e3f",
            "uppercasing the domain too must give a different key"
        );
    }

    /// MS-NLMP section 4.2.4.2.2: the NTLMv2 proof and the session base key for the same
    /// worked example -- server challenge 0123456789abcdef, client challenge eight 0xaa,
    /// time zero, target info MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server".
    ///
    /// **The session base key is what every signing key is derived from, and nothing else
    /// pins it to anything outside this crate.** The scripted test peer derives
    /// its key with these same functions, so a defect here would be shared by both ends of
    /// every signing arm and pass all of them; only a live server would have said otherwise.
    /// The two published values were also recomputed independently (Python's `hmac` over
    /// impacket's `NTOWFv2`) before being written down here.
    #[test]
    fn the_ntlmv2_proof_and_session_key_match_the_ms_nlmp_worked_example() {
        let unhex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let blob = unhex(concat!(
            "01010000000000000000000000000000aaaaaaaaaaaaaaaa00000000",
            "02000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000",
        ));
        let challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let (response, session_key) =
            ntlmv2_response(&ntowf_v2("User", "Domain", "Password"), &challenge, &blob);
        assert_eq!(
            hex(&response[..16]),
            "68cd0ab851e51c96aabc927bebef6a1c",
            "NTProofStr"
        );
        assert_eq!(
            hex(&session_key),
            "8de40ccadbc14a82f15cb0ad0de95ca3",
            "SessionBaseKey"
        );
        // and the response is the proof followed by the blob, byte for byte
        assert_eq!(&response[16..], &blob[..]);
    }
}
