//! NTLMv2 (MS-NLMP), which SMB2 session setup needs and nothing else here does, over the
//! RustCrypto `md4`, `md-5` and `hmac` crates.
//!
//! **MD4 and MD5 are here because NTLM requires them, not because they are worth having.**
//! Both are broken as hash functions and neither is offered as an rcp digest -- `-md5`
//! does not exist and will not. They appear only inside the NTLM key schedule, where the
//! protocol specifies them and no choice is available, and they are named `ntlm::md4`
//! rather than `hash::md4` so that stays visible at every call site.
//!
//! Every function below is checked against the vectors in its own defining document --
//! RFC 1320 for MD4, RFC 1321 for MD5, RFC 2202 for HMAC-MD5, and MS-NLMP's worked example
//! for NTLMv2 -- because a key schedule that is subtly wrong produces a login failure
//! fifteen layers away, and the protocol gives back `STATUS_LOGON_FAILURE` either way.

/// MD4 (RFC 1320).
pub fn md4(data: &[u8]) -> [u8; 16] {
    <md4::Md4 as md4::Digest>::digest(data).into()
}

/// MD5 (RFC 1321).
pub fn md5(data: &[u8]) -> [u8; 16] {
    <md5::Md5 as md5::Digest>::digest(data).into()
}

/// HMAC-MD5 (RFC 2104), the only MAC NTLMv2 uses.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
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
