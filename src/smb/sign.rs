//! SMB2 message signing: AES-128-CMAC, the SP800-108 key derivation, and the two signing
//! algorithms the dialects this client offers actually use. The block cipher and the MAC
//! come from the RustCrypto `aes` and `cmac` crates; `aes` uses AES-NI (x86) or the ARMv8
//! AES instructions where the CPU has them and a constant-time software cipher otherwise.
//!
//! **Why this exists.** Windows 11 24H2, Windows Server 2025 and any domain-member Samba
//! require signing by default. A client that reads the "signing required" bit and refuses by
//! name is correct, and excludes most modern deployments. The refusal remains for a server
//! this cannot satisfy; it is not the answer to the ordinary case.
//!
//! Two algorithms, because the dialect decides (MS-SMB2 3.1.4.1):
//!
//! | dialect | signing |
//! | --- | --- |
//! | 0x0202, 0x0210 | HMAC-SHA256, truncated to 16 bytes |
//! | 0x0300 | AES-128-CMAC |
//!
//! and 0x0300 also derives a separate signing key from the session key through the
//! SP800-108 counter-mode KDF rather than using it directly.
//!
//! Everything here is checked against published vectors -- FIPS-197 for the AES block,
//! RFC 4493 for CMAC, and signatures from an independent implementation -- because a
//! signing path that is subtly wrong does not fail loudly: the server rejects every request
//! with `STATUS_ACCESS_DENIED`, which reads exactly like a credential problem and sends you
//! to look at the password.
//!
//! `RCP_NO_AES_NI` used to force rcp's own portable cipher. It is still accepted and is now
//! a no-op: the crate's selection cannot be overridden at run time.

use crate::sha256::hmac_sha256;

/// AES-128-CMAC (RFC 4493).
pub fn aes_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    use cmac::{KeyInit, Mac};
    let mut mac = cmac::Cmac::<aes::Aes128>::new(key.into());
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The bytes the PRF is run over: `i || Label || 0x00 || Context || L`, per SP800-108
/// counter mode, with `i = 1` and `L = 128` because MS-SMB2 3.1.4.2 asks for one 128-bit
/// key.
///
/// **There are TWO zero bytes between the label and the context, and that is the whole
/// reason this is a separate function with an arm on it.** The spec's arguments are the
/// NUL-TERMINATED strings `"SMB2AESCMAC\0"` and `"SmbSign\0"`, and SP800-108 then puts its
/// OWN `0x00` separator after the label. So the terminator and the separator are different
/// bytes that happen to be equal, and writing the construction as "label, then a NUL, then
/// context, then a NUL" -- the natural reading, and one that passes every self-consistent
/// test -- yields an input one byte short and therefore a completely different key.
///
/// What that failure looks like from outside is the point: not a key error, not a signing
/// error. Samba answers `STATUS_ACCESS_DENIED` on the first signed request, which is the
/// same status a wrong password produces. The only thing that names it is the server's own
/// log printing the signature it expected beside the one it got.
fn kdf_input(label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
    input.extend_from_slice(&1u32.to_be_bytes()); // i, the counter
    input.extend_from_slice(label); // INCLUDING its NUL terminator
    input.push(0); // the SP800-108 separator, which is a second zero byte
    input.extend_from_slice(context); // INCLUDING its NUL terminator
    input.extend_from_slice(&128u32.to_be_bytes()); // L, in bits
    input
}

/// SP800-108 counter-mode KDF with HMAC-SHA256, as MS-SMB2 3.1.4.2 uses it: one iteration,
/// 128 bits out. `label` and `context` are passed NUL-terminated -- see `kdf_input`.
pub fn kdf(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 16] {
    let full = hmac_sha256(key, &kdf_input(label, context));
    full[..16]
        .try_into()
        .expect("HMAC-SHA256 output is 32 bytes")
}

/// The key this connection signs with, derived from the session key per dialect.
///
/// 0x0202 and 0x0210 sign with the session key itself. 0x0300 derives, and the label and
/// context are exactly these strings -- `SMB2AESCMAC` and `SmbSign` -- which is the kind of
/// constant that is either right or produces a key that fails everything.
///
/// The session key is NTLMv2's, which is always exactly 16 bytes, so the type says so and
/// MS-SMB2's padding of a shorter key never arises.
pub fn signing_key(session_key: &[u8; 16], dialect: u16) -> Option<[u8; 16]> {
    let k = *session_key;
    // MATCHED EXACTLY, not with `>=`, and that is the point of this shape.
    //
    // `dialect >= 0x0300` is correct for every dialect this client currently offers and
    // silently WRONG for the next one. SMB 3.1.1 derives its signing key from the label
    // "SMBSigningKey\0" with `Session.PreauthIntegrityHashValue` as the context, not from
    // "SmbSign\0" (MS-SMB2 3.1.4.2). Adding 0x0311 to the offered list is a one-line
    // change in a DIFFERENT file, and under `>=` it would have produced a wrong key with
    // no diagnostic -- the server answers STATUS_ACCESS_DENIED, which this module's own
    // header notes is indistinguishable from a bad password.
    //
    // So an unknown dialect yields None and the caller refuses the session by name. A
    // client that cannot sign correctly must not pretend to: the failure belongs at the
    // near end, named, not as a mystery at the far one.
    match dialect {
        0x0202 | 0x0210 => Some(k),
        0x0300 | 0x0302 => Some(kdf(&k, b"SMB2AESCMAC\0", b"SmbSign\0")),
        _ => None,
    }
}

/// The 16-byte signature for a whole SMB2 message, computed the way the server will
/// recompute it: with the signature field itself zeroed.
///
/// The caller is responsible for having set `SMB2_FLAGS_SIGNED` BEFORE calling, because
/// the flag is inside the bytes being signed. Getting that order wrong produces a
/// signature the server cannot reproduce, and the server's complaint is
/// `STATUS_ACCESS_DENIED` -- indistinguishable, from the outside, from a bad password.
pub fn sign(message: &[u8], key: &[u8; 16], dialect: u16) -> [u8; 16] {
    // THE FULL COPY IS DELIBERATE, AND THE REASON IS A MEASUREMENT RATHER THAN A GUESS.
    // It is a 1 MiB allocation per signed WRITE on the hot path, but it costs almost
    // nothing. Measured before AES-NI, 20 iterations at 1 MiB: `sign` took 12.785 ms and
    // the `to_vec` inside it 0.062 ms -- **0.49%**. Spanning the MAC across three slices to
    // avoid it would complicate both the CMAC block loop and the HMAC path to recover half
    // a percent.
    //
    // The other 99.5% was not this copy but the MAC: a table-driven software AES ran at
    // about 78-100 MB/s, and AES-NI at well over 1 GB/s. The `aes` crate takes the hardware
    // path where the CPU has it; measured on `aes_cmac` (1 MiB, best of 5, a Xeon with
    // AES-NI) it runs at about 1.7 GB/s. CMAC is CBC-chained, so that is one block's
    // `aesenc` LATENCY at a time and not the instruction's throughput.
    //
    // **What that number is NOT is the speed of a signed stream**, and it is tempting to
    // read it as "above 10 GbE line rate". A signed WRITE copies its payload four times --
    // data into the body, body into the message, the message here, the message into the
    // frame -- and a call-shaped benchmark of that path took 1.029 ms per MiB, about
    // 1019 MB/s: BELOW the 1250 MB/s a 10 GbE link carries raw. With an allocator that
    // hands out fresh pages each time the copy here alone rose from 0.041 ms to 0.52 ms.
    // So at 10 GbE a signed session is copy-bound as well as MAC-bound, this copy is one of
    // four, and removing only this one would not change that conclusion.
    let mut m = message.to_vec();
    if m.len() >= 64 {
        m[48..64].fill(0);
    }
    if dialect >= 0x0300 {
        aes_cmac(key, &m)
    } else {
        let mac = hmac_sha256(key, &m);
        let mut out = [0u8; 16];
        out.copy_from_slice(&mac[..16]);
        out
    }
}

/// Whether a RECEIVED message carries a signature this key and dialect reproduce.
///
/// **Signing a request proves this client to the server. It does nothing about the reply,
/// and the reply is where the bytes are.** MS-SMB2 3.2.5.1.3 makes verification a MUST on a
/// session that requires signing, and for a copy tool the reason is not ceremony: an
/// unverified READ response is attacker-chosen file content, and an unverified status code
/// steers the copy -- `STATUS_END_OF_FILE` truncates a file to whatever arrived. A client
/// that signs and does not verify has bought the half of the guarantee it needed least.
///
/// The comparison is constant-time. Not because a timing oracle on a MAC comparison is a
/// realistic threat to a file copy, but because `==` on a 16-byte array is a short-circuit
/// compare and writing the careful version costs three lines.
pub fn verify(message: &[u8], key: &[u8; 16], dialect: u16) -> bool {
    if message.len() < 64 {
        return false;
    }
    let want = sign(message, key, dialect);
    let got = &message[48..64];
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= want[i] ^ got[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// FIPS-197 appendix C.1, the published AES-128 vector, on the cipher signing uses.
    ///
    /// A block cipher wired up wrongly (the wrong key size, the wrong crate type) still
    /// produces 16 plausible bytes, and every failure downstream reads as an authentication
    /// problem. So it is checked against the number in the standard.
    #[test]
    fn the_aes_block_matches_the_fips_197_vector() {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encrypt = |k: &[u8; 16]| {
            let mut block = plain.into();
            aes::Aes128::new(k.into()).encrypt_block(&mut block);
            let out: [u8; 16] = block.into();
            out
        };
        let block = encrypt(&key);
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
        // THE CONTROL: one bit of the key changes the whole block, so this is not a
        // function that happens to return its input or a constant.
        let mut k2 = key;
        k2[0] ^= 1;
        assert_ne!(hex(&encrypt(&k2)), hex(&block));
    }

    /// A real 0x0300 `sign` IS AES-128-CMAC over the message with its signature field
    /// zeroed, computed by the `cmac` crate, and a 0x02xx `sign` is not.
    ///
    /// This replaces the old arm that counted entries into rcp's own AES-NI kernel: that
    /// kernel is gone, and the crate picks its hardware path itself. What can still go
    /// wrong at THIS layer is the call site -- the wrong algorithm for a dialect, or a
    /// field left unzeroed -- so that is what is pinned, against the crate called directly
    /// and over every length residue mod 16 (which decides the CMAC subkey) plus large
    /// bodies.
    #[test]
    fn a_real_signature_is_the_crate_cmac_exactly_when_the_dialect_asks_for_it() {
        use cmac::{KeyInit, Mac};
        // xorshift64: reproducible variety across keys and bytes.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut compared = 0;
        for round in 0..16 {
            let mut key = [0u8; 16];
            key.iter_mut().for_each(|b| *b = next() as u8);
            for len in (64..=80).chain([1024, 65_536 + 7]) {
                let msg: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                let mut zeroed = msg.clone();
                zeroed[48..64].fill(0);
                let mut mac = cmac::Cmac::<aes::Aes128>::new((&key).into());
                mac.update(&zeroed);
                let want: [u8; 16] = mac.finalize().into_bytes().into();
                assert_eq!(
                    sign(&msg, &key, 0x0300),
                    want,
                    "round {round}, {len}-byte message: 0x0300 is not AES-CMAC"
                );
                // THE CONTROL: 0x0210 signs with HMAC-SHA256, so it must differ.
                assert_ne!(sign(&msg, &key, 0x0210), want, "0x0210 used AES-CMAC");
                compared += 1;
            }
        }
        assert_eq!(
            compared,
            16 * 19,
            "the comparison loop did not run as many cases as it claims"
        );
    }

    /// Signatures computed by an INDEPENDENT implementation, reproduced byte for byte.
    ///
    /// **Nothing else in this module could fail on a wrong KDF context at the call site,
    /// and that was measured rather than suspected.** The KDF arms do not reach
    /// `signing_key`: replanted, `kdf(&k, b"SMB2AESCMAC\0", b"SmbSign")` -- the context one
    /// byte short, the exact shape of the defect this module already shipped once -- leaves
    /// all nine signing arms green. The layout arm below pins `kdf_input`; it
    /// never sees what `signing_key` passes it. Every other arm compares this code with
    /// itself.
    ///
    /// These vectors come from outside it: impacket's `crypto.KDF_CounterMode` for the
    /// key, Cryptodome's `CMAC` for 0x0300, Python's `hmac`/`hashlib` for 0x0202. The
    /// message is a real SMB2 header (SIGNED set, session id 0x1122334455667788) with a
    /// 40-byte body -- 104 bytes, so the last CMAC block is PARTIAL and takes the subkey
    /// the RFC 4493 vectors exercise least -- and its signature field is filled with 0xAA,
    /// so the vector also proves the field is zeroed before signing rather than trusted.
    ///
    /// ```text
    /// sk = bytes(range(16)); z = msg[:48] + b"\0"*16 + msg[64:]
    /// k = impacket.crypto.KDF_CounterMode(sk, b"SMB2AESCMAC\0", b"SmbSign\0", 128)
    /// hmac.new(sk, z, hashlib.sha256).digest()[:16];  CMAC.new(k, ciphermod=AES).update(z)
    /// ```
    #[test]
    fn signing_reproduces_vectors_from_an_independent_implementation() {
        let unhex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        let session_key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let msg = unhex(concat!(
            "fe534d42400000000000000003000000080000000000000005000000000000000000000000000000",
            "8877665544332211aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa030a11181f262d343b424950575e656c",
            "737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d14",
        ));
        assert_eq!(msg.len(), 104);
        assert_eq!(
            msg[48..64],
            [0xaa; 16],
            "the vector's signature field must carry junk, or it cannot show the field is zeroed"
        );

        let k300 = signing_key(&session_key, 0x0300).expect("3.0 is implemented");
        assert_eq!(
            hex(&k300),
            "6234814cbb8ea9227440ebfeb5eacbe1",
            "the 0x0300 signing key disagrees with impacket's KDF"
        );
        assert_eq!(signing_key(&session_key, 0x0202), Some(session_key));
        assert_eq!(
            hex(&sign(&msg, &session_key, 0x0202)),
            "59571dd1a31e7c053a85120e6a7d96f5",
            "HMAC-SHA256 signature"
        );
        assert_eq!(
            hex(&sign(&msg, &k300, 0x0300)),
            "7a15a40ab2c6be85cc7678fe2ee5f57d",
            "AES-CMAC signature"
        );
        // and the MAC alone over the zeroed message, without `sign` around it
        let mut zeroed = msg.clone();
        zeroed[48..64].fill(0);
        assert_eq!(
            hex(&aes_cmac(&k300, &zeroed)),
            "7a15a40ab2c6be85cc7678fe2ee5f57d",
            "CMAC over the zeroed message"
        );
        // and a message carrying the independent signature verifies in place
        let mut signed = msg.clone();
        signed[48..64].copy_from_slice(&unhex("7a15a40ab2c6be85cc7678fe2ee5f57d"));
        assert!(
            verify(&signed, &k300, 0x0300),
            "the independent signature must verify"
        );
    }

    /// RFC 4493 section 4, all four published AES-CMAC vectors.
    ///
    /// The four are not decoration: they are the empty message, one whole block, a PARTIAL
    /// last block and a whole-block-multiple. Those last two take the two different subkeys,
    /// which is the half of CMAC that is easy to get backwards and which a single vector
    /// would not distinguish.
    #[test]
    fn aes_cmac_matches_all_four_rfc_4493_vectors() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        assert_eq!(
            hex(&aes_cmac(&key, &[])),
            "bb1d6929e95937287fa37d129b756746",
            "the empty message"
        );
        assert_eq!(
            hex(&aes_cmac(&key, &msg[..16])),
            "070a16b46b4d4144f79bdd9dd04a287c",
            "one whole block"
        );
        assert_eq!(
            hex(&aes_cmac(&key, &msg[..40])),
            "dfa66747de9ae63030ca32611497c827",
            "a partial last block, which takes the OTHER subkey"
        );
        assert_eq!(
            hex(&aes_cmac(&key, &msg[..64])),
            "51f0bebf7e3b9d92fc49741779363cfe",
            "four whole blocks"
        );
        // THE CONTROL: the two subkeys really do differ, so a 16-byte message and the same
        // 16 bytes padded to 32 do not collide.
        let mut padded = msg[..16].to_vec();
        padded.extend_from_slice(&[0u8; 16]);
        assert_ne!(
            hex(&aes_cmac(&key, &msg[..16])),
            hex(&aes_cmac(&key, &padded))
        );
    }

    /// The signature covers the message with its own field zeroed, and the dialect picks
    /// the algorithm.
    #[test]
    fn a_signature_zeroes_its_own_field_and_follows_the_dialect() {
        let key = [7u8; 16];
        let mut msg = vec![0u8; 128];
        msg[0..4].copy_from_slice(b"\xfeSMB");
        let want = sign(&msg, &key, 0x0300);
        // whatever was in the signature field before cannot matter
        let mut dirty = msg.clone();
        dirty[48..64].copy_from_slice(&[0xab; 16]);
        assert_eq!(
            sign(&dirty, &key, 0x0300),
            want,
            "the old signature bytes changed the new signature"
        );
        // THE CONTROL: a change anywhere ELSE does matter, so this is not zeroing too much
        let mut altered = msg.clone();
        altered[70] ^= 1;
        assert_ne!(sign(&altered, &key, 0x0300), want);
        // and the two dialect families use different algorithms
        assert_ne!(
            sign(&msg, &key, 0x0210),
            want,
            "0x0210 must sign with HMAC-SHA256, not CMAC"
        );
        assert_eq!(
            sign(&msg, &key, 0x0202),
            sign(&msg, &key, 0x0210),
            "both 0x02xx dialects sign the same way"
        );
    }

    /// The 0x0300 signing key is DERIVED; the 0x02xx one is the session key itself.
    #[test]
    fn the_signing_key_is_derived_only_for_the_dialect_that_asks_for_it() {
        let session = [9u8; 16];
        assert_eq!(
            signing_key(&session, 0x0210),
            Some(session),
            "0x0210 signs with the session key directly"
        );
        assert_ne!(
            signing_key(&session, 0x0300),
            Some(session),
            "0x0300 must derive a separate signing key"
        );
        // the label and the context both matter -- a KDF that ignored either would be a
        // silent wrong key, and every request would be refused as if the password were bad
        assert_ne!(
            kdf(&session, b"SMB2AESCMAC\0", b"SmbSign\0"),
            kdf(&session, b"SMB2AESCMAC\0", b"SmbRcmd\0")
        );
        assert_ne!(
            kdf(&session, b"SMB2AESCMAC\0", b"SmbSign\0"),
            kdf(&session, b"SMBSigningKey\0", b"SmbSign\0")
        );
    }

    /// A dialect whose key derivation is not implemented yields NO KEY.
    ///
    /// The replaced code read `dialect >= 0x0300`, which is right for everything offered
    /// today and silently wrong for 0x0311 -- a different label and a different context.
    /// The old arm could not catch that: it asserted only that 0x0210 returns the session
    /// key unchanged and 0x0300 does not, which holds for ANY threshold placement and so
    /// says nothing about where the threshold actually is.
    #[test]
    fn a_dialect_this_code_cannot_key_is_refused_rather_than_guessed() {
        let sk = [9u8; 16];
        assert_eq!(
            signing_key(&sk, 0x0202),
            Some(sk),
            "pre-3.0 signs with the session key itself"
        );
        assert_eq!(signing_key(&sk, 0x0210), Some(sk));
        let three_oh = signing_key(&sk, 0x0300).expect("3.0 is implemented");
        assert_ne!(three_oh, sk, "3.0 must derive, not pass through");
        assert_eq!(
            signing_key(&sk, 0x0302),
            Some(three_oh),
            "3.0.2 shares 3.0's derivation"
        );

        // THE CONTROL, and the whole reason this arm exists. 0x0311 is GREATER than
        // 0x0300, so the old `>=` happily produced the 3.0 key for it -- a key the server
        // cannot reproduce, surfacing as STATUS_ACCESS_DENIED and reading like a bad
        // password.
        assert_eq!(
            signing_key(&sk, 0x0311),
            None,
            "3.1.1 uses a different label and context; guessing is worse than refusing"
        );
        for d in [0x0000u16, 0x0201, 0x0311, 0x0400, 0xffff] {
            assert_eq!(
                signing_key(&sk, d),
                None,
                "dialect 0x{d:04x} is not implemented and must not be guessed"
            );
        }
    }

    /// `verify` accepts what `sign` produced and refuses everything else.
    ///
    /// The controls are the arm: an acceptance-only check would pass on a `verify` that
    /// returned `true` unconditionally, which is precisely the shape a missing verification
    /// takes. So every field a tamperer would touch is altered in turn and each must be
    /// refused -- the body, the status, the flags, the signature itself, and the key.
    #[test]
    fn verify_accepts_its_own_signature_and_refuses_every_alteration() {
        let key = [0x11u8; 16];
        let mut msg = vec![0u8; 128];
        msg[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        msg[16..20].copy_from_slice(&crate::smb::proto::FLAGS_SIGNED.to_le_bytes());
        for (i, b) in msg.iter_mut().enumerate().skip(64) {
            *b = i as u8;
        }
        for dialect in [0x0202u16, 0x0300] {
            let sig = sign(&msg, &key, dialect);
            let mut signed = msg.clone();
            signed[48..64].copy_from_slice(&sig);
            assert!(
                verify(&signed, &key, dialect),
                "dialect 0x{dialect:04x}: a message must verify under the key that signed it"
            );

            // THE CONTROLS. Each is a byte an attacker would plausibly change.
            for (what, at) in [
                ("the body", 100usize),
                ("the status", 8),
                ("the flags", 16),
                ("the signature", 50),
            ] {
                let mut tampered = signed.clone();
                tampered[at] ^= 1;
                assert!(
                    !verify(&tampered, &key, dialect),
                    "dialect 0x{dialect:04x}: altering {what} must not verify"
                );
            }
            // a different key is a different server
            let mut other = key;
            other[0] ^= 1;
            assert!(
                !verify(&signed, &other, dialect),
                "dialect 0x{dialect:04x}: another key must not verify"
            );
            // and the algorithms are not interchangeable, so a dialect confusion is caught
            let cross = if dialect == 0x0300 { 0x0202 } else { 0x0300 };
            assert!(
                !verify(&signed, &key, cross),
                "a signature must not verify under the other dialect's algorithm"
            );
        }
        // Too short to hold a signature field: refused rather than indexed into.
        assert!(!verify(&[0u8; 63], &key, 0x0300));
    }

    /// **The arm the one above could not be.** Everything it asserts is a statement about
    /// this KDF against itself -- change the label and the key changes -- and all of it
    /// stays true with the key wrong when the defect is a MISSING byte rather than a wrong
    /// one. A self-consistency check cannot see a missing byte; only the layout can.
    ///
    /// So this spells the PRF input out against MS-SMB2 3.1.4.2 and SP800-108 §5.1:
    /// `i || Label || 0x00 || Context || L`, where Label and Context arrive NUL-terminated.
    /// The consequence is the pair of zeros at offsets 15 and 16, and reproducing the
    /// original defect -- deleting exactly one of them -- has to fail this.
    #[test]
    fn the_kdf_input_has_both_zero_bytes_between_the_label_and_the_context() {
        let got = kdf_input(b"SMB2AESCMAC\0", b"SmbSign\0");
        let mut want = Vec::new();
        want.extend_from_slice(&[0, 0, 0, 1]); // i = 1
        want.extend_from_slice(b"SMB2AESCMAC"); // the label
        want.push(0); //   ... its NUL terminator, which is part of the spec's argument
        want.push(0); //   ... and the SP800-108 separator, which is a DIFFERENT byte
        want.extend_from_slice(b"SmbSign"); // the context
        want.push(0); //   ... its NUL terminator; no separator follows, L does
        want.extend_from_slice(&[0, 0, 0, 0x80]); // L = 128 bits, big-endian
        assert_eq!(got, want, "the PRF input does not match MS-SMB2 3.1.4.2");
        assert_eq!(got.len(), 4 + 12 + 1 + 8 + 4);
        assert_eq!(
            (got[15], got[16]),
            (0, 0),
            "the label's terminator and the separator are two bytes, not one"
        );

        // THE CONTROL, and it is the defect itself replanted: drop one of the two zeros --
        // the exact shape of "label, then a NUL, then context, then a NUL" -- and both the
        // input and the key it produces must change. Without this the arm above would pass
        // on the broken construction, which is what happened.
        let mut short = got.clone();
        short.remove(15);
        assert_ne!(short, got);
        let key = [9u8; 16];
        assert_ne!(
            hmac_sha256(&key, &short)[..16],
            kdf(&key, b"SMB2AESCMAC\0", b"SmbSign\0")[..]
        );
    }
}
