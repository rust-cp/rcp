//! A scripted SMB2 peer, for the arms the impacket stand-in cannot reach.
//!
//! **Three properties this adapter claims have no arm that can fail without this peer, and
//! replanting each one shows it.** Deleting the reply-signature check leaves every other
//! arm green. Deleting the hand check on the final SESSION_SETUP cannot be tried at all,
//! because nothing else in the suite produces a signed session. And arms that stand in for
//! a server with counters set by hand let seven of nine edits to the credential budget
//! pass.
//!
//! The reason is the same each time: impacket cannot REQUIRE signing, cannot hang up
//! after an AUTHENTICATE, and does not say how many AUTHENTICATEs it received. A real
//! Samba can do the first but is not in every run. So this peer speaks just enough SMB2 --
//! NEGOTIATE, the two SESSION_SETUPs, and a generic answer to anything after -- to make
//! each of those choices on purpose, and COUNTS what it was sent.
//!
//! It is not a conformance server and makes no attempt to be one. What it gets right is
//! the part the arms depend on: it derives the session key from the NTLMv2 proof the
//! client actually sent, the same way a server does, so a signature it produces is one the
//! client can only verify if the two ends really agree on the key.

use super::{ntlm, proto, sign};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The credential this peer derives its key from. A client offering another password
/// still gets whatever `Answer` says -- which is the point of `Answer::Accept` with a
/// wrong password: an impostor that says yes but cannot sign.
pub(crate) const USER: &str = "tester";
pub(crate) const PASSWORD: &str = "correct horse";
pub(crate) const DOMAIN: &str = "";

const SESSION: u64 = 0x0000_4000_0000_0011;
const TREE: u32 = 7;
const LARGE_MTU: u32 = 0x0000_0004;
const SERVER_TO_REDIR: u32 = 0x0000_0001;

/// How a reply is signed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Signature {
    /// With the session's key, as a server must.
    Correct,
    /// Not at all, and the SIGNED flag clear -- the downgrade shape.
    Absent,
    /// Flag set, signature one bit off -- the tampering shape.
    Wrong,
}

/// What the peer does with an NTLMSSP AUTHENTICATE.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Answer {
    /// `STATUS_SUCCESS` for a CORRECT NTLMv2 proof, with the response signed as given; a
    /// proof that does not reproduce under the peer's own credential gets
    /// `STATUS_LOGON_FAILURE`, as a real server would. If it checked nothing, a client
    /// sending a bad proof would pass every arm here.
    Accept(Signature),
    /// `STATUS_SUCCESS` for ANY proof: the impostor, a server that says yes to a password it
    /// cannot check -- and therefore cannot sign with the key the password derives.
    ///
    /// Only ever evidence of a REFUSAL. A login which succeeds against this answer proves
    /// nothing about the credential, since the key comes from whatever proof the client
    /// sent; an arm using it must assert that the login FAILS.
    AcceptAnything(Signature),
    /// `STATUS_SUCCESS` with SessionFlags IS_GUEST, unsigned: how a server that maps bad
    /// passwords to guest says no.
    Guest,
    /// `STATUS_LOGON_FAILURE`: the unambiguous refusal.
    Reject,
    /// Refuse with this status, unsigned -- what an on-path party can inject, since no key
    /// exists to sign a failed logon with.
    Fail(u32),
    /// Close the connection without answering: the credential went out and nobody said
    /// what became of it. This is the shape that no error kind can tell apart from a
    /// network fault, which is why it matters.
    HangUp,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Script {
    pub signing_required: bool,
    pub dialect: u16,
    pub answer: Answer,
    /// How every reply after the session is set up is signed, when the session is signed.
    pub later: Signature,
    /// The status those replies carry. TREE_CONNECT answers with a tree on success.
    pub later_status: u32,
    /// Close the connection on the first SESSION_SETUP, before any challenge -- a login
    /// that dies before a credential could have gone out.
    pub hang_up_at_challenge: bool,
    /// Before each reply after the session is set up, send an UNSIGNED interim
    /// `STATUS_PENDING` granting this many credits: what an on-path party can inject,
    /// since interim responses are not verified.
    pub forged_interim: Option<u16>,
    /// Send the challenge, then close: the server that gave up on a login while the client
    /// waited to answer it.
    pub close_after_challenge: bool,
    /// Never answer the first SESSION_SETUP: a login that stalls before any credential.
    pub stall_at_challenge: bool,
    /// Credits the FINAL reply to each request after the session is set up grants, instead
    /// of what was asked -- so an arm can tell a grant that came in an interim from one
    /// that came in the final reply.
    pub final_grant: Option<u16>,
    /// Answer the FIRST SESSION_SETUP with this status, before any challenge.
    pub fail_first_leg: Option<u32>,
    /// Deliver the answer to the AUTHENTICATE one byte at a time, this far apart: a server
    /// that never lets a single read time out and never finishes.
    pub trickle: Option<std::time::Duration>,
    /// Wait this long before answering the AUTHENTICATE.
    pub delay_answer: Option<std::time::Duration>,
    /// Wait this long before answering anything after the session is set up.
    pub delay_later: Option<std::time::Duration>,
    /// Deliver the reply to anything after the session is set up (the TREE_CONNECT) one byte
    /// at a time, this far apart: a server that trickles the tree connect, which a per-syscall
    /// socket timeout never catches but an absolute deadline does.
    pub trickle_later: Option<std::time::Duration>,
}

impl Script {
    /// A server that requires signing at 0x0300 and does everything right.
    pub(crate) fn signing() -> Script {
        Script {
            signing_required: true,
            dialect: 0x0300,
            answer: Answer::Accept(Signature::Correct),
            later: Signature::Correct,
            later_status: proto::STATUS_SUCCESS,
            hang_up_at_challenge: false,
            forged_interim: None,
            close_after_challenge: false,
            stall_at_challenge: false,
            final_grant: None,
            fail_first_leg: None,
            trickle: None,
            delay_answer: None,
            delay_later: None,
            trickle_later: None,
        }
    }

    /// A server that does not require signing and answers the AUTHENTICATE as given.
    pub(crate) fn unsigned(answer: Answer) -> Script {
        Script {
            signing_required: false,
            dialect: 0x0210,
            answer,
            later: Signature::Correct,
            later_status: proto::STATUS_SUCCESS,
            hang_up_at_challenge: false,
            forged_interim: None,
            close_after_challenge: false,
            stall_at_challenge: false,
            final_grant: None,
            fail_first_leg: None,
            trickle: None,
            delay_answer: None,
            delay_later: None,
            trickle_later: None,
        }
    }
}

pub(crate) struct Peer {
    pub port: u16,
    script: Arc<Mutex<Script>>,
    authenticates: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    finished: Arc<AtomicUsize>,
}

impl Peer {
    /// How many NTLMSSP AUTHENTICATE messages -- credentials -- this peer has received.
    pub(crate) fn authenticates(&self) -> usize {
        self.authenticates.load(Ordering::SeqCst)
    }

    /// How many connections this peer has finished serving -- closed its side of.
    pub(crate) fn finished(&self) -> usize {
        self.finished.load(Ordering::SeqCst)
    }

    /// How many TCP connections this peer has accepted, credential or not.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Changes what the peer does from the next message on, for an arm that needs a server
    /// to recover mid-run.
    pub(crate) fn set(&self, change: impl FnOnce(&mut Script)) {
        change(&mut self.script.lock().unwrap());
    }
}

/// Listens on a free loopback port and serves every connection on its own thread, so a
/// pool of workers can dial it at once.
pub(crate) fn spawn(script: Script) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().unwrap().port();
    let script = Arc::new(Mutex::new(script));
    let authenticates = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let (s, a, c, f) = (
        script.clone(),
        authenticates.clone(),
        connections.clone(),
        finished.clone(),
    );
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            c.fetch_add(1, Ordering::SeqCst);
            let (s, a, f) = (s.clone(), a.clone(), f.clone());
            std::thread::spawn(move || {
                let _ = serve(stream, &s, &a);
                // `serve` owned the stream, so it is closed by the time this counts
                f.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    Peer {
        port,
        script,
        authenticates,
        connections,
        finished,
    }
}

fn serve(
    mut sock: TcpStream,
    script: &Mutex<Script>,
    authenticates: &AtomicUsize,
) -> io::Result<()> {
    let mut dialect = 0x0202u16;
    let mut key: Option<[u8; 16]> = None;
    // A FRESH CHALLENGE PER CONNECTION, as a server issues one. A constant would hide a
    // client replaying an AUTHENTICATE it had cached from an earlier session: it would
    // reproduce the proof and pass every arm here.
    let server_challenge = fresh_challenge();
    loop {
        let req = read_frame(&mut sock)?;
        let command = u16::from_le_bytes([req[12], req[13]]);
        let sc = *script.lock().unwrap();
        match command {
            proto::NEGOTIATE => {
                dialect = sc.dialect;
                reply(
                    &mut sock,
                    &req,
                    proto::STATUS_SUCCESS,
                    0,
                    0,
                    &negotiate_body(&sc),
                    None,
                )?;
            }
            proto::SESSION_SETUP => {
                let blob = request_blob(&req)?;
                match u32::from_le_bytes(blob[8..12].try_into().unwrap()) {
                    1 if sc.hang_up_at_challenge => return Ok(()),
                    1 if sc.fail_first_leg.is_some() => {
                        reply(
                            &mut sock,
                            &req,
                            sc.fail_first_leg.unwrap(),
                            0,
                            0,
                            &error_body(),
                            None,
                        )?;
                    }
                    // held open, unanswered, until the client gives up and closes it
                    1 if sc.stall_at_challenge => {
                        let _ = read_frame(&mut sock);
                        return Ok(());
                    }
                    1 => {
                        reply(
                            &mut sock,
                            &req,
                            proto::STATUS_MORE_PROCESSING_REQUIRED,
                            SESSION,
                            0,
                            &session_setup_body(&challenge(&server_challenge)),
                            None,
                        )?;
                        if sc.close_after_challenge {
                            return Ok(());
                        }
                    }
                    3 => {
                        authenticates.fetch_add(1, Ordering::SeqCst);
                        if let Some(d) = sc.delay_answer {
                            std::thread::sleep(d);
                        }
                        // MS-SMB2 3.3.5.5: the session is signed if the server requires it OR
                        // the client's SESSION_SETUP SecurityMode says the client does.
                        let client_requires =
                            req.get(proto::HEADER + 3).is_some_and(|m| m & 2 != 0);
                        match sc.answer {
                            Answer::HangUp => return Ok(()),
                            Answer::Reject if sc.trickle.is_some() => {
                                let mut frame = Vec::new();
                                reply(
                                    &mut frame,
                                    &req,
                                    proto::STATUS_LOGON_FAILURE,
                                    SESSION,
                                    0,
                                    &error_body(),
                                    None,
                                )?;
                                for b in frame {
                                    std::thread::sleep(sc.trickle.unwrap());
                                    sock.write_all(&[b])?;
                                }
                            }
                            Answer::Reject => reply(
                                &mut sock,
                                &req,
                                proto::STATUS_LOGON_FAILURE,
                                SESSION,
                                0,
                                &error_body(),
                                None,
                            )?,
                            Answer::Fail(status) => {
                                reply(&mut sock, &req, status, SESSION, 0, &error_body(), None)?
                            }
                            Answer::Guest => reply(
                                &mut sock,
                                &req,
                                proto::STATUS_SUCCESS,
                                SESSION,
                                0,
                                &session_setup_flags(&[], 0x0001),
                                None,
                            )?,
                            Answer::Accept(_) if !proof_holds(blob, &server_challenge)? => reply(
                                &mut sock,
                                &req,
                                proto::STATUS_LOGON_FAILURE,
                                SESSION,
                                0,
                                &error_body(),
                                None,
                            )?,
                            Answer::Accept(sig) | Answer::AcceptAnything(sig) => {
                                let k = sign::signing_key(&session_key_of(blob)?, dialect)
                                    .expect("a dialect this peer offers");
                                reply(
                                    &mut sock,
                                    &req,
                                    proto::STATUS_SUCCESS,
                                    SESSION,
                                    0,
                                    &session_setup_body(&[]),
                                    Some((k, dialect, sig)),
                                )?;
                                if sc.signing_required || client_requires {
                                    key = Some(k);
                                }
                            }
                        }
                    }
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("NTLMSSP type {other}"),
                        ))
                    }
                }
            }
            // ON A SIGNED SESSION, AN UNSIGNED OR MIS-SIGNED REQUEST IS REFUSED, as a real
            // server refuses it. A peer that did not look would let a client which stopped
            // signing its requests pass every arm built on it.
            _ if key.is_some_and(|k| {
                u32::from_le_bytes(req[16..20].try_into().unwrap()) & proto::FLAGS_SIGNED == 0
                    || !sign::verify(&req, &k, dialect)
            }) =>
            {
                reply(
                    &mut sock,
                    &req,
                    proto::STATUS_ACCESS_DENIED,
                    SESSION,
                    0,
                    &error_body(),
                    key.map(|k| (k, dialect, Signature::Correct)),
                )?;
            }
            _ => {
                let (status, tree, body) = match (command, sc.later_status) {
                    (proto::TREE_CONNECT, proto::STATUS_SUCCESS) => {
                        (proto::STATUS_SUCCESS, TREE, tree_connect_body())
                    }
                    (proto::LOGOFF | proto::TREE_DISCONNECT, proto::STATUS_SUCCESS) => {
                        (proto::STATUS_SUCCESS, 0, vec![4, 0, 0, 0])
                    }
                    (_, status) => (status, 0, error_body()),
                };
                if let Some(d) = sc.delay_later {
                    std::thread::sleep(d);
                }
                if let Some(credits) = sc.forged_interim {
                    interim(&mut sock, &req, credits)?;
                }
                if let Some(d) = sc.trickle_later {
                    // dribble the reply a byte at a time, each within a per-syscall timeout
                    // but well past an absolute deadline
                    let mut frame = Vec::new();
                    reply_granting(
                        &mut frame,
                        &req,
                        status,
                        SESSION,
                        tree,
                        &body,
                        key.map(|k| (k, dialect, sc.later)),
                        sc.final_grant,
                    )?;
                    for b in frame {
                        std::thread::sleep(d);
                        sock.write_all(&[b])?;
                    }
                } else {
                    reply_granting(
                        &mut sock,
                        &req,
                        status,
                        SESSION,
                        tree,
                        &body,
                        key.map(|k| (k, dialect, sc.later)),
                        sc.final_grant,
                    )?;
                }
            }
        }
    }
}

fn read_frame(sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut nb = [0u8; 4];
    sock.read_exact(&mut nb)?;
    let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize;
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf)?;
    if buf.len() < proto::HEADER {
        return Err(proto::short("a request header"));
    }
    Ok(buf)
}

/// The NTLMSSP blob out of a SESSION_SETUP request, by the offset the request gives.
fn request_blob(req: &[u8]) -> io::Result<&[u8]> {
    let at = proto::HEADER + 12;
    let field = req
        .get(at..at + 4)
        .ok_or_else(|| proto::short("a SESSION_SETUP request"))?;
    let off = u16::from_le_bytes([field[0], field[1]]) as usize;
    let len = u16::from_le_bytes([field[2], field[3]]) as usize;
    req.get(off..off + len)
        .filter(|b| b.len() >= 12)
        .ok_or_else(|| proto::short("the security blob"))
}

/// The session key a server derives from an NTLMv2 AUTHENTICATE: HMAC-MD5 under the
/// NTOWFv2 of the credential it holds, over the proof the client sent. No KEY_EXCH, because
/// the client does not negotiate it.
fn session_key_of(auth: &[u8]) -> io::Result<[u8; 16]> {
    Ok(ntlm::hmac_md5(
        &ntlm::ntowf_v2(USER, DOMAIN, PASSWORD),
        &nt_response(auth)?[..16],
    ))
}

/// The NT response field of an AUTHENTICATE, bounds-checked. To the client a short message
/// looks the same either way -- the connection closes -- so this is not about what an arm
/// sees; it keeps a malformed request from printing a panic into the test output.
fn nt_response(auth: &[u8]) -> io::Result<&[u8]> {
    if auth.len() < 28 {
        return Err(proto::short("an NTLMSSP AUTHENTICATE"));
    }
    let len = u16::from_le_bytes([auth[20], auth[21]]) as usize;
    let off = u32::from_le_bytes(auth[24..28].try_into().unwrap()) as usize;
    // An NTLMv2 response: the 16-byte proof, then a client blob of at least the 28-byte fixed
    // part (RespType 1, HiRespType 1, reserved, timestamp, nonce, reserved) -- so a client
    // sending the proof alone, over the challenge alone, is refused rather than accepted.
    auth.get(off..off.saturating_add(len))
        .filter(|n| n.len() >= 16 + 28 && n[16] == 1 && n[17] == 1)
        .ok_or_else(|| proto::short("an NTLMv2 NT response"))
}

/// Whether the client's NTLMv2 proof reproduces under the peer's own credential: the proof
/// is HMAC-MD5 under NTOWFv2 of the server challenge followed by the client's blob.
fn proof_holds(auth: &[u8], server_challenge: &[u8; 8]) -> io::Result<bool> {
    let nt = nt_response(auth)?;
    let mut input = server_challenge.to_vec();
    input.extend_from_slice(&nt[16..]);
    Ok(ntlm::hmac_md5(&ntlm::ntowf_v2(USER, DOMAIN, PASSWORD), &input)[..] == nt[..16])
}

fn reply(
    sock: &mut impl Write,
    req: &[u8],
    status: u32,
    session: u64,
    tree: u32,
    body: &[u8],
    signing: Option<([u8; 16], u16, Signature)>,
) -> io::Result<()> {
    reply_granting(sock, req, status, session, tree, body, signing, None)
}

#[allow(clippy::too_many_arguments)]
fn reply_granting(
    sock: &mut impl Write,
    req: &[u8],
    status: u32,
    session: u64,
    tree: u32,
    body: &[u8],
    signing: Option<([u8; 16], u16, Signature)>,
    grant: Option<u16>,
) -> io::Result<()> {
    let mut m = vec![0u8; proto::HEADER];
    m[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    m[4..6].copy_from_slice(&64u16.to_le_bytes());
    m[6..8].copy_from_slice(&req[6..8]); // CreditCharge, echoed
    m[8..12].copy_from_slice(&status.to_le_bytes());
    m[12..14].copy_from_slice(&req[12..14]); // Command
                                             // Grant what was asked, and never less than one, so the window never closes.
    let asked = u16::from_le_bytes([req[14], req[15]]).max(1);
    m[14..16].copy_from_slice(&grant.unwrap_or(asked).to_le_bytes());
    let mut flags = SERVER_TO_REDIR;
    let signing = signing.filter(|(_, _, s)| *s != Signature::Absent);
    if signing.is_some() {
        flags |= proto::FLAGS_SIGNED;
    }
    m[16..20].copy_from_slice(&flags.to_le_bytes());
    m[24..32].copy_from_slice(&req[24..32]); // MessageId
    m[36..40].copy_from_slice(
        &(if tree != 0 {
            tree
        } else {
            u32::from_le_bytes(req[36..40].try_into().unwrap())
        })
        .to_le_bytes(),
    );
    m[40..48].copy_from_slice(&session.to_le_bytes());
    m.extend_from_slice(body);
    if let Some((key, dialect, how)) = signing {
        let mut sig = sign::sign(&m, &key, dialect);
        if how == Signature::Wrong {
            sig[0] ^= 1;
        }
        m[48..64].copy_from_slice(&sig);
    }
    let mut frame = vec![
        0,
        (m.len() >> 16) as u8,
        (m.len() >> 8) as u8,
        m.len() as u8,
    ];
    frame.extend_from_slice(&m);
    sock.write_all(&frame)
}

/// An unsigned interim response (MS-SMB2 3.3.4.2): `STATUS_PENDING`, ASYNC set, the
/// request's message id, granting `credits`.
fn interim(sock: &mut TcpStream, req: &[u8], credits: u16) -> io::Result<()> {
    let mut m = vec![0u8; proto::HEADER];
    m[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    m[4..6].copy_from_slice(&64u16.to_le_bytes());
    m[8..12].copy_from_slice(&proto::STATUS_PENDING.to_le_bytes());
    m[12..14].copy_from_slice(&req[12..14]);
    m[14..16].copy_from_slice(&credits.to_le_bytes());
    m[16..20].copy_from_slice(&(SERVER_TO_REDIR | proto::FLAGS_ASYNC_COMMAND).to_le_bytes());
    m[24..32].copy_from_slice(&req[24..32]); // MessageId
    m[32..40].copy_from_slice(&1u64.to_le_bytes()); // AsyncId
    m[40..48].copy_from_slice(&SESSION.to_le_bytes());
    m.extend_from_slice(&error_body());
    let mut frame = vec![
        0,
        (m.len() >> 16) as u8,
        (m.len() >> 8) as u8,
        m.len() as u8,
    ];
    frame.extend_from_slice(&m);
    sock.write_all(&frame)
}

/// MS-SMB2 2.2.4, structure size 65.
fn negotiate_body(sc: &Script) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&65u16.to_le_bytes());
    b.extend_from_slice(&(1u16 | if sc.signing_required { 2 } else { 0 }).to_le_bytes()); // SecurityMode
    b.extend_from_slice(&sc.dialect.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    b.extend_from_slice(&[0x5c; 16]); // ServerGuid
    b.extend_from_slice(&(if sc.dialect > 0x0202 { LARGE_MTU } else { 0 }).to_le_bytes());
    for _ in 0..3 {
        b.extend_from_slice(&(1u32 << 20).to_le_bytes()); // MaxTransact/Read/WriteSize
    }
    b.extend_from_slice(&[0u8; 16]); // SystemTime, ServerStartTime
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    b.push(0);
    b
}

/// MS-SMB2 2.2.6, structure size 9, the security buffer right after the fixed part.
fn session_setup_body(blob: &[u8]) -> Vec<u8> {
    session_setup_flags(blob, 0)
}

fn session_setup_flags(blob: &[u8], session_flags: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes());
    b.extend_from_slice(&session_flags.to_le_bytes()); // SessionFlags
    b.extend_from_slice(&((proto::HEADER + 8) as u16).to_le_bytes());
    b.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    b.extend_from_slice(blob);
    if blob.is_empty() {
        b.push(0);
    }
    b
}

/// Eight bytes no two connections share: a process-wide counter, so two arms running at
/// once cannot collide either.
fn fresh_challenge() -> [u8; 8] {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    let n = NEXT.fetch_add(1, Ordering::SeqCst) as u64;
    (n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5c5c_5c5c_5c5c_5c5c).to_le_bytes()
}

/// An NTLMSSP CHALLENGE carrying `server_challenge` and a target info of only MsvAvEOL.
fn challenge(server_challenge: &[u8; 8]) -> Vec<u8> {
    let mut c = vec![0u8; 48];
    c[0..8].copy_from_slice(b"NTLMSSP\0");
    c[8..12].copy_from_slice(&2u32.to_le_bytes());
    c[16..20].copy_from_slice(&48u32.to_le_bytes()); // TargetName: empty, at 48
    c[20..24].copy_from_slice(&0x0008_8215u32.to_le_bytes());
    c[24..32].copy_from_slice(server_challenge);
    c[40..42].copy_from_slice(&4u16.to_le_bytes());
    c[42..44].copy_from_slice(&4u16.to_le_bytes());
    c[44..48].copy_from_slice(&48u32.to_le_bytes());
    c.extend_from_slice(&[0, 0, 0, 0]);
    c
}

/// MS-SMB2 2.2.10, structure size 16: a disk share.
fn tree_connect_body() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&16u16.to_le_bytes());
    b.push(1); // ShareType: disk
    b.push(0);
    b.extend_from_slice(&0u32.to_le_bytes()); // ShareFlags
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0x001f_01ffu32.to_le_bytes()); // MaximalAccess
    b
}

/// MS-SMB2 2.2.2, structure size 9.
fn error_body() -> Vec<u8> {
    vec![9, 0, 0, 0, 0, 0, 0, 0, 0]
}
