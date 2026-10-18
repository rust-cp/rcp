//! Connecting, negotiating a dialect, authenticating with NTLMv2 and connecting a tree.
//!
//! One request in flight at a time. SMB2 has credits and compounding and both are worth
//! having eventually, but a correct serial client is the thing to be sure of first, and
//! the read path gets its parallelism from rcp's own worker pool rather than from
//! pipelining inside one connection.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::ntlm;
use super::proto::{self, Cursor, Header};
use super::sign;

/// The largest single SMB2 message this client will read.
///
/// The length comes from the NetBIOS header, which the server writes, so it needs a cap
/// or a hostile server names 16 MB and gets it allocated before a single field is
/// checked. 8 MiB is far above any response these operations produce -- the biggest is a
/// READ, and reads are issued at 1 MiB.
const MAX_MESSAGE: usize = 8 << 20;

/// `SMB2_NEGOTIATE_SIGNING_REQUIRED` in a negotiate response's SecurityMode: the server
/// will not accept an unsigned request.
const SIGNING_REQUIRED: u16 = 0x0002;

/// `SMB2_NEGOTIATE_SIGNING_ENABLED`, which MS-SMB2 2.2.3 states the client MUST set.
///
/// 0 is not a legal value for the field, and the sort of thing that works everywhere
/// until it does not. ENABLED is a statement of CAPABILITY, not of intent:
/// a session only ends up signed when the SERVER requires it or when the client sets
/// SIGNING_REQUIRED (`-smb.sign`), which is the neighboring bit and is added only then.
///
/// It is NOT a fix for the handshake stall; tested as one, it measured 85 failures of
/// 3072 against a baseline's 70 of 3072. It is here on spec grounds alone, which is
/// worth saying so nobody reads it as the fix for that.
const SIGNING_ENABLED: u16 = 0x0001;

/// `SMB2_GLOBAL_CAP_LARGE_MTU` in a negotiate response's Capabilities.
///
/// **The credit window is this server's to offer, not the dialect's to imply.** MS-SMB2
/// 3.2.5.2 sets `Connection.SupportsMultiCredit` from a dialect above 0x0202 AND this bit;
/// 3.2.4.1.2 then says that when it is FALSE the client MUST send `CreditCharge` 0. A
/// dialect of 0x0210 or better is necessary and NOT sufficient.
///
/// Reading this field and discarding it, and deciding the charge from the dialect alone, is
/// the SAME mistake as a constant-0 charge, one layer up: right against every server
/// tested -- Samba advertises `0x00000007` here, measured -- and
/// wrong against a 0x0210 or 0x0300 server that does not advertise it, where a 64 KiB read
/// charges 2 and is refused with the same opaque `STATUS_INVALID_PARAMETER`.
const LARGE_MTU: u32 = 0x0000_0004;

/// How many STATUS_PENDING interim responses one request may collect before the client
/// calls it a hang. Each already costs a full socket read timeout, so this is a bound on a
/// pathological server rather than a tuning knob.
const MAX_INTERIM: u32 = 64;

/// Whether a reply is the server saying "still working", rather than an answer.
///
/// BOTH conditions, and the flag is the one that matters: `STATUS_PENDING` alone, without
/// `SMB2_FLAGS_ASYNC_COMMAND`, is not a valid interim response, and waiting for a follow-up
/// that a malformed server will never send is a hang. Checking only the status would turn a
/// broken server into an indefinite wait.
/// NetBIOS keep-alives tolerated while one reply is awaited. Real ones come minutes apart.
const MAX_KEEPALIVES: u32 = 8;

fn is_interim(reply: &proto::Reply) -> bool {
    reply.status == proto::STATUS_PENDING && reply.flags & proto::FLAGS_ASYNC_COMMAND != 0
}

/// How much of a file to ask for in one READ. Servers cap this at MaxReadSize, which the
/// NEGOTIATE response reports, so the effective size is the smaller of the two.
pub const READ_CHUNK: u32 = 1 << 20;

/// Credits this client ASKS FOR on every request.
///
/// Named because an arm needs to compare the largest I/O against it, and a test that
/// copies the number instead of reading it passes whatever this becomes. `credits` in the
/// header is a request, not a grant: the server decides, and `Conn::call` refuses a
/// request whose charge exceeds the balance actually granted. So this bounds what the
/// client asks for, never what it gets.
pub(crate) const CREDITS_REQUESTED: u16 = 64;

pub struct Conn {
    sock: TcpStream,
    pub(crate) next_id: u64,
    session_id: u64,
    pub dialect: u16,
    /// `Connection.SupportsMultiCredit` (MS-SMB2 3.2.5.2): whether this connection may
    /// charge more than one credit. Read from the server's Capabilities, not inferred.
    pub multi_credit: bool,
    /// Whether the server said it will not accept an unsigned request.
    pub signing_required: bool,
    /// Whether THIS client insists on signing, whatever the server says. See
    /// `Settings::requires_signing` in `client.rs`.
    pub(crate) require_signing: bool,
    /// The key every request after session setup is signed with, once there is a session.
    /// `None` until then, and `None` for a server that does not require signing.
    signing_key: Option<[u8; 16]>,
    /// The CreditCharge the most recent request carried ON THE WIRE.
    ///
    /// Recorded for ONE reason: the charge is computed here from what a call site passes,
    /// and both credit defects this adapter has had were in what the call site passed
    /// rather than in the formula. An arm that calls `credit_charge` directly cannot see
    /// that class of bug -- proven by replanting, it stays green -- so an arm needs to read
    /// back what a real request actually carried.
    ///
    /// **Read out of the sent frame, after the write succeeded.** A copy of the computed
    /// number, stored before the write, is not enough: with the header changed to carry
    /// `credit_charge: 0` -- the exact constant-zero defect this adapter shipped once --
    /// every arm stays green, including one that claims to read "what a real request
    /// actually carried". Storing it before the write also records requests that never
    /// left, and a request refused for want of credits leaves the PREVIOUS request's value
    /// behind.
    pub(crate) last_credit_charge: u16,
    /// The status the server gave the NTLMSSP AUTHENTICATE, if it gave one.
    ///
    /// This is what decides whether a failed handshake could contribute to an ACCOUNT
    /// LOCKOUT, and it cannot be recovered from the error afterwards. `None` with the
    /// credential sent means the server never said -- it hung up, or the read timed out --
    /// and that is the case no `io::ErrorKind` can separate from a lost race.
    /// `Some(STATUS_SUCCESS)` is what the reply SAID -- and on a signed session that is
    /// not yet evidence of anything, because the status arrives before the signature on it
    /// has been checked. See `credential_verified`.
    pub(crate) credential_answer: Option<u32>,
    /// Whether a `STATUS_SUCCESS` answer to the AUTHENTICATE survived every check this login
    /// makes -- on a signed session, the hand check of its signature.
    ///
    /// **Only this may give the credential budget back.** It is tempting to settle the budget
    /// from `credential_answer` alone, so that a signing fault after a real success is not
    /// reported as "check the password". That opens a hole: the status is read BEFORE the
    /// signature is checked, so an on-path forger can let each real `STATUS_LOGON_FAILURE`
    /// reach the domain controller and hand this client an unsigned `STATUS_SUCCESS` instead
    /// -- the budget resets every time and the password keeps going out, one bad-password
    /// count at a time. An unverifiable success therefore counts against the budget and is
    /// reported as what it is: an answer that could not be authenticated.
    pub(crate) credential_verified: bool,
    /// The server answered the AUTHENTICATE with `STATUS_SUCCESS` but marked the session as
    /// a GUEST or NULL session -- how a server configured to map bad passwords to guest
    /// (Samba's `map to guest = Bad Password`, for one) reports a credential it did NOT
    /// accept. Left unread, those flags let such a login reset the credential budget and then
    /// copy as guest. It is a rejection, and the budget counts it as one.
    pub(crate) credential_guest: bool,
    /// The AUTHENTICATE -- the credential -- was handed to the socket. Set immediately
    /// before the write, so a write that fails partway still counts: a partial frame may
    /// have been read. A caller bounding offers counts from this, not from its callback.
    pub(crate) credential_sent: bool,
    /// When the handshake must be over, whatever the reads in between do. `None` once the
    /// session's own timeout is set.
    ///
    /// **The handshake timeout is one deadline, not a per-READ timeout.** With a per-read
    /// timeout, a server answering the AUTHENTICATE one byte per interval never trips it,
    /// holds its budget slot indefinitely, and leaves every other worker for the account
    /// waiting in `reserve` -- whose wait is only "bounded, because every offer settles within
    /// the handshake deadline" if that deadline exists. So each read of the handshake is given
    /// what is LEFT of one deadline.
    deadline: Option<std::time::Instant>,
    /// The handshake's length, kept so the deadline can restart once a budget slot is held.
    fuse: Duration,
    /// An exchange went out and did not come back whole: set before a request is sent and
    /// cleared only when its complete, verified reply has been read. While it is set, the
    /// stream may hold the rest of a reply nobody will read -- after a data-path timeout
    /// mid-READ, say -- and the next request would take those bytes as its own answer.
    /// On an unsigned session they could come from FILE CONTENT, which frames as a reply as
    /// readily as anything else. So a broken connection refuses every later request without
    /// touching the socket, and the pool never takes it back.
    ///
    /// The message-id check in `call` is not a substitute. It is not a framing guard:
    /// misframed bytes that happen to carry the expected id pass it. And `SmbReader`/`SmbSink`
    /// send a CLOSE on the same connection after a failed read or write, which without this
    /// flag would go out before anything checked.
    pub(crate) broken: bool,
    /// What the server has granted and this client has not yet spent.
    ///
    /// **Why track it.** A client that asks for credits on every request and never reads
    /// what comes back can send a request charging more than it holds and learn about it
    /// only as `STATUS_INVALID_PARAMETER` -- a status that says nothing about credits, on the
    /// same wire as half a dozen other causes. Keeping the balance turns that into a
    /// sentence naming the number.
    ///
    /// It is a diagnostic, not a throttle: this client issues one request at a time, spends
    /// each request's charge from the balance before sending it, and asks for at least that
    /// much back, so in normal operation the balance never runs short. The value of holding
    /// it is that when it does, the error says so. (The balance is decremented, in `call`;
    /// it does not only grow.)
    credits: u16,
    pub max_read: u32,
    pub max_write: u32,
    pub server: String,
}

/// The largest charge any request on THIS THREAD has carried since the last call. Test
/// builds only, and thread-local so arms running in parallel cannot see each other's.
///
/// `last_credit_charge` answers for one request an arm issues by hand. This answers for the
/// requests the PRODUCTION paths issue -- a sink writing a file, a reader reading one --
/// which chunk by `min(max_write, WRITE_CHUNK_CAP)` and `min(max_read, READ_CHUNK)` and hand
/// the arm no connection to look at.
#[cfg(test)]
pub(crate) fn take_largest_charge() -> u16 {
    LARGEST_CHARGE.with(|c| c.replace(0))
}

#[cfg(test)]
thread_local! {
    static LARGEST_CHARGE: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

impl Conn {
    /// Opens the socket and negotiates a dialect. No credentials are sent here.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> io::Result<Conn> {
        Conn::connect_requiring(host, port, timeout, false)
    }

    /// `connect`, for a client that insists on signing. Decided here rather than at login
    /// because the NEGOTIATE request carries the client's SecurityMode too.
    pub(crate) fn connect_requiring(
        host: &str,
        port: u16,
        timeout: Duration,
        require_signing: bool,
    ) -> io::Result<Conn> {
        let addr = format!("{host}:{port}");
        let sock = std::net::ToSocketAddrs::to_socket_addrs(&addr)
            .map_err(|e| io::Error::new(e.kind(), format!("{addr}: {e}")))?
            .next()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{addr}: no address"))
            })?;
        let sock = TcpStream::connect_timeout(&sock, timeout)
            .map_err(|e| io::Error::new(e.kind(), format!("{addr}: {e}")))?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;
        sock.set_nodelay(true)?;
        let mut c = Conn {
            sock,
            next_id: 0,
            session_id: 0,
            dialect: 0,
            multi_credit: false,
            signing_required: false,
            require_signing,
            signing_key: None,
            last_credit_charge: 0,
            credential_answer: None,
            credential_verified: false,
            credential_guest: false,
            credential_sent: false,
            deadline: Some(std::time::Instant::now() + timeout),
            fuse: timeout,
            broken: false,
            credits: 0,
            max_read: READ_CHUNK,
            max_write: READ_CHUNK,
            server: host.to_string(),
        };
        c.negotiate()?;
        Ok(c)
    }

    /// The SecurityMode this client sends. ENABLED always -- MS-SMB2 2.2.3 makes it a MUST --
    /// and REQUIRED only when this client insists, since per 3.2.4.1.3 that bit mirrors the
    /// client's own RequireMessageSigning.
    fn security_mode(&self) -> u16 {
        SIGNING_ENABLED
            | if self.require_signing {
                SIGNING_REQUIRED
            } else {
                0
            }
    }

    /// Re-arms the socket deadline. The handshake runs on a short fuse and the session's
    /// own operations on the full one; see `HANDSHAKE_TIMEOUT` in `client.rs`.
    /// A connection already set up, over a socket to a test peer that plays the server
    /// by hand: dialect 2.1, unsigned, one credit, no deadline.
    #[cfg(test)]
    pub(crate) fn over(sock: TcpStream) -> Conn {
        Conn {
            sock,
            next_id: 0,
            session_id: 0,
            dialect: 0x0210,
            multi_credit: false,
            signing_required: false,
            require_signing: false,
            signing_key: None,
            last_credit_charge: 0,
            credential_answer: None,
            credential_verified: false,
            credential_guest: false,
            credential_sent: false,
            deadline: None,
            fuse: Duration::from_secs(2),
            broken: false,
            credits: 1,
            max_read: READ_CHUNK,
            max_write: READ_CHUNK,
            server: "peer".to_string(),
        }
    }

    pub(crate) fn set_timeout(&mut self, d: Duration) -> io::Result<()> {
        self.deadline = None;
        self.sock.set_read_timeout(Some(d))?;
        self.sock.set_write_timeout(Some(d))?;
        Ok(())
    }

    /// Arms an ABSOLUTE deadline of `d` from now, so `read_by_deadline`/`write_by_deadline`
    /// bound the whole of the next exchange -- not each syscall.
    ///
    /// `set_timeout` clears `self.deadline` and installs only a per-syscall socket timeout,
    /// which a peer trickling one byte just inside that timeout outlasts forever. That is
    /// fine for the data path, whose reads are legitimately long and hold no budget slot, but
    /// not for the `TREE_CONNECT` after a login: under `set_timeout(handshake)` the deadline
    /// is cleared, so a trickled tree connect hangs the worker. It holds no budget slot, but
    /// it is a small fixed exchange that should not hang, so it gets an absolute deadline of
    /// its own. The socket timeouts are set too, so a first read before `within_deadline`
    /// runs is still bounded.
    pub(crate) fn arm_deadline(&mut self, d: Duration) -> io::Result<()> {
        self.sock.set_read_timeout(Some(d))?;
        self.sock.set_write_timeout(Some(d))?;
        self.deadline = Some(std::time::Instant::now() + d);
        Ok(())
    }

    /// One request, one response. Returns the header fields and the whole message, since
    /// every variable-length field in SMB2 is addressed from the start of the header.
    ///
    /// `send_payload` and `expect_payload` are the two sizes MS-SMB2 3.1.5.2 computes the
    /// credit charge from. Both are PAYLOAD sizes -- "the size of the data within the
    /// variable-length field", in the spec's own words -- and NOT the size of the message
    /// that carries them. Only the caller knows them: a READ sends 113 bytes and gets a
    /// megabyte back. Everything that is not a READ, WRITE, IOCTL or QUERY_DIRECTORY passes
    /// 0 for both, which lands on a charge of 1, which is what 3.2.4.1.5 requires of every
    /// other command regardless of how big it is.
    fn call(
        &mut self,
        command: u16,
        tree_id: u32,
        body: &[u8],
        send_payload: u32,
        expect_payload: u32,
    ) -> io::Result<(proto::Reply, Vec<u8>)> {
        if self.broken {
            return Err(io::Error::other(
                format!(
                    "{}: an earlier exchange on this connection failed partway, so the stream may be out of step \
                     with its requests; not sending another on it",
                    self.server
                ),
            ));
        }
        let charge = proto::credit_charge(
            self.multi_credit,
            send_payload as usize,
            expect_payload as usize,
        );
        // A client may always send ONE request -- that is what keeps a connection from
        // deadlocking at a balance of zero. This is not a free request the spec grants; it
        // is that a balance of zero HERE can only be this client under-counting, because
        // MS-SMB2 3.3.1.2 requires the server to ensure "the number of credits held by the
        // client is never reduced to zero" (text checked on learn.microsoft.com, 2026-09-27),
        // and this client caps what it counts (below). A
        // one-credit request at a counted zero is therefore inside the server's real window.
        // Anything above one credit has to be covered by
        // what the server has granted. Refusing here names the quantity; sending anyway
        // gets `STATUS_INVALID_PARAMETER` from the server and names nothing.
        if charge > 1 && charge > self.credits {
            return Err(io::Error::other(format!(
                "{}: this request needs {charge} credits and the server has granted {}. \
                     The transfer size is larger than the window this connection was given",
                self.server, self.credits
            )));
        }
        // A zero charge -- every request on a 2.0.2 connection, which has no multi-credit --
        // still spends ONE credit. The message id below already counted it that way; the
        // balance did not, and gained a credit per request it never had.
        self.credits = self.credits.saturating_sub(charge.max(1));
        let message_id = self.next_id;
        // NOT `+= 1`. A request charging N credits consumes the id range `message_id ..
        // message_id + N`; starting the next request inside that range re-uses ids the
        // server has retired, and both Samba and Windows refuse it.
        self.next_id += charge.max(1) as u64;
        // Ask back for at least what this request spends, so a run of large transfers does
        // not drain the window.
        //
        // **This does NOT make a large request safe on its own**, though it is tempting to
        // read it that way. CreditRequest is granted on the RESPONSE, so it
        // cannot pay for the message carrying it: a request whose charge exceeds the
        // credits already granted is refused whatever it asks for. What keeps that from
        // happening is the cap on how much I/O this client issues at once -- 1 MiB for both
        // reads and writes, charge 17 -- against the 64 it holds. `the_largest_io_this_
        // client_issues_fits_in_the_credit_window_it_asks_for` in `client.rs` is what
        // fails if either cap is raised past that point.
        let asked = charge.max(CREDITS_REQUESTED);
        let header = Header {
            command,
            message_id,
            session_id: self.session_id,
            tree_id,
            credits: asked,
            credit_charge: charge,
        };
        let mut msg = header.bytes();
        msg.extend_from_slice(body);
        // SIGN, if this connection has a key. The flag goes in BEFORE the signature is
        // computed, because the flag is one of the bytes being signed -- get that order
        // wrong and the server answers STATUS_ACCESS_DENIED, which reads exactly like a
        // bad password and sends you to look at the credential.
        if let Some(key) = self.signing_key {
            let flags =
                u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) | proto::FLAGS_SIGNED;
            msg[16..20].copy_from_slice(&flags.to_le_bytes());
            let sig = sign::sign(&msg, &key, self.dialect);
            msg[48..64].copy_from_slice(&sig);
        }

        // NetBIOS session service: one zero byte then a 24-bit big-endian length
        let mut frame = Vec::with_capacity(4 + msg.len());
        frame.push(0);
        let n = msg.len();
        frame.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        frame.extend_from_slice(&msg);
        // From here until the reply is read whole and verified, any early return leaves the
        // stream mid-exchange.
        self.broken = true;
        self.write_by_deadline(&frame)?;
        // What went out, from the bytes that went out: header offset 6, after the four-byte
        // NetBIOS prefix.
        self.last_credit_charge = u16::from_le_bytes([frame[4 + 6], frame[4 + 7]]);
        #[cfg(test)]
        LARGEST_CHARGE.with(|c| c.set(c.get().max(self.last_credit_charge)));

        // AN INTERIM RESPONSE IS NOT AN ANSWER. A server that needs longer than its timer
        // allows replies STATUS_PENDING with SMB2_FLAGS_ASYNC_COMMAND set and sends the real
        // response later under the SAME message id (MS-SMB2 3.3.4.2). Reading one message
        // and returning it treated that as a failure, so the client gave up on a request the
        // server was still working on -- and the caller got `SMB status 0x00000103`, which
        // names nothing a person can act on.
        //
        // This never happens on the stand-in, which is synchronous. It is ordinary against a
        // real share: a CREATE on a file another client holds with an oplock, a delete on a
        // large directory, a read that has to be recalled from tiered storage. So the case
        // that matters most on a Windows server is exactly the one no test here produces,
        // and the fix is written from the spec with the arm below checking the decision
        // rather than a round trip.
        let mut interim = 0u32;
        let mut keepalives = 0u32;
        // Credits every reply to THIS request has granted, interim ones included.
        let mut granted = 0u16;
        loop {
            let mut nb = [0u8; 4];
            self.read_by_deadline(&mut nb)?;
            // The NetBIOS type byte (RFC 1002 4.3.1). A session KEEP ALIVE (0x85, empty) may
            // arrive while a reply is awaited, and treating its zero length as a short SMB2
            // message would kill the connection -- so it is skipped, but only so many per
            // request, or a peer sending nothing else would hold the worker. Any other
            // non-zero type is not a session message this client can read.
            if nb == [0x85, 0, 0, 0] {
                keepalives += 1;
                if keepalives > MAX_KEEPALIVES {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("the server sent {keepalives} keep-alives to one request and never the answer"),
                    ));
                }
                continue;
            }
            if nb[0] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "NetBIOS frame type 0x{:02x} where a session message was expected",
                        nb[0]
                    ),
                ));
            }
            let len = ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize;
            if len < proto::HEADER {
                return Err(proto::short(&format!(
                    "a {len}-byte message, shorter than an SMB2 header"
                )));
            }
            if len > MAX_MESSAGE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the server announced a {len}-byte message; the cap is {MAX_MESSAGE}"),
                ));
            }
            let mut buf = vec![0u8; len];
            self.read_by_deadline(&mut buf)?;
            let reply = proto::parse_header(&buf)?;
            // A RESPONSE, not a request. Nothing else here tells them apart: a request echoed
            // back has this request's id and command, a zero Status that reads as
            // STATUS_SUCCESS, and -- SMB2 and SMB3 sign both directions with one key -- a
            // signature that verifies, because this client computed it. Without the bit, that
            // reflection would clear `broken` with the real reply still unread.
            if reply.flags & proto::FLAGS_SERVER_TO_REDIR == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: a message without the response flag came back where a reply was expected -- a request, reflected or misrouted", self.server),
                ));
            }
            if reply.message_id != message_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the server answered message {} to request {message_id}",
                        reply.message_id
                    ),
                ));
            }
            // And for the command asked. A reply with the right id but another command is not
            // this request's answer -- that one may still be on its way -- so the connection
            // stays broken. Checking only the id would let such a reply clear `broken`, and a
            // caller's parse failure would then leave a desynced stream looking usable.
            if reply.command != command {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the server answered command 0x{:04x} to a 0x{command:04x} request",
                        reply.command
                    ),
                ));
            }
            // Every reply grants, including an interim one -- which in current Samba
            // grants zero, and is one of the documented ways to arrive at an empty window.
            //
            // **Capped at what this request ASKED for, because an interim reply cannot be
            // authenticated.** Banked uncapped from an unsigned STATUS_PENDING on a signed
            // session, the grant would let an on-path party inject one granting 65535 and
            // leave the client sending requests the server's real window does not cover.
            // Ignoring interim grants is not the answer -- a server may grant in the interim
            // and not in the final response, and the window would drain -- and verifying the
            // final reply says nothing about the interim before it. The cap bounds what ONE
            // request's injected interim can add to what a server honoring the request would
            // grant anyway. **Per request, not in aggregate**: an injection repeated on every
            // request still walks the balance above the server's real window, up to 64 a
            // time. What that buys is a request the server refuses as over its window -- a
            // failed connection, which an on-path party could cause more simply by dropping
            // it. A server that grants more than asked is under-counted, which only makes the
            // pre-send check stricter.
            granted = granted.saturating_add(reply.credits_granted);
            if !is_interim(&reply) {
                self.check_signature(&buf, &reply)?;
                self.credits = self.credits.saturating_add(granted.min(asked));
                self.broken = false;
                return Ok((reply, buf));
            }
            // BOUNDED, because "wait for the next one" with no limit is a hang. The socket
            // read timeout already bounds each wait; this bounds how many a server may ask
            // for, so one that only ever answers PENDING is refused by name instead of
            // holding a worker forever.
            interim += 1;
            if interim > MAX_INTERIM {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the server sent {interim} interim responses to one request and never the answer"),
                ));
            }
        }
    }

    /// Refuses a reply this session cannot authenticate.
    ///
    /// Two failures, and the second is the one that is easy to leave out. A reply whose
    /// signature does NOT reproduce is a tampered or misrouted message. A reply carrying NO
    /// signature at all, on a session that requires signing, is the same attack with the
    /// flag cleared -- and a client that only checks signatures it is offered accepts it
    /// happily, having implemented signing and gained nothing.
    ///
    /// Scoped to sessions with a key, which is exactly the set MS-SMB2 3.2.5.1.3 scopes it
    /// to. Before the key is armed there is nothing to verify with, and the messages in
    /// that window -- NEGOTIATE and the two SESSION_SETUPs -- are unsigned by definition.
    /// Interim `STATUS_PENDING` responses never reach here: the caller loops on them.
    fn check_signature(&self, msg: &[u8], reply: &proto::Reply) -> io::Result<()> {
        let Some(key) = self.signing_key else {
            return Ok(());
        };
        let signed = reply.flags & proto::FLAGS_SIGNED != 0;
        // AN UNSIGNED FAILURE IS NAMED BY THE STATUS IT CLAIMS -- BUT CARRIES NO MEANING.
        // Real servers do send these, so reporting one as tampering would send the operator
        // hunting for an attacker when a server had, say, expired the session and could not
        // sign with a key it no longer holds. So the message names the status.
        //
        // **The error KIND is not the status's.** It is tempting to think trusting the status
        // "costs nothing: the worst a forger gets is to choose which error this request fails
        // with, which it could do anyway by dropping the connection." The equivalence is
        // false. Dropping gives a transport error. A chosen status gives a MEANING:
        // `status_error` maps OBJECT_NAME_NOT_FOUND to `NotFound`, and `SmbTree::stat` reads
        // `NotFound` as "this file is absent" -- which a sync's removal step acts on. A forger
        // could turn "present" into "absent" on the one kind of session that exists to prevent
        // that. `Other` is a kind no caller branches on.
        if !signed && reply.status != proto::STATUS_SUCCESS {
            return Err(io::Error::other(
                format!(
                    "{}: {} (the reply was unsigned on a signed session, so this status is the server's word only, \
                     and is not acted on)",
                    self.server,
                    proto::status_text(reply.status)
                ),
            ));
        }
        if !signed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: the server answered without a signature on a session that requires signing. \
                     A reply that simply clears the flag is the same tampering as a bad signature",
                    self.server
                ),
            ));
        }
        if !sign::verify(msg, &key, self.dialect) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: the server's signature on its reply does not verify. \
                     The reply was altered in transit, or it did not come from the server this session authenticated to",
                    self.server
                ),
            ));
        }
        Ok(())
    }

    /// The same, refusing any status but success. `expect_more` allows the one status that
    /// is a normal step rather than a failure: session setup's continuation.
    fn call_ok(
        &mut self,
        command: u16,
        tree_id: u32,
        body: &[u8],
        what: &str,
    ) -> io::Result<Vec<u8>> {
        let (reply, buf) = self.call(command, tree_id, body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        Ok(buf)
    }

    fn negotiate(&mut self) -> io::Result<()> {
        // 0x0202, 0x0210, 0x0300 -- deliberately NOT 0x0311, which requires the
        // negotiate-context preauth integrity hash this client does not compute. Signing,
        // which it does, is a separate matter: it is required by SERVERS, not by 0x0311.
        let dialects: [u16; 3] = [0x0202, 0x0210, 0x0300];
        let mut body = Vec::new();
        body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
        body.extend_from_slice(&self.security_mode().to_le_bytes()); // SecurityMode, per MS-SMB2 2.2.3
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        body.extend_from_slice(&[0u8; 16]); // ClientGuid
        body.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
        for d in dialects {
            body.extend_from_slice(&d.to_le_bytes());
        }
        let buf = self.call_ok(proto::NEGOTIATE, 0, &body, "negotiating a dialect")?;

        let mut c = Cursor::new(&buf);
        c.seek(proto::HEADER)?;
        let size = c.u16("the negotiate response size")?;
        if size != 65 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a negotiate response of structure size {size}, not 65"),
            ));
        }
        let security_mode = c.u16("the security mode")?;
        // THIS BIT ARMS SIGNING, and the reasoning behind that is what decides where this
        // client works.
        //
        // The dialect list above says 0x0311 is skipped because it needs preauth integrity
        // AND signing, which could be read as implying signing is a 3.1.1 cost. It is not.
        // Message signing has been in SMB2 since 0x0202, and it is the SERVER that decides:
        // Windows 11 24H2 and Windows Server 2025 require it by DEFAULT, as does a Samba
        // configured `server signing = mandatory`, which is usual for a domain member. That
        // is why refusing here would exclude most current deployments, and why signing is
        // implemented rather than documented as a limit.
        //
        // When the bit is CLEAR the client does not sign, and that is not laziness: an
        // unsigned message skips a CMAC over every byte of every request.
        self.signing_required = security_mode & SIGNING_REQUIRED != 0;
        self.dialect = c.u16("the dialect")?;
        if !dialects.contains(&self.dialect) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the server chose dialect 0x{:04x}, which was not offered",
                    self.dialect
                ),
            ));
        }
        c.u16("the negotiate context count")?;
        c.take(16, "the server guid")?;
        let capabilities = c.u32("the capabilities")?;
        // KEPT, not discarded. See LARGE_MTU.
        self.multi_credit = self.dialect > 0x0202 && capabilities & LARGE_MTU != 0;
        // MS-SMB2 2.2.4 order: MaxTransactSize, MaxReadSize, MaxWriteSize. The first is
        // read and discarded because no operation here is a transaction -- and it is NAMED,
        // because `Cursor`'s whole purpose is that a truncated response says which field ran
        // out. Reading it as "MaxReadSize" into `max_read` and then overwriting that gives
        // the right result while making both the diagnostic and the code misleading.
        c.u32("MaxTransactSize")?;
        self.max_read = c.u32("MaxReadSize")?.max(64 << 10);
        self.max_write = c.u32("MaxWriteSize")?.max(64 << 10);
        Ok(())
    }

    /// NTLMv2 session setup: NEGOTIATE out, CHALLENGE back, AUTHENTICATE out.
    ///
    /// The security buffer carries raw NTLMSSP rather than a SPNEGO wrapper. That is what
    /// this is tested against and it is what Samba and impacket accept; a Windows server
    /// that insists on SPNEGO will refuse, and saying so here is better than implying a
    /// coverage this has not got.
    #[cfg(test)]
    pub fn login(&mut self, user: &str, password: &str, domain: &str) -> io::Result<()> {
        self.login_offering(user, password, domain, &mut || Ok(()))
    }

    /// `write_all`, but with the handshake deadline re-applied before every `send` -- the
    /// same defect as the read side, one direction over: a peer that opens its receive
    /// window a few bytes at a time keeps each `send` inside its own timeout, so `write_all`
    /// loops as long as the peer likes while holding a budget slot.
    fn write_by_deadline(&mut self, buf: &[u8]) -> io::Result<()> {
        write_by_deadline(&mut self.sock, buf, self.deadline, &self.server)
    }

    /// `read_exact`, but with the handshake deadline re-applied before EVERY `recv`.
    ///
    /// Setting it once per message is not enough, and the arm for this measures that at
    /// 7.7 s against a 1 s deadline: the socket timeout bounds each `recv`, and `read_exact`
    /// loops over as many as a server cares to cause, so a message sent a byte at a time
    /// outlives the deadline by as many bytes as it has.
    fn read_by_deadline(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if self.deadline.is_none() {
            // Data path: no absolute deadline (a large read is legitimately long), the socket's
            // own `SO_RCVTIMEO` from `set_timeout(TIMEOUT)` is the only bound. `read_exact`
            // would surface a timed-out recv as the raw `WouldBlock`/`EAGAIN` Linux returns,
            // which a caller matching on `TimedOut` misreads. Map it.
            return read_exact_or_timeout(&mut self.sock, buf, &self.server);
        }
        let mut at = 0;
        while at < buf.len() {
            self.within_deadline()?;
            match self.sock.read(&mut buf[at..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection mid-message",
                    ))
                }
                Ok(n) => at += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // As on the write side: a recv that hit the per-syscall timeout returns
                // `WouldBlock`, not `TimedOut`. Loop back so `within_deadline` above reports
                // the deadline as `TimedOut` once it has actually elapsed.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Gives the next read whatever is left of the handshake deadline, or refuses it if none is.
    fn within_deadline(&self) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{}: the handshake ran past its deadline", self.server),
            ));
        }
        // never below a millisecond: a sub-microsecond remainder must not round to the zero
        // timeval that means "no timeout at all"
        self.sock
            .set_read_timeout(Some(left.max(Duration::from_millis(1))))
    }

    /// Whether the server has closed this connection, or left bytes on it nobody asked for,
    /// without blocking: a zero-length peek is the FIN. Either way the connection is not one
    /// to send a credential on.
    fn closed_by_peer(&self) -> io::Result<bool> {
        self.sock.set_nonblocking(true)?;
        let mut b = [0u8; 1];
        let seen = loop {
            match self.sock.peek(&mut b) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        };
        // Blocking is restored BEFORE the verdict, so an error restoring it cannot leave a
        // socket non-blocking behind an early return -- whatever this function concludes.
        self.sock.set_nonblocking(false)?;
        match seen {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Ok(_) => Ok(true),
            Err(_) => Ok(true),
        }
    }

    /// `login`, calling `offer` once the credential is ready to go on the wire.
    ///
    /// `offer` runs once the challenge is in hand and the AUTHENTICATE is built: before it,
    /// nothing sent carried a credential -- NEGOTIATE and the first SESSION_SETUP -- so a
    /// failure up to here could not lock anything out. It is where the pool takes its
    /// budget slot, and it may WAIT there. An error from `offer` is returned before anything
    /// is sent. Whether the credential then actually went out is `credential_sent`.
    ///
    /// **After `offer`, the connection is checked before the credential is written.** A
    /// worker can wait in `offer` for the logins ahead of it, holding this connection with
    /// the server's challenge issued; a server that gave up on it meanwhile has closed the
    /// socket, and writing the AUTHENTICATE into a closed socket reads back as "no answer",
    /// which the budget must count. The check turns that case into an uncounted failure.
    /// It cannot see a server that forgot the exchange but kept the socket open.
    pub(crate) fn login_offering(
        &mut self,
        user: &str,
        password: &str,
        domain: &str,
        offer: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let negotiate = ntlmssp_negotiate(domain);
        let (reply, buf) = self.call(
            proto::SESSION_SETUP,
            0,
            &session_setup_body(&negotiate, self.security_mode()),
            0,
            0,
        )?;
        if reply.status != proto::STATUS_MORE_PROCESSING_REQUIRED
            && reply.status != proto::STATUS_SUCCESS
        {
            return Err(login_error(reply.status, "starting session setup"));
        }
        self.session_id = reply.session_id;
        let challenge_blob = security_buffer_of(&buf)?;
        let (server_challenge, target_info) = ntlmssp_challenge(challenge_blob)?;

        let (authenticate, session_key) =
            ntlmssp_authenticate(user, password, domain, &server_challenge, &target_info)?;
        // THE FINAL SESSION SETUP GOES OUT UNSIGNED, and the key is armed from the response.
        // The order matters and the tempting order is wrong.
        //
        // MS-SMB2 3.2.4.1.1 conditions signing on `Session.SessionKey` being non-empty, and
        // it is easy to read that as covering this request, since the client can derive the
        // key from the blob it is about to send. It does not: for an initial (non-binding)
        // authentication the session key only exists on the server once THIS request's
        // NTLMSSP AUTHENTICATE has been processed, so a signature on it is one the server
        // cannot yet check.
        //
        // Measured, against a Samba with `server signing = mandatory`: signing this request
        // got `NT_STATUS_INVALID_HANDLE` and a dropped connection, and the server's own log
        // read `smb2_signing_sign_pdu: No signing key for SMB2 signing` -- it could not even
        // sign the error it was sending back. From this side that surfaced as "failed to
        // fill whole buffer", which names nothing at all. Sending it unsigned and arming
        // from the response is what that server accepts; whether Windows would refuse the
        // signed form too is not measured.
        offer()?;
        if self.closed_by_peer()? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: the server closed the connection, or sent something unasked, before the credential was sent; \
                     nothing was offered",
                    self.server
                ),
            ));
        }
        // The clock restarts HERE, where the budget slot is held: it bounds how long an offer
        // can be in flight, which is what the workers queued in `reserve` are waiting on. Left
        // running from the dial, a worker that queued past it would send its credential and
        // time out on the answer at once -- spending the budget on a wait of its own.
        self.deadline = Some(std::time::Instant::now() + self.fuse);
        self.credential_sent = true;
        let (reply, buf) = self.call(
            proto::SESSION_SETUP,
            0,
            &session_setup_body(&authenticate, self.security_mode()),
            0,
            0,
        )?;
        self.credential_answer = Some(reply.status);
        // THE STATUS COMES FIRST, before the signing key is derived. On an unsupported
        // dialect the derivation below returns `Unsupported`, and with the check after it a
        // server that had actually answered ACCESS_DENIED, LOGON_FAILURE or an account
        // verdict would be reported as "this client does not implement the KDF" -- the wrong
        // cause. The budget settles correctly either way (it reads `credential_answer`), but
        // the first visible error would name the client's gap, not the server's answer. A
        // non-success reply needs no key: nothing below it verifies a signature.
        if reply.status != proto::STATUS_SUCCESS {
            return Err(login_error(
                reply.status,
                &format!("authenticating as {user:?}"),
            ));
        }
        if self.signing_required || self.require_signing {
            // None means this code does not know how to derive a key for the negotiated
            // dialect. Refusing here is the whole value of `signing_key` returning an
            // Option: the alternative is signing with a wrong key, which the server
            // rejects as STATUS_ACCESS_DENIED and which reads exactly like a bad password.
            let Some(key) = sign::signing_key(&session_key, self.dialect) else {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "{}: the server requires signing on dialect 0x{:04x}, and this client does not implement \
                         that dialect's key derivation. Refusing rather than signing with a key the server cannot reproduce",
                        self.server, self.dialect
                    ),
                ));
            };
            self.signing_key = Some(key);
        }
        // SessionFlags (MS-SMB2 2.2.6): IS_GUEST 0x0001, IS_NULL 0x0002. A guest session for a
        // named user is the server saying no without saying STATUS_LOGON_FAILURE; an anonymous
        // login (no user) asked for exactly that and is left alone.
        let session_flags = u16::from_le_bytes([
            *buf.get(proto::HEADER + 2)
                .ok_or_else(|| proto::short("the session flags"))?,
            *buf.get(proto::HEADER + 3)
                .ok_or_else(|| proto::short("the session flags"))?,
        ]);
        if session_flags & (SESSION_FLAG_IS_GUEST | SESSION_FLAG_IS_NULL) != 0 && !user.is_empty() {
            self.credential_guest = true;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: the answer accepted {user:?} only as a guest session (session flags 0x{session_flags:04x}), \
                     which is how a server that maps bad passwords to guest rejects a credential. It cannot be \
                     authenticated -- a server has no key to sign a guest session with -- so it may also be forged. \
                     Refusing rather than copying with a guest's rights",
                    self.server
                ),
            ));
        }
        // AND VERIFY THIS ONE BY HAND. It cannot be done inside `call`, which returned
        // before there was a key.
        //
        // The server signs this response (MS-SMB2 3.3.5.5.3) with the key it derived from
        // the authentication that just succeeded, so a signature that verifies proves the
        // far end holds THIS session's key: both ends derived it from the same exchange. It does
        // NOT prove WHICH server that is -- NTLM here has no channel binding, so a relay that
        // forwards every byte to some other server accepting the same credential produces a
        // session that verifies. And the dialect it catches is an edit of the server's CHOICE,
        // in the reply; a downgrade made by striking dialects from this client's request
        // leaves both ends agreeing on the weaker one, and verifies.
        //
        // **What it does NOT do is defend against a signing downgrade.** It is tempting to
        // read this check as closing one; it cannot. Signing is armed from the SecurityMode
        // bit of the NEGOTIATE response, which arrives before any session exists and cannot
        // be authenticated. An attacker who clears that bit also stops `signing_key` from
        // being armed, so this check never runs -- the client has no expectation of its own
        // to hold the server to, UNLESS the caller asked for one: `-smb.sign`
        // (`require_signing`) arms the key whatever the bit says, and the branch below
        // refuses an unsigned answer. Without it the downgrade is open, and the README says
        // so. Nor does this signature cover the negotiate's other fields -- capabilities,
        // sizes -- which only 3.1.1's preauth integrity hash does, and
        // `FSCTL_VALIDATE_NEGOTIATE_INFO` (3.2.5.5), the 3.0 answer, is not implemented.
        if let Some(key) = self.signing_key {
            // The one case this client can now name exactly: it asked for a signed session,
            // the server's negotiate response did not require one, and the answer came back
            // unsigned. Either the server does not sign at all, or the negotiate response
            // was edited on the way -- and from here those are the same refusal.
            if reply.flags & proto::FLAGS_SIGNED == 0 && !self.signing_required {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: signing is required by this client (-smb.sign) and the server's session setup response \
                         was not signed. Either the server does not sign, or its negotiate response was altered to \
                         clear the bit that asks for signing",
                        self.server
                    ),
                ));
            }
            if reply.flags & proto::FLAGS_SIGNED == 0 || !sign::verify(&buf, &key, self.dialect) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: the session setup succeeded but its response is not correctly signed. \
                         The far end does not hold the key this authentication derived: the negotiate \
                         exchange was altered, or the answer came from something that never checked the password",
                        self.server
                    ),
                ));
            }
        }
        // Past every check: on a signed session the signature verified, and on an unsigned
        // one there is nothing more this side can check.
        //
        // **On an unsigned session that includes a FORGED success, and it resets this
        // credential's budget.** Four review rounds raised it; it is left open, on purpose,
        // for this reason: the party able to rewrite a LOGON_FAILURE into a SUCCESS is on the
        // path to the server, and can lock the account out without this client -- an
        // AUTHENTICATE with any wrong password for the user name, sent on its own connection,
        // counts toward the lockout as surely as one of ours. The budget bounds what THIS
        // client offers; against that party it bounds nothing either way. `-smb.sign` is what
        // makes a success authenticated, and under it an unsigned success settles `Unverified`.
        self.credential_verified = true;
        self.session_id = reply.session_id;
        Ok(())
    }

    /// Connects a share and returns its tree id.
    pub fn tree_connect(&mut self, share: &str) -> io::Result<u32> {
        let path = format!("\\\\{}\\{}", self.server, share);
        let name = ntlm::utf16le(&path);
        let mut body = Vec::new();
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&((proto::HEADER + 8) as u16).to_le_bytes()); // PathOffset
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&name);
        let (reply, buf) = self.call(proto::TREE_CONNECT, 0, &body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(
                reply.status,
                &format!("connecting the share {share:?}"),
            ));
        }
        let _ = buf;
        Ok(reply.tree_id)
    }

    pub fn tree_disconnect(&mut self, tree_id: u32) -> io::Result<()> {
        let body = [4u8, 0, 0, 0];
        self.call_ok(
            proto::TREE_DISCONNECT,
            tree_id,
            &body,
            "disconnecting the share",
        )?;
        Ok(())
    }

    pub fn logoff(&mut self) -> io::Result<()> {
        let body = [4u8, 0, 0, 0];
        self.call_ok(proto::LOGOFF, 0, &body, "logging off")?;
        self.session_id = 0;
        Ok(())
    }

    /// Exposed for the operations in `client.rs`, which build their own bodies.
    pub(crate) fn request(
        &mut self,
        command: u16,
        tree_id: u32,
        body: &[u8],
        send_payload: u32,
        expect_payload: u32,
    ) -> io::Result<(proto::Reply, Vec<u8>)> {
        self.call(command, tree_id, body, send_payload, expect_payload)
    }
}

/// `read_exact`, but a recv that hits the socket's `SO_RCVTIMEO` is reported as `TimedOut`
/// rather than the raw `WouldBlock`/`EAGAIN` Linux returns. For the DATA path, which sets a
/// per-syscall socket timeout (`set_timeout(TIMEOUT)`) but no absolute deadline: one timed-out
/// recv there means the server stalled for the whole timeout, which is a genuine stall, so it
/// settles as `TimedOut` (not retried -- retrying would grant another whole timeout, unbounded).
/// `EINTR` is retried. The `WouldBlock` arm is load-bearing on Linux: a probe on this
/// container (rustc 1.94) read `WouldBlock`, errno 11, from both a timed-out recv and a
/// timed-out send, and removing the send side's arm fails
/// `a_data_path_send_that_stalls_reads_as_timed_out`. (It is tempting to assume this host
/// returns `TimedOut` natively and the arm cannot be tested here; the probe shows otherwise.)
fn read_exact_or_timeout(sock: &mut TcpStream, buf: &mut [u8], server: &str) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        match sock.read(&mut buf[at..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the server closed the connection mid-message",
                ))
            }
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{server}: the server stalled past the socket timeout while reading"),
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `write_all`, with the same `SO_SNDTIMEO`-timeout-to-`TimedOut` normalization as
/// [`read_exact_or_timeout`], for the data path.
fn write_all_or_timeout(sock: &mut TcpStream, buf: &[u8], server: &str) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        #[cfg(windows)]
        let end = (at + 64 * 1024).min(buf.len());
        #[cfg(unix)]
        let end = buf.len();
        match sock.write(&buf[at..end]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the connection accepted no more bytes",
                ))
            }
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{server}: the connection stalled past the socket timeout while writing"
                    ),
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `write_all` on `sock`, re-applying what is left of `deadline` before every `send`.
/// Without a deadline it is [`write_all_or_timeout`].
pub(crate) fn write_by_deadline(
    sock: &mut TcpStream,
    buf: &[u8],
    deadline: Option<std::time::Instant>,
    server: &str,
) -> io::Result<()> {
    // Data path (no absolute deadline): the socket's own `SO_SNDTIMEO` is the only bound, and a
    // timed-out send must surface as `TimedOut`, not the raw `WouldBlock` Linux returns.
    let Some(deadline) = deadline else {
        return write_all_or_timeout(sock, buf, server);
    };
    let mut at = 0;
    while at < buf.len() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{server}: the handshake ran past its deadline while sending"),
            ));
        }
        sock.set_write_timeout(Some(left.max(Duration::from_millis(1))))?;
        #[cfg(windows)]
        let end = (at + 64 * 1024).min(buf.len());
        #[cfg(unix)]
        let end = buf.len();
        match sock.write(&buf[at..end]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the connection accepted no more bytes",
                ))
            }
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // A send that hit the per-syscall timeout comes back `WouldBlock` (Linux) rather
            // than `TimedOut`; returning it verbatim would name "resource temporarily
            // unavailable" for what is a deadline expiry. Loop back instead: the top
            // re-checks the clock and turns the real timeout into the `TimedOut` above.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A SESSION_SETUP failure as an error: `PermissionDenied` for the statuses that mean "not
/// this credential", `Other` for everything else -- and never a file-level kind.
///
/// **Neither SESSION_SETUP reply can be authenticated**: the key does not exist until the
/// second one has arrived, and a server has no key to sign a failed logon with. So their
/// status is unauthenticated on every session, signed or not, and the rule in
/// `check_signature` -- an unauthenticated status names itself but carries no meaning --
/// applies to both. Routed through `status_error` instead, a forged OBJECT_NAME_NOT_FOUND on
/// the AUTHENTICATE reply would become `NotFound`, which the transfer layer reads, for a
/// DESTINATION listing, as "this tree is empty". The credential
/// statuses keep `PermissionDenied` because a genuine rejection must not be retried; a
/// forger choosing one gets a refused login, which is what dropping the reply would get.
fn login_error(status: u32, what: &str) -> io::Error {
    let kind = match login_verdict(status) {
        LoginVerdict::BadCredential | LoginVerdict::Account => io::ErrorKind::PermissionDenied,
        // retried by `worth_another_connection`, as a dropped connection is: the server did
        // not judge the credential, and a forger choosing one of these gets what dropping gets
        LoginVerdict::Unjudged => io::ErrorKind::ConnectionAborted,
        LoginVerdict::Unknown => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{what}: {}", proto::status_text(status)))
}

/// What a SESSION_SETUP failure says about the credential.
///
/// **Treating every non-success as a rejected password is wrong in both directions.** A
/// server that lost the half-built session, could not reach a domain controller, or ran out
/// of resources never judged the password -- counting that as a rejection means it is not
/// retried and the refusal says "check the password". And an account that is locked out,
/// disabled or expired would be told the same, when no password can help it. Statuses not
/// listed stay `Unknown` and are counted as rejections: the conservative default for a
/// budget that exists to prevent lockouts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum LoginVerdict {
    /// The credential was judged and refused.
    BadCredential,
    /// The ACCOUNT was refused, whatever the password: offering another cannot help.
    Account,
    /// The credential was not judged at all.
    Unjudged,
    /// Anything else: treated as a rejection.
    Unknown,
}

pub(crate) fn login_verdict(status: u32) -> LoginVerdict {
    match status {
        // LOGON_FAILURE only. ACCESS_DENIED does not belong here: SMB2 sends it for a
        // signature the server refuses and for access policy, not for a wrong password --
        // this file's own comments say a wrong signing key comes back as ACCESS_DENIED and
        // "reads exactly like a bad password". It is `Unknown`: still counted, but not
        // narrated as a verdict on the password.
        proto::STATUS_LOGON_FAILURE => LoginVerdict::BadCredential,
        proto::STATUS_ACCOUNT_LOCKED_OUT
        | proto::STATUS_ACCOUNT_DISABLED
        | proto::STATUS_ACCOUNT_EXPIRED
        | proto::STATUS_PASSWORD_EXPIRED
        | proto::STATUS_PASSWORD_MUST_CHANGE
        | proto::STATUS_INVALID_LOGON_HOURS
        | proto::STATUS_INVALID_WORKSTATION
        | proto::STATUS_ACCOUNT_RESTRICTION
        | proto::STATUS_LOGON_TYPE_NOT_GRANTED => LoginVerdict::Account,
        // MORE_PROCESSING_REQUIRED here is on the FINAL leg: a server asking for a third round
        // this client does not speak, which is not a verdict on the password
        proto::STATUS_USER_SESSION_DELETED
        | proto::STATUS_NO_LOGON_SERVERS
        | proto::STATUS_DOMAIN_CONTROLLER_NOT_FOUND
        | proto::STATUS_INSUFFICIENT_RESOURCES
        | proto::STATUS_REQUEST_NOT_ACCEPTED
        | proto::STATUS_MORE_PROCESSING_REQUIRED => LoginVerdict::Unjudged,
        _ => LoginVerdict::Unknown,
    }
}

/// Turns a status into an error whose kind a caller can match on, with words in the
/// message rather than only a number.
pub fn status_error(status: u32, what: &str) -> io::Error {
    let kind = match status {
        proto::STATUS_NO_SUCH_FILE
        | proto::STATUS_OBJECT_NAME_NOT_FOUND
        | proto::STATUS_OBJECT_PATH_NOT_FOUND => io::ErrorKind::NotFound,
        proto::STATUS_ACCESS_DENIED | proto::STATUS_LOGON_FAILURE => {
            io::ErrorKind::PermissionDenied
        }
        proto::STATUS_OBJECT_NAME_COLLISION => io::ErrorKind::AlreadyExists,
        // named, because a removal that meets it in a filtered or depth-capped run is the
        // directory keeping what that run did not look at -- not a fault
        proto::STATUS_DIRECTORY_NOT_EMPTY => io::ErrorKind::DirectoryNotEmpty,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{what}: {}", proto::status_text(status)))
}

/// The SESSION_SETUP request around a security blob. `security_mode` is this client's own,
/// from `Conn::security_mode`.
fn session_setup_body(blob: &[u8], security_mode: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    body.push(0); // Flags
    body.push(security_mode as u8); // SecurityMode, per MS-SMB2 2.2.5
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    body.extend_from_slice(&((proto::HEADER + 24) as u16).to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    body.extend_from_slice(blob);
    body
}

/// The security blob out of a SESSION_SETUP response, by the offset and length the
/// response itself gives -- both checked against the message, since both are the
/// server's to choose.
fn security_buffer_of(buf: &[u8]) -> io::Result<&[u8]> {
    let c = Cursor::new(buf);
    let mut r = Cursor::new(buf);
    r.seek(proto::HEADER)?;
    r.u16("the session setup response size")?;
    r.u16("the session flags")?;
    let offset = r.u16("the security buffer offset")? as usize;
    let len = r.u16("the security buffer length")? as usize;
    c.at_offset(offset, len, "the security blob")
}

/// SessionFlags in a SESSION_SETUP response (MS-SMB2 2.2.6).
const SESSION_FLAG_IS_GUEST: u16 = 0x0001;
const SESSION_FLAG_IS_NULL: u16 = 0x0002;

const NTLMSSP: &[u8; 8] = b"NTLMSSP\0";

// The flags this client asks for: unicode, NTLM, sign, always-sign, extended session
// security. No SEAL and no KEY_EXCH: sealing is encryption, which this does not do, and
// without key exchange the exported session key IS the NTLMv2 session base key, which is
// what the signing key is derived from. Samba confirms that reading in its own log --
// `ntlmssp_server_auth: Using unmodified nt session key` -- and signing works against it.
const NEG_UNICODE: u32 = 0x0000_0001;
const NEG_OEM: u32 = 0x0000_0002;
const NEG_REQUEST_TARGET: u32 = 0x0000_0004;
const NEG_NTLM: u32 = 0x0000_0200;
const NEG_EXTENDED_SECURITY: u32 = 0x0008_0000;
/// `NTLMSSP_NEGOTIATE_SIGN` and `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`.
///
/// These say the client intends to sign, and MEASURED against Samba: without them the
/// server logs `neg_flags=0x00080207`, sets up no session key, and then refuses the next
/// request while its own log reads `No signing key for SMB2 signing`. The status that
/// reaches the client names neither signing nor keys. What a server does with a session key
/// it declines to establish is not something this arm can see from outside -- what is
/// established is that the flags in the FIRST message decide it.
const NEG_SIGN: u32 = 0x0000_0010;
const NEG_ALWAYS_SIGN: u32 = 0x0000_8000;

fn ntlmssp_negotiate(domain: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&1u32.to_le_bytes()); // type 1
                                              // SIGN and ALWAYS_SIGN belong in the NEGOTIATE message as well as the AUTHENTICATE,
                                              // and putting them in only the second one is a silent failure: Samba logged
                                              // `Got NTLMSSP neg_flags=0x00080207` -- no SIGN bit -- set up no signing key, and then
                                              // refused the next request with INVALID_HANDLE while its own log said "No signing key
                                              // for SMB2 signing". The server decides here, from the FIRST message.
    let flags = NEG_UNICODE
        | NEG_OEM
        | NEG_REQUEST_TARGET
        | NEG_NTLM
        | NEG_EXTENDED_SECURITY
        | NEG_SIGN
        | NEG_ALWAYS_SIGN;
    m.extend_from_slice(&flags.to_le_bytes());
    // domain and workstation are sent empty: the server does not need them to produce a
    // challenge, and an empty pair keeps the offsets trivial
    let _ = domain;
    m.extend_from_slice(&[0u8; 8]); // DomainNameFields
    m.extend_from_slice(&[0u8; 8]); // WorkstationFields
    m
}

/// The server challenge and the target-info blob out of a type 2 message.
fn ntlmssp_challenge(blob: &[u8]) -> io::Result<([u8; 8], Vec<u8>)> {
    if blob.len() < 32 || &blob[0..8] != NTLMSSP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the server's challenge is not an NTLMSSP message",
        ));
    }
    let kind = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    if kind != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected an NTLMSSP CHALLENGE (type 2), got type {kind}"),
        ));
    }
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&blob[24..32]);
    // TargetInfoFields at 40: len, maxlen, offset. Absent on older servers, which is not
    // an error -- the blob is then empty and the response carries only the timestamp.
    let mut target_info = Vec::new();
    if blob.len() >= 48 {
        let len = u16::from_le_bytes(blob[40..42].try_into().unwrap()) as usize;
        let off = u32::from_le_bytes(blob[44..48].try_into().unwrap()) as usize;
        if len > 0 {
            let end = off
                .checked_add(len)
                .ok_or_else(|| proto::short("the target info"))?;
            if end > blob.len() {
                return Err(proto::short("the target info"));
            }
            target_info.extend_from_slice(&blob[off..end]);
        }
    }
    Ok((challenge, target_info))
}

/// Eight bytes from the OS random source, for the NTLMv2 client challenge.
///
/// `/dev/urandom` (`BCryptGenRandom` on Windows), the OS source a random crate would read
/// anyway. If it cannot be read -- which on Linux
/// means something is badly wrong -- this REFUSES rather than falling back to the clock. A
/// silent downgrade from "unpredictable" to "derivable from a timestamp" is precisely the
/// kind of failure nobody would notice, and a login that errors is recoverable in a way a
/// weakened session key is not.
fn client_nonce() -> io::Result<[u8; 8]> {
    #[cfg(unix)]
    use std::io::Read;
    let mut n = [0u8; 8];
    #[cfg(windows)]
    crate::windows::random(&mut n)?;
    #[cfg(unix)]
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut n))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("reading /dev/urandom for the NTLM client challenge: {e}"),
            )
        })?;
    Ok(n)
}

fn ntlmssp_authenticate(
    user: &str,
    password: &str,
    domain: &str,
    challenge: &[u8; 8],
    target_info: &[u8],
) -> io::Result<(Vec<u8>, [u8; 16])> {
    let ntowf = ntlm::ntowf_v2(user, domain, password);

    // the NTLMv2 blob: header, timestamp, client nonce, target info
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0, 0]); // RespType, HiRespType, Reserved
    blob.extend_from_slice(&0u32.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    blob.extend_from_slice(&proto::unix_ns_to_filetime(now).to_le_bytes());
    // THE CLIENT NONCE COMES FROM THE OS, not from the clock.
    //
    // A clock-derived value is not good enough once the client signs. The nonce goes into
    // the NTLMv2 proof and therefore into the session key, which is the key every signature
    // on this connection is derived from -- a value an observer can predict from a timestamp
    // is one input to that key they do not have to guess.
    blob.extend_from_slice(&client_nonce()?);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&0u32.to_le_bytes());

    let (nt_response, session_key) = ntlm::ntlmv2_response(&ntowf, challenge, &blob);
    let lm_response = [0u8; 24];

    let domain_b = ntlm::utf16le(domain);
    let user_b = ntlm::utf16le(user);
    let host_b = ntlm::utf16le("rcp");

    // payload order: LM, NT, domain, user, workstation, session key
    let base = 64usize;
    let mut offsets = Vec::new();
    let mut payload = Vec::new();
    for part in [
        &lm_response[..],
        &nt_response[..],
        &domain_b[..],
        &user_b[..],
        &host_b[..],
        &[][..],
    ] {
        offsets.push((part.len() as u16, (base + payload.len()) as u32));
        payload.extend_from_slice(part);
    }

    let mut m = Vec::with_capacity(base + payload.len());
    m.extend_from_slice(NTLMSSP);
    m.extend_from_slice(&3u32.to_le_bytes()); // type 3
    for (len, off) in &offsets {
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&len.to_le_bytes()); // MaxLen
        m.extend_from_slice(&off.to_le_bytes());
    }
    let flags = NEG_UNICODE
        | NEG_REQUEST_TARGET
        | NEG_NTLM
        | NEG_EXTENDED_SECURITY
        | NEG_SIGN
        | NEG_ALWAYS_SIGN;
    m.extend_from_slice(&flags.to_le_bytes());
    debug_assert_eq!(
        m.len(),
        base,
        "the type 3 header is 64 bytes before the payload"
    );
    m.extend_from_slice(&payload);
    // The session key comes back with the blob. Dropping it here -- `let (nt_response,
    // _session_key)` -- would leave signing impossible, however small the rest of it is.
    Ok((m, session_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DATA-path send to a peer that stops reading surfaces as `TimedOut`, not the raw
    /// `WouldBlock` a socket timeout returns on some platforms. `write_all_or_timeout` is the
    /// data path's send: no absolute deadline (a large transfer is legitimately long), the
    /// socket's own `SO_SNDTIMEO` is the only bound. On Linux a timed-out send returns
    /// `WouldBlock` (measured here, errno 11), so this catches the removal of the
    /// `WouldBlock`->`TimedOut` arm -- verified by planting that removal.
    #[test]
    fn a_data_path_send_that_stalls_reads_as_timed_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let _s = listener.accept().unwrap(); // accept and never read
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_write_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let big = vec![0u8; 64 << 20];
        let started = std::time::Instant::now();
        let e = write_all_or_timeout(&mut sock, &big, "peer")
            .expect_err("a peer that never reads cannot absorb 64 MiB");
        assert_eq!(
            e.kind(),
            io::ErrorKind::TimedOut,
            "a data-path send timeout must read as TimedOut: {e:?}"
        );
        // a lower bound too, so an error that is merely immediate cannot pass as a timeout
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "the error came before any socket timeout could: {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the data-path send outlived its socket timeout: {:?}",
            started.elapsed()
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(sock);
        let _ = reader.join();
    }

    /// The read side of the same: a DATA-path recv from a peer that goes silent is `TimedOut`,
    /// after one socket timeout. Without this arm, removing the read side's mapping fails
    /// nothing.
    #[test]
    fn a_data_path_read_that_stalls_reads_as_timed_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"abc").unwrap(); // part of a message, then silence
            std::thread::sleep(Duration::from_secs(2));
        });
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut buf = [0u8; 16];
        let started = std::time::Instant::now();
        let e =
            read_exact_or_timeout(&mut sock, &mut buf, "peer").expect_err("16 bytes never arrive");
        assert_eq!(
            e.kind(),
            io::ErrorKind::TimedOut,
            "a data-path recv timeout must read as TimedOut: {e:?}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "the error came before any socket timeout could: {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "it waited out the peer, not the timeout: {:?}",
            started.elapsed()
        );
        drop(sock);
        let _ = held.join();
    }

    /// Under an ABSOLUTE deadline, the recv that outlasts it is `TimedOut` from the request
    /// itself. The tree-connect arm in `client.rs` cannot pin this: without the `WouldBlock`
    /// arm the pool retries the raw error, and whether the LAST attempt ends in the recv or
    /// at the top of the loop is timing -- with the removal planted, that arm stays green.
    /// Here there is no pool in between.
    /// A non-empty directory is `DirectoryNotEmpty`, the kind the local, NFS and WebDAV
    /// adapters give it: a filtered or depth-capped sync keeps such a directory instead of
    /// failing the run, and it can only do that if SMB says so in the same words.
    #[test]
    fn a_directory_not_empty_is_named_as_such() {
        assert_eq!(
            status_error(proto::STATUS_DIRECTORY_NOT_EMPTY, "removing d").kind(),
            io::ErrorKind::DirectoryNotEmpty
        );
    }

    #[test]
    fn a_deadline_that_expires_in_a_recv_reads_as_timed_out() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD, USER};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.delay_later = Some(Duration::from_secs(3)); // answers, but long after the deadline
        let peer = spawn(script);
        let mut conn =
            Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), false)
                .expect("connects");
        conn.login(USER, PASSWORD, "").expect("logs in");
        conn.arm_deadline(Duration::from_millis(400)).unwrap();
        let started = std::time::Instant::now();
        let e = conn
            .tree_connect("share")
            .expect_err("the reply comes after the deadline");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "{:?}",
            started.elapsed()
        );
        // and it did not simply wait for the late reply
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// The send side under an absolute deadline: a peer that never reads fills the buffers,
    /// and the send that outlasts the deadline is `TimedOut`, not the raw `WouldBlock`.
    #[test]
    fn a_deadline_that_expires_in_a_send_reads_as_timed_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = std::thread::spawn(move || {
            let _s = listener.accept().unwrap(); // accept and never read
            std::thread::sleep(Duration::from_secs(3));
        });
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // FILL the buffers first. A send into a buffer with room copies what fits and returns
        // `Ok(n)` when its timeout fires, and the loop then stops on its own clock check --
        // so a test that starts with room never reaches the `WouldBlock` arm (with its removal
        // planted, such a version stays green). Full, the first send copies nothing and the
        // timeout comes back as `WouldBlock`.
        sock.set_nonblocking(true).unwrap();
        let chunk = vec![0u8; 1 << 16];
        loop {
            match sock.write(&chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        sock.set_nonblocking(false).unwrap();
        let big = vec![0u8; 1 << 20];
        let started = std::time::Instant::now();
        let deadline = started + Duration::from_millis(400);
        let e = write_by_deadline(&mut sock, &big, Some(deadline), "peer")
            .expect_err("a full pipe cannot take another MiB");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "{:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        drop(sock);
        let _ = held.join();
    }

    /// A connection whose exchange failed partway is not used again: the next request is
    /// refused without being sent, rather than reading the rest of the old reply as its own.
    /// The data path's per-syscall timeout stalls the tree connect after the request went
    /// out; the peer's reply keeps arriving afterwards, which is exactly the stale tail a
    /// second request would have read.
    #[test]
    fn a_connection_that_failed_mid_exchange_is_not_used_again() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD, USER};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.trickle_later = Some(Duration::from_millis(300));
        let peer = spawn(script);
        let mut conn =
            Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), false)
                .expect("connects");
        conn.login(USER, PASSWORD, "").expect("logs in");
        conn.set_timeout(Duration::from_millis(100)).unwrap();
        let first = conn
            .tree_connect("share")
            .expect_err("the reply is slower than the socket timeout");
        assert_eq!(first.kind(), io::ErrorKind::TimedOut, "{first}");
        assert!(
            conn.broken,
            "a request that went out and never came back whole must mark the connection"
        );
        // the message id is taken before the request is written, so an unmoved id proves
        // nothing was sent. A timing bound would prove less (a small write returns at once)
        // and could fail on a scheduler pause, so there is none.
        let id_before = conn.next_id;
        let second = conn
            .tree_connect("share")
            .expect_err("a broken connection must refuse")
            .to_string();
        assert_eq!(
            conn.next_id, id_before,
            "the refused request was sent anyway"
        );
        assert!(
            second.contains("out of step"),
            "the second request was sent on a desynced stream: {second}"
        );
    }

    /// A reply carrying this request's message id but ANOTHER command is not its answer, and
    /// must not clear `broken`. The peer answers a CLOSE with a well-formed TREE_CONNECT
    /// response under the same id.
    #[test]
    fn a_reply_for_another_command_does_not_count_as_the_answer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut nb = [0u8; 4];
            s.read_exact(&mut nb).unwrap();
            let mut req =
                vec![0u8; ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize];
            s.read_exact(&mut req).unwrap();
            let id = u64::from_le_bytes(req[24..32].try_into().unwrap());
            let mut msg = Header {
                command: proto::TREE_CONNECT,
                message_id: id,
                session_id: 0,
                tree_id: 0,
                credits: 1,
                credit_charge: 1,
            }
            .bytes();
            msg[16..20].copy_from_slice(&proto::FLAGS_SERVER_TO_REDIR.to_le_bytes());
            msg.extend_from_slice(&[0u8; 16]);
            let n = msg.len();
            let mut frame = vec![0, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            frame.extend_from_slice(&msg);
            s.write_all(&frame).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut conn = Conn::over(sock);
        let e = conn
            .request(proto::CLOSE, 0, &[0u8; 24], 0, 0)
            .map(drop)
            .expect_err("a TREE_CONNECT reply is not a CLOSE's answer");
        assert!(e.to_string().contains("answered command"), "{e}");
        assert!(
            conn.broken,
            "a reply for another command cleared the broken mark"
        );
        let _ = peer.join();
    }

    /// A request REFLECTED back is not its own reply. The echo has the
    /// request's id and command and a zero status; on a signed session it would even verify,
    /// since one key signs both directions. Only the response flag tells them apart.
    #[test]
    fn a_reflected_request_is_not_taken_for_its_reply() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut nb = [0u8; 4];
            s.read_exact(&mut nb).unwrap();
            let mut req =
                vec![0u8; ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize];
            s.read_exact(&mut req).unwrap();
            s.write_all(&nb).unwrap(); // the same frame, straight back
            s.write_all(&req).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut conn = Conn::over(sock);
        let e = conn
            .request(proto::CLOSE, 0, &[0u8; 24], 0, 0)
            .map(drop)
            .expect_err("an echoed request is not a reply");
        assert!(e.to_string().contains("response flag"), "{e}");
        assert!(conn.broken, "a reflected request cleared the broken mark");
        let _ = peer.join();
    }

    /// A NetBIOS keep-alive before the reply is skipped, not read as a short message; an
    /// endless run of them is refused rather than waited on forever.
    #[test]
    fn a_netbios_keepalive_before_the_reply_is_skipped_and_bounded() {
        for (keepalives, answered) in [(2usize, true), (MAX_KEEPALIVES as usize + 1, false)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let peer = std::thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let mut nb = [0u8; 4];
                s.read_exact(&mut nb).unwrap();
                let mut req =
                    vec![0u8; ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize];
                s.read_exact(&mut req).unwrap();
                let id = u64::from_le_bytes(req[24..32].try_into().unwrap());
                for _ in 0..keepalives {
                    s.write_all(&[0x85, 0, 0, 0]).unwrap();
                }
                let mut msg = Header {
                    command: proto::CLOSE,
                    message_id: id,
                    session_id: 0,
                    tree_id: 0,
                    credits: 1,
                    credit_charge: 1,
                }
                .bytes();
                msg[16..20].copy_from_slice(&proto::FLAGS_SERVER_TO_REDIR.to_le_bytes());
                msg.extend_from_slice(&[0u8; 60]);
                let n = msg.len();
                let mut frame = vec![0, (n >> 16) as u8, (n >> 8) as u8, n as u8];
                frame.extend_from_slice(&msg);
                let _ = s.write_all(&frame);
                std::thread::sleep(Duration::from_millis(200));
            });
            let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut conn = Conn::over(sock);
            let r = conn.request(proto::CLOSE, 0, &[0u8; 24], 0, 0).map(drop);
            if answered {
                r.expect("keep-alives before the answer must be skipped");
                assert!(!conn.broken);
            } else {
                let e = r.expect_err("endless keep-alives must be refused");
                assert!(e.to_string().contains("keep-alives"), "{e}");
            }
            let _ = peer.join();
        }
    }

    /// Negotiate, authenticate and connect a share against a REAL SMB2 server.
    ///
    /// The unit arms above check the shapes of messages nobody has read. This one is the
    /// only thing that says the shapes are right, because a server is the only authority
    /// on that -- and NTLM in particular fails the same way whether the key schedule is
    /// wrong, an offset is wrong or the flags are wrong: `STATUS_LOGON_FAILURE`, with no
    /// hint which.
    ///
    /// impacket's SimpleSMBServer is the stand-in, started by the test and torn down with
    /// it. A missing impacket is a SKIP that says so rather than a pass.
    #[test]
    fn a_real_server_negotiates_authenticates_and_connects_a_share() {
        let Some(mut server) = super::super::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        let mut c = Conn::connect("127.0.0.1", server.port, Duration::from_secs(10))
            .expect("connects and negotiates");
        assert!(
            [0x0202, 0x0210, 0x0300].contains(&c.dialect),
            "the server chose dialect 0x{:04x}, which is not one of the three offered",
            c.dialect
        );
        assert!(
            c.max_read >= 64 << 10,
            "a MaxReadSize of {} is below the floor",
            c.max_read
        );
        // THE STAND-IN MUST OFFER A CREDIT WINDOW, and this assertion exists because by
        // default it does not. impacket answers NEGOTIATE with DialectRevision 0x0202 and
        // Capabilities 0; either alone sets `Connection.SupportsMultiCredit` false, so
        // `credit_charge` returns 0 on EVERY request in EVERY automated run. Both credit
        // defects this repo has fixed -- the constant zero, and payload-versus-message --
        // are structurally invisible to such a suite, because arms that call the formula
        // directly never reach a call site.
        //
        // `tests/support/smb_server.py` overrides the negotiate response. If that override
        // ever stops working this fails HERE, loudly, rather than quietly restoring the
        // blind spot -- which is easy to do, because `testserver.rs` sends that script's
        // stderr to /dev/null and a broken override is indistinguishable from a working one
        // without it.
        assert!(c.multi_credit, "the stand-in is not advertising LARGE_MTU, so nothing in this suite exercises the credit charge");

        c.login("tester", "", "").expect("NTLMv2 login");
        let tid = c.tree_connect("DATA").expect("tree connect");

        // THE CONTROL on the login: a wrong password must be REFUSED, or the assertion
        // above says only that the server answered, not that it checked anything. This is
        // the arm that distinguishes "authentication works" from "authentication is not
        // happening".
        let mut bad =
            Conn::connect("127.0.0.1", server.port, Duration::from_secs(10)).expect("connects");
        match bad.login("tester", "definitely-not-the-password", "") {
            Ok(()) => panic!("the server accepted a wrong password, so this arm proves nothing about authentication"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "a wrong password should be a permission error, got: {e}"),
        }

        // a share that does not exist is refused by name rather than silently empty
        let mut c2 =
            Conn::connect("127.0.0.1", server.port, Duration::from_secs(10)).expect("connects");
        c2.login("tester", "", "").expect("login");
        let e = c2.tree_connect("NOSUCHSHARE").unwrap_err().to_string();
        assert!(
            e.contains("NOSUCHSHARE"),
            "the refusal should name the share: {e}"
        );

        c.tree_disconnect(tid).expect("tree disconnect");
        c.logoff().expect("logoff");
        server.stop();
    }

    /// Logs in to a scripted peer with the peer's own credential.
    fn signed_session(
        script: super::super::scripted::Script,
    ) -> (super::super::scripted::Peer, io::Result<Conn>) {
        use super::super::scripted::{spawn, DOMAIN, PASSWORD, USER};
        let peer = spawn(script);
        let mut c = Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5))
            .expect("connects and negotiates");
        let login = c.login(USER, PASSWORD, DOMAIN).map(|()| c);
        (peer, login)
    }

    /// On a session that requires signing, every reply is verified -- and one that cannot
    /// be is refused, whether its signature is wrong or simply absent.
    ///
    /// **Without this arm, deleting the verification leaves every arm green**, because
    /// nothing else in the suite produces a signed session: the stand-in cannot require
    /// signing, and the Samba measurement is not in every run. So the peer here requires it,
    /// at both algorithms, and signs later replies three ways.
    #[test]
    fn a_signed_session_refuses_every_reply_it_cannot_authenticate() {
        use super::super::scripted::{Script, Signature};
        for dialect in [0x0300u16, 0x0210] {
            for later in [Signature::Correct, Signature::Absent, Signature::Wrong] {
                let mut script = Script::signing();
                script.dialect = dialect;
                script.later = later;
                let (_peer, login) = signed_session(script);
                let mut c = login.unwrap_or_else(|e| {
                    panic!("0x{dialect:04x}: a correctly signed login must succeed: {e}")
                });
                assert!(
                    c.signing_key.is_some(),
                    "the peer requires signing, so the session must be keyed"
                );
                let got = c.tree_connect("DATA");
                match later {
                    // THE CONTROL: without it, a check that refused everything would pass
                    Signature::Correct => assert!(
                        got.is_ok(),
                        "0x{dialect:04x}: a correctly signed reply was refused: {got:?}"
                    ),
                    Signature::Absent => {
                        let e =
                            got.expect_err("an unsigned reply on a signed session must be refused");
                        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                        assert!(
                            e.to_string().contains("without a signature"),
                            "0x{dialect:04x}: {e}"
                        );
                    }
                    Signature::Wrong => {
                        let e = got
                            .expect_err("a reply whose signature does not verify must be refused");
                        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                        assert!(
                            e.to_string().contains("does not verify"),
                            "0x{dialect:04x}: {e}"
                        );
                    }
                }
            }
        }
    }

    /// What one request's replies can add to the balance is capped at what it asked for, and
    /// an interim grant still counts.
    ///
    /// Both halves matter, and a peer that always grants what was asked in the FINAL reply
    /// can see neither: a client ignoring interim grants and one capping them bank the same
    /// number. Here the final reply grants nothing, so the whole change in the balance comes
    /// from the interim.
    #[test]
    fn an_interim_grant_counts_and_what_one_request_can_add_is_capped() {
        use super::super::scripted::Script;
        for (interim, expect_gain) in [(10u16, 10u16), (60_000, CREDITS_REQUESTED)] {
            let mut script = Script::signing();
            script.forged_interim = Some(interim);
            script.final_grant = Some(0);
            let (_peer, login) = signed_session(script);
            let mut c = login.expect("a correctly signed login");
            let before = c.credits;
            c.tree_connect("DATA")
                .expect("the signed final reply is genuine, so the request succeeds");
            // a TREE_CONNECT spends one credit, whatever its CreditCharge says
            assert_eq!(
                c.credits,
                before - 1 + expect_gain,
                "interim {interim}: {before} credits became {}",
                c.credits
            );
        }
    }

    /// A request with CreditCharge zero still spends a credit.
    ///
    /// Every request on a 2.0.2 connection carries charge zero. The message id counted it
    /// as one; the balance counted it as nothing and gained a credit per request.
    #[test]
    fn a_zero_charge_request_still_spends_a_credit() {
        use super::super::scripted::{spawn, Answer, Script, Signature, DOMAIN, PASSWORD, USER};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.dialect = 0x0202;
        // two per reply, so a client that never debits (+10) and one that never credits (-5)
        // both miss; with one per reply, a client doing neither also came out even
        script.final_grant = Some(2);
        let peer = spawn(script);
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        c.login(USER, PASSWORD, DOMAIN).expect("login");
        assert!(
            !c.multi_credit,
            "2.0.2 has no multi-credit, so its charge is zero"
        );
        let before = c.credits;
        for _ in 0..5 {
            c.tree_connect("DATA").expect("tree connect");
        }
        assert_eq!(
            c.credits,
            before + 5,
            "five requests granted two each and spent one each"
        );
    }

    /// A SESSION_SETUP failure never carries a file-level meaning, on any session.
    ///
    /// Neither SESSION_SETUP reply can be authenticated -- no key exists yet, and a server has
    /// none to sign a failed logon with -- so the rule for unsigned errors has to hold here
    /// too. Otherwise a forged OBJECT_NAME_NOT_FOUND on the AUTHENTICATE reply comes back
    /// `NotFound`, which the transfer layer reads, for a destination, as "this tree is empty".
    #[test]
    fn a_session_setup_failure_never_carries_a_file_meaning() {
        use super::super::scripted::{spawn, Answer, Script, DOMAIN, PASSWORD, USER};
        for status in [
            proto::STATUS_NO_SUCH_FILE,
            proto::STATUS_OBJECT_NAME_NOT_FOUND,
            proto::STATUS_OBJECT_PATH_NOT_FOUND,
            proto::STATUS_OBJECT_NAME_COLLISION,
        ] {
            // on the FIRST leg too, before any challenge -- the test's name claims both legs
            let mut script = Script::signing();
            script.fail_first_leg = Some(status);
            let peer = spawn(script);
            let mut c =
                Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), true)
                    .expect("connects");
            let e = c
                .login(USER, PASSWORD, DOMAIN)
                .expect_err("a failed first leg is an error");
            assert_eq!(
                e.kind(),
                io::ErrorKind::Other,
                "first leg, 0x{status:08x} chose a meaning: {e}"
            );
            let mut script = Script::signing();
            script.answer = Answer::Fail(status);
            let peer = spawn(script);
            let mut c =
                Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), true)
                    .expect("connects");
            let e = c
                .login(USER, PASSWORD, DOMAIN)
                .expect_err("a failed session setup is an error");
            assert_eq!(
                e.kind(),
                io::ErrorKind::Other,
                "0x{status:08x} chose a meaning: {e}"
            );
            assert!(
                e.to_string().contains(&proto::status_text(status)),
                "the status must still be named: {e}"
            );
        }
        // THE CONTROL: a rejection of the credential stays a rejection, so it is not retried
        let mut script = Script::signing();
        script.answer = Answer::Fail(proto::STATUS_LOGON_FAILURE);
        let peer = spawn(script);
        let mut c = Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), true)
            .expect("connects");
        assert_eq!(
            c.login(USER, PASSWORD, DOMAIN)
                .expect_err("rejected")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        // and a status that did not judge the credential is one a fresh connection may retry
        let mut script = Script::signing();
        script.answer = Answer::Fail(proto::STATUS_USER_SESSION_DELETED);
        let peer = spawn(script);
        let mut c = Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), true)
            .expect("connects");
        assert_eq!(
            c.login(USER, PASSWORD, DOMAIN)
                .expect_err("unjudged")
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// An UNSIGNED ERROR reply is reported as the error it claims, not as tampering -- and
    /// an unsigned SUCCESS is still refused.
    ///
    /// Real servers send unsigned error replies when they cannot sign -- a session the
    /// server has already expired has no key to sign with. Calling that "altered in
    /// transit" sent the operator hunting for an attacker. Trusting the status costs nothing,
    /// because the reply is an error either way.
    #[test]
    fn an_unsigned_error_reply_reports_its_status_and_an_unsigned_success_does_not_pass() {
        use super::super::scripted::{Script, Signature};
        // NOT_FOUND is the one that matters: `SmbTree::stat` reads the NotFound kind as "this
        // file is absent", which a sync's removal step acts on. A forger must not be able to
        // choose that meaning on a signed session. ACCESS_DENIED is the other kind a caller
        // branches on.
        for status in [
            proto::STATUS_OBJECT_NAME_NOT_FOUND,
            proto::STATUS_ACCESS_DENIED,
        ] {
            let text = proto::status_text(status);
            let mut script = Script::signing();
            script.later = Signature::Absent;
            script.later_status = status;
            let (_peer, login) = signed_session(script);
            let e = login
                .expect("login")
                .tree_connect("DATA")
                .expect_err("an error reply is an error");
            assert_eq!(
                e.kind(),
                io::ErrorKind::Other,
                "an unsigned status chose the error's meaning: {e}"
            );
            assert!(
                e.to_string().contains(&text),
                "the message must still name the status it claimed: {e}"
            );
            assert!(
                e.to_string().contains("unsigned"),
                "the error must say the status is unauthenticated: {e}"
            );
            assert!(
                !e.to_string().contains("altered in transit"),
                "an unsigned error was reported as tampering: {e}"
            );
        }
        // and an unsigned SUCCESS is refused outright -- the one status a forger gains from
        let mut script = Script::signing();
        script.later = Signature::Absent;
        let (_peer, login) = signed_session(script);
        let e = login
            .expect("login")
            .tree_connect("DATA")
            .expect_err("an unsigned success on a signed session must be refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        // named as what it is -- an answer with the signature stripped -- and not left to the
        // verification below it, which also refuses it but calls it an altered reply
        assert!(e.to_string().contains("without a signature"), "{e}");
        // THE CONTROL: a SIGNED error keeps its meaning
        let mut script = Script::signing();
        script.later_status = proto::STATUS_OBJECT_NAME_NOT_FOUND;
        let (_peer, login) = signed_session(script);
        let e = login
            .expect("login")
            .tree_connect("DATA")
            .expect_err("an error reply is an error");
        assert_eq!(
            e.kind(),
            io::ErrorKind::NotFound,
            "a signed NOT_FOUND must stay NotFound: {e}"
        );
        // THE CONTROL is the Absent case in the arm above: the same unsigned reply carrying
        // SUCCESS is refused as InvalidData, because success is the one status a forger gains from.
    }

    /// The final SESSION_SETUP is checked by hand, and it must be signed by the key THIS
    /// authentication derived.
    ///
    /// It is the only reply `call` cannot verify -- the key does not exist until it has
    /// arrived -- so it has its own check, and nothing else reaches that check. The
    /// impostor case is the sharpest: a server that says yes to a password it cannot check
    /// cannot produce the signature, because the key comes from the password.
    #[test]
    fn the_final_session_setup_must_be_signed_by_the_key_this_login_derived() {
        use super::super::scripted::{spawn, Answer, Script, Signature, DOMAIN, USER};
        for sig in [Signature::Absent, Signature::Wrong] {
            let mut script = Script::signing();
            script.answer = Answer::Accept(sig);
            let (_peer, login) = signed_session(script);
            let e = login
                .map(drop)
                .expect_err("a final response the key does not verify must fail the login");
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(
                e.to_string().contains("not correctly signed"),
                "{sig:?}: {e}"
            );
        }
        // the impostor: accepts ANY password, but can only derive the key from its own
        let mut impostor = Script::signing();
        impostor.answer = Answer::AcceptAnything(Signature::Correct);
        let peer = spawn(impostor);
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        let e = c
            .login(USER, "not the password the peer holds", DOMAIN)
            .expect_err("a server that cannot derive the key must be refused");
        assert!(e.to_string().contains("not correctly signed"), "{e}");
        // THE CONTROLS: the correct signature passes, and an unsigned final response is fine
        // where signing was never required -- so the check is scoped, not blanket.
        assert!(
            signed_session(Script::signing()).1.is_ok(),
            "a correctly signed final response must pass"
        );
        let (_peer, plain) = signed_session(Script::unsigned(Answer::Accept(Signature::Absent)));
        let plain = plain.expect("no signing required, so an unsigned final response is normal");
        assert!(
            plain.signing_key.is_none(),
            "a server that does not require signing must not arm a key"
        );
    }

    /// A wrong password is REFUSED by the scripted peer, not merely mis-keyed.
    ///
    /// Pins the peer's NTLMv2 proof check. Forced to always pass, that check leaves every
    /// other smb arm green: the key comes from whatever proof the client sent, so a peer
    /// that checks nothing still agrees with the client on signatures. On an UNSIGNED
    /// session there is no signature to disagree about, so only the proof check can refuse.
    #[test]
    fn a_wrong_password_is_refused_by_the_peer_not_merely_mis_keyed() {
        use super::super::scripted::{spawn, Answer, Script, Signature, DOMAIN, PASSWORD, USER};
        let peer = spawn(Script::unsigned(Answer::Accept(Signature::Absent)));
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        let e = c
            .login(USER, "not the password", DOMAIN)
            .expect_err("a wrong proof must be refused");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        // THE CONTROL: the right password logs in on the same unsigned peer
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        c.login(USER, PASSWORD, DOMAIN)
            .expect("the right password must log in");
    }

    /// A GUEST session for a named user is a refusal, not a login.
    ///
    /// A server that maps bad passwords to guest answers `STATUS_SUCCESS` with SessionFlags
    /// IS_GUEST. With those flags unread, a wrong password logs in -- as guest, unsigned --
    /// and the copy runs with a guest's rights.
    #[test]
    fn a_guest_session_for_a_named_user_is_refused() {
        use super::super::scripted::{spawn, Answer, Script, DOMAIN, PASSWORD, USER};
        let peer = spawn(Script::unsigned(Answer::Guest));
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        let e = c
            .login(USER, PASSWORD, DOMAIN)
            .expect_err("a guest session must not count as a login");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("guest"), "{e}");
        assert!(
            c.credential_guest,
            "the budget reads this flag to count the attempt as a rejection"
        );
        // THE CONTROL: an anonymous login asked for exactly that and is left alone
        let mut c =
            Conn::connect("127.0.0.1", peer.port, Duration::from_secs(5)).expect("connects");
        c.login("", "", "")
            .expect("an anonymous login that gets a guest session got what it asked for");
    }

    /// With `-smb.sign`, clearing the server's signing bit no longer downgrades the session.
    ///
    /// The control IS the attack, run first: the peer's negotiate says signing is not
    /// required -- what an on-path edit of that one bit leaves behind -- and every later
    /// reply arrives with its signature stripped. A client with no expectation of its own
    /// signs nothing, verifies nothing, and takes the stripped reply. That is why the
    /// option exists, and why without it the hand check on the final SESSION_SETUP defends
    /// nothing.
    #[test]
    fn a_client_that_requires_signing_is_not_downgraded_by_a_cleared_bit() {
        use super::super::scripted::{spawn, Answer, Script, Signature, DOMAIN, PASSWORD, USER};
        let downgraded = |later: Signature| {
            let mut s = Script::unsigned(Answer::Accept(Signature::Correct));
            s.dialect = 0x0300;
            s.later = later;
            s
        };
        let dial = |script: Script, require: bool| {
            let peer = spawn(script);
            let c =
                Conn::connect_requiring("127.0.0.1", peer.port, Duration::from_secs(5), require)
                    .expect("connects");
            (peer, c)
        };

        // THE ATTACK, against a client that does not insist: it works.
        let (_p, mut c) = dial(downgraded(Signature::Absent), false);
        c.login(USER, PASSWORD, DOMAIN).expect("login");
        assert!(
            c.signing_key.is_none(),
            "with the bit cleared, a client that does not insist must not be signing"
        );
        assert!(
            c.tree_connect("DATA").is_ok(),
            "the control failed to reproduce the downgrade, so the arm below proves nothing"
        );

        // INSISTING: the session is keyed despite the bit, the server signs it because the
        // client's SESSION_SETUP asked, and a stripped reply is refused.
        let (_p, mut c) = dial(downgraded(Signature::Absent), true);
        c.login(USER, PASSWORD, DOMAIN)
            .expect("a server that merely enables signing signs a session the client requires");
        assert!(
            c.signing_key.is_some(),
            "-smb.sign must arm the key whatever the server's bit says"
        );
        let e = c.tree_connect("DATA").expect_err(
            "a stripped reply on a session this client required signing for must be refused",
        );
        assert!(e.to_string().contains("without a signature"), "{e}");
        // and correctly signed replies still pass, so the refusal is about the signature
        let (_p, mut c) = dial(downgraded(Signature::Correct), true);
        c.login(USER, PASSWORD, DOMAIN).expect("login");
        assert!(
            c.tree_connect("DATA").is_ok(),
            "a correctly signed reply was refused"
        );

        // A server that does not sign at all is refused at login, by name.
        let (_p, mut c) = dial(Script::unsigned(Answer::Accept(Signature::Absent)), true);
        let e = c.login(USER, PASSWORD, DOMAIN).expect_err(
            "an unsigned session setup must be refused when this client requires signing",
        );
        assert!(
            e.to_string().contains("-smb.sign"),
            "the refusal must name the setting that caused it: {e}"
        );
    }

    /// An interim response is waited through, and the flag is what decides it.
    ///
    /// The stand-in is synchronous and never sends one, so nothing here can prove the WAIT
    /// end to end. What is proved is the decision -- which is where the defect would be: a
    /// `call` that reads one message and returns it hands a perfectly ordinary
    /// STATUS_PENDING from a Windows server back to the caller as a failed request.
    #[test]
    fn an_interim_response_is_recognized_only_when_the_async_flag_says_so() {
        let reply = |status: u32, flags: u32| proto::Reply {
            command: proto::CREATE,
            status,
            session_id: 1,
            tree_id: 1,
            message_id: 7,
            flags,
            credits_granted: 1,
        };
        assert!(
            is_interim(&reply(proto::STATUS_PENDING, proto::FLAGS_ASYNC_COMMAND)),
            "a pending reply with the async flag is interim"
        );
        // THE CONTROL THAT MATTERS, because getting it wrong turns a broken server into an
        // indefinite wait: STATUS_PENDING WITHOUT the flag is not a valid interim response,
        // and a client that waits for a follow-up nobody will send hangs a worker.
        assert!(
            !is_interim(&reply(proto::STATUS_PENDING, 0)),
            "pending without the async flag must NOT be waited on"
        );
        // and the other direction: the flag alone, on a real answer, is not a reason to wait
        assert!(!is_interim(&reply(
            proto::STATUS_SUCCESS,
            proto::FLAGS_ASYNC_COMMAND
        )));
        assert!(!is_interim(&reply(proto::STATUS_SUCCESS, 0)));
        assert!(!is_interim(&reply(
            proto::STATUS_ACCESS_DENIED,
            proto::FLAGS_ASYNC_COMMAND
        )));
        // the header parser really reads Flags from offset 16, rather than this arm
        // agreeing with itself about a field nothing extracts
        let mut h = Header {
            command: proto::CREATE,
            message_id: 7,
            session_id: 1,
            tree_id: 1,
            credits: 1,
            credit_charge: 1,
        }
        .bytes();
        h[16..20].copy_from_slice(&proto::FLAGS_ASYNC_COMMAND.to_le_bytes());
        h[8..12].copy_from_slice(&proto::STATUS_PENDING.to_le_bytes());
        assert!(
            is_interim(&proto::parse_header(&h).expect("parses")),
            "the flag did not survive the header parser"
        );
    }

    /// The credit balance is read off replies, and a request it cannot cover is refused by
    /// name rather than sent for the server to reject.
    ///
    /// `CreditResponse` sits at bytes 14..16 of a reply header. A client that does not parse
    /// it cannot know what it is allowed to spend, and finds out as
    /// `STATUS_INVALID_PARAMETER`, a status that says nothing about credits. This checks the
    /// parse and the decision; the balance
    /// arithmetic itself is exercised end to end by every arm that talks to the stand-in.
    #[test]
    fn a_reply_grants_credits_and_a_request_the_balance_cannot_cover_is_named() {
        // the field really comes off the header, rather than this arm agreeing with itself
        let mut h = Header {
            command: proto::READ,
            message_id: 3,
            session_id: 1,
            tree_id: 1,
            credits: 64,
            credit_charge: 1,
        }
        .bytes();
        h[14..16].copy_from_slice(&37u16.to_le_bytes());
        assert_eq!(
            proto::parse_header(&h).expect("parses").credits_granted,
            37,
            "CreditResponse is not at offset 14"
        );

        // the decision: one credit is always allowed, because a client that cannot send a
        // single request can never recover the balance to send one
        let covered = |charge: u16, held: u16| !(charge > 1 && charge > held);
        assert!(
            covered(1, 0),
            "one credit must be sendable at a zero balance, or the connection deadlocks"
        );
        assert!(
            covered(16, 64),
            "a 1 MiB read fits the window this client asks for"
        );
        assert!(covered(64, 64), "an exact fit is a fit");
        // THE CONTROL, and it is the case a client without a balance sends anyway: more than the
        // server has granted. Refusing here is what turns an opaque server status into a
        // sentence with the number in it.
        assert!(
            !covered(65, 64),
            "a charge above the balance must be refused"
        );
        assert!(
            !covered(129, 0),
            "an 8 MiB transfer on a fresh connection must be refused"
        );
    }

    /// The two bits of the negotiate response that this client must READ rather than infer:
    /// the SecurityMode bit that arms signing, and the LARGE_MTU capability that decides the
    /// credit window.
    ///
    /// The stand-in cannot require signing, so this builds the negotiate response instead
    /// and asserts only what the bits mean. That the signing those bits arm actually
    /// satisfies a server is a separate claim, and it is measured against a real Samba
    /// rather than here -- see the smb:// section of the README for the run and its numbers.
    #[test]
    fn the_negotiate_response_bits_that_arm_signing_and_the_credit_window_are_read_not_inferred() {
        // a negotiate response body, structure size 65, with the SecurityMode this arm is about
        let response = |security_mode: u16| {
            let mut b = Vec::new();
            b.extend_from_slice(&65u16.to_le_bytes());
            b.extend_from_slice(&security_mode.to_le_bytes());
            b.extend_from_slice(&0x0202u16.to_le_bytes()); // DialectRevision
            b.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
            b.extend_from_slice(&[0u8; 16]); // ServerGuid
            b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
            b.extend_from_slice(&(1u32 << 20).to_le_bytes()); // MaxTransactSize
            b.extend_from_slice(&(1u32 << 20).to_le_bytes()); // MaxReadSize
            b.extend_from_slice(&(1u32 << 20).to_le_bytes()); // MaxWriteSize
            b
        };
        // THE CAPABILITY THAT DECIDES THE CREDIT WINDOW, checked on the same synthetic
        // response, because it is the other thing this body carries that the client must
        // not infer. Reading it and discarding it, and deciding the charge from the dialect,
        // is right against every server tested -- Samba advertises 0x00000007, measured off
        // the wire -- and wrong against a 0x0300 server that does not advertise it, where a
        // 64 KiB read charges 2 and is refused.
        let with_caps = |dialect: u16, capabilities: u32| {
            let mut b = response(0);
            b[4..6].copy_from_slice(&dialect.to_le_bytes());
            b[24..28].copy_from_slice(&capabilities.to_le_bytes());
            b
        };
        let read_multi_credit = |b: &[u8]| {
            let dialect = u16::from_le_bytes([b[4], b[5]]);
            let caps = u32::from_le_bytes([b[24], b[25], b[26], b[27]]);
            dialect > 0x0202 && caps & LARGE_MTU != 0
        };
        assert!(
            read_multi_credit(&with_caps(0x0300, LARGE_MTU)),
            "0x0300 with LARGE_MTU has a credit window"
        );
        // THE CONTROL, and it is the defect: the same dialect WITHOUT the bit has no
        // window, and charging by dialect alone would have sent 2 for a 64 KiB read.
        assert!(
            !read_multi_credit(&with_caps(0x0300, 0)),
            "0x0300 without LARGE_MTU must not charge"
        );
        assert!(
            !read_multi_credit(&with_caps(0x0202, LARGE_MTU)),
            "0x0202 has no window whatever it advertises"
        );
        assert_eq!(
            proto::credit_charge(read_multi_credit(&with_caps(0x0300, 0)), 113, 65536 + 80),
            0
        );
        assert_eq!(
            proto::credit_charge(
                read_multi_credit(&with_caps(0x0300, LARGE_MTU)),
                113,
                65536 + 80
            ),
            2
        );

        // the field this client reads is the SecurityMode at offset 2 of the body
        let required = response(SIGNING_REQUIRED);
        assert_eq!(
            u16::from_le_bytes([required[2], required[3]]) & SIGNING_REQUIRED,
            SIGNING_REQUIRED
        );
        // THE CONTROL: a server that merely ENABLES signing sets bit 0 and not bit 1, and
        // must not read as requiring it. Getting this backwards does not lock the client
        // out -- it signs either way -- but it would put a CMAC over every byte of every
        // message on the common configuration, where nothing asked for one.
        // the module constant, not a local copy -- so this arm moves if the bit this
        // client SENDS ever moves, rather than agreeing with a second definition of it
        let enabled = response(SIGNING_ENABLED);
        assert_eq!(
            u16::from_le_bytes([enabled[2], enabled[3]]) & SIGNING_REQUIRED,
            0,
            "signing ENABLED must not read as signing REQUIRED"
        );
        assert_eq!(
            u16::from_le_bytes([response(0)[2], response(0)[3]]) & SIGNING_REQUIRED,
            0
        );

        // AND WHAT THIS CLIENT SENDS: MS-SMB2 2.2.3 states SIGNING_ENABLED as a MUST, so 0
        // is not a legal value here, even though some servers tolerate it. ENABLED is
        // capability; REQUIRED is the neighboring bit and stays clear because per MS-SMB2
        // 3.2.4.1.3 it mirrors the CLIENT's own RequireMessageSigning, which this client does
        // not set. It can sign; it does not demand that the server does.
        // byte 3, after the two-byte StructureSize and the one-byte Flags -- an offset that
        // is easy to get wrong, which is the whole reason this arm reads the built body
        // rather than trusting the line that writes it
        let sent = session_setup_body(b"blob", SIGNING_ENABLED);
        assert_eq!(
            sent[3], SIGNING_ENABLED as u8,
            "the session setup does not claim signing capability"
        );
        assert_eq!(
            sent[3] as u16 & SIGNING_REQUIRED,
            0,
            "by default the client must not demand signing"
        );
        // and -smb.sign puts REQUIRED in the same byte, which is what a server reads
        let demanded = session_setup_body(b"blob", SIGNING_ENABLED | SIGNING_REQUIRED);
        assert_eq!(
            demanded[3] as u16,
            SIGNING_ENABLED | SIGNING_REQUIRED,
            "-smb.sign must ask for a signed session"
        );
    }

    /// The NTLMv2 client challenge comes from the OS, and this arm is built around a
    /// clock-derived construction rather than around "is it random", which nothing this
    /// size can answer.
    ///
    /// The clock-derived value is `(nanos_since_epoch).rotate_left(17) ^ CONST`. Consecutive
    /// calls in a run differ only in the low bits of the clock, and rotating by 17 lands
    /// those in a narrow band -- so most BYTE POSITIONS never change across a whole run,
    /// while every sample is still distinct. An arm that only asked for distinct samples
    /// would pass on it. Asking every byte position to move is what separates the two.
    #[test]
    fn the_client_challenge_moves_in_every_byte_rather_than_tracking_the_clock() {
        let samples: Vec<[u8; 8]> = (0..64)
            .map(|_| client_nonce().expect("/dev/urandom"))
            .collect();
        let distinct: std::collections::HashSet<_> = samples.iter().collect();
        assert_eq!(
            distinct.len(),
            samples.len(),
            "the challenge repeated within 64 calls"
        );
        let moves = |xs: &[[u8; 8]]| {
            (0..8)
                .filter(|&i| {
                    xs.iter()
                        .map(|x| x[i])
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        > 1
                })
                .count()
        };
        assert_eq!(
            moves(&samples),
            8,
            "some byte of the challenge never changed across 64 calls"
        );

        // THE CONTROL: the clock-derived construction, sampled the same way. It is distinct every
        // time -- so it passes the first assertion -- and it must FAIL the second, which is
        // the whole reason that assertion is the one being made.
        let clock = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            (now.rotate_left(17) ^ 0x5851_f42d_4c95_7f2d).to_le_bytes()
        };
        let old: Vec<[u8; 8]> = (0..64).map(|_| clock()).collect();
        assert!(moves(&old) < 8, "the control did not reproduce the defect: the clock-derived challenge moved in every byte, so this arm proves nothing");
    }

    /// The three NTLMSSP messages, checked for the shapes a server reads them by, with no
    /// server involved. A wrong offset here produces a login failure and nothing else.
    #[test]
    fn the_ntlmssp_messages_have_the_shape_a_server_reads() {
        let neg = ntlmssp_negotiate("WORKGROUP");
        assert_eq!(&neg[0..8], NTLMSSP);
        assert_eq!(u32::from_le_bytes(neg[8..12].try_into().unwrap()), 1);

        // a type 2 built the way a server builds one, with target info after the header
        let mut chal = vec![0u8; 48];
        chal[0..8].copy_from_slice(NTLMSSP);
        chal[8..12].copy_from_slice(&2u32.to_le_bytes());
        chal[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let info = b"TARGETINFO";
        chal[40..42].copy_from_slice(&(info.len() as u16).to_le_bytes());
        chal[42..44].copy_from_slice(&(info.len() as u16).to_le_bytes());
        chal[44..48].copy_from_slice(&48u32.to_le_bytes());
        chal.extend_from_slice(info);
        let (c, ti) = ntlmssp_challenge(&chal).expect("parses");
        assert_eq!(c, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(ti, info);

        // a target info that points past the end is refused rather than read
        let mut bad = chal.clone();
        bad[44..48].copy_from_slice(&9999u32.to_le_bytes());
        assert!(
            ntlmssp_challenge(&bad).is_err(),
            "a target info past the end must be refused"
        );

        // and something that is not NTLMSSP at all
        assert!(ntlmssp_challenge(b"not ntlmssp at all, really not").is_err());

        // the type 3's payload offsets must land on the parts they name
        let (auth, _) = ntlmssp_authenticate("tester", "", "WORKGROUP", &c, &ti)
            .expect("/dev/urandom is readable");
        let field = |i: usize| {
            let at = 12 + i * 8;
            let len = u16::from_le_bytes(auth[at..at + 2].try_into().unwrap()) as usize;
            let off = u32::from_le_bytes(auth[at + 4..at + 8].try_into().unwrap()) as usize;
            auth[off..off + len].to_vec()
        };
        assert_eq!(field(0).len(), 24, "the LM response is 24 bytes");
        assert!(
            field(1).len() > 16,
            "the NT response is a proof plus a blob"
        );
        assert_eq!(
            field(2),
            ntlm::utf16le("WORKGROUP"),
            "the domain field does not point at the domain"
        );
        assert_eq!(
            field(3),
            ntlm::utf16le("tester"),
            "the user field does not point at the user"
        );
        // THE CONTROL: the fields are distinct, so the offsets are not all pointing at one
        // place and happening to satisfy the assertions above
        assert_ne!(field(2), field(3));
    }
}
