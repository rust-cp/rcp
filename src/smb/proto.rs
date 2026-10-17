//! The SMB2 wire: NetBIOS session framing, the 64-byte header, and the request and
//! response bodies this client uses.
//!
//! Every structure here is little-endian and every offset is from the start of the SMB2
//! HEADER, not from the start of the body -- a distinction MS-SMB2 states once and which
//! is the single most common way to get a parser subtly wrong, because an off-by-64 still
//! produces plausible-looking bytes.

use std::io;

pub const HEADER: usize = 64;

// Commands (MS-SMB2 2.2.1.2)
pub const NEGOTIATE: u16 = 0x0000;
pub const SESSION_SETUP: u16 = 0x0001;
pub const LOGOFF: u16 = 0x0002;
pub const TREE_CONNECT: u16 = 0x0003;
pub const TREE_DISCONNECT: u16 = 0x0004;
pub const CREATE: u16 = 0x0005;
pub const CLOSE: u16 = 0x0006;
pub const FLUSH: u16 = 0x0007;
pub const READ: u16 = 0x0008;
pub const WRITE: u16 = 0x0009;
pub const QUERY_DIRECTORY: u16 = 0x000e;
pub const QUERY_INFO: u16 = 0x0010;
pub const SET_INFO: u16 = 0x0011;

// Status codes worth naming, because a number here is a support ticket
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// An INTERIM response: the server has accepted the request and needs longer than its
/// timer allows, so it answers now and sends the real response later under the same message
/// id. MS-SMB2 3.3.4.2. It is not an error and it is not a failure, and a client that reads
/// it as either gives up on a request the server is still working on.
///
/// This is ordinary against a real server and never happens on the stand-in, which is
/// synchronous: a CREATE on a file another client holds with an oplock, a delete on a large
/// directory, a read from a jukebox or a tiered-storage recall. So the case that matters on
/// a Windows share is the one nothing here can produce.
pub const STATUS_PENDING: u32 = 0x0000_0103;
/// `SMB2_FLAGS_ASYNC_COMMAND` in the header's Flags.
pub const FLAGS_ASYNC_COMMAND: u32 = 0x0000_0002;
/// `SMB2_FLAGS_SERVER_TO_REDIR`: set on every response, clear on every request.
pub const FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
/// `SMB2_FLAGS_SIGNED`: this message carries a signature in bytes 48..64.
pub const FLAGS_SIGNED: u32 = 0x0000_0008;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_END_OF_FILE: u32 = 0xc000_0011;
/// A CREATE with disposition FILE_OPEN against a path that is not there.
///
/// NOT the same code as `STATUS_OBJECT_NAME_NOT_FOUND`, and forgetting it cost a real
/// defect: every "does this exist" path -- `stat`, the create-the-destination branch of
/// `connect`, and `remove`'s vanished-entry case -- tests `ErrorKind::NotFound`, and with
/// this code unmapped they all saw `Other`. The destination directory of a copy was
/// therefore not created, and the message was a bare `SMB status 0xc000000f`. It is also
/// the status a server with nothing at all to enumerate answers to the first
/// QUERY_DIRECTORY, which is where it was already handled -- that one place made it look
/// accounted for.
pub const STATUS_NO_SUCH_FILE: u32 = 0xc000_000f;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xc000_003a;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xc000_0035;
pub const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
pub const STATUS_LOGON_FAILURE: u32 = 0xc000_006d;
// Answers to an AUTHENTICATE that are about the ACCOUNT, not the password: values from
// MS-ERREF 2.3.1, checked on learn.microsoft.com 2026-09-27. STATUS_NETWORK_SESSION_EXPIRED
// is deliberately absent -- the page came back truncated before its value, and an
// unverified constant is worse than the conservative default it would replace.
pub const STATUS_ACCOUNT_RESTRICTION: u32 = 0xc000_006e;
pub const STATUS_INVALID_LOGON_HOURS: u32 = 0xc000_006f;
pub const STATUS_INVALID_WORKSTATION: u32 = 0xc000_0070;
pub const STATUS_PASSWORD_EXPIRED: u32 = 0xc000_0071;
pub const STATUS_ACCOUNT_DISABLED: u32 = 0xc000_0072;
pub const STATUS_LOGON_TYPE_NOT_GRANTED: u32 = 0xc000_015b;
pub const STATUS_ACCOUNT_EXPIRED: u32 = 0xc000_0193;
pub const STATUS_PASSWORD_MUST_CHANGE: u32 = 0xc000_0224;
pub const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xc000_0234;
// ...and answers that say nothing about the credential at all.
pub const STATUS_NO_LOGON_SERVERS: u32 = 0xc000_005e;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
pub const STATUS_REQUEST_NOT_ACCEPTED: u32 = 0xc000_00d0;
pub const STATUS_USER_SESSION_DELETED: u32 = 0xc000_0203;
pub const STATUS_DOMAIN_CONTROLLER_NOT_FOUND: u32 = 0xc000_0233;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xc000_0103;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xc000_00ba;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xc000_0101;
/// A delete refused because the file carries the read-only attribute. Named because it is
/// the status an ordinary resync hits on Windows and never on the stand-in, which does not
/// enforce it -- so "delete works" here is not a statement about a real share.
pub const STATUS_CANNOT_DELETE: u32 = 0xc000_0121;
/// What a server answers when it could not PARSE what it was sent, as distinct from
/// refusing what it understood. Worth its own words: a security blob a server's SPNEGO
/// layer will not read comes back as this, while a wrong password inside a blob that parsed
/// comes back as STATUS_LOGON_FAILURE. Collapsing both into "logon failed" hides the one a
/// person can actually act on.
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;

/// What a status code means, in words, for an error a person has to act on.
///
/// The fallback prints the hex rather than "unknown error", because the hex is
/// searchable and "unknown" is not.
pub fn status_text(status: u32) -> String {
    match status {
        STATUS_SUCCESS => "success".into(),
        STATUS_PENDING => "the server is still working on this (an interim response)".into(),
        STATUS_MORE_PROCESSING_REQUIRED => "more processing required".into(),
        STATUS_NO_MORE_FILES => "no more files".into(),
        STATUS_END_OF_FILE => "end of file".into(),
        STATUS_NO_SUCH_FILE => "no such file or directory".into(),
        STATUS_OBJECT_NAME_NOT_FOUND => "no such file".into(),
        STATUS_OBJECT_PATH_NOT_FOUND => "no such directory".into(),
        STATUS_OBJECT_NAME_COLLISION => "already exists".into(),
        STATUS_ACCESS_DENIED => "access denied".into(),
        STATUS_LOGON_FAILURE => "the server rejected the credentials".into(),
        STATUS_ACCOUNT_RESTRICTION => "the account is restricted from this logon".into(),
        STATUS_INVALID_LOGON_HOURS => "the account may not log on at this time".into(),
        STATUS_INVALID_WORKSTATION => "the account may not log on from this workstation".into(),
        STATUS_PASSWORD_EXPIRED => "the account's password has expired".into(),
        STATUS_ACCOUNT_DISABLED => "the account is disabled".into(),
        STATUS_LOGON_TYPE_NOT_GRANTED => "the account is not granted this type of logon".into(),
        STATUS_ACCOUNT_EXPIRED => "the account has expired".into(),
        STATUS_PASSWORD_MUST_CHANGE => {
            "the account's password must be changed before it can log on".into()
        }
        STATUS_ACCOUNT_LOCKED_OUT => "the account is locked out".into(),
        STATUS_NO_LOGON_SERVERS => {
            "the server could not reach a logon server to check the credential".into()
        }
        STATUS_INSUFFICIENT_RESOURCES => "the server is out of resources".into(),
        STATUS_REQUEST_NOT_ACCEPTED => "the server is not accepting more sessions".into(),
        STATUS_USER_SESSION_DELETED => "the server discarded the half-built session".into(),
        STATUS_DOMAIN_CONTROLLER_NOT_FOUND => {
            "the server could not find a domain controller".into()
        }
        STATUS_NOT_A_DIRECTORY => "not a directory".into(),
        STATUS_FILE_IS_A_DIRECTORY => "is a directory".into(),
        STATUS_DIRECTORY_NOT_EMPTY => "directory not empty".into(),
        STATUS_CANNOT_DELETE => "cannot be deleted; it is probably marked read-only".into(),
        STATUS_INVALID_PARAMETER => {
            "the server could not parse the request (which is not the same as refusing it)".into()
        }
        other => format!("SMB status 0x{other:08x}"),
    }
}

/// A little-endian reader that refuses to run off the end rather than panicking.
///
/// Every length and offset in an SMB2 response is attacker-controlled -- a hostile or
/// merely broken server can claim a name is 4 GB long -- so indexing is never done
/// directly. `Cursor` returns an error where a slice would panic, and the error names the
/// field rather than the byte, so a truncated response reports which structure ran out.
pub struct Cursor<'a> {
    pub buf: &'a [u8],
    pub at: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, at: 0 }
    }

    pub fn seek(&mut self, at: usize) -> io::Result<()> {
        if at > self.buf.len() {
            return Err(short(&format!(
                "a field at byte {at} in a {}-byte response",
                self.buf.len()
            )));
        }
        self.at = at;
        Ok(())
    }

    pub fn take(&mut self, n: usize, what: &str) -> io::Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or_else(|| short(what))?;
        if end > self.buf.len() {
            return Err(short(&format!(
                "{what}: {n} bytes at offset {} of a {}-byte response",
                self.at,
                self.buf.len()
            )));
        }
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn u8(&mut self, what: &str) -> io::Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &str) -> io::Result<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, what: &str) -> io::Result<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self, what: &str) -> io::Result<u64> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A slice named by an absolute offset and a length, which is how SMB2 carries every
    /// variable-length field. Both are checked against the whole response.
    pub fn at_offset(&self, offset: usize, len: usize, what: &str) -> io::Result<&'a [u8]> {
        let end = offset.checked_add(len).ok_or_else(|| short(what))?;
        if end > self.buf.len() {
            return Err(short(&format!(
                "{what}: {len} bytes at offset {offset} of a {}-byte response",
                self.buf.len()
            )));
        }
        Ok(&self.buf[offset..end])
    }
}

pub fn short(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the SMB response ends inside {what}"),
    )
}

/// UTF-16LE bytes back to a String, for names on the wire.
///
/// Unpaired surrogates are replaced rather than refused: a file whose name a Windows
/// server will happily store is not a reason to fail a listing, and the replacement is
/// visible.
pub fn from_utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// What one request costs, in credits AND in message ids (MS-SMB2 3.1.5.2).
///
/// **This is the field that decides whether this client works on a real server at all.**
/// A constant 0 costs every copy of a file over 64 KiB: Samba answers
/// `STATUS_INVALID_PARAMETER`, which surfaces as "the server could not parse the request",
/// naming nothing about the size of anything. Windows behaves the same way.
///
/// The stand-in cannot see it. impacket negotiates 0x0202, where the field is unused and
/// ignored, so the whole suite passes while a 300 KB file cannot cross to a real share.
/// Measured against Samba 4.19.5 with a constant 0: a 64 KiB file copied, a 64 KiB + 1
/// file did not, with MaxWriteSize reported as 8 MiB -- so it is not a size cap, it is this.
///
/// Two consequences, and the second is easy to miss because nothing warns about it:
///
/// - The charge must cover the LARGER of what is sent and what is expected back. A 1 MiB
///   READ sends 113 bytes and must still charge 16, or the server refuses the read.
/// - A request charging N consumes message ids `id .. id + N`, so the next request starts
///   at `id + N`. Charging correctly and then advancing the id by one re-uses ids the
///   server has already retired, which Samba and Windows both reject.
///
/// `multi_credit` is `Connection.SupportsMultiCredit` (MS-SMB2 3.2.5.2), which the CONNECTION
/// decides: a dialect above 0x0202 AND `SMB2_GLOBAL_CAP_LARGE_MTU` in the server's
/// Capabilities. When it is false the client MUST send 0. Deciding from the dialect alone
/// is right against every server tested and wrong against a 0x0300 server that does not
/// advertise the bit. So "0 is right for exactly one of the three dialects offered" is too
/// generous: 0 is right whenever the server has not offered a credit window.
pub fn credit_charge(multi_credit: bool, send_payload: usize, expected_response: usize) -> u16 {
    if !multi_credit {
        return 0;
    }
    let n = send_payload.max(expected_response).max(1) as u64;
    // The clamp is unreachable for any caller that keeps its I/O inside the negotiated
    // maximum -- 65535 credits is a 4 GiB payload -- but it is a SILENT clamp, and a
    // clamped charge is an UNDER-charge, which is the failure this whole function exists
    // to prevent. So the invariant is asserted where it can be seen rather than left in a
    // different file. It costs nothing in a release build.
    debug_assert!(
        n <= 65535 * 65536,
        "a {n}-byte payload would clamp the credit charge, and a clamped charge is an under-charge"
    );
    (((n - 1) / 65536) + 1).min(u16::MAX as u64) as u16
}

/// Builds an SMB2 request header. `credits` is left at the modest constant a
/// single-request-at-a-time client needs; `credit_charge` comes from `credit_charge`.
pub struct Header {
    pub command: u16,
    pub message_id: u64,
    pub session_id: u64,
    pub tree_id: u32,
    pub credits: u16,
    /// How many credits -- and how many message ids -- this request consumes.
    /// See `credit_charge`, which is where the rule and the reason live.
    pub credit_charge: u16,
}

impl Header {
    pub fn bytes(&self) -> Vec<u8> {
        let mut h = vec![0u8; HEADER];
        h[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        h[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        h[6..8].copy_from_slice(&self.credit_charge.to_le_bytes());
        h[8..12].copy_from_slice(&0u32.to_le_bytes()); // Status / ChannelSequence
        h[12..14].copy_from_slice(&self.command.to_le_bytes());
        h[14..16].copy_from_slice(&self.credits.to_le_bytes());
        h[16..20].copy_from_slice(&0u32.to_le_bytes()); // Flags
        h[20..24].copy_from_slice(&0u32.to_le_bytes()); // NextCommand
        h[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        h[32..36].copy_from_slice(&0u32.to_le_bytes()); // Reserved / AsyncId
        h[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        h[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        // The signature field is left zero here and filled in by the caller if this
        // connection signs -- see `Conn::call`. It MUST be zero while the signature is
        // computed, since the field is inside the bytes being signed, so a header that
        // arrives pre-zeroed is the right default rather than an omission.
        h
    }
}

/// The header fields of a response that the caller acts on.
#[derive(Debug, Clone, Copy)]
pub struct Reply {
    pub command: u16,
    pub status: u32,
    pub session_id: u64,
    pub tree_id: u32,
    pub message_id: u64,
    /// The header's Flags field, which carries `SMB2_FLAGS_ASYNC_COMMAND`. Read because an
    /// interim response is only interim when that bit is set; a STATUS_PENDING WITHOUT it
    /// is not a "wait for me", and treating it as one would hang on a malformed server.
    pub flags: u32,
    /// `CreditResponse`: how many credits this reply GRANTS. The client's balance is the
    /// running sum of these minus what it has charged.
    ///
    /// A client that does not read it cannot know what it is allowed to spend, and finds out
    /// only when a server refuses a request -- as `STATUS_INVALID_PARAMETER`, which says
    /// nothing about credits. Note too that a request-byte comparison can never see this
    /// quantity, since it lives entirely in the response.
    pub credits_granted: u16,
}

pub fn parse_header(buf: &[u8]) -> io::Result<Reply> {
    if buf.len() < HEADER {
        return Err(short("an SMB2 header"));
    }
    if buf[0..4] != [0xfe, b'S', b'M', b'B'] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "not an SMB2 response (protocol id {:02x?}); SMB1 servers are not supported",
                &buf[0..4]
            ),
        ));
    }
    Ok(Reply {
        status: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        command: u16::from_le_bytes([buf[12], buf[13]]),
        message_id: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        flags: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        credits_granted: u16::from_le_bytes([buf[14], buf[15]]),
        tree_id: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        session_id: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
    })
}

/// Windows FILETIME (100 ns ticks since 1601-01-01) to nanoseconds since the Unix epoch.
///
/// Zero means "not set" on the wire and is passed through as 0 rather than becoming 1601,
/// because a caller comparing times wants "unknown", not a date three centuries early.
pub fn filetime_to_unix_ns(ft: u64) -> i128 {
    if ft == 0 {
        return 0;
    }
    const EPOCH_DIFF_100NS: i128 = 116_444_736_000_000_000;
    (ft as i128 - EPOCH_DIFF_100NS) * 100
}

/// The inverse, for `SET_INFO`.
pub fn unix_ns_to_filetime(ns: i128) -> u64 {
    const EPOCH_DIFF_100NS: i128 = 116_444_736_000_000_000;
    let ticks = ns / 100 + EPOCH_DIFF_100NS;
    ticks.clamp(0, u64::MAX as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one conversion in this file that has a published fixed point: the Unix epoch is
    /// FILETIME 116444736000000000, stated in MS-DTYP.
    #[test]
    fn filetime_and_unix_time_agree_at_the_epoch_and_round_trip() {
        assert_eq!(filetime_to_unix_ns(116_444_736_000_000_000), 0);
        assert_eq!(unix_ns_to_filetime(0), 116_444_736_000_000_000);
        // a real instant, both ways
        let ns = 1_700_000_000_123_456_700i128;
        assert_eq!(filetime_to_unix_ns(unix_ns_to_filetime(ns)), ns);
        // zero is "not set", not 1601
        assert_eq!(filetime_to_unix_ns(0), 0);
        // THE CONTROL: a non-zero time before the Unix epoch is negative, so the mapping
        // is not silently clamping everything into the future
        assert!(filetime_to_unix_ns(1) < 0);
    }

    /// The formula at the boundary, which is where it breaks.
    ///
    /// With `CreditCharge` a constant 0, every file over 64 KiB fails to reach a real Samba
    /// or Windows server while the whole suite stays green, because impacket negotiates
    /// 0x0202, where the field is unused -- so this arm exists to decide the question
    /// WITHOUT a server, since the only server available here is the one that cannot see it.
    #[test]
    fn the_credit_charge_crosses_at_64_kib_and_is_zero_when_the_server_offers_no_window() {
        assert_eq!(
            credit_charge(true, 1, 0),
            1,
            "a one-byte request is one credit"
        );
        assert_eq!(
            credit_charge(true, 65536, 0),
            1,
            "64 KiB exactly is still one credit"
        );
        assert_eq!(credit_charge(true, 65537, 0), 2, "one byte more is two");
        assert_eq!(
            credit_charge(true, 1 << 20, 0),
            16,
            "a 1 MiB write is sixteen"
        );
        // THE HALF THAT IS EASY TO MISS: a READ sends ~113 bytes and gets a megabyte
        // back, so charging on what is SENT under-charges it and the server refuses.
        assert_eq!(
            credit_charge(true, 113, 1 << 20),
            16,
            "the charge covers the RESPONSE too"
        );
        // and a request with no payload at all is still one, never zero
        assert_eq!(credit_charge(true, 0, 0), 1);
        // THE CONTROL, and it is the reason a constant looked plausible: with no credit
        // window the field is reserved and MUST be 0. An implementation that charged
        // correctly whenever the dialect allowed it would be wrong here, which is why the
        // capability bit is read instead of inferred.
        assert_eq!(
            credit_charge(false, 1 << 20, 1 << 20),
            0,
            "no credit window means no charge"
        );
        assert_eq!(credit_charge(false, 1, 0), 0);
        // the field really lands at bytes 6..8 of the header, rather than this arm agreeing
        // with itself about a number nothing writes
        let h = Header {
            command: WRITE,
            message_id: 0,
            session_id: 1,
            tree_id: 1,
            credits: 64,
            credit_charge: 16,
        }
        .bytes();
        assert_eq!(
            u16::from_le_bytes([h[6], h[7]]),
            16,
            "CreditCharge is not at offset 6"
        );
    }

    /// Every length in a response is the server's to choose, so the reader has to refuse
    /// rather than panic. Rust would panic on a direct slice, which is a crash rather than
    /// an error message, and in a copy tool a crash loses the catalog.
    #[test]
    fn a_truncated_response_is_an_error_naming_the_field_rather_than_a_panic() {
        let buf = [1u8, 2, 3];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.u16("a count").unwrap(), 0x0201);
        let e = c.u32("a length").unwrap_err().to_string();
        assert!(e.contains("a length"), "{e}");
        assert!(c.seek(99).is_err(), "seeking past the end must be refused");
        let e = c
            .at_offset(2, usize::MAX, "a name")
            .unwrap_err()
            .to_string();
        assert!(e.contains("a name"), "{e}");
        // THE CONTROL: a read that fits still works, so the reader is not simply refusing
        // everything -- which would pass all three assertions above
        let mut c = Cursor::new(&buf);
        assert_eq!(c.take(3, "the lot").unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn a_header_round_trips_through_its_own_parser() {
        let h = Header {
            command: CREATE,
            message_id: 42,
            session_id: 0xdead_beef,
            tree_id: 7,
            credits: 1,
            credit_charge: 1,
        };
        let r = parse_header(&h.bytes()).expect("parses");
        assert_eq!(
            (r.command, r.message_id, r.session_id, r.tree_id),
            (CREATE, 42, 0xdead_beef, 7)
        );
        // an SMB1 response is refused by name rather than misread
        let mut smb1 = h.bytes();
        smb1[0..4].copy_from_slice(&[0xff, b'S', b'M', b'B']);
        let e = parse_header(&smb1).unwrap_err().to_string();
        assert!(e.contains("SMB1"), "{e}");
    }
}
