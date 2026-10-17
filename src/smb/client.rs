//! `SmbTree`: the `Tree` port over SMB2, so a Windows share, a Samba export or a NAS is an
//! endpoint. One connection per pooled session, each carrying its own tree id; a request is
//! answered before the next goes out, and the parallelism comes from rcp's worker pool.
//!
//! What SMB2 cannot say, stated here rather than left to be discovered:
//!
//! - **No modes and no owners.** A share carries DOS attributes, not a POSIX mode, so the
//!   adapter SYNTHESIZES `0o755`/`0o644` and uid 0 — and answers `keeps_modes` and
//!   `keeps_owner` with false so `verify` does not compare an invented number against a
//!   real one.
//! - **No symlinks and no hard links.** Reparse points exist in the protocol and are not
//!   this; both refuse by name, and `copy_tree` turns a refused hard link into a plain copy.
//! - **No extended attributes.** SMB2 has EAs, but they are a different namespace from
//!   `user.*` and mapping one onto the other would invent an equivalence; `keeps_xattrs` is
//!   false.
//! - **No hole map.** `FSCTL_QUERY_ALLOCATED_RANGES` could give one and is not used, so a
//!   sparse file is read by detecting zero runs, exactly as the sftp adapter does.
//!
//! Times ARE carried, both ways, through `FileBasicInformation`.

use crate::ports::KernelFileDescriptor as RawFd;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::conn::{login_verdict, status_error, Conn, LoginVerdict};
use super::ntlm;
use super::proto::{self, Cursor};
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::ports::{
    is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed, Segment,
    Sink, Tree,
};

/// How long a single socket operation may take before the connection is called dead.
const TIMEOUT: Duration = Duration::from_secs(60);

/// The same, for the handshake alone, which is shorter for a reason.
///
/// A READ of a megabyte off a loaded filer can legitimately take most of a minute. A
/// NEGOTIATE, a SESSION_SETUP or a TREE_CONNECT cannot: the server either answers those
/// promptly or is not going to. Sixty seconds there is not patience, it is the difference
/// between a retry that costs a moment and one nobody waits for.
///
/// **Ten seconds is a LAN number, so it has a knob.** Every
/// measurement behind it was taken against a Samba on loopback; a share reached over a
/// satellite hop, a congested VPN or a transcontinental link can legitimately need longer,
/// and there the short fuse turns a slow server into an unreachable one. `-smb.handshake
/// SECONDS` (or `RCP_SMB_HANDSHAKE`) moves it; this is what it is when nobody says.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many times a connection may be built before the attempt is reported.
const HANDSHAKE_ATTEMPTS: u32 = 3;

/// How many handshakes may fail in a row, across the whole pool, before the retry stops.
///
/// **The retry is on the hot path and needs a way to stop, and this is it.** The retry
/// exists for a race that resolves on a second connection: one failure in
/// forty-five, independent. When the server is actually gone -- stopped, firewalled, the
/// share deleted -- every failure is instead correlated, and the retry turns each worker's
/// one doomed connection into three plus two sleeps. A pool of sixteen workers then spends
/// its time dialing a host that is not there, and the error the operator finally sees is
/// the same one it would have seen immediately.
///
/// Twelve is deliberately well clear of the case the retry was measured for. IF failures
/// were independent at one in forty-five, twelve in a row would be about a 1-in-10^19
/// coincidence -- but they are not independent: the wedge happens "when several
/// connections are opened at once", so its failures cluster, and the figure is a way of
/// saying "far from anything the race was measured to do" rather than a probability. One
/// success re-arms it, so a recovered server costs one slow open and no more.
const HANDSHAKE_GIVE_UP_AFTER: usize = 12;

/// How many times IN A ROW a credential may go on the wire without the server accepting it,
/// for one account across this whole process, before this client refuses to offer it again.
///
/// **Classifying the error cannot bound this, which is why the budget exists at all.**
/// `worth_another_connection` retries `UnexpectedEof`, and a server that answers a bad
/// password by closing the socket produces exactly that -- so does a server that restarts
/// mid-login, or a network that drops. No `io::ErrorKind` separates them, because at this
/// layer they are the same event. What CAN be known is whether a credential went out and
/// what, if anything, the server said about it: see `Conn::credential_answer`.
///
/// **Two, and the premise behind the old value was wrong.** It was three, "because Active
/// Directory's own default lockout threshold is five and hardened policies use three". The
/// Default Domain Policy in fact ships with lockout DISABLED (threshold 0), and DISA's
/// Windows STIGs require a threshold of three or fewer -- so on exactly the domains that
/// lock accounts out, three equalled the threshold, and the comment's own rule condemned
/// it: a budget at or above the threshold is not a budget. Two leaves the operator one
/// attempt of their own under a threshold of three. (Those policy values are Microsoft's
/// and DISA's published defaults, taken on trust here, not measured.)
///
/// **Per ACCOUNT, not per pool**, because lockout counts per account: a copy whose source
/// and destination are shares in one domain, under one user, offers the same password to
/// both, and two pool-sized budgets would have been four attempts. It does NOT span runs:
/// each `rcp` process starts with a fresh budget, and nothing here can see what an earlier
/// one spent.
///
/// A success resets it -- but only for the CREDENTIAL that succeeded. Past the budget nothing
/// is offered, so nothing can succeed, and the refusal says so rather than promising that
/// "one success clears this" -- which the old message did, about a success it had just made
/// impossible.
const CREDENTIAL_GIVE_UP_AFTER: usize = 2;

/// What became of one offered credential.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Settled {
    /// The server said `STATUS_SUCCESS` and it survived every check this login makes -- on a
    /// signed session, its signature. Clears the credential's failure count, if every failure
    /// in it settled before this offer was reserved (`BudgetState::clock`).
    ///
    /// **It never clears an account latch.** If any success could clear one, a forged unsigned
    /// success would erase a real lockout. Restricting that to signed successes is not enough
    /// either: a genuine success delayed on the wire is authentic and still older than the
    /// lockout. Only a success reserved after the latch could supersede it, and `reserve`
    /// refuses a latched credential -- so the latch holds for the run, and a signed/unsigned
    /// split would have nothing left to distinguish.
    Accepted,
    /// `STATUS_SUCCESS` that could not be authenticated on a SIGNED session: unsigned, or signed
    /// with a key this login did not derive. It may be a forgery covering a real rejection, so
    /// it counts against the budget like one. See `Conn::credential_verified`.
    Unverified,
    /// The server refused the credential (`LoginVerdict::BadCredential`).
    Rejected,
    /// A status this client does not recognize as a verdict of any kind. Counted like a
    /// rejection -- the conservative default -- but named as what it is, not narrated as a
    /// password verdict.
    Other(u32),
    /// The credential went out and no answer came back -- or an answer that did not judge
    /// it (`LoginVerdict::Unjudged`). It may have been evaluated.
    Unanswered,
    /// The server refused the ACCOUNT, whatever the password -- locked out, disabled, expired.
    /// Counted, and this credential is not offered to this server again this run.
    Account(u32),
}

/// Offers in a row that ended without an accepted login, and of what kind.
#[derive(Default, Clone, Copy)]
struct Failures {
    /// Offers that ended `Unverified`, `Rejected`, `Unanswered`, `Other` or `Account`.
    failed: usize,
    /// How many of those were `Unanswered`, so the refusal can say which kind it saw.
    unanswered: usize,
    /// How many were `Unverified`, for the same reason.
    unverified: usize,
    /// How many were `Other`, and the last such status, so the refusal can name it.
    other: usize,
    last_other: Option<u32>,
    /// How many were `Account` (the server refused the account itself), and the last such
    /// status. Counted like every other failure toward the sum, but named as an account
    /// verdict rather than a rejected password -- the same distinction `Other` draws. Without
    /// this sub-counter an account lockout would be absorbed into `rejected` and the refusal
    /// would say "N rejected", the exact "check the password" narration the classification
    /// exists to avoid.
    account: usize,
    last_account: Option<u32>,
    /// The budget clock when the NEWEST of these failures settled. A success clears them only
    /// if its own offer was reserved after that -- see `BudgetState::clock`.
    newest: u64,
}

#[derive(Default)]
struct BudgetState {
    /// Failures in a row, PER CREDENTIAL -- the account's spelling and the password, as
    /// [`credential_id`] fingerprints them.
    ///
    /// **One count for the whole account would be a hole.** The budget merges every spelling
    /// of `alice` so that none of them gets a budget of its own. If a success reset that
    /// merged count, a copy from `smb://alice:WRONG@a/...` to `smb://alice:RIGHT@b/...` would
    /// let each success on the destination re-arm two more wrong offers on the source, without
    /// end: the reset would loosen what the merge was meant to tighten. Offers are gated on
    /// the SUM, which keeps the merge's bound; a success
    /// clears only its own credential's failures, because its own are the only ones it says
    /// anything about. The cost is that one credential's failures can refuse another that
    /// would have worked -- the conservative direction, and the copy it belongs to was
    /// failing on the wrong one anyway.
    by_credential: std::collections::HashMap<u64, Failures>,
    /// Offers reserved and not yet settled or released.
    in_flight: usize,
    /// Credentials a server refused outright (`Settled::Account`), with that server and its
    /// status. A refused credential is not offered again this run.
    ///
    /// **Per credential, not per ACCOUNT.** The budget is keyed by the bare user name across
    /// every server, so a per-account latch would let one server's "locked out" -- a local
    /// account, a policy that is that machine's own (LOGON_TYPE_NOT_GRANTED is "access this
    /// computer from the network"), or a single forged unsigned packet -- stop every `alice`
    /// on every server, name the WRONG server as the one that refused, and not be undone by a
    /// success elsewhere. What a
    /// server said about a credential is evidence about that credential at that server, and
    /// that is all it now stops. It still counts toward the account's sum, so it spends one
    /// of the account's offers.
    refused: std::collections::HashMap<u64, (String, u32)>,
    /// A logical clock, ticked when an offer is reserved and when a failure settles, so a
    /// success can tell which failures it actually supersedes.
    ///
    /// **Authentic is not fresh.** A signed success proves the server said
    /// it, not that the server said it AFTER the failure another offer reported. Two offers
    /// on two connections: A is accepted but its answer is slow; the password is changed; B
    /// comes back rejected; then A's success lands, and clearing B's failure would buy the
    /// budget an offer it should not have (and, if it were allowed to, clear a lockout latch
    /// the same way). Settlement order across connections is not the server's
    /// processing order, and neither is reservation order. The one order that IS established:
    /// a failure whose answer was already in hand when a success was reserved was processed
    /// by the server before that success's credential was even sent. So a success clears a
    /// credential's failures only if every one of them settled before it was reserved;
    /// otherwise it clears nothing, the conservative direction.
    clock: u64,
    /// Workers blocked in `reserve`. Only observed, by an arm that must know a worker is
    /// really waiting before it changes what the worker will find.
    waiting: usize,
}

impl BudgetState {
    /// Every credential's failures together, which is what the offers are gated on.
    fn totals(&self) -> Failures {
        self.by_credential
            .values()
            .fold(Failures::default(), |a, f| Failures {
                failed: a.failed + f.failed,
                unanswered: a.unanswered + f.unanswered,
                unverified: a.unverified + f.unverified,
                other: a.other + f.other,
                last_other: f.last_other.or(a.last_other),
                account: a.account + f.account,
                last_account: f.last_account.or(a.last_account),
                newest: a.newest.max(f.newest),
            })
    }
}

/// A fingerprint of one credential AT ONE SERVER: the host and port, the domain and user as
/// given, without case, and the password. Hashed under a per-process random key so the
/// password itself is not held here.
///
/// **The server is part of it because the same text can name two accounts.** `alice` with
/// password `P` can be a LOCAL account on each of two servers, right on B and wrong on A.
/// Without the server that is one fingerprint, so every success on B would clear A's
/// failures -- the hole the per-credential entries close, reached by identical text rather
/// than by collision. With the server in it, a success clears only what that server said
/// about that exact credential. A domain account used at two servers then clears less than
/// it could, which is the conservative direction.
///
/// It is tempting to call a collision harmless; it is not. Merging is neutral for the gate,
/// which sums anyway, but a success of one colliding credential clears the other's failures
/// -- the defect the per-credential entries exist to prevent. It needs two distinct
/// credentials for one account to agree on 64 bits of a keyed SipHash whose key never leaves
/// this process: about 2^-64 per pair, and not something an outsider can steer.
fn credential_id(server: &str, port: u16, domain: &str, user: &str, password: &str) -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    use std::sync::OnceLock;
    static KEY: OnceLock<RandomState> = OnceLock::new();

    KEY.get_or_init(RandomState::new).hash_one(&(
        server.to_lowercase(),
        port,
        domain.to_uppercase(),
        user.to_uppercase(),
        password,
    ))
}

/// The credential budget for one account. See [`CREDENTIAL_GIVE_UP_AFTER`].
///
/// **A slot is RESERVED before the credential goes out, because the obvious design
/// measurably overshoots.** Loading a counter, dialing, and incrementing after the failure
/// resolves is check-then-act: every worker that loads the counter before the first failure
/// lands goes ahead. Sixteen workers run that way against a stand-in refusing the password
/// sent sixteen AUTHENTICATEs against a budget of three. So `reserve` counts offers in
/// flight against the budget too, and a worker that would exceed it WAITS for one to settle
/// rather than offering: bounded, because every offer settles within the handshake deadline.
///
/// The cost is that at most two logins are in flight at once for one account. A pool of
/// sixteen workers opens its connections two at a time, which on a LAN is milliseconds and
/// on a long link is several round trips at startup -- paid once per connection, not per
/// file.
#[derive(Default)]
pub(crate) struct CredentialBudget {
    state: Mutex<BudgetState>,
    turn: std::sync::Condvar,
}

impl CredentialBudget {
    /// The budget for an account, shared by every pool in this process.
    ///
    /// Keyed by the BARE account name, without case -- `CORP\alice`, `alice@corp.example`,
    /// `.\alice` and plain `alice` are one budget. Keying by `(domain, user)` would treat the
    /// spellings Windows sees as one account as several, each with its own two offers.
    /// Mapping a UPN suffix to a NetBIOS domain needs
    /// a directory this client does not have, so the domain is dropped rather than guessed:
    /// two different domains' `alice`s then share a budget, which only tightens the bound.
    /// Not handled: Unicode normalization (`é` precomposed versus `e` plus a combining
    /// accent), which needs tables this dependency-free crate does not carry.
    fn for_account(user: &str) -> Arc<CredentialBudget> {
        use std::collections::HashMap;
        use std::sync::OnceLock;
        static ALL: OnceLock<Mutex<HashMap<String, Arc<CredentialBudget>>>> = OnceLock::new();
        // Normalized HERE, not only by `Settings::parts`, which already splits `DOMAIN\\user`,
        // so this function does the folding its comment claims when read on its own.
        // Anything after the last `\\` or `/`, before the first `@`.
        let bare = user.rsplit(['\\', '/']).next().unwrap_or(user);
        // UPPERcase, the direction Windows compares names in: lowercasing splits a Greek final
        // sigma from its medial form, which uppercase folds together. Not handled, and not
        // handleable here: a UPN prefix that differs from the sAMAccountName (`CORP\\flast`
        // versus `first.last@corp.com`) -- only the directory knows those are one account.
        let key = bare.split('@').next().unwrap_or(bare).to_uppercase();
        ALL.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(key)
            .or_default()
            .clone()
    }

    /// The refusal, if nothing more may be offered. Checked before DIALING, so a spent
    /// budget costs no connection at all.
    fn spent(&self, host: &str, credential: u64) -> Option<io::Error> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((origin, status)) = s.refused.get(&credential) {
            return Some(account_refusal(origin, *status));
        }
        let t = s.totals();
        (t.failed >= CREDENTIAL_GIVE_UP_AFTER).then(|| refusal(host, &t))
    }

    /// Takes a slot for one offer of `credential`, waiting while offers already in flight
    /// fill the rest.
    ///
    /// **Taken once the challenge is in hand, not before dialing.** Taking it ahead of the
    /// dial would spare a waiter from holding a connection halfway through NTLMSSP, which a
    /// server could expire. The price is worse: a connection that stalls BEFORE the
    /// AUTHENTICATE -- Samba 4.19.5 was measured doing that about one time in forty-five --
    /// would then hold a slot until the handshake deadline, and every worker for the account,
    /// on every host, would queue behind it. A measured stall rate outweighs an unmeasured
    /// expiry, so the slot is taken where only a ready credential waits for it.
    ///
    /// **Only the visible part of expiry is handled.** `Conn::login_offering` checks the
    /// connection after this returns and
    /// before writing, so a server that gave up and CLOSED the connection costs nothing. A
    /// server that forgets the exchange but keeps the socket open cannot be seen from here:
    /// the AUTHENTICATE goes out and is counted, as a rejection or no answer, against a
    /// password that may be right. Whether any real server does that within one handshake
    /// deadline is not measured.
    fn reserve(&self, host: &str, credential: u64) -> io::Result<Offer<'_>> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some((origin, status)) = s.refused.get(&credential) {
                return Err(account_refusal(origin, *status));
            }
            let t = s.totals();
            if t.failed >= CREDENTIAL_GIVE_UP_AFTER {
                return Err(refusal(host, &t));
            }
            if t.failed + s.in_flight < CREDENTIAL_GIVE_UP_AFTER {
                s.in_flight += 1;
                s.clock += 1;
                let reserved = s.clock;
                return Ok(Offer {
                    budget: self,
                    credential,
                    host: host.to_string(),
                    reserved,
                    sent: false,
                    open: true,
                });
            }
            s.waiting += 1;
            s = self.turn.wait(s).unwrap_or_else(|p| p.into_inner());
            s.waiting -= 1;
        }
    }

    /// Ends a reservation. `None` is one whose credential never went out, which says
    /// nothing about the credential and so changes nothing but the slot.
    /// `reserved` is the clock when this offer was reserved; a success clears only evidence
    /// that settled before it (see `BudgetState::clock`).
    fn settle(&self, credential: u64, host: &str, reserved: u64, how: Option<Settled>) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        debug_assert!(
            s.in_flight > 0,
            "an offer settled twice, or one never reserved"
        );
        s.in_flight = s.in_flight.saturating_sub(1);
        match how {
            None => {}
            Some(Settled::Accepted) => {
                // Clears the failure count -- a transient failure before a real success must
                // not spend the budget, and normal operation must not throttle after two
                // successes -- but only if every failure in it settled before this offer was
                // reserved: one that landed while this was in flight may be newer server state
                // than this success. The account latch is never touched (`Settled::Accepted`).
                //
                // **So "a transient failure before a real success" holds SEQUENTIALLY, not
                // under overlap**: failure, an overlapping success, then one
                // more failure spends a budget of two though the password is right. It cannot
                // persist -- after a failure the gate lets one offer fly at a time, and that
                // one's success always clears -- but the conservative rule does cost that case.
                if s.by_credential
                    .get(&credential)
                    .is_none_or(|f| f.newest < reserved)
                {
                    s.by_credential.remove(&credential);
                }
            }
            Some(how) => {
                s.clock += 1;
                let now = s.clock;
                let f = s.by_credential.entry(credential).or_default();
                f.failed += 1;
                f.newest = now;
                match how {
                    Settled::Unverified => f.unverified += 1,
                    Settled::Unanswered => f.unanswered += 1,
                    Settled::Other(status) => {
                        f.other += 1;
                        f.last_other = Some(status);
                    }
                    Settled::Account(status) => {
                        f.account += 1;
                        f.last_account = Some(status);
                        s.refused.insert(credential, (host.to_string(), status));
                    }
                    Settled::Rejected | Settled::Accepted => {}
                }
            }
        }
        drop(s);
        self.turn.notify_all();
    }
}

/// One reserved offer. Settles as `Unanswered` if dropped unsettled after its credential
/// went out, and is released uncounted if dropped before -- so an early return or a panic
/// cannot leak a slot and leave every other worker waiting in `reserve`.
struct Offer<'a> {
    budget: &'a CredentialBudget,
    credential: u64,
    /// The server this offer goes to, so a verdict about the account can name it.
    host: String,
    /// The budget clock when this offer was reserved (`BudgetState::clock`).
    reserved: u64,
    /// Whether the credential may have gone out. Set `true` the moment the slot is taken --
    /// presumed sent, so an unwind before the login returns is counted -- and corrected to
    /// `Conn::credential_sent` once it does. A panic therefore never releases the slot
    /// uncounted; `handshake` shows the presumption.
    sent: bool,
    open: bool,
}

impl Offer<'_> {
    fn settle(mut self, how: Settled) {
        self.open = false;
        self.budget.settle(
            self.credential,
            &self.host,
            self.reserved,
            self.sent.then_some(how),
        );
    }
}

impl Drop for Offer<'_> {
    fn drop(&mut self) {
        if self.open {
            self.budget.settle(
                self.credential,
                &self.host,
                self.reserved,
                self.sent.then_some(Settled::Unanswered),
            );
        }
    }
}

/// What a finished login says about the credential it offered. Its own function so the tests
/// can drive a real login and check the verdict it PRODUCES: tests that feed the budget
/// verdicts directly would stay green under a mapping that promoted a guest or an
/// unverified success to `Accepted`.
fn settlement(conn: &Conn) -> Settled {
    match conn.credential_answer {
        // A guest session for a named user is the server declining the credential.
        Some(proto::STATUS_SUCCESS) if conn.credential_guest => Settled::Rejected,
        Some(proto::STATUS_SUCCESS) if conn.credential_verified => Settled::Accepted,
        Some(proto::STATUS_SUCCESS) => Settled::Unverified,
        Some(status) => match login_verdict(status) {
            LoginVerdict::Account => Settled::Account(status),
            LoginVerdict::Unjudged => Settled::Unanswered,
            LoginVerdict::BadCredential => Settled::Rejected,
            LoginVerdict::Unknown => Settled::Other(status),
        },
        None => Settled::Unanswered,
    }
}

/// Why a credential is not offered again to the server that refused its account outright.
/// `origin` is that server -- the one this worker was about to dial, since the credential
/// fingerprint includes the server.
fn account_refusal(origin: &str, status: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{origin}: refusing to offer this credential to it again: the answer was an account-level refusal ({}), \
             which no password changes. The answer cannot be authenticated -- no key exists for a refused logon -- so if it is not what \
             the server's administrator sees, suspect the path to it. Otherwise resolve it there, then run again",
            proto::status_text(status)
        ),
    )
}

/// Why the budget stopped, in terms of what it actually saw -- and advice that fits it.
///
/// "Check the password" is the wrong advice for two of the three kinds: under `-smb.sign`
/// against a server that does not sign, the password is right and the server recorded a
/// successful logon. Each kind says what it points at, and a mix names every kind it
/// contains.
fn refusal(host: &str, s: &Failures) -> io::Error {
    // every failure settles as exactly one kind
    let rejected = s
        .failed
        .saturating_sub(s.unanswered + s.unverified + s.other + s.account);
    let mut seen = Vec::new();
    if rejected > 0 {
        seen.push(format!("{rejected} rejected"));
    }
    if s.account > 0 {
        // These verdicts were earned on the servers that REFUSED the account, not on `host`
        // (the target of this offer) -- the summed budget spans every server this account
        // reached. Naming `host` here would send the operator to the wrong machine, so the
        // wording keeps the verdict off it. The per-credential
        // `account_refusal` still names the exact origin server when the SAME credential is
        // refused again.
        seen.push(format!(
            "{} attempt(s) for this account were refused by their own server, not by this one and \
             not for the password (a lockout, a disabled or expired account, logon hours, a \
             workstation or logon-type restriction){}; no password can clear that -- resolve it on \
             the server that reported it",
            s.account,
            s.last_account
                .map(|st| format!(" -- last status: {}", proto::status_text(st)))
                .unwrap_or_default()
        ));
    }
    if s.unanswered > 0 {
        seen.push(format!(
            "{} ended with no verdict on the password -- the connection was lost, or the server answered without judging \
             it (a discarded session, no reachable domain controller); a server restarting mid-login looks exactly like one \
             refusing a password by hanging up",
            s.unanswered
        ));
    }
    if s.other > 0 {
        seen.push(format!(
            "{} answered with a status this client does not recognize as a verdict on the password{}",
            s.other,
            s.last_other.map(|st| format!(" (last: {})", proto::status_text(st))).unwrap_or_default()
        ));
    }
    if s.unverified > 0 {
        seen.push(format!(
            "{} said success but could not be authenticated -- unsigned, or signed with a key this login did not derive",
            s.unverified
        ));
    }
    let advice = if s.unverified > 0 {
        "An answer that cannot be authenticated is what a forgery covering a real rejection looks like, and also what a \
         server that does not sign looks like under -smb.sign; check the server's signing configuration before the password"
    } else if s.unanswered > 0 {
        "Check the password; if it is right and the server was restarting, run again once it answers"
    } else {
        "Check the password"
    };
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{host}: refusing to offer a password for this account again: passwords for it were offered {} times \
             without being accepted ({}; an accepted login clears only its own credential's count, so this total can \
             span several). Offering another is how an account gets locked out. {advice}",
            s.failed,
            seen.join("; ")
        ),
    )
}

/// The largest WRITE this client will issue, whatever the server's `MaxWriteSize` allows.
///
/// Named for the same reason as `CREDITS_REQUESTED`: the arm that checks the largest I/O
/// against the credit window reads it from here. Hardcoded there, raising the cap here
/// would not fail the arm that exists to catch exactly that.
const WRITE_CHUNK_CAP: u32 = 1 << 20;

/// Whether a failed handshake is worth trying again on a fresh connection.
///
/// **The distinction is the point, and getting it wrong is worse than not retrying at
/// all.** A transport failure -- a reset, a short read, a timeout -- says nothing about
/// the credentials, and a second connection usually works. A rejected password says
/// exactly what it says, and repeating it three times per connection, across a worker pool,
/// is how an account gets locked out. So the kinds are named rather than defaulted: this
/// returns false for anything it does not recognize, including `PermissionDenied` and
/// `NotFound`, which is the safe direction to be wrong in.
fn worth_another_connection(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

// DesiredAccess (MS-SMB2 2.2.13.1.1)
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

// CreateDisposition
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE_IF: u32 = 5;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// ShareAccess: let other clients keep working while a copy runs
const SHARE_ALL: u32 = 0x0000_0007;

// FileAttributes
const ATTR_DIRECTORY: u32 = 0x0000_0010;
const ATTR_NORMAL: u32 = 0x0000_0080;
const ATTR_REPARSE_POINT: u32 = 0x0000_0400;

// SET_INFO / QUERY_INFO classes (MS-FSCC 2.4)
const INFO_TYPE_FILE: u8 = 0x01;
const FILE_BASIC_INFORMATION: u8 = 4;
const FILE_RENAME_INFORMATION: u8 = 10;
const FILE_DISPOSITION_INFORMATION: u8 = 13;
const FILE_END_OF_FILE_INFORMATION: u8 = 20;

/// `FileBothDirectoryInformation`, the listing class every SMB2 server implements.
///
/// `FileIdBothDirectoryInformation` would additionally carry a file index, which on Samba
/// and Windows is the inode and would make hard-link detection possible. It is NOT used,
/// because the stand-in this is tested against leaves that field zero — so the branch that
/// read it could never be exercised here, and an unmeasured branch in a copy tool is worse
/// than a stated limit.
const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;

/// Where the fixed part of `FILE_BOTH_DIR_INFORMATION` ends and the name begins.
const BOTH_DIR_NAME_AT: usize = 94;

/// How much of a directory listing to ask for in one QUERY_DIRECTORY.
///
/// Named rather than inlined because it is the request's `OutputBufferLength` AND the
/// expected response size the credit charge is computed from, and those two drifting apart
/// is a class of bug that produces `STATUS_INVALID_PARAMETER` with nothing in the message
/// about sizes. Note the RESPONSE is larger than the page -- header plus fixed part -- so a
/// full page charges 2, not the 1 the page alone would suggest.
const QUERY_DIR_PAGE: u32 = 64 << 10;

type FileId = [u8; 16];

/// Credentials for a share. The password never appears in a URL; see the parser.
#[derive(Clone, Default)]
pub struct Settings {
    /// `-smb.user [DOMAIN\]USER:PASSWORD`, or `RCP_SMB_USER` with `RCP_SMB_PASSWORD`.
    pub user: Option<String>,
    /// `-smb.handshake SECONDS`, or `RCP_SMB_HANDSHAKE`. `None` is `HANDSHAKE_TIMEOUT`.
    pub handshake_secs: Option<u64>,
    /// `-smb.sign`, or `RCP_SMB_SIGN`: sign and verify every message whether or not the
    /// server asks. See [`Settings::requires_signing`].
    pub require_signing: bool,
}

impl Settings {
    /// `RCP_SMB_USER` with `RCP_SMB_PASSWORD`, joined into the one-string form the flag
    /// takes. The same shape as the WebDAV adapter's, and for the same reason: an option
    /// that can only be written on a command line is an option a detached job or an MCP
    /// server cannot carry without putting it in `ps`.
    fn from_env() -> String {
        match (
            std::env::var("RCP_SMB_USER"),
            std::env::var("RCP_SMB_PASSWORD"),
        ) {
            (Ok(u), Ok(p)) if !u.is_empty() => format!("{u}:{p}"),
            (Ok(u), _) if u.contains(':') => u,
            _ => String::new(),
        }
    }

    /// Splits the setting into domain, user and password.
    ///
    /// An absent setting is the guest login every SMB server offers and most refuse; that
    /// refusal is a `PermissionDenied` naming the share, which is the right answer for
    /// "you did not pass a credential" and does not need a second code path.
    fn parts(&self, url_user: Option<&str>) -> (String, String, String) {
        let raw = self.user.clone().unwrap_or_else(Settings::from_env);
        let (ident, password) = match raw.split_once(':') {
            Some((i, p)) => (i.to_string(), p.to_string()),
            None => (raw, String::new()),
        };
        // the URL's user is a default the flag overrides, so `smb://alice@host/share` with
        // `-smb.user bob:secret` logs in as bob rather than silently as alice
        let ident = if ident.is_empty() {
            url_user.unwrap_or("").to_string()
        } else {
            ident
        };
        let (domain, user) = match ident.split_once('\\') {
            Some((d, u)) => (d.to_string(), u.to_string()),
            None => match ident.split_once('/') {
                Some((d, u)) => (d.to_string(), u.to_string()),
                None => (String::new(), ident),
            },
        };
        (domain, user, password)
    }

    /// Whether this client insists on a signed session, from the flag or the environment.
    ///
    /// **This is what gives the final SESSION_SETUP check something to defend.** Without
    /// it, signing is armed only by the server's SecurityMode bit, which arrives in an
    /// unauthenticated NEGOTIATE response -- so an on-path attacker who clears it gets a
    /// client that signs nothing and checks nothing, and no check this side runs can notice,
    /// because the client had no expectation of its own. Set, the client arms the key
    /// whatever the bit says and sets SIGNING_REQUIRED in its own SESSION_SETUP, which is
    /// what makes a server that merely ENABLES signing sign the session anyway (MS-SMB2
    /// 3.3.5.5). A server that cannot sign is then refused rather than trusted.
    ///
    /// Off by default because it costs a MAC over every byte of every message on the
    /// configuration where nothing asked for one. `RCP_SMB_SIGN` counts when it is set to
    /// anything but empty or `0`.
    pub fn requires_signing(&self) -> bool {
        self.require_signing
            || std::env::var("RCP_SMB_SIGN").is_ok_and(|v| !v.is_empty() && v != "0")
    }

    /// How long a handshake may take, from the flag, then the environment, then the default.
    ///
    /// A zero or unparseable value falls back rather than erroring: this is a deadline, and
    /// a deadline of zero would make every connection fail instantly, which is a worse
    /// answer to a typo than ignoring it. The flag parser rejects a non-number before it
    /// reaches here; the environment has no parser, which is why this one is forgiving.
    fn handshake_timeout(&self) -> Duration {
        let from_env = || {
            std::env::var("RCP_SMB_HANDSHAKE")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        match self.handshake_secs.or_else(from_env) {
            Some(s) if s > 0 => Duration::from_secs(s),
            _ => HANDSHAKE_TIMEOUT,
        }
    }
}

/// One logged-in connection with one share connected.
struct Session {
    conn: Conn,
    tree: u32,
}

pub struct Pool {
    settings: Settings,
    url_user: Option<String>,
    host: String,
    port: u16,
    share: String,
    idle: Mutex<Vec<Session>>,
    /// This account's credential budget, shared with every other pool for the same account.
    /// Separate from `consecutive_failures` because the two bound different harms: that one
    /// bounds wasted latency against a server that is gone, this one bounds how many times
    /// a possibly-wrong password is offered. See `CREDENTIAL_GIVE_UP_AFTER`.
    credential: Arc<CredentialBudget>,
    /// Handshakes that have failed in a row since the last success. See
    /// [`HANDSHAKE_GIVE_UP_AFTER`]. Shared across the pool on purpose: the condition it
    /// detects is a property of the SERVER, so a worker that has not personally failed yet
    /// should still stop retrying.
    consecutive_failures: AtomicUsize,
}

impl Pool {
    /// This pool's credential, as the budget fingerprints it.
    fn credential_fingerprint(&self) -> u64 {
        let (domain, user, password) = self.settings.parts(self.url_user.as_deref());
        credential_id(&self.host, self.port, &domain, &user, &password)
    }

    /// One attempt at a connection, all the way to a connected tree.
    fn handshake(&self) -> io::Result<Session> {
        // No credential has gone out when this fails, so it cannot lock anything out.
        let mut conn = Conn::connect_requiring(
            &self.host,
            self.port,
            self.settings.handshake_timeout(),
            self.settings.requires_signing(),
        )?;
        let (domain, user, password) = self.settings.parts(self.url_user.as_deref());
        let credential = self.credential_fingerprint();
        let mut offer = None;
        let login = conn.login_offering(&user, &password, &domain, &mut || {
            let mut o = self
                .credential
                .reserve(&format!("{}:{}", self.host, self.port), credential)?;
            // Presumed SENT until the login says otherwise, below. If anything between here
            // and there unwinds, the `Offer` drops believing the credential went out, and is
            // counted -- the direction a lockout budget has to err in. Copying the flag only
            // after the login returned would release a slot uncounted on exactly that path.
            o.sent = true;
            offer = Some(o);
            Ok(())
        });
        let offer = offer.map(|mut o| {
            o.sent = conn.credential_sent;
            o
        });
        let how = settlement(&conn);
        if let Some(o) = offer {
            o.settle(how);
        }
        login?;
        // Past here the server ACCEPTED the credential, so nothing that follows can be
        // contributing to a lockout however it fails.
        //
        // The offer's deadline ends HERE, with the offer. Left running, it would bound the
        // tree connect too, so an AUTHENTICATE answered late in its deadline would leave the
        // tree connect almost none: it would time out, and a login that had succeeded would be
        // thrown away and the password sent again. The tree connect gets a fresh deadline of
        // its own -- an ABSOLUTE one, not the per-syscall socket timeout `set_timeout` leaves:
        // the latter lets a peer trickle the tree-connect reply a byte at a time and hang the
        // worker, since `read_by_deadline` falls back to `read_exact` when `self.deadline` is
        // None. It holds no budget slot, but a small fixed exchange should not hang.
        conn.arm_deadline(self.settings.handshake_timeout())?;
        let tree = conn.tree_connect(&self.share)?;
        // The short fuse was for the handshake. The session's own operations get the full
        // one, or a big read off a loaded filer would be called dead at ten seconds.
        conn.set_timeout(TIMEOUT)?;
        Ok(Session { conn, tree })
    }

    /// A connection, retrying a handshake that failed at the transport.
    ///
    /// **A connection that dies before TREE_CONNECT has written nothing**, so throwing it
    /// away and dialing again is not a retry of an operation -- there is no operation yet,
    /// no handle, no partial file, nothing for a second attempt to duplicate. That is what
    /// makes this safe where retrying a WRITE would not be.
    ///
    /// It is here because of a measured defect: against Samba 4.19.5, when several
    /// connections are opened at once, about one in forty-five never gets an answer to its
    /// SESSION_SETUP. The server reports its credit window as empty on a connection whose
    /// own NEGOTIATE response granted a credit. The wire says the client is not at fault in
    /// what it SENDS -- across 256 captured connections the NEGOTIATE and SESSION_SETUP
    /// bytes hash to one value each, wedged and healthy alike -- so there is nothing to
    /// correct in the message, and the honest fix at this layer is to notice and dial again.
    fn open(&self) -> io::Result<Session> {
        use std::sync::atomic::Ordering;
        // THE BREAKER. Past the threshold the retry is switched off -- one attempt, no
        // sleep -- because every failure so far says the server is gone rather than racing,
        // and a retry against a gone server is pure latency charged to the operator.
        // Reading it here rather than at each attempt is deliberate: an open that is
        // already under way finishes under the rules it started with.
        let attempts =
            if self.consecutive_failures.load(Ordering::Relaxed) >= HANDSHAKE_GIVE_UP_AFTER {
                1
            } else {
                HANDSHAKE_ATTEMPTS
            };
        let mut last = None;
        for attempt in 0..attempts {
            // THE CREDENTIAL BUDGET, checked before DIALING so a spent budget costs no
            // connection. This is only the fast path: the binding check is `reserve`, taken
            // immediately before the AUTHENTICATE goes out, because between here and there
            // another worker may spend what is left.
            if let Some(refused) = self
                .credential
                .spent(&self.host, self.credential_fingerprint())
            {
                return Err(refused);
            }
            match self.handshake() {
                Ok(s) => {
                    // A success re-arms the retry for everyone. Not a decrement: the
                    // condition is "the server is answering again", and that is a fact
                    // about the server, not a credit to be spent down one failure at a time.
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                    return Ok(s);
                }
                // A login the server never answered IS retried. It is tempting to reason that
                // Samba's wedge always strikes the first, credential-free SESSION_SETUP, so a
                // retry after the AUTHENTICATE could only re-offer a password to cure a race
                // it had not lost. Measured against Samba 4.19.5, sixteen workers, that is
                // false: a run that did not retry failed with `os error 11` -- the read
                // timeout -- waiting on the AUTHENTICATE's reply, where a build that retried
                // succeeded. Refusing to retry there turns a transient into a failed file.
                //
                // What bounds the password now is the reservation, not this arm: every
                // retry that reaches the AUTHENTICATE takes a slot, and an unanswered offer
                // keeps it spent. The price, stated rather than hidden: against a server
                // that keeps hanging up after the credential -- one restarting mid-login --
                // a single open can spend the whole budget, and the rest of the run is
                // refused with a message that says it saw hang-ups, not rejections.
                Err(e) if worth_another_connection(&e) => {
                    self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                    // A short, growing, JITTERED pause. Growing because the failure is a
                    // race lost during connection setup, and dialing again instantly is the
                    // one thing likely to lose it the same way. Jittered because a fixed
                    // delay makes N workers that failed together retry together, turning one
                    // spike into three synchronized ones -- and it is cheap enough to fix
                    // that leaving the anti-pattern in would be a choice.
                    //
                    // The jitter source is the thread id and the attempt, not a random
                    // number generator: this crate has no rand dependency, and the property
                    // needed is only that concurrent workers differ from each other.
                    if attempt + 1 < attempts {
                        let base = 50u64 << attempt;
                        let spread = {
                            let id = format!("{:?}", std::thread::current().id());
                            id.bytes()
                                .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64))
                        };
                        std::thread::sleep(Duration::from_millis(base + spread % base));
                    }
                    last = Some(e);
                }
                Err(e) => {
                    // NOT counted against the BREAKER. A refused credential is not a server
                    // that is down, and letting it trip the breaker would make one bad
                    // password switch the retry off for every worker against a server that
                    // is answering fine. The credential budget has already counted it, in
                    // `handshake`, when the offer settled.
                    return Err(e);
                }
            }
        }
        // The attempts are named, because "connection reset" on its own invites someone to
        // go looking at the network for a fault that is in the handshake.
        //
        // And when the breaker is what limited them, SAY SO. `{attempts}` alone would read
        // "the handshake failed on 1 connections in a row", which is both ungrammatical and
        // actively misleading: it hides that this server has been failing for a while and
        // makes a long-dead host look like a single unlucky connection.
        let e = last.expect("a loop that ran at least once recorded an error");
        let how = if attempts == 1 {
            format!(
                "the handshake failed, and the retry is off after {} failures in a row -- this server has not answered for a while",
                self.consecutive_failures.load(Ordering::Relaxed)
            )
        } else {
            format!("the handshake failed on {attempts} connections in a row")
        };
        Err(io::Error::new(
            e.kind(),
            format!("{}: {how}: {e}", self.host),
        ))
    }

    fn take(&self) -> io::Result<Session> {
        if let Some(s) = self.idle.lock().unwrap().pop() {
            return Ok(s);
        }
        self.open()
    }

    fn give(&self, s: Session) {
        // A connection left mid-exchange is never pooled (`Conn::broken`): the connect probe
        // gives a session back after ANY failed create, a transport error among them.
        if s.conn.broken {
            return;
        }
        self.idle.lock().unwrap().push(s);
    }

    fn with<R>(&self, f: impl FnOnce(&mut Session) -> io::Result<R>) -> io::Result<R> {
        let mut s = self.take()?;
        let r = f(&mut s);
        // A connection that failed mid-exchange may have a reply still in the socket, and
        // handing it to the next caller would answer the wrong request. `Conn::broken` is the
        // guard that holds (the message-id check is not a framing guard -- bytes that frame
        // with the expected id pass it); this drop is the pool's half of it, and also drops
        // a session whose exchange finished with an error status, which costs a connection
        // and nothing else.
        match &r {
            Ok(_) => self.give(s),
            Err(_) => drop(s),
        }
        r
    }
}

/// What a CREATE answered with: the handle, and the metadata that saves a QUERY_INFO.
struct Opened {
    id: FileId,
    attributes: u32,
    size: u64,
    mtime: u64,
    atime: u64,
}

impl Session {
    fn create(
        &mut self,
        path: &str,
        access: u32,
        attrs: u32,
        disposition: u32,
        options: u32,
        what: &str,
    ) -> io::Result<Opened> {
        let name = ntlm::utf16le(path);
        // NameLength is 16 bits. A longer path would wrap (65538 bytes encoded as 2) and the
        // server would open a one-character prefix of it -- on the write side, a different
        // file.
        if name.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{what}: a path of {} UTF-16 bytes, past the 65535 an SMB2 name can carry",
                    name.len()
                ),
            ));
        }
        let mut body = Vec::with_capacity(56 + name.len());
        body.extend_from_slice(&57u16.to_le_bytes()); // StructureSize
        body.push(0); // SecurityFlags
        body.push(0); // RequestedOplockLevel: none
        body.extend_from_slice(&2u32.to_le_bytes()); // ImpersonationLevel: Impersonation
        body.extend_from_slice(&0u64.to_le_bytes()); // SmbCreateFlags
        body.extend_from_slice(&0u64.to_le_bytes()); // Reserved
        body.extend_from_slice(&(access | SYNCHRONIZE | FILE_READ_ATTRIBUTES).to_le_bytes());
        body.extend_from_slice(&attrs.to_le_bytes());
        body.extend_from_slice(&SHARE_ALL.to_le_bytes());
        body.extend_from_slice(&disposition.to_le_bytes());
        body.extend_from_slice(&options.to_le_bytes());
        body.extend_from_slice(&((proto::HEADER + 56) as u16).to_le_bytes()); // NameOffset
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        body.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        if name.is_empty() {
            // The share root. MS-SMB2 2.2.13 says the buffer is one padding byte when the
            // name is empty; sending a zero-length body would leave the structure size
            // disagreeing with what was sent.
            body.push(0);
        } else {
            body.extend_from_slice(&name);
        }

        let (reply, buf) = self.conn.request(proto::CREATE, self.tree, &body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        let mut c = Cursor::new(&buf);
        c.seek(proto::HEADER)?;
        let size = c.u16("the create response size")?;
        if size != 89 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: a create response of structure size {size}, not 89"),
            ));
        }
        c.u8("the oplock level")?;
        c.u8("the create flags")?;
        c.u32("the create action")?;
        c.u64("the creation time")?;
        let atime = c.u64("the last access time")?;
        let mtime = c.u64("the last write time")?;
        c.u64("the change time")?;
        c.u64("the allocation size")?;
        let eof = c.u64("the end of file")?;
        let attributes = c.u32("the file attributes")?;
        c.u32("the reserved field")?;
        let mut id = [0u8; 16];
        id.copy_from_slice(c.take(16, "the file id")?);
        Ok(Opened {
            id,
            attributes,
            size: eof,
            mtime,
            atime,
        })
    }

    /// Asks the server to put the file's data on stable storage (MS-SMB2 2.2.17).
    fn flush(&mut self, id: &FileId, what: &str) -> io::Result<()> {
        let mut body = Vec::with_capacity(24);
        body.extend_from_slice(&24u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        body.extend_from_slice(id);
        let (reply, _) = self.conn.request(proto::FLUSH, self.tree, &body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        Ok(())
    }

    fn close(&mut self, id: &FileId) -> io::Result<()> {
        let mut body = Vec::with_capacity(24);
        body.extend_from_slice(&24u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // Flags: no post-query attributes
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        body.extend_from_slice(id);
        let (reply, _) = self.conn.request(proto::CLOSE, self.tree, &body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, "closing a handle"));
        }
        Ok(())
    }

    /// Reads at most `len` bytes at `offset`; an empty answer means end of file.
    fn read_at(&mut self, id: &FileId, offset: u64, len: u32, what: &str) -> io::Result<Vec<u8>> {
        let mut body = Vec::with_capacity(49);
        body.extend_from_slice(&49u16.to_le_bytes());
        body.push(0); // Padding: MS-SMB2 requires this byte to be zero on a request
        body.push(0); // Flags
        body.extend_from_slice(&len.to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(id);
        body.extend_from_slice(&1u32.to_le_bytes()); // MinimumCount
        body.extend_from_slice(&0u32.to_le_bytes()); // Channel
        body.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        body.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // ReadChannelInfoLength
        body.push(0); // Buffer

        // THE DATA, not the message -- and this was the message until the spec was read.
        //
        // An audit of 545 captured pairs showed a 1 MiB read weighing 1048656 bytes on the
        // wire, so charging `len` alone looked like an under-charge by one credit and this
        // was "corrected" to HEADER + fixed + len. MS-SMB2 3.1.5.2 says otherwise, in terms
        // that leave no room: the charge is computed from "the payload size (the size of
        // the data within the variable-length field of the request) or the maximum size of
        // the response". The header and the fixed part are not payload. A 1 MiB read is 16,
        // which is what Windows sends, and 3.3.5.2.5 has the server compute the same
        // number from the same definition -- so both ends now agree exactly instead of this
        // one paying a credit and a message id per read to be safe.
        let (reply, buf) = self.conn.request(proto::READ, self.tree, &body, 0, len)?;
        if reply.status == proto::STATUS_END_OF_FILE {
            return Ok(Vec::new());
        }
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        let c = Cursor::new(&buf);
        let mut r = Cursor::new(&buf);
        r.seek(proto::HEADER)?;
        r.u16("the read response size")?;
        let data_offset = r.u8("the data offset")? as usize;
        r.u8("the read reserved byte")?;
        let data_len = r.u32("the data length")? as usize;
        // The data starts after the response's fixed part. An offset inside the header is
        // the header returned as file content; `at_offset` only checks the
        // frame's end.
        if data_len > 0 && data_offset < proto::HEADER + 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: read data at offset {data_offset}, inside the response header"),
            ));
        }
        // More than was asked for is a protocol violation, and the reader would advance its
        // offset by it: refused, as `SmbSink::write` refuses a count larger than it offered.
        if data_len > len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: the server returned {data_len} bytes to a {len}-byte read"),
            ));
        }
        Ok(c.at_offset(data_offset, data_len, "the data of a read")?
            .to_vec())
    }

    fn write_at(&mut self, id: &FileId, offset: u64, data: &[u8], what: &str) -> io::Result<u32> {
        let mut body = Vec::with_capacity(48 + data.len());
        body.extend_from_slice(&49u16.to_le_bytes());
        body.extend_from_slice(&((proto::HEADER + 48) as u16).to_le_bytes()); // DataOffset
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(id);
        body.extend_from_slice(&0u32.to_le_bytes()); // Channel
        body.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
        body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
        body.extend_from_slice(&0u32.to_le_bytes()); // Flags
        body.extend_from_slice(data);

        // The data written is this request's payload; the response carries none.
        let (reply, buf) =
            self.conn
                .request(proto::WRITE, self.tree, &body, data.len() as u32, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        let mut r = Cursor::new(&buf);
        r.seek(proto::HEADER)?;
        r.u16("the write response size")?;
        r.u16("the write reserved field")?;
        r.u32("the written count")
    }

    fn set_info(&mut self, id: &FileId, class: u8, payload: &[u8], what: &str) -> io::Result<()> {
        let mut body = Vec::with_capacity(32 + payload.len());
        body.extend_from_slice(&33u16.to_le_bytes());
        body.push(INFO_TYPE_FILE);
        body.push(class);
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(&((proto::HEADER + 32) as u16).to_le_bytes()); // BufferOffset
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // AdditionalInformation
        body.extend_from_slice(id);
        body.extend_from_slice(payload);
        let (reply, _) = self.conn.request(proto::SET_INFO, self.tree, &body, 0, 0)?;
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        Ok(())
    }

    /// One page of a directory listing; `None` once the server says there are no more.
    fn query_dir(&mut self, id: &FileId, what: &str) -> io::Result<Option<Vec<Entry>>> {
        let pattern = ntlm::utf16le("*");
        let mut body = Vec::with_capacity(32 + pattern.len());
        body.extend_from_slice(&33u16.to_le_bytes());
        body.push(FILE_BOTH_DIRECTORY_INFORMATION);
        body.push(0); // Flags: continue from where the last call stopped
        body.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        body.extend_from_slice(id);
        body.extend_from_slice(&((proto::HEADER + 32) as u16).to_le_bytes()); // FileNameOffset
        body.extend_from_slice(&(pattern.len() as u16).to_le_bytes());
        body.extend_from_slice(&QUERY_DIR_PAGE.to_le_bytes()); // OutputBufferLength
        body.extend_from_slice(&pattern);

        // `OutputBufferLength` IS the maximum response payload, and it is the field
        // 3.3.5.2.5 tells the server to validate a QUERY_DIRECTORY against -- so the two
        // sides read the same number out of the same field. A 64 KiB page charges 1; adding
        // the header and the fixed part to it charged 2 for no reason.
        let (reply, buf) =
            self.conn
                .request(proto::QUERY_DIRECTORY, self.tree, &body, 0, QUERY_DIR_PAGE)?;
        // Either status ends the enumeration, in ANY position -- a COMPATIBILITY choice, and
        // it has a cost. Accepting NO_SUCH_FILE only as the first answer would catch a server
        // that lost its search state mid-listing and said so this way, which otherwise cuts
        // the listing short with no error. But servers are reported ending enumerations with
        // it, and a maintained client (smbprotocol) treats it as the end wherever it comes, so
        // refusing it risks failing every non-empty listing on such a server. Whether the spec
        // sanctions it is disputed; it may not. What is traded away is detecting that one
        // truncation, and that is said here rather than presented as the protocol's blessing.
        if reply.status == proto::STATUS_NO_MORE_FILES || reply.status == proto::STATUS_NO_SUCH_FILE
        {
            return Ok(None);
        }
        if reply.status != proto::STATUS_SUCCESS {
            return Err(status_error(reply.status, what));
        }
        let c = Cursor::new(&buf);
        let mut r = Cursor::new(&buf);
        r.seek(proto::HEADER)?;
        r.u16("the query directory response size")?;
        let offset = r.u16("the output buffer offset")? as usize;
        let len = r.u32("the output buffer length")? as usize;
        // As for READ: the listing starts after the fixed part, not inside the header.
        if len > 0 && offset < proto::HEADER + 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what}: a listing at offset {offset}, inside the response header"),
            ));
        }
        let page = c.at_offset(offset, len, "a directory listing")?;
        Ok(Some(parse_both_dir(page)?))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    /// Why this name cannot be carried as a path -- an unpaired surrogate, which NTFS allows
    /// and UTF-8 cannot hold, or a path separator. The listing reports such an entry and does
    /// not copy it: decoding it lossily would let two names collide, and refusing the whole
    /// directory over one legitimate NTFS name would fail a working copy.
    pub unrepresentable: Option<&'static str>,
    /// The name's raw UTF-16 bytes: its identity. `name` is lossy for an unrepresentable
    /// entry, so two different raw names can share it -- a lone surrogate and a real U+FFFD
    /// both read "\u{fffd}" -- and deduplicating on `name` would drop the valid one as a
    /// duplicate of the flagged one.
    pub raw: Vec<u8>,
    pub attributes: u32,
    pub size: u64,
    pub mtime: u64,
    pub atime: u64,
}

/// Pages in a row that may add no new name before a listing is refused as not advancing.
///
/// Three is too tight: a server with an ordinal cursor, under concurrent
/// inserts ahead of it, can hand back the same entry several pages running and still finish.
/// A stale page adds nothing to memory -- duplicates are dropped -- so a larger bound costs
/// only round trips before a truly stuck server is refused.
const STALE_PAGES: usize = 16;

/// One page of `FILE_BOTH_DIR_INFORMATION` records.
///
/// `NextEntryOffset` is the server's, so a zero-or-backwards value would loop forever and a
/// large one would read past the page. Both are refused: the walk only ever moves forward,
/// and within the page it was given.
fn parse_both_dir(page: &[u8]) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        if at + BOTH_DIR_NAME_AT > page.len() {
            return Err(proto::short("a directory entry"));
        }
        let rec = &page[at..];
        let u32at = |o: usize| u32::from_le_bytes(rec[o..o + 4].try_into().expect("4 bytes"));
        let u64at = |o: usize| u64::from_le_bytes(rec[o..o + 8].try_into().expect("8 bytes"));
        let next = u32at(0) as usize;
        let name_len = u32at(60) as usize;
        let end = BOTH_DIR_NAME_AT
            .checked_add(name_len)
            .ok_or_else(|| proto::short("a directory entry name"))?;
        if end > rec.len() {
            return Err(proto::short("a directory entry name"));
        }
        // Decoded STRICTLY. Lossy decoding turns every unpaired surrogate into U+FFFD, so two
        // names differing only there come out equal and one file overwrites the other at the
        // destination. An empty name is no entry at all, and at the share root it would name
        // the root itself.
        let raw = &rec[BOTH_DIR_NAME_AT..end];
        if raw.is_empty() || !raw.len().is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a directory entry with a {}-byte name", raw.len()),
            ));
        }
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let (name, unrepresentable) = match String::from_utf16(&units) {
            Ok(n) if n.contains('\\') || n.contains('/') => {
                (n, Some("a name containing a path separator"))
            }
            Ok(n) => (n, None),
            Err(_) => (
                String::from_utf16_lossy(&units),
                Some("a name that is not valid UTF-16 (an unpaired surrogate, which NTFS allows)"),
            ),
        };
        out.push(Entry {
            name,
            unrepresentable,
            raw: raw.to_vec(),
            attributes: u32at(56),
            size: u64at(40),
            atime: u64at(16),
            mtime: u64at(24),
        });
        if next == 0 {
            return Ok(out);
        }
        // The next record must start AFTER this one's name ends. `next >= BOTH_DIR_NAME_AT`
        // is not enough: an offset in
        // `[94, 94 + FileNameLength)` leaves the name -- which is sliced by its own declared
        // length -- running into the next record's header, so the name swallows a record and
        // the walk then parses the middle of a name as an entry. Names, sizes and times all
        // come out wrong and nothing errors. Padding AFTER the name is legal and still is;
        // overlap is not.
        if next < end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a directory listing whose next-entry offset is {next}, inside the {end}-byte record it came from"),
            ));
        }
        // On a 32-bit target `at += next` wraps rather than running off the page, and a
        // wrapped cursor lands back inside the buffer and parses garbage. Checked, like
        // every other offset here.
        at = at
            .checked_add(next)
            .ok_or_else(|| proto::short("a directory listing"))?;
        // A next record that starts PAST the page is a chain cut short, and returning the
        // entries so far would read it as complete. Exactly at the end is a server
        // that set the offset where it could have set zero, and is taken as the end.
        if at > page.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "a directory listing whose next entry starts at {at}, past its {}-byte page",
                    page.len()
                ),
            ));
        }
        if at == page.len() {
            return Ok(out);
        }
    }
}

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Which port kind a set of DOS attributes describes.
///
/// A reparse point is NOT reported as a symlink: the protocol would need
/// `FSCTL_GET_REPARSE_POINT` to say what it points at, this client does not issue one, and
/// calling it a symlink with no target would put a broken link in every catalog. It is
/// skipped, and `list` says so once per listing.
fn kind_of(attributes: u32) -> Option<Kind> {
    if attributes & ATTR_REPARSE_POINT != 0 {
        return None;
    }
    Some(if attributes & ATTR_DIRECTORY != 0 {
        Kind::Dir
    } else {
        Kind::File
    })
}

pub struct SmbTree {
    pool: Arc<Pool>,
    /// The path inside the share, backslash-separated, with no leading or trailing
    /// separator. Empty at the share root.
    root: String,
    display: PathBuf,
}

impl SmbTree {
    pub fn connect(
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        share: &str,
        path: &Path,
        create: bool,
        settings: &Settings,
        log: &dyn crate::ports::Log,
    ) -> io::Result<SmbTree> {
        let port = port.unwrap_or(445);
        let root = path.to_string_lossy().trim_matches('/').replace('/', "\\");
        let (_, account, _) = settings.parts(user);
        let pool = Arc::new(Pool {
            credential: CredentialBudget::for_account(&account),
            settings: settings.clone(),
            url_user: user.map(str::to_string),
            host: host.to_string(),
            port,
            share: share.to_string(),
            idle: Mutex::new(Vec::new()),
            consecutive_failures: AtomicUsize::new(0),
        });
        let display = PathBuf::from(format!(
            "smb://{}{host}{}/{share}{}",
            user.map(|u| format!("{u}@")).unwrap_or_default(),
            if port == 445 {
                String::new()
            } else {
                format!(":{port}")
            },
            if root.is_empty() {
                String::new()
            } else {
                format!("/{}", root.replace('\\', "/"))
            }
        ));
        let tree = SmbTree {
            pool,
            root,
            display,
        };

        // Reach the directory once here rather than failing later inside a worker, and
        // create it when asked, the way every other adapter's `connect` does.
        let mut s = tree.pool.take()?;
        let probe = s.create(
            &tree.root,
            FILE_READ_ATTRIBUTES,
            0,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            &format!("opening {}", tree.display.display()),
        );
        match probe {
            Ok(o) => {
                let _ = s.close(&o.id);
                if o.attributes & ATTR_DIRECTORY == 0 {
                    tree.pool.give(s);
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        format!("{}: not a directory", tree.display.display()),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create && !tree.root.is_empty() => {
                let o = s.create(
                    &tree.root,
                    FILE_READ_ATTRIBUTES,
                    ATTR_DIRECTORY,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE,
                    &format!("creating {}", tree.display.display()),
                )?;
                let _ = s.close(&o.id);
            }
            // Not refused here when it is not to be created: a dry run opens its destination
            // this way, and a destination that does not exist yet is an empty one to plan
            // against -- refused, `-dryrun` into a new directory on this transport would fail at
            // open while the same run into a local one plans it. A SOURCE that
            // is not there still fails: its listing answers `NotFound`, which ends the run.
            Err(e) if e.kind() == io::ErrorKind::NotFound && !create => {}
            Err(e) => {
                tree.pool.give(s);
                return Err(e);
            }
        }
        crate::debug!(
            log,
            "smb {}: dialect 0x{:04x}, max read {}, max write {}",
            tree.display.display(),
            s.conn.dialect,
            s.conn.max_read,
            s.conn.max_write
        );
        tree.pool.give(s);
        Ok(tree)
    }

    /// The share-relative path of `rel`.
    fn abs(&self, rel: &str) -> String {
        let rel = if rel == "." { "" } else { rel };
        match (self.root.is_empty(), rel.is_empty()) {
            (true, true) => String::new(),
            (true, false) => rel.replace('/', "\\"),
            (false, true) => self.root.clone(),
            (false, false) => format!("{}\\{}", self.root, rel.replace('/', "\\")),
        }
    }

    fn item_of(&self, rel: &str, kind: Kind, size: u64, mtime: u64, atime: u64) -> Item {
        let size = if kind == Kind::File { size } else { 0 };
        Item {
            rel: rel.to_string(),
            kind,
            size,
            mtime_ns: proto::filetime_to_unix_ns(mtime),
            atime_ns: proto::filetime_to_unix_ns(atime),
            // synthesized: SMB carries DOS attributes, not a POSIX mode. `keeps_modes` is
            // false so nothing compares this against a real one.
            mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            dev: 0,
            ino: fnv64(&self.abs(rel)),
            nlink: 1,
            blocks: size,
            link_target: None,
        }
    }

    fn stat_on(&self, s: &mut Session, rel: &str) -> io::Result<Option<Item>> {
        let path = self.abs(rel);
        // No QUERY_INFO: a CREATE response already carries the times, the size and the
        // attributes, so the stat is one round trip rather than two.
        match s.create(
            &path,
            FILE_READ_ATTRIBUTES,
            0,
            FILE_OPEN,
            0,
            &format!("reading the attributes of {rel}"),
        ) {
            Ok(o) => {
                let _ = s.close(&o.id);
                Ok(kind_of(o.attributes).map(|k| self.item_of(rel, k, o.size, o.mtime, o.atime)))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Every entry of one directory.
    fn readdir(&self, s: &mut Session, rel: &str) -> io::Result<Vec<Entry>> {
        let path = self.abs(rel);
        let o = s.create(
            &path,
            FILE_LIST_DIRECTORY,
            0,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            &format!("listing {rel}"),
        )?;
        let mut out = Vec::new();
        let result = (|| -> io::Result<()> {
            // The server pages the listing and says NO_MORE_FILES when it is finished; a
            // fixed number of calls would silently truncate a large directory.
            //
            // The server keeps the cursor, so one that ignores it can return pages forever --
            // the same one or a cycle of them (A, B, A, B passes an identical-page check).
            // Names are unique in a directory, so a page that adds no
            // new name is progress-free; a few in a row are tolerated (a server may repeat
            // entries while the directory changes under the listing), more is refused. The
            // same set drops a name listed twice, which would copy one server file twice. (An
            // empty page cannot arrive: `parse_both_dir` refuses one.)
            let mut seen = std::collections::HashSet::new();
            let mut stale = 0;
            while let Some(page) = s.query_dir(&o.id, &format!("listing {rel}"))? {
                let before = seen.len();
                for e in &page {
                    if e.name == "." || e.name == ".." || !seen.insert(e.raw.clone()) {
                        continue;
                    }
                    // Kept, flagged: `list` reports an unrepresentable name as an entry it did
                    // not copy. Dropping it silently would leave a file out with nothing said.
                    out.push(e.clone());
                }
                stale = if seen.len() == before { stale + 1 } else { 0 };
                if stale > STALE_PAGES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("listing {rel}: {stale} pages in a row named nothing new, so the server is not advancing the listing"),
                    ));
                }
            }
            Ok(())
        })();
        let closed = s.close(&o.id);
        result?;
        closed?;
        Ok(out)
    }

    /// Opens `rel` for reading and hands back the session with it.
    fn open_read(&self, rel: &str) -> io::Result<SmbReader> {
        let path = self.abs(rel);
        let mut s = self.pool.take()?;
        match s.create(
            &path,
            FILE_READ_DATA,
            0,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            &format!("opening {rel}"),
        ) {
            Ok(o) => {
                let chunk = s.conn.max_read.min(super::conn::READ_CHUNK);
                Ok(SmbReader {
                    pool: self.pool.clone(),
                    sess: Some(s),
                    id: o.id,
                    size: o.size,
                    pos: 0,
                    rel: rel.to_string(),
                    buf: Vec::new(),
                    taken: 0,
                    chunk,
                })
            }
            Err(e) => {
                drop(s);
                Err(e)
            }
        }
    }

    /// The `FileBasicInformation` payload for a set of times.
    ///
    /// LastAccessTime and LastWriteTime, and DELIBERATELY NOT ChangeTime, which is left 0:
    /// zero means "do not change this field" per MS-FSCC 2.4.7.
    ///
    /// It is tempting to write all three: ChangeTime is settable, so that is legal, and a
    /// stand-in that reads LastWriteTime as the ACCESS time and ChangeTime as the
    /// MODIFICATION time would see the value land either way. That is a hedge for the test
    /// server with a real cost on a real one. Windows change time is what USN consumers and
    /// several backup products treat as "this file changed", and stamping it with the
    /// SOURCE's mtime backdates it, so a file copied onto a share that is itself a backup
    /// source can look older than the last backup and be skipped.
    ///
    /// The stand-in (`tests/support/smb_server.py`) reads the fields as the spec defines
    /// them, so this writes what a real server reads and is still measured. The read path
    /// takes mtime from LastWriteTime; the two ends of this adapter agree with each other and
    /// with the spec, rather than with impacket.
    fn basic_times(atime_ns: i128, mtime_ns: i128) -> Vec<u8> {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&0u64.to_le_bytes()); // CreationTime: leave the server's
        p.extend_from_slice(&proto::unix_ns_to_filetime(atime_ns).to_le_bytes());
        p.extend_from_slice(&proto::unix_ns_to_filetime(mtime_ns).to_le_bytes());
        p.extend_from_slice(&0u64.to_le_bytes()); // ChangeTime: 0 means leave it alone
        p.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes: leave them alone
        p.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        p
    }
}

pub struct SmbReader {
    pool: Arc<Pool>,
    sess: Option<Session>,
    id: FileId,
    size: u64,
    /// The offset the next READ will ask for.
    pos: u64,
    /// The path, for errors.
    rel: String,
    buf: Vec<u8>,
    taken: usize,
    chunk: u32,
}

impl SmbReader {
    /// The next block of bytes, or `None` at end of file.
    fn next_block(&mut self) -> io::Result<Option<&[u8]>> {
        if self.taken >= self.buf.len() {
            if self.pos >= self.size {
                return Ok(None);
            }
            let want = self
                .chunk
                .min((self.size - self.pos).min(u32::MAX as u64) as u32);
            let s = self.sess.as_mut().expect("an open reader has a session");
            let data = s.read_at(&self.id, self.pos, want, &format!("reading {}", self.rel))?;
            // The end of the file BEFORE the size the open reported: the file shrank under
            // the copy, or the server is wrong. This returned "end of file" and the copy
            // finished short, reported as the full size -- silent truncation into any sink
            // that does not check the length itself (a local or SMB destination does not).
            // The S3, WebDAV, OCI and tar sinks already refuse this shape by the same words.
            if data.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: {} bytes arrived for {} declared (the source changed during the copy)",
                        self.rel, self.pos, self.size
                    ),
                ));
            }
            self.pos += data.len() as u64;
            self.buf = data;
            self.taken = 0;
        }
        let at = self.taken;
        self.taken = self.buf.len();
        Ok(Some(&self.buf[at..]))
    }
}

impl Drop for SmbReader {
    fn drop(&mut self) {
        if let Some(mut s) = self.sess.take() {
            match s.close(&self.id) {
                Ok(()) => self.pool.give(s),
                Err(_) => drop(s),
            }
        }
    }
}

impl Read for SmbReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.taken >= self.buf.len() {
            if self.next_block()?.is_none() {
                return Ok(0);
            }
            self.taken = 0;
        }
        let n = out.len().min(self.buf.len() - self.taken);
        out[..n].copy_from_slice(&self.buf[self.taken..self.taken + n]);
        self.taken += n;
        Ok(n)
    }
}

impl Seek for SmbReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let consumed = self.pos - (self.buf.len() - self.taken) as u64;
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => consumed as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        let new = new as u64;
        if new != consumed {
            self.buf.clear();
            self.taken = 0;
            self.pos = new;
        }
        Ok(new)
    }
}

pub struct SmbSink {
    pool: Arc<Pool>,
    sess: Option<Session>,
    id: FileId,
    rel: String,
    /// Where the next byte belongs, holes included.
    pos: u64,
    /// How far the bytes actually written reach, which is where a trailing hole shows up.
    written: u64,
    /// The length `reserve` declared, so `finish` does not set the same one twice.
    reserved: u64,
    chunk: usize,
    closed: bool,
}

impl Drop for SmbSink {
    fn drop(&mut self) {
        if let Some(mut s) = self.sess.take() {
            let ok = if self.closed {
                Ok(())
            } else {
                s.close(&self.id)
            };
            match ok {
                Ok(()) => self.pool.give(s),
                Err(_) => drop(s),
            }
        }
    }
}

impl Sink for SmbSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        // DECLARE THE LENGTH UP FRONT, which is what this port's contract asks for. The cost
        // of a no-op here is silent data loss on every sparse file, and it is worth writing
        // down because the server reports success:
        //
        //   an 8 MiB file of `head` + hole + `tail` arrived as 4096 bytes -- the head alone
        //
        // A write lands at an absolute offset, so after a hole the offset is past the end
        // of a file that has only had its head written. MS-FSA ("Server Requests a Write")
        // DOES require the server to extend the file to meet such a write, and Windows and
        // Samba do; it is easy to overstate this as MS-SMB2 not requiring it. The stand-in
        // this is tested against is the non-compliant case: it
        // SKIPS the write -- and then answers `Count = Length`, claiming bytes it never wrote.
        // There is nothing in that response for a client to check. Setting the length
        // first is what makes the offsets land, on that server and on a real one, and it
        // is also what lets the filesystem keep the unwritten ranges as holes.
        if len > 0 {
            let s = self.sess.as_mut().expect("an open sink has a session");
            s.set_info(
                &self.id,
                FILE_END_OF_FILE_INFORMATION,
                &len.to_le_bytes(),
                &format!("reserving {len} bytes for {}", self.rel),
            )?;
            self.reserved = len;
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        // Checked before anything is sent, as `hole` checks its own addition: after a hole near
        // the top of the range, `pos += n` would wrap and the file would be cut to a few bytes
        // at `finish`.
        if self.pos.checked_add(data.len() as u64).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: data past the largest offset a file can have", self.rel),
            ));
        }
        for part in data.chunks(self.chunk) {
            let mut sent = 0usize;
            while sent < part.len() {
                let s = self.sess.as_mut().expect("an open sink has a session");
                // A server may take fewer bytes than offered, and treating the call as
                // all-or-nothing would silently drop the tail.
                let offered = part.len() - sent;
                let n = s.write_at(
                    &self.id,
                    self.pos,
                    &part[sent..],
                    &format!("writing {}", self.rel),
                )? as usize;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("{}: the server accepted 0 of {offered} bytes", self.rel),
                    ));
                }
                // The count is the SERVER's, like every other number in a response. Clamping
                // it would leave `sent` and `self.pos` advancing by different amounts, and
                // the offset of every later write in the file would be wrong -- silent
                // corruption from one bad number. A count larger than what was offered is a
                // protocol violation, so it is refused rather than made plausible.
                if n > offered {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: the server reported writing {n} bytes of the {offered} it was given", self.rel),
                    ));
                }
                sent += n;
                self.pos += n as u64;
            }
            self.written = self.pos;
        }
        Ok(())
    }

    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.pos = self.pos.checked_add(len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: a hole past the largest offset a file can have",
                    self.rel
                ),
            )
        })?;
        Ok(())
    }

    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals> {
        let refusals = Refusals {
            owner: opts.owner,
            xattrs: xattrs.iter().map(|(k, _)| k.clone()).collect(),
        };
        let s = self.sess.as_mut().expect("an open sink has a session");
        // ONLY when the file must be extended past the bytes written -- that is, when it
        // ends in a hole -- AND `reserve` did not already set that length. Sending it
        // unconditionally is harmless on a server that truncates, and the stand-in these
        // arms use implements it as "seek to length-1 and write a zero byte", which would
        // overwrite the last real byte of every file. A file that ends in a hole has a
        // zero there already, so this case is safe; a file that ends in DATA never reaches
        // it, because then `pos == written`.
        //
        // **And when the stream came up SHORT of what `reserve` declared** -- a source that
        // shrank under the copy. The file is `max(reserved, written)` long at this point, so
        // a guard on `written` alone would leave a pre-sized file with a zero tail at the
        // declared size, reported as a copy. The local, NFS and SFTP sinks truncate to what
        // arrived; this
        // does the same. On the stand-in that zeroes the last real byte, but a stream that
        // came up short is already not the file it declared, and real servers truncate.
        if self.reserved.max(self.written) != self.pos {
            s.set_info(
                &self.id,
                FILE_END_OF_FILE_INFORMATION,
                &self.pos.to_le_bytes(),
                &format!("setting the length of {}", self.rel),
            )?;
        }
        if opts.times {
            let atime = if opts.atime {
                item.atime_ns
            } else {
                item.mtime_ns
            };
            s.set_info(
                &self.id,
                FILE_BASIC_INFORMATION,
                &SmbTree::basic_times(atime, item.mtime_ns),
                &format!("setting the times of {}", self.rel),
            )?;
        }
        // `-fsync` must not be accepted and ignored here: a WRITE the server acknowledged may
        // still be in its cache, and the copy would report the file durable.
        if fsync {
            s.flush(&self.id, &format!("flushing {}", self.rel))?;
        }
        s.close(&self.id)?;
        self.closed = true;
        Ok(refusals)
    }

    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl Tree for SmbTree {
    type Reader = SmbReader;
    type Sink = SmbSink;

    fn root(&self) -> &Path {
        &self.display
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        _parallel: usize,
    ) -> io::Result<Listing> {
        let now = crate::filter::now_ns();
        self.pool.with(|s| {
            // a root that is not there is `NotFound`: a source that ends the run, a dry run's
            // destination that is empty. Never an empty, error-free listing.
            let Some(root) = self.stat_on(s, ".")? else { return Err(io::Error::new(io::ErrorKind::NotFound, format!("{}: no such directory", self.display.display()))) };
            let mut items = vec![root];
            let mut errors = Vec::new();
            let mut dirs: Vec<(String, usize)> = vec![(".".to_string(), 0)];
            while let Some((dir, depth)) = dirs.pop() {
                // A directory AT the depth limit is not read: nothing in it can be listed.
                // Reading it would fetch every entry over the network only to discard it --
                // and one that could not be read would fail the run over a directory it
                // never needed to open.
                if max_depth.is_some_and(|d| depth >= d) {
                    continue;
                }
                let entries = match self.readdir(s, &dir) {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(format!("{}: {e}", self.abs(&dir)));
                        continue;
                    }
                };
                for e in entries {
                    let rel = if dir == "." { e.name.clone() } else { format!("{dir}/{}", e.name) };
                    // THE FILTER FIRST. A listing error fails the run and marks the source
                    // incomplete, which stops a sync's deletions -- so an entry the operator
                    // excluded, or one below the depth asked for, must not produce one: it was
                    // never part of the copy.
                    let kind = kind_of(e.attributes);
                    if !filter.allows(&rel, kind == Some(Kind::Dir)) || max_depth.is_some_and(|d| depth + 1 > d) {
                        continue;
                    }
                    let Some(kind) = kind else {
                        // a reparse point: see `kind_of`. Reported rather than dropped, so
                        // a listing that is short of an entry says why.
                        errors.push(format!("{}: a reparse point, which this client cannot resolve, so it is not copied", self.abs(&rel)));
                        continue;
                    };
                    if let Some(why) = e.unrepresentable {
                        errors.push(format!("{}: {why}, so it cannot be named as a path and is not copied", self.abs(&rel)));
                        continue;
                    }
                    let item = self.item_of(&rel, kind, e.size, e.mtime, e.atime);
                    let keep = match kind {
                        Kind::Dir => true,
                        _ => filter.allows_file(item.size, item.mtime_ns, now) && filter.allows_owner_kind(kind, item.uid, item.gid, item.ino),
                    };
                    if kind == Kind::Dir {
                        dirs.push((rel.clone(), depth + 1));
                    }
                    if keep {
                        items.push(item);
                    }
                }
            }
            items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
            errors.sort();
            Ok(Listing { items, errors })
        })
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        self.pool.with(|s| self.stat_on(s, rel))
    }

    fn open(&self, rel: &str) -> io::Result<SmbReader> {
        self.open_read(rel)
    }

    fn read(
        &self,
        rel: &str,
        _buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        // A run of zeros is reported as a hole: SMB2 will not say where a file's data is
        // without an FSCTL this client does not issue, so this is what keeps a sparse file
        // sparse across it -- the same answer the sftp adapter gives, for the same reason.
        let mut r = self.open_read(rel)?;
        while let Some(block) = r.next_block()? {
            if is_all_zero(block) {
                sink(Segment::Hole(block.len() as u64))?;
            } else {
                sink(Segment::Data(block))?;
            }
        }
        Ok(())
    }

    fn create_file(&self, item: &Item) -> io::Result<SmbSink> {
        let path = self.abs(&item.rel);
        let mut s = self.pool.take()?;
        let opened = s.create(
            &path,
            FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
            ATTR_NORMAL,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE,
            &format!("creating {}", item.rel),
        );
        match opened {
            Ok(o) => {
                let chunk = (s.conn.max_write as usize).min(WRITE_CHUNK_CAP as usize);
                Ok(SmbSink {
                    pool: self.pool.clone(),
                    sess: Some(s),
                    id: o.id,
                    rel: item.rel.clone(),
                    pos: 0,
                    written: 0,
                    reserved: 0,
                    chunk,
                    closed: false,
                })
            }
            Err(e) => {
                drop(s);
                Err(e)
            }
        }
    }

    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut SmbSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        let path = self.abs(rel);
        self.pool.with(|s| {
            match s.create(
                &path,
                FILE_READ_ATTRIBUTES,
                ATTR_DIRECTORY,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
                &format!("creating the directory {rel}"),
            ) {
                Ok(o) => {
                    s.close(&o.id)?;
                    Ok(())
                }
                Err(err) => {
                    // A directory already there is what was wanted. `FILE_OPEN_IF` would
                    // say that in one call on a real server, and NOT on the stand-in these
                    // arms use, which runs `mkdir` unconditionally for that disposition
                    // and fails on an existing name. Asking afterwards works on both.
                    match self.stat_on(s, rel) {
                        Ok(Some(i)) if i.kind == Kind::Dir => Ok(()),
                        _ => Err(err),
                    }
                }
            }
        })
    }

    fn symlink(&self, rel: &str, _target: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{rel}: this SMB2 client does not create reparse points, so it has no symlinks"
            ),
        ))
    }

    fn hard_link(&self, _existing: &str, rel: &str) -> io::Result<()> {
        // SMB2 does have `FileLinkInformation`, and this deliberately does not use it: a
        // hard link is only worth making when the source SAID two names share an inode,
        // and this adapter cannot read one back (see `FILE_BOTH_DIRECTORY_INFORMATION`).
        // Making links it can never verify would put a group in the catalog that `verify`
        // reports as different forever. `copy_tree` turns `Unsupported` into a plain copy.
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("{rel}: this SMB2 client cannot read a file's link count, so it does not make hard links")))
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        let path = self.abs(rel);
        // Split rather than `pool.with`, for the reason the sftp adapter records: taking a
        // session can fail with the same error kind the server uses to refuse, and folding
        // them together reports "rerun once the entry can go" for a case where no packet
        // was ever sent.
        let mut s = self
            .pool
            .take()
            .map_err(|e| io::Error::new(e.kind(), format!("{rel}: the SMB connection could not be opened, so nothing was asked of the server: {e}")))?;
        let options = if kind == Kind::Dir {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
        let r = (|| {
            let o = s.create(
                &path,
                DELETE,
                0,
                FILE_OPEN,
                options,
                &format!("removing {rel}"),
            )?;
            // FileDispositionInformation rather than FILE_DELETE_ON_CLOSE at create: a
            // server checks a directory is empty when the disposition is SET, and answers
            // DIRECTORY_NOT_EMPTY there. Asked for at create time, the check lands at
            // close, where this client has nothing useful to do with the answer.
            let set = s.set_info(
                &o.id,
                FILE_DISPOSITION_INFORMATION,
                &[1u8],
                &format!("removing {rel}"),
            );
            let closed = s.close(&o.id);
            set?;
            closed
        })();
        match r {
            Ok(()) => {
                self.pool.give(s);
                Ok(Removed::Gone)
            }
            // The end state holds: a name that vanished between the listing and now is
            // removed, which is what the local and NFSv3 adapters already say.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.pool.give(s);
                Ok(Removed::Gone)
            }
            Err(e) => {
                drop(s);
                Removed::or_refused(e)
            }
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (self.abs(from), self.abs(to));
        self.pool.with(|s| {
            let o = s.create(&a, DELETE, 0, FILE_OPEN, 0, &format!("renaming {from}"))?;
            let name = ntlm::utf16le(&b);
            let mut payload = Vec::with_capacity(20 + name.len());
            payload.push(1); // ReplaceIfExists
            payload.extend_from_slice(&[0u8; 7]); // Reserved
            payload.extend_from_slice(&0u64.to_le_bytes()); // RootDirectory: share-relative
            payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
            payload.extend_from_slice(&name);
            let set = s.set_info(
                &o.id,
                FILE_RENAME_INFORMATION,
                &payload,
                &format!("renaming {from} to {to}"),
            );
            let closed = s.close(&o.id);
            set?;
            closed
        })
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        // Modes and owners have nowhere to go on a share; `keeps_modes` and `keeps_owner`
        // are false so nothing compares them, and `rewrites_metadata_in_place` is false so
        // `chmod` and `chown` refuse before walking a tree they could not change.
        let refusals = Refusals {
            owner: opts.owner,
            xattrs: Vec::new(),
        };
        if !opts.times {
            return Ok(refusals);
        }
        let path = self.abs(rel);
        let atime = if opts.atime {
            item.atime_ns
        } else {
            item.mtime_ns
        };
        let options = if item.kind == Kind::Dir {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
        self.pool.with(|s| {
            let o = s.create(
                &path,
                FILE_WRITE_ATTRIBUTES,
                0,
                FILE_OPEN,
                options,
                &format!("opening {rel} to set its times"),
            )?;
            let set = s.set_info(
                &o.id,
                FILE_BASIC_INFORMATION,
                &SmbTree::basic_times(atime, item.mtime_ns),
                &format!("setting the times of {rel}"),
            );
            let closed = s.close(&o.id);
            set?;
            closed?;
            Ok(refusals)
        })
    }

    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new())
    }

    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|(k, _)| k.clone()).collect())
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        self.set_metadata(
            &item.rel,
            item,
            MetaOptions {
                mode: false,
                times: true,
                owner: false,
                atime: true,
            },
        )
        .map(|_| ())
    }

    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    fn keeps_modes(&self) -> bool {
        // synthesized 0755/0644: a share carries DOS attributes, not a POSIX mode
        false
    }

    fn keeps_owner(&self) -> bool {
        // synthesized uid 0 / gid 0: the SIDs on a share are not uids
        false
    }

    fn keeps_xattrs(&self) -> bool {
        false
    }

    fn rewrites_metadata_in_place(&self) -> bool {
        // The flag's question is whether `chmod` and `chown` can change anything here, and
        // the answer is no: there is no mode and no uid on a share, so a walk would report
        // every entry changed having stored none of it.
        //
        // The cost is stated rather than hidden: `diag change -mtime` gates on the same
        // flag, and times ARE settable over SMB2 -- so that command is refused against an
        // smb:// tree even though it could work. A copy still carries times, through the
        // sink's `finish` and through `set_metadata`, which is the path that matters. A
        // finer-grained port would separate the two questions; this does not pretend to.
        false
    }

    fn native_copy(
        &self,
        _dst: &Self,
        _files: &[&Item],
        _next: &AtomicUsize,
        _workers: usize,
        _opts: &FileOptions,
        _done: &mut dyn FnMut(usize, io::Result<FileOutcome>),
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no native engine over smb",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `-smb.user` is split the way a person writes it, and the URL's user is only a
    /// default.
    #[test]
    fn a_credential_splits_into_domain_user_and_password() {
        let s = |v: &str| Settings {
            user: Some(v.to_string()),
            handshake_secs: None,
            require_signing: false,
        };
        assert_eq!(
            s("alice:secret").parts(None),
            (String::new(), "alice".into(), "secret".into())
        );
        assert_eq!(
            s("CORP\\alice:secret").parts(None),
            ("CORP".into(), "alice".into(), "secret".into())
        );
        assert_eq!(
            s("CORP/alice:secret").parts(None),
            ("CORP".into(), "alice".into(), "secret".into())
        );
        // a password may contain a colon; only the FIRST one separates
        assert_eq!(s("alice:a:b:c").parts(None).2, "a:b:c");
        // no password at all
        assert_eq!(
            s("alice").parts(None),
            (String::new(), "alice".into(), String::new())
        );
        // the URL supplies the user when the flag does not
        assert_eq!(
            Settings::default().parts(Some("bob")),
            (String::new(), "bob".into(), String::new())
        );
        // THE CONTROL: the flag WINS over the URL, so a run with both does not
        // silently authenticate as the name in the URL while using the flag's password
        assert_eq!(
            s("bob:secret").parts(Some("alice")),
            (String::new(), "bob".into(), "secret".into())
        );
    }

    /// A page of directory records, including the two a server always sends and the
    /// hostile shapes it might.
    #[test]
    fn a_directory_page_is_walked_forward_and_refuses_to_loop_or_overrun() {
        fn record(name: &str, next: u32, attrs: u32, size: u64) -> Vec<u8> {
            let n = ntlm::utf16le(name);
            let mut r = vec![0u8; BOTH_DIR_NAME_AT];
            r[0..4].copy_from_slice(&next.to_le_bytes());
            r[16..24].copy_from_slice(&700u64.to_le_bytes()); // LastAccessTime
            r[24..32].copy_from_slice(&900u64.to_le_bytes()); // LastWriteTime
            r[40..48].copy_from_slice(&size.to_le_bytes()); // EndOfFile
            r[56..60].copy_from_slice(&attrs.to_le_bytes());
            r[60..64].copy_from_slice(&(n.len() as u32).to_le_bytes());
            r.extend_from_slice(&n);
            r
        }
        let a = record("dir", (BOTH_DIR_NAME_AT + 6) as u32, ATTR_DIRECTORY, 0);
        let b = record("file.txt", 0, ATTR_NORMAL, 4321);
        let mut page = a.clone();
        page.extend_from_slice(&b);
        let out = parse_both_dir(&page).expect("walks");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "dir");
        assert_eq!(kind_of(out[0].attributes), Some(Kind::Dir));
        assert_eq!(out[1].name, "file.txt");
        assert_eq!(out[1].size, 4321);
        assert_eq!(out[1].mtime, 900);
        assert_eq!(out[1].atime, 700);

        // a next-entry offset pointing INSIDE the record it came from would walk the same
        // bytes forever; the walk refuses rather than hanging
        let loopy = record("x", 8, ATTR_NORMAL, 0);
        let e = parse_both_dir(&loopy).unwrap_err().to_string();
        assert!(e.contains("next-entry offset"), "{e}");

        // a name longer than the page is refused rather than sliced
        let mut overrun = record("y", 0, ATTR_NORMAL, 0);
        overrun[60..64].copy_from_slice(&9999u32.to_le_bytes());
        assert!(
            parse_both_dir(&overrun).is_err(),
            "a name past the end must be refused"
        );

        // AN OVERLAPPING RECORD, which `next >= BOTH_DIR_NAME_AT` alone accepted: the
        // offset is past the fixed header and INSIDE the name, so the name -- sliced by its
        // own length -- swallows the next record's header, and the walk then reads the
        // middle of a name as an entry. Everything it reports is wrong and nothing errors,
        // which is why this is refused rather than tolerated. The case comes from reading
        // the walker, not from any server known to send one.
        let mut overlap = record(
            "a-name-long-enough-to-matter",
            (BOTH_DIR_NAME_AT + 6) as u32,
            ATTR_NORMAL,
            0,
        );
        overlap.extend_from_slice(&record("second", 0, ATTR_NORMAL, 0));
        let e = parse_both_dir(&overlap).unwrap_err().to_string();
        assert!(
            e.contains("next-entry offset"),
            "an overlapping record was accepted: {e}"
        );
        // THE CONTROL on that, and it is the one that keeps the rule from being "refuse
        // anything with padding": a record whose next-entry offset leaves the name intact
        // and adds PADDING after it is legal, and still parses.
        let name = ntlm::utf16le("padded");
        let padded_to = BOTH_DIR_NAME_AT + name.len() + 6;
        let mut padded = record("padded", padded_to as u32, ATTR_NORMAL, 0);
        padded.extend_from_slice(&[0u8; 6]);
        padded.extend_from_slice(&record("after", 0, ATTR_NORMAL, 0));
        let out = parse_both_dir(&padded).expect("padding after the name is legal");
        assert_eq!(
            out.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["padded", "after"]
        );

        // a page too short for even one record
        assert!(parse_both_dir(&[0u8; 12]).is_err());

        // THE CONTROL on all three: the good page above still parses, so the walk is not
        // simply refusing everything -- which would pass every assertion after the first
        assert_eq!(parse_both_dir(&page).expect("still walks").len(), 2);
    }

    /// A reparse point is neither a file nor a directory here, and saying so is the whole
    /// point: read as a file it would copy the link's own bytes under the target's name.
    #[test]
    fn a_reparse_point_is_not_reported_as_a_file() {
        assert_eq!(kind_of(ATTR_NORMAL), Some(Kind::File));
        assert_eq!(kind_of(ATTR_DIRECTORY), Some(Kind::Dir));
        assert_eq!(kind_of(ATTR_NORMAL | ATTR_REPARSE_POINT), None);
        // including a directory-flavored one, which is how a junction appears
        assert_eq!(kind_of(ATTR_DIRECTORY | ATTR_REPARSE_POINT), None);
    }

    /// Joining the tree root with a relative path, in both separators.
    #[test]
    fn a_relative_path_joins_the_root_with_backslashes() {
        let tree = |root: &str| SmbTree {
            pool: Arc::new(pool_at(445, Settings::default())),
            root: root.to_string(),
            display: PathBuf::from("smb://h/DATA"),
        };
        let t = tree("");
        assert_eq!(t.abs("."), "");
        assert_eq!(t.abs("a/b"), "a\\b");
        let t = tree("sub");
        assert_eq!(t.abs("."), "sub");
        assert_eq!(t.abs("a/b"), "sub\\a\\b");
        let t = tree("one\\two");
        assert_eq!(t.abs("x"), "one\\two\\x");
    }

    /// A rejected password is never retried, and that is the half that could do harm.
    ///
    /// The retry exists for a transport failure during the handshake, where a second
    /// connection usually works and nothing has been written. Applied to a CREDENTIAL
    /// failure it would send the same wrong password three times per connection, across a
    /// worker pool -- which is how an account gets locked out, by a client trying to be
    /// helpful. So the kinds are named and the default is NOT to retry.
    #[test]
    fn a_handshake_is_retried_for_a_transport_failure_and_never_for_a_refused_credential() {
        use std::io::ErrorKind::*;
        for kind in [
            TimedOut,
            WouldBlock,
            UnexpectedEof,
            ConnectionReset,
            ConnectionAborted,
            BrokenPipe,
        ] {
            assert!(
                worth_another_connection(&io::Error::new(kind, "x")),
                "{kind:?} is a transport failure and is worth another connection"
            );
        }
        // THE CONTROL, and it is the reason this arm exists rather than a comment:
        // PermissionDenied is what a rejected password arrives as, through
        // `status_error`'s mapping of STATUS_LOGON_FAILURE.
        assert!(!worth_another_connection(&io::Error::new(
            PermissionDenied,
            "the server rejected the credentials"
        )));
        assert!(!worth_another_connection(&io::Error::new(
            NotFound,
            "no such share"
        )));
        assert!(!worth_another_connection(&io::Error::new(
            InvalidData,
            "not an SMB2 response"
        )));
        assert!(!worth_another_connection(&io::Error::other(
            "SMB status 0xc000000d"
        )));
        // and the mapping this depends on really produces PermissionDenied, rather than
        // this arm agreeing with itself about a kind nothing emits
        let refused = status_error(proto::STATUS_LOGON_FAILURE, "authenticating");
        assert_eq!(refused.kind(), PermissionDenied);
        assert!(
            !worth_another_connection(&refused),
            "a refused credential must not be dialed again"
        );
    }

    /// The retry gives up on a server that is simply gone, and re-arms when it comes back.
    ///
    /// This COUNTS CONNECTIONS against a real listener rather than reading the counter,
    /// because the counter agreeing with itself is not the property -- the property is how
    /// many times a doomed `open()` dials. The listener accepts and closes immediately,
    /// which is `UnexpectedEof`: a transport failure, the kind that IS retried.
    #[test]
    fn the_handshake_retry_gives_up_on_a_server_that_is_gone_and_re_arms_when_it_answers() {
        use std::net::TcpListener;
        use std::sync::atomic::Ordering;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream); // closed before a NEGOTIATE response: UnexpectedEof
            }
        });
        let pool = pool_at(
            port,
            Settings {
                user: None,
                handshake_secs: Some(2),
                require_signing: false,
            },
        );

        // BEFORE the breaker trips: three connections per open, which is the retry working.
        let before = accepts.load(Ordering::SeqCst);
        assert!(
            pool.open().is_err(),
            "a server that closes the socket cannot hand back a session"
        );
        let first_open = accepts.load(Ordering::SeqCst) - before;
        assert_eq!(
            first_open, HANDSHAKE_ATTEMPTS as usize,
            "a fresh pool must still retry"
        );

        // Drive it past the threshold, then measure one more open.
        while pool.consecutive_failures.load(Ordering::SeqCst) < HANDSHAKE_GIVE_UP_AFTER {
            let _ = pool.open();
        }
        let tripped = accepts.load(Ordering::SeqCst);
        assert!(pool.open().is_err());
        let after = accepts.load(Ordering::SeqCst) - tripped;
        assert_eq!(
            after, 1,
            "past the threshold an open must dial once, not {HANDSHAKE_ATTEMPTS}"
        );

        // Two things this arm does NOT show, each shown elsewhere against a server that can
        // produce the event: that a SUCCESS re-arms the breaker (`a_successful_handshake_
        // re_arms_the_breaker` -- this listener can never succeed), and that a REFUSED
        // credential leaves the breaker alone (`a_rejected_password_reaches_the_server_at_
        // most_the_budget...`, which reads the counter after sixteen rejections). Neither is
        // asserted here, because nothing here could make such an assertion fail: one would
        // restate the loop condition that had just exited, and the other would check only
        // the classifier.
    }

    /// The CreditCharge a REAL READ carries, read back off the request that carried it.
    ///
    /// This is the arm `a_read_charges_for_the_payload_...` could not be. That one calls
    /// `credit_charge` with literals, so it passes whatever the call site does -- reverting
    /// `read_at` to the message-based expectation leaves it green, which was demonstrated
    /// rather than argued. Both credit defects this adapter has had lived in the call site.
    ///
    /// It needs a server that offers a credit window, which the stand-in did not until the
    /// negotiate override in `tests/support/smb_server.py`. Before that, `multi_credit` was
    /// false in every automated run and every charge was 0 -- so this arm could not have
    /// existed, and that is why the defects went unseen.
    #[test]
    fn a_real_read_carries_the_charge_its_payload_asks_for() {
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        // A file large enough that the charge is NOT 1, so the arm distinguishes a real
        // computation from the constant it used to be.
        let big = server.share.join("big.bin");
        std::fs::write(&big, vec![7u8; 300 << 10]).expect("write the fixture");

        let mut conn =
            Conn::connect("127.0.0.1", server.port, Duration::from_secs(10)).expect("connect");
        assert!(
            conn.multi_credit,
            "the stand-in must offer a credit window or this arm measures nothing"
        );
        conn.login("tester", "", "").expect("login");
        let tree = conn.tree_connect("DATA").expect("tree connect");
        let mut session = Session { conn, tree };

        let opened = session
            .create(
                "big.bin",
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                "opening the fixture",
            )
            .expect("open the fixture");
        let id = opened.id;
        let want = (256 << 10) as u32;
        let got = session
            .read_at(&id, 0, want, "reading the fixture")
            .expect("read");
        assert!(
            !got.is_empty(),
            "the read returned nothing, so no request carried a charge"
        );
        // 256 KiB of PAYLOAD is four credits. The message-based computation would be five,
        // and the constant-zero defect would be zero -- so this one number separates the
        // current behavior from both defects this adapter has had.
        assert_eq!(
            session.conn.last_credit_charge, 4,
            "a {want}-byte read must charge 4"
        );

        // AND THE MESSAGE IDS the charge consumed: a request charging N uses N ids, and the
        // next request starting inside that range reuses ids the server retired. impacket
        // never checks, so this is read off the client -- `+= 1` passed everything before.
        let before = session.conn.next_id;
        session
            .read_at(&id, 0, want, "reading the fixture")
            .expect("read");
        assert_eq!(
            session.conn.next_id - before,
            4,
            "a request charging 4 must consume 4 message ids"
        );

        // One byte past a 64 KiB multiple, because an exact multiple cannot tell `len` from
        // `len - 1` at the call site: 262144 and 262143 both charge 4. 65537 charges 2 and
        // 65536 charges 1, so an off-by-one in what `read_at` passes shows here.
        session
            .read_at(&id, 0, 65_537, "reading the fixture")
            .expect("read");
        assert_eq!(
            session.conn.last_credit_charge, 2,
            "a 65537-byte read must charge 2"
        );

        // THE CONTROL: a command with no payload charges 1, whatever else is going on.
        session.close(&id).ok();
        assert_eq!(
            session.conn.last_credit_charge, 1,
            "a CLOSE carries no payload and must charge 1"
        );
        server.stop();
    }

    /// The PRODUCTION read and write paths charge what their caps allow, against a server
    /// that offers more than the caps.
    ///
    /// The arm above drives `read_at` by hand; this one drives the paths a copy uses. Against
    /// a stand-in advertising 64 KiB `MaxReadSize` / `MaxWriteSize` it could not show
    /// anything: every chunk would be 64 KiB and charge 1, so removing both caps and passing
    /// a zero payload to WRITE's charge would leave every arm green. The stand-in advertises
    /// Samba's 8 MiB, so a missing cap is a 128-credit request against a window of 64 --
    /// refused -- and a correct one is exactly 16.
    #[test]
    fn a_copy_s_reads_and_writes_charge_what_their_caps_allow() {
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        let settings = Settings {
            user: Some("tester:".into()),
            handshake_secs: Some(10),
            require_signing: false,
        };
        let tree = SmbTree::connect(
            None,
            "127.0.0.1",
            Some(server.port),
            "DATA",
            Path::new(""),
            false,
            &settings,
            &crate::ports::Silent,
        )
        .expect("connect");
        let data: Vec<u8> = (0..(3 << 20) + 1).map(|i: u32| (i % 251) as u8).collect();
        let item = Item {
            rel: "charged.bin".into(),
            kind: Kind::File,
            size: data.len() as u64,
            mtime_ns: 0,
            atime_ns: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: 0,
            link_target: None,
        };
        {
            let mut sink = tree.create_file(&item).expect("create");
            assert!(
                sink.chunk > 64 << 10,
                "the stand-in must offer more than 64 KiB, or the cap is never reached: {}",
                sink.chunk
            );
            crate::smb::conn::take_largest_charge();
            sink.write(&data).expect("write 3 MiB + 1 through the sink");
            assert_eq!(
                crate::smb::conn::take_largest_charge(),
                16,
                "a copy's writes must charge exactly the 1 MiB cap"
            );
        }
        crate::smb::conn::take_largest_charge();
        let mut back = Vec::new();
        tree.open("charged.bin")
            .expect("open")
            .read_to_end(&mut back)
            .expect("read back");
        assert_eq!(
            crate::smb::conn::take_largest_charge(),
            16,
            "a copy's reads must charge exactly the 1 MiB cap"
        );
        // THE CONTROL that the charges were for real data: it arrived, and it came back.
        assert_eq!(back, data, "the file did not round-trip");
        assert_eq!(
            std::fs::read(server.share.join("charged.bin")).expect("on disk"),
            data
        );
        server.stop();
    }

    /// A pool at `port` with its OWN credential budget.
    ///
    /// Production pools share a budget per account, process-wide. Arms must not: two arms
    /// running in parallel under the same test user would spend each other's budget, and
    /// the failure would appear in whichever arm happened to run second.
    fn pool_at(port: u16, settings: Settings) -> Pool {
        Pool {
            settings,
            url_user: None,
            host: "127.0.0.1".into(),
            port,
            share: "DATA".into(),
            idle: Mutex::new(Vec::new()),
            consecutive_failures: AtomicUsize::new(0),
            credential: Arc::new(CredentialBudget::default()),
        }
    }

    fn as_user(password: &str) -> Settings {
        Settings {
            user: Some(format!("{}:{password}", crate::smb::scripted::USER)),
            handshake_secs: Some(5),
            require_signing: false,
        }
    }

    /// A rejected password reaches the server at most the budget's number of times, however
    /// many workers ask at once.
    ///
    /// **Counted at the SERVER, which is the only place the property lives.** An arm that
    /// reads the client's own counter, sets it by hand, or builds a struct and asserts the
    /// field it has just set passes whatever the budget does. The defect that matters most
    /// is structural: a budget that loads a counter, dials, and increments after the failure
    /// resolves lets sixteen workers that start together send the server SIXTEEN wrong
    /// passwords. That shape is reproduced here and must come to exactly the budget.
    #[test]
    fn a_rejected_password_reaches_the_server_at_most_the_budget_however_many_workers_ask() {
        use crate::smb::scripted::{spawn, Answer, Script};
        use std::sync::atomic::Ordering;
        let peer = spawn(Script::unsigned(Answer::Reject));
        let pool = Arc::new(pool_at(peer.port, as_user("wrong")));
        let workers = 16;
        let start = Arc::new(std::sync::Barrier::new(workers));
        let results: Vec<io::Result<()>> = (0..workers)
            .map(|_| {
                let (pool, start) = (pool.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    pool.open().map(drop)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().expect("a worker panicked"))
            .collect();

        assert_eq!(peer.authenticates(), CREDENTIAL_GIVE_UP_AFTER, "{workers} workers must offer a rejected password exactly the budget's number of times, in total");
        for r in &results {
            let e = r
                .as_ref()
                .expect_err("a rejected password cannot produce a session");
            assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "a rejection and a refusal are both permission errors: {e}"
            );
        }
        let refusals: Vec<String> = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .map(|e| e.to_string())
            .filter(|e| e.contains("refusing to offer"))
            .collect();
        assert_eq!(
            refusals.len(),
            workers - CREDENTIAL_GIVE_UP_AFTER,
            "every worker past the budget must be refused by name"
        );
        assert!(
            refusals[0].contains(&format!("({CREDENTIAL_GIVE_UP_AFTER} rejected;")),
            "an explicit rejection must be reported as one: {}",
            refusals[0]
        );
        assert!(
            refusals[0].contains("Check the password"),
            "{}",
            refusals[0]
        );
        // A refused password is not a server that is down, so the breaker must not move.
        assert_eq!(
            pool.consecutive_failures.load(Ordering::SeqCst),
            0,
            "rejections tripped the breaker"
        );

        // and once spent, an open does not even dial
        let dialed = peer.connections();
        assert!(pool.open().is_err());
        assert_eq!(
            peer.connections(),
            dialed,
            "a spent budget must refuse BEFORE dialing"
        );
    }

    /// A login the server hangs up on IS retried -- inside the budget -- and past it the
    /// refusal says it saw hang-ups rather than rejections.
    ///
    /// Both halves are easy to get wrong. It is tempting to switch the retry off here on the
    /// reasoning that Samba's wedge only strikes the credential-free first SESSION_SETUP; a
    /// live run against Samba 4.19.5 without the retry failed a file on a wedge AFTER the
    /// AUTHENTICATE, which a build that retried got through. And a refusal that says "check
    /// the password" whatever it has seen sends the operator to a password that is right.
    #[test]
    fn a_login_the_server_hangs_up_on_is_retried_within_the_budget_and_then_refused_by_name() {
        use crate::smb::scripted::{spawn, Answer, Script, PASSWORD};
        let peer = spawn(Script::unsigned(Answer::HangUp));
        let pool = pool_at(peer.port, as_user(PASSWORD));

        let refused = pool
            .open()
            .map(drop)
            .expect_err("a server that hangs up cannot hand back a session")
            .to_string();
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "one open must retry a hang-up until the budget, and no further"
        );
        assert!(
            refused.contains("refusing to offer"),
            "past the budget the open must be refused by name: {refused}"
        );
        // THE CONTROL on the wording: hang-ups must not be reported as rejections.
        assert!(
            refused.contains("the connection was lost"),
            "the refusal must say what it saw: {refused}"
        );
        assert!(
            !refused.contains("rejected"),
            "hang-ups reported as rejections: {refused}"
        );

        let dialed = peer.connections();
        assert!(pool.open().is_err());
        assert_eq!(
            (peer.authenticates(), peer.connections()),
            (CREDENTIAL_GIVE_UP_AFTER, dialed),
            "a spent budget must not dial again"
        );
    }

    /// A success clears the budget, so a server that recovers gets the whole budget back.
    ///
    /// Against a server that can actually succeed, because that is the only way the reset
    /// runs: an arm that resets the counter BY HAND tests nothing, the same trap a breaker
    /// re-arm arm falls into when it re-arms by hand.
    #[test]
    fn a_success_gives_the_whole_budget_back() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let peer = spawn(Script::unsigned(Answer::Reject));
        let pool = pool_at(peer.port, as_user(PASSWORD));
        assert!(pool.open().is_err(), "rejected");
        peer.set(|s| s.answer = Answer::Accept(Signature::Correct));
        pool.open().expect("the server accepts now");
        peer.set(|s| s.answer = Answer::Reject);
        let before = peer.authenticates();
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 1 {
            let _ = pool.open();
        }
        // one rejection before the success must not still be counted after it
        assert_eq!(
            peer.authenticates() - before,
            CREDENTIAL_GIVE_UP_AFTER,
            "after a success the full budget must be available again, and no more"
        );
    }

    /// A success the session cannot verify does NOT give the budget back -- sequentially or
    /// across a pool -- and the refusal says the answers could not be authenticated.
    ///
    /// **It is tempting to assert the opposite, and that would be the hole.** The opposite
    /// requires four offers to reach a server whose `STATUS_SUCCESS` is signed with the wrong
    /// key, on the reasoning that a real success followed by a signing fault should not read
    /// as "check the password". But the status is read before its signature is checked, so
    /// on a signed session it is exactly what an on-path forger controls: let each real
    /// `STATUS_LOGON_FAILURE` through to the domain controller, hand this client an unsigned
    /// success, and the budget never fills. Such an assertion measures that bypass and calls
    /// it correct.
    #[test]
    fn a_success_the_session_cannot_verify_does_not_give_the_budget_back() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        for sig in [Signature::Wrong, Signature::Absent] {
            let mut script = Script::signing();
            script.answer = Answer::Accept(sig);
            let peer = spawn(script);
            let pool = pool_at(peer.port, as_user(PASSWORD));
            for _ in 0..CREDENTIAL_GIVE_UP_AFTER {
                let e = pool
                    .open()
                    .map(drop)
                    .expect_err("a success the key does not verify must fail the login");
                assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{sig:?}: {e}");
            }
            let refused = pool
                .open()
                .map(drop)
                .expect_err("past the budget the pool must refuse")
                .to_string();
            assert_eq!(
                peer.authenticates(),
                CREDENTIAL_GIVE_UP_AFTER,
                "{sig:?}: an unverifiable success gave the budget back"
            );
            assert!(
                refused.contains("could not be authenticated"),
                "{sig:?}: the refusal must say what it saw: {refused}"
            );
            assert!(!refused.contains("rejected"), "{sig:?}: {refused}");
            // and the advice points at signing, not at a password that may well be right
            assert!(
                refused.contains("signing configuration before the password"),
                "{sig:?}: {refused}"
            );
        }

        // and across a pool: sixteen workers behind a barrier, the shape that overshot before
        let mut script = Script::signing();
        script.answer = Answer::Accept(Signature::Absent);
        let peer = spawn(script);
        let pool = Arc::new(pool_at(peer.port, as_user(PASSWORD)));
        let start = Arc::new(std::sync::Barrier::new(16));
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let (pool, start) = (pool.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    pool.open().map(drop)
                })
            })
            .collect();
        for w in workers {
            assert!(w.join().expect("a worker panicked").is_err());
        }
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "sixteen workers offered past the budget on unverifiable successes"
        );

        // THE CONTROL: a success that DOES verify still gives the budget back, so the change
        // above is not simply "never reset".
        let peer = spawn(Script::signing());
        let pool = pool_at(peer.port, as_user(PASSWORD));
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            pool.open()
                .expect("a correctly signed success must open, every time");
        }
    }

    /// A success for one credential does not clear another credential's failures, even
    /// where the two share the account's budget.
    ///
    /// The budget merges every spelling of an account, and a success that reset the merged
    /// count would let each success on a right password re-arm two more offers of a wrong
    /// one. This is that interleaving: a copy whose source has the wrong password and whose
    /// destination has the right one.
    #[test]
    fn a_success_for_one_credential_does_not_clear_another_credentials_failures() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let wrong_peer = spawn(Script::unsigned(Answer::Reject));
        let right_peer = spawn(Script::unsigned(Answer::Accept(Signature::Correct)));
        let shared = Arc::new(CredentialBudget::default());
        let mut wrong = pool_at(wrong_peer.port, as_user("wrong"));
        wrong.credential = shared.clone();
        let mut right = pool_at(right_peer.port, as_user(PASSWORD));
        right.credential = shared;
        assert!(wrong.open().is_err(), "the wrong password is rejected");
        right.open().expect("the right password opens");
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 1 {
            let _ = wrong.open();
            // a fresh login each time, as a pool that dropped a session would make
            let _ = right.open();
        }
        assert_eq!(
            wrong_peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "successes on another credential re-armed the wrong password's budget"
        );
    }

    /// A login stalled BEFORE its credential holds no budget slot, so it does not hold up
    /// logins to the same account elsewhere.
    ///
    /// With the reservation ahead of the dial, a connection wedged at NEGOTIATE or the first
    /// SESSION_SETUP would hold a slot until the handshake deadline, and every worker for the
    /// account would queue behind it. Deterministic: the stalled peer having accepted both
    /// connections is observed before the healthy login starts, so on the defective
    /// placement both slots are provably taken.
    #[test]
    fn a_login_stalled_before_its_credential_holds_no_budget_slot() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let mut stall = Script::unsigned(Answer::Accept(Signature::Correct));
        stall.stall_at_challenge = true;
        let stalled_peer = spawn(stall);
        let healthy_peer = spawn(Script::unsigned(Answer::Accept(Signature::Correct)));
        let shared = Arc::new(CredentialBudget::default());
        let mut stalled = pool_at(
            stalled_peer.port,
            Settings {
                handshake_secs: Some(4),
                ..as_user(PASSWORD)
            },
        );
        stalled.credential = shared.clone();
        let stalled = Arc::new(stalled);
        let mut healthy = pool_at(healthy_peer.port, as_user(PASSWORD));
        healthy.credential = shared;
        let wedged: Vec<_> = (0..CREDENTIAL_GIVE_UP_AFTER)
            .map(|_| {
                let p = stalled.clone();
                std::thread::spawn(move || p.open().map(drop))
            })
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while stalled_peer.connections() < CREDENTIAL_GIVE_UP_AFTER {
            assert!(
                std::time::Instant::now() < deadline,
                "the stalled logins never reached their peer"
            );
            std::thread::yield_now();
        }
        let started = std::time::Instant::now();
        healthy
            .open()
            .expect("a healthy login must not wait on logins that have sent nothing");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the healthy login waited {:?} behind stalled ones",
            started.elapsed()
        );
        // the stalled ones time out having offered nothing, so the budget is untouched
        for w in wedged {
            assert!(w.join().expect("a stalled worker panicked").is_err());
        }
        assert_eq!(stalled_peer.authenticates(), 0);
        assert!(healthy.credential.spent("h", 0).is_none());
    }

    /// A connection the server closed while its worker waited for a budget slot is not
    /// counted as an offer.
    ///
    /// The case that reserving before the dial would prevent, handled where it can be seen:
    /// the connection is checked after the wait and before the credential is written.
    /// Deterministic: both slots are held by hand until the peer has closed the connection.
    #[test]
    fn a_connection_closed_while_waiting_for_a_budget_slot_is_not_an_offer() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.close_after_challenge = true;
        let peer = spawn(script);
        let pool = Arc::new(pool_at(peer.port, as_user(PASSWORD)));
        let budget = pool.credential.clone();
        let held: Vec<_> = (0..CREDENTIAL_GIVE_UP_AFTER)
            .map(|_| budget.reserve("h", 0).expect("a free slot"))
            .collect();
        let waiter = {
            let pool = pool.clone();
            std::thread::spawn(move || pool.open().map(drop))
        };
        // The waiter has its challenge and is queued: wait until the peer has CLOSED that
        // connection -- not merely accepted it, which is all a fixed sleep would stand in for,
        // and which could let the waiter send first.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while peer.finished() < 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the peer never closed the waiter's connection"
            );
            std::thread::yield_now();
        }
        // and the waiter really is WAITING, holding that connection -- not still on its way to
        // `reserve`, which nothing above establishes
        while budget.state.lock().unwrap().waiting < 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the waiter never reached the budget"
            );
            std::thread::yield_now();
        }
        // the FIN is sent by that close; let loopback deliver it
        std::thread::sleep(Duration::from_millis(50));
        // and the retries `open` makes next must not race a close either: from here the peer
        // hangs up before issuing a challenge, so no later attempt can reach a credential
        peer.set(|s| {
            s.close_after_challenge = false;
            s.hang_up_at_challenge = true;
        });
        drop(held);
        let e = waiter
            .join()
            .expect("the waiter panicked")
            .expect_err("every connection is closed after its challenge");
        assert_ne!(
            e.kind(),
            io::ErrorKind::PermissionDenied,
            "a closed connection was counted as an offer: {e}"
        );
        assert_eq!(peer.authenticates(), 0);
        let s = budget.state.lock().unwrap();
        assert_eq!(
            (s.totals().failed, s.in_flight),
            (0, 0),
            "a credential that never went out was counted or a slot leaked"
        );
    }

    /// A login the server did not judge is counted -- the credential went out -- and retried,
    /// as a dropped connection is.
    ///
    /// It is tempting to treat every non-success as a rejected password and not retry. A
    /// server that discards the half-built session (USER_SESSION_DELETED) never judged the
    /// password, and the operator would nonetheless be told to "check the password".
    #[test]
    fn a_login_the_server_did_not_judge_is_retried_within_the_budget() {
        use crate::smb::scripted::{spawn, Answer, Script, PASSWORD};
        let peer = spawn(Script::unsigned(Answer::Fail(
            proto::STATUS_USER_SESSION_DELETED,
        )));
        // the arm relies on a third attempt reaching `spent()`, so it says so
        assert!(
            HANDSHAKE_ATTEMPTS as usize > CREDENTIAL_GIVE_UP_AFTER,
            "this arm needs more attempts per open than the budget allows"
        );
        let pool = pool_at(peer.port, as_user(PASSWORD));
        let e = pool
            .open()
            .map(drop)
            .expect_err("the server never judges it");
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "an unjudged answer must be retried, and the retries counted"
        );
        assert!(e.to_string().contains("no verdict on the password"), "{e}");
    }

    /// An account a server refuses outright is not offered to THAT server again -- and only
    /// to that server: the same name elsewhere is another account, or the same one under
    /// another machine's policy.
    ///
    /// Stopping the whole account on one such answer, keyed by the bare name across every
    /// server, would let one server's "locked out" (or one forged unsigned packet) stop every
    /// `alice` everywhere and name the wrong server as the one that refused.
    #[test]
    fn an_account_a_server_refuses_outright_is_not_offered_to_it_again() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let refusing = spawn(Script::unsigned(Answer::Fail(
            proto::STATUS_ACCOUNT_LOCKED_OUT,
        )));
        let accepting = spawn(Script::unsigned(Answer::Accept(Signature::Correct)));
        let shared = Arc::new(CredentialBudget::default());
        let mut a = pool_at(refusing.port, as_user(PASSWORD));
        a.credential = shared.clone();
        let mut b = pool_at(accepting.port, as_user(PASSWORD));
        b.credential = shared;
        let first = a.open().map(drop).expect_err("locked out");
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied, "{first}");
        let again = a
            .open()
            .map(drop)
            .expect_err("still locked out")
            .to_string();
        assert_eq!(
            refusing.authenticates(),
            1,
            "a locked-out account was offered a password again"
        );
        assert!(
            again.contains("locked out") && again.contains(&format!(":{}", refusing.port)),
            "the refusal must name the server that said it: {again}"
        );
        // THE SCOPE: another server is not stopped by what the first one said
        b.open()
            .expect("one server's verdict on an account must not stop another server");
    }

    /// An answer this client does not recognize is counted, but named as what it is -- not
    /// narrated as a verdict on the password.
    #[test]
    fn an_unrecognized_login_status_is_named_not_called_a_bad_password() {
        use crate::smb::scripted::{spawn, Answer, Script, PASSWORD};
        let peer = spawn(Script::unsigned(Answer::Fail(proto::STATUS_ACCESS_DENIED)));
        let pool = pool_at(peer.port, as_user(PASSWORD));
        let _ = pool.open();
        let _ = pool.open();
        let refused = pool
            .open()
            .map(drop)
            .expect_err("the budget is spent")
            .to_string();
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "still counted, as a rejection would be"
        );
        assert!(
            refused.contains("does not recognize") && refused.contains("access denied"),
            "{refused}"
        );
        assert!(
            !refused.contains(" rejected"),
            "an unrecognized status was narrated as a rejection: {refused}"
        );
    }

    /// The tree connect after a login gets a deadline of its own, not what the offer left.
    #[test]
    fn the_tree_connect_is_not_bound_by_what_the_offer_left() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.delay_answer = Some(Duration::from_millis(700));
        script.delay_later = Some(Duration::from_millis(500));
        let peer = spawn(script);
        let pool = pool_at(
            peer.port,
            Settings {
                handshake_secs: Some(1),
                ..as_user(PASSWORD)
            },
        );
        pool.open()
            .expect("an answer inside its deadline and a tree connect inside its own must log in");
        assert_eq!(
            peer.authenticates(),
            1,
            "a login that succeeded was thrown away and the password sent again"
        );
    }

    /// The tree connect's deadline is ABSOLUTE, not a per-read socket timeout: a reply
    /// trickled a byte at a time is cut off, where the per-syscall bound would let it run.
    #[test]
    fn the_tree_connect_gets_an_absolute_deadline_not_a_per_read_one() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        // the login answers at once; the TREE_CONNECT reply dribbles a byte every 200 ms, so
        // no single read times out against a 1 s socket timeout but the whole exceeds a 1 s
        // absolute deadline. Unbounded, a ~90-byte reply would take ~18 s.
        script.trickle_later = Some(Duration::from_millis(200));
        let peer = spawn(script);
        let pool = pool_at(
            peer.port,
            Settings {
                handshake_secs: Some(1),
                ..as_user(PASSWORD)
            },
        );
        let started = std::time::Instant::now();
        let r = pool.open().map(drop);
        let e =
            r.expect_err("a trickled tree-connect reply must be cut off by an absolute deadline");
        // The kind too: a deadline expiry read as `WouldBlock` would say "resource temporarily
        // unavailable" for it, which is what the read side's `WouldBlock` arm exists to prevent;
        // this is the assertion that catches that arm's removal.
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        // the failure must be the ~1 s deadline firing, not an unrelated early error: a lower
        // bound rules out an immediate protocol/encoding failure passing this test, while the
        // upper bound (allowing a few 1 s retries) rules out a per-read hang
        assert!(
            started.elapsed() > Duration::from_millis(800),
            "the error came too early to be the deadline: {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the tree connect ran past its deadline: {:?}",
            started.elapsed()
        );
    }

    /// An account verdict counts toward the account's summed budget, but when a DIFFERENT
    /// credential then hits that budget the refusal names the account verdict rather than
    /// calling it a rejected password.
    #[test]
    fn an_account_verdict_in_the_sum_is_named_not_called_a_rejection() {
        let budget = CredentialBudget::default();
        // two distinct credentials, each refused at the account level, spend the two-offer
        // budget between them and latch themselves
        for cred in [1u64, 2] {
            let mut o = budget
                .reserve("locked-server:445", cred)
                .expect("a free slot");
            o.sent = true;
            o.settle(Settled::Account(proto::STATUS_ACCOUNT_LOCKED_OUT));
        }
        // a THIRD credential, not itself latched, meets the summed budget
        let refused = budget
            .spent("another-server:445", 3)
            .expect("the summed budget is spent")
            .to_string();
        assert!(
            refused.contains("refused by their own server"),
            "account verdicts in the sum must be named: {refused}"
        );
        // and NOT attributed to the target host, which never saw the credential
        assert!(
            refused.contains("not by this one"),
            "the account verdict must not be blamed on the target host: {refused}"
        );
        assert!(
            !refused.contains("rejected"),
            "an account verdict in the sum was narrated as a rejected password: {refused}"
        );
    }

    /// Every per-credential map rests on this fingerprint being STABLE for one credential and
    /// DISTINCT across servers and passwords, and this pins both: a hasher keyed per call
    /// would silently disable the latch and the success reset together.
    #[test]
    fn the_credential_fingerprint_is_stable_and_scoped_to_the_server() {
        let id = |host: &str, port: u16, user: &str, password: &str| {
            credential_id(host, port, "CORP", user, password)
        };
        assert_eq!(
            id("a", 445, "alice", "p"),
            id("a", 445, "alice", "p"),
            "one credential, two fingerprints"
        );
        assert_eq!(
            id("A", 445, "ALICE", "p"),
            id("a", 445, "alice", "p"),
            "host and user compare without case"
        );
        assert_ne!(
            id("a", 445, "alice", "p"),
            id("b", 445, "alice", "p"),
            "another server is another credential"
        );
        assert_ne!(
            id("a", 445, "alice", "p"),
            id("a", 1445, "alice", "p"),
            "another port is another credential"
        );
        assert_ne!(
            id("a", 445, "alice", "p"),
            id("a", 445, "alice", "P"),
            "the password is case-sensitive"
        );
    }

    /// A session whose connection is mid-exchange (`Conn::broken`) is not pooled again; a
    /// sound one is. The connect probe hands a session back after any failed create, so this
    /// is the check that keeps a desynced stream out of the pool.
    #[test]
    fn a_broken_connection_is_not_pooled_again() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let peer = spawn(Script::unsigned(Answer::Accept(Signature::Correct)));
        let pool = pool_at(peer.port, as_user(PASSWORD));
        let sound = pool.open().expect("opens");
        pool.give(sound);
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            1,
            "a sound session must be pooled"
        );
        let mut broken = pool.take().expect("the pooled one");
        broken.conn.broken = true;
        pool.give(broken);
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "a connection left mid-exchange was pooled again"
        );
    }

    /// No success clears an account latch -- not a concurrent one, unsigned or signed. It is
    /// tempting to let a signed success clear it, but a genuine signed success delayed on the
    /// wire is still OLDER than the lockout it would erase. This also pins that the latch is
    /// SET by `Account` and that `spent` consults it.
    #[test]
    fn no_concurrent_success_clears_an_account_latch() {
        let budget = CredentialBudget::default();
        let mut a = budget.reserve("s:445", 7).expect("first slot");
        let mut b = budget.reserve("s:445", 7).expect("second slot");
        a.sent = true;
        b.sent = true;
        a.settle(Settled::Account(proto::STATUS_ACCOUNT_LOCKED_OUT)); // latches credential 7
        assert!(
            budget.spent("s:445", 7).is_some(),
            "the account latch must be set and read by spent"
        );
        b.settle(Settled::Accepted); // authentic or not, it was in flight when the lockout landed
        assert!(
            budget.spent("s:445", 7).is_some(),
            "a success reserved before the lockout cleared it"
        );
        // and the latch holds for the run: nothing can be reserved after it to supersede it
        assert!(
            budget.reserve("s:445", 7).is_err(),
            "a latched credential was offered again"
        );
    }

    /// A success clears only failures that settled BEFORE it was reserved.
    /// Offer A is reserved, then B; B is rejected while A is in flight; A's success lands.
    /// B's rejection may be the newer server state -- a password changed between them -- so
    /// it must still count, and one more rejection spends the budget. Clearing it would buy
    /// an extra offer each time the race recurs.
    #[test]
    fn a_success_does_not_clear_a_failure_that_landed_while_it_was_in_flight() {
        let budget = CredentialBudget::default();
        let mut a = budget.reserve("s:445", 7).expect("first slot");
        let mut b = budget.reserve("s:445", 7).expect("second slot");
        a.sent = true;
        b.sent = true;
        b.settle(Settled::Rejected);
        a.settle(Settled::Accepted);
        let mut c = budget
            .reserve("s:445", 7)
            .expect("one failure leaves a slot");
        c.sent = true;
        c.settle(Settled::Rejected);
        assert!(
            budget.spent("s:445", 7).is_some(),
            "a stale success cleared a newer rejection and bought an offer"
        );
    }

    /// The other side of the same rule: a success reserved AFTER a failure settled does clear
    /// it, so a transient failure before a real success does not spend the budget.
    #[test]
    fn a_success_reserved_after_a_failure_clears_it() {
        let budget = CredentialBudget::default();
        let mut a = budget.reserve("s:445", 7).expect("a slot");
        a.sent = true;
        a.settle(Settled::Unanswered);
        let mut b = budget.reserve("s:445", 7).expect("a slot");
        b.sent = true;
        b.settle(Settled::Accepted);
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER - 1 {
            let mut o = budget
                .reserve("s:445", 7)
                .expect("the budget was given back");
            o.sent = true;
            o.settle(Settled::Rejected);
        }
        assert!(
            budget.spent("s:445", 7).is_none(),
            "a success reserved after the failure did not clear it"
        );
    }

    /// What a REAL login settles as, for each shape of answer -- the producer the budget's own
    /// tests cannot see. A mapping that promoted a guest, a
    /// mis-signed or an unsigned-under-`-smb.sign` success to `Accepted` fails here.
    #[test]
    fn a_real_login_settles_as_what_its_answer_proves() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD, USER};
        let cases: [(&str, Script, bool, &str, Settled); 8] = [
            (
                "unsigned success",
                Script::unsigned(Answer::Accept(Signature::Correct)),
                false,
                PASSWORD,
                Settled::Accepted,
            ),
            (
                "signed success that verifies",
                Script::signing(),
                false,
                PASSWORD,
                Settled::Accepted,
            ),
            (
                "guest",
                Script::unsigned(Answer::Guest),
                false,
                PASSWORD,
                Settled::Rejected,
            ),
            (
                "signed session, unsigned success",
                Script {
                    answer: Answer::Accept(Signature::Absent),
                    ..Script::signing()
                },
                false,
                PASSWORD,
                Settled::Unverified,
            ),
            (
                "signed session, mis-signed success",
                Script {
                    answer: Answer::Accept(Signature::Wrong),
                    ..Script::signing()
                },
                false,
                PASSWORD,
                Settled::Unverified,
            ),
            (
                "-smb.sign, server answers unsigned",
                Script::unsigned(Answer::Accept(Signature::Absent)),
                true,
                PASSWORD,
                Settled::Unverified,
            ),
            (
                "signed session, success under a key the password did not derive",
                Script {
                    answer: Answer::AcceptAnything(Signature::Correct),
                    ..Script::signing()
                },
                false,
                "wrong",
                Settled::Unverified,
            ),
            (
                "locked out",
                Script::unsigned(Answer::Fail(proto::STATUS_ACCOUNT_LOCKED_OUT)),
                false,
                PASSWORD,
                Settled::Account(proto::STATUS_ACCOUNT_LOCKED_OUT),
            ),
        ];
        for (what, script, require_signing, password, want) in cases {
            let peer = spawn(script);
            let mut conn = Conn::connect_requiring(
                "127.0.0.1",
                peer.port,
                Duration::from_secs(5),
                require_signing,
            )
            .expect("connects");
            let _ = conn.login(USER, password, "");
            assert_eq!(settlement(&conn), want, "{what}");
        }
    }

    /// A send to a SLOWLY-DRAINING peer is bounded by the ABSOLUTE deadline, not merely a
    /// per-syscall timeout, and is reported as `TimedOut`.
    ///
    /// The distinction is the whole point: the per-syscall write timeout is set generously
    /// (10 s), and the peer keeps making room a little at a time, so each `write` returns
    /// `Ok(small)` well inside that timeout and never itself fails -- only the 1 s aggregate
    /// deadline stops the loop. A per-syscall-only implementation would run until the whole
    /// 32 MiB drained (seconds), so the sub-3 s bound distinguishes the two clocks. A peer
    /// that never reads would NOT: one blocked write hits the per-syscall timeout at ~1 s
    /// either way, which is why a never-reader cannot tell them apart. (The kind assert is
    /// not decorative: a timed-out send on Linux returns `WouldBlock`, not `TimedOut` -- it
    /// is easy to assume this host returns `TimedOut` natively, and a probe showed errno 11.)
    #[test]
    fn a_slowly_drained_send_is_bounded_by_the_absolute_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let mut chunk = [0u8; 64 << 10];
                // drain ~64 KiB every 10 ms (~6 MiB/s): fast enough that 32 MiB would finish in
                // seconds if unbounded, slow enough that each write makes partial progress and
                // never itself times out against the 10 s per-syscall timeout
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match Read::read(&mut s, &mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let started = std::time::Instant::now();
        let big = vec![0u8; 32 << 20];
        let r = super::super::conn::write_by_deadline(
            &mut sock,
            &big,
            Some(started + Duration::from_secs(1)),
            "peer",
        );
        let e = r.expect_err("32 MiB draining at ~6 MiB/s cannot finish inside a 1 s deadline");
        assert_eq!(
            e.kind(),
            io::ErrorKind::TimedOut,
            "a timed-out send named the wrong kind: {e:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the send outlived its absolute deadline: {:?}",
            started.elapsed()
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(sock);
        let _ = reader.join();
    }

    /// A login that never finishes is bounded by ONE deadline, not by a timeout per read.
    ///
    /// With the handshake timeout applied to each read, a server answering the AUTHENTICATE
    /// a byte at a time would hold its budget slot as long as it liked -- and every other
    /// worker for the account would wait in `reserve`, whose "bounded" would rest on a
    /// deadline that did not exist.
    #[test]
    fn a_login_that_never_finishes_is_bounded_by_one_deadline() {
        use crate::smb::scripted::{spawn, Answer, Script};
        let mut script = Script::unsigned(Answer::Reject);
        script.trickle = Some(Duration::from_millis(100));
        let peer = spawn(script);
        let pool = pool_at(
            peer.port,
            Settings {
                handshake_secs: Some(1),
                ..as_user("wrong")
            },
        );
        let started = std::time::Instant::now();
        let _ = pool.open();
        // the answer takes ~8 s to trickle out; one deadline per offer, two offers, is ~2 s
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a trickled answer held the login for {:?}",
            started.elapsed()
        );
        // and it was the ANSWER that was bounded: both offers reached the peer, so a fast
        // failure somewhere earlier is not what passed this
        assert_eq!(peer.authenticates(), CREDENTIAL_GIVE_UP_AFTER);
    }

    /// A worker that queued for a budget slot longer than the handshake deadline still gets a
    /// whole deadline for its own offer.
    ///
    /// The deadline bounds how long an offer is in flight, so it starts when the slot is
    /// taken. Started at the dial, a worker that waited past it would write its credential and
    /// time out on the answer at once -- an offer spent, and counted, on nothing but its wait.
    #[test]
    fn a_worker_that_queued_past_the_deadline_still_gets_a_whole_one() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        // the answer takes most of a deadline, so a restart to anything much shorter fails
        let mut script = Script::unsigned(Answer::Accept(Signature::Correct));
        script.delay_answer = Some(Duration::from_millis(600));
        let peer = spawn(script);
        let pool = Arc::new(pool_at(
            peer.port,
            Settings {
                handshake_secs: Some(1),
                ..as_user(PASSWORD)
            },
        ));
        let budget = pool.credential.clone();
        let held: Vec<_> = (0..CREDENTIAL_GIVE_UP_AFTER)
            .map(|_| budget.reserve("h", 0).expect("a free slot"))
            .collect();
        let waiter = {
            let pool = pool.clone();
            std::thread::spawn(move || pool.open().map(drop))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while budget.state.lock().unwrap().waiting < 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the waiter never reached the budget"
            );
            std::thread::yield_now();
        }
        // queue it for longer than its whole handshake deadline
        std::thread::sleep(Duration::from_millis(1500));
        drop(held);
        waiter
            .join()
            .expect("the waiter panicked")
            .expect("a worker that waited must still log in");
        assert_eq!(peer.authenticates(), 1, "the wait itself cost an offer");
    }

    /// The server is part of the fingerprint: the same credential text at two HOSTS -- not
    /// merely two ports, which is all the arm below varies -- is two credentials.
    #[test]
    fn the_fingerprint_varies_with_the_host_as_well_as_the_port() {
        assert_ne!(
            credential_id("files-a", 445, "", "tester", "p"),
            credential_id("files-b", 445, "", "tester", "p")
        );
        assert_ne!(
            credential_id("files-a", 445, "", "tester", "p"),
            credential_id("files-a", 446, "", "tester", "p")
        );
        // THE CONTROL: the same server spelled in another case is the same credential
        assert_eq!(
            credential_id("FILES-A", 445, "corp", "Tester", "p"),
            credential_id("files-a", 445, "CORP", "tester", "p")
        );
    }

    /// The same user and password text at two servers is two credentials.
    ///
    /// `tester` with one password can be a LOCAL account on each of two servers, right on
    /// one and wrong on the other. Without the server in the fingerprint, every success on
    /// the first would clear the second's failures.
    #[test]
    fn the_same_credential_text_at_two_servers_is_two_credentials() {
        use crate::smb::scripted::{spawn, Answer, Script, Signature, PASSWORD};
        let refusing = spawn(Script::unsigned(Answer::Reject));
        let accepting = spawn(Script::unsigned(Answer::Accept(Signature::Correct)));
        let shared = Arc::new(CredentialBudget::default());
        let mut a = pool_at(refusing.port, as_user(PASSWORD));
        a.credential = shared.clone();
        let mut b = pool_at(accepting.port, as_user(PASSWORD));
        b.credential = shared;
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            let _ = a.open();
            let _ = b.open();
        }
        assert_eq!(
            refusing.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "successes at one server re-armed the same text's failures at another"
        );
    }

    /// One wrong password spelled two ways for one account is still offered at most the
    /// budget in total.
    ///
    /// The gate sums every credential's failures, and this pins that: a gate on each
    /// credential's own count passes every other arm here while letting `CORP\\tester` and
    /// `tester` spend two offers each -- four against a lockout threshold of three.
    #[test]
    fn one_wrong_password_under_two_spellings_is_offered_at_most_the_budget() {
        use crate::smb::scripted::{spawn, Answer, Script};
        let (a, b) = (
            spawn(Script::unsigned(Answer::Reject)),
            spawn(Script::unsigned(Answer::Reject)),
        );
        let shared = Arc::new(CredentialBudget::default());
        let mut plain = pool_at(a.port, as_user("wrong"));
        plain.credential = shared.clone();
        let mut spelled = pool_at(
            b.port,
            Settings {
                user: Some(format!("CORP\\{}:wrong", crate::smb::scripted::USER)),
                ..as_user("wrong")
            },
        );
        spelled.credential = shared;
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 1 {
            let _ = plain.open();
            let _ = spelled.open();
        }
        assert_eq!(
            a.authenticates() + b.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "two spellings of one account each got a budget"
        );
    }

    /// A handshake that fails before the credential goes out spends nothing, and gives its
    /// slot back.
    #[test]
    fn a_login_that_fails_before_the_credential_goes_out_spends_nothing() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let pool = pool_at(port, as_user("wrong"));
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            let e = pool.open().map(drop).expect_err("nothing is listening");
            assert_ne!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "a connection nobody answered was counted as an offer: {e}"
            );
        }
        let s = pool.credential.state.lock().unwrap();
        assert_eq!(
            (s.totals().failed, s.in_flight),
            (0, 0),
            "a reservation whose credential never went out was counted or leaked"
        );
        drop(s);

        // and a connection the server drops AFTER answering NEGOTIATE, before the challenge:
        // the login fails inside `login_offering`, down the settle path rather than a drop
        use crate::smb::scripted::{spawn, Answer, Script};
        let mut script = Script::unsigned(Answer::Reject);
        script.hang_up_at_challenge = true;
        let peer = spawn(script);
        let pool = pool_at(peer.port, as_user("wrong"));
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            let e = pool.open().map(drop).expect_err("the server hangs up");
            assert_ne!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "a login that died before its credential went out was counted: {e}"
            );
        }
        assert_eq!(peer.authenticates(), 0);
        assert!(
            peer.connections() > CREDENTIAL_GIVE_UP_AFTER,
            "the arm never reached the peer"
        );
        let s = pool.credential.state.lock().unwrap();
        assert_eq!((s.totals().failed, s.in_flight), (0, 0));
    }

    /// A guest session spends the budget like the rejection it is.
    #[test]
    fn a_guest_session_spends_the_budget_as_a_rejection() {
        use crate::smb::scripted::{spawn, Answer, Script};
        let peer = spawn(Script::unsigned(Answer::Guest));
        let pool = pool_at(peer.port, as_user("wrong"));
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            assert!(
                pool.open().is_err(),
                "a guest session must not open a pool session"
            );
        }
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "guest sessions reset the budget"
        );
    }

    /// Two pools for one account share one budget -- through the constructor production
    /// actually uses.
    ///
    /// Lockout counts per account. A copy between two shares in one domain, under one user,
    /// offers one password to both, and a budget per pool would let it offer twice the
    /// budget. The user name is unique to this arm so the process-wide registry cannot be
    /// touched by any other.
    #[test]
    fn two_trees_for_one_account_spend_one_budget() {
        use crate::smb::scripted::{spawn, Answer, Script};
        let peer = spawn(Script::unsigned(Answer::Reject));
        let settings = Settings {
            user: Some("CORP\\budget-arm-account:wrong".into()),
            handshake_secs: Some(5),
            require_signing: false,
        };
        let log = crate::ports::Silent;
        for _ in 0..CREDENTIAL_GIVE_UP_AFTER + 2 {
            // a NEW tree, and so a new pool, every time
            let e = SmbTree::connect(
                None,
                "127.0.0.1",
                Some(peer.port),
                "DATA",
                Path::new(""),
                false,
                &settings,
                &log,
            )
            .map(drop)
            .expect_err("rejected");
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        }
        assert_eq!(
            peer.authenticates(),
            CREDENTIAL_GIVE_UP_AFTER,
            "separate pools for one account must share one budget"
        );
        // case-insensitively, as Windows matches account names
        assert!(Arc::ptr_eq(
            &CredentialBudget::for_account("BUDGET-ARM-ACCOUNT"),
            &CredentialBudget::for_account("budget-arm-account")
        ));
        // and across the spellings Windows treats as one account: a UPN, the local-machine
        // domain `.`, and no domain at all
        let one = CredentialBudget::for_account("budget-arm-account");
        for (domain, user) in [
            ("", "budget-arm-account@corp.example"),
            (".", "budget-arm-account"),
            ("", "budget-arm-account"),
            // and handed an UNSPLIT name, which `parts` never produces but this must not rely on
            ("", "CORP\\budget-arm-account"),
            ("", ".\\budget-arm-account"),
            ("", "corp/Budget-Arm-Account"),
        ] {
            assert!(
                Arc::ptr_eq(&one, &CredentialBudget::for_account(user)),
                "{domain:?} {user:?} got its own budget"
            );
        }
        // THE CONTROL: another account is another budget
        assert!(!Arc::ptr_eq(
            &CredentialBudget::for_account("budget-arm-account"),
            &CredentialBudget::for_account("budget-arm-other")
        ));
    }

    /// A SUCCESSFUL handshake re-arms the retry.
    ///
    /// Separated from the arm above because it needs something the arm above cannot have: a
    /// server that actually completes a handshake. Without one, `Pool::open` never reaches
    /// its `Ok` arm, so the line that resets the counter never executes and any assertion
    /// about it is decoration: deleting the line would leave the suite green.
    ///
    /// The counter is set by hand here and that is fine: HOW it got high is not the property.
    /// The property is that one real success clears it, and deleting
    /// `consecutive_failures.store(0, ..)` from the success path fails this.
    #[test]
    fn a_successful_handshake_re_arms_the_breaker() {
        use std::sync::atomic::Ordering;
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        let pool = pool_at(server.port, Settings::default());
        pool.consecutive_failures
            .store(HANDSHAKE_GIVE_UP_AFTER + 5, Ordering::SeqCst);
        // tripped, so this open gets ONE attempt -- which against a live server is enough
        let session = pool.open().expect("the stand-in completes a handshake");
        assert_eq!(
            pool.consecutive_failures.load(Ordering::SeqCst),
            0,
            "a successful handshake must clear the failure count"
        );
        drop(session);
        server.stop();
    }

    /// The handshake deadline is a knob, and the precedence is flag, then environment,
    /// then the built-in.
    ///
    /// Ten seconds was measured entirely against a Samba on loopback. A share over a
    /// satellite hop or a congested VPN can legitimately need longer, and there a short fuse
    /// turns a slow server into an unreachable one.
    #[test]
    fn the_handshake_deadline_is_settable_and_a_nonsense_value_falls_back() {
        // No flag and no environment: the built-in. (The environment is not set in this
        // process; an arm that mutated it would race every other arm in the binary.)
        assert_eq!(Settings::default().handshake_timeout(), HANDSHAKE_TIMEOUT);
        // The flag.
        let s = |secs| Settings {
            user: None,
            handshake_secs: secs,
            require_signing: false,
        };
        assert_eq!(s(Some(90)).handshake_timeout(), Duration::from_secs(90));
        // THE CONTROL: zero is not a deadline, it is a guarantee that every connection
        // fails instantly, so it falls back rather than being honored. The flag parser
        // rejects it before this point; this is the second line of defense for the
        // environment variable, which has no parser.
        assert_eq!(
            s(Some(0)).handshake_timeout(),
            HANDSHAKE_TIMEOUT,
            "zero must not become an instant-failure deadline"
        );
        // and the knob really is larger than the default, or the arm above would pass on a
        // function that ignored its argument and returned a constant
        assert!(s(Some(90)).handshake_timeout() > Settings::default().handshake_timeout());
    }

    /// A peer that answers requests IN ORDER with the given (status, body) pairs -- echoing
    /// each request's command and id, marked as a response -- and reports the commands it
    /// saw. It hangs up once the answers run out.
    fn answering(answers: Vec<(u32, Vec<u8>)>) -> (u16, std::thread::JoinHandle<Vec<u16>>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // bounded, so a client that sends fewer requests than scripted fails the arm
            // instead of hanging it (a FLUSH the client never sends would otherwise hang here)
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut seen = Vec::new();
            for (status, body) in answers {
                let mut nb = [0u8; 4];
                if s.read_exact(&mut nb).is_err() {
                    break;
                }
                let mut req =
                    vec![0u8; ((nb[1] as usize) << 16) | ((nb[2] as usize) << 8) | nb[3] as usize];
                s.read_exact(&mut req).unwrap();
                let command = u16::from_le_bytes([req[12], req[13]]);
                seen.push(command);
                let id = u64::from_le_bytes(req[24..32].try_into().unwrap());
                let mut msg = proto::Header {
                    command,
                    message_id: id,
                    session_id: 0,
                    tree_id: 0,
                    credits: 1,
                    credit_charge: 1,
                }
                .bytes();
                msg[8..12].copy_from_slice(&status.to_le_bytes());
                msg[16..20].copy_from_slice(&proto::FLAGS_SERVER_TO_REDIR.to_le_bytes());
                msg.extend_from_slice(&body);
                let n = msg.len();
                let mut frame = vec![0, (n >> 16) as u8, (n >> 8) as u8, n as u8];
                frame.extend_from_slice(&msg);
                s.write_all(&frame).unwrap();
            }
            seen
        });
        (port, peer)
    }

    fn session_to(port: u16) -> Session {
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        Session {
            conn: Conn::over(sock),
            tree: 0,
        }
    }

    fn create_answer(attrs: u32) -> Vec<u8> {
        let mut b = vec![0u8; 88];
        b[0..2].copy_from_slice(&89u16.to_le_bytes());
        b[56..60].copy_from_slice(&attrs.to_le_bytes()); // FileAttributes, after 8 + 32 + 16
        b
    }

    fn close_answer() -> Vec<u8> {
        let mut b = vec![0u8; 60];
        b[0..2].copy_from_slice(&60u16.to_le_bytes());
        b
    }

    fn error_answer() -> Vec<u8> {
        let mut b = vec![0u8; 9];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        b
    }

    fn listing_answer(page: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&9u16.to_le_bytes());
        b.extend_from_slice(&((proto::HEADER + 8) as u16).to_le_bytes());
        b.extend_from_slice(&(page.len() as u32).to_le_bytes());
        b.extend_from_slice(page);
        b
    }

    fn dir_record(name: &[u8], next: u32) -> Vec<u8> {
        let mut r = vec![0u8; BOTH_DIR_NAME_AT];
        r[0..4].copy_from_slice(&next.to_le_bytes());
        r[56..60].copy_from_slice(&ATTR_NORMAL.to_le_bytes());
        r[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
        r.extend_from_slice(name);
        r
    }

    fn test_tree() -> SmbTree {
        SmbTree {
            pool: Arc::new(pool_at(1, Settings::default())),
            root: String::new(),
            display: PathBuf::from("smb://test/DATA"),
        }
    }

    /// A name is refused when it is empty or odd-length, and flagged when it is not valid
    /// UTF-16 -- lossy decoding makes two names differing in an unpaired surrogate equal, so
    /// one file overwrites the other -- and a chain whose next record starts past the page is
    /// refused, not read as complete.
    #[test]
    fn a_directory_entry_needs_a_real_name_and_a_chain_that_ends_on_its_page() {
        assert!(
            parse_both_dir(&dir_record(&ntlm::utf16le("ok"), 0)).is_ok(),
            "the control must parse"
        );
        for (what, name) in [("empty", Vec::new()), ("odd-length", vec![b'a', 0, b'b'])] {
            let e = parse_both_dir(&dir_record(&name, 0))
                .expect_err(what)
                .to_string();
            assert!(e.contains("name"), "{what}: {e}");
        }
        // Legitimate on NTFS, so the ENTRY is flagged -- not the listing refused, and not
        // decoded into a name that could collide with another.
        for (what, name) in [
            ("an unpaired surrogate", vec![b'a', 0, 0x00, 0xd8]),
            ("a separator", ntlm::utf16le("a\\b")),
        ] {
            let out = parse_both_dir(&dir_record(&name, 0)).expect(what);
            assert!(out[0].unrepresentable.is_some(), "{what} must be flagged");
        }
        assert!(
            parse_both_dir(&dir_record(&ntlm::utf16le("ok"), 0)).unwrap()[0]
                .unrepresentable
                .is_none(),
            "an ordinary name is not flagged"
        );
        let e = parse_both_dir(&dir_record(&ntlm::utf16le("a"), 1000))
            .expect_err("a next entry past the page")
            .to_string();
        assert!(e.contains("past its"), "{e}");
    }

    /// A READ whose data offset points inside the response header is refused, not returned
    /// as file content.
    #[test]
    fn read_data_inside_the_header_is_refused() {
        let mut body = Vec::new();
        body.extend_from_slice(&17u16.to_le_bytes());
        body.push(0); // DataOffset 0: the header itself
        body.push(0);
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(&[1u8; 16]);
        let (port, peer) = answering(vec![(proto::STATUS_SUCCESS, body)]);
        let mut s = session_to(port);
        let e = s
            .read_at(&[0u8; 16], 0, 16, "reading a file")
            .expect_err("header bytes are not file data");
        assert!(e.to_string().contains("inside the response header"), "{e}");
        drop(s);
        let _ = peer.join();
    }

    /// A path longer than a 16-bit NameLength can carry is refused before anything is sent.
    /// Wrapped, the server would open a short prefix of it -- another file.
    #[test]
    fn a_path_too_long_for_its_length_field_is_refused_not_wrapped() {
        let (port, peer) = answering(Vec::new());
        let mut s = session_to(port);
        let long = "a".repeat(40_000); // 80,000 UTF-16 bytes
        let e = s
            .create(&long, FILE_READ_DATA, 0, FILE_OPEN, 0, "opening")
            .map(|_| ())
            .expect_err("too long for NameLength");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        assert_eq!(s.conn.next_id, 0, "the request went out anyway");
        drop(s);
        let _ = peer.join();
    }

    /// A server that ignores the enumeration cursor is refused, not listed forever -- whether
    /// it repeats one page or cycles through several. A name listed twice is listed once.
    #[test]
    fn a_listing_that_stops_advancing_is_refused_and_a_repeated_name_listed_once() {
        let a = listing_answer(&dir_record(&ntlm::utf16le("a"), 0));
        let b = listing_answer(&dir_record(&ntlm::utf16le("b"), 0));
        // a cycle: a, b, then a, b, a, b ... never NO_MORE_FILES
        let mut answers = vec![(proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY))];
        for i in 0..STALE_PAGES + 4 {
            answers.push((
                proto::STATUS_SUCCESS,
                if i % 2 == 0 { a.clone() } else { b.clone() },
            ));
        }
        answers.push((proto::STATUS_SUCCESS, close_answer()));
        let (port, peer) = answering(answers);
        let mut s = session_to(port);
        let e = test_tree()
            .readdir(&mut s, "")
            .expect_err("a cycle never ends")
            .to_string();
        assert!(e.contains("nothing new"), "{e}");
        drop(s);
        let _ = peer.join();
        // the control: a name repeated once on a later page is listed once, and the listing ends
        let mut page2 = dir_record(&ntlm::utf16le("b"), (BOTH_DIR_NAME_AT + 2) as u32);
        page2.extend_from_slice(&dir_record(&ntlm::utf16le("a"), 0));
        let (port, peer) = answering(vec![
            (proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY)),
            (proto::STATUS_SUCCESS, a.clone()),
            (proto::STATUS_SUCCESS, listing_answer(&page2)),
            (proto::STATUS_NO_MORE_FILES, error_answer()),
            (proto::STATUS_SUCCESS, close_answer()),
        ]);
        let mut s = session_to(port);
        let names: Vec<String> = test_tree()
            .readdir(&mut s, "")
            .expect("lists")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            names,
            vec!["a".to_string(), "b".to_string()],
            "a name listed twice must be listed once"
        );
        drop(s);
        let _ = peer.join();
    }

    /// NO_SUCH_FILE ends a listing in any position, as NO_MORE_FILES does, not only as the
    /// first answer: servers end enumerations with either (see `Session::query_dir`).
    #[test]
    fn no_such_file_ends_a_listing_wherever_it_comes() {
        let page = dir_record(&ntlm::utf16le("a"), 0);
        let (port, peer) = answering(vec![
            (proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY)),
            (proto::STATUS_SUCCESS, listing_answer(&page)),
            (proto::STATUS_NO_SUCH_FILE, error_answer()),
            (proto::STATUS_SUCCESS, close_answer()),
        ]);
        let mut s = session_to(port);
        assert_eq!(test_tree().readdir(&mut s, "").expect("lists").len(), 1);
        drop(s);
        let _ = peer.join();
    }

    /// A stream that comes up SHORT of what `reserve` declared leaves a file of the length
    /// that arrived, not the declared length with a zero tail. The engine calls
    /// `reserve(item.size)`; a source that shrank then streams fewer bytes.
    #[test]
    fn a_short_stream_does_not_leave_a_zero_tail_at_the_declared_length() {
        let mut ack = vec![0u8; 16];
        ack[0..2].copy_from_slice(&17u16.to_le_bytes());
        ack[4..8].copy_from_slice(&10u32.to_le_bytes()); // Count: all ten bytes
        let (port, peer) = answering(vec![
            (proto::STATUS_SUCCESS, vec![2, 0]), // SET_INFO: the reserve
            (proto::STATUS_SUCCESS, ack),        // WRITE
            (proto::STATUS_SUCCESS, vec![2, 0]), // SET_INFO: the length that arrived
            (proto::STATUS_SUCCESS, close_answer()),
        ]);
        let tree = test_tree();
        let mut sink = SmbSink {
            pool: tree.pool.clone(),
            sess: Some(session_to(port)),
            id: [0u8; 16],
            rel: "f".into(),
            pos: 0,
            written: 0,
            reserved: 0,
            chunk: 1 << 16,
            closed: false,
        };
        sink.reserve(100).expect("reserve");
        sink.write(&[1u8; 10]).expect("write");
        let item = tree.item_of("f", Kind::File, 100, 0, 0);
        sink.finish(
            &item,
            &[],
            MetaOptions {
                mode: false,
                times: false,
                owner: false,
                atime: false,
            },
            false,
        )
        .expect("finish");
        drop(sink);
        assert_eq!(
            peer.join().unwrap(),
            vec![proto::SET_INFO, proto::WRITE, proto::SET_INFO, proto::CLOSE],
            "the declared length was left in place"
        );
    }

    /// A write that would carry the offset past `u64::MAX` is refused before it is sent, not
    /// wrapped to a low offset that `finish` then cuts the file to.
    #[test]
    fn a_write_past_the_largest_offset_is_refused_before_it_is_sent() {
        let (port, peer) = answering(Vec::new());
        let tree = test_tree();
        let mut sink = SmbSink {
            pool: tree.pool.clone(),
            sess: Some(session_to(port)),
            id: [0u8; 16],
            rel: "f".into(),
            pos: 0,
            written: 0,
            reserved: 0,
            chunk: 1 << 16,
            closed: true,
        };
        sink.hole(u64::MAX - 10)
            .expect("a hole up to just short of the top");
        let e = sink
            .write(&[1u8; 20])
            .expect_err("20 bytes past u64::MAX - 10");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        assert_eq!(
            sink.sess.as_ref().unwrap().conn.next_id,
            0,
            "the write went out anyway"
        );
        drop(sink);
        let _ = peer.join();
    }

    /// `-fsync` sends a FLUSH before the CLOSE, and without it none is sent. Accepted and
    /// ignored, it would report a file durable while the server might still be caching it.
    #[test]
    fn fsync_flushes_the_file_before_closing_it() {
        for fsync in [true, false] {
            let answers = if fsync {
                vec![
                    (proto::STATUS_SUCCESS, vec![4, 0, 0, 0]),
                    (proto::STATUS_SUCCESS, close_answer()),
                ]
            } else {
                vec![(proto::STATUS_SUCCESS, close_answer())]
            };
            let (port, peer) = answering(answers);
            let tree = test_tree();
            let mut sink = SmbSink {
                pool: tree.pool.clone(),
                sess: Some(session_to(port)),
                id: [0u8; 16],
                rel: "f".into(),
                pos: 0,
                written: 0,
                reserved: 0,
                chunk: 1 << 16,
                closed: false,
            };
            let item = tree.item_of("f", Kind::File, 0, 0, 0);
            let opts = MetaOptions {
                mode: false,
                times: false,
                owner: false,
                atime: false,
            };
            sink.finish(&item, &[], opts, fsync).expect("finishes");
            drop(sink);
            let seen = peer.join().unwrap();
            let want = if fsync {
                vec![proto::FLUSH, proto::CLOSE]
            } else {
                vec![proto::CLOSE]
            };
            assert_eq!(seen, want, "fsync={fsync}");
        }
    }

    /// A READ answered with MORE data than it asked for is refused -- as a WRITE
    /// acknowledging more than it was given already is. The reader would advance its offset
    /// by the server's count, past what it requested.
    #[test]
    fn a_read_answered_with_more_than_it_asked_for_is_refused() {
        use std::io::Write;
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
            let mut msg = proto::Header {
                command: proto::READ,
                message_id: id,
                session_id: 0,
                tree_id: 0,
                credits: 1,
                credit_charge: 1,
            }
            .bytes();
            msg[16..20].copy_from_slice(&proto::FLAGS_SERVER_TO_REDIR.to_le_bytes());
            msg.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
            msg.push(proto::HEADER as u8 + 16); // DataOffset
            msg.push(0);
            msg.extend_from_slice(&32u32.to_le_bytes()); // DataLength: twice what was asked
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&0u32.to_le_bytes());
            msg.extend_from_slice(&[9u8; 32]);
            let n = msg.len();
            let mut frame = vec![0, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            frame.extend_from_slice(&msg);
            s.write_all(&frame).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut session = Session {
            conn: Conn::over(sock),
            tree: 0,
        };
        let e = session
            .read_at(&[0u8; 16], 0, 16, "reading a file")
            .expect_err("32 bytes for a 16-byte read");
        assert!(e.to_string().contains("to a 16-byte read"), "{e}");
        let _ = peer.join();
    }

    /// A name that decodes lossily to U+FFFD and a real U+FFFD name are two files, and both
    /// are kept -- deduplication is on the raw bytes (on the decoded name the valid one would
    /// be dropped as a duplicate of the flagged one).
    #[test]
    fn a_lossy_name_does_not_shadow_a_real_one_that_decodes_the_same() {
        let mut page = dir_record(&[0x00, 0xd8], (BOTH_DIR_NAME_AT + 2) as u32); // lone surrogate
        page.extend_from_slice(&dir_record(&[0xfd, 0xff], 0)); // U+FFFD itself
        let (port, peer) = answering(vec![
            (proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY)),
            (proto::STATUS_SUCCESS, listing_answer(&page)),
            (proto::STATUS_NO_MORE_FILES, error_answer()),
            (proto::STATUS_SUCCESS, close_answer()),
        ]);
        let mut s = session_to(port);
        let out = test_tree().readdir(&mut s, "").expect("lists");
        assert_eq!(
            out.len(),
            2,
            "one of two distinct names was dropped as a duplicate: {out:?}"
        );
        assert_eq!(
            out.iter().filter(|e| e.unrepresentable.is_none()).count(),
            1,
            "the real U+FFFD name must be copyable"
        );
        drop(s);
        let _ = peer.join();
    }

    /// A directory AT the depth limit is not listed -- its entries could not be used, and a
    /// failure to read it would fail the run for nothing. The peer answers
    /// the root's stat and listing only; a listing of `a` would find it out of answers and
    /// land in the errors.
    #[test]
    fn a_directory_at_the_depth_limit_is_not_read() {
        let mut a = dir_record(&ntlm::utf16le("a"), 0);
        a[56..60].copy_from_slice(&ATTR_DIRECTORY.to_le_bytes());
        let (port, peer) = answering(vec![
            (proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY)), // stat "."
            (proto::STATUS_SUCCESS, close_answer()),
            (proto::STATUS_SUCCESS, create_answer(ATTR_DIRECTORY)), // list "."
            (proto::STATUS_SUCCESS, listing_answer(&a)),
            (proto::STATUS_NO_MORE_FILES, error_answer()),
            (proto::STATUS_SUCCESS, close_answer()),
        ]);
        let tree = test_tree();
        tree.pool.give(session_to(port));
        let listing = tree.list(&Filter::default(), Some(1), 1).expect("lists");
        assert!(
            listing.errors.is_empty(),
            "a directory at the depth limit was read: {:?}",
            listing.errors
        );
        assert!(
            listing.items.iter().any(|i| i.rel == "a"),
            "the directory itself is within the depth and must be listed"
        );
        drop(tree);
        let _ = peer.join();
    }

    /// A root that is not there when it is listed makes an INCOMPLETE listing, not an empty
    /// one: an empty listing with no errors is what a complete listing of an
    /// empty source looks like, and a mirror or sync would plan every destination or catalog
    /// entry as gone. The tree is built directly, so the connect check that normally catches
    /// a missing root first cannot -- standing in for a root that vanished after it.
    #[test]
    fn a_root_that_is_not_there_lists_as_incomplete_not_empty() {
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        let tree = SmbTree {
            pool: Arc::new(pool_at(server.port, Settings::default())),
            root: "not-there".into(),
            display: PathBuf::from("smb://test/DATA/not-there"),
        };
        // NotFound, not an empty listing: a source run ends on it, and a dry run's destination
        // plans against it as empty (an incomplete listing would make a dry run's destination
        // report as unreadable)
        let e = tree
            .list(&Filter::default(), None, 1)
            .expect_err("a missing root is not a listing");
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        server.stop();
    }

    /// A name a path cannot carry -- here a backslash, legal in a Linux filename the server
    /// lists as-is -- is REPORTED as not copied, while the rest of the directory lists.
    /// Dropping it silently and failing the whole directory are both wrong.
    #[test]
    fn an_unrepresentable_name_is_reported_and_the_rest_of_the_directory_lists() {
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        std::fs::write(server.share.join("fine.txt"), b"x").unwrap();
        std::fs::write(server.share.join("back\\slash.txt"), b"y").unwrap();
        let tree = SmbTree {
            pool: Arc::new(pool_at(server.port, Settings::default())),
            root: String::new(),
            display: PathBuf::from("smb://test/DATA"),
        };
        let listing = tree
            .list(&Filter::default(), None, 1)
            .expect("the directory still lists");
        assert!(
            listing.items.iter().any(|i| i.rel == "fine.txt"),
            "the ordinary file is missing: {:?}",
            listing.items.iter().map(|i| &i.rel).collect::<Vec<_>>()
        );
        assert!(
            !listing.items.iter().any(|i| i.rel.contains("slash")),
            "the unrepresentable name was listed as an item"
        );
        assert!(
            listing.errors.iter().any(|e| e.contains("path separator")),
            "the unrepresentable name was not reported: {:?}",
            listing.errors
        );
        // ...unless the operator excluded it: then it was never part of the copy, and an
        // error would fail the run and stop a sync's deletions over it
        let excluded = Filter {
            exclude: vec!["back*".into()],
            ..Filter::default()
        };
        let listing = tree.list(&excluded, None, 1).expect("lists");
        assert!(
            listing.errors.is_empty(),
            "an excluded entry was reported: {:?}",
            listing.errors
        );
        server.stop();
    }

    /// A file that SHRINKS under the copy is an error, not a short file reported as whole
    /// Otherwise the reader takes the end of the file before the size the open reported as
    /// "end of file", and the copy finishes short -- silent truncation into a local or SMB
    /// destination, which do not check the length themselves.
    #[test]
    fn a_source_that_shrinks_under_the_read_is_refused() {
        let Some(mut server) = crate::smb::testserver::start() else {
            eprintln!("SKIP: python3 with impacket is needed for the smb stand-in server");
            return;
        };
        let path = server.share.join("shrinks.bin");
        std::fs::write(&path, vec![5u8; 300 << 10]).expect("write the fixture");
        let tree = SmbTree {
            pool: Arc::new(pool_at(server.port, Settings::default())),
            root: String::new(),
            display: PathBuf::from("smb://test/DATA"),
        };
        let mut reader = tree.open_read("shrinks.bin").expect("open");
        // the open has recorded 300 KiB; the file is now a third of that
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(100 << 10)
            .unwrap();
        let mut got = Vec::new();
        let e = reader
            .read_to_end(&mut got)
            .expect_err("a file that shrank must not read as complete");
        assert!(e.to_string().contains("changed during the copy"), "{e}");
        drop(reader);
        server.stop();
    }

    /// A READ charges for the DATA, and the tempting alternative is the point of the arm.
    ///
    /// An audit of 545 captured pairs shows a 1 MiB read's response weighing 1048656 bytes
    /// on the wire, which looks like a one-credit under-charge whenever `len` is a multiple
    /// of 64 KiB if only `len` is charged. The obvious "fix" is `HEADER + fixed + len` -- 17
    /// for a megabyte -- and it is tempting to call 16 possibly right and 17 merely generous.
    ///
    /// **The spec settles it, and against that fix.** MS-SMB2 3.1.5.2: the charge is computed
    /// from "the payload size (the size of the data within the variable-length field of the
    /// request) or the maximum size of the response". A header is not payload. 3.3.5.2.5
    /// has the server compute its expected charge from the same definition and fail only
    /// when `calculated > sent` -- which is why 17 is accepted everywhere and why nothing
    /// catches it. It costs a credit and a message id per read, silently.
    ///
    /// The lesson worth keeping: **such an audit measures the right bytes and answers the
    /// wrong question.** "How big is this response" is not "what is this request's payload
    /// size", and no amount of wire capture distinguishes them -- only the document does.
    // The fixed parts of the READ (MS-SMB2 2.2.20) and QUERY_DIRECTORY (2.2.34) responses.
    //
    // HERE, NOT IN THE MODULE ABOVE, and deliberately. Adding them to the credit charge is
    // the message-sized over-charge -- the charge is computed from the PAYLOAD (3.1.5.2).
    // Their only use is the control below, which proves the message-sized computation gives
    // the wrong answer. Kept in production code they would be a warning on every non-test
    // build and a template sitting beside the real call sites, inviting a command to be
    // charged `HEADER + X_RESPONSE_FIXED + len`. In this module they cannot be reached from
    // a call site at all.
    const READ_RESPONSE_FIXED: u32 = 16;
    const QUERY_DIR_RESPONSE_FIXED: u32 = 8;

    #[test]
    fn a_read_charges_for_the_payload_and_not_for_the_message_that_carries_it() {
        let len = 1u32 << 20;
        assert_eq!(
            proto::credit_charge(true, 0, len as usize),
            16,
            "a 1 MiB read is 16 credits, which is what Windows sends"
        );
        // THE CONTROL, and it is the over-charge this replaced: adding the header and the
        // fixed part crosses into a 17th credit. An arm asserting only "16" would pass on a
        // function that ignored its input, and one asserting only "not 17" would pass on
        // anything at all.
        let message = proto::HEADER as u32 + READ_RESPONSE_FIXED + len;
        assert_eq!(
            message, 1_048_656,
            "the response size is not the one the wire showed"
        );
        assert_eq!(
            proto::credit_charge(true, 0, message as usize),
            17,
            "the message-sized computation should still give its old answer"
        );
        // and the boundary itself is where the spec puts it: 64 KiB of payload is one
        // credit, one byte more is two
        assert_eq!(proto::credit_charge(true, 0, 65536), 1);
        assert_eq!(proto::credit_charge(true, 0, 65537), 2);
        // A full directory page is `OutputBufferLength`, which is what 3.3.5.2.5 tells the
        // server to validate against -- so one credit, not the two the message-sized
        // computation charged.
        assert_eq!(proto::credit_charge(true, 0, QUERY_DIR_PAGE as usize), 1);
        assert_eq!(
            proto::credit_charge(
                true,
                0,
                (proto::HEADER as u32 + QUERY_DIR_RESPONSE_FIXED + QUERY_DIR_PAGE) as usize
            ),
            2,
            "the old computation should still give the old answer"
        );
        // A command with no payload in either direction charges 1, which is what
        // MS-SMB2 3.2.4.1.5 requires of everything that is not READ, WRITE, IOCTL or
        // QUERY_DIRECTORY -- "even if the payload size ... is greater than 65536".
        assert_eq!(proto::credit_charge(true, 0, 0), 1);
    }

    /// The largest I/O this client issues fits in the credit window it asks for.
    ///
    /// A request whose CreditCharge exceeds the credits the server has ALREADY granted is
    /// refused, and `CreditRequest` cannot help: it is granted on the response, so it never
    /// pays for the message carrying it. The only thing standing between this client and
    /// that failure is the cap on a single read or write.
    ///
    /// Raising either cap toward the negotiated maximum walks into it: an 8 MiB write --
    /// which is exactly the `MaxWriteSize` Samba advertises here -- is charge 129, against
    /// a window of 64. That is the constant-0 defect one boundary higher, and nothing else
    /// in this repo would catch it.
    #[test]
    fn the_largest_io_this_client_issues_fits_in_the_credit_window_it_asks_for() {
        // READ the two numbers from where they are DEFINED. Local copies of the literals in
        // `conn.rs` and in `write_at`'s chunking (`const REQUESTED: u16 = 64`, `1 << 20`
        // inline) would stay green when either changes at its real site, which makes an arm
        // whose whole purpose is to catch that change worth nothing. Named constants, so the
        // arm moves when the code does.
        let requested = crate::smb::conn::CREDITS_REQUESTED;
        for cap in [crate::smb::conn::READ_CHUNK, WRITE_CHUNK_CAP] {
            let charge = proto::credit_charge(true, 0, cap as usize);
            assert!(charge <= requested, "a {cap}-byte transfer charges {charge}, above the {requested} credits this client asks for");
        }
        // THE CONTROL: the negotiated maximum is NOT safe, so this arm is measuring a real
        // margin rather than a bound nothing could exceed.
        let eight_mib = 8u32 << 20;
        let charge = proto::credit_charge(true, 0, eight_mib as usize);
        assert!(
            charge > requested,
            "an 8 MiB transfer should overrun the window; it charges {charge}"
        );

        // AND WHAT THIS ARM DOES NOT ESTABLISH, said plainly because the name invites the
        // stronger reading. `CREDITS_REQUESTED` is what the client ASKS FOR in every
        // header; the server grants what it likes, and `Conn::call` compares the charge
        // against the GRANTED balance, not this one. So a server that grants less than it
        // is asked for can still refuse a large read, and no arm here can prevent that --
        // the protection for it is the runtime refusal in `call`, which names the numbers.
        // What this bounds is the client's own arithmetic: it never asks for less than its
        // own largest I/O needs.
        assert!(
            proto::credit_charge(true, 0, crate::smb::conn::READ_CHUNK as usize) > 1,
            "if the largest read charged 1 this arm would pass on any window at all, and prove nothing"
        );
    }
}
