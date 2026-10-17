# Windows, Samba and NAS shares: smb://

`smb://[user@]host[:port]/share[/path]` is an SMB2 share. The first path component is the
share — what `TREE_CONNECT` takes — and the rest is a path inside it. Dialects 0x0202,
0x0210 and 0x0300 are offered; 0x0311 deliberately is not, because it requires the preauth
integrity hash this client does not compute — signing, which it does, is a separate matter
and is covered below. Authentication is
NTLMv2, with the credential in `-smb.user [DOMAIN\]USER:PASSWORD` or `RCP_SMB_USER` with
`RCP_SMB_PASSWORD` — never in the URL, which reaches the job log, a report and `ps`, and a
URL carrying one is refused without being quoted back.

Copy, sync, verify, scan, delete and rename all work across it, in both directions. What a
share cannot say is refused or reported rather than invented: there is no POSIX mode and no
owner, so those are synthesized for the listing and `verify` reports them as **not
compared** instead of holding an invented `0644` against a real `0755`; no symlinks and no
hard links, both refused by name (the core copies the file instead); no extended
attributes; and no hole map, so runs of zeros are detected on read and skipped on write, as
on sftp. Modification times do cross, both ways, through `FileBasicInformation` — at SMB's
own resolution, which is the 100-nanosecond FILETIME tick, so a local nanosecond time
arrives rounded down to it. `verify` treats that as equal, the way it already treats a
destination that keeps only seconds or milliseconds. Precisely: the guard is "either side
sits on a tick", not "both do" — it has to be, since the case it exists for is a
nanosecond source against a tick-aligned destination. **An SMB destination is always on a
tick**, so against a share this does accept any source within the same 100 ns bucket. A
file written one tick later is still a difference; one written 40 ns later is not. That is
the same shape as the whole-second tolerance beside it and a thousand times narrower.

One consequence is worth stating because it is a real cost rather than a limitation of the
protocol: `chmod` and `chown` refuse against an `smb://` tree — correctly, since neither
could change anything — and `diag change -mtime` gates on the same predicate, so it is
refused too even though SMB2 could carry it. A copy still sets times.

**Message signing is implemented**, which is what decides where this works. It is tempting
to read the dialect choice as though signing were a cost of 3.1.1. It is not: signing has
been in SMB2 since 0x0202, and the server decides whether to require it — Windows 11 24H2
and Windows Server 2025 require it by default, as does a Samba configured
`server signing = mandatory`, which is usual for a domain member. Against such a server
there is no dialect to fall back to, so until this existed the client read the bit and
refused by name, which is correct and excludes most current deployments. The client now
reads the same bit and signs: HMAC-SHA256 truncated to 16 bytes on 0x0202 and 0x0210,
AES-128-CMAC on 0x0300 with its signing key derived through the SP800-108 counter-mode KDF.
When the server does not require signing, nothing is signed.

On a signed session **every final reply is checked**, and one carrying no signature is
refused exactly like one carrying a wrong signature: a reply that simply clears the flag is
the same tampering. Two exceptions. An unsigned *error* is reported as the status it claims
and marked as unauthenticated; it fails either way, and real servers send them when they
have no key to sign with. It carries no *meaning*, though: its error kind is a neutral one,
so a forged `OBJECT_NAME_NOT_FOUND` cannot make a file read as absent, which a sync's
removal step would act on. The same holds for both `SESSION_SETUP` replies, which no key can
authenticate on any session: their failures are reported as a refused login or as a neutral
error, never as a missing file, so a forged status during login cannot make a destination
read as empty. **On an unsigned session none of this applies**: every reply is the server's
word only, so a sync whose removals should not rest on unauthenticated answers wants
`-smb.sign`. And an interim `STATUS_PENDING` is not verified, since the spec
leaves it unsigned; nothing is taken from it but a wait and a capped credit grant. The final `SESSION_SETUP` response is checked by hand against the
key the login derived, which catches a server that accepts a password it cannot check and an
edit of the dialect the server chose. It does not prove *which* server answered: without
channel binding, NTLM can be relayed to another server that accepts the same credential, and
that session verifies. Nor does it catch a downgrade made by striking dialects from this
client's request, since both ends then agree on the weaker one.

**On its own, that is not a defense against a downgrade**, though it is easy to read it as
one. Signing is armed by a bit in the `NEGOTIATE` response, which arrives before any
session exists and cannot be authenticated. An attacker who clears that bit gets a client
that signs nothing and checks nothing. **`-smb.sign`** (or `RCP_SMB_SIGN=1`) closes that:
the client sets `SIGNING_REQUIRED` in its own `SESSION_SETUP`, which makes a server that
merely *enables* signing sign the session anyway, arms the key whatever the server's bit
says, and refuses a server that will not sign. Measured through a relay counting reply
flags against a Samba with `server signing = auto`: without the flag, every reply but the
final `SESSION_SETUP` came back unsigned. With it, the only unsigned replies were the four
first-round `SESSION_SETUP` answers, which come before any key exists, and one interim
`STATUS_PENDING`, which the spec leaves unsigned. Because an interim reply cannot be
authenticated, the credits one request's replies can add are capped at what that request
asked for. That bounds each injection; repeated on every request it can still walk the
balance past the server's real window, and what that buys is a request the server refuses,
which an on-path party could get more simply by dropping the connection. It is off by default because it puts a MAC
over every byte where nothing asked for one. `FSCTL_VALIDATE_NEGOTIATE_INFO`, which would
also protect the negotiate's other fields, is not implemented.

Signing runs on AES-NI where the CPU has it (`RCP_NO_AES_NI` forces the portable cipher).
Measured on 1 MiB: **100 MB/s portable, 1333 MB/s on AES-NI**. That is the MAC alone. A
signed write copies its payload four times on the way to the socket, and a call-shaped
benchmark of that path ran at about **1019 MB/s**, which is below the 1250 MB/s a 10 GbE
link carries. The signatures are pinned to vectors computed by an independent
implementation (impacket's KDF, Cryptodome's CMAC), because every other arm compares this
code with itself. Replanted, the KDF's context one byte short at the call site left all of
those arms green.

**Measured against a Samba 4.19.5 with `server signing = mandatory`**, at each of the three
dialects this client offers — so both algorithms ran, not just the one the default
negotiates: `scan` of 2114 files, a 213 MB copy out, a copy back in, and a `verify` of the
two, **0 differences and 0 signature complaints in the server's log**. Still not measured:
any Windows server.

Two things about getting there are worth recording, because both failed in the same
uninformative way — `STATUS_ACCESS_DENIED` or a dropped connection, which is exactly what a
wrong password looks like:

- **The KDF input was one byte short.** MS-SMB2 3.1.4.2 passes SP800-108 the NUL-terminated
  strings `"SMB2AESCMAC\0"` and `"SmbSign\0"`, and SP800-108 then adds its *own* `0x00`
  separator after the label — so there are **two** zero bytes between label and context, a
  terminator and a separator that happen to be the same byte. Writing it as "label, NUL,
  context, NUL" gives a completely different key. The unit arm in place at the time asserted
  that changing the label changed the key, and it passed the whole time: a self-consistency
  check cannot see a *missing* byte. The arm that replaced it spells the input out and has
  the original defect replanted as its control.
- **The final SESSION_SETUP request must go out unsigned.** For an initial, non-binding
  authentication the session key exists on the server only once that request's NTLMSSP
  AUTHENTICATE has been processed, so signing it produced `NT_STATUS_INVALID_HANDLE` and a
  server that could not sign its own error reply. `NTLMSSP_NEGOTIATE_SIGN` and
  `ALWAYS_SIGN`, meanwhile, have to be in the NTLMSSP **NEGOTIATE** as well as the
  AUTHENTICATE; with them only in the second, Samba set up no session key at all.

Both were found by reading the server's log — it prints the signature it expected beside the
one it received — rather than by reasoning about the client. Neither was visible from this
side of the wire.

**A real Samba is what found the one defect the stand-in could not see**, and it is worth
saying what each measures. The suite's stand-in is impacket, which negotiates 0x0202 — a
dialect with no credit window, where the header's `CreditCharge` is reserved and ignored.
This client wrote 0 there for every dialect, so the whole suite was green while **any file
over 64 KiB failed to reach a real server**: Samba answers `STATUS_INVALID_PARAMETER`,
which surfaces as "the server could not parse the request" and names nothing about size.
Measured against Samba 4.19.5 on dialect 0x0300: 64 KiB crossed, 64 KiB + 1 did not, with
`MaxWriteSize` reported as 8 MiB — so it was never a cap, it was the charge. It is fixed,
with a unit arm on the formula at the boundary, and a copy, read-back and byte-for-byte
comparison of a 3 MB tree against that Samba now passes. The lesson is the one this repo
keeps paying for: the probe and the real path took different routes, so the probe could not
see the failure.

**And the charge is computed from the PAYLOAD, which took reading the specification to get
right — a capture could not settle it.** An audit of 545 captured request/response pairs
showed a 1 MiB read's response weighing 1048656 bytes on the wire, so charging the data
length alone looked like a one-credit under-charge whenever the length is a multiple of
64 KiB. It was "corrected" to header + fixed part + data, and this document recorded the
question as unsettled: 17 might be generous, Windows sends 16, and over-charging cannot
fail where under-charging can.

[MS-SMB2 3.1.5.2][creditcharge] settles it against that fix. The charge is computed from
*"the payload size (the size of the data within the variable-length field of the request)
or the maximum size of the response"*. A header is not payload. [3.3.5.2.5][verifycharge]
has the server compute its expected charge from the same definition and fail only when its
number **exceeds** what was sent — which is exactly why 17 was accepted everywhere and why
nothing ever caught it, at a cost of one credit and one message id per read.

The audit measured the right bytes and answered the wrong question. "How big is this
response" is not "what is this request's payload size", and no amount of wire capture
distinguishes them. `scripts/smb-audit-credit-charge.py` had the same mistake baked in and
would have gone on reporting a spec-correct client as under-charging, so it now computes
from the payload and prints the message-sized number beside it. Re-measured against that
Samba after the fix, over 401 pairs: READ and WRITE send **16**, need 16, and the
message-sized number is 17 — **0 under-charged**, with the transfers accepted.

[creditcharge]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/18183100-026a-46e1-87a4-46013d534b9c
[verifycharge]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fba3123b-f566-4d8f-9715-0f529e856d25

**A connection occasionally dies during its handshake when several are opened at once, and
the client now notices and dials again.** Against Samba 4.19.5 about one connection in
forty-five never gets an answer to its `SESSION_SETUP`; the server reports
`client used more credits than granted, mid 1, charge 1, credits_granted 0, seqnum
low/range: 1/0` — its credit window empty on a connection whose own `NEGOTIATE` response
granted a credit.

**The wire says the client is not at fault in what it sends.** Across 256 captured
connections, wedged and healthy alike, the `NEGOTIATE` and `SESSION_SETUP` messages hash to
**one value each** — byte-identical, same length, same `CreditCharge`. Every wedge has the
same shape: three messages, then nothing. So there is no message to correct, and the honest
fix at this layer is to notice and reconnect:

- the handshake runs on a **10 s** fuse rather than the 60 s the data path needs, because a
  `NEGOTIATE` either answers promptly or is not going to. That number was measured entirely
  against a Samba on loopback, and a share over a satellite hop or a congested VPN can
  legitimately need longer — so **`-smb.handshake SECONDS`** (or `RCP_SMB_HANDSHAKE`) moves
  it, and 10 is only what it is when nobody says;
- a handshake that fails **at the transport** is retried on a fresh connection, up to three;
- **the retry gives up on a server that is simply gone.** It exists for a race that clears
  on a second connection — one failure in forty-five, independent. When the server is
  stopped or firewalled instead, every failure is correlated and the retry turns each
  worker's one doomed connection into three plus two sleeps, so a pool spends its time
  dialing a host that is not there and the operator waits longer for the same error. After
  **12** consecutive failures across the pool the retry switches off: one attempt, no
  sleep. Twelve is well clear of the independent case. If failures were independent at
  1-in-45, twelve in a row would be about a 1-in-10^19 coincidence. They are not entirely
  independent, though: the wedge happens when several connections open at once, so its
  failures cluster. Read the figure as "far from anything the race was measured to do", not
  as a probability. One
  success re-arms it for everyone, and a **refused credential never counts**, so one bad
  password cannot switch the retry off against a server that is answering fine. The arm
  counts connections against a real listener rather than reading the counter, and was
  checked by removing the breaker and requiring it to fail;
- **a refused credential is never retried.** That is the half that could do harm: three
  attempts per connection across a worker pool is how an account gets locked out by a
  client trying to be helpful. The retryable kinds are named, the default is not to retry,
  and an arm pins it with the `STATUS_LOGON_FAILURE` mapping it depends on;
- **a login the server hung up on is retried, but only inside the credential budget
  below.** No error kind can tell a server refusing a password by closing the socket from
  one that lost a race, and Samba's wedge was measured striking *after* the `AUTHENTICATE`
  as well as before it: a build that declined to retry there failed a file that the
  previous build had copied. The price is that a server restarting mid-login can spend the
  whole budget in one open;
- **the password is offered at most twice in a row without being accepted, per account,
  for the whole run.** A slot is reserved once the challenge is in hand, just before the
  `AUTHENTICATE`, and released when the server answers, so sixteen workers starting together
  cannot overshoot. A login that stalls before its credential holds no slot. (Taking the
  slot before dialing would let a stall at `NEGOTIATE` hold it until the handshake deadline,
  with every login to the account queued behind it.) A worker that waited is
  checked before it writes: if the server closed the connection meanwhile, nothing is sent
  and nothing is counted. Each offer then gets one deadline for its whole answer, however
  the server paces it, so a server answering a byte at a time cannot hold a slot for longer.
  The same deadline bounds the *send*: a peer that stops reading and lets this client's
  socket buffer fill — draining the `AUTHENTICATE` a byte at a time, or not at all — cannot
  hold the slot open any longer than one that stalls the reply, because every `write` is cut
  off at the same clock.
  What an answer *means* is classified, from MS-ERREF's values: only `STATUS_LOGON_FAILURE`
  is a rejected password — it counts and is not retried; an answer about the account itself
  (locked out, disabled, expired, outside its logon hours, a workstation or logon-type
  restriction) counts and stops offering that credential to the server that gave it, with the
  reason in the refusal — another server still gets a try, because a logon-hours or
  workstation restriction is that server's own, and even a lockout seen at one domain member
  need not bind a different one; an answer that never judged the password (a discarded
  session, no reachable domain controller, a server out of resources) counts and is retried
  like a dropped connection. Anything else — `STATUS_ACCESS_DENIED` among it, which a share
  ACL or a firewall can raise without the password being wrong — counts but is named in the
  refusal as the status it was, not reported as a bad password, and is not retried. (It is
  tempting to call `ACCESS_DENIED` a rejection, or to stop the account run-wide on any
  account verdict; both are too broad.)
  The budget is reserved before an offer goes out, not checked and incremented after the
  fact: checking afterward let sixteen wrong passwords through against a budget of three.
  Two, because the Default Domain Policy ships with lockout disabled and DISA's STIGs require
  a threshold of three or fewer, and a budget at the threshold is not a budget. The budget is shared by every
  share the run reaches under one account, keyed by the bare account name so `CORP\alice`
  and `alice@corp.example` are one budget. Failures are recorded per credential and offers
  are gated on their sum, so a right password for one `alice` cannot clear a wrong one's
  failures: a single shared count would let every success on a copy's destination re-arm
  two more wrong offers on its source. A guest session for a named user counts as the
  rejection it is. On a *signed* session only a success whose signature verifies resets
  the budget; an unsigned or mis-signed `STATUS_SUCCESS` counts against it, because that is
  what a forger covering a real rejection would send. **That protection needs `-smb.sign`**:
  without it, the same forger can clear the server's signing bit first, and then there is
  no signature to check. **A success clears only failures that settled before it was
  reserved**, and never an account latch: a signature proves a success is genuine, not that
  it is newer than a lockout or rejection another connection reported while it was in flight.
  An answer already in hand when an offer was reserved is the one ordering the
  server's processing is known to follow. So a transient failure before a real success does
  not spend the budget, while a stale success -- forged, or genuine but delayed -- clears
  nothing. A latched credential cannot be reserved again, so the latch holds for the run.
  (Letting a success clear it is tempting, and letting only a signed one clear it looks
  safer; both are the same hole.) The budget does not span runs. Past it, the refusal says which of
  rejections, account verdicts, hang-ups, unauthenticated answers or unrecognized statuses it
  saw, with advice to match -- an account verdict (a lockout, a disabled account) that a
  *different* credential meets at the summed budget is named as that, not counted among
  "rejected", the same distinction drawn for an unrecognized status;
- the backoff is jittered, so workers that fail together do not retry together;
- the `TREE_CONNECT` that follows a login gets its own full handshake deadline, not
  whatever milliseconds the login's offer had left. The offer's deadline is a budget for the
  `AUTHENTICATE` alone; letting it carry into the next request would time out a tree connect
  for no reason but a slow login before it, so the clock is reset before it. That reset is an
  **absolute** deadline, not the per-syscall socket timeout a plain `set_timeout` leaves: the
  latter lets a peer trickle the tree-connect reply a byte at a time and
  hang the worker, since the deadline-bounded reader falls back to `read_exact` when no
  absolute deadline is set. The tree connect holds no budget slot, but a small fixed exchange
  should not hang;
- a connection whose request went out but whose reply did not come back whole is **never
  used again** -- not for the CLOSE a failed read or write used to send on it, and not by the
  pool. After a timeout mid-READ the rest of that reply is still arriving, and the next
  request would read it as its own answer. On an unsigned session those bytes can be file
  content, which frames as a reply as readily as anything else. A matching message id is not
  a framing guard, so the connection refuses further requests instead of trusting one;
- a reply must carry the response flag as well as the request's id and command: a request
  reflected back matches both, and on a signed session its signature verifies, since one key
  signs both directions;
- a file that ends before the size its open reported is an error ("the source changed during
  the copy"), not a short file reported as whole; a READ returning more than it asked for, or
  data placed inside the response header, is refused; a listing whose pages stop naming
  anything new (a server ignoring the cursor) is refused, a name listed twice is listed once,
  and an empty name is refused; a name a path cannot carry -- an unpaired surrogate, which NTFS
  allows, or a path separator -- is reported as not copied while the rest of the directory
  lists; and `-fsync` sends an SMB2 FLUSH before the CLOSE. A destination whose stream came up
  short is cut to the bytes that arrived, not left at the declared length with a zero tail.

**And the client now keeps a credit balance.** `CreditResponse` sits at bytes 14..16 of
every reply and nothing in the adapter parsed it — so the client asked for credits on every
request, never learned what it was granted, and could send a request charging more than it
held. It found out as `STATUS_INVALID_PARAMETER`, which says nothing about credits and is
the same status half a dozen other causes produce. The balance is a diagnostic rather than
a throttle — one request at a time, I/O capped well inside the window — but when it does
run short the error now names the number: *"this request needs 16 credits and the server
has granted 1"*.

A connection that dies before `TREE_CONNECT` has written nothing — no handle, no partial
file, no operation for a second attempt to duplicate. That is what makes this safe where
retrying a `WRITE` would not be.

Measured with an interleaved control on an identical harness, 2048 trials each:

| | failures |
| --- | --- |
| without the retry | **32 of 2048** |
| with it | **1 of 2048** |

**That first measurement confounded two changes**: the retry
arrived together with the shorter deadline, and the harness bounded a wedged trial at 45 s
— so "fail fast enough that three attempts fit inside the cap" explains the numbers just
as well as "the retry works". Settled by varying only the retry, with the deadline held at
the data path's 60 s and the cap raised to 240 s:

| 60 s deadline, cap 240 s | failures |
| --- | --- |
| retry off | **8 of 256** |
| retry on | **0 of 256** |

The retry is what does the work. The short deadline decides what it costs, not whether it
helps.

The one survivor is **not explained**. The obvious account — the harness's own 45 s cap
landing on a trial already into its third attempt — does not add up: three 10 s attempts
plus 50 and 100 ms of backoff finish near 30 s, inside the cap. Either something in that
run ignored the deadline or all three connections wedged. It is one event in 2048 and was
not chased; it is recorded rather than explained away.

Two things worth keeping from getting there. **A harness has to reproduce the failure at a
high, stable rate before any candidate can be judged** — the first one ran a whole tree
copy per trial, so it produced a handful of results per minute and a rate that appeared to
drift between 1% and 9%; replacing the copy with a `scan` (the handshake and almost nothing
else) gave 1024 trials a minute and a rate steady at 2.3 / 2.3 / 2.1%. Three candidates had
looked promising against the noisy one and none survived the steady one: 1 credit on
`NEGOTIATE` as Windows does, `SecurityMode = SIGNING_ENABLED` as MS-SMB2 requires, and a
10 ms pause after the negotiate response. And **the reference-client comparison has to use
the same dialect**: `smbclient` picks 0x0311 by default and a clean run there says nothing
about the 0x0300 path this client takes. Forced to `-m SMB3_00` it is clean 48 of 48, so
the conclusion stands — on the second measurement, not the first.

`scripts/smb-decode-pcap.py` is the tool for looking at what actually crossed.

`SecurityMode` claims `SMB2_NEGOTIATE_SIGNING_ENABLED`, which MS-SMB2 2.2.3 states as a
MUST and which this client sent as 0 — not a legal value — until it was read against the
spec rather than against servers that tolerated it. That bit is a statement of capability:
the neighboring `SIGNING_REQUIRED` is deliberately left clear, because a client that asks
for a signed session it cannot sign is worse off than one that does not ask.

The security buffer carries raw NTLMSSP rather than a SPNEGO wrapper. That excludes less
than it sounds like — Windows accepts an unwrapped NTLMSSP message, and Samba's SPNEGO
layer recognizes the signature and falls back — so the servers it does exclude are stacks
with no such fallback, and Kerberos-only deployments where NTLM is disabled and SPNEGO
would not help either. No sealing, no Kerberos, no SMB1, no DFS.
