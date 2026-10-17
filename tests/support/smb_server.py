#!/usr/bin/env python3
"""A stand-in SMB2 server for the smb:// arms, on impacket's SimpleSMBServer.

Prints `READY <port>` on stdout once it is listening, so the test waits for the server
rather than for a sleep -- a sleep is a race that passes on a fast machine and fails on a
loaded one, which is the flake this repo keeps refusing to accept.

Credentials are deliberately trivial (tester / empty password): the arms are about the
protocol, and a real secret in a test fixture is a secret in a repository.

TWO THINGS THIS CANNOT MEASURE, stated here so nobody has to rediscover them:

- It does not VALIDATE `CreditCharge` or message ids. The negotiate override below makes
  the client compute real charges and put them on the wire, and an arm reads them back;
  but impacket accepts any charge, echoes back whatever credits are asked for, and never
  checks that a request's message id follows the last one's charge. A client that gets any
  of those wrong can still pass everything here and fail on a real server -- which is what
  happened with the constant-zero charge, found by a real Samba.
- It cannot REQUIRE SIGNING, hang up after an AUTHENTICATE, or say how many it received.
  `src/smb/scripted.rs` is the peer for those.
- Its DIRECTORY LISTING reports whole seconds. impacket builds its FILETIMEs from
  `os.stat`'s integer tuple, so the sub-second part is gone before any conversion and no
  hook here can recover it. The write path IS corrected to 100 ns ticks below, so what a
  client SENDS can be checked off the filesystem; what it READS cannot.
"""
import os, sys, logging, threading

from impacket import smb, smbserver

# BOUND BEFORE THE PATCH AT THE END OF THIS BLOCK, and that is load-bearing rather than
# style. Writing `smb.SMBSetFileBasicInfo.__getitem__(...)` inside the override resolves
# through the MODULE ATTRIBUTE, which the patch replaces with the override -- so the method
# called itself, 983 frames deep, and the server died on every SET_INFO. From the client
# that read as `failed to fill whole buffer` on all seven entries, naming no server at all.
#
# A standalone check of the class had passed, because it had not patched the module: the
# probe and the real path took different routes, so the probe could not see the failure.
# That is the same shape as the `/dev/tcp` probe that could not see a broken relay.
_Original = smb.SMBSetFileBasicInfo


class BasicInfoPerSpec(_Original):
    """`FileBasicInformation` read the way MS-FSCC 2.4.7 defines it.

    impacket's SET_INFO handler applies `LastWriteTime` as the ACCESS time and `ChangeTime`
    as the MODIFICATION time -- the reverse of the spec. Left alone, that inversion gets
    pushed into the CLIENT: it has to write all three fields so the value lands either way,
    which on a real server stamps ChangeTime with the SOURCE's mtime and backdates the field
    Windows USN consumers and several backup products read as "this file changed". A file
    copied onto a share that is itself a backup source can then look older than the last
    backup and be skipped.

    So the STAND-IN is corrected rather than the client. This maps the two names impacket
    asks for onto the fields the spec says carry those meanings; every other key falls
    through. The client writes LastAccessTime and LastWriteTime, which is what a real server
    reads, and the arms measure that instead of a mistake the two ends share.
    """

    def __getitem__(self, key):
        if key == "LastWriteTime":  # impacket assigns this one to atime
            value = _Original.__getitem__(self, "LastAccessTime")
            _remember("LastAccessTime", value)
            return value
        if key == "ChangeTime":  # and this one to mtime
            value = _Original.__getitem__(self, "LastWriteTime")
            _remember("LastWriteTime", value)
            return value
        return _Original.__getitem__(self, key)


smbserver.smb.SMBSetFileBasicInfo = BasicInfoPerSpec


# ---------------------------------------------------------------------------
# AND THE SECOND THING THE STAND-IN GOT WRONG ABOUT TIMES: RESOLUTION.
#
# impacket converts a FILETIME with `FTtoPOSIX`, which is `t //= 10000000` -- floor
# division to WHOLE SECONDS -- and then calls `os.utime(path, (atime, mtime))` with ints.
# So every time written through this stand-in landed on a second boundary.
#
# SMB does not do that. NTFS and `FileBasicInformation` both count in 100-nanosecond
# FILETIME ticks, so a real server stores `...123_456_789` as `...123_456_700`. Measured
# against Samba 4.19.5, that rounding made `verify` report a difference for every file of a
# copy `diff -r` calls byte-identical -- and no arm here could see it, because a stand-in
# that keeps only seconds is covered by the whole-second tolerance that already existed.
#
# A stand-in COARSER than the protocol cannot measure the protocol's own edge. So the ticks
# are restored: the override records the exact FILETIME it hands over, per thread (impacket
# serves each connection on its own thread and reads the fields immediately before calling
# `utime`), and the `utime` wrapper spends it through the `ns=` keyword instead of the
# second-resolution tuple.
#
# `_os_utime` is bound BEFORE the patch for the same reason `_Original` is above: patching
# `smbserver.os` patches the `os` module itself, so calling `os.utime` inside the wrapper
# would call the wrapper. That mistake cost 983 frames of recursion once already in this
# file; it is not being made twice.
_os_utime = os.utime
_ticks = {}


def _remember(field, filetime):
    if filetime:
        _ticks.setdefault(threading.get_ident(), {})[field] = filetime


def _utime_with_ticks(path, times=None, **kw):
    mine = _ticks.pop(threading.get_ident(), None)
    if mine and times is not None and "ns" not in kw:
        # FILETIME is 100 ns ticks since 1601-01-01; 116444736000000000 of them precede the
        # Unix epoch (MS-DTYP). Multiplying by 100 is exact in Python's unbounded ints, so
        # nothing is lost on the way to `ns=` -- which a float seconds value could not say,
        # since a float64 near 1.79e9 resolves only to about 238 ns.
        def ns(field):
            return (mine[field] - 116_444_736_000_000_000) * 100
        if "LastAccessTime" in mine and "LastWriteTime" in mine:
            return _os_utime(path, ns=(ns("LastAccessTime"), ns("LastWriteTime")), **kw)
    return _os_utime(path, times, **kw) if times is not None else _os_utime(path, **kw)


os.utime = _utime_with_ticks


# ---------------------------------------------------------------------------
# A CREDIT WINDOW, so the client's CreditCharge arithmetic is exercised on a wire.
#
# impacket answers NEGOTIATE with DialectRevision 0x0202 and Capabilities 0. Either alone
# sets `Connection.SupportsMultiCredit` false in the client, which means `credit_charge`
# returned 0 for EVERY request in EVERY automated run -- so the constant-zero CreditCharge
# defect and the payload-versus-message defect that followed it were both structurally
# invisible to the suite that carried their names. The arms called the formula directly;
# none of them reached a call site.
#
# This override was got wrong TWICE before it was got right, and the reason is worth
# keeping: `testserver.rs` sends this script's stderr to /dev/null, so an override that
# silently changed nothing looked exactly like one that worked. The first guess read the
# handler's first return value (it is `None`; the packets are the second). The second
# guess re-parsed `packet["Data"]` as bytes -- but impacket stores the response STRUCTURE
# there, not its serialization, so parsing raised and the `except` swallowed it. One line
# of stderr, run by hand outside cargo, showed both in seconds.
#
# impacket does not validate CreditCharge -- it is a stand-in, not a conformance server --
# so this does not make the suite check the server's side. What it does is make the CLIENT
# compute a real charge and put it on a wire, which is where both defects lived.
#
# AND IT ADVERTISES SAMBA'S SIZES, 8 MiB. impacket's own MaxReadSize and MaxWriteSize are
# 64 KiB, so without this the client's production chunking -- `min(max_read, READ_CHUNK)`,
# `min(max_write, WRITE_CHUNK_CAP)` -- always comes out at 64 KiB and every real read and
# write charges 1. Deleting both caps would then leave the suite green; against Samba's
# 8 MiB that deletion makes every write charge 129 against a window of 64, so every SMB
# write fails. The caps only mean something against a server offering more than they allow.
#
# NOT touched: the SMB1 multi-protocol reply, where 0x0210 is not a legal answer (the client
# never sends SMB1, but a stand-in should not be wrong where nobody is looking), and
# `fsctlValidateNegotiateInfo`, which still answers 0x0202 with no capabilities -- so a
# future VALIDATE_NEGOTIATE_INFO in the client would disagree with this stand-in, and an arm
# for it must not be read as a server's verdict.
_orig_negotiate = smbserver.SMB2Commands.smb2Negotiate

LARGE_MTU = 0x00000004
DIALECT_210 = 0x0210
SAMBA_MAX_IO = 8 << 20


def _negotiate_with_a_credit_window(connId, smbServer, recvPacket, isSMB1=False):
    errs, packets, status = _orig_negotiate(connId, smbServer, recvPacket, isSMB1)
    if isSMB1:
        return errs, packets, status
    for packet in packets or []:
        body = packet["Data"]
        # Mutated in place: `Data` holds the structure, and it is serialized on the way out.
        if hasattr(body, "fields") and "Capabilities" in body.fields:
            body["DialectRevision"] = DIALECT_210
            body["Capabilities"] = body["Capabilities"] | LARGE_MTU
            body["MaxReadSize"] = SAMBA_MAX_IO
            body["MaxWriteSize"] = SAMBA_MAX_IO
    return errs, packets, status


smbserver.SMB2Commands.smb2Negotiate = staticmethod(_negotiate_with_a_credit_window)


def main():
    share_path = sys.argv[1]
    port = int(sys.argv[2])
    logging.getLogger().setLevel(logging.ERROR)
    srv = smbserver.SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    srv.addShare("DATA", share_path, "rcp test share")
    srv.setSMB2Support(True)
    srv.addCredential("tester", 0, "", "")
    srv.setSMBChallenge('')
    # SimpleSMBServer keeps no accessor for its socket, so the port is chosen HERE and
    # announced, rather than asked for afterwards. Binding a port before handing it over
    # would race with the server's own bind.
    print(f"READY {port}", flush=True)
    srv.start()


if __name__ == "__main__":
    main()
