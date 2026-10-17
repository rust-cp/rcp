#!/usr/bin/env python3
"""Audit every SMB2 request's CreditCharge against the response it actually got.

    tcpdump -i lo -s 0 -U -w /tmp/smb.pcap "tcp port 445"
    python3 scripts/smb-audit-credit-charge.py /tmp/smb.pcap 445

MS-SMB2 3.1.5.2 charges on `max(SendPayloadSize, ExpectedResponsePayloadSize)`, and those
are PAYLOAD sizes -- "the size of the data within the variable-length field", in the spec's
own words. A client can only DECLARE an expectation; this checks the declaration against
what actually came back, per request.

**This tool printed the wrong verdict for a while, and the correction is the reason to read
this paragraph before trusting its output.** It computed what a request "needed" from the
whole MESSAGE -- header, fixed part and all -- and on that basis reported every 1 MiB READ
as UNDER-CHARGED at 16 where it "needed" 17. The client was duly changed to send 17. The
spec says 16: a header is not payload, 3.3.5.2.5 has the server compute its expected charge
from the same definition, and Windows sends 16. So the tool was measuring the right bytes
and answering the wrong question, and it talked a correct client into over-charging.

It now computes `needed` from the payload and prints the message-sized number beside it, so
the two are visibly different quantities rather than one silently replacing the other.
Deriving the payload from a capture is not exact for every command, so:

  - READ  -> the response's data, taken as the response message minus header and fixed part
  - WRITE -> the request's data, likewise
  - everything else -> 0, which charges 1, which is what 3.2.4.1.5 requires of every
    command that is not READ, WRITE, IOCTL or QUERY_DIRECTORY

Over-charging is legal -- 3.2.4.1.5 says "greater than or equal to", and the server fails
only when its calculated charge EXCEEDS what was sent -- so an over-charge is a cost, not a
defect. Only the UNDER-CHARGED line is a defect. NEGOTIATE charging 0 is correct and not
flagged: the dialect is not settled yet, so `Connection.SupportsMultiCredit` is false.
"""
import os, struct, sys, collections, importlib.util

# SMB2 header, and the fixed part of the two responses that carry bulk data.
_HEADER, _READ_FIXED, _WRITE_FIXED = 64, 16, 48


def _payload(name, request_len, response_len):
    """(send payload, expected response payload) for one pair, as best a capture can say."""
    if name == "READ":
        return (0, max(response_len - _HEADER - _READ_FIXED, 0))
    if name == "WRITE":
        return (max(request_len - _HEADER - _WRITE_FIXED, 0), 0)
    # QUERY_DIRECTORY declares OutputBufferLength in its request body; this tool does not
    # parse bodies, and the page this client asks for charges 1 either way. Saying 0 here
    # is the honest under-statement rather than a guess dressed as a measurement.
    return (0, 0)

# The sibling decoder, resolved beside THIS file rather than from an absolute path -- a
# checked-in path from one developer's machine is what `scripts/check-portability.sh`
# exists to refuse, and it refused this.
_here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "d", os.path.join(_here, "smb-decode-pcap.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

PORT = int(sys.argv[2])
streams = collections.OrderedDict()
for ts, lt, data in d.packets(sys.argv[1]):
    got = d.tcp_payload(lt, data)
    if not got:
        continue
    key, pay = got
    if PORT not in (key[1], key[3]) or not pay:
        continue
    conn = key[1] if key[3] == PORT else key[3]
    streams.setdefault(conn, []).append((key[3] == PORT, pay))


def messages(chunks):
    buf = {True: b"", False: b""}
    out = []
    for o, pay in chunks:
        buf[o] += pay
        b = buf[o]
        while len(b) >= 4:
            n = (b[1] << 16) | (b[2] << 8) | b[3]
            if len(b) < 4 + n:
                break
            out.append((o, b[4:4 + n]))
            b = b[4 + n:]
        buf[o] = b
    return out


worst = {}
under = []
total = 0
for conn, chunks in streams.items():
    sent = {}
    for out, msg in messages(chunks):
        if len(msg) < 64 or msg[:4] != b"\xfeSMB":
            continue
        charge = struct.unpack("<H", msg[6:8])[0]
        cmd = struct.unpack("<H", msg[12:14])[0]
        mid = struct.unpack("<Q", msg[24:32])[0]
        if out:
            sent[mid] = (cmd, charge, len(msg))
        elif mid in sent:
            cmd0, charge0, sendlen = sent.pop(mid)
            total += 1
            name = d.CMD.get(cmd0, cmd0)
            # What the two sides actually needed, from the PAYLOAD. `_payload` strips the
            # header and the fixed part for the two commands that carry bulk data, and
            # returns 0 for the rest -- which lands on a charge of 1, as the spec requires.
            need = (max(max(_payload(name, sendlen, len(msg))), 1) - 1) // 65536 + 1
            # and the number this tool used to print, kept so the difference stays visible
            need_msg = (max(sendlen, len(msg)) - 1) // 65536 + 1
            prev = worst.get(name, (0, 0, 0))
            if len(msg) > prev[0]:
                worst[name] = (len(msg), sendlen, charge0)
            if charge0 and need > charge0:
                under.append((name, mid, sendlen, len(msg), charge0, need, need_msg))

print(f"request/response pairs audited: {total}")
print(f"{'command':16} {'largest response':>17} {'its request':>12} {'charge sent':>12} {'charge needed':>14} {'(by message)':>16}")
for name, (rsp, snd, ch) in sorted(worst.items(), key=lambda kv: -kv[1][0]):
    need = (max(max(_payload(name, snd, rsp)), 1) - 1) // 65536 + 1
    by_message = (max(snd, rsp) - 1) // 65536 + 1
    flag = "  <-- UNDER-CHARGED" if ch and need > ch else ""
    print(f"{str(name):16} {rsp:17} {snd:12} {ch:12} {need:14} {by_message:16}{flag}")
print()
print(f"UNDER-CHARGED REQUESTS: {len(under)}")
for u in under[:10]:
    print("   ", u)
