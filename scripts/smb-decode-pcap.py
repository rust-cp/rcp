#!/usr/bin/env python3
"""Decode SMB2 headers out of a pcap, grouped by TCP connection.

    tcpdump -i lo -s 0 -U -w /tmp/smb.pcap "tcp port 445"
    python3 scripts/smb-decode-pcap.py /tmp/smb.pcap 445

Written for the handshake defect in the smb:// adapter, where the client's bytes had to be
compared against `smbclient`'s against the same server -- and where the useful view is one
connection at a time, since the failure is that ONE connection of eight never gets a reply.
A short connection, or a `!! leftover` line, is what a wedged one looks like.

It reassembles by connection in arrival order, which is sound on loopback (no reordering,
no loss) and NOT sound on a real network -- reach for tshark there. No dependency beyond
the standard library, because the machine that needs this is usually the one that cannot
install anything.
"""
import struct, sys, collections

CMD = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT",
       5: "CREATE", 6: "CLOSE", 8: "READ", 9: "WRITE", 14: "QUERY_DIR", 16: "QUERY_INFO", 17: "SET_INFO"}


def packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic, = struct.unpack("<I", gh[:4])
        endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
        linktype, = struct.unpack(endian + "I", gh[20:24])
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts, tus, caplen, wirelen = struct.unpack(endian + "IIII", ph)
            data = f.read(caplen)
            yield ts + tus / 1e6, linktype, data


def tcp_payload(linktype, data):
    # LINKTYPE_NULL (0) on loopback: 4-byte family header. LINKTYPE_ETHERNET (1): 14 bytes.
    off = 4 if linktype == 0 else 14
    if linktype == 1 and struct.unpack(">H", data[12:14])[0] != 0x0800:
        return None
    ip = data[off:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0xf) * 4
    if ip[9] != 6:
        return None
    total = struct.unpack(">H", ip[2:4])[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack(">HH", tcp[:4])
    doff = (tcp[12] >> 4) * 4
    return (src, sport, dst, dport), tcp[doff:]


def main(path, port):
    streams = collections.OrderedDict()
    for ts, lt, data in packets(path):
        got = tcp_payload(lt, data)
        if not got:
            continue
        key, pay = got
        if port not in (key[1], key[3]) or not pay:
            continue
        # one stream per connection, keyed by the ephemeral port
        conn = key[1] if key[3] == port else key[3]
        out = key[3] == port
        streams.setdefault(conn, []).append((ts, out, pay))

    for conn, chunks in streams.items():
        # reassemble each direction, then walk NetBIOS frames
        print(f"\n=== connection ephemeral port {conn} ===")
        buf = {True: b"", False: b""}
        for ts, out, pay in chunks:
            buf[out] += pay
            b = buf[out]
            while len(b) >= 4:
                n = (b[1] << 16) | (b[2] << 8) | b[3]
                if len(b) < 4 + n:
                    break
                msg = b[4:4 + n]
                b = b[4 + n:]
                if len(msg) >= 64 and msg[:4] == b"\xfeSMB":
                    charge = struct.unpack("<H", msg[6:8])[0]
                    status = struct.unpack("<I", msg[8:12])[0]
                    cmd = struct.unpack("<H", msg[12:14])[0]
                    credits = struct.unpack("<H", msg[14:16])[0]
                    flags = struct.unpack("<I", msg[16:20])[0]
                    mid = struct.unpack("<Q", msg[24:32])[0]
                    print("  %-3s %-14s mid=%-3d charge=%-3d credits=%-3d flags=0x%x status=0x%08x len=%d"
                          % ("->" if out else "<-", CMD.get(cmd, cmd), mid, charge, credits, flags, status, n))
                else:
                    print("  %-3s (not an SMB2 message, %d bytes)" % ("->" if out else "<-", n))
            buf[out] = b
        for d in (True, False):
            if buf[d]:
                print("  !! %s leftover %d bytes (incomplete frame)" % ("->" if d else "<-", len(buf[d])))


if __name__ == "__main__":
    try:
        main(sys.argv[1], int(sys.argv[2]))
    except BrokenPipeError:
        # `| head` is the normal way to read this; a traceback there would look like a
        # defect in the decoder rather than the reader having seen enough.
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
