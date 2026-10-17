# IPv6 addresses

An endpoint may name an IPv6 literal in brackets -- `dav://[::1]:8443/p`,
`oci://[fe80::1]/repo`, `ssh://user@[::1]:2222/p`, `hdfs://[::1]:9870/p`,
`nfs://[::1]/export` -- and one reader handles the authority for all of them, so a
bracketed host cannot mean one thing to the endpoint parser and another to the transport's.

**The interesting part is the arm that was missing.** Unifying the parsers and proving it
by round-tripping `Endpoint::parse` into `display()` and back into each transport's own
parser is not enough: every such arm passed, and `dav://[::1]:8443/p` still could not open.
A parser round-trip is not a connection, and nothing measured the connection. The host
arrived at `(host, port).to_socket_addrs()` still wearing its brackets, and `[::1]` is not
an address -- it is a name, so it went to the resolver and came back `failed to lookup
address information`.

The brackets are *correct* everywhere else: `Host: [::1]:8443` needs them, `CONNECT
[::1]:443` needs them, RFC 3986 requires them in the URL. So the fix is a strip at the
three points of use rather than a second host field: the resolver (`unbracketed` in
`connect_tcp`, which every HTTP adapter and the proxy dial share, and in the NFS RPC
client -- those are the crate's only two `to_socket_addrs` call sites), and rustls's
`ServerName`, which reads an IP or a DNS name and `[::1]` is neither.

Two parsers were also still splitting on the last colon with no bracket awareness, each
reachable only by a route the table arm did not cover: `-s3.endpoint http://[::1]:9000`
became a host of that whole name on the scheme's default port, and `HTTPS_PROXY` did the
same. Both read the authority the way the other four do now, and the table arm covers all
six.

`nfs://` is deliberately different: its display form is `host:/export`, where brackets mean
nothing, and the bare spelling `::1:/export` already stored the address. The two spellings
disagreed -- one worked and one did not -- so the URL form now stores the address too, per
element, since an address list may be `nfs://[::1],[::2]/export`.

**A zone id is the second half of this.** A link-local
address carries one -- which interface to leave by -- and RFC 6874 writes it `%25eth0` in a
URI because `%` must be escaped there. Strip only the brackets and the resolver gets
`fe80::1%25eth0`, which is not an address either, so it goes to the name lookup exactly as
`[::1]` used to. Measured, and it needs no IPv6 stack because it is a parse: `fe80::1%25lo`
fails the lookup and `fe80::1%lo` resolves to `[fe80::1%1]:80`. A certificate is the
opposite case -- a zone is a local routing detail and no part of the peer's identity, so
nothing names one and rustls refuses the whole string -- and `unzoned` drops it for the
`ServerName` alone.

**`NO_PROXY` was mangling the addresses it was told to exempt.** The port strip split every
entry on its last colon, which is right for `example.com:8080` and destroys an address:
`NO_PROXY=::1` became `::` and `NO_PROXY=[::1]` became `[::`, so neither matched the stored
host and traffic went through the proxy the operator had just excluded. A port is stripped
only when what follows the colon is one, both spellings are accepted, and the comparison is
made on the bare address.

**What is NOT measured here, and the arm says so in its own comment:** this container has
no IPv6 stack at all (`bind [::1]` answers `EAFNOSUPPORT`), so no arm in this suite makes
an IPv6 connection. What the arm measures is the thing that was wrong -- that the literal
reaches the resolver as an address and not as a name -- with a control that a genuine
unresolvable name still fails the other way, so the distinction it reads is a real one.
