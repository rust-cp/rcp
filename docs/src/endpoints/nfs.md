# NFS without a mount

`rcp copy /data 192.0.2.10:/backup` speaks NFSv3 to the server itself: the MOUNT protocol
for the root handle (over TCP, found through the portmapper), then LOOKUP, READDIRPLUS,
READ, WRITE, CREATE, MKDIR, SYMLINK, LINK, SETATTR, REMOVE, RMDIR and COMMIT with AUTH_SYS
credentials (the calling uid and gid, so the export's root-squash rules apply as they would
to a mount). Every worker thread holds its own connection from a pool; a reader keeps eight
READs ahead of the consumer and a writer keeps sixteen UNSTABLE WRITEs in flight and commits
once at the end, which is what a kernel mount's per-mount request cap does not allow. Holes
are never written, so a sparse image stays sparse on the server. Sources are copied to
exports, exports to local paths, and exports to exports, all through the same commands.

POSIX ACLs travel on the wire through the NFSACL sideband program (100227, the one Linux
`nfsd` and ONTAP serve beside NFSv3): `GETACL` on the way out, `SETACL` before the mode
lands on the way in, so `verify` compares them and `sync` repairs them the way it does
locally. A server without the program gets no ACL calls and the attributes are counted as
refused in the summary, never dropped in silence. `RCP_NFSACL_PORT` names the port when the
portmapper cannot be asked.

`-acl4` adds NFSv4 ACLs: with it, every file and
directory on an export lists `system.nfs4_acl`, read with an NFSv4 `GETATTR` of the ACL
attribute and written with a `SETATTR` of it under the anonymous stateid, both stateless
operations that need no client id, open or lease, so one small COMPOUND rides beside the
v3 data path. The attribute's XDR is what the kernel exposes as `system.nfs4_acl` on a v4
mount, so an export and a mount of it compare equal byte for byte. It is meant between
exports, or between an export and a kernel v4 mount; a plain local directory lists no such
attribute, so `verify -acl4` between it and an export reports the ACLs the export has and
the directory does not, which is the truth. A server that does not serve NFSv4 is refused
before anything is planned rather than dropping what the option asked for. So is
`-acl4 -noxattr` (and `-acl4 -noattrs`): these ACLs ride in the extended-attribute channel,
so asking for them while turning that channel off carries none, and the combination used to
be accepted in silence -- a run that printed the same counts and the same `STATUS: PASSED`
as one that had carried every ACL.

Kerberos: `-nfs.sec krb5`, `krb5i` or `krb5p` (or `RCP_NFS_SEC`) reaches every export with
RPCSEC_GSS instead of AUTH_SYS, which is what an export with `sec=krb5*` requires. rcp
carries no Kerberos code of its own: it loads the host's GSSAPI library (`libgssapi_krb5`,
the one the kernel's `rpc.gssd`, `mount.nfs` and `curl` use) at run time, so the host's
`krb5.conf`, ticket cache (`kinit` first, or `KRB5CCNAME`) and keytabs apply unchanged and
the build links no Kerberos library; a host without the library gets a clear refusal
when Kerberos is asked for. Each connection establishes its own context with `nfs@host`,
every call's header carries a MIC, and `krb5i` checksums the body while `krb5p` encrypts
it, in both directions; the pipelining is untouched, since a context is per connection and
the sequence numbers are per call. The mount, the NFSACL program and the `-acl4` sidecar
ride the same contexts. The contract suite runs all three flavors against a stand-in that
requires Kerberos, through a real MIT KDC it starts itself in a throwaway realm, with
AUTH_SYS refused as too weak and a missing ticket refused before anything is planned.

`-nfs.vers 4` (or `RCP_NFS_VERS=4`) moves the data over NFSv4.0 (RFC 7530) instead of v3:
no MOUNT protocol (the export is walked from the server's pseudo root), one client id per
run established with SETCLIENTID and confirmed, a fresh open-owner and an OPEN, OPEN_CONFIRM
and CLOSE per file, READs and WRITEs under that open's stateid (still pipelined per
connection, UNSTABLE writes committed once), a delegation returned the moment a server
presses one, and the lease renewed when the run has been idle. Owners travel as strings:
numeric while the server takes them, `name@domain` after its first NFS4ERR_BADOWNER
(`RCP_NFS4_DOMAIN` names the domain, else the one the server itself uses; a name this host
does not know becomes 65534). `-acl4` rides the same connection as one more attribute. Minor
version 0 only: no sessions (4.1) and no server-side copy (4.2), and no user extended
attributes on the wire in any version rcp speaks (they are reported as refused). The contract
suite runs copy, verify, sync, scan, chmod, delete, sparse files, hard links, `-acl4` and
Kerberos over v4 against a stand-in whose client ids and open stateids are real, so a READ
under a stateid no OPEN produced is refused there as it would be on a server.

Limits, stated plainly: v3 and v4.0 only, and the v3 path is the default. `show HOST` asks
a server for its RPC services and exports before anything is planned. `RCP_NFS_PORT` and
`RCP_MOUNT_PORT` bypass the portmapper for a server on fixed ports, `RCP_PORTMAP_PORT` moves
the portmapper. A server with several interfaces is written
`ip1,ip2:/export`: the mount goes through the first address that answers and the connection
pool rotates across all of them, skipping one that refuses, which spreads the load across
the server's interfaces.

The contract suite exercises the client against an in-process stand-in server
(`src/nfs/testserver.rs`, a directory served over the real wire format), so the protocol code
is tested on every run; behavior against a production filer is a separate check to make on
one before trusting it with a migration.
