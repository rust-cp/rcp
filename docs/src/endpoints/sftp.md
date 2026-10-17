# Hosts with only OpenSSH: sftp://

`sftp://[user@]host[:port]/path` is a directory on a host where rcp is not installed but
OpenSSH is: the endpoint opens `ssh host -s sftp` and speaks SFTP version 3 to the
subsystem, one session per worker, with reads kept eight deep and writes sixteen deep. Everything above works across it: copy, sync, verify, scan, delta (the signing and
matching run on this side, since the far side is only a filesystem). What the protocol
cannot say is refused or approximated in the open: no inode numbers, so a hard link on
an sftp source is a second copy of the file and one bound for an sftp destination is
written as a file (`hardlink@openssh.com` is used where the server offers it); times to
the second (`verify` accepts a whole-second destination against a source with
nanoseconds); no holes, so runs of zeros are detected on read and skipped on write; no
extended attributes, so every one is reported refused. The trust model is ssh's, as for
`ssh://`, and the same `RCP_SSH` hook reaches a stand-in for the suite.

**Each read and write is the size the server says it takes.** A server that offers
`limits@openssh.com` (OpenSSH 8.7 and later) is asked, and OpenSSH answers 256 KiB less
1024. One that does not gets 32 KiB, which every version 3 server must accept and which
OpenSSH's own client uses in the same case. `-loglevel DEBUG` prints the sizes in use.

This used to be 256 KiB for every request, on the belief that it was the largest read or
write OpenSSH accepts. OpenSSH's 256 KiB limit is on the whole message, header included, so
every file of 256 KiB or more failed against a real server. Measured against OpenSSH 10.3:
262,100 bytes crossed and 262,144 did not. The suite's stand-in is paramiko, which accepts
messages of up to 16 MB, so it could not see the problem. It now enforces OpenSSH's limit
and offers the extension as OpenSSH does, and it can also leave the extension out, as a
server older than 8.7 does.

**A session that ends mid-file is a failure the run reports.** `ERROR` names the file, the
run ends `STATUS: FAILED`, and the catalog keeps what completed for `rcp resume`. Before, a
server that dropped the connection killed the run on its next write: exit 141, no message.
