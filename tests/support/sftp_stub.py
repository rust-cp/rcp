#!/usr/bin/env python3
"""A stand-in `sftp-server`: speaks SFTP version 3 on stdin/stdout over the local
filesystem, so the contract suite can reach `sftp://` endpoints through the same
transport-command hook the ssh arms use (`RCP_SSH` names a script that execs this). It is
paramiko's server side with a stdio channel and a plain-filesystem backend; paths are
taken as the client sends them (absolute), the way OpenSSH's sftp-server takes them.

Usage: sftp_stub.py [ignored ssh-style arguments]
"""
import os
import stat as statmod
import struct
import sys

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.message import Message
from paramiko.sftp import CMD_EXTENDED, CMD_EXTENDED_REPLY, CMD_INIT, CMD_VERSION
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_OP_UNSUPPORTED, SFTP_PERMISSION_DENIED

# OpenSSH's sftp-server takes no message longer than this, header included, and ends the
# session with status 11 on one that is. Paramiko takes anything up to 16 MB, and while the
# stand-in did the same a client sending 256 KiB of WRITE data plus its header passed here
# and failed against every real OpenSSH.
SFTP_MAX_MSG_LENGTH = 256 * 1024
# What OpenSSH advertises through limits@openssh.com for a read or a write.
SFTP_MAX_IO_LENGTH = SFTP_MAX_MSG_LENGTH - 1024


def status_of(error):
    if isinstance(error, FileNotFoundError):
        return SFTP_NO_SUCH_FILE
    if isinstance(error, PermissionError):
        return SFTP_PERMISSION_DENIED
    return SFTP_FAILURE


class NoTransport:
    """What paramiko's subsystem plumbing asks a channel's transport for."""

    def get_log_channel(self):
        return "paramiko.sftp"

    def get_hexdump(self):
        return False


class Stdio:
    """The channel paramiko's server reads and writes: this process's stdin and stdout."""

    def get_transport(self):
        return NoTransport()

    def recv(self, n):
        return os.read(0, n)

    def send(self, data):
        return os.write(1, data)

    def close(self):
        pass

    def get_name(self):
        return "stdio"


class Handle(SFTPHandle):
    def __init__(self, f, path, flags=0):
        super().__init__(flags)
        self.readfile = f
        self.writefile = f
        self.path = path

    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return status_of(e)

    def chattr(self, attr):
        return apply_attr(self.readfile.fileno(), attr, fd=True)


def apply_attr(target, attr, fd=False):
    try:
        if attr._flags & attr.FLAG_PERMISSIONS:
            (os.fchmod if fd else os.chmod)(target, attr.st_mode & 0o7777)
        if attr._flags & attr.FLAG_UIDGID:
            try:
                (os.fchown if fd else os.lchown)(target, attr.st_uid, attr.st_gid)
            except PermissionError:
                return SFTP_PERMISSION_DENIED
        if attr._flags & attr.FLAG_AMTIME:
            os.utime(target, (attr.st_atime, attr.st_mtime), follow_symlinks=not (not fd))
        if attr._flags & attr.FLAG_SIZE and fd:
            os.ftruncate(target, attr.st_size)
    except OSError as e:
        return status_of(e)
    return SFTP_OK


def bare(a, path):
    # RCP_STUB_BARE_LINKS: a symlink's attributes leave out the permissions, which SFTP v3
    # allows, so the client cannot tell a link from the mode bits
    if os.environ.get("RCP_STUB_BARE_LINKS") and os.path.islink(path):
        a.st_mode = None
    return a


class Backend(SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)

    def list_folder(self, path):
        try:
            out = []
            for name in sorted(os.listdir(path)):
                a = bare(SFTPAttributes.from_stat(os.lstat(os.path.join(path, name)), name), os.path.join(path, name))
                out.append(a)
            return out
        except OSError as e:
            return status_of(e)

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(path))
        except OSError as e:
            return status_of(e)

    def lstat(self, path):
        try:
            return bare(SFTPAttributes.from_stat(os.lstat(path)), path)
        except OSError as e:
            return status_of(e)

    def open(self, path, flags, attr):
        try:
            mode = attr.st_mode & 0o7777 if attr._flags & attr.FLAG_PERMISSIONS else 0o666
            fd = os.open(path, flags, mode)
        except OSError as e:
            return status_of(e)
        if flags & os.O_WRONLY:
            f = os.fdopen(fd, "wb", buffering=0)
        elif flags & os.O_RDWR:
            f = os.fdopen(fd, "r+b", buffering=0)
        else:
            f = os.fdopen(fd, "rb", buffering=0)
        return Handle(f, path, flags)

    def remove(self, path):
        try:
            os.remove(path)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        # SFTP v3 RENAME refuses an existing target; the stand-in follows sftp-server
        if os.path.lexists(newpath):
            return SFTP_FAILURE
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def mkdir(self, path, attr):
        try:
            os.mkdir(path, attr.st_mode & 0o7777 if attr._flags & attr.FLAG_PERMISSIONS else 0o777)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(path)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def chattr(self, path, attr):
        return apply_attr(path, attr)

    def symlink(self, target_path, path):
        try:
            os.symlink(target_path, path)
        except OSError as e:
            return status_of(e)
        return SFTP_OK

    def readlink(self, path):
        # RCP_STUB_NO_READLINK: a server that does not implement READLINK, which v3 allows
        if os.environ.get("RCP_STUB_NO_READLINK"):
            return paramiko.sftp.SFTP_OP_UNSUPPORTED
        try:
            return os.readlink(path)
        except OSError as e:
            return status_of(e)

    def canonicalize(self, path):
        # RCP_STUB_LEXICAL_REALPATH: normalize the spelling only, as draft-02 allows and
        # pkg/sftp and SFTPGo do, without resolving a link
        if os.environ.get("RCP_STUB_LEXICAL_REALPATH"):
            return os.path.normpath(path)
        return os.path.realpath(path)


class Quiet(paramiko.ServerInterface):
    pass


class OpenSshLike(SFTPServer):
    """Paramiko's server held to the two things about OpenSSH's sftp-server a client has to
    get right: its message length limit, and the limits@openssh.com extension that says what
    fits under it. RCP_SFTP_STUB_NO_LIMITS=1 leaves the extension out, the way a server that
    predates it (OpenSSH before 8.7) does, so the client's fallback is exercised too.
    RCP_SFTP_STUB_DIE_AFTER=N ends the session once N bytes have been read, the way a server
    that drops the connection mid-file does."""

    received = 0

    def _read_packet(self):
        (size,) = struct.unpack(">I", self._read_all(4))
        self.received += 4 + size
        die_after = int(os.environ.get("RCP_SFTP_STUB_DIE_AFTER", "0"))
        if die_after and self.received > die_after:
            os._exit(1)
        if size > SFTP_MAX_MSG_LENGTH:
            sys.stderr.write(f"sftp_stub: bad message length {size}\n")
            sys.stderr.flush()
            os._exit(11)
        data = self._read_all(size)
        if size == 0:
            return 0, bytes()
        return data[0], data[1:]

    def _send_server_version(self):
        t, data = self._read_packet()
        if t != CMD_INIT:
            raise paramiko.SFTPError("Incompatible sftp protocol")
        msg = Message()
        msg.add_int(3)
        if os.environ.get("RCP_SFTP_STUB_NO_LIMITS") != "1":
            msg.add("limits@openssh.com", "1")
        self._send_packet(CMD_VERSION, msg)
        return struct.unpack(">I", data[:4])[0]

    def _process(self, t, request_number, msg):
        if t == CMD_EXTENDED:
            tag = msg.get_text()
            if tag == "limits@openssh.com" and os.environ.get("RCP_SFTP_STUB_NO_LIMITS") != "1":
                reply = Message()
                reply.add_int(request_number)
                reply.add_int64(SFTP_MAX_MSG_LENGTH)
                reply.add_int64(SFTP_MAX_IO_LENGTH)
                reply.add_int64(SFTP_MAX_IO_LENGTH)
                reply.add_int64(0)
                self._send_packet(CMD_EXTENDED_REPLY, reply)
                return
            msg.rewind()
            msg.get_int()
        super()._process(t, request_number, msg)


def main():
    server = OpenSshLike(Stdio(), "sftp", Quiet(), Backend)
    server.start_subsystem("sftp", NoTransport(), Stdio())


if __name__ == "__main__":
    main()
