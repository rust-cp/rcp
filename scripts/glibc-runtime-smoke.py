#!/usr/bin/env python3
"""Exercise an exact binary in a separately pinned older-glibc runtime."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
libc = ctypes.CDLL('libc.so.6')
libc.gnu_get_libc_version.restype = ctypes.c_char_p
version = libc.gnu_get_libc_version().decode()
assert tuple(map(int, version.split('.'))) <= (2, 34), version
gssapi = ctypes.CDLL('libgssapi_krb5.so.2')
assert getattr(gssapi, 'gss_init_sec_context')
commands = []
with tempfile.TemporaryDirectory(prefix='rcp-glibc-smoke-') as directory:
    root = Path(directory)
    env = dict(os.environ, HOME=str(root), RCP_CATALOG=str(root/'catalog'))

    def run(*args, input=None, ok=True):
        result = subprocess.run([str(binary), *map(str, args)], input=input,
                                capture_output=True, text=True, env=env, timeout=30)
        commands.append(dict(args=list(map(str, args)), returncode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        assert (result.returncode == 0) == ok, commands[-1]
        return result

    # The release names the version it built; other callers check that it reports one.
    expected = os.environ.get('RCP_EXPECTED_VERSION')
    reported = run('version').stdout.splitlines()[0]
    if expected:
        assert reported == f'rcp {expected}', (reported, expected)
    else:
        assert re.fullmatch(r'rcp \d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?', reported), reported
    source, destination = root/'source', root/'destination'
    source.mkdir()
    (source/'payload').write_bytes(bytes(range(256))*100)
    run('copy', source, destination)
    run('verify', source, destination)
    assert (source/'payload').read_bytes() == (destination/'payload').read_bytes()
    (source/'payload').write_text('changed baseline smoke\n')
    run('isync', source, destination)
    run('verify', source, destination)
    reply = run('mcp', input=json.dumps({'jsonrpc':'2.0','id':'baseline','method':'ping'})+'\n')
    response = json.loads(reply.stdout)
    assert response['id'] == 'baseline' and 'result' in response
    run('copy', root/'missing', root/'bad', ok=False)
    run('delete', destination)
    assert (destination/'payload').is_file()
    run('delete', '-force', destination)
    assert not any(destination.iterdir())
print(json.dumps(dict(status='passed', glibc=version, gssapi_load=True,
                      binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      commands=commands), indent=2))
