#!/usr/bin/env python3
"""Exercise the actual minimal image; all volumes/containers are owned test fixtures."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--image', required=True)
parser.add_argument('--probe', type=Path, required=True)
parser.add_argument('--engine', choices=('docker', 'podman'), default='docker')
parser.add_argument('--connection')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
engine = [args.engine]
if args.connection:
    if args.engine != 'podman':
        parser.error('--connection requires Podman')
    engine += ['--connection', args.connection]
prefix = 'rcp-smoke-'+uuid.uuid4().hex
volume = prefix+'-state'
probe_image = 'localhost/'+prefix+':probe'
containers = []
results = []
restrictions = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m']


def command(arguments, *, expected=0, input=None):
    result = subprocess.run([*engine, *arguments], input=input, capture_output=True, text=True)
    results.append(dict(argv=[*engine, *arguments], returncode=result.returncode,
                        stdout=result.stdout, stderr=result.stderr))
    (args.output/'commands.json').write_text(json.dumps(results, indent=2)+'\n')
    if (expected == 0 and result.returncode != 0) or (expected != 0 and result.returncode == 0):
        raise RuntimeError(f'Unexpected exit for {arguments[0]}: {result.returncode}\n{result.stderr}\n{result.stdout}')
    return result.stdout


def run(arguments, *, expected=0, input=None, image=None, entrypoint=None):
    invocation = ['run', '--rm', *restrictions, '--mount', f'type=volume,source={volume},target=/state']
    if input is not None:
        invocation += ['-i']
    if entrypoint:
        invocation += ['--entrypoint', entrypoint]
    return command([*invocation, image or args.image, *arguments], expected=expected, input=input)


try:
    command(['image', 'inspect', args.image])
    command(['volume', 'create', volume])
    with tempfile.TemporaryDirectory(prefix='rcp-container-smoke-') as temporary:
        fixture = Path(temporary)
        shutil.copy(args.probe, fixture/'probe')
        (fixture/'Dockerfile').write_text(f'FROM {args.image}\nCOPY --chmod=0755 probe /usr/local/bin/rcp-probe\n')
        command(['build', '--network', 'none', '--tag', probe_image, str(fixture)])
        posture = json.loads(run([], image=probe_image, entrypoint='/usr/local/bin/rcp-probe'))
        if not (posture['uid'] == posture['gid'] == 10001 and
                int(posture['effective'], 16) == int(posture['bounding'], 16) == 0 and
                posture['no_new_privileges'] == 1 and posture['seccomp'] == 2):
            raise RuntimeError(f'Hardening posture mismatch: {posture}')
        (args.output/'posture.json').write_text(json.dumps(posture, indent=2)+'\n')
        version = run(['version'])
        if 'kerberos: available' not in version:
            raise RuntimeError('Required GSSAPI runtime library did not load')
        run(['-V'], entrypoint='/usr/bin/ssh')
        run(['-c', 'true'], expected=1, entrypoint='/bin/sh')
        source = fixture/'source'
        source.mkdir()
        (source/'nested').mkdir()
        (source/'a.txt').write_text('original data\n')
        (source/'nested'/'unicode-α.txt').write_text('Unicode content: αβγ\n', encoding='utf-8')
        for path in source.rglob('*'):
            if path.is_file():
                os.utime(path, ns=(1700000000000000000,)*2)
        container = prefix+'-copy'
        containers.append(container)
        command(['create', '--name', container, *restrictions, '--mount', f'type=volume,source={volume},target=/state',
                 args.image, 'copy', '/state/source', '/state/destination', '-noId', '-noown', '-noxattr', '-nolinks', '-sha256', '-noprogress'])
        command(['cp', str(source), container+':/state/source'])
        command(['start', '--attach', container])
        verify = ['verify', '/state/source', '/state/destination', '-sha256', '-noown', '-noxattr']
        run(verify)
        changed = fixture/'changed'
        changed.mkdir()
        (changed/'a.txt').write_text('changed data with a new size\n')
        (changed/'new.txt').write_text('new file\n')
        for path in changed.iterdir():
            os.utime(path, ns=(1700000002000000000,)*2)
        command(['cp', str(changed), container+':/state/changed'])
        run(['isync', '/state/changed', '/state/destination', '-noown', '-noxattr', '-nolinks', '-sha256', '-noprogress'])
        run(['verify', '/state/changed', '/state/destination', '-sha256', '-noown', '-noxattr'])
        run(['copy', '/state/source', '/must-not-be-written', '-noId', '-noown', '-noxattr', '-nolinks'], expected=1)
        requests = [{'jsonrpc': '2.0', 'id': 'escaped"id', 'method': 'initialize',
                     'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'smoke', 'version': '1'}}},
                    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}]
        response = run(['mcp'], input=''.join(json.dumps(r)+'\n' for r in requests))
        replies = [json.loads(line) for line in response.splitlines() if line.strip()]
        if [r['id'] for r in replies] != ['escaped"id', 2] or any('error' in r for r in replies):
            raise RuntimeError('MCP stdout was not a valid matching protocol response')
        run(['delete', '/state/destination'])
        run(['verify', '/state/changed', '/state/destination', '-sha256', '-noown', '-noxattr'])
        run(['delete', '/state/destination', '-force'])
        run(['verify', '/state/changed', '/state/destination', '-sha256', '-noown', '-noxattr'], expected=1)
    (args.output/'result.json').write_text(json.dumps(dict(status='passed', image=args.image, posture=posture,
        cases=['nonroot', 'zero_capabilities', 'no_new_privileges', 'seccomp', 'read_only_rootfs',
               'gssapi_load', 'ssh_client', 'no_shell', 'copy', 'sha256_metadata_verify',
               'changed_sync_with_removal', 'mcp_stdout', 'delete_confirmation']), indent=2)+'\n')
    print('Container smoke passed')
finally:
    # Exact generated names only; no existing user containers, images or volumes.
    for container in containers:
        subprocess.run([*engine, 'rm', '-f', container], capture_output=True)
    subprocess.run([*engine, 'volume', 'rm', volume], capture_output=True)
    subprocess.run([*engine, 'image', 'rm', probe_image], capture_output=True)
