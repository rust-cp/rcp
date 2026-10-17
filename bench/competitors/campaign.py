#!/usr/bin/env python3
"""Bounded, synthetic, cache-warm local comparisons; no network or cache dropping."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tempfile
import threading
import time


def manifest(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_file():
            st = path.stat()
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            result[str(path.relative_to(root))] = [st.st_size, st.st_mtime_ns, st.st_mode & 0o777, digest.hexdigest()]
    return result


def sampled_rss(pid):
    pending, seen, total = [pid], set(), 0
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            total += int(Path(f'/proc/{current}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
            pending.extend(map(int, Path(f'/proc/{current}/task/{current}/children').read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return total


def measured(argv, env, log):
    stop = threading.Event()
    peak = [0]
    started = time.perf_counter_ns()
    with log.open('w') as output:
        proc = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], sampled_rss(proc.pid))
                stop.wait(0.005)
        sampler = threading.Thread(target=sample)
        sampler.start()
        _, status, usage = os.wait4(proc.pid, 0)
        ended = time.perf_counter_ns()
        proc.returncode = os.waitstatus_to_exitcode(status)
        stop.set()
        sampler.join()
    return dict(argv=argv, exit_code=proc.returncode, wall_s=(ended-started)/1e9,
                user_s=usage.ru_utime, system_s=usage.ru_stime,
                max_process_rss_kib=usage.ru_maxrss, sampled_tree_rss_bytes=peak[0],
                filesystem_input_bytes=usage.ru_inblock*512,
                filesystem_output_bytes=usage.ru_oublock*512)


def generate(root, kind):
    root.mkdir()
    sizes = {'small': [4096]*1200, 'large': [16*1024*1024]*8,
             'mixed': [4096]*800 + [512*1024]*8 + [32*1024*1024]}[kind]
    for index, size in enumerate(sizes):
        folder = root / f'd{index % 20:02}'
        folder.mkdir(exist_ok=True)
        path = folder / f'f{index:04}.bin'
        block = random.Random(1000+index).randbytes(min(size, 65536))
        with path.open('wb') as stream:
            remaining = size
            while remaining:
                piece = block[:min(remaining, len(block))]
                stream.write(piece)
                remaining -= len(piece)
        path.chmod(0o640 if index % 2 else 0o644)
        os.utime(path, ns=(1700000000000000000,)*2)


def commands(tool, case, source, destination, binary):
    if tool == 'rcp':
        return [str(binary), 'copy' if case == 'fresh' else 'isync', str(source), str(destination),
                '-noId', '-nohash', '-noown', '-noxattr', '-nolinks', '-parallel', '1', '-noprogress']
    if tool == 'rsync':
        return ['rsync', '-rtp', '--whole-file', '--no-owner', '--no-group',
                *(['--delete'] if case == 'changed' else []), str(source)+'/', str(destination)+'/']
    if tool == 'rclone':
        return ['rclone', 'copy' if case == 'fresh' else 'sync', str(source), str(destination),
                '--metadata', '--ignore-checksum', '--transfers', '1', '--checkers', '1',
                '--multi-thread-streams', '0', '--retries', '1', '--low-level-retries', '1', '--stats', '0']
    return ['cp', '-Rp', '--reflink=never', '--sparse=never', str(source)+'/.', str(destination)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rcp', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--workloads', nargs='+', choices=('small', 'large', 'mixed'), default=['small', 'large', 'mixed'])
    parser.add_argument('--cases', nargs='+', choices=('fresh', 'changed'), default=['fresh', 'changed'])
    parser.add_argument('--preload', type=Path, help='Optional local profiling shim; profiled results are not baseline rankings')
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('repeats must be between 1 and 20')
    args.rcp = args.rcp.resolve()
    binary_sha256 = hashlib.sha256(args.rcp.read_bytes()).hexdigest()
    if binary_sha256 != '1657ddc25a3a8427dc705c29f39dfcb750eb0a565413a31e6d91904d186424d7':
        parser.error('This campaign requires the verified v0.1.0 release binary; provenance would otherwise be incorrect')
    args.output.mkdir(parents=True, exist_ok=False)
    tool_path = '/usr/local/bin:/usr/bin:/bin'
    executables = {'rcp': str(args.rcp), **{tool: shutil.which(tool, path=tool_path)
                    for tool in ('rsync', 'rclone', 'cp')}}
    if not all(executables.values()):
        parser.error('A competitor is unavailable in the measurement PATH')
    versions = {tool: subprocess.check_output([executables[tool], flag], text=True)
                for tool, flag in {'rcp': 'version', 'rsync': '--version',
                                   'rclone': 'version', 'cp': '--version'}.items()}
    environment = dict(versions=versions, executables=executables,
                       executable_sha256={tool: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                          for tool, path in executables.items()},
                       kernel=platform.release(), machine=platform.machine(),
                       python=platform.python_version(), cpu_count=os.cpu_count(),
                       binary_sha256=binary_sha256,
                       archive_sha256='1d39749d7811c273b9c5265e138006b1294462bfbdae9dc77e02a0c278399784',
                       rcp_commit='02b75bd980e0a8639d9a6f67a1fa58983474a068', seed=20261001,
                       memory_info=Path('/proc/meminfo').read_text().splitlines()[:3])
    (args.output/'environment.json').write_text(json.dumps(environment, indent=2)+'\n')
    if args.preload:
        environment['profiling_shim'] = str(args.preload.resolve())
        environment['profiling_shim_sha256'] = hashlib.sha256(args.preload.read_bytes()).hexdigest()
        (args.output/'environment.json').write_text(json.dumps(environment, indent=2)+'\n')
    records = []
    rng = random.Random(20261001)
    with tempfile.TemporaryDirectory(prefix='rcp-competitors-', dir='/var/tmp') as temporary:
        scratch = Path(temporary)
        env = {'PATH': tool_path, 'HOME': str(scratch),
               'RCP_CATALOG': str(scratch/'catalog'), 'RCLONE_CONFIG': '/dev/null', 'LANG': 'C.UTF-8'}
        if args.preload:
            env['LD_PRELOAD'] = str(args.preload.resolve())
        (args.output/'filesystem.txt').write_text(subprocess.check_output(
            ['findmnt', '-T', str(scratch), '-n', '-o', 'FSTYPE,SOURCE,OPTIONS'], text=True))
        with (args.output/'raw.jsonl').open('w') as raw:
            for kind in args.workloads:
                base = scratch/f'{kind}-base'
                generate(base, kind)
                before = manifest(base)
                changed = scratch/f'{kind}-changed'
                shutil.copytree(base, changed)
                files = sorted(changed.rglob('*.bin'))
                for path in files[::10]:
                    with path.open('ab') as stream:
                        stream.write(b'changed\n')
                    os.utime(path, ns=(1700000002000000000,)*2)
                deleted = files[5::20]
                for path in deleted:
                    path.unlink()
                for index in range(max(1, len(deleted))):
                    path = changed/f'added-{index:04}.bin'
                    path.write_bytes(bytes([index%256])*4096)
                    path.chmod(0o644)
                    os.utime(path, ns=(1700000002000000000,)*2)
                after = manifest(changed)
                (args.output/f'{kind}-base-manifest.json').write_text(json.dumps(before, sort_keys=True)+'\n')
                (args.output/f'{kind}-changed-manifest.json').write_text(json.dumps(after, sort_keys=True)+'\n')
                for case, expected, source in [('fresh', before, base), ('changed', after, changed)]:
                    if case not in args.cases:
                        continue
                    tools = ['rcp', 'rsync', 'rclone'] + (['cp'] if case == 'fresh' else [])
                    for repeat in range(-1, args.repeats):
                        order = tools.copy()
                        rng.shuffle(order)
                        for tool in order:
                            destination = scratch/'destination'
                            if destination.exists():
                                shutil.rmtree(destination)  # Only this newly created scratch directory.
                            if case == 'changed':
                                shutil.copytree(base, destination)
                            else:
                                destination.mkdir()
                            subprocess.run(['sync', '-f', str(scratch)], check=True, env=env)
                            label = f'{kind}-{case}-{repeat}-{tool}'
                            command = commands(tool, case, source, destination, args.rcp)
                            command[0] = executables[tool]
                            transfer = measured(command,
                                                env, args.output/(label+'.log'))
                            barrier = measured(['sync', '-f', str(destination)], env,
                                               args.output/(label+'-sync.log'))
                            verify_started = time.perf_counter_ns()
                            actual = manifest(destination)
                            verify_s = (time.perf_counter_ns()-verify_started)/1e9
                            valid = actual == expected and transfer['exit_code'] == barrier['exit_code'] == 0
                            payload = sum(v[0] for k, v in expected.items()
                                          if case == 'fresh' or before.get(k) != v)
                            record = dict(workload=kind, case=case, repeat=repeat, warmup=repeat==-1,
                                          tool=tool, order=order, valid=valid, transfer=transfer,
                                          barrier=barrier, verification_s=verify_s,
                                          completion_s=transfer['wall_s']+barrier['wall_s']+verify_s,
                                          source_bytes=sum(v[0] for v in expected.values()),
                                          changed_or_new_payload_bytes=payload, source_files=len(expected),
                                          removed_files=len(set(before)-set(after)) if case=='changed' else 0)
                            if not valid:
                                record['mismatch_paths'] = sorted(k for k in set(actual)|set(expected)
                                                                   if actual.get(k) != expected.get(k))[:30]
                            raw.write(json.dumps(record)+'\n'); raw.flush()
                            records.append(record)
                            print(label, 'PASS' if valid else 'FAIL', round(record['completion_s'], 4), flush=True)
                            if not valid:
                                raise SystemExit('Semantic mismatch; raw failing run retained, no rankings produced')
                shutil.rmtree(base); shutil.rmtree(changed)
    rows = ['workload,case,tool,runs,median_transfer_s,median_completion_s,min_completion_s,max_completion_s,median_cpu_s,median_sampled_tree_rss_bytes,median_fs_output_bytes']
    for kind in args.workloads:
        for case in args.cases:
            for tool in ('rcp', 'rsync', 'rclone', 'cp'):
                group = [r for r in records if (r['workload'],r['case'],r['tool'])==(kind,case,tool) and not r['warmup']]
                if not group:
                    continue
                med = lambda f: statistics.median(f(r) for r in group)
                rows.append(','.join(map(str,[kind,case,tool,len(group),med(lambda r:r['transfer']['wall_s']),
                    med(lambda r:r['completion_s']),min(r['completion_s'] for r in group),
                    max(r['completion_s'] for r in group),med(lambda r:r['transfer']['user_s']+r['transfer']['system_s']),
                    med(lambda r:r['transfer']['sampled_tree_rss_bytes']),med(lambda r:r['transfer']['filesystem_output_bytes'])])))
    (args.output/'summary.csv').write_text('\n'.join(rows)+'\n')
    print('COMPLETE', len(records), 'validated trials including warmups', flush=True)


if __name__ == '__main__':
    main()
