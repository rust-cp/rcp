param([switch]$BuildCandidate)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Run this qualification on native Windows.' }
if ($BuildCandidate) {
    if ($env:RUSTFLAGS -match 'target-feature=.*-crt-static') {
        throw 'Candidate qualification requires the static MSVC runtime.'
    }
    $env:RUSTFLAGS = "$($env:RUSTFLAGS) -C target-feature=+crt-static".Trim()
}
$features = 's3,smb,dav,https'
function Invoke-Cargo {
    param([string[]]$Arguments)
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) { throw "cargo failed with exit code $LASTEXITCODE" }
}
& rustc --version --verbose
Invoke-Cargo -Arguments @('fmt', '--all', '--check')
Invoke-Cargo -Arguments @('clippy', '--locked', '--no-default-features', '--features', $features,
    '--lib', '--bin', 'rcp', '--test', 'windows_local', '--test', 'hexagon', '--', '-D', 'warnings')
# Select platform-appropriate suites; the Unix process/peer contract suite stays
# on Linux. Serial execution avoids scheduler noise in the tuner's mock traffic.
Invoke-Cargo -Arguments @('test', '--locked', '--release', '--no-default-features', '--features', $features,
    '--lib', '--bin', 'rcp', '--test', 'windows_local', '--test', 'hexagon', '--', '--test-threads=1')
if ($BuildCandidate) {
    Invoke-Cargo -Arguments @('test', '--locked', '--release', '--no-default-features', '--features', "$features,rustls",
        '--test', 'windows_local', '--', '--test-threads=1')
    Invoke-Cargo -Arguments @('build', '--locked', '--release', '--no-default-features', '--features', "$features,rustls")
    $out = Join-Path (Get-Location) 'target/portability'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $candidate = Join-Path $out 'rcp-windows-x86_64-candidate.exe'
    Copy-Item -LiteralPath 'target/release/rcp.exe' -Destination $candidate
    $hash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  rcp-windows-x86_64-candidate.exe" | Set-Content -LiteralPath "$candidate.sha256" -Encoding ascii
    Write-Output "$hash  rcp-windows-x86_64-candidate.exe"
    $metadata = Join-Path $out 'cargo-metadata-windows.json'
    Invoke-Cargo -Arguments @('metadata', '--locked', '--no-default-features', '--features', "$features,rustls",
        '--filter-platform', 'x86_64-pc-windows-msvc', '--format-version', '1') |
        Set-Content -LiteralPath $metadata -Encoding utf8
    $env:PYTHONUTF8 = '1'
    $notices = Join-Path $out 'THIRD_PARTY_LICENSES.txt'
    Get-Content -LiteralPath $metadata -Raw | & python scripts/third-party-licenses.py |
        Set-Content -LiteralPath $notices -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'License collection failed.' }
    $runtime = Join-Path $out 'RUNTIME.txt'
    @(
        'Windows x86-64 MSVC; NTFS only. No default features; s3,smb,dav,https,rustls.'
        'Native local copy/verify/resume/sync/deletion, hard links, sparse files, catalog/cache and foreground termination qualified.'
        'HTTP, WebDAV, S3 and verified explicit-CA TLS fixtures qualified; real Windows SMB peers remain unqualified.'
        'Unsupported: NFS,HDFS,SFTP,remote rcp,tar,system-zstd,MCP,detached jobs,worker fleets,diagnostics,mount reports,chmod/chown,nocache.'
        'No POSIX owner/mode/ACL/xattr translation; skipped metadata checks are visible. Symlinks/junctions refused; UNC/non-NTFS mounts unqualified.'
        'Abrupt termination preserves the old destination and permits resume, but can leave an abandoned stage file.'
        'TLS needs an explicit PEM CA bundle; Windows certificate-store integration is unqualified.'
        'Built with -C target-feature=+crt-static; the MSVC runtime is statically linked. System DLL imports are recorded in MANIFEST.json.'
        'Unsigned development candidate; no release publication or FIPS claim.'
    ) | Set-Content -LiteralPath $runtime -Encoding utf8
    & python -m unittest discover -s scripts -p test_package_candidate.py
    if ($LASTEXITCODE -ne 0) { throw 'Candidate packaging controls failed.' }
    & python scripts/package-candidate.py --binary $candidate --notices $notices --runtime $runtime `
        --metadata $metadata --output $out --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Candidate packaging failed.' }
}
