r"""Scan up to 50 signed Windows System32 PE files without executing them.

    .\.venv\Scripts\python.exe .\scan_signed_system_files.py --limit 50

A valid signature is evidence of the local verification status at this time,
not a ground-truth guarantee of benignness. Creates local eNVy history entries.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import time

from measure_envy import get_job, sha256_file, submit


def signed_candidates(limit):
    # No paths or commands supplied by a remote party are interpolated here.
    command = r"""
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$source = Join-Path $env:windir 'System32'
$files = Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Extension -in '.exe','.dll' } | Sort-Object FullName
$found = [System.Collections.Generic.List[object]]::new()
foreach ($file in $files) {
    if ($file.Length -le 0 -or $file.Length -gt 314572800) { continue }
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    if ($null -eq $sig -or $sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate) { continue }
    $found.Add([PSCustomObject]@{path=$file.FullName; bytes=$file.Length; status='Valid'; signer=$sig.SignerCertificate.Subject; thumbprint=$sig.SignerCertificate.Thumbprint})
    if ($found.Count -ge LIMIT_PLACEHOLDER) { break }
}
ConvertTo-Json -InputObject @($found.ToArray()) -Depth 4 -Compress
""".replace('LIMIT_PLACEHOLDER', str(limit))
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            encoding='utf-8', errors='replace', timeout=900)
    if result.returncode != 0:
        raise RuntimeError('Authenticode enumeration failed: ' + result.stderr[:500])
    candidates = json.loads(result.stdout)
    if not isinstance(candidates, list):
        raise ValueError('Unexpected signature enumeration result')
    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=50)
    parser.add_argument('--out', type=Path, help='New JSON report filename')
    parser.add_argument('--poll-seconds', type=float, default=0.5)
    parser.add_argument('--deadline-seconds', type=float, default=900)
    args = parser.parse_args()
    if platform.system() != 'Windows':
        parser.error('This tool requires Windows and PowerShell Get-AuthenticodeSignature')
    if not 1 <= args.limit <= 50 or not 0.1 <= args.poll_seconds <= 30 or args.deadline_seconds <= 0:
        parser.error('limit must be 1-50; poll must be 0.1-30 and deadline positive')
    out = args.out or Path('evaluation_results') / ('signed_system_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {'created_utc': datetime.now(timezone.utc).isoformat(), 'selection_limit': args.limit,
              'selection': 'First lexicographically ordered System32 .exe/.dll files with Authenticode status Valid, size <=300 MiB',
              'environment': {'platform': platform.platform(), 'python': platform.python_version()},
              'files': [], 'limits': ['Valid signature is not proof of benignness.',
                  'These System32 files are a convenience sample, not a representative population.',
                  'A suspicious model prediction is not an independently confirmed false positive.',
                  'Sequential scan; not a load test. Individual jobs are recorded in the eNVy database.']}
    error = None
    with out.open('x', encoding='utf-8') as handle:
        try:
            candidates = signed_candidates(args.limit)
            report['candidates_found'] = len(candidates)
            if not candidates:
                raise ValueError('No Valid-signed System32 candidates found')
            for i, candidate in enumerate(candidates, 1):
                path = Path(candidate['path'])
                item = {'path': str(path), 'bytes': candidate['bytes'],
                        'signature_status': candidate['status'], 'signer': candidate['signer'],
                        'certificate_thumbprint': candidate['thumbprint']}
                report['files'].append(item)
                try:
                    before = path.stat()
                    if before.st_size != candidate['bytes']:
                        raise ValueError('File changed after candidate selection')
                    item['sha256'] = sha256_file(path)
                    start = time.perf_counter()
                    status, job = submit(path, args.deadline_seconds)
                    item['initial_http_status'] = status
                    item['job_id'] = job['job_id']
                    while job.get('status') not in ('succeeded', 'failed'):
                        if time.perf_counter() - start > args.deadline_seconds:
                            raise TimeoutError('polling deadline exceeded')
                        time.sleep(args.poll_seconds)
                        job = get_job(item['job_id'])
                    item['status'] = job['status']
                    item['result_source'] = job.get('result_source')
                    result = job.get('result') or {}
                    item['score'] = result.get('score')
                    item['verdict'] = result.get('verdict')
                    item['model_version'] = job.get('model_version')
                    item['error'] = job.get('error')
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        item['status'] = 'file_changed'
                    print(f'{i}/{len(candidates)}: {path.name}: {item["status"]}, {item.get("verdict")}', flush=True)
                except Exception as exc:
                    item['status'] = 'client_error'
                    item['error'] = f'{type(exc).__name__}: {exc}'
                    print(f'{i}/{len(candidates)}: {path.name}: client_error', flush=True)
                    if 'HTTP 429' in str(exc) or 'HTTP 503' in str(exc):
                        raise RuntimeError('Server admission or queue unavailable; stopped early') from exc
        except Exception as exc:
            error = exc
            report['error'] = f'{type(exc).__name__}: {exc}'
        finally:
            complete = [f for f in report['files'] if f.get('status') == 'succeeded']
            report['summary'] = {'selected': report.get('candidates_found', 0), 'attempted': len(report['files']),
                'completed': len(complete), 'failed_or_changed': len(report['files']) - len(complete),
                'model_suspected': sum(f.get('verdict') == '악성으로 의심' for f in complete),
                'model_estimated_benign': sum(f.get('verdict') == '정상으로 추정' for f in complete)}
            json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write('\n')
    print(f'Saved: {out}')
    if error:
        raise SystemExit(str(error))


if __name__ == '__main__':
    main()
