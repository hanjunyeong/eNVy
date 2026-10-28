"""Measure a local eNVy upload to acknowledgement and to completed result.

Run from the project directory while Docker Compose is healthy:
    python measure_envy.py --file C:\\Windows\\System32\\where.exe --repeat 3

The script sends only to localhost:8000, does not execute the file, does not
delete cache, and saves a new JSON report. It cannot measure individual model
load, feature-extraction, inference or pure queue durations in the current API.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import platform
import secrets
import statistics
import time
import urllib.error
import urllib.request


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def submit(path, timeout):
    boundary = 'envybenchmark' + secrets.token_hex(16)
    # The server uses this ASCII-only name solely for display; contents determine SHA.
    filename = 'sample' + path.suffix.lower()
    start = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
             'Content-Type: application/octet-stream\r\n\r\n').encode('ascii')
    end = f'\r\n--{boundary}--\r\n'.encode('ascii')
    size = path.stat().st_size
    conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=timeout)
    try:
        conn.putrequest('POST', '/scan')
        conn.putheader('Content-Type', f'multipart/form-data; boundary={boundary}')
        conn.putheader('Content-Length', str(len(start) + size + len(end)))
        conn.endheaders()
        conn.send(start)
        with path.open('rb') as source:
            sent = 0
            for block in iter(lambda: source.read(1024 * 1024), b''):
                sent += len(block)
                if sent > size:
                    raise ValueError('File changed while being sent')
                conn.send(block)
        if sent != size:
            raise ValueError('File changed while being sent')
        conn.send(end)
        response = conn.getresponse()
        body = response.read()
        if response.status not in (200, 202):
            raise RuntimeError(f'POST /scan returned HTTP {response.status}: {body[:500].decode("utf-8", "replace")}')
        return response.status, json.loads(body)
    finally:
        conn.close()


def get_job(job_id):
    if len(job_id) != 32 or any(x not in '0123456789abcdef' for x in job_id):
        raise ValueError('Invalid server job ID')
    url = f'http://127.0.0.1:8000/jobs/{job_id}'
    with urllib.request.urlopen(url, timeout=15) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--poll-seconds', type=float, default=0.5)
    parser.add_argument('--deadline-seconds', type=float, default=900)
    parser.add_argument('--out', type=Path, help='New JSON file; never overwrites an existing file')
    args = parser.parse_args()
    if not args.file.is_file() or args.file.suffix.lower() not in ('.exe', '.dll'):
        parser.error('--file must name an existing .exe or .dll')
    if not 1 <= args.repeat <= 20 or not 0.1 <= args.poll_seconds <= 30 or args.deadline_seconds <= 0:
        parser.error('repeat must be 1-20, poll seconds 0.1-30, deadline positive')
    out = args.out or Path('evaluation_results') / ('timing_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the report before sending files; fail safely if it already exists.
    report_handle = out.open('x', encoding='utf-8')
    before = args.file.stat()
    report = {'created_utc': datetime.now(timezone.utc).isoformat(),
              'sample_name': args.file.name, 'sample_bytes': before.st_size,
              'sample_sha256': sha256_file(args.file), 'repeat_requested': args.repeat,
              'poll_interval_seconds': args.poll_seconds,
              'environment': {'platform': platform.platform(), 'processor': platform.processor(),
                              'python': platform.python_version()},
              'definitions': {'ack_seconds': 'POST start through HTTP response; includes upload, multipart parsing, hashing and enqueue/cache response',
                              'result_seconds': 'POST start through observed terminal status; includes polling delay',
                              'analysis_seconds': 'Worker-reported analysis duration including stages; only for fresh analysis, not cache',
                              'queue_wait': 'not measured; DB created_at precedes upload copying and is not a queue-entry timestamp'},
              'runs': [], 'warnings': ['This is a local demo measurement, not a load test.',
                 'Cache hits require an already cached score >=0.5; the script never clears the cache.',
                 'Different cache status or machine load affects comparison; no causality or speedup is claimed.']}
    failure = None
    try:
        for i in range(args.repeat):
            current = args.file.stat()
            if (current.st_size, current.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                raise ValueError('File changed since measurement started')
            start = time.perf_counter()
            status_code, job = submit(args.file, args.deadline_seconds)
            ack = time.perf_counter() - start
            job_id = job.get('job_id')
            if not isinstance(job_id, str):
                raise ValueError('Server returned no job ID')
            polls = 0
            while job.get('status') not in ('succeeded', 'failed'):
                if time.perf_counter() - start > args.deadline_seconds:
                    raise TimeoutError(f'Polling deadline exceeded for job {job_id}')
                time.sleep(args.poll_seconds)
                job = get_job(job_id)
                polls += 1
            elapsed = time.perf_counter() - start
            result = job.get('result') or {}
            source = job.get('result_source')
            item = {'run': i + 1, 'job_id': job_id, 'initial_http_status': status_code,
                    'status': job.get('status'), 'result_source': source,
                    'ack_seconds': round(ack, 6), 'result_seconds': round(elapsed, 6),
                    'polls': polls, 'model_version': job.get('model_version'),
                    'score': result.get('score'), 'verdict': result.get('verdict'),
                    'analysis_seconds': result.get('analysis_seconds') if source == 'analysis' else None,
                    'error': job.get('error')}
            report['runs'].append(item)
            print(f'Run {i+1}: {item["status"]}, source={source}, ACK={ack:.3f}s, result={elapsed:.3f}s', flush=True)
            if item['status'] != 'succeeded':
                raise RuntimeError(f'Scan failed: {item["error"]}')
        if sha256_file(args.file) != report['sample_sha256']:
            raise ValueError('File bytes changed during measurements')
    except Exception as error:
        failure = error
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        report['summary_by_source'] = {}
        for source in ('analysis', 'cache'):
            rows = [r for r in report['runs'] if r['status'] == 'succeeded' and r['result_source'] == source]
            if rows:
                report['summary_by_source'][source] = {'runs': len(rows),
                    'median_ack_seconds': statistics.median(r['ack_seconds'] for r in rows),
                    'median_result_seconds': statistics.median(r['result_seconds'] for r in rows)}
        with report_handle:
            json.dump(report, report_handle, ensure_ascii=False, indent=2, allow_nan=False)
            report_handle.write('\n')
        print(f'Saved: {out}')
    if failure:
        raise SystemExit(str(failure))


if __name__ == '__main__':
    main()
