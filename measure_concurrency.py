r"""Measure concurrent uploads against the local eNVy service, including HTTP 429.

    .\.venv\Scripts\python.exe .\measure_concurrency.py --file C:\Windows\System32\where.exe

Only localhost:8000 is contacted. The file is read but never executed.
Pure queue waiting cannot be recovered from the API's current timestamps.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import platform
import secrets
import statistics
import threading
import time
import urllib.request


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def request_scan(path, timeout):
    boundary = 'envyload' + secrets.token_hex(16)
    prefix = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="sample{path.suffix.lower()}"\r\n'
              'Content-Type: application/octet-stream\r\n\r\n').encode('ascii')
    suffix = f'\r\n--{boundary}--\r\n'.encode('ascii')
    size = path.stat().st_size
    conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=timeout)
    try:
        conn.putrequest('POST', '/scan')
        conn.putheader('Content-Type', f'multipart/form-data; boundary={boundary}')
        conn.putheader('Content-Length', str(len(prefix) + size + len(suffix)))
        conn.endheaders()
        try:
            conn.send(prefix)
            sent = 0
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    sent += len(block)
                    if sent > size:
                        raise ValueError('file grew during upload')
                    conn.send(block)
            if sent != size:
                raise ValueError('file shrank during upload')
            conn.send(suffix)
        except (BrokenPipeError, ConnectionResetError) as error:
            # The server can reject before reading the complete body. Try to
            # retain its HTTP status; if unavailable, expose a client error.
            try:
                response = conn.getresponse()
            except Exception:
                raise error
            body = response.read()
            try:
                return response.status, json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return response.status, {'detail': body[:300].decode('utf-8', 'replace')}
        response = conn.getresponse()
        body = response.read()
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            payload = {'detail': body[:300].decode('utf-8', 'replace')}
        return response.status, payload
    finally:
        conn.close()


def get_job(job_id):
    if len(job_id) != 32 or any(c not in '0123456789abcdef' for c in job_id):
        raise ValueError('invalid job id')
    with urllib.request.urlopen(f'http://127.0.0.1:8000/jobs/{job_id}', timeout=15) as response:
        return json.load(response)


def scenario(path, concurrency, poll, deadline):
    barrier = threading.Barrier(concurrency, timeout=30)
    group_start = time.perf_counter()

    def run(number):
        entry = {'request': number, 'http_status': None, 'status': None}
        try:
            barrier.wait()
            started = time.perf_counter()
            code, body = request_scan(path, deadline)
            entry['ack_seconds'] = round(time.perf_counter() - started, 6)
            entry['http_status'] = code
            if code not in (200, 202):
                entry['status'] = 'http_rejected'
                entry['detail'] = body.get('detail') if isinstance(body, dict) else None
                entry['elapsed_seconds'] = round(time.perf_counter() - started, 6)
                return entry
            if not isinstance(body, dict) or not isinstance(body.get('job_id'), str):
                raise ValueError('invalid acknowledgement')
            job_id = body['job_id']
            entry['job_id'] = job_id
            polls = 0
            while body.get('status') not in ('succeeded', 'failed'):
                if time.perf_counter() - started > deadline:
                    raise TimeoutError('polling deadline exceeded')
                time.sleep(poll)
                body = get_job(job_id)
                polls += 1
            entry.update(status=body['status'], result_source=body.get('result_source'),
                         score=(body.get('result') or {}).get('score'),
                         polls=polls, error=body.get('error'),
                         elapsed_seconds=round(time.perf_counter() - started, 6))
        except Exception as error:
            entry['status'] = 'client_error'
            entry['error'] = f'{type(error).__name__}: {error}'
        return entry

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        results = list(executor.map(run, range(1, concurrency + 1)))
    finished = time.perf_counter() - group_start
    elapsed = [r['elapsed_seconds'] for r in results if r['status'] == 'succeeded']
    return {'concurrency': concurrency, 'group_elapsed_seconds': round(finished, 6),
            'http_429': sum(r['http_status'] == 429 for r in results),
            'succeeded': sum(r['status'] == 'succeeded' for r in results),
            'http_or_task_or_client_failures': sum(r['status'] != 'succeeded' for r in results),
            'median_success_seconds': statistics.median(elapsed) if elapsed else None,
            'requests': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--concurrency', type=int, nargs='+', default=[3, 5])
    parser.add_argument('--poll-seconds', type=float, default=0.5)
    parser.add_argument('--deadline-seconds', type=float, default=900)
    parser.add_argument('--out', type=Path, help='New JSON report filename')
    args = parser.parse_args()
    if not args.file.is_file() or args.file.suffix.lower() not in ('.exe', '.dll'):
        parser.error('--file must be an existing .exe or .dll')
    if not args.concurrency or any(not 1 <= n <= 8 for n in args.concurrency):
        parser.error('each concurrency must be between 1 and 8')
    if not 0.1 <= args.poll_seconds <= 30 or args.deadline_seconds <= 0:
        parser.error('invalid poll or deadline')
    out = args.out or Path('evaluation_results') / ('concurrency_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    before = args.file.stat()
    sample_hash = file_sha(args.file)
    report = {'created_utc': datetime.now(timezone.utc).isoformat(),
              'file': {'name': args.file.name, 'bytes': before.st_size, 'sha256': sample_hash},
              'environment': {'platform': platform.platform(), 'python': platform.python_version()},
              'poll_interval_seconds': args.poll_seconds, 'scenarios': [],
              'limits': ['One file per request; simultaneous start, no controlled warm-up and no large-population load test.',
                         'Each scenario is run once, and includes upload, server processing and polling delay.',
                         'Pure queue wait is not measurable without a queue-entry timestamp.',
                         'Cached results and HTTP 429 rejections must be reported, not omitted.']}
    failure = None
    # Reserve the output name before sending any files.
    with out.open('x', encoding='utf-8') as output:
        try:
            for n in args.concurrency:
                before_scenario = args.file.stat()
                if (before_scenario.st_size, before_scenario.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                    raise ValueError('sample changed during test')
                item = scenario(args.file, n, args.poll_seconds, args.deadline_seconds)
                report['scenarios'].append(item)
                print(f'concurrency={n}: succeeded={item["succeeded"]}, HTTP429={item["http_429"]}, total={item["group_elapsed_seconds"]:.3f}s', flush=True)
            if file_sha(args.file) != sample_hash:
                raise ValueError('sample changed during test')
        except Exception as error:
            failure = error
            report['error'] = f'{type(error).__name__}: {error}'
        finally:
            json.dump(report, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write('\n')
    print(f'Saved: {out}')
    if failure:
        raise SystemExit(str(failure))


if __name__ == '__main__':
    main()
