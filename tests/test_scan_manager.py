"""300 MiB transport/lifecycle tests; no malware and no real model needed."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REAL_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory
REAL_POPEN = subprocess.Popen
MIB = 1024 * 1024

WORKER_SOURCE = r'''
import argparse
import json
import os
from pathlib import Path
import time

p = argparse.ArgumentParser()
p.add_argument('--model', required=True)
p.add_argument('--input', required=True)
p.add_argument('--result', required=True)
a = p.parse_args()
model = Path(a.model)
source = Path(a.input)
size = source.stat().st_size
with source.open('rb') as f:
    mode = f.read(32)
record = {'input_path': str(source), 'size': size, 'pid': os.getpid()}
(model.parent / 'received.json').write_text(json.dumps(record), encoding='utf-8')
if mode in (b'hold', b'timeout'):
    time.sleep(30)
if mode == b'crash':
    os._exit(7)
result = Path(a.result)
if mode == b'invalid':
    result.write_text('not-json', encoding='utf-8')
    raise SystemExit(0)
if mode == b'missing':
    raise SystemExit(0)
if mode == b'error':
    payload = {'ok': False, 'status_code': 400, 'detail': 'invalid PE'}
else:
    payload = {'ok': True, 'result': {
        'score': 0.1, 'verdict': '정상으로 추정',
        'details': {'transport_size': size}, 'details_error': None,
    }}
temporary = result.with_suffix('.tmp')
temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
os.replace(temporary, result)
'''


class GeneratedStream:
    """Generate bytes only in requested bounded chunks, not one giant buffer."""
    def __init__(self, size, prefix=b'', delay=0):
        self.size = size
        self.remaining = size
        self.prefix = prefix
        self.delay = delay
        self.requests = []
        self.bytes_returned = 0

    def read(self, amount=-1):
        if not isinstance(amount, int) or amount < 0:
            raise AssertionError('unbounded reads are forbidden')
        if amount > MIB:
            raise AssertionError('reads must be <= 1 MiB')
        self.requests.append(amount)
        if self.delay:
            time.sleep(self.delay)
        amount = min(amount, self.remaining)
        result = b'\x00' * amount
        if self.bytes_returned == 0 and self.prefix:
            result = self.prefix[:amount] + result[len(self.prefix[:amount]):]
        self.remaining -= amount
        self.bytes_returned += amount
        return result


def until(condition, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(.01)
    raise AssertionError('condition did not become true')


def pid_alive(pid):
    if os.name == 'nt':
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            status = ctypes.c_ulong()
            return bool(kernel.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(status))) and status.value == 259
        finally:
            kernel.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class LargeUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        package = ROOT
        sys.path.insert(0, str(package))
        path = package / 'scan_manager.py'
        spec = importlib.util.spec_from_file_location('large_upload_manager_tested', path)
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)
        config_spec = importlib.util.spec_from_file_location('large_upload_config_tested', package / 'scan_config.py')
        cls.config = importlib.util.module_from_spec(config_spec)
        config_spec.loader.exec_module(cls.config)

    def setUp(self):
        self.temp = REAL_TEMPORARY_DIRECTORY(prefix='envy-large-test-')
        self.root = Path(self.temp.name)
        self.worker = self.root / 'worker.py'
        self.worker.write_text(WORKER_SOURCE, encoding='utf-8')
        self.model = self.root / 'model.stub'
        self.model.write_text('stub model', encoding='utf-8')
        self.managers = []
        self.threads = []

    def tearDown(self):
        for manager in self.managers:
            manager.close()
        for thread in self.threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.temp.cleanup()

    def manager(self, timeout=3, max_concurrent=1, max_file_size=300*MIB):
        manager = self.module.ScanManager(self.worker, self.model,
                                         timeout_seconds=timeout,
                                         max_concurrent=max_concurrent,
                                         max_file_size=max_file_size)
        self.managers.append(manager)
        return manager

    @contextmanager
    def capture_directories(self):
        paths = []
        def create(*args, **kwargs):
            kwargs['dir'] = self.root
            directory = REAL_TEMPORARY_DIRECTORY(*args, **kwargs)
            paths.append(Path(directory.name))
            return directory
        with patch.object(self.module.tempfile, 'TemporaryDirectory', side_effect=create):
            yield paths

    def assert_error(self, code, callback):
        with self.assertRaises(self.module.ScanError) as caught:
            callback()
        self.assertEqual(caught.exception.status_code, code)

    def running(self, manager, source):
        outcome = {}
        def call():
            try:
                outcome['result'] = manager.scan_file(source)
            except Exception as error:
                outcome['error'] = error
        thread = threading.Thread(target=call, daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread, outcome

    def test_default_config(self):
        self.assertEqual(self.config.MAX_FILE_SIZE, 300*MIB)
        self.assertEqual(self.config.CHUNK_SIZE, MIB)
        self.assertEqual(self.config.SCAN_TIMEOUT_SECONDS, 120.)
        self.assertEqual(self.config.MAX_CONCURRENT_SCANS, 1)

    def test_exact_300_mib_streams_and_cleans_input(self):
        manager = self.manager()
        source = GeneratedStream(300*MIB)
        with self.capture_directories() as directories, patch.object(self.module.subprocess, 'Popen', wraps=REAL_POPEN) as popen:
            result = manager.scan_file(source)
            self.assertEqual(result['score'], .1)
            self.assertEqual(result['details']['transport_size'], 300*MIB)
            self.assertEqual(source.bytes_returned, 300*MIB)
            self.assertTrue(source.requests)
            self.assertLessEqual(max(source.requests), MIB)
            self.assertEqual(popen.call_count, 1)
            self.assertFalse(popen.call_args.kwargs['shell'])
            self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)
        record = json.loads((self.root/'received.json').read_text())
        self.assertEqual(record['size'], 300*MIB)
        self.assertFalse(Path(record['input_path']).exists())
        self.assertTrue(directories)
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.status()['active_scans'], 0)

    def test_300_mib_plus_one_rejected_before_worker_starts(self):
        manager = self.manager()
        source = GeneratedStream(300*MIB+1)
        with self.capture_directories() as directories, patch.object(self.module.subprocess, 'Popen', wraps=REAL_POPEN) as popen:
            self.assert_error(413, lambda: manager.scan_file(source))
            self.assertFalse(popen.called)
        self.assertEqual(source.bytes_returned, 300*MIB+1)
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.status()['active_scans'], 0)
        self.assertEqual(manager.scan(b'after-reject')['score'], .1)

    def test_timeout_kills_child_and_cleans_staged_file(self):
        manager = self.manager(timeout=.5)
        with self.capture_directories() as directories:
            self.assert_error(504, lambda: manager.scan(b'timeout'))
        record = json.loads((self.root/'received.json').read_text())
        self.assertFalse(pid_alive(record['pid']))
        self.assertFalse(Path(record['input_path']).exists())
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.scan(b'after-timeout')['score'], .1)

    def test_busy_rejects_before_reading_new_stream(self):
        manager = self.manager(timeout=5)
        thread, outcome = self.running(manager, io.BytesIO(b'hold'))
        until(lambda: manager.status()['active_scans'] == 1 and (self.root/'received.json').exists())
        source = GeneratedStream(10)
        self.assert_error(429, lambda: manager.scan_file(source))
        self.assertEqual(source.requests, [])
        manager.close()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(outcome.get('error'), self.module.ScanError)
        record = json.loads((self.root/'received.json').read_text())
        self.assertFalse(pid_alive(record['pid']))
        self.assertFalse(Path(record['input_path']).exists())
        self.assert_error(503, lambda: manager.scan(b'after-close'))

    def test_startup_failure_releases_capacity_and_removes_input(self):
        manager = self.manager()
        with self.capture_directories() as directories, patch.object(self.module.subprocess, 'Popen', side_effect=OSError('fake creation failure')):
            self.assert_error(503, lambda: manager.scan(b'input'))
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.status()['active_scans'], 0)
        self.assertEqual(manager.scan(b'next')['score'], .1)

    def test_worker_crash_and_bad_json_cleanup_and_recovery(self):
        manager = self.manager()
        for data in [b'crash', b'invalid', b'missing']:
            with self.subTest(data=data), self.capture_directories() as directories:
                self.assert_error(502, lambda: manager.scan(data))
            self.assertTrue(all(not path.exists() for path in directories))
            self.assertEqual(manager.status()['active_scans'], 0)
        self.assertEqual(manager.scan(b'recover')['score'], .1)

    def test_small_injected_limit_has_same_exact_boundary(self):
        manager = self.manager(max_file_size=9)
        self.assertEqual(manager.scan(b'123456789')['details']['transport_size'], 9)
        self.assert_error(413, lambda: manager.scan(b'1234567890'))
        self.assertEqual(manager.status()['max_file_size_bytes'], 9)

    def test_read_failure_and_empty_stream_cleanup_without_worker(self):
        manager = self.manager()
        class FailingStream:
            calls = 0
            def read(self, amount):
                self.calls += 1
                if self.calls == 1:
                    return b'partial upload'
                raise OSError('fake input read failure')
        with self.capture_directories() as directories, patch.object(self.module.subprocess, 'Popen', wraps=REAL_POPEN) as popen:
            self.assert_error(503, lambda: manager.scan_file(FailingStream()))
            self.assert_error(400, lambda: manager.scan_file(io.BytesIO()))
            self.assertFalse(popen.called)
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.status()['preparing_scans'], 0)
        self.assertEqual(manager.scan(b'recover')['score'], .1)

    def test_busy_and_close_during_staging_clean_before_process_creation(self):
        manager = self.manager()
        ready = threading.Event()
        release = threading.Event()
        class GatedStream:
            calls = 0
            def read(self, amount):
                self.calls += 1
                if self.calls == 1:
                    ready.set()
                    if not release.wait(3):
                        raise AssertionError('staging gate was never released')
                    return b'staged data'
                return b''
        with self.capture_directories() as directories, patch.object(self.module.subprocess, 'Popen', wraps=REAL_POPEN) as popen:
            thread, outcome = self.running(manager, GatedStream())
            self.assertTrue(ready.wait(3))
            try:
                self.assertEqual(manager.status()['active_scans'], 0)
                self.assertEqual(manager.status()['preparing_scans'], 1)
                source = GeneratedStream(10)
                self.assert_error(429, lambda: manager.scan_file(source))
                self.assertEqual(source.requests, [])
                manager.close()
            finally:
                release.set()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcome['error'].status_code, 503)
            self.assertFalse(popen.called)
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(manager.status()['preparing_scans'], 0)

    def test_staging_time_is_not_charged_to_analysis_deadline(self):
        manager = self.manager(timeout=.5)
        # Two bounded reads (data then EOF) take .6sec, outside the .5sec child budget.
        source = GeneratedStream(32, delay=.3)
        self.assertEqual(manager.scan_file(source)['score'], .1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
