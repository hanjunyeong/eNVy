"""Run trusted analysis code in disposable processes, never the uploaded file.

Stages samples in bounded chunks to private temporary files and publishes atomic
JSON results. This is process separation, not an OS sandbox.
"""
import json
import io
import logging
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from scan_config import MAX_FILE_SIZE, CHUNK_SIZE, SCAN_TIMEOUT_SECONDS, MAX_CONCURRENT_SCANS

MAX_RESULT_BYTES = 32 * 1024 * 1024
STAGE_LABELS = {
    "read_file": "검사 파일 읽기",
    "load_dependencies": "분석 모듈 준비",
    "pe_validation": "PE 형식 검사",
    "metadata": "파일 상세정보 추출",
    "model_load": "모델 준비",
    "features_and_prediction": "특징 추출 및 모델 분석",
    "result_write": "결과 정리",
}


class ScanError(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class _Job:
    process: subprocess.Popen
    directory: tempfile.TemporaryDirectory
    finalized: bool = False
    finalize_lock: threading.Lock = field(default_factory=threading.Lock)


class ScanManager:
    def __init__(self, worker_script, model_path, timeout_seconds=SCAN_TIMEOUT_SECONDS,
                 max_concurrent=MAX_CONCURRENT_SCANS, max_file_size=MAX_FILE_SIZE):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        if not isinstance(max_concurrent, int) or max_concurrent < 1:
            raise ValueError("max_concurrent must be a positive integer")
        self.worker_script = Path(worker_script).resolve()
        self.model_path = Path(model_path).resolve()
        self.timeout_seconds = float(timeout_seconds)
        self.max_concurrent = max_concurrent
        if not isinstance(max_file_size, int) or max_file_size < 1:
            raise ValueError("max_file_size must be positive")
        self.max_file_size = max_file_size
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._lock = threading.Lock()
        self._active = {}
        self._closed = False
        self._in_use = 0

    def status(self):
        with self._lock:
            return {
                "active_scans": len(self._active),
                "max_concurrent_scans": self.max_concurrent,
                "scan_timeout_seconds": self.timeout_seconds,
                "accepting_scans": not self._closed,
                "max_file_size_bytes": self.max_file_size,
                "preparing_scans": self._in_use - len(self._active),
            }

    @staticmethod
    def _stop(process):
        """Bounded termination; return True only after the child is reaped."""
        if process.poll() is not None:
            return True
        try:
            process.terminate()
        except OSError:
            pass  # The child may have exited concurrently.
        try:
            process.wait(timeout=0.5)
            return True
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2.0)
            return True
        except subprocess.TimeoutExpired:
            return False

    def _finalize(self, job):
        with job.finalize_lock:
            if job.finalized:
                return True
            if job.process.poll() is None:
                return False
            # No live process can own a released slot or deleted result directory.
            with self._lock:
                self._active.pop(job.process.pid, None)
                self._in_use -= 1
            try:
                job.directory.cleanup()
            except OSError:
                logging.exception("Could not remove an analysis result directory")
            job.finalized = True
            self._slots.release()
            return True

    def _reap_later(self, job):
        # A rare OS-level failure to reap retains both slot and directory.
        # Keep retrying; never admit another job into this slot while it is alive.
        while not self._stop(job.process):
            time.sleep(1)
        self._finalize(job)

    def _read_result(self, path):
        try:
            with path.open("rb") as source:
                raw = source.read(MAX_RESULT_BYTES + 1)
            if len(raw) > MAX_RESULT_BYTES:
                raise ValueError("Worker result exceeds limit")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("Worker result is not an object")
            if payload.get("ok") is False:
                status = payload.get("status_code")
                message = payload.get("detail")
                if status not in {400, 413, 422, 500, 503} or not isinstance(message, str):
                    raise ValueError("Invalid worker error")
                raise ScanError(status, message[:512])
            if payload.get("ok") is not True:
                raise ValueError("Missing success flag")
            result = payload["result"]
            score = result["score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Invalid model score")
            verdict = "악성으로 의심" if score >= 0.5 else "정상으로 추정"
            if result["verdict"] != verdict:
                raise ValueError("Inconsistent model verdict")
            if result.get("details") is not None and not isinstance(result["details"], dict):
                raise ValueError("Invalid metadata")
            if result.get("details_error") is not None and not isinstance(result["details_error"], str):
                raise ValueError("Invalid metadata error")
            return {"score": float(score), "verdict": verdict,
                    "details": result.get("details"), "details_error": result.get("details_error")}
        except ScanError:
            raise
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            logging.exception("Could not read analysis worker result")
            raise ScanError(502, "분석 프로세스의 결과를 읽지 못했습니다. 다시 시도해 주세요.") from None

    @staticmethod
    def _last_stage_label(result_path):
        # Only fixed identifiers are displayed, never arbitrary worker/file text.
        try:
            with result_path.with_name("stage.json").open("rb") as source:
                raw = source.read(1025)
            if len(raw) > 1024:
                return None
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not isinstance(payload.get("stage"), str):
                return None
            return STAGE_LABELS.get(payload["stage"])
        except (OSError, ValueError, TypeError, RecursionError):
            return None

    def scan(self, data):
        # Byte-based compatibility for small tests; HTTP uploads use scan_file.
        return self.scan_file(io.BytesIO(data))

    def scan_file(self, source):
        with self._lock:
            if self._closed:
                raise ScanError(503, "서버가 종료 중입니다. 잠시 후 다시 시도해 주세요.")
            if not self._slots.acquire(blocking=False):
                raise ScanError(429, "다른 파일을 분석 중입니다. 잠시 후 다시 시도해 주세요.")
            self._in_use += 1
        job = None
        directory = None
        try:
            directory = tempfile.TemporaryDirectory(prefix="envy-scan-")
            input_path = Path(directory.name) / "sample.bin"
            result_path = Path(directory.name) / "result.json"
            size = 0
            # Enforce actual bytes, independently of client/UploadFile metadata.
            # One small chunk is resident in the server, not the whole upload.
            with input_path.open("wb") as target:
                while True:
                    with self._lock:
                        if self._closed:
                            raise ScanError(503, "서버 종료로 분석 준비가 중단됐습니다.")
                    block = source.read(CHUNK_SIZE)
                    if not block:
                        break
                    size += len(block)
                    if size > self.max_file_size:
                        limit = self.max_file_size / 1024 / 1024
                        raise ScanError(413, f"{limit:g} MiB 이하의 파일을 선택해 주세요.")
                    target.write(block)
            if not size:
                raise ScanError(400, "빈 파일입니다.")
            # The staging handle is closed before child creation (Windows-safe).
            started = time.monotonic()
            environment = os.environ.copy()
            environment.update({"OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1"})
            with self._lock:
                if self._closed:
                    raise ScanError(503, "서버가 종료 중입니다. 잠시 후 다시 시도해 주세요.")
                process = subprocess.Popen(
                    [sys.executable, str(self.worker_script), "--model", str(self.model_path),
                     "--input", str(input_path), "--result", str(result_path)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    shell=False, cwd=str(self.worker_script.parent), env=environment,
                )
                job = _Job(process, directory)
                self._active[process.pid] = job
            remaining = max(0.001, self.timeout_seconds - (time.monotonic() - started))
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                stage = self._last_stage_label(result_path)
                detail = f"분석 제한 시간({self.timeout_seconds:g}초)을 초과해 중단했습니다."
                if stage:
                    detail += f" 마지막 확인 단계: {stage}."
                logging.warning("Analysis timed out after %gs; last stage: %s", self.timeout_seconds, stage or "unknown")
                raise ScanError(504, detail) from None
            with self._lock:
                closed = self._closed
            if closed:
                raise ScanError(503, "서버 종료로 분석이 중단됐습니다.")
            if process.returncode != 0:
                logging.error("Analysis worker exited with code %s", process.returncode)
                raise ScanError(502, "분석 프로세스가 예기치 않게 종료됐습니다. 다시 시도해 주세요.")
            result = self._read_result(result_path)
            result["analysis_seconds"] = round(time.monotonic() - started, 3)
            return result
        except ScanError:
            raise
        except (OSError, subprocess.SubprocessError, RuntimeError):
            logging.exception("Could not prepare or run analysis worker")
            raise ScanError(503, "파일을 분석할 준비를 하지 못했습니다. 임시 저장 공간과 서버 상태를 확인해 주세요.") from None
        finally:
            if job is None:
                try:
                    if directory is not None:
                        directory.cleanup()
                finally:
                    with self._lock:
                        self._in_use -= 1
                    self._slots.release()
            else:
                self._stop(job.process)
                if not self._finalize(job):
                    logging.error("Analysis process could not be reaped immediately; retaining capacity")
                    threading.Thread(target=self._reap_later, args=(job,), daemon=True).start()

    def close(self):
        with self._lock:
            self._closed = True
            jobs = list(self._active.values())
        for job in jobs:
            self._stop(job.process)
        # Request threads own finalization; close() never deletes their files
        # while they are still reading a result.
