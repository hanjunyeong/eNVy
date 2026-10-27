import hashlib
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import fakeredis
from fastapi.testclient import TestClient
import numpy as np
from billiard.einfo import ExceptionWithTraceback
from billiard.exceptions import SoftTimeLimitExceeded, WorkerLostError
from celery.exceptions import Retry
from celery.worker.request import Request

from envy.config import Settings
from envy.inference import create_app
from envy.engine import AnalysisError, InferenceClient, analyze_job
from envy.cache import RedisCache, CacheUnavailable
from envy.store import Store
from envy import tasks


def pe_fixture():
    """Parser-only synthetic PE header/section; never executed."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10b)
    struct.pack_into("<II", data, optional + 16, 0x1000, 0x1000)
    struct.pack_into("<II", data, optional + 24, 0x1000, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 224
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 512, 0x1000, 512, 512)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[512:] = bytes(range(256)) * 2
    return bytes(data)


class InferenceTests(unittest.TestCase):
    def test_model_loaded_once_and_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model"
            model.write_bytes(b"fake model for singleton test")
            settings = Settings(data_dir=root, model_path=model)
            loads = []
            vectors = []

            class Booster:
                def __init__(self, model_file):
                    loads.append(model_file)

                def num_feature(self):
                    return 2568

                def predict(self, vector, **kwargs):
                    vectors.append(vector)
                    assert kwargs == {"num_threads": 1}
                    return [.8]

            application = create_app(settings, Booster)
            with TestClient(application) as client:
                metadata = client.get("/health").json()
                self.assertEqual(metadata["model_sha256"], hashlib.sha256(model.read_bytes()).hexdigest())
                self.assertEqual(metadata["pipeline_fingerprint"], settings.pipeline_fingerprint())
                body = {"features": [0.1] * 2568, "model_version": metadata["model_version"]}
                for _ in range(3):
                    response = client.post("/predict", json=body)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["score"], .8)
                self.assertEqual(len(loads), 1)
                self.assertEqual(len(vectors), 3)
                self.assertEqual(vectors[0].dtype, np.dtype("float32"))
                self.assertEqual(vectors[0].shape, (1, 2568))
                self.assertEqual(client.post("/predict", json={**body, "features": [0.1]}).status_code, 422)
                self.assertEqual(client.post("/predict", json={**body, "model_version": "old-model"}).status_code, 409)
                self.assertEqual(client.post("/predict", json={**body, "features": [True] * 2568}).status_code, 422)
                self.assertEqual(client.post("/predict", json={**body, "features": [1e50] * 2568}).status_code, 422)
                oversized = b" " * 65537
                self.assertEqual(client.post("/predict", content=oversized,
                                             headers={"Content-Type": "application/json"}).status_code, 413)


class EngineTests(unittest.TestCase):
    def test_same_float32_feature_representation_and_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(data_dir=Path(directory))
            job_id = uuid.uuid4().hex
            data = pe_fixture()
            settings.input_path(job_id).write_bytes(data)
            version = settings.model_version("1" * 64)
            job = {"id": job_id, "size_bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "model_version": version}
            stages = []
            captured = []

            class Extractor:
                def feature_vector(self, bytez):
                    self_data = data
                    assert bytez == self_data
                    return [1 / 3] * 2568

            class RPC:
                def metadata(self):
                    return {"model_version": version, "feature_count": 2568}

                def predict(self, vector, model_version):
                    captured.append(vector)
                    assert model_version == version
                    return {"score": .8, "verdict": "악성으로 의심"}

            result = analyze_job(job, settings, RPC(), stages.append, Extractor)
            self.assertEqual(result["score"], .8)
            self.assertEqual(result["details"]["sha256"], job["sha256"])
            self.assertEqual(stages, ["read_file", "pe_validation", "metadata", "feature_extraction", "inference"])
            self.assertEqual(captured[0].dtype, np.dtype("float32"))
            self.assertEqual(float(captured[0][0]), float(np.float32(1 / 3)))
            settings.input_path(job_id).write_bytes(b"changed")
            with self.assertRaises(AnalysisError):
                analyze_job(job, settings, RPC(), extractor_factory=Extractor)

    def test_inference_rpc_checks_version_and_verdict(self):
        import httpx
        settings = Settings()
        outputs = [{"score": .8, "verdict": "악성으로 의심", "model_version": "v1"},
                   {"score": .8, "verdict": "정상으로 추정", "model_version": "v1"}]
        def handler(request):
            return httpx.Response(200, json=outputs.pop(0))
        client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://inference")
        rpc = InferenceClient(settings, client)
        try:
            self.assertEqual(rpc.predict(np.zeros(2568, dtype=np.float32), "v1")["score"], .8)
            with self.assertRaises(AnalysisError):
                rpc.predict(np.zeros(2568, dtype=np.float32), "v1")
        finally:
            rpc.close()

    def test_inference_metadata_rejects_partial_or_stale_rollout(self):
        import httpx
        settings = Settings()
        sha = "1" * 64
        baseline = {"status": "ready", "model_sha256": sha,
                    "model_version": settings.model_version(sha), "feature_count": 2568,
                    "pipeline_version": settings.pipeline_version,
                    "pipeline_fingerprint": settings.pipeline_fingerprint(),
                    "threshold": settings.threshold}
        payloads = [baseline,
                    {**baseline, "pipeline_version": "previous-pipeline"},
                    {**baseline, "pipeline_fingerprint": "previous-build"},
                    {**baseline, "threshold": .6},
                    {**baseline, "model_version": "previous-model"},
                    {**baseline, "model_sha256": "not-a-hash"},
                    {key: value for key, value in baseline.items() if key != "pipeline_fingerprint"}]
        def handler(request):
            return httpx.Response(200, json=payloads.pop(0))
        rpc = InferenceClient(settings, httpx.Client(transport=httpx.MockTransport(handler),
                                                   base_url="http://inference"))
        try:
            self.assertEqual(rpc.metadata()["model_version"], baseline["model_version"])
            for _ in range(6):
                with self.assertRaises(AnalysisError):
                    rpc.metadata()
        finally:
            rpc.close()


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.settings = Settings(data_dir=root, database_url="sqlite:///" + str(root / "jobs.db"))
        self.store = Store(self.settings)
        self.store.init()
        self.cache = RedisCache(self.settings, fakeredis.FakeRedis())
        self.version = self.settings.model_version("1" * 64)

    def tearDown(self):
        self.cache.close()
        self.store.close()
        self.temporary.cleanup()

    def job(self, sha="2" * 64):
        identifier = uuid.uuid4().hex
        self.store.create_job(identifier, "test.exe", self.version)
        self.store.set_uploaded(identifier, sha, 1024)
        return identifier

    def complete_result(self, score=.8):
        return {"score": score, "verdict": "악성으로 의심" if score >= .5 else "정상으로 추정",
                "details": None, "details_error": None, "analysis_seconds": .25}

    def test_fresh_result_then_versioned_cache_hit_skips_engine(self):
        first = self.job()
        services = (self.settings, self.store, self.cache, object())
        with patch.object(tasks, "services", return_value=services), \
             patch.object(tasks, "analyze_job", return_value=self.complete_result()) as engine:
            tasks.scan_job.run(first)
            self.assertEqual(self.store.get_job(first)["status"], "succeeded")
            self.store.mark_cleaned(first)  # API confirms raw-file cleanup.
            second = self.job()
            tasks.scan_job.run(second)
            self.assertEqual(engine.call_count, 1)
            self.assertEqual(self.store.get_job(second)["result_source"], "cache")
            self.store.mark_cleaned(second)
            self.assertEqual(self.store.capacity(), 0)

    def test_benign_result_is_not_cached(self):
        services = (self.settings, self.store, self.cache, object())
        with patch.object(tasks, "services", return_value=services), \
             patch.object(tasks, "analyze_job", return_value=self.complete_result(.1)) as engine:
            for _ in range(2):
                identifier = self.job()
                tasks.scan_job.run(identifier)
                self.store.mark_cleaned(identifier)
            self.assertEqual(engine.call_count, 2)

    def test_registered_celery_task_applies_and_cache_outage_does_not_block(self):
        identifier = self.job()
        services = (self.settings, self.store, self.cache, object())
        with patch.object(tasks, "services", return_value=services), \
             patch.object(self.cache, "acquire", side_effect=CacheUnavailable()), \
             patch.object(tasks, "analyze_job", return_value=self.complete_result()) as engine:
            task_result = tasks.scan_job.apply(args=[identifier], throw=True)
        self.assertTrue(task_result.successful())
        self.assertEqual(tasks.scan_job.name, "envy.scan")
        self.assertEqual(self.store.get_job(identifier)["status"], "succeeded")
        self.assertEqual(engine.call_count, 1)

    def test_locked_duplicate_retries_without_starting(self):
        identifier = self.job()
        self.cache.acquire("2" * 64, self.version, "other-job", 30)
        with patch.object(tasks, "services", return_value=(self.settings, self.store, self.cache, object())), \
             patch.object(tasks.scan_job, "retry", side_effect=Retry()) as retry:
            with self.assertRaises(Retry):
                tasks.scan_job.run(identifier)
        self.assertEqual(self.store.get_job(identifier)["status"], "queued")
        retry.assert_called_once_with(countdown=2)

    def test_soft_timeout_records_terminal_failure(self):
        identifier = self.job()
        with patch.object(tasks, "services", return_value=(self.settings, self.store, self.cache, object())), \
             patch.object(tasks, "analyze_job", side_effect=SoftTimeLimitExceeded()):
            tasks.scan_job.run(identifier)
        record = self.store.get_job(identifier)
        self.assertEqual(record["status"], "failed")
        self.assertIn("제한 시간", record["error"])

    def test_parent_handles_hard_timeout_and_worker_loss_but_not_retry(self):
        request = object.__new__(tasks.ManagedRequest)
        request._args = ["3" * 32]
        request._kwargs = {}
        with patch.object(Request, "on_timeout"), patch.object(tasks, "fail_in_parent") as fail:
            request.on_timeout(True, 300)
            fail.assert_not_called()
            request.on_timeout(False, 330)
            fail.assert_called_once()
        with patch.object(Request, "on_failure"), patch.object(tasks, "fail_in_parent") as fail:
            request.on_failure(SimpleNamespace(exception=WorkerLostError("killed")))
            fail.assert_called_once()
        with patch.object(Request, "on_failure"), patch.object(tasks, "fail_in_parent") as fail:
            wrapped = ExceptionWithTraceback(Retry(), "")
            request.on_failure(SimpleNamespace(exception=wrapped))
            fail.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
