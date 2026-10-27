from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import fakeredis
from fastapi.testclient import TestClient

from envy.api import create_app
from envy.cache import RedisCache
from envy.config import Settings
from envy.store import Store


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.settings = Settings(data_dir=root / "uploads", database_url="sqlite:///" + str(root / "jobs.db"))
        self.store = Store(self.settings)
        self.cache = RedisCache(self.settings, fakeredis.FakeRedis())
        self.version = self.settings.model_version("a" * 64)
        self.published = []
        self.model = {"status": "ready", "model_version": self.version, "feature_count": 2568,
                      "model_sha256": "a"*64, "pipeline_version": self.settings.pipeline_version,
                      "pipeline_fingerprint": self.settings.pipeline_fingerprint(),
                      "threshold": self.settings.threshold}

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def client(self, publish=None):
        return TestClient(create_app(self.settings, self.store, self.cache,
                                     publish or self.published.append, self.model, maintenance=False))

    def post(self, client, data=b"sample bytes", filename="x.exe"):
        return client.post("/scan", files={"file": (filename, data)})

    def test_queue_result_history_and_cleanup(self):
        with self.client() as client:
            response = self.post(client, filename="..\\nested\\x.exe")
            self.assertEqual(response.status_code, 202)
            job = response.json()
            self.assertEqual(job["filename"], "x.exe")
            self.assertEqual(self.published, [job["id"]])
            self.assertTrue(self.settings.input_path(job["id"]).is_file())
            self.store.start_job(job["id"])
            self.store.finish(job["id"], {"score": .1, "verdict": "정상으로 추정", "details": None})
            self.assertEqual(self.store.capacity(), 1)
            completed = client.get("/jobs/" + job["id"]).json()
            self.assertEqual(completed["status"], "succeeded")
            self.assertFalse(self.settings.input_path(job["id"]).exists())
            self.assertEqual(self.store.capacity(), 0)
            history = client.get("/history").json()["items"]
            self.assertEqual(history[0]["score"], .1)
            self.assertNotIn("result", history[0])
            self.assertEqual(client.get("/jobs/not-a-uuid").status_code, 404)

    def test_verified_hash_cache_hit_uses_current_filename_without_publish(self):
        data = b"cached input bytes"
        digest = hashlib.sha256(data).hexdigest()
        self.assertTrue(self.cache.put(digest, self.version,
            {"score": .91, "verdict": "악성으로 의심", "details": {"sha256": digest}, "filename": "old.exe"}))
        with self.client() as client:
            response = self.post(client, data, "new.exe")
            self.assertEqual(response.status_code, 200)
            job = response.json()
            self.assertTrue(job["cached"])
            self.assertEqual(job["result"]["filename"], "new.exe")
            self.assertEqual(self.published, [])
            self.assertEqual(self.store.capacity(), 0)
            self.assertEqual(list(self.settings.data_dir.glob("*.bin")), [])

    def test_version_change_misses_cache_and_queue_bound_includes_cleanup(self):
        self.settings.max_pending_jobs = 1
        data = b"versioned bytes"
        self.cache.put(hashlib.sha256(data).hexdigest(), "old-model",
                       {"score": .9, "verdict": "악성으로 의심"})
        with self.client() as client:
            first = self.post(client, data).json()
            self.assertEqual(first["status"], "queued")
            self.assertEqual(self.post(client).status_code, 429)
            self.store.finish(first["id"], None, error="test error")
            self.assertEqual(self.post(client).status_code, 429)
            self.assertEqual(client.get("/jobs/" + first["id"]).json()["status"], "failed")
            self.assertEqual(self.post(client).status_code, 202)

    def test_input_and_publish_failures_release_workspace(self):
        with self.client() as client:
            for data, name, code in [(b"", "x.exe", 400), (b"text", "x.txt", 400)]:
                self.assertEqual(self.post(client, data, name).status_code, code)
            self.assertEqual(client.post("/scan", files={"other": ("x.exe", b"x")}).status_code, 400)
            self.assertEqual(self.store.capacity(), 0)
        def fail(_):
            raise OSError("test broker unavailable")
        with self.client(fail) as client:
            self.assertEqual(self.post(client).status_code, 503)
            self.assertEqual(self.store.capacity(), 0)
            self.assertEqual(list(self.settings.data_dir.glob("*.bin")), [])

    def test_request_body_limit_and_single_file(self):
        self.settings.max_file_size = 10
        with self.client() as client:
            self.assertEqual(self.post(client, b"x" * 11).status_code, 413)
            self.assertEqual(client.post("/scan", files=[("file", ("a.exe", b"a")),
                                                       ("file", ("b.exe", b"b"))]).status_code, 400)
            response = client.post("/scan", content=b"x" * 70000,
                                   headers={"Content-Type": "multipart/form-data; boundary=x"})
            self.assertEqual(response.status_code, 413)
            body = b'--x\r\nContent-Disposition: form-data; name="file"; filename="x.exe"\r\n\r\n' + b'x' * 70000 + b'\r\n--x--\r\n'
            response = client.post("/scan", content=iter([body[:100], body[100:]]),
                                   headers={"Content-Type": "multipart/form-data; boundary=x"})
            self.assertEqual(response.status_code, 413)

    def test_upload_admission_rejects_before_more_body_parsing(self):
        self.settings.max_concurrent_uploads = 1
        entered, released = threading.Event(), threading.Event()
        def hold(job_id):
            entered.set()
            released.wait(3)
            self.published.append(job_id)
        with self.client(hold) as client, ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.post, client)
            self.assertTrue(entered.wait(2))
            self.assertEqual(self.post(client).status_code, 429)
            self.assertEqual(client.get("/health").status_code, 200)
            released.set()
            self.assertEqual(first.result(3).status_code, 202)

    def test_api_registered_task_db_cache_round_trip(self):
        from envy import tasks
        with self.client() as client:
            def publish(job_id):
                return tasks.scan_job.apply(args=[job_id], task_id=job_id)
            client.app.state.service.publish = publish
            analysis = {"score": .93, "verdict": "악성으로 의심", "details": None, "details_error": None}
            with patch.object(tasks, "services", return_value=(self.settings, self.store, self.cache, object())), \
                 patch.object(tasks, "analyze_job", return_value=analysis) as analyze:
                first = self.post(client, b"same hash input", "first.exe")
                self.assertEqual(first.status_code, 202)
                self.assertEqual(first.json()["status"], "succeeded")
                second = self.post(client, b"same hash input", "second.exe")
                self.assertEqual(second.status_code, 200)
                self.assertTrue(second.json()["cached"])
                self.assertEqual(second.json()["result"]["filename"], "second.exe")
                self.assertEqual(analyze.call_count, 1)
                self.assertEqual(self.store.capacity(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
