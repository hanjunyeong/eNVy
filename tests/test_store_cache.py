import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import fakeredis
from redis.exceptions import ConnectionError
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from envy.config import Settings
from envy.store import CapacityError, Store, utcnow
from envy.cache import CacheUnavailable, RedisCache

SHA = "a" * 64
RESULT = {"score": .9, "verdict": "악성으로 의심", "details": {"sha256": SHA}, "details_error": None}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = Settings(data_dir=self.root, database_url="sqlite:///" + str(self.root / "jobs.db"))
        self.store = Store(self.settings)
        self.store.init()

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def create(self, filename="sample.exe"):
        return self.store.create_job(uuid4().hex, filename, "model-sha:pipeline-v4:0.5")

    def test_job_lifecycle_history_and_idempotent_release(self):
        job = self.create()
        job_id = job["id"]
        self.assertEqual(job["status"], "uploading")
        self.assertEqual(self.store.capacity(), 1)
        self.assertEqual(self.store.set_uploaded(job_id, SHA, 100)["status"], "queued")
        self.assertEqual(self.store.start_job(job_id)["status"], "running")
        self.assertIsNone(self.store.start_job(job_id))
        self.store.set_stage(job_id, "features")
        result = self.store.finish(job_id, RESULT)
        self.assertEqual(result["result"], RESULT)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["stage"], "completed")
        self.assertTrue(result["started_at"].endswith("+00:00"))
        self.assertEqual(self.store.capacity(), 1)
        self.store.finish(job_id, error="late failure")
        self.assertEqual(self.store.capacity(), 1)
        self.store.mark_cleaned(job_id)
        self.store.mark_cleaned(job_id)
        self.assertEqual(self.store.capacity(), 0)
        self.assertEqual(self.store.get_job(job_id)["status"], "succeeded")
        self.assertEqual(self.store.recent()[0]["id"], job_id)
        self.assertNotIn("result", self.store.recent()[0])
        self.assertEqual(self.store.recent()[0]["score"], .9)

    def test_capacity_is_atomic_under_parallel_admission(self):
        def reserve(_):
            try:
                return self.create()["id"]
            except CapacityError:
                return None
        with ThreadPoolExecutor(max_workers=16) as executor:
            jobs = [j for j in executor.map(reserve, range(24)) if j]
        self.assertEqual(len(jobs), self.settings.max_pending_jobs)
        self.assertEqual(self.store.capacity(), self.settings.max_pending_jobs)
        with ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda _: self.store.finish(jobs[0], RESULT), range(24)))
        self.assertEqual(self.store.capacity(), self.settings.max_pending_jobs)
        with self.assertRaises(CapacityError):
            self.create()
        with ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda _: self.store.mark_cleaned(jobs[0]), range(24)))
        self.assertEqual(self.store.capacity(), self.settings.max_pending_jobs - 1)
        self.assertIsNotNone(self.create())

    def test_insert_failure_rolls_back_reservation(self):
        job = self.create()
        with self.assertRaises(IntegrityError):
            self.store.create_job(job["id"], "again.exe", "v")
        self.assertEqual(self.store.capacity(), 1)

    def test_cache_hit_holds_reservation_until_cleanup(self):
        job = self.create("new-name.exe")
        self.store.set_uploaded(job["id"], SHA, 123)
        result = self.store.mark_cache_hit(job["id"], RESULT)
        self.assertEqual(result["result_source"], "cache")
        self.assertEqual(result["filename"], "new-name.exe")
        self.assertEqual(self.store.capacity(), 1)
        self.store.mark_cleaned(job["id"])
        self.assertEqual(self.store.capacity(), 0)

    def test_maintenance_expires_stale_jobs_preserves_fresh_and_purges_cleaned(self):
        now = utcnow()
        old_upload, old_queue, old_running, fresh = [self.create() for _ in range(4)]
        self.store.set_uploaded(old_queue["id"], SHA, 1)
        self.store.set_uploaded(old_running["id"], SHA, 1)
        self.store.start_job(old_running["id"])
        with self.store.engine.begin() as connection:
            connection.execute(update(self.store.jobs).where(self.store.jobs.c.id == old_upload["id"]).values(created_at=now-timedelta(seconds=301)))
            connection.execute(update(self.store.jobs).where(self.store.jobs.c.id == old_queue["id"]).values(created_at=now-timedelta(seconds=self.settings.queue_ttl+1)))
            connection.execute(update(self.store.jobs).where(self.store.jobs.c.id == old_running["id"]).values(started_at=now-timedelta(seconds=self.settings.hard_timeout+121)))
        cleanable = self.store.maintenance(now)
        self.assertEqual({j["id"] for j in cleanable}, {old_upload["id"], old_queue["id"], old_running["id"]})
        self.assertEqual(self.store.capacity(), 4)
        self.assertEqual(self.store.get_job(fresh["id"])["status"], "uploading")
        self.store.mark_cleaned(old_upload["id"])
        self.assertEqual(self.store.capacity(), 3)
        self.assertNotIn(old_upload["id"], {j["id"] for j in self.store.cleanable_jobs()})
        with self.store.engine.begin() as connection:
            connection.execute(update(self.store.jobs).where(self.store.jobs.c.id.in_([old_upload["id"], old_queue["id"]])).values(finished_at=now-timedelta(days=31)))
        self.store.maintenance(now)
        self.assertIsNone(self.store.get_job(old_upload["id"]))
        self.assertIsNotNone(self.store.get_job(old_queue["id"]))

    def test_validation_and_restart_do_not_reset_capacity(self):
        self.assertIsNone(self.store.get_job("../../path"))
        with self.assertRaises(ValueError):
            self.store.create_job("../bad", "x.exe", "v")
        self.create()
        self.store.init()
        self.assertEqual(self.store.capacity(), 1)

    def test_active_sample_cannot_release_its_reservation(self):
        job = self.create()
        self.store.mark_cleaned(job["id"])
        self.assertEqual(self.store.capacity(), 1)
        self.assertFalse(self.store.get_job(job["id"])["input_cleaned"])
        self.store.set_uploaded(job["id"], SHA, 123)
        self.store.start_job(job["id"])
        self.store.mark_cleaned(job["id"])
        self.assertEqual(self.store.capacity(), 1)
        self.store.finish(job["id"], error="failure")
        self.store.mark_cleaned(job["id"])
        self.assertEqual(self.store.capacity(), 0)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.settings = Settings()
        self.client = fakeredis.FakeRedis()
        self.cache = RedisCache(self.settings, self.client)

    def tearDown(self):
        self.cache.close()

    def test_malicious_cache_version_ttl_and_filename_privacy(self):
        result = {**RESULT, "filename": "previous-user.exe", "analysis_seconds": 42}
        self.assertTrue(self.cache.put(SHA, "model-v1", result))
        self.assertEqual(self.cache.get(SHA, "model-v1"), RESULT)
        self.assertIsNone(self.cache.get(SHA, "model-v2"))
        key = self.cache._key("result", SHA, "model-v1")
        self.assertGreater(self.client.ttl(key), self.settings.cache_ttl - 5)

    def test_only_valid_malicious_results_are_cached(self):
        for bad in [
            {**RESULT, "score": .49}, {**RESULT, "score": float("nan")},
            {**RESULT, "score": 1.1}, {**RESULT, "score": True},
            {**RESULT, "verdict": "정상으로 추정"}, {**RESULT, "details": []},
            {**RESULT, "details": {"value": float("nan")}},
        ]:
            self.assertFalse(self.cache.put(SHA, "v", bad))
        self.assertIsNone(self.cache.get(SHA, "v"))

    def test_corrupt_values_and_cache_errors_degrade_to_miss(self):
        key = self.cache._key("result", SHA, "v")
        for payload in [b"bad json", json.dumps({"sha256": SHA, "model_version": "wrong", "result": RESULT}),
                        json.dumps({"sha256": SHA, "model_version": "v", "result": {**RESULT, "score": .2}})]:
            self.client.set(key, payload)
            self.assertIsNone(self.cache.get(SHA, "v"))
        with patch.object(self.client, "get", side_effect=ConnectionError("offline")):
            self.assertIsNone(self.cache.get(SHA, "v"))
        with patch.object(self.client, "set", side_effect=ConnectionError("offline")):
            self.assertFalse(self.cache.put(SHA, "v", RESULT))
            with self.assertRaises(CacheUnavailable):
                self.cache.acquire(SHA, "v", "job", 330)

    def test_locks_are_owner_checked_and_versioned(self):
        self.assertTrue(self.cache.acquire(SHA, "v1", "first", 330))
        self.assertFalse(self.cache.acquire(SHA, "v1", "second", 330))
        self.assertTrue(self.cache.acquire(SHA, "v2", "other-version", 330))
        self.assertFalse(self.cache.release(SHA, "v1", "second"))
        self.assertFalse(self.cache.acquire(SHA, "v1", "second", 330))
        self.assertTrue(self.cache.release(SHA, "v1", "first"))
        self.assertTrue(self.cache.acquire(SHA, "v1", "second", 330))


if __name__ == "__main__":
    unittest.main(verbosity=2)
