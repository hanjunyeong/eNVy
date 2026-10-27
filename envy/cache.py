"""Versioned malicious-result cache and best-effort duplicate-work locks."""
import hashlib
import json
import logging
import math
import re

import redis
from redis.exceptions import RedisError, ResponseError, WatchError

MAX_CACHE_BYTES = 32 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end
"""


class CacheUnavailable(Exception):
    """Duplicate-work coordination is unavailable; analysis may proceed uncached."""


class RedisCache:
    def __init__(self, settings, client=None):
        self.settings = settings
        self.client = client if client is not None else redis.Redis.from_url(
            settings.cache_url, socket_connect_timeout=2, socket_timeout=2,
            decode_responses=False,
        )

    @staticmethod
    def _key(prefix, sha256, model_version):
        if not isinstance(sha256, str) or SHA256.fullmatch(sha256) is None:
            raise ValueError("Invalid SHA-256")
        if not isinstance(model_version, str) or not 1 <= len(model_version) <= 512:
            raise ValueError("Invalid model version")
        version = hashlib.sha256(model_version.encode("utf-8")).hexdigest()
        return f"envy:{prefix}:{version}:{sha256}"

    def _result(self, result):
        if not isinstance(result, dict):
            return None
        score = result.get("score")
        if isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score):
            return None
        if not self.settings.threshold <= score <= 1:
            return None
        if result.get("verdict") != "악성으로 의심":
            return None
        details = result.get("details")
        error = result.get("details_error")
        if details is not None and not isinstance(details, dict):
            return None
        if error is not None and not isinstance(error, str):
            return None
        # Do not return a previous uploader's filename, job ID, or latency.
        candidate = {"score": float(score), "verdict": "악성으로 의심",
                     "details": details, "details_error": error}
        try:
            json.dumps(candidate, allow_nan=False)
        except (ValueError, TypeError, RecursionError):
            return None
        return candidate

    def get(self, sha256, model_version):
        key = self._key("result", sha256, model_version)
        try:
            raw = self.client.get(key)
            if raw is None or len(raw) > MAX_CACHE_BYTES:
                return None
            payload = json.loads(raw)
            if not isinstance(payload, dict) or payload.get("sha256") != sha256 or payload.get("model_version") != model_version:
                return None
            return self._result(payload.get("result"))
        except (RedisError, ValueError, TypeError, RecursionError):
            logging.warning("Result cache unavailable or invalid; using fresh analysis")
            return None

    def put(self, sha256, model_version, result):
        key = self._key("result", sha256, model_version)
        result = self._result(result)
        if result is None:
            return False
        try:
            payload = json.dumps({"sha256": sha256, "model_version": model_version, "result": result},
                                 ensure_ascii=False, allow_nan=False)
            if len(payload.encode("utf-8")) > MAX_CACHE_BYTES:
                return False
            return bool(self.client.set(key, payload, ex=self.settings.cache_ttl))
        except (RedisError, ValueError, TypeError, RecursionError):
            logging.warning("Result cache write skipped")
            return False

    def acquire(self, sha256, model_version, owner, ttl):
        key = self._key("lock", sha256, model_version)
        if not isinstance(owner, str) or not 1 <= len(owner) <= 128:
            raise ValueError("Invalid lock owner")
        if not isinstance(ttl, int) or ttl < 1:
            raise ValueError("Invalid lock TTL")
        try:
            return bool(self.client.set(key, owner, nx=True, ex=ttl))
        except RedisError:
            # Cache outage must not turn all new analyses into endless retries.
            # Celery's worker/container limits still bound actual concurrency.
            logging.warning("Duplicate-work lock unavailable; proceeding without deduplication")
            raise CacheUnavailable("Duplicate-work cache is unavailable") from None

    def release(self, sha256, model_version, owner):
        key = self._key("lock", sha256, model_version)
        try:
            return bool(self.client.eval(RELEASE_SCRIPT, 1, key, owner))
        except ResponseError as error:
            # fakeredis without its optional Lua runtime uses this equivalent
            # atomic WATCH/MULTI path. Real Redis normally executes the Lua path.
            if "unknown command" not in str(error).lower():
                return False
            for _ in range(3):
                try:
                    with self.client.pipeline() as transaction:
                        transaction.watch(key)
                        current = transaction.get(key)
                        if isinstance(current, bytes):
                            current = current.decode("utf-8")
                        if current != owner:
                            transaction.unwatch()
                            return False
                        transaction.multi()
                        transaction.delete(key)
                        return bool(transaction.execute()[0])
                except WatchError:
                    continue
            return False
        except RedisError:
            return False

    def close(self):
        self.client.close()
