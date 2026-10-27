"""Measure an existing cache lookup; never claim upload-to-result latency."""
import argparse
import statistics
import time
import httpx
from envy.cache import RedisCache
from envy.config import Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sha256")
    parser.add_argument("--runs", type=int, default=100)
    args = parser.parse_args()
    settings = Settings()
    response = httpx.get(settings.inference_url + "/health", timeout=10, trust_env=False)
    response.raise_for_status()
    version = response.json()["model_version"]
    cache = RedisCache(settings)
    if cache.get(args.sha256, version) is None:
        raise SystemExit("No malicious-result cache entry for this SHA/model version")
    values = []
    for _ in range(max(1, min(args.runs, 10000))):
        started = time.perf_counter()
        if cache.get(args.sha256, version) is None:
            raise SystemExit("Cache miss during measurement; results discarded")
        values.append((time.perf_counter() - started) * 1000)
    values.sort()
    print(f"Runs: {len(values)}, median: {statistics.median(values):.3f} ms, p95: {values[int((len(values)-1)*.95)]:.3f} ms")
    print("Cache lookup only. Excludes upload, SHA hashing, queue, API/DB response and original inference.")


if __name__ == "__main__":
    main()
