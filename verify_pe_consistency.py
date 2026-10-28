"""Compare a real PE, the worker extraction path and inference endpoint in-process.

Run in an isolated eNVy inference image with a small read-only PE mounted.
This never runs the PE. The HTTP endpoint is exercised through FastAPI
TestClient; this is not a production-network or full Docker queue test.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import tempfile
import time
import uuid

import lightgbm as lgb
import numpy as np
from fastapi.testclient import TestClient
from thrember.features import PEFeatureExtractor

from envy.config import Settings
from envy.engine import InferenceClient, analyze_job
from envy.inference import create_app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--model', type=Path, default=Path('/models/EMBER2024_PE.model'))
    parser.add_argument('--repeat', type=int, default=3)
    args = parser.parse_args()
    if not args.file.is_file() or not args.model.is_file():
        parser.error('PE sample and model file must exist')
    if not 1 <= args.repeat <= 10 or not 0 < args.file.stat().st_size <= 32 * 1024 * 1024:
        parser.error('Use a sample <=32 MiB and 1-10 repetitions')
    raw = args.file.read_bytes()
    sample_sha = hashlib.sha256(raw).hexdigest()
    model_sha = hashlib.sha256(args.model.read_bytes()).hexdigest()
    start = time.perf_counter()
    direct_model = lgb.Booster(model_file=str(args.model))
    load_time = time.perf_counter() - start
    reference = np.asarray(PEFeatureExtractor().feature_vector(raw), dtype=np.float32)
    if reference.shape != (2568,) or not np.isfinite(reference).all():
        raise ValueError('Reference feature vector is invalid')
    expected = float(direct_model.predict(reference.reshape(1, -1), num_threads=1)[0])
    recorded = {'server_vectors': [], 'wire_vectors': [], 'extract_seconds': [],
                'rpc_seconds': [], 'model_predict_seconds': [], 'factory_loads': 0}

    class ModelWrapper:
        def __init__(self, model_file):
            recorded['factory_loads'] += 1
            self.model = lgb.Booster(model_file=model_file)

        def num_feature(self):
            return self.model.num_feature()

        def predict(self, vector, **kwargs):
            recorded['server_vectors'].append(vector.copy().reshape(-1))
            started = time.perf_counter()
            try:
                return self.model.predict(vector, **kwargs)
            finally:
                recorded['model_predict_seconds'].append(time.perf_counter() - started)

    class TimedExtractor:
        def __init__(self):
            self.inner = PEFeatureExtractor()

        def feature_vector(self, data):
            started = time.perf_counter()
            try:
                return self.inner.feature_vector(data)
            finally:
                recorded['extract_seconds'].append(time.perf_counter() - started)

    class RecordingTransport:
        def __init__(self, client):
            self.client = client

        def get(self, *args, **kwargs):
            return self.client.get(*args, **kwargs)

        def post(self, *args, **kwargs):
            recorded['wire_vectors'].append(np.asarray(kwargs['json']['features'], dtype=np.float32))
            started = time.perf_counter()
            try:
                return self.client.post(*args, **kwargs)
            finally:
                recorded['rpc_seconds'].append(time.perf_counter() - started)

        def close(self):
            pass

    with tempfile.TemporaryDirectory(prefix='envy-parity-') as tmp:
        settings = Settings(data_dir=Path(tmp), model_path=args.model)
        application = create_app(settings=settings, booster_factory=ModelWrapper)
        results = []
        with TestClient(application) as client:
            metadata = client.get('/health').json()
            rpc = InferenceClient(settings, RecordingTransport(client))
            for _ in range(args.repeat):
                job_id = uuid.uuid4().hex
                settings.input_path(job_id).write_bytes(raw)
                job = {'id': job_id, 'sha256': sample_sha, 'size_bytes': len(raw),
                       'model_version': metadata['model_version']}
                result = analyze_job(job, settings, rpc, extractor_factory=TimedExtractor)
                results.append(result['score'])
        wire_ok = all(v.shape == reference.shape and v.dtype == np.float32 and np.array_equal(v, reference)
                      for v in recorded['wire_vectors'])
        server_ok = all(v.shape == reference.shape and v.dtype == np.float32 and np.array_equal(v, reference)
                        for v in recorded['server_vectors'])
        score_delta = max(abs(s - expected) for s in results)
        report = {'sample_sha256': sample_sha, 'sample_bytes': len(raw), 'model_sha256': model_sha,
                  'feature_count': len(reference), 'dtype': str(reference.dtype),
                  'reference_vector_sha256': hashlib.sha256(reference.tobytes()).hexdigest(),
                  'reference_equals_rpc_input': wire_ok,
                  'reference_equals_server_decoded_vector': server_ok,
                  'direct_model_score': expected, 'endpoint_scores': results,
                  'max_absolute_score_difference': score_delta,
                  'one_server_model_load_count': recorded['factory_loads'],
                  'repeat': args.repeat,
                  'diagnostic_timings_seconds': {
                      'standalone_model_load_once': load_time,
                      'median_feature_extraction': statistics.median(recorded['extract_seconds']),
                      'median_testclient_http_request': statistics.median(recorded['rpc_seconds']),
                      'median_model_predict': statistics.median(recorded['model_predict_seconds'])},
                  'limits': ['In-process HTTP TestClient; not the running production network or queue.',
                             'One sample only; timings include this environment and are not a before/after benchmark.',
                             'Feature extraction timing excludes extractor construction; HTTP timing includes JSON and model prediction.',
                             'The sample was read, not executed.']}
        print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
        if not (wire_ok and server_ok and score_delta <= 1e-12 and recorded['factory_loads'] == 1
                and len(results) == len(recorded['wire_vectors']) == len(recorded['server_vectors']) == args.repeat
                and all(math.isfinite(x) for x in results)):
            raise SystemExit('Parity verification failed')


if __name__ == '__main__':
    main()
