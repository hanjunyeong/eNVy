r"""Measure repeated LightGBM Booster construction; never scan or execute a PE.

Windows, from the eNVy project directory:
    .\.venv\Scripts\python.exe .\benchmark_model_load.py
"""
import argparse
from datetime import datetime, timezone
import gc
import hashlib
import json
from pathlib import Path
import platform
import statistics
import time


def digest_file(path):
    sha = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, default=Path('models/EMBER2024_PE.model'))
    parser.add_argument('--repeat', type=int, default=10)
    parser.add_argument('--out', type=Path, help='New report filename; existing files are never overwritten')
    args = parser.parse_args()
    if not args.model.is_file() or not 1 <= args.repeat <= 100:
        parser.error('Provide an existing model and --repeat between 1 and 100')
    import lightgbm as lgb
    before = args.model.stat()
    sha = digest_file(args.model)
    durations = []
    for _ in range(args.repeat):
        gc.collect()
        start = time.perf_counter()
        model = lgb.Booster(model_file=str(args.model))
        elapsed = time.perf_counter() - start
        if model.num_feature() != 2568:
            raise ValueError('This benchmark expects the 2568-feature PE model')
        durations.append(elapsed)
        del model
    after = args.model.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Model changed during measurement')
    out = args.out or Path('evaluation_results') / ('model_load_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'environment': {'platform': platform.platform(), 'processor': platform.processor(),
                        'python': platform.python_version(), 'lightgbm': lgb.__version__},
        'model': {'filename': args.model.name, 'bytes': before.st_size, 'sha256': sha, 'features': 2568},
        'metric': 'elapsed seconds around lgb.Booster(model_file=...) only',
        'repeat': args.repeat, 'seconds': durations, 'mean_seconds': statistics.mean(durations),
        'median_seconds': statistics.median(durations), 'min_seconds': min(durations),
        'max_seconds': max(durations), 'sum_seconds': sum(durations),
        'limitations': ['The model is read for its SHA-256 before timing, so file pages may already be cached.',
                        'Repeated loads in one process; operating-system file caches and scheduling are not controlled.',
                        'Does not measure server start, feature extraction, prediction, network or end-to-end speedup.',
                        'Different environments and warm-up conditions may produce different results.']}
    with out.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, allow_nan=False)
        handle.write('\n')
    print(f'Model load ({args.repeat} runs): mean={report["mean_seconds"]:.6f}s median={report["median_seconds"]:.6f}s')
    print(f'Saved: {out}')


if __name__ == '__main__':
    main()
