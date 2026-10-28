r"""Summarize existing prediction scores at four thresholds after SHA-256 deduplication.

Windows, from the eNVy project directory:
    .\.venv\Scripts\python.exe .\analyze_thresholds.py

This is a descriptive analysis of the recorded test set, not a validation-set
threshold selection or a new model inference. Conflicting duplicate labels or
scores stop the analysis. No input data or cache entries are modified.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import tempfile


def digest_file(path):
    sha = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', type=Path, default=Path('evaluation_results/full/predictions.csv'))
    parser.add_argument('--metrics', type=Path, default=Path('evaluation_results/full/metrics.json'))
    parser.add_argument('--out', type=Path, help='New JSON report filename; no existing file is overwritten')
    args = parser.parse_args()
    if not args.predictions.is_file():
        parser.error('predictions.csv not found')
    original_metrics = json.loads(args.metrics.read_text(encoding='utf-8-sig')) if args.metrics.is_file() else {}
    if original_metrics and (original_metrics.get('limit') != 0 or
                             original_metrics.get('evaluation_scope') != 'all_downloaded_test_rows'):
        raise ValueError('Recorded metrics do not describe a full evaluation')
    input_sha = digest_file(args.predictions)
    stat_before = args.predictions.stat()
    thresholds = (0.3, 0.5, 0.7, 0.9)
    counts = {threshold: {'TN': 0, 'FP': 0, 'FN': 0, 'TP': 0} for threshold in thresholds}
    rows = unique = conflicts = 0
    # SQLite bounds Python memory for a million-row file.
    with tempfile.TemporaryDirectory(prefix='envy-threshold-') as directory:
        db = sqlite3.connect(str(Path(directory) / 'scores.sqlite'))
        try:
            db.execute('CREATE TABLE predictions (sha TEXT NOT NULL, label INTEGER NOT NULL, score REAL NOT NULL)')
            with args.predictions.open(encoding='utf-8-sig', newline='') as f:
                reader = csv.DictReader(f)
                if not {'sha256', 'label', 'score'}.issubset(reader.fieldnames or []):
                    raise ValueError('CSV needs sha256, label and score columns')
                batch = []
                for row in reader:
                    sha = row['sha256'].lower()
                    try:
                        label, score = int(row['label']), float(row['score'])
                    except (TypeError, ValueError) as error:
                        raise ValueError(f'Invalid label or score at CSV row {rows + 2}') from error
                    if not re.fullmatch(r'[0-9a-f]{64}', sha) or label not in (0, 1) or not math.isfinite(score) or not 0 <= score <= 1:
                        raise ValueError(f'Invalid SHA-256, label or score at CSV row {rows + 2}')
                    batch.append((sha, label, score))
                    rows += 1
                    if len(batch) >= 5000:
                        db.executemany('INSERT INTO predictions VALUES (?,?,?)', batch)
                        batch.clear()
                if batch:
                    db.executemany('INSERT INTO predictions VALUES (?,?,?)', batch)
            db.commit()
            db.execute('CREATE INDEX idx_sha ON predictions(sha)')
            for sha, lo_label, hi_label, lo_score, hi_score in db.execute(
                    'SELECT sha,MIN(label),MAX(label),MIN(score),MAX(score) FROM predictions GROUP BY sha'):
                unique += 1
                if lo_label != hi_label or lo_score != hi_score:
                    conflicts += 1
                    continue
                for threshold in thresholds:
                    predicted = lo_score >= threshold
                    key = ('TP' if predicted else 'FN') if lo_label else ('FP' if predicted else 'TN')
                    counts[threshold][key] += 1
        finally:
            db.close()
    stat_after = args.predictions.stat()
    if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
        raise ValueError('predictions.csv changed during analysis')
    if conflicts or not unique:
        raise ValueError(f'No threshold results: {conflicts} conflicting duplicate SHA groups, {unique} unique groups')
    if original_metrics and original_metrics.get('samples') != rows:
        raise ValueError('Prediction row count does not match metrics.json')
    output = []
    for threshold in thresholds:
        c = counts[threshold]
        tn, fp, fn, tp = (c[x] for x in ('TN', 'FP', 'FN', 'TP'))
        output.append({'threshold': threshold, **c,
                       'false_positive_rate': fp / (tn + fp) if tn + fp else None,
                       'recall': tp / (tp + fn) if tp + fn else None,
                       'precision': tp / (tp + fp) if tp + fp else None,
                       'accuracy': (tp + tn) / unique})
    report = {'created_utc': datetime.now(timezone.utc).isoformat(),
              'prediction_csv_sha256': input_sha, 'model_sha256_recorded': original_metrics.get('model_sha256'),
              'input_rows': rows, 'unique_sha256': unique, 'duplicate_conflicts': conflicts,
              'thresholds': output,
              'scope': 'Existing test-set CSV scores only; no model inference or raw-feature comparison.',
              'limits': ['Test-set comparisons are descriptive; use a separate validation set for selecting a threshold.',
                         'Then evaluate the chosen threshold on a separate untouched test set.',
                         'These scores and labels are not a current real-world operational performance estimate.']}
    out = args.out or Path('evaluation_results') / ('thresholds_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write('\n')
    for item in output:
        print(f"threshold={item['threshold']:.1f} FPR={item['false_positive_rate']} recall={item['recall']} FP={item['FP']} FN={item['FN']}")
    print(f'Saved: {out}')


if __name__ == '__main__':
    main()
