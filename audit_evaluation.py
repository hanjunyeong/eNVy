"""Audit eNVy evaluation provenance against the original EMBER2024 JSONL files.

Run from the project directory, using Python 3.11+:
    python audit_evaluation.py --data evaluation_data --predictions evaluation_results/full/predictions.csv --metrics evaluation_results/full/metrics.json

Read-only with respect to input files. A new timestamped audit directory is
created under evaluation_results. This checks provenance and duplicate label/
score agreement; it does not recompute model predictions or establish labels.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import tempfile


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def classify(name):
    for part in ('Win32', 'Win64', 'Dot_Net'):
        if f'_{part}_test.jsonl' in name:
            return part
    return 'other'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=Path('evaluation_data'))
    parser.add_argument('--predictions', type=Path, default=Path('evaluation_results/full/predictions.csv'))
    parser.add_argument('--metrics', type=Path, default=Path('evaluation_results/full/metrics.json'))
    parser.add_argument('--model', type=Path, default=Path('models/EMBER2024_PE.model'))
    parser.add_argument('--evaluate-script', type=Path, default=Path('evaluate.py'))
    parser.add_argument('--out', type=Path, help='New directory; existing directories are not overwritten')
    parser.add_argument('--score-tolerance', type=float, default=0.0,
                        help='Maximum difference between duplicate scores (default: exact)')
    args = parser.parse_args()
    if not math.isfinite(args.score_tolerance) or args.score_tolerance < 0:
        parser.error('--score-tolerance must be finite and nonnegative')
    if not args.data.is_dir() or not args.predictions.is_file() or not args.metrics.is_file():
        parser.error('data directory, predictions.csv, and metrics.json must exist; see --help')
    metrics = json.loads(args.metrics.read_text(encoding='utf-8-sig'))
    names = metrics.get('feature_files')
    if not isinstance(names, list) or not names or len(names) != len(set(names)):
        raise ValueError('metrics feature_files must be a nonempty list of unique basenames')
    if metrics.get('limit') != 0 or metrics.get('evaluation_scope') != 'all_downloaded_test_rows':
        raise ValueError('Only a full evaluation with limit=0 can be audited as full')
    if any(not isinstance(n, str) or Path(n).name != n or not n.endswith('_test.jsonl') for n in names):
        raise ValueError('Unexpected file name in metrics feature_files')
    discovered = {}
    for path in args.data.rglob('*_test.jsonl'):
        if path.is_file():
            discovered.setdefault(path.name, []).append(path)
    for name in names:
        if len(discovered.get(name, [])) != 1:
            raise ValueError(f'Expected exactly one original file named {name!r}; found {len(discovered.get(name, []))}')
    extras = sorted(str(p.relative_to(args.data)) for name, paths in discovered.items()
                    if name not in set(names) for p in paths)
    out = args.out or Path('evaluation_results') / ('audit_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    out.mkdir(parents=True, exist_ok=False)
    threshold = float(metrics.get('threshold', 0.5))
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError('Invalid original threshold')
    file_reports = []
    visited = skipped = csv_count = 0
    per_type = Counter()
    with tempfile.TemporaryDirectory(prefix='sqlite_', dir=out) as tempdir:
        db = sqlite3.connect(str(Path(tempdir) / 'audit.sqlite'))
        try:
            db.execute('PRAGMA temp_store=FILE')
            db.execute('PRAGMA cache_size=-65536')
            db.execute('CREATE TABLE obs (sha TEXT NOT NULL, label INTEGER NOT NULL, score REAL NOT NULL, source TEXT NOT NULL, raw_digest TEXT NOT NULL)')
            with args.predictions.open(encoding='utf-8-sig', newline='') as handle:
                reader = csv.DictReader(handle)
                required = {'source_jsonl', 'line', 'sha256', 'label', 'score', 'prediction'}
                if not reader.fieldnames or not required.issubset(reader.fieldnames):
                    raise ValueError(f'CSV missing required columns: {required}')
                current = next(reader, None)
                for name in names:
                    path = discovered[name][0]
                    print(f'Reading {name}', flush=True)
                    digest = hashlib.sha256()
                    raw_lines = labeled = unlabelled = 0
                    stat_before = path.stat()
                    batch = []
                    with path.open('rb') as src:
                        for number, rawline in enumerate(src, 1):
                            digest.update(rawline)
                            if not rawline.strip():
                                continue
                            raw_lines += 1
                            visited += 1
                            try:
                                raw = json.loads(rawline)
                                label = raw.get('label')
                            except Exception as error:
                                raise ValueError(f'Invalid JSON at {name}:{number}') from error
                            if label not in (0, 1):
                                unlabelled += 1
                                skipped += 1
                                continue
                            if current is None:
                                raise ValueError(f'CSV ended before {name}:{number}')
                            sha = str(raw.get('sha256', '')).lower()
                            if not re.fullmatch(r'[0-9a-f]{64}', sha):
                                raise ValueError(f'Invalid source SHA-256 at {name}:{number}')
                            try:
                                score = float(current['score'])
                                row_matches = (current['source_jsonl'] == name
                                               and int(current['line']) == number
                                               and current['sha256'].lower() == sha
                                               and int(current['label']) == int(label)
                                               and int(current['prediction']) == int(score >= threshold))
                            except (KeyError, TypeError, ValueError) as error:
                                raise ValueError(f'Invalid CSV row at {name}:{number}') from error
                            if not row_matches or not math.isfinite(score) or not 0 <= score <= 1:
                                raise ValueError(f'Source/line/SHA/label/prediction mismatch at {name}:{number}')
                            # Raw-byte comparison detects exact row differences, not feature inequality.
                            row_digest = hashlib.sha256(rawline.rstrip(b'\r\n')).hexdigest()
                            batch.append((sha, int(label), score, name, row_digest))
                            labeled += 1
                            csv_count += 1
                            per_type[classify(name)] += 1
                            if len(batch) >= 5000:
                                db.executemany('INSERT INTO obs VALUES (?,?,?,?,?)', batch)
                                batch.clear()
                                db.commit()
                            current = next(reader, None)
                    if batch:
                        db.executemany('INSERT INTO obs VALUES (?,?,?,?,?)', batch)
                        db.commit()
                    stat_after = path.stat()
                    if (stat_before.st_size, stat_before.st_mtime_ns) != (stat_after.st_size, stat_after.st_mtime_ns):
                        raise ValueError(f'Source file changed while reading: {name}')
                    file_reports.append({'file': str(path.relative_to(args.data)), 'type': classify(name),
                                         'bytes': stat_after.st_size, 'sha256': digest.hexdigest(),
                                         'nonempty_rows': raw_lines, 'labeled_rows': labeled,
                                         'unlabeled_rows': unlabelled})
                if current is not None:
                    raise ValueError('Predictions CSV contains extra or out-of-order rows')
            print('Grouping duplicate hashes...', flush=True)
            db.execute('CREATE INDEX obs_sha ON obs(sha)')
            db.execute('CREATE TABLE uniques (sha TEXT, label INTEGER, score REAL)')
            group_query = ('SELECT sha,COUNT(*),MIN(label),MAX(label),MIN(score),MAX(score),'
                           'COUNT(DISTINCT source),COUNT(DISTINCT raw_digest) FROM obs GROUP BY sha')
            multiplicity = Counter()
            label_conflicts = score_conflicts = differing_raw = cross_file = 0
            unique_count = 0
            unique_batch = []
            for sha, count, lo_label, hi_label, lo_score, hi_score, nsource, nraw in db.execute(group_query):
                unique_count += 1
                multiplicity[count] += 1
                label_conflicts += int(lo_label != hi_label)
                score_conflicts += int(hi_score - lo_score > args.score_tolerance)
                differing_raw += int(count > 1 and nraw > 1)
                cross_file += int(nsource > 1)
                unique_batch.append((sha, lo_label, lo_score))
                if len(unique_batch) >= 5000:
                    db.executemany('INSERT INTO uniques VALUES (?,?,?)', unique_batch)
                    unique_batch.clear()
            if unique_batch:
                db.executemany('INSERT INTO uniques VALUES (?,?,?)', unique_batch)
            db.commit()
            same_file = db.execute('SELECT COUNT(DISTINCT sha) FROM (SELECT sha,source FROM obs GROUP BY sha,source HAVING COUNT(*) > 1)').fetchone()[0]
            scores = None
            if label_conflicts == 0 and score_conflicts == 0:
                tn, fp, fn, tp = db.execute('SELECT '
                    'SUM(CASE WHEN label=0 AND score<? THEN 1 ELSE 0 END),'
                    'SUM(CASE WHEN label=0 AND score>=? THEN 1 ELSE 0 END),'
                    'SUM(CASE WHEN label=1 AND score<? THEN 1 ELSE 0 END),'
                    'SUM(CASE WHEN label=1 AND score>=? THEN 1 ELSE 0 END) '
                    'FROM uniques', (threshold, threshold, threshold, threshold)).fetchone()
                tn, fp, fn, tp = (int(v or 0) for v in (tn, fp, fn, tp))
                negatives, positives = tn + fp, tp + fn
                before_neg = 0
                auc_numerator = 0.0
                for n, positive in db.execute('SELECT COUNT(*),SUM(label) FROM uniques GROUP BY score ORDER BY score'):
                    negative = n - positive
                    auc_numerator += positive * (before_neg + negative / 2)
                    before_neg += negative
                scores = {'samples': unique_count, 'benign': negatives, 'malicious': positives,
                          'threshold': threshold, 'TN': tn, 'FP': fp, 'FN': fn, 'TP': tp,
                          'accuracy': (tn + tp) / unique_count if unique_count else None,
                          'precision': tp / (tp + fp) if tp + fp else 0.0,
                          'recall': tp / positives if positives else None,
                          'false_positive_rate': fp / negatives if negatives else None,
                          'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
                          'roc_auc': auc_numerator / (positives * negatives) if positives and negatives else None}
            report = {'audit_timestamp_utc': datetime.now(timezone.utc).isoformat(),
                'scope': 'Recorded full evaluation: source files matched against prediction CSV in order; no new predictions.',
                'file_count': len(names), 'files': file_reports, 'additional_test_files_not_in_metrics': extras,
                'visited_nonempty_rows': visited, 'unlabeled_rows_skipped': skipped,
                'prediction_rows_verified': csv_count, 'rows_by_type': dict(per_type),
                'unique_sha256': unique_count, 'duplicate_rows_removed': csv_count - unique_count,
                'sha256_multiplicity': {str(k): v for k, v in sorted(multiplicity.items())},
                'unique_hashes_repeated_within_a_file': same_file,
                'unique_hashes_found_in_multiple_files': cross_file,
                'duplicate_hashes_with_different_raw_line_bytes': differing_raw,
                'raw_byte_note': 'Different raw lines can differ in metadata, formatting or features; this is not a feature-vector comparison.',
                'duplicate_label_conflicts': label_conflicts, 'duplicate_score_conflicts': score_conflicts,
                'score_tolerance': args.score_tolerance, 'deduplicated_metrics': scores,
                'original_metrics': {'samples': metrics.get('samples'), 'visited_rows': metrics.get('visited_rows'),
                                     'unlabeled_rows_skipped': metrics.get('unlabeled_rows_skipped'),
                                     'model_sha256': metrics.get('model_sha256')},
                'input_hashes': {'predictions_csv_sha256': file_sha256(args.predictions),
                                 'metrics_json_sha256': file_sha256(args.metrics),
                                 'evaluate_script_sha256': file_sha256(args.evaluate_script) if args.evaluate_script.is_file() else None,
                                 'local_model_sha256': file_sha256(args.model) if args.model.is_file() else None},
                'limits': ['Source file provenance is checked, but score correctness is not recomputed.',
                           'Full upstream dataset completeness and reason for duplication are not established.',
                           'No identical feature-vector or equal ground-truth guarantee is implied by SHA or raw-line comparison.']}
            for k, observed in [('samples', csv_count), ('visited_rows', visited), ('unlabeled_rows_skipped', skipped)]:
                if metrics.get(k) != observed:
                    raise ValueError(f'Original metrics {k} does not match audit count ({metrics.get(k)} vs {observed})')
            with (out / 'audit.json').open('x', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, allow_nan=False)
                f.write('\n')
            with (out / 'files.csv').open('x', encoding='utf-8-sig', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(file_reports[0]))
                writer.writeheader()
                writer.writerows(file_reports)
            print(f'Raw rows: {visited:,}; labeled: {csv_count:,}; unique: {unique_count:,}')
            print(f'Label conflicts: {label_conflicts:,}; score conflicts: {score_conflicts:,}; extra test files: {len(extras):,}')
            print(f'Saved: {out / "audit.json"} and {out / "files.csv"}')
            if label_conflicts or score_conflicts:
                raise SystemExit('Conflicting duplicate groups found; metrics were not produced.')
        finally:
            db.close()


if __name__ == '__main__':
    main()
