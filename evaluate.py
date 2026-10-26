"""Evaluate eNVy's pretrained model on downloaded EMBER2024 PE test JSONL.

Run from the project directory:
  python evaluate.py --limit 1000  # smoke test only
  python evaluate.py             # complete downloaded test split
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from thrember.features import PEFeatureExtractor
from thrember.model import gather_feature_paths


def summarize(labels, scores):
    y = np.asarray(labels, dtype=np.int32)
    scores = np.asarray(scores, dtype=np.float64)
    predicted = (scores >= 0.5).astype(np.int32)
    tn, fp, fn, tp = (int(n) for n in confusion_matrix(y, predicted, labels=[0, 1]).ravel())
    return {
        "samples": len(labels), "benign": tn + fp, "malicious": tp + fn,
        "threshold": 0.5, "TN": tn, "FP": fp, "FN": fn, "TP": tp,
        "accuracy": float(accuracy_score(y, predicted)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)) if tp + fn else None,
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, scores)) if len(np.unique(y)) == 2 else None,
    }


def main():
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=base / "evaluation_data")
    parser.add_argument("--model", type=Path, default=base / "models" / "EMBER2024_PE.model")
    parser.add_argument("--limit", type=int, default=0, help="0 = all rows; positive = smoke test")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be >= 0")
    paths = gather_feature_paths(args.data, "test")
    model = lgb.Booster(model_file=str(args.model))
    extractor = PEFeatureExtractor()
    if extractor.dim != model.num_feature():
        raise ValueError(f"Feature mismatch: extractor={extractor.dim}, model={model.num_feature()}")
    output = base / "evaluation_results" / ("smoke" if args.limit else "full")
    output.mkdir(parents=True, exist_ok=True)
    labels, scores, batch, metadata = [], [], [], []
    visited = 0
    skipped = 0
    print(f"Test feature files: {len(paths)}", flush=True)

    with (output / "predictions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source_jsonl", "line", "sha256", "label", "score", "prediction"])

        def flush():
            if not batch:
                return
            values = np.asarray(model.predict(np.asarray(batch, dtype=np.float32))).reshape(-1)
            if len(values) != len(metadata) or not all(math.isfinite(float(s)) and 0 <= s <= 1 for s in values):
                raise ValueError("Invalid model predictions")
            for (source, line_number, sha, label), score in zip(metadata, values):
                score = float(score)
                labels.append(label)
                scores.append(score)
                writer.writerow([source, line_number, sha, label, score, int(score >= 0.5)])
            batch.clear()
            metadata.clear()
            print(f"Evaluated: {len(labels):,}", flush=True)

        for path in paths:
            print(f"Reading: {path.name}", flush=True)
            with path.open(encoding="utf-8") as source:
                for line_number, line in enumerate(source, start=1):
                    if not line.strip():
                        continue
                    if args.limit and visited >= args.limit:
                        break
                    visited += 1
                    try:
                        raw = json.loads(line)
                        label = raw.get("label")
                        if label not in (0, 1):
                            skipped += 1
                            continue
                        vector = np.asarray(extractor.process_raw_features(raw), dtype=np.float32)
                        if vector.shape != (model.num_feature(),):
                            raise ValueError(f"Unexpected vector shape: {vector.shape}")
                    except Exception as exc:
                        raise RuntimeError(f"Feature conversion failed at {path.name}:{line_number}") from exc
                    batch.append(vector)
                    metadata.append((path.name, line_number, raw.get("sha256", ""), int(label)))
                    if len(batch) >= 256:
                        flush()
            if args.limit and visited >= args.limit:
                break
        flush()

    if not labels:
        raise ValueError("No labeled test rows found")
    result = summarize(labels, scores)
    result.update({
        "evaluation_scope": "smoke_test_only" if args.limit else "all_downloaded_test_rows",
        "limit": args.limit, "visited_rows": visited, "unlabeled_rows_skipped": skipped,
        "model": args.model.name,
        "model_sha256": hashlib.sha256(args.model.read_bytes()).hexdigest(),
        "feature_files": [p.name for p in paths],
    })
    with (output / "metrics.json").open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False, allow_nan=False)
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    print(f"Saved: {output}")
    print("NOTE: smoke-test results are not the final benchmark." if args.limit else
          "NOTE: results cover the downloaded test rows; verify file completeness before reporting.")


if __name__ == "__main__":
    main()
