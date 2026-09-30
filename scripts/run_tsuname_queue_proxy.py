#!/usr/bin/env python
"""CLI: TsuNAME queue-based proxy (catalog §7, "similarity rule over the last K packets")
-- LIMIT if >= threshold of the last window_size packets (global, all clients) share the
same canonical QNAME. Standalone pass, separate from run_pipeline.py's R1-R6/R7(delta-t) pass.

Usage:
    python scripts/run_tsuname_queue_proxy.py --csv data/raw/dataset.csv --schema config/schema.json \
        --out reports/tsuname_queue_proxy.json [--window 100] [--threshold 5] [--max-rows N]
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.canonicalize import canonicalize_qname
from tier0fp.pipeline import read_rows
from tier0fp.r7_proxy import R7QueueProxyState
from tier0fp.schema import SchemaConfig


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--window", type=int, default=100)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    args = parser.parse_args()

    schema = SchemaConfig.from_json(args.schema)
    state = R7QueueProxyState(window_size=args.window, threshold=args.threshold)

    reader_rows = 0
    quarantined = 0
    labeled = 0
    benign = 0
    start = time.time()

    for row in read_rows(args.csv, schema):
        reader_rows += 1
        if args.max_rows and reader_rows > args.max_rows:
            reader_rows -= 1
            break

        try:
            qname_raw = row[schema.qname_col]
            label_raw = row[schema.label_col]
        except IndexError:
            quarantined += 1
            continue

        canon = canonicalize_qname(qname_raw)
        if canon.is_malformed:
            quarantined += 1
            continue

        if not schema.is_benign_label(label_raw):
            labeled += 1
            continue

        benign += 1
        state.observe(canon.normalized)

        if args.progress_every and reader_rows % args.progress_every == 0:
            elapsed = time.time() - start
            print(f"[tsuname_queue_proxy] {reader_rows:,} rows in {elapsed:.1f}s", flush=True)

    summary = state.to_summary()
    summary["accounting"] = {
        "reader_rows": reader_rows,
        "quarantined": quarantined,
        "labeled": labeled,
        "benign": benign,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    elapsed = time.time() - start
    print(
        f"\nDone in {elapsed:.1f}s. benign={benign:,} "
        f"flagged={summary['flagged_count']:,} ({summary['fraction']*100:.4f}%) "
        f"window={args.window} threshold={args.threshold}"
    )
    print(f"Written to {args.out}")


if __name__ == "__main__":
    main()
