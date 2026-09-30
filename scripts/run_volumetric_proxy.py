#!/usr/bin/env python
"""CLI: Volumetric QPS Flood queue-based proxy (catalog §1) -- standalone pass, separate
from run_pipeline.py's R1-R6/R7 pass, since it only needs (2LD, ts) and skips the regex
rule evaluation entirely.

Usage:
    python scripts/run_volumetric_proxy.py --csv data/raw/dataset.csv --schema config/schema.json \
        --out reports/volumetric_proxy.json [--max-rows N]
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.aggregate import approx_registrable_domain
from tier0fp.canonicalize import canonicalize_qname
from tier0fp.pipeline import _parse_ts, read_rows
from tier0fp.schema import SchemaConfig
from tier0fp.volumetric_proxy import VolumetricQPSProxyState


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-rows", type=int, default=None, help="Stop after this many reader rows (for a fast representative-subset run).")
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    args = parser.parse_args()

    schema = SchemaConfig.from_json(args.schema)
    state = VolumetricQPSProxyState()

    reader_rows = 0
    quarantined = 0
    labeled = 0
    benign = 0
    first_ts = None
    last_ts = None
    start = time.time()

    for row in read_rows(args.csv, schema):
        reader_rows += 1
        if args.max_rows and reader_rows > args.max_rows:
            reader_rows -= 1
            break

        try:
            ts_raw = row[schema.ts_col]
            qname_raw = row[schema.qname_col]
            label_raw = row[schema.label_col]
        except IndexError:
            quarantined += 1
            continue

        canon = canonicalize_qname(qname_raw)
        ts = _parse_ts(ts_raw)
        if canon.is_malformed or ts is None:
            quarantined += 1
            continue

        if not schema.is_benign_label(label_raw):
            labeled += 1
            continue

        benign += 1
        twoLD = approx_registrable_domain(canon.normalized)
        state.observe(twoLD, ts)
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts

        if args.progress_every and reader_rows % args.progress_every == 0:
            elapsed = time.time() - start
            print(f"[volumetric_proxy] {reader_rows:,} rows in {elapsed:.1f}s", flush=True)

    summary = state.to_summary()
    summary["accounting"] = {
        "reader_rows": reader_rows,
        "quarantined": quarantined,
        "labeled": labeled,
        "benign": benign,
    }
    summary["span_seconds"] = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else None

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.1f}s. benign={benign:,} span={summary['span_seconds']}s max_2ld_rate={summary['max_single_2ld_rate_seen']}")
    for t in sorted(summary["thresholds"], key=lambda k: int(k)):
        stats = summary["thresholds"][t]
        print(f"  >= {t} qps/2LD: {stats['flagged_count']:,} ({stats['fraction']*100:.4f}%)")
    print(f"\nWritten to {args.out}")


if __name__ == "__main__":
    main()
