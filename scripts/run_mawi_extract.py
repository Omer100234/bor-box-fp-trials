#!/usr/bin/env python
"""CLI: extract DNS header-count rule results from a real MAWI backbone pcap.gz capture.

Usage:
    python scripts/run_mawi_extract.py --pcap data/mawi/200701011400.dump.gz \
        --out reports/mawi_response_rules.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.mawi_extract import extract_and_apply_rules, summarize


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    start = time.time()
    stats = extract_and_apply_rules(str(args.pcap))
    summary = summarize(stats)
    summary["source"] = str(args.pcap)
    summary["extraction_seconds"] = round(time.time() - start, 1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nWritten to {args.out}")


if __name__ == "__main__":
    main()
