#!/usr/bin/env python
"""CLI: plan §9.5 secondary-corpus cross-check against the GraphTunnel normal/ and
wildcard/ sets. Run once per set and, optionally, diff against the primary ISP-corpus
report.json from run_pipeline.py.

Usage:
    python scripts/run_secondary_corpus.py --root data/graphtunnel/normal --label normal \
        --primary-report reports/run1/report.json --out reports/graphtunnel_normal.json
    python scripts/run_secondary_corpus.py --root data/graphtunnel/wildcard --label wildcard \
        --primary-report reports/run1/report.json --out reports/graphtunnel_wildcard.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.secondary_corpus import write_secondary_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Directory of QNAME text files")
    parser.add_argument("--label", required=True, choices=["normal", "wildcard"])
    parser.add_argument("--primary-report", type=Path, default=None, help="Primary ISP-corpus report.json to diff against")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    result = write_secondary_report(args.root, args.label, args.primary_report, args.out)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
