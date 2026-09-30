#!/usr/bin/env python
"""CLI: plan §4.5 dataset profile. Run this BEFORE run_pipeline.py -- it's the sanity
anchor (Zipf head, DNSBL presence, diurnal shape) that tells you the schema map is right
before any rule executes.

Usage:
    python scripts/run_profile.py --csv data/raw/dataset.csv --schema config/schema.json \
        --out reports/profile.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.profile import build_profile
from tier0fp.schema import SchemaConfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path, help="Path to a SchemaConfig JSON file")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    schema = SchemaConfig.from_json(args.schema)
    profile = build_profile(args.csv, schema, args.out)
    print(json.dumps(profile.to_summary(top_k=20), indent=2, default=str))


if __name__ == "__main__":
    main()
