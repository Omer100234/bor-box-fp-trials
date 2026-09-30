#!/usr/bin/env python
"""CLI: live re-resolution harness for response-side rules (catalog §3-§6, §10, §11).

Issues real DNS queries against real root servers and a public recursive resolver for a
sample of real domain names (this project's own corpus top-2LDs plus a small DNSSEC/NSEC3
diversity supplement -- see tier0fp/live_harness.py). Not part of the offline test suite:
network-dependent and non-deterministic (real infrastructure can change).

Usage:
    python scripts/run_live_response_harness.py --corpus-2ld-json reports/full_run/report.json \
        --out reports/live_response_harness.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tier0fp.live_harness import aggregate_results, build_sample_domains, run_harness


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-2ld-json", type=Path, default=None,
                         help="report.json from run_pipeline.py, used to source real corpus 2LDs (allow_list_candidates_ranked)")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--delay", type=float, default=0.05, help="Seconds between queries per domain (politeness)")
    args = parser.parse_args()

    corpus_2lds = []
    if args.corpus_2ld_json and args.corpus_2ld_json.exists():
        data = json.loads(args.corpus_2ld_json.read_text(encoding="utf-8"))
        corpus_2lds = [name for name, _count in data.get("allow_list_candidates_ranked", [])]

    domains = build_sample_domains(corpus_2lds)
    print(f"Sample: {len(domains)} real domains ({len(corpus_2lds)} corpus-derived + supplement)")

    start = time.time()

    def progress(i, total, domain):
        if i % 10 == 0 or i == total:
            print(f"[{i}/{total}] {domain} ({time.time()-start:.1f}s)", flush=True)

    results = run_harness(domains, delay=args.delay, progress_cb=progress)
    agg = aggregate_results(results)
    agg["domains_sampled"] = domains

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(agg, indent=2), encoding="utf-8")

    print()
    print(json.dumps(agg["rules"], indent=2))
    print(f"\nWritten to {args.out}")


if __name__ == "__main__":
    main()
