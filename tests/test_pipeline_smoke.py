"""End-to-end smoke test on a small synthetic CSV, standing in for the real Mendeley
dataset until it is downloaded. This is NOT the measurement itself -- it only proves the
streaming pipeline (reader -> normalize -> split -> evaluate -> aggregate -> report) wires
together correctly and that plan §9's validation checklist items are computable.
"""
import csv
import json

from tier0fp.pipeline import run_pipeline
from tier0fp.profile import build_profile
from tier0fp.report import render_report
from tier0fp.schema import SchemaConfig

SCHEMA = SchemaConfig(
    delimiter=",",
    has_header=True,
    client_col=0,
    ts_col=1,
    qname_col=2,
    label_col=3,
)


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["client", "ts", "qname", "label"])
        w.writerows(rows)


def _make_dataset(path):
    rows = []
    base_ts = 1_700_000_000.0
    # Benign, all-miss ordinary traffic.
    for i in range(50):
        rows.append([f"client-{i % 5}", base_ts + i, "www.example.com.", ""])
    # Benign traffic that trips R1 (independent) -- an unlabeled long-random-looking name,
    # standing in for a real FP the plan expects rules to produce on organic traffic.
    for i in range(10):
        rows.append([f"client-{i}", base_ts + 1000 + i, f"abcdefgh{i}xxxxxxx.telemetry.example.com.", ""])
    # Exfiltration-labeled rows that must trip R1/R4 at a high rate (plan §9.1 TP smoke test).
    for i in range(5):
        rows.append([f"client-exfil-{i}", base_ts + 2000 + i, f"iodine{i}payloadchunk12345678.tunnel.example.", "iodine"])
    # A malformed row (bad qname) that must be quarantined, not silently dropped.
    rows.append(["client-bad", base_ts + 3000, "", ""])
    return rows


def test_pipeline_end_to_end_smoke(tmp_path):
    csv_path = tmp_path / "synthetic_dataset.csv"
    _write_csv(csv_path, _make_dataset(csv_path))

    out_dir = tmp_path / "out"
    result = run_pipeline(csv_path, SCHEMA, out_dir, progress_every=0)

    # §9.4 row accounting: reader rows = quarantined + labeled + benign, exact equality.
    assert result.accounting.check()
    assert result.accounting.reader_rows == 66
    assert result.accounting.quarantined == 1
    assert result.accounting.labeled == 5
    assert result.accounting.benign == 60

    # §9.1 TP smoke test: labeled exfiltration rows must be pulled out of the benign
    # stream (they are evaluated as TPs, not as candidate FPs) -- assert they never leak
    # into the benign aggregates by checking the labeled-rows side-file row count.
    with open(result.tp_dir, encoding="utf-8") as f:
        tp_rows = list(csv.reader(f))
    assert len(tp_rows) - 1 == 5  # minus header

    pipeline_json = json.loads((out_dir / "pipeline_result.json").read_text(encoding="utf-8"))
    assert pipeline_json["accounting_check_ok"] is True

    # §9.1 TP smoke test: labeled exfiltration rows must trip R1/R4 at a high rate.
    assert pipeline_json["tp_rule_hit_counts"]["R1"] == 5
    assert pipeline_json["tp_rule_hit_counts"]["R4"] == 5

    # The injected long-random-looking benign names should have tripped R4 independently
    # (they are 4-label names so they miss R1's exactly-3-labels structure, matching the
    # plan's point that R1/R4 have materially different FP populations).
    assert pipeline_json["independent_aggregates"]["R4"]["match_count"] >= 10

    report = render_report(out_dir / "pipeline_result.json", out_dir / "report.json")
    assert report["accounting_check_ok"] is True
    r4_row = next(r for r in report["per_rule_results"] if r["rule_id"] == "R4")
    assert r4_row["independent_fp_pct"] > 0

    # Attack-group aggregation: the water_torture group is the union of R1-R4, so its
    # independent FP% must be >= any single member rule's (both benign injections above
    # trip R1 or R4, both members of water_torture; tudoor_qname_only stays at 0 since no
    # empty-label QNAME was injected).
    wt_row = next(r for r in report["per_attack_results"] if r["attack"] == "water_torture")
    assert wt_row["independent_fp_pct"] >= r4_row["independent_fp_pct"]
    tudoor_row = next(r for r in report["per_attack_results"] if r["attack"] == "tudoor_qname_only")
    assert tudoor_row["independent_fp_pct"] == 0.0

    # TP smoke test at the attack level: the labeled exfil rows (which trip R1/R4, both in
    # water_torture) must show up in the attack-group hit counts too.
    assert pipeline_json["tp_attack_group_hit_counts"]["water_torture"] == 5


def test_profile_smoke(tmp_path):
    csv_path = tmp_path / "synthetic_dataset.csv"
    _write_csv(csv_path, _make_dataset(csv_path))

    profile = build_profile(csv_path, SCHEMA, tmp_path / "profile.json")
    summary = profile.to_summary()
    assert summary["record_count"] == 65  # excludes the one malformed row
    assert summary["unique_client_count"] >= 5
