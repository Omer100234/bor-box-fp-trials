import json

from tier0fp.schema import SchemaConfig
from tier0fp.secondary_corpus import run_secondary_corpus, compare_to_primary


def test_schema_from_json_ignores_comment_field(tmp_path):
    path = tmp_path / "schema.json"
    path.write_text(json.dumps({
        "_comment": "ignored",
        "delimiter": ",",
        "has_header": True,
        "client_col": 0,
        "ts_col": 1,
        "qname_col": 2,
        "qtype_col": None,
        "label_col": 3,
        "label_benign_values": ["", "0"],
    }), encoding="utf-8")

    schema = SchemaConfig.from_json(path)
    assert schema.qname_col == 2
    assert schema.label_benign_values == ("", "0")


def test_secondary_corpus_counts_and_skips_malformed(tmp_path):
    root = tmp_path / "normal"
    root.mkdir()
    (root / "batch1.txt").write_text(
        "abcdefgh.example.com\nwww.example.com.\n\n   \n",
        encoding="utf-8",
    )

    result = run_secondary_corpus(root, "normal")
    assert result["total_records"] == 2
    assert result["malformed_skipped"] == 0
    assert result["per_rule"]["R1"]["match_count"] == 1
    assert result["per_rule"]["R4"]["match_count"] == 1


def test_compare_to_primary_computes_delta():
    secondary = {"per_rule": {"R1": {"match_count": 5, "fp_pct": 2.0}}}
    primary_report = {"per_rule_results": [{"rule_id": "R1", "independent_fp_pct": 1.5}]}
    comparison = compare_to_primary(secondary, primary_report)
    assert comparison["R1"]["delta_pct_points"] == 0.5
