"""Schema discovery and column mapping (plan §4.2).

Nothing downstream reads a data file until a SchemaConfig has been explicitly constructed
and checked in -- there is no auto-inference of "which column is the qname" from a raw CSV,
because guessing wrong here would silently corrupt every number the program produces.
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class SchemaConfig:
    delimiter: str
    has_header: bool
    client_col: int
    ts_col: int
    qname_col: int
    label_col: int
    qtype_col: Optional[int] = None
    label_benign_values: tuple = ("", "0", "benign", "none", "na")

    def is_benign_label(self, raw_label: str) -> bool:
        return (raw_label or "").strip().lower() in self.label_benign_values

    def to_json(self, path: Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2, default=list), encoding="utf-8")

    @staticmethod
    def from_json(path: Path) -> "SchemaConfig":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        known_fields = {f.name for f in fields(SchemaConfig)}
        d = {k: v for k, v in raw.items() if k in known_fields}
        d["label_benign_values"] = tuple(d.get("label_benign_values", ("", "0", "benign", "none", "na")))
        return SchemaConfig(**d)


def preview_columns(csv_path: Path, delimiter: str = ",", n_rows: int = 5) -> list[list[str]]:
    """Read the first n_rows of a CSV for manual column-map construction. Read-only, makes
    no assumption about which column is which -- that mapping is a human decision recorded
    in a SchemaConfig once dataset_description.txt has been read."""
    rows = []
    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        for i, row in enumerate(reader):
            if i >= n_rows:
                break
            rows.append(row)
    return rows
