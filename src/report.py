"""
report.py
---------
Writes enrichment results to JSON and CSV for easy sharing and analysis.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import List

from .providers import EnrichmentResult


def write_json(results: List[EnrichmentResult], out_path: Path) -> None:
    """
    Save full structured output to JSON.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(r) for r in results]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(results: List[EnrichmentResult], out_path: Path) -> None:
    """
    Save a flattened report to CSV for Excel/Google Sheets.

    We keep details as a JSON string in one column so you still preserve context.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "provider",
        "ioc",
        "ioc_type",
        "verdict",
        "score",
        "recommended_action",
        "details_json",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for r in results:
            w.writerow({
                "provider": r.provider,
                "ioc": r.ioc,
                "ioc_type": r.ioc_type,
                "verdict": r.verdict,
                "score": "" if r.score is None else r.score,
                "recommended_action": r.details.get("recommended_action", ""),
                "details_json": json.dumps(r.details, ensure_ascii=False),
            })
