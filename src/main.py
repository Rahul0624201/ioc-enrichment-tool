"""
main.py
-------
IOC Enrichment Tool (AbuseIPDB only)

Features:
- Enrich IP IOCs using AbuseIPDB
- Detect domain/hash but mark as unsupported (for now)
- Caching to avoid duplicate API calls
- Rate limiting
- Recommended action for SOC-style triage

Run:
  py -m src.main --in iocs.txt --sleep 1.0
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from .ioc import detect_ioc_type
from .providers import EnrichmentResult, abuseipdb_check_ip
from .report import write_json, write_csv


def load_cache(path: Path) -> Dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(cache: Dict[str, dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def recommended_action(verdict: str) -> str:
    if verdict == "malicious":
        return "BLOCK + INVESTIGATE"
    if verdict == "suspicious":
        return "MONITOR / INVESTIGATE"
    if verdict == "benign":
        return "ALLOW / IGNORE"
    if verdict == "error":
        return "RETRY / CHECK CONFIG"
    return "REVIEW"


def main() -> int:
    ap = argparse.ArgumentParser(description="IOC Enrichment Tool (AbuseIPDB)")
    ap.add_argument("--in", dest="infile", default="iocs.txt", help="Input IOC file")
    ap.add_argument("--outdir", default="output", help="Output folder")
    ap.add_argument("--max-age", type=int, default=90, help="Max age in days for AbuseIPDB")
    ap.add_argument("--sleep", type=float, default=1.0, help="Seconds to sleep between API calls")
    ap.add_argument("--no-cache", action="store_true", help="Disable cache usage")
    args = ap.parse_args()

    infile = Path(args.infile).resolve()
    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    if not infile.exists():
        print(f"[ERROR] Input file not found: {infile}")
        return 2

    cache_path = outdir / "cache.json"
    cache: Dict[str, dict] = {} if args.no_cache else load_cache(cache_path)

    raw_lines = infile.read_text(encoding="utf-8", errors="ignore").splitlines()

    results: List[EnrichmentResult] = []
    skipped = 0
    cache_hits = 0

    for line in raw_lines:
        ioc = detect_ioc_type(line)

        if ioc.ioc_type == "unknown":
            skipped += 1
            continue

        cache_key = f"{ioc.ioc_type}:{ioc.value}"

        if not args.no_cache and cache_key in cache:
            try:
                results.append(EnrichmentResult(**cache[cache_key]))
                cache_hits += 1
                continue
            except TypeError:
                pass

        # Only enrich IPs for now
        if ioc.ioc_type == "ip":
            res = abuseipdb_check_ip(ioc.value, max_age_days=args.max_age)
        else:
            res = EnrichmentResult(
                provider="(none)",
                ioc=ioc.value,
                ioc_type=ioc.ioc_type,
                verdict="unknown",
                score=None,
                details={"note": "Detected but not enriched (IP-only in this version)"},
            )

        res.details["recommended_action"] = recommended_action(res.verdict)
        results.append(res)

        if not args.no_cache:
            cache[cache_key] = asdict(res)

        if args.sleep > 0:
            time.sleep(args.sleep)

    if not args.no_cache:
        save_cache(cache, cache_path)

    out_json = outdir / "enrichment.json"
    out_csv = outdir / "enrichment.csv"
    write_json(results, out_json)
    write_csv(results, out_csv)

    by_verdict: Dict[str, int] = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1

    print(f"[OK] Processed: {len(results)} IOCs | Skipped: {skipped} | Cache hits: {cache_hits}")
    print("Verdicts:")
    for k, v in sorted(by_verdict.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {k}: {v}")

    print(f"Saved: {out_json}")
    print(f"Saved: {out_csv}")
    if not args.no_cache:
        print(f"Cache: {cache_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
