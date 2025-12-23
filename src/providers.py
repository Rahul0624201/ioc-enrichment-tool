"""
providers.py
------------
Threat intel provider for IP enrichment using AbuseIPDB.

Reads API key from environment variable:
- ABUSEIPDB_API_KEY
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class EnrichmentResult:
    provider: str
    ioc: str
    ioc_type: str
    verdict: str          # malicious | suspicious | unknown | benign | error
    score: Optional[int]  # abuse confidence score
    details: Dict[str, Any]


def abuseipdb_check_ip(ip: str, max_age_days: int = 90) -> EnrichmentResult:
    """
    Query AbuseIPDB for IP reputation.
    Docs: https://docs.abuseipdb.com/
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return EnrichmentResult(
            provider="AbuseIPDB",
            ioc=ip,
            ioc_type="ip",
            verdict="error",
            score=None,
            details={"error": "Missing ABUSEIPDB_API_KEY env var"},
        )

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
        "verbose": "true",
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)

        if r.status_code != 200:
            return EnrichmentResult(
                provider="AbuseIPDB",
                ioc=ip,
                ioc_type="ip",
                verdict="error",
                score=None,
                details={"http_status": r.status_code, "body": r.text[:300]},
            )

        data = (r.json() or {}).get("data", {}) or {}
        score = data.get("abuseConfidenceScore")

        if score is None:
            verdict = "unknown"
        elif score >= 80:
            verdict = "malicious"
        elif score >= 30:
            verdict = "suspicious"
        elif score >= 1:
            verdict = "unknown"
        else:
            verdict = "benign"

        details = {
            "abuseConfidenceScore": score,
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports"),
            "lastReportedAt": data.get("lastReportedAt"),
        }

        return EnrichmentResult(
            provider="AbuseIPDB",
            ioc=ip,
            ioc_type="ip",
            verdict=verdict,
            score=score if isinstance(score, int) else None,
            details=details,
        )

    except requests.RequestException as e:
        return EnrichmentResult(
            provider="AbuseIPDB",
            ioc=ip,
            ioc_type="ip",
            verdict="error",
            score=None,
            details={"error": str(e)},
        )
