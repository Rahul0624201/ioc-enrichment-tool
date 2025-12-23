"""
ioc.py
-------
IOC parsing + type detection.

We take a raw line from iocs.txt and classify it as:
- IPv4 / IPv6 address
- domain
- hash (md5/sha1/sha256)
- unknown (blank/comment/unsupported)

This file keeps detection logic clean and reusable.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Optional

# Basic domain regex (good enough for typical IOC lists)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,63})+$"
)

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class IOC:
    value: str
    ioc_type: str           # "ip" | "domain" | "hash" | "unknown"
    hash_type: Optional[str] = None  # "md5" | "sha1" | "sha256" | None


def detect_ioc_type(raw: str) -> IOC:
    """
    Detect IOC type from a raw string line.
    """
    v = raw.strip()

    # Ignore empty lines and comments
    if not v or v.startswith("#"):
        return IOC(value=v, ioc_type="unknown")

    # IP detection (supports IPv4 and IPv6)
    try:
        ipaddress.ip_address(v)
        return IOC(value=v, ioc_type="ip")
    except ValueError:
        pass

    # Hash detection
    if MD5_RE.match(v):
        return IOC(value=v, ioc_type="hash", hash_type="md5")
    if SHA1_RE.match(v):
        return IOC(value=v, ioc_type="hash", hash_type="sha1")
    if SHA256_RE.match(v):
        return IOC(value=v, ioc_type="hash", hash_type="sha256")

    # Domain detection
    if DOMAIN_RE.match(v.lower()):
        return IOC(value=v.lower(), ioc_type="domain")

    return IOC(value=v, ioc_type="unknown")
