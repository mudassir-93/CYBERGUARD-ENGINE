"""Read-only ThreatFox community feed adapter.

Only supported IP/domain IOCs are imported. Feed data is treated as untrusted
input, bounded before parsing, normalized, and never executed or submitted.
"""
from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threat_intel import normalize_indicator

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_INDICATORS = 5000
DEFAULT_TIMEOUT_SECONDS = 20


class ThreatFoxError(RuntimeError):
    """A safe, user-facing ThreatFox retrieval or response error."""


class ThreatFoxFeed:
    """Fetch and normalize recent ThreatFox IOCs using a user-supplied API key."""

    def __init__(self, api_key: str | None = None, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = (
            api_key if api_key is not None
            else os.environ.get("CYBERGUARD_THREATFOX_API_KEY", "")
        ).strip()
        if not self.api_key:
            raise ThreatFoxError(
                "ThreatFox API key is not configured; set CYBERGUARD_THREATFOX_API_KEY"
            )
        if len(self.api_key) > 512 or any(ch in self.api_key for ch in "\r\n"):
            raise ThreatFoxError("ThreatFox API key has an invalid format")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
            raise ValueError("timeout must be an integer from 1 to 60 seconds")
        self.timeout = timeout

    @staticmethod
    def _feed_timestamp(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        cleaned = value.strip()
        if cleaned.endswith(" UTC"):
            cleaned = cleaned[:-4] + "+00:00"
        try:
            parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _indicator(row: object) -> dict | None:
        if not isinstance(row, dict):
            return None
        kind = row.get("ioc_type")
        value = row.get("ioc")
        if kind not in {"ip", "domain"} or not isinstance(value, str):
            return None
        confidence = row.get("confidence_level", 50)
        if isinstance(confidence, bool):
            return None
        try:
            confidence = int(confidence)
        except (TypeError, ValueError):
            return None
        if not 0 <= confidence <= 100:
            return None
        severity = (
            "critical" if confidence >= 95 else
            "high" if confidence >= 80 else
            "medium" if confidence >= 50 else "low"
        )
        tags = row.get("tags")
        if not isinstance(tags, list):
            tags = []
        description_parts = [
            row.get("threat_type_desc"),
            row.get("malware_printable"),
        ]
        reference = row.get("reference")
        if isinstance(reference, str) and reference.startswith(("https://", "http://")):
            description_parts.append("Reference: " + reference[:500])
        try:
            normalized = normalize_indicator({
                "type": kind,
                "value": value,
                "confidence": confidence,
                "severity": severity,
                "source": "ThreatFox",
                "description": " | ".join(
                    str(part)[:300] for part in description_parts
                    if isinstance(part, str) and part.strip()
                )[:1000],
                "tags": tags,
                "first_seen": ThreatFoxFeed._feed_timestamp(
                    row.get("first_seen_utc") or row.get("first_seen")
                ),
                "last_seen": ThreatFoxFeed._feed_timestamp(
                    row.get("last_seen_utc") or row.get("last_seen")
                ),
            })
        except (TypeError, ValueError):
            return None
        # Do not promote private/reserved IPs to operational threat indicators.
        if kind == "ip":
            try:
                address = ipaddress.ip_address(normalized["value"])
            except ValueError:
                return None
            if not address.is_global:
                return None
        return normalized

    def fetch(self, days: int = 3) -> dict:
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 7:
            raise ValueError("days must be an integer from 1 to 7")
        request = Request(
            API_URL,
            data=json.dumps({"query": "get_iocs", "days": days}).encode("utf-8"),
            headers={
                "Auth-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "CyberGuard-Engine/1.0 (read-only threat-intelligence sync)",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            raise ThreatFoxError(f"ThreatFox returned HTTP {error.code}") from error
        except (URLError, TimeoutError, OSError) as error:
            raise ThreatFoxError(
                "Unable to reach ThreatFox; check connectivity and retry later"
            ) from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ThreatFoxError("ThreatFox response exceeded the 5 MB safety limit")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ThreatFoxError("ThreatFox returned invalid JSON") from error
        if not isinstance(payload, dict):
            raise ThreatFoxError("ThreatFox response must be a JSON object")
        status = payload.get("query_status")
        if status == "no_result":
            return {"indicators": [], "received": 0, "accepted": 0, "skipped": 0}
        if status != "ok" or not isinstance(payload.get("data"), list):
            raise ThreatFoxError("ThreatFox did not return a successful IOC dataset")
        rows = payload["data"]
        if len(rows) > MAX_INDICATORS:
            raise ThreatFoxError(
                "ThreatFox returned more than 5,000 indicators; refusing oversized import"
            )
        indicators = [
            item for row in rows
            if (item := self._indicator(row)) is not None
        ]
        return {
            "indicators": indicators,
            "received": len(rows),
            "accepted": len(indicators),
            "skipped": len(rows) - len(indicators),
        }
