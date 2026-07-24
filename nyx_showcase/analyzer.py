"""Small deterministic analyzer used by the public Nyx portfolio edition."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .redaction import redact_text

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_SIGNALS: tuple[tuple[str, re.Pattern[str], float, str], ...] = (
    (
        "scan_indicator",
        re.compile(r"\b(?:syn\s+scan|port\s+scan(?:ning|ned)?|nmap|masscan)\b", re.IGNORECASE),
        0.45,
        "Reconnaissance-related language was observed.",
    ),
    (
        "auth_bruteforce",
        re.compile(
            r"\b(?:ssh\s+brute[\s-]?force|brute[\s-]?force|failed\s+password|"
            r"invalid\s+user|password\s+guessing)\b",
            re.IGNORECASE,
        ),
        0.55,
        "Repeated-authentication or password-guessing language was observed.",
    ),
    (
        "dns_beaconing",
        re.compile(
            r"\b(?:dns\s+beaconing|dga(?:-like)?|randomized\s+subdomain|"
            r"algorithmically\s+generated|nxdomain\s+spike)\b",
            re.IGNORECASE,
        ),
        0.55,
        "Suspicious periodic or generated-domain language was observed.",
    ),
)


def extract_valid_ipv4(text: str) -> list[str]:
    """Return unique, valid IPv4 addresses in first-seen order."""
    addresses: list[str] = []
    seen: set[str] = set()
    for candidate in _IPV4.findall(text or ""):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        normalized = str(address)
        if address.version == 4 and normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)
    return addresses


def analyze_event(text: str) -> dict[str, Any]:
    """Analyze one text event without network access or side effects."""
    raw = str(text or "")
    matches = [
        {"type": signal, "explanation": explanation}
        for signal, pattern, _confidence, explanation in _SIGNALS
        if pattern.search(raw)
    ]
    confidence = max(
        (confidence for _signal, pattern, confidence, _explanation in _SIGNALS if pattern.search(raw)),
        default=0.20,
    )

    if len(matches) >= 3:
        severity, confidence = "high", max(confidence, 0.82)
    elif len(matches) >= 2:
        severity, confidence = "medium", max(confidence, 0.70)
    elif matches:
        severity = "low"
    else:
        severity = "none"

    actionable = severity in {"medium", "high"} and confidence >= 0.65
    if matches:
        analysis = " ".join(item["explanation"] for item in matches)
    else:
        analysis = "No supported demonstration signal was found; Nyx abstained."

    return {
        "event_sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
        "sample": redact_text(raw),
        "severity": severity,
        "confidence": round(confidence, 2),
        "signals": matches,
        "entities": {"ipv4": extract_valid_ipv4(raw)},
        "analysis": analysis,
        "decision": "analyst_review" if actionable else "observe",
        "action_executed": False,
    }


def analyze_events(events: Iterable[str]) -> dict[str, Any]:
    """Analyze events and return deterministic summary and event-level results."""
    results = [analyze_event(event) for event in events if str(event).strip()]
    severity_counts = Counter(result["severity"] for result in results)
    entity_counts = Counter(
        address
        for result in results
        for address in result["entities"]["ipv4"]
    )
    severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    max_severity = max(
        (result["severity"] for result in results),
        key=lambda value: severity_order[value],
        default="none",
    )
    return {
        "summary": {
            "events_analyzed": len(results),
            "severity_counts": {
                severity: severity_counts.get(severity, 0)
                for severity in ("none", "low", "medium", "high")
            },
            "max_severity": max_severity,
            "analyst_review_count": sum(
                result["decision"] == "analyst_review" for result in results
            ),
            "top_ipv4": [
                {"value": address, "count": count}
                for address, count in entity_counts.most_common(10)
            ],
        },
        "results": results,
        "safety": {
            "network_calls": False,
            "actions_enabled": False,
            "raw_events_retained": False,
        },
    }

