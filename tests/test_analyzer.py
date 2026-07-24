from __future__ import annotations

from nyx_showcase.analyzer import analyze_event, analyze_events, extract_valid_ipv4


def test_scan_signal_is_explainable_and_advisory() -> None:
    result = analyze_event("Possible SYN scan from 192.0.2.10 to 198.51.100.20")
    assert result["severity"] == "low"
    assert result["confidence"] == 0.45
    assert result["signals"][0]["type"] == "scan_indicator"
    assert result["decision"] == "observe"
    assert result["action_executed"] is False


def test_independent_signals_raise_review_priority() -> None:
    result = analyze_event(
        "nmap scan after failed password burst from 192.0.2.55"
    )
    assert result["severity"] == "medium"
    assert result["confidence"] == 0.70
    assert result["decision"] == "analyst_review"


def test_no_supported_signal_abstains() -> None:
    result = analyze_event("Routine backup completed for host 192.0.2.8")
    assert result["severity"] == "none"
    assert result["confidence"] == 0.20
    assert result["signals"] == []
    assert "abstained" in result["analysis"]


def test_ipv4_extraction_rejects_invalid_values_and_deduplicates() -> None:
    assert extract_valid_ipv4(
        "192.0.2.1 999.0.0.1 192.0.2.1 198.51.100.2"
    ) == ["192.0.2.1", "198.51.100.2"]


def test_report_has_stable_summary_and_ranked_entities() -> None:
    report = analyze_events(
        [
            "SYN scan from 192.0.2.10 to 198.51.100.20",
            "failed password from 192.0.2.10",
            "normal service start on 198.51.100.20",
        ]
    )
    assert report["summary"]["events_analyzed"] == 3
    assert report["summary"]["severity_counts"] == {
        "none": 1,
        "low": 2,
        "medium": 0,
        "high": 0,
    }
    assert report["summary"]["top_ipv4"][0] == {
        "value": "192.0.2.10",
        "count": 2,
    }
    assert report["safety"]["actions_enabled"] is False


def test_event_hash_is_stable_without_raw_retention() -> None:
    first = analyze_event("failed password from 192.0.2.1")
    second = analyze_event("failed password from 192.0.2.1")
    assert first["event_sha256"] == second["event_sha256"]
    assert "raw_event" not in first

