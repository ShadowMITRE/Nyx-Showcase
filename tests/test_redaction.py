from __future__ import annotations

from nyx_showcase.redaction import redact_text


def test_redacts_email_token_and_paths() -> None:
    text = (
        "user=analyst@example.com token=supersecret12345 "
        r"path=C:\Users\Analyst\secrets.txt and /home/analyst/.ssh/id_rsa"
    )
    redacted = redact_text(text)
    assert "analyst@example.com" not in redacted
    assert "supersecret12345" not in redacted
    assert "C:\\Users\\Analyst" not in redacted
    assert "/home/analyst" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_TOKEN]" in redacted
    assert "[REDACTED_PATH]" in redacted


def test_redaction_bounds_external_sample() -> None:
    assert len(redact_text("x" * 500, max_length=32)) == 32

