from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from connector.security.secret_scrubber import scrub_outbound

VARY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"

# Synthetic high-entropy fixture (43 chars, mixed case + digits, not a real
# credential). An earlier revision used a REAL grant secret here and GitHub push
# protection rejected the push -- correctly. Fixtures must never be real values.
_GRANT = "aB3cD9eF2gH7iJ4kL6mN8oP1qR5sT0uV3wX9yZ2bCdE4"

# Samples are assembled at runtime and carry a `testonly` marker: key-shaped
# literals in a repository trip provider secret scanning. Keep them synthetic.
_SYNTH = "testonly"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        "AGENT_CONNECTOR_SCRUB",
        "AGENT_CONNECTOR_SCRUB_ENTROPY",
        "AGENT_CONNECTOR_SCRUB_EXTRA_RULES",
        "AGENT_CONNECTOR_SCRUB_RULES",
        "AGENT_CONNECTOR_SCRUB_LOG",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_LOG", str(tmp_path / "audit.log"))


@pytest.mark.parametrize(
    ("name", "sample"),
    [
        ("openai", "sk-" + _SYNTH + "0" * 24),
        ("anthropic", "sk-ant-" + _SYNTH + "0" * 20),
        ("google", "AIza" + _SYNTH + "0" * 28),
        ("aws", "AKIA" + "TESTONLY" + "0" * 8),
        ("github", "ghp_" + _SYNTH + "0" * 28),
        ("slack", "xoxb-" + _SYNTH + "-0000-0000-000000000000"),
        ("pem", "-----BEGIN RSA PRIVATE KEY-----\n" + _SYNTH + "\n-----END RSA PRIVATE KEY-----"),
    ],
)
def test_prefix_rules_redact(name: str, sample: str) -> None:
    out = scrub_outbound({"text": f"before {sample} after"})
    assert sample not in out["text"]
    assert "[REDACTED:" in out["text"]


def test_unprefixed_secret_is_redacted_as_a_whole_string() -> None:
    out = scrub_outbound({"text": _GRANT})
    assert out["text"].startswith("[REDACTED:entropy:")


def test_uri_password_is_redacted_but_structure_is_kept() -> None:
    out = scrub_outbound({"text": "postgres://admin:S3cr3tP4ssw0rd@db.example.com:5432/prod"})
    assert out["text"].startswith("postgres://admin:[REDACTED:uri-cred:")
    assert out["text"].endswith("@db.example.com:5432/prod")


def test_hashes_and_plain_text_are_untouched() -> None:
    digest = "9f2b1c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"
    assert scrub_outbound({"text": digest})["text"] == digest
    assert scrub_outbound({"text": "an ordinary sentence about testing"})["text"] == (
        "an ordinary sentence about testing"
    )
    assert scrub_outbound({"text": "H:\\project\\.env"})["text"] == "H:\\project\\.env"


def test_identity_fields_are_exempt() -> None:
    payload = {"item": {"contentHash": _GRANT, "sessionId": _GRANT, "text": _GRANT}}
    out = scrub_outbound(payload)
    assert out["item"]["contentHash"] == _GRANT
    assert out["item"]["sessionId"] == _GRANT
    assert out["item"]["text"] != _GRANT


def test_copy_on_write_leaves_the_input_alone() -> None:
    payload = {"item": {"text": "sk-" + VARY[:32]}}
    out = scrub_outbound(payload)
    assert out is not payload
    assert "[REDACTED" not in payload["item"]["text"]
    clean = {"a": "ordinary", "b": ["x", "y"]}
    assert scrub_outbound(clean) is clean


def test_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB", "0")
    payload = {"text": "sk-" + VARY[:32]}
    assert scrub_outbound(payload)["text"] == payload["text"]


def test_entropy_fallback_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_ENTROPY", "0")
    assert scrub_outbound({"text": _GRANT})["text"] == _GRANT
    assert "[REDACTED:" in scrub_outbound({"text": "sk-" + VARY[:32]})["text"]


def test_extra_rule_table_is_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rules = [
        {
            "id": "sendgrid-api-token",
            "src": r"\bSG\.[a-z0-9=_\-.]{66}",
            "flags": "",
            "e": 2.0,
            "k": ["sg."],
        }
    ]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_RULES", str(path))
    sample = "SG." + (VARY * 2).lower()[:66]
    out = scrub_outbound({"text": f"x {sample} y"})
    assert "sendgrid-api-token" in out["text"]
    assert sample not in out["text"]


def test_extra_rule_entropy_gate_rejects_low_entropy_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = [{"id": "sendgrid-api-token", "src": r"\bSG\.[a-z0-9=_\-.]{66}", "flags": "", "e": 2.0}]
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_RULES", str(path))
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_ENTROPY", "0")
    sample = "SG." + "a" * 66
    assert sample in scrub_outbound({"text": f"x {sample} y"})["text"]


def test_malformed_rule_table_degrades_to_builtin_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "rules.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("AGENT_CONNECTOR_SCRUB_RULES", str(path))
    assert "[REDACTED:" in scrub_outbound({"text": "sk-" + VARY[:32]})["text"]


def test_audit_log_records_a_fingerprint_not_the_secret(tmp_path: Path) -> None:
    secret = "sk-" + VARY[:32]
    scrub_outbound({"text": secret})
    log = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert secret not in log
    assert '"fp"' in log


def test_scrubbing_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class Exploding:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    payload = {"nested": [1, None, True, {"odd": Exploding()}]}
    assert scrub_outbound(payload) is payload


def test_environment_is_not_mutated_by_reading() -> None:
    before = dict(os.environ)
    scrub_outbound({"text": _GRANT})
    assert dict(os.environ) == before
