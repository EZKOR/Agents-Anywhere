"""Redact secret-shaped substrings from the connector's outbound payloads.

Why this exists
---------------
The connector reads local agent session stores (``~/.claude/projects``,
``~/.codex/sessions``, the DSH session log) and republishes that content to the
backend so it can be viewed from another device. The content is the agent's own
transcript, so anything an agent read, printed, or that a user pasted into a
prompt — including credentials — travels with it. The store itself is the
user's own data on their own machine; the copy that leaves the machine is not.

This module redacts credential-shaped substrings at the one choke point every
outbound frame passes through, so the local store stays intact while the
published copy does not carry secrets.

Design constraints (deliberate, please keep them)
-------------------------------------------------
* **Redact, never block.** Synchronisation must not fail because of a false
  positive. Matched spans are replaced, never dropped.
* **Never raise.** Any failure returns the payload untouched. A scrubbing bug
  must not be able to break the connector.
* **Copy-on-write.** Callers keep ownership of the object they passed in;
  unchanged inputs are returned by identity.
* **Identity/hash fields are exempt.** ``id``, ``*SessionId``, ``*Hash``,
  ``seq`` … are used for deduplication and content verification on both sides;
  rewriting them would corrupt session history.
* **Field-aware, not whole-text.** The payload is walked as a tree and only
  string leaves are examined, so structure and identifiers survive.

Configuration (all optional)
----------------------------
``AGENT_CONNECTOR_SCRUB=0``          disable entirely
``AGENT_CONNECTOR_SCRUB_ENTROPY=0``  keep prefix rules, drop the entropy fallback
``AGENT_CONNECTOR_SCRUB_EXTRA_RULES=0``  ignore the external rule table
``AGENT_CONNECTOR_SCRUB_RULES``      path to a JSON rule table (see below)
``AGENT_CONNECTOR_SCRUB_LOG``        append an audit log of redactions to this file

The external rule table is a JSON array of objects::

    [{"id": "sendgrid-api-token", "src": "\\bSG\\.[a-z0-9=_\\-.]{66}",
      "flags": "i", "e": 2.0, "g": 1, "k": ["sg."]}]

``src``/``flags`` are a regular expression and its flags; ``e`` is an optional
minimum Shannon entropy for the extracted secret; ``g`` an optional 1-based
capture group holding the secret; ``k`` optional lowercase keywords used as a
cheap prefilter. ``.security/gitleaks-to-rules.mjs`` in our local tooling emits
this format from gitleaks' own rule file (MIT).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from typing import Any

__all__ = ["scrub_outbound"]

# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

#: Prefix-shaped credentials. Cheap, near-zero false positives, so they run on
#: every string including the keys the identity list below does not cover.
_PREFIX_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("anthropic", re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}")),
    ("generic", re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{24,}")),
    ("ark", re.compile(r"(?<![A-Za-z0-9])ark-[A-Za-z0-9]{24,}")),
    ("google", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{30,}")),
    ("github", re.compile(r"(?<![A-Za-z0-9])(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("aws", re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}")),
    ("slack", re.compile(r"(?<![A-Za-z0-9])xox[abp]-[A-Za-z0-9-]{20,}")),
)

#: Credentials embedded in a URI authority. Only the password span is replaced.
_URI_CRED_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:@/]{1,64}:)([^\s:@/]{4,128})(@)"
)

#: Whole-string high-entropy fallback: catches secrets with no recognisable
#: prefix. Anchored on purpose — an unanchored variant matches every random
#: substring inside tool output, file diffs and command text, which on real
#: traffic produced ~640k redactions in 24 minutes and shredded the transcript.
_ENTROPY_RE = re.compile(r"[A-Za-z0-9_\-+/=.]{40,128}\Z")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")

#: Never rewritten: deduplication and content verification depend on these.
_SKIP_KEYS = frozenset(
    """id itemId messageId callId rootCallId parentItemId sessionId externalSessionId
    snapshotId streamId batchSeq projectionVersion revision seq throughSeq eventSeq
    hash contentHash itemHash sha256 nonce requestId jsonrpc rpcId scanToken
    selectionId transferId connectorId projectId runtimeId fileId attachmentId
    messageSource kind type role method status level""".split()
)
_SKIP_SUFFIX_RE = re.compile(
    r"(id|ids|uuid|guid|hash|nonce|seq|epoch|session|sessions|source|kind|type|role"
    r"|method|status|level|revision|version)$",
    re.IGNORECASE,
)

_MAX_DEPTH = 12
_ENTROPY_MIN_LEN = 40
_ENTROPY_MAX_LEN = 128
_ENTROPY_UNIQUE_RATIO = 0.4

_WINDOW = 16_384
_OVERLAP = 512
_MAX_WINDOWS = 64

_extra_rules: list[dict[str, Any]] | None = None
_extra_rules_path: str | None = None


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value else None


def _enabled() -> bool:
    return _env("AGENT_CONNECTOR_SCRUB") != "0"


def _fingerprint(secret: str) -> str:
    """Stable, irreversible label so two redactions of the same secret match."""
    try:
        return hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:10]
    except Exception:  # noqa: BLE001
        return "nohash"


def _audit(kind: str, fingerprint: str, location: str) -> None:
    path = _env("AGENT_CONNECTOR_SCRUB_LOG")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"kind": kind, "fp": fingerprint, "at": location}, ensure_ascii=False) + "\n"
            )
    except OSError:
        pass


def _redact(secret: str, kind: str, location: str) -> str:
    fingerprint = _fingerprint(secret)
    _audit(kind, fingerprint, location)
    return f"[REDACTED:{kind}:{fingerprint}]"


def _shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _looks_random(token: str) -> bool:
    length = len(token)
    if length < _ENTROPY_MIN_LEN or length > _ENTROPY_MAX_LEN:
        return False
    if _HEX_RE.match(token):  # hashes are not secrets, and they matter for identity
        return False
    if not any(char.isalpha() for char in token) or not any(char.isdigit() for char in token):
        return False
    return len(set(token)) / length >= _ENTROPY_UNIQUE_RATIO


def _load_extra_rules() -> list[dict[str, Any]]:
    """Compile the external rule table; a bad rule is skipped, a bad file ignored.

    The cache is keyed by the resolved path rather than filled once and frozen.
    An empty result must not be sticky: if the table is configured after the
    first outbound frame, a one-shot cache would silently never pick it up.
    """
    global _extra_rules, _extra_rules_path
    path = _env("AGENT_CONNECTOR_SCRUB_RULES")
    if _env("AGENT_CONNECTOR_SCRUB_EXTRA_RULES") == "0":
        path = None
    if _extra_rules is not None and _extra_rules_path == path:
        return _extra_rules
    compiled: list[dict[str, Any]] = []
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            raw = []
        for rule in raw if isinstance(raw, list) else []:
            try:
                flags = 0
                declared = str(rule.get("flags", ""))
                if "i" in declared:
                    flags |= re.IGNORECASE
                if "m" in declared:
                    flags |= re.MULTILINE
                if "s" in declared:
                    flags |= re.DOTALL
                # Rule tables written for JavaScript use (?<name>; Python wants (?P<name>.
                source = re.sub(r"\(\?<([A-Za-z])", r"(?P<\1", str(rule["src"]))
                compiled.append(
                    {
                        "id": str(rule["id"]),
                        "re": re.compile(source, flags),
                        "entropy": rule.get("e"),
                        "group": rule.get("g"),
                        "keywords": [str(k).lower() for k in rule.get("k", [])] or None,
                    }
                )
            except (KeyError, TypeError, ValueError, re.error):
                continue
    _extra_rules = compiled
    _extra_rules_path = path
    return compiled


def _scrub_with_extra_rules(text: str, location: str) -> str:
    rules = _load_extra_rules()
    if not rules:
        return text
    out = text
    stride = _WINDOW - _OVERLAP
    for window_index in range(_MAX_WINDOWS):
        offset = window_index * stride
        if offset >= len(text):
            break
        chunk = text[offset : offset + _WINDOW]
        lowered = chunk.lower()
        for rule in rules:
            keywords = rule["keywords"]
            if keywords and not any(keyword in lowered for keyword in keywords):
                continue
            for match in rule["re"].finditer(chunk):
                secret = match.group(0)
                group = rule["group"]
                if group is not None:
                    try:
                        captured = match.group(group)
                    except Exception:  # noqa: BLE001 - a bad group index must not abort the walk
                        captured = None
                    if captured:
                        secret = captured
                if not secret:
                    continue
                threshold = rule["entropy"]
                if threshold is not None and _shannon(secret) < threshold:
                    continue
                if secret not in out:
                    continue
                out = out.replace(secret, _redact(secret, rule["id"], location))
        if len(chunk) < _WINDOW:
            break
    return out


def _scrub_text(text: str, location: str) -> str:
    if len(text) < 8:
        return text
    out = text
    for kind, pattern in _PREFIX_RULES:
        if pattern.search(out):
            out = pattern.sub(lambda match, kind=kind: _redact(match.group(0), kind, location), out)
    if "://" in out and "@" in out:
        out = _URI_CRED_RE.sub(
            lambda match: match.group(1) + _redact(match.group(2), "uri-cred", location) + match.group(3),
            out,
        )
    if _env("AGENT_CONNECTOR_SCRUB_ENTROPY") != "0" and _ENTROPY_RE.match(out) and _looks_random(out):
        out = _redact(out, "entropy", location)
    if len(out) >= 12:
        out = _scrub_with_extra_rules(out, location)
    return out


def _is_exempt(key: str) -> bool:
    return key in _SKIP_KEYS or bool(_SKIP_SUFFIX_RE.search(key))


def _scrub_value(value: Any, depth: int, location: str) -> Any:
    if depth > _MAX_DEPTH:
        return value
    if isinstance(value, str):
        return _scrub_text(value, location)
    if isinstance(value, (bytes, bytearray)):
        return value
    if isinstance(value, (list, tuple)):
        changed = False
        items = []
        for item in value:
            scrubbed = _scrub_value(item, depth + 1, location + "[]")
            changed = changed or scrubbed is not item
            items.append(scrubbed)
        if not changed:
            return value
        return items if isinstance(value, list) else tuple(items)
    if isinstance(value, dict):
        updated: dict[Any, Any] | None = None
        for key, child in value.items():
            if isinstance(key, str) and _is_exempt(key):
                continue
            scrubbed = _scrub_value(child, depth + 1, f"{location}.{key}")
            if scrubbed is not child:
                if updated is None:
                    updated = dict(value)
                updated[key] = scrubbed
        return updated if updated is not None else value
    return value


def scrub_outbound(payload: Any) -> Any:
    """Return ``payload`` with credential-shaped strings redacted.

    Called on every frame the connector sends. Returns the input unchanged when
    scrubbing is disabled or anything goes wrong — that is the contract.
    """
    if not _enabled():
        return payload
    try:
        return _scrub_value(payload, 0, "$")
    except Exception:  # noqa: BLE001
        return payload
