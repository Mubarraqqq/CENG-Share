"""
ids.py — Lightweight Intrusion Detection System for CENGShare.

The IDS does not do crypto itself. It observes the outcomes reported by the
verification pipeline and raises alerts for:

  * tampered files          -> integrity (hash) check failed
  * invalid packages        -> malformed / undecodable package
  * failed decryption       -> AES-GCM tag mismatch or key recovery failure
  * bad signatures          -> authentication failed
  * repeated suspicious access
                            -> N failed events within a short rolling window
                               (brute-force / probing behaviour)

Alerts are persisted to logs/alerts.jsonl AND mirrored into the hash-chained
audit log so detection events are themselves tamper-evident.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from audit_log import LOG_DIR, log_event

ALERTS_PATH = LOG_DIR / "alerts.jsonl"

# Raise an escalated alert after this many failures within the window.
REPEAT_THRESHOLD = 3
WINDOW_SECONDS = 120


def _read_alerts() -> list[dict]:
    if not ALERTS_PATH.exists():
        return []
    out = []
    for line in ALERTS_PATH.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def raise_alert(severity: str, category: str, message: str, context: dict | None = None) -> dict:
    """Persist an alert and mirror it into the tamper-evident audit log."""
    LOG_DIR.mkdir(exist_ok=True)
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,            # INFO | WARNING | CRITICAL
        "category": category,
        "message": message,
        "context": context or {},
    }
    with ALERTS_PATH.open("a") as fh:
        fh.write(json.dumps(alert) + "\n")
    log_event("IDS_ALERT", {"severity": severity, "category": category, "message": message})
    return alert


def _recent_failures(window_seconds: int = WINDOW_SECONDS) -> int:
    now = datetime.now(timezone.utc)
    count = 0
    for alert in _read_alerts():
        if alert["severity"] == "INFO":
            continue
        try:
            ts = datetime.fromisoformat(alert["timestamp"])
        except ValueError:
            continue
        if (now - ts).total_seconds() <= window_seconds:
            count += 1
    return count


def analyze_verification(result, source: str = "unknown") -> list[dict]:
    """Inspect a VerificationResult and raise alerts for any failure mode.

    Returns the list of alerts raised for this single verification attempt.
    """
    alerts: list[dict] = []
    ctx = {"source": source, **result.as_dict()}

    if not result.package_valid:
        alerts.append(raise_alert("CRITICAL", "INVALID_PACKAGE",
                                  "Malformed or unreadable secure package.", ctx))
    else:
        if not result.signature_valid:
            alerts.append(raise_alert("CRITICAL", "BAD_SIGNATURE",
                                      "Digital signature verification failed — sender not authentic.", ctx))
        if not result.decrypted:
            alerts.append(raise_alert("CRITICAL", "FAILED_DECRYPTION",
                                      "Decryption failed — ciphertext/nonce tampered or wrong key.", ctx))
        elif not result.integrity_valid:
            alerts.append(raise_alert("CRITICAL", "TAMPERED_FILE",
                                      "Integrity check failed — file hash mismatch after decryption.", ctx))

    # Behavioural detection: repeated failures in a short window.
    if alerts:
        recent = _recent_failures()
        if recent >= REPEAT_THRESHOLD:
            alerts.append(raise_alert(
                "CRITICAL", "REPEATED_SUSPICIOUS_ACCESS",
                f"{recent} failed/suspicious events within {WINDOW_SECONDS}s — possible probing or brute force.",
                {"source": source, "recent_failures": recent},
            ))
    return alerts


def read_alerts() -> list[dict]:
    return _read_alerts()


def alert_summary() -> dict:
    alerts = _read_alerts()
    summary = {"total": len(alerts), "CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for a in alerts:
        summary[a.get("severity", "INFO")] = summary.get(a.get("severity", "INFO"), 0) + 1
    return summary
