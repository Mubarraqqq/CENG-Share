"""
audit_log.py — Forensic, tamper-evident audit log for CENGShare.

Every security-relevant event (encryption, decryption, verification, alert) is
appended as one JSON line. Each record stores the hash of the previous record,
forming a hash chain (a tiny blockchain). Editing or deleting any past record
breaks every hash after it, so tampering is detectable by re-walking the chain.

    entry_hash = SHA256( index | timestamp | event | details | prev_hash )

Stored as JSON Lines at logs/audit_log.jsonl.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"
AUDIT_PATH = LOG_DIR / "audit_log.jsonl"
GENESIS_HASH = "0" * 64


def _compute_hash(record: dict) -> str:
    payload = json.dumps(
        {
            "index": record["index"],
            "timestamp": record["timestamp"],
            "event": record["event"],
            "details": record["details"],
            "prev_hash": record["prev_hash"],
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _read_all() -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    records = []
    for line in AUDIT_PATH.read_text().splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def log_event(event: str, details: dict | None = None) -> dict:
    """Append a hash-chained event record and return it."""
    LOG_DIR.mkdir(exist_ok=True)
    records = _read_all()
    prev_hash = records[-1]["entry_hash"] if records else GENESIS_HASH
    record = {
        "index": len(records),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "details": details or {},
        "prev_hash": prev_hash,
    }
    record["entry_hash"] = _compute_hash(record)
    with AUDIT_PATH.open("a") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def read_log() -> list[dict]:
    return _read_all()


def verify_chain() -> dict:
    """Re-walk the chain. Returns integrity status and the first broken index."""
    records = _read_all()
    expected_prev = GENESIS_HASH
    for record in records:
        if record.get("prev_hash") != expected_prev:
            return {
                "intact": False,
                "broken_index": record["index"],
                "reason": "prev_hash does not match the previous record's hash.",
                "count": len(records),
            }
        if _compute_hash(record) != record.get("entry_hash"):
            return {
                "intact": False,
                "broken_index": record["index"],
                "reason": "record contents were altered (entry_hash mismatch).",
                "count": len(records),
            }
        expected_prev = record["entry_hash"]
    return {"intact": True, "broken_index": None, "reason": "", "count": len(records)}
