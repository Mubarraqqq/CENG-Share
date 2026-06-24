
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).parent
CHANNEL_DIR = BASE / "channel"
KEYRING_DIR = CHANNEL_DIR / "keyring"
OUTBOX_DIR = CHANNEL_DIR / "outbox"

_SAFE = re.compile(r"[^A-Za-z0-9_.-]")
_SUFFIX = ".cengshare.json"


def _safe(token: str) -> str:
    return _SAFE.sub("_", token)


def _msg_id(path: Path) -> str:
    name = path.name
    return name[: -len(_SUFFIX)] if name.endswith(_SUFFIX) else path.stem


def publish(package_bytes: bytes, sender: str, recipient: str) -> str:
    """Write a package onto the channel; return its message id."""
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    msg_id = f"{stamp}__{_safe(sender)}__to__{_safe(recipient)}"
    (OUTBOX_DIR / f"{msg_id}.cengshare.json").write_bytes(package_bytes)
    return msg_id


def _entry(path: Path) -> dict | None:
    try:
        package = json.loads(path.read_text())
        meta = package.get("metadata", {})
    except Exception:  # noqa: BLE001 - a corrupted/garbage file on the wire
        return {
            "msg_id": _msg_id(path),
            "path": str(path),
            "sender": "?",
            "recipient": "?",
            "filename": path.name,
            "timestamp": "",
            "size": 0,
            "corrupt": True,
        }
    return {
        "msg_id": _msg_id(path),
        "path": str(path),
        "sender": meta.get("sender", "?"),
        "recipient": meta.get("recipient", "?"),
        "filename": meta.get("filename", "?"),
        "timestamp": meta.get("timestamp", ""),
        "size": meta.get("size", 0),
        "corrupt": False,
    }


def _all_entries() -> list[dict]:
    if not OUTBOX_DIR.exists():
        return []
    entries = [_entry(p) for p in OUTBOX_DIR.glob(f"*{_SUFFIX}")]
    return sorted(entries, key=lambda e: e["msg_id"], reverse=True)


def inbox(recipient: str) -> list[dict]:
    """Messages on the channel addressed to `recipient` (newest first)."""
    return [e for e in _all_entries() if e["recipient"] == recipient]


def all_messages() -> list[dict]:
    """Every message on the channel — used by the monitor view."""
    return _all_entries()


def read_package(msg_id: str) -> bytes:
    return (OUTBOX_DIR / f"{msg_id}.cengshare.json").read_bytes()


def delete(msg_id: str) -> None:
    path = OUTBOX_DIR / f"{msg_id}.cengshare.json"
    if path.exists():
        path.unlink()
